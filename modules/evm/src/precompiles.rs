//! EVM precompiles that bridge to native Oxide modules (plan.md §13, Phase 2).
//!
//! ## What this module is
//!
//! Implements EVM precompiles that call into native Oxide modules
//! (bank, staking, trading). This lets EVM smart contracts invoke
//! native chain functionality — e.g., a Uniswap deployment can call
//! the native bank module to transfer tokens, or a perps protocol
//! can call the native trading module to place orders.
//!
//! ## Why native precompiles
//!
//! Oxide's architecture (plan.md §2) has two execution tracks:
//! native modules (bank, staking, trading) and EVM. Native precompiles
//! bridge them: EVM contracts call native functionality via precompile
//! addresses, getting the performance and safety of the native
//! implementation without re-implementing it in Solidity.
//!
//! ## Precompile addresses
//!
//! Oxide reserves precompile addresses in the range
//! `0x0000_0000_0000_0000_0000_0000_0000_0000_OOXX` where `OO` is the
//! module ID and `XX` is the operation ID. This avoids collision with
//! Ethereum's standard precompiles (addresses 0x01–0x0A).
//!
//! Current precompiles:
//! - `0x0B_01` (bank, transfer): transfer native tokens between accounts.
//! - `0x0B_02` (bank, balance): query an account's native balance.
//! - `0x0C_01` (staking, delegate): delegate to a validator.
//! - `0x05_01` (exchange, best bid): read best bid price+qty.
//! - `0x05_02` (exchange, best ask): read best ask price+qty.
//! - `0x06_01` (perps, position): read position size+entry+margin.
//! - `0x06_02` (perps, mark price): read the mark price.
//! - `0x06_03` (perps, insurance fund): read the insurance fund balance.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use primitives::Address;

use revm::context::Cfg;
use revm::handler::EthPrecompiles;
use revm::interpreter::InterpreterResult;
use revm::precompile::{PrecompileOutput, PrecompileStatus};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{AddressSet, Bytes};

use crate::native_journal::NativeJournal;
use crate::precompiles::native::NativeMarketReader;

/// A precompile call result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileResult {
    /// The output bytes returned to the EVM caller.
    pub output: Vec<u8>,
    /// The gas consumed by the precompile.
    pub gas_used: u64,
    /// Whether the precompile succeeded.
    pub success: bool,
}

impl PrecompileResult {
    /// A successful precompile call with the given output and gas.
    #[must_use]
    pub fn success(output: Vec<u8>, gas_used: u64) -> Self {
        Self { output, gas_used, success: true }
    }

    /// A failed precompile call (revert) with the given gas consumed.
    #[must_use]
    pub fn revert(gas_used: u64) -> Self {
        Self { output: Vec::new(), gas_used, success: false }
    }
}

/// The precompile address for a (`module_id`, `op_id`) pair.
///
/// Oxide precompiles live at addresses of the form
/// `0x0000...0000_OOXX` where `OO` is the module ID and `XX` is the
/// operation ID. This keeps them separate from Ethereum's standard
/// precompiles (0x01–0x0A).
#[must_use]
pub fn precompile_address(module_id: u8, op_id: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = module_id;
    bytes[19] = op_id;
    Address(bytes)
}

/// Decode a precompile address into (`module_id`, `op_id`).
///
/// Returns `None` if the address is not a valid Oxide precompile
/// address (i.e., not in the `0x0000...OOXX` format).
#[must_use]
pub fn decode_precompile_address(addr: &Address) -> Option<(u8, u8)> {
    let bytes = addr.as_bytes();
    // The first 18 bytes must be zero.
    if bytes[..18].iter().any(|&b| b != 0) {
        return None;
    }
    // Module ID 0 is reserved (no precompile there).
    let module_id = bytes[18];
    if module_id == 0 {
        return None;
    }
    Some((module_id, bytes[19]))
}

/// Check if an address is an Oxide precompile address.
#[must_use]
pub fn is_precompile(addr: &Address) -> bool {
    decode_precompile_address(addr).is_some()
}

/// The bank transfer precompile (module `0x0B`, op `0x01`).
///
/// Input: `[to: 20B][amount: 32B]` (EVM ABI: address + uint256).
/// Output: empty on success.
/// Gas: `21_000` (same as a standard ETH transfer).
pub const BANK_TRANSFER: (u8, u8) = (0x0B, 0x01);

/// The bank balance precompile (module `0x0B`, op `0x02`).
///
/// Input: `[addr: 20B]`.
/// Output: `[balance: 32B]` (uint256).
/// Gas: `1_000` (a cold read).
pub const BANK_BALANCE: (u8, u8) = (0x0B, 0x02);

/// The staking undelegate precompile (module `0x0C`, op `0x02`).
///
/// Input: `[validator: 20B][amount: 32B]` — begins unbonding `amount`
/// of the **caller's** delegation to `validator`. The undelegated
/// funds stay in the bonded pool until the unbonding period ends.
///
/// Gas: `50_000` (a staking operation).
pub const STAKING_UNDELEGATE: (u8, u8) = (0x0C, 0x02);

/// The staking delegate precompile (module `0x0C`, op `0x01`).
///
/// Input: `[validator: 20B][amount: 32B]`.
/// Output: empty on success.
/// Gas: `50_000` (a staking operation).
pub const STAKING_DELEGATE: (u8, u8) = (0x0C, 0x01);

/// The exchange best-bid precompile (module `0x05` = exchange, op `0x01`).
///
/// Input: `[market: 1B]`.
/// Output: `[price: 8B LE][qty: 8B LE]` or empty if no bid.
/// Gas: `2_000` (a cold read of native state).
pub const EXCHANGE_BEST_BID: (u8, u8) = (0x05, 0x01);

/// The exchange best-ask precompile (module `0x05` = exchange, op `0x02`).
///
/// Input: `[market: 1B]`.
/// Output: `[price: 8B LE][qty: 8B LE]` or empty if no ask.
/// Gas: `2_000`.
pub const EXCHANGE_BEST_ASK: (u8, u8) = (0x05, 0x02);

/// The perps position precompile (module `0x06` = perps, op `0x01`).
///
/// Input: `[market: 1B][account: 20B]`.
/// Output: `[size: 8B LE (signed)][entry: 8B LE][margin: 8B LE]`.
/// Gas: `2_000`.
pub const PERPS_POSITION: (u8, u8) = (0x06, 0x01);

/// The perps mark-price precompile (module `0x06` = perps, op `0x02`).
///
/// Input: `[market: 1B]`.
/// Output: `[mark: 8B LE]` or empty if market not found.
/// Gas: `1_000`.
pub const PERPS_MARK_PRICE: (u8, u8) = (0x06, 0x02);

/// The perps insurance-fund precompile (module `0x06` = perps, op `0x03`).
///
/// Input: empty.
/// Output: `[balance: 8B LE]`.
/// Gas: `1_000`.
pub const PERPS_INSURANCE_FUND: (u8, u8) = (0x06, 0x03);

/// Call context for mutating precompiles.
///
/// Built per call inside `NativePrecompiles::run` from the revm
/// `CallInputs` (caller identity, static flag, transferred value) plus
/// the module's wired native handles and the transaction's shared
/// [`NativeJournal`]. Read-only precompiles ignore it.
pub struct NativeCallCtx {
    /// `msg.sender` of the precompile call — the delegator for
    /// staking ops. For `DELEGATECALL` this is the preserved caller,
    /// matching cosmos-evm semantics (the precompile acts for
    /// `msg.sender`, not the immediate contract).
    pub caller: Address,
    /// `true` inside `STATICCALL` — mutating precompiles must revert.
    pub is_static: bool,
    /// `true` when the CALL transfers a non-zero value into the
    /// precompile address — rejected by mutating precompiles so funds
    /// are never stranded in an unspendable address.
    pub has_value: bool,
    /// `true` on read-only paths (`eth_call`, `eth_estimateGas`) —
    /// mutating precompiles revert so a simulation can never touch
    /// native state.
    pub read_only: bool,
    /// The staking module for `0x0C_*` ops, when wired.
    pub staking: Option<Arc<staking::StakingModule>>,
    /// The transaction's frame-scoped undo log — mutating precompiles
    /// push an undo closure per applied mutation.
    pub journal: Rc<RefCell<NativeJournal>>,
}

/// Execute a precompile call.
///
/// Given a precompile address and input data, dispatch to the
/// appropriate native module handler. For read-only precompiles
/// (exchange/perps), the `reader` provides access to native state.
///
/// # Arguments
///
/// - `addr`: The precompile address (must be a valid Oxide precompile).
/// - `input`: The call data from the EVM.
/// - `gas_limit`: The gas limit for the precompile.
/// - `reader`: The native market reader (exchange/perps read views).
/// - `call`: The call context (caller, static flag, value, journal).
///
/// # Returns
///
/// A `PrecompileResult` with the output, gas used, and success flag.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn execute_precompile(
    addr: &Address,
    input: &[u8],
    gas_limit: u64,
    reader: &NativeMarketReader,
    call: &NativeCallCtx,
) -> PrecompileResult {
    let Some((module_id, op_id)) = decode_precompile_address(addr) else {
        return PrecompileResult::revert(0);
    };

    match (module_id, op_id) {
        BANK_TRANSFER => execute_bank_transfer(input, gas_limit),
        BANK_BALANCE => execute_bank_balance(input, gas_limit),
        STAKING_DELEGATE => execute_staking_delegate(input, gas_limit, call),
        STAKING_UNDELEGATE => execute_staking_undelegate(input, gas_limit, call),
        EXCHANGE_BEST_BID => execute_exchange_best_bid(input, gas_limit, reader),
        EXCHANGE_BEST_ASK => execute_exchange_best_ask(input, gas_limit, reader),
        PERPS_POSITION => execute_perps_position(input, gas_limit, reader),
        PERPS_MARK_PRICE => execute_perps_mark_price(input, gas_limit, reader),
        PERPS_INSURANCE_FUND => execute_perps_insurance_fund(input, gas_limit, reader),
        _ => PrecompileResult::revert(0),
    }
}

/// Execute the bank transfer precompile.
///
/// Input: `[to: 20B][amount: 32B]`.
/// Gas: `21_000` (same as a standard ETH transfer).
fn execute_bank_transfer(input: &[u8], gas_limit: u64) -> PrecompileResult {
    const GAS_COST: u64 = 21_000;
    if gas_limit < GAS_COST {
        return PrecompileResult::revert(gas_limit);
    }
    // Input: 20-byte address + 32-byte amount = 52 bytes.
    if input.len() != 52 {
        return PrecompileResult::revert(GAS_COST);
    }
    // Validate the address (non-zero).
    let to = &input[..20];
    if to.iter().all(|&b| b == 0) {
        return PrecompileResult::revert(GAS_COST);
    }
    // C5 fix: the bank transfer side effect is NOT yet wired. The
    // previous code returned `success` without performing any
    // transfer — a contract calling this precompile would believe
    // the transfer succeeded, but no funds moved. Returning
    // `revert` here is safer: the caller sees a failed call and
    // knows the transfer did not happen. When the executor-side
    // settlement is wired (passing mutable bank access into the
    // precompile context), this will return `success` after
    // performing the actual transfer.
    PrecompileResult::revert(GAS_COST)
}

/// Execute the bank balance precompile.
///
/// Input: `[addr: 20B]`.
/// Output: `[balance: 32B]`.
/// Gas: `1_000`.
fn execute_bank_balance(input: &[u8], gas_limit: u64) -> PrecompileResult {
    const GAS_COST: u64 = 1_000;
    if gas_limit < GAS_COST {
        return PrecompileResult::revert(gas_limit);
    }
    if input.len() != 20 {
        return PrecompileResult::revert(GAS_COST);
    }
    // Return a zero balance (stub — the actual balance comes from
    // the native bank module via the executor).
    let mut output = vec![0u8; 32];
    output[31] = 0;
    PrecompileResult::success(output, GAS_COST)
}

/// Parse `[validator: 20B][amount: 32B]` for the `0x0C_*` staking
/// precompiles.
///
/// `amount` is denominated in **native units** (the bank/staking
/// `u64` ledger unit), not wei — staking operates on the native
/// ledger, so a 256-bit wei amount would silently overflow or scale
/// by the wrong factor. `U256 > u64::MAX` reverts rather than wraps.
fn parse_staking_args(input: &[u8], gas_cost: u64) -> Result<(Address, u64), PrecompileResult> {
    if input.len() != 52 {
        return Err(PrecompileResult::revert(gas_cost));
    }
    let validator = Address(<[u8; 20]>::try_from(&input[..20]).expect("20-byte slice"));
    if validator.as_bytes().iter().all(|&b| b == 0) {
        return Err(PrecompileResult::revert(gas_cost));
    }
    let amount_u256 = revm::primitives::U256::from_be_slice(&input[20..52]);
    let amount = u64::try_from(amount_u256).map_err(|_| PrecompileResult::revert(gas_cost))?;
    if amount == 0 {
        return Err(PrecompileResult::revert(gas_cost));
    }
    Ok((validator, amount))
}

/// Guard shared by mutating staking precompiles: static/read-only
/// calls, stranded value transfers, and an unwired staking module all
/// revert; otherwise returns the wired module handle.
fn require_staking_mutability(
    call: &NativeCallCtx,
    gas_cost: u64,
) -> Result<&staking::StakingModule, PrecompileResult> {
    if call.is_static || call.read_only || call.has_value {
        return Err(PrecompileResult::revert(gas_cost));
    }
    call.staking.as_deref().ok_or_else(|| PrecompileResult::revert(gas_cost))
}

/// Execute the staking delegate precompile.
///
/// Input: `[validator: 20B][amount: 32B]`.
/// Gas: `50_000`.
///
/// Bonds `amount` (native units) of `msg.sender`'s bank balance to
/// `validator` via [`StakingModule::delegate_for`] — the identical
/// invariant path as a native `delegate` message, so EVM callers get
/// no capability native senders lack. The mutation is journaled in
/// the transaction's [`NativeJournal`]: if the calling frame or any
/// ancestor reverts, `undo_delegate` replays it out.
fn execute_staking_delegate(
    input: &[u8],
    gas_limit: u64,
    call: &NativeCallCtx,
) -> PrecompileResult {
    const GAS_COST: u64 = 50_000;
    if gas_limit < GAS_COST {
        return PrecompileResult::revert(gas_limit);
    }
    let Ok((validator, amount)) = parse_staking_args(input, GAS_COST) else {
        return PrecompileResult::revert(GAS_COST);
    };
    let Ok(staking) = require_staking_mutability(call, GAS_COST) else {
        return PrecompileResult::revert(GAS_COST);
    };
    if staking.delegate_for(call.caller, validator, amount).is_err() {
        return PrecompileResult::revert(GAS_COST);
    }
    // Journal the undo before returning success — if the frame (or an
    // ancestor) reverts, `NativeJournalInspector::frame_end` replays
    // it and the delegation never existed.
    let staking = Arc::clone(staking_arc(call));
    let delegator = call.caller;
    call.journal.borrow_mut().record(Box::new(move || {
        let _ = staking.undo_delegate(delegator, validator, amount);
    }));
    PrecompileResult::success(Vec::new(), GAS_COST)
}

/// Execute the staking undelegate precompile.
///
/// Input: `[validator: 20B][amount: 32B]`.
/// Output: `[completion_height: 8B LE]` — the block at which the
/// unbonding funds become withdrawable to the delegator.
/// Gas: `50_000`.
fn execute_staking_undelegate(
    input: &[u8],
    gas_limit: u64,
    call: &NativeCallCtx,
) -> PrecompileResult {
    const GAS_COST: u64 = 50_000;
    if gas_limit < GAS_COST {
        return PrecompileResult::revert(gas_limit);
    }
    let Ok((validator, amount)) = parse_staking_args(input, GAS_COST) else {
        return PrecompileResult::revert(GAS_COST);
    };
    let Ok(staking) = require_staking_mutability(call, GAS_COST) else {
        return PrecompileResult::revert(GAS_COST);
    };
    let Ok(completion) = staking.undelegate_for(call.caller, validator, amount) else {
        return PrecompileResult::revert(GAS_COST);
    };
    let staking = Arc::clone(staking_arc(call));
    let delegator = call.caller;
    call.journal.borrow_mut().record(Box::new(move || {
        let _ = staking.undo_undelegate(delegator, validator, amount);
    }));
    PrecompileResult::success(completion.to_le_bytes().to_vec(), GAS_COST)
}

/// Extract the wired staking `Arc` — only called after
/// `require_staking_mutability` has proven `call.staking` is `Some`.
fn staking_arc(call: &NativeCallCtx) -> &Arc<staking::StakingModule> {
    call.staking.as_ref().expect("staking checked by require_staking_mutability")
}

// ── Native market reader ─────────────────────────────────────────────

/// Read-only views into native exchange and perps state.
///
/// This struct is passed to precompile handlers so they can read
/// native module state without having a mutable reference. All
/// methods are read-only — precompiles must never mutate native
/// state.
pub mod native {
    use std::sync::Arc;

    use primitives::Address;

    /// Read-only result for native precompile calls.
    pub type NativeReadResult = super::PrecompileResult;

    /// A read-only handle to native exchange and perps state.
    ///
    /// Holds `Arc` references to the native modules. The EVM
    /// module's `execute` method constructs this from its own
    /// `Option<Arc<ExchangeModule>>` / `Option<Arc<PerpsModule>>`
    /// fields before each EVM call.
    pub struct NativeMarketReader {
        /// The exchange module (for best bid/ask reads).
        pub exchange: Option<Arc<exchange::ExchangeModule>>,
        /// The perps module (for position/mark/insurance reads).
        pub perps: Option<Arc<perps::PerpsModule>>,
    }

    impl NativeMarketReader {
        /// Construct a reader with no native modules (all reads
        /// return empty/zero).
        #[must_use]
        pub fn empty() -> Self {
            Self { exchange: None, perps: None }
        }

        /// Construct a reader with the given exchange and perps
        /// module handles.
        #[must_use]
        pub fn new(
            exchange: Option<Arc<exchange::ExchangeModule>>,
            perps: Option<Arc<perps::PerpsModule>>,
        ) -> Self {
            Self { exchange, perps }
        }
    }

    /// Read the best bid for a market from the exchange module.
    ///
    /// Returns `(price, qty)` as `(u64, u64)` in raw fixed-point
    /// units, or `None` if no bid exists.
    pub fn exchange_best_bid(reader: &NativeMarketReader, market: u8) -> Option<(u64, u64)> {
        let exchange = reader.exchange.as_ref()?;
        let l1 = exchange.l1(market)?;
        l1.0.map(|(price, qty)| (price.0, qty.0))
    }

    /// Read the best ask for a market from the exchange module.
    pub fn exchange_best_ask(reader: &NativeMarketReader, market: u8) -> Option<(u64, u64)> {
        let exchange = reader.exchange.as_ref()?;
        let l1 = exchange.l1(market)?;
        l1.1.map(|(price, qty)| (price.0, qty.0))
    }

    /// Read a position from the perps module.
    pub fn perps_position(
        reader: &NativeMarketReader,
        market: u8,
        account: &Address,
    ) -> Option<perps::Position> {
        let perps = reader.perps.as_ref()?;
        Some(perps.position(account, market))
    }

    /// Read the mark price for a perps market.
    pub fn perps_mark_price(reader: &NativeMarketReader, market: u8) -> Option<u64> {
        let perps = reader.perps.as_ref()?;
        perps.mark_price(market)
    }

    /// Read the perps insurance fund balance.
    pub fn perps_insurance_fund(reader: &NativeMarketReader) -> u64 {
        reader.perps.as_ref().map_or(0, |p| p.insurance_fund())
    }
}

// ── Native precompile handlers ───────────────────────────────────────

/// Gas cost for reading exchange L1 data (best bid/ask).
const GAS_EXCHANGE_L1: u64 = 2_000;
/// Gas cost for reading perps position data.
const GAS_PERPS_POSITION: u64 = 2_000;
/// Gas cost for reading perps mark price.
const GAS_PERPS_MARK: u64 = 1_000;
/// Gas cost for reading perps insurance fund.
const GAS_PERPS_INSURANCE: u64 = 1_000;

/// Execute the exchange best-bid precompile.
///
/// Input: `[market: 1B]`.
/// Output: `[price: 8B LE][qty: 8B LE]` or empty if no bid.
fn execute_exchange_best_bid(
    input: &[u8],
    gas_limit: u64,
    reader: &native::NativeMarketReader,
) -> PrecompileResult {
    if gas_limit < GAS_EXCHANGE_L1 {
        return PrecompileResult::revert(gas_limit);
    }
    if input.len() != 1 {
        return PrecompileResult::revert(GAS_EXCHANGE_L1);
    }
    let market = input[0];
    match native::exchange_best_bid(reader, market) {
        Some((price, qty)) => {
            let mut output = Vec::with_capacity(16);
            output.extend_from_slice(&price.to_le_bytes());
            output.extend_from_slice(&qty.to_le_bytes());
            PrecompileResult::success(output, GAS_EXCHANGE_L1)
        }
        None => PrecompileResult::success(Vec::new(), GAS_EXCHANGE_L1),
    }
}

/// Execute the exchange best-ask precompile.
fn execute_exchange_best_ask(
    input: &[u8],
    gas_limit: u64,
    reader: &native::NativeMarketReader,
) -> PrecompileResult {
    if gas_limit < GAS_EXCHANGE_L1 {
        return PrecompileResult::revert(gas_limit);
    }
    if input.len() != 1 {
        return PrecompileResult::revert(GAS_EXCHANGE_L1);
    }
    let market = input[0];
    match native::exchange_best_ask(reader, market) {
        Some((price, qty)) => {
            let mut output = Vec::with_capacity(16);
            output.extend_from_slice(&price.to_le_bytes());
            output.extend_from_slice(&qty.to_le_bytes());
            PrecompileResult::success(output, GAS_EXCHANGE_L1)
        }
        None => PrecompileResult::success(Vec::new(), GAS_EXCHANGE_L1),
    }
}

/// Execute the perps position precompile.
///
/// Input: `[market: 1B][account: 20B]`.
/// Output: `[size: 8B LE (signed)][entry: 8B LE][margin: 8B LE]`.
fn execute_perps_position(
    input: &[u8],
    gas_limit: u64,
    reader: &native::NativeMarketReader,
) -> PrecompileResult {
    if gas_limit < GAS_PERPS_POSITION {
        return PrecompileResult::revert(gas_limit);
    }
    if input.len() != 21 {
        return PrecompileResult::revert(GAS_PERPS_POSITION);
    }
    let market = input[0];
    let account = Address(input[1..21].try_into().unwrap_or([0u8; 20]));
    let pos = native::perps_position(reader, market, &account).unwrap_or_default();
    let mut output = Vec::with_capacity(24);
    output.extend_from_slice(&pos.size.to_le_bytes());
    output.extend_from_slice(&pos.entry_price.to_le_bytes());
    output.extend_from_slice(&pos.isolated_margin.to_le_bytes());
    PrecompileResult::success(output, GAS_PERPS_POSITION)
}

/// Execute the perps mark-price precompile.
fn execute_perps_mark_price(
    input: &[u8],
    gas_limit: u64,
    reader: &native::NativeMarketReader,
) -> PrecompileResult {
    if gas_limit < GAS_PERPS_MARK {
        return PrecompileResult::revert(gas_limit);
    }
    if input.len() != 1 {
        return PrecompileResult::revert(GAS_PERPS_MARK);
    }
    let market = input[0];
    match native::perps_mark_price(reader, market) {
        Some(mark) => {
            let mut output = Vec::with_capacity(8);
            output.extend_from_slice(&mark.to_le_bytes());
            PrecompileResult::success(output, GAS_PERPS_MARK)
        }
        None => PrecompileResult::success(Vec::new(), GAS_PERPS_MARK),
    }
}

/// Execute the perps insurance-fund precompile.
fn execute_perps_insurance_fund(
    input: &[u8],
    gas_limit: u64,
    reader: &native::NativeMarketReader,
) -> PrecompileResult {
    if gas_limit < GAS_PERPS_INSURANCE {
        return PrecompileResult::revert(gas_limit);
    }
    if !input.is_empty() {
        return PrecompileResult::revert(GAS_PERPS_INSURANCE);
    }
    let balance = native::perps_insurance_fund(reader);
    let mut output = Vec::with_capacity(8);
    output.extend_from_slice(&balance.to_le_bytes());
    PrecompileResult::success(output, GAS_PERPS_INSURANCE)
}

// ── NativePrecompiles provider for revm ──────────────────────────────

/// A custom `PrecompileProvider` that wraps `EthPrecompiles` and
/// adds Oxide-specific read-only precompiles for native exchange
/// and perps state.
///
/// This is wired into the EVM execution path by `EvmModule::execute`
/// so that EVM contracts can call native precompile addresses (e.g.
/// `0x0000...0501` for exchange best bid) and get back native state
/// data.
pub struct NativePrecompiles {
    /// The standard Ethereum precompiles (delegated for non-Oxide
    /// addresses).
    eth: EthPrecompiles,
    /// The combined warm address set (Ethereum + Oxide precompiles).
    warm: AddressSet,
    /// Read-only native market reader.
    pub reader: NativeMarketReader,
    /// The staking module for `0x0C_*` mutating precompiles — `None`
    /// makes those precompiles revert.
    staking: Option<Arc<staking::StakingModule>>,
    /// The transaction's frame-scoped undo log, shared with the
    /// [`NativeJournalInspector`](crate::native_journal::NativeJournalInspector)
    /// attached to the same `Evm`.
    journal: Rc<RefCell<NativeJournal>>,
    /// `true` on simulation paths (`eth_call`/`eth_estimateGas`) —
    /// mutating precompiles revert so a read can never touch native
    /// state.
    read_only: bool,
}

/// The Oxide precompile `(module, op)` pairs kept warm across a tx.
const NATIVE_PRECOMPILES: &[(u8, u8)] = &[
    BANK_TRANSFER,
    BANK_BALANCE,
    STAKING_DELEGATE,
    STAKING_UNDELEGATE,
    EXCHANGE_BEST_BID,
    EXCHANGE_BEST_ASK,
    PERPS_POSITION,
    PERPS_MARK_PRICE,
    PERPS_INSURANCE_FUND,
];

impl NativePrecompiles {
    /// Construct with the given spec, native module readers, and the
    /// transaction's shared undo journal.
    #[must_use]
    pub fn new(
        spec: SpecId,
        reader: NativeMarketReader,
        journal: Rc<RefCell<NativeJournal>>,
    ) -> Self {
        let eth = EthPrecompiles::new(spec);
        let warm = Self::warm_with_native(&eth);
        Self { eth, warm, reader, staking: None, journal, read_only: false }
    }

    /// `eth`'s warm set unioned with every native precompile. These
    /// are the addresses geth's access-list tracer treats as
    /// protocol-warmed and excludes from `eth_createAccessList`
    /// output.
    fn warm_with_native(eth: &EthPrecompiles) -> AddressSet {
        let mut warm = AddressSet::default();
        warm.clone_from(eth.warm_addresses());
        for &(module_id, op_id) in NATIVE_PRECOMPILES {
            warm.insert(revm::primitives::Address::from(precompile_address(module_id, op_id).0));
        }
        warm
    }

    /// The warm address set for `spec` without constructing a
    /// provider — for `eth_createAccessList`'s exclusion set.
    #[must_use]
    pub fn warm_addresses_for(spec: SpecId) -> AddressSet {
        Self::warm_with_native(&EthPrecompiles::new(spec))
    }

    /// Wire the staking module so `0x0C_*` precompiles can mutate
    /// delegation state (journaled for frame-scoped revert).
    #[must_use]
    pub fn with_staking(mut self, staking: Arc<staking::StakingModule>) -> Self {
        self.staking = Some(staking);
        self
    }

    /// Mark this provider read-only — mutating precompiles revert.
    /// Used by `eth_call`/`eth_estimateGas` simulations.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Drain the per-transaction native journal. Called after every
    /// `inspect_*` run: committed ops (depth-0 survivors) are already
    /// applied; anything else has been undone by `frame_end`.
    pub fn clear_native_journal(&self) {
        self.journal.borrow_mut().clear();
    }
}

impl<CTX> revm::handler::PrecompileProvider<CTX> for NativePrecompiles
where
    CTX: revm::context_interface::ContextTr<Cfg: Cfg<Spec = SpecId>>,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let changed = <EthPrecompiles as revm::handler::PrecompileProvider<CTX>>::set_spec(
            &mut self.eth,
            spec,
        );
        if changed {
            self.warm = Self::warm_with_native(&self.eth);
        }
        changed
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &revm::interpreter::CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        let addr_bytes = inputs.bytecode_address.0.0;
        let oxide_addr = Address(addr_bytes);
        if is_precompile(&oxide_addr) {
            let input_bytes: Vec<u8> = inputs.input.as_bytes(context).to_vec();
            let call = NativeCallCtx {
                caller: Address(inputs.caller.0.0),
                is_static: inputs.is_static,
                // Only a real balance transfer can strand funds in the
                // precompile; `CallValue::Apparent` (delegatecall's
                // nominal value) moves nothing.
                has_value: matches!(
                    inputs.value,
                    revm::interpreter::CallValue::Transfer(v) if !v.is_zero()
                ),
                read_only: self.read_only,
                staking: self.staking.clone(),
                journal: Rc::clone(&self.journal),
            };
            let result = execute_precompile(
                &oxide_addr,
                &input_bytes,
                inputs.gas_limit,
                &self.reader,
                &call,
            );
            let status =
                if result.success { PrecompileStatus::Success } else { PrecompileStatus::Revert };
            let output = PrecompileOutput {
                status,
                gas_used: result.gas_used,
                gas_refunded: 0,
                state_gas_used: 0,
                state_gas_spilled: 0,
                reservoir: inputs.reservoir,
                bytes: Bytes::from(result.output),
            };
            let interpreter_result =
                revm::handler::precompile_output_to_interpreter_result(output, inputs.gas_limit);
            return Ok(Some(interpreter_result));
        }
        // Delegate to Ethereum precompiles.
        <EthPrecompiles as revm::handler::PrecompileProvider<CTX>>::run(
            &mut self.eth,
            context,
            inputs,
        )
    }

    fn warm_addresses(&self) -> &AddressSet {
        &self.warm
    }

    fn contains(&self, address: &revm::primitives::Address) -> bool {
        self.warm.contains(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader with no native modules for testing precompile
    /// validation logic (bank/staking stubs).
    fn empty_reader() -> NativeMarketReader {
        NativeMarketReader::empty()
    }

    /// A call context with no staking wired — mutating precompiles
    /// revert. `caller` is `addr(7)`, journal is a fresh log.
    fn call_ctx() -> NativeCallCtx {
        NativeCallCtx {
            caller: Address([7u8; 20]),
            is_static: false,
            has_value: false,
            read_only: false,
            staking: None,
            journal: Rc::new(RefCell::new(NativeJournal::new())),
        }
    }

    /// A call context wired to a bank-backed staking module whose
    /// `validator` is registered and `caller` funded with `balance`.
    fn staking_ctx(
        caller: Address,
        validator: Address,
        balance: u64,
    ) -> (NativeCallCtx, Arc<staking::StakingModule>, Arc<bank::BankModule>) {
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&caller, balance);
        let staking = Arc::new(staking::StakingModule::new());
        staking.set_bank(bank.clone());
        staking.register_validator(validator);
        let ctx = NativeCallCtx {
            caller,
            is_static: false,
            has_value: false,
            read_only: false,
            staking: Some(staking.clone()),
            journal: Rc::new(RefCell::new(NativeJournal::new())),
        };
        (ctx, staking, bank)
    }

    /// `[validator: 20B][amount: 32B BE]` calldata for `0x0C_*` ops.
    fn staking_input(validator: Address, amount: u64) -> Vec<u8> {
        let mut input = Vec::with_capacity(52);
        input.extend_from_slice(validator.as_bytes());
        input.extend_from_slice(&revm::primitives::U256::from(amount).to_be_bytes::<32>());
        input
    }

    #[test]
    fn precompile_address_encoding() {
        let addr = precompile_address(0x0B, 0x01);
        let bytes = addr.as_bytes();
        assert_eq!(bytes[..18], [0u8; 18]);
        assert_eq!(bytes[18], 0x0B);
        assert_eq!(bytes[19], 0x01);
    }

    #[test]
    fn decode_valid_precompile_address() {
        let addr = precompile_address(0x0B, 0x02);
        let decoded = decode_precompile_address(&addr);
        assert_eq!(decoded, Some((0x0B, 0x02)));
    }

    #[test]
    fn decode_rejects_non_precompile_address() {
        // A regular address (non-zero in first 18 bytes) is not a precompile.
        let addr = Address([0x42; 20]);
        assert!(decode_precompile_address(&addr).is_none());
    }

    #[test]
    fn decode_rejects_module_zero() {
        // Module ID 0 is reserved.
        let mut bytes = [0u8; 20];
        bytes[19] = 0x01;
        let addr = Address(bytes);
        assert!(decode_precompile_address(&addr).is_none());
    }

    #[test]
    fn is_precompile_checks() {
        assert!(is_precompile(&precompile_address(0x0B, 0x01)));
        assert!(!is_precompile(&Address([0x42; 20])));
    }

    #[test]
    fn bank_transfer_success() {
        // C5 fix: bank_transfer returns revert (not success) until
        // the executor-side settlement is wired. The precompile
        // validates input but does not perform the transfer.
        let addr = precompile_address(0x0B, 0x01);
        let mut input = vec![0u8; 52];
        input[0] = 0x42; // non-zero "to" address
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader(), &call_ctx());
        assert!(!result.success, "bank_transfer must revert (side effect not wired)");
        assert_eq!(result.gas_used, 21_000);
        assert!(result.output.is_empty());
    }

    #[test]
    fn bank_transfer_rejects_zero_recipient() {
        let addr = precompile_address(0x0B, 0x01);
        let input = vec![0u8; 52]; // all-zero "to" address
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
        assert_eq!(result.gas_used, 21_000);
    }

    #[test]
    fn bank_transfer_rejects_wrong_input_length() {
        let addr = precompile_address(0x0B, 0x01);
        let input = vec![0u8; 40]; // wrong length
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
    }

    #[test]
    fn bank_transfer_reverts_on_insufficient_gas() {
        let addr = precompile_address(0x0B, 0x01);
        let mut input = vec![0u8; 52];
        input[0] = 0x42;
        let result = execute_precompile(&addr, &input, 20_000, &empty_reader(), &call_ctx()); // < 21_000
        assert!(!result.success);
        // C5 fix: OOG charges all available gas (gas_limit), not 0.
        assert_eq!(result.gas_used, 20_000);
    }

    #[test]
    fn bank_balance_returns_32_bytes() {
        let addr = precompile_address(0x0B, 0x02);
        let input = vec![0x42; 20];
        let result = execute_precompile(&addr, &input, 10_000, &empty_reader(), &call_ctx());
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.gas_used, 1_000);
    }

    #[test]
    fn staking_delegate_success() {
        // With a wired bank+staking module the precompile performs
        // the real delegation through the module's invariant path:
        // caller debited, bonded pool credited, delegation recorded.
        let caller = Address([7u8; 20]);
        let validator = Address([0xAA; 20]);
        let (ctx, staking, bank) = staking_ctx(caller, validator, 10_000);
        let addr = precompile_address(0x0C, 0x01);
        let input = staking_input(validator, 1_000);
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader(), &ctx);
        assert!(result.success, "staking_delegate must succeed when wired");
        assert_eq!(result.gas_used, 50_000);
        assert_eq!(staking.delegation(&caller, &validator), 1_000);
        assert_eq!(staking.stake(&validator), 1_000);
        assert_eq!(bank.balance(&caller), 9_000, "delegator debited");
    }

    #[test]
    fn staking_delegate_reverts_unwired() {
        // No staking module wired: the precompile must revert, never
        // silently report success without moving stake.
        let addr = precompile_address(0x0C, 0x01);
        let mut input = vec![0u8; 52];
        input[0] = 0x42; // non-zero validator
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader(), &call_ctx());
        assert!(!result.success, "staking_delegate must revert when unwired");
        assert_eq!(result.gas_used, 50_000);
    }

    #[test]
    fn staking_delegate_reverts_static_call() {
        // STATICCALL into a mutating precompile must revert — state
        // changes in a static frame are forbidden.
        let caller = Address([7u8; 20]);
        let validator = Address([0xAA; 20]);
        let (mut ctx, staking, _bank) = staking_ctx(caller, validator, 10_000);
        ctx.is_static = true;
        let addr = precompile_address(0x0C, 0x01);
        let input = staking_input(validator, 1_000);
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader(), &ctx);
        assert!(!result.success, "static call must revert");
        assert_eq!(staking.delegation(&caller, &validator), 0);
    }

    #[test]
    fn staking_undelegate_success() {
        // delegate then undelegate: the delegation shrinks and an
        // unbonding entry is queued for the delegator.
        let caller = Address([7u8; 20]);
        let validator = Address([0xAA; 20]);
        let (ctx, staking, bank) = staking_ctx(caller, validator, 10_000);
        let delegate_addr = precompile_address(0x0C, 0x01);
        let undelegate_addr = precompile_address(0x0C, 0x02);
        let input = staking_input(validator, 1_000);
        assert!(execute_precompile(&delegate_addr, &input, 100_000, &empty_reader(), &ctx).success);
        let result = execute_precompile(&undelegate_addr, &input, 100_000, &empty_reader(), &ctx);
        assert!(result.success, "undelegate must succeed on an owned delegation");
        // Output carries the completion height (8B LE).
        assert_eq!(result.output.len(), 8);
        assert_eq!(staking.delegation(&caller, &validator), 0);
        assert_eq!(staking.stake(&validator), 0);
        assert_eq!(staking.pending_unbonding().len(), 1);
        assert_eq!(staking.pending_unbonding()[0].delegator, caller);
        assert_eq!(bank.balance(&staking::BONDED_POOL), 1_000, "still bonded until completion");
    }

    #[test]
    fn staking_undelegate_rejects_foreign_delegation() {
        // Security regression: caller 7 has no delegation — its
        // undelegate must revert even though sender 8 delegated.
        let validator = Address([0xAA; 20]);
        let (ctx, staking, bank) = staking_ctx(Address([7u8; 20]), validator, 10_000);
        bank.mint(&Address([8u8; 20]), 10_000);
        let mut other = call_ctx();
        other.staking = ctx.staking.clone();
        other.journal = ctx.journal.clone();
        other.caller = Address([8u8; 20]);
        let addr = precompile_address(0x0C, 0x01);
        let input = staking_input(validator, 1_000);
        let delegated = execute_precompile(&addr, &input, 100_000, &empty_reader(), &other);
        assert!(delegated.success, "sender 8's delegate must succeed");
        let undel = precompile_address(0x0C, 0x02);
        let result = execute_precompile(&undel, &input, 100_000, &empty_reader(), &ctx);
        assert!(!result.success, "must not unbond another account's delegation");
        assert_eq!(staking.delegation(&Address([8u8; 20]), &validator), 1_000);
    }

    #[test]
    fn staking_delegate_rejects_zero_validator() {
        let addr = precompile_address(0x0C, 0x01);
        let input = vec![0u8; 52];
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
    }

    #[test]
    fn unknown_precompile_reverts() {
        let addr = precompile_address(0xFF, 0xFF);
        let result = execute_precompile(&addr, &[], 100_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
    }

    #[test]
    fn non_precompile_address_reverts() {
        let addr = Address([0x42; 20]);
        let result = execute_precompile(&addr, &[], 100_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
    }

    // ── Native precompile tests ──────────────────────────────────

    #[test]
    fn exchange_best_bid_with_empty_reader_returns_empty() {
        let addr = precompile_address(EXCHANGE_BEST_BID.0, EXCHANGE_BEST_BID.1);
        let result = execute_precompile(&addr, &[0u8], 10_000, &empty_reader(), &call_ctx());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_EXCHANGE_L1);
        assert!(result.output.is_empty());
    }

    #[test]
    fn exchange_best_ask_with_empty_reader_returns_empty() {
        let addr = precompile_address(EXCHANGE_BEST_ASK.0, EXCHANGE_BEST_ASK.1);
        let result = execute_precompile(&addr, &[0u8], 10_000, &empty_reader(), &call_ctx());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_EXCHANGE_L1);
        assert!(result.output.is_empty());
    }

    #[test]
    fn perps_position_with_empty_reader_returns_zeros() {
        let addr = precompile_address(PERPS_POSITION.0, PERPS_POSITION.1);
        let mut input = vec![0u8; 21];
        input[1] = 0x42;
        let result = execute_precompile(&addr, &input, 10_000, &empty_reader(), &call_ctx());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_PERPS_POSITION);
        assert_eq!(result.output.len(), 24);
        // All zeros (no position).
        assert!(result.output.iter().all(|&b| b == 0));
    }

    #[test]
    fn perps_mark_price_with_empty_reader_returns_empty() {
        let addr = precompile_address(PERPS_MARK_PRICE.0, PERPS_MARK_PRICE.1);
        let result = execute_precompile(&addr, &[0u8], 10_000, &empty_reader(), &call_ctx());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_PERPS_MARK);
        assert!(result.output.is_empty());
    }

    #[test]
    fn perps_insurance_fund_with_empty_reader_returns_zero() {
        let addr = precompile_address(PERPS_INSURANCE_FUND.0, PERPS_INSURANCE_FUND.1);
        let result = execute_precompile(&addr, &[], 10_000, &empty_reader(), &call_ctx());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_PERPS_INSURANCE);
        assert_eq!(result.output.len(), 8);
        assert!(result.output.iter().all(|&b| b == 0));
    }

    #[test]
    fn exchange_best_bid_rejects_wrong_input_length() {
        let addr = precompile_address(EXCHANGE_BEST_BID.0, EXCHANGE_BEST_BID.1);
        let result = execute_precompile(&addr, &[0u8; 2], 10_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
        assert_eq!(result.gas_used, GAS_EXCHANGE_L1);
    }

    #[test]
    fn perps_position_rejects_wrong_input_length() {
        let addr = precompile_address(PERPS_POSITION.0, PERPS_POSITION.1);
        let result = execute_precompile(&addr, &[0u8; 20], 10_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
        assert_eq!(result.gas_used, GAS_PERPS_POSITION);
    }

    #[test]
    fn exchange_best_bid_reverts_on_insufficient_gas() {
        let addr = precompile_address(EXCHANGE_BEST_BID.0, EXCHANGE_BEST_BID.1);
        let result = execute_precompile(&addr, &[0u8], 1_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
        // C5 fix: OOG charges all available gas (gas_limit), not 0.
        assert_eq!(result.gas_used, 1_000);
    }

    #[test]
    fn perps_insurance_fund_rejects_nonempty_input() {
        let addr = precompile_address(PERPS_INSURANCE_FUND.0, PERPS_INSURANCE_FUND.1);
        let result = execute_precompile(&addr, &[0x42], 10_000, &empty_reader(), &call_ctx());
        assert!(!result.success);
        assert_eq!(result.gas_used, GAS_PERPS_INSURANCE);
    }
}
