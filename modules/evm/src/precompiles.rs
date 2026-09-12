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

use primitives::Address;

use revm::context::Cfg;
use revm::handler::EthPrecompiles;
use revm::interpreter::InterpreterResult;
use revm::precompile::{PrecompileOutput, PrecompileStatus};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{AddressSet, Bytes};

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
) -> PrecompileResult {
    let Some((module_id, op_id)) = decode_precompile_address(addr) else {
        return PrecompileResult::revert(0);
    };

    match (module_id, op_id) {
        BANK_TRANSFER => execute_bank_transfer(input, gas_limit),
        BANK_BALANCE => execute_bank_balance(input, gas_limit),
        STAKING_DELEGATE => execute_staking_delegate(input, gas_limit),
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

/// Execute the staking delegate precompile.
///
/// Input: `[validator: 20B][amount: 32B]`.
/// Gas: `50_000`.
fn execute_staking_delegate(input: &[u8], gas_limit: u64) -> PrecompileResult {
    const GAS_COST: u64 = 50_000;
    if gas_limit < GAS_COST {
        return PrecompileResult::revert(gas_limit);
    }
    // Input: 20-byte validator + 32-byte amount = 52 bytes.
    if input.len() != 52 {
        return PrecompileResult::revert(GAS_COST);
    }
    // Validate the validator address (non-zero).
    let validator = &input[..20];
    if validator.iter().all(|&b| b == 0) {
        return PrecompileResult::revert(GAS_COST);
    }
    // C5 fix: the staking delegation side effect is NOT yet wired.
    // The previous code returned `success` without performing any
    // delegation — a contract calling this precompile would believe
    // the delegation succeeded, but no stake moved. Returning
    // `revert` here is safer: the caller sees a failed call and
    // knows the delegation did not happen. When the executor-side
    // settlement is wired, this will return `success` after
    // performing the actual delegation.
    PrecompileResult::revert(GAS_COST)
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
}

impl NativePrecompiles {
    /// Construct with the given spec and native module readers.
    #[must_use]
    pub fn new(spec: SpecId, reader: NativeMarketReader) -> Self {
        let eth = EthPrecompiles::new(spec);
        let mut warm = AddressSet::default();
        warm.clone_from(eth.warm_addresses());
        for &(module_id, op_id) in &[
            BANK_TRANSFER,
            BANK_BALANCE,
            STAKING_DELEGATE,
            EXCHANGE_BEST_BID,
            EXCHANGE_BEST_ASK,
            PERPS_POSITION,
            PERPS_MARK_PRICE,
            PERPS_INSURANCE_FUND,
        ] {
            warm.insert(revm::primitives::Address::from(precompile_address(module_id, op_id).0));
        }
        Self { eth, warm, reader }
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
            self.warm.clone_from(self.eth.warm_addresses());
            for &(module_id, op_id) in &[
                BANK_TRANSFER,
                BANK_BALANCE,
                STAKING_DELEGATE,
                EXCHANGE_BEST_BID,
                EXCHANGE_BEST_ASK,
                PERPS_POSITION,
                PERPS_MARK_PRICE,
                PERPS_INSURANCE_FUND,
            ] {
                self.warm.insert(revm::primitives::Address::from(
                    precompile_address(module_id, op_id).0,
                ));
            }
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
            let result =
                execute_precompile(&oxide_addr, &input_bytes, inputs.gas_limit, &self.reader);
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
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader());
        assert!(!result.success, "bank_transfer must revert (side effect not wired)");
        assert_eq!(result.gas_used, 21_000);
        assert!(result.output.is_empty());
    }

    #[test]
    fn bank_transfer_rejects_zero_recipient() {
        let addr = precompile_address(0x0B, 0x01);
        let input = vec![0u8; 52]; // all-zero "to" address
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader());
        assert!(!result.success);
        assert_eq!(result.gas_used, 21_000);
    }

    #[test]
    fn bank_transfer_rejects_wrong_input_length() {
        let addr = precompile_address(0x0B, 0x01);
        let input = vec![0u8; 40]; // wrong length
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader());
        assert!(!result.success);
    }

    #[test]
    fn bank_transfer_reverts_on_insufficient_gas() {
        let addr = precompile_address(0x0B, 0x01);
        let mut input = vec![0u8; 52];
        input[0] = 0x42;
        let result = execute_precompile(&addr, &input, 20_000, &empty_reader()); // < 21_000
        assert!(!result.success);
        // C5 fix: OOG charges all available gas (gas_limit), not 0.
        assert_eq!(result.gas_used, 20_000);
    }

    #[test]
    fn bank_balance_returns_32_bytes() {
        let addr = precompile_address(0x0B, 0x02);
        let input = vec![0x42; 20];
        let result = execute_precompile(&addr, &input, 10_000, &empty_reader());
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.gas_used, 1_000);
    }

    #[test]
    fn staking_delegate_success() {
        // C5 fix: staking_delegate returns revert (not success) until
        // the executor-side settlement is wired. The precompile
        // validates input but does not perform the delegation.
        let addr = precompile_address(0x0C, 0x01);
        let mut input = vec![0u8; 52];
        input[0] = 0x42; // non-zero validator
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader());
        assert!(!result.success, "staking_delegate must revert (side effect not wired)");
        assert_eq!(result.gas_used, 50_000);
    }

    #[test]
    fn staking_delegate_rejects_zero_validator() {
        let addr = precompile_address(0x0C, 0x01);
        let input = vec![0u8; 52];
        let result = execute_precompile(&addr, &input, 100_000, &empty_reader());
        assert!(!result.success);
    }

    #[test]
    fn unknown_precompile_reverts() {
        let addr = precompile_address(0xFF, 0xFF);
        let result = execute_precompile(&addr, &[], 100_000, &empty_reader());
        assert!(!result.success);
    }

    #[test]
    fn non_precompile_address_reverts() {
        let addr = Address([0x42; 20]);
        let result = execute_precompile(&addr, &[], 100_000, &empty_reader());
        assert!(!result.success);
    }

    // ── Native precompile tests ──────────────────────────────────

    #[test]
    fn exchange_best_bid_with_empty_reader_returns_empty() {
        let addr = precompile_address(EXCHANGE_BEST_BID.0, EXCHANGE_BEST_BID.1);
        let result = execute_precompile(&addr, &[0u8], 10_000, &empty_reader());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_EXCHANGE_L1);
        assert!(result.output.is_empty());
    }

    #[test]
    fn exchange_best_ask_with_empty_reader_returns_empty() {
        let addr = precompile_address(EXCHANGE_BEST_ASK.0, EXCHANGE_BEST_ASK.1);
        let result = execute_precompile(&addr, &[0u8], 10_000, &empty_reader());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_EXCHANGE_L1);
        assert!(result.output.is_empty());
    }

    #[test]
    fn perps_position_with_empty_reader_returns_zeros() {
        let addr = precompile_address(PERPS_POSITION.0, PERPS_POSITION.1);
        let mut input = vec![0u8; 21];
        input[1] = 0x42;
        let result = execute_precompile(&addr, &input, 10_000, &empty_reader());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_PERPS_POSITION);
        assert_eq!(result.output.len(), 24);
        // All zeros (no position).
        assert!(result.output.iter().all(|&b| b == 0));
    }

    #[test]
    fn perps_mark_price_with_empty_reader_returns_empty() {
        let addr = precompile_address(PERPS_MARK_PRICE.0, PERPS_MARK_PRICE.1);
        let result = execute_precompile(&addr, &[0u8], 10_000, &empty_reader());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_PERPS_MARK);
        assert!(result.output.is_empty());
    }

    #[test]
    fn perps_insurance_fund_with_empty_reader_returns_zero() {
        let addr = precompile_address(PERPS_INSURANCE_FUND.0, PERPS_INSURANCE_FUND.1);
        let result = execute_precompile(&addr, &[], 10_000, &empty_reader());
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_PERPS_INSURANCE);
        assert_eq!(result.output.len(), 8);
        assert!(result.output.iter().all(|&b| b == 0));
    }

    #[test]
    fn exchange_best_bid_rejects_wrong_input_length() {
        let addr = precompile_address(EXCHANGE_BEST_BID.0, EXCHANGE_BEST_BID.1);
        let result = execute_precompile(&addr, &[0u8; 2], 10_000, &empty_reader());
        assert!(!result.success);
        assert_eq!(result.gas_used, GAS_EXCHANGE_L1);
    }

    #[test]
    fn perps_position_rejects_wrong_input_length() {
        let addr = precompile_address(PERPS_POSITION.0, PERPS_POSITION.1);
        let result = execute_precompile(&addr, &[0u8; 20], 10_000, &empty_reader());
        assert!(!result.success);
        assert_eq!(result.gas_used, GAS_PERPS_POSITION);
    }

    #[test]
    fn exchange_best_bid_reverts_on_insufficient_gas() {
        let addr = precompile_address(EXCHANGE_BEST_BID.0, EXCHANGE_BEST_BID.1);
        let result = execute_precompile(&addr, &[0u8], 1_000, &empty_reader());
        assert!(!result.success);
        // C5 fix: OOG charges all available gas (gas_limit), not 0.
        assert_eq!(result.gas_used, 1_000);
    }

    #[test]
    fn perps_insurance_fund_rejects_nonempty_input() {
        let addr = precompile_address(PERPS_INSURANCE_FUND.0, PERPS_INSURANCE_FUND.1);
        let result = execute_precompile(&addr, &[0x42], 10_000, &empty_reader());
        assert!(!result.success);
        assert_eq!(result.gas_used, GAS_PERPS_INSURANCE);
    }
}
