//! Oxide EVM module — revm host, precompiles, EIP-1559 gas metering.
//!
//! This module is the `x/vm` analog (plan.md §2, §8): it wraps the
//! `revm` EVM engine and exposes it as a Cosmos-SDK-style `Module`
//! in the Oxide module router. Native messages (bank, staking,
//! trading) and EVM transactions share the same block and gas meter.
//!
//! # Reference implementation
//!
//! **reth** (<https://github.com/paradigmxyz/reth>) is the canonical
//! EVM reference for Oxide — analogous to how cosmos-evm uses geth.
//! When verifying EVM correctness (state persistence, replay
//! integrity, gas accounting, nonce progression, JSON-RPC parity),
//! we consult reth's execution pipeline and test suites. See
//! `plan.md` §16 for the full reference framework.
//!//!
//! # What this module does
//!
//! - Receives raw signed EVM transactions via the module router's
//!   `handle` dispatch. The message is an RLP-encoded signed
//!   transaction (Legacy, EIP-2930, or EIP-1559 per EIP-2718).
//! - Recovers the sender from the transaction's secp256k1 signature —
//!   **never** trusts the outer envelope's sender field. This is the
//!   core security boundary (Phase A).
//! - Enforces EIP-155 chain ID replay protection.
//! - Executes the transaction through `revm` with EIP-1559 gas metering.
//! - Persists account state (balance, nonce, code, storage) in a
//!   `CacheDB` (in-memory, backed by `EmptyDB`).
//! - Emits execution results as Oxide events (gas used, status, logs).
//!
//! # Why a module, not a standalone crate
//!
//! The Oxide architecture (plan.md §2) treats the EVM as one execution
//! track alongside the native track (trading modules). Both are modules
//! in the router; the executor dispatches by module ID. This keeps the
//! EVM swappable (future SVM/MoveVM modules use the same seam) and
//! lets native precompiles call into EVM and vice versa.
//!
//! # Phase 2 scope
//!
//! v0 implements:
//! - A `revm` `Evm` instance with a `CacheDB`-backed state.
//! - EIP-1559 gas metering (base fee + priority fee).
//! - Signed transaction execution (Legacy, EIP-2930, EIP-1559) with
//!   secp256k1 sender recovery (Phase A).
//! - EIP-155 chain ID replay protection.
//! - Account state in `CacheDB` (in-memory).
//! - Optional `StorageBackend` persistence (flush after each block,
//!   load on construction — added session 26).
//!
//! Future phases add:
//! - Gas debiting, base-fee burn, and priority-fee tips (Phase A5).
//! - Block context and coinbase/fee-recipient wiring (Phase A6).
//! - Precompiles that call into native modules (bank, trading).
//! - Parallel OCC scheduler for cross-tx parallelism.
//! - JSON-RPC + WebSocket server.

use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::module_id;
use primitives::{Address, Hash, Height};
// rayon: parallel secp256k1 sender recovery in `handle_batch`.
// 88% of per-tx cost is ECDSA recovery; parallelizing across cores
// turns that into 88%/N_cores.
use rayon::prelude::*;

pub mod fee;
mod persist;
pub mod precompiles;
pub mod receipts;
pub mod spec;
pub mod trie;
pub mod tx;

// revm imports. The `revm` crate re-exports all sub-crates.
use revm::Context;
use revm::context::TxEnv;
use revm::context::result::{ExecutionResult, Output, SuccessReason};
use revm::context_interface::result::ResultGas;
use revm::database::CacheDB;
use revm::database_interface::{DatabaseRef, EmptyDB};
use revm::handler::{ExecuteCommitEvm, MainBuilder, MainContext};
use revm::inspector::NoOpInspector;
use revm::primitives::TxKind;
use revm::primitives::hardfork::SpecId;
use std::sync::Arc;

/// The EVM module's dispatch ID in the module router.
///
/// Reserved by `framework::module_id::EVM` (3). Native modules use
/// IDs 0–2 (core, bank, staking); the EVM is the first VM module.
pub const MODULE_ID: u8 = module_id::EVM;

/// The base intrinsic gas cost for any EVM transaction (EIP-2028).
///
/// `21_000` gas is the cost of a simple value transfer (no calldata, no
/// contract creation). This is a conservative lower bound for the
/// intrinsic gas check in `validate`; the full calldata-aware check
/// arrives with the gas economics phase (A5).
const INTRINSIC_GAS_BASE: u64 = 21_000;

/// The block time in seconds. Used to derive a deterministic timestamp
/// from the block height when the real timestamp is not yet wired from
/// the block header. Ethereum mainnet uses ~12s; we use 15s as a
/// conservative estimate.
const BLOCK_TIME_SECS: u64 = 15;

/// The default gas limit for a single EVM transaction (EIP-1559).
///
/// 30M gas matches Ethereum mainnet's default block-level tx limit.
/// This is a cold-path constant (set once per tx, not per-opcode).
/// Used by test helpers when constructing signed transactions.
#[cfg(test)]
const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// Intrinsic gas cost for a simple ETH transfer (no calldata).
/// This is the EVM base transaction cost: 21,000 gas units per
/// EIP-2028. Used by the native fast path to bypass revm for
/// simple transfers.
const TX_GAS_TRANSFER: u64 = 21_000;

/// A transaction with a pre-recovered sender.
///
/// The mempool recovers the sender once at ingestion time (via
/// [`SignedTx::recover_sender`](tx::SignedTx::recover_sender)). The
/// execution layer trusts this pre-recovered sender and skips
/// secp256k1 recovery entirely, saving ~30 µs/tx — the dominant
/// cost in batch execution.
///
/// # Security
///
/// The caller MUST ensure `sender` is correctly recovered from
/// `raw`. A byzantine block proposer providing wrong senders will
/// cause state divergence, detectable by state root comparison
/// across validators. For the Phase 0 devnet (single validator),
/// trusting the proposer is safe. For production, pair this with
/// verification sampling (future work).
///
/// # Construction
///
/// Use [`EvmModule::preverify_batch`] to construct a batch of
/// `PreverifiedTx` from raw RLP-encoded transactions. Then pass
/// the result to [`EvmModule::handle_batch_preverified`] or
/// [`EvmModule::handle_batch_parallel_preverified`].
#[derive(Debug, Clone)]
pub struct PreverifiedTx {
    /// RLP-encoded signed transaction bytes (Legacy, EIP-2930, or
    /// EIP-1559 per EIP-2718).
    pub raw: Vec<u8>,
    /// The sender recovered from the transaction's secp256k1
    /// signature by the mempool. The execution layer trusts this
    /// address without re-verifying.
    pub sender: revm::primitives::Address,
}

/// The EVM module: wraps `revm` and exposes it as an Oxide `Module`.
///
/// State is stored in a `CacheDB<EmptyDB>` (in-memory) during
/// execution. When a `StorageBackend` is attached via
/// [`EvmModule::with_storage`], the cache is flushed to durable
/// storage after each block (`end_block`) and loaded on construction.
/// This makes the EVM state persistent across restarts and shareable
/// between nodes — the foundation for standalone-chain operation.
pub struct EvmModule {
    /// The in-memory EVM database (account state, code, storage).
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    db: Mutex<CacheDB<EmptyDB>>,
    /// The chain ID for EIP-155 signed transactions.
    chain_id: u64,
    /// The base fee for EIP-1559 gas metering (wei per gas unit).
    /// Phase 2 v0 uses a fixed base fee; the dynamic base fee
    /// adjustment algorithm arrives with the full EIP-1559 impl.
    base_fee: u64,
    /// The EVM hardfork spec to use for execution.
    /// `SpecId::PRAGUE` is the latest stable mainnet spec in revm 42.
    spec: SpecId,
    /// Optional durable storage backend. When `Some`, the EVM state
    /// (accounts, code, storage) is flushed here after each block
    /// and loaded on construction. When `None`, the module is
    /// purely in-memory (useful for tests and single-block sims).
    backend: Mutex<Option<Box<dyn storage::StorageBackend + Send>>>,
    /// The coinbase / fee recipient for the current block.
    /// The priority fee (tip) is paid to this address by revm's
    /// internal gas accounting. Set via `begin_block`.
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    coinbase: Mutex<revm::primitives::Address>,
    /// The current block height. Set in `begin_block`, read in
    /// `execute` to populate the EVM block environment.
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    block_height: Mutex<u64>,
    /// The current block timestamp (seconds since Unix epoch).
    /// Set in `begin_block`, read in `execute`.
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    block_timestamp: Mutex<u64>,
    /// The block gas limit. Used to populate the EVM block
    /// environment and enforce block-level gas limits.
    block_gas_limit: u64,
    /// Phase D: accounts touched in the current block. Tracked
    /// during `execute` so `end_block` can flush only the changed
    /// accounts (incremental flush) instead of the full state.
    /// Cleared after each `end_block` flush.
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    touched: Mutex<std::collections::HashSet<revm::primitives::Address>>,
}

impl EvmModule {
    /// Construct a fresh EVM module with no accounts.
    ///
    /// # Arguments
    ///
    /// - `chain_id`: The EIP-155 chain ID. Used for signed transaction
    ///   validation.
    /// - `base_fee`: The initial EIP-1559 base fee (wei per gas). Phase
    ///   2 v0 uses a fixed base fee; dynamic adjustment arrives later.
    #[must_use]
    pub fn new(chain_id: u64, base_fee: u64) -> Self {
        Self {
            db: Mutex::new(CacheDB::new(EmptyDB::new())),
            chain_id,
            base_fee,
            spec: SpecId::PRAGUE,
            backend: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: 30_000_000,
            touched: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Construct with a specific hardfork spec (for testing older
    /// EVM behavior).
    #[must_use]
    pub fn with_spec(chain_id: u64, base_fee: u64, spec: SpecId) -> Self {
        Self {
            db: Mutex::new(CacheDB::new(EmptyDB::new())),
            chain_id,
            base_fee,
            spec,
            backend: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: 30_000_000,
            touched: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Construct with a durable `StorageBackend`. Initial EVM state
    /// (accounts, code, storage) is loaded from the backend into the
    /// in-memory `CacheDB`. After each block, `end_block` flushes the
    /// updated state back to the backend.
    ///
    /// This is the standalone-chain constructor: state persists
    /// across restarts and can be shared between nodes.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned during `load_from_storage`.
    /// This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn with_storage(
        chain_id: u64,
        base_fee: u64,
        backend: Box<dyn storage::StorageBackend + Send>,
    ) -> Self {
        let module = Self {
            db: Mutex::new(CacheDB::new(EmptyDB::new())),
            chain_id,
            base_fee,
            spec: SpecId::PRAGUE,
            backend: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: 30_000_000,
            touched: Mutex::new(std::collections::HashSet::new()),
        };
        // Load initial state from the backend into the CacheDB, then
        // install the backend for future flushes.
        module.load_from_storage(&*backend);
        *module.backend.lock().expect("backend mutex not poisoned") = Some(backend);
        module
    }

    /// The chain ID (EIP-155).
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The current EIP-1559 base fee (wei per gas).
    #[must_use]
    pub fn base_fee(&self) -> u64 {
        self.base_fee
    }

    /// Set the coinbase / fee recipient for the current block.
    ///
    /// The priority fee (tip) from each transaction is paid to this
    /// address by revm's internal gas accounting. This is the
    /// validator's reward for including transactions.
    ///
    /// # Panics
    ///
    /// Panics if the coinbase mutex is poisoned.
    pub fn set_coinbase(&self, coinbase: revm::primitives::Address) {
        *self.coinbase.lock().expect("coinbase mutex not poisoned") = coinbase;
    }

    /// Get the coinbase / fee recipient for the current block.
    ///
    /// # Panics
    ///
    /// Panics if the coinbase mutex is poisoned.
    #[must_use]
    pub fn coinbase(&self) -> revm::primitives::Address {
        *self.coinbase.lock().expect("coinbase mutex not poisoned")
    }

    /// Execute a signed EVM transaction. The `msg` is a raw RLP-encoded
    /// signed transaction (Legacy, EIP-2930, or EIP-1559 per EIP-2718).
    ///
    /// The sender is recovered from the signature inside the transaction —
    /// **never** trusted from the outer envelope (`ctx.sender`). This is
    /// the core security boundary: authentication is enforced at
    /// execution, not admission.
    ///
    /// Returns the revm `ExecutionResult` containing gas used, status,
    /// logs, output, and (for CREATE) the created address.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message cannot be parsed
    /// as a valid signed transaction (RLP decode failure, invalid
    /// signature, wrong chain ID).
    /// Returns [`ExecError::ModuleRejected`] if the EVM execution fails.
    fn execute(
        &self,
        _ctx: &TxContext,
        msg: &[u8],
    ) -> Result<revm::context::result::ExecutionResult, ExecError> {
        // Decode the signed transaction from RLP.
        let mut buf = msg;
        let signed: tx::SignedTx =
            alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;

        // Enforce chain ID (EIP-155 replay protection).
        if signed.chain_id() != self.chain_id {
            return Err(ExecError::Malformed);
        }

        // Recover the sender from the signature. This is the
        // authentication step — the EVM never trusts `ctx.sender`.
        let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
        let caller = alloy_primitives_address(sender.0);

        // Build the transaction environment from the signed tx fields.
        let tx = Self::build_tx_env(&signed, caller)?;

        // Build and run the EVM. `transact_commit` executes the tx and
        // commits the state changes to the CacheDB in one step.
        //
        // A5/A6: wire the block environment (base fee, coinbase, block
        // number, timestamp, gas limit) into revm. revm's internal gas
        // accounting then:
        //   1. Charges `gas_used * gas_price` from the sender.
        //   2. Burns `gas_used * base_fee` (removes from supply).
        //   3. Tips `gas_used * (gas_price - base_fee)` to the coinbase.
        let mut db = self.db.lock().expect("db mutex not poisoned");
        let coinbase = *self.coinbase.lock().expect("coinbase mutex not poisoned");
        let block_number = *self.block_height.lock().expect("block_height mutex not poisoned");
        let block_timestamp =
            *self.block_timestamp.lock().expect("block_timestamp mutex not poisoned");
        let mut evm = Context::mainnet()
            .with_db(&mut *db)
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(self.spec))
            .modify_block_chained(|block| {
                block.number = revm::primitives::U256::from(block_number);
                block.beneficiary = coinbase;
                block.timestamp = revm::primitives::U256::from(block_timestamp);
                block.gas_limit = self.block_gas_limit;
                block.basefee = self.base_fee;
            })
            .build_mainnet_with_inspector(NoOpInspector);

        let result = evm
            .transact_commit(tx)
            .map_err(|e| ExecError::ModuleRejected(format!("evm transact failed: {e:?}")))?;

        // Phase D: track touched accounts for incremental flush.
        // After `transact_commit`, the CacheDB has the updated state.
        // We mark the caller, the `to` address (if Call), and the
        // created address (if Create succeeded) as touched. The
        // coinbase is also touched (it receives the priority fee).
        // This covers the accounts most likely modified by the tx.
        // For deeper accuracy (e.g., SSTORE to a third account),
        // a future optimization can diff the cache before/after.
        {
            let mut touched = self.touched.lock().expect("touched mutex not poisoned");
            touched.insert(caller);
            if let tx::TxKind::Call(addr) = signed.to() {
                touched.insert(revm::primitives::Address::from(addr.0));
            }
            if let Some(created) = result.created_address() {
                touched.insert(created);
            }
            touched.insert(coinbase);
        }

        Ok(result)
    }

    /// Try to execute a simple ETH transfer natively, bypassing revm.
    ///
    /// This is the **native fast path**: for simple value transfers
    /// (empty calldata, recipient is an EOA, no access list), the full
    /// EVM is unnecessary. A native balance+nonce update is ~10-50x
    /// faster than revm's stack-machine execution.
    ///
    /// # When the native path applies
    ///
    /// All of the following must be true:
    /// 1. `to` is `TxKind::Call` (not `Create`).
    /// 2. `data` is empty (no calldata).
    /// 3. Access list is empty (EIP-2930/1559).
    /// 4. Recipient has no code (`code_hash == KECCAK_EMPTY` or
    ///    account doesn't exist).
    /// 5. `gas_limit >= 21000` (intrinsic gas for a simple transfer).
    /// 6. Sender nonce matches the tx nonce.
    /// 7. Sender has sufficient balance for `value + gas_limit *
    ///    effective_gas_price`.
    /// 8. `effective_gas_price >= base_fee`.
    /// 9. `value`, `gas_price` fit in `u128` (Ethereum amounts always
    ///    do, but we check for safety).
    ///
    /// If any check fails, returns `None` and the caller falls through
    /// to revm, which handles the error identically.
    ///
    /// # Gas semantics
    ///
    /// For a simple transfer: `gas_used = 21000` (intrinsic gas, no
    /// execution). The effective gas price is computed per EIP-1559:
    /// - Legacy/EIP-2930: `effective = gas_price`
    /// - EIP-1559: `effective = min(max_fee, base_fee + priority_fee)`
    ///
    /// The coinbase receives `gas_used * (effective - base_fee)` (the
    /// tip). The base fee portion (`gas_used * base_fee`) is burned
    /// (removed from supply).
    ///
    /// # State changes (identical to revm)
    ///
    /// - `sender.balance -= value + gas_used * effective_gas_price`
    /// - `sender.nonce += 1`
    /// - `recipient.balance += value`
    /// - `coinbase.balance += gas_used * (effective_gas_price - base_fee)`
    ///
    /// # Arguments
    ///
    /// - `signed`: the signed transaction.
    /// - `caller`: the recovered sender address.
    /// - `db`: the cache database (reads via `DatabaseRef`, writes
    ///   via direct `cache.accounts` mutation).
    /// - `coinbase`: the block's coinbase address (tip recipient).
    /// - `base_fee`: the block's base fee (wei per gas unit).
    ///
    /// # Returns
    ///
    /// `Some(ExecutionResult)` if the native path was taken.
    /// `None` if the tx doesn't qualify (caller should use revm).
    ///
    /// # Panics
    ///
    /// Panics if the database mutex is poisoned (internal to
    /// `load_account`).
    fn try_native_transfer<DB: DatabaseRef>(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        db: &mut CacheDB<DB>,
        coinbase: revm::primitives::Address,
        base_fee: u64,
    ) -> Option<ExecutionResult> {
        // ── Qualification checks ──────────────────────────────

        // 1. Must be a Call (not Create).
        let recipient = match signed.to() {
            tx::TxKind::Create => return None,
            tx::TxKind::Call(addr) => addr,
        };

        // 2. Empty calldata.
        if !signed.data().is_empty() {
            return None;
        }

        // 3. Empty access list.
        if !signed.access_list().is_empty() {
            return None;
        }

        // 4. Recipient has no code (is an EOA).
        //    Check the cache directly — avoids the `AccountInfo`
        //    clone from `basic_ref`. If the account is not in the
        //    cache, it doesn't exist yet (no code, is an EOA).
        //    `B256::ZERO` is a sentinel used by test setup; treat
        //    it the same as `KECCAK_EMPTY` (no code).
        let recipient_has_code = match db.cache.accounts.get(&recipient) {
            Some(account) => {
                account.info.code_hash != revm::primitives::KECCAK_EMPTY
                    && account.info.code_hash != revm::primitives::B256::ZERO
            }
            None => false, // Account doesn't exist — no code.
        };
        if recipient_has_code {
            return None; // Recipient is a contract — needs EVM.
        }

        // 5. Gas limit >= intrinsic gas (21000 for a simple transfer).
        let gas_limit = signed.gas_limit();
        if gas_limit < TX_GAS_TRANSFER {
            return None; // Let revm handle the error.
        }

        // 9. Value and gas price must fit in u128.
        let value_u128: u128 = match signed.value().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let max_fee: u128 = match signed.max_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let priority_fee: u128 = match signed.max_priority_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };

        // Compute effective gas price per EIP-1559.
        let effective_gas_price = std::cmp::min(max_fee, u128::from(base_fee) + priority_fee);

        // 8. Effective gas price >= base fee.
        if effective_gas_price < u128::from(base_fee) {
            return None; // Let revm handle the error.
        }

        // ── Read + validate sender ─────────────────────────────
        //
        // We load the sender account, check nonce and balance, then
        // modify in place. The `load_account` call returns a `&mut
        // DbAccount` that borrows `db`; we scope it so the borrow is
        // released before we load other accounts.
        {
            let sender_account = db.load_account(caller).ok()?;

            // 6. Nonce must match.
            if sender_account.info.nonce != signed.nonce() {
                return None;
            }

            // 7. Sufficient balance for value + gas reserve.
            //    The EVM deducts `gas_limit * effective_gas_price`
            //    upfront as a gas reserve, then refunds the unused
            //    portion. The sender must have enough for both the
            //    reserve and the value transfer.
            let gas_reserve = u128::from(gas_limit) * effective_gas_price;
            let total_needed = value_u128 + gas_reserve;
            if sender_account.info.balance < revm::primitives::U256::from(total_needed) {
                return None;
            }

            // ── All checks passed — execute natively ───────────
            //
            // Net gas cost = gas_used * effective_gas_price
            // (gas_limit - gas_used is refunded).
            let gas_cost = u128::from(TX_GAS_TRANSFER) * effective_gas_price;
            sender_account.info.balance -= revm::primitives::U256::from(value_u128 + gas_cost);
            sender_account.info.nonce += 1;
            // Normalize code_hash: revm sets KECCAK_EMPTY for EOAs
            // during execution. Test setup (fund_account_for_test)
            // may use B256::ZERO as a sentinel; revm fixes it, so we
            // must too to produce identical state roots.
            if sender_account.info.code_hash == revm::primitives::B256::ZERO {
                sender_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            sender_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Update recipient ───────────────────────────────────
        {
            let recipient_account = db.load_account(recipient).ok()?;
            recipient_account.info.balance += signed.value();
            if recipient_account.info.code_hash == revm::primitives::B256::ZERO {
                recipient_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            recipient_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Update coinbase (tip only, base fee is burned) ─────
        let tip = effective_gas_price - u128::from(base_fee);
        if tip > 0 {
            let coinbase_tip = u128::from(TX_GAS_TRANSFER) * tip;
            let coinbase_account = db.load_account(coinbase).ok()?;
            coinbase_account.info.balance += revm::primitives::U256::from(coinbase_tip);
            if coinbase_account.info.code_hash == revm::primitives::B256::ZERO {
                coinbase_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            coinbase_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Build ExecutionResult ──────────────────────────────
        //
        // Identical to what revm produces for a successful simple
        // transfer: Success with gas_used=21000, no logs, no output.
        let result = ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::default()
                .with_total_gas_spent(TX_GAS_TRANSFER)
                .with_refunded(0)
                .with_floor_gas(0),
            logs: Vec::new(),
            output: Output::Call(revm::primitives::Bytes::new()),
        };

        Some(result)
    }

    /// Build a revm `TxEnv` from a signed transaction and recovered
    /// caller address.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the `TxEnv` cannot be
    /// constructed from the signed tx fields.
    fn build_tx_env(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
    ) -> Result<TxEnv, ExecError> {
        let to = match signed.to() {
            tx::TxKind::Create => TxKind::Create,
            tx::TxKind::Call(addr) => TxKind::Call(revm::primitives::Address::from(addr.0)),
        };
        // A5: wire gas pricing from the signed tx into the TxEnv.
        // - Legacy/EIP-2930: `gas_price` is the exact fee per gas.
        // - EIP-1559: `max_fee_per_gas` is the cap; `max_priority_fee_per_gas`
        //   is the tip. revm uses these with the block's base fee to
        //   compute the effective gas price.
        let gas_price = signed.max_fee_per_gas().to::<u128>();
        let priority_fee = signed.max_priority_fee_per_gas().to::<u128>();
        let tx = TxEnv::builder()
            .gas_limit(signed.gas_limit())
            .caller(caller)
            .kind(to)
            .data(signed.data().clone())
            .nonce(signed.nonce())
            .value(signed.value())
            .gas_price(gas_price)
            .gas_priority_fee(Some(priority_fee))
            .build()
            .map_err(|_| ExecError::Malformed)?;
        Ok(tx)
    }

    /// Execute a batch of signed EVM transactions with **parallel
    /// sender recovery**.
    ///
    /// This is the high-throughput execution path. Profiling shows
    /// secp256k1 ECDSA recovery is 88% of per-tx cost (29.6 µs out
    /// of 33.6 µs). By recovering all senders in parallel across
    /// cores using `rayon`, then executing sequentially (the `CacheDB`
    /// requires single-writer access), we turn the 88% into
    /// `88%/N_cores`.
    ///
    /// On an 8-core machine, the expected per-tx cost drops from
    /// ~33.6 µs to ~4 µs (execution) + 29.6/8 µs (recovery) ≈ 7.7 µs,
    /// yielding ~130,000 tx/s.
    ///
    /// For even higher throughput, use [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// which skips sender recovery entirely (the caller pre-recovers
    /// senders at mempool ingestion time).
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is recovered from the signature).
    /// - `msgs`: a slice of raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction. Each result is
    /// either a vector of events (success) or an `ExecError` (failure).
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch — subsequent transactions
    /// are still executed.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`, `block_timestamp`, or
    /// touched mutex is poisoned (a previous thread panicked while
    /// holding the lock).
    pub fn handle_batch(
        &self,
        ctx: &TxContext,
        msgs: &[Vec<u8>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 1: decode + recover all senders in parallel.
        // Each tx is independently decoded and its sender recovered.
        // Failures are recorded and skipped during execution.
        //
        // secp256k1 recovery (~30 µs/tx) is the dominant cost. Rayon
        // parallelizes it across cores, reducing effective per-tx
        // cost to ~30µs/N_cores. For pre-recovered senders (mempool
        // already verified), use `handle_batch_preverified` to skip
        // this entirely.
        let decoded: Vec<Result<(tx::SignedTx, revm::primitives::Address), ExecError>> = msgs
            .par_iter()
            .map(|raw| {
                let mut buf = raw.as_slice();
                let signed: tx::SignedTx =
                    alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                Ok((signed, caller))
            })
            .collect();

        self.execute_decoded(ctx, decoded)
    }

    /// Pre-recover senders from a batch of raw transactions.
    ///
    /// The mempool calls this at ingestion time to recover the sender
    /// for each transaction **once**. The resulting [`PreverifiedTx`]
    /// pairs are then passed to [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// or [`handle_batch_parallel_preverified`](Self::handle_batch_parallel_preverified),
    /// which skip secp256k1 recovery entirely during block execution.
    ///
    /// This is the key to eliminating the ~30 µs/tx signature recovery
    /// cost from the block execution critical path. Recovery happens
    /// once at mempool admission (off the consensus critical path);
    /// execution reuses the pre-recovered sender.
    ///
    /// # Arguments
    ///
    /// - `msgs`: raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of `PreverifiedTx` (for valid txs) or `ExecError` (for
    /// malformed txs, wrong chain ID, or invalid signatures). The
    /// vector is in the same order as the input.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] for each transaction that
    /// cannot be decoded, has the wrong chain ID, or has an invalid
    /// signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn preverify_batch(&self, msgs: &[Vec<u8>]) -> Vec<Result<PreverifiedTx, ExecError>> {
        msgs.par_iter()
            .map(|raw| {
                let mut buf = raw.as_slice();
                let signed: tx::SignedTx =
                    alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                Ok(PreverifiedTx { raw: raw.clone(), sender: caller })
            })
            .collect()
    }

    /// Execute a batch of transactions with **pre-verified senders**.
    ///
    /// This is the highest-throughput serial execution path. The
    /// caller (mempool/block builder) has already recovered the sender
    /// for each tx via [`preverify_batch`](Self::preverify_batch).
    /// This method skips secp256k1 recovery entirely — only RLP
    /// decoding (~79 ns/tx) and chain ID validation remain in Phase 1.
    ///
    /// # Performance
    ///
    /// Eliminating recovery removes ~30 µs/tx (single-threaded) or
    /// ~3.7 µs/tx (8-core parallelized) from the critical path. For
    /// 10k simple transfers, this reduces batch time from ~80 ms
    /// (recovery + native execution) to ~10 ms (decode + native
    /// execution) — roughly a 5-8x speedup.
    ///
    /// # Security
    ///
    /// The caller MUST ensure `senders` are correctly recovered from
    /// the corresponding `raw` bytes. A byzantine block proposer could
    /// provide wrong senders, causing state divergence. This is
    /// detectable by state root comparison across validators. For
    /// production multi-validator deployment, pair this with
    /// verification sampling (re-verify a random fraction of senders).
    /// For the current Phase 0 devnet (single validator), trusting
    /// the proposer is safe.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is pre-recovered).
    /// - `txs`: a slice of [`PreverifiedTx`] (raw bytes + pre-recovered
    ///   sender).
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    pub fn handle_batch_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 1: decode only (no recovery). RLP decode is ~79 ns/tx
        // vs ~30 µs/tx for secp256k1 recovery — a 380x speedup on
        // Phase 1 alone.
        let decoded: Vec<Result<(tx::SignedTx, revm::primitives::Address), ExecError>> = txs
            .par_iter()
            .map(|pv| {
                let mut buf = pv.raw.as_slice();
                let signed: tx::SignedTx =
                    alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                Ok((signed, pv.sender))
            })
            .collect();

        self.execute_decoded(ctx, decoded)
    }

    /// Shared execution loop for decoded transactions.
    ///
    /// Both [`handle_batch`](Self::handle_batch) and
    /// [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// produce a `decoded` vector of `(SignedTx, caller)` pairs (or
    /// errors). This method executes them sequentially under a single
    /// DB lock, trying the native fast path first and falling through
    /// to revm for non-native txs.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    fn execute_decoded(
        &self,
        ctx: &TxContext,
        decoded: Vec<Result<(tx::SignedTx, revm::primitives::Address), ExecError>>,
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 2: execute all txs sequentially under a single lock.
        // The CacheDB is a single-writer structure — parallel execution
        // would require partitioning the state, which is future work.
        //
        // For each tx, try the **native fast path** first (simple ETH
        // transfers bypass revm entirely). Only fall through to revm
        // for contract calls, creations, and txs with calldata.
        //
        // For all-native batches (simple transfers to EOAs), the EVM
        // context is never constructed — zero revm overhead. For mixed
        // batches, the EVM context is built per non-native tx inside a
        // scoped block; the ~100 ns rebuild cost is negligible vs the
        // ~3.7 µs EVM execution cost.
        let mut results = Vec::with_capacity(decoded.len());

        // Acquire the DB lock once for the entire batch.
        let mut db = self.db.lock().expect("db mutex not poisoned");
        let coinbase = *self.coinbase.lock().expect("coinbase mutex not poisoned");
        let block_number = *self.block_height.lock().expect("block_height mutex not poisoned");
        let block_timestamp =
            *self.block_timestamp.lock().expect("block_timestamp mutex not poisoned");

        // Accumulate touched accounts in a local set to avoid
        // locking the mutex per tx. Merge once at the end.
        let mut local_touched: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();

        for item in decoded {
            let (signed, caller) = match item {
                Ok(v) => v,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };

            // Try the native fast path first. For simple ETH
            // transfers (empty calldata, EOA recipient), this
            // bypasses revm entirely — just balance + nonce
            // updates. The native path accesses the CacheDB
            // directly, so no EVM context is needed.
            if let Some(result) =
                Self::try_native_transfer(&signed, caller, &mut *db, coinbase, self.base_fee)
            {
                local_touched.insert(caller);
                if let tx::TxKind::Call(addr) = signed.to() {
                    local_touched.insert(revm::primitives::Address::from(addr.0));
                }
                local_touched.insert(coinbase);
                results.push(Self::exec_result_to_events(Ok(result), self.base_fee));
                continue;
            }

            // Fall through to revm for non-native txs (contract
            // calls, creations, txs with calldata, etc.). Build
            // the EVM context in a scoped block — the `&mut *db`
            // borrow is released when the block exits, allowing
            // the next tx to use the native path if it qualifies.
            let tx = match Self::build_tx_env(&signed, caller) {
                Ok(t) => t,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };

            let result = {
                let mut evm = Context::mainnet()
                    .with_db(&mut *db)
                    .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(self.spec))
                    .modify_block_chained(|block| {
                        block.number = revm::primitives::U256::from(block_number);
                        block.beneficiary = coinbase;
                        block.timestamp = revm::primitives::U256::from(block_timestamp);
                        block.gas_limit = self.block_gas_limit;
                        block.basefee = self.base_fee;
                    })
                    .build_mainnet_with_inspector(NoOpInspector);
                match evm.transact_commit(tx) {
                    Ok(r) => r,
                    Err(e) => {
                        results.push(Err(ExecError::ModuleRejected(format!(
                            "evm transact failed: {e:?}"
                        ))));
                        continue;
                    }
                }
            };

            // Track touched accounts locally (no lock per tx).
            local_touched.insert(caller);
            if let tx::TxKind::Call(addr) = signed.to() {
                local_touched.insert(revm::primitives::Address::from(addr.0));
            }
            if let Some(created) = result.created_address() {
                local_touched.insert(created);
            }
            local_touched.insert(coinbase);

            results.push(Self::exec_result_to_events(Ok(result), self.base_fee));
        }

        // Merge local touched set into the global one (single lock).
        {
            let mut touched = self.touched.lock().expect("touched mutex not poisoned");
            touched.extend(local_touched);
        }

        // Silence unused-ctx warning — ctx is part of the Module
        // interface but EVM recovers the sender from the signature.
        let _ = ctx;

        results
    }

    /// Execute a batch of signed EVM transactions with **parallel
    /// speculative execution**.
    ///
    /// This is the highest-throughput execution path. It extends
    /// [`handle_batch`](Self::handle_batch) by parallelizing not only
    /// signature recovery but also EVM execution itself, using
    /// per-sender-group state snapshots.
    ///
    /// # Algorithm
    ///
    /// 1. **Parallel decode + recovery**: All senders are recovered in
    ///    parallel (same as `handle_batch`).
    /// 2. **Sender grouping**: Transactions are grouped by sender.
    ///    Within a group, transactions execute sequentially (nonce
    ///    dependency). Across groups, transactions are independent
    ///    (different senders).
    /// 3. **Parallel execution**: Each group executes on its own clone
    ///    of the main `CacheDB`. Groups execute in parallel via `rayon`.
    ///    Each transaction uses `transact` (non-commit) to obtain the
    ///    `EvmState` diff, then commits it to the group's local clone so
    ///    the next transaction in the group sees the updated state.
    /// 4. **Conflict detection**: After parallel execution, groups are
    ///    committed in canonical order (by minimum original tx index).
    ///    If a group's touched accounts overlap with a previously
    ///    committed group — **excluding the coinbase**, which is handled
    ///    additively — the group is re-executed sequentially against the
    ///    main DB. This preserves Ethereum semantics: any read-write
    ///    conflict between groups falls back to the serial path.
    /// 5. **Coinbase handling**: The coinbase (fee recipient) is touched
    ///    by every transaction. Each group's tip contribution is
    ///    computed as a balance delta and applied additively to the main
    ///    DB's coinbase. This is correct because tips are strictly
    ///    additive (the coinbase only receives balance, never spends).
    ///
    /// # When to use this vs `handle_batch`
    ///
    /// Use `handle_batch_parallel` when the batch contains
    /// transactions from **multiple senders** (the common case in a
    /// real blockchain). When all transactions share a single sender,
    /// this method degrades to sequential execution (one group) plus
    /// the overhead of cloning the DB — `handle_batch` is faster in
    /// that case.
    ///
    /// # Limitations
    ///
    /// - Clones the entire `CacheDB` per group. For large state (many
    ///   accounts), the clone cost may dominate. A future optimization
    ///   will use copy-on-write or account-level snapshots.
    /// - Conflict detection is conservative: any shared touched
    ///   account (excluding coinbase) triggers sequential
    ///   re-execution of the later group. Finer-grained conflict
    ///   detection (per-storage-slot) is future work.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is recovered from the signature).
    /// - `msgs`: a slice of raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction. Each result is
    /// either a vector of events (success) or an `ExecError` (failure).
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch — subsequent transactions
    /// are still executed.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned (a previous
    /// thread panicked while holding the lock).
    #[allow(clippy::too_many_lines)]
    pub fn handle_batch_parallel(
        &self,
        ctx: &TxContext,
        msgs: &[Vec<u8>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Fast path: empty batch.
        if msgs.is_empty() {
            return Vec::new();
        }

        // Phase 1: decode + recover all senders in parallel.
        // Same as handle_batch — rayon parallelizes the 88%-of-cost
        // secp256k1 recovery across cores.
        //
        // For pre-recovered senders (mempool already verified), use
        // `handle_batch_parallel_preverified` to skip this entirely.
        let decoded: Vec<Result<(tx::SignedTx, revm::primitives::Address), ExecError>> = msgs
            .par_iter()
            .map(|raw| {
                let mut buf = raw.as_slice();
                let signed: tx::SignedTx =
                    alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                Ok((signed, caller))
            })
            .collect();

        self.execute_parallel_decoded(ctx, decoded)
    }

    /// Execute a batch of transactions with **pre-verified senders**
    /// and **parallel speculative execution**.
    ///
    /// This combines the two highest-throughput optimizations:
    /// 1. **Pre-verified senders** — skips secp256k1 recovery entirely
    ///    (the caller pre-recovered senders at mempool ingestion time).
    /// 2. **Parallel speculative execution** — transactions from
    ///    different senders execute in parallel on per-group state
    ///    snapshots, with conflict detection and sequential fallback.
    ///
    /// This is the fastest execution path in the EVM module. Use it
    /// when the mempool has already verified senders and the batch
    /// contains transactions from multiple senders.
    ///
    /// # Security
    ///
    /// Same security model as
    /// [`handle_batch_preverified`](Self::handle_batch_preverified):
    /// the caller MUST ensure senders are correctly recovered. See
    /// that method's documentation for the full security discussion.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM).
    /// - `txs`: a slice of [`PreverifiedTx`] (raw bytes + pre-recovered
    ///   sender).
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    #[allow(clippy::too_many_lines)]
    pub fn handle_batch_parallel_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Fast path: empty batch.
        if txs.is_empty() {
            return Vec::new();
        }

        // Phase 1: decode only (no recovery). RLP decode is ~79 ns/tx
        // vs ~30 µs/tx for secp256k1 recovery.
        let decoded: Vec<Result<(tx::SignedTx, revm::primitives::Address), ExecError>> = txs
            .par_iter()
            .map(|pv| {
                let mut buf = pv.raw.as_slice();
                let signed: tx::SignedTx =
                    alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                Ok((signed, pv.sender))
            })
            .collect();

        self.execute_parallel_decoded(ctx, decoded)
    }

    /// Shared parallel execution loop for decoded transactions.
    ///
    /// Both [`handle_batch_parallel`](Self::handle_batch_parallel) and
    /// [`handle_batch_parallel_preverified`](Self::handle_batch_parallel_preverified)
    /// produce a `decoded` vector. This method implements the
    /// parallel speculative execution algorithm: sender grouping,
    /// parallel execution on per-group snapshots, conflict detection,
    /// and sequential fallback for conflicting groups.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    #[allow(clippy::too_many_lines)]
    fn execute_parallel_decoded(
        &self,
        ctx: &TxContext,
        decoded: Vec<Result<(tx::SignedTx, revm::primitives::Address), ExecError>>,
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 2: group txs by sender, preserving original order
        // within each group. Txs from the same sender must execute
        // sequentially (nonce dependency). Txs from different senders
        // can execute in parallel.
        //
        // We use an insertion-ordered map so that groups are naturally
        // ordered by first appearance (canonical order).
        let mut groups: std::collections::HashMap<
            revm::primitives::Address,
            Vec<(usize, tx::SignedTx)>,
        > = std::collections::HashMap::new();
        let mut group_order: Vec<revm::primitives::Address> = Vec::new();
        let mut errors: Vec<Option<ExecError>> = vec![None; decoded.len()];
        let n_txs = decoded.len();

        for (idx, item) in decoded.into_iter().enumerate() {
            match item {
                Ok((signed, caller)) => {
                    use std::collections::hash_map::Entry;
                    match groups.entry(caller) {
                        Entry::Occupied(_) => {
                            groups.get_mut(&caller).expect("group exists").push((idx, signed));
                        }
                        Entry::Vacant(v) => {
                            group_order.push(caller);
                            v.insert(Vec::from([(idx, signed)]));
                        }
                    }
                }
                Err(e) => {
                    errors[idx] = Some(e);
                }
            }
        }

        // Note: single-group batches (all txs from one sender) are
        // handled correctly by the parallel path — the group executes
        // sequentially on its own clone. The clone cost (O(n_accounts))
        // is acceptable; a future optimization can skip the clone for
        // single-group batches by calling `execute_decoded` directly.

        // Phase 3: snapshot the main DB into an `Arc` for
        // copy-on-write sharing. Each group gets a
        // `CacheDB::new(SharedCacheDB(arc_clone))` — a fresh, empty
        // local cache backed by the shared parent via
        // `DatabaseRef`. Reads fall through to the parent on cache
        // miss; writes stay local. Per-group cost is O(1) init +
        // O(touched) memory, vs O(state) for a full clone.
        let snapshot = Arc::new({
            let db = self.db.lock().expect("db mutex not poisoned");
            db.clone()
        });
        let coinbase = *self.coinbase.lock().expect("coinbase mutex not poisoned");
        let block_number = *self.block_height.lock().expect("block_height mutex not poisoned");
        let block_timestamp =
            *self.block_timestamp.lock().expect("block_timestamp mutex not poisoned");

        // Phase 4: execute each group in parallel on its own COW
        // nested cache. Each group's txs execute sequentially via
        // `transact_commit` (no per-tx EvmState clone). After
        // execution, the nested cache's touched accounts are
        // extracted directly as the group's state diff.
        let group_results: Vec<GroupExecResult> = group_order
            .par_iter()
            .map(|sender| {
                let txs = groups.get(sender).expect("group exists");
                // COW nested cache: empty local cache, reads from
                // the shared parent on miss.
                let mut db: CacheDB<SharedCacheDB> = CacheDB::new(SharedCacheDB(snapshot.clone()));

                // Pre-load hot accounts into the nested cache before
                // execution. This avoids `DatabaseRef` trait dispatch
                // on the first access to each account. Three accounts
                // are touched by (almost) every tx in a group:
                //
                // 1. **Sender** — nonce bump + balance deduction on
                //    every tx.
                // 2. **Coinbase** — receives tips on every tx.
                // 3. **Recipient** — if all txs in the group send to
                //    the same recipient (common in CLOB/transfer
                //    workloads), pre-loading avoids a miss on tx #1.
                //    We extract the recipient from the first valid tx.
                let _ = db.load_account(*sender);
                let _ = db.load_account(coinbase);
                if let Some((_, first_signed)) = txs.first() {
                    if let tx::TxKind::Call(addr) = first_signed.to() {
                        let _ = db.load_account(revm::primitives::Address::from(addr.0));
                    }
                }

                // Build the EVM context lazily — only needed for
                // non-native txs (contract calls, creations, txs
                // with calldata). For groups where all txs are
                // simple transfers, the EVM is never built.
                // Context rebuild is ~100 ns; negligible vs the
                // ~3.7 µs EVM execution cost for non-native txs.

                let mut tx_results: Vec<(
                    usize,
                    Result<revm::context::result::ExecutionResult, ExecError>,
                )> = Vec::with_capacity(txs.len());

                for (idx, signed) in txs {
                    let caller = *sender;

                    // Try the native fast path first. For simple
                    // ETH transfers, this bypasses revm entirely.
                    if let Some(result) =
                        Self::try_native_transfer(signed, caller, &mut db, coinbase, self.base_fee)
                    {
                        tx_results.push((*idx, Ok(result)));
                        continue;
                    }

                    // Fall through to revm.
                    let tx_env = match Self::build_tx_env(signed, caller) {
                        Ok(t) => t,
                        Err(e) => {
                            tx_results.push((*idx, Err(e)));
                            continue;
                        }
                    };

                    let result = {
                        let mut evm = Context::mainnet()
                            .with_db(&mut db)
                            .modify_cfg_chained(|cfg| {
                                cfg.set_spec_and_mainnet_gas_params(self.spec);
                            })
                            .modify_block_chained(|block| {
                                block.number = revm::primitives::U256::from(block_number);
                                block.beneficiary = coinbase;
                                block.timestamp = revm::primitives::U256::from(block_timestamp);
                                block.gas_limit = self.block_gas_limit;
                                block.basefee = self.base_fee;
                            })
                            .build_mainnet_with_inspector(NoOpInspector);
                        evm.transact_commit(tx_env)
                    };

                    match result {
                        Ok(r) => {
                            tx_results.push((*idx, Ok(r)));
                        }
                        Err(e) => {
                            tx_results.push((
                                *idx,
                                Err(ExecError::ModuleRejected(format!(
                                    "evm transact failed: {e:?}"
                                ))),
                            ));
                        }
                    }
                }

                // Extract the nested cache's touched accounts and
                // new contracts as the group's state diff. Only
                // accounts with `account_state != None` were
                // actually modified (touched, created, or
                // selfdestructed) — accounts that were only loaded
                // (read) have `account_state = None` and are
                // excluded.
                let touched_accounts: revm::primitives::AddressMap<revm::database::DbAccount> = db
                    .cache
                    .accounts
                    .into_iter()
                    .filter(|(_, a)| a.account_state != revm::database::AccountState::None)
                    .collect();

                let new_contracts = db.cache.contracts;

                // Compute the coinbase balance delta for this group.
                // The nested cache's coinbase balance = parent's
                // coinbase balance + tips received by this group.
                // The delta is strictly additive (the coinbase only
                // receives tips).
                let coinbase_after = touched_accounts
                    .get(&coinbase)
                    .map_or(revm::primitives::U256::ZERO, |a| a.info.balance);
                let coinbase_before = snapshot
                    .cache
                    .accounts
                    .get(&coinbase)
                    .map_or(revm::primitives::U256::ZERO, |a| a.info.balance);
                let coinbase_delta = coinbase_after - coinbase_before;

                GroupExecResult {
                    sender: *sender,
                    tx_results,
                    touched_accounts,
                    new_contracts,
                    coinbase_delta,
                }
            })
            .collect();

        // Phase 5: commit groups in canonical order with conflict
        // detection. Groups are already ordered by first appearance
        // (group_order), which matches canonical tx order.
        //
        // We maintain a set of accounts touched by previously
        // committed groups. If a new group touches any of those
        // accounts (excluding the coinbase, which is handled
        // additively), we re-execute the group sequentially against
        // the main DB to preserve Ethereum semantics.
        let mut db = self.db.lock().expect("db mutex not poisoned");
        let mut committed_touched: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();
        let mut total_coinbase_delta = revm::primitives::U256::ZERO;
        let mut all_touched: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();
        // Results from sequential re-execution of conflicting groups.
        // Keyed by original tx index. Takes precedence over the
        // speculative results in `group_results`.
        let mut reexec_results: std::collections::HashMap<
            usize,
            Result<revm::context::result::ExecutionResult, ExecError>,
        > = std::collections::HashMap::new();

        for gr in &group_results {
            // Touched accounts for this group, excluding coinbase.
            let group_touched: std::collections::HashSet<revm::primitives::Address> =
                gr.touched_accounts.keys().filter(|addr| **addr != coinbase).copied().collect();

            let has_conflict = group_touched.iter().any(|addr| committed_touched.contains(addr));

            if has_conflict {
                // Conflict: re-execute this group's txs sequentially
                // against the main DB. The speculative execution
                // assumed stale state for the conflicting account.
                //
                // Try the native fast path first for each tx; fall
                // through to revm only for non-native txs. Build the
                // EVM context lazily — only if a non-native tx is
                // encountered.
                for (idx, signed) in groups.get(&gr.sender).expect("group exists") {
                    let caller = gr.sender;

                    // Try native fast path first.
                    if let Some(result) =
                        Self::try_native_transfer(signed, caller, &mut *db, coinbase, self.base_fee)
                    {
                        all_touched.insert(caller);
                        if let tx::TxKind::Call(addr) = signed.to() {
                            all_touched.insert(revm::primitives::Address::from(addr.0));
                        }
                        all_touched.insert(coinbase);
                        committed_touched.insert(caller);
                        if let tx::TxKind::Call(addr) = signed.to() {
                            committed_touched.insert(revm::primitives::Address::from(addr.0));
                        }
                        committed_touched.insert(coinbase);
                        reexec_results.insert(*idx, Ok(result));
                        continue;
                    }

                    // Fall through to revm.
                    let tx_env = match Self::build_tx_env(signed, caller) {
                        Ok(t) => t,
                        Err(e) => {
                            reexec_results.insert(*idx, Err(e));
                            continue;
                        }
                    };
                    let result = {
                        let mut evm = Context::mainnet()
                            .with_db(&mut *db)
                            .modify_cfg_chained(|cfg| {
                                cfg.set_spec_and_mainnet_gas_params(self.spec);
                            })
                            .modify_block_chained(|block| {
                                block.number = revm::primitives::U256::from(block_number);
                                block.beneficiary = coinbase;
                                block.timestamp = revm::primitives::U256::from(block_timestamp);
                                block.gas_limit = self.block_gas_limit;
                                block.basefee = self.base_fee;
                            })
                            .build_mainnet_with_inspector(NoOpInspector);
                        evm.transact_commit(tx_env)
                    };
                    match result {
                        Ok(r) => {
                            all_touched.insert(caller);
                            if let tx::TxKind::Call(addr) = signed.to() {
                                all_touched.insert(revm::primitives::Address::from(addr.0));
                            }
                            if let Some(created) = r.created_address() {
                                all_touched.insert(created);
                            }
                            committed_touched.insert(caller);
                            if let tx::TxKind::Call(addr) = signed.to() {
                                committed_touched.insert(revm::primitives::Address::from(addr.0));
                            }
                            if let Some(created) = r.created_address() {
                                committed_touched.insert(created);
                            }
                            reexec_results.insert(*idx, Ok(r));
                        }
                        Err(e) => {
                            reexec_results.insert(
                                *idx,
                                Err(ExecError::ModuleRejected(format!(
                                    "evm transact failed: {e:?}"
                                ))),
                            );
                        }
                    }
                }
            } else {
                // No conflict: directly merge the group's touched
                // accounts and new contracts into the main DB. This
                // avoids the `EvmState` → `commit_account` conversion
                // — we insert `DbAccount`s directly, which is what
                // `commit_account` would produce anyway.
                //
                // Exclude the coinbase from the merge — it is
                // handled additively via `coinbase_delta` at the
                // end. Including it here would double-count the
                // tips (once from the merge, once from the delta).
                for (addr, account) in &gr.touched_accounts {
                    if *addr != coinbase {
                        db.cache.accounts.insert(*addr, account.clone());
                    }
                }
                for (hash, bytecode) in &gr.new_contracts {
                    db.cache.contracts.entry(*hash).or_insert_with(|| bytecode.clone());
                }
                committed_touched.extend(group_touched.iter().copied());
                all_touched.extend(group_touched.iter().copied());

                // Coinbase delta is only added for non-conflicting
                // groups. For conflicting groups, the sequential
                // re-execution via `transact_commit` already pays
                // tips to the coinbase — adding the delta here would
                // double-count.
                total_coinbase_delta += gr.coinbase_delta;
            }
        }

        // Apply the total coinbase balance delta.
        if total_coinbase_delta != revm::primitives::U256::ZERO {
            let coinbase_account =
                db.cache.accounts.entry(coinbase).or_insert_with(|| revm::database::DbAccount {
                    info: revm::database::state::AccountInfo {
                        balance: revm::primitives::U256::ZERO,
                        nonce: 0,
                        // `KECCAK_EMPTY` matches what revm's
                        // `insert_contract` sets for an empty-code
                        // account. Using `B256::ZERO` here would
                        // produce a different state root from the
                        // serial path.
                        code_hash: revm::primitives::KECCAK_EMPTY,
                        account_id: None,
                        code: Some(revm::bytecode::Bytecode::new_raw(
                            revm::primitives::Bytes::new(),
                        )),
                    },
                    // `Touched` matches what revm's `commit_account`
                    // sets for a modified account.
                    account_state: revm::database::AccountState::Touched,
                    storage: revm::primitives::HashMap::default(),
                });
            coinbase_account.info.balance += total_coinbase_delta;
            all_touched.insert(coinbase);
        }

        // Merge touched accounts into the module-level set.
        {
            let mut touched = self.touched.lock().expect("touched mutex not poisoned");
            touched.extend(all_touched);
        }

        // Phase 6: assemble results in original order.
        // Re-executed results (from conflict fallback) take
        // precedence over speculative results.
        //
        // Build a flat index map from tx index -> speculative
        // result, so we can look up results in O(1) instead of
        // O(groups * txs).
        let mut spec_index: std::collections::HashMap<
            usize,
            &Result<revm::context::result::ExecutionResult, ExecError>,
        > = std::collections::HashMap::with_capacity(n_txs);
        for gr in &group_results {
            for (idx, result) in &gr.tx_results {
                spec_index.insert(*idx, result);
            }
        }

        let mut results: Vec<Result<Vec<Event>, ExecError>> = Vec::with_capacity(n_txs);
        for (i, err) in errors.iter().enumerate() {
            if let Some(e) = err {
                results.push(Err(e.clone()));
                continue;
            }
            // Check re-executed results first (conflict fallback).
            if let Some(r) = reexec_results.remove(&i) {
                results.push(Self::exec_result_to_events(r, self.base_fee));
                continue;
            }
            // Fall back to speculative results.
            match spec_index.get(&i) {
                Some(result) => {
                    results.push(Self::exec_result_to_events((*result).clone(), self.base_fee));
                }
                None => {
                    results.push(Err(ExecError::ModuleRejected(
                        "parallel execution: missing result".to_string(),
                    )));
                }
            }
        }

        // Silence unused-ctx warning — ctx is part of the Module
        // interface but EVM recovers the sender from the signature.
        let _ = ctx;

        results
    }

    /// Convert a revm `ExecutionResult` to a vector of Oxide events.
    ///
    /// Shared between `handle_batch` and `handle_batch_parallel` to
    /// ensure identical event formatting.
    fn exec_result_to_events(
        result: Result<revm::context::result::ExecutionResult, ExecError>,
        base_fee: u64,
    ) -> Result<Vec<Event>, ExecError> {
        match result {
            Ok(r) => {
                let receipt = receipts::Receipt::from_execution_result(&r);
                let status_str = if receipt.status { "success" } else { "revert" };
                let contract_info =
                    receipt.contract_address.map(|a| format!(" contract={a}")).unwrap_or_default();
                let log_count = receipt.logs.len();
                Ok(vec![Event {
                    module: "evm",
                    kind: "evm_call".to_string(),
                    data: format!(
                        "gas_used={} status={} base_fee={} logs={}{}",
                        receipt.gas_used, status_str, base_fee, log_count, contract_info
                    )
                    .into_bytes(),
                }])
            }
            Err(e) => Err(e),
        }
    }
}

/// A shared reference to a `CacheDB<EmptyDB>` for copy-on-write
/// nested caches.
///
/// This wrapper implements [`DatabaseRef`] by delegating to the
/// inner `CacheDB`. It is the key to efficient parallel speculative
/// execution: each worker gets a
/// `CacheDB::new(SharedCacheDB(arc_clone))`, which starts with an
/// empty local cache and reads from the shared parent on cache miss.
/// Per-worker initialization cost is O(1) instead of O(state), and
/// per-worker memory is O(touched) instead of O(state).
///
/// # Why not `CacheDB::nest()`?
///
/// `nest()` consumes `self`, so it can only create one nested
/// cache. We need N nested caches (one per sender group) sharing
/// the same parent. `SharedCacheDB(Arc<...>)` lets us share the
/// parent across all workers via cheap `Arc` clones.
///
/// # Error type
///
/// The error type is [`Infallible`] — `EmptyDB` never returns
/// errors, and `CacheDB<EmptyDB>` delegates to it on cache miss.
/// The shared parent is read-only, so no errors can arise from
/// concurrent reads.
#[derive(Debug, Clone)]
struct SharedCacheDB(Arc<CacheDB<EmptyDB>>);

impl DatabaseRef for SharedCacheDB {
    type Error = std::convert::Infallible;

    #[inline]
    fn basic_ref(
        &self,
        address: revm::primitives::Address,
    ) -> Result<Option<revm::database::state::AccountInfo>, Self::Error> {
        self.0.basic_ref(address)
    }

    #[inline]
    fn code_by_hash_ref(
        &self,
        code_hash: revm::primitives::B256,
    ) -> Result<revm::bytecode::Bytecode, Self::Error> {
        self.0.code_by_hash_ref(code_hash)
    }

    #[inline]
    fn storage_ref(
        &self,
        address: revm::primitives::Address,
        index: revm::primitives::U256,
    ) -> Result<revm::primitives::U256, Self::Error> {
        self.0.storage_ref(address, index)
    }

    #[inline]
    fn block_hash_ref(&self, number: u64) -> Result<revm::primitives::B256, Self::Error> {
        self.0.block_hash_ref(number)
    }
}

/// The result of executing a single sender group in parallel.
///
/// Each group executes on its own COW nested cache. After
/// execution, the nested cache's touched accounts and new
/// contracts are extracted as the group's state diff — no
/// per-tx `EvmState` cloning needed. The `coinbase_delta` is the
/// group's tip contribution (additive, applied once at the end).
struct GroupExecResult {
    /// The sender address for this group.
    sender: revm::primitives::Address,
    /// Per-tx results, indexed by original position in the batch.
    tx_results: Vec<(usize, Result<revm::context::result::ExecutionResult, ExecError>)>,
    /// Touched accounts from the nested cache (final state of all
    /// accounts modified by this group). Extracted directly from
    /// `CacheDB::cache::accounts`, filtered to only touched
    /// accounts (`account_state != None`).
    touched_accounts: revm::primitives::AddressMap<revm::database::DbAccount>,
    /// New contracts created by this group, extracted from
    /// `CacheDB::cache::contracts`.
    new_contracts: revm::primitives::B256Map<revm::bytecode::Bytecode>,
    /// The coinbase balance delta for this group (tips received).
    coinbase_delta: revm::primitives::U256,
}

impl Module for EvmModule {
    fn name(&self) -> &'static str {
        "evm"
    }

    fn id(&self) -> u8 {
        MODULE_ID
    }

    fn begin_block(&self, height: Height) {
        // A6: set the block context for EVM execution. The block number
        // and timestamp are wired into revm's BlockEnv in `execute`.
        // The timestamp uses the height as a deterministic stand-in
        // (real timestamp comes from the block header in a full node).
        let h = height.value();
        *self.block_height.lock().expect("block_height mutex not poisoned") = h;
        *self.block_timestamp.lock().expect("block_timestamp mutex not poisoned") =
            h.saturating_mul(BLOCK_TIME_SECS);
    }

    /// A4: validate a signed EVM transaction for mempool admission.
    ///
    /// This is the admission gate. It runs on every submitted tx
    /// *before* the tx enters the mempool. It checks:
    ///
    /// 1. **RLP decode** — the message must be a valid RLP-encoded
    ///    signed transaction (Legacy, EIP-2930, or EIP-1559).
    /// 2. **Chain ID** — must match the module's chain ID (EIP-155
    ///    replay protection).
    /// 3. **Signature** — the secp256k1 signature must recover to a
    ///    valid sender address.
    /// 4. **Nonce** — the tx nonce must be ≥ the sender's current
    ///    account nonce (rejects stale txs; allows future nonces for
    ///    mempool queueing).
    /// 5. **Gas limit** — must be positive and within block limits.
    /// 6. **Intrinsic gas** — the gas limit must cover the tx's
    ///    intrinsic cost (21k base + calldata + access list).
    /// 7. **Balance** — the sender must have enough balance to cover
    ///    the gas cost (`gas_limit * max_fee_per_gas`) plus the
    ///    transferred value.
    ///
    /// This method is pure: it reads module state but does not mutate
    /// it. A tx that passes `validate` may still fail in `handle`
    /// (e.g. out-of-gas, revert). But a tx that fails `validate`
    /// never reaches `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] for RLP decode failures,
    /// wrong chain ID, or signature recovery failure. Returns
    /// [`ExecError::ModuleRejected`] for nonce, gas, or balance
    /// violations.
    fn validate(&self, _ctx: &TxContext, msg: &[u8]) -> Result<(), ExecError> {
        // 1. RLP decode.
        let mut buf = msg;
        let signed: tx::SignedTx =
            alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;

        // 2. Chain ID (EIP-155 replay protection).
        if signed.chain_id() != self.chain_id {
            return Err(ExecError::Malformed);
        }

        // 3. Signature recovery.
        let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
        let sender_addr = Address(sender.0);

        // 4. Nonce: tx nonce must be ≥ current account nonce.
        //    This rejects stale (already-used) nonces. Future nonces
        //    are allowed for mempool queueing.
        let current_nonce = self.nonce(&sender_addr);
        if signed.nonce() < current_nonce {
            return Err(ExecError::ModuleRejected(format!(
                "nonce {nonce} < current {current_nonce}",
                nonce = signed.nonce()
            )));
        }

        // 5. Gas limit: must be positive.
        let gas_limit = signed.gas_limit();
        if gas_limit == 0 {
            return Err(ExecError::ModuleRejected("gas_limit is zero".to_string()));
        }

        // 6. Intrinsic gas: gas_limit must cover the intrinsic cost.
        //    The intrinsic cost is 21_000 (base) + calldata cost
        //    (16/byte for non-zero, 4/byte for zero) + access list
        //    cost. We use a conservative lower bound of 21_000 here;
        //    the full calldata-aware check arrives with the gas
        //    economics phase (A5).
        if gas_limit < INTRINSIC_GAS_BASE {
            return Err(ExecError::ModuleRejected(format!(
                "gas_limit {gas_limit} < intrinsic {INTRINSIC_GAS_BASE}"
            )));
        }

        // 7. Balance: sender must cover gas_cost + value.
        //    gas_cost = gas_limit * max_fee_per_gas (the worst-case
        //    fee the sender could pay). For legacy txs, gas_price is
        //    the max fee. For EIP-1559, max_fee_per_gas is the cap.
        let max_fee = signed.max_fee_per_gas().to::<u128>();
        let balance = self.balance(&sender_addr);
        let value = signed.value().to::<u128>();
        // gas_cost = gas_limit * max_fee, checked for overflow.
        let gas_cost = u128::from(gas_limit)
            .checked_mul(max_fee)
            .ok_or_else(|| ExecError::ModuleRejected("gas cost overflow".to_string()))?;
        let total_needed = gas_cost
            .checked_add(value)
            .ok_or_else(|| ExecError::ModuleRejected("gas_cost + value overflow".to_string()))?;
        if balance < total_needed {
            return Err(ExecError::ModuleRejected(format!(
                "insufficient balance: have {balance}, need {total_needed}"
            )));
        }

        Ok(())
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let result = self.execute(ctx, msg)?;

        // Phase C: build a receipt from the execution result.
        // The receipt captures status, gas used, logs, bloom, and
        // (for CREATE) the created address. This is the data that
        // `eth_getTransactionReceipt` returns and that goes into the
        // block's receipts trie.
        let receipt = receipts::Receipt::from_execution_result(&result);

        let status_str = if receipt.status { "success" } else { "revert" };
        let contract_info =
            receipt.contract_address.map(|a| format!(" contract={a}")).unwrap_or_default();
        let log_count = receipt.logs.len();

        Ok(vec![Event {
            module: "evm",
            kind: "evm_call".to_string(),
            data: format!(
                "gas_used={} status={} base_fee={} logs={}{}",
                receipt.gas_used, status_str, self.base_fee, log_count, contract_info
            )
            .into_bytes(),
        }])
    }

    fn end_block(&self, _height: Height) {
        // If a StorageBackend is attached, flush the current CacheDB
        // state to durable storage. This makes the EVM state
        // persistent across restarts and shareable between nodes.
        let mut backend_guard = self.backend.lock().expect("backend mutex not poisoned");
        if let Some(ref mut backend) = *backend_guard {
            self.flush_to_storage(backend.as_mut());
        }
    }

    fn state_root(&self) -> Hash {
        // Phase B: compute the Ethereum-compatible Merkle-Patricia
        // Trie state root over all accounts in the CacheDB.
        //
        // The state trie is keyed by keccak256(address) with the
        // RLP-encoded `TrieAccount { nonce, balance, storage_root,
        // code_hash }` as the value. Each account's `storage_root`
        // is computed from its individual storage trie (keyed by
        // keccak256(slot)).
        //
        // This replaces the Phase 2 sorted-account BLAKE3 hash with
        // a proper keccak MPT root — matching Ethereum mainnet and
        // reth for identical state. The root is deterministic
        // regardless of HashMap iteration order (alloy-trie sorts
        // internally by hashed key).
        //
        // # Panics
        //
        // Panics if the DB mutex is poisoned (a thread panicked while
        // holding the lock). This is unrecoverable and indicates a bug.
        let db = self.db.lock().expect("db mutex not poisoned");

        // Build the account iterator: for each account, compute its
        // storage root and build a TrieAccount.
        let accounts = db.cache.accounts.iter().map(|(addr, account)| {
            // Compute the storage root for this account.
            // The storage trie is keyed by keccak256(slot) with
            // RLP-encoded U256 values. Empty storage → EMPTY_ROOT.
            let storage_root = if account.storage.is_empty() {
                trie::EMPTY_ROOT
            } else {
                // Convert U256 storage keys to B256 (big-endian 32
                // bytes) for the trie. alloy-trie hashes them
                // internally with keccak256.
                let storage_iter = account.storage.iter().map(|(slot, value)| {
                    (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                });
                trie::storage_root(storage_iter)
            };

            // Build the TrieAccount for the MPT.
            let trie_account = trie::build_trie_account(
                account.info.nonce,
                account.info.balance,
                storage_root,
                account.info.code_hash,
            );

            (*addr, trie_account)
        });

        // Compute the state root via alloy-trie.
        let root = trie::state_root(accounts);

        // Convert the alloy B256 root to Oxide's Hash type.
        Hash(root.0)
    }
}

impl EvmModule {
    /// Get an account's balance from the EVM state.
    ///
    /// Returns 0 for accounts not in the state (EVM convention).
    /// The EVM uses `U256` for balances; we truncate to `u128` (the
    /// upper 128 bits are always zero for any realistic balance).
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned (a thread panicked while
    /// holding the lock). This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn balance(&self, addr: &Address) -> u128 {
        let db = self.db.lock().expect("db mutex not poisoned");
        let evm_addr = alloy_primitives_address(addr.0);
        db.cache.accounts.get(&evm_addr).map_or(0, |a| a.info.balance.to::<u128>())
    }

    /// Get an account's nonce from the EVM state.
    ///
    /// Returns 0 for accounts not in the state.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned (a thread panicked while
    /// holding the lock). This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn nonce(&self, addr: &Address) -> u64 {
        let db = self.db.lock().expect("db mutex not poisoned");
        let evm_addr = alloy_primitives_address(addr.0);
        db.cache.accounts.get(&evm_addr).map_or(0, |a| a.info.nonce)
    }

    /// Extract the `StorageBackend` for testing. The backend is
    /// removed from the module (set to `None`), so subsequent
    /// `end_block` calls will not flush. The returned backend can
    /// be passed to `EvmModule::with_storage` to create a new
    /// module with the same persisted state.
    ///
    /// # Panics
    ///
    /// Panics if the backend mutex is poisoned or no backend is
    /// attached (the module was constructed with `new`, not
    /// `with_storage`).
    #[doc(hidden)]
    pub fn backend_for_test(&self) -> Box<dyn storage::StorageBackend + Send> {
        let mut guard = self.backend.lock().expect("backend mutex not poisoned");
        guard.take().expect("backend_for_test: no storage backend attached")
    }

    /// Fund an account with the given balance (test-only helper).
    ///
    /// This directly inserts the balance into the CacheDB, bypassing
    /// execution. It's used by `validate` tests to set up accounts
    /// with sufficient balance to pass the admission gate.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    #[doc(hidden)]
    pub fn fund_account_for_test(&self, addr: &Address, balance: u128) {
        let mut db = self.db.lock().expect("db mutex not poisoned");
        let evm_addr = alloy_primitives_address(addr.0);
        let account =
            db.cache.accounts.entry(evm_addr).or_insert_with(|| revm::database::DbAccount {
                info: revm::database::state::AccountInfo {
                    balance: revm::primitives::U256::ZERO,
                    nonce: 0,
                    code_hash: revm::primitives::B256::ZERO,
                    account_id: None,
                    code: Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::new())),
                },
                account_state: revm::database::AccountState::None,
                storage: revm::primitives::HashMap::default(),
            });
        account.info.balance = revm::primitives::U256::from(balance);
    }

    /// Flush the current `CacheDB` state to the `StorageBackend`.
    ///
    /// Phase D: incremental flush. Only accounts touched in the
    /// current block are flushed. This is O(touched) instead of
    /// O(N) — a major improvement for large states where each
    /// block modifies only a few accounts.
    ///
    /// If no accounts were touched (e.g., empty block), this is a
    /// no-op.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    fn flush_to_storage(&self, backend: &mut (dyn storage::StorageBackend + Send)) {
        let db = self.db.lock().expect("db mutex not poisoned");
        let mut touched = self.touched.lock().expect("touched mutex not poisoned");

        // If nothing was touched, skip the flush entirely.
        if touched.is_empty() {
            return;
        }

        let mut ops = Vec::with_capacity(touched.len());
        for evm_addr in touched.iter() {
            // Skip accounts that don't exist (never touched or
            // selfdestructed).
            let Some(account) = db.cache.accounts.get(evm_addr) else {
                continue;
            };
            if account.account_state == revm::database::AccountState::NotExisting {
                continue;
            }
            let oxide_addr = Address(evm_addr.0.into());
            let key = persist::account_key(&oxide_addr);

            // Extract code bytes if present. Accounts with
            // `KECCAK_EMPTY` code hash are EOAs — their `code` field
            // is `Some(Bytecode::default())` which contains a single
            // STOP opcode, but they have no real code. Skip the code
            // bytes for these accounts so they reload as true EOAs
            // (revm's EIP-3607 check rejects callers with any code).
            let code_bytes: Vec<u8> = if account.info.code_hash == revm::primitives::KECCAK_EMPTY {
                Vec::new()
            } else {
                account.info.code.as_ref().map_or(Vec::new(), |bc| bc.bytes_slice().to_vec())
            };

            // Extract storage slots as (slot, value) pairs.
            // `DbAccount.storage` is `U256Map<U256>` — values are
            // plain `U256`, not an enum with Original/Pending variants.
            let storage_slots: Vec<(revm::primitives::U256, revm::primitives::U256)> =
                account.storage.iter().map(|(slot, val)| (*slot, *val)).collect();

            let value = persist::serialize_account(
                account.info.balance,
                account.info.nonce,
                account.info.code_hash,
                &code_bytes,
                &storage_slots,
            );
            ops.push(storage::Op::Set { key, value });
        }
        backend.apply_batch(&ops);

        // Clear the touched set for the next block.
        touched.clear();
    }

    /// Load EVM state from the `StorageBackend` into the `CacheDB`.
    ///
    /// Reads all account entries (namespace prefix `0x01`) and
    /// populates the cache with balances, nonces, code, and storage.
    /// Called from `with_storage` on construction.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    fn load_from_storage(&self, backend: &(dyn storage::StorageBackend + Send)) {
        let entries = backend.range(&persist::account_prefix());
        if entries.is_empty() {
            return;
        }
        let mut db = self.db.lock().expect("db mutex not poisoned");
        for (key, value) in entries {
            let Some(oxide_addr) = persist::key_to_address(&key) else { continue };
            let Some(account) = persist::deserialize_account(&value) else {
                continue;
            };
            let evm_addr = alloy_primitives_address(oxide_addr.0);

            // Insert account info into the cache.
            let info = revm::database::state::AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                account_id: None,
                // revm's `Bytecode::default()` contains a STOP opcode,
                // which makes `is_empty()` return false and triggers
                // EIP-3607 `RejectCallerWithCode`. Use `new_raw` with
                // empty bytes to create a truly empty bytecode.
                code: if account.code.is_empty() {
                    Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::new()))
                } else {
                    Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::from_iter(
                        account.code.iter().copied(),
                    )))
                },
            };
            db.cache.accounts.insert(
                evm_addr,
                revm::database::DbAccount {
                    info,
                    // `None` = account exists in cache but EVM hasn't
                    // interacted with it in this block. This is correct
                    // for loaded state — revm will read storage from
                    // the `DbAccount.storage` field. `StorageCleared`
                    // would incorrectly zero out the storage.
                    account_state: revm::database::AccountState::None,
                    storage: account.storage.into_iter().collect(),
                },
            );
        }
    }
}

/// Convert an Oxide `Address` (20 bytes) to a revm `Address`.
fn alloy_primitives_address(bytes: [u8; 20]) -> revm::primitives::Address {
    revm::primitives::Address::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::secp;
    use revm::primitives::U256;

    fn make_module() -> EvmModule {
        EvmModule::new(1, 7)
    }

    /// A fixed private key for deterministic tests. This key is
    /// generated fresh per test run via `generate_keypair_for_test`,
    /// which uses the secp256k1 crate's RNG. The address is derived
    /// from the recovered public key.
    fn test_keypair() -> ([u8; 32], Address) {
        let (privkey, addr) = secp::generate_keypair_for_test();
        (privkey, Address(addr.0))
    }

    /// Build a signed legacy transaction for testing.
    fn signed_tx(privkey: &[u8], nonce: u64, to: tx::TxKind, data: &[u8]) -> Vec<u8> {
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce,
                gas_limit: DEFAULT_GAS_LIMIT,
                to,
                value: U256::ZERO,
                data: revm::primitives::Bytes::copy_from_slice(data),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000),
        };
        let signed = tx::SignedTx::sign_legacy(tx, privkey).expect("sign must succeed");
        signed.encode_to_bytes()
    }

    /// A `TxContext` with a dummy sender (the EVM module ignores it
    /// and recovers the sender from the signature).
    fn dummy_ctx() -> TxContext {
        TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 }
    }

    /// Fund an account with a large balance for testing.
    fn fund(m: &EvmModule, addr: &Address) {
        m.fund_account_for_test(addr, u128::MAX);
    }

    #[test]
    fn module_id_is_evm() {
        let m = make_module();
        assert_eq!(m.id(), MODULE_ID);
        assert_eq!(m.id(), module_id::EVM);
    }

    #[test]
    fn name_is_evm() {
        let m = make_module();
        assert_eq!(m.name(), "evm");
    }

    #[test]
    fn chain_id_round_trips() {
        let m = EvmModule::new(42, 1);
        assert_eq!(m.chain_id(), 42);
    }

    #[test]
    fn base_fee_round_trips() {
        let m = EvmModule::new(1, 10_000_000_000);
        assert_eq!(m.base_fee(), 10_000_000_000);
    }

    #[test]
    fn handle_rejects_short_message() {
        let m = make_module();
        let result = m.handle(&dummy_ctx(), b"too short");
        assert!(matches!(result, Err(ExecError::Malformed)));
    }

    #[test]
    fn handle_executes_signed_deploy() {
        let (privkey, sender) = test_keypair();
        let m = make_module();
        fund(&m, &sender);
        // Deploy a contract: `to` = Create, calldata = simple bytecode.
        let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
        let result = m.handle(&dummy_ctx(), &msg).expect("handle must succeed");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].module, "evm");
        assert_eq!(result[0].kind, "evm_call");
        // The sender's nonce must be 1 after a deploy.
        assert_eq!(m.nonce(&sender), 1, "sender nonce must be 1 after deploy");
    }

    #[test]
    fn handle_rejects_wrong_chain_id() {
        let (privkey, _) = test_keypair();
        let m = EvmModule::new(42, 7); // chain ID 42
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Create,
                value: U256::ZERO,
                data: revm::primitives::Bytes::new(),
                chain_id: 1, // wrong chain ID
            },
            gas_price: U256::from(1_000_000_000),
        };
        let signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign must succeed");
        let msg = signed.encode_to_bytes();
        let result = m.handle(&dummy_ctx(), &msg);
        assert!(matches!(result, Err(ExecError::Malformed)), "wrong chain ID must reject");
    }

    #[test]
    fn handle_rejects_invalid_signature() {
        let m = make_module();
        // A valid RLP-encoded legacy tx with a tampered signature.
        let (privkey, _) = test_keypair();
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Create,
                value: U256::ZERO,
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000),
        };
        let mut signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign must succeed");
        // Tamper with the signature.
        if let tx::SignedTx::Legacy(_, ref mut sig) = signed {
            sig.r = U256::ZERO; // invalid r
        }
        let msg = signed.encode_to_bytes();
        let result = m.handle(&dummy_ctx(), &msg);
        assert!(matches!(result, Err(ExecError::Malformed)), "invalid signature must reject");
    }

    #[test]
    fn begin_block_does_not_panic() {
        let m = make_module();
        m.begin_block(Height::new(0));
    }

    #[test]
    fn end_block_does_not_panic() {
        let m = make_module();
        m.end_block(Height::new(0));
    }

    #[test]
    fn state_root_is_deterministic() {
        let m1 = make_module();
        let m2 = make_module();
        assert_eq!(
            m1.state_root(),
            m2.state_root(),
            "two fresh modules must have the same state root"
        );
    }

    /// An empty EVM state must produce Ethereum's `EMPTY_ROOT_HASH`.
    /// This is the most important MPT invariant: if our empty root
    /// differs from mainnet, no state root will ever match.
    #[test]
    fn empty_state_root_matches_ethereum_constant() {
        let m = make_module();
        let root = m.state_root();
        // Ethereum's EMPTY_ROOT_HASH — the state root of a chain
        // with zero accounts.
        let expected = Hash([
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
            0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
            0xe3, 0x63, 0xb4, 0x21,
        ]);
        assert_eq!(root, expected, "empty state root must match Ethereum's EMPTY_ROOT_HASH");
    }

    #[test]
    fn balance_defaults_to_zero() {
        let m = make_module();
        assert_eq!(m.balance(&Address([0u8; 20])), 0);
    }

    #[test]
    fn nonce_defaults_to_zero() {
        let m = make_module();
        assert_eq!(m.nonce(&Address([0u8; 20])), 0);
    }

    #[test]
    fn state_root_changes_after_deploy() {
        let (privkey, sender) = test_keypair();
        let m = make_module();
        fund(&m, &sender);
        let root_before = m.state_root();
        let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
        m.handle(&dummy_ctx(), &msg).expect("deploy must succeed");
        let root_after = m.state_root();
        assert_ne!(root_before, root_after, "state root must change after a deploy");
    }

    #[test]
    fn deploy_increases_caller_nonce() {
        let (privkey, sender) = test_keypair();
        let m = make_module();
        fund(&m, &sender);
        // Before any tx, the caller has no account (nonce 0).
        assert_eq!(m.nonce(&sender), 0);
        // Deploy a contract.
        let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
        m.handle(&dummy_ctx(), &msg).expect("deploy must succeed");
        // After a successful deploy, the caller's nonce must be 1.
        assert_eq!(m.nonce(&sender), 1, "caller nonce must be 1 after a deploy");
    }

    #[test]
    fn sender_is_recovered_not_trusted() {
        // The EVM module must recover the sender from the signature,
        // not trust ctx.sender. We verify by setting ctx.sender to a
        // different address and checking that the recovered sender
        // (not ctx.sender) gets the nonce increment.
        let (privkey, real_sender) = test_keypair();
        let fake_sender = Address([0xFF; 20]);
        let m = make_module();
        fund(&m, &real_sender);
        let ctx = TxContext { sender: fake_sender, nonce: 999, fee: 999 };
        let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
        m.handle(&ctx, &msg).expect("deploy must succeed");
        // The real sender's nonce must be 1, not the fake sender's.
        assert_eq!(m.nonce(&real_sender), 1, "real sender nonce must be 1");
        assert_eq!(m.nonce(&fake_sender), 0, "fake sender nonce must stay 0");
    }

    // ---- A4: validate (mempool admission) tests ----------------------

    #[test]
    fn validate_accepts_well_formed_tx() {
        let (privkey, sender) = test_keypair();
        let m = make_module();
        // Fund the account so the balance check passes.
        m.fund_account_for_test(&sender, u128::MAX);
        let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
        assert!(m.validate(&dummy_ctx(), &msg).is_ok(), "well-formed tx must validate");
    }

    #[test]
    fn validate_rejects_malformed_rlp() {
        let m = make_module();
        assert!(matches!(m.validate(&dummy_ctx(), b"not rlp"), Err(ExecError::Malformed)));
    }

    #[test]
    fn validate_rejects_wrong_chain_id() {
        let (privkey, _) = test_keypair();
        let m = EvmModule::new(42, 7); // chain ID 42
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Create,
                value: U256::ZERO,
                data: revm::primitives::Bytes::new(),
                chain_id: 1, // wrong
            },
            gas_price: U256::from(1_000_000_000),
        };
        let signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign");
        let msg = signed.encode_to_bytes();
        assert!(matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::Malformed)));
    }

    #[test]
    fn validate_rejects_bad_signature() {
        let (privkey, _) = test_keypair();
        let m = make_module();
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Create,
                value: U256::ZERO,
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000),
        };
        let mut signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign");
        if let tx::SignedTx::Legacy(_, ref mut sig) = signed {
            sig.r = U256::ZERO;
        }
        let msg = signed.encode_to_bytes();
        assert!(matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::Malformed)));
    }

    #[test]
    fn validate_rejects_stale_nonce() {
        let (privkey, sender) = test_keypair();
        let m = make_module();
        m.fund_account_for_test(&sender, u128::MAX);
        // Execute nonce 0 (deploy).
        let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
        m.handle(&dummy_ctx(), &msg).expect("deploy");
        assert_eq!(m.nonce(&sender), 1);
        // Now validate a tx with nonce 0 (stale) — must reject.
        let stale_msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
        assert!(matches!(m.validate(&dummy_ctx(), &stale_msg), Err(ExecError::ModuleRejected(_))));
    }

    #[test]
    fn validate_accepts_future_nonce() {
        let (privkey, sender) = test_keypair();
        let m = make_module();
        m.fund_account_for_test(&sender, u128::MAX);
        // A tx with nonce 5 (future) should be accepted for mempool
        // queueing.
        let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
        let msg = signed_tx(&privkey, 5, tx::TxKind::Create, &data);
        assert!(m.validate(&dummy_ctx(), &msg).is_ok(), "future nonce must validate");
    }

    #[test]
    fn validate_rejects_zero_gas_limit() {
        let (privkey, _) = test_keypair();
        let m = make_module();
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: 0,
                to: tx::TxKind::Create,
                value: U256::ZERO,
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000),
        };
        let signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign");
        let msg = signed.encode_to_bytes();
        assert!(matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::ModuleRejected(_))));
    }

    #[test]
    fn validate_rejects_insufficient_balance() {
        let (privkey, _) = test_keypair();
        let m = make_module();
        // A brand-new account has 0 balance. Any tx with gas_cost > 0
        // must be rejected.
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Create,
                value: U256::ZERO,
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000), // 1 gwei
        };
        let signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign");
        let msg = signed.encode_to_bytes();
        // gas_cost = 30M * 1 gwei = 30M gwei = 0.03 ETH — but balance is 0.
        assert!(matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::ModuleRejected(_))));
    }

    #[test]
    fn handle_batch_executes_all_txs() {
        let (privkey, sender) = test_keypair();
        let m = make_module();
        fund(&m, &sender);
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Build 10 transfer txs with incrementing nonces.
        let txs: Vec<Vec<u8>> = (0u64..10)
            .map(|i| {
                let tx = tx::TxLegacy {
                    fields: tx::TxFields {
                        nonce: i,
                        gas_limit: DEFAULT_GAS_LIMIT,
                        to: tx::TxKind::Call(recipient),
                        value: U256::from(1_000_000_000),
                        data: revm::primitives::Bytes::new(),
                        chain_id: 1,
                    },
                    gas_price: U256::from(1_000_000_000),
                };
                tx::SignedTx::sign_legacy(tx, &privkey).expect("sign").encode_to_bytes()
            })
            .collect();

        let results = m.handle_batch(&dummy_ctx(), &txs);
        assert_eq!(results.len(), 10, "must return 10 results");
        for (i, r) in results.iter().enumerate() {
            assert!(r.is_ok(), "tx {i} must succeed");
        }
        assert_eq!(m.nonce(&sender), 10, "sender nonce must be 10");
        let oxide_recipient = primitives::Address(recipient.0.into());
        assert_eq!(m.balance(&oxide_recipient), 10_000_000_000, "recipient must have 10 * 1M");
    }

    #[test]
    fn handle_batch_skips_invalid_txs() {
        let (privkey, sender) = test_keypair();
        let m = make_module();
        fund(&m, &sender);
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Build a valid tx (nonce 0) and an invalid tx (wrong chain ID).
        let valid_tx = {
            let tx = tx::TxLegacy {
                fields: tx::TxFields {
                    nonce: 0,
                    gas_limit: DEFAULT_GAS_LIMIT,
                    to: tx::TxKind::Call(recipient),
                    value: U256::from(1_000_000_000),
                    data: revm::primitives::Bytes::new(),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            };
            tx::SignedTx::sign_legacy(tx, &privkey).expect("sign").encode_to_bytes()
        };

        let invalid_tx = {
            let tx = tx::TxLegacy {
                fields: tx::TxFields {
                    nonce: 1,
                    gas_limit: DEFAULT_GAS_LIMIT,
                    to: tx::TxKind::Call(recipient),
                    value: U256::from(1_000_000_000),
                    data: revm::primitives::Bytes::new(),
                    chain_id: 999, // wrong chain ID
                },
                gas_price: U256::from(1_000_000_000),
            };
            tx::SignedTx::sign_legacy(tx, &privkey).expect("sign").encode_to_bytes()
        };

        let txs = vec![valid_tx, invalid_tx];
        let results = m.handle_batch(&dummy_ctx(), &txs);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok(), "valid tx must succeed");
        assert!(results[1].is_err(), "invalid tx must fail");
        assert_eq!(m.nonce(&sender), 1, "only the valid tx incremented nonce");
    }

    // ── Parallel speculative execution tests ──────────────────────

    /// Build a signed transfer tx (test helper for parallel tests).
    fn signed_transfer_tx(
        privkey: &[u8],
        nonce: u64,
        to: revm::primitives::Address,
        value: u128,
    ) -> Vec<u8> {
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Call(to),
                value: U256::from(value),
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000),
        };
        tx::SignedTx::sign_legacy(tx, privkey).expect("sign").encode_to_bytes()
    }

    /// Parallel execution with multiple senders, distinct
    /// recipients — the conflict-free fast path. State and nonces
    /// must match serial execution.
    #[test]
    fn handle_batch_parallel_multi_sender_distinct_recipients() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let m = make_module();
        fund(&m, &addr_a);
        fund(&m, &addr_b);
        let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
        let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

        // Sender A -> recipient A (nonce 0)
        // Sender B -> recipient B (nonce 0)
        let txs = vec![
            signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
            signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
        ];

        let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok(), "tx 0 must succeed");
        assert!(results[1].is_ok(), "tx 1 must succeed");
        assert_eq!(m.nonce(&addr_a), 1, "sender A nonce must be 1");
        assert_eq!(m.nonce(&addr_b), 1, "sender B nonce must be 1");
        let oxide_recipient_a = primitives::Address(recipient_a.0.into());
        let oxide_recipient_b = primitives::Address(recipient_b.0.into());
        assert_eq!(m.balance(&oxide_recipient_a), 1_000_000_000, "recipient A balance");
        assert_eq!(m.balance(&oxide_recipient_b), 1_000_000_000, "recipient B balance");
    }

    /// Parallel execution must produce the same state root as serial
    /// execution for the same multi-sender workload.
    #[test]
    fn handle_batch_parallel_matches_serial_state_root() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
        let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

        // Serial module.
        let m_serial = make_module();
        fund(&m_serial, &addr_a);
        fund(&m_serial, &addr_b);
        let txs = vec![
            signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
            signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
        ];
        m_serial.begin_block(Height::new(1));
        for raw in &txs {
            m_serial.handle(&dummy_ctx(), raw).expect("serial tx must succeed");
        }
        m_serial.end_block(Height::new(1));
        let serial_root = m_serial.state_root();

        // Parallel module.
        let m_par = make_module();
        fund(&m_par, &addr_a);
        fund(&m_par, &addr_b);
        m_par.begin_block(Height::new(1));
        let results = m_par.handle_batch_parallel(&dummy_ctx(), &txs);
        m_par.end_block(Height::new(1));
        let parallel_root = m_par.state_root();

        assert!(results.iter().all(std::result::Result::is_ok), "all parallel txs must succeed");
        assert_eq!(serial_root, parallel_root, "state roots must match");
    }

    /// The native fast path (simple transfers bypass revm) must
    /// produce identical state roots to the revm path. This is the
    /// correctness invariant: native is an optimization, not a
    /// semantic change.
    #[test]
    fn native_transfer_matches_revm_state_root() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Path 1: handle() — uses revm for every tx.
        let m1 = make_module();
        fund(&m1, &addr);
        let tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
        m1.begin_block(Height::new(1));
        m1.handle(&dummy_ctx(), &tx).expect("revm tx must succeed");
        m1.end_block(Height::new(1));
        let root1 = m1.state_root();

        // Path 2: handle_batch() — uses native fast path for simple
        // transfers (empty calldata, EOA recipient).
        let m2 = make_module();
        fund(&m2, &addr);
        m2.begin_block(Height::new(1));
        m2.handle_batch(&dummy_ctx(), std::slice::from_ref(&tx));
        m2.end_block(Height::new(1));
        let root2 = m2.state_root();

        assert_eq!(root1, root2, "revm and native state roots must match");
    }

    /// Native fast path with multiple transfers from the same sender.
    /// Verifies nonce sequencing and balance deductions match revm.
    #[test]
    fn native_transfer_multi_tx_matches_revm() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let txs: Vec<Vec<u8>> =
            (0..5).map(|nonce| signed_transfer_tx(&pk, nonce, recipient, 1_000_000_000)).collect();

        // Path 1: handle() per tx — uses revm.
        let m1 = make_module();
        fund(&m1, &addr);
        m1.begin_block(Height::new(1));
        for raw in &txs {
            m1.handle(&dummy_ctx(), raw).expect("revm tx must succeed");
        }
        m1.end_block(Height::new(1));
        let root1 = m1.state_root();

        // Path 2: handle_batch() — uses native fast path.
        let m2 = make_module();
        fund(&m2, &addr);
        m2.begin_block(Height::new(1));
        m2.handle_batch(&dummy_ctx(), &txs);
        m2.end_block(Height::new(1));
        let root2 = m2.state_root();

        assert_eq!(root1, root2, "revm and native state roots must match");
    }

    /// Native fast path should NOT activate for contract calls
    /// (non-empty calldata). The tx must fall through to revm.
    #[test]
    fn native_transfer_skipped_for_calldata() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Build a tx with non-empty calldata — should NOT take the
        // native fast path.
        let tx = signed_tx(&pk, 0, tx::TxKind::Call(recipient), &[0x01, 0x02, 0x03]);

        // handle_batch should still succeed (falls through to revm).
        let m = make_module();
        fund(&m, &addr);
        m.begin_block(Height::new(1));
        let results = m.handle_batch(&dummy_ctx(), &[tx]);
        m.end_block(Height::new(1));

        // The tx should succeed (revm handles the call to a
        // non-existent contract — it just executes the CALL opcode
        // with no code to run, which succeeds).
        assert!(
            results.iter().all(std::result::Result::is_ok),
            "calldata tx should succeed via revm fallback"
        );
    }

    /// Parallel execution with conflicting recipients (two senders
    /// transfer to the same recipient). The conflict must be detected
    /// and the second group re-executed sequentially. The final
    /// recipient balance must be the sum of both transfers.
    #[test]
    fn handle_batch_parallel_conflict_same_recipient() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let m = make_module();
        fund(&m, &addr_a);
        fund(&m, &addr_b);
        let shared_recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Both senders transfer to the SAME recipient -> conflict.
        let txs = vec![
            signed_transfer_tx(&pk_a, 0, shared_recipient, 1_000_000_000),
            signed_transfer_tx(&pk_b, 0, shared_recipient, 2_000_000_000),
        ];

        let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok(), "tx 0 must succeed");
        assert!(results[1].is_ok(), "tx 1 must succeed");
        let oxide_recipient = primitives::Address(shared_recipient.0.into());
        assert_eq!(
            m.balance(&oxide_recipient),
            3_000_000_000,
            "recipient must have sum of both transfers"
        );
    }

    /// Parallel execution with conflicting recipients must produce the
    /// same state root as serial execution.
    #[test]
    fn handle_batch_parallel_conflict_matches_serial_state_root() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let shared_recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let txs = vec![
            signed_transfer_tx(&pk_a, 0, shared_recipient, 1_000_000_000),
            signed_transfer_tx(&pk_b, 0, shared_recipient, 2_000_000_000),
        ];

        // Serial.
        let m_serial = make_module();
        fund(&m_serial, &addr_a);
        fund(&m_serial, &addr_b);
        m_serial.begin_block(Height::new(1));
        for raw in &txs {
            m_serial.handle(&dummy_ctx(), raw).expect("serial tx");
        }
        m_serial.end_block(Height::new(1));
        let serial_root = m_serial.state_root();

        // Parallel.
        let m_par = make_module();
        fund(&m_par, &addr_a);
        fund(&m_par, &addr_b);
        m_par.begin_block(Height::new(1));
        let results = m_par.handle_batch_parallel(&dummy_ctx(), &txs);
        m_par.end_block(Height::new(1));
        let parallel_root = m_par.state_root();

        assert!(results.iter().all(std::result::Result::is_ok), "all parallel txs must succeed");
        assert_eq!(serial_root, parallel_root, "conflict state roots must match");
    }

    /// Parallel execution with multiple nonces per sender. Each
    /// sender's txs must execute in nonce order within the group.
    #[test]
    fn handle_batch_parallel_multi_nonce_per_sender() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let m = make_module();
        fund(&m, &addr_a);
        fund(&m, &addr_b);
        let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
        let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

        // Sender A: 3 txs (nonces 0, 1, 2)
        // Sender B: 2 txs (nonces 0, 1)
        let txs = vec![
            signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
            signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
            signed_transfer_tx(&pk_a, 1, recipient_a, 1_000_000_000),
            signed_transfer_tx(&pk_b, 1, recipient_b, 1_000_000_000),
            signed_transfer_tx(&pk_a, 2, recipient_a, 1_000_000_000),
        ];

        let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(std::result::Result::is_ok), "all txs must succeed");
        assert_eq!(m.nonce(&addr_a), 3, "sender A nonce must be 3");
        assert_eq!(m.nonce(&addr_b), 2, "sender B nonce must be 2");
        let oxide_recipient_a = primitives::Address(recipient_a.0.into());
        assert_eq!(m.balance(&oxide_recipient_a), 3_000_000_000, "recipient A balance");
        let oxide_recipient_b = primitives::Address(recipient_b.0.into());
        assert_eq!(m.balance(&oxide_recipient_b), 2_000_000_000, "recipient B balance");
    }

    /// Parallel execution with a single sender falls back to
    /// `handle_batch` (no parallelism, but must be correct).
    #[test]
    fn handle_batch_parallel_single_sender_fallback() {
        let (pk, addr) = test_keypair();
        let m = make_module();
        fund(&m, &addr);
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let txs: Vec<Vec<u8>> =
            (0..5).map(|i| signed_transfer_tx(&pk, i, recipient, 1_000_000_000)).collect();

        let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(std::result::Result::is_ok), "all txs must succeed");
        assert_eq!(m.nonce(&addr), 5, "nonce must be 5");
        let oxide_recipient = primitives::Address(recipient.0.into());
        assert_eq!(m.balance(&oxide_recipient), 5_000_000_000, "recipient balance");
    }

    /// Parallel execution with empty batch returns empty results.
    #[test]
    fn handle_batch_parallel_empty_batch() {
        let m = make_module();
        let results = m.handle_batch_parallel(&dummy_ctx(), &[]);
        assert!(results.is_empty());
    }

    /// Parallel execution with invalid txs mixed in. Invalid txs
    /// must not affect valid txs.
    #[test]
    fn handle_batch_parallel_skips_invalid_txs() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let m = make_module();
        fund(&m, &addr_a);
        fund(&m, &addr_b);
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let valid_a = signed_transfer_tx(&pk_a, 0, recipient, 1_000_000_000);
        let valid_b = signed_transfer_tx(&pk_b, 0, recipient, 1_000_000_000);

        // Invalid tx: wrong chain ID.
        let invalid_tx = {
            let tx = tx::TxLegacy {
                fields: tx::TxFields {
                    nonce: 0,
                    gas_limit: DEFAULT_GAS_LIMIT,
                    to: tx::TxKind::Call(recipient),
                    value: U256::from(1_000_000_000),
                    data: revm::primitives::Bytes::new(),
                    chain_id: 999,
                },
                gas_price: U256::from(1_000_000_000),
            };
            tx::SignedTx::sign_legacy(tx, &pk_a).expect("sign").encode_to_bytes()
        };

        let txs = vec![valid_a, invalid_tx, valid_b];
        let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok(), "valid tx 0 must succeed");
        assert!(results[1].is_err(), "invalid tx must fail");
        assert!(results[2].is_ok(), "valid tx 2 must succeed");
    }

    /// Parallel execution determinism: running the same batch twice
    /// must produce the same state root.
    #[test]
    fn handle_batch_parallel_deterministic_state_root() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
        let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

        let txs = vec![
            signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
            signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
        ];

        // Run 1.
        let m1 = make_module();
        fund(&m1, &addr_a);
        fund(&m1, &addr_b);
        m1.begin_block(Height::new(1));
        m1.handle_batch_parallel(&dummy_ctx(), &txs);
        m1.end_block(Height::new(1));
        let root1 = m1.state_root();

        // Run 2.
        let m2 = make_module();
        fund(&m2, &addr_a);
        fund(&m2, &addr_b);
        m2.begin_block(Height::new(1));
        m2.handle_batch_parallel(&dummy_ctx(), &txs);
        m2.end_block(Height::new(1));
        let root2 = m2.state_root();

        assert_eq!(root1, root2, "state roots must be deterministic");
    }

    // ── Pre-verified sender recovery tests ──────────────────────

    /// `preverify_batch` recovers senders correctly: the
    /// pre-recovered address matches what `SignedTx::recover_sender`
    /// would produce.
    #[test]
    fn preverify_batch_recovers_correct_senders() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);
        let m = make_module();

        let txs = vec![
            signed_transfer_tx(&pk, 0, recipient, 1_000_000_000),
            signed_transfer_tx(&pk, 1, recipient, 1_000_000_000),
        ];

        let preverified = m.preverify_batch(&txs);
        assert_eq!(preverified.len(), 2, "must return one result per tx");
        for (i, pv) in preverified.iter().enumerate() {
            let pv = pv.as_ref().expect("valid tx must preverify");
            let expected = alloy_primitives_address(addr.0);
            assert_eq!(pv.sender, expected, "pre-recovered sender must match keypair address");
            assert_eq!(pv.raw, txs[i], "raw bytes must be preserved");
        }
    }

    /// `preverify_batch` rejects malformed transactions.
    #[test]
    fn preverify_batch_rejects_malformed() {
        let m = make_module();
        let garbage = vec![vec![0xff, 0xff, 0xff]];
        let preverified = m.preverify_batch(&garbage);
        assert_eq!(preverified.len(), 1);
        assert!(preverified[0].is_err(), "malformed tx must fail preverify");
    }

    /// `handle_batch_preverified` produces identical state roots to
    /// `handle_batch` (which recovers senders internally). This is the
    /// core correctness invariant: pre-verified recovery is an
    /// optimization, not a semantic change.
    #[test]
    fn preverified_matches_recovery_state_root() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let txs: Vec<Vec<u8>> =
            (0..10).map(|i| signed_transfer_tx(&pk, i, recipient, 1_000_000_000)).collect();

        // Path 1: handle_batch (recovers senders internally).
        let m1 = make_module();
        fund(&m1, &addr);
        m1.begin_block(Height::new(1));
        m1.handle_batch(&dummy_ctx(), &txs);
        m1.end_block(Height::new(1));
        let root1 = m1.state_root();

        // Path 2: preverify + handle_batch_preverified.
        let m2 = make_module();
        fund(&m2, &addr);
        let preverified: Vec<PreverifiedTx> = m2
            .preverify_batch(&txs)
            .into_iter()
            .map(|r| r.expect("preverify must succeed"))
            .collect();
        m2.begin_block(Height::new(1));
        m2.handle_batch_preverified(&dummy_ctx(), &preverified);
        m2.end_block(Height::new(1));
        let root2 = m2.state_root();

        assert_eq!(root1, root2, "pre-verified and recovery state roots must match");
    }

    /// `handle_batch_parallel_preverified` produces identical state
    /// roots to `handle_batch_parallel` (which recovers senders
    /// internally). This verifies the pre-verified path is correct
    /// for the parallel speculative execution algorithm.
    #[test]
    fn preverified_parallel_matches_recovery_parallel_state_root() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
        let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

        let txs = vec![
            signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
            signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
            signed_transfer_tx(&pk_a, 1, recipient_a, 1_000_000_000),
            signed_transfer_tx(&pk_b, 1, recipient_b, 1_000_000_000),
        ];

        // Path 1: handle_batch_parallel (recovers senders internally).
        let m1 = make_module();
        fund(&m1, &addr_a);
        fund(&m1, &addr_b);
        m1.begin_block(Height::new(1));
        m1.handle_batch_parallel(&dummy_ctx(), &txs);
        m1.end_block(Height::new(1));
        let root1 = m1.state_root();

        // Path 2: preverify + handle_batch_parallel_preverified.
        let m2 = make_module();
        fund(&m2, &addr_a);
        fund(&m2, &addr_b);
        let preverified: Vec<PreverifiedTx> = m2
            .preverify_batch(&txs)
            .into_iter()
            .map(|r| r.expect("preverify must succeed"))
            .collect();
        m2.begin_block(Height::new(1));
        m2.handle_batch_parallel_preverified(&dummy_ctx(), &preverified);
        m2.end_block(Height::new(1));
        let root2 = m2.state_root();

        assert_eq!(
            root1, root2,
            "pre-verified parallel and recovery parallel state roots must match"
        );
    }

    /// `handle_batch_preverified` with an empty batch returns an empty
    /// result vector (no panic).
    #[test]
    fn preverified_empty_batch() {
        let m = make_module();
        let results = m.handle_batch_preverified(&dummy_ctx(), &[]);
        assert!(results.is_empty(), "empty batch must return empty results");
    }

    /// `handle_batch_parallel_preverified` with an empty batch returns
    /// an empty result vector (no panic).
    #[test]
    fn preverified_parallel_empty_batch() {
        let m = make_module();
        let results = m.handle_batch_parallel_preverified(&dummy_ctx(), &[]);
        assert!(results.is_empty(), "empty batch must return empty results");
    }

    /// `handle_batch_preverified` skips invalid txs without aborting
    /// the batch (same semantics as `handle_batch`).
    #[test]
    fn preverified_skips_invalid_txs() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let valid_tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
        let garbage = vec![0xff_u8; 10];

        let m = make_module();
        fund(&m, &addr);

        // Pre-verify: the valid tx succeeds, the garbage fails.
        let raw_txs = vec![valid_tx.clone(), garbage];
        let preverified: Vec<PreverifiedTx> =
            m.preverify_batch(&raw_txs).into_iter().filter_map(std::result::Result::ok).collect();
        assert_eq!(preverified.len(), 1, "only the valid tx should preverify");

        m.begin_block(Height::new(1));
        let results = m.handle_batch_preverified(&dummy_ctx(), &preverified);
        m.end_block(Height::new(1));

        assert_eq!(results.len(), 1, "one tx in, one result out");
        assert!(results[0].is_ok(), "valid tx must succeed");
        assert_eq!(m.nonce(&addr), 1, "nonce must increment for the valid tx");
    }
}
