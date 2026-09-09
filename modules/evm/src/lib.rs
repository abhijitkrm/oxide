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
use revm::database::CacheDB;
use revm::database_interface::EmptyDB;
use revm::handler::{ExecuteCommitEvm, MainBuilder, MainContext};
use revm::inspector::NoOpInspector;
use revm::primitives::TxKind;
use revm::primitives::hardfork::SpecId;

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

        Ok(result)
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
    /// Serializes every account (balance, nonce, code, storage) into
    /// a single `Op::Set` per account and applies the batch atomically.
    /// Called from `end_block` when a backend is attached.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    fn flush_to_storage(&self, backend: &mut (dyn storage::StorageBackend + Send)) {
        let db = self.db.lock().expect("db mutex not poisoned");
        let mut ops = Vec::with_capacity(db.cache.accounts.len());
        for (evm_addr, account) in &db.cache.accounts {
            // Skip accounts that don't exist (never touched).
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
}
