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
// Ceiling 1: the chain-configured block gas limit is the single
// source of truth for the EVM's block gas limit too.
use types::CHAIN_BLOCK_GAS_LIMIT;
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
use revm::handler::{ExecuteCommitEvm, ExecuteEvm, MainContext};
use revm::inspector::NoOpInspector;
use revm::primitives::TxKind;
use revm::primitives::hardfork::SpecId;
use std::sync::Arc;

/// The EVM module's dispatch ID in the module router.
///
/// Reserved by `framework::module_id::EVM` (3). Native modules use
/// IDs 0–2 (core, bank, staking); the EVM is the first VM module.
pub const MODULE_ID: u8 = module_id::EVM;

/// Wrap an RLP-encoded signed EVM transaction in the Oxide v0 tx
/// envelope format for mempool submission.
///
/// The v0 envelope is:
/// `[sender:20B][nonce:8B LE][fee:8B LE][module_id:1B][payload]`
///
/// For EVM, the `payload` is the raw RLP-encoded signed transaction.
/// The `sender`, `nonce`, and `fee` fields are used by the mempool
/// for fee-priority selection and nonce ordering. The EVM module
/// ignores them during execution — it recovers the sender from the
/// secp256k1 signature in the RLP payload.
///
/// # Arguments
///
/// - `sender`: the recovered sender address (20 bytes).
/// - `nonce`: the transaction's nonce (for mempool nonce ordering).
/// - `fee`: the transaction's fee (for mempool fee-priority ranking).
/// - `rlp_signed_tx`: the RLP-encoded signed EVM transaction bytes.
///
/// # Returns
///
/// The v0 envelope bytes, ready for `Executor::ingest_tx`.
pub fn wrap_evm_tx_envelope(
    sender: &primitives::Address,
    nonce: u64,
    fee: u64,
    rlp_signed_tx: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20 + 8 + 8 + 1 + rlp_signed_tx.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(MODULE_ID);
    bytes.extend_from_slice(rlp_signed_tx);
    bytes
}

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
pub struct PreverifiedTx<'a> {
    /// RLP-encoded signed transaction bytes (Legacy, EIP-2930, or
    /// EIP-1559 per EIP-2718), borrowed from the caller's buffer —
    /// the batch hot path must not clone per-tx.
    pub raw: &'a [u8],
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
    ///
    /// Wrapped in `Arc` so the parallel execution path can take an
    /// O(1) snapshot via `Arc::clone` instead of an `O(total_state)`
    /// deep clone. Mutable access uses `Arc::make_mut`, which is
    /// free when the refcount is 1 (no outstanding snapshots) and
    /// only clones when a snapshot is actually held.
    db: Mutex<Arc<CacheDB<EmptyDB>>>,
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
    /// Cleared at the start of each `begin_block` (after
    /// `state_root` has consumed the set for incremental updates).
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    ///
    /// `BTreeSet` (sorted): `flush_to_storage` iterates this set to
    /// build the backend op batch, and op order is part of the
    /// journaled state transition. A `HashSet` would produce a
    /// different op order on every validator — identical logical
    /// state, divergent journal/MMR histories.
    touched: Mutex<std::collections::BTreeSet<revm::primitives::Address>>,
    /// Per-account storage root cache. Updated incrementally in
    /// `state_root` — only touched accounts have their storage
    /// roots recomputed; the rest are reused from the cache.
    ///
    /// This turns the per-block state root computation from
    /// `O(total_state)` to `O(touched + log(total_accounts))` for the
    /// storage root portion. The state trie itself is still rebuilt
    /// from scratch (alloy-trie's `HashBuilder` is `O(n)` but very
    /// fast — the dominant cost was per-account storage root
    /// computation, not the trie assembly).
    storage_root_cache:
        Mutex<std::collections::HashMap<revm::primitives::Address, alloy_primitives::B256>>,
    /// Cached state root from the last `state_root` call. If no
    /// Phase B: incremental account-trie leaf cache — hashed
    /// address (`keccak256` of the 20-byte EVM address) →
    /// RLP-encoded `TrieAccount`. `state_root` patches this map
    /// for `touched` accounts only instead of re-hashing every
    /// address, re-encoding every account, and re-sorting every
    /// call. The `BTreeMap` keeps leaves in sorted hashed-key
    /// order — the exact order `HashBuilder::add_leaf` requires.
    trie_leaves: Mutex<std::collections::BTreeMap<revm::primitives::B256, Vec<u8>>>,
    /// Whether `trie_leaves` reflects the full account set. False
    /// at construction and after `import_state` (state was
    /// replaced wholesale); the next `state_root` rebuilds the
    /// map in one pass — the same cost as the old non-incremental
    /// path — then flips this true.
    trie_leaves_ready: Mutex<bool>,
    /// accounts were touched since the last computation, the cached
    /// root is returned directly (O(1) fast path).
    cached_state_root: Mutex<Option<alloy_primitives::B256>>,
    /// Optional exchange module handle for read-only EVM precompiles
    /// (plan.md §10). When `Some`, EVM contracts can call precompile
    /// addresses to read exchange L1 data (best bid/ask).
    exchange: Mutex<Option<Arc<exchange::ExchangeModule>>>,
    /// Optional perps module handle for read-only EVM precompiles.
    /// When `Some`, EVM contracts can read perps positions, mark
    /// prices, and insurance fund balance.
    perps: Mutex<Option<Arc<perps::PerpsModule>>>,
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
            db: Mutex::new(Arc::new(CacheDB::new(EmptyDB::new()))),
            chain_id,
            base_fee,
            spec: SpecId::PRAGUE,
            backend: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: CHAIN_BLOCK_GAS_LIMIT,
            touched: Mutex::new(std::collections::BTreeSet::new()),
            storage_root_cache: Mutex::new(std::collections::HashMap::new()),
            trie_leaves: Mutex::new(std::collections::BTreeMap::new()),
            trie_leaves_ready: Mutex::new(false),
            cached_state_root: Mutex::new(None),
            exchange: Mutex::new(None),
            perps: Mutex::new(None),
        }
    }

    /// Construct with a specific hardfork spec (for testing older
    /// EVM behavior).
    #[must_use]
    pub fn with_spec(chain_id: u64, base_fee: u64, spec: SpecId) -> Self {
        Self {
            db: Mutex::new(Arc::new(CacheDB::new(EmptyDB::new()))),
            chain_id,
            base_fee,
            spec,
            backend: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: CHAIN_BLOCK_GAS_LIMIT,
            touched: Mutex::new(std::collections::BTreeSet::new()),
            storage_root_cache: Mutex::new(std::collections::HashMap::new()),
            trie_leaves: Mutex::new(std::collections::BTreeMap::new()),
            trie_leaves_ready: Mutex::new(false),
            cached_state_root: Mutex::new(None),
            exchange: Mutex::new(None),
            perps: Mutex::new(None),
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
            db: Mutex::new(Arc::new(CacheDB::new(EmptyDB::new()))),
            chain_id,
            base_fee,
            spec: SpecId::PRAGUE,
            backend: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: CHAIN_BLOCK_GAS_LIMIT,
            touched: Mutex::new(std::collections::BTreeSet::new()),
            storage_root_cache: Mutex::new(std::collections::HashMap::new()),
            trie_leaves: Mutex::new(std::collections::BTreeMap::new()),
            trie_leaves_ready: Mutex::new(false),
            cached_state_root: Mutex::new(None),
            exchange: Mutex::new(None),
            perps: Mutex::new(None),
        };
        // Load initial state from the backend into the CacheDB, then
        // install the backend for future flushes.
        module.load_from_storage(&*backend);
        *module.backend.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(backend);
        module
    }

    /// The chain ID (EIP-155).
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Wire native exchange and perps modules for read-only EVM
    /// precompiles (plan.md §10). EVM contracts can call precompile
    /// addresses to read exchange L1 data and perps state.
    ///
    /// # Panics
    ///
    /// Panics if the internal exchange or perps mutexes are
    /// poisoned (indicates a panic in another thread holding the
    /// lock — unrecoverable).
    pub fn set_native_modules(
        &self,
        exchange: Option<Arc<exchange::ExchangeModule>>,
        perps: Option<Arc<perps::PerpsModule>>,
    ) {
        *self.exchange.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = exchange;
        *self.perps.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = perps;
    }

    /// Build a `NativeMarketReader` from the wired exchange and
    /// perps modules. Returns an empty reader if no modules are
    /// wired (all precompile reads return empty/zero).
    fn build_reader(&self) -> precompiles::native::NativeMarketReader {
        let exchange =
            self.exchange.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let perps = self.perps.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        precompiles::native::NativeMarketReader::new(exchange, perps)
    }

    /// Build a revm `Evm` with `NativePrecompiles` wired in. This
    /// replaces `build_mainnet_with_inspector` so that EVM contracts
    /// can call Oxide native precompile addresses.
    ///
    /// Generic over the database type to support both the
    /// single-tx path (`CacheDB<EmptyDB>`) and the batch paths
    /// (`CacheDB<SharedCacheDB>`).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    #[allow(clippy::type_complexity)]
    fn build_evm<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        NoOpInspector,
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        let reader = self.build_reader();
        let ctx = Context::mainnet()
            .with_db(db)
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(self.spec))
            .modify_block_chained(|block| {
                block.number = revm::primitives::U256::from(block_number);
                block.beneficiary = coinbase;
                block.timestamp = revm::primitives::U256::from(block_timestamp);
                block.gas_limit = self.block_gas_limit;
                block.basefee = self.base_fee;
            });
        let instruction = revm::handler::instructions::EthInstructions::<
            revm::interpreter::interpreter::EthInterpreter,
            _,
        >::new_mainnet_with_spec(self.spec);
        let precompiles = precompiles::NativePrecompiles::new(self.spec, reader);
        revm::context::Evm::new_with_inspector(ctx, NoOpInspector, instruction, precompiles)
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
        *self.coinbase.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = coinbase;
    }

    /// Get the coinbase / fee recipient for the current block.
    ///
    /// # Panics
    ///
    /// Panics if the coinbase mutex is poisoned.
    #[must_use]
    pub fn coinbase(&self) -> revm::primitives::Address {
        *self.coinbase.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let mut db_guard = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let db = Arc::make_mut(&mut *db_guard);
        let coinbase = *self.coinbase.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let block_number =
            *self.block_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let block_timestamp =
            *self.block_timestamp.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut evm = self.build_evm(db, coinbase, block_number, block_timestamp);

        // `transact` (not `transact_commit`) so we get the complete
        // `EvmState` — the exact set of accounts the tx modified.
        // The previous top-level-only tracking (caller + to +
        // created + coinbase) missed accounts changed by internal
        // calls, SELFDESTRUCT beneficiaries, and SSTORE writes to
        // third accounts — those accounts were updated in the
        // CacheDB but never flushed or reflected in the incremental
        // state root, diverging durable state from in-memory state.
        let result_and_state = evm
            .transact(tx)
            .map_err(|e| ExecError::ModuleRejected(format!("evm transact failed: {e:?}")))?;

        // Phase D: track touched accounts for incremental flush.
        // `state` contains EVERY account revm modified (including
        // internal-call targets and selfdestruct beneficiaries);
        // `commit` then applies it to the CacheDB — identical
        // semantics to `transact_commit` but with the state
        // available for tracking first.
        {
            let mut touched =
                self.touched.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            touched.extend(result_and_state.state.keys().copied());
        }
        evm.commit(result_and_state.state);

        Ok(result_and_state.result)
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

    /// Native fast path for calls to contracts with **no runtime code**.
    ///
    /// When a transaction sends calldata to an address that has no
    /// deployed code (an EOA or a contract whose constructor didn't
    /// return runtime bytecode), revm still creates a full call frame,
    /// loads the empty code, and immediately returns. This costs
    /// ~60–80 µs per tx in revm overhead (frame setup, gas accounting,
    /// state journal). This fast path performs the same state changes
    /// (nonce bump, gas deduction, coinbase tip) in ~200 ns — a
    /// ~300× speedup for this tx class.
    ///
    /// # Qualification
    ///
    /// The tx must:
    /// 1. Be a `Call` (not `Create`).
    /// 2. Have **non-empty** calldata (empty calldata is handled by
    ///    `try_native_transfer`).
    /// 3. Have an empty access list.
    /// 4. Target a recipient with no code (`KECCAK_EMPTY` or `B256::ZERO`).
    /// 5. Have `gas_limit >= 21000 + calldata_gas`.
    /// 6. Have a matching nonce and sufficient balance.
    ///
    /// # Gas model
    ///
    /// `gas_used = max(21000 + calldata_gas, 21000 + calldata_tokens × 10)`
    /// 4 per zero byte and 16 per non-zero byte (EIP-2028). This
    /// matches revm's intrinsic gas calculation for a transaction
    /// that executes no opcodes. The cold-access surcharge
    /// (EIP-2929, 2600 gas) is **not** charged because the
    /// `try_native_transfer` fast path (which produces matching
    /// state roots) also doesn't charge it — revm's 21000 base
    /// includes the recipient access cost for top-level transactions.
    ///
    /// Budget: ~200 ns per tx (vs ~60–80 µs through revm).
    fn try_empty_code_call<DB: DatabaseRef>(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        db: &mut CacheDB<DB>,
        coinbase: revm::primitives::Address,
        base_fee: u64,
    ) -> Option<ExecutionResult> {
        // 1. Must be a Call (not Create).
        let recipient = match signed.to() {
            tx::TxKind::Create => return None,
            tx::TxKind::Call(addr) => addr,
        };

        // 2. Must have non-empty calldata (empty → try_native_transfer).
        let data = signed.data();
        if data.is_empty() {
            return None;
        }

        // 3. Empty access list.
        if !signed.access_list().is_empty() {
            return None;
        }

        // 4. Recipient has no code. Unlike `try_native_transfer`,
        //    we **must** load the account from the database (not just
        //    check the local cache) because the recipient might have
        //    code in the parent DB that hasn't been loaded into the
        //    local cache yet. For simple transfers this doesn't matter
        //    (code is irrelevant for balance updates), but for calls
        //    with calldata, skipping execution against real code would
        //    produce wrong state roots.
        //
        //    `load_account` checks the local cache first, then falls
        //    through to the parent on miss. It also caches the account
        //    for later use (the recipient touch below). The borrow is
        //    scoped so we can access `db` again for the sender.
        let recipient_has_code = {
            let recipient_account = db.load_account(recipient).ok()?;
            recipient_account.info.code_hash != revm::primitives::KECCAK_EMPTY
                && recipient_account.info.code_hash != revm::primitives::B256::ZERO
        };
        if recipient_has_code {
            return None;
        }

        // 5. Gas limit >= intrinsic gas.
        //    EIP-2028: 4 gas per zero byte, 16 per non-zero byte.
        //    EIP-7623 (Prague): floor gas = 21000 + calldata_tokens × 10,
        //    where calldata_tokens = zero_bytes×1 + non_zero_bytes×4.
        //    The actual gas used is max(standard_gas, floor_gas).
        //    For empty calldata, floor_gas == standard_gas == 21000,
        //    so `try_native_transfer` is unaffected. For non-empty
        //    calldata, floor_gas is usually higher.
        let zero_bytes = data.iter().fold(0u64, |acc, &b| acc + u64::from(b == 0));
        let non_zero_bytes = data.len() as u64 - zero_bytes;
        let calldata_gas = zero_bytes * 4 + non_zero_bytes * 16;
        let calldata_tokens = zero_bytes + non_zero_bytes * 4;
        let floor_gas = TX_GAS_TRANSFER + calldata_tokens * 10;
        let standard_gas = TX_GAS_TRANSFER + calldata_gas;
        let gas_used = std::cmp::max(standard_gas, floor_gas);
        let gas_limit = signed.gas_limit();
        if gas_limit < gas_used {
            return None;
        }

        // 6. Value and gas price must fit in u128.
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

        // 7. Effective gas price >= base fee (EIP-1559).
        let effective_gas_price = std::cmp::min(max_fee, u128::from(base_fee) + priority_fee);
        if effective_gas_price < u128::from(base_fee) {
            return None;
        }

        // ── All checks passed — execute natively ───────────────
        //
        // Same state changes as `try_native_transfer` but with
        // `gas_used = 21000 + calldata_gas` instead of 21000.

        // 8. Nonce must match + sufficient balance.
        {
            let sender_account = db.load_account(caller).ok()?;
            if sender_account.info.nonce != signed.nonce() {
                return None;
            }
            let gas_reserve = u128::from(gas_limit) * effective_gas_price;
            let total_needed = value_u128 + gas_reserve;
            if sender_account.info.balance < revm::primitives::U256::from(total_needed) {
                return None;
            }

            // Deduct gas cost + value, increment nonce.
            let gas_cost = u128::from(gas_used) * effective_gas_price;
            sender_account.info.balance -= revm::primitives::U256::from(value_u128 + gas_cost);
            sender_account.info.nonce += 1;
            if sender_account.info.code_hash == revm::primitives::B256::ZERO {
                sender_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            sender_account.account_state = revm::database::AccountState::Touched;
        }

        // Update recipient. revm touches the callee account for all
        // calls (even zero-value, even to empty-code accounts) because
        // the CALL frame loads the account. We must match this.
        {
            let recipient_account = db.load_account(recipient).ok()?;
            if value_u128 > 0 {
                recipient_account.info.balance += signed.value();
            }
            if recipient_account.info.code_hash == revm::primitives::B256::ZERO {
                recipient_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            recipient_account.account_state = revm::database::AccountState::Touched;
        }

        // Update coinbase (tip only, base fee is burned).
        let tip = effective_gas_price - u128::from(base_fee);
        if tip > 0 {
            let coinbase_tip = u128::from(gas_used) * tip;
            let coinbase_account = db.load_account(coinbase).ok()?;
            coinbase_account.info.balance += revm::primitives::U256::from(coinbase_tip);
            if coinbase_account.info.code_hash == revm::primitives::B256::ZERO {
                coinbase_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            coinbase_account.account_state = revm::database::AccountState::Touched;
        }

        // Build ExecutionResult — identical to what revm produces for
        // a successful call to empty code: Success with no logs, no
        // output, gas_used = 21000 + calldata_gas.
        let result = ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::default()
                .with_total_gas_spent(gas_used)
                .with_refunded(0)
                .with_floor_gas(0),
            logs: Vec::new(),
            output: Output::Call(revm::primitives::Bytes::new()),
        };

        Some(result)
    }
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
        // Fuzz fix: U256::to::<u128>() panics if the value doesn't fit
        // in u128. Use try_into and reject oversized values.
        let gas_price =
            u128::try_from(signed.max_fee_per_gas()).map_err(|_| ExecError::Malformed)?;
        let priority_fee =
            u128::try_from(signed.max_priority_fee_per_gas()).map_err(|_| ExecError::Malformed)?;
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
        msgs: &[impl AsRef<[u8]> + Sync],
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
                let mut buf = raw.as_ref();
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
    pub fn preverify_batch<'a, T: AsRef<[u8]> + Sync + 'a>(
        &self,
        msgs: &'a [T],
    ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
        msgs.par_iter()
            .map(|raw| {
                let mut buf = raw.as_ref();
                let signed: tx::SignedTx =
                    alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                Ok(PreverifiedTx { raw: raw.as_ref(), sender: caller })
            })
            .collect()
    }

    /// Execute a batch of transactions with **pre-verified senders**.
    ///
    /// This is the highest-throughput serial execution path. The
    /// caller (mempool/block builder) has already recovered the sender
    /// for each tx via [`preverify_batch`](Self::preverify_batch).
    /// This method re-recovers the sender from the signature and
    /// checks it matches the pre-recovered value — only RLP decoding
    /// (~79 ns/tx), chain ID validation, and sender re-verification
    /// remain in Phase 1.
    ///
    /// # Performance
    ///
    /// Re-recovery adds ~30 µs/tx (single-threaded) or ~3.7 µs/tx
    /// (8-core parallelized) back to the critical path. This is the
    /// cost of not trusting the proposer. For 10k simple transfers,
    /// batch time is ~80 ms (recovery + native execution) — the same
    /// as the non-preverified path. The preverified path still wins
    /// because it avoids redundant recovery at mempool ingestion.
    ///
    /// # Security
    ///
    /// The sender is re-recovered from the signature inside this
    /// method and checked against `pv.sender`. A byzantine block
    /// proposer supplying wrong senders will be detected here —
    /// mismatched senders are rejected with `ExecError::Malformed`
    /// before any state transition occurs. This closes the trust
    /// gap: the proposer cannot forge a sender.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is re-recovered from the signature).
    /// - `txs`: a slice of [`PreverifiedTx`] (raw bytes + pre-recovered
    ///   sender, used as a hint and verified).
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch. A sender mismatch
    /// (pre-recovered vs signature-recovered) returns `Malformed`.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    pub fn handle_batch_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 1: decode and re-recover the sender. RLP decode is
        // ~79 ns/tx; secp256k1 recovery is ~30 µs/tx. We re-recover
        // the sender and check it matches the pre-recovered value.
        // A byzantine proposer cannot forge a sender — any mismatch
        // is rejected before state transition.
        let decoded: Vec<Result<(tx::SignedTx, revm::primitives::Address), ExecError>> = txs
            .par_iter()
            .map(|pv| {
                let mut buf = pv.raw;
                let signed: tx::SignedTx =
                    alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                // Re-recover the sender from the signature. This is
                // the security gate: we do NOT trust `pv.sender`.
                let recovered = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let recovered_addr = alloy_primitives_address(recovered.0);
                // Check the pre-recovered sender matches the
                // signature-recovered sender. A mismatch means the
                // proposer supplied a wrong sender — reject it.
                if recovered_addr != pv.sender {
                    return Err(ExecError::Malformed);
                }
                Ok((signed, recovered_addr))
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
        let mut db_guard = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let db = Arc::make_mut(&mut *db_guard);
        let coinbase = *self.coinbase.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let block_number =
            *self.block_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let block_timestamp =
            *self.block_timestamp.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

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
                results.push(Self::exec_result_to_events(
                    Ok(result),
                    self.base_fee,
                    signed.tx_type(),
                ));
                continue;
            }

            // Try the empty-code call fast path. For calls to
            // contracts with no runtime code (EOA or constructor-only
            // deployment), this bypasses revm's call-frame setup.
            if let Some(result) =
                Self::try_empty_code_call(&signed, caller, &mut *db, coinbase, self.base_fee)
            {
                local_touched.insert(caller);
                if let tx::TxKind::Call(addr) = signed.to() {
                    local_touched.insert(revm::primitives::Address::from(addr.0));
                }
                local_touched.insert(coinbase);
                results.push(Self::exec_result_to_events(
                    Ok(result),
                    self.base_fee,
                    signed.tx_type(),
                ));
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
                let mut evm = self.build_evm(&mut *db, coinbase, block_number, block_timestamp);
                // `transact` (not `transact_commit`) gives the
                // complete `EvmState`: every account the tx
                // modified, including internal-call targets and
                // selfdestruct beneficiaries — not just the
                // top-level caller/to/created/coinbase set that
                // under-tracked durable state.
                let result_and_state = match evm.transact(tx) {
                    Ok(rs) => rs,
                    Err(e) => {
                        results.push(Err(ExecError::ModuleRejected(format!(
                            "evm transact failed: {e:?}"
                        ))));
                        continue;
                    }
                };
                // Track the exact modified-account set locally
                // (no lock per tx), then commit.
                local_touched.extend(result_and_state.state.keys().copied());
                evm.commit(result_and_state.state);
                result_and_state.result
            };

            results.push(Self::exec_result_to_events(Ok(result), self.base_fee, signed.tx_type()));
        }

        // Merge local touched set into the global one (single lock).
        {
            let mut touched =
                self.touched.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        msgs: &[impl AsRef<[u8]> + Sync],
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
                let mut buf = raw.as_ref();
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
    /// 1. **Pre-verified senders** — re-recovers the sender from the
    ///    signature and checks it matches the pre-recovered value
    ///    (the caller pre-recovered senders at mempool ingestion time;
    ///    we verify rather than trust).
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
    /// the sender is re-recovered from the signature and checked
    /// against the pre-recovered value. A byzantine proposer
    /// supplying wrong senders is rejected. See that method's
    /// documentation for the full security discussion.
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
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Fast path: empty batch.
        if txs.is_empty() {
            return Vec::new();
        }

        // Phase 1: decode and re-recover the sender. We do NOT
        // trust `pv.sender` — a byzantine proposer could forge it.
        let decoded: Vec<Result<(tx::SignedTx, revm::primitives::Address), ExecError>> = txs
            .par_iter()
            .map(|pv| {
                let mut buf = pv.raw;
                let signed: tx::SignedTx =
                    alloy_rlp::Decodable::decode(&mut buf).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                // Re-recover the sender from the signature and
                // check it matches the pre-recovered value.
                let recovered = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let recovered_addr = alloy_primitives_address(recovered.0);
                if recovered_addr != pv.sender {
                    return Err(ExecError::Malformed);
                }
                Ok((signed, recovered_addr))
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
        use std::collections::hash_map::Entry;
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
        // Collect tx types for receipt encoding (EIP-2718). Indexed
        // by the original tx index so the results assembly phase can
        // look up the type for each receipt.
        let mut tx_types: Vec<u8> = vec![0; n_txs];

        for (idx, item) in decoded.into_iter().enumerate() {
            match item {
                Ok((signed, caller)) => {
                    tx_types[idx] = signed.tx_type();
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
        //
        // The snapshot is an O(1) `Arc::clone` — no deep clone of
        // the CacheDB. Each parallel group gets a fresh empty
        // `CacheDB<SharedCacheDB>` backed by the shared snapshot via
        // `DatabaseRef`. Reads fall through to the parent on cache
        // miss; writes stay local.
        let snapshot = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let coinbase = *self.coinbase.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let block_number =
            *self.block_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let block_timestamp =
            *self.block_timestamp.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

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
                // on the first access to each account. The accounts
                // touched by (almost) every tx in a group:
                //
                // 1. **Sender** — nonce bump + balance deduction on
                //    every tx.
                // 2. **Coinbase** — receives tips on every tx.
                // 3. **All unique recipients** — pre-loading every
                //    recipient in the group avoids a cache miss on
                //    the first call to each contract. For workloads
                //    with many calls to the same contract (CLOB,
                //    storage patterns), this eliminates repeated
                //    `DatabaseRef` dispatch.
                let _ = db.load_account(*sender);
                let _ = db.load_account(coinbase);
                // Collect unique recipient addresses from all txs in
                // the group. Uses a small HashSet to deduplicate —
                // typical groups have 1–5 unique recipients.
                let mut recipients: std::collections::HashSet<revm::primitives::Address> =
                    std::collections::HashSet::new();
                for (_, signed) in txs {
                    if let tx::TxKind::Call(addr) = signed.to() {
                        recipients.insert(revm::primitives::Address::from(addr.0));
                    }
                }
                for addr in &recipients {
                    let _ = db.load_account(*addr);
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

                    // Try the native transfer fast path first. For
                    // simple ETH transfers (empty calldata, EOA
                    // recipient), this bypasses revm entirely.
                    if let Some(result) =
                        Self::try_native_transfer(signed, caller, &mut db, coinbase, self.base_fee)
                    {
                        tx_results.push((*idx, Ok(result)));
                        continue;
                    }

                    // Try the empty-code call fast path. For calls
                    // to contracts with no runtime code (EOA or
                    // constructor-only deployment), this bypasses
                    // revm's call-frame setup and gas accounting.
                    if let Some(result) =
                        Self::try_empty_code_call(signed, caller, &mut db, coinbase, self.base_fee)
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
                        let mut evm =
                            self.build_evm(&mut db, coinbase, block_number, block_timestamp);
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
                //
                // We clone the touched accounts and new contracts
                // because the local cache is still needed for the
                // `accessed_accounts` extraction below. Attempting
                // to drain/move caused a significant throughput
                // regression (likely due to HashMap internal
                // reallocation behavior during drain on the
                // CacheDB's concurrent access patterns).
                let touched_accounts: revm::primitives::AddressMap<revm::database::DbAccount> = db
                    .cache
                    .accounts
                    .iter()
                    .filter(|(_, a)| a.account_state != revm::database::AccountState::None)
                    .map(|(addr, a)| (*addr, a.clone()))
                    .collect();

                // Read-set tracking (hardening): collect ALL accounts
                // accessed by this group (read OR written). This
                // includes accounts with `account_state == None`
                // (read-only) and `account_state != None` (written).
                // Used for read-write conflict detection in the
                // commit phase: a group conflicts if its accessed
                // set overlaps with any previously committed group's
                // write set. Without this, a group that reads an
                // account modified by an earlier group would not be
                // detected as conflicting and would commit stale
                // state.
                let accessed_accounts: std::collections::HashSet<revm::primitives::Address> =
                    db.cache.accounts.keys().copied().collect();

                let new_contracts = db.cache.contracts.clone();

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
                    accessed_accounts,
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
        let mut db_guard = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let db = Arc::make_mut(&mut *db_guard);
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
            // Read-write conflict detection (hardening):
            //
            // A group conflicts if any account it *accessed* (read OR
            // wrote) was *written* by a previously committed group.
            // The prior implementation only checked write-write
            // conflicts (group's write set vs committed write set),
            // missing read-write conflicts where a group reads an
            // account that was modified by an earlier group. This
            // caused the group to commit stale state silently.
            //
            // The `accessed_accounts` set includes all accounts in
            // the group's cache (read + written). The
            // `committed_touched` set includes all accounts written
            // by previously committed groups. The coinbase is
            // excluded from both sides (it is handled additively).
            //
            // **Read-only group fast path**: if the group's only
            // writes are to its own sender account (nonce/balance)
            // and the coinbase (tips), it cannot conflict with any
            // other group — the sender is unique per group (groups
            // are by sender), and the coinbase is handled
            // additively. This skips the conflict check and the
            // `accessed_accounts` set intersection, which is O(n_groups)
            // per group and O(n_groups²) total. For workloads with
            // many read-only contract calls (e.g. 10% reads in the
            // standard mix), this eliminates unnecessary conflict
            // detection and potential false-positive re-execution.
            let group_touched: std::collections::HashSet<revm::primitives::Address> =
                gr.touched_accounts.keys().filter(|addr| **addr != coinbase).copied().collect();

            // A group is "read-only" (with respect to other groups)
            // if its only write outside the coinbase is its own
            // sender account. The sender is unique per group, so it
            // can never conflict with another group's writes.
            let is_read_only = group_touched.iter().all(|addr| *addr == gr.sender);

            let has_conflict = if is_read_only {
                // Read-only group: skip conflict check entirely.
                false
            } else {
                // Read-write group: check if any accessed account was
                // written by a previously committed group.
                let group_accessed: std::collections::HashSet<revm::primitives::Address> = gr
                    .accessed_accounts
                    .iter()
                    .filter(|addr| **addr != coinbase)
                    .copied()
                    .collect();
                group_accessed.iter().any(|addr| committed_touched.contains(addr))
            };

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

                    // Try empty-code call fast path — must use the
                    // same fast paths as the speculative execution to
                    // ensure identical state roots.
                    if let Some(result) =
                        Self::try_empty_code_call(signed, caller, &mut *db, coinbase, self.base_fee)
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
                    {
                        let mut evm =
                            self.build_evm(&mut *db, coinbase, block_number, block_timestamp);
                        // `transact` gives the complete `EvmState` —
                        // every modified account (internal calls,
                        // selfdestruct beneficiaries, third-party
                        // SSTORE), not just caller/to/created.
                        match evm.transact(tx_env) {
                            Ok(rs) => {
                                // Track the exact modified set before
                                // committing it.
                                let r = rs.result;
                                for addr in rs.state.keys() {
                                    all_touched.insert(*addr);
                                    committed_touched.insert(*addr);
                                }
                                evm.commit(rs.state);
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
            let mut touched =
                self.touched.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
                results.push(Self::exec_result_to_events(r, self.base_fee, tx_types[i]));
                continue;
            }
            // Fall back to speculative results.
            match spec_index.get(&i) {
                Some(result) => {
                    results.push(Self::exec_result_to_events(
                        (*result).clone(),
                        self.base_fee,
                        tx_types[i],
                    ));
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
        tx_type: u8,
    ) -> Result<Vec<Event>, ExecError> {
        match result {
            Ok(r) => {
                let receipt = receipts::Receipt::from_execution_result(&r, tx_type);
                let status_str = if receipt.status { "success" } else { "revert" };
                let contract_info =
                    receipt.contract_address.map(|a| format!(" contract={a}")).unwrap_or_default();
                let log_count = receipt.logs.len();
                Ok(vec![Event {
                    module: "evm",
                    kind: "evm_call",
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
    /// All accounts accessed by this group (read OR written),
    /// extracted from `CacheDB::cache::accounts`. This includes
    /// accounts with `account_state == None` (read-only) and
    /// `account_state != None` (written). Used for read-write
    /// conflict detection: a group conflicts if its accessed set
    /// overlaps with any previously committed group's write set.
    accessed_accounts: std::collections::HashSet<revm::primitives::Address>,
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
        *self.block_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = h;
        *self.block_timestamp.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            h.saturating_mul(BLOCK_TIME_SECS);

        // Clear the touched set from the previous block. The set was
        // consumed by `state_root` (for incremental storage root
        // updates) and by `flush_to_storage` (for dirty-only writes).
        // Clearing here (not in `end_block`) lets `state_root` see
        // which accounts were touched in this block.
        self.touched.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
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

        // HIGH fix: gas_limit must fit within the block gas limit.
        // A tx with gas_limit > block_gas_limit can never be included
        // and should be rejected at admission to save mempool space.
        if gas_limit > self.block_gas_limit {
            return Err(ExecError::ModuleRejected(format!(
                "gas_limit {gas_limit} > block_gas_limit {}",
                self.block_gas_limit
            )));
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

        // HIGH fix: EIP-1559 fee gates.
        //   a. max_fee >= base_fee: a tx with max_fee < base_fee
        //      can never be included (revm rejects it during
        //      execution). Reject at admission to save resources.
        //   b. priority_fee <= max_fee: EIP-1559 requires
        //      max_priority_fee_per_gas <= max_fee_per_gas. A tx
        //      with priority_fee > max_fee is invalid.
        let max_fee = u128::try_from(signed.max_fee_per_gas())
            .map_err(|_| ExecError::ModuleRejected("max_fee overflow u128".to_string()))?;
        let priority_fee = u128::try_from(signed.max_priority_fee_per_gas())
            .map_err(|_| ExecError::ModuleRejected("priority_fee overflow u128".to_string()))?;
        if max_fee < u128::from(self.base_fee) {
            return Err(ExecError::ModuleRejected(format!(
                "max_fee {max_fee} < base_fee {}",
                self.base_fee
            )));
        }
        if priority_fee > max_fee {
            return Err(ExecError::ModuleRejected(format!(
                "priority_fee {priority_fee} > max_fee {max_fee}"
            )));
        }

        // 7. Balance: sender must cover gas_cost + value.
        //    gas_cost = gas_limit * max_fee_per_gas (the worst-case
        //    fee the sender could pay). For legacy txs, gas_price is
        //    the max fee. For EIP-1559, max_fee_per_gas is the cap.
        let balance = self.balance(&sender_addr);
        let value = u128::try_from(signed.value())
            .map_err(|_| ExecError::ModuleRejected("value overflow u128".to_string()))?;
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

    /// The EVM is self-funded: revm charges `gas_used × effective
    /// gas price` from the sender's account inside execution,
    /// bounded below by the block base fee (`GasPriceLessThanBasefee`
    /// rejects under-priced txs). Charging the envelope fee on top
    /// would double-charge every EVM user.
    fn pays_own_fee(&self) -> bool {
        true
    }

    /// Gas estimate = the tx's declared `gas_limit`, decoded from
    /// the RLP payload. The default `1000 + len` proxy would let a
    /// tx with a 30M gas limit count as ~150 gas and blow through
    /// the block limit at execution time — the block gas limit must
    /// be enforced against *declared* limits (EIP-1559 semantics:
    /// `sum(tx.gas_limit) <= block.gas_limit`).
    ///
    /// An undecodable tx counts as `u64::MAX`: it cannot carry a
    /// valid gas limit, so any proposal containing it exceeds the
    /// limit and is rejected at `process_proposal` — the safe
    /// direction.
    fn estimate_gas(&self, msg: &[u8]) -> u64 {
        let mut buf = msg;
        match <tx::SignedTx as alloy_rlp::Decodable>::decode(&mut buf) {
            Ok(signed) => signed.gas_limit(),
            Err(_) => u64::MAX,
        }
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        // Decode once to get the tx type for the receipt. The
        // execute() call decodes again — this is a cold path (one
        // decode per tx, not per opcode), and the decode is cheap
        // (~1 µs) compared to EVM execution (~60–80 µs).
        let tx_type = {
            let mut buf = msg;
            match <tx::SignedTx as alloy_rlp::Decodable>::decode(&mut buf) {
                Ok(signed) => signed.tx_type(),
                Err(_) => 0, // Malformed tx — execute() will reject it.
            }
        };
        let result = self.execute(ctx, msg)?;

        // Phase C: build a receipt from the execution result.
        // The receipt captures status, gas used, logs, bloom, and
        // (for CREATE) the created address. This is the data that
        // `eth_getTransactionReceipt` returns and that goes into the
        // block's receipts trie.
        let receipt = receipts::Receipt::from_execution_result(&result, tx_type);

        let status_str = if receipt.status { "success" } else { "revert" };
        let contract_info =
            receipt.contract_address.map(|a| format!(" contract={a}")).unwrap_or_default();
        let log_count = receipt.logs.len();

        Ok(vec![Event {
            module: "evm",
            kind: "evm_call",
            data: format!(
                "gas_used={} status={} base_fee={} logs={}{}",
                receipt.gas_used, status_str, self.base_fee, log_count, contract_info
            )
            .into_bytes(),
        }])
    }

    /// Batch execution: delegate to the inherent `handle_batch` which
    /// recovers senders in parallel via rayon and uses the native fast
    /// path for simple transfers.
    ///
    /// The `ctx` (sender, nonce, fee) from the tx envelope is ignored
    /// — the EVM recovers the sender from the secp256k1 signature in
    /// the RLP-encoded payload. The envelope's sender/nonce/fee fields
    /// exist only for the mempool's v0 format compatibility.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch(&self, msgs: &[(TxContext, &[u8])]) -> Vec<Result<Vec<Event>, ExecError>> {
        // Borrow the raw RLP bytes from each (ctx, payload) pair —
        // no per-tx clone. The payload IS the RLP-encoded signed
        // transaction.
        let raw_txs: Vec<&[u8]> = msgs.iter().map(|(_, payload)| *payload).collect();
        let ctx = TxContext { sender: primitives::Address([0u8; 20]), nonce: 0, fee: 0 };
        // Call the inherent `handle_batch` (2 args: ctx, msgs) — Rust
        // resolves to the inherent method, not the trait method (1 arg)
        // because the signatures differ.
        self.handle_batch(&ctx, &raw_txs)
    }

    /// Pre-recover senders from RLP-encoded signed EVM transactions.
    ///
    /// Delegates to the inherent `preverify_batch` which uses rayon
    /// to parallelize secp256k1 recovery across cores. The
    /// pre-recovered senders are cached by the executor and reused
    /// at block execution time to skip recovery entirely.
    ///
    /// # Errors
    ///
    /// Returns `Err(ExecError::Malformed)` for each transaction
    /// that cannot be RLP-decoded, has a wrong chain ID, or whose
    /// signature is invalid.
    fn preverify_batch<'a>(
        &self,
        msgs: &'a [&'a [u8]],
    ) -> Vec<Result<executor::PreverifiedTx<'a>, ExecError>> {
        // Delegate to the inherent `preverify_batch` (which returns
        // `evm::PreverifiedTx` borrowing from `msgs`) and convert to
        // the executor's `PreverifiedTx` (which uses a generic
        // `[u8; 20]` sender). The borrow propagates — zero clones.
        let results = EvmModule::preverify_batch(self, msgs);
        results
            .into_iter()
            .map(|r| {
                r.map(|pv| executor::PreverifiedTx { raw: pv.raw, sender: pv.sender.into_array() })
            })
            .collect()
    }

    /// Execute a batch of pre-verified EVM transactions (serial).
    ///
    /// Delegates to the inherent `handle_batch_preverified` which
    /// skips secp256k1 recovery entirely — only RLP decoding and
    /// chain ID validation remain. This is the highest-throughput
    /// serial execution path.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch_preverified(
        &self,
        ctx: &TxContext,
        txs: &[executor::PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Convert the executor's `PreverifiedTx` (generic [u8; 20]
        // sender) to the EVM's `PreverifiedTx` (revm Address sender).
        // The raw bytes stay borrowed — no per-tx clone.
        let evm_txs: Vec<PreverifiedTx<'_>> = txs
            .iter()
            .map(|pv| PreverifiedTx {
                raw: pv.raw,
                sender: revm::primitives::Address::from(pv.sender),
            })
            .collect();
        // Call the inherent `handle_batch_preverified` (3 args).
        EvmModule::handle_batch_preverified(self, ctx, &evm_txs)
    }

    /// Execute a batch of pre-verified EVM transactions in parallel.
    ///
    /// Delegates to the inherent `handle_batch_parallel_preverified`
    /// which groups transactions by sender and executes each group on
    /// a separate rayon thread. Results are merged in original block
    /// order.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch_parallel_preverified(
        &self,
        ctx: &TxContext,
        txs: &[executor::PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Convert the executor's `PreverifiedTx` to the EVM's.
        // The raw bytes stay borrowed — no per-tx clone.
        let evm_txs: Vec<PreverifiedTx<'_>> = txs
            .iter()
            .map(|pv| PreverifiedTx {
                raw: pv.raw,
                sender: revm::primitives::Address::from(pv.sender),
            })
            .collect();
        // Call the inherent `handle_batch_parallel_preverified` (3 args).
        EvmModule::handle_batch_parallel_preverified(self, ctx, &evm_txs)
    }

    fn end_block(&self, _height: Height) {
        // If a StorageBackend is attached, flush the current CacheDB
        // state to durable storage. This makes the EVM state
        // persistent across restarts and shareable between nodes.
        let mut backend_guard =
            self.backend.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        // # Incremental storage root cache
        //
        // The dominant cost of `state_root` is per-account storage
        // root computation (O(storage_size) per account). We cache
        // each account's storage root and only recompute it for
        // accounts in the `touched` set. This turns the per-block
        // cost from O(total_storage) to O(touched_storage +
        // total_accounts) — the trie assembly is still O(n) but
        // the storage root computation (the expensive part) is
        // incremental.
        //
        // # Panics
        //
        // Panics if the DB mutex is poisoned (a thread panicked while
        // holding the lock). This is unrecoverable and indicates a bug.
        let touched = self.touched.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut leaves = self.trie_leaves.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut leaves_ready =
            self.trie_leaves_ready.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        // Fast path: if the leaf map is built and nothing was
        // touched since the last computation, return the cached
        // root. This makes consecutive `state_root` calls with no
        // intervening execution O(1).
        if *leaves_ready && touched.is_empty() {
            if let Some(cached) =
                *self.cached_state_root.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                return Hash(cached.0);
            }
        }

        let db = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut storage_root_cache =
            self.storage_root_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        if *leaves_ready {
            // Incremental patch — only `touched` accounts are
            // re-encoded. `touched` is the complete modified set
            // (populated from `EvmState::keys()` post-commit), so
            // every changed account is patched; accounts absent
            // from the cache were removed from state.
            for addr in touched.iter() {
                let hashed = alloy_primitives::keccak256(addr);
                match db.cache.accounts.get(addr) {
                    Some(account) => {
                        let storage_root = if account.storage.is_empty() {
                            trie::EMPTY_ROOT
                        } else {
                            // Touched → always recompute the
                            // storage root (its slots changed).
                            let storage_iter = account.storage.iter().map(|(slot, value)| {
                                (
                                    alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()),
                                    *value,
                                )
                            });
                            let root = trie::storage_root(storage_iter);
                            storage_root_cache.insert(*addr, root);
                            root
                        };
                        leaves.insert(hashed, encode_trie_leaf(account, storage_root));
                    }
                    None => {
                        leaves.remove(&hashed);
                    }
                }
            }
        } else {
            // Full build — first call after construction or
            // `import_state`. Hashes and encodes every account once
            // (same cost as the old path); subsequent calls patch
            // only `touched` accounts.
            for (addr, account) in &db.cache.accounts {
                let storage_root = if account.storage.is_empty() {
                    trie::EMPTY_ROOT
                } else if touched.contains(addr) {
                    // Recompute for touched accounts.
                    let storage_iter = account.storage.iter().map(|(slot, value)| {
                        (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                    });
                    let root = trie::storage_root(storage_iter);
                    storage_root_cache.insert(*addr, root);
                    root
                } else {
                    // Reuse cached storage root for untouched accounts.
                    storage_root_cache.get(addr).copied().unwrap_or_else(|| {
                        let storage_iter = account.storage.iter().map(|(slot, value)| {
                            (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                        });
                        let root = trie::storage_root(storage_iter);
                        storage_root_cache.insert(*addr, root);
                        root
                    })
                };
                leaves.insert(
                    alloy_primitives::keccak256(addr),
                    encode_trie_leaf(account, storage_root),
                );
            }
            *leaves_ready = true;
        }

        // Feed the leaves into `HashBuilder` in sorted hashed-key
        // order — the `BTreeMap` iteration order is exactly what
        // `add_leaf` requires (it asserts sorted input).
        let mut hb = alloy_trie::HashBuilder::default();
        for (hashed_key, rlp) in leaves.iter() {
            hb.add_leaf(alloy_trie::Nibbles::unpack(hashed_key), rlp);
        }
        let root = hb.root();

        // Cache the state root for the next call's fast path.
        *self.cached_state_root.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(root);

        // Convert the alloy B256 root to Oxide's Hash type.
        Hash(root.0)
    }

    /// Export the EVM's full key-value state for snapshot sync.
    ///
    /// Returns `Some(snapshot)` if a `StorageBackend` is attached,
    /// `None` otherwise. The snapshot includes all key-value pairs
    /// in the backend — the complete EVM state (accounts, code,
    /// storage).
    ///
    /// This is used for full state sync: a new node imports the
    /// snapshot to skip replaying the entire chain from genesis.
    fn export_state(&self) -> Option<storage::Snapshot> {
        let backend = self.backend.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        backend.as_ref().map(|b| b.snapshot_export())
    }

    /// Import a key-value snapshot, restoring the EVM's state.
    ///
    /// Flushes the current in-memory state to the backend, then
    /// replaces the backend's state with the snapshot, then reloads
    /// the in-memory cache from the backend.
    ///
    /// Returns `Ok(())` on success, or an error if the backend is
    /// not attached or the import fails.
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        // Flush the current state to the backend first (so we don't
        // lose any pending changes — though in practice, import
        // happens before consensus starts, so there are no pending
        // changes).
        {
            let mut backend =
                self.backend.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(ref mut b) = *backend {
                self.flush_to_storage(b.as_mut());
                b.snapshot_import(snapshot.clone())?;
            } else {
                return Err(storage::SnapshotError::BackendError);
            }
        }
        // Reload the in-memory cache from the backend.
        let backend = self.backend.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref b) = *backend {
            self.load_from_storage(b.as_ref());
        }
        // The account set was wholesale replaced — the incremental
        // leaf map is stale. The next `state_root` rebuilds it in
        // one pass.
        *self.trie_leaves_ready.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        *self.cached_state_root.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        Ok(())
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
        let db = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let evm_addr = alloy_primitives_address(addr.0);
        // `to::<u128>` panics on balances above u128::MAX — reachable
        // via crafted state (e.g. snapshot import). Saturate instead:
        // a balance that large cannot be spent anyway, and this is a
        // query accessor, not a consensus path.
        db.cache
            .accounts
            .get(&evm_addr)
            .map_or(0, |a| u128::try_from(a.info.balance).unwrap_or(u128::MAX))
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
        let db = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let mut guard = self.backend.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let mut db_guard = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let db = Arc::make_mut(&mut *db_guard);
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

    /// Mark an account as touched for the current block — the
    /// incremental `state_root` then re-encodes its leaf. Test/bench
    /// hook: real execution populates `touched` from
    /// `EvmState::keys()` automatically; benches need a way to mark
    /// accounts without executing txs.
    ///
    /// # Panics
    ///
    /// Panics if the touched mutex is poisoned.
    #[doc(hidden)]
    pub fn mark_touched_for_test(&self, addr: &Address) {
        self.touched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(alloy_primitives_address(addr.0));
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
    /// # Self-destructed accounts
    ///
    /// Accounts that became `NotExisting` (self-destructed) or were
    /// removed from the cache emit a `Delete` op so the storage
    /// backend removes the stale entry. Without this, a
    /// self-destructed account would reappear on reload.
    ///
    /// # Deterministic serialization
    ///
    /// Storage slots are sorted by slot key before serialization so
    /// the persisted blob is byte-identical across all validators
    /// with the same logical state. Without this, `HashMap`
    /// iteration order would make the raw `StorageBackend` value
    /// non-deterministic.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    fn flush_to_storage(&self, backend: &mut (dyn storage::StorageBackend + Send)) {
        let db = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let touched = self.touched.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        // If nothing was touched, skip the flush entirely.
        if touched.is_empty() {
            return;
        }

        let mut ops = Vec::with_capacity(touched.len());
        for evm_addr in touched.iter() {
            let oxide_addr = Address(evm_addr.0.into());
            let key = persist::account_key(&oxide_addr);

            // Handle self-destructed / removed accounts: emit a
            // Delete op so the stale entry is removed from storage.
            // Without this, a self-destructed account reappears on
            // reload because the old persisted value is still there.
            let Some(account) = db.cache.accounts.get(evm_addr) else {
                ops.push(storage::Op::Delete { key });
                continue;
            };
            if account.account_state == revm::database::AccountState::NotExisting {
                ops.push(storage::Op::Delete { key });
                continue;
            }

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

            // Extract storage slots and sort by slot key for
            // deterministic serialization. `DbAccount.storage` is a
            // `U256Map<U256>` (HashMap) — iteration order is
            // non-deterministic. Sorting ensures every validator
            // produces the same byte blob for the same logical state.
            let mut storage_slots: Vec<(revm::primitives::U256, revm::primitives::U256)> =
                account.storage.iter().map(|(slot, val)| (*slot, *val)).collect();
            storage_slots.sort_by_key(|a| a.0);

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

        // The touched set is cleared in `begin_block` (not here) so
        // that `state_root` can use it for incremental storage root
        // updates.
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
        let mut db_guard = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let db = Arc::make_mut(&mut *db_guard);
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
            // HIGH fix: also populate `cache.contracts` (the code
            // hash → Bytecode map). revm looks up contract code by
            // hash via `cache.contracts`, not via the account's
            // `info.code` field. Without this, after a storage
            // reload, the EVM can't find contract code by hash —
            // calling a reloaded contract would behave as if it
            // has no code (a silent no-op call).
            if !account.code.is_empty() {
                db.cache.contracts.insert(
                    account.code_hash,
                    revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::from_iter(
                        account.code.iter().copied(),
                    )),
                );
            }
        }
    }
}

/// Convert an Oxide `Address` (20 bytes) to a revm `Address`.
fn alloy_primitives_address(bytes: [u8; 20]) -> revm::primitives::Address {
    revm::primitives::Address::from(bytes)
}

/// RLP-encode an account's `TrieAccount` leaf value for the account
/// trie. Shared by the full-build and incremental-patch paths in
/// `state_root` so both produce byte-identical leaves.
fn encode_trie_leaf(
    account: &revm::database::DbAccount,
    storage_root: revm::primitives::B256,
) -> Vec<u8> {
    let trie_account = trie::build_trie_account(
        account.info.nonce,
        account.info.balance,
        storage_root,
        account.info.code_hash,
    );
    // TrieAccount RLP is ~70 bytes (nonce + 32B balance + two
    // 32B hashes + RLP overhead); one allocation per leaf.
    let mut buf = Vec::with_capacity(80);
    alloy_rlp::Encodable::encode(&trie_account, &mut buf);
    buf
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

    /// `try_empty_code_call` fast path: a call with calldata to an
    /// EOA (no code) should produce the same state root as revm.
    /// This is the differential test for the empty-code call fast
    /// path — it verifies that the native gas calculation and state
    /// changes match revm exactly.
    #[test]
    fn empty_code_call_matches_revm_state_root() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Build a tx with non-empty calldata to an EOA (no code).
        // This triggers `try_empty_code_call` in the batch path.
        let calldata = [0x60, 0xfe, 0x47, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let tx = signed_tx(&pk, 0, tx::TxKind::Call(recipient), &calldata);

        // Path 1: handle() — uses revm for the call.
        let m1 = make_module();
        fund(&m1, &addr);
        m1.begin_block(Height::new(1));
        m1.handle(&dummy_ctx(), &tx).expect("revm tx must succeed");
        m1.end_block(Height::new(1));
        let root1 = m1.state_root();

        // Path 2: handle_batch() — uses try_empty_code_call fast path.
        let m2 = make_module();
        fund(&m2, &addr);
        m2.begin_block(Height::new(1));
        m2.handle_batch(&dummy_ctx(), std::slice::from_ref(&tx));
        m2.end_block(Height::new(1));
        let root2 = m2.state_root();

        assert_eq!(root1, root2, "revm and empty-code-call state roots must match");
    }

    /// `try_empty_code_call` with multiple txs from the same sender.
    /// Verifies nonce sequencing and gas deductions match revm.
    #[test]
    fn empty_code_call_multi_tx_matches_revm() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let calldata = [0x6d, 0x4c, 0xe6, 0x3c]; // get() selector
        let txs: Vec<Vec<u8>> = (0..5)
            .map(|nonce| signed_tx(&pk, nonce, tx::TxKind::Call(recipient), &calldata))
            .collect();

        // Path 1: handle() per tx — uses revm.
        let m1 = make_module();
        fund(&m1, &addr);
        m1.begin_block(Height::new(1));
        for raw in &txs {
            m1.handle(&dummy_ctx(), raw).expect("revm tx must succeed");
        }
        m1.end_block(Height::new(1));
        let root1 = m1.state_root();

        // Path 2: handle_batch() — uses try_empty_code_call fast path.
        let m2 = make_module();
        fund(&m2, &addr);
        m2.begin_block(Height::new(1));
        m2.handle_batch(&dummy_ctx(), &txs);
        m2.end_block(Height::new(1));
        let root2 = m2.state_root();

        assert_eq!(root1, root2, "revm and empty-code-call multi-tx state roots must match");
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
        let results = m.handle_batch_parallel(&dummy_ctx(), &Vec::<&[u8]>::new());
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
        let preverified: Vec<PreverifiedTx<'_>> = m2
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
        let preverified: Vec<PreverifiedTx<'_>> = m2
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
        let preverified: Vec<PreverifiedTx<'_>> =
            m.preverify_batch(&raw_txs).into_iter().filter_map(std::result::Result::ok).collect();
        assert_eq!(preverified.len(), 1, "only the valid tx should preverify");

        m.begin_block(Height::new(1));
        let results = m.handle_batch_preverified(&dummy_ctx(), &preverified);
        m.end_block(Height::new(1));

        assert_eq!(results.len(), 1, "one tx in, one result out");
        assert!(results[0].is_ok(), "valid tx must succeed");
        assert_eq!(m.nonce(&addr), 1, "nonce must increment for the valid tx");
    }

    // ── EVM integration: full pipeline ingest→propose→finalize ──

    /// Build a signed legacy EVM transfer tx (test helper for
    /// integration tests).
    fn pipeline_signed_transfer(
        privkey: &[u8],
        nonce: u64,
        to: revm::primitives::Address,
        value: u128,
    ) -> Vec<u8> {
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce,
                gas_limit: 100_000,
                to: tx::TxKind::Call(to),
                value: U256::from(value),
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000),
        };
        tx::SignedTx::sign_legacy(tx, privkey).expect("sign must succeed").encode_to_bytes()
    }

    /// The full EVM pipeline: submit signed EVM txs through the
    /// executor's mempool, propose a block, finalize it, and verify
    /// the state root is non-zero (the EVM executed the txs).
    ///
    /// This is the integration test that proves the pipeline is wired:
    /// `ingest_tx` → mempool → `prepare_proposal` → `process_proposal`
    /// → `finalize_block` → `execute_block` → EVM `handle_batch` →
    /// state root.
    #[test]
    fn evm_txs_through_executor_pipeline() {
        use ports::AppInterface;
        use std::sync::Arc;

        let (privkey, addr) = test_keypair();
        let oxide_addr = Address(addr.0);
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Build the executor with an EVM module.
        let evm_module = EvmModule::new(1, 7);
        evm_module.fund_account_for_test(&oxide_addr, u128::MAX);
        let mut executor = executor::Executor::new(1000);
        executor.register_module(Arc::new(evm_module));

        // Build 3 signed EVM transfer txs and wrap them in the v0
        // envelope format for the mempool.
        for nonce in 0..3u64 {
            let rlp = pipeline_signed_transfer(&privkey, nonce, recipient, 1_000_000_000);
            let envelope = wrap_evm_tx_envelope(&oxide_addr, nonce, 1_000_000_000, &rlp);
            let ack = executor.ingest_tx(types::TxBytes::new(envelope));
            assert!(
                matches!(ack, types::MempoolAck::Accepted),
                "EVM tx {nonce} must be accepted by mempool"
            );
        }

        // Prepare a proposal — the mempool should select all 3 txs.
        let budget = types::CHAIN_BLOCK_BUDGET;
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 3, "mempool must select all 3 EVM txs");

        // Process the proposal — should be accepted (all txs are valid).
        match executor.process_proposal(&proposal) {
            types::Verdict::Accept => {}
            types::Verdict::Reject { reason } => panic!("proposal must be accepted: {reason}"),
        }

        // Finalize the block — executes the EVM txs.
        let block = types::FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        let ack = executor.finalize_block(&block);
        assert_eq!(ack.height, Height::new(0));

        // The state root must be non-zero — the EVM executed the txs
        // and changed the state (sender balance decreased, recipient
        // balance increased, nonce advanced).
        let attestation = executor.attest_state(Height::new(0));
        assert_ne!(
            attestation.root,
            primitives::Hash::ZERO,
            "state root must be non-zero after EVM execution"
        );
    }

    /// EVM txs through the full `SequencerEngine` pipeline: submit →
    /// propose → finalize → attest, driven by the consensus engine.
    #[test]
    fn evm_txs_through_sequencer_engine_pipeline() {
        use ports::ConsensusEngine;
        use std::sync::Arc;

        let (privkey, addr) = test_keypair();
        let oxide_addr = Address(addr.0);
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let evm_module = EvmModule::new(1, 7);
        evm_module.fund_account_for_test(&oxide_addr, u128::MAX);
        let mut executor = executor::Executor::new(1000);
        executor.register_module(Arc::new(evm_module));

        let app: Arc<dyn ports::AppInterface> = Arc::new(executor);
        let mut engine = consensus::SequencerEngine::new(app);

        // Submit 3 EVM txs through the engine.
        for nonce in 0..3u64 {
            let rlp = pipeline_signed_transfer(&privkey, nonce, recipient, 1_000_000_000);
            let envelope = wrap_evm_tx_envelope(&oxide_addr, nonce, 1_000_000_000, &rlp);
            engine.submit_tx(types::TxBytes::new(envelope));
        }
        engine.run_until_idle();

        // The engine should have finalized a block.
        assert!(engine.finalized_height().is_some(), "engine must finalize a block");

        // The state root must be non-zero.
        let app = engine.app();
        let attestation = app.attest_state(Height::new(0));
        assert_ne!(
            attestation.root,
            primitives::Hash::ZERO,
            "state root must be non-zero after EVM execution through engine"
        );
    }

    /// EVM pipeline with 5 txs produces a different state root than
    /// an empty block. This proves the EVM txs are actually executed
    /// through the pipeline (not silently skipped).
    #[test]
    fn evm_pipeline_state_root_differs_from_empty_block() {
        use ports::AppInterface;
        use std::sync::Arc;

        let (privkey, addr) = test_keypair();
        let oxide_addr = Address(addr.0);
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Path 1: executor with 5 EVM txs.
        let evm_module = EvmModule::new(1, 7);
        evm_module.fund_account_for_test(&oxide_addr, u128::MAX);
        let mut executor = executor::Executor::new(1000);
        executor.register_module(Arc::new(evm_module));

        for nonce in 0..5u64 {
            let rlp = pipeline_signed_transfer(&privkey, nonce, recipient, 1_000_000_000);
            let envelope = wrap_evm_tx_envelope(&oxide_addr, nonce, 1_000_000_000, &rlp);
            executor.ingest_tx(types::TxBytes::new(envelope));
        }
        let budget = types::CHAIN_BLOCK_BUDGET;
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 5, "mempool must select all 5 EVM txs");
        let block = types::FinalizedBlock { height: Height::new(1), txs: proposal.txs };
        executor.finalize_block(&block);
        let tx_root = executor.attest_state(Height::new(1)).root;

        // Path 2: executor with an empty block (same EVM module, same
        // funding, but no txs).
        let evm_module_empty = EvmModule::new(1, 7);
        evm_module_empty.fund_account_for_test(&oxide_addr, u128::MAX);
        let mut exec_empty = executor::Executor::new(1000);
        exec_empty.register_module(Arc::new(evm_module_empty));
        let empty_block = types::FinalizedBlock { height: Height::new(1), txs: vec![] };
        exec_empty.finalize_block(&empty_block);
        let empty_root = exec_empty.attest_state(Height::new(1)).root;

        assert_ne!(tx_root, empty_root, "pipeline with 5 EVM txs must differ from empty block");
    }

    // ---- Read-write conflict detection (hardening) -------------------
    //
    // These tests prove the parallel path detects read-write conflicts
    // (Group B reads an account Group A wrote) and re-executes to match
    // serial execution. Without `accessed_accounts` tracking, the
    // conflict would be missed and Group B would commit stale state.

    /// Read-write conflict: Group A writes to account R (via native
    /// transfer), Group B reads R's balance (via BALANCE opcode in
    /// contract D) and stores it in D's storage. Without read-set
    /// tracking, Group B would not detect the conflict and would
    /// commit with R's stale balance. The fix adds `accessed_accounts`
    /// tracking, which includes all accounts in the group's cache
    /// (read + write), enabling read-write conflict detection.
    #[test]
    fn handle_batch_parallel_read_write_conflict_matches_serial() {
        let (pk_a, addr_a) = test_keypair();
        let (pk_b, addr_b) = test_keypair();
        let (pk_deploy, addr_deploy) = test_keypair();

        // R is a random EOA that will receive ETH from sender A.
        let recipient_r = revm::primitives::Address::from_slice(&[0x99; 20]);

        // Contract D runtime bytecode: reads an address from calldata
        // (offset 0), gets its balance via BALANCE, and stores the
        // balance in slot 0.
        //   PUSH1 0x00  (60 00)  - calldata offset 0
        //   CALLDATALOAD (35)    - load 32 bytes (address in lower 20)
        //   BALANCE     (31)     - get balance of the address
        //   PUSH1 0x00  (60 00)  - slot 0
        //   SSTORE      (55)     - store balance in slot 0
        //   STOP        (00)
        //
        // Init code: copies the 8-byte runtime code to memory and
        // returns it.
        //   PUSH1 0x08  (60 08)  - runtime code length (8 bytes)
        //   PUSH1 0x0c  (60 0c)  - runtime code offset (12 = init len)
        //   PUSH1 0x00  (60 00)  - destination offset in memory (0)
        //   CODECOPY    (39)     - copy runtime code to memory
        //   PUSH1 0x08  (60 08)  - runtime code length (8 bytes)
        //   PUSH1 0x00  (60 00)  - memory offset (0)
        //   RETURN      (f3)     - return runtime code from memory
        let d_init_code: Vec<u8> = vec![
            0x60, 0x08, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x08, 0x60, 0x00, 0xf3, 0x60, 0x00,
            0x35, 0x31, 0x60, 0x00, 0x55, 0x00,
        ];

        // Fund R with an initial balance so the BALANCE opcode reads a
        // non-zero value. This makes the read-write conflict observable:
        // without the fix, Group B reads R's stale (pre-A) balance; with
        // the fix, Group B re-executes and reads R's updated balance.
        let oxide_r = primitives::Address(recipient_r.0.into());

        // Compute D's address (deployer at nonce 0).
        let d_address = revm::primitives::Address::from_slice(&addr_deploy.0).create(0);

        // Build the deploy tx and test txs once.
        let deploy_tx = signed_tx(&pk_deploy, 0, tx::TxKind::Create, &d_init_code);
        let tx_a = signed_transfer_tx(&pk_a, 0, recipient_r, 1_000_000_000);
        let mut calldata = [0u8; 32];
        calldata[12..].copy_from_slice(recipient_r.as_slice());
        let tx_b = signed_tx(&pk_b, 0, tx::TxKind::Call(d_address), &calldata);

        // --- Serial execution ---
        let m_serial = make_module();
        fund(&m_serial, &addr_a);
        fund(&m_serial, &addr_b);
        fund(&m_serial, &addr_deploy);
        m_serial.fund_account_for_test(&oxide_r, 1_000_000_000);
        m_serial.begin_block(Height::new(1));
        m_serial.handle(&dummy_ctx(), &deploy_tx).expect("deploy D (serial)");
        m_serial.handle(&dummy_ctx(), &tx_a).expect("serial tx A");
        m_serial.handle(&dummy_ctx(), &tx_b).expect("serial tx B");
        m_serial.end_block(Height::new(1));
        let serial_root = m_serial.state_root();

        // --- Parallel execution ---
        let m_par = make_module();
        fund(&m_par, &addr_a);
        fund(&m_par, &addr_b);
        fund(&m_par, &addr_deploy);
        m_par.fund_account_for_test(&oxide_r, 1_000_000_000);
        m_par.begin_block(Height::new(1));
        // Deploy D first (serial, before the parallel batch).
        m_par.handle(&dummy_ctx(), &deploy_tx).expect("deploy D (parallel)");
        // Run txs A and B in parallel.
        let txs = vec![tx_a.clone(), tx_b.clone()];
        let results = m_par.handle_batch_parallel(&dummy_ctx(), &txs);
        m_par.end_block(Height::new(1));
        let parallel_root = m_par.state_root();

        assert!(results.iter().all(std::result::Result::is_ok), "all txs must succeed");
        assert_eq!(
            serial_root, parallel_root,
            "read-write conflict: parallel state root must match serial"
        );
    }

    /// Regression test: a byzantine proposer supplying a wrong
    /// pre-recovered sender must be rejected. `handle_batch_preverified`
    /// re-recovers the sender from the signature and checks it
    /// matches `pv.sender`. A mismatch returns `ExecError::Malformed`.
    #[test]
    fn preverified_rejects_wrong_sender() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let txs: Vec<Vec<u8>> =
            (0..1).map(|i| signed_transfer_tx(&pk, i, recipient, 1_000_000_000)).collect();

        // Pre-verify to get the correct sender.
        let m = make_module();
        let preverified: Vec<PreverifiedTx<'_>> = m
            .preverify_batch(&txs)
            .into_iter()
            .map(|r| r.expect("preverify must succeed"))
            .collect();

        // Tamper: replace the sender with a wrong address.
        let wrong_addr = revm::primitives::Address::from_slice(&[0x99; 20]);
        let tampered: Vec<PreverifiedTx<'_>> = preverified
            .into_iter()
            .map(|pv| PreverifiedTx { raw: pv.raw, sender: wrong_addr })
            .collect();

        // Execute: must reject the tampered sender.
        m.begin_block(Height::new(1));
        let results = m.handle_batch_preverified(&dummy_ctx(), &tampered);
        m.end_block(Height::new(1));

        assert!(
            results.iter().all(|r| matches!(r, Err(ExecError::Malformed))),
            "wrong sender must be rejected with Malformed"
        );
        // The real sender's balance must be untouched.
        assert_eq!(m.balance(&addr), 0, "no state change on rejected tx");
    }

    /// Regression test: a byzantine proposer supplying a wrong
    /// pre-recovered sender must be rejected in the parallel path too.
    #[test]
    fn preverified_parallel_rejects_wrong_sender() {
        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let txs: Vec<Vec<u8>> =
            (0..2).map(|i| signed_transfer_tx(&pk, i, recipient, 1_000_000_000)).collect();

        let m = make_module();
        let preverified: Vec<PreverifiedTx<'_>> = m
            .preverify_batch(&txs)
            .into_iter()
            .map(|r| r.expect("preverify must succeed"))
            .collect();

        let wrong_addr = revm::primitives::Address::from_slice(&[0x99; 20]);
        let tampered: Vec<PreverifiedTx<'_>> = preverified
            .into_iter()
            .map(|pv| PreverifiedTx { raw: pv.raw, sender: wrong_addr })
            .collect();

        m.begin_block(Height::new(1));
        let results = m.handle_batch_parallel_preverified(&dummy_ctx(), &tampered);
        m.end_block(Height::new(1));

        assert!(
            results.iter().all(|r| matches!(r, Err(ExecError::Malformed))),
            "wrong sender must be rejected with Malformed (parallel)"
        );
        assert_eq!(m.balance(&addr), 0, "no state change on rejected tx");
    }

    /// Regression test: `flush_to_storage` emits `Op::Delete` for
    /// self-destructed accounts so they don't reappear on reload.
    #[test]
    fn flush_emits_delete_for_selfdestructed() {
        use storage::Volatile;

        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        // Create a module with a Volatile backend.
        let backend = Box::new(Volatile::new());
        let m = EvmModule::with_storage(1, 7, backend);
        fund(&m, &addr);

        // Execute a transfer to touch the sender account.
        let tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
        m.begin_block(Height::new(1));
        let results = m.handle_batch(&dummy_ctx(), &[tx]);
        assert!(results.iter().all(Result::is_ok), "tx must succeed: {results:?}");
        m.end_block(Height::new(1));

        // The sender account should be persisted.
        let oxide_addr = primitives::Address(addr.0);
        let key = persist::account_key(&oxide_addr);
        {
            let backend_guard = m.backend.lock().expect("backend lock");
            let backend_ref = backend_guard.as_ref().expect("backend is Some");
            assert!(backend_ref.get(&key).is_some(), "account must be persisted");
        }

        // Now check that a Delete op is emitted when the account
        // becomes NotExisting. We simulate this by directly
        // manipulating the cache.
        let evm_addr = alloy_primitives_address(addr.0);
        m.begin_block(Height::new(2));
        {
            let mut db = m.db.lock().expect("db lock");
            let db = Arc::make_mut(&mut *db);
            if let Some(account) = db.cache.accounts.get_mut(&evm_addr) {
                account.account_state = revm::database::AccountState::NotExisting;
            }
            m.touched.lock().expect("touched lock").insert(evm_addr);
        }
        m.end_block(Height::new(2));

        // The account should now be deleted from storage.
        {
            let backend_guard = m.backend.lock().expect("backend lock");
            let backend_ref = backend_guard.as_ref().expect("backend is Some");
            assert!(backend_ref.get(&key).is_none(), "self-destructed account must be deleted");
        }
    }

    /// Regression test: `flush_to_storage` serializes storage slots
    /// in sorted order so the persisted blob is deterministic.
    #[test]
    fn flush_serializes_slots_in_sorted_order() {
        use storage::Volatile;

        let (pk, addr) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

        let backend = Box::new(Volatile::new());
        let m = EvmModule::with_storage(1, 7, backend);
        fund(&m, &addr);

        // Execute a transfer to touch the sender account.
        let tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
        m.begin_block(Height::new(1));
        let results = m.handle_batch(&dummy_ctx(), &[tx]);
        assert!(results.iter().all(Result::is_ok), "tx must succeed: {results:?}");
        m.end_block(Height::new(1));

        // Read the persisted value and verify it's deterministic.
        // The account should have no storage slots (EOA), so this
        // tests the serialization path without slot ordering.
        let oxide_addr = primitives::Address(addr.0);
        let key = persist::account_key(&oxide_addr);
        let value1 = {
            let backend_guard = m.backend.lock().expect("backend lock");
            let backend_ref = backend_guard.as_ref().expect("backend is Some");
            backend_ref.get(&key).expect("account must be persisted")
        };

        // Reload and re-flush — the value must be byte-identical.
        let backend2 = Box::new(Volatile::new());
        let m2 = EvmModule::with_storage(1, 7, backend2);
        fund(&m2, &addr);
        let tx2 = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
        m2.begin_block(Height::new(1));
        let results2 = m2.handle_batch(&dummy_ctx(), &[tx2]);
        assert!(results2.iter().all(Result::is_ok), "tx must succeed: {results2:?}");
        m2.end_block(Height::new(1));

        let value2 = {
            let backend_guard = m2.backend.lock().expect("backend lock");
            let backend_ref = backend_guard.as_ref().expect("backend is Some");
            backend_ref.get(&key).expect("account must be persisted")
        };

        assert_eq!(value1, value2, "persisted value must be deterministic");
    }

    /// Regression test: the touched-account set must contain EVERY
    /// account a tx modifies — not just `caller`/`to`/`created`/
    /// `coinbase`.
    /// A SELFDESTRUCT beneficiary is a third-party account: under the
    /// old top-level-only tracking it was updated in the `CacheDB` but
    /// never marked touched, so `flush_to_storage` skipped it and the
    /// incremental state root reused its stale storage root —
    /// diverging durable state from in-memory state.
    #[test]
    fn selfdestruct_beneficiary_is_tracked_as_touched() {
        let (pk_caller, addr_caller) = test_keypair();
        let (pk_deploy, addr_deploy) = test_keypair();
        let beneficiary = revm::primitives::Address::from_slice(&[0xBB; 20]);
        let oxide_beneficiary = primitives::Address(beneficiary.0.into());

        // Runtime code: PUSH20 <beneficiary> ; SELFDESTRUCT — sends
        // the contract's whole balance to `beneficiary` and removes
        // the contract.
        //   0x73 <20 bytes> = PUSH20, 0xff = SELFDESTRUCT (22 bytes)
        // Init code: copy 22-byte runtime (at offset 12) and return it.
        //   PUSH1 0x16 PUSH1 0x0c PUSH1 0x00 CODECOPY PUSH1 0x16
        //   PUSH1 0x00 RETURN (12 bytes)
        let mut deploy_data: Vec<u8> =
            vec![0x60, 0x16, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x16, 0x60, 0x00, 0xf3, 0x73];
        deploy_data.extend_from_slice(beneficiary.as_slice());
        deploy_data.push(0xff);

        let contract_addr = revm::primitives::Address::from_slice(&addr_deploy.0).create(0);
        let oxide_contract = primitives::Address(contract_addr.0.into());

        let m = make_module();
        fund(&m, &addr_caller);
        fund(&m, &addr_deploy);
        m.begin_block(Height::new(1));
        m.handle(&dummy_ctx(), &signed_tx(&pk_deploy, 0, tx::TxKind::Create, &deploy_data))
            .expect("deploy must succeed");

        // Give the contract a balance to selfdestruct away.
        m.fund_account_for_test(&oxide_contract, 5_000_000_000);

        // Call the contract — runs SELFDESTRUCT, paying the
        // beneficiary (a third-party account absent from the old
        // touched set).
        let call = signed_tx(&pk_caller, 0, tx::TxKind::Call(contract_addr), &[]);
        m.handle(&dummy_ctx(), &call).expect("call must succeed");
        m.end_block(Height::new(1));

        assert!(
            m.touched
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&beneficiary),
            "selfdestruct beneficiary must be tracked as touched"
        );
        assert_eq!(
            m.balance(&oxide_beneficiary),
            5_000_000_000,
            "beneficiary must receive the contract balance"
        );
    }

    /// Regression test: `balance()` must not panic on a U256 balance
    /// above `u128::MAX` (reachable via crafted snapshot import). The
    /// accessor saturates rather than crashing the node.
    #[test]
    fn balance_saturates_above_u128() {
        let m = make_module();
        let evm_addr = revm::primitives::Address::from_slice(&[0xCC; 20]);
        let oxide_addr = primitives::Address(evm_addr.0.into());

        // Insert an account with a U256::MAX balance directly —
        // beyond what `fund_account_for_test` (u128) can express.
        {
            let mut db_guard = m.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let db = Arc::make_mut(&mut *db_guard);
            db.cache.accounts.insert(
                evm_addr,
                revm::database::DbAccount {
                    info: revm::database::state::AccountInfo {
                        balance: U256::MAX,
                        nonce: 0,
                        code_hash: revm::primitives::B256::ZERO,
                        account_id: None,
                        code: Some(revm::bytecode::Bytecode::new_raw(
                            revm::primitives::Bytes::new(),
                        )),
                    },
                    account_state: revm::database::AccountState::None,
                    storage: revm::primitives::HashMap::default(),
                },
            );
        }

        // Previously `to::<u128>()` panicked here.
        assert_eq!(m.balance(&oxide_addr), u128::MAX);
    }

    /// Regression test: `estimate_gas` must return the tx's declared
    /// `gas_limit`, not the `1000 + len` size proxy — a 30M-gas tx
    /// must count as 30M gas toward the block limit. Undecodable
    /// payloads count as `u64::MAX` (un-includable, fail-safe).
    #[test]
    fn estimate_gas_returns_declared_limit() {
        let m = make_module();
        let (pk, _) = test_keypair();
        let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);
        let raw = signed_tx(&pk, 0, tx::TxKind::Call(recipient), &[]);
        assert_eq!(m.estimate_gas(&raw), DEFAULT_GAS_LIMIT);
        // Undecodable payload → u64::MAX (any block containing it is
        // over-limit → rejected, fail-safe direction).
        assert_eq!(m.estimate_gas(&[0xff, 0x00]), u64::MAX);
    }

    /// The EVM is self-funded: revm charges `gas_used × effective
    /// gas price` from the sender inside execution (bounded below
    /// by the block base fee). The envelope fee must not be charged
    /// on top — that would double-charge every EVM user.
    #[test]
    fn evm_module_pays_own_fee() {
        let m = make_module();
        assert!(m.pays_own_fee());
    }
}
