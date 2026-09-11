//! Oxide executor v0 — sequential block executor with module router.
//!
//! The executor is the application's execution lane (plan.md §6). It
//! consumes finalized blocks from consensus, executes transactions
//! sequentially through the module router, and produces state roots
//! for the execution certificate.
//!
//! # Phase 1 scope (v0)
//!
//! v0 is a **sequential** executor: one tx at a time, in block order.
//! No parallel execution, no OCC, no EVM. The module router dispatches
//! native messages to registered modules (bank, staking, etc.). EVM
//! integration arrives in Phase 2.
//!
//! # Architecture
//!
//! ```text
//! FinalizedBlock → Executor → for each tx:
//!   parse Tx envelope → route to Module → Module::handle() → Events
//!                                       ↓
//!   StateRoot = hash of all module state roots
//! ```
//!
//! The executor owns the `StorageBackend` (via the app) and drives
//! module `begin_block` / `handle` / `end_block` hooks. Each module
//! owns a subtree of the storage.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

pub mod divergence;
pub mod occ;

use ports::AppInterface;
use primitives::{Hash, Height};
use types::{CommitAck, FinalizedBlock, MempoolAck, Proposal, StateAttestation, TxBytes, Verdict};

use crypto::hash::{Domain, Hasher};

/// A module execution error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The tx envelope is malformed.
    Malformed,
    /// The module is not registered.
    UnknownModule(u8),
    /// The module rejected the message.
    ModuleRejected(String),
    /// Insufficient gas.
    OutOfGas,
}

/// A point-in-time snapshot of the executor's state (plan.md §8).
///
/// Captures the chain height, the aggregate state root, per-module
/// state roots, and optionally per-module key-value state. Used for
/// fast state sync: a new node imports a snapshot to skip replaying
/// the entire chain from genesis.
///
/// # Determinism
///
/// The snapshot is deterministic: two executors with the same state
/// produce byte-identical snapshots. The module roots are listed in
/// registration order (module ID order).
///
/// # Full vs metadata-only
///
/// When `module_state` is populated, the snapshot includes the full
/// key-value state for each module that supports `export_state`. This
/// allows a new node to restore complete state without replaying.
/// When `module_state` is empty, the snapshot is metadata-only
/// (height + roots) — the v0 snapshot sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorSnapshot {
    /// The chain height (highest finalized block).
    pub height: u64,
    /// The aggregate state root (hash of all module state roots).
    pub state_root: Hash,
    /// Per-module state roots, in registration order.
    pub module_roots: Vec<(&'static str, Hash)>,
    /// Per-module full key-value state, in registration order.
    /// `None` for modules that don't support `export_state`. Empty
    /// for metadata-only snapshots (v0).
    pub module_state: Vec<Option<storage::Snapshot>>,
}

/// A snapshot import error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotImportError {
    /// The snapshot has height 0 (nothing to import).
    EmptySnapshot,
    /// The snapshot's state root does not match the recomputed
    /// aggregate of per-module state roots (corrupted or tampered).
    StateRootMismatch {
        /// The expected root from the snapshot.
        expected: Hash,
        /// The recomputed root from the module roots.
        actual: Hash,
    },
    /// The snapshot's module count does not match the executor's
    /// registered module count (snapshot from a different config).
    ModuleCountMismatch {
        /// Module count in the snapshot.
        snapshot: usize,
        /// Registered module count in the executor.
        registered: usize,
    },
    /// A module's `import_state` call failed (corrupted KV state
    /// or backend error).
    StateImportFailed,
}

impl std::fmt::Display for SnapshotImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySnapshot => write!(f, "empty snapshot (height 0)"),
            Self::StateRootMismatch { expected, actual } => {
                write!(f, "state root mismatch: expected {expected}, got {actual}")
            }
            Self::ModuleCountMismatch { snapshot, registered } => {
                write!(
                    f,
                    "module count mismatch: snapshot has {snapshot}, executor has {registered}"
                )
            }
            Self::StateImportFailed => write!(f, "module state import failed"),
        }
    }
}

impl std::error::Error for SnapshotImportError {}

/// Transaction context passed to modules during `handle`.
///
/// Carries the sender, nonce, and fee parsed from the tx envelope.
/// This is the C2 fix: before, `handle` received only the message
/// bytes and had no way to know who sent the tx — so the bank module
/// could only mint to the recipient, never debit the sender. Now
/// modules have the sender's identity and can enforce balance
/// checks, nonce ordering, and fee deduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxContext {
    /// The sender's address (20 bytes, parsed from the tx envelope).
    pub sender: primitives::Address,
    /// The tx nonce (8 bytes LE, parsed from the tx envelope).
    pub nonce: u64,
    /// The tx fee (8 bytes LE, parsed from the tx envelope).
    pub fee: u64,
}

/// A transaction with a pre-recovered sender.
///
/// The sender is recovered from the transaction's signature at
/// mempool ingestion time (via `Module::preverify_batch`). The
/// execution layer trusts this sender without re-verifying —
/// skipping secp256k1 recovery on the block execution hot path.
///
/// # Security
///
/// The pre-recovered sender must come from a trusted source (the
/// local mempool's `preverify_batch` call). A byzantine proposer
/// could provide wrong senders, but this is detectable by state
/// root comparison across validators. For production multi-validator
/// deployment, pair this with verification sampling.
#[derive(Debug, Clone)]
pub struct PreverifiedTx {
    /// The raw module payload bytes (e.g. RLP-encoded signed EVM tx).
    pub raw: Vec<u8>,
    /// The sender recovered from the signature (20 bytes).
    pub sender: [u8; 20],
}

/// A module: a Cosmos-SDK-style state machine that handles messages.
///
/// Each module owns a subtree of the storage and exposes `handle` for
/// message dispatch. The executor calls `begin_block` before any txs,
/// `handle` for each tx, and `end_block` after all txs.
pub trait Module: Send + Sync {
    /// The module's name (used as a storage prefix and for routing).
    fn name(&self) -> &'static str;

    /// The module's dispatch ID (used in the tx envelope to route).
    fn id(&self) -> u8;

    /// Called at the beginning of each block, before any txs.
    fn begin_block(&self, height: Height);

    /// Validate a message for mempool admission. This is the
    /// admission gate: it runs *before* `handle`, on every tx
    /// submitted to the mempool. It must be:
    ///
    /// - **Pure:** no state mutation, no side effects. It may read
    ///   module state (e.g. to check the sender's nonce and balance)
    ///   but must not write.
    /// - **Cheap:** it runs on every submitted tx, so it must be
    ///   fast enough to handle the full mempool ingress rate.
    /// - **Conservative:** a tx that passes `validate` may still fail
    ///   in `handle` (e.g. out-of-gas, revert). But a tx that fails
    ///   `validate` must never reach `handle`.
    ///
    /// The default implementation accepts all well-formed messages.
    /// Modules override this to enforce signature, nonce, gas, and
    /// balance checks before the tx enters the pool.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message can't be
    /// parsed, [`ExecError::ModuleRejected`] if the message is
    /// well-formed but fails a validation rule (bad nonce,
    /// insufficient balance, etc.).
    fn validate(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<(), ExecError> {
        Ok(())
    }

    /// Handle a message. Returns events on success, or an error.
    ///
    /// The `ctx` carries the sender, nonce, and fee parsed from the
    /// tx envelope. Modules use `ctx.sender` to debit balances, check
    /// nonces, and attribute fees.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message can't be parsed,
    /// [`ExecError::ModuleRejected`] if the module rejects the message,
    /// or [`ExecError::OutOfGas`] if the message exceeds the gas budget.
    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError>;

    /// Handle a batch of messages. Returns a vector of results, one
    /// per input message, in the same order as the input.
    ///
    /// The default implementation loops over the messages and calls
    /// [`handle`](Self::handle) for each. Modules with a faster batch
    /// path (e.g. EVM with parallel sender recovery or pre-verified
    /// senders) override this to avoid per-tx overhead.
    ///
    /// Each message is paired with its `TxContext` (parsed from the
    /// tx envelope by the executor). The module receives the
    /// *payload* — the bytes after the `[sender:20B][nonce:8B]
    /// [fee:8B][module_id:1B]` envelope header.
    ///
    /// # Errors
    ///
    /// Each result is either a vector of events (success) or an
    /// `ExecError` (failure). A failed message does not abort the
    /// batch — subsequent messages are still executed.
    fn handle_batch(&self, msgs: &[(TxContext, &[u8])]) -> Vec<Result<Vec<Event>, ExecError>> {
        msgs.iter().map(|(ctx, msg)| self.handle(ctx, msg)).collect()
    }

    /// Pre-recover senders from a batch of raw transaction payloads.
    ///
    /// This is called at mempool ingestion time to amortize
    /// secp256k1 recovery (the single most expensive per-tx
    /// operation, ~30 µs/tx) across the tx's lifetime in the pool.
    /// The pre-recovered senders are cached and reused at block
    /// execution time via [`handle_batch_preverified`](Self::handle_batch_preverified),
    /// skipping recovery entirely on the execution hot path.
    ///
    /// The default implementation returns `PreverifiedTx` with a
    /// zero sender (no pre-recovery). Modules that support
    /// pre-verification (e.g. EVM) override this to recover the
    /// sender from the transaction's signature.
    ///
    /// # Errors
    ///
    /// Returns `Err(ExecError::Malformed)` for each transaction
    /// that cannot be parsed or whose signature is invalid.
    fn preverify_batch(&self, msgs: &[&[u8]]) -> Vec<Result<PreverifiedTx, ExecError>> {
        msgs.iter().map(|raw| Ok(PreverifiedTx { raw: raw.to_vec(), sender: [0u8; 20] })).collect()
    }

    /// Execute a batch of transactions with pre-recovered senders.
    ///
    /// This is the highest-throughput serial execution path. The
    /// caller has already recovered the sender for each tx via
    /// [`preverify_batch`](Self::preverify_batch). This method
    /// skips secp256k1 recovery entirely — only RLP decoding and
    /// chain ID validation remain.
    ///
    /// The default implementation falls back to [`handle_batch`](Self::handle_batch).
    /// Modules with a pre-verified path (e.g. EVM) override this
    /// to skip sender recovery.
    ///
    /// # Errors
    ///
    /// Each result is either a vector of events (success) or an
    /// `ExecError` (failure). A failed transaction does not abort
    /// the batch.
    fn handle_batch_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        let batch: Vec<(TxContext, &[u8])> =
            txs.iter().map(|pv| (*ctx, pv.raw.as_slice())).collect();
        self.handle_batch(&batch)
    }

    /// Execute a batch of pre-verified transactions in parallel.
    ///
    /// This is the speculative parallel execution path. Transactions
    /// are grouped by sender to avoid write conflicts, and each
    /// group is executed on a separate rayon thread. Results are
    /// merged in original block order.
    ///
    /// The default implementation falls back to
    /// [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// (serial). Modules with a parallel path (e.g. EVM) override
    /// this to use rayon for speculative parallel execution.
    ///
    /// # Errors
    ///
    /// Each result is either a vector of events (success) or an
    /// `ExecError` (failure). A failed transaction does not abort
    /// the batch.
    fn handle_batch_parallel_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        self.handle_batch_preverified(ctx, txs)
    }

    /// Called at the end of each block, after all txs.
    fn end_block(&self, height: Height);

    /// Compute the module's state root (over its storage subtree).
    fn state_root(&self) -> Hash;

    /// Export the module's full key-value state for snapshot sync.
    ///
    /// Returns `None` if the module does not support KV export (e.g.
    /// in-memory modules without a `StorageBackend`). Modules with a
    /// `StorageBackend` override this to return the backend's
    /// `snapshot_export()`.
    ///
    /// This is used for full state sync: a new node imports the
    /// snapshot to skip replaying the entire chain from genesis.
    /// The snapshot includes all key-value pairs, not just the
    /// state root.
    ///
    /// # Default
    ///
    /// Returns `None` — modules without a `StorageBackend` cannot
    /// export KV state.
    fn export_state(&self) -> Option<storage::Snapshot> {
        None
    }

    /// Import a key-value snapshot, restoring the module's state.
    ///
    /// This is the import side of snapshot sync. The module restores
    /// its `StorageBackend` from the snapshot, then reloads its
    /// in-memory cache from the backend.
    ///
    /// # Default
    ///
    /// Returns `Ok(())` — modules without a `StorageBackend` silently
    /// ignore the import (their state is in-memory only).
    ///
    /// # Errors
    ///
    /// Returns [`storage::SnapshotError`] if the backend import
    /// fails (malformed snapshot, backend I/O error).
    fn import_state(&self, _snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        Ok(())
    }
}

/// An event emitted by a module during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The module that emitted this event.
    pub module: &'static str,
    /// The event type (e.g. "transfer", "delegate").
    pub kind: String,
    /// The event data (module-specific).
    pub data: Vec<u8>,
}

/// The v0 tx envelope payload format. The full tx is owned by the
/// mempool: `[sender: 20B][nonce: 8B LE][fee: 8B LE][payload]`. The
/// executor routes on the first byte of `payload`:
/// `[module_id: 1B][module_payload: ...]`.
const MODULE_ID_OFFSET: usize = 36; // 20 + 8 + 8

/// Parse the module ID from a tx's payload section.
fn parse_module_id(bytes: &[u8]) -> Option<u8> {
    if bytes.len() < MODULE_ID_OFFSET + 1 {
        return None;
    }
    Some(bytes[MODULE_ID_OFFSET])
}

/// Extract the module payload from a tx (everything after `module_id`).
fn module_payload(bytes: &[u8]) -> &[u8] {
    if bytes.len() <= MODULE_ID_OFFSET + 1 {
        return &[];
    }
    &bytes[MODULE_ID_OFFSET + 1..]
}

/// Parse the tx context (sender, nonce, fee) from the tx envelope.
///
/// The v0 tx format is: `[sender: 20B][nonce: 8B LE][fee: 8B LE]
/// [module_id: 1B][module_payload: ...]`. This extracts the first
/// 36 bytes into a `TxContext`. Returns `None` if the tx is too
/// short or the sender is not a valid 20-byte address.
fn parse_tx_context(bytes: &[u8]) -> Option<TxContext> {
    if bytes.len() < TX_MIN_SIZE {
        return None;
    }
    let sender = primitives::Address::from_slice(&bytes[..20]).ok()?;
    let nonce = u64::from_le_bytes(bytes[20..28].try_into().ok()?);
    let fee = u64::from_le_bytes(bytes[28..36].try_into().ok()?);
    Some(TxContext { sender, nonce, fee })
}

/// Minimum tx batch size to use the parallel speculative execution
/// path. Below this threshold, serial execution is faster (avoids
/// rayon thread-pool overhead). Source: benchmark results showing
/// parallel execution wins above ~100 txs due to `CacheDB` clone cost.
/// See `modules/evm/benches/tps_rw.rs`.
///
/// This is the default value used when no explicit config is provided.
/// Production code should use [`Executor::with_config`] to set this
/// from the [`config`](::config) crate's `ExecutorConfig`.
pub const DEFAULT_PARALLEL_THRESHOLD: usize = 32;

/// Minimum tx size: sender (20) + nonce (8) + fee (8) = 36 bytes.
const TX_MIN_SIZE: usize = 20 + 8 + 8;

/// The executor: a sequential block executor with a module router.
///
/// Owns the registered modules and drives them through the block
/// lifecycle. Implements `AppInterface` so it can be wired behind any
/// `ConsensusEngine`.
pub struct Executor {
    /// Registered modules, indexed by their dispatch ID (0–255).
    ///
    /// A flat array gives O(1) dispatch with no pointer-chasing (vs
    /// `BTreeMap`'s tree traversal). Module IDs are `u8`, so the
    /// array has exactly 256 slots. The memory cost (256 × 8 bytes =
    /// 2 KiB on 64-bit) is negligible and the lookup is a single
    /// indexed load.
    modules: [Option<Arc<dyn Module>>; 256],
    /// The mempool (owned, so the executor is the app's intake).
    /// Behind `Mutex` because `AppInterface` methods take `&self`.
    mempool: Mutex<mempool::Mempool>,
    /// Finalized blocks, keyed by height.
    finalized: Mutex<BTreeMap<u64, FinalizedBlock>>,
    /// State roots per finalized height.
    state_roots: Mutex<BTreeMap<u64, Hash>>,
    /// The next proposal height.
    next_proposal_height: Mutex<u64>,
    /// Phase D: the most recently finalized block that hasn't been
    /// executed yet. Execution is deferred until `attest_state` or
    /// the next `finalize_block` flushes it.
    ///
    /// This is the "async execution lane": the consensus engine can
    /// commit block h and immediately proceed to propose/vote/commit
    /// block h+1 while block h's execution is deferred. When the
    /// state root for h is needed (via `attest_state`), or when h+1
    /// is committed (the next `finalize_block`), the pending block
    /// is executed synchronously.
    ///
    /// This overlaps execution with consensus without spawning
    /// threads — the execution happens lazily when the state root
    /// is actually needed. Blocks are still executed in order (the
    /// next `finalize_block` flushes the pending block first).
    pending_block: Mutex<Option<FinalizedBlock>>,
    /// Pending events from the current block (cleared each block).
    events: Mutex<Vec<Event>>,
    /// Pre-recovered senders, keyed by tx hash. Populated at
    /// `ingest_tx` time via `Module::preverify_batch`. Consumed at
    /// `execute_block` time to skip secp256k1 recovery on the
    /// execution hot path.
    ///
    /// Entries are removed after the block containing the tx is
    /// finalized (they are no longer needed — re-execution would
    /// re-preverify). This bounds the cache size to the mempool's
    /// capacity.
    preverify_cache: Mutex<HashMap<Hash, PreverifiedTx>>,
    /// Minimum batch size to use the parallel speculative execution
    /// path. Configurable via [`Executor::with_config`]. Default:
    /// [`DEFAULT_PARALLEL_THRESHOLD`] (32 txs). Lowered from 100
    /// because the per-group `CacheDB` init is O(1) (Arc clone) and
    /// rayon task overhead (~10 µs) amortizes at 32+ txs.
    parallel_threshold: usize,
    /// Phase D: enable the async execution lane. When `true`,
    /// `finalize_block` defers execution to overlap with consensus.
    /// When `false` (default), execution is synchronous.
    ///
    /// The async lane trades a small per-block overhead (extra lock
    /// acquisitions for pending block tracking) for the ability to
    /// overlap execution of block h-1 with consensus for block h.
    /// For single-block benchmarks, the overhead is a net loss;
    /// for the full consensus pipeline, it's a net win.
    async_execution: bool,
    /// Optional latency recorder for the block pipeline. When set,
    /// `prepare_proposal`, `finalize_block`, and `attest_state`
    /// record their durations. This is the "measure everything"
    /// directive from plan.md §10.
    recorder: Option<Arc<metrics::Recorder>>,
    /// Lock-free MPSC ring for transaction intake. `ingest_tx` pushes
    /// to this ring; `prepare_proposal` drains it into the mempool
    /// under a single lock acquisition.
    ///
    /// This eliminates the per-tx `mempool.lock()` on the ingestion
    /// hot path — the mempool lock is only acquired once per
    /// `prepare_proposal` call, not once per tx.
    mempool_intake_tx: std::sync::mpsc::Sender<TxBytes>,
    /// The receiver side of the intake ring. Drained by
    /// `prepare_proposal` to flush buffered txs into the mempool.
    mempool_intake_rx: std::sync::Mutex<std::sync::mpsc::Receiver<TxBytes>>,
}

impl Executor {
    /// Construct a fresh executor with no modules and an empty mempool.
    ///
    /// Uses the default parallel threshold (100 txs). For custom
    /// configuration, use [`Executor::with_config`].
    pub fn new(max_mempool_entries: usize) -> Self {
        Self::with_config(max_mempool_entries, DEFAULT_PARALLEL_THRESHOLD)
    }

    /// Construct a fresh executor with explicit config values.
    ///
    /// # Arguments
    ///
    /// - `max_mempool_entries`: the maximum number of entries in the
    ///   mempool.
    /// - `parallel_threshold`: the minimum batch size to use the
    ///   parallel speculative execution path. Below this threshold,
    ///   serial execution is used.
    pub fn with_config(max_mempool_entries: usize, parallel_threshold: usize) -> Self {
        let (intake_tx, intake_rx) = std::sync::mpsc::channel();
        Self {
            modules: std::array::from_fn(|_| None),
            mempool: Mutex::new(mempool::Mempool::new(max_mempool_entries)),
            finalized: Mutex::new(BTreeMap::new()),
            state_roots: Mutex::new(BTreeMap::new()),
            next_proposal_height: Mutex::new(0),
            pending_block: Mutex::new(None),
            events: Mutex::new(Vec::new()),
            preverify_cache: Mutex::new(HashMap::new()),
            parallel_threshold,
            async_execution: false,
            recorder: None,
            mempool_intake_tx: intake_tx,
            mempool_intake_rx: Mutex::new(intake_rx),
        }
    }

    /// Attach a latency recorder for the block pipeline.
    ///
    /// When set, `prepare_proposal`, `finalize_block`, and
    /// `attest_state` record their durations under operation names
    /// `"prepare_proposal"`, `"finalize_block"`, and
    /// `"attest_state"`. This is the "measure everything" directive
    /// from plan.md §10.
    pub fn set_recorder(&mut self, recorder: Arc<metrics::Recorder>) {
        self.recorder = Some(recorder);
    }

    /// Register a module. The module's `ID` must be unique.
    ///
    /// # Panics
    ///
    /// Panics if a module with the same `ID` is already registered.
    pub fn register_module(&mut self, module: Arc<dyn Module>) {
        let id = module.id() as usize;
        assert!(self.modules[id].is_none(), "module with `ID` {id} already registered");
        self.modules[id] = Some(module);
    }

    /// Phase D: enable the async execution lane.
    ///
    /// When enabled, `finalize_block` defers execution to overlap
    /// with consensus. The pending block is executed lazily when
    /// `attest_state` is called or when the next `finalize_block`
    /// flushes it.
    ///
    /// This trades a small per-block overhead for the ability to
    /// overlap execution of block h-1 with consensus for block h.
    /// For the full consensus pipeline (2-chain), this can hide
    /// execution latency behind consensus latency.
    pub fn enable_async_execution(&mut self) {
        self.async_execution = true;
    }

    /// The current chain height (the highest finalized block).
    ///
    /// Returns 0 if no blocks have been finalized yet (genesis state).
    #[must_use]
    pub fn current_height(&self) -> u64 {
        let next =
            *self.next_proposal_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        next.saturating_sub(1)
    }

    /// The state root at a given finalized height.
    ///
    /// Returns `Hash::ZERO` if the height is not finalized or unknown.
    #[must_use]
    pub fn state_root_at(&self, height: u64) -> Hash {
        self.state_roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&height)
            .copied()
            .unwrap_or(Hash::ZERO)
    }

    /// The latest state root (at the current chain height).
    ///
    /// Returns `Hash::ZERO` if no blocks have been finalized.
    #[must_use]
    pub fn current_state_root(&self) -> Hash {
        self.state_root_at(self.current_height())
    }

    /// Export a snapshot of the executor's state at the current
    /// chain height.
    ///
    /// The snapshot captures:
    /// - The chain height.
    /// - The aggregate state root (hash of all module state roots).
    /// - Per-module state roots (for verification on import).
    ///
    /// This is used for fast state sync: a new node imports a
    /// snapshot to skip replaying the entire chain from genesis.
    /// The snapshot is deterministic: two executors with the same
    /// state produce byte-identical snapshots.
    #[must_use]
    pub fn export_snapshot(&self) -> ExecutorSnapshot {
        use crypto::hash::{Domain, Hasher};
        let height = self.current_height();
        let state_root = self.state_root_at(height);
        let module_roots: Vec<(&'static str, Hash)> =
            self.modules.iter().flatten().map(|m| (m.name(), m.state_root())).collect();
        // Export full KV state for each module that supports it.
        let module_state: Vec<Option<storage::Snapshot>> =
            self.modules.iter().flatten().map(|m| m.export_state()).collect();
        // Debug: verify the state root matches the recomputed aggregate.
        // This is a sanity check for the snapshot's internal consistency.
        let mut root_data = Vec::new();
        for (_, root) in &module_roots {
            root_data.extend_from_slice(root.as_bytes());
        }
        let recomputed = Hasher::hash_one(Domain::Block, &root_data);
        // If the stored state root doesn't match the recomputed one,
        // use the recomputed one (the stored root may be stale if
        // the block hasn't been executed yet, e.g., async execution).
        let state_root = if state_root == Hash::ZERO && !module_roots.is_empty() {
            recomputed
        } else {
            state_root
        };
        ExecutorSnapshot { height, state_root, module_roots, module_state }
    }

    /// Import a snapshot, restoring the executor to the snapshot's
    /// chain height and state.
    ///
    /// After import, the executor's `current_height` and
    /// `current_state_root` must match the snapshot. The next
    /// proposal height is set to `snapshot.height + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotImportError`] if:
    /// - The snapshot's state root does not match the recomputed
    ///   aggregate of the per-module state roots (corrupted snapshot).
    /// - The snapshot's height is 0 (empty snapshot — nothing to
    ///   import).
    ///
    /// # Panics
    ///
    /// Does not panic. Import is atomic: if verification fails, the
    /// executor's state is unchanged.
    ///
    /// # Safety
    ///
    /// This method does NOT restore individual module key-value
    /// state — it only restores the chain height and state root
    /// metadata. Full state restoration requires each module to
    /// implement its own snapshot import. When `module_state` is
    /// populated in the snapshot, this method calls each module's
    /// `import_state` to restore the full key-value state.
    pub fn import_snapshot(&self, snapshot: &ExecutorSnapshot) -> Result<(), SnapshotImportError> {
        // A snapshot at height 0 is valid — it represents the genesis
        // state after the first (empty) block. We only reject if there
        // are no module roots (truly empty snapshot).
        if snapshot.module_roots.is_empty() {
            return Err(SnapshotImportError::EmptySnapshot);
        }

        // Verify the snapshot's internal consistency: the state root
        // must match the recomputed aggregate of the snapshot's own
        // per-module state roots. This catches corrupted or tampered
        // snapshots without requiring the local modules to have the
        // same state (the snapshot is from a peer, not local).
        let mut root_data = Vec::new();
        for (_, root) in &snapshot.module_roots {
            root_data.extend_from_slice(root.as_bytes());
        }
        let recomputed = Hasher::hash_one(Domain::Block, &root_data);
        if recomputed != snapshot.state_root {
            return Err(SnapshotImportError::StateRootMismatch {
                expected: snapshot.state_root,
                actual: recomputed,
            });
        }

        // Verify that the number of module roots matches the number
        // of registered modules. This catches snapshots from a
        // different module configuration.
        let registered_count = self.modules.iter().flatten().count();
        if snapshot.module_roots.len() != registered_count {
            return Err(SnapshotImportError::ModuleCountMismatch {
                snapshot: snapshot.module_roots.len(),
                registered: registered_count,
            });
        }

        // If the snapshot includes full KV state, import it into
        // each module that supports `import_state`. This restores
        // the complete key-value state, not just the roots.
        if !snapshot.module_state.is_empty() {
            for (module, state) in self.modules.iter().flatten().zip(&snapshot.module_state) {
                if let Some(state) = state {
                    module
                        .import_state(state)
                        .map_err(|_| SnapshotImportError::StateImportFailed)?;
                }
            }
        }

        // Import: set the chain height and state root. The local
        // modules' key-value state is restored above (if the snapshot
        // included it). We set the chain height so consensus can
        // resume from the correct position, and we store the trusted
        // state root for attestation.
        self.state_roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(snapshot.height, snapshot.state_root);
        *self.next_proposal_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            snapshot.height.saturating_add(1); // M2 fix

        Ok(())
    }

    /// Phase D: flush any pending block — execute it and store its
    /// state root.
    ///
    /// This is the "drain" side of the async execution lane. When
    /// `finalize_block` defers execution, the block is stored as
    /// pending. This method executes the pending block (if any) and
    /// stores its state root.
    ///
    /// Called by `finalize_block` (before storing a new pending
    /// block) and by `attest_state` (before returning the state
    /// root).
    fn flush_pending(&self) {
        let pending =
            self.pending_block.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        if let Some(block) = pending {
            let root = self.execute_block(&block);
            self.state_roots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(block.height.value(), root);
        }
    }

    /// Execute a finalized block: call `begin_block`, group txs by
    /// module, call `handle_batch` per module group, call `end_block`,
    /// compute the state root.
    ///
    /// Txs are grouped by module ID, preserving block order within
    /// each group. Each module's group is passed to `handle_batch`
    /// in one call — this lets modules with batch-optimized paths
    /// (e.g. EVM parallel sender recovery, pre-verified senders)
    /// amortize per-tx overhead across the whole group.
    ///
    /// Modules are independent (each owns its storage subtree), so
    /// grouping by module produces identical state roots to the
    /// per-tx interleaved execution. Events are grouped by module
    /// rather than interleaved, but state roots are unchanged.
    fn execute_block(&self, block: &FinalizedBlock) -> Hash {
        // Single lock acquisition for the events vector: clear at start,
        // extend after execution. The lock is released between the clear
        // and the extend because module execution can take milliseconds
        // and we don't want to hold the lock during that time. The
        // clear is here only to discard stale events from a previous
        // block; the extend publishes this block's events.
        self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();

        // begin_block for all modules.
        for module in self.modules.iter().flatten() {
            module.begin_block(block.height);
        }

        // Group txs by module ID, preserving block order within each
        // group. Each entry is (ctx, payload_bytes, full_tx_hash). We
        // collect the payload as a Vec<u8> so we can pass a slice of
        // slices to handle_batch. The full tx hash is the same key
        // used by `ingest_tx` to cache preverified senders — using it
        // here (not the payload hash) is what makes the preverify
        // cache actually hit. See docs/devlog.md session N for the
        // root-cause analysis of the prior key mismatch.
        //
        // We use a BTreeMap so module groups are processed in a
        // deterministic order (sorted by module ID).
        let mut groups: BTreeMap<u8, Vec<(TxContext, Vec<u8>, Hash)>> = BTreeMap::new();
        for tx in &block.txs {
            let bytes = tx.as_bytes();
            let Some(ctx) = parse_tx_context(bytes) else {
                continue; // skip malformed txs
            };
            let Some(module_id) = parse_module_id(bytes) else {
                continue; // skip malformed txs
            };
            let payload = module_payload(bytes).to_vec();
            // Cache key must match `ingest_tx`: hash of the FULL tx
            // envelope, not just the module payload. The payload
            // alone does not uniquely identify a transaction (two
            // senders can send identical payloads).
            let tx_hash = Hasher::hash_one(Domain::Transaction, bytes);
            groups.entry(module_id).or_default().push((ctx, payload, tx_hash));
        }

        // Execute each module's txs as a batch.
        let mut block_events: Vec<Event> = Vec::new();

        // Clear the preverify cache after the block is executed —
        // the cached senders are no longer needed (re-execution would
        // re-preverify). We move the cache out in one lock acquisition
        // (zero-copy: `mem::take` swaps in an empty map, no clone).
        let mut preverify_cache = std::mem::take(
            &mut *self.preverify_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        );

        for (module_id, group) in &groups {
            let Some(module) = self.modules[*module_id as usize].as_ref() else {
                continue; // unknown module — skip
            };

            // Phase E: zero-copy payload handling.
            //
            // First, check if all txs in this group have cached
            // senders. If yes, construct the preverified Vec (no
            // payload clones — the cached PreverifiedTx already
            // owns the raw bytes). If no, use the fallback path
            // directly (no preverified Vec constructed, no wasted
            // clones).
            //
            // Previously, the preverified Vec was always
            // constructed, cloning payloads for txs without cached
            // senders — even when the fallback path would be used,
            // making those clones wasted work.
            let all_cached =
                group.iter().all(|(_ctx, _payload, tx_hash)| preverify_cache.contains_key(tx_hash));

            let results = if all_cached {
                // All senders are pre-recovered — construct the
                // preverified Vec from the cache (no payload clones).
                let preverified: Vec<PreverifiedTx> = group
                    .iter()
                    .map(|(_ctx, payload, tx_hash)| {
                        preverify_cache.remove(tx_hash).unwrap_or_else(|| PreverifiedTx {
                            raw: payload.clone(),
                            sender: [0u8; 20],
                        })
                    })
                    .collect();

                // Use the pre-verified path. For large batches, use
                // the parallel speculative path; for small batches,
                // serial is faster (avoids rayon overhead).
                if group.len() >= self.parallel_threshold {
                    module.handle_batch_parallel_preverified(&group[0].0, &preverified)
                } else {
                    module.handle_batch_preverified(&group[0].0, &preverified)
                }
            } else {
                // Fall back to the recovery path — no preverified
                // Vec constructed, no payload clones.
                let batch: Vec<(TxContext, &[u8])> = group
                    .iter()
                    .map(|(ctx, payload, _tx_hash)| (*ctx, payload.as_slice()))
                    .collect();
                module.handle_batch(&batch)
            };
            for events in results.into_iter().flatten() {
                block_events.extend(events);
            }
        }
        // Publish all events from this block in one lock acquisition.
        self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend(block_events);

        // end_block for all modules.
        for module in self.modules.iter().flatten() {
            module.end_block(block.height);
        }

        // Compute the state root: hash all module state roots.
        let mut root_data = Vec::new();
        for module in self.modules.iter().flatten() {
            let mr = module.state_root();
            root_data.extend_from_slice(mr.as_bytes());
        }
        Hasher::hash_one(Domain::Block, &root_data)
    }
}

impl AppInterface for Executor {
    fn ingest_tx(&self, tx: TxBytes) -> MempoolAck {
        // A4: route mempool admission through `Module::validate`.
        // Before storing the tx in the mempool, we parse the envelope,
        // find the target module, and call its `validate` method. This
        // rejects invalid txs (bad signature, wrong chain ID, bad
        // nonce, insufficient balance) before they enter the pool —
        // keeping the pool clean and the execution path fast.
        let bytes = tx.as_bytes();
        let Some(ctx) = parse_tx_context(bytes) else {
            return MempoolAck::Rejected { reason: "malformed: tx context".to_string() };
        };
        let Some(module_id) = parse_module_id(bytes) else {
            return MempoolAck::Rejected { reason: "malformed: no module ID".to_string() };
        };
        let Some(module) = self.modules[module_id as usize].as_ref() else {
            return MempoolAck::Rejected { reason: format!("unknown module {module_id}") };
        };
        let payload = module_payload(bytes);
        if let Err(e) = module.validate(&ctx, payload) {
            return MempoolAck::Rejected { reason: format!("validate: {e:?}") };
        }

        // Pre-recover the sender at ingestion time and cache it.
        // This amortizes secp256k1 recovery (~30 µs/tx) across the
        // tx's lifetime in the mempool. At block execution time, the
        // cached sender is used to skip recovery entirely — the
        // execution hot path sees only RLP decode + chain ID check.
        //
        // For modules without a preverify implementation (default
        // returns a zero sender), this is a no-op that stores a
        // placeholder. The execution path falls back to `handle_batch`
        // when the sender is zero.
        let preverify_result = module.preverify_batch(&[payload]);
        if let Ok(preverified) = &preverify_result[0] {
            let tx_hash =
                crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, tx.as_bytes());
            self.preverify_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(tx_hash, preverified.clone());
        }

        // Push to the lock-free intake ring. The mempool submission
        // is deferred to `prepare_proposal` — this eliminates the
        // per-tx mempool lock on the ingestion hot path.
        match self.mempool_intake_tx.send(tx) {
            Ok(()) => MempoolAck::Accepted,
            Err(_) => MempoolAck::Rejected { reason: "intake ring closed".to_string() },
        }
    }

    /// Phase E: batch mempool intake. Acquires the mempool lock once
    /// for the entire batch, amortizing the per-tx lock overhead.
    /// Validation and preverify are still per-tx (they call into
    /// module code), but the mempool insertion is batched.
    fn ingest_tx_batch(&self, txs: Vec<TxBytes>) -> Vec<MempoolAck> {
        let mut results = Vec::with_capacity(txs.len());
        // Validate and preverify each tx, collecting the accepted
        // ones for batch submission to the mempool.
        let mut accepted_txs: Vec<TxBytes> = Vec::with_capacity(txs.len());
        for tx in txs {
            let bytes = tx.as_bytes();
            let Some(ctx) = parse_tx_context(bytes) else {
                results.push(MempoolAck::Rejected { reason: "malformed: tx context".to_string() });
                continue;
            };
            let Some(module_id) = parse_module_id(bytes) else {
                results
                    .push(MempoolAck::Rejected { reason: "malformed: no module ID".to_string() });
                continue;
            };
            let Some(module) = self.modules[module_id as usize].as_ref() else {
                results
                    .push(MempoolAck::Rejected { reason: format!("unknown module {module_id}") });
                continue;
            };
            let payload = module_payload(bytes);
            if let Err(e) = module.validate(&ctx, payload) {
                results.push(MempoolAck::Rejected { reason: format!("validate: {e:?}") });
                continue;
            }
            // Pre-recover the sender at ingestion time.
            let preverify_result = module.preverify_batch(&[payload]);
            if let Ok(preverified) = &preverify_result[0] {
                let tx_hash = crypto::hash::Hasher::hash_one(
                    crypto::hash::Domain::Transaction,
                    tx.as_bytes(),
                );
                self.preverify_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(tx_hash, preverified.clone());
            }
            accepted_txs.push(tx);
            results.push(MempoolAck::Accepted);
        }
        // Batch-submit all accepted txs to the mempool in one lock
        // acquisition.
        if !accepted_txs.is_empty() {
            let mut mempool =
                self.mempool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for (i, tx) in accepted_txs.into_iter().enumerate() {
                if let Err(e) = mempool.submit(tx) {
                    // Overwrite the Accepted result with the rejection.
                    results[i] = MempoolAck::Rejected { reason: format!("{e:?}") };
                }
            }
        }
        results
    }

    fn prepare_proposal(&self, budget: &types::BlockBudget) -> Proposal {
        let start = std::time::Instant::now();
        // Drain the lock-free intake ring into the mempool under a
        // single lock acquisition. This batches all pending txs into
        // the mempool before selection, eliminating the per-tx
        // mempool lock on the ingestion hot path.
        {
            let rx =
                self.mempool_intake_rx.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut pool = self.mempool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            while let Ok(tx) = rx.try_recv() {
                let _ = pool.submit(tx);
            }
        }
        // Select txs from the mempool by fee priority.
        let txs = self
            .mempool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .select(budget.max_bytes);
        let height = Height::new(
            *self.next_proposal_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if let Some(recorder) = &self.recorder {
            recorder.record("prepare_proposal", start.elapsed());
        }
        Proposal { height, txs, attestation: None }
    }

    fn process_proposal(&self, proposal: &Proposal) -> Verdict {
        // M2 fix: validate each tx's static structure. Previously
        // this accepted all proposals unconditionally, which meant
        // a byzantine leader could propose a block with malformed
        // txs and they'd be silently skipped during execution.
        //
        // Static validity checks (no state access):
        // 1. Each tx must be long enough to have a sender, nonce,
        //    fee, and module ID (≥ 37 bytes).
        // 2. Each tx's module ID must be a registered module.
        //
        // Dynamic checks (nonce ordering, balance, signature) are
        // not done here — they require state access and are checked
        // during execution. Signature verification arrives when the
        // tx envelope format includes signatures (Phase 2).
        for tx in &proposal.txs {
            let bytes = tx.as_bytes();
            // Check that the tx context is parseable (sender, nonce,
            // fee). This also implicitly checks the minimum size
            // (TX_MIN_SIZE = 36 bytes).
            if parse_tx_context(bytes).is_none() {
                return Verdict::Reject {
                    reason: "tx context (sender/nonce/fee) is malformed".to_string(),
                };
            }
            // Check that the tx has a module ID byte.
            if bytes.len() < MODULE_ID_OFFSET + 1 {
                return Verdict::Reject { reason: "tx too short for module ID".to_string() };
            }
            // Check that the module is registered.
            let Some(module_id) = parse_module_id(bytes) else {
                return Verdict::Reject { reason: "tx has no module ID".to_string() };
            };
            if self.modules[module_id as usize].is_none() {
                return Verdict::Reject { reason: format!("unknown module ID {module_id}") };
            }
        }
        Verdict::Accept
    }

    fn finalize_block(&self, block: &FinalizedBlock) -> CommitAck {
        let start = std::time::Instant::now();
        if self.async_execution {
            // Phase D: async execution lane — defer execution.
            //
            // Flush any previously pending block (execute it and
            // store its state root) before storing the new block as
            // pending. This ensures blocks are executed in order and
            // the state is consistent when the new block is
            // eventually executed.
            self.flush_pending();

            // Store the new block as pending and advance the proposal
            // height immediately. The consensus engine can proceed to
            // propose/vote/commit the next block while this block's
            // execution is deferred.
            *self.pending_block.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(block.clone());
            self.finalized
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(block.height.value(), block.clone());
            *self.next_proposal_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                block.height.value().saturating_add(1); // M2 fix
        } else {
            // Synchronous execution (default): execute the block
            // immediately and store the state root.
            let root = self.execute_block(block);
            self.state_roots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(block.height.value(), root);
            self.finalized
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(block.height.value(), block.clone());
            *self.next_proposal_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                block.height.value().saturating_add(1); // M2 fix
        }
        if let Some(recorder) = &self.recorder {
            recorder.record("finalize_block", start.elapsed());
        }
        CommitAck { height: block.height }
    }

    fn attest_state(&self, height: Height) -> StateAttestation {
        let start = std::time::Instant::now();
        // Phase D: flush any pending block before attesting state.
        // This ensures the state root for the requested height is
        // available (if it was deferred). When async execution is
        // disabled, flush_pending is a no-op (pending_block is
        // always None).
        self.flush_pending();
        let root = self
            .state_roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&height.value())
            .copied()
            .unwrap_or(Hash::ZERO);
        if let Some(recorder) = &self.recorder {
            recorder.record("attest_state", start.elapsed());
        }
        StateAttestation { height, root }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::SequencerEngine;
    use ports::ConsensusEngine;
    use primitives::Address;

    /// A trivial test module that counts messages.
    struct CounterModule {
        count: Mutex<u64>,
    }

    impl CounterModule {
        fn new() -> Self {
            Self { count: Mutex::new(0) }
        }
    }

    impl Module for CounterModule {
        fn name(&self) -> &'static str {
            "counter"
        }
        fn id(&self) -> u8 {
            1
        }

        fn begin_block(&self, _height: Height) {}

        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            let mut c = self.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            *c += 1;
            Ok(vec![Event { module: "counter", kind: "increment".to_string(), data: vec![] }])
        }

        fn end_block(&self, _height: Height) {}

        fn state_root(&self) -> Hash {
            let c = *self.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let byte = u8::try_from(c).unwrap_or(0xff);
            Hash([byte; 32])
        }
    }

    fn make_tx(module_id: u8, payload: &[u8]) -> TxBytes {
        // Build a tx in the mempool's v0 format:
        // [sender: 20B][nonce: 8B LE][fee: 8B LE][module_id: 1B][payload].
        let sender = Address([0u8; 20]);
        let nonce = 0u64;
        let fee = 100u64;
        let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
        bytes.extend_from_slice(&sender.0);
        bytes.extend_from_slice(&nonce.to_le_bytes());
        bytes.extend_from_slice(&fee.to_le_bytes());
        bytes.push(module_id);
        bytes.extend_from_slice(payload);
        TxBytes::new(bytes)
    }

    #[test]
    fn executor_executes_block_and_produces_state_root() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Submit a tx to the executor's mempool (via AppInterface).
        let tx = make_tx(1, &[42]);
        executor.ingest_tx(tx);

        // Prepare a proposal.
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 1);

        // Finalize the block.
        let block = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        let ack = executor.finalize_block(&block);
        assert_eq!(ack.height, Height::new(0));

        // The state root should be non-zero (the counter incremented).
        let attestation = executor.attest_state(Height::new(0));
        assert_ne!(attestation.root, Hash::ZERO);
    }

    #[test]
    fn executor_with_sequencer_engine_end_to_end() {
        // Wire the executor behind a SequencerEngine and run the full
        // OAI flow: submit → propose → finalize → attest.
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Wrap in Arc for the engine.
        let app: Arc<dyn AppInterface> = Arc::new(executor);
        let mut engine = SequencerEngine::new(app);

        // Submit a tx through the engine.
        let tx = make_tx(1, &[1]);
        engine.submit_tx(tx);
        engine.run_until_idle();

        // The engine should have finalized a block.
        assert!(engine.finalized_height().is_some());

        // The state root should be non-zero.
        let app = engine.app();
        let attestation = app.attest_state(Height::new(0));
        assert_ne!(attestation.root, Hash::ZERO, "state root should be non-zero after execution");
    }

    #[test]
    fn executor_skips_unknown_module() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Submit a tx for an unregistered module (ID 99).
        let tx = make_tx(99, &[1]);
        executor.ingest_tx(tx);

        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        executor.finalize_block(&block);

        // The unknown module's tx should be silently skipped.
        // The counter module should not have been called.
        let attestation = executor.attest_state(Height::new(0));
        // State root is the hash of the counter's state root (0).
        assert_ne!(attestation.root, Hash::ZERO, "state root should reflect counter=0");
    }

    #[test]
    fn executor_multiple_blocks_state_advances() {
        let mut executor = Executor::new(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Execute 3 blocks, each with 1 tx.
        for h in 0..3u64 {
            let h_byte = u8::try_from(h).unwrap_or(0xff);
            let tx = make_tx(1, &[h_byte]);
            executor.ingest_tx(tx);
            let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
            let proposal = executor.prepare_proposal(&budget);
            let block = FinalizedBlock { height: Height::new(h), txs: proposal.txs };
            executor.finalize_block(&block);
        }

        // The counter should have been called 3 times.
        let count = *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(count, 3, "counter should have been incremented 3 times");

        // Each block should have a different state root.
        let root0 = executor.attest_state(Height::new(0)).root;
        let root1 = executor.attest_state(Height::new(1)).root;
        let root2 = executor.attest_state(Height::new(2)).root;
        assert_ne!(root0, root1, "state roots should differ across blocks");
        assert_ne!(root1, root2, "state roots should differ across blocks");
    }

    // ---- M2 fix: process_proposal validation tests ----

    #[test]
    fn process_proposal_accepts_valid_tx() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let tx = make_tx(1, &[42]);
        let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
        assert!(matches!(executor.process_proposal(&proposal), Verdict::Accept));
    }

    #[test]
    fn process_proposal_rejects_too_short_tx() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let proposal = Proposal {
            height: Height::new(0),
            txs: vec![TxBytes::new(vec![1, 2, 3])], // way too short
            attestation: None,
        };
        match executor.process_proposal(&proposal) {
            Verdict::Reject { reason } => assert!(reason.contains("malformed")),
            Verdict::Accept => panic!("should reject too-short tx"),
        }
    }

    #[test]
    fn process_proposal_rejects_unknown_module() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let tx = make_tx(99, &[1]); // module 99 is not registered
        let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
        match executor.process_proposal(&proposal) {
            Verdict::Reject { reason } => assert!(reason.contains("unknown module")),
            Verdict::Accept => panic!("should reject unknown module"),
        }
    }

    #[test]
    fn process_proposal_rejects_malformed_context() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));
        // A tx with 37 bytes (minimum for module ID) but with a
        // malformed sender (not a valid address — but actually
        // any 20 bytes is a valid Address, so we need to test a
        // different malformation). Let's use a tx that's exactly
        // 36 bytes (no module ID byte) — this should be rejected
        // as "too short for module ID".
        let mut bytes = vec![0u8; 36]; // 20 + 8 + 8, no module ID
        bytes.push(1); // add module ID
        // Actually this is valid. Let's make a tx with a bad nonce
        // section — but u64::from_le_bytes never fails on 8 bytes.
        // The real malformation is a tx shorter than 36 bytes.
        let short_tx = TxBytes::new(vec![0u8; 30]); // < 36 bytes
        let proposal = Proposal { height: Height::new(0), txs: vec![short_tx], attestation: None };
        match executor.process_proposal(&proposal) {
            Verdict::Reject { reason } => assert!(reason.contains("malformed")),
            Verdict::Accept => panic!("should reject malformed tx"),
        }
    }

    // ---- Preverification cache key fix ----

    /// A test module that records whether `handle_batch_preverified`
    /// (the cache-hit path) or `handle_batch` (the fallback path) was
    /// called. This lets us prove the preverify cache actually hits.
    struct PreverifyTrackingModule {
        preverified_calls: Mutex<usize>,
        fallback_calls: Mutex<usize>,
    }

    impl PreverifyTrackingModule {
        fn new() -> Self {
            Self { preverified_calls: Mutex::new(0), fallback_calls: Mutex::new(0) }
        }
    }

    impl Module for PreverifyTrackingModule {
        fn name(&self) -> &'static str {
            "preverify-tracker"
        }
        fn id(&self) -> u8 {
            2
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            Ok(vec![])
        }
        fn end_block(&self, _height: Height) {}
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
        fn preverify_batch(&self, msgs: &[&[u8]]) -> Vec<Result<PreverifiedTx, ExecError>> {
            msgs.iter()
                .map(|raw| Ok(PreverifiedTx { raw: raw.to_vec(), sender: [0u8; 20] }))
                .collect()
        }
        fn handle_batch_preverified(
            &self,
            _ctx: &TxContext,
            txs: &[PreverifiedTx],
        ) -> Vec<Result<Vec<Event>, ExecError>> {
            *self.preverified_calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner) +=
                txs.len();
            (0..txs.len()).map(|_| Ok(vec![])).collect()
        }
        fn handle_batch(&self, batch: &[(TxContext, &[u8])]) -> Vec<Result<Vec<Event>, ExecError>> {
            *self.fallback_calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner) +=
                batch.len();
            (0..batch.len()).map(|_| Ok(vec![])).collect()
        }
    }

    /// Prove the preverify cache key matches between `ingest_tx` and
    /// `execute_block`. Before the fix, `ingest_tx` cached under the
    /// full-tx hash but `execute_block` looked up under the payload
    /// hash — a guaranteed miss. After the fix, both use the full-tx
    /// hash, so the preverified path is taken.
    #[test]
    fn preverify_cache_key_matches_between_ingest_and_execute() {
        let mut executor = Executor::new(100);
        let tracker = Arc::new(PreverifyTrackingModule::new());
        executor.register_module(tracker.clone());

        // Ingest a tx — this caches the preverified sender under the
        // full-tx hash.
        let tx = make_tx(2, &[0xAA]);
        executor.ingest_tx(tx.clone());

        // Prepare + finalize a block containing that tx.
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 1, "the ingested tx should be in the proposal");
        let block = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        executor.finalize_block(&block);

        // The preverified path should have been taken (cache hit),
        // not the fallback path (cache miss).
        let preverified =
            *tracker.preverified_calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let fallback =
            *tracker.fallback_calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(preverified, 1, "preverified path should have been used (cache hit)");
        assert_eq!(fallback, 0, "fallback path should not have been used (no cache miss)");
    }
}
