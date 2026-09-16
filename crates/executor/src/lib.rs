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
use primitives::{Address, Hash, Height};
use types::{CommitAck, FinalizedBlock, MempoolAck, Proposal, StateAttestation, TxBytes, Verdict};

use crypto::hash::{Domain, Hasher};

/// Maximum finalized-block / state-root history retained in memory.
///
/// These maps exist for recent-height queries (`finalized_block`,
/// `state_root_at`); full history is the journal's job. 4096
/// heights ≈ 7 minutes at a 100 ms block cadence — bounded so a
/// long-lived node doesn't grow memory without limit.
const MAX_RETAINED_HISTORY: usize = 4096;

/// Insert-then-prune for height-keyed history maps: keeps the
/// newest [`MAX_RETAINED_HISTORY`] entries by dropping the oldest.
trait InsertRetained<K: Ord, V> {
    /// Insert `v` at `k`, then evict oldest entries until at most
    /// [`MAX_RETAINED_HISTORY`] remain.
    fn insert_retained(&mut self, k: K, v: V);
}

impl<K: Ord, V> InsertRetained<K, V> for BTreeMap<K, V> {
    fn insert_retained(&mut self, k: K, v: V) {
        self.insert(k, v);
        while self.len() > MAX_RETAINED_HISTORY {
            self.pop_first();
        }
    }
}

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
    /// The aggregate state root (hash of all module state roots AND
    /// the executed-nonce root).
    pub state_root: Hash,
    /// Per-module state roots, in registration order.
    pub module_roots: Vec<(String, Hash)>,
    /// Per-module full key-value state, in registration order.
    /// `None` for modules that don't support `export_state`. Empty
    /// for metadata-only snapshots (v0).
    pub module_state: Vec<Option<storage::Snapshot>>,
    /// H4/H5 fix: per-account executed-nonce map, so replay
    /// protection survives restarts/sync. Each entry is
    /// `(address, next_expected_nonce)`. Empty for v0 snapshots
    /// (treated as "all nonces start at 0" on import).
    pub executed_nonces: Vec<(primitives::Address, u64)>,
    /// HIGH fix: hash of the executed-nonce map, binding it into the
    /// authenticated `state_root`. Without this, a crafted snapshot
    /// could zero or corrupt `executed_nonces` (replay protection)
    /// without detection — `executed_nonces` are not part of any
    /// module's state root. The nonce root is computed as
    /// `keccak256(concat(address || nonce_le))` over all entries,
    /// sorted by address for determinism.
    pub nonce_root: Hash,
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
    /// M3 fix: a module's recomputed state root (from the imported
    /// KV data) does not match the snapshot's claimed module root.
    /// This indicates a crafted or corrupted snapshot where the KV
    /// data doesn't match the claimed roots.
    ModuleRootMismatch {
        /// The module's name.
        module: String,
        /// The expected root from the snapshot.
        expected: Hash,
        /// The recomputed root from the imported KV data.
        actual: Hash,
    },
    /// HIGH fix: the snapshot's `nonce_root` does not match the
    /// recomputed hash of the `executed_nonces` field. This catches
    /// a crafted snapshot that tampers with replay-protection
    /// nonces without updating the authenticated root.
    NonceRootMismatch {
        /// The expected root from the snapshot.
        expected: Hash,
        /// The recomputed root from the `executed_nonces`.
        actual: Hash,
    },
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
            Self::ModuleRootMismatch { module, expected, actual } => {
                write!(f, "module {module} root mismatch: expected {expected}, got {actual}")
            }
            Self::NonceRootMismatch { expected, actual } => {
                write!(f, "nonce root mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for SnapshotImportError {}

// ---------------------------------------------------------------------------
// Codec impls — binary serialization for snapshot save/load and RPC export.
// ---------------------------------------------------------------------------

impl codec::Encode for ExecutorSnapshot {
    fn encode(&self, buf: &mut Vec<u8>) {
        codec::write::u64(buf, self.height);
        self.state_root.encode(buf);
        codec::write::u32(buf, u32::try_from(self.module_roots.len()).unwrap_or(u32::MAX));
        for (name, root) in &self.module_roots {
            codec::write::bytes(buf, name.as_bytes());
            root.encode(buf);
        }
        codec::write::u32(buf, u32::try_from(self.module_state.len()).unwrap_or(u32::MAX));
        for state in &self.module_state {
            codec::write::bool(buf, state.is_some());
            if let Some(snap) = state {
                snap.encode(buf);
            }
        }
        codec::write::u32(buf, u32::try_from(self.executed_nonces.len()).unwrap_or(u32::MAX));
        for (addr, nonce) in &self.executed_nonces {
            addr.encode(buf);
            codec::write::u64(buf, *nonce);
        }
        self.nonce_root.encode(buf);
    }
}

impl<'a> codec::Decode<'a> for ExecutorSnapshot {
    fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        let height = reader.read_u64()?;
        let state_root = Hash::decode(reader)?;
        let roots_count = reader.read_u32()?;
        let mut module_roots = Vec::with_capacity(roots_count as usize);
        for _ in 0..roots_count {
            let name_bytes = reader.read_bytes()?;
            let name = String::from_utf8(name_bytes.to_vec())
                .map_err(|_| codec::DecodeError::InvalidUtf8)?;
            let root = Hash::decode(reader)?;
            module_roots.push((name, root));
        }
        let state_count = reader.read_u32()?;
        let mut module_state = Vec::with_capacity(state_count as usize);
        for _ in 0..state_count {
            let present = reader.read_bool()?;
            if present {
                module_state.push(Some(storage::Snapshot::decode(reader)?));
            } else {
                module_state.push(None);
            }
        }
        let nonces_count = reader.read_u32()?;
        let mut executed_nonces = Vec::with_capacity(nonces_count as usize);
        for _ in 0..nonces_count {
            let addr = primitives::Address::decode(reader)?;
            let nonce = reader.read_u64()?;
            executed_nonces.push((addr, nonce));
        }
        let nonce_root = Hash::decode(reader)?;
        Ok(Self { height, state_root, module_roots, module_state, executed_nonces, nonce_root })
    }
}

/// HIGH fix: compute the authenticated root of the executed-nonce
/// map. This binds `executed_nonces` into the snapshot's
/// `state_root` so a crafted snapshot cannot tamper with
/// replay-protection nonces without detection.
///
/// The root is `keccak256(concat(address || nonce_le))` over all
/// entries sorted by address. Sorting ensures determinism regardless
/// of `HashMap` iteration order.
fn compute_nonce_root(nonces: &[(primitives::Address, u64)]) -> Hash {
    let mut sorted = nonces.to_vec();
    sorted.sort_by_key(|a| a.0);
    let mut data = Vec::with_capacity(sorted.len() * 28);
    for (addr, nonce) in &sorted {
        data.extend_from_slice(&addr.0);
        data.extend_from_slice(&nonce.to_le_bytes());
    }
    Hasher::hash_one(Domain::Block, &data)
}

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
pub struct PreverifiedTx<'a> {
    /// The raw module payload bytes (e.g. RLP-encoded signed EVM tx),
    /// borrowed from the caller's transaction buffer — the batch hot
    /// path must not clone per-tx.
    pub raw: &'a [u8],
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
    fn preverify_batch<'a>(
        &self,
        msgs: &'a [&'a [u8]],
    ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
        msgs.iter().map(|raw| Ok(PreverifiedTx { raw, sender: [0u8; 20] })).collect()
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
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        let batch: Vec<(TxContext, &[u8])> = txs.iter().map(|pv| (*ctx, pv.raw)).collect();
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
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        self.handle_batch_preverified(ctx, txs)
    }

    /// Called at the end of each block, after all txs.
    fn end_block(&self, height: Height);

    /// Charge the transaction fee from the sender's account.
    ///
    /// This is called by the executor *before* `handle` to enforce
    /// that every transaction pays its declared fee. A tx whose
    /// sender has insufficient balance to cover the fee is rejected
    /// — it is not executed, and its nonce is not advanced.
    ///
    /// The default implementation is a no-op (no fee charged).
    /// Modules that manage account balances (e.g. the bank module)
    /// override this to debit the sender's balance.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] if the sender has
    /// insufficient balance to cover the fee.
    fn charge_fee(&self, _ctx: &TxContext) -> Result<(), ExecError> {
        Ok(())
    }

    /// Whether this module pays for its own execution internally,
    /// exempting it from the envelope fee charged by the configured
    /// fee module. `false` (default): the executor charges `ctx.fee`
    /// through the fee module before execution. `true`: the module
    /// meters and collects its own fee — the EVM is the canonical
    /// case (revm charges `gas_used × effective_gas_price` from the
    /// sender's account inside execution, bounded below by the block
    /// base fee). Charging the envelope fee on top of that would
    /// double-charge every EVM user.
    fn pays_own_fee(&self) -> bool {
        false
    }

    /// Estimate the gas cost of a message for block gas limit
    /// enforcement.
    ///
    /// The default implementation uses the message byte length as a
    /// proxy for gas cost (1 byte = 1 gas unit). Modules with a more
    /// accurate gas model (e.g. EVM) override this to return the
    /// actual gas estimate.
    ///
    /// This is called by the executor in `process_proposal` to check
    /// that the total block gas does not exceed the block gas limit,
    /// and in `execute_block` to track cumulative gas consumption.
    fn estimate_gas(&self, msg: &[u8]) -> u64 {
        // Default: 1 gas per byte + a base cost of 1000 gas per tx
        // (covers fixed overhead: nonce check, fee deduction, event
        // emission). The base cost prevents a flood of 1-byte txs
        // from fitting in a block with a low gas limit.
        1000 + msg.len() as u64
    }

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

    /// Drain pending validator key changes.
    ///
    /// Called by the consensus layer at epoch boundary to collect
    /// key rotations submitted via `KEY_CHANGE` transactions. Each
    /// entry is `(staking_address, new_bls_key_bytes)` — the staking
    /// module records them; the consensus engine applies them to
    /// the validator set.
    ///
    /// # Default
    ///
    /// Returns empty — most modules don't track key changes. Only
    /// the staking module overrides this.
    fn take_key_changes(&self) -> Vec<(Address, Vec<u8>)> {
        Vec::new()
    }

    /// Take all pending validator additions and removals, clearing
    /// the queues. Called by the consensus engine at the epoch
    /// boundary to apply validator set changes.
    ///
    /// Returns `(adds, removes)` — `adds` is a list of `(address,
    /// bls_public_key, stake)` tuples for new validators; `removes`
    /// is a list of addresses to remove.
    ///
    /// # Default
    ///
    /// Returns empty — most modules don't track validator set
    /// changes. Only the staking module overrides this.
    fn take_validator_changes(&self) -> ValidatorChanges {
        ValidatorChanges::default()
    }
}

/// A pending validator set change: additions and removals to apply
/// at the next epoch rotation.
///
/// `adds` is a list of `(staking_address, bls_public_key, stake)`
/// tuples for new validators. `removes` is a list of staking
/// addresses to remove.
#[derive(Debug, Clone, Default)]
pub struct ValidatorChanges {
    /// Validators to add: `(address, bls_public_key, stake)`.
    pub adds: Vec<(Address, Vec<u8>, u64)>,
    /// Validator addresses to remove.
    pub removes: Vec<Address>,
}

impl ValidatorChanges {
    /// Whether there are no pending changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adds.is_empty() && self.removes.is_empty()
    }
}

/// An event emitted by a module during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The module that emitted this event.
    pub module: &'static str,
    /// The event type (e.g. "transfer", "delegate"). A static
    /// string — every module emits a fixed set of kinds, so a
    /// `String` here allocated once per event for no reason.
    pub kind: &'static str,
    /// The event data (module-specific).
    pub data: Vec<u8>,
}

/// The v0 tx envelope payload format. The full tx is owned by the
/// mempool: `[sender: 20B][nonce: 8B LE][fee: 8B LE][payload]`. The
/// executor routes on the first byte of `payload`:
/// `[module_id: 1B][module_payload: ...]`.
const MODULE_ID_OFFSET: usize = 36; // 20 + 8 + 8

/// A tx grouped by module for batch execution. The payload is a
/// zero-copy slice into the original tx bytes (no per-tx Vec
/// allocation). The hash is the full tx hash (used for preverify
/// cache lookup).
type GroupedTx<'a> = (TxContext, &'a [u8], Hash);

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

/// Default block gas limit: 30 million gas units per block.
///
/// This is comparable to Ethereum's 30M gas limit. Each transaction
/// consumes at least 1000 gas (base cost) plus 1 gas per byte of
/// payload. The limit prevents a byzantine proposer from including
/// unbounded computation in a single block.
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;

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
    /// Finalized blocks, keyed by height. Bounded to the newest
    /// [`MAX_RETAINED_HISTORY`] heights — full history is the
    /// journal's job; this map serves recent-height queries only.
    finalized: Mutex<BTreeMap<u64, FinalizedBlock>>,
    /// State roots per finalized height. Same retention bound.
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
    ///
    /// Only the recovered `sender` is stored — the payload bytes are
    /// re-borrowed from the block's tx at execution time, so no
    /// per-tx `Vec<u8>` is ever cloned into or out of this cache.
    preverify_cache: Mutex<HashMap<Hash, [u8; 20]>>,
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
    mempool_intake_tx: std::sync::mpsc::SyncSender<TxBytes>,
    /// The receiver side of the intake ring. Drained by
    /// `prepare_proposal` to flush buffered txs into the mempool.
    mempool_intake_rx: std::sync::Mutex<std::sync::mpsc::Receiver<TxBytes>>,
    /// H4/H5 fix: per-account executed-nonce map. Tracks the next
    /// expected nonce for each sender. Updated after `execute_block`
    /// completes for each tx that was executed.
    ///
    /// This is the replay-protection gate: `ingest_tx` rejects any tx
    /// whose `ctx.nonce < executed_nonce[sender]` (already executed),
    /// and `process_proposal` / `execute_block` enforce strict
    /// per-sender nonce ordering (H5: no gaps, no reorderings).
    ///
    /// The map is restored from snapshots via `import_snapshot` so
    /// replay protection survives restarts.
    executed_nonce: Mutex<HashMap<primitives::Address, u64>>,
    /// Block gas limit. The total gas of all txs in a block must not
    /// exceed this limit. Enforced in `process_proposal` (rejects
    /// blocks that exceed the limit) and `execute_block` (skips
    /// txs that would exceed the cumulative limit).
    ///
    /// Default: 30 million gas per block (comparable to Ethereum's
    /// 30M gas limit). Configurable via [`Executor::with_gas_limit`].
    block_gas_limit: u64,
    /// The module that collects transaction fees (the bank). When
    /// set, every non-self-funded module's txs are charged `ctx.fee`
    /// through this module before execution — previously the charge
    /// was dispatched to the *target* module, so any module that
    /// didn't implement `charge_fee` executed for free.
    ///
    /// `None` = no fee collection (tests and dev-mode executors).
    fee_module: Option<u8>,
    /// Minimum acceptable `ctx.fee` per transaction. Txs declaring a
    /// fee below this floor are skipped before the fee charge —
    /// the envelope's fee field is sender-controlled, so without a
    /// floor every tx could declare 0 and execute for free.
    ///
    /// `0` = no floor (the fee module's own rules apply — e.g.
    /// zero-fee txs are free).
    min_fee: u64,
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
        let (intake_tx, intake_rx) = std::sync::mpsc::sync_channel(10_000);
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
            executed_nonce: Mutex::new(HashMap::new()),
            block_gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
            fee_module: None,
            min_fee: 0,
        }
    }

    /// Set the block gas limit.
    ///
    /// The total gas of all txs in a block must not exceed this
    /// limit. Each tx consumes at least 1000 gas (base cost) plus
    /// 1 gas per byte of payload.
    #[must_use]
    pub fn with_gas_limit(mut self, limit: u64) -> Self {
        self.block_gas_limit = limit;
        self
    }

    /// Designate a module as the fee collector (the bank).
    ///
    /// Once set, every tx routed to a non-self-funded module is
    /// charged `ctx.fee` through this module before execution —
    /// the charge is dispatched to the collector, not the target
    /// module, so modules that never implemented `charge_fee` no
    /// longer execute for free.
    pub fn set_fee_module(&mut self, module_id: u8) {
        self.fee_module = Some(module_id);
    }

    /// Set the minimum acceptable `ctx.fee` per transaction.
    ///
    /// The envelope's fee field is sender-declared; without a floor
    /// every tx could declare 0 and execute for free. Txs below the
    /// floor are skipped before the fee charge (and before the nonce
    /// advances). `0` (default) = no floor.
    #[must_use]
    pub fn with_min_fee(mut self, min_fee: u64) -> Self {
        self.min_fee = min_fee;
        self
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

    /// Drain pending validator key changes from all modules.
    ///
    /// Called by the consensus layer at epoch boundary. Iterates all
    /// registered modules and collects their pending key changes —
    /// only the staking module produces non-empty results.
    ///
    /// Returns `Vec<(staking_address, new_bls_key_bytes)>`. The
    /// caller passes these to `OxideBft::apply_key_changes` which
    /// builds the updated `ValidatorSet` and schedules an epoch
    /// rotation.
    #[must_use]
    pub fn take_pending_key_changes(&self) -> Vec<(Address, Vec<u8>)> {
        self.modules.iter().flatten().flat_map(|m| m.take_key_changes()).collect()
    }

    /// Take all pending validator additions and removals across all
    /// modules, clearing the queues. Called by the consensus engine
    /// at the epoch boundary.
    ///
    /// Returns a [`ValidatorChanges`] — `adds` is a list of `(address,
    /// bls_public_key, stake)` tuples for new validators; `removes`
    /// is a list of addresses to remove.
    pub fn take_pending_validator_changes(&self) -> ValidatorChanges {
        let mut changes = ValidatorChanges::default();
        for m in self.modules.iter().flatten() {
            let c = m.take_validator_changes();
            changes.adds.extend(c.adds);
            changes.removes.extend(c.removes);
        }
        changes
    }

    /// Snapshot the mempool for `txpool_*` RPC introspection.
    ///
    /// Returns `(sender, nonce, tx_bytes, is_pending)` for every
    /// pooled transaction — see [`Mempool::txpool_snapshot`] for the
    /// pending/queued split rule. This is a cold-path read used by
    /// the JSON-RPC layer; it takes the mempool lock and clones the
    /// tx bytes, so it must never appear on the block path.
    #[must_use]
    pub fn txpool_snapshot(&self) -> Vec<(Address, u64, TxBytes, bool)> {
        self.mempool.lock().unwrap_or_else(std::sync::PoisonError::into_inner).txpool_snapshot()
    }

    /// Save executed nonces to a storage backend (C10 fix).
    ///
    /// Persists the per-sender `executed_nonce` map to the storage
    /// backend using a reserved key prefix. Call this on shutdown
    /// or after each block commit to ensure nonces survive restart.
    /// Without this, a restart resets all executed nonces to zero,
    /// allowing replay of already-executed native transactions.
    pub fn save_executed_nonces(&self, backend: &mut (dyn storage::StorageBackend + Send)) {
        /// Key prefix: `exec_nonce` padded to 32 bytes. Each entry
        /// is keyed by `prefix || addr` and valued by the nonce as
        /// 8-byte LE.
        const PREFIX: &[u8] = b"exec_nonce";
        let nonces = self.executed_nonce.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut ops: Vec<storage::Op> = Vec::with_capacity(nonces.len());
        for (addr, nonce) in nonces.iter() {
            let mut key_bytes = [0u8; 32];
            key_bytes[..PREFIX.len()].copy_from_slice(PREFIX);
            key_bytes[PREFIX.len()..PREFIX.len() + 20].copy_from_slice(&addr.0);
            ops.push(storage::Op::Set {
                key: primitives::Hash(key_bytes),
                value: nonce.to_le_bytes().to_vec(),
            });
        }
        backend.apply_batch(&ops);
    }

    /// Load executed nonces from a storage backend (C10 fix).
    ///
    /// Restores the per-sender `executed_nonce` map from the storage
    /// backend. Call this on startup before processing any
    /// transactions.
    pub fn load_executed_nonces(&self, backend: &(dyn storage::StorageBackend + Send)) {
        const PREFIX: &[u8] = b"exec_nonce";
        let entries = backend.range(PREFIX);
        let mut nonces =
            self.executed_nonce.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (key, value) in entries {
            let addr_bytes = &key.0[PREFIX.len()..PREFIX.len() + 20];
            let mut addr_arr = [0u8; 20];
            addr_arr.copy_from_slice(addr_bytes);
            let addr = primitives::Address(addr_arr);
            if value.len() >= 8 {
                let nonce = u64::from_le_bytes(value[..8].try_into().unwrap_or([0u8; 8]));
                nonces.insert(addr, nonce);
            }
        }
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
        let module_roots: Vec<(String, Hash)> =
            self.modules.iter().flatten().map(|m| (m.name().to_string(), m.state_root())).collect();
        // Export full KV state for each module that supports it.
        let module_state: Vec<Option<storage::Snapshot>> =
            self.modules.iter().flatten().map(|m| m.export_state()).collect();
        // Debug: verify the state root matches the recomputed aggregate.
        // This is a sanity check for the snapshot's internal consistency.
        let mut root_data = Vec::new();
        for (_, root) in &module_roots {
            root_data.extend_from_slice(root.as_bytes());
        }
        // Recompute the state root from the module roots and the
        // nonce root. We always recompute (rather than using the
        // stored root) because the stored root may be stale if the
        // block hasn't been executed yet (async execution), and
        // the HIGH fix binds the nonce root into the state root.
        let _ = state_root; // stored root may be stale; we recompute below
        let executed_nonces: Vec<(primitives::Address, u64)> = self
            .executed_nonce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(addr, nonce)| (*addr, *nonce))
            .collect();
        // HIGH fix: compute the nonce root and bind it into the
        // state root so `executed_nonces` are authenticated.
        let nonce_root = compute_nonce_root(&executed_nonces);
        root_data.extend_from_slice(nonce_root.as_bytes());
        let state_root = Hasher::hash_one(Domain::Block, &root_data);
        ExecutorSnapshot {
            height,
            state_root,
            module_roots,
            module_state,
            executed_nonces,
            nonce_root,
        }
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
        // per-module state roots AND the nonce root. This catches
        // corrupted or tampered snapshots without requiring the local
        // modules to have the same state (the snapshot is from a
        // peer, not local).
        let mut root_data = Vec::new();
        for (_, root) in &snapshot.module_roots {
            root_data.extend_from_slice(root.as_bytes());
        }
        // HIGH fix: bind the nonce root into the state root so
        // `executed_nonces` are authenticated. Without this, a
        // crafted snapshot could zero or corrupt replay-protection
        // nonces without detection.
        let recomputed_nonce_root = compute_nonce_root(&snapshot.executed_nonces);
        if recomputed_nonce_root != snapshot.nonce_root {
            return Err(SnapshotImportError::NonceRootMismatch {
                expected: snapshot.nonce_root,
                actual: recomputed_nonce_root,
            });
        }
        root_data.extend_from_slice(recomputed_nonce_root.as_bytes());
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
        //
        // M3 fix: after importing KV state, recompute each module's
        // state root from the imported data and verify it matches
        // the snapshot's claimed module root. Without this, a
        // crafted snapshot with arbitrary KV + matching aggregate
        // root is accepted — the KV data doesn't actually produce
        // the claimed per-module roots.
        if !snapshot.module_state.is_empty() {
            for (module, state) in self.modules.iter().flatten().zip(&snapshot.module_state) {
                if let Some(state) = state {
                    module
                        .import_state(state)
                        .map_err(|_| SnapshotImportError::StateImportFailed)?;
                }
            }

            // M3: recompute each module's state root from the
            // imported KV data and verify it matches the snapshot's
            // claimed root. This catches a crafted snapshot where
            // the KV data doesn't match the claimed roots.
            //
            // Only verify modules that actually have KV state in
            // the snapshot (`module_state[i].is_some()`). Modules
            // without KV state (in-memory or no export support)
            // cannot be verified from KV — we trust their claimed
            // root.
            for ((module, state), (name, claimed_root)) in self
                .modules
                .iter()
                .flatten()
                .zip(&snapshot.module_state)
                .zip(&snapshot.module_roots)
            {
                if state.is_some() {
                    let actual_root = module.state_root();
                    if actual_root != *claimed_root {
                        return Err(SnapshotImportError::ModuleRootMismatch {
                            module: name.clone(),
                            expected: *claimed_root,
                            actual: actual_root,
                        });
                    }
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

        // H4/H5: restore the executed-nonce map so replay protection
        // survives restarts and state sync. Without this, a node
        // that restarts from a snapshot would accept already-executed
        // txs (replay attack).
        *self.executed_nonce.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            snapshot.executed_nonces.iter().copied().collect();

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

        // H5 fix: cross-block nonce continuity. Verify that each
        // sender's first tx in this block continues from the last
        // executed nonce. This closes the replay window across blocks
        // — a tx with a stale nonce from a previous block is rejected
        // here, not just in the mempool.
        //
        // We snapshot the executed_nonce map into a local copy so we
        // can update it as we process txs in this block without
        // holding the lock for the entire block execution.
        let mut local_nonce: HashMap<primitives::Address, u64> = {
            let executed =
                self.executed_nonce.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            executed.clone()
        };

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
        //
        // H5: we also validate per-sender nonce continuity against
        // the executed_nonce map. Txs with stale or out-of-order
        // nonces are skipped (not executed) — this is the defense
        // against a byzantine proposer that bypassed
        // `process_proposal` (e.g. via a direct finalize path).
        let mut groups: BTreeMap<u8, Vec<GroupedTx<'_>>> = BTreeMap::new();
        let mut cumulative_gas: u64 = 0;
        for tx in &block.txs {
            let bytes = tx.as_bytes();
            let Some(ctx) = parse_tx_context(bytes) else {
                continue; // skip malformed txs
            };
            // H5: check nonce continuity. Each tx's nonce must equal
            // the next expected nonce for its sender. Txs that fail
            // this check are skipped — they are not executed, and
            // they do not advance the nonce counter.
            let expected = local_nonce.get(&ctx.sender).copied().unwrap_or(0);
            if ctx.nonce != expected {
                continue; // stale or out-of-order nonce — skip
            }
            let Some(module_id) = parse_module_id(bytes) else {
                continue; // skip malformed txs
            };
            let Some(module) = self.modules[module_id as usize].as_ref() else {
                continue; // unknown module — skip
            };
            // Enforce block gas limit: skip txs that would exceed
            // the cumulative gas limit. This is the execution-time
            // enforcement (the proposal-time check is in
            // `process_proposal`). A byzantine proposer that
            // bypasses `process_proposal` still hits this gate.
            let payload = module_payload(bytes);
            let gas = module.estimate_gas(payload);
            if cumulative_gas.saturating_add(gas) > self.block_gas_limit {
                continue; // block gas limit exceeded — skip remaining txs
            }
            // Fee gate: every tx routed to a non-self-funded module
            // pays `ctx.fee` through the configured fee collector
            // (the bank) — not the target module. Previously the
            // charge was dispatched to `module.charge_fee`, whose
            // default no-op meant any module without an override
            // (exchange, perps, EVM, ...) executed for free.
            //
            // `min_fee` is enforced first: the envelope's fee field
            // is sender-declared, so without a floor every tx could
            // declare 0. Self-funded modules (EVM: gas is the fee)
            // are exempt — charging here would double-charge.
            //
            // The fee is kept even if `handle` later fails —
            // standard chain semantics (work was attempted; the fee
            // pays for the resources consumed, like gas on revert).
            if !module.pays_own_fee() {
                if ctx.fee < self.min_fee {
                    continue; // below the fee floor — skip
                }
                if let Some(fee_module) =
                    self.fee_module.and_then(|id| self.modules[usize::from(id)].as_ref())
                {
                    if fee_module.charge_fee(&ctx).is_err() {
                        continue; // insufficient balance for fee — skip
                    }
                }
            }
            // Advance the local nonce counter for this sender.
            // (Only after fee charge succeeds — a tx that can't pay
            // its fee doesn't get its nonce advanced.)
            local_nonce.insert(ctx.sender, expected + 1);
            cumulative_gas = cumulative_gas.saturating_add(gas);
            // Zero-copy: store a reference to the payload in the
            // original tx bytes, avoiding a per-tx Vec allocation.
            // The payload is only cloned later if the tx is not in
            // the preverify cache (uncached txs).
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
                // All senders are pre-recovered — build borrowed
                // `PreverifiedTx`s straight from the block bytes.
                let preverified: Vec<PreverifiedTx<'_>> = group
                    .iter()
                    .map(|(_ctx, payload, tx_hash)| PreverifiedTx {
                        raw: payload,
                        sender: preverify_cache.remove(tx_hash).unwrap_or([0u8; 20]),
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
                let batch: Vec<(TxContext, &[u8])> =
                    group.iter().map(|(ctx, payload, _tx_hash)| (*ctx, *payload)).collect();
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

        // H4/H5: persist the updated nonce map. `local_nonce` was
        // advanced as each tx passed the continuity check. We write
        // it back in a single lock acquisition so the next block's
        // `execute_block` and the mempool's `ingest_tx` see the
        // updated state.
        *self.executed_nonce.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            local_nonce;

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
        // H4 fix: replay protection. Reject txs whose nonce has
        // already been executed. Without this, a tx removed from the
        // mempool after block selection can be re-submitted and
        // re-executed — a replay attack.
        {
            let executed =
                self.executed_nonce.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let next_expected = executed.get(&ctx.sender).copied().unwrap_or(0);
            if ctx.nonce < next_expected {
                return MempoolAck::Rejected {
                    reason: format!("replay: nonce {} < next expected {next_expected}", ctx.nonce),
                };
            }
        }
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
        // `msgs` must outlive `preverify_result` — the returned
        // `PreverifiedTx` borrows the payload slice.
        let msgs = [payload];
        let preverify_result = module.preverify_batch(&msgs);
        if let Ok(preverified) = &preverify_result[0] {
            let tx_hash =
                crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, tx.as_bytes());
            // Only the sender is cached — the payload is re-borrowed
            // from the block's tx at execution time.
            self.preverify_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(tx_hash, preverified.sender);
        }

        // Push to the bounded intake ring. The mempool submission
        // is deferred to `prepare_proposal` — this eliminates the
        // per-tx mempool lock on the ingestion hot path.
        //
        // We use `try_send` (non-blocking) instead of `send` (blocking)
        // because a blocking send would deadlock if the intake channel
        // is full and no consumer is draining it. This happens when the
        // consensus pipeline stalls (e.g., during view changes) — the
        // intake fills up, `send` blocks waiting for a consumer, but the
        // consumer (the propose phase) can't run because the submission
        // thread holds the test's main loop. `try_send` breaks the
        // deadlock: a full intake returns `Rejected` (backpressure)
        // instead of blocking forever. The caller can retry later.
        match self.mempool_intake_tx.try_send(tx) {
            Ok(()) => MempoolAck::Accepted,
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                MempoolAck::Rejected { reason: "intake ring full".to_string() }
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                MempoolAck::Rejected { reason: "intake ring closed".to_string() }
            }
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
            // H4 fix: replay protection. Reject txs whose nonce has
            // already been executed. This check exists in `ingest_tx`
            // but was missing from the batch path — a replay attack
            // vector. A tx removed from the mempool after block
            // selection could be re-submitted via the batch path and
            // re-executed.
            {
                let executed =
                    self.executed_nonce.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let next_expected = executed.get(&ctx.sender).copied().unwrap_or(0);
                if ctx.nonce < next_expected {
                    results.push(MempoolAck::Rejected {
                        reason: format!(
                            "replay: nonce {} < next expected {next_expected}",
                            ctx.nonce
                        ),
                    });
                    continue;
                }
            }
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
            // Pre-recover the sender at ingestion time. `msgs` must
            // outlive `preverify_result` — the returned
            // `PreverifiedTx` borrows the payload slice.
            let msgs = [payload];
            let preverify_result = module.preverify_batch(&msgs);
            if let Ok(preverified) = &preverify_result[0] {
                let tx_hash = crypto::hash::Hasher::hash_one(
                    crypto::hash::Domain::Transaction,
                    tx.as_bytes(),
                );
                // Only the sender is cached — the payload is
                // re-borrowed from the block's tx at execution time.
                self.preverify_cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(tx_hash, preverified.sender);
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
        let candidates = self
            .mempool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .select(budget.max_bytes);
        // Enforce the block gas limit at proposal time. The binding
        // constraint is `min(budget.max_gas, block_gas_limit)` —
        // `process_proposal` rejects blocks over `block_gas_limit`,
        // and the consensus budget may ask for less. Without this
        // the proposer could build a block the validators reject
        // outright, wasting a round.
        //
        // Txs that would poison the proposal are skipped entirely:
        // an unparseable context, missing module id, or unregistered
        // module makes `process_proposal` reject the WHOLE block —
        // a single malformed mempool entry could otherwise stall
        // the chain by poisoning every proposal.
        let gas_cap = budget.max_gas.min(self.block_gas_limit);
        let mut total_gas: u64 = 0;
        let mut txs = Vec::with_capacity(candidates.len());
        for tx in candidates {
            let bytes = tx.as_bytes();
            let gas = match (parse_tx_context(bytes), parse_module_id(bytes)) {
                (Some(_), Some(module_id)) => self.modules[usize::from(module_id)]
                    .as_ref()
                    .map(|m| m.estimate_gas(module_payload(bytes))),
                _ => None,
            };
            let Some(gas) = gas else {
                continue;
            };
            // Skip (not stop): a tx that doesn't fit leaves room for
            // a smaller later tx.
            if total_gas.saturating_add(gas) > gas_cap {
                continue;
            }
            total_gas += gas;
            txs.push(tx);
        }
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
        // H5 fix: per-sender nonce ordering. A byzantine leader can
        // reorder same-account txs or insert gaps. We now enforce
        // that within a proposal, each sender's nonces are strictly
        // contiguous and increasing (no gaps, no reorderings).
        //
        // Cross-block nonce anchoring is NOT checked here because the
        // pipelined two-chain HotStuff consensus proposes a new block
        // before the previous block's execution completes. The
        // `executed_nonce` map may lag behind the proposal height, so
        // anchoring here would reject valid proposals. Instead, cross-
        // block anchoring is enforced at two other points:
        // 1. `ingest_tx` (mempool admission): rejects txs with
        //    `nonce < executed_nonce[sender]` (replay protection).
        // 2. `execute_block` (execution): skips txs with stale or
        //    out-of-order nonces (silent skip, not block rejection).
        //
        // Dynamic checks (balance, signature) are not done here —
        // they require state access and are checked during execution.
        // Signature verification arrives when the tx envelope format
        // includes signatures (Phase 2).
        let mut last_nonce: HashMap<primitives::Address, u64> = HashMap::new();
        let mut total_gas: u64 = 0;
        for tx in &proposal.txs {
            let bytes = tx.as_bytes();
            // Check that the tx context is parseable (sender, nonce,
            // fee). This also implicitly checks the minimum size
            // (TX_MIN_SIZE = 36 bytes).
            let Some(ctx) = parse_tx_context(bytes) else {
                return Verdict::Reject {
                    reason: "tx context (sender/nonce/fee) is malformed".to_string(),
                };
            };
            // H5: enforce per-sender nonce ordering within the
            // proposal. Each sender's nonces must be strictly
            // contiguous (n, n+1, n+2, ...). A gap or reordering
            // indicates a byzantine proposer.
            // Cross-block anchoring is NOT checked here (see comment
            // above — pipelined consensus means execution may lag).
            match last_nonce.get(&ctx.sender) {
                Some(&prev) if ctx.nonce != prev + 1 => {
                    return Verdict::Reject {
                        reason: format!(
                            "nonce gap/reorder: sender {:?} expected {} got {}",
                            ctx.sender,
                            prev + 1,
                            ctx.nonce
                        ),
                    };
                }
                // Either no previous nonce (first tx from this
                // sender) or the nonce is contiguous (prev + 1) —
                // accepted. Cross-block continuity is enforced in
                // `ingest_tx` (mempool) and `execute_block`.
                _ => {}
            }
            last_nonce.insert(ctx.sender, ctx.nonce);
            // Check that the tx has a module ID byte.
            if bytes.len() < MODULE_ID_OFFSET + 1 {
                return Verdict::Reject { reason: "tx too short for module ID".to_string() };
            }
            // Check that the module is registered.
            let Some(module_id) = parse_module_id(bytes) else {
                return Verdict::Reject { reason: "tx has no module ID".to_string() };
            };
            let Some(module) = self.modules[module_id as usize].as_ref() else {
                return Verdict::Reject { reason: format!("unknown module ID {module_id}") };
            };
            // Enforce block gas limit: sum the gas estimate of each
            // tx and reject the block if the total exceeds the limit.
            // This prevents a byzantine proposer from including
            // unbounded computation in a single block.
            let payload = module_payload(bytes);
            let gas = module.estimate_gas(payload);
            total_gas = total_gas.saturating_add(gas);
            if total_gas > self.block_gas_limit {
                return Verdict::Reject {
                    reason: format!(
                        "block gas limit exceeded: {total_gas} > {}",
                        self.block_gas_limit
                    ),
                };
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
                .insert_retained(block.height.value(), block.clone());
            *self.next_proposal_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                block.height.value().saturating_add(1); // M2 fix
        } else {
            // Synchronous execution (default): execute the block
            // immediately and store the state root.
            let root = self.execute_block(block);
            self.state_roots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert_retained(block.height.value(), root);
            self.finalized
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert_retained(block.height.value(), block.clone());
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
            Ok(vec![Event { module: "counter", kind: "increment", data: vec![] }])
        }

        fn end_block(&self, _height: Height) {}

        fn state_root(&self) -> Hash {
            let c = *self.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let byte = u8::try_from(c).unwrap_or(0xff);
            Hash([byte; 32])
        }
    }

    fn make_tx(module_id: u8, payload: &[u8]) -> TxBytes {
        make_tx_with_nonce(module_id, payload, 0)
    }

    fn make_tx_with_nonce(module_id: u8, payload: &[u8], nonce: u64) -> TxBytes {
        // Build a tx in the mempool's v0 format:
        // [sender: 20B][nonce: 8B LE][fee: 8B LE][module_id: 1B][payload].
        let sender = Address([0u8; 20]);
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

        // Execute 3 blocks, each with 1 tx. Each tx must use an
        // incrementing nonce — the executor now enforces per-account
        // nonce ordering (H4/H5 fix).
        for h in 0..3u64 {
            let h_byte = u8::try_from(h).unwrap_or(0xff);
            let tx = make_tx_with_nonce(1, &[h_byte], h);
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

    /// A minimal fee-collector module: records how much it charged.
    struct FeeCollector {
        charged: Mutex<u64>,
    }

    impl Module for FeeCollector {
        fn id(&self) -> u8 {
            9
        }
        fn name(&self) -> &'static str {
            "feecollector"
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            Ok(vec![])
        }
        fn end_block(&self, _height: Height) {}
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
        fn charge_fee(&self, ctx: &TxContext) -> Result<(), ExecError> {
            *self.charged.lock().unwrap_or_else(std::sync::PoisonError::into_inner) += ctx.fee;
            Ok(())
        }
    }

    /// Build a tx with an explicit fee (defaults differ from
    /// `make_tx`'s fixed 100).
    fn make_tx_with_fee_and_sender(
        module_id: u8,
        payload: &[u8],
        nonce: u64,
        fee: u64,
        sender_byte: u8,
    ) -> TxBytes {
        let sender = Address([sender_byte; 20]);
        let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
        bytes.extend_from_slice(&sender.0);
        bytes.extend_from_slice(&nonce.to_le_bytes());
        bytes.extend_from_slice(&fee.to_le_bytes());
        bytes.push(module_id);
        bytes.extend_from_slice(payload);
        TxBytes::new(bytes)
    }

    fn make_tx_with_fee(module_id: u8, payload: &[u8], nonce: u64, fee: u64) -> TxBytes {
        make_tx_with_fee_and_sender(module_id, payload, nonce, fee, 0)
    }

    /// Regression test: txs routed to a module that never implements
    /// `charge_fee` must still pay — through the configured fee
    /// collector. Before the fix, the charge was dispatched to the
    /// *target* module, whose default no-op meant only bank txs ever
    /// paid a fee.
    #[test]
    fn fee_module_charges_non_bank_txs() {
        let mut executor = Executor::new(100);
        let counter = Arc::new(CounterModule::new());
        let collector = Arc::new(FeeCollector { charged: Mutex::new(0) });
        executor.register_module(counter.clone());
        executor.register_module(collector.clone());
        executor.set_fee_module(9);

        executor.ingest_tx(make_tx_with_fee(1, &[1], 0, 50));
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        executor.finalize_block(&FinalizedBlock { height: Height::new(0), txs: proposal.txs });

        assert_eq!(
            *collector.charged.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            50,
            "the counter tx's fee must be charged through the collector"
        );
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "the tx must still execute after paying"
        );
    }

    /// Regression test: `min_fee` rejects txs whose declared fee is
    /// below the floor — the envelope's fee field is
    /// sender-controlled, so without a floor every tx could declare 0.
    #[test]
    fn min_fee_floor_skips_underpaying_txs() {
        let mut executor = Executor::new(100).with_min_fee(50);
        let counter = Arc::new(CounterModule::new());
        let collector = Arc::new(FeeCollector { charged: Mutex::new(0) });
        executor.register_module(counter.clone());
        executor.register_module(collector.clone());
        executor.set_fee_module(9);

        // fee=10 < min_fee=50 → skipped (never executed, nonce not
        // advanced). fee=100 ≥ 50 → charged and executed. Different
        // senders: a skipped tx doesn't advance its sender's nonce,
        // so a same-sender follow-up would also be nonce-skipped.
        executor.ingest_tx(make_tx_with_fee_and_sender(1, &[1], 0, 10, 7));
        executor.ingest_tx(make_tx_with_fee_and_sender(1, &[1], 0, 100, 8));
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        executor.finalize_block(&FinalizedBlock { height: Height::new(0), txs: proposal.txs });

        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "only the adequately-paid tx executes"
        );
        assert_eq!(
            *collector.charged.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            100,
            "only the 100-fee tx is charged"
        );
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
        fn preverify_batch<'a>(
            &self,
            msgs: &'a [&'a [u8]],
        ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
            msgs.iter().map(|raw| Ok(PreverifiedTx { raw, sender: [0u8; 20] })).collect()
        }
        fn handle_batch_preverified(
            &self,
            _ctx: &TxContext,
            txs: &[PreverifiedTx<'_>],
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

    // ---- H4 fix: mempool replay protection ----

    /// H4: After a tx with nonce N is executed, re-submitting the
    /// same tx (or any tx with nonce < N+1) must be rejected by
    /// `ingest_tx`. Without this, a tx removed from the mempool
    /// after block selection can be re-submitted and re-executed.
    #[test]
    fn h4_ingest_rejects_stale_nonce_after_execution() {
        let mut executor = Executor::new(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Submit and execute nonce 0.
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        executor.ingest_tx(tx0);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        executor.finalize_block(&block);

        // Re-submit nonce 0 — must be rejected (replay).
        let tx0_again = make_tx_with_nonce(1, &[0], 0);
        match executor.ingest_tx(tx0_again) {
            MempoolAck::Rejected { reason } => {
                assert!(reason.contains("replay"), "expected replay rejection, got: {reason}");
            }
            MempoolAck::Accepted => panic!("stale nonce must be rejected (replay)"),
        }

        // Nonce 1 should still be accepted.
        let tx1 = make_tx_with_nonce(1, &[1], 1);
        assert!(matches!(executor.ingest_tx(tx1), MempoolAck::Accepted));
    }

    /// Regression test: `ingest_tx_batch` must reject txs with stale
    /// nonces (replay protection). Before the fix, the batch path
    /// skipped the executed-nonce check that `ingest_tx` enforced,
    /// allowing replayed txs to enter the mempool via the batch path.
    #[test]
    fn h4_ingest_batch_rejects_stale_nonce_after_execution() {
        let mut executor = Executor::new(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Submit and execute nonce 0.
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        executor.ingest_tx(tx0);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        executor.finalize_block(&block);

        // Re-submit nonce 0 via the batch path — must be rejected.
        let tx0_again = make_tx_with_nonce(1, &[0], 0);
        let tx1 = make_tx_with_nonce(1, &[1], 1);
        let results = executor.ingest_tx_batch(vec![tx0_again, tx1]);
        assert_eq!(results.len(), 2);
        match &results[0] {
            MempoolAck::Rejected { reason } => {
                assert!(
                    reason.contains("replay"),
                    "expected replay rejection for stale nonce in batch, got: {reason}"
                );
            }
            MempoolAck::Accepted => panic!("stale nonce must be rejected in batch path (replay)"),
        }
        // Nonce 1 should still be accepted.
        assert!(
            matches!(results[1], MempoolAck::Accepted),
            "valid nonce must be accepted in batch path"
        );
    }

    // ---- H5 fix: process_proposal nonce ordering ----

    /// H5: `process_proposal` must reject a proposal where a
    /// sender's nonces are not strictly contiguous. A byzantine
    /// proposer cannot reorder same-account txs.
    #[test]
    fn h5_process_proposal_rejects_nonce_gap() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Two txs from the same sender: nonce 0 then nonce 2 (gap).
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        let tx2 = make_tx_with_nonce(1, &[2], 2);
        let proposal = Proposal { height: Height::new(0), txs: vec![tx0, tx2], attestation: None };
        match executor.process_proposal(&proposal) {
            Verdict::Reject { reason } => {
                assert!(
                    reason.contains("nonce gap"),
                    "expected nonce gap rejection, got: {reason}"
                );
            }
            Verdict::Accept => panic!("nonce gap must be rejected"),
        }
    }

    /// H5: `process_proposal` must reject a proposal where a
    /// sender's nonces are out of order (e.g. nonce 1 before nonce 0).
    #[test]
    fn h5_process_proposal_rejects_nonce_reorder() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Nonce 1 before nonce 0 — reorder.
        let tx1 = make_tx_with_nonce(1, &[1], 1);
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        let proposal = Proposal { height: Height::new(0), txs: vec![tx1, tx0], attestation: None };
        match executor.process_proposal(&proposal) {
            Verdict::Reject { reason } => {
                assert!(
                    reason.contains("nonce gap"),
                    "expected nonce gap rejection, got: {reason}"
                );
            }
            Verdict::Accept => panic!("nonce reorder must be rejected"),
        }
    }

    /// H5: `process_proposal` must accept a proposal with
    /// contiguous, strictly increasing nonces.
    #[test]
    fn h5_process_proposal_accepts_contiguous_nonces() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        let tx0 = make_tx_with_nonce(1, &[0], 0);
        let tx1 = make_tx_with_nonce(1, &[1], 1);
        let tx2 = make_tx_with_nonce(1, &[2], 2);
        let proposal =
            Proposal { height: Height::new(0), txs: vec![tx0, tx1, tx2], attestation: None };
        assert!(matches!(executor.process_proposal(&proposal), Verdict::Accept));
    }

    /// H5: `execute_block` must skip txs with stale nonces (nonce
    /// already executed). This is the cross-block continuity check.
    #[test]
    fn h5_execute_block_skips_stale_nonce() {
        let mut executor = Executor::new(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Execute nonce 0 in block 0.
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        executor.ingest_tx(tx0);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block0 = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        executor.finalize_block(&block0);
        assert_eq!(*counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 1);

        // Try to execute nonce 0 again in block 1 — must be skipped.
        let tx0_again = make_tx_with_nonce(1, &[0], 0);
        let block1 = FinalizedBlock { height: Height::new(1), txs: vec![tx0_again] };
        executor.finalize_block(&block1);

        // Counter should still be 1 — the stale tx was skipped.
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "stale nonce tx must be skipped during execution"
        );
    }

    /// H5+: `ingest_tx` (mempool admission) must reject txs with
    /// stale nonces (nonce < `executed_nonce`). This is the cross-block
    /// nonce anchoring gate — it prevents replay attacks where a tx
    /// removed from the mempool after block selection is re-submitted.
    /// `process_proposal` does NOT check cross-block anchoring because
    /// the pipelined consensus may propose before the previous block's
    /// execution completes.
    #[test]
    fn h5_ingest_tx_rejects_stale_nonce_after_execution() {
        let mut executor = Executor::new(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Execute nonce 0 in block 0.
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        executor.ingest_tx(tx0);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block0 = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        executor.finalize_block(&block0);
        assert_eq!(*counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 1);

        // Try to ingest nonce 0 again (stale) — must be rejected.
        let tx0_stale = make_tx_with_nonce(1, &[0], 0);
        let ack = executor.ingest_tx(tx0_stale);
        assert!(
            matches!(ack, MempoolAck::Rejected { .. }),
            "stale nonce must be rejected by mempool"
        );

        // Ingest nonce 1 (correct) — must be accepted.
        let tx1 = make_tx_with_nonce(1, &[1], 1);
        let ack = executor.ingest_tx(tx1);
        assert!(matches!(ack, MempoolAck::Accepted), "correct nonce must be accepted by mempool");
    }

    /// H4/H5: snapshot export/import must preserve the executed-nonce
    /// map so replay protection survives restarts.
    #[test]
    fn h4h5_snapshot_preserves_executed_nonce() {
        let mut executor = Executor::new(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Execute nonce 0 and nonce 1.
        for n in 0..2u64 {
            let tx = make_tx_with_nonce(1, &[u8::try_from(n).unwrap_or(0xff)], n);
            executor.ingest_tx(tx);
            let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
            let proposal = executor.prepare_proposal(&budget);
            let block = FinalizedBlock { height: Height::new(n), txs: proposal.txs };
            executor.finalize_block(&block);
        }

        // Export snapshot.
        let snapshot = executor.export_snapshot();
        assert_eq!(snapshot.executed_nonces.len(), 1, "one sender in the nonce map");
        assert_eq!(snapshot.executed_nonces[0].1, 2, "next expected nonce is 2");

        // Import into a fresh executor.
        let mut executor2 = Executor::new(100);
        executor2.register_module(Arc::new(CounterModule::new()));
        executor2.import_snapshot(&snapshot).expect("import must succeed");

        // Re-submitting nonce 0 must be rejected (replay).
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        match executor2.ingest_tx(tx0) {
            MempoolAck::Rejected { reason } => {
                assert!(
                    reason.contains("replay"),
                    "expected replay rejection after snapshot import, got: {reason}"
                );
            }
            MempoolAck::Accepted => panic!("stale nonce must be rejected after snapshot import"),
        }

        // Nonce 2 should be accepted (next expected).
        let tx2 = make_tx_with_nonce(1, &[2], 2);
        assert!(matches!(executor2.ingest_tx(tx2), MempoolAck::Accepted));
    }

    /// Regression test: `process_proposal` must reject a block whose
    /// total gas exceeds the block gas limit. Before the fix, the
    /// `BlockBudget.max_gas` field was ignored — a byzantine proposer
    /// could include unbounded computation in a single block.
    #[test]
    fn process_proposal_rejects_block_exceeding_gas_limit() {
        let mut executor =
            Executor::with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2000);
        executor.register_module(Arc::new(CounterModule::new()));

        // Each tx costs 1000 gas (base) + payload bytes. With a 2000
        // gas limit, we can fit at most 1 tx with a small payload
        // (1000 + N bytes). Two txs would exceed 2000.
        let tx1 = make_tx(1, &[0]);
        let tx2 = make_tx_with_nonce(1, &[1], 1);

        // A proposal with 2 txs (each ~1001 gas) totals ~2002 gas,
        // exceeding the 2000 limit.
        let proposal = Proposal { height: Height::new(0), txs: vec![tx1, tx2], attestation: None };
        let verdict = executor.process_proposal(&proposal);
        match verdict {
            Verdict::Reject { reason } => {
                assert!(
                    reason.contains("gas limit"),
                    "expected gas limit rejection, got: {reason}"
                );
            }
            Verdict::Accept => panic!("block exceeding gas limit must be rejected"),
        }
    }

    /// Regression test: `process_proposal` must accept a block whose
    /// total gas is within the block gas limit.
    #[test]
    fn process_proposal_accepts_block_within_gas_limit() {
        let mut executor =
            Executor::with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(10_000);
        executor.register_module(Arc::new(CounterModule::new()));

        // One tx with a small payload: 1000 + 1 = 1001 gas, well
        // within the 10,000 limit.
        let tx = make_tx(1, &[0]);
        let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
        let verdict = executor.process_proposal(&proposal);
        assert!(matches!(verdict, Verdict::Accept), "block within gas limit must be accepted");
    }

    /// Regression test: `execute_block` must skip txs that would
    /// exceed the cumulative block gas limit. This is the
    /// execution-time enforcement (the proposal-time check is in
    /// `process_proposal`).
    #[test]
    fn execute_block_skips_txs_exceeding_gas_limit() {
        let mut executor =
            Executor::with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2000);
        executor.register_module(Arc::new(CounterModule::new()));

        // Two txs, each costing ~1001 gas. The first fits (cumulative
        // 1001 ≤ 2000), the second would push to 2002 > 2000.
        let tx1 = make_tx(1, &[0]);
        let tx2 = make_tx_with_nonce(1, &[1], 1);
        let block = FinalizedBlock { height: Height::new(0), txs: vec![tx1, tx2] };
        executor.finalize_block(&block);

        // Only the first tx should have been executed (counter = 1).
        // The second tx was skipped due to the gas limit.
        let counter = executor.modules[1].as_ref().unwrap();
        let count = counter.state_root();
        assert_eq!(
            count.0[0], 1,
            "only the first tx should execute (gas limit), got counter = {}",
            count.0[0]
        );
    }

    /// Regression test: `prepare_proposal` must not build a block
    /// the validators reject. Before the fix, proposal selection
    /// used only the byte budget — a proposer could pack enough
    /// gas into `max_bytes` to exceed the block gas limit, and
    /// `process_proposal` would reject the whole proposal.
    #[test]
    fn prepare_proposal_respects_block_gas_limit() {
        let mut executor =
            Executor::with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2500);
        executor.register_module(Arc::new(CounterModule::new()));

        // Submit 4 txs, each ~1001 gas (1000 base + 1 byte). Under
        // a 2500 gas cap at most 2 fit (2×1001 = 2002; 3×1001 = 3003).
        for n in 0..4u64 {
            let tx = make_tx_with_nonce(1, &[u8::try_from(n).unwrap_or(0xff)], n);
            assert!(matches!(executor.ingest_tx(tx), MempoolAck::Accepted));
        }

        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 2, "only two ~1001-gas txs fit under 2500");
        // The built proposal must pass validation.
        assert!(
            matches!(executor.process_proposal(&proposal), Verdict::Accept),
            "a gas-bounded proposal must be accepted"
        );
    }
}
