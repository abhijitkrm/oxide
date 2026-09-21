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
//! native messages to registered modules (staking, exchange, etc.)
//! and EVM transactions.
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

/// Maximum committed-but-unreceived blocks the execution lane
/// buffers — the bound on how far consensus may outrun execution.
///
/// Unit: committed blocks. The worker holds at most one additional
/// in-flight block, so the total execution lag is at most
/// `EXEC_LANE_DEPTH + 1` heights — far inside the default
/// [`MAX_RETAINED_HISTORY`] window, which keeps every unexecuted
/// block reachable by the inline backlog drain. Origin: the audit
/// requires "one block behind" to be *enforced* — an unbounded
/// queue let consensus run arbitrarily ahead while `finalized`
/// pruned to a fixed window, so a dead lane could leave committed
/// heights already evicted and unexecutable. Tradeoff: a deeper
/// queue absorbs commit bursts without stalling `finalize_block`;
/// a shallower one tightens the lag bound and shrinks worst-case
/// queued tx bytes. 64 keeps the stall rare (attestations already
/// wait on execution, so deeper buffering buys nothing) while
/// bounded enough that a stalled lane cannot hide.
const EXEC_LANE_DEPTH: usize = 64;

/// Insert-then-prune for height-keyed history maps: keeps the
/// newest [`MAX_RETAINED_HISTORY`] entries by dropping the oldest.
trait InsertRetained<K: Ord, V> {
    /// Insert `v` at `k`, then evict oldest entries until at most
    /// `max` remain.
    fn insert_retained(&mut self, k: K, v: V, max: usize);
}

impl<K: Ord, V> InsertRetained<K, V> for BTreeMap<K, V> {
    fn insert_retained(&mut self, k: K, v: V, max: usize) {
        self.insert(k, v);
        while self.len() > max {
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
///
/// The current `ExecutorSnapshot` *format* version. v1 is the
/// pre-versioning layout (implicit — decoded snapshots that end at
/// `nonce_root` read as 1); v2 adds `version` + `module_versions`;
/// v3 changes the state-root semantics (C8): module roots now
/// commit each module's complete canonical state — not just its
/// KV store — and the block/snapshot/replay paths share one
/// aggregate definition (`H(module_roots || nonce_root)`). A v2
/// snapshot's roots were computed under the old KV-only scheme and
/// would verify against stale-definition roots, so they must be
/// refused outright.
/// Bumped whenever the snapshot layout or semantics change so an
/// importer can reject bytes written by a newer binary.
pub const SNAPSHOT_FORMAT_VERSION: u32 = 3;

/// A point-in-time snapshot of the executor's state — see the
/// header comment above [`SNAPSHOT_FORMAT_VERSION`] for the full
/// contract (determinism, full vs metadata-only).
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
    /// The snapshot *format* version — bumped whenever this
    /// struct's layout or semantics change, so an importer can
    /// reject bytes written by a newer binary before touching
    /// state. Decoded snapshots that predate versioning read as 1.
    pub version: u32,
    /// Each module's declared [`Module::state_version`] at export
    /// time, in registration order — parallel to `module_roots`.
    /// On import, a module whose stored version is older than its
    /// declared version gets `Module::migrate(from)` after
    /// `import_state`, so an old-binary snapshot is upgraded in
    /// place. Empty for pre-versioning snapshots (treated as "all
    /// current" — v1 state predates the hook entirely).
    pub module_versions: Vec<u32>,
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
    /// The snapshot's format `version` is newer than this binary's
    /// [`SNAPSHOT_FORMAT_VERSION`] — it was written by a newer
    /// binary and cannot be safely interpreted.
    UnsupportedVersion {
        /// The snapshot's claimed format version.
        snapshot: u32,
        /// The highest format this binary supports.
        supported: u32,
    },
    /// A module's `migrate` hook failed while upgrading imported
    /// state from an older `module_versions` entry.
    MigrationFailed {
        /// The module's name.
        module: String,
        /// The schema version the imported state was written at.
        from: u32,
    },
    /// The snapshot's module name at position `i` does not match
    /// the registered module's name — the snapshot was written by a
    /// chain with a different module ordering, or the name list was
    /// forged to slide a foreign blob into a module's slot.
    ModuleNameMismatch {
        /// Position in the module list.
        index: usize,
        /// The name the snapshot claims.
        snapshot: String,
        /// The registered module's name.
        registered: String,
    },
    /// A module that declares committed state (`export_state`
    /// returns `Some`) has no state payload in the snapshot — the
    /// snapshot cannot be a complete image of that module.
    MissingModuleState {
        /// The module's name.
        module: String,
    },
    /// A module that declares itself stateless (`export_state`
    /// returns `None`) has a state payload in the snapshot — bytes
    /// it cannot interpret must not be silently trusted.
    UnexpectedModuleState {
        /// The module's name.
        module: String,
    },
    /// A module's `inspect_state` rejected its staged snapshot —
    /// the bytes are malformed or internally inconsistent. Raised
    /// during the verify phase, before any module state mutates.
    MalformedModuleState {
        /// The module's name.
        module: String,
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
            Self::UnsupportedVersion { snapshot, supported } => {
                write!(f, "snapshot format v{snapshot} exceeds supported v{supported}")
            }
            Self::MigrationFailed { module, from } => {
                write!(f, "module {module} failed migrating state from schema v{from}")
            }
            Self::ModuleNameMismatch { index, snapshot, registered } => {
                write!(
                    f,
                    "module name mismatch at position {index}: snapshot says '{snapshot}', registered is '{registered}'"
                )
            }
            Self::MissingModuleState { module } => {
                write!(f, "snapshot is missing state for stateful module '{module}'")
            }
            Self::UnexpectedModuleState { module } => {
                write!(f, "snapshot carries state for stateless module '{module}'")
            }
            Self::MalformedModuleState { module } => {
                write!(f, "module '{module}' rejected its snapshot state as malformed")
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
        // Version tail (v2): appended last so pre-versioning
        // payloads still decode — an empty tail reads as version 1.
        codec::write::u32(buf, self.version);
        codec::write::u32(buf, u32::try_from(self.module_versions.len()).unwrap_or(u32::MAX));
        for v in &self.module_versions {
            codec::write::u32(buf, *v);
        }
    }
}

/// Minimum wire bytes one element of a length-prefixed decode loop
/// can occupy — used to cap `Vec::with_capacity` against the
/// attacker-controlled count prefix. A count can promise at most
/// `remaining / MIN` elements; reserving beyond that is pure
/// allocation amplification (a crafted `u32::MAX` count would
/// otherwise reserve gigabytes before the first element read fails).
/// The decode still fails honestly on truncation — the cap only
/// prevents the speculative reserve from trusting the claim.
fn bounded_capacity(count: u32, min_elem_wire: usize, remaining: usize) -> usize {
    (count as usize).min(remaining / min_elem_wire.max(1))
}

impl<'a> codec::Decode<'a> for ExecutorSnapshot {
    fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        let height = reader.read_u64()?;
        let state_root = Hash::decode(reader)?;
        let roots_count = reader.read_u32()?;
        // Each entry costs ≥ 33 bytes on the wire: a varint length
        // prefix (≥1) for the name plus a 32-byte root.
        let mut module_roots =
            Vec::with_capacity(bounded_capacity(roots_count, 33, reader.remaining()));
        for _ in 0..roots_count {
            let name_bytes = reader.read_bytes()?;
            let name = String::from_utf8(name_bytes.to_vec())
                .map_err(|_| codec::DecodeError::InvalidUtf8)?;
            let root = Hash::decode(reader)?;
            module_roots.push((name, root));
        }
        let state_count = reader.read_u32()?;
        // Each entry costs ≥ 1 byte: the `present` bool.
        let mut module_state =
            Vec::with_capacity(bounded_capacity(state_count, 1, reader.remaining()));
        for _ in 0..state_count {
            let present = reader.read_bool()?;
            if present {
                module_state.push(Some(storage::Snapshot::decode(reader)?));
            } else {
                module_state.push(None);
            }
        }
        let nonces_count = reader.read_u32()?;
        // Each entry is exactly 28 bytes: 20-byte address + u64 nonce.
        let mut executed_nonces =
            Vec::with_capacity(bounded_capacity(nonces_count, 28, reader.remaining()));
        for _ in 0..nonces_count {
            let addr = primitives::Address::decode(reader)?;
            let nonce = reader.read_u64()?;
            executed_nonces.push((addr, nonce));
        }
        let nonce_root = Hash::decode(reader)?;
        // Tolerant tail: snapshots encoded before versioning end at
        // `nonce_root` — read them as format v1 with no recorded
        // module versions (all treated as current on import).
        let mut version = 1u32;
        let mut module_versions = Vec::new();
        if reader.remaining() > 0 {
            version = reader.read_u32()?;
            let versions_count = reader.read_u32()?;
            // Each version is exactly 4 bytes.
            module_versions.reserve(bounded_capacity(versions_count, 4, reader.remaining()));
            for _ in 0..versions_count {
                module_versions.push(reader.read_u32()?);
            }
        }
        Ok(Self {
            height,
            state_root,
            module_roots,
            module_state,
            executed_nonces,
            nonce_root,
            version,
            module_versions,
        })
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

/// C8: THE canonical aggregate state root — the single definition
/// shared by block execution, snapshot export, snapshot import, and
/// journal replay. It commits every module's canonical root plus
/// the executed-nonce root: replay protection is consensus state
/// (it decides which future txs are admissible), so it must move
/// the root like any other state. Before this, `execute_block`
/// hashed module roots alone while `export_snapshot` appended the
/// nonce root — two different commitments for the same state.
fn canonical_state_root(module_roots: impl IntoIterator<Item = Hash>, nonce_root: Hash) -> Hash {
    let mut data = Vec::new();
    for root in module_roots {
        data.extend_from_slice(root.as_bytes());
    }
    data.extend_from_slice(nonce_root.as_bytes());
    Hasher::hash_one(Domain::Block, &data)
}

/// Transaction context passed to modules during `handle`.
///
/// Carries the sender, nonce, and fee parsed from the tx envelope.
/// This is the C2 fix: before, `handle` received only the message
/// bytes and had no way to know who sent the tx — so a module could
/// only credit the recipient, never debit the sender. Now modules
/// have the sender's identity and can enforce balance
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

    /// Called at the beginning of each block with the canonical
    /// consensus-derived [`BlockContext`] — the timestamp, fee
    /// beneficiary, and block gas limit the engine committed in the
    /// block header and carried onto the [`FinalizedBlock`].
    ///
    /// The default implementation discards the context and forwards
    /// to [`begin_block`](Self::begin_block), preserving the
    /// height-only contract for modules that consume no consensus
    /// context (and for every legacy call site). Modules that need
    /// the real timestamp, proposer beneficiary, or
    /// consensus-enforced gas limit override this method — the
    /// production path (`Executor::execute_block`) always drives
    /// `begin_block_ctx`, so an overriding module observes the
    /// committed values on every finalized block, including journal
    /// replay (the context is encoded on the block).
    ///
    /// An all-zero context field is the documented "no data"
    /// sentinel (clockless engines, hand-built blocks, pre-context
    /// journals): treat it as "keep configured defaults", never as
    /// a real value.
    fn begin_block_ctx(&self, height: Height, ctx: &types::BlockContext) {
        let _ = ctx;
        self.begin_block(height);
    }

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
    /// `ctxs` carries the per-transaction envelope context parsed by
    /// the executor: `ctxs[i]` is the authenticated context (sender,
    /// nonce, fee) for `txs[i]`. Passing one context for the whole
    /// batch was a silent wrong-sender bug — every tx in the group
    /// executed under the first tx's identity.
    ///
    /// The default implementation pairs each context with its
    /// payload and falls back to [`handle_batch`](Self::handle_batch).
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
        ctxs: &[TxContext],
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        debug_assert_eq!(
            ctxs.len(),
            txs.len(),
            "each preverified tx must carry its own envelope context"
        );
        let batch: Vec<(TxContext, &[u8])> =
            txs.iter().zip(ctxs.iter()).map(|(pv, ctx)| (*ctx, pv.raw)).collect();
        self.handle_batch(&batch)
    }

    /// Execute a batch of pre-verified transactions in parallel.
    ///
    /// This is the speculative parallel execution path. Transactions
    /// are grouped by sender to avoid write conflicts, and each
    /// group is executed on a separate rayon thread. Results are
    /// merged in original block order.
    ///
    /// `ctxs` carries the per-transaction envelope context:
    /// `ctxs[i]` belongs to `txs[i]`.
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
        ctxs: &[TxContext],
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        self.handle_batch_preverified(ctxs, txs)
    }

    /// Called at the end of each block, after all txs.
    ///
    /// Returns the module's end-of-block events — appended to the
    /// block's event log after every tx event, so scheduled effects
    /// (liquidation sweeps, epoch work) are as auditable as
    /// transaction effects.
    fn end_block(&self, height: Height) -> Vec<Event>;

    /// Called at the end of each block with the same canonical
    /// [`BlockContext`] `begin_block_ctx` received. The default
    /// forwards to [`end_block`](Self::end_block); modules that seal
    /// block metadata (timestamp, beneficiary, gas limit) or evolve
    /// per-block state from consensus-provided values override this.
    /// Same sentinel rule as `begin_block_ctx`: zero fields mean
    /// "no data", not real values.
    fn end_block_ctx(&self, height: Height, ctx: &types::BlockContext) -> Vec<Event> {
        let _ = ctx;
        self.end_block(height)
    }

    /// Called once per finalized block with the staking addresses of
    /// the validators whose votes formed the committing QC — the
    /// attendance record for that height. Delivered *inside*
    /// `execute_block` (after `end_block`) so journal replay derives
    /// identical attendance effects.
    ///
    /// `signers` is empty when the engine cannot attribute signers
    /// (sequencer mode, mock engine) — modules must treat empty as
    /// "no data", never as "everyone absent".
    ///
    /// The default is a no-op; only modules that track consensus
    /// participation (staking's downtime tracking) override it.
    fn record_block_attendance(&self, _height: Height, _signers: &[Address]) {}

    /// The module's declared state-schema version — bumped by a
    /// release whenever the module's persisted/encoded state layout
    /// changes. Recorded into snapshots (`module_versions`) so an
    /// importer knows what schema produced the bytes it is about to
    /// load, and consulted by `migrate` when restoring older state.
    ///
    /// Modules whose state only rebuilds from journal replay can
    /// leave the default — their "schema" is the tx format, not
    /// stored bytes. Modules with durable backends (EVM's
    /// `StorageBackend`) must bump this on layout changes.
    fn state_version(&self) -> u32 {
        1
    }

    /// Migrate module state written at schema version `from` to the
    /// module's current [`state_version`](Self::state_version).
    /// Called when older-versioned state is loaded — snapshot
    /// imports (per `module_versions`) and durable-backend loads.
    ///
    /// The default is a no-op returning the declared version: most
    /// releases need no state transform. A release that changes
    /// layout overrides this to run the from→to transform and MUST
    /// return the new version on success.
    ///
    /// # Errors
    ///
    /// Returns an error when `from` is newer than the declared
    /// version (state written by a newer binary — cannot safely
    /// downgrade) or the transform itself fails.
    fn migrate(&self, from: u32) -> Result<u32, ExecError> {
        if from > self.state_version() {
            return Err(ExecError::ModuleRejected(format!(
                "state version {from} is newer than module's declared {}",
                self.state_version()
            )));
        }
        Ok(self.state_version())
    }

    /// A scheduled coordinated halt height, if the module's
    /// governance has set one. The executor freezes execution for
    /// heights above it — every node stops at the same height, so
    /// operators can snapshot, swap binaries, and resume with
    /// migrations applied. The earliest non-`None` value across
    /// modules wins. `None` (default) = no halt scheduled.
    fn scheduled_halt_height(&self) -> Option<u64> {
        None
    }

    /// Charge the transaction fee from the sender's account.
    ///
    /// This is called by the executor *before* `handle` to enforce
    /// that every transaction pays its declared fee. A tx whose
    /// sender has insufficient balance to cover the fee is rejected
    /// — it is not executed, and its nonce is not advanced.
    ///
    /// The default implementation is a no-op (no fee charged).
    /// The module that owns the native-token ledger (the EVM
    /// module) overrides this to debit the sender's balance.
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

    /// Whether this module authenticates the transaction sender
    /// inside its own payload, making an envelope signature
    /// redundant.
    ///
    /// `false` (default): the module trusts `ctx.sender`, which is
    /// only as trustworthy as the envelope — for these modules the
    /// executor enforces the EIP-712 envelope signature when
    /// [`Executor::unsigned_tx_policy`] rejects unsigned txs, and
    /// always verifies the signature when one is attached.
    ///
    /// `true`: the module recovers the real sender from a signature
    /// inside its own payload — the EVM is the canonical case (the
    /// RLP transaction carries its own secp256k1 signature, which
    /// the module verifies in `handle`). For self-authenticating
    /// modules an envelope signature is meaningless *and* harmful —
    /// it would shift the payload offset — so flagged txs for these
    /// modules are rejected as malformed.
    fn authenticates_sender(&self) -> bool {
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

    /// Export the module's full committed state for snapshot sync.
    ///
    /// Returns `None` if — and only if — the module carries no
    /// committed state beyond what its constructor fixed (the
    /// `state_root` a fresh instance reports is then the complete
    /// commitment). `None` is a *declaration*: under strict snapshot
    /// import the executor rejects a snapshot that supplies state
    /// for a `None`-exporting module, and requires a `Some` snapshot
    /// whose [`Self::inspect_state`] verifies for every module whose
    /// `export_state` returns `Some`.
    ///
    /// This is used for full state sync: a new node imports the
    /// snapshot to skip replaying the entire chain from genesis.
    /// The snapshot must encode **every field that contributes to
    /// [`Self::state_root`]** — not merely a KV backend — or the
    /// importer restores a state whose root it cannot prove.
    ///
    /// # Default
    ///
    /// Returns `None` — declares the module stateless past
    /// construction.
    fn export_state(&self) -> Option<storage::Snapshot> {
        None
    }

    /// Compute the state root a staged snapshot claims — WITHOUT
    /// mutating the module.
    ///
    /// The executor calls this during the verification phase of a
    /// strict snapshot import, before any module state is written:
    /// it must decode and fully validate `snapshot` and return the
    /// state root the snapshot's contents produce. The result is
    /// compared against the snapshot's claimed per-module root; only
    /// after **every** module passes does the executor call
    /// [`Self::import_state`] to apply.
    ///
    /// "Fully validate" means byte-exact decoding of the module's own
    /// encoding — malformed fields, trailing bytes, and internally
    /// inconsistent sections are all `Err`, never silently skipped.
    ///
    /// # Default
    ///
    /// Fails closed: returns `Err(Malformed)`. A module whose
    /// `export_state` yields `Some` must override this — a stateful
    /// module that cannot inspect its snapshot cannot prove the
    /// root it would restore.
    ///
    /// # Errors
    ///
    /// [`storage::SnapshotError::Malformed`] on any decode or
    /// consistency failure.
    fn inspect_state(&self, _snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        Err(storage::SnapshotError::Malformed)
    }

    /// Import a snapshot, restoring the module's committed state.
    ///
    /// The executor calls this in the apply phase of a strict import
    /// — after [`Self::inspect_state`] has already verified this
    /// snapshot produces the claimed root — so `snapshot` here is
    /// authenticated input. The module must still decode defensively
    /// (it is a public entry point), then install the staged state
    /// atomically: fields are swapped in only after the whole
    /// payload decodes.
    ///
    /// # Default
    ///
    /// Returns `Ok(())` — reachable only for modules whose
    /// `export_state` is `None` (the executor never calls it with
    /// state then), so silently ignoring is correct: there is no
    /// state to install.
    ///
    /// # Errors
    ///
    /// Returns [`storage::SnapshotError`] if the payload fails to
    /// decode (should not happen post-inspection) or a backend I/O
    /// error occurs mid-apply.
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

/// Policy for transactions to non-self-authenticating modules that
/// carry no envelope signature.
///
/// Module dispatch is unaffected — this only governs whether an
/// unsigned envelope routed to a module that does not authenticate
/// its own sender is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsignedTxPolicy {
    /// Accept unsigned txs for non-self-authenticating modules.
    ///
    /// The sender field is trusted as declared, so any account can
    /// be impersonated. Only acceptable for devnet/test harnesses
    /// that must emit unsigned envelopes — never on a network that
    /// faces untrusted submitters.
    Allow,
    /// Reject unsigned txs for non-self-authenticating modules at
    /// mempool admission and skip them at execution.
    ///
    /// Required for production: without it, `ctx.sender` is
    /// unauthenticated and any native-module tx can claim any
    /// sender — e.g. bonding another account's balance as stake.
    /// Self-authenticating modules (EVM) are unaffected — their
    /// payload carries its own signature.
    Reject,
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

/// Why a transaction proposed in a finalized block never reached
/// module execution. A skipped tx was dropped at a pre-execution
/// gate: no fee was charged and the sender's `executed_nonce` was
/// NOT advanced — so the distinction between retryable and terminal
/// skips matters to any submitter waiting for confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxSkipReason {
    /// The envelope failed to parse (truncated, or no module-ID
    /// byte). Deterministic — the same bytes can never execute.
    Malformed,
    /// No module is registered at the declared module ID.
    /// Deterministic until a chain upgrade registers the module.
    UnknownModule,
    /// `ctx.nonce` was not the sender's next expected nonce (stale,
    /// gapped, or the reserved `u64::MAX`). Deterministic dead end:
    /// the executor's expected nonce only moves forward, so a nonce
    /// it has already passed can never become expected again, and a
    /// nonce ahead of expectation can never be reached while this
    /// tx itself is the gap.
    StaleNonce,
    /// Missing or invalid envelope signature, wrong chain ID, or a
    /// recovered signer that does not match the declared sender.
    /// Deterministic — the same bytes can never pass.
    BadSignature,
    /// The block gas budget was exhausted before this tx. The tx
    /// stays pooled and is re-proposed in later blocks — retryable.
    GasLimit,
    /// The declared fee is below the executor's `min_fee` floor.
    /// Deterministic until the floor policy changes.
    FeeFloor,
    /// The sender could not pay the declared fee (insufficient
    /// balance). Retryable if the account is later funded.
    FeeCharge,
}

/// The finalized outcome of one proposed transaction, recorded when
/// its block executes. This is the settlement-relevant boundary:
/// mempool acceptance only means a tx MAY be proposed; a `TxOutcome`
/// means the tx was in a block the executor actually ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxOutcome {
    /// The tx reached its module and was dispatched.
    ///
    /// `error` is `Some` when the module rejected the operation —
    /// the fee was still charged and the sender nonce still consumed
    /// (the tx executed; the business operation failed, like a
    /// revert). `events` carries whatever the module emitted —
    /// including per-leg failure events for batch operations that
    /// partially succeeded.
    Executed {
        /// Events the module emitted for this tx (empty on `Err`).
        events: Vec<Event>,
        /// The module's rejection, if it returned `Err`.
        error: Option<String>,
    },
    /// The tx was dropped at a pre-execution gate — see
    /// [`TxSkipReason`]. The nonce was not consumed; whether a
    /// resubmission can ever land depends on the reason.
    Skipped {
        /// The gate that rejected the tx.
        reason: TxSkipReason,
    },
}

/// Bound on the finalized-outcome window: 8192 txs.
///
/// The store exists so submitters can distinguish "executed" from
/// "accepted into the mempool" — it is a recent-history ring, not an
/// archive. 8192 covers ~8 full blocks at the 1000-tx default or
/// ~160 settlement batches, far beyond any sane confirmation
/// latency; entries older than that return `None`, which a waiter
/// must treat the same as "still in flight" (and bound its wait).
/// Memory cost is bounded: outcomes hold at most a few events each.
const MAX_TX_OUTCOMES: usize = 8192;

/// Insertion-ordered bounded map of tx hash → finalized outcome.
/// The `order` deque is the eviction frontier: the oldest recorded
/// hash is removed when the window is full.
#[derive(Default)]
struct TxOutcomeStore {
    /// Hashes in record order — front is oldest.
    order: std::collections::VecDeque<Hash>,
    /// The outcomes themselves.
    outcomes: HashMap<Hash, TxOutcome>,
}

impl TxOutcomeStore {
    /// Record an outcome, evicting the oldest entry at capacity.
    ///
    /// A tx may be `Skipped` in several blocks before landing (e.g.
    /// a gas-limit skip while it waits pooled for a freer block), so
    /// a `Skipped` entry is provisional — later records overwrite it.
    /// `Executed` is final: execution consumes the sender nonce, so
    /// an executed tx can never dispatch again; any later record for
    /// the same hash can only be a stale re-proposal being skipped.
    fn record(&mut self, hash: Hash, outcome: TxOutcome) {
        if matches!(self.outcomes.get(&hash), Some(TxOutcome::Executed { .. })) {
            return;
        }
        if self.outcomes.insert(hash, outcome).is_some() {
            return; // replaced a provisional skip — position unchanged
        }
        if self.order.len() >= MAX_TX_OUTCOMES
            && let Some(oldest) = self.order.pop_front()
        {
            self.outcomes.remove(&oldest);
        }
        self.order.push_back(hash);
    }
}

/// The v0 tx envelope payload format. The full tx is owned by the
/// mempool: `[sender: 20B][nonce: 8B LE][fee: 8B LE][payload]`. The
/// executor routes on the first byte of `payload`:
/// `[module_id: 1B][module_payload: ...]`.
const MODULE_ID_OFFSET: usize = 36; // 20 + 8 + 8

/// The high bit of the `module_id` byte marks a *signed* envelope
/// (v1): the module ID byte is followed by a 65-byte secp256k1
/// signature (`r ‖ s ‖ v`, v ∈ {0,1}) over the EIP-712 typed-data
/// digest of the transaction (`crypto::eip712::tx_signing_digest`).
///
/// Signed layout:
/// `[sender: 20B][nonce: 8B LE][fee: 8B LE][module_id|0x80: 1B]
///  [sig: 65B][module_payload: ...]`.
///
/// Putting the flag in the module-ID byte keeps every header field
/// at its v0 offset and makes the signature position a fixed offset
/// (37..102), so parsing stays branch-cheap. Module dispatch IDs
/// are conventionally ≤ 127 — all registered IDs today are 0–6 — so
/// the high bit is unambiguous.
const SIGNED_FLAG: u8 = 0x80;

/// Length of the secp256k1 signature in a signed envelope:
/// 32-byte `r` ‖ 32-byte `s` ‖ 1-byte recovery id.
const ENVELOPE_SIG_LEN: usize = 65;

/// Offset where the signature starts in a signed envelope
/// (immediately after the flagged module-ID byte).
const ENVELOPE_SIG_OFFSET: usize = MODULE_ID_OFFSET + 1; // 37

/// Offset where the module payload starts in a signed envelope.
const SIGNED_PAYLOAD_OFFSET: usize = ENVELOPE_SIG_OFFSET + ENVELOPE_SIG_LEN; // 102

/// A tx grouped by module for batch execution. The payload is a
/// zero-copy slice into the original tx bytes (no per-tx Vec
/// allocation). The hash is the full tx hash (used for preverify
/// cache lookup).
type GroupedTx<'a> = (TxContext, &'a [u8], Hash);

/// Parse the dispatch module ID from a tx's payload section.
///
/// The high bit of the stored byte is the [`SIGNED_FLAG`] marker,
/// not part of the module ID — this returns `byte & 0x7F`, the
/// actual dispatch ID.
fn parse_module_id(bytes: &[u8]) -> Option<u8> {
    if bytes.len() < MODULE_ID_OFFSET + 1 {
        return None;
    }
    Some(bytes[MODULE_ID_OFFSET] & !SIGNED_FLAG)
}

/// Whether the tx envelope carries an EIP-712 signature
/// ([`SIGNED_FLAG`] set on the module-ID byte).
fn is_signed_envelope(bytes: &[u8]) -> bool {
    bytes.len() > MODULE_ID_OFFSET && bytes[MODULE_ID_OFFSET] & SIGNED_FLAG != 0
}

/// Extract the 65-byte signature from a signed envelope.
/// Returns `None` if the envelope is unsigned or too short to hold
/// a signature.
fn envelope_signature(bytes: &[u8]) -> Option<&[u8]> {
    if !is_signed_envelope(bytes) {
        return None;
    }
    bytes.get(ENVELOPE_SIG_OFFSET..SIGNED_PAYLOAD_OFFSET)
}

/// Extract the module payload from a tx (everything after
/// `module_id` for unsigned txs, everything after the signature
/// for signed txs). The signature is envelope-level metadata — the
/// module only ever sees its own payload bytes.
fn module_payload(bytes: &[u8]) -> &[u8] {
    if is_signed_envelope(bytes) {
        bytes.get(SIGNED_PAYLOAD_OFFSET..).unwrap_or(&[])
    } else if bytes.len() <= MODULE_ID_OFFSET + 1 {
        &[]
    } else {
        &bytes[MODULE_ID_OFFSET + 1..]
    }
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

/// Shared execution-lane progress: the worker publishes `executed`
/// (highest height whose state root is recorded); `finalize_block`
/// publishes `enqueued` (highest height handed to the lane).
/// `attest_state` waits on the paired condvar while the height it
/// needs is owed to the lane.
struct ExecSync {
    /// Highest block height handed to the worker (`None`: none yet).
    enqueued: Option<u64>,
    /// Highest block height whose execution completed. Always
    /// `<= enqueued`; equal while the lane is idle.
    executed: Option<u64>,
    /// Set when the worker thread exits for ANY reason — panic or
    /// clean disconnect. A dead lane can never advance `executed`,
    /// so `attest_state` waiters must stop waiting on it and
    /// `finalize_block` must drive the committed backlog inline
    /// instead of sending into a void. Terminal: the lane is never
    /// respawned (a second spawn is already a panic).
    lane_dead: bool,
    /// The height currently inside `execute_block` on the worker —
    /// `Some` only while module state is mid-mutation. When the
    /// lane dies with this set AND the height has no recorded root,
    /// the block was PARTIALLY APPLIED: fees charged, nonces
    /// advanced, and module state mutated for some prefix of its
    /// txs. Replaying such a block re-runs those mutations on
    /// already-mutated state and can produce a silently wrong root
    /// — the backlog drain must refuse rather than re-execute.
    in_flight: Option<u64>,
}

/// RAII marker that flags the execution lane dead when the worker
/// thread exits — normal return AND panic unwind both run `Drop`.
/// The worker installs it before entering the receive loop so no
/// exit path can skip it. A panic prints its own message via the
/// panic runtime; the guard adds the lane-death notice so operators
/// can correlate the later withheld attestations with the cause.
struct LaneDeath {
    /// The progress channel shared with `attest_state` waiters and
    /// `finalize_block`.
    sync: std::sync::Arc<(Mutex<ExecSync>, std::sync::Condvar)>,
}

impl Drop for LaneDeath {
    fn drop(&mut self) {
        let (lock, cv) = &*self.sync;
        let in_flight = {
            let mut s = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            s.lane_dead = true;
            s.in_flight
        };
        // Wake every waiter: heights the dead lane still owes will
        // never execute — `attest_state` must stop waiting now, not
        // at the next commit.
        cv.notify_all();
        if std::thread::panicking() {
            eprintln!(
                "executor: exec lane worker panicked — lane marked dead \
                 (in-flight height: {in_flight:?})"
            );
        }
    }
}

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
    /// Phase D: the execution-lane channel. `Some` once
    /// [`Executor::spawn_exec_lane`] has installed the worker
    /// thread; `None` means synchronous finalize (the default).
    /// `OnceLock` so spawning races are refused loudly rather than
    /// silently splitting the commit stream between two workers.
    exec_lane_tx: std::sync::OnceLock<std::sync::mpsc::SyncSender<FinalizedBlock>>,
    /// Execution progress shared with the worker. `attest_state`
    /// waits on the condvar only while the requested height is
    /// enqueued-but-not-yet-executed — preserving the synchronous
    /// contract that an attested height's root exists, without
    /// blocking callers that attest a height the lane never saw.
    exec_sync: std::sync::Arc<(Mutex<ExecSync>, std::sync::Condvar)>,
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
    /// Finalized per-tx outcomes — the submitter-facing confirmation
    /// surface. Written once per proposed tx inside `execute_block`;
    /// read by `tx_outcome` from any thread (e.g. the matcher's
    /// settlement confirmer).
    tx_outcomes: Mutex<TxOutcomeStore>,
    /// Block gas limit. The total gas of all txs in a block must not
    /// exceed this limit. Enforced in `process_proposal` (rejects
    /// blocks that exceed the limit) and `execute_block` (skips
    /// txs that would exceed the cumulative limit).
    ///
    /// Default: 30 million gas per block (comparable to Ethereum's
    /// 30M gas limit). Configurable via [`Executor::with_gas_limit`].
    block_gas_limit: u64,
    /// The module that collects transaction fees (the EVM ledger).
    /// When set, every non-self-funded module's txs are charged
    /// `ctx.fee` through this module before execution — previously
    /// the charge was dispatched to the *target* module, so any
    /// module that didn't implement `charge_fee` executed for free.
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
    /// The chain ID mixed into the EIP-712 domain separator for
    /// native transaction signature verification. Binds every
    /// signed native tx to this chain — a signature produced for
    /// another chain ID fails verification (cross-chain replay
    /// protection). Default `1` (devnet); production must set it
    /// from chain config via [`Executor::with_chain_id`].
    chain_id: u64,
    /// Heights of `finalized`/`state_roots` kept in memory —
    /// `MAX_RETAINED_HISTORY` by default, tunable via
    /// [`with_history_retention`](Self::with_history_retention)
    /// (archive nodes raise it; constrained nodes lower it).
    /// Recent-height queries (`state_root_at`, `finalized_block`)
    /// only serve within this window; full history is the
    /// journal's job.
    history_retention: usize,
    /// Whether unsigned txs to non-self-authenticating modules are
    /// admitted. See [`UnsignedTxPolicy`]. Default `Reject` —
    /// authenticated envelopes are the default everywhere; devnet
    /// and test harnesses that emit unsigned envelopes opt out
    /// explicitly via [`Executor::with_unsigned_tx_policy`].
    unsigned_tx_policy: UnsignedTxPolicy,
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
            exec_lane_tx: std::sync::OnceLock::new(),
            exec_sync: std::sync::Arc::new((
                Mutex::new(ExecSync {
                    enqueued: None,
                    executed: None,
                    lane_dead: false,
                    in_flight: None,
                }),
                std::sync::Condvar::new(),
            )),
            events: Mutex::new(Vec::new()),
            tx_outcomes: Mutex::new(TxOutcomeStore::default()),
            preverify_cache: Mutex::new(HashMap::new()),
            parallel_threshold,
            recorder: None,
            mempool_intake_tx: intake_tx,
            mempool_intake_rx: Mutex::new(intake_rx),
            executed_nonce: Mutex::new(HashMap::new()),
            block_gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
            fee_module: None,
            min_fee: 0,
            chain_id: 1,
            unsigned_tx_policy: UnsignedTxPolicy::Reject,
            history_retention: MAX_RETAINED_HISTORY,
        }
    }

    /// Set the chain ID used for native transaction signature
    /// verification (the EIP-712 domain separator's `chainId`
    /// field).
    ///
    /// Must match the chain ID the wallets sign against — a
    /// mismatch rejects every signed native tx as unverifiable.
    /// Default `1` (devnet convention).
    #[must_use]
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Set the policy for unsigned txs to non-self-authenticating
    /// modules. See [`UnsignedTxPolicy`].
    ///
    /// The default is [`UnsignedTxPolicy::Reject`] — unauthenticated
    /// `ctx.sender` is a privilege-escalation hole, so the safe
    /// policy is the one you get by forgetting to configure it.
    /// Devnet/test harnesses that emit unsigned envelopes must opt
    /// out explicitly with [`UnsignedTxPolicy::Allow`].
    #[must_use]
    pub fn with_unsigned_tx_policy(mut self, policy: UnsignedTxPolicy) -> Self {
        self.unsigned_tx_policy = policy;
        self
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

    /// Set how many finalized heights `finalized`/`state_roots`
    /// retain in memory (default `MAX_RETAINED_HISTORY` = 4096).
    /// Raise for archive-style nodes serving deep `state_root_at`
    /// queries; lower to bound RAM on lean followers.
    #[must_use]
    pub fn with_history_retention(mut self, n: usize) -> Self {
        self.history_retention = n;
        self
    }

    /// Designate a module as the fee collector (the EVM ledger).
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
    /// Spawn the async execution worker. `finalize_block` then
    /// hands each committed block to the worker and returns
    /// immediately; the worker executes it and records the state
    /// root — overlapping execution of block h with consensus for
    /// block h+1, instead of serializing both on the consensus
    /// thread.
    ///
    /// # Correctness
    ///
    /// Blocks arrive strictly in commit order (the engine's commit
    /// walk is contiguous and oldest-first), so the worker's serial
    /// execution matches the synchronous path's ordering exactly.
    /// `attest_state(h)` waits on the watermark while h is
    /// enqueued-but-not-executed — the same root the synchronous
    /// path would have produced, just computed off-thread.
    ///
    /// The worker holds a `Weak` back-reference: dropping the
    /// `Executor` disconnects the channel and the thread exits —
    /// no reference cycle leaks the executor through its own
    /// worker.
    ///
    /// # Panics
    ///
    /// Panics if called twice — a second lane would split the
    /// commit stream.
    pub fn spawn_exec_lane(self: &std::sync::Arc<Self>) {
        // Bound the lane's queue: at most `depth` committed blocks
        // may sit unreceived. `finalize_block`'s blocking send then
        // *enforces* bounded execution lag — a worker that falls
        // behind stalls the commit path rather than silently
        // accumulating a backlog the drain could never replay.
        // Capping at `retention - 1` keeps the maximum possible
        // backlog (queue + one in-flight) inside the retained
        // history window even for tiny custom retentions.
        let depth = EXEC_LANE_DEPTH.min(self.history_retention.saturating_sub(1)).max(1);
        let (tx, rx) = std::sync::mpsc::sync_channel::<FinalizedBlock>(depth);
        self.exec_lane_tx.set(tx).expect("exec lane already spawned");
        let weak = std::sync::Arc::downgrade(self);
        let sync = self.exec_sync.clone();
        std::thread::Builder::new()
            .name("exec-lane".to_string())
            .spawn(move || {
                // RAII: ANY worker exit — panic unwind or clean
                // channel disconnect — marks the lane dead and wakes
                // every waiter. Without this, a panic mid-`execute_block`
                // left `attest_state` waiting forever on a watermark
                // that could never advance, and the death surfaced
                // only as unexplained withheld votes.
                let _death = LaneDeath { sync: sync.clone() };
                while let Ok(block) = rx.recv() {
                    // If the executor is gone there is no one left
                    // to serve — exit rather than resurrect it.
                    let Some(executor) = weak.upgrade() else { return };
                    let height = block.height.value();
                    // Mark the block in-flight BEFORE executing: if
                    // `execute_block` panics below, `LaneDeath` fires
                    // with this set and no root recorded — the state
                    // the recovery path must treat as partially
                    // applied, never blindly replayed.
                    {
                        let (lock, _cv) = &*sync;
                        lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).in_flight =
                            Some(height);
                    }
                    let root = executor.execute_block(&block);
                    executor
                        .state_roots
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert_retained(height, root, executor.history_retention);
                    // Blocks arrive in commit order, so the newest
                    // height is always the watermark.
                    let (lock, cv) = &*sync;
                    {
                        let mut s = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        s.in_flight = None;
                        s.executed = Some(height);
                    }
                    cv.notify_all();
                }
            })
            .expect("spawn exec lane thread");
    }

    /// Drive every committed-but-unexecuted height through block
    /// execution inline, in commit order. Called when the async
    /// lane is dead or unreachable: `finalized` already holds the
    /// committed blocks, so nothing is lost — the lane is only an
    /// offload, never the owner of correctness. Roots land in
    /// `state_roots` exactly as the worker would have written them,
    /// and the `executed` watermark advances to the newest root so
    /// `attest_state` waiters see the lane's debt as settled.
    ///
    /// A deterministic panic in `execute_block` propagates to the
    /// caller: a committed block that cannot execute is a fatal,
    /// chain-level fault. Crashing on the committing thread with
    /// the real panic is honest failure propagation — masking it
    /// would convert a loud crash into a silent liveness stall.
    ///
    /// # Panics
    ///
    /// Panics when the dead lane was mid-`execute_block` on a height
    /// that never recorded a root: that block was PARTIALLY APPLIED
    /// (fees charged, nonces advanced, module state mutated for some
    /// prefix of its txs), and re-executing it would replay those
    /// mutations on already-mutated state — potentially producing a
    /// silently wrong root rather than a second panic. There is no
    /// whole-block rollback to restore the pre-block state, so the
    /// only safe course is to halt: recovery must come from durable
    /// state (journal/snapshot/backend) at process restart. Heights
    /// the lane never started are unaffected — replaying an
    /// unstarted block mutates nothing twice.
    /// Insert a committed block into `finalized` and prune to the
    /// retention window — but never evict a height that has not
    /// been executed. Unexecuted committed blocks are the backlog
    /// the inline drain replays on lane failure; pruning one would
    /// strand that height permanently rootless. Execution is in
    /// height order, so every height at or below the `executed`
    /// watermark already has a root and is safe to drop; the pin
    /// simply refuses to evict above it.
    ///
    /// The watermark is read before the map lock — two short,
    /// non-nested critical sections keep the lock graph flat. A
    /// stale read only makes eviction more conservative, never
    /// wrong.
    fn insert_finalized(&self, height: u64, block: FinalizedBlock) {
        let executed = {
            let (lock, _cv) = &*self.exec_sync;
            lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).executed
        };
        let mut f = self.finalized.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        f.insert(height, block);
        while f.len() > self.history_retention {
            let evictable =
                f.keys().next().is_some_and(|first| executed.is_some_and(|e| *first <= e));
            if !evictable {
                break;
            }
            f.pop_first();
        }
    }

    fn execute_committed_backlog(&self) {
        // Fail closed on a partially applied block before replaying
        // anything. `in_flight` is set by the worker around
        // `execute_block` and cleared only after the root lands, so
        // `Some(h)` + no root = the worker died mid-mutation.
        let poisoned = {
            let (lock, _cv) = &*self.exec_sync;
            let in_flight =
                lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).in_flight;
            in_flight.filter(|h| {
                !self
                    .state_roots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains_key(h)
            })
        };
        if let Some(h) = poisoned {
            panic!(
                "executor: execution lane died mid-execution of committed block {h}; \
                 the block may be partially applied (fees/nonces/module state already \
                 mutated) and cannot be safely replayed in-process — halting; restart \
                 to recover from durable state"
            );
        }
        loop {
            // Oldest committed height still lacking a state root —
            // height order preserves the worker's serial ordering
            // exactly. Two short critical sections, never nested:
            // no lock-order contract between the block log and the
            // root map.
            let next = {
                let heights: Vec<u64> = self
                    .finalized
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .keys()
                    .copied()
                    .collect();
                let roots =
                    self.state_roots.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                heights.into_iter().find(|h| !roots.contains_key(h))
            };
            let Some(height) = next else { break };
            let Some(block) = self
                .finalized
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&height)
                .cloned()
            else {
                // The entry was found moments ago and this thread is
                // the only pruner — unreachable, but bail rather
                // than spin if invariants ever change.
                break;
            };
            // Mark the height in-flight around the inline execution
            // exactly as the worker does: if `execute_block` panics
            // here, the panic propagates to the committer AND the
            // marker stays set — so a later `finalize_block` meets
            // the same fail-closed check above instead of silently
            // retrying a block this drain partially applied.
            {
                let (lock, _cv) = &*self.exec_sync;
                lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).in_flight =
                    Some(height);
            }
            let root = self.execute_block(&block);
            self.state_roots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert_retained(height, root, self.history_retention);
            {
                let (lock, _cv) = &*self.exec_sync;
                lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).in_flight = None;
            }
        }
        // Advance the executed watermark to the newest recorded
        // root: heights the dead lane owed have now been executed
        // inline, and `attest_state` waiters must observe that.
        let newest = self
            .state_roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .next_back()
            .map(|(h, _)| *h);
        if let Some(h) = newest {
            let (lock, cv) = &*self.exec_sync;
            let mut s = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            s.executed = Some(s.executed.map_or(h, |e| e.max(h)));
            cv.notify_all();
        }
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

    /// The finalized execution outcome for a proposed transaction,
    /// keyed by its full `Domain::Transaction` hash.
    ///
    /// `None` means the tx has not appeared in an executed block yet
    /// (still pooled, proposed-but-not-finalized, or evicted from the
    /// bounded [`MAX_TX_OUTCOMES`] window). Callers must bound their
    /// wait — `None` is ambiguous between "in flight" and "aged out".
    #[must_use]
    pub fn tx_outcome(&self, tx_hash: &Hash) -> Option<TxOutcome> {
        self.tx_outcomes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outcomes
            .get(tx_hash)
            .cloned()
    }

    /// The next nonce the executor expects from `sender` — the count
    /// of its txs that have passed execution-time continuity. This is
    /// the authoritative resync anchor for a submitter whose local
    /// nonce may have drifted (restart, dead-lettered batch).
    #[must_use]
    pub fn executed_nonce_of(&self, sender: &primitives::Address) -> u64 {
        self.executed_nonce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(sender)
            .copied()
            .unwrap_or(0)
    }

    /// The latest state root (at the current chain height).
    ///
    /// Returns `Hash::ZERO` if no blocks have been finalized.
    #[must_use]
    pub fn current_state_root(&self) -> Hash {
        self.state_root_at(self.current_height())
    }

    /// The earliest scheduled coordinated halt height across
    /// modules, if any module's governance set one. Above this
    /// height the chain freezes: `prepare_proposal` emits empty
    /// blocks and `execute_block` is a no-op returning the frozen
    /// root — every node stops mutating state at the same height,
    /// so operators can snapshot and swap binaries deterministically.
    ///
    /// `None` = no halt scheduled.
    #[must_use]
    pub fn halt_height(&self) -> Option<u64> {
        self.modules.iter().flatten().filter_map(|m| m.scheduled_halt_height()).min()
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

    /// Pending mempool entry count — cold-path diagnostic for the
    /// devnet harness (a nonzero value after a run means txs were
    /// accepted into the pool but never selected for a proposal).
    #[must_use]
    pub fn mempool_len(&self) -> usize {
        self.mempool.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Save executed nonces to a storage backend (C10 fix).
    ///
    /// Persists the per-sender `executed_nonce` map to the storage
    /// backend using a reserved key prefix. Call this on shutdown
    /// or after each block commit to ensure nonces survive restart.
    /// Without this, a restart resets all executed nonces to zero,
    /// allowing replay of already-executed native transactions.
    ///
    /// # Errors
    ///
    /// Returns [`storage::ApplyError`] when the backend rejects the
    /// batch — the nonce map was NOT persisted and a restart would
    /// reopen the replay window; the caller must not treat the
    /// shutdown/commit as complete.
    pub fn save_executed_nonces(
        &self,
        backend: &mut (dyn storage::StorageBackend + Send),
    ) -> Result<(), storage::ApplyError> {
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
        backend.apply_batch(&ops)
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

    /// Block until the execution lane has fully drained — every
    /// enqueued block executed. Callers that must observe a
    /// consistent cross-module state (snapshot export, state sync)
    /// wait here rather than reading module state while the worker
    /// is mid-block. No-op when the lane is not installed or is
    /// already idle.
    fn wait_exec_idle(&self) {
        if self.exec_lane_tx.get().is_some() {
            let (lock, cv) = &*self.exec_sync;
            let mut s = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            while s.enqueued != s.executed {
                s = cv.wait(s).unwrap_or_else(std::sync::PoisonError::into_inner);
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
    ///
    /// Drains the execution lane before reading module state so the
    /// snapshot captures a quiesced height boundary, never a
    /// mid-block mix of pre- and post-execution module roots.
    #[must_use]
    pub fn export_snapshot(&self) -> ExecutorSnapshot {
        // Drain the execution lane first: module state is mutated by
        // the worker thread block-by-block, so a snapshot taken
        // mid-block could mix pre- and post-execution module roots.
        // Waiting for `executed == enqueued` captures a quiesced
        // height boundary.
        self.wait_exec_idle();
        let height = self.current_height();
        let state_root = self.state_root_at(height);
        let module_roots: Vec<(String, Hash)> =
            self.modules.iter().flatten().map(|m| (m.name().to_string(), m.state_root())).collect();
        // Export full KV state for each module that supports it.
        let module_state: Vec<Option<storage::Snapshot>> =
            self.modules.iter().flatten().map(|m| m.export_state()).collect();
        // C8: recompute the canonical aggregate — module roots +
        // nonce root, the same definition `execute_block` uses. We
        // always recompute (rather than using the stored root)
        // because the stored root may be stale if the block hasn't
        // been executed yet (async execution), and the nonce root
        // binds `executed_nonces` into the commitment.
        let _ = state_root; // stored root may be stale; we recompute below
        let executed_nonces: Vec<(primitives::Address, u64)> = self
            .executed_nonce
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(addr, nonce)| (*addr, *nonce))
            .collect();
        let nonce_root = compute_nonce_root(&executed_nonces);
        let state_root =
            canonical_state_root(module_roots.iter().map(|(_, root)| *root), nonce_root);
        ExecutorSnapshot {
            height,
            state_root,
            module_roots,
            module_state,
            executed_nonces,
            nonce_root,
            version: SNAPSHOT_FORMAT_VERSION,
            // Record each module's declared schema version so an
            // importer restoring this state under a newer binary
            // knows which `migrate(from)` calls to run.
            module_versions: self.modules.iter().flatten().map(|m| m.state_version()).collect(),
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
    /// Does not panic. Verification is atomic: no module state
    /// mutates until every module's staged payload has passed
    /// `inspect_state` against its claimed root.
    ///
    /// # Safety
    ///
    /// Every module's committed state is restored: modules that
    /// declare state (`export_state` → `Some`) must carry a payload
    /// whose `inspect_state` reproduces the claimed module root;
    /// stateless-declaring modules must match their construction
    /// root and carry no payload. Anything else — missing, extra,
    /// malformed, or mislabeled module state — fails the import
    /// before any mutation.
    pub fn import_snapshot(&self, snapshot: &ExecutorSnapshot) -> Result<(), SnapshotImportError> {
        // A snapshot at height 0 is valid — it represents the genesis
        // state after the first (empty) block. We only reject if there
        // are no module roots (truly empty snapshot).
        if snapshot.module_roots.is_empty() {
            return Err(SnapshotImportError::EmptySnapshot);
        }

        // Verify the snapshot's internal consistency: the state root
        // must match the recomputed canonical aggregate of the
        // snapshot's own per-module state roots AND the nonce root
        // (C8 — the same definition `execute_block` uses). This
        // catches corrupted or tampered snapshots without requiring
        // the local modules to have the same state (the snapshot is
        // from a peer, not local).
        let recomputed_nonce_root = compute_nonce_root(&snapshot.executed_nonces);
        if recomputed_nonce_root != snapshot.nonce_root {
            return Err(SnapshotImportError::NonceRootMismatch {
                expected: snapshot.nonce_root,
                actual: recomputed_nonce_root,
            });
        }
        let recomputed = canonical_state_root(
            snapshot.module_roots.iter().map(|(_, root)| *root),
            recomputed_nonce_root,
        );
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

        // Format gate: a snapshot written by a newer binary cannot
        // be safely interpreted — reject before touching state.
        if snapshot.version > SNAPSHOT_FORMAT_VERSION {
            return Err(SnapshotImportError::UnsupportedVersion {
                snapshot: snapshot.version,
                supported: SNAPSHOT_FORMAT_VERSION,
            });
        }

        // Verify + restore every module's committed state — staged,
        // name-bound, and proven before a single byte is installed.
        self.restore_module_state(snapshot)?;

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

    /// Strict, staged module-state restore for [`import_snapshot`].
    ///
    /// A snapshot is untrusted until every module's claimed state has
    /// been proven from the staged bytes. Two passes:
    ///
    ///   1. VERIFY — bind names, check completeness, and run each
    ///      module's [`Module::inspect_state`] over the staged
    ///      payload so the claimed root is derived from the data, not
    ///      trusted. No module state is mutated in this pass.
    ///   2. APPLY — only after every module verifies, call
    ///      `import_state` + `migrate`.
    ///
    /// Binding: `module_state[i]` belongs to the module registered at
    /// position i only because `module_roots[i].0` equals its
    /// `name()` — position alone is not binding (a forged name list
    /// would slide a foreign blob into the wrong module).
    ///
    /// Completeness: `export_state` returning `Some` declares the
    /// module stateful — the snapshot must carry a payload whose
    /// `inspect_state` reproduces the claimed root. Returning `None`
    /// declares it stateless — its committed state is fixed at
    /// construction, so the claimed root must equal a fresh module's
    /// root, and any supplied payload is rejected as uninterpretable.
    ///
    /// # Errors
    ///
    /// `ModuleNameMismatch` when the claimed name doesn't match the
    /// registered module; `ModuleCountMismatch` when the state vector
    /// length disagrees with `module_roots`; `MissingModuleState` /
    /// `UnexpectedModuleState` on the stateful/stateless declaration
    /// boundary; `MalformedModuleState` when `inspect_state` rejects
    /// the payload; `ModuleRootMismatch` when the staged bytes don't
    /// hash to the claimed root; `StateImportFailed` / `MigrationFailed`
    /// during the apply pass.
    fn restore_module_state(&self, snapshot: &ExecutorSnapshot) -> Result<(), SnapshotImportError> {
        let modules: Vec<&Arc<dyn Module>> = self.modules.iter().flatten().collect();
        for (i, (module, (name, claimed_root))) in
            modules.iter().zip(&snapshot.module_roots).enumerate()
        {
            if module.name() != name.as_str() {
                return Err(SnapshotImportError::ModuleNameMismatch {
                    index: i,
                    snapshot: name.clone(),
                    registered: module.name().to_string(),
                });
            }
            if module.export_state().is_none() && module.state_root() != *claimed_root {
                // Stateless module claiming a root no fresh instance
                // produces — either the snapshot lies or the configs
                // differ.
                return Err(SnapshotImportError::ModuleRootMismatch {
                    module: name.clone(),
                    expected: *claimed_root,
                    actual: module.state_root(),
                });
            }
        }

        if snapshot.module_state.is_empty() {
            // Metadata-only snapshot: complete only when no module
            // declares committed state — anything else is missing
            // data, not a sparse encoding.
            for module in &modules {
                if module.export_state().is_some() {
                    return Err(SnapshotImportError::MissingModuleState {
                        module: module.name().to_string(),
                    });
                }
            }
            return Ok(());
        }

        if snapshot.module_state.len() != snapshot.module_roots.len() {
            return Err(SnapshotImportError::ModuleCountMismatch {
                snapshot: snapshot.module_state.len(),
                registered: modules.len(),
            });
        }
        // VERIFY pass — inspect every payload before mutating.
        let mut staged: Vec<(usize, &storage::Snapshot)> = Vec::new();
        for (i, module) in modules.iter().enumerate() {
            let (name, claimed_root) = &snapshot.module_roots[i];
            match &snapshot.module_state[i] {
                Some(state) => {
                    if module.export_state().is_none() {
                        return Err(SnapshotImportError::UnexpectedModuleState {
                            module: name.clone(),
                        });
                    }
                    let actual = module.inspect_state(state).map_err(|_| {
                        SnapshotImportError::MalformedModuleState { module: name.clone() }
                    })?;
                    if actual != *claimed_root {
                        return Err(SnapshotImportError::ModuleRootMismatch {
                            module: name.clone(),
                            expected: *claimed_root,
                            actual,
                        });
                    }
                    staged.push((i, state));
                }
                None => {
                    if module.export_state().is_some() {
                        return Err(SnapshotImportError::MissingModuleState {
                            module: name.clone(),
                        });
                    }
                }
            }
        }

        // APPLY pass — every module verified. `import_state`
        // re-decodes and installs atomically; `migrate` upgrades
        // the freshly imported bytes when the snapshot's recorded
        // schema trails the binary's declared version (empty
        // `module_versions` — v1 snapshots — means "all current",
        // as v1 predates the hook entirely). A backend I/O error
        // or failed migration can still leave an earlier module
        // applied: mutation-after-verification is inherent to
        // apply, but NO malformed input ever reaches this point.
        for (i, state) in staged {
            let module = modules[i];
            module.import_state(state).map_err(|_| SnapshotImportError::StateImportFailed)?;
            let from = snapshot.module_versions.get(i).copied().unwrap_or(module.state_version());
            if from < module.state_version() {
                module.migrate(from).map_err(|_| SnapshotImportError::MigrationFailed {
                    module: module.name().to_string(),
                    from,
                })?;
            }
        }
        Ok(())
    }

    /// Check the envelope authentication of a tx routed to `module`.
    ///
    /// Returns:
    /// - `Ok(true)` — the envelope carries a signature and it
    ///   verified: the recovered signer equals `ctx.sender`. The
    ///   caller should record the tx hash in the preverify cache so
    ///   `execute_block` can skip re-verification.
    /// - `Ok(false)` — the envelope is unsigned and admitted (either
    ///   the module self-authenticates or the policy allows it).
    /// - `Err(reason)` — rejected: bad signature, sender mismatch,
    ///   malformed signature field, flag set on a self-authenticating
    ///   module, or unsigned tx under [`UnsignedTxPolicy::Reject`].
    ///
    /// The signature covers the EIP-712 digest of
    /// `(chain_id, sender, nonce, fee, module_id, payload)` — see
    /// [`crypto::eip712`]. Because `sender` is a field of the signed
    /// struct, verifying `recovered == ctx.sender` binds the whole
    /// envelope: the signer, the declared sender, and the exact
    /// module message bytes.
    ///
    /// This is deterministic and state-free, so all validators agree
    /// on the outcome — safe to run in `execute_block` (skip on
    /// failure) as well as at mempool admission (reject).
    fn check_envelope_auth(
        &self,
        bytes: &[u8],
        ctx: &TxContext,
        module_id: u8,
        module: &dyn Module,
        verified: Option<&HashMap<Hash, [u8; 20]>>,
    ) -> Result<bool, &'static str> {
        let signed = is_signed_envelope(bytes);
        if module.authenticates_sender() {
            // The module's payload carries its own signature (EVM
            // RLP). An envelope signature would shift the payload
            // offset and serves no purpose — reject as malformed so
            // the flag can never silently corrupt an EVM payload.
            return if signed {
                Err("malformed: envelope signature on self-authenticating module")
            } else {
                Ok(false)
            };
        }
        if !signed {
            return match self.unsigned_tx_policy {
                UnsignedTxPolicy::Allow => Ok(false),
                UnsignedTxPolicy::Reject => Err("unsigned native tx (signature required)"),
            };
        }
        // Signed envelope: recover and compare.
        //
        // If the caller supplies a `verified` map (the preverify
        // cache at execution time), a hit means this node's
        // `ingest_tx` already ran the secp256k1 recovery for these
        // exact tx bytes — the cache key is `Domain::Transaction` of
        // the full envelope, so a hit implies the signature was
        // verified. Skip re-verification (~40 µs saved per tx).
        if let Some(cache) = verified {
            let tx_hash = Hasher::hash_one(Domain::Transaction, bytes);
            if cache.contains_key(&tx_hash) {
                return Ok(true);
            }
        }
        let Some(sig_bytes) = envelope_signature(bytes) else {
            return Err("malformed: truncated envelope signature");
        };
        // v is the last byte. We accept only 0/1 — the canonical
        // recovery IDs secp256k1 produces. IDs 2/3 correspond to
        // provably-unused keys and 27/28 is the Ethereum `v`
        // convention; MetaMask returns 27/28, which submitters must
        // normalize to 0/1 before building the envelope.
        let recid = sig_bytes[64];
        if recid > 1 {
            return Err("malformed: envelope signature recovery id must be 0 or 1");
        }
        let sig = crypto::secp::RecoverableSignature::from_bytes(&sig_bytes[..64], recid)
            .map_err(|_| "malformed: envelope signature")?;
        let payload = module_payload(bytes);
        let recovered = crypto::eip712::verify_tx_sender(
            self.chain_id,
            &ctx.sender,
            ctx.nonce,
            ctx.fee,
            module_id,
            payload,
            &sig,
        )
        .map_err(|_| "invalid envelope signature")?;
        if recovered != ctx.sender {
            return Err("envelope signature does not match declared sender");
        }
        Ok(true)
    }

    /// Group a finalized block's txs by module for batch execution,
    /// applying the execution-time admission gates in block order.
    ///
    /// Each tx must pass, in order:
    /// 1. envelope parse — malformed bytes are skipped;
    /// 2. nonce continuity — `ctx.nonce` must equal the next expected
    ///    nonce for `ctx.sender` in the local copy of `executed_nonce`
    ///    (H5; closes the cross-block replay window for byzantine
    ///    proposers that bypass `process_proposal`);
    /// 3. known module — the routed module must be registered;
    /// 4. envelope authentication — `check_envelope_auth`; a tx in
    ///    `preverify_cache` was verified at this node's `ingest_tx`
    ///    (same full-tx-hash key), so it skips the ~40 µs recovery,
    ///    while a tx arriving via a foreign proposal is verified
    ///    inline. Failures skip the tx — deterministic across
    ///    validators, so all produce the same state root;
    /// 5. block gas limit — cumulative `estimate_gas` across the
    ///    block (execution-time enforcement of the proposal-time
    ///    check in `process_proposal`);
    /// 6. fee floor + fee charge — non-self-funded modules pay
    ///    `ctx.fee` via the configured fee module. The fee is kept
    ///    even if `handle` later fails (work was attempted — like
    ///    gas on revert), and the nonce only advances after the
    ///    charge succeeds.
    ///
    /// Entries are `(ctx, payload, full_tx_hash)`; the payload is a
    /// zero-copy borrow into the block bytes and the hash is the
    /// preverify-cache key.
    ///
    /// The plan preserves **committed block order**: the returned
    /// `Vec` is a sequence of contiguous same-module *runs* — a new
    /// run starts whenever the module id changes, so cross-module
    /// semantics are exactly sequential (an EVM transfer funding a
    /// later delegate is visible to it). Batching amortizes only
    /// where the committed order already made txs adjacent; it never
    /// reorders across modules. This replaces the old global
    /// `BTreeMap<module_id>` grouping, which was deterministic but
    /// NOT faithful to the ordering consensus finalized — modules
    /// share one balance ledger, so sorted-module execution could
    /// reorder a funding transfer past its dependent.
    ///
    /// The fee *floor* is a stateless gate and stays here; the fee
    /// *charge* does NOT — it debits the shared ledger, so it must
    /// observe the effects of every earlier tx. It runs at dispatch
    /// time, per run in block order (see `execute_block`).
    ///
    /// `skipped` collects the hash + gate for every proposed tx that
    /// never reaches a module — the caller records each as a
    /// [`TxOutcome::Skipped`] so a submitter can tell "dropped at a
    /// gate" apart from "executed and rejected".
    fn plan_block_runs<'b>(
        &self,
        txs: &'b [TxBytes],
        local_nonce: &mut HashMap<primitives::Address, u64>,
        preverify_cache: &HashMap<Hash, [u8; 20]>,
        skipped: &mut Vec<(Hash, TxSkipReason)>,
    ) -> Vec<(u8, Vec<GroupedTx<'b>>)> {
        let mut runs: Vec<(u8, Vec<GroupedTx<'b>>)> = Vec::new();
        let mut cumulative_gas: u64 = 0;
        for tx in txs {
            let bytes = tx.as_bytes();
            // Hash once up front: grouped txs already paid for this
            // hash (preverify key), and skipped txs need it for the
            // outcome record. Skips are rare in honest traffic, so
            // the extra hash on a dropped tx costs nothing real.
            let tx_hash = Hasher::hash_one(Domain::Transaction, bytes);
            let Some(ctx) = parse_tx_context(bytes) else {
                skipped.push((tx_hash, TxSkipReason::Malformed));
                continue;
            };
            let Some(module_id) = parse_module_id(bytes) else {
                skipped.push((tx_hash, TxSkipReason::Malformed));
                continue;
            };
            let Some(module) = self.modules[module_id as usize].as_ref() else {
                skipped.push((tx_hash, TxSkipReason::UnknownModule));
                continue;
            };
            // A self-authenticating module (the EVM) recovers its real
            // sender and nonce from its own payload, so the envelope's
            // declared pair is a mempool ordering hint and nothing more.
            // Driving the executor's account-indexed nonce state from it
            // would let anyone advance *another* account's counter: wrap
            // your own valid signed payload in a victim's envelope and
            // the victim's `executed_nonce` moves while their balance and
            // their EVM account nonce never do. The executor's nonce gate
            // therefore applies only to modules that authenticate from
            // the envelope; a self-authenticating module enforces its own
            // nonce during execution.
            let self_authenticating = module.authenticates_sender();
            // H5: each tx's nonce must equal the next expected nonce
            // for its sender; txs that fail are skipped and do not
            // advance the counter. u64::MAX is reserved — skipping it
            // here keeps `expected + 1` below overflow-free (a MAX
            // nonce would wrap the counter to 0 and reopen the
            // sender's whole nonce range to replay).
            let expected = local_nonce.get(&ctx.sender).copied().unwrap_or(0);
            if !self_authenticating && (ctx.nonce != expected || ctx.nonce == u64::MAX) {
                skipped.push((tx_hash, TxSkipReason::StaleNonce));
                continue;
            }
            if self
                .check_envelope_auth(bytes, &ctx, module_id, module.as_ref(), Some(preverify_cache))
                .is_err()
            {
                skipped.push((tx_hash, TxSkipReason::BadSignature));
                continue;
            }
            let payload = module_payload(bytes);
            let gas = module.estimate_gas(payload);
            if cumulative_gas.saturating_add(gas) > self.block_gas_limit {
                skipped.push((tx_hash, TxSkipReason::GasLimit));
                continue;
            }
            // Fee floor gate: the envelope's fee field is
            // sender-declared, so `min_fee` is enforced here — a
            // pure predicate, no ledger effect. The charge itself
            // moved to dispatch (`execute_block`) so it observes the
            // balance effects of every earlier tx; charging it here
            // would debit all senders before ANY module ran — a
            // later tx's fee failing though an earlier tx funded
            // the account is exactly the reordering this plan
            // exists to eliminate. Self-funded modules (EVM: gas is
            // the fee) are exempt either way.
            if !module.pays_own_fee() && ctx.fee < self.min_fee {
                skipped.push((tx_hash, TxSkipReason::FeeFloor));
                continue;
            }
            // Advance the local nonce counter for this sender —
            // provisionally: a dispatch-time fee failure rewinds it
            // (see `execute_block`) so a failed charge never consumes
            // the nonce. `expected + 1` cannot overflow: the
            // reserved-nonce skip above keeps `expected ≤ u64::MAX -
            // 1`. Self-authenticating modules keep their own account
            // nonce (enforced inside the module), so the executor
            // tracks nothing for them.
            if !self_authenticating {
                local_nonce.insert(ctx.sender, expected + 1);
            }
            cumulative_gas = cumulative_gas.saturating_add(gas);
            // Zero-copy: the payload is borrowed from the block tx
            // bytes; the full-tx hash is the same key `ingest_tx`
            // used for the preverify cache.
            match runs.last_mut() {
                Some((run_module, run)) if *run_module == module_id => {
                    run.push((ctx, payload, tx_hash));
                }
                _ => runs.push((module_id, vec![(ctx, payload, tx_hash)])),
            }
        }
        runs
    }

    /// Charge the fee for every tx in one contiguous run, in run
    /// order, and return the survivors for dispatch. The charge
    /// lives at dispatch time — not in `plan_block_runs` — because it
    /// debits the shared ledger and must observe every earlier tx's
    /// effects. Cross-module ordering is exact; within a run, a tx's
    /// fee does not see earlier same-run txs (the documented
    /// residual — closing it would need per-tx charge/execute
    /// interleaving and lose batching entirely).
    ///
    /// `broken_nonce` records the first failed-charge nonce per
    /// sender: under sequential semantics a failed charge consumes
    /// no nonce, so that sender's later txs are unreachable this
    /// block — they're skipped `StaleNonce` rather than executed
    /// with a gap. `local_nonce` is rewound to the failed nonce so
    /// `executed_nonce` reflects the last consumed nonce + 1 and
    /// the failed tx stays retryable. Self-funded modules (EVM:
    /// gas is the fee) skip charging entirely.
    fn charge_run_fees<'b>(
        &self,
        run: Vec<GroupedTx<'b>>,
        module: &dyn Module,
        local_nonce: &mut HashMap<primitives::Address, u64>,
        broken_nonce: &mut HashMap<primitives::Address, u64>,
        dispatch_skipped: &mut Vec<(Hash, TxSkipReason)>,
    ) -> Vec<GroupedTx<'b>> {
        if module.pays_own_fee() {
            return run;
        }
        let fee_module = self.fee_module.and_then(|id| self.modules[usize::from(id)].as_ref());
        let self_authenticating = module.authenticates_sender();
        let mut survivors = Vec::with_capacity(run.len());
        for entry in run {
            let ctx = entry.0;
            if let Some(&broken) = broken_nonce.get(&ctx.sender)
                && ctx.nonce >= broken
            {
                dispatch_skipped.push((entry.2, TxSkipReason::StaleNonce));
                continue;
            }
            let charged = fee_module.is_none_or(|m| m.charge_fee(&ctx).is_ok());
            if !charged {
                dispatch_skipped.push((entry.2, TxSkipReason::FeeCharge));
                broken_nonce.entry(ctx.sender).or_insert(ctx.nonce);
                if !self_authenticating {
                    local_nonce.insert(ctx.sender, ctx.nonce);
                }
                continue;
            }
            survivors.push(entry);
        }
        survivors
    }

    /// Dispatch one run to its module and return per-tx results.
    ///
    /// Phase E: zero-copy payload handling. If every tx in the run
    /// has a cached sender, borrowed `PreverifiedTx`s are built
    /// straight from the block bytes and the run goes through the
    /// preverified path — parallel when it clears
    /// `parallel_threshold` (speculation is sound inside a run:
    /// the planner only batches contiguous same-module txs). If any
    /// sender is uncached, the fallback `handle_batch` path is used
    /// directly — no preverified Vec constructed, no wasted clones.
    /// (Previously the preverified Vec was always built, cloning
    /// payloads for txs the fallback path never used.)
    fn dispatch_run(
        &self,
        module: &dyn Module,
        group: &[GroupedTx<'_>],
        preverify_cache: &mut HashMap<Hash, [u8; 20]>,
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        let all_cached =
            group.iter().all(|(_ctx, _payload, tx_hash)| preverify_cache.contains_key(tx_hash));
        if !all_cached {
            let batch: Vec<(TxContext, &[u8])> =
                group.iter().map(|(ctx, payload, _tx_hash)| (*ctx, *payload)).collect();
            return module.handle_batch(&batch);
        }
        // All senders are pre-recovered — build borrowed
        // `PreverifiedTx`s straight from the block bytes.
        let preverified: Vec<PreverifiedTx<'_>> = group
            .iter()
            .map(|(_ctx, payload, tx_hash)| PreverifiedTx {
                raw: payload,
                sender: preverify_cache.remove(tx_hash).unwrap_or([0u8; 20]),
            })
            .collect();
        // Each tx keeps its own authenticated envelope context —
        // `ctxs[i]` pairs with `preverified[i]`. Passing `group[0].0`
        // here previously executed the whole group under the first
        // tx's identity.
        let ctxs: Vec<TxContext> = group.iter().map(|(ctx, _, _)| *ctx).collect();
        if group.len() >= self.parallel_threshold {
            module.handle_batch_parallel_preverified(&ctxs, &preverified)
        } else {
            module.handle_batch_preverified(&ctxs, &preverified)
        }
    }

    /// Execute a finalized block: call `begin_block`, plan contiguous
    /// same-module runs (preserving committed block order), charge
    /// fees + dispatch each run via `handle_batch`, call `end_block`,
    /// compute the state root.
    ///
    /// Execution order is the committed block order at run
    /// granularity: a new run starts when the module id changes, so
    /// a tx always observes the ledger effects of every earlier
    /// cross-module tx — and of its own fee charge, which happens at
    /// dispatch time rather than during planning. Contiguous
    /// same-module txs still batch in one `handle_batch*` call, so
    /// modules with batch-optimized paths (EVM parallel sender
    /// recovery, pre-verified senders) amortize per-tx overhead.
    /// This replaces the old sort-by-module grouping, which was
    /// deterministic but not faithful to committed order — modules
    /// share one balance ledger, so "group then execute" was not
    /// equivalent to sequential execution.
    fn execute_block(&self, block: &FinalizedBlock) -> Hash {
        // Coordinated halt: above the scheduled height the chain is
        // frozen — no begin/handle/end_block, no fee charge, no
        // attendance record. The returned root is the state at the
        // halt height, so every replica freezes on identical state.
        // Deterministic across live and replayed execution (the
        // schedule lives in module state, journaled like any other).
        if let Some(halt) = self.halt_height()
            && block.height.value() > halt
        {
            return self.state_root_at(halt);
        }

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

        // begin_block for all modules — via `begin_block_ctx` so the
        // consensus-committed execution context (timestamp,
        // beneficiary, gas limit) reaches modules that consume it.
        for module in self.modules.iter().flatten() {
            module.begin_block_ctx(block.height, &block.context);
        }

        // Move the preverify cache out before the grouping loop —
        // the loop consults it to skip re-verifying envelope
        // signatures that were already verified at mempool
        // admission, and the dispatch loop below consumes it.
        // (`mem::take` swaps in an empty map — zero-copy, one lock
        // acquisition for the whole block.)
        let mut preverify_cache = std::mem::take(
            &mut *self.preverify_cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        );

        let mut skipped: Vec<(Hash, TxSkipReason)> = Vec::new();
        let mut runs =
            self.plan_block_runs(&block.txs, &mut local_nonce, &preverify_cache, &mut skipped);

        // Record finalized outcomes for txs that never reached a
        // module. These are the only outcomes a submitter can get
        // for a gate-dropped tx — the mempool no longer holds it
        // (it was proposed), so without this record a skipped tx is
        // indistinguishable from "still in flight" forever.
        {
            let mut outcomes =
                self.tx_outcomes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for (hash, reason) in skipped {
                outcomes.record(hash, TxOutcome::Skipped { reason });
            }
        }

        // Execute each contiguous same-module run in committed block
        // order — sequential cross-module semantics. Fee charging
        // happens inside `charge_run_fees`, immediately before each
        // run's dispatch.
        let mut block_events: Vec<Event> = Vec::new();
        let mut broken_nonce: HashMap<primitives::Address, u64> = HashMap::new();
        let mut dispatch_skipped: Vec<(Hash, TxSkipReason)> = Vec::new();

        for (module_id, run) in &mut runs {
            let Some(module) = self.modules[*module_id as usize].as_ref() else {
                continue; // unknown module — skip
            };

            // Charge each tx's fee through the configured collector
            // (the EVM ledger), in run order — see `charge_run_fees`.
            let group: Vec<GroupedTx<'_>> = self.charge_run_fees(
                std::mem::take(run),
                module.as_ref(),
                &mut local_nonce,
                &mut broken_nonce,
                &mut dispatch_skipped,
            );
            if group.is_empty() {
                continue;
            }
            let results = self.dispatch_run(module.as_ref(), &group, &mut preverify_cache);
            self.record_group_outcomes(&group, results, &mut block_events);
        }
        if !dispatch_skipped.is_empty() {
            let mut outcomes =
                self.tx_outcomes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for (hash, reason) in dispatch_skipped {
                outcomes.record(hash, TxOutcome::Skipped { reason });
            }
        }
        // Publish all events from this block in one lock acquisition.
        self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend(block_events);

        // end_block for all modules — same context as begin_block.
        // Module scheduled effects (liquidation sweeps, epoch work)
        // emit events that land in the block log AFTER every tx
        // event — same publish path, one extension.
        let end_block_events: Vec<Event> = self
            .modules
            .iter()
            .flatten()
            .flat_map(|module| module.end_block_ctx(block.height, &block.context))
            .collect();
        if !end_block_events.is_empty() {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(end_block_events);
        }

        // Attendance delivery, inside execute_block so journal
        // replay derives identical effects (see the trait doc).
        for module in self.modules.iter().flatten() {
            module.record_block_attendance(block.height, &block.signers);
        }

        // Compute the state root: ONE canonical commitment (C8) over
        // every module's canonical root plus the executed-nonce
        // root — the same definition `export_snapshot` /
        // `import_snapshot` use, so block, snapshot, and replay
        // roots always agree. `local_nonce` already holds the
        // post-block map (advanced as each tx passed continuity).
        let post_block_nonces: Vec<(primitives::Address, u64)> =
            local_nonce.iter().map(|(a, n)| (*a, *n)).collect();
        let nonce_root = compute_nonce_root(&post_block_nonces);
        let mut module_roots = Vec::new();
        for module in self.modules.iter().flatten() {
            module_roots.push(module.state_root());
        }

        // Push the fresh nonce anchors into the mempool — the live
        // update path the pool's `executed_nonces` anchoring was
        // built for. `refresh_anchors` also prunes pooled entries
        // whose nonce this block consumed (a losing same-nonce
        // candidate can never execute), so stale entries don't
        // linger until a size-cap eviction reaches them.
        self.mempool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .refresh_anchors(&local_nonce);

        // H4/H5: persist the updated nonce map. `local_nonce` was
        // advanced as each tx passed the continuity check. We write
        // it back in a single lock acquisition so the next block's
        // `execute_block` and the mempool's `ingest_tx` see the
        // updated state.
        *self.executed_nonce.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            local_nonce;

        canonical_state_root(module_roots, nonce_root)
    }

    /// Record the finalized outcome for every tx in one module
    /// group and append the executed txs' events to `block_events`.
    /// `results` is index-aligned with `group` (every
    /// `handle_batch*` contract returns one result per input tx):
    /// `Ok` carries the module's events — which may still report
    /// per-leg failures for batch ops; `Err` means the module
    /// rejected the whole tx (fee charged, nonce consumed — a
    /// revert, not a skip). One lock acquisition per group keeps
    /// the outcome store off the per-tx path.
    fn record_group_outcomes(
        &self,
        group: &[GroupedTx<'_>],
        results: Vec<Result<Vec<Event>, ExecError>>,
        block_events: &mut Vec<Event>,
    ) {
        let mut outcomes =
            self.tx_outcomes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for ((_ctx, _payload, tx_hash), result) in group.iter().zip(results) {
            let outcome = match result {
                Ok(events) => {
                    block_events.extend(events.iter().cloned());
                    TxOutcome::Executed { events, error: None }
                }
                Err(e) => TxOutcome::Executed { events: Vec::new(), error: Some(format!("{e:?}")) },
            };
            outcomes.record(*tx_hash, outcome);
        }
    }
}

/// A batch-ingest tx that passed validation and awaits pool
/// submission. Carries the metadata the pool-admission pass needs
/// that the tx bytes alone can't recover.
struct AcceptedTx {
    /// The tx's index in the *caller's* batch — the `results` slot
    /// a pool rejection must be written back to. `accepted_txs` is
    /// filtered, so its own position cannot stand in for this.
    result_idx: usize,
    /// The preverified `(tx_hash, sender)` pair to cache once the
    /// pool admits the tx — `None` for admitted-unsigned txs with
    /// no authenticated sender.
    cacheable: Option<(Hash, [u8; 20])>,
    /// The transaction itself.
    tx: TxBytes,
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
        // Nonce u64::MAX is reserved: executing it would wrap the
        // next-expected counter (MAX + 1 → 0) and reopen the sender's
        // entire nonce range to replay. Rejecting it at admission
        // keeps `expected + 1` in `group_block_txs` overflow-free —
        // no honest account can exhaust 2^64 − 1 nonces anyway.
        if ctx.nonce == u64::MAX {
            return MempoolAck::Rejected { reason: "nonce `u64::MAX` is reserved".to_string() };
        }
        let Some(module_id) = parse_module_id(bytes) else {
            return MempoolAck::Rejected { reason: "malformed: no module ID".to_string() };
        };
        let Some(module) = self.modules[module_id as usize].as_ref() else {
            return MempoolAck::Rejected { reason: format!("unknown module {module_id}") };
        };
        // Envelope authentication: for modules that don't recover the
        // sender inside their own payload (everything but the EVM),
        // a signed envelope's secp256k1 signature must recover to the
        // declared sender — otherwise `ctx.sender` is just a claim.
        // Unsigned txs are admitted or rejected per
        // `unsigned_tx_policy`. The returned bool records whether a
        // signature actually verified — it decides what the preverify
        // cache may claim below.
        let envelope_verified =
            match self.check_envelope_auth(bytes, &ctx, module_id, module.as_ref(), None) {
                Ok(v) => v,
                Err(reason) => return MempoolAck::Rejected { reason: reason.to_string() },
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
        // A cache entry asserts "a trustworthy sender exists for this
        // exact tx hash" — `check_envelope_auth` treats a hit as
        // already-verified, and `execute_block` routes all-cached
        // groups through the preverified path. We therefore only
        // cache a sender that was actually authenticated:
        //
        // - a non-zero sender from `preverify_batch` means the module
        //   verified the payload itself (EVM signature recovery);
        // - otherwise, if the envelope signature verified, `ctx.sender`
        //   is the authenticated sender — cache it so the entry is
        //   honest rather than a zero placeholder;
        // - an admitted-unsigned tx with a zero placeholder sender
        //   has nothing verified to cache — skipping it keeps
        //   `all_cached` false, so the group takes the plain
        //   `handle_batch` path (correct per-tx contexts).
        //
        // `msgs` must outlive `preverify_result` — the returned
        // `PreverifiedTx` borrows the payload slice.
        let msgs = [payload];
        let preverify_result = module.preverify_batch(&msgs);
        // Compute the cacheable entry now but insert it only if the
        // bounded intake accepts the tx below — a cache populated
        // ahead of admission grew on *rejected* submissions (an
        // intake-full flood filled it with senders for txs the pool
        // never held), the one intake-side map that wasn't bounded
        // by any capacity check. The hash is taken now because `tx`
        // moves into the channel below.
        let cacheable = preverify_result[0]
            .as_ref()
            .ok()
            .and_then(|preverified| {
                if preverified.sender != [0u8; 20] {
                    Some(preverified.sender)
                } else if envelope_verified {
                    Some(ctx.sender.0)
                } else {
                    None
                }
            })
            .map(|sender| {
                (crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, bytes), sender)
            });

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
            Ok(()) => {
                if let Some((tx_hash, sender)) = cacheable {
                    // Only the sender is cached — the payload is
                    // re-borrowed from the block's tx at execution
                    // time.
                    self.preverify_cache
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(tx_hash, sender);
                }
                MempoolAck::Accepted
            }
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
        // ones for batch submission to the mempool. Each entry
        // carries its index into `results` (the accepted vec is
        // filtered — position `i` here is not position `i` in the
        // caller's batch) and an optional preverified
        // `(tx_hash, sender)` that is cached only if the pool
        // accepts the tx.
        let mut accepted_txs: Vec<AcceptedTx> = Vec::with_capacity(txs.len());
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
            // Same reserved-nonce rule as `ingest_tx`.
            if ctx.nonce == u64::MAX {
                results.push(MempoolAck::Rejected {
                    reason: "nonce `u64::MAX` is reserved".to_string(),
                });
                continue;
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
            // Envelope authentication — same rules as `ingest_tx`.
            // The bool records whether a signature verified, which
            // decides what the preverify cache may claim below.
            let envelope_verified =
                match self.check_envelope_auth(bytes, &ctx, module_id, module.as_ref(), None) {
                    Ok(v) => v,
                    Err(reason) => {
                        results.push(MempoolAck::Rejected { reason: reason.to_string() });
                        continue;
                    }
                };
            let payload = module_payload(bytes);
            if let Err(e) = module.validate(&ctx, payload) {
                results.push(MempoolAck::Rejected { reason: format!("validate: {e:?}") });
                continue;
            }
            // Pre-recover the sender at ingestion time. Only cache a
            // sender that was actually authenticated — the module's
            // own recovery (non-zero) or the envelope-verified
            // `ctx.sender`. A zero placeholder on an
            // admitted-unsigned tx is skipped so `all_cached` stays
            // false and the group keeps the plain `handle_batch`
            // path. `msgs` must outlive `preverify_result` — the
            // returned `PreverifiedTx` borrows the payload slice.
            // The entry is *computed* here but cached only after the
            // pool accepts the tx below — caching ahead of bounded
            // admission let rejected submissions grow the map past
            // every capacity check.
            let msgs = [payload];
            let preverify_result = module.preverify_batch(&msgs);
            let cacheable = preverify_result[0]
                .as_ref()
                .ok()
                .and_then(|preverified| {
                    if preverified.sender != [0u8; 20] {
                        Some(preverified.sender)
                    } else if envelope_verified {
                        Some(ctx.sender.0)
                    } else {
                        None
                    }
                })
                .map(|sender| {
                    (
                        crypto::hash::Hasher::hash_one(
                            crypto::hash::Domain::Transaction,
                            tx.as_bytes(),
                        ),
                        sender,
                    )
                });
            accepted_txs.push(AcceptedTx { result_idx: results.len(), cacheable, tx });
            results.push(MempoolAck::Accepted);
        }
        // Batch-submit all accepted txs to the mempool in one lock
        // acquisition.
        if !accepted_txs.is_empty() {
            let mut mempool =
                self.mempool.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            // `result_idx` is the tx's index in the *caller's*
            // batch — `accepted_txs` is filtered, so a positional
            // `enumerate()` would write pool rejections into the
            // wrong result slots (acknowledging a rejected tx as
            // Accepted and re-rejecting an unrelated one — the bug
            // this field fixes).
            for AcceptedTx { result_idx, cacheable, tx } in accepted_txs {
                match mempool.submit(tx) {
                    Ok(()) => {
                        // Admitted — now the preverified sender may
                        // be cached.
                        if let Some((tx_hash, sender)) = cacheable {
                            self.preverify_cache
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .insert(tx_hash, sender);
                        }
                    }
                    Err(e) => {
                        // Overwrite the Accepted result with the rejection.
                        results[result_idx] = MempoolAck::Rejected { reason: format!("{e:?}") };
                    }
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
        // Coordinated halt: once the next height is past the
        // scheduled halt, propose empty blocks only — the chain
        // keeps committing (deterministic liveness) while state
        // stays frozen at the halt height.
        // `current + 1 > halt` ⟺ `current >= halt`, written without
        // the addition so a height of u64::MAX can't wrap.
        let past_halt = self.halt_height().is_some_and(|halt| self.current_height() >= halt);
        // Select txs from the mempool by fee priority.
        let candidates = if past_halt {
            Vec::new()
        } else {
            self.mempool
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .select(budget.max_bytes)
        };
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

    /// `prepare_proposal` drains the intake ring into the pool before
    /// selecting, so by the time consensus calls this the pool depth
    /// already reflects every ingested tx — including ones `select`
    /// skipped for a nonce gap (the case the liveness gate exists for).
    fn has_queued_txs(&self) -> bool {
        self.mempool_len() > 0
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
        // they require state access or per-tx cryptography and are
        // enforced elsewhere: envelope signatures are verified at
        // `ingest_tx`/`ingest_tx_batch` (rejected) and `execute_block`
        // (skipped), so a bad-sig tx in an accepted proposal is a
        // deterministically-skipped no-op rather than a consensus
        // failure.
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
                // `prev + 1` must not wrap: a previous nonce of
                // u64::MAX has no valid successor — `checked_add`
                // yields `None`, which falls through to `_` and
                // rejects the tx (the match arm ordering makes the
                // non-contiguous case the failure path).
                Some(&prev) if prev.checked_add(1).is_none_or(|next| ctx.nonce != next) => {
                    return Verdict::Reject {
                        reason: format!(
                            "nonce gap/reorder: sender {:?} expected {} got {}",
                            ctx.sender,
                            prev.wrapping_add(1),
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
            // u64::MAX is a reserved nonce (see `group_block_txs`):
            // a block containing one is invalid.
            if ctx.nonce == u64::MAX {
                return Verdict::Reject { reason: "nonce `u64::MAX` is reserved".to_string() };
            }
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
            // Static malformed check: an envelope signature on a
            // self-authenticating module (EVM) is meaningless — the
            // flag shifts the payload offset, so the module's own
            // payload would be corrupted. This check is state-free
            // (module registration and the flag bit only), unlike
            // signature verification which is intentionally left to
            // `ingest_tx`/`execute_block` for cost reasons.
            if is_signed_envelope(bytes) && module.authenticates_sender() {
                return Verdict::Reject {
                    reason: "envelope signature on self-authenticating module".to_string(),
                };
            }
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
        // Remove the committed txs from the mempool at finality.
        // `select` is a peek — pooled entries outlive proposals — so
        // this is the single point where inclusion becomes permanent
        // and the pool releases custody. Doing it here (rather than
        // inside `execute_block`) also covers the async lane: a
        // committed tx can never be re-proposed by a `prepare` that
        // runs while the worker is still draining the backlog.
        self.mempool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove_committed(&block.txs);
        if let Some(tx) = self.exec_lane_tx.get() {
            // Async execution lane: `finalized` and the proposal
            // height advance now — they record *ordering* finality,
            // which consensus already settled — while `state_roots`
            // is written by the worker (or the inline backlog drain
            // below) when execution lands. `finalized` is inserted
            // BEFORE the send so the backlog drain can see this
            // block too.
            self.insert_finalized(block.height.value(), block.clone());
            *self.next_proposal_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                block.height.value().saturating_add(1); // M2 fix
            let lane_dead = {
                let (lock, cv) = &*self.exec_sync;
                let mut s = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                s.enqueued = Some(block.height.value());
                cv.notify_all();
                s.lane_dead
            };
            if lane_dead || tx.send(block.clone()).is_err() {
                // The lane can never execute this block — drive
                // every committed-but-unexecuted height inline.
                // Executing only THIS block (the old behavior) left
                // the height the worker died on permanently
                // rootless: a hole no later commit can fill,
                // stalling every exec-cert that references it.
                self.execute_committed_backlog();
            }
        } else {
            // Synchronous execution (default): fail closed on a
            // partially applied block BEFORE executing, exactly as
            // the backlog drain does — a `Some(h)` marker with no
            // recorded root means a previous `execute_block` panicked
            // mid-mutation, and replaying over surviving writes would
            // double-apply fees/nonces/module effects.
            let poisoned = {
                let (lock, _cv) = &*self.exec_sync;
                lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).in_flight.filter(
                    |h| {
                        !self
                            .state_roots
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .contains_key(h)
                    },
                )
            };
            if let Some(h) = poisoned {
                panic!(
                    "executor: synchronous execution of committed block {h} panicked \
                     mid-mutation; the block may be partially applied (fees/nonces/module \
                     state already mutated) and cannot be safely replayed in-process — \
                     halting; restart to recover from durable state"
                );
            }
            // Mark the height in-flight around `execute_block` exactly
            // as the backlog drain does: if the panic propagates, the
            // marker stays set and the NEXT `finalize_block` meets the
            // fail-closed check above instead of silently replaying.
            {
                let (lock, _cv) = &*self.exec_sync;
                lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).in_flight =
                    Some(block.height.value());
            }
            let root = self.execute_block(block);
            self.state_roots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert_retained(block.height.value(), root, self.history_retention);
            {
                let (lock, _cv) = &*self.exec_sync;
                lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).in_flight = None;
            }
            // Keep the watermark honest in synchronous mode too:
            // the block was just executed, and `insert_finalized`
            // evicts only at-or-below it.
            {
                let (lock, _cv) = &*self.exec_sync;
                let mut s = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                s.enqueued = Some(block.height.value());
                s.executed = Some(block.height.value());
            }
            self.insert_finalized(block.height.value(), block.clone());
            *self.next_proposal_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                block.height.value().saturating_add(1); // M2 fix
        }
        if let Some(recorder) = &self.recorder {
            recorder.record("finalize_block", start.elapsed());
        }
        CommitAck { height: block.height }
    }

    fn attest_state(&self, height: Height) -> Option<StateAttestation> {
        let start = std::time::Instant::now();
        // Async lane: wait only while the height is owed to a LIVE
        // worker. A height never enqueued has no execution coming,
        // and a dead lane can never advance `executed` — both return
        // `None` ("not executed") rather than blocking forever. The
        // `lane_dead` check is what makes a worker panic propagate
        // instead of hanging every attester.
        if self.exec_lane_tx.get().is_some() {
            let (lock, cv) = &*self.exec_sync;
            let mut s = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            while !s.lane_dead
                && s.enqueued.is_some_and(|e| height.value() <= e)
                && s.executed.is_none_or(|x| x < height.value())
            {
                s = cv.wait(s).unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
        let root = self
            .state_roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&height.value())
            .copied();
        if let Some(recorder) = &self.recorder {
            recorder.record("attest_state", start.elapsed());
        }
        root.map(|root| StateAttestation { height, root })
    }

    fn attest_latest(&self) -> Option<StateAttestation> {
        // Deliberately does NOT flush pending execution: the vote
        // path calls this on every vote and cannot afford to wait
        // on the execution lane. A stale attestation certifies an
        // older height — never a wrong one. `None` before the first
        // execution: there is no attestation to make.
        self.state_roots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .next_back()
            .map(|(h, root)| StateAttestation { height: Height::new(*h), root: *root })
    }

    /// Drain both pending-transition queues as one atomic
    /// [`EpochChanges`] record — the consensus-facing half of the
    /// epoch protocol. The engine polls this each epoch-boundary
    /// pass; draining and rotating in the same pass keeps the
    /// module queues from re-reporting an enacted transition.
    fn take_epoch_changes(&self) -> types::EpochChanges {
        // One drain per queue — `take_pending_validator_changes`
        // clears the module queues, so a second call would report
        // empty and the removes would be lost.
        let val = self.take_pending_validator_changes();
        types::EpochChanges {
            key_changes: self.take_pending_key_changes(),
            adds: val.adds,
            removes: val.removes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::SequencerEngine;
    use ports::ConsensusEngine;
    use primitives::Address;

    /// Test executor with unsigned envelopes admitted — most tests
    /// submit unsigned envelopes built by `build_tx`. The policy is
    /// set explicitly at every construction so the `Reject` default
    /// exercised by production wiring stays honest.
    fn test_executor(max_mempool_entries: usize) -> Executor {
        Executor::new(max_mempool_entries).with_unsigned_tx_policy(UnsignedTxPolicy::Allow)
    }

    /// [`test_executor`] with explicit sizing — same reasoning.
    fn test_executor_with_config(mempool: usize, threshold: usize) -> Executor {
        Executor::with_config(mempool, threshold).with_unsigned_tx_policy(UnsignedTxPolicy::Allow)
    }

    /// A trivial test module that counts messages.
    struct CounterModule {
        /// Dispatch id — parametrized so snapshot tests can register
        /// two independent counters.
        id: u8,
        /// The snapshot-entry key this counter's blob lives under.
        key: Hash,
        count: Mutex<u64>,
    }

    impl CounterModule {
        fn new() -> Self {
            Self { id: 1, key: Hash([0xEE; 32]), count: Mutex::new(0) }
        }

        /// A second counter for multi-module strict-import tests —
        /// distinct dispatch id and snapshot key.
        fn other() -> Self {
            Self { id: 2, key: Hash([0xEF; 32]), count: Mutex::new(0) }
        }
    }

    impl Module for CounterModule {
        fn name(&self) -> &'static str {
            "counter"
        }
        fn id(&self) -> u8 {
            self.id
        }

        fn begin_block(&self, _height: Height) {}

        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            let mut c = self.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            *c += 1;
            Ok(vec![Event { module: "counter", kind: "increment", data: vec![] }])
        }

        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }

        fn state_root(&self) -> Hash {
            let c = *self.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let byte = u8::try_from(c).unwrap_or(0xff);
            Hash([byte; 32])
        }

        // The counter is committed state: export/import/inspect it
        // so strict snapshot verification exercises the real path.
        fn export_state(&self) -> Option<storage::Snapshot> {
            let c = *self.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            Some(storage::Snapshot {
                height: 0,
                entries: vec![(self.key, c.to_le_bytes().to_vec())],
            })
        }

        fn inspect_state(
            &self,
            snapshot: &storage::Snapshot,
        ) -> Result<Hash, storage::SnapshotError> {
            let c = self.decode_count(snapshot)?;
            let byte = u8::try_from(c).unwrap_or(0xff);
            Ok(Hash([byte; 32]))
        }

        fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
            let c = self.decode_count(snapshot)?;
            *self.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = c;
            Ok(())
        }
    }

    impl CounterModule {
        /// The snapshot payload is exactly one entry under our key:
        /// the counter as `u64` LE.
        fn decode_count(
            &self,
            snapshot: &storage::Snapshot,
        ) -> Result<u64, storage::SnapshotError> {
            if snapshot.entries.len() != 1 || snapshot.entries[0].0 != self.key {
                return Err(storage::SnapshotError::Malformed);
            }
            let bytes: [u8; 8] = snapshot.entries[0]
                .1
                .as_slice()
                .try_into()
                .map_err(|_| storage::SnapshotError::Malformed)?;
            Ok(u64::from_le_bytes(bytes))
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
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Submit a tx to the executor's mempool (via AppInterface).
        let tx = make_tx(1, &[42]);
        executor.ingest_tx(tx);

        // Prepare a proposal.
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 1);

        // Finalize the block.
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        let ack = executor.finalize_block(&block);
        assert_eq!(ack.height, Height::new(0));

        // The state root should be non-zero (the counter incremented).
        let attestation = executor.attest_state(Height::new(0)).expect("executed");
        assert_ne!(attestation.root, Hash::ZERO);
    }

    #[test]
    fn snapshot_root_matches_block_root() {
        // C8: ONE canonical state-root definition. The root stored
        // at finalize must equal the snapshot's recomputed root —
        // both are `H(module_roots || nonce_root)`. Before the fix
        // `execute_block` hashed module roots alone while
        // `export_snapshot` appended the nonce root: two different
        // commitments for the same state.
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        executor.ingest_tx(make_tx(1, &[42]));
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        executor.finalize_block(&block);
        let block_root = executor.state_root_at(0);
        let snapshot = executor.export_snapshot();
        assert_eq!(
            snapshot.state_root, block_root,
            "snapshot and block must share one canonical root definition"
        );
    }

    #[test]
    fn executor_with_sequencer_engine_end_to_end() {
        // Wire the executor behind a SequencerEngine and run the full
        // OAI flow: submit → propose → finalize → attest.
        let mut executor = test_executor(100);
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
        let attestation = app.attest_state(Height::new(0)).expect("executed");
        assert_ne!(attestation.root, Hash::ZERO, "state root should be non-zero after execution");
    }

    #[test]
    fn executor_skips_unknown_module() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Submit a tx for an unregistered module (ID 99).
        let tx = make_tx(99, &[1]);
        executor.ingest_tx(tx);

        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        executor.finalize_block(&block);

        // The unknown module's tx should be silently skipped.
        // The counter module should not have been called.
        let attestation = executor.attest_state(Height::new(0)).expect("executed");
        // State root is the hash of the counter's state root (0).
        assert_ne!(attestation.root, Hash::ZERO, "state root should reflect counter=0");
    }

    #[test]
    fn executor_multiple_blocks_state_advances() {
        let mut executor = test_executor(100);
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
            let block = FinalizedBlock {
                context: types::BlockContext::default(),
                height: Height::new(h),
                txs: proposal.txs,
                signers: Vec::new(),
            };
            executor.finalize_block(&block);
        }

        // The counter should have been called 3 times.
        let count = *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(count, 3, "counter should have been incremented 3 times");

        // Each block should have a different state root.
        let root0 = executor.attest_state(Height::new(0)).expect("executed").root;
        let root1 = executor.attest_state(Height::new(1)).expect("executed").root;
        let root2 = executor.attest_state(Height::new(2)).expect("executed").root;
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
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
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
    /// *target* module, whose default no-op meant only self-funded
    /// txs ever paid a fee.
    #[test]
    fn fee_module_charges_other_module_txs() {
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        let collector = Arc::new(FeeCollector { charged: Mutex::new(0) });
        executor.register_module(counter.clone());
        executor.register_module(collector.clone());
        executor.set_fee_module(9);

        executor.ingest_tx(make_tx_with_fee(1, &[1], 0, 50));
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        });

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
        let mut executor = test_executor(100).with_min_fee(50);
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
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        });

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
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let tx = make_tx(1, &[42]);
        let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
        assert!(matches!(executor.process_proposal(&proposal), Verdict::Accept));
    }

    #[test]
    fn process_proposal_rejects_too_short_tx() {
        let mut executor = test_executor(100);
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
        let mut executor = test_executor(100);
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
        let mut executor = test_executor(100);
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
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
        fn preverify_batch<'a>(
            &self,
            msgs: &'a [&'a [u8]],
        ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
            // Return a non-zero sender — a zero sender is the
            // "no pre-verification" placeholder and is no longer
            // cached by `ingest_tx`.
            msgs.iter().map(|raw| Ok(PreverifiedTx { raw, sender: [0x42; 20] })).collect()
        }
        fn handle_batch_preverified(
            &self,
            _ctxs: &[TxContext],
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
        let mut executor = test_executor(100);
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
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
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

    /// A test module with a *real* `preverify_batch` (returns a
    /// non-zero recovered sender, like the EVM's signature recovery)
    /// that deliberately does NOT override `handle_batch_preverified`.
    /// The default impl is what executes — this is the shape every
    /// native module has once it gains payload-level pre-verification.
    /// `handle` records the `TxContext` each tx ran under so the test
    /// can prove per-tx identity propagation.
    struct CtxRecordingModule {
        seen: Mutex<Vec<TxContext>>,
    }

    impl CtxRecordingModule {
        fn new() -> Self {
            Self { seen: Mutex::new(Vec::new()) }
        }
    }

    impl Module for CtxRecordingModule {
        fn name(&self) -> &'static str {
            "ctx-recorder"
        }
        fn id(&self) -> u8 {
            7
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(*ctx);
            Ok(vec![])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
        fn preverify_batch<'a>(
            &self,
            msgs: &'a [&'a [u8]],
        ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
            // A non-zero sender marks "the module verified this
            // payload" — the executor caches it so `execute_block`
            // takes the preverified path.
            msgs.iter().map(|raw| Ok(PreverifiedTx { raw, sender: [0x42; 20] })).collect()
        }
    }

    /// Records every `(height, BlockContext)` the executor delivers —
    /// the oracle proving the consensus execution context crosses the
    /// application boundary verbatim.
    struct BlockCtxRecorder {
        seen: Mutex<Vec<(Height, types::BlockContext)>>,
    }

    impl BlockCtxRecorder {
        fn new() -> Self {
            Self { seen: Mutex::new(Vec::new()) }
        }
    }

    impl Module for BlockCtxRecorder {
        fn name(&self) -> &'static str {
            "block-ctx-recorder"
        }
        fn id(&self) -> u8 {
            6
        }
        fn begin_block(&self, _height: Height) {}
        fn begin_block_ctx(&self, height: Height, ctx: &types::BlockContext) {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((height, *ctx));
        }
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            Ok(vec![])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
    }

    /// The execution context committed on the `FinalizedBlock` must
    /// reach modules verbatim — timestamp, beneficiary, and gas
    /// limit all arrive exactly as consensus produced them.
    #[test]
    fn execute_block_delivers_consensus_context() {
        let mut executor = test_executor(100);
        let recorder = Arc::new(BlockCtxRecorder::new());
        executor.register_module(recorder.clone());

        let ctx = types::BlockContext {
            timestamp_ms: 1_700_000_000_123,
            beneficiary: Address([0x77; 20]),
            gas_limit: 42_000,
        };
        let block =
            FinalizedBlock { height: Height::new(3), txs: vec![], signers: vec![], context: ctx };
        executor.finalize_block(&block);

        let seen = recorder.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(seen.as_slice(), &[(Height::new(3), ctx)]);
    }

    /// Regression test for the cached-execution identity bug: the
    /// preverified path must execute each tx under **its own**
    /// `TxContext` — sender, nonce, and fee — not the first tx's.
    /// Before the fix, `execute_block` passed `group[0].0` and the
    /// default `handle_batch_preverified` replicated it across every
    /// tx, so all txs in a cached group ran as the first sender.
    /// Because every validator with the same cache population made
    /// the same mistake the state roots still agreed — the bug was
    /// silent — but a validator whose cache missed (never ingested
    /// the tx, e.g. received it only via proposal) executed
    /// correctly and *diverged*.
    #[test]
    fn preverified_path_preserves_per_tx_context() {
        let mut executor = test_executor(100);
        let recorder = Arc::new(CtxRecordingModule::new());
        executor.register_module(recorder.clone());

        // Two txs from different senders — both nonce 0 is legal
        // because nonces are per-sender.
        let tx_a = make_tx_with_fee_and_sender(7, &[1], 0, 100, 0xA1);
        let tx_b = make_tx_with_fee_and_sender(7, &[2], 0, 100, 0xB2);
        executor.ingest_tx(tx_a);
        executor.ingest_tx(tx_b);

        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 2, "both txs should be in the proposal");
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        executor.finalize_block(&block);

        let seen = recorder.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(seen.len(), 2, "both txs should have executed");
        // The mempool may reorder txs, so don't assume group order —
        // the property is that *each* tx ran under its own context:
        // both senders must appear exactly once.
        let mut senders: Vec<primitives::Address> = seen.iter().map(|c| c.sender).collect();
        senders.sort();
        assert_eq!(
            senders,
            vec![Address([0xA1; 20]), Address([0xB2; 20])],
            "each tx must execute under its own sender, not the group leader's"
        );
    }

    // ---- H4 fix: mempool replay protection ----

    /// H4: After a tx with nonce N is executed, re-submitting the
    /// same tx (or any tx with nonce < N+1) must be rejected by
    /// `ingest_tx`. Without this, a tx removed from the mempool
    /// after block selection can be re-submitted and re-executed.
    #[test]
    fn h4_ingest_rejects_stale_nonce_after_execution() {
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Submit and execute nonce 0.
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        executor.ingest_tx(tx0);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
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
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Submit and execute nonce 0.
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        executor.ingest_tx(tx0);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
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
        let mut executor = test_executor(100);
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
        let mut executor = test_executor(100);
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
        let mut executor = test_executor(100);
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
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Execute nonce 0 in block 0.
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        executor.ingest_tx(tx0);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block0 = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        executor.finalize_block(&block0);
        assert_eq!(*counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 1);

        // Try to execute nonce 0 again in block 1 — must be skipped.
        let tx0_again = make_tx_with_nonce(1, &[0], 0);
        let block1 = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: vec![tx0_again],
            signers: Vec::new(),
        };
        executor.finalize_block(&block1);

        // Counter should still be 1 — the stale tx was skipped.
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "stale nonce tx must be skipped during execution"
        );
    }

    /// Regression: nonce `u64::MAX` is reserved. Executing it would
    /// wrap the sender's next-expected counter (`MAX + 1` → 0) and
    /// reopen the whole nonce range to replay. The tx must be
    /// rejected at admission, skipped at execution, and rejected at
    /// proposal validation.
    #[test]
    fn nonce_u64_max_is_reserved() {
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Admission: nonce MAX is rejected outright.
        let tx_max = make_tx_with_nonce(1, &[9], u64::MAX);
        assert!(
            matches!(executor.ingest_tx(tx_max.clone()), MempoolAck::Rejected { .. }),
            "nonce u64::MAX must be rejected at admission"
        );

        // Execution: a MAX-nonce tx smuggled into a block is skipped
        // — the counter does not move and the nonce map is not
        // poisoned.
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![tx_max],
            signers: Vec::new(),
        };
        executor.finalize_block(&block);
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            0,
            "reserved nonce must not execute"
        );

        // The nonce map must still expect 0 — a subsequent nonce-0 tx
        // executes normally (no wrap-induced replay window).
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        let block1 = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: vec![tx0],
            signers: Vec::new(),
        };
        executor.finalize_block(&block1);
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "nonce 0 must still execute after a smuggled MAX nonce"
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
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Execute nonce 0 in block 0.
        let tx0 = make_tx_with_nonce(1, &[0], 0);
        executor.ingest_tx(tx0);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block0 = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        };
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
    /// An EVM transaction must not be able to advance *another*
    /// account's executor nonce.
    ///
    /// The EVM recovers its sender and nonce from the signed RLP, so a
    /// caller can wrap their own valid payload in any envelope. Before
    /// this fix the executor drove `executed_nonce` from the envelope's
    /// declared `(sender, nonce)`, so such an envelope advanced the
    /// victim's counter without the victim's authorization —
    /// desynchronizing ordinary Ethereum submissions from the real EVM
    /// account nonce. The envelope must not touch account-indexed nonce
    /// state for a module that authenticates itself.
    #[test]
    fn self_authenticating_module_cannot_advance_another_accounts_nonce() {
        const VICTIM: u8 = 0x11;
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(SelfAuthModule));

        // The attacker's payload, wrapped in the victim's envelope at
        // the victim's nonce. Module 3 is `SelfAuthModule` (see the
        // signed-transaction section below), which reports
        // `authenticates_sender() == true` exactly like the EVM.
        let tx = make_tx_with_fee_and_sender(3, &[0xAA], 0, 0, VICTIM);
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![tx],
            signers: vec![],
        });

        let snap = executor.export_snapshot();
        assert!(
            !snap.executed_nonces.iter().any(|(a, _)| *a == Address([VICTIM; 20])),
            "a self-authenticating module must not advance the envelope sender's nonce"
        );
    }

    /// Control: a module that authenticates from the envelope *does* own
    /// the nonce gate, so its counter still advances normally.
    #[test]
    fn envelope_authenticating_module_still_advances_nonce() {
        const SENDER: u8 = 0x22;
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));

        let tx = make_tx_with_fee_and_sender(1, &[0xAA], 0, 0, SENDER);
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![tx],
            signers: vec![],
        });

        let snap = executor.export_snapshot();
        assert_eq!(
            snap.executed_nonces.iter().find(|(a, _)| *a == Address([SENDER; 20])).map(|(_, n)| *n),
            Some(1),
            "an envelope-authenticating module must advance its sender's nonce"
        );
    }

    #[test]
    fn h4h5_snapshot_preserves_executed_nonce() {
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Execute nonce 0 and nonce 1.
        for n in 0..2u64 {
            let tx = make_tx_with_nonce(1, &[u8::try_from(n).unwrap_or(0xff)], n);
            executor.ingest_tx(tx);
            let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
            let proposal = executor.prepare_proposal(&budget);
            let block = FinalizedBlock {
                context: types::BlockContext::default(),
                height: Height::new(n),
                txs: proposal.txs,
                signers: Vec::new(),
            };
            executor.finalize_block(&block);
        }

        // Export snapshot.
        let snapshot = executor.export_snapshot();
        assert_eq!(snapshot.executed_nonces.len(), 1, "one sender in the nonce map");
        assert_eq!(snapshot.executed_nonces[0].1, 2, "next expected nonce is 2");

        // Import into a fresh executor.
        let mut executor2 = test_executor(100);
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
            test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2000);
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
            test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(10_000);
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
            test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2000);
        executor.register_module(Arc::new(CounterModule::new()));

        // Two txs, each costing ~1001 gas. The first fits (cumulative
        // 1001 ≤ 2000), the second would push to 2002 > 2000.
        let tx1 = make_tx(1, &[0]);
        let tx2 = make_tx_with_nonce(1, &[1], 1);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![tx1, tx2],
            signers: Vec::new(),
        };
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
            test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2500);
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

    // ---- EIP-712 signed native transactions (item 16) ----

    /// A module that self-authenticates (like the EVM): its payload
    /// carries its own signature, so an envelope signature on it is
    /// malformed by definition.
    struct SelfAuthModule;

    impl Module for SelfAuthModule {
        fn name(&self) -> &'static str {
            "selfauth"
        }
        fn id(&self) -> u8 {
            3
        }
        fn authenticates_sender(&self) -> bool {
            true
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            Ok(vec![])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
    }

    /// Build a signed tx to the counter module with a fresh keypair.
    /// Returns `(tx_bytes, sender)`.
    fn signed_counter_tx(chain_id: u64, nonce: u64, payload: &[u8]) -> (TxBytes, Address) {
        let (privkey, sender) = crypto::secp::generate_keypair_for_test();
        let tx = mempool::build_signed_tx(&privkey, chain_id, nonce, 0, 1, payload)
            .expect("valid key must sign");
        (tx, sender)
    }

    /// The signed-envelope codec: `module_id` masks the flag bit and
    /// the payload excludes the 65-byte signature.
    #[test]
    fn signed_envelope_parses_correctly() {
        let (tx, sender) = signed_counter_tx(1, 5, b"my-payload");
        let bytes = tx.as_bytes();
        assert!(is_signed_envelope(bytes));
        assert_eq!(parse_module_id(bytes), Some(1));
        assert_eq!(envelope_signature(bytes).map(<[u8]>::len), Some(65));
        assert_eq!(module_payload(bytes), b"my-payload");
        let ctx = parse_tx_context(bytes).unwrap();
        assert_eq!(ctx.sender, sender);
        assert_eq!(ctx.nonce, 5);
    }

    /// A properly signed native tx is admitted and executes.
    #[test]
    fn signed_tx_executes_end_to_end() {
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        let (tx, _sender) = signed_counter_tx(1, 0, b"inc");
        assert!(matches!(executor.ingest_tx(tx), MempoolAck::Accepted));
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 1);
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        });
        assert_eq!(*counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 1);
    }

    /// A corrupted signature is rejected at mempool admission.
    #[test]
    fn bad_signature_rejected_at_ingest() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));

        let (tx, _sender) = signed_counter_tx(1, 0, b"inc");
        let mut bytes = tx.as_bytes().to_vec();
        bytes[ENVELOPE_SIG_OFFSET] ^= 0xFF; // corrupt first byte of r
        let ack = executor.ingest_tx(TxBytes::new(bytes));
        assert!(matches!(ack, MempoolAck::Rejected { .. }), "bad sig must be rejected");
    }

    /// A signature produced for chain 2 is rejected on chain 1 —
    /// the domain separator binds the chain ID.
    #[test]
    fn cross_chain_signature_rejected() {
        let mut executor = test_executor(100).with_chain_id(1);
        executor.register_module(Arc::new(CounterModule::new()));

        let (tx, _sender) = signed_counter_tx(2, 0, b"inc");
        assert!(matches!(executor.ingest_tx(tx), MempoolAck::Rejected { .. }));
    }

    /// A signed envelope whose declared sender was overwritten with
    /// a victim's address is rejected — the signature proves the
    /// signer's key, not the claimed field.
    #[test]
    fn forged_declared_sender_rejected() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));

        let victim = Address([0xEE; 20]);
        let (tx, _sender) = signed_counter_tx(1, 0, b"inc");
        let mut bytes = tx.as_bytes().to_vec();
        bytes[..20].copy_from_slice(&victim.0); // forge sender
        assert!(matches!(executor.ingest_tx(TxBytes::new(bytes)), MempoolAck::Rejected { .. }));
    }

    /// Under `UnsignedTxPolicy::Reject`, an unsigned native tx is
    /// rejected at admission — closing the unauthenticated-sender
    /// hole.
    #[test]
    fn unsigned_tx_rejected_when_required() {
        let mut executor = Executor::new(100).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
        executor.register_module(Arc::new(CounterModule::new()));

        let ack = executor.ingest_tx(make_tx(1, b"unsigned"));
        assert!(matches!(ack, MempoolAck::Rejected { .. }), "unsigned must be rejected");
    }

    /// Under `Reject`, an unsigned tx injected into a finalized block
    /// (bypassing this node's mempool — e.g. proposed by another
    /// validator) is skipped deterministically at execution.
    #[test]
    fn unsigned_tx_skipped_at_execution_when_required() {
        let mut executor = Executor::new(100).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![make_tx(1, b"unsigned")],
            signers: Vec::new(),
        });
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            0,
            "unsigned tx must not execute under Reject"
        );
    }

    /// A signed tx that never touched this node's mempool (foreign
    /// proposal) is verified inline at execution and executes.
    #[test]
    fn foreign_signed_tx_verified_at_execution() {
        let mut executor = Executor::new(100).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        let (tx, _sender) = signed_counter_tx(1, 0, b"inc");
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![tx],
            signers: Vec::new(),
        });
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "foreign signed tx must execute"
        );
    }

    /// A signed tx whose signature was computed over a different
    /// payload is skipped at execution — the signature binds the
    /// exact module message bytes.
    #[test]
    fn tampered_payload_rejected_at_execution() {
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        let (tx, _sender) = signed_counter_tx(1, 0, b"orig");
        let mut bytes = tx.as_bytes().to_vec();
        // Rewrite the payload (last 4 bytes).
        let n = bytes.len();
        bytes[n - 4..].copy_from_slice(b"evil");

        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![TxBytes::new(bytes)],
            signers: Vec::new(),
        });
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            0,
            "tampered payload must not execute"
        );
    }

    /// An envelope signature on a self-authenticating module is
    /// malformed — it would corrupt the module's own payload.
    #[test]
    fn flagged_self_auth_module_rejected() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(SelfAuthModule));

        // Flagged envelope routed to module 3 (SelfAuthModule).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&Address([1; 20]).0);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.push(3 | 0x80); // SIGNED_FLAG on a self-auth module
        bytes.extend_from_slice(&[0u8; 65]); // dummy sig
        bytes.extend_from_slice(b"payload");

        assert!(matches!(executor.ingest_tx(TxBytes::new(bytes)), MempoolAck::Rejected { .. }));
    }

    /// The same malformed tx is rejected statically at proposal
    /// validation — the flag on a self-auth module is a structural
    /// error, no crypto needed.
    #[test]
    fn proposal_rejects_flagged_self_auth() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(SelfAuthModule));

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&Address([1; 20]).0);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.push(3 | 0x80);
        bytes.extend_from_slice(&[0u8; 65]);
        bytes.extend_from_slice(b"payload");

        let proposal =
            Proposal { height: Height::new(0), txs: vec![TxBytes::new(bytes)], attestation: None };
        let verdict = executor.process_proposal(&proposal);
        assert!(matches!(verdict, Verdict::Reject { .. }), "flagged self-auth must reject");
    }

    /// A signed tx truncated inside the signature field is a clean
    /// rejection, not a panic.
    #[test]
    fn truncated_signed_envelope_rejected_cleanly() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));

        let (tx, _s) = signed_counter_tx(1, 0, b"inc");
        let bytes = tx.as_bytes().to_vec();
        let truncated = bytes[..ENVELOPE_SIG_OFFSET + 30].to_vec();
        assert!(matches!(executor.ingest_tx(TxBytes::new(truncated)), MempoolAck::Rejected { .. }));
    }

    /// Batch ingestion applies the same signature policy per tx.
    #[test]
    fn batch_ingest_enforces_signatures() {
        let mut executor = Executor::new(100).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
        executor.register_module(Arc::new(CounterModule::new()));

        let (signed, _s) = signed_counter_tx(1, 0, b"ok");
        let unsigned = make_tx(1, b"no-sig");
        let results = executor.ingest_tx_batch(vec![signed, unsigned]);
        assert!(matches!(results[0], MempoolAck::Accepted));
        assert!(matches!(results[1], MempoolAck::Rejected { .. }));
    }

    /// A module with a declared schema version, a migration spy, an
    /// optional halt schedule, and trivial KV export/import — the
    /// fixture for every upgrade-mechanism test.
    struct VersionedModule {
        /// Declared `state_version` — what this "binary" writes.
        version: u32,
        /// Heights at which `scheduled_halt_height` reports a halt.
        halt: Mutex<Option<u64>>,
        /// Records every `migrate(from)` argument — the assertion
        /// surface proving the executor drove the migration.
        migrate_calls: Mutex<Vec<u32>>,
        /// When set, `migrate` fails — exercises the fail-closed
        /// import path.
        migrate_fails: bool,
        /// Trivial in-memory KV so `export_state`/`import_state` have
        /// something to round-trip.
        kv: Mutex<Vec<(Hash, Vec<u8>)>>,
    }

    impl VersionedModule {
        fn new(version: u32) -> Arc<Self> {
            Arc::new(Self {
                version,
                halt: Mutex::new(None),
                migrate_calls: Mutex::new(Vec::new()),
                migrate_fails: false,
                kv: Mutex::new(Vec::new()),
            })
        }
    }

    impl Module for VersionedModule {
        fn name(&self) -> &'static str {
            "versioned"
        }
        fn id(&self) -> u8 {
            9
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            Ok(vec![Event { module: "versioned", kind: "noop", data: vec![] }])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            // A stable non-zero root — upgrade tests assert on
            // version plumbing, not root math.
            Hash([9u8; 32])
        }
        fn state_version(&self) -> u32 {
            self.version
        }
        fn migrate(&self, from: u32) -> Result<u32, ExecError> {
            self.migrate_calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(from);
            if self.migrate_fails {
                return Err(ExecError::ModuleRejected("boom".to_string()));
            }
            Ok(self.version)
        }
        fn scheduled_halt_height(&self) -> Option<u64> {
            *self.halt.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
        }
        fn export_state(&self) -> Option<storage::Snapshot> {
            Some(storage::Snapshot {
                height: 0,
                entries: self.kv.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone(),
            })
        }
        fn inspect_state(
            &self,
            snapshot: &storage::Snapshot,
        ) -> Result<Hash, storage::SnapshotError> {
            // `kv` is test scratch that `state_root` does not commit —
            // the claimed root is the constant. Still validate the
            // payload is well-formed (sorted, unique keys) so the
            // strict path exercises real checks.
            for w in snapshot.entries.windows(2) {
                if w[0].0 >= w[1].0 {
                    return Err(storage::SnapshotError::Malformed);
                }
            }
            Ok(self.state_root())
        }
        fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
            *self.kv.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                snapshot.entries.clone();
            Ok(())
        }
    }

    /// The snapshot must carry the format version and each module's
    /// declared schema version — the importer needs both to decide
    /// which `migrate(from)` calls to run.
    #[test]
    fn snapshot_export_records_format_and_module_versions() {
        let mut executor = test_executor(100);
        executor.register_module(VersionedModule::new(3) as Arc<dyn Module>);
        let snapshot = executor.export_snapshot();
        assert_eq!(snapshot.version, SNAPSHOT_FORMAT_VERSION);
        assert_eq!(snapshot.module_versions, vec![3]);
    }

    /// A v1 (pre-versioning) snapshot payload must still decode:
    /// the version tail is absent → version 1, empty `module_versions`.
    #[test]
    fn snapshot_v1_payload_decodes_as_version_one() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let snapshot = executor.export_snapshot();
        let mut buf = Vec::new();
        codec::Encode::encode(&snapshot, &mut buf);
        // Strip the v2 tail: u32 version + u32 count + N*u32 = 8 + 4 bytes.
        let v1_len = buf.len() - 8 - 4;
        let v1_bytes = &buf[..v1_len];
        let mut reader = codec::Reader::new(v1_bytes);
        let decoded = <ExecutorSnapshot as codec::Decode>::decode(&mut reader)
            .expect("v1 payload must decode");
        assert_eq!(decoded.version, 1, "absent tail reads as format v1");
        assert!(decoded.module_versions.is_empty());
        assert_eq!(decoded.height, snapshot.height);
    }

    /// A forged count prefix must not become an allocation size:
    /// `decode` reserves at most `remaining / min-wire-size` slots
    /// per section, so a `u32::MAX` count fails with a plain decode
    /// error instead of reserving ~hundreds of GiB and killing the
    /// importer. Covers every counted section: roots, state,
    /// nonces, versions.
    #[test]
    fn snapshot_decode_bounds_count_driven_allocations() {
        // An empty executor (no modules, no nonces) produces a
        // layout with fixed count offsets:
        //   [0..8)   height
        //   [8..40)  state_root
        //   [40..44) roots_count   = 0
        //   [44..48) state_count   = 0
        //   [48..52) nonces_count  = 0
        //   [52..84) nonce_root
        //   [84..88) version
        //   [88..92) versions_count = 0
        let executor = test_executor(100);
        let snapshot = executor.export_snapshot();
        assert!(snapshot.module_roots.is_empty() && snapshot.module_state.is_empty());
        let mut buf = Vec::new();
        codec::Encode::encode(&snapshot, &mut buf);
        assert_eq!(buf.len(), 92, "empty snapshot layout must be the fixed size asserted below");

        for offset in [40usize, 44, 48, 88] {
            let mut forged = buf.clone();
            forged[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            let mut reader = codec::Reader::new(&forged);
            assert!(
                <ExecutorSnapshot as codec::Decode>::decode(&mut reader).is_err(),
                "count field at offset {offset} inflated to u32::MAX must fail decode"
            );
        }
    }

    /// A snapshot from a newer binary must be refused — importing
    /// state it can't interpret would corrupt the validator.
    #[test]
    fn snapshot_newer_version_rejected() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let mut snapshot = executor.export_snapshot();
        snapshot.version = SNAPSHOT_FORMAT_VERSION + 1;
        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(CounterModule::new()));
        match executor2.import_snapshot(&snapshot) {
            Err(SnapshotImportError::UnsupportedVersion { snapshot, supported }) => {
                assert_eq!(snapshot, SNAPSHOT_FORMAT_VERSION + 1);
                assert_eq!(supported, SNAPSHOT_FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    /// A module whose snapshot version trails its declared version
    /// must get `migrate(from)` called with the recorded version.
    #[test]
    fn snapshot_import_runs_module_migration() {
        let mut executor = test_executor(100);
        executor.register_module(VersionedModule::new(1) as Arc<dyn Module>);
        let mut snapshot = executor.export_snapshot();
        // Forge an old-schema record: the importer declares v2 but
        // the snapshot's state was written at v1.
        snapshot.module_versions = vec![1];

        let module = VersionedModule::new(2);
        let spy = Arc::clone(&module);
        let mut executor2 = test_executor(100);
        executor2.register_module(module as Arc<dyn Module>);
        executor2.import_snapshot(&snapshot).expect("import + migrate must succeed");
        assert_eq!(
            *spy.migrate_calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            vec![1],
            "migrate must be called with the snapshot's recorded version"
        );
    }

    /// A failing migration must fail the whole import — a partially
    /// migrated state set is worse than no import at all.
    #[test]
    fn snapshot_import_fails_closed_on_migration_error() {
        let mut executor = test_executor(100);
        executor.register_module(VersionedModule::new(1) as Arc<dyn Module>);
        let mut snapshot = executor.export_snapshot();
        snapshot.module_versions = vec![1];

        let module = VersionedModule {
            version: 2,
            halt: Mutex::new(None),
            migrate_calls: Mutex::new(Vec::new()),
            migrate_fails: true,
            kv: Mutex::new(Vec::new()),
        };
        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(module) as Arc<dyn Module>);
        match executor2.import_snapshot(&snapshot) {
            Err(SnapshotImportError::MigrationFailed { module, from }) => {
                assert_eq!(module, "versioned");
                assert_eq!(from, 1);
            }
            other => panic!("expected MigrationFailed, got {other:?}"),
        }
    }

    // ── Strict snapshot import (audit 3.2) ─────────────────────────
    //
    // A snapshot is untrusted input: every structural defect and every
    // unproven claim must reject BEFORE any module mutates. These
    // tests build the failing variants from a *valid* exported
    // snapshot so the only difference is the defect under test.

    /// Run one counter tx so the source module has non-fresh
    /// committed state to carry across.
    fn exec_one_tx(executor: &Executor) {
        let tx = make_tx(1, &[0xAA]);
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![tx],
            signers: vec![],
        });
    }

    /// The name in `module_roots` binds the payload to the module —
    /// a forged name (a different chain's ordering) must reject.
    #[test]
    fn snapshot_import_rejects_module_name_mismatch() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        exec_one_tx(&executor);
        let mut snapshot = executor.export_snapshot();
        // The root aggregate commits only the root values, not names,
        // so a name swap does not disturb `state_root`.
        snapshot.module_roots[0].0 = "not-counter".to_string();

        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(CounterModule::new()));
        match executor2.import_snapshot(&snapshot) {
            Err(SnapshotImportError::ModuleNameMismatch { index, snapshot, registered }) => {
                assert_eq!(index, 0);
                assert_eq!(snapshot, "not-counter");
                assert_eq!(registered, "counter");
            }
            other => panic!("expected ModuleNameMismatch, got {other:?}"),
        }
    }

    /// A `module_state` shorter than the module list is malformed —
    /// the tail modules' state was never committed.
    #[test]
    fn snapshot_import_rejects_module_state_count_mismatch() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        exec_one_tx(&executor);
        let mut snapshot = executor.export_snapshot();
        snapshot.module_state.clear(); // module claims state, none carried

        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(CounterModule::new()));
        match executor2.import_snapshot(&snapshot) {
            Err(SnapshotImportError::MissingModuleState { module }) => {
                assert_eq!(module, "counter");
            }
            other => panic!("expected MissingModuleState, got {other:?}"),
        }
    }

    /// A `None` payload for a stateful module is incomplete state,
    /// not a sparse encoding.
    #[test]
    fn snapshot_import_rejects_dropped_module_state() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        exec_one_tx(&executor);
        let mut snapshot = executor.export_snapshot();
        snapshot.module_state[0] = None;

        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(CounterModule::new()));
        match executor2.import_snapshot(&snapshot) {
            Err(SnapshotImportError::MissingModuleState { module }) => {
                assert_eq!(module, "counter");
            }
            other => panic!("expected MissingModuleState, got {other:?}"),
        }
    }

    /// A payload supplied for a stateless module is uninterpretable —
    /// it must be rejected, not silently ignored.
    #[test]
    fn snapshot_import_rejects_unexpected_module_state() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(SelfAuthModule));
        let mut snapshot = executor.export_snapshot();
        assert!(snapshot.module_state[0].is_none());
        snapshot.module_state[0] =
            Some(storage::Snapshot { height: 0, entries: vec![(Hash([0; 32]), vec![1])] });

        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(SelfAuthModule));
        match executor2.import_snapshot(&snapshot) {
            Err(SnapshotImportError::UnexpectedModuleState { module }) => {
                assert_eq!(module, "selfauth");
            }
            other => panic!("expected UnexpectedModuleState, got {other:?}"),
        }
    }

    /// A payload that fails the module's own decode must surface as
    /// malformed during the verify pass.
    #[test]
    fn snapshot_import_rejects_malformed_module_state() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        exec_one_tx(&executor);
        let mut snapshot = executor.export_snapshot();
        // Corrupt the counter's blob: wrong length value.
        snapshot.module_state[0] =
            Some(storage::Snapshot { height: 0, entries: vec![(Hash([0xEE; 32]), vec![1, 2, 3])] });

        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(CounterModule::new()));
        match executor2.import_snapshot(&snapshot) {
            Err(SnapshotImportError::MalformedModuleState { module }) => {
                assert_eq!(module, "counter");
            }
            other => panic!("expected MalformedModuleState, got {other:?}"),
        }
    }

    /// A claimed module root that doesn't match the staged payload's
    /// decoded root must reject — the claim is never trusted over
    /// the data.
    #[test]
    fn snapshot_import_rejects_forged_module_root() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        exec_one_tx(&executor);
        let mut snapshot = executor.export_snapshot();
        // Forge the claimed root, then re-fix the aggregate so only
        // the per-module claim is wrong.
        snapshot.module_roots[0].1 = Hash([0x99; 32]);
        snapshot.state_root = canonical_state_root(
            snapshot.module_roots.iter().map(|(_, r)| *r),
            snapshot.nonce_root,
        );

        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(CounterModule::new()));
        match executor2.import_snapshot(&snapshot) {
            Err(SnapshotImportError::ModuleRootMismatch { module, expected, actual }) => {
                assert_eq!(module, "counter");
                assert_eq!(expected, Hash([0x99; 32]));
                assert_eq!(actual, Hash([1; 32]), "the staged count is 1");
            }
            other => panic!("expected ModuleRootMismatch, got {other:?}"),
        }
    }

    /// Verify-before-mutate: a corrupt payload for the SECOND module
    /// must leave the FIRST module untouched — no module state may be
    /// installed until every module's payload verifies.
    #[test]
    fn snapshot_import_verifies_all_modules_before_mutating() {
        let mut executor = test_executor(100);
        let c1 = Arc::new(CounterModule::new());
        let c2 = Arc::new(CounterModule::other());
        executor.register_module(c1.clone());
        executor.register_module(c2.clone());
        exec_one_tx(&executor);
        let mut snapshot = executor.export_snapshot();
        // Corrupt only the second module's payload.
        snapshot.module_state[1] = Some(storage::Snapshot {
            height: 0,
            entries: vec![(Hash([0xEF; 32]), vec![0xDE, 0xAD])],
        });

        let d1 = Arc::new(CounterModule::new());
        let d2 = Arc::new(CounterModule::other());
        let mut executor2 = test_executor(100);
        executor2.register_module(d1.clone());
        executor2.register_module(d2.clone());
        assert!(
            executor2.import_snapshot(&snapshot).is_err(),
            "a malformed payload must fail the import"
        );
        assert_eq!(
            *d1.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            0,
            "module 0 must not be mutated while module 1's payload is unproven"
        );
        assert_eq!(
            *d2.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            0,
            "module 1 must not be mutated by a malformed payload"
        );
    }

    /// Metadata-only import is complete only for an executor whose
    /// modules are all stateless — then it applies cleanly.
    #[test]
    fn snapshot_import_metadata_only_with_stateless_modules() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(SelfAuthModule));
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![],
            signers: vec![],
        });
        let mut snapshot = executor.export_snapshot();
        snapshot.module_state.clear();

        let mut executor2 = test_executor(100);
        executor2.register_module(Arc::new(SelfAuthModule));
        executor2.import_snapshot(&snapshot).expect("stateless modules need no payloads");
    }

    /// Past the scheduled halt, `execute_block` must return the
    /// frozen root and run no handlers — every replica stops
    /// mutating state at the same height.
    #[test]
    fn halt_height_freezes_execution() {
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());
        let halter = VersionedModule::new(1);
        *halter.halt.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(1);
        executor.register_module(halter as Arc<dyn Module>);

        // Height 1 executes normally (halt = last live height).
        let tx = make_tx(1, &[0]);
        executor.ingest_tx(tx);
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: proposal.txs,
            signers: Vec::new(),
        });
        let live_root = executor.current_state_root();
        let live_count = *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        // Height 2 is past the halt: state must not change even
        // though the block carries a tx.
        let block2 = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(2),
            txs: vec![make_tx(1, &[1])],
            signers: Vec::new(),
        };
        executor.finalize_block(&block2);
        assert_eq!(executor.current_state_root(), live_root, "state must freeze at halt");
        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            live_count,
            "no handlers run past the halt"
        );
    }

    /// Past the halt, proposals carry no txs — the chain keeps
    /// committing empty blocks so consensus stays live while
    /// operators swap binaries.
    #[test]
    fn prepare_proposal_empty_past_halt() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let halter = VersionedModule::new(1);
        *halter.halt.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(0);
        executor.register_module(halter as Arc<dyn Module>);

        executor.ingest_tx(make_tx(1, &[0]));
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert!(proposal.txs.is_empty(), "no txs may be proposed past the halt");
    }

    // ---- Async execution lane tests ----
    //
    // `spawn_exec_lane` moves block execution onto a worker thread:
    // `finalize_block` returns immediately, `attest_state` waits on
    // the watermark only for heights the lane actually owes.

    #[test]
    fn exec_lane_executes_and_attests() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let executor = Arc::new(executor);
        executor.spawn_exec_lane();

        // A real tx so the counter module's root is non-zero
        // (count=0 → Hash::ZERO, the same sentinel attest_state
        // returns for unexecuted heights — a zero-root block would
        // make this test vacuous).
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![make_tx_with_nonce(1, &[7], 0)],
            signers: vec![],
        };
        executor.finalize_block(&block);

        // attest_state waits on the worker watermark and returns
        // the worker-computed root.
        let att = executor.attest_state(Height::new(0)).expect("executed");
        assert_eq!(att.height, Height::new(0));
        assert_ne!(att.root, Hash::ZERO, "worker must have executed the block");
        // attest_latest reads the watermark without blocking.
        let latest = executor.attest_latest().expect("executed");
        assert_eq!(latest.height, Height::new(0));
        assert_eq!(latest.root, att.root);
    }

    #[test]
    fn exec_lane_matches_sync_roots() {
        // The lane must produce byte-identical state roots to the
        // synchronous path — same blocks, same order.
        let mut sync_exec = test_executor(100);
        sync_exec.register_module(Arc::new(CounterModule::new()));
        let mut async_exec = test_executor(100);
        async_exec.register_module(Arc::new(CounterModule::new()));
        let async_exec = Arc::new(async_exec);
        async_exec.spawn_exec_lane();

        for h in 0..5u64 {
            let block = FinalizedBlock {
                context: types::BlockContext::default(),
                height: Height::new(h),
                txs: vec![make_tx_with_nonce(1, &[u8::try_from(h).unwrap_or(0)], h)],
                signers: vec![],
            };
            sync_exec.finalize_block(&block);
            async_exec.finalize_block(&block);
        }
        for h in 0..5u64 {
            let sync_root = sync_exec.attest_state(Height::new(h)).expect("executed").root;
            let async_root = async_exec.attest_state(Height::new(h)).expect("executed").root;
            assert_eq!(sync_root, async_root, "height {h} root mismatch");
            assert_ne!(sync_root, Hash::ZERO);
        }
    }

    #[test]
    fn attest_beyond_enqueued_does_not_block() {
        // attest_state for a height the lane never saw must return
        // `None` immediately — never wait on execution that isn't
        // coming.
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let executor = Arc::new(executor);
        executor.spawn_exec_lane();
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![make_tx_with_nonce(1, &[1], 0)],
            signers: vec![],
        });
        executor.attest_state(Height::new(0)); // drain the lane

        // Run the attest on a helper thread with a hard deadline —
        // if the wait logic ever blocks on an unknown height this
        // test fails by timeout rather than hanging CI forever.
        let (tx, rx) = std::sync::mpsc::channel();
        let app = executor.clone();
        std::thread::spawn(move || {
            tx.send(app.attest_state(Height::new(99))).expect("send");
        });
        let att = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("attest_state must not block on an unenqueued height");
        // An unenqueued height has no execution coming — `None`,
        // the explicit "not executed" signal.
        assert!(att.is_none());
    }

    /// A module that panics inside `handle` exactly once — models a
    /// worker-killing execution fault that replays cleanly when the
    /// same committed block is re-executed later.
    struct PanicOnceModule {
        /// Set until the first `handle` call detonates it.
        armed: std::sync::atomic::AtomicBool,
        /// Invocation count, for the post-recovery state root.
        calls: Mutex<u64>,
    }

    impl PanicOnceModule {
        fn new() -> Self {
            Self { armed: std::sync::atomic::AtomicBool::new(true), calls: Mutex::new(0) }
        }
    }

    impl Module for PanicOnceModule {
        fn name(&self) -> &'static str {
            "panic-once"
        }
        fn id(&self) -> u8 {
            2
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            assert!(
                !self.armed.swap(false, std::sync::atomic::Ordering::SeqCst),
                "panic-once: injected execution fault"
            );
            *self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
            Ok(vec![Event { module: "panic-once", kind: "call", data: vec![] }])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            // Non-zero once any call has landed (count 1 → byte 1).
            let c = *self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            Hash([u8::try_from(c.max(1)).unwrap_or(0xff); 32])
        }
    }

    #[test]
    fn exec_lane_death_unblocks_attest() {
        // A worker that dies mid-block must not leave `attest_state`
        // waiting forever: the lane's death is terminal, so the
        // attest for the lost height returns `None` (no root landed)
        // instead of blocking on a watermark that can never advance.
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(PanicOnceModule::new()));
        let executor = Arc::new(executor);
        executor.spawn_exec_lane();

        // The panic tx kills the worker during block 0's execution.
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![make_tx_with_nonce(2, &[1], 0)],
            signers: vec![],
        });
        // Give the worker a beat to receive, panic, and unwind —
        // execution is microseconds; this margin only needs to
        // outlive thread scheduling.
        std::thread::sleep(std::time::Duration::from_millis(200));

        // attest_state on the dead lane's lost height must return —
        // on a helper thread with a hard deadline so a hang fails
        // by timeout rather than hanging CI forever.
        let (tx, rx) = std::sync::mpsc::channel();
        let app = executor.clone();
        std::thread::spawn(move || {
            tx.send(app.attest_state(Height::new(0))).expect("send");
        });
        let att = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("attest_state must not hang on a dead execution lane");
        // The panicked block's root never landed — nothing executed.
        assert!(att.is_none(), "a height lost to a dead lane has no root to attest");
    }

    /// A module that mutates observable state BEFORE panicking —
    /// the partial-application case the old `PanicOnceModule`
    /// fixture could not express (it detonated before mutating, so
    /// its replay was benign by construction). Here the mutation
    /// lands first, so the block is provably half-applied when the
    /// worker dies.
    struct MutateThenPanicModule {
        /// Invocation count — the observable mutation proving
        /// execution began before the fault.
        calls: Mutex<u64>,
        /// Set until the first `handle` detonates it.
        armed: std::sync::atomic::AtomicBool,
    }

    impl Module for MutateThenPanicModule {
        fn name(&self) -> &'static str {
            "mutate-then-panic"
        }
        fn id(&self) -> u8 {
            3
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            // Mutation FIRST — the moment this lands the block is
            // partially applied, and replaying it would repeat it.
            *self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
            assert!(
                !self.armed.swap(false, std::sync::atomic::Ordering::SeqCst),
                "mutate-then-panic: injected mid-mutation fault"
            );
            Ok(vec![Event { module: "mutate-then-panic", kind: "call", data: vec![] }])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            let c = *self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            Hash([u8::try_from(c.max(1)).unwrap_or(0xff); 32])
        }
    }

    #[test]
    fn exec_lane_death_backfills_committed_blocks() {
        // A lane that dies mid-`execute_block` leaves a PARTIALLY
        // APPLIED block — replaying it would re-run fees, nonces,
        // and module mutations on already-mutated state. The backlog
        // drain must fail closed (panic) instead of re-executing:
        // recovery belongs to durable state at restart, not to a
        // blind in-process replay.
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(PanicOnceModule::new()));
        let executor = Arc::new(executor);
        executor.spawn_exec_lane();

        // Block 0 kills the worker mid-execution.
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![make_tx_with_nonce(2, &[1], 0)],
            signers: vec![],
        });
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Block 1's finalize drives the backlog drain — which must
        // refuse to replay the partially applied block 0.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.finalize_block(&FinalizedBlock {
                context: types::BlockContext::default(),
                height: Height::new(1),
                txs: vec![make_tx_with_nonce(2, &[2], 1)],
                signers: vec![],
            });
        }));
        let payload = result.expect_err("the drain must fail closed on a partially applied block");
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(msg.contains("partially applied"), "halt message must name the cause, got: {msg}");
    }

    #[test]
    fn exec_lane_death_mid_mutation_is_not_replayed() {
        // The `MutateThenPanicModule` lands its mutation BEFORE the
        // fault — block 0 is provably half-applied. The drain's
        // refusal must ALSO leave the mutation unreplayed: `calls`
        // stays at exactly 1 — a blind replay would have run the
        // same mutation a second time.
        let mut executor = test_executor(100);
        let module = Arc::new(MutateThenPanicModule {
            calls: Mutex::new(0),
            armed: std::sync::atomic::AtomicBool::new(true),
        });
        executor.register_module(module.clone() as Arc<dyn Module>);
        let executor = Arc::new(executor);
        executor.spawn_exec_lane();

        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![make_tx_with_nonce(3, &[1], 0)],
            signers: vec![],
        });
        std::thread::sleep(std::time::Duration::from_millis(200));

        // The mutation landed before the panic — the block WAS
        // partially applied.
        assert_eq!(
            *module.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "the pre-panic mutation must have landed exactly once"
        );

        // The drain refuses; the mutation is never replayed.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.finalize_block(&FinalizedBlock {
                context: types::BlockContext::default(),
                height: Height::new(1),
                txs: vec![make_tx_with_nonce(3, &[2], 1)],
                signers: vec![],
            });
        }));
        assert_eq!(
            *module.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "a refused replay must not run the mutation a second time"
        );
    }

    /// The synchronous dispatch path must enforce the same
    /// fail-closed contract as the exec lane: a module panic that
    /// lands after earlier mutations leaves `in_flight` set with no
    /// root, so the next `finalize_block` refuses to execute on top
    /// of the half-applied block — replay belongs to durable-state
    /// recovery at restart, not to in-process retry.
    #[test]
    fn sync_path_panic_mid_mutation_poisons_executor() {
        let mut executor = test_executor(100);
        let module = Arc::new(MutateThenPanicModule {
            calls: Mutex::new(0),
            armed: std::sync::atomic::AtomicBool::new(true),
        });
        executor.register_module(module.clone() as Arc<dyn Module>);
        // No exec lane — the default synchronous path.

        // Block 0: mutation lands, then the panic propagates through
        // `finalize_block` to the caller.
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.finalize_block(&FinalizedBlock {
                context: types::BlockContext::default(),
                height: Height::new(0),
                txs: vec![make_tx_with_nonce(3, &[1], 0)],
                signers: vec![],
            });
        }));
        assert!(first.is_err(), "the module panic must propagate to the committer");
        assert_eq!(
            *module.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "the pre-panic mutation landed — the block is partially applied"
        );

        // Block 1 must fail closed: replaying block 0 on top of the
        // surviving mutation would double-apply it. (The module is
        // disarmed, so a blind retry would even SUCCEED — silently
        // returning a root computed over double-applied state.)
        let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.finalize_block(&FinalizedBlock {
                context: types::BlockContext::default(),
                height: Height::new(1),
                txs: vec![make_tx_with_nonce(3, &[2], 1)],
                signers: vec![],
            });
        }));
        let payload = second.expect_err("the sync path must fail closed on a partial apply");
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(msg.contains("partially applied"), "halt message must name the cause, got: {msg}");
        assert_eq!(
            *module.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "no mutation may replay on the poisoned executor"
        );
    }

    /// A module whose `handle` blocks until the test opens a gate —
    /// models a slow worker so the lane's queue can be filled
    /// deterministically. Spins on an atomic rather than a channel
    /// so a single flag release unblocks every later call too.
    struct GatedModule {
        /// Open when the test releases execution.
        gate: std::sync::atomic::AtomicBool,
        /// Invocation count, for post-drain assertions.
        calls: Mutex<u64>,
    }

    impl Module for GatedModule {
        fn name(&self) -> &'static str {
            "gated"
        }
        fn id(&self) -> u8 {
            4
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            while !self.gate.load(std::sync::atomic::Ordering::SeqCst) {
                std::hint::spin_loop();
            }
            *self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
            Ok(vec![Event { module: "gated", kind: "call", data: vec![] }])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            let c = *self.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            Hash([u8::try_from(c.max(1)).unwrap_or(0xff); 32])
        }
    }

    fn finalized_block(height: u64, module: u8, nonce: u64) -> FinalizedBlock {
        FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(height),
            txs: vec![make_tx_with_nonce(module, &[u8::try_from(height).unwrap_or(0xff)], nonce)],
            signers: vec![],
        }
    }

    #[test]
    fn finalized_pruning_pins_unexecuted_heights() {
        // Retention bounds only the executed prefix: a committed
        // height without a state root is the drain's backlog and
        // must survive pruning no matter how far behind execution
        // falls.
        let executor = test_executor(100).with_history_retention(2);

        // Nothing executed: every committed height is unexecuted —
        // the pin holds all of them even past the window.
        for h in 0..4 {
            executor.insert_finalized(h, finalized_block(h, 1, h));
        }
        assert_eq!(
            executor.finalized.lock().unwrap().len(),
            4,
            "unexecuted heights must never be evicted"
        );

        // Mark 0–2 executed (in-order execution ⇒ rooted): they
        // become evictable; 3 and the new 4 stay pinned.
        {
            let (lock, _cv) = &*executor.exec_sync;
            lock.lock().unwrap().executed = Some(2);
        }
        executor.insert_finalized(4, finalized_block(4, 1, 4));
        let kept: Vec<u64> = executor.finalized.lock().unwrap().keys().copied().collect();
        assert_eq!(kept, vec![3, 4], "only executed heights may be evicted");
    }

    #[test]
    fn exec_lane_queue_is_bounded() {
        // The lane queue must bound how far consensus can outrun
        // execution: once the channel holds `depth` unreceived
        // blocks, `finalize_block` blocks until the worker drains —
        // backpressure, not an unbounded backlog that outlives the
        // retained history.
        let mut executor = test_executor(100).with_history_retention(5);
        // lane depth = min(EXEC_LANE_DEPTH, retention - 1) = 4.
        let module = Arc::new(GatedModule {
            gate: std::sync::atomic::AtomicBool::new(false),
            calls: Mutex::new(0),
        });
        executor.register_module(module.clone() as Arc<dyn Module>);
        let executor = Arc::new(executor);
        executor.spawn_exec_lane();

        // h0 reaches the worker and parks inside the gate.
        executor.finalize_block(&finalized_block(0, 4, 0));
        std::thread::sleep(std::time::Duration::from_millis(100));

        // h1..h4 fill the bounded queue (depth 4).
        for h in 1..=4u64 {
            executor.finalize_block(&finalized_block(h, 4, h));
        }

        // h5 cannot be queued until the worker drains — its
        // finalize must block.
        let done = std::sync::mpsc::channel::<()>();
        let exec2 = executor.clone();
        let join = std::thread::spawn(move || {
            exec2.finalize_block(&finalized_block(5, 4, 5));
            let _ = done.0.send(());
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(
            done.1.try_recv().is_err(),
            "a full lane queue must apply backpressure to the commit path"
        );

        // Release the worker: the backlog drains and h5 completes.
        module.gate.store(true, std::sync::atomic::Ordering::SeqCst);
        done.1
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("h5 finalize must complete once the worker drains");
        join.join().expect("finalize thread must not panic");
        executor.wait_exec_idle();
        assert_eq!(
            *module.calls.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            6,
            "every committed block executed exactly once"
        );
    }

    // ---- Mempool finality-custody tests ----

    /// A tx in a proposal that never commits must stay re-proposable:
    /// `select` is a peek, so losing the round doesn't lose the tx.
    /// The old remove-on-select path drained the pool the moment a
    /// proposal was built — a losing proposal erased its txs forever.
    #[test]
    fn uncommitted_proposal_keeps_txs() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        executor.ingest_tx(make_tx(1, &[42]));
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let first = executor.prepare_proposal(&budget);
        assert_eq!(first.txs.len(), 1);
        // The proposal loses — no `finalize_block` — so the next
        // round's proposal must offer the same tx again.
        let second = executor.prepare_proposal(&budget);
        assert_eq!(second.txs.len(), 1, "uncommitted txs stay re-proposable");
        assert_eq!(second.txs, first.txs);
    }

    /// The mirror image: txs DO leave the pool — but only when a
    /// block finalizes them.
    #[test]
    fn committed_txs_leave_pool_at_finalize() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        executor.ingest_tx(make_tx(1, &[42]));
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 1);
        // Before finality the tx is still pooled.
        assert_eq!(executor.mempool_len(), 1);
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: proposal.txs,
            signers: Vec::new(),
        });
        assert_eq!(executor.mempool_len(), 0, "committed txs leave the pool");
        assert!(
            executor.prepare_proposal(&budget).txs.is_empty(),
            "nothing may be re-proposed after commit"
        );
    }

    /// Candidates the proposal-time gas filter skips must survive
    /// for the next block — previously they were silently deleted
    /// with the rest of the selection.
    #[test]
    fn gas_filtered_candidates_stay_pooled() {
        let mut executor =
            test_executor_with_config(100, DEFAULT_PARALLEL_THRESHOLD).with_gas_limit(2500);
        executor.register_module(Arc::new(CounterModule::new()));
        // Four ~1001-gas txs; only 2 fit under a 2500 cap per block.
        for n in 0..4u64 {
            let tx = make_tx_with_nonce(1, &[u8::try_from(n).unwrap_or(0xff)], n);
            assert!(matches!(executor.ingest_tx(tx), MempoolAck::Accepted));
        }
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let first = executor.prepare_proposal(&budget);
        assert_eq!(first.txs.len(), 2);
        // Committing the first two leaves the filtered two pooled —
        // they fill the next block exactly.
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: first.txs,
            signers: Vec::new(),
        });
        let second = executor.prepare_proposal(&budget);
        assert_eq!(second.txs.len(), 2, "filtered candidates fill the next block");
    }

    /// `ingest_tx_batch` must map pool rejections back to the
    /// tx's slot in the *caller's* batch — the filtered `accepted`
    /// vec's position used to be used as the index, so a rejection
    /// overwrote an unrelated earlier `Accepted` result and left the
    /// actually-rejected tx acknowledged.
    #[test]
    fn batch_acks_map_to_original_indices() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let good = make_tx(1, &[42]);
        let results = executor.ingest_tx_batch(vec![
            TxBytes::new(vec![1, 2, 3]), // malformed — rejected in validation
            good.clone(),                // accepted
            good,                        // duplicate — rejected by the pool
        ]);
        assert_eq!(results.len(), 3);
        assert!(matches!(results[0], MempoolAck::Rejected { .. }), "malformed tx rejected");
        assert!(
            matches!(results[1], MempoolAck::Accepted),
            "the valid tx must be acknowledged Accepted — not clobbered by the duplicate's rejection"
        );
        assert!(
            matches!(results[2], MempoolAck::Rejected { .. }),
            "the duplicate must be the one reported Rejected"
        );
    }

    /// Finalized outcomes distinguish executed txs from gate-skipped
    /// ones — the record a settlement client waits on. Mempool
    /// acceptance alone must never read as "settled": these txs are
    /// hand-built into the block so the gate-skips are exercised at
    /// execution time, exactly where they occur in production.
    #[test]
    fn tx_outcome_records_executed_and_skipped() {
        let mut executor = test_executor(100);
        executor.register_module(Arc::new(CounterModule::new()));

        let good = make_tx_with_nonce(1, &[42], 0);
        let stale = make_tx_with_nonce(1, &[7], 7);
        let unknown = make_tx(99, &[1]);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![good.clone(), stale.clone(), unknown.clone()],
            signers: vec![],
        };
        executor.finalize_block(&block);

        let h = |tx: &TxBytes| Hasher::hash_one(Domain::Transaction, tx.as_bytes());
        match executor.tx_outcome(&h(&good)) {
            Some(TxOutcome::Executed { events, error }) => {
                assert!(error.is_none(), "clean dispatch");
                assert_eq!(events.len(), 1, "the module's event is attached to the outcome");
            }
            other => panic!("expected Executed, got {other:?}"),
        }
        assert_eq!(
            executor.tx_outcome(&h(&stale)),
            Some(TxOutcome::Skipped { reason: TxSkipReason::StaleNonce }),
        );
        assert_eq!(
            executor.tx_outcome(&h(&unknown)),
            Some(TxOutcome::Skipped { reason: TxSkipReason::UnknownModule }),
        );
        // Only the executed tx consumed its sender's nonce — the
        // skips left the counter at the executed value.
        assert_eq!(executor.executed_nonce_of(&Address([0u8; 20])), 1);
        // A tx never proposed has no outcome — `None` is "in flight".
        assert!(executor.tx_outcome(&Hash::ZERO).is_none());
    }

    /// A provisional `Skipped` outcome is overwritten when the same
    /// tx later executes — the gas-limit case in production — while
    /// an `Executed` outcome is final and can never be rewritten by
    /// a stale re-proposal's skip.
    #[test]
    fn tx_outcome_store_overwrite_semantics() {
        let mut store = TxOutcomeStore::default();
        let h = Hash([1u8; 32]);
        store.record(h, TxOutcome::Skipped { reason: TxSkipReason::GasLimit });
        // The tx lands in a later block — Executed supersedes.
        let executed = TxOutcome::Executed { events: vec![], error: None };
        store.record(h, executed.clone());
        assert_eq!(store.outcomes.get(&h), Some(&executed));
        // A stale re-proposal skipping afterwards cannot rewrite it.
        store.record(h, TxOutcome::Skipped { reason: TxSkipReason::StaleNonce });
        assert_eq!(store.outcomes.get(&h), Some(&executed), "Executed is final");
    }

    /// A module rejection is still an execution: the fee was charged
    /// and the nonce consumed — the outcome records the error so a
    /// submitter can tell a revert apart from a clean apply.
    #[test]
    fn tx_outcome_records_module_rejection() {
        /// A module whose `handle` always rejects.
        struct RejectingModule;
        impl Module for RejectingModule {
            fn name(&self) -> &'static str {
                "rejector"
            }
            fn id(&self) -> u8 {
                3
            }
            fn begin_block(&self, _height: Height) {}
            fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
                Err(ExecError::ModuleRejected("nope".to_string()))
            }
            fn end_block(&self, _height: Height) -> Vec<Event> {
                Vec::new()
            }
            fn state_root(&self) -> Hash {
                Hash::ZERO
            }
        }

        let mut executor = test_executor(100);
        executor.register_module(Arc::new(RejectingModule));
        let tx = make_tx_with_nonce(3, &[1], 0);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![tx.clone()],
            signers: vec![],
        };
        executor.finalize_block(&block);

        let h = Hasher::hash_one(Domain::Transaction, tx.as_bytes());
        match executor.tx_outcome(&h) {
            Some(TxOutcome::Executed { events, error }) => {
                assert!(events.is_empty());
                assert!(error.unwrap_or_default().contains("nope"));
            }
            other => panic!("expected Executed-with-error, got {other:?}"),
        }
        // The rejection still consumed the nonce — a revert, not a
        // skip.
        assert_eq!(executor.executed_nonce_of(&Address([0u8; 20])), 1);
    }

    // ── Cross-module ordering regression fixtures — committed block
    //    order, not module-id order, decides execution. ────────────

    /// A ledger both fixture modules share — the test-side analogue
    /// of the real EVM account store every module settles against.
    type SharedLedger = Arc<Mutex<HashMap<Address, u64>>>;

    /// Module id 7: credits `Address([payload[0]; 20])` with
    /// `payload[1]` units. Deliberately a *higher* module id than
    /// `CounterModule` (1) — under sorted-module grouping the funder
    /// ran *after* the counter regardless of block order.
    struct FunderModule {
        ledger: SharedLedger,
    }

    impl Module for FunderModule {
        fn name(&self) -> &'static str {
            "funder"
        }
        fn id(&self) -> u8 {
            7
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            if msg.len() >= 2 {
                let mut ledger =
                    self.ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                *ledger.entry(Address([msg[0]; 20])).or_insert(0) += u64::from(msg[1]);
            }
            Ok(vec![Event { module: "funder", kind: "funded", data: vec![] }])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
    }

    /// Fee collector (id 9) that debits the shared ledger — a charge
    /// fails when the sender's balance is short, so tests can observe
    /// *when* the charge ran relative to other txs' effects.
    struct LedgerFeeCollector {
        ledger: SharedLedger,
    }

    impl Module for LedgerFeeCollector {
        fn name(&self) -> &'static str {
            "ledgerfeecollector"
        }
        fn id(&self) -> u8 {
            9
        }
        fn begin_block(&self, _height: Height) {}
        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            Ok(vec![])
        }
        fn end_block(&self, _height: Height) -> Vec<Event> {
            Vec::new()
        }
        fn state_root(&self) -> Hash {
            Hash::ZERO
        }
        fn charge_fee(&self, ctx: &TxContext) -> Result<(), ExecError> {
            let mut ledger = self.ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let balance = ledger.entry(ctx.sender).or_insert(0);
            if *balance < ctx.fee {
                return Err(ExecError::ModuleRejected("insufficient fee balance".to_string()));
            }
            *balance -= ctx.fee;
            Ok(())
        }
    }

    fn ordering_executor(ledger: &SharedLedger) -> (Executor, Arc<CounterModule>) {
        let mut executor = test_executor(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());
        executor.register_module(Arc::new(FunderModule { ledger: ledger.clone() }));
        executor.register_module(Arc::new(LedgerFeeCollector { ledger: ledger.clone() }));
        executor.set_fee_module(9);
        (executor, counter)
    }

    /// Finalize `txs` in the given order — the committed order is the
    /// semantic under test, so blocks are built directly rather than
    /// routed through `prepare_proposal` (whose fee-priority mempool
    /// ordering is a separate, legitimate concern).
    fn run_block(executor: &Executor, txs: Vec<TxBytes>) {
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs,
            signers: Vec::new(),
        });
    }

    /// The audit's core case: a tx in a *higher-numbered* module
    /// (funder, id 7) credits the sender of a *lower-numbered*
    /// module's tx (counter, id 1). Committed order is [funder,
    /// counter] — sequential execution funds sender 9 before its
    /// fee is charged. The old sort-by-module grouping ran the
    /// counter's group first and charged fees before ANY module
    /// executed — this tx was skipped either way. Now it runs.
    #[test]
    fn cross_module_funding_visible_to_later_fee_charge() {
        let ledger: SharedLedger = Arc::new(Mutex::new(HashMap::new()));
        let (executor, counter) = ordering_executor(&ledger);

        // Funder tx (sender 8, fee 0) credits sender 9 with 100 —
        // committed BEFORE the counter tx.
        let funder = make_tx_with_fee_and_sender(7, &[9, 100], 0, 0, 8);
        // Counter tx (sender 9, fee 100) — spends exactly what the
        // funder grants.
        let counter_tx = make_tx_with_fee_and_sender(1, &[1], 0, 100, 9);
        run_block(&executor, vec![funder, counter_tx]);

        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            1,
            "the counter tx must execute — its sender was funded earlier in the block"
        );
        assert_eq!(
            ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[&Address([9u8; 20])],
            0,
            "the 100-unit fee was charged against the funding"
        );
    }

    /// The reverse order proves block order — not module order —
    /// decides: counter (id 1) before funder (id 7), so the fee
    /// charge fails on the empty balance even though the funder
    /// runs later in the same block.
    #[test]
    fn later_module_funding_does_not_help_earlier_tx() {
        let ledger: SharedLedger = Arc::new(Mutex::new(HashMap::new()));
        let (executor, counter) = ordering_executor(&ledger);

        // Counter tx FIRST (sender 9 unfunded, fee 100 → charge fails).
        let counter_tx = make_tx_with_fee_and_sender(1, &[1], 0, 100, 9);
        // Funder SECOND — too late to help.
        let funder = make_tx_with_fee_and_sender(7, &[9, 100], 0, 0, 8);
        run_block(&executor, vec![counter_tx, funder]);

        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            0,
            "the counter tx must be skipped — its fee preceded the funding"
        );
        assert_eq!(
            ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner)[&Address([9u8; 20])],
            100,
            "the funder still executed — its own fee was 0"
        );
    }

    /// A dispatch-time fee failure must not consume the nonce:
    /// sequential semantics skip the failed tx AND everything behind
    /// it in the sender's chain (the gap is unreachable), while the
    /// executed-nonce marker stays retryable.
    #[test]
    fn fee_failure_rewinds_sender_nonce_chain() {
        let ledger: SharedLedger = Arc::new(Mutex::new(HashMap::new()));
        let (executor, counter) = ordering_executor(&ledger);

        // Sender 9: nonce 0 fee 100 (fails — empty balance), nonce 1
        // fee 0 (would charge fine — but the chain is broken).
        let head = make_tx_with_fee_and_sender(1, &[1], 0, 100, 9);
        let next = make_tx_with_fee_and_sender(1, &[1], 1, 0, 9);
        run_block(&executor, vec![head, next]);

        assert_eq!(
            *counter.count.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            0,
            "neither tx executes — the chain broke at nonce 0"
        );
        assert_eq!(
            executor.executed_nonce_of(&Address([9u8; 20])),
            0,
            "nonce 0 stays unconsumed — the failed tx is retryable"
        );
    }
}
