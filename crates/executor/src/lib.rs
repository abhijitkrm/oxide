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
    /// The snapshot's `executed_nonces` lists a sender twice. The
    /// fold commitment is over a set — a duplicated leaf XORs out
    /// while the installed map dedupes — so the imported root would
    /// diverge from the fold of the imported map. Rejected rather
    /// than silently reconciled: a sender appears at most once in a
    /// well-formed export.
    DuplicateNonceEntry,
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
            Self::DuplicateNonceEntry => {
                write!(f, "executed_nonces lists a sender more than once")
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
/// The root is the **XOR-fold of per-leaf hashes**
/// `⊕ H(ExecutedNonceLeaf ‖ address ‖ nonce_le)` — a set
/// commitment, not a sequence commitment. That construction is
/// deliberate: the previous sorted-concatenation hash was O(map) to
/// recompute, so every block paid a full scan of every sender that
/// had ever transacted (7.4). The XOR-fold is order-independent
/// (deterministic across `HashMap` iteration order, no sort, no
/// concatenated buffer) and — the point — incrementally updatable:
/// a nonce change folds out the old leaf and folds in the new one
/// in O(1), so a block pays O(touched senders), not O(all senders).
///
/// Strength note: against a *consensus-pinned* expected root (the
/// only way this value is trusted — it is recomputed from the
/// snapshot's own bytes and compared), finding a different nonce
/// set with the same fold is a subset-XOR problem over 256-bit
/// leaf hashes — ~2^128-class work, the same order as generic
/// collision search on the prior sequential hash. The leaf hash
/// keeps an attacker from folding chosen bytes directly.
fn compute_nonce_root(nonces: &[(primitives::Address, u64)]) -> Hash {
    let mut root = Hash::ZERO;
    for (addr, nonce) in nonces {
        xor_fold(&mut root, nonce_leaf(addr, *nonce));
    }
    root
}

/// One leaf of the nonce commitment: `H(ExecutedNonceLeaf ‖ addr ‖
/// nonce_le)`. Hashing the leaf is what makes the fold a commitment
/// to a *set of preimages* rather than to raw XOR-able bytes.
fn nonce_leaf(addr: &primitives::Address, nonce: u64) -> Hash {
    let mut preimage = [0u8; 20 + 8];
    preimage[..20].copy_from_slice(&addr.0);
    preimage[20..].copy_from_slice(&nonce.to_le_bytes());
    Hasher::hash_one(Domain::ExecutedNonceLeaf, &preimage)
}

/// `*acc ^= leaf`, byte-wise. XOR is the fold operation: adding a
/// leaf and later removing the *same* leaf returns the accumulator
/// to its prior value, which is what makes the root incrementally
/// maintainable.
fn xor_fold(acc: &mut Hash, leaf: Hash) {
    for (a, b) in acc.0.iter_mut().zip(leaf.0.iter()) {
        *a ^= *b;
    }
}

/// The executed-nonce map paired with its commitment.
///
/// `root` is maintained incrementally — every mutation goes through
/// [`ExecutedNonces::bump`], which folds the leaf change into the
/// root in O(1). The invariant `root == compute_nonce_root(map)` is
/// therefore upheld by construction rather than recomputed per
/// block: a block that advances K senders' nonces pays K leaf
/// hashes, not a scan of every account that ever transacted.
#[derive(Clone, Default)]
struct ExecutedNonces {
    /// sender → next-expected nonce (replay protection state).
    map: HashMap<primitives::Address, u64>,
    /// `⊕ nonce_leaf(addr, nonce)` over `map` — kept in lockstep.
    root: Hash,
}

impl ExecutedNonces {
    /// Set `addr`'s next-expected nonce to `next`, folding the leaf
    /// change into `root`: the old leaf (if any) is XOR'd out and
    /// the new leaf XOR'd in. An unchanged value folds out and back
    /// in — a net no-op — so callers need not pre-check.
    fn bump(&mut self, addr: primitives::Address, next: u64) {
        if let Some(&old) = self.map.get(&addr) {
            xor_fold(&mut self.root, nonce_leaf(&addr, old));
        }
        self.map.insert(addr, next);
        xor_fold(&mut self.root, nonce_leaf(&addr, next));
    }
}

/// Per-block speculative overlay on the committed nonce map.
///
/// `execute_block` reads through `delta` first, then the committed
/// `base`; `bump` writes only the delta and folds each leaf change
/// into `root` — so a block that touches K senders allocates O(K)
/// and hashes O(K), never cloning or scanning the committed map.
/// At block end `finish` hands back the delta and the post-block
/// root; applying the delta into the committed map preserves the
/// invariant `root == fold(map)` by induction (each bump folds out
/// the sender's effective leaf — delta value if present, else the
/// committed one — and folds in the new leaf).
struct BlockNonces<'a> {
    /// The committed map+root this block builds on (an `Arc` clone —
    /// O(1) snapshot, never copied).
    base: &'a ExecutedNonces,
    /// Provisional `sender → next-expected` writes from this block.
    delta: HashMap<primitives::Address, u64>,
    /// `base.root` folded forward by every `bump` so far.
    root: Hash,
}

impl<'a> BlockNonces<'a> {
    fn new(base: &'a ExecutedNonces) -> Self {
        Self { base, delta: HashMap::new(), root: base.root }
    }

    /// The sender's effective next-expected nonce: this block's
    /// provisional advance if present, else the committed value.
    fn next_expected(&self, addr: &primitives::Address) -> Option<u64> {
        self.delta.get(addr).or_else(|| self.base.map.get(addr)).copied()
    }

    /// Set `addr`'s effective next-expected nonce to `next`: fold
    /// out the current effective leaf (delta value wins over the
    /// committed one) and fold in the new leaf. Folding out the
    /// delta's value on a re-bump is what makes the fee-charge
    /// rewind (`bump` back to the failed nonce) algebraically exact.
    fn bump(&mut self, addr: primitives::Address, next: u64) {
        if let Some(old) = self.next_expected(&addr) {
            xor_fold(&mut self.root, nonce_leaf(&addr, old));
        }
        self.delta.insert(addr, next);
        xor_fold(&mut self.root, nonce_leaf(&addr, next));
    }

    /// The block's touched entries plus the folded post-block root —
    /// applying the delta to the committed map yields a map whose
    /// fold equals `root`.
    fn finish(self) -> (HashMap<primitives::Address, u64>, Hash) {
        (self.delta, self.root)
    }
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
            let mut s = primitives::sync::lock_state(lock);
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
    ///
    /// Carries its commitment alongside the map (`ExecutedNonces`):
    /// the root is folded per nonce change so `execute_block` pays
    /// O(touched senders) rather than re-hashing every account each
    /// block. The `Arc` lets a block take an O(1) snapshot of the
    /// committed map instead of cloning it — see `BlockNonces`.
    executed_nonce: Mutex<Arc<ExecutedNonces>>,
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
            executed_nonce: Mutex::new(Arc::new(ExecutedNonces::default())),
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
                        primitives::sync::lock_state(lock).in_flight = Some(height);
                    }
                    let root = executor.execute_block(&block);
                    primitives::sync::lock_state(&executor.state_roots).insert_retained(
                        height,
                        root,
                        executor.history_retention,
                    );
                    // Blocks arrive in commit order, so the newest
                    // height is always the watermark.
                    let (lock, cv) = &*sync;
                    {
                        let mut s = primitives::sync::lock_state(lock);
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
            primitives::sync::lock_state(lock).executed
        };
        let mut f = primitives::sync::lock_state(&self.finalized);
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
            let in_flight = primitives::sync::lock_state(lock).in_flight;
            in_flight.filter(|h| !primitives::sync::lock_state(&self.state_roots).contains_key(h))
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
                let heights: Vec<u64> =
                    primitives::sync::lock_state(&self.finalized).keys().copied().collect();
                let roots = primitives::sync::lock_state(&self.state_roots);
                heights.into_iter().find(|h| !roots.contains_key(h))
            };
            let Some(height) = next else { break };
            let Some(block) = primitives::sync::lock_state(&self.finalized).get(&height).cloned()
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
                primitives::sync::lock_state(lock).in_flight = Some(height);
            }
            let root = self.execute_block(&block);
            primitives::sync::lock_state(&self.state_roots).insert_retained(
                height,
                root,
                self.history_retention,
            );
            {
                let (lock, _cv) = &*self.exec_sync;
                primitives::sync::lock_state(lock).in_flight = None;
            }
        }
        // Advance the executed watermark to the newest recorded
        // root: heights the dead lane owed have now been executed
        // inline, and `attest_state` waiters must observe that.
        let newest =
            primitives::sync::lock_state(&self.state_roots).iter().next_back().map(|(h, _)| *h);
        if let Some(h) = newest {
            let (lock, cv) = &*self.exec_sync;
            let mut s = primitives::sync::lock_state(lock);
            s.executed = Some(s.executed.map_or(h, |e| e.max(h)));
            cv.notify_all();
        }
    }

    /// The current chain height (the highest finalized block).
    ///
    /// Returns 0 if no blocks have been finalized yet (genesis state).
    #[must_use]
    pub fn current_height(&self) -> u64 {
        let next = *primitives::sync::lock_state(&self.next_proposal_height);
        next.saturating_sub(1)
    }

    /// The state root at a given finalized height.
    ///
    /// Returns `Hash::ZERO` if the height is not finalized or unknown.
    #[must_use]
    pub fn state_root_at(&self, height: u64) -> Hash {
        primitives::sync::lock_state(&self.state_roots).get(&height).copied().unwrap_or(Hash::ZERO)
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
        primitives::sync::lock_state(&self.tx_outcomes).outcomes.get(tx_hash).cloned()
    }

    /// The next nonce the executor expects from `sender` — the count
    /// of its txs that have passed execution-time continuity. This is
    /// the authoritative resync anchor for a submitter whose local
    /// nonce may have drifted (restart, dead-lettered batch).
    #[must_use]
    pub fn executed_nonce_of(&self, sender: &primitives::Address) -> u64 {
        primitives::sync::lock_state(&self.executed_nonce).map.get(sender).copied().unwrap_or(0)
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
        primitives::sync::lock_state(&self.mempool).txpool_snapshot()
    }

    /// Pending mempool entry count — cold-path diagnostic for the
    /// devnet harness (a nonzero value after a run means txs were
    /// accepted into the pool but never selected for a proposal).
    #[must_use]
    pub fn mempool_len(&self) -> usize {
        primitives::sync::lock_state(&self.mempool).len()
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
        let nonces = primitives::sync::lock_state(&self.executed_nonce);
        let mut ops: Vec<storage::Op> = Vec::with_capacity(nonces.map.len());
        for (addr, nonce) in &nonces.map {
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
        let mut nonces = primitives::sync::lock_state(&self.executed_nonce);
        let nonces = Arc::make_mut(&mut nonces);
        for (key, value) in entries {
            let addr_bytes = &key.0[PREFIX.len()..PREFIX.len() + 20];
            let mut addr_arr = [0u8; 20];
            addr_arr.copy_from_slice(addr_bytes);
            let addr = primitives::Address(addr_arr);
            if value.len() >= 8 {
                let nonce = u64::from_le_bytes(value[..8].try_into().unwrap_or([0u8; 8]));
                // `bump` (not a bare map insert) keeps the folded
                // root in lockstep — restore is O(entries) once, a
                // cold path.
                nonces.bump(addr, nonce);
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
            let mut s = primitives::sync::lock_state(lock);
            while s.enqueued != s.executed {
                s = cv.wait(s).unwrap_or_else(|_| {
                    panic!("state mutex poisoned: a holder panicked mid-mutation")
                });
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
        let (executed_nonces, maintained_root) = {
            let en = primitives::sync::lock_state(&self.executed_nonce);
            (en.map.iter().map(|(addr, nonce)| (*addr, *nonce)).collect::<Vec<_>>(), en.root)
        };
        // Recompute from the bytes being exported — the snapshot's
        // `nonce_root` must commit to its own `executed_nonces`
        // payload. It must equal the incrementally-maintained root;
        // the assert makes any bookkeeping drift a test-visible bug
        // rather than a silent divergence between the live path and
        // the snapshot path.
        let nonce_root = compute_nonce_root(&executed_nonces);
        debug_assert_eq!(nonce_root, maintained_root, "nonce root drifted from its map");
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
        // The nonce root is an XOR-fold over *set* semantics — a
        // duplicated `(addr, nonce)` pair folds out entirely while a
        // `HashMap::collect` silently dedupes it, so the installed
        // root would no longer match the fold of the installed map.
        // Reject duplicates explicitly: a sender appears at most
        // once in a well-formed snapshot.
        {
            let mut seen = std::collections::HashSet::with_capacity(snapshot.executed_nonces.len());
            if snapshot.executed_nonces.iter().any(|(addr, _)| !seen.insert(addr)) {
                return Err(SnapshotImportError::DuplicateNonceEntry);
            }
        }
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
        primitives::sync::lock_state(&self.state_roots)
            .insert(snapshot.height, snapshot.state_root);
        *primitives::sync::lock_state(&self.next_proposal_height) =
            snapshot.height.saturating_add(1); // M2 fix

        // H4/H5: restore the executed-nonce map so replay protection
        // survives restarts and state sync. Without this, a node
        // that restarts from a snapshot would accept already-executed
        // txs (replay attack).
        *primitives::sync::lock_state(&self.executed_nonce) = Arc::new(ExecutedNonces {
            map: snapshot.executed_nonces.iter().copied().collect(),
            // Verified above to equal both the fold of this map
            // and the snapshot's committed `nonce_root` — reuse
            // it rather than re-folding.
            root: recomputed_nonce_root,
        });

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
        local_nonce: &mut BlockNonces<'_>,
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
            let expected = local_nonce.next_expected(&ctx.sender).unwrap_or(0);
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
                local_nonce.bump(ctx.sender, expected + 1);
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

    /// Charge each tx's fee and execute it, interleaved per tx, in
    /// run order. The charge lives at dispatch time — not in
    /// `plan_block_runs` — because it debits the shared ledger and
    /// must observe every earlier tx's effects; within a run the
    /// charge→execute interleave extends that guarantee to same-run
    /// predecessors, so a tx whose sender's balance was consumed by
    /// an earlier same-run tx (e.g. a fill that debited the maker)
    /// is fee-rejected rather than executed on a stale balance.
    /// This is exact sequential semantics for every module that
    /// pays an executor fee. It costs nothing in practice: the only
    /// module with a real batch dispatch path (EVM: parallel sender
    /// recovery) is self-funded and never enters this path — for
    /// every other module `handle_batch` is the serial `handle`
    /// loop this loop performs anyway. A module that later adds a
    /// genuine batch override still gets it — but only for
    /// self-funded runs, where no executor fee interleaves.
    ///
    /// Returns the executed txs plus their results, index-aligned
    /// for `record_group_outcomes`. `broken_nonce` records the
    /// first failed-charge nonce per sender: under sequential
    /// semantics a failed charge consumes no nonce, so that
    /// sender's later txs are unreachable this block — they're
    /// skipped `StaleNonce` rather than executed with a gap.
    /// `local_nonce` is rewound to the failed nonce so
    /// `executed_nonce` reflects the last consumed nonce + 1 and
    /// the failed tx stays retryable. Self-funded modules (EVM:
    /// gas is the fee) skip charging entirely — the caller
    /// dispatches them as one batch.
    fn charge_and_execute_run<'b>(
        &self,
        run: Vec<GroupedTx<'b>>,
        module: &dyn Module,
        local_nonce: &mut BlockNonces<'_>,
        broken_nonce: &mut HashMap<primitives::Address, u64>,
        dispatch_skipped: &mut Vec<(Hash, TxSkipReason)>,
    ) -> (Vec<GroupedTx<'b>>, Vec<Result<Vec<Event>, ExecError>>) {
        let fee_module = self.fee_module.and_then(|id| self.modules[usize::from(id)].as_ref());
        let self_authenticating = module.authenticates_sender();
        let mut executed = Vec::with_capacity(run.len());
        let mut results = Vec::with_capacity(run.len());
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
                    local_nonce.bump(ctx.sender, ctx.nonce);
                }
                continue;
            }
            results.push(module.handle(&ctx, entry.1));
            executed.push(entry);
        }
        (executed, results)
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
    /// dispatch time rather than during planning. Fee-paying runs
    /// execute charge→handle per tx (`charge_and_execute_run`), so
    /// the same-run guarantee is exact: each tx's fee observes all
    /// earlier effects, same module or not. Self-funded runs keep
    /// the module's batch dispatch (`handle_batch*`), preserving
    /// batch-optimized paths (EVM parallel sender recovery,
    /// pre-verified senders) where no executor fee interleaves.
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
        primitives::sync::lock_state(&self.events).clear();

        // H5 fix: cross-block nonce continuity. Verify that each
        // sender's first tx in this block continues from the last
        // executed nonce. This closes the replay window across blocks
        // — a tx with a stale nonce from a previous block is rejected
        // here, not just in the mempool.
        //
        // We snapshot the committed nonce state as an `Arc` clone —
        // O(1), no map copy — and apply this block's advances into a
        // `BlockNonces` delta so a block pays O(touched senders), not
        // O(every account that ever transacted). The folded root
        // travels with the delta and lands committed at block end.
        let nonce_base: Arc<ExecutedNonces> = {
            let executed = primitives::sync::lock_state(&self.executed_nonce);
            Arc::clone(&executed)
        };
        let mut local_nonce = BlockNonces::new(&nonce_base);

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
        let mut preverify_cache =
            std::mem::take(&mut *primitives::sync::lock_state(&self.preverify_cache));

        let mut skipped: Vec<(Hash, TxSkipReason)> = Vec::new();
        let mut runs =
            self.plan_block_runs(&block.txs, &mut local_nonce, &preverify_cache, &mut skipped);

        // Record finalized outcomes for txs that never reached a
        // module. These are the only outcomes a submitter can get
        // for a gate-dropped tx — the mempool no longer holds it
        // (it was proposed), so without this record a skipped tx is
        // indistinguishable from "still in flight" forever.
        {
            let mut outcomes = primitives::sync::lock_state(&self.tx_outcomes);
            for (hash, reason) in skipped {
                outcomes.record(hash, TxOutcome::Skipped { reason });
            }
        }

        // Execute each contiguous same-module run in committed block
        // order — sequential cross-module semantics. Fee-paying runs
        // interleave charge→execute per tx (`charge_and_execute_run`);
        // self-funded runs dispatch as one batch.
        let mut block_events: Vec<Event> = Vec::new();
        let mut broken_nonce: HashMap<primitives::Address, u64> = HashMap::new();
        let mut dispatch_skipped: Vec<(Hash, TxSkipReason)> = Vec::new();

        for (module_id, run) in &mut runs {
            let Some(module) = self.modules[*module_id as usize].as_ref() else {
                continue; // unknown module — skip
            };

            if module.pays_own_fee() {
                // Self-funded module (EVM: gas is the fee) — no
                // executor charge interleaves, so the run takes the
                // module's real batch dispatch (preverified /
                // parallel sender recovery).
                let group: Vec<GroupedTx<'_>> = std::mem::take(run);
                if group.is_empty() {
                    continue;
                }
                let results = self.dispatch_run(module.as_ref(), &group, &mut preverify_cache);
                self.record_group_outcomes(&group, results, &mut block_events);
            } else {
                // Fee-paying module — charge each tx and execute it
                // immediately so the next tx's charge observes this
                // tx's ledger effects (exact sequential semantics).
                let (group, results) = self.charge_and_execute_run(
                    std::mem::take(run),
                    module.as_ref(),
                    &mut local_nonce,
                    &mut broken_nonce,
                    &mut dispatch_skipped,
                );
                self.record_group_outcomes(&group, results, &mut block_events);
            }
        }
        if !dispatch_skipped.is_empty() {
            let mut outcomes = primitives::sync::lock_state(&self.tx_outcomes);
            for (hash, reason) in dispatch_skipped {
                outcomes.record(hash, TxOutcome::Skipped { reason });
            }
        }
        // Publish all events from this block in one lock acquisition.
        primitives::sync::lock_state(&self.events).extend(block_events);

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
            primitives::sync::lock_state(&self.events).extend(end_block_events);
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
        // post-block root (folded incrementally by `bump`), so this
        // block pays O(touched senders), not a full scan of every
        // account that ever transacted.
        let mut module_roots = Vec::new();
        for module in self.modules.iter().flatten() {
            module_roots.push(module.state_root());
        }

        // Push the fresh nonce anchors into the mempool — the live
        // update path the pool's `executed_nonces` anchoring was
        // built for. `refresh_anchors` also prunes pooled entries
        // whose nonce this block consumed (a losing same-nonce
        // candidate can never execute), so stale entries don't
        // linger until a size-cap eviction reaches them. The lookup
        // reads through the block's delta — the effective post-block
        // value for every pooled sender.
        primitives::sync::lock_state(&self.mempool)
            .refresh_anchors(|sender| local_nonce.next_expected(sender));

        // H4/H5: persist the updated nonce map. The delta applies in
        // place (`Arc::make_mut` — the base snapshot is dropped first
        // so the committed map is uniquely owned and the update is
        // O(delta), not a copy) in a single lock acquisition so the
        // next block's `execute_block` and the mempool's `ingest_tx`
        // see the updated state.
        let (nonce_delta, nonce_root) = local_nonce.finish();
        drop(nonce_base);
        {
            let mut committed = primitives::sync::lock_state(&self.executed_nonce);
            let committed = Arc::make_mut(&mut committed);
            committed.map.extend(nonce_delta);
            committed.root = nonce_root;
        }

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
        let mut outcomes = primitives::sync::lock_state(&self.tx_outcomes);
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
            let executed = primitives::sync::lock_state(&self.executed_nonce);
            let next_expected = executed.map.get(&ctx.sender).copied().unwrap_or(0);
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
                    primitives::sync::lock_state(&self.preverify_cache).insert(tx_hash, sender);
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
                let executed = primitives::sync::lock_state(&self.executed_nonce);
                let next_expected = executed.map.get(&ctx.sender).copied().unwrap_or(0);
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
            let mut mempool = primitives::sync::lock_state(&self.mempool);
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
                            primitives::sync::lock_state(&self.preverify_cache)
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
            let rx = primitives::sync::lock_state(&self.mempool_intake_rx);
            let mut pool = primitives::sync::lock_state(&self.mempool);
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
            primitives::sync::lock_state(&self.mempool).select(budget.max_bytes)
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
        let height = Height::new(*primitives::sync::lock_state(&self.next_proposal_height));
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
        primitives::sync::lock_state(&self.mempool).remove_committed(&block.txs);
        if let Some(tx) = self.exec_lane_tx.get() {
            // Async execution lane: `finalized` and the proposal
            // height advance now — they record *ordering* finality,
            // which consensus already settled — while `state_roots`
            // is written by the worker (or the inline backlog drain
            // below) when execution lands. `finalized` is inserted
            // BEFORE the send so the backlog drain can see this
            // block too.
            self.insert_finalized(block.height.value(), block.clone());
            *primitives::sync::lock_state(&self.next_proposal_height) =
                block.height.value().saturating_add(1); // M2 fix
            let lane_dead = {
                let (lock, cv) = &*self.exec_sync;
                let mut s = primitives::sync::lock_state(lock);
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
                primitives::sync::lock_state(lock)
                    .in_flight
                    .filter(|h| !primitives::sync::lock_state(&self.state_roots).contains_key(h))
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
                primitives::sync::lock_state(lock).in_flight = Some(block.height.value());
            }
            let root = self.execute_block(block);
            primitives::sync::lock_state(&self.state_roots).insert_retained(
                block.height.value(),
                root,
                self.history_retention,
            );
            {
                let (lock, _cv) = &*self.exec_sync;
                primitives::sync::lock_state(lock).in_flight = None;
            }
            // Keep the watermark honest in synchronous mode too:
            // the block was just executed, and `insert_finalized`
            // evicts only at-or-below it.
            {
                let (lock, _cv) = &*self.exec_sync;
                let mut s = primitives::sync::lock_state(lock);
                s.enqueued = Some(block.height.value());
                s.executed = Some(block.height.value());
            }
            self.insert_finalized(block.height.value(), block.clone());
            *primitives::sync::lock_state(&self.next_proposal_height) =
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
            let mut s = primitives::sync::lock_state(lock);
            while !s.lane_dead
                && s.enqueued.is_some_and(|e| height.value() <= e)
                && s.executed.is_none_or(|x| x < height.value())
            {
                s = cv.wait(s).unwrap_or_else(|_| {
                    panic!("state mutex poisoned: a holder panicked mid-mutation")
                });
            }
        }
        let root = primitives::sync::lock_state(&self.state_roots).get(&height.value()).copied();
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
        primitives::sync::lock_state(&self.state_roots)
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
mod tests;
