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
pub mod durability;
pub mod occ;

pub use durability::{DurabilityConfig, DurabilityError, RecoveryReport};

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

/// Saturation threshold for the execution lane's pending deque —
/// the debt at which the executor reports `exec_saturated` and the
/// engine starts withholding votes and deferring commit walks.
///
/// Unit: committed-but-unexecuted blocks. A committed block can
/// never be *dropped* — it must execute eventually — so the depth
/// is a signal, not a queue bound: past it, the engine-side gates
/// are what actually stop new commits from arriving (a withheld
/// vote is the throttle; the pump thread itself never blocks on
/// the lane). The worker holds at most one additional in-flight
/// block, so the lag a saturated engine tolerates is roughly
/// `EXEC_LANE_DEPTH + 1` heights — far inside the default
/// [`MAX_RETAINED_HISTORY`] window, which keeps every unexecuted
/// block reachable by the inline backlog drain. Origin: the audit
/// requires execution lag to be *bounded* — an unbounded queue let
/// consensus run arbitrarily ahead while `finalized` pruned to a
/// fixed window, so a dead lane could leave committed heights
/// already evicted and unexecutable. Tradeoff: a deeper threshold
/// absorbs commit bursts before the engine self-throttles; a
/// shallower one tightens the lag bound and shrinks worst-case
/// queued tx bytes. 64 keeps saturation rare (attestations already
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

/// The machine-readable class of a module rejection.
///
/// `ModuleRejected` used to carry only a free-form string, which made
/// every semantic distinction — insufficient funds vs missing market
/// vs wrong owner — unmatchable without string parsing. The category
/// is the stable half admission, verdict, and RPC paths may branch on;
/// the human `detail` remains for logs and error messages.
///
/// Distinction that matters to callers: `InsufficientFunds`,
/// `Unauthorized`, `NotFound`, `InvalidInput`, and `Precondition` are
/// *user-actionable* transaction rejections (the operation failed; the
/// tx still consumed its nonce and fee like an EVM revert).
/// `Internal` marks a module-side invariant or wiring break — those
/// warrant operator attention, not user retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectCategory {
    /// A balance, escrow, margin, or fee check failed — the account
    /// could not cover the required amount.
    InsufficientFunds,
    /// The sender lacks authority for the operation: not the object
    /// owner, not the operator, not a committee member, bad signer.
    Unauthorized,
    /// A referenced object does not exist: market, order, validator,
    /// proposal, delegation, account.
    NotFound,
    /// The message itself is invalid for this module regardless of
    /// state: zero amount, out-of-range value, malformed argument.
    InvalidInput,
    /// The object exists but state forbids the operation right now:
    /// already exists, wrong phase, halted or paused, registry full.
    /// Typically retryable only after state changes.
    Precondition,
    /// The module's own state path failed mid-handler — a wiring or
    /// invariant break (refund failed, engine returned an internal
    /// error), not user error. Investigate, don't retry.
    Internal,
    /// The rejection doesn't fit a narrower category.
    Other,
}

impl std::fmt::Display for RejectCategory {
    /// The stable lowercase token used when the category prefixes a
    /// rejection reason at wire seams (e.g. `insufficient_funds: …`).
    /// Treat as an API surface — match tokens are never renamed
    /// without a versioned change.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            RejectCategory::InsufficientFunds => "insufficient_funds",
            RejectCategory::Unauthorized => "unauthorized",
            RejectCategory::NotFound => "not_found",
            RejectCategory::InvalidInput => "invalid_input",
            RejectCategory::Precondition => "precondition",
            RejectCategory::Internal => "internal",
            RejectCategory::Other => "rejected",
        };
        f.write_str(token)
    }
}

/// A module's rejection of a well-formed message: a typed
/// [`RejectCategory`] for machines plus a human-readable `detail`
/// for logs, verdicts, and RPC reason strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRejection {
    /// Stable classification — safe to branch on.
    pub category: RejectCategory,
    /// Human-readable context (which market, which balance). Not a
    /// stable API: match on `category`, never on this string.
    pub detail: String,
}

impl ModuleRejection {
    /// A rejection in `category` with a human-readable `detail`.
    pub fn new(category: RejectCategory, detail: impl Into<String>) -> Self {
        Self { category, detail: detail.into() }
    }
}

impl std::fmt::Display for ModuleRejection {
    /// Renders `"category: detail"`. At the mempool/RPC seams the
    /// category token is a stable prefix clients may match on; the
    /// detail stays free-form.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.category, self.detail)
    }
}

/// A module execution error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The tx envelope is malformed.
    Malformed,
    /// The module is not registered.
    UnknownModule(u8),
    /// The module rejected the message. Carries a typed
    /// [`RejectCategory`] so admission and RPC paths classify
    /// without string-matching.
    ModuleRejected(ModuleRejection),
    /// Insufficient gas.
    OutOfGas,
}

impl ExecError {
    /// Shorthand constructor for a [`RejectCategory`]-typed module
    /// rejection — keeps handler call sites one line.
    pub fn rejected(category: RejectCategory, detail: impl Into<String>) -> Self {
        Self::ModuleRejected(ModuleRejection::new(category, detail))
    }

    /// The rejection category, if this is a module rejection.
    /// Executor-internal variants (`Malformed`, `UnknownModule`,
    /// `OutOfGas`) are pre-module failures with no module category.
    pub fn rejection_category(&self) -> Option<RejectCategory> {
        match self {
            ExecError::ModuleRejected(r) => Some(r.category),
            _ => None,
        }
    }
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Malformed => f.write_str("malformed transaction"),
            ExecError::UnknownModule(id) => write!(f, "unknown module {id}"),
            ExecError::ModuleRejected(r) => write!(f, "{r}"),
            ExecError::OutOfGas => f.write_str("out of gas"),
        }
    }
}

impl std::error::Error for ExecError {}

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
    /// The snapshot imported and verified, but writing the durable
    /// checkpoint that should preserve it across restarts failed
    /// (atomic `snapshot.bin` write, journal seal, or prune). The
    /// state IS installed — this variant exists so a caller cannot
    /// mistake a non-persisted import for a durable one: a node
    /// that continues after this error rewinds below the imported
    /// height on its next restart.
    CheckpointFailed {
        /// The underlying durability error, rendered.
        reason: String,
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
            Self::CheckpointFailed { reason } => {
                write!(f, "snapshot imported but checkpoint persistence failed: {reason}")
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
/// skipping secp256k1 recovery on the block execution hot path —
/// but ONLY when [`PreverifiedTx::verified_locally`] proves the
/// sender came from this node's own ingest recovery (hft-audit
/// F-06).
///
/// # Security
///
/// The pre-recovered sender must come from a trusted source (the
/// local mempool's `preverify_batch` call). `verified_locally` is
/// the load-bearing flag: it is set only where the cache key — a
/// `Domain::Transaction` hash computed locally over these exact
/// bytes — proves this node ran the recovery. A `false` flag keeps
/// the module's recover-and-compare gate, so a fabricated sender
/// from any other caller is still rejected.
#[derive(Debug, Clone)]
pub struct PreverifiedTx<'a> {
    /// The raw module payload bytes (e.g. RLP-encoded signed EVM tx),
    /// borrowed from the caller's transaction buffer — the batch hot
    /// path must not clone per-tx.
    pub raw: &'a [u8],
    /// The sender recovered from the signature (20 bytes).
    pub sender: [u8; 20],
    /// Provenance token for `sender` (hft-audit F-06): `true` iff the
    /// sender came from THIS node's own ingest-time recovery — the
    /// executor's preverify-cache drain is the only code that sets
    /// it, and only when the cache key (a locally-computed
    /// `Domain::Transaction` hash of `raw`) proves these exact bytes
    /// were verified here. Consumers may then trust `sender` and
    /// skip the ~30 µs secp256k1 recovery; every other caller must
    /// leave it `false`, which keeps the module's defensive
    /// recover-and-compare gate. Setting it on an unverified sender
    /// silently misattributes execution — that is an in-process
    /// contract violation, exactly like fabricating `sender` itself.
    pub verified_locally: bool,
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

    /// Validate a message for mempool admission with the sender
    /// already recovered by [`preverify_batch`](Self::preverify_batch).
    ///
    /// Why this exists: the EVM's `validate` and `preverify_batch`
    /// both decode the RLP and recover the secp256k1 sender — the
    /// two most expensive per-tx intake operations, paid TWICE per
    /// tx on the old path (~90µs/tx intake measured, of which ~32µs
    /// was the duplicated recovery+decode). Batch intake now runs
    /// `preverify_batch` once per module group (parallel across the
    /// batch) and hands each result here, so the recovery is paid
    /// exactly once.
    ///
    /// The contract is `validate`'s, with one addition: when
    /// `preverified` carries a sender, the module MUST NOT recover
    /// again — the preverify pass already authenticated the payload
    /// signature for these exact bytes. `None` means no preverify
    /// ran (single-tx path on a module without pre-verification);
    /// the default delegates to `validate`, so modules that don't
    /// override this behave exactly as before.
    ///
    /// # Errors
    ///
    /// Same contract as [`validate`](Self::validate).
    fn validate_preverified(
        &self,
        ctx: &TxContext,
        msg: &[u8],
        preverified: Option<&PreverifiedTx<'_>>,
    ) -> Result<(), ExecError> {
        let _ = preverified;
        self.validate(ctx, msg)
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
        msgs.iter()
            .map(|raw| Ok(PreverifiedTx { raw, sender: [0u8; 20], verified_locally: false }))
            .collect()
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
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                format!(
                    "state version {from} is newer than module's declared {}",
                    self.state_version()
                ),
            ));
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
    /// entry is `(staking_address, new_bls_key)` where the key is a
    /// [`ValidatedPublicKey`] — the token proves the module
    /// validated the point at admission, so the engine folds it
    /// without a re-check and an unchecked key cannot cross.
    ///
    /// # Default
    ///
    /// Returns empty — most modules don't track key changes. Only
    /// the staking module overrides this.
    fn take_key_changes(&self) -> Vec<(Address, crypto::bls_signer::ValidatedPublicKey)> {
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
/// addresses to remove. The key in each add is a
/// [`ValidatedPublicKey`](crypto::bls_signer::ValidatedPublicKey):
/// proof that the admitting module ran point + subgroup
/// validation, not just a 48-byte length check.
#[derive(Debug, Clone, Default)]
pub struct ValidatorChanges {
    /// Validators to add: `(address, bls_public_key, stake)`.
    pub adds: Vec<(Address, crypto::bls_signer::ValidatedPublicKey, u64)>,
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
        /// `Arc`-shared with the block event log (hft-audit F-08):
        /// the outcome store and `Executor::events` hold the same
        /// allocation — recording a result bumps a refcount instead
        /// of deep-copying every event the tx emitted.
        events: std::sync::Arc<[Event]>,
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
///
/// Kept as a named type alias for `exec::PlannedTx` — the real
/// type lives in `exec.rs`, where private fields make
/// `plan_block_runs` the only mint site.
type GroupedTx<'a> = exec::PlannedTx<'a>;

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
    /// `true` once [`Executor::spawn_exec_lane`] has installed the
    /// worker thread — the async-lane gate `attest_state` and
    /// `finalize_block` read (replacing the old channel-handle
    /// `OnceLock`: the deque below is the hand-off now, so the only
    /// question callers ask is "does a lane exist").
    lane_spawned: bool,
    /// Committed blocks handed to the worker but not yet popped —
    /// the lane's work queue. Unbounded because a committed block
    /// can never be dropped: the real bound is [`EXEC_LANE_DEPTH`]
    /// as a *signal* — crossing it sets `saturated` and the engine
    /// throttles new commits at the source. Condvar-signalled on
    /// every push; drained strictly in commit order.
    pending: std::collections::VecDeque<FinalizedBlock>,
    /// `pending` exceeded [`EXEC_LANE_DEPTH`] — the engine reads
    /// this via `exec_saturated` and withholds votes + defers
    /// commit walks until the worker drains the deque empty. The
    /// empty-to-clear rule gives hysteresis for free: a flap at the
    /// threshold boundary means the lane is at the edge of
    /// catching up, and only a fully drained queue proves it has.
    saturated: bool,
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
    /// Phase D: once-only spawn latch for the execution lane.
    /// `spawn_exec_lane` sets it before installing the worker, so a
    /// second spawn is refused loudly rather than silently splitting
    /// the commit stream between two workers.
    exec_lane_once: std::sync::OnceLock<()>,
    /// Execution progress shared with the worker: watermarks, the
    /// pending deque, and the saturation flag. `attest_state`
    /// waits on the condvar only while the requested height is
    /// enqueued-but-not-yet-executed — preserving the synchronous
    /// contract that an attested height's root exists, without
    /// blocking callers that attest a height the lane never saw.
    exec_sync: std::sync::Arc<(Mutex<ExecSync>, std::sync::Condvar)>,
    /// Pending events from the current block (cleared each block).
    /// Each entry is the `Arc<[Event]>` of one tx (or one module's
    /// `end_block` output) — shared with the tx's [`TxOutcome`] so
    /// the block log never deep-copies event payloads (F-08).
    events: Mutex<Vec<std::sync::Arc<[Event]>>>,
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
    preverify_cache: Mutex<primitives::digest_map::DigestMap<[u8; 20]>>,
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
    /// Live chain-level execution parameters — block gas limit,
    /// block byte budget, and the minimum envelope-fee floor —
    /// shared with the consensus engine and the governance `chain.*`
    /// parameter sink (see [`types::ChainParams`]). The executor's
    /// enforcement points read the atomics on every block so a
    /// timelocked governance apply lands here at the same height it
    /// lands in the engine's proposal budget.
    ///
    /// `with_gas_limit`/`with_min_fee` configure the atomics before
    /// the `Arc` is shared; a private default `Arc` exists until
    /// [`Executor::with_chain_params`] installs the shared handle.
    chain_params: Arc<types::ChainParams>,
    /// The module that collects transaction fees (the EVM ledger).
    /// When set, every non-self-funded module's txs are charged
    /// `ctx.fee` through this module before execution — previously
    /// the charge was dispatched to the *target* module, so any
    /// module that didn't implement `charge_fee` executed for free.
    ///
    /// `None` = no fee collection (tests and dev-mode executors).
    fee_module: Option<u8>,
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
    /// Crash-durability wiring: the finalized-block journal +
    /// checkpoint state installed by [`Executor::with_durability`].
    /// `None` = in-memory only (tests, sims, and throwaway nodes);
    /// nodes configured with a data directory always install it.
    durability: Option<durability::Durability>,
    /// Logical CPU the exec lane pins to (`hft-audit` F-02) — the
    /// whole finalized-block → state-root path runs on one thread,
    /// so keeping it resident on one core stops cache thrash from
    /// migrations. `None` = unpinned (default; dev/test never set
    /// it). Validation (core in the online set) happens at config
    /// load, not here.
    exec_lane_core: Option<u32>,
}

mod app_iface;
mod exec;
mod lane;
mod snapshot;

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
        // The intake ring is the mempool's staging buffer — bounded
        // by the same admission budget. A fixed 10k slot ring
        // thrashed at large blocks: a 10k-tx round filled it exactly,
        // so every subsequent round's submission bounced off the
        // full ring and retried (measured: submit phase doubled at
        // 10k txs/round in the EVM load test). Ring capacity =
        // mempool capacity keeps `submit_ahead` rounds of headroom
        // honest: the ring can always hold what the pool can.
        let (intake_tx, intake_rx) = std::sync::mpsc::sync_channel(max_mempool_entries);
        Self {
            modules: std::array::from_fn(|_| None),
            mempool: Mutex::new(mempool::Mempool::new(max_mempool_entries)),
            finalized: Mutex::new(BTreeMap::new()),
            state_roots: Mutex::new(BTreeMap::new()),
            next_proposal_height: Mutex::new(0),
            exec_lane_once: std::sync::OnceLock::new(),
            exec_sync: std::sync::Arc::new((
                Mutex::new(ExecSync {
                    enqueued: None,
                    executed: None,
                    lane_dead: false,
                    lane_spawned: false,
                    pending: std::collections::VecDeque::new(),
                    saturated: false,
                    in_flight: None,
                }),
                std::sync::Condvar::new(),
            )),
            events: Mutex::new(Vec::new()),
            tx_outcomes: Mutex::new(TxOutcomeStore::default()),
            preverify_cache: Mutex::new(primitives::digest_map::DigestMap::default()),
            parallel_threshold,
            recorder: None,
            mempool_intake_tx: intake_tx,
            mempool_intake_rx: Mutex::new(intake_rx),
            executed_nonce: Mutex::new(Arc::new(ExecutedNonces::default())),
            chain_params: Arc::new(types::ChainParams {
                max_gas: std::sync::atomic::AtomicU64::new(DEFAULT_BLOCK_GAS_LIMIT),
                max_bytes: std::sync::atomic::AtomicU64::new(types::CHAIN_BLOCK_MAX_BYTES),
                min_fee: std::sync::atomic::AtomicU64::new(0),
            }),
            fee_module: None,
            chain_id: 1,
            unsigned_tx_policy: UnsignedTxPolicy::Reject,
            history_retention: MAX_RETAINED_HISTORY,
            durability: None,
            exec_lane_core: None,
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

    /// Pin the exec lane to logical CPU `core` (hft-audit F-02).
    ///
    /// The lane is the single writer for block execution → state
    /// attestation; pinning stops the scheduler migrating it between
    /// cores (cold L1/L2 on every hop). A failed pin logs and the
    /// lane runs unpinned — locality is a latency property, never a
    /// correctness one. Validate `core` against
    /// `primitives::pin::online_cpus()` at config time.
    #[must_use]
    pub fn with_exec_lane_pin(mut self, core: Option<u32>) -> Self {
        self.exec_lane_core = core;
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
    /// 1 gas per byte of payload. The limit lives in the shared
    /// [`types::ChainParams`], so a later governance apply over the
    /// `chain.block_gas_limit` key can move it again at runtime.
    #[must_use]
    pub fn with_gas_limit(self, limit: u64) -> Self {
        self.chain_params.max_gas.store(limit, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Install the shared chain-parameters handle.
    ///
    /// Node assembly creates one `Arc<ChainParams>` seeded from the
    /// chain config and installs it here, on the consensus engine,
    /// and behind the governance `chain.*` sink — the enforcement
    /// points then read one set of atomics. Until this is called the
    /// executor reads a private default handle, so standalone
    /// executors behave exactly as before.
    ///
    /// The handle is authoritative once installed: seed it before
    /// sharing (stores made via [`Self::with_gas_limit`]/
    /// [`Self::with_min_fee`] on the previous handle do not carry
    /// over).
    #[must_use]
    pub fn with_chain_params(mut self, params: Arc<types::ChainParams>) -> Self {
        self.chain_params = params;
        self
    }

    /// The shared chain-parameters handle — the `Arc` the engine and
    /// the governance sink must see the same instance of.
    pub fn chain_params(&self) -> Arc<types::ChainParams> {
        Arc::clone(&self.chain_params)
    }

    /// The live block gas limit — read through the shared params so
    /// a governance apply takes effect at the same height on every
    /// enforcement point.
    fn block_gas_limit(&self) -> u64 {
        self.chain_params.max_gas.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The live minimum envelope-fee floor — same shared-params
    /// read path as [`Self::block_gas_limit`].
    fn min_fee(&self) -> u64 {
        self.chain_params.min_fee.load(std::sync::atomic::Ordering::Relaxed)
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
    pub fn with_min_fee(self, min_fee: u64) -> Self {
        self.chain_params.min_fee.store(min_fee, std::sync::atomic::Ordering::Relaxed);
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

    /// The current chain height (the highest finalized block).
    ///
    /// Returns 0 if no blocks have been finalized yet (genesis state).
    #[must_use]
    pub fn current_height(&self) -> u64 {
        let next = *primitives::sync::lock_state(&self.next_proposal_height);
        next.saturating_sub(1)
    }

    /// The highest height with a recorded state root — `None` when no
    /// block has executed yet.
    ///
    /// Unlike [`Self::current_height`] (which saturates at 0 for the
    /// empty chain), this distinguishes "nothing committed" from
    /// "block 0 committed" — the distinction journal replay and
    /// checkpoint gating need around the genesis boundary.
    #[must_use]
    pub fn committed_height(&self) -> Option<u64> {
        primitives::sync::lock_state(&self.state_roots).keys().next_back().copied()
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
    /// Returns `Vec<(staking_address, new_bls_key)>` — each key a
    /// [`ValidatedPublicKey`](crypto::bls_signer::ValidatedPublicKey)
    /// proven at module admission. The caller passes these to
    /// `OxideBft::apply_key_changes` which builds the updated
    /// `ValidatorSet` and schedules an epoch rotation.
    #[must_use]
    pub fn take_pending_key_changes(
        &self,
    ) -> Vec<(Address, crypto::bls_signer::ValidatedPublicKey)> {
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
    /// The tx's index into the caller's `Vec<TxBytes>` — the tx is
    /// moved into the pool only after every borrow into the batch
    /// (payload slices in the preverify results) is dead.
    tx_idx: usize,
}

#[cfg(test)]
mod tests;
