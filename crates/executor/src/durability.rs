//! Crash durability for the executor: a finalized-block journal,
//! replay, and atomic checkpoints.
//!
//! ## The problem this solves
//!
//! The EVM module flushes its account state to its own backend every
//! block, but every other module (staking, exchange, perps, oracle,
//! governance, core) — plus the executed-nonce replay-protection map —
//! lived only in memory between shutdown snapshots. A crash could
//! therefore restart with the EVM at height *H* and every native
//! module at an earlier height or genesis: a cross-module torn state
//! that no amount of consensus WAL could repair, and a replay window
//! where already-executed nonces looked fresh again.
//!
//! ## The design
//!
//! **Journal ⊇ applied state, always.** `finalize_block` appends the
//! `FinalizedBlock`'s bytes to a [`storage::journal`] (CRC-checked,
//! segmented, fsync'd) *before* any module state mutates — before the
//! mempool removal, before execution, before the lane hand-off. The
//! consensus engine calls `finalize_block` strictly before it WALs
//! its own commit record, so the journal is always at least as far
//! along as anything consensus considers committed.
//!
//! **Baseline record.** The first append to a *fresh* journal first
//! writes a checkpoint record carrying a full [`ExecutorSnapshot`] of
//! the pre-block state (genesis, or the state restored from
//! `snapshot.bin`). Replay re-imports it, which wholesale replaces
//! every module's committed state — including the EVM backend — so
//! replay never double-applies onto an EVM whose own per-block flush
//! already advanced past the base.
//!
//! **Replay.** On boot, [`Executor::recover_durable_state`] imports
//! `snapshot.bin` if present, then walks the journal: checkpoint
//! records at-or-above the current base are imported; block records
//! above it are pushed through `insert_finalized` +
//! `execute_committed_backlog` — the same drain the lane-death path
//! uses — so roots, nonces, and `tx_outcomes` land exactly as the
//! live run produced them. Heights must be contiguous: a gap means
//! the journal cannot produce a correct state, and recovery fails
//! loudly rather than diverging.
//!
//! **Checkpoints bound replay.** Every `checkpoint_interval` heights
//! (and on shutdown via [`Executor::durable_checkpoint`]) the
//! executor drains the lane, exports a snapshot, and writes
//! `snapshot.bin` atomically — write to `.tmp`, fsync, rename,
//! fsync the directory — so a crash mid-write leaves either the old
//! snapshot or the new one, never a torn file. The journal is then
//! sealed (recording its height index) and segments fully covered
//! by the checkpoint are pruned, bounding both disk use and
//! worst-case replay length to roughly one interval.
//!
//! ## Record format
//!
//! Each journal record payload is `[tag: u8][bytes]`:
//! - `0x00` — [`FinalizedBlock`] codec bytes (txs, signers, and the
//!   execution context, so replay re-executes under the values the
//!   live run committed).
//! - `0x01` — `[next_block: u64][ExecutorSnapshot]` codec bytes (a
//!   checkpoint record; `next_block` names the first height that
//!   still must replay on top, since `snapshot.height` cannot
//!   distinguish "nothing executed" from "block 0 executed" at the
//!   genesis boundary). Only the baseline uses this today — periodic
//!   checkpoints are whole-file `snapshot.bin` writes because
//!   snapshots can exceed the journal's per-record size ceiling.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use codec::{Decode, Encode};
use storage::journal::{self, JournalConfig, JournalWriter};

use super::{Executor, ExecutorSnapshot, FinalizedBlock, SnapshotImportError};

/// Directory inside [`DurabilityConfig::dir`] holding the block
/// journal's segment files. A subdirectory — not a single file —
/// because the journal is segmented (`segment-<n>.log`) with a
/// `heights.idx` pruning sidecar. `pub(crate)` so crash-recovery
/// tests can address the same directory the writer uses.
pub(crate) const JOURNAL_DIR_NAME: &str = "block-journal";

/// The checkpoint file inside [`DurabilityConfig::dir`] — the same
/// `snapshot.bin` the devnet auto-persistence convention already
/// uses, so the durability checkpoint and the shutdown snapshot are
/// one artifact.
const SNAPSHOT_FILE_NAME: &str = "snapshot.bin";

/// Journal record tag: a committed block.
const TAG_BLOCK: u8 = 0x00;
/// Journal record tag: a checkpoint (full [`ExecutorSnapshot`]).
const TAG_CHECKPOINT: u8 = 0x01;

/// Default blocks between checkpoint writes.
///
/// Origin: matches `MAX_RETAINED_HISTORY` (4096) — the window the
/// executor already keeps hot in memory — so worst-case crash replay
/// is the same order of work the in-memory history covers anyway.
/// Tradeoff: halving it doubles the frequency of the O(state)
/// export + fsync stall on the commit path; doubling it doubles
/// worst-case replay length and unpruned journal size.
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 4096;

/// Durability configuration for [`Executor::with_durability`].
#[derive(Debug, Clone)]
pub struct DurabilityConfig {
    /// The node's data directory. The block journal lives at
    /// `<dir>/block-journal/`; checkpoints write
    /// `<dir>/snapshot.bin`. Conventionally the same `data_dir`
    /// whose `evm.redb` backs the EVM module.
    pub dir: PathBuf,
    /// Heights between checkpoint writes — see
    /// [`DEFAULT_CHECKPOINT_INTERVAL`] for the tradeoff. A checkpoint
    /// costs one lane-draining O(state) export + fsync; each one
    /// bounds crash replay to the blocks after it.
    pub checkpoint_interval: u64,
}

impl DurabilityConfig {
    /// Durability rooted at `dir` with the default checkpoint
    /// interval.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into(), checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL }
    }

    /// Override the checkpoint cadence (blocks between checkpoints).
    #[must_use]
    pub fn with_checkpoint_interval(mut self, interval: u64) -> Self {
        self.checkpoint_interval = interval;
        self
    }
}

/// Why a durability operation failed. Split by responsibility:
/// `Journal`/`Io` are operational (disk, permissions) while `Gap`,
/// `UnknownRecordTag`, and `Import` indicate a journal that cannot
/// produce a correct state — a foreign, corrupt, or truncated-below-
/// the-base history that must stop the boot, not be replayed past.
#[derive(Debug)]
pub enum DurabilityError {
    /// Journal write/read failure.
    Journal(journal::JournalError),
    /// Snapshot file IO failure (read, atomic write, rename).
    Io(std::io::Error),
    /// A journal record's payload failed codec decode — the journal
    /// is corrupt or written by an incompatible binary.
    Decode(codec::DecodeError),
    /// A checkpoint record or `snapshot.bin` failed snapshot import
    /// verification — the staged state did not reproduce its claimed
    /// root.
    Import(SnapshotImportError),
    /// A block record's height is not the successor of the last
    /// applied height: the journal has a hole it cannot fill, so
    /// replaying further would silently skip committed history.
    JournalGap {
        /// The height replay expected next.
        expected: u64,
        /// The height the journal actually carried.
        found: u64,
    },
    /// A journal record's tag byte is neither [`TAG_BLOCK`] nor
    /// [`TAG_CHECKPOINT`] — foreign or corrupt content.
    UnknownRecordTag(u8),
}

impl std::fmt::Display for DurabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Journal(e) => write!(f, "block journal: {e}"),
            Self::Io(e) => write!(f, "durability io: {e}"),
            Self::Decode(e) => write!(f, "journal record decode failed: {e}"),
            Self::Import(e) => write!(f, "checkpoint import failed: {e}"),
            Self::JournalGap { expected, found } => {
                write!(f, "journal gap: expected height {expected}, found {found}")
            }
            Self::UnknownRecordTag(tag) => {
                write!(f, "journal record with unknown tag {tag:#04x}")
            }
        }
    }
}

impl std::error::Error for DurabilityError {}

impl From<journal::JournalError> for DurabilityError {
    fn from(e: journal::JournalError) -> Self {
        Self::Journal(e)
    }
}

impl From<std::io::Error> for DurabilityError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<codec::DecodeError> for DurabilityError {
    fn from(e: codec::DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<SnapshotImportError> for DurabilityError {
    fn from(e: SnapshotImportError) -> Self {
        Self::Import(e)
    }
}

/// What [`Executor::recover_durable_state`] did at boot.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryReport {
    /// The height of the imported `snapshot.bin`, if one was present
    /// and imported cleanly.
    pub snapshot_height: Option<u64>,
    /// Why `snapshot.bin` was skipped, if it existed but failed to
    /// decode or import. Recovery then fell back to the journal —
    /// which is authoritative anyway — but the rejection is reported
    /// so a corrupt checkpoint is never silent.
    pub snapshot_rejected: Option<String>,
    /// Block records re-executed from the journal.
    pub blocks_replayed: u64,
    /// The height recovery leaves the executor at: the greater of
    /// the snapshot height and the journal tip.
    pub recovered_height: u64,
}

/// The journal writer plus the baseline flag, locked together —
/// `finalize_block` takes `&self`, so the writer lives behind a
/// mutex. The critical section covers one record append + fsync per
/// block; it is never held across module execution.
struct JournalState {
    writer: JournalWriter,
    /// Whether the baseline checkpoint record has been written (or
    /// never needed — a journal that opened non-empty already has
    /// its base, whether as a baseline record or pruned in favor of
    /// `snapshot.bin`).
    baseline_done: bool,
}

/// Executor-side durability wiring, installed by
/// [`Executor::with_durability`].
pub(crate) struct Durability {
    /// Journal writer + baseline flag. Lock ordering: this mutex is
    /// only ever taken alone; checkpoint takes it *after* the
    /// snapshot write completes.
    journal: Mutex<JournalState>,
    /// Data directory — journal at `dir/block-journal`, checkpoints
    /// at `dir/snapshot.bin`.
    dir: PathBuf,
    /// Heights between checkpoint writes (`DurabilityConfig`).
    checkpoint_interval: u64,
}

impl Durability {
    fn journal_dir(&self) -> PathBuf {
        self.dir.join(JOURNAL_DIR_NAME)
    }

    fn snapshot_path(&self) -> PathBuf {
        self.dir.join(SNAPSHOT_FILE_NAME)
    }
}

/// Write `bytes` to `path` atomically: write `path.tmp`, fsync the
/// file, rename over `path`, fsync the directory.
///
/// A crash lands on one of two complete states — the old file or the
/// new one — never a torn `snapshot.bin`. This is the standard
/// write-tmp-fsync-rename-fsync-dir protocol; both fsyncs are
/// required (the rename is a directory entry, durable only when the
/// directory itself is synced).
///
/// On non-Unix targets the directory fsync is skipped (`File::open`
/// on a directory needs platform flags std does not expose) — the
/// rename is still atomic there.
///
/// # Errors
///
/// Returns the underlying `io::Error` from any step; on failure the
/// destination is either untouched or holds the complete new file.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // `rename` replaces atomically on Unix. On Windows it fails if
    // the destination exists — remove then rename, accepting the
    // small non-atomic gap on that platform only (a crash in the gap
    // leaves no snapshot.bin, which journal replay covers).
    if let Err(e) = std::fs::rename(&tmp, path) {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(&tmp, path).map_err(|_| e)?;
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

impl Executor {
    /// Enable crash durability rooted at `config.dir`.
    ///
    /// Opens the block journal at `<dir>/block-journal` (replaying it
    /// first, per the journal's recovery contract — a torn old tail is
    /// never appended onto — then continuing in a fresh segment) and
    /// remembers whether the journal opened empty, which decides
    /// whether the first `finalize_block` must write a baseline
    /// checkpoint record.
    ///
    /// # Errors
    ///
    /// [`journal::JournalError::Io`] if the journal directory cannot be
    /// created, scanned, or the new segment file cannot be opened — a
    /// node that cannot journal must not serve undurably.
    pub fn with_durability(mut self, config: DurabilityConfig) -> Result<Self, DurabilityError> {
        let journal_dir = config.dir.join(JOURNAL_DIR_NAME);
        // The journal's own recovery flow is replay-then-create:
        // scanning first tells us whether a baseline record is needed
        // (an empty journal has no base) and leaves torn tails behind
        // a fresh segment boundary.
        let opened_empty = journal::replay(&journal_dir)?.records.is_empty();
        let writer = JournalWriter::create(&journal_dir, JournalConfig::default())?;
        self.durability = Some(Durability {
            journal: Mutex::new(JournalState { writer, baseline_done: !opened_empty }),
            dir: config.dir,
            checkpoint_interval: config.checkpoint_interval,
        });
        Ok(self)
    }

    /// Journal `block` before any of its effects apply — the "journal
    /// ⊇ applied state" invariant.
    ///
    /// On the first append to a fresh journal, a baseline checkpoint
    /// record (a full `ExecutorSnapshot` of the pre-block state) is
    /// written first so replay always has a verified base to import —
    /// without it, an EVM backend that already flushed past the base
    /// would be double-applied onto.
    ///
    /// `append` is memory-only — this call leaves the record in the
    /// journal's group buffer and returns. The *sync* is deferred to
    /// [`journal_sync_pending`](Self::journal_sync_pending), which the
    /// three durability barriers invoke:
    ///
    /// - the execution lane / inline drain, before any block executes
    ///   (journal stays ahead of the EVM backend's per-block durable
    ///   flush — durable state never outruns the journal);
    /// - the engine's signature-gated WAL sync via
    ///   [`AppInterface::commit_durability_barrier`] — consensus's
    ///   commit record can never be durable while its journal record
    ///   was still buffered, or a restart could believe a height
    ///   committed that the journal never received;
    /// - checkpoints and shutdown export (`seal_and_rotate` flushes
    ///   and fsyncs the buffer; `export_snapshot` drains first).
    ///
    /// One sync per drain batch (or per signature emission while
    /// records are pending) replaces the old per-block fsync — the
    /// commit path no longer pays a disk round-trip per finalized
    /// block.
    ///
    /// # Panics
    ///
    /// Panics on any journal error: a finalized block that cannot be
    /// journaled cannot be recovered after a crash, so continuing
    /// would silently trade durability for liveness. Halting matches
    /// the executor's fail-closed convention for partially applied
    /// blocks.
    pub(crate) fn journal_append(&self, block: &FinalizedBlock) {
        let Some(durability) = &self.durability else { return };
        let mut state = primitives::sync::lock_state(&durability.journal);
        if !state.baseline_done {
            // The baseline is the journal's record #0: a full snapshot
            // of the state blocks replay onto. Captured lazily here
            // (not at `with_durability`) because module registration
            // and genesis land *between* construction and the first
            // finalize — the snapshot must contain them. The inner
            // export skips the lane drain and journal sync: this is
            // the FIRST commit, so nothing is queued yet, and the
            // journal lock we hold must not be re-entered.
            let snapshot = self.export_snapshot_inner();
            let mut payload = Vec::with_capacity(1 + 64);
            payload.push(TAG_CHECKPOINT);
            // `next_block` names the first height that still must
            // replay on top of this snapshot — the block being
            // journaled right now. It is required because
            // `snapshot.height` cannot express coverage at the
            // genesis boundary: `current_height()` saturates at 0,
            // which means both "nothing executed" and "block 0
            // executed". Replay reads coverage from `next_block`,
            // never from `snapshot.height`.
            block.height.value().encode(&mut payload);
            snapshot.encode(&mut payload);
            state
                .writer
                .append_at_height(snapshot.height, &payload)
                .unwrap_or_else(|e| panic!("executor: failed to journal baseline checkpoint: {e}"));
            state.baseline_done = true;
        }
        let mut payload = Vec::with_capacity(64);
        payload.push(TAG_BLOCK);
        block.encode(&mut payload);
        state.writer.append_at_height(block.height.value(), &payload).unwrap_or_else(|e| {
            panic!(
                "executor: failed to journal committed block {}: {e} — \
                     halting rather than serving undurable finality",
                block.height.value()
            )
        });
    }

    /// The deferred durability point for [`journal_append`](Self::journal_append):
    /// flush + fdatasync everything buffered so far, or a no-op when
    /// the journal is already clean. Every barrier that must order
    /// "journal durable" before something else — module execution
    /// (whose EVM backend flush is durable) or the consensus WAL's
    /// commit evidence — runs this; the dirty-check keeps the
    /// common already-synced case syscall-free.
    ///
    /// # Panics
    ///
    /// Panics on any journal error, same fail-closed convention as
    /// [`journal_append`](Self::journal_append).
    pub(crate) fn journal_sync_pending(&self) {
        let Some(durability) = &self.durability else { return };
        primitives::sync::lock_state(&durability.journal).writer.sync_if_dirty().unwrap_or_else(
            |e| {
                panic!(
                    "executor: failed to sync committed-block journal: {e} — \
                        halting rather than serving undurable finality"
                )
            },
        );
    }

    /// Write a checkpoint at `height` when the interval divides it —
    /// called at the tail of `finalize_block`, after the block's
    /// execution has been recorded or handed to the lane.
    pub(crate) fn maybe_checkpoint(&self, height: u64) {
        let Some(durability) = &self.durability else { return };
        if height == 0 || !height.is_multiple_of(durability.checkpoint_interval) {
            return;
        }
        // A checkpoint that cannot complete (disk full, IO error)
        // fails loudly on the commit path: the journal stays correct
        // but unbounded, and silent skips are how "bounded replay"
        // regressions ship. Panic per the fail-closed convention.
        self.durable_checkpoint()
            .unwrap_or_else(|e| panic!("executor: checkpoint at height {height} failed: {e}"));
    }

    /// Write a durable checkpoint: drain the execution lane, export
    /// the quiesced state to `<dir>/snapshot.bin` atomically, then
    /// seal + prune journal segments the checkpoint covers.
    ///
    /// Returns `Ok(None)` when durability is not configured —
    /// callers (e.g. the shutdown path) fall back to a manual
    /// snapshot write.
    ///
    /// Ordering matters: the snapshot must be durable *before* the
    /// journal below it is pruned, or a crash between them leaves a
    /// journal whose replay base was deleted. `seal_and_rotate` runs
    /// first among the journal ops so the sealed segment gets a
    /// height-index entry and becomes prunable.
    ///
    /// # Errors
    ///
    /// [`DurabilityError`] on snapshot write or journal seal/prune
    /// failure. The checkpoint is all-or-nothing: a prune error
    /// leaves an oversized-but-correct journal, a write error leaves
    /// the journal unpruned and the old snapshot in place.
    pub fn durable_checkpoint(&self) -> Result<Option<u64>, DurabilityError> {
        let Some(durability) = &self.durability else { return Ok(None) };
        // Refuse to checkpoint an executor that has committed
        // nothing: `export_snapshot` would stamp `height = 0`,
        // which on disk is indistinguishable from "block 0
        // executed" — a height-0 `snapshot.bin` must therefore
        // always mean post-block-0. Nothing committed also means
        // nothing needs checkpointing: the journal's baseline
        // record is the base either way.
        if self.committed_height().is_none() {
            return Ok(None);
        }
        // `export_snapshot` drains the exec lane first, so the
        // checkpoint always captures a quiesced height boundary even
        // in async mode.
        let snapshot = self.export_snapshot();
        let mut buf = Vec::new();
        snapshot.encode(&mut buf);
        atomic_write(&durability.snapshot_path(), &buf)?;
        let mut state = primitives::sync::lock_state(&durability.journal);
        state.writer.seal_and_rotate()?;
        // `prune_below_height(h + 1)` deletes sealed segments whose
        // maximum record height is ≤ h — everything the checkpoint
        // covers. The active (newly rotated) segment is never
        // pruned; records above h keep replay possible.
        state.writer.prune_below_height(snapshot.height.saturating_add(1))?;
        Ok(Some(snapshot.height))
    }

    /// Recover executor state from the durability directory: import
    /// `snapshot.bin` if present, then replay the block journal on
    /// top. Returns `Ok(None)` when durability is not configured.
    ///
    /// Replay is deterministic: block records carry the full
    /// `FinalizedBlock` (txs + signers + committed execution
    /// context), and `execute_committed_backlog` re-executes them in
    /// height order through the identical `execute_block` path the
    /// live run used — so `state_root_at(h)`, module state, and
    /// executed nonces all land at the same values peers hold.
    ///
    /// A corrupt `snapshot.bin` is *not* fatal: the journal is the
    /// authority, and its baseline record provides a complete base —
    /// the rejection is reported on the [`RecoveryReport`] and
    /// recovery continues from the journal alone. A journal gap or
    /// corrupt record IS fatal — replaying past either would produce
    /// a state no peer shares.
    ///
    /// # Errors
    ///
    /// [`DurabilityError`] on journal IO failure, undecodable or
    /// unknown record tags, a height gap, or a checkpoint record
    /// that fails import verification.
    ///
    /// # Panics
    ///
    /// Panics if a journaled block fails to execute on replay —
    /// the same fail-closed rule `execute_committed_backlog` applies
    /// to lane-death replays.
    pub fn recover_durable_state(&self) -> Result<Option<RecoveryReport>, DurabilityError> {
        let Some(durability) = &self.durability else { return Ok(None) };
        let mut report = RecoveryReport::default();

        // Phase 1 — snapshot.bin (the last checkpoint). On decode or
        // import failure we continue to the journal: its baseline
        // record is a complete base, so a torn or foreign checkpoint
        // degrades to a longer replay rather than a dead node.
        let snap_path = durability.snapshot_path();
        if snap_path.exists() {
            let imported =
                std::fs::read(&snap_path).map_err(DurabilityError::Io).and_then(|bytes| {
                    let mut reader = codec::Reader::new(&bytes);
                    let snap = ExecutorSnapshot::decode(&mut reader)?;
                    self.import_snapshot(&snap).map_err(DurabilityError::Import)?;
                    Ok(snap.height)
                });
            match imported {
                Ok(height) => report.snapshot_height = Some(height),
                Err(e) => report.snapshot_rejected = Some(e.to_string()),
            }
        }

        // Phase 2 — journal replay. `covered` tracks the highest
        // committed height already in place — `None` when nothing has
        // executed. The discriminator is `committed_height()` (the
        // `state_roots` map's tip), NOT `current_height()`: the latter
        // saturates at 0, which means both "genesis, nothing executed"
        // and "block 0 executed" — conflating them would either skip
        // block 0's replay or double-apply it.
        let replay = journal::replay(&durability.journal_dir())?;
        let mut covered = self.committed_height();
        let mut applied_tip = covered.unwrap_or(0);
        for record in replay.records {
            let Some((&tag, payload)) = record.payload.split_first() else {
                return Err(DurabilityError::UnknownRecordTag(0xff));
            };
            match tag {
                TAG_CHECKPOINT => {
                    let mut reader = codec::Reader::new(payload);
                    // `next_block` is the first height that must still
                    // apply on top — see `journal_append` for why
                    // `snapshot.height` alone cannot carry it.
                    let next_block = u64::decode(&mut reader)?;
                    let snapshot = ExecutorSnapshot::decode(&mut reader)?;
                    // Import only a checkpoint that reaches at or past
                    // the covered floor — a stale baseline would
                    // rewind module state the snapshot.bin phase or a
                    // later checkpoint already advanced. `>=` because
                    // a checkpoint whose first live block is the next
                    // expected one still performs the module reset
                    // replay needs (an EVM backend durable ahead of
                    // its peers is exactly the case the baseline
                    // exists to undo).
                    let floor = covered.map_or(0, |c| c.saturating_add(1));
                    if next_block >= floor {
                        self.import_snapshot(&snapshot)?;
                        covered = next_block.checked_sub(1);
                        // `import_snapshot` plants a root at
                        // `snapshot.height`. When that height still
                        // has to replay (`snapshot.height >=
                        // next_block` — the height-0 baseline, whose
                        // stamped root is the *pre*-block state), the
                        // planted root would make the backlog drain
                        // believe the block already executed and skip
                        // it. Remove the marker; the real root lands
                        // when the block replays.
                        if snapshot.height >= next_block {
                            primitives::sync::lock_state(&self.state_roots)
                                .remove(&snapshot.height);
                        }
                    }
                }
                TAG_BLOCK => {
                    let mut reader = codec::Reader::new(payload);
                    let block = FinalizedBlock::decode(&mut reader)?;
                    let height = block.height.value();
                    if covered.is_some_and(|c| height <= c) {
                        continue; // covered by the checkpoint/snapshot
                    }
                    let expected = covered.map_or(0, |c| c.saturating_add(1));
                    if height != expected {
                        return Err(DurabilityError::JournalGap { expected, found: height });
                    }
                    // Stage, don't execute yet: the backlog drain
                    // below replays in height order through the same
                    // path the live commit used.
                    self.insert_finalized(height, block);
                    covered = Some(height);
                    applied_tip = height;
                    report.blocks_replayed += 1;
                }
                other => return Err(DurabilityError::UnknownRecordTag(other)),
            }
        }
        if report.blocks_replayed > 0 {
            self.execute_committed_backlog();
            // Watermarks: the replayed heights are committed and now
            // executed — recording both keeps `attest_state`'s
            // enqueued/executed contract honest for post-recovery
            // calls and lets `prepare_proposal` resume at tip + 1.
            {
                let (lock, cv) = &*self.exec_sync;
                let mut s = primitives::sync::lock_state(lock);
                s.enqueued = Some(s.enqueued.map_or(applied_tip, |e| e.max(applied_tip)));
                s.executed = Some(s.executed.map_or(applied_tip, |e| e.max(applied_tip)));
                cv.notify_all();
            }
            let next = applied_tip.saturating_add(1);
            let mut height = primitives::sync::lock_state(&self.next_proposal_height);
            if next > *height {
                *height = next;
            }
        }
        report.recovered_height = applied_tip;
        Ok(Some(report))
    }

    /// Repair-time import: install a peer-served, certificate-
    /// verified snapshot and rebuild execution on top of it — the
    /// in-process half of certified state repair after an
    /// execution-divergence halt.
    ///
    /// Unlike [`Executor::import_snapshot`] (used on cold paths where
    /// nothing is mid-flight), this variant is safe on a LIVE
    /// executor whose committed history kept executing on the
    /// diverged base while consensus kept finalizing:
    ///
    ///   1. The lane is quiesced first (skipped when `lane_dead` —
    ///      a dead worker cannot race, and the watermark it stopped
    ///      at would hang the wait forever).
    ///   2. [`Executor::import_snapshot`] performs the staged,
    ///      fully verified module reset — no payload byte installs
    ///      before every module's claimed root reproduces.
    ///   3. `state_roots` above the snapshot height are purged: they
    ///      were computed on the diverged base and must never answer
    ///      an attestation again. Roots at or below it are retained —
    ///      they predate the diverged height (or are the freshly
    ///      imported, certified one).
    ///   4. The lane's pending deque is drained without execution:
    ///      `finalize_block` journals every block before enqueueing,
    ///      so nothing is lost — the replay below refills
    ///      `finalized` — and no block the snapshot already covers
    ///      can be double-applied by a stale queue entry.
    ///   5. The durable journal refills `finalized` above the
    ///      snapshot height. `TAG_CHECKPOINT` records are skipped
    ///      unconditionally: a journaled checkpoint exported after
    ///      the divergence carries the same wrong state this repair
    ///      exists to remove — only the verified peer snapshot is a
    ///      trusted base. Heights must be contiguous from
    ///      `snapshot.height + 1`; a gap fails closed, because
    ///      replaying past a hole produces a state no peer shares.
    ///   6. `execute_committed_backlog` re-executes the gap through
    ///      the identical `execute_block` path the live commit used,
    ///      then the `enqueued`/`executed` watermarks and
    ///      `next_proposal_height` advance to the rebuilt tip.
    ///
    /// When durability is not configured the in-memory `finalized`
    /// map is the only block source; it must cover
    /// `snapshot.height + 1 ..= tip` contiguously or the repair
    /// reports [`DurabilityError::JournalGap`] — retention eviction
    /// cannot be undone in-process.
    ///
    /// Clearing the consensus divergence latch is deliberately NOT
    /// done here: the engine owns that decision and only clears it
    /// when the rebuilt state reproduces a quorum-certified root
    /// (`OxideBft::mark_repaired`) — a deterministic executor fault
    /// replays to the same wrong root and stays halted, which is
    /// the correct outcome.
    ///
    /// # Errors
    ///
    /// [`DurabilityError`] — `Import` on snapshot verification
    /// failure, `Journal`/`Io`/`Decode`/`UnknownRecordTag` on journal
    /// replay, `JournalGap` when committed history above the
    /// snapshot cannot be replayed contiguously.
    ///
    /// # Returns
    ///
    /// The highest committed height execution now covers — the
    /// snapshot height plus replayed journal blocks.
    pub fn repair_import_snapshot(
        &self,
        snapshot: &ExecutorSnapshot,
    ) -> Result<u64, DurabilityError> {
        let lane_dead = {
            let (lock, _cv) = &*self.exec_sync;
            primitives::sync::lock_state(lock).lane_dead
        };
        if !lane_dead {
            self.wait_exec_idle();
        }
        self.import_snapshot(snapshot).map_err(DurabilityError::Import)?;
        let base = snapshot.height;

        // Purge post-snapshot taint and lane debt. Roots above
        // `base` were computed on the diverged base; every pending
        // block is journaled, so dropping the deque loses nothing.
        primitives::sync::lock_state(&self.state_roots).retain(|h, _| *h <= base);
        {
            let (lock, _cv) = &*self.exec_sync;
            let mut s = primitives::sync::lock_state(lock);
            s.pending.clear();
            s.in_flight = None;
            s.executed = Some(base);
            s.saturated = false;
        }
        // Committed blocks the snapshot covers are no longer owed —
        // keep only the heights the replay must re-execute.
        primitives::sync::lock_state(&self.finalized).retain(|h, _| *h > base);

        let mut covered = base;
        if let Some(durability) = &self.durability {
            let replay = journal::replay(&durability.journal_dir())?;
            for record in replay.records {
                let Some((&tag, payload)) = record.payload.split_first() else {
                    return Err(DurabilityError::UnknownRecordTag(0xff));
                };
                match tag {
                    // Never a repair base — see the doc comment.
                    TAG_CHECKPOINT => {}
                    TAG_BLOCK => {
                        let mut reader = codec::Reader::new(payload);
                        let block = FinalizedBlock::decode(&mut reader)?;
                        let height = block.height.value();
                        if height <= covered {
                            continue;
                        }
                        let expected = covered.saturating_add(1);
                        if height != expected {
                            return Err(DurabilityError::JournalGap { expected, found: height });
                        }
                        self.insert_finalized(height, block);
                        covered = height;
                    }
                    other => return Err(DurabilityError::UnknownRecordTag(other)),
                }
            }
        } else {
            // In-memory only: the retained `finalized` map must span
            // base+1..=tip without a hole — there is no journal to
            // backfill from.
            let heights: Vec<u64> =
                primitives::sync::lock_state(&self.finalized).keys().copied().collect();
            for (i, h) in heights.iter().enumerate() {
                let expected = base.saturating_add(1).saturating_add(i as u64);
                if *h != expected {
                    return Err(DurabilityError::JournalGap { expected, found: *h });
                }
                covered = *h;
            }
        }
        self.execute_committed_backlog();
        // Watermarks — mirror recover_durable_state's contract so
        // attestation waiters and `prepare_proposal` resume at the
        // rebuilt tip, not the snapshot's.
        {
            let (lock, cv) = &*self.exec_sync;
            let mut s = primitives::sync::lock_state(lock);
            s.enqueued = Some(s.enqueued.map_or(covered, |e| e.max(covered)));
            s.executed = Some(s.executed.map_or(covered, |e| e.max(covered)));
            cv.notify_all();
        }
        {
            // Scoped guard: `durable_checkpoint` below re-enters
            // `next_proposal_height` through `export_snapshot` —
            // holding this MutexGuard across the call deadlocks
            // (std Mutex is non-reentrant).
            let next = covered.saturating_add(1);
            let mut height = primitives::sync::lock_state(&self.next_proposal_height);
            if next > *height {
                *height = next;
            }
        }
        // Persist the repaired base: a checkpoint rewrites
        // `snapshot.bin` with the rebuilt state and prunes the
        // covered journal — so a crash after repair restarts from
        // clean durable state instead of re-importing the tainted
        // snapshot and re-latching the halt. Failure leaves the
        // in-memory repair intact (the next divergence-free
        // checkpoint interval will retry); log loudly rather than
        // fail the repair over a persistence nicety.
        if let Err(e) = self.durable_checkpoint() {
            eprintln!(
                "executor: repair checkpoint failed ({e}) — in-memory state is repaired \
                 but snapshot.bin may still hold pre-repair state; a restart will \
                 re-run divergence repair"
            );
        }
        Ok(covered)
    }
}
