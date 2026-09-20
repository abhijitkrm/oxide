//! Authenticated journal: integrates the journal (durability) with the
//! MMR (authentication).
//!
//! The M1 audit finding: the journal and MMR were separate. Every
//! journal record should contribute to the authenticated log root,
//! and replay should verify against the MMR root. Without this,
//! a corrupted or tampered journal record could go undetected if
//! the CRC check is bypassed (e.g., by replacing the segment file).
//!
//! # Design
//!
//! `AuthenticatedJournal` wraps a `JournalWriter` and an `Mmr`:
//! - `append(payload)` writes the payload to the journal and pushes
//!   `hash_leaf(payload)` to the MMR. The MMR root commits the
//!   entire log.
//! - `root()` returns the current MMR root.
//! - `replay_verified(dir, expected_root)` replays the journal,
//!   reconstructs the MMR from the replayed records, and verifies
//!   the root matches `expected_root`. A mismatch means the journal
//!   was tampered with.
//!
//! # Invariants
//!
//! - Every journal record contributes exactly one MMR leaf.
//! - The MMR root is deterministic: replaying the same journal
//!   always produces the same root.
//! - A tampered journal (modified record, inserted record, deleted
//!   record) produces a different root and is rejected.

use std::path::Path;

use crate::backend::{ApplyError, Caps, Op, Snapshot, SnapshotError, StorageBackend};
use crate::journal::{JournalConfig, JournalError, JournalWriter, Replay, replay};
use crate::mmr::{Mmr, hash_leaf};
use primitives::Hash;

/// Why opening a [`JournalBackend`] can fail.
///
/// Distinct from [`JournalError`]: opening is replay *plus* an
/// integrity decision, and the integrity arm carries the two roots
/// that disagreed — information a bare IO error cannot express.
#[derive(Debug)]
pub enum OpenError {
    /// The journal itself failed (IO, unreadable directory).
    Journal(JournalError),
    /// The replayed MMR root does not match the trusted root the
    /// caller persisted. The journal was truncated, corrupted past
    /// CRC detection, or belongs to a different history. This is
    /// fatal on purpose: opening anyway would silently continue a
    /// divergent log — every subsequent MMR root (and thus every
    /// state attestation) would commit a different history.
    IntegrityMismatch {
        /// The trusted root the caller expected.
        expected: Hash,
        /// The root reconstructed by replay.
        actual: Hash,
    },
    /// The journal's first record is a checkpoint marker — segments
    /// before it were pruned — but no base-state `Snapshot` was
    /// supplied. Opening without the snapshot would silently
    /// reconstruct a state missing everything the checkpoint
    /// summarizes. Use [`JournalBackend::open_with_snapshot`].
    CheckpointWithoutSnapshot,
    /// The supplied snapshot's computed state root does not equal
    /// the state root the checkpoint marker committed — the
    /// snapshot does not cover this journal's pruned prefix.
    SnapshotMismatch {
        /// The state root committed by the checkpoint marker.
        expected: Hash,
        /// The state root computed from the supplied snapshot.
        actual: Hash,
    },
    /// The checkpoint marker record was malformed — the journal
    /// head was tampered with or corrupted past CRC detection.
    MalformedCheckpoint,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Journal(e) => write!(f, "journal error during open: {e}"),
            Self::IntegrityMismatch { expected, actual } => {
                write!(f, "journal integrity mismatch: expected {expected:?}, replayed {actual:?}")
            }
            Self::CheckpointWithoutSnapshot => {
                write!(f, "journal is pruned at a checkpoint but no snapshot was supplied")
            }
            Self::SnapshotMismatch { expected, actual } => {
                write!(f, "snapshot root mismatch: checkpoint expects {expected:?}, got {actual:?}")
            }
            Self::MalformedCheckpoint => write!(f, "malformed checkpoint marker record"),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Journal(e) => Some(e),
            Self::IntegrityMismatch { .. }
            | Self::CheckpointWithoutSnapshot
            | Self::SnapshotMismatch { .. }
            | Self::MalformedCheckpoint => None,
        }
    }
}

impl From<JournalError> for OpenError {
    fn from(e: JournalError) -> Self {
        Self::Journal(e)
    }
}

/// An authenticated journal: the journal (durability) plus the MMR
/// (authentication). Every `append` writes to both; the MMR root
/// commits the entire log.
pub struct AuthenticatedJournal {
    writer: JournalWriter,
    mmr: Mmr,
}

/// The result of authenticated replay.
#[derive(Debug)]
pub struct AuthenticatedReplay {
    /// The replay result (records, `truncated_at`).
    pub replay: Replay,
    /// The MMR root reconstructed from the replayed records.
    pub root: primitives::Hash,
    /// Whether the reconstructed root matches the expected root.
    pub root_matches: bool,
}

impl AuthenticatedJournal {
    /// Create a new authenticated journal in `dir`.
    ///
    /// # Errors
    /// Returns `JournalError` if the journal cannot be created.
    pub fn create(dir: &Path, config: JournalConfig) -> Result<Self, crate::journal::JournalError> {
        Ok(Self { writer: JournalWriter::create(dir, config)?, mmr: Mmr::new() })
    }

    /// Append a payload to the journal and push its hash to the MMR.
    ///
    /// # Errors
    /// Returns `JournalError` if the payload is too large or the
    /// journal cannot be written.
    pub fn append(
        &mut self,
        payload: &[u8],
    ) -> Result<crate::journal::Location, crate::journal::JournalError> {
        let location = self.writer.append(payload)?;
        self.mmr.push(hash_leaf(payload));
        Ok(location)
    }

    /// Flush the journal buffer to the OS.
    ///
    /// # Errors
    /// Returns `JournalError::Io` on write failure.
    pub fn flush(&mut self) -> Result<(), crate::journal::JournalError> {
        self.writer.flush()
    }

    /// Flush and sync the journal (durability point).
    ///
    /// # Errors
    /// Returns `JournalError::Io` on write or sync failure.
    pub fn sync(&mut self) -> Result<(), crate::journal::JournalError> {
        self.writer.sync()
    }

    /// The current MMR root — commits the entire log.
    pub fn root(&self) -> primitives::Hash {
        self.mmr.root()
    }

    /// The number of leaves (records) in the MMR.
    pub fn leaf_count(&self) -> u64 {
        self.mmr.leaf_count()
    }

    /// Delete sealed segment files with `seq < watermark`. See
    /// [`JournalWriter::prune_below`] — the caller must have a
    /// checkpoint covering the pruned records.
    ///
    /// # Errors
    /// Returns `JournalError::Io` on flush or removal failure.
    pub fn prune_below(&mut self, watermark: u32) -> Result<u32, JournalError> {
        self.writer.prune_below(watermark)
    }

    /// The active segment's sequence number.
    pub fn active_segment(&self) -> u32 {
        self.writer.active_segment()
    }
}

/// Replay a journal directory and reconstruct the MMR root from
/// the replayed records. If `expected_root` is provided, verify
/// the reconstructed root matches.
///
/// # Errors
/// Returns `JournalError` only for true IO failures.
pub fn replay_verified(
    dir: &Path,
    expected_root: Option<primitives::Hash>,
) -> Result<AuthenticatedReplay, crate::journal::JournalError> {
    let replay = replay(dir)?;
    let mut mmr = Mmr::new();
    for record in &replay.records {
        mmr.push(hash_leaf(&record.payload));
    }
    let root = mmr.root();
    let root_matches = match expected_root {
        Some(expected) => root == expected,
        None => true,
    };
    Ok(AuthenticatedReplay { replay, root, root_matches })
}

// ─── JournalBackend: StorageBackend over AuthenticatedJournal ──────

/// A `StorageBackend` backed by an `AuthenticatedJournal`.
///
/// Combines an in-memory `BTreeMap` for fast point reads with an
/// `AuthenticatedJournal` for durability and authentication. Every
/// `apply_batch` applies the ops to the in-memory map AND appends a
/// serialized batch record to the journal (which also pushes to the
/// MMR). The MMR root is the authenticated state root — it commits
/// the entire log of batch records.
///
/// # State root
///
/// The MMR root authenticates the *log* (the sequence of batch
/// records), not the *state* (the current key-value map). To
/// authenticate the state itself, the batch record includes a
/// state-root hash computed from the in-memory map after applying
/// the batch. The MMR root then commits the sequence of state roots,
/// proving that the state evolved correctly.
///
/// # Replay
///
/// On startup, the journal is replayed: each batch record is decoded
/// and applied to a fresh `BTreeMap`, reconstructing the in-memory
/// state. The MMR is reconstructed from the replayed records and
/// verified against the last known root.
pub struct JournalBackend {
    /// The authenticated journal (durability + MMR authentication).
    journal: AuthenticatedJournal,
    /// In-memory state for fast point reads (the "hot" state).
    state: std::collections::BTreeMap<Hash, Vec<u8>>,
    /// The current state root (hash of all key-value pairs).
    state_root: Hash,
}

impl JournalBackend {
    /// Create a new `JournalBackend` in `dir`.
    ///
    /// # Errors
    /// Returns `JournalError` if the journal cannot be created.
    pub fn create(dir: &Path, config: JournalConfig) -> Result<Self, crate::journal::JournalError> {
        Ok(Self {
            journal: AuthenticatedJournal::create(dir, config)?,
            state: std::collections::BTreeMap::new(),
            state_root: Hash::ZERO,
        })
    }

    /// Open an existing `JournalBackend` from `dir`, replaying the
    /// journal to reconstruct the in-memory state.
    ///
    /// `expected_root` is the trusted MMR log root the caller
    /// persisted before shutdown (what [`JournalBackend::log_root`]
    /// returned). When `Some`, the reconstructed MMR root must match
    /// exactly — a truncated, corrupted, or foreign journal is a
    /// fatal [`OpenError::IntegrityMismatch`], not a silent
    /// continue-from-prefix. `None` = unverified open (dev/testing;
    /// production callers should always pass their last root).
    ///
    /// The reconstructed MMR is *kept* (previously it was rebuilt
    /// and then discarded for `Mmr::new()`, so `log_root()` after
    /// restart reflected an empty log and new appends forked off
    /// history). The writer still starts a fresh segment — the on-
    /// disk append order is unchanged; the MMR continues the same
    /// leaf sequence.
    ///
    /// # Errors
    /// Returns [`OpenError::Journal`] if the journal cannot be
    /// replayed, and [`OpenError::IntegrityMismatch`] when a trusted
    /// `expected_root` does not match the replayed log.
    pub fn open(
        dir: &Path,
        config: JournalConfig,
        expected_root: Option<Hash>,
    ) -> Result<Self, OpenError> {
        Self::open_with_snapshot(dir, config, None, expected_root)
    }

    /// Open with an optional base-state snapshot for a journal whose
    /// prefix was pruned behind a checkpoint marker.
    ///
    /// If the first surviving record is a checkpoint marker, the
    /// marker's committed state root is verified against the
    /// supplied snapshot's recomputed root — a snapshot that does
    /// not cover the pruned prefix is a fatal
    /// [`OpenError::SnapshotMismatch`], never a silent wrong state.
    /// The MMR resumes from the marker's `(leaf_count, peaks)` so
    /// the log root continues the identical history (checkpointing
    /// never forks the root). Records after the marker apply on top
    /// of the snapshot.
    ///
    /// Supplying a snapshot for an *unpruned* journal is an error —
    /// the snapshot would silently shadow real history.
    ///
    /// # Errors
    /// As [`open`](Self::open), plus [`OpenError::CheckpointWithoutSnapshot`]
    /// when the journal is pruned and no snapshot was supplied, and
    /// [`OpenError::MalformedCheckpoint`] for a corrupt marker.
    pub fn open_with_snapshot(
        dir: &Path,
        config: JournalConfig,
        snapshot: Option<Snapshot>,
        expected_root: Option<Hash>,
    ) -> Result<Self, OpenError> {
        let replay_result = replay(dir)?;
        let mut mmr = Mmr::new();
        let mut state = std::collections::BTreeMap::new();
        let mut first_is_checkpoint = false;

        // Checkpoint detection: the first record carries the
        // checkpoint sentinel. Everything it summarizes was pruned —
        // base state must come from the caller's snapshot.
        if let Some(first) = replay_result.records.first() {
            if is_checkpoint_marker(&first.payload) {
                let (marker_root, leaf_count, peaks) =
                    decode_checkpoint(&first.payload).ok_or(OpenError::MalformedCheckpoint)?;
                let Some(snapshot) = snapshot else {
                    return Err(OpenError::CheckpointWithoutSnapshot);
                };
                // Rebuild the base state from the snapshot (sorted +
                // unique keys, same rule as snapshot_import) and
                // verify it against the marker's committed root.
                let mut base = std::collections::BTreeMap::new();
                let mut prev: Option<Hash> = None;
                for (k, v) in &snapshot.entries {
                    if let Some(p) = prev {
                        if *k <= p {
                            return Err(OpenError::MalformedCheckpoint);
                        }
                    }
                    prev = Some(*k);
                    base.insert(*k, v.clone());
                }
                let snap_root = compute_state_root(&base);
                if snap_root != marker_root {
                    return Err(OpenError::SnapshotMismatch {
                        expected: marker_root,
                        actual: snap_root,
                    });
                }
                state = base;
                mmr = Mmr::from_checkpoint(leaf_count, &peaks);
                first_is_checkpoint = true;
            } else if snapshot.is_some() {
                return Err(OpenError::MalformedCheckpoint);
            }
        } else if snapshot.is_some() {
            // An empty journal can't be "pruned at a checkpoint" —
            // a snapshot here is a caller error, not a valid open.
            return Err(OpenError::MalformedCheckpoint);
        }

        for (i, record) in replay_result.records.iter().enumerate() {
            // Every record is a leaf — including the marker itself
            // (it was appended as a normal record at checkpoint
            // time, so the resumed MMR pushes it too).
            mmr.push(hash_leaf(&record.payload));
            if i == 0 && first_is_checkpoint {
                continue; // marker: no ops to apply
            }
            apply_ops(&mut state, &decode_batch_record(&record.payload));
        }
        let actual_root = mmr.root();
        if let Some(expected) = expected_root {
            if actual_root != expected {
                return Err(OpenError::IntegrityMismatch { expected, actual: actual_root });
            }
        }
        let state_root = compute_state_root(&state);
        Ok(Self {
            journal: AuthenticatedJournal { writer: JournalWriter::create(dir, config)?, mmr },
            state,
            state_root,
        })
    }

    /// Write a checkpoint marker into the journal and return the
    /// segment sequence it landed in. The marker commits the
    /// current state root and the MMR checkpoint state
    /// `(leaf_count, peaks)` — everything in segments strictly
    /// below the returned seq may then be deleted via
    /// [`prune_below`](Self::prune_below).
    ///
    /// The marker is synced to disk before returning — pruning must
    /// never outrun durability.
    ///
    /// After pruning, [`open`](Self::open) must be replaced by
    /// [`open_with_snapshot`](Self::open_with_snapshot) supplying a
    /// [`Snapshot`] exported (and stored) *before* the checkpoint.
    /// The checkpoint does not carry the state itself — a marker
    /// big enough to hold every entry would exceed the record size
    /// bound; the snapshot lives wherever the caller keeps cold
    /// state (see `snapshot_export`).
    ///
    /// # Errors
    /// Returns `JournalError` if the marker cannot be appended or
    /// synced.
    pub fn checkpoint(&mut self) -> Result<u32, crate::journal::JournalError> {
        // Rotate FIRST: the marker must head a fresh segment so that
        // `prune_below(marker_segment)` leaves it as the very first
        // record replay sees. A marker sharing a segment with older
        // records would sit behind them — replay would hit real ops
        // before the marker, the checkpoint would be undetectable,
        // and MMR resume would fork.
        self.journal.writer.seal_and_rotate()?;
        let marker = encode_checkpoint(
            self.state_root,
            self.journal.leaf_count(),
            &self.journal.mmr.peak_hashes(),
        );
        let location = self.journal.append(&marker)?;
        self.journal.sync()?;
        Ok(location.segment)
    }

    /// Delete sealed journal segments with `seq < watermark`. The
    /// typical call is `prune_below(backend.checkpoint())`, which
    /// removes everything before the checkpoint marker.
    ///
    /// # Errors
    /// Returns `JournalError::Io` on flush or removal failure.
    pub fn prune_below(&mut self, watermark: u32) -> Result<u32, crate::journal::JournalError> {
        self.journal.prune_below(watermark)
    }

    /// The current MMR root — commits the entire log of batch records.
    #[must_use]
    pub fn log_root(&self) -> Hash {
        self.journal.root()
    }

    /// The current state root — hash of all key-value pairs.
    #[must_use]
    pub fn state_root(&self) -> Hash {
        self.state_root
    }

    /// Flush and sync the journal (durability point). Callers invoke
    /// this once per committed block batch to ensure the journal is
    /// persisted to disk.
    ///
    /// # Errors
    /// Returns `JournalError` on write or sync failure.
    pub fn sync(&mut self) -> Result<(), crate::journal::JournalError> {
        self.journal.sync()
    }

    /// Compute the state root from the current in-memory state.
    fn recompute_state_root(&mut self) {
        self.state_root = compute_state_root(&self.state);
    }
}

impl StorageBackend for JournalBackend {
    fn capabilities(&self) -> Caps {
        Caps { authenticated: true }
    }

    fn get(&self, key: &Hash) -> Option<Vec<u8>> {
        self.state.get(key).cloned()
    }

    fn range(&self, prefix: &[u8]) -> Vec<(Hash, Vec<u8>)> {
        if prefix.len() > Hash::LEN {
            return Vec::new();
        }
        let (lo, hi) = prefix_bounds(prefix);
        let iter = hi.map_or_else(|| self.state.range(lo..), |hi| self.state.range(lo..hi));
        iter.map(|(k, v)| (*k, v.clone())).collect()
    }

    fn apply_batch(&mut self, ops: &[Op]) -> Result<(), ApplyError> {
        // Save the old state root and the old values of affected
        // keys so we can roll back if the journal append fails.
        // Without this, a failed append (e.g., disk full) would
        // leave the in-memory state inconsistent with the journal:
        // the state reflects the batch, but the journal doesn't.
        // On restart, the journal replay would miss this batch.
        let old_state_root = self.state_root;
        let old_values: Vec<(Hash, Option<Vec<u8>>)> = ops
            .iter()
            .map(|op| match op {
                Op::Set { key, .. } | Op::Delete { key } => (*key, self.state.get(key).cloned()),
            })
            .collect();
        // Apply ops to the in-memory state.
        apply_ops(&mut self.state, ops);
        // Recompute the state root.
        self.recompute_state_root();
        // Serialize the batch + state root and append to the journal.
        let record = encode_batch_record(ops, self.state_root);
        if let Err(e) = self.journal.append(&record) {
            // Append failed — roll back the in-memory state to
            // keep it consistent with the journal. Restore each
            // affected key to its old value (or remove it if it
            // didn't exist before). The error is then returned:
            // swallowing it would let the caller commit a block
            // the journal can never replay — silent state/disk
            // divergence.
            for (key, old_value) in &old_values {
                match old_value {
                    Some(v) => {
                        self.state.insert(*key, v.clone());
                    }
                    None => {
                        self.state.remove(key);
                    }
                }
            }
            self.state_root = old_state_root;
            return Err(ApplyError(format!("journal append failed: {e}")));
        }
        Ok(())
    }

    fn sync(&mut self) -> Result<(), ApplyError> {
        self.journal.sync().map_err(|e| ApplyError(format!("journal sync failed: {e}")))
    }

    fn snapshot_export(&self) -> Snapshot {
        let entries: Vec<(Hash, Vec<u8>)> =
            self.state.iter().map(|(k, v)| (*k, v.clone())).collect();
        Snapshot { height: 0, entries }
    }

    fn snapshot_import(&mut self, snapshot: Snapshot) -> Result<(), SnapshotError> {
        // Validate: keys must be sorted and unique.
        let mut prev: Option<&Hash> = None;
        for (k, _) in &snapshot.entries {
            if let Some(p) = prev {
                if k <= p {
                    return Err(SnapshotError::Malformed);
                }
            }
            prev = Some(k);
        }
        // The journal record must carry the imported entries —
        // previously it wrote only the state root with zero ops, so
        // replay restored nothing and the entire snapshot silently
        // vanished on restart. Encode the replacement as a real
        // batch: delete every live key, then set every snapshot
        // entry. Replay then rebuilds exactly the imported state.
        let mut ops = Vec::with_capacity(self.state.len() + snapshot.entries.len());
        ops.extend(self.state.keys().map(|key| Op::Delete { key: *key }));
        let mut new_state = std::collections::BTreeMap::new();
        for (k, v) in &snapshot.entries {
            new_state.insert(*k, v.clone());
            ops.push(Op::Set { key: *k, value: v.clone() });
        }
        let new_root = compute_state_root(&new_state);
        let record = encode_batch_record(&ops, new_root);
        // Durability is not optional: previously the append result
        // was discarded, so a failed write left in-memory state the
        // journal could never restore. Propagate the failure and
        // leave the old state untouched — all-or-nothing, the same
        // contract `apply_batch`'s rollback enforces.
        if self.journal.append(&record).is_err() {
            return Err(SnapshotError::BackendError);
        }
        self.state = new_state;
        self.state_root = new_root;
        Ok(())
    }
}

/// Compute a deterministic state root from a `BTreeMap<Hash, Vec<u8>>`.
///
/// The state root is the BLAKE3 hash of the concatenation of all
/// (key, value) pairs in sorted key order. This is a simple but
/// deterministic state root — not a Merkle-Patricia trie, but
/// sufficient for authentication (any state change produces a
/// different root).
fn compute_state_root(state: &std::collections::BTreeMap<Hash, Vec<u8>>) -> Hash {
    if state.is_empty() {
        return Hash::ZERO;
    }
    let mut data = Vec::new();
    for (k, v) in state {
        data.extend_from_slice(&k.0);
        data.extend_from_slice(&(v.len() as u64).to_le_bytes());
        data.extend_from_slice(v);
    }
    crypto::hash::Hasher::hash_one(crypto::hash::Domain::StateRoot, &data)
}

/// Apply a batch of ops to a `BTreeMap` state.
fn apply_ops(state: &mut std::collections::BTreeMap<Hash, Vec<u8>>, ops: &[Op]) {
    for op in ops {
        match op {
            Op::Set { key, value } => {
                state.insert(*key, value.clone());
            }
            Op::Delete { key } => {
                state.remove(key);
            }
        }
    }
}

/// Encode a batch of ops + the resulting state root as a journal
/// record. Format: `[state_root 32B][op_count varint][ops...]`.
fn encode_batch_record(ops: &[Op], state_root: Hash) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&state_root.0);
    buf.extend_from_slice(&(ops.len() as u64).to_le_bytes());
    for op in ops {
        match op {
            Op::Set { key, value } => {
                buf.push(0); // Set tag
                buf.extend_from_slice(&key.0);
                buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
                buf.extend_from_slice(value);
            }
            Op::Delete { key } => {
                buf.push(1); // Delete tag
                buf.extend_from_slice(&key.0);
            }
        }
    }
    buf
}

/// Decode a batch record back into ops.
fn decode_batch_record(payload: &[u8]) -> Vec<Op> {
    if payload.len() < 40 {
        return Vec::new();
    }
    let mut ops = Vec::new();
    let mut pos = 40; // skip state_root (32) + op_count (8)
    let op_count = u64::from_le_bytes(payload[32..40].try_into().unwrap_or([0u8; 8]));
    for _ in 0..op_count {
        if pos >= payload.len() {
            break;
        }
        let tag = payload[pos];
        pos += 1;
        match tag {
            0 => {
                // Set
                if pos + 32 > payload.len() {
                    break;
                }
                let key = Hash(payload[pos..pos + 32].try_into().unwrap_or([0u8; 32]));
                pos += 32;
                if pos + 8 > payload.len() {
                    break;
                }
                let val_len = usize::try_from(u64::from_le_bytes(
                    payload[pos..pos + 8].try_into().unwrap_or([0u8; 8]),
                ))
                .unwrap_or(0);
                pos += 8;
                if pos + val_len > payload.len() {
                    break;
                }
                let value = payload[pos..pos + val_len].to_vec();
                pos += val_len;
                ops.push(Op::Set { key, value });
            }
            1 => {
                // Delete
                if pos + 32 > payload.len() {
                    break;
                }
                let key = Hash(payload[pos..pos + 32].try_into().unwrap_or([0u8; 32]));
                pos += 32;
                ops.push(Op::Delete { key });
            }
            _ => break,
        }
    }
    ops
}

/// The `op_count` sentinel marking a checkpoint record instead of a
/// batch. `u64::MAX` can never be a real op count — a batch that
/// large cannot be encoded (its ops alone would exceed the 16 MiB
/// record bound by ~10¹⁵×), so the sentinel is collision-free by
/// construction, not by convention.
const CHECKPOINT_OP_COUNT: u64 = u64::MAX;

/// Fixed checkpoint marker layout:
/// `[state_root 32B][CHECKPOINT_OP_COUNT u64][leaf_count u64]
///  [peaks_count u32][peaks 32B each]`.
///
/// `leaf_count`/`peaks` describe the MMR *before* the marker record
/// itself was appended — on open, `Mmr::from_checkpoint` rebuilds
/// that forest and the marker is then pushed as a normal leaf.
const CHECKPOINT_FIXED_LEN: usize = 32 + 8 + 8 + 4;

/// Whether `payload` is a checkpoint marker (vs a batch record).
fn is_checkpoint_marker(payload: &[u8]) -> bool {
    payload.len() >= CHECKPOINT_FIXED_LEN
        && u64::from_le_bytes(payload[32..40].try_into().unwrap_or([0u8; 8])) == CHECKPOINT_OP_COUNT
}

/// Encode a checkpoint marker.
fn encode_checkpoint(state_root: Hash, leaf_count: u64, peaks: &[Hash]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CHECKPOINT_FIXED_LEN + peaks.len() * Hash::LEN);
    buf.extend_from_slice(&state_root.0);
    buf.extend_from_slice(&CHECKPOINT_OP_COUNT.to_le_bytes());
    buf.extend_from_slice(&leaf_count.to_le_bytes());
    buf.extend_from_slice(&u32::try_from(peaks.len()).unwrap_or(u32::MAX).to_le_bytes());
    for peak in peaks {
        buf.extend_from_slice(&peak.0);
    }
    buf
}

/// Decode a checkpoint marker → `(state_root, leaf_count, peaks)`.
/// `None` on any malformed field — the caller maps that to
/// [`OpenError::MalformedCheckpoint`], never a partial state.
fn decode_checkpoint(payload: &[u8]) -> Option<(Hash, u64, Vec<Hash>)> {
    if payload.len() < CHECKPOINT_FIXED_LEN {
        return None;
    }
    if u64::from_le_bytes(payload[32..40].try_into().ok()?) != CHECKPOINT_OP_COUNT {
        return None;
    }
    let state_root = Hash(payload[..32].try_into().ok()?);
    let leaf_count = u64::from_le_bytes(payload[40..48].try_into().ok()?);
    let peaks_count = usize::try_from(u32::from_le_bytes(payload[48..52].try_into().ok()?)).ok()?;
    // Exact-length check: a trailing garbage byte or a truncated
    // peak table makes the marker untrustworthy.
    if payload.len() != CHECKPOINT_FIXED_LEN + peaks_count * Hash::LEN {
        return None;
    }
    // Sanity bound: an MMR with `leaf_count` leaves has
    // popcount(leaf_count) ≤ 64 peaks. Anything more is corrupt.
    if peaks_count > 64 {
        return None;
    }
    let peaks = payload[CHECKPOINT_FIXED_LEN..]
        .chunks_exact(Hash::LEN)
        .map(|c| Hash(c.try_into().unwrap_or([0u8; 32])))
        .collect();
    Some((state_root, leaf_count, peaks))
}

/// Compute the (lo, hi) range bounds for a prefix scan over a
/// `BTreeMap<Hash, _>`.
fn prefix_bounds(prefix: &[u8]) -> (Hash, Option<Hash>) {
    let mut lo = [0u8; 32];
    let prefix_len = prefix.len().min(32);
    lo[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
    // Compute the upper bound by incrementing the prefix.
    let mut hi = lo;
    for i in (0..prefix_len).rev() {
        if hi[i] < 0xFF {
            hi[i] += 1;
            hi[i + 1..].fill(0);
            return (Hash(lo), Some(Hash(hi)));
        }
    }
    // All 0xFF — no upper bound.
    (Hash(lo), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::Hash;
    use std::io::Write as _;

    /// A temp dir helper that cleans up on drop.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "oxide-auth-journal-{}-{}",
                name,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn authenticated_journal_root_is_deterministic() {
        let dir = TempDir::new("deterministic");
        let config = JournalConfig::default();
        let mut aj = AuthenticatedJournal::create(&dir.0, config).unwrap();
        aj.append(b"hello").unwrap();
        aj.append(b"world").unwrap();
        aj.sync().unwrap();
        let root1 = aj.root();

        // Replay and reconstruct.
        let result = replay_verified(&dir.0, Some(root1)).unwrap();
        assert!(result.root_matches, "reconstructed root must match");
        assert_eq!(result.root, root1);
        assert_eq!(result.replay.records.len(), 2);
    }

    #[test]
    fn tampered_journal_detected() {
        let dir = TempDir::new("tampered");
        let config = JournalConfig::default();
        let mut aj = AuthenticatedJournal::create(&dir.0, config).unwrap();
        aj.append(b"record1").unwrap();
        aj.append(b"record2").unwrap();
        aj.append(b"record3").unwrap();
        aj.sync().unwrap();
        let original_root = aj.root();

        // Tamper: append a record directly to the segment file
        // (bypassing the MMR). This simulates an attacker inserting
        // a record after the journal was written.
        let segment_path = dir.0.join("segment-0.log");
        let mut file = std::fs::OpenOptions::new().append(true).open(&segment_path).unwrap();
        // Write a valid-framed record that the journal will accept
        // during replay but the MMR won't know about.
        let tampered_payload = b"tampered";
        let len = u32::try_from(tampered_payload.len()).unwrap();
        let crc = crate::journal::crc32(tampered_payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(tampered_payload);
        file.write_all(&buf).unwrap();
        file.sync_all().unwrap();

        // Replay: the journal will accept the tampered record (valid
        // CRC), but the reconstructed MMR root will differ from the
        // original root because the MMR has an extra leaf.
        let result = replay_verified(&dir.0, Some(original_root)).unwrap();
        assert!(!result.root_matches, "tampered journal must produce a different root");
        assert_eq!(result.replay.records.len(), 4, "journal accepted the tampered record");
        assert_ne!(result.root, original_root, "roots must differ");
    }

    #[test]
    fn empty_journal_has_zero_root() {
        let dir = TempDir::new("empty");
        let result = replay_verified(&dir.0, None).unwrap();
        // An empty MMR has a zero root (all-zeros hash).
        assert_eq!(result.root, Hash::ZERO, "empty journal root must be zero");
        assert_eq!(result.replay.records.len(), 0);
    }

    #[test]
    fn root_changes_after_each_append() {
        let dir = TempDir::new("changes");
        let config = JournalConfig::default();
        let mut aj = AuthenticatedJournal::create(&dir.0, config).unwrap();
        let root0 = aj.root();
        aj.append(b"a").unwrap();
        let root1 = aj.root();
        aj.append(b"b").unwrap();
        let root2 = aj.root();
        assert_ne!(root0, root1, "root must change after append");
        assert_ne!(root1, root2, "root must change after append");
    }

    // ─── JournalBackend tests ──────────────────────────────────

    #[test]
    fn journal_backend_capabilities_authenticated() {
        let dir = TempDir::new("backend-caps");
        let backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        assert!(backend.capabilities().authenticated, "JournalBackend must be authenticated");
    }

    #[test]
    fn journal_backend_get_set_delete() {
        let dir = TempDir::new("backend-gsd");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        let key = Hash([0x01; 32]);
        let key2 = Hash([0x02; 32]);

        // Set and get.
        backend
            .apply_batch(&[Op::Set { key, value: vec![0xAA, 0xBB] }])
            .expect("apply_batch must succeed");
        assert_eq!(backend.get(&key), Some(vec![0xAA, 0xBB]));
        assert_eq!(backend.get(&key2), None);

        // Delete.
        backend.apply_batch(&[Op::Delete { key }]).expect("apply_batch must succeed");
        assert_eq!(backend.get(&key), None);
    }

    #[test]
    fn journal_backend_state_root_changes() {
        let dir = TempDir::new("backend-root");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        let root0 = backend.state_root();
        assert_eq!(root0, Hash::ZERO, "empty state root must be zero");

        let key = Hash([0x01; 32]);
        backend
            .apply_batch(&[Op::Set { key, value: vec![0xAA] }])
            .expect("apply_batch must succeed");
        let root1 = backend.state_root();
        assert_ne!(root0, root1, "state root must change after set");

        backend
            .apply_batch(&[Op::Set { key, value: vec![0xBB] }])
            .expect("apply_batch must succeed");
        let root2 = backend.state_root();
        assert_ne!(root1, root2, "state root must change after update");
    }

    #[test]
    fn journal_backend_range_prefix() {
        let dir = TempDir::new("backend-range");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        let key_a = Hash({
            let mut a = [0u8; 32];
            a[0] = 0x01;
            a
        });
        let key_b = Hash({
            let mut a = [0u8; 32];
            a[0] = 0x01;
            a[1] = 0x01;
            a
        });
        let key_c = Hash({
            let mut a = [0u8; 32];
            a[0] = 0x02;
            a
        });

        backend
            .apply_batch(&[
                Op::Set { key: key_a, value: vec![1] },
                Op::Set { key: key_b, value: vec![2] },
                Op::Set { key: key_c, value: vec![3] },
            ])
            .expect("apply_batch must succeed");

        // Prefix [0x01] matches key_a and key_b.
        let results = backend.range(&[0x01]);
        assert_eq!(results.len(), 2, "prefix 0x01 should match 2 keys");
        assert_eq!(results[0].0, key_a);
        assert_eq!(results[1].0, key_b);

        // Prefix [0x02] matches key_c.
        let results = backend.range(&[0x02]);
        assert_eq!(results.len(), 1, "prefix 0x02 should match 1 key");
        assert_eq!(results[0].0, key_c);
    }

    #[test]
    fn journal_backend_snapshot_roundtrip() {
        let dir = TempDir::new("backend-snap");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        let key1 = Hash([0x01; 32]);
        let key2 = Hash([0x02; 32]);

        backend
            .apply_batch(&[
                Op::Set { key: key1, value: vec![0xAA, 0xBB] },
                Op::Set { key: key2, value: vec![0xCC] },
            ])
            .expect("apply_batch must succeed");

        // Export snapshot.
        let snapshot = backend.snapshot_export();
        assert_eq!(snapshot.entries.len(), 2);

        // Import into a fresh backend.
        let dir2 = TempDir::new("backend-snap-restore");
        let mut backend2 = JournalBackend::create(&dir2.0, JournalConfig::default()).unwrap();
        backend2.snapshot_import(snapshot).unwrap();

        // State must match.
        assert_eq!(backend2.get(&key1), Some(vec![0xAA, 0xBB]));
        assert_eq!(backend2.get(&key2), Some(vec![0xCC]));
        assert_eq!(backend.state_root(), backend2.state_root(), "state roots must match");
    }

    #[test]
    fn journal_backend_log_root_advances() {
        let dir = TempDir::new("backend-logroot");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        let root0 = backend.log_root();

        let key = Hash([0x01; 32]);
        backend
            .apply_batch(&[Op::Set { key, value: vec![0xAA] }])
            .expect("apply_batch must succeed");
        let root1 = backend.log_root();
        assert_ne!(root0, root1, "log root must advance after batch");
    }

    /// Regression test: `open` must use verified replay to
    /// reconstruct the MMR root from the replayed records.
    /// Before the fix, `open` used the unverified `replay` function,
    /// which did not reconstruct the MMR root — a corrupted or
    /// tampered journal would not be detected.
    #[test]
    fn journal_backend_open_uses_verified_replay() {
        let dir = TempDir::new("backend-verified-open");

        // Create a backend and apply some batches.
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        let key1 = Hash([0x01; 32]);
        let key2 = Hash([0x02; 32]);
        backend
            .apply_batch(&[Op::Set { key: key1, value: vec![0xAA, 0xBB] }])
            .expect("apply_batch must succeed");
        backend
            .apply_batch(&[Op::Set { key: key2, value: vec![0xCC] }])
            .expect("apply_batch must succeed");
        // Flush the journal to disk before opening a new backend.
        backend.sync().unwrap();
        let expected_state_root = backend.state_root();

        // Open a new backend from the same directory — this
        // replays the journal and reconstructs the state.
        let backend2 = JournalBackend::open(&dir.0, JournalConfig::default(), None).unwrap();

        // The state must match.
        assert_eq!(backend2.get(&key1), Some(vec![0xAA, 0xBB]));
        assert_eq!(backend2.get(&key2), Some(vec![0xCC]));
        assert_eq!(
            backend2.state_root(),
            expected_state_root,
            "state root must match after verified replay"
        );
    }

    /// Regression test: `open` must verify the trusted MMR root and
    /// *keep* the reconstructed MMR. Before the fix the caller could
    /// not pass an expected root (integrity info was computed then
    /// discarded), and the rebuilt MMR was dropped for `Mmr::new()`
    /// — `log_root()` after restart reflected an empty log and new
    /// appends forked off history.
    #[test]
    fn journal_backend_open_verifies_expected_root_and_continues_mmr() {
        let dir = TempDir::new("backend-trusted-open");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        backend
            .apply_batch(&[Op::Set { key: Hash([0x01; 32]), value: vec![0xAA] }])
            .expect("apply_batch must succeed");
        backend
            .apply_batch(&[Op::Set { key: Hash([0x02; 32]), value: vec![0xBB] }])
            .expect("apply_batch must succeed");
        backend.sync().unwrap();
        let trusted_root = backend.log_root();

        // Correct trusted root → opens, and the MMR continues the
        // same leaf sequence (log_root unchanged across restart).
        let mut reopened =
            JournalBackend::open(&dir.0, JournalConfig::default(), Some(trusted_root))
                .expect("open with the trusted root must succeed");
        assert_eq!(reopened.log_root(), trusted_root, "MMR must continue across restart");

        // A wrong trusted root → fatal IntegrityMismatch.
        let wrong = JournalBackend::open(&dir.0, JournalConfig::default(), Some(Hash([0xFF; 32])));
        assert!(
            matches!(wrong.map(|_| ()), Err(OpenError::IntegrityMismatch { .. })),
            "wrong trusted root must be a fatal IntegrityMismatch"
        );

        // New appends extend the *same* MMR — the root changes as a
        // continuation, not a fork from empty.
        reopened
            .apply_batch(&[Op::Set { key: Hash([0x03; 32]), value: vec![0xCC] }])
            .expect("apply_batch must succeed");
        reopened.sync().unwrap();
        let continued_root = reopened.log_root();
        assert_ne!(continued_root, trusted_root, "new appends must advance the root");

        // Reopen again — the continued root is now the trusted one.
        let reopened2 =
            JournalBackend::open(&dir.0, JournalConfig::default(), Some(continued_root))
                .expect("reopen with the continued root must succeed");
        assert_eq!(reopened2.log_root(), continued_root);
    }

    /// Regression test: `snapshot_import` must journal the imported
    /// entries — previously the record carried only the state root
    /// with zero ops, so replay restored nothing and the snapshot
    /// silently vanished on restart. It must also propagate append
    /// failures (a durability failure used to be silently ignored).
    #[test]
    fn journal_backend_snapshot_import_survives_restart() {
        let dir = TempDir::new("backend-snapshot-durability");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        // Pre-existing state that the import must replace.
        backend
            .apply_batch(&[Op::Set { key: Hash([0xAA; 32]), value: vec![1] }])
            .expect("apply_batch must succeed");
        backend.sync().unwrap();

        // Import a snapshot: two entries, sorted.
        let snap = Snapshot {
            height: 5,
            entries: vec![(Hash([0x01; 32]), vec![0x11]), (Hash([0x02; 32]), vec![0x22])],
        };
        backend.snapshot_import(snap).expect("import must succeed");
        backend.sync().unwrap();
        let imported_root = backend.state_root();
        let imported_log_root = backend.log_root();

        // Reopen — replay must rebuild the snapshot's entries.
        let reopened =
            JournalBackend::open(&dir.0, JournalConfig::default(), Some(imported_log_root))
                .expect("open after snapshot import must succeed");
        assert_eq!(reopened.get(&Hash([0x01; 32])), Some(vec![0x11]));
        assert_eq!(reopened.get(&Hash([0x02; 32])), Some(vec![0x22]));
        assert_eq!(
            reopened.get(&Hash([0xAA; 32])),
            None,
            "replaced keys must stay deleted after restart"
        );
        assert_eq!(reopened.state_root(), imported_root);
    }

    /// Regression test: `apply_batch` must roll back the in-memory
    /// state AND report the failure when the journal append fails.
    /// Before the fallible contract, the append error was silently
    /// ignored — the in-memory state rolled back but the caller was
    /// told nothing, so the EVM could commit a block the journal
    /// could never replay.
    ///
    /// We simulate an append failure by creating a backend with a
    /// very large value that exceeds `MAX_RECORD_BYTES`. The append
    /// returns `RecordTooLarge`; the batch must report `Err` and the
    /// in-memory state must be rolled back.
    #[test]
    fn journal_backend_apply_batch_rolls_back_on_append_failure() {
        let dir = TempDir::new("backend-rollback");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();

        // Set an initial value.
        let key = Hash([0x01; 32]);
        backend
            .apply_batch(&[Op::Set { key, value: vec![0xAA] }])
            .expect("apply_batch must succeed");
        let state_root_before = backend.state_root();

        // Try to set a value that's too large to append. The
        // encoded batch record will exceed MAX_RECORD_BYTES (16 MiB).
        // The append must fail AND the error must reach the caller —
        // previously it was swallowed, letting the EVM commit state
        // the journal could never replay.
        let huge_value = vec![0xBB; 17 * 1024 * 1024]; // 17 MiB > 16 MiB max
        let result = backend.apply_batch(&[Op::Set { key, value: huge_value }]);
        assert!(result.is_err(), "oversized append must return Err, not be swallowed");

        // The in-memory state must be rolled back — the key must
        // still have its old value, and the state root must be
        // unchanged.
        assert_eq!(
            backend.get(&key),
            Some(vec![0xAA]),
            "state must be rolled back after append failure"
        );
        assert_eq!(
            backend.state_root(),
            state_root_before,
            "state root must be unchanged after append failure"
        );

        // A subsequent well-formed batch must still apply — a
        // transient append failure poisons only its own batch, not
        // the backend.
        backend
            .apply_batch(&[Op::Set { key, value: vec![0xCC] }])
            .expect("post-failure batch must apply");
        assert_eq!(backend.get(&key), Some(vec![0xCC]));
    }

    /// Rotation keeps sealed records readable on reopen: replay
    /// must see every record a rotated-away segment carried.
    ///
    /// Note this guards the rotate→seal→replay contract (records
    /// survive handle-swap intact), not fsync itself — a process-
    /// level reopen still reads page-cache data, so only a power
    /// loss distinguishes a synced seal from an unsynced one. That
    /// needs fault injection this test level cannot provide; the
    /// seal-time `sync_data` in `rotate()` is the durability fix.
    #[test]
    fn journal_backend_rotation_durable_without_explicit_sync() {
        let dir = TempDir::new("backend-rotate-sync");
        // Small segments force rotation every couple of records.
        let config = JournalConfig { max_segment_bytes: 128 };
        let mut backend = JournalBackend::create(&dir.0, config).unwrap();
        for i in 0..6u8 {
            backend
                .apply_batch(&[Op::Set { key: Hash([i; 32]), value: vec![i] }])
                .expect("apply_batch must succeed");
            // Deliberately NO `sync` — rotation's seal-time fsync is
            // what must carry the sealed segment's tail writes.
        }
        // Reopen from disk: replay must see every record a SEALED
        // segment carried — rotation must not strand or tear data.
        // The last record is NOT asserted: it sits in the active
        // segment's write buffer (never flushed — buffered is not
        // "written", let alone durable), so replay legitimately
        // misses it. Sealed-segment records are the contract.
        let reopened = JournalBackend::open(&dir.0, JournalConfig::default(), None)
            .unwrap_or_else(|_| panic!("reopen must succeed"));
        for i in 0..5u8 {
            assert_eq!(
                reopened.get(&Hash([i; 32])),
                Some(vec![i]),
                "sealed record {i} must survive rotation+reopen"
            );
        }
    }

    // ─── Checkpoint + pruning tests ────────────────────────────

    /// Full checkpoint lifecycle: write batches across multiple
    /// segments, export the snapshot, write the checkpoint marker,
    /// prune all segments below it, then reopen with the snapshot.
    /// The reopened backend must have identical state AND an
    /// identical log root — checkpointing summarizes the prefix,
    /// it never forks the MMR.
    #[test]
    fn journal_backend_checkpoint_prune_reopen() {
        let dir = TempDir::new("backend-checkpoint");
        // Small segments force rotation every couple of records.
        let config = JournalConfig { max_segment_bytes: 128 };
        let mut backend = JournalBackend::create(&dir.0, config).unwrap();
        for i in 0..8u8 {
            backend
                .apply_batch(&[Op::Set { key: Hash([i; 32]), value: vec![i, i, i] }])
                .expect("apply_batch must succeed");
            backend.sync().unwrap();
        }
        // Snapshot BEFORE checkpointing — the caller's contract.
        let snapshot = backend.snapshot_export();

        // Checkpoint + prune everything below the marker's segment.
        let ckpt_seg = backend.checkpoint().expect("checkpoint must succeed");
        let deleted = backend.prune_below(ckpt_seg).expect("prune must succeed");
        assert!(deleted > 0, "sealed segments below the checkpoint are deleted");

        // A later batch lands in the surviving tail.
        backend
            .apply_batch(&[Op::Set { key: Hash([0xF0; 32]), value: vec![9] }])
            .expect("apply_batch must succeed");
        backend.sync().unwrap();
        let post_batch_log_root = backend.log_root();

        // Reopen with the snapshot: base state from the snapshot,
        // tail records applied on top, MMR resumed from the marker.
        let reopened = JournalBackend::open_with_snapshot(
            &dir.0,
            config,
            Some(snapshot),
            Some(post_batch_log_root),
        )
        .expect("open with the covering snapshot must succeed");
        assert_eq!(reopened.log_root(), post_batch_log_root, "resumed MMR is identical");
        assert_eq!(reopened.get(&Hash([0xF0; 32])), Some(vec![9]), "tail ops apply on top");
        assert_eq!(reopened.get(&Hash([0x00; 32])), Some(vec![0, 0, 0]), "snapshot state present");
    }

    /// Opening a pruned (checkpointed) journal WITHOUT a snapshot
    /// must fail loudly — silently rebuilding only the suffix would
    /// produce a wrong state and fork the chain.
    #[test]
    fn journal_backend_pruned_open_without_snapshot_fails() {
        let dir = TempDir::new("backend-no-snapshot");
        let config = JournalConfig { max_segment_bytes: 128 };
        let mut backend = JournalBackend::create(&dir.0, config).unwrap();
        for i in 0..6u8 {
            backend
                .apply_batch(&[Op::Set { key: Hash([i; 32]), value: vec![i] }])
                .expect("apply_batch must succeed");
            backend.sync().unwrap();
        }
        let ckpt_seg = backend.checkpoint().unwrap();
        backend.prune_below(ckpt_seg).unwrap();

        let result = JournalBackend::open(&dir.0, config, None);
        assert!(
            matches!(result.map(|_| ()), Err(OpenError::CheckpointWithoutSnapshot)),
            "pruned journal without a snapshot must refuse to open"
        );
    }

    /// A snapshot that does NOT cover the pruned prefix must be
    /// rejected — its state root won't match the checkpoint's
    /// committed root.
    #[test]
    fn journal_backend_checkpoint_wrong_snapshot_fails() {
        let dir = TempDir::new("backend-wrong-snap");
        let config = JournalConfig { max_segment_bytes: 128 };
        let mut backend = JournalBackend::create(&dir.0, config).unwrap();
        for i in 0..6u8 {
            backend
                .apply_batch(&[Op::Set { key: Hash([i; 32]), value: vec![i] }])
                .expect("apply_batch must succeed");
            backend.sync().unwrap();
        }
        let ckpt_seg = backend.checkpoint().unwrap();
        backend.prune_below(ckpt_seg).unwrap();

        // A bogus snapshot — different keys entirely.
        let bogus = Snapshot { height: 0, entries: vec![(Hash([0xEE; 32]), vec![0xEE])] };
        let result = JournalBackend::open_with_snapshot(&dir.0, config, Some(bogus), None);
        assert!(
            matches!(result.map(|_| ()), Err(OpenError::SnapshotMismatch { .. })),
            "a snapshot that doesn't cover the pruned prefix must be rejected"
        );
    }

    /// The active segment is never pruned, even if the watermark
    /// exceeds it — deleting the segment being written would lose
    /// unflushed records.
    #[test]
    fn journal_prune_never_touches_active_segment() {
        let dir = TempDir::new("backend-active-safe");
        let config = JournalConfig { max_segment_bytes: 128 };
        let mut backend = JournalBackend::create(&dir.0, config).unwrap();
        backend
            .apply_batch(&[Op::Set { key: Hash([0x01; 32]), value: vec![1] }])
            .expect("apply_batch must succeed");
        backend.sync().unwrap();

        // Watermark beyond the active segment — only sealed
        // segments may go; the active one survives.
        let deleted = backend.prune_below(u32::MAX).unwrap();
        let active = backend.journal.active_segment();
        assert!(dir.0.join(format!("segment-{active}.log")).exists(), "active survives");
        let _ = deleted;

        // Everything still replays (the journal is intact).
        let replayed = crate::journal::replay(&dir.0).unwrap();
        assert!(replayed.truncated_at.is_none(), "journal must stay intact");
    }
}
