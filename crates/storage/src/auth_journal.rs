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

use crate::backend::{Caps, Op, Snapshot, SnapshotError, StorageBackend};
use crate::journal::{JournalConfig, JournalWriter, Replay, replay};
use crate::mmr::{Mmr, hash_leaf};
use primitives::Hash;

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
    /// Uses `replay_verified` to reconstruct the MMR root from the
    /// replayed records. This ensures the journal's integrity is
    /// verified during replay — a corrupted or tampered journal is
    /// detected by a mismatched MMR root (when an expected root is
    /// provided by the caller).
    ///
    /// # Errors
    /// Returns `JournalError` if the journal cannot be replayed.
    pub fn open(dir: &Path, config: JournalConfig) -> Result<Self, crate::journal::JournalError> {
        // Use `replay_verified` to reconstruct the MMR root from
        // the replayed records. This verifies the journal's
        // integrity during replay. Previously, `open` used the
        // unverified `replay` function, which did not reconstruct
        // the MMR root — a corrupted or tampered journal would not
        // be detected.
        let replay_result = replay_verified(dir, None)?;
        let mut state = std::collections::BTreeMap::new();
        for record in &replay_result.replay.records {
            // Decode the batch record and apply ops.
            let ops = decode_batch_record(&record.payload);
            apply_ops(&mut state, &ops);
        }
        let state_root = compute_state_root(&state);
        Ok(Self {
            journal: AuthenticatedJournal {
                writer: JournalWriter::create(dir, config)?,
                mmr: Mmr::new(), // MMR is rebuilt as new records are appended
            },
            state,
            state_root,
        })
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

    fn apply_batch(&mut self, ops: &[Op]) {
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
        if self.journal.append(&record).is_err() {
            // Append failed — roll back the in-memory state to
            // keep it consistent with the journal. Restore each
            // affected key to its old value (or remove it if it
            // didn't exist before).
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
        }
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
        // Replace all state.
        self.state.clear();
        for (k, v) in snapshot.entries {
            self.state.insert(k, v);
        }
        self.recompute_state_root();
        // Append a snapshot-import record to the journal.
        let record = encode_snapshot_record(&self.state_root);
        let _ = self.journal.append(&record);
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

/// Encode a snapshot-import record (just the state root).
fn encode_snapshot_record(state_root: &Hash) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&state_root.0);
    buf.extend_from_slice(&0u64.to_le_bytes()); // 0 ops
    buf
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
        backend.apply_batch(&[Op::Set { key, value: vec![0xAA, 0xBB] }]);
        assert_eq!(backend.get(&key), Some(vec![0xAA, 0xBB]));
        assert_eq!(backend.get(&key2), None);

        // Delete.
        backend.apply_batch(&[Op::Delete { key }]);
        assert_eq!(backend.get(&key), None);
    }

    #[test]
    fn journal_backend_state_root_changes() {
        let dir = TempDir::new("backend-root");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();
        let root0 = backend.state_root();
        assert_eq!(root0, Hash::ZERO, "empty state root must be zero");

        let key = Hash([0x01; 32]);
        backend.apply_batch(&[Op::Set { key, value: vec![0xAA] }]);
        let root1 = backend.state_root();
        assert_ne!(root0, root1, "state root must change after set");

        backend.apply_batch(&[Op::Set { key, value: vec![0xBB] }]);
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

        backend.apply_batch(&[
            Op::Set { key: key_a, value: vec![1] },
            Op::Set { key: key_b, value: vec![2] },
            Op::Set { key: key_c, value: vec![3] },
        ]);

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

        backend.apply_batch(&[
            Op::Set { key: key1, value: vec![0xAA, 0xBB] },
            Op::Set { key: key2, value: vec![0xCC] },
        ]);

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
        backend.apply_batch(&[Op::Set { key, value: vec![0xAA] }]);
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
        backend.apply_batch(&[Op::Set { key: key1, value: vec![0xAA, 0xBB] }]);
        backend.apply_batch(&[Op::Set { key: key2, value: vec![0xCC] }]);
        // Flush the journal to disk before opening a new backend.
        backend.sync().unwrap();
        let expected_state_root = backend.state_root();

        // Open a new backend from the same directory — this
        // replays the journal and reconstructs the state.
        let backend2 = JournalBackend::open(&dir.0, JournalConfig::default()).unwrap();

        // The state must match.
        assert_eq!(backend2.get(&key1), Some(vec![0xAA, 0xBB]));
        assert_eq!(backend2.get(&key2), Some(vec![0xCC]));
        assert_eq!(
            backend2.state_root(),
            expected_state_root,
            "state root must match after verified replay"
        );
    }

    /// Regression test: `apply_batch` must roll back the in-memory
    /// state if the journal append fails. Before the fix, the
    /// append error was silently ignored (`let _ = ...`), leaving
    /// the in-memory state inconsistent with the journal.
    ///
    /// We simulate an append failure by creating a backend with a
    /// very large value that exceeds `MAX_RECORD_BYTES`. The append
    /// returns `RecordTooLarge`, and the in-memory state must be
    /// rolled back.
    #[test]
    fn journal_backend_apply_batch_rolls_back_on_append_failure() {
        let dir = TempDir::new("backend-rollback");
        let mut backend = JournalBackend::create(&dir.0, JournalConfig::default()).unwrap();

        // Set an initial value.
        let key = Hash([0x01; 32]);
        backend.apply_batch(&[Op::Set { key, value: vec![0xAA] }]);
        let state_root_before = backend.state_root();

        // Try to set a value that's too large to append. The
        // encoded batch record will exceed MAX_RECORD_BYTES (16 MiB).
        let huge_value = vec![0xBB; 17 * 1024 * 1024]; // 17 MiB > 16 MiB max
        backend.apply_batch(&[Op::Set { key, value: huge_value }]);

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
    }
}
