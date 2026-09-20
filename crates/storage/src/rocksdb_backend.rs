//! `RocksDB`-backed `StorageBackend` adapter (plan.md §2.3, Phase 2).
//!
//! ## What this module is
//!
//! A persistent, ACID, disk-backed `StorageBackend` implementation using
//! `RocksDB` — the industry-standard LSM key-value store. This is the
//! second disk-backed adapter, complementing `redb` (pure Rust).
//!
//! ## Why `RocksDB`
//!
//! The plan (§2.3) calls for `MDBX`, `RocksDB`, and redb adapters.
//! `RocksDB` is the most widely-deployed embedded KV store in
//! blockchain infrastructure (used by Bitcoin Core, Ethereum nodes,
//! Solana). It's an LSM-tree (log-structured merge-tree) with
//! background compaction, optimized for write-heavy workloads — a
//! good fit for Oxide's append-heavy journal commit pattern.
//!
//! ## Key encoding
//!
//! Oxide `StorageBackend` keys are 32-byte `Hash` values. `RocksDB`
//! stores arbitrary byte-slice keys directly, so we pass the raw 32
//! bytes. Values are arbitrary-length byte slices.
//!
//! ## Crash safety
//!
//! `RocksDB` provides ACID guarantees via write-ahead logging (WAL).
//! `apply_batch` uses a single `WriteBatch` (atomic write), so a crash
//! mid-batch leaves the database in its pre-batch state.

use std::path::Path;

use rocksdb::{DB, Options, WriteBatch};

use crate::backend::{ApplyError, Caps, Op, Snapshot, SnapshotError, StorageBackend};
use primitives::Hash;

/// A `RocksDB`-backed `StorageBackend`.
///
/// Wraps a `rocksdb::DB` file. All operations use `RocksDB`'s
/// transactional API: `get` and `range` use read snapshots,
/// `apply_batch` uses a single `WriteBatch` (atomic per batch, per the
/// `StorageBackend` contract).
///
/// # Crash safety
///
/// `RocksDB` is ACID-compliant with the WAL enabled (default). A crash
/// during `apply_batch` leaves the database in its pre-batch state.
pub struct RocksDbBackend {
    db: DB,
}

impl RocksDbBackend {
    /// Open or create a `RocksDB` database at `path`.
    ///
    /// Creates the file if it doesn't exist; opens it if it does.
    /// The database is crash-safe by default (WAL + group commit).
    ///
    /// # Errors
    ///
    /// Returns `rocksdb::Error` if the file cannot be created or
    /// opened, or if the file is not a valid `RocksDB` database.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)?;
        Ok(Self { db })
    }
}

impl StorageBackend for RocksDbBackend {
    fn capabilities(&self) -> Caps {
        // RocksDB is not authenticated (no built-in Merkle roots).
        // Authentication is provided by the journal + MMR layer above.
        Caps { authenticated: false }
    }

    fn get(&self, key: &Hash) -> Option<Vec<u8>> {
        self.db.get(key.as_bytes()).ok().flatten()
    }

    fn range(&self, prefix: &[u8]) -> Vec<(Hash, Vec<u8>)> {
        let mut out = Vec::new();
        // Prefixes longer than the key width match nothing (keys are
        // exactly 32 bytes), matching Volatile's behavior.
        if prefix.len() > 32 {
            return out;
        }

        // Compute the range bounds for the prefix.
        let (_lo, hi) = prefix_bounds(prefix);

        // Use RocksDB's iterator with the prefix range.
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        for item in iter {
            let Ok((k, v)) = item else { continue };
            let key_bytes = &k[..];
            // Skip keys shorter than the prefix.
            if key_bytes.len() < prefix.len() {
                continue;
            }
            // Check if the key starts with the prefix and is 32 bytes.
            if key_bytes.starts_with(prefix) && key_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(key_bytes);
                out.push((Hash(arr), v.to_vec()));
            }
            // If we've passed the prefix range, stop.
            if let Some(hi) = &hi {
                if key_bytes >= hi.as_slice() {
                    break;
                }
            }
        }
        // Sort by key (RocksDB iterator is sorted, but be explicit).
        out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        out
    }

    fn apply_batch(&mut self, ops: &[Op]) -> Result<(), ApplyError> {
        // Single WriteBatch = atomic batch (StorageBackend contract).
        let mut batch = WriteBatch::default();
        for op in ops {
            match op {
                Op::Set { key, value } => {
                    batch.put(key.as_bytes(), value);
                }
                Op::Delete { key } => {
                    batch.delete(key.as_bytes());
                }
            }
        }
        // Write with WAL for durability. A rejected write applies
        // nothing — the WriteBatch was never committed — and the
        // error propagates instead of panicking (the caller decides
        // whether this commit failure is retryable or fatal).
        self.db.write(batch).map_err(|e| ApplyError(format!("rocksdb write failed: {e}")))
    }

    fn sync(&mut self) -> Result<(), ApplyError> {
        // Flush the WAL to stable storage — `apply_batch` writes go
        // through the WAL, so this is the durability boundary between
        // "written" and "survives a crash".
        self.db.flush_wal(true).map_err(|e| ApplyError(format!("rocksdb WAL flush failed: {e}")))
    }

    fn snapshot_export(&self) -> Snapshot {
        let mut entries = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        for item in iter {
            let Ok((k, v)) = item else { continue };
            let key_bytes = &k[..];
            if key_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(key_bytes);
                entries.push((Hash(arr), v.to_vec()));
            }
        }
        // Sort by key (RocksDB iterator is already sorted, but be
        // explicit for determinism).
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
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
        // Replace all state: clear + insert in a single batch.
        let mut batch = WriteBatch::default();
        // Clear all existing keys by iterating and deleting.
        let iter = self.db.iterator(rocksdb::IteratorMode::Start);
        for item in iter {
            let Ok((k, _)) = item else { continue };
            batch.delete(&k[..]);
        }
        // Insert snapshot entries.
        for (k, v) in &snapshot.entries {
            batch.put(k.as_bytes(), v);
        }
        self.db.write(batch).map_err(|_| SnapshotError::BackendError)?;
        Ok(())
    }
}

/// Compute the range bounds for a prefix scan.
///
/// Returns `(lo, hi)`: keys in `[lo, hi)` start with `prefix`.
/// `lo` is the prefix zero-padded to 32 bytes; `hi` is the prefix
/// with its last byte incremented (then zero-padded), or `None`
/// when the prefix is all `0xFF` (the range runs to the end).
fn prefix_bounds(prefix: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut lo = vec![0u8; 32];
    let take = prefix.len().min(32);
    lo[..take].copy_from_slice(&prefix[..take]);
    if prefix.is_empty() {
        return (lo, None);
    }
    let mut succ = prefix.to_vec();
    let mut carry = true;
    for i in (0..succ.len()).rev() {
        if succ[i] != 0xFF {
            succ[i] += 1;
            carry = false;
            break;
        }
    }
    if carry {
        return (lo, None);
    }
    let mut hi = vec![0u8; 32];
    hi[..succ.len()].copy_from_slice(&succ);
    (lo, Some(hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backend() -> RocksDbBackend {
        let path = std::env::temp_dir().join(format!(
            "oxide_rocksdb_test_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        RocksDbBackend::open(&path).expect("open rocksdb")
    }

    #[test]
    fn rocksdb_set_get_round_trip() {
        let mut store = make_backend();
        let k = Hash([0x42; 32]);
        store
            .apply_batch(&[Op::Set { key: k, value: b"hello".to_vec() }])
            .expect("apply_batch must succeed");
        assert_eq!(store.get(&k), Some(b"hello".to_vec()));
    }

    #[test]
    fn rocksdb_batch_atomicity_last_op_wins() {
        let mut store = make_backend();
        let k = Hash([0x01; 32]);
        store
            .apply_batch(&[
                Op::Set { key: k, value: b"first".to_vec() },
                Op::Set { key: k, value: b"second".to_vec() },
            ])
            .expect("apply_batch must succeed");
        assert_eq!(store.get(&k), Some(b"second".to_vec()));
    }

    #[test]
    fn rocksdb_delete_removes_key() {
        let mut store = make_backend();
        let k = Hash([0x02; 32]);
        store
            .apply_batch(&[Op::Set { key: k, value: b"v".to_vec() }])
            .expect("apply_batch must succeed");
        assert!(store.get(&k).is_some());
        store.apply_batch(&[Op::Delete { key: k }]).expect("apply_batch must succeed");
        assert!(store.get(&k).is_none());
    }

    #[test]
    fn rocksdb_range_prefix_exact() {
        let mut store = make_backend();
        let make_key = |last: u8| {
            let mut k = [0x42; 32];
            k[31] = last;
            Hash(k)
        };
        store
            .apply_batch(&[
                Op::Set { key: make_key(1), value: vec![1] },
                Op::Set { key: make_key(3), value: vec![3] },
                Op::Set { key: make_key(2), value: vec![2] },
                Op::Set { key: Hash([0x99; 32]), value: vec![9] },
            ])
            .expect("apply_batch must succeed");
        let hits = store.range(&[0x42]);
        assert_eq!(hits.len(), 3);
        let lasts: Vec<u8> = hits.iter().map(|(k, _)| k.as_bytes()[31]).collect();
        assert_eq!(lasts, vec![1, 2, 3], "deterministic key order");
    }

    #[test]
    fn rocksdb_persists_across_reopen() {
        let path = std::env::temp_dir().join(format!(
            "oxide_rocksdb_persist_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let k = Hash([0x77; 32]);
        {
            let mut store = RocksDbBackend::open(&path).expect("open");
            store
                .apply_batch(&[Op::Set { key: k, value: b"persistent".to_vec() }])
                .expect("apply_batch must succeed");
        }
        // Reopen and verify the data survived.
        let store = RocksDbBackend::open(&path).expect("reopen");
        assert_eq!(store.get(&k), Some(b"persistent".to_vec()));
        // Clean up.
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn rocksdb_snapshot_round_trip() {
        let mut store = make_backend();
        store
            .apply_batch(&[
                Op::Set { key: Hash([0x01; 32]), value: b"alpha".to_vec() },
                Op::Set { key: Hash([0x02; 32]), value: b"beta".to_vec() },
                Op::Delete { key: Hash([0x02; 32]) },
            ])
            .expect("apply_batch must succeed");
        let snapshot = store.snapshot_export();
        assert_eq!(snapshot.entries.len(), 1);

        // Import into a fresh backend.
        let mut store2 = make_backend();
        store2.snapshot_import(snapshot.clone()).expect("import");
        assert_eq!(store2.get(&Hash([0x01; 32])), Some(b"alpha".to_vec()));
        assert_eq!(store2.get(&Hash([0x02; 32])), None);

        // Re-export and verify round-trip.
        let snapshot2 = store2.snapshot_export();
        assert_eq!(snapshot.entries, snapshot2.entries);
    }
}
