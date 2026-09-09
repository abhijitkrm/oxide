//! `MDBX`-backed `StorageBackend` adapter (plan.md §2.3, Phase 2).
//!
//! ## What this module is
//!
//! A persistent, ACID, disk-backed `StorageBackend` implementation using
//! `MDBX` — the LMDB-compatible, improved B-tree key-value store. This
//! is the third disk-backed adapter, complementing `redb` (pure Rust)
//! and `RocksDB` (LSM).
//!
//! ## Why `MDBX`
//!
//! The plan (§2.3) calls for `MDBX`, `RocksDB`, and redb adapters. `MDBX`
//! is an improved fork of `LMDB` — a memory-mapped B-tree store with
//! excellent read performance and single-writer semantics. It's used
//! by many blockchain projects (e.g., Erigon, Polygon Edge). The
//! single-writer model fits Oxide's single-writer commit pipeline
//! (plan.md §8).
//!
//! ## Key encoding
//!
//! Oxide `StorageBackend` keys are 32-byte `Hash` values. `MDBX` stores
//! arbitrary byte-slice keys directly, so we pass the raw 32 bytes.
//! Values are arbitrary-length byte slices.
//!
//! ## Crash safety
//!
//! `MDBX` is ACID-compliant. `apply_batch` uses a single write
//! transaction (atomic per batch, per the `StorageBackend` contract).
//! A crash mid-batch leaves the database in its pre-batch state.

use std::path::Path;

use libmdbx::{Database, NoWriteMap};

use crate::backend::{Caps, Op, Snapshot, SnapshotError, StorageBackend};
use primitives::Hash;

/// An `MDBX`-backed `StorageBackend`.
///
/// Wraps a `libmdbx::Database<NoWriteMap>` file. All operations use
/// `MDBX`'s transactional API: `get` and `range` use read-only
/// transactions, `apply_batch` uses a single read-write transaction
/// (atomic per batch, per the `StorageBackend` contract).
///
/// # Crash safety
///
/// `MDBX` is ACID-compliant. A crash during `apply_batch` leaves the
/// database in its pre-batch state.
pub struct MdbxBackend {
    db: Database<NoWriteMap>,
}

impl MdbxBackend {
    /// Open or create an `MDBX` database at `path`.
    ///
    /// Creates the file if it doesn't exist; opens it if it does.
    /// The database is crash-safe by default (WAL + group commit).
    ///
    /// # Errors
    ///
    /// Returns `libmdbx::Error` if the file cannot be created or
    /// opened, or if the file is not a valid `MDBX` database.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, libmdbx::Error> {
        let db = Database::<NoWriteMap>::open(path)?;
        Ok(Self { db })
    }
}

impl StorageBackend for MdbxBackend {
    fn capabilities(&self) -> Caps {
        // MDBX is not authenticated (no built-in Merkle roots).
        // Authentication is provided by the journal + MMR layer above.
        Caps { authenticated: false }
    }

    fn get(&self, key: &Hash) -> Option<Vec<u8>> {
        let txn = self.db.begin_ro_txn().ok()?;
        let table = txn.open_table(None).ok()?;
        let result: Option<Vec<u8>> = txn.get(&table, key.as_bytes()).ok().flatten();
        // Transaction drops here (read-only, no commit needed).
        result
    }

    fn range(&self, prefix: &[u8]) -> Vec<(Hash, Vec<u8>)> {
        let mut out = Vec::new();
        // Prefixes longer than the key width match nothing (keys are
        // exactly 32 bytes), matching Volatile's behavior.
        if prefix.len() > 32 {
            return out;
        }

        let Ok(txn) = self.db.begin_ro_txn() else {
            return out;
        };
        let Ok(table) = txn.open_table(None) else {
            return out;
        };
        let Ok(mut cursor) = txn.cursor(&table) else {
            return out;
        };

        // Iterate over all keys in sorted order.
        for item in cursor.iter::<Vec<u8>, Vec<u8>>() {
            let Ok((k, v)) = item else { continue };
            // Skip keys shorter than the prefix.
            if k.len() < prefix.len() {
                continue;
            }
            // Check if the key starts with the prefix and is 32 bytes.
            if k.starts_with(prefix) && k.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&k);
                out.push((Hash(arr), v));
            }
        }
        out
    }

    fn apply_batch(&mut self, ops: &[Op]) {
        // Single read-write transaction = atomic batch.
        let txn = self.db.begin_rw_txn().expect("mdbx begin write txn");
        let table = txn.open_table(None).expect("mdbx open table");
        for op in ops {
            match op {
                Op::Set { key, value } => {
                    txn.put(&table, key.as_bytes(), value, libmdbx::WriteFlags::default())
                        .expect("mdbx put");
                }
                Op::Delete { key } => {
                    txn.del(&table, key.as_bytes(), None).expect("mdbx del");
                }
            }
        }
        txn.commit().expect("mdbx commit");
    }

    fn snapshot_export(&self) -> Snapshot {
        let mut entries = Vec::new();
        let Ok(txn) = self.db.begin_ro_txn() else {
            return Snapshot { height: 0, entries };
        };
        let Ok(table) = txn.open_table(None) else {
            return Snapshot { height: 0, entries };
        };
        let Ok(mut cursor) = txn.cursor(&table) else {
            return Snapshot { height: 0, entries };
        };
        // Iterate over all keys in sorted order.
        for item in cursor.iter::<Vec<u8>, Vec<u8>>() {
            let Ok((k, v)) = item else { continue };
            if k.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&k);
                entries.push((Hash(arr), v));
            }
        }
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
        // Replace all state: clear + insert in a single transaction.
        let txn = self.db.begin_rw_txn().map_err(|_| SnapshotError::BackendError)?;
        let table = txn.open_table(None).map_err(|_| SnapshotError::BackendError)?;
        // Clear all existing keys.
        txn.clear_table(&table).map_err(|_| SnapshotError::BackendError)?;
        // Insert snapshot entries.
        for (k, v) in &snapshot.entries {
            txn.put(&table, k.as_bytes(), v, libmdbx::WriteFlags::default())
                .map_err(|_| SnapshotError::BackendError)?;
        }
        txn.commit().map_err(|_| SnapshotError::BackendError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backend() -> MdbxBackend {
        let path = std::env::temp_dir().join(format!(
            "oxide_mdbx_test_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        MdbxBackend::open(&path).expect("open mdbx")
    }

    #[test]
    fn mdbx_set_get_round_trip() {
        let mut store = make_backend();
        let k = Hash([0x42; 32]);
        store.apply_batch(&[Op::Set { key: k, value: b"hello".to_vec() }]);
        assert_eq!(store.get(&k), Some(b"hello".to_vec()));
    }

    #[test]
    fn mdbx_batch_atomicity_last_op_wins() {
        let mut store = make_backend();
        let k = Hash([0x01; 32]);
        store.apply_batch(&[
            Op::Set { key: k, value: b"first".to_vec() },
            Op::Set { key: k, value: b"second".to_vec() },
        ]);
        assert_eq!(store.get(&k), Some(b"second".to_vec()));
    }

    #[test]
    fn mdbx_delete_removes_key() {
        let mut store = make_backend();
        let k = Hash([0x02; 32]);
        store.apply_batch(&[Op::Set { key: k, value: b"v".to_vec() }]);
        assert!(store.get(&k).is_some());
        store.apply_batch(&[Op::Delete { key: k }]);
        assert!(store.get(&k).is_none());
    }

    #[test]
    fn mdbx_range_prefix_exact() {
        let mut store = make_backend();
        let make_key = |last: u8| {
            let mut k = [0x42; 32];
            k[31] = last;
            Hash(k)
        };
        store.apply_batch(&[
            Op::Set { key: make_key(1), value: vec![1] },
            Op::Set { key: make_key(3), value: vec![3] },
            Op::Set { key: make_key(2), value: vec![2] },
            Op::Set { key: Hash([0x99; 32]), value: vec![9] },
        ]);
        let hits = store.range(&[0x42]);
        assert_eq!(hits.len(), 3);
        let lasts: Vec<u8> = hits.iter().map(|(k, _)| k.as_bytes()[31]).collect();
        assert_eq!(lasts, vec![1, 2, 3], "deterministic key order");
    }

    #[test]
    fn mdbx_snapshot_round_trip() {
        let mut store = make_backend();
        store.apply_batch(&[
            Op::Set { key: Hash([0x01; 32]), value: b"alpha".to_vec() },
            Op::Set { key: Hash([0x02; 32]), value: b"beta".to_vec() },
            Op::Delete { key: Hash([0x02; 32]) },
        ]);
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
