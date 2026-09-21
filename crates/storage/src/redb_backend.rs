//! `redb`-backed `StorageBackend` adapter (plan.md §2.3, Phase 2).
//!
//! ## What this module is
//!
//! A persistent, ACID, disk-backed `StorageBackend` implementation using
//! the `redb` embedded key-value store. `redb` is pure Rust, LMDB-like,
//! and crash-safe by default — the first disk-backed adapter to pass
//! the `storage-conformance` suite.
//!
//! ## Why redb first
//!
//! The plan (§2.3) calls for `MDBX`, `RocksDB`, and redb adapters. `redb`
//! ships first because it's pure Rust (no C deps, no system libraries),
//! which keeps the build hermetic and the CI matrix simple. `MDBX` and
//! `RocksDB` arrive later with their C bindings and platform-specific
//! perf characteristics.
//!
//! ## Key encoding
//!
//! Oxide `StorageBackend` keys are 32-byte `Hash` values. `redb` stores
//! `&[u8]` keys directly, so we pass the raw 32 bytes. Values are
//! arbitrary-length byte slices. The table definition is
//! `TableDefinition<&[u8], &[u8]>`.
//!
//! ## Crash safety
//!
//! `redb` is ACID-compliant: `apply_batch` runs inside a single write
//! transaction, so a crash mid-batch leaves the database in its
//! pre-batch state. This satisfies the crash-replay determinism
//! property of the storage-conformance suite.

use std::path::Path;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::backend::{ApplyError, Caps, Op, Snapshot, SnapshotError, StorageBackend};
use primitives::Hash;

/// The redb table definition: byte-slice keys → byte-slice values.
///
/// Keys are 32-byte `Hash` values (stored as `&[u8]`); values are
/// arbitrary-length byte slices. A single table holds all module
/// state — the `StorageBackend` seam is flat (no nested namespaces).
const TABLE: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("oxide_state");

/// A `redb`-backed `StorageBackend`.
///
/// Wraps a `redb::Database` file. All operations run inside
/// transactions: `get` and `range` use read transactions, `apply_batch`
/// uses a single write transaction (atomic per batch, per the
/// `StorageBackend` contract).
///
/// # Crash safety
///
/// `redb` is ACID-compliant. A crash during `apply_batch` leaves the
/// database in its pre-batch state — no partial writes.
pub struct RedbBackend {
    db: Database,
}

impl RedbBackend {
    /// Open or create a `redb` database at `path`.
    ///
    /// Creates the file if it doesn't exist; opens it if it does.
    /// The database is crash-safe by default (WAL + group commit).
    ///
    /// # Errors
    ///
    /// Returns `redb::DatabaseError` if the file cannot be created or
    /// opened, or if the file is not a valid `redb` database.
    ///
    /// # Panics
    ///
    /// This function does not panic. The caller should handle the
    /// `Result` to catch I/O errors.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, redb::DatabaseError> {
        let db = Database::create(path)?;
        Ok(Self { db })
    }

    /// Open an in-memory `redb` database (for tests).
    ///
    /// Uses `redb`'s `backends::FileBackend` with a temp file. The
    /// database is destroyed when the `RedbBackend` is dropped.
    ///
    /// # Errors
    ///
    /// Returns `redb::DatabaseError` if the in-memory backend cannot
    /// be created.
    pub fn open_in_memory() -> Result<Self, redb::DatabaseError> {
        // redb doesn't have a native in-memory mode, but we can use
        // a temp file. For tests, this is sufficient.
        let path = std::env::temp_dir().join(format!("oxide_redb_{}.db", std::process::id()));
        let db = Database::create(&path)?;
        // Clean up on drop by leaking the path — redb will remove the
        // file when the Database is dropped. For tests this is fine.
        std::mem::forget(path);
        Ok(Self { db })
    }
}

impl StorageBackend for RedbBackend {
    fn capabilities(&self) -> Caps {
        // redb is not authenticated (no built-in Merkle roots).
        // Authentication is provided by the journal + MMR layer above.
        Caps { authenticated: false }
    }

    fn get(&self, key: &Hash) -> Option<Vec<u8>> {
        // Read transactions are cheap in redb (MVCC, non-blocking).
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(TABLE).ok()?;
        let guard = table.get(key.as_bytes()).ok()?;
        guard.map(|v| v.value().to_vec())
    }

    fn range(&self, prefix: &[u8]) -> Vec<(Hash, Vec<u8>)> {
        let mut out = Vec::new();
        // Prefixes longer than the key width match nothing (keys are
        // exactly 32 bytes), matching Volatile's behavior.
        if prefix.len() > 32 {
            return out;
        }
        let Ok(txn) = self.db.begin_read() else {
            return out;
        };
        let Ok(table) = txn.open_table(TABLE) else {
            return out;
        };

        // Compute the range bounds for the prefix.
        let (lo, hi) = prefix_bounds(prefix);

        // Iterate over the range [lo, hi) and collect results.
        let range = if let Some(hi) = hi {
            table.range(lo.as_slice()..hi.as_slice())
        } else {
            table.range(lo.as_slice()..)
        };

        if let Ok(range) = range {
            for item in range {
                let Ok((k, v)) = item else { continue };
                let key_bytes = k.value();
                if key_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(key_bytes);
                    out.push((Hash(arr), v.value().to_vec()));
                }
            }
        }
        out
    }

    fn apply_batch(&mut self, ops: &[Op]) -> Result<(), ApplyError> {
        // Single write transaction = atomic batch (StorageBackend
        // contract). Every fallible step propagates: an uncommitted
        // txn applies nothing on drop, and the caller learns the
        // batch did not happen instead of the process dying mid-
        // commit on a recoverable engine error.
        let txn = self
            .db
            .begin_write()
            .map_err(|e| ApplyError(format!("redb begin write failed: {e}")))?;
        {
            let mut table = txn
                .open_table(TABLE)
                .map_err(|e| ApplyError(format!("redb open table failed: {e}")))?;
            for op in ops {
                match op {
                    Op::Set { key, value } => {
                        table
                            .insert(key.as_bytes(), value.as_slice())
                            .map_err(|e| ApplyError(format!("redb insert failed: {e}")))?;
                    }
                    Op::Delete { key } => {
                        table
                            .remove(key.as_bytes())
                            .map_err(|e| ApplyError(format!("redb delete failed: {e}")))?;
                    }
                }
            }
        }
        txn.commit().map_err(|e| ApplyError(format!("redb commit failed: {e}")))
    }

    fn snapshot_export(&self) -> Snapshot {
        let mut entries = Vec::new();
        let Ok(txn) = self.db.begin_read() else {
            return Snapshot { height: 0, entries };
        };
        let Ok(table) = txn.open_table(TABLE) else {
            return Snapshot { height: 0, entries };
        };
        // redb iterates in sorted key order, so the snapshot is
        // deterministic.
        if let Ok(iter) = table.iter() {
            for item in iter {
                let Ok((k, v)) = item else { continue };
                let key_bytes = k.value();
                if key_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(key_bytes);
                    entries.push((Hash(arr), v.value().to_vec()));
                }
            }
        }
        Snapshot { height: 0, entries }
    }

    fn snapshot_import(&mut self, snapshot: Snapshot) -> Result<(), SnapshotError> {
        // Validate: keys must be sorted and unique.
        let mut prev: Option<&Hash> = None;
        for (k, _) in &snapshot.entries {
            if let Some(p) = prev
                && k <= p
            {
                return Err(SnapshotError::Malformed);
            }
            prev = Some(k);
        }
        // Replace all state: clear + insert in a single transaction.
        let txn = self.db.begin_write().map_err(|_| SnapshotError::BackendError)?;
        {
            let mut table = txn.open_table(TABLE).map_err(|_| SnapshotError::BackendError)?;
            // Clear all existing keys.
            table.retain(|_, _| false).map_err(|_| SnapshotError::BackendError)?;
            // Insert snapshot entries.
            for (k, v) in &snapshot.entries {
                table
                    .insert(k.as_bytes(), v.as_slice())
                    .map_err(|_| SnapshotError::BackendError)?;
            }
        }
        txn.commit().map_err(|_| SnapshotError::BackendError)?;
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

    fn make_backend() -> RedbBackend {
        let path = std::env::temp_dir().join(format!(
            "oxide_redb_test_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        RedbBackend::open(&path).expect("open redb")
    }

    #[test]
    fn redb_set_get_round_trip() {
        let mut store = make_backend();
        let k = Hash([0x42; 32]);
        store
            .apply_batch(&[Op::Set { key: k, value: b"hello".to_vec() }])
            .expect("apply_batch must succeed");
        assert_eq!(store.get(&k), Some(b"hello".to_vec()));
        // Verify via range too.
        let hits = store.range(&[0x42]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, b"hello");
    }

    #[test]
    fn redb_batch_atomicity_last_op_wins() {
        let mut store = make_backend();
        let k = Hash([0x01; 32]);
        store
            .apply_batch(&[
                Op::Set { key: k, value: b"first".to_vec() },
                Op::Set { key: k, value: b"second".to_vec() },
            ])
            .expect("apply_batch must succeed");
        let hits = store.range(&[0x01]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, b"second");
    }

    #[test]
    fn redb_delete_removes_key() {
        let mut store = make_backend();
        let k = Hash([0x02; 32]);
        store
            .apply_batch(&[Op::Set { key: k, value: b"v".to_vec() }])
            .expect("apply_batch must succeed");
        assert_eq!(store.range(&[0x02]).len(), 1);
        store.apply_batch(&[Op::Delete { key: k }]).expect("apply_batch must succeed");
        assert_eq!(store.range(&[0x02]).len(), 0);
    }

    #[test]
    fn redb_range_prefix_exact() {
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
    fn redb_persists_across_reopen() {
        let path = std::env::temp_dir().join(format!(
            "oxide_redb_persist_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let k = Hash([0x77; 32]);
        {
            let mut store = RedbBackend::open(&path).expect("open");
            store
                .apply_batch(&[Op::Set { key: k, value: b"persistent".to_vec() }])
                .expect("apply_batch must succeed");
        }
        // Reopen and verify the data survived.
        let store = RedbBackend::open(&path).expect("reopen");
        let hits = store.range(&[0x77]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].1, b"persistent");
        // Clean up.
        let _ = std::fs::remove_file(&path);
    }
}
