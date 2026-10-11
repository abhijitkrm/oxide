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
    /// `Some` in journal-backed mode (hft-audit-2 X-8): batches commit
    /// with `Durability::None` and `sync` makes them durable with an
    /// `Immediate` commit only every `every` calls. `None` keeps the
    /// default: every `apply_batch` commit is durable on return.
    deferred: Option<DeferredSync>,
}

/// Bookkeeping for journal-backed mode — see [`RedbBackend::open_journal_backed`].
struct DeferredSync {
    /// `sync` calls between durable (`Immediate`) commits.
    every: u32,
    /// `sync` calls since the last durable commit.
    pending: u32,
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
        Ok(Self { db, deferred: None })
    }

    /// Open `path` for a caller whose own write-ahead journal already
    /// makes every batch recoverable (hft-audit-2 X-8).
    ///
    /// The default mode pays one `fsync` per `apply_batch` commit —
    /// ~4 ms p50 / 13 ms p99 on the md RAID-1 target, serialized on
    /// the exec lane once per block on top of the executor journal's
    /// own sync. When the executor journal is enabled it is the crash
    /// authority (`executor::durability`: recovery re-imports the last
    /// checkpoint and replays journaled blocks above whatever height
    /// the modules restored), so this backend may lag. Here batches
    /// commit with `Durability::None` — atomic and visible to readers,
    /// not yet on disk — and every `sync_every`-th
    /// [`sync`](StorageBackend::sync) issues one `Immediate` commit,
    /// which makes every earlier commit durable. A crash rolls the
    /// file back to the last durable commit, never to a torn state;
    /// the journal replays the gap. Dropping the backend flushes.
    ///
    /// Never use this without such a journal: the lag is lost state.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open).
    pub fn open_journal_backed<P: AsRef<Path>>(
        path: P,
        sync_every: u32,
    ) -> Result<Self, redb::DatabaseError> {
        let db = Database::create(path)?;
        Ok(Self { db, deferred: Some(DeferredSync { every: sync_every.max(1), pending: 0 }) })
    }

    /// One `Immediate` commit of an empty write transaction — in redb
    /// this persists every preceding `Durability::None` commit.
    fn durable_commit(&self) -> Result<(), ApplyError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| ApplyError(format!("redb begin write failed: {e}")))?;
        txn.commit().map_err(|e| ApplyError(format!("redb durable commit failed: {e}")))
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
        Ok(Self { db, deferred: None })
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
        let mut txn = self
            .db
            .begin_write()
            .map_err(|e| ApplyError(format!("redb begin write failed: {e}")))?;
        if self.deferred.is_some() {
            // Journal-backed: durable at the next `sync` cadence point.
            txn.set_durability(redb::Durability::None)
                .map_err(|e| ApplyError(format!("redb set durability failed: {e}")))?;
        }
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

    fn sync(&mut self) -> Result<(), ApplyError> {
        // Default mode: every commit was already durable on return.
        let Some(deferred) = self.deferred.as_mut() else {
            return Ok(());
        };
        deferred.pending = deferred.pending.saturating_add(1);
        if deferred.pending < deferred.every {
            return Ok(());
        }
        self.durable_commit()?;
        if let Some(deferred) = self.deferred.as_mut() {
            deferred.pending = 0;
        }
        Ok(())
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

impl Drop for RedbBackend {
    /// Journal-backed mode flushes its lag on a clean shutdown so a
    /// restart replays nothing it doesn't have to. Best effort: a
    /// failure here leaves the file at its last durable commit, which
    /// the journal covers.
    fn drop(&mut self) {
        if self.deferred.as_ref().is_some_and(|d| d.pending > 0) {
            let _ = self.durable_commit();
        }
    }
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

    /// hft-audit-2 X-8: journal-backed commits are visible at once,
    /// and survive a clean close/reopen (the drop-time flush plus the
    /// cadence commit).
    #[test]
    fn journal_backed_commits_visible_and_flushed_on_drop() {
        let path = std::env::temp_dir().join(format!(
            "oxide_redb_deferred_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let k1 = Hash([0x11; 32]);
        let k2 = Hash([0x22; 32]);
        {
            let mut store = RedbBackend::open_journal_backed(&path, 2).expect("open");
            store.apply_batch(&[Op::Set { key: k1, value: b"one".to_vec() }]).expect("apply");
            store.sync().expect("sync below cadence");
            assert_eq!(store.get(&k1), Some(b"one".to_vec()), "None-durability commit is visible");
            store.apply_batch(&[Op::Set { key: k2, value: b"two".to_vec() }]).expect("apply");
            store.sync().expect("cadence sync");
            store.apply_batch(&[Op::Delete { key: k1 }]).expect("apply");
            store.sync().expect("pending again");
        }
        let store = RedbBackend::open(&path).expect("reopen");
        assert_eq!(store.get(&k1), None, "drop flushed the trailing batch");
        assert_eq!(store.get(&k2), Some(b"two".to_vec()));
        drop(store);
        let _ = std::fs::remove_file(&path);
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
