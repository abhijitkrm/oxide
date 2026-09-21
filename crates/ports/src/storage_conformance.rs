//! Storage adapter conformance suite — the contract every
//! `StorageBackend` must honor (plan.md §2.5, docs/storage-spec.md §4).
//!
//! # How backends use this
//!
//! A backend's test suite calls [`assert_storage_conformance`] with a
//! factory that constructs a fresh, isolated backend. The suite
//! exercises the behavioral rules against that backend. `Volatile`
//! (the in-memory reference) passes it; disk-backed adapters (MDBX,
//! `RocksDB`, `redb`) must pass it before node wiring lets a validator
//! run them.
//!
//! # What is asserted
//!
//! - **Batch atomicity** (§2.5): `apply_batch` is atomic per call —
//!   all ops land or none do. Last-op-wins within a batch.
//! - **Deterministic iteration order** (§2.5): `range` returns keys
//!   in lexicographic order, independent of insertion order.
//! - **Crash-replay determinism** (§2.5): re-applying the same batch
//!   sequence produces the same final state. (Full torn-write/bit-flip
//!   coverage arrives with the journal-backed adapter; the trait-level
//!   test verifies that two fresh backends fed the same batches end up
//!   byte-identical.)
//! - **Root stability across restarts** (§2.5): a backend that is
//!   dropped and reconstructed from the same inputs produces the same
//!   state. (Disk-backed adapters test this via their persistence
//!   layer; the trait-level test verifies determinism of the apply
//!   function.)
//! - **Prefix exactness**: `range(prefix)` returns exactly the keys
//!   starting with `prefix`, no more, no less.
//! - **Crash atomicity across reopen** (persistent backends only, via
//!   [`assert_persistent_storage_conformance`]): dropping the handle —
//!   the closest a process boundary gets to a crash — never splits a
//!   batch: reopened state is always a whole-batch prefix of what was
//!   applied, and synced state always survives. (Torn-write and
//!   interrupted-rotation coverage lives in the journal's fault-
//!   injection tests; this layer asserts the adapter-level contract.)
//!
//! Snapshot export/import round-trip: export a snapshot from one
//! backend, import it into a fresh backend, and verify the state
//! is byte-identical (plan.md §8, §2.5).

use std::collections::BTreeMap;
use std::path::Path;

use primitives::Hash;

use storage::{Op, Snapshot, StorageBackend};

/// Run the full storage conformance suite against a backend produced
/// by `make_backend`.
///
/// `make_backend` must construct a **fresh, empty** backend each call
/// — the determinism assertion compares two independent runs, so any
/// shared state between them would defeat it.
pub fn assert_storage_conformance<B: StorageBackend>(make_backend: impl Fn() -> B) {
    batch_atomicity(&make_backend);
    deterministic_iteration_order(&make_backend);
    crash_replay_determinism(&make_backend);
    prefix_exactness(&make_backend);
    delete_idempotence(&make_backend);
    snapshot_round_trip(&make_backend);
}

/// Crash-atomicity conformance for backends that persist to a path.
///
/// `make_at` opens (creating if needed) the backend rooted at the
/// given path — the same call must serve first-open and reopen, which
/// every persistent adapter's `open` already does.
///
/// The suite asserts the crash contract the trait can express:
///
/// - **Synced state survives reopen.** Everything acknowledged before
///   a `sync` + drop is readable after reopening the same path, and
///   the re-exported snapshot is byte-identical.
/// - **A crash never splits a batch.** A batch applied but never
///   synced may be entirely absent after reopen (write-behind
///   buffering) or entirely present (write-through) — never torn:
///   the reopened state must equal either the pre-batch or the
///   post-batch snapshot, nothing in between.
/// - **Reopened state accepts new batches.** After a restart the
///   backend keeps accumulating state on top of whatever survived —
///   a reopened backend is not read-only.
///
/// # Panics
/// This is a conformance assertion: it panics on any contract
/// violation and on filesystem errors creating its temp dirs —
/// like the base suite, failure of the harness is failure of the
/// backend under test.
pub fn assert_persistent_storage_conformance<B, F>(make_at: F)
where
    B: StorageBackend,
    F: Fn(&Path) -> B,
{
    let base = std::env::temp_dir().join(format!(
        "oxide-persist-conformance-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("create conformance temp dir");

    // ---- Synced state survives reopen ----
    let dir = base.join("reopen");
    let committed: Vec<(Hash, Vec<u8>)> =
        (0..8u8).map(|i| (key1(i), vec![i; i as usize + 1])).collect();
    {
        let mut b = make_at(&dir);
        for (k, v) in &committed {
            b.apply_batch(&[Op::Set { key: *k, value: v.clone() }])
                .expect("apply_batch must succeed");
        }
        b.sync().expect("sync must succeed");
        // Explicit drop = the process boundary: nothing after this
        // line may rely on in-memory state.
    }
    {
        let b = make_at(&dir);
        for (k, v) in &committed {
            assert_eq!(b.get(k).as_deref(), Some(v.as_slice()), "synced key lost on reopen");
        }
        let exported = b.snapshot_export();
        assert_eq!(
            exported.entries, committed,
            "reopened state must re-export the identical snapshot"
        );
    }

    // ---- A crash never splits a batch ----
    // `unset` writes three keys and deletes one; after an unsynced
    // drop the reopened state must be exactly `committed` (buffered
    // backend discarded the batch) or `committed + batch` (write-
    // through backend persisted it) — any mixture is a torn batch.
    let dir = base.join("split");
    let batch: Vec<Op> = vec![
        Op::Set { key: key1(0xA0), value: vec![1] },
        Op::Set { key: key1(0xA1), value: vec![2] },
        Op::Set { key: key1(0xA2), value: vec![3] },
        Op::Delete { key: committed[0].0 },
    ];
    {
        let mut b = make_at(&dir);
        for (k, v) in &committed {
            b.apply_batch(&[Op::Set { key: *k, value: v.clone() }])
                .expect("apply_batch must succeed");
        }
        b.sync().expect("sync must succeed");
        b.apply_batch(&batch).expect("apply_batch must succeed");
        // No sync: drop here is a crash one step after the API call.
    }
    let expected_without: BTreeMap<Hash, Vec<u8>> = committed.iter().cloned().collect();
    let mut expected_with = expected_without.clone();
    apply_ops_to_map(&mut expected_with, &batch);
    {
        let b = make_at(&dir);
        let actual: BTreeMap<Hash, Vec<u8>> = b.range(b"").into_iter().collect();
        assert!(
            actual == expected_without || actual == expected_with,
            "reopened state must be a whole-batch prefix — partial \
             batch application across a crash is a torn write \
             (missing: {:?}, extra: {:?})",
            expected_without
                .keys()
                .chain(expected_with.keys())
                .filter(|k| !actual.contains_key(*k))
                .collect::<Vec<_>>(),
            actual.keys().filter(|k| !expected_with.contains_key(*k)).collect::<Vec<_>>(),
        );
        // ---- Reopened state accepts new batches ----
        let mut b = b;
        let more = vec![Op::Set { key: key1(0xF0), value: vec![9] }];
        b.apply_batch(&more).expect("post-reopen batch must apply");
        b.sync().expect("post-reopen sync must succeed");
        drop(b);
        let b = make_at(&dir);
        let mut expected = actual.clone();
        apply_ops_to_map(&mut expected, &more);
        let actual2: BTreeMap<Hash, Vec<u8>> = b.range(b"").into_iter().collect();
        assert_eq!(
            actual2, expected,
            "state after reopen+append+reopen must accumulate, not reset"
        );
    }

    let _ = std::fs::remove_dir_all(&base);
}

/// Replay ops into a map — the suite's model of `apply_batch` for
/// comparing expected vs actual state (same last-op-wins rule).
fn apply_ops_to_map(state: &mut BTreeMap<Hash, Vec<u8>>, ops: &[Op]) {
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

// ---- Test keys ----

/// A key with a given first byte (rest zero-padded to 32 bytes).
fn key1(first: u8) -> Hash {
    let mut k = [0u8; 32];
    k[0] = first;
    Hash(k)
}

/// A key with a given prefix (first 2 bytes) and last byte.
fn key2(prefix: [u8; 2], last: u8) -> Hash {
    let mut k = [0u8; 32];
    k[0] = prefix[0];
    k[1] = prefix[1];
    k[31] = last;
    Hash(k)
}

// ---- Properties ----

/// Batch atomicity: `apply_batch` applies all ops in order, last-op-wins
/// for duplicate keys. A batch with mixed Set/Delete produces the correct
/// final state.
fn batch_atomicity<B: StorageBackend>(make_backend: &impl Fn() -> B) {
    let mut store = make_backend();
    let k1 = key1(1);
    let k2 = key1(2);

    // Batch with two Sets to the same key — last wins.
    store
        .apply_batch(&[
            Op::Set { key: k1, value: b"first".to_vec() },
            Op::Set { key: k1, value: b"second".to_vec() },
            Op::Set { key: k2, value: b"v2".to_vec() },
        ])
        .expect("apply_batch must succeed");
    assert_eq!(store.get(&k1), Some(b"second".to_vec()));
    assert_eq!(store.get(&k2), Some(b"v2".to_vec()));

    // Batch with a Delete then re-Set — the re-Set wins (applied in order).
    store
        .apply_batch(&[Op::Delete { key: k1 }, Op::Set { key: k1, value: b"resurrected".to_vec() }])
        .expect("apply_batch must succeed");
    assert_eq!(store.get(&k1), Some(b"resurrected".to_vec()));
}

/// Deterministic iteration order: `range` returns keys in lexicographic
/// order regardless of insertion order.
fn deterministic_iteration_order<B: StorageBackend>(make_backend: &impl Fn() -> B) {
    let mut store = make_backend();
    // Insert in reverse order to prove range sorts, not insertion-order.
    let prefix = [0x42u8; 2];
    store
        .apply_batch(&[
            Op::Set { key: key2(prefix, 3), value: vec![3] },
            Op::Set { key: key2(prefix, 1), value: vec![1] },
            Op::Set { key: key2(prefix, 2), value: vec![2] },
            Op::Set { key: key1(9), value: vec![9] }, // different prefix
        ])
        .expect("apply_batch must succeed");

    let hits = store.range(&prefix);
    assert_eq!(hits.len(), 3, "non-matching keys excluded");
    let lasts: Vec<u8> = hits.iter().map(|(k, _)| k.as_bytes()[31]).collect();
    assert_eq!(lasts, vec![1, 2, 3], "keys must be in lexicographic order");
}

/// Crash-replay determinism: two fresh backends fed the same batch
/// sequence produce byte-identical state.
fn crash_replay_determinism<B: StorageBackend>(make_backend: &impl Fn() -> B) {
    let batches: Vec<Vec<Op>> = vec![
        vec![
            Op::Set { key: key1(1), value: b"a".to_vec() },
            Op::Set { key: key1(2), value: b"b".to_vec() },
        ],
        vec![Op::Delete { key: key1(1) }],
        vec![
            Op::Set { key: key1(3), value: b"c".to_vec() },
            Op::Set { key: key1(2), value: b"b2".to_vec() },
        ],
    ];

    let mut first = make_backend();
    for batch in &batches {
        first.apply_batch(batch).expect("apply_batch must succeed");
    }

    let mut second = make_backend();
    for batch in &batches {
        second.apply_batch(batch).expect("apply_batch must succeed");
    }

    // Both backends must have identical state.
    let first_all = first.range(&[]);
    let second_all = second.range(&[]);
    assert_eq!(
        first_all, second_all,
        "two runs with identical batches must produce identical state"
    );
}

/// Prefix exactness: `range(prefix)` returns exactly the keys starting
/// with `prefix` — no more, no less. Edge cases: empty prefix (all
/// keys), all-0xFF prefix (matches nothing past it), prefix longer
/// than the key width (matches nothing).
fn prefix_exactness<B: StorageBackend>(make_backend: &impl Fn() -> B) {
    let mut store = make_backend();
    store
        .apply_batch(&[
            Op::Set { key: key1(0x42), value: vec![1] },
            Op::Set { key: key1(0x43), value: vec![2] },
            Op::Set { key: key1(0x44), value: vec![3] },
        ])
        .expect("apply_batch must succeed");

    // 1-byte prefix matches exactly one key.
    assert_eq!(store.range(&[0x42]).len(), 1);
    assert_eq!(store.range(&[0x43]).len(), 1);

    // Empty prefix = all keys.
    assert_eq!(store.range(&[]).len(), 3);

    // All-0xFF prefix: no keys start with 0xFF.
    assert!(store.range(&[0xFF]).is_empty());

    // Prefix longer than 32 bytes matches nothing.
    assert!(store.range(&[0x42; 33]).is_empty());
}

/// Delete idempotence: deleting an absent key is a no-op, not an error.
/// Deleting a key twice produces the same state as deleting once.
fn delete_idempotence<B: StorageBackend>(make_backend: &impl Fn() -> B) {
    let mut store = make_backend();
    let k = key1(5);

    // Delete of absent key is a no-op.
    store.apply_batch(&[Op::Delete { key: k }]).expect("apply_batch must succeed");
    assert!(store.get(&k).is_none());

    // Set then delete twice — same as delete once.
    store
        .apply_batch(&[Op::Set { key: k, value: b"v".to_vec() }])
        .expect("apply_batch must succeed");
    store.apply_batch(&[Op::Delete { key: k }]).expect("apply_batch must succeed");
    let state_after_one_delete = store.range(&[]);
    store.apply_batch(&[Op::Delete { key: k }]).expect("apply_batch must succeed");
    let state_after_two_deletes = store.range(&[]);
    assert_eq!(state_after_one_delete, state_after_two_deletes, "double delete must be idempotent");
}

/// Snapshot export/import round-trip: export a snapshot from one
/// backend, import it into a fresh backend, and verify the state is
/// byte-identical (plan.md §8, §2.5).
///
/// This is the gate for state sync: a new node imports a snapshot to
/// skip replaying the entire journal from genesis. The round-trip
/// must be lossless — export → import → export must produce the same
/// snapshot.
fn snapshot_round_trip<B: StorageBackend>(make_backend: &impl Fn() -> B) {
    // Populate a backend with some state.
    let mut store = make_backend();
    store
        .apply_batch(&[
            Op::Set { key: key1(1), value: b"alpha".to_vec() },
            Op::Set { key: key1(2), value: b"beta".to_vec() },
            Op::Set { key: key1(3), value: b"gamma".to_vec() },
            Op::Delete { key: key1(2) }, // delete one to test non-trivial state
        ])
        .expect("apply_batch must succeed");

    // Export the snapshot.
    let snapshot: Snapshot = store.snapshot_export();
    assert_eq!(snapshot.entries.len(), 2, "snapshot must have 2 keys (1 deleted)");

    // Import into a fresh backend.
    let mut store2 = make_backend();
    store2.snapshot_import(snapshot.clone()).expect("import must succeed");

    // Verify the imported state matches the original.
    let original_state = store.range(&[]);
    let imported_state = store2.range(&[]);
    assert_eq!(original_state, imported_state, "imported state must match original");

    // Re-export from the imported backend and verify round-trip equality.
    let snapshot2: Snapshot = store2.snapshot_export();
    assert_eq!(snapshot.entries, snapshot2.entries, "round-trip must be lossless");
}
