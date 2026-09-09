//! Storage backend performance report card (plan.md §13, Phase 2).
//!
//! ## What this benchmark is
//!
//! Compares the throughput of all `StorageBackend` adapters
//! (`Volatile`, `RedbBackend`, `RocksDbBackend`, `MdbxBackend`)
//! on the two operations that matter for Oxide:
//!
//! 1. `apply_batch` — block commit (the hot path).
//! 2. `get` — point read (RPC queries, state access).
//!
//! ## Acceptance gate
//!
//! plan.md §13: "storage-conformance + perf report card green for
//! every shipped adapter". This benchmark generates the perf
//! report card — it runs, produces numbers, and documents them
//! in the devlog. The gate is "runs and reports", not a specific
//! throughput target (throughput depends on hardware).

#![allow(missing_docs)]

/// Fallback `main` for when no storage features are enabled.
/// The actual benchmarks are behind `#[cfg(feature = "...")]` guards
/// on each function. Without this, `cargo build --benches` fails
/// with "main function not found" when no features are enabled.
#[cfg(not(any(feature = "redb", feature = "rocksdb", feature = "mdbx")))]
fn main() {
    eprintln!(
        "This benchmark requires at least one storage feature: \
         cargo bench --features redb|rocksdb|mdbx"
    );
}

#[cfg(any(feature = "redb", feature = "rocksdb", feature = "mdbx"))]
criterion_group!(benches, bench_apply_batch, bench_get);
#[cfg(any(feature = "redb", feature = "rocksdb", feature = "mdbx"))]
criterion_main!(benches);

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primitives::Hash;
use storage::{Op, StorageBackend, Volatile};

#[cfg(feature = "redb")]
use storage::RedbBackend;

#[cfg(feature = "rocksdb")]
use storage::RocksDbBackend;

#[cfg(feature = "mdbx")]
use storage::MdbxBackend;

/// Number of keys to write in each batch.
const BATCH_SIZE: usize = 1_000;

/// Generate `n` unique (key, value) pairs for a batch.
fn make_batch(n: usize) -> Vec<Op> {
    (0..n)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            let val_byte = u8::try_from(i % 256).unwrap_or(0);
            Op::Set { key: Hash(key), value: vec![val_byte; 64] }
        })
        .collect()
}

/// The first key from a batch (for point-read benchmarks).
fn first_key(batch: &[Op]) -> Hash {
    match &batch[0] {
        Op::Set { key, .. } | Op::Delete { key } => *key,
    }
}

/// Benchmark `apply_batch` (block commit) across backends.
fn bench_apply_batch(c: &mut Criterion) {
    let batch = make_batch(BATCH_SIZE);
    let mut group = c.benchmark_group("storage_apply_batch");
    group.throughput(Throughput::Elements(BATCH_SIZE as u64));

    // Volatile (in-memory reference).
    group.bench_with_input(BenchmarkId::new("apply_batch", "Volatile"), &batch, |b, batch| {
        b.iter_with_setup(Volatile::new, |mut store| {
            store.apply_batch(std::hint::black_box(batch));
            store
        });
    });

    // redb (disk-backed, pure Rust).
    #[cfg(feature = "redb")]
    group.bench_with_input(BenchmarkId::new("apply_batch", "RedbBackend"), &batch, |b, batch| {
        b.iter_with_setup(
            || {
                let path = std::env::temp_dir().join(format!(
                    "oxide_bench_redb_{}_{}.db",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                RedbBackend::open(&path).expect("open redb")
            },
            |mut store| {
                store.apply_batch(std::hint::black_box(batch));
                store
            },
        );
    });

    // RocksDB (disk-backed, LSM).
    #[cfg(feature = "rocksdb")]
    group.bench_with_input(
        BenchmarkId::new("apply_batch", "RocksDbBackend"),
        &batch,
        |b, batch| {
            b.iter_with_setup(
                || {
                    let path = std::env::temp_dir().join(format!(
                        "oxide_bench_rocksdb_{}_{}.db",
                        std::process::id(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos()
                    ));
                    RocksDbBackend::open(&path).expect("open rocksdb")
                },
                |mut store| {
                    store.apply_batch(std::hint::black_box(batch));
                    store
                },
            );
        },
    );

    // MDBX (disk-backed, B-tree).
    #[cfg(feature = "mdbx")]
    group.bench_with_input(BenchmarkId::new("apply_batch", "MdbxBackend"), &batch, |b, batch| {
        b.iter_with_setup(
            || {
                let path = std::env::temp_dir().join(format!(
                    "oxide_bench_mdbx_{}_{}.db",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                MdbxBackend::open(&path).expect("open mdbx")
            },
            |mut store| {
                store.apply_batch(std::hint::black_box(batch));
                store
            },
        );
    });

    group.finish();
}

/// Benchmark `get` (point read) across backends.
fn bench_get(c: &mut Criterion) {
    let batch = make_batch(BATCH_SIZE);
    let key = first_key(&batch);
    let mut group = c.benchmark_group("storage_get");
    group.throughput(Throughput::Elements(1));

    // Volatile (in-memory reference).
    group.bench_with_input(BenchmarkId::new("get", "Volatile"), &batch, |b, batch| {
        let mut store = Volatile::new();
        store.apply_batch(batch);
        b.iter(|| std::hint::black_box(store.get(std::hint::black_box(&key))));
    });

    // redb (disk-backed, pure Rust).
    #[cfg(feature = "redb")]
    group.bench_with_input(BenchmarkId::new("get", "RedbBackend"), &batch, |b, batch| {
        let path = std::env::temp_dir().join(format!(
            "oxide_bench_get_redb_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut store = RedbBackend::open(&path).expect("open redb");
        store.apply_batch(batch);
        b.iter(|| std::hint::black_box(store.get(std::hint::black_box(&key))));
    });

    // RocksDB (disk-backed, LSM).
    #[cfg(feature = "rocksdb")]
    group.bench_with_input(BenchmarkId::new("get", "RocksDbBackend"), &batch, |b, batch| {
        let path = std::env::temp_dir().join(format!(
            "oxide_bench_get_rocksdb_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut store = RocksDbBackend::open(&path).expect("open rocksdb");
        store.apply_batch(batch);
        b.iter(|| std::hint::black_box(store.get(std::hint::black_box(&key))));
    });

    // MDBX (disk-backed, B-tree).
    #[cfg(feature = "mdbx")]
    group.bench_with_input(BenchmarkId::new("get", "MdbxBackend"), &batch, |b, batch| {
        let path = std::env::temp_dir().join(format!(
            "oxide_bench_get_mdbx_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut store = MdbxBackend::open(&path).expect("open mdbx");
        store.apply_batch(batch);
        b.iter(|| std::hint::black_box(store.get(std::hint::black_box(&key))));
    });

    group.finish();
}
