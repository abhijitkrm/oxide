//! Storage conformance for the `RocksDB` adapter (Phase 2).
//!
//! Runs `assert_storage_conformance` against `RocksDbBackend` to verify
//! it satisfies the same contract as `Volatile` and `RedbBackend`.

#![cfg(feature = "rocksdb")]

use ports::storage_conformance::assert_storage_conformance;
use storage::RocksDbBackend;

fn make_rocksdb() -> RocksDbBackend {
    let path = std::env::temp_dir().join(format!(
        "oxide_rocksdb_conformance_{}_{}.db",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    RocksDbBackend::open(&path).expect("open rocksdb")
}

#[test]
fn rocksdb_passes_storage_conformance() {
    assert_storage_conformance(make_rocksdb);
}
