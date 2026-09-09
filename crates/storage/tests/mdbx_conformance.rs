//! Storage conformance for the `MDBX` adapter (Phase 2).
//!
//! Runs `assert_storage_conformance` against `MdbxBackend` to verify
//! it satisfies the same contract as `Volatile`, `RedbBackend`, and
//! `RocksDbBackend`.

#![cfg(feature = "mdbx")]

use ports::storage_conformance::assert_storage_conformance;
use storage::MdbxBackend;

fn make_mdbx() -> MdbxBackend {
    let path = std::env::temp_dir().join(format!(
        "oxide_mdbx_conformance_{}_{}.db",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    MdbxBackend::open(&path).expect("open mdbx")
}

#[test]
fn mdbx_passes_storage_conformance() {
    assert_storage_conformance(make_mdbx);
}
