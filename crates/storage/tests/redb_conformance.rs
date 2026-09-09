//! Storage conformance for the `redb` adapter (Phase 2).
//!
//! Runs `assert_storage_conformance` against `RedbBackend` to verify
//! it satisfies the same contract as `Volatile`. This is the gate
//! redb must pass before it can be registered in node wiring.

#![cfg(feature = "redb")]

use ports::storage_conformance::assert_storage_conformance;
use storage::RedbBackend;

fn make_redb() -> RedbBackend {
    let path = std::env::temp_dir().join(format!(
        "oxide_redb_conformance_{}_{}.db",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    RedbBackend::open(&path).expect("open redb")
}

#[test]
fn redb_passes_storage_conformance() {
    assert_storage_conformance(make_redb);
}
