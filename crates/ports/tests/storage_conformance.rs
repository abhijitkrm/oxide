//! Storage conformance suite — runs `assert_storage_conformance`
//! against every registered `StorageBackend` adapter.
//!
//! Phase 2: `Volatile` (the in-memory reference) is the only
//! registered adapter. `MDBX`, `RocksDB`, and `redb` adapters must pass
//! this same suite before they can be registered in node wiring.

use ports::storage_conformance::assert_storage_conformance;
use storage::Volatile;

#[test]
fn volatile_passes_storage_conformance() {
    assert_storage_conformance(Volatile::new);
}
