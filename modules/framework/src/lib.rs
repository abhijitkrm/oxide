//! Oxide module framework — Cosmos-SDK-style module dispatch and routing.
//!
//! The framework provides the shared infrastructure modules use:
//! - The `Module` trait (re-exported from `executor`).
//! - Module dispatch IDs (canonical constants).
//! - A `ModuleRouter` that registers modules and routes messages.
//! - Shared storage prefix conventions.
//!
//! # Phase 1 scope
//!
//! v0 is a minimal router: modules are registered with a dispatch ID,
//! and the router forwards messages. No ABCI-style hooks beyond what
//! the `executor::Module` trait defines. The storage layer is a
//! simple in-memory `BTreeMap` (the real storage backend arrives with
//! the `storage` crate integration).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use executor::Module;
use primitives::Hash;

/// Canonical module dispatch IDs. These are stable wire constants —
/// changing them is a consensus-breaking change.
pub mod module_id {
    /// The core module: chain parameters, metadata.
    pub const CORE: u8 = 0;
    /// The bank module: token transfers and balances.
    pub const BANK: u8 = 1;
    /// The staking module: delegation, validation, slashing.
    pub const STAKING: u8 = 2;
    /// The EVM module: revm host, precompiles, EIP-1559.
    pub const EVM: u8 = 3;
}

/// A shared in-memory key-value store for module state.
///
/// Each module owns a subtree keyed by its dispatch ID. The store is
/// behind `Mutex` because `Module::handle` takes `&self` (the executor
/// is single-threaded in the deterministic runtime, but the trait
/// requires `Sync`).
pub type KVStore = Mutex<BTreeMap<Vec<u8>, Vec<u8>>>;

/// A module router: registers modules and provides lookup.
pub struct ModuleRouter {
    modules: BTreeMap<u8, Arc<dyn Module>>,
}

impl ModuleRouter {
    /// Construct an empty router.
    pub fn new() -> Self {
        Self { modules: BTreeMap::new() }
    }

    /// Register a module by its dispatch ID.
    ///
    /// # Panics
    ///
    /// Panics if a module with the same ID is already registered.
    pub fn register(&mut self, module: Arc<dyn Module>) {
        let id = module.id();
        assert!(self.modules.insert(id, module).is_none(), "module {id} already registered");
    }

    /// Look up a module by dispatch ID.
    pub fn get(&self, id: u8) -> Option<&Arc<dyn Module>> {
        self.modules.get(&id)
    }

    /// Iterate all registered modules.
    pub fn modules(&self) -> impl Iterator<Item = &Arc<dyn Module>> {
        self.modules.values()
    }
}

impl Default for ModuleRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a deterministic state root for a KV subtree by hashing
/// all (key, value) pairs in sorted order.
///
/// # Panics
///
/// Panics if the `KVStore` mutex is poisoned (a thread panicked while
/// holding the lock).
pub fn subtree_root(store: &KVStore) -> Hash {
    use crypto::hash::{Domain, Hasher};
    let mut data = Vec::new();
    let locked = store.lock().unwrap();
    for (k, v) in locked.iter() {
        data.extend_from_slice(k);
        data.extend_from_slice(&(v.len() as u64).to_le_bytes());
        data.extend_from_slice(v);
    }
    Hasher::hash_one(Domain::Block, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use executor::{Event, ExecError};
    use primitives::Height;

    struct DummyModule {
        store: KVStore,
    }

    impl Module for DummyModule {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn id(&self) -> u8 {
            module_id::CORE
        }
        fn begin_block(&self, _h: Height) {}
        fn handle(&self, _ctx: &executor::TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            self.store.lock().unwrap().insert(b"last".to_vec(), msg.to_vec());
            Ok(vec![])
        }
        fn end_block(&self, _h: Height) {}
        fn state_root(&self) -> Hash {
            subtree_root(&self.store)
        }
    }

    #[test]
    fn router_registers_and_looks_up() {
        let mut router = ModuleRouter::new();
        let module = Arc::new(DummyModule { store: Mutex::new(BTreeMap::new()) });
        router.register(module);
        assert!(router.get(module_id::CORE).is_some());
        assert!(router.get(99).is_none());
    }

    #[test]
    fn subtree_root_changes_with_state() {
        let store: KVStore = Mutex::new(BTreeMap::new());
        let root0 = subtree_root(&store);
        store.lock().unwrap().insert(b"k".to_vec(), b"v".to_vec());
        let root1 = subtree_root(&store);
        assert_ne!(root0, root1, "state root must change when state changes");
    }
}
