//! Oxide core module — chain parameters, metadata, genesis state.
//!
//! The core module holds chain-wide constants that don't belong to any
//! specific application module: the chain ID, the current epoch, the
//! block height counter, and the consensus parameters. It's the
//! module-equivalent of Cosmos SDK's `x/params` + `x/genutil`.
//!
//! # Phase 1 scope
//!
//! v0 tracks the chain height and epoch. No parameter governance yet.

use std::collections::BTreeMap;
use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::{KVStore, module_id, subtree_root};
use primitives::{Hash, Height};

/// The core module: chain metadata.
pub struct CoreModule {
    store: KVStore,
    /// Current chain height (advanced in `end_block`).
    current_height: Mutex<u64>,
    /// Current epoch.
    current_epoch: Mutex<u64>,
}

impl CoreModule {
    /// Construct a fresh core module at genesis (height 0, epoch 0).
    pub fn new() -> Self {
        Self {
            store: Mutex::new(BTreeMap::new()),
            current_height: Mutex::new(0),
            current_epoch: Mutex::new(0),
        }
    }

    /// The current chain height.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn current_height(&self) -> u64 {
        *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The current epoch.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn current_epoch(&self) -> u64 {
        *self.current_epoch.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for CoreModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for CoreModule {
    fn name(&self) -> &'static str {
        "core"
    }
    fn id(&self) -> u8 {
        module_id::CORE
    }

    fn begin_block(&self, height: Height) {
        // Record the block height in the store.
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.insert(b"height".to_vec(), height.value().to_le_bytes().to_vec());
    }

    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        // The core module has no user-facing messages in v0.
        Ok(vec![])
    }

    fn end_block(&self, height: Height) {
        *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            height.value();
    }

    fn state_root(&self) -> Hash {
        // C8: commit every field — the store only holds `height`;
        // `current_epoch` lives in memory and must move the root.
        let mut w = framework::CanonicalState::new();
        w.put_root(&subtree_root(&self.store));
        w.put_u64(*self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        w.put_u64(*self.current_epoch.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        w.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_module_tracks_height() {
        let module = CoreModule::new();
        assert_eq!(module.current_height(), 0);
        module.begin_block(Height::new(5));
        module.end_block(Height::new(5));
        assert_eq!(module.current_height(), 5);
    }

    #[test]
    fn core_module_state_root_changes_with_height() {
        let module = CoreModule::new();
        let root0 = module.state_root();
        module.begin_block(Height::new(1));
        module.end_block(Height::new(1));
        let root1 = module.state_root();
        assert_ne!(root0, root1, "state root must change when height changes");
    }
}
