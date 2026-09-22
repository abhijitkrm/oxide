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
        *framework::lock_state(&self.current_height)
    }

    /// The current epoch.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn current_epoch(&self) -> u64 {
        *framework::lock_state(&self.current_epoch)
    }

    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        w.put_u64(*framework::lock_state(&self.current_height));
        w.put_u64(*framework::lock_state(&self.current_epoch));
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema.
    fn decode_committed(r: &mut framework::CanonicalReader<'_>) -> Option<(u64, u64)> {
        let height = r.get_u64()?;
        let epoch = r.get_u64()?;
        Some((height, epoch))
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
        let mut store = framework::lock_state(&self.store);
        store.insert(b"height".to_vec(), height.value().to_le_bytes().to_vec());
    }

    fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        // The core module has no user-facing messages in v0.
        Ok(vec![])
    }

    fn end_block(&self, height: Height) -> Vec<Event> {
        *framework::lock_state(&self.current_height) = height.value();
        Vec::new()
    }

    fn state_root(&self) -> Hash {
        // C8: commit every field — the store only holds `height`;
        // `current_epoch` lives in memory and must move the root.
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        w.root()
    }

    /// Export the committed state as one canonical blob —
    /// `canon ‖ store`. The canon section is the `state_root`
    /// preimage, so a peer can verify the claimed root before
    /// installing anything (audit 3.2).
    fn export_state(&self) -> Option<storage::Snapshot> {
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        Some(storage::Snapshot {
            height: 0,
            entries: vec![(
                framework::state_blob_key(),
                framework::encode_state_blob(w.as_bytes(), &framework::lock_state(&self.store)),
            )],
        })
    }

    /// Verify a staged snapshot's claimed root without mutating:
    /// decode the blob, check the store section hashes to the
    /// committed subtree root, fully decode the fields, then hash
    /// the canonical preimage.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let (canon, _fields, _store) =
            framework::stage_blob_snapshot(snapshot, |r, _store| Self::decode_committed(r))?;
        Ok(framework::canon_root(canon))
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then the fields swap in
    /// atomically (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let (_canon, (height, epoch), store) =
            framework::stage_blob_snapshot(snapshot, |r, _store| Self::decode_committed(r))?;
        *framework::lock_state(&self.store) = store;
        *framework::lock_state(&self.current_height) = height;
        *framework::lock_state(&self.current_epoch) = epoch;
        Ok(())
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

    /// Export → inspect → import must reproduce the exact committed
    /// state: the staged root equals the live root, and a fresh
    /// module importing the snapshot reports the same root.
    #[test]
    fn core_module_state_round_trips() {
        let src = CoreModule::new();
        src.begin_block(Height::new(7));
        src.end_block(Height::new(7));
        let snapshot = src.export_state().expect("core exports state");
        assert_eq!(
            src.inspect_state(&snapshot).unwrap(),
            src.state_root(),
            "staged root must equal the live root"
        );

        let dst = CoreModule::new();
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), src.state_root());
        assert_eq!(dst.current_height(), 7);
    }

    /// Corrupt payloads must fail inspection, not import.
    #[test]
    fn core_module_rejects_corrupt_state() {
        let src = CoreModule::new();
        src.begin_block(Height::new(7));
        src.end_block(Height::new(7));
        let mut snapshot = src.export_state().unwrap();
        // Truncate the blob — decode must fail.
        snapshot.entries[0].1.truncate(10);
        assert!(src.inspect_state(&snapshot).is_err());
        assert!(CoreModule::new().import_state(&snapshot).is_err());
    }
}
