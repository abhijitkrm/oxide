//! Executor snapshot boundary.
//!
//! Split from `lib.rs` around the durability invariant:
//! [`Executor::export_snapshot`] / [`Executor::import_snapshot`]
//! and the executed-nonce journal are the only paths that move
//! executor state across the storage boundary. Nonce persistence
//! is replay protection — it must round-trip exactly or a
//! restarted node re-executes transactions.

use super::{
    Arc, ExecutedNonces, Executor, ExecutorSnapshot, Hash, Module, SNAPSHOT_FORMAT_VERSION,
    SnapshotImportError, canonical_state_root, compute_nonce_root,
};

impl Executor {
    /// Save executed nonces to a storage backend (C10 fix).
    ///
    /// Persists the per-sender `executed_nonce` map to the storage
    /// backend using a reserved key prefix. Call this on shutdown
    /// or after each block commit to ensure nonces survive restart.
    /// Without this, a restart resets all executed nonces to zero,
    /// allowing replay of already-executed native transactions.
    ///
    /// # Errors
    ///
    /// Returns [`storage::ApplyError`] when the backend rejects the
    /// batch — the nonce map was NOT persisted and a restart would
    /// reopen the replay window; the caller must not treat the
    /// shutdown/commit as complete.
    pub fn save_executed_nonces(
        &self,
        backend: &mut (dyn storage::StorageBackend + Send),
    ) -> Result<(), storage::ApplyError> {
        /// Key prefix: `exec_nonce` padded to 32 bytes. Each entry
        /// is keyed by `prefix || addr` and valued by the nonce as
        /// 8-byte LE.
        const PREFIX: &[u8] = b"exec_nonce";
        let nonces = primitives::sync::lock_state(&self.executed_nonce);
        let mut ops: Vec<storage::Op> = Vec::with_capacity(nonces.map.len());
        for (addr, nonce) in &nonces.map {
            let mut key_bytes = [0u8; 32];
            key_bytes[..PREFIX.len()].copy_from_slice(PREFIX);
            key_bytes[PREFIX.len()..PREFIX.len() + 20].copy_from_slice(&addr.0);
            ops.push(storage::Op::Set {
                key: primitives::Hash(key_bytes),
                value: nonce.to_le_bytes().to_vec(),
            });
        }
        backend.apply_batch(&ops)
    }

    /// Load executed nonces from a storage backend (C10 fix).
    ///
    /// Restores the per-sender `executed_nonce` map from the storage
    /// backend. Call this on startup before processing any
    /// transactions.
    pub fn load_executed_nonces(&self, backend: &(dyn storage::StorageBackend + Send)) {
        const PREFIX: &[u8] = b"exec_nonce";
        let entries = backend.range(PREFIX);
        let mut nonces = primitives::sync::lock_state(&self.executed_nonce);
        let nonces = Arc::make_mut(&mut nonces);
        for (key, value) in entries {
            let addr_bytes = &key.0[PREFIX.len()..PREFIX.len() + 20];
            let mut addr_arr = [0u8; 20];
            addr_arr.copy_from_slice(addr_bytes);
            let addr = primitives::Address(addr_arr);
            if value.len() >= 8 {
                let nonce = u64::from_le_bytes(value[..8].try_into().unwrap_or([0u8; 8]));
                // `bump` (not a bare map insert) keeps the folded
                // root in lockstep — restore is O(entries) once, a
                // cold path.
                nonces.bump(addr, nonce);
            }
        }
    }

    /// Block until the execution lane has fully drained — every
    /// enqueued block executed. Callers that must observe a
    /// consistent cross-module state (snapshot export, state sync)
    /// wait here rather than reading module state while the worker
    /// is mid-block. No-op when the lane is not installed or is
    /// already idle.
    pub(crate) fn wait_exec_idle(&self) {
        if self.exec_lane_tx.get().is_some() {
            let (lock, cv) = &*self.exec_sync;
            let mut s = primitives::sync::lock_state(lock);
            while s.enqueued != s.executed {
                s = cv.wait(s).unwrap_or_else(|_| {
                    panic!("state mutex poisoned: a holder panicked mid-mutation")
                });
            }
        }
    }

    /// Export a snapshot of the executor's state at the current
    /// chain height.
    ///
    /// The snapshot captures:
    /// - The chain height.
    /// - The aggregate state root (hash of all module state roots).
    /// - Per-module state roots (for verification on import).
    ///
    /// This is used for fast state sync: a new node imports a
    /// snapshot to skip replaying the entire chain from genesis.
    /// The snapshot is deterministic: two executors with the same
    /// state produce byte-identical snapshots.
    ///
    /// Drains the execution lane before reading module state so the
    /// snapshot captures a quiesced height boundary, never a
    /// mid-block mix of pre- and post-execution module roots.
    #[must_use]
    pub fn export_snapshot(&self) -> ExecutorSnapshot {
        // Drain the execution lane first: module state is mutated by
        // the worker thread block-by-block, so a snapshot taken
        // mid-block could mix pre- and post-execution module roots.
        // Waiting for `executed == enqueued` captures a quiesced
        // height boundary.
        self.wait_exec_idle();
        let height = self.current_height();
        let state_root = self.state_root_at(height);
        let module_roots: Vec<(String, Hash)> =
            self.modules.iter().flatten().map(|m| (m.name().to_string(), m.state_root())).collect();
        // Export full KV state for each module that supports it.
        let module_state: Vec<Option<storage::Snapshot>> =
            self.modules.iter().flatten().map(|m| m.export_state()).collect();
        // C8: recompute the canonical aggregate — module roots +
        // nonce root, the same definition `execute_block` uses. We
        // always recompute (rather than using the stored root)
        // because the stored root may be stale if the block hasn't
        // been executed yet (async execution), and the nonce root
        // binds `executed_nonces` into the commitment.
        let _ = state_root; // stored root may be stale; we recompute below
        let (executed_nonces, maintained_root) = {
            let en = primitives::sync::lock_state(&self.executed_nonce);
            (en.map.iter().map(|(addr, nonce)| (*addr, *nonce)).collect::<Vec<_>>(), en.root)
        };
        // Recompute from the bytes being exported — the snapshot's
        // `nonce_root` must commit to its own `executed_nonces`
        // payload. It must equal the incrementally-maintained root;
        // the assert makes any bookkeeping drift a test-visible bug
        // rather than a silent divergence between the live path and
        // the snapshot path.
        let nonce_root = compute_nonce_root(&executed_nonces);
        debug_assert_eq!(nonce_root, maintained_root, "nonce root drifted from its map");
        let state_root =
            canonical_state_root(module_roots.iter().map(|(_, root)| *root), nonce_root);
        ExecutorSnapshot {
            height,
            state_root,
            module_roots,
            module_state,
            executed_nonces,
            nonce_root,
            version: SNAPSHOT_FORMAT_VERSION,
            // Record each module's declared schema version so an
            // importer restoring this state under a newer binary
            // knows which `migrate(from)` calls to run.
            module_versions: self.modules.iter().flatten().map(|m| m.state_version()).collect(),
        }
    }

    /// Import a snapshot, restoring the executor to the snapshot's
    /// chain height and state.
    ///
    /// After import, the executor's `current_height` and
    /// `current_state_root` must match the snapshot. The next
    /// proposal height is set to `snapshot.height + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotImportError`] if:
    /// - The snapshot's state root does not match the recomputed
    ///   aggregate of the per-module state roots (corrupted snapshot).
    /// - The snapshot's height is 0 (empty snapshot — nothing to
    ///   import).
    ///
    /// # Panics
    ///
    /// Does not panic. Verification is atomic: no module state
    /// mutates until every module's staged payload has passed
    /// `inspect_state` against its claimed root.
    ///
    /// # Safety
    ///
    /// Every module's committed state is restored: modules that
    /// declare state (`export_state` → `Some`) must carry a payload
    /// whose `inspect_state` reproduces the claimed module root;
    /// stateless-declaring modules must match their construction
    /// root and carry no payload. Anything else — missing, extra,
    /// malformed, or mislabeled module state — fails the import
    /// before any mutation.
    pub fn import_snapshot(&self, snapshot: &ExecutorSnapshot) -> Result<(), SnapshotImportError> {
        // A snapshot at height 0 is valid — it represents the genesis
        // state after the first (empty) block. We only reject if there
        // are no module roots (truly empty snapshot).
        if snapshot.module_roots.is_empty() {
            return Err(SnapshotImportError::EmptySnapshot);
        }

        // Verify the snapshot's internal consistency: the state root
        // must match the recomputed canonical aggregate of the
        // snapshot's own per-module state roots AND the nonce root
        // (C8 — the same definition `execute_block` uses). This
        // catches corrupted or tampered snapshots without requiring
        // the local modules to have the same state (the snapshot is
        // from a peer, not local).
        // The nonce root is an XOR-fold over *set* semantics — a
        // duplicated `(addr, nonce)` pair folds out entirely while a
        // `HashMap::collect` silently dedupes it, so the installed
        // root would no longer match the fold of the installed map.
        // Reject duplicates explicitly: a sender appears at most
        // once in a well-formed snapshot.
        {
            let mut seen = std::collections::HashSet::with_capacity(snapshot.executed_nonces.len());
            if snapshot.executed_nonces.iter().any(|(addr, _)| !seen.insert(addr)) {
                return Err(SnapshotImportError::DuplicateNonceEntry);
            }
        }
        let recomputed_nonce_root = compute_nonce_root(&snapshot.executed_nonces);
        if recomputed_nonce_root != snapshot.nonce_root {
            return Err(SnapshotImportError::NonceRootMismatch {
                expected: snapshot.nonce_root,
                actual: recomputed_nonce_root,
            });
        }
        let recomputed = canonical_state_root(
            snapshot.module_roots.iter().map(|(_, root)| *root),
            recomputed_nonce_root,
        );
        if recomputed != snapshot.state_root {
            return Err(SnapshotImportError::StateRootMismatch {
                expected: snapshot.state_root,
                actual: recomputed,
            });
        }

        // Verify that the number of module roots matches the number
        // of registered modules. This catches snapshots from a
        // different module configuration.
        let registered_count = self.modules.iter().flatten().count();
        if snapshot.module_roots.len() != registered_count {
            return Err(SnapshotImportError::ModuleCountMismatch {
                snapshot: snapshot.module_roots.len(),
                registered: registered_count,
            });
        }

        // Format gate: a snapshot written by a newer binary cannot
        // be safely interpreted — reject before touching state.
        if snapshot.version > SNAPSHOT_FORMAT_VERSION {
            return Err(SnapshotImportError::UnsupportedVersion {
                snapshot: snapshot.version,
                supported: SNAPSHOT_FORMAT_VERSION,
            });
        }

        // Verify + restore every module's committed state — staged,
        // name-bound, and proven before a single byte is installed.
        self.restore_module_state(snapshot)?;

        // Import: set the chain height and state root. The local
        // modules' key-value state is restored above (if the snapshot
        // included it). We set the chain height so consensus can
        // resume from the correct position, and we store the trusted
        // state root for attestation.
        primitives::sync::lock_state(&self.state_roots)
            .insert(snapshot.height, snapshot.state_root);
        *primitives::sync::lock_state(&self.next_proposal_height) =
            snapshot.height.saturating_add(1); // M2 fix

        // H4/H5: restore the executed-nonce map so replay protection
        // survives restarts and state sync. Without this, a node
        // that restarts from a snapshot would accept already-executed
        // txs (replay attack).
        *primitives::sync::lock_state(&self.executed_nonce) = Arc::new(ExecutedNonces {
            map: snapshot.executed_nonces.iter().copied().collect(),
            // Verified above to equal both the fold of this map
            // and the snapshot's committed `nonce_root` — reuse
            // it rather than re-folding.
            root: recomputed_nonce_root,
        });

        Ok(())
    }

    /// Strict, staged module-state restore for [`import_snapshot`].
    ///
    /// A snapshot is untrusted until every module's claimed state has
    /// been proven from the staged bytes. Two passes:
    ///
    ///   1. VERIFY — bind names, check completeness, and run each
    ///      module's [`Module::inspect_state`] over the staged
    ///      payload so the claimed root is derived from the data, not
    ///      trusted. No module state is mutated in this pass.
    ///   2. APPLY — only after every module verifies, call
    ///      `import_state` + `migrate`.
    ///
    /// Binding: `module_state[i]` belongs to the module registered at
    /// position i only because `module_roots[i].0` equals its
    /// `name()` — position alone is not binding (a forged name list
    /// would slide a foreign blob into the wrong module).
    ///
    /// Completeness: `export_state` returning `Some` declares the
    /// module stateful — the snapshot must carry a payload whose
    /// `inspect_state` reproduces the claimed root. Returning `None`
    /// declares it stateless — its committed state is fixed at
    /// construction, so the claimed root must equal a fresh module's
    /// root, and any supplied payload is rejected as uninterpretable.
    ///
    /// # Errors
    ///
    /// `ModuleNameMismatch` when the claimed name doesn't match the
    /// registered module; `ModuleCountMismatch` when the state vector
    /// length disagrees with `module_roots`; `MissingModuleState` /
    /// `UnexpectedModuleState` on the stateful/stateless declaration
    /// boundary; `MalformedModuleState` when `inspect_state` rejects
    /// the payload; `ModuleRootMismatch` when the staged bytes don't
    /// hash to the claimed root; `StateImportFailed` / `MigrationFailed`
    /// during the apply pass.
    pub(crate) fn restore_module_state(
        &self,
        snapshot: &ExecutorSnapshot,
    ) -> Result<(), SnapshotImportError> {
        let modules: Vec<&Arc<dyn Module>> = self.modules.iter().flatten().collect();
        for (i, (module, (name, claimed_root))) in
            modules.iter().zip(&snapshot.module_roots).enumerate()
        {
            if module.name() != name.as_str() {
                return Err(SnapshotImportError::ModuleNameMismatch {
                    index: i,
                    snapshot: name.clone(),
                    registered: module.name().to_string(),
                });
            }
            if module.export_state().is_none() && module.state_root() != *claimed_root {
                // Stateless module claiming a root no fresh instance
                // produces — either the snapshot lies or the configs
                // differ.
                return Err(SnapshotImportError::ModuleRootMismatch {
                    module: name.clone(),
                    expected: *claimed_root,
                    actual: module.state_root(),
                });
            }
        }

        if snapshot.module_state.is_empty() {
            // Metadata-only snapshot: complete only when no module
            // declares committed state — anything else is missing
            // data, not a sparse encoding.
            for module in &modules {
                if module.export_state().is_some() {
                    return Err(SnapshotImportError::MissingModuleState {
                        module: module.name().to_string(),
                    });
                }
            }
            return Ok(());
        }

        if snapshot.module_state.len() != snapshot.module_roots.len() {
            return Err(SnapshotImportError::ModuleCountMismatch {
                snapshot: snapshot.module_state.len(),
                registered: modules.len(),
            });
        }
        // VERIFY pass — inspect every payload before mutating.
        let mut staged: Vec<(usize, &storage::Snapshot)> = Vec::new();
        for (i, module) in modules.iter().enumerate() {
            let (name, claimed_root) = &snapshot.module_roots[i];
            match &snapshot.module_state[i] {
                Some(state) => {
                    if module.export_state().is_none() {
                        return Err(SnapshotImportError::UnexpectedModuleState {
                            module: name.clone(),
                        });
                    }
                    let actual = module.inspect_state(state).map_err(|_| {
                        SnapshotImportError::MalformedModuleState { module: name.clone() }
                    })?;
                    if actual != *claimed_root {
                        return Err(SnapshotImportError::ModuleRootMismatch {
                            module: name.clone(),
                            expected: *claimed_root,
                            actual,
                        });
                    }
                    staged.push((i, state));
                }
                None => {
                    if module.export_state().is_some() {
                        return Err(SnapshotImportError::MissingModuleState {
                            module: name.clone(),
                        });
                    }
                }
            }
        }

        // APPLY pass — every module verified. `import_state`
        // re-decodes and installs atomically; `migrate` upgrades
        // the freshly imported bytes when the snapshot's recorded
        // schema trails the binary's declared version (empty
        // `module_versions` — v1 snapshots — means "all current",
        // as v1 predates the hook entirely). A backend I/O error
        // or failed migration can still leave an earlier module
        // applied: mutation-after-verification is inherent to
        // apply, but NO malformed input ever reaches this point.
        for (i, state) in staged {
            let module = modules[i];
            module.import_state(state).map_err(|_| SnapshotImportError::StateImportFailed)?;
            let from = snapshot.module_versions.get(i).copied().unwrap_or(module.state_version());
            if from < module.state_version() {
                module.migrate(from).map_err(|_| SnapshotImportError::MigrationFailed {
                    module: module.name().to_string(),
                    from,
                })?;
            }
        }
        Ok(())
    }
}
