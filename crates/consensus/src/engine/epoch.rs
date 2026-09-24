//! Epoch rotation for oxideBFT.
//!
//! Split from `engine.rs` around the epoch invariant: a rotation is
//! a two-phase commit — [`OxideBft::schedule_rotation`] stages the
//! next validator set, and the pending set activates only at an
//! epoch boundary, never mid-view. Validator/key changes flow
//! through `apply_*_changes` into [`OxideBft::build_next_set`], and
//! [`OxideBft::drive_epoch_changes`] is the single entry the app
//! calls per block. Keeping the whole rotation state machine in one
//! file makes it auditable that the validator set can never change
//! under an in-flight view.

use super::{Epoch, EpochRotationError, KeyChangeError, OxideBft, ValidatorSet, View};

impl OxideBft {
    /// Schedule an epoch rotation (stage 6). The new validator set
    /// takes over after the old set commits the last block of the
    /// current epoch. This is the first phase of the two-phase
    /// handoff: announce the new set, continue with the old set.
    ///
    /// The activation height defaults to the current committed
    /// height — callers that do not supply a certified delay (tests,
    /// simulations, `rotate_epoch` force-completions) keep the
    /// historical "next drive completes it" semantics. The
    /// production drain path uses [`Self::schedule_rotation_at`]
    /// with [`crate::engine::ROTATION_ACTIVATION_DELAY`].
    ///
    /// # Errors
    /// Returns `EpochRotationError::AlreadyPending` if a rotation is
    /// already pending (the caller must wait for it to complete).
    pub fn schedule_rotation(&mut self, new_set: ValidatorSet) -> Result<(), EpochRotationError> {
        let committed = self.last_committed.map_or(0, |(_, h)| h.value());
        self.schedule_rotation_at(new_set, committed)
    }

    /// Schedule an epoch rotation activating at a specific committed
    /// height. The pending set is observable via
    /// [`OxideBft::next_validator_set`] for the whole
    /// schedule→activation window — the transport layer publishes it
    /// so an incoming member's handshake is admitted *before* its
    /// first consensus duty.
    ///
    /// # Errors
    /// Returns `EpochRotationError::AlreadyPending` if a rotation is
    /// already pending.
    pub(crate) fn schedule_rotation_at(
        &mut self,
        new_set: ValidatorSet,
        activation_height: u64,
    ) -> Result<(), EpochRotationError> {
        if self.next_validator_set.is_some() {
            return Err(EpochRotationError::AlreadyPending);
        }
        self.next_validator_set = Some(new_set);
        self.rotation_activation_height = Some(activation_height);
        Ok(())
    }

    /// Complete the epoch rotation (stage 6, phase 2). Switches to
    /// the new validator set, increments the epoch, and resets the
    /// view to 0. Called when the old set commits the last block of
    /// the old epoch.
    ///
    /// # Errors
    /// Returns `EpochRotationError::NoPendingRotation` if no
    /// rotation is pending.
    fn complete_rotation(&mut self) -> Result<(), EpochRotationError> {
        let Some(new_set) = self.next_validator_set.take() else {
            return Err(EpochRotationError::NoPendingRotation);
        };
        self.rotation_activation_height = None;
        self.validator_set = new_set;
        // The reputation window indexes into the *old* committee —
        // its bitmaps name positions that no longer exist. Clear it:
        // the new set earns its own participation history (the
        // minimum-window guard keeps reputation inert until it has).
        self.recent_signers.clear();
        // Re-seat our own index under the new committee — removals
        // shift positions and the genesis index may now name a
        // different validator. Matching by BLS key is the honest
        // remap (it is the identity we can actually sign with).
        // `None` means we were removed: keep the stale index — our
        // signatures fail verification against the new set, which
        // is fail-closed silence, not authority.
        if let Some(ref signer) = self.signer
            && let Some(idx) = self.validator_set.index_of_key(&signer.public_key())
        {
            self.validator_index = idx;
        }
        // Saturating: epoch = u64::MAX would wrap to 0, confusing
        // the epoch boundary. Saturation is safe — the chain is
        // already dead at epoch u64::MAX.
        self.epoch = self.epoch.saturating_next();
        self.current_view = View::new(0);
        // The new epoch's first view starts the round-time mark
        // fresh — the pacemaker rebuild discards the old EWMA too.
        self.restart_view_mark();
        self.clear_epoch_scoped_state();
        // Persist the cleared locks: a crash between rotation and the
        // next vote would otherwise restore the old epoch's locks
        // from the WAL and wedge the new epoch's first heights (the
        // new chain continues from `last_committed`, so those stale
        // entries can never be released by a commit). A failure here
        // latches `wal_failed` — signing stays disabled from now on.
        // The entry carries the *new* validator set: a restart past
        // this point must recover the rotated committee, not the
        // genesis set the engine was constructed with — membership
        // and epoch become durable in the same fsync.
        let _ = self.append_wal_full(true);
        // Reset the pacemaker for the new epoch — carrying the
        // configured timeouts, not the compiled defaults: a rebuild
        // through `Pacemaker::new` here would silently revert the
        // operator's `base_timeout_ms`/`max_timeout_ms` at the first
        // rotation and desynchronize view timing from the effective
        // config every other validator is running.
        self.pacemaker = crate::pacemaker::Pacemaker::with_config(
            self.validator_set.clone(),
            View::new(0),
            self.epoch,
            self.pacemaker_base_timeout_ms,
            self.pacemaker_max_timeout_ms,
        );
        Ok(())
    }

    /// Force-complete the epoch rotation (for tests and simulation).
    /// This completes the rotation immediately, regardless of whether
    /// the old set has committed the last block. In production, the
    /// rotation completes automatically when the old set commits.
    ///
    /// # Errors
    /// Returns `EpochRotationError::NoPendingRotation` if no rotation
    /// is pending.
    pub fn rotate_epoch(&mut self) -> Result<(), EpochRotationError> {
        self.complete_rotation()
    }

    /// Drop every piece of state scoped to the epoch that just ended.
    ///
    /// Shared by [`Self::complete_rotation`] (scheduled committee
    /// swap) and [`Self::adopt_certified_epoch`] (QC-proven epoch
    /// adoption for a node that already holds the new committee):
    /// both paths cross an epoch boundary, and everything the old
    /// epoch produced — vote locks, timeout bars, high-QC, TC
    /// evidence, attestation pool, rejection memos — is meaningless
    /// or actively harmful across it. The vote/timeout buffers are
    /// re-sized (not merely filled) so callers may run this before
    /// or after the committee changes.
    ///
    /// Epoch-scoped state cleared:
    /// - `last_voted_view`, `timeout_signed_view`: view bars restart
    ///   at view 0 in the new epoch; a stale record would suppress
    ///   legitimate signatures.
    /// - `high_qc`, `last_tc`: certificates from the old epoch.
    /// - `voted_at_height`: per-height locks — heights continue
    ///   across the boundary via `last_committed`, but stale locks
    ///   must not constrain the new epoch's proposals.
    /// - `votes`, `timeout_signatures`, `vote_count`, `vote_stake`:
    ///   in-flight collections judged under the old epoch.
    /// - `exec_attest_pool`, `exec_certs`, `verified_exec_certs`:
    ///   signatures bind `(height, root, epoch)` and index the
    ///   signing epoch's committee — unverifiable or harmful after
    ///   the boundary.
    /// - `rejected_headers`: a header correctly refused under epoch
    ///   N may be authentic under N+1 (rotated-in leader's first
    ///   proposal), so the memo must not outlive its set.
    /// - `sync_staged`: staged sync records bind the signing
    ///   committee — after a rotation they can never verify or
    ///   commit, so retaining them would only pin memory and stall
    ///   the frontier.
    pub(crate) fn clear_epoch_scoped_state(&mut self) {
        self.last_voted_view = None;
        self.timeout_signed_view = None;
        self.high_qc = None;
        self.voted_at_height.clear();
        self.last_tc = None;
        self.votes = vec![None; self.validator_set.n()];
        self.vote_count = 0;
        self.vote_stake = 0;
        self.timeout_signatures = vec![None; self.validator_set.n()];
        self.exec_attest_pool.clear();
        self.exec_certs.clear();
        self.verified_exec_certs.clear();
        self.rejected_headers.clear();
        // Staged sync records are signed under the outgoing
        // committee — unverifiable (and uncommittable) after the
        // boundary. The committed anchor is untouched: the new
        // epoch's chain still extends it.
        self.sync_staged.clear();
    }

    /// Adopt a QC-certified epoch when this engine's committee is
    /// already the one that produced it.
    ///
    /// A validator can hold the right committee but a stale epoch —
    /// e.g. it joined or restarted with a config naming the current
    /// committee while the chain was already mid-epoch. Votes,
    /// timeouts, and attestations all sign `(…, epoch)`, so such a
    /// node is mute until its epoch catches up. The QC itself is
    /// the certified handoff: a quorum of our validator set signing
    /// `(view, phase, block, E)` proves that committee operated at
    /// epoch E — the same committee we hold, so the bitmap resolved
    /// to the real signers and the aggregate verified under E.
    ///
    /// Callers must only invoke this after the QC has verified under
    /// `epoch` against the *current* validator set — the signature
    /// is the evidence, the adoption is the consequence. A node
    /// holding the WRONG committee (it genuinely missed a rotation)
    /// fails that verification and never reaches here: fail-closed.
    ///
    /// Everything epoch-scoped is dropped, the validator index is
    /// re-seated by key, the pacemaker is rebuilt under the adopted
    /// epoch (carrying configured timeouts), and the boundary is
    /// persisted to the WAL — a restart must recover the adopted
    /// epoch, not the stale one.
    pub(crate) fn adopt_certified_epoch(&mut self, epoch: Epoch) {
        self.epoch = epoch;
        if let Some(ref signer) = self.signer
            && let Some(idx) = self.validator_set.index_of_key(&signer.public_key())
        {
            self.validator_index = idx;
        }
        // Views restart per epoch, the same boundary
        // `complete_rotation` draws: keeping the old epoch's view
        // would leave a node that stopped at view N stranded above
        // every view the new epoch produces, since `deliver_qc`'s
        // catch-up only fires when the QC's view is strictly higher.
        // The QC that triggered this adoption bumps us to
        // `qc.view + 1` on the way out.
        self.current_view = View::new(0);
        self.restart_view_mark();
        self.clear_epoch_scoped_state();
        let _ = self.append_wal_full(true);
        self.pacemaker = crate::pacemaker::Pacemaker::with_config(
            self.validator_set.clone(),
            self.current_view,
            self.epoch,
            self.pacemaker_base_timeout_ms,
            self.pacemaker_max_timeout_ms,
        );
    }

    /// Apply pending validator key changes and schedule an epoch
    /// rotation (staking `KEY_CHANGE` → `schedule_rotation` bridge).
    ///
    /// For each `(address, new_key)` in `changes`, finds the
    /// validator index via `validator_set.index_of(address)`,
    /// replaces the BLS key, and builds an updated `ValidatorSet`
    /// preserving stakes and addresses. The updated set is scheduled
    /// via `schedule_rotation` — the two-phase handoff completes at
    /// the epoch boundary when `complete_rotation` swaps it in.
    ///
    /// Each key arrives as a
    /// [`ValidatedPublicKey`](crypto::bls_signer::ValidatedPublicKey):
    /// the admitting module already proved the bytes decode to a
    /// subgroup element, so the engine does not re-decode here — the
    /// token type is what makes that skip safe.
    ///
    /// Returns the number of key changes applied. Returns `Ok(0)` if
    /// `changes` is empty.
    ///
    /// # Errors
    /// - `KeyChangeError::InvalidSet` — the updated set failed
    ///   construction.
    /// - `KeyChangeError::RotationAlreadyPending` — a rotation is
    ///   already scheduled.
    pub fn apply_key_changes(
        &mut self,
        changes: &[(primitives::Address, crypto::bls_signer::ValidatedPublicKey)],
    ) -> Result<usize, KeyChangeError> {
        self.apply_epoch_changes(changes, &[], &[])
    }

    /// Apply pending validator set changes to the validator set and
    /// schedule the result for the next epoch rotation.
    ///
    /// `changes.adds` is a list of `(staking_address, bls_public_key,
    /// stake)` tuples for new validators — each key a
    /// [`ValidatedPublicKey`](crypto::bls_signer::ValidatedPublicKey)
    /// proven at module admission. `changes.removes` is a list of
    /// staking addresses to remove.
    ///
    /// Removes are applied first (in descending index order to avoid
    /// index shifting), then adds are appended at the end. The
    /// resulting `ValidatorSet` is scheduled via
    /// [`schedule_rotation`](Self::schedule_rotation) — it takes
    /// effect at the next [`complete_rotation`](Self::complete_rotation)
    /// or [`rotate_epoch`](Self::rotate_epoch) call.
    ///
    /// # Errors
    ///
    /// - [`KeyChangeError::InvalidSet`] if the resulting set would be
    ///   invalid (empty, zero stake, etc.).
    /// - [`KeyChangeError::RotationAlreadyPending`] if a rotation is
    ///   already scheduled.
    ///
    /// # Returns
    ///
    /// The number of changes applied (adds + removes).
    pub fn apply_validator_changes(
        &mut self,
        adds: &[(primitives::Address, crypto::bls_signer::ValidatedPublicKey, u64)],
        removes: &[primitives::Address],
    ) -> Result<usize, KeyChangeError> {
        self.apply_epoch_changes(&[], adds, removes)
    }

    /// Build the next-epoch `ValidatorSet` from a combined
    /// transition record — key replacements, member removals, and
    /// member additions — without scheduling anything.
    ///
    /// Fixed application order is the determinism contract: key
    /// replacements run against the *current* set's indices, then
    /// removals descend through those same original indices, then
    /// additions append at the tail. Every replica that folds the
    /// same finalized deltas through this builder derives the same
    /// committee — order, keys, and stakes included.
    ///
    /// Returns the candidate set plus the count of deltas that
    /// actually landed (a key change for an address not in the set
    /// is skipped, not counted).
    fn build_next_set(
        &self,
        key_changes: &[(primitives::Address, crypto::bls_signer::ValidatedPublicKey)],
        adds: &[(primitives::Address, crypto::bls_signer::ValidatedPublicKey, u64)],
        removes: &[primitives::Address],
    ) -> Result<(ValidatorSet, usize), KeyChangeError> {
        let mut keys = self.validator_set.public_keys().to_vec();
        let mut stakes = self.validator_set.stakes().to_vec();
        let mut addresses = self.validator_set.validator_addresses().to_vec();
        let mut applied = 0usize;

        // 1. Key replacements — against the original indices. The
        //    token carries the proof: the admitting module already
        //    ran point + subgroup validation, so no decode can fail
        //    here.
        for (addr, key) in key_changes {
            if let Some(idx) = self.validator_set.index_of(addr) {
                keys[usize::from(idx)] = key.public_key();
                applied += 1;
            }
        }

        // 2. Removals — original indices, descending so positions
        //    don't shift under later removals.
        let mut to_remove: Vec<usize> = Vec::new();
        for addr in removes {
            if let Some(idx) = self.validator_set.index_of(addr) {
                to_remove.push(usize::from(idx));
            }
        }
        to_remove.sort_unstable_by(|a, b| b.cmp(a));
        // A record that names the same member twice must not eat a
        // second validator — after the first removal the index it
        // held now belongs to the next member.
        to_remove.dedup();
        for idx in to_remove {
            keys.remove(idx);
            stakes.remove(idx);
            addresses.remove(idx);
            applied += 1;
        }

        // 3. Additions — appended at the tail. Membership is checked
        //    against the post-removal set: re-offering an add whose
        //    address already sits there is a replay of an enacted
        //    transition (a queue drain that repeated after a
        //    mid-transition restart) and must fold to a no-op, not
        //    fail on the duplicate-key error. A remove+add of the
        //    same address in one record still lands — the removal
        //    dropped it from `remaining`, so the add applies.
        let mut remaining: std::collections::HashSet<primitives::Address> =
            addresses.iter().copied().collect();
        for (addr, key, stake) in adds {
            if !remaining.insert(*addr) {
                continue;
            }
            if *stake == 0 {
                return Err(KeyChangeError::InvalidSet);
            }
            keys.push(key.public_key());
            stakes.push(*stake);
            addresses.push(*addr);
            applied += 1;
        }

        let set = ValidatorSet::with_addresses(keys, stakes, addresses)
            .map_err(|_| KeyChangeError::InvalidSet)?;
        Ok((set, applied))
    }

    /// Apply a combined epoch transition — key changes, additions,
    /// and removals — as ONE candidate set and ONE scheduled
    /// rotation.
    ///
    /// The separate `apply_key_changes`/`apply_validator_changes`
    /// entry points each schedule their own rotation, so a block
    /// that enacted both kinds of delta could not be applied
    /// through them (the second call would hit
    /// `RotationAlreadyPending`). This is the production path: the
    /// executor's [`types::EpochChanges`] record is drained as one
    /// unit and folded through [`build_next_set`](Self::build_next_set)
    /// into a single transition.
    ///
    /// # Errors
    /// Same conditions as `build_next_set` plus
    /// [`KeyChangeError::RotationAlreadyPending`].
    pub fn apply_epoch_changes(
        &mut self,
        key_changes: &[(primitives::Address, crypto::bls_signer::ValidatedPublicKey)],
        adds: &[(primitives::Address, crypto::bls_signer::ValidatedPublicKey, u64)],
        removes: &[primitives::Address],
    ) -> Result<usize, KeyChangeError> {
        if key_changes.is_empty() && adds.is_empty() && removes.is_empty() {
            return Ok(0);
        }
        let (new_set, applied) = self.build_next_set(key_changes, adds, removes)?;
        if applied > 0 {
            self.schedule_rotation(new_set).map_err(|_| KeyChangeError::RotationAlreadyPending)?;
        }
        Ok(applied)
    }

    /// Drive the epoch lifecycle: drain the app's pending
    /// validator-set transition and, if it produces a different
    /// committee, rotate the epoch.
    ///
    /// This is the production bridge the epoch protocol needs:
    /// executed blocks record staking deltas in the module's
    /// pending queues; the engine folds them into a candidate set
    /// and certifies the swap through the two-phase handoff —
    /// `schedule_rotation` (announce) + `rotate_epoch` (the old set
    /// has already committed the change, so completing immediately
    /// activates the new set from the next view). Every node that
    /// executes the same finalized block derives the same
    /// transition — the drain is deterministic because the module
    /// queues are deterministic.
    ///
    /// The dedup check is the restart-mid-transition case: a crash
    /// between a rotation and the queue drain re-pends the same
    /// deltas after recovery (module state persists them), and
    /// re-applying would produce *this same set* — recognized by
    /// equality, so the queues drain without a spurious second
    /// epoch bump that would diverge us from every peer that
    /// stayed up.
    ///
    /// Returns the number of deltas applied, `0` when nothing was
    /// pending or the transition was already enacted.
    ///
    /// # Errors
    /// [`KeyChangeError`] when the drained deltas cannot fold into
    /// a valid set — deterministic on every node, so the rejection
    /// is consistent; the queues are drained first precisely so a
    /// bad record cannot wedge the loop in a retry cycle.
    pub fn drive_epoch_changes(&mut self) -> Result<usize, KeyChangeError> {
        // Phase 1: a scheduled rotation completes once the chain has
        // committed its certified activation height. Checked before
        // the drain so a due rotation completes even when nothing
        // new is queued.
        //
        // While a rotation is pending, later deltas stay queued:
        // draining them mid-window would have to either schedule
        // over the pending transition (rejected — the record is
        // already consumed, so the change would be silently lost)
        // or merge sets built against different bases. Deferring is
        // deterministic on every replica — the pending set drains
        // identically at the activation height everywhere — and
        // lossless: the queued deltas fold into the NEXT transition.
        if self.next_validator_set.is_some() {
            let committed = self.last_committed.map_or(0, |(_, h)| h.value());
            let activation = self.rotation_activation_height.unwrap_or(committed);
            if committed >= activation {
                // `next_validator_set` is Some — `NoPendingRotation`
                // is unreachable here.
                let _ = self.complete_rotation();
            }
            return Ok(0);
        }

        let changes = self.app.take_epoch_changes();
        if changes.is_empty() {
            return Ok(0);
        }
        // Build the candidate BEFORE touching rotation state — an
        // invalid transition is rejected here, deterministically on
        // every replica, and the (already drained) record cannot
        // re-pend.
        let (new_set, applied) =
            self.build_next_set(&changes.key_changes, &changes.adds, &changes.removes)?;
        if applied == 0 || new_set == self.validator_set {
            return Ok(0);
        }
        // Membership activates at a certified future height: the
        // transition is already committed (the block carrying it is
        // the certification), and the delay is the join window —
        // the network layer admits the pending set's members to the
        // peer mesh before they must carry quorum. `saturating_add`
        // because committed-height u64::MAX is unreachable in
        // practice but must not wrap.
        let activation = self
            .last_committed
            .map_or(0, |(_, h)| h.value())
            .saturating_add(crate::engine::ROTATION_ACTIVATION_DELAY);
        self.schedule_rotation_at(new_set, activation)
            .map_err(|_| KeyChangeError::RotationAlreadyPending)?;
        Ok(applied)
    }
}
