//! Persistence boundary for oxideBFT — WAL and state snapshots.
//!
//! Split from `engine.rs` around the durability invariant: the WAL
//! append is the *only* thing standing between a vote and a
//! restart-amnesia double-sign, so every signing-path mutation
//! calls [`OxideBft::append_wal`] first and any failure latches
//! `wal_failed` (the engine must not sign again until restarted on
//! healthy storage). `save_state`/`restore_state` own the snapshot
//! codec — the restart path replays WAL first, then the snapshot,
//! and the two must agree.

use super::{
    ConsensusError, Decode, Encode, Epoch, Hash, Height, OxideBft, QuorumCertificate, View,
};

impl OxideBft {
    /// Recover safety-critical state from the WAL.
    ///
    /// Reads the latest valid `WalEntry` from the WAL and
    /// restores `last_voted_view`, `voted_at_height`, `high_qc`,
    /// `current_view`, `next_height`, and `epoch`. This must be
    /// called before the engine participates in consensus after a
    /// restart.
    ///
    /// # Errors
    ///
    /// Returns [`WalError`] if the WAL cannot be read.
    pub fn recover_from_wal(&mut self) -> Result<(), crate::wal::WalError> {
        let Some(ref wal) = self.wal else {
            return Ok(()); // no WAL — nothing to recover
        };
        if let Some(entry) = wal.recover()? {
            self.last_voted_view = entry.last_voted_view;
            self.voted_at_height = entry.voted_at_height;
            self.high_qc = entry.high_qc;
            self.current_view = entry.current_view;
            self.next_height = entry.next_height;
            self.epoch = entry.epoch;
            self.last_committed = entry.last_committed;
            // Membership is part of the recovered state too: rotation
            // entries carry the committed set, and `Wal::recover`
            // forwards the most recent one. Without this a
            // post-rotation restart would resurrect the genesis
            // committee under a later epoch — wrong leader schedule,
            // wrong quorum, divergent from every peer that stayed up.
            // `None` means the WAL predates set persistence (or no
            // rotation ever committed): the construction set stands.
            if let Some(set) = entry.validator_set
                && set != self.validator_set
            {
                self.validator_set = set;
                // Per-set state is sized/keyed to membership:
                // vote buffers index by `ValidatorIndex`, timeout
                // sigs likewise, and exec-cert artifacts verify
                // against the signing epoch's set. All are
                // view/epoch-scoped — a restart drops in-flight
                // collections regardless — so resize fresh rather
                // than carry stale shape or stale verdicts.
                self.votes = vec![None; self.validator_set.n()];
                self.vote_count = 0;
                self.vote_stake = 0;
                self.timeout_signatures = vec![None; self.validator_set.n()];
                self.exec_attest_pool.clear();
                self.exec_certs.clear();
                self.verified_exec_certs.clear();
                // Re-seat our own index: the committed set may
                // have moved us (removals shift positions, our
                // key may be at a different index than genesis).
                // The BLS key is the identity the operator
                // actually holds — `index_of_key` is the honest
                // remap. `None` means we are no longer in the
                // committee: leave the stale index — our
                // signatures will fail verification against the
                // new set anyway, which is fail-closed.
                if let Some(ref key) = self.secret_key
                    && let Some(idx) = self.validator_set.index_of_key(&key.public_key())
                {
                    self.validator_index = idx;
                }
            }
            // Rebuild the pacemaker with the recovered epoch AND the
            // recovered set — a bare `sync_to_view` used to leave it
            // running the construction-time epoch/membership, so a
            // post-rotation restart stamped and rejected timeout
            // certificates on the wrong epoch. Configured timeouts
            // carry over (same rule rotation applies).
            self.pacemaker = crate::pacemaker::Pacemaker::with_config(
                self.validator_set.clone(),
                self.current_view,
                self.epoch,
                self.pacemaker_base_timeout_ms,
                self.pacemaker_max_timeout_ms,
            );
        }
        Ok(())
    }

    /// Build a `WalEntry` snapshot of the engine's current
    /// safety-critical state. `include_set` attaches the committed
    /// validator set — used only by epoch transitions, so ordinary
    /// per-vote entries stay ~200 bytes.
    #[allow(dead_code)]
    pub(crate) fn wal_entry(&self, include_set: bool) -> crate::wal::WalEntry {
        crate::wal::WalEntry {
            last_voted_view: self.last_voted_view,
            voted_at_height: self.voted_at_height.clone(),
            high_qc: self.high_qc.clone(),
            current_view: self.current_view,
            next_height: self.next_height,
            epoch: self.epoch,
            last_committed: self.last_committed,
            validator_set: include_set.then(|| self.validator_set.clone()),
        }
    }

    /// Append the current state to the WAL (if attached).
    ///
    /// Called after every vote-lock update, QC adoption, commit, and
    /// epoch rotation — always BEFORE any signature that depends on
    /// the new state is emitted.
    ///
    /// C10 fix: a failed append latches [`Self::wal_failed`] and
    /// alerts on stderr. From then on no signature leaves this
    /// engine — a vote, timeout, attestation, or proposal signed
    /// while its anti-equivocation state is undurable can equivocate
    /// after a restart. The latch is permanent for the process:
    /// WAL failures indicate failing storage, and the safe remedy is
    /// an operator restart on healthy media, not silent retry.
    ///
    /// # Errors
    /// Returns [`crate::wal::WalError`] when the append (or its
    /// fsync) fails. With no WAL attached this is a no-op `Ok(())`
    /// — WAL-less engines (tests, sims, conformance runs) keep
    /// their previous best-effort semantics.
    pub(crate) fn append_wal(&mut self) -> Result<(), crate::wal::WalError> {
        self.append_wal_full(false)
    }

    /// [`append_wal`](Self::append_wal) with control over the
    /// validator-set trailer: `include_set` records the committed
    /// set in this entry. Epoch transitions pass `true` so recovery
    /// restores membership and epoch atomically from the same
    /// fsync'd record; ordinary per-vote appends pass `false` — the
    /// set is unchanged and ~n×76 bytes of redundancy per entry
    /// buys nothing.
    pub(crate) fn append_wal_full(
        &mut self,
        include_set: bool,
    ) -> Result<(), crate::wal::WalError> {
        let Some(ref mut wal) = self.wal else {
            return Ok(());
        };
        // Build the entry first to avoid borrowing self while
        // the WAL is mutably borrowed.
        let entry = crate::wal::WalEntry {
            last_voted_view: self.last_voted_view,
            voted_at_height: self.voted_at_height.clone(),
            high_qc: self.high_qc.clone(),
            current_view: self.current_view,
            next_height: self.next_height,
            epoch: self.epoch,
            last_committed: self.last_committed,
            validator_set: include_set.then(|| self.validator_set.clone()),
        };
        match wal.append(&entry) {
            Ok(()) => Ok(()),
            Err(err) => {
                // Latch + alert once: repeated failures of a dead
                // disk would otherwise spam stderr every view.
                if !self.wal_failed {
                    self.wal_failed = true;
                    eprintln!(
                        "oxideBFT: WAL append failed ({err}) — validator signing disabled; \
                         restart on healthy storage"
                    );
                }
                Err(err)
            }
        }
    }

    /// Serialize the engine's safety-critical state to a byte buffer
    /// (C9 fix). The state includes:
    /// - `high_qc` (the highest QC seen).
    /// - `current_view` (the current view).
    /// - `last_voted_view` (the highest view voted in).
    /// - `next_height` (the next proposal height).
    /// - `epoch` (the current epoch).
    ///
    /// This state must be persisted to a journal/WAL before the
    /// engine shuts down. On restart, call [`restore_state`] with
    /// the persisted bytes to restore the engine's safety state.
    ///
    /// The `voted_at_height` map is also included — it's the per-
    /// height vote lock that prevents double-voting.
    ///
    /// # Panics
    ///
    /// Panics if the state cannot be encoded (should never happen
    /// for valid consensus state — all fields are plain integers
    /// or encoded types).
    #[must_use]
    pub fn save_state(&self) -> Vec<u8> {
        // Format:
        // - 8 bytes: current_view
        // - 8 bytes: last_voted_view (0 = None)
        // - 8 bytes: next_height
        // - 8 bytes: epoch
        // - 1 byte: high_qc present (0 = None, 1 = Some)
        // - if high_qc present: encoded QuorumCertificate
        // - 8 bytes: voted_at_height.len()
        // - for each entry: 8 bytes height + 32 bytes hash
        // - 1 byte: last_committed present (0 = None, 1 = Some)
        // - if present: 8 bytes height + 32 bytes hash
        //   (optional trailer — buffers written before the field
        //   existed decode as None; it is safety state: the anchor
        //   a proposal must extend while high_qc is None across an
        //   epoch boundary)

        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.current_view.value().to_le_bytes());
        buf.extend_from_slice(
            &self.last_voted_view.map_or(0u64, primitives::Id::value).to_le_bytes(),
        );
        buf.extend_from_slice(&self.next_height.value().to_le_bytes());
        buf.extend_from_slice(&self.epoch.value().to_le_bytes());

        match &self.high_qc {
            Some(qc) => {
                buf.push(1);
                qc.encode(&mut buf);
            }
            None => buf.push(0),
        }

        let voted_len = u64::try_from(self.voted_at_height.len()).unwrap_or(u64::MAX);
        buf.extend_from_slice(&voted_len.to_le_bytes());
        for (height, hash) in &self.voted_at_height {
            buf.extend_from_slice(&height.to_le_bytes());
            buf.extend_from_slice(hash.as_bytes());
        }

        match self.last_committed {
            Some((hash, height)) => {
                buf.push(1);
                buf.extend_from_slice(&height.value().to_le_bytes());
                buf.extend_from_slice(hash.as_bytes());
            }
            None => buf.push(0),
        }

        buf
    }

    /// Restore the engine's safety-critical state from a byte buffer
    /// (C9 fix). This is the inverse of [`save_state`]. Call this
    /// on restart after constructing a fresh engine, before
    /// processing any proposals or votes.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::InvalidState`] if the buffer is
    /// malformed (wrong length, bad encoding, etc.).
    ///
    /// # Panics
    ///
    /// Panics if a `try_into` slice conversion fails — this is
    /// impossible because the slice lengths are checked before the
    /// conversion.
    pub fn restore_state(&mut self, bytes: &[u8]) -> Result<(), ConsensusError> {
        if bytes.len() < 33 {
            return Err(ConsensusError::InvalidState);
        }

        let mut offset = 0;
        let current_view_val = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let last_voted_val = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let next_height_val = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let epoch_val = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        self.current_view = View::new(current_view_val);
        self.last_voted_view =
            if last_voted_val == 0 { None } else { Some(View::new(last_voted_val)) };
        self.next_height = Height::new(next_height_val);
        self.epoch = Epoch::new(epoch_val);

        let qc_present = bytes[offset];
        offset += 1;

        if qc_present == 1 {
            let mut reader = codec::Reader::new(&bytes[offset..]);
            self.high_qc = Some(
                QuorumCertificate::decode(&mut reader).map_err(|_| ConsensusError::InvalidState)?,
            );
            offset = bytes.len() - reader.remaining();
        }

        if offset + 8 > bytes.len() {
            return Err(ConsensusError::InvalidState);
        }
        let voted_len = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        self.voted_at_height.clear();
        for _ in 0..voted_len {
            if offset + 40 > bytes.len() {
                return Err(ConsensusError::InvalidState);
            }
            let height = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let hash_bytes: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
            offset += 32;
            self.voted_at_height.insert(
                height,
                Hash::from_slice(&hash_bytes).map_err(|_| ConsensusError::InvalidState)?,
            );
        }

        // Optional trailer: `last_committed` (1-byte flag + 8-byte
        // height + 32-byte hash). Buffers written before the field
        // existed end here — decode as `None`.
        self.last_committed = None;
        if offset < bytes.len() {
            let flag = bytes[offset];
            offset += 1;
            if flag == 1 {
                if offset + 40 > bytes.len() {
                    return Err(ConsensusError::InvalidState);
                }
                let height = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                offset += 8;
                let hash_bytes: [u8; 32] = bytes[offset..offset + 32].try_into().unwrap();
                self.last_committed = Some((
                    Hash::from_slice(&hash_bytes).map_err(|_| ConsensusError::InvalidState)?,
                    Height::new(height),
                ));
            }
        }

        Ok(())
    }

    /// Sync this engine's `next_height` to `max_height`. In a real
    /// system, all validators see the same blocks via broadcast, so
    /// their `next_height` stays in lockstep. In the in-process
    /// simulation, each engine has its own counter, so we sync them
    /// to the max after each round.
    pub fn sync_next_height(&mut self, max_height: u64) {
        if self.next_height.value() < max_height {
            self.next_height = Height::new(max_height);
        }
    }

    /// Observe a block height from a received proposal or QC.
    ///
    /// When a follower receives a proposal from the network, it
    /// learns the height the leader assigned to that block. The
    /// follower's `next_height` must advance to `height + 1` so that
    /// if it later becomes the leader (after a view change), it
    /// proposes at the correct height instead of re-proposing an
    /// already-finalized height.
    ///
    /// Without this, a follower that never proposes (because it's
    /// never the leader) keeps `next_height = 0`. When a view change
    /// makes it the leader, it proposes a block at height 0 —
    /// conflicting with the already-finalized block at height 0 and
    /// corrupting the chain state (the app re-executes height 0 with
    /// different transactions, overwriting finalized state).
    ///
    /// This method is idempotent: calling it with a height below the
    /// current `next_height` is a no-op.
    pub fn observe_block_height(&mut self, height: Height) {
        if height.value() >= self.next_height.value() {
            // Saturating, not wrapping: a byzantine proposal with
            // height = u64::MAX must not wrap next_height to 0 (which
            // would make the validator re-propose height 0, conflicting
            // with the finalized genesis block). The vote() path
            // additionally rejects absurd heights before this is
            // called, but saturating here is defense in depth.
            self.next_height = height.saturating_next();
        }
    }
}
