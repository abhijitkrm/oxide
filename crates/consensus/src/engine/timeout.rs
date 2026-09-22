//! Timeout and view-change path for oxideBFT.
//!
//! Split from `engine.rs` around the liveness invariant: when the
//! pacemaker fires, [`OxideBft::on_timeout`] signs a timeout vote;
//! [`OxideBft::collect_timeout_signature`] aggregates 2f+1 of them
//! into a [`TimeoutCertificate`]; and
//! [`OxideBft::on_timeout_certificate`] advances the view. A TC is
//! the *only* evidence that releases a validator locked on a
//! proposal — [`OxideBft::proposal_tc_releases_lock`] enforces that
//! the TC must be for a strictly later view than the lock.

use super::{
    BlockHeader, ConsensusError, Epoch, OxideBft, QuorumCertificate, Signature, TimeoutCertificate,
    ValidatorIndex, View,
};

impl OxideBft {
    /// The certificate evidence that justifies our presence at
    /// `current_view` — the `DiemBFT` v4 timeout-message fields a
    /// receiver needs before honoring a claimed view.
    ///
    /// Entering view *v* is legitimate only via QC(*v−1*) (the
    /// preceding round certified a block) or TC(*v−1*) (quorum
    /// timed out there). The sender therefore attaches its
    /// `high_qc`, plus `last_tc` when the high QC is not from the
    /// immediately preceding view — the same disjunction `DiemBFT`'s
    /// `TimeoutMsg` carries (`high_qc` + `last_round_tc` when
    /// `high_qc.view ≠ view − 1`).
    ///
    /// The evidence is self-authenticating (each certificate
    /// carries its own aggregate signature), so it is not bound
    /// into the timeout signature — a relay swapping it for another
    /// real certificate can only attach evidence that itself
    /// verifies, which justifies the same view regardless of
    /// carrier.
    pub fn timeout_evidence(&self) -> (Option<QuorumCertificate>, Option<TimeoutCertificate>) {
        let needs_tc = match &self.high_qc {
            Some(qc) => qc.view.saturating_next() != self.current_view,
            None => true,
        };
        (self.high_qc.clone(), if needs_tc { self.last_tc.clone() } else { None })
    }

    /// Process the certificate evidence attached to a remote
    /// timeout signature. Each piece feeds the verified ingestion
    /// path (`deliver_qc`, `on_timeout_certificate`) — a real
    /// certificate is useful even when it doesn't justify the
    /// sender's claimed view, and a forged one is rejected there.
    ///
    /// The bounded-catch-up rule lives in the *caller*: after this
    /// returns, a remote signature is only collectible when its
    /// claimed `view == self.current_view` — either the evidence
    /// moved us there, or we were already there. A bare signature
    /// for a far-future view moves nothing, so a single peer can no
    /// longer pull us to an arbitrary view (previously
    /// `sync_to_view(sig_view)` trusted the claimed view outright).
    ///
    /// Cross-epoch evidence is dropped: certificates are verified
    /// against the *current* validator set, so a foreign-epoch cert
    /// would fail verification anyway — the explicit check makes
    /// the intent loud rather than emergent.
    pub fn deliver_timeout_evidence(
        &mut self,
        high_qc: Option<QuorumCertificate>,
        last_tc: Option<TimeoutCertificate>,
    ) {
        if let Some(qc) = high_qc
            && qc.epoch == self.epoch
        {
            let _ = self.deliver_qc(qc);
        }
        if let Some(tc) = last_tc
            && tc.epoch == self.epoch
        {
            let _ = self.on_timeout_certificate(&tc);
        }
    }

    /// Returns the pacemaker's current timeout duration in
    /// milliseconds. The devnet consensus loop uses this to decide
    /// when to fire `on_timeout()` and initiate a view change when
    /// the leader doesn't propose.
    pub fn pacemaker_timeout_ms(&self) -> u64 {
        self.pacemaker.timeout_duration_ms()
    }

    /// Validator: local timer expired. Returns a timeout signature
    /// for the pacemaker. In single-validator mode, this is a no-op
    /// (no one to timeout). In multi-validator mode, the simulation
    /// collects these and forms a TC.
    ///
    /// The signed message binds `(view, epoch)` to prevent replay
    /// across epochs (M1 fix). The domain is `Timeout`.
    pub fn on_timeout(&mut self) -> Option<Signature> {
        // C10: refuse to sign while the WAL latch is set. Timeout
        // signatures are deterministic per (view, epoch) — a re-sign
        // can never equivocate — but a validator that cannot trust
        // its durability layer must not participate at all.
        if self.wal_failed {
            return None;
        }
        let _ = self.pacemaker.on_local_timeout();
        match &self.secret_key {
            Some(sk) => {
                // M1 fix: bind epoch into the timeout message so a
                // timeout signature from epoch 0 cannot be replayed
                // in epoch 1 (views reset to 0 on epoch rotation).
                let mut msg = Vec::with_capacity(16);
                msg.extend_from_slice(&self.current_view.value().to_le_bytes());
                msg.extend_from_slice(&self.epoch.value().to_le_bytes());
                Some(sk.sign(crypto::hash::Domain::Timeout, &msg))
            }
            None => Some(Signature::ZERO),
        }
    }

    /// Verify a peer's timeout signature for an explicit `(view, epoch)`
    /// **without mutating any state**.
    ///
    /// The node's message pump needs to authenticate timeout evidence
    /// *before* acting on it. `collect_timeout_signature` verifies
    /// against the engine's *current* view, so the pump previously had
    /// to call `sync_to_view(sig_view)` first — which meant an
    /// unauthenticated peer could move the view, reset the pacemaker
    /// timer, and clear the vote buffer simply by claiming a high view
    /// and attaching garbage. A forged timeout must change nothing.
    ///
    /// This entry point breaks that ordering: authenticate here, then
    /// (only if it verifies) let the caller sync and collect. The
    /// signature binds `(view, epoch)` under [`Domain::Timeout`], so a
    /// signature is only ever valid for the view it was cast for.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::SignerOutOfBounds`] if `voter` is past the end
    /// of the set, or [`ConsensusError::InvalidVoteSignature`] if the
    /// signature does not verify for this `(view, epoch)`.
    pub fn verify_timeout_signature_for(
        &self,
        voter: ValidatorIndex,
        view: View,
        epoch: Epoch,
        signature: &Signature,
    ) -> Result<(), ConsensusError> {
        crate::verify::verify_timeout_signature_for(
            &self.validator_set,
            self.verify_signatures,
            voter,
            view,
            epoch,
            signature,
        )
    }

    /// Validator: collect a timeout signature from `voter` for the
    /// current view. If this brings the pacemaker to a quorum, a TC
    /// is formed and the view advances internally. Returns the TC
    /// if one was formed.
    ///
    /// This is the multi-node simulation's view-change path: when
    /// the leader is faulty, followers collect timeout signatures
    /// from each other; the first to reach quorum forms a TC and
    /// broadcasts it.
    ///
    /// # Signature verification (TC safety fix)
    ///
    /// When `verify_signatures` is `true` (production), the timeout
    /// signature is verified against the voter's public key from the
    /// validator set. A forged timeout signature is rejected with
    /// [`ConsensusError::InvalidVoteSignature`]. The signed message
    /// is the view's little-endian bytes, signed with
    /// `Domain::Timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::InvalidVoteSignature`] if the
    /// signature does not verify, or [`ConsensusError::SignerOutOfBounds`]
    /// if the voter index is out of bounds.
    pub fn collect_timeout_signature(
        &mut self,
        voter: ValidatorIndex,
        signature: Signature,
    ) -> Result<Option<TimeoutCertificate>, ConsensusError> {
        // Verify the timeout signature before collecting (TC safety).
        // M1 fix: verify against (view, epoch), not just view.
        if self.verify_signatures {
            let pk = self
                .validator_set
                .validator(voter)
                .map_err(|_| ConsensusError::SignerOutOfBounds)?;
            let mut msg = Vec::with_capacity(16);
            msg.extend_from_slice(&self.current_view.value().to_le_bytes());
            msg.extend_from_slice(&self.epoch.value().to_le_bytes());
            crypto::bls_signer::verify(&signature, crypto::hash::Domain::Timeout, &msg, pk)
                .map_err(|_| ConsensusError::InvalidVoteSignature { voter })?;
        }
        // Store the verified signature so the pacemaker can aggregate
        // it when forming the TC.
        self.timeout_signatures[usize::from(voter)] = Some(signature);
        let events = self.pacemaker.on_timeout_signature(voter, signature);
        let mut tc = events.iter().find_map(|e| {
            if let crate::pacemaker::PacemakerEvent::TimeoutCertificateFormed(tc) = e {
                Some(tc.clone())
            } else {
                None
            }
        });
        // If a TC was formed, aggregate the collected signatures and
        // replace the placeholder aggregate in the TC.
        if let Some(ref mut tc) = tc {
            if self.secret_key.is_some() {
                let sigs: Vec<Signature> =
                    self.timeout_signatures.iter().filter_map(|s| *s).collect();
                if !sigs.is_empty()
                    && let Ok(agg) = crypto::aggregate(&sigs)
                {
                    tc.aggregate_signature = agg;
                }
            }
            // Clear per-view state for the new view. The TC
            // formation advances the view; stale votes from the
            // old view must not pollute the new view.
            self.clear_per_view_state();
            self.current_view = self.pacemaker.current_view();
            // Record the TC that brought us into this view — the
            // next proposal we make must embed it (spec §view-
            // changes: legitimate-successor evidence).
            self.last_tc = Some(tc.clone());
        }
        Ok(tc)
    }

    /// Validator: process a timeout certificate. Advances the view
    /// if the TC is for the current view. The new leader must extend
    /// the highest QC (tail-fork resistance).
    ///
    /// # Signature verification (TC safety fix)
    ///
    /// When `verify_signatures` is `true` (production), the TC's
    /// aggregate signature is verified against the signer bitmap +
    /// validator set public keys. A forged TC is rejected with
    /// [`ConsensusError::InvalidTcSignature`].
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::InvalidTcSignature`] if the TC's
    /// aggregate signature does not verify, or
    /// [`ConsensusError::SignerOutOfBounds`] if the bitmap references
    /// an out-of-bounds validator.
    pub fn on_timeout_certificate(
        &mut self,
        tc: &TimeoutCertificate,
    ) -> Result<(), ConsensusError> {
        // Hardening: enforce quorum threshold regardless of whether
        // signature verification is enabled. A TC backed by less
        // than quorum voting power is not a valid view-change
        // certificate.
        let voting_power = self.validator_set.signer_stake(&tc.signer_bitmap);
        let required = self.validator_set.quorum_stake();
        if voting_power < required {
            return Err(ConsensusError::InsufficientQuorum { voting_power, required });
        }

        // Verify the TC's aggregate signature (TC safety).
        if self.verify_signatures {
            self.verify_tc_signature(tc)?;
        }
        if let Some(crate::pacemaker::PacemakerEvent::AdvanceView { new_view, .. }) =
            self.pacemaker.on_timeout_certificate(tc)
        {
            self.current_view = new_view;
            // Clear stale per-view state. Votes collected for the
            // old view must not pollute the new view's quorum
            // accounting (they would cause ConflictingVote errors
            // when the new view's real votes arrive). Timeout
            // signatures collected for the old view must not leak
            // into the new view's TC aggregation (they would
            // produce an aggregate that fails verification because
            // the signatures were for a different view).
            self.clear_per_view_state();
            // Record the TC that brought us into this view so the
            // next proposal embeds it as successor evidence.
            self.last_tc = Some(tc.clone());
        }
        Ok(())
    }

    /// Whether the proposal's embedded timeout certificate releases
    /// our per-height vote lock for this view.
    ///
    /// The TC must be the exact certificate that justified the
    /// leader's entry into `header.view` — `tc.view + 1 ==
    /// header.view` (the legitimate-successor shape, spec
    /// §view-changes). Because `header.view > last_voted_view` is
    /// already enforced, `tc.view` is always >= the view in which
    /// the conflicting earlier vote was cast, so this check alone
    /// proves the locked vote's view timed out.
    ///
    /// The TC is fully validated here (epoch, quorum, aggregate
    /// signature) — a forged TC must not release the lock.
    pub(crate) fn proposal_tc_releases_lock(&self, header: &BlockHeader) -> bool {
        let Some(tc) = &header.timeout_cert else {
            return false;
        };
        if tc.epoch != self.epoch || tc.view.saturating_next() != header.view {
            return false;
        }
        if !self.bitmap_meets_quorum(&tc.signer_bitmap) {
            return false;
        }
        !self.verify_signatures || self.verify_tc_signature(tc).is_ok()
    }

    /// Verify a TC's aggregate signature against the signer bitmap
    /// and the validator set's public keys. The signed message is
    /// the TC's view as little-endian bytes, signed with
    /// `Domain::Timeout`.
    ///
    /// The quorum threshold check is performed by the caller
    /// ([`on_timeout_certificate`](Self::on_timeout_certificate)) via
    /// [`ValidatorSet::signer_stake`], so it is enforced regardless
    /// of whether signature verification is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::SignerOutOfBounds`] if the bitmap
    /// references an out-of-bounds validator,
    /// [`ConsensusError::InsufficientQuorum`] if the signers' voting
    /// power is below quorum, or [`ConsensusError::InvalidTcSignature`]
    /// if the aggregate does not verify.
    fn verify_tc_signature(&self, tc: &TimeoutCertificate) -> Result<(), ConsensusError> {
        crate::verify::verify_tc_signature(&self.validator_set, tc)
    }
}
