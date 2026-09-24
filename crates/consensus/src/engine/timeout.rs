//! Timeout and view-change path for oxideBFT.
//!
//! Split from `engine.rs` around the liveness invariant: when the
//! pacemaker fires, [`OxideBft::on_timeout`] signs a timeout claim;
//! [`OxideBft::collect_timeout_signature`] gathers 2f+1 of them into
//! a [`TimeoutCertificate`]; and
//! [`OxideBft::on_timeout_certificate`] advances the view.
//!
//! # The Jolteon evidence rule
//!
//! A timeout signature binds `(view, epoch, qc_high)` — the signer's
//! highest *adopted* QC at signing time — and a TC carries each
//! signer's evidence verbatim ([`types::TimeoutSigner`]). This is
//! the mechanism arXiv:2106.10362 §3 calls the "view-change
//! protocol": because every later quorum TC intersects the honest
//! validators locked on a committed chain, the TC provably contains
//! a `qc_high` at least as recent as the committed block's QC, and
//! the vote predicate ([`OxideBft::vote_if_eligible`]) forces the
//! next proposal to extend it. The two invariants the proof needs:
//!
//! - **Evidence is signature-bound.** Each entry's signature covers
//!   its own claim, so an aggregator cannot drop or weaken the max
//!   `qc_high` without losing that signer — and losing a signer can
//!   only shrink the TC below quorum, never launder it.
//! - **Timeout-signed views cannot also be voted.** If a validator
//!   could sign `timeout(v)` and then vote in `v`, its TC evidence
//!   would underreport the lock its vote created. The asymmetric
//!   rule ([`OxideBft::on_timeout`] records `timeout_signed_view`;
//!   the vote path refuses a view we timed out on) keeps every TC
//!   entry honest *at the moment it was signed* — a vote cast after
//!   the timeout is exactly the lock the evidence must report, so
//!   the bar must apply in only this direction.
//!
//! A TC is also the *only* evidence that releases a validator locked
//! on a proposal — [`OxideBft::valid_entry_tc`] enforces that the TC
//! must be the verified successor certificate for the proposal's
//! view.

use super::{
    BlockHeader, ConsensusError, Epoch, OxideBft, QuorumCertificate, Signature, TimeoutCertificate,
    ValidatorIndex, View,
};
use crate::verify::{VerifiedQc, VerifiedTc};

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
    /// The `high_qc` leg is *also* the Jolteon `qc_high` evidence:
    /// the timeout signature binds it (see [`OxideBft::on_timeout`]),
    /// so what a sender attests here is exactly what its TC entry
    /// will claim. `last_tc` is unbound — it is view-sync evidence,
    /// verified independently at ingestion.
    pub fn timeout_evidence(&self) -> (Option<QuorumCertificate>, Option<TimeoutCertificate>) {
        let needs_tc = match &self.high_qc {
            Some(qc) => qc.view().saturating_next() != self.current_view,
            None => true,
        };
        (
            self.high_qc.as_ref().map(|v| v.qc().clone()),
            if needs_tc { self.last_tc.as_ref().map(|v| v.tc().clone()) } else { None },
        )
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
    /// The signed message binds `(view, epoch, qc_high)` — see
    /// [`crate::verify::timeout_signing_message`]. Signing records
    /// `timeout_signed_view` (WAL-persisted before the signature is
    /// emitted): a validator that timed out on view *v* must not
    /// vote in *v*, or its TC entry would underreport the lock the
    /// vote created — the evidence a TC carries must be what the
    /// signer held when it signed, never less.
    ///
    /// Vote-then-timeout stays legal (and required): a validator
    /// that voted in *v* and still hasn't seen a QC must be able to
    /// time out, and its signature then reports exactly the lock
    /// its vote produced.
    pub fn on_timeout(&mut self) -> Option<Signature> {
        // C10: refuse to sign while the WAL latch is set. A timeout
        // signature pins our evidence claim; a validator that cannot
        // trust its durability layer must not participate at all.
        // The divergence latch gates identically: a validator whose
        // executed state is proven wrong must not attest evidence
        // for a chain it no longer shares.
        if self.wal_failed || self.divergence.is_some() {
            return None;
        }
        let _ = self.pacemaker.on_local_timeout();
        // Latch the mark as timed-out: a view that completes *after*
        // timing out measures dead-leader-plus-timeout, not a
        // round-trip — `observe_completed_view` skips it. A `None`
        // mark (timeout before any transition) latched the same way
        // keeps the first measured view honest too.
        self.view_round_mark = Some(crate::engine::ViewMark::TimedOut);
        // Persist the signed view BEFORE the signature leaves the
        // engine — a restart that forgot it could emit both the
        // timeout and a vote for the same view, which is exactly the
        // equivocation the Jolteon evidence rule forbids.
        self.timeout_signed_view = Some(self.current_view);
        if self.append_wal().is_err() {
            return None;
        }
        match &self.secret_key {
            Some(sk) => {
                let msg = crate::verify::timeout_signing_message(
                    self.current_view,
                    self.epoch,
                    self.high_qc.as_ref().map(VerifiedQc::qc),
                );
                Some(sk.sign(crypto::hash::Domain::Timeout, &msg))
            }
            None => Some(Signature::ZERO),
        }
    }

    /// Verify a peer's timeout signature for an explicit `(view,
    /// epoch, high_qc)` **without mutating any state**.
    ///
    /// The node's message pump needs to authenticate timeout
    /// evidence *before* acting on it. `collect_timeout_signature`
    /// verifies against the engine's *current* view, so the pump
    /// previously had to call `sync_to_view(sig_view)` first — which
    /// meant an unauthenticated peer could move the view, reset the
    /// pacemaker timer, and clear the vote buffer simply by claiming
    /// a high view and attaching garbage. A forged timeout must
    /// change nothing.
    ///
    /// This entry point breaks that ordering: authenticate here,
    /// then (only if it verifies) let the caller sync and collect.
    /// The signature binds `(view, epoch)` plus the claimed
    /// `qc_high` under [`Domain::Timeout`] — `high_qc` must be the
    /// exact certificate the sender attached, so a relay cannot
    /// swap in a different (even valid) QC without breaking the
    /// signature.
    ///
    /// # Errors
    ///
    /// [`ConsensusError::SignerOutOfBounds`] if `voter` is past the
    /// end of the set, or [`ConsensusError::InvalidVoteSignature`]
    /// if the signature does not verify for this
    /// `(view, epoch, high_qc)`.
    pub fn verify_timeout_signature_for(
        &self,
        voter: ValidatorIndex,
        view: View,
        epoch: Epoch,
        high_qc: Option<&QuorumCertificate>,
        signature: &Signature,
    ) -> Result<(), ConsensusError> {
        crate::verify::verify_timeout_signature_for(
            &self.validator_set,
            self.verify_signatures,
            voter,
            view,
            epoch,
            high_qc,
            signature,
        )
    }

    /// Validator: collect a timeout signature from `voter` for the
    /// current view. `qc_high` is the evidence the signature binds —
    /// it is stored into the TC's per-signer record verbatim, so a
    /// TC built from these signatures provably reports what every
    /// signer actually held.
    ///
    /// If this brings the pacemaker to a quorum, a TC is formed and
    /// the view advances internally. Returns the TC if one was
    /// formed.
    ///
    /// This is the multi-node simulation's view-change path: when
    /// the leader is faulty, followers collect timeout signatures
    /// from each other; the first to reach quorum forms a TC and
    /// broadcasts it.
    ///
    /// # Signature verification (TC safety fix)
    ///
    /// When `verify_signatures` is `true` (production), the timeout
    /// signature is verified against the voter's public key over
    /// `(view, epoch, qc_high)` — the claimed evidence is part of
    /// the signed message, so a forged or evidence-swapped timeout
    /// is rejected with [`ConsensusError::InvalidVoteSignature`].
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::InvalidVoteSignature`] if the
    /// signature does not verify, or
    /// [`ConsensusError::SignerOutOfBounds`] if the voter index is
    /// out of bounds.
    pub fn collect_timeout_signature(
        &mut self,
        voter: ValidatorIndex,
        signature: Signature,
        qc_high: Option<QuorumCertificate>,
    ) -> Result<Option<TimeoutCertificate>, ConsensusError> {
        // Verify the timeout signature over its evidence claim
        // before collecting (TC safety): the bound `qc_high` is what
        // makes the TC's per-signer records unfalsifiable.
        if self.verify_signatures {
            let pk = self
                .validator_set
                .validator(voter)
                .map_err(|_| ConsensusError::SignerOutOfBounds)?;
            let msg = crate::verify::timeout_signing_message(
                self.current_view,
                self.epoch,
                qc_high.as_ref(),
            );
            crypto::bls_signer::verify(&signature, crypto::hash::Domain::Timeout, &msg, pk)
                .map_err(|_| ConsensusError::InvalidVoteSignature { voter })?;
            // Screen the claimed QC itself: the signature binds the
            // claim, but a byzantine signer can legitimately sign a
            // claim carrying a *forged* QC — the entry would then
            // fail TC verification and poison every TC it lands in
            // (a one-message liveness DoS on the view change). A
            // valid signature over garbage evidence must die here.
            // Same checks as `verify_tc_signature`'s structural pass:
            // same epoch, view at-or-below the timed-out view — a
            // signer can legitimately hold a QC formed *in* the view
            // it times out on (it adopted the QC, then timed out
            // still at that view), but evidence from a *later* view
            // is unreachable: adopting it would have advanced the
            // signer past the view it claims to be timing out on.
            if let Some(qc) = &qc_high {
                if qc.epoch != self.epoch || qc.view > self.current_view {
                    return Err(ConsensusError::InvalidVoteSignature { voter });
                }
                crate::verify::verify_qc_signature(&self.validator_set, self.epoch, qc)
                    .map_err(|_| ConsensusError::InvalidVoteSignature { voter })?;
            }
        }
        // Store the verified record so the TC carries the signer's
        // evidence verbatim when it forms.
        let idx = usize::from(voter);
        if idx >= self.timeout_signatures.len() {
            return Err(ConsensusError::SignerOutOfBounds);
        }
        self.timeout_signatures[idx] =
            Some(types::TimeoutSigner { voter, high_qc: qc_high, signature });
        let events = self.pacemaker.on_timeout_signature(voter, signature);
        let mut tc = events.iter().find_map(|e| {
            if let crate::pacemaker::PacemakerEvent::TimeoutCertificateFormed(tc) = e {
                Some(tc.clone())
            } else {
                None
            }
        });
        // If a TC was formed, fill its per-signer records from the
        // verified collection — the pacemaker's placeholder TC only
        // carries the view/epoch; the evidence lives here, where the
        // signatures were authenticated.
        if let Some(ref mut tc) = tc {
            tc.signers = self.timeout_signatures.iter().filter_map(Option::clone).collect();
            // Clear per-view state for the new view. The TC
            // formation advances the view; stale votes from the
            // old view must not pollute the new view.
            self.clear_per_view_state();
            // A timeout-driven advance is not a round-trip sample —
            // restart the view-start mark without observing.
            self.restart_view_mark();
            self.current_view = self.pacemaker.current_view();
            // Record the TC that brought us into this view — the
            // next proposal we make must embed it (spec §view-
            // changes: legitimate-successor evidence). `last_tc`
            // holds `VerifiedTc`, so mint through the same
            // verification inbound TCs get: the records were
            // screened at collection, and this re-asserts quorum +
            // structure over the assembled certificate rather than
            // trusting the pacemaker's formation condition.
            if let Ok(verified) = self.verify_tc_signature(tc) {
                self.last_tc = Some(verified);
                // Adopt the TC's max `qc_high` evidence so a
                // proposal we make (or evaluate) in the new view
                // extends the highest locked chain — the Jolteon
                // entry rule.
                self.adopt_tc_evidence(tc);
            } else {
                // A TC assembled from records that each screened
                // clean at collection should always re-verify —
                // failure means pacemaker state and the verified
                // buffer disagree, which is a bug. Fail closed:
                // the view still advances (liveness is the
                // pacemaker's job) but we store no successor
                // evidence and adopt nothing from it.
                self.last_tc = None;
                debug_assert!(false, "self-collected TC failed re-verification");
            }
        }
        Ok(tc)
    }

    /// Validator: process a timeout certificate. Advances the view
    /// if the TC is for the current view. The new leader must extend
    /// the highest QC (tail-fork resistance).
    ///
    /// # Signature verification (TC safety fix)
    ///
    /// The TC's per-signer records are always structurally checked
    /// (distinct in-bounds voters, quorum stake, evidence sanity);
    /// with `verify_signatures` on, every entry's signature is
    /// verified over its own `(view, epoch, qc_high)` claim and each
    /// carried QC is verified — a forged TC or a TC whose evidence
    /// was tampered with is rejected with
    /// [`ConsensusError::InvalidTcSignature`].
    ///
    /// On acceptance, the max `qc_high` evidence is adopted via the
    /// ordinary QC path: the TC is proof that a quorum held those
    /// locks, so our `high_qc` must reflect them before we evaluate
    /// (or build) the next proposal.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::InvalidTcSignature`] if a record is
    /// malformed or unverifiable,
    /// [`ConsensusError::SignerOutOfBounds`] if a record references
    /// an out-of-bounds validator, or
    /// [`ConsensusError::InsufficientQuorum`] if the signers' voting
    /// power is below the quorum threshold.
    pub fn on_timeout_certificate(
        &mut self,
        tc: &TimeoutCertificate,
    ) -> Result<(), ConsensusError> {
        // Structural + quorum + per-signer verification in one
        // pass — see `crate::verify::verify_tc_signature` for the
        // exact checks. Enforced unconditionally: a TC is only a
        // certificate at quorum with well-formed records. The token
        // is what `last_tc` stores — a view we entered via TC only
        // ever re-embeds a certificate that passed verification.
        let verified = self.verify_tc_signature(tc)?;
        if let Some(crate::pacemaker::PacemakerEvent::AdvanceView { new_view, .. }) =
            self.pacemaker.on_timeout_certificate(verified.tc())
        {
            self.current_view = new_view;
            // TC-driven advance — restart the mark, no observation.
            self.restart_view_mark();
            // Clear stale per-view state. Votes collected for the
            // old view must not pollute the new view's quorum
            // accounting (they would cause ConflictingVote errors
            // when the new view's real votes arrive). Timeout
            // signatures collected for the old view must not leak
            // into the new view's TC records.
            self.clear_per_view_state();
            // Record the TC that brought us into this view so the
            // next proposal embeds it as successor evidence.
            self.last_tc = Some(verified);
            // Adopt the TC's max evidence before it can constrain
            // (or be ignored by) the next vote — see
            // [`adopt_tc_evidence`](Self::adopt_tc_evidence).
            self.adopt_tc_evidence(tc);
        }
        Ok(())
    }

    /// Adopt the highest `qc_high` carried in a verified TC.
    ///
    /// This is the receiver half of the Jolteon entry rule: the
    /// TC proves a quorum reported these locks, so the max evidence
    /// is the chain the next proposal must extend. Adoption goes
    /// through `deliver_qc` — the QC is already verified inside the
    /// TC, and the ordinary path handles monotonicity, WAL, and the
    /// commit walk if the evidence completes a certified chain.
    fn adopt_tc_evidence(&mut self, tc: &TimeoutCertificate) {
        let Some(max_qc) =
            tc.signers.iter().filter_map(|s| s.high_qc.as_ref()).max_by_key(|qc| qc.view.value())
        else {
            return;
        };
        // `StaleQc` (evidence at or below our own high QC) and any
        // verification re-check failure are both safe to ignore:
        // the TC is still a valid view-change certificate, and the
        // vote predicate re-derives the floor from the TC itself.
        let _ = self.deliver_qc(max_qc.clone());
    }

    /// The header's timeout certificate iff it is the legitimate
    /// successor evidence for this view: same epoch, `tc.view + 1
    /// == header.view`, and fully verified. `None` for absent,
    /// mismatched, or unverifiable TCs — a TC that isn't the
    /// legitimate entry proof has no protocol effect.
    pub(crate) fn valid_entry_tc(&self, header: &BlockHeader) -> Option<VerifiedTc> {
        let tc = header.timeout_cert.as_ref()?;
        if tc.epoch != self.epoch || tc.view.saturating_next() != header.view {
            return None;
        }
        self.verify_tc_signature(tc).ok()
    }

    /// Verify a TC's per-signer evidence records: distinct in-bounds
    /// voters, quorum stake, each signature over its own
    /// `(view, epoch, qc_high)` claim, each carried QC verified.
    /// Structural checks apply even in conformance mode — see
    /// [`crate::verify::verify_tc_signature`].
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::SignerOutOfBounds`] if an entry
    /// references an out-of-bounds or duplicate validator,
    /// [`ConsensusError::InsufficientQuorum`] if the signers' voting
    /// power is below quorum, or [`ConsensusError::InvalidTcSignature`]
    /// if a signature or record does not verify.
    fn verify_tc_signature(&self, tc: &TimeoutCertificate) -> Result<VerifiedTc, ConsensusError> {
        crate::verify::verify_tc_signature(&self.validator_set, self.verify_signatures, tc)
    }
}
