//! Vote path for oxideBFT — authentication, eligibility, signing,
//! and QC formation.
//!
//! Split from `engine.rs` around the vote invariant: a vote is
//! only ever cast for a proposal that authenticated
//! ([`OxideBft::authenticate_proposal`] — leader signature,
//! view-consistent justify, `prev == justify`), and only while the
//! engine is unlocked on a conflicting chain
//! ([`OxideBft::vote_if_eligible`]). On the collection side,
//! [`OxideBft::collect_vote`] buffers per-view votes and
//! [`OxideBft::try_form_qc`] aggregates them once quorum power is
//! reached — the bitmap it emits is exactly the set whose stake
//! cleared quorum, which `deliver_qc` re-checks.

use super::{
    AggregateSignature, AttestVerifyTask, BlockBody, BlockHeader, ConsensusError, Encode,
    ExecCertificate, Hash, Height, MAX_PENDING_EVIDENCE, OxideBft, Proposal, QuorumCertificate,
    Signature, StateAttestation, ValidatorIndex, Verdict, View, Vote, VotePhase, proposer_hash,
};
use crate::verify::VerifiedTc;
use types::ExecDivergence;

/// Ceiling on how long the vote path may wait for the execution
/// lane to produce a certified height's local root.
///
/// Unit: wall-clock duration. Origin: `vote_if_eligible` compares a
/// proposal's exec cert against `attest_state(cert.height)`; with
/// the async lane an unbounded wait stalls the consensus thread
/// behind execution lag — the exact coupling this bound breaks.
/// 250 ms is ~1/8 of the default 2 s pacemaker base timeout: long
/// enough that a nearly-caught-up lane (single-digit-ms executes)
/// almost always answers, short enough that a saturated lane costs
/// the view a bounded slice instead of an unbounded stall. On
/// expiry the vote is withheld — recoverable on re-delivery, never
/// a safety risk (withholding is always safe).
pub(crate) const EXEC_ATTEST_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

impl OxideBft {
    /// Validator: vote on a proposal. Returns the vote, or `None` if
    /// the validator already voted in this view (safety: no double-
    /// voting) or the proposal is invalid.
    ///
    /// The validator stores the block for later commit lookup. If a
    /// BLS secret key is set (stage 5), the vote is signed with real
    /// BLS; otherwise `Signature::ZERO` is used (conformance mode).
    pub fn vote(&mut self, header: &BlockHeader, proposal: &Proposal) -> Option<Vote> {
        // Execution-lag throttle: while the app reports its lane
        // saturated, withhold the vote AND refuse admission (nothing
        // stored → nothing new for a later commit walk to finalize).
        // A committed block can never be dropped, so the only honest
        // bound on execution debt is to stop committing — a withheld
        // vote is the throttle, and it recovers on re-delivery once
        // the lane drains. Crucially this *pauses* rather than
        // blocks: the pump thread keeps servicing timeouts, QC
        // adoption, and catch-up while debt drains — a consensus
        // thread stalled inside `finalize_block` (the old bounded-
        // channel send) could do none of that.
        if self.app.exec_saturated() {
            return None;
        }
        // Authentication memoisation: a proposal's authenticity is a
        // pure function of its bytes, so re-deliveries must not
        // re-pay the proposer BLS verify + shard-commitment encode.
        // `admit_proposal` owns the verdict stores:
        //  - `rejected_headers` — the header failed authentication.
        //    Permanent: reject without work.
        //  - `blocks[hash]` as `Complete` — only a header+body that
        //    cleared both checks ever lands there, so its presence
        //    IS the positive memo; skip straight to eligibility with
        //    the *stored* body (the verified one — a re-delivered
        //    equivocating body must not reach `process_proposal`).
        // Without this, every pump iteration re-verified every
        // pending proposal — one Byzantine peer could keep the whole
        // consensus thread inside BLS verification (proposal-flood
        // exhaustion).
        let block_hash = Self::block_hash(header);
        if !self.admit_proposal(header, proposal) {
            return None;
        }
        let stored = match self.blocks.get(&block_hash) {
            Some((_, BlockBody::Complete(stored))) => stored.clone(),
            _ => return None,
        };
        self.vote_if_eligible(header, block_hash, Some(&stored))
    }

    /// Authenticate a proposal and store it for later voting — the
    /// intake half of [`OxideBft::vote`], split out so a network
    /// driver can verify a wire proposal *before* letting it claim a
    /// pending slot. Returns `true` iff the block now sits in
    /// `self.blocks` as `Complete` (stored by this call or an
    /// earlier one).
    ///
    /// Why drivers must call this before dedupe: `header.proposer`
    /// is a *claim* — `proposer_hash` is a public function of the
    /// validator index, so a Byzantine peer can mint frames that pass
    /// the cheap leader-compare while carrying a forged signature.
    /// If a `(view, proposer)` dedupe slot is claimed on the claim
    /// alone, junk that races ahead of the real leader parks the key
    /// and the genuine proposal is dropped as a "duplicate" — the
    /// flood becomes censorship. Only a *verified* proposal may
    /// occupy the slot.
    ///
    /// Storage semantics:
    ///  - authentication failure → `rejected_headers` memo, nothing
    ///    stored (the header itself is forged — permanently junk).
    ///  - authentic header + body that fails the commitment check →
    ///    the header is parked `Awaiting`: the signature is real, so
    ///    the failure indicts the *relay's body*, not the header —
    ///    memoising the header here would let a corrupting relay
    ///    censor a genuine leader proposal. A later delivery with
    ///    the correct body upgrades it to `Complete` without
    ///    re-verifying the signature.
    ///  - authentic header + commitment-matching body → `Complete`.
    ///  - saturated execution lane → `false` for anything not already
    ///    stored: admitting new bodies while the app cannot execute
    ///    would grow `blocks` without bound. `false` memoises
    ///    nothing — re-delivery after the lane drains re-admits.
    pub fn admit_proposal(&mut self, header: &BlockHeader, proposal: &Proposal) -> bool {
        self.admit_proposal_inner(header, proposal, None)
    }

    /// [`admit_proposal`] with the wire crypto already screened by
    /// the node's bounded signature pool: `sig_ok` replaces the
    /// proposer-signature verify and `commit_ok` the shard-
    /// commitment encode — both computed off-thread by
    /// [`OxideBft::proposal_verify_context`]'s material.
    ///
    /// Nothing else is offloaded. Every state-dependent check —
    /// the saturation gate, the height bound, the effective-leader
    /// schedule, the storage decision — still runs here against
    /// *live* engine state, so a verdict computed under a committee
    /// that has since rotated can never store a proposal: the
    /// leader check re-derives the expected proposer at apply time
    /// and rejects the stale claim.
    pub fn admit_preverified(
        &mut self,
        header: &BlockHeader,
        proposal: &Proposal,
        sig_ok: bool,
        commit_ok: bool,
    ) -> bool {
        self.admit_proposal_inner(header, proposal, Some((sig_ok, commit_ok)))
    }

    /// Shared admission body for [`admit_proposal`] and
    /// [`admit_preverified`]. `verdict` is `Some((sig_ok,
    /// commit_ok))` when the pool already ran the crypto; `None`
    /// computes both inline exactly as before.
    fn admit_proposal_inner(
        &mut self,
        header: &BlockHeader,
        proposal: &Proposal,
        verdict: Option<(bool, bool)>,
    ) -> bool {
        let block_hash = Self::block_hash(header);
        if self.rejected_headers.contains(&block_hash) {
            return false;
        }
        if let Some((_, BlockBody::Complete(_))) = self.blocks.get(&block_hash) {
            return true;
        }
        if self.app.exec_saturated() {
            return false;
        }
        if !self.blocks.contains_key(&block_hash) {
            if self.authenticate_proposal_inner(header, verdict.map(|(sig_ok, _)| sig_ok)).is_none()
            {
                self.reject_header(block_hash);
                return false;
            }
            // Park the verified header (`Awaiting`) before the body
            // check: the signature is paid once no matter how many
            // bad bodies a relay attaches, and the dispersed-
            // broadcast path already treats `Awaiting` as the
            // "header verified, body pending" state.
            self.blocks.insert(block_hash, (header.clone(), BlockBody::Awaiting));
        }
        // Body↔commitment binding: the leader signed a shard
        // commitment into the header — the body it shipped must hash
        // to it. Without this check a byzantine leader could attach
        // an arbitrary body to a commitment that honest validators
        // attested (notarize-on-commitment means the *commitment* is
        // what the QC actually certifies). Gated on
        // `verify_signatures`: unauthenticated conformance headers
        // carry no meaningful commitment (same precedent as the
        // signature checks); the shard path enforces the binding
        // unconditionally at `supply_body`.
        if self.verify_signatures {
            let commit_ok = if let Some((_, commit_ok)) = verdict {
                commit_ok
            } else if header.body_hash == Hash::ZERO {
                // Synthetic/legacy headers (body_hash absent) fall
                // back to the erasure commitment.
                let mut buf = Vec::new();
                proposal.encode(&mut buf);
                types::shard::commitment(&buf, self.validator_set.n(), self.erasure_k())
                    == header.body_commitment
            } else {
                // Fast path: the header carries the body's BLAKE3
                // integrity hash — one hash pass over the canonical
                // encoding instead of a Reed-Solomon encode (measured
                // ~4× cheaper on a 1.5MB body). Same binding strength:
                // both fields are signed in the header.
                let mut buf = Vec::new();
                proposal.encode(&mut buf);
                crypto::hash::Hasher::hash_one(crypto::hash::Domain::BodyHash, &buf)
                    == header.body_hash
            };
            if !commit_ok {
                return false;
            }
        }
        // Store the authenticated block body BEFORE the vote-
        // eligibility checks. The QC commit walk in `deliver_qc`
        // can only run while the QC'd block is in `self.blocks`, and
        // real networks reorder: a QC frequently reaches a validator
        // before the proposal it certifies (different peers, different
        // paths). If the proposal then arrives while its view is
        // already past, the vote path below rejects it as stale — but
        // the body is still required for the commit walk that the
        // early QC could not complete. Storing here (after proposer-
        // signature verification, so only the genuine leader's blocks
        // land) keeps block availability independent of vote
        // eligibility — the deciding factor for *commit* order is the
        // QC chain, not local vote timing.
        self.blocks.insert(block_hash, (header.clone(), BlockBody::Complete(proposal.clone())));
        true
    }

    /// Validator: vote on a block *header* alone — the dispersed-
    /// broadcast path. The voter has verified its assigned body
    /// shard against `header.body_commitment` (harness-side) and
    /// notarizes the commitment immediately; the full body is
    /// reconstructed lazily and certified at `supply_body` before
    /// it can ever finalize (`DispersedSimplex`: notarize on partial
    /// information, certify before finalize).
    ///
    /// The block is stored `Awaiting` so header-level rules
    /// (parentage, QC-chain walk) work exactly as with a complete
    /// body — commit still defers until the body lands.
    pub fn vote_header(&mut self, header: &BlockHeader) -> Option<Vote> {
        // Same saturation contract as `vote()`: withhold the vote and
        // do not even park the header `Awaiting` — the shard re-gossip
        // re-delivers it once the lane drains.
        if self.app.exec_saturated() {
            return None;
        }
        // Same memoisation contract as `vote()`: a stored entry —
        // `Awaiting` or `Complete` — exists only for an authenticated
        // header, and `rejected_headers` covers the negative verdict.
        let block_hash = Self::block_hash(header);
        if self.rejected_headers.contains(&block_hash) {
            return None;
        }
        if !self.blocks.contains_key(&block_hash) {
            if self.authenticate_proposal(header).is_none() {
                self.reject_header(block_hash);
                return None;
            }
            // Insert only when vacant: a `Complete` body already
            // stored must never be downgraded to `Awaiting`.
            self.blocks.entry(block_hash).or_insert_with(|| (header.clone(), BlockBody::Awaiting));
        }
        self.vote_if_eligible(header, block_hash, None)
    }

    /// Memoise a permanent proposal rejection. Both failure modes
    /// covered by the callers are pure functions of the header bytes
    /// (authentication: schedule + signature; commitment: body hash
    /// vs signed commitment), so the verdict survives for the
    /// process epoch — it is cleared at rotation alongside the other
    /// committee-bound verdict caches.
    ///
    /// Capacity is bounded by `MAX_REJECTED_HEADERS`; on overflow the
    /// set is cleared wholesale rather than evicting selectively —
    /// the worst case is re-verifying junk that floods back in, and
    /// the intake dedupe in the network drivers makes a genuine
    /// flood of *distinct* headers the only way to fill it.
    fn reject_header(&mut self, block_hash: Hash) {
        if self.rejected_headers.len() >= super::MAX_REJECTED_HEADERS {
            self.rejected_headers.clear();
        }
        self.rejected_headers.insert(block_hash);
    }

    /// Shared proposal authentication for both vote paths: sanity
    /// bounds, expected-leader + signature verification, and the
    /// observed-height watermark update. Returns the block hash when
    /// the header is genuine; `None` means the caller must not vote
    /// AND must not store anything — an unauthenticated header is
    /// worthless for both voting and the commit walk.
    pub(crate) fn authenticate_proposal(&mut self, header: &BlockHeader) -> Option<Hash> {
        self.authenticate_proposal_inner(header, None)
    }

    /// [`authenticate_proposal`] with the proposer-signature verify
    /// already run by the signature pool: `sig_verdict` asserts the
    /// pool's pass/fail for `header.proposer_signature` over the
    /// signing hash under the intake-resolved leader key. The
    /// leader-identity check and the height bound re-run here on
    /// live state regardless — the verdict only replaces the BLS
    /// pairing, never the schedule lookup.
    fn authenticate_proposal_inner(
        &mut self,
        header: &BlockHeader,
        sig_verdict: Option<bool>,
    ) -> Option<Hash> {
        // Sanity bound (C1 fix): reject proposals with height near
        // u64::MAX before learning it. Such a height is never
        // legitimate (at 10 blk/s, u64::MAX is ~58 billion years),
        // and observe_block_height would saturate next_height to MAX,
        // permanently stalling this validator's proposer duty.
        // Rejecting here prevents a byzantine leader from poisoning
        // next_height via a crafted header.
        if header.height.value() >= Height::MAX.prev().unwrap_or(Height::MAX).value() {
            return None;
        }
        // C3 fix: verify the proposer is the expected leader for
        // this view and that the proposal is genuinely signed by
        // that leader. Without this, any validator could fabricate
        // a proposal in any view — the header's `proposer` field is
        // self-claimed and `proposer_signature` was always `None`.
        //
        // In production mode (`verify_signatures`), we check:
        //   1. `header.proposer` matches the expected leader for
        //      `header.view` (prevents a non-leader from proposing).
        //   2. `proposer_signature` is present and verifies against
        //      the leader's public key over the proposal signing hash
        //      (prevents a byzantine node from forging the leader's
        //      proposal).
        // In conformance mode, both checks are skipped.
        if self.verify_signatures {
            // Reputation-aware expectation: the schedule skips
            // validators that signed nothing in the committed
            // window, so the honest leader here is the *effective*
            // one — a proposal from the raw (possibly excluded)
            // schedule position is as forged as any other wrong
            // proposer.
            let expected_leader = self.effective_leader(header.view);
            let expected_proposer = proposer_hash(expected_leader);
            if header.proposer != expected_proposer {
                return None;
            }
            let Some(sig) = &header.proposer_signature else {
                return None;
            };
            // The leader key is re-resolved under the *live* set:
            // if the committee rotated between intake and apply,
            // the expected leader for this view may differ and the
            // pooled verdict (computed under the old key) no longer
            // stands — the claim fails the leader check above
            // first, so a stale verdict can never admit.
            let leader_pk = self.validator_set.validator(expected_leader).map_err(|_| ()).ok()?;
            let verified = if let Some(ok) = sig_verdict {
                ok
            } else {
                let signing_hash = Self::proposal_signing_hash(header);
                crypto::verify(
                    sig,
                    crypto::hash::Domain::Proposal,
                    signing_hash.as_bytes(),
                    leader_pk,
                )
                .is_ok()
            };
            if !verified {
                return None;
            }
        }
        // Height sync: learn the chain's progression from this
        // proposal. Even if we reject the proposal (tail-fork
        // resistance, already voted, etc.), the height is a fact
        // about the chain's progression. If we later become the
        // leader, we must propose at a height above any we've seen.
        self.observe_block_height(header.height);
        Some(Self::block_hash(header))
    }

    /// The committed timestamp of `header`'s declared parent, if the
    /// parent is known locally. Two sources cover both states a
    /// parent can be in:
    ///
    /// - **In-flight** (`self.blocks`): the parent header is stored
    ///   verbatim, timestamp included.
    /// - **Committed** (`last_committed` → `finalized`): the header
    ///   is dropped at commit, but its timestamp survives on the
    ///   `FinalizedBlock`'s execution context — the same value the
    ///   app executed under.
    ///
    /// `None` means "parent unknown" (e.g. a genesis proposal): the
    /// caller skips the monotonicity check — an unavailable parent
    /// timestamp proves nothing either way.
    pub(crate) fn parent_timestamp(&self, header: &BlockHeader) -> Option<u64> {
        if let Some((parent, _)) = self.blocks.get(&header.prev_block) {
            return Some(parent.timestamp);
        }
        self.last_committed
            .filter(|(hash, _)| *hash == header.prev_block)
            .and_then(|(_, height)| self.finalized.get(&height.value()))
            .map(|block| block.context.timestamp_ms)
    }

    /// The Jolteon timeout-path predicate (arXiv:2106.10362 §3,
    /// Figure 2): a proposal entering through `TC(v−1)` must carry a
    /// QC at least as recent as the maximum `qc_high` evidence the
    /// TC reports — `B.qc.r >= max{qc_high.r | qc_high ∈ B.tc}`.
    ///
    /// The max evidence is adopted first, so the parent-binding
    /// check in `vote_if_eligible` evaluates against the locked
    /// chain rather than our (possibly staler) high QC — a TC
    /// carrying a QC we never saw is precisely the withheld-QC case
    /// this mechanism exists for, and the proposer of a legitimate
    /// continuation builds on exactly that block.
    ///
    /// Returns `false` when the proposal's embedded QC is absent or
    /// below the evidence floor; `true` when there is no entry TC
    /// (the happy path has no floor) or the floor is met.
    fn tc_evidence_floor_ok(
        &mut self,
        header: &BlockHeader,
        entry_tc: Option<&VerifiedTc>,
    ) -> bool {
        let Some(tc) = entry_tc else { return true };
        let Some(max_qc) = tc.max_evidence() else {
            // No evidence at all: a TC of `None` claims is legal
            // (view 0 timeouts carry no QCs) — any QC clears the
            // floor.
            return true;
        };
        if self.high_qc.as_ref().is_none_or(|h| h.view() < max_qc.view) {
            let _ = self.deliver_qc(max_qc.clone());
        }
        matches!(&header.high_qc, Some(prop_qc) if prop_qc.view >= max_qc.view)
    }

    /// Tail-fork resistance: a proposal is votable only if it
    /// extends the chain our `high_qc` points at.
    ///
    /// A proposal extends our highest QC when its `high_qc` is at
    /// least as recent as ours (`prop_qc.view >= our_high_qc.view`).
    /// This covers three legitimate cases:
    ///   1. The proposal's QC *is* our `high_qc` (happy path: the
    ///      leader built on the same QC — views are equal).
    ///   2. The proposal's QC is *newer* than ours (view change:
    ///      the new leader saw a QC we missed and built on it —
    ///      `prop_qc.view > our_high_qc.view`). Accepting this is
    ///      what lets the chain advance after a view change and is
    ///      the core of tail-fork *resistance*: a validator on a
    ///      stalling fork must still vote for a proposal that
    ///      extends the highest QC it has seen, even if that QC
    ///      arrived via a proposal rather than directly.
    ///   3. The proposal's block chain traces back to our
    ///      `high_qc`'s block (transitively). The view-ordering
    ///      check is the cheap, sound over-approximation of this:
    ///      any chain extending our `high_qc` carries a QC with
    ///      view >= ours, so the view test admits all extending
    ///      chains while rejecting stale forks.
    ///
    /// A leader with a *lower* `high_qc` view is forking away from
    /// a more recent notarized block — reject it.
    ///
    /// Beyond the view check, `prev_block` must equal our `high_qc`'s
    /// block hash (binds the parent to the notarized block we hold —
    /// otherwise a leader could pair a valid QC view with an
    /// unrelated `prev`, creating a phantom chain), and the stamped
    /// height must be the parent's + 1 (a forged future height would
    /// commit at a gap and per-height-lock the voters the honest
    /// chain still needs). If we adopted a QC for a block whose
    /// header we never saw, continuity can't be verified — refuse
    /// until the block arrives via catch-up gossip.
    ///
    /// With no `high_qc`, the only votable proposal extends the
    /// committed anchor: genesis (height 0, zero parent) or the
    /// post-rotation `last_committed` block. Anything else is a
    /// forged chain — without the anchor check a Byzantine leader
    /// could attach a made-up parent hash and stamp any height.
    fn extends_locked_chain(&self, header: &BlockHeader) -> bool {
        if let Some(our_high_qc) = &self.high_qc {
            match &header.high_qc {
                Some(prop_qc) if prop_qc.view < our_high_qc.view() => return false,
                None => return false,
                _ => {}
            }
            if header.prev_block != our_high_qc.block_hash() {
                return false;
            }
            // Parent resolution: in-flight blocks live in `blocks`;
            // a block synced in via `apply_certified_block` goes
            // straight to the committed prefix and is only reachable
            // through `last_committed`. Without the anchor arm a
            // proposal extending a freshly synced tip is unvotable —
            // the synced node would catch up but never rejoin.
            if let Some((parent_header, _)) = self.blocks.get(&header.prev_block) {
                return header.height == parent_header.height.saturating_next();
            }
            match self.last_committed {
                Some((anchor_hash, anchor_height)) if anchor_hash == header.prev_block => {
                    header.height == anchor_height.saturating_next()
                }
                _ => false,
            }
        } else {
            match self.last_committed {
                Some((anchor_hash, anchor_height)) => {
                    header.prev_block == anchor_hash
                        && header.height == anchor_height.saturating_next()
                }
                None => header.height == Height::new(0) && header.prev_block == Hash::ZERO,
            }
        }
    }

    /// Shared vote-eligibility chain for both vote paths. `body` is
    /// `Some` for the complete-proposal path (`vote`) and `None` for
    /// the commitment path (`vote_header`): the app's static
    /// `process_proposal` check needs body bytes, so the commitment
    /// path defers it to `supply_body`'s certification — a notarized
    /// block whose body fails certification can never finalize.
    pub(crate) fn vote_if_eligible(
        &mut self,
        header: &BlockHeader,
        block_hash: Hash,
        body: Option<&Proposal>,
    ) -> Option<Vote> {
        // HIGH fix: require the proposal's view to match our current
        // view. A proposal for a different view is either stale
        // (already finalized) or premature (future round). Voting
        // for a stale view re-opens a committed height; voting for
        // a future view breaks the one-view-one-vote invariant.
        // The `last_voted_view` check below prevents re-voting in
        // the same view, but does not prevent voting in a *wrong*
        // view.
        if header.view != self.current_view {
            return None;
        }

        // Safety: never vote twice in the same view.
        if self.last_voted_view.is_some_and(|v| v >= header.view) {
            return None;
        }
        // Jolteon evidence integrity (arXiv:2106.10362 §3): a view we
        // signed a timeout for is unvotable. The timeout signature
        // bound the `qc_high` we held *at signing time*; voting in
        // that view afterward would mean the TC quorum contains an
        // entry that underreports the lock our vote created — and
        // once a consecutive pair commits, that underreporting is
        // exactly what would let a later proposal skip the committed
        // chain. The bar is one-directional by design: a voter that
        // already voted can (and must) still time out, reporting the
        // lock; a signer that timed out can never vote that view.
        if self.timeout_signed_view.is_some_and(|v| v == header.view) {
            return None;
        }
        // Validate the proposal's entry TC once — it feeds both the
        // per-height lock release below and the Jolteon evidence
        // floor. `None` means absent, mismatched, or unverifiable —
        // in each case it carries no protocol weight.
        let entry_tc = self.valid_entry_tc(header);
        // Per-height vote lock: never vote for a *different* block at
        // a height we already voted. The view check alone does not
        // cover this: after a timeout, a new leader can propose a
        // conflicting block at the same height extending the same
        // parent QC — the tail-fork check passes on equal QC view,
        // and voting here would notarize two conflicting blocks at
        // one height. Re-voting the same hash is safe and required
        // for liveness (a leader re-proposing an uncommitted block).
        //
        // Release (spec §view-changes): the lock yields when the
        // proposal carries a valid TC for the immediately preceding
        // view — quorum-certified evidence that the timed-out view
        // is past. Under the Jolteon evidence rule the TC also proves
        // *what the quorum was locked on*, so the release alone no
        // longer suffices for safety — the proposal must additionally
        // extend the highest lock the TC reports (the floor check
        // below), which is what makes a conflicting same-height
        // successor unvotable once a chain is committed.
        if self
            .voted_at_height
            .get(&header.height.value())
            .is_some_and(|voted| *voted != block_hash)
            && entry_tc.is_none()
        {
            return None;
        }
        // Jolteon timeout-path predicate (arXiv:2106.10362 §3,
        // Figure 2): a proposal entering through TC(v−1) must carry
        // a QC at least as recent as the maximum `qc_high` evidence
        // the TC reports — `B.qc.r >= max{qc_high.r | qc_high ∈
        // B.tc}`. We additionally adopt that max evidence first, so
        // the parent-binding check below evaluates against the
        // locked chain rather than our (possibly staler) high QC —
        // a TC carrying a QC we never saw is precisely the withheld-
        // QC case this mechanism exists for, and the proposer of a
        // legitimate continuation builds on exactly that block.
        if !self.tc_evidence_floor_ok(header, entry_tc.as_ref()) {
            return None;
        }
        // Structural rule (spec §2): a block extends exactly the
        // block its embedded QC certifies — `prev_block ==
        // high_qc.block_hash`. Honest proposals always satisfy this
        // (`propose` sets both from the same highQC), so only a
        // crafted proposal can violate it — and the payoff is real:
        // the tail-fork check below binds `prev` to OUR highQC block
        // while the two-chain commit rule walks JUSTIFY edges (a
        // QC'd block commits its embedded QC's target). Decoupling
        // the two lets a Byzantine leader attach a newer-view QC for
        // a different block: the proposal passes tail-fork on `prev`,
        // but its adoption later commits through `justify` — the
        // voter's real parent is never committed (finalized gap) and
        // peers who adopted the justify chain commit a different
        // block at the same height (fork). TLC's `InvNoGap`
        // counterexample is exactly this shape.
        if let Some(hqc) = &header.high_qc
            && header.prev_block != hqc.block_hash
        {
            return None;
        }
        // Timestamp monotonicity: a block's committed timestamp must
        // never go backwards relative to its declared parent. This is
        // an *objective* rule — the parent is fixed by the header's
        // own `prev_block`/`high_qc` chain, so the check needs no
        // local clock and cannot fork on validator skew. `0` is the
        // "no timestamp" sentinel (clockless engines, hand-built
        // headers): either side reading zero carries no ordering
        // information, so the rule binds only when both stamps are
        // present. Equal timestamps are legal — the millisecond
        // granularity can stamp two blocks in the same tick.
        if header.timestamp != 0
            && let Some(parent_ts) = self.parent_timestamp(header)
            && parent_ts != 0
            && header.timestamp < parent_ts
        {
            return None;
        }
        // Tail-fork resistance / extends-highest-QC rule
        // (docs/oxidebft-spec.md §4): reject proposals that don't
        // extend our highest QC. A leader that forks away a notarized
        // block must be bypassed, not rewarded. See
        // `extends_locked_chain` for the full rule.
        if !self.extends_locked_chain(header) {
            return None;
        }
        // Ordered before the high-QC signature check on purpose: the
        // gates are independent conditions (all must pass), so their
        // order is not a safety property — but under execution lag
        // this is the gate that fails, and a retrying driver (zero
        // `exec_attest_wait`) must not pay a BLS aggregate verify on
        // every attempt before discovering it.
        // Divergence detection (docs/oxidebft-spec.md §6): if the
        // proposal carries an `exec_cert` for a previous block, verify
        // that the certified state root matches our locally computed
        // state root for that height. A mismatch means either our
        // execution diverged from the network, or the network is
        // byzantine. In either case, refuse to vote — voting for a
        // block built on a divergent state would extend the divergence.
        //
        // The check is skipped when `verify_signatures` is false
        // (conformance mode) since the app may not have real state.
        if self.verify_signatures
            && let Some(cert) = &header.exec_cert
        {
            // Full validation once per unique certificate
            // (cached in `verified_exec_certs`): epoch match,
            // bitmap bounds, quorum power, aggregate signature.
            // A forged cert — even one carrying a
            // locally-matching root — is unproven execution
            // agreement and must never ride into a committed
            // block as if it were evidence. The old code skipped
            // verification whenever the root matched, letting a
            // fabricated cert be committed unquestioned.
            if !self.exec_cert_verified(cert) {
                return None;
            }
            // The now-verified cert's root must equal what WE
            // executed at that height. `None` means the height
            // has not executed locally — we cannot confirm the
            // certificate, so the vote is withheld. (The old
            // `Hash::ZERO` sentinel here let a forged cert
            // claiming a zero root "match" an unexecuted
            // height.) The wait is bounded by `exec_attest_wait`
            // (default `EXEC_ATTEST_WAIT`; zero for drivers that
            // retry every pass): a lagging execution lane must never
            // stall the consensus thread — a timed-out attestation
            // withholds the vote, which a later attempt recovers.
            // A mismatch on a *verified* cert means a
            // stake supermajority really attested a root we did
            // not compute — confirmed divergence; refuse to
            // extend it.
            let local = self.app.attest_state_bounded(cert.height, self.exec_attest_wait)?;
            if local.root != cert.state_root {
                // Confirmed divergence — the cert is fully verified
                // (quorum + signature), so a supermajority attested
                // a root this validator did not compute. Halt all
                // signing for the process lifetime: every signature
                // from here extends a chain built on state we do
                // not share, and silence without a latch once let
                // each validator quietly leak out of the quorum
                // while operators saw only a slowing chain. The
                // latch survives rotation — a new epoch does not
                // repair diverged state; certified resync does.
                self.latch_divergence(ExecDivergence {
                    height: cert.height,
                    local_root: local.root,
                    certified_root: cert.state_root,
                });
                return None;
            }
        }
        // The embedded QC is commit evidence — its bitmap becomes the
        // committed parent's attendance record — so it must be a real
        // certificate, not claimed bytes. Verified here (after the
        // cheap structural checks) rather than in `deliver_qc`: a
        // fabricated justify must never gather votes at all. Same
        // cost class as the standalone QC verify in `deliver_qc` —
        // one aggregate verify per accepted-position proposal.
        if let Some(hqc) = &header.high_qc {
            // Quorum is a structural property, not a cryptographic
            // one — a sub-quorum bitmap is not a certificate even
            // when its aggregate signature verifies (a QC with a
            // single honest signer's vote verifies as a valid
            // aggregate yet carries no quorum). Enforced
            // unconditionally, matching `deliver_qc`: without it a
            // Byzantine leader could embed a self-signed "QC" and
            // have honest voters notarize a chain whose parent never
            // achieved real consensus. The threshold is voting
            // *power* — a majority of low-stake signers is not a
            // quorum under unequal stake.
            if !self.bitmap_meets_quorum(&hqc.signer_bitmap) {
                return None;
            }
            // A `high_qc` this engine already delivered was verified
            // then (inline or by the pool) — skip the second pairing
            // (hft-audit-2 N-4).
            if self.verify_signatures
                && !self.qc_memo_hit(hqc)
                && self.verify_qc_signature(hqc).is_err()
            {
                return None;
            }
        }
        // Process the proposal through the app (static validity).
        // The commitment path (`vote_header`) has no body yet — its
        // `process_proposal` runs at `supply_body` certification, so
        // a notarized block carrying invalid txs can never finalize.
        if let Some(proposal) = body {
            match self.app.process_proposal(proposal) {
                Verdict::Accept => {}
                Verdict::Reject { .. } => return None,
            }
        }
        // The block body was already stored above (before the
        // eligibility checks) — commit-walk completeness must not
        // depend on this vote succeeding.
        self.last_voted_view = Some(header.view);
        // Record the per-height lock: we may only ever vote this
        // hash at this height from now on.
        self.voted_at_height.insert(header.height.value(), block_hash);
        // C9 fix: persist safety-critical state to the WAL before
        // sending the vote. If the node crashes after the vote is
        // sent but before the WAL is written, a restart could
        // double-vote or vote for a conflicting block. The WAL
        // append fsyncs before returning, ensuring durability.
        //
        // C10 fix: the append must succeed for the vote to exist at
        // all. A signature emitted while its locks might be
        // undurable can equivocate after a restart, so a failed
        // append withholds the vote entirely (and latches
        // `wal_failed` for everything that follows).
        if self.append_wal().is_err() {
            return None;
        }
        // Sign the vote (stage 5: real BLS if key is set). The
        // `wal_failed` latch gates inside `sign_vote` too, so no
        // path can emit a signature after a durability failure.
        let signature = self.sign_vote(header.view, block_hash)?;
        // Attach the newest execution attestation — the divergence-
        // detection input leaders aggregate into `ExecCertificate`s.
        let (attestation, attestation_sig) = self.build_attestation();
        Some(Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature,
            attestation,
            attestation_sig,
        })
    }

    /// Build the BLS signing message for a vote. Binds `(view,
    /// phase, block_hash, epoch)` to prevent replay across phases
    /// or epochs (C3 fix).
    ///
    /// Format: `view.to_le_bytes() (8) + phase_byte (1) +
    /// block_hash (32) + epoch.to_le_bytes() (8)` = 49 bytes.
    ///
    /// Returns a fixed stack array — this runs once per vote
    /// (verify + sign) on the quorum hot path, and a heap `Vec`
    /// allocated 49 bytes per call for no reason.
    ///
    /// Exposed for the deterministic-simulation harness (`oxide-sim`):
    /// a byzantine-voter strategy must sign a second, conflicting vote
    /// for the same view with the node's real key to exercise
    /// equivocation/double-vote handling. Production callers should
    /// not need this — the engine signs internally in `vote()`.
    pub fn vote_signing_message(&self, view: View, phase_byte: u8, block_hash: &Hash) -> [u8; 49] {
        crate::verify::vote_signing_message(self.epoch, view, phase_byte, block_hash)
    }

    /// Get the current pipeline phase as a byte. In the current
    /// oxideBFT implementation, all votes are in the generic "vote"
    /// phase (the engine doesn't distinguish prepare/pre-commit/
    /// commit in the signing path yet — the phase is carried in the
    /// `Vote` struct and will be bound to the signature in a future
    /// hardening pass). For now, we use 0 as a placeholder.
    pub(crate) fn current_phase_byte() -> u8 {
        0
    }

    /// Sign a vote with this engine's BLS secret key. If no key is set
    /// (conformance mode), returns `Signature::ZERO`.
    ///
    /// Returns `None` when `wal_failed` is latched (C10): the engine
    /// is the single signing authority for every vote it emits, and
    /// no signature may leave while the durability of its
    /// anti-equivocation state is in doubt.
    ///
    /// # Signed message (C3 fix)
    ///
    /// The signed message binds `(view, phase, block_hash, epoch)` to
    /// prevent vote replay across phases or epochs. A `Prepare` vote
    /// signature cannot be reused as a `PreCommit` or `Commit` vote because
    /// the phase byte differs. A vote from epoch 0 cannot be replayed
    /// in epoch 1 because the epoch bytes differ.
    pub(crate) fn sign_vote(&self, view: View, block_hash: Hash) -> Option<Signature> {
        // Both latches are fail-closed: undurable safety state
        // (WAL) and proven-wrong execution (divergence) each make
        // any further signature equivocation- or divergence-
        // extending, so none may leave the engine.
        if self.wal_failed || self.divergence.is_some() {
            return None;
        }
        Some(match &self.signer {
            Some(signer) => {
                let phase_byte = Self::current_phase_byte();
                let msg = self.vote_signing_message(view, phase_byte, &block_hash);
                // A failed signer (e.g. a downed remote endpoint)
                // withholds the vote — the signature path is
                // fail-closed, not fail-open.
                signer
                    .sign(
                        crypto::hash::Domain::Vote,
                        &msg,
                        crypto::SignContext {
                            epoch: self.epoch.value(),
                            mark: view.value(),
                            phase: phase_byte,
                        },
                    )
                    .ok()?
            }
            None => Signature::ZERO,
        })
    }

    /// The message a validator signs for an execution attestation:
    /// `(height, state_root, epoch)` — 48 bytes. The epoch binding
    /// prevents attestation replay across epoch boundaries (same
    /// defense as the vote signing message, C3).
    pub(crate) fn attestation_signing_message(&self, height: Height, root: &Hash) -> [u8; 48] {
        crate::verify::attestation_signing_message(self.epoch, height, root)
    }

    /// Build this validator's execution attestation for an outgoing
    /// vote: the newest *executed* state root from the app, signed
    /// under `Domain::ExecAttest`. Returns `(None, None)` when
    /// nothing has executed yet — attestations are only ever claims
    /// about real execution, never placeholders.
    ///
    /// `attest_latest` is non-blocking by contract: with the async
    /// execution lane the attestation may lag the committed height
    /// by a block or more. That is safe — the height travels inside
    /// the attestation, so it certifies whatever it certifies.
    /// Public form used by harnesses that construct a leader
    /// self-vote manually (the engine only returns votes from
    /// `vote`/`vote_header`, which leaders never call on their own
    /// proposals). Returns the same `(attestation, attestation_sig)`
    /// those methods embed.
    pub fn vote_attestation(&mut self) -> (Option<StateAttestation>, Option<Signature>) {
        self.build_attestation()
    }

    pub(crate) fn build_attestation(&mut self) -> (Option<StateAttestation>, Option<Signature>) {
        // C10: an attestation is a signature too — a WAL-failed
        // validator goes fully silent rather than emitting any
        // signature whose surrounding safety state is undurable. A
        // diverged validator likewise must never attest a root it
        // no longer stands behind.
        if self.wal_failed || self.divergence.is_some() {
            return (None, None);
        }
        // `None` = nothing executed yet — attestations are only
        // ever claims about real execution, never placeholders. A
        // `Hash::ZERO` root gets the same treatment: no real state
        // root is the zero hash, so an app reporting one has not
        // actually executed anything.
        let Some(att) = self.app.attest_latest() else {
            return (None, None);
        };
        if att.root == Hash::ZERO {
            return (None, None);
        }
        // BLS signing is deterministic: an unchanged `(height,
        // root, epoch)` yields an identical signature, so the
        // cached one is byte-for-byte valid. Saves one sign per
        // vote once the executed watermark stalls behind consensus.
        // The epoch must match — the signed message binds it, so a
        // signature minted before a rotation verifies against
        // nothing in the new epoch.
        if let Some((cached_att, cached_epoch, cached_sig)) = &self.last_attestation
            && cached_att.height == att.height
            && cached_att.root == att.root
            && *cached_epoch == self.epoch
        {
            return (Some(*cached_att), Some(*cached_sig));
        }
        let sig = match &self.signer {
            Some(signer) => {
                let msg = self.attestation_signing_message(att.height, &att.root);
                // Signer failure withholds the attestation — the
                // vote still goes out (attestations are advisory),
                // just without a cert claim this round.
                match signer.sign(
                    crypto::hash::Domain::ExecAttest,
                    &msg,
                    crypto::SignContext {
                        epoch: self.epoch.value(),
                        mark: att.height.value(),
                        phase: 0,
                    },
                ) {
                    Ok(sig) => sig,
                    Err(_) => return (Some(att), None),
                }
            }
            None => Signature::ZERO,
        };
        self.last_attestation = Some((att, self.epoch, sig));
        (Some(att), Some(sig))
    }

    /// Verify an [`ExecCertificate`]'s aggregate signature against
    /// the validator set — the same pattern as
    /// [`verify_qc_signature`](Self::verify_qc_signature): the bitmap
    /// names the signers, `aggregate_verify` checks the BLS
    /// aggregate over `(height, state_root, epoch)` under
    /// `Domain::ExecAttest`.
    ///
    /// This check matters for liveness, not just authenticity: the
    /// voter-side divergence check refuses to vote on a cert whose
    /// root disagrees with local state, so a leader embedding a
    /// *fabricated* root could freeze quorum. Verifying the
    /// aggregate proves signers holding >2/3 of voting power actually
    /// attested the root —
    /// a fabricated cert fails here and the proposal is ignored
    /// before the root comparison ever runs.
    ///
    /// # Errors
    /// [`ConsensusError::SignerOutOfBounds`] if the bitmap references
    /// an out-of-range validator,
    /// [`ConsensusError::InsufficientQuorum`] if the signers' voting
    /// power is below quorum, or
    /// [`ConsensusError::InvalidQcSignature`] if the aggregate does
    /// not verify.
    pub(crate) fn verify_exec_cert(&self, cert: &ExecCertificate) -> Result<(), ConsensusError> {
        crate::verify::verify_exec_cert(&self.validator_set, self.epoch, cert)
    }

    /// Validate an embedded [`ExecCertificate`] at most once per
    /// complete identity. The vote path calls this on every proposal
    /// carrying a cert; the first sight pays the full check (epoch,
    /// bitmap bounds, quorum power, aggregate signature — one
    /// `aggregate_verify`, ~4ms) and the certificate is then cached
    /// in `verified_exec_certs` keyed by certified height with the
    /// cert itself as the value. A different cert at the same height
    /// fails the equality check and re-validates, so the cache can
    /// never launder an unverified certificate under a previously
    /// verified height. Entries are cleared at epoch rotation:
    /// verification is only defined against the epoch's validator
    /// set, so cached verdicts must not outlive it.
    pub(crate) fn exec_cert_verified(&mut self, cert: &ExecCertificate) -> bool {
        if self.verified_exec_certs.get(&cert.height.value()) == Some(cert) {
            return true;
        }
        if self.verify_exec_cert(cert).is_err() {
            return false;
        }
        self.verified_exec_certs.insert(cert.height.value(), cert.clone());
        self.exec_cert_generation = self.exec_cert_generation.wrapping_add(1);
        true
    }

    /// Latch a confirmed execution divergence — the shared halt for
    /// both paths that compare a verified certificate against local
    /// state: the vote gate above and the consume-path
    /// [`OxideBft::confirm_exec_cert`]. First write wins (the
    /// earliest mismatch is the better repair anchor), and the WAL
    /// append persists the latch before it is reported — a crash
    /// between detection and the next routine append must not
    /// restart into signing or serving over the same diverged
    /// state. A failed append latches `wal_failed`, which halts
    /// signing identically, so the failure mode stays closed.
    fn latch_divergence(&mut self, detail: ExecDivergence) {
        if self.divergence.is_some() {
            return;
        }
        // Display, not Debug: `Hash`'s Debug truncates to 12 hex
        // chars, and the certified root in this line is the
        // operator's `--trusted-root` repair value — it must be
        // complete.
        eprintln!(
            "oxideBFT: CRITICAL — execution divergence at height {}: \
             local root 0x{} != quorum-certified root 0x{}; \
             signing halted — repair via --state-sync with \
             --trusted-height {} --trusted-root 0x{}",
            detail.height.value(),
            detail.local_root,
            detail.certified_root,
            detail.height.value(),
            detail.certified_root,
        );
        self.divergence = Some(detail);
        let _ = self.append_wal();
    }

    /// Consume-path divergence check — the non-voting analog of the
    /// exec-cert gate inside [`OxideBft::vote`]. Verifies `cert`
    /// (epoch, bitmap bounds, quorum power, aggregate signature —
    /// cached in `verified_exec_certs`), then requires the locally
    /// executed root at `cert.height` to match the attested root.
    ///
    /// [`OxideBft::admit_exec_cert`] alone only verifies signatures
    /// and never compares local state: that is correct for the
    /// repair flow (which proves the rebuilt root later through
    /// `mark_repaired`), but a replica that never votes — a
    /// follower or indexer consuming certified blocks — would
    /// mirror diverged state forever with no signal. Calling this
    /// instead runs the same local-root comparison voters get,
    /// with identical latch semantics on a confirmed mismatch.
    ///
    /// Returns `true` only when the cert verifies and local state
    /// confirms it. An unverifiable cert returns `false`; a height
    /// not yet executed locally returns `false` too — transient
    /// execution lag, never a confirmed divergence (the bounded
    /// wait is the default `EXEC_ATTEST_WAIT` even when the vote
    /// path runs with zero: callers here confirm once and do not
    /// retry, so a zero wait would silently skip the check). A verified
    /// cert attesting a root this engine did not compute latches
    /// `divergence` and returns `false`; callers gate the consume
    /// path on [`OxideBft::divergence`].
    pub fn confirm_exec_cert(&mut self, cert: &ExecCertificate) -> bool {
        if !self.exec_cert_verified(cert) {
            return false;
        }
        let Some(local) = self.app.attest_state_bounded(cert.height, EXEC_ATTEST_WAIT) else {
            return false;
        };
        if local.root == cert.state_root {
            return true;
        }
        self.latch_divergence(ExecDivergence {
            height: cert.height,
            local_root: local.root,
            certified_root: cert.state_root,
        });
        false
    }

    /// Leader: collect a vote from validator `voter`. Stores the vote
    /// for later QC formation. The `voter` index identifies which
    /// slot in the signer bitmap to set.
    ///
    /// # Signature verification (C1 fix)
    ///
    /// When `verify_signatures` is `true` (production), the vote's
    /// signature is verified against the voter's public key from the
    /// validator set. A forged vote is rejected with
    /// [`ConsensusError::InvalidVoteSignature`]. The signed message
    /// is the vote's `block_hash` (32 bytes) under `Domain::Vote`.
    ///
    /// # Vote consistency (hardening)
    ///
    /// Every vote collected for the current view must agree on
    /// `(view, block_hash)`. A byzantine voter could send conflicting
    /// votes for different blocks at the same view to different
    /// leaders. Without this check, a leader could mix votes for
    /// different blocks into one QC, producing a QC that appears
    /// valid but does not represent agreement on a single block.
    /// The first vote collected sets the expected `(view, block_hash)`;
    /// subsequent votes for the same view must match.
    ///
    /// # Errors
    /// Returns [`ConsensusError::InvalidVoteSignature`] if the
    /// voter index is out of bounds or the signature does not verify,
    /// or [`ConsensusError::ConflictingVote`] if the vote's
    /// `(view, block_hash)` does not match the first vote collected
    /// for this view.
    pub fn collect_vote(
        &mut self,
        voter: ValidatorIndex,
        vote: Vote,
    ) -> Result<(), ConsensusError> {
        let (res, attest) = self.collect_vote_split(voter, vote);
        if let Some(task) = attest
            && crypto::verify(
                &task.signature,
                crypto::hash::Domain::ExecAttest,
                &task.msg,
                &task.pk,
            )
            .is_ok()
        {
            self.apply_verified_attestation(task.voter, task.attestation, task.signature);
        }
        res
    }

    /// [`collect_vote`] with the attestation's BLS verify deferred
    /// to the node's signature pool: the vote collects immediately
    /// — QC formation is latency-critical and a vote is never
    /// gated on its attestation — while the attestation's verify
    /// material returns for a worker to run. The verdict applies
    /// through [`OxideBft::apply_attest_verdict`].
    ///
    /// Everything else matches `collect_vote` exactly — including
    /// the `verify_per_vote` vote-signature check, which stays
    /// inline: a collected vote can't be unwound on a late
    /// verdict, so it is never deferred.
    pub fn collect_vote_pooled(
        &mut self,
        voter: ValidatorIndex,
        vote: Vote,
    ) -> (Result<(), ConsensusError>, Option<AttestVerifyTask>) {
        self.collect_vote_split(voter, vote)
    }

    /// Apply a pooled attestation verdict: a passing verdict
    /// inserts exactly as the inline path does; a failing one
    /// drops the attestation — the vote itself already collected
    /// (attestations are best-effort and individually droppable).
    pub fn apply_attest_verdict(
        &mut self,
        voter: ValidatorIndex,
        attestation: StateAttestation,
        signature: Signature,
        verified: bool,
    ) {
        if verified {
            self.apply_verified_attestation(voter, attestation, signature);
        }
    }

    /// Insert a signature-verified attestation into the
    /// aggregation pool and form the [`ExecCertificate`] at stake
    /// quorum — the tail `collect_vote` and `apply_attest_verdict`
    /// share. The cert-existence gate and voter bounds re-run
    /// against *live* state: a verdict that went stale between
    /// intake and apply — a cert formed meanwhile, or the
    /// committee rotated — can never insert.
    fn apply_verified_attestation(
        &mut self,
        voter: ValidatorIndex,
        attestation: StateAttestation,
        signature: Signature,
    ) {
        let att = &attestation;
        // Skip when a cert already exists for this height —
        // quorum is proven, so further attestations are redundant.
        // Attestations for the committed tip are NOT redundant:
        // the normal steady state is voters attesting their newest
        // executed (= committed) block, and that is precisely the
        // root the next proposals certify. Re-checked at apply
        // because a pooled verdict can land after the cert formed.
        if self.exec_certs.contains_key(&att.height.value())
            || self.validator_set.validator(voter).is_err()
        {
            return;
        }
        let sig = signature;
        let bucket = self
            .exec_attest_pool
            .entry(att.height.value())
            .or_default()
            .entry(att.root)
            .or_default();
        if bucket.iter().any(|(v, _)| *v == voter) {
            return;
        }
        bucket.push((voter, sig));
        // Quorum of identical attestations measured in voting
        // power — the same stake-weighted threshold the cert will
        // be validated against downstream. Checked on every
        // insert; the `exec_certs.contains_key` gate above makes a
        // formed cert stop absorbing further attestations, so this
        // aggregates exactly once.
        let bucket_power: u64 =
            bucket.iter().map(|(v, _)| self.validator_set.stake(*v).unwrap_or(0)).sum();
        if bucket_power >= self.validator_set.quorum_stake() {
            let sigs: Vec<Signature> = bucket.iter().map(|(_, s)| *s).collect();
            if let Ok(aggregate_signature) = crypto::aggregate(&sigs) {
                let bitmap_len = self.validator_set.n().div_ceil(8);
                let mut signer_bitmap = vec![0u8; bitmap_len];
                for (v, _) in bucket.iter() {
                    let i = usize::from(*v);
                    signer_bitmap[i / 8] |= 1u8 << (i % 8);
                }
                self.exec_cert_generation = self.exec_cert_generation.wrapping_add(1);
                self.exec_certs.insert(
                    att.height.value(),
                    ExecCertificate {
                        height: att.height,
                        state_root: att.root,
                        epoch: self.epoch,
                        signer_bitmap,
                        aggregate_signature,
                    },
                );
            }
        }
    }

    /// The collection body `collect_vote` and `collect_vote_pooled`
    /// share: every gate and state mutation runs here except the
    /// attestation's BLS pairing, which is returned as
    /// [`AttestVerifyTask`] material for the caller to run (inline
    /// or pooled) and feed through `apply_verified_attestation`.
    fn collect_vote_split(
        &mut self,
        voter: ValidatorIndex,
        vote: Vote,
    ) -> (Result<(), ConsensusError>, Option<AttestVerifyTask>) {
        let idx = usize::from(voter);
        if idx >= self.votes.len() {
            return (Err(ConsensusError::InvalidVoteSignature { voter }), None);
        }
        // Reject votes not for the current view. Stale votes
        // (view < current_view) are leftovers from a previous round.
        // Future votes (view > current_view) are either premature
        // (the voter advanced before us) or byzantine — in both
        // cases, accepting them would poison the vote buffer: the
        // future-view vote becomes the "first vote" and all real
        // current-view votes then fail the ConflictingVote check,
        // stalling the view until a ~2s timeout. One message per
        // view = permanent liveness DoS (C2 fix). Silently dropping
        // is safe — the voter will resend, or we'll catch up via QC
        // delivery and then accept votes for the new current_view.
        if vote.view != self.current_view {
            return (Ok(()), None);
        }
        // Equivocation detection (system-audit S1): this voter has
        // already signed a vote at this `(view, phase)` naming a
        // *different* block — two signatures for conflicting blocks
        // at one position is the exact slashable offense the staking
        // module's `evidence` message consumes. The check reads the
        // per-validator history (`vote_history`), which unlike the
        // QC buffer survives QC formation and view-scoped clears —
        // an equivocating pair straddling a buffer clear is still
        // caught. The conflicting vote never enters the collection
        // bucket: it cannot pollute the QC, and the preserved pair
        // self-authenticates downstream (the module re-verifies both
        // signatures before slashing, so an unverified signature
        // slipping in under `verify_per_vote = false` is harmless).
        // Dropping returns `Ok`: the relaying peer is not the
        // offender — the slash, not a transport penalty, is the
        // correct consequence.
        // A vote is recorded below only after it clears every
        // admissibility gate (idempotent slot, signature, phantom
        // guard, conflict check), so `seen_*` always names a vote
        // this node actually counted — a dropped phantom or forged
        // message can never masquerade as the voter's first
        // signature.
        if let Some((seen_view, seen_hash, seen_sig)) = self.vote_history.get(&(voter, vote.phase))
            && *seen_view == vote.view
            && *seen_hash != vote.block_hash
        {
            if self.evidence_out.len() < MAX_PENDING_EVIDENCE {
                // `idx` was bounds-checked against `votes.len()`
                // (= committee size) above, and
                // `validator_addresses` is index-parallel — `ZERO`
                // is the unreachable fallback for a broken-set
                // invariant, and an evidence record naming it
                // simply fails module verification ("no consensus
                // key on record") rather than accusing the wrong
                // account.
                let offender = self
                    .validator_set
                    .validator_addresses()
                    .get(idx)
                    .copied()
                    .unwrap_or(primitives::Address::ZERO);
                self.evidence_out.push_back(types::DoubleSignEvidence {
                    validator: offender,
                    view: vote.view,
                    phase: vote.phase,
                    epoch: self.epoch,
                    first_block_hash: *seen_hash,
                    first_signature: *seen_sig,
                    second_block_hash: vote.block_hash,
                    second_signature: vote.signature,
                });
            } else {
                self.evidence_dropped = self.evidence_dropped.saturating_add(1);
            }
            return (Ok(()), None);
        }
        // Otherwise: no entry, a stale one from a prior view, or a
        // re-delivered copy of the recorded vote — all fall through
        // to the collection slot, which is idempotent. The insert
        // happens at the storage point below so only votes that
        // clear admissibility anchor the history.
        // Already collected — idempotent (not an error, just a no-op).
        if self.votes[idx].is_some() {
            return (Ok(()), None);
        }

        // C1 fix: verify the vote's BLS signature against the voter's
        // public key. The signed message binds (view, phase,
        // block_hash, epoch) to prevent replay across phases or
        // epochs (C3 fix).
        //
        // HIGH perf fix: when `verify_per_vote` is `false` (the
        // default), we skip per-vote verification and rely on the
        // aggregate verification in `deliver_qc`. The aggregate
        // verification catches any forged votes — a forged vote
        // included in the QC causes the QC's aggregate to fail,
        // rejecting the QC. We still verify the voter is in the
        // validator set (structural check below) and the vote is for
        // the current view (C2 fix above) regardless of this flag.
        if self.verify_signatures && self.verify_per_vote {
            let Some(pk) = self.validator_set.validator(voter).ok() else {
                return (Err(ConsensusError::InvalidVoteSignature { voter }), None);
            };
            let phase_byte = vote.phase as u8;
            let msg = self.vote_signing_message(vote.view, phase_byte, &vote.block_hash);
            if crypto::verify(&vote.signature, crypto::hash::Domain::Vote, &msg, pk).is_err() {
                return (Err(ConsensusError::InvalidVoteSignature { voter }), None);
            }
        }

        // Phantom-block guard: the first buffered vote fixes the
        // (view, block_hash) reference every later vote is checked
        // against below. If that first vote could name a block this
        // node never stored, a single byzantine vote arriving before
        // the leader's self-vote would anchor the quorum to garbage
        // and `ConflictingVote` every honest vote — a one-message
        // liveness DoS on the view, the same class as the future-view
        // poison above. A QC we emit is only useful if it certifies a
        // block we can actually serve to the commit walk, so a vote
        // for an unknown (or stale-view) block is dropped, not
        // anchored. Once a reference exists, the conflict check
        // arbitrates every later vote — including votes for unknown
        // hashes, which still surface as `ConflictingVote`.
        if self.vote_count == 0 {
            let stored_for_view = self
                .blocks
                .get(&vote.block_hash)
                .is_some_and(|(stored_header, _)| stored_header.view == vote.view);
            if !stored_for_view {
                return (Ok(()), None);
            }
        }

        // Hardening: check that this vote agrees with the first vote
        // collected for this view. All votes in a QC must be for the
        // same (view, block_hash) — otherwise the QC does not
        // represent agreement on a single block.
        if let Some(first) = self.votes.iter().find_map(Option::as_ref)
            && (first.view != vote.view || first.block_hash != vote.block_hash)
        {
            return (
                Err(ConsensusError::ConflictingVote {
                    voter,
                    view: vote.view,
                    expected_block: first.block_hash,
                    actual_block: vote.block_hash,
                }),
                None,
            );
        }

        // Harvest-eligible attestations return as verify material
        // — the caller runs the BLS pairing (inline via
        // `collect_vote`, pooled via `collect_vote_pooled`) and
        // applies the verdict through `apply_verified_attestation`.
        // Only signature-verified attestations ever count: a forged
        // attestation that slipped into an aggregate would make the
        // resulting cert fail verification at proposal time,
        // letting one byzantine voter poison a whole block's
        // embedded cert. The vote itself is unaffected either way:
        // attestations ride along as best-effort signals and are
        // dropped individually when invalid.
        let attest = if self.verify_signatures
            && let (Some(att), Some(sig)) = (&vote.attestation, &vote.attestation_sig)
            // Skip emitting a job when a cert already exists for
            // this height — the same redundancy gate the inline
            // path applied before paying the pairing.
            && !self.exec_certs.contains_key(&att.height.value())
            && let Ok(pk) = self.validator_set.validator(voter)
        {
            Some(AttestVerifyTask {
                voter,
                attestation: *att,
                signature: *sig,
                pk: *pk,
                msg: self.attestation_signing_message(att.height, &att.root),
            })
        } else {
            None
        };

        // The vote cleared every admissibility gate — record it as
        // the voter's position at `(view, phase)` for equivocation
        // detection. Unlike the QC buffer (`votes`), this history
        // survives QC formation and view-scoped clears, so an
        // equivocating pair straddling a buffer clear is still
        // caught; the `seen_view` tag makes entries from prior
        // views inert rather than blocking.
        self.vote_history.insert((voter, vote.phase), (vote.view, vote.block_hash, vote.signature));
        self.votes[idx] = Some(vote);
        self.vote_count += 1;
        // `voter` is in-range (checked against `votes.len()` above),
        // so the stake lookup cannot fail.
        self.vote_stake =
            self.vote_stake.saturating_add(self.validator_set.stake(voter).unwrap_or(0));
        (Ok(()), attest)
    }

    /// Whether `aggregate` verifies against the public keys of the
    /// validators whose votes are currently buffered, over the buffered
    /// vote message.
    ///
    /// All buffered votes are for one `(view, phase, block_hash)` — the
    /// `ConflictingVote` rule in `collect_vote` guarantees it — so a
    /// single message reconstructs what the aggregate must cover.
    pub(crate) fn buffered_aggregate_verifies(&self, aggregate: &AggregateSignature) -> bool {
        let Some(first) = self.votes.iter().find_map(Option::as_ref) else {
            return false;
        };
        let mut signer_pks: Vec<crypto::bls::PublicKey> = Vec::with_capacity(self.votes.len());
        for (i, vote) in self.votes.iter().enumerate() {
            if vote.is_none() {
                continue;
            }
            let Ok(voter) = u16::try_from(i) else {
                return false;
            };
            let Ok(pk) = self.validator_set.validator(voter) else {
                return false;
            };
            signer_pks.push(*pk);
        }
        if signer_pks.is_empty() {
            return false;
        }
        let msg = self.vote_signing_message(first.view, first.phase as u8, &first.block_hash);
        crypto::aggregate_verify(aggregate, crypto::hash::Domain::Vote, &msg, &signer_pks).is_ok()
    }

    /// Aggregate the buffered votes and prove the result verifies
    /// against its signers *before* it can be broadcast.
    ///
    /// `collect_vote` stores the first vote per validator **without**
    /// verifying it: per-vote BLS verification costs ~1 ms, so at n
    /// validators it would dominate the view budget (the documented
    /// reason `verify_per_vote` defaults off). Delegating the check to
    /// receivers is not equivalent, though. A QC whose aggregate fails
    /// verification is rejected by every peer, so the view stalls until
    /// its timeout — and because the offending vote stays buffered, the
    /// same forged vote poisons every retry. One Byzantine participant
    /// gets one permanently stalled view: a liveness `DoS`, not a safety
    /// break, but a cheap and total one.
    ///
    /// So the leader verifies its own aggregate here — one pairing check
    /// per QC rather than per vote — and on failure takes a quarantine
    /// pass: each buffered vote is verified individually (a slow path
    /// reached only when something is already wrong), invalid
    /// contributions are dropped from both the buffer and the stake
    /// accounting, and the aggregate is rebuilt. Honest votes are never
    /// discarded, so a faulty participant cannot stall the view.
    ///
    /// Returns `None` when no honest quorum remains — the caller must
    /// not emit a QC it cannot prove.
    pub(crate) fn aggregate_collected_votes(&mut self) -> Option<AggregateSignature> {
        let sigs: Vec<Signature> =
            self.votes.iter().filter_map(|v| v.as_ref().map(|v| v.signature)).collect();
        let aggregate = crypto::aggregate(&sigs).ok()?;
        // Conformance mode has no real keys, and per-vote mode already
        // screened every contribution at collect time.
        if !self.verify_signatures || self.verify_per_vote {
            return Some(aggregate);
        }
        if self.buffered_aggregate_verifies(&aggregate) {
            return Some(aggregate);
        }

        // Quarantine pass: drop the invalid contributions, keep the rest.
        let mut dropped = false;
        for idx in 0..self.votes.len() {
            let Some(vote) = self.votes[idx].as_ref() else {
                continue;
            };
            let msg = self.vote_signing_message(vote.view, vote.phase as u8, &vote.block_hash);
            let Ok(voter) = u16::try_from(idx) else {
                continue;
            };
            let valid = self.validator_set.validator(voter).is_ok_and(|pk| {
                crypto::verify(&vote.signature, crypto::hash::Domain::Vote, &msg, pk).is_ok()
            });
            if !valid {
                let stake = self.validator_set.stake(voter).unwrap_or(0);
                self.vote_stake = self.vote_stake.saturating_sub(stake);
                self.vote_count = self.vote_count.saturating_sub(1);
                self.votes[idx] = None;
                dropped = true;
            }
        }
        // Nothing was individually invalid, yet the aggregate failed:
        // the aggregate bytes themselves are malformed. Emitting it
        // would be pointless — no receiver could verify it.
        if !dropped {
            return None;
        }
        if self.vote_stake < self.validator_set.quorum_stake() {
            return None; // quarantining the bad votes cost us the quorum
        }
        let sigs: Vec<Signature> =
            self.votes.iter().filter_map(|v| v.as_ref().map(|v| v.signature)).collect();
        crypto::aggregate(&sigs).ok()
    }

    /// Leader: try to form a QC from collected votes. Returns the QC
    /// if quorum (>2/3 of voting power) is reached, `None` otherwise.
    ///
    /// After forming a QC, the vote buffer is cleared for the next
    /// view.
    pub fn try_form_qc(&mut self) -> Option<QuorumCertificate> {
        if self.vote_stake < self.validator_set.quorum_stake() {
            return None;
        }

        // Form the QC from the first valid vote (all votes are for
        // the same block in the happy path).
        let first_vote = self.votes.iter().find_map(Option::clone)?;

        // Stage 5: aggregate the collected signatures via blst.
        // If no signer is set (conformance mode), use ZERO.
        // H6 fix: propagate aggregation errors instead of silently
        // replacing with ZERO (which would produce an invalid QC).
        let aggregate_signature = if self.signer.is_some() {
            self.aggregate_collected_votes()?
        } else {
            AggregateSignature::ZERO
        };

        // Build the signer bitmap AFTER aggregation: the quarantine
        // pass inside `aggregate_collected_votes` may have dropped
        // invalid votes, and the bitmap must describe exactly the
        // signers whose signatures the aggregate covers — a stale bit
        // would make the QC unverifiable at every receiver.
        let bitmap_len = self.validator_set.n().div_ceil(8);
        let mut signer_bitmap = vec![0u8; bitmap_len];
        for (i, v) in self.votes.iter().enumerate() {
            if v.is_some() {
                signer_bitmap[i / 8] |= 1u8 << (i % 8);
            }
        }

        let qc = QuorumCertificate {
            view: first_vote.view,
            phase: first_vote.phase,
            block_hash: first_vote.block_hash,
            epoch: self.epoch,
            signer_bitmap,
            aggregate_signature,
        };

        // `aggregate_collected_votes` proved the aggregate over the
        // buffered signers (quarantining any bad vote) and only
        // returns when an honest quorum remains, so the leader's own
        // `deliver_qc` of this QC need not pair again (hft-audit-2
        // N-4). Conformance mode memoizes nothing.
        if self.signer.is_some() {
            self.memo_verified_qc(&qc);
        }

        // Clear the vote buffer for the next view.
        self.votes.fill(None);
        self.vote_count = 0;
        self.vote_stake = 0;

        Some(qc)
    }
}
