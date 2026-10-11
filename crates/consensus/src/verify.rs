//! Certificate and vote signature verification — the pure
//! half of the engine's authentication surface.
//!
//! Split from `engine.rs` around the invariant every function here
//! shares: a certificate proves something only if its signer bitmap
//! resolves to **quorum voting power** under the *current* epoch's
//! validator set AND the BLS aggregate verifies over the full
//! domain-separated message. Bitmap resolution, quorum checks, and
//! message construction live in this one module so every call site
//! — `deliver_qc`, the embedded-justify check, the pacemaker's TC
//! path, the exec-cert gate — enforces the same rules.
//!
//! The functions are free (not `impl` methods) because they are
//! pure: each takes the `ValidatorSet`/`Epoch` it verifies against
//! as explicit parameters rather than reaching into engine state —
//! a verification that cannot see mutable engine fields cannot be
//! influenced by them.

use crypto::bls::Signature;
use primitives::{Epoch, Hash, Height, View};
use types::{ExecCertificate, QuorumCertificate, TimeoutCertificate};

use crate::engine::ConsensusError;
use crate::validator::{ValidatorIndex, ValidatorSet};

/// A [`QuorumCertificate`] that has cleared quorum-stake + aggregate
/// signature verification against a known [`ValidatorSet`] — or was
/// loaded from the node's own durable state, which was written only
/// after verification.
///
/// This is the certificate analogue of
/// [`crypto::bls_signer::ValidatedPublicKey`]: the *value* proves its
/// admission check ran, so engine state that anchors consensus safety
/// (`high_qc`, the commit chain's certificate references) cannot hold
/// a certificate that merely *looks* structured — it either passed
/// `verify_qc_signature` or came back from our own WAL/snapshot via
/// [`VerifiedQc::from_trusted`]. Wire and stored types keep the bare
/// `QuorumCertificate`: headers carry unverified claims until
/// admitted, and a certificate embedded in a stored block was
/// verified before it was stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedQc {
    qc: QuorumCertificate,
}

impl VerifiedQc {
    /// The verified certificate, for embedding in wire types
    /// (proposal `high_qc` fields, timeout evidence claims) — the
    /// token authenticates *this node's* adoption; a peer must
    /// verify the bytes itself.
    pub(crate) fn qc(&self) -> &QuorumCertificate {
        &self.qc
    }

    /// The view the certificate certifies.
    pub(crate) fn view(&self) -> View {
        self.qc.view
    }

    /// The block the certificate certifies.
    pub(crate) fn block_hash(&self) -> Hash {
        self.qc.block_hash
    }

    /// Wrap a certificate the caller guarantees was already verified.
    ///
    /// Trusted interiors only: own-WAL/`save_state` decode (that
    /// state was written post-verification — the same trust basis as
    /// `voted_at_height` and `timeout_signed_view`, which decode
    /// unverified because a node that cannot trust its own disk
    /// cannot operate at all), conformance-mode mints where
    /// signature checks are deliberately compiled out, and TC
    /// evidence claims that `verify_tc_signature` already screened.
    /// Never use this on a value arriving from the network or a
    /// module — those mint through `verify_qc_signature`.
    pub(crate) fn from_trusted(qc: QuorumCertificate) -> Self {
        Self { qc }
    }
}

/// A [`TimeoutCertificate`] that cleared per-signer record
/// verification: distinct in-bounds voters, quorum stake, each
/// timeout signature verified over its own `(view, epoch, qc_high)`
/// claim, and each carried QC itself quorum+signature checked.
///
/// Same role as [`VerifiedQc`] for the view-change seam: `last_tc`
/// is the evidence a proposal re-embeds, and `valid_entry_tc`
/// returns the token so the vote path's floor check cannot
/// accidentally read an *unverified* TC's evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedTc {
    tc: TimeoutCertificate,
}

impl VerifiedTc {
    /// The verified certificate, for embedding into the next
    /// proposal's `timeout_cert` field.
    pub(crate) fn tc(&self) -> &TimeoutCertificate {
        &self.tc
    }

    /// The timed-out view the certificate covers.
    #[cfg(test)]
    pub(crate) fn view(&self) -> View {
        self.tc.view
    }

    /// The highest-view `qc_high` evidence any signer reported —
    /// already quorum+signature screened per claim during
    /// verification, so the floor derived from it is sound.
    pub(crate) fn max_evidence(&self) -> Option<&QuorumCertificate> {
        self.tc.signers.iter().filter_map(|s| s.high_qc.as_ref()).max_by_key(|qc| qc.view.value())
    }

    /// Wrap a certificate the caller guarantees was already
    /// verified — the verify-pool mirror of
    /// [`VerifiedQc::from_trusted`]. A pooled verdict asserts the
    /// per-record signatures and carried QCs verified under the
    /// committee the pump resolved at intake; the *structural*
    /// half (`check_tc_structure`) still runs on the live engine
    /// before this is minted, so the token is only ever built over
    /// a certificate that passed both halves.
    pub(crate) fn from_trusted(tc: TimeoutCertificate) -> Self {
        Self { tc }
    }
}

/// Resolve a certificate's signer bitmap into the signers' public
/// keys plus their combined voting power.
///
/// Quorum is a stake threshold (oxideBFT spec §3), so every
/// certificate check needs both halves: the keys for aggregate
/// signature verification and the summed stake for the
/// `> 2/3 of total` power check. Returning them together keeps
/// the two readings of one bitmap from drifting apart across the
/// QC/TC/exec-cert call sites.
///
/// # Errors
/// [`ConsensusError::SignerOutOfBounds`] if a set bit references
/// a validator past the end of the set — an out-of-range bit must
/// neither pass verification nor contribute phantom stake.
pub(crate) fn signer_keys_and_power(
    vset: &ValidatorSet,
    bitmap: &[u8],
) -> Result<(Vec<crypto::bls::PublicKey>, u64), ConsensusError> {
    let mut signer_pks: Vec<crypto::bls::PublicKey> = Vec::with_capacity(vset.n());
    let mut voting_power = 0u64;
    for (i, byte) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                let idx =
                    u16::try_from(i * 8 + bit).map_err(|_| ConsensusError::SignerOutOfBounds)?;
                let pk = vset.validator(idx).map_err(|_| ConsensusError::SignerOutOfBounds)?;
                voting_power = voting_power.saturating_add(
                    vset.stake(idx).map_err(|_| ConsensusError::SignerOutOfBounds)?,
                );
                signer_pks.push(*pk);
            }
        }
    }
    Ok((signer_pks, voting_power))
}

/// [`signer_keys_and_power`] over the set's pre-decompressed keys
/// (hft-audit-2 S-9): no key copies and no per-verify decompression.
/// An entry is `None` when that signer's key does not decode; callers
/// treat any `None` as a failed signature check *after* the quorum
/// check, the order `aggregate_verify`'s decode failure produced.
///
/// # Errors
/// [`ConsensusError::SignerOutOfBounds`], as [`signer_keys_and_power`].
pub(crate) fn signer_prepared_and_power<'a>(
    vset: &'a ValidatorSet,
    bitmap: &[u8],
) -> Result<(Vec<Option<&'a crypto::PreparedPublicKey>>, u64), ConsensusError> {
    let mut keys = Vec::with_capacity(vset.n());
    let mut voting_power = 0u64;
    for (i, byte) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if (byte >> bit) & 1 == 1 {
                let idx =
                    u16::try_from(i * 8 + bit).map_err(|_| ConsensusError::SignerOutOfBounds)?;
                // Bounds via `validator`, like the unprepared walk.
                vset.validator(idx).map_err(|_| ConsensusError::SignerOutOfBounds)?;
                voting_power = voting_power.saturating_add(
                    vset.stake(idx).map_err(|_| ConsensusError::SignerOutOfBounds)?,
                );
                keys.push(vset.prepared_key(usize::from(idx)));
            }
        }
    }
    Ok((keys, voting_power))
}

/// Aggregate-verify over prepared signer keys; `false` if any key
/// failed to decode or the list is empty.
pub(crate) fn prepared_aggregate_verifies(
    agg: &crypto::bls::AggregateSignature,
    domain: crypto::hash::Domain,
    msg: &[u8],
    keys: &[Option<&crypto::PreparedPublicKey>],
) -> bool {
    !keys.is_empty()
        && keys.iter().all(Option::is_some)
        && crypto::aggregate_verify_prepared(agg, domain, msg, keys.iter().flatten().copied())
            .is_ok()
}

/// Voting power behind a certificate bitmap, checked against the
/// stake quorum. A convenience for structural (pre-signature)
/// checks that need the power without the keys — equivalent to
/// [`signer_keys_and_power`](signer_keys_and_power) minus
/// the allocation.
pub(crate) fn bitmap_meets_quorum(vset: &ValidatorSet, bitmap: &[u8]) -> bool {
    vset.signer_stake(bitmap) >= vset.quorum_stake()
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
pub fn vote_signing_message(
    epoch: Epoch,
    view: View,
    phase_byte: u8,
    block_hash: &Hash,
) -> [u8; 49] {
    let mut msg = [0u8; 49];
    msg[..8].copy_from_slice(&view.value().to_le_bytes());
    msg[8] = phase_byte;
    msg[9..41].copy_from_slice(block_hash.as_bytes());
    msg[41..49].copy_from_slice(&epoch.value().to_le_bytes());
    msg
}

/// The message a validator signs for an execution attestation:
/// `(height, state_root, epoch)` — 48 bytes. The epoch binding
/// prevents attestation replay across epoch boundaries (same
/// defense as the vote signing message, C3).
pub(crate) fn attestation_signing_message(epoch: Epoch, height: Height, root: &Hash) -> [u8; 48] {
    let mut msg = [0u8; 48];
    msg[..8].copy_from_slice(&height.value().to_le_bytes());
    msg[8..40].copy_from_slice(root.as_bytes());
    msg[40..48].copy_from_slice(&epoch.value().to_le_bytes());
    msg
}

/// Verify an [`ExecCertificate`]'s aggregate signature against
/// the validator set — the same pattern as
/// [`verify_qc_signature`]: the bitmap
/// names the signers, `aggregate_verify` checks the BLS
/// aggregate over `(height, state_root, epoch)` under
/// `Domain::ExecAttest`.
///
/// Public so state-sync clients (e.g. `oxide-fullnode
/// --state-sync`) can verify a served certificate against a
/// weak-subjectivity validator-set checkpoint: the caller supplies
/// the epoch whose set it trusts — `epoch` must equal
/// `cert.epoch`, so a checkpoint for the wrong epoch fails here
/// rather than silently indexing the wrong signer bitmap.
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
pub fn verify_exec_cert(
    vset: &ValidatorSet,
    epoch: Epoch,
    cert: &ExecCertificate,
) -> Result<(), ConsensusError> {
    // The certificate's epoch must equal this engine's epoch:
    // the signed message binds `(height, root, epoch)` and the
    // bitmap indexes the *current* validator set — a cert from
    // any other epoch is unverifiable here (its signers index a
    // different set and its signatures commit to a different
    // epoch), not merely stale. Checked before the bitmap walk
    // so an out-of-epoch bitmap can never index the wrong set.
    if cert.epoch != epoch {
        return Err(ConsensusError::CertEpochMismatch { cert_epoch: cert.epoch, epoch });
    }
    let (signer_keys, voting_power) = signer_prepared_and_power(vset, &cert.signer_bitmap)?;
    if voting_power < vset.quorum_stake() {
        return Err(ConsensusError::InsufficientQuorum {
            voting_power,
            required: vset.quorum_stake(),
        });
    }
    let msg = attestation_signing_message(epoch, cert.height, &cert.state_root);
    if prepared_aggregate_verifies(
        &cert.aggregate_signature,
        crypto::hash::Domain::ExecAttest,
        &msg,
        &signer_keys,
    ) {
        Ok(())
    } else {
        Err(ConsensusError::InvalidQcSignature)
    }
}

/// Verify a QC's aggregate signature against the signer bitmap
/// and the validator set's public keys.
///
/// Extracts the public keys of the signers from the bitmap, then
/// calls `crypto::aggregate_verify` with the QC's aggregate
/// signature, the block hash as the message, and `Domain::Vote`.
///
/// The quorum threshold is enforced both by callers
/// ([`deliver_qc`](Self::deliver_qc), the embedded-justify check —
/// which must hold even when `verify_signatures` is off) and again
/// here, so this function alone is a complete certificate
/// validator for any call site.
///
/// # Errors
/// Returns [`ConsensusError::SignerOutOfBounds`] if the bitmap
/// references a validator past the end of the set,
/// [`ConsensusError::InsufficientQuorum`] if the signers' voting
/// power is below the stake quorum, or
/// [`ConsensusError::InvalidQcSignature`] if the aggregate does
/// not verify.
pub(crate) fn verify_qc_signature(
    vset: &ValidatorSet,
    epoch: Epoch,
    qc: &QuorumCertificate,
) -> Result<VerifiedQc, ConsensusError> {
    // Resolve the bitmap into signer keys + voting power.
    let (signer_keys, voting_power) = signer_prepared_and_power(vset, &qc.signer_bitmap)?;
    if signer_keys.is_empty() {
        return Err(ConsensusError::InvalidQcSignature);
    }
    // A certificate is only a certificate at quorum. Callers
    // (deliver_qc, the embedded-justify check) enforce this too,
    // but the check lives here as well so no future call site can
    // accept a validly-signed but sub-quorum bitmap — a single
    // signer's aggregate verifies fine yet proves nothing. The
    // threshold is voting power: enough low-stake signers to
    // outnumber the honest set still cannot form a QC.
    let required = vset.quorum_stake();
    if voting_power < required {
        return Err(ConsensusError::InsufficientQuorum { voting_power, required });
    }
    // C3 fix: verify against the full (view, phase, block_hash,
    // epoch) message, not just the block hash.
    let msg = vote_signing_message(epoch, qc.view, qc.phase as u8, &qc.block_hash);
    if !prepared_aggregate_verifies(
        &qc.aggregate_signature,
        crypto::hash::Domain::Vote,
        &msg,
        &signer_keys,
    ) {
        return Err(ConsensusError::InvalidQcSignature);
    }
    Ok(VerifiedQc { qc: qc.clone() })
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
/// The message a validator signs when its pacemaker timer fires:
/// `(view, epoch, has_qc, qc_high_view, qc_high_hash)` — 57 bytes.
///
/// Binding the signer's `qc_high` into the signature is the Jolteon
/// view-change mechanism (arXiv:2106.10362 §3): a TC built from these
/// signatures carries, for every signer, *exactly* the evidence it
/// reported — an aggregator cannot weaken it (the claim is signed)
/// and cannot substitute another certificate for it. That is what
/// makes `prop_qc.view >= max(TC evidence)` a sound entry rule for
/// the next view: once a consecutive pair commits, every later TC's
/// quorum provably contains a locked voter reporting the committed
/// chain's QC.
///
/// `None` evidence encodes as `has_qc = 0, view = 0, hash = ZERO`.
/// The flag disambiguates "no QC held" from a QC at view 0 — a real
/// certificate's view is always meaningful.
pub(crate) fn timeout_signing_message(
    view: View,
    epoch: Epoch,
    high_qc: Option<&QuorumCertificate>,
) -> [u8; 57] {
    let mut msg = [0u8; 57];
    msg[..8].copy_from_slice(&view.value().to_le_bytes());
    msg[8..16].copy_from_slice(&epoch.value().to_le_bytes());
    if let Some(qc) = high_qc {
        msg[16] = 1;
        msg[17..25].copy_from_slice(&qc.view.value().to_le_bytes());
        msg[25..57].copy_from_slice(qc.block_hash.as_bytes());
    }
    msg
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
/// signature binds `(view, epoch)` plus the signer's claimed
/// `qc_high` under [`Domain::Timeout`] — `high_qc` must be the exact
/// certificate the sender attached, so a relay cannot swap in a
/// different (even valid) QC without breaking the signature.
///
/// # Errors
///
/// [`ConsensusError::SignerOutOfBounds`] if `voter` is past the end
/// of the set, or [`ConsensusError::InvalidVoteSignature`] if the
/// signature does not verify for this `(view, epoch, high_qc)`.
pub fn verify_timeout_signature_for(
    vset: &ValidatorSet,
    verify_signatures: bool,
    voter: ValidatorIndex,
    view: View,
    epoch: Epoch,
    high_qc: Option<&QuorumCertificate>,
    signature: &Signature,
) -> Result<(), ConsensusError> {
    // Conformance mode carries no real keys, so there is nothing to
    // authenticate (the same precedent as every other check gated on
    // `verify_signatures`).
    if !verify_signatures {
        return Ok(());
    }
    let pk = vset.validator(voter).map_err(|_| ConsensusError::SignerOutOfBounds)?;
    let msg = timeout_signing_message(view, epoch, high_qc);
    crypto::bls_signer::verify(signature, crypto::hash::Domain::Timeout, &msg, pk)
        .map_err(|_| ConsensusError::InvalidVoteSignature { voter })
}

/// Verify a TC's per-signer evidence records against the validator
/// set: every entry's signature must verify over its own claimed
/// `(view, epoch, high_qc)`, voters must be distinct and in bounds,
/// the combined stake must reach quorum, and every carried QC must
/// itself verify.
///
/// The per-signer shape (rather than one aggregate signature) is
/// forced by the evidence binding: each signer reports a potentially
/// different `qc_high`, and BLS same-message aggregation cannot
/// cover distinct payloads. The cost is `q` individual verifies per
/// TC — acceptable because TCs exist only on view changes, the rare
/// path by construction.
///
/// Structural checks that hold even in conformance mode
/// (`verify_signatures = false`): distinct in-bounds voters, quorum
/// stake, `qc_high.view <= tc.view` (a signer can hold a QC formed
/// in the view it times out on — it adopted the QC, then timed out
/// still at that view — but evidence from a *later* view is
/// unreachable: adopting it would have advanced the signer past
/// the view it claims to be timing out on), and each carried QC's
/// epoch matching the TC's.
///
/// # Errors
///
/// Returns [`ConsensusError::SignerOutOfBounds`] if an entry
/// references an out-of-bounds or duplicate validator,
/// [`ConsensusError::InsufficientQuorum`] if the signers' voting
/// power is below quorum, [`ConsensusError::InvalidTcSignature`] if
/// a signature does not verify or an entry is malformed, or
/// [`ConsensusError::InvalidQcSignature`] if a carried high-QC is
/// itself unverifiable.
pub(crate) fn verify_tc_signature(
    vset: &ValidatorSet,
    verify_signatures: bool,
    tc: &TimeoutCertificate,
) -> Result<VerifiedTc, ConsensusError> {
    check_tc_structure(vset, tc)?;
    if verify_signatures {
        // Carried QCs are deduplicated for verification: honest
        // quorum members overwhelmingly report the *same* high QC
        // (the chain's tip), so the common case verifies one
        // certificate regardless of signer count.
        let mut verified_qcs: std::collections::HashSet<(u64, Hash)> =
            std::collections::HashSet::new();
        for entry in &tc.signers {
            if let Some(qc) = &entry.high_qc
                && verified_qcs.insert((qc.view.value(), qc.block_hash))
            {
                verify_qc_signature(vset, tc.epoch, qc)?;
            }
            // Voter bounds were asserted by `check_tc_structure`;
            // a failure here would mean the set changed under us,
            // which a `&ValidatorSet` borrow rules out — but there
            // is no `unwrap` on the wire path, so map to the same
            // malformed-certificate error.
            let pk = vset.validator(entry.voter).map_err(|_| ConsensusError::InvalidTcSignature)?;
            let msg = timeout_signing_message(tc.view, tc.epoch, entry.high_qc.as_ref());
            crypto::bls_signer::verify(&entry.signature, crypto::hash::Domain::Timeout, &msg, pk)
                .map_err(|_| ConsensusError::InvalidTcSignature)?;
        }
    }
    Ok(VerifiedTc { tc: tc.clone() })
}

/// The non-cryptographic half of [`verify_tc_signature`] — every
/// check that reads only the certificate's structure and the
/// validator set's roster: non-empty records, distinct in-bounds
/// voters, each carried QC's `(view <= tc.view, epoch == tc.epoch)`
/// bound, and quorum voting power.
///
/// Split out so the engine's verify-pool apply path
/// (`on_timeout_certificate_preverified`) can re-run exactly these
/// checks against *live* state while the signatures were verified
/// off-thread — structure is a function of the committee the engine
/// holds *now*, which a pooled job can never see.
///
/// # Errors
///
/// Returns [`ConsensusError::InvalidTcSignature`] if `tc` has no
/// signers, a duplicate voter, or a carried QC from a later view or
/// a different epoch; [`ConsensusError::SignerOutOfBounds`] if a
/// voter index is out of range; or
/// [`ConsensusError::InsufficientQuorum`] if the combined voting
/// power is below quorum.
pub(crate) fn check_tc_structure(
    vset: &ValidatorSet,
    tc: &TimeoutCertificate,
) -> Result<(), ConsensusError> {
    if tc.signers.is_empty() {
        return Err(ConsensusError::InvalidTcSignature);
    }
    let mut seen = std::collections::HashSet::with_capacity(tc.signers.len());
    let mut voting_power = 0u64;
    for entry in &tc.signers {
        if !seen.insert(entry.voter) {
            return Err(ConsensusError::InvalidTcSignature);
        }
        vset.validator(entry.voter).map_err(|_| ConsensusError::SignerOutOfBounds)?;
        voting_power = voting_power.saturating_add(
            vset.stake(entry.voter).map_err(|_| ConsensusError::SignerOutOfBounds)?,
        );
        if let Some(qc) = &entry.high_qc {
            // Evidence from a view *after* the timed-out view is
            // impossible honestly — adopting it would have advanced
            // the signer past this view — so it marks a malformed
            // record. A QC from the timed-out view itself is legal:
            // the signer adopted it mid-view, then timed out.
            if qc.view.value() > tc.view.value() || qc.epoch != tc.epoch {
                return Err(ConsensusError::InvalidTcSignature);
            }
        }
    }
    let required = vset.quorum_stake();
    if voting_power < required {
        return Err(ConsensusError::InsufficientQuorum { voting_power, required });
    }
    Ok(())
}

/// The pure crypto inputs for verifying a [`QuorumCertificate`]
/// under one candidate committee — resolved pump-side from live
/// engine state via [`OxideBft::qc_verify_context`], verified by
/// the node's signature pool off the consensus thread.
///
/// A material carries no engine state: the bitmap has already been
/// resolved to keys and summed stake, and the signing message is
/// prebuilt. Verifying it is a pure function — exactly what a
/// bounded worker can run without any access to engine internals.
///
/// [`OxideBft::qc_verify_context`]: crate::engine::OxideBft::qc_verify_context
#[derive(Debug)]
pub struct QcVerifyMaterial {
    /// Bitmap-resolved signer keys under this candidate committee.
    pub signer_pks: Vec<crypto::bls::PublicKey>,
    /// The signers' combined voting power under this candidate —
    /// checked against `required_power` as part of the verdict.
    pub voting_power: u64,
    /// The stake quorum under this candidate committee.
    pub required_power: u64,
    /// `vote_signing_message(qc.epoch, qc.view, qc.phase,
    /// qc.block_hash)` — the exact 49-byte payload
    /// `verify_qc_signature` checks the aggregate against.
    pub msg: [u8; 49],
    /// Whether this candidate was resolved from the staged
    /// `next_validator_set` — the certified-epoch-adoption case
    /// `deliver_qc` tries second. `false` for the live committee.
    pub pending_set: bool,
}

/// Which candidate committee a pooled QC verification proved — the
/// verdict half of [`QcVerifyMaterial`], reported back to the pump
/// for `deliver_qc_preverified` to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QcVerdict {
    /// The aggregate verified under the live committee's material.
    Current,
    /// The aggregate verified only under the staged next committee
    /// — the epoch-adoption candidate. Only meaningful for a QC
    /// claiming an epoch beyond the engine's (the pending material
    /// is resolved in that case alone); `deliver_qc_preverified`
    /// rejects it otherwise.
    Pending,
    /// No candidate's material verified — bitmap unresolved,
    /// sub-quorum stake, or a bad aggregate. Equivalent to
    /// `deliver_qc`'s signature-failure rejection.
    Invalid,
}

/// The pure crypto inputs for verifying a [`TimeoutCertificate`]'s
/// wire authentication — resolved by
/// [`OxideBft::tc_verify_context`], verified by the signature pool.
///
/// The evidence-binding shape forces per-record verification (each
/// signer signs its own `qc_high` claim, so BLS same-message
/// aggregation cannot apply), plus one [`QcVerifyMaterial`] per
/// *distinct* carried QC — deduplicated exactly the way
/// `verify_tc_signature` deduplicates them.
///
/// [`OxideBft::tc_verify_context`]: crate::engine::OxideBft::tc_verify_context
#[derive(Debug)]
pub struct TcVerifyMaterial {
    /// One `(key, signing message, signature)` triple per signer
    /// record — the key resolved under the live committee, the
    /// message bound to that record's own `qc_high` claim.
    pub records: Vec<(crypto::bls::PublicKey, [u8; 57], Signature)>,
    /// One `(certificate, material)` pair per distinct
    /// `(view, block_hash)` carried QC, all under the live
    /// committee (`pending_set` is always `false` — TC-carried QCs
    /// never epoch-adopt). The certificate travels with its
    /// material because `qc_material_verifies` needs the
    /// aggregate signature it verifies against.
    pub qcs: Vec<(QuorumCertificate, QcVerifyMaterial)>,
}

/// Resolve `qc`'s verification material under `set` — the bitmap's
/// signer keys + summed power, the quorum threshold, and the
/// signing message for `epoch`. `pending_set` marks which
/// committee `set` was (for the verdict's bookkeeping only).
///
/// `None` when the bitmap doesn't resolve under `set` (an
/// out-of-range bit) or resolves empty — the candidate simply
/// cannot verify and contributes no material.
pub(crate) fn qc_verify_material(
    set: &ValidatorSet,
    epoch: Epoch,
    qc: &QuorumCertificate,
    pending_set: bool,
) -> Option<QcVerifyMaterial> {
    let (signer_pks, voting_power) = signer_keys_and_power(set, &qc.signer_bitmap).ok()?;
    if signer_pks.is_empty() {
        return None;
    }
    Some(QcVerifyMaterial {
        signer_pks,
        voting_power,
        required_power: set.quorum_stake(),
        msg: vote_signing_message(epoch, qc.view, qc.phase as u8, &qc.block_hash),
        pending_set,
    })
}

/// Run the crypto half of `verify_qc_signature` against resolved
/// material — pure: no validator set, no engine state, safe to run
/// on a worker thread. `true` iff the signers' power reaches the
/// quorum threshold AND the aggregate signature verifies over the
/// material's message.
pub fn qc_material_verifies(material: &QcVerifyMaterial, qc: &QuorumCertificate) -> bool {
    material.voting_power >= material.required_power
        && crypto::aggregate_verify(
            &qc.aggregate_signature,
            crypto::hash::Domain::Vote,
            &material.msg,
            &material.signer_pks,
        )
        .is_ok()
}

/// Resolve the wire-authentication material of `tc` under `vset`:
/// each signer record's key + `(view, epoch, qc_high)` signing
/// message + signature, and one [`QcVerifyMaterial`] per distinct
/// carried QC. Mirrors the crypto half of `verify_tc_signature`
/// exactly — including the `(view, block_hash)` QC dedup — so a
/// pooled verdict over this material is the same pass/fail the
/// inline path would compute.
///
/// `None` when any voter index is out of bounds — the structural
/// pass reports `SignerOutOfBounds` for the same condition, so an
/// unresolvable record yields no material rather than a partial
/// job.
pub(crate) fn tc_verify_material(
    vset: &ValidatorSet,
    tc: &TimeoutCertificate,
) -> Option<TcVerifyMaterial> {
    let mut records = Vec::with_capacity(tc.signers.len());
    let mut qcs = Vec::new();
    let mut seen_qcs: std::collections::HashSet<(u64, Hash)> = std::collections::HashSet::new();
    for entry in &tc.signers {
        let pk = *vset.validator(entry.voter).ok()?;
        records.push((
            pk,
            timeout_signing_message(tc.view, tc.epoch, entry.high_qc.as_ref()),
            entry.signature,
        ));
        if let Some(qc) = &entry.high_qc
            && seen_qcs.insert((qc.view.value(), qc.block_hash))
        {
            qcs.push((qc.clone(), qc_verify_material(vset, tc.epoch, qc, false)?));
        }
    }
    Some(TcVerifyMaterial { records, qcs })
}
