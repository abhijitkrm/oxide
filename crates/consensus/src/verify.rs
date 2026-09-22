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
pub(crate) fn verify_exec_cert(
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
    let (signer_pks, voting_power) = signer_keys_and_power(vset, &cert.signer_bitmap)?;
    if voting_power < vset.quorum_stake() {
        return Err(ConsensusError::InsufficientQuorum {
            voting_power,
            required: vset.quorum_stake(),
        });
    }
    let msg = attestation_signing_message(epoch, cert.height, &cert.state_root);
    crypto::aggregate_verify(
        &cert.aggregate_signature,
        crypto::hash::Domain::ExecAttest,
        &msg,
        &signer_pks,
    )
    .map_err(|_| ConsensusError::InvalidQcSignature)
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
) -> Result<(), ConsensusError> {
    // Resolve the bitmap into signer keys + voting power.
    let (signer_pks, voting_power) = signer_keys_and_power(vset, &qc.signer_bitmap)?;
    if signer_pks.is_empty() {
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
    crypto::aggregate_verify(&qc.aggregate_signature, crypto::hash::Domain::Vote, &msg, &signer_pks)
        .map_err(|_| ConsensusError::InvalidQcSignature)
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
    vset: &ValidatorSet,
    verify_signatures: bool,
    voter: ValidatorIndex,
    view: View,
    epoch: Epoch,
    signature: &Signature,
) -> Result<(), ConsensusError> {
    // Conformance mode carries no real keys, so there is nothing to
    // authenticate (the same precedent as every other check gated on
    // `verify_signatures`).
    if !verify_signatures {
        return Ok(());
    }
    let pk = vset.validator(voter).map_err(|_| ConsensusError::SignerOutOfBounds)?;
    let mut msg = Vec::with_capacity(16);
    msg.extend_from_slice(&view.value().to_le_bytes());
    msg.extend_from_slice(&epoch.value().to_le_bytes());
    crypto::bls_signer::verify(signature, crypto::hash::Domain::Timeout, &msg, pk)
        .map_err(|_| ConsensusError::InvalidVoteSignature { voter })
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
pub(crate) fn verify_tc_signature(
    vset: &ValidatorSet,
    tc: &TimeoutCertificate,
) -> Result<(), ConsensusError> {
    let (signer_pks, voting_power) = signer_keys_and_power(vset, &tc.signer_bitmap)?;
    if signer_pks.is_empty() {
        return Err(ConsensusError::InvalidTcSignature);
    }
    // Same defense-in-depth as `verify_qc_signature`: a TC is
    // only a certificate at quorum (voting power), enforced here
    // too so no call site can accept a validly-signed sub-quorum
    // bitmap.
    let required = vset.quorum_stake();
    if voting_power < required {
        return Err(ConsensusError::InsufficientQuorum { voting_power, required });
    }
    // M1 fix: verify against (view, epoch), not just view.
    let mut msg = Vec::with_capacity(16);
    msg.extend_from_slice(&tc.view.value().to_le_bytes());
    msg.extend_from_slice(&tc.epoch.value().to_le_bytes());
    crypto::aggregate_verify(
        &tc.aggregate_signature,
        crypto::hash::Domain::Timeout,
        &msg,
        &signer_pks,
    )
    .map_err(|_| ConsensusError::InvalidTcSignature)
}
