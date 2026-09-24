//! The oxideBFT consensus engine — `ConsensusEngine` implementation
//! (docs/oxidebft-spec.md §6).
//!
//! # Phase 1 stage 4: 2-chain commit + view changes
//!
//! Stage 4 upgrades the commit rule from 1-chain to 2-chain and wires
//! in the pacemaker for view changes. The 2-chain rule preserves
//! safety under view changes: a block locked by a pre-commit QC
//! cannot be forked by a new leader.
//!
//! ## The 2-chain commit rule
//!
//! A block *B* is committed when:
//! 1. There is a QC over *B* (call it `QC_B`).
//! 2. There is a block *B'* that extends *B* (`B'.high_qc == QC_B`).
//! 3. There is a QC over *B'* (call it `QC_B'`).
//!
//! In the pipeline, this means each new QC commits the *previous*
//! certified block (the one whose QC the new block extends). The
//! "uncommitted certified tip" is derived on demand from `high_qc`
//! vs `last_committed` — no separate pointer is tracked, so the
//! answer can't go stale under message reorder (a QC that arrives
//! before its proposal body).
//!
//! ## Multi-validator support
//!
//! The engine exposes methods for both single-validator (conformance
//! suite) and multi-validator (simulation) modes:
//! - [`OxideBft::propose`] — leader proposes a block.
//! - [`OxideBft::vote`] — validator votes on a proposal.
//! - [`OxideBft::collect_vote`] — leader collects a vote.
//! - [`OxideBft::try_form_qc`] — leader forms a QC when quorum reached.
//! - [`OxideBft::deliver_qc`] — all validators receive a QC, check commit.
//! - [`OxideBft::on_timeout`] — validator times out.
//! - [`OxideBft::on_timeout_certificate`] — validator processes a TC.
//!
//! ## View changes
//!
//! When a validator's local timer expires, it produces a timeout
//! signature. When validators holding >2/3 of voting power timeout,
//! a TC forms and the view
//! advances. The new leader must extend the highest QC (tail-fork
//! resistance). The pacemaker (stage 2) drives the view advancement;
//! the engine wires it in here.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use codec::{Decode, Encode};
use crypto::bls::{AggregateSignature, Signature};
use crypto::hash::{Domain, Hasher};
use ports::{AppInterface, ConsensusEngine};
use primitives::{Address, Epoch, Hash, Height, View};
use types::{
    BlockHeader, CertifiedBlock, ExecCertificate, ExecDivergence, FinalizedBlock, MempoolAck,
    Proposal, QuorumCertificate, StateAttestation, TimeoutCertificate, TxBytes, Verdict, Vote,
    VotePhase,
};

use crate::validator::{ValidatorIndex, ValidatorSet};
use crate::verify::{VerifiedQc, VerifiedTc};

/// Convert a `ValidatorIndex` to a `Hash` for the proposer field.
/// The proposer is identified by the hash of its public key; stage 5
/// replaces this with the actual public key hash.
///
/// Public so network drivers can run the cheap intake gate — "is the
/// claimed `header.proposer` the scheduled leader for `header.view`?"
/// — before paying the signature verification inside `vote()`.
pub fn proposer_hash(idx: ValidatorIndex) -> Hash {
    let mut bytes = [0u8; 32];
    let idx_bytes = idx.to_le_bytes();
    bytes[0..2].copy_from_slice(&idx_bytes);
    Hash(bytes)
}

/// Maximum finalized blocks retained in the engine's in-memory map.
///
/// The `finalized` map exists for the commit path and recent-height
/// queries (`finalized_block`); full history is the journal's job.
/// 4096 heights ≈ 7 minutes of blocks at a 100 ms cadence — far
/// beyond any reorg-free query horizon, bounded so a long-lived
/// validator doesn't grow memory without limit.
const MAX_RETAINED_FINALIZED: usize = 4096;

/// How far behind the current view a wire proposal may lag and
/// still be admissible (unit: views) — see
/// [`OxideBft::proposal_admissible`].
///
/// Stale-view proposals are unvotable, but in-window ones are worth
/// authenticating for their bodies: the commit walk needs a QC'd
/// block's body when the QC arrived first. 10 matches the devnet
/// pump's historical retention prune. Raising it widens the junk
/// surface an authenticated-but-faulty peer can occupy; lowering it
/// shrinks the reorder horizon the commit walk can recover from.
pub const PROPOSAL_PAST_VIEWS: u64 = 10;

/// How far ahead of the current view a wire proposal may run and
/// still be admissible (unit: views).
///
/// A future-view proposal becomes votable the moment we reach that
/// view, so keeping it costs one pending slot — with the leader
/// check and per-`(view, proposer)` dedupe, a driver's pending
/// buffer is bounded by `PAST + FUTURE + 1` entries, each verified
/// at most once. 32 covers a validator resyncing through several
/// consecutive leader timeouts; raising it only enlarges that
/// worst case.
pub const PROPOSAL_FUTURE_VIEWS: u64 = 32;

/// Per-sender ceiling on *admissible* proposal frames accepted for
/// authentication per rolling second (unit: frames per
/// authenticated peer per second).
///
/// The cheap intake gates reject wrong-window and wrong-leader junk
/// for free, but every *distinct* admissible frame pays one BLS
/// proposer-signature verify (~1 ms) inside
/// [`OxideBft::admit_proposal`] — and a Byzantine committee member
/// can mint distinct forged headers at link rate. Bounding the rate
/// per *sender* (the handshake-authenticated peer id, so it cannot
/// be spoofed) means a flood exhausts only the flood's own budget:
/// the scheduled leader's proposal arrives on a different peer id
/// and always gets verified.
///
/// 50/s is far above honest rates — a leader proposes once per
/// ~2 s view, and even catch-up bursts are bounded by the
/// `PAST + FUTURE` window — while capping one flooding peer at ~5%
/// of a consensus thread. Legitimate bursts beyond the cap are
/// dropped and re-sent or superseded by later views.
pub const PROPOSAL_VERIFY_BUDGET_PER_SEC: u32 = 50;

/// Ceiling on memoised proposal rejections (`rejected_headers`).
///
/// Unit: entries (32-byte hashes, ~128 KiB at the cap). Origin: the
/// intake gates in the network drivers bound how many distinct junk
/// headers can reach `vote()`, but the engine does not rely on every
/// driver bounding correctly — this cap is the second line. Tradeoff
/// of changing it: raising it buys more memo coverage under a flood
/// of *distinct* well-formed junk (each entry saves one BLS verify +
/// shard-commitment encode per re-delivery); lowering it saves
/// memory. Eviction is wholesale clear: re-verifying a re-delivered
/// junk header is safe (the verdict is a pure function of its bytes)
/// and merely re-adds it, so the cost of a clear is bounded
/// re-verification, never a wrong verdict.
const MAX_REJECTED_HEADERS: usize = 4096;

/// Heights between a validator-set transition being committed and
/// its activation.
///
/// Unit: committed blocks. Origin: the validator-set-change audit
/// finding — membership must "activate at a certified future
/// height", and the activation gap is what gives the network layer
/// a window to admit incoming members' peer connections before they
/// carry quorum (the pending set is published to the transport
/// authenticator during it). The change itself is already certified
/// — the committing block's QC is the certificate — so the delay is
/// purely a join window, not a safety margin. Tradeoff: 2 heights is
/// one or two block periods — long enough for a pending member's
/// reconnect retry to land, short enough that a committee fix (e.g.
/// ejecting a dead validator) is not meaningfully delayed. Every
/// replica schedules the transition at the same commit height, so
/// the activation height is identical everywhere.
pub const ROTATION_ACTIVATION_DELAY: u64 = 2;

/// The crypto material a proposal's wire authentication needs —
/// resolved by [`OxideBft::proposal_verify_context`] against live
/// committee state at intake, verified by the node's signature
/// pool off the consensus thread.
///
/// Every field is a pure value: verifying it requires no access to
/// engine state, so a bounded worker can run the BLS pairing and
/// the shard-commitment encode without touching the single-writer
/// engine. The apply half (`admit_preverified`) re-runs all
/// state-dependent checks before storing.
#[derive(Debug)]
pub struct ProposalVerifyMaterial {
    /// The effective leader's BLS key for `header.view` — effective
    /// because the reputation schedule may skip excluded validators,
    /// and only the effective leader's signature authenticates.
    pub leader_pk: crypto::bls::PublicKey,
    /// `proposal_signing_hash(header)` — the domain-bound 32-byte
    /// digest the proposer signs.
    pub signing_hash: Hash,
    /// Live validator-set size — the shard commitment's `n`.
    pub shard_count: usize,
    /// `erasure_k` under the live set — the commitment's
    /// reconstruction threshold.
    pub shard_threshold: usize,
}

/// The crypto material a vote's execution attestation verifies
/// against — resolved by [`OxideBft::collect_vote_pooled`] at
/// intake, verified by the node's signature pool off the
/// consensus thread, applied via [`OxideBft::apply_attest_verdict`].
///
/// Every field is a pure value: the worker needs no engine state
/// to run the pairing, and the apply half re-checks the live
/// cert-existence gate and voter bounds before inserting, so a
/// verdict that went stale since intake can never write into the
/// attestation pool.
#[derive(Debug)]
pub struct AttestVerifyTask {
    /// The attesting committee seat — resolved at intake from the
    /// authenticated peer.
    pub voter: ValidatorIndex,
    /// The claim the signature covers — carried to the apply side
    /// so the verdict binds exactly what was verified.
    pub attestation: types::StateAttestation,
    /// The voter's `Domain::ExecAttest` signature over `msg`.
    pub signature: Signature,
    /// The voter's BLS key under the live committee.
    pub pk: crypto::bls::PublicKey,
    /// `attestation_signing_message(epoch, attestation.height,
    /// attestation.root)` — the exact 48-byte payload the
    /// attestation path verifies against.
    pub msg: [u8; 48],
}

/// A block that has a QC but hasn't been committed yet — waiting for
/// the 2-chain commit rule to fire.
///
/// When the *next* block (which extends this one) gets a QC, this
/// block is committed. The engine tracks exactly one pending block at
/// a time (the tip of the pipeline). The hash is not stored — it is
/// Errors from epoch rotation (stage 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochRotationError {
    /// A rotation was scheduled while one was already pending.
    AlreadyPending,
    /// A rotation completion was attempted with no pending rotation.
    NoPendingRotation,
}

impl std::fmt::Display for EpochRotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyPending => write!(f, "epoch rotation already pending"),
            Self::NoPendingRotation => write!(f, "no pending epoch rotation"),
        }
    }
}

impl std::error::Error for EpochRotationError {}

/// Errors from applying validator key changes (staking `KEY_CHANGE`).
///
/// Key changes are submitted as transactions and stored in the
/// staking module's `pending_key_changes`. At epoch boundary, the
/// caller drains them and passes them to `apply_key_changes`, which
/// builds an updated `ValidatorSet` and schedules a rotation. Keys
/// arrive as `ValidatedPublicKey` tokens — point + subgroup validity
/// was proven at module admission, so malformed key bytes are
/// unrepresentable here rather than a runtime error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyChangeError {
    /// The updated `ValidatorSet` failed construction (e.g. a key
    /// change produced an invalid set — should not happen in
    /// practice since `apply_key_change` preserves stakes and
    /// addresses).
    InvalidSet,
    /// A rotation is already scheduled — the caller must wait for
    /// it to complete before applying more key changes.
    RotationAlreadyPending,
}

impl std::fmt::Display for KeyChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSet => write!(f, "updated validator set failed construction"),
            Self::RotationAlreadyPending => write!(f, "epoch rotation already pending"),
        }
    }
}

impl std::error::Error for KeyChangeError {}

/// Errors from consensus message verification (C1 fix + hardening).
///
/// These are distinct from operational errors (io, codec): they
/// indicate byzantine behavior — a peer sent a vote or QC with an
/// invalid signature, conflicting metadata, or insufficient quorum.
/// Stored state of a block's body in `OxideBft::blocks`.
///
/// With dispersed broadcast (`types::shard`), a validator votes on the
/// block *commitment* as soon as it holds a verified own-shard +
/// header — the full body is reconstructed lazily and is required
/// only at commit time, not vote time (the `DispersedSimplex` split:
/// notarize on partial information, certify before finalize).
/// `Awaiting` blocks participate in every header-level rule
/// (parentage, height, QC chain) but can never be committed until
/// `OxideBft::supply_body` upgrades them to `Complete` — the
/// commit walk treats them exactly like a body that hasn't arrived
/// yet and defers.
#[derive(Debug, Clone)]
enum BlockBody {
    /// The full proposal — known-valid bytes, executable at commit.
    Complete(Proposal),
    /// Header verified and notarization-eligible; the body is still
    /// propagating as shards (or, adversarially, may never arrive).
    Awaiting,
}

/// The caller should penalize the peer, not retry the operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// A vote's signature did not verify against the claimed voter's
    /// public key. The voter index may be out of bounds or the
    /// signature may be forged.
    InvalidVoteSignature {
        /// The validator index that allegedly signed.
        voter: ValidatorIndex,
    },
    /// A QC's aggregate signature did not verify against the signer
    /// bitmap + validator set. The leader may be byzantine or the QC
    /// may be corrupted in transit.
    InvalidQcSignature,
    /// A timeout certificate's aggregate signature did not verify
    /// against the signer bitmap + validator set. A forged TC could
    /// allow an attacker to force a spurious view change.
    InvalidTcSignature,
    /// The signer bitmap references a validator index that is out of
    /// bounds for the current validator set.
    SignerOutOfBounds,
    /// A vote was collected for a different (view, `block_hash`) than
    /// the votes already collected for this view. A byzantine voter
    /// could send conflicting votes to different leaders; this check
    /// prevents mixing votes for different blocks into one QC.
    ConflictingVote {
        /// The validator index that sent the conflicting vote.
        voter: ValidatorIndex,
        /// The view of the conflicting vote.
        view: View,
        /// The block hash the engine expected (from the first vote).
        expected_block: Hash,
        /// The block hash the conflicting vote was for.
        actual_block: Hash,
    },
    /// A QC was received from an epoch older than the engine's.
    /// Its signer bitmap indexes a committee the node no longer
    /// holds and its view numbers the old epoch's restarted view
    /// space — neither can be verified or applied safely, so the
    /// certificate is dead evidence, refused before any state
    /// change. (Distinguished from [`ConsensusError::StaleQc`],
    /// which is the same-epoch monotonic-view rejection.)
    PastEpochQc {
        /// The epoch the QC was certified under.
        qc_epoch: Epoch,
        /// The engine's current epoch.
        epoch: Epoch,
    },
    /// A QC was formed or received whose signer voting power is below
    /// the quorum threshold. The aggregate signature may verify, but
    /// the QC does not represent >2/3 of total stake — it cannot be
    /// trusted as a commitment certificate.
    InsufficientQuorum {
        /// The total stake of the signers in the QC's bitmap.
        voting_power: u64,
        /// The voting-power quorum for the current validator set.
        required: u64,
    },
    /// A QC was received whose view is not greater than the engine's
    /// current `high_qc` view. A byzantine leader could replay an old
    /// QC to trick the engine into regressing its view. The engine
    /// rejects stale QCs to enforce monotonic progress.
    StaleQc {
        /// The QC's view.
        qc_view: View,
        /// The highest QC view the engine has already seen.
        high_qc_view: View,
    },
    /// The execution certificate's state root does not match the
    /// locally computed state root for the same height. This means
    /// the validator has diverged from the network — either the
    /// local execution is wrong, or the network is byzantine. The
    /// validator must refuse to vote and alert the operator.
    StateDivergence {
        /// The height whose execution diverged.
        height: Height,
        /// The state root the network agreed on (from `exec_cert`).
        expected_root: Hash,
        /// The state root the local validator computed.
        actual_root: Hash,
    },
    /// An execution certificate's epoch differs from the engine's
    /// current epoch. Attestation signatures commit to
    /// `(height, root, epoch)` and the signer bitmap indexes the
    /// *current* validator set, so a certificate from any other
    /// epoch is unverifiable here — refused rather than silently
    /// trusted.
    CertEpochMismatch {
        /// The epoch the certificate claims to belong to.
        cert_epoch: Epoch,
        /// The engine's current epoch.
        epoch: Epoch,
    },
    /// A reconstructed block body failed certification: either its
    /// shard-commitment does not match the `body_commitment` in the
    /// notarized header (the leader dispersed inconsistent bodies —
    /// a provable equivocation) or the app's static
    /// `process_proposal` check rejected it. A notarized-but-uncertified
    /// block must never finalize (`DispersedSimplex` certify gate).
    BodyRejected {
        /// The block whose body failed certification.
        block_hash: Hash,
    },
    /// The persisted consensus state could not be restored — the
    /// byte buffer is malformed, truncated, or corrupted (C9 fix).
    InvalidState,
    /// A fetched `CertifiedBlock` failed a structural or
    /// cryptographic check in `apply_certified_block`. Sync only
    /// ever *adds* committed history, so rejection is always safe:
    /// the node keeps its tip and can retry from an honest peer.
    SyncRejected {
        /// The height the record claimed.
        height: u64,
        /// Which check failed — a stable tag for logs and tests.
        reason: SyncReject,
    },
    /// The record verified but the execution lane is saturated —
    /// finalizing would grow the lane's unexecuted debt past its
    /// bound. Retry when the lane drains; the record stays valid.
    SyncDeferred {
        /// The height the record claimed.
        height: u64,
    },
    /// The record's epoch differs from the engine's: the QC bitmap
    /// indexes a committee this engine does not hold, so the proof
    /// cannot be verified here. The caller must use certified state
    /// sync (a weak-subjectivity checkpoint) for cross-epoch gaps.
    SyncEpoch {
        /// The height the record claimed.
        height: u64,
        /// The epoch the record was certified under.
        record_epoch: Epoch,
        /// The engine's current epoch.
        epoch: Epoch,
    },
}

/// Which check a [`ConsensusError::SyncRejected`] record failed —
/// one variant per `apply_certified_block` rule, in check order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncReject {
    /// Not the direct successor of the verified frontier (committed
    /// tip or staged tail) — the caller buffers or re-fetches; not
    /// evidence of malice.
    NotNext,
    /// `header.prev_block` does not match the frontier parent hash —
    /// the record claims our height but extends a different parent.
    AnchorMismatch,
    /// `child.prev_block != hash(header)` — the certified child does
    /// not extend the block it claims to commit.
    BrokenPair,
    /// `child.view <= header.view` — a certifying child must sit at
    /// a strictly later view. Forward gaps (`child.view > header.
    /// view + 1`) are LEGAL interior links under commit-by-descent
    /// and stage rather than reject.
    NonConsecutiveViews,
    /// `qc` does not certify `child` (`block_hash`/`view`/`epoch`
    /// mismatch), or `child.height != header.height + 1` — the
    /// commit certificate is malformed.
    MalformedCertificate,
    /// `child.high_qc` is absent or does not certify `header` —
    /// the notarization link of the pair is broken.
    BrokenNotarization,
    /// `proposal` does not match `header` — height, `tx_root`, or
    /// `body_commitment` mismatch; the body is not what quorum
    /// certified.
    BodyMismatch,
    /// The proposer seat does not resolve in the committee or the
    /// proposal signature does not verify under its key.
    BadProposerSignature,
}

/// What [`OxideBft::mark_repaired`] concluded about the divergence
/// latch — the state machine around a confirmed execution
/// divergence, certified-repair cleared or still halted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairOutcome {
    /// No divergence is latched — nothing to repair.
    NotLatched,
    /// The latch cleared: local state now attests identically to a
    /// quorum-certified root at the returned height (at or above
    /// the diverged height). Signing may resume.
    Repaired(Height),
    /// Still halted: no held certificate at or above the diverged
    /// height matches a locally executed root. Either repair has
    /// not landed or the divergence is a deterministic executor
    /// fault — re-execution reproduces the wrong root either way.
    NoAnchor,
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVoteSignature { voter } => {
                write!(f, "invalid vote signature from validator {voter}")
            }
            Self::InvalidQcSignature => write!(f, "invalid QC aggregate signature"),
            Self::InvalidTcSignature => write!(f, "invalid TC aggregate signature"),
            Self::SignerOutOfBounds => {
                write!(f, "signer bitmap references out-of-bounds validator")
            }
            Self::ConflictingVote { voter, view, expected_block, actual_block } => {
                write!(
                    f,
                    "conflicting vote from validator {voter} at view {}: expected block {expected_block}, got {actual_block}",
                    view.value()
                )
            }
            Self::InsufficientQuorum { voting_power, required } => {
                write!(f, "insufficient quorum: {voting_power} stake < {required} threshold")
            }
            Self::PastEpochQc { qc_epoch, epoch } => {
                write!(
                    f,
                    "QC from past epoch {} — engine is at epoch {}",
                    qc_epoch.value(),
                    epoch.value()
                )
            }
            Self::StaleQc { qc_view, high_qc_view } => {
                write!(
                    f,
                    "stale QC: view {} <= high_qc view {}",
                    qc_view.value(),
                    high_qc_view.value()
                )
            }
            Self::StateDivergence { height, expected_root, actual_root } => {
                write!(
                    f,
                    "state divergence at height {}: network root {expected_root}, local root {actual_root}",
                    height.value()
                )
            }
            Self::CertEpochMismatch { cert_epoch, epoch } => {
                write!(
                    f,
                    "exec cert epoch {} does not match current epoch {}",
                    cert_epoch.value(),
                    epoch.value()
                )
            }
            Self::BodyRejected { block_hash } => {
                write!(f, "block body failed certification: {block_hash}")
            }
            Self::InvalidState => write!(f, "invalid persisted consensus state"),
            Self::SyncRejected { height, reason } => {
                write!(f, "certified sync record at height {height} rejected: {reason:?}")
            }
            Self::SyncDeferred { height } => {
                write!(
                    f,
                    "certified sync record at height {height} deferred: execution lane saturated"
                )
            }
            Self::SyncEpoch { height, record_epoch, epoch } => {
                write!(
                    f,
                    "certified sync record at height {height} is epoch {} — engine is at epoch {}",
                    record_epoch.value(),
                    epoch.value()
                )
            }
        }
    }
}

impl std::error::Error for ConsensusError {}

/// The oxideBFT consensus engine.
///
/// Implements `ports::ConsensusEngine`. In single-validator mode
/// (quorum = 1), the engine self-proposes, self-votes, and commits via
/// the 2-chain rule. In multi-validator mode (driven by the
/// simulation), each engine is one validator: the leader proposes,
/// followers vote, the leader forms QCs, and all validators commit.
pub struct OxideBft {
    /// The application (executor + mempool + state). Behind `Arc` so
    /// the engine can be `Send` (the app is `Send + Sync`).
    app: Arc<dyn AppInterface>,
    /// The validator set for the current epoch.
    validator_set: ValidatorSet,
    /// The next validator set (stage 6 epoch rotation). `None` when no
    /// rotation is pending. When set, the engine is in the first
    /// phase of the two-phase handoff: the old set continues to
    /// propose/vote/commit, and the new set takes over after the old
    /// set commits the last block of the old epoch.
    next_validator_set: Option<ValidatorSet>,
    /// The committed height at which a scheduled rotation activates.
    /// `Some` only while `next_validator_set` is `Some`. Membership
    /// changes apply at a certified *future* height — never mid-view
    /// and never at the exact commit that staged them — so the
    /// incoming committee has a window (the network layer publishes
    /// the pending set for peer admission during it) before it must
    /// carry quorum. `drive_epoch_changes` completes the rotation
    /// once `last_committed` reaches this height.
    rotation_activation_height: Option<u64>,
    /// This engine's index in the validator set.
    validator_index: ValidatorIndex,
    /// Leader-reputation window (audit M1): the certifying QC's
    /// signer bitmap for each of the last `leader_rep_window()`
    /// committed heights, oldest → newest. A validator absent from
    /// every bitmap in a full window has signed nothing the chain
    /// committed — it is crashed or hopelessly partitioned — and
    /// [`Self::effective_leader`] walks the schedule past it so its
    /// turns stop costing a full view timeout each cycle.
    ///
    /// Determinism: the inputs are committed QC bitmaps — identical
    /// on every replica that committed the same prefix — and the
    /// window rides the WAL, so a restart restores the same
    /// exclusions rather than computing divergent ones. Replicas at
    /// different commit depths can disagree transiently (their
    /// windows differ by the lag) — a wasted vote, never a safety
    /// issue — and converge on the next commit. Cleared on epoch
    /// rotation: bitmaps index into the *signing* set, and the new
    /// committee is a different index space.
    recent_signers: std::collections::VecDeque<Vec<u8>>,
    /// The round-time mark for the pacemaker's adaptive-timeout
    /// EWMA — when the current view started (injected-clock ms) and
    /// whether it has already burned a local timeout. `None` until
    /// the first view transition: at construction the clock may
    /// still be the default (a `with_clock` override would
    /// otherwise seed a bogus epoch-scale sample), so the first
    /// advance skips the measurement and merely starts the mark.
    /// A view that completes *after* timing out measures "dead
    /// leader plus timeout", not a round-trip —
    /// [`Self::observe_completed_view`] skips it so a crashed
    /// leader can't masquerade as a slow network and inflate the
    /// timeout floor it was excluded for.
    view_round_mark: Option<ViewMark>,
    /// This engine's consensus signer (stage 5) — the key that signs
    /// votes, proposals, timeouts, and attestations behind the
    /// [`crypto::ConsensusSigner`] seam: in-process [`BlsSecretKey`]
    /// today, a remote signer daemon (privval/KMS-style) tomorrow,
    /// without the engine learning where the key lives. `None` in
    /// conformance mode (placeholder `Signature::ZERO`).
    ///
    /// [`BlsSecretKey`]: crypto::BlsSecretKey
    signer: Option<Arc<dyn crypto::ConsensusSigner>>,
    /// The pacemaker (stage 2). Drives view changes on timeout.
    pacemaker: crate::pacemaker::Pacemaker,
    /// The highest QC the engine has seen. Carried in the next
    /// proposal's `high_qc` field (the pipeline's chain-link).
    ///
    /// The [`VerifiedQc`] token is the audit-9.A boundary: this is
    /// the engine's safety anchor, so it can only hold a certificate
    /// that cleared quorum+signature verification (`deliver_qc`) or
    /// came back from our own durable state (`from_trusted` at
    /// WAL/snapshot decode — self-authored bytes written only after
    /// verification, the same trust basis as `voted_at_height`).
    high_qc: Option<VerifiedQc>,
    /// The highest view the engine has voted in (prevents double-
    /// voting; a safety invariant). `None` = never voted.
    last_voted_view: Option<View>,
    /// The latest view this engine signed a timeout for (Jolteon
    /// evidence integrity, arXiv:2106.10362 §3). A timeout
    /// signature binds the `qc_high` we held at signing time; if we
    /// could still vote in that view afterward, our TC entry would
    /// underreport the lock our vote created — a quorum of such
    /// stale entries lets a proposal skip the committed chain.
    /// `vote_if_eligible` rejects any proposal at this view. The
    /// asymmetry is required by the lock-persistence proof:
    /// vote-then-timeout is legal (the timeout then reports the
    /// lock), timeout-then-vote is not.
    ///
    /// Persisted in the WAL — a restart that forgot it could emit
    /// both signatures for one view.
    timeout_signed_view: Option<View>,
    /// The block hash this validator voted for at each height — the
    /// per-height vote lock (docs/oxidebft-spec.md §4). The view
    /// check alone is insufficient: after a timeout the new leader
    /// can propose a *different* block at the same height extending
    /// the same parent QC; the tail-fork check passes (equal QC
    /// view) and the validator would notarize two conflicting
    /// blocks at one height — a safety violation that can fork the
    /// committed chain. A validator may only re-vote a height for
    /// the SAME block hash. Entries are pruned on commit (a
    /// finalized prefix cannot conflict).
    voted_at_height: BTreeMap<u64, Hash>,
    /// Block store: block hash → (header, body state). Used to look
    /// up blocks at commit time.
    blocks: HashMap<Hash, (BlockHeader, BlockBody)>,
    /// Finalized blocks keyed by height. `BTreeMap` for ordered
    /// iteration (the conformance suite checks the height sequence).
    /// Bounded to `MAX_RETAINED_FINALIZED` — old blocks are pruned.
    finalized: BTreeMap<u64, FinalizedBlock>,
    /// Certified commit records waiting for the node layer to drain
    /// into its durable serve store. Every `record_committed` — live
    /// commit or verified sync — pushes the [`CertifiedBlock`] that
    /// carries the block's full Jolteon two-chain proof, so a peer
    /// can verify served history without trusting this node. Capped
    /// at `MAX_RETAINED_FINALIZED`; the pump drains each loop
    /// iteration, so the cap only binds engines nobody drains
    /// (tests, sims), where dropping oldest is sound.
    certified_out: std::collections::VecDeque<CertifiedBlock>,
    /// Verified sync records staged above the committed anchor,
    /// awaiting a consecutive-view *seal*. Sync verification mirrors
    /// `commit_walk`'s commit-by-descent: a record's `(child, qc)`
    /// pair proves its header and child are notarized chain links,
    /// but the header commits only when a *consecutive* pair closes
    /// somewhere above it (`child.view == header.view + 1`). During
    /// timeout churn, interior committed blocks legitimately have
    /// non-consecutive children (their commit rode on the run's
    /// tail seal), so a strict per-record adjacency check would
    /// reject valid history forever — the exact failure this
    /// staging exists to prevent. Bounded by fetch-side flow
    /// control: entries only enter contiguously from the committed
    /// frontier, each fully verified before staging.
    sync_staged: std::collections::BTreeMap<u64, CertifiedBlock>,
    /// Optional commit listener. Called with each committed block
    /// before it's added to `finalized`. Used by devnet harnesses to
    /// observe all commits (the `finalized` map prunes old entries,
    /// so external consumers can't rely on it for full history).
    #[allow(clippy::type_complexity)]
    commit_listener: Option<Box<dyn Fn(&FinalizedBlock) + Send + Sync>>,
    /// Hash and height of the most recently committed block — the
    /// anchor a proposal must extend when no `high_qc` is known.
    ///
    /// `high_qc = None` has three legitimate cases: true genesis
    /// (nothing committed — anchor is `None`), the first block after
    /// an epoch rotation (the rotation resets `high_qc`, but the
    /// chain's heights continue — the anchor is the last block the
    /// old epoch committed), and a freshly synced node (no anchor —
    /// it must obtain a QC before it can vote). Height continuity
    /// is checked against this anchor so post-rotation stamps keep
    /// increasing instead of colliding with the old epoch's
    /// `finalized` entries.
    last_committed: Option<(Hash, Height)>,
    /// The next height at which a block will be proposed. Advances in
    /// lockstep with the app's `next_proposal_height`.
    next_height: Height,
    /// The current view. Advances by 1 per proposed block (one view
    /// per block in the happy path) or on view change (via TC).
    current_view: View,
    /// The current epoch. Stage 6 adds rotation: when a rotation is
    /// pending and the old set commits the last block, the epoch
    /// increments and the new validator set takes over.
    epoch: Epoch,
    /// Collected votes for the current view (leader only). `None` =
    /// no vote from that validator. Indexed by `ValidatorIndex`.
    votes: Vec<Option<Vote>>,
    /// Number of votes collected in the current view (diagnostics).
    /// The quorum decision uses `vote_stake` — signer *count* is not
    /// voting *power* under unequal stake.
    vote_count: usize,
    /// Total stake of the validators whose votes have been collected
    /// in the current view. Compared against
    /// [`ValidatorSet::quorum_stake`] in `try_form_qc` — a quorum is
    /// >2/3 of voting power, not >2/3 of validator count.
    vote_stake: u64,
    /// Execution attestations harvested from collected votes, grouped
    /// by `(height, state_root)`. A bucket reaching quorum is
    /// aggregated into an [`ExecCertificate`] in `exec_certs`.
    ///
    /// Unlike `votes` (cleared every view), attestations persist
    /// across views — a validator may attest the same execution
    /// result in several consecutive votes, and the certificate
    /// forms whenever quorum is reached regardless of view.
    ///
    /// Safety: a bucket counts each voter at most once (checked on
    /// insert), so reaching `quorum_stake` requires distinct
    /// validators contributing distinct stake — equivocating
    /// attestations cannot double-count a validator's power.
    /// Only signature-verified attestations are admitted
    /// (`verify_signatures` mode); in conformance mode the pool
    /// stays empty and `exec_cert` is never embedded.
    exec_attest_pool: std::collections::BTreeMap<
        u64,
        std::collections::HashMap<Hash, Vec<(ValidatorIndex, Signature)>>,
    >,
    /// Formed execution certificates, keyed by certified height.
    /// `propose()` embeds the newest entry whose height is at most
    /// `proposed_height - 2`: voters only refuse-vote on a cert they
    /// cannot verify locally, and at vote time a follower's executed
    /// tip trails the proposed height by one full 2-chain lag.
    /// Entries at or below the committed height are pruned — the
    /// committed prefix no longer needs certification.
    exec_certs: std::collections::BTreeMap<u64, ExecCertificate>,
    /// Certificates that have passed [`verify_exec_cert`]
    /// (`Self::verify_exec_cert`) under the *current* validator set,
    /// keyed by certified height. The vote path consults this before
    /// paying the ~4ms aggregate verify: a certificate is validated
    /// once and the result is bound to its complete identity — the
    /// cached value must equal the presented cert, so a different
    /// cert at the same height re-validates rather than inheriting
    /// the earlier verdict. Cleared at epoch rotation: verification
    /// is only defined against the epoch's validator set.
    verified_exec_certs: std::collections::BTreeMap<u64, ExecCertificate>,
    /// Negative authentication memo: block hashes that failed
    /// `authenticate_proposal` or the body-commitment check.
    ///
    /// A proposal's authenticity is a pure function of its bytes —
    /// leader schedule, signature, and commitment either verify or
    /// they don't — so a rejection is permanent and re-delivering
    /// the same junk must be free. Drivers retry `vote()` for
    /// proposals whose *eligibility* was merely pending (e.g. the
    /// bounded attestation wait timed out); without this set every
    /// retry of an unauthenticatable header re-paid the BLS verify,
    /// which is exactly the consensus-thread exhaustion a junk-
    /// proposal flood aims for. Cleared at epoch rotation — the
    /// verdict was computed against the old committee's leader
    /// schedule and keys — and capped by [`MAX_REJECTED_HEADERS`].
    rejected_headers: std::collections::HashSet<Hash>,
    /// The last attestation this validator signed, cached by
    /// `(height, state_root, epoch)`. Execution attestations only
    /// change
    /// when the app's executed tip advances, but votes are cast
    /// once per view — under steady-state pipelining the same
    /// watermark is attested several times. Re-signing an
    /// identical `(height, root)` would produce an identical BLS
    /// signature (BLS is deterministic), so the cached signature is
    /// reused verbatim — one `sign` per executed height instead of
    /// one per vote (~0.5ms saved per vote on the critical path).
    /// The epoch is part of the key: the signed message binds
    /// `(height, root, epoch)`, so a signature minted in epoch N
    /// is invalid under epoch N+1 and must never be replayed from
    /// this cache.
    last_attestation: Option<(StateAttestation, Epoch, Signature)>,
    /// The timeout certificate that justified entry into the current
    /// view, when the view was reached via the timeout path. `None`
    /// when the view was entered via QC progress (the happy path),
    /// catch-up sync, or epoch rotation.
    ///
    /// The next leader embeds this TC in its proposal
    /// (docs/oxidebft-spec.md §view-changes), proving it is the
    /// legitimate successor of a timed-out view. On the voter side
    /// it is the evidence that releases a per-height vote lock: a
    /// view that timed out produced no QC, so re-voting a different
    /// block at the same height cannot create conflicting commits
    /// (only one notarization can gather commit momentum — QC
    /// adoption is view-monotonic, so all honest voters converge on
    /// the newest notarization's chain).
    ///
    /// Carried as a [`VerifiedTc`]: every assignment passes through
    /// `verify_tc_signature`, so the proposal path re-embeds a
    /// certificate that provably cleared per-signer verification.
    last_tc: Option<VerifiedTc>,
    /// Collected timeout signatures for the current view (TC safety).
    /// `None` = no timeout signature from that validator. Indexed by
    /// `ValidatorIndex`. Used to aggregate the TC's signature when
    /// quorum is reached.
    timeout_signatures: Vec<Option<types::TimeoutSigner>>,
    /// Whether to verify BLS signatures on votes and QCs (C1 fix).
    ///
    /// `true` (production): every vote's signature is verified in
    /// `collect_vote`, and every QC's aggregate is verified in
    /// `deliver_qc`. A forged vote or QC is rejected with
    /// [`ConsensusError`].
    ///
    /// `false` (conformance mode): signature verification is skipped.
    /// Used only by pure-logic tests that don't set BLS keys. The
    /// multi-node simulation uses real keys + verification.
    verify_signatures: bool,
    /// Whether to verify each vote's BLS signature individually on
    /// collection (HIGH perf fix). `true` = verify each vote as it
    /// arrives (safe but ~1-2 ms per vote). `false` = skip per-vote
    /// verification and rely on the aggregate verification in
    /// `deliver_qc` (faster — one aggregate verify per QC instead
    /// of N individual verifies per view). The aggregate verification
    /// catches any forged votes, so this is safe: a forged vote
    /// included in the QC causes the QC's aggregate to fail, rejecting
    /// the QC. We still verify the voter is in the validator set
    /// (structural check) and the vote is for the current view (C2
    /// fix) regardless of this flag.
    verify_per_vote: bool,
    /// C9 fix: optional consensus WAL for restart safety. When
    /// set, the engine appends a `WalEntry` after every vote and
    /// QC delivery, ensuring `last_voted_view`, `voted_at_height`,
    /// and `high_qc` are durable before the vote/QC message hits
    /// the network. On restart, call [`OxideBft::recover_from_wal`]
    /// to restore safety-critical state.
    wal: Option<crate::wal::Wal>,
    /// C10 fix: fail-closed signing latch. Set the first time a WAL
    /// append reports an error and never cleared in-process: a
    /// signature emitted while its anti-equivocation state might not
    /// be durable can equivocate after a restart, so a WAL-failed
    /// engine refuses to sign — vote, timeout, attestation, and
    /// proposal signatures are all withheld until the operator
    /// restarts the validator on healthy storage.
    wal_failed: bool,
    /// Confirmed execution divergence latch. Set when a *verified*
    /// `ExecCertificate` — a stake supermajority's attested root —
    /// disagrees with the root this validator computed at that
    /// height. From then on the engine refuses to sign anything:
    /// votes, timeouts, attestations, and proposals would all extend
    /// a chain built on state this node does not share. Never
    /// cleared in-process — the only safe recovery is certified
    /// state repair, not more participation. Surfaced through
    /// [`OxideBft::divergence`] so operators see the halt.
    divergence: Option<ExecDivergence>,
    /// The block budget the engine passes to `app.prepare_proposal`.
    /// Configured via [`OxideBft::with_block_budget`]; defaults to
    /// [`types::CHAIN_BLOCK_BUDGET`]. The TOML
    /// `consensus.max_block_bytes` / `consensus.max_block_gas`
    /// values reach the proposal path through this field — before it
    /// existed they parsed fine and then silently did nothing.
    ///
    /// When `chain_params` is installed this is only the configured
    /// fallback: the shared atomics are the live budget a governance
    /// `chain.*` apply can move at runtime (see [`Self::block_budget`]).
    block_budget: types::BlockBudget,
    /// Shared live chain parameters, when node assembly wired the
    /// governance `chain.*` sink. `None` keeps the configured
    /// `block_budget` static (tests, bare engines); `Some` makes
    /// [`Self::block_budget`] read the atomics so a timelocked
    /// parameter change reaches proposals at the height it applies.
    chain_params: Option<Arc<types::ChainParams>>,
    /// Pacemaker timeout config (milliseconds), retained on the
    /// engine so the pacemaker rebuilt at each epoch rotation keeps
    /// the operator's timeouts instead of reverting to defaults.
    /// Configured via [`OxideBft::with_pacemaker_timeouts`].
    pacemaker_base_timeout_ms: u64,
    /// See `pacemaker_base_timeout_ms`.
    pacemaker_max_timeout_ms: u64,
    /// The proposal clock: milliseconds since the Unix epoch, read
    /// once per `propose()` and committed into the block header's
    /// `timestamp` field. The header is signed and QC-certified, so
    /// the stamp is the value every replica executes under — voters
    /// never compare it against their own clocks (only against the
    /// parent's, an objective ordering rule), so clock skew between
    /// validators cannot fork execution.
    ///
    /// Injectable via [`OxideBft::with_clock`] so tests and the
    /// deterministic sim control time; production defaults to
    /// [`types::system_time_ms`].
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

/// Round-time sampling mark for the adaptive timeout: the
/// injected-clock ms at which the current view started, tagged by
/// how the view has fared. `Clean` views that complete in a single
/// step feed the EWMA; `TimedOut` views (a local timeout fired
/// while the view was open) are skipped — their duration conflates
/// a dead leader's wait with network latency.
#[derive(Debug, Clone, Copy)]
enum ViewMark {
    /// View started at this clock reading; no local timeout yet.
    Clean(u64),
    /// A local timeout already fired in this view — duration is
    /// dead-leader-plus-timeout, not a round-trip sample.
    TimedOut,
}

mod commit;
mod epoch;
mod persist;
mod timeout;
mod votes;

impl OxideBft {
    /// Construct a fresh engine with `app` and `validator_set` at
    /// genesis (height 0, view 0, epoch 0). The engine is validator
    /// index 0 by default; use [`OxideBft::with_index`] to set a
    /// different index for multi-validator mode. No BLS secret key
    /// (conformance mode — placeholder signatures).
    #[must_use]
    pub fn new(app: Arc<dyn AppInterface>, validator_set: ValidatorSet) -> Self {
        Self::with_index(app, validator_set, 0)
    }

    /// Construct a fresh engine with a specific validator index (for
    /// multi-validator mode). No BLS secret key.
    #[must_use]
    pub fn with_index(
        app: Arc<dyn AppInterface>,
        validator_set: ValidatorSet,
        validator_index: ValidatorIndex,
    ) -> Self {
        let initial_view = View::new(0);
        let epoch = Epoch::new(0);
        let pacemaker =
            crate::pacemaker::Pacemaker::new(validator_set.clone(), initial_view, epoch);
        let n = validator_set.n();
        Self {
            app,
            validator_set,
            next_validator_set: None,
            rotation_activation_height: None,
            validator_index,
            recent_signers: std::collections::VecDeque::new(),
            view_round_mark: None,
            signer: None,
            pacemaker,
            high_qc: None,
            last_voted_view: None,
            voted_at_height: BTreeMap::new(),
            blocks: HashMap::new(),
            finalized: BTreeMap::new(),
            certified_out: std::collections::VecDeque::new(),
            sync_staged: std::collections::BTreeMap::new(),
            commit_listener: None,
            last_committed: None,
            next_height: Height::new(0),
            current_view: initial_view,
            epoch,
            timeout_signed_view: None,
            votes: vec![None; n],
            vote_count: 0,
            vote_stake: 0,
            exec_attest_pool: std::collections::BTreeMap::new(),
            exec_certs: std::collections::BTreeMap::new(),
            verified_exec_certs: std::collections::BTreeMap::new(),
            rejected_headers: std::collections::HashSet::new(),
            last_attestation: None,
            last_tc: None,
            timeout_signatures: vec![None; n],
            verify_signatures: true,
            // HIGH perf fix: default to skipping per-vote BLS
            // verification and relying on the aggregate verification
            // in deliver_qc. This saves ~1-2 ms per vote (100-200 ms
            // per view at 100 validators) while maintaining safety
            // — the aggregate verification catches any forged votes.
            verify_per_vote: false,
            wal: None,
            wal_failed: false,
            divergence: None,
            block_budget: types::CHAIN_BLOCK_BUDGET,
            chain_params: None,
            pacemaker_base_timeout_ms: crate::pacemaker::DEFAULT_BASE_TIMEOUT_MS,
            pacemaker_max_timeout_ms: crate::pacemaker::DEFAULT_MAX_TIMEOUT_MS,
            clock: Arc::new(types::system_time_ms),
        }
    }

    /// Set a commit listener that fires on each committed block.
    ///
    /// The listener is called with the committed block before it's
    /// added to `finalized`. Used by devnet harnesses to observe all
    /// commits (the `finalized` map prunes old entries at
    /// `MAX_RETAINED_FINALIZED`, so external consumers can't rely on
    /// it for full history).
    pub fn set_commit_listener(&mut self, listener: Box<dyn Fn(&FinalizedBlock) + Send + Sync>) {
        self.commit_listener = Some(listener);
    }

    /// Set the BLS secret key for this engine (stage 5). When set,
    /// votes are signed with real BLS; when `None`, placeholder
    /// `Signature::ZERO` is used (conformance mode).
    #[must_use]
    pub fn with_secret_key(mut self, sk: crypto::BlsSecretKey) -> Self {
        self.signer = Some(Arc::new(sk));
        self
    }

    /// Set an arbitrary consensus signer — the remote-signer seam.
    ///
    /// A [`crypto::ConsensusSigner`] implementation may proxy
    /// signatures to a signer daemon, KMS, or HSM so the validator
    /// process never holds the secret. Signing failures withhold the
    /// signature (no vote/proposal is emitted) rather than latching
    /// the engine — a transient signer outage is a liveness event,
    /// not a durable-safety failure like `wal_failed`.
    #[must_use]
    pub fn with_signer(mut self, signer: Arc<dyn crypto::ConsensusSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Disable BLS signature verification (conformance mode only).
    ///
    /// By default, the engine verifies every vote signature in
    /// `collect_vote` and every QC aggregate in `deliver_qc`. This
    /// **TEST/CONFORMANCE ONLY — never call in production.**
    ///
    /// Disables BLS signature verification on votes, QCs, TCs, and
    /// proposals. This is a release-build backdoor: if called in a
    /// production validator, a byzantine peer could forge votes and
    /// QCs with `Signature::ZERO`. The method is gated behind
    /// `#[cfg(any(test, feature = "conformance"))]` so it cannot be
    /// called from a production build without explicitly enabling the
    /// `conformance` feature.
    ///
    /// The multi-node simulation does NOT call this — it uses real
    /// keys and real verification.
    #[cfg(any(test, feature = "conformance"))]
    #[doc(hidden)]
    #[must_use]
    pub fn without_signature_verification(mut self) -> Self {
        self.verify_signatures = false;
        self
    }

    /// Enable per-vote BLS verification (HIGH perf fix). By default,
    /// per-vote verification is skipped and the engine relies on the
    /// aggregate verification in `deliver_qc`. Enable this for tests
    /// that specifically verify per-vote rejection behavior.
    #[must_use]
    pub fn with_per_vote_verification(mut self) -> Self {
        self.verify_per_vote = true;
        self
    }

    /// Attach a consensus WAL for restart safety (C9 fix).
    ///
    /// When set, the engine appends a [`WalEntry`] to the WAL
    /// after every vote and QC delivery, ensuring the
    /// safety-critical state (`last_voted_view`,
    /// `voted_at_height`, `high_qc`, `current_view`,
    /// `next_height`, `epoch`) is durable before the vote/QC
    /// message hits the network.
    ///
    /// On restart, call [`OxideBft::recover_from_wal`] to
    /// restore the engine's state from the WAL.
    #[must_use]
    pub fn with_wal(mut self, wal: crate::wal::Wal) -> Self {
        self.wal = Some(wal);
        self
    }

    /// Set the starting epoch (builder).
    ///
    /// Construction-time trust: a non-signing follower bootstrapping
    /// from a validator-set checkpoint (`--trusted-validators`)
    /// names the checkpoint's epoch — the committee it was handed is
    /// only meaningful paired with the epoch that ratified it, and
    /// `apply_certified_block` rejects records signed under any
    /// other. Validators never use this (genesis is always epoch 0;
    /// rotations move through `drive_epoch_changes`), and a WAL
    /// recovery overrides it — the durable epoch is authoritative
    /// over the configured one.
    #[must_use]
    pub fn with_epoch(mut self, epoch: Epoch) -> Self {
        self.epoch = epoch;
        self
    }

    /// Set the proposal block budget (bytes + gas) the engine passes
    /// to `app.prepare_proposal` when this validator leads.
    ///
    /// Consensus is the natural owner of the block-size policy:
    /// every validator enforces the same bounds in
    /// `process_proposal`, so a proposal built within this budget is
    /// valid cluster-wide. The TOML `consensus.max_block_bytes` /
    /// `consensus.max_block_gas` values reach the running engine
    /// through this knob — without it they parsed fine and then
    /// silently did nothing while the engine always proposed at the
    /// compiled-in [`types::CHAIN_BLOCK_BUDGET`].
    #[must_use]
    pub fn with_block_budget(mut self, budget: types::BlockBudget) -> Self {
        self.block_budget = budget;
        self
    }

    /// Install the shared live chain-parameters handle.
    ///
    /// Node assembly shares one `Arc<types::ChainParams>` between the
    /// executor, this engine, and the governance `chain.*` sink —
    /// once installed, [`Self::block_budget`] reads the atomics so a
    /// timelocked `chain.block_gas_limit` / `chain.block_max_bytes`
    /// apply reaches proposal packing and the stamped
    /// `BlockContext.gas_limit` at the height it lands. Until called,
    /// the configured `block_budget` is the whole story (tests, bare
    /// engines).
    #[must_use]
    pub fn with_chain_params(mut self, params: Arc<types::ChainParams>) -> Self {
        self.chain_params = Some(params);
        self
    }

    /// Set the proposal clock — the function `propose()` calls once
    /// per proposal to stamp `BlockHeader.timestamp` (milliseconds
    /// since the Unix epoch).
    ///
    /// The stamp travels inside the signed header, so every replica
    /// executes under the leader's reading: voters validate only the
    /// objective monotonicity rule (`vote_if_eligible` rejects a
    /// timestamp earlier than its parent's), never their own clocks.
    /// That keeps the consensus outcome independent of validator
    /// clock skew — a skewed leader's stamp is committed, not judged.
    ///
    /// Tests and the deterministic sim inject a fixed or scripted
    /// clock so block context stays reproducible; production uses
    /// the default [`types::system_time_ms`].
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Set pacemaker timeouts (base + backoff cap, milliseconds).
    ///
    /// The values are stored on the engine so the pacemaker rebuilt
    /// at each epoch rotation keeps the configured timeouts — a
    /// rebuild via `Pacemaker::new` would silently revert to the
    /// compiled defaults and desynchronize view timing from what the
    /// operator configured. The TOML `consensus.base_timeout_ms` /
    /// `consensus.max_timeout_ms` values reach the running engine
    /// through this knob.
    ///
    /// # Panics
    ///
    /// Panics if `base_timeout_ms` is 0 or exceeds `max_timeout_ms`:
    /// a misconfigured pacemaker either never times out or starts
    /// past its own backoff cap, and startup must fail loudly rather
    /// than limp into an unrecoverable view schedule.
    #[must_use]
    pub fn with_pacemaker_timeouts(mut self, base_timeout_ms: u64, max_timeout_ms: u64) -> Self {
        assert!(
            base_timeout_ms > 0 && base_timeout_ms <= max_timeout_ms,
            "invalid pacemaker timeouts: base {base_timeout_ms}ms must be in 1..={max_timeout_ms}ms"
        );
        self.pacemaker_base_timeout_ms = base_timeout_ms;
        self.pacemaker_max_timeout_ms = max_timeout_ms;
        self.pacemaker = crate::pacemaker::Pacemaker::with_config(
            self.validator_set.clone(),
            self.pacemaker.current_view(),
            self.pacemaker.current_epoch(),
            base_timeout_ms,
            max_timeout_ms,
        );
        self
    }

    /// Whether this engine may still emit signatures. `false` once a
    /// WAL append has failed (C10): durable signing must not fail
    /// open, so a WAL-failed validator goes silent and stays silent
    /// until restarted on healthy storage. Also `false` after a
    /// confirmed execution divergence (the `divergence` latch): a
    /// validator that disagrees with a quorum-certified root must
    /// not extend the chain it diverged from. Always `true` for
    /// engines with no WAL attached and no divergence — they never
    /// promised durability.
    #[must_use]
    pub fn signing_healthy(&self) -> bool {
        !self.wal_failed && self.divergence.is_none()
    }

    /// The confirmed execution divergence that halted signing, if
    /// any. `Some` means participation is unsafe until certified
    /// state repair lands — signing only resumes through
    /// [`OxideBft::mark_repaired`] (or process restart into a
    /// repaired data dir), never on its own.
    #[must_use]
    pub fn divergence(&self) -> Option<&ExecDivergence> {
        self.divergence.as_ref()
    }

    /// Feed an externally fetched execution certificate through the
    /// same verification the proposal path applies — epoch match,
    /// bitmap bounds, quorum stake, aggregate signature against the
    /// live committee — and cache the verdict. Returns `true` only
    /// when the cert verifies: the repair flow uses it to admit a
    /// certificate served by a peer's snapshot endpoint into the
    /// engine's verified store, so `mark_repaired` can compare it
    /// against rebuilt state. A cert under a different epoch cannot
    /// verify here (that committee is gone or not yet installed);
    /// such repairs need a weak-subjectivity checkpoint file, which
    /// the manual `--state-sync` path already supports.
    pub fn admit_exec_cert(&mut self, cert: &ExecCertificate) -> bool {
        self.exec_cert_verified(cert)
    }

    /// Attempt to clear the divergence latch by proving the local
    /// state once again reproduces a quorum-certified root.
    ///
    /// The latch exists because a *verified* certificate attested a
    /// root this node did not compute; the symmetric clearing rule
    /// is therefore: a verified certificate at a height **at or
    /// above** the diverged height whose root the app now attests
    /// identically. Scanning only `h >= diverged.height` matters —
    /// matching an earlier root never proved the diverged height
    /// was rebuilt, and scanning above the executed tip would wait
    /// on heights that cannot have roots yet, so candidates are
    /// bounded by `attest_latest`.
    ///
    /// On success the latch clears, the WAL is appended (persisting
    /// `divergence = None` — a failed append latches `wal_failed`,
    /// which halts signing identically, so the failure mode stays
    /// closed), and staged sync records are left in place: they are
    /// verified consensus evidence, not execution state, and the
    /// commit walk will consume them normally.
    ///
    /// `NoAnchor` means no held certificate matches a local root —
    /// either repair has not landed or the divergence is a
    /// deterministic executor fault, in which case re-execution
    /// reproduces the same wrong root and the halt correctly
    /// persists.
    pub fn mark_repaired(&mut self) -> RepairOutcome {
        let Some(d) = self.divergence else {
            return RepairOutcome::NotLatched;
        };
        // The newest executed root bounds which certified heights
        // can possibly attest — certs above it cannot match yet.
        let Some(latest) = self.app.attest_latest() else {
            return RepairOutcome::NoAnchor;
        };
        // Newest-first: after a snapshot repair the rebuilt tip is
        // the likeliest anchor, and a single match is sufficient.
        let mut candidates: Vec<u64> = self
            .exec_certs
            .keys()
            .chain(self.verified_exec_certs.keys())
            .copied()
            .filter(|h| *h >= d.height.value() && *h <= latest.height.value())
            .collect();
        candidates.sort_unstable_by(|a, b| b.cmp(a));
        candidates.dedup();
        for h in candidates {
            let Some(att) = self.app.attest_state(Height::new(h)) else {
                continue;
            };
            let certified = self
                .exec_certs
                .get(&h)
                .or_else(|| self.verified_exec_certs.get(&h))
                .map(|c| c.state_root);
            if certified == Some(att.root) {
                eprintln!(
                    "oxideBFT: execution state repaired — local root at height {h} \
                     matches the quorum-certified root; resuming participation \
                     (was halted since height {})",
                    d.height.value()
                );
                self.divergence = None;
                // Persist BEFORE reporting success — a crash between
                // the in-memory clear and the next routine append
                // would restore the latch, and the repaired state is
                // durable so re-running repair is only wasteful, but
                // a silent clear is strictly better than a
                // re-halted node whose repair already landed.
                let _ = self.append_wal();
                return RepairOutcome::Repaired(Height::new(h));
            }
        }
        RepairOutcome::NoAnchor
    }

    /// The execution certificates this engine holds, keyed by
    /// certified height — the union of locally formed certs
    /// (`exec_certs`: aggregated from signature-verified
    /// attestations this validator collected) and header-carried
    /// certs this engine fully verified (`verified_exec_certs`).
    /// Both stores carry only quorum-strength evidence, so either
    /// is safe to serve; the merge exists because the two fill on
    /// different triggers (quorum formation vs proposal arrival)
    /// and a height may be present in only one.
    ///
    /// Callers are the state-sync serving path: a syncing node
    /// verifies a served cert against its own validator-set
    /// checkpoint, so the *served* bytes need only be authentic —
    /// which they are by construction here. Retention follows the
    /// commit-path floor (~2 committee rotations behind the
    /// committed height): certs older than that are dropped and a
    /// `/snapshot/cert` request for them 404s.
    #[must_use]
    pub fn exec_certificates(&self) -> Vec<ExecCertificate> {
        self.exec_certs
            .iter()
            .chain(self.verified_exec_certs.iter())
            .map(|(height, cert)| (*height, cert.clone()))
            .collect::<std::collections::BTreeMap<u64, ExecCertificate>>()
            .into_values()
            .collect()
    }

    /// The budget the engine uses when assembling proposals. Ceiling 1:
    /// defaults to the chain-configured limit from
    /// `types::CHAIN_BLOCK_BUDGET` (10 GG/block, 16 MiB) so the
    /// engine, the EVM, and the tests all agree on a single source of
    /// truth (plan.md §3); `with_block_budget` overrides it from
    /// parsed config.
    ///
    /// With `chain_params` installed the shared atomics are the live
    /// value — a governance `chain.*` apply mid-run moves the budget
    /// here and in the executor at the same height. `Relaxed`
    /// ordering is sufficient: each atomic is an independent knob
    /// with no cross-field invariant, and the apply's determinism
    /// comes from `end_block` ordering, not the memory order.
    #[must_use]
    pub fn block_budget(&self) -> types::BlockBudget {
        match &self.chain_params {
            Some(params) => types::BlockBudget {
                max_bytes: params.max_bytes.load(std::sync::atomic::Ordering::Relaxed),
                max_gas: params.max_gas.load(std::sync::atomic::Ordering::Relaxed),
            },
            None => self.block_budget,
        }
    }

    /// Current view.
    #[must_use]
    pub fn current_view(&self) -> View {
        self.current_view
    }

    /// Cheap inbound gate for network drivers: could this proposal
    /// ever be worth an authentication pass?
    ///
    /// Two pure checks, cheapest first — a junk proposal must be
    /// droppable before it costs this single-threaded consensus loop
    /// a BLS verify:
    ///
    /// 1. **View window** — `header.view` must lie within
    ///    `[current − PROPOSAL_PAST_VIEWS, current +
    ///    PROPOSAL_FUTURE_VIEWS]`. Stale-view proposals can never be
    ///    voted (`vote_if_eligible` requires `view == current_view`)
    ///    but in-window ones are still worth authenticating:
    ///    `vote()` stores the verified body, which the commit walk
    ///    needs when a QC outran its proposal. Far-future views are
    ///    unverifiable churn — a peer racing views ahead is dropped
    ///    here.
    /// 2. **Scheduled leader** — `header.proposer` must equal
    ///    [`proposer_hash`] of `validator_set.leader(header.view)` —
    ///    a 32-byte compare that rejects every non-leader claim
    ///    before any signature work. `vote()` re-checks this inside
    ///    `authenticate_proposal` (the engine never trusts the gate
    ///    for correctness); the gate exists purely to keep junk off
    ///    the expensive path.
    ///
    /// Drivers should pair this with a per-`(view, proposer)` dedupe
    /// so pending storage stays bounded by the window itself.
    #[must_use]
    pub fn proposal_admissible(&self, header: &BlockHeader) -> bool {
        let current = self.current_view.value();
        let view = header.view.value();
        if view < current.saturating_sub(PROPOSAL_PAST_VIEWS)
            || view > current.saturating_add(PROPOSAL_FUTURE_VIEWS)
        {
            return false;
        }
        header.proposer == proposer_hash(self.effective_leader(header.view))
    }

    /// Resolve the crypto material the node's signature pool needs
    /// to authenticate `header` off-thread: the effective leader's
    /// BLS key, the proposal signing hash, and the shard-commitment
    /// parameters — all read from *live* committee state at intake.
    ///
    /// `None` when `verify_signatures` is off (conformance mode —
    /// there is no crypto to offload), when `header.proposer` is
    /// not the effective leader for `header.view` (the context can
    /// never prove a forged claim), or when the signature field is
    /// absent. Callers fall back to `admit_proposal`, which applies
    /// the identical checks inline.
    ///
    /// The matching apply half is `admit_preverified`: it re-runs
    /// every state-dependent check (leader schedule, height bound,
    /// saturation, storage) so a verdict computed under a rotated
    /// committee can never store a proposal.
    #[must_use]
    pub fn proposal_verify_context(&self, header: &BlockHeader) -> Option<ProposalVerifyMaterial> {
        if !self.verify_signatures {
            return None;
        }
        // Already decided: a rejected header fails cheap inside
        // `admit_proposal` and a stored-complete one admits cheap —
        // neither should re-pay a pool job for the same bytes.
        let block_hash = Self::block_hash(header);
        if self.rejected_headers.contains(&block_hash)
            || matches!(self.blocks.get(&block_hash), Some((_, BlockBody::Complete(_))))
        {
            return None;
        }
        let leader = self.effective_leader(header.view);
        if header.proposer != proposer_hash(leader) || header.proposer_signature.is_none() {
            return None;
        }
        let leader_pk = *self.validator_set.validator(leader).ok()?;
        Some(ProposalVerifyMaterial {
            leader_pk,
            signing_hash: Self::proposal_signing_hash(header),
            shard_count: self.validator_set.n(),
            shard_threshold: self.erasure_k(),
        })
    }

    /// The highest QC the engine has seen, if any.
    ///
    /// Used by pipelined drivers to check whether the leader for the
    /// next view has the QC needed to propose (the QC's view must
    /// match `current_view` — the leader builds the next block on
    /// this QC as `prev_block`).
    #[must_use]
    pub fn high_qc(&self) -> Option<&QuorumCertificate> {
        self.high_qc.as_ref().map(VerifiedQc::qc)
    }

    /// Whether the current view carries the justification a proposal
    /// needs: view 0 is self-justifying at boot; later views need
    /// either a `high_qc` to extend or a timeout certificate that
    /// directly carried us into this view (`tc.view + 1 == view`,
    /// same epoch — the same filter `propose_inner` applies when
    /// embedding it into the header).
    ///
    /// Drivers must gate `propose()` on this — and must *not* gate
    /// on `high_qc` alone: when the first view times out before any
    /// QC formed (e.g. the view-0 leader never booted), `high_qc`
    /// stays `None` permanently and only the TC justifies the next
    /// leader. Without the TC alternative the fleet livelocks at
    /// height 0 — every leader waits for a QC that can never form.
    #[must_use]
    pub fn view_justified(&self) -> bool {
        if self.current_view.value() == 0 || self.high_qc.is_some() {
            return true;
        }
        self.last_tc.as_ref().is_some_and(|v| {
            let tc = v.tc();
            tc.epoch == self.epoch && tc.view.saturating_next() == self.current_view
        })
    }

    /// Current vote count collected for the current view (diagnostic).
    #[must_use]
    pub fn vote_count(&self) -> usize {
        self.vote_count
    }

    /// Equal-stake quorum size for the current validator set
    /// (diagnostic). The authoritative quorum threshold under unequal
    /// stake is [`quorum_stake`](Self::quorum_stake) — certificate
    /// validation uses voting power, not signer count.
    #[must_use]
    pub fn quorum(&self) -> usize {
        self.validator_set.quorum()
    }

    /// Voting-power quorum for the current validator set —
    /// `⌊2·total_stake/3⌋ + 1` (diagnostic). This is the threshold
    /// every QC, TC, and execution certificate is checked against.
    #[must_use]
    pub fn quorum_stake(&self) -> u64 {
        self.validator_set.quorum_stake()
    }

    /// The active validator set for the current epoch.
    ///
    /// Exposed for key-rotation tests and epoch-boundary inspection.
    /// The set is swapped by `complete_rotation` when a pending
    /// rotation finishes.
    #[must_use]
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// The reconstruction threshold for the dispersed-body layout
    /// under the CURRENT committee — `types::shard::erasure_params`
    /// over live stakes and quorum. Recomputed per call: an epoch
    /// rotation changes both inputs, and a stale `k` would either
    /// stall reconstruction (too high) or weaken the withholding
    /// tolerance the commitment format implies (too low).
    fn erasure_k(&self) -> usize {
        types::shard::erasure_params(self.validator_set.stakes(), self.validator_set.quorum_stake())
            .0
    }

    /// Last voted view (diagnostic).
    #[must_use]
    pub fn last_voted_view(&self) -> Option<View> {
        self.last_voted_view
    }

    /// Current epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Whether an epoch rotation is pending (stage 6 two-phase handoff,
    /// phase 1: the new validator set is announced but the old set
    /// is still active).
    #[must_use]
    pub fn rotation_pending(&self) -> bool {
        self.next_validator_set.is_some()
    }

    /// The scheduled next-epoch validator set, when a rotation is
    /// pending. The network layer publishes this to the transport
    /// authenticator so incoming members' handshakes are admitted
    /// during the schedule→activation window — an added member must
    /// be *reachable* before its first leader turn or its own
    /// activation stalls the chain.
    #[must_use]
    pub fn next_validator_set(&self) -> Option<&ValidatorSet> {
        self.next_validator_set.as_ref()
    }

    /// The committed height at which a pending rotation activates,
    /// when a rotation is pending.
    #[must_use]
    pub fn rotation_activation_height(&self) -> Option<u64> {
        self.rotation_activation_height
    }

    /// Whether this engine is the leader for the current view.
    /// Reputation-aware: a crashed validator's slot is taken by the
    /// next eligible member of the schedule, so this answers the
    /// same question `authenticate_proposal` asks of incoming
    /// proposals on every replica.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.effective_leader(self.current_view) == self.validator_index
    }

    /// Depth of the leader-reputation window, in committed heights.
    ///
    /// Two full schedule rotations: every member gets a leader turn
    /// (and every voter a signing opportunity) inside the window, so
    /// a validator absent from *all* of it has provably signed
    /// nothing — one missed QC can never exclude a healthy member.
    /// Unit: committed heights. Tradeoff: deeper tolerates longer
    /// transient partitions before exclusion; shallower evicts a
    /// crashed leader faster.
    fn leader_rep_window(&self) -> usize {
        2 * self.validator_set.leader_cycle_len().max(1)
    }

    /// The set of validator indices excluded from leadership by
    /// reputation — absent from every committed QC in the window.
    ///
    /// Deterministic by construction for replicas that committed the
    /// same prefix: the window holds only committed-QC bitmaps, and
    /// ties in the quorum bound below break by ascending index.
    ///
    /// Two guards keep the rule liveness-safe: the window must cover
    /// at least one full schedule rotation before anything is
    /// excluded — early in a chain (or right after a rotation cleared
    /// the window) "no signatures yet" is not evidence of a crash —
    /// and exclusions stop before the eligible set's stake would drop
    /// below quorum (a mass crash already halts the chain on its own;
    /// excluding the survivors' peers would only bury the schedule
    /// deeper).
    fn excluded_leaders(&self) -> Vec<bool> {
        let n = self.validator_set.n();
        let mut excluded = vec![false; n];
        if self.recent_signers.len() < self.validator_set.leader_cycle_len() {
            return excluded;
        }
        let mut participation = vec![0u64; n];
        for bitmap in &self.recent_signers {
            for (v, count) in participation.iter_mut().enumerate() {
                if bitmap.get(v / 8).is_some_and(|b| b & (1 << (v % 8)) != 0) {
                    *count += 1;
                }
            }
        }
        let quorum = self.validator_set.quorum_stake();
        let mut eligible_stake = self.validator_set.total_stake();
        for v in 0..n {
            if participation[v] != 0 {
                continue;
            }
            let stake = self.validator_set.stake(u16::try_from(v).unwrap_or(0)).unwrap_or(0);
            if eligible_stake.saturating_sub(stake) < quorum {
                // Excluding this member strands quorum — keep it
                // (a crashed whale must retain its slots rather
                // than bury the schedule) but keep scanning:
                // a lower-stake absent member may still be
                // excluded safely. Ascending index order keeps
                // the greedy choice identical on every replica.
                continue;
            }
            excluded[v] = true;
            eligible_stake = eligible_stake.saturating_sub(stake);
        }
        excluded
    }

    /// The leader for `view` after reputation exclusions — the
    /// identity every proposer-stamping and proposal-verifying path
    /// must agree on. Wraps the raw schedule: the raw leader for the
    /// view, or the next non-excluded member walking the cycle
    /// forward. Deterministic given the same committed prefix (see
    /// [`Self::recent_signers`]); the walk always terminates because
    /// `excluded_leaders` never excludes below quorum.
    fn effective_leader(&self, view: View) -> ValidatorIndex {
        let excluded = self.excluded_leaders();
        if excluded.iter().all(|e| !e) {
            return self.validator_set.leader(view);
        }
        let mut v = view.value();
        loop {
            let idx = self.validator_set.leader(View::new(v));
            if !excluded.get(usize::from(idx)).copied().unwrap_or(false) {
                return idx;
            }
            v = v.saturating_add(1);
        }
    }

    /// Sample the completed view's duration into the pacemaker's
    /// adaptive-timeout EWMA, then restart the mark. Only called from
    /// the single-step progress path (`advance_view`): a view that
    /// ends in exactly one step is a clean round-trip measurement,
    /// while multi-view catch-up jumps measure the replica's own
    /// stall — and timeout-driven advances measure the timeout
    /// itself, which fed back would inflate the estimate it sprang
    /// from. `saturating_sub` tolerates injected clocks that jump
    /// backwards between calls.
    fn observe_completed_view(&mut self) {
        let now = (self.clock)();
        if let Some(ViewMark::Clean(started)) = self.view_round_mark {
            self.pacemaker.observe_round_ms(now.saturating_sub(started));
        }
        self.restart_view_mark_at(now);
    }

    /// Restart the round-time mark without sampling — used by every
    /// view transition that is not a clean single-step completion:
    /// multi-view catch-up (measures the replica's own stall),
    /// timeout/TC advances (measure the timeout), rotations, and
    /// recovery (the mark predates the process).
    fn restart_view_mark(&mut self) {
        self.restart_view_mark_at((self.clock)());
    }

    /// `restart_view_mark` at a clock reading the caller already
    /// took — avoids a second clock read when observe+restart run
    /// in the same step.
    fn restart_view_mark_at(&mut self, now: u64) {
        self.view_round_mark = Some(ViewMark::Clean(now));
    }

    /// Our index in the *current* validator set — re-seated by epoch
    /// rotation and by WAL recovery, so it tracks committee
    /// membership rather than the construction-time value. Callers
    /// deciding "am I the leader/voter for this view" must read
    /// this, not a cached startup index.
    #[must_use]
    pub fn validator_index(&self) -> ValidatorIndex {
        self.validator_index
    }

    /// The next height at which this engine will propose a block.
    /// Used by the multi-node simulation to sync heights across
    /// engines (the in-process equivalent of broadcast delivery).
    #[must_use]
    pub fn next_height_value(&self) -> u64 {
        self.next_height.value()
    }

    /// Debug accessor for the current vote count (number of votes
    /// collected for the current view). Used by the devnet node
    /// loop for diagnostic logging.
    pub fn vote_count_debug(&self) -> usize {
        self.vote_count
    }

    /// Number of in-flight (not yet committed) blocks the engine is
    /// storing — headers received via `vote`/`vote_header` that the
    /// commit walk may still traverse. Diagnostic for simulation
    /// harnesses attributing commit lag: a node whose stored count
    /// is far below its peers' committed tip is missing ancestors.
    #[must_use]
    pub fn stored_block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Whether `block_hash` resolves to a stored, *authenticated*
    /// proposal — `Awaiting` (header verified, body pending) or
    /// `Complete` (header + body verified). Entries enter `blocks`
    /// only through an authenticated or locally-created path, so
    /// presence is the positive verdict memo.
    ///
    /// Drivers use this to disambiguate a `None` vote: a forged
    /// proposal is rejected into `rejected_headers` (never stored),
    /// while a not-yet-eligible one is stored — only the latter may
    /// claim a retry-queue slot, or a forged first delivery would
    /// park the slot and censor the genuine proposal behind it.
    #[must_use]
    pub fn proposal_known(&self, block_hash: &Hash) -> bool {
        self.blocks.contains_key(block_hash)
    }

    /// Returns the number of timeout signatures collected so far for
    /// the current view. Used by the devnet consensus loop for debug
    /// logging.
    #[must_use]
    pub fn timeout_signer_count_debug(&self) -> usize {
        self.pacemaker.timeout_signer_count()
    }

    /// Compute the Merkle root of a transaction list.
    ///
    /// Stage 4: a simple domain-separated hash of the concatenated tx
    /// bytes. A proper Merkle root (MMR or binary Merkle tree) lands
    /// when individual tx inclusion proofs are needed.
    fn tx_root(txs: &[TxBytes]) -> Hash {
        // Perf: pre-size the buffer to the total tx bytes to avoid
        // reallocations. Each tx is ~120 B min, so a 10k-tx block
        // is ~1.2 MB — one allocation instead of ~20 regrowths.
        let total: usize = txs.iter().map(|t| t.as_bytes().len()).sum();
        let mut buf = Vec::with_capacity(total);
        for tx in txs {
            buf.extend_from_slice(tx.as_bytes());
        }
        Hasher::hash_one(Domain::Transaction, &buf)
    }

    /// Compute a block's hash from its header.
    ///
    /// The hash is `H(Domain::Block ‖ encoded_header)` — domain-
    /// separated so a block hash can never collide with a vote or tx
    /// hash. Deterministic: two validators produce the same hash for
    /// the same header (the consensus contract).
    /// Compute the block hash for a header. Public so the multi-node
    /// simulation can reference the same hash when constructing votes.
    pub fn block_hash(header: &BlockHeader) -> Hash {
        // Perf: pre-size to the header's encoded length. A BlockHeader
        // is ~200 bytes, so this avoids one reallocation.
        let mut buf = Vec::with_capacity(256);
        header.encode(&mut buf);
        Hasher::hash_one(Domain::Block, &buf)
    }

    /// Compute the signing hash of a header — the block hash with
    /// `proposer_signature` set to `None`. The leader signs this
    /// hash; the signature is then stored in `proposer_signature`.
    /// Verifiers recompute this hash (with the signature stripped)
    /// and check the signature against it.
    ///
    /// This binds all header fields (`height`, `view`, `epoch`, `prev_block`,
    /// `tx_root`, `high_qc`, `timeout_cert`, `proposer`, `timestamp`) into the
    /// signed message, preventing a byzantine leader from swapping
    /// any field after signing (C3 fix).
    ///
    /// The clone is acceptable: this runs once per block per
    /// validator in `vote()`, not per-order or per-message.
    ///
    /// Exposed for the deterministic-simulation harness (`oxide-sim`):
    /// a byzantine-leader strategy must produce a second, validly
    /// signed header for the same view to exercise equivocation
    /// handling. Production callers should not need this — the engine
    /// signs internally in `propose()`.
    pub fn proposal_signing_hash(header: &BlockHeader) -> Hash {
        let mut unsigned = header.clone();
        unsigned.proposer_signature = None;
        Self::block_hash(&unsigned)
    }

    /// Voting power behind a certificate bitmap, checked against the
    /// stake quorum. A convenience for structural (pre-signature)
    /// checks that need the power without the keys — equivalent to
    /// [`signer_keys_and_power`](Self::signer_keys_and_power) minus
    /// the allocation.
    fn bitmap_meets_quorum(&self, bitmap: &[u8]) -> bool {
        crate::verify::bitmap_meets_quorum(&self.validator_set, bitmap)
    }

    /// Leader: propose a block. Calls `app.prepare_proposal`, wraps
    /// the result in a `BlockHeader`, stores it, and returns the
    /// header + proposal. Returns `None` if there is no work (no
    /// pending txs and no pending block to flush).
    ///
    /// The flush logic: if there are no pending txs but the pending
    /// block has txs (meaning a tx hasn't been finalized yet), propose
    /// an empty block to advance the pipeline and commit the pending
    /// block. If there are no pending txs and the pending block is
    /// empty or None, return `None` (idle).
    ///
    /// **Height tracking:** the stamped height is derived from the
    /// parent — `parent.height + 1` for the `high_qc` block, or the
    /// committed anchor + 1 when no `high_qc` exists. It is never
    /// taken from `next_height`: that field is only an
    /// observed-height watermark (sync bookkeeping, WAL), and
    /// stamping from it would let a forged observed height poison
    /// every future honest proposal. The app's
    /// `next_proposal_height` advances on finalization; the engine's
    /// pipeline height leads it.
    ///
    /// # Errors
    ///
    /// Returns `None` if the app rejects the proposal via
    /// `process_proposal`. A rejection means the proposal is invalid
    /// (e.g. bad state transition); the leader logs this and waits
    /// for the next view rather than crashing. A byzantine app
    /// implementation could trigger this, so panicking would give an
    /// attacker a trivial network-kill vector.
    pub fn propose(&mut self) -> Option<(BlockHeader, Proposal)> {
        self.propose_inner(false)
    }

    /// Produce a proposal even when no work is pending — the
    /// idle-mode heartbeat.
    ///
    /// A leader that stays silent when idle is indistinguishable
    /// from a dead leader: followers' view timers fire, timeout
    /// certificates form, and views churn forever without
    /// committing anything. The designed idle mode is a *slow
    /// heartbeat block*: the driver calls this when the view has
    /// been idle past its heartbeat interval, producing a normal
    /// (usually empty) proposal whose QC advances the chain through
    /// the healthy path — proving liveness and committing the
    /// uncommitted tail, without fake transactions.
    ///
    /// Everything except the idle early-return still applies: the
    /// WAL/divergence gates, `process_proposal`, height stamping,
    /// and signing are identical to [`propose`](Self::propose).
    pub fn propose_heartbeat(&mut self) -> Option<(BlockHeader, Proposal)> {
        self.propose_inner(true)
    }

    /// Shared proposal construction. `heartbeat` skips only the
    /// idle early-return; every other validity and safety gate is
    /// identical for work and heartbeat blocks.
    fn propose_inner(&mut self, heartbeat: bool) -> Option<(BlockHeader, Proposal)> {
        // C10: a proposal carries the leader's `proposer_signature` —
        // it is a signature, so a WAL-failed validator must not
        // produce one. Going silent lets the view time out and a
        // healthy leader take over. A diverged validator must not
        // propose either — its block would embed attestation state
        // peers have already proven it does not share.
        if self.wal_failed || self.divergence.is_some() {
            return None;
        }
        let mut proposal = self.app.prepare_proposal(&self.block_budget());
        let has_pending_txs = !proposal.txs.is_empty();
        // Liveness gate: the leader stays silent only when no work
        // is locally visible. Two sources count as work:
        //
        //  1. `app.has_queued_txs()` — the app holds txs at all, even
        //     ones `prepare_proposal` can't yet select (e.g. nonce-
        //     blocked behind uncommitted earlier rounds). A leader
        //     holding such txs must keep the chain advancing — the
        //     conveyor that reaches the later view where those txs
        //     become contiguous with executed state. Without this, a
        //     leader whose selection comes back empty would stay
        //     silent and freeze the view.
        //  2. A stored uncommitted block carrying txs — flush work:
        //     extending the chain is how those blocks commit. `blocks`
        //     holds only uncommitted entries (commit prunes at/below
        //     the committed height), so any tx-carrying stored block
        //     is live work. This also covers the post-submission
        //     tail: leaders with drained pools must still extend the
        //     chain to commit the last tx-carrying blocks.
        //
        // The earlier forms asked narrower questions — whether the
        // QC'd tip itself carried txs, or whether it was committed —
        // and each misjudged a real case: an empty tip with queued
        // txs froze the conveyor, and "tip uncommitted" is perpetual
        // (the newest QC'd block only ever commits via the NEXT QC),
        // so it never let `run_until_idle` terminate.
        // An `Awaiting` body counts as work regardless of contents —
        // it is uncommitted consensus state that only a longer chain
        // can finalize.
        let uncommitted_has_txs = self.blocks.values().any(|(_, b)| match b {
            BlockBody::Complete(p) => !p.txs.is_empty(),
            BlockBody::Awaiting => true,
        });
        let work_outstanding = self.app.has_queued_txs() || uncommitted_has_txs;

        // No work: nothing queued and nothing left to flush. The
        // leader returns None and waits — an idle leader doesn't
        // produce empty blocks *unless* the driver asked for a
        // heartbeat (`heartbeat == true`, see [`Self::propose_heartbeat`]).
        // The 2-chain commit rule only needs a child block when
        // there's actual work to commit.
        if !heartbeat && !has_pending_txs && !work_outstanding && self.next_height != Height::new(0)
        {
            if std::env::var_os("OXIDE_DEBUG_PROPOSE").is_some() {
                eprintln!(
                    "propose() idle: view={:?} next_height={:?} highqc={:?} has_txs={has_pending_txs} work_outstanding={work_outstanding}",
                    self.current_view,
                    self.next_height,
                    self.high_qc.as_ref().map(|q| q.view().value()),
                );
            }
            return None;
        }

        // Process the proposal through the app (static validity).
        // If the app rejects, drop the proposal and return None —
        // do NOT panic. A panic here would let a byzantine app
        // implementation crash every honest validator.
        match self.app.process_proposal(&proposal) {
            Verdict::Accept => {}
            Verdict::Reject { reason } => {
                // Log and drop; the pacemaker will trigger a view
                // change to bypass the faulty leader. Do NOT panic —
                // a panic here would let a byzantine app crash every
                // honest validator (trivial network-kill vector).
                eprintln!(
                    "oxideBFT: app rejected proposal (view={:?}, height={:?}): {reason}",
                    self.current_view, self.next_height
                );
                return None;
            }
        }

        let tx_root = Self::tx_root(&proposal.txs);
        // Stamp `parent.height + 1` — the same rule `vote()` enforces.
        // Stamping `self.next_height` instead would let a forged
        // observed height poison every future honest proposal: the
        // watermark only ever moves up, so one bad header would
        // desynchronize stamps from the real chain forever. If the
        // highQC block's header is unknown here (a QC can be adopted
        // before its block arrives on catch-up), we cannot stamp a
        // valid height — stay idle until gossip delivers the block.
        let (height, prev_block) = match &self.high_qc {
            Some(qc) => {
                if let Some((parent, _)) = self.blocks.get(&qc.block_hash()) {
                    (parent.height.saturating_next(), qc.block_hash())
                } else if let Some((anchor_hash, anchor_height)) = self.last_committed
                    && anchor_hash == qc.block_hash()
                {
                    // The QC'd tip is already committed — reachable
                    // after certified block sync, whose records
                    // finalize without entering `blocks`. Extend the
                    // anchor directly; the alternative (returning
                    // None) leaves a caught-up leader silent forever.
                    (anchor_height.saturating_next(), anchor_hash)
                } else {
                    if std::env::var_os("OXIDE_DEBUG_PROPOSE").is_some() {
                        eprintln!(
                            "propose() blocked: view={:?} highqc_view={:?} highqc_block={:?} unknown — waiting for block",
                            self.current_view,
                            qc.view().value(),
                            qc.block_hash(),
                        );
                    }
                    return None;
                }
            }
            // No highQC: extend the committed anchor — genesis at
            // height 0, or the last committed block across an epoch
            // boundary. This is the same rule voters enforce.
            None => match self.last_committed {
                Some((hash, height)) => (height.saturating_next(), hash),
                None => (Height::new(0), Hash::ZERO),
            },
        };
        // Bind the proposal body for dispersed broadcast: validators
        // verify their assigned shard's inclusion proof against this
        // root and vote on the commitment before reconstructing the
        // full body (the DispersedSimplex split — notarize on partial
        // information, certify before finalize). Computed over the
        // canonical `Proposal` encoding; receivers recompute it
        // identically in `supply_body`.
        let mut body_bytes = Vec::new();
        proposal.encode(&mut body_bytes);
        let body_commitment =
            types::shard::commitment(&body_bytes, self.validator_set.n(), self.erasure_k());
        let mut header = BlockHeader {
            height,
            view: self.current_view,
            epoch: self.epoch,
            prev_block,
            tx_root,
            body_commitment,
            high_qc: self.high_qc.as_ref().map(|v| v.qc().clone()),
            // Embed the TC that brought us into this view, if any
            // (spec §view-changes: "the next leader embeds the TC in
            // its proposal, proving it is the legitimate successor").
            // It must directly justify this view (`tc.view + 1 ==
            // current_view`) and belong to this epoch — a stale TC
            // from an earlier view or epoch is not evidence for this
            // succession. Voters use it to release same-height vote
            // locks left over from the timed-out view.
            timeout_cert: self.last_tc.as_ref().map(|v| v.tc().clone()).filter(|tc| {
                tc.epoch == self.epoch && tc.view.saturating_next() == self.current_view
            }),
            // Reputation-aware identity: `propose_inner`'s gate
            // checks `is_leader` (same `effective_leader` source),
            // so the stamp must match — stamping the raw schedule
            // here would sign a proposal every replica rejects.
            proposer: proposer_hash(self.effective_leader(self.current_view)),
            // The proposer's clock reading, committed under the
            // proposal signature. Voters enforce only the objective
            // rule (non-decreasing vs. the parent) — never their own
            // clocks — so the committed value is what every replica's
            // execution context carries via `FinalizedBlock`.
            timestamp: (self.clock)(),
            proposer_signature: None, // set below after signing
            // Embed the newest execution certificate that every voter
            // can verify locally. The bound is `cert.height <= h - 2`:
            // a voter's executed tip at vote(h) time is h-2 — block
            // h-1 commits only *after* QC(h) forms (the 2-chain lag),
            // so a cert for h-1 would hit `attest_state(h-1) ==
            // Hash::ZERO` on every honest voter and freeze quorum.
            // Anything older is safely verifiable and still proves
            // execution agreement for the committed prefix.
            exec_cert: self
                .exec_certs
                .range(..height.value().saturating_sub(1))
                .next_back()
                .map(|(_, cert)| cert.clone())
                // Only a same-epoch cert is verifiable: the signed
                // message binds `(height, root, epoch)` and the
                // bitmap indexes the current validator set. Certs
                // are cleared at rotation so the map should only
                // ever hold same-epoch entries — this filter is
                // defense in depth: embedding an out-of-epoch cert
                // would withhold every honest vote and burn the
                // view.
                .filter(|cert| cert.epoch == self.epoch),
        };
        // Durability before signature: the proposal binds the adopted
        // `high_qc`, `current_view`, and embedded TC — all safety
        // state the anti-equivocation rules protect. With QC adoption
        // now WAL-deferred, this synced append is what carries that
        // context durable before the leader's signature can leave:
        // a crash without it restarts amnesiac, and a re-proposal at
        // this view emits a second, different signed proposal — the
        // wire-level equivocation the WAL exists to prevent. A failed
        // append latches `wal_failed` inside `append_wal`; refuse to
        // sign rather than emit a signature over undurable state.
        // Conformance mode (no signer) signs nothing, so it pays
        // no fsync here.
        if self.signer.is_some() && self.append_wal().is_err() {
            return None;
        }
        // C3 fix: sign the header with the leader's consensus key.
        // The signature authenticates that the claimed proposer
        // actually created this proposal — preventing a byzantine
        // node from fabricating a proposal in another validator's
        // name. In conformance mode (no signer), the signature
        // stays `None` and `vote()` skips verification. A signer
        // that cannot produce the signature (remote endpoint down)
        // withholds the proposal entirely — an unsigned proposal
        // would fail authentication at every peer anyway.
        if self.signer.is_some() && !self.sign_proposal_header(&mut header, &mut proposal) {
            return None;
        }
        let block_hash = Self::block_hash(&header);
        self.blocks.insert(block_hash, (header.clone(), BlockBody::Complete(proposal.clone())));
        // Keep the observed-height watermark at least one past the
        // stamp we just used. `next_height` no longer drives stamps
        // (they are derived from the parent block) — it remains a
        // watermark for catch-up sync and the WAL.
        self.next_height = self.next_height.max(height.saturating_next());
        Some((header, proposal))
    }

    /// Sign `header` under [`Domain::Proposal`] and stamp the
    /// signature on it. On signer failure the proposal's txs are
    /// requeued through `ingest_tx_batch` — `prepare_proposal` left
    /// them pooled (selection is a peek), so the requeue is a dedup
    /// no-op for them but re-admits any entry evicted between select
    /// and now — and `false` returns to abort the proposal. The
    /// in-flight mark made at proposal build stays until a commit
    /// resolves the position; a failed signature means no block
    /// occupies it, so the next commit releases them.
    ///
    /// The fencing coordinate a remote signer persists is the
    /// proposal's `(view, epoch)`: the signable is an opaque hash,
    /// so the coordinate is what lets the daemon refuse a second
    /// distinct proposal at the same view.
    fn sign_proposal_header(&mut self, header: &mut BlockHeader, proposal: &mut Proposal) -> bool {
        let Some(signer) = &self.signer else { return true };
        let signing_hash = Self::proposal_signing_hash(header);
        let ctx = crypto::SignContext {
            epoch: header.epoch.value(),
            mark: header.view.value(),
            phase: 0,
        };
        let Ok(sig) = signer.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes(), ctx)
        else {
            let txs = std::mem::take(&mut proposal.txs);
            let _ = self.app.ingest_tx_batch(txs);
            return false;
        };
        header.proposer_signature = Some(sig);
        true
    }

    /// Supply a reconstructed body for a header-verified block — the
    /// certification step of dispersed broadcast. The harness calls
    /// this once it has gathered every shard of `block_hash` and
    /// reassembled the proposal.
    ///
    /// Two checks, exactly mirroring what the complete-proposal path
    /// does up front:
    ///
    /// 1. **Commitment:** the canonical `Proposal` encoding must hash
    ///    to the `body_commitment` the leader signed into the header.
    ///    A mismatch means the leader dispersed inconsistent bodies
    ///    across validators — provable equivocation; the body is
    ///    rejected and never stored.
    /// 2. **Static validity:** `app.process_proposal` — the same
    ///    check `vote` runs eagerly on the complete path, deferred
    ///    here for the commitment path.
    ///
    /// On success the stored state upgrades `Awaiting` → `Complete`
    /// and the commit walk retries from `high_qc`: the QC certifying
    /// this block may well have arrived while its body was still
    /// propagating — deferral, not loss. Idempotent: re-supplying an
    /// already-complete body is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::BodyRejected`] when the block is
    /// unknown/pruned, when the body's shard commitment does not
    /// match the signed header's `body_commitment`, or when the app
    /// rejects the body's static validity — none of which mutate the
    /// stored `Awaiting` slot.
    pub fn supply_body(
        &mut self,
        block_hash: Hash,
        proposal: &Proposal,
    ) -> Result<(), ConsensusError> {
        let n = self.validator_set.n();
        let k = self.erasure_k();
        let Some((header, body)) = self.blocks.get_mut(&block_hash) else {
            // The header never arrived or the block was already
            // pruned — nothing to certify; the caller drops the body.
            return Err(ConsensusError::BodyRejected { block_hash });
        };
        if matches!(body, BlockBody::Complete(_)) {
            return Ok(());
        }
        let mut buf = Vec::new();
        proposal.encode(&mut buf);
        if types::shard::commitment(&buf, n, k) != header.body_commitment {
            return Err(ConsensusError::BodyRejected { block_hash });
        }
        match self.app.process_proposal(proposal) {
            Verdict::Accept => {}
            Verdict::Reject { .. } => return Err(ConsensusError::BodyRejected { block_hash }),
        }
        *body = BlockBody::Complete(proposal.clone());
        if let Some(qc) = self.high_qc.clone()
            && let Some((tip, _)) = self.blocks.get(&qc.block_hash()).cloned()
        {
            // `qc` certifies `tip` — it is the outer link of the
            // first commit pair the walk collects.
            self.commit_walk(&tip, qc.qc());
        }
        Ok(())
    }

    /// All validators: receive a QC, update `high_qc`, and run the
    /// 2-chain commit rule.
    ///
    /// If the QC's block is stored (via `propose` or `vote`), the
    /// commit walk fires: the block's parent and every uncommitted
    /// stored ancestor beneath it are committed in height order —
    /// see the commit-rule comment at the call site for why a
    /// single pending link is insufficient. If the QC's block is
    /// not stored, the QC still advances `high_qc`/view but no
    /// commit runs (the block cannot be executed without its
    /// content anyway; block catch-up is the node layer's job).
    ///
    /// # Signature verification (C1 fix)
    ///
    /// When `verify_signatures` is `true` (production), the QC's
    /// aggregate signature is verified against the public keys of
    /// the signers identified by the signer bitmap. A forged QC is
    /// rejected with [`ConsensusError::InvalidQcSignature`]. The
    /// signed message is the QC's `block_hash` under `Domain::Vote`.
    ///
    /// # Monotonic view enforcement (hardening)
    ///
    /// The QC's view must be strictly greater than the current
    /// `high_qc`'s view. A byzantine leader could replay an old QC
    /// to trick the engine into regressing its view or re-committing
    /// an already-finalized block. The engine rejects stale QCs to
    /// enforce monotonic progress.
    ///
    /// # Errors
    /// Returns [`ConsensusError::InvalidQcSignature`] if the
    /// aggregate signature does not verify,
    /// [`ConsensusError::SignerOutOfBounds`] if the bitmap references
    /// a validator past the end of the set,
    /// [`ConsensusError::InsufficientQuorum`] if the signers' voting
    /// power is below the quorum threshold, or
    /// [`ConsensusError::StaleQc`] if the QC's view is not greater
    /// than the current `high_qc`'s view.
    pub fn deliver_qc(&mut self, qc: QuorumCertificate) -> Result<(), ConsensusError> {
        let adopts_epoch = self.check_qc_admission(&qc)?;

        // Committee selection + quorum + signature verification.
        // A same-epoch QC admits under the current set only. A
        // higher-epoch QC is tried against the current set first —
        // that is a node that restarted with the post-rotation
        // committee but a stale epoch — then against the staged
        // `next_validator_set`: a node that was down across the
        // activation boundary re-derived the pending committee from
        // the committed transition but never ran the boundary
        // itself, and the pending set is already certified evidence
        // (a committed block scheduled it), so a QC verifying under
        // it proves the new committee operated at `qc.epoch`. Both
        // checks under the chosen set — quorum under its stakes and
        // the aggregate over the QC's claimed epoch — run inside
        // `verify_qc_with`; nothing here stores an unchecked
        // certificate.
        let mut adopts_pending_set = false;
        let verified = match self.verify_qc_with(&self.validator_set, &qc) {
            Ok(v) => v,
            Err(current_err) => {
                if !adopts_epoch {
                    return Err(current_err);
                }
                let Some(pending) = self.next_validator_set.clone() else {
                    return Err(current_err);
                };
                match self.verify_qc_with(&pending, &qc) {
                    Ok(v) => {
                        adopts_pending_set = true;
                        v
                    }
                    // Report the current-set failure: that committee
                    // is the one a correctly-synced node holds, so
                    // its error is the primary diagnosis.
                    Err(_) => return Err(current_err),
                }
            }
        };
        self.deliver_qc_tail(qc, verified, adopts_epoch, adopts_pending_set);
        Ok(())
    }

    /// [`deliver_qc`] with the aggregate signature already screened
    /// by the node's signature-verification pool: `verdict` names
    /// which candidate committee's [`crate::verify::QcVerifyMaterial`]
    /// verified — the same current-then-pending order this function
    /// tries inline. The live admission gates (`check_qc_admission`)
    /// re-run exactly as in the verified path: a pooled verdict is
    /// crypto evidence, never an admission decision, so a verdict
    /// computed under a committee that rotated since intake still
    /// dies at the epoch/stale gates.
    ///
    /// [`QcVerdict::Pending`] is meaningful only for an epoch-
    /// adopting QC — the pending material is resolved in that case
    /// alone. For a same-epoch QC it is contradictory (the pending
    /// committee could not have signed its own epoch) and fails
    /// closed; a `Pending` verdict also requires the staged set to
    /// still be there, so a verdict issued pre-rotation cannot
    /// adopt twice.
    ///
    /// # Errors
    ///
    /// Same gates as [`deliver_qc`]. The signature-failure case
    /// collapses to [`ConsensusError::InvalidQcSignature`] for any
    /// verdict naming no verifying candidate — the specific
    /// structural reason was computed pump-side at context
    /// resolution and is not a safety distinction.
    pub fn deliver_qc_preverified(
        &mut self,
        qc: QuorumCertificate,
        verdict: crate::verify::QcVerdict,
    ) -> Result<(), ConsensusError> {
        use crate::verify::QcVerdict;
        let adopts_epoch = self.check_qc_admission(&qc)?;
        let adopts_pending_set = match verdict {
            QcVerdict::Current => false,
            QcVerdict::Pending if adopts_epoch && self.next_validator_set.is_some() => true,
            QcVerdict::Pending | QcVerdict::Invalid => {
                return Err(ConsensusError::InvalidQcSignature);
            }
        };
        let verified = crate::verify::VerifiedQc::from_trusted(qc.clone());
        self.deliver_qc_tail(qc, verified, adopts_epoch, adopts_pending_set);
        Ok(())
    }

    /// The live-state admission gates every QC entry point shares —
    /// extracted so `deliver_qc` and `deliver_qc_preverified` apply
    /// the identical ordering and no pooled verdict can bypass it.
    /// Returns whether `qc` claims an epoch beyond ours (the
    /// certified-adoption case the callers then handle).
    ///
    /// # Errors
    ///
    /// [`ConsensusError::PastEpochQc`] for a certificate from a
    /// finished epoch, [`ConsensusError::StaleQc`] for a same-epoch
    /// QC at-or-below the current `high_qc` view.
    fn check_qc_admission(&self, qc: &QuorumCertificate) -> Result<bool, ConsensusError> {
        // Certified epoch adoption. A QC claiming an epoch beyond
        // ours is verifiable only if a committee we already hold
        // produced it: the signed message binds `(view, phase,
        // block_hash, epoch)`, so a quorum of a KNOWN validator set
        // certifying epoch E is itself the handoff proof — adopt
        // E. A node holding neither matching committee fails the
        // verification (the bitmap resolves to the wrong keys) and
        // rejects the QC — fail-closed, as before.
        //
        // A QC from a PAST epoch is dead evidence: its signer bitmap
        // indexes a committee we no longer hold, and its view numbers
        // the old epoch's restarted view space, so it can neither
        // verify nor safely update `high_qc`. Rejected before any
        // state touches it.
        if qc.epoch < self.epoch {
            return Err(ConsensusError::PastEpochQc { qc_epoch: qc.epoch, epoch: self.epoch });
        }
        let adopts_epoch = qc.epoch > self.epoch;
        // Hardening: enforce monotonic view progression. A QC for a
        // view ≤ the current high_qc's view is stale — a byzantine
        // leader could replay it to regress the engine's state.
        // Exception: the first QC (when high_qc is None) is always
        // accepted.
        //
        // This check runs only for same-epoch QCs: a new epoch's
        // views restart at 0, so comparing the QC's view against the
        // old epoch's `high_qc` would reject the new epoch's first
        // certificate on arrival.
        if !adopts_epoch
            && let Some(current_high_qc) = &self.high_qc
            && qc.view.value() <= current_high_qc.view().value()
        {
            return Err(ConsensusError::StaleQc {
                qc_view: qc.view,
                high_qc_view: current_high_qc.view(),
            });
        }
        Ok(adopts_epoch)
    }

    /// The post-verification tail `deliver_qc` and
    /// `deliver_qc_preverified` share: epoch adoption, `high_qc`
    /// update, deferred WAL append, view catch-up, and the commit
    /// walk. `verified` is the certificate the caller already
    /// authenticated (inline via `verify_qc_with`, or minted from a
    /// pooled verdict); nothing in here re-checks signatures.
    fn deliver_qc_tail(
        &mut self,
        qc: QuorumCertificate,
        verified: VerifiedQc,
        adopts_epoch: bool,
        adopts_pending_set: bool,
    ) {
        if adopts_epoch {
            // The staged committee produced this QC — install it
            // before the epoch-adoption re-seat reads the live set.
            if adopts_pending_set && let Some(pending) = self.next_validator_set.take() {
                self.validator_set = pending;
                self.rotation_activation_height = None;
            }
            self.adopt_certified_epoch(qc.epoch);
        }

        // Update the highest QC.
        self.high_qc = Some(verified);
        // C9 fix: persist the updated high_qc to the WAL — deferred:
        // the frame is flushed but not fsynced, and becomes durable
        // at the next signature-path append (every signature
        // emission — vote, timeout, proposal — still fsyncs its
        // safety state first, and that fsync covers this frame).
        // A crash in the gap loses the adoption; peers re-gossip
        // the QC on reconnect, so the window is self-healing. A
        // restarted validator must propose from the correct
        // high_qc; without persistence, it could propose a stale
        // fork. A failure latches `wal_failed` (C10) — this engine
        // must not sign again until restarted on healthy storage.
        let _ = self.append_wal_deferred();

        // Catch-up: if the QC's view is higher than our current view,
        // advance our view to qc.view + 1. This lets a restarted or
        // partitioned validator that fell behind catch up to the
        // network's current view when it receives a higher-view QC
        // from peers. Without this, a lagging validator stays stuck
        // at its old view and can never participate in consensus
        // again (its timeout signatures are for the wrong view, its
        // votes are for the wrong view, etc.).
        //
        // The QC is already verified (quorum + signature) at this
        // point, so advancing to qc.view + 1 is safe — the QC proves
        // that view qc.view has a notarized block, so view qc.view + 1
        // is the next view that should propose.
        //
        // Only trigger catch-up when qc.view > current_view (strictly
        // higher). When qc.view == current_view, the caller handles
        // the normal view advancement via `advance_view()`.
        if qc.view.value() > self.current_view.value() {
            // A multi-view catch-up jump measures how long this
            // replica went without progress, not a round-trip —
            // reset the mark without feeding the EWMA (only the
            // single-step `advance_view` samples cleanly).
            self.restart_view_mark();
            // Saturating: a verified QC with view = u64::MAX would
            // wrap current_view to 0 here; saturation keeps it at
            // MAX (chain dead) instead of corrupting the view space.
            self.current_view = qc.view.saturating_next();
            self.pacemaker.sync_to_view(self.current_view);
            self.pacemaker.on_progress();
            // Clear stale per-view state from the old view.
            self.clear_per_view_state();
            // QC-driven catch-up — no TC evidence for this view.
            self.last_tc = None;
        }

        // 2-chain commit — the general rule, not a single pending
        // link (docs/oxidebft-spec.md §4): adopting QC(b) for a
        // stored block b satisfies two-chain for b's parent —
        // QC(b) is the child's certificate and b's embedded QC is
        // the parent's — and recursively for every stored ancestor
        // below it: `prev == justify` (enforced at vote time) makes
        // the stored parent chain exactly the certified chain, and
        // every stored block carries a verified QC for its parent,
        // so each ancestor has a QC *and* a QC'd child.
        //
        // The single-link form (commit only `pending` when the new
        // QC's block extends it) is incomplete: if QC(b0) arrives
        // before b0's proposal is stored, or QC(b2) leapfrogs
        // QC(b1), `pending` never holds the skipped link and it is
        // never committed — a gap in the finalized prefix (the
        // `InvNoGap` counterexample TLC produced). A commit that
        // skips a link must never happen, so the commit walk runs
        // the full ancestor chain and `commit_block` fires in
        // height order (oldest first) — the app requires in-order
        // finalization.
        if let Some((header, _)) = self.blocks.get(&qc.block_hash).cloned() {
            // `qc` certifies `header` — the outer link of the first
            // commit pair the walk collects.
            self.commit_walk(&header, &qc);
        }
    }

    /// Drain the certified commit records produced since the last
    /// call — the block-sync server's feed.
    ///
    /// Every committed height emits exactly one [`CertifiedBlock`]
    /// carrying its Jolteon two-chain proof (header, body, certifying
    /// child, QC on the child), whether the block committed through
    /// the live walk or through `apply_certified_block` — synced
    /// records are re-emitted so a caught-up node re-serves them.
    /// The node layer journals these into its durable serve store;
    /// the queue itself is bounded (`MAX_RETAINED_FINALIZED`) and
    /// drops oldest when never drained.
    pub fn take_certified(&mut self) -> Vec<CertifiedBlock> {
        self.certified_out.drain(..).collect()
    }

    /// The committed tip — hash and height of the last block this
    /// engine finalized. Unlike `finalized_height` (which reads the
    /// in-memory `finalized` map, empty after a restart), this is
    /// the WAL-restored anchor: a post-restart engine reports its
    /// true committed height here even before it re-commits
    /// anything. The block-sync layer uses it as the catch-up floor.
    pub fn committed_anchor(&self) -> Option<(Hash, Height)> {
        self.last_committed
    }

    /// Whether `hash` names a block this engine holds — committed or
    /// still in the uncommitted store. The sync layer uses it to
    /// decide whether a QC's `block_hash` must be fetched by hash
    /// from the QC's sender. Only the committed *tip's* hash is
    /// tracked (`last_committed`); a QC naming an older committed
    /// block is stale evidence and needs no fetch regardless.
    pub fn has_block(&self, hash: &Hash) -> bool {
        self.blocks.contains_key(hash)
            || self.last_committed.is_some_and(|(h, _)| h == *hash)
            || self.certified_out.iter().any(|r| Self::block_hash(&r.header) == *hash)
    }

    /// The stored `(header, proposal)` for `hash` when the body is
    /// complete — the live, not-yet-committed edge a certified record
    /// cannot cover. The block-sync serve path answers `ByHash`
    /// requests for the QC'd tip from here: the block is certified
    /// (a QC names it) but commits only through its child's QC, so
    /// no `CertifiedBlock` exists for it yet. Receivers authenticate
    /// the served bytes through `admit_proposal` exactly as they
    /// would a gossiped proposal — serving carries no authority.
    /// `Awaiting` bodies are never answers: a header without its
    /// certified body is worth nothing to a peer.
    #[must_use]
    pub fn get_proposal(&self, hash: &Hash) -> Option<(BlockHeader, Proposal)> {
        match self.blocks.get(hash) {
            Some((header, BlockBody::Complete(proposal))) => {
                Some((header.clone(), proposal.clone()))
            }
            _ => None,
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
    fn verify_qc_signature(&self, qc: &QuorumCertificate) -> Result<VerifiedQc, ConsensusError> {
        crate::verify::verify_qc_signature(&self.validator_set, self.epoch, qc)
    }

    /// Verify `qc` against an explicit committee `set`: quorum
    /// weight under its stakes plus the aggregate signature bound
    /// to `qc.epoch` — the epoch the signers actually signed for,
    /// never the local one (for a same-epoch QC they coincide;
    /// for a higher-epoch QC the claimed epoch is what makes the
    /// certificate valid handoff evidence). Both checks stay inside
    /// this helper so every caller — current-set or pending-set —
    /// pays the same admission bar.
    ///
    /// With `verify_signatures` off (conformance mode) the
    /// structural quorum check is the entire admission —
    /// `VerifiedQc::from_trusted` records that it ran.
    ///
    /// # Errors
    /// [`ConsensusError::InsufficientQuorum`] if the bitmap's stake
    /// is below `set`'s quorum, [`ConsensusError::SignerOutOfBounds`]
    /// if it indexes past `set`, or [`ConsensusError::InvalidQcSignature`]
    /// if the aggregate does not verify under `qc.epoch`.
    fn verify_qc_with(
        &self,
        set: &ValidatorSet,
        qc: &QuorumCertificate,
    ) -> Result<VerifiedQc, ConsensusError> {
        let voting_power = set.signer_stake(&qc.signer_bitmap);
        let required = set.quorum_stake();
        if voting_power < required {
            return Err(ConsensusError::InsufficientQuorum { voting_power, required });
        }
        if self.verify_signatures {
            crate::verify::verify_qc_signature(set, qc.epoch, qc)
        } else {
            Ok(VerifiedQc::from_trusted(qc.clone()))
        }
    }

    /// Resolve the crypto material the node's signature pool needs
    /// to verify `qc` off-thread — one [`crate::verify::QcVerifyMaterial`]
    /// per candidate committee, in the order `deliver_qc` tries
    /// them: the live set first, then the staged `next_validator_set`
    /// when `qc` claims an epoch beyond ours (certified-epoch
    /// adoption — the second candidate exists for that case alone).
    ///
    /// `None` in conformance mode (no crypto to offload — callers
    /// fall back to `deliver_qc`); an empty `Vec` when no
    /// candidate's bitmap resolves under any held set — the pool
    /// reports [`crate::verify::QcVerdict::Invalid`] for it, which
    /// is also the right verdict for a sub-quorum or bad-aggregate
    /// QC.
    ///
    /// The bitmap→keys resolution happens here, pump-side, because
    /// it reads the live committee; the worker only runs the
    /// threshold check + pairing over the resolved material.
    #[must_use]
    pub fn qc_verify_context(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<Vec<crate::verify::QcVerifyMaterial>> {
        if !self.verify_signatures {
            return None;
        }
        // Admission-doomed QCs route to the cheap inline path —
        // `deliver_qc` rejects a past-epoch or stale QC before any
        // crypto, so they must not burn a pool job either. The
        // apply side re-runs this gate on live state regardless.
        if self.check_qc_admission(qc).is_err() {
            return None;
        }
        let mut materials = Vec::with_capacity(2);
        if let Some(m) = crate::verify::qc_verify_material(&self.validator_set, qc.epoch, qc, false)
        {
            materials.push(m);
        }
        if qc.epoch > self.epoch
            && let Some(pending) = self.next_validator_set.as_ref()
            && let Some(m) = crate::verify::qc_verify_material(pending, qc.epoch, qc, true)
        {
            materials.push(m);
        }
        Some(materials)
    }

    /// Resolve the crypto material a timeout signature's carried
    /// `qc_high` verifies against. The carried QC's role here is
    /// *evidence of a lock the signer held*, not a view-advancing
    /// delivery — so [`OxideBft::qc_verify_context`]'s admission
    /// gate must not apply: the signer's `high_qc` is typically a
    /// QC we have already adopted, which admission would reject as
    /// stale, yet the timeout signature binds it and the TC it
    /// joins must carry it verbatim.
    ///
    /// Mirrors `collect_timeout_signature`'s inline screen exactly:
    /// material is resolved under the live committee only — the
    /// apply side's same-epoch check rejects anything the staged
    /// set could claim, so `Pending` verdicts cannot arise here.
    /// `None` in conformance mode (callers fall back to the inline
    /// path); an empty `Vec` when the bitmap does not resolve, which
    /// the pool correctly reports as
    /// [`crate::verify::QcVerdict::Invalid`].
    #[must_use]
    pub fn qc_evidence_verify_context(
        &self,
        qc: &QuorumCertificate,
    ) -> Option<Vec<crate::verify::QcVerifyMaterial>> {
        if !self.verify_signatures {
            return None;
        }
        Some(
            crate::verify::qc_verify_material(&self.validator_set, qc.epoch, qc, false)
                .into_iter()
                .collect(),
        )
    }

    /// Advance to the next view (happy path: one view per block).
    /// Public so the multi-node simulation can drive view advancement
    /// in lockstep across all validators. Syncs the pacemaker so that
    /// a later timeout fires for the correct view.
    pub fn advance_view(&mut self) {
        // Saturating: view = u64::MAX wraps to 0 without this guard,
        // which would make the validator vote in view 0 again (double
        // vote, safety violation). Saturation stalls the chain
        // instead — the only recovery is epoch rotation.
        self.observe_completed_view();
        self.current_view = self.current_view.saturating_next();
        self.pacemaker.sync_to_view(self.current_view);
        self.pacemaker.on_progress();
        // Clear per-view state. Stale votes from the previous view
        // that arrive late over the network must not pollute the
        // new view's quorum accounting. Stale timeout signatures
        // must not leak into the new view's TC aggregation.
        self.clear_per_view_state();
        // This advance was not driven by a TC — there is no
        // successor evidence to embed in the next proposal.
        self.last_tc = None;
    }

    /// Jump forward to `view` if it is higher than the current view.
    /// This is the catch-up path for validators that fell behind
    /// (e.g., after a restart or partition). It syncs the pacemaker
    /// and clears stale votes, but does NOT trigger a view change
    /// event — the caller is responsible for any subsequent actions
    /// (e.g., collecting a timeout signature for the new view).
    ///
    /// Returns `true` if the view was advanced, `false` if `view` is
    /// not higher than the current view (no-op).
    pub fn sync_to_view(&mut self, view: View) -> bool {
        if view.value() <= self.current_view.value() {
            return false;
        }
        // A sync-driven jump measures "how long this replica went
        // without progress", not a round-trip — reset the mark
        // without feeding the EWMA.
        self.restart_view_mark();
        self.current_view = view;
        self.pacemaker.sync_to_view(self.current_view);
        self.pacemaker.on_progress();
        self.clear_per_view_state();
        // Sync-driven advance carries no TC evidence.
        self.last_tc = None;
        true
    }

    /// Drive one propose-vote-QC-commit cycle (single-validator mode).
    /// Returns `true` if a block was proposed, `false` if idle.
    fn step(&mut self) -> bool {
        // Solo mode pauses while the execution lane is saturated —
        // the self-vote below bypasses `vote()`, so without this gate
        // a solo validator would keep proposing (and queueing
        // unexecutable blocks) while its own lane is behind.
        if self.app.exec_saturated() {
            return false;
        }
        // Propose.
        let Some((header, proposal)) = self.propose() else {
            return false;
        };
        let block_hash = Self::block_hash(&header);

        // Self-vote — same durable order as `vote_if_eligible`
        // (C10): record the locks, persist them, and only then sign.
        // The old order signed first and never appended the WAL, so
        // a crash after the signature left restart state unaware the
        // vote was ever cast.
        self.last_voted_view = Some(self.current_view);
        // Record the per-height lock for the self-vote as well.
        self.voted_at_height.insert(header.height.value(), block_hash);
        if self.append_wal().is_err() {
            // Durability failed: withhold the vote entirely — no
            // signature may leave while its locks are undurable.
            return false;
        }
        let Some(signature) = self.sign_vote(self.current_view, block_hash) else {
            return false;
        };
        let (attestation, attestation_sig) = self.build_attestation();
        let vote = Vote {
            view: self.current_view,
            phase: VotePhase::Prepare,
            block_hash,
            signature,
            attestation,
            attestation_sig,
        };

        // Form QC (single validator: quorum = 1). Stage 5: aggregate
        // the real signature(s) if a key is set.
        let bitmap_len = self.validator_set.n().div_ceil(8);
        let mut signer_bitmap = vec![0u8; bitmap_len];
        let idx = usize::from(self.validator_index);
        signer_bitmap[idx / 8] |= 1u8 << (idx % 8);
        let aggregate_signature = if self.signer.is_some() {
            // Real BLS: aggregate the single self-vote.
            // H6 fix: propagate aggregation errors.
            match crypto::aggregate(&[vote.signature]) {
                Ok(agg) => agg,
                Err(_) => return false, // aggregation failed — can't form QC
            }
        } else {
            AggregateSignature::ZERO
        };
        let qc = QuorumCertificate {
            view: self.current_view,
            phase: VotePhase::Prepare,
            block_hash,
            epoch: self.epoch,
            signer_bitmap,
            aggregate_signature,
        };

        // C4 fix: don't panic on deliver_qc failure. In single-
        // validator mode the QC was self-formed and should always
        // verify, but a panic here would be a DoS vector if the
        // invariant is violated. Log and return instead.
        if let Err(e) = self.deliver_qc(qc) {
            // Self-formed QC verification failed — this indicates a
            // bug in the signing/verification logic, not a byzantine
            // attack. We log the error and continue rather than
            // panicking.
            eprintln!("WARN: self-formed QC verification failed: {e:?}");
            return false;
        }

        // Advance the view.
        self.advance_view();
        let _ = (header, proposal, vote); // suppress unused warnings
        true
    }
}

impl ConsensusEngine for OxideBft {
    fn submit_tx(&mut self, tx: TxBytes) -> MempoolAck {
        self.app.ingest_tx(tx)
    }

    fn run_until_idle(&mut self) {
        // Drive propose-vote-commit cycles until no more work.
        while self.step() {}
    }

    fn finalized_height(&self) -> Option<Height> {
        // `last_committed` is the authoritative high-water mark —
        // it survives WAL recovery, while `finalized` is only the
        // in-memory window of recently committed blocks. A
        // restarted node that reports 0 here would misrepresent a
        // recovered tip as unsynced (RPC `eth_blockNumber`, fleet
        // progress logs) until the next commit lands.
        let fin = self.finalized.keys().next_back().copied();
        let committed = self.last_committed.map(|(_, h)| h.value());
        fin.max(committed).map(Height::new)
    }

    fn finalized_block(&self, height: Height) -> Option<FinalizedBlock> {
        self.finalized.get(&height.value()).cloned()
    }

    fn divergence(&self) -> Option<types::ExecDivergence> {
        // `OxideBft::divergence` is the inherent accessor; calling it
        // by UFCS keeps the trait method a pure mirror rather than
        // duplicating the field read.
        OxideBft::divergence(self).copied()
    }

    fn exec_certificates(&self) -> Vec<types::ExecCertificate> {
        OxideBft::exec_certificates(self)
    }
}
#[cfg(test)]
mod tests;
