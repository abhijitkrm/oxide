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
    BlockHeader, ExecCertificate, FinalizedBlock, MempoolAck, Proposal, QuorumCertificate,
    StateAttestation, TimeoutCertificate, TxBytes, Verdict, Vote, VotePhase,
};

use crate::validator::{ValidatorIndex, ValidatorSet};

/// Convert a `ValidatorIndex` to a `Hash` for the proposer field.
/// The proposer is identified by the hash of its public key; stage 5
/// replaces this with the actual public key hash.
fn proposer_hash(idx: ValidatorIndex) -> Hash {
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
/// builds an updated `ValidatorSet` and schedules a rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyChangeError {
    /// A key in the change list is not exactly 48 bytes (BLS12-381
    /// compressed public key length).
    InvalidKeyLength,
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
            Self::InvalidKeyLength => write!(f, "key change key is not 48 bytes"),
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
    /// This engine's index in the validator set.
    validator_index: ValidatorIndex,
    /// This engine's BLS secret key (stage 5). Used to sign votes and
    /// timeout messages. `None` in conformance mode (no real signing).
    secret_key: Option<crypto::BlsSecretKey>,
    /// The pacemaker (stage 2). Drives view changes on timeout.
    pacemaker: crate::pacemaker::Pacemaker,
    /// The highest QC the engine has seen. Carried in the next
    /// proposal's `high_qc` field (the pipeline's chain-link).
    high_qc: Option<QuorumCertificate>,
    /// The highest view the engine has voted in (prevents double-
    /// voting; a safety invariant). `None` = never voted.
    last_voted_view: Option<View>,
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
    last_tc: Option<TimeoutCertificate>,
    /// Collected timeout signatures for the current view (TC safety).
    /// `None` = no timeout signature from that validator. Indexed by
    /// `ValidatorIndex`. Used to aggregate the TC's signature when
    /// quorum is reached.
    timeout_signatures: Vec<Option<Signature>>,
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
    /// The block budget the engine passes to `app.prepare_proposal`.
    /// Configured via [`OxideBft::with_block_budget`]; defaults to
    /// [`types::CHAIN_BLOCK_BUDGET`]. The TOML
    /// `consensus.max_block_bytes` / `consensus.max_block_gas`
    /// values reach the proposal path through this field — before it
    /// existed they parsed fine and then silently did nothing.
    block_budget: types::BlockBudget,
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
            validator_index,
            secret_key: None,
            pacemaker,
            high_qc: None,
            last_voted_view: None,
            voted_at_height: BTreeMap::new(),
            blocks: HashMap::new(),
            finalized: BTreeMap::new(),
            commit_listener: None,
            last_committed: None,
            next_height: Height::new(0),
            current_view: initial_view,
            epoch,
            votes: vec![None; n],
            vote_count: 0,
            vote_stake: 0,
            exec_attest_pool: std::collections::BTreeMap::new(),
            exec_certs: std::collections::BTreeMap::new(),
            verified_exec_certs: std::collections::BTreeMap::new(),
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
            block_budget: types::CHAIN_BLOCK_BUDGET,
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
        self.secret_key = Some(sk);
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
            if let Some(set) = entry.validator_set {
                if set != self.validator_set {
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
                    if let Some(ref key) = self.secret_key {
                        if let Some(idx) = self.validator_set.index_of_key(&key.public_key()) {
                            self.validator_index = idx;
                        }
                    }
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
    fn wal_entry(&self, include_set: bool) -> crate::wal::WalEntry {
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
    fn append_wal(&mut self) -> Result<(), crate::wal::WalError> {
        self.append_wal_full(false)
    }

    /// [`append_wal`](Self::append_wal) with control over the
    /// validator-set trailer: `include_set` records the committed
    /// set in this entry. Epoch transitions pass `true` so recovery
    /// restores membership and epoch atomically from the same
    /// fsync'd record; ordinary per-vote appends pass `false` — the
    /// set is unchanged and ~n×76 bytes of redundancy per entry
    /// buys nothing.
    fn append_wal_full(&mut self, include_set: bool) -> Result<(), crate::wal::WalError> {
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

    /// Whether this engine may still emit signatures. `false` once a
    /// WAL append has failed (C10): durable signing must not fail
    /// open, so a WAL-failed validator goes silent and stays silent
    /// until restarted on healthy storage. Always `true` for engines
    /// with no WAL attached — they never promised durability.
    #[must_use]
    pub fn signing_healthy(&self) -> bool {
        !self.wal_failed
    }

    /// The budget the engine uses when assembling proposals. Ceiling 1:
    /// defaults to the chain-configured limit from
    /// `types::CHAIN_BLOCK_BUDGET` (10 GG/block, 16 MiB) so the
    /// engine, the EVM, and the tests all agree on a single source of
    /// truth (plan.md §3); `with_block_budget` overrides it from
    /// parsed config.
    #[must_use]
    pub fn block_budget(&self) -> types::BlockBudget {
        self.block_budget
    }

    /// Current view.
    #[must_use]
    pub fn current_view(&self) -> View {
        self.current_view
    }

    /// The highest QC the engine has seen, if any.
    ///
    /// Used by pipelined drivers to check whether the leader for the
    /// next view has the QC needed to propose (the QC's view must
    /// match `current_view` — the leader builds the next block on
    /// this QC as `prev_block`).
    #[must_use]
    pub fn high_qc(&self) -> Option<&QuorumCertificate> {
        self.high_qc.as_ref()
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

    /// Schedule an epoch rotation (stage 6). The new validator set
    /// takes over after the old set commits the last block of the
    /// current epoch. This is the first phase of the two-phase
    /// handoff: announce the new set, continue with the old set.
    ///
    /// # Errors
    /// Returns `EpochRotationError::AlreadyPending` if a rotation is
    /// already pending (the caller must wait for it to complete).
    pub fn schedule_rotation(&mut self, new_set: ValidatorSet) -> Result<(), EpochRotationError> {
        if self.next_validator_set.is_some() {
            return Err(EpochRotationError::AlreadyPending);
        }
        self.next_validator_set = Some(new_set);
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
        self.validator_set = new_set;
        // Re-seat our own index under the new committee — removals
        // shift positions and the genesis index may now name a
        // different validator. Matching by BLS key is the honest
        // remap (it is the identity we can actually sign with).
        // `None` means we were removed: keep the stale index — our
        // signatures fail verification against the new set, which
        // is fail-closed silence, not authority.
        if let Some(ref key) = self.secret_key {
            if let Some(idx) = self.validator_set.index_of_key(&key.public_key()) {
                self.validator_index = idx;
            }
        }
        // Saturating: epoch = u64::MAX would wrap to 0, confusing
        // the epoch boundary. Saturation is safe — the chain is
        // already dead at epoch u64::MAX.
        self.epoch = self.epoch.saturating_next();
        self.current_view = View::new(0);
        self.last_voted_view = None;
        self.high_qc = None;
        // Per-height vote locks are evidence of the old epoch's
        // consensus instance: heights continue across the boundary
        // (the anchor in `last_committed`), but stale locks must not
        // constrain the new epoch's proposals at those heights.
        self.voted_at_height.clear();
        self.last_tc = None;
        self.votes = vec![None; self.validator_set.n()];
        self.vote_count = 0;
        self.vote_stake = 0;
        self.timeout_signatures = vec![None; self.validator_set.n()];
        // Execution certificates, pooled attestations, and cached
        // cert verifications are all epoch-bound: the signatures
        // commit to `(height, root, epoch)` and verify against the
        // signing epoch's validator set, which is gone after this
        // swap. Stale certs are unverifiable, stale pool entries
        // could only aggregate into certs that fail verification
        // (a leader embedding one would withhold every honest
        // vote), and cached verdicts were computed against the old
        // set. Drop all of it — the new epoch's attestations
        // rebuild the pool from scratch.
        self.exec_attest_pool.clear();
        self.exec_certs.clear();
        self.verified_exec_certs.clear();
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

    /// Apply pending validator key changes and schedule an epoch
    /// rotation (staking `KEY_CHANGE` → `schedule_rotation` bridge).
    ///
    /// For each `(address, new_key_bytes)` in `changes`, finds the
    /// validator index via `validator_set.index_of(address)`,
    /// replaces the BLS key, and builds an updated `ValidatorSet`
    /// preserving stakes and addresses. The updated set is scheduled
    /// via `schedule_rotation` — the two-phase handoff completes at
    /// the epoch boundary when `complete_rotation` swaps it in.
    ///
    /// Returns the number of key changes applied. Returns `Ok(0)` if
    /// `changes` is empty.
    ///
    /// # Errors
    /// - `KeyChangeError::InvalidKeyLength` — a key is not 48 bytes.
    /// - `KeyChangeError::InvalidSet` — the updated set failed
    ///   construction.
    /// - `KeyChangeError::RotationAlreadyPending` — a rotation is
    ///   already scheduled.
    pub fn apply_key_changes(
        &mut self,
        changes: &[(primitives::Address, Vec<u8>)],
    ) -> Result<usize, KeyChangeError> {
        self.apply_epoch_changes(changes, &[], &[])
    }

    /// Apply pending validator set changes to the validator set and
    /// schedule the result for the next epoch rotation.
    ///
    /// `changes.adds` is a list of `(staking_address, bls_public_key,
    /// stake)` tuples for new validators. `changes.removes` is a list
    /// of staking addresses to remove.
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
    /// - [`KeyChangeError::InvalidKeyLength`] if a `bls_public_key` is
    ///   not exactly 48 bytes.
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
        adds: &[(primitives::Address, Vec<u8>, u64)],
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
        key_changes: &[(primitives::Address, Vec<u8>)],
        adds: &[(primitives::Address, Vec<u8>, u64)],
        removes: &[primitives::Address],
    ) -> Result<(ValidatorSet, usize), KeyChangeError> {
        let mut keys = self.validator_set.public_keys().to_vec();
        let mut stakes = self.validator_set.stakes().to_vec();
        let mut addresses = self.validator_set.validator_addresses().to_vec();
        let mut applied = 0usize;

        // 1. Key replacements — against the original indices.
        for (addr, key_bytes) in key_changes {
            let new_key = crypto::bls::PublicKey::from_slice(key_bytes)
                .map_err(|_| KeyChangeError::InvalidKeyLength)?;
            if let Some(idx) = self.validator_set.index_of(addr) {
                keys[usize::from(idx)] = new_key;
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
        for (addr, key_bytes, stake) in adds {
            if !remaining.insert(*addr) {
                continue;
            }
            let new_key = crypto::bls::PublicKey::from_slice(key_bytes)
                .map_err(|_| KeyChangeError::InvalidKeyLength)?;
            if *stake == 0 {
                return Err(KeyChangeError::InvalidSet);
            }
            keys.push(new_key);
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
        key_changes: &[(primitives::Address, Vec<u8>)],
        adds: &[(primitives::Address, Vec<u8>, u64)],
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
        self.schedule_rotation(new_set).map_err(|_| KeyChangeError::RotationAlreadyPending)?;
        // The pending set is already the old committee's committed
        // output — complete immediately so the transition takes
        // effect at this height boundary on every node.
        let _ = self.rotate_epoch();
        Ok(applied)
    }

    /// Whether this engine is the leader for the current view.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.validator_set.leader(self.current_view) == self.validator_index
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

    /// Returns the number of timeout signatures collected so far for
    /// the current view. Used by the devnet consensus loop for debug
    /// logging.
    #[must_use]
    pub fn timeout_signer_count_debug(&self) -> usize {
        self.pacemaker.timeout_signer_count()
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
    fn signer_keys_and_power(
        &self,
        bitmap: &[u8],
    ) -> Result<(Vec<crypto::bls::PublicKey>, u64), ConsensusError> {
        let mut signer_pks: Vec<crypto::bls::PublicKey> =
            Vec::with_capacity(self.validator_set.n());
        let mut voting_power = 0u64;
        for (i, byte) in bitmap.iter().enumerate() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    let idx = u16::try_from(i * 8 + bit)
                        .map_err(|_| ConsensusError::SignerOutOfBounds)?;
                    let pk = self
                        .validator_set
                        .validator(idx)
                        .map_err(|_| ConsensusError::SignerOutOfBounds)?;
                    voting_power = voting_power.saturating_add(
                        self.validator_set
                            .stake(idx)
                            .map_err(|_| ConsensusError::SignerOutOfBounds)?,
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
    /// [`signer_keys_and_power`](Self::signer_keys_and_power) minus
    /// the allocation.
    fn bitmap_meets_quorum(&self, bitmap: &[u8]) -> bool {
        self.validator_set.signer_stake(bitmap) >= self.validator_set.quorum_stake()
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
        // C10: a proposal carries the leader's `proposer_signature` —
        // it is a signature, so a WAL-failed validator must not
        // produce one. Going silent lets the view time out and a
        // healthy leader take over.
        if self.wal_failed {
            return None;
        }
        let proposal = self.app.prepare_proposal(&self.block_budget);
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
        // produce empty blocks. The 2-chain commit rule only needs a
        // child block when there's actual work to commit.
        if !has_pending_txs && !work_outstanding && self.next_height != Height::new(0) {
            if std::env::var_os("OXIDE_DEBUG_PROPOSE").is_some() {
                eprintln!(
                    "propose() idle: view={:?} next_height={:?} highqc={:?} has_txs={has_pending_txs} work_outstanding={work_outstanding}",
                    self.current_view,
                    self.next_height,
                    self.high_qc.as_ref().map(|q| q.view.value()),
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
                let Some((parent, _)) = self.blocks.get(&qc.block_hash) else {
                    if std::env::var_os("OXIDE_DEBUG_PROPOSE").is_some() {
                        eprintln!(
                            "propose() blocked: view={:?} highqc_view={:?} highqc_block={:?} unknown — waiting for block",
                            self.current_view,
                            qc.view.value(),
                            qc.block_hash,
                        );
                    }
                    return None;
                };
                (parent.height.saturating_next(), qc.block_hash)
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
            high_qc: self.high_qc.clone(),
            // Embed the TC that brought us into this view, if any
            // (spec §view-changes: "the next leader embeds the TC in
            // its proposal, proving it is the legitimate successor").
            // It must directly justify this view (`tc.view + 1 ==
            // current_view`) and belong to this epoch — a stale TC
            // from an earlier view or epoch is not evidence for this
            // succession. Voters use it to release same-height vote
            // locks left over from the timed-out view.
            timeout_cert: self.last_tc.clone().filter(|tc| {
                tc.epoch == self.epoch && tc.view.saturating_next() == self.current_view
            }),
            proposer: proposer_hash(self.validator_set.leader(self.current_view)),
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
        // C3 fix: sign the header with the leader's BLS secret key.
        // The signature authenticates that the claimed proposer
        // actually created this proposal — preventing a byzantine
        // node from fabricating a proposal in another validator's
        // name. In conformance mode (no secret key), the signature
        // stays `None` and `vote()` skips verification.
        if let Some(sk) = &self.secret_key {
            let signing_hash = Self::proposal_signing_hash(&header);
            let sig = sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes());
            header.proposer_signature = Some(sig);
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

    /// Validator: vote on a proposal. Returns the vote, or `None` if
    /// the validator already voted in this view (safety: no double-
    /// voting) or the proposal is invalid.
    ///
    /// The validator stores the block for later commit lookup. If a
    /// BLS secret key is set (stage 5), the vote is signed with real
    /// BLS; otherwise `Signature::ZERO` is used (conformance mode).
    pub fn vote(&mut self, header: &BlockHeader, proposal: &Proposal) -> Option<Vote> {
        let block_hash = self.authenticate_proposal(header)?;
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
            let mut buf = Vec::new();
            proposal.encode(&mut buf);
            if types::shard::commitment(&buf, self.validator_set.n(), self.erasure_k())
                != header.body_commitment
            {
                return None;
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
        self.vote_if_eligible(header, block_hash, Some(proposal))
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
        let block_hash = self.authenticate_proposal(header)?;
        // Insert only when vacant: a `Complete` body already stored
        // must never be downgraded to `Awaiting`.
        self.blocks.entry(block_hash).or_insert_with(|| (header.clone(), BlockBody::Awaiting));
        self.vote_if_eligible(header, block_hash, None)
    }

    /// Shared proposal authentication for both vote paths: sanity
    /// bounds, expected-leader + signature verification, and the
    /// observed-height watermark update. Returns the block hash when
    /// the header is genuine; `None` means the caller must not vote
    /// AND must not store anything — an unauthenticated header is
    /// worthless for both voting and the commit walk.
    fn authenticate_proposal(&mut self, header: &BlockHeader) -> Option<Hash> {
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
            let expected_leader = self.validator_set.leader(header.view);
            let expected_proposer = proposer_hash(expected_leader);
            if header.proposer != expected_proposer {
                return None;
            }
            let Some(sig) = &header.proposer_signature else {
                return None;
            };
            let leader_pk = self.validator_set.validator(expected_leader).map_err(|_| ()).ok()?;
            let signing_hash = Self::proposal_signing_hash(header);
            crypto::verify(sig, crypto::hash::Domain::Proposal, signing_hash.as_bytes(), leader_pk)
                .ok()?;
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
    fn parent_timestamp(&self, header: &BlockHeader) -> Option<u64> {
        if let Some((parent, _)) = self.blocks.get(&header.prev_block) {
            return Some(parent.timestamp);
        }
        self.last_committed
            .filter(|(hash, _)| *hash == header.prev_block)
            .and_then(|(_, height)| self.finalized.get(&height.value()))
            .map(|block| block.context.timestamp_ms)
    }

    /// Shared vote-eligibility chain for both vote paths. `body` is
    /// `Some` for the complete-proposal path (`vote`) and `None` for
    /// the commitment path (`vote_header`): the app's static
    /// `process_proposal` check needs body bytes, so the commitment
    /// path defers it to `supply_body`'s certification — a notarized
    /// block whose body fails certification can never finalize.
    fn vote_if_eligible(
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
        // view. A TC proves quorum-certified that the view ended
        // undecided — the only way a same-height conflict can exist
        // at all (a formed QC would have moved `high_qc` forward,
        // changing the required `prev_block`/`height`). Without the
        // release, one equivocating leader could split the vote and
        // permanently wedge the height: neither side could gather a
        // quorum again. Safety is preserved because QC adoption is
        // view-monotonic (`deliver_qc` rejects stale views): if a
        // hidden QC for the locked block exists, its later-view
        // rival's adoption still wins, so only one of the two
        // notarizations can gather the child-chain votes needed to
        // commit.
        if self
            .voted_at_height
            .get(&header.height.value())
            .is_some_and(|voted| *voted != block_hash)
            && !self.proposal_tc_releases_lock(header)
        {
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
        if let Some(hqc) = &header.high_qc {
            if header.prev_block != hqc.block_hash {
                return None;
            }
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
        if header.timestamp != 0 {
            if let Some(parent_ts) = self.parent_timestamp(header) {
                if parent_ts != 0 && header.timestamp < parent_ts {
                    return None;
                }
            }
        }
        // Tail-fork resistance / extends-highest-QC rule
        // (docs/oxidebft-spec.md §4): reject proposals that don't
        // extend our highest QC. A leader that forks away a notarized
        // block must be bypassed, not rewarded.
        //
        // A proposal extends our highest QC when its `high_qc` is at
        // least as recent as ours (`prop_qc.view >= our_high_qc.view`).
        // This covers three legitimate cases:
        //   1. The proposal's QC *is* our `high_qc` (happy path: the
        //      leader built on the same QC — views are equal).
        //   2. The proposal's QC is *newer* than ours (view change:
        //      the new leader saw a QC we missed and built on it —
        //      `prop_qc.view > our_high_qc.view`). Accepting this is
        //      what lets the chain advance after a view change and is
        //      the core of tail-fork *resistance*: a validator on a
        //      stalling fork must still vote for a proposal that
        //      extends the highest QC it has seen, even if that QC
        //      arrived via a proposal rather than directly.
        //   3. The proposal's block chain traces back to our
        //      `high_qc`'s block (transitively). The view-ordering
        //      check below is the cheap, sound over-approximation of
        //      this: any chain extending our `high_qc` carries a QC
        //      with view >= ours, so the view test admits all
        //      extending chains while rejecting stale forks.
        //
        // A leader with a *lower* `high_qc` view is forking away from
        // a more recent notarized block — reject it.
        //
        // Exception: at genesis (no high_qc yet), any proposal is
        // accepted.
        if let Some(our_high_qc) = &self.high_qc {
            match &header.high_qc {
                // Proposal carries a QC older than ours: it extends a
                // stale fork, not our highest QC. Reject.
                Some(prop_qc) if prop_qc.view < our_high_qc.view => {
                    return None;
                }
                // Proposal has no high_qc but we have one: the
                // leader is proposing a fork that ignores our QC.
                None => return None,
                // prop_qc.view >= our_high_qc.view: the proposal
                // extends or advances our highest QC — accept.
                _ => {}
            }
            // HIGH fix: bind the proposal's parent to our high QC.
            // The proposal's `prev_block` must equal the block hash
            // in our `high_qc` — the leader must build on the same
            // notarized block we hold. Without this, a byzantine
            // leader could propose a block with a valid high_qc view
            // but a `prev_block` that doesn't match, creating a
            // phantom chain that doesn't extend any real block.
            // Exception: at genesis (prev_block = ZERO, no high_qc
            // yet), this is the expected case.
            if header.prev_block != our_high_qc.block_hash {
                return None;
            }
            // Height continuity: the stamped height must be exactly
            // the parent's height + 1. `header.height` is a
            // proposer-chosen field — without this check a Byzantine
            // leader can stamp an arbitrary future height, get the
            // block committed at that height (creating a finalized
            // gap and divergent `finalized_height()` across nodes),
            // and — worse — the voters who signed it become
            // per-height-locked at the height the honest chain still
            // needs, permanently wedging quorum there. The parent is
            // our highQC block (enforced above), so its height must
            // be known: if we adopted a QC for a block whose header
            // we never saw, we cannot verify continuity and must
            // refuse until the block arrives via catch-up gossip.
            let (parent_header, _) = self.blocks.get(&header.prev_block)?;
            if header.height != parent_header.height.saturating_next() {
                return None;
            }
        } else {
            // No highQC: the only voteable proposal extends the
            // committed anchor — height 0 / zero-hash parent at true
            // genesis, or the last committed block at the
            // post-rotation boundary (rotation resets `high_qc` but
            // heights continue). Anything else is a forged chain:
            // without an anchor check, a Byzantine leader could
            // attach a made-up parent hash and stamp any height.
            match self.last_committed {
                Some((anchor_hash, anchor_height)) => {
                    if header.prev_block != anchor_hash
                        || header.height != anchor_height.saturating_next()
                    {
                        return None;
                    }
                }
                None => {
                    if header.height != Height::new(0) || header.prev_block != Hash::ZERO {
                        return None;
                    }
                }
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
            if self.verify_signatures && self.verify_qc_signature(hqc).is_err() {
                return None;
            }
        }
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
        if self.verify_signatures {
            if let Some(cert) = &header.exec_cert {
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
                // height.) A mismatch on a *verified* cert means a
                // stake supermajority really attested a root we did
                // not compute — confirmed divergence; refuse to
                // extend it.
                let local = self.app.attest_state(cert.height)?;
                if local.root != cert.state_root {
                    return None;
                }
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
        if let Some(qc) = self.high_qc.clone() {
            if let Some((tip, _)) = self.blocks.get(&qc.block_hash).cloned() {
                self.commit_walk(&tip);
            }
        }
        Ok(())
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
        let mut msg = [0u8; 49];
        msg[..8].copy_from_slice(&view.value().to_le_bytes());
        msg[8] = phase_byte;
        msg[9..41].copy_from_slice(block_hash.as_bytes());
        msg[41..49].copy_from_slice(&self.epoch.value().to_le_bytes());
        msg
    }

    /// Get the current pipeline phase as a byte. In the current
    /// oxideBFT implementation, all votes are in the generic "vote"
    /// phase (the engine doesn't distinguish prepare/pre-commit/
    /// commit in the signing path yet — the phase is carried in the
    /// `Vote` struct and will be bound to the signature in a future
    /// hardening pass). For now, we use 0 as a placeholder.
    fn current_phase_byte() -> u8 {
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
    fn sign_vote(&self, view: View, block_hash: Hash) -> Option<Signature> {
        if self.wal_failed {
            return None;
        }
        Some(match &self.secret_key {
            Some(sk) => {
                let phase_byte = Self::current_phase_byte();
                let msg = self.vote_signing_message(view, phase_byte, &block_hash);
                sk.sign(crypto::hash::Domain::Vote, &msg)
            }
            None => Signature::ZERO,
        })
    }

    /// The message a validator signs for an execution attestation:
    /// `(height, state_root, epoch)` — 48 bytes. The epoch binding
    /// prevents attestation replay across epoch boundaries (same
    /// defense as the vote signing message, C3).
    fn attestation_signing_message(&self, height: Height, root: &Hash) -> [u8; 48] {
        let mut msg = [0u8; 48];
        msg[..8].copy_from_slice(&height.value().to_le_bytes());
        msg[8..40].copy_from_slice(root.as_bytes());
        msg[40..48].copy_from_slice(&self.epoch.value().to_le_bytes());
        msg
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

    fn build_attestation(&mut self) -> (Option<StateAttestation>, Option<Signature>) {
        // C10: an attestation is a signature too — a WAL-failed
        // validator goes fully silent rather than emitting any
        // signature whose surrounding safety state is undurable.
        if self.wal_failed {
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
        if let Some((cached_att, cached_epoch, cached_sig)) = &self.last_attestation {
            if cached_att.height == att.height
                && cached_att.root == att.root
                && *cached_epoch == self.epoch
            {
                return (Some(*cached_att), Some(*cached_sig));
            }
        }
        let sig = match &self.secret_key {
            Some(sk) => {
                let msg = self.attestation_signing_message(att.height, &att.root);
                sk.sign(crypto::hash::Domain::ExecAttest, &msg)
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
    fn verify_exec_cert(&self, cert: &ExecCertificate) -> Result<(), ConsensusError> {
        // The certificate's epoch must equal this engine's epoch:
        // the signed message binds `(height, root, epoch)` and the
        // bitmap indexes the *current* validator set — a cert from
        // any other epoch is unverifiable here (its signers index a
        // different set and its signatures commit to a different
        // epoch), not merely stale. Checked before the bitmap walk
        // so an out-of-epoch bitmap can never index the wrong set.
        if cert.epoch != self.epoch {
            return Err(ConsensusError::CertEpochMismatch {
                cert_epoch: cert.epoch,
                epoch: self.epoch,
            });
        }
        let (signer_pks, voting_power) = self.signer_keys_and_power(&cert.signer_bitmap)?;
        if voting_power < self.validator_set.quorum_stake() {
            return Err(ConsensusError::InsufficientQuorum {
                voting_power,
                required: self.validator_set.quorum_stake(),
            });
        }
        let msg = self.attestation_signing_message(cert.height, &cert.state_root);
        crypto::aggregate_verify(
            &cert.aggregate_signature,
            crypto::hash::Domain::ExecAttest,
            &msg,
            &signer_pks,
        )
        .map_err(|_| ConsensusError::InvalidQcSignature)
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
    fn exec_cert_verified(&mut self, cert: &ExecCertificate) -> bool {
        if self.verified_exec_certs.get(&cert.height.value()) == Some(cert) {
            return true;
        }
        if self.verify_exec_cert(cert).is_err() {
            return false;
        }
        self.verified_exec_certs.insert(cert.height.value(), cert.clone());
        true
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
        let idx = usize::from(voter);
        if idx >= self.votes.len() {
            return Err(ConsensusError::InvalidVoteSignature { voter });
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
            return Ok(());
        }
        // Already collected — idempotent (not an error, just a no-op).
        if self.votes[idx].is_some() {
            return Ok(());
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
            let pk = self
                .validator_set
                .validator(voter)
                .map_err(|_| ConsensusError::InvalidVoteSignature { voter })?;
            let phase_byte = vote.phase as u8;
            let msg = self.vote_signing_message(vote.view, phase_byte, &vote.block_hash);
            crypto::verify(&vote.signature, crypto::hash::Domain::Vote, &msg, pk)
                .map_err(|_| ConsensusError::InvalidVoteSignature { voter })?;
        }

        // Hardening: check that this vote agrees with the first vote
        // collected for this view. All votes in a QC must be for the
        // same (view, block_hash) — otherwise the QC does not
        // represent agreement on a single block.
        if let Some(first) = self.votes.iter().find_map(Option::as_ref) {
            if first.view != vote.view || first.block_hash != vote.block_hash {
                return Err(ConsensusError::ConflictingVote {
                    voter,
                    view: vote.view,
                    expected_block: first.block_hash,
                    actual_block: vote.block_hash,
                });
            }
        }

        // Harvest the execution attestation (if any) for exec-cert
        // aggregation. Only signature-verified attestations count —
        // a forged attestation that slipped into an aggregate would
        // make the resulting cert fail verification at proposal
        // time, letting one byzantine voter poison a whole block's
        // embedded cert. The vote itself is unaffected either way:
        // attestations ride along as best-effort signals and are
        // dropped individually when invalid.
        if self.verify_signatures {
            if let (Some(att), Some(sig)) = (&vote.attestation, &vote.attestation_sig) {
                // Skip the BLS verify (~1.5ms) when a cert already
                // exists for this height — quorum is proven, so
                // further attestations are redundant. Attestations
                // for the committed tip are NOT redundant: the
                // normal steady state is voters attesting their
                // newest executed (= committed) block, and that is
                // precisely the root the next proposals certify.
                let valid = !self.exec_certs.contains_key(&att.height.value())
                    && self.validator_set.validator(voter).is_ok_and(|pk| {
                        let msg = self.attestation_signing_message(att.height, &att.root);
                        crypto::verify(sig, crypto::hash::Domain::ExecAttest, &msg, pk).is_ok()
                    });
                if valid {
                    let bucket = self
                        .exec_attest_pool
                        .entry(att.height.value())
                        .or_default()
                        .entry(att.root)
                        .or_default();
                    if !bucket.iter().any(|(v, _)| *v == voter) {
                        bucket.push((voter, *sig));
                        // Quorum of identical attestations measured
                        // in voting power — the same stake-weighted
                        // threshold the cert will be validated
                        // against downstream. Checked on every
                        // insert; the `exec_certs.contains_key` gate
                        // above makes a formed cert stop absorbing
                        // further attestations, so this aggregates
                        // exactly once.
                        let bucket_power: u64 = bucket
                            .iter()
                            .map(|(v, _)| self.validator_set.stake(*v).unwrap_or(0))
                            .sum();
                        if bucket_power >= self.validator_set.quorum_stake() {
                            let sigs: Vec<Signature> = bucket.iter().map(|(_, s)| *s).collect();
                            if let Ok(aggregate_signature) = crypto::aggregate(&sigs) {
                                let bitmap_len = self.validator_set.n().div_ceil(8);
                                let mut signer_bitmap = vec![0u8; bitmap_len];
                                for (v, _) in bucket.iter() {
                                    let i = usize::from(*v);
                                    signer_bitmap[i / 8] |= 1u8 << (i % 8);
                                }
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
                }
            }
        }

        self.votes[idx] = Some(vote);
        self.vote_count += 1;
        // `voter` is in-range (checked against `votes.len()` above),
        // so the stake lookup cannot fail.
        self.vote_stake =
            self.vote_stake.saturating_add(self.validator_set.stake(voter).unwrap_or(0));
        Ok(())
    }

    /// Whether `aggregate` verifies against the public keys of the
    /// validators whose votes are currently buffered, over the buffered
    /// vote message.
    ///
    /// All buffered votes are for one `(view, phase, block_hash)` — the
    /// `ConflictingVote` rule in `collect_vote` guarantees it — so a
    /// single message reconstructs what the aggregate must cover.
    fn buffered_aggregate_verifies(&self, aggregate: &AggregateSignature) -> bool {
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
    fn aggregate_collected_votes(&mut self) -> Option<AggregateSignature> {
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
        // If no secret key is set (conformance mode), use ZERO.
        // H6 fix: propagate aggregation errors instead of silently
        // replacing with ZERO (which would produce an invalid QC).
        let aggregate_signature = if self.secret_key.is_some() {
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

        // Clear the vote buffer for the next view.
        self.votes.fill(None);
        self.vote_count = 0;
        self.vote_stake = 0;

        Some(qc)
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
        // Hardening: enforce monotonic view progression. A QC for a
        // view ≤ the current high_qc's view is stale — a byzantine
        // leader could replay it to regress the engine's state.
        // Exception: the first QC (when high_qc is None) is always
        // accepted.
        if let Some(current_high_qc) = &self.high_qc {
            if qc.view.value() <= current_high_qc.view.value() {
                return Err(ConsensusError::StaleQc {
                    qc_view: qc.view,
                    high_qc_view: current_high_qc.view,
                });
            }
        }

        // Hardening: enforce quorum threshold regardless of whether
        // signature verification is enabled. A QC backed by less
        // than quorum voting power is not a valid commitment
        // certificate, even in conformance mode — the signer stake
        // is a structural property of the QC, not a cryptographic
        // one.
        let voting_power = self.validator_set.signer_stake(&qc.signer_bitmap);
        let required = self.validator_set.quorum_stake();
        if voting_power < required {
            return Err(ConsensusError::InsufficientQuorum { voting_power, required });
        }

        // C1 fix: verify the QC's aggregate signature against the
        // signer bitmap + validator set. The signed message is the
        // block hash (32 bytes) under Domain::Vote — the same domain
        // used by `sign_vote` and verified in `collect_vote`.
        if self.verify_signatures {
            self.verify_qc_signature(&qc)?;
        }

        // Update the highest QC.
        self.high_qc = Some(qc.clone());
        // C9 fix: persist the updated high_qc to the WAL. A
        // restarted validator must propose from the correct
        // high_qc; without persistence, it could propose a stale
        // fork. A failure latches `wal_failed` (C10) — this engine
        // must not sign again until restarted on healthy storage.
        let _ = self.append_wal();

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
            self.commit_walk(&header);
        }
        Ok(())
    }

    /// Walk the certified ancestor chain under a QC'd tip and commit
    /// the contiguous uncommitted prefix, oldest-first.
    ///
    /// A block joins the collected chain only while its stored body
    /// is `Complete`: an `Awaiting` ancestor (dispersed body still
    /// propagating as shards) breaks the walk exactly like a missing
    /// block — the contiguity guard below then defers the whole
    /// commit rather than finalizing over an unexecutable body. The
    /// walk re-runs when `supply_body` completes the body or when a
    /// later QC arrives.
    ///
    /// The tip itself is never committed here — it commits only when
    /// a QC for its *child* arrives — so the tip's own body state is
    /// irrelevant to this walk.
    fn commit_walk(&mut self, header: &BlockHeader) {
        // Collect the uncommitted ancestor chain, newest→oldest:
        // (block hash, bitmap of the QC certifying it). The
        // certifying QC for a block X is the embedded `high_qc`
        // of X's child — for the tip that is `header.high_qc`.
        // The walk stops at genesis (prev ZERO / no stored
        // parent), at a committed block (evicted from `blocks`
        // by `commit_block`'s retain — a missing ancestor is
        // always already finalized, since vote-time storage is
        // prefix-closed: a block can only be stored after its
        // parent was), at an `Awaiting` body (dispersed body not
        // yet reconstructed — never commit unexecutable state),
        // or when the embedded-QC chain ends.
        // The walk only applies when the stored block's parent IS
        // its certified block — `prev == justify`, enforced at
        // vote time. A divergent stored block (impossible via the
        // vote path; only a future import seam could create one)
        // would otherwise commit an *uncertified* parent: the
        // embedded QC certifies `justify`, not `prev`.
        let mut chain: Vec<(Hash, Vec<u8>, u64)> = Vec::new();
        if header.high_qc.as_ref().is_some_and(|qc| qc.block_hash == header.prev_block) {
            let mut cursor_hash = header.prev_block;
            let mut certifying = header.high_qc.clone();
            while let Some(bitmap) = certifying.as_ref().map(|qc| qc.signer_bitmap.clone()) {
                let Some((cursor_header, cursor_body)) = self.blocks.get(&cursor_hash) else {
                    break;
                };
                if !matches!(cursor_body, BlockBody::Complete(_)) {
                    break;
                }
                if self.finalized.contains_key(&cursor_header.height.value()) {
                    break;
                }
                chain.push((cursor_hash, bitmap, cursor_header.height.value()));
                certifying.clone_from(&cursor_header.high_qc);
                cursor_hash = cursor_header.prev_block;
            }
        }
        // Contiguity guard: commit only when the collected chain's
        // oldest block is the direct child of the commit tip.
        // A gap means an ancestor proposal is still in flight —
        // the QC that certifies this chain arrived before the
        // block body did (real networks reorder). Committing
        // anyway would finalize out of order AND permanently
        // orphan the missing height: later walks stop at the
        // finalized sibling and never reach back. Deferring is
        // safe — the walk re-runs on the next delivered QC, by
        // which time the body has landed via the vote path.
        let expected_next =
            self.last_committed.map_or(0, |(_, committed_height)| committed_height.value() + 1);
        let contiguous =
            chain.last().is_none_or(|(_, _, oldest_height)| *oldest_height == expected_next);
        // Commit oldest-first so `finalize_block` sees a
        // contiguous ascending prefix.
        if contiguous {
            for (hash, bitmap, _) in chain.iter().rev() {
                self.commit_block(*hash, bitmap);
            }
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
    fn verify_qc_signature(&self, qc: &QuorumCertificate) -> Result<(), ConsensusError> {
        // Resolve the bitmap into signer keys + voting power.
        let (signer_pks, voting_power) = self.signer_keys_and_power(&qc.signer_bitmap)?;
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
        let required = self.validator_set.quorum_stake();
        if voting_power < required {
            return Err(ConsensusError::InsufficientQuorum { voting_power, required });
        }
        // C3 fix: verify against the full (view, phase, block_hash,
        // epoch) message, not just the block hash.
        let msg = self.vote_signing_message(qc.view, qc.phase as u8, &qc.block_hash);
        crypto::aggregate_verify(
            &qc.aggregate_signature,
            crypto::hash::Domain::Vote,
            &msg,
            &signer_pks,
        )
        .map_err(|_| ConsensusError::InvalidQcSignature)
    }

    /// Commit `block_hash`: look up the block, create a
    /// `FinalizedBlock`, call `app.finalize_block`, and store it.
    ///
    /// `signer_bitmap` is the committing QC's bitmap — bit `i` marks
    /// `validator_addresses()[i]` as a signer. It is resolved to
    /// staking addresses here so the app receives attendance in its
    /// own identity space, never in consensus-internal indices.
    ///
    /// Note: `next_height` is NOT advanced here — it was already
    /// advanced when the block was proposed (the 2-chain pipeline
    /// proposes before committing). The app's `next_proposal_height`
    /// advances here (via `finalize_block`).
    fn commit_block(&mut self, block_hash: Hash, signer_bitmap: &[u8]) {
        let Some((header, body)) = self.blocks.remove(&block_hash) else {
            return; // already committed or unknown
        };
        // Certify gate (dispersed broadcast): a block whose body is
        // still `Awaiting` reconstruction must never finalize —
        // the commit walk already skips it, this is the last-line
        // guard if a future path ever reaches here directly. Put
        // the entry back so a later `supply_body` can complete it.
        let BlockBody::Complete(proposal) = body else {
            self.blocks.insert(block_hash, (header, body));
            return;
        };
        let addresses = self.validator_set.validator_addresses();
        let signers: Vec<Address> = signer_bitmap
            .iter()
            .enumerate()
            .flat_map(|(byte_i, byte)| {
                (0..8).filter_map(move |bit| {
                    if byte & (1u8 << bit) != 0 {
                        addresses.get(byte_i * 8 + bit).copied()
                    } else {
                        None
                    }
                })
            })
            .collect();
        // The execution context every replica must agree on. All
        // three fields are derived from consensus-committed material,
        // never local state:
        //
        // - `timestamp_ms`: the header's own stamp — signed by the
        //   proposer and QC-certified, so every node reads the same
        //   value the leader committed.
        // - `beneficiary`: the proposer's staking address, recovered
        //   from `header.proposer` (the validator index is encoded in
        //   the hash — see `proposer_hash`) against this epoch's
        //   validator set. `Address::ZERO` when the index doesn't
        //   resolve — a header whose proposer passed authentication
        //   always resolves, so ZERO only marks conformance-shaped
        //   headers; modules read it as "no beneficiary".
        // - `gas_limit`: the block budget this engine enforced when
        //   building/processing proposals — the authoritative block
        //   capacity the EVM must run under. Config-derived (same on
        //   every correctly configured node) rather than
        //   header-carried, so it cannot be lied about per-block.
        let proposer_idx = u16::from_le_bytes([header.proposer.0[0], header.proposer.0[1]]);
        let beneficiary = self
            .validator_set
            .validator_addresses()
            .get(usize::from(proposer_idx))
            .copied()
            .unwrap_or(Address::ZERO);
        let context = types::BlockContext {
            timestamp_ms: header.timestamp,
            beneficiary,
            gas_limit: self.block_budget.max_gas,
        };
        let block = FinalizedBlock { height: header.height, txs: proposal.txs, signers, context };
        // Notify the commit listener before inserting into `finalized`
        // — the map prunes at `MAX_RETAINED_FINALIZED`, so external
        // consumers that need full history must observe commits here.
        if let Some(listener) = &self.commit_listener {
            listener(&block);
        }
        self.app.finalize_block(&block);
        self.finalized.insert(header.height.value(), block);
        // Record the committed anchor: the parent a proposal must
        // extend while `high_qc` is `None` (post-rotation boundary,
        // or a node that has committed but not yet adopted a QC).
        // It is persisted safety state (WalEntry/save_state), so the
        // advance must hit the WAL before we act on it: otherwise a
        // crash → restart → rotation sequence would WAL-append the
        // *stale* anchor and the new epoch's first proposals would
        // collide with it (or worse, a `None` restore would accept
        // a forged genesis chain in a later epoch).
        self.last_committed = Some((block_hash, header.height));
        // A failed append latches `wal_failed` (C10): the commit is
        // already real in memory and cannot be undone, but signing
        // must stop — durable state may now trail emitted signatures.
        let _ = self.append_wal();
        // Prune per-height vote locks at-or-below the committed
        // height: a finalized prefix cannot be forked, so the lock
        // is no longer needed. Keeps the map bounded by the number
        // of in-flight (uncommitted) heights.
        self.voted_at_height.retain(|h, _| *h > header.height.value());
        // Prune attestation state at-or-below the committed height:
        // the committed prefix is final and needs no certification.
        // `exec_certs` keeps a generous retention window — a cert is
        // formed by whichever leader collected the attesting votes,
        // and that leader only gets to embed it on its *next* turn,
        // up to a full committee rotation (~n views) plus the
        // attestation lag (~2 views) later. Two rotations of margin
        // covers both without unbounded growth: certs are ~200 B and
        // only the newest embeddable one is ever chosen anyway.
        let committed_height = header.height.value();
        self.exec_attest_pool.retain(|h, _| *h > committed_height);
        let cert_floor = committed_height
            .saturating_sub(2 * u64::try_from(self.validator_set.n()).unwrap_or(u64::MAX));
        self.exec_certs.retain(|h, _| *h >= cert_floor);
        self.verified_exec_certs.retain(|h, _| *h >= cert_floor);
        // Prune the block store of stale proposals: a block at or
        // below the just-committed height can never be needed again
        // (the 2-chain rule only walks ancestors of the pending
        // block, which are strictly above). Without this, a
        // byzantine leader could flood `blocks` with never-committed
        // proposals and grow memory without bound — a memory DoS
        // on every validator.
        let committed = header.height.value();
        self.blocks.retain(|_, (h, _)| h.height.value() > committed);
        // Bound the in-memory finalized history. Full history lives
        // in the journal/backend; the engine's map exists for the
        // commit path and recent-height queries, so retaining the
        // newest `MAX_RETAINED_FINALIZED` heights keeps memory
        // bounded without changing consensus semantics.
        while self.finalized.len() > MAX_RETAINED_FINALIZED {
            self.finalized.pop_first();
        }
    }

    /// Clear all per-view state: collected votes and timeout
    /// signatures.
    ///
    /// This must be called on every view transition (advance,
    /// sync, TC-driven jump, QC catch-up). Stale votes from a
    /// previous view cause `ConflictingVote` errors when the new
    /// view's votes arrive. Stale timeout signatures from a
    /// previous view get aggregated into the new view's TC,
    /// producing an aggregate that fails verification (the
    /// signatures were for a different view) — peers reject the
    /// TC and the view-change stalls.
    fn clear_per_view_state(&mut self) {
        self.votes.fill(None);
        self.vote_count = 0;
        self.vote_stake = 0;
        self.timeout_signatures.fill(None);
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
        self.current_view = view;
        self.pacemaker.sync_to_view(self.current_view);
        self.pacemaker.on_progress();
        self.clear_per_view_state();
        // Sync-driven advance carries no TC evidence.
        self.last_tc = None;
        true
    }

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
        if let Some(qc) = high_qc {
            if qc.epoch == self.epoch {
                let _ = self.deliver_qc(qc);
            }
        }
        if let Some(tc) = last_tc {
            if tc.epoch == self.epoch {
                let _ = self.on_timeout_certificate(&tc);
            }
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
        // Conformance mode carries no real keys, so there is nothing to
        // authenticate (the same precedent as every other check gated on
        // `verify_signatures`).
        if !self.verify_signatures {
            return Ok(());
        }
        let pk =
            self.validator_set.validator(voter).map_err(|_| ConsensusError::SignerOutOfBounds)?;
        let mut msg = Vec::with_capacity(16);
        msg.extend_from_slice(&view.value().to_le_bytes());
        msg.extend_from_slice(&epoch.value().to_le_bytes());
        crypto::bls_signer::verify(signature, crypto::hash::Domain::Timeout, &msg, pk)
            .map_err(|_| ConsensusError::InvalidVoteSignature { voter })
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
                if !sigs.is_empty() {
                    if let Ok(agg) = crypto::aggregate(&sigs) {
                        tc.aggregate_signature = agg;
                    }
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
    fn proposal_tc_releases_lock(&self, header: &BlockHeader) -> bool {
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
        let (signer_pks, voting_power) = self.signer_keys_and_power(&tc.signer_bitmap)?;
        if signer_pks.is_empty() {
            return Err(ConsensusError::InvalidTcSignature);
        }
        // Same defense-in-depth as `verify_qc_signature`: a TC is
        // only a certificate at quorum (voting power), enforced here
        // too so no call site can accept a validly-signed sub-quorum
        // bitmap.
        let required = self.validator_set.quorum_stake();
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

    /// Drive one propose-vote-QC-commit cycle (single-validator mode).
    /// Returns `true` if a block was proposed, `false` if idle.
    fn step(&mut self) -> bool {
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
        let aggregate_signature = if self.secret_key.is_some() {
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
        self.finalized.keys().next_back().map(|&h| Height::new(h))
    }

    fn finalized_block(&self, height: Height) -> Option<FinalizedBlock> {
        self.finalized.get(&height.value()).cloned()
    }
}

#[cfg(test)]
mod tests {
    //! Conformance + unit tests for the oxideBFT engine.
    //!
    //! The conformance suite proves the engine honors the OAI contract
    //! (liveness, sequence, finality, determinism). Unit tests check
    //! the internal state (block hash, `tx_root`, view advancement).

    use super::*;
    use crate::pacemaker::PacemakerEvent;
    use ports::conformance;
    use ports::mock::MockApp;
    use types::ExecCertificate;

    fn pk(byte: u8) -> crypto::bls::PublicKey {
        crypto::bls::PublicKey([byte; crypto::bls::PublicKey::LEN])
    }

    fn single_validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![pk(1)], vec![1]).expect("1 validator")
    }

    fn make_engine() -> OxideBft {
        let app = Arc::new(MockApp::new());
        // Fixed clock: the conformance determinism gate compares
        // finalized blocks byte-for-byte across two runs, and the
        // committed header timestamp now lands in the execution
        // context — a wall clock would make identical runs differ.
        OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_clock(|| 1_700_000_000_000)
    }

    #[test]
    fn oxidebft_passes_conformance() {
        conformance::assert_conformance(make_engine);
    }

    #[test]
    fn engine_starts_at_genesis() {
        let engine = make_engine();
        assert_eq!(engine.finalized_height(), None);
        assert_eq!(engine.next_height, Height::new(0));
        assert_eq!(engine.current_view(), View::new(0));
    }

    #[test]
    fn one_tx_produces_one_committed_block() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1, 2, 3]));
        engine.run_until_idle();
        // The tx is in a committed block (the 2-chain flush ensures this).
        assert!(engine.finalized_height().is_some());
        // Find the block containing our tx.
        let mut found = false;
        let h = engine.finalized_height().unwrap().value();
        for i in 0..=h {
            if let Some(block) = engine.finalized_block(Height::new(i)) {
                if block.txs.iter().any(|t| t.as_bytes() == [1, 2, 3]) {
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "tx must appear in a committed block");
    }

    #[test]
    fn multiple_txs_all_committed() {
        let mut engine = make_engine();
        for i in 0..5u8 {
            engine.submit_tx(TxBytes::new(vec![i]));
            engine.run_until_idle();
        }
        // All 5 txs must be in committed blocks.
        let mut found_txs = 0;
        let h = engine.finalized_height().unwrap().value();
        for i in 0..=h {
            if let Some(block) = engine.finalized_block(Height::new(i)) {
                found_txs += block.txs.len();
            }
        }
        assert_eq!(found_txs, 5, "all 5 txs must be committed");
    }

    #[test]
    fn view_advances_per_block() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        // After proposing + flushing, the view should have advanced.
        assert!(engine.current_view().value() > 0);
    }

    #[test]
    fn high_qc_advances() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        assert!(engine.high_qc.is_some(), "high_qc should be set after first block");
    }

    #[test]
    fn no_work_when_idle() {
        let mut engine = make_engine();
        // With no txs, the engine proposes genesis but it stays
        // pending (2-chain needs a second block to commit). A second
        // run is a no-op (no new work).
        engine.run_until_idle();
        // Genesis is pending but not committed (no second block to
        // form the 2-chain). This is correct 2-chain behavior.
        // A second run is a true no-op.
        let height_before = engine.finalized_height();
        engine.run_until_idle();
        assert_eq!(engine.finalized_height(), height_before);
    }

    #[test]
    fn is_leader_for_view_zero() {
        let engine = make_engine();
        // Validator 0 is the leader for view 0 (round-robin, equal stakes).
        assert!(engine.is_leader());
    }

    // ---- Multi-validator tests ----
    //
    // These tests exercise the engine's multi-validator API
    // (propose/vote/collect_vote/try_form_qc/deliver_qc) with a
    // 4-validator set, proving the 2-chain commit rule works with
    // quorum > 1.

    fn four_validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![1, 1, 1, 1]).expect("4 validators")
    }

    fn make_multi_engine(idx: ValidatorIndex) -> OxideBft {
        let app = Arc::new(MockApp::new());
        OxideBft::with_index(app, four_validator_set(), idx).without_signature_verification()
    }

    /// Drive one happy-path round with 4 validators:
    /// 1. Leader proposes.
    /// 2. All 4 validators vote.
    /// 3. Leader collects votes and forms a QC.
    /// 4. All validators receive the QC (2-chain commit check).
    /// 5. Advance the view.
    ///
    /// Returns the QC so the caller can chain rounds.
    fn drive_round(
        leader: &mut OxideBft,
        followers: &mut [&mut OxideBft],
        tx: Option<TxBytes>,
    ) -> QuorumCertificate {
        // Submit tx to leader's app (if any).
        if let Some(t) = tx {
            leader.submit_tx(t);
        }

        // 1. Leader proposes.
        let (header, proposal) = leader.propose().expect("leader should propose");

        // 2. Leader self-votes through `vote()` — the single signing
        // authority (C10): locks + WAL update precede the signature,
        // same as for followers.
        let leader_idx = leader.validator_index;
        if let Some(leader_vote) = leader.vote(&header, &proposal) {
            leader.collect_vote(leader_idx, leader_vote).expect("conformance: no verification");
        }

        // 3. Followers vote.
        for (i, follower) in followers.iter_mut().enumerate() {
            if let Some(vote) = follower.vote(&header, &proposal) {
                // Voter index is i+1 (leader is 0, followers are 1..n).
                let voter_idx = u16::try_from(i + 1).expect("validator index fits u16");
                leader.collect_vote(voter_idx, vote).expect("conformance: no verification");
            }
        }

        // 4. Leader forms a QC.
        let qc = leader.try_form_qc().expect("quorum should be reached");

        // 5. All validators receive the QC.
        leader.deliver_qc(qc.clone()).expect("conformance: no verification");
        for follower in followers.iter_mut() {
            follower.deliver_qc(qc.clone()).expect("conformance: no verification");
        }

        // 6. Advance the view on all validators.
        leader.advance_view();
        for follower in followers.iter_mut() {
            follower.advance_view();
        }

        qc
    }

    /// Drive one round over the dispersed-broadcast path
    /// (DispersedSimplex): followers vote on the *header only* —
    /// the shard-commitment vote — while the body is still
    /// propagating; the QC forms and delivers before any follower
    /// holds the body. `supply_body` then certifies the body and
    /// triggers the deferred commit walk.
    ///
    /// Returns `(header, proposal, qc)` — callers inspect the QC
    /// and choose whether/when to supply bodies.
    fn drive_round_sharded(
        leader: &mut OxideBft,
        followers: &mut [&mut OxideBft],
        tx: Option<TxBytes>,
        supply_bodies: bool,
    ) -> (BlockHeader, Proposal, QuorumCertificate) {
        if let Some(t) = tx {
            leader.submit_tx(t);
        }
        let (header, proposal) = leader.propose().expect("leader should propose");
        let block_hash = OxideBft::block_hash(&header);
        // Leader self-vote through `vote()` — the single signing
        // authority (C10): locks + WAL update precede the signature.
        // It produced the body, so the complete path applies.
        let leader_idx = leader.validator_index;
        if let Some(leader_vote) = leader.vote(&header, &proposal) {
            leader.collect_vote(leader_idx, leader_vote).expect("conformance: no verification");
        }
        // Followers notarize the commitment — body not required.
        for (i, follower) in followers.iter_mut().enumerate() {
            if let Some(vote) = follower.vote_header(&header) {
                let voter_idx = u16::try_from(i + 1).expect("validator index fits u16");
                leader.collect_vote(voter_idx, vote).expect("conformance: no verification");
            }
        }
        let qc = leader.try_form_qc().expect("quorum should be reached");
        leader.deliver_qc(qc.clone()).expect("conformance: no verification");
        for follower in followers.iter_mut() {
            follower.deliver_qc(qc.clone()).expect("conformance: no verification");
        }
        // The body lands *after* the QC — the dispersed order.
        if supply_bodies {
            for follower in followers.iter_mut() {
                follower
                    .supply_body(block_hash, &proposal)
                    .expect("certified body must be accepted");
            }
        }
        leader.advance_view();
        for follower in followers.iter_mut() {
            follower.advance_view();
        }
        (header, proposal, qc)
    }

    /// A follower must vote on a block's commitment without ever
    /// having seen its body — notarization attests availability of
    /// the *commitment*, execution waits for certification.
    #[test]
    fn vote_header_notarizes_without_body() {
        let mut leader = make_multi_engine(0);
        let mut follower = make_multi_engine(1);
        leader.submit_tx(TxBytes::new(vec![9]));
        let (header, _proposal) = leader.propose().expect("leader proposes");
        assert!(follower.vote_header(&header).is_some(), "commitment vote must not need the body");
        // One vote per view — a second header-vote in the same view
        // is a no-op, same as the full path.
        assert!(follower.vote_header(&header).is_none());
    }

    /// The certify gate: a QC'd block whose body is still `Awaiting`
    /// must defer the commit walk, and `supply_body` must trigger
    /// the deferred walk — finalization only after the body is
    /// verified and complete.
    #[test]
    fn commit_defers_until_body_certified() {
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];

        // Round 1: block h0 — followers never receive its body.
        let (h0, p0, _qc0) =
            drive_round_sharded(&mut leader, &mut followers, Some(TxBytes::new(vec![42])), false);
        // Round 2: block h1 — QC(h1) is what would commit h0.
        drive_round_sharded(&mut leader, &mut followers, None, false);

        // On every follower, h0 is notarized but NOT committed: its
        // body is still Awaiting, so the commit walk broke on it.
        for (name, e) in [("f1", &f1), ("f2", &f2), ("f3", &f3)] {
            assert!(
                e.finalized_block(Height::new(0)).is_none(),
                "{name}: uncommitted body must defer finalization"
            );
        }

        // The body arrives — certification completes it and the
        // deferred walk fires: h0 commits under the already-stored
        // QC(h1) (2-chain rule satisfied since h1's header is known).
        let h0_hash = OxideBft::block_hash(&h0);
        for (i, e) in [&mut f1, &mut f2, &mut f3].iter_mut().enumerate() {
            e.supply_body(h0_hash, &p0)
                .unwrap_or_else(|e| panic!("f{}: certified body accepted: {e:?}", i + 1));
            let block = e.finalized_block(Height::new(0));
            assert!(block.is_some(), "f{}: certified body must unblock commit", i + 1);
            assert_eq!(block.map(|b| b.txs.len()), Some(1));
        }
    }

    /// `supply_body` must reject a body whose canonical encoding
    /// does not hash to the header's signed `body_commitment` —
    /// equivocating bodies can never be certified, and the stored
    /// `Awaiting` slot must not be poisoned (the genuine body is
    /// still accepted afterwards).
    #[test]
    fn supply_body_rejects_commitment_mismatch() {
        let mut leader = make_multi_engine(0);
        let mut follower = make_multi_engine(1);
        leader.submit_tx(TxBytes::new(vec![7]));
        let (header, proposal) = leader.propose().expect("leader proposes");
        let hash = OxideBft::block_hash(&header);
        assert!(follower.vote_header(&header).is_some());

        let mut wrong = proposal.clone();
        wrong.txs = vec![TxBytes::new(vec![8])];
        assert!(matches!(
            follower.supply_body(hash, &wrong),
            Err(ConsensusError::BodyRejected { .. })
        ));
        // Genuine body still accepted — the failed supply did not
        // poison the slot. Duplicate supply is idempotent.
        follower.supply_body(hash, &proposal).expect("genuine body accepted");
        follower.supply_body(hash, &proposal).expect("duplicate supply is a no-op");
    }

    /// A notarized header keeps the block eligible for all
    /// header-level rules while its body propagates: with bodies
    /// supplied every round, the dispersed path commits identically
    /// to the full-proposal path.
    #[test]
    fn sharded_round_trip_commits_identically() {
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];

        drive_round_sharded(&mut leader, &mut followers, Some(TxBytes::new(vec![42])), true);
        drive_round_sharded(&mut leader, &mut followers, None, true);

        for (name, e) in [("leader", &leader), ("f1", &f1), ("f2", &f2), ("f3", &f3)] {
            let block = e.finalized_block(Height::new(0)).expect("block 0 committed");
            assert_eq!(block.txs.len(), 1, "{name}: block 0 should have 1 tx");
            assert_eq!(block.txs[0].as_bytes(), [42], "{name}: block 0 tx mismatch");
        }
    }

    #[test]
    fn multi_validator_two_chain_commits() {
        // 4 validators, 1 leader (index 0), 3 followers.
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];

        // Round 1: propose block0 with a tx.
        drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![42])));
        // After round 1: block0 is pending (has a QC but no 2-chain yet).

        // Round 2: propose block1 (empty) to flush the pipeline.
        drive_round(&mut leader, &mut followers, None);
        // After round 2: block0 should be committed (2-chain: block0
        // → block1 extends block0 → QC over block1).

        // Check block0 is committed on all validators.
        for (name, engine) in [("leader", &leader), ("f1", &f1), ("f2", &f2), ("f3", &f3)] {
            let block = engine.finalized_block(Height::new(0)).expect("block 0 committed");
            assert_eq!(block.txs.len(), 1, "{name}: block 0 should have 1 tx");
            assert_eq!(block.txs[0].as_bytes(), [42], "{name}: block 0 tx mismatch");
        }
    }

    /// Regression test (safety): a validator that voted for block A
    /// at height h must refuse a *different* block B at the same
    /// height, even in a later view. Without the per-height lock,
    /// the post-timeout flow — vote A at view v, time out, new
    /// leader proposes conflicting B at height h extending the same
    /// parent QC — passes the tail-fork check (equal QC view) and
    /// the validator notarizes two conflicting blocks at one
    /// height: both can form QCs and commit divergent state.
    #[test]
    fn vote_lock_rejects_conflicting_block_at_same_height() {
        let mut leader = make_multi_engine(0);
        let mut follower = make_multi_engine(1);

        // Leader proposes block A at height 0, view 0.
        let (header_a, prop_a) = leader.propose().expect("leader should propose");
        assert!(follower.vote(&header_a, &prop_a).is_some(), "first vote at height 0 must succeed");

        // Conflicting block B: same height, same parent QC, later
        // view — different contents → different block hash.
        let mut header_b = header_a.clone();
        header_b.view = View::new(header_a.view.value() + 1);
        header_b.tx_root = Hash([0xAB; 32]);
        let prop_b = prop_a.clone();
        // HIGH fix: vote() requires header.view == current_view.
        follower.current_view = header_b.view;
        assert!(
            follower.vote(&header_b, &prop_b).is_none(),
            "a conflicting block at an already-voted height must be refused"
        );

        // A block at the NEXT height is unaffected — normal
        // progression continues. Voting for a non-genesis block
        // requires a highQC (the tail-fork rule needs `prev ==
        // high_qc.block`), so give the follower QC(A) — its block
        // header is already stored from the first vote.
        let qc_a = QuorumCertificate {
            view: header_a.view,
            phase: VotePhase::Prepare,
            block_hash: OxideBft::block_hash(&header_a),
            epoch: Epoch::new(0),
            // A QC's bitmap must carry quorum signers — the count is
            // a structural property enforced even without signature
            // verification (conformance mode): a fabricated
            // single-signer "QC" is not a certificate.
            signer_bitmap: vec![0x07],
            aggregate_signature: AggregateSignature::ZERO,
        };
        let mut header_c = header_a.clone();
        header_c.view = View::new(header_a.view.value() + 1);
        header_c.height = Height::new(header_a.height.value() + 1);
        header_c.prev_block = OxideBft::block_hash(&header_a);
        // The child must justify with QC(A) — a proposal without a
        // high_qc is refused while the voter holds one.
        header_c.high_qc = Some(qc_a.clone());
        follower.high_qc = Some(qc_a);
        // current_view already set to header_c.view above.
        assert!(
            follower.vote(&header_c, &prop_a).is_some(),
            "voting at the next height must still succeed"
        );
    }

    #[test]
    fn multi_validator_multiple_rounds() {
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];

        // Drive 5 rounds with txs.
        for i in 0..5u8 {
            drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![i])));
        }
        // Drive one more empty round to flush the last pending block.
        drive_round(&mut leader, &mut followers, None);

        // All 5 txs should be committed across the validators.
        let mut total_txs = 0;
        let h = leader.finalized_height().expect("some blocks finalized").value();
        for i in 0..=h {
            if let Some(block) = leader.finalized_block(Height::new(i)) {
                total_txs += block.txs.len();
            }
        }
        assert_eq!(total_txs, 5, "all 5 txs must be committed");
    }

    #[test]
    fn multi_validator_finalized_heights_match() {
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];

        for i in 0..3u8 {
            drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![i])));
        }
        drive_round(&mut leader, &mut followers, None);

        // All validators should have the same finalized height.
        let leader_h = leader.finalized_height();
        assert_eq!(f1.finalized_height(), leader_h, "f1 height mismatch");
        assert_eq!(f2.finalized_height(), leader_h, "f2 height mismatch");
        assert_eq!(f3.finalized_height(), leader_h, "f3 height mismatch");
    }

    /// Regression test (safety + liveness): a Byzantine leader can
    /// stamp an arbitrary `height` on a proposal — `vote()` never
    /// checked that the stamped height is `parent.height + 1`. A
    /// forged block is then committable at a height the honest chain
    /// has not reached: `finalized.insert(forged_h, d)` creates a
    /// finalized *gap*, and the voters who signed d's child are now
    /// per-height-locked at the height the honest chain still needs —
    /// the next honest proposal at that height can never reach quorum
    /// again. The chain wedges permanently and finalized histories
    /// diverge.
    ///
    /// Scenario: commit b0@0 and b1@1 honestly; at view 3 the
    /// Byzantine leader proposes d with height forged to 5 (prev =
    /// the real highQC block, so tail-fork checks pass — nobody holds
    /// a height-5 lock); QC(d) forms; the honest view-4 leader adopts
    /// QC(d) as its highQC and proposes a child; QC(child) commits d
    /// at forged height 5 while only heights 0..=2 exist.
    ///
    /// The fix makes stamped heights chain coordinates: a voter
    /// accepts a proposal only if `header.height ==
    /// parent.height + 1` (genesis excepted), and the proposer
    /// derives its stamp the same way.
    #[test]
    fn forged_height_block_cannot_commit_or_wedge_chain() {
        let mut e0 = make_multi_engine(0);
        let mut e1 = make_multi_engine(1);
        let mut e2 = make_multi_engine(2);
        let mut e3 = make_multi_engine(3);

        // Views 0..=2: honest rounds — leaders rotate e0, e1, e2.
        // After view 1 every engine has committed b0@0; after view 2,
        // b1@1 (and pending = b2). drive_round's follower→voter-index
        // mapping (i+1) mislabels indices for non-zero leaders but
        // still collects quorum — conformance mode ignores identity.
        drive_round(&mut e0, &mut [&mut e1, &mut e2, &mut e3], Some(TxBytes::new(vec![0xA0])));
        drive_round(&mut e1, &mut [&mut e0, &mut e2, &mut e3], Some(TxBytes::new(vec![0xB0])));
        drive_round(&mut e2, &mut [&mut e0, &mut e1, &mut e3], Some(TxBytes::new(vec![0xC0])));

        // View 3 — Byzantine leader e3: take its honest proposal and
        // forge the stamped height to 5 (skipping 3 and 4). Parent
        // and justify pointers stay the real highQC — every existing
        // vote check passes; only the height is a lie.
        let (mut d_header, d_proposal) = e3.propose().expect("byz leader proposes");
        assert_eq!(d_header.height, Height::new(3), "honest stamp would be 3");
        d_header.height = Height::new(5); // the attack: a height the chain hasn't reached
        let d_hash = OxideBft::block_hash(&d_header);
        e3.blocks.insert(d_hash, (d_header.clone(), BlockBody::Complete(d_proposal.clone())));

        // e0 and e1 vote for d: nobody holds a height-5 lock, the
        // parent is the real highQC, and the view matches.
        let d_vote0 = e0.vote(&d_header, &d_proposal);
        let d_vote1 = e1.vote(&d_header, &d_proposal);
        assert!(d_vote0.is_none(), "forged-height proposal must be rejected");
        assert!(d_vote1.is_none(), "forged-height proposal must be rejected");
        e3.collect_vote(
            3,
            Vote {
                view: d_header.view,
                phase: VotePhase::Prepare,
                block_hash: d_hash,
                signature: Signature::ZERO,
                attestation: None,
                attestation_sig: None,
            },
        )
        .expect("conformance mode");
        assert!(e3.try_form_qc().is_none(), "a forged-height block must never reach quorum");

        // The honest chain is unaffected: no forged commit, no
        // finalized gap, and the next honest round still works. Move
        // to view 4 (leader e0) — view 3's buffer on e3 still holds
        // the forged self-vote; advancing clears per-view state.
        assert!(e0.finalized_block(Height::new(5)).is_none(), "no forged commit");
        assert!(e0.finalized_height().map_or(0, Height::value) <= 2, "no height gap");
        e0.advance_view();
        e1.advance_view();
        e2.advance_view();
        e3.advance_view();
        drive_round(&mut e0, &mut [&mut e1, &mut e2, &mut e3], Some(TxBytes::new(vec![0xD0])));
        assert!(
            e0.finalized_block(Height::new(2)).is_some(),
            "honest chain still finalizes (b2 lands at height 2)"
        );
    }

    /// Regression test (liveness, complements the forged-height fix):
    /// once stamped heights are bound to `parent.height + 1`, a
    /// same-height equivocation that produces no QC leaves honest
    /// voters per-height-locked — the only recovery is re-voting the
    /// height after the view provably timed out. The proposal's
    /// embedded TC is that proof (spec §view-changes: the new leader
    /// is the TC's legitimate successor). Without the release, one
    /// Byzantine leader could wedge a height forever.
    #[test]
    fn same_height_lock_releases_on_timeout_certificate() {
        let mut e0 = make_multi_engine(0);
        let mut e1 = make_multi_engine(1);
        let mut e2 = make_multi_engine(2);
        let mut e3 = make_multi_engine(3);

        // View 0: leader e0 equivocates — block A goes to e1, a
        // conflicting block A' (same height, same view, different
        // tx_root) goes to e2 and e3. Votes split 2-2; no QC forms.
        e0.submit_tx(TxBytes::new(vec![0xA0]));
        let (ha, pa) = e0.propose().expect("leader proposes A");
        let mut ha2 = ha.clone();
        ha2.tx_root = Hash([0xAB; 32]);
        let pa2 = Proposal { height: ha2.height, ..pa.clone() };
        let hash_a = OxideBft::block_hash(&ha);
        let hash_a2 = OxideBft::block_hash(&ha2);
        assert_ne!(hash_a, hash_a2, "equivocated blocks must differ");

        e0.collect_vote(
            0,
            Vote {
                view: ha.view,
                phase: VotePhase::Prepare,
                block_hash: hash_a,
                signature: Signature::ZERO,
                attestation: None,
                attestation_sig: None,
            },
        )
        .expect("conformance mode");
        assert!(e1.vote(&ha, &pa).is_some(), "e1 votes A");
        assert!(e2.vote(&ha2, &pa2).is_some(), "e2 votes A'");
        assert!(e3.vote(&ha2, &pa2).is_some(), "e3 votes A'");
        assert!(e0.try_form_qc().is_none(), "2 votes < quorum 3");

        // All four validators time out view 0 and collect each
        // other's signatures — every engine forms TC(0) and advances
        // to view 1 with `last_tc` set.
        let sigs: Vec<Signature> = [&mut e0, &mut e1, &mut e2, &mut e3]
            .iter_mut()
            .map(|e| e.on_timeout().expect("timeout signature"))
            .collect();
        for engine in [&mut e0, &mut e1, &mut e2, &mut e3] {
            for (signer, sig) in sigs.iter().enumerate() {
                let _ = engine.collect_timeout_signature(u16::try_from(signer).unwrap_or(0), *sig);
            }
        }
        assert_eq!(e1.current_view(), View::new(1), "TC(0) advances to view 1");

        // View 1: new leader e1 re-proposes at height 0 (its highQC
        // is still genesis — no block was ever notarized). The
        // proposal embeds TC(0).
        e1.submit_tx(TxBytes::new(vec![0xB0]));
        let (hb, pb) = e1.propose().expect("new leader re-proposes the height");
        assert_eq!(hb.height, Height::new(0), "the failed height is retried");
        assert_eq!(hb.prev_block, Hash::ZERO, "genesis anchor parent");
        assert_eq!(
            hb.timeout_cert.as_ref().map(|tc| tc.view),
            Some(View::new(0)),
            "proposal embeds TC(0) as successor evidence"
        );

        // Locked voters release: e0 voted A, e2/e3 voted A' — all
        // accept B because TC(0) proves the split view ended
        // undecided.
        assert!(e0.vote(&hb, &pb).is_some(), "A-voter releases on TC evidence");
        assert!(e2.vote(&hb, &pb).is_some(), "A'-voter releases on TC evidence");
        assert!(e3.vote(&hb, &pb).is_some(), "A'-voter releases on TC evidence");
    }

    /// Regression test (safety): a Byzantine leader can decouple a
    /// proposal's `prev_block` from the block its embedded QC
    /// certifies (`justify`). The tail-fork rule binds `prev` to the
    /// voter's own highQC block, while the two-chain commit rule in
    /// `deliver_qc` walks *justify* edges — the QC'd block commits
    /// its embedded QC's target. A proposal with `prev = our highQC
    /// block` but `justify = a different, newer-view notarized block`
    /// passes every pre-fix check: it is stored, gathers votes,
    /// becomes `pending`, and commits via its child — while the
    /// voter's real parent chain is never committed. Result: a gap
    /// in `finalized`, and a same-height conflict against validators
    /// that committed through the justify chain.
    ///
    /// The fix is the structural `HotStuff` rule: a block extends
    /// exactly the block its embedded QC certifies —
    /// `header.prev_block == header.high_qc.block_hash`. Honest
    /// proposers always satisfy this (`propose()` sets both from the
    /// same highQC); only a crafted proposal can violate it.
    ///
    /// Scenario: all validators hold highQC = QC(a), pending = a.
    /// `b@1` is honestly proposed and notarized at view 1, but QC(b)
    /// is delivered to nobody — e0/e2/e3 keep highQC = QC(a) and a
    /// per-height-1 lock on b. View 1 then times out (TC(1) exists:
    /// honest voters can both vote and later timeout-sign a view).
    /// The Byzantine view-2 leader crafts `d` with prev = a (the
    /// stale voters' highQC block), justify = QC(b) (a real QC for
    /// a DIFFERENT block), and TC(1) (which legitimately releases
    /// the h1 locks). Pre-fix all three vote for d — QC(d) forms,
    /// adoption sets pending = d without committing a, and a child's
    /// QC would commit d@1: a finalized gap on e0/e2/e3 and a
    /// height-1 fork against e1, which commits b through QC(d)'s
    /// justify edge. Post-fix every vote must be rejected.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn prev_justify_divergence_cannot_fork_commits() {
        let mut e0 = make_multi_engine(0);
        let mut e1 = make_multi_engine(1);
        let mut e2 = make_multi_engine(2);
        let mut e3 = make_multi_engine(3);

        // View 0: e0 proposes a@0, everyone votes, QC(a) delivered to
        // all four — pending = a, highQC = QC(a).
        e0.submit_tx(TxBytes::new(vec![0xA0]));
        let (ha, pa) = e0.propose().expect("e0 proposes a@0");
        let hash_a = OxideBft::block_hash(&ha);
        e0.collect_vote(
            0,
            Vote {
                view: ha.view,
                phase: VotePhase::Prepare,
                block_hash: hash_a,
                signature: Signature::ZERO,
                attestation: None,
                attestation_sig: None,
            },
        )
        .expect("conformance mode");
        for (idx, e) in [&mut e1, &mut e2, &mut e3].iter_mut().enumerate() {
            let v = e.vote(&ha, &pa).expect("honest vote for a");
            e0.collect_vote(u16::try_from(idx + 1).unwrap_or(0), v).expect("collect");
        }
        let qc_a = e0.try_form_qc().expect("QC(a)");
        for e in [&mut e0, &mut e1, &mut e2, &mut e3] {
            e.deliver_qc(qc_a.clone()).expect("deliver QC(a)");
            e.advance_view();
        }

        // View 1: e1 honestly proposes b@1 (prev = a, justify =
        // QC(a)). All four vote so QC(b) is real — but it is
        // delivered to NOBODY: e0/e2/e3 keep highQC = QC(a),
        // pending = a, and a height-1 lock on b.
        e1.submit_tx(TxBytes::new(vec![0xB0]));
        let (hb, pb) = e1.propose().expect("e1 proposes b@1");
        let hash_b = OxideBft::block_hash(&hb);
        assert_eq!(hb.prev_block, hash_a, "honest b extends a");
        e1.collect_vote(
            1,
            Vote {
                view: hb.view,
                phase: VotePhase::Prepare,
                block_hash: hash_b,
                signature: Signature::ZERO,
                attestation: None,
                attestation_sig: None,
            },
        )
        .expect("conformance mode");
        for (voter_idx, e) in [(0u16, &mut e0), (2, &mut e2), (3, &mut e3)] {
            let v = e.vote(&hb, &pb).expect("honest vote for b");
            e1.collect_vote(voter_idx, v).expect("collect");
        }
        let qc_b = e1.try_form_qc().expect("QC(b) is real");

        // View 1 times out everywhere: TC(1) forms and advances all
        // engines to view 2 — the release evidence the crafted
        // proposal will carry.
        let sigs: Vec<Signature> = [&mut e0, &mut e1, &mut e2, &mut e3]
            .iter_mut()
            .map(|e| e.on_timeout().expect("timeout signature"))
            .collect();
        let mut tc1 = None;
        for engine in [&mut e0, &mut e1, &mut e2, &mut e3] {
            for (signer, sig) in sigs.iter().enumerate() {
                if let Ok(Some(tc)) =
                    engine.collect_timeout_signature(u16::try_from(signer).unwrap_or(0), *sig)
                {
                    tc1 = Some(tc);
                }
            }
        }
        let tc1 = tc1.expect("TC(1) formed");
        assert_eq!(e0.current_view(), View::new(2), "TC(1) advances to view 2");

        // View 2 — Byzantine leader e2 crafts `d`: prev = a (the
        // stale voters' highQC block), justify = QC(b), height = 1,
        // and TC(1) as the lock-release evidence. Every pre-fix
        // check passes for e0/e2/e3: prev == their highQC block,
        // justify.view > theirs, height = parent + 1, and the TC
        // releases their b-lock at height 1.
        let d_header = BlockHeader {
            view: View::new(2),
            height: Height::new(1),
            prev_block: hash_a,          // the stale voters' highQC block
            high_qc: Some(qc_b.clone()), // justify: a DIFFERENT, newer notarized block
            timeout_cert: Some(tc1),
            ..hb.clone()
        };
        // d carries its own payload so a commit is distinguishable
        // from b's.
        let d_proposal = Proposal {
            height: d_header.height,
            txs: vec![TxBytes::new(vec![0xD0])],
            attestation: None,
        };
        let hash_d = OxideBft::block_hash(&d_header);
        assert_ne!(hash_d, hash_b, "crafted block is distinct from b");

        assert!(
            e0.vote(&d_header, &d_proposal).is_none(),
            "prev=a / justify=b divergence must be rejected"
        );
        assert!(
            e2.vote(&d_header, &d_proposal).is_none(),
            "TC-released lock does not rescue a divergent justify"
        );
        assert!(
            e3.vote(&d_header, &d_proposal).is_none(),
            "prev=a / justify=b divergence must be rejected"
        );

        // The honest chain is unaffected: deliver QC(b) (commits a
        // via the justify edge on voters that stored b), advance,
        // and the pipeline keeps committing contiguous heights.
        for e in [&mut e0, &mut e1, &mut e2, &mut e3] {
            e.deliver_qc(qc_b.clone()).expect("deliver QC(b)");
            e.advance_view();
        }
        drive_round(&mut e3, &mut [&mut e0, &mut e1, &mut e2], Some(TxBytes::new(vec![0xC0])));

        // b@1 — not d — commits, and the committed prefix is
        // contiguous from genesis.
        let b1 = e1.finalized_block(Height::new(1)).expect("b@1 committed");
        assert_eq!(b1.txs[0].as_bytes(), [0xB0], "height 1 must contain b, not d");
        let h = e1.finalized_height().map_or(0, Height::value);
        for height in 0..=h {
            assert!(e1.finalized_block(Height::new(height)).is_some(), "height {height} committed");
        }
    }

    /// Commit-rule completeness (third TLC finding): adopting a QC
    /// must commit the *entire* certified ancestor chain, not just
    /// the single `pending` link. With the single-link rule, a
    /// validator whose stored blocks outpace its pending pointer —
    /// the state a block-import/catch-up seam produces — skips the
    /// intermediate commits forever: adopting QC(b3) with pending
    /// b0 committed nothing, and the chain finalized b3 later with
    /// heights 1..2 missing (`InvNoGap` counterexample shape).
    ///
    /// The scenario is not reachable through `vote()` today —
    /// storage is prefix-closed (a vote requires the parent stored)
    /// so pending can never actually lag the stored chain — but the
    /// commit rule must be correct against the storage states the
    /// planned import seam will create, so the test seeds `blocks`
    /// directly.
    #[test]
    fn leapfrog_qc_commits_full_ancestor_chain() {
        let mut e0 = make_multi_engine(0);
        e0.current_view = View::new(10);

        let qc = |view: u64, block_hash: Hash| QuorumCertificate {
            view: View::new(view),
            phase: VotePhase::Prepare,
            block_hash,
            epoch: Epoch::new(0),
            // 3-of-4 signers: meets quorum under conformance mode.
            signer_bitmap: vec![0x07],
            aggregate_signature: AggregateSignature::ZERO,
        };
        let store = |e: &mut OxideBft,
                     height: u64,
                     view: u64,
                     prev_block: Hash,
                     high_qc: Option<QuorumCertificate>,
                     tag: u8| {
            let header = BlockHeader {
                height: Height::new(height),
                view: View::new(view),
                epoch: Epoch::new(0),
                prev_block,
                tx_root: Hash([tag; 32]),
                high_qc,
                timeout_cert: None,
                proposer: Hash([tag; 32]),
                timestamp: 0,
                proposer_signature: None,
                exec_cert: None,
                body_commitment: Hash::ZERO,
            };
            let proposal = Proposal {
                height: header.height,
                txs: vec![TxBytes::new(vec![tag])],
                attestation: None,
            };
            let hash = OxideBft::block_hash(&header);
            e.blocks.insert(hash, (header, BlockBody::Complete(proposal.clone())));
            (hash, proposal)
        };

        let (h0, _) = store(&mut e0, 0, 0, Hash::ZERO, None, 0xB0);
        let (h1, _) = store(&mut e0, 1, 1, h0, Some(qc(0, h0)), 0xB1);
        let (h2, _) = store(&mut e0, 2, 2, h1, Some(qc(1, h1)), 0xB2);
        let (h3, _) = store(&mut e0, 3, 3, h2, Some(qc(2, h2)), 0xB3);

        // QC(b3) arrives (e.g. via catch-up): commits b2, and the
        // recursive walk must finalize b0 and b1 beneath it —
        // oldest first.
        e0.deliver_qc(qc(3, h3)).expect("leapfrog QC accepted");

        for (height, tag) in [(0u64, 0xB0u8), (1, 0xB1), (2, 0xB2)] {
            let block = e0
                .finalized_block(Height::new(height))
                .unwrap_or_else(|| panic!("height {height} must be committed"));
            assert_eq!(block.txs[0].as_bytes(), [tag], "height {height} content");
        }
        assert!(
            e0.finalized_block(Height::new(3)).is_none(),
            "b3 is notarized, not committed — commits need its child QC"
        );
    }

    /// Companion (integrity): the embedded QC's aggregate signature
    /// is commit evidence — its bitmap becomes the committed
    /// parent's attendance record in `commit_block`. A proposal
    /// carrying a structurally consistent but *unverifiable* QC must
    /// be rejected at vote time, not deferred to commit.
    #[test]
    fn proposal_with_forged_embedded_qc_is_rejected() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
        let mut voter = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
            .with_secret_key(keys[1].clone());

        // Real QC(a) for a genesis block: voter adopts it so the
        // proposal's embedded QC is a newer-view claim.
        let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
            .with_secret_key(keys[0].clone());
        leader.submit_tx(TxBytes::new(vec![0xA0]));
        let (ha, pa) = leader.propose().expect("leader proposes a");
        let hash_a = OxideBft::block_hash(&ha);
        // Sign a real quorum of votes for a.
        let mut sigs = Vec::new();
        for (i, k) in keys.iter().enumerate() {
            let mut msg = Vec::with_capacity(49);
            msg.extend_from_slice(&ha.view.value().to_le_bytes());
            msg.push(VotePhase::Prepare as u8);
            msg.extend_from_slice(hash_a.as_bytes());
            msg.extend_from_slice(&leader.epoch.value().to_le_bytes());
            sigs.push((i, k.sign(crypto::hash::Domain::Vote, &msg)));
        }
        for (i, sig) in sigs.iter().take(3) {
            leader
                .collect_vote(
                    u16::try_from(*i).unwrap_or(0),
                    Vote {
                        view: ha.view,
                        phase: VotePhase::Prepare,
                        block_hash: hash_a,
                        signature: *sig,
                        attestation: None,
                        attestation_sig: None,
                    },
                )
                .expect("real votes");
        }
        let qc_a = leader.try_form_qc().expect("real QC(a)");
        // The voter must have `a` stored (the height-continuity check
        // needs the parent header), so it votes for a first, then
        // adopts QC(a).
        assert!(voter.vote(&ha, &pa).is_some(), "voter stores a via its vote");
        voter.deliver_qc(qc_a.clone()).expect("adopt real QC(a)");
        voter.advance_view();

        // Craft a child proposal whose embedded QC has a valid
        // structure (certifies a, the real parent) but a garbage
        // aggregate signature. Pre-fix: the embedded QC was never
        // verified, so the vote passed. Post-fix: reject.
        let mut forged_qc = qc_a.clone();
        forged_qc.aggregate_signature = AggregateSignature::ZERO;
        let mut header_c = ha.clone();
        header_c.view = View::new(1);
        header_c.height = Height::new(1);
        header_c.prev_block = hash_a;
        header_c.high_qc = Some(forged_qc);
        // Re-sign the crafted header as the view-1 leader so the
        // proposer check passes and only the embedded QC is bad.
        let leader_idx = vs.leader(header_c.view);
        header_c.proposer = proposer_hash(leader_idx);
        let signing_hash = OxideBft::proposal_signing_hash(&header_c);
        header_c.proposer_signature = Some(
            keys[usize::from(leader_idx)]
                .sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()),
        );
        voter.current_view = header_c.view;
        assert!(
            voter.vote(&header_c, &pa).is_none(),
            "a proposal carrying an unverifiable embedded QC must be rejected"
        );
    }

    /// Complement: without the TC the lock still holds — a retried
    /// proposal at a locked height with different content is refused.
    #[test]
    fn same_height_lock_holds_without_timeout_certificate() {
        let mut e0 = make_multi_engine(0);
        let mut e1 = make_multi_engine(1);

        e0.submit_tx(TxBytes::new(vec![0xA0]));
        let (ha, pa) = e0.propose().expect("leader proposes A");
        assert!(e1.vote(&ha, &pa).is_some(), "e1 votes A at height 0");

        // Advance the view WITHOUT a TC (models the QC/happy-path
        // advance the driver performs) and craft a conflicting
        // same-height block — no TC is attached, so the lock holds.
        e1.advance_view();
        let mut hb = ha.clone();
        hb.view = View::new(1);
        hb.tx_root = Hash([0xAB; 32]);
        assert!(
            e1.vote(&hb, &pa).is_none(),
            "same-height conflict without TC evidence must be refused"
        );
    }

    // ---- BLS integration tests (stage 5) ----
    //
    // These tests use real BLS signing (via blst) to prove the engine
    // produces valid signatures and aggregate signatures.

    fn bls_key(byte: u8) -> crypto::BlsSecretKey {
        let ikm = vec![byte; 32];
        crypto::BlsSecretKey::from_ikm(&ikm).expect("key gen")
    }

    #[test]
    fn bls_signed_vote_verifies() {
        // Single validator with a real BLS key. The validator set
        // must contain the real PK derived from the secret key so
        // that deliver_qc's signature verification passes.
        let key = bls_key(1);
        let pk = key.public_key();
        let app = Arc::new(MockApp::new());
        let vs = ValidatorSet::new(vec![pk], vec![1]).expect("1 validator with real PK");
        let mut engine = OxideBft::new(app, vs).with_secret_key(key);
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();

        // The engine should have formed a QC with a real aggregate
        // signature (not ZERO).
        let qc = engine.high_qc.as_ref().expect("high_qc");
        assert_ne!(
            qc.aggregate_signature,
            AggregateSignature::ZERO,
            "QC must have a real aggregate signature"
        );

        // Verify the aggregate signature against the validator's PK.
        // C3 fix: the signed message now binds (view, phase,
        // block_hash, epoch).
        let block_hash = qc.block_hash;
        let mut msg = Vec::with_capacity(49);
        msg.extend_from_slice(&qc.view.value().to_le_bytes());
        msg.push(qc.phase as u8);
        msg.extend_from_slice(block_hash.as_bytes());
        msg.extend_from_slice(&qc.epoch.value().to_le_bytes());
        let result = crypto::aggregate_verify(
            &qc.aggregate_signature,
            crypto::hash::Domain::Vote,
            &msg,
            &[pk],
        );
        assert!(result.is_ok(), "QC aggregate signature must verify");
    }

    #[test]
    fn bls_multi_validator_qc_verifies() {
        // 4 validators with real BLS keys.
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let stakes = vec![1u64; 4];
        let vs = ValidatorSet::new(pks.clone(), stakes).expect("4 validators");

        let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
            .with_secret_key(keys[0].clone());
        let mut followers: Vec<OxideBft> = (1..4u8)
            .map(|i| {
                OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), u16::from(i))
                    .with_secret_key(keys[i as usize].clone())
            })
            .collect();

        // Submit a tx and drive one round.
        leader.submit_tx(TxBytes::new(vec![42]));
        let (header, proposal) = leader.propose().expect("propose");
        let block_hash = OxideBft::block_hash(&header);

        // Leader self-votes. C3 fix: sign with (view, phase,
        // block_hash, epoch) message.
        let mut vote_msg = Vec::with_capacity(49);
        vote_msg.extend_from_slice(&header.view.value().to_le_bytes());
        vote_msg.push(VotePhase::Prepare as u8);
        vote_msg.extend_from_slice(block_hash.as_bytes());
        vote_msg.extend_from_slice(&leader.epoch.value().to_le_bytes());
        let leader_sig = keys[0].sign(crypto::hash::Domain::Vote, &vote_msg);
        leader
            .collect_vote(
                0,
                Vote {
                    view: header.view,
                    phase: VotePhase::Prepare,
                    block_hash,
                    signature: leader_sig,
                    attestation: None,
                    attestation_sig: None,
                },
            )
            .expect("valid self-vote must verify");

        // Followers vote.
        for (i, follower) in followers.iter_mut().enumerate() {
            if let Some(vote) = follower.vote(&header, &proposal) {
                leader
                    .collect_vote(u16::try_from(i + 1).expect("validator index fits u16"), vote)
                    .expect("valid follower vote must verify");
            }
        }

        // Form QC.
        let qc = leader.try_form_qc().expect("quorum");
        assert_ne!(
            qc.aggregate_signature,
            AggregateSignature::ZERO,
            "QC must have a real aggregate signature"
        );

        // Verify the aggregate signature against all 4 public keys.
        // C3 fix: verify against (view, phase, block_hash, epoch).
        let mut verify_msg = Vec::with_capacity(49);
        verify_msg.extend_from_slice(&qc.view.value().to_le_bytes());
        verify_msg.push(qc.phase as u8);
        verify_msg.extend_from_slice(block_hash.as_bytes());
        verify_msg.extend_from_slice(&qc.epoch.value().to_le_bytes());
        let result = crypto::aggregate_verify(
            &qc.aggregate_signature,
            crypto::hash::Domain::Vote,
            &verify_msg,
            &pks,
        );
        assert!(result.is_ok(), "QC aggregate signature must verify against all 4 keys");
    }

    // ---- C1 fix: signature verification tests ----
    //
    // These tests prove the production vote path rejects forged
    // votes and QCs (the C1 audit finding). A forged vote has a
    // signature that does not verify against the claimed voter's
    // public key. A forged QC has an aggregate signature that does
    // not verify against the signer bitmap's public keys.

    /// Regression test (C3): `vote()` must reject a proposal whose
    /// `proposer` field does not match the expected leader for the
    /// view. Without this check, any validator could fabricate a
    /// proposal in any view.
    #[test]
    fn vote_rejects_proposal_from_wrong_proposer() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
            .with_secret_key(keys[1].clone());

        // Leader for view 0 is index 0 (round-robin/stake-weighted).
        // Construct a header claiming proposer = validator 2 (wrong).
        let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
        let mut header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: Hash::ZERO,
            high_qc: None,
            timeout_cert: None,
            proposer: proposer_hash(2), // wrong proposer
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        // Even with a valid signature from key 2, the proposer field
        // doesn't match the expected leader (0), so vote() rejects.
        let sk2 = bls_key(3);
        let signing_hash = OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk2.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
        assert!(
            follower.vote(&header, &proposal).is_none(),
            "proposal from wrong proposer must be rejected"
        );
    }

    /// Regression test (C3): `vote()` must reject a proposal with a
    /// missing or invalid proposer signature. The signature proves
    /// the claimed leader actually created the proposal.
    #[test]
    fn vote_rejects_proposal_with_missing_signature() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
            .with_secret_key(keys[1].clone());

        let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
        // Correct proposer (leader 0 for view 0) but no signature.
        let header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: Hash::ZERO,
            high_qc: None,
            timeout_cert: None,
            proposer: proposer_hash(0),
            timestamp: 0,
            proposer_signature: None, // missing
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        assert!(
            follower.vote(&header, &proposal).is_none(),
            "proposal with missing proposer signature must be rejected"
        );
    }

    /// Regression test (C3): `vote()` must reject a proposal with a
    /// forged proposer signature (signed by a different key).
    #[test]
    fn vote_rejects_proposal_with_forged_signature() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
            .with_secret_key(keys[1].clone());

        let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
        // Correct proposer (leader 0 for view 0) but signed by key 3.
        let mut header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: Hash::ZERO,
            high_qc: None,
            timeout_cert: None,
            proposer: proposer_hash(0),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let forged_sk = bls_key(3);
        let signing_hash = OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(forged_sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
        assert!(
            follower.vote(&header, &proposal).is_none(),
            "proposal with forged proposer signature must be rejected"
        );
    }

    /// A single forged vote must not stall the view.
    ///
    /// `collect_vote` stores the first vote per validator *without*
    /// verifying it (per-vote BLS verification is opt-in for cost
    /// reasons), so a Byzantine validator can slip a bad signature into
    /// the leader's buffer. Before this fix the resulting aggregate
    /// failed verification at every receiver, so the view stalled until
    /// its timeout — and because the bad vote stayed buffered, it
    /// poisoned every retry: one participant, one permanently stalled
    /// view. The leader must now detect its own bad aggregate,
    /// quarantine the invalid contribution, and still form a QC from
    /// the honest quorum.
    #[test]
    fn forged_vote_is_quarantined_and_quorum_still_forms() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut leader =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        leader.submit_tx(TxBytes::new(vec![42]));
        let (header, _proposal) = leader.propose().expect("propose");
        let block_hash = OxideBft::block_hash(&header);

        let mut msg = Vec::with_capacity(49);
        msg.extend_from_slice(&header.view.value().to_le_bytes());
        msg.push(VotePhase::Prepare as u8);
        msg.extend_from_slice(block_hash.as_bytes());
        msg.extend_from_slice(&leader.epoch.value().to_le_bytes());

        // Three honest votes — quorum at n=4 is 3.
        for voter in [0u16, 2, 3] {
            let vote = Vote {
                view: header.view,
                phase: VotePhase::Prepare,
                block_hash,
                signature: keys[usize::from(voter)].sign(crypto::hash::Domain::Vote, &msg),
                attestation: None,
                attestation_sig: None,
            };
            leader.collect_vote(voter, vote).expect("honest vote accepted");
        }

        // Validator 1 equivocates by signing with validator 3's key:
        // well-formed bytes, wrong signer for the claimed slot.
        let forged = Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: keys[3].sign(crypto::hash::Domain::Vote, &msg),
            attestation: None,
            attestation_sig: None,
        };
        leader
            .collect_vote(1, forged)
            .expect("the default path stores without per-vote verification");

        // Nominal quorum is reached, but one contribution is forged.
        let qc =
            leader.try_form_qc().expect("the honest quorum must still form a QC after quarantine");

        // The QC must describe exactly the three honest signers.
        assert_eq!(qc.signer_bitmap, vec![0b0000_1101], "voter 1 must be quarantined");

        let honest_pks: Vec<crypto::bls::PublicKey> =
            [0usize, 2, 3].iter().map(|i| keys[*i].public_key()).collect();
        crypto::aggregate_verify(
            &qc.aggregate_signature,
            crypto::hash::Domain::Vote,
            &msg,
            &honest_pks,
        )
        .expect("the emitted QC must verify against exactly its signers");
    }

    /// If quarantine leaves less than a quorum, no QC may be emitted.
    /// Broadcasting a certificate no peer can verify is worse than
    /// stalling, and the honest votes must stay buffered for the retry.
    #[test]
    fn quarantine_below_quorum_emits_no_qc() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut leader =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        leader.submit_tx(TxBytes::new(vec![42]));
        let (header, _proposal) = leader.propose().expect("propose");
        let block_hash = OxideBft::block_hash(&header);

        let mut msg = Vec::with_capacity(49);
        msg.extend_from_slice(&header.view.value().to_le_bytes());
        msg.push(VotePhase::Prepare as u8);
        msg.extend_from_slice(block_hash.as_bytes());
        msg.extend_from_slice(&leader.epoch.value().to_le_bytes());

        // Two honest votes plus one forged: nominally 3, honestly 2.
        for voter in [0u16, 2] {
            let vote = Vote {
                view: header.view,
                phase: VotePhase::Prepare,
                block_hash,
                signature: keys[usize::from(voter)].sign(crypto::hash::Domain::Vote, &msg),
                attestation: None,
                attestation_sig: None,
            };
            leader.collect_vote(voter, vote).expect("honest vote accepted");
        }
        leader
            .collect_vote(
                1,
                Vote {
                    view: header.view,
                    phase: VotePhase::Prepare,
                    block_hash,
                    signature: keys[3].sign(crypto::hash::Domain::Vote, &msg),
                    attestation: None,
                    attestation_sig: None,
                },
            )
            .expect("default path stores without per-vote verification");

        assert!(leader.try_form_qc().is_none(), "must not emit a QC it cannot prove");
        assert_eq!(leader.vote_count(), 2, "honest votes must be preserved for the retry");
    }

    #[test]
    fn collect_vote_rejects_forged_signature() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
            .with_secret_key(keys[0].clone())
            .with_per_vote_verification();

        // Submit a tx and propose.
        leader.submit_tx(TxBytes::new(vec![42]));
        let (header, _proposal) = leader.propose().expect("propose");
        let block_hash = OxideBft::block_hash(&header);

        // Forge a vote: sign with key[2] but claim it's from validator 1.
        // The signature will verify against key[2]'s PK, not key[1]'s PK.
        // C3 fix: use the full (view, phase, block_hash, epoch) message.
        let mut vote_msg = Vec::with_capacity(49);
        vote_msg.extend_from_slice(&header.view.value().to_le_bytes());
        vote_msg.push(VotePhase::Prepare as u8);
        vote_msg.extend_from_slice(block_hash.as_bytes());
        vote_msg.extend_from_slice(&leader.epoch.value().to_le_bytes());
        let forged_sig = keys[2].sign(crypto::hash::Domain::Vote, &vote_msg);
        let forged_vote = Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: forged_sig,
            attestation: None,
            attestation_sig: None,
        };

        // collect_vote must reject the forged vote.
        let err = leader.collect_vote(1, forged_vote).expect_err("forged vote must be rejected");
        assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 1 });
    }

    #[test]
    fn collect_vote_rejects_out_of_bounds_voter() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut leader =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        let block_hash = Hash::ZERO;
        let vote = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };

        // Voter index 99 is out of bounds (n=4).
        let err = leader.collect_vote(99, vote).expect_err("out-of-bounds voter must be rejected");
        assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 99 });
    }

    /// C9 fix: `save_state` / `restore_state` round-trip must preserve
    /// the engine's safety-critical state.
    #[test]
    fn save_restore_state_round_trip() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
            .with_secret_key(keys[0].clone());

        // Advance the engine: submit, propose, vote.
        leader.submit_tx(TxBytes::new(vec![42]));
        let (header, _proposal) = leader.propose().expect("propose");
        let block_hash = OxideBft::block_hash(&header);

        // Simulate a vote at height 0 for this block.
        leader.voted_at_height.insert(0, block_hash);

        // The committed anchor must also round-trip: it is safety
        // state (the no-highQC vote arm's parent check).
        leader.last_committed = Some((block_hash, header.height));

        // Save the state.
        let state_bytes = leader.save_state();
        assert!(!state_bytes.is_empty(), "save_state must produce non-empty bytes");

        // Create a fresh engine and restore the state.
        let mut restored =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        restored.restore_state(&state_bytes).expect("restore_state must succeed");

        // Verify the state was restored.
        assert_eq!(restored.current_view, leader.current_view, "current_view must match");
        assert_eq!(restored.last_voted_view, leader.last_voted_view, "last_voted_view must match");
        assert_eq!(restored.next_height, leader.next_height, "next_height must match");
        assert_eq!(restored.epoch, leader.epoch, "epoch must match");
        assert_eq!(restored.high_qc, leader.high_qc, "high_qc must match");
        assert_eq!(restored.voted_at_height, leader.voted_at_height, "voted_at_height must match");
        assert_eq!(restored.last_committed, leader.last_committed, "last_committed must match");
    }

    /// C9 fix: `restore_state` must reject malformed buffers.
    #[test]
    fn restore_state_rejects_malformed_buffer() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut leader =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        // Too short (less than 33 bytes).
        let short = vec![0u8; 10];
        let err = leader.restore_state(&short).expect_err("short buffer must be rejected");
        assert_eq!(err, ConsensusError::InvalidState);

        // Empty buffer.
        let empty: Vec<u8> = vec![];
        let err = leader.restore_state(&empty).expect_err("empty buffer must be rejected");
        assert_eq!(err, ConsensusError::InvalidState);
    }

    #[test]
    fn deliver_qc_rejects_forged_aggregate() {
        // 4 validators with real BLS keys. A QC with a forged aggregate
        // signature (all zeros) must be rejected by deliver_qc.
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut engine =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        // Forge a QC: all-zero aggregate signature, but the signer
        // bitmap claims all 4 validators signed.
        let forged_qc = QuorumCertificate {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111], // all 4 validators
            aggregate_signature: AggregateSignature::ZERO, // forged
        };

        let err = engine.deliver_qc(forged_qc).expect_err("forged QC must be rejected");
        assert_eq!(err, ConsensusError::InvalidQcSignature);
    }

    #[test]
    fn collect_vote_accepts_valid_signature() {
        // 4 validators with real BLS keys. A valid vote (signed by
        // the claimed voter's key) must be accepted.
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut leader =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        leader.submit_tx(TxBytes::new(vec![42]));
        let (header, _proposal) = leader.propose().expect("propose");
        let block_hash = OxideBft::block_hash(&header);

        // Validator 1 signs its own vote with its own key.
        // C3 fix: sign with (view, phase, block_hash, epoch) message.
        let mut vote_msg = Vec::with_capacity(49);
        vote_msg.extend_from_slice(&header.view.value().to_le_bytes());
        vote_msg.push(VotePhase::Prepare as u8);
        vote_msg.extend_from_slice(block_hash.as_bytes());
        vote_msg.extend_from_slice(&leader.epoch.value().to_le_bytes());
        let valid_sig = keys[1].sign(crypto::hash::Domain::Vote, &vote_msg);
        let valid_vote = Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: valid_sig,
            attestation: None,
            attestation_sig: None,
        };

        leader.collect_vote(1, valid_vote).expect("valid vote must be accepted");
    }

    #[test]
    fn on_timeout_certificate_rejects_forged_tc() {
        // 4 validators with real BLS keys. A TC with a forged aggregate
        // signature (all zeros) must be rejected by on_timeout_certificate.
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut engine =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        // Forge a TC: all-zero aggregate signature, but the signer
        // bitmap claims all 4 validators signed.
        let forged_tc = TimeoutCertificate {
            view: View::new(0),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111], // all 4 validators
            aggregate_signature: AggregateSignature::ZERO, // forged
        };

        let err =
            engine.on_timeout_certificate(&forged_tc).expect_err("forged TC must be rejected");
        assert_eq!(err, ConsensusError::InvalidTcSignature);
    }

    #[test]
    fn collect_timeout_signature_rejects_forged_signature() {
        // 4 validators with real BLS keys. A forged timeout signature
        // (signed by the wrong key) must be rejected.
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut engine =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        // Validator 1 times out and signs the view.
        let _ = engine.on_timeout();

        // Forge a timeout signature: sign with validator 2's key but
        // claim it's from validator 1. M1 fix: sign with (view, epoch).
        let mut timeout_msg = Vec::with_capacity(16);
        timeout_msg.extend_from_slice(&engine.current_view.value().to_le_bytes());
        timeout_msg.extend_from_slice(&engine.epoch.value().to_le_bytes());
        let forged_sig = keys[2].sign(crypto::hash::Domain::Timeout, &timeout_msg);
        let err = engine
            .collect_timeout_signature(1, forged_sig)
            .expect_err("forged timeout signature must be rejected");
        assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 1 });
    }

    #[test]
    fn collect_timeout_signature_accepts_valid_signature() {
        // 4 validators with real BLS keys. A valid timeout signature
        // (signed by the claimed voter's key) must be accepted.
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut engine =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        // Validator 1 signs the timeout for view 0. M1 fix: sign
        // with (view, epoch).
        let mut timeout_msg = Vec::with_capacity(16);
        timeout_msg.extend_from_slice(&engine.current_view.value().to_le_bytes());
        timeout_msg.extend_from_slice(&engine.epoch.value().to_le_bytes());
        let valid_sig = keys[1].sign(crypto::hash::Domain::Timeout, &timeout_msg);
        let result = engine.collect_timeout_signature(1, valid_sig);
        assert!(result.is_ok(), "valid timeout signature must be accepted");
    }

    // ---- Epoch rotation tests (stage 6) ----
    //
    // These tests exercise the two-phase epoch handoff: schedule a
    // new validator set, then complete the rotation.

    fn second_validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![pk(5), pk(6)], vec![1, 1]).expect("2 validators")
    }

    /// A different single-validator set — used by the rotation
    /// continuation test. A lone engine inside a multi-validator set
    /// legitimately cannot reach quorum (`n − f` signers), so driving
    /// post-rotation consensus requires a set it can quorum in alone.
    fn replacement_single_validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![pk(9)], vec![1]).expect("1 validator")
    }

    #[test]
    fn schedule_rotation_sets_pending() {
        let mut engine = make_engine();
        assert!(!engine.rotation_pending());
        engine.schedule_rotation(second_validator_set()).expect("schedule");
        assert!(engine.rotation_pending());
    }

    #[test]
    fn schedule_rotation_rejects_double_schedule() {
        let mut engine = make_engine();
        engine.schedule_rotation(second_validator_set()).expect("first");
        let err = engine.schedule_rotation(second_validator_set());
        assert!(err.is_err(), "double schedule must fail");
    }

    #[test]
    fn rotate_epoch_completes_rotation() {
        let mut engine = make_engine();
        engine.schedule_rotation(second_validator_set()).expect("schedule");
        assert!(engine.rotation_pending());
        engine.rotate_epoch().expect("rotate");
        assert!(!engine.rotation_pending());
        assert_eq!(engine.epoch(), Epoch::new(1));
        assert_eq!(engine.current_view(), View::new(0));
    }

    #[test]
    fn rotate_epoch_without_pending_fails() {
        let mut engine = make_engine();
        let err = engine.rotate_epoch();
        assert!(err.is_err(), "rotation without pending must fail");
    }

    #[test]
    fn rotate_epoch_resets_view_and_votes() {
        let mut engine = make_engine();
        // Advance the view and collect some state.
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        let view_before = engine.current_view();
        assert!(view_before.value() > 0, "view should have advanced");

        // Schedule and complete rotation.
        engine.schedule_rotation(second_validator_set()).expect("schedule");
        engine.rotate_epoch().expect("rotate");

        // View resets to 0, last_voted_view resets to None.
        assert_eq!(engine.current_view(), View::new(0));
        assert_eq!(engine.last_voted_view, None);
    }

    #[test]
    fn rotate_epoch_changes_validator_set() {
        let mut engine = make_engine();
        let original_n = engine.validator_set.n();
        engine.schedule_rotation(second_validator_set()).expect("schedule");
        engine.rotate_epoch().expect("rotate");
        // The new set has 2 validators, the old had 1.
        assert_ne!(engine.validator_set.n(), original_n);
        assert_eq!(engine.validator_set.n(), 2);
    }

    #[test]
    fn pacemaker_timeouts_reach_the_running_engine() {
        // `with_pacemaker_timeouts` must override the compiled
        // defaults — the parsed `consensus.base_timeout_ms` /
        // `max_timeout_ms` values flow through this knob.
        let engine = make_engine().with_pacemaker_timeouts(5_000, 60_000);
        assert_eq!(
            engine.pacemaker_timeout_ms(),
            5_000,
            "the current view timeout must equal the configured base"
        );
    }

    #[test]
    fn pacemaker_timeouts_survive_epoch_rotation() {
        // Rotation rebuilds the pacemaker — a rebuild from
        // `Pacemaker::new` would silently revert configured timeouts
        // to defaults. The engine must carry them across the rebuild.
        let mut engine = make_engine().with_pacemaker_timeouts(5_000, 60_000);
        engine.schedule_rotation(second_validator_set()).expect("schedule");
        engine.rotate_epoch().expect("rotate");
        assert_eq!(
            engine.pacemaker_timeout_ms(),
            5_000,
            "configured timeouts must survive the rotation rebuild, \
             not revert to the 2000ms default"
        );
    }

    #[test]
    fn block_budget_is_configurable() {
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1_000_000_000 };
        let engine = make_engine().with_block_budget(budget);
        assert_eq!(engine.block_budget(), budget);
        // Default remains the chain-configured budget.
        assert_eq!(make_engine().block_budget(), types::CHAIN_BLOCK_BUDGET);
    }

    /// The body commitment must follow the LIVE committee's
    /// erasure layout: after a rotation that changes the stake
    /// distribution, the next proposal's `body_commitment`
    /// recomputes with the new set's `k` — not the construction
    /// set's. A stale `k` would make honest replicas (deriving the
    /// same new `k`) fail to reproduce the signed root.
    #[test]
    fn body_commitment_uses_rotated_committee_layout() {
        let mut engine = make_engine();
        // Single-validator committee: no Byzantine possible —
        // k = 1, one plain chunk.
        assert_eq!(engine.erasure_k(), 1);
        // Rotate into a 4-validator committee with skewed stakes:
        // the Byzantine budget admits the two small validators,
        // so k = 2 — different layout, different root.
        let rotated = ValidatorSet::new(vec![pk(5), pk(6), pk(7), pk(8)], vec![3, 3, 1, 1])
            .expect("rotated set");
        engine.schedule_rotation(rotated.clone()).expect("schedule");
        engine.rotate_epoch().expect("rotate");
        assert_eq!(engine.erasure_k(), 2);
        engine.submit_tx(TxBytes::new(vec![1, 2, 3]));
        let (header, proposal) = engine.propose().expect("propose after rotation");
        let mut buf = Vec::new();
        proposal.encode(&mut buf);
        assert_eq!(
            header.body_commitment,
            types::shard::commitment(&buf, rotated.n(), engine.erasure_k()),
            "the signed root must follow the rotated committee's layout"
        );
        assert_ne!(
            header.body_commitment,
            types::shard::commitment(&buf, rotated.n(), rotated.n()),
            "and must differ from the plain n-of-n layout a stale derivation would produce"
        );
    }

    /// The proposal clock lands in the signed header: a leader
    /// stamps `with_clock`'s value — the value the whole cluster
    /// will execute under — not a height-derived stand-in.
    #[test]
    fn propose_stamps_injected_clock() {
        let mut leader = make_multi_engine(0).with_clock(|| 1_700_000_000_123);
        let (header, _proposal) = leader.propose().expect("leader proposes");
        assert_eq!(header.timestamp, 1_700_000_000_123);
    }

    /// The committed block carries the consensus execution context
    /// on every replica: the header's signed timestamp, the
    /// proposer's staking address resolved from `header.proposer`
    /// against the validator set, and the block budget's gas limit.
    /// Because all three derive from committed material, leader and
    /// followers observe identical contexts.
    #[test]
    fn committed_block_carries_execution_context() {
        const TS: u64 = 1_700_000_000_123;
        let mut leader = make_multi_engine(0).with_clock(|| TS);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];
        drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![1])));
        // The QC for h1 is what commits h0 (2-chain rule).
        drive_round(&mut leader, &mut followers, None);

        let expected_beneficiary = four_validator_set().validator_addresses()[0];
        for (name, e) in [("leader", &leader), ("f1", &f1), ("f2", &f2), ("f3", &f3)] {
            let block = e
                .finalized_block(Height::new(0))
                .unwrap_or_else(|| panic!("{name}: h0 must be committed"));
            assert_eq!(block.context.timestamp_ms, TS, "{name}: committed timestamp");
            assert_eq!(
                block.context.beneficiary, expected_beneficiary,
                "{name}: beneficiary is the proposer's staking address"
            );
            assert_eq!(
                block.context.gas_limit,
                types::CHAIN_BLOCK_BUDGET.max_gas,
                "{name}: gas limit is the enforced block budget"
            );
        }
    }

    /// `vote()` rejects a proposal whose committed timestamp goes
    /// backwards relative to its parent — the one objective clock
    /// rule consensus enforces. An equal timestamp (same millisecond
    /// tick) remains legal.
    #[test]
    fn vote_rejects_backwards_timestamp() {
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
        let mut leader = make_multi_engine(0).with_clock({
            let c = Arc::clone(&clock);
            move || c.load(std::sync::atomic::Ordering::Relaxed)
        });
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];
        // Round 1: h0 is proposed (ts=1000), voted, and QC'd — the
        // followers store its header in `blocks`, which is what
        // `parent_timestamp` consults for the round-2 child.
        drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![1])));

        // Round 2 with a backwards clock: the child of the
        // ts=1000 parent stamps 500 — an objective violation.
        clock.store(500, std::sync::atomic::Ordering::Relaxed);
        let (header, proposal) = leader.propose().expect("round-2 proposal");
        assert_eq!(header.timestamp, 500);
        assert!(
            f1.vote(&header, &proposal).is_none(),
            "a timestamp earlier than the parent's must be rejected"
        );

        // An equal stamp (same millisecond as the parent) is legal.
        clock.store(1_000, std::sync::atomic::Ordering::Relaxed);
        let (header2, proposal2) = leader.propose().expect("re-proposal");
        assert_eq!(header2.timestamp, 1_000);
        assert!(
            f2.vote(&header2, &proposal2).is_some(),
            "a timestamp equal to the parent's must be accepted"
        );
    }

    #[test]
    fn engine_continues_after_rotation() {
        let mut engine = make_engine();
        // Commit a block in epoch 0.
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();

        // Rotate to a new epoch — a single-validator set, because a
        // lone engine inside a multi-validator set cannot reach the
        // `n − f` quorum alone (a self-signed single-signer "QC" is
        // not a certificate). Under the previous `2f + 1` formula a
        // 2-validator set had quorum 1 and this engine could commit
        // unilaterally — exactly the unsafe threshold this fix removes.
        engine.schedule_rotation(replacement_single_validator_set()).expect("schedule");
        engine.rotate_epoch().expect("rotate");
        assert_eq!(engine.epoch(), Epoch::new(1));

        // The engine should still be able to propose and commit in
        // the new epoch. Note: the validator_index (0) is still valid
        // in the new 2-validator set.
        engine.submit_tx(TxBytes::new(vec![2]));
        engine.run_until_idle();

        // The new tx should be committed.
        let h = engine.finalized_height().expect("finalized").value();
        let mut found = false;
        for i in 0..=h {
            if let Some(block) = engine.finalized_block(Height::new(i)) {
                if block.txs.iter().any(|t| t.as_bytes() == [2]) {
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "tx submitted after rotation must be committed");
    }

    #[test]
    fn epoch_in_blocks_increments_after_rotation() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();

        // Before rotation, blocks are in epoch 0.
        assert_eq!(engine.epoch(), Epoch::new(0));

        // Rotate.
        engine.schedule_rotation(second_validator_set()).expect("schedule");
        engine.rotate_epoch().expect("rotate");

        // After rotation, new blocks are in epoch 1.
        engine.submit_tx(TxBytes::new(vec![2]));
        engine.run_until_idle();
        assert_eq!(engine.epoch(), Epoch::new(1));
    }

    // ---- Tail-fork resistance tests ----
    //
    // docs/oxidebft-spec.md §4: validators reject proposals that don't
    // extend the highest QC they voted for. This prevents a faulty
    // leader from discarding a notarized block (MEV-by-discard).

    #[test]
    fn tail_fork_rejects_proposal_without_high_qc() {
        // After the engine has a high_qc, a proposal with no high_qc
        // (a fork) must be rejected.
        let mut engine = make_engine();
        // Drive one round to establish a high_qc.
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        assert!(engine.high_qc.is_some(), "high_qc should be set");

        // Craft a proposal with no high_qc (a fork).
        let proposal = Proposal {
            height: Height::new(99),
            txs: vec![TxBytes::new(vec![2])],
            attestation: None,
        };
        let header = BlockHeader {
            height: Height::new(99),
            view: View::new(99),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: OxideBft::tx_root(&proposal.txs),
            high_qc: None, // fork: no high_qc
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let vote = engine.vote(&header, &proposal);
        assert!(vote.is_none(), "fork proposal without high_qc must be rejected");
    }

    #[test]
    fn tail_fork_rejects_proposal_with_wrong_high_qc() {
        // After the engine has a high_qc, a proposal with a different
        // high_qc (extending a different chain) must be rejected.
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        let our_high_qc = engine.high_qc.clone().expect("high_qc set");

        // Craft a fake QC over a different block.
        let fake_qc = QuorumCertificate {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO, // different block
            epoch: Epoch::new(0),
            signer_bitmap: vec![0x01],
            aggregate_signature: AggregateSignature::ZERO,
        };

        let proposal = Proposal {
            height: Height::new(99),
            txs: vec![TxBytes::new(vec![2])],
            attestation: None,
        };
        let header = BlockHeader {
            height: Height::new(99),
            view: View::new(99),
            epoch: Epoch::new(0),
            prev_block: fake_qc.block_hash,
            tx_root: OxideBft::tx_root(&proposal.txs),
            high_qc: Some(fake_qc),
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let vote = engine.vote(&header, &proposal);
        assert!(
            vote.is_none(),
            "fork proposal with wrong high_qc must be rejected (our high_qc block: {:?})",
            our_high_qc.block_hash
        );
    }

    #[test]
    fn tail_fork_accepts_proposal_extending_high_qc() {
        // After the engine has a high_qc, a proposal that extends it
        // (same high_qc) must be accepted.
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        let our_high_qc = engine.high_qc.clone().expect("high_qc set");

        // The stamped height must be the parent's height + 1 —
        // vote() now enforces height continuity, so derive it from
        // the stored parent header.
        let stamped_height = engine
            .blocks
            .get(&our_high_qc.block_hash)
            .map(|(h, _)| h.height.saturating_next())
            .expect("high_qc block must be in the block map");

        let proposal = Proposal {
            height: stamped_height,
            txs: vec![TxBytes::new(vec![2])],
            attestation: None,
        };
        // HIGH fix: vote() now requires header.view == current_view.
        // Set current_view to match the test proposal's view.
        engine.current_view = View::new(99);
        let header = BlockHeader {
            height: stamped_height,
            view: View::new(99),
            epoch: Epoch::new(0),
            prev_block: our_high_qc.block_hash,
            tx_root: OxideBft::tx_root(&proposal.txs),
            high_qc: Some(our_high_qc),
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let vote = engine.vote(&header, &proposal);
        assert!(vote.is_some(), "proposal extending high_qc must be accepted");
    }

    #[test]
    fn tail_fork_accepts_proposal_with_newer_high_qc() {
        // Regression test for tail-fork *resistance* (extends-highest-QC
        // rule, docs/oxidebft-spec.md §4). After the engine has a
        // high_qc, a proposal carrying a *newer* QC (higher view, e.g.
        // from a view-change leader that saw a QC we missed) must be
        // accepted — not rejected for failing strict equality with our
        // high_qc. The old strict-`block_hash`-equality check rejected
        // these valid proposals from a newer fork; the view-ordering
        // check (`prop_qc.view >= our_high_qc.view`) accepts them.
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        let our_high_qc = engine.high_qc.clone().expect("high_qc set");

        // Craft a QC one view newer than ours, over a different block
        // (simulating a view-change leader that built on a fresher QC).
        let newer_qc = QuorumCertificate {
            view: View::new(our_high_qc.view.value() + 1),
            phase: VotePhase::Prepare,
            block_hash: Hash([0xab; 32]), // different block — strict equality would reject
            epoch: Epoch::new(0),
            signer_bitmap: vec![0x01],
            aggregate_signature: AggregateSignature::ZERO,
        };

        // HIGH fix: vote() now requires header.view == current_view
        // and prev_block == high_qc.block_hash. Set current_view to
        // match, and update high_qc so prev_block matches. The voter
        // must also have the parent block stored — height continuity
        // (`header.height == parent.height + 1`) is verified against
        // the stored header — so insert the block the newer QC
        // points at, stamped at the chain tip's height.
        let parent_height = engine.next_height;
        let parent_proposal =
            Proposal { height: parent_height, txs: vec![TxBytes::new(vec![9])], attestation: None };
        let parent_header = BlockHeader {
            height: parent_height,
            view: View::new(our_high_qc.view.value() + 1),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: OxideBft::tx_root(&parent_proposal.txs),
            high_qc: None,
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        engine
            .blocks
            .insert(newer_qc.block_hash, (parent_header, BlockBody::Complete(parent_proposal)));

        let stamped_height = parent_height.saturating_next();
        let proposal_view = View::new(our_high_qc.view.value() + 2);
        engine.current_view = proposal_view;
        engine.high_qc = Some(newer_qc.clone());
        let proposal = Proposal {
            height: stamped_height,
            txs: vec![TxBytes::new(vec![2])],
            attestation: None,
        };
        let header = BlockHeader {
            height: stamped_height,
            view: proposal_view,
            epoch: Epoch::new(0),
            prev_block: newer_qc.block_hash,
            tx_root: OxideBft::tx_root(&proposal.txs),
            high_qc: Some(newer_qc),
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let vote = engine.vote(&header, &proposal);
        assert!(
            vote.is_some(),
            "proposal with a newer high_qc (view > ours) must be accepted (extends-highest-QC rule)"
        );
    }

    #[test]
    fn tail_fork_rejects_proposal_with_older_high_qc() {
        // Complement to the above: a proposal carrying an *older* QC
        // (lower view than our high_qc) is a stale fork and must still
        // be rejected. This guards against regressing the safety side
        // of the extends-highest-QC rule.
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        let our_high_qc = engine.high_qc.clone().expect("high_qc set");
        // Only meaningful once we've advanced past view 0.
        assert!(our_high_qc.view.value() > 0, "high_qc should be past view 0 after a round");

        let older_qc = QuorumCertificate {
            view: View::new(our_high_qc.view.value() - 1),
            phase: VotePhase::Prepare,
            block_hash: Hash([0xcd; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0x01],
            aggregate_signature: AggregateSignature::ZERO,
        };

        let proposal = Proposal {
            height: Height::new(99),
            txs: vec![TxBytes::new(vec![2])],
            attestation: None,
        };
        let header = BlockHeader {
            height: Height::new(99),
            view: View::new(99),
            epoch: Epoch::new(0),
            prev_block: older_qc.block_hash,
            tx_root: OxideBft::tx_root(&proposal.txs),
            high_qc: Some(older_qc),
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let vote = engine.vote(&header, &proposal);
        assert!(
            vote.is_none(),
            "proposal with an older high_qc (view < ours) must be rejected (stale fork)"
        );
    }

    #[test]
    fn tail_fork_accepts_genesis_proposal() {
        // At genesis (no high_qc), any proposal is accepted.
        let mut engine = make_engine();
        let proposal = Proposal {
            height: Height::new(0),
            txs: vec![TxBytes::new(vec![1])],
            attestation: None,
        };
        let header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: OxideBft::tx_root(&proposal.txs),
            high_qc: None,
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let vote = engine.vote(&header, &proposal);
        assert!(vote.is_some(), "genesis proposal must be accepted");
    }

    #[test]
    fn divergence_detection_rejects_mismatched_exec_cert() {
        // When a proposal carries an exec_cert whose state_root
        // differs from the locally computed state root, the engine
        // must refuse to vote (divergence detected).
        //
        // We use an engine with signature verification enabled (the
        // divergence check is gated on verify_signatures). C3 fix:
        // the validator set must use the real public key derived
        // from the BLS secret key so proposer-signature verification
        // passes (the fake `pk(1)` key doesn't match `bls_key(1)`).
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

        // The MockApp's attest_state for height 0 returns
        // Hash([0x00; 32]) (height 0 → byte 0). We craft an
        // exec_cert with a *different* state_root to trigger
        // divergence.
        let mock_root = Hash([0x00; 32]);
        let divergent_root = Hash([0xDE; 32]); // != mock_root

        // A real, correctly-signed cert over the *wrong* root —
        // the reject must come from the root comparison, not from
        // signature verification (a fabricated cert would fail
        // verify_exec_cert earlier and for a different reason).
        let att_msg = engine.attestation_signing_message(Height::new(0), &divergent_root);
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let exec_cert = ExecCertificate {
            height: Height::new(0),
            state_root: divergent_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        };

        let proposal = Proposal {
            height: Height::new(0),
            txs: vec![TxBytes::new(vec![1])],
            attestation: None,
        };
        // C3: sign the header so the proposer-auth check passes;
        // the divergence check is what we're testing here.
        let mut header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: OxideBft::tx_root(&proposal.txs),
            high_qc: None,
            timeout_cert: None,
            proposer: proposer_hash(0),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: Some(exec_cert),
            body_commitment: Hash::ZERO,
        };
        let signing_hash = OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
        let vote = engine.vote(&header, &proposal);
        assert!(
            vote.is_none(),
            "proposal with divergent exec_cert must be rejected (state divergence)"
        );

        // Sanity: the divergent root is indeed different from the
        // mock root.
        assert_ne!(divergent_root, mock_root, "test setup: roots must differ");
    }

    #[test]
    fn divergence_detection_accepts_matching_exec_cert() {
        // When a proposal carries an exec_cert whose state_root
        // *matches* the locally computed state root, the engine
        // proceeds normally (no divergence).
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

        // MockApp returns Hash([0x00; 32]) for height 0.
        let matching_root = Hash([0x00; 32]);

        let att_msg = engine.attestation_signing_message(Height::new(0), &matching_root);
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let exec_cert = ExecCertificate {
            height: Height::new(0),
            state_root: matching_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        };

        let proposal = Proposal {
            height: Height::new(0),
            txs: vec![TxBytes::new(vec![1])],
            attestation: None,
        };
        // C3: sign the header so the proposer-auth check passes.
        // The signed header must also carry the real body
        // commitment — `vote` verifies the binding in production
        // mode (this engine verifies signatures).
        let mut body = Vec::new();
        proposal.encode(&mut body);
        let mut header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: OxideBft::tx_root(&proposal.txs),
            body_commitment: types::shard::commitment(&body, 1, 1),
            high_qc: None,
            timeout_cert: None,
            proposer: proposer_hash(0),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: Some(exec_cert),
        };
        let signing_hash = OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
        let vote = engine.vote(&header, &proposal);
        assert!(vote.is_some(), "proposal with matching exec_cert must be accepted");
    }

    // ---- Exec-cert validation hardening ----
    //
    // Audit: a matching `state_root` used to skip *all* certificate
    // validation — signature, signer bitmap, quorum, and epoch — so a
    // leader could embed a fabricated cert and have it committed as
    // unproven "proof" of execution agreement. Attestations were also
    // cached by `(height, root)` without the epoch they sign, and an
    // unexecuted height reported `Hash::ZERO`, matching a forged cert
    // that claimed a zero root. These tests pin the hardened
    // behavior: full validation once per cert identity, epoch-bound
    // certificates, and an explicit "not executed" signal.

    /// Build a correctly-signed single-validator proposal at genesis
    /// carrying `cert` as its `exec_cert`. Mirrors the header shape
    /// `divergence_detection_accepts_matching_exec_cert` proves is
    /// accepted when the cert is valid.
    fn genesis_proposal_with_cert(
        sk: &crypto::BlsSecretKey,
        cert: ExecCertificate,
    ) -> (BlockHeader, Proposal) {
        let proposal = Proposal {
            height: Height::new(0),
            txs: vec![TxBytes::new(vec![1])],
            attestation: None,
        };
        let mut body = Vec::new();
        proposal.encode(&mut body);
        let mut header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: OxideBft::tx_root(&proposal.txs),
            body_commitment: types::shard::commitment(&body, 1, 1),
            high_qc: None,
            timeout_cert: None,
            proposer: proposer_hash(0),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: Some(cert),
        };
        let signing_hash = OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
        (header, proposal)
    }

    #[test]
    fn forged_exec_cert_with_matching_root_rejected() {
        // The cert's root matches local execution, but its aggregate
        // signature is over a different message — a fabrication. The
        // old code voted anyway (root match bypassed verification);
        // a forged cert must withhold the vote regardless of the
        // root it carries.
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

        let matching_root = Hash([0x00; 32]); // mock_state_root(0)
        let wrong_msg = engine.attestation_signing_message(Height::new(0), &Hash([0xAA; 32]));
        let forged_sig = sk.sign(crypto::hash::Domain::ExecAttest, &wrong_msg);
        let cert = ExecCertificate {
            height: Height::new(0),
            state_root: matching_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[forged_sig]).expect("aggregate"),
        };
        let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
        let vote = engine.vote(&header, &proposal);
        assert!(
            vote.is_none(),
            "a forged exec_cert must withhold the vote even when its root matches local state"
        );
    }

    #[test]
    fn exec_cert_with_wrong_epoch_rejected() {
        // Attestations sign `(height, root, epoch)` and the bitmap
        // indexes the *current* validator set — a cert claiming any
        // other epoch is unverifiable even when its signature
        // happens to match this epoch's message.
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

        let matching_root = Hash([0x00; 32]);
        let att_msg = engine.attestation_signing_message(Height::new(0), &matching_root);
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let cert = ExecCertificate {
            height: Height::new(0),
            state_root: matching_root,
            // One epoch ahead of the engine — same signature bytes,
            // wrong claimed epoch.
            epoch: Epoch::new(1),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        };
        assert!(
            engine.verify_exec_cert(&cert).is_err(),
            "a cert whose epoch differs from the engine's must fail verification"
        );
        let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
        assert!(
            engine.vote(&header, &proposal).is_none(),
            "a proposal embedding a stale-epoch cert must be refused"
        );
    }

    #[test]
    fn propose_never_embeds_stale_epoch_cert() {
        // `propose()` selects the newest embeddable cert; a cert from
        // another epoch can never be verified by voters, so the
        // leader must not embed it — doing so would withhold every
        // honest vote and waste the view.
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

        // A cert for height 0 stamped with a foreign epoch, and a
        // committed anchor at height 1 so the leader proposes
        // height 2 (the embed bound is `cert.height <= h - 2`).
        let att_msg = engine.attestation_signing_message(Height::new(0), &Hash([0x00; 32]));
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        engine.exec_certs.insert(
            0,
            ExecCertificate {
                height: Height::new(0),
                state_root: Hash([0x00; 32]),
                epoch: Epoch::new(99),
                signer_bitmap: vec![0b0000_0001],
                aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
            },
        );
        engine.last_committed = Some((Hash([9; 32]), Height::new(1)));

        let (header, _proposal) = engine.propose().expect("genesis chain must propose");
        assert_eq!(header.height, Height::new(2));
        assert!(
            header.exec_cert.is_none(),
            "a stale-epoch cert must never be embedded in a proposal"
        );
    }

    #[test]
    fn attestation_cache_binds_epoch() {
        // The attestation signature cache must key on the epoch the
        // signature commits to. Reusing a signature minted in epoch N
        // under epoch N+1 attaches an attestation that fails every
        // verify — the cached sig must not survive an epoch change.
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(app.clone(), vs).with_secret_key(sk.clone());

        // Give the app an executed tip with a non-zero root (height 1;
        // height 0's mock root is Hash::ZERO, the never-attested
        // sentinel).
        app.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![],
            signers: vec![],
        });
        app.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: vec![],
            signers: vec![],
        });

        let (att0, sig0) = engine.vote_attestation();
        assert!(att0.is_some() && sig0.is_some(), "executed tip must produce an attestation");
        // Same epoch: the deterministic BLS signature is cached —
        // byte-identical on repeat.
        let (_, sig0_again) = engine.vote_attestation();
        assert_eq!(sig0, sig0_again, "same-epoch attestation must reuse the cached signature");

        // Simulate the epoch boundary: the same `(height, root)` now
        // signs a different message, so the cached signature is
        // invalid and must be re-minted.
        engine.epoch = Epoch::new(1);
        let (att1, sig1) = engine.vote_attestation();
        assert_eq!(att0, att1, "the attested tip is unchanged across the boundary");
        assert_ne!(sig0, sig1, "an epoch change must invalidate the cached attestation signature");
    }

    /// An app whose execution lane never runs: `attest_state`
    /// returns `None` for every height — the explicit "not
    /// executed" signal a `Hash::ZERO` sentinel used to hide.
    /// Exercises the vote path's cannot-confirm branch, which
    /// `MockApp`'s fabricating `attest_state` cannot reach.
    struct NeverExecutedApp;

    impl AppInterface for NeverExecutedApp {
        fn ingest_tx(&self, _tx: TxBytes) -> MempoolAck {
            MempoolAck::Accepted
        }
        fn prepare_proposal(&self, _budget: &types::BlockBudget) -> Proposal {
            Proposal { height: Height::new(0), txs: Vec::new(), attestation: None }
        }
        fn has_queued_txs(&self) -> bool {
            false
        }
        fn process_proposal(&self, _proposal: &Proposal) -> Verdict {
            Verdict::Accept
        }
        fn finalize_block(&self, block: &FinalizedBlock) -> types::CommitAck {
            types::CommitAck { height: block.height }
        }
        fn attest_state(&self, _height: Height) -> Option<StateAttestation> {
            None
        }
        fn attest_latest(&self) -> Option<StateAttestation> {
            None
        }
    }

    #[test]
    fn exec_cert_for_unexecuted_height_withheld() {
        // A *validly signed* cert claiming a state root for a height
        // the app never executed must still withhold the vote: there
        // is no local execution to confirm it against. Before
        // `attest_state` returned `Option`, the `Hash::ZERO` sentinel
        // made a cert claiming a zero root "match" an unexecuted
        // height and the vote went through.
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(Arc::new(NeverExecutedApp), vs).with_secret_key(sk.clone());

        // Claim a ZERO root at height 0 — the exact value the old
        // sentinel produced for unexecuted heights. The cert itself
        // verifies (real signature, in-bounds bitmap, right epoch);
        // only local confirmation is missing.
        let att_msg = engine.attestation_signing_message(Height::new(0), &Hash::ZERO);
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let cert = ExecCertificate {
            height: Height::new(0),
            state_root: Hash::ZERO,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        };
        let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
        assert!(
            engine.vote(&header, &proposal).is_none(),
            "a cert for a height with no local execution must withhold the vote"
        );
    }

    #[test]
    fn verified_exec_cert_is_cached_per_identity() {
        // A cert that passes full validation is cached under its
        // complete identity; a *different* cert at the same height
        // must re-validate (and fail, here) rather than inheriting
        // the cached verdict.
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

        let matching_root = Hash([0x00; 32]);
        let att_msg = engine.attestation_signing_message(Height::new(0), &matching_root);
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let cert = ExecCertificate {
            height: Height::new(0),
            state_root: matching_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        };
        let (header, proposal) = genesis_proposal_with_cert(&sk, cert.clone());
        assert!(engine.vote(&header, &proposal).is_some(), "a valid cert must be accepted");
        assert_eq!(
            engine.verified_exec_certs.get(&0),
            Some(&cert),
            "the verified cert must be cached under its complete identity"
        );

        // A forged cert at the SAME height: the cached entry must
        // not launder it — it re-validates and fails.
        let wrong_msg = engine.attestation_signing_message(Height::new(0), &Hash([0xBB; 32]));
        let forged_sig = sk.sign(crypto::hash::Domain::ExecAttest, &wrong_msg);
        let forged = ExecCertificate {
            aggregate_signature: crypto::aggregate(&[forged_sig]).expect("aggregate"),
            ..cert
        };
        let (header, proposal) = genesis_proposal_with_cert(&sk, forged);
        assert!(
            engine.vote(&header, &proposal).is_none(),
            "a forged cert must re-validate even when a valid cert is cached at its height"
        );
    }

    #[test]
    fn rotation_clears_exec_cert_state() {
        // Certs, pooled attestations, and cached verifications are
        // bound to the signing epoch's validator set — none may
        // outlive the epoch they were formed in.
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

        let att_msg = engine.attestation_signing_message(Height::new(0), &Hash([7; 32]));
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let cert = ExecCertificate {
            height: Height::new(0),
            state_root: Hash([7; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        };
        engine
            .exec_attest_pool
            .entry(0)
            .or_default()
            .entry(Hash([7; 32]))
            .or_default()
            .push((0u16, Signature::ZERO));
        engine.exec_certs.insert(0, cert.clone());
        engine.verified_exec_certs.insert(0, cert);

        engine.schedule_rotation(second_validator_set()).expect("schedule");
        engine.rotate_epoch().expect("rotate");
        assert!(engine.exec_attest_pool.is_empty(), "stale attestations must not survive rotation");
        assert!(engine.exec_certs.is_empty(), "stale certs must not survive rotation");
        assert!(
            engine.verified_exec_certs.is_empty(),
            "cached verifications must not survive rotation"
        );
    }

    // ---- Execution attestation / exec-cert aggregation tests ----
    //
    // Votes carry `StateAttestation`s (BLS-signed under
    // `Domain::ExecAttest`); leaders aggregate quorum-identical
    // attestations into `ExecCertificate`s embedded in later
    // proposals — the chain's divergence-detection substrate.

    /// Build a signed-mode 4-validator committee: engines with real
    /// keys and signature verification on (production path).
    fn signed_committee() -> (Vec<OxideBft>, Vec<crypto::BlsSecretKey>) {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
        let engines = (0..4u16)
            .map(|i| {
                OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), i)
                    .with_secret_key(keys[usize::from(i)].clone())
            })
            .collect();
        (engines, keys)
    }

    #[test]
    fn vote_carries_execution_attestation() {
        // After the app has executed a block, the engine's vote must
        // carry an attestation for that height+root — the raw input
        // leaders aggregate into exec certs.
        let (mut engines, _keys) = signed_committee();
        let engine = &mut engines[1];
        // Height 1, not 0: the mock's height-derived root for height 0
        // is `Hash::ZERO` — the same value `attest_latest` uses as the
        // "nothing executed" sentinel — so an attestation for height 0
        // could never be observed. Height 1 attests cleanly.
        engine.app.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: vec![],
            signers: vec![],
        });

        // A genesis-style proposal (height 0, no highQC needed).
        let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
        let mut body = Vec::new();
        proposal.encode(&mut body);
        let mut header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: OxideBft::tx_root(&proposal.txs),
            body_commitment: types::shard::commitment(&body, 4, 3),
            high_qc: None,
            timeout_cert: None,
            proposer: proposer_hash(0),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
        };
        // Sign with the real leader key so proposer auth passes.
        let sk = bls_key(1);
        let signing_hash = OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));

        let vote = engine.vote(&header, &proposal).expect("vote must be produced");
        let att = vote.attestation.expect("vote must carry an attestation");
        assert_eq!(att.height, Height::new(1), "attestation covers executed height");
        assert_eq!(
            att.root,
            engine.app.attest_state(Height::new(1)).expect("executed").root,
            "attestation root matches local execution"
        );
        // The attestation signature must verify under ExecAttest.
        let msg = engine.attestation_signing_message(att.height, &att.root);
        let pk = &bls_key(2).public_key();
        crypto::verify(
            &vote.attestation_sig.expect("attestation must be signed"),
            crypto::hash::Domain::ExecAttest,
            &msg,
            pk,
        )
        .expect("attestation signature must verify");
    }

    #[test]
    fn exec_cert_forms_from_quorum_attestations() {
        // Three (of four) identical, correctly-signed attestations
        // for the same (height, root) must aggregate into an
        // ExecCertificate on the collecting leader.
        let (mut engines, keys) = signed_committee();
        let leader = &mut engines[0];
        let height = Height::new(7);
        let root = Hash([0x77; 32]);
        let block_hash = Hash([0xAB; 32]);

        for i in 1u16..=3 {
            let att = StateAttestation { height, root };
            let msg = leader.attestation_signing_message(height, &root);
            let att_sig = keys[usize::from(i)].sign(crypto::hash::Domain::ExecAttest, &msg);
            let vote_msg = leader.vote_signing_message(View::new(0), 0, &block_hash);
            let vote_sig = keys[usize::from(i)].sign(crypto::hash::Domain::Vote, &vote_msg);
            leader
                .collect_vote(
                    i,
                    Vote {
                        view: View::new(0),
                        phase: VotePhase::Prepare,
                        block_hash,
                        signature: vote_sig,
                        attestation: Some(att),
                        attestation_sig: Some(att_sig),
                    },
                )
                .expect("vote accepted");
        }

        let cert = leader.exec_certs.get(&7).expect("exec cert must form at quorum");
        assert_eq!(cert.state_root, root);
        assert_eq!(cert.height, height);
        // The cert must verify: aggregate sig + bitmap ≥ quorum.
        leader.verify_exec_cert(cert).expect("formed cert must verify");
    }

    #[test]
    fn forged_attestation_signature_is_dropped_not_fatal() {
        // An attestation signed by the wrong key must be ignored —
        // but the vote carrying it still counts for the QC (an
        // attestation is a best-effort signal, not a vote defect).
        let (mut engines, keys) = signed_committee();
        let leader = &mut engines[0];
        let block_hash = Hash([0xCD; 32]);

        // Attestation for (7, root) signed by validator 0's key but
        // claimed as validator 1's — fails verification.
        let root = Hash([0x77; 32]);
        let msg = leader.attestation_signing_message(Height::new(7), &root);
        let bad_sig = keys[0].sign(crypto::hash::Domain::ExecAttest, &msg);
        let vote_msg = leader.vote_signing_message(View::new(0), 0, &block_hash);
        let vote_sig = keys[1].sign(crypto::hash::Domain::Vote, &vote_msg);
        leader
            .collect_vote(
                1,
                Vote {
                    view: View::new(0),
                    phase: VotePhase::Prepare,
                    block_hash,
                    signature: vote_sig,
                    attestation: Some(StateAttestation { height: Height::new(7), root }),
                    attestation_sig: Some(bad_sig),
                },
            )
            .expect("vote itself must still be accepted");
        assert!(leader.exec_attest_pool.is_empty(), "forged attestation must be dropped");
        assert_eq!(leader.vote_count, 1, "the vote still counts toward the QC");
    }

    #[test]
    fn forged_exec_cert_is_rejected_on_root_mismatch() {
        // A proposal carrying a cert whose aggregate signature does
        // not verify AND whose root the voter never computed must be
        // refused — the leader can withhold a vote this way but never
        // redirect it. (A forged cert claiming the root we DID compute
        // is harmless: the vote outcome is unchanged, so the signature
        // is not even checked — the aggregate verify only runs on the
        // mismatch path.)
        let (mut engines, keys) = signed_committee();
        let engine = &mut engines[1];

        // Cert over a root the engine never produced (local attest is
        // Hash::ZERO at every unexecuted height), with an aggregate
        // built from a Vote-domain signature — fails verify_exec_cert.
        let root = Hash([0xab; 32]);
        let msg = engine.attestation_signing_message(Height::new(0), &root);
        let wrong_domain_sig = keys[0].sign(crypto::hash::Domain::Vote, &msg);
        let exec_cert = ExecCertificate {
            height: Height::new(0),
            state_root: root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[wrong_domain_sig]).expect("aggregate"),
        };

        let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
        let mut body = Vec::new();
        proposal.encode(&mut body);
        let mut header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: OxideBft::tx_root(&proposal.txs),
            body_commitment: types::shard::commitment(&body, 4, 3),
            high_qc: None,
            timeout_cert: None,
            proposer: proposer_hash(0),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: Some(exec_cert),
        };
        let sk = bls_key(1);
        let signing_hash = OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
        assert!(
            engine.vote(&header, &proposal).is_none(),
            "proposal with a forged exec cert must be rejected"
        );
    }

    #[test]
    fn propose_embeds_exec_cert_only_for_proven_heights() {
        // The embed rule: block h may carry a cert only for heights
        // <= h-2 — voters have only executed through h-2 at vote
        // time (2-chain lag), so a newer cert would freeze quorum.
        let (mut engines, _keys) = signed_committee();
        let leader = &mut engines[0];
        leader.submit_tx(TxBytes::new(vec![1]));

        // Seed a cert at height 3 and one at height 4 (not yet
        // provable when proposing height 5).
        for h in [3u64, 4] {
            leader.exec_certs.insert(
                h,
                ExecCertificate {
                    height: Height::new(h),
                    state_root: Hash([0x55; 32]),
                    epoch: Epoch::new(0),
                    signer_bitmap: vec![0xFF],
                    aggregate_signature: AggregateSignature::ZERO,
                },
            );
        }
        // Committed tip = 4 → next proposal is height 5; embeddable
        // certs are those <= 3.
        leader.last_committed = Some((Hash([0x01; 32]), Height::new(4)));
        let (header, _proposal) = leader.propose().expect("must propose");
        assert_eq!(header.height, Height::new(5));
        let cert = header.exec_cert.expect("cert(3) must be embedded");
        assert_eq!(cert.height, Height::new(3), "the *newest embeddable* cert wins");
    }

    #[test]
    fn exec_cert_flows_through_signed_pipeline() {
        // End-to-end: 4 signed engines drive rounds; attestations
        // ride every vote, certs form, and later proposals embed
        // them — with finality unaffected.
        let (mut engines, keys) = signed_committee();
        let mut saw_cert = false;
        for round in 0..8usize {
            let leader_idx = round % 4;
            // Keep the mempool non-empty: `propose()` returns None
            // when no work is outstanding (liveness gate), which
            // would stall the driver.
            engines[leader_idx]
                .submit_tx(TxBytes::new(vec![u8::try_from(round).unwrap_or(u8::MAX)]));
            let mut followers: Vec<&mut OxideBft> = Vec::new();
            // Split borrow: leader at leader_idx, followers elsewhere.
            let (before, rest) = engines.split_at_mut(leader_idx);
            let (leader, after) = rest.split_at_mut(1);
            followers.extend(before.iter_mut());
            followers.extend(after.iter_mut());
            let (header, proposal) = leader[0].propose().expect("propose");
            if header.exec_cert.is_some() {
                saw_cert = true;
            }
            let block_hash = OxideBft::block_hash(&header);
            let leader_vi = leader[0].validator_index;
            let msg = leader[0].vote_signing_message(header.view, 0, &block_hash);
            let sig = keys[usize::from(leader_vi)].sign(crypto::hash::Domain::Vote, &msg);
            let (attestation, attestation_sig) = leader[0].vote_attestation();
            leader[0]
                .collect_vote(
                    leader_vi,
                    Vote {
                        view: header.view,
                        phase: VotePhase::Prepare,
                        block_hash,
                        signature: sig,
                        attestation,
                        attestation_sig,
                    },
                )
                .expect("self vote");
            for f in &mut followers {
                if let Some(vote) = f.vote(&header, &proposal) {
                    leader[0].collect_vote(f.validator_index, vote).expect("vote");
                }
            }
            let qc = leader[0].try_form_qc().expect("qc");
            leader[0].deliver_qc(qc.clone()).expect("deliver");
            for f in &mut followers {
                f.deliver_qc(qc.clone()).expect("deliver");
                f.advance_view();
            }
            leader[0].advance_view();
        }
        assert!(saw_cert, "exec certs must flow through proposals once quorum attests");
    }

    /// Regression test for the embedded-justify hole: a proposal's
    /// `high_qc` used to be checked only for a *verifying* aggregate
    /// signature — never for quorum. A QC with one real signer's vote
    /// verifies as a valid aggregate yet certifies nothing: a
    /// Byzantine leader could embed a self-signed "QC" and have
    /// honest validators notarize a chain whose parent never reached
    /// consensus. The signer count must be enforced unconditionally.
    #[test]
    fn subquorum_embedded_qc_is_rejected() {
        let (mut engines, keys) = signed_committee();
        let engine = &mut engines[1];

        // Anchor the chain at (H, 0): the vote path accepts a
        // proposal whose `prev_block`/`height` continue the committed
        // tip when no highQC is known locally.
        let parent_hash = Hash([0x42; 32]);
        engine.last_committed = Some((parent_hash, Height::new(0)));

        // A structurally valid QC for the parent — but with only
        // validator 0's signature (1 < quorum 3). The aggregate is a
        // real BLS signature and verifies fine: the signature is not
        // the problem, the missing quorum is.
        let vote_msg = engine.vote_signing_message(View::new(0), 0, &parent_hash);
        let one_sig = keys[0].sign(crypto::hash::Domain::Vote, &vote_msg);
        let thin_qc = QuorumCertificate {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: parent_hash,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[one_sig]).expect("aggregate"),
        };
        // Sanity: the signature itself is sound — only the count fails.
        assert!(
            engine.verify_qc_signature(&thin_qc).is_err(),
            "sub-quorum QC must fail complete certificate validation"
        );

        let proposal = Proposal { height: Height::new(1), txs: vec![], attestation: None };
        let mut body = Vec::new();
        proposal.encode(&mut body);
        let mut header = BlockHeader {
            height: Height::new(1),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: parent_hash,
            tx_root: OxideBft::tx_root(&proposal.txs),
            body_commitment: types::shard::commitment(&body, 4, 3),
            high_qc: Some(thin_qc),
            timeout_cert: None,
            proposer: proposer_hash(0),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
        };
        let sk = bls_key(1);
        let signing_hash = OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));

        assert!(
            engine.vote(&header, &proposal).is_none(),
            "a proposal whose embedded QC lacks quorum must not be voted"
        );
    }

    // ---- View-change tests (multi-validator) ----
    //
    // docs/oxidebft-spec.md §4: a faulty leader is bypassed after one
    // timeout. Validators collect timeout signatures, form a TC, and
    // advance the view. The new leader takes over.

    #[test]
    fn faulty_leader_bypassed_via_timeout() {
        // 4 validators. The leader (index 0) for view 0 is faulty
        // (withholds proposals). The 3 followers time out, collect
        // timeout signatures, form a TC, and advance to view 1.
        // The leader for view 1 (index 1) is honest and proposes.
        let mut v0 = make_multi_engine(0);
        let mut v1 = make_multi_engine(1);
        let mut v2 = make_multi_engine(2);
        let mut v3 = make_multi_engine(3);

        // All followers time out for view 0.
        let _ = v1.on_timeout();
        let _ = v2.on_timeout();
        let _ = v3.on_timeout();

        // Each follower produces a timeout signature (placeholder
        // Signature::ZERO — stage 5 would sign the timeout message).
        // The signatures are gossiped: each validator collects
        // signatures from the others. v1 collects from itself, v2, v3.
        let _ = v1.pacemaker.on_timeout_signature(1, Signature::ZERO); // self
        let events1 = v1.pacemaker.on_timeout_signature(2, Signature::ZERO);
        let events1b = v1.pacemaker.on_timeout_signature(3, Signature::ZERO);

        // With 3 signatures (quorum = 3 for n=4, f=1), v1 should
        // form a TC and advance the view.
        let tc_formed = events1
            .iter()
            .chain(events1b.iter())
            .any(|e| matches!(e, PacemakerEvent::TimeoutCertificateFormed(_)));
        assert!(tc_formed, "v1 should form a TC at quorum");

        // Extract the TC from the events.
        let tc = events1
            .iter()
            .chain(events1b.iter())
            .find_map(|e| {
                if let PacemakerEvent::TimeoutCertificateFormed(tc) = e {
                    Some(tc.clone())
                } else {
                    None
                }
            })
            .expect("TC should be in the events");
        assert_eq!(tc.view, View::new(0), "TC is for view 0");

        // v1's pacemaker already advanced its view internally, but
        // the engine's `current_view` field is separate. Sync it
        // from the pacemaker. (In a real system, the engine would
        // process its own AdvanceView event; here we sync directly.)
        v1.current_view = v1.pacemaker.current_view();

        // All other validators receive the TC and advance the view.
        let _ = v2.on_timeout_certificate(&tc);
        let _ = v3.on_timeout_certificate(&tc);
        let _ = v0.on_timeout_certificate(&tc);

        // All validators should now be at view 1.
        assert_eq!(v1.current_view(), View::new(1), "v1 should be at view 1");
        assert_eq!(v2.current_view(), View::new(1), "v2 should be at view 1");
        assert_eq!(v3.current_view(), View::new(1), "v3 should be at view 1");
        assert_eq!(v0.current_view(), View::new(1), "v0 should be at view 1");

        // The leader for view 1 is validator 1 (round-robin).
        assert!(v1.is_leader(), "v1 should be leader for view 1");
    }

    // ---- Deterministic multi-node simulation ----
    //
    // A synchronous deterministic simulation of N validators running
    // oxideBFT. This is layer 4 of the testing pyramid (testing-
    // standards skill §4): deterministic simulation. The simulation
    // drives multiple engines in a fixed round-robin order, routes
    // messages deterministically, and asserts:
    // - Liveness: all submitted txs appear in finalized blocks.
    // - Finality: all validators agree on the same finalized blocks.
    // - Determinism: two runs with the same inputs produce identical
    //   finalized block sequences.

    /// A deterministic multi-node simulation. Creates N validators,
    /// drives `rounds` happy-path rounds with txs, and returns the
    /// finalized blocks from each validator.
    #[allow(clippy::too_many_lines)] // test helper: the .expect() calls for C1 verification added 4 lines
    fn run_simulation(n: usize, txs_per_round: usize, rounds: usize) -> Vec<Vec<FinalizedBlock>> {
        let pks: Vec<crypto::bls::PublicKey> = (1..=u8::try_from(n).unwrap()).map(pk).collect();
        let stakes = vec![1u64; n];
        let vs = ValidatorSet::new(pks, stakes).expect("validator set");

        let mut engines: Vec<OxideBft> = (0..n)
            .map(|i| {
                OxideBft::with_index(
                    Arc::new(MockApp::new()),
                    vs.clone(),
                    u16::try_from(i).unwrap(),
                )
                .without_signature_verification()
            })
            .collect();

        for round in 0..rounds {
            // The leader for this view is engines[0]'s leader.
            let leader_idx = usize::from(vs.leader(engines[0].current_view()));
            let tx = TxBytes::new(vec![
                u8::try_from(round).unwrap() + 1,
                u8::try_from(txs_per_round).unwrap(),
            ]);
            // Submit tx only to the leader's app. In a real system,
            // txs are gossiped, but each validator's mempool dedups
            // by tx hash. Here, each engine has its own MockApp, so
            // submitting to all would cause duplicate txs in blocks
            // (each leader would pull all pending txs from its
            // mempool). Submitting only to the leader matches the
            // real-world flow: the leader proposes, followers vote.
            engines[leader_idx].submit_tx(tx);

            // Leader proposes.
            let (header, proposal) = engines[leader_idx]
                .propose()
                .unwrap_or_else(|| panic!("leader {leader_idx} should propose in round {round}"));
            let block_hash = OxideBft::block_hash(&header);

            // Leader self-votes.
            let leader_vote = Vote {
                view: header.view,
                phase: VotePhase::Prepare,
                block_hash,
                signature: Signature::ZERO,
                attestation: None,
                attestation_sig: None,
            };
            engines[leader_idx]
                .collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote)
                .expect("conformance: no verification");

            // All followers vote (deterministic order: 0, 1, 2, ...).
            // Collect votes first to avoid double mutable borrow.
            let mut follower_votes = Vec::new();
            for (i, engine) in engines.iter_mut().enumerate() {
                if i == leader_idx {
                    continue;
                }
                if let Some(vote) = engine.vote(&header, &proposal) {
                    follower_votes.push((u16::try_from(i).unwrap(), vote));
                }
            }
            for (voter, vote) in follower_votes {
                engines[leader_idx]
                    .collect_vote(voter, vote)
                    .expect("conformance: no verification");
            }

            // Leader forms QC.
            let qc = engines[leader_idx]
                .try_form_qc()
                .unwrap_or_else(|| panic!("quorum should be reached in round {round}"));

            // All validators receive the QC (deterministic order).
            for engine in &mut engines {
                engine.deliver_qc(qc.clone()).expect("conformance: no verification");
            }

            // All validators advance the view (deterministic order).
            for engine in &mut engines {
                engine.advance_view();
            }

            // Sync next_height across all engines. In a real system,
            // the height is a chain property (all validators see the
            // same blocks via broadcast). Here, each engine has its
            // own next_height counter, so we sync them to the max
            // after each round.
            let max_height = engines.iter().map(|e| e.next_height.value()).max().unwrap_or(0);
            for engine in &mut engines {
                if engine.next_height.value() < max_height {
                    engine.next_height = Height::new(max_height);
                }
            }
        }

        // Drive one more empty round to flush the pipeline.
        let leader_idx = usize::from(vs.leader(engines[0].current_view()));
        let (header, proposal) =
            engines[leader_idx].propose().expect("leader should propose flush round");
        let block_hash = OxideBft::block_hash(&header);
        let leader_vote = Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        engines[leader_idx]
            .collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote)
            .expect("conformance: no verification");
        let mut follower_votes = Vec::new();
        for (i, engine) in engines.iter_mut().enumerate() {
            if i == leader_idx {
                continue;
            }
            if let Some(vote) = engine.vote(&header, &proposal) {
                follower_votes.push((u16::try_from(i).unwrap(), vote));
            }
        }
        for (voter, vote) in follower_votes {
            engines[leader_idx].collect_vote(voter, vote).expect("conformance: no verification");
        }
        let qc = engines[leader_idx].try_form_qc().expect("flush quorum");
        for engine in &mut engines {
            engine.deliver_qc(qc.clone()).expect("conformance: no verification");
        }
        for engine in &mut engines {
            engine.advance_view();
        }

        // Collect finalized blocks from each validator.
        engines
            .iter()
            .map(|e| {
                let h = e.finalized_height().map_or(0, primitives::Id::value);
                (0..=h).filter_map(|i| e.finalized_block(Height::new(i))).collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn sim_4_validators_liveness() {
        // 4 validators, 5 rounds with txs. All txs must be finalized.
        let results = run_simulation(4, 1, 5);
        // All validators should have the same number of finalized blocks.
        let n_blocks = results[0].len();
        assert!(n_blocks > 0, "should have finalized blocks");
        for (i, blocks) in results.iter().enumerate() {
            assert_eq!(
                blocks.len(),
                n_blocks,
                "validator {i} has {n_blocks} blocks expected, got {}",
                blocks.len()
            );
        }
        // All txs should be present.
        let total_txs: usize = results[0].iter().map(|b| b.txs.len()).sum();
        assert_eq!(total_txs, 5, "all 5 txs must be finalized");
    }

    #[test]
    fn sim_4_validators_finality_agreement() {
        // All validators must agree on the same finalized blocks.
        let results = run_simulation(4, 1, 5);
        let reference = &results[0];
        for (i, blocks) in results.iter().enumerate().skip(1) {
            assert_eq!(blocks.len(), reference.len(), "validator {i} disagrees on block count");
            for (j, (a, b)) in reference.iter().zip(blocks.iter()).enumerate() {
                assert_eq!(a.height, b.height, "validator {i} disagrees on height at block {j}");
                assert_eq!(a.txs, b.txs, "validator {i} disagrees on txs at block {j}");
            }
        }
    }

    #[test]
    fn sim_deterministic_across_runs() {
        // Two runs with identical inputs must produce identical outputs.
        let run1 = run_simulation(4, 1, 5);
        let run2 = run_simulation(4, 1, 5);
        assert_eq!(run1.len(), run2.len(), "different validator count across runs");
        for (i, (a, b)) in run1.iter().zip(run2.iter()).enumerate() {
            assert_eq!(a.len(), b.len(), "validator {i}: different block count");
            for (j, (ba, bb)) in a.iter().zip(b.iter()).enumerate() {
                assert_eq!(ba.height, bb.height, "validator {i} block {j}: height mismatch");
                assert_eq!(ba.txs, bb.txs, "validator {i} block {j}: txs mismatch");
            }
        }
    }

    #[test]
    fn sim_7_validators_liveness() {
        // 7 validators (f=2, quorum=5). 3 rounds with txs.
        let results = run_simulation(7, 1, 3);
        let n_blocks = results[0].len();
        assert!(n_blocks > 0, "should have finalized blocks");
        let total_txs: usize = results[0].iter().map(|b| b.txs.len()).sum();
        assert_eq!(total_txs, 3, "all 3 txs must be finalized");
    }

    // ---- Certificate validation hardening tests ----
    //
    // These tests prove the engine rejects byzantine attacks that
    // the prior validation missed: conflicting votes, insufficient
    // quorum, and stale QCs.

    #[test]
    fn collect_vote_rejects_conflicting_vote_for_different_block() {
        // 4 validators, conformance mode (no BLS). The leader collects
        // a vote for block A, then receives a vote for block B at the
        // same view. The conflicting vote must be rejected.
        let mut leader = make_multi_engine(0);

        // First vote: for block hash A.
        let vote_a = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash([0xAA; 32]),
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        leader.collect_vote(1, vote_a).expect("first vote accepted");

        // Second vote: for block hash B (different block, same view).
        let vote_b = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash([0xBB; 32]),
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        let err = leader.collect_vote(2, vote_b).expect_err("conflicting vote must be rejected");
        assert!(
            matches!(err, ConsensusError::ConflictingVote { voter, .. } if voter == 2),
            "expected ConflictingVote from voter 2, got {err:?}"
        );
    }

    #[test]
    fn collect_vote_rejects_conflicting_vote_for_different_view() {
        // 4 validators, conformance mode. The leader collects a vote
        // for view 0, then receives a vote for view 1 (different view).
        // C2 fix: future-view votes are silently dropped (not
        // ConflictingVote errors) to prevent buffer poisoning — a
        // single future-view vote must not become the "first vote"
        // and block all real current-view votes.
        let mut leader = make_multi_engine(0);

        let vote_v0 = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        leader.collect_vote(1, vote_v0).expect("first vote accepted");

        let vote_v1 = Vote {
            view: View::new(1),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        // C2: future-view vote is silently dropped, not an error.
        leader.collect_vote(2, vote_v1).expect("future-view vote silently dropped (C2)");
        // The vote buffer must not contain the future-view vote.
        assert!(leader.votes[2].is_none(), "future-view vote must not be stored");
    }

    /// Regression test (C2): a single future-view vote must not
    /// poison the vote buffer. Before the fix, the future-view vote
    /// became the "first vote" and all real current-view votes then
    /// failed the `ConflictingVote` check, stalling the view until
    /// timeout — a permanent liveness `DoS` with one message per view.
    #[test]
    fn collect_vote_future_view_does_not_block_current_view_votes() {
        let mut leader = make_multi_engine(0);

        // Byzantine voter sends a vote for view 1 (future).
        let future_vote = Vote {
            view: View::new(1),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        leader.collect_vote(1, future_vote).expect("future-view vote silently dropped");

        // Real votes for view 0 (current) must still be accepted.
        let real_vote = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        leader
            .collect_vote(2, real_vote)
            .expect("current-view vote accepted after future-view drop");
        assert!(leader.votes[2].is_some(), "current-view vote must be stored");
    }

    #[test]
    fn deliver_qc_rejects_insufficient_quorum() {
        // 4 validators (quorum = 3). A QC with only 2 signers has a
        // valid aggregate signature (in conformance mode) but does
        // not meet quorum — it must be rejected.
        let mut engine = make_multi_engine(0);

        // QC with 2 signers (below quorum of 3).
        let insufficient_qc = QuorumCertificate {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0011], // 2 signers
            aggregate_signature: AggregateSignature::ZERO,
        };

        let err = engine
            .deliver_qc(insufficient_qc)
            .expect_err("QC with insufficient quorum must be rejected");
        assert!(
            matches!(err, ConsensusError::InsufficientQuorum { voting_power, required } if voting_power == 2 && required == 3),
            "expected InsufficientQuorum (2 < 3), got {err:?}"
        );
    }

    /// Stake-weighted quorum (spec §3): a committee with stakes
    /// [100, 1, 1, 1] has `quorum_stake = 69` of `T = 103`. The three
    /// low-stake validators outnumber the honest quorum by *count*
    /// (3 ≥ 3) but hold only 3 stake — a count-based check would
    /// accept a certificate that commits nothing. The dominant
    /// validator alone carries enough power to form a QC.
    #[test]
    fn deliver_qc_enforces_stake_weighted_quorum() {
        let weighted_set = ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![100, 1, 1, 1])
            .expect("4 validators, 100:1:1:1 stake");
        let app = Arc::new(MockApp::new());
        let mut engine =
            OxideBft::with_index(app, weighted_set, 0).without_signature_verification();
        assert_eq!(engine.validator_set().quorum_stake(), 69);

        // QC signed by the three 1-stake validators: count says 3/4
        // signers (≥ count-quorum 3), power says 3/103 (< 69). This
        // certificate must be rejected — the exact failure mode the
        // count-based quorum admitted.
        let small_signers_qc = QuorumCertificate {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1110],
            aggregate_signature: AggregateSignature::ZERO,
        };
        let err = engine
            .deliver_qc(small_signers_qc)
            .expect_err("low-stake signers must not form a quorum");
        assert!(
            matches!(err, ConsensusError::InsufficientQuorum { voting_power, required } if voting_power == 3 && required == 69),
            "expected InsufficientQuorum (3 < 69), got {err:?}"
        );

        // The 100-stake validator alone exceeds the power quorum —
        // fewer signers, more weight.
        let dominant_qc = QuorumCertificate {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.deliver_qc(dominant_qc).expect("dominant-stake signer alone must form a quorum");
    }

    #[test]
    fn deliver_qc_rejects_stale_qc() {
        // 4 validators, conformance mode. The engine receives a QC
        // for view 1, then receives a QC for view 0 (stale). The
        // stale QC must be rejected.
        let mut engine = make_multi_engine(0);

        // First QC: view 1 (accepted, sets high_qc).
        let qc_v1 = QuorumCertificate {
            view: View::new(1),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x11; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111], // 4 signers (≥ quorum)
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.deliver_qc(qc_v1).expect("first QC accepted");

        // Second QC: view 0 (stale — below high_qc's view 1).
        let stale_qc = QuorumCertificate {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x00; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        let err = engine.deliver_qc(stale_qc).expect_err("stale QC must be rejected");
        assert!(
            matches!(err, ConsensusError::StaleQc { qc_view, high_qc_view } if qc_view == View::new(0) && high_qc_view == View::new(1)),
            "expected StaleQc (view 0 ≤ high_qc view 1), got {err:?}"
        );
    }

    #[test]
    fn deliver_qc_rejects_qc_with_same_view_as_high_qc() {
        // A QC with the same view as the current high_qc is also
        // stale (not strictly greater). This prevents replaying the
        // same QC.
        let mut engine = make_multi_engine(0);

        let qc = QuorumCertificate {
            view: View::new(1),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x11; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.deliver_qc(qc.clone()).expect("first QC accepted");

        // Same view, different block — stale.
        let same_view_qc = QuorumCertificate {
            view: View::new(1),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x22; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        let err = engine.deliver_qc(same_view_qc).expect_err("same-view QC must be rejected");
        assert!(matches!(err, ConsensusError::StaleQc { .. }), "expected StaleQc, got {err:?}");
    }

    #[test]
    fn on_timeout_certificate_rejects_insufficient_quorum() {
        // 4 validators (quorum = 3). A TC with only 2 signers must
        // be rejected even if the aggregate signature verifies (in
        // conformance mode it always does).
        let mut engine = make_multi_engine(0);

        let insufficient_tc = TimeoutCertificate {
            view: View::new(0),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0011], // 2 signers
            aggregate_signature: AggregateSignature::ZERO,
        };

        let err = engine
            .on_timeout_certificate(&insufficient_tc)
            .expect_err("TC with insufficient quorum must be rejected");
        assert!(
            matches!(err, ConsensusError::InsufficientQuorum { voting_power, required } if voting_power == 2 && required == 3),
            "expected InsufficientQuorum (2 < 3), got {err:?}"
        );
    }

    /// Regression test: a validator that restarts at view 0 must
    /// catch up when it receives a higher-view QC from peers. Before
    /// the fix, `deliver_qc` only updated `high_qc` without advancing
    /// `current_view`, so a restarted validator stayed stuck at view 0
    /// forever and could never participate in consensus again.
    #[test]
    fn deliver_qc_advances_lagging_validator_view() {
        // Run 5 rounds to advance the view.
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        for i in 0..5u8 {
            drive_round(&mut leader, &mut [&mut f1, &mut f2, &mut f3], Some(TxBytes::new(vec![i])));
        }
        // All validators should have advanced beyond view 0.
        let peer_view = leader.current_view().value();
        assert!(peer_view > 0, "peers should have advanced beyond view 0");

        // Simulate a restart: create a fresh engine for validator 3
        // at view 0 (as if the process restarted from scratch).
        let mut restarted = make_multi_engine(3);
        assert_eq!(restarted.current_view().value(), 0);

        // The restarted validator receives a QC from a peer for the
        // peers' current high QC view.
        let qc = leader.high_qc().expect("high_qc should be set").clone();
        let qc_view = qc.view.value();
        assert!(qc_view > 0, "QC should be for a view > 0");

        // Deliver the QC to the restarted validator. Before the fix,
        // this would update `high_qc` but NOT advance `current_view`,
        // leaving the validator stuck at view 0.
        restarted.deliver_qc(qc).expect("QC must verify");

        // After the fix, the restarted validator's view should advance
        // to qc.view + 1, allowing it to participate in consensus.
        assert_eq!(
            restarted.current_view().value(),
            qc_view + 1,
            "restarted validator must catch up to qc.view + 1"
        );
    }

    /// Regression test: a validator that restarts at view 0 must
    /// catch up when it receives a higher-view TC from peers. Before
    /// the fix, the pacemaker rejected any TC whose view differed
    /// from the current view, so a restarted validator could never
    /// advance its view via TCs.
    #[test]
    fn on_timeout_certificate_advances_lagging_validator() {
        // Run 5 rounds to advance the view.
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        for i in 0..5u8 {
            drive_round(&mut leader, &mut [&mut f1, &mut f2, &mut f3], Some(TxBytes::new(vec![i])));
        }
        let peer_view = leader.current_view().value();
        assert!(peer_view > 0, "peers should have advanced beyond view 0");

        // Simulate a restart: create a fresh engine for validator 3
        // at view 0.
        let mut restarted = make_multi_engine(3);
        assert_eq!(restarted.current_view().value(), 0);

        // Construct a TC for the peers' current view with quorum.
        let tc = TimeoutCertificate {
            view: View::new(peer_view),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0111], // 3 signers (quorum)
            aggregate_signature: AggregateSignature::ZERO,
        };

        // Deliver the TC to the restarted validator. Before the fix,
        // the pacemaker would reject this TC because tc.view != current_view.
        restarted.on_timeout_certificate(&tc).expect("TC must be accepted");

        // After the fix, the restarted validator's view should advance
        // to tc.view + 1.
        assert_eq!(
            restarted.current_view().value(),
            peer_view + 1,
            "restarted validator must catch up to tc.view + 1"
        );
    }

    // ---- Bounded view catch-up (DiemBFT v4 timeout evidence) ----
    //
    // A remote timeout signature may not pull a node to an arbitrary
    // view: the claimed view is honored only when certificate
    // evidence (QC or TC for the preceding view) moves us there.
    // `deliver_timeout_evidence` feeds attached certificates through
    // the verified ingestion paths; the wire handler then collects
    // the signature only when `sig_view == current_view`.

    /// A TC for the preceding view carried as timeout evidence
    /// advances a lagging validator — the certificate, not the
    /// signature, does the moving.
    #[test]
    fn timeout_evidence_tc_advances_view() {
        let mut engine = make_multi_engine(0);
        assert_eq!(engine.current_view().value(), 0);
        let tc = TimeoutCertificate {
            view: View::new(4),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.deliver_timeout_evidence(None, Some(tc));
        assert_eq!(
            engine.current_view().value(),
            5,
            "TC(4) evidence moves the validator to view 5"
        );
        // And the TC is recorded as the view's successor evidence.
        assert_eq!(
            engine.last_tc.as_ref().map(|t| t.view.value()),
            Some(4),
            "the carried TC becomes last_tc — the next proposal embeds it"
        );
    }

    /// A QC carried as timeout evidence both advances the view AND
    /// updates `high_qc` — the timeout message doubles as high-QC
    /// propagation, as in `DiemBFT`.
    #[test]
    fn timeout_evidence_qc_advances_view_and_high_qc() {
        let mut engine = make_multi_engine(0);
        let qc = QuorumCertificate {
            view: View::new(7),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x77; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.deliver_timeout_evidence(Some(qc), None);
        assert_eq!(engine.current_view().value(), 8, "QC(7) evidence moves to view 8");
        assert_eq!(
            engine.high_qc().map(|q| q.view.value()),
            Some(7),
            "the carried QC updates high_qc"
        );
    }

    /// Evidence that cannot verify must move nothing — a forged QC
    /// (zero aggregate) is rejected by `deliver_qc`, so the claimed
    /// jump collapses to nothing.
    #[test]
    fn timeout_evidence_forged_qc_moves_nothing() {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
        let mut engine =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

        let forged_qc = QuorumCertificate {
            view: View::new(49),
            phase: VotePhase::Prepare,
            block_hash: Hash([0xAA; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111],
            aggregate_signature: AggregateSignature::ZERO, // forged
        };
        engine.deliver_timeout_evidence(Some(forged_qc), None);
        assert_eq!(
            engine.current_view().value(),
            0,
            "a forged QC justifies nothing — the view stays put"
        );
    }

    /// A validly-signed TC from a different epoch is ignored — the
    /// explicit epoch check keeps foreign-epoch evidence out even
    /// when the validator sets happen to share keys.
    #[test]
    fn timeout_evidence_ignores_foreign_epoch() {
        let mut engine = make_multi_engine(0);
        let foreign_tc = TimeoutCertificate {
            view: View::new(4),
            epoch: Epoch::new(9), // not our epoch
            signer_bitmap: vec![0b0000_0111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.deliver_timeout_evidence(None, Some(foreign_tc));
        assert_eq!(engine.current_view().value(), 0, "foreign-epoch evidence must be ignored");
    }

    /// The sender side: `timeout_evidence` reports the certificate
    /// that justifies our current view. Entered via QC → the high QC
    /// alone justifies (no TC attached). Entered via TC → the last
    /// TC rides alongside the (older) high QC.
    #[test]
    fn timeout_evidence_reports_justifying_certificates() {
        let mut engine = make_multi_engine(0);
        // Enter view 6 via QC(5).
        let qc = QuorumCertificate {
            view: View::new(5),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x55; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.deliver_qc(qc).expect("QC accepted");
        assert_eq!(engine.current_view().value(), 6);
        let (qc_ev, tc_ev) = engine.timeout_evidence();
        assert_eq!(qc_ev.map(|q| q.view.value()), Some(5));
        assert!(tc_ev.is_none(), "QC(view−1) alone justifies the view");

        // Then enter view 10 via TC(9) — high_qc stays at 5, so the
        // TC is the justifying evidence.
        let tc = TimeoutCertificate {
            view: View::new(9),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.on_timeout_certificate(&tc).expect("TC accepted");
        assert_eq!(engine.current_view().value(), 10);
        let (qc_ev, tc_ev) = engine.timeout_evidence();
        assert_eq!(
            qc_ev.map(|q| q.view.value()),
            Some(5),
            "high_qc still propagates (it feeds the receiver's own high_qc)"
        );
        assert_eq!(
            tc_ev.map(|t| t.view.value()),
            Some(9),
            "TC(view−1) is the justifying evidence here"
        );
    }

    /// Regression test: a TC for a past view must NOT regress the
    /// engine's view. This ensures the catch-up logic doesn't
    /// allow view regression (safety violation).
    #[test]
    fn on_timeout_certificate_rejects_past_view() {
        let mut engine = make_multi_engine(0);
        // Advance to view 5.
        for _ in 0..5 {
            engine.advance_view();
        }
        assert_eq!(engine.current_view().value(), 5);

        // TC for view 3 (past view) — must be rejected.
        let past_tc = TimeoutCertificate {
            view: View::new(3),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0111],
            aggregate_signature: AggregateSignature::ZERO,
        };
        // The engine accepts the TC (quorum + signature pass) but
        // the pacemaker ignores it (past view) — the view must not
        // change.
        engine.on_timeout_certificate(&past_tc).expect("TC with valid quorum should not error");

        // View must not regress.
        assert_eq!(engine.current_view().value(), 5);
    }

    /// Regression test: `sync_to_view` must advance a lagging
    /// validator forward to a higher view. This is the catch-up path
    /// used when a validator receives a timeout signature for a
    /// higher view (e.g., after a restart or partition). Without
    /// this, validators at adjacent views can never converge
    /// because they reject each other's timeout signatures.
    #[test]
    fn sync_to_view_advances_lagging_validator() {
        let mut engine = make_multi_engine(0);
        assert_eq!(engine.current_view().value(), 0);

        // Sync forward to view 10.
        let advanced = engine.sync_to_view(View::new(10));
        assert!(advanced, "sync_to_view should return true for a higher view");
        assert_eq!(engine.current_view().value(), 10, "view should be 10");
    }

    /// Regression test: `sync_to_view` must NOT regress the view.
    /// A lower or equal view is a no-op (returns false).
    #[test]
    fn sync_to_view_rejects_lower_or_equal_view() {
        let mut engine = make_multi_engine(0);
        // Advance to view 5.
        for _ in 0..5 {
            engine.advance_view();
        }
        assert_eq!(engine.current_view().value(), 5);

        // Lower view — no-op.
        let advanced = engine.sync_to_view(View::new(3));
        assert!(!advanced, "sync_to_view should return false for a lower view");
        assert_eq!(engine.current_view().value(), 5, "view must not regress");

        // Equal view — no-op.
        let advanced = engine.sync_to_view(View::new(5));
        assert!(!advanced, "sync_to_view should return false for an equal view");
        assert_eq!(engine.current_view().value(), 5, "view must not change");
    }

    /// Regression test: `sync_to_view` must clear stale vote state
    /// so that late-arriving votes from the old view don't pollute
    /// the new view's quorum accounting.
    #[test]
    fn sync_to_view_clears_stale_votes() {
        let mut engine = make_multi_engine(0);

        // Manually collect a vote to populate vote state.
        let vote = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        engine.collect_vote(1, vote).expect("conformance: no verification");
        assert!(engine.vote_count > 0, "engine should have collected a vote");

        // Sync forward to a higher view.
        let advanced = engine.sync_to_view(View::new(100));
        assert!(advanced, "sync should advance");

        // Vote state must be cleared.
        assert_eq!(engine.vote_count, 0, "vote_count must be cleared after sync");
        assert!(engine.votes.iter().all(Option::is_none), "votes must be cleared after sync");
    }

    /// Regression test: a follower that votes on proposals must
    /// advance its `next_height` via `observe_block_height` (called
    /// from `vote`). Without this, a follower that becomes the leader
    /// after a view change would propose at a stale height,
    /// re-executing an already-finalized height with different
    /// transactions and corrupting chain state.
    #[test]
    fn vote_syncs_next_height_from_proposal() {
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];

        // Drive 3 rounds. The leader proposes at heights 0, 1, 2.
        for i in 0..3u8 {
            drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![i])));
        }

        // Followers should have advanced their next_height past 0
        // because they voted on proposals at heights 0, 1, 2.
        // After 3 rounds, next_height should be at least 3 (the
        // leader proposed at heights 0, 1, 2, so next_height = 3).
        for (name, follower) in [("f1", &f1), ("f2", &f2), ("f3", &f3)] {
            assert!(
                follower.next_height.value() >= 3,
                "{name}: next_height should be >= 3 after 3 rounds, got {}",
                follower.next_height.value()
            );
        }
    }

    /// Regression test: `observe_block_height` must be idempotent
    /// and only advance forward. A stale height must not regress
    /// `next_height`.
    #[test]
    fn observe_block_height_only_advances_forward() {
        let mut engine = make_multi_engine(0);
        assert_eq!(engine.next_height.value(), 0);

        // Observe height 5 — should advance to 6.
        engine.observe_block_height(Height::new(5));
        assert_eq!(engine.next_height.value(), 6);

        // Observe height 3 (stale) — should be a no-op.
        engine.observe_block_height(Height::new(3));
        assert_eq!(engine.next_height.value(), 6);

        // Observe height 6 (equal) — should advance to 7.
        engine.observe_block_height(Height::new(6));
        assert_eq!(engine.next_height.value(), 7);
    }

    /// Regression test (C1): `observe_block_height` with
    /// `height = u64::MAX` must saturate `next_height` at `MAX`
    /// rather than wrapping to 0. Before the fix, the unchecked
    /// `value() + 1` wrapped `next_height` to 0, which would make
    /// the validator re-propose height 0 — conflicting with the
    /// finalized genesis block and corrupting chain state.
    #[test]
    fn observe_block_height_saturates_at_max_not_wraps_to_zero() {
        let mut engine = make_multi_engine(0);
        assert_eq!(engine.next_height.value(), 0);

        // A byzantine proposal with height = u64::MAX.
        engine.observe_block_height(Height::MAX);
        assert_eq!(
            engine.next_height.value(),
            u64::MAX,
            "next_height must saturate at u64::MAX, not wrap to 0"
        );
    }

    /// Regression test (C1): `Id::checked_next` and `saturating_next`
    /// must not wrap at `u64::MAX`. This guards the primitive that all
    /// consensus `+1` paths now use.
    #[test]
    fn id_checked_and_saturating_next_do_not_wrap() {
        assert!(Height::MAX.checked_next().is_none());
        assert_eq!(Height::MAX.saturating_next(), Height::MAX);
        assert_eq!(Height::new(5).checked_next(), Some(Height::new(6)));
        assert_eq!(Height::new(5).saturating_next(), Height::new(6));
    }

    /// Regression test: a follower that becomes the leader after a
    /// view change must propose at the correct height (not height 0).
    /// Before the fix, followers never advanced `next_height` from
    /// received proposals, so a new leader proposed at height 0,
    /// conflicting with the already-finalized block at height 0.
    #[test]
    fn new_leader_proposes_at_correct_height_after_view_change() {
        let mut leader = make_multi_engine(0);
        let mut f1 = make_multi_engine(1);
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let mut followers = [&mut f1, &mut f2, &mut f3];

        // Drive 3 rounds with leader 0 (heights 0, 1, 2).
        for i in 0..3u8 {
            drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![i])));
        }

        // All validators should have finalized blocks up to height 1
        // (2-chain: 3 rounds → 2 committed blocks).
        let finalized_h = leader.finalized_height().map_or(0, primitives::Id::value);
        assert!(finalized_h >= 1, "should have finalized at least height 1");

        // Now simulate a view change: advance views so that f1
        // becomes the leader. With 4 validators and round-robin,
        // view 4 % 4 = 0 (leader 0), view 5 % 4 = 1 (leader 1).
        // Advance to view 5 so f1 is the leader.
        for engine in [&mut leader, &mut f1, &mut f2, &mut f3] {
            while engine.current_view().value() < 5 {
                engine.advance_view();
            }
        }
        assert!(f1.is_leader(), "f1 should be leader for view 5");

        // f1 should propose at a height > finalized_h, not height 0.
        f1.submit_tx(TxBytes::new(vec![42]));
        let (header, _proposal) = f1.propose().expect("f1 should propose as new leader");
        assert!(
            header.height.value() > finalized_h,
            "new leader must propose at height > {finalized_h} (finalized), got {}",
            header.height.value()
        );
    }

    /// Regression test: `on_timeout_certificate` must clear votes
    /// and timeout signatures when the view advances. Before the
    /// fix, `on_timeout_certificate` advanced the view but left
    /// stale votes in the buffer, causing `ConflictingVote` errors
    /// when the new view's real votes arrived.
    #[test]
    fn on_timeout_certificate_clears_per_view_state() {
        let mut engine = make_multi_engine(0);

        // Populate vote and timeout signature state for view 0.
        let vote = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        engine.collect_vote(1, vote).expect("conformance: no verification");
        engine.timeout_signatures[2] = Some(Signature::ZERO);
        assert!(engine.vote_count > 0, "should have collected a vote");
        assert!(
            engine.timeout_signatures.iter().any(Option::is_some),
            "should have a timeout signature"
        );

        // Process a TC for view 0 with quorum (advances to view 1).
        let tc = TimeoutCertificate {
            view: View::new(0),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0111], // 3 signers (quorum)
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.on_timeout_certificate(&tc).expect("TC must be accepted");

        // After the view advance, all per-view state must be cleared.
        assert_eq!(engine.vote_count, 0, "vote_count must be cleared after TC");
        assert!(engine.votes.iter().all(Option::is_none), "votes must be cleared after TC");
        assert!(
            engine.timeout_signatures.iter().all(Option::is_none),
            "timeout_signatures must be cleared after TC"
        );
    }

    /// Regression test: `sync_to_view` must clear timeout
    /// signatures, not just votes. Before the fix, stale timeout
    /// signatures from the old view leaked into the new view's TC
    /// aggregation, producing an aggregate that failed verification.
    #[test]
    fn sync_to_view_clears_timeout_signatures() {
        let mut engine = make_multi_engine(0);

        // Populate timeout signature state for view 0.
        engine.timeout_signatures[1] = Some(Signature::ZERO);
        engine.timeout_signatures[2] = Some(Signature::ZERO);
        assert!(
            engine.timeout_signatures.iter().any(Option::is_some),
            "should have timeout signatures"
        );

        // Sync forward to view 10.
        let advanced = engine.sync_to_view(View::new(10));
        assert!(advanced, "sync should advance");

        // Timeout signatures must be cleared.
        assert!(
            engine.timeout_signatures.iter().all(Option::is_none),
            "timeout_signatures must be cleared after sync_to_view"
        );
    }

    /// Regression test: `deliver_qc` catch-up (when the QC's view
    /// is higher than the local view) must clear timeout signatures,
    /// not just votes. Before the fix, stale timeout signatures
    /// from the old view leaked into the new view's TC aggregation.
    #[test]
    fn deliver_qc_catchup_clears_timeout_signatures() {
        let mut engine = make_multi_engine(0);

        // Populate timeout signature state for view 0.
        engine.timeout_signatures[1] = Some(Signature::ZERO);
        assert!(
            engine.timeout_signatures.iter().any(Option::is_some),
            "should have a timeout signature"
        );

        // Deliver a QC for a higher view (triggers catch-up).
        let qc = QuorumCertificate {
            view: View::new(5),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x11; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_1111], // 4 signers (quorum)
            aggregate_signature: AggregateSignature::ZERO,
        };
        engine.deliver_qc(qc).expect("QC must be accepted");

        // After the catch-up, timeout signatures must be cleared.
        assert!(
            engine.timeout_signatures.iter().all(Option::is_none),
            "timeout_signatures must be cleared after deliver_qc catch-up"
        );
    }

    /// Regression test: `advance_view` must clear timeout
    /// signatures, not just votes.
    #[test]
    fn advance_view_clears_timeout_signatures() {
        let mut engine = make_multi_engine(0);

        // Populate timeout signature state.
        engine.timeout_signatures[1] = Some(Signature::ZERO);
        assert!(
            engine.timeout_signatures.iter().any(Option::is_some),
            "should have a timeout signature"
        );

        engine.advance_view();

        assert!(
            engine.timeout_signatures.iter().all(Option::is_none),
            "timeout_signatures must be cleared after advance_view"
        );
    }

    /// C9 test: a restarted engine recovers `last_voted_view` and
    /// `voted_at_height` from the WAL, preventing double-voting
    /// and conflicting votes after a crash.
    #[test]
    fn c9_wal_restart_recovery() {
        use crate::wal::Wal;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let wal_path = dir.path().join("consensus.wal");

        // Phase 1: create an engine with a WAL, vote on a proposal,
        // and verify the WAL was written.
        {
            let app = Arc::new(MockApp::new());
            let wal = Wal::open(&wal_path).expect("open WAL");
            let mut engine = OxideBft::new(app, single_validator_set())
                .without_signature_verification()
                .with_wal(wal);

            // Manually set safety-critical state to simulate a vote.
            engine.last_voted_view = Some(View::new(5));
            engine.voted_at_height.insert(3, Hash([0xAA; 32]));
            engine.current_view = View::new(6);
            engine.next_height = Height::new(4);
            engine.last_committed = Some((Hash([0xBB; 32]), Height::new(2)));
            engine.append_wal().expect("tempdir WAL append must succeed");
        }

        // Phase 2: simulate a restart — create a new engine with
        // the same WAL and recover.
        {
            let app = Arc::new(MockApp::new());
            let wal = Wal::open(&wal_path).expect("open WAL");
            let mut engine = OxideBft::new(app, single_validator_set())
                .without_signature_verification()
                .with_wal(wal);

            engine.recover_from_wal().expect("recover from WAL");

            // The recovered state must prevent double-voting.
            assert_eq!(engine.last_voted_view, Some(View::new(5)));
            // The recovered state must prevent conflicting votes.
            assert_eq!(
                engine.voted_at_height.get(&3),
                Some(&Hash([0xAA; 32])),
                "voted_at_height must be recovered from WAL"
            );
            // The recovered state must have the correct view and height.
            assert_eq!(engine.current_view, View::new(6));
            assert_eq!(engine.next_height, Height::new(4));
            // The committed anchor must survive restart — it gates
            // the no-highQC vote arm after epoch rotation.
            assert_eq!(
                engine.last_committed,
                Some((Hash([0xBB; 32]), Height::new(2))),
                "last_committed must be recovered from WAL"
            );
        }
    }

    /// C9 test: an engine without a WAL does not crash when
    /// `append_wal` or `recover_from_wal` is called.
    #[test]
    fn c9_no_wal_no_crash() {
        let mut engine = make_engine();

        // append_wal with no WAL should be a no-op.
        engine.append_wal().expect("no-WAL append is a no-op Ok");

        // recover_from_wal with no WAL should return Ok(()).
        engine.recover_from_wal().expect("recover with no WAL should be Ok");
    }

    // ---- C10: durable signing fails closed ----

    /// C10 test: a WAL append failure must withhold the vote — a
    /// signature emitted while its anti-equivocation state is not
    /// durable can equivocate after a restart. `Wal::poison` makes
    /// every append fail without touching the file — the same
    /// outcome an ENOSPC write produces.
    #[test]
    fn c10_wal_failure_disables_vote_signing() {
        use crate::wal::Wal;
        use tempfile::tempdir;

        // Follower engine (index 1) with a WAL that fails on append.
        let dir = tempdir().expect("tempdir");
        let mut wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
        wal.poison();
        let mut follower = make_multi_engine(1).with_wal(wal);

        // A valid proposal from leader 0 at view 0.
        let mut leader = make_multi_engine(0);
        leader.submit_tx(TxBytes::new(vec![1]));
        let (header, proposal) = leader.propose().expect("leader proposes");

        // The vote must be withheld: the vote-lock update cannot be
        // made durable, so no signature may leave.
        assert!(
            follower.vote(&header, &proposal).is_none(),
            "vote must be withheld when the WAL append fails"
        );
        assert!(follower.wal_failed, "WAL failure must latch");
        assert!(!follower.signing_healthy(), "signing_healthy must report the latched failure");
    }

    /// C10 test: the WAL-failure latch is sticky — a validator with
    /// a failed WAL must go silent for every signature kind until
    /// the operator restarts it on healthy storage.
    #[test]
    fn c10_wal_failure_latches_all_signing() {
        use crate::wal::Wal;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let mut wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
        wal.poison();
        let mut follower = make_multi_engine(1).with_wal(wal);
        let mut leader = make_multi_engine(0);
        leader.submit_tx(TxBytes::new(vec![1]));
        let (header, proposal) = leader.propose().expect("leader proposes");

        // First vote attempt fails and latches.
        assert!(follower.vote(&header, &proposal).is_none());
        assert!(follower.wal_failed);

        // Timeout signatures must also be refused.
        assert!(
            follower.on_timeout().is_none(),
            "timeout signature must be withheld while the WAL is failed"
        );
        // A second vote attempt must still refuse even though the
        // locks are already updated in memory.
        assert!(follower.vote(&header, &proposal).is_none());
    }

    /// C10 test: an attestation signature is still a signature — a
    /// WAL-failed validator must not emit one either.
    #[test]
    fn c10_wal_failure_disables_attestation() {
        use crate::wal::Wal;
        use tempfile::tempdir;

        // Two committed rounds so `attest_latest` reports a nonzero
        // executed root (the height-0 mock root is `Hash::ZERO`).
        let dir = tempdir().expect("tempdir");
        let wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
        let mut engine = OxideBft::new(Arc::new(MockApp::new()), single_validator_set())
            .without_signature_verification()
            .with_wal(wal);
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        engine.submit_tx(TxBytes::new(vec![2]));
        engine.run_until_idle();
        assert!(
            engine.vote_attestation().0.is_some(),
            "committed blocks give a non-empty attestation"
        );

        // Poison the WAL: the next step's vote append fails and
        // latches — the self-vote must be withheld, nothing new
        // can finalize, and attestations go silent too.
        engine.wal.as_mut().expect("wal attached").poison();
        engine.submit_tx(TxBytes::new(vec![3]));
        engine.run_until_idle();
        assert!(engine.wal_failed, "failed append must latch wal_failed");

        assert_eq!(
            engine.vote_attestation(),
            (None, None),
            "attestation signatures must be withheld while the WAL is failed"
        );
    }

    /// C10 test: `step()` (single-validator mode) must refuse to
    /// cast its self-vote when the WAL append fails — previously it
    /// signed first, updated the locks after, and never appended at
    /// all, so a crash left restart state unaware the vote was cast.
    #[test]
    fn c10_step_refuses_when_wal_fails() {
        use crate::wal::Wal;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let mut wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
        wal.poison();
        let mut engine = OxideBft::new(Arc::new(MockApp::new()), single_validator_set())
            .without_signature_verification()
            .with_wal(wal);
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();

        assert!(engine.wal_failed, "failed append must latch wal_failed");
        assert!(
            engine.finalized_height().is_none(),
            "a WAL-failed engine must not vote, so nothing can finalize"
        );
    }

    /// C10 test: `step()`'s self-vote is durable — a restart
    /// recovering the WAL must see exactly the lock state the
    /// engine holds (committed-height pruning included).
    #[test]
    fn c10_step_persists_locks_before_signing() {
        use crate::wal::Wal;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let wal_path = dir.path().join("consensus.wal");
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(Arc::new(MockApp::new()), single_validator_set())
            .without_signature_verification()
            .with_wal(wal);
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        assert!(engine.last_voted_view.is_some(), "run_until_idle must have voted at least once");

        // The WAL's latest entry must cover the engine's live
        // safety state — every lock the engine relies on is durable.
        // (The WAL may hold MORE locks than the live map: commit
        // appends run before `voted_at_height` pruning, so the
        // durable set is the safe, strictly-conservative superset.)
        let entry = Wal::open(&wal_path)
            .expect("reopen WAL")
            .recover()
            .expect("recover")
            .expect("WAL must contain at least one entry");
        assert_eq!(entry.last_voted_view, engine.last_voted_view);
        assert!(
            engine.voted_at_height.iter().all(|(h, b)| entry.voted_at_height.get(h) == Some(b)),
            "every live vote lock must be durable in the WAL"
        );
    }

    /// C10 test: the leader's self-vote must go through `vote()` —
    /// the single signing authority — which updates the vote locks
    /// and appends the WAL before the signature exists. Harnesses
    /// that hand-built a `Vote` and called `collect_vote` skipped
    /// both.
    #[test]
    fn c10_leader_self_vote_via_vote_is_durable() {
        use crate::wal::Wal;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let wal_path = dir.path().join("consensus.wal");
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut leader = make_multi_engine(0).with_wal(wal);
        leader.submit_tx(TxBytes::new(vec![1]));
        let (header, proposal) = leader.propose().expect("leader proposes");
        let block_hash = OxideBft::block_hash(&header);

        // The engine's own proposal passes every eligibility rule —
        // vote() is the canonical path for leader and follower alike.
        let vote = leader.vote(&header, &proposal);
        assert!(vote.is_some(), "leader self-vote through vote() must succeed");

        // The lock must be recorded in memory AND durable in the WAL.
        assert_eq!(
            leader.voted_at_height.get(&header.height.value()),
            Some(&block_hash),
            "leader vote must take the per-height lock"
        );
        let entry = Wal::open(&wal_path)
            .expect("reopen WAL")
            .recover()
            .expect("recover")
            .expect("WAL entry must exist");
        assert_eq!(
            entry.voted_at_height.get(&header.height.value()),
            Some(&block_hash),
            "leader vote lock must be durable before the vote ships"
        );
    }

    /// C10 test: a healthy WAL keeps signing enabled — the
    /// fail-closed gate must not break the normal path.
    #[test]
    fn c10_healthy_wal_signs() {
        use crate::wal::Wal;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
        let mut follower = make_multi_engine(1).with_wal(wal);
        let mut leader = make_multi_engine(0);
        leader.submit_tx(TxBytes::new(vec![1]));
        let (header, proposal) = leader.propose().expect("leader proposes");

        assert!(follower.vote(&header, &proposal).is_some());
        assert!(follower.signing_healthy());
        assert!(follower.on_timeout().is_some());
    }

    // ---- Validator key rotation (staking KEY_CHANGE) ----

    /// `apply_key_changes` reads pending key changes, builds an
    /// updated `ValidatorSet`, and schedules a rotation. After
    /// `rotate_epoch`, the new key is active.
    #[test]
    fn key_change_rotates_validator_key() {
        // 4 validators with derived addresses (production convention:
        // address = validator_address(pk)).
        let pks: Vec<crypto::bls::PublicKey> = (1..=4u8).map(pk).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
            .without_signature_verification();

        // The staking address of validator 0 is derived from pk(1).
        let addr = vs.validator_addresses()[0];

        // Submit a key change: validator 0 rotates to pk(0xFF).
        let new_key = crypto::bls::PublicKey([0xFF; crypto::bls::PublicKey::LEN]);
        let changes = vec![(addr, new_key.0.to_vec())];
        let applied = engine.apply_key_changes(&changes).expect("apply key changes");
        assert_eq!(applied, 1, "one key change applied");

        // The rotation is pending.
        assert!(engine.rotation_pending(), "rotation should be pending");

        // Complete the rotation — the new key takes effect.
        engine.rotate_epoch().expect("complete rotation");

        // The new set has the updated key for validator 0.
        let new_set = engine.validator_set();
        assert_eq!(
            new_set.validator(0).expect("validator 0").as_bytes(),
            new_key.as_bytes(),
            "validator 0's key must be rotated",
        );

        // The staking address is preserved (identity survives key rotation).
        assert_eq!(new_set.validator_addresses()[0], addr);
    }

    /// `apply_key_changes` with an unknown address skips it (no-op).
    #[test]
    fn key_change_unknown_address_skipped() {
        let pks: Vec<crypto::bls::PublicKey> = (1..=4u8).map(pk).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut engine =
            OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).without_signature_verification();

        // An address not in the validator set — no index_of match.
        let unknown = primitives::Address([0xAA; 20]);
        let changes = vec![(unknown, vec![0xBB; 48])];
        let applied = engine.apply_key_changes(&changes).expect("apply key changes");
        assert_eq!(applied, 0, "unknown address produces no change");
        assert!(!engine.rotation_pending(), "no rotation scheduled");
    }

    /// `apply_key_changes` with an invalid key length returns an error.
    #[test]
    fn key_change_invalid_key_length() {
        let pks: Vec<crypto::bls::PublicKey> = (1..=4u8).map(pk).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
            .without_signature_verification();

        let addr = vs.validator_addresses()[0];
        let changes = vec![(addr, vec![0xBB; 47])]; // 47 bytes — not 48
        let result = engine.apply_key_changes(&changes);
        assert!(result.is_err(), "invalid key length must be rejected");
    }

    /// `ValidatorSet::index_of` finds the right index for a derived
    /// address, and `apply_key_change` preserves the address.
    #[test]
    fn validator_set_index_of_and_apply_key_change() {
        let pks: Vec<crypto::bls::PublicKey> = (1..=4u8).map(pk).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        // Derived addresses: index_of finds each validator.
        for i in 0..4u16 {
            let addr = vs.validator_addresses()[usize::from(i)];
            assert_eq!(vs.index_of(&addr), Some(i));
        }

        // Unknown address returns None.
        let unknown = primitives::Address([0xAA; 20]);
        assert_eq!(vs.index_of(&unknown), None);

        // apply_key_change replaces the key, preserves the address.
        let new_key = crypto::bls::PublicKey([0xFF; 48]);
        let updated = vs.apply_key_change(0, new_key).expect("apply key change");
        assert_eq!(updated.validator(0).expect("v0").as_bytes(), new_key.as_bytes());
        assert_eq!(updated.validator_addresses()[0], vs.validator_addresses()[0]);
    }

    /// A BLS-keyed validator set for index re-seat tests — keys that
    /// correspond to real secret keys, so `index_of_key` can find
    /// them after membership moves.
    fn bls_validator_set() -> (Vec<crypto::BlsSecretKey>, ValidatorSet) {
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
        (keys, vs)
    }

    /// The production epoch bridge: staged adds drain through the
    /// app seam and complete a rotation in one drive.
    #[test]
    fn drive_epoch_changes_rotates_committee() {
        let app = Arc::new(MockApp::new());
        let mut engine =
            OxideBft::new(app.clone(), single_validator_set()).without_signature_verification();
        let (new_keys, _) = bls_validator_set();
        app.queue_epoch_changes(types::EpochChanges {
            key_changes: Vec::new(),
            adds: vec![(
                primitives::Address([0x09; 20]),
                new_keys[0].public_key().as_bytes().to_vec(),
                1,
            )],
            removes: Vec::new(),
        });
        assert_eq!(engine.drive_epoch_changes().expect("drive"), 1);
        assert_eq!(engine.epoch(), Epoch::new(1));
        assert_eq!(engine.validator_set().n(), 2);
        // A second drain sees nothing — the queues were consumed.
        assert_eq!(engine.drive_epoch_changes().expect("drive"), 0);
    }

    /// Key replacement + removal + addition fold into ONE rotation —
    /// the combined path the two separate apply methods could not
    /// express (the second schedule would hit `AlreadyPending`).
    #[test]
    fn drive_epoch_changes_combines_key_add_remove() {
        let app = Arc::new(MockApp::new());
        let (_, vs) = bls_validator_set();
        let mut engine =
            OxideBft::with_index(app.clone(), vs.clone(), 1).without_signature_verification();
        let old_addr = vs.validator_addresses()[0];
        let rotate_key_addr = vs.validator_addresses()[1];
        let fresh = bls_key(9);
        app.queue_epoch_changes(types::EpochChanges {
            key_changes: vec![(rotate_key_addr, fresh.public_key().as_bytes().to_vec())],
            adds: vec![(
                primitives::Address([0x0A; 20]),
                bls_key(10).public_key().as_bytes().to_vec(),
                1,
            )],
            removes: vec![old_addr],
        });
        let applied = engine.drive_epoch_changes().expect("drive");
        assert_eq!(applied, 3, "key change + remove + add");
        assert_eq!(engine.epoch(), Epoch::new(1));
        let new_set = engine.validator_set();
        // Original members 0 removed; 1..3 remain, plus the append.
        assert_eq!(new_set.n(), 4);
        assert_eq!(new_set.index_of(&old_addr), None, "removed member gone");
        assert_eq!(new_set.index_of_key(&fresh.public_key()), Some(0), "key replaced at index 0");
    }

    /// The restart-mid-transition case: module queues persist the
    /// deltas, so a node that rotated then crashed before draining
    /// would re-offer the same transition post-recovery. Re-applying
    /// must recognize the already-enacted set and NOT bump the
    /// epoch a second time — a spurious extra epoch diverges us
    /// from every peer that stayed up.
    #[test]
    fn drive_epoch_changes_dedups_replayed_transition() {
        let app = Arc::new(MockApp::new());
        let mut engine =
            OxideBft::new(app.clone(), single_validator_set()).without_signature_verification();
        let change = types::EpochChanges {
            key_changes: Vec::new(),
            adds: vec![(
                primitives::Address([0x09; 20]),
                bls_key(9).public_key().as_bytes().to_vec(),
                1,
            )],
            removes: Vec::new(),
        };
        app.queue_epoch_changes(change.clone());
        assert_eq!(engine.drive_epoch_changes().expect("drive"), 1);
        assert_eq!(engine.epoch(), Epoch::new(1));
        // Replay: the same deltas re-pend after a restart — the
        // candidate equals the current set, so it is a no-op, not
        // a second transition.
        app.queue_epoch_changes(change);
        assert_eq!(engine.drive_epoch_changes().expect("re-drive"), 0);
        assert_eq!(engine.epoch(), Epoch::new(1), "no duplicate epoch bump");
    }

    /// Local index remapping: removing a lower-index member shifts
    /// our slot; the engine must re-seat `validator_index` by
    /// matching our BLS key, or we'd sign under the wrong identity.
    #[test]
    fn rotation_reseats_validator_index() {
        let (keys, vs) = bls_validator_set();
        let app = Arc::new(MockApp::new());
        // We are validator index 3 (key 4).
        let mut engine = OxideBft::with_index(app.clone(), vs.clone(), 3)
            .without_signature_verification()
            .with_secret_key(keys[3].clone());
        let removed_addr = vs.validator_addresses()[0];
        app.queue_epoch_changes(types::EpochChanges {
            key_changes: Vec::new(),
            adds: Vec::new(),
            removes: vec![removed_addr],
        });
        engine.drive_epoch_changes().expect("drive");
        // Validator 0 removed → our key now sits at index 2.
        assert_eq!(engine.validator_index(), 2);
        assert_eq!(engine.validator_set().index_of_key(&keys[3].public_key()), Some(2));
    }

    /// Recovery is a full lifecycle restore: the rotated committee,
    /// the epoch, AND the pacemaker's epoch/membership all come
    /// back — not just the view. A restart that rebuilt only the
    /// view would stamp timeouts under the wrong epoch and reject
    /// the cluster's TCs.
    #[test]
    fn recover_from_wal_restores_rotated_set_and_pacemaker() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("consensus.wal");

        let (_, rotated_vs) = bls_validator_set();
        // Engine commits a rotation, which appends a set-bearing
        // WAL entry.
        {
            let app = Arc::new(MockApp::new());
            let mut engine = OxideBft::new(app, single_validator_set())
                .without_signature_verification()
                .with_wal(crate::wal::Wal::open(&path).expect("wal"));
            engine.schedule_rotation(rotated_vs.clone()).expect("schedule");
            engine.rotate_epoch().expect("rotate");
            assert_eq!(engine.epoch(), Epoch::new(1));
        }

        // Restart: a fresh engine built with the GENESIS set
        // recovers from the same WAL — it must come back with the
        // rotated committee, epoch, and a pacemaker rebuilt for
        // both (leader schedule + timeout epoch correctness).
        let app = Arc::new(MockApp::new());
        let mut engine = OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_wal(crate::wal::Wal::open(&path).expect("wal"));
        engine.recover_from_wal().expect("recover");
        assert_eq!(engine.epoch(), Epoch::new(1), "epoch recovered");
        assert_eq!(engine.validator_set(), &rotated_vs, "committee recovered");
        assert_eq!(
            engine.pacemaker.current_epoch(),
            Epoch::new(1),
            "pacemaker rebuilt with the recovered epoch — timeouts attest the right epoch"
        );
        assert_eq!(
            engine.pacemaker.validator_set().n(),
            rotated_vs.n(),
            "pacemaker rebuilt with the recovered committee — quorum math matches peers"
        );
    }

    /// Recovery re-seats `validator_index` through the key match:
    /// a restart whose committee moved under it must not sign under
    /// the stale construction index.
    #[test]
    fn recover_from_wal_reseats_index_by_key() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("consensus.wal");

        let (keys, vs) = bls_validator_set();
        // Rotate: drop validator 0 — key 4 moves from index 3 to 2.
        {
            let app = Arc::new(MockApp::new());
            let mut engine = OxideBft::with_index(app, vs.clone(), 3)
                .without_signature_verification()
                .with_secret_key(keys[3].clone())
                .with_wal(crate::wal::Wal::open(&path).expect("wal"));
            engine
                .apply_validator_changes(&[], &[vs.validator_addresses()[0]])
                .expect("apply remove");
            engine.rotate_epoch().expect("rotate");
        }

        // Restart with the ORIGINAL set at the ORIGINAL index — the
        // WAL carries the rotated committee; recovery must both
        // restore it and re-seat us at index 2.
        let app = Arc::new(MockApp::new());
        let mut engine = OxideBft::with_index(app, vs, 3)
            .without_signature_verification()
            .with_secret_key(keys[3].clone())
            .with_wal(crate::wal::Wal::open(&path).expect("wal"));
        engine.recover_from_wal().expect("recover");
        assert_eq!(engine.validator_set().n(), 3);
        assert_eq!(engine.validator_index(), 2, "re-seated by BLS key match");
    }
}
