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
        if let Some(ref key) = self.secret_key
            && let Some(idx) = self.validator_set.index_of_key(&key.public_key())
        {
            self.validator_index = idx;
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

    /// Number of in-flight (not yet committed) blocks the engine is
    /// storing — headers received via `vote`/`vote_header` that the
    /// commit walk may still traverse. Diagnostic for simulation
    /// harnesses attributing commit lag: a node whose stored count
    /// is far below its peers' committed tip is missing ancestors.
    #[must_use]
    pub fn stored_block_count(&self) -> usize {
        self.blocks.len()
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
            // height.) A mismatch on a *verified* cert means a
            // stake supermajority really attested a root we did
            // not compute — confirmed divergence; refuse to
            // extend it.
            let local = self.app.attest_state(cert.height)?;
            if local.root != cert.state_root {
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
            && let Some((tip, _)) = self.blocks.get(&qc.block_hash).cloned()
        {
            self.commit_walk(&tip);
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
        crate::verify::vote_signing_message(self.epoch, view, phase_byte, block_hash)
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
        if let Some((cached_att, cached_epoch, cached_sig)) = &self.last_attestation
            && cached_att.height == att.height
            && cached_att.root == att.root
            && *cached_epoch == self.epoch
        {
            return (Some(*cached_att), Some(*cached_sig));
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
                return Ok(());
            }
        }

        // Hardening: check that this vote agrees with the first vote
        // collected for this view. All votes in a QC must be for the
        // same (view, block_hash) — otherwise the QC does not
        // represent agreement on a single block.
        if let Some(first) = self.votes.iter().find_map(Option::as_ref)
            && (first.view != vote.view || first.block_hash != vote.block_hash)
        {
            return Err(ConsensusError::ConflictingVote {
                voter,
                view: vote.view,
                expected_block: first.block_hash,
                actual_block: vote.block_hash,
            });
        }

        // Harvest the execution attestation (if any) for exec-cert
        // aggregation. Only signature-verified attestations count —
        // a forged attestation that slipped into an aggregate would
        // make the resulting cert fail verification at proposal
        // time, letting one byzantine voter poison a whole block's
        // embedded cert. The vote itself is unaffected either way:
        // attestations ride along as best-effort signals and are
        // dropped individually when invalid.
        if self.verify_signatures
            && let (Some(att), Some(sig)) = (&vote.attestation, &vote.attestation_sig)
        {
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
        if let Some(current_high_qc) = &self.high_qc
            && qc.view.value() <= current_high_qc.view.value()
        {
            return Err(ConsensusError::StaleQc {
                qc_view: qc.view,
                high_qc_view: current_high_qc.view,
            });
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
        crate::verify::verify_qc_signature(&self.validator_set, self.epoch, qc)
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
        crate::verify::verify_tc_signature(&self.validator_set, tc)
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
mod tests;
