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
//! pending block (the one whose QC the new block extends). The
//! engine tracks one pending block at a time — the last block with a
//! QC that hasn't been committed yet.
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
//! signature. When ≥2f+1 validators timeout, a TC forms and the view
//! advances. The new leader must extend the highest QC (tail-fork
//! resistance). The pacemaker (stage 2) drives the view advancement;
//! the engine wires it in here.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use codec::Encode;
use crypto::bls::{AggregateSignature, Signature};
use crypto::hash::{Domain, Hasher};
use ports::{AppInterface, ConsensusEngine};
use primitives::{Epoch, Hash, Height, View};
use types::{
    BlockBudget, BlockHeader, FinalizedBlock, MempoolAck, Proposal, QuorumCertificate,
    TimeoutCertificate, TxBytes, Verdict, Vote, VotePhase,
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

/// A block that has a QC but hasn't been committed yet — waiting for
/// the 2-chain commit rule to fire.
///
/// When the *next* block (which extends this one) gets a QC, this
/// block is committed. The engine tracks exactly one pending block at
/// a time (the tip of the pipeline).
#[derive(Debug, Clone)]
struct PendingBlock {
    /// The block's hash.
    hash: Hash,
    /// The block's proposal (txs).
    proposal: Proposal,
}

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

/// Errors from consensus message verification (C1 fix + hardening).
///
/// These are distinct from operational errors (io, codec): they
/// indicate byzantine behavior — a peer sent a vote or QC with an
/// invalid signature, conflicting metadata, or insufficient quorum.
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
    /// A QC was formed or received whose signer count is below the
    /// quorum threshold. The aggregate signature may verify, but the
    /// QC does not represent ≥2f+1 validators — it cannot be trusted
    /// as a commitment certificate.
    InsufficientQuorum {
        /// The number of signers in the QC's bitmap.
        signers: usize,
        /// The quorum threshold for the current validator set.
        threshold: usize,
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
            Self::InsufficientQuorum { signers, threshold } => {
                write!(f, "insufficient quorum: {signers} signers < {threshold} threshold")
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
    /// Block store: block hash → (header, proposal). Used to look up
    /// blocks at commit time.
    blocks: HashMap<Hash, (BlockHeader, Proposal)>,
    /// The pending block: the last block with a QC, waiting for the
    /// 2-chain commit rule to fire. `None` when no block is pending
    /// (e.g. at genesis, or after the last pending block was committed).
    pending: Option<PendingBlock>,
    /// Finalized blocks keyed by height. `BTreeMap` for ordered
    /// iteration (the conformance suite checks the height sequence).
    finalized: BTreeMap<u64, FinalizedBlock>,
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
    /// Number of votes collected in the current view.
    vote_count: usize,
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
            blocks: HashMap::new(),
            pending: None,
            finalized: BTreeMap::new(),
            next_height: Height::new(0),
            current_view: initial_view,
            epoch,
            votes: vec![None; n],
            vote_count: 0,
            timeout_signatures: vec![None; n],
            verify_signatures: true,
        }
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
    /// is the production setting — a forged vote or QC is rejected
    /// with [`ConsensusError`].
    ///
    /// Conformance tests that don't set BLS keys (votes carry
    /// `Signature::ZERO`) call this to skip verification. The
    /// multi-node simulation does NOT call this — it uses real keys
    /// and real verification.
    #[must_use]
    pub fn without_signature_verification(mut self) -> Self {
        self.verify_signatures = false;
        self
    }

    /// The budget the engine uses when assembling proposals. Phase 1
    /// uses a generous fixed budget; Phase 2 tunes it from chain
    /// config (plan.md §6: 1–2 GG/block).
    const BUDGET: BlockBudget = BlockBudget {
        max_bytes: 1 << 20, // 1 MiB
        max_gas: 1 << 30,   // 1 gigagas
    };

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
        self.epoch = Epoch::new(self.epoch.value() + 1);
        self.current_view = View::new(0);
        self.last_voted_view = None;
        self.high_qc = None;
        self.pending = None;
        self.votes = vec![None; self.validator_set.n()];
        self.vote_count = 0;
        // Reset the pacemaker for the new epoch.
        self.pacemaker =
            crate::pacemaker::Pacemaker::new(self.validator_set.clone(), View::new(0), self.epoch);
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

    /// Whether this engine is the leader for the current view.
    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.validator_set.leader(self.current_view) == self.validator_index
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
            self.next_height = Height::new(height.value() + 1);
        }
    }

    /// Compute the Merkle root of a transaction list.
    ///
    /// Stage 4: a simple domain-separated hash of the concatenated tx
    /// bytes. A proper Merkle root (MMR or binary Merkle tree) lands
    /// when individual tx inclusion proofs are needed.
    fn tx_root(txs: &[TxBytes]) -> Hash {
        let mut buf = Vec::new();
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
        let mut buf = Vec::new();
        header.encode(&mut buf);
        Hasher::hash_one(Domain::Block, &buf)
    }

    /// Count the number of set bits in a signer bitmap. This is the
    /// number of validators who signed the certificate (QC or TC).
    /// Used for quorum enforcement — a structural property checked
    /// regardless of whether BLS signature verification is enabled.
    fn count_signers(bitmap: &[u8]) -> usize {
        bitmap.iter().map(|b| b.count_ones() as usize).sum()
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
    /// **Height tracking:** the engine maintains its own `next_height`
    /// that advances on proposal (not finalization). This is required
    /// because the 2-chain pipeline proposes multiple blocks before
    /// committing any of them. The app's `next_proposal_height`
    /// advances on finalization (in `finalize_block`); the engine's
    /// `next_height` is the pipeline's height, which leads the app's.
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
        let proposal = self.app.prepare_proposal(&Self::BUDGET);
        let has_pending_txs = !proposal.txs.is_empty();
        let pending_has_txs = self.pending.as_ref().is_some_and(|p| !p.proposal.txs.is_empty());

        // No work: no pending txs and no pending block to flush.
        if !has_pending_txs && !pending_has_txs && self.next_height != Height::new(0) {
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
        let prev_block = self.high_qc.as_ref().map_or(Hash::ZERO, |qc| qc.block_hash);
        let header = BlockHeader {
            height: self.next_height,
            view: self.current_view,
            epoch: self.epoch,
            prev_block,
            tx_root,
            high_qc: self.high_qc.clone(),
            timeout_cert: None, // Stage 4: TC attached on view changes
            proposer: proposer_hash(self.validator_set.leader(self.current_view)),
            timestamp: 0,             // deterministic: no real clock in the test model
            proposer_signature: None, // Stage 5: leader signs the header
            exec_cert: None,          // Wired after exec-cert aggregation
        };
        let block_hash = Self::block_hash(&header);
        self.blocks.insert(block_hash, (header.clone(), proposal.clone()));
        // Advance the engine's height on proposal (not finalization).
        // The 2-chain pipeline proposes multiple blocks before
        // committing any; the engine's height leads the app's.
        self.next_height = Height::new(self.next_height.value() + 1);
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
        // Height sync: learn the chain's progression from this
        // proposal. Even if we reject the proposal (tail-fork
        // resistance, already voted, etc.), the height is a fact
        // about the chain's progression. If we later become the
        // leader, we must propose at a height above any we've seen.
        self.observe_block_height(header.height);

        // Safety: never vote twice in the same view.
        if self.last_voted_view.is_some_and(|v| v >= header.view) {
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
                let local = self.app.attest_state(cert.height);
                if local.root != cert.state_root {
                    // Log the divergence and refuse to vote. The
                    // operator should be alerted — this is a critical
                    // condition that requires investigation.
                    return None;
                }
            }
        }
        // Process the proposal through the app (static validity).
        match self.app.process_proposal(proposal) {
            Verdict::Accept => {}
            Verdict::Reject { .. } => return None,
        }
        // Store the block for later commit lookup.
        let block_hash = Self::block_hash(header);
        self.blocks.insert(block_hash, (header.clone(), proposal.clone()));
        self.last_voted_view = Some(header.view);
        // Sign the vote (stage 5: real BLS if key is set).
        let signature = self.sign_vote(header.view, block_hash);
        Some(Vote { view: header.view, phase: VotePhase::Prepare, block_hash, signature })
    }

    /// Build the BLS signing message for a vote. Binds `(view,
    /// phase, block_hash, epoch)` to prevent replay across phases
    /// or epochs (C3 fix).
    ///
    /// Format: `view.to_le_bytes() (8) + phase_byte (1) +
    /// block_hash (32) + epoch.to_le_bytes() (8)` = 49 bytes.
    fn vote_signing_message(&self, view: View, phase_byte: u8, block_hash: &Hash) -> Vec<u8> {
        let mut msg = Vec::with_capacity(49);
        msg.extend_from_slice(&view.value().to_le_bytes());
        msg.push(phase_byte);
        msg.extend_from_slice(block_hash.as_bytes());
        msg.extend_from_slice(&self.epoch.value().to_le_bytes());
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
    /// # Signed message (C3 fix)
    ///
    /// The signed message binds `(view, phase, block_hash, epoch)` to
    /// prevent vote replay across phases or epochs. A `Prepare` vote
    /// signature cannot be reused as a `PreCommit` or `Commit` vote because
    /// the phase byte differs. A vote from epoch 0 cannot be replayed
    /// in epoch 1 because the epoch bytes differ.
    fn sign_vote(&self, view: View, block_hash: Hash) -> Signature {
        match &self.secret_key {
            Some(sk) => {
                let phase_byte = Self::current_phase_byte();
                let msg = self.vote_signing_message(view, phase_byte, &block_hash);
                sk.sign(crypto::hash::Domain::Vote, &msg)
            }
            None => Signature::ZERO,
        }
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
        // Reject stale votes: votes for views below the engine's
        // current view are leftovers from a previous round that
        // arrived late over the network. Collecting them would
        // pollute the vote buffer and cause spurious ConflictingVote
        // errors when the real votes for the current view arrive.
        // Silently dropping them is safe — the leader that needed
        // them already formed its QC or timed out.
        if vote.view < self.current_view {
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
        if self.verify_signatures {
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

        self.votes[idx] = Some(vote);
        self.vote_count += 1;
        Ok(())
    }

    /// Leader: try to form a QC from collected votes. Returns the QC
    /// if quorum (≥2f+1) is reached, `None` otherwise.
    ///
    /// After forming a QC, the vote buffer is cleared for the next
    /// view.
    pub fn try_form_qc(&mut self) -> Option<QuorumCertificate> {
        if self.vote_count < self.validator_set.quorum() {
            return None;
        }

        // Form the QC from the first valid vote (all votes are for
        // the same block in the happy path).
        let first_vote = self.votes.iter().find_map(Option::clone)?;
        let bitmap_len = self.validator_set.n().div_ceil(8);
        let mut signer_bitmap = vec![0u8; bitmap_len];
        for (i, v) in self.votes.iter().enumerate() {
            if v.is_some() {
                signer_bitmap[i / 8] |= 1u8 << (i % 8);
            }
        }

        // Stage 5: aggregate the collected signatures via blst.
        // If no secret key is set (conformance mode), use ZERO.
        // H6 fix: propagate aggregation errors instead of silently
        // replacing with ZERO (which would produce an invalid QC).
        let aggregate_signature = if self.secret_key.is_some() {
            let sigs: Vec<Signature> =
                self.votes.iter().filter_map(|v| v.as_ref().map(|v| v.signature)).collect();
            match crypto::aggregate(&sigs) {
                Ok(agg) => agg,
                Err(_) => return None, // aggregation failed — can't form QC
            }
        } else {
            AggregateSignature::ZERO
        };

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

        Some(qc)
    }

    /// All validators: receive a QC, update `high_qc`, and check the
    /// 2-chain commit rule. If the QC's block extends the pending
    /// block, commit the pending block.
    ///
    /// The QC's block must already be stored (via `propose` or
    /// `vote`); if not, the QC is accepted but no commit check runs
    /// (the block will be committed when it's eventually received).
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
    /// [`ConsensusError::InsufficientQuorum`] if the signer count is
    /// below the quorum threshold, or
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
        // signature verification is enabled. A QC with fewer than
        // quorum signers is not a valid commitment certificate, even
        // in conformance mode — the signer count is a structural
        // property of the QC, not a cryptographic one.
        let signer_count = Self::count_signers(&qc.signer_bitmap);
        let threshold = self.validator_set.quorum();
        if signer_count < threshold {
            return Err(ConsensusError::InsufficientQuorum { signers: signer_count, threshold });
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
            self.current_view = View::new(qc.view.value() + 1);
            self.pacemaker.sync_to_view(self.current_view);
            self.pacemaker.on_progress();
            // Clear stale votes from the old view.
            self.votes.fill(None);
            self.vote_count = 0;
        }

        // 2-chain commit check: if the QC's block extends the pending
        // block (i.e., the QC's block's high_qc matches the pending
        // block's hash), commit the pending block.
        if let Some(pending) = &self.pending {
            if let Some((header, proposal)) = self.blocks.get(&qc.block_hash).cloned() {
                // Does the QC's block extend the pending block?
                if header.high_qc.as_ref().is_some_and(|hqc| hqc.block_hash == pending.hash) {
                    // 2-chain: pending.qc → new_block → new_qc → commit pending.
                    let pending_hash = pending.hash;
                    self.commit_block(pending_hash);
                    // The QC's block becomes the new pending block.
                    self.pending = Some(PendingBlock { hash: qc.block_hash, proposal });
                    return Ok(());
                }
            }
        }

        // No commit: the QC's block becomes the new pending block
        // (if we have it stored).
        if let Some((_, proposal)) = self.blocks.get(&qc.block_hash).cloned() {
            self.pending = Some(PendingBlock { hash: qc.block_hash, proposal });
        }
        Ok(())
    }

    /// Verify a QC's aggregate signature against the signer bitmap
    /// and the validator set's public keys.
    ///
    /// Extracts the public keys of the signers from the bitmap, then
    /// calls `crypto::aggregate_verify` with the QC's aggregate
    /// signature, the block hash as the message, and `Domain::Vote`.
    ///
    /// The quorum threshold check is performed by the caller
    /// ([`deliver_qc`](Self::deliver_qc)) via [`count_signers`](Self::count_signers),
    /// so it is enforced regardless of whether signature verification
    /// is enabled.
    ///
    /// # Errors
    /// Returns [`ConsensusError::SignerOutOfBounds`] if the bitmap
    /// references a validator past the end of the set, or
    /// [`ConsensusError::InvalidQcSignature`] if the aggregate does
    /// not verify.
    fn verify_qc_signature(&self, qc: &QuorumCertificate) -> Result<(), ConsensusError> {
        // Extract the signer public keys from the bitmap.
        let mut signer_pks: Vec<crypto::bls::PublicKey> = Vec::new();
        for (i, byte) in qc.signer_bitmap.iter().enumerate() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    let idx = u16::try_from(i * 8 + bit)
                        .map_err(|_| ConsensusError::SignerOutOfBounds)?;
                    let pk = self
                        .validator_set
                        .validator(idx)
                        .map_err(|_| ConsensusError::SignerOutOfBounds)?;
                    signer_pks.push(*pk);
                }
            }
        }
        if signer_pks.is_empty() {
            return Err(ConsensusError::InvalidQcSignature);
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
    /// Note: `next_height` is NOT advanced here — it was already
    /// advanced when the block was proposed (the 2-chain pipeline
    /// proposes before committing). The app's `next_proposal_height`
    /// advances here (via `finalize_block`).
    fn commit_block(&mut self, block_hash: Hash) {
        let Some((header, proposal)) = self.blocks.remove(&block_hash) else {
            return; // already committed or unknown
        };
        let block = FinalizedBlock { height: header.height, txs: proposal.txs };
        self.app.finalize_block(&block);
        self.finalized.insert(header.height.value(), block);
    }

    /// Advance to the next view (happy path: one view per block).
    /// Public so the multi-node simulation can drive view advancement
    /// in lockstep across all validators. Syncs the pacemaker so that
    /// a later timeout fires for the correct view.
    pub fn advance_view(&mut self) {
        self.current_view = View::new(self.current_view.value() + 1);
        self.pacemaker.sync_to_view(self.current_view);
        self.pacemaker.on_progress();
        // Clear the vote buffer on view advance. Stale votes from
        // the previous view that arrive late over the network must
        // not pollute the new view's quorum accounting. Without
        // this, a late vote for view N could be collected into view
        // N+1's buffer and cause a spurious ConflictingVote error
        // when the real votes for view N+1 arrive.
        self.votes.fill(None);
        self.vote_count = 0;
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
        self.votes.fill(None);
        self.vote_count = 0;
        true
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
            // Clear stored timeout signatures for the next view.
            self.timeout_signatures.fill(None);
            self.current_view = self.pacemaker.current_view();
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
        // signature verification is enabled. A TC with fewer than
        // quorum signers is not a valid view-change certificate.
        let signer_count = Self::count_signers(&tc.signer_bitmap);
        let threshold = self.validator_set.quorum();
        if signer_count < threshold {
            return Err(ConsensusError::InsufficientQuorum { signers: signer_count, threshold });
        }

        // Verify the TC's aggregate signature (TC safety).
        if self.verify_signatures {
            self.verify_tc_signature(tc)?;
        }
        if let Some(crate::pacemaker::PacemakerEvent::AdvanceView { new_view, .. }) =
            self.pacemaker.on_timeout_certificate(tc)
        {
            self.current_view = new_view;
        }
        Ok(())
    }

    /// Verify a TC's aggregate signature against the signer bitmap
    /// and the validator set's public keys. The signed message is
    /// the TC's view as little-endian bytes, signed with
    /// `Domain::Timeout`.
    ///
    /// The quorum threshold check is performed by the caller
    /// ([`on_timeout_certificate`](Self::on_timeout_certificate)) via
    /// [`count_signers`](Self::count_signers), so it is enforced
    /// regardless of whether signature verification is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::SignerOutOfBounds`] if the bitmap
    /// references an out-of-bounds validator, or
    /// [`ConsensusError::InvalidTcSignature`] if the aggregate does
    /// not verify.
    fn verify_tc_signature(&self, tc: &TimeoutCertificate) -> Result<(), ConsensusError> {
        let mut signer_pks: Vec<crypto::bls::PublicKey> = Vec::new();
        for (i, byte) in tc.signer_bitmap.iter().enumerate() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    let idx = u16::try_from(i * 8 + bit)
                        .map_err(|_| ConsensusError::SignerOutOfBounds)?;
                    let pk = self
                        .validator_set
                        .validator(idx)
                        .map_err(|_| ConsensusError::SignerOutOfBounds)?;
                    signer_pks.push(*pk);
                }
            }
        }
        if signer_pks.is_empty() {
            return Err(ConsensusError::InvalidTcSignature);
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

        // Self-vote (stage 5: real BLS if key is set).
        let signature = self.sign_vote(self.current_view, block_hash);
        let vote =
            Vote { view: self.current_view, phase: VotePhase::Prepare, block_hash, signature };
        self.last_voted_view = Some(self.current_view);

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
        OxideBft::new(app, single_validator_set()).without_signature_verification()
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
        let block_hash = OxideBft::block_hash(&header);

        // 2. Leader self-votes.
        let leader_idx = leader.validator_index;
        let leader_vote = Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: Signature::ZERO,
        };
        leader.collect_vote(leader_idx, leader_vote).expect("conformance: no verification");

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

    #[test]
    fn collect_vote_rejects_forged_signature() {
        // 4 validators with real BLS keys. The leader has verification
        // enabled (the default). A vote with a forged signature (signed
        // by a different key) must be rejected.
        let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

        let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
            .with_secret_key(keys[0].clone());

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
        };

        // Voter index 99 is out of bounds (n=4).
        let err = leader.collect_vote(99, vote).expect_err("out-of-bounds voter must be rejected");
        assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 99 });
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
        let valid_vote =
            Vote { view: header.view, phase: VotePhase::Prepare, block_hash, signature: valid_sig };

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
    fn engine_continues_after_rotation() {
        let mut engine = make_engine();
        // Commit a block in epoch 0.
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();

        // Rotate to a new epoch.
        engine.schedule_rotation(second_validator_set()).expect("schedule");
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

        let proposal = Proposal {
            height: Height::new(99),
            txs: vec![TxBytes::new(vec![2])],
            attestation: None,
        };
        let header = BlockHeader {
            height: Height::new(99),
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

        let proposal = Proposal {
            height: Height::new(99),
            txs: vec![TxBytes::new(vec![2])],
            attestation: None,
        };
        let header = BlockHeader {
            height: Height::new(99),
            view: View::new(our_high_qc.view.value() + 2),
            epoch: Epoch::new(0),
            prev_block: newer_qc.block_hash,
            tx_root: OxideBft::tx_root(&proposal.txs),
            high_qc: Some(newer_qc),
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
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
        // divergence check is gated on verify_signatures).
        let app = Arc::new(MockApp::new());
        let mut engine = OxideBft::new(app, single_validator_set()).with_secret_key(bls_key(1));

        // The MockApp's attest_state for height 0 returns
        // Hash([0x00; 32]) (height 0 → byte 0). We craft an
        // exec_cert with a *different* state_root to trigger
        // divergence.
        let mock_root = Hash([0x00; 32]);
        let divergent_root = Hash([0xDE; 32]); // != mock_root

        let exec_cert = ExecCertificate {
            height: Height::new(0),
            state_root: divergent_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: AggregateSignature::ZERO,
        };

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
            exec_cert: Some(exec_cert),
        };
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
        let mut engine = OxideBft::new(app, single_validator_set()).with_secret_key(bls_key(1));

        // MockApp returns Hash([0x00; 32]) for height 0.
        let matching_root = Hash([0x00; 32]);

        let exec_cert = ExecCertificate {
            height: Height::new(0),
            state_root: matching_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: AggregateSignature::ZERO,
        };

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
            exec_cert: Some(exec_cert),
        };
        let vote = engine.vote(&header, &proposal);
        assert!(vote.is_some(), "proposal with matching exec_cert must be accepted");
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
        };
        leader.collect_vote(1, vote_a).expect("first vote accepted");

        // Second vote: for block hash B (different block, same view).
        let vote_b = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash([0xBB; 32]),
            signature: Signature::ZERO,
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
        let mut leader = make_multi_engine(0);

        let vote_v0 = Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            signature: Signature::ZERO,
        };
        leader.collect_vote(1, vote_v0).expect("first vote accepted");

        let vote_v1 = Vote {
            view: View::new(1),
            phase: VotePhase::Prepare,
            block_hash: Hash::ZERO,
            signature: Signature::ZERO,
        };
        let err = leader.collect_vote(2, vote_v1).expect_err("conflicting vote must be rejected");
        assert!(
            matches!(err, ConsensusError::ConflictingVote { voter, view, .. } if voter == 2 && view == View::new(1)),
            "expected ConflictingVote for view 1, got {err:?}"
        );
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
            matches!(err, ConsensusError::InsufficientQuorum { signers, threshold } if signers == 2 && threshold == 3),
            "expected InsufficientQuorum (2 < 3), got {err:?}"
        );
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
            matches!(err, ConsensusError::InsufficientQuorum { signers, threshold } if signers == 2 && threshold == 3),
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
}
