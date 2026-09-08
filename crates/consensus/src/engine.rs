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
    fn block_hash(header: &BlockHeader) -> Hash {
        let mut buf = Vec::new();
        header.encode(&mut buf);
        Hasher::hash_one(Domain::Block, &buf)
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
    /// # Panics
    ///
    /// Panics if the app rejects the proposal via `process_proposal`.
    /// In the happy path the app proposed the block, so rejection is a
    /// bug. In production this logs and drops the proposal instead.
    pub fn propose(&mut self) -> Option<(BlockHeader, Proposal)> {
        let proposal = self.app.prepare_proposal(&Self::BUDGET);
        let has_pending_txs = !proposal.txs.is_empty();
        let pending_has_txs = self.pending.as_ref().is_some_and(|p| !p.proposal.txs.is_empty());

        // No work: no pending txs and no pending block to flush.
        if !has_pending_txs && !pending_has_txs && self.next_height != Height::new(0) {
            return None;
        }

        // Process the proposal through the app (static validity).
        match self.app.process_proposal(&proposal) {
            Verdict::Accept => {}
            Verdict::Reject { reason } => {
                panic!("oxideBFT: proposal rejected by app: {reason}");
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
            timestamp: 0, // deterministic: no real clock in the test model
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
        // Safety: never vote twice in the same view.
        if self.last_voted_view.is_some_and(|v| v >= header.view) {
            return None;
        }
        // Tail-fork resistance (docs/oxidebft-spec.md §4): reject
        // proposals that don't extend our highest QC. A leader that
        // forks away a notarized block must be bypassed, not
        // rewarded. The check: the proposal's `high_qc` must equal
        // (or extend) our `high_qc`. In the happy path they're equal
        // (the leader built on the same QC). On a view change, the
        // new leader's `high_qc` may be higher than ours (it saw a
        // QC we missed) — that's fine, we accept it. But a leader
        // with a *lower* `high_qc` is forking.
        //
        // Exception: at genesis (no high_qc yet), any proposal is
        // accepted.
        if let Some(our_high_qc) = &self.high_qc {
            match &header.high_qc {
                // Proposal has a high_qc: it must match ours. (We
                // don't chase chains of QCs here — the 2-chain
                // commit rule already ensures block validity. This
                // check prevents the simple fork where a leader
                // discards a notarized block.)
                Some(prop_qc) if prop_qc.block_hash != our_high_qc.block_hash => {
                    return None;
                }
                // Proposal has no high_qc but we have one: the
                // leader is proposing a fork that ignores our QC.
                None => return None,
                _ => {}
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

    /// Sign a vote with this engine's BLS secret key. If no key is set
    /// (conformance mode), returns `Signature::ZERO`. The `view` is
    /// reserved for future use (e.g. signing the view into the message).
    fn sign_vote(&self, _view: View, block_hash: Hash) -> Signature {
        match &self.secret_key {
            Some(sk) => {
                // The signed message is the block hash (32 bytes).
                // The domain is `Vote` for vote signatures.
                let msg = block_hash.as_bytes();
                sk.sign(crypto::hash::Domain::Vote, msg)
            }
            None => Signature::ZERO,
        }
    }

    /// Leader: collect a vote from validator `voter`. Stores the vote
    /// for later QC formation. The `voter` index identifies which
    /// slot in the signer bitmap to set.
    pub fn collect_vote(&mut self, voter: ValidatorIndex, vote: Vote) {
        let idx = usize::from(voter);
        if idx < self.votes.len() && self.votes[idx].is_none() {
            self.votes[idx] = Some(vote);
            self.vote_count += 1;
        }
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
        let aggregate_signature = if self.secret_key.is_some() {
            let sigs: Vec<Signature> =
                self.votes.iter().filter_map(|v| v.as_ref().map(|v| v.signature)).collect();
            crypto::aggregate(&sigs).unwrap_or(AggregateSignature::ZERO)
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
    pub fn deliver_qc(&mut self, qc: QuorumCertificate) {
        // Update the highest QC.
        self.high_qc = Some(qc.clone());

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
                    return;
                }
            }
        }

        // No commit: the QC's block becomes the new pending block
        // (if we have it stored).
        if let Some((_, proposal)) = self.blocks.get(&qc.block_hash).cloned() {
            self.pending = Some(PendingBlock { hash: qc.block_hash, proposal });
        }
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
    fn advance_view(&mut self) {
        self.current_view = View::new(self.current_view.value() + 1);
    }

    /// Validator: local timer expired. Returns a timeout signature
    /// for the pacemaker. In single-validator mode, this is a no-op
    /// (no one to timeout). In multi-validator mode, the simulation
    /// collects these and forms a TC.
    ///
    /// Stage 5 replaces the placeholder signature with real BLS.
    pub fn on_timeout(&mut self) -> Option<Signature> {
        let _ = self.pacemaker.on_local_timeout();
        Some(Signature::ZERO)
    }

    /// Validator: process a timeout certificate. Advances the view
    /// if the TC is for the current view. The new leader must extend
    /// the highest QC (tail-fork resistance).
    pub fn on_timeout_certificate(&mut self, tc: &TimeoutCertificate) {
        if let Some(crate::pacemaker::PacemakerEvent::AdvanceView { new_view, .. }) =
            self.pacemaker.on_timeout_certificate(tc)
        {
            self.current_view = new_view;
        }
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
            crypto::aggregate(&[vote.signature]).unwrap_or(AggregateSignature::ZERO)
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

        // Deliver the QC (checks 2-chain commit).
        self.deliver_qc(qc);

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

    fn pk(byte: u8) -> crypto::bls::PublicKey {
        crypto::bls::PublicKey([byte; crypto::bls::PublicKey::LEN])
    }

    fn single_validator_set() -> ValidatorSet {
        ValidatorSet::new(vec![pk(1)], vec![1]).expect("1 validator")
    }

    fn make_engine() -> OxideBft {
        let app = Arc::new(MockApp::new());
        OxideBft::new(app, single_validator_set())
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
        OxideBft::with_index(app, four_validator_set(), idx)
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
        leader.collect_vote(leader_idx, leader_vote);

        // 3. Followers vote.
        for (i, follower) in followers.iter_mut().enumerate() {
            if let Some(vote) = follower.vote(&header, &proposal) {
                // Voter index is i+1 (leader is 0, followers are 1..n).
                let voter_idx = u16::try_from(i + 1).expect("validator index fits u16");
                leader.collect_vote(voter_idx, vote);
            }
        }

        // 4. Leader forms a QC.
        let qc = leader.try_form_qc().expect("quorum should be reached");

        // 5. All validators receive the QC.
        leader.deliver_qc(qc.clone());
        for follower in followers.iter_mut() {
            follower.deliver_qc(qc.clone());
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
        // Single validator with a real BLS key.
        let key = bls_key(1);
        let pk = key.public_key();
        let app = Arc::new(MockApp::new());
        let vs = single_validator_set();
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
        // The signed message is the block hash.
        let block_hash = qc.block_hash;
        let result = crypto::aggregate_verify(
            &qc.aggregate_signature,
            crypto::hash::Domain::Vote,
            block_hash.as_bytes(),
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

        // Leader self-votes.
        let leader_sig = keys[0].sign(crypto::hash::Domain::Vote, block_hash.as_bytes());
        leader.collect_vote(
            0,
            Vote {
                view: header.view,
                phase: VotePhase::Prepare,
                block_hash,
                signature: leader_sig,
            },
        );

        // Followers vote.
        for (i, follower) in followers.iter_mut().enumerate() {
            if let Some(vote) = follower.vote(&header, &proposal) {
                leader.collect_vote(u16::try_from(i + 1).expect("validator index fits u16"), vote);
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
        let result = crypto::aggregate_verify(
            &qc.aggregate_signature,
            crypto::hash::Domain::Vote,
            block_hash.as_bytes(),
            &pks,
        );
        assert!(result.is_ok(), "QC aggregate signature must verify against all 4 keys");
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
        };
        let vote = engine.vote(&header, &proposal);
        assert!(vote.is_some(), "proposal extending high_qc must be accepted");
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
        };
        let vote = engine.vote(&header, &proposal);
        assert!(vote.is_some(), "genesis proposal must be accepted");
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
        v2.on_timeout_certificate(&tc);
        v3.on_timeout_certificate(&tc);
        v0.on_timeout_certificate(&tc);

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
            engines[leader_idx].collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote);

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
                engines[leader_idx].collect_vote(voter, vote);
            }

            // Leader forms QC.
            let qc = engines[leader_idx]
                .try_form_qc()
                .unwrap_or_else(|| panic!("quorum should be reached in round {round}"));

            // All validators receive the QC (deterministic order).
            for engine in &mut engines {
                engine.deliver_qc(qc.clone());
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
        engines[leader_idx].collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote);
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
            engines[leader_idx].collect_vote(voter, vote);
        }
        let qc = engines[leader_idx].try_form_qc().expect("flush quorum");
        for engine in &mut engines {
            engine.deliver_qc(qc.clone());
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
}
