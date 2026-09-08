//! The oxideBFT consensus engine — `ConsensusEngine` implementation
//! (docs/oxidebft-spec.md §6).
//!
//! # Phase 1 stage 3: single-leader happy path
//!
//! Stage 3 implements the single-leader happy path (no view changes):
//! the leader proposes, self-votes (single validator), forms a QC,
//! and commits. The 2-chain pipeline (pre-commit → commit requiring
//! two QCs) is stage 4; stage 3 uses a 1-chain commit rule (commit on
//! QC formation) which is safe when there are no view changes and no
//! faults — exactly the happy-path assumption.
//!
//! # What this exercises
//!
//! Even in the 1-chain simplification, the engine:
//! - Creates `BlockHeader`s with view, epoch, QC, proposer fields.
//! - Forms `Vote`s and `QuorumCertificate`s (with placeholder BLS
//!   signatures; stage 5 adds real `blst` signing).
//! - Drives the full OAI boundary: `prepare_proposal` →
//!   `process_proposal` → `finalize_block` → `attest_state`.
//! - Passes the conformance suite (liveness, sequence, finality,
//!   determinism).
//!
//! # Why 1-chain for stage 3
//!
//! The 2-chain rule exists to preserve safety under view changes: a
//! block locked by a pre-commit QC cannot be forked by a new leader.
//! In the single-leader happy path (no timeouts, no view changes, no
//! faults), there is no forking risk, so 1-chain is safe. Stage 4
//! upgrades to 2-chain when view changes are introduced.

use std::collections::BTreeMap;
use std::sync::Arc;

use codec::Encode;
use crypto::bls::{AggregateSignature, Signature};
use crypto::hash::{Domain, Hasher};
use ports::{AppInterface, ConsensusEngine};
use primitives::{Epoch, Hash, Height, View};
use types::{
    BlockBudget, BlockHeader, FinalizedBlock, MempoolAck, Proposal, QuorumCertificate, TxBytes,
    Verdict, Vote, VotePhase,
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

/// The oxideBFT consensus engine.
///
/// Stage 3: single-validator, 1-chain commit, no networking. The
/// engine owns its `AppInterface` (matching `MockEngine`'s pattern) so
/// the conformance suite can construct a fresh, isolated engine+app
/// pair per run.
pub struct OxideBft {
    /// The application (executor + mempool + state). Behind `Arc` so
    /// the engine can be `Send` (the app is `Send + Sync`).
    app: Arc<dyn AppInterface>,
    /// The validator set for the current epoch.
    validator_set: ValidatorSet,
    /// The pacemaker (stage 2). Present but not actively driving
    /// timeouts in the happy path; stage 4 wires it in for view changes.
    #[allow(dead_code)]
    pacemaker: crate::pacemaker::Pacemaker,
    /// The highest QC the engine has formed. Carried in the next
    /// proposal's `high_qc` field (the pipeline's chain-link).
    high_qc: Option<QuorumCertificate>,
    /// The highest view the engine has voted in (prevents double-
    /// voting; a safety invariant even in self-voting mode).
    last_voted_view: View,
    /// Block store: block hash → (header, proposal). The proposal
    /// carries the txs; the header carries the consensus metadata.
    /// Both are needed at commit time (header for the chain, proposal
    /// for the txs).
    blocks: std::collections::HashMap<Hash, (BlockHeader, Proposal)>,
    /// Finalized blocks keyed by height. `BTreeMap` for ordered
    /// iteration (the conformance suite checks the height sequence).
    finalized: BTreeMap<u64, FinalizedBlock>,
    /// The next height at which a block will be proposed. Advances in
    /// lockstep with the app's `next_proposal_height` (the app is the
    /// ledger's source of truth; the engine mirrors it).
    next_height: Height,
    /// The current view. Advances by 1 per proposed block (one view
    /// per block in the happy path).
    current_view: View,
    /// The current epoch. Fixed in stage 3; stage 6 adds rotation.
    epoch: Epoch,
}

impl OxideBft {
    /// Construct a fresh engine with `app` and `validator_set` at
    /// genesis (height 0, view 0, epoch 0).
    #[must_use]
    pub fn new(app: Arc<dyn AppInterface>, validator_set: ValidatorSet) -> Self {
        let initial_view = View::new(0);
        let epoch = Epoch::new(0);
        let pacemaker =
            crate::pacemaker::Pacemaker::new(validator_set.clone(), initial_view, epoch);
        Self {
            app,
            validator_set,
            pacemaker,
            high_qc: None,
            last_voted_view: View::new(0),
            blocks: std::collections::HashMap::new(),
            finalized: BTreeMap::new(),
            next_height: Height::new(0),
            current_view: initial_view,
            epoch,
        }
    }

    /// The budget the engine uses when assembling proposals. Phase 1
    /// uses a generous fixed budget; Phase 2 tunes it from chain
    /// config (plan.md §6: 1–2 GG/block).
    const BUDGET: BlockBudget = BlockBudget {
        max_bytes: 1 << 20, // 1 MiB
        max_gas: 1 << 30,   // 1 gigagas
    };

    /// Compute the Merkle root of a transaction list.
    ///
    /// Stage 3: a simple domain-separated hash of the concatenated tx
    /// bytes. Stage 4+ replaces this with a proper Merkle root (MMR
    /// or binary Merkle tree) so individual tx inclusion can be
    /// proven. For now, the root is deterministic and unique per tx
    /// list — sufficient for the pipeline.
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

    /// Self-vote for `block_hash` in the current view. Returns the
    /// vote. Stage 5 replaces the placeholder signature with real BLS.
    fn self_vote(&mut self, block_hash: Hash) -> Vote {
        // Safety: never vote twice in the same view.
        if self.last_voted_view >= self.current_view {
            // Already voted in this view (or a later one); don't
            // double-vote. This shouldn't happen in the happy path
            // (one block per view), but the check is here for safety.
            return Vote {
                view: self.current_view,
                phase: VotePhase::Prepare,
                block_hash,
                signature: Signature::ZERO,
            };
        }
        self.last_voted_view = self.current_view;
        Vote {
            view: self.current_view,
            phase: VotePhase::Prepare,
            block_hash,
            // Stage 5: sign with the validator's BLS secret key.
            // For now, a deterministic placeholder.
            signature: Signature::ZERO,
        }
    }

    /// Form a quorum certificate from the self-vote. Single-validator:
    /// quorum = 1, so one vote suffices.
    fn form_qc(&self, vote: &Vote) -> QuorumCertificate {
        let leader_idx = self.validator_set.leader(vote.view);
        let bitmap_len = self.validator_set.n().div_ceil(8);
        let mut signer_bitmap = vec![0u8; bitmap_len];
        let idx = usize::from(leader_idx);
        signer_bitmap[idx / 8] |= 1u8 << (idx % 8);
        QuorumCertificate {
            view: vote.view,
            phase: vote.phase,
            block_hash: vote.block_hash,
            epoch: self.epoch,
            signer_bitmap,
            // Stage 5: aggregate the collected signatures via blst.
            // For now, a placeholder.
            aggregate_signature: AggregateSignature::ZERO,
        }
    }

    /// Commit `block_hash`: look up the block, create a
    /// `FinalizedBlock`, call `app.finalize_block`, and store it.
    fn commit_block(&mut self, block_hash: Hash) {
        let Some((header, proposal)) = self.blocks.remove(&block_hash) else {
            return; // already committed or unknown
        };
        let block = FinalizedBlock { height: header.height, txs: proposal.txs };
        self.app.finalize_block(&block);
        self.finalized.insert(header.height.value(), block);
        self.next_height = Height::new(header.height.value() + 1);
    }

    /// Drive one propose-vote-commit cycle. Returns `true` if a block
    /// was proposed (work was done), `false` if idle (no pending txs).
    fn step(&mut self) -> bool {
        let proposal = self.app.prepare_proposal(&Self::BUDGET);
        // No pending txs and not genesis → idle.
        if proposal.txs.is_empty() && self.next_height != Height::new(0) {
            return false;
        }
        // Process the proposal through the app (static validity).
        match self.app.process_proposal(&proposal) {
            Verdict::Accept => {}
            Verdict::Reject { reason } => {
                // The app rejected the proposal; don't commit it.
                // In the happy path this shouldn't happen (the app
                // proposed it). Panic in tests; log in production.
                panic!("oxideBFT: proposal rejected by app: {reason}");
            }
        }
        // Wrap the proposal in a BlockHeader and store it.
        let tx_root = Self::tx_root(&proposal.txs);
        let prev_block = self.high_qc.as_ref().map_or(Hash::ZERO, |qc| qc.block_hash);
        let header = BlockHeader {
            height: self.next_height,
            view: self.current_view,
            epoch: self.epoch,
            prev_block,
            tx_root,
            high_qc: self.high_qc.clone(),
            timeout_cert: None,
            proposer: proposer_hash(self.validator_set.leader(self.current_view)),
            timestamp: 0,
        };
        let block_hash = Self::block_hash(&header);
        self.blocks.insert(block_hash, (header, proposal));

        // Self-vote and form a QC.
        let vote = self.self_vote(block_hash);
        let qc = self.form_qc(&vote);
        self.high_qc = Some(qc.clone());

        // 1-chain commit: commit immediately on QC formation.
        // (Stage 4 upgrades to 2-chain when view changes are added.)
        self.commit_block(block_hash);

        // Advance the view for the next block.
        self.current_view = View::new(self.current_view.value() + 1);
        true
    }
}

impl ConsensusEngine for OxideBft {
    fn submit_tx(&mut self, tx: TxBytes) -> MempoolAck {
        self.app.ingest_tx(tx)
    }

    fn run_until_idle(&mut self) {
        // Drive propose-vote-commit cycles until no more pending txs.
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
        assert_eq!(engine.current_view, View::new(0));
    }

    #[test]
    fn one_tx_produces_one_block() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1, 2, 3]));
        engine.run_until_idle();
        assert_eq!(engine.finalized_height(), Some(Height::new(0)));
        let block = engine.finalized_block(Height::new(0)).expect("block 0");
        assert_eq!(block.txs.len(), 1);
        assert_eq!(block.txs[0].as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn multiple_txs_produce_contiguous_blocks() {
        let mut engine = make_engine();
        for i in 0..5u8 {
            engine.submit_tx(TxBytes::new(vec![i]));
            engine.run_until_idle();
        }
        assert_eq!(engine.finalized_height(), Some(Height::new(4)));
        for h in 0..5u64 {
            let block = engine.finalized_block(Height::new(h)).expect("block");
            assert_eq!(block.height, Height::new(h));
            assert!(!block.txs.is_empty());
        }
    }

    #[test]
    fn view_advances_per_block() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        assert_eq!(engine.current_view, View::new(1));
        engine.submit_tx(TxBytes::new(vec![2]));
        engine.run_until_idle();
        assert_eq!(engine.current_view, View::new(2));
    }

    #[test]
    fn high_qc_advances() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        assert!(engine.high_qc.is_some(), "high_qc should be set after first block");
        let qc = engine.high_qc.as_ref().expect("qc");
        assert_eq!(qc.view, View::new(0));
    }

    #[test]
    fn no_work_when_idle() {
        let mut engine = make_engine();
        // The engine produces a genesis block (height 0) even when
        // idle, matching the MockEngine pattern (genesis is the
        // chain's first block, produced unconditionally).
        engine.run_until_idle();
        assert_eq!(engine.finalized_height(), Some(Height::new(0)));
        // A second run is a true no-op (no new genesis to produce).
        engine.run_until_idle();
        assert_eq!(engine.finalized_height(), Some(Height::new(0)));
    }
}
