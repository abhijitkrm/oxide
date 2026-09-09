//! Multi-node devnet runner — N validators with oxideBFT and the
//! real application stack (executor + modules).
//!
//! # What this is
//!
//! The Phase 1 acceptance gate (plan.md §13): "4–50 node local devnet
//! sustains 50–100ms blocks on oxideBFT." This module assembles N
//! validator nodes, each with its own [`Executor`] + core/bank/staking
//! modules behind an [`OxideBft`] engine, and drives them through the
//! consensus round loop.
//!
//! # Why direct-call, not Transport
//!
//! The [`OxideBft`] engine does not yet have an I/O loop that consumes
//! a [`Transport`](ports::Transport). The engine is driven step-by-step
//! (propose → vote → QC → advance), which is exactly what the
//! deterministic simulation in the consensus tests does. This module
//! generalizes that pattern to the real app stack. When the engine
//! gets a Transport-based I/O loop (Phase 2), this runner will swap
//! the direct calls for `MeshTransport` message routing — same
//! consensus logic, different delivery mechanism.
//!
//! # Determinism
//!
//! The round loop is deterministic: messages are delivered in a fixed
//! order (leader first, then followers 0, 1, 2, ...). Two runs with
//! the same inputs produce identical finalized block sequences. This
//! matches the consensus crate's simulation determinism contract.

use std::sync::Arc;

use consensus::{OxideBft, ValidatorSet};
use executor::Executor;
use ports::{AppInterface, ConsensusEngine};
use types::{FinalizedBlock, TxBytes};

/// A multi-node devnet: N validators running oxideBFT with the real
/// app stack.
///
/// Each validator has its own [`Executor`] (with core/bank/staking
/// modules) and its own [`OxideBft`] engine. The engines share a
/// single [`ValidatorSet`]. The round loop drives all engines in a
/// deterministic order.
pub struct MultiNodeDevnet {
    /// One engine per validator.
    engines: Vec<OxideBft>,
    /// One executor per validator (kept for post-run inspection).
    apps: Vec<Arc<Executor>>,
    /// The shared validator set.
    validator_set: ValidatorSet,
    /// The number of validators.
    n: usize,
}

/// The result of running a multi-node devnet: the finalized blocks
/// from each validator.
#[derive(Debug, Clone)]
pub struct DevnetResult {
    /// Finalized blocks per validator.
    pub finalized: Vec<Vec<FinalizedBlock>>,
}

impl MultiNodeDevnet {
    /// Assemble a multi-node devnet with `n` validators.
    ///
    /// Each validator gets a fresh [`Executor`] with core, bank, and
    /// staking modules registered. The engines share a single
    /// [`ValidatorSet`] with equal stakes.
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` or if the validator set construction fails
    /// (impossible with equal stakes ≥ 1).
    pub fn new(n: usize, max_mempool_entries: usize) -> Self {
        assert!(n > 0, "devnet must have at least one validator");
        let pks: Vec<crypto::bls::PublicKey> = (1..=u8::try_from(n).unwrap()).map(pk).collect();
        let stakes = vec![1u64; n];
        let vs = ValidatorSet::new(pks, stakes).expect("validator set");

        let mut engines = Vec::with_capacity(n);
        let mut apps = Vec::with_capacity(n);
        for i in 0..n {
            let mut executor = Executor::new(max_mempool_entries);
            executor.register_module(Arc::new(core::CoreModule::new()));
            executor.register_module(Arc::new(bank::BankModule::new()));
            executor.register_module(Arc::new(staking::StakingModule::new()));
            let app: Arc<Executor> = Arc::new(executor);
            let app_dyn: Arc<dyn AppInterface> = app.clone();
            let engine = OxideBft::with_index(app_dyn, vs.clone(), u16::try_from(i).unwrap());
            engines.push(engine);
            apps.push(app);
        }

        Self { engines, apps, validator_set: vs, n }
    }

    /// The number of validators.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Access the executor for validator `i` (for post-run inspection).
    ///
    /// # Panics
    ///
    /// Panics if `i >= n`.
    pub fn app(&self, i: usize) -> &Executor {
        assert!(i < self.n, "validator index {i} out of range");
        &self.apps[i]
    }

    /// Run `rounds` consensus rounds, each with one tx submitted to
    /// the leader. Returns the finalized blocks from each validator.
    ///
    /// Each round:
    /// 1. Submit a tx to the leader's mempool.
    /// 2. Leader proposes.
    /// 3. Leader self-votes.
    /// 4. All followers vote (in index order).
    /// 5. Leader collects votes and forms a QC.
    /// 6. All validators receive the QC and advance the view.
    ///
    /// After all rounds, one flush round (no tx) clears the pipeline.
    pub fn run(&mut self, rounds: usize) -> DevnetResult {
        for round in 0..rounds {
            let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));
            let tx = make_round_tx(round);
            self.engines[leader_idx].submit_tx(tx);
            self.run_round();
        }
        // Flush round: propose with no tx to commit the last pending block.
        self.run_round();

        // Collect finalized blocks from each validator.
        let finalized = self
            .engines
            .iter()
            .map(|e| {
                let h = e.finalized_height().map_or(0, primitives::Id::value);
                (0..=h)
                    .filter_map(|i| e.finalized_block(primitives::Height::new(i)))
                    .collect::<Vec<_>>()
            })
            .collect();
        DevnetResult { finalized }
    }

    /// Run one consensus round: propose → vote → QC → advance.
    ///
    /// This is the deterministic message-delivery loop. The order is
    /// fixed: leader proposes, leader self-votes, followers vote in
    /// index order, leader forms QC, all deliver QC and advance.
    fn run_round(&mut self) {
        let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));

        // Leader proposes.
        let (header, proposal) = self.engines[leader_idx]
            .propose()
            .unwrap_or_else(|| panic!("leader {leader_idx} should propose"));
        let block_hash = OxideBft::block_hash(&header);

        // Leader self-votes.
        let leader_vote = types::Vote {
            view: header.view,
            phase: types::VotePhase::Prepare,
            block_hash,
            signature: crypto::bls::Signature::ZERO,
        };
        self.engines[leader_idx].collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote);

        // Followers vote in index order (deterministic).
        let mut follower_votes = Vec::new();
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if i == leader_idx {
                continue;
            }
            if let Some(vote) = engine.vote(&header, &proposal) {
                follower_votes.push((u16::try_from(i).unwrap(), vote));
            }
        }
        for (voter, vote) in follower_votes {
            self.engines[leader_idx].collect_vote(voter, vote);
        }

        // Leader forms QC.
        let qc = self.engines[leader_idx].try_form_qc().expect("quorum should be reached");

        // All validators receive the QC and advance the view.
        for engine in &mut self.engines {
            engine.deliver_qc(qc.clone());
        }
        for engine in &mut self.engines {
            engine.advance_view();
        }

        // Sync next_height across all engines (the simulation
        // equivalent of broadcast delivery).
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
        }
    }
}

/// Construct a test public key from a single byte (deterministic,
/// non-cryptographic — for simulation only).
fn pk(byte: u8) -> crypto::bls::PublicKey {
    crypto::bls::PublicKey([byte; crypto::bls::PublicKey::LEN])
}

/// Construct a simple tx for round `r`: a bank transfer of `r+1`
/// tokens to a fixed address. Uses the mempool's v0 format.
fn make_round_tx(round: usize) -> TxBytes {
    let sender = primitives::Address([0u8; 20]);
    let nonce = u64::try_from(round).unwrap();
    let fee = 100u64;
    let to = primitives::Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, u64::try_from(round).unwrap_or(0) + 1);
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::BANK);
    bytes.extend_from_slice(&module_payload);
    TxBytes::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 4 validators, 5 rounds: all txs must be finalized.
    #[test]
    fn multinode_4_validators_liveness() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        let result = devnet.run(5);
        let n_blocks = result.finalized[0].len();
        assert!(n_blocks > 0, "should have finalized blocks");
        // All validators agree on block count.
        for (i, blocks) in result.finalized.iter().enumerate() {
            assert_eq!(
                blocks.len(),
                n_blocks,
                "validator {i} has {n_blocks} blocks expected, got {}",
                blocks.len()
            );
        }
        // All 5 txs should be present.
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert_eq!(total_txs, 5, "all 5 txs must be finalized");
    }

    /// All validators must agree on the same finalized blocks.
    #[test]
    fn multinode_4_validators_finality_agreement() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        let result = devnet.run(5);
        let reference = &result.finalized[0];
        for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
            assert_eq!(blocks.len(), reference.len(), "validator {i} disagrees on block count");
            for (j, (a, b)) in reference.iter().zip(blocks.iter()).enumerate() {
                assert_eq!(a.height, b.height, "validator {i} disagrees on height at block {j}");
                assert_eq!(a.txs, b.txs, "validator {i} disagrees on txs at block {j}");
            }
        }
    }

    /// Two runs with identical inputs must produce identical outputs.
    #[test]
    fn multinode_deterministic_across_runs() {
        let run1 = MultiNodeDevnet::new(4, 10_000).run(5);
        let run2 = MultiNodeDevnet::new(4, 10_000).run(5);
        assert_eq!(run1.finalized.len(), run2.finalized.len());
        for (i, (a, b)) in run1.finalized.iter().zip(run2.finalized.iter()).enumerate() {
            assert_eq!(a.len(), b.len(), "validator {i}: different block count");
            for (j, (ba, bb)) in a.iter().zip(b.iter()).enumerate() {
                assert_eq!(ba.height, bb.height, "validator {i} block {j}: height mismatch");
                assert_eq!(ba.txs, bb.txs, "validator {i} block {j}: txs mismatch");
            }
        }
    }

    /// 7 validators (f=2, quorum=5): 3 rounds with txs.
    #[test]
    fn multinode_7_validators_liveness() {
        let mut devnet = MultiNodeDevnet::new(7, 10_000);
        let result = devnet.run(3);
        let n_blocks = result.finalized[0].len();
        assert!(n_blocks > 0, "should have finalized blocks");
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert_eq!(total_txs, 3, "all 3 txs must be finalized");
    }

    /// The bank module should have processed transfers: the state
    /// root should be non-zero after running.
    #[test]
    fn multinode_bank_module_executes() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        devnet.run(3);
        // Check that the executor has a non-zero state root at height 0.
        let root = devnet.app(0).attest_state(primitives::Height::new(0));
        assert_ne!(root.root, primitives::Hash::ZERO, "state root should be non-zero");
    }

    /// Single validator (quorum=1): should still finalize blocks.
    #[test]
    fn multinode_single_validator() {
        let mut devnet = MultiNodeDevnet::new(1, 10_000);
        let result = devnet.run(3);
        assert!(!result.finalized[0].is_empty(), "single validator should finalize");
    }
}
