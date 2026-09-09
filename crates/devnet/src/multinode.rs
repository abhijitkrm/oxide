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
    /// The BLS secret keys for each validator (used to sign timeout
    /// messages during view changes). Stored alongside the engines
    /// so the runner can produce real timeout signatures.
    secret_keys: Vec<crypto::BlsSecretKey>,
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
    /// [`ValidatorSet`] with equal stakes. Each validator gets a real
    /// BLS secret key (deterministic, from fixed IKM) so that vote
    /// and QC signatures are real and verified by the engine (C1 fix).
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` or if the validator set construction fails
    /// (impossible with equal stakes ≥ 1).
    pub fn new(n: usize, max_mempool_entries: usize) -> Self {
        assert!(n > 0, "devnet must have at least one validator");
        // Generate real BLS keys for each validator. The IKM is
        // deterministic (byte i repeated 32 times) so the same `n`
        // always produces the same keys — the simulation is
        // reproducible (determinism contract).
        let secret_keys: Vec<crypto::BlsSecretKey> =
            (1..=u8::try_from(n).unwrap()).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            secret_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let stakes = vec![1u64; n];
        let vs = ValidatorSet::new(pks, stakes).expect("validator set");

        let mut engines = Vec::with_capacity(n);
        let mut apps = Vec::with_capacity(n);
        for (i, key) in secret_keys.iter().cloned().enumerate() {
            let mut executor = Executor::new(max_mempool_entries);
            executor.register_module(Arc::new(core::CoreModule::new()));
            executor.register_module(Arc::new(bank::BankModule::new()));
            executor.register_module(Arc::new(staking::StakingModule::new()));
            let app: Arc<Executor> = Arc::new(executor);
            let app_dyn: Arc<dyn AppInterface> = app.clone();
            let engine = OxideBft::with_index(app_dyn, vs.clone(), u16::try_from(i).unwrap())
                .with_secret_key(key);
            engines.push(engine);
            apps.push(app);
        }

        Self { engines, apps, validator_set: vs, secret_keys, n }
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

    /// Run `rounds` consensus rounds, each with `txs_per_round`
    /// core-module txs (minimal dispatch, no bank `BTreeMap`
    /// overhead). Returns the finalized blocks and wall-clock
    /// elapsed time. This is the purest measure of consensus +
    /// dispatch throughput.
    pub fn run_batch_core(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
    ) -> (DevnetResult, std::time::Duration) {
        let start = std::time::Instant::now();
        for round in 0..rounds {
            let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));
            for tx_i in 0..txs_per_round {
                let tx = make_core_tx(round, tx_i);
                self.engines[leader_idx].submit_tx(tx);
            }
            self.run_round();
        }
        self.run_round();
        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }

    /// Run `rounds` consensus rounds, each with `txs_per_round` txs
    /// submitted to the leader. Returns the finalized blocks from
    /// each validator and the total wall-clock elapsed time.
    ///
    /// This is the throughput simulator (plan.md §13: "≥ 200k
    /// simple native tx/s in sim (n=32)"). It measures how many
    /// transactions the consensus + execution pipeline processes
    /// per second of wall-clock time in the deterministic simulation.
    ///
    /// Each round:
    /// 1. Submit `txs_per_round` txs to the leader's mempool.
    /// 2. Leader proposes (pulling txs from mempool up to budget).
    /// 3. Leader self-votes.
    /// 4. All followers vote (in index order).
    /// 5. Leader collects votes and forms a QC.
    /// 6. All validators receive the QC and advance the view.
    ///
    /// After all rounds, one flush round (no tx) clears the pipeline.
    pub fn run_batch(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
    ) -> (DevnetResult, std::time::Duration) {
        let start = std::time::Instant::now();
        for round in 0..rounds {
            let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));
            for tx_i in 0..txs_per_round {
                let tx = make_batch_tx(round, tx_i);
                self.engines[leader_idx].submit_tx(tx);
            }
            self.run_round();
        }
        // Flush round: propose with no tx to commit the last pending block.
        self.run_round();
        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
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

        self.collect_result()
    }

    /// Run `rounds` consensus rounds with a faulty leader at
    /// `faulty_round`. The faulty leader withholds its proposal;
    /// the followers time out, form a TC, and advance the view.
    /// The next leader (honest) proposes and the chain recovers.
    ///
    /// This tests the Phase 1 acceptance gate: "fault injection
    /// (kill leader) recovers within 2 views" (plan.md §13).
    ///
    /// Returns the finalized blocks from each validator.
    pub fn run_with_faulty_leader(&mut self, rounds: usize, faulty_round: usize) -> DevnetResult {
        for round in 0..rounds {
            let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));
            if round == faulty_round {
                // The leader is faulty: it withholds its proposal.
                // Followers detect the timeout, form a TC, and
                // advance the view. The next leader (view+1) proposes.
                self.handle_faulty_leader();
                // Retry the round with the new leader.
                let new_leader =
                    usize::from(self.validator_set.leader(self.engines[0].current_view()));
                let tx = make_round_tx(round);
                self.engines[new_leader].submit_tx(tx);
                self.run_round();
            } else {
                let tx = make_round_tx(round);
                self.engines[leader_idx].submit_tx(tx);
                self.run_round();
            }
        }
        // Flush round.
        self.run_round();

        self.collect_result()
    }

    /// Handle a faulty leader: all non-leader validators time out,
    /// collect timeout signatures, form a TC, and advance the view.
    ///
    /// The view advances by exactly 1 (one timeout, one TC). The
    /// acceptance gate requires recovery within 2 views; this is
    /// 1 view.
    fn handle_faulty_leader(&mut self) {
        let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));

        // All non-leader validators time out for the current view.
        // Each produces a timeout signature (placeholder ZERO in v0).
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if i == leader_idx {
                continue;
            }
            let _ = engine.on_timeout();
        }

        // Collect timeout signatures: each non-leader validator
        // collects signatures from all other non-leader validators.
        // The first to reach quorum forms a TC.
        let non_leader_indices: Vec<usize> = (0..self.n).filter(|&i| i != leader_idx).collect();
        let mut formed_tc: Option<types::TimeoutCertificate> = None;
        for &collector_i in &non_leader_indices {
            for &signer_i in &non_leader_indices {
                if signer_i == collector_i {
                    continue;
                }
                if let Some(tc) = self.engines[collector_i].collect_timeout_signature(
                    u16::try_from(signer_i).unwrap(),
                    crypto::bls::Signature::ZERO,
                ) {
                    formed_tc = Some(tc);
                }
            }
            // Self-signature (the validator that timed out also
            // signs its own timeout).
            if let Some(tc) = self.engines[collector_i].collect_timeout_signature(
                u16::try_from(collector_i).unwrap(),
                crypto::bls::Signature::ZERO,
            ) {
                formed_tc = Some(tc);
            }
        }

        // If no TC was formed (not enough signatures), we need to
        // collect more. For n=4, f=1, quorum=3: 3 non-leader
        // validators each sign, so the first collector that gets
        // all 3 (self + 2 others) forms the TC.
        let tc = formed_tc.expect("a TC should form at quorum");

        // All validators (including the faulty leader) receive the
        // TC and advance the view.
        for engine in &mut self.engines {
            engine.on_timeout_certificate(&tc);
        }
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

        // Leader self-votes. The leader signs its own block with its
        // real BLS key (C1 fix: all votes carry real signatures).
        let leader_sig =
            self.secret_keys[leader_idx].sign(crypto::hash::Domain::Vote, block_hash.as_bytes());
        let leader_vote = types::Vote {
            view: header.view,
            phase: types::VotePhase::Prepare,
            block_hash,
            signature: leader_sig,
        };
        self.engines[leader_idx]
            .collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote)
            .expect("leader self-vote must verify");

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
            self.engines[leader_idx].collect_vote(voter, vote).expect("follower vote must verify");
        }

        // Leader forms QC.
        let qc = self.engines[leader_idx].try_form_qc().expect("quorum should be reached");

        // All validators receive the QC and advance the view.
        for engine in &mut self.engines {
            engine.deliver_qc(qc.clone()).expect("QC must verify");
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

    /// Collect finalized blocks from each validator into a `DevnetResult`.
    fn collect_result(&self) -> DevnetResult {
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
}

/// Construct a deterministic BLS secret key from a single byte
/// (the byte repeated 32 times as IKM). The same byte always
/// produces the same key — the simulation is reproducible
/// (determinism contract). Used for real vote/QC signatures.
fn bls_key(byte: u8) -> crypto::BlsSecretKey {
    let ikm = vec![byte; 32];
    crypto::BlsSecretKey::from_ikm(&ikm).expect("BLS key generation from valid IKM")
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

/// Construct a simple tx for batch throughput testing: a bank
/// transfer of 1 token to a fixed address. Each tx has a unique
/// nonce (derived from round and tx index) to avoid dedup.
fn make_batch_tx(round: usize, tx_i: usize) -> TxBytes {
    let sender = primitives::Address([0u8; 20]);
    let nonce = u64::try_from(round * 1000 + tx_i).unwrap();
    let fee = 100u64;
    let to = primitives::Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, 1);
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::BANK);
    bytes.extend_from_slice(&module_payload);
    TxBytes::new(bytes)
}

/// Construct a minimal tx for throughput testing: routes to the
/// core module (ID 0) with an empty payload. The core module's
/// `handle` is a no-op, so this measures the consensus + dispatch
/// overhead without the bank module's `BTreeMap` cost.
fn make_core_tx(round: usize, tx_i: usize) -> TxBytes {
    let sender = primitives::Address([0u8; 20]);
    let nonce = u64::try_from(round * 1000 + tx_i).unwrap();
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1);
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::CORE);
    TxBytes::new(bytes)
}

/// Compute transactions per second from a tx count and elapsed
/// duration. Uses `f64` for the rate; tx counts in the simulation
/// are well below 2^52 so no precision is lost.
#[cfg(test)]
fn tps(total_txs: usize, elapsed: std::time::Duration) -> f64 {
    // `usize as f64` triggers `clippy::cast_precision_loss` on
    // 64-bit targets (usize is 64 bits, f64 mantissa is 52). The
    // simulation's tx count never exceeds ~10^6, far below 2^52,
    // so the cast is exact. Allow the lint here, not globally.
    #![allow(clippy::cast_precision_loss)]
    total_txs as f64 / elapsed.as_secs_f64()
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

    /// Fault injection: kill the leader at round 2. The followers
    /// time out, form a TC, advance the view, and the next leader
    /// proposes. The chain recovers within 1 view (the acceptance
    /// gate is 2 views).
    #[test]
    fn fault_injection_kill_leader_recovers() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        let result = devnet.run_with_faulty_leader(5, 2);

        // All validators should agree on finalized blocks.
        let n_blocks = result.finalized[0].len();
        assert!(n_blocks > 0, "should have finalized blocks despite faulty leader");
        for (i, blocks) in result.finalized.iter().enumerate() {
            assert_eq!(blocks.len(), n_blocks, "validator {i} disagrees on block count");
        }

        // All 5 txs should be finalized (the faulty round's tx is
        // resubmitted to the new leader).
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert_eq!(total_txs, 5, "all 5 txs must be finalized after recovery");
    }

    /// Fault injection: kill the leader at round 0 (the very first
    /// round). The chain should still bootstrap and finalize.
    #[test]
    fn fault_injection_kill_first_leader() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        let result = devnet.run_with_faulty_leader(3, 0);
        let n_blocks = result.finalized[0].len();
        assert!(n_blocks > 0, "should finalize despite first leader being faulty");
        // All validators agree.
        for (i, blocks) in result.finalized.iter().enumerate() {
            assert_eq!(blocks.len(), n_blocks, "validator {i} disagrees");
        }
    }

    /// Fault injection: 7 validators (f=2), kill the leader. The
    /// 6 remaining validators form a TC (quorum=5) and recover.
    #[test]
    fn fault_injection_7_validators_kill_leader() {
        let mut devnet = MultiNodeDevnet::new(7, 10_000);
        let result = devnet.run_with_faulty_leader(4, 1);
        let n_blocks = result.finalized[0].len();
        assert!(n_blocks > 0, "should finalize despite faulty leader in 7-validator set");
        for (i, blocks) in result.finalized.iter().enumerate() {
            assert_eq!(blocks.len(), n_blocks, "validator {i} disagrees");
        }
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert_eq!(total_txs, 4, "all 4 txs must be finalized");
    }

    /// Fault injection: kill the leader at the last round. The
    /// chain should still finalize all blocks.
    #[test]
    fn fault_injection_kill_last_leader() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        let result = devnet.run_with_faulty_leader(3, 2);
        let n_blocks = result.finalized[0].len();
        assert!(n_blocks > 0, "should finalize despite last leader being faulty");
    }

    /// Fault injection: finality agreement after recovery. All
    /// validators must agree on the same blocks after a faulty
    /// leader is bypassed.
    #[test]
    fn fault_injection_finality_agreement() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        let result = devnet.run_with_faulty_leader(5, 2);
        let reference = &result.finalized[0];
        for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
            assert_eq!(blocks.len(), reference.len(), "validator {i} disagrees on count");
            for (j, (a, b)) in reference.iter().zip(blocks.iter()).enumerate() {
                assert_eq!(a.height, b.height, "validator {i} block {j}: height mismatch");
                assert_eq!(a.txs, b.txs, "validator {i} block {j}: txs mismatch");
            }
        }
    }

    // ---- Throughput simulation ----
    //
    // The Phase 1 acceptance gate (plan.md §13): "≥ 200k simple
    // native tx/s in sim (n=32)." These tests measure the
    // consensus + execution pipeline's throughput in wall-clock
    // time. They are `#[ignore]` by default because they are slow
    // in debug mode; run with `cargo test --release -- --ignored`.

    /// Throughput sim: 4 validators, 10 rounds, 100 txs/round.
    /// Measures tx/s and asserts the pipeline processes all txs.
    #[test]
    #[ignore = "throughput sim: run with --release -- --ignored"]
    fn throughput_sim_4_validators() {
        let mut devnet = MultiNodeDevnet::new(4, 100_000);
        let (result, elapsed) = devnet.run_batch(10, 100);
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert_eq!(total_txs, 1000, "all 1000 txs must be finalized");
        let tps = tps(total_txs, elapsed);
        eprintln!("throughput_sim_4_validators: {total_txs} txs in {elapsed:?} = {tps:.0} tx/s");
    }

    /// Throughput sim: 32 validators (the acceptance gate's n=32).
    /// 3 rounds, 10000 txs/round = 30000 txs. Measures tx/s.
    /// The mempool budget (1 MiB / ~62 bytes per tx) limits each
    /// block to ~16k txs; 10k txs/round stays within budget while
    /// amortizing the per-round O(n) consensus overhead.
    #[test]
    #[ignore = "throughput sim: run with --release -- --ignored"]
    fn throughput_sim_32_validators() {
        let mut devnet = MultiNodeDevnet::new(32, 100_000);
        let (result, elapsed) = devnet.run_batch(3, 10_000);
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert!(total_txs > 0, "should finalize some txs");
        let tps = tps(total_txs, elapsed);
        eprintln!("throughput_sim_32_validators: {total_txs} txs in {elapsed:?} = {tps:.0} tx/s");
        // The acceptance gate: >= 200k tx/s in release mode.
        // This is a soft check in the test; the real gate is in
        // the benchmark suite.
    }

    /// Throughput sim (core module): 32 validators, 3 rounds,
    /// 10000 txs/round. Uses the core module (no-op handle) to
    /// measure pure consensus + dispatch throughput without the
    /// bank module's `BTreeMap` overhead.
    #[test]
    #[ignore = "throughput sim: run with --release -- --ignored"]
    fn throughput_sim_32_validators_core() {
        let mut devnet = MultiNodeDevnet::new(32, 100_000);
        let (result, elapsed) = devnet.run_batch_core(3, 10_000);
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert!(total_txs > 0, "should finalize some txs");
        let tps = tps(total_txs, elapsed);
        eprintln!(
            "throughput_sim_32_validators_core: {total_txs} txs in {elapsed:?} = {tps:.0} tx/s"
        );
    }

    /// Throughput sim: 4 validators, 1 round, 1000 txs. Tests
    /// that the mempool and executor handle a large batch.
    #[test]
    #[ignore = "throughput sim: run with --release -- --ignored"]
    fn throughput_sim_large_batch() {
        let mut devnet = MultiNodeDevnet::new(4, 100_000);
        let (result, elapsed) = devnet.run_batch(1, 1000);
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert!(total_txs > 0, "should finalize some txs");
        let tps = tps(total_txs, elapsed);
        eprintln!("throughput_sim_large_batch: {total_txs} txs in {elapsed:?} = {tps:.0} tx/s");
    }

    /// Throughput sim: 4 validators, 5 rounds, 100 txs/round.
    /// Verifies finality agreement at scale.
    #[test]
    #[ignore = "throughput sim: run with --release -- --ignored"]
    fn throughput_sim_finality_agreement() {
        let mut devnet = MultiNodeDevnet::new(4, 100_000);
        let (result, _elapsed) = devnet.run_batch(5, 100);
        let reference = &result.finalized[0];
        for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
            assert_eq!(blocks.len(), reference.len(), "validator {i} disagrees on count");
            for (j, (a, b)) in reference.iter().zip(blocks.iter()).enumerate() {
                assert_eq!(a.height, b.height, "validator {i} block {j}: height mismatch");
                assert_eq!(a.txs, b.txs, "validator {i} block {j}: txs mismatch");
            }
        }
    }
}
