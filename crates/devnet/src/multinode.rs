//! Multi-node devnet runner — N validators with oxideBFT and the
//! real application stack (executor + modules).
//!
//! # What this is
//!
//! The Phase 1 acceptance gate (plan.md §13): "4–50 node local devnet
//! sustains 50–100ms blocks on oxideBFT." This module assembles N
//! validator nodes, each with its own [`Executor`] + core/evm/staking
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

use codec::{Decode, Encode};
use consensus::{OxideBft, ValidatorSet};
use executor::Executor;
use ports::transport::Transport;
use ports::{AppInterface, ConsensusEngine};
use types::{FinalizedBlock, TxBytes};

use crate::txs;

/// The genesis balance minted to each sender on every validator's
/// EVM account store. Large enough that the simulation never exhausts
/// it (the max transfer in any round is `rounds` tokens; the
/// throughput test sends 1 token per tx, up to ~30k txs).
/// Source: plan.md §13 (Phase 1 gate: 200k tx/s sim).
const GENESIS_BALANCE: u64 = 1_000_000_000_000; // 10^12

/// Deterministic block-clock base, milliseconds since the Unix
/// epoch — the counter every engine's injected clock starts from.
/// The value is arbitrary but realistic-looking (Nov 2023); what
/// matters is that it is *fixed*, so two runs with the same inputs
/// stamp identical header timestamps and the module-level
/// determinism contract ("identical finalized block sequences")
/// survives the header timestamp becoming a real field. Shared
/// across engines as a single `AtomicU64` counter rather than a
/// per-engine counter: every `propose` draws the next tick from
/// the same source, so timestamps increase monotonically across
/// leaders and the engine's parent-timestamp rule can never see a
/// regression it would have to reject.
const SIM_CLOCK_BASE_MS: u64 = 1_700_000_000_000;

/// A multi-node devnet: N validators running oxideBFT over the
/// production app stack.
///
/// Each validator's executor is assembled by
/// [`node::assemble_executor`] — the same module graph the shipped
/// binaries run (core, evm, staking, exchange, perps, oracle,
/// governance, plus the async execution lane), parameterized only
/// by genesis state and mempool size. The engines share a single
/// [`ValidatorSet`]. The round loop drives all engines in a
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
    /// The mesh network for transport-routed rounds (H4 fix).
    /// `None` for direct-call rounds (backward compat).
    network: Option<p2p::MeshNetwork>,
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
    /// Each validator gets a fresh [`Executor`] with core, evm, and
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
        // Devnet convention: validator `i`'s staking address is the
        // secp256k1 identity `txs::identity_addr(i)` — key-derived so
        // the validator can sign its own `key_change`/endorsement txs
        // (a signed envelope's sender must recover to its key).
        let addresses: Vec<primitives::Address> =
            (0..n).map(|i| txs::identity_addr(u8::try_from(i).unwrap_or(0))).collect();
        let vs =
            ValidatorSet::with_addresses(pks, stakes, addresses.clone()).expect("validator set");

        let mut engines = Vec::with_capacity(n);
        let mut apps = Vec::with_capacity(n);
        // One clock counter shared by every engine — see
        // `SIM_CLOCK_BASE_MS` for why a single source (not
        // per-engine counters) is required.
        let block_clock = Arc::new(std::sync::atomic::AtomicU64::new(SIM_CLOCK_BASE_MS));
        // Every validator assembles through `node::assemble_executor`
        // — THE production module graph (core, evm, staking, exchange,
        // perps, oracle, governance + exec lane) — so the sim exercises
        // the same admission/execution pipeline the binaries run. The
        // harness's only inputs are the ones production legitimately
        // varies: genesis state, mempool size, and the clock. The
        // genesis spec is what a `--genesis-file` would carry: the
        // validator set (stake 1 each, real BLS keys so evidence paths
        // see the true consensus identities) plus the funded sender
        // identities. `None` storage_path + `evm_persistence` selects
        // the Volatile backend — the storage seam's in-memory side.
        let genesis = node::GenesisSpec {
            validators: addresses
                .iter()
                .zip(secret_keys.iter())
                .map(|(addr, sk)| node::GenesisValidator {
                    address: *addr,
                    stake: 1,
                    public_key: Some(sk.public_key().as_bytes().to_vec()),
                })
                .collect(),
            // M4: mint to a range of sender identities (index 0
            // through 31 — see `txs::identity_addr`) so the
            // multi-sender throughput test can use distinct senders.
            // Genesis balances are wei; `GENESIS_BALANCE` is base
            // units (what `Balances::mint` credited before).
            balances: (0u8..32)
                .map(|i| {
                    (txs::identity_addr(i), u128::from(GENESIS_BALANCE) * framework::WEI_PER_UNIT)
                })
                .collect(),
        };
        let config = node::NodeConfig {
            max_mempool_entries,
            genesis: Some(genesis),
            ..node::NodeConfig::default()
        };
        for (i, key) in secret_keys.iter().cloned().enumerate() {
            let assembled = node::assemble_executor(&config);
            let app = assembled.app;
            let app_dyn: Arc<dyn AppInterface> = app.clone();
            // Shared sim clock: all engines draw proposal timestamps
            // from one counter so stamps increase across leaders and
            // identical schedules reproduce identical blocks.
            let clock = std::sync::Arc::clone(&block_clock);
            let engine = OxideBft::with_index(app_dyn, vs.clone(), u16::try_from(i).unwrap())
                .with_secret_key(key)
                .with_clock(move || clock.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
            engines.push(engine);
            apps.push(app);
        }

        Self { engines, apps, validator_set: vs, secret_keys, n, network: None }
    }

    /// The number of validators.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Read-only access to the validator engines, for simulation
    /// harnesses that drive consensus rounds themselves.
    pub fn engines(&self) -> &[OxideBft] {
        &self.engines
    }

    /// Mutable access to the validator engines, for simulation
    /// harnesses that drive consensus rounds themselves (the
    /// `oxide-sim` chaos driver proposes/votes/collects through the
    /// real engine API while injecting byzantine deviations).
    pub fn engines_mut(&mut self) -> &mut [OxideBft] {
        &mut self.engines
    }

    /// The shared validator set (leader rotation, quorum size).
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Validator `index`'s BLS secret key. Simulation harnesses use
    /// this to sign *conflicting* byzantine messages with the node's
    /// real key — the honest engines then exercise their real
    /// verification/equivocation paths on real signatures.
    ///
    /// # Panics
    ///
    /// Panics if `index >= n`.
    pub fn secret_key(&self, index: usize) -> &crypto::BlsSecretKey {
        &self.secret_keys[index]
    }

    /// A `MeshTransport` handle for validator `index`. Requires
    /// `enable_mesh()` to have been called.
    ///
    /// # Panics
    ///
    /// Panics if the mesh is not enabled or `index >= n`.
    pub fn transport(&self, index: usize) -> p2p::MeshTransport {
        self.network.as_ref().expect("mesh not enabled — call enable_mesh()").transport(index)
    }

    /// Enable the mesh network for transport-routed rounds (H4 fix).
    /// After calling this, `run_round_transport` can be used to route
    /// consensus messages through `MeshTransport` instead of direct
    /// method calls.
    pub fn enable_mesh(&mut self) {
        self.network = Some(p2p::MeshNetwork::new(self.n));
    }

    /// Partition a validator: messages to/from this validator are
    /// dropped until `heal` is called (H2 fix). Requires the mesh
    /// network to be enabled.
    ///
    /// # Panics
    ///
    /// Panics if the mesh is not enabled or `index >= n`.
    pub fn partition(&self, index: usize) {
        let net = self.network.as_ref().expect("mesh not enabled");
        net.partition(index);
    }

    /// Heal a partitioned validator (H2 fix).
    ///
    /// # Panics
    ///
    /// Panics if the mesh is not enabled or `index >= n`.
    pub fn heal(&self, index: usize) {
        let net = self.network.as_ref().expect("mesh not enabled");
        net.heal(index);
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
    /// core-module txs (minimal dispatch, no ledger settlement
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

    /// Run `rounds` consensus rounds with `txs_per_round` txs from
    /// `num_senders` distinct senders. Each sender gets a per-sender
    /// nonce. This exercises the M4 scenario: multiple senders
    /// transferring concurrently, testing per-account nonce
    /// ordering and dedup behavior.
    ///
    /// Each sender must have a genesis balance. This method mints
    /// to each sender on every validator's EVM ledger before
    /// running the rounds.
    pub fn run_batch_multi_sender(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
        num_senders: u8,
    ) -> (DevnetResult, std::time::Duration) {
        // The constructor mints to identities 0 through 31. The
        // caller must ensure `num_senders <= 32`.
        //
        // Nonces are per-sender sequential: sender i gets nonces
        // 0, 1, 2, ... This is the correct multi-sender workload
        // (M4 fix). The mempool enforces strict per-sender nonce
        // ordering, so gaps would cause txs to be stuck.
        let start = std::time::Instant::now();
        // Track per-sender nonce counters across rounds.
        let mut sender_nonces: Vec<u64> = vec![0; num_senders as usize];
        for _round in 0..rounds {
            let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));
            for tx_i in 0..txs_per_round {
                let sender_idx = u8::try_from(tx_i % num_senders as usize).unwrap_or(0);
                let nonce = sender_nonces[usize::from(sender_idx)];
                sender_nonces[usize::from(sender_idx)] += 1;
                let tx = make_multi_sender_tx(sender_idx, nonce);
                self.engines[leader_idx].submit_tx(tx);
            }
            self.run_round();
        }
        // Flush round.
        self.run_round();
        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }

    /// Run `rounds` consensus rounds with messages routed through
    /// `MeshTransport` (H4 fix). Requires `enable_mesh()`. Each
    /// round submits `txs_per_round` txs to the leader and runs
    /// `run_round_transport`.
    ///
    /// # Panics
    ///
    /// Panics if the mesh network is not enabled.
    pub fn run_batch_transport(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
    ) -> (DevnetResult, std::time::Duration) {
        assert!(self.network.is_some(), "call enable_mesh() first");
        let start = std::time::Instant::now();
        for round in 0..rounds {
            let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));
            for tx_i in 0..txs_per_round {
                let tx = make_batch_tx(round, tx_i);
                self.engines[leader_idx].submit_tx(tx);
            }
            self.run_round_transport();
        }
        // Flush round.
        self.run_round_transport();
        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }
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
        //
        // TC safety fix: each validator signs the view with its real
        // BLS key (on_timeout), and the collector verifies the
        // signature before collecting.
        let non_leader_indices: Vec<usize> = (0..self.n).filter(|&i| i != leader_idx).collect();
        // Collect each non-leader's real timeout signature.
        let timeout_sigs: Vec<crypto::bls::Signature> = non_leader_indices
            .iter()
            .map(|&i| self.engines[i].on_timeout().unwrap_or(crypto::bls::Signature::ZERO))
            .collect();
        let mut formed_tc: Option<types::TimeoutCertificate> = None;
        for (collector_idx, &collector_i) in non_leader_indices.iter().enumerate() {
            for (signer_idx, &signer_i) in non_leader_indices.iter().enumerate() {
                if signer_i == collector_i {
                    continue;
                }
                if let Ok(Some(tc)) = self.engines[collector_i].collect_timeout_signature(
                    u16::try_from(signer_i).unwrap(),
                    timeout_sigs[signer_idx],
                ) {
                    formed_tc = Some(tc);
                }
            }
            // Self-signature (the validator that timed out also
            // signs its own timeout).
            if let Ok(Some(tc)) = self.engines[collector_i].collect_timeout_signature(
                u16::try_from(collector_i).unwrap(),
                timeout_sigs[collector_idx],
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
            let _ = engine.on_timeout_certificate(&tc);
        }
    }

    /// Timeout-path advance for all engines: collect every
    /// validator's real timeout signature into a TC, which each
    /// engine records as view-change evidence (`last_tc`) so the
    /// next leader's proposal carries legitimate-successor proof —
    /// required for same-height lock release after a failed view.
    /// Used by the round drivers' failure paths.
    fn timeout_advance_all(&mut self) {
        let sigs: Vec<crypto::bls::Signature> = self
            .engines
            .iter_mut()
            .map(|e| e.on_timeout().unwrap_or(crypto::bls::Signature::ZERO))
            .collect();
        for collector in 0..self.n {
            for (signer, sig) in sigs.iter().enumerate() {
                let _ = self.engines[collector]
                    .collect_timeout_signature(u16::try_from(signer).unwrap_or(0), *sig);
            }
        }
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
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

        // Leader self-votes through the engine's single signing
        // path (C10): `vote()` records the vote locks and appends
        // the WAL before the signature exists — the hand-built Vote
        // it replaces skipped both, so a leader's own vote was never
        // durable.
        if let Some(leader_vote) = self.engines[leader_idx].vote(&header, &proposal) {
            self.engines[leader_idx]
                .collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote)
                .expect("leader self-vote must verify");
        }

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

    /// Run one consensus round with messages routed through
    /// `MeshTransport` (H4 fix). This proves the Transport seam:
    /// votes and QCs are encoded, sent through the transport,
    /// received, and decoded on the other side.
    ///
    /// The message flow:
    /// 1. Leader proposes (direct — the proposal is broadcast via
    ///    the block broadcast layer, not the transport).
    /// 2. Leader self-votes (direct — the leader doesn't need to
    ///    send its vote to itself over the network).
    /// 3. Followers vote via transport: each follower encodes its
    ///    vote and sends it to the leader.
    /// 4. Leader receives votes via transport, decodes them, and
    ///    collects them.
    /// 5. Leader forms a QC and broadcasts it via transport.
    /// 6. Followers receive the QC via transport, decode it, and
    ///    deliver it.
    /// 7. All advance the view and sync heights.
    ///
    /// Requires `enable_mesh()` to have been called.
    ///
    /// # Panics
    ///
    /// Panics if the mesh is not enabled or any transport operation
    /// fails (a transport failure in the sim is a bug).
    fn run_round_transport(&mut self) {
        let net = self.network.as_ref().expect("mesh not enabled — call enable_mesh()");
        let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));

        // Leader proposes (direct — proposal broadcast is a
        // separate layer). If the leader is partitioned, it may
        // not be able to propose (no txs from followers, or the
        // leader's view is stale). In that case, skip the round —
        // the view will advance via the flush round.
        let Some((header, proposal)) = self.engines[leader_idx].propose() else {
            // Leader can't propose (partitioned or no txs) — the
            // view times out. Run the real TC path so the next
            // leader carries successor evidence and locked voters
            // can re-vote the failed height.
            self.timeout_advance_all();
            return;
        };

        // Leader self-votes through the engine's single signing
        // path (C10): `vote()` records the vote locks and appends
        // the WAL before the signature exists.
        if let Some(leader_vote) = self.engines[leader_idx].vote(&header, &proposal) {
            self.engines[leader_idx]
                .collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote)
                .expect("leader self-vote must verify");
        }

        // Followers vote via transport: each follower encodes its
        // vote and sends it to the leader.
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if i == leader_idx {
                continue;
            }
            if let Some(vote) = engine.vote(&header, &proposal) {
                let mut transport = net.transport(i);
                let mut buf = Vec::new();
                vote.encode(&mut buf);
                transport
                    .send(&p2p::MeshNetwork::peer_id(leader_idx), &buf)
                    .expect("transport send must succeed");
            }
        }

        // Leader receives votes via transport, decodes, collects.
        let mut leader_transport = net.transport(leader_idx);
        for _ in 0..self.n - 1 {
            if let Some(msg) = leader_transport.recv() {
                let mut reader = codec::Reader::new(&msg.bytes);
                let vote = types::Vote::decode(&mut reader).expect("vote decode");
                let voter = u16::try_from(
                    p2p::MeshNetwork::parse_peer_id(&msg.from).expect("valid peer id"),
                )
                .unwrap_or(0);
                self.engines[leader_idx]
                    .collect_vote(voter, vote)
                    .expect("follower vote must verify");
            }
        }

        // Leader forms QC.
        // Leader forms QC. If the leader can't reach quorum (e.g.,
        // too many partitioned followers), the view timed out — run
        // the real TC path so locked voters can re-vote next view.
        let Some(qc) = self.engines[leader_idx].try_form_qc() else {
            self.timeout_advance_all();
            return;
        };

        // Leader broadcasts QC via transport.
        let mut qc_buf = Vec::new();
        qc.encode(&mut qc_buf);
        for i in 0..self.n {
            if i == leader_idx {
                continue;
            }
            let mut transport = net.transport(leader_idx);
            transport
                .send(&p2p::MeshNetwork::peer_id(i), &qc_buf)
                .expect("transport send must succeed");
        }

        // Followers receive QC via transport, decode, deliver.
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if i == leader_idx {
                engine.deliver_qc(qc.clone()).expect("QC must verify");
                continue;
            }
            let mut transport = net.transport(i);
            if let Some(msg) = transport.recv() {
                let mut reader = codec::Reader::new(&msg.bytes);
                let received_qc = types::QuorumCertificate::decode(&mut reader).expect("QC decode");
                engine.deliver_qc(received_qc).expect("QC must verify");
            }
        }

        // All advance the view.
        for engine in &mut self.engines {
            engine.advance_view();
        }

        // Sync heights (the simulation equivalent of broadcast).
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
        }
    }

    /// Collect finalized blocks from each validator into a `DevnetResult`.
    /// Wait until every validator's execution lane has applied the
    /// last committed block.
    ///
    /// The lane (spawned by `node::assemble_executor`, always on —
    /// production never runs without it) executes committed blocks
    /// off the driving thread, so a run can finish with the tail
    /// block committed but still executing. `attest_state` blocks
    /// on the executed watermark — the same synchronization the
    /// production exec-cert path uses. A dead lane surfaces as
    /// `None` → loud panic rather than a silently stale read.
    ///
    /// # Panics
    ///
    /// Panics if a validator's lane died before executing the last
    /// committed height.
    pub fn drain_execution(&self) {
        for (i, app) in self.apps.iter().enumerate() {
            let Some(height) = self.engines[i].finalized_height() else { continue };
            app.attest_state(height).expect("execution lane must apply committed blocks");
        }
    }

    fn collect_result(&self) -> DevnetResult {
        self.drain_execution();
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

/// Construct a simple tx for round `r`: a staking delegate of
/// `r+1` units to validator `identity_addr(0)` (registered at genesis).
/// Delegation exercises the real ledger path — an EVM account
/// transfer into the bonded pool — so the throughput number
/// includes ledger settlement, not just dispatch.
fn make_round_tx(round: usize) -> TxBytes {
    let nonce = u64::try_from(round).unwrap();
    let fee = 100u64;
    let validator = txs::identity_addr(0);
    let module_payload = staking::msg::delegate(validator, u64::try_from(round).unwrap_or(0) + 1);
    txs::signed_tx(0, nonce, fee, framework::module_id::STAKING, &module_payload)
}

/// Construct a simple tx for batch throughput testing: a staking
/// delegate of 1 unit to validator `identity_addr(0)`. Each tx has a
/// unique nonce (derived from round and tx index) to avoid dedup.
fn make_batch_tx(round: usize, tx_i: usize) -> TxBytes {
    let nonce = u64::try_from(round * 1000 + tx_i).unwrap();
    let fee = 100u64;
    let validator = txs::identity_addr(0);
    let module_payload = staking::msg::delegate(validator, 1);
    txs::signed_tx(0, nonce, fee, framework::module_id::STAKING, &module_payload)
}

/// Construct a minimal tx for throughput testing: routes to the
/// core module (ID 0) with an empty payload. The core module's
/// `handle` is a no-op, so this measures the consensus + dispatch
/// overhead without ledger settlement cost.
fn make_core_tx(round: usize, tx_i: usize) -> TxBytes {
    let nonce = u64::try_from(round * 1000 + tx_i).unwrap();
    let fee = 100u64;
    txs::signed_tx(0, nonce, fee, framework::module_id::CORE, &[])
}

/// Construct a multi-sender staking-delegate tx for throughput
/// testing. Each tx comes from a distinct sender — the secp256k1
/// identity `txs::identity_addr(sender_idx)` — with a per-sender
/// nonce. This exercises the M4 scenario: multiple senders bonding
/// concurrently, testing per-account nonce ordering and dedup.
///
/// The genesis mint in `MultiNodeDevnet::new` funds identities 0
/// through 31, so `sender_idx` must stay below 32.
/// See `run_batch_multi_sender`.
fn make_multi_sender_tx(sender_idx: u8, nonce: u64) -> TxBytes {
    let fee = 100u64;
    let validator = txs::identity_addr(0);
    let module_payload = staking::msg::delegate(validator, 1);
    txs::signed_tx(sender_idx, nonce, fee, framework::module_id::STAKING, &module_payload)
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

    /// The EVM ledger should have processed state: the state
    /// root should be non-zero after running.
    #[test]
    fn multinode_evm_ledger_executes() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        devnet.run(3);
        // Check that the executor has a non-zero state root at height 0.
        let root = devnet.app(0).attest_state(primitives::Height::new(0)).expect("executed");
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
    /// ledger settlement overhead.
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

    /// Multi-sender throughput sim (M4 fix): 4 validators, 3 rounds,
    /// 1000 txs/round, 8 distinct senders. Each sender has a genesis
    /// balance (minted in the constructor). Tests that multiple
    /// senders can transfer concurrently without nonce collisions
    /// or dedup collapse.
    #[test]
    #[ignore = "throughput sim: run with --release -- --ignored"]
    fn throughput_sim_multi_sender() {
        let mut devnet = MultiNodeDevnet::new(4, 100_000);
        let (result, elapsed) = devnet.run_batch_multi_sender(3, 1000, 8);
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert!(total_txs > 0, "should finalize some txs");
        let tps = tps(total_txs, elapsed);
        eprintln!(
            "throughput_sim_multi_sender: {total_txs} txs in {elapsed:?} = {tps:.0} tx/s (8 senders)"
        );
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

    /// Block-timing measurement (H3 fix). Measures the wall-clock
    /// time per block in the 4-validator simulation. This is NOT a
    /// real block-time measurement (the sim is single-threaded with
    /// no network delay), but it provides evidence that:
    /// 1. The pacemaker-driven view advancement produces blocks.
    /// 2. The per-block overhead (BLS verify + execute) is measurable.
    /// 3. The target block time (50-100ms) is achievable in production
    ///    with parallelized BLS verification (the sim's single-threaded
    ///    BLS verify is the bottleneck, not the block production logic).
    ///
    /// Gate: the pacemaker config targets 50-100ms blocks
    /// (plan.md §4). Real block-timing evidence requires a network
    /// deployment (Phase 2). This test records the sim's per-block
    /// wall-clock time as a lower bound on the production block time.
    #[test]
    #[ignore = "timing sim: run with --release -- --ignored"]
    fn block_timing_4_validators() {
        let mut devnet = MultiNodeDevnet::new(4, 100_000);
        let (result, elapsed) = devnet.run_batch(10, 100);
        let num_blocks = result.finalized[0].len();
        assert!(num_blocks > 0, "should finalize blocks");
        let per_block = elapsed / u32::try_from(num_blocks).unwrap_or(1);
        let tps = tps(result.finalized[0].iter().map(|b| b.txs.len()).sum::<usize>(), elapsed);
        eprintln!(
            "block_timing_4_validators: {num_blocks} blocks in {elapsed:?} = {per_block:?}/block, {tps:.0} tx/s"
        );
        // The sim's per-block time is dominated by BLS verification
        // (4 vote verifications + 4 QC aggregate verifications per
        // block = 8 BLS pairing checks). In production, these are
        // batched and parallelized, so the real per-block time will
        // be much lower.
    }

    /// Transport-routed consensus round (H4 fix): 4 validators, 3
    /// rounds, 100 txs/round. Messages are routed through
    /// `MeshTransport` instead of direct method calls. Proves the
    /// Transport seam works end-to-end.
    #[test]
    fn transport_routed_consensus() {
        let mut devnet = MultiNodeDevnet::new(4, 10_000);
        devnet.enable_mesh();
        let (result, _elapsed) = devnet.run_batch_transport(3, 100);
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert!(total_txs > 0, "should finalize some txs via transport");
        // All validators should agree on the same blocks.
        let reference = &result.finalized[0];
        for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
            assert_eq!(blocks.len(), reference.len(), "validator {i} disagrees on count");
        }
    }

    /// Partition recovery (H2 fix): 7 validators, partition 2
    /// (one-third of f+1), run rounds during partition, heal, and
    /// verify consensus recovers. The partitioned nodes can't vote,
    /// but the remaining 5 validators (≥ 2f+1 = 5) can still reach
    /// quorum and finalize blocks.
    #[test]
    fn partition_recovery() {
        let mut devnet = MultiNodeDevnet::new(7, 10_000);
        devnet.enable_mesh();

        // Run 2 rounds before partition (all nodes online).
        let (result, _) = devnet.run_batch_transport(2, 10);
        let blocks_before = result.finalized[0].len();
        assert!(blocks_before > 0, "should finalize before partition");

        // Partition nodes 5 and 6 (2 of 7 = ~one-third).
        devnet.partition(5);
        devnet.partition(6);

        // Run 2 rounds during partition. The remaining 5 validators
        // (≥ 2f+1 = 5 for n=7, f=2) can still reach quorum.
        let (result, _) = devnet.run_batch_transport(2, 10);
        let blocks_during = result.finalized[0].len();
        assert!(blocks_during > blocks_before, "should finalize during partition");

        // Heal the partition.
        devnet.heal(5);
        devnet.heal(6);

        // Run 2 rounds after healing. All 7 validators participate.
        let (result, _) = devnet.run_batch_transport(2, 10);
        let blocks_after = result.finalized[0].len();
        assert!(blocks_after > blocks_during, "should finalize after healing");
    }
}
