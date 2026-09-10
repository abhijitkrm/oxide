//! TCP-based multi-node devnet — N validators with oxideBFT over real
//! TCP transport.
//!
//! # What this is
//!
//! A multi-node devnet runner that uses [`p2p::tcp::TcpTransport`] for
//! real network I/O. Each validator runs in the same process but
//! communicates over TCP loopback connections. This validates that
//! the consensus and broadcast layers work over a real network stack.
//!
//! # Why this exists
//!
//! The in-process [`MultiNodeDevnet`](crate::multinode::MultiNodeDevnet)
//! proves the consensus logic but doesn't exercise real networking.
//! The TCP devnet validates the full network path: TCP connections,
//! length-prefixed framing, thread-per-peer I/O, and message routing
//! through the `Transport` trait.
//!
//! # How it works
//!
//! 1. Construct N validators, each with its own `Executor` + `OxideBft`.
//! 2. Each validator gets a `TcpTransport` listening on a unique port.
//! 3. The round loop routes votes and QCs through TCP instead of
//!    direct method calls.
//! 4. The leader proposes, followers vote via TCP, the leader forms
//!    a QC and broadcasts it via TCP.
//!
//! # Phase 1 scope
//!
//! No TLS, no authentication. The TCP transport advertises
//! `authenticated = false`, `encrypted = false`. This is for local
//! devnet only — do not use across untrusted networks.

use std::sync::Arc;

use codec::{Decode, Encode};
use consensus::{OxideBft, ValidatorSet};
use executor::Executor;
use ports::transport::Transport;
use ports::{AppInterface, ConsensusEngine};
use types::{FinalizedBlock, TxBytes};

/// The genesis balance minted to each sender on every validator's
/// bank module. Large enough that the simulation never exhausts it.
const GENESIS_BALANCE: u64 = 1_000_000_000_000;

/// The base port for TCP transport. Each node gets `base_port + i`.
/// Default uses ports 20000+, but tests should pass a unique base
/// port to avoid collisions when running in parallel.
const DEFAULT_BASE_PORT: u16 = 20000;

/// A TCP-based multi-node devnet: N validators running oxideBFT with
/// real TCP transport.
pub struct TcpMultiNodeDevnet {
    /// One engine per validator.
    engines: Vec<OxideBft>,
    /// One executor per validator (kept for post-run inspection).
    apps: Vec<Arc<Executor>>,
    /// One TCP transport per validator.
    transports: Vec<p2p::tcp::TcpTransport>,
    /// The shared validator set.
    validator_set: ValidatorSet,
    /// The BLS secret keys for each validator.
    secret_keys: Vec<crypto::BlsSecretKey>,
    /// The number of validators.
    n: usize,
}

/// The result of running a TCP devnet: finalized blocks from each
/// validator.
#[derive(Debug, Clone)]
pub struct TcpDevnetResult {
    /// Finalized blocks per validator.
    pub finalized: Vec<Vec<FinalizedBlock>>,
}

impl TcpMultiNodeDevnet {
    /// Assemble a TCP-based multi-node devnet with `n` validators,
    /// using the default base port (20000).
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` or if any TCP port cannot be bound.
    pub fn new(n: usize, max_mempool_entries: usize) -> Self {
        Self::with_base_port(n, max_mempool_entries, DEFAULT_BASE_PORT)
    }

    /// Assemble a TCP-based multi-node devnet from a [`config::Config`].
    ///
    /// Uses the config's `genesis.num_validators`, `genesis.base_port`,
    /// `genesis.genesis_balance`, `executor.max_mempool_entries`,
    /// `executor.parallel_threshold`, and `network` settings to
    /// construct the devnet.
    ///
    /// # Panics
    ///
    /// Panics if `num_validators == 0` or if any TCP port cannot be bound.
    pub fn from_config(config: &config::Config) -> Self {
        let n = config.genesis.num_validators;
        let base_port = config.genesis.base_port;
        let genesis_balance = config.genesis.genesis_balance;
        let num_senders = config.genesis.num_prefunded_senders;
        let max_mempool = config.executor.max_mempool_entries;
        let parallel_threshold = config.executor.parallel_threshold;

        let tcp_config = p2p::tcp::TcpTransportConfig {
            max_message_bytes: config.network.max_message_bytes,
            connect_timeout: config.network.connect_timeout(),
            read_timeout: config.network.read_timeout(),
        };

        Self::build(
            n,
            base_port,
            genesis_balance,
            num_senders,
            max_mempool,
            parallel_threshold,
            tcp_config,
        )
    }

    /// Assemble a TCP-based multi-node devnet with `n` validators,
    /// using a custom base port. Each node listens on
    /// `127.0.0.1:{base_port + i}`.
    ///
    /// Use this in tests to avoid port collisions when running
    /// multiple devnets in parallel.
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` or if any TCP port cannot be bound.
    pub fn with_base_port(n: usize, max_mempool_entries: usize, base_port: u16) -> Self {
        Self::build(
            n,
            base_port,
            GENESIS_BALANCE,
            32,
            max_mempool_entries,
            executor::DEFAULT_PARALLEL_THRESHOLD,
            p2p::tcp::TcpTransportConfig::default(),
        )
    }

    /// Internal constructor with all parameters explicit.
    fn build(
        n: usize,
        base_port: u16,
        genesis_balance: u64,
        num_senders: u8,
        max_mempool_entries: usize,
        parallel_threshold: usize,
        tcp_config: p2p::tcp::TcpTransportConfig,
    ) -> Self {
        assert!(n > 0, "devnet must have at least one validator");

        let secret_keys: Vec<crypto::BlsSecretKey> =
            (1..=u8::try_from(n).unwrap()).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            secret_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let stakes = vec![1u64; n];
        let vs = ValidatorSet::new(pks, stakes).expect("validator set");

        // Build peer addresses for full mesh.
        let peer_addrs: Vec<(Vec<u8>, String)> = (0..n)
            .map(|i| {
                let port = base_port + u16::try_from(i).unwrap();
                (vec![u8::try_from(i).unwrap()], format!("127.0.0.1:{port}"))
            })
            .collect();

        let mut engines = Vec::with_capacity(n);
        let mut apps = Vec::with_capacity(n);
        let mut transports = Vec::with_capacity(n);

        for (i, key) in secret_keys.iter().cloned().enumerate() {
            let mut executor = Executor::with_config(max_mempool_entries, parallel_threshold);
            executor.register_module(Arc::new(oxide_core::CoreModule::new()));
            let bank = bank::BankModule::new();
            for sender_byte in 0u8..num_senders {
                bank.mint(&primitives::Address([sender_byte; 20]), genesis_balance);
            }
            executor.register_module(Arc::new(bank));
            executor.register_module(Arc::new(staking::StakingModule::new()));
            let app: Arc<Executor> = Arc::new(executor);
            let app_dyn: Arc<dyn AppInterface> = app.clone();

            // Build the peer list (all peers except self).
            let peers: Vec<(Vec<u8>, String)> = peer_addrs
                .iter()
                .filter(|(pid, _)| pid[0] != u8::try_from(i).unwrap())
                .cloned()
                .collect();

            let port = base_port + u16::try_from(i).unwrap();
            let listen_addr = format!("127.0.0.1:{port}");
            let transport = p2p::tcp::TcpTransport::with_config(
                &listen_addr,
                vec![u8::try_from(i).unwrap()],
                peers,
                tcp_config.clone(),
            );

            let engine = OxideBft::with_index(app_dyn, vs.clone(), u16::try_from(i).unwrap())
                .with_secret_key(key);

            engines.push(engine);
            apps.push(app);
            transports.push(transport);
        }

        // Give connections time to establish.
        std::thread::sleep(std::time::Duration::from_millis(500));

        Self { engines, apps, transports, validator_set: vs, secret_keys, n }
    }

    /// The number of validators.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Access the executor for validator `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i >= n`.
    pub fn app(&self, i: usize) -> &Executor {
        assert!(i < self.n, "validator index {i} out of range");
        &self.apps[i]
    }

    /// Run `rounds` consensus rounds with `txs_per_round` bank
    /// transfer txs, routing messages through TCP transport.
    ///
    /// Each round:
    /// 1. Submit `txs_per_round` txs to the leader's mempool.
    /// 2. Leader proposes.
    /// 3. Leader self-votes.
    /// 4. Followers vote via TCP.
    /// 5. Leader receives votes via TCP, forms QC.
    /// 6. Leader broadcasts QC via TCP.
    /// 7. Followers receive QC via TCP, deliver, advance view.
    pub fn run_batch(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
    ) -> (TcpDevnetResult, std::time::Duration) {
        let start = std::time::Instant::now();
        for round in 0..rounds {
            let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));
            for tx_i in 0..txs_per_round {
                let tx = make_batch_tx(round, tx_i);
                self.engines[leader_idx].submit_tx(tx);
            }
            self.run_round_tcp();
        }
        // Flush round.
        self.run_round_tcp();
        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }

    /// Run one consensus round with messages routed through TCP.
    fn run_round_tcp(&mut self) {
        let leader_idx = usize::from(self.validator_set.leader(self.engines[0].current_view()));

        // Leader proposes (direct — proposal broadcast is a separate
        // layer). If the leader can't propose, skip the round.
        let Some((header, proposal)) = self.engines[leader_idx].propose() else {
            for engine in &mut self.engines {
                engine.advance_view();
            }
            let max_height =
                self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
            for engine in &mut self.engines {
                engine.sync_next_height(max_height);
            }
            return;
        };
        let block_hash = OxideBft::block_hash(&header);

        // Leader self-votes (direct — no network self-send).
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

        // Followers vote via TCP: each follower encodes its vote and
        // sends it to the leader.
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if i == leader_idx {
                continue;
            }
            if let Some(vote) = engine.vote(&header, &proposal) {
                let mut buf = Vec::new();
                vote.encode(&mut buf);
                self.transports[i]
                    .send(&vec![u8::try_from(leader_idx).unwrap()], &buf)
                    .expect("TCP send vote to leader");
            }
        }

        // Leader receives votes via TCP, decodes, collects.
        // Poll until we have n-1 votes or timeout.
        let mut votes_received = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while votes_received < self.n - 1 && std::time::Instant::now() < deadline {
            if let Some(msg) = self.transports[leader_idx].recv() {
                let mut reader = codec::Reader::new(&msg.bytes);
                if let Ok(vote) = types::Vote::decode(&mut reader) {
                    let voter = u16::from(msg.from[0]);
                    let _ = self.engines[leader_idx].collect_vote(voter, vote);
                    votes_received += 1;
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        // Leader forms QC.
        let Some(qc) = self.engines[leader_idx].try_form_qc() else {
            for engine in &mut self.engines {
                engine.advance_view();
            }
            let max_height =
                self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
            for engine in &mut self.engines {
                engine.sync_next_height(max_height);
            }
            return;
        };

        // Leader broadcasts QC via TCP.
        let mut qc_buf = Vec::new();
        qc.encode(&mut qc_buf);
        for i in 0..self.n {
            if i == leader_idx {
                continue;
            }
            self.transports[leader_idx]
                .send(&vec![u8::try_from(i).unwrap()], &qc_buf)
                .expect("TCP send QC to follower");
        }

        // Followers receive QC via TCP, decode, deliver.
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if i == leader_idx {
                engine.deliver_qc(qc.clone()).expect("QC must verify");
                continue;
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if let Some(msg) = self.transports[i].recv() {
                    let mut reader = codec::Reader::new(&msg.bytes);
                    if let Ok(received_qc) = types::QuorumCertificate::decode(&mut reader) {
                        engine.deliver_qc(received_qc).expect("QC must verify");
                        break;
                    }
                }
                if std::time::Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        // All advance the view.
        for engine in &mut self.engines {
            engine.advance_view();
        }

        // Sync heights.
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
        }
    }

    /// Collect finalized blocks from each validator.
    fn collect_result(&self) -> TcpDevnetResult {
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
        TcpDevnetResult { finalized }
    }
}

/// Construct a deterministic BLS secret key from a single byte.
fn bls_key(byte: u8) -> crypto::BlsSecretKey {
    let ikm = vec![byte; 32];
    crypto::BlsSecretKey::from_ikm(&ikm).expect("BLS key generation from valid IKM")
}

/// Construct a bank transfer tx for batch throughput testing.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 4 validators, 3 rounds, 10 txs/round over TCP.
    #[test]
    fn tcp_multinode_4_validators_liveness() {
        let mut devnet = TcpMultiNodeDevnet::with_base_port(4, 10_000, 21000);
        let (result, _elapsed) = devnet.run_batch(3, 10);
        let n_blocks = result.finalized[0].len();
        assert!(n_blocks > 0, "should have finalized blocks over TCP");
        // All validators agree on block count.
        for (i, blocks) in result.finalized.iter().enumerate() {
            assert_eq!(
                blocks.len(),
                n_blocks,
                "validator {i} has {n_blocks} blocks expected, got {}",
                blocks.len()
            );
        }
        // All 30 txs should be finalized.
        let total_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
        assert_eq!(total_txs, 30, "all 30 txs must be finalized over TCP");
    }

    /// All validators must agree on the same finalized blocks.
    #[test]
    fn tcp_multinode_finality_agreement() {
        let mut devnet = TcpMultiNodeDevnet::with_base_port(4, 10_000, 21100);
        let (result, _) = devnet.run_batch(3, 10);
        let reference = &result.finalized[0];
        for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
            assert_eq!(blocks.len(), reference.len(), "validator {i} disagrees on block count");
            for (j, (a, b)) in reference.iter().zip(blocks.iter()).enumerate() {
                assert_eq!(a.height, b.height, "validator {i} block {j}: height mismatch");
                assert_eq!(a.txs, b.txs, "validator {i} block {j}: txs mismatch");
            }
        }
    }

    /// The bank module should have processed transfers: the state
    /// root should be non-zero after running.
    #[test]
    fn tcp_multinode_bank_module_executes() {
        let mut devnet = TcpMultiNodeDevnet::with_base_port(4, 10_000, 21200);
        devnet.run_batch(3, 10);
        let root = devnet.app(0).attest_state(primitives::Height::new(0));
        assert_ne!(root.root, primitives::Hash::ZERO, "state root should be non-zero");
    }

    /// Single validator (quorum=1) over TCP.
    #[test]
    fn tcp_multinode_single_validator() {
        let mut devnet = TcpMultiNodeDevnet::with_base_port(1, 10_000, 21300);
        let (result, _) = devnet.run_batch(3, 10);
        assert!(!result.finalized[0].is_empty(), "single validator should finalize over TCP");
    }

    /// The `from_config` constructor respects config values.
    #[test]
    fn tcp_multinode_from_config() {
        let config = config::Config {
            network: config::NetworkConfig {
                listen_addr: "127.0.0.1:21400".to_string(),
                peers: vec!["127.0.0.1:21401".to_string()],
                ..Default::default()
            },
            genesis: config::GenesisConfig {
                num_validators: 2,
                base_port: 21400,
                genesis_balance: 500_000_000_000,
                num_prefunded_senders: 16,
            },
            executor: config::ExecutorConfig { max_mempool_entries: 5_000, parallel_threshold: 50 },
            ..Default::default()
        };
        let mut devnet = TcpMultiNodeDevnet::from_config(&config);
        let (result, _) = devnet.run_batch(2, 5);
        assert!(!result.finalized[0].is_empty(), "from_config devnet should finalize");
    }
}
