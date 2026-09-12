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

use std::collections::HashSet;
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

/// Message type tag: vote. Prepended to vote messages in the pipelined
/// driver so the receiver can distinguish votes from QCs without
/// ambiguity (both start with view + phase + `block_hash`, and the `Vote`
/// decoder can succeed on QC bytes by reading the epoch + bitmap as
/// the 96-byte signature).
const MSG_VOTE: u8 = 0x01;

/// Message type tag: QC.
const MSG_QC: u8 = 0x02;

/// Build the BLS vote signing message: `(view, phase, block_hash,
/// epoch)`. This must match the format used by
/// `OxideBft::vote_signing_message` (C3 fix).
fn vote_signing_message(
    view: primitives::View,
    phase: types::VotePhase,
    block_hash: &primitives::Hash,
    epoch: primitives::Epoch,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(49);
    msg.extend_from_slice(&view.value().to_le_bytes());
    msg.push(phase as u8);
    msg.extend_from_slice(block_hash.as_bytes());
    msg.extend_from_slice(&epoch.value().to_le_bytes());
    msg
}

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
    /// EVM module handles (one per validator) for direct state access.
    /// These are the same `EvmModule` instances registered in each
    /// validator's executor, kept here so tests can fund accounts and
    /// inspect balances/nonces without downcasting from `dyn Module`.
    evm_modules: Vec<Arc<evm::EvmModule>>,
    /// Exchange module handles (one per validator) for direct state
    /// access. Only populated when the devnet is built with
    /// `with_exchange_and_base_port`; empty for the default bank-only
    /// devnet. Each validator gets its own `ExchangeModule` instance
    /// backed by that validator's `BankModule` — all validators
    /// execute the same blocks, so their exchange state converges
    /// after finality.
    exchange_modules: Vec<Arc<exchange::ExchangeModule>>,
}

/// The result of running a TCP devnet: finalized blocks from each
/// validator.
#[derive(Debug, Clone)]
pub struct TcpDevnetResult {
    /// Finalized blocks per validator.
    pub finalized: Vec<Vec<FinalizedBlock>>,
}

/// Mutable state shared across ticks of the pipelined event loop.
///
/// This is extracted from `run_pipelined` to keep each phase function
/// small and to avoid passing half a dozen locals through every call.
/// All fields are private to the module; phases mutate them via `&mut`.
struct PipelineState {
    /// Pending proposals, indexed by view (in-process — all engines
    /// see them via `propose()` / `vote()`).
    proposals: Vec<(types::BlockHeader, types::Proposal)>,
    /// Views that have been proposed (prevents duplicate proposals).
    proposed_views: HashSet<u64>,
    /// `(engine_idx, view)` pairs that have voted (prevents double-voting).
    voted: HashSet<(usize, u64)>,
    /// Number of QCs formed across all ticks.
    qcs_formed: u64,
}

impl PipelineState {
    fn new() -> Self {
        Self {
            proposals: Vec::new(),
            proposed_views: HashSet::new(),
            voted: HashSet::new(),
            qcs_formed: 0,
        }
    }

    /// Remove proposals that all `n` engines have voted on.
    ///
    /// This keeps Phase 2 iteration `O(pipeline_depth)` instead of
    /// `O(rounds)`. Blocks are already stored in each engine's `blocks`
    /// `HashMap` (via `vote()` / `propose()`), so removing the proposal
    /// from the vector is safe.
    fn compact_proposals(&mut self, n: usize) {
        self.proposals.retain(|(header, _)| {
            let view = header.view.value();
            (0..n).any(|i| !self.voted.contains(&(i, view)))
        });
    }
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

    /// Assemble a TCP-based multi-node devnet with `n` validators,
    /// registering the exchange module (backed by each validator's
    /// bank module) on every validator. Use this for trading TPS
    /// tests that need the exchange module's `handle()` path through
    /// the full consensus pipeline.
    ///
    /// Each validator gets:
    /// - Its own `BankModule` (funded with `GENESIS_BALANCE` per
    ///   prefunded sender).
    /// - Its own `ExchangeModule::with_bank(bank_clone)` — the
    ///   exchange settles fills by debiting/crediting the same bank
    ///   module that consensus executes.
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` or if any TCP port cannot be bound.
    pub fn with_exchange_and_base_port(
        n: usize,
        max_mempool_entries: usize,
        base_port: u16,
    ) -> Self {
        Self::build_with_modules(
            n,
            base_port,
            GENESIS_BALANCE,
            32,
            max_mempool_entries,
            executor::DEFAULT_PARALLEL_THRESHOLD,
            p2p::tcp::TcpTransportConfig::default(),
            true, // register_exchange
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
        Self::build_with_modules(
            n,
            base_port,
            genesis_balance,
            num_senders,
            max_mempool_entries,
            parallel_threshold,
            tcp_config,
            false, // do not register exchange
        )
    }

    /// Internal constructor with all parameters explicit, including
    /// an optional exchange module registration.
    ///
    /// When `register_exchange` is true, each validator gets an
    /// `ExchangeModule::with_bank(bank_clone)` backed by the same
    /// `BankModule` that consensus executes. The exchange module
    /// handles (as `Arc<ExchangeModule>`) are stored in
    /// `exchange_modules` for post-run inspection.
    #[allow(clippy::too_many_arguments)]
    fn build_with_modules(
        n: usize,
        base_port: u16,
        genesis_balance: u64,
        num_senders: u8,
        max_mempool_entries: usize,
        parallel_threshold: usize,
        tcp_config: p2p::tcp::TcpTransportConfig,
        register_exchange: bool,
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
        let mut evm_modules = Vec::with_capacity(n);
        let mut exchange_modules = Vec::with_capacity(n);

        for (i, key) in secret_keys.iter().cloned().enumerate() {
            let mut executor = Executor::with_config(max_mempool_entries, parallel_threshold)
                // Devnet measures throughput, not gas policy — the
                // block gas cap matches the consensus budget's
                // `max_gas` (1 gigagas) so large test blocks fit
                // under the declared-gas proposal check.
                .with_gas_limit(1 << 30);
            executor.register_module(Arc::new(oxide_core::CoreModule::new()));
            // Create the bank as an `Arc` so the exchange module (if
            // registered) can share the same bank instance — the
            // exchange settles fills by debiting/crediting this bank.
            let bank = Arc::new(bank::BankModule::new());
            for sender_byte in 0u8..num_senders {
                bank.mint(&primitives::Address([sender_byte; 20]), genesis_balance);
            }
            executor.register_module(bank.clone());
            // The bank collects fees for all native-module txs —
            // without this only bank txs paid (other modules ran free).
            executor.set_fee_module(framework::module_id::BANK);
            executor.register_module(Arc::new(staking::StakingModule::new()));
            // Optionally register the exchange module backed by this
            // validator's bank. Each validator gets its own exchange
            // instance; state diverges during proposal but converges
            // after finality (all validators execute the same block).
            if register_exchange {
                let ex = Arc::new(exchange::ExchangeModule::with_bank(bank.clone()));
                executor.register_module(ex.clone());
                exchange_modules.push(ex);
            }
            // Register the EVM module and fund the prefunded senders
            // so EVM transactions (transfers, deploys, calls) can
            // debit gas and value. Each validator gets its own EVM
            // module instance; state diverges until consensus
            // finalizes a block and all validators execute it.
            let evm_module = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
            for sender_byte in 0u8..num_senders {
                evm_module
                    .fund_account_for_test(&primitives::Address([sender_byte; 20]), u128::MAX);
            }
            executor.register_module(evm_module.clone());
            evm_modules.push(evm_module);
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

        Self {
            engines,
            apps,
            transports,
            validator_set: vs,
            secret_keys,
            n,
            evm_modules,
            exchange_modules,
        }
    }

    /// The number of validators.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Access the engines (mutable) — for Byzantine injection.
    pub(crate) fn engines_mut(&mut self) -> &mut [OxideBft] {
        &mut self.engines
    }

    /// Access the engines (immutable) — for Byzantine inspection.
    pub(crate) fn engines(&self) -> &[OxideBft] {
        &self.engines
    }

    /// Access the transports (mutable) — for Byzantine message injection.
    pub(crate) fn transports_mut(&mut self) -> &mut [p2p::tcp::TcpTransport] {
        &mut self.transports
    }

    /// Access the secret keys — for Byzantine vote signing.
    pub(crate) fn secret_keys(&self) -> &[crypto::BlsSecretKey] {
        &self.secret_keys
    }

    /// Access the apps (immutable) — for state root inspection.
    pub(crate) fn apps(&self) -> &[Arc<Executor>] {
        &self.apps
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

    /// Access the exchange module handles (one per validator).
    /// Empty if the devnet was built without `with_exchange_and_base_port`.
    pub fn exchange_modules(&self) -> &[Arc<exchange::ExchangeModule>] {
        &self.exchange_modules
    }

    /// Fund an EVM account on all validators.
    ///
    /// This is used by EVM load tests to fund the secp256k1-derived
    /// sender addresses that the workload generator creates. The
    /// `[byte; 20]` prefunded senders are funded at genesis, but
    /// random keypairs have arbitrary addresses that need explicit
    /// funding.
    ///
    /// # Panics
    ///
    /// Panics if `i >= n`.
    pub fn fund_evm_account(&self, addr: &primitives::Address, balance: u128) {
        for evm in &self.evm_modules {
            evm.fund_account_for_test(addr, balance);
        }
    }

    /// Get the EVM module for validator `i` for direct state inspection
    /// (balance, nonce, state root).
    ///
    /// # Panics
    ///
    /// Panics if `i >= n`.
    pub fn evm_module(&self, i: usize) -> &evm::EvmModule {
        assert!(i < self.n, "validator index {i} out of range");
        &self.evm_modules[i]
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

    /// Run `rounds` consensus rounds with `txs_per_round` txs, using a
    /// **pipelined** event loop that overlaps vote collection, QC
    /// formation, and QC delivery across views.
    ///
    /// Unlike [`run_batch`](Self::run_batch), which processes one round
    /// at a time with blocking polls (1ms `thread::sleep` per poll
    /// iteration), this method:
    ///
    /// 1. Submits all transactions upfront to each view's leader.
    /// 2. Runs a tick-based loop where each tick:
    ///    - Proposes for any view whose leader has the `high_qc`.
    ///    - Votes on any seen proposal (votes sent via TCP).
    ///    - Drains **all** inbound TCP messages concurrently.
    ///    - Forms QCs as soon as quorum is reached.
    ///    - Delivers QCs via TCP, advancing views **independently**.
    ///
    /// This overlaps round N+1's proposal with round N's QC delivery,
    /// eliminating the sequential bottleneck. The leader for view V+1
    /// proposes as soon as it receives QC V via TCP — it does not wait
    /// for all followers to acknowledge QC V.
    ///
    /// # Performance
    ///
    /// The previous `run_batch` driver slept 1ms per poll iteration
    /// (macOS scheduler granularity makes this 1–10ms in practice),
    /// and delivered QCs sequentially per follower. With 4 validators,
    /// each round took ~25ms. This pipelined driver uses
    /// `std::hint::spin_loop` (no scheduler delay) and drains all
    /// transports concurrently, reducing each round to ~100–300μs
    /// (two TCP loopback round-trips).
    ///
    /// # Panics
    ///
    /// Panics if a TCP send fails (vote or QC), or if the leader's
    /// self-delivered QC fails verification. These are test-only
    /// assertions — in production, the transport handles retries.
    pub fn run_pipelined(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
    ) -> (TcpDevnetResult, std::time::Duration) {
        let start = std::time::Instant::now();
        let target_blocks = u64::try_from(rounds).unwrap_or(u64::MAX);

        // Submit all txs upfront to each view's leader. Each view's
        // leader is determined by `validator_set.leader(view)`, which
        // rotates round-robin. The leader's mempool holds that round's
        // txs; `propose()` pulls them via `prepare_proposal`.
        for round in 0..rounds {
            let view = primitives::View::new(round as u64);
            let leader_idx = usize::from(self.validator_set.leader(view));
            for tx_i in 0..txs_per_round {
                let tx = make_batch_tx(round, tx_i);
                self.engines[leader_idx].submit_tx(tx);
            }
        }

        // Pipelined state: shared between the main loop and flush loop.
        let mut state = PipelineState::new();

        // Main loop: run until all `rounds` QCs are formed.
        let deadline = start + std::time::Duration::from_secs(30);
        loop {
            if state.qcs_formed >= target_blocks {
                break;
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            self.pipelined_tick(&mut state, target_blocks);
            std::hint::spin_loop();
        }

        // Flush round: propose one more empty block to commit the last
        // pending block (2-chain rule). Runs until ALL validators have
        // finalized `target_blocks` blocks — checking the minimum
        // across validators ensures followers aren't left lagging on
        // the last QC delivery.
        //
        // The 2-chain commit rule requires 2 QCs to commit the first
        // block: block N is committed when block N+1's QC is delivered.
        // So with `target_blocks=1`, we need the flush loop to propose
        // a second empty block and form its QC to commit block 0.
        //
        // `finalized_height()` returns `None` when no blocks are
        // committed. We map `None` to `u64::MAX` so the loop doesn't
        // exit prematurely (the `map_or(0, ...)` pattern treats "no
        // blocks" the same as "block 0 committed", which is wrong).
        let flush_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let min_finalized = self
                .engines
                .iter()
                .map(|e| e.finalized_height().map_or(u64::MAX, primitives::Id::value))
                .min()
                .unwrap_or(u64::MAX);
            if min_finalized != u64::MAX && min_finalized + 1 >= target_blocks {
                break;
            }
            if std::time::Instant::now() > flush_deadline {
                break;
            }
            self.pipelined_tick(&mut state, u64::MAX);
            std::hint::spin_loop();
        }

        // Final height sync (cleanup, same as `run_batch`).
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
        }

        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }

    /// Run `rounds` consensus rounds with pre-built txs, using the
    /// pipelined event loop. Each round's txs are submitted to that
    /// view's leader before the pipelined loop starts.
    ///
    /// This is the EVM-compatible variant of `run_pipelined`: instead
    /// of building bank-transfer txs internally, it accepts pre-built
    /// `TxBytes` envelopes (which can be EVM txs, bank txs, or any
    /// module's txs). The caller is responsible for:
    ///
    /// - Using correct nonces (the mempool rejects stale/duplicate
    ///   nonces per sender).
    /// - Funding the sender accounts (the EVM module rejects txs from
    ///   accounts with insufficient balance).
    /// - Using the correct module ID in the envelope (EVM = 3, bank =
    ///   1, etc.).
    ///
    /// `txs_per_round` txs are submitted per round, drawn from the
    /// flat `all_txs` slice in order. The total txs submitted is
    /// `rounds * txs_per_round`, which must be <= `all_txs.len()`.
    ///
    /// # Panics
    ///
    /// Panics if `rounds * txs_per_round > all_txs.len()`, if a TCP
    /// send fails, or if the leader's self-delivered QC fails
    /// verification.
    pub fn run_pipelined_txs(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
        all_txs: &[TxBytes],
    ) -> (TcpDevnetResult, std::time::Duration) {
        let start = std::time::Instant::now();
        let target_blocks = u64::try_from(rounds).unwrap_or(u64::MAX);
        let needed = rounds.checked_mul(txs_per_round).expect("rounds * txs_per_round overflow");
        assert!(
            all_txs.len() >= needed,
            "need {needed} txs for {rounds} rounds × {txs_per_round} txs/round, got {}",
            all_txs.len()
        );

        // Submit txs to each view's leader.
        let mut tx_idx = 0usize;
        for round in 0..rounds {
            let view = primitives::View::new(round as u64);
            let leader_idx = usize::from(self.validator_set.leader(view));
            for _ in 0..txs_per_round {
                self.engines[leader_idx].submit_tx(all_txs[tx_idx].clone());
                tx_idx += 1;
            }
        }

        // Pipelined loop (same as run_pipelined).
        let mut state = PipelineState::new();
        // Scale the deadline with the workload: 60s base + 250ms per
        // round (~4x the healthy ~10 blocks/s pipelined rate, so a
        // genuinely stalled pipeline still trips the deadline while
        // a slow-but-progressing one completes). 2000 rounds ≈ 230s
        // at full rate, 560s deadline.
        let deadline_secs = 60 + u64::try_from(rounds / 4).unwrap_or(0);
        let deadline = start + std::time::Duration::from_secs(deadline_secs);
        loop {
            if state.qcs_formed >= target_blocks {
                break;
            }
            if std::time::Instant::now() > deadline {
                break;
            }
            self.pipelined_tick(&mut state, target_blocks);
            std::hint::spin_loop();
        }

        // Flush round: propose one more empty block to commit the last
        // pending block (2-chain rule), and continue running until ALL
        // validators have finalized `target_blocks` blocks. The
        // original `run_pipelined` only checked the leader's finalized
        // height, which left followers lagging on the last QC. We check
        // the minimum finalized height across all validators to ensure
        // every validator has committed every block.
        //
        // `finalized_height()` returns `None` when no blocks are
        // committed. We map `None` to `u64::MAX` so the loop doesn't
        // exit prematurely (the `map_or(0, ...)` pattern treats "no
        // blocks" the same as "block 0 committed", which is wrong).
        let flush_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let min_finalized = self
                .engines
                .iter()
                .map(|e| e.finalized_height().map_or(u64::MAX, primitives::Id::value))
                .min()
                .unwrap_or(u64::MAX);
            if min_finalized != u64::MAX && min_finalized + 1 >= target_blocks {
                break;
            }
            if std::time::Instant::now() > flush_deadline {
                break;
            }
            self.pipelined_tick(&mut state, u64::MAX);
            std::hint::spin_loop();
        }

        // Final height sync.
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
        }

        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }

    /// One tick of the pipelined event loop.
    ///
    /// Each tick runs five phases: propose, vote, drain, form QC,
    /// advance views. The `state` tracks proposals, votes, and QCs
    /// across ticks. The `view_cap` limits which views may be proposed
    /// (the main loop caps at `target_blocks`; the flush loop uses
    /// `u64::MAX`).
    fn pipelined_tick(&mut self, state: &mut PipelineState, view_cap: u64) {
        self.propose_phase(state, view_cap);
        self.vote_phase(state);
        state.compact_proposals(self.n);
        self.drain_transports();
        self.form_qc_phase(state);
        self.advance_views_phase();
    }

    /// Phase 1: any leader with the `high_qc` that hasn't proposed yet.
    fn propose_phase(&mut self, state: &mut PipelineState, view_cap: u64) {
        for (i, engine) in self.engines.iter_mut().enumerate() {
            let view = engine.current_view().value();
            if view >= view_cap || state.proposed_views.contains(&view) {
                continue;
            }
            let leader_idx = usize::from(self.validator_set.leader(engine.current_view()));
            if i != leader_idx {
                continue;
            }
            // At genesis (view 0), no `high_qc` is needed. For view > 0,
            // the leader must have the QC from the previous view
            // (tail-fork resistance, oxidebft-spec.md §4).
            if view > 0 && engine.high_qc().is_none() {
                continue;
            }
            if let Some((header, proposal)) = engine.propose() {
                state.proposed_views.insert(view);
                state.proposals.push((header, proposal));
            }
        }
    }

    /// Phase 2: any engine that hasn't voted, vote on the proposal.
    fn vote_phase(&mut self, state: &mut PipelineState) {
        for (i, engine) in self.engines.iter_mut().enumerate() {
            for (header, proposal) in &state.proposals {
                let view = header.view.value();
                if state.voted.contains(&(i, view)) {
                    continue;
                }
                let leader_idx = usize::from(self.validator_set.leader(header.view));
                if i == leader_idx {
                    // Leader self-votes directly (no network).
                    let block_hash = OxideBft::block_hash(header);
                    let msg = vote_signing_message(
                        header.view,
                        types::VotePhase::Prepare,
                        &block_hash,
                        engine.epoch(),
                    );
                    let sig = self.secret_keys[i].sign(crypto::hash::Domain::Vote, &msg);
                    let leader_vote = types::Vote {
                        view: header.view,
                        phase: types::VotePhase::Prepare,
                        block_hash,
                        signature: sig,
                    };
                    let _ = engine.collect_vote(u16::try_from(i).unwrap(), leader_vote);
                    state.voted.insert((i, view));
                } else if let Some(vote) = engine.vote(header, proposal) {
                    let mut buf = Vec::with_capacity(1 + 137);
                    buf.push(MSG_VOTE);
                    vote.encode(&mut buf);
                    // Tolerate transient send failure: the transport
                    // reconnects a dropped peer connection after a
                    // short backoff, so `UnknownPeer`/`ChannelClosed`
                    // is expected during a reconnect window. Only
                    // mark the view voted when the send succeeded —
                    // otherwise the vote is retried next tick.
                    if self.transports[i]
                        .send(&vec![u8::try_from(leader_idx).unwrap()], &buf)
                        .is_ok()
                    {
                        state.voted.insert((i, view));
                    }
                }
            }
        }
    }

    /// Phase 3: drain all inbound TCP messages concurrently.
    ///
    /// Each message is decoded by its 1-byte type tag:
    /// `MSG_VOTE` → `collect_vote` on the receiving engine.
    /// `MSG_QC` → `deliver_qc` on the receiving engine.
    fn drain_transports(&mut self) {
        for (i, transport) in self.transports.iter_mut().enumerate() {
            while let Some(msg) = transport.recv() {
                if msg.bytes.is_empty() {
                    continue;
                }
                let tag = msg.bytes[0];
                let mut reader = codec::Reader::new(&msg.bytes[1..]);
                match tag {
                    MSG_VOTE => {
                        if let Ok(vote) = types::Vote::decode(&mut reader) {
                            let voter_idx = u16::from(msg.from[0]);
                            let _ = self.engines[i].collect_vote(voter_idx, vote);
                        }
                    }
                    MSG_QC => {
                        if let Ok(qc) = types::QuorumCertificate::decode(&mut reader) {
                            let _ = self.engines[i].deliver_qc(qc);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Phase 4: any leader with quorum, form QC and broadcast.
    fn form_qc_phase(&mut self, state: &mut PipelineState) {
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if let Some(qc) = engine.try_form_qc() {
                state.qcs_formed += 1;
                let mut qc_buf = Vec::with_capacity(1 + 150);
                qc_buf.push(MSG_QC);
                qc.encode(&mut qc_buf);
                for j in 0..self.n {
                    if j != i {
                        // Same transient-failure tolerance as the
                        // vote path: a peer mid-reconnect gets the
                        // QC dropped — it still finalizes via the
                        // next QC or catches up on restart.
                        let _ = self.transports[i].send(&vec![u8::try_from(j).unwrap()], &qc_buf);
                    }
                }
                engine.deliver_qc(qc).expect("leader self-deliver QC");
            }
        }
    }

    /// Phase 5: advance views for engines with a `high_qc`, sync heights.
    fn advance_views_phase(&mut self) {
        for engine in &mut self.engines {
            if let Some(hqc) = engine.high_qc() {
                if hqc.view == engine.current_view() {
                    engine.advance_view();
                }
            }
        }
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
        }
    }

    /// Run one consensus round with messages routed through TCP.
    #[allow(clippy::too_many_lines)]
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
        let leader_msg = vote_signing_message(
            header.view,
            types::VotePhase::Prepare,
            &block_hash,
            self.engines[leader_idx].epoch(),
        );
        let leader_sig = self.secret_keys[leader_idx].sign(crypto::hash::Domain::Vote, &leader_msg);
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
                // Tolerate transient send failure (peer mid-reconnect)
                // — a dropped vote stalls this view into a timeout,
                // which is the intended fault-injection behavior.
                let _ = self.transports[i].send(&vec![u8::try_from(leader_idx).unwrap()], &buf);
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
            // Tolerate transient send failure (peer mid-reconnect).
            let _ = self.transports[leader_idx].send(&vec![u8::try_from(i).unwrap()], &qc_buf);
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
