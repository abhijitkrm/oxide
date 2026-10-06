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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use codec::{Decode, Encode};
use consensus::{OxideBft, ValidatorSet};
use executor::Executor;
use ports::transport::Transport;
use ports::{AppInterface, ConsensusEngine};
use types::{FinalizedBlock, TxBytes};

use crate::txs;

/// The genesis balance minted to each sender on every validator's
/// EVM account store. Large enough that the simulation never
/// exhausts it.
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

/// Message type tag: block proposal (header + txs).
///
/// Only the threaded driver sends this: the single-threaded pipeline
/// shares proposals in-process (`state.proposals`), which skips the
/// largest real network cost — multi-MiB payload fan-out to every
/// follower. Shipping the proposal over TCP makes the threaded run
/// the first harness to pay the real distribution cost.
const MSG_PROPOSAL: u8 = 0x03;

/// Message type tag: body shard (header + one committed chunk).
///
/// The threaded driver's dispersed-broadcast path: the leader sends
/// each peer its assigned shard only (~body/n), and validators relay
/// their own shard so every peer reassembles the body off the vote
/// critical path. Votes attest the `body_commitment`; bodies certify
/// at `supply_body` before finalization — the `DispersedSimplex`
/// split used by `Commonware` `marshal::coding` and `LayerZero` `Zero`.
const MSG_SHARD: u8 = 0x04;

/// Per-receiver reliable fallback queue: `(sender_peer_id, frame)`.
/// The threaded driver drops frames here when a peer's TCP writer
/// channel reports `ChannelFull`, preserving the harness's "no
/// message loss" invariant without blocking the sender's hot loop —
/// the receiving validator drains its inbox each iteration. Peer IDs
/// are staking addresses (the same bytes the TCP layer proves
/// ownership of), so attribution survives committee reshuffles.
type Inboxes = Vec<Arc<std::sync::Mutex<VecDeque<(Vec<u8>, Vec<u8>)>>>>;

/// Mutable per-validator state the inbound dispatcher needs beyond
/// the engine: future-view headers awaiting vote retry, reassembling
/// body shards keyed by block hash, and the relay out-queue (our
/// assigned shard for peers — ownership derives from the engine's
/// live seat, not a stored index).
struct DispatchState<'a> {
    /// Future-view headers queued for `vote_header` retry.
    pending: &'a mut BTreeMap<u64, types::BlockHeader>,
    /// Reassembling bodies: `(shard set, block height)`.
    shard_sets: &'a mut HashMap<primitives::Hash, (types::shard::ShardSet, u64)>,
    /// Shard frames to forward to every peer this pass.
    relays: &'a mut Vec<Vec<u8>>,
    /// Reconstruction threshold for reassembling bodies — the
    /// committee's `erasure_params` output, identical on every
    /// validator because it derives from the shared stakes.
    shard_k: usize,
    /// Per-sender proposal-verify budget: `(window start, count)`
    /// per peer — mirrors the binary pump's bound so harness floods
    /// see the same admission behavior as the shipped driver. Keyed
    /// by the authenticated peer id (staking-address bytes).
    verify_budget: &'a mut HashMap<Vec<u8>, (std::time::Instant, u32)>,
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
    /// Spawn-order staking addresses — `validator_addrs[i]` is the
    /// identity of `engines[i]`/`transports[i]`. Committee *index*
    /// is derived per-lookup via `engine_pos`: a removal reshuffles
    /// seats, so the position↔index identity that held at genesis
    /// must never be assumed afterward.
    validator_addrs: Vec<primitives::Address>,
    /// Per-validator live committee shared with its `BlsPeerAuth` —
    /// the rotation methods publish the rotated set into each slot
    /// so handshakes authenticate against the active committee.
    live_sets: Vec<Arc<std::sync::RwLock<ValidatorSet>>>,
    /// Per-validator staged committee slot shared with its
    /// `BlsPeerAuth` — `None` unless a rotation is mid-window (the
    /// harness's synchronous `rotate_epoch_with_*` force-completion
    /// leaves no observable window; production holds it between
    /// schedule and activation).
    pending_sets: Vec<Arc<std::sync::RwLock<Option<ValidatorSet>>>>,
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
    /// access. The exchange is part of the production module graph —
    /// always populated, on every constructor. Each validator gets
    /// its own `ExchangeModule` instance settling through that
    /// validator's `EvmModule` ledger — all validators execute the
    /// same blocks, so their exchange state converges after finality.
    exchange_modules: Vec<Arc<exchange::ExchangeModule>>,
    /// Full commit history per validator. The engine's `finalized`
    /// map prunes at `MAX_RETAINED_FINALIZED` (4096), so the devnet
    /// collects commits via `commit_listener` into these unbounded
    /// vectors for the integrity check.
    committed_blocks: Vec<Arc<std::sync::Mutex<Vec<FinalizedBlock>>>>,
    /// Per-validator commit counters bumped inside the listener —
    /// lets the threaded loop's completion check skip the block-store
    /// mutex when nothing new committed.
    commit_seqs: Vec<Arc<AtomicU64>>,
    /// Phase timings from the most recent pipelined run — populated
    /// by `run_pipelined`/`run_pipelined_txs`, read via
    /// [`phase_timers`](Self::phase_timers).
    last_phase_timers: PhaseTimers,
}

/// The result of running a TCP devnet: finalized blocks from each
/// validator.
#[derive(Debug, Clone)]
pub struct TcpDevnetResult {
    /// Finalized blocks per validator.
    pub finalized: Vec<Vec<FinalizedBlock>>,
}

/// Wall-clock time spent in each pipelined-loop phase, accumulated
/// across all ticks of a run.
///
/// The devnet drives every engine from one thread, so these timers
/// measure how the single driver thread's time divides between
/// consensus phases — the primary diagnostic for locating the
/// throughput ceiling. `qc_deliver` covers `deliver_qc` calls, which
/// is where block commit and transaction execution happen, so it is
/// the closest proxy for "execution share of the round".
///
/// All fields are wall-clock [`Duration`]s on the driver thread, not
/// CPU time; TCP wait shows up inside `drain`.
#[derive(Debug, Default, Clone, Copy)]
pub struct PhaseTimers {
    /// Submitting txs to leader intakes (includes intake-drain retries).
    pub submit: std::time::Duration,
    /// Leader `propose()` calls: mempool pull + block assembly + sign.
    pub propose: std::time::Duration,
    /// `vote()` calls: structural checks + embedded-QC verify + sign,
    /// plus the TCP send and in-process collection of each vote.
    pub vote: std::time::Duration,
    /// Draining inbound TCP messages (votes/QCs decoded + delivered).
    pub drain: std::time::Duration,
    /// `try_form_qc` + QC TCP broadcast (aggregate-sign + fan-out).
    pub qc_form: std::time::Duration,
    /// `deliver_qc` to every engine — includes `commit_block` →
    /// `app.finalize_block`, i.e. transaction execution.
    pub qc_deliver: std::time::Duration,
    /// View advancement + height sync bookkeeping.
    pub advance: std::time::Duration,
    /// Proposal-vector compaction between ticks.
    pub compact: std::time::Duration,
    /// Number of ticks measured.
    pub ticks: u64,
}

impl PhaseTimers {
    /// Total time accounted to instrumented phases.
    fn total(&self) -> std::time::Duration {
        self.submit
            + self.propose
            + self.vote
            + self.drain
            + self.qc_form
            + self.qc_deliver
            + self.advance
            + self.compact
    }
}

impl std::fmt::Display for PhaseTimers {
    /// One-line-per-phase breakdown ordered by cost, with each phase's
    /// share of the instrumented total. Printed at the end of pipelined
    /// runs so the throughput ceiling's location is visible without a
    /// profiler.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_ms = self.total().as_secs_f64() * 1e3;
        let mut rows: [(&str, std::time::Duration); 8] = [
            ("qc_deliver (commit+execute)", self.qc_deliver),
            ("drain (TCP msgs)", self.drain),
            ("vote (verify+sign+send)", self.vote),
            ("qc_form (aggregate+fan-out)", self.qc_form),
            ("propose (mempool+build+sign)", self.propose),
            ("submit (tx intake)", self.submit),
            ("advance views", self.advance),
            ("compact proposals", self.compact),
        ];
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));
        writeln!(f, "phase breakdown ({:.1} ms instrumented, {} ticks):", total_ms, self.ticks)?;
        for (name, d) in rows {
            let ms = d.as_secs_f64() * 1e3;
            let pct = if total_ms > 0.0 { ms / total_ms * 100.0 } else { 0.0 };
            writeln!(f, "  {name:32} {ms:9.1} ms  {pct:5.1}%")?;
        }
        Ok(())
    }
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
    /// Accumulated per-phase wall-clock time (see [`PhaseTimers`]).
    timers: PhaseTimers,
}

impl PipelineState {
    fn new() -> Self {
        Self {
            proposals: Vec::new(),
            proposed_views: HashSet::new(),
            voted: HashSet::new(),
            qcs_formed: 0,
            timers: PhaseTimers::default(),
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
            allowed_peer_ids: None,
            // Queue byte budgets stay at the protocol defaults —
            // `NetworkConfig` does not expose them separately.
            ..Default::default()
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
    /// using a custom base port and parallel execution threshold.
    ///
    /// Use this in tests to control whether the EVM parallel
    /// speculative execution path is used. Setting
    /// `parallel_threshold` to `usize::MAX` forces the serial path.
    pub fn with_base_port_and_threshold(
        n: usize,
        max_mempool_entries: usize,
        base_port: u16,
        parallel_threshold: usize,
    ) -> Self {
        Self::build(
            n,
            base_port,
            GENESIS_BALANCE,
            32,
            max_mempool_entries,
            parallel_threshold,
            p2p::tcp::TcpTransportConfig::default(),
        )
    }

    /// Assemble a TCP-based multi-node devnet with `n` validators,
    /// registering the exchange module (backed by each validator's
    /// EVM ledger) on every validator. Use this for trading TPS
    /// tests that need the exchange module's `handle()` path through
    /// the full consensus pipeline.
    ///
    /// Each validator gets:
    /// - Its own `EvmModule` account store (funded with
    ///   `GENESIS_BALANCE` units per prefunded sender).
    /// - Its own `ExchangeModule::with_ledger(evm_clone)` — the
    ///   exchange settles fills by debiting/crediting the same EVM
    ///   ledger that consensus executes.
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
            None, // no settlement operator
        )
    }

    /// Like [`Self::with_exchange_and_base_port`], but also configures
    /// `operator` as the exchange's settlement operator — the only
    /// account allowed to submit `batch_settle` txs. Use this for
    /// tests of the off-chain-matcher settlement path (the operator
    /// should be one of the 32 prefunded senders so its txs pay fees).
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` or if any TCP port cannot be bound.
    pub fn with_exchange_settlement_and_base_port(
        n: usize,
        max_mempool_entries: usize,
        base_port: u16,
        operator: primitives::Address,
    ) -> Self {
        Self::build_with_modules(
            n,
            base_port,
            GENESIS_BALANCE,
            32,
            max_mempool_entries,
            executor::DEFAULT_PARALLEL_THRESHOLD,
            p2p::tcp::TcpTransportConfig::default(),
            Some(operator),
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
            None, // no settlement operator
        )
    }

    /// Internal constructor with all parameters explicit.
    ///
    /// Every validator assembles the production module graph via
    /// [`node::assemble_executor`] — the exchange module is always
    /// registered (it is part of the shipped graph), and its handles
    /// are stored in `exchange_modules` for post-run inspection.
    ///
    /// When `settlement_operator` is `Some`, the exchange modules are
    /// additionally configured to accept `batch_settle` txs from that
    /// address (the off-chain-matcher settlement path).
    #[allow(clippy::too_many_arguments)]
    fn build_with_modules(
        n: usize,
        base_port: u16,
        genesis_balance: u64,
        num_senders: u8,
        max_mempool_entries: usize,
        parallel_threshold: usize,
        tcp_config: p2p::tcp::TcpTransportConfig,
        settlement_operator: Option<primitives::Address>,
    ) -> Self {
        assert!(n > 0, "devnet must have at least one validator");

        let secret_keys: Vec<crypto::BlsSecretKey> =
            (1..=u8::try_from(n).unwrap()).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            secret_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let stakes = vec![1u64; n];
        // Devnet convention: validator `i`'s staking address is the
        // secp256k1 identity `txs::identity_addr(i)` — key-derived so
        // validators can sign their own `key_change`/endorsement txs
        // (a signed envelope's sender must recover to its key).
        let addresses: Vec<primitives::Address> =
            (0..n).map(|i| txs::identity_addr(u8::try_from(i).unwrap_or(0))).collect();
        let vs =
            ValidatorSet::with_addresses(pks, stakes, addresses.clone()).expect("validator set");

        // Build peer addresses for full mesh. Peer IDs are staking
        // addresses — the identity that survives committee reshuffles
        // (a removal moves seats; the address never does).
        let peer_addrs: Vec<(Vec<u8>, String)> = (0..n)
            .map(|i| {
                let port = base_port + u16::try_from(i).unwrap();
                (addresses[i].0.to_vec(), format!("127.0.0.1:{port}"))
            })
            .collect();

        let mut engines = Vec::with_capacity(n);
        let mut apps = Vec::with_capacity(n);
        let mut transports = Vec::with_capacity(n);
        let mut evm_modules = Vec::with_capacity(n);
        let mut exchange_modules = Vec::with_capacity(n);
        // Per-node committee views shared with its handshake
        // authenticator — the rotation methods publish each node's
        // rotated set so auth follows membership live.
        let live_sets: Vec<Arc<std::sync::RwLock<ValidatorSet>>> =
            (0..n).map(|_| Arc::new(std::sync::RwLock::new(vs.clone()))).collect();
        let pending_sets: Vec<Arc<std::sync::RwLock<Option<ValidatorSet>>>> =
            (0..n).map(|_| Arc::new(std::sync::RwLock::new(None))).collect();
        let committed_blocks: Vec<Arc<std::sync::Mutex<Vec<FinalizedBlock>>>> =
            (0..n).map(|_| Arc::new(std::sync::Mutex::new(Vec::new()))).collect();
        // Commit sequence counters — bumped by the listener on every
        // push. The threaded validator loop's completion check reads
        // these to skip the `committed_blocks` mutex entirely when
        // nothing new committed; without them the check locked +
        // scanned on every spin iteration (~35% of each thread's
        // time in measurement).
        let commit_seqs: Vec<Arc<AtomicU64>> =
            (0..n).map(|_| Arc::new(AtomicU64::new(0))).collect();

        // Every validator assembles through `node::assemble_executor`
        // — THE production module graph (core, evm, staking, exchange,
        // perps, oracle, governance) with the async execution lane
        // always on, exactly as the shipped binaries run. The harness
        // varies only what production legitimately varies: genesis
        // balances, mempool/parallel sizing, settlement operator.
        // `run_*` methods drain the lane before returning so executed
        // state is observable — see `drain_execution`.
        let genesis = node::GenesisSpec {
            // The committee is a single stake-0 member (registered
            // post-assembly below): every endorsement test relies on
            // one member's endorsement deciding quorum. Not in the
            // spec because `GenesisValidator` requires stake > 0.
            validators: Vec::new(),
            // Prefunded senders get `genesis_balance` base units
            // scaled to wei — the same credit `fund_account_for_test`
            // applied before, expressed as genesis state.
            balances: (0u8..num_senders)
                .map(|i| {
                    (txs::identity_addr(i), u128::from(genesis_balance) * framework::WEI_PER_UNIT)
                })
                .collect(),
        };
        let config = node::NodeConfig {
            max_mempool_entries,
            parallel_threshold,
            settlement_operator,
            genesis: Some(genesis),
            ..node::NodeConfig::default()
        };
        for (i, key) in secret_keys.iter().cloned().enumerate() {
            // The same startup the `oxide-devnet` binary boots —
            // engine wired with the configured pacemaker timeouts
            // and block budget, membership gate enforced. The
            // transport stays harness-side (the threaded pump drives
            // it); the clock seam stays at the production default
            // (wall clock — TCP timing is deliberately real).
            let signer: std::sync::Arc<dyn crypto::ConsensusSigner> = std::sync::Arc::new(key);
            let node = node::devnet::assemble_devnet_node(node::devnet::DevnetNodeSpec {
                index: i,
                validator_set: vs.clone(),
                signer: std::sync::Arc::clone(&signer),
                config: config.clone(),
                clock: None,
                wal_path: None,
            })
            .expect("devnet node assembles — deterministic keys are committee members");
            // Register the power-0 committee member: the sole
            // endorsement quorum (see the genesis comment above).
            node.staking_module.register_validator(txs::identity_addr(0));
            let app = node.app;
            let mut engine = node.engine;
            evm_modules.push(node.evm_module);
            exchange_modules.push(node.exchange_module);

            // Build the peer list (all peers except self).
            let own_id = addresses[i].0.to_vec();
            let peers: Vec<(Vec<u8>, String)> =
                peer_addrs.iter().filter(|(pid, _)| *pid != own_id).cloned().collect();

            let port = base_port + u16::try_from(i).unwrap();
            let listen_addr = format!("127.0.0.1:{port}");
            // Authenticate the greeting: a peer claiming address `a`
            // must sign with the key registered for `a` in the LIVE
            // committee — the rotation methods publish each node's
            // rotated set into `live_sets[i]` so auth follows
            // membership without a transport restart.
            let mut node_tcp_config = tcp_config.clone();
            node_tcp_config.peer_auth = Some(Arc::new(node::peer_auth::BlsPeerAuth::new(
                signer,
                live_sets[i].clone(),
                pending_sets[i].clone(),
            )));
            let transport =
                p2p::tcp::TcpTransport::with_config(&listen_addr, own_id, peers, node_tcp_config);

            // Wire a commit listener that pushes each committed block
            // into the shared `committed_blocks` vector. The engine's
            // `finalized` map prunes at `MAX_RETAINED_FINALIZED` (4096),
            // so the devnet needs an external copy for the integrity
            // check on tests > 4096 blocks.
            let committed = committed_blocks[i].clone();
            let commit_seq = commit_seqs[i].clone();
            engine.set_commit_listener(Box::new(move |block| {
                primitives::sync::lock_state(&committed).push(block.clone());
                // Release so a reader that observes the bump is
                // guaranteed to see the push that caused it.
                commit_seq.fetch_add(1, Ordering::Release);
            }));

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
            validator_addrs: addresses,
            live_sets,
            pending_sets,
            validator_set: vs,
            secret_keys,
            n,
            evm_modules,
            exchange_modules,
            committed_blocks,
            commit_seqs,
            last_phase_timers: PhaseTimers::default(),
        }
    }

    /// Wait until every validator's execution lane has applied the
    /// last committed block.
    ///
    /// The lane (spawned by `node::assemble_executor`, always on —
    /// production never runs without it) executes committed blocks
    /// off the consensus thread, so run loops can return with block
    /// h committed but still executing. Tests that read balances,
    /// nonces, or book state must observe post-execution state:
    /// `attest_state` blocks on the executed watermark, which is
    /// exactly the synchronization the production exec-cert path
    /// uses. A dead lane surfaces as `None` → loud panic rather
    /// than a silently stale read.
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

    /// The number of validators.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Per-phase wall-clock timings accumulated during the most recent
    /// pipelined run (`run_pipelined` / `run_pipelined_txs`).
    ///
    /// The devnet drives all engines from one thread, so the breakdown
    /// shows where the single driver thread spends its time — the
    /// `qc_deliver` phase covers `deliver_qc` → `commit_block` →
    /// `finalize_block` and is the closest proxy for "execution share".
    pub fn phase_timers(&self) -> PhaseTimers {
        self.last_phase_timers
    }

    /// Map a committee index to the spawn-order position of the
    /// engine holding that seat — or `None` for a phantom member
    /// (an added validator with no spawned engine) or an index past
    /// the committee.
    ///
    /// The lookup goes through each engine's OWN validator set and
    /// the spawn-order staking address, never `position == index`:
    /// a removal reshuffles seats, so a removed member's stale index
    /// can collide with a live member's new seat — only the engine
    /// whose *address* the committee still lists at `idx` counts.
    fn engine_pos(&self, committee_idx: usize) -> Option<usize> {
        let idx = consensus::ValidatorIndex::try_from(committee_idx).ok()?;
        self.engines.iter().enumerate().find_map(|(pos, e)| {
            (e.validator_set().index_of(&self.validator_addrs[pos]) == Some(idx)).then_some(pos)
        })
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

    /// The shared validator set. Used by key-rotation tests to
    /// inspect validator keys and staking addresses.
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
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

    /// Run `rounds` consensus rounds with `txs_per_round` staking
    /// delegate txs, routing messages through TCP transport.
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
            // A phantom member (validator_add without a spawned
            // engine) can't take mempool submissions — skip the
            // submit; its leader slot times out in `run_round_tcp`.
            // `engine_pos` resolves seat → position so a reshuffled
            // committee can't submit to the member that MOVED into
            // the leader's old index.
            if let Some(pos) = self.engine_pos(leader_idx) {
                for tx_i in 0..txs_per_round {
                    let tx = make_batch_tx(round, tx_i);
                    self.engines[pos].submit_tx(tx);
                }
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
            // Phantom member (validator_add without a spawned
            // engine): its round's txs can never be proposed —
            // skip them as a crashed leader's would be lost.
            if let Some(pos) = self.engine_pos(leader_idx) {
                for tx_i in 0..txs_per_round {
                    let tx = make_batch_tx(round, tx_i);
                    self.engines[pos].submit_tx(tx);
                }
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

        self.last_phase_timers = state.timers;
        eprintln!("{}", state.timers);

        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }

    /// Run `rounds` consensus rounds with pre-built txs, using the
    /// pipelined event loop. Each round's txs are submitted to that
    /// view's leader before the pipelined loop starts.
    ///
    /// This is the EVM-compatible variant of `run_pipelined`: instead
    /// of building staking-delegate txs internally, it accepts pre-built
    /// `TxBytes` envelopes (which can be EVM txs, staking txs, or any
    /// module's txs). The caller is responsible for:
    ///
    /// - Using correct nonces (the mempool rejects stale/duplicate
    ///   nonces per sender).
    /// - Funding the sender accounts (the EVM module rejects txs from
    ///   accounts with insufficient balance).
    /// - Using the correct module ID in the envelope (EVM = 3,
    ///   staking = 2, etc.).
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
    // Driver state machine — splitting phases across helpers
    // would scatter the shared `PipelineState` bookkeeping.
    #[allow(clippy::too_many_lines)]
    pub fn run_pipelined_txs(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
        all_txs: &[TxBytes],
    ) -> (TcpDevnetResult, std::time::Duration) {
        // Submit ahead by at least n validators so every upcoming
        // leader has txs in its intake before the pipeline reaches
        // its view. With the tx_idx accumulation fix, each round's
        // txs go to the correct leader; SUBMIT_AHEAD >= n ensures
        // the leader isn't starved when the pipeline advances.
        // 4 is the minimum (covers the 4-validator case); we scale
        // up to n when n > 4.
        let submit_ahead: usize = self.n.max(4);
        let start = std::time::Instant::now();
        let target_blocks = u64::try_from(rounds).unwrap_or(u64::MAX);
        let needed = rounds.checked_mul(txs_per_round).expect("rounds * txs_per_round overflow");
        assert!(
            all_txs.len() >= needed,
            "need {needed} txs for {rounds} rounds × {txs_per_round} txs/round, got {}",
            all_txs.len()
        );

        // Progress reporting: print a line every `progress_interval`
        // blocks or every 5 seconds, whichever comes first. This gives
        // real-time visibility into long-running tests (1M+ txs) instead
        // of a multi-minute silence.
        let progress_interval = (rounds / 20).max(1); // ~5% steps
        let mut last_progress_block = 0u64;
        let mut last_progress_time = std::time::Instant::now();
        let progress_secs = std::time::Duration::from_secs(5);

        // Interleave tx submission with the consensus loop.
        //
        // The executor's mempool intake is a bounded sync channel
        // (capacity 10,000). Submitting all txs upfront before the
        // consensus loop starts consuming would fill the channel and
        // block on `send` — a deadlock at 0% CPU (the producer waits
        // for the consumer, but the consumer hasn't started).
        //
        // Instead, we submit txs for each round inside the pipelined
        // loop, a few rounds ahead of the pipeline's current position.
        // The consensus loop drains the intake channel between
        // submissions, preventing the deadlock.
        //
        // `submit_ahead` controls how many rounds of txs are buffered
        // in the intake channel ahead of the pipeline. Too few and the
        // leader has no txs to propose; too many and the channel fills
        // up. 4 rounds ahead is enough to keep the pipeline fed without
        // exceeding the 10K channel capacity (4 × 1000 = 4000 < 10000).
        //
        // If the intake channel is full (the pipeline stalled), we run
        // a pipelined tick to drain it before retrying the submission.
        // This prevents the second deadlock: the pipeline stalls, the
        // intake fills up, `try_send` returns `Rejected`, and we drain
        // the intake by advancing the pipeline.
        let mut tx_idx = 0usize;
        let mut next_submit_round = 0usize;

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

            // Submit txs for rounds that are within `submit_ahead` of
            // the pipeline's current position. The pipeline has
            // formed `state.qcs_formed` blocks, so we submit txs
            // for rounds up to `qcs_formed + submit_ahead`.
            let submit_through = usize::try_from(state.qcs_formed)
                .unwrap_or(usize::MAX)
                .saturating_add(submit_ahead)
                .min(rounds);
            while next_submit_round < submit_through {
                let view = primitives::View::new(next_submit_round as u64);
                let leader_idx = usize::from(self.validator_set.leader(view));
                // Accumulate tx_idx: submit_round_txs returns the
                // count of txs submitted from the given slice, not
                // the absolute index. Using `=` instead of `+=`
                // resets tx_idx to the count (e.g. 1000) instead of
                // advancing it (e.g. 1000 → 2000), causing every
                // round after the first to re-submit the same txs
                // from all_txs[1000..2000]. Those duplicate txs are
                // rejected by the replay check (nonce already
                // executed), and the pipeline stalls.
                let t_sub = std::time::Instant::now();
                tx_idx += self.submit_round_txs(
                    leader_idx,
                    txs_per_round,
                    &all_txs[tx_idx..],
                    &mut state,
                    target_blocks,
                    deadline,
                );
                state.timers.submit += t_sub.elapsed();
                next_submit_round += 1;
            }

            self.pipelined_tick(&mut state, target_blocks);

            // Progress report: print finalized txs / total and current
            // throughput every `progress_interval` blocks or every 5s.
            let blocks_done = state.qcs_formed;
            let time_since = last_progress_time.elapsed();
            if blocks_done >= last_progress_block + progress_interval as u64
                || (time_since >= progress_secs && blocks_done > last_progress_block)
            {
                Self::report_progress(blocks_done, txs_per_round, needed, target_blocks, &start);
                last_progress_block = blocks_done;
                last_progress_time = std::time::Instant::now();
            }

            std::hint::spin_loop();
        }

        // Submit any remaining txs (in case the deadline hit early).
        // This phase has its own deadline — if the intake is full and
        // the pipeline can't drain it fast enough, we give up rather
        // than looping forever. The integrity check will then report
        // how many txs were actually finalized.
        let remaining_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while next_submit_round < rounds {
            if std::time::Instant::now() > remaining_deadline {
                eprintln!(
                    "trading TPS test: remaining-submit deadline hit at round {next_submit_round}/{rounds}"
                );
                break;
            }
            let view = primitives::View::new(next_submit_round as u64);
            let leader_idx = usize::from(self.validator_set.leader(view));
            let t_sub = std::time::Instant::now();
            tx_idx += self.submit_round_txs(
                leader_idx,
                txs_per_round,
                &all_txs[tx_idx..],
                &mut state,
                u64::MAX,
                remaining_deadline,
            );
            state.timers.submit += t_sub.elapsed();
            next_submit_round += 1;
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

        self.last_phase_timers = state.timers;
        eprintln!("{}", state.timers);

        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }

    /// Run `rounds` blocks × `txs_per_round` pre-built txs with each
    /// validator on its own OS thread — the closest single-machine
    /// approximation of a real multi-machine deployment.
    ///
    /// # How this differs from `run_pipelined_txs`
    ///
    /// The pipelined driver drives every engine from one thread, so
    /// all validators' propose/vote/verify/execute work serializes on
    /// shared cores — a throughput ceiling no real deployment has.
    /// Here each engine + executor runs an independent event loop on
    /// its own thread; per-validator work parallelizes across cores.
    ///
    /// Two protocol-level differences fall out of that:
    ///
    /// 1. **Proposals go over the wire.** The single-threaded driver
    ///    shares `(header, proposal)` pairs in-process, so payload
    ///    fan-out costs nothing. The threaded leader broadcasts
    ///    `MSG_PROPOSAL` frames (header + full tx bytes) over TCP —
    ///    the first harness to pay real multi-MiB distribution cost.
    /// 2. **Reliability comes from a fallback queue, not in-process
    ///    delivery.** `TcpTransport::send` is best-effort
    ///    (`try_send` into a bounded writer channel — `ChannelFull`
    ///    drops). Failed sends are pushed into the receiver's shared
    ///    inbox, which its thread drains alongside TCP. Ordering
    ///    between TCP and fallback can interleave; the engine
    ///    tolerates this (idempotent vote/QC delivery, ancestor-walk
    ///    commit catches late blocks on the next QC, and leaders
    ///    keep proposing empty blocks until every validator commits
    ///    the target).
    ///
    /// # Termination
    ///
    /// Each thread exits when a shared `done` counter reaches `n` —
    /// a validator marks itself done once its own commit count hits
    /// `rounds`, but keeps voting/proposing until all peers finish,
    /// so the flush views still reach quorum. The driver paces tx
    /// submission on the global minimum committed height (same
    /// `submit_ahead` lookahead as the pipelined path) and sets a
    /// `stop` flag on any deadline so joins can't hang.
    ///
    /// # Panics
    ///
    /// Panics if `rounds * txs_per_round > all_txs.len()` or if a
    /// validator thread panics.
    // Harness orchestration: spawn/join + submit pacing share
    // the same locals; splitting obscures the run protocol.
    #[allow(clippy::too_many_lines)]
    pub fn run_threaded_txs(
        &mut self,
        rounds: usize,
        txs_per_round: usize,
        all_txs: &[TxBytes],
    ) -> (TcpDevnetResult, std::time::Duration) {
        let n = self.n;
        let start = std::time::Instant::now();
        let needed = rounds.checked_mul(txs_per_round).expect("rounds * txs_per_round overflow");
        assert!(
            all_txs.len() >= needed,
            "need {needed} txs for {rounds} rounds × {txs_per_round} txs/round, got {}",
            all_txs.len()
        );

        // Shared mesh: per-receiver fallback inboxes (reliable path
        // for sends the bounded TCP writer channel drops), a done
        // counter, and a stop flag for deadline exits. Inboxes are
        // keyed by COMMITTEE SEAT, not spawn position — the committee
        // may exceed the spawned count (phantom members) and seats
        // reshuffle on removal; each thread drains the inbox of the
        // seat its engine held at spawn.
        let committee_n = self.validator_set.n();
        let inboxes: Inboxes =
            (0..committee_n).map(|_| Arc::new(std::sync::Mutex::new(VecDeque::new()))).collect();
        let global_done = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Completion is measured in finalized *transactions*, not
        // blocks: a tx whose round's leader proposed before the tx was
        // selectable (nonce not yet contiguous with executed state)
        // heals in a later view, so block count alone can reach the
        // round target while txs are still pending — and every
        // committed block must still be counted for integrity.
        let target_txs = u64::try_from(rounds.saturating_mul(txs_per_round)).unwrap_or(u64::MAX);
        // Per-validator current view, shared with the driver thread.
        // Submission pacing uses `min(views)` — a leader cannot reach
        // view k until the slowest validator is close behind, so
        // pacing on the minimum view guarantees the round's txs land
        // in the leader's intake *before* it proposes. (Pacing on
        // committed height instead raced: commits lag views by the
        // 2-chain delay plus execution time, letting a fast leader
        // propose an empty block and then stall the next leader,
        // whose `pending` then has no txs.)
        let views: Vec<Arc<std::sync::atomic::AtomicU64>> =
            (0..n).map(|_| Arc::new(std::sync::atomic::AtomicU64::new(0))).collect();

        // Pre-seed each leader's intake BEFORE the validator threads
        // start. Once threads run, a leader can reach its view before
        // the driver submits that round's txs and propose an empty
        // block — the stranded txs then sit in the intake forever
        // (a leader at view k never proposes again within `rounds`
        // when k >= n). Seeding first removes the arrival race for
        // every round the 10K-entry intake can hold; the paced loop
        // below handles the overflow for larger runs.
        let mut tx_idx = 0usize;
        let mut next_submit_round = 0usize;
        'seed: while next_submit_round < rounds {
            let view = primitives::View::new(next_submit_round as u64);
            let leader_idx = usize::from(self.validator_set.leader(view));
            let round_end = (next_submit_round + 1) * txs_per_round;
            // A phantom member (validator_add without a spawned
            // engine) has no app to ingest into — consume the
            // round's txs without submitting, the same outcome as
            // a crashed leader losing its round. `engine_pos`
            // resolves the seat to the engine actually holding it —
            // a reshuffled committee's `apps[leader_idx]` would feed
            // the wrong member's mempool.
            let Some(leader_pos) = self.engine_pos(leader_idx) else {
                tx_idx = round_end;
                next_submit_round += 1;
                continue;
            };
            while tx_idx < round_end {
                match self.apps[leader_pos].ingest_tx(all_txs[tx_idx].clone()) {
                    types::MempoolAck::Accepted => tx_idx += 1,
                    // Intake channel full — stop seeding; the paced
                    // loop continues once the pipeline is draining.
                    types::MempoolAck::Rejected { .. } => break 'seed,
                }
            }
            next_submit_round += 1;
        }

        // Move each engine + transport into its own thread. They are
        // returned on join and restored into `self` so post-run
        // inspection (`engines()`, `evm_module()`) keeps working.
        let engines: Vec<OxideBft> = std::mem::take(&mut self.engines);
        let transports: Vec<p2p::tcp::TcpTransport> = std::mem::take(&mut self.transports);
        let mut handles = Vec::with_capacity(n);
        for (i, (engine, transport)) in engines.into_iter().zip(transports).enumerate() {
            let vs = self.validator_set.clone();
            let inboxes = inboxes.clone();
            let committed = self.committed_blocks[i].clone();
            let commit_seq = self.commit_seqs[i].clone();
            let done = Arc::clone(&global_done);
            let stop = Arc::clone(&stop);
            let view = Arc::clone(&views[i]);
            // The peer id this thread's transport claimed — its
            // staking address, used as `from` on the inbox fallback.
            let my_id = self.validator_addrs[i].0.to_vec();
            handles.push(std::thread::spawn(move || {
                Self::validator_loop(
                    engine, transport, my_id, n, vs, inboxes, committed, commit_seq, done, stop,
                    view, target_txs,
                )
            }));
        }

        // Submit loop (driver thread): continues from where the
        // pre-seed stopped, paced on the global minimum view +
        // `submit_ahead` lookahead. `ingest_tx` goes straight to each
        // app's bounded intake channel; a `Rejected` ack means the
        // channel is full, which drains as the leader's own thread
        // proposes — yield and retry.
        let submit_ahead = n.max(4);
        let deadline =
            start + std::time::Duration::from_secs(60 + u64::try_from(rounds / 4).unwrap_or(0));
        while next_submit_round < rounds && global_done.load(Ordering::Relaxed) != n {
            if std::time::Instant::now() > deadline {
                eprintln!("threaded run: submit deadline at round {next_submit_round}/{rounds}");
                break;
            }
            let min_view = views.iter().map(|v| v.load(Ordering::Relaxed)).min().unwrap_or(0);
            let submit_through = usize::try_from(min_view)
                .unwrap_or(usize::MAX)
                .saturating_add(submit_ahead)
                .min(rounds);
            while next_submit_round < submit_through {
                let view = primitives::View::new(next_submit_round as u64);
                let leader_idx = usize::from(self.validator_set.leader(view));
                let round_end = (next_submit_round + 1) * txs_per_round;
                // Phantom member — no engine holds the seat; consume
                // the round's txs as if the leader were crashed.
                let Some(leader_pos) = self.engine_pos(leader_idx) else {
                    tx_idx = round_end;
                    next_submit_round += 1;
                    continue;
                };
                while tx_idx < round_end {
                    match self.apps[leader_pos].ingest_tx(all_txs[tx_idx].clone()) {
                        types::MempoolAck::Accepted => tx_idx += 1,
                        types::MempoolAck::Rejected { .. } => break,
                    }
                }
                if tx_idx < round_end {
                    break;
                }
                next_submit_round += 1;
            }
            std::thread::yield_now();
        }

        // Wait for every validator to commit `target_commits` blocks.
        // Threads that finish early keep looping (voting/proposing)
        // until `global_done == n`, so late flush views still reach
        // quorum. On deadline, `stop` releases them for a clean join.
        let wait_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while global_done.load(Ordering::Relaxed) != n && std::time::Instant::now() < wait_deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let (engine, transport) = h.join().expect("validator thread panicked");
            self.engines.push(engine);
            self.transports.push(transport);
        }

        // Final height sync (same as the pipelined drivers).
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
        }

        // Diagnostic: leftover mempool entries mean a leader's txs
        // arrived after its last proposal — a submission-timing gap,
        // not an execution failure.
        if std::env::var_os("THREADED_DEBUG").is_some() {
            for (i, app) in self.apps.iter().enumerate() {
                let leftover = app.mempool_len();
                if leftover > 0 {
                    eprintln!("  [v{i}] mempool leftover: {leftover} txs never proposed");
                }
            }
        }

        let elapsed = start.elapsed();
        (self.collect_result(), elapsed)
    }

    /// Per-validator event loop for [`run_threaded_txs`](Self::run_threaded_txs).
    ///
    /// Mirrors the pipelined driver's five phases — drain, propose,
    /// vote, form QC, advance — but on this validator's own thread
    /// and with proposals arriving over the wire. Returns the engine
    /// and transport so the devnet can restore them post-run.
    // Per-thread consensus state machine — one poll loop driving
    // propose/vote/qc/inbound phases; extraction would thread a
    // dozen shared locals through helpers for no gain.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn validator_loop(
        mut engine: OxideBft,
        mut transport: p2p::tcp::TcpTransport,
        my_id: Vec<u8>,
        n_spawned: usize,
        validator_set: ValidatorSet,
        inboxes: Inboxes,
        committed: Arc<std::sync::Mutex<Vec<FinalizedBlock>>>,
        commit_seq: Arc<AtomicU64>,
        global_done: Arc<AtomicUsize>,
        stop: Arc<std::sync::atomic::AtomicBool>,
        view_out: Arc<std::sync::atomic::AtomicU64>,
        target_txs: u64,
    ) -> (OxideBft, p2p::tcp::TcpTransport) {
        // Our committee seat is whatever the engine re-seated to —
        // after a rotation it may differ from spawn order. Broadcast
        // targets and the inbox key are committee seats; `my_id`
        // (the staking address) is what peers authenticate us as.
        // `n_spawned` bounds the done bookkeeping (threads that
        // exist); `n_committee` bounds the broadcast/inbox keyspace
        // (seats that exist — possibly more, when phantom members
        // were added without engines).
        let me = usize::from(engine.validator_index());
        let n_committee = validator_set.n();
        // Pending proposals by view — filled by `MSG_PROPOSAL`
        // frames, voted on in view order (BTreeMap keeps the oldest
        // first so a burst of views resolves FIFO).
        // Future-view headers queued for vote retry — keyed by view.
        // Header-only: `vote_header` resolves the body from engine
        // state (already stored `Complete` on the full-proposal path,
        // or `Awaiting` on the shard path — vote eligibility is
        // identical either way).
        let mut pending: BTreeMap<u64, types::BlockHeader> = BTreeMap::new();
        // Reassembling block bodies, keyed by block hash. A set is
        // inserted on the first valid shard seen for a block and
        // removed when it completes (supply_body) or is pruned below
        // the committed height. The `u64` is the block height, kept
        // solely for pruning.
        let mut shard_sets: HashMap<primitives::Hash, (types::shard::ShardSet, u64)> =
            HashMap::new();
        // The reconstruction threshold for this committee — every
        // validator derives the same `k` from the shared stakes and
        // quorum, so dispersal and reassembly agree on it without a
        // wire field.
        let shard_k =
            types::shard::erasure_params(validator_set.stakes(), validator_set.quorum_stake()).0;
        let mut proposed_views: HashSet<u64> = HashSet::new();
        let mut voted_views: HashSet<u64> = HashSet::new();
        // Per-sender proposal-verify budget — the same bound the
        // binary pump applies (`PROPOSAL_VERIFY_BUDGET_PER_SEC`),
        // keyed by the sender's authenticated peer id (staking-address
        // bytes) so a flooding peer can only spend its own quota.
        let mut verify_budget: HashMap<Vec<u8>, (std::time::Instant, u32)> = HashMap::new();
        let mut marked_done = false;
        let mut finalized_txs = 0u64;
        let mut counted_blocks = 0usize;
        let mut last_commit_seq = 0u64;
        let mut last_debug = std::time::Instant::now();
        // Hoisted out of the loop: `var_os` scans the environ block
        // on every call — ~35M iterations made it the single biggest
        // line item in the profile (~1.2s/thread).
        let debug = std::env::var_os("THREADED_DEBUG").is_some();
        // Per-thread phase accounting — printed at exit so the
        // threaded profile shows where each validator's loop time
        // actually goes (the same question `PhaseTimers` answers for
        // the single-threaded driver). `qc_us` covers try_form_qc +
        // fan-out + self-deliver; inbound QC delivery (the commit +
        // execute hot path) is timed inside `dispatch_inbound` and
        // reported as `commit_us`.
        let mut t_inbound = std::time::Duration::ZERO;
        let mut t_commit = std::time::Duration::ZERO;
        let mut t_propose = std::time::Duration::ZERO;
        let mut t_vote = std::time::Duration::ZERO;
        let mut t_qc = std::time::Duration::ZERO;
        let mut t_done = std::time::Duration::ZERO;
        let loop_start = std::time::Instant::now();

        loop {
            // ── inbound: TCP first, then the reliable fallback ──
            let t0 = std::time::Instant::now();
            let mut relays: Vec<Vec<u8>> = Vec::new();
            while let Some(msg) = transport.recv() {
                let mut state = DispatchState {
                    pending: &mut pending,
                    shard_sets: &mut shard_sets,
                    relays: &mut relays,
                    shard_k,
                    verify_budget: &mut verify_budget,
                };
                if let Some((v, vote)) = Self::dispatch_inbound(
                    &mut engine,
                    &mut state,
                    &msg.from,
                    &msg.bytes,
                    &mut t_commit,
                ) {
                    voted_views.insert(v);
                    Self::send_vote(
                        &mut engine,
                        &mut transport,
                        &inboxes,
                        &validator_set,
                        &my_id,
                        v,
                        vote,
                    );
                }
            }
            // A removed member's stale seat can collide with a live
            // member's inbox, and a phantom seat has no reader at
            // all — `.get` keeps both from panicking.
            let mut drained: VecDeque<(Vec<u8>, Vec<u8>)> = VecDeque::new();
            if let Some(inbox) = inboxes.get(me) {
                let mut guard = primitives::sync::lock_state(inbox);
                drained = std::mem::take(&mut *guard);
            }
            for (from, bytes) in drained {
                let mut state = DispatchState {
                    pending: &mut pending,
                    shard_sets: &mut shard_sets,
                    relays: &mut relays,
                    shard_k,
                    verify_budget: &mut verify_budget,
                };
                if let Some((v, vote)) =
                    Self::dispatch_inbound(&mut engine, &mut state, &from, &bytes, &mut t_commit)
                {
                    voted_views.insert(v);
                    Self::send_vote(
                        &mut engine,
                        &mut transport,
                        &inboxes,
                        &validator_set,
                        &my_id,
                        v,
                        vote,
                    );
                }
            }
            // Shard relays collected this pass — our assigned shard
            // goes to every peer once (it arrives back at us only via
            // no path: peers relay their own index only).
            for frame in relays {
                for peer in 0..n_committee {
                    if peer != me {
                        Self::wire_send(
                            &mut transport,
                            &inboxes,
                            &validator_set,
                            &my_id,
                            peer,
                            &frame,
                        );
                    }
                }
            }
            t_inbound += t0.elapsed();

            // ── propose: leader only, gated on high_qc like the sim ──
            let t0 = std::time::Instant::now();
            let view = engine.current_view().value();
            if !proposed_views.contains(&view)
                && usize::from(validator_set.leader(engine.current_view())) == me
                && (view == 0 || engine.high_qc().is_some())
                && let Some((header, proposal)) = engine.propose()
            {
                proposed_views.insert(view);
                // Dispersed broadcast (DispersedSimplex): encode
                // the body once, chunk it into n shards committed
                // by `header.body_commitment`, and send each peer
                // only its assigned shard + the header. Leader
                // egress is O(S) instead of O(n·S); validators
                // relay their own shard so everyone reassembles
                // the body off the vote critical path.
                let mut body = Vec::new();
                proposal.encode(&mut body);
                let (root, shards) = types::shard::disperse_body(&body, n_committee, shard_k);
                debug_assert_eq!(
                    root, header.body_commitment,
                    "engine and harness must compute the same body commitment"
                );
                for (peer, shard) in shards.iter().enumerate() {
                    if peer != me {
                        let mut frame = Vec::with_capacity(64 + shard.bytes.len());
                        frame.push(MSG_SHARD);
                        header.encode(&mut frame);
                        shard.encode(&mut frame);
                        Self::wire_send(
                            &mut transport,
                            &inboxes,
                            &validator_set,
                            &my_id,
                            peer,
                            &frame,
                        );
                    }
                }
                // The leader is also shard `me`'s owner: every
                // peer needs all n chunks to reconstruct, and
                // only the leader ever holds this one — it must
                // broadcast it exactly like peers relay theirs.
                // Skipping it leaves every peer's set at n-1
                // shards forever — notarization still races
                // ahead on commitments while nothing can ever
                // finalize (observed: commits=0 with unbounded
                // shard-set growth).
                let mut own = Vec::with_capacity(64 + shards[me].bytes.len());
                own.push(MSG_SHARD);
                header.encode(&mut own);
                shards[me].encode(&mut own);
                for peer in 0..n_committee {
                    if peer != me {
                        Self::wire_send(
                            &mut transport,
                            &inboxes,
                            &validator_set,
                            &my_id,
                            peer,
                            &own,
                        );
                    }
                }
                // Leader self-vote through the engine's single
                // signing path (C10): `vote()` records the locks
                // and appends the WAL before the signature
                // exists — the hand-built Vote + collect_vote it
                // replaces skipped durability entirely.
                if let Some(leader_vote) = engine.vote(&header, &proposal) {
                    let _ = engine.collect_vote(engine.validator_index(), leader_vote);
                    voted_views.insert(view);
                }
            }
            t_propose += t0.elapsed();

            // ── vote on pending proposals ──
            let t0 = std::time::Instant::now();
            // Entries here are future-view headers (queued on arrival
            // because we weren't at their view yet). `vote_header`
            // resolves whatever body state the engine already stored —
            // `Complete` from a full proposal or `Awaiting` from the
            // shard path — and emits the commitment vote when our
            // view has caught up. Stale entries (view passed while
            // they waited) are dropped; the stored state still serves
            // the commit walk.
            let current = engine.current_view().value();
            let pending_views: Vec<u64> = pending.keys().copied().collect();
            for v in pending_views {
                if voted_views.contains(&v) || v < current {
                    voted_views.insert(v);
                    pending.remove(&v);
                    continue;
                }
                if v > current {
                    continue;
                }
                let Some(header) = pending.get(&v) else { continue };
                if let Some(vote) = engine.vote_header(header) {
                    voted_views.insert(v);
                    Self::send_vote(
                        &mut engine,
                        &mut transport,
                        &inboxes,
                        &validator_set,
                        &my_id,
                        v,
                        vote,
                    );
                }
            }

            t_vote += t0.elapsed();

            // ── form QC: aggregate → broadcast → self-deliver ──
            let t0 = std::time::Instant::now();
            if let Some(qc) = engine.try_form_qc() {
                let mut frame = Vec::with_capacity(1 + 150);
                frame.push(MSG_QC);
                qc.encode(&mut frame);
                for peer in 0..n_committee {
                    if peer != me {
                        Self::wire_send(
                            &mut transport,
                            &inboxes,
                            &validator_set,
                            &my_id,
                            peer,
                            &frame,
                        );
                    }
                }
                engine.deliver_qc(qc).expect("leader self-deliver QC");
            }

            // ── advance on a fresh high_qc ──
            if let Some(hqc) = engine.high_qc()
                && hqc.view == engine.current_view()
            {
                engine.advance_view();
            }
            // Publish the view for the driver's submission pacing.
            view_out.store(engine.current_view().value(), Ordering::Relaxed);
            t_qc += t0.elapsed();

            // ── done bookkeeping ──
            let t0 = std::time::Instant::now();
            // Debug heartbeat: `THREADED_DEBUG=1` prints each
            // validator's position once per second — view, high_qc,
            // pending proposals, commits. The primary liveness
            // diagnostic for threaded runs.
            if debug && last_debug.elapsed() >= std::time::Duration::from_secs(1) {
                last_debug = std::time::Instant::now();
                eprintln!(
                    "  [v{me}] view={} highqc={:?} pending={} shards={} proposed={} voted={} commits={}",
                    engine.current_view().value(),
                    engine.high_qc().map(|q| q.view.value()),
                    pending.len(),
                    shard_sets.len(),
                    proposed_views.len(),
                    voted_views.len(),
                    primitives::sync::lock_state(&committed).len(),
                );
            }
            // Done = every submitted tx finalized. Gated on the
            // commit counter so the block-store mutex is only taken
            // when something actually committed since the last look —
            // the spin loop iterates ~35M times/run and the naive
            // always-lock version burned ~35% of every thread's time
            // here. Counted incrementally over newly committed blocks
            // so the check stays O(new blocks), not O(history).
            if !marked_done {
                // Snapshot BEFORE the lock: the listener bumps the
                // counter after pushing, so a seq observed here is
                // already visible under the mutex. Storing the
                // pre-lock snapshot (not a post-count reload) means a
                // commit landing mid-count re-triggers the check
                // next iteration instead of being folded invisibly.
                let seq_now = commit_seq.load(Ordering::Acquire);
                if seq_now != last_commit_seq {
                    let guard = primitives::sync::lock_state(&committed);
                    let new_txs: u64 = guard[counted_blocks..]
                        .iter()
                        .map(|b| u64::try_from(b.txs.len()).unwrap_or(u64::MAX))
                        .sum();
                    counted_blocks = guard.len();
                    finalized_txs += new_txs;
                    // Committed blocks can never need their bodies
                    // again — drop any straggling incomplete shard
                    // sets at/below the commit tip.
                    if let Some(tip) = guard.last().map(|b| b.height.value()) {
                        shard_sets.retain(|_, (_, h)| *h > tip);
                    }
                    drop(guard);
                    last_commit_seq = seq_now;
                    if finalized_txs >= target_txs {
                        marked_done = true;
                        global_done.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            t_done += t0.elapsed();
            if global_done.load(Ordering::Relaxed) == n_spawned || stop.load(Ordering::Relaxed) {
                break;
            }
            std::hint::spin_loop();
        }
        // Threaded profile: per-validator loop-time breakdown.
        // `commit` (inbound QC delivery → commit+execute) is the
        // hot path the single-threaded driver serialized; inbound
        // is everything else off the wire (proposal decode, vote,
        // fallback); the remainder is idle spin (waiting on peers).
        let total = loop_start.elapsed();
        eprintln!(
            "  [v{me}] threaded profile: total={:.1}ms inbound={:.1} commit={:.1} propose={:.1} vote={:.1} qc={:.1} done={:.1} idle={:.1}",
            total.as_secs_f64() * 1e3,
            t_inbound.as_secs_f64() * 1e3,
            t_commit.as_secs_f64() * 1e3,
            t_propose.as_secs_f64() * 1e3,
            t_vote.as_secs_f64() * 1e3,
            t_qc.as_secs_f64() * 1e3,
            t_done.as_secs_f64() * 1e3,
            total
                .saturating_sub(t_inbound)
                .saturating_sub(t_propose)
                .saturating_sub(t_vote)
                .saturating_sub(t_qc)
                .saturating_sub(t_done)
                .as_secs_f64()
                * 1e3,
        );
        (engine, transport)
    }

    /// Decode and deliver one inbound wire frame.
    ///
    /// `MSG_PROPOSAL` frames go straight through `engine.vote()`:
    /// the engine stores the authenticated body on arrival — the QC
    /// commit walk needs it even when the proposal lands too late to
    /// vote on (a QC frequently arrives first over a different
    /// network path) — and returns a `Vote` when we're already at
    /// the proposal's view. Future-view proposals queue into
    /// `pending` for the retry phase; stale ones are dropped (the
    /// stored body still serves the commit walk). Returns
    /// `(view, vote)` when a vote must go out to that view's leader.
    ///
    /// `MSG_VOTE` frames collect on the engine; `MSG_QC` frames
    /// deliver (idempotent — stale QCs are rejected inside
    /// `deliver_qc`). Malformed frames are dropped silently: this is
    /// a devnet harness, not the hardened production ingress path.
    /// `from` is the sender's authenticated peer id — the 20-byte
    /// staking address the handshake proved ownership of (or the
    /// sender id an inbox fallback entry claims — the fallback is
    /// trusted in-process plumbing, but the same `index_of`
    /// attribution applies). Vote/timeout attribution resolves it
    /// against the RECEIVER's live committee — a removed member's
    /// address resolves to nothing and its frames die here.
    // The match arms cover five frame types with per-arm rationale
    // comments — splitting them would scatter the intake contract.
    #[allow(clippy::too_many_lines)]
    fn dispatch_inbound(
        engine: &mut OxideBft,
        state: &mut DispatchState<'_>,
        from: &[u8],
        bytes: &[u8],
        t_commit: &mut std::time::Duration,
    ) -> Option<(u64, types::Vote)> {
        let (&tag, rest) = bytes.split_first()?;
        let mut reader = codec::Reader::new(rest);
        match tag {
            MSG_PROPOSAL => {
                let header = types::BlockHeader::decode(&mut reader).ok()?;
                let proposal = types::Proposal::decode(&mut reader).ok()?;
                // Intake gate before any crypto: outside the view
                // window or not the scheduled leader — dropped
                // without spending a verify. `vote()` re-checks
                // everything properly; this only keeps junk off the
                // expensive path (the binary pump applies the same
                // gate at its intake).
                if !engine.proposal_admissible(&header) {
                    return None;
                }
                let v = header.view.value();
                // Per-sender verify budget — same bound as the
                // binary pump: each distinct admissible frame costs
                // one BLS verify, so a flooding peer can only burn
                // its own quota; the leader's proposal arrives on a
                // different peer id and always verifies.
                let budget = state
                    .verify_budget
                    .entry(from.to_vec())
                    .or_insert((std::time::Instant::now(), 0));
                if budget.0.elapsed() >= std::time::Duration::from_secs(1) {
                    *budget = (std::time::Instant::now(), 0);
                }
                if budget.1 >= consensus::PROPOSAL_VERIFY_BUDGET_PER_SEC {
                    return None;
                }
                budget.1 += 1;
                // Authenticate before the pending slot is claimed —
                // `vote()` returns None both for a forged proposal
                // and for a future view, so a rejected junk header
                // would otherwise be queued here, parking the view's
                // retry slot and censoring the real proposal when it
                // arrives. `admit_proposal` verifies once and stores
                // the body, so `vote()` below hits the memoised
                // verdict instead of re-paying the BLS check.
                if !engine.admit_proposal(&header, &proposal) {
                    return None;
                }
                match engine.vote(&header, &proposal) {
                    Some(vote) => Some((v, vote)),
                    // Future view: queue for the retry phase — the
                    // body is stored, only the vote waits for our
                    // view to catch up.
                    None if v >= engine.current_view().value() => {
                        state.pending.entry(v).or_insert(header);
                        None
                    }
                    // Stale: body stored, no vote possible or needed.
                    None => None,
                }
            }
            // Dispersed broadcast: one body shard + the signed header.
            // The validator (a) verifies its own shard's inclusion
            // proof against `header.body_commitment`, (b) notarizes
            // the commitment immediately — the full body is *not*
            // required to vote, and (c) relays the shard to peers iff
            // it is our leader-assigned shard (index == me). Bodies
            // reconstruct incrementally as peer relays arrive; once a
            // set is complete it is certified by `supply_body` and can
            // finalize — the DispersedSimplex certify gate.
            MSG_SHARD => {
                let header = types::BlockHeader::decode(&mut reader).ok()?;
                let shard = types::shard::Shard::decode(&mut reader).ok()?;
                // Window/leader gate first — free compared to even
                // the shard hash check, and it bounds `shard_sets`
                // and `pending` to in-window block hashes so a junk
                // shard flood cannot grow either map unboundedly.
                if !engine.proposal_admissible(&header) {
                    return None;
                }
                // Commitment check next — cheap (~4 hashes) and does
                // not depend on header authenticity; garbage shards
                // are dropped before any BLS work.
                if !types::shard::verify_shard(&header.body_commitment, &shard) {
                    return None;
                }
                let block_hash = OxideBft::block_hash(&header);
                // The relay-ownership check compares the shard's
                // committee seat against OUR live seat — the engine's
                // re-seated index, so a rotation can't make us relay
                // another member's shard.
                let is_mine = shard.index == u32::from(engine.validator_index());
                // On the first shard seen for a block, authenticate
                // and vote on the commitment — `vote_header` also
                // stores the header as `Awaiting`, which `supply_body`
                // requires later regardless of whether a vote emits.
                // Subsequent shards skip the BLS work.
                let vote_out = if state.shard_sets.contains_key(&block_hash) {
                    None
                } else {
                    let v = header.view.value();
                    match engine.vote_header(&header) {
                        Some(vote) => Some((v, vote)),
                        // Queue only if the header actually
                        // authenticated into `blocks` — `vote_header`
                        // returns None for a forged header too, and
                        // queuing that would park the view's retry
                        // slot, censoring the genuine proposal that
                        // arrives after it.
                        None if v >= engine.current_view().value()
                            && engine.proposal_known(&block_hash) =>
                        {
                            state.pending.entry(v).or_insert(header.clone());
                            None
                        }
                        None => None,
                    }
                };
                // Accumulate the shard — even for views we can't vote
                // on yet: the body must exist before this block can
                // ever commit.
                let entry = state.shard_sets.entry(block_hash).or_insert_with(|| {
                    (
                        types::shard::ShardSet::new(
                            usize::try_from(shard.total).unwrap_or(0),
                            state.shard_k,
                        ),
                        header.height.value(),
                    )
                });
                // `insert` returns true exactly once — when this
                // shard completes the set.
                if entry.0.insert(shard)
                    && let Some((set, _)) = state.shard_sets.remove(&block_hash)
                    && let Some(body) = set.reconstruct()
                    && let Ok(proposal) = types::Proposal::decode(&mut codec::Reader::new(&body))
                {
                    let t0 = std::time::Instant::now();
                    let _ = engine.supply_body(block_hash, &proposal);
                    *t_commit += t0.elapsed();
                }
                // Relay our leader-assigned shard — each validator
                // forwards only the shard the leader sent *it*, so
                // every shard traverses exactly one extra hop.
                if is_mine {
                    state.relays.push(bytes.to_vec());
                }
                vote_out
            }
            MSG_VOTE => {
                if let Ok(vote) = types::Vote::decode(&mut reader) {
                    // Attribute by authenticated address → committee
                    // seat. A peer whose address is not in OUR set
                    // (removed, or never a member) collects nothing.
                    let voter = <[u8; 20]>::try_from(from)
                        .map(primitives::Address)
                        .ok()
                        .and_then(|a| engine.validator_set().index_of(&a));
                    if let Some(voter_idx) = voter {
                        let _ = engine.collect_vote(voter_idx, vote);
                    }
                }
                None
            }
            MSG_QC => {
                if let Ok(qc) = types::QuorumCertificate::decode(&mut reader) {
                    // deliver_qc runs the commit walk — finalize_block
                    // executes the payload — the dominant per-validator
                    // cost. Timed separately so the profile splits
                    // "execution" from "everything else off the wire".
                    let t0 = std::time::Instant::now();
                    let _ = engine.deliver_qc(qc);
                    *t_commit += t0.elapsed();
                }
                None
            }
            _ => None,
        }
    }

    /// Route a produced vote to the leader of its view — direct
    /// `collect_vote` when we are that leader, else a `MSG_VOTE`
    /// frame over the wire/fallback mesh.
    ///
    /// `my_id` is this thread's peer id (its staking-address bytes) —
    /// the `from` a fallback inbox entry carries. The self-collect
    /// check compares the leader seat against the engine's own
    /// re-seated index, so a rotated committee can't strand votes.
    fn send_vote(
        engine: &mut OxideBft,
        transport: &mut p2p::tcp::TcpTransport,
        inboxes: &Inboxes,
        validator_set: &ValidatorSet,
        my_id: &[u8],
        view: u64,
        vote: types::Vote,
    ) {
        let leader_idx = usize::from(validator_set.leader(primitives::View::new(view)));
        if leader_idx == usize::from(engine.validator_index()) {
            let _ = engine.collect_vote(engine.validator_index(), vote);
            return;
        }
        let mut frame = Vec::with_capacity(1 + 137);
        frame.push(MSG_VOTE);
        vote.encode(&mut frame);
        Self::wire_send(transport, inboxes, validator_set, my_id, leader_idx, &frame);
    }

    /// Send one wire frame to a committee seat: TCP first, fallback
    /// queue on failure.
    ///
    /// `to_seat` is a committee index — resolved to its staking
    /// address (the transport peer id) via `validator_set`, so the
    /// destination follows the live committee across reshuffles.
    /// `my_id` is the sender's peer id, recorded in the fallback
    /// entry as `from`.
    ///
    /// `TcpTransport::send` is `try_send` into a bounded per-peer
    /// writer channel — `ChannelFull`/`ChannelClosed` drop the frame.
    /// Those go into the receiver's shared inbox instead, which its
    /// thread drains every loop. Cross-path reordering is tolerated
    /// by the engine (idempotent delivery + ancestor-walk commit).
    /// A seat with no inbox (phantom member) and no transport drops
    /// the frame — the same outcome as a crashed validator's peers.
    fn wire_send(
        transport: &mut p2p::tcp::TcpTransport,
        inboxes: &Inboxes,
        validator_set: &ValidatorSet,
        my_id: &[u8],
        to_seat: usize,
        bytes: &[u8],
    ) {
        let Some(to_addr) = validator_set.validator_addresses().get(to_seat) else {
            return;
        };
        if transport.send(&to_addr.0.to_vec(), bytes).is_err()
            && let Some(inbox) = inboxes.get(to_seat)
        {
            primitives::sync::lock_state(inbox).push_back((my_id.to_vec(), bytes.to_vec()));
        }
    }

    /// Print a progress report for the pipelined TPS run.
    ///
    /// Extracted from `run_pipelined_txs` to keep that function under
    /// the 100-line clippy limit. All `u64 → f64` casts are in this
    /// cold-path diagnostic only — they are not on any hot path.
    #[allow(clippy::cast_precision_loss)]
    fn report_progress(
        blocks_done: u64,
        txs_per_round: usize,
        needed: usize,
        target_blocks: u64,
        start: &std::time::Instant,
    ) {
        let txs_done = blocks_done * txs_per_round as u64;
        let elapsed = start.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { txs_done as f64 / elapsed } else { 0.0 };
        let pct =
            if target_blocks > 0 { blocks_done as f64 / target_blocks as f64 * 100.0 } else { 0.0 };
        eprintln!(
            "  progress: {txs_done}/{needed} txs ({pct:.1}%) — {blocks_done}/{target_blocks} blocks — {rate:.0} tx/s — {elapsed:.1}s elapsed"
        );
    }

    /// Submit one round's worth of txs to the leader's intake,
    /// draining the intake via pipelined ticks when it's full.
    ///
    /// Submits in BATCHES through `submit_txs` — the executor's
    /// parallel intake path (secp256k1 recovery fanned across cores,
    /// ~43µs/tx serial → ~12µs/tx effective). The old per-tx
    /// `submit_tx` loop was 60% of the whole pipelined run's wall
    /// clock in the 10k EVM load test; this is the harness matching
    /// the deployment shape (RPC clients batch).
    ///
    /// Returns the next tx index after the submitted round.
    fn submit_round_txs(
        &mut self,
        leader_idx: usize,
        txs_per_round: usize,
        txs: &[TxBytes],
        state: &mut PipelineState,
        view_cap: u64,
        deadline: std::time::Instant,
    ) -> usize {
        let mut tx_idx = 0;
        // A phantom member (validator_add without a spawned engine)
        // has no mempool — its round's txs simply never land, which
        // is the same outcome as a crashed leader. `engine_pos`
        // resolves the seat to the engine actually holding it — a
        // removal reshuffles indices, so the leader seat is no
        // longer `engines[leader_idx]`.
        let Some(leader_pos) = self.engine_pos(leader_idx) else {
            return txs_per_round;
        };
        // Batch size: the whole remaining round in one call — the
        // intake ring bounds admission, so an oversized batch
        // back-pressures via `Rejected` acks and the retry loop
        // below drains it. `try_send` fails only once the ring is
        // full, so within one batch the accepted acks are a PREFIX
        // and the rejected acks a contiguous suffix — advancing by
        // the accepted count and retrying the tail is exact.
        while tx_idx < txs_per_round {
            let remaining = txs_per_round - tx_idx;
            let batch: Vec<TxBytes> = txs[tx_idx..tx_idx + remaining].to_vec();
            let acks = self.engines[leader_pos].submit_txs(batch);
            let accepted =
                acks.iter().take_while(|a| matches!(a, types::MempoolAck::Accepted)).count();
            tx_idx += accepted;
            if accepted < remaining {
                // Intake ring full — run the pipeline for multiple
                // ticks to drain it, then retry the rejected tail.
                for _ in 0..64 {
                    self.pipelined_tick(state, view_cap);
                    if std::time::Instant::now() > deadline {
                        break;
                    }
                }
            }
        }
        tx_idx
    }

    /// One tick of the pipelined event loop.
    ///
    /// Each tick runs five phases: propose, vote, drain, form QC,
    /// advance views. The `state` tracks proposals, votes, and QCs
    /// across ticks. The `view_cap` limits which views may be proposed
    /// (the main loop caps at `target_blocks`; the flush loop uses
    /// `u64::MAX`).
    fn pipelined_tick(&mut self, state: &mut PipelineState, view_cap: u64) {
        let mut t = std::time::Instant::now();
        self.propose_phase(state, view_cap);
        state.timers.propose += t.elapsed();

        t = std::time::Instant::now();
        self.vote_phase(state);
        state.timers.vote += t.elapsed();

        t = std::time::Instant::now();
        state.compact_proposals(self.n);
        state.timers.compact += t.elapsed();

        t = std::time::Instant::now();
        self.drain_transports();
        state.timers.drain += t.elapsed();

        // `form_qc_phase` times its own halves (`qc_form` vs
        // `qc_deliver`) — the deliver sub-loop is where commits and
        // execution land, so it needs the split.
        self.form_qc_phase(state);

        t = std::time::Instant::now();
        self.advance_views_phase();
        state.timers.advance += t.elapsed();

        state.timers.ticks += 1;
    }

    /// Phase 1: any leader with the `high_qc` that hasn't proposed yet.
    fn propose_phase(&mut self, state: &mut PipelineState, view_cap: u64) {
        // `propose()` must run on the engine that ADDRESS-VERIFIES
        // as the seat holder — a removed member keeps a stale index
        // that can collide with a live member's new seat, and letting
        // it claim `proposed_views` first would park the view on a
        // proposal no peer can verify (a self-inflicted censorship).
        // `seat_holder[seat]` = spawn position of the engine whose
        // address the committee still lists at `seat` — precomputed
        // because `engine_pos` borrows `self` while the loop below
        // holds `self.engines` mutably.
        let seat_holder: Vec<Option<usize>> =
            (0..self.validator_set.n()).map(|seat| self.engine_pos(seat)).collect();
        for (i, engine) in self.engines.iter_mut().enumerate() {
            let view = engine.current_view().value();
            if view >= view_cap || state.proposed_views.contains(&view) {
                continue;
            }
            let leader_idx = usize::from(self.validator_set.leader(engine.current_view()));
            if seat_holder.get(leader_idx) != Some(&Some(i)) {
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
    ///
    /// Votes are delivered two ways (same as QC delivery):
    /// 1. **In-process** (reliable): the vote is collected directly on
    ///    the leader's engine. This is the authoritative path.
    /// 2. **TCP** (best-effort): the vote is sent via the transport
    ///    for realism. TCP delivery may fail during reconnects; the
    ///    in-process path ensures liveness regardless.
    fn vote_phase(&mut self, state: &mut PipelineState) {
        // Collect votes to deliver in-process after the loop (avoid
        // borrow conflicts — can't collect on another engine while
        // iterating `self.engines` mutably).
        let mut votes_to_collect: Vec<(usize, u16, types::Vote)> = Vec::new();

        for (i, engine) in self.engines.iter_mut().enumerate() {
            // `my_seat` is this engine's CURRENT committee index —
            // re-seated by key at each rotation, `u16::MAX`-stale for
            // a removed member. Role checks compare it, never the
            // spawn position.
            let my_seat = usize::from(engine.validator_index());
            for (header, proposal) in &state.proposals {
                let view = header.view.value();
                if state.voted.contains(&(i, view)) {
                    continue;
                }
                let leader_idx = usize::from(self.validator_set.leader(header.view));
                if my_seat == leader_idx {
                    // Leader self-votes through `engine.vote()` —
                    // the single signing authority (C10): the vote
                    // locks and WAL append precede the signature,
                    // exactly as for followers.
                    if let Some(leader_vote) = engine.vote(header, proposal) {
                        let _ = engine.collect_vote(engine.validator_index(), leader_vote);
                        state.voted.insert((i, view));
                    }
                } else if let Some(vote) = engine.vote(header, proposal) {
                    let mut buf = Vec::with_capacity(1 + 137);
                    buf.push(MSG_VOTE);
                    vote.encode(&mut buf);
                    // Best-effort TCP send to the leader's peer id —
                    // its staking address under the live committee.
                    // Failures are tolerated — the in-process delivery
                    // below is authoritative.
                    if let Some(leader_addr) =
                        self.validator_set.validator_addresses().get(leader_idx)
                    {
                        let _ = self.transports[i].send(&leader_addr.0.to_vec(), &buf);
                    }
                    // In-process vote delivery: collect the vote
                    // directly on the leader's engine. This ensures
                    // the vote is received even if TCP drops it. The
                    // voter index is the engine's seat — post-rotation
                    // it is NOT the spawn position.
                    votes_to_collect.push((leader_idx, engine.validator_index(), vote));
                    state.voted.insert((i, view));
                }
            }
        }

        // In-process vote delivery: collect all votes formed this
        // tick on their respective leader engines. `engine_pos`
        // resolves seat → position: a phantom member (validator_add
        // without a spawned engine) resolves to None — its votes are
        // simply lost, which is the same outcome as a crashed
        // validator.
        for (leader_idx, voter_idx, vote) in votes_to_collect {
            if let Some(pos) = self.engine_pos(leader_idx) {
                let _ = self.engines[pos].collect_vote(voter_idx, vote);
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
                            // Attribute by the authenticated
                            // staking-address peer id → seat in the
                            // receiver's live committee. A removed
                            // member's frames resolve to nothing.
                            let voter = <[u8; 20]>::try_from(msg.from.as_slice())
                                .map(primitives::Address)
                                .ok()
                                .and_then(|a| self.engines[i].validator_set().index_of(&a));
                            if let Some(voter_idx) = voter {
                                let _ = self.engines[i].collect_vote(voter_idx, vote);
                            }
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
    ///
    /// QCs are delivered two ways:
    /// 1. **In-process** (reliable): the QC is delivered directly to
    ///    every engine's `deliver_qc`. This is the authoritative path
    ///    for the in-process devnet — it guarantees the QC is received
    ///    even if the TCP transport drops a connection.
    /// 2. **TCP** (best-effort): the QC is broadcast via the transport
    ///    for realism. TCP delivery may fail during reconnects; the
    ///    in-process path ensures liveness regardless.
    ///
    /// The TCP-only path was the original design, but it has a
    /// liveness bug: if a TCP connection drops (e.g., due to a
    /// transient I/O error), the QC is silently dropped, and the
    /// validators that miss it can't advance their views. The leader
    /// for the next view is stuck at the old view and can't propose.
    /// The pipeline deadlocks at 0% CPU. The in-process delivery
    /// eliminates this failure mode for the devnet harness.
    fn form_qc_phase(&mut self, state: &mut PipelineState) {
        let t_form = std::time::Instant::now();
        // Collect QCs formed this tick. We deliver them in-process
        // after the loop to avoid borrow conflicts (can't deliver to
        // other engines while iterating `self.engines` mutably).
        let mut qcs_to_deliver: Vec<types::QuorumCertificate> = Vec::new();
        let committee_addrs = self.validator_set.validator_addresses().to_vec();
        let my_addrs: Vec<Vec<u8>> = self.validator_addrs.iter().map(|a| a.0.to_vec()).collect();
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if let Some(qc) = engine.try_form_qc() {
                state.qcs_formed += 1;
                let mut qc_buf = Vec::with_capacity(1 + 150);
                qc_buf.push(MSG_QC);
                qc.encode(&mut qc_buf);
                // Broadcast to every committee member except us —
                // addressed by staking-address peer id, so a rotated
                // committee's members are reached, not whoever holds
                // the genesis slots now.
                for addr in &committee_addrs {
                    if addr.0.as_slice() != my_addrs[i].as_slice() {
                        // Best-effort TCP broadcast. Failures are
                        // tolerated — the in-process delivery below
                        // is the authoritative path.
                        let _ = self.transports[i].send(&addr.0.to_vec(), &qc_buf);
                    }
                }
                // Self-deliver: the leader that formed the QC must
                // also receive it to advance its own view.
                engine.deliver_qc(qc.clone()).expect("leader self-deliver QC");
                qcs_to_deliver.push(qc);
            }
        }
        state.timers.qc_form += t_form.elapsed();

        // In-process delivery: deliver every QC formed this tick to
        // every engine. This is the reliable path — TCP is best-effort.
        // `deliver_qc` is idempotent for stale QCs — it rejects QCs
        // with view <= high_qc.view, so delivering to the engine that
        // already has it is a no-op.
        //
        // This loop is where block commits and transaction execution
        // land (`deliver_qc` → `commit_block` → `finalize_block`), so
        // it gets its own timer — it is typically the dominant phase.
        let t_deliver = std::time::Instant::now();
        for qc in &qcs_to_deliver {
            for engine in &mut self.engines {
                let _ = engine.deliver_qc(qc.clone());
            }
        }
        state.timers.qc_deliver += t_deliver.elapsed();
    }

    /// Phase 5: advance views for engines with a `high_qc`, sync heights.
    fn advance_views_phase(&mut self) {
        for engine in &mut self.engines {
            if let Some(hqc) = engine.high_qc()
                && hqc.view == engine.current_view()
            {
                engine.advance_view();
            }
        }
        let max_height = self.engines.iter().map(OxideBft::next_height_value).max().unwrap_or(0);
        for engine in &mut self.engines {
            engine.sync_next_height(max_height);
        }
    }

    /// Timeout-path advance for all engines: collect every
    /// validator's real timeout signature into a TC, which each
    /// engine then records as the view-change evidence (`last_tc`)
    /// so the next leader's proposal carries legitimate-successor
    /// proof — required for same-height lock release after a failed
    /// view.
    fn timeout_advance_all(&mut self) {
        let sigs: Vec<crypto::bls::Signature> = self
            .engines
            .iter_mut()
            .map(|e| e.on_timeout().unwrap_or(crypto::bls::Signature::ZERO))
            .collect();
        let evidences: Vec<Option<types::QuorumCertificate>> =
            self.engines.iter().map(|e| e.high_qc().cloned()).collect();
        // Each signature is collected under its signer's CURRENT seat
        // — resolved by staking address, so a removed member (whose
        // address is no longer in the set) contributes nothing rather
        // than stamping another member's timeout slot with a
        // signature that cannot verify.
        let signer_seats: Vec<Option<u16>> =
            self.validator_addrs.iter().map(|addr| self.validator_set.index_of(addr)).collect();
        for engine in &mut self.engines {
            for (signer, sig) in sigs.iter().enumerate() {
                let Some(seat) = signer_seats[signer] else { continue };
                let _ = engine.collect_timeout_signature(seat, *sig, evidences[signer].clone());
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
        let leader_addr =
            self.validator_set.validator_addresses().get(leader_idx).map(|a| a.0.to_vec());

        // Leader proposes (direct — proposal broadcast is a separate
        // layer). If the leader can't propose, the view times out.
        // A `None` position means the seat is a phantom member
        // (validator_add without a spawned engine) — the phantom
        // leader can't propose, so the view times out and advances
        // to a live one. `engine_pos` resolves the seat to the
        // engine holding it: post-rotation, `engines[leader_idx]`
        // can name the member that MOVED INTO the leader's old
        // index or a removed member's stale seat.
        let Some(leader_pos) = self.engine_pos(leader_idx) else {
            self.timeout_advance_all();
            return;
        };
        let Some((header, proposal)) = self.engines[leader_pos].propose() else {
            self.timeout_advance_all();
            return;
        };
        // Leader self-votes through the engine's single signing
        // path (C10): `vote()` records the locks and appends the
        // WAL before the signature exists. If the engine withholds
        // (e.g. WAL failure), the view simply times out — the same
        // outcome as a crashed leader.
        if let Some(leader_vote) = self.engines[leader_pos].vote(&header, &proposal) {
            let seat = self.engines[leader_pos].validator_index();
            self.engines[leader_pos]
                .collect_vote(seat, leader_vote)
                .expect("leader self-vote must verify");
        }

        // Followers vote via TCP: each follower encodes its vote and
        // sends it to the leader's staking-address peer id.
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if i == leader_pos {
                continue;
            }
            if let Some(vote) = engine.vote(&header, &proposal) {
                let mut buf = Vec::new();
                vote.encode(&mut buf);
                // Tolerate transient send failure (peer mid-reconnect)
                // — a dropped vote stalls this view into a timeout,
                // which is the intended fault-injection behavior.
                if let Some(ref addr) = leader_addr {
                    let _ = self.transports[i].send(addr, &buf);
                }
            }
        }

        // Leader receives votes via TCP, decodes, collects —
        // attributed by the authenticated staking-address peer id
        // resolved to a seat in the leader's live committee.
        let mut votes_received = 0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while votes_received < self.validator_set.n() - 1 && std::time::Instant::now() < deadline {
            if let Some(msg) = self.transports[leader_pos].recv() {
                let mut reader = codec::Reader::new(&msg.bytes);
                if let Ok(vote) = types::Vote::decode(&mut reader) {
                    let voter = <[u8; 20]>::try_from(msg.from.as_slice())
                        .map(primitives::Address)
                        .ok()
                        .and_then(|a| self.engines[leader_pos].validator_set().index_of(&a));
                    if let Some(voter) = voter {
                        let _ = self.engines[leader_pos].collect_vote(voter, vote);
                        votes_received += 1;
                    }
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        // Leader forms QC. No quorum → the view timed out: run the
        // real TC path so locked voters can re-vote the failed
        // height next view.
        let Some(qc) = self.engines[leader_pos].try_form_qc() else {
            self.timeout_advance_all();
            return;
        };

        // Leader broadcasts QC via TCP — every committee member's
        // address except the leader's own.
        let mut qc_buf = Vec::new();
        qc.encode(&mut qc_buf);
        let leader_own = self.validator_addrs[leader_pos].0.to_vec();
        for addr in self.validator_set.validator_addresses() {
            if addr.0.as_slice() != leader_own.as_slice() {
                // Tolerate transient send failure (peer mid-reconnect).
                let _ = self.transports[leader_pos].send(&addr.0.to_vec(), &qc_buf);
            }
        }

        // Followers receive QC via TCP, decode, deliver.
        for (i, engine) in self.engines.iter_mut().enumerate() {
            if i == leader_pos {
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
    ///
    /// Uses the `committed_blocks` vectors populated by the commit
    /// listeners — the engine's `finalized` map prunes at
    /// `MAX_RETAINED_FINALIZED` (4096), so iterating `0..=height`
    /// misses pruned blocks on long-running tests.
    fn collect_result(&self) -> TcpDevnetResult {
        // The async execution lane may still be applying the tail
        // blocks: drain it so post-run assertions observe executed
        // state, not just committed state.
        self.drain_execution();
        let finalized =
            self.committed_blocks.iter().map(|v| primitives::sync::lock_state(v).clone()).collect();
        TcpDevnetResult { finalized }
    }

    /// Drain pending validator key changes from the staking module
    /// and schedule an epoch rotation. Returns the number of key
    /// changes applied.
    ///
    /// The key-change flow:
    /// 1. A `KEY_CHANGE` tx is finalized → the staking module
    ///    records it in `pending_key_changes`.
    /// 2. `take_pending_key_changes` drains the map from the first
    ///    app's executor (all apps execute the same blocks, so they
    ///    all see the same changes).
    /// 3. `apply_key_changes` builds an updated `ValidatorSet` and
    ///    calls `schedule_rotation` on each engine.
    /// 4. `rotate_epoch` completes the handoff — the new keys take
    ///    effect for the next epoch.
    ///
    /// Called after `run_pipelined` or `run_pipelined_txs` — reads
    /// the first app's pending changes.
    pub fn rotate_epoch_with_key_changes(&mut self) -> usize {
        let changes = self.apps[0].take_pending_key_changes();
        if changes.is_empty() {
            return 0;
        }
        let mut applied = 0;
        for engine in &mut self.engines {
            match engine.apply_key_changes(&changes) {
                Ok(n) => applied = n,
                Err(e) => {
                    eprintln!("key-change apply failed: {e}");
                }
            }
        }
        if applied > 0 {
            for engine in &mut self.engines {
                let _ = engine.rotate_epoch();
            }
            // Update the devnet's copy of the validator set — the
            // engines' sets were rotated, and `self.validator_set`
            // must match for `leader()` lookups to stay correct.
            self.validator_set = self.engines[0].validator_set().clone();
            // Publish the rotated committee into every node's live
            // auth set — a removed member's handshake proofs stop
            // verifying the moment its address leaves the set.
            self.publish_auth_sets();
        }
        applied
    }

    /// Take pending validator additions and removals from the first
    /// app, apply them to every engine's validator set, rotate the
    /// epoch, and update the devnet's own `ValidatorSet` copy.
    ///
    /// Returns the number of changes applied (adds + removes).
    /// Returns 0 if no changes are pending.
    pub fn rotate_epoch_with_validator_changes(&mut self) -> usize {
        let changes = self.apps[0].take_pending_validator_changes();
        if changes.is_empty() {
            return 0;
        }
        let mut applied = 0;
        for engine in &mut self.engines {
            match engine.apply_validator_changes(&changes.adds, &changes.removes) {
                Ok(n) => applied = n,
                Err(e) => {
                    eprintln!("validator-change apply failed: {e}");
                }
            }
        }
        if applied > 0 {
            for engine in &mut self.engines {
                let _ = engine.rotate_epoch();
            }
            self.validator_set = self.engines[0].validator_set().clone();
            self.publish_auth_sets();
        }
        applied
    }

    /// Push each engine's current validator set into the shared
    /// `RwLock` its `BlsPeerAuth` reads — handshake verification
    /// follows the rotated committee without a transport restart.
    /// Pending slots are cleared — the harness force-completes
    /// rotations, so post-rotation no schedule→activation window
    /// exists (the window itself is exercised by the engine unit
    /// tests and the binary pump).
    fn publish_auth_sets(&mut self) {
        for (i, engine) in self.engines.iter().enumerate() {
            if let Some(live) = self.live_sets.get(i)
                && let Ok(mut guard) = live.write()
            {
                *guard = engine.validator_set().clone();
            }
            if let Some(pending) = self.pending_sets.get(i)
                && let Ok(mut guard) = pending.write()
            {
                *guard = None;
            }
        }
    }
}

/// Construct a deterministic BLS secret key from a single byte.
fn bls_key(byte: u8) -> crypto::BlsSecretKey {
    let ikm = vec![byte; 32];
    crypto::BlsSecretKey::from_ikm(&ikm).expect("BLS key generation from valid IKM")
}

/// Construct a staking-delegate tx for batch throughput testing.
/// Delegation bonds 1 unit to `identity_addr(0)` (registered in the
/// constructor), exercising the real EVM-ledger transfer path.
fn make_batch_tx(round: usize, tx_i: usize) -> TxBytes {
    let nonce = u64::try_from(round * 1000 + tx_i).unwrap();
    let fee = 100u64;
    let module_payload = staking::msg::delegate(txs::identity_addr(0), 1);
    txs::signed_tx(0, nonce, fee, framework::module_id::STAKING, &module_payload)
}

/// Build a signed staking-module tx from devnet identity 0 — the
/// registered validator and default sender (genesis-funded).
#[cfg(test)]
fn make_staking_tx(module_payload: &[u8], nonce: u64) -> TxBytes {
    make_staking_tx_from(0, module_payload, nonce)
}

/// Build a signed staking-module tx from devnet identity `idx` —
/// the sender is `txs::identity_addr(idx)`. Committee endorsement
/// tests need txs from *different* validators — the identity must
/// carry a genesis balance for fee payment (the devnet prefunds
/// identities `< 32`).
#[cfg(test)]
fn make_staking_tx_from(idx: u8, module_payload: &[u8], nonce: u64) -> TxBytes {
    let fee = 100u64;
    txs::signed_tx(idx, nonce, fee, framework::module_id::STAKING, module_payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end validator key rotation: submit a `KEY_CHANGE` tx,
    /// finalize it, apply the rotation, verify the new key is active.
    ///
    /// Exercises the full flow: `staking::msg::key_change` →
    /// `handle_key_change` → `pending_key_changes` →
    /// `take_pending_key_changes` → `apply_key_changes` →
    /// `schedule_rotation` → `rotate_epoch`.
    #[test]
    fn tcp_multinode_key_rotation() {
        let mut devnet =
            TcpMultiNodeDevnet::with_base_port(4, 10_000, crate::test_ports::reserve(10));

        // Record the original key for validator 0.
        let original_key = *devnet.validator_set().validator(0).expect("validator 0");

        // Build a key-change tx for validator 0 (devnet identity 0
        // — `txs::identity_addr(0)`). The delegate
        // must come first so `handle_key_change` accepts the tx.
        // The new key carries its proof-of-possession — required
        // since C3 made PoP admission mandatory (rogue-key defense).
        let new_sk = bls_key(0xAA);
        let new_key_bytes = new_sk.public_key().as_bytes().to_vec();
        let pop = new_sk.pop_prove();
        let delegate_msg = staking::msg::delegate(txs::identity_addr(0), 1);
        let key_change_msg =
            staking::msg::key_change(txs::identity_addr(0), &new_key_bytes, pop.as_bytes());

        // Submit both txs to the first app's mempool — they'll be
        // included in the next block.
        devnet.apps[0].ingest_tx(make_staking_tx(&delegate_msg, 0));
        devnet.apps[0].ingest_tx(make_staking_tx(&key_change_msg, 1));

        // Run a few rounds to finalize both txs.
        devnet.run_batch(3, 0);

        // Apply the pending key change — should find 1 change for
        // validator 0 (identity_addr(0) → index 0).
        let applied = devnet.rotate_epoch_with_key_changes();
        assert_eq!(applied, 1, "one key change should be applied");

        // The new key is active for validator 0.
        let new_key = *devnet.validator_set().validator(0).expect("validator 0");
        assert_eq!(new_key.as_bytes(), new_key_bytes.as_slice(), "validator 0 key must be rotated");
        assert_ne!(new_key, original_key, "key must have changed");

        // The staking address is preserved (identity survives rotation).
        assert_eq!(
            devnet.validator_set().validator_addresses()[0],
            txs::identity_addr(0),
            "staking address must be preserved across key rotation",
        );
    }

    /// End-to-end validator add + remove: submit `VALIDATOR_ADD` and
    /// `VALIDATOR_REMOVE` txs, finalize them, apply the epoch
    /// rotation, verify the set grew and shrank.
    ///
    /// Exercises the full flow: `staking::msg::validator_add` →
    /// `handle_validator_add` → `pending_validator_adds` →
    /// `take_pending_validator_changes` → `apply_validator_changes` →
    /// `schedule_rotation` → `rotate_epoch`. Then the same for
    /// `validator_remove`.
    #[test]
    fn tcp_multinode_validator_add_remove() {
        let mut devnet =
            TcpMultiNodeDevnet::with_base_port(4, 10_000, crate::test_ports::reserve(10));
        let initial_n = devnet.validator_set().n();

        // Identity 0 must be a validator (have stake) to submit
        // governance txs — delegate first. With it the only
        // powered committee member, its endorsement alone is the
        // two-thirds quorum (1·3 > 1·2).
        let delegate_msg = staking::msg::delegate(txs::identity_addr(0), 1);
        devnet.apps[0].ingest_tx(make_staking_tx(&delegate_msg, 0));
        devnet.run_batch(2, 0);

        // Submit a validator_add endorsement for a new validator.
        // The candidate's address must be (a) one of the 32
        // prefunded senders so it can pay fees and cast its own
        // endorsement later, and (b) OUTSIDE the engine identity
        // range — engine i already holds `identity_addr(i)` in the
        // ValidatorSet, so 0..n would collide at apply time.
        // `identity_addr(9)` satisfies both (funded: `num_senders`
        // is 32).
        // Bonded stake stays at 1 — the devnet does not
        // spawn an engine for the added validator, so its voting
        // power must stay below the quorum the existing 4 engines
        // can reach on their own: with [1,1,1,1,1] the power quorum
        // is 4 and progress continues with the new validator
        // offline. A large stake here would (correctly) halt the
        // chain — the dominant validator would be required for
        // every quorum.
        let new_sk = bls_key(0xAA);
        let new_key = new_sk.public_key();
        let pop = new_sk.pop_prove();
        let new_addr = txs::identity_addr(9);
        let add_msg = staking::msg::validator_add(new_addr, new_key.as_bytes(), pop.as_bytes());
        devnet.apps[0].ingest_tx(make_staking_tx(&add_msg, 1));
        devnet.run_batch(3, 0);

        // C9 bonded admission: the quorum-admitted candidate
        // carries no stake until collateral is bonded to it — the
        // delegate debits a funded account, which is the collateral
        // proof the rotation requires.
        let bond_msg = staking::msg::delegate(new_addr, 1);
        devnet.apps[0].ingest_tx(make_staking_tx(&bond_msg, 2));
        devnet.run_batch(3, 0);

        // Apply the pending validator change — should add 1 validator.
        let applied = devnet.rotate_epoch_with_validator_changes();
        assert_eq!(applied, 1, "one validator add should be applied");
        assert_eq!(devnet.validator_set().n(), initial_n + 1, "validator set must grow by 1");

        // The new validator's key and address are in the set.
        let new_idx =
            devnet.validator_set().index_of(&new_addr).expect("new validator must be in set");
        assert_eq!(
            devnet.validator_set().validator(new_idx).expect("new validator key").as_bytes(),
            new_key.as_bytes(),
            "new validator's BLS key must match",
        );

        // Now remove the new validator — committee quorum is two
        // endorsements once the candidate is powered (power 1 of
        // total 2 each). ZERO's endorsement alone is below quorum.
        // With a 5-member set apps[0] leads every fifth view, so
        // the batch runs five rounds to guarantee its mempool txs
        // are proposed.
        let remove_msg = staking::msg::validator_remove(new_addr);
        devnet.apps[0].ingest_tx(make_staking_tx(&remove_msg, 3));
        devnet.run_batch(5, 0);
        assert_eq!(
            devnet.apps[0].take_pending_validator_changes().removes.len(),
            0,
            "one endorsement must not remove — no quorum yet",
        );
        // The seated member casts the second endorsement → quorum.
        devnet.apps[0].ingest_tx(make_staking_tx_from(9, &remove_msg, 0));
        devnet.run_batch(5, 0);

        let applied = devnet.rotate_epoch_with_validator_changes();
        assert_eq!(applied, 1, "one validator remove should be applied");
        assert_eq!(
            devnet.validator_set().n(),
            initial_n,
            "validator set must return to original size"
        );
        assert!(
            devnet.validator_set().index_of(&new_addr).is_none(),
            "removed validator must not be in the set",
        );
    }

    /// Regression for stale-seat authority: removing a committee
    /// member leaves its spawned engine holding an index that now
    /// names a DIFFERENT live member. Removing member 1 of
    /// {0,1,2,3} yields {0,2,3} — engine 1's stale index collides
    /// with member 2's new seat. Routing must resolve the seat by
    /// address so the removed engine can neither claim it nor have
    /// its signatures collect under it.
    ///
    /// The removal is applied at the engine layer directly —
    /// `apply_validator_changes` + `rotate_epoch` — because the
    /// staking module's endorsement path only reaches registered
    /// validators (the module-driven flow is covered by
    /// [`tcp_multinode_validator_add_remove`]).
    #[test]
    fn tcp_multinode_removed_member_cannot_use_stale_seat() {
        let mut devnet =
            TcpMultiNodeDevnet::with_base_port(4, 10_000, crate::test_ports::reserve(10));
        let removed_addr = txs::identity_addr(1);
        let removed_key = devnet.secret_keys[1].public_key();

        for engine in &mut devnet.engines {
            let applied =
                engine.apply_validator_changes(&[], &[removed_addr]).expect("removal applies");
            assert_eq!(applied, 1);
            engine.rotate_epoch().expect("rotation completes");
        }
        devnet.validator_set = devnet.engines[0].validator_set().clone();
        devnet.publish_auth_sets();

        // Committee is {0,2,3}: seat 1 now belongs to member 2.
        assert_eq!(devnet.validator_set.n(), 3);
        assert!(devnet.validator_set.index_of(&removed_addr).is_none());
        // Seat 1 resolves to spawn position 2 — the engine whose
        // address the committee lists there — never to the removed
        // engine's stale position 1.
        assert_eq!(devnet.engine_pos(1), Some(2));

        // The attack: the removed engine sends a vote for a garbage
        // block hash to the view-0 leader (seat 0 = member 0 = engine
        // 0). The frame leaves transport 1, so `msg.from` authenticates
        // as `identity_addr(1)` — which resolves to NO seat in the
        // live committee, so the vote must be dropped at attribution.
        //
        // If attribution still trusted a positional index, the forged
        // vote would occupy seat 1's vote slot: member 2's genuine
        // vote then drops as an idempotent duplicate, and with a
        // 3-of-3 quorum no QC can ever form for the real proposal —
        // the removed member would have censored the seat it lost.
        let view = devnet.engines[0].current_view();
        let epoch = devnet.engines[0].epoch();
        let block_hash = primitives::Hash([0x42; 32]);
        let mut msg = Vec::with_capacity(49);
        msg.extend_from_slice(&view.value().to_le_bytes());
        msg.push(types::VotePhase::Prepare as u8);
        msg.extend_from_slice(block_hash.as_bytes());
        msg.extend_from_slice(&epoch.value().to_le_bytes());
        let sig = devnet.secret_keys[1].sign(crypto::hash::Domain::Vote, &msg);
        let _ = removed_key; // documents which identity signed
        let vote = types::Vote {
            view,
            phase: types::VotePhase::Prepare,
            block_hash,
            signature: sig,
            attestation: None,
            attestation_sig: None,
        };
        let mut frame = Vec::with_capacity(1 + 137);
        frame.push(MSG_VOTE);
        vote.encode(&mut frame);
        let leader_addr = devnet.validator_set.validator_addresses()[0].0.to_vec();
        devnet.transports_mut()[1].send(&leader_addr, &frame).expect("forged vote send");

        // The rotated committee keeps finalizing: seats resolve to
        // engines {0,2,3}, the forged frame is dropped at attribution,
        // and member 2's honest vote collects into seat 1. A poisoned
        // seat would stall every view — quorum needs all three.
        // (Nonzero txs: `propose` returns None on an empty mempool —
        // the harness has no heartbeat path.)
        let (result, _) = devnet.run_batch(3, 2);
        assert!(
            result.finalized[0].len() >= 2,
            "3-member committee must finalize past the poisoned view: {:?}",
            result.finalized.iter().map(Vec::len).collect::<Vec<_>>()
        );
    }

    /// 4 validators, 3 rounds, 10 txs/round over TCP.
    #[test]
    fn tcp_multinode_4_validators_liveness() {
        let mut devnet =
            TcpMultiNodeDevnet::with_base_port(4, 10_000, crate::test_ports::reserve(10));
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
        let mut devnet =
            TcpMultiNodeDevnet::with_base_port(4, 10_000, crate::test_ports::reserve(10));
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

    /// The EVM ledger should have processed state: the state
    /// root should be non-zero after running.
    #[test]
    fn tcp_multinode_evm_ledger_executes() {
        let mut devnet =
            TcpMultiNodeDevnet::with_base_port(4, 10_000, crate::test_ports::reserve(10));
        devnet.run_batch(3, 10);
        let root = devnet.app(0).attest_state(primitives::Height::new(0)).expect("executed");
        assert_ne!(root.root, primitives::Hash::ZERO, "state root should be non-zero");
    }

    /// Single validator (quorum=1) over TCP.
    #[test]
    fn tcp_multinode_single_validator() {
        let mut devnet =
            TcpMultiNodeDevnet::with_base_port(1, 10_000, crate::test_ports::reserve(10));
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
            executor: config::ExecutorConfig {
                max_mempool_entries: 5_000,
                parallel_threshold: 50,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut devnet = TcpMultiNodeDevnet::from_config(&config);
        let (result, _) = devnet.run_batch(2, 5);
        assert!(!result.finalized[0].is_empty(), "from_config devnet should finalize");
    }
}
