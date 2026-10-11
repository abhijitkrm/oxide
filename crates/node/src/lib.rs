//! Oxide production node assembly — config-driven engine selection,
//! module registration, and node lifecycle.
//!
//! This crate is the **production** node assembly path. It wires the
//! executor (with all registered modules: core, staking, EVM)
//! behind the selected consensus engine (`Sequencer` or `oxideBFT`).
//! The `oxide-validator` and `oxide-fullnode` binaries call
//! [`Node::assemble`] to build their stack.
//!
//! This crate contains **no test-harness code** — no multi-node
//! runners, no TCP loopback devnets, no workload generators. Those
//! live in the `devnet` crate, which depends on this one.
//!
//! # Config-driven engine selection
//!
//! The key Phase 1 acceptance gate: "the node also runs on
//! `SequencerEngine` via config swap with zero app-code changes."
//! [`NodeConfig`] with [`ConsensusConfig`] selects between
//! `sequencer` and `oxideBFT`. The same app (executor + modules)
//! runs under either engine.
//!
//! # Example
//!
//! ```no_run
//! use node::{ConsensusConfig, Node, NodeConfig};
//!
//! let config = NodeConfig {
//!     consensus: ConsensusConfig::OxideBft,
//!     max_mempool_entries: 10_000,
//!     parallel_threshold: 32,
//!     evm_persistence: true,
//!     storage_path: None,
//!     durability_dir: None,
//!     wal_path: None,
//!     settlement_operator: None,
//!     min_fee: 0,
//!     chain_id: 1,
//!     require_signed_txs: true,
//!     history_retention: None,
//!     base_fee: 7_000_000_000,
//!     genesis: None,
//!     block_budget: types::CHAIN_BLOCK_BUDGET,
//!     base_timeout_ms: 2_000,
//!     max_timeout_ms: 30_000,
//!     consensus_core: None,
//!     exec_lane_core: None,
//!     numa_node: None,
//!     verify_workers: None,
//!     intake_threads: None,
//!     rayon_threads: None,
//! };
//! let mut node = Node::assemble(&config);
//! // Drive consensus, inspect state, etc.
//! ```

use std::sync::Arc;

use consensus::{OxideBft, SequencerEngine};
use executor::Executor;
use ports::{AppInterface, ConsensusEngine};
use primitives::Address;
use primitives::fixed::{Price, Qty};

pub mod block_sync;
pub mod cli;
pub mod devnet;
pub mod follower;
pub mod peer_auth;
pub mod remote_signer;
pub mod rpc_adapters;
pub mod validator_net;
pub mod verify_pool;

/// The consensus engine selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusConfig {
    /// Single-leader dev-mode engine (no voting, no `BFT`).
    Sequencer,
    /// `oxideBFT` (2-chain `HotStuff` with `BLS` QCs).
    OxideBft,
}

impl ConsensusConfig {
    /// Parse from a string (for TOML config).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sequencer" => Some(Self::Sequencer),
            "oxideBFT" | "oxidebft" => Some(Self::OxideBft),
            _ => None,
        }
    }

    /// The string name for config serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::OxideBft => "oxideBFT",
        }
    }
}

/// One staking validator declared at genesis.
///
/// This is the runtime-neutral shape the binaries hand to
/// [`assemble_executor`]; the TOML/JSON genesis-file types in the
/// `config` crate are converted into it by the binary (hex decode,
/// unit conversion) so this crate stays free of file-format concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisValidator {
    /// The validator's account address — also its on-chain link to
    /// the consensus identity.
    pub address: Address,
    /// Declaration stake (unattributed — not backed by the bonding
    /// pool, so it cannot be undelegated).
    pub stake: u64,
    /// Optional BLS public key — the validator's consensus identity,
    /// kept by staking so double-sign evidence can be verified
    /// on-chain. `None` is acceptable on single-node devnets where
    /// there are no real signatures to prove against.
    pub public_key: Option<Vec<u8>>,
}

/// Genesis state applied at executor assembly.
///
/// The single shared input to [`assemble_executor`]'s genesis path:
/// `Node::assemble` passes `None` (selecting the documented devnet
/// default) and the validator binary converts a `--genesis-file` or
/// synthesizes a spec from `[genesis]` config values. Keeping one
/// application path means the shipped multi-validator binary and the
/// single-node path run the same state initialization — previously
/// the binary maintained its own divergent copy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenesisSpec {
    /// Validators registered in the staking module at genesis.
    pub validators: Vec<GenesisValidator>,
    /// Native-token balances minted at genesis, in wei (the EVM
    /// account store is the single ledger — there is no bank).
    /// `(address, wei balance)`.
    pub balances: Vec<(Address, u128)>,
}

/// The node configuration: engine selection + mempool size + parallel
/// execution tuning + EVM persistence + disk storage path.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Which consensus engine to use.
    pub consensus: ConsensusConfig,
    /// Maximum mempool entries.
    pub max_mempool_entries: usize,
    /// Minimum batch size to use the parallel speculative EVM
    /// execution path. Below this threshold, txs execute
    /// sequentially (avoids rayon thread-pool overhead for small
    /// batches). Default: [`executor::DEFAULT_PARALLEL_THRESHOLD`]
    /// (32 txs). Lower for workloads with many small blocks; raise
    /// for latency-sensitive single-threaded deployments.
    pub parallel_threshold: usize,
    /// Whether to enable EVM state persistence. When `true`, the
    /// EVM module is created with a storage backend and flushes
    /// state at `end_block`. When `false`, the EVM module runs
    /// in-memory only (state is lost on restart). Default:
    /// `true` — persistence is the production-safe default.
    pub evm_persistence: bool,
    /// Optional disk path for the EVM state database. When `Some`,
    /// the EVM module uses a `RedbBackend` (disk-backed ACID KV
    /// store) for durable persistence. When `None`, uses a
    /// `Volatile` (in-memory) backend. Default: `None` —
    /// in-memory for devnet; set to a path for production.
    pub storage_path: Option<std::path::PathBuf>,
    /// Crash-durability root directory. When `Some`, the executor
    /// journals every finalized block to `<dir>/block-journal/`
    /// *before* executing it and writes an atomic `snapshot.bin`
    /// checkpoint every [`executor::DEFAULT_CHECKPOINT_INTERVAL`]
    /// heights — after a crash, `Executor::recover_durable_state`
    /// imports the newest checkpoint and replays the journaled
    /// blocks above it, so native-module state, the EVM, and the
    /// executed-nonce map restart at one consistent height. `None`
    /// disables the journal (in-memory only — tests and sims).
    /// Conventionally the same `data_dir` whose `evm.redb` child is
    /// `storage_path`.
    pub durability_dir: Option<std::path::PathBuf>,
    /// Consensus WAL path — persists `last_voted_view`, `high_qc`,
    /// `last_committed`, and the vote locks that make restarting
    /// safe. Conventionally `<data_dir>/consensus.wal`: executor
    /// durability (`durability_dir`) restores *state* on restart,
    /// but without the WAL the engine would re-propose at height 0
    /// on top of a recovered tip — re-committing already-covered
    /// heights and corrupting the block journal's contiguous-height
    /// invariant. `None` keeps the WAL in-memory (tests, sims).
    pub wal_path: Option<std::path::PathBuf>,
    /// The settlement operator address — the only account allowed to
    /// submit exchange `batch_settle` transactions (the off-chain
    /// matching service's tx sender). `None` disables batch
    /// settlement entirely (fail-closed default — safe when no
    /// external matcher is attached to this node).
    pub settlement_operator: Option<primitives::Address>,
    /// Logical CPU the consensus pump thread pins to (hft-audit
    /// F-02). The pump serializes propose/vote/timeout handling —
    /// pinning keeps its hot state on one core. `None` = unpinned.
    /// Validated against the online-CPU set by
    /// [`NodeConfig::validate_perf_pins`].
    pub consensus_core: Option<u32>,
    /// Logical CPU the executor commit lane pins to (hft-audit
    /// F-02). Same rationale: block execution is one thread's hot
    /// loop; migration costs a cold cache per hop. `None` = unpinned.
    pub exec_lane_core: Option<u32>,
    /// NUMA node the pinned threads are expected on (hft-audit
    /// F-02). Validated against `/sys/devices/system/node/` at
    /// startup; informational only — all pinned roles should sit on
    /// this node's cores so shared state (book memory, chain
    /// buffers) stays node-local. `None` disables the check.
    pub numa_node: Option<u32>,
    /// BLS verify-pool workers (hft-audit-2 C-1). `None` = the pool's
    /// default (`available_parallelism − 1`, clamped to [2, 8]).
    pub verify_workers: Option<usize>,
    /// Mempool-intake rayon threads (hft-audit-2 X-3). `None` =
    /// [`physical_cores`].
    pub intake_threads: Option<usize>,
    /// Global rayon pool threads (hft-audit-2 X-3). `None` =
    /// [`physical_cores`].
    pub rayon_threads: Option<usize>,
    /// Minimum transaction fee (`ctx.fee`) for native-module txs.
    /// Txs declaring less are skipped before execution — the fee
    /// field is sender-controlled, so without a floor every tx could
    /// declare 0 and execute for free. Self-funded modules (EVM: gas
    /// is the fee) are exempt. `0` = no floor.
    pub min_fee: u64,
    /// The chain ID mixed into the EIP-712 domain separator for
    /// native transaction signature verification. Must match the
    /// chain ID wallets sign against. Default `1` (devnet).
    pub chain_id: u64,
    /// Whether to reject unsigned transactions to
    /// non-self-authenticating modules (everything but the EVM).
    ///
    /// `true` (default) enforces EIP-712 envelope signatures at
    /// mempool admission and execution. `false` admits unsigned
    /// envelopes where `ctx.sender` is trusted as declared — any
    /// account can be impersonated, so the opt-out exists only for
    /// devnet/test harnesses and is gated behind the operator's
    /// explicit unsafe flag at the binary layer.
    pub require_signed_txs: bool,
    /// Heights of finalized-block / state-root history the executor
    /// retains in memory (`Executor::with_history_retention`).
    /// `None` = the executor default (4096).
    pub history_retention: Option<usize>,
    /// The EVM base fee (wei per gas) the module advertises and
    /// charges. Must equal the RPC-advertised base fee — the
    /// validator binary sources both from `rpc.base_fee` so the
    /// advertised and enforced parameters agree. Default:
    /// `7_000_000_000` (7 gwei).
    pub base_fee: u64,
    /// Genesis state applied at assembly. `None` selects the
    /// single-node devnet default: `[0u8; 20]` and devnet identity 0
    /// (`crypto::secp::test_identity_address`) are funded with
    /// `u128::MAX` wei and registered as the sole staking validator.
    /// That default is a development convenience — production
    /// deployments pass a [`GenesisSpec`] converted from the genesis
    /// file.
    pub genesis: Option<GenesisSpec>,
    /// The block budget the consensus engine passes to
    /// `prepare_proposal` (bytes + gas). Maps
    /// `consensus.max_block_bytes` / `consensus.max_block_gas` from
    /// TOML. Default: [`types::CHAIN_BLOCK_BUDGET`].
    pub block_budget: types::BlockBudget,
    /// Pacemaker base timeout in milliseconds — the first view's
    /// timeout before exponential backoff. Maps
    /// `consensus.base_timeout_ms` from TOML. Default: 2000 ms.
    pub base_timeout_ms: u64,
    /// Pacemaker maximum timeout in milliseconds — the cap on
    /// exponential backoff. Maps `consensus.max_timeout_ms` from
    /// TOML. Default: `30_000` ms.
    pub max_timeout_ms: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            consensus: ConsensusConfig::OxideBft,
            max_mempool_entries: 10_000,
            parallel_threshold: executor::DEFAULT_PARALLEL_THRESHOLD,
            evm_persistence: true,
            storage_path: None,
            durability_dir: None,
            wal_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: true,
            history_retention: None,
            base_fee: 7_000_000_000,
            genesis: None,
            block_budget: types::CHAIN_BLOCK_BUDGET,
            base_timeout_ms: 2_000,
            max_timeout_ms: 30_000,
            consensus_core: None,
            exec_lane_core: None,
            numa_node: None,
            verify_workers: None,
            intake_threads: None,
            rayon_threads: None,
        }
    }
}

/// Physical cores on this machine: distinct SMT sibling groups among
/// the online CPUs (Linux sysfs), else the logical CPU count.
///
/// The default size for the CPU-bound rayon pools (hft-audit-2 X-3):
/// secp256k1 and BLS saturate a core's ALUs, so a second thread on
/// the SMT sibling adds contention, not throughput — on the 8-core /
/// 16-thread target the old defaults ran ~50 threads on 8 cores.
#[must_use]
pub fn physical_cores() -> usize {
    let logical = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let mut groups = std::collections::BTreeSet::new();
    for cpu in 0..logical {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
        match std::fs::read_to_string(path) {
            Ok(list) => {
                groups.insert(list.trim().to_owned());
            }
            Err(_) => return logical,
        }
    }
    groups.len().max(1)
}

impl NodeConfig {
    /// Validate the pinning/NUMA surface against live topology
    /// (hft-audit F-02): every configured core must be in the
    /// online set and the NUMA node must exist under sysfs. A bad
    /// pin is a deployment misconfiguration — it fails validation
    /// loudly here rather than silently degrading locality after
    /// startup. Returns the offending setting names + reasons.
    pub fn perf_pin_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let online = primitives::pin::online_cpus();
        for (name, core) in
            [("consensus_core", self.consensus_core), ("exec_lane_core", self.exec_lane_core)]
        {
            if let Some(c) = core
                && c >= online
            {
                errors.push(format!(
                    "performance.{name} = {c} is outside the online CPU set \
                     (online cores: {online})"
                ));
            }
        }
        if let Some(node) = self.numa_node
            && !primitives::pin::numa_node_present(node)
        {
            errors.push(format!(
                "performance.numa_node = {node} does not exist under \
                 /sys/devices/system/node/"
            ));
        }
        errors
    }
}

/// A fully assembled Oxide node: consensus engine + app (executor).
///
/// The engine drives the app through the [`AppInterface`] boundary.
/// The app is the executor with registered modules (core,
/// staking, EVM).
///
/// Created via [`Node::assemble`]. The node is ready to accept
/// transactions and run consensus immediately after assembly.
pub struct Node {
    /// The consensus engine, boxed for engine-agnostic storage.
    engine: Box<dyn ConsensusEngine>,
    /// The app (executor), kept for post-run inspection and for
    /// sharing with the RPC server via [`Node::app_handle`].
    app: Arc<Executor>,
    /// The EVM module handle for direct state access (funding,
    /// balance/nonce inspection). `None` if the EVM module is not
    /// registered (should not happen with the default `assemble`
    /// path).
    evm_module: Option<Arc<evm::EvmModule>>,
    /// Metrics recorder for node-level observability. Records
    /// counters (txs submitted, blocks finalized), gauges (height,
    /// mempool size), and latency histograms (block commit, snapshot
    /// export/import). Accessible via [`Node::metrics`] for RPC
    /// exposition.
    metrics: Arc<metrics::Recorder>,
}

impl Node {
    /// Assemble a node from config.
    ///
    /// Registers the core, staking, and EVM modules on the
    /// executor, then wires the executor behind the selected
    /// consensus engine.
    ///
    /// # Modules registered
    ///
    /// - [`CoreModule`](oxide_core::CoreModule) — block height, timestamps.
    /// - [`StakingModule`](staking::StakingModule) — validator staking.
    /// - [`EvmModule`](evm::EvmModule) — `revm`-based EVM. Base fee 7 gwei.
    ///   Funds `[0u8; 20]` and devnet identity 0 with `u128::MAX` for
    ///   test/devnet use. The
    ///   EVM account store is also the chain's **single balance
    ///   ledger**: envelope fees, staking bonds, exchange settlement,
    ///   and perps margin all debit/credit the same accounts EVM
    ///   transactions move (there is no separate bank ledger).
    ///
    /// # Panics
    ///
    /// Panics if BLS key generation fails (impossible with valid IKM)
    /// or if the validator set construction fails (impossible with
    /// equal stakes >= 1).
    pub fn assemble(config: &NodeConfig) -> Self {
        let assembled = assemble_executor(config);
        let app = assembled.app.clone();
        let evm_module = assembled.evm_module.clone();
        let app_dyn: Arc<dyn AppInterface> = app.clone();

        // Select the consensus engine.
        let engine: Box<dyn ConsensusEngine> = match config.consensus {
            ConsensusConfig::Sequencer => Box::new(
                SequencerEngine::new(app_dyn.clone())
                    .with_chain_params(assembled.chain_params.clone()),
            ),
            ConsensusConfig::OxideBft => {
                // oxideBFT in single-validator mode (quorum=1): the
                // engine self-proposes, self-votes, and commits via
                // the 2-chain rule. This is a real oxideBFT run, not
                // a fallback — the consensus logic is identical to
                // the multi-node case, just with n=1.
                //
                // M6 fix: previously this silently fell back to
                // SequencerEngine, which meant the config name
                // "oxideBFT" was a lie. Now it runs the real engine.
                let key =
                    crypto::BlsSecretKey::from_ikm(&[1u8; 32]).expect("BLS key gen from valid IKM");
                let pk = key.public_key();
                let vs =
                    consensus::ValidatorSet::new(vec![pk], vec![1]).expect("single validator set");
                let mut engine = OxideBft::new(app_dyn.clone(), vs)
                    .with_secret_key(key)
                    .with_pacemaker_timeouts(config.base_timeout_ms, config.max_timeout_ms)
                    .with_block_budget(config.block_budget)
                    .with_chain_params(assembled.chain_params.clone());
                // Consensus WAL: restores `last_committed`, `high_qc`,
                // and the per-height vote locks — without it a restart
                // would re-propose from height 0 over the executor's
                // recovered tip. The same attach+recover pair the
                // devnet path runs in `assemble_devnet_node`.
                if let Some(wal_path) = &config.wal_path {
                    if let Some(parent) = wal_path.parent() {
                        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                            panic!("failed to create WAL dir {}: {e}", parent.display())
                        });
                    }
                    let wal = consensus::wal::Wal::open(wal_path).unwrap_or_else(|e| {
                        panic!("failed to open consensus WAL {}: {e}", wal_path.display())
                    });
                    engine = engine.with_wal(wal);
                    engine.recover_from_wal().unwrap_or_else(|e| {
                        panic!("consensus WAL recovery failed at {}: {e}", wal_path.display())
                    });
                }
                Box::new(engine)
            }
        };

        Self {
            engine,
            app,
            evm_module: Some(evm_module),
            metrics: Arc::new(metrics::Recorder::new()),
        }
    }

    /// Access the consensus engine for driving.
    pub fn engine(&mut self) -> &mut dyn ConsensusEngine {
        self.engine.as_mut()
    }

    /// Access the app (executor) for inspection.
    pub fn app(&self) -> &Executor {
        &self.app
    }

    /// Access the metrics recorder for Prometheus exposition or
    /// inspection. The recorder is shared via `Arc` so the RPC
    /// layer can expose `/metrics` without holding a reference to
    /// the `Node`.
    pub fn metrics(&self) -> &Arc<metrics::Recorder> {
        &self.metrics
    }

    /// Access the EVM module for direct state inspection (balance,
    /// nonce, state root). Returns `None` if the EVM module is not
    /// registered.
    pub fn evm_module(&self) -> Option<&evm::EvmModule> {
        self.evm_module.as_deref()
    }

    /// Clone the shared EVM-module handle so another owner (the RPC
    /// server) can read state and sealed-block history while the
    /// executor keeps executing against the same instance.
    pub fn evm_module_handle(&self) -> Option<Arc<evm::EvmModule>> {
        self.evm_module.clone()
    }

    /// Clone the shared executor handle.
    ///
    /// The executor is wrapped in an `Arc` so the RPC server can submit
    /// transactions into the mempool from a separate thread without
    /// taking ownership of the node.
    pub fn app_handle(&self) -> Arc<Executor> {
        self.app.clone()
    }

    /// Export a snapshot of the node's state at the current chain
    /// height.
    ///
    /// The snapshot captures the chain height, aggregate state root,
    /// and per-module state roots. It can be transferred to a new
    /// node for fast state sync (skipping replay from genesis).
    ///
    /// See [`Executor::export_snapshot`] for details.
    #[must_use]
    pub fn export_snapshot(&self) -> executor::ExecutorSnapshot {
        let start = std::time::Instant::now();
        let snap = self.app.export_snapshot();
        self.metrics.record("snapshot_export", start.elapsed());
        self.metrics.incr_counter("snapshot_exports", 1);
        self.metrics.set_gauge("snapshot_height", i64::try_from(snap.height).unwrap_or(i64::MAX));
        snap
    }

    /// Import a snapshot, restoring the node to the snapshot's
    /// chain height and state.
    ///
    /// After import, the node's chain height and state root match
    /// the snapshot. Consensus resumes from `snapshot.height + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`executor::SnapshotImportError`] if the snapshot is
    /// corrupted, has a state root mismatch, or has a module count
    /// mismatch.
    ///
    /// # Atomicity
    ///
    /// If import fails, the node's state is unchanged (the executor
    /// validates the snapshot before modifying any state). A
    /// `CheckpointFailed` error is the exception: the import itself
    /// succeeded but persisting it failed — the variant exists so
    /// callers cannot mistake a non-persisted import for a durable
    /// one.
    ///
    /// # When to call
    ///
    /// Call this **before** driving consensus (before the first
    /// `prepare_proposal` or `finalize_block`). Importing after
    /// consensus has started would create a gap in the chain.
    pub fn import_snapshot(
        &self,
        snapshot: &executor::ExecutorSnapshot,
    ) -> Result<(), executor::SnapshotImportError> {
        let start = std::time::Instant::now();
        let result = self.app.import_snapshot(snapshot);
        self.metrics.record("snapshot_import", start.elapsed());
        self.metrics.incr_counter("snapshot_imports", 1);
        if result.is_ok() {
            self.metrics
                .set_gauge("snapshot_height", i64::try_from(snapshot.height).unwrap_or(i64::MAX));
            // Persist the imported state under the durability
            // contract. Without this checkpoint a restart would
            // replay whatever the journal previously held and
            // silently rewind below the synced height — the imported
            // state would exist only until the process exited.
            // `durable_checkpoint` writes `snapshot.bin` atomically
            // and prunes journal segments the imported height now
            // covers; a no-op when durability is not configured.
            self.app.durable_checkpoint().map_err(|e| {
                executor::SnapshotImportError::CheckpointFailed { reason: e.to_string() }
            })?;
        }
        result
    }

    /// Assemble a node from config and restore from a snapshot.
    ///
    /// This is the snapshot-sync entry point: a new node calls
    /// `assemble_from_snapshot` instead of `assemble` to start
    /// from a known chain state (e.g., synced from a peer).
    ///
    /// The method:
    /// 1. Assembles the node with the standard module set.
    /// 2. Imports the snapshot, setting the chain height and
    ///    state root.
    /// 3. Returns the assembled node, ready for consensus.
    ///
    /// # Errors
    ///
    /// Returns [`executor::SnapshotImportError`] if the snapshot
    /// is invalid. The assembled node is dropped on error (no
    /// state is partially installed).
    ///
    /// # Panics
    ///
    /// Panics if BLS key generation fails (same as `assemble`).
    pub fn assemble_from_snapshot(
        config: &NodeConfig,
        snapshot: &executor::ExecutorSnapshot,
    ) -> Result<Self, executor::SnapshotImportError> {
        let node = Self::assemble(config);
        node.import_snapshot(snapshot)?;
        Ok(node)
    }

    /// Fund an EVM account.
    ///
    /// This is used by the EVM load test path to fund secp256k1-derived
    /// sender addresses created by the workload generator. In
    /// production, accounts are funded via genesis or L1 deposits, not
    /// this method.
    ///
    /// # Panics
    ///
    /// Panics if the EVM module is not registered (should not happen
    /// with the default [`Node::assemble`] path).
    pub fn fund_evm_account(&self, addr: &primitives::Address, balance: u128) {
        self.evm_module
            .as_ref()
            .expect("EVM module not registered")
            .fund_account_for_test(addr, balance);
    }
}

/// The `chain.*` parameter sink — writes the shared
/// [`types::ChainParams`] the consensus engine and executor read.
/// Values are bare `u64` LE payloads for every key; the block-budget
/// keys reject `0` (a block that can hold nothing is not a
/// legitimate governable state — the chain would still finalize
/// empty blocks, but no transaction could ever land), while
/// `chain.min_fee` accepts `0` as "no floor".
struct ChainParamSink(std::sync::Arc<types::ChainParams>);

impl framework::ParameterSink for ChainParamSink {
    fn apply_param(&self, key: &[u8], value: &[u8]) -> Result<(), executor::ExecError> {
        let target = match key {
            b"chain.block_gas_limit" => &self.0.max_gas,
            b"chain.block_max_bytes" => &self.0.max_bytes,
            b"chain.min_fee" => &self.0.min_fee,
            _ => {
                return Err(executor::ExecError::rejected(
                    executor::RejectCategory::NotFound,
                    "chain: unknown governed parameter",
                ));
            }
        };
        let Ok(v) = <[u8; 8]>::try_from(value) else {
            return Err(executor::ExecError::Malformed);
        };
        let v = u64::from_le_bytes(v);
        if key != b"chain.min_fee" && v == 0 {
            return Err(executor::ExecError::rejected(
                executor::RejectCategory::InvalidInput,
                format!("{}: block budget must be > 0", String::from_utf8_lossy(key)),
            ));
        }
        target.store(v, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// The executor half of node assembly: the `Arc`'d executor plus the
/// module handles callers need after construction.
///
/// `Node::assemble` keeps these internally; the multi-validator
/// binary path (which drives its own `OxideBft` engine over a real
/// transport) consumes the same struct so both binaries run an
/// identical module graph — previously the validator binary
/// maintained a second, narrower assembly that silently omitted
/// exchange/perps/oracle/governance and never spawned the execution
/// lane.
pub struct AssembledExecutor {
    /// The shared executor handle: the engine drives it through
    /// `Arc<dyn AppInterface>`; the RPC layer clones it for mempool
    /// submission and state reads.
    pub app: Arc<Executor>,
    /// The EVM module — the chain's single native-token ledger and
    /// the fee collector for native-module txs.
    pub evm_module: Arc<evm::EvmModule>,
    /// The staking module — the committee source wired into
    /// exchange, perps, and oracle.
    pub staking_module: Arc<staking::StakingModule>,
    /// The exchange module — needed by harnesses that drive
    /// settlement or inspect book state post-run.
    pub exchange_module: Arc<exchange::ExchangeModule>,
    /// The crash-durability recovery report, when the config enabled
    /// a durability directory: how much of the journal was replayed
    /// and which checkpoint anchored it. `None` when durability is
    /// not configured (in-memory deployments) — distinct from
    /// `Some` with an empty report, which means "durability on,
    /// nothing on disk yet" (a fresh start).
    pub recovery: Option<executor::RecoveryReport>,
    /// The shared live chain parameters — the `Arc` already installed
    /// on the executor and behind the governance `chain.*` sink.
    /// Engine-construction sites (`Node::assemble`,
    /// `assemble_devnet_node`) must hand it to the engine so
    /// proposal budgeting and `BlockContext.gas_limit` read the same
    /// atomics the executor enforces and governance writes.
    pub chain_params: Arc<types::ChainParams>,
}

/// Blocks between durable redb commits when the executor journal is
/// on (hft-audit-2 X-8).
///
/// Unit: blocks (one `sync` per `end_block` flush). Origin: an
/// `Immediate` redb commit is one fsync — 4 ms p50 / 13 ms p99 on the
/// md RAID-1 target — and the journal already makes every block
/// recoverable, so the only cost of a larger value is a longer replay
/// after a crash (≤ 64 blocks, well under one checkpoint interval).
/// 1 restores a sync per block; raising it further saves nothing
/// measurable once the fsync is amortized away.
const REDB_JOURNAL_SYNC_EVERY: u32 = 64;

/// Assemble the executor + full module graph from `config`.
///
/// This is **the** executor assembly path: `Node::assemble` calls it,
/// and the multi-validator binary path calls it directly before
/// attaching its own transport-driven `OxideBft` engine. Every
/// config field that affects execution is consumed here:
///
/// - `max_mempool_entries`, `parallel_threshold`, `min_fee`,
///   `chain_id`, `require_signed_txs`, `history_retention` → executor
/// - `evm_persistence`, `storage_path`, `chain_id`, `base_fee` →
///   EVM module (the EVM's chain id and base fee now come from
///   config — they were previously hardcoded to `1` / 7 gwei while
///   the executor's chain id was configurable, letting the EIP-712
///   domain and the EVM chain diverge)
/// - `genesis` → validators + native balances (or the documented
///   single-node devnet default when `None`)
/// - `settlement_operator` → exchange batch-settlement gate
///
/// # Modules registered
///
/// core, staking, exchange, perps, oracle, governance, EVM — the
/// full production graph, in both binary paths.
///
/// The async execution lane is spawned before returning, so every
/// consumer gets the same commit→execute pipeline.
///
/// # Panics
///
/// Panics if the `RedbBackend` cannot open `storage_path`, if a
/// genesis validator has zero stake, or if a genesis BLS key is not
/// 48 bytes.
#[must_use]
// Module assembly is inherently linear: one register call per
// module, in dependency order — the function's length tracks the
// module count, not its complexity.
#[allow(clippy::too_many_lines)]
pub fn assemble_executor(config: &NodeConfig) -> AssembledExecutor {
    // Size the global rayon pool before anything can touch it
    // (hft-audit-2 X-3). A second assembly in one process (tests,
    // devnet clusters) finds it already built and keeps it.
    let _ = Executor::init_global_pool(config.rayon_threads.unwrap_or_else(physical_cores));
    // Build the executor with standard modules. Use `with_config`
    // so the parallel threshold is configurable (default: 32 txs,
    // lowered from 100 in the block-size sweep session — rayon
    // overhead amortizes at 32+).
    // The shared live chain parameters: one `Arc` the executor's
    // builders write into (so configured values are already in the
    // atomics), the engine reads for proposal budgeting, and the
    // governance `chain.*` sink mutates on apply.
    let chain_params = Arc::new(types::ChainParams::default());
    let mut executor = Executor::with_config(config.max_mempool_entries, config.parallel_threshold)
        .with_chain_params(chain_params.clone())
        .with_min_fee(config.min_fee)
        // One gas source: the executor's declared-gas admission cap is
        // the same `block_budget.max_gas` consensus packs proposals
        // against. Previously the executor defaulted to
        // `DEFAULT_BLOCK_GAS_LIMIT` (30M) while the consensus budget
        // allowed `CHAIN_BLOCK_GAS_LIMIT` (10G) — a maximally packed
        // proposal would have its tail silently `GasLimit`-skipped on
        // every replica. Deterministic, but the effective cap was an
        // invisible constant no config could reach; devnet had to
        // hand-set `with_gas_limit` to compensate.
        .with_gas_limit(config.block_budget.max_gas)
        .with_chain_id(config.chain_id)
        .with_exec_lane_pin(config.exec_lane_core)
        .with_intake_threads(config.intake_threads.unwrap_or_else(physical_cores))
        .with_unsigned_tx_policy(if config.require_signed_txs {
            executor::UnsignedTxPolicy::Reject
        } else {
            executor::UnsignedTxPolicy::Allow
        });
    // The byte budget has no executor consumer — proposals are
    // packed against it consensus-side — so it is seeded here
    // rather than through a builder.
    chain_params
        .max_bytes
        .store(config.block_budget.max_bytes, std::sync::atomic::Ordering::Relaxed);
    if let Some(n) = config.history_retention {
        executor = executor.with_history_retention(n);
    }
    // Crash durability: with a data dir configured, every finalized
    // block is journaled before execution and periodic atomic
    // checkpoints bound the replay window. `None` keeps the
    // in-memory behavior for tests and sims.
    if let Some(dir) = &config.durability_dir {
        executor =
            executor.with_durability(executor::DurabilityConfig::new(dir.clone())).unwrap_or_else(
                |e| panic!("failed to open block journal under {}: {e}", dir.display()),
            );
    }
    executor.register_module(Arc::new(oxide_core::CoreModule::new()));

    // The EVM module is built FIRST: it is the chain's balance
    // ledger, so staking/exchange/perps take its `Arc` for
    // settlement and it is the executor's fee module.
    //
    // Persistence: when `evm_persistence` is enabled (the
    // default), the EVM module is created with a storage backend
    // and flushes state at `end_block`. When `storage_path` is
    // `Some`, a disk-backed `RedbBackend` is used (durable ACID
    // persistence — state survives restarts). When `None`, a
    // `Volatile` (in-memory) backend is used. When disabled
    // entirely (`evm_persistence = false`), the EVM runs
    // in-memory only.
    //
    // `chain_id` and `base_fee` come from config — the same values
    // the RPC layer advertises, so the enforced and advertised
    // parameters cannot diverge.
    let evm_module: Arc<evm::EvmModule> = if config.evm_persistence {
        let backend: Box<dyn storage::StorageBackend + Send> = match &config.storage_path {
            // With the executor journal on, it is the crash authority
            // and redb may lag it: per-block commits skip the fsync
            // and every `REDB_JOURNAL_SYNC_EVERY`-th block syncs
            // (hft-audit-2 X-8). Without the journal every commit
            // stays durable.
            Some(path) if config.durability_dir.is_some() => Box::new(
                storage::RedbBackend::open_journal_backed(path, REDB_JOURNAL_SYNC_EVERY)
                    .expect("redb backend"),
            ),
            Some(path) => Box::new(storage::RedbBackend::open(path).expect("redb backend")),
            None => Box::new(storage::Volatile::new()),
        };
        Arc::new(
            evm::EvmModule::with_storage(config.chain_id, config.base_fee, backend)
                .with_fee_recipient(staking::FEE_POOL),
        )
    } else {
        Arc::new(
            evm::EvmModule::new(config.chain_id, config.base_fee)
                .with_fee_recipient(staking::FEE_POOL),
        )
    };
    // Canonical preinstalls (CREATE2 factory, Multicall3, Permit2,
    // singleton factories) — Foundry/Hardhat/Safe tooling assumes
    // they exist at fixed addresses on every EVM chain. Applied
    // before genesis balances/alloc so a genesis entry can still
    // intentionally override a preinstall address.
    evm_module.install_preinstalls();
    // The EVM account store is the fee collector: every
    // native-module tx is charged `ctx.fee` (base units → wei)
    // from the sender's EVM balance before execution.
    executor.set_fee_module(framework::module_id::EVM);
    // Staking is EVM-ledger-backed: delegation debits the
    // delegator into the bonded pool, unbonding refunds from it.
    let staking_module = staking::StakingModule::new();
    staking_module.set_ledger(evm_module.clone());
    match &config.genesis {
        // Single-node devnet default: fund and register
        // deterministic identities —
        //   * `[0u8;20]`: the legacy byte-pattern sender/validator,
        //     kept as a delegate target for unsigned test fixtures;
        //   * `test_identity_address(0)`: the key-derived devnet
        //     validator — the only identity that can *sign*
        //     envelopes, so sender-gated flows (key_change,
        //     endorsements) must run as it. Compiled only under
        //     `dev-identities`: a production build ships no
        //     derivable signing identity, funded or not.
        // Development convenience only — production passes an
        // explicit `GenesisSpec`.
        None => {
            evm_module.fund_account_for_test(&primitives::Address([0u8; 20]), u128::MAX);
            staking_module.register_validator(primitives::Address([0u8; 20]));
            #[cfg(feature = "dev-identities")]
            {
                let identity0 = crypto::secp::test_identity_address(0)
                    .expect("devnet identity 0 is a valid secp256k1 key");
                evm_module.fund_account_for_test(&identity0, u128::MAX);
                staking_module.register_validator(identity0);
            }
        }
        Some(spec) => {
            for (addr, wei) in &spec.balances {
                evm_module.genesis_insert_account(addr, *wei, 0, Vec::new(), Vec::new());
            }
            for v in &spec.validators {
                staking_module.genesis_register_validator(v.address, v.stake);
                if let Some(pk) = &v.public_key {
                    staking_module.genesis_set_bls_key(v.address, pk);
                }
            }
        }
    }
    // Shared: perps consults it for committee-gated mark/funding
    // overrides, the oracle for feed authorization + quorum sizing.
    let staking_module = Arc::new(staking_module);
    executor.register_module(staking_module.clone());
    // Register the exchange module with a default spot market
    // (tick 0.01, lot 0.001, [$10, $20], 64 max resting). The
    // exchange settles fills against EVM balances (plan.md §9.2).
    let mut exchange_mod = exchange::ExchangeModule::with_ledger(evm_module.clone())
        .with_committee(staking_module.clone());
    if let Some(operator) = config.settlement_operator {
        exchange_mod.set_settlement_operator(operator);
    }
    let exchange = Arc::new(exchange_mod);
    exchange
        .list_market(trading::MarketConfig {
            market_id: 0,
            tick_size: Price(1_000_000),
            lot_size: Qty(1_000),
            min_price: Price(1_000_000_000),
            max_price: Price(2_000_000_000),
            max_resting: 64,
        })
        .expect("default market config is valid");
    executor.register_module(exchange.clone());
    // Register the perps module with a default perpetual market
    // (10x max leverage, 0.5% maintenance margin). The perps
    // module settles margin deposits/withdrawals against EVM
    // balances (plan.md §9.3).
    let perps = Arc::new(
        perps::PerpsModule::with_ledger(evm_module.clone()).with_committee(staking_module.clone()),
    );
    perps
        .list_market(perps::PerpsMarketConfig {
            base: trading::MarketConfig {
                market_id: 0,
                tick_size: Price(1_000_000),
                lot_size: Qty(1_000),
                min_price: Price(1_000_000_000),
                max_price: Price(2_000_000_000),
                max_resting: 64,
            },
            max_leverage: 10,
            mmr_base_bps: 50,
        })
        .expect("default perps market config is valid");
    executor.register_module(perps.clone());
    // The oracle module: validators submit per-market price
    // observations during the block; at end_block it aggregates
    // them (strict-majority quorum → median → EMA) and pushes the
    // result into perps through `MarkSink`. Staking supplies both
    // feeder authorization and the quorum denominator.
    let oracle = Arc::new(oracle::OracleModule::new().with_committee(staking_module.clone()));
    oracle.with_sink(perps.clone());
    executor.register_module(oracle);
    // Governance: stake-weighted parameter lifecycle — deposits
    // escrow on the EVM ledger, staking supplies the voting power,
    // and `<module>.*` keys route to the registered parameter
    // sinks. `exchange.*` pays fee-vault withdrawals out of module
    // custody; `staking.*`, `perps.*`, and `governance.*` move the
    // modules' own tunables; `chain.*` writes the shared block
    // budget / fee floor the engine and executor read — so a
    // timelocked proposal is the only path that moves them.
    let gov = governance::GovernanceModule::new()
        .with_committee(staking_module.clone())
        .with_ledger(evm_module.clone());
    let gov_params = gov.params();
    let gov = gov
        .with_sink("exchange", exchange.clone())
        .with_sink("staking", staking_module.clone())
        .with_sink("perps", perps.clone())
        .with_sink("governance", gov_params)
        .with_sink("chain", Arc::new(ChainParamSink(chain_params.clone())));
    executor.register_module(Arc::new(gov));
    // Wire the exchange and perps modules into the EVM for
    // read-only precompiles (plan.md §10), then register the EVM.
    evm_module.set_native_modules(Some(exchange.clone()), Some(perps));
    executor.register_module(evm_module.clone());
    let app: Arc<Executor> = Arc::new(executor);
    // Crash recovery runs here — inside the ONE assembly path — so
    // every consumer (`Node::assemble`, the multi-validator binary,
    // the harnesses) restarts from the same durable state. When
    // `durability_dir` is configured this imports the newest
    // `snapshot.bin` checkpoint and replays the journaled blocks
    // above it; with no durability configured it is a `None`
    // no-op. Recovery must precede the exec-lane spawn: replay
    // drives `execute_committed_backlog` inline, and the lane must
    // start from a state whose watermarks already reflect the
    // recovered tip.
    let recovery = app
        .recover_durable_state()
        .unwrap_or_else(|e| panic!("durable state recovery failed: {e}"));
    // Spawn the async execution lane (plan.md §13 Phase D):
    // `finalize_block` hands each committed block to a worker
    // thread, overlapping execution of block h with consensus
    // for block h+1. Both binary paths get the lane — the
    // multi-validator binary previously ran without it, a second
    // execution pipeline with different backpressure behavior.
    app.spawn_exec_lane();
    AssembledExecutor {
        app,
        evm_module,
        staking_module,
        exchange_module: exchange,
        recovery,
        chain_params,
    }
}

/// Run a simple smoke test: assemble a node, submit a tx, finalize a block.
///
/// This is used by the `oxide-deploy` binary's smoke test and by
/// integration tests that need a quick end-to-end check.
///
/// # Panics
///
/// Panics if the smoke test fails (no block finalized or zero state root).
pub fn run_node_smoke_test() {
    let config = NodeConfig::default();
    let mut node = Node::assemble(&config);

    // Submit a *signed* staking delegate tx — the default node
    // requires authenticated envelopes, so the smoke test exercises
    // the same path a production submitter would. The sender is the
    // signing key's derived address, funded on the EVM ledger; the
    // delegate targets the genesis validator [0u8;20].
    let (privkey, sender) = crypto::secp::generate_keypair_for_test();
    node.fund_evm_account(&sender, 1_000_000_000_000_000_000);
    let validator = Address([0u8; 20]);
    let module_payload = staking::msg::delegate(validator, 100);
    let tx = cli::build_signed_tx_with(
        &privkey,
        sender,
        config.chain_id,
        framework::module_id::STAKING,
        &module_payload,
        0,
    );
    node.engine().submit_tx(tx);
    node.metrics().incr_counter("txs_submitted", 1);
    node.engine().run_until_idle();

    // Verify the block was finalized.
    let height = node.engine().finalized_height();
    assert!(height.is_some(), "node: a block should be finalized");
    node.metrics().incr_counter("blocks_finalized", 1);
    if let Some(h) = height {
        node.metrics().set_gauge("finalized_height", i64::try_from(h.value()).unwrap_or(i64::MAX));
    }

    // Verify the state transition executed.
    let balance = node.app().attest_state(primitives::Height::new(0)).expect("executed");
    assert_ne!(balance.root, primitives::Hash::ZERO, "state root should be non-zero");

    // Verify metrics were recorded.
    assert_eq!(node.metrics().counter("txs_submitted"), 1);
    assert_eq!(node.metrics().counter("blocks_finalized"), 1);
    if let Some(h) = height {
        node.metrics().set_gauge("finalized_height", i64::try_from(h.value()).unwrap_or(i64::MAX));
    }
}

/// Build a tx in the mempool's v0 format with a module dispatch byte.
/// Test-only: the default policy rejects unsigned envelopes, so the
/// only non-test caller (the smoke test) signs instead.
#[cfg(test)]
fn build_tx(module_id: u8, module_payload: &[u8]) -> types::TxBytes {
    let sender = Address([0u8; 20]);
    let nonce = 0u64;
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(module_payload);
    types::TxBytes::new(bytes)
}

// ── Parsed-config → assembly conversion ─────────────────────────
//
// The functions below are THE mapping between the TOML/env/CLI
// `config::Config` and the running `NodeConfig`. Both node binaries
// (`oxide-validator`, `oxide-fullnode`) call them — keeping one
// conversion means a field added to the parsed schema cannot drift
// out of sync between the binaries' running systems (the audit's
// core 6.5 complaint: the two binaries each maintained their own
// conversion, and both silently dropped most fields).

/// Which startup path the configuration is being resolved for.
///
/// The modes consume different config fields — e.g. the TCP
/// transport only exists in devnet mode — so
/// [`validate_effective_config`] needs the mode to decide which
/// settings are harmless and which are operator-visible lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    /// Single-node mode: in-process engine, no transport.
    Single,
    /// Multi-validator devnet mode (`oxide-devnet`): real `OxideBft` over the
    /// TCP transport.
    Devnet,
    /// Production multi-validator mode (`oxide-validator --validator`):
    /// `OxideBft` over the TCP/mTLS transport with peers resolved from
    /// `[network] peers` (`addr=host:port` entries) — the same
    /// `validator_net` pump the devnet binary runs.
    Validator,
}

/// Inputs the shared conversion cannot source from `config::Config`
/// itself — CLI flags and binary-resolved choices. `Default` maps
/// to "no overrides" (signed envelopes required, in-memory state,
/// devnet genesis).
#[derive(Debug, Clone, Default)]
pub struct AssemblyOverrides {
    /// `--unsafe-allow-unsigned-txs` CLI flag — OR'd with
    /// `[executor] allow_unsigned_txs`. Named for the hazard it
    /// enables: unsigned envelopes carry an unauthenticated sender.
    pub allow_unsigned_txs: bool,
    /// `--data-dir` / `[storage] data_dir` — the resolved data
    /// directory; its `evm.redb` child becomes `storage_path`.
    pub data_dir: Option<std::path::PathBuf>,
    /// `--wal-file` — explicit consensus WAL location. `None` derives
    /// `<data_dir>/consensus.wal` when a data dir is configured, so
    /// crash recovery covers engine safety state (vote locks,
    /// `high_qc`, `last_committed`) without a second flag.
    pub wal_path: Option<std::path::PathBuf>,
    /// The resolved genesis spec — from `--genesis-file` via
    /// [`genesis_spec_from_file`], or the devnet fallback via
    /// [`genesis_spec_devnet`]. `None` selects `NodeConfig`'s
    /// single-node devnet default.
    pub genesis: Option<GenesisSpec>,
}

/// Map a parsed `config::Config` onto the `NodeConfig` the shared
/// assembly consumes.
///
/// Every field that affects execution, persistence, fees, or
/// consensus parameters is propagated — previously the binaries'
/// per-path conversions hardcoded `min_fee`, `settlement_operator`,
/// `storage_path`, `evm_persistence`, and dropped the consensus
/// timeout/block-budget and network settings entirely.
///
/// In [`NodeMode::Devnet`] the engine is always [`ConsensusConfig::OxideBft`]
/// — the mode itself is the engine selection (a multi-validator
/// cluster cannot run a single-leader sequencer). A parsed
/// `engine = "sequencer"` therefore warns in
/// [`validate_effective_config`] rather than silently running the
/// wrong protocol or failing on a value the operator never set
/// (`ConsensusEngineKind`'s serde default is `sequencer`, so every
/// config-less `oxide-devnet` launch would otherwise be fatal).
///
/// # Errors
///
/// Returns `Err` for malformed values that would panic later (e.g.
/// a bad `exchange.settlement_operator` address) — config errors
/// belong at startup, not mid-run.
pub fn node_config_from(
    config: &config::Config,
    rpc: &config::RpcConfig,
    overrides: &AssemblyOverrides,
    mode: NodeMode,
) -> Result<NodeConfig, String> {
    let consensus = match (config.consensus.engine, mode) {
        (config::ConsensusEngineKind::Sequencer, NodeMode::Single) => ConsensusConfig::Sequencer,
        (_, NodeMode::Devnet | NodeMode::Validator)
        | (config::ConsensusEngineKind::OxideBft, NodeMode::Single) => ConsensusConfig::OxideBft,
    };
    // `[exchange] settlement_operator` is a 0x-hex string in TOML —
    // parse it here so a malformed address fails at startup, not at
    // the first settlement tx.
    let settlement_operator = config
        .exchange
        .settlement_operator
        .as_ref()
        .map(|hex| {
            let bytes = cli::hex_decode(hex)
                .map_err(|e| format!("invalid exchange.settlement_operator address: {e}"))?;
            let arr: [u8; 20] = bytes
                .try_into()
                .map_err(|_| "exchange.settlement_operator must be 20 bytes".to_string())?;
            Ok::<primitives::Address, String>(primitives::Address(arr))
        })
        .transpose()?;
    Ok(NodeConfig {
        consensus,
        max_mempool_entries: config.executor.max_mempool_entries,
        parallel_threshold: config.executor.parallel_threshold,
        // Persistence is always on; `storage_path` selects the
        // backend. With a data dir the EVM state lives in
        // `<dir>/evm.redb` (survives restarts); without one the
        // `Volatile` backend keeps the in-memory behavior.
        evm_persistence: true,
        storage_path: overrides.data_dir.as_ref().map(|d| d.join("evm.redb")),
        // A configured data dir enables the block journal +
        // checkpoint machinery: `evm.redb` alone only persisted the
        // EVM's half of the state, leaving native modules one crash
        // away from a cross-module height tear.
        durability_dir: overrides.data_dir.clone(),
        // Executor durability without the consensus WAL is a trap:
        // the executor would resume at the journaled tip while the
        // engine re-proposed from height 0, re-committing covered
        // heights into the journal. `consensus.wal` restores
        // `last_committed`/`high_qc`/vote locks so the chain
        // continues at tip + 1. An explicit `--wal-file` overrides
        // the derived location.
        wal_path: overrides
            .wal_path
            .clone()
            .or_else(|| overrides.data_dir.as_ref().map(|d| d.join("consensus.wal"))),
        settlement_operator,
        min_fee: config.executor.min_fee,
        // One chain id, one base fee: the executor, the EVM module,
        // and the RPC layer all read the same source so the
        // advertised and enforced parameters cannot diverge.
        chain_id: rpc.chain_id,
        base_fee: rpc.base_fee,
        // Signed envelopes are the default at every layer; the
        // opt-out is an OR of the unsafe flag and the config field
        // so neither can silently weaken the other.
        require_signed_txs: !(overrides.allow_unsigned_txs || config.executor.allow_unsigned_txs),
        history_retention: Some(config.storage.history_retention),
        genesis: overrides.genesis.clone(),
        block_budget: types::BlockBudget {
            max_bytes: config.consensus.max_block_bytes,
            max_gas: config.consensus.max_block_gas,
        },
        base_timeout_ms: config.consensus.base_timeout_ms,
        max_timeout_ms: config.consensus.max_timeout_ms,
        // Pinning is deployment hygiene, not protocol config — it
        // arrives through `[performance]` (TOML/env) rather than the
        // assembly overrides. `None` = unpinned; topology errors are
        // caught by `validate_effective_config` before this is used.
        consensus_core: config.performance.consensus_core,
        exec_lane_core: config.performance.exec_lane_core,
        numa_node: config.performance.numa_node,
        verify_workers: config.performance.verify_workers,
        intake_threads: config.performance.intake_threads,
        rayon_threads: config.performance.rayon_threads,
    })
}

/// Convert a parsed `--genesis-file` into the [`GenesisSpec`] the
/// shared assembly applies: staking validators (address, stake,
/// optional BLS key) plus the legacy `bank.balances` map folded
/// into the EVM ledger scaled to wei (the EVM account store is the
/// single ledger — there is no bank).
///
/// `evm.alloc` is deliberately NOT folded here: its storage slots
/// need a 256-bit type this crate doesn't depend on. The binary
/// applies it directly to the assembled EVM module.
///
/// # Errors
///
/// Returns `Err` naming the malformed entry (index + reason) —
/// genesis errors belong at startup, not mid-run.
pub fn genesis_spec_from_file(genesis: &config::genesis::Genesis) -> Result<GenesisSpec, String> {
    let validators = genesis
        .staking
        .validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let addr_bytes = cli::hex_decode(&v.address)
                .map_err(|e| format!("genesis validator {i} invalid address: {e}"))?;
            let addr: [u8; 20] = addr_bytes
                .try_into()
                .map_err(|_| format!("genesis validator {i} address must be 20 bytes"))?;
            let public_key = v
                .public_key
                .as_ref()
                .map(|pk_hex| {
                    cli::hex_decode(pk_hex)
                        .map_err(|e| format!("genesis validator {i} invalid BLS key: {e}"))
                })
                .transpose()?;
            Ok(GenesisValidator { address: primitives::Address(addr), stake: v.stake, public_key })
        })
        .collect::<Result<Vec<_>, String>>()?;
    // Legacy `bank.balances` (base units) folds into the EVM ledger
    // scaled to wei — the EVM store is the single ledger. Malformed
    // entries fail loudly: silently skipping (or zeroing, as an
    // earlier conversion did) a genesis balance corrupts the money
    // supply with no signal.
    let balances = genesis
        .bank
        .balances
        .iter()
        .map(|(addr_hex, balance_val)| {
            let balance = balance_val
                .as_u64()
                .or_else(|| balance_val.as_str().and_then(|s| s.parse::<u64>().ok()))
                .ok_or_else(|| format!("genesis bank balance for {addr_hex} is not an integer"))?;
            let bytes = cli::hex_decode(addr_hex)
                .map_err(|e| format!("genesis bank address {addr_hex}: {e}"))?;
            let addr: [u8; 20] = bytes
                .try_into()
                .map_err(|_| format!("genesis bank address {addr_hex} must be 20 bytes"))?;
            Ok((primitives::Address(addr), u128::from(balance) * framework::WEI_PER_UNIT))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(GenesisSpec { validators, balances })
}

/// The deterministic devnet genesis spec — `num_validators`
/// validators `[i;20]` at stake `1_000_000` and
/// `num_prefunded_senders` funded addresses `[i;20]` at
/// `genesis_balance` units each. NOT suitable for production.
#[must_use]
pub fn genesis_spec_devnet(fallback: &config::GenesisConfig) -> GenesisSpec {
    let validators = (0..fallback.num_validators)
        .map(|i| GenesisValidator {
            address: primitives::Address([u8::try_from(i).unwrap_or(0); 20]),
            stake: 1_000_000,
            public_key: None,
        })
        .collect();
    let balances = (0..fallback.num_prefunded_senders)
        .map(|i| {
            (
                primitives::Address([i; 20]),
                u128::from(fallback.genesis_balance) * framework::WEI_PER_UNIT,
            )
        })
        .collect();
    GenesisSpec { validators, balances }
}

/// Validate the effective configuration before the node builds
/// anything — the "unsupported settings fail rather than silently
/// do nothing" gate.
///
/// Returns `(warnings, fatal_errors)`: warnings are settings that
/// are consumed-but-overridden in this mode (log them, startup
/// continues); fatal errors are settings that would silently do
/// nothing or are semantically impossible (log them, abort).
///
/// Pure: takes the parsed config, the derived `NodeConfig`, and the
/// mode explicitly so tests can drive it without CLI/env.
#[must_use]
pub fn validate_effective_config(
    config: &config::Config,
    node_config: &NodeConfig,
    mode: NodeMode,
) -> (Vec<String>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    // The sequencer engine cannot run a multi-validator cluster —
    // devnet mode forces oxideBFT regardless (see
    // `node_config_from`). A parsed `engine = "sequencer"` is an
    // override, not a fatal error: `ConsensusEngineKind`'s serde
    // default IS sequencer, so the setting is indistinguishable from
    // "unset" for config-less launches — warning is the honest
    // signal.
    if matches!(mode, NodeMode::Devnet | NodeMode::Validator)
        && config.consensus.engine == config::ConsensusEngineKind::Sequencer
    {
        warnings.push(
            "consensus.engine = \"sequencer\" is overridden in multi-validator mode — \
             running oxideBFT (a single-leader engine cannot run a multi-validator cluster)"
                .to_string(),
        );
    }

    // Pinning/NUMA misconfiguration is a startup error, not a
    // runtime surprise — check the online set and sysfs here so a
    // bad core id fails at `validate` instead of degrading locality
    // silently (hft-audit F-02).
    errors.extend(node_config.perf_pin_errors());

    // `storage.archive` and `journal_retain_segments` have no
    // consumer in the node's storage stack — setting them would
    // silently do nothing, so they fail rather than parse-then-drop.
    if config.storage.archive {
        errors.push(
            "storage.archive = true is not implemented — archive retention is not wired \
             to a consumer in this binary"
                .to_string(),
        );
    }
    if config.storage.journal_retain_segments != 1_000 {
        errors.push(format!(
            "storage.journal_retain_segments = {} is not wired to a consumer in this \
             binary (the EVM backend does not use storage journals)",
            config.storage.journal_retain_segments
        ));
    }

    // `network.listen_addr`/`network.peers` are derived per-index in
    // devnet mode and unused entirely in single-node mode — a
    // config that sets them is valid TOML but not what the operator
    // expects, so it warns rather than fails. In validator mode
    // both are LIVE: `listen_addr` is the transport bind and every
    // `peers` entry must carry the member's staking address
    // (`addr=host:port`) — the transport cannot dial a peer whose
    // committee identity it does not know to expect.
    let network_addr_set = config.network.listen_addr != "127.0.0.1:20000";
    let network_peers_set = !config.network.peers.is_empty();
    match mode {
        NodeMode::Validator => {
            for entry in &config.network.peers {
                let Some((addr_hex, hostport)) = entry.split_once('=') else {
                    errors.push(format!(
                        "network.peers entry {entry:?} is missing `<addr>=` — validator mode \
                         requires `<40-hex-addr>=<host:port>` so the peer's committee identity \
                         is bound to its endpoint before the handshake"
                    ));
                    continue;
                };
                if addr_hex.len() != 40 || !addr_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    errors.push(format!(
                        "network.peers entry {entry:?} has a malformed address — expected \
                         40 hex chars (20 bytes), the member's staking address"
                    ));
                }
                if hostport
                    .rsplit_once(':')
                    .is_none_or(|(h, p)| h.is_empty() || p.parse::<u16>().is_err())
                {
                    errors.push(format!(
                        "network.peers entry {entry:?} has a malformed endpoint — expected \
                         `<host>:<port>` after `=`"
                    ));
                }
            }
            if !network_peers_set {
                warnings.push(
                    "network.peers is empty in validator mode — this node forms a \
                     1-validator network; single-node mode is the honest shape for that"
                        .to_string(),
                );
            }
        }
        _ if network_addr_set || network_peers_set => {
            // Validator is handled above; only Devnet and Single
            // reach this arm.
            let why = if mode == NodeMode::Devnet {
                "overridden by the --node/--base-port index derivation"
            } else {
                "no transport runs in single-node mode"
            };
            warnings.push(format!(
                "network.listen_addr/network.peers are set but {why} — \
                 only network.*_timeout_secs and network.max_message_bytes apply"
            ));
        }
        _ => {}
    }

    if !node_config.require_signed_txs {
        warnings.push(
            "UNSAFE: unsigned native-module envelopes are admitted \
             ([executor] allow_unsigned_txs / --unsafe-allow-unsigned-txs) — \
             ctx.sender is unauthenticated and any account can be impersonated; \
             never run this on a network reachable by untrusted submitters"
                .to_string(),
        );
    }

    (warnings, errors)
}

#[cfg(test)]
mod tests;
