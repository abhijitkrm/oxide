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
//!     settlement_operator: None,
//!     min_fee: 0,
//!     chain_id: 1,
//!     require_signed_txs: false,
//!     history_retention: None,
//!     base_fee: 7_000_000_000,
//!     genesis: None,
//!     block_budget: types::CHAIN_BLOCK_BUDGET,
//!     base_timeout_ms: 2_000,
//!     max_timeout_ms: 30_000,
//! };
//! let mut node = Node::assemble(&config);
//! // Drive consensus, inspect state, etc.
//! ```

use std::sync::Arc;

use consensus::{OxideBft, SequencerEngine};
use executor::Executor;
use ports::{AppInterface, ConsensusEngine};
use primitives::Address;

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
    /// The settlement operator address — the only account allowed to
    /// submit exchange `batch_settle` transactions (the off-chain
    /// matching service's tx sender). `None` disables batch
    /// settlement entirely (fail-closed default — safe when no
    /// external matcher is attached to this node).
    pub settlement_operator: Option<primitives::Address>,
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
    /// `false` (default) admits unsigned envelopes — the historical
    /// devnet behaviour, where `ctx.sender` is trusted as declared.
    /// `true` enforces EIP-712 envelope signatures at mempool
    /// admission and execution. Required for production: without it,
    /// any native-module tx can claim any sender.
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
    /// single-node devnet default: `[0u8; 20]` is funded with
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
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            base_fee: 7_000_000_000,
            genesis: None,
            block_budget: types::CHAIN_BLOCK_BUDGET,
            base_timeout_ms: 2_000,
            max_timeout_ms: 30_000,
        }
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
    ///   Funds `[0u8; 20]` with `u128::MAX` for test/devnet use. The
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
            ConsensusConfig::Sequencer => Box::new(SequencerEngine::new(app_dyn.clone())),
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
                Box::new(
                    OxideBft::new(app_dyn.clone(), vs)
                        .with_secret_key(key)
                        .with_pacemaker_timeouts(config.base_timeout_ms, config.max_timeout_ms)
                        .with_block_budget(config.block_budget),
                )
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
    /// validates the snapshot before modifying any state).
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
}

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
pub fn assemble_executor(config: &NodeConfig) -> AssembledExecutor {
    // Build the executor with standard modules. Use `with_config`
    // so the parallel threshold is configurable (default: 32 txs,
    // lowered from 100 in the block-size sweep session — rayon
    // overhead amortizes at 32+).
    let mut executor = Executor::with_config(config.max_mempool_entries, config.parallel_threshold)
        .with_min_fee(config.min_fee)
        .with_chain_id(config.chain_id)
        .with_unsigned_tx_policy(if config.require_signed_txs {
            executor::UnsignedTxPolicy::Reject
        } else {
            executor::UnsignedTxPolicy::Allow
        });
    if let Some(n) = config.history_retention {
        executor = executor.with_history_retention(n);
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
        // Single-node devnet default: fund and register the
        // deterministic `[0u8;20]` sender/validator identity so
        // self-delegation (e.g. the key-change keep-alive delegate)
        // has a registered target. Development convenience only —
        // production passes an explicit `GenesisSpec`.
        None => {
            evm_module.fund_account_for_test(&primitives::Address([0u8; 20]), u128::MAX);
            staking_module.register_validator(primitives::Address([0u8; 20]));
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
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
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
                tick_size: 1_000_000,
                lot_size: 1_000,
                min_price: 1_000_000_000,
                max_price: 2_000_000_000,
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
    // Governance: minimal on-chain parameter votes (plan.md §7 —
    // Phase 4 scope: propose/vote/finalize, no timelock/veto).
    executor.register_module(Arc::new(governance::GovernanceModule::new()));
    // Wire the exchange and perps modules into the EVM for
    // read-only precompiles (plan.md §10), then register the EVM.
    evm_module.set_native_modules(Some(exchange), Some(perps));
    executor.register_module(evm_module.clone());
    let app: Arc<Executor> = Arc::new(executor);
    // Spawn the async execution lane (plan.md §13 Phase D):
    // `finalize_block` hands each committed block to a worker
    // thread, overlapping execution of block h with consensus
    // for block h+1. Both binary paths get the lane — the
    // multi-validator binary previously ran without it, a second
    // execution pipeline with different backpressure behavior.
    app.spawn_exec_lane();
    AssembledExecutor { app, evm_module, staking_module }
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

    // Submit a staking delegate tx — sender [0u8;20] is a
    // registered validator and is genesis-funded on the EVM ledger.
    let validator = Address([0u8; 20]);
    let module_payload = staking::msg::delegate(validator, 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
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
/// transport only exists in devnet-node mode — so
/// [`validate_effective_config`] needs the mode to decide which
/// settings are harmless and which are operator-visible lies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeMode {
    /// Single-node mode: in-process engine, no transport.
    Single,
    /// Multi-validator devnet-node mode: real `OxideBft` over the
    /// TCP transport.
    Devnet,
}

/// Inputs the shared conversion cannot source from `config::Config`
/// itself — CLI flags and binary-resolved choices. `Default` maps
/// to "no overrides" (devnet-compatible unsigned txs, in-memory
/// state, devnet genesis).
#[derive(Debug, Clone, Default)]
pub struct AssemblyOverrides {
    /// `--require-signed-txs` CLI flag — OR'd with
    /// `[executor] require_signed_txs`.
    pub require_signed_txs: bool,
    /// `--data-dir` / `[storage] data_dir` — the resolved data
    /// directory; its `evm.redb` child becomes `storage_path`.
    pub data_dir: Option<std::path::PathBuf>,
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
/// config-less `--devnet-node` launch would otherwise be fatal).
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
        (_, NodeMode::Devnet) | (config::ConsensusEngineKind::OxideBft, NodeMode::Single) => {
            ConsensusConfig::OxideBft
        }
    };
    // `[exchange] settlement_operator` is a 0x-hex string in TOML —
    // parse it here so a malformed address fails at startup, not at
    // the first settlement tx.
    let settlement_operator = config
        .exchange
        .settlement_operator
        .as_ref()
        .map(|hex| {
            let bytes = hex_decode(hex)
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
        settlement_operator,
        min_fee: config.executor.min_fee,
        // One chain id, one base fee: the executor, the EVM module,
        // and the RPC layer all read the same source so the
        // advertised and enforced parameters cannot diverge.
        chain_id: rpc.chain_id,
        base_fee: rpc.base_fee,
        require_signed_txs: overrides.require_signed_txs || config.executor.require_signed_txs,
        history_retention: Some(config.storage.history_retention),
        genesis: overrides.genesis.clone(),
        block_budget: types::BlockBudget {
            max_bytes: config.consensus.max_block_bytes,
            max_gas: config.consensus.max_block_gas,
        },
        base_timeout_ms: config.consensus.base_timeout_ms,
        max_timeout_ms: config.consensus.max_timeout_ms,
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
            let addr_bytes = hex_decode(&v.address)
                .map_err(|e| format!("genesis validator {i} invalid address: {e}"))?;
            let addr: [u8; 20] = addr_bytes
                .try_into()
                .map_err(|_| format!("genesis validator {i} address must be 20 bytes"))?;
            let public_key = v
                .public_key
                .as_ref()
                .map(|pk_hex| {
                    hex_decode(pk_hex)
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
            let bytes = hex_decode(addr_hex)
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
    // devnet-node mode forces oxideBFT regardless (see
    // `node_config_from`). A parsed `engine = "sequencer"` is an
    // override, not a fatal error: `ConsensusEngineKind`'s serde
    // default IS sequencer, so the setting is indistinguishable from
    // "unset" for config-less launches — warning is the honest
    // signal.
    if mode == NodeMode::Devnet && config.consensus.engine == config::ConsensusEngineKind::Sequencer
    {
        warnings.push(
            "consensus.engine = \"sequencer\" is overridden in --devnet-node mode — \
             running oxideBFT (a single-leader engine cannot run a multi-validator cluster)"
                .to_string(),
        );
    }

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
    // devnet-node mode and unused entirely in single-node mode — a
    // config that sets them is valid TOML but not what the operator
    // expects, so it warns rather than fails.
    let network_addr_set = config.network.listen_addr != "127.0.0.1:20000";
    let network_peers_set = !config.network.peers.is_empty();
    if network_addr_set || network_peers_set {
        let why = match mode {
            NodeMode::Devnet => "overridden by the --devnet-node/--base-port index derivation",
            NodeMode::Single => "no transport runs in single-node mode",
        };
        warnings.push(format!(
            "network.listen_addr/network.peers are set but {why} — \
             only network.*_timeout_secs and network.max_message_bytes apply"
        ));
    }

    if !node_config.require_signed_txs {
        warnings.push(
            "executor.require_signed_txs is off — unsigned native-module envelopes are \
             admitted (devnet compatibility; enable for production)"
                .to_string(),
        );
    }

    (warnings, errors)
}

/// Decode a bare-or-`0x` hex string to bytes (genesis addresses,
/// keys, operator addresses).
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err("odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use executor::Module;

    #[test]
    fn node_assembles_with_sequencer() {
        let config = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node = Node::assemble(&config);
        // The engine should be ready (no blocks yet).
        assert!(node.engine().finalized_height().is_none());
    }

    #[test]
    fn node_assembles_with_oxidebft() {
        let config = NodeConfig {
            consensus: ConsensusConfig::OxideBft,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node = Node::assemble(&config);
        assert!(node.engine().finalized_height().is_none());
    }

    #[test]
    fn node_smoke_test_passes() {
        run_node_smoke_test();
    }

    #[test]
    fn config_parses_engine_names() {
        assert_eq!(ConsensusConfig::parse("sequencer"), Some(ConsensusConfig::Sequencer));
        assert_eq!(ConsensusConfig::parse("oxideBFT"), Some(ConsensusConfig::OxideBft));
        assert_eq!(ConsensusConfig::parse("unknown"), None);
    }

    #[test]
    fn config_engine_swap_produces_same_app() {
        // The seam proof: the same app (executor + modules) runs under
        // either engine config without changes.
        let seq_config = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let bft_config = NodeConfig {
            consensus: ConsensusConfig::OxideBft,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };

        let mut seq_node = Node::assemble(&seq_config);
        let mut bft_node = Node::assemble(&bft_config);

        // Both should assemble and be ready to run.
        assert!(seq_node.engine().finalized_height().is_none());
        assert!(bft_node.engine().finalized_height().is_none());
    }

    #[test]
    fn fund_evm_account_works() {
        let node = Node::assemble(&NodeConfig::default());
        let addr = primitives::Address([0xAB; 20]);
        node.fund_evm_account(&addr, 1_000_000_000);
        // The EVM module should have the account funded.
        // We can't directly check the balance without importing
        // executor::Module, but the fact that this doesn't panic is
        // the proof that the EVM module is registered.
    }

    // ─── Disk-backed EVM storage tests ───────────────────────────

    #[test]
    fn disk_backed_evm_storage_assembles() {
        // A node with a disk-backed EVM store should assemble and
        // run consensus without errors.
        let tmp = std::env::temp_dir().join(format!(
            "oxide-test-redb-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let config = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: Some(tmp.clone()),
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node = Node::assemble(&config);
        // Submit a tx and finalize a block.
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);
        node.engine().run_until_idle();
        assert!(node.engine().finalized_height().is_some(), "block finalized");
        // Clean up the temp file.
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn full_kv_snapshot_sync_restores_evm_state() {
        // Full KV snapshot sync: export a snapshot with actual KV
        // state from a node with a disk-backed EVM store, import it
        // into a fresh node, and verify the EVM state matches.
        let tmp1 = std::env::temp_dir().join(format!(
            "oxide-test-snap-src-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let tmp2 = std::env::temp_dir().join(format!(
            "oxide-test-snap-dst-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));

        // Source node: disk-backed EVM store.
        let config_src = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: Some(tmp1.clone()),
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node_src = Node::assemble(&config_src);
        // Submit a tx and finalize a block to produce EVM state.
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node_src.engine().submit_tx(tx);
        node_src.engine().run_until_idle();
        assert!(node_src.engine().finalized_height().is_some());

        // Export the snapshot (with full KV state).
        let snapshot = node_src.export_snapshot();
        assert!(!snapshot.module_state.is_empty(), "snapshot must include module state");
        // At least one module (EVM) should have exported KV state.
        let has_kv = snapshot.module_state.iter().any(Option::is_some);
        assert!(has_kv, "at least one module must export KV state");

        // Destination node: fresh disk-backed EVM store.
        let config_dst = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: Some(tmp2.clone()),
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let node_dst = Node::assemble(&config_dst);

        // Import the snapshot into the destination node.
        node_dst.import_snapshot(&snapshot).expect("snapshot import must succeed");

        // Verify the destination node's height matches.
        assert_eq!(
            node_dst.app_handle().current_height(),
            node_src.app_handle().current_height(),
            "height must match after snapshot sync"
        );

        // Verify the EVM module's state root matches — this proves
        // the full KV state was transferred. Other modules (core,
        // staking) don't have StorageBackends yet, so their state
        // remains at genesis; the aggregate root won't match until
        // all modules support export_state/import_state.
        let evm_src = node_src.evm_module().expect("src has EVM");
        let evm_dst = node_dst.evm_module().expect("dst has EVM");
        assert_eq!(
            evm_dst.state_root(),
            evm_src.state_root(),
            "EVM state root must match after full KV snapshot sync"
        );

        // Clean up.
        let _ = std::fs::remove_file(&tmp1);
        let _ = std::fs::remove_file(&tmp2);
    }

    // ─── Snapshot sync tests ─────────────────────────────────────

    #[test]
    fn snapshot_export_round_trip() {
        // Assemble a node, finalize a block, export a snapshot,
        // import it into a fresh node, and verify the state matches.
        let config = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node = Node::assemble(&config);
        // Submit a tx and finalize a block.
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);
        node.engine().run_until_idle();
        assert!(node.engine().finalized_height().is_some(), "block finalized");

        // Export the snapshot.
        let snapshot = node.export_snapshot();
        // Height may be 0 (genesis block) — that's valid.
        assert!(!snapshot.module_roots.is_empty(), "snapshot must have module roots");

        // Import into a fresh node.
        let node2 =
            Node::assemble_from_snapshot(&config, &snapshot).expect("snapshot import must succeed");
        // The imported node's chain height must match the snapshot.
        assert_eq!(node2.app().current_height(), snapshot.height, "height must match after import");
        // The imported node's state root at the snapshot height must
        // match the snapshot's state root (it was set during import).
        assert_eq!(
            node2.app().state_root_at(snapshot.height),
            snapshot.state_root,
            "state root must match after import"
        );
    }

    #[test]
    fn snapshot_import_rejects_empty() {
        let config = NodeConfig::default();
        let node = Node::assemble(&config);
        let empty_snapshot = executor::ExecutorSnapshot {
            height: 5,
            state_root: primitives::Hash::ZERO,
            module_roots: vec![],
            module_state: vec![],
            executed_nonces: vec![],
            nonce_root: primitives::Hash::ZERO,
            version: executor::SNAPSHOT_FORMAT_VERSION,
            module_versions: vec![],
        };
        let err = node.import_snapshot(&empty_snapshot).expect_err("empty snapshot must fail");
        assert_eq!(err, executor::SnapshotImportError::EmptySnapshot);
    }

    #[test]
    fn snapshot_import_rejects_corrupted_state_root() {
        let config = NodeConfig::default();
        let mut node = Node::assemble(&config);
        // Finalize a block to get a real snapshot.
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);
        node.engine().run_until_idle();

        let mut snapshot = node.export_snapshot();
        // Corrupt the state root so it doesn't match the module roots.
        snapshot.state_root = primitives::Hash([0xFF; 32]);

        let node2 = Node::assemble(&config);
        let err = node2.import_snapshot(&snapshot).expect_err("corrupted snapshot must fail");
        match err {
            executor::SnapshotImportError::StateRootMismatch { expected, .. } => {
                assert_eq!(expected, primitives::Hash([0xFF; 32]));
            }
            other => panic!("expected StateRootMismatch, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_import_rejects_module_count_mismatch() {
        use crypto::hash::{Domain, Hasher};
        let config = NodeConfig::default();
        let mut node = Node::assemble(&config);
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);
        node.engine().run_until_idle();

        let mut snapshot = node.export_snapshot();
        // Add a fake module root to create a count mismatch.
        // Also recompute the state root to match so we test the
        // module count check, not the state root check.
        snapshot.module_roots.push(("fake".to_string(), primitives::Hash::ZERO));
        let mut root_data = Vec::new();
        for (_, root) in &snapshot.module_roots {
            root_data.extend_from_slice(root.as_bytes());
        }
        // HIGH fix: include the nonce root in the state root
        // recomputation (it's now part of the authenticated root).
        root_data.extend_from_slice(snapshot.nonce_root.as_bytes());
        snapshot.state_root = Hasher::hash_one(Domain::Block, &root_data);

        let node2 = Node::assemble(&config);
        let err = node2.import_snapshot(&snapshot).expect_err("module count mismatch must fail");
        match err {
            executor::SnapshotImportError::ModuleCountMismatch { snapshot: s, registered: r } => {
                assert!(s > r, "snapshot has more modules than registered");
            }
            other => panic!("expected ModuleCountMismatch, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_resume_after_import() {
        // After importing a snapshot, the node should be able to
        // resume consensus: finalize new blocks at height + 1, + 2, etc.
        let config = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node = Node::assemble(&config);
        // Finalize one block.
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);
        node.engine().run_until_idle();
        let snapshot = node.export_snapshot();
        let original_height = snapshot.height;

        // Import into a fresh node and resume.
        let mut node2 =
            Node::assemble_from_snapshot(&config, &snapshot).expect("snapshot import must succeed");
        // The executor's height should match the snapshot.
        assert_eq!(
            node2.app().current_height(),
            original_height,
            "executor height must match snapshot"
        );
        // Submit another tx and finalize — should produce a new block.
        let module_payload2 = staking::msg::delegate(Address([0u8; 20]), 50);
        let tx2 = build_tx(framework::module_id::STAKING, &module_payload2);
        node2.engine().submit_tx(tx2);
        node2.engine().run_until_idle();
        // The executor's height should have advanced.
        assert!(
            node2.app().current_height() > original_height,
            "executor height must advance after new block"
        );
    }

    #[test]
    fn snapshot_export_deterministic() {
        // Two nodes with the same state produce the same snapshot.
        let config = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node1 = Node::assemble(&config);
        let mut node2 = Node::assemble(&config);
        // Both finalize the same block.
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node1.engine().submit_tx(tx.clone());
        node2.engine().submit_tx(tx);
        node1.engine().run_until_idle();
        node2.engine().run_until_idle();

        let snap1 = node1.export_snapshot();
        let snap2 = node2.export_snapshot();
        assert_eq!(snap1.height, snap2.height, "heights must match");
        assert_eq!(snap1.state_root, snap2.state_root, "state roots must match");
        assert_eq!(snap1.module_roots, snap2.module_roots, "module roots must match");
    }

    // ─── Metrics tests ───────────────────────────────────────────

    #[test]
    fn metrics_recorder_available_after_assemble() {
        let node = Node::assemble(&NodeConfig::default());
        // The metrics recorder should be available and empty.
        let prom = node.metrics().prometheus();
        // No metrics recorded yet — output should have headers but
        // no data lines.
        assert!(prom.contains("oxide_latency_ns"));
    }

    #[test]
    fn metrics_records_snapshot_export() {
        let config = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node = Node::assemble(&config);
        // Finalize a block.
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);
        node.engine().run_until_idle();

        // Export a snapshot — should record metrics.
        let _ = node.export_snapshot();
        assert!(node.metrics().counter("snapshot_exports") >= 1);
        assert!(node.metrics().snapshot("snapshot_export").is_some());
    }

    #[test]
    fn metrics_records_snapshot_import() {
        let config = NodeConfig {
            consensus: ConsensusConfig::Sequencer,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: true,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
            history_retention: None,
            ..Default::default()
        };
        let mut node = Node::assemble(&config);
        let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);
        node.engine().run_until_idle();
        let snapshot = node.export_snapshot();

        // Import into a fresh node — should record metrics.
        let node2 = Node::assemble(&config);
        node2.import_snapshot(&snapshot).expect("import must succeed");
        assert!(node2.metrics().counter("snapshot_imports") >= 1);
        assert!(node2.metrics().snapshot("snapshot_import").is_some());
    }

    #[test]
    fn metrics_prometheus_includes_counters_and_gauges() {
        let node = Node::assemble(&NodeConfig::default());
        node.metrics().incr_counter("test_counter", 42);
        node.metrics().set_gauge("test_gauge", 100);
        let prom = node.metrics().prometheus();
        assert!(prom.contains("oxide_counter{name=\"test_counter\"} 42"));
        assert!(prom.contains("oxide_gauge{name=\"test_gauge\"} 100"));
    }

    // ── Shared config conversion (the 6.5 remediation) ──────────

    /// A `config::Config` with every propagated field set to a
    /// non-default value — the fixture `node_config_from` tests run
    /// against.
    fn full_config() -> config::Config {
        let mut config = config::Config::default();
        config.consensus.engine = config::ConsensusEngineKind::OxideBft;
        config.consensus.base_timeout_ms = 5_000;
        config.consensus.max_timeout_ms = 60_000;
        config.consensus.max_block_bytes = 4 << 20;
        config.consensus.max_block_gas = 2_000_000_000;
        config.executor.max_mempool_entries = 777;
        config.executor.parallel_threshold = 64;
        config.executor.min_fee = 42;
        config.executor.require_signed_txs = true;
        config.storage.history_retention = 128;
        config.exchange.settlement_operator = Some(format!("0x{}", "ab".repeat(20)));
        config
    }

    #[test]
    fn node_config_from_propagates_every_field() {
        let config = full_config();
        let rpc = config::RpcConfig { chain_id: 7777, base_fee: 123_456, ..Default::default() };
        let data_dir = std::path::PathBuf::from("/tmp/oxide-test");
        let overrides = AssemblyOverrides {
            require_signed_txs: false,
            data_dir: Some(data_dir.clone()),
            genesis: None,
        };
        let node_config = node_config_from(&config, &rpc, &overrides, NodeMode::Single)
            .expect("valid config maps cleanly");

        assert_eq!(node_config.consensus, ConsensusConfig::OxideBft);
        assert_eq!(node_config.max_mempool_entries, 777);
        assert_eq!(node_config.parallel_threshold, 64);
        assert_eq!(node_config.min_fee, 42);
        assert_eq!(node_config.chain_id, 7777);
        assert_eq!(node_config.base_fee, 123_456);
        assert!(node_config.require_signed_txs);
        assert_eq!(node_config.history_retention, Some(128));
        assert_eq!(
            node_config.storage_path,
            Some(data_dir.join("evm.redb")),
            "data_dir must become the EVM state path"
        );
        assert_eq!(
            node_config.settlement_operator,
            Some(primitives::Address([0xab; 20])),
            "the hex operator address must parse"
        );
        assert_eq!(
            node_config.block_budget,
            types::BlockBudget { max_bytes: 4 << 20, max_gas: 2_000_000_000 },
            "consensus block budgets must reach the engine"
        );
        assert_eq!(node_config.base_timeout_ms, 5_000);
        assert_eq!(node_config.max_timeout_ms, 60_000);
    }

    #[test]
    fn node_config_from_cli_flag_or_toml_enables_signed_txs() {
        let mut config = config::Config::default();
        config.executor.require_signed_txs = false;
        let rpc = config::RpcConfig::default();
        // CLI flag alone enables it.
        let with_cli = AssemblyOverrides { require_signed_txs: true, ..Default::default() };
        assert!(
            node_config_from(&config, &rpc, &with_cli, NodeMode::Single)
                .expect("ok")
                .require_signed_txs
        );
        // TOML alone enables it.
        config.executor.require_signed_txs = true;
        assert!(
            node_config_from(&config, &rpc, &AssemblyOverrides::default(), NodeMode::Single)
                .expect("ok")
                .require_signed_txs
        );
    }

    #[test]
    fn node_config_from_rejects_bad_operator_address() {
        let mut config = config::Config::default();
        config.exchange.settlement_operator = Some("0xzz".to_string());
        let err = node_config_from(
            &config,
            &config::RpcConfig::default(),
            &AssemblyOverrides::default(),
            NodeMode::Single,
        )
        .expect_err("malformed operator hex must fail");
        assert!(err.contains("settlement_operator"), "error should name the field: {err}");
    }

    #[test]
    fn genesis_spec_from_file_converts_validators_and_balances() {
        let bls_hex = "11".repeat(48);
        let json = format!(
            r#"{{
                "chain_id": 1,
                "bank": {{ "balances": {{ "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "1000" }} }},
                "staking": {{ "validators": [
                    {{ "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                      "stake": 5000,
                      "public_key": "{bls_hex}" }}
                ] }}
            }}"#
        );
        let genesis = config::genesis::Genesis::from_json_str(&json).expect("test genesis parses");
        let spec = genesis_spec_from_file(&genesis).expect("valid genesis converts");
        assert_eq!(spec.validators.len(), 1);
        assert_eq!(spec.validators[0].address, primitives::Address([0xbb; 20]));
        assert_eq!(spec.validators[0].stake, 5_000);
        assert_eq!(spec.validators[0].public_key.as_ref().map(Vec::len), Some(48));
        assert_eq!(spec.balances.len(), 1);
        assert_eq!(spec.balances[0].0, primitives::Address([0xaa; 20]));
        assert_eq!(spec.balances[0].1, 1_000 * framework::WEI_PER_UNIT);
    }

    #[test]
    fn genesis_spec_devnet_synthesizes_fallback() {
        let fallback = config::GenesisConfig {
            num_validators: 3,
            num_prefunded_senders: 5,
            genesis_balance: 7,
            ..Default::default()
        };
        let spec = genesis_spec_devnet(&fallback);
        assert_eq!(spec.validators.len(), 3);
        assert_eq!(spec.balances.len(), 5);
        assert_eq!(spec.validators[0].stake, 1_000_000);
        assert_eq!(spec.balances[4].1, 7 * framework::WEI_PER_UNIT);
    }

    #[test]
    fn devnet_mode_forces_oxidebft_and_warns_on_sequencer() {
        // `--devnet-node` with no --engine/--config parses
        // `ConsensusEngineKind`'s serde default (sequencer) — the
        // mode must still run oxideBFT, and warn rather than fail
        // on a value indistinguishable from "unset".
        let mut config = config::Config::default();
        config.consensus.engine = config::ConsensusEngineKind::Sequencer;
        let node_config = node_config_from(
            &config,
            &config::RpcConfig::default(),
            &AssemblyOverrides::default(),
            NodeMode::Devnet,
        )
        .expect("ok");
        assert_eq!(
            node_config.consensus,
            ConsensusConfig::OxideBft,
            "devnet-node mode always runs oxideBFT"
        );
        let (warnings, errors) = validate_effective_config(&config, &node_config, NodeMode::Devnet);
        assert!(errors.is_empty(), "the override warns, never fails: {errors:?}");
        assert!(
            warnings.iter().any(|w| w.contains("sequencer")),
            "the override must be visible: {warnings:?}"
        );
        // The same parsed engine is honored (not overridden) in
        // single-node mode.
        let single_config = node_config_from(
            &config,
            &config::RpcConfig::default(),
            &AssemblyOverrides::default(),
            NodeMode::Single,
        )
        .expect("ok");
        assert_eq!(single_config.consensus, ConsensusConfig::Sequencer);
    }

    #[test]
    fn validate_effective_config_fails_on_unwired_settings() {
        let mut config = config::Config::default();
        config.storage.archive = true;
        config.storage.journal_retain_segments = 5;
        let node_config = node_config_from(
            &config,
            &config::RpcConfig::default(),
            &AssemblyOverrides::default(),
            NodeMode::Devnet,
        )
        .expect("ok");
        let (_, errors) = validate_effective_config(&config, &node_config, NodeMode::Single);
        assert!(errors.iter().any(|e| e.contains("archive")), "archive must fail: {errors:?}");
        assert!(
            errors.iter().any(|e| e.contains("journal_retain_segments")),
            "journal_retain_segments must fail: {errors:?}"
        );
    }

    #[test]
    fn validate_effective_config_warns_on_overrides_and_unsigned() {
        let mut config = config::Config::default();
        config.network.peers = vec!["127.0.0.1:20001".to_string()];
        let node_config = node_config_from(
            &config,
            &config::RpcConfig::default(),
            &AssemblyOverrides::default(),
            NodeMode::Devnet,
        )
        .expect("ok");
        let (warnings, errors) = validate_effective_config(&config, &node_config, NodeMode::Devnet);
        assert!(errors.is_empty());
        assert!(
            warnings.iter().any(|w| w.contains("network.peers")),
            "derived peer config should warn: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("require_signed_txs")),
            "unsigned envelopes should warn: {warnings:?}"
        );
    }

    // ── Shared executor assembly ─────────────────────────────────

    #[test]
    fn assemble_executor_registers_the_full_module_graph() {
        let assembled = assemble_executor(&NodeConfig::default());
        let snap = assembled.app.export_snapshot();
        let names: Vec<&str> = snap.module_roots.iter().map(|(name, _)| name.as_str()).collect();
        for expected in ["core", "staking", "exchange", "perps", "oracle", "governance", "evm"] {
            assert!(
                names.contains(&expected),
                "module {expected} missing from the assembled graph: {names:?}"
            );
        }
    }

    #[test]
    fn assemble_executor_honors_chain_id_and_base_fee() {
        // Previously the EVM module hardcoded chain id 1 / 7 gwei
        // while the executor's chain id was configurable — the two
        // could silently diverge.
        let config = NodeConfig { chain_id: 7777, base_fee: 555, ..Default::default() };
        let assembled = assemble_executor(&config);
        assert_eq!(assembled.evm_module.chain_id(), 7777);
        assert_eq!(assembled.evm_module.base_fee(), 555);
    }

    #[test]
    fn assemble_executor_applies_genesis_spec() {
        let validator = primitives::Address([0x11; 20]);
        let funded = primitives::Address([0x22; 20]);
        let spec = GenesisSpec {
            validators: vec![GenesisValidator {
                address: validator,
                stake: 9_000,
                public_key: None,
            }],
            balances: vec![(funded, 42_000)],
        };
        let config = NodeConfig { genesis: Some(spec), ..Default::default() };
        let assembled = assemble_executor(&config);
        assert_eq!(assembled.staking_module.stake(&validator), 9_000);
        assert_eq!(assembled.evm_module.balance(&funded), 42_000);
        // The devnet-default `[0u8;20]` validator must NOT be
        // registered when an explicit spec is given.
        assert_eq!(assembled.staking_module.stake(&primitives::Address([0u8; 20])), 0);
    }

    #[test]
    fn assemble_executor_devnet_default_registers_zero_identity() {
        let assembled = assemble_executor(&NodeConfig::default());
        // The devnet default funds and registers `[0u8;20]`.
        assert!(assembled.evm_module.balance(&primitives::Address([0u8; 20])) > 0);
    }

    /// End-to-end: a real oxideBFT commit drives the executor, which
    /// delivers the consensus execution context to the EVM — the
    /// sealed block's timestamp is the proposer's wall-clock stamp
    /// (seconds), not the height-derived stand-in.
    #[test]
    fn committed_block_timestamp_reaches_evm_history() {
        let config = NodeConfig { consensus: ConsensusConfig::OxideBft, ..Default::default() };
        let mut node = Node::assemble(&config);

        // A staking delegate tx — the same payload the smoke test
        // uses, from the genesis-funded `[0u8;20]` validator.
        let validator = Address([0u8; 20]);
        let module_payload = staking::msg::delegate(validator, 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);
        node.engine().run_until_idle();
        assert!(node.engine().finalized_height().is_some(), "a block finalized");

        let evm = node.evm_module().expect("evm module registered");
        let sealed = {
            let history = evm.history();
            history.block(0).cloned()
        }
        .expect("block 0 sealed in history");
        // Height-derived would be `0 * 15 = 0`; a real epoch stamp is
        // post-2001 — assert the value came from a wall clock, not
        // the stand-in formula.
        assert!(
            sealed.timestamp > 1_000_000_000,
            "sealed timestamp {} must be a real epoch value",
            sealed.timestamp
        );
        // The gas limit is the consensus-enforced budget, and the
        // beneficiary is the single validator's staking address —
        // derived from its BLS key the same way `ValidatorSet` does.
        assert_eq!(sealed.gas_limit, config.block_budget.max_gas);
        let key = crypto::BlsSecretKey::from_ikm(&[1u8; 32]).expect("BLS key");
        let expected_beneficiary = crypto::bls::validator_address(&key.public_key());
        assert_eq!(sealed.coinbase.0, expected_beneficiary.0);
    }
}
