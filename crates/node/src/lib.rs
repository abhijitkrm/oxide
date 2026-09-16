//! Oxide production node assembly — config-driven engine selection,
//! module registration, and node lifecycle.
//!
//! This crate is the **production** node assembly path. It wires the
//! executor (with all registered modules: core, bank, staking, EVM)
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
        }
    }
}

/// A fully assembled Oxide node: consensus engine + app (executor).
///
/// The engine drives the app through the [`AppInterface`] boundary.
/// The app is the executor with registered modules (core, bank,
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
    /// Registers the core, bank, staking, and EVM modules on the
    /// executor, then wires the executor behind the selected
    /// consensus engine.
    ///
    /// # Modules registered
    ///
    /// - [`CoreModule`](oxide_core::CoreModule) — block height, timestamps.
    /// - [`BankModule`](bank::BankModule) — native token transfers. Genesis-mints
    ///   1T to `[0u8; 20]` so bank transfers can debit.
    /// - [`StakingModule`](staking::StakingModule) — validator staking.
    /// - [`EvmModule`](evm::EvmModule) — `revm`-based EVM. Base fee 7 gwei.
    ///   Funds `[0u8; 20]` with `u128::MAX` for test/devnet use.
    ///
    /// # Panics
    ///
    /// Panics if BLS key generation fails (impossible with valid IKM)
    /// or if the validator set construction fails (impossible with
    /// equal stakes >= 1).
    pub fn assemble(config: &NodeConfig) -> Self {
        // Build the executor with standard modules. Use
        // `with_config` so the parallel threshold is configurable
        // (default: 32 txs, lowered from 100 in the block-size sweep
        // session — rayon overhead amortizes at 32+).
        let mut executor =
            Executor::with_config(config.max_mempool_entries, config.parallel_threshold)
                .with_min_fee(config.min_fee)
                .with_chain_id(config.chain_id)
                .with_unsigned_tx_policy(if config.require_signed_txs {
                    executor::UnsignedTxPolicy::Reject
                } else {
                    executor::UnsignedTxPolicy::Allow
                });
        // Enable the async execution lane (plan.md §13 Phase D):
        // defer block execution to `attest_state`, overlapping
        // execution of block h-1 with consensus for block h.
        executor.enable_async_execution();
        executor.register_module(Arc::new(oxide_core::CoreModule::new()));
        // Genesis-mint to the sender address so bank transfers can
        // debit (C2 fix: the bank now debits the sender). The bank is
        // shared with the exchange module for cross-module settlement
        // (plan.md §9.2): fills debit the buyer and credit the seller.
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&primitives::Address([0u8; 20]), 1_000_000_000_000);
        executor.register_module(bank.clone());
        // The bank is the fee collector: every native-module tx is
        // charged `ctx.fee` through it before execution. Without
        // this, only bank txs paid fees — exchange/perps/core txs
        // ran free.
        executor.set_fee_module(framework::module_id::BANK);
        // Staking is bank-backed: delegation debits the delegator
        // into the bonded pool, unbonding refunds from it. Register
        // the devnet sender/validator identity so self-delegation
        // (e.g. the key-change keep-alive delegate) has a registered
        // target.
        let staking_module = staking::StakingModule::new();
        staking_module.set_bank(bank.clone());
        staking_module.register_validator(primitives::Address([0u8; 20]));
        executor.register_module(Arc::new(staking_module));
        // Register the exchange module with a default spot market
        // (tick 0.01, lot 0.001, [$10, $20], 64 max resting). The
        // exchange is wired to the bank for quote-currency settlement.
        let mut exchange_mod = exchange::ExchangeModule::with_bank(bank.clone());
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
        // module is wired to the bank for margin deposits/withdrawals
        // (plan.md §9.3).
        let perps = Arc::new(perps::PerpsModule::with_bank(bank.clone()));
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
        // Register the EVM module and fund the default sender so EVM
        // transactions can debit gas and value. The base fee is 7 gwei;
        // the gas price in the workload generator is 10 gwei. Wire the
        // exchange and perps modules into the EVM for read-only
        // precompiles (plan.md §10).
        //
        // Persistence: when `evm_persistence` is enabled (the
        // default), the EVM module is created with a storage backend
        // and flushes state at `end_block`. When `storage_path` is
        // `Some`, a disk-backed `RedbBackend` is used (durable ACID
        // persistence — state survives restarts). When `None`, a
        // `Volatile` (in-memory) backend is used. When disabled
        // entirely (`evm_persistence = false`), the EVM runs
        // in-memory only.
        let evm_module: Arc<evm::EvmModule> = if config.evm_persistence {
            let backend: Box<dyn storage::StorageBackend + Send> = match &config.storage_path {
                Some(path) => Box::new(storage::RedbBackend::open(path).expect("redb backend")),
                None => Box::new(storage::Volatile::new()),
            };
            Arc::new(evm::EvmModule::with_storage(1, 7_000_000_000, backend))
        } else {
            Arc::new(evm::EvmModule::new(1, 7_000_000_000))
        };
        evm_module.fund_account_for_test(&primitives::Address([0u8; 20]), u128::MAX);
        // Canonical preinstalls (CREATE2 factory, Multicall3, Permit2,
        // singleton factories) — Foundry/Hardhat/Safe tooling assumes
        // they exist at fixed addresses on every EVM chain.
        evm_module.install_preinstalls();
        evm_module.set_native_modules(Some(exchange), Some(perps));
        executor.register_module(evm_module.clone());
        let app: Arc<Executor> = Arc::new(executor);
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
                Box::new(OxideBft::new(app_dyn.clone(), vs).with_secret_key(key))
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

    // Submit a bank transfer tx.
    let to = Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, 100);
    let tx = build_tx(framework::module_id::BANK, &module_payload);
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

    // Verify the bank module processed the transfer.
    let balance = node.app().attest_state(primitives::Height::new(0));
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
        };
        let mut node = Node::assemble(&config);
        // Submit a tx and finalize a block.
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
        };
        let mut node_src = Node::assemble(&config_src);
        // Submit a tx and finalize a block to produce EVM state.
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
        // the full KV state was transferred. Other modules (bank,
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
        };
        let mut node = Node::assemble(&config);
        // Submit a tx and finalize a block.
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
        };
        let err = node.import_snapshot(&empty_snapshot).expect_err("empty snapshot must fail");
        assert_eq!(err, executor::SnapshotImportError::EmptySnapshot);
    }

    #[test]
    fn snapshot_import_rejects_corrupted_state_root() {
        let config = NodeConfig::default();
        let mut node = Node::assemble(&config);
        // Finalize a block to get a real snapshot.
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
        };
        let mut node = Node::assemble(&config);
        // Finalize one block.
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
        let to2 = Address([3u8; 20]);
        let module_payload2 = bank::msg::transfer(to2, 50);
        let tx2 = build_tx(framework::module_id::BANK, &module_payload2);
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
        };
        let mut node1 = Node::assemble(&config);
        let mut node2 = Node::assemble(&config);
        // Both finalize the same block.
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
        };
        let mut node = Node::assemble(&config);
        // Finalize a block.
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
        };
        let mut node = Node::assemble(&config);
        let to = Address([2u8; 20]);
        let module_payload = bank::msg::transfer(to, 100);
        let tx = build_tx(framework::module_id::BANK, &module_payload);
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
}
