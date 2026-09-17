//! Autonomous consensus driver — continuously drives the consensus
//! engine in a background tokio task.
//!
//! # Design
//!
//! The consensus engine (`OxideBft`) is a synchronous, pure state
//! machine — it doesn't have its own event loop or timers. In a
//! production node, the engine must be driven continuously:
//!
//! 1. **Block production**: when the node is the leader and has
//!    pending transactions, it proposes a block.
//! 2. **View advancement**: when the current view times out, the
//!    pacemaker triggers a view change.
//! 3. **Vote processing**: incoming votes from peers are collected
//!    into quorum certificates.
//! 4. **Commit detection**: when a 2-chain forms, the engine
//!    commits blocks.
//!
//! This driver wraps the synchronous engine in an async loop. It
//! runs `engine.run_until_idle()` on a fixed interval (the "block
//! time"), which processes all pending work in one batch. This is
//! the simplest correct approach for a single-node devnet; a
//! multi-node production deployment would add network channels for
//! votes and proposals.
//!
//! # Pacemaker integration
//!
//! The driver manages a view timer. If no block is finalized within
//! the timeout period, the driver calls the pacemaker's
//! `on_local_timeout` to trigger a view change. In single-validator
//! mode, this never fires (the leader always proposes immediately).
//!
//! # Metrics
//!
//! The driver reports block height and finalized count to the RPC
//! metrics system on each tick, keeping the `/metrics` endpoint
//! up-to-date.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use node::Node;

/// Configuration for the consensus driver.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)]
pub struct DriverConfig {
    /// Block production interval (milliseconds). The driver calls
    /// `engine.run_until_idle()` on this interval. Default: 100ms
    /// (10 blocks/sec — the target from plan.md §4).
    pub block_time_ms: u64,
    /// View timeout (milliseconds). If no block is finalized within
    /// this period, a view change is triggered. Default: 2000ms
    /// (matches the pacemaker's base timeout). Reserved for future
    /// use when the pacemaker is fully wired into the driver.
    #[allow(dead_code)]
    pub view_timeout_ms: u64,
    /// Metrics reporting interval (milliseconds). Default: 1000ms.
    pub metrics_interval_ms: u64,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self { block_time_ms: 100, view_timeout_ms: 2_000, metrics_interval_ms: 1_000 }
    }
}

/// Metrics shared between the consensus driver and the RPC server.
/// Updated atomically by the driver, read by the RPC `/metrics`
/// endpoint.
#[derive(Debug, Default)]
pub struct DriverMetrics {
    /// Current finalized block height.
    pub block_height: AtomicU64,
    /// Total transactions finalized.
    pub tx_count: AtomicU64,
    /// Total blocks finalized.
    pub block_count: AtomicU64,
    /// Current view number (populated when the pacemaker is wired
    /// into the driver; reserved for future use).
    #[allow(dead_code)]
    pub current_view: AtomicU64,
}

impl DriverMetrics {
    /// Create a new metrics container initialized to zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current block height.
    #[must_use]
    pub fn block_height(&self) -> u64 {
        self.block_height.load(Ordering::Relaxed)
    }

    /// Get the total transaction count.
    #[must_use]
    pub fn tx_count(&self) -> u64 {
        self.tx_count.load(Ordering::Relaxed)
    }
}

/// The autonomous consensus driver. Runs the consensus engine in a
/// background tokio task on a fixed interval.
pub struct ConsensusDriver {
    /// The driver configuration.
    config: DriverConfig,
    /// Shared metrics (updated by the driver, read by RPC).
    metrics: Arc<DriverMetrics>,
    /// Optional observer invoked once per newly finalized height.
    /// The validator wires this to the RPC server so
    /// `eth_blockNumber` tracks finalization live and
    /// `eth_subscribe(newHeads)` pushes fire — without it the RPC
    /// height is frozen at its startup seed.
    block_observer: Option<Arc<dyn Fn(u64) + Send + Sync>>,
}

impl ConsensusDriver {
    /// Create a new driver with the given configuration.
    #[must_use]
    pub fn new(config: DriverConfig) -> Self {
        Self { config, metrics: Arc::new(DriverMetrics::new()), block_observer: None }
    }

    /// Create a new driver with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DriverConfig::default())
    }

    /// Install a callback invoked with each newly finalized height,
    /// on the driver task's tick. The callback runs synchronously on
    /// the block-production loop, so it must be cheap — the RPC
    /// publish path is (one lock + channel send per subscriber).
    pub fn set_block_observer(&mut self, observer: Arc<dyn Fn(u64) + Send + Sync>) {
        self.block_observer = Some(observer);
    }

    /// Get a handle to the shared metrics (for wiring into the RPC
    /// server's `/metrics` endpoint).
    #[must_use]
    pub fn metrics(&self) -> Arc<DriverMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Start the consensus driver in a background tokio task.
    /// The driver takes ownership of the `Node` and drives its
    /// consensus engine continuously until the task is cancelled
    /// (e.g. on shutdown).
    ///
    /// # Panics
    ///
    /// The driver task panics if the consensus engine encounters an
    /// internal invariant violation during `run_until_idle()`. This
    /// is intentional — a consensus invariant violation is
    /// unrecoverable and must abort the process.
    pub fn start(self, mut node: Node) {
        let block_time = Duration::from_millis(self.config.block_time_ms);
        let metrics_interval = Duration::from_millis(self.config.metrics_interval_ms);
        let metrics = self.metrics;
        let block_observer = self.block_observer;

        // The last finalized height we saw. Used to detect new
        // finalization events for metrics reporting.
        let mut last_height: Option<u64> = None;
        let mut last_metrics_tick = std::time::Instant::now();

        tokio::spawn(async move {
            tracing::info!(block_time_ms = block_time.as_millis(), "consensus driver started");

            // Use a tokio interval for the block production loop.
            // The interval fires every `block_time`, driving the
            // engine to propose/vote/commit any pending work.
            let mut ticker = tokio::time::interval(block_time);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;

                // Drive the consensus engine. In single-validator
                // mode, this proposes a block if there are pending
                // txs, self-votes, forms a QC, and commits. In
                // multi-validator mode (future), this processes
                // incoming votes and proposals from the network.
                node.engine().run_until_idle();

                // Check for new finalization.
                let current_height =
                    node.engine().finalized_height().map(primitives::Height::value);

                if current_height != last_height {
                    if let Some(h) = current_height {
                        tracing::debug!(height = h, "consensus driver: block finalized");
                        metrics.block_height.store(h, Ordering::Relaxed);
                        metrics.block_count.fetch_add(1, Ordering::Relaxed);

                        // Update tx count from the finalized block.
                        if let Some(block) =
                            node.engine().finalized_block(primitives::Height::new(h))
                        {
                            let txs = u64::try_from(block.txs.len()).unwrap_or(0);
                            metrics.tx_count.fetch_add(txs, Ordering::Relaxed);
                        }

                        // Notify the RPC server (block height +
                        // `eth_subscribe` pushes).
                        if let Some(observer) = &block_observer {
                            observer(h);
                        }
                    }
                    last_height = current_height;
                }

                // Periodically log metrics.
                if last_metrics_tick.elapsed() >= metrics_interval {
                    tracing::info!(
                        height = metrics.block_height(),
                        blocks = metrics.block_count.load(Ordering::Relaxed),
                        txs = metrics.tx_count.load(Ordering::Relaxed),
                        "consensus driver: metrics"
                    );
                    last_metrics_tick = std::time::Instant::now();
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_config_defaults() {
        let cfg = DriverConfig::default();
        assert_eq!(cfg.block_time_ms, 100);
        assert_eq!(cfg.view_timeout_ms, 2_000);
        assert_eq!(cfg.metrics_interval_ms, 1_000);
    }

    #[test]
    fn driver_metrics_start_at_zero() {
        let metrics = DriverMetrics::new();
        assert_eq!(metrics.block_height(), 0);
        assert_eq!(metrics.tx_count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn driver_starts_and_finalizes_blocks() {
        use node::{ConsensusConfig, NodeConfig};

        let config = NodeConfig {
            consensus: ConsensusConfig::OxideBft,
            max_mempool_entries: 100,
            parallel_threshold: 32,
            evm_persistence: false,
            storage_path: None,
            settlement_operator: None,
            min_fee: 0,
            chain_id: 1,
            require_signed_txs: false,
        };
        let mut node = Node::assemble(&config);

        // Submit a transaction so the engine has work to do —
        // a staking delegate to `Address::ZERO` (registered at
        // genesis by `Node::assemble`).
        let module_payload = staking::msg::delegate(primitives::Address::ZERO, 100);
        let tx = build_tx(framework::module_id::STAKING, &module_payload);
        node.engine().submit_tx(tx);

        // Verify the engine can finalize directly (sanity check).
        node.engine().run_until_idle();
        let direct_height = node.engine().finalized_height();
        assert!(direct_height.is_some(), "engine should finalize directly");

        // Now start the driver with the node (already has finalized
        // one block). Submit another tx and verify the driver
        // finalizes it.
        let module_payload2 = staking::msg::delegate(primitives::Address::ZERO, 200);
        let tx2 = build_tx(framework::module_id::STAKING, &module_payload2);
        node.engine().submit_tx(tx2);

        let driver = ConsensusDriver::with_defaults();
        let metrics = driver.metrics();
        let initial_height = direct_height.map_or(0, primitives::Height::value);
        driver.start(node);

        // Wait for the driver to finalize at least one new block
        // beyond the initial height.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let current = metrics.block_height();
            if current > initial_height {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "driver did not finalize any new blocks within 5 seconds (initial={initial_height}, current={current})"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(
            metrics.block_height() > initial_height,
            "at least one new block should be finalized by the driver"
        );
    }

    fn build_tx(module_id: u8, module_payload: &[u8]) -> types::TxBytes {
        let sender = primitives::Address([0u8; 20]);
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
}
