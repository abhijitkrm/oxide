//! Oxide JSON-RPC server — Ethereum-compatible RPC endpoints for
//! MetaMask/Foundry/Blockscout integration (plan.md §13, Phase 2).
//!
//! ## What this module is
//!
//! A JSON-RPC 2.0 server that exposes Ethereum-compatible endpoints
//! for wallet integration (`MetaMask`), development tooling (`Foundry`),
//! and block explorers (Blockscout). The server translates RPC calls
//! into operations on the Oxide EVM module and chain state.
//!
//! ## Why a custom server, not a reth/reth-RPC fork
//!
//! Oxide's architecture (plan.md §2) treats the RPC as a cold-path
//! adapter on top of the EVM module. A custom server keeps the
//! dependency footprint minimal and the API surface under our
//! control. The JSON-RPC 2.0 protocol is simple enough that a
//! focused implementation is cleaner than importing a full-featured
//! but heavy RPC framework.
//!
//! ## Supported endpoints (Phase 2 v0)
//!
//! - `eth_chainId` — returns the chain ID (EIP-155).
//! - `eth_blockNumber` — returns the current block height.
//! - `eth_getBalance` — returns an account's balance.
//! - `eth_getTransactionCount` — returns an account's nonce.
//! - `eth_gasPrice` — returns the current gas price (base fee).
//! - `eth_sendRawTransaction` — submits a raw EVM transaction.
//! - `net_version` — returns the network ID.
//! - `web3_clientVersion` — returns the client version.
//! - `eth_subscribe` — creates a WebSocket subscription.
//! - `eth_unsubscribe` — cancels a WebSocket subscription.
//!
//! ## Subscription types (Phase 2)
//!
//! - `newHeads` — notifies on each new finalized block.
//! - `logs` — notifies on matching logs (optional address/topics filter).
//!
//! Future phases add: `eth_call`, `eth_getBlockByNumber`,
//! `eth_getTransactionReceipt`, `eth_getLogs`, and full
//! Foundry/MetaMask compatibility.

pub mod server;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::{B256, U256};
use evm::history::{ExecutedBlock, LogFilter, StoredTx, TopicMatcher};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use types::TxBytes;

/// A handle that the RPC server uses to submit wrapped Oxide transaction
/// envelopes into the application's mempool.
///
/// The RPC layer is deliberately decoupled from the executor crate: it
/// only needs the ability to push a wrapped `TxBytes` into the mempool
/// and learn whether the submission was accepted. Real nodes implement
/// this trait for their `executor::Executor` (which already implements
/// `ports::AppInterface::ingest_tx`); tests implement it with a mock
/// that records submissions.
///
/// The trait is `Send + Sync` so an `Arc<dyn TxSubmitter>` can be shared
/// across the HTTP handler's async tasks.
pub trait TxSubmitter: Send + Sync {
    /// Submit a wrapped Oxide transaction envelope to the mempool.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` with a human-readable rejection reason if
    /// the mempool or validation layer rejected the transaction (bad
    /// signature, wrong nonce, insufficient balance, duplicate,
    /// pool full, etc.).
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String>;
}

/// Trait for providing a state snapshot via the `/snapshot` endpoint.
///
/// Implemented by the node's executor handle. The snapshot is returned
/// as codec-encoded bytes, hex-encoded for the HTTP response.
///
/// The trait is `Send + Sync` so an `Arc<dyn SnapshotProvider>` can be
/// shared across the HTTP handler's async tasks.
pub trait SnapshotProvider: Send + Sync {
    /// Export the current state snapshot, codec-encoded.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` if the snapshot cannot be produced (e.g.
    /// the node is not yet initialized, or state is being written).
    fn export_snapshot(&self) -> Result<Vec<u8>, String>;
}

/// A validator-set entry for the `GET /validator-set` endpoint.
///
/// Serializes the current validator set as JSON so a new validator
/// joining mid-epoch can discover the current set + peer addresses
/// without a genesis file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetEntry {
    /// The validator's staking address (hex, 20 bytes).
    pub address: String,
    /// The validator's BLS12-381 public key (hex, 48 bytes).
    pub public_key: String,
    /// The validator's stake in atomic units.
    pub stake: u64,
}

/// Trait for providing the current validator set via the
/// `GET /validator-set` endpoint.
///
/// Implemented by the node's validator-set handle — the consensus
/// engine writes the updated set after each epoch rotation; the RPC
/// handler reads it.
///
/// The trait is `Send + Sync` so an `Arc<dyn ValidatorSetProvider>`
/// can be shared across the HTTP handler's async tasks.
pub trait ValidatorSetProvider: Send + Sync {
    /// The current validator set entries.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` if the validator set cannot be read
    /// (e.g. the engine is not yet initialized).
    fn validator_set(&self) -> Result<Vec<ValidatorSetEntry>, String>;
}

/// The JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcRequest {
    /// The method name (e.g. `eth_chainId`).
    pub method: String,
    /// The method parameters (positional or named).
    #[serde(default)]
    pub params: Vec<Value>,
    /// The request ID (number or string).
    pub id: Value,
    /// The JSON-RPC version (always `2.0`).
    #[serde(default = "default_version")]
    pub jsonrpc: String,
}

/// The JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    /// The request ID this response corresponds to.
    pub id: Value,
    /// The JSON-RPC version (always `2.0`).
    pub jsonrpc: String,
    /// The result (on success) or null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The error (on failure) or null.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    /// The error code (negative for protocol errors, non-negative
    /// for application errors).
    pub code: i32,
    /// A human-readable error message.
    pub message: String,
    /// Optional additional data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    /// Parse error: invalid JSON.
    #[must_use]
    pub fn parse_error() -> Self {
        Self { code: -32700, message: "Parse error".to_string(), data: None }
    }

    /// Method not found.
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self { code: -32601, message: format!("Method not found: {method}"), data: None }
    }

    /// Invalid params.
    #[must_use]
    pub fn invalid_params(msg: &str) -> Self {
        Self { code: -32602, message: format!("Invalid params: {msg}"), data: None }
    }

    /// Internal error.
    #[must_use]
    pub fn internal_error(msg: &str) -> Self {
        Self { code: -32603, message: format!("Internal error: {msg}"), data: None }
    }

    /// Transaction rejected by the mempool or validation layer.
    ///
    /// Uses the JSON-RPC application error code `-32000` (the
    /// conventional "server error" range used by Ethereum clients for
    /// transaction submission failures such as bad nonce, insufficient
    /// balance, or pool-full rejections).
    #[must_use]
    pub fn transaction_rejected(reason: &str) -> Self {
        Self { code: -32_000, message: format!("transaction rejected: {reason}"), data: None }
    }
}

fn default_version() -> String {
    "2.0".to_string()
}

// ---- WebSocket subscriptions ----

/// A subscription type (EIP-1193 / Ethereum `eth_subscribe`).
///
/// Determines what events a subscriber receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionType {
    /// Notify on each new finalized block header.
    NewHeads,
    /// Notify on matching logs (optional address + topics filter).
    Logs,
}

impl SubscriptionType {
    /// Parse a subscription type from a JSON-RPC params string.
    ///
    /// Returns `None` for unknown subscription types.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "newHeads" => Some(Self::NewHeads),
            "logs" => Some(Self::Logs),
            _ => None,
        }
    }
}

/// A subscription notification message (sent to subscribers).
///
/// This is the JSON-RPC notification envelope for `eth_subscription`:
/// `{ "jsonrpc": "2.0", "method": "eth_subscription", "params": {
///   "subscription": "0x...", "result": ... } }`.
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionNotification {
    /// The JSON-RPC version.
    pub jsonrpc: String,
    /// The method name (always `eth_subscription`).
    pub method: String,
    /// The subscription ID and result.
    pub params: SubscriptionParams,
}

/// The `params` field of a subscription notification.
#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionParams {
    /// The subscription ID.
    pub subscription: String,
    /// The event payload (block header, log, etc.).
    pub result: Value,
}

/// An active subscription bound to one WebSocket connection.
///
/// The `sink` is the connection's outbound channel: notification
/// JSON is serialized once and pushed per-subscription. When the
/// socket closes the server calls
/// [`SubscriptionManager::drop_connection`], which removes every
/// subscription tagged with the connection's `conn_id`.
#[derive(Debug)]
struct ActiveSubscription {
    /// Owning WebSocket connection ID.
    conn_id: u64,
    /// What the subscriber asked for.
    kind: SubscriptionType,
    /// `logs` subscriptions carry an optional address/topics filter
    /// (parsed at `eth_subscribe` time with the same semantics as
    /// `eth_getLogs`). `None` = match every log.
    filter: Option<LogFilter>,
    /// Outbound channel to the connection's writer loop.
    sink: tokio::sync::mpsc::UnboundedSender<String>,
}

/// The subscription manager: tracks active subscriptions across
/// WebSocket connections and fans out notifications when a block
/// finalizes.
///
/// Each subscription gets a monotonically increasing hex ID scoped
/// to this server instance (geth uses the same scheme). The manager
/// is `Send + Sync` so it can be shared across WebSocket
/// connections via `Arc`.
///
/// Concurrency: a `Mutex<HashMap>` guards the subscription table.
/// This is a cold path — registrations happen per `eth_subscribe`
/// call and publishes happen once per finalized block — so a
/// lock-free structure buys nothing.
pub struct SubscriptionManager {
    /// The next subscription ID to assign.
    next_id: AtomicU64,
    /// The next WebSocket connection ID to assign. Connection IDs
    /// scope subscriptions so a dropped socket cleans up all of its
    /// subscriptions in one pass.
    next_conn_id: AtomicU64,
    /// `subscription_id -> active subscription`.
    active: std::sync::Mutex<HashMap<String, ActiveSubscription>>,
}

impl SubscriptionManager {
    /// Create a fresh subscription manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            next_conn_id: AtomicU64::new(1),
            active: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Allocate a connection ID for a freshly upgraded WebSocket.
    fn next_connection_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a subscription for a connection. Returns the
    /// subscription ID.
    fn register(
        &self,
        kind: SubscriptionType,
        filter: Option<LogFilter>,
        conn_id: u64,
        sink: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> String {
        let id = format!("0x{:x}", self.next_id.fetch_add(1, Ordering::Relaxed));
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.clone(), ActiveSubscription { conn_id, kind, filter, sink });
        id
    }

    /// Cancel a subscription by ID. Returns `true` if it existed
    /// (geth returns `false` — not an error — for unknown IDs).
    fn unregister(&self, id: &str) -> bool {
        self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(id).is_some()
    }

    /// Remove every subscription owned by a closed connection.
    fn drop_connection(&self, conn_id: u64) {
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|_, sub| sub.conn_id != conn_id);
    }

    /// Cheap gate so the per-block publish path exits without
    /// touching the EVM history lock when nobody is subscribed.
    fn has_subscriptions(&self) -> bool {
        !self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty()
    }

    /// Fan out a finalized block to all subscribers: the header to
    /// `newHeads` subs, each matching log to `logs` subs.
    ///
    /// A dead sink (connection closed but not yet reaped) simply
    /// fails the `send` — the subscription is removed so we don't
    /// retry it on the next block.
    fn publish(&self, header: &Value, logs: &[evm::history::LogMatch]) {
        let mut dead = Vec::new();
        {
            let active = self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for (id, sub) in active.iter() {
                let send = |result: Value| {
                    sub.sink.send(
                        serde_json::to_string(&SubscriptionNotification {
                            jsonrpc: "2.0".to_string(),
                            method: "eth_subscription".to_string(),
                            params: SubscriptionParams { subscription: id.clone(), result },
                        })
                        .unwrap_or_else(|_| "{}".to_string()),
                    )
                };
                match sub.kind {
                    SubscriptionType::NewHeads => {
                        if send(header.clone()).is_err() {
                            dead.push(id.clone());
                        }
                    }
                    SubscriptionType::Logs => {
                        for log in logs {
                            let matches = sub.filter.as_ref().is_none_or(|f| f.matches(log));
                            if matches && send(log_json(log)).is_err() {
                                dead.push(id.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }
        if !dead.is_empty() {
            let mut active = self.active.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for id in dead {
                active.remove(&id);
            }
        }
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// A live WebSocket connection, passed down the dispatch for the
/// duration of one request so `eth_subscribe` can bind the new
/// subscription to the caller's outbound channel.
///
/// `sink` is unbounded: the writer loop drains it continuously, and
/// notification volume is bounded by subscription count × block
/// rate — both small relative to memory. Requests responses go
/// through the same channel.
pub(crate) struct WsConn {
    /// The connection's unique ID (scopes its subscriptions).
    pub(crate) conn_id: u64,
    /// Outbound channel to the socket writer loop.
    pub(crate) sink: tokio::sync::mpsc::UnboundedSender<String>,
}

impl WsConn {
    /// Create a connection handle for `conn_id` writing to `sink`.
    pub(crate) fn new(conn_id: u64, sink: tokio::sync::mpsc::UnboundedSender<String>) -> Self {
        Self { conn_id, sink }
    }
}

/// The RPC server state. Holds references to the EVM module and
/// chain state needed to answer queries.
pub struct RpcServer {
    /// The chain ID (EIP-155).
    chain_id: u64,
    /// The current block height (atomic so it can be updated through
    /// `Arc<RpcServer>` after the server starts, e.g. by the executor
    /// after each finalized block).
    block_height: AtomicU64,
    /// The current base fee (wei per gas).
    base_fee: u64,
    /// The client version string.
    client_version: String,
    /// The subscription manager for WebSocket subscriptions.
    subscriptions: SubscriptionManager,
    /// Optional mempool submitter. When set, `eth_sendRawTransaction`
    /// decodes the raw EVM transaction, recovers the sender, wraps it in
    /// the Oxide envelope, and pushes it into the mempool via this
    /// handle. When `None`, the RPC returns a computed hash but does not
    /// submit (the Phase 2 v0 behaviour, kept for stateless tests).
    tx_submitter: Option<Arc<dyn TxSubmitter>>,
    /// Optional latency recorder for RPC handler metrics. When set,
    /// `eth_sendRawTransaction` records its duration under the
    /// `"rpc_send_raw_tx"` operation. Exposed via `prometheus()`.
    recorder: Option<Arc<metrics::Recorder>>,
    /// Total transactions processed (atomic counter, exposed via
    /// `/metrics` as `oxide_tx_count`).
    tx_count: AtomicU64,
    /// Current mempool size (atomic gauge, exposed via `/metrics` as
    /// `oxide_mempool_size`). Updated by the executor or node assembly
    /// as transactions enter/leave the mempool.
    mempool_size: AtomicU64,
    /// Rate limiter: maximum requests per second per client. 0 =
    /// unlimited. Enforced in `handle_request` before dispatch.
    max_requests_per_second: u64,
    /// Rate limiter state: timestamp (ms) of the start of the current
    /// 1-second window.
    rate_window_start_ms: AtomicU64,
    /// Rate limiter state: request count within the current window.
    rate_window_count: AtomicU64,
    /// Optional snapshot provider for the `GET /snapshot` endpoint.
    /// When set, the endpoint returns the codec-encoded snapshot as
    /// hex. When `None`, the endpoint returns 404.
    snapshot_provider: Option<Arc<dyn SnapshotProvider>>,
    /// Optional validator-set provider for the `GET /validator-set`
    /// endpoint. When set, the endpoint returns the current validator
    /// set as JSON (addresses, public keys, stakes). When `None`,
    /// the endpoint returns 404.
    validator_set_provider: Option<Arc<dyn ValidatorSetProvider>>,
    /// Optional EVM module handle — the same `Arc` the executor
    /// executes against. When set, the read paths (`eth_call`,
    /// `eth_estimateGas`, account queries) serve real state and the
    /// lookup paths (`eth_getTransactionReceipt`, `eth_getBlock*`,
    /// `eth_getLogs`) serve the module's sealed-block history.
    /// When `None`, those endpoints return the stateless-test
    /// placeholders documented per-handler.
    ///
    /// Concurrency: all module methods take `&self` (interior
    /// `Mutex`es serialize against block execution), so sharing the
    /// `Arc` with the HTTP handler tasks is safe.
    evm: Option<Arc<evm::EvmModule>>,
}

impl RpcServer {
    /// Create a new RPC server with the given chain parameters.
    #[must_use]
    pub fn new(chain_id: u64, base_fee: u64) -> Self {
        Self {
            chain_id,
            block_height: AtomicU64::new(0),
            base_fee,
            client_version: format!("oxide/{}", env!("CARGO_PKG_VERSION")),
            subscriptions: SubscriptionManager::new(),
            tx_submitter: None,
            recorder: None,
            tx_count: AtomicU64::new(0),
            mempool_size: AtomicU64::new(0),
            max_requests_per_second: 0, // unlimited by default
            rate_window_start_ms: AtomicU64::new(0),
            rate_window_count: AtomicU64::new(0),
            snapshot_provider: None,
            validator_set_provider: None,
            evm: None,
        }
    }

    /// Attach a mempool submitter so `eth_sendRawTransaction` pushes
    /// decoded transactions into the application's mempool.
    ///
    /// Without this call, `eth_sendRawTransaction` computes and returns
    /// the transaction hash but does not submit the transaction — the
    /// Phase 2 v0 behaviour, retained for stateless unit tests.
    pub fn set_tx_submitter(&mut self, submitter: Arc<dyn TxSubmitter>) {
        self.tx_submitter = Some(submitter);
    }

    /// Attach a snapshot provider so `GET /snapshot` returns the
    /// current executor state as codec-encoded bytes (hex-encoded in
    /// the HTTP response).
    ///
    /// Without this call, `/snapshot` returns 404 — the endpoint is
    /// disabled for stateless test configurations.
    pub fn set_snapshot_provider(&mut self, provider: Arc<dyn SnapshotProvider>) {
        self.snapshot_provider = Some(provider);
    }

    /// Get the snapshot provider, if attached.
    #[must_use]
    pub fn snapshot_provider(&self) -> Option<&Arc<dyn SnapshotProvider>> {
        self.snapshot_provider.as_ref()
    }

    /// Attach a validator-set provider so `GET /validator-set`
    /// returns the current validator set as JSON.
    ///
    /// Without this call, `/validator-set` returns 404 — the endpoint
    /// is disabled for stateless test configurations.
    pub fn set_validator_set_provider(&mut self, provider: Arc<dyn ValidatorSetProvider>) {
        self.validator_set_provider = Some(provider);
    }

    /// Get the validator-set provider, if attached.
    #[must_use]
    pub fn validator_set_provider(&self) -> Option<&Arc<dyn ValidatorSetProvider>> {
        self.validator_set_provider.as_ref()
    }

    /// Attach the EVM module the executor runs, so the `eth_*` read
    /// and lookup endpoints serve real state and sealed-block history.
    ///
    /// The `Arc` must be the same instance registered with the
    /// executor — reads then observe exactly what blocks commit.
    /// Without this call the account/history endpoints return the
    /// stateless-test placeholders (`0x0`, `null`, `[]`).
    pub fn set_evm(&mut self, module: Arc<evm::EvmModule>) {
        self.evm = Some(module);
    }

    /// Attach a latency recorder for RPC handler metrics.
    ///
    /// When set, `eth_sendRawTransaction` records its duration, and
    /// `prometheus()` returns the recorded metrics in Prometheus text
    /// format for a `/metrics` endpoint.
    pub fn set_recorder(&mut self, recorder: Arc<metrics::Recorder>) {
        self.recorder = Some(recorder);
    }

    /// Generate a Prometheus text exposition of all recorded metrics.
    ///
    /// Returns an empty string if no recorder is attached.
    #[must_use]
    pub fn prometheus(&self) -> String {
        self.recorder.as_ref().map_or(String::new(), |r| r.prometheus())
    }

    /// Update the block height (called by the executor after each
    /// finalized block).
    ///
    /// Takes `&self` so it can be called through `Arc<RpcServer>` after
    /// the HTTP server has started (the value is stored in an
    /// `AtomicU64`).
    pub fn set_block_height(&self, height: u64) {
        self.block_height.store(height, Ordering::Relaxed);
    }

    /// Get the current block height (atomic load).
    #[must_use]
    pub fn block_height(&self) -> u64 {
        self.block_height.load(Ordering::Relaxed)
    }

    /// Increment the total transaction counter by one (called after a
    /// transaction is accepted into the mempool or included in a block).
    pub fn increment_tx_count(&self) {
        self.tx_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of transactions processed (atomic load).
    #[must_use]
    pub fn tx_count(&self) -> u64 {
        self.tx_count.load(Ordering::Relaxed)
    }

    /// Set the current mempool size (called by the executor or node
    /// assembly as transactions enter/leave the mempool).
    pub fn set_mempool_size(&self, size: u64) {
        self.mempool_size.store(size, Ordering::Relaxed);
    }

    /// Set the maximum requests per second per client. 0 = unlimited.
    ///
    /// This is a simple global rate limiter that caps total RPC
    /// requests per second. In a production deployment behind a load
    /// balancer, per-IP rate limiting would be handled by the LB;
    /// this is a defense-in-depth measure for direct exposure.
    pub fn set_rate_limit(&mut self, max_per_second: u64) {
        self.max_requests_per_second = max_per_second;
    }

    /// Check if the current request is within the rate limit. Returns
    /// `true` if the request is allowed, `false` if rate-limited.
    ///
    /// Uses a simple fixed-window counter: requests are counted within
    /// a 1-second window. When the window rolls over, the counter
    /// resets. This is less precise than a sliding window but
    /// sufficient for RPC rate limiting (the consensus hot path is
    /// not affected).
    fn check_rate_limit(&self) -> bool {
        if self.max_requests_per_second == 0 {
            return true; // unlimited
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u64, |d| u64::try_from(d.as_millis()).unwrap_or(0));
        let window_start = self.rate_window_start_ms.load(Ordering::Relaxed);
        // If the window has expired (more than 1 second old), reset.
        if window_start == 0 || now.saturating_sub(window_start) >= 1_000 {
            // Try to reset the window. Use compare_exchange to avoid
            // a race where two threads both try to reset.
            let _ = self.rate_window_start_ms.compare_exchange(
                window_start,
                now,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            self.rate_window_count.store(1, Ordering::Relaxed);
            return true;
        }
        // Within the current window — increment and check.
        let count = self.rate_window_count.fetch_add(1, Ordering::Relaxed);
        count < self.max_requests_per_second
    }

    /// Get the current mempool size (atomic load).
    #[must_use]
    pub fn mempool_size(&self) -> u64 {
        self.mempool_size.load(Ordering::Relaxed)
    }

    /// Generate a Prometheus text exposition of all node metrics.
    ///
    /// Exposes the basic node gauges/counters:
    /// - `oxide_block_height` — current block height (gauge)
    /// - `oxide_tx_count` — total transactions processed (counter)
    /// - `oxide_mempool_size` — current mempool size (gauge)
    ///
    /// If a latency recorder is attached, its HDR histogram metrics
    /// (latency percentiles per operation) are appended.
    #[must_use]
    pub fn metrics_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "# HELP oxide_block_height Current block height");
        let _ = writeln!(out, "# TYPE oxide_block_height gauge");
        let _ = writeln!(out, "oxide_block_height {}", self.block_height());
        let _ = writeln!(out, "# HELP oxide_tx_count Total transactions processed");
        let _ = writeln!(out, "# TYPE oxide_tx_count counter");
        let _ = writeln!(out, "oxide_tx_count {}", self.tx_count());
        let _ = writeln!(out, "# HELP oxide_mempool_size Current mempool size");
        let _ = writeln!(out, "# TYPE oxide_mempool_size gauge");
        let _ = writeln!(out, "oxide_mempool_size {}", self.mempool_size());
        // Append latency histogram metrics if a recorder is attached.
        let latency = self.prometheus();
        if !latency.is_empty() {
            out.push_str(&latency);
        }
        out
    }

    /// Handle a single JSON-RPC request and produce a response.
    ///
    /// This is the core dispatch function. It parses the method
    /// name, validates the params, and returns the result or error.
    ///
    /// # Errors
    ///
    /// Returns `RpcError` in the response for unknown methods,
    /// invalid params, or internal errors.
    pub fn handle(&self, request: &RpcRequest) -> RpcResponse {
        self.handle_ctx(request, None)
    }

    /// Handle a single JSON-RPC request over a WebSocket
    /// connection. `eth_subscribe` binds the subscription to
    /// `conn`'s outbound channel; every other method behaves
    /// identically to the HTTP path.
    pub(crate) fn handle_ws(&self, request: &RpcRequest, conn: &WsConn) -> RpcResponse {
        self.handle_ctx(request, Some(conn))
    }

    /// Dispatch one request. `conn` is `Some` only for WebSocket
    /// transport — `eth_subscribe` rejects notifications over HTTP
    /// (geth parity: `"notifications not supported"`).
    fn handle_ctx(&self, request: &RpcRequest, conn: Option<&WsConn>) -> RpcResponse {
        // Rate limit check: reject requests exceeding the configured
        // rate. Returns a -32005 "requests rate limited" error (the
        // convention used by Ethereum JSON-RPC servers).
        if !self.check_rate_limit() {
            return RpcResponse {
                id: request.id.clone(),
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(RpcError {
                    code: -32_005,
                    message: "request rate limited".to_string(),
                    data: None,
                }),
            };
        }
        let result: Result<Value, RpcError> = match request.method.as_str() {
            // ---- Chain info ----
            "eth_chainId" => Ok(self.eth_chain_id()),
            "eth_blockNumber" => Ok(self.eth_block_number()),
            "eth_gasPrice" => Ok(self.eth_gas_price()),
            "net_version" => Ok(self.net_version()),
            "net_listening" => Ok(self.net_listening()),
            "net_peerCount" => Ok(self.net_peer_count()),
            "web3_clientVersion" => Ok(self.web3_client_version()),
            "web3_sha3" => self.web3_sha3(&request.params),
            // ---- Account queries ----
            "eth_getBalance" => self.eth_get_balance(&request.params),
            "eth_getTransactionCount" => self.eth_get_transaction_count(&request.params),
            "eth_getCode" => self.eth_get_code(&request.params),
            "eth_getStorageAt" => self.eth_get_storage_at(&request.params),
            // ---- Block queries ----
            "eth_getBlockByNumber" => self.eth_get_block_by_number(&request.params),
            "eth_getBlockByHash" => self.eth_get_block_by_hash(&request.params),
            "eth_getBlockTransactionCountByNumber" => {
                self.eth_get_block_tx_count_by_number(&request.params)
            }
            "eth_getBlockTransactionCountByHash" => {
                self.eth_get_block_tx_count_by_hash(&request.params)
            }
            // ---- Transaction queries ----
            "eth_getTransactionByHash" => self.eth_get_transaction_by_hash(&request.params),
            "eth_getTransactionByBlockNumberAndIndex" => {
                self.eth_get_transaction_by_block_and_index(&request.params)
            }
            "eth_getTransactionByBlockHashAndIndex" => {
                self.eth_get_transaction_by_block_hash_and_index(&request.params)
            }
            "eth_getTransactionReceipt" => self.eth_get_transaction_receipt(&request.params),
            "eth_sendRawTransaction" => self.eth_send_raw_transaction(&request.params),
            // ---- Call / estimate ----
            "eth_call" => self.eth_call(&request.params),
            "eth_estimateGas" => self.eth_estimate_gas(&request.params),
            "eth_maxPriorityFeePerGas" => Ok(self.eth_max_priority_fee_per_gas()),
            "eth_getBlockReceipts" => self.eth_get_block_receipts(&request.params),
            // ---- Logs ----
            "eth_getLogs" => self.eth_get_logs(&request.params),
            // ---- Gas / fee ----
            "eth_feeHistory" => self.eth_fee_history(&request.params),
            // ---- Protocol ----
            "eth_mining" => Ok(self.eth_mining()),
            "eth_syncing" => Ok(self.eth_syncing()),
            "eth_protocolVersion" => Ok(self.eth_protocol_version()),
            "eth_accounts" => Ok(self.eth_accounts()),
            "eth_coinbase" => Ok(self.eth_coinbase()),
            "eth_hashrate" => Ok(self.eth_hashrate()),
            // ---- Subscriptions ----
            "eth_subscribe" => self.eth_subscribe(&request.params, conn),
            "eth_unsubscribe" => self.eth_unsubscribe(&request.params),
            _ => Err(RpcError::method_not_found(&request.method)),
        };

        match result {
            Ok(value) => RpcResponse {
                id: request.id.clone(),
                jsonrpc: "2.0".to_string(),
                result: Some(value),
                error: None,
            },
            Err(err) => RpcResponse {
                id: request.id.clone(),
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(err),
            },
        }
    }

    /// Handle a raw JSON string. Parses, dispatches, and serializes
    /// the response.
    ///
    /// # Errors
    ///
    /// Returns a parse error response if the JSON is invalid.
    pub fn handle_raw(&self, raw: &str) -> String {
        let Ok(request): Result<RpcRequest, _> = serde_json::from_str(raw) else {
            let response = RpcResponse {
                id: Value::Null,
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(RpcError::parse_error()),
            };
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        };
        let response = self.handle(&request);
        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
    }

    /// Handle a raw JSON-RPC string arriving on a WebSocket
    /// connection. Identical to [`handle_raw`](Self::handle_raw)
    /// except `eth_subscribe` registers against `conn`'s sink.
    pub(crate) fn handle_ws_raw(&self, raw: &str, conn: &WsConn) -> String {
        let Ok(request): Result<RpcRequest, _> = serde_json::from_str(raw) else {
            let response = RpcResponse {
                id: Value::Null,
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(RpcError::parse_error()),
            };
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        };
        let response = self.handle_ws(&request, conn);
        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
    }

    /// Allocate a connection ID for a newly upgraded WebSocket.
    /// Called by the transport layer (`server.rs`).
    pub(crate) fn next_connection_id(&self) -> u64 {
        self.subscriptions.next_connection_id()
    }

    /// Drop every subscription owned by a closed WebSocket
    /// connection. Called by the transport layer when the socket
    /// read loop ends.
    pub(crate) fn drop_connection(&self, conn_id: u64) {
        self.subscriptions.drop_connection(conn_id);
    }

    /// Fan a newly finalized block out to subscribers: the header
    /// to `newHeads` subs, each matching log to `logs` subs.
    ///
    /// Called from the consensus finalization path right after
    /// `set_block_height` — the EVM history for `height` is already
    /// sealed by then (the executor's `end_block` runs inside
    /// `commit_block`, before the engine reports the height).
    ///
    /// Exits early when no subscriptions are active or no EVM
    /// module is attached, so the per-block cost on nodes serving
    /// no WS clients is one lock + empty-map check.
    pub fn publish_new_block(&self, height: u64) {
        if !self.subscriptions.has_subscriptions() {
            return;
        }
        let Some(evm) = self.evm.as_ref() else { return };
        let (header, logs) = {
            let history = evm.history();
            let Some(block) = history.block(height) else { return };
            (
                block_header_json(block),
                history.logs(&LogFilter {
                    from_block: height,
                    to_block: height,
                    ..LogFilter::default()
                }),
            )
        };
        self.subscriptions.publish(&header, &logs);
    }

    // ---- Ethereum RPC methods ----

    /// `eth_chainId` — returns the chain ID as a hex string.
    fn eth_chain_id(&self) -> Value {
        json!(format!("0x{:x}", self.chain_id))
    }

    /// `eth_blockNumber` — returns the current block height as a hex
    /// string.
    fn eth_block_number(&self) -> Value {
        json!(format!("0x{:x}", self.block_height()))
    }

    /// `eth_gasPrice` — returns the current gas price (base fee) as
    /// a hex string in wei.
    fn eth_gas_price(&self) -> Value {
        json!(format!("0x{:x}", self.base_fee))
    }

    /// `net_version` — returns the network ID as a decimal string.
    fn net_version(&self) -> Value {
        json!(self.chain_id.to_string())
    }

    /// `web3_clientVersion` — returns the client version string.
    fn web3_client_version(&self) -> Value {
        json!(self.client_version)
    }

    /// `eth_getBalance` — returns an account's balance as a hex
    /// string in wei.
    ///
    /// Params: `[address: String, block: String?]`
    ///
    /// Only the latest state is servable (no historical trie window
    /// yet); a tag resolving to an older sealed block returns the
    /// geth-style "missing trie node" error.
    fn eth_get_balance(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let evm = self.require_evm()?;
        self.require_latest(params.get(1))?;
        Ok(hex_quantity_u128(evm.balance(&addr)))
    }

    /// `eth_getTransactionCount` — returns an account's nonce as a
    /// hex string.
    ///
    /// Params: `[address: String, block: String?]`
    fn eth_get_transaction_count(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let evm = self.require_evm()?;
        self.require_latest(params.get(1))?;
        Ok(json!(format!("0x{:x}", evm.nonce(&addr))))
    }

    /// `eth_subscribe` — creates a WebSocket subscription.
    ///
    /// Params: `[subscriptionType: String, options?: Object]`
    ///
    /// Returns the subscription ID as a hex string. Over HTTP the
    /// method errors with `"notifications not supported"` — the
    /// geth behaviour, since there is no push channel.
    ///
    /// For `logs` subscriptions, `options` is an `eth_getLogs`-shaped
    /// filter object (`address`, `topics`); block-range fields are
    /// accepted but ignored — pushes only cover newly finalized
    /// blocks.
    fn eth_subscribe(&self, params: &[Value], conn: Option<&WsConn>) -> Result<Value, RpcError> {
        let Some(conn) = conn else {
            return Err(RpcError {
                code: -32_000,
                message: "notifications not supported".to_string(),
                data: None,
            });
        };
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing subscription type"));
        }
        let type_str = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("subscription type must be a string"))?;
        let kind = SubscriptionType::parse(type_str).ok_or_else(|| {
            RpcError::invalid_params(&format!("unknown subscription type: {type_str}"))
        })?;
        let filter = match (kind.clone(), params.get(1)) {
            (SubscriptionType::Logs, Some(obj)) => Some(self.parse_log_filter(obj)?),
            (SubscriptionType::Logs, None) => Some(LogFilter::default()),
            _ => None,
        };
        Ok(json!(self.subscriptions.register(kind, filter, conn.conn_id, conn.sink.clone())))
    }

    /// `eth_unsubscribe` — cancels a WebSocket subscription.
    ///
    /// Params: `[subscriptionId: String]`
    ///
    /// Returns `true` if the subscription existed, `false` for
    /// unknown IDs (geth semantics — not an error).
    fn eth_unsubscribe(&self, params: &[Value]) -> Result<Value, RpcError> {
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing subscription ID"));
        }
        let id = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("subscription ID must be a string"))?;
        Ok(json!(self.subscriptions.unregister(id)))
    }

    // ---- Phase E: extended RPC methods ----

    /// `net_listening` — returns `true` (Oxide is always listening).
    fn net_listening(&self) -> Value {
        let _ = self;
        json!(true)
    }

    /// `net_peerCount` — returns the peer count as hex. Phase E v0
    /// returns `0x0` (no P2P wired yet).
    fn net_peer_count(&self) -> Value {
        let _ = self;
        json!("0x0")
    }

    /// `web3_sha3` — returns keccak-256 of the input data.
    ///
    /// Params: `[data: String]` (hex-encoded data)
    fn web3_sha3(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing data"));
        }
        let data_hex = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("data must be a hex string"))?;
        let data = hex_decode(data_hex)?;
        let hash = keccak256(&data);
        Ok(json!(format!("0x{}", hex::encode(hash))))
    }

    /// `eth_getCode` — returns the code at a given address.
    ///
    /// Params: `[address: String, block: String?]`
    fn eth_get_code(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let evm = self.require_evm()?;
        self.require_latest(params.get(1))?;
        Ok(json!(format!("0x{}", hex::encode(evm.code(&addr)))))
    }

    /// `eth_getStorageAt` — returns the storage value at a given
    /// address and slot.
    ///
    /// Params: `[address: String, slot: String, block: String?]`
    fn eth_get_storage_at(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let slot = parse_u256(
            params.get(1).ok_or_else(|| RpcError::invalid_params("missing storage slot"))?,
        )?;
        let evm = self.require_evm()?;
        self.require_latest(params.get(2))?;
        let value = evm.storage_at(&addr, &slot);
        Ok(json!(format!("0x{value:064x}")))
    }

    /// `eth_getBlockByNumber` — returns a block by number.
    ///
    /// Params: `[blockNumber: String|Object, fullTransactions: bool]`
    ///
    /// Serves the module's sealed-block history window; heights
    /// outside the window (evicted or future) return `null`.
    fn eth_get_block_by_number(&self, params: &[Value]) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
        let number = self.resolve_block_ref(params.first())?;
        let history = evm.history();
        Ok(match history.block(number) {
            Some(block) => block_json(block, full),
            None => Value::Null,
        })
    }

    /// `eth_getBlockByHash` — returns a block by hash.
    ///
    /// Params: `[blockHash: String, fullTransactions: bool]`
    fn eth_get_block_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash = parse_b256(
            params.first().ok_or_else(|| RpcError::invalid_params("missing block hash"))?,
        )?;
        let evm = self.require_evm()?;
        let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
        let history = evm.history();
        Ok(match history.block_by_hash(&hash) {
            Some(block) => block_json(block, full),
            None => Value::Null,
        })
    }

    /// `eth_getBlockTransactionCountByNumber` — returns the number of
    /// transactions in a block.
    ///
    /// Params: `[blockNumber: String]`
    fn eth_get_block_tx_count_by_number(&self, params: &[Value]) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let number = self.resolve_block_ref(params.first())?;
        let history = evm.history();
        Ok(match history.block(number) {
            Some(block) => json!(format!("0x{:x}", block.txs.len())),
            None => Value::Null,
        })
    }

    /// `eth_getBlockTransactionCountByHash` — returns the number of
    /// transactions in a block by hash.
    ///
    /// Params: `[blockHash: String]`
    fn eth_get_block_tx_count_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash = parse_b256(
            params.first().ok_or_else(|| RpcError::invalid_params("missing block hash"))?,
        )?;
        let evm = self.require_evm()?;
        let history = evm.history();
        Ok(match history.block_by_hash(&hash) {
            Some(block) => json!(format!("0x{:x}", block.txs.len())),
            None => Value::Null,
        })
    }

    /// `eth_getTransactionByHash` — returns a transaction by hash.
    ///
    /// Params: `[txHash: String]`
    fn eth_get_transaction_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash =
            parse_b256(params.first().ok_or_else(|| RpcError::invalid_params("missing tx hash"))?)?;
        let evm = self.require_evm()?;
        let history = evm.history();
        Ok(match history.tx_location(&hash) {
            Some((height, index)) => history
                .block(height)
                .and_then(|b| b.txs.get(index as usize).map(|t| tx_json(t, b)))
                .unwrap_or(Value::Null),
            None => Value::Null,
        })
    }

    /// `eth_getTransactionByBlockNumberAndIndex` — returns a tx by
    /// block number and index.
    ///
    /// Params: `[blockNumber: String, index: String]`
    fn eth_get_transaction_by_block_and_index(&self, params: &[Value]) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let number = self.resolve_block_ref(params.first())?;
        let index =
            parse_u64(params.get(1).ok_or_else(|| RpcError::invalid_params("missing tx index"))?)?;
        let history = evm.history();
        let i = usize::try_from(index).unwrap_or(usize::MAX);
        Ok(match history.block(number) {
            Some(block) => block.txs.get(i).map_or(Value::Null, |t| tx_json(t, block)),
            None => Value::Null,
        })
    }

    /// `eth_getTransactionByBlockHashAndIndex` — returns a tx by
    /// block hash and index.
    ///
    /// Params: `[blockHash: String, index: String]`
    fn eth_get_transaction_by_block_hash_and_index(
        &self,
        params: &[Value],
    ) -> Result<Value, RpcError> {
        let hash = parse_b256(
            params.first().ok_or_else(|| RpcError::invalid_params("missing block hash"))?,
        )?;
        let evm = self.require_evm()?;
        let index =
            parse_u64(params.get(1).ok_or_else(|| RpcError::invalid_params("missing tx index"))?)?;
        let history = evm.history();
        let i = usize::try_from(index).unwrap_or(usize::MAX);
        Ok(match history.block_by_hash(&hash) {
            Some(block) => block.txs.get(i).map_or(Value::Null, |t| tx_json(t, block)),
            None => Value::Null,
        })
    }

    /// `eth_getTransactionReceipt` — returns a transaction receipt.
    ///
    /// Params: `[txHash: String]`
    fn eth_get_transaction_receipt(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash =
            parse_b256(params.first().ok_or_else(|| RpcError::invalid_params("missing tx hash"))?)?;
        let evm = self.require_evm()?;
        let history = evm.history();
        Ok(match history.tx_location(&hash) {
            Some((height, index)) => history.block(height).map_or(Value::Null, |block| {
                let i = index as usize;
                match (block.txs.get(i), block.receipts.get(i)) {
                    (Some(tx), Some(receipt)) => {
                        let cumulative = evm::receipts::Receipt::cumulative_gas(&block.receipts);
                        let log_base: u32 = block.receipts[..i]
                            .iter()
                            .map(|r| u32::try_from(r.logs.len()).unwrap_or(u32::MAX))
                            .sum();
                        receipt_json(tx, receipt, block, cumulative[i], log_base)
                    }
                    _ => Value::Null,
                }
            }),
            None => Value::Null,
        })
    }

    /// `eth_sendRawTransaction` — submits a raw EVM transaction.
    ///
    /// Params: `[rawTx: String]` (hex-encoded RLP transaction)
    ///
    /// When a [`TxSubmitter`] is attached, the raw RLP bytes are decoded
    /// into an [`evm::tx::SignedTx`], the sender is recovered via
    /// secp256k1, and the transaction is wrapped in the Oxide envelope
    /// (`evm::wrap_evm_tx_envelope`) and pushed into the mempool. The
    /// returned hash is the keccak256 of the raw RLP — the canonical
    /// Ethereum transaction hash.
    ///
    /// When no submitter is attached, the hash is still computed and
    /// returned, but the transaction is not submitted (Phase 2 v0
    /// behaviour, retained for stateless unit tests).
    fn eth_send_raw_transaction(&self, params: &[Value]) -> Result<Value, RpcError> {
        let start = std::time::Instant::now();
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing raw transaction"));
        }
        let raw_hex = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("raw tx must be a hex string"))?;
        let raw = hex_decode(raw_hex)?;
        // The canonical Ethereum tx hash is keccak256 of the raw RLP.
        let hash = keccak256(&raw);

        if let Some(submitter) = &self.tx_submitter {
            // Decode the raw RLP into a signed EVM transaction. This
            // validates the transaction's structure (legacy, EIP-2930,
            // or EIP-1559) and lets us recover the sender and extract
            // the nonce and fee needed for the Oxide envelope.
            let signed = evm::tx::SignedTx::decode_raw(&raw).map_err(|e| {
                RpcError::invalid_params(&format!("invalid raw transaction: {e:?}"))
            })?;
            // Recover the sender's Ethereum address from the
            // signature. This is the same recovery the EVM module
            // performs during execution; doing it here lets the
            // mempool order by sender nonce without re-decoding.
            let sender = signed
                .recover_sender()
                .map_err(|e| RpcError::invalid_params(&format!("invalid signature: {e:?}")))?;
            // The envelope fee is the max fee per gas (EIP-1559) or
            // the gas price (legacy/EIP-2930), truncated to u64. The
            // mempool uses this for fee-density ranking. Amounts that
            // do not fit in u64 are rejected — Ethereum gas prices
            // are always small in practice, but we guard against
            // malformed input.
            let fee_u256 = signed.max_fee_per_gas();
            let fee: u64 = u64::try_from(fee_u256)
                .map_err(|_| RpcError::invalid_params("fee exceeds u64 range"))?;
            let nonce = signed.nonce();
            // Wrap the raw RLP in the Oxide envelope and submit.
            let envelope = evm::wrap_evm_tx_envelope(&sender, nonce, fee, &raw);
            submitter
                .submit_tx(TxBytes::new(envelope))
                .map_err(|reason| RpcError::transaction_rejected(&reason))?;
        }

        if let Some(recorder) = &self.recorder {
            recorder.record("rpc_send_raw_tx", start.elapsed());
        }

        Ok(json!(format!("0x{}", hex::encode(hash))))
    }

    /// `eth_call` — executes a call without persisting state.
    ///
    /// Params: `[call: Object, block: String?]`
    ///
    /// Runs on the module's simulation env (nonce/block-gas-limit/
    /// base-fee checks disabled; balance and fee checks kept, as in
    /// geth's `DoCall`). Reverts surface as JSON-RPC error code 3
    /// with the revert data attached — the shape web3 libraries
    /// decode into `Error(string)` reasons.
    fn eth_call(&self, params: &[Value]) -> Result<Value, RpcError> {
        let call = params.first().ok_or_else(|| RpcError::invalid_params("missing call object"))?;
        let req = parse_call_object(call)?;
        let evm = self.require_evm()?;
        self.require_latest(params.get(1))?;
        match evm.call_read(&req) {
            Ok(outcome) => Ok(json!(format!("0x{}", hex::encode(outcome.output)))),
            Err(e) => Err(call_error(e)),
        }
    }

    /// `eth_estimateGas` — estimates gas for a call.
    ///
    /// Params: `[call: Object, block: String?]`
    ///
    /// Binary-searches the simulation env for the smallest succeeding
    /// gas limit (geth/reth semantics). A call that cannot succeed at
    /// the block gas limit surfaces the underlying revert/halt error.
    fn eth_estimate_gas(&self, params: &[Value]) -> Result<Value, RpcError> {
        let call = params.first().ok_or_else(|| RpcError::invalid_params("missing call object"))?;
        let req = parse_call_object(call)?;
        let evm = self.require_evm()?;
        self.require_latest(params.get(1))?;
        match evm.estimate_call_gas(&req) {
            Ok(gas) => Ok(json!(format!("0x{gas:x}"))),
            Err(e) => Err(call_error(e)),
        }
    }

    /// `eth_maxPriorityFeePerGas` — returns the current priority fee.
    fn eth_max_priority_fee_per_gas(&self) -> Value {
        // Phase E v0: return 1 gwei (typical priority fee).
        let _ = self;
        json!("0x3b9aca00")
    }

    /// `eth_getBlockReceipts` — returns all receipts for a block.
    ///
    /// Params: `[block: String]`
    fn eth_get_block_receipts(&self, params: &[Value]) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let number = self.resolve_block_ref(params.first())?;
        let history = evm.history();
        Ok(match history.block(number) {
            Some(block) => {
                let cumulative = evm::receipts::Receipt::cumulative_gas(&block.receipts);
                let mut log_base = 0u32;
                Value::Array(
                    block
                        .txs
                        .iter()
                        .zip(block.receipts.iter())
                        .zip(cumulative.iter())
                        .map(|((tx, receipt), &cum)| {
                            let json = receipt_json(tx, receipt, block, cum, log_base);
                            log_base = log_base.saturating_add(
                                u32::try_from(receipt.logs.len()).unwrap_or(u32::MAX),
                            );
                            json
                        })
                        .collect(),
                )
            }
            None => Value::Null,
        })
    }

    /// `eth_getLogs` — returns logs matching a filter.
    ///
    /// Params: `[filter: Object]` with `fromBlock`, `toBlock`,
    /// `address` (string or array), `topics` (positional array of
    /// hash / hash-array / null), or `blockHash` (EIP-234
    /// single-block form).
    ///
    /// Bounds: the scan is limited to the retained history window
    /// and `MAX_LOG_RESULTS` entries — an unbounded request returns
    /// `-32005` rather than OOM-ing the node (geth applies the same
    /// resource-limit principle via `FilterQuery` caps).
    fn eth_get_logs(&self, params: &[Value]) -> Result<Value, RpcError> {
        let filter_obj =
            params.first().ok_or_else(|| RpcError::invalid_params("missing filter"))?;
        if !filter_obj.is_object() {
            return Err(RpcError::invalid_params("filter must be an object"));
        }
        let evm = self.require_evm()?;
        let filter = self.parse_log_filter(filter_obj)?;
        let history = evm.history();
        let matches = history.logs(&filter);
        if matches.len() > MAX_LOG_RESULTS {
            return Err(RpcError {
                code: -32_005,
                message: format!(
                    "query returned more than {MAX_LOG_RESULTS} results; narrow the filter"
                ),
                data: None,
            });
        }
        Ok(Value::Array(matches.iter().map(log_json).collect()))
    }

    /// `eth_feeHistory` — returns fee history.
    ///
    /// Params: `[blockCount: String, newestBlock: String, rewardPercentiles: Array?]`
    ///
    /// Serves per-block `baseFeePerGas`, `gasUsedRatio`, and (when
    /// percentiles are requested) per-block priority-fee percentiles
    /// over executed transactions — the same shape geth returns.
    fn eth_fee_history(&self, params: &[Value]) -> Result<Value, RpcError> {
        let count = parse_u64(
            params.first().ok_or_else(|| RpcError::invalid_params("missing blockCount"))?,
        )?;
        if count == 0 {
            return Err(RpcError::invalid_params("blockCount must be > 0"));
        }
        if count > MAX_FEE_HISTORY_BLOCKS {
            return Err(RpcError::invalid_params(&format!(
                "blockCount exceeds maximum {MAX_FEE_HISTORY_BLOCKS}"
            )));
        }
        let evm = self.require_evm()?;
        let newest = self.resolve_block_ref(params.get(1))?;
        let percentiles: Vec<f64> = params
            .get(2)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_f64).collect())
            .unwrap_or_default();
        let history = evm.history();
        let latest = history.latest().unwrap_or(0);
        let newest = newest.min(latest);
        // `+1` for the EIP-1559 next-block base fee geth appends.
        let oldest = newest.saturating_sub(count).saturating_add(1);
        // `count` ≤ MAX_FEE_HISTORY_BLOCKS (checked above) — always
        // fits usize even on 32-bit targets.
        let cap = usize::try_from(count).unwrap_or(0);
        let mut base_fees = Vec::with_capacity(cap + 1);
        let mut ratios = Vec::with_capacity(cap);
        let mut rewards: Vec<Vec<String>> = Vec::with_capacity(cap);
        for h in oldest..=newest {
            if let Some(block) = history.block(h) {
                base_fees.push(format!("0x{:x}", block.base_fee));
                #[allow(clippy::cast_precision_loss)]
                ratios.push(block.gas_used as f64 / block.gas_limit.max(1) as f64);
                if !percentiles.is_empty() {
                    rewards.push(block_reward_percentiles(block, &percentiles));
                }
            } else {
                base_fees.push("0x0".to_string());
                ratios.push(0.0);
                if !percentiles.is_empty() {
                    rewards.push(Vec::new());
                }
            }
        }
        // The next block's base fee: our base fee is configured
        // statically (no EIP-1559 adjustment), so it repeats.
        base_fees.push(format!("0x{:x}", self.base_fee));
        let mut out = json!({
            "oldestBlock": format!("0x{oldest:x}"),
            "baseFeePerGas": base_fees,
            "gasUsedRatio": ratios,
        });
        if !percentiles.is_empty() {
            out["reward"] = json!(rewards);
        }
        Ok(out)
    }

    /// `eth_mining` — returns whether the node is mining.
    fn eth_mining(&self) -> Value {
        let _ = self;
        json!(false)
    }

    /// `eth_syncing` — returns sync status.
    fn eth_syncing(&self) -> Value {
        let _ = self;
        json!(false)
    }

    /// `eth_protocolVersion` — returns the protocol version.
    fn eth_protocol_version(&self) -> Value {
        let _ = self;
        json!("0x41")
    }

    /// `eth_accounts` — returns the accounts the node manages.
    fn eth_accounts(&self) -> Value {
        let _ = self;
        json!([])
    }

    /// `eth_coinbase` — returns the coinbase address.
    fn eth_coinbase(&self) -> Value {
        let _ = self;
        json!("0x0000000000000000000000000000000000000000")
    }

    /// `eth_hashrate` — returns the hashrate.
    fn eth_hashrate(&self) -> Value {
        let _ = self;
        json!("0x0")
    }

    // ---- Helpers ----

    /// The attached EVM module, or an internal error when the node
    /// was built without one (stateless test harnesses).
    fn require_evm(&self) -> Result<&evm::EvmModule, RpcError> {
        self.evm.as_deref().ok_or_else(|| RpcError::internal_error("evm module unavailable"))
    }

    /// Resolve a block tag / number / EIP-1898 object to a concrete
    /// block height in the sealed history window.
    ///
    /// Tag semantics under instant-finality consensus:
    ///
    /// - `latest` — the most recently *sealed* block
    ///   (`history.latest()`; falls back to the executor-reported
    ///   height when no block has sealed yet).
    /// - `safe` / `finalized` — identical to `latest`: a committed
    ///   block is final, there is no unfinalized "latest".
    /// - `pending` — `latest` for lookups (no pending-block
    ///   simulation is implemented yet).
    /// - `earliest` — height 0.
    /// - `"0x…"` — a literal height; may resolve outside the
    ///   retained window (history queries then return `null`).
    /// - `{blockHash: "0x…"}` / `{blockNumber: "0x…"}` — EIP-1898
    ///   object form; an unknown hash is an error.
    fn resolve_block_ref(&self, tag: Option<&Value>) -> Result<u64, RpcError> {
        let latest = self.latest_sealed_height();
        match tag {
            None => Ok(latest),
            Some(Value::String(s)) => match s.as_str() {
                "latest" | "safe" | "finalized" | "pending" => Ok(latest),
                "earliest" => Ok(0),
                _ => {
                    let s = s.strip_prefix("0x").unwrap_or(s);
                    u64::from_str_radix(s, 16).map_err(|e| {
                        RpcError::invalid_params(&format!("invalid block number: {e}"))
                    })
                }
            },
            Some(Value::Object(obj)) => {
                if let Some(hash) = obj.get("blockHash") {
                    let hash = parse_b256(hash)?;
                    let evm = self.require_evm()?;
                    let history = evm.history();
                    return history
                        .block_by_hash(&hash)
                        .map(|b| b.number)
                        .ok_or_else(|| RpcError::invalid_params("unknown block hash"));
                }
                if let Some(number) = obj.get("blockNumber") {
                    return self.resolve_block_ref(Some(number));
                }
                Err(RpcError::invalid_params("invalid block object"))
            }
            Some(_) => Err(RpcError::invalid_params("block must be a tag, number, or object")),
        }
    }

    /// The height of the most recent sealed block — the height
    /// `"latest"` resolves to. Falls back to the executor-reported
    /// height before the first block seals.
    fn latest_sealed_height(&self) -> u64 {
        self.evm
            .as_deref()
            .and_then(|evm| evm.history().latest())
            .unwrap_or_else(|| self.block_height())
    }

    /// Gate for *state* queries (`eth_call`, `eth_getBalance`, …):
    /// only the latest state is servable (no historical trie window
    /// yet). A tag resolving below the latest sealed height returns
    /// the geth-style "missing trie node" error; above it, "header
    /// not found".
    fn require_latest(&self, tag: Option<&Value>) -> Result<(), RpcError> {
        let h = self.resolve_block_ref(tag)?;
        let latest = self.latest_sealed_height();
        if h > latest {
            return Err(RpcError::internal_error("header not found"));
        }
        if h < latest {
            return Err(RpcError::internal_error(&format!(
                "missing trie node: state for block {h} unavailable (latest is {latest})"
            )));
        }
        Ok(())
    }

    /// Parse an `eth_getLogs`/`eth_newFilter` filter object into the
    /// module's [`LogFilter`].
    ///
    /// `fromBlock`/`toBlock` accept tags and hex numbers (default
    /// `latest`); `blockHash` (EIP-234) makes the range fields
    /// irrelevant. `address` accepts a string or array of strings;
    /// `topics` accepts `null`, a hash, or an array of hashes per
    /// position.
    fn parse_log_filter(&self, obj: &Value) -> Result<LogFilter, RpcError> {
        let mut filter = LogFilter {
            from_block: self.latest_sealed_height(),
            to_block: self.latest_sealed_height(),
            ..LogFilter::default()
        };
        let Some(map) = obj.as_object() else {
            return Err(RpcError::invalid_params("filter must be an object"));
        };
        if let Some(v) = map.get("blockHash") {
            filter.block_hash = Some(parse_b256(v)?);
        }
        if let Some(v) = map.get("fromBlock") {
            filter.from_block = self.resolve_block_ref(Some(v))?;
        }
        if let Some(v) = map.get("toBlock") {
            filter.to_block = self.resolve_block_ref(Some(v))?;
        }
        if filter.from_block > filter.to_block && filter.block_hash.is_none() {
            return Err(RpcError::invalid_params("fromBlock exceeds toBlock"));
        }
        match map.get("address") {
            None | Some(Value::Null) => {}
            Some(Value::String(_)) => {
                filter.addresses.push(parse_eth_address(map.get("address"))?);
            }
            Some(Value::Array(addrs)) => {
                for a in addrs {
                    filter.addresses.push(parse_eth_address(Some(a))?);
                }
            }
            Some(_) => {
                return Err(RpcError::invalid_params("address must be string or array"));
            }
        }
        if let Some(Value::Array(topics)) = map.get("topics") {
            for entry in topics {
                let matcher = match entry {
                    Value::Null => TopicMatcher::Any,
                    Value::String(_) => TopicMatcher::One(parse_b256(entry)?),
                    Value::Array(set) => TopicMatcher::AnyOf(
                        set.iter().map(parse_b256).collect::<Result<Vec<B256>, _>>()?,
                    ),
                    _ => {
                        return Err(RpcError::invalid_params(
                            "topics entries must be null, a hash, or an array",
                        ));
                    }
                };
                filter.topics.push(matcher);
            }
        }
        Ok(filter)
    }
}

/// Maximum `eth_getLogs` results per request. geth does not cap
/// `eth_getLogs` server-side (only via timeouts); we cap because a
/// full-window scan over a 500k-tx block can produce hundreds of
/// thousands of entries in one response body.
const MAX_LOG_RESULTS: usize = 10_000;

/// Maximum `eth_feeHistory` block count per request — mirrors
/// geth's `maxFeeHistory` (1024) headroom while staying comfortably
/// inside the 8192-block retained window.
const MAX_FEE_HISTORY_BLOCKS: u64 = 1024;

/// Map a [`evm::CallError`] onto the Ethereum JSON-RPC error
/// surface: reverts use code `3` ("execution reverted") with the
/// revert data attached for ABI decoding; halts and validation
/// rejections use `-32000` with a human-readable reason.
fn call_error(e: evm::CallError) -> RpcError {
    match e {
        evm::CallError::Revert { output, .. } => RpcError {
            code: 3,
            message: revert_message(&output),
            data: Some(json!(format!("0x{}", hex::encode(output)))),
        },
        evm::CallError::Halt { reason, .. } => {
            RpcError::internal_error(&format!("execution halted: {reason}"))
        }
        evm::CallError::Rejected(err) => {
            RpcError::internal_error(&format!("execution rejected: {err:?}"))
        }
    }
}

/// Extract the `Error(string)` reason from ABI revert data, falling
/// back to geth's generic message when the payload is not an
/// `Error(string)` selector.
fn revert_message(output: &[u8]) -> String {
    // ABI Error(string): selector 0x08c379a0, offset, length, utf8.
    const ERROR_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
    if output.len() >= 4 + 64 && output[..4] == ERROR_SELECTOR {
        let len_bytes: [u8; 32] = output[4 + 32..4 + 64].try_into().unwrap_or([0; 32]);
        let len = U256::from_be_bytes(len_bytes).to::<usize>();
        if output.len() >= 4 + 64 + len
            && let Ok(reason) = std::str::from_utf8(&output[4 + 64..4 + 64 + len])
        {
            return format!("execution reverted: {reason}");
        }
    }
    "execution reverted".to_string()
}

/// Per-block priority-fee percentiles for `eth_feeHistory`.
///
/// The tip each transaction paid is `effective_gas_price −
/// base_fee`; percentiles are taken over the block's txs (empty
/// blocks yield zeroes, matching geth).
fn block_reward_percentiles(block: &ExecutedBlock, percentiles: &[f64]) -> Vec<String> {
    if block.txs.is_empty() {
        return vec!["0x0".to_string(); percentiles.len()];
    }
    let mut tips: Vec<u128> = block
        .txs
        .iter()
        .map(|tx| {
            evm::history::effective_gas_price(tx, block.base_fee)
                .saturating_sub(u128::from(block.base_fee))
        })
        .collect();
    tips.sort_unstable();
    percentiles
        .iter()
        .map(|p| {
            let p = p.clamp(0.0, 100.0);
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_sign_loss,
                clippy::cast_possible_truncation
            )]
            let idx = ((tips.len() - 1) as f64 * p / 100.0) as usize;
            format!("0x{:x}", tips[idx])
        })
        .collect()
}

/// Serialize a stored transaction to the `eth_getTransactionByHash`
/// object shape. `block` supplies the positional metadata.
fn tx_json(tx: &StoredTx, block: &ExecutedBlock) -> Value {
    json!({
        "hash": format!("0x{:x}", tx.hash),
        "nonce": format!("0x{:x}", tx.nonce),
        "blockHash": format!("0x{:x}", block.hash),
        "blockNumber": format!("0x{:x}", block.number),
        "transactionIndex": format!("0x{:x}", tx.tx_index),
        "from": format!("0x{:x}", tx.from),
        "to": tx.to.map_or(Value::Null, |a| json!(format!("0x{a:x}"))),
        "value": format!("0x{:x}", tx.value),
        "gas": format!("0x{:x}", tx.gas_limit),
        "gasPrice": format!("0x{:x}", evm::history::effective_gas_price(tx, block.base_fee)),
        "maxFeePerGas": format!("0x{:x}", tx.gas_price),
        "maxPriorityFeePerGas": format!("0x{:x}", tx.max_priority_fee_per_gas),
        "input": format!("0x{}", hex::encode(&tx.input)),
        "type": format!("0x{:x}", tx.tx_type),
        "chainId": "0x1",
        "v": format!("0x{:x}", tx.v),
        "r": format!("0x{:x}", tx.r),
        "s": format!("0x{:x}", tx.s),
    })
}

/// Serialize a receipt to the `eth_getTransactionReceipt` object
/// shape. `cumulative` is the block-cumulative gas up to and
/// including this tx; `log_base` is the block-wide index of this
/// receipt's first log.
fn receipt_json(
    tx: &StoredTx,
    receipt: &evm::receipts::Receipt,
    block: &ExecutedBlock,
    cumulative: u64,
    log_base: u32,
) -> Value {
    let logs: Vec<Value> = receipt
        .logs
        .iter()
        .enumerate()
        .map(|(i, log)| {
            json!({
                "address": format!("0x{:x}", log.address),
                "topics": log.topics().iter().map(|t| format!("0x{t:x}")).collect::<Vec<_>>(),
                "data": format!("0x{}", hex::encode(&log.data.data)),
                "blockNumber": format!("0x{:x}", block.number),
                "blockHash": format!("0x{:x}", block.hash),
                "transactionHash": format!("0x{:x}", tx.hash),
                "transactionIndex": format!("0x{:x}", tx.tx_index),
                "logIndex": format!("0x{:x}", log_base.saturating_add(u32::try_from(i).unwrap_or(u32::MAX))),
                "removed": false,
            })
        })
        .collect();
    json!({
        "transactionHash": format!("0x{:x}", tx.hash),
        "transactionIndex": format!("0x{:x}", tx.tx_index),
        "blockHash": format!("0x{:x}", block.hash),
        "blockNumber": format!("0x{:x}", block.number),
        "from": format!("0x{:x}", tx.from),
        "to": tx.to.map_or(Value::Null, |a| json!(format!("0x{a:x}"))),
        "cumulativeGasUsed": format!("0x{cumulative:x}"),
        "gasUsed": format!("0x{:x}", receipt.gas_used),
        "contractAddress": receipt
            .contract_address
            .map_or(Value::Null, |a| json!(format!("0x{a:x}"))),
        "logs": logs,
        "logsBloom": format!("0x{}", hex::encode(receipt.bloom.as_slice())),
        "status": if receipt.status { "0x1" } else { "0x0" },
        "type": format!("0x{:x}", tx.tx_type),
        "effectiveGasPrice": format!("0x{:x}", evm::history::effective_gas_price(tx, block.base_fee)),
    })
}

/// Serialize a [`evm::history::LogMatch`] to the `eth_getLogs`
/// entry shape.
fn log_json(m: &evm::history::LogMatch) -> Value {
    json!({
        "address": format!("0x{:x}", m.address),
        "topics": m.topics.iter().map(|t| format!("0x{t:x}")).collect::<Vec<_>>(),
        "data": format!("0x{}", hex::encode(&m.data)),
        "blockNumber": format!("0x{:x}", m.block_number),
        "blockHash": format!("0x{:x}", m.block_hash),
        "transactionHash": format!("0x{:x}", m.tx_hash),
        "transactionIndex": format!("0x{:x}", m.tx_index),
        "logIndex": format!("0x{:x}", m.log_index),
        "removed": false,
    })
}

/// Serialize a sealed block to the `eth_getBlockBy*` object shape.
/// `full` selects full transaction objects over bare hashes.
///
/// Post-merge fields carry their canonical empties: `sha3Uncles`
/// is the empty-list hash, `nonce`/`difficulty`/`mixHash` are zero,
/// `withdrawals`/`withdrawalsRoot` are the empty Prague values.
fn block_json(block: &ExecutedBlock, full: bool) -> Value {
    let txs: Vec<Value> = if full {
        block.txs.iter().map(|t| tx_json(t, block)).collect()
    } else {
        block.txs.iter().map(|t| json!(format!("0x{:x}", t.hash))).collect()
    };
    json!({
        "number": format!("0x{:x}", block.number),
        "hash": format!("0x{:x}", block.hash),
        "parentHash": format!("0x{:x}", block.parent_hash),
        "nonce": "0x0000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": format!("0x{}", hex::encode(block.bloom)),
        "transactionsRoot": format!("0x{:x}", block.tx_root),
        "stateRoot": format!("0x{:x}", block.state_root),
        "receiptsRoot": format!("0x{:x}", block.receipts_root),
        "miner": format!("0x{:x}", block.coinbase),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "extraData": "0x",
        "size": "0x0",
        "gasLimit": format!("0x{:x}", block.gas_limit),
        "gasUsed": format!("0x{:x}", block.gas_used),
        "timestamp": format!("0x{:x}", block.timestamp),
        "baseFeePerGas": format!("0x{:x}", block.base_fee),
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "transactions": txs,
        "uncles": [],
        "withdrawals": [],
        "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    })
}

/// Serialize a block header for a `newHeads` subscription
/// notification. geth sends the header object without the
/// transaction list, `uncles`, `size`, or `totalDifficulty` —
/// same fields, same hex encoding as [`block_json`].
fn block_header_json(block: &ExecutedBlock) -> Value {
    json!({
        "number": format!("0x{:x}", block.number),
        "hash": format!("0x{:x}", block.hash),
        "parentHash": format!("0x{:x}", block.parent_hash),
        "nonce": "0x0000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": format!("0x{}", hex::encode(block.bloom)),
        "transactionsRoot": format!("0x{:x}", block.tx_root),
        "stateRoot": format!("0x{:x}", block.state_root),
        "receiptsRoot": format!("0x{:x}", block.receipts_root),
        "miner": format!("0x{:x}", block.coinbase),
        "difficulty": "0x0",
        "extraData": "0x",
        "gasLimit": format!("0x{:x}", block.gas_limit),
        "gasUsed": format!("0x{:x}", block.gas_used),
        "timestamp": format!("0x{:x}", block.timestamp),
        "baseFeePerGas": format!("0x{:x}", block.base_fee),
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    })
}

/// Parse a 20-byte hex address param into `primitives::Address`.
fn parse_address(v: Option<&Value>) -> Result<primitives::Address, RpcError> {
    let v = v.ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let s = v.as_str().ok_or_else(|| RpcError::invalid_params("address must be a hex string"))?;
    let bytes = hex_decode(s)?;
    let arr: [u8; 20] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| RpcError::invalid_params("address must be 20 bytes"))?;
    Ok(primitives::Address(arr))
}

/// Parse a 20-byte hex address param into the `alloy`/`revm`
/// address type used inside `LogFilter`, `AccessListItem`, and
/// `StoredTx` (distinct from the envelope's `primitives::Address`).
fn parse_eth_address(v: Option<&Value>) -> Result<alloy_primitives::Address, RpcError> {
    let v = v.ok_or_else(|| RpcError::invalid_params("missing address"))?;
    let s = v.as_str().ok_or_else(|| RpcError::invalid_params("address must be a hex string"))?;
    let bytes = hex_decode(s)?;
    let arr: [u8; 20] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| RpcError::invalid_params("address must be 20 bytes"))?;
    Ok(alloy_primitives::Address::from(arr))
}

/// Parse a 32-byte hex hash param into [`B256`].
fn parse_b256(v: &Value) -> Result<B256, RpcError> {
    let s = v.as_str().ok_or_else(|| RpcError::invalid_params("hash must be a hex string"))?;
    let bytes = hex_decode(s)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| RpcError::invalid_params("hash must be 32 bytes"))?;
    Ok(B256::from(arr))
}

/// Parse a hex-quantity (`"0x…"`) or decimal param into `u64`.
fn parse_u64(v: &Value) -> Result<u64, RpcError> {
    let s = v.as_str().ok_or_else(|| RpcError::invalid_params("expected hex quantity"))?;
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .map_err(|e| RpcError::invalid_params(&format!("invalid quantity: {e}")))
    } else {
        s.parse::<u64>().map_err(|e| RpcError::invalid_params(&format!("invalid quantity: {e}")))
    }
}

/// Parse a hex-quantity param into `u128` (gas-price fields can
/// exceed u64 on paper).
fn parse_u128(v: &Value) -> Result<u128, RpcError> {
    let s = v.as_str().ok_or_else(|| RpcError::invalid_params("expected hex quantity"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u128::from_str_radix(s, 16)
        .map_err(|e| RpcError::invalid_params(&format!("invalid quantity: {e}")))
}

/// Parse a hex-quantity/storage-slot param into [`U256`].
fn parse_u256(v: &Value) -> Result<U256, RpcError> {
    let s = v.as_str().ok_or_else(|| RpcError::invalid_params("expected hex quantity"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(s, 16)
        .map_err(|e| RpcError::invalid_params(&format!("invalid quantity: {e}")))
}

/// Format a `u128` as an Ethereum hex quantity (`0x0` for zero).
fn hex_quantity_u128(v: u128) -> Value {
    json!(format!("0x{v:x}"))
}

/// Parse the `eth_call`/`eth_estimateGas` call object into
/// [`evm::CallRequest`]. `data` and `input` are interchangeable
/// (geth merges them; `input` wins when both are present).
fn parse_call_object(v: &Value) -> Result<evm::CallRequest, RpcError> {
    let Some(map) = v.as_object() else {
        return Err(RpcError::invalid_params("call object must be an object"));
    };
    let opt = |key: &str| map.get(key).filter(|v| !v.is_null());
    let mut req = evm::CallRequest {
        from: None,
        to: None,
        gas: None,
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: U256::ZERO,
        data: Vec::new(),
        nonce: None,
        access_list: Vec::new(),
    };
    if let Some(v) = opt("from") {
        req.from = Some(parse_address(Some(v))?);
    }
    if let Some(v) = opt("to") {
        req.to = Some(parse_address(Some(v))?);
    }
    if let Some(v) = opt("gas") {
        req.gas = Some(parse_u64(v)?);
    }
    if let Some(v) = opt("gasPrice") {
        req.gas_price = Some(parse_u128(v)?);
    }
    if let Some(v) = opt("maxFeePerGas") {
        req.max_fee_per_gas = Some(parse_u128(v)?);
    }
    if let Some(v) = opt("maxPriorityFeePerGas") {
        req.max_priority_fee_per_gas = Some(parse_u128(v)?);
    }
    if let Some(v) = opt("value") {
        req.value = parse_u256(v)?;
    }
    if let Some(v) = opt("data").or_else(|| opt("input")) {
        req.data = hex_decode(
            v.as_str().ok_or_else(|| RpcError::invalid_params("data must be a hex string"))?,
        )?;
    }
    if let Some(v) = opt("nonce") {
        req.nonce = Some(parse_u64(v)?);
    }
    if let Some(Value::Array(items)) = opt("accessList") {
        for item in items {
            let address = parse_eth_address(item.get("address"))?;
            let storage_keys = item
                .get("storageKeys")
                .and_then(Value::as_array)
                .map(|keys| keys.iter().map(parse_b256).collect::<Result<Vec<B256>, _>>())
                .transpose()?
                .unwrap_or_default();
            req.access_list.push(evm::tx::AccessListItem { address, storage_keys });
        }
    }
    Ok(req)
}

/// Decode a hex string (with or without `0x` prefix) to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, RpcError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| RpcError::invalid_params(&format!("invalid hex: {e}")))
}

/// Compute keccak-256 of data.
fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server() -> RpcServer {
        RpcServer::new(1, 7_000_000_000)
    }

    /// Server with a live `EvmModule` attached — the same `Arc` an
    /// executor would run against. `seal` lets a test run a
    /// `begin_block`/`end_block` pair so history queries see a real
    /// sealed block.
    fn make_evm_server() -> (RpcServer, Arc<evm::EvmModule>) {
        let mut s = RpcServer::new(1, 7);
        let module = Arc::new(evm::EvmModule::new(1, 7));
        s.set_evm(module.clone());
        (s, module)
    }

    fn make_request(method: &str, params: Vec<Value>, id: Value) -> RpcRequest {
        RpcRequest { method: method.to_string(), params, id, jsonrpc: "2.0".to_string() }
    }

    #[test]
    fn eth_chain_id_returns_hex() {
        let s = make_server();
        let req = make_request("eth_chainId", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x1")));
    }

    #[test]
    fn eth_chain_id_custom_chain() {
        let s = RpcServer::new(42, 1);
        let req = make_request("eth_chainId", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x2a")));
    }

    #[test]
    fn eth_block_number_returns_hex() {
        let s = make_server();
        s.set_block_height(100);
        let req = make_request("eth_blockNumber", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x64")));
    }

    #[test]
    fn metrics_text_exposes_basic_gauges() {
        let s = make_server();
        s.set_block_height(10);
        s.increment_tx_count();
        s.increment_tx_count();
        s.increment_tx_count();
        s.set_mempool_size(5);
        let text = s.metrics_text();
        assert!(text.contains("oxide_block_height 10"), "text: {text}");
        assert!(text.contains("oxide_tx_count 3"), "text: {text}");
        assert!(text.contains("oxide_mempool_size 5"), "text: {text}");
    }

    #[test]
    fn eth_gas_price_returns_hex() {
        let s = RpcServer::new(1, 1_000_000_000);
        let req = make_request("eth_gasPrice", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x3b9aca00")));
    }

    #[test]
    fn net_version_returns_decimal() {
        let s = RpcServer::new(1, 1);
        let req = make_request("net_version", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("1")));
    }

    #[test]
    fn web3_client_version_returns_string() {
        let s = make_server();
        let req = make_request("web3_clientVersion", vec![], json!(1));
        let resp = s.handle(&req);
        let version = resp.result.unwrap().as_str().unwrap().to_string();
        assert!(version.starts_with("oxide/"), "version must start with oxide/: {version}");
    }

    #[test]
    fn eth_get_balance_returns_zero() {
        let (s, _evm) = make_evm_server();
        let req = make_request(
            "eth_getBalance",
            vec![json!("0x0000000000000000000000000000000000000000")],
            json!(1),
        );
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x0")));
    }

    #[test]
    fn eth_get_balance_missing_address_errors() {
        let s = make_server();
        let req = make_request("eth_getBalance", vec![], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_get_transaction_count_returns_zero() {
        let (s, _evm) = make_evm_server();
        let req = make_request(
            "eth_getTransactionCount",
            vec![json!("0x0000000000000000000000000000000000000000")],
            json!(1),
        );
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x0")));
    }

    #[test]
    fn unknown_method_returns_error() {
        let s = make_server();
        let req = make_request("eth_unknownMethod", vec![], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn rate_limiter_unlimited_by_default() {
        let s = make_server();
        // With no rate limit set, all requests should succeed.
        for _ in 0..100 {
            let req = make_request("eth_chainId", vec![], json!(1));
            let resp = s.handle(&req);
            assert!(resp.error.is_none(), "request should succeed with unlimited rate");
        }
    }

    #[test]
    fn rate_limiter_rejects_excess_requests() {
        let mut s = make_server();
        s.set_rate_limit(5); // 5 requests per second
        // The first 5 requests should succeed.
        for i in 0..5 {
            let req = make_request("eth_chainId", vec![], json!(i));
            let resp = s.handle(&req);
            assert!(resp.error.is_none(), "request {i} should succeed within rate limit");
        }
        // The 6th request should be rejected with rate limit error.
        let req = make_request("eth_chainId", vec![], json!(6));
        let resp = s.handle(&req);
        assert!(resp.error.is_some(), "request 6 should be rate-limited");
        assert_eq!(resp.error.unwrap().code, -32_005);
    }

    #[test]
    fn handle_raw_parses_json() {
        let s = make_server();
        let raw = r#"{"method":"eth_chainId","params":[],"id":1,"jsonrpc":"2.0"}"#;
        let resp = s.handle_raw(raw);
        let parsed: RpcResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed.result, Some(json!("0x1")));
    }

    #[test]
    fn handle_raw_invalid_json_returns_parse_error() {
        let s = make_server();
        let resp = s.handle_raw("not json");
        let parsed: RpcResponse = serde_json::from_str(&resp).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, -32700);
    }

    #[test]
    fn response_id_echoes_request_id() {
        let s = make_server();
        let req = make_request("eth_chainId", vec![], json!("my-id"));
        let resp = s.handle(&req);
        assert_eq!(resp.id, json!("my-id"));
    }

    #[test]
    fn response_id_echoes_numeric_id() {
        let s = make_server();
        let req = make_request("eth_chainId", vec![], json!(42));
        let resp = s.handle(&req);
        assert_eq!(resp.id, json!(42));
    }

    // ---- WebSocket subscription tests ----

    /// A `WsConn` writing into a test channel — what the WS
    /// transport hands the dispatch for each socket.
    fn ws_conn() -> (WsConn, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (WsConn::new(1, tx), rx)
    }

    #[test]
    fn eth_subscribe_over_http_errors_notifications_not_supported() {
        // geth parity: subscriptions need a push channel; HTTP has
        // none, so every `eth_subscribe` on `handle` errors -32000.
        let s = make_server();
        for params in [vec![json!("newHeads")], vec![json!("logs")], vec![]] {
            let req = make_request("eth_subscribe", params, json!(1));
            let resp = s.handle(&req);
            let err = resp.error.expect("HTTP subscribe must fail");
            assert_eq!(err.code, -32_000);
            assert_eq!(err.message, "notifications not supported");
        }
    }

    #[test]
    fn eth_subscribe_new_heads_returns_id_over_ws() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = make_request("eth_subscribe", vec![json!("newHeads")], json!(1));
        let resp = s.handle_ws(&req, &conn);
        assert!(resp.error.is_none());
        let id = resp.result.unwrap().as_str().unwrap().to_string();
        assert!(id.starts_with("0x"), "subscription ID must be hex: {id}");
    }

    #[test]
    fn eth_subscribe_logs_returns_id_over_ws() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = make_request("eth_subscribe", vec![json!("logs")], json!(1));
        let resp = s.handle_ws(&req, &conn);
        assert!(resp.error.is_none());
        assert!(resp.result.unwrap().as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn eth_subscribe_logs_rejects_bad_filter_over_ws() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = make_request(
            "eth_subscribe",
            vec![json!("logs"), json!({"address": "not-an-address"})],
            json!(1),
        );
        let resp = s.handle_ws(&req, &conn);
        assert_eq!(resp.error.expect("bad filter must fail").code, -32602);
    }

    #[test]
    fn eth_subscribe_unknown_type_errors_over_ws() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = make_request("eth_subscribe", vec![json!("unknownType")], json!(1));
        let resp = s.handle_ws(&req, &conn);
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_subscribe_missing_type_errors_over_ws() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = make_request("eth_subscribe", vec![], json!(1));
        let resp = s.handle_ws(&req, &conn);
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_subscribe_non_string_type_errors_over_ws() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = make_request("eth_subscribe", vec![json!(42)], json!(1));
        let resp = s.handle_ws(&req, &conn);
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_unsubscribe_returns_true_for_active_sub() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let sub = make_request("eth_subscribe", vec![json!("newHeads")], json!(1));
        let id = s.handle_ws(&sub, &conn).result.unwrap().as_str().unwrap().to_string();
        let req = make_request("eth_unsubscribe", vec![json!(id)], json!(2));
        assert_eq!(s.handle_ws(&req, &conn).result, Some(json!(true)));
    }

    #[test]
    fn eth_unsubscribe_returns_false_for_unknown_id() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = make_request("eth_unsubscribe", vec![json!("0xdead")], json!(1));
        assert_eq!(s.handle_ws(&req, &conn).result, Some(json!(false)));
    }

    #[test]
    fn eth_unsubscribe_missing_id_errors() {
        let s = make_server();
        let req = make_request("eth_unsubscribe", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_unsubscribe_non_string_id_errors() {
        let s = make_server();
        let req = make_request("eth_unsubscribe", vec![json!(42)], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn subscription_ids_are_unique() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = || make_request("eth_subscribe", vec![json!("newHeads")], json!(1));
        let id1 = s.handle_ws(&req(), &conn).result.unwrap().as_str().unwrap().to_string();
        let id2 = s.handle_ws(&req(), &conn).result.unwrap().as_str().unwrap().to_string();
        assert_ne!(id1, id2, "subscription IDs must be unique");
    }

    #[test]
    fn drop_connection_reaps_its_subscriptions() {
        let s = make_server();
        let (conn, _rx) = ws_conn();
        let req = make_request("eth_subscribe", vec![json!("newHeads")], json!(1));
        let id = s.handle_ws(&req, &conn).result.unwrap().as_str().unwrap().to_string();
        s.drop_connection(conn.conn_id);
        // After the connection drops, the ID is unknown.
        let unsub = make_request("eth_unsubscribe", vec![json!(id)], json!(2));
        assert_eq!(s.handle(&unsub).result, Some(json!(false)));
    }

    #[test]
    fn publish_new_block_pushes_new_heads_notification() {
        use executor::Module;
        let (s, evm) = make_evm_server();
        let (conn, mut rx) = ws_conn();
        let sub = make_request("eth_subscribe", vec![json!("newHeads")], json!(1));
        let id = s.handle_ws(&sub, &conn).result.unwrap().as_str().unwrap().to_string();

        // Seal a real block, then publish — the notification must
        // carry the real header fields, not a fabricated hash.
        evm.begin_block(primitives::Height::new(1));
        evm.end_block(primitives::Height::new(1));
        s.publish_new_block(1);

        let text = rx.try_recv().expect("newHeads notification must arrive");
        let notif: Value = serde_json::from_str(&text).expect("notification must be JSON");
        assert_eq!(notif["jsonrpc"], json!("2.0"));
        assert_eq!(notif["method"], json!("eth_subscription"));
        assert_eq!(notif["params"]["subscription"], json!(id));
        let result = &notif["params"]["result"];
        assert_eq!(result["number"], json!("0x1"));
        assert_eq!(
            result["hash"].as_str().unwrap().len(),
            66,
            "hash must be a 32-byte hex quantity"
        );
        assert!(result["gasUsed"].as_str().unwrap().starts_with("0x"));
        assert!(result["stateRoot"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn publish_new_block_without_subscriptions_is_noop() {
        use executor::Module;
        let (s, evm) = make_evm_server();
        evm.begin_block(primitives::Height::new(1));
        evm.end_block(primitives::Height::new(1));
        // Must not panic or require the history lookup.
        s.publish_new_block(1);
    }

    #[test]
    fn notification_serializes_to_json() {
        let notif = SubscriptionNotification {
            jsonrpc: "2.0".to_string(),
            method: "eth_subscription".to_string(),
            params: SubscriptionParams {
                subscription: "0x1".to_string(),
                result: json!({"number": "0x2a"}),
            },
        };
        let json_str = serde_json::to_string(&notif).unwrap();
        assert!(json_str.contains("eth_subscription"));
        assert!(json_str.contains("0x1"));
        assert!(json_str.contains("0x2a"));
    }

    // ---- Phase E: extended RPC method tests ----

    #[test]
    fn web3_sha3_returns_keccak_hash() {
        let s = make_server();
        // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let req = make_request("web3_sha3", vec![json!("0x")], json!(1));
        let resp = s.handle(&req);
        let result = resp.result.unwrap();
        assert_eq!(
            result,
            json!("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
    }

    #[test]
    fn eth_get_code_returns_empty() {
        let (s, _evm) = make_evm_server();
        let req = make_request(
            "eth_getCode",
            vec![json!("0x0000000000000000000000000000000000000000")],
            json!(1),
        );
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x")));
    }

    #[test]
    fn eth_get_storage_at_returns_zero() {
        let (s, _evm) = make_evm_server();
        let req = make_request(
            "eth_getStorageAt",
            vec![json!("0x0000000000000000000000000000000000000000"), json!("0x0")],
            json!(1),
        );
        let resp = s.handle(&req);
        assert_eq!(
            resp.result,
            Some(json!("0x0000000000000000000000000000000000000000000000000000000000000000"))
        );
    }

    #[test]
    fn eth_get_block_by_number_returns_block() {
        use executor::Module;
        use primitives::Height;
        let (s, evm) = make_evm_server();
        // Seal an empty block 0 — the module seals every block it
        // executes, including empty ones.
        evm.begin_block(Height::new(0));
        evm.end_block(Height::new(0));
        let req = make_request("eth_getBlockByNumber", vec![json!("0x0"), json!(false)], json!(1));
        let resp = s.handle(&req);
        let block = resp.result.unwrap();
        assert_eq!(block["number"], json!("0x0"));
        assert!(block["transactions"].is_array());
        // A real header hash — not the zeroed stub.
        assert_ne!(
            block["hash"],
            json!("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
    }

    #[test]
    fn eth_estimate_gas_returns_intrinsic() {
        let (s, _evm) = make_evm_server();
        let req = make_request(
            "eth_estimateGas",
            vec![json!({"to": "0x0000000000000000000000000000000000000000", "value": "0x0"})],
            json!(1),
        );
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x5208"))); // 21000
    }

    #[test]
    fn eth_max_priority_fee_returns_1_gwei() {
        let s = make_server();
        let req = make_request("eth_maxPriorityFeePerGas", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x3b9aca00"))); // 1 gwei
    }

    #[test]
    fn eth_send_raw_transaction_returns_hash() {
        let s = make_server();
        // Empty tx → keccak256("") = 0xc5d2...
        let req = make_request("eth_sendRawTransaction", vec![json!("0x")], json!(1));
        let resp = s.handle(&req);
        let hash = resp.result.unwrap().as_str().unwrap().to_string();
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn eth_fee_history_returns_minimal() {
        let (s, _evm) = make_evm_server();
        let req = make_request("eth_feeHistory", vec![json!("0x1"), json!("latest")], json!(1));
        let resp = s.handle(&req);
        let result = resp.result.unwrap();
        assert!(result["baseFeePerGas"].is_array());
    }

    #[test]
    fn eth_mining_returns_false() {
        let s = make_server();
        let req = make_request("eth_mining", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!(false)));
    }

    #[test]
    fn eth_syncing_returns_false() {
        let s = make_server();
        let req = make_request("eth_syncing", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!(false)));
    }

    #[test]
    fn eth_accounts_returns_empty() {
        let s = make_server();
        let req = make_request("eth_accounts", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!([])));
    }

    #[test]
    fn eth_get_logs_returns_empty() {
        let (s, _evm) = make_evm_server();
        let req = make_request(
            "eth_getLogs",
            vec![json!({"fromBlock": "0x0", "toBlock": "latest"})],
            json!(1),
        );
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!([])));
    }

    #[test]
    fn net_listening_returns_true() {
        let s = make_server();
        let req = make_request("net_listening", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!(true)));
    }

    // ---- eth_sendRawTransaction with TxSubmitter -------------------

    /// A mock submitter that records every submitted envelope and can
    /// be configured to reject.
    struct MockSubmitter {
        submissions: std::sync::Mutex<Vec<TxBytes>>,
        reject_next: std::sync::Mutex<bool>,
    }

    impl MockSubmitter {
        fn new() -> Self {
            Self {
                submissions: std::sync::Mutex::new(Vec::new()),
                reject_next: std::sync::Mutex::new(false),
            }
        }

        fn count(&self) -> usize {
            self.submissions.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
        }

        fn last(&self) -> TxBytes {
            self.submissions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .last()
                .cloned()
                .unwrap_or_default()
        }
    }

    impl TxSubmitter for MockSubmitter {
        fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
            if *self.reject_next.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
                return Err("mock rejection".to_string());
            }
            self.submissions.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(tx);
            Ok(())
        }
    }

    /// Without a submitter, the RPC returns the hash but does not
    /// submit anything (Phase 2 v0 behaviour).
    #[test]
    fn eth_send_raw_transaction_without_submitter_returns_hash_only() {
        let s = make_server();
        // Empty tx → keccak256("") = 0xc5d2...
        let req = make_request("eth_sendRawTransaction", vec![json!("0x")], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_none(), "expected success without submitter");
        let hash = resp.result.unwrap().as_str().unwrap().to_string();
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66);
    }

    /// With a submitter, a malformed raw tx (not valid RLP) is rejected
    /// with an invalid-params error and nothing is submitted.
    #[test]
    fn eth_send_raw_transaction_with_submitter_rejects_invalid_rlp() {
        let mut s = make_server();
        let submitter = Arc::new(MockSubmitter::new());
        s.set_tx_submitter(submitter.clone());

        // "0x" decodes to empty bytes, which is not a valid signed tx.
        let req = make_request("eth_sendRawTransaction", vec![json!("0x")], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_some(), "expected error for invalid RLP");
        assert_eq!(resp.error.unwrap().code, -32602, "expected invalid-params code");
        assert_eq!(submitter.count(), 0, "nothing should be submitted on decode failure");
    }

    /// A valid signed EVM transaction is decoded, wrapped in the
    /// Oxide envelope, and submitted to the mempool. The returned
    /// hash matches the canonical Ethereum tx hash (keccak256 of the
    /// raw RLP).
    #[test]
    fn eth_send_raw_transaction_with_submitter_submits_envelope() {
        use evm::tx::{SignedTx, TxEip1559, TxFields, TxKind};
        use revm::primitives::{Address, Bytes, U256};

        let mut s = make_server();
        let submitter = Arc::new(MockSubmitter::new());
        s.set_tx_submitter(submitter.clone());

        // Build and sign a minimal EIP-1559 transaction.
        let privkey = [0x01u8; 32];
        let tx = TxEip1559 {
            fields: TxFields {
                nonce: 0,
                gas_limit: 21_000,
                to: TxKind::Call(Address::from([0x42; 20])),
                value: U256::ZERO,
                data: Bytes::new(),
                chain_id: 1,
            },
            max_fee_per_gas: U256::from(10_000_000_000u64),
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            access_list: Vec::new(),
        };
        let signed = SignedTx::sign_eip1559(tx, &privkey).expect("signing must succeed");
        let raw = signed.encode_to_bytes();
        let expected_hash = signed.hash();

        let req = make_request(
            "eth_sendRawTransaction",
            vec![json!(format!("0x{}", hex::encode(&raw)))],
            json!(1),
        );
        let resp = s.handle(&req);
        assert!(resp.error.is_none(), "expected success, got {:?}", resp.error);
        let returned_hash = resp.result.unwrap().as_str().unwrap().to_string();
        assert_eq!(
            returned_hash,
            format!("0x{}", hex::encode(expected_hash)),
            "returned hash must match canonical Ethereum tx hash"
        );

        // The submitter received exactly one envelope.
        assert_eq!(submitter.count(), 1, "exactly one tx should be submitted");
        let envelope = submitter.last();
        let bytes = envelope.as_bytes();

        // The Oxide envelope is: sender(20) + nonce(8) + fee(8) +
        // module_id(1) + rlp_signed_tx. Verify the structure.
        assert!(bytes.len() > 37, "envelope must be longer than the header");
        // Module ID byte is at offset 36 (20 + 8 + 8).
        assert_eq!(bytes[36], evm::MODULE_ID, "module ID must be EVM");
        // The RLP payload starts at offset 37.
        let rlp_payload = &bytes[37..];
        assert_eq!(rlp_payload, raw.as_slice(), "RLP payload must match the raw tx");
    }

    /// When the submitter rejects (e.g. mempool full), the RPC returns
    /// a transaction-rejected error.
    #[test]
    fn eth_send_raw_transaction_with_submitter_propagates_rejection() {
        use evm::tx::{SignedTx, TxEip1559, TxFields, TxKind};
        use revm::primitives::{Address, Bytes, U256};

        let mut s = make_server();
        let submitter = Arc::new(MockSubmitter::new());
        *submitter.reject_next.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        s.set_tx_submitter(submitter.clone());

        let privkey = [0x02u8; 32];
        let tx = TxEip1559 {
            fields: TxFields {
                nonce: 5,
                gas_limit: 50_000,
                to: TxKind::Call(Address::from([0x99; 20])),
                value: U256::from(1_000_000_000u64),
                data: Bytes::new(),
                chain_id: 1,
            },
            max_fee_per_gas: U256::from(20_000_000_000u64),
            max_priority_fee_per_gas: U256::from(2_000_000_000u64),
            access_list: Vec::new(),
        };
        let signed = SignedTx::sign_eip1559(tx, &privkey).expect("signing must succeed");
        let raw = signed.encode_to_bytes();

        let req = make_request(
            "eth_sendRawTransaction",
            vec![json!(format!("0x{}", hex::encode(&raw)))],
            json!(1),
        );
        let resp = s.handle(&req);
        let err = resp.error.expect("expected rejection error");
        assert_eq!(err.code, -32_000, "expected transaction-rejected code");
        assert!(err.message.contains("mock rejection"), "error must carry the rejection reason");
    }
}
