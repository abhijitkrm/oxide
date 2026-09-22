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

use alloy_primitives::{Address, B256, U256};
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

/// One exported snapshot instance kept for chunk serving: the
/// encoded blob plus the manifest describing its chunks.
struct CachedSnapshot {
    /// Codec-encoded `ExecutorSnapshot` bytes — chunks are byte
    /// slices of this blob (`[i*chunk_size .. min((i+1)*cs, len)]`).
    blob: Vec<u8>,
    /// The chunk-hash manifest for `blob`.
    manifest: statesync::Manifest,
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

    /// Metadata of the snapshot `export_snapshot` would produce:
    /// `(height, state_root, format_version)`. The manifest
    /// endpoint needs these values without decoding the blob —
    /// the implementor returns them straight from its typed
    /// snapshot (`ExecutorSnapshot`'s fields).
    ///
    /// # Errors
    ///
    /// Same conditions as [`export_snapshot`](Self::export_snapshot).
    fn snapshot_meta(&self) -> Result<(u64, primitives::Hash, u32), String>;
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

/// One pooled transaction as the `txpool_*` methods report it.
///
/// The tuple mirrors `Mempool::txpool_snapshot`'s element shape:
/// the Oxide-envelope sender, the envelope nonce, the raw envelope
/// bytes (sender/nonce/fee header + module payload), and whether
/// the transaction sits in the sender's contiguous-nonce run
/// (*pending*, executable next block) or behind a nonce gap
/// (*queued*).
#[derive(Debug)]
pub struct TxpoolItem {
    /// The Oxide-envelope sender (20 bytes).
    pub sender: primitives::Address,
    /// The envelope nonce.
    pub nonce: u64,
    /// The raw wrapped-envelope bytes.
    pub envelope: TxBytes,
    /// `true` when the tx is in the executable contiguous-nonce run;
    /// `false` when it sits behind a nonce gap.
    pub pending: bool,
}

/// Read-only transaction-pool introspection for the `txpool_*`
/// namespace.
///
/// Implemented by the node's executor handle — the adapter calls
/// `Executor::txpool_snapshot`, which takes the mempool lock once
/// and clones the pooled bytes. This is a cold-path query: the RPC
/// layer holds no lock across the whole snapshot and never touches
/// the block path.
pub trait TxpoolProvider: Send + Sync {
    /// Snapshot the pool into pending/queued items. See
    /// [`TxpoolItem`] for the shape.
    fn txpool_snapshot(&self) -> Vec<TxpoolItem>;
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
    /// Notify with the Ethereum tx hash of each transaction that
    /// enters this node's mempool (local `eth_sendRawTransaction`
    /// or gossiped). geth also offers a `fullTx` variant — we only
    /// push the hash (hash is what wallet/provider polling needs).
    PendingTx,
}

impl SubscriptionType {
    /// Parse a subscription type from a JSON-RPC params string.
    ///
    /// Returns `None` for unknown subscription types.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "newHeads" => Some(Self::NewHeads),
            "logs" => Some(Self::Logs),
            "newPendingTransactions" => Some(Self::PendingTx),
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
        primitives::sync::lock_state(&self.active)
            .insert(id.clone(), ActiveSubscription { conn_id, kind, filter, sink });
        id
    }

    /// Cancel a subscription by ID. Returns `true` if it existed
    /// (geth returns `false` — not an error — for unknown IDs).
    fn unregister(&self, id: &str) -> bool {
        primitives::sync::lock_state(&self.active).remove(id).is_some()
    }

    /// Remove every subscription owned by a closed connection.
    fn drop_connection(&self, conn_id: u64) {
        primitives::sync::lock_state(&self.active).retain(|_, sub| sub.conn_id != conn_id);
    }

    /// Cheap gate so the per-block publish path exits without
    /// touching the EVM history lock when nobody is subscribed.
    fn has_subscriptions(&self) -> bool {
        !primitives::sync::lock_state(&self.active).is_empty()
    }

    /// Fan out a finalized block to all subscribers: the header to
    /// `newHeads` subs, each matching log to `logs` subs.
    fn publish(&self, header: &Value, logs: &[evm::history::LogMatch]) {
        self.for_each_sub(|sub, send| match sub.kind {
            SubscriptionType::NewHeads => send(header.clone()),
            SubscriptionType::Logs => {
                for log in logs {
                    if sub.filter.as_ref().is_none_or(|f| f.matches(log)) {
                        send(log_json(log));
                    }
                }
            }
            SubscriptionType::PendingTx => {}
        });
    }

    /// Push a newly arrived mempool transaction hash to
    /// `newPendingTransactions` subscribers.
    fn publish_pending_tx(&self, hash: B256) {
        let result = json!(format!("0x{hash:x}"));
        self.for_each_sub(|sub, send| {
            if sub.kind == SubscriptionType::PendingTx {
                send(result.clone());
            }
        });
    }

    /// Walk the subscription table invoking `f` with each active
    /// subscription and a `send` closure that pushes a notification
    /// to its connection. A dead sink (connection closed but not
    /// yet reaped) fails `send` and the subscription is removed so
    /// we don't retry it on the next event.
    fn for_each_sub(&self, mut f: impl FnMut(&ActiveSubscription, &mut dyn FnMut(Value))) {
        let mut dead = Vec::new();
        {
            let active = primitives::sync::lock_state(&self.active);
            for (id, sub) in active.iter() {
                let mut failed = false;
                let mut send = |result: Value| {
                    if failed {
                        return;
                    }
                    if sub
                        .sink
                        .send(
                            serde_json::to_string(&SubscriptionNotification {
                                jsonrpc: "2.0".to_string(),
                                method: "eth_subscription".to_string(),
                                params: SubscriptionParams { subscription: id.clone(), result },
                            })
                            .unwrap_or_else(|_| "{}".to_string()),
                        )
                        .is_err()
                    {
                        failed = true;
                    }
                };
                f(sub, &mut send);
                if failed {
                    dead.push(id.clone());
                }
            }
        }
        if !dead.is_empty() {
            let mut active = primitives::sync::lock_state(&self.active);
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
#[derive(Clone)]
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

/// How long a pollable filter may sit unpolluted before it is
/// reaped — geth's `filterLogTimeout` default (5 minutes). The
/// sweep is lazy: entries are dropped when next accessed, plus a
/// full sweep on each registration so a client creating filters
/// without polling can't grow the map unboundedly.
const FILTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Maximum concurrently-registered pollable filters — the
/// `filter-cap` role (cosmos-evm defaults to 200). The TTL sweep
/// bounds *time*; this bounds *count*: without it a client that
/// registers-and-abandons faster than the 300 s reap can still
/// grow the map without limit. 1,024 is generous for real
/// workloads (a live client polls within the TTL and needs only a
/// handful of filters) while still capping memory at
/// `1024 × size_of::<FilterEntry>` ≈ tens of KB.
const MAX_FILTERS: usize = 1024;

/// A pollable filter's kind and per-kind cursor.
#[derive(Debug)]
enum FilterKind {
    /// `eth_newFilter`: the parsed `eth_getLogs`-shaped filter plus
    /// the height last served by `eth_getFilterChanges` — each poll
    /// returns matching logs in `(last_served, latest]`.
    Log { filter: LogFilter, last_served: u64 },
    /// `eth_newBlockFilter`: `eth_getFilterChanges` returns the
    /// hashes of blocks in `(last_served, latest]`.
    Block { last_served: u64 },
    /// `eth_newPendingTransactionFilter`: a sequence cursor into
    /// the pending ring — each poll returns hashes appended since.
    PendingTx { next_seq: u64 },
}

/// A registered pollable filter.
#[derive(Debug)]
struct FilterEntry {
    /// What the filter watches and its per-kind cursor.
    kind: FilterKind,
    /// When the filter was last polled (or created). Entries older
    /// than [`FILTER_TIMEOUT`] are reaped — geth's liveness rule:
    /// clients must poll to keep a filter alive.
    last_poll: std::time::Instant,
}

/// The pending-tx feed: a bounded ring of `(seq, eth_tx_hash)` for
/// every transaction that entered this node's mempool via
/// `eth_sendRawTransaction` or tx gossip.
///
/// `newPendingTransactions` subscribers get each hash pushed live;
/// `eth_newPendingTransactionFilter` polls drain the ring by seq.
/// The cap bounds memory when a filter stops polling — hashes older
/// than the cap are simply missed, matching geth's "only what the
/// feed carried" semantics.
const PENDING_RING_CAP: usize = 1024;

/// Ring state: monotonically increasing sequence and the retained
/// `(seq, hash)` window.
#[derive(Debug, Default)]
struct PendingRing {
    /// Sequence number that will be assigned to the next appended
    /// hash. A new pending filter starts here — only future txs are
    /// seen.
    next_seq: u64,
    /// Retained `(seq, hash)` entries, oldest first.
    entries: std::collections::VecDeque<(u64, B256)>,
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
    /// Optional read-only mempool handle for the `txpool_*`
    /// namespace. When `None`, the namespace returns a
    /// method-not-found-style error (not silently empty results — an
    /// unbacked `txpool_status` that claims the pool is empty is a
    /// lie a debugger would trust).
    txpool: Option<Arc<dyn TxpoolProvider>>,
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
    /// The most recent chunked snapshot export — the blob the
    /// `/snapshot/chunk/{i}` handlers slice and the manifest that
    /// describes it. Populated lazily by the first manifest or
    /// chunk request; a manifest request re-exports so the served
    /// manifest always describes the latest finalized state.
    /// Single-slot by design: a second sync's manifest call
    /// replaces the blob, which the first client detects as a
    /// chunk-hash mismatch and retries — integrity is guaranteed
    /// by the hash manifest regardless of interleaving.
    snapshot_cache: std::sync::Mutex<Option<CachedSnapshot>>,
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
    /// Pollable filters created by `eth_newFilter`,
    /// `eth_newBlockFilter`, and `eth_newPendingTransactionFilter`.
    filters: std::sync::Mutex<HashMap<String, FilterEntry>>,
    /// The next pollable filter ID to assign.
    next_filter_id: AtomicU64,
    /// The pending-tx ring feeding `newPendingTransactions` subs and
    /// `eth_newPendingTransactionFilter` polls.
    pending_txs: std::sync::Mutex<PendingRing>,
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
            txpool: None,
            recorder: None,
            tx_count: AtomicU64::new(0),
            mempool_size: AtomicU64::new(0),
            max_requests_per_second: 0, // unlimited by default
            rate_window_start_ms: AtomicU64::new(0),
            rate_window_count: AtomicU64::new(0),
            snapshot_provider: None,
            snapshot_cache: std::sync::Mutex::new(None),
            validator_set_provider: None,
            evm: None,
            filters: std::sync::Mutex::new(HashMap::new()),
            next_filter_id: AtomicU64::new(1),
            pending_txs: std::sync::Mutex::new(PendingRing::default()),
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

    /// Attach a read-only mempool handle so the `txpool_*` namespace
    /// reports the real pending/queued split.
    ///
    /// Without this call the namespace errors — an unbacked
    /// `txpool_status` claiming the pool is empty would mislead
    /// tooling that trusts the counts.
    pub fn set_txpool_provider(&mut self, provider: Arc<dyn TxpoolProvider>) {
        self.txpool = Some(provider);
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

    /// Export-or-load the cached chunked snapshot. `refresh`
    /// re-exports (the manifest endpoint wants the freshest state);
    /// chunk serving accepts whatever is cached.
    fn cached_snapshot(
        &self,
        refresh: bool,
    ) -> Result<std::sync::MutexGuard<'_, Option<CachedSnapshot>>, String> {
        let mut guard = primitives::sync::lock_state(&self.snapshot_cache);
        if refresh || guard.is_none() {
            let provider = self
                .snapshot_provider
                .as_ref()
                .ok_or_else(|| "snapshot provider not configured".to_string())?;
            let blob = provider.export_snapshot()?;
            let (height, state_root, format_version) = provider.snapshot_meta()?;
            let (manifest, _) = statesync::chunk_blob(
                height,
                state_root,
                format_version,
                &blob,
                statesync::DEFAULT_CHUNK_SIZE,
            );
            *guard = Some(CachedSnapshot { blob, manifest });
        }
        Ok(guard)
    }

    /// The codec-encoded sync manifest for the latest snapshot
    /// (`GET /snapshot/manifest` body before hex-encoding).
    ///
    /// # Errors
    ///
    /// Propagates the provider's export/meta errors; `Err` also
    /// when no provider is configured.
    ///
    /// # Panics
    ///
    /// Panics if the cache mutex is poisoned or the populate step
    /// left the slot empty (invariant: `cached_snapshot` only
    /// returns `Ok` after writing `Some`).
    pub fn snapshot_manifest(&self) -> Result<Vec<u8>, String> {
        let guard = self.cached_snapshot(true)?;
        let cached = guard.as_ref().expect("populated by cached_snapshot");
        let mut buf = Vec::new();
        codec::Encode::encode(&cached.manifest, &mut buf);
        Ok(buf)
    }

    /// Chunk `index` of the cached snapshot blob
    /// (`GET /snapshot/chunk/{index}` body before hex-encoding).
    ///
    /// # Errors
    ///
    /// `Err` when no provider is configured or `index` is out of
    /// range — the client should re-fetch the manifest (the cached
    /// snapshot may have been replaced by a newer export).
    ///
    /// # Panics
    ///
    /// Same invariants as [`snapshot_manifest`](Self::snapshot_manifest).
    pub fn snapshot_chunk(&self, index: usize) -> Result<Vec<u8>, String> {
        let guard = self.cached_snapshot(false)?;
        let cached = guard.as_ref().expect("populated by cached_snapshot");
        let cs = cached.manifest.chunk_size as usize;
        let start = index.checked_mul(cs).ok_or_else(|| "chunk index out of range".to_string())?;
        if index >= cached.manifest.chunk_count() || start >= cached.blob.len() {
            return Err("chunk index out of range".to_string());
        }
        let end = (start + cs).min(cached.blob.len());
        Ok(cached.blob[start..end].to_vec())
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
            "eth_getProof" => self.eth_get_proof(&request.params),
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
            "oxide_sendRawTransaction" => self.oxide_send_raw_transaction(&request.params),
            // ---- Call / estimate ----
            "eth_call" => self.eth_call(&request.params),
            "eth_estimateGas" => self.eth_estimate_gas(&request.params),
            "eth_createAccessList" => self.eth_create_access_list(&request.params),
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
            // ---- Pollable filters ----
            "eth_newFilter" => self.eth_new_filter(&request.params),
            "eth_newBlockFilter" => self.eth_new_block_filter(),
            "eth_newPendingTransactionFilter" => self.eth_new_pending_transaction_filter(),
            "eth_getFilterChanges" => self.eth_get_filter_changes(&request.params),
            "eth_getFilterLogs" => self.eth_get_filter_logs(&request.params),
            "eth_uninstallFilter" => self.eth_uninstall_filter(&request.params),
            // ---- Transaction pool ----
            "eth_pendingTransactions" => self.eth_pending_transactions(),
            "txpool_status" => self.txpool_status(),
            "txpool_content" => self.txpool_content(),
            "txpool_contentFrom" => self.txpool_content_from(&request.params),
            "txpool_inspect" => self.txpool_inspect(),
            // ---- Debug / tracing ----
            "debug_traceTransaction" => self.debug_trace_transaction(&request.params),
            "debug_traceCall" => self.debug_trace_call(&request.params),
            "debug_traceBlockByNumber" => self.debug_trace_block_by_number(&request.params),
            "debug_traceBlockByHash" => self.debug_trace_block_by_hash(&request.params),
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
        self.dispatch_raw(raw, None)
    }

    /// Handle a raw JSON-RPC string arriving on a WebSocket
    /// connection. Identical to [`handle_raw`](Self::handle_raw)
    /// except `eth_subscribe` registers against `conn`'s sink.
    pub(crate) fn handle_ws_raw(&self, raw: &str, conn: &WsConn) -> String {
        self.dispatch_raw(raw, Some(conn))
    }

    /// Parse a raw request body — a single request object or a
    /// JSON-RPC 2.0 batch array — and dispatch it.
    ///
    /// Batch semantics follow geth/reth: each element produces one
    /// response in order; a body that isn't valid JSON is a `-32700`
    /// parse error; an empty array is a `-32600` Invalid Request;
    /// and a batch larger than [`MAX_BATCH_REQUESTS`] is rejected as
    /// a whole with a `-32005` limit error (reth's shape) rather than
    /// partially processed — an oversized batch is a resource attack,
    /// not a request to honor.
    fn dispatch_raw(&self, raw: &str, conn: Option<&WsConn>) -> String {
        let Ok(body): Result<Value, _> = serde_json::from_str(raw) else {
            let response = RpcResponse {
                id: Value::Null,
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(RpcError::parse_error()),
            };
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        };
        let response = self.handle_value(&body, conn);
        serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
    }

    /// Dispatch a parsed request body (single object or batch array)
    /// to a response [`Value`].
    fn handle_value(&self, body: &Value, conn: Option<&WsConn>) -> Value {
        match body {
            Value::Array(elements) => {
                if elements.is_empty() {
                    // JSON-RPC 2.0: an empty batch is itself an
                    // Invalid Request, not an empty response.
                    return serde_json::to_value(RpcResponse {
                        id: Value::Null,
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(RpcError {
                            code: -32_600,
                            message: "Invalid Request".to_string(),
                            data: None,
                        }),
                    })
                    .unwrap_or_default();
                }
                if elements.len() > MAX_BATCH_REQUESTS {
                    return serde_json::to_value(RpcResponse {
                        id: Value::Null,
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(RpcError {
                            code: -32_005,
                            message: format!(
                                "batch request count {} exceeds limit {MAX_BATCH_REQUESTS}",
                                elements.len()
                            ),
                            data: None,
                        }),
                    })
                    .unwrap_or_default();
                }
                Value::Array(elements.iter().map(|e| self.handle_element(e, conn)).collect())
            }
            _ => self.handle_element(body, conn),
        }
    }

    /// Dispatch one parsed element: deserialize as [`RpcRequest`] and
    /// run the method, or answer with a `-32600` Invalid Request when
    /// the element is not a request object (JSON-RPC 2.0 convention —
    /// `-32700` is reserved for unparseable bodies, not malformed
    /// elements).
    fn handle_element(&self, element: &Value, conn: Option<&WsConn>) -> Value {
        match serde_json::from_value::<RpcRequest>(element.clone()) {
            Ok(request) => {
                let response = match conn {
                    Some(c) => self.handle_ws(&request, c),
                    None => self.handle(&request),
                };
                serde_json::to_value(response).unwrap_or_default()
            }
            Err(_) => serde_json::to_value(RpcResponse {
                // Preserve the element's `id` when present so the
                // client can correlate the failure.
                id: element.get("id").cloned().unwrap_or(Value::Null),
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(RpcError {
                    code: -32_600,
                    message: "Invalid Request".to_string(),
                    data: None,
                }),
            })
            .unwrap_or_default(),
        }
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

    /// `eth_gasPrice` — the oracle-suggested gas price: latest
    /// sealed block's base fee plus the sampled priority tip —
    /// geth's `SuggestGasPrice` = `suggestTip + head.BaseFee`.
    /// Without an attached EVM (stateless serving) the configured
    /// base fee is the honest fallback.
    fn eth_gas_price(&self) -> Value {
        let price = self.evm.as_deref().map_or(u128::from(self.base_fee), |evm| {
            u128::from(evm.latest_base_fee()).saturating_add(evm.suggest_gas_tip())
        });
        json!(format!("0x{price:x}"))
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
    /// Heights within the retained undo window are served from the
    /// versioned overlay; older tags return geth's "missing trie
    /// node" error.
    fn eth_get_balance(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        evm.balance_at(&addr, h).map(hex_quantity_u128).map_err(state_error)
    }

    /// `eth_getTransactionCount` — returns an account's nonce as a
    /// hex string.
    ///
    /// Params: `[address: String, block: String?]`
    fn eth_get_transaction_count(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        evm.nonce_at(&addr, h).map(|n| json!(format!("0x{n:x}"))).map_err(state_error)
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

    // ---- Pollable filters (`eth_newFilter` family) ----

    /// Register a pollable filter and return its hex ID. Reaps any
    /// expired filters first so the map can't grow on
    /// register-and-abandon clients.
    ///
    /// # Errors
    ///
    /// `-32000 "filter limit reached"` once [`MAX_FILTERS`] live
    /// filters are registered — the `filter-cap` guard.
    fn register_filter(&self, kind: FilterKind) -> Result<String, RpcError> {
        let mut filters = primitives::sync::lock_state(&self.filters);
        let now = std::time::Instant::now();
        filters.retain(|_, e| now.duration_since(e.last_poll) < FILTER_TIMEOUT);
        if filters.len() >= MAX_FILTERS {
            return Err(RpcError {
                code: -32000,
                message: format!("filter limit reached (max {MAX_FILTERS})"),
                data: None,
            });
        }
        let id = format!("0x{:x}", self.next_filter_id.fetch_add(1, Ordering::Relaxed));
        filters.insert(id.clone(), FilterEntry { kind, last_poll: now });
        Ok(id)
    }

    /// `eth_newFilter` — create a pollable log filter.
    ///
    /// Params: `[filter: Object]` — the same `eth_getLogs` shape.
    /// `eth_getFilterChanges` then returns matching logs in
    /// `(last_served, latest]` per poll (geth semantics).
    fn eth_new_filter(&self, params: &[Value]) -> Result<Value, RpcError> {
        let obj = params.first().ok_or_else(|| RpcError::invalid_params("missing filter"))?;
        let filter = self.parse_log_filter(obj)?;
        self.require_evm()?;
        let latest = self.latest_sealed_height();
        Ok(json!(self.register_filter(FilterKind::Log { filter, last_served: latest })?))
    }

    /// `eth_newBlockFilter` — create a pollable block filter.
    /// Each `eth_getFilterChanges` poll returns the hashes of blocks
    /// finalized since the last poll.
    fn eth_new_block_filter(&self) -> Result<Value, RpcError> {
        self.require_evm()?;
        let latest = self.latest_sealed_height();
        Ok(json!(self.register_filter(FilterKind::Block { last_served: latest })?))
    }

    /// `eth_newPendingTransactionFilter` — create a pollable
    /// pending-tx filter. Each `eth_getFilterChanges` poll returns
    /// the hashes of txs that entered the mempool since the last
    /// poll.
    ///
    fn eth_new_pending_transaction_filter(&self) -> Result<Value, RpcError> {
        let next_seq = primitives::sync::lock_state(&self.pending_txs).next_seq;
        Ok(json!(self.register_filter(FilterKind::PendingTx { next_seq })?))
    }

    /// `eth_uninstallFilter` — drop a pollable filter. Returns
    /// `true` if it existed (geth returns `false` for unknown IDs).
    fn eth_uninstall_filter(&self, params: &[Value]) -> Result<Value, RpcError> {
        let id = parse_filter_id(params.first())?;
        let removed = primitives::sync::lock_state(&self.filters).remove(&id).is_some();
        Ok(json!(removed))
    }

    // ---- Transaction pool ----

    /// Require the txpool provider or return the unbacked-namespace
    /// error — an unbacked `txpool_*` that answers as if the pool
    /// were empty is worse than an error.
    fn require_txpool(&self) -> Result<&dyn TxpoolProvider, RpcError> {
        self.txpool.as_deref().ok_or_else(|| RpcError {
            code: -32_000,
            message: "txpool namespace not enabled on this node".to_string(),
            data: None,
        })
    }

    /// `txpool_status` — `{pending, queued}` counts of pooled
    /// transactions (hex-encoded, per geth).
    fn txpool_status(&self) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        let (mut pending, mut queued) = (0u64, 0u64);
        for item in pool.txpool_snapshot() {
            if item.pending {
                pending += 1;
            } else {
                queued += 1;
            }
        }
        Ok(json!({
            "pending": format!("0x{pending:x}"),
            "queued": format!("0x{queued:x}"),
        }))
    }

    /// `txpool_content` — `{pending: {addr: {nonce: tx}}, queued: …}`
    /// with full pending-transaction objects (geth shape: positional
    /// block fields are `null` for pooled txs).
    fn txpool_content(&self) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        Ok(txpool_content_json(&pool.txpool_snapshot(), None))
    }

    /// `txpool_contentFrom` — like `txpool_content` but restricted to
    /// one sender address (geth extension used by block explorers).
    fn txpool_content_from(&self, params: &[Value]) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        let addr = params
            .first()
            .and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("0x").map(str::to_owned).or_else(|| Some(s.to_owned())))
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| <[u8; 20]>::try_from(b.as_slice()).ok())
            .map(primitives::Address)
            .ok_or_else(|| RpcError {
                code: -32_602,
                message: "invalid address parameter".to_string(),
                data: None,
            })?;
        Ok(txpool_content_json(&pool.txpool_snapshot(), Some(addr)))
    }

    /// `eth_pendingTransactions` — a flat array of the pool's
    /// *pending* (executable) transactions as full tx objects
    /// (`blockHash`/`blockNumber`/`transactionIndex` null — geth's
    /// shape for unmined txs). Queued txs behind nonce gaps are
    /// excluded, matching geth's pending-set definition.
    fn eth_pending_transactions(&self) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        let txs: Vec<Value> =
            pool.txpool_snapshot().iter().filter(|item| item.pending).map(pooled_tx_json).collect();
        Ok(json!(txs))
    }

    /// `txpool_inspect` — same grouping as `txpool_content` but each
    /// leaf is geth's summary string `"to: value wei + gas × price"`.
    fn txpool_inspect(&self) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        let mut pending = serde_json::Map::new();
        let mut queued = serde_json::Map::new();
        for item in pool.txpool_snapshot() {
            let addr = format!("0x{}", hex::encode(item.sender.0));
            let bucket = if item.pending { &mut pending } else { &mut queued };
            let entry = bucket.entry(addr).or_insert_with(|| json!({}));
            if let Some(m) = entry.as_object_mut() {
                m.insert(format!("0x{:x}", item.nonce), txpool_inspect_summary(&item));
            }
        }
        Ok(json!({ "pending": pending, "queued": queued }))
    }

    // ---- Debug / tracing ----

    /// `debug_traceTransaction` — the recorded call tree for a
    /// sealed transaction.
    ///
    /// Traces are captured at execution time (see `evm::trace`):
    /// there is no archive state to re-execute against, so this is a
    /// history lookup bounded by the same retention window as every
    /// other history query. A hash outside the window returns the
    /// geth-style "transaction not found" error; a missing trace
    /// (impossible for an executed tx) returns a server error rather
    /// than fabricated output.
    ///
    /// Options: `{"tracer": "callTracer"}` is the only supported
    /// tracer — the struct-logger (`{structLogs}`) output geth
    /// produces by default is not recorded (per-step tracing is too
    /// expensive to run on every committed tx). An absent `tracer`
    /// therefore returns the callTracer shape — a documented
    /// deviation from geth; a named-but-unsupported tracer is a
    /// `-32602` error rather than a silently wrong shape.
    fn debug_trace_transaction(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash = params
            .first()
            .map(parse_b256)
            .transpose()?
            .ok_or_else(|| RpcError::invalid_params("missing tx hash"))?;
        parse_trace_options(params.get(1))?;
        let evm = self.require_evm()?;
        let history = evm.history();
        let Some((height, tx_index)) = history.tx_location(&hash) else {
            return Err(RpcError {
                code: -32_000,
                message: "transaction not found (or evicted from the history window)".to_string(),
                data: None,
            });
        };
        let Some(block) = history.block(height) else {
            return Err(RpcError {
                code: -32_000,
                message: "block evicted from history window".to_string(),
                data: None,
            });
        };
        let idx = tx_index as usize;
        let Some(Some(frame)) = block.traces.get(idx) else {
            return Err(RpcError {
                code: -32_000,
                message: "no call trace recorded for this transaction".to_string(),
                data: None,
            });
        };
        // Root-frame `gas`/`gasUsed` are tx-level in geth's
        // callTracer (the recorder reports frame-scoped values —
        // patch with the tx gas limit and the receipt's total gas
        // used, which includes the intrinsic cost).
        let tx = &block.txs[idx];
        let receipt = &block.receipts[idx];
        Ok(call_frame_json(frame, Some((tx.gas_limit, receipt.gas_used))))
    }

    /// `debug_traceCall` — simulate a call against latest state and
    /// return its call tree. Always servable: it executes fresh
    /// rather than needing recorded history.
    fn debug_trace_call(&self, params: &[Value]) -> Result<Value, RpcError> {
        let mut req = parse_call_object(params.first().ok_or_else(|| RpcError {
            code: -32_602,
            message: "missing call object".to_string(),
            data: None,
        })?)?;
        // Optional block tag — historical heights within the
        // retained undo window are servable.
        let h = self.resolve_block_ref(params.get(1))?;
        let ovr = parse_trace_options(params.get(2))?;
        // Same gas-cap clamp as `eth_call` — an unbounded simulation
        // is a resource-exhaustion vector.
        if req.gas.is_some_and(|g| g > types::CHAIN_BLOCK_GAS_LIMIT) {
            req.gas = Some(types::CHAIN_BLOCK_GAS_LIMIT);
        }
        let evm = self.require_evm()?;
        let gas_cap = req.gas.unwrap_or(evm.block_gas_limit());
        // Revert/halt is a *trace result*, not an RPC error — geth
        // returns the call tree with the frame's `error` set.
        let (gas_used, frame) =
            evm.call_read_traced_with_overrides(&req, Some(h), &ovr).map_err(call_error)?;
        let Some(frame) = frame else {
            return Err(RpcError {
                code: -32_000,
                message: "call produced no trace".to_string(),
                data: None,
            });
        };
        Ok(call_frame_json(&frame, Some((gas_cap, gas_used))))
    }

    /// `debug_traceBlockByNumber` — per-tx call trees for a sealed
    /// block, `[{txHash, result}]` in block order (geth shape).
    fn debug_trace_block_by_number(&self, params: &[Value]) -> Result<Value, RpcError> {
        parse_trace_options(params.get(1))?;
        let height = self.resolve_block_ref(params.first())?;
        self.trace_block_at(height)
    }

    /// `debug_traceBlockByHash` — same body keyed by block hash.
    fn debug_trace_block_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash = params
            .first()
            .map(parse_b256)
            .transpose()?
            .ok_or_else(|| RpcError::invalid_params("missing block hash"))?;
        parse_trace_options(params.get(1))?;
        let evm = self.require_evm()?;
        let history = evm.history();
        let Some(block) = history.block_by_hash(&hash) else {
            return Err(RpcError {
                code: -32_000,
                message: "block not found (or evicted from the history window)".to_string(),
                data: None,
            });
        };
        let number = block.number;
        drop(history);
        self.trace_block_at(number)
    }

    /// Shared per-block trace body for `debug_traceBlock*`.
    fn trace_block_at(&self, height: u64) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let history = evm.history();
        let Some(block) = history.block(height) else {
            return Err(RpcError {
                code: -32_000,
                message: "block not found (or evicted from the history window)".to_string(),
                data: None,
            });
        };
        let out: Vec<Value> = block
            .txs
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                let result = match block.traces.get(i) {
                    Some(Some(frame)) => {
                        call_frame_json(frame, Some((tx.gas_limit, block.receipts[i].gas_used)))
                    }
                    _ => Value::Null,
                };
                json!({ "txHash": format!("0x{:x}", tx.hash), "result": result })
            })
            .collect();
        Ok(Value::Array(out))
    }

    /// Fetch a filter by ID, refreshing its liveness timestamp.
    /// Expired or unknown IDs produce geth's `filter not found`
    /// error (-32000).
    fn take_filter(&self, id: &str) -> Result<FilterEntry, RpcError> {
        let mut filters = primitives::sync::lock_state(&self.filters);
        let not_found =
            || RpcError { code: -32_000, message: "filter not found".to_string(), data: None };
        let entry = filters.get_mut(id).ok_or_else(not_found)?;
        let now = std::time::Instant::now();
        if now.duration_since(entry.last_poll) >= FILTER_TIMEOUT {
            filters.remove(id);
            return Err(not_found());
        }
        entry.last_poll = now;
        // The caller mutates cursors through the entry; simplest
        // correct approach is to remove and let the caller re-insert
        // — but then a concurrent poll could see a missing filter.
        // Filters are per-client state and the lock is held for the
        // whole update, so take-and-reinsert under one lock hold is
        // equivalent; we take to keep ownership simple.
        Ok(filters.remove(id).expect("entry present"))
    }

    /// `eth_getFilterChanges` — poll a filter for new results.
    ///
    /// - Log filter → logs in `(last_served, latest]`
    /// - Block filter → block hashes in `(last_served, latest]`
    /// - `PendingTx` filter → mempool-arrival tx hashes since last poll
    fn eth_get_filter_changes(&self, params: &[Value]) -> Result<Value, RpcError> {
        let id = parse_filter_id(params.first())?;
        let mut entry = self.take_filter(&id)?;
        let latest = self.latest_sealed_height();
        let result = match &mut entry.kind {
            FilterKind::Log { filter, last_served } => {
                let changes = if latest > *last_served {
                    let delta = LogFilter {
                        from_block: *last_served + 1,
                        to_block: latest,
                        addresses: filter.addresses.clone(),
                        topics: filter.topics.clone(),
                        ..LogFilter::default()
                    };
                    let evm = self.require_evm()?;
                    let matches = evm.history().logs(&delta);
                    if matches.len() > MAX_LOG_RESULTS {
                        // Reinsert the filter before erroring so the
                        // poll cursor survives — the client can still
                        // narrow the filter via a new `eth_newFilter`.
                        *last_served = latest;
                        let result = Err(RpcError {
                            code: -32_005,
                            message: format!(
                                "query returned more than {MAX_LOG_RESULTS} results; \
                                 narrow the filter"
                            ),
                            data: None,
                        });
                        primitives::sync::lock_state(&self.filters).insert(id.clone(), entry);
                        return result;
                    }
                    matches.iter().map(log_json).collect()
                } else {
                    Vec::new()
                };
                *last_served = latest;
                Value::Array(changes)
            }
            FilterKind::Block { last_served } => {
                let mut hashes = Vec::new();
                if latest > *last_served {
                    let evm = self.require_evm()?;
                    let history = evm.history();
                    for h in (*last_served + 1)..=latest {
                        if let Some(block) = history.block(h) {
                            hashes.push(json!(format!("0x{:x}", block.hash)));
                        }
                    }
                }
                *last_served = latest;
                Value::Array(hashes)
            }
            FilterKind::PendingTx { next_seq } => {
                let ring = primitives::sync::lock_state(&self.pending_txs);
                let hashes: Vec<Value> = ring
                    .entries
                    .iter()
                    .filter(|(seq, _)| *seq >= *next_seq)
                    .map(|(_, hash)| json!(format!("0x{hash:x}")))
                    .collect();
                *next_seq = ring.next_seq;
                drop(ring);
                Value::Array(hashes)
            }
        };
        primitives::sync::lock_state(&self.filters).insert(id, entry);
        Ok(result)
    }

    /// `eth_getFilterLogs` — all logs matching a log filter's stored
    /// criteria (unlike `getFilterChanges`, this does not advance a
    /// cursor). Non-log filters and unknown IDs produce geth's
    /// `filter not found` error.
    fn eth_get_filter_logs(&self, params: &[Value]) -> Result<Value, RpcError> {
        let id = parse_filter_id(params.first())?;
        let entry = self.take_filter(&id)?;
        let not_found =
            || RpcError { code: -32_000, message: "filter not found".to_string(), data: None };
        let FilterKind::Log { filter, .. } = &entry.kind else {
            // Re-insert before erroring so a block/pending filter
            // survives an erroneous `getFilterLogs` call.
            primitives::sync::lock_state(&self.filters).insert(id, entry);
            return Err(not_found());
        };
        let evm = self.require_evm()?;
        let matches = evm.history().logs(filter);
        let result = if matches.len() > MAX_LOG_RESULTS {
            Err(RpcError {
                code: -32_005,
                message: format!(
                    "query returned more than {MAX_LOG_RESULTS} results; narrow the filter"
                ),
                data: None,
            })
        } else {
            Ok(Value::Array(matches.iter().map(log_json).collect()))
        };
        primitives::sync::lock_state(&self.filters).insert(id, entry);
        result
    }

    /// Record a transaction entering this node's mempool — feeds
    /// `newPendingTransactions` subscribers and pending-tx filters.
    /// `hash` is the Ethereum tx hash (keccak256 of the signed RLP),
    /// not the envelope hash.
    pub fn record_pending_tx(&self, hash: B256) {
        {
            let mut ring = primitives::sync::lock_state(&self.pending_txs);
            if ring.entries.len() >= PENDING_RING_CAP {
                ring.entries.pop_front();
            }
            let seq = ring.next_seq;
            ring.entries.push_back((seq, hash));
            ring.next_seq = seq.saturating_add(1);
        }
        self.subscriptions.publish_pending_tx(hash);
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
        let h = self.resolve_block_ref(params.get(1))?;
        evm.code_at(&addr, h).map(|c| json!(format!("0x{}", hex::encode(c)))).map_err(state_error)
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
        let h = self.resolve_block_ref(params.get(2))?;
        let value = evm.storage_at_height(&addr, &slot, h).map_err(state_error)?;
        Ok(json!(format!("0x{value:064x}")))
    }

    /// `eth_getProof` — EIP-1186 account + storage Merkle proofs.
    ///
    /// Params: `[address: String, storageKeys: String[], block: String?]`
    ///
    /// The proof is rebuilt from the state at the requested height
    /// via `HashBuilder` + `ProofRetainer` — `O(state)` per call, a
    /// cold-path archive query. Heights below the retained window
    /// return geth's `missing trie node` error.
    fn eth_get_proof(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let keys = params
            .get(1)
            .and_then(Value::as_array)
            .ok_or_else(|| RpcError::invalid_params("missing storage keys array"))?;
        let mut slots = Vec::with_capacity(keys.len());
        for k in keys {
            slots.push(parse_b256(k)?);
        }
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(2))?;
        let proof = evm.account_proof(&addr, &slots, h).map_err(call_error)?;
        Ok(json!({
            "address": format!("0x{}", hex::encode(proof.address.0)),
            "accountProof": proof
                .account_proof
                .iter()
                .map(|n| format!("0x{}", hex::encode(n)))
                .collect::<Vec<_>>(),
            "balance": format!("0x{:x}", proof.balance),
            "codeHash": format!("0x{}", hex::encode(proof.code_hash)),
            "nonce": format!("0x{:x}", proof.nonce),
            "storageHash": format!("0x{}", hex::encode(proof.storage_hash)),
            "storageProof": proof
                .storage_proofs
                .iter()
                .map(|sp| json!({
                    "key": format!("0x{}", hex::encode(sp.key)),
                    "value": format!("0x{:x}", sp.value),
                    "proof": sp
                        .proof
                        .iter()
                        .map(|n| format!("0x{}", hex::encode(n)))
                        .collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>(),
        }))
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
            // Feed pending-tx subscribers/filters — the tx is now
            // in this node's mempool.
            self.record_pending_tx(B256::from(hash));
        }

        if let Some(recorder) = &self.recorder {
            recorder.record("rpc_send_raw_tx", start.elapsed());
        }

        Ok(json!(format!("0x{}", hex::encode(hash))))
    }

    /// `oxide_sendRawTransaction` — submits a raw *native* module
    /// transaction (non-EVM).
    ///
    /// Params: `[rawTx: String]` (hex-encoded signed v1 envelope:
    /// `[sender][nonce][fee][module_id|0x80][sig:65B][payload]`).
    ///
    /// The envelope is pushed into the mempool as-is — admission
    /// checks (EIP-712 signature verification, replay protection,
    /// module validation) run inside `ingest_tx`, so this method is
    /// a thin decode+submit. The returned hash is the domain-tagged
    /// BLAKE3 transaction hash the executor/mempool index by — not
    /// keccak256 of the raw bytes, since the envelope is not an
    /// Ethereum tx.
    fn oxide_send_raw_transaction(&self, params: &[Value]) -> Result<Value, RpcError> {
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing raw transaction"));
        }
        let raw_hex = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("raw tx must be a hex string"))?;
        let raw = hex_decode(raw_hex)?;
        // The executor/mempool tx hash is BLAKE3 over the full
        // envelope under Domain::Transaction.
        let hash = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, &raw);

        if let Some(submitter) = &self.tx_submitter {
            submitter
                .submit_tx(TxBytes::new(raw))
                .map_err(|reason| RpcError::transaction_rejected(&reason))?;
        }

        Ok(json!(format!("0x{}", hex::encode(hash.0))))
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
        let mut req = parse_call_object(call)?;
        // Gas cap: a request may ask for more gas than any real tx
        // can carry. geth clamps `msg.GasLimit` to `--rpc.gascap`
        // (50M default) rather than erroring; our equivalent ceiling
        // is the block gas limit — a simulation can never need more.
        if req.gas.is_some_and(|g| g > types::CHAIN_BLOCK_GAS_LIMIT) {
            req.gas = Some(types::CHAIN_BLOCK_GAS_LIMIT);
        }
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        let ovr = parse_state_overrides(params.get(2))?;
        match evm.call_read_with_overrides(&req, Some(h), &ovr) {
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
        let h = self.resolve_block_ref(params.get(1))?;
        let ovr = parse_state_overrides(params.get(2))?;
        match evm.estimate_call_gas_with_overrides(&req, Some(h), &ovr) {
            Ok(gas) => Ok(json!(format!("0x{gas:x}"))),
            Err(e) => Err(call_error(e)),
        }
    }

    /// `eth_createAccessList` — generate the access list a call
    /// would touch (`{accessList, gasUsed}`).
    ///
    /// Params: `[call: Object, block: String?]`. Same call-object
    /// semantics as `eth_call` including a caller-supplied
    /// `accessList` (kept verbatim in the result, per geth).
    /// `gasUsed` is measured with the provided list applied — geth
    /// does not re-run with the generated one. Gas is clamped to the
    /// block limit exactly like `eth_call` (`gas-cap`).
    fn eth_create_access_list(&self, params: &[Value]) -> Result<Value, RpcError> {
        let call = params.first().ok_or_else(|| RpcError::invalid_params("missing call object"))?;
        let mut req = parse_call_object(call)?;
        if req.gas.is_some_and(|g| g > types::CHAIN_BLOCK_GAS_LIMIT) {
            req.gas = Some(types::CHAIN_BLOCK_GAS_LIMIT);
        }
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        match evm.create_access_list_at(&req, h) {
            Ok((list, gas_used)) => Ok(json!({
                "accessList": list.iter().map(|item| json!({
                    "address": format!("0x{}", hex::encode(item.address.0)),
                    "storageKeys": item
                        .storage_keys
                        .iter()
                        .map(|k| format!("0x{}", hex::encode(k.0)))
                        .collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "gasUsed": format!("0x{gas_used:x}"),
            })),
            Err(e) => Err(call_error(e)),
        }
    }

    /// `eth_maxPriorityFeePerGas` — the oracle's suggested tip
    /// (p60 of recent-block inclusion tips, geth `GasPriceOracle`).
    /// Without an EVM there is no sample history — return the 1 gwei
    /// default geth falls back to.
    fn eth_max_priority_fee_per_gas(&self) -> Value {
        let tip = match self.evm.as_deref() {
            Some(evm) => evm.suggest_gas_tip(),
            None => 1_000_000_000,
        };
        json!(format!("0x{tip:x}"))
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
    /// `"latest"` resolves to for state reads.
    ///
    /// The EVM module is authoritative: `history.latest()` when at
    /// least one block has sealed, else `current_height()` (the
    /// in-flight or genesis height). The RPC `block_height` counter
    /// is only the fallback when no EVM is attached — the two can
    /// diverge (the counter is set by the driver, while state reads
    /// must land inside the EVM's servable window).
    fn latest_sealed_height(&self) -> u64 {
        self.evm.as_deref().map_or_else(
            || self.block_height(),
            |evm| evm.history().latest().unwrap_or_else(|| evm.current_height()),
        )
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

/// Maximum number of elements in one JSON-RPC batch body. geth's
/// `--rpc.batch-request-limit` default; a batch larger than this is
/// rejected whole (reth shape: one `-32005` error object), because
/// per-element dispatch of an unbounded array is a resource attack —
/// each element can be a full `eth_call` against the state lock.
/// Units: requests per batch. Tradeoff: lower breaks legitimate
/// multicall-style clients that batch hundreds of reads; higher
/// weakens the `DoS` bound.
const MAX_BATCH_REQUESTS: usize = 1000;

/// Map a [`evm::CallError`] onto the Ethereum JSON-RPC error
/// surface: reverts use code `3` ("execution reverted") with the
/// revert data attached for ABI decoding; halts and validation
/// rejections use `-32000` with a human-readable reason.
/// Map a [`evm::StateError`] onto geth's RPC error shape:
/// `header not found` above the chain, `missing trie node` below
/// the retained state window (a pruned geth node's answer).
fn state_error(e: evm::StateError) -> RpcError {
    match e {
        evm::StateError::TooNew { .. } => RpcError::internal_error("header not found"),
        evm::StateError::Pruned { requested, floor } => RpcError::internal_error(&format!(
            "missing trie node: state for block {requested} unavailable \
             (earliest retained is {floor})"
        )),
    }
}

fn call_error(e: evm::CallError) -> RpcError {
    match e {
        evm::CallError::Revert { output, .. } => RpcError {
            code: 3,
            message: revert_message(&output),
            data: Some(json!(format!("0x{}", hex::encode(output)))),
        },
        evm::CallError::Halt { reason, .. } => {
            // The deadline inspector surfaces its own reason string
            // — report it verbatim rather than double-prefixing it
            // ("execution halted: execution timed out").
            if reason == "execution timed out" {
                RpcError::internal_error("execution timed out")
            } else {
                RpcError::internal_error(&format!("execution halted: {reason}"))
            }
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
    let mut v = json!({
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
    });
    attach_authorization_list(&mut v, tx.tx_type, &tx.authorization_list);
    v
}

/// Attach the `authorizationList` field for EIP-7702 (type-4)
/// transactions, matching the geth/reth JSON shape:
/// `[{chainId, address, nonce, yParity, r, s}]`.
fn attach_authorization_list(v: &mut Value, tx_type: u8, list: &[evm::tx::TxAuthorization]) {
    if tx_type != 4 {
        return;
    }
    v["authorizationList"] = json!(
        list.iter()
            .map(|a| json!({
                "chainId": format!("0x{:x}", a.chain_id),
                "address": format!("0x{:x}", a.address),
                "nonce": format!("0x{:x}", a.nonce),
                "yParity": format!("0x{:x}", a.sig.recid.as_u8()),
                "r": format!("0x{:x}", a.sig.r),
                "s": format!("0x{:x}", a.sig.s),
            }))
            .collect::<Vec<_>>()
    );
}

/// Serialize a pooled transaction to the pending-tx object shape —
/// identical to `tx_json` except `blockHash`, `blockNumber`, and
/// `transactionIndex` are `null` (the tx is not yet included) and
/// `gasPrice` is the max-fee cap (no base fee exists yet).
///
/// `signed` must already be validated; `from` is the recovered
/// sender. Returns `None` for non-EVM envelopes — see
/// [`pooled_tx_json`], which falls back to a minimal object.
fn pending_tx_json(signed: &evm::tx::SignedTx, from: Address, raw: &[u8]) -> Value {
    let hash = B256::from(keccak256(raw));
    let stx = evm::history::stored_tx(signed, from, hash, 0);
    let mut v = json!({
        "hash": format!("0x{:x}", stx.hash),
        "nonce": format!("0x{:x}", stx.nonce),
        "blockHash": Value::Null,
        "blockNumber": Value::Null,
        "transactionIndex": Value::Null,
        "from": format!("0x{:x}", stx.from),
        "to": stx.to.map_or(Value::Null, |a| json!(format!("0x{a:x}"))),
        "value": format!("0x{:x}", stx.value),
        "gas": format!("0x{:x}", stx.gas_limit),
        "gasPrice": format!("0x{:x}", stx.gas_price),
        "maxFeePerGas": format!("0x{:x}", stx.gas_price),
        "maxPriorityFeePerGas": format!("0x{:x}", stx.max_priority_fee_per_gas),
        "input": format!("0x{}", hex::encode(&stx.input)),
        "type": format!("0x{:x}", stx.tx_type),
        "chainId": format!("0x{:x}", signed.chain_id()),
        "v": format!("0x{:x}", stx.v),
        "r": format!("0x{:x}", stx.r),
        "s": format!("0x{:x}", stx.s),
    });
    attach_authorization_list(&mut v, stx.tx_type, &stx.authorization_list);
    v
}

/// Serialize one pooled envelope for `txpool_content`: decode the
/// inner signed EVM tx when possible, else emit a minimal
/// `{hash, from, nonce}` object — non-EVM module txs share the
/// mempool and hiding them would under-report `txpool_status`.
fn pooled_tx_json(item: &TxpoolItem) -> Value {
    let raw = evm::unwrap_evm_tx_envelope(item.envelope.as_bytes());
    let decoded = raw.and_then(|r| evm::tx::SignedTx::decode_raw(r).ok());
    if let (Some(raw), Some(signed)) = (raw, decoded) {
        // The envelope sender was already recovered and validated at
        // ingest — trust it over re-recovering here.
        return pending_tx_json(&signed, Address::from(item.sender.0), raw);
    }
    let hash = B256::from(keccak256(item.envelope.as_bytes()));
    json!({
        "hash": format!("0x{hash:x}"),
        "nonce": format!("0x{:x}", item.nonce),
        "blockHash": Value::Null,
        "blockNumber": Value::Null,
        "transactionIndex": Value::Null,
        "from": format!("0x{}", hex::encode(item.sender.0)),
        "to": Value::Null,
        "value": "0x0",
        "gas": "0x0",
        "input": format!("0x{}", hex::encode(item.envelope.as_bytes())),
    })
}

/// geth's `txpool_inspect` leaf: `"to: value wei + gas gas ×
/// price wei"`, or `"contract creation: …"` for creates.
fn txpool_inspect_summary(item: &TxpoolItem) -> Value {
    let raw = evm::unwrap_evm_tx_envelope(item.envelope.as_bytes());
    let decoded = raw.and_then(|r| evm::tx::SignedTx::decode_raw(r).ok());
    let Some(signed) = decoded else {
        return json!(format!("non-EVM envelope: {} bytes", item.envelope.as_bytes().len()));
    };
    let to = match signed.to() {
        evm::tx::TxKind::Call(addr) => format!("0x{addr:x}"),
        evm::tx::TxKind::Create => "contract creation".to_string(),
    };
    json!(format!(
        "{to}: {} wei + {} gas × {} wei",
        signed.value(),
        signed.gas_limit(),
        signed.max_fee_per_gas()
    ))
}

/// Build the `{pending, queued}` body shared by `txpool_content`
/// and `txpool_contentFrom`. `only` restricts to one sender.
fn txpool_content_json(items: &[TxpoolItem], only: Option<primitives::Address>) -> Value {
    let mut pending = serde_json::Map::new();
    let mut queued = serde_json::Map::new();
    for item in items {
        if let Some(addr) = only
            && item.sender != addr
        {
            continue;
        }
        let addr = format!("0x{}", hex::encode(item.sender.0));
        let bucket = if item.pending { &mut pending } else { &mut queued };
        let entry = bucket.entry(addr).or_insert_with(|| json!({}));
        if let Some(m) = entry.as_object_mut() {
            m.insert(format!("0x{:x}", item.nonce), pooled_tx_json(item));
        }
    }
    json!({ "pending": pending, "queued": queued })
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

/// Validate the `debug_trace*` options object. The only supported
/// `tracer` is `"callTracer"` (or absent — this implementation's
/// default, a documented deviation from geth's struct-logger
/// default). A named-but-unsupported tracer is a `-32602` error:
/// returning the callTracer shape to a caller expecting struct logs
/// would silently hand them the wrong data.
/// Parse the `debug_trace*` config object — `{tracer, stateOverrides?}`.
/// Returns the parsed `stateOverrides` table (geth `TraceCallConfig`
/// nests it inside the config); only `debug_traceCall` consumes it —
/// block tracers validate the shape and drop it (the block already
/// executed; overrides can't retroactively change it).
fn parse_trace_options(v: Option<&Value>) -> Result<evm::overrides::StateOverrides, RpcError> {
    let Some(Value::Object(obj)) = v else {
        // Absent or non-object options: defaults apply.
        return match v {
            None | Some(Value::Null) => Ok(evm::overrides::StateOverrides::new()),
            Some(_) => Err(RpcError::invalid_params("trace options must be an object")),
        };
    };
    if let Some(tracer) = obj.get("tracer") {
        match tracer.as_str() {
            None | Some("callTracer") => {}
            Some(other) => {
                return Err(RpcError {
                    code: -32_602,
                    message: format!(
                        "unsupported tracer {other:?}: only \"callTracer\" is implemented \
                         (the default geth struct-logger output is not recorded — see \
                         docs/evm-parity-gap-analysis.md)"
                    ),
                    data: None,
                });
            }
        }
    }
    parse_state_overrides(obj.get("stateOverrides"))
}

/// Serialize a [`evm::trace::CallFrame`] to the geth `callTracer`
/// object shape, recursively. `root_override` patches the top frame's
/// `gas`/`gasUsed` with the tx-level values (geth reports the tx gas
/// limit and total gas used including intrinsic cost; the recorder
/// reports the frame-scoped post-intrinsic numbers).
fn call_frame_json(f: &evm::trace::CallFrame, root_override: Option<(u64, u64)>) -> Value {
    let (gas, gas_used) = root_override.unwrap_or((f.gas_limit, f.gas_used));
    let mut obj = json!({
        "type": f.kind,
        "from": format!("0x{:x}", f.from),
        "to": f.to.map_or(Value::Null, |a| json!(format!("0x{a:x}"))),
        "value": format!("0x{:x}", f.value),
        "gas": format!("0x{gas:x}"),
        "gasUsed": format!("0x{gas_used:x}"),
        "input": format!("0x{}", hex::encode(&f.input)),
    });
    // geth emits `output` on success and `error` (+ `revertReason`)
    // on failure — not both.
    match &f.error {
        None => {
            obj["output"] = json!(format!("0x{}", hex::encode(&f.output)));
        }
        Some(err) => {
            obj["error"] = json!(err);
            if let Some(reason) = &f.revert_reason {
                obj["revertReason"] = json!(reason);
            }
        }
    }
    if !f.calls.is_empty() {
        obj["calls"] = Value::Array(f.calls.iter().map(|c| call_frame_json(c, None)).collect());
    }
    obj
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

/// Parse a pollable-filter ID param (`"0x…"` hex string as geth
/// returns them).
fn parse_filter_id(v: Option<&Value>) -> Result<String, RpcError> {
    let v = v.ok_or_else(|| RpcError::invalid_params("missing filter ID"))?;
    v.as_str()
        .map(str::to_string)
        .ok_or_else(|| RpcError::invalid_params("filter ID must be a string"))
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

/// Parse geth's `stateOverride` argument (`eth_call`/`eth_estimateGas`
/// param 2/3): `{ "0xaddr": { balance?, nonce?, code?, state?,
/// stateDiff? } }`.
///
/// `state` replaces an account's whole storage map; `stateDiff`
/// merges into it — geth rejects supplying both for one account.
/// `movePrecompileToAddress` is intentionally unimplemented (native
/// precompiles are fixed-address protocol code, not movable
/// bytecode) — unknown fields are otherwise ignored, matching
/// geth's permissive decode.
fn parse_state_overrides(v: Option<&Value>) -> Result<evm::overrides::StateOverrides, RpcError> {
    let mut out = evm::overrides::StateOverrides::new();
    let Some(v) = v.filter(|v| !v.is_null()) else { return Ok(out) };
    let obj = v.as_object().ok_or_else(|| {
        RpcError::invalid_params("stateOverride must be an address→override object")
    })?;
    for (key, entry) in obj {
        let addr = parse_eth_address(Some(&Value::String(key.clone())))?;
        let fields = entry
            .as_object()
            .ok_or_else(|| RpcError::invalid_params("override entry must be an object"))?;
        let get = |k: &str| fields.get(k).filter(|v| !v.is_null());
        let mut ovr = evm::overrides::AccountOverride::default();
        if let Some(v) = get("balance") {
            ovr.balance = Some(parse_u256(v)?);
        }
        if let Some(v) = get("nonce") {
            ovr.nonce = Some(parse_u64(v)?);
        }
        if let Some(v) = get("code") {
            let s =
                v.as_str().ok_or_else(|| RpcError::invalid_params("code must be a hex string"))?;
            ovr.code = Some(hex_decode(s)?);
        }
        if let Some(v) = get("state") {
            ovr.state = Some(parse_override_slots(v)?);
        }
        if let Some(v) = get("stateDiff") {
            ovr.state_diff = Some(parse_override_slots(v)?);
        }
        if ovr.state.is_some() && ovr.state_diff.is_some() {
            return Err(RpcError::invalid_params("both state and stateDiff given"));
        }
        out.insert(addr, ovr);
    }
    Ok(out)
}

/// Parse a `state`/`stateDiff` slot map `{ "0xslot": "0xvalue" }`.
fn parse_override_slots(v: &Value) -> Result<std::collections::BTreeMap<U256, U256>, RpcError> {
    let obj = v
        .as_object()
        .ok_or_else(|| RpcError::invalid_params("state override must be a slot→value object"))?;
    let mut slots = std::collections::BTreeMap::new();
    for (slot, value) in obj {
        slots.insert(parse_u256(&Value::String(slot.clone()))?, parse_u256(value)?);
    }
    Ok(slots)
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
mod tests;
