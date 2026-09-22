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

mod endpoints;

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
