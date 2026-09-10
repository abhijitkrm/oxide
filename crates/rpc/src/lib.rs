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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

/// A WebSocket subscription.
///
/// Created by `eth_subscribe`, cancelled by `eth_unsubscribe`.
/// Each subscription has a unique hex ID and a type that
/// determines what events it receives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// The subscription ID (hex string, e.g. `"0x1"`).
    pub id: String,
    /// The subscription type.
    pub sub_type: SubscriptionType,
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

/// The subscription manager: tracks active subscriptions and
/// generates notifications.
///
/// Each subscription gets a monotonically increasing ID. The
/// manager is `Send + Sync` so it can be shared across WebSocket
/// connections via `Arc`.
pub struct SubscriptionManager {
    /// The next subscription ID to assign.
    next_id: Arc<AtomicU64>,
}

impl SubscriptionManager {
    /// Create a fresh subscription manager.
    #[must_use]
    pub fn new() -> Self {
        Self { next_id: Arc::new(AtomicU64::new(1)) }
    }

    /// Create a new subscription.
    ///
    /// Parses the subscription type from the params, assigns a
    /// unique ID, and returns the subscription.
    ///
    /// # Errors
    ///
    /// Returns `RpcError` if the subscription type is unknown
    /// or params are invalid.
    pub fn subscribe(&self, params: &[Value]) -> Result<Subscription, RpcError> {
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing subscription type"));
        }
        let type_str = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("subscription type must be a string"))?;
        let sub_type = SubscriptionType::parse(type_str).ok_or_else(|| {
            RpcError::invalid_params(&format!("unknown subscription type: {type_str}"))
        })?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        Ok(Subscription { id: format!("0x{id:x}"), sub_type })
    }

    /// Build a `newHeads` notification for a subscription.
    ///
    /// The `result` is a block header object with `number`,
    /// `hash`, `gasUsed`, etc.
    #[must_use]
    pub fn new_heads_notification(
        sub: &Subscription,
        block_height: u64,
    ) -> SubscriptionNotification {
        SubscriptionNotification {
            jsonrpc: "2.0".to_string(),
            method: "eth_subscription".to_string(),
            params: SubscriptionParams {
                subscription: sub.id.clone(),
                result: json!({
                    "number": format!("0x{block_height:x}"),
                    "hash": format!("0x{block_height:064x}"),
                    "gasUsed": "0x0",
                }),
            },
        }
    }

    /// Build a `logs` notification for a subscription.
    ///
    /// The `result` is a log object with `address`, `data`,
    /// `topics`, etc.
    #[must_use]
    pub fn logs_notification(
        sub: &Subscription,
        address: &str,
        data: &str,
    ) -> SubscriptionNotification {
        SubscriptionNotification {
            jsonrpc: "2.0".to_string(),
            method: "eth_subscription".to_string(),
            params: SubscriptionParams {
                subscription: sub.id.clone(),
                result: json!({
                    "address": address,
                    "data": data,
                    "topics": [],
                }),
            },
        }
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// The RPC server state. Holds references to the EVM module and
/// chain state needed to answer queries.
pub struct RpcServer {
    /// The chain ID (EIP-155).
    chain_id: u64,
    /// The current block height.
    block_height: u64,
    /// The current base fee (wei per gas).
    base_fee: u64,
    /// The client version string.
    client_version: String,
    /// The subscription manager for WebSocket subscriptions.
    subscriptions: SubscriptionManager,
}

impl RpcServer {
    /// Create a new RPC server with the given chain parameters.
    #[must_use]
    pub fn new(chain_id: u64, base_fee: u64) -> Self {
        Self {
            chain_id,
            block_height: 0,
            base_fee,
            client_version: format!("oxide/{}", env!("CARGO_PKG_VERSION")),
            subscriptions: SubscriptionManager::new(),
        }
    }

    /// Update the block height (called by the executor after each
    /// finalized block).
    pub fn set_block_height(&mut self, height: u64) {
        self.block_height = height;
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
            "eth_subscribe" => self.eth_subscribe(&request.params),
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

    // ---- Ethereum RPC methods ----

    /// `eth_chainId` — returns the chain ID as a hex string.
    fn eth_chain_id(&self) -> Value {
        json!(format!("0x{:x}", self.chain_id))
    }

    /// `eth_blockNumber` — returns the current block height as a hex
    /// string.
    fn eth_block_number(&self) -> Value {
        json!(format!("0x{:x}", self.block_height))
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
    fn eth_get_balance(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing address"));
        }
        // Phase 2 v0: always return 0 (no account state wired yet).
        // Full implementation reads from the EVM module's CacheDB.
        Ok(json!("0x0"))
    }

    /// `eth_getTransactionCount` — returns an account's nonce as a
    /// hex string.
    ///
    /// Params: `[address: String, block: String?]`
    fn eth_get_transaction_count(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing address"));
        }
        // Phase 2 v0: always return 0 (no account state wired yet).
        Ok(json!("0x0"))
    }

    /// `eth_subscribe` — creates a WebSocket subscription.
    ///
    /// Params: `[subscriptionType: String, options?: Object]`
    ///
    /// Returns the subscription ID as a hex string.
    fn eth_subscribe(&self, params: &[Value]) -> Result<Value, RpcError> {
        let sub = self.subscriptions.subscribe(params)?;
        Ok(json!(sub.id))
    }

    /// `eth_unsubscribe` — cancels a WebSocket subscription.
    ///
    /// Params: `[subscriptionId: String]`
    ///
    /// Returns `true` on success. Phase 2 v0 always returns `true`
    /// (subscriptions are stateless until wired to a real WebSocket
    /// connection).
    fn eth_unsubscribe(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing subscription ID"));
        }
        // Phase 2 v0: always return true (no persistent subscription
        // state to cancel — the subscription manager assigns IDs
        // but doesn't track active connections yet).
        Ok(json!(true))
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
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing address"));
        }
        // Phase E v0: return "0x" (empty code) — no account state
        // wired to the RPC server yet.
        Ok(json!("0x"))
    }

    /// `eth_getStorageAt` — returns the storage value at a given
    /// address and slot.
    ///
    /// Params: `[address: String, slot: String, block: String?]`
    fn eth_get_storage_at(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.len() < 2 {
            return Err(RpcError::invalid_params("missing address or slot"));
        }
        // Phase E v0: return 32-byte zero — no storage wired.
        Ok(json!("0x0000000000000000000000000000000000000000000000000000000000000000"))
    }

    /// `eth_getBlockByNumber` — returns a block by number.
    ///
    /// Params: `[blockNumber: String, fullTransactions: bool]`
    fn eth_get_block_by_number(&self, params: &[Value]) -> Result<Value, RpcError> {
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing block number"));
        }
        let block_num = parse_block_tag(&params[0])?;
        Ok(self.block_json(block_num))
    }

    /// `eth_getBlockByHash` — returns a block by hash.
    ///
    /// Params: `[blockHash: String, fullTransactions: bool]`
    fn eth_get_block_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing block hash"));
        }
        // Phase E v0: return null (no block store wired).
        Ok(Value::Null)
    }

    /// `eth_getBlockTransactionCountByNumber` — returns the number of
    /// transactions in a block.
    ///
    /// Params: `[blockNumber: String]`
    fn eth_get_block_tx_count_by_number(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing block number"));
        }
        // Phase E v0: return 0.
        Ok(json!("0x0"))
    }

    /// `eth_getBlockTransactionCountByHash` — returns the number of
    /// transactions in a block by hash.
    ///
    /// Params: `[blockHash: String]`
    fn eth_get_block_tx_count_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing block hash"));
        }
        Ok(json!("0x0"))
    }

    /// `eth_getTransactionByHash` — returns a transaction by hash.
    ///
    /// Params: `[txHash: String]`
    fn eth_get_transaction_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing tx hash"));
        }
        // Phase E v0: return null (no tx store wired).
        Ok(Value::Null)
    }

    /// `eth_getTransactionByBlockNumberAndIndex` — returns a tx by
    /// block number and index.
    ///
    /// Params: `[blockNumber: String, index: String]`
    fn eth_get_transaction_by_block_and_index(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.len() < 2 {
            return Err(RpcError::invalid_params("missing block number or index"));
        }
        Ok(Value::Null)
    }

    /// `eth_getTransactionReceipt` — returns a transaction receipt.
    ///
    /// Params: `[txHash: String]`
    fn eth_get_transaction_receipt(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing tx hash"));
        }
        // Phase E v0: return null (no receipt store wired).
        Ok(Value::Null)
    }

    /// `eth_sendRawTransaction` — submits a raw EVM transaction.
    ///
    /// Params: `[rawTx: String]` (hex-encoded RLP transaction)
    fn eth_send_raw_transaction(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing raw transaction"));
        }
        let raw_hex = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("raw tx must be a hex string"))?;
        let raw = hex_decode(raw_hex)?;
        // Compute the tx hash: keccak256 of the raw RLP.
        let hash = keccak256(&raw);
        Ok(json!(format!("0x{}", hex::encode(hash))))
    }

    /// `eth_call` — executes a call without persisting state.
    ///
    /// Params: `[call: Object, block: String?]`
    fn eth_call(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing call object"));
        }
        // Phase E v0: return "0x" (empty return data).
        Ok(json!("0x"))
    }

    /// `eth_estimateGas` — estimates gas for a call.
    ///
    /// Params: `[call: Object, block: String?]`
    fn eth_estimate_gas(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing call object"));
        }
        // Phase E v0: return 21,000 (intrinsic gas for a simple
        // transfer).
        Ok(json!("0x5208"))
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
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing block"));
        }
        // Phase E v0: return null (no receipt store wired).
        Ok(Value::Null)
    }

    /// `eth_getLogs` — returns logs matching a filter.
    ///
    /// Params: `[filter: Object]`
    fn eth_get_logs(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing filter"));
        }
        // Phase E v0: return empty array (no log store wired).
        Ok(json!([]))
    }

    /// `eth_feeHistory` — returns fee history.
    ///
    /// Params: `[blockCount: String, newestBlock: String, rewardPercentiles: Array?]`
    fn eth_fee_history(&self, params: &[Value]) -> Result<Value, RpcError> {
        if params.len() < 2 {
            return Err(RpcError::invalid_params("missing blockCount or newestBlock"));
        }
        // Phase E v0: return a minimal fee history with the
        // current base fee.
        Ok(json!({
            "oldestBlock": "0x0",
            "baseFeePerGas": [format!("0x{:x}", self.base_fee)],
            "gasUsedRatio": [0.0],
        }))
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

    /// Build a minimal block JSON object for `eth_getBlockByNumber`.
    ///
    /// Phase E v0: returns a stub block with the correct number but
    /// zeroed hashes/txs. Full implementation reads from the block
    /// store.
    fn block_json(&self, block_num: u64) -> Value {
        let _ = self;
        json!({
            "number": format!("0x{block_num:x}"),
            "hash": format!("0x{block_num:064x}"),
            "parentHash": format!("0x{:064x}", block_num.saturating_sub(1)),
            "nonce": "0x0000000000000000",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "miner": "0x0000000000000000000000000000000000000000",
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "size": "0x0",
            "gasLimit": format!("0x{:x}", 30_000_000),
            "gasUsed": "0x0",
            "timestamp": "0x0",
            "transactions": [],
            "uncles": [],
        })
    }
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

/// Parse a block tag (`"latest"`, `"earliest"`, `"pending"`, or a
/// hex block number) to a `u64`.
fn parse_block_tag(v: &Value) -> Result<u64, RpcError> {
    let s = v.as_str().ok_or_else(|| RpcError::invalid_params("block must be a string"))?;
    match s {
        "latest" | "pending" | "earliest" => Ok(0), // Phase E v0: no block store
        _ => {
            let s = s.strip_prefix("0x").unwrap_or(s);
            u64::from_str_radix(s, 16)
                .map_err(|e| RpcError::invalid_params(&format!("invalid block number: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_server() -> RpcServer {
        RpcServer::new(1, 7_000_000_000)
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
        let mut s = make_server();
        s.set_block_height(100);
        let req = make_request("eth_blockNumber", vec![], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!("0x64")));
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
        let s = make_server();
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
        let s = make_server();
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

    #[test]
    fn eth_subscribe_new_heads_returns_id() {
        let s = make_server();
        let req = make_request("eth_subscribe", vec![json!("newHeads")], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_none());
        let id = resp.result.unwrap().as_str().unwrap().to_string();
        assert!(id.starts_with("0x"), "subscription ID must be hex: {id}");
    }

    #[test]
    fn eth_subscribe_logs_returns_id() {
        let s = make_server();
        let req = make_request("eth_subscribe", vec![json!("logs")], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_none());
        assert!(resp.result.unwrap().as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn eth_subscribe_unknown_type_errors() {
        let s = make_server();
        let req = make_request("eth_subscribe", vec![json!("unknownType")], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_subscribe_missing_type_errors() {
        let s = make_server();
        let req = make_request("eth_subscribe", vec![], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_subscribe_non_string_type_errors() {
        let s = make_server();
        let req = make_request("eth_subscribe", vec![json!(42)], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn eth_unsubscribe_returns_true() {
        let s = make_server();
        let req = make_request("eth_unsubscribe", vec![json!("0x1")], json!(1));
        let resp = s.handle(&req);
        assert_eq!(resp.result, Some(json!(true)));
    }

    #[test]
    fn eth_unsubscribe_missing_id_errors() {
        let s = make_server();
        let req = make_request("eth_unsubscribe", vec![], json!(1));
        let resp = s.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[test]
    fn subscription_ids_are_unique() {
        let mgr = SubscriptionManager::new();
        let sub1 = mgr.subscribe(&[json!("newHeads")]).unwrap();
        let sub2 = mgr.subscribe(&[json!("newHeads")]).unwrap();
        assert_ne!(sub1.id, sub2.id, "subscription IDs must be unique");
    }

    #[test]
    fn new_heads_notification_has_block_number() {
        let mgr = SubscriptionManager::new();
        let sub = mgr.subscribe(&[json!("newHeads")]).unwrap();
        let notif = SubscriptionManager::new_heads_notification(&sub, 42);
        assert_eq!(notif.method, "eth_subscription");
        assert_eq!(notif.params.subscription, sub.id);
        let number = notif.params.result["number"].as_str().unwrap();
        assert_eq!(number, "0x2a");
    }

    #[test]
    fn logs_notification_has_address_and_data() {
        let mgr = SubscriptionManager::new();
        let sub = mgr.subscribe(&[json!("logs")]).unwrap();
        let notif = SubscriptionManager::logs_notification(&sub, "0xabc", "0xdead");
        assert_eq!(notif.method, "eth_subscription");
        assert_eq!(notif.params.subscription, sub.id);
        assert_eq!(notif.params.result["address"], json!("0xabc"));
        assert_eq!(notif.params.result["data"], json!("0xdead"));
    }

    #[test]
    fn notification_serializes_to_json() {
        let mgr = SubscriptionManager::new();
        let sub = mgr.subscribe(&[json!("newHeads")]).unwrap();
        let notif = SubscriptionManager::new_heads_notification(&sub, 1);
        let json_str = serde_json::to_string(&notif).unwrap();
        assert!(json_str.contains("eth_subscription"));
        assert!(json_str.contains(&sub.id));
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
        let s = make_server();
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
        let s = make_server();
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
        let s = make_server();
        let req = make_request("eth_getBlockByNumber", vec![json!("0x0"), json!(false)], json!(1));
        let resp = s.handle(&req);
        let block = resp.result.unwrap();
        assert_eq!(block["number"], json!("0x0"));
        assert!(block["transactions"].is_array());
    }

    #[test]
    fn eth_estimate_gas_returns_intrinsic() {
        let s = make_server();
        let req = make_request(
            "eth_estimateGas",
            vec![json!({"to": "0x0000000000000000000000000000000000000000", "value": "0x1"})],
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
        let s = make_server();
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
        let s = make_server();
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
}
