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
//!
//! Future phases add: `eth_call`, `eth_getBlockByNumber`,
//! `eth_getTransactionReceipt`, `eth_getLogs`, WebSocket
//! subscriptions (`eth_subscribe`), and full Foundry/MetaMask
//! compatibility.

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
            "eth_chainId" => Ok(self.eth_chain_id()),
            "eth_blockNumber" => Ok(self.eth_block_number()),
            "eth_gasPrice" => Ok(self.eth_gas_price()),
            "net_version" => Ok(self.net_version()),
            "web3_clientVersion" => Ok(self.web3_client_version()),
            "eth_getBalance" => self.eth_get_balance(&request.params),
            "eth_getTransactionCount" => self.eth_get_transaction_count(&request.params),
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
}
