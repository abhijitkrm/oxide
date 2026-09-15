//! Integration tests for `MetaMask`, `Foundry`, and `Blockscout`
//! compatibility (plan.md §13, Phase 2).
//!
//! These tests simulate the exact JSON-RPC calls that `MetaMask`,
//! `Foundry`, and `Blockscout` make when connecting to an Oxide node.
//! They verify the responses match what these tools expect —
//! correct hex formatting, correct types, correct error codes.
//!
//! ## `MetaMask`
//!
//! `MetaMask` makes these calls on connection:
//! - `eth_chainId` — to display the chain.
//! - `net_version` — to identify the network.
//! - `eth_blockNumber` — to check sync status.
//! - `eth_getBalance` — to display account balance.
//! - `eth_getTransactionCount` — to get the nonce for tx building.
//! - `eth_gasPrice` — to estimate gas.
//!
//! ## `Foundry`
//!
//! `Foundry` (cast/forge) makes these calls:
//! - `eth_chainId` — chain identification.
//! - `eth_blockNumber` — latest block.
//! - `eth_getBalance` — account balance.
//! - `web3_clientVersion` — node version.
//!
//! ## `Blockscout`
//!
//! `Blockscout` makes these calls:
//! - `eth_blockNumber` — latest block for the explorer.
//! - `net_version` — network identification.
//! - `web3_clientVersion` — node version for the explorer UI.
//! - `eth_subscribe` (newHeads) — WebSocket live updates.

use rpc::{RpcRequest, RpcServer};
use serde_json::{Value, json};

fn make_server() -> RpcServer {
    let mut s = RpcServer::new(1337, 1_000_000_000);
    s.set_block_height(42);
    // Attach a real EVM module so state/history reads return actual
    // values (empty state → zero balances/nonces) instead of the
    // "evm module unavailable" error.
    s.set_evm(std::sync::Arc::new(evm::EvmModule::new(1337, 1_000_000_000)));
    s
}

fn make_request(method: &str, params: Vec<Value>, id: Value) -> RpcRequest {
    RpcRequest { method: method.to_string(), params, id, jsonrpc: "2.0".to_string() }
}

fn handle(server: &RpcServer, method: &str, params: Vec<Value>) -> Value {
    let req = make_request(method, params, json!(1));
    let resp = server.handle(&req);
    assert!(resp.error.is_none(), "unexpected error for {method}: {:?}", resp.error);
    resp.result.unwrap()
}

// ---- MetaMask integration tests ----

#[test]
fn metamask_eth_chain_id_returns_hex_string() {
    // MetaMask expects eth_chainId to return a hex string like
    // "0x539" (not a number). This is used to display the chain
    // in the network selector.
    let s = make_server();
    let result = handle(&s, "eth_chainId", vec![]);
    let hex = result.as_str().expect("chainId must be a string");
    assert!(hex.starts_with("0x"), "MetaMask requires hex prefix: {hex}");
    assert_eq!(hex, "0x539", "chain 1337 = 0x539");
}

#[test]
fn metamask_net_version_returns_decimal_string() {
    // MetaMask uses net_version to identify the network. It
    // expects a decimal string (not hex).
    let s = make_server();
    let result = handle(&s, "net_version", vec![]);
    let net = result.as_str().expect("net_version must be a string");
    assert_eq!(net, "1337", "net_version must be decimal: {net}");
}

#[test]
fn metamask_eth_block_number_returns_hex() {
    // MetaMask calls eth_blockNumber to check sync status.
    let s = make_server();
    let result = handle(&s, "eth_blockNumber", vec![]);
    let hex = result.as_str().expect("blockNumber must be a string");
    assert!(hex.starts_with("0x"));
    assert_eq!(hex, "0x2a", "block 42 = 0x2a");
}

#[test]
fn metamask_eth_get_balance_returns_hex_wei() {
    // MetaMask calls eth_getBalance with [address, "latest"].
    let s = make_server();
    let result = handle(
        &s,
        "eth_getBalance",
        vec![json!("0x0000000000000000000000000000000000000000"), json!("latest")],
    );
    let hex = result.as_str().expect("balance must be a string");
    assert!(hex.starts_with("0x"), "MetaMask requires hex balance: {hex}");
}

#[test]
fn metamask_eth_get_transaction_count_returns_hex() {
    // MetaMask calls eth_getTransactionCount to get the nonce.
    let s = make_server();
    let result = handle(
        &s,
        "eth_getTransactionCount",
        vec![json!("0x0000000000000000000000000000000000000000"), json!("latest")],
    );
    let hex = result.as_str().expect("nonce must be a string");
    assert!(hex.starts_with("0x"));
}

#[test]
fn metamask_eth_gas_price_returns_hex_wei() {
    // MetaMask calls eth_gasPrice to estimate gas costs.
    let s = make_server();
    let result = handle(&s, "eth_gasPrice", vec![]);
    let hex = result.as_str().expect("gasPrice must be a string");
    assert!(hex.starts_with("0x"));
}

// ---- Foundry integration tests ----

#[test]
fn foundry_eth_chain_id_works() {
    // `cast chain-id` calls eth_chainId.
    let s = make_server();
    let result = handle(&s, "eth_chainId", vec![]);
    assert_eq!(result, json!("0x539"));
}

#[test]
fn foundry_eth_block_number_works() {
    // `cast block-number` calls eth_blockNumber.
    let s = make_server();
    let result = handle(&s, "eth_blockNumber", vec![]);
    assert_eq!(result, json!("0x2a"));
}

#[test]
fn foundry_eth_get_balance_works() {
    // `cast balance` calls eth_getBalance.
    let s = make_server();
    let result =
        handle(&s, "eth_getBalance", vec![json!("0x0000000000000000000000000000000000000000")]);
    assert_eq!(result, json!("0x0"));
}

#[test]
fn foundry_web3_client_version_works() {
    // `cast web3_clientVersion` checks the node version.
    let s = make_server();
    let result = handle(&s, "web3_clientVersion", vec![]);
    let version = result.as_str().expect("clientVersion must be a string");
    assert!(version.starts_with("oxide/"), "Foundry expects a client version string: {version}");
}

// ---- Blockscout integration tests ----

#[test]
fn blockscout_eth_block_number_works() {
    // Blockscout polls eth_blockNumber for the latest block.
    let s = make_server();
    let result = handle(&s, "eth_blockNumber", vec![]);
    assert_eq!(result, json!("0x2a"));
}

#[test]
fn blockscout_net_version_works() {
    // Blockscout uses net_version for network identification.
    let s = make_server();
    let result = handle(&s, "net_version", vec![]);
    assert_eq!(result, json!("1337"));
}

#[test]
fn blockscout_web3_client_version_works() {
    // Blockscout displays the client version in the UI.
    let s = make_server();
    let result = handle(&s, "web3_clientVersion", vec![]);
    assert!(result.as_str().unwrap().starts_with("oxide/"));
}

#[test]
fn blockscout_eth_subscribe_new_heads_works() {
    // Blockscout subscribes to newHeads for live block updates.
    let s = make_server();
    let result = handle(&s, "eth_subscribe", vec![json!("newHeads")]);
    let id = result.as_str().expect("subscription ID must be a string");
    assert!(id.starts_with("0x"), "Blockscout expects hex subscription ID: {id}");
}

// ---- Cross-tool error handling ----

#[test]
fn all_tools_unknown_method_returns_method_not_found() {
    // All three tools handle method-not-found errors. The error
    // code must be -32601 (JSON-RPC 2.0 standard).
    let s = make_server();
    let req = make_request("eth_nonexistent", vec![], json!(1));
    let resp = s.handle(&req);
    assert!(resp.error.is_some());
    let error = resp.error.unwrap();
    assert_eq!(error.code, -32601, "method not found = -32601");
}

#[test]
fn all_tools_invalid_json_returns_parse_error() {
    // All three tools send JSON; invalid JSON must return -32700.
    let s = make_server();
    let resp = s.handle_raw("not valid json");
    let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let error = &parsed["error"];
    assert_eq!(error["code"], -32700, "parse error = -32700");
}

#[test]
fn all_tools_response_has_jsonrpc_field() {
    // JSON-RPC 2.0 responses must include the jsonrpc field.
    let s = make_server();
    let req = make_request("eth_chainId", vec![], json!(1));
    let resp = s.handle(&req);
    assert_eq!(resp.jsonrpc, "2.0");
}

#[test]
fn all_tools_response_id_echoes_request_id() {
    // JSON-RPC 2.0 requires the response ID to match the request
    // ID. Tools use this to correlate requests and responses.
    let s = make_server();
    let req = make_request("eth_chainId", vec![], json!("metamask-request-1"));
    let resp = s.handle(&req);
    assert_eq!(resp.id, json!("metamask-request-1"));
}
