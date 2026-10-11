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
    assert_eq!(result["hash"].as_str().unwrap().len(), 66, "hash must be a 32-byte hex quantity");
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
    assert_eq!(result, json!("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
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
    /// Senders handed over through `submit_tx_recovered`.
    recovered: std::sync::Mutex<Vec<[u8; 20]>>,
}

impl MockSubmitter {
    fn new() -> Self {
        Self {
            submissions: std::sync::Mutex::new(Vec::new()),
            reject_next: std::sync::Mutex::new(false),
            recovered: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn count(&self) -> usize {
        primitives::sync::lock_state(&self.submissions).len()
    }

    fn last(&self) -> TxBytes {
        primitives::sync::lock_state(&self.submissions).last().cloned().unwrap_or_default()
    }
}

impl TxSubmitter for MockSubmitter {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        if *primitives::sync::lock_state(&self.reject_next) {
            return Err("mock rejection".to_string());
        }
        primitives::sync::lock_state(&self.submissions).push(tx);
        Ok(())
    }

    fn submit_tx_recovered(&self, tx: TxBytes, sender: [u8; 20]) -> Result<(), String> {
        primitives::sync::lock_state(&self.recovered).push(sender);
        self.submit_tx(tx)
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

    // hft-audit-2 P-1: the sender the endpoint recovered travels with
    // the envelope so admission does not recover it again — and it is
    // the payload's real signer, matching the envelope header.
    let tx_sender = signed.recover_sender().expect("recover");
    let carried = primitives::sync::lock_state(&submitter.recovered).clone();
    assert_eq!(carried, vec![tx_sender.0], "submit must carry the recovered sender");
    assert_eq!(&bytes[..20], tx_sender.0.as_slice(), "envelope sender must be the signer");
}

/// When the submitter rejects (e.g. mempool full), the RPC returns
/// a transaction-rejected error.
#[test]
fn eth_send_raw_transaction_with_submitter_propagates_rejection() {
    use evm::tx::{SignedTx, TxEip1559, TxFields, TxKind};
    use revm::primitives::{Address, Bytes, U256};

    let mut s = make_server();
    let submitter = Arc::new(MockSubmitter::new());
    *primitives::sync::lock_state(&submitter.reject_next) = true;
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

// ---- Pollable filter tests ----

/// Seal a block containing one LOG0-emitting call so filters
/// have something to observe. Returns the emitting contract.
#[cfg(test)]
fn seal_log_block(
    evm: &evm::EvmModule,
    height: u64,
    contract: primitives::Address,
    sender: primitives::Address,
    nonce: u64,
) {
    use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
    use executor::Module;
    use primitives::Height;
    use revm::primitives::{Bytes, U256};
    let tx = TxLegacy {
        fields: TxFields {
            nonce,
            gas_limit: 30_000_000,
            to: TxKind::Call(alloy_primitives::Address::from(contract.0)),
            value: U256::ZERO,
            data: Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000u64),
    };
    let raw = SignedTx::sign_legacy(tx, &[0x11; 32]).expect("sign").encode_to_bytes();
    let ctx = executor::TxContext { sender, nonce: 0, fee: 0 };
    evm.begin_block(Height::new(height));
    let results = evm.handle_batch(&ctx, &[raw]);
    assert!(results[0].is_ok(), "block tx must execute: {:?}", results[0]);
    evm.end_block(Height::new(height));
}

/// EVM server with a LOG0 contract installed at `0xAA…` and a
/// funded sender at the `[0x11;32]` key's recovered address.
#[cfg(test)]
fn make_log_server() -> (RpcServer, Arc<evm::EvmModule>, primitives::Address) {
    use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
    use revm::primitives::{Bytes, U256};
    let (s, evm) = make_evm_server();
    let contract = primitives::Address([0xAA; 20]);
    // LOG0 with 32 bytes ending 0x42.
    evm.genesis_insert_account(
        &contract,
        0,
        1,
        hex::decode("604260005260206000a0").expect("contract hex"),
        Vec::new(),
    );
    let probe = TxLegacy {
        fields: TxFields {
            nonce: 0,
            gas_limit: 30_000_000,
            to: TxKind::Call(alloy_primitives::Address::from([0xAA; 20])),
            value: U256::ZERO,
            data: Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000u64),
    };
    let raw = SignedTx::sign_legacy(probe, &[0x11; 32]).expect("sign").encode_to_bytes();
    let sender = SignedTx::decode_raw(&raw).expect("decode").recover_sender().expect("recover");
    evm.genesis_insert_account(&sender, u128::MAX, 0, Vec::new(), Vec::new());
    (s, evm, contract)
}

#[test]
fn new_filter_changes_returns_new_logs() {
    let (s, evm, contract) = make_log_server();
    let new = make_request("eth_newFilter", vec![json!({})], json!(1));
    let id = s.handle(&new).result.unwrap().as_str().unwrap().to_string();

    // Seal block 1 with a log; the filter polls it.
    seal_log_block(&evm, 1, contract, primitives::Address([0; 20]), 0);
    let changes = make_request("eth_getFilterChanges", vec![json!(id.clone())], json!(2));
    let logs = s.handle(&changes).result.unwrap().as_array().unwrap().clone();
    assert_eq!(logs.len(), 1, "one LOG0 expected, got {logs:?}");
    assert_eq!(logs[0]["address"].as_str().unwrap(), format!("0x{}", hex::encode(contract.0)));
    assert_eq!(logs[0]["blockNumber"], json!("0x1"));

    // A second poll with no new block returns [].
    let again = make_request("eth_getFilterChanges", vec![json!(id)], json!(3));
    assert_eq!(s.handle(&again).result, Some(json!([])));
}

#[test]
fn new_filter_address_restriction_excludes_other_logs() {
    let (s, evm, _contract) = make_log_server();
    // Filter for a different contract — sees nothing.
    let new = make_request(
        "eth_newFilter",
        vec![json!({"address": format!("0x{}", hex::encode([0xBBu8; 20]))})],
        json!(1),
    );
    let id = s.handle(&new).result.unwrap().as_str().unwrap().to_string();
    seal_log_block(&evm, 1, primitives::Address([0xAA; 20]), primitives::Address([0; 20]), 0);
    let changes = make_request("eth_getFilterChanges", vec![json!(id)], json!(2));
    assert_eq!(s.handle(&changes).result, Some(json!([])));
}

#[test]
fn new_block_filter_changes_returns_real_hashes() {
    use executor::Module;
    use primitives::Height;
    let (s, evm) = make_evm_server();
    let new = make_request("eth_newBlockFilter", vec![], json!(1));
    let id = s.handle(&new).result.unwrap().as_str().unwrap().to_string();

    for h in 1..=2 {
        evm.begin_block(Height::new(h));
        evm.end_block(Height::new(h));
    }
    let changes = make_request("eth_getFilterChanges", vec![json!(id.clone())], json!(2));
    let hashes = s.handle(&changes).result.unwrap().as_array().unwrap().clone();
    assert_eq!(hashes.len(), 2);
    for hash in &hashes {
        assert_eq!(hash.as_str().unwrap().len(), 66, "real 32-byte block hash");
    }
    // The served heights match `eth_getBlockByNumber`.
    let b1 = make_request("eth_getBlockByNumber", vec![json!("0x1"), json!(false)], json!(3));
    assert_eq!(s.handle(&b1).result.unwrap()["hash"], hashes[0]);
}

#[test]
fn pending_tx_filter_drains_the_feed() {
    let s = make_server();
    let new = make_request("eth_newPendingTransactionFilter", vec![], json!(1));
    let id = s.handle(&new).result.unwrap().as_str().unwrap().to_string();

    let hash = B256::from([0xAB; 32]);
    s.record_pending_tx(hash);
    s.record_pending_tx(B256::from([0xCD; 32]));

    let changes = make_request("eth_getFilterChanges", vec![json!(id.clone())], json!(2));
    let hashes = s.handle(&changes).result.unwrap().as_array().unwrap().clone();
    assert_eq!(hashes.len(), 2);
    assert_eq!(hashes[0], json!(format!("0x{hash:x}")));

    // A second poll sees nothing new.
    let again = make_request("eth_getFilterChanges", vec![json!(id)], json!(3));
    assert_eq!(s.handle(&again).result, Some(json!([])));
}

#[test]
fn uninstall_filter_then_poll_fails() {
    let s = make_evm_server().0;
    let new = make_request("eth_newBlockFilter", vec![], json!(1));
    let id = s.handle(&new).result.unwrap().as_str().unwrap().to_string();

    let unsub = make_request("eth_uninstallFilter", vec![json!(id.clone())], json!(2));
    assert_eq!(s.handle(&unsub).result, Some(json!(true)));
    // Unknown after uninstall — geth's `filter not found`.
    let poll = make_request("eth_getFilterChanges", vec![json!(id.clone())], json!(3));
    let err = s.handle(&poll).error.expect("removed filter must error");
    assert_eq!(err.code, -32_000);
    assert_eq!(err.message, "filter not found");
    // Uninstalling again returns false.
    let unsub2 = make_request("eth_uninstallFilter", vec![json!(id)], json!(4));
    assert_eq!(s.handle(&unsub2).result, Some(json!(false)));
}

#[test]
fn get_filter_changes_unknown_id_errors() {
    let s = make_server();
    let req = make_request("eth_getFilterChanges", vec![json!("0xdead")], json!(1));
    let err = s.handle(&req).error.expect("unknown filter must error");
    assert_eq!(err.code, -32_000);
    assert_eq!(err.message, "filter not found");
}

#[test]
fn get_filter_logs_rejects_non_log_filter() {
    let s = make_evm_server().0;
    let new = make_request("eth_newBlockFilter", vec![], json!(1));
    let id = s.handle(&new).result.unwrap().as_str().unwrap().to_string();
    let req = make_request("eth_getFilterLogs", vec![json!(id.clone())], json!(2));
    let err = s.handle(&req).error.expect("block filter must error");
    assert_eq!(err.code, -32_000);
    // The block filter must still work afterwards.
    let poll = make_request("eth_getFilterChanges", vec![json!(id)], json!(3));
    assert!(s.handle(&poll).error.is_none());
}

#[test]
fn new_pending_transactions_subscription_pushes_hash() {
    let s = make_server();
    let (conn, mut rx) = ws_conn();
    let sub = make_request("eth_subscribe", vec![json!("newPendingTransactions")], json!(1));
    let id = s.handle_ws(&sub, &conn).result.unwrap().as_str().unwrap().to_string();

    let hash = B256::from([0x5A; 32]);
    s.record_pending_tx(hash);
    let text = rx.try_recv().expect("pending-tx notification must arrive");
    let notif: Value = serde_json::from_str(&text).expect("notification must be JSON");
    assert_eq!(notif["method"], json!("eth_subscription"));
    assert_eq!(notif["params"]["subscription"], json!(id));
    assert_eq!(notif["params"]["result"], json!(format!("0x{hash:x}")));
}

#[test]
fn eth_call_gas_above_block_limit_is_clamped_not_rejected() {
    let (s, _evm) = make_evm_server();
    let req = make_request(
        "eth_call",
        vec![
            json!({
                "to": "0x0000000000000000000000000000000000000000",
                // Way above the 10 GG block gas limit.
                "gas": "0x100000000000"
            }),
            json!("latest"),
        ],
        json!(1),
    );
    let resp = s.handle(&req);
    assert!(resp.error.is_none(), "clamped call must succeed: {:?}", resp.error);
    assert_eq!(resp.result, Some(json!("0x")));
}

// ---- txpool_* ---------------------------------------------------

/// A mock txpool provider returning a fixed item list.
struct MockTxpool {
    items: Vec<TxpoolItem>,
}

impl TxpoolProvider for MockTxpool {
    fn txpool_snapshot(&self) -> Vec<TxpoolItem> {
        // TxBytes is cheap to clone for tests; the provider
        // returns a fresh snapshot per call like the real
        // executor adapter.
        self.items
            .iter()
            .map(|i| TxpoolItem {
                sender: i.sender,
                nonce: i.nonce,
                envelope: TxBytes::new(i.envelope.as_bytes().to_vec()),
                pending: i.pending,
            })
            .collect()
    }
}

/// Build a signed EIP-1559 envelope for `TxpoolItem` tests.
fn signed_envelope(privkey: [u8; 32], nonce: u64) -> TxpoolItem {
    use evm::tx::{SignedTx, TxEip1559, TxFields, TxKind};
    use revm::primitives::{Address, Bytes, U256};

    let signed = SignedTx::sign_eip1559(
        TxEip1559 {
            fields: TxFields {
                nonce,
                gas_limit: 21_000,
                to: TxKind::Call(Address::from([0x42; 20])),
                value: U256::from(5u64),
                data: Bytes::new(),
                chain_id: 1,
            },
            max_fee_per_gas: U256::from(10_000_000_000u64),
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            access_list: Vec::new(),
        },
        &privkey,
    )
    .expect("signing must succeed");
    let sender = signed.recover_sender().expect("sender recovery");
    let raw = signed.encode_to_bytes();
    let envelope = evm::wrap_evm_tx_envelope(&sender, nonce, 10_000_000_000, &raw);
    TxpoolItem { sender, nonce, envelope: TxBytes::new(envelope), pending: false }
}

#[test]
fn txpool_status_reports_pending_and_queued_counts() {
    let mut s = make_server();
    let mut a = signed_envelope([0x01; 32], 0);
    a.pending = true;
    let mut b = signed_envelope([0x02; 32], 3);
    b.pending = false;
    s.set_txpool_provider(Arc::new(MockTxpool { items: vec![a, b] }));

    let resp = s.handle(&make_request("txpool_status", vec![], json!(1)));
    assert!(resp.error.is_none());
    assert_eq!(resp.result.unwrap(), json!({ "pending": "0x1", "queued": "0x1" }));
}

#[test]
fn txpool_content_groups_by_sender_and_nonce() {
    let mut s = make_server();
    let mut item = signed_envelope([0x01; 32], 0);
    item.pending = true;
    s.set_txpool_provider(Arc::new(MockTxpool { items: vec![item] }));

    let resp = s.handle(&make_request("txpool_content", vec![], json!(1)));
    let body = resp.result.unwrap();
    let pending = &body["pending"];
    // Exactly one sender bucket with a nonce-"0x0" tx object.
    let bucket = pending.as_object().expect("pending map");
    assert_eq!(bucket.len(), 1);
    let by_nonce = bucket.values().next().unwrap().as_object().unwrap();
    let tx = &by_nonce["0x0"];
    assert_eq!(tx["nonce"], json!("0x0"));
    assert_eq!(tx["value"], json!("0x5"));
    assert_eq!(tx["to"], json!("0x4242424242424242424242424242424242424242"));
    assert_eq!(tx["blockHash"], Value::Null);
    assert_eq!(tx["blockNumber"], Value::Null);
}

#[test]
fn txpool_inspect_returns_geth_summary_strings() {
    let mut s = make_server();
    let item = signed_envelope([0x01; 32], 0);
    s.set_txpool_provider(Arc::new(MockTxpool { items: vec![item] }));

    let resp = s.handle(&make_request("txpool_inspect", vec![], json!(1)));
    let body = resp.result.unwrap();
    let summary = body["queued"].as_object().unwrap().values().next().unwrap()["0x0"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(summary.contains("5 wei + 21000 gas"), "summary must be geth-shaped, got: {summary}");
}

#[test]
fn txpool_content_from_filters_to_one_sender() {
    let mut s = make_server();
    let keep = signed_envelope([0x01; 32], 0);
    let drop_item = signed_envelope([0x02; 32], 0);
    let keep_addr = format!("0x{}", hex::encode(keep.sender.0));
    s.set_txpool_provider(Arc::new(MockTxpool { items: vec![keep, drop_item] }));

    let resp = s.handle(&make_request("txpool_contentFrom", vec![json!(keep_addr)], json!(1)));
    let body = resp.result.unwrap();
    let total = body["pending"].as_object().unwrap().values().count()
        + body["queued"].as_object().unwrap().values().count();
    assert_eq!(total, 1, "only the requested sender's bucket survives");
}

#[test]
fn txpool_methods_error_without_provider() {
    let s = make_server();
    for method in ["txpool_status", "txpool_content", "txpool_inspect"] {
        let resp = s.handle(&make_request(method, vec![], json!(1)));
        assert_eq!(resp.error.unwrap().code, -32_000, "{method} must error when unbacked");
    }
}

// ---- JSON-RPC batch + request limits --------------------------------

/// A batch body must return one response per element, in order.
#[test]
fn batch_returns_one_response_per_element() {
    let s = make_server();
    let body = r#"[
            {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
            {"jsonrpc":"2.0","method":"net_version","params":[],"id":2},
            {"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":"three"}
        ]"#;
    let out: Value = serde_json::from_str(&s.handle_raw(body)).expect("batch response");
    let arr = out.as_array().expect("batch returns an array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["id"], json!(1));
    assert_eq!(arr[0]["result"], json!("0x1"));
    assert_eq!(arr[1]["id"], json!(2));
    assert_eq!(arr[2]["id"], json!("three"));
}

/// A batch with a malformed element still answers the rest —
/// the bad element gets -32600 Invalid Request (not -32700,
/// which is for unparseable bodies).
#[test]
fn batch_malformed_element_gets_invalid_request() {
    let s = make_server();
    let body = r#"[
            {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
            {"not":"a request","id":7},
            {"jsonrpc":"2.0","method":"net_version","params":[],"id":3}
        ]"#;
    let out: Value = serde_json::from_str(&s.handle_raw(body)).expect("batch response");
    let arr = out.as_array().expect("batch array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["result"], json!("0x1"));
    assert_eq!(arr[1]["id"], json!(7), "element id is preserved");
    assert_eq!(arr[1]["error"]["code"], json!(-32600));
    assert_eq!(arr[2]["result"], json!("1"), "net_version is decimal");
}

/// An empty batch is Invalid Request per JSON-RPC 2.0.
#[test]
fn batch_empty_array_is_invalid_request() {
    let s = make_server();
    let out: Value = serde_json::from_str(&s.handle_raw("[]")).expect("response");
    assert_eq!(out["error"]["code"], json!(-32600));
}

/// A batch over `MAX_BATCH_REQUESTS` is rejected as a whole with a
/// single limit error — not partially processed.
#[test]
fn batch_over_limit_rejected() {
    let s = make_server();
    let elements: Vec<Value> = (0..=MAX_BATCH_REQUESTS)
        .map(|i| json!({"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":i}))
        .collect();
    let body = serde_json::to_string(&elements).expect("serialize");
    let out: Value = serde_json::from_str(&s.handle_raw(&body)).expect("response");
    assert!(out.is_object(), "over-cap batch returns one error object");
    assert_eq!(out["error"]["code"], json!(-32005));
}

// ---- RPC surface leftovers --------------------------------------

/// `eth_pendingTransactions` returns only the pool's *pending*
/// (executable) entries as geth-shaped tx objects — `blockHash`,
/// `blockNumber`, `transactionIndex` null for unmined txs —
/// excluding queued entries behind nonce gaps.
#[test]
fn eth_pending_transactions_returns_pending_only() {
    let mut s = make_server();
    let mut pending = signed_envelope([0x01; 32], 0);
    pending.pending = true;
    let queued = signed_envelope([0x02; 32], 3); // pending: false
    s.set_txpool_provider(Arc::new(MockTxpool { items: vec![pending, queued] }));

    let resp = s.handle(&make_request("eth_pendingTransactions", vec![], json!(1)));
    let arr = resp.result.unwrap().as_array().unwrap().clone();
    assert_eq!(arr.len(), 1, "queued entries must be excluded");
    assert_eq!(arr[0]["nonce"], json!("0x0"));
    assert_eq!(arr[0]["to"], json!("0x4242424242424242424242424242424242424242"));
    assert_eq!(arr[0]["blockHash"], Value::Null);
    assert_eq!(arr[0]["blockNumber"], Value::Null);
    assert_eq!(arr[0]["transactionIndex"], Value::Null);
}

/// A node with no mempool attached has no pending txs to serve —
/// the method errors rather than silently returning `[]` (geth
/// parity: the method exists only when a txpool is present).
#[test]
fn eth_pending_transactions_without_pool_errors() {
    let s = make_server();
    let resp = s.handle(&make_request("eth_pendingTransactions", vec![], json!(1)));
    assert!(resp.error.is_some());
}

/// The filter registry is count-bounded (`filter-cap`): the
/// `MAX_FILTERS + 1`th live registration is refused, and
/// uninstalling one frees a slot.
#[test]
fn filter_cap_rejects_over_limit_and_frees_on_uninstall() {
    let s = make_server();
    let mut first_id = String::new();
    for i in 0..MAX_FILTERS {
        let req = make_request("eth_newPendingTransactionFilter", vec![], json!(i));
        let resp = s.handle(&req);
        let id = resp
            .result
            .as_ref()
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("filter {i} must register: {:?}", resp.error))
            .to_string();
        if i == 0 {
            first_id = id;
        }
    }
    let over = make_request("eth_newPendingTransactionFilter", vec![], json!(MAX_FILTERS));
    let err = s.handle(&over).error.expect("over-cap must error");
    assert_eq!(err.code, -32_000);
    assert!(err.message.contains("filter limit"), "msg: {}", err.message);

    // Uninstall frees a slot — the next registration succeeds.
    let unsub = make_request("eth_uninstallFilter", vec![json!(first_id)], json!(9000));
    assert_eq!(s.handle(&unsub).result, Some(json!(true)));
    let again = make_request("eth_newPendingTransactionFilter", vec![], json!(9001));
    assert!(s.handle(&again).error.is_none());
}

/// `eth_call` `stateOverride` (param 2): a `code` override makes
/// an EOA execute as a contract for the call's duration; the
/// authoritative state is untouched afterwards.
#[test]
fn eth_call_state_override_code_not_persisted() {
    use executor::Module;
    use primitives::Height;
    let (s, evm) = make_evm_server();
    // `0x4242…` is outside the native precompile range
    // (`0x0000…00XX`): a plain EOA that returns empty output.
    let target = "0x4242424242424242424242424242424242424243";
    evm.begin_block(Height::new(1));
    evm.end_block(Height::new(1));

    // Baseline: the account has no code → empty return.
    let plain = make_request("eth_call", vec![json!({"to": target}), json!("latest")], json!(1));
    let r = s.handle(&plain);
    assert_eq!(r.result, Some(json!("0x")), "err: {:?}", r.error);

    // Override code: `PUSH1 0x2a; PUSH1 0; MSTORE; PUSH1 0x20;
    // PUSH1 0; RETURN` — returns the word 42.
    let ovr = make_request(
        "eth_call",
        vec![
            json!({"to": target}),
            json!("latest"),
            json!({target: {"code": "0x602a60005260206000f3"}}),
        ],
        json!(2),
    );
    let resp = s.handle(&ovr);
    let out = resp.result.expect("override call must succeed");
    assert_eq!(out, json!(format!("0x{:064x}", 42)));

    // The override must not leak into state — still no code.
    let still = make_request("eth_getCode", vec![json!(target), json!("latest")], json!(3));
    assert_eq!(s.handle(&still).result, Some(json!("0x")));
}

/// `state` replaces the account's whole storage map while
/// `stateDiff` merges — observable on slots the override omits.
#[test]
fn eth_call_state_vs_statediff() {
    use executor::Module;
    use primitives::Height;
    use revm::primitives::U256;
    let (s, evm) = make_evm_server();
    let contract = primitives::Address([0xCC; 20]);
    // Runtime `PUSH1 0; SLOAD; PUSH1 0; MSTORE; PUSH1 0x20;
    // PUSH1 0; RETURN` — echoes storage slot 0. Real slot 0 = 7.
    evm.genesis_insert_account(
        &contract,
        0,
        1,
        hex::decode("60005460005260206000f3").expect("contract hex"),
        vec![(U256::ZERO, U256::from(7))],
    );
    evm.begin_block(Height::new(1));
    evm.end_block(Height::new(1));

    let target = "0xcccccccccccccccccccccccccccccccccccccccc";
    let call = |ovr: Value, id| {
        let req =
            make_request("eth_call", vec![json!({"to": target}), json!("latest"), ovr], json!(id));
        s.handle(&req).result.expect("call must succeed")
    };
    // Baseline: the real slot value.
    let plain = make_request("eth_call", vec![json!({"to": target}), json!("latest")], json!(1));
    assert_eq!(s.handle(&plain).result, Some(json!(format!("0x{:064x}", 7))));
    // stateDiff: slot 0 overridden → 42; unlisted slots keep
    // base values.
    assert_eq!(
        call(json!({target: {"stateDiff": {"0x00": "0x2a"}}}), 2),
        json!(format!("0x{:064x}", 42))
    );
    // state (replace): slot 0 not listed → reads 0 even though
    // base state has 7.
    assert_eq!(
        call(json!({target: {"state": {"0x05": "0x09"}}}), 3),
        json!(format!("0x{:064x}", 0))
    );
    // state + stateDiff together → invalid params (geth).
    let req = make_request(
        "eth_call",
        vec![
            json!({"to": target}),
            json!("latest"),
            json!({target: {"state": {}, "stateDiff": {}}}),
        ],
        json!(4),
    );
    let err = s.handle(&req).error.expect("conflict must error");
    assert_eq!(err.code, -32_602);
}

/// The `debug_*` namespace is opt-in: tracing re-executes blocks,
/// the heaviest calls on the endpoint, so a default server answers
/// method-not-found exactly as it would for an unregistered method.
#[test]
fn debug_api_off_by_default() {
    let (s, _evm) = make_evm_server();
    let req = make_request(
        "debug_traceCall",
        vec![json!({"to": "0x0000000000000000000000000000000000000001"}), json!("latest")],
        json!(1),
    );
    let err = s.handle(&req).error.expect("debug must error when disabled");
    assert_eq!(err.code, -32_601, "disabled debug namespace must read as method-not-found");
    // And an enabled server dispatches (the call may still fail on
    // params — but never with method-not-found).
    let s = s.with_debug_api(true);
    let resp = s.handle(&req);
    assert_ne!(
        resp.error.as_ref().map(|e| e.code),
        Some(-32_601),
        "with_debug_api must wire the namespace"
    );
}

/// geth nests `stateOverrides` inside the `debug_traceCall`
/// config object — it must be parsed from there, not param 3.
#[test]
fn debug_trace_call_applies_nested_state_overrides() {
    use executor::Module;
    use primitives::Height;
    let (s, evm) = make_evm_server();
    let s = s.with_debug_api(true);
    evm.begin_block(Height::new(1));
    evm.end_block(Height::new(1));

    let target = "0x4242424242424242424242424242424242424243";
    let req = make_request(
        "debug_traceCall",
        vec![
            json!({"to": target}),
            json!("latest"),
            json!({
                "tracer": "callTracer",
                "stateOverrides": {target: {"code": "0x602a60005260206000f3"}},
            }),
        ],
        json!(1),
    );
    let res = s.handle(&req).result.expect("trace must succeed");
    assert_eq!(res["output"], json!(format!("0x{:064x}", 42)));
    assert_eq!(res["type"], json!("CALL"));
}

/// `eth_gasPrice` / `eth_maxPriorityFeePerGas` quote the history
/// oracle — p60 of recent inclusion tips — not a stub constant.
#[test]
fn gas_price_oracle_samples_history() {
    use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
    use executor::Module;
    use primitives::Height;
    use revm::primitives::{Bytes, U256};

    let (s, evm) = make_evm_server();
    // Fund and recover the `[0x11;32]` sender.
    let probe = SignedTx::sign_legacy(
        TxLegacy {
            fields: TxFields {
                nonce: 0,
                gas_limit: 21_000,
                to: TxKind::Call(alloy_primitives::Address::ZERO),
                value: U256::ZERO,
                data: Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000u64),
        },
        &[0x11; 32],
    )
    .expect("sign");
    let sender = probe.recover_sender().expect("recover");
    evm.fund_account_for_test(&sender, u128::MAX / 2);

    // One block with legacy txs priced 1g/2g/3g. Legacy
    // effective price == gas_price, so the inclusion tips are
    // {price - base_fee(7)}: {999999993, 1999999993, 2999999993}.
    // The oracle's p60 of three samples is the middle one.
    let raws: Vec<Vec<u8>> = [(1u64, 1_000_000_000u64), (2, 2_000_000_000), (3, 3_000_000_000)]
        .iter()
        .enumerate()
        .map(|(nonce, (_, price))| {
            SignedTx::sign_legacy(
                TxLegacy {
                    fields: TxFields {
                        nonce: nonce as u64,
                        gas_limit: 21_000,
                        to: TxKind::Call(alloy_primitives::Address::ZERO),
                        value: U256::ZERO,
                        data: Bytes::new(),
                        chain_id: 1,
                    },
                    gas_price: U256::from(*price),
                },
                &[0x11; 32],
            )
            .expect("sign")
            .encode_to_bytes()
        })
        .collect();
    evm.begin_block(Height::new(1));
    let ctx = executor::TxContext { sender, nonce: 0, fee: 0 };
    for (i, r) in evm.handle_batch(&ctx, &raws).iter().enumerate() {
        assert!(r.is_ok(), "tx {i} must execute: {r:?}");
    }
    evm.end_block(Height::new(1));

    let tip = s.handle(&make_request("eth_maxPriorityFeePerGas", vec![], json!(1)));
    assert_eq!(tip.result, Some(json!(format!("0x{:x}", 1_999_999_993u64))));
    // gasPrice = latest base fee (7) + tip → 2_000_000_000.
    let price = s.handle(&make_request("eth_gasPrice", vec![], json!(2)));
    assert_eq!(price.result, Some(json!(format!("0x{:x}", 2_000_000_000u64))));
}

/// With an EVM attached but no sealed history the oracle falls
/// back to the configured base fee plus the 1-gwei default tip —
/// geth's `SuggestGasPrice` behavior on a young chain.
#[test]
fn gas_price_oracle_empty_history_fallback() {
    let (s, _evm) = make_evm_server();
    let price = s.handle(&make_request("eth_gasPrice", vec![], json!(1)));
    assert_eq!(price.result, Some(json!(format!("0x{:x}", 1_000_000_007u64))));
    let tip = s.handle(&make_request("eth_maxPriorityFeePerGas", vec![], json!(2)));
    assert_eq!(tip.result, Some(json!(format!("0x{:x}", 1_000_000_000u64))));
}

/// `eth_estimateGas` accepts the same `stateOverride` argument —
/// a code override makes the estimate include execution gas
/// instead of the plain-transfer intrinsic.
#[test]
fn eth_estimate_gas_applies_state_override() {
    use executor::Module;
    use primitives::Height;
    let (s, evm) = make_evm_server();
    evm.begin_block(Height::new(1));
    evm.end_block(Height::new(1));

    let target = "0x4242424242424242424242424242424242424243";
    // Baseline: call to a codeless account is intrinsic-only.
    let plain =
        make_request("eth_estimateGas", vec![json!({"to": target}), json!("latest")], json!(1));
    assert_eq!(s.handle(&plain).result, Some(json!("0x5208"))); // 21000

    // With the SLOAD+return contract as a code override the
    // estimate must cover the executed opcodes (> 21000).
    let ovr = make_request(
        "eth_estimateGas",
        vec![
            json!({"to": target}),
            json!("latest"),
            json!({target: {"code": "0x60005460005260206000f3"}}),
        ],
        json!(2),
    );
    let resp = s.handle(&ovr);
    let gas = resp.result.expect("estimate must succeed");
    let gas =
        u64::from_str_radix(gas.as_str().unwrap().trim_start_matches("0x"), 16).expect("hex gas");
    assert!(gas > 21_000, "override code must add execution gas, got {gas}");
}

// ---- oxide_sendRawTransaction (native signed envelopes) ----

/// A hex-encoded native envelope is decoded and submitted; the
/// returned hash is the domain-tagged BLAKE3 tx hash.
#[test]
fn oxide_send_raw_transaction_submits_envelope() {
    let mut s = make_server();
    let submitter = Arc::new(MockSubmitter::new());
    s.set_tx_submitter(submitter.clone());

    // [sender:20][nonce:8][fee:8][module_id|0x80][sig:65][payload]
    let mut raw = vec![0xAA; 20];
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.push(1 | 0x80);
    raw.extend_from_slice(&[0xBB; 65]);
    raw.extend_from_slice(b"payload");

    let req = make_request(
        "oxide_sendRawTransaction",
        vec![json!(format!("0x{}", hex::encode(&raw)))],
        json!(1),
    );
    let resp = s.handle(&req);
    assert!(resp.error.is_none(), "envelope should submit: {:?}", resp.error);
    let hash = resp.result.unwrap().as_str().unwrap().to_string();
    assert_eq!(hash.len(), 66);
    assert_eq!(submitter.count(), 1);
    assert_eq!(submitter.last().as_bytes(), raw.as_slice());
    // The returned hash is the BLAKE3 tx hash, not keccak256.
    let expected = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, &raw);
    assert_eq!(hash, format!("0x{}", hex::encode(expected.0)));
}

/// Bad hex is an invalid-params error; a submitter rejection
/// surfaces as a transaction-rejected error.
#[test]
fn oxide_send_raw_transaction_error_paths() {
    let mut s = make_server();
    let submitter = Arc::new(MockSubmitter::new());
    s.set_tx_submitter(submitter.clone());

    // Non-hex input.
    let req = make_request("oxide_sendRawTransaction", vec![json!("0xZZ")], json!(1));
    let resp = s.handle(&req);
    assert!(resp.error.is_some());
    assert_eq!(submitter.count(), 0);

    // Missing param.
    let req = make_request("oxide_sendRawTransaction", vec![], json!(2));
    assert!(s.handle(&req).error.is_some());

    // Submitter rejection surfaces as -32003 (transaction rejected).
    *primitives::sync::lock_state(&submitter.reject_next) = true;
    let req = make_request("oxide_sendRawTransaction", vec![json!("0xdeadbeef")], json!(3));
    let resp = s.handle(&req);
    assert!(resp.error.is_some(), "rejection must surface as error");
}

/// `cost_of` weights batches per element and methods by weight —
/// the admission charge must match the real work, not the request
/// count.
#[test]
fn cost_of_weights_batches_and_methods() {
    let s = make_server();
    // Single cheap read.
    let body = json!({"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1});
    assert_eq!(s.cost_of(&body), 1);
    // eth_call weighs 10.
    let call = json!({"jsonrpc": "2.0", "method": "eth_call", "params": [], "id": 1});
    assert_eq!(s.cost_of(&call), 10);
    // debug_* weighs 50 (even with the namespace disabled — the
    // cost check runs before dispatch).
    let dbg = json!({"jsonrpc": "2.0", "method": "debug_traceCall", "params": [], "id": 1});
    assert_eq!(s.cost_of(&dbg), 50);
    // Batch: 2 reads + 1 call = 12.
    let batch = json!([
        {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
        {"jsonrpc": "2.0", "method": "eth_call", "params": [], "id": 2},
        {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 3}
    ]);
    assert_eq!(s.cost_of(&batch), 12);
    // Malformed elements still cost 1 each.
    let weird = json!(["not a request", 42]);
    assert_eq!(s.cost_of(&weird), 2);
}

/// `handle_parsed` must answer identically to `handle_raw` — the
/// server parses once for costing, then dispatches the same body.
#[test]
fn handle_parsed_matches_handle_raw() {
    let s = make_server();
    let raw = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":7}"#;
    let parsed: Value = serde_json::from_str(raw).unwrap();
    assert_eq!(s.handle_parsed(&parsed), s.handle_raw(raw));
    // Batch parity too.
    let raw_batch = r#"[{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}]"#;
    let parsed: Value = serde_json::from_str(raw_batch).unwrap();
    assert_eq!(s.handle_parsed(&parsed), s.handle_raw(raw_batch));
}
