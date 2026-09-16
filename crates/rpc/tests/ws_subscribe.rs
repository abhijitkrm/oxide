//! WebSocket `eth_subscribe`/`eth_unsubscribe` integration tests.
//!
//! These drive the real transport: an axum `WebSocketUpgrade` on
//! `GET /`, a `tokio-tungstenite` client, and the executor-sealed
//! block history feeding `publish_new_block`. This is the path a
//! MetaMask/ethers `Provider` uses for live updates (`newHeads`,
//! filtered `logs`).

use std::sync::Arc;
use std::time::Duration;

use evm::EvmModule;
use executor::Module;
use futures_util::{SinkExt, StreamExt};
use primitives::Height;
use rpc::RpcServer;
use rpc::server::HttpServer;
use serde_json::{Value, json};

/// Runtime code that emits `LOG0` with 32 bytes ending in 0x42:
/// `PUSH1 0x42 PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 LOG0`.
const LOG_CONTRACT: &str = "604260005260206000a0";

/// Deterministic test private key (same scheme as `evm_parity.rs`).
const PRIVKEY: [u8; 32] = [0x11; 32];

fn sign_call(privkey: &[u8; 32], nonce: u64, to: primitives::Address) -> Vec<u8> {
    let tx = evm::tx::TxLegacy {
        fields: evm::tx::TxFields {
            nonce,
            gas_limit: 30_000_000,
            to: evm::tx::TxKind::Call(alloy_primitives::Address::from(to.0)),
            value: revm::primitives::U256::ZERO,
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: revm::primitives::U256::from(1_000_000_000u64),
    };
    evm::tx::SignedTx::sign_legacy(tx, privkey).expect("sign").encode_to_bytes()
}

/// A running server: the `RpcServer` (with an EVM module that has
/// one sealed block containing a log-emitting call) plus its bound
/// WS URL.
struct WsHarness {
    rpc: Arc<RpcServer>,
    evm: Arc<EvmModule>,
    url: String,
    /// The log-emitting contract installed in genesis state.
    log_contract: primitives::Address,
    /// Sender funded at genesis; used to drive later blocks.
    sender: primitives::Address,
    /// Next block height to seal + publish.
    next_height: u64,
}

/// Build the server, seal block 1 (one LOG0-emitting call), and
/// start listening on an ephemeral port.
async fn spawn_harness() -> WsHarness {
    let evm = Arc::new(EvmModule::new(1, 7));
    let log_contract = primitives::Address([0xAA; 20]);
    evm.genesis_insert_account(
        &log_contract,
        0,
        1,
        hex::decode(LOG_CONTRACT).expect("contract hex"),
        Vec::new(),
    );
    // Recover the sender from a probe signature, then fund it.
    let probe = sign_call(&PRIVKEY, 0, log_contract);
    let sender =
        evm::tx::SignedTx::decode_raw(&probe).expect("decode").recover_sender().expect("recover");
    evm.genesis_insert_account(&sender, u128::MAX, 0, Vec::new(), Vec::new());

    let ctx = executor::TxContext { sender: primitives::Address([0; 20]), nonce: 0, fee: 0 };
    evm.begin_block(Height::new(1));
    let results = evm.handle_batch(&ctx, std::slice::from_ref(&probe));
    assert!(results[0].is_ok(), "block-1 tx must execute: {:?}", results[0]);
    evm.end_block(Height::new(1));

    let mut rpc = RpcServer::new(1, 7);
    rpc.set_evm(evm.clone());
    rpc.set_block_height(1);
    let rpc = Arc::new(rpc);

    // Reserve an ephemeral port, release it, and let the server bind
    // it. The close-then-bind race is standard practice for tests on
    // loopback; retries below absorb the rare collision.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("local addr")
        .port();
    let server = HttpServer::from_shared(rpc.clone(), format!("127.0.0.1:{port}"));
    tokio::spawn(server.serve());
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    WsHarness {
        rpc,
        evm,
        url: format!("ws://127.0.0.1:{port}"),
        log_contract,
        sender,
        next_height: 2,
    }
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Connect a real WebSocket client and perform the upgrade.
async fn connect(url: &str) -> WsStream {
    let (stream, resp) =
        tokio_tungstenite::connect_async(url).await.expect("websocket upgrade must succeed");
    assert_eq!(resp.status(), 101, "upgrade must return 101 Switching Protocols");
    stream
}

/// Send one JSON-RPC request over the socket and return the parsed
/// response.
async fn request(stream: &mut WsStream, method: &str, params: Vec<Value>) -> Value {
    stream
        .send(tokio_tungstenite::tungstenite::Message::Text(
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
                .to_string()
                .into(),
        ))
        .await
        .expect("send request");
    let msg = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("response must arrive within 5s")
        .expect("stream must stay open")
        .expect("frame must be valid");
    serde_json::from_str(msg.to_text().expect("response must be text"))
        .expect("response must be JSON")
}

/// Seal block `h.next_height` (containing one log-emitting call)
/// and publish it to subscribers.
fn seal_and_publish(h: &mut WsHarness) {
    let call = sign_call(&PRIVKEY, h.next_height - 1, h.log_contract);
    let ctx = executor::TxContext { sender: h.sender, nonce: 0, fee: 0 };
    let height = Height::new(h.next_height);
    h.evm.begin_block(height);
    let results = h.evm.handle_batch(&ctx, &[call]);
    assert!(results[0].is_ok(), "tx must execute: {:?}", results[0]);
    h.evm.end_block(height);
    h.rpc.publish_new_block(h.next_height);
    h.next_height += 1;
}

/// Read the next text frame as JSON within a timeout.
async fn next_json(stream: &mut WsStream, timeout: Duration) -> Option<Value> {
    match tokio::time::timeout(timeout, stream.next()).await {
        Ok(Some(Ok(msg))) => serde_json::from_str(msg.to_text().ok()?).ok(),
        _ => None,
    }
}

#[tokio::test]
async fn ws_new_heads_pushes_finalized_headers() {
    let mut h = spawn_harness().await;
    let mut ws = connect(&h.url).await;

    let resp = request(&mut ws, "eth_subscribe", vec![json!("newHeads")]).await;
    let sub_id = resp["result"].as_str().expect("subscribe must return an id").to_string();
    assert!(sub_id.starts_with("0x"));

    seal_and_publish(&mut h);
    let notif = next_json(&mut ws, Duration::from_secs(5))
        .await
        .expect("newHeads notification must arrive");
    assert_eq!(notif["method"], json!("eth_subscription"));
    assert_eq!(notif["params"]["subscription"], json!(sub_id));
    let header = &notif["params"]["result"];
    assert_eq!(header["number"], json!("0x2"));
    assert_eq!(header["hash"].as_str().unwrap().len(), 66);
    assert_eq!(header["parentHash"].as_str().unwrap().len(), 66);
}

#[tokio::test]
async fn ws_logs_pushes_matching_entries() {
    let mut h = spawn_harness().await;
    let mut ws = connect(&h.url).await;

    // Subscribe to logs from the harness contract only.
    let filter = json!({"address": format!("0x{}", hex::encode(h.log_contract.0))});
    let resp = request(&mut ws, "eth_subscribe", vec![json!("logs"), filter]).await;
    let sub_id = resp["result"].as_str().expect("subscribe must return an id").to_string();

    seal_and_publish(&mut h);
    let notif =
        next_json(&mut ws, Duration::from_secs(5)).await.expect("logs notification must arrive");
    assert_eq!(notif["method"], json!("eth_subscription"));
    assert_eq!(notif["params"]["subscription"], json!(sub_id));
    let log = &notif["params"]["result"];
    assert_eq!(
        log["address"].as_str().unwrap().to_lowercase(),
        format!("0x{}", hex::encode(h.log_contract.0)).to_lowercase()
    );
    assert_eq!(log["blockNumber"], json!("0x2"));
    assert!(log["transactionHash"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
async fn ws_unsubscribe_stops_notifications() {
    let mut h = spawn_harness().await;
    let mut ws = connect(&h.url).await;

    let resp = request(&mut ws, "eth_subscribe", vec![json!("newHeads")]).await;
    let sub_id = resp["result"].as_str().unwrap().to_string();

    let unsub = request(&mut ws, "eth_unsubscribe", vec![json!(sub_id)]).await;
    assert_eq!(unsub["result"], json!(true));
    // A second unsubscribe reports the ID is gone.
    let again = request(&mut ws, "eth_unsubscribe", vec![json!(sub_id)]).await;
    assert_eq!(again["result"], json!(false));

    seal_and_publish(&mut h);
    assert!(
        next_json(&mut ws, Duration::from_millis(500)).await.is_none(),
        "unsubscribed connection must not receive notifications"
    );
}

#[tokio::test]
async fn ws_serves_ordinary_methods_and_rejects_bad_json() {
    let h = spawn_harness().await;
    let mut ws = connect(&h.url).await;

    // Ordinary methods work over WS identically to HTTP.
    let resp = request(&mut ws, "eth_chainId", vec![]).await;
    assert_eq!(resp["result"], json!("0x1"));
    let resp = request(&mut ws, "eth_blockNumber", vec![]).await;
    assert_eq!(resp["result"], json!("0x1"));

    // Malformed JSON gets a -32700 parse error response.
    ws.send(tokio_tungstenite::tungstenite::Message::Text("{not json".into()))
        .await
        .expect("send malformed");
    let resp = next_json(&mut ws, Duration::from_secs(5)).await.expect("parse error response");
    assert_eq!(resp["error"]["code"], json!(-32700));
}

#[tokio::test]
async fn ws_subscribe_rejects_unknown_type() {
    let h = spawn_harness().await;
    let mut ws = connect(&h.url).await;
    let resp = request(&mut ws, "eth_subscribe", vec![json!("syncing")]).await;
    assert_eq!(resp["error"]["code"], json!(-32602));
}
