//! End-to-end over real loopback TCP: session open/close frames, MAC
//! orders under a session, expiry, JSON-RPC session methods, and
//! gateway-certified batches, all against the real multi-market matcher
//! with the `multi` authenticator.

#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crypto::ed25519::{Ed25519SecretKey, owner_address};
use matcher::auth::{
    AuthConfig, AuthKind, MarketScope, SessionClose, SessionOpen, certify, sign_order_evm,
    sign_order_session,
};
use matcher::control::{
    Status, decode_session_response, encode_cert_batch, encode_session_close, encode_session_open,
};
use matcher::protocol::{
    CHAIN_ID, OrderRequest, RESPONSE_SIZE, RejectReason, decode_batch_response, decode_response,
    encode_request, sign_order,
};
use matcher::{AtomicBalanceCache, MultiMarketMatcher};
use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::{MarketConfig, OrderType, Side, TimeInForce};

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_millis()
        as u64
}

fn ed(seed: u8) -> (Ed25519SecretKey, Address) {
    let sk = Ed25519SecretKey::from_bytes(&[seed; 32]);
    let a = owner_address(&sk.verifying_key());
    (sk, a)
}

fn blank(nonce: u64, price: u64) -> OrderRequest {
    OrderRequest {
        market: 0,
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(price),
        qty: Qty(1_000),
        nonce,
        owner: Address([0; 20]),
        pubkey: [0; 32],
        signature: [0; 64],
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind").local_addr().expect("addr").port()
}

fn connect(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            s.set_read_timeout(Some(Duration::from_secs(5))).ok();
            return s;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("server on {port} did not come up");
}

fn exchange(s: &mut TcpStream, frame: &[u8]) -> [u8; 5] {
    s.write_all(frame).expect("write");
    let mut r = [0u8; 5];
    s.read_exact(&mut r).expect("read");
    r
}

fn place(s: &mut TcpStream, req: &OrderRequest) -> matcher::protocol::OrderResponse {
    s.write_all(&encode_request(req)).expect("write");
    let mut r = [0u8; RESPONSE_SIZE];
    s.read_exact(&mut r).expect("read");
    decode_response(&r).expect("decode")
}

struct Rig {
    tcp: u16,
    rpc: u16,
    _rt: tokio::runtime::Runtime,
}

fn start(gateway: &Ed25519SecretKey, accounts: &[Address]) -> Rig {
    let balances = Arc::new(AtomicBalanceCache::new(8));
    for a in accounts {
        balances.set(a, 1_000_000_000_000);
    }
    let cfg = AuthConfig {
        kind: AuthKind::Multi,
        trusted_gateways: vec![gateway.verifying_key().to_bytes()],
        audit_every: 1,
        ..AuthConfig::default()
    };
    let m = Arc::new(
        MultiMarketMatcher::new(
            vec![MarketConfig {
                market_id: 0,
                tick_size: Price(1_000_000),
                lot_size: Qty(1_000),
                min_price: Price(1_000_000_000),
                max_price: Price(2_000_000_000),
                max_resting: 1 << 14,
            }],
            balances,
        )
        .with_authenticator(cfg.build()),
    );
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("rt");
    let (tcp, rpc) = (free_port(), free_port());
    rt.spawn(matcher::server::run_binary_tcp_server_multi(Arc::clone(&m), tcp));
    rt.spawn(matcher::server::run_jsonrpc_tcp_server_multi(Arc::clone(&m), rpc));
    Rig { tcp, rpc, _rt: rt }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(String::new(), |mut acc, x| {
        let _ = write!(acc, "{x:02x}");
        acc
    })
}

#[test]
fn session_lifecycle_over_the_binary_protocol() {
    let (gw, _) = ed(99);
    let (sk, owner) = ed(7);
    let (other, _) = ed(8);
    let rig = start(&gw, &[owner]);
    let mut c = connect(rig.tcp);
    let key = [0x33; 32];

    // Open (expires in an hour; the default cap is 24h and refuses "never").
    let open = SessionOpen::sign_ed25519_until(
        &sk,
        key,
        MarketScope::only(&[0]),
        now_ms() + 3_600_000,
        CHAIN_ID,
    );
    let (status, id) =
        decode_session_response(&exchange(&mut c, &encode_session_open(&open))).expect("resp");
    assert_eq!(status, Status::Ok);

    let mac_order = |nonce| {
        let mut r = blank(nonce, 1_500_000_000);
        r.owner = owner;
        sign_order_session(&mut r, id, &key, CHAIN_ID);
        r
    };
    let r = place(&mut c, &mac_order(1));
    assert!(!r.rejected, "a MAC order under the open session rests: {r:?}");

    // Someone else cannot close it; it stays usable.
    let bad_close = SessionClose::sign_ed25519(&other, id, CHAIN_ID);
    let (status, _) = decode_session_response(&exchange(&mut c, &encode_session_close(&bad_close)))
        .expect("resp");
    assert_eq!(status, Status::BadAuthorization);
    assert!(!place(&mut c, &mac_order(2)).rejected);

    // The owner closes it; the next order is refused.
    let close = SessionClose::sign_ed25519(&sk, id, CHAIN_ID);
    let (status, _) =
        decode_session_response(&exchange(&mut c, &encode_session_close(&close))).expect("resp");
    assert_eq!(status, Status::Ok);
    let r = place(&mut c, &mac_order(3));
    assert_eq!(r.reject_reason, Some(RejectReason::BadSignature));
    let (status, _) =
        decode_session_response(&exchange(&mut c, &encode_session_close(&close))).expect("resp");
    assert_eq!(status, Status::NotFound);

    // A never-expiring open is refused by the default lifetime cap.
    let forever = SessionOpen::sign_ed25519(&sk, key, MarketScope::all(), CHAIN_ID);
    let (status, _) =
        decode_session_response(&exchange(&mut c, &encode_session_open(&forever))).expect("resp");
    assert_eq!(status, Status::BadExpiry);
    // A forged open (claims someone else's account) is refused.
    let mut forged =
        SessionOpen::sign_ed25519_until(&sk, key, MarketScope::all(), now_ms() + 60_000, CHAIN_ID);
    forged.owner = Address([5; 20]);
    let (status, _) =
        decode_session_response(&exchange(&mut c, &encode_session_open(&forged))).expect("resp");
    assert_eq!(status, Status::BadAuthorization);
}

#[test]
fn sessions_expire_on_the_real_clock() {
    let (gw, _) = ed(99);
    let (sk, owner) = ed(7);
    let rig = start(&gw, &[owner]);
    let mut c = connect(rig.tcp);
    let key = [0x44; 32];
    let open =
        SessionOpen::sign_ed25519_until(&sk, key, MarketScope::all(), now_ms() + 700, CHAIN_ID);
    let (status, id) =
        decode_session_response(&exchange(&mut c, &encode_session_open(&open))).expect("resp");
    assert_eq!(status, Status::Ok);
    let mut order = |nonce| {
        let mut r = blank(nonce, 1_500_000_000);
        r.owner = owner;
        sign_order_session(&mut r, id, &key, CHAIN_ID);
        place(&mut c, &r)
    };
    assert!(!order(1).rejected);
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(order(2).reject_reason, Some(RejectReason::BadSignature), "expired");
}

#[test]
fn sessions_over_json_rpc() {
    let (gw, _) = ed(99);
    let (sk, owner) = ed(7);
    let rig = start(&gw, &[owner]);
    let s = connect(rig.rpc);
    let mut w = s.try_clone().expect("clone");
    let mut r = BufReader::new(s);
    let mut call = |method: &str, frame: &[u8]| -> serde_json::Value {
        let line = format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"{method}\",\"params\":{{\"frame\":\"{}\"}},\"id\":1}}\n",
            hex(frame)
        );
        w.write_all(line.as_bytes()).expect("write");
        let mut out = String::new();
        r.read_line(&mut out).expect("read");
        serde_json::from_str(&out).expect("json")
    };
    let open = SessionOpen::sign_ed25519_until(
        &sk,
        [9; 32],
        MarketScope::all(),
        now_ms() + 60_000,
        CHAIN_ID,
    );
    let v = call("oxide_openSession", &open.to_bytes());
    assert_eq!(v["result"]["status"], "ok", "{v}");
    let id = v["result"]["session_id"].as_u64().expect("id") as u32;
    let v = call("oxide_closeSession", &SessionClose::sign_ed25519(&sk, id, CHAIN_ID).to_bytes());
    assert_eq!(v["result"]["status"], "ok", "{v}");
    let v = call("oxide_closeSession", &SessionClose::sign_ed25519(&sk, id, CHAIN_ID).to_bytes());
    assert!(v["error"]["message"].as_str().expect("msg").contains("NotFound"), "{v}");
    let v = call("oxide_openSession", &[1, 2, 3]);
    assert!(v["error"]["message"].as_str().expect("msg").contains("Malformed"), "{v}");
}

#[test]
fn certified_batches_over_tcp_and_other_credentials_alongside() {
    let (gw, _) = ed(99);
    let (rogue, _) = ed(98);
    let (_, a1) = ed(1);
    let (_, a2) = ed(2);
    let evm_key = {
        let mut k = [4u8; 32];
        k[0] = 1;
        k
    };
    let evm_addr = crypto::secp::signable_pubkey_address(&evm_key).expect("key");
    let rig = start(&gw, &[a1, a2, evm_addr]);
    let mut c = connect(rig.tcp);

    // A gateway-certified batch of ed25519 orders: all admitted.
    let mut batch: Vec<OrderRequest> = (1..=2u8)
        .map(|s| {
            let mut r = blank(1, 1_500_000_000);
            sign_order(&mut r, &ed(s).0);
            r
        })
        .collect();
    let cert = certify(&gw, &batch, CHAIN_ID);
    c.write_all(&encode_cert_batch(&cert, &batch)).expect("write");
    let mut head = [0u8; 5];
    c.read_exact(&mut head).expect("read");
    let n = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let mut body = vec![0u8; n * RESPONSE_SIZE];
    c.read_exact(&mut body).expect("read");
    let mut full = head.to_vec();
    full.extend_from_slice(&body);
    let resp = decode_batch_response(&full).expect("batch response");
    assert!(resp.iter().all(|r| !r.rejected), "certified batch admitted: {resp:?}");

    // A batch certified by an untrusted gateway is refused wholesale.
    batch.iter_mut().enumerate().for_each(|(i, r)| {
        r.nonce = 2;
        sign_order(r, &ed(i as u8 + 1).0);
    });
    let bad = certify(&rogue, &batch, CHAIN_ID);
    c.write_all(&encode_cert_batch(&bad, &batch)).expect("write");
    c.read_exact(&mut head).expect("read");
    let n = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let mut body = vec![0u8; n * RESPONSE_SIZE];
    c.read_exact(&mut body).expect("read");
    let mut full = head.to_vec();
    full.extend_from_slice(&body);
    let resp = decode_batch_response(&full).expect("batch response");
    assert!(resp.iter().all(|r| r.reject_reason == Some(RejectReason::BadSignature)));

    // The same connection also takes an EVM-signed order (multi accepts both).
    let mut e = blank(1, 1_500_000_000);
    sign_order_evm(&mut e, &evm_key, CHAIN_ID);
    assert!(!place(&mut c, &e).rejected);
}

// ── single-market servers: mutex mode and ring mode ────────────────

use matcher::{MatchingServer, RingMatcher, SharedMatcher};

fn single_market() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 14,
    }
}

fn single_server(gateway: &Ed25519SecretKey, funded: &[Address]) -> MatchingServer {
    let mut server = MatchingServer::new(single_market(), 16);
    for a in funded {
        server.fund_account(a, 1_000_000_000_000);
    }
    let cfg = AuthConfig {
        kind: AuthKind::Multi,
        trusted_gateways: vec![gateway.verifying_key().to_bytes()],
        audit_every: 1,
        ..AuthConfig::default()
    };
    server.set_authenticator(cfg.build());
    server
}

/// The same lifecycle on a single-market server: session open, a MAC
/// order, a certified batch, owner close, then refusal.
fn single_market_lifecycle(
    port: u16,
    owner: Address,
    sk: &Ed25519SecretKey,
    gw: &Ed25519SecretKey,
) {
    let mut c = connect(port);
    let key = [0x21; 32];
    let open = SessionOpen::sign_ed25519_until(
        sk,
        key,
        MarketScope::all(),
        now_ms() + 3_600_000,
        CHAIN_ID,
    );
    let (status, id) =
        decode_session_response(&exchange(&mut c, &encode_session_open(&open))).expect("resp");
    assert_eq!(status, Status::Ok);
    let mut r = blank(1, 1_500_000_000);
    r.owner = owner;
    sign_order_session(&mut r, id, &key, CHAIN_ID);
    assert!(!place(&mut c, &r).rejected);

    // Certified batch (an ed25519 order from the same owner, next nonce).
    let mut b = blank(2, 1_500_000_000);
    sign_order(&mut b, sk);
    let batch = [b];
    let cert = certify(gw, &batch, CHAIN_ID);
    c.write_all(&encode_cert_batch(&cert, &batch)).expect("write");
    let mut head = [0u8; 5];
    c.read_exact(&mut head).expect("read");
    let mut body = [0u8; RESPONSE_SIZE];
    c.read_exact(&mut body).expect("read");
    let mut full = head.to_vec();
    full.extend_from_slice(&body);
    assert!(!decode_batch_response(&full).expect("resp")[0].rejected);

    let close = SessionClose::sign_ed25519(sk, id, CHAIN_ID);
    let (status, _) =
        decode_session_response(&exchange(&mut c, &encode_session_close(&close))).expect("resp");
    assert_eq!(status, Status::Ok);
    let mut r = blank(3, 1_500_000_000);
    r.owner = owner;
    sign_order_session(&mut r, id, &key, CHAIN_ID);
    assert_eq!(place(&mut c, &r).reject_reason, Some(RejectReason::BadSignature));
}

#[test]
fn single_market_mutex_server_handles_control_frames() {
    let (gw, _) = ed(99);
    let (sk, owner) = ed(7);
    let shared = Arc::new(SharedMatcher::new(single_server(&gw, &[owner])));
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("rt");
    let port = free_port();
    rt.spawn(matcher::server::run_binary_tcp_server(shared, port));
    single_market_lifecycle(port, owner, &sk, &gw);
}

#[test]
fn single_market_ring_server_handles_control_frames() {
    let (gw, _) = ed(99);
    let (sk, owner) = ed(7);
    let server = single_server(&gw, &[owner]);
    let shared = Arc::new(SharedMatcher::new(single_server(&gw, &[owner])));
    let ring = Arc::new(RingMatcher::new(server, 4, 1024, None));
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("rt");
    let port = free_port();
    rt.spawn(matcher::server::run_binary_tcp_server_ring(
        shared,
        ring,
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        port,
    ));
    single_market_lifecycle(port, owner, &sk, &gw);
}
