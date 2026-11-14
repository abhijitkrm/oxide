//! End-to-end orders/s over real loopback TCP for each authentication
//! scheme, through the multi-market matcher (batch endpoint, several
//! connections). Orders are signed/MAC'd before the clock starts, so
//! the number is the server's: decode, authenticate, replay-gate,
//! match, respond.
//!
//! ```sh
//! AUTH_ORDERS=200000 cargo test -p matcher --release --test e2e_auth_tps -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::too_many_lines)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crypto::ed25519::{Ed25519SecretKey, owner_address};
use matcher::auth::{
    AuthConfig, AuthKind, Authenticator, MarketScope, SessionOpen, certify, sign_order_evm,
    sign_order_session,
};
use matcher::control::encode_cert_batch;
use matcher::protocol::{
    CHAIN_ID, OrderRequest, RESPONSE_SIZE, decode_batch_response, encode_batch_request, sign_order,
};
use matcher::{AtomicBalanceCache, MultiMarketMatcher};
use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::{MarketConfig, OrderType, Side, TimeInForce};

const ACCOUNTS: usize = 64;
const CONNS: usize = 4;
const BATCH: usize = 500;

fn env(name: &str, d: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_millis()
        as u64
}

fn ed(seed: usize) -> Ed25519SecretKey {
    Ed25519SecretKey::from_bytes(&[(seed % 250) as u8 + 1; 32])
}

fn evm_key(seed: usize) -> [u8; 32] {
    let mut k = [1u8; 32];
    k[1] = (seed % 250) as u8 + 1;
    k
}

fn blank(i: usize) -> OrderRequest {
    OrderRequest {
        market: 0,
        // Alternate sell/buy at one price: every pair crosses (50% fills).
        side: if i.is_multiple_of(2) { Side::Sell } else { Side::Buy },
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce: (i / ACCOUNTS) as u64 + 1,
        owner: Address([0; 20]),
        pubkey: [0; 32],
        signature: [0; 64],
    }
}

fn addr_of(scheme: &str, a: usize) -> Address {
    match scheme {
        "evm" => crypto::secp::signable_pubkey_address(&evm_key(a)).expect("key"),
        _ => owner_address(&ed(a).verifying_key()),
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind").local_addr().expect("addr").port()
}

/// Run `orders` (already authenticated material) through the server in
/// `CONNS` connections, each owning the accounts `a % CONNS == c`.
fn drive(port: u16, per_conn: Vec<Vec<Vec<u8>>>) -> f64 {
    let start = Instant::now();
    let handles: Vec<_> = per_conn
        .into_iter()
        .map(|frames| {
            std::thread::spawn(move || {
                let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(60))).ok();
                s.set_nodelay(true).ok();
                let mut n = 0usize;
                for f in frames {
                    s.write_all(&f).expect("write");
                    let mut head = [0u8; 5];
                    s.read_exact(&mut head).expect("read");
                    let c = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
                    let mut body = vec![0u8; c * RESPONSE_SIZE];
                    s.read_exact(&mut body).expect("read");
                    let mut full = head.to_vec();
                    full.extend_from_slice(&body);
                    let r = decode_batch_response(&full).expect("resp");
                    assert!(
                        r.iter().all(|x| !x.rejected),
                        "unexpected reject: {:?}",
                        r.iter().find(|x| x.rejected)
                    );
                    n += c;
                }
                n
            })
        })
        .collect();
    let n: usize = handles.into_iter().map(|h| h.join().expect("conn")).sum();
    n as f64 / start.elapsed().as_secs_f64()
}

fn run(scheme: &str, n_orders: usize) -> f64 {
    let kind = match scheme {
        "ed25519_batch" => AuthKind::Ed25519Batch,
        "ed25519" => AuthKind::Ed25519,
        "evm" => AuthKind::Evm,
        "session_mac" => AuthKind::SessionMac,
        "certified" => AuthKind::Certified,
        _ => AuthKind::Multi,
    };
    let gw = Ed25519SecretKey::from_bytes(&[200; 32]);
    let cfg = AuthConfig {
        kind,
        evm_threads: 4,
        trusted_gateways: vec![gw.verifying_key().to_bytes()],
        audit_every: 64,
        ..AuthConfig::default()
    };
    let auth: Arc<dyn Authenticator> = cfg.build();

    // Capacity = accounts the lock-free tiers can hold (`--accounts-cap`). A
    // tiny value pushes every account onto the global-mutex overflow map.
    let balances = Arc::new(AtomicBalanceCache::new(ACCOUNTS * 16));
    for a in 0..ACCOUNTS {
        balances.set(&addr_of(scheme, a), 1_000_000_000_000_000);
    }
    let m = Arc::new(
        MultiMarketMatcher::new(
            vec![MarketConfig {
                market_id: 0,
                tick_size: Price(1_000_000),
                lot_size: Qty(1_000),
                min_price: Price(1_000_000_000),
                max_price: Price(2_000_000_000),
                max_resting: 1 << 16,
            }],
            balances,
        )
        .with_authenticator(Arc::clone(&auth)),
    );
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("rt");
    let port = free_port();
    rt.spawn(matcher::server::run_binary_tcp_server_multi(Arc::clone(&m), port));
    std::thread::sleep(Duration::from_millis(200));

    // Sessions (one per account), opened before the clock.
    let key = [0x5a; 32];
    let sessions: Vec<u32> = if scheme == "session_mac" {
        (0..ACCOUNTS)
            .map(|a| {
                auth.open_session(
                    &SessionOpen::sign_ed25519_until(
                        &ed(a),
                        key,
                        MarketScope::all(),
                        now_ms() + 3_600_000,
                        CHAIN_ID,
                    ),
                    CHAIN_ID,
                )
                .expect("open")
            })
            .collect()
    } else {
        Vec::new()
    };

    // Build and authenticate orders (untimed), grouped per connection by account.
    let mut by_conn: Vec<Vec<OrderRequest>> = vec![Vec::new(); CONNS];
    for i in 0..n_orders {
        let a = i % ACCOUNTS;
        let mut r = blank(i);
        match scheme {
            "evm" => sign_order_evm(&mut r, &evm_key(a), CHAIN_ID),
            "session_mac" => {
                r.owner = addr_of("ed", a);
                sign_order_session(&mut r, sessions[a], &key, CHAIN_ID);
            }
            _ => sign_order(&mut r, &ed(a)),
        }
        by_conn[a % CONNS].push(r);
    }
    let frames: Vec<Vec<Vec<u8>>> = by_conn
        .into_iter()
        .map(|orders| {
            orders
                .chunks(BATCH)
                .map(|c| {
                    if scheme == "certified" {
                        encode_cert_batch(&certify(&gw, c, CHAIN_ID), c)
                    } else {
                        encode_batch_request(c)
                    }
                })
                .collect()
        })
        .collect();
    drive(port, frames)
}

#[test]
#[ignore = "throughput measurement; run with --ignored --nocapture"]
fn auth_scheme_end_to_end_throughput() {
    let n = env("AUTH_ORDERS", 200_000);
    println!(
        "\n=== end-to-end orders/s by authentication scheme ({n} orders, {CONNS} conns, batch {BATCH}) ==="
    );
    for scheme in ["ed25519", "ed25519_batch", "evm", "session_mac", "certified", "multi"] {
        let r = run(scheme, n);
        println!("  {scheme:<14} {r:>12.0} orders/s");
    }
}
