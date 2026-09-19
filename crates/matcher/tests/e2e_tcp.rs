//! End-to-end matching server benchmark: client → TCP → match → settle.
//!
//! Spawns the binary TCP matching server, connects a client, submits
//! orders through the TCP socket, and measures end-to-end throughput
//! including network I/O, balance checks, matching, and settlement.
//!
//! The batch settler is wired to a mock submitter that counts
//! settlement txs. This measures the full off-chain path with real
//! TCP network overhead.
//!
//! # Running
//!
//! ```sh
//! # Default: 10M orders through TCP, 10k accounts
//! cargo test -p matcher --release --test e2e_tcp -- --ignored --nocapture
//!
//! # Custom: 100M orders with 100k accounts
//! E2E_ORDERS=100_000_000 E2E_ACCOUNTS=100_000 \
//!   cargo test -p matcher --release --test e2e_tcp -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use crypto::ed25519::{Ed25519SecretKey, owner_address};
use matcher::protocol::{OrderRequest, decode_response, encode_request, sign_order};
use matcher::{MatchingServer, SharedMatcher};
use primitives::fixed::{Price, Qty};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use trading::{MarketConfig, OrderType, Side, TimeInForce};

/// Parse an env var as a usize, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: 1_000_000,
        lot_size: 1_000,
        min_price: 1_000_000_000,
        max_price: 2_000_000_000,
        max_resting: 1 << 16,
    }
}

fn addr_from_index(i: u32) -> primitives::Address {
    let mut addr = [0u8; 20];
    addr[..4].copy_from_slice(&i.to_le_bytes());
    primitives::Address(addr)
}

/// Deterministic per-account signing key — account `i` is an Ed25519
/// key whose owner address is derived. The admission boundary
/// requires every order to carry a valid signature over a request
/// whose `owner` equals `owner_address(pubkey)`.
fn account_key(i: u32) -> Ed25519SecretKey {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&i.to_le_bytes());
    Ed25519SecretKey::from_bytes(&seed)
}

/// Submit a maker sell + taker buy pair through a TCP socket.
/// Each order is signed by the account's key with that account's
/// next nonce. Returns `(fills, rejections)`.
async fn submit_pair(
    sock: &mut TcpStream,
    buf: &mut [u8],
    seller_key: &Ed25519SecretKey,
    seller_nonce: u64,
    buyer_key: &Ed25519SecretKey,
    buyer_nonce: u64,
) -> (u64, u64) {
    let mut maker = OrderRequest {
        market: 0,
        side: Side::Sell,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce: seller_nonce,
        owner: addr_from_index(0),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    sign_order(&mut maker, seller_key);
    sock.write_all(&encode_request(&maker)).await.expect("write maker");
    sock.read_exact(buf).await.expect("read maker resp");
    let resp = decode_response(buf).expect("decode maker resp");
    let (mut fills, mut rejects) =
        if resp.rejected { (0, 1) } else { (u64::from(resp.fills_count), 0) };

    let mut taker = OrderRequest {
        market: 0,
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce: buyer_nonce,
        owner: addr_from_index(0),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    sign_order(&mut taker, buyer_key);
    sock.write_all(&encode_request(&taker)).await.expect("write taker");
    sock.read_exact(buf).await.expect("read taker resp");
    let resp = decode_response(buf).expect("decode taker resp");
    if resp.rejected {
        rejects += 1;
    } else {
        fills += u64::from(resp.fills_count);
    }
    (fills, rejects)
}

/// A mock tx submitter that counts submissions.
struct CountingSubmitter {
    count: std::sync::atomic::AtomicU64,
}

impl CountingSubmitter {
    fn new() -> Self {
        Self { count: std::sync::atomic::AtomicU64::new(0) }
    }

    fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl matcher::server::TxSubmitter for CountingSubmitter {
    fn submit_tx(&self, _tx: types::TxBytes) -> Result<(), String> {
        self.count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// End-to-end TCP benchmark: client → binary TCP → match → settle.
#[tokio::test]
#[ignore = "long-running e2e TCP benchmark; run with --release --ignored --nocapture"]
async fn e2e_tcp_benchmark() {
    let n_orders = env_usize("E2E_ORDERS", 10_000_000);
    let n_accounts = env_usize("E2E_ACCOUNTS", 10_000);
    let initial_balance = 1_000_000_000_000u64;
    let port = 36100u16;

    eprintln!("e2e: {n_orders} orders, {n_accounts} accounts, port {port}");

    // Setup: create the matching server, fund accounts. Each account
    // is an Ed25519 key — the funded address is the key's derived
    // owner, and every order is signed by that key.
    eprintln!("e2e: funding {n_accounts} accounts...");
    let account_keys: Vec<Ed25519SecretKey> =
        (0..u32::try_from(n_accounts).unwrap_or(u32::MAX)).map(account_key).collect();
    let mut server = MatchingServer::new(cfg(), n_accounts);
    for key in &account_keys {
        server.fund_account(&owner_address(&key.verifying_key()), initial_balance);
    }
    let shared = Arc::new(SharedMatcher::new(server));

    // Start the batch settler with a mock submitter.
    let counter = Arc::new(CountingSubmitter::new());
    let submitter: Arc<dyn matcher::server::TxSubmitter> =
        Arc::clone(&counter) as Arc<dyn matcher::server::TxSubmitter>;
    let sealer: Arc<dyn matcher::BatchSealer> =
        Arc::clone(&shared) as Arc<dyn matcher::BatchSealer>;
    let settler = Arc::new(matcher::server::BatchSettler::new(
        sealer,
        Arc::clone(&submitter),
        100, // 100ms batch interval.
        addr_from_index(0),
        0,
    ));
    let settler_clone = Arc::clone(&settler);
    tokio::spawn(async move {
        settler_clone.run().await;
    });

    // Start the binary TCP server.
    let tcp_matcher = Arc::clone(&shared);
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server(tcp_matcher, port).await;
    });

    // Give the server a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect a client.
    eprintln!("e2e: connecting to 127.0.0.1:{port}...");
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect to TCP server");

    // Pre-build all order requests.
    eprintln!("e2e: building {n_orders} order requests...");
    let n_pairs = n_orders / 2;
    let n_accounts_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);

    // Run the benchmark: submit orders via TCP.
    eprintln!("e2e: running {n_orders} orders through TCP...");
    let start = Instant::now();

    let mut buf = [0u8; matcher::protocol::RESPONSE_SIZE];
    let mut fills = 0u64;
    let mut rejections = 0u64;
    // Per-account nonce counters — each account's nonces must be
    // strictly increasing across every request it signs.
    let mut nonces = vec![0u64; n_accounts];

    for i in 0..n_pairs {
        let seller_idx = (u32::try_from(2 * i).unwrap_or(u32::MAX) % n_accounts_u32) as usize;
        let buyer_idx = (u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_accounts_u32) as usize;
        let seller_nonce = nonces[seller_idx];
        nonces[seller_idx] += 1;
        let buyer_nonce = nonces[buyer_idx];
        nonces[buyer_idx] += 1;

        let (f, r) = submit_pair(
            &mut sock,
            &mut buf,
            &account_keys[seller_idx],
            seller_nonce,
            &account_keys[buyer_idx],
            buyer_nonce,
        )
        .await;
        fills += f;
        rejections += r;
    }

    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();

    // Wait for the batch settler to flush.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let stats = shared.stats();
    let settled_txs = counter.count();

    eprintln!();
    eprintln!("=== End-to-End TCP Benchmark Results ===");
    eprintln!("  orders:            {n_orders}");
    eprintln!("  accounts:         {n_accounts}");
    eprintln!("  fills (client):   {fills}");
    eprintln!("  rejections:        {rejections}");
    eprintln!("  orders processed:  {}", stats.orders_processed);
    eprintln!("  fills (server):   {}", stats.fills_produced);
    eprintln!("  balance rejects:   {}", stats.balance_rejections);
    eprintln!("  resting count:     {}", stats.resting_count);
    eprintln!("  settlement txs:    {settled_txs}");
    eprintln!("  elapsed:           {:.3}s", elapsed.as_secs_f64());
    eprintln!("  throughput:        {tps:.0} orders/s (TCP round-trip)");
    eprintln!("==========================================");

    // Integrity checks.
    assert_eq!(
        stats.orders_processed as usize, n_orders,
        "all {n_orders} orders must be processed"
    );
    assert_eq!(rejections, 0, "no rejections expected (accounts well-funded)");
    assert_eq!(stats.resting_count, 0, "all makers should be matched");
    assert!(settled_txs > 0, "batch settler should have submitted at least one settlement tx");

    eprintln!("e2e: all checks passed ✓");
}

/// Smoke test: 100k orders through TCP.
#[tokio::test]
#[ignore = "e2e TCP smoke test; run with --release --ignored --nocapture"]
async fn e2e_tcp_smoke() {
    let n_orders = env_usize("E2E_ORDERS", 100_000);
    let n_accounts = env_usize("E2E_ACCOUNTS", 100);
    let initial_balance = 1_000_000_000_000u64;
    let port = 36110u16;

    let account_keys: Vec<Ed25519SecretKey> =
        (0..u32::try_from(n_accounts).unwrap_or(u32::MAX)).map(account_key).collect();
    let mut server = MatchingServer::new(cfg(), n_accounts);
    for key in &account_keys {
        server.fund_account(&owner_address(&key.verifying_key()), initial_balance);
    }
    let shared = Arc::new(SharedMatcher::new(server));

    let counter = Arc::new(CountingSubmitter::new());
    let submitter: Arc<dyn matcher::server::TxSubmitter> =
        Arc::clone(&counter) as Arc<dyn matcher::server::TxSubmitter>;
    let sealer: Arc<dyn matcher::BatchSealer> =
        Arc::clone(&shared) as Arc<dyn matcher::BatchSealer>;
    let settler = Arc::new(matcher::server::BatchSettler::new(
        sealer,
        Arc::clone(&submitter),
        100,
        addr_from_index(0),
        0,
    ));
    let settler_clone = Arc::clone(&settler);
    tokio::spawn(async move {
        settler_clone.run().await;
    });

    let tcp_matcher = Arc::clone(&shared);
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server(tcp_matcher, port).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");

    let n_pairs = n_orders / 2;
    let n_accounts_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let mut buf = [0u8; matcher::protocol::RESPONSE_SIZE];
    let mut fills = 0u64;
    let mut nonces = vec![0u64; n_accounts];

    let start = Instant::now();
    for i in 0..n_pairs {
        let seller_idx = (u32::try_from(2 * i).unwrap_or(u32::MAX) % n_accounts_u32) as usize;
        let buyer_idx = (u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_accounts_u32) as usize;
        let seller_nonce = nonces[seller_idx];
        nonces[seller_idx] += 1;
        let buyer_nonce = nonces[buyer_idx];
        nonces[buyer_idx] += 1;
        let (f, _) = submit_pair(
            &mut sock,
            &mut buf,
            &account_keys[seller_idx],
            seller_nonce,
            &account_keys[buyer_idx],
            buyer_nonce,
        )
        .await;
        fills += f;
    }
    let elapsed = start.elapsed();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let stats = shared.stats();
    let settled_txs = counter.count();

    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!("smoke: {n_orders} orders in {:.3}s = {tps:.0} orders/s", elapsed.as_secs_f64());
    eprintln!("smoke: fills={fills}, settled_txs={settled_txs}, resting={}", stats.resting_count);

    assert_eq!(stats.orders_processed as usize, n_orders);
    assert_eq!(stats.resting_count, 0);
    assert!(settled_txs > 0);
}
