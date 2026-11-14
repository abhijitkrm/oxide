//! oxide-loadgen — the matching server load generator.
//!
//! Connects to the oxide-matcher server via binary TCP and submits
//! orders at scale using the batch protocol. Reports throughput
//! (orders/s), fills, and latency.
//!
//! # Authentication schemes
//!
//! `--auth ed25519` (default), `evm`, `session_mac` or `certified` choose the
//! credential every order carries; the server must run a matching
//! `oxide-matcher --auth ...` (or `--auth multi`). Identities are the
//! deterministic, publicly derivable benchmark keys of `matcher::loadkeys`;
//! start the server with `--fund-loadgen-keys` (a `dev-identities` build) so
//! they have balances, and for `certified` pass the gateway key printed by
//! `oxide-loadgen --print-gateway-key` as `--gateway-keys`. Batch mode builds,
//! signs and frames every order BEFORE the clock starts, so the reported
//! throughput is the server's, not the generator's signing speed.
//!
//! # Usage
//!
//! ```sh
//! # Default: 1M orders, 1k accounts, 8 connections, batch=500
//! oxide-loadgen --host 127.0.0.1 --port 36000
//!
//! # 10M orders with 16 connections and batch=1000
//! oxide-loadgen --orders 10000000 --connections 16 --batch 1000
//!
//! # Synchronous mode (no pipelining, no batch)
//! oxide-loadgen --mode sync
//! ```

#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crypto::ed25519::Ed25519SecretKey;
use matcher::auth::{MarketScope, SessionOpen, certify, sign_order_evm, sign_order_session};
use matcher::control::{Status, decode_session_response, encode_cert_batch, encode_session_open};
use matcher::loadkeys;
use matcher::protocol::{
    OrderRequest, decode_batch_response, decode_response, encode_batch_request, encode_request,
    sign_order,
};
use primitives::fixed::{Price, Qty};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use trading::{OrderType, Side, TimeInForce};

/// Default number of orders to submit.
const DEFAULT_ORDERS: usize = 1_000_000;

/// Default number of accounts.
const DEFAULT_ACCOUNTS: usize = 1_000;

/// Default number of TCP connections.
const DEFAULT_CONNECTIONS: usize = 8;

/// Default batch size (orders per batch request).
const DEFAULT_BATCH: usize = 500;

/// Default host.
const DEFAULT_HOST: &str = "127.0.0.1";

/// Default port.
const DEFAULT_PORT: u16 = 36000;

/// Default number of markets (1 = single-market, the original behavior).
const DEFAULT_MARKETS: u8 = 1;

fn main() {
    let host = parse_flag("--host", DEFAULT_HOST.to_string());
    let port = parse_flag("--port", DEFAULT_PORT);
    let orders = parse_flag("--orders", DEFAULT_ORDERS);
    let accounts = parse_flag("--accounts", DEFAULT_ACCOUNTS);
    let connections = parse_flag("--connections", DEFAULT_CONNECTIONS);
    let batch_size = parse_flag("--batch", DEFAULT_BATCH);
    let mode = parse_flag("--mode", "batch".to_string());
    let markets = parse_flag("--markets", DEFAULT_MARKETS);
    let auth = parse_flag("--auth", "ed25519".to_string());
    let chain_id = parse_flag("--chain-id", matcher::protocol::CHAIN_ID);
    if env::args().any(|a| a == "--print-gateway-key") {
        let pk = loadkeys::gateway_key().verifying_key().to_bytes();
        let hex = pk.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        println!("{hex}");
        return;
    }
    if !matches!(auth.as_str(), "ed25519" | "evm" | "session_mac" | "certified") {
        eprintln!("error: --auth must be ed25519, evm, session_mac or certified");
        std::process::exit(1);
    }

    println!("oxide-loadgen: connecting to {host}:{port}");
    println!("  orders:      {orders}");
    println!("  accounts:    {accounts}");
    println!("  connections: {connections}");
    println!("  batch size:  {batch_size}");
    println!("  markets:     {markets}");
    println!("  mode:        {mode}");
    println!("  auth:        {auth}");

    let runtime =
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");

    let result = runtime.block_on(async move {
        if mode == "sync" {
            run_sync(&host, port, orders, accounts, markets).await
        } else if mode == "pipe" {
            run_pipelined(&host, port, orders, accounts, batch_size, markets).await
        } else {
            // Default: batch mode (fastest).
            run_batch(
                &host,
                port,
                orders,
                accounts,
                connections,
                batch_size,
                markets,
                &auth,
                chain_id,
            )
            .await
        }
    });

    println!();
    println!("=== oxide-loadgen Results ===");
    println!("  orders:      {}", result.orders);
    println!("  fills:       {}", result.fills);
    println!("  rejected:    {}", result.rejected);
    println!("  elapsed:     {:.3}s", result.elapsed.as_secs_f64());
    println!("  throughput:  {:.0} orders/s", result.tps);
    println!(
        "  avg latency: {:.3} us/order",
        result.elapsed.as_micros() as f64 / result.orders as f64
    );
    println!("=============================");
}

struct BenchResult {
    orders: usize,
    fills: u64,
    /// Orders the server rejected (should be 0; non-zero means the run is
    /// measuring rejections, not matching).
    rejected: u64,
    elapsed: Duration,
    tps: f64,
}

fn addr_from_index(i: u32) -> primitives::Address {
    let mut addr = [0u8; 20];
    addr[..4].copy_from_slice(&i.to_le_bytes());
    primitives::Address(addr)
}

/// Deterministic per-account signing key — the server authenticates
/// every order (signature + derived-owner binding), so loadgen
/// signs exactly like a real client. Accounts are assumed to be
/// pre-funded on the server side at each key's derived owner.
fn account_key(i: u32) -> Ed25519SecretKey {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&i.to_le_bytes());
    Ed25519SecretKey::from_bytes(&seed)
}

/// Build a signed order for `key`'s account at `nonce` on `market`.
fn make_order(key: &Ed25519SecretKey, side: Side, nonce: u64, market: u8) -> OrderRequest {
    let mut req = OrderRequest {
        market,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner: addr_from_index(0),
        nonce,
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    sign_order(&mut req, key);
    req
}

fn generate_orders(n_orders: usize, keys: &[Ed25519SecretKey], n_markets: u8) -> Vec<OrderRequest> {
    let mut nonces = vec![0u64; keys.len()];
    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    let mut orders = Vec::with_capacity(n_orders);
    for i in 0..n_pairs {
        let seller = (u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32) as usize;
        let buyer = (u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32) as usize;
        // Round-robin market assignment: each order pair goes to
        // market (i % n_markets). This spreads load evenly across
        // all markets so the multi-market parallel matcher can
        // exercise all worker threads.
        let market =
            if n_markets == 1 { 0 } else { u8::try_from(i % usize::from(n_markets)).unwrap_or(0) };
        orders.push(make_order(&keys[seller], Side::Sell, nonces[seller], market));
        nonces[seller] += 1;
        orders.push(make_order(&keys[buyer], Side::Buy, nonces[buyer], market));
        nonces[buyer] += 1;
    }
    orders
}

/// Generate orders grouped by market: all orders in a batch-sized
/// chunk go to the same market, and different chunks go to
/// different markets round-robin. This ensures each batch sent over
/// TCP hits the multi-market fast path (one channel send per batch,
/// not 128).
fn generate_orders_grouped(
    n_orders: usize,
    keys: &[Ed25519SecretKey],
    n_markets: u8,
    batch_size: usize,
) -> Vec<OrderRequest> {
    let mut nonces = vec![0u64; keys.len()];
    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    let pairs_per_batch = (batch_size / 2).max(1);
    let mut orders = Vec::with_capacity(n_orders);
    for i in 0..n_pairs {
        let seller = (u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32) as usize;
        let buyer = (u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32) as usize;
        // Group by batch: pairs 0..(pairs_per_batch-1) → market 0,
        // pairs pairs_per_batch..(2*pairs_per_batch-1) → market 1, etc.
        let market = if n_markets == 1 {
            0
        } else {
            let batch_idx = i / pairs_per_batch;
            u8::try_from(batch_idx % usize::from(n_markets)).unwrap_or(0)
        };
        orders.push(make_order(&keys[seller], Side::Sell, nonces[seller], market));
        nonces[seller] += 1;
        orders.push(make_order(&keys[buyer], Side::Buy, nonces[buyer], market));
        nonces[buyer] += 1;
    }
    orders
}

/// Synchronous mode: one request, one response, repeat.
async fn run_sync(
    host: &str,
    port: u16,
    orders: usize,
    accounts: usize,
    markets: u8,
) -> BenchResult {
    let keys: Vec<Ed25519SecretKey> =
        (0..u32::try_from(accounts).unwrap_or(u32::MAX)).map(account_key).collect();
    let all_orders = generate_orders(orders, &keys, markets);
    let mut sock = TcpStream::connect((host, port)).await.expect("connect");
    let mut buf = [0u8; matcher::protocol::RESPONSE_SIZE];
    let mut fills = 0u64;

    let start = Instant::now();
    for req in &all_orders {
        sock.write_all(&encode_request(req)).await.expect("write");
        sock.read_exact(&mut buf).await.expect("read");
        fills += u64::from(decode_response(&buf).expect("decode").fills_count);
    }
    let elapsed = start.elapsed();
    let tps = orders as f64 / elapsed.as_secs_f64();
    BenchResult { orders, fills, rejected: 0, elapsed, tps }
}

/// Pipelined mode: send N requests in a burst, then read N responses.
async fn run_pipelined(
    host: &str,
    port: u16,
    orders: usize,
    accounts: usize,
    pipe: usize,
    markets: u8,
) -> BenchResult {
    let keys: Vec<Ed25519SecretKey> =
        (0..u32::try_from(accounts).unwrap_or(u32::MAX)).map(account_key).collect();
    let all_orders = generate_orders(orders, &keys, markets);
    let mut sock = TcpStream::connect((host, port)).await.expect("connect");
    let mut resp_buf = vec![0u8; pipe * matcher::protocol::RESPONSE_SIZE];
    let mut fills = 0u64;

    let start = Instant::now();
    for chunk in all_orders.chunks(pipe) {
        for req in chunk {
            sock.write_all(&encode_request(req)).await.expect("write");
        }
        let resp_len = chunk.len() * matcher::protocol::RESPONSE_SIZE;
        sock.read_exact(&mut resp_buf[..resp_len]).await.expect("read");
        for i in 0..chunk.len() {
            let off = i * matcher::protocol::RESPONSE_SIZE;
            fills += u64::from(
                decode_response(&resp_buf[off..off + matcher::protocol::RESPONSE_SIZE])
                    .expect("decode")
                    .fills_count,
            );
        }
    }
    let elapsed = start.elapsed();
    let tps = orders as f64 / elapsed.as_secs_f64();
    BenchResult { orders, fills, rejected: 0, elapsed, tps }
}

/// Batch mode: M connections, each sending batch requests.
///
/// Each connection gets a DISJOINT partition of the account space:
/// nonces are per-account and strictly increasing, so the same
/// account's orders must flow through one connection in sequence
/// (each batch's response is read before the next is sent, which
/// keeps that connection's stream totally ordered). Splitting one
/// account across connections could deliver a higher nonce before
/// a lower one and get it rejected as `StaleNonce`.
/// Wall-clock milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Open one session per account (in `range`) over a short-lived blocking
/// connection and return `account index -> session id`. Sessions are
/// server-wide, so this need not be the connection that sends orders.
fn open_sessions(
    host: &str,
    port: u16,
    range: std::ops::Range<u32>,
    chain_id: u64,
) -> std::collections::HashMap<u32, u32> {
    use std::io::{Read, Write};
    let mut sock = std::net::TcpStream::connect((host, port)).expect("connect for session open");
    let mut ids = std::collections::HashMap::new();
    for idx in range {
        let open = SessionOpen::sign_ed25519_until(
            &loadkeys::ed_key(idx),
            loadkeys::SESSION_KEY,
            MarketScope::all(),
            now_ms() + 3_600_000,
            chain_id,
        );
        sock.write_all(&encode_session_open(&open)).expect("write session open");
        let mut resp = [0u8; 5];
        sock.read_exact(&mut resp).expect("read session response");
        match decode_session_response(&resp) {
            Some((Status::Ok, id)) => {
                ids.insert(idx, id);
            }
            other => panic!(
                "session open for account {idx} failed: {other:?} (server needs --auth session_mac \
                 or multi, and --fund-loadgen-keys)"
            ),
        }
    }
    ids
}

/// Build and frame one connection's batches under `auth` (untimed).
#[allow(clippy::too_many_arguments)] // one value per knob of a single batch-prep step
fn prepare_frames(
    host: &str,
    port: u16,
    lo: u32,
    hi: u32,
    orders_per_conn: usize,
    batch_size: usize,
    markets: u8,
    auth: &str,
    chain_id: u64,
) -> Vec<Vec<u8>> {
    let keys: Vec<Ed25519SecretKey> = (lo..hi).map(loadkeys::ed_key).collect();
    let mut chunk = generate_orders_grouped(orders_per_conn, &keys, markets, batch_size);
    // Owner address -> global account index, to re-authenticate under another scheme.
    let by_owner: std::collections::HashMap<primitives::Address, u32> =
        (lo..hi).map(|i| (loadkeys::ed_owner(i), i)).collect();
    match auth {
        "evm" => {
            for o in &mut chunk {
                let idx = by_owner[&o.owner];
                sign_order_evm(o, &loadkeys::evm_key(idx), chain_id);
            }
        }
        "session_mac" => {
            let ids = open_sessions(host, port, lo..hi, chain_id);
            for o in &mut chunk {
                let idx = by_owner[&o.owner];
                // `owner` stays the ed25519-derived address the session was opened for.
                sign_order_session(o, ids[&idx], &loadkeys::SESSION_KEY, chain_id);
            }
        }
        _ => {}
    }
    if auth == "certified" {
        let gw = loadkeys::gateway_key();
        chunk
            .chunks(batch_size)
            .map(|sub| encode_cert_batch(&certify(&gw, sub, chain_id), sub))
            .collect()
    } else {
        chunk.chunks(batch_size).map(encode_batch_request).collect()
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_batch(
    host: &str,
    port: u16,
    orders: usize,
    accounts: usize,
    connections: usize,
    batch_size: usize,
    markets: u8,
    auth: &str,
    chain_id: u64,
) -> BenchResult {
    let orders_per_conn = orders / connections;
    // Floor partition — leftover accounts (accounts % connections)
    // simply go unused; every connection's account set is disjoint.
    let accounts_per_conn = (accounts / connections).max(1);

    // Phase 1 (untimed): build, authenticate and frame every connection's
    // batches in parallel, opening sessions if the scheme needs them.
    let prep: Vec<_> = (0..connections)
        .map(|conn_idx| {
            let lo = u32::try_from(conn_idx * accounts_per_conn).unwrap_or(u32::MAX);
            let hi = lo + u32::try_from(accounts_per_conn).unwrap_or(u32::MAX);
            let (host, auth) = (host.to_string(), auth.to_string());
            tokio::task::spawn_blocking(move || {
                prepare_frames(
                    &host,
                    port,
                    lo,
                    hi,
                    orders_per_conn,
                    batch_size,
                    markets,
                    &auth,
                    chain_id,
                )
            })
        })
        .collect();
    let mut all_frames = Vec::with_capacity(connections);
    for p in prep {
        all_frames.push(p.await.expect("prepare frames"));
    }
    println!("oxide-loadgen: {} orders prepared, sending...", orders_per_conn * connections);

    // Phase 2 (timed): send the prebuilt frames.
    let host = Arc::new(host.to_string());
    let start = Instant::now();
    let mut handles = Vec::with_capacity(connections);
    for frames in all_frames {
        let host = Arc::clone(&host);
        handles.push(tokio::spawn(async move {
            let mut sock = TcpStream::connect((host.as_str(), port)).await.expect("connect");
            let (mut fills, mut rejected) = (0u64, 0u64);
            for frame in frames {
                sock.write_all(&frame).await.expect("write batch");
                // Read batch response header (5 bytes).
                let mut header = [0u8; 5];
                sock.read_exact(&mut header).await.expect("read header");
                let count = u32::from_le_bytes(header[1..5].try_into().expect("count")) as usize;
                let resp_len = count * matcher::protocol::RESPONSE_SIZE;
                let mut resp_buf = vec![0u8; resp_len];
                sock.read_exact(&mut resp_buf).await.expect("read entries");
                let mut full = Vec::with_capacity(5 + resp_len);
                full.extend_from_slice(&header);
                full.extend_from_slice(&resp_buf);
                let responses = decode_batch_response(&full).expect("decode batch");
                for r in &responses {
                    fills += u64::from(r.fills_count);
                    rejected += u64::from(r.rejected);
                }
            }
            (fills, rejected)
        }));
    }
    let (mut total_fills, mut total_rejected) = (0u64, 0u64);
    for h in handles {
        let (f, r) = h.await.expect("join");
        total_fills += f;
        total_rejected += r;
    }
    let elapsed = start.elapsed();
    let sent = orders_per_conn * connections;
    let tps = sent as f64 / elapsed.as_secs_f64();
    BenchResult { orders: sent, fills: total_fills, rejected: total_rejected, elapsed, tps }
}

/// Parse a CLI flag of the form `--name value`.
fn parse_flag<T: std::str::FromStr>(name: &str, default: T) -> T {
    let args: Vec<String> = env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == name
            && let Some(val) = args.get(i + 1)
            && let Ok(parsed) = val.parse()
        {
            return parsed;
        }
    }
    default
}
