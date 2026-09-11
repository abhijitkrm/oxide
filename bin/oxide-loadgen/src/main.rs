//! oxide-loadgen — the matching server load generator.
//!
//! Connects to the oxide-matcher server via binary TCP and submits
//! orders at scale using the batch protocol. Reports throughput
//! (orders/s), fills, and latency.
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

use matcher::protocol::{
    OrderRequest, decode_batch_response, decode_response, encode_batch_request, encode_request,
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

    println!("oxide-loadgen: connecting to {host}:{port}");
    println!("  orders:      {orders}");
    println!("  accounts:    {accounts}");
    println!("  connections: {connections}");
    println!("  batch size:  {batch_size}");
    println!("  markets:     {markets}");
    println!("  mode:        {mode}");

    let runtime =
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");

    let result = runtime.block_on(async move {
        if mode == "sync" {
            run_sync(&host, port, orders, accounts, markets).await
        } else if mode == "pipe" {
            run_pipelined(&host, port, orders, accounts, batch_size, markets).await
        } else {
            // Default: batch mode (fastest).
            run_batch(&host, port, orders, accounts, connections, batch_size, markets).await
        }
    });

    println!();
    println!("=== oxide-loadgen Results ===");
    println!("  orders:      {}", result.orders);
    println!("  fills:       {}", result.fills);
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
    elapsed: Duration,
    tps: f64,
}

fn addr_from_index(i: u32) -> primitives::Address {
    let mut addr = [0u8; 20];
    addr[..4].copy_from_slice(&i.to_le_bytes());
    primitives::Address(addr)
}

fn make_order(side: Side, owner_idx: u32, market: u8) -> OrderRequest {
    OrderRequest {
        market,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner: addr_from_index(owner_idx),
    }
}

fn generate_orders(n_orders: usize, n_accounts: usize, n_markets: u8) -> Vec<OrderRequest> {
    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let mut orders = Vec::with_capacity(n_orders);
    for i in 0..n_pairs {
        let seller = u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32;
        let buyer = u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32;
        // Round-robin market assignment: each order pair goes to
        // market (i % n_markets). This spreads load evenly across
        // all markets so the multi-market parallel matcher can
        // exercise all worker threads.
        let market =
            if n_markets == 1 { 0 } else { u8::try_from(i % usize::from(n_markets)).unwrap_or(0) };
        orders.push(make_order(Side::Sell, seller, market));
        orders.push(make_order(Side::Buy, buyer, market));
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
    n_accounts: usize,
    n_markets: u8,
    batch_size: usize,
) -> Vec<OrderRequest> {
    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let pairs_per_batch = (batch_size / 2).max(1);
    let mut orders = Vec::with_capacity(n_orders);
    for i in 0..n_pairs {
        let seller = u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32;
        let buyer = u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32;
        // Group by batch: pairs 0..(pairs_per_batch-1) → market 0,
        // pairs pairs_per_batch..(2*pairs_per_batch-1) → market 1, etc.
        let market = if n_markets == 1 {
            0
        } else {
            let batch_idx = i / pairs_per_batch;
            u8::try_from(batch_idx % usize::from(n_markets)).unwrap_or(0)
        };
        orders.push(make_order(Side::Sell, seller, market));
        orders.push(make_order(Side::Buy, buyer, market));
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
    let all_orders = generate_orders(orders, accounts, markets);
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
    BenchResult { orders, fills, elapsed, tps }
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
    let all_orders = generate_orders(orders, accounts, markets);
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
    BenchResult { orders, fills, elapsed, tps }
}

/// Batch mode: M connections, each sending batch requests.
async fn run_batch(
    host: &str,
    port: u16,
    orders: usize,
    accounts: usize,
    connections: usize,
    batch_size: usize,
    markets: u8,
) -> BenchResult {
    let all_orders = Arc::new(generate_orders_grouped(orders, accounts, markets, batch_size));
    let orders_per_conn = orders / connections;
    let host = Arc::new(host.to_string());

    let start = Instant::now();
    let mut handles = Vec::with_capacity(connections);
    for conn_idx in 0..connections {
        let off = conn_idx * orders_per_conn;
        let end = if conn_idx == connections - 1 { orders } else { off + orders_per_conn };
        let chunk = all_orders[off..end].to_vec();
        let host = Arc::clone(&host);
        handles.push(tokio::spawn(async move {
            let mut sock = TcpStream::connect((host.as_str(), port)).await.expect("connect");
            let mut fills = 0u64;
            for sub in chunk.chunks(batch_size) {
                let batch_req = encode_batch_request(sub);
                sock.write_all(&batch_req).await.expect("write batch");
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
                }
            }
            fills
        }));
    }
    let mut total_fills = 0u64;
    for h in handles {
        total_fills += h.await.expect("join");
    }
    let elapsed = start.elapsed();
    let tps = orders as f64 / elapsed.as_secs_f64();
    BenchResult { orders, fills: total_fills, elapsed, tps }
}

/// Parse a CLI flag of the form `--name value`.
fn parse_flag<T: std::str::FromStr>(name: &str, default: T) -> T {
    let args: Vec<String> = env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            if let Some(val) = args.get(i + 1) {
                if let Ok(parsed) = val.parse() {
                    return parsed;
                }
            }
        }
    }
    default
}
