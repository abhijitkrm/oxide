//! Optimized throughput benchmark: pipelining + connection pooling + batch.
//!
//! Compares three optimization strategies against the synchronous baseline:
//!
//! 1. **Synchronous** (baseline): write request → read response → repeat.
//!    One TCP round-trip per order.
//! 2. **Pipelining**: send N requests in a burst, then read N responses.
//!    Amortizes TCP round-trip latency across N orders.
//! 3. **Connection pooling**: M connections, each pipelining N/M orders.
//!    Scales horizontally across TCP connections.
//! 4. **Batch endpoint**: send N orders in a single batch request, receive
//!    N responses in a single batch reply. Minimizes syscalls and lock
//!    acquisitions.
//!
//! # Running
//!
//! ```sh
//! # Default: 1M orders, 1k accounts
//! cargo test -p matcher --release --test e2e_optimized -- --ignored --nocapture
//!
//! # Custom: 10M orders with 10k accounts, 16 connections, batch size 1000
//! OPT_ORDERS=10_000_000 OPT_ACCOUNTS=10_000 OPT_CONNECTIONS=16 OPT_BATCH=1000 \
//!   cargo test -p matcher --release --test e2e_optimized -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use matcher::protocol::{
    OrderRequest, decode_batch_response, decode_response, encode_batch_request, encode_request,
};
use matcher::{MatchingServer, SharedMatcher};
use primitives::fixed::{Price, Qty};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use trading::{MarketConfig, OrderType, Side, TimeInForce};

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

fn make_order(side: Side, owner_idx: u32) -> OrderRequest {
    OrderRequest {
        market: 0,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner: addr_from_index(owner_idx),
    }
}

fn build_matcher(n_accounts: usize, initial_balance: u64) -> Arc<SharedMatcher> {
    let mut server = MatchingServer::new(cfg(), n_accounts);
    for i in 0..u32::try_from(n_accounts).unwrap_or(u32::MAX) {
        server.fund_account(&addr_from_index(i), initial_balance);
    }
    Arc::new(SharedMatcher::new(server))
}

/// Generate order pairs (maker sell + taker buy) for the benchmark.
fn generate_orders(n_orders: usize, n_accounts: usize) -> Vec<OrderRequest> {
    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let mut orders = Vec::with_capacity(n_orders);
    for i in 0..n_pairs {
        let seller = u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32;
        let buyer = u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32;
        orders.push(make_order(Side::Sell, seller));
        orders.push(make_order(Side::Buy, buyer));
    }
    orders
}

/// Baseline: synchronous request-response (one round-trip per order).
async fn bench_sync(n_orders: usize, n_accounts: usize, port: u16) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let tcp_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server(tcp_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let orders = generate_orders(n_orders, n_accounts);
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let mut buf = [0u8; matcher::protocol::RESPONSE_SIZE];
    let mut fills = 0u64;

    let start = Instant::now();
    for req in &orders {
        sock.write_all(&encode_request(req)).await.expect("w");
        sock.read_exact(&mut buf).await.expect("r");
        fills += u64::from(decode_response(&buf).expect("d").fills_count);
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  sync:         {n_orders} orders, {fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Pipelining: send N requests in a burst, then read N responses.
/// Amortizes TCP round-trip latency.
async fn bench_pipelined(n_orders: usize, n_accounts: usize, port: u16, pipe_size: usize) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let tcp_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server(tcp_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let orders = generate_orders(n_orders, n_accounts);
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let mut resp_buf = vec![0u8; pipe_size * matcher::protocol::RESPONSE_SIZE];
    let mut fills = 0u64;

    let start = Instant::now();
    for chunk in orders.chunks(pipe_size) {
        // Send all requests in the pipeline.
        for req in chunk {
            sock.write_all(&encode_request(req)).await.expect("w");
        }
        // Read all responses.
        sock.read_exact(&mut resp_buf[..chunk.len() * matcher::protocol::RESPONSE_SIZE])
            .await
            .expect("r");
        for i in 0..chunk.len() {
            let off = i * matcher::protocol::RESPONSE_SIZE;
            fills += u64::from(
                decode_response(&resp_buf[off..off + matcher::protocol::RESPONSE_SIZE])
                    .expect("d")
                    .fills_count,
            );
        }
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  pipelined:    {n_orders} orders (pipe={pipe_size}), {fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Connection pooling: M connections, each pipelining N/M orders.
async fn bench_pooled(
    n_orders: usize,
    n_accounts: usize,
    port: u16,
    n_connections: usize,
    pipe_size: usize,
) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let tcp_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server(tcp_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let orders = generate_orders(n_orders, n_accounts);
    let orders_per_conn = n_orders / n_connections;

    let start = Instant::now();
    let mut handles = Vec::with_capacity(n_connections);
    for conn_idx in 0..n_connections {
        let off = conn_idx * orders_per_conn;
        let end = if conn_idx == n_connections - 1 { n_orders } else { off + orders_per_conn };
        let chunk = orders[off..end].to_vec();
        handles.push(tokio::spawn(async move {
            let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
            let mut resp_buf = vec![0u8; pipe_size * matcher::protocol::RESPONSE_SIZE];
            let mut fills = 0u64;
            for sub in chunk.chunks(pipe_size) {
                for req in sub {
                    sock.write_all(&encode_request(req)).await.expect("w");
                }
                sock.read_exact(&mut resp_buf[..sub.len() * matcher::protocol::RESPONSE_SIZE])
                    .await
                    .expect("r");
                for i in 0..sub.len() {
                    let off = i * matcher::protocol::RESPONSE_SIZE;
                    fills += u64::from(
                        decode_response(&resp_buf[off..off + matcher::protocol::RESPONSE_SIZE])
                            .expect("d")
                            .fills_count,
                    );
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
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  pooled:       {n_orders} orders (conns={n_connections}, pipe={pipe_size}), {total_fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Batch endpoint: send N orders in a single batch request, receive
/// N responses in a single batch reply. Minimizes syscalls and lock
/// acquisitions.
async fn bench_batch(n_orders: usize, n_accounts: usize, port: u16, batch_size: usize) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let tcp_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server(tcp_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let orders = generate_orders(n_orders, n_accounts);
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let mut fills = 0u64;

    let start = Instant::now();
    for chunk in orders.chunks(batch_size) {
        // Encode the batch request.
        let batch_req = encode_batch_request(chunk);
        sock.write_all(&batch_req).await.expect("w batch");
        // Read the batch response header (5 bytes: flag + count).
        let mut header = [0u8; 5];
        sock.read_exact(&mut header).await.expect("r header");
        let count = u32::from_le_bytes(header[1..5].try_into().expect("count")) as usize;
        // Read the batch response entries.
        let resp_len = count * matcher::protocol::RESPONSE_SIZE;
        let mut resp_buf = vec![0u8; resp_len];
        sock.read_exact(&mut resp_buf).await.expect("r entries");
        // Reconstruct the full batch response for decoding.
        let mut full = Vec::with_capacity(5 + resp_len);
        full.extend_from_slice(&header);
        full.extend_from_slice(&resp_buf);
        let responses = decode_batch_response(&full).expect("decode batch");
        for r in &responses {
            fills += u64::from(r.fills_count);
        }
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  batch:        {n_orders} orders (batch={batch_size}), {fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Combined: connection pooling + pipelining + batch endpoint.
/// The ultimate optimization — M connections, each sending batch
/// requests with pipelining.
async fn bench_combined(
    n_orders: usize,
    n_accounts: usize,
    port: u16,
    n_connections: usize,
    batch_size: usize,
) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let tcp_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server(tcp_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let orders = generate_orders(n_orders, n_accounts);
    let orders_per_conn = n_orders / n_connections;

    let start = Instant::now();
    let mut handles = Vec::with_capacity(n_connections);
    for conn_idx in 0..n_connections {
        let off = conn_idx * orders_per_conn;
        let end = if conn_idx == n_connections - 1 { n_orders } else { off + orders_per_conn };
        let chunk = orders[off..end].to_vec();
        handles.push(tokio::spawn(async move {
            let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
            let mut fills = 0u64;
            // Pipeline multiple batch requests.
            let mut pending_batches = Vec::new();
            for sub in chunk.chunks(batch_size) {
                let batch_req = encode_batch_request(sub);
                sock.write_all(&batch_req).await.expect("w batch");
                // Read batch response.
                let mut header = [0u8; 5];
                sock.read_exact(&mut header).await.expect("r header");
                let count = u32::from_le_bytes(header[1..5].try_into().expect("count")) as usize;
                let resp_len = count * matcher::protocol::RESPONSE_SIZE;
                let mut resp_buf = vec![0u8; resp_len];
                sock.read_exact(&mut resp_buf).await.expect("r entries");
                let mut full = Vec::with_capacity(5 + resp_len);
                full.extend_from_slice(&header);
                full.extend_from_slice(&resp_buf);
                let responses = decode_batch_response(&full).expect("decode batch");
                for r in &responses {
                    fills += u64::from(r.fills_count);
                }
                pending_batches.push(responses.len());
            }
            let _ = pending_batches;
            fills
        }));
    }
    let mut total_fills = 0u64;
    for h in handles {
        total_fills += h.await.expect("join");
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  combined:     {n_orders} orders (conns={n_connections}, batch={batch_size}), {total_fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Ring matcher benchmark: batch orders routed through the lock-free
/// SPSC ring (no mutex on the order path).
async fn bench_ring_batch(n_orders: usize, n_accounts: usize, port: u16, batch_size: usize) -> f64 {
    // Build a funded server for the ring matcher's thread.
    let mut funded = MatchingServer::new(cfg(), n_accounts);
    for i in 0..u32::try_from(n_accounts).unwrap_or(u32::MAX) {
        funded.fund_account(&addr_from_index(i), 1_000_000_000_000);
    }
    let ring_matcher = Arc::new(matcher::RingMatcher::new(funded, 8, 8192));
    // The SharedMatcher is only used for the mutex path fallback in
    // the server (settlement isn't measured here).
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let tcp_matcher = Arc::clone(&matcher);
    let ring = Arc::clone(&ring_matcher);
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server_ring(tcp_matcher, ring, counter, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let orders = generate_orders(n_orders, n_accounts);
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let mut fills = 0u64;

    let start = Instant::now();
    for chunk in orders.chunks(batch_size) {
        let batch_req = encode_batch_request(chunk);
        sock.write_all(&batch_req).await.expect("w batch");
        let mut header = [0u8; 5];
        sock.read_exact(&mut header).await.expect("r header");
        let count = u32::from_le_bytes(header[1..5].try_into().expect("count")) as usize;
        let resp_len = count * matcher::protocol::RESPONSE_SIZE;
        let mut resp_buf = vec![0u8; resp_len];
        sock.read_exact(&mut resp_buf).await.expect("r entries");
        let mut full = Vec::with_capacity(5 + resp_len);
        full.extend_from_slice(&header);
        full.extend_from_slice(&resp_buf);
        let responses = decode_batch_response(&full).expect("decode batch");
        for r in &responses {
            fills += u64::from(r.fills_count);
        }
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  ring-batch:   {n_orders} orders (batch={batch_size}), {fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Full optimized benchmark comparing all strategies.
#[tokio::test]
#[ignore = "long-running optimized benchmark; run with --release --ignored --nocapture"]
async fn benchmark_optimized() {
    let n_orders = env_usize("OPT_ORDERS", 1_000_000);
    let n_accounts = env_usize("OPT_ACCOUNTS", 1_000);
    let n_connections = env_usize("OPT_CONNECTIONS", 8);
    let batch_size = env_usize("OPT_BATCH", 500);
    let pipe_size = env_usize("OPT_PIPE", 500);

    eprintln!();
    eprintln!("=== Optimized Throughput Benchmark ===");
    eprintln!("  orders:      {n_orders}");
    eprintln!("  accounts:    {n_accounts}");
    eprintln!("  connections: {n_connections}");
    eprintln!("  batch size:  {batch_size}");
    eprintln!("  pipe size:   {pipe_size}");
    eprintln!();

    // 1. Synchronous baseline.
    eprintln!("  [1/6] Synchronous baseline...");
    let sync_tps = bench_sync(n_orders, n_accounts, 36300).await;

    // 2. Pipelining.
    eprintln!("  [2/6] Pipelining...");
    let pipe_tps = bench_pipelined(n_orders, n_accounts, 36301, pipe_size).await;

    // 3. Connection pooling + pipelining.
    eprintln!("  [3/6] Connection pooling + pipelining...");
    let pooled_tps = bench_pooled(n_orders, n_accounts, 36302, n_connections, pipe_size).await;

    // 4. Batch endpoint.
    eprintln!("  [4/6] Batch endpoint...");
    let batch_tps = bench_batch(n_orders, n_accounts, 36303, batch_size).await;

    // 5. Combined: pooling + batch.
    eprintln!("  [5/6] Combined (pooling + batch)...");
    let combined_tps = bench_combined(n_orders, n_accounts, 36304, n_connections, batch_size).await;

    // 6. Ring matcher: batch through lock-free SPSC rings.
    eprintln!("  [6/6] Ring matcher (SPSC, no mutex)...");
    let ring_tps = bench_ring_batch(n_orders, n_accounts, 36305, batch_size).await;

    eprintln!();
    eprintln!("=== Results Summary ===");
    eprintln!("  Strategy                    | Throughput (orders/s) | Speedup");
    eprintln!("  ----------------------------+----------------------+---------");
    eprintln!("  Synchronous (baseline)      | {sync_tps:>10.0}          | 1.00x");
    eprintln!(
        "  Pipelining (pipe={pipe_size:<5})        | {pipe_tps:>10.0}          | {:.2}x",
        pipe_tps / sync_tps
    );
    eprintln!(
        "  Pooled (conn={n_connections}, pipe={pipe_size})   | {pooled_tps:>10.0}          | {:.2}x",
        pooled_tps / sync_tps
    );
    eprintln!(
        "  Batch (batch={batch_size:<5})        | {batch_tps:>10.0}          | {:.2}x",
        batch_tps / sync_tps
    );
    eprintln!(
        "  Combined (conn={n_connections}, batch={batch_size}) | {combined_tps:>10.0}          | {:.2}x",
        combined_tps / sync_tps
    );
    eprintln!(
        "  Ring matcher (batch={batch_size})   | {ring_tps:>10.0}          | {:.2}x",
        ring_tps / sync_tps
    );
    eprintln!();

    // All strategies should be faster than synchronous.
    assert!(pipe_tps > sync_tps, "pipelining should be faster than sync");
    assert!(pooled_tps > sync_tps, "pooling should be faster than sync");
    assert!(batch_tps > sync_tps, "batch should be faster than sync");
    assert!(combined_tps > sync_tps, "combined should be faster than sync");
    assert!(ring_tps > sync_tps, "ring matcher should be faster than sync");

    eprintln!("  All optimizations verified ✓");
}

/// Smoke test: 100k orders.
#[tokio::test]
#[ignore = "optimized smoke test; run with --release --ignored --nocapture"]
async fn smoke_optimized() {
    let n_orders = env_usize("OPT_ORDERS", 100_000);
    let n_accounts = env_usize("OPT_ACCOUNTS", 100);
    let n_connections = env_usize("OPT_CONNECTIONS", 4);
    let batch_size = env_usize("OPT_BATCH", 100);
    let pipe_size = env_usize("OPT_PIPE", 100);

    eprintln!("=== Optimized Smoke Test ({n_orders} orders) ===");

    let sync_tps = bench_sync(n_orders, n_accounts, 36310).await;
    let pipe_tps = bench_pipelined(n_orders, n_accounts, 36311, pipe_size).await;
    let pooled_tps = bench_pooled(n_orders, n_accounts, 36312, n_connections, pipe_size).await;
    let batch_tps = bench_batch(n_orders, n_accounts, 36313, batch_size).await;
    let combined_tps = bench_combined(n_orders, n_accounts, 36314, n_connections, batch_size).await;

    eprintln!();
    eprintln!("  Synchronous  | {sync_tps:>10.0} orders/s");
    eprintln!("  Pipelined    | {pipe_tps:>10.0} orders/s");
    eprintln!("  Pooled       | {pooled_tps:>10.0} orders/s");
    eprintln!("  Batch        | {batch_tps:>10.0} orders/s");
    eprintln!("  Combined     | {combined_tps:>10.0} orders/s");
}
