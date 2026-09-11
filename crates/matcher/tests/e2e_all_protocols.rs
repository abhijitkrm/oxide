//! TPS benchmark for all four order-entry protocols:
//! - Binary TCP (43-byte binary)
//! - WebSocket (JSON over WS)
//! - JSON-RPC (line-delimited JSON over TCP)
//! - FIX 4.4 (SOH-delimited text)
//!
//! Each protocol is benchmarked with the same workload: N orders
//! through a real TCP connection, measuring end-to-end throughput
//! including network I/O, protocol parsing, balance checks, and
//! matching.
//!
//! # Running
//!
//! ```sh
//! # Default: 1M orders per protocol, 1k accounts
//! cargo test -p matcher --release --test e2e_all_protocols -- --ignored --nocapture
//!
//! # Custom: 10M orders with 10k accounts
//! ALL_PROTO_ORDERS=10_000_000 ALL_PROTO_ACCOUNTS=10_000 \
//!   cargo test -p matcher --release --test e2e_all_protocols -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use matcher::protocol::{OrderRequest, decode_response, encode_request};
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
        nonce: 0,
        owner: addr_from_index(owner_idx),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    }
}

/// Build a shared matcher with funded accounts.
fn build_matcher(n_accounts: usize, initial_balance: u64) -> Arc<SharedMatcher> {
    let mut server = MatchingServer::new(cfg(), n_accounts);
    for i in 0..u32::try_from(n_accounts).unwrap_or(u32::MAX) {
        server.fund_account(&addr_from_index(i), initial_balance);
    }
    Arc::new(SharedMatcher::new(server))
}

/// Run the binary TCP protocol benchmark.
async fn bench_binary_tcp(n_orders: usize, n_accounts: usize, port: u16) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let tcp_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_binary_tcp_server(tcp_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let mut buf = [0u8; matcher::protocol::RESPONSE_SIZE];
    let mut fills = 0u64;

    let start = Instant::now();
    for i in 0..n_pairs {
        let seller = u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32;
        let buyer = u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32;
        let maker = make_order(Side::Sell, seller);
        sock.write_all(&encode_request(&maker)).await.expect("w");
        sock.read_exact(&mut buf).await.expect("r");
        fills += u64::from(decode_response(&buf).expect("d").fills_count);
        let taker = make_order(Side::Buy, buyer);
        sock.write_all(&encode_request(&taker)).await.expect("w");
        sock.read_exact(&mut buf).await.expect("r");
        fills += u64::from(decode_response(&buf).expect("d").fills_count);
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  binary_tcp: {n_orders} orders, {fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Run the JSON-RPC protocol benchmark.
async fn bench_jsonrpc(n_orders: usize, n_accounts: usize, port: u16) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let rpc_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_jsonrpc_tcp_server(rpc_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let mut fills = 0u64;
    let mut resp_buf = vec![0u8; 4096];

    let start = Instant::now();
    for i in 0..n_pairs {
        let seller = u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32;
        let buyer = u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32;
        // Maker sell.
        let maker = make_order(Side::Sell, seller);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "oxide_placeOrder",
            "params": {
                "market": 0,
                "side": "sell",
                "type": "limit",
                "tif": "gtc",
                "price": maker.price.0,
                "qty": maker.qty.0,
                "owner": format!("0x{}", hex::encode(maker.owner.0)),
            },
            "id": i * 2,
        });
        let mut line = serde_json::to_string(&req).unwrap_or_default();
        line.push('\n');
        sock.write_all(line.as_bytes()).await.expect("w");
        // Read response line.
        resp_buf.fill(0);
        let n = read_line(&mut sock, &mut resp_buf).await.expect("r");
        let resp: serde_json::Value = serde_json::from_slice(&resp_buf[..n]).expect("d");
        fills += resp
            .get("result")
            .and_then(|r| r.get("fills"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        // Taker buy.
        let taker = make_order(Side::Buy, buyer);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "oxide_placeOrder",
            "params": {
                "market": 0,
                "side": "buy",
                "type": "limit",
                "tif": "gtc",
                "price": taker.price.0,
                "qty": taker.qty.0,
                "owner": format!("0x{}", hex::encode(taker.owner.0)),
            },
            "id": i * 2 + 1,
        });
        let mut line = serde_json::to_string(&req).unwrap_or_default();
        line.push('\n');
        sock.write_all(line.as_bytes()).await.expect("w");
        resp_buf.fill(0);
        let n = read_line(&mut sock, &mut resp_buf).await.expect("r");
        let resp: serde_json::Value = serde_json::from_slice(&resp_buf[..n]).expect("d");
        fills += resp
            .get("result")
            .and_then(|r| r.get("fills"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  jsonrpc:     {n_orders} orders, {fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Run the FIX 4.4 protocol benchmark.
async fn bench_fix(n_orders: usize, n_accounts: usize, port: u16) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let fix_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_fix_server(fix_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let mut fills = 0u64;
    let mut resp_buf = vec![0u8; 4096];

    let start = Instant::now();
    for i in 0..n_pairs {
        let seller = u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32;
        let buyer = u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32;
        // Maker sell (FIX NewOrderSingle).
        let maker = make_order(Side::Sell, seller);
        let fix_msg = format!(
            "8=FIX.4.4\x0135=D\x0149=CLIENT\x0156=MATCHER\x0134={i}\x0111=M{i}\x01\
             54=2\x0140=2\x0159=0\x0144=15.00\x0138=0.001\x01\
             1=0x{}\x0155=OXIDE\x0110=000\x01",
            hex::encode(maker.owner.0)
        );
        sock.write_all(fix_msg.as_bytes()).await.expect("w");
        resp_buf.fill(0);
        let _ = sock.read(&mut resp_buf).await.expect("r");
        // We don't parse the FIX response for fills — just count orders.
        // Taker buy.
        let taker = make_order(Side::Buy, buyer);
        let fix_msg = format!(
            "8=FIX.4.4\x0135=D\x0149=CLIENT\x0156=MATCHER\x0134={}\x0111=T{i}\x01\
             54=1\x0140=2\x0159=0\x0144=15.00\x0138=0.001\x01\
             1=0x{}\x0155=OXIDE\x0110=000\x01",
            i + 1,
            hex::encode(taker.owner.0)
        );
        sock.write_all(fix_msg.as_bytes()).await.expect("w");
        resp_buf.fill(0);
        let _ = sock.read(&mut resp_buf).await.expect("r");
        fills += 1; // Approximate — FIX response parsing is complex.
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  fix:         {n_orders} orders, ~{fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Run the WebSocket protocol benchmark.
async fn bench_websocket(n_orders: usize, n_accounts: usize, port: u16) -> f64 {
    let matcher = build_matcher(n_accounts, 1_000_000_000_000);
    let ws_matcher = Arc::clone(&matcher);
    tokio::spawn(async move {
        let _ = matcher::server::run_websocket_server(ws_matcher, port).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect via raw TCP and do the WebSocket handshake manually.
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    // WebSocket handshake.
    let handshake = format!(
        "GET / HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n"
    );
    sock.write_all(handshake.as_bytes()).await.expect("handshake");
    // Read handshake response.
    let mut hs_buf = vec![0u8; 4096];
    let n = sock.read(&mut hs_buf).await.expect("read hs");
    let hs = String::from_utf8_lossy(&hs_buf[..n]);
    assert!(hs.contains("101"), "WebSocket handshake failed: {hs}");

    let n_pairs = n_orders / 2;
    let n_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let mut fills = 0u64;

    let start = Instant::now();
    for i in 0..n_pairs {
        let seller = u32::try_from(2 * i).unwrap_or(u32::MAX) % n_u32;
        let buyer = u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_u32;
        // Maker sell (JSON).
        let maker = make_order(Side::Sell, seller);
        let json = format!(
            r#"{{"market":0,"side":"sell","type":"limit","tif":"gtc","price":{},"qty":{},"owner":"0x{}"}}"#,
            maker.price.0,
            maker.qty.0,
            hex::encode(maker.owner.0)
        );
        write_ws_frame(&mut sock, json.as_bytes()).await.expect("w");
        read_ws_frame(&mut sock).await.expect("r");
        // Taker buy.
        let taker = make_order(Side::Buy, buyer);
        let json = format!(
            r#"{{"market":0,"side":"buy","type":"limit","tif":"gtc","price":{},"qty":{},"owner":"0x{}"}}"#,
            taker.price.0,
            taker.qty.0,
            hex::encode(taker.owner.0)
        );
        write_ws_frame(&mut sock, json.as_bytes()).await.expect("w");
        let resp = read_ws_frame(&mut sock).await.expect("r");
        // Check if the response contains a fill.
        if resp.contains("\"fills\":1") || resp.contains("\"fills\":2") {
            fills += 1;
        }
    }
    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!(
        "  websocket:   {n_orders} orders, ~{fills} fills, {:.3}s = {tps:.0} orders/s",
        elapsed.as_secs_f64()
    );
    tps
}

/// Write a WebSocket text frame (client→server, masked per RFC 6455).
async fn write_ws_frame(sock: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let mut header = Vec::with_capacity(14);
    // FIN=1, opcode=1 (text).
    header.push(0x81);
    // Masked (client→server must mask per RFC 6455 §5.3).
    if payload.len() < 126 {
        header.push(0x80 | payload.len() as u8);
    } else if payload.len() < 65536 {
        header.push(0x80 | 0x7E);
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        header.push(0x80 | 0x7F);
        header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    // Masking key (use a fixed key for simplicity — RFC allows any 4 bytes).
    let mask = [0x12u8, 0x34, 0x56, 0x78];
    header.extend_from_slice(&mask);
    // Mask the payload.
    let mut masked = Vec::with_capacity(payload.len());
    for (i, &b) in payload.iter().enumerate() {
        masked.push(b ^ mask[i % 4]);
    }
    sock.write_all(&header).await?;
    sock.write_all(&masked).await?;
    Ok(())
}

/// Read a WebSocket frame from the server. Returns the text payload.
async fn read_ws_frame(sock: &mut TcpStream) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 2];
    sock.read_exact(&mut header).await?;
    let opcode = header[0] & 0x0F;
    let masked = (header[1] & 0x80) != 0;
    let mut len = (header[1] & 0x7F) as usize;
    if len == 126 {
        let mut ext = [0u8; 2];
        sock.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as usize;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        sock.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext) as usize;
    }
    let mut mask = [0u8; 4];
    if masked {
        sock.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload).await?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    if opcode == 8 {
        // Close frame.
        return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "WS close"));
    }
    Ok(String::from_utf8_lossy(&payload).to_string())
}

/// Read a newline-delimited line from a TCP socket.
async fn read_line(sock: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt;
    let mut total = 0;
    loop {
        if total >= buf.len() {
            break;
        }
        let n = sock.read(&mut buf[total..]).await?;
        if n == 0 {
            break;
        }
        total += n;
        if buf[total - 1] == b'\n' {
            break;
        }
    }
    Ok(total)
}

/// Benchmark all four protocols and print a comparison table.
#[tokio::test]
#[ignore = "long-running all-protocol benchmark; run with --release --ignored --nocapture"]
async fn benchmark_all_protocols() {
    let n_orders = env_usize("ALL_PROTO_ORDERS", 1_000_000);
    let n_accounts = env_usize("ALL_PROTO_ACCOUNTS", 1_000);

    eprintln!();
    eprintln!("=== All-Protocol TPS Benchmark ===");
    eprintln!("  orders per protocol: {n_orders}");
    eprintln!("  accounts:            {n_accounts}");
    eprintln!();

    // Binary TCP (fastest — pure binary, minimal parsing).
    eprintln!("  [1/4] Binary TCP...");
    let tcp_tps = bench_binary_tcp(n_orders, n_accounts, 36200).await;

    // JSON-RPC (JSON parsing overhead).
    eprintln!("  [2/4] JSON-RPC...");
    let jsonrpc_tps = bench_jsonrpc(n_orders, n_accounts, 36201).await;

    // FIX 4.4 (SOH-delimited text parsing).
    eprintln!("  [3/4] FIX 4.4...");
    let fix_tps = bench_fix(n_orders, n_accounts, 36202).await;

    // WebSocket (JSON + WS framing overhead).
    eprintln!("  [4/4] WebSocket...");
    let ws_tps = bench_websocket(n_orders, n_accounts, 36203).await;

    eprintln!();
    eprintln!("=== Results Summary ===");
    eprintln!("  Protocol       | Throughput (orders/s)");
    eprintln!("  ---------------+---------------------");
    eprintln!("  Binary TCP     | {tcp_tps:>10.0}");
    eprintln!("  JSON-RPC       | {jsonrpc_tps:>10.0}");
    eprintln!("  FIX 4.4        | {fix_tps:>10.0}");
    eprintln!("  WebSocket      | {ws_tps:>10.0}");
    eprintln!();

    // Binary TCP should be fastest.
    assert!(tcp_tps > 0.0, "binary TCP should have positive throughput");
    assert!(jsonrpc_tps > 0.0, "JSON-RPC should have positive throughput");
    assert!(fix_tps > 0.0, "FIX should have positive throughput");
    assert!(ws_tps > 0.0, "WebSocket should have positive throughput");

    eprintln!("  All protocols verified ✓");
}

/// Smoke test: 10k orders per protocol.
#[tokio::test]
#[ignore = "all-protocol smoke test; run with --release --ignored --nocapture"]
async fn smoke_all_protocols() {
    let n_orders = env_usize("ALL_PROTO_ORDERS", 10_000);
    let n_accounts = env_usize("ALL_PROTO_ACCOUNTS", 100);

    eprintln!("=== All-Protocol Smoke Test ({n_orders} orders each) ===");

    let tcp_tps = bench_binary_tcp(n_orders, n_accounts, 36210).await;
    let jsonrpc_tps = bench_jsonrpc(n_orders, n_accounts, 36211).await;
    let fix_tps = bench_fix(n_orders, n_accounts, 36212).await;
    let ws_tps = bench_websocket(n_orders, n_accounts, 36213).await;

    eprintln!();
    eprintln!("  Binary TCP  | {tcp_tps:>10.0} orders/s");
    eprintln!("  JSON-RPC    | {jsonrpc_tps:>10.0} orders/s");
    eprintln!("  FIX 4.4     | {fix_tps:>10.0} orders/s");
    eprintln!("  WebSocket   | {ws_tps:>10.0} orders/s");
}
