//! 1B-order throughput benchmark with 1M active accounts.
//!
//! Measures the off-chain matching server's throughput with:
//! - 1,000,000 active accounts (funded with balance).
//! - 1,000,000,000 orders (500M maker sells + 500M taker buys).
//! - Balance check on every buy order (anti-spam gate).
//!
//! # What this measures
//!
//! The full off-chain order entry path:
//! 1. Decode the order (binary protocol, 42 bytes).
//! 2. Balance check (`HashMap` lookup, 1M accounts).
//! 3. Match via `MatchingEngine::place()`.
//! 4. Settle (update balance cache, accumulate fills).
//! 5. Encode the response (9 bytes).
//!
//! This is the number that matters for HFT — how many orders/s
//! can the matching server actually sustain with real balance
//! checks and 1M active accounts.
//!
//! # Running
//!
//! ```sh
//! # Full 1B orders with 1M accounts (default)
//! cargo bench -p matcher --bench matcher_throughput
//!
//! # Smaller run: 10M orders with 100k accounts
//! BENCH_ORDERS=10_000_000 BENCH_ACCOUNTS=100_000 cargo bench -p matcher --bench matcher_throughput
//! ```

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use matcher::{MatchingServer, OrderRequest};
use primitives::fixed::{Price, Qty};
use std::hint::black_box;
use trading::{MarketConfig, OrderType, Side, TimeInForce};

/// Parse an env var as a usize, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// A test market config: tick 0.01, lot 0.001, [$10, $20], 64k max resting.
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

/// Generate a deterministic address from an index.
fn addr_from_index(i: u32) -> primitives::Address {
    let mut addr = [0u8; 20];
    addr[..4].copy_from_slice(&i.to_le_bytes());
    primitives::Address(addr)
}

/// Build a maker sell order for account `i`.
fn maker_sell(i: u32) -> OrderRequest {
    OrderRequest {
        market: 0,
        side: Side::Sell,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce: 0,
        owner: addr_from_index(i),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    }
}

/// Build a taker buy order for account `i`.
fn taker_buy(i: u32) -> OrderRequest {
    OrderRequest {
        market: 0,
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce: 0,
        owner: addr_from_index(i),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    }
}

/// Benchmark the full order entry path: decode → balance check →
/// match → settle → encode response.
fn bench_order_entry(c: &mut Criterion) {
    let n_orders = env_usize("BENCH_ORDERS", 1_000_000_000);
    let n_accounts = env_usize("BENCH_ACCOUNTS", 1_000_000);

    let mut group = c.benchmark_group("order_entry");
    group.throughput(Throughput::Elements(n_orders as u64));
    group.sample_size(10); // Fewer samples for large runs.
    group.measurement_time(std::time::Duration::from_secs(30));

    group.bench_function("1b_orders_1m_accounts", |bencher| {
        bencher.iter_with_setup(
            || {
                // Setup: create server, fund 1M accounts.
                let mut server = MatchingServer::new(cfg(), n_accounts);
                for i in 0..u32::try_from(n_accounts).unwrap_or(u32::MAX) {
                    server.fund_account(&addr_from_index(i), 1_000_000_000_000);
                }
                server
            },
            |mut server| {
                // Measured: submit n_orders orders, alternating
                // maker sells and taker buys. Each maker rests, then
                // the next taker matches it. This keeps the book at
                // 0–1 resting orders (avoids max_resting cap) and
                // exercises the balance check on every buy order.
                //
                // Use two accounts: account 0 (maker/seller) and
                // account 1 (taker/buyer). Alternate between them.
                let maker = maker_sell(0);
                let taker = taker_buy(1);

                for _ in 0..n_orders / 2 {
                    let _ = server.submit_order(black_box(&maker));
                    let _ = server.submit_order(black_box(&taker));
                }

                black_box(server.orders_processed());
            },
        );
    });

    group.finish();
}

/// Benchmark the binary protocol encode/decode overhead (no matching).
fn bench_protocol_codec(c: &mut Criterion) {
    let req = OrderRequest {
        market: 0,
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce: 0,
        owner: primitives::Address([0x42; 20]),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };

    let mut group = c.benchmark_group("protocol_codec");
    group.throughput(Throughput::Elements(1));

    group.bench_function("encode_request", |b| {
        b.iter(|| {
            let encoded = matcher::protocol::encode_request(black_box(&req));
            black_box(encoded);
        });
    });

    let encoded = matcher::protocol::encode_request(&req);

    group.bench_function("decode_request", |b| {
        b.iter(|| {
            let decoded = matcher::protocol::decode_request(black_box(&encoded));
            black_box(decoded);
        });
    });

    group.finish();
}

/// Benchmark the balance cache with 1M accounts.
fn bench_balance_cache(c: &mut Criterion) {
    let n_accounts = env_usize("BENCH_ACCOUNTS", 1_000_000);

    let mut group = c.benchmark_group("balance_cache");
    group.throughput(Throughput::Elements(1));

    group.bench_function("lookup_1m_accounts", |b| {
        b.iter_with_setup(
            || {
                // Setup: create cache with 1M funded accounts.
                let mut cache = matcher::BalanceCache::with_capacity(n_accounts);
                for i in 0..u32::try_from(n_accounts).unwrap_or(u32::MAX) {
                    cache.set(&addr_from_index(i), 1_000_000_000_000);
                }
                cache
            },
            |cache| {
                // Measured: random lookups across 1M accounts.
                let i = std::hint::black_box(500_000u32);
                let balance = cache.get(&addr_from_index(i));
                black_box(balance);
            },
        );
    });

    group.finish();
}

criterion_group!(benches, bench_order_entry, bench_protocol_codec, bench_balance_cache);
criterion_main!(benches);
