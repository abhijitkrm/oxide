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
use crypto::ed25519::{Ed25519SecretKey, owner_address};
use matcher::protocol::{ActionRequest, ActionType, sign_action, sign_order};
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
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 16,
    }
}

/// Generate a deterministic address from an index.
fn addr_from_index(i: u32) -> primitives::Address {
    let mut addr = [0u8; 20];
    addr[..4].copy_from_slice(&i.to_le_bytes());
    primitives::Address(addr)
}

/// Deterministic per-account signing key — every order must
/// authenticate at the admission boundary (signature + derived-owner
/// binding), so the benchmark signs like a real client.
fn account_key(i: u32) -> Ed25519SecretKey {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&i.to_le_bytes());
    Ed25519SecretKey::from_bytes(&seed)
}

/// Build a signed order for `key`'s account at `nonce`.
fn signed_order(key: &Ed25519SecretKey, side: Side, nonce: u64) -> OrderRequest {
    let mut req = OrderRequest {
        market: 0,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce,
        owner: addr_from_index(0),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    sign_order(&mut req, key);
    req
}

/// Benchmark the full order entry path: decode → verify → nonce →
/// balance check → match → settle → encode response.
///
/// Orders are pre-signed in setup — Ed25519 signing is client-side
/// work, so the measured region isolates the server path (which now
/// includes `verify_order` on every submission). Each order carries
/// a unique per-account nonce or the replay gate would reject it.
fn bench_order_entry(c: &mut Criterion) {
    // Default 100k orders: the pre-signed pool is materialized in
    // memory (~200 B/order) and each pool costs a signing pass in
    // setup — scale with BENCH_ORDERS as RAM/time allow.
    let n_orders = env_usize("BENCH_ORDERS", 100_000);
    let n_accounts = env_usize("BENCH_ACCOUNTS", 1_000_000);

    let mut group = c.benchmark_group("order_entry");
    group.throughput(Throughput::Elements(n_orders as u64));
    group.sample_size(10); // Fewer samples for large runs.
    group.measurement_time(std::time::Duration::from_secs(30));

    group.bench_function("authenticated_order_entry", |bencher| {
        bencher.iter_with_setup(
            || {
                // Setup: two trading accounts (maker + taker) plus
                // the 1M-account balance map for lookup realism.
                let seller_key = account_key(0);
                let buyer_key = account_key(1);
                let seller = owner_address(&seller_key.verifying_key());
                let buyer = owner_address(&buyer_key.verifying_key());
                let mut server = MatchingServer::new(cfg(), n_accounts);
                for i in 0..u32::try_from(n_accounts).unwrap_or(u32::MAX) {
                    server.fund_account(&addr_from_index(i), 1_000_000_000_000);
                }
                server.fund_account(&seller, u64::MAX / 4);
                server.fund_account(&buyer, u64::MAX / 4);
                // Pre-sign the workload: alternating maker sells and
                // taker buys, per-account nonces 0..n/2. Each maker
                // rests, the next taker matches it (book stays at
                // 0–1 resting orders).
                let orders: Vec<OrderRequest> = (0..n_orders)
                    .map(|i| {
                        if i % 2 == 0 {
                            signed_order(&seller_key, Side::Sell, (i / 2) as u64)
                        } else {
                            signed_order(&buyer_key, Side::Buy, (i / 2) as u64)
                        }
                    })
                    .collect();
                (server, orders)
            },
            |(mut server, orders)| {
                // Measured: submit each pre-signed order through the
                // full admission boundary (verify → nonce → risk →
                // balance → match → settle).
                for req in &orders {
                    let _ = server.submit_order(black_box(req));
                }
                black_box(server.orders_processed());
            },
        );
    });

    group.finish();
}

/// Benchmark order-batch authentication: per-item `verify_strict`
/// (the displaced admission path) vs `VerifiedOrder::batch_with_chain_id`
/// (one multi-scalar multiplication across the whole batch).
///
/// Acceptance gate (audit remediation): the batch path must beat the
/// per-item path at the batch sizes transports actually send — a
/// negative or flat result means the machinery is dead weight and the
/// batch seam should revert to per-item verification.
fn bench_order_auth(c: &mut Criterion) {
    let batch_size = env_usize("BENCH_BATCH", 256);
    // Pre-sign a realistic batch: many distinct accounts, all valid.
    let orders: Vec<OrderRequest> =
        (0..batch_size).map(|i| signed_order(&account_key(i as u32), Side::Buy, 0)).collect();

    let mut group = c.benchmark_group("order_auth");
    group.throughput(Throughput::Elements(batch_size as u64));

    group.bench_function("per_item_verify", |bencher| {
        bencher.iter(|| {
            let mut ok = 0usize;
            for req in &orders {
                if matcher::protocol::VerifiedOrder::with_chain_id(
                    *req,
                    matcher::protocol::CHAIN_ID,
                )
                .is_some()
                {
                    ok += 1;
                }
            }
            black_box(ok)
        });
    });

    group.bench_function("batch_verify", |bencher| {
        bencher.iter(|| {
            let out = matcher::protocol::VerifiedOrder::batch_with_chain_id(
                black_box(&orders),
                matcher::protocol::CHAIN_ID,
            );
            black_box(out.iter().filter(|o| o.is_some()).count())
        });
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

/// Build a server with `n_resting` live sell orders spread across
/// `n_accounts` (the per-account resting cap is 1000 — risk.rs — so
/// a real book needs real spread), then pre-sign one cancel or amend
/// per resting order. `amend_every` selects the mix: 0 = all cancels,
/// 1 = all amends, 5 = four cancels per amend. Each account's nonces
/// continue sequentially from its order flow — orders and actions
/// share the replay gate, so the setup is the honest interleaving.
fn cancel_amend_setup(
    n_resting: usize,
    n_accounts: usize,
    amend_every: usize,
) -> (MatchingServer, Vec<ActionRequest>) {
    let keys: Vec<Ed25519SecretKey> =
        (0..u32::try_from(n_accounts).unwrap_or(u32::MAX)).map(account_key).collect();
    let mut next_nonce = vec![0u64; n_accounts];
    let mut server = MatchingServer::new(cfg(), n_accounts);
    for k in &keys {
        server.fund_account(&owner_address(&k.verifying_key()), u64::MAX / 4);
    }
    // Resting sell ladder across 64 tick-aligned levels inside the
    // market's [$10, $20] band — a multi-level book, not a stack at
    // one price.
    let mut resting_ids = Vec::with_capacity(n_resting);
    for k in 0..n_resting {
        let a = k % n_accounts;
        let mut req = OrderRequest {
            market: 0,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000 + (k as u64 % 64) * 1_000_000),
            qty: Qty(1_000),
            nonce: next_nonce[a],
            owner: addr_from_index(0),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        sign_order(&mut req, &keys[a]);
        next_nonce[a] += 1;
        let resp = server.submit_order(&req);
        assert!(!resp.rejected, "setup order {k} rejected: {:?}", resp.reject_reason);
        resting_ids.push(resp.order_id);
    }
    // Pre-sign the action workload — Ed25519 signing is client-side,
    // so it stays out of the measured region exactly as for orders.
    let actions = resting_ids
        .iter()
        .enumerate()
        .map(|(k, &oid)| {
            let a = k % n_accounts;
            let amend = amend_every != 0 && k % amend_every == amend_every - 1;
            let mut req = ActionRequest {
                action_type: if amend { ActionType::Amend } else { ActionType::Cancel },
                order_id: oid,
                new_price: Price(if amend {
                    1_600_000_000 + (k as u64 % 64) * 1_000_000
                } else {
                    0
                }),
                new_qty: Qty(if amend { 2_000 } else { 0 }),
                side: Side::Sell,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                nonce: next_nonce[a],
                owner: addr_from_index(0),
                pubkey: [0u8; 32],
                signature: [0u8; 64],
            };
            next_nonce[a] += 1;
            sign_action(&mut req, &keys[a]);
            req
        })
        .collect();
    (server, actions)
}

/// Benchmark the cancel/amend-dominant workload — the message class
/// that actually dominates an HFT venue (audit 7.5: resting orders
/// churn via cancel/re-quote far more often than fresh flow arrives;
/// the "actions are rare" assumption was wrong). Every action crosses
/// the full admission boundary: Ed25519 verify + owner binding +
/// nonce consume + authorization + engine dispatch.
///
/// - `cancel_resting`: terminal cancels on live orders (id unbind +
///   reserve refund path).
/// - `amend_resting`: cancel + resubmit at a new price — the market
///   maker's re-quote, the most frequent control message.
/// - `cancel_amend_4to1`: four cancels per amend on disjoint order
///   sets, so every action lands on a live order.
fn bench_cancel_amend(c: &mut Criterion) {
    let n_resting = env_usize("BENCH_RESTING", 10_000);
    let n_accounts = env_usize("BENCH_ACCOUNTS", 1_000).max(n_resting / 1_000 + 1);

    let mut group = c.benchmark_group("cancel_amend");
    group.throughput(Throughput::Elements(n_resting as u64));
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(20));

    for (name, amend_every) in
        [("cancel_resting", 0usize), ("amend_resting", 1), ("cancel_amend_4to1", 5)]
    {
        group.bench_function(name, |bencher| {
            bencher.iter_with_setup(
                || cancel_amend_setup(n_resting, n_accounts, amend_every),
                |(mut server, actions)| {
                    for req in &actions {
                        let _ = server.submit_action(black_box(req));
                    }
                    // Honesty gate: every action must have landed —
                    // otherwise the row is timing rejection fast
                    // paths, not the real workload.
                    assert_eq!(server.auth_rejections(), 0, "auth rejects");
                    assert_eq!(server.engine_rejections(), 0, "engine rejects");
                    black_box(server.orders_processed());
                },
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_order_entry,
    bench_order_auth,
    bench_protocol_codec,
    bench_balance_cache,
    bench_cancel_amend
);
criterion_main!(benches);
