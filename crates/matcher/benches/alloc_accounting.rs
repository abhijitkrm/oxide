//! Allocation accounting — audit001 §7.5's last named measurement.
//!
//! Wall-clock benches can't see the heap. This bench installs a
//! counting `GlobalAlloc` shim and runs the production-shaped
//! workloads inside it, reporting **allocations and bytes per
//! operation** for the paths the audit named:
//!
//! - the authenticated action path (`submit_action` cancel/amend —
//!   the dominant HFT message class);
//! - the matching path (`submit_order` crossing — fill/event vec
//!   production per match);
//! - the string-heavy API surfaces (`parse_fix_tags` builds a
//!   `HashMap<String, String>` per message; `extract_str` hands out
//!   owned `String`s; `format_*` build response `String`s).
//!
//! Informational only — no gate. The numbers are the budget any
//! allocation-free hot-path claim must beat, and the baseline a
//! future arena/ring-string refactor must improve on. The counting
//! shim lives in its own bench binary so the two atomic increments
//! per alloc never skew the timing benches.

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]
// per-op ratios in the report
// The workspace forbids unsafe code; this bench needs exactly one
// exemption — `GlobalAlloc` is the only way to count allocations
// process-wide, which is what this file exists to measure. The impl
// is a pure pass-through to `System`; no shipped code is affected
// (a bench binary has its own allocator).
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use crypto::ed25519::{Ed25519SecretKey, owner_address};
use matcher::protocol::{ActionRequest, ActionType, OrderResponse, sign_action, sign_order};
use matcher::{MatchingServer, OrderRequest};
use primitives::fixed::{Price, Qty};
use trading::{MarketConfig, OrderType, Side, TimeInForce};

/// Counting allocator — forwards every call to the system allocator
/// and tallies count + requested bytes. Two relaxed atomic adds per
/// alloc; that's the whole instrumentation, so what it measures is
/// the workload, not itself.
static ALLOC_OPS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

struct Counting;

// SAFETY: `Counting` is a pure pass-through to `System` — it adds no
// ownership, aliasing, or layout changes; the counters are
// observational only.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_OPS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarded verbatim to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded verbatim to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// One measured row: ops performed, allocs made, bytes requested.
#[derive(Default)]
struct Row {
    ops: u64,
    allocs: u64,
    bytes: u64,
}

static ROWS: Mutex<Vec<(&'static str, Row)>> = Mutex::new(Vec::new());

/// Snapshot the counters, run `f`, and accumulate the deltas under
/// `name`. Returns the wall time so the closure can feed
/// `iter_custom`.
fn measured<F: FnOnce()>(name: &'static str, iters: u64, f: F) -> std::time::Duration {
    let ops0 = ALLOC_OPS.load(Ordering::Relaxed);
    let bytes0 = ALLOC_BYTES.load(Ordering::Relaxed);
    let t = Instant::now();
    f();
    let elapsed = t.elapsed();
    let ops = ALLOC_OPS.load(Ordering::Relaxed) - ops0;
    let bytes = ALLOC_BYTES.load(Ordering::Relaxed) - bytes0;
    let mut rows = ROWS.lock().expect("rows");
    if let Some((_, row)) = rows.iter_mut().find(|(n, _)| *n == name) {
        row.ops += iters;
        row.allocs += ops;
        row.bytes += bytes;
    } else {
        rows.push((name, Row { ops: iters, allocs: ops, bytes }));
    }
    elapsed
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

fn account_key(i: u32) -> Ed25519SecretKey {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&i.to_le_bytes());
    Ed25519SecretKey::from_bytes(&seed)
}

/// Build a server with `n_resting` live sell orders across
/// `n_accounts` plus one pre-signed action per resting order — same
/// shape as `matcher_throughput`'s `cancel_amend_setup`, scaled down
/// because allocations (not time) are the measurement.
fn action_setup(
    n_resting: usize,
    n_accounts: usize,
    amend: bool,
) -> (MatchingServer, Vec<ActionRequest>) {
    let keys: Vec<Ed25519SecretKey> =
        (0..u32::try_from(n_accounts).unwrap_or(u32::MAX)).map(account_key).collect();
    let mut next_nonce = vec![0u64; n_accounts];
    let mut server = MatchingServer::new(cfg(), n_accounts);
    for k in &keys {
        server.fund_account(&owner_address(&k.verifying_key()), u64::MAX / 4);
    }
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
            owner: primitives::Address([0u8; 20]),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        sign_order(&mut req, &keys[a]);
        next_nonce[a] += 1;
        let resp = server.submit_order(&req);
        assert!(!resp.rejected, "setup order {k} rejected");
        resting_ids.push(resp.order_id);
    }
    let actions = resting_ids
        .iter()
        .enumerate()
        .map(|(k, &oid)| {
            let a = k % n_accounts;
            let mut req = ActionRequest {
                action_type: if amend { ActionType::Amend } else { ActionType::Cancel },
                order_id: oid,
                new_price: Price(if amend { 1_600_000_000 } else { 0 }),
                new_qty: Qty(if amend { 2_000 } else { 0 }),
                side: Side::Sell,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                nonce: next_nonce[a],
                owner: primitives::Address([0u8; 20]),
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

/// `submit_order` pool: alternating maker sells and taker buys so
/// each buy crosses the book — the fill/event-vec path.
fn order_setup(n_orders: usize) -> (MatchingServer, Vec<OrderRequest>) {
    let seller_key = account_key(0);
    let buyer_key = account_key(1);
    let mut server = MatchingServer::new(cfg(), 1_000);
    server.fund_account(&owner_address(&seller_key.verifying_key()), u64::MAX / 4);
    server.fund_account(&owner_address(&buyer_key.verifying_key()), u64::MAX / 4);
    let orders = (0..n_orders)
        .map(|i| {
            let (key, side) =
                if i % 2 == 0 { (&seller_key, Side::Sell) } else { (&buyer_key, Side::Buy) };
            let mut req = OrderRequest {
                market: 0,
                side,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price(1_500_000_000),
                qty: Qty(1_000),
                nonce: (i / 2) as u64,
                owner: primitives::Address([0u8; 20]),
                pubkey: [0u8; 32],
                signature: [0u8; 64],
            };
            sign_order(&mut req, key);
            req
        })
        .collect();
    (server, orders)
}

/// A representative FIX new-order body — SOH-delimited tag=value
/// pairs, 9 tags: realistic tag-map churn per message.
fn fix_order_body() -> String {
    format!(
        "54=1\x0140=2\x0159=0\x0144=15.00\x0138=0.001\x011=0x{}\x019666=3\x019700={}\x019701={}\x01",
        "42".repeat(20),
        "aa".repeat(32),
        "bb".repeat(64),
    )
}

/// A representative WS/JSON order body — the shape `parse_ws_order`
/// expects.
fn ws_order_body() -> String {
    format!(
        "{{\"method\":\"oxide_submitOrder\",\"params\":{{\"market\":0,\"side\":\"buy\",\"type\":\"limit\",\"tif\":\"gtc\",\"price\":1500000000,\"qty\":1000,\"nonce\":3,\"owner\":\"0x{}\",\"pubkey\":\"0x{}\",\"signature\":\"0x{}\"}},\"id\":1}}",
        "42".repeat(20),
        "aa".repeat(32),
        "bb".repeat(64),
    )
}

fn bench_allocs(c: &mut Criterion) {
    let mut g = c.benchmark_group("alloc_accounting");
    g.sample_size(10);

    // Server-path rows: real signed actions against a live book.
    for amend in [false, true] {
        let name = if amend { "amend_action" } else { "cancel_action" };
        g.bench_function(name, |b| {
            b.iter_custom(|iters| {
                let n = usize::try_from(iters).unwrap_or(usize::MAX).max(1);
                // ≤10 orders + 10 actions per account stays inside
                // the admission rate limit (the earlier
                // cancel_amend setup hit it at 100/account).
                let (mut server, actions) = action_setup(n, (n / 10 + 1).max(2), amend);
                measured(name, iters, || {
                    for req in &actions {
                        let _ = server.submit_action(black_box(req));
                    }
                })
            });
        });
    }

    g.bench_function("crossing_fill", |b| {
        b.iter_custom(|iters| {
            let n = usize::try_from(iters).unwrap_or(usize::MAX).max(2);
            let (mut server, orders) = order_setup(n);
            measured("crossing_fill", iters, || {
                for req in &orders {
                    let _ = server.submit_order(black_box(req));
                }
            })
        });
    });

    // String-alloc API surfaces — pure functions, measured per call.
    let fix_body = fix_order_body();
    g.bench_function("fix_parse_order", |b| {
        b.iter_custom(|iters| {
            measured("fix_parse_order", iters, || {
                for _ in 0..iters {
                    black_box(matcher::fix::parse_fix_order(black_box(&fix_body)));
                }
            })
        });
    });

    let ws_body = ws_order_body();
    g.bench_function("ws_parse_order", |b| {
        b.iter_custom(|iters| {
            measured("ws_parse_order", iters, || {
                for _ in 0..iters {
                    black_box(matcher::ws::parse_ws_order(black_box(&ws_body)));
                }
            })
        });
    });

    let resp = OrderResponse::resting(trading::OrderId(42), 0);
    g.bench_function("fix_report", |b| {
        b.iter_custom(|iters| {
            measured("fix_report", iters, || {
                for _ in 0..iters {
                    black_box(matcher::fix::format_fix_execution_report(
                        black_box(&resp),
                        "clid-001",
                    ));
                }
            })
        });
    });

    g.bench_function("ws_response", |b| {
        b.iter_custom(|iters| {
            measured("ws_response", iters, || {
                for _ in 0..iters {
                    black_box(matcher::ws::format_ws_response(black_box(&resp), 7));
                }
            })
        });
    });

    g.finish();
}

/// Print the accumulated per-row table. Runs last so every row has
/// numbers; the printout — not the timing — is this bench's output.
fn alloc_report(c: &mut Criterion) {
    let printed = AtomicU64::new(0);
    c.bench_function("alloc_report", |b| {
        b.iter(|| {
            // One print per run — criterion iterates `b.iter` ~100×
            // and the accumulated table is identical every time.
            if printed.fetch_add(1, Ordering::Relaxed) > 0 {
                return;
            }
            let rows = ROWS.lock().expect("rows");
            eprintln!("\n=== allocation accounting (per operation) ===");
            eprintln!("{:<18} {:>10} {:>12} {:>10}", "row", "ops", "allocs/op", "bytes/op");
            for (name, row) in rows.iter() {
                let a = row.allocs as f64 / row.ops.max(1) as f64;
                let b = row.bytes as f64 / row.ops.max(1) as f64;
                eprintln!("{name:<18} {:>10} {a:>12.2} {b:>10.1}", row.ops);
            }
            eprintln!();
        });
    });
}

criterion_group!(benches, bench_allocs, alloc_report);
criterion_main!(benches);
