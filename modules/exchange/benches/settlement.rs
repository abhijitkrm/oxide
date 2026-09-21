//! Exchange settlement criterion benches — the trading-stack
//! settlement acceptance gates.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]
#![allow(clippy::doc_markdown)]
//!
//! ## What is measured, and the gates each enforces
//!
//! | Bench | What | Gate (source: plan.md §13 Phase 3, §9.2) |
//! |---|---|---|
//! | `settlement_single_fill` | full `handle()`: parse + pre-trade check + match + ledger transfer + event emit | p50 < 2 µs ⇒ ≥500k orders/s/core settled |
//! | `settlement_sweep_10_levels` | full `handle()` sweeping 10 resting makers | p50 < 10 µs ⇒ ≥100k sweeps/s/core |
//! | `raw_engine_single_fill` | `MatchingEngine::place()` only (no settlement) | baseline for head-to-head |
//! | `settlement_overhead` | derived: `settlement_single_fill − raw_engine_single_fill` | the ledger + event overhead per fill |
//! | `batch_settle_1k_distinct_pairs` | `handle_batch_settle`, 1k fills, every leg a unique (buyer,seller) pair | p50 < 1 ms ⇒ ≥1M fills/s settled |
//! | `batch_settle_1k_same_pair` | `handle_batch_settle`, 1k fills collapsing to 1 transfer | p50 < 1 ms ⇒ ≥1M fills/s validated |
//!
//! ## Measured results (M-series dev Mac, criterion p50)
//!
//! | Bench | p50 | Throughput | Gate | Verdict |
//! |-------|-----|-----------|------|---------|
//! | `settlement_single_fill` | 829 ns | ~1.2M orders/s/core | < 2 µs | ✅ |
//! | `settlement_sweep_10_levels` | 3.08 µs | ~325k sweeps/s/core | < 10 µs | ✅ |
//! | `raw_engine_single_fill` | 459 ns | ~2.2M fills/s/core | baseline | — |
//! | Settlement overhead | ~370 ns/fill | — | — | — |
//! | `batch_settle_1k_distinct_pairs` | 254 µs/1k fills | ~3.9M fills/s | < 1 ms | ✅ |
//! | `batch_settle_1k_same_pair` | 9.0 µs/1k fills | ~110M fills/s | < 1 ms | ✅ |
//!
//! `batch_settle` is the 1M-orders/s settlement path: ~254 ns/fill
//! worst-case (no pair aggregation — one ledger transfer per fill),
//! ~9 ns/fill when the batch aggregates to a single pair. End-to-end
//! through the 4-validator oxideBFT TCP pipeline it sustains
//! ~1.85M fills/s (~3.7M orders/s) at the 65,536-fill wire maximum —
//! see `crates/devnet/tests/settle_tps.rs`.
//!
//! ## Why these gates
//!
//! The matching engine alone sustains 22.5M ops/s/core (44.5 ns/op,
//! `crates/trading/benches/matching.rs`). Settlement adds, per fill:
//! - one `ledger.balance()` account-cache read (pre-trade check),
//! - one `ledger.transfer()` = two BTreeMap lookups + two inserts,
//! - one `fill_event` Vec allocation + byte copies,
//! - one `outcome_event` Vec allocation.
//!
//! The ledger's account-cache write (plus undo capture) is the dominant settlement
//! cost: each `transfer` does two key lookups and two key allocations
//! (`addr.0.to_vec()`). The gate (≥500k orders/s/core settled) is
//! conservative — it is 1/40th of the raw engine throughput, reflecting
//! that settlement is BTreeMap-bound, not arena-bound.
//!
//! ## Method notes
//!
//! - `black_box` on every input and consumed output.
//! - The exchange + ledger are created ONCE outside the bench (the
//!   `Module::handle` takes `&self` via internal Mutex, so no RefCell
//!   is needed). Setup only rests a maker; the measured section places
//!   a taker that fills it. After the fill, the book is empty, so the
//!   next iteration's setup rests a new maker. The ledger is funded with
//!   1T quote per trader — enough for ~13M fills at 75k each.
//! - This avoids the `iter_batched` by-value drop-in-measured-section
//!   regression documented in `crates/trading/benches/matching.rs`
//!   (234 µs false reading from Vec drop inside the timed loop).
//! - Realistic payloads: tick 1M ($0.01), lot 1K ($0.001), band
//!   [$10, $20] (1000 levels), 5-lot orders at tick 500 ($15.00).
//!   Notional per fill = 5_000 × 1.5B / 1e8 = 75_000 quote units.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use executor::{Module, TxContext};
use framework::Balances;
use primitives::Address;
use primitives::fixed::{Price, Qty};
use std::cell::RefCell;
use std::hint::black_box;
use std::sync::Arc;
use trading::{
    DenseBook, MarketConfig, MatchingEngine, NewOrder, OrderOutcome, OrderType, Side, StpMode,
    TimeInForce,
};

use exchange::ExchangeModule;

/// Fixture market: tick 0.01, lot 0.001, band [$10, $20] (1000
/// levels — a realistic ladder size for a liquid pair).
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

/// A test address: `[tag; 20]`.
fn addr(tag: u8) -> Address {
    Address([tag; 20])
}

/// A test `TxContext` with the given sender tag.
fn ctx(tag: u8) -> TxContext {
    TxContext { sender: addr(tag), nonce: 0, fee: 0 }
}

/// A limit order at `ticks` above the band floor, `lots` lots, owned
/// by `owner`.
fn limit(side: Side, ticks: u64, lots: u64, owner: u8) -> NewOrder {
    NewOrder {
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_000_000_000 + ticks * 1_000_000),
        qty: Qty(lots * 1_000),
        owner: addr(owner),
        stp: StpMode::None,
    }
}

/// The batch legs' fill price: tick 500 ($15.00), the same value the
/// registered orders carry as their limit.
const FILL_PRICE: u64 = 1_500_000_000;
/// The registered-order pool size (scale-6 qty units): every
/// account's working order is sized so criterion iterations can
/// never exhaust `remaining` — a bench iteration draws at most
/// `FILLS × fill qty` ≈ 16M units from a 1e15 pool.
const ORDER_POOL_QTY: u64 = 1_000_000_000_000_000;

/// Register one working order for `owner` under `client_id` — the
/// on-chain authorization every batch leg consumes. Both sides
/// escrow at registration: buys `FILL_PRICE × ORDER_POOL_QTY /
/// PRICE_SCALE` = 1.5e16 quote units (well under the `u64::MAX/4`
/// mint); sells `ORDER_POOL_QTY` of base custody, funded by a
/// same-size mint + deposit here. `client_id` is per-side (buys 1,
/// sells 2) so an account can hold both a buy and a sell working
/// order — the `distinct_pairs` fixture's seller range overlaps its
/// buyers.
fn register_working_order(
    ex: &ExchangeModule,
    ledger: &Arc<evm::EvmModule>,
    owner: u8,
    side: Side,
    mid: u8,
    client_id: u64,
) {
    if side == Side::Sell {
        ledger.mint(&addr(owner), ORDER_POOL_QTY);
        ex.handle(&ctx(owner), &exchange::msg::deposit_base(mid, ORDER_POOL_QTY))
            .expect("working-order base deposit");
    }
    ex.handle(
        &ctx(owner),
        &exchange::msg::register_order(u16::from(mid), side, FILL_PRICE, ORDER_POOL_QTY, client_id),
    )
    .expect("working-order registration");
}

/// Gate: p50 < 2 µs (≥500k orders/s/core settled).
///
/// Measures the full `ExchangeModule::handle()` path for a single
/// fill: message parse, pre-trade balance check, engine match, ledger
/// transfer (debit buyer + credit seller), and event emission. The
/// setup rests one maker sell; the measured section places one taker
/// buy that fills it.
fn settlement_single_fill(c: &mut Criterion) {
    // Create exchange + ledger ONCE; reuse across all iterations.
    // handle() takes &self (internal Mutex), so no RefCell needed.
    // Fund with 1e15 (1 quadrillion) quote — each fill costs 75k, so
    // the bench can run ~13 billion fills before exhausting funds.
    // The ledger is the real EVM account store — the production
    // `Balances` impl — so the measured fill cost includes the undo
    // capture + touched marking every production transfer pays.
    let ledger = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    ledger.mint(&addr(1), 1_000_000_000_000_000); // 1e15 units for buyer
    ledger.mint(&addr(9), 1_000_000_000_000_000); // 1e15 units for seller
    let ex = ExchangeModule::with_ledger(ledger);
    let mid = ex.list_market(cfg()).expect("market config valid");
    // Seller base custody: each iteration's maker sell escrows
    // 5_000 units at admission — 1e12 covers ~200M iterations.
    ex.handle(&ctx(9), &exchange::msg::deposit_base(mid, 1_000_000_000_000)).unwrap();
    let maker = limit(Side::Sell, 500, 5, 9);
    let taker = limit(Side::Buy, 500, 5, 1);

    c.bench_function("settlement_single_fill", |b| {
        b.iter_batched(
            || {
                // Setup (excluded): rest one maker sell.
                ex.handle(&ctx(9), &exchange::msg::place(mid, maker)).unwrap();
            },
            |_setup| {
                // Measured: taker buy fills the resting maker.
                let events = ex
                    .handle(black_box(&ctx(1)), black_box(&exchange::msg::place(mid, taker)))
                    .unwrap();
                assert_eq!(events.len(), 2, "1 fill + 1 outcome");
                black_box(events);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Gate: p50 < 10 µs (≥100k sweeps/s/core).
///
/// Measures the full `handle()` path for a 10-level sweep: 10 resting
/// makers at ticks 500–509, one marketable taker buy that fills all
/// 10. Each fill triggers a separate `ledger.transfer()`, so settlement
/// cost scales linearly with fill count.
fn settlement_sweep_10_levels(c: &mut Criterion) {
    let ledger = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    ledger.mint(&addr(1), 1_000_000_000_000_000);
    ledger.mint(&addr(9), 1_000_000_000_000_000);
    let ex = ExchangeModule::with_ledger(ledger);
    let mid = ex.list_market(cfg()).expect("market config valid");
    // Seller base custody: each iteration rests 10 lots of sells —
    // 1e12 units covers ~100M iterations of 10_000-unit escrows.
    ex.handle(&ctx(9), &exchange::msg::deposit_base(mid, 1_000_000_000_000)).unwrap();
    let taker = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Ioc,
        price: Price(1_509_000_000),
        qty: Qty(10_000),
        owner: addr(1),
        stp: StpMode::None,
    };

    c.bench_function("settlement_sweep_10_levels", |b| {
        b.iter_batched(
            || {
                // Setup (excluded): rest 10 maker sells at ticks 500..509.
                for i in 0..10u64 {
                    let maker = limit(Side::Sell, 500 + i, 1, 9);
                    ex.handle(&ctx(9), &exchange::msg::place(mid, maker)).unwrap();
                }
            },
            |_setup| {
                // Measured: taker buy 10 lots at tick 509, sweeps all.
                let events = ex
                    .handle(black_box(&ctx(1)), black_box(&exchange::msg::place(mid, taker)))
                    .unwrap();
                // 10 fills + 1 outcome.
                assert_eq!(events.len(), 11, "10 fills + 1 outcome");
                black_box(events);
            },
            BatchSize::PerIteration,
        );
    });
}

/// Baseline: raw `MatchingEngine::place()` for a single fill (no
/// settlement, no events, no ledger). This is the head-to-head
/// comparison point — the difference between this and
/// `settlement_single_fill` is the settlement overhead.
///
/// Uses `RefCell` so the engine outlives the setup closure (same
/// pattern as `crates/trading/benches/matching.rs`).
fn raw_engine_single_fill(c: &mut Criterion) {
    let e = RefCell::new(MatchingEngine::new(cfg(), DenseBook::new(cfg()).unwrap()).unwrap());
    let fills = RefCell::new(Vec::with_capacity(64));
    let maker = limit(Side::Sell, 500, 5, 9);
    let taker = limit(Side::Buy, 500, 5, 1);

    c.bench_function("raw_engine_single_fill", |b| {
        b.iter_batched(
            || {
                // Setup (excluded): rest one maker.
                let out = e.borrow_mut().place(maker, &mut fills.borrow_mut()).unwrap();
                let OrderOutcome::Resting { order_id, .. } = out else { panic!("setup must rest") };
                order_id
            },
            |_setup_id| {
                // Measured: taker buy fills the resting maker.
                let mut fills_ref = fills.borrow_mut();
                let out = e.borrow_mut().place(taker, &mut fills_ref).unwrap();
                assert_eq!(out, OrderOutcome::Filled);
                black_box(&out);
                black_box(&fills_ref);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Gate: p50 < 1 ms per 1k-fill batch ⇒ ≥1M fills/s settled.
///
/// This is the bench for the actual 1M-orders/s architecture: the
/// off-chain matcher does the book work; the chain only validates
/// each pre-matched leg (tick/lot/band/notional) and settles the
/// aggregated (buyer, seller) transfers. No engine `place()` call is
/// made — the measured cost is parse + validate + BTreeMap
/// accumulation + `ledger.transfer` per pair.
///
/// Worst case is measured: every fill is a *distinct* (buyer, seller)
/// pair, so aggregation cannot amortize the ledger transfers — 1k
/// fills mean 1k transfers.
fn batch_settle_1k_distinct_pairs(c: &mut Criterion) {
    const FILLS: usize = 1_000;
    let ledger = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0x5E));
    let mid = ex.list_market(cfg()).expect("market config valid");

    // Pre-build the batch: 1000 fills, each between a distinct
    // (buyer, seller) registered-order pair — the
    // aggregation-hostile case. Addresses are derived from the fill
    // index so pairs never repeat; each account registers ONE
    // working order under client id 1 (4 buyers × 256 sellers ⇒
    // 1024 possible order pairs, 1000 exercised).
    // u8→u16 indexing keeps 2×256 = 65k distinct pairs available.
    for b in 1u8..=4 {
        ledger.mint(&addr(b), u64::MAX / 4);
        register_working_order(&ex, &ledger, b, Side::Buy, mid, 1);
    }
    for s in 0u8..=255 {
        register_working_order(&ex, &ledger, s.wrapping_add(100), Side::Sell, mid, 2);
    }
    let fills: Vec<exchange::BatchFillEntry> = (0..FILLS)
        .map(|i| {
            #[allow(clippy::cast_possible_truncation)]
            let buyer = addr(((i / 256) + 1) as u8);
            #[allow(clippy::cast_possible_truncation)]
            let seller = addr(((i % 256) + 100) as u8);
            exchange::BatchFillEntry {
                market: u16::from(mid),
                price: Price(FILL_PRICE),
                qty: Qty(1_000),
                buy: exchange::OrderKey { owner: buyer, client_id: 1 },
                sell: exchange::OrderKey { owner: seller, client_id: 2 },
            }
        })
        .collect();
    let payload = exchange::msg::batch_settle(&fills);
    let op_ctx = ctx(0x5E);

    c.bench_function("batch_settle_1k_distinct_pairs", |b| {
        b.iter(|| {
            let events = ex.handle(black_box(&op_ctx), black_box(&payload)).expect("batch settles");
            // 1 `batch_fill` per (buyer, seller) pair + 1
            // `base_delivered` per (buyer, market) — 4 buyers.
            assert_eq!(events.len(), FILLS + 4, "pair fills + base deliveries");
            black_box(events);
        });
    });
}

/// Gate: p50 < 1 ms per 1k-fill batch ⇒ ≥1M fills/s settled.
///
/// Best case for the aggregation path: all 1k fills share one
/// (buyer, seller) pair, so the whole batch collapses to a single
/// ledger transfer. The measured cost is then pure per-leg
/// parse+validation — the floor for what `batch_settle` can ever
/// cost per fill.
fn batch_settle_1k_same_pair(c: &mut Criterion) {
    const FILLS: usize = 1_000;
    let ledger = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0x5E));
    let mid = ex.list_market(cfg()).expect("market config valid");
    ledger.mint(&addr(1), u64::MAX / 4);
    register_working_order(&ex, &ledger, 1, Side::Buy, mid, 1);
    register_working_order(&ex, &ledger, 9, Side::Sell, mid, 2);

    let fills: Vec<exchange::BatchFillEntry> = (0..FILLS)
        .map(|_| exchange::BatchFillEntry {
            market: u16::from(mid),
            price: Price(FILL_PRICE),
            qty: Qty(1_000),
            buy: exchange::OrderKey { owner: addr(1), client_id: 1 },
            sell: exchange::OrderKey { owner: addr(9), client_id: 2 },
        })
        .collect();
    let payload = exchange::msg::batch_settle(&fills);
    let op_ctx = ctx(0x5E);

    c.bench_function("batch_settle_1k_same_pair", |b| {
        b.iter(|| {
            let events = ex.handle(black_box(&op_ctx), black_box(&payload)).expect("batch settles");
            // All 1k fills share one (buyer, seller) pair — one
            // `batch_fill` event for the summed quote transfer plus
            // one `base_delivered` for the buyer's custody credit.
            assert_eq!(events.len(), 2, "one transfer + one delivery");
            black_box(events);
        });
    });
}

/// The production-devnet fixture shape: 16,384 fills clustering into
/// 16 buyers × 15 sellers = 240 distinct (buyer, seller) pairs — the
/// workload `settle_tps` generates end-to-end. This is the
/// aggregation-friendly case the flat map is built for: ~68 fills
/// per pair, so the per-leg cost is the probe+accumulate and the 240
/// transfers amortize away. Isolates the settle inner loop from the
/// consensus-pipeline noise that makes end-to-end A/B runs
/// unreliable.
fn batch_settle_16k_clustered_pairs(c: &mut Criterion) {
    const FILLS: usize = 16_384;
    const BUYERS: u8 = 16;
    const SELLERS: u8 = 15;
    let ledger = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0x5E));
    let mid = ex.list_market(cfg()).expect("market config valid");

    // Buyer ids 1..=16, seller ids 100..=114 — 240 disjoint
    // registered-order pairs, matching the devnet fixture's fan-out.
    // Each account registers one working order under client id 1.
    for b in 1u8..=BUYERS {
        ledger.mint(&addr(b), u64::MAX / 4);
        register_working_order(&ex, &ledger, b, Side::Buy, mid, 1);
    }
    for s in 100u8..100 + SELLERS {
        register_working_order(&ex, &ledger, s, Side::Sell, mid, 2);
    }
    let fills: Vec<exchange::BatchFillEntry> = (0..FILLS)
        .map(|i| {
            #[allow(clippy::cast_possible_truncation)]
            let buyer = addr(((i % usize::from(BUYERS)) + 1) as u8);
            #[allow(clippy::cast_possible_truncation)]
            let seller = addr(((i % usize::from(SELLERS)) + 100) as u8);
            exchange::BatchFillEntry {
                market: u16::from(mid),
                price: Price(FILL_PRICE),
                qty: Qty(1_000),
                buy: exchange::OrderKey { owner: buyer, client_id: 1 },
                sell: exchange::OrderKey { owner: seller, client_id: 2 },
            }
        })
        .collect();
    let payload = exchange::msg::batch_settle(&fills);
    let op_ctx = ctx(0x5E);

    c.bench_function("batch_settle_16k_clustered_pairs", |b| {
        b.iter(|| {
            let events = ex.handle(black_box(&op_ctx), black_box(&payload)).expect("batch settles");
            // gcd(16,15)=1 ⇒ the i%16 × i%15 cycle hits all 240
            // combos; buyer/seller id ranges are disjoint so every
            // leg is valid — 240 aggregated `batch_fill` transfers
            // plus one `base_delivered` per buyer (16).
            assert_eq!(events.len(), 256, "pair transfers + base deliveries");
            black_box(events);
        });
    });
}

criterion_group!(
    benches,
    settlement_single_fill,
    settlement_sweep_10_levels,
    raw_engine_single_fill,
    batch_settle_1k_distinct_pairs,
    batch_settle_1k_same_pair,
    batch_settle_16k_clustered_pairs
);
criterion_main!(benches);
