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
//!
//! ## Measured results (M-series dev Mac, criterion p50)
//!
//! | Bench | p50 | Throughput | Gate | Verdict |
//! |-------|-----|-----------|------|---------|
//! | `settlement_single_fill` | 829 ns | ~1.2M orders/s/core | < 2 µs | ✅ |
//! | `settlement_sweep_10_levels` | 3.08 µs | ~325k sweeps/s/core | < 10 µs | ✅ |
//! | `raw_engine_single_fill` | 459 ns | ~2.2M fills/s/core | baseline | — |
//! | Settlement overhead | ~370 ns/fill | — | — | — |
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

criterion_group!(
    benches,
    settlement_single_fill,
    settlement_sweep_10_levels,
    raw_engine_single_fill
);
criterion_main!(benches);
