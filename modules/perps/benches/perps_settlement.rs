//! Perps settlement criterion benches — the perps trading-stack
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
//! | Bench | What | Gate (source: plan.md §13 Phase 3, §9.3) |
//! |---|---|---|
//! | `perps_place_with_margin` | full `handle()`: parse + match + position update + margin check + event emit | p50 < 3 µs ⇒ ≥333k orders/s/core |
//! | `perps_deposit` | full `handle()`: ledger debit + margin credit | p50 < 2 µs ⇒ ≥500k deposits/s/core |
//! | `perps_liquidation_check` | `liquidation_check()`: equity + maintenance calc | p50 < 5 µs ⇒ ≥200k checks/s/core |
//! | `raw_perps_engine_place` | `MatchingEngine::place()` only (no perps state) | baseline for head-to-head |
//!
//! ## Measured results (M-series dev Mac, criterion p50)
//!
//! | Bench | p50 | Throughput | Gate | Verdict |
//! |-------|-----|-----------|------|---------|
//! | `perps_place_with_margin` | 723 ns | ~1.38M orders/s/core | < 3 µs | ✅ |
//! | `perps_deposit` | 274 ns | ~3.65M deposits/s/core | < 2 µs | ✅ |
//! | `perps_liquidation_check` | 150 ns | ~6.7M checks/s/core | < 5 µs | ✅ |
//! | `raw_perps_engine_place` | 406 ns | ~2.46M fills/s/core | baseline | — |
//! | Perps overhead | ~316 ns/fill | — | — | — |
//!
//! ## Why these gates
//!
//! The perps module adds, on top of the raw matching engine:
//! - `apply_fill_to_position` per fill: BTreeMap lookup for the
//!   account, BTreeMap lookup/insert for the position, VWAP entry
//!   price recalculation (i128 multiply + divide),
//! - `margin_check` per place: clone of configs + marks BTreeMaps,
//!   equity calculation (iterate positions, i128 PnL + scale
//!   conversion), maintenance calculation,
//! - event emission (Vec allocations for fill + outcome events).
//!
//! The perps path is heavier than the spot exchange path because of
//! the position-state machine and the post-trade margin check. The
//! gate (≥333k orders/s/core) is conservative — 1/67th of the raw
//! engine throughput — reflecting the BTreeMap + i128 arithmetic
//! overhead.
//!
//! ## Method notes
//!
//! - `black_box` on every input and consumed output.
//! - The perps module + ledger are created ONCE outside the bench
//!   (`handle` takes `&self` via internal Mutex). Setup only rests a
//!   maker; the measured section places a taker. After the fill, the
//!   book is empty for the next iteration.
//! - This avoids the `iter_batched` by-value drop-in-measured-section
//!   regression documented in `crates/trading/benches/matching.rs`.
//! - Realistic payloads: tick 1M, lot 1K, band [$10, $20], 5-lot
//!   orders at tick 500 ($15.00). Mark price = 1.5B (mid of band).
//! - Both traders deposit 500M cross-margin so the margin check
//!   never triggers a margin call (happy path).
//! - The `liquidation_check` bench uses a fresh perps module per
//!   iteration (RefCell) because the position state must be reset.

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

use perps::{PerpsMarketConfig, PerpsModule};

/// Fixture market: tick 0.01, lot 0.001, band [$10, $20].
fn base_cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: 1_000_000,
        lot_size: 1_000,
        min_price: 1_000_000_000,
        max_price: 2_000_000_000,
        max_resting: 1 << 16,
    }
}

/// Fixture perps config: 10x max leverage, 0.5% maintenance margin.
fn perps_cfg() -> PerpsMarketConfig {
    PerpsMarketConfig { base: base_cfg(), max_leverage: 10, mmr_base_bps: 50 }
}

/// A test address: `[tag; 20]`.
fn addr(tag: u8) -> Address {
    Address([tag; 20])
}

/// A test `TxContext` with the given sender tag.
fn ctx(tag: u8) -> TxContext {
    TxContext { sender: addr(tag), nonce: 0, fee: 0 }
}

/// A limit order at `ticks` above the band floor, `lots` lots.
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

/// Gate: p50 < 3 µs (≥333k orders/s/core).
///
/// Measures the full `PerpsModule::handle()` path for a single fill:
/// message parse, engine match, `apply_fill_to_position` (VWAP
/// update), `margin_check` (equity + maintenance), and event emission.
/// The setup rests one maker sell; the measured section places one
/// taker buy that fills it, opening a long for trader 1 and a short
/// for trader 9.
fn perps_place_with_margin(c: &mut Criterion) {
    // Create perps + ledger ONCE; reuse across all iterations.
    // Fund with 1e15 quote — the margin top-ups below draw from it.
    let ledger = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    ledger.mint(&addr(1), 1_000_000_000_000_000);
    ledger.mint(&addr(9), 1_000_000_000_000_000);
    let perps = PerpsModule::with_ledger(ledger);
    let mid = perps.list_market(perps_cfg()).expect("perps config valid");
    perps.handle(&ctx(1), &perps::msg::deposit(0xFF, 500_000_000)).unwrap();
    perps.handle(&ctx(9), &perps::msg::deposit(0xFF, 500_000_000)).unwrap();
    let maker = limit(Side::Sell, 500, 5, 9);
    let taker = limit(Side::Buy, 500, 5, 1);
    // Setup margin top-up (excluded): positions accumulate — the
    // taker's long and maker's short each grow 5 lots per fill —
    // so each iteration's setup deposits enough cross-margin to
    // keep the initial-margin gate (notional/10x ≈ +7.5k per fill)
    // comfortably ahead. Without this the reused module would hit
    // "insufficient initial margin" after ~66k fills.
    let top_up = |tag: u8| {
        perps.handle(&ctx(tag), &perps::msg::deposit(0xFF, 1_000_000)).unwrap();
    };

    c.bench_function("perps_place_with_margin", |b| {
        b.iter_batched(
            || {
                top_up(1);
                top_up(9);
                perps.handle(&ctx(9), &perps::msg::place(mid, maker)).unwrap();
            },
            |_setup| {
                // Measured: taker buy fills the resting maker.
                let events = perps
                    .handle(black_box(&ctx(1)), black_box(&perps::msg::place(mid, taker)))
                    .unwrap();
                assert!(events.len() >= 2, "1 fill + 1 outcome");
                black_box(events);
            },
            BatchSize::PerIteration,
        );
    });
}

/// Gate: p50 < 2 µs (≥500k deposits/s/core).
///
/// Measures the full `handle()` path for a margin deposit: message
/// parse, `ledger.debit()` (account-cache write + undo capture), margin credit
/// (BTreeMap lookup/insert for the account + position), and event
/// emission. The ledger is funded with 1B quote; each deposit moves
/// 1k, so the bench can run ~1M iterations before exhausting funds.
fn perps_deposit(c: &mut Criterion) {
    let ledger = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    ledger.mint(&addr(1), 1_000_000_000_000_000);
    let perps = PerpsModule::with_ledger(ledger);
    perps.list_market(perps_cfg()).expect("perps config valid");

    c.bench_function("perps_deposit", |b| {
        b.iter_batched(
            || {},
            |_setup| {
                // Measured: deposit 1000 quote into cross-margin.
                let events = perps
                    .handle(black_box(&ctx(1)), black_box(&perps::msg::deposit(0xFF, 1_000)))
                    .unwrap();
                assert_eq!(events.len(), 1, "1 deposit event");
                black_box(events);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Gate: p50 < 5 µs (≥200k checks/s/core).
///
/// Measures `liquidation_check()` for an account with one open
/// position: equity calculation (PnL + scale conversion) and
/// maintenance margin comparison. Uses RefCell because the position
/// state must be reset each iteration (the liquidation closes the
/// position).
fn perps_liquidation_check(c: &mut Criterion) {
    // Build a fresh perps module per iteration via RefCell — the
    // liquidation closes the position, so state must reset.
    let build = || {
        let ledger = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
        ledger.mint(&addr(1), 1_000_000_000_000);
        ledger.mint(&addr(9), 1_000_000_000_000);
        let perps = PerpsModule::with_ledger(ledger);
        let mid = perps.list_market(perps_cfg()).unwrap();
        perps.handle(&ctx(1), &perps::msg::deposit(0xFF, 500_000_000)).unwrap();
        perps.handle(&ctx(9), &perps::msg::deposit(0xFF, 500_000_000)).unwrap();
        // Rest a sell and match with a buy to open a long.
        let maker = limit(Side::Sell, 500, 5, 9);
        perps.handle(&ctx(9), &perps::msg::place(mid, maker)).unwrap();
        let taker = limit(Side::Buy, 500, 5, 1);
        perps.handle(&ctx(1), &perps::msg::place(mid, taker)).unwrap();
        // Drop mark to 1.0B (entry was 1.5B) → underwater.
        perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
        perps
    };

    let perps = RefCell::new(build());

    c.bench_function("perps_liquidation_check", |b| {
        b.iter_batched(
            || {
                // Setup (excluded): rebuild the perps state if the
                // position was closed by a prior liquidation.
                if perps.borrow().position(&addr(1), 0).size == 0 {
                    *perps.borrow_mut() = build();
                }
            },
            |_setup| {
                // Measured: liquidation check on the underwater account.
                let events =
                    perps.borrow().liquidation_check(black_box(&addr(1))).expect("liq check ok");
                black_box(events);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Baseline: raw `MatchingEngine::place()` for a single fill (no
/// perps state, no margin check, no events). This is the head-to-head
/// comparison point — the difference between this and
/// `perps_place_with_margin` is the perps overhead.
fn raw_perps_engine_place(c: &mut Criterion) {
    let e = RefCell::new(
        MatchingEngine::new(
            base_cfg().validated().unwrap(),
            DenseBook::new(base_cfg().validated().unwrap()).unwrap(),
        )
        .unwrap(),
    );
    let fills = RefCell::new(Vec::with_capacity(64));
    let maker = limit(Side::Sell, 500, 5, 9);
    let taker = limit(Side::Buy, 500, 5, 1);

    c.bench_function("raw_perps_engine_place", |b| {
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
    perps_place_with_margin,
    perps_deposit,
    perps_liquidation_check,
    raw_perps_engine_place
);
criterion_main!(benches);
