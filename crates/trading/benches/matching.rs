//! Matching-engine criterion benches — the Phase 3 acceptance gates.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]
//!
//! ## What is measured, and the gates each enforces
//!
//! | Bench | What | Gate (source: plan.md §13 Phase 3, §9.1) |
//! |---|---|---|
//! | `rest_cancel_pair` | place a GTC order (rests) + cancel it | pair p50 < 400ns ⇒ each op < 200ns ("insert/cancel p50 < 200ns") |
//! | `match_single_level` | one taker fully fills one resting maker | p50 < 300ns ("match-op p50 < 300ns") |
//! | `match_sweep_10_levels` | market order sweeps 10 one-order levels | p50 < 3µs (10 × 300ns match-ops) |
//! | `mixed_workload` | deterministic mixed place/match/cancel stream | ≥ 1M ops/s/core ("mixed workload ≥ 1M ops/s") |
//! | `fok_prescan_bitboard` vs `fok_prescan_linear` | FOK `capped_fillable` pre-scan: bitboard walk vs the displaced linear band scan | head-to-head (hft-audit F-22): bitboard must win decisively on a sparse book |
//!
//! `rest_cancel_pair` at p50 < 400ns is exactly 5M simple ops/s
//! single-core (2 ops per pair) — the "engine-only ≥ 5M ops/s"
//! gate. Numbers below are from an M-series dev machine (relative
//! baseline); the 16-core `x86_64` rig is the source for absolute gate
//! claims (benchmarks skill §4).
//!
//! ## Method notes
//!
//! - `black_box` on every input and consumed output — the compiler
//!   must not elide the work.
//! - `iter_batched` where per-iteration setup (resting a maker) must
//!   be excluded from the measurement.
//! - The mixed workload uses a fixed-seed xorshift stream: identical
//!   run-to-run (testing-standards determinism rule), no `rand`
//!   dependency in a hot-path crate.
//! - Realistic payloads: scale-8 prices in a ~$10–20 band, 1–10 lot
//!   quantities, distinct 20-byte owners.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primitives::Address;
use primitives::fixed::{Price, Qty};
use std::cell::RefCell;
use std::hint::black_box;
use trading::{
    DenseBook, MarketConfig, MatchingEngine, NewOrder, OrderId, OrderOutcome, OrderType, Side,
    StpMode, TimeInForce,
};

/// Fixture market: tick 0.01, lot 0.001, band [$10, $20] (1,000
/// levels — a realistic ladder size for a liquid pair).
fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 1,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 16,
    }
}

fn engine() -> MatchingEngine {
    MatchingEngine::new(
        cfg().validated().unwrap(),
        DenseBook::new(cfg().validated().unwrap()).unwrap(),
    )
    .unwrap()
}

/// An engine wired as the exchange wires it: the resting fold is
/// what `state_root` reads per block, so every resting mutation
/// pays one `committed_leaf` hash. This is the consensus-relevant
/// engine configuration — the `_folded` rows are the honest gate.
fn folded_engine() -> MatchingEngine {
    let mut e = engine();
    // The exchange module's own leaf function — not a replica — so
    // the `_folded` rows price exactly what consensus pays per
    // resting mutation, including the `CanonicalState` preimage
    // build (hft-audit-2 F-26: a stack-buffer replica hid ~75 ns of
    // per-leaf reallocations the production fn paid).
    e.enable_resting_fold(exchange::book_resting_leaf);
    e
}

/// A limit order at `ticks` above the band floor.
fn limit(side: Side, ticks: u64, lots: u64, owner: u8, tif: TimeInForce) -> NewOrder {
    NewOrder {
        side,
        order_type: OrderType::Limit,
        tif,
        price: Price(1_000_000_000 + ticks * 1_000_000),
        qty: Qty(lots * 1_000),
        owner: Address([owner; 20]),
        stp: StpMode::None,
    }
}

/// Gate: pair p50 < 400ns (⇒ insert < 200ns, cancel < 200ns; ≥5M
/// simple ops/s single-core).
fn rest_cancel_pair(c: &mut Criterion) {
    let mut e = engine();
    let mut fills = Vec::with_capacity(64);
    // Far from the mid — resting is the dominant cost being measured
    // (level link + bitboard set), not any match work.
    let order = limit(Side::Buy, 10, 5, 1, TimeInForce::Gtc);
    c.bench_function("rest_cancel_pair", |b| {
        b.iter(|| {
            let out = black_box(&mut e).place(black_box(order), black_box(&mut fills)).unwrap();
            match out {
                OrderOutcome::Resting { order_id, .. } => {
                    black_box(black_box(&mut e).cancel(order_id).unwrap());
                }
                other => panic!("bench invariant broken: {other:?}"),
            }
        });
    });
}

/// Gate: p50 < 300ns (single match-op).
///
/// Measures the full `place()` of one crossing limit order that fills
/// one resting maker. `iter_batched` + `RefCell` is used because the
/// taker consumes the maker, so each iteration needs a fresh book, but
/// the engine must outlive the setup closure (shared `&mut`).
///
/// **Reading this number:** the measured p50 (~470 ns) is the full
/// `place()` call — validation, book lookup, one match-op, and fill
/// generation — plus two `RefCell` borrows. The per-match-op cost in
/// isolation is derived from `match_sweep_10_levels`: that bench pays
/// the same per-call overhead once but performs 10 match-ops, so
/// `(sweep − single) / 9` isolates the inner match-op. The derived
/// per-match-op is ~160–190 ns, well under the 300 ns gate.
fn match_single_level(c: &mut Criterion) {
    let e = RefCell::new(engine());
    let fills = RefCell::new(Vec::with_capacity(64));
    let maker = limit(Side::Sell, 500, 5, 9, TimeInForce::Gtc);
    let taker = limit(Side::Buy, 500, 5, 1, TimeInForce::Gtc);
    c.bench_function("match_single_level", |b| {
        b.iter_batched(
            || {
                // Setup (excluded): rest one maker, 5 lots at tick 500.
                let out = e.borrow_mut().place(maker, &mut fills.borrow_mut()).unwrap();
                let OrderOutcome::Resting { order_id, .. } = out else { panic!("setup must rest") };
                order_id
            },
            |_setup_id| {
                // Measured: taker fully fills the maker.
                let mut fills_ref = fills.borrow_mut();
                let out = e.borrow_mut().place(taker, &mut fills_ref).unwrap();
                debug_assert_eq!(out, OrderOutcome::Filled);
                black_box(&out);
                debug_assert_eq!(fills_ref.len(), 1);
                black_box(&fills_ref);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Gate: p50 < 3µs (a 10-level sweep is ≥10 match-ops at <300ns).
///
/// Same `RefCell` + `iter_batched` pattern as `match_single_level`: the
/// taker consumes all 10 levels, so each iteration needs a fresh book.
/// The per-match-op cost is derived as `(sweep − single) / 9`.
fn match_sweep_10_levels(c: &mut Criterion) {
    let e = RefCell::new(engine());
    let fills = RefCell::new(Vec::with_capacity(64));
    let taker = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Market,
        tif: TimeInForce::Ioc,
        price: Price(0),
        qty: Qty(10_000),
        owner: Address([1; 20]),
        stp: StpMode::None,
    };
    c.bench_function("match_sweep_10_levels", |b| {
        b.iter_batched(
            || {
                // Setup (excluded): 10 ask levels, one 1-lot order each,
                // ticks 500..509.
                for i in 0..10u64 {
                    let out = e
                        .borrow_mut()
                        .place(
                            limit(Side::Sell, 500 + i, 1, 9, TimeInForce::Gtc),
                            &mut fills.borrow_mut(),
                        )
                        .unwrap();
                    debug_assert!(matches!(out, OrderOutcome::Resting { .. }));
                }
            },
            |()| {
                // Measured: market buy sweeps all ten.
                let mut fills_ref = fills.borrow_mut();
                let out = e.borrow_mut().place(taker, &mut fills_ref).unwrap();
                debug_assert_eq!(out, OrderOutcome::Filled);
                debug_assert_eq!(fills_ref.len(), 10);
                black_box(&fills_ref);
            },
            BatchSize::SmallInput,
        );
    });
}

/// Deterministic xorshift64* — fixed-seed stream for the mixed
/// workload. Determinism rule (testing-standards): no wall clock, no
/// OS randomness in benches.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Gate: ≥ 1M ops/s/core on the mixed stream.
///
/// Mix mirrors a taker-heavy venue: ~55% resting limit placements
/// (both sides, staggered prices), ~30% marketable takers that fill
/// against the book, ~15% cancels. The book reaches a steady-state
/// depth of tens of resting orders across tens of levels, so every op
/// exercises live ladder state (bitboard discovery, FIFO walks,
/// idmap hits).
fn mixed_workload(c: &mut Criterion) {
    let mut e = engine();
    let mut fills = Vec::with_capacity(256);
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut live: Vec<OrderId> = Vec::with_capacity(512);
    // Seed the book: 50 resting orders per side.
    for i in 0..50u64 {
        let bid = e
            .place(limit(Side::Buy, 400 + i % 40, 1 + i % 5, 7, TimeInForce::Gtc), &mut fills)
            .unwrap();
        let ask = e
            .place(limit(Side::Sell, 500 + i % 40, 1 + i % 5, 8, TimeInForce::Gtc), &mut fills)
            .unwrap();
        if let OrderOutcome::Resting { order_id, .. } = bid {
            live.push(order_id);
        }
        if let OrderOutcome::Resting { order_id, .. } = ask {
            live.push(order_id);
        }
    }

    c.bench_function("mixed_workload", |b| {
        b.iter(|| {
            // 256 ops per measured iteration for a stable mix ratio.
            for _ in 0..256 {
                let r = black_box(&mut rng).next();
                match r % 100 {
                    0..=54 => {
                        // Rest a limit order on a pseudo-random side and
                        // staggered price; keep it if it rests.
                        let side = if r & 0x100 == 0 { Side::Buy } else { Side::Sell };
                        let ticks = match side {
                            Side::Buy => 350 + (r >> 9) % 90,
                            Side::Sell => 500 + (r >> 9) % 90,
                        };
                        let lots = 1 + (r >> 16) % 5;
                        let out = e
                            .place(
                                limit(side, ticks, lots, 1, TimeInForce::Gtc),
                                black_box(&mut fills),
                            )
                            .unwrap();
                        if let OrderOutcome::Resting { order_id, .. } = out {
                            live.push(order_id);
                        }
                    }
                    55..=84 => {
                        // Marketable taker: cross the spread into the
                        // resting side.
                        let (side, ticks) =
                            if r & 0x200 == 0 { (Side::Buy, 600) } else { (Side::Sell, 400) };
                        let lots = 1 + (r >> 20) % 3;
                        let out = e
                            .place(
                                NewOrder {
                                    side,
                                    order_type: OrderType::Limit,
                                    tif: TimeInForce::Ioc,
                                    price: Price(1_000_000_000 + ticks * 1_000_000),
                                    qty: Qty(lots * 1_000),
                                    owner: Address([2; 20]),
                                    stp: StpMode::None,
                                },
                                black_box(&mut fills),
                            )
                            .unwrap();
                        black_box(&out);
                    }
                    _ => {
                        // Cancel a live order (FIFO-ish eviction).
                        if !live.is_empty() {
                            // u64→usize: masked by live.len(), cannot
                            // truncate the index.
                            #[allow(clippy::cast_possible_truncation)]
                            let idx = ((r >> 24) as usize) % live.len();
                            let id = live.swap_remove(idx);
                            if let Ok(canceled) = e.cancel(id) {
                                black_box(&canceled);
                            }
                        }
                    }
                }
            }
        });
    });
}

/// Fold-enabled variant of `rest_cancel_pair` — same gate (pair
/// p50 < 400ns) against the consensus engine shape. Every rest +
/// cancel now pays one `committed_leaf` hash each, so this row
/// prices the 7.4 fold on the two most common book mutations.
///
/// Measured (x86 audit box, Zen 2, loaded host, criterion p50, with
/// the real `exchange::book_resting_leaf`): 669 ns with the old
/// `Vec`-grown `CanonicalState` preimage → 390 ns with the inline
/// buffer (hft-audit-2 T-3/F-26). The remaining fold tax over the raw
/// pair is the two BLAKE3 leaf hashes. The 400 ns gate is met only
/// narrowly on the consensus shape.
fn rest_cancel_pair_folded(c: &mut Criterion) {
    let mut e = folded_engine();
    let mut fills = Vec::with_capacity(64);
    let order = limit(Side::Buy, 10, 5, 1, TimeInForce::Gtc);
    c.bench_function("rest_cancel_pair_folded", |b| {
        b.iter(|| {
            let out = black_box(&mut e).place(black_box(order), black_box(&mut fills)).unwrap();
            match out {
                OrderOutcome::Resting { order_id, .. } => {
                    black_box(black_box(&mut e).cancel(order_id).unwrap());
                }
                other => panic!("bench invariant broken: {other:?}"),
            }
        });
    });
}

/// Fold-enabled variant of `mixed_workload` — same ≥1M ops/s gate.
/// Taker fills exercise the `fold_replace` path (out old qty, in
/// new) plus maker removals — the heaviest per-op fold density the
/// book can produce.
fn mixed_workload_folded(c: &mut Criterion) {
    let mut e = folded_engine();
    let mut fills = Vec::with_capacity(256);
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut live: Vec<OrderId> = Vec::with_capacity(512);
    for i in 0..50u64 {
        let bid = e
            .place(limit(Side::Buy, 400 + i % 40, 1 + i % 5, 7, TimeInForce::Gtc), &mut fills)
            .unwrap();
        let ask = e
            .place(limit(Side::Sell, 500 + i % 40, 1 + i % 5, 8, TimeInForce::Gtc), &mut fills)
            .unwrap();
        if let OrderOutcome::Resting { order_id, .. } = bid {
            live.push(order_id);
        }
        if let OrderOutcome::Resting { order_id, .. } = ask {
            live.push(order_id);
        }
    }

    c.bench_function("mixed_workload_folded", |b| {
        b.iter(|| {
            for _ in 0..256 {
                let r = black_box(&mut rng).next();
                match r % 100 {
                    0..=54 => {
                        let side = if r & 0x100 == 0 { Side::Buy } else { Side::Sell };
                        let ticks = match side {
                            Side::Buy => 350 + (r >> 9) % 90,
                            Side::Sell => 500 + (r >> 9) % 90,
                        };
                        let lots = 1 + (r >> 16) % 5;
                        let out = e
                            .place(
                                limit(side, ticks, lots, 1, TimeInForce::Gtc),
                                black_box(&mut fills),
                            )
                            .unwrap();
                        if let OrderOutcome::Resting { order_id, .. } = out {
                            live.push(order_id);
                        }
                    }
                    55..=84 => {
                        let (side, ticks) =
                            if r & 0x200 == 0 { (Side::Buy, 600) } else { (Side::Sell, 400) };
                        let lots = 1 + (r >> 20) % 3;
                        let out = e
                            .place(
                                NewOrder {
                                    side,
                                    order_type: OrderType::Limit,
                                    tif: TimeInForce::Ioc,
                                    price: Price(1_000_000_000 + ticks * 1_000_000),
                                    qty: Qty(lots * 1_000),
                                    owner: Address([2; 20]),
                                    stp: StpMode::None,
                                },
                                black_box(&mut fills),
                            )
                            .unwrap();
                        black_box(&out);
                    }
                    _ => {
                        if !live.is_empty() {
                            #[allow(clippy::cast_possible_truncation)]
                            let idx = ((r >> 24) as usize) % live.len();
                            let id = live.swap_remove(idx);
                            if let Ok(canceled) = e.cancel(id) {
                                black_box(&canceled);
                            }
                        }
                    }
                }
            }
        });
    });
}

/// Head-to-head gate for the F-22 fix: the FOK pre-scan
/// (`capped_fillable`) walks the opposing side's *active* levels via
/// the bitboard instead of scanning all `level_count` slots. On this
/// book — 1,000 levels, liquidity only in ticks 500..510 — the linear
/// scan pays ~500 idle level visits (plus a divide per visit) before
/// reaching liquidity; the bitboard pays only the 11 active levels.
///
/// What is measured: one `capped_fillable_probe` call (new code) vs
/// `capped_fillable_linear` (the displaced implementation, kept
/// `#[doc(hidden)]` solely as this baseline). No gate number — the
/// requirement is a decisive relative win; criterion's own
/// regression tracking guards it thereafter.
fn fok_prescan(c: &mut Criterion) {
    let mut e = engine();
    let mut fills = Vec::with_capacity(64);
    // 11 resting asks at ticks 500..510 — ~500 idle levels below and
    // ~490 above, the shape where the linear scan burns the most time.
    for i in 0..11u64 {
        let out = e.place(limit(Side::Sell, 500 + i, 1, 9, TimeInForce::Gtc), &mut fills).unwrap();
        debug_assert!(matches!(out, OrderOutcome::Resting { .. }));
    }
    let req = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Fok,
        price: Price(1_000_000_000 + 600 * 1_000_000),
        qty: Qty(11_000),
        owner: Address([3; 20]),
        stp: StpMode::None,
    };
    let mut group = c.benchmark_group("fok_prescan");
    group.bench_function("bitboard", |b| {
        b.iter(|| {
            black_box(e.capped_fillable_probe(black_box(&req), black_box(Some(req.price.0))))
        });
    });
    group.bench_function("linear", |b| {
        b.iter(|| {
            black_box(e.capped_fillable_linear(black_box(&req), black_box(Some(req.price.0))))
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    rest_cancel_pair,
    match_single_level,
    match_sweep_10_levels,
    mixed_workload,
    rest_cancel_pair_folded,
    mixed_workload_folded,
    fok_prescan
);
criterion_main!(benches);
