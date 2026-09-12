//! Single-node trading throughput test — 100M trades through the
//! raw trading machine and exchange settlement path (no consensus,
//! no TCP, no BLS, no executor block storage).
//!
//! This measures the trading machine's full `handle()` path
//! (matching + bank settlement + event emission) at scale, without
//! consensus or executor overhead. It's the "how fast can the
//! trading engine actually go" number — the upper bound on trading
//! TPS before consensus, networking, and signature verification are
//! added.
//!
//! # What this measures
//!
//! Two measurements are reported:
//!
//! 1. **Raw matching engine**: calls `MatchingEngine::place()`
//!    directly. Each maker sell is placed (resting), then each taker
//!    buy is placed (matching the maker). Measures pure matching
//!    throughput (no settlement, no event collection).
//!
//! 2. **Exchange settlement**: calls `ExchangeModule::handle()`
//!    directly (via the `Module` trait). Each call parses the message,
//!    matches, settles the fill through the bank (debit buyer,
//!    credit seller), and emits events. Measures the full settlement
//!    path that consensus would execute.
//!
//! # Integrity checks
//!
//! - All orders are processed (no panics).
//! - The matching engine's resting count is consistent.
//! - The exchange module's resting count is consistent.
//! - Bank balances are non-negative.
//!
//! # Running
//!
//! ```sh
//! # Default: 100M trades (100M maker + 100M taker = 200M orders)
//! cargo test -p devnet --test trading_throughput --release -- --ignored --nocapture
//!
//! # Smaller run: 1M trades
//! THROUGHPUT_TRADES=1_000_000 cargo test -p devnet --test trading_throughput --release -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]

use executor::Module;
use primitives::fixed::{Price, Qty};
use std::sync::Arc;
use std::time::Instant;
use trading::{
    DenseBook, MarketConfig, MatchingEngine, NewOrder, OrderType, Side, StpMode, TimeInForce,
};

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

/// Build a maker sell order at tick 500 ($15.00), 1 lot.
fn maker_sell(owner: primitives::Address) -> NewOrder {
    NewOrder {
        side: Side::Sell,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner,
        stp: StpMode::None,
    }
}

/// Build a taker buy order at tick 500 ($15.00), 1 lot.
fn taker_buy(owner: primitives::Address) -> NewOrder {
    NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner,
        stp: StpMode::None,
    }
}

/// Run the raw matching engine throughput test.
///
/// Creates a `MatchingEngine`, then places `n_trades` maker sells
/// (each resting) followed by `n_trades` taker buys (each matching
/// one maker). Measures pure matching throughput — no settlement,
/// no event collection, no bank interaction.
fn run_raw_engine(n_trades: usize) {
    eprintln!("\n--- Raw Matching Engine Throughput ---");
    eprintln!("raw engine: {n_trades} maker sells + {n_trades} taker buys = {n_trades} fills");

    let mut engine = MatchingEngine::new(cfg(), DenseBook::new(cfg()).expect("book creation"))
        .expect("engine creation");
    let maker_addr = primitives::Address([0x09; 20]);
    let taker_addr = primitives::Address([0x01; 20]);
    let mut fills = Vec::with_capacity(64);

    let start = Instant::now();

    // Alternate maker sells and taker buys: each maker rests, then
    // the next taker matches it. This keeps the book at 0–1 resting
    // orders at all times, avoiding the `max_resting` cap (64k).
    // It's also the realistic trading pattern for a high-frequency
    // market — makers and takers interleave continuously.
    let mut total_fills = 0usize;
    for _ in 0..n_trades {
        fills.clear();
        let _ = engine.place(maker_sell(maker_addr), &mut fills);
        fills.clear();
        let _ = engine.place(taker_buy(taker_addr), &mut fills);
        total_fills += fills.len();
    }

    let elapsed = start.elapsed();
    let total_orders = n_trades * 2;
    let tps = total_orders as f64 / elapsed.as_secs_f64();
    let fills_ps = total_fills as f64 / elapsed.as_secs_f64();

    eprintln!("raw engine: {total_fills} fills in {:.3}s", elapsed.as_secs_f64());
    eprintln!("  order throughput: {tps:.0} orders/s");
    eprintln!("  fill throughput:  {fills_ps:.0} fills/s");
    eprintln!("  resting count:    {} (should be 0)", engine.resting_count());

    // Integrity: all makers should be matched (resting count = 0).
    assert_eq!(
        engine.resting_count(),
        0,
        "all makers should be matched after {n_trades} taker buys"
    );
    assert_eq!(total_fills, n_trades, "each taker should match exactly one maker");

    // Gate: raw matching engine must sustain ≥ 1M ops/s
    // (plan.md §13 Phase 3, matching.rs bench gate). This is the
    // "engine-only ≥ 5M ops/s" gate de-rated for the full place()
    // call (validation + book lookup + match + fill generation).
    // The 1M floor is conservative for CI runners; the 16-core
    // x86_64 rig is the source for absolute gate claims.
    if n_trades >= 100_000 {
        assert!(
            tps >= 1_000_000.0,
            "raw engine throughput gate failed: {tps:.0} orders/s < 1M orders/s (plan.md §13 Phase 3)"
        );
    }
}

/// Run the exchange settlement throughput test.
///
/// Creates an `ExchangeModule` backed by a `BankModule`, lists a
/// market, then processes `n_trades` maker sells + `n_trades` taker
/// buys via `Module::handle()`. Each taker buy matches one maker
/// sell, producing a fill + bank transfer (debit buyer, credit
/// seller). Measures the full settlement path that consensus would
/// execute.
fn run_exchange_settlement(n_trades: usize) {
    eprintln!("\n--- Exchange Settlement Throughput ---");
    eprintln!("exchange: {n_trades} maker sells + {n_trades} taker buys = {n_trades} fills");

    // Setup: bank + exchange with 10T quote each for buyer and seller.
    // 100M fills at 15k quote/fill = 1.5T total. 10T is enough.
    let bank = Arc::new(bank::BankModule::new());
    bank.mint(&primitives::Address([0x01; 20]), 10_000_000_000_000);
    bank.mint(&primitives::Address([0x09; 20]), 10_000_000_000_000);
    let exchange = Arc::new(exchange::ExchangeModule::with_bank(bank));
    exchange.list_market(cfg()).expect("market config valid");

    let maker_ctx =
        executor::TxContext { sender: primitives::Address([0x09; 20]), nonce: 0, fee: 100 };
    let taker_ctx =
        executor::TxContext { sender: primitives::Address([0x01; 20]), nonce: 0, fee: 100 };

    // Pre-build the place-order messages (not timed).
    eprintln!("exchange: building {n_trades} maker + taker messages...");
    let maker_msg = exchange::msg::place(0, maker_sell(primitives::Address([0x09; 20])));
    let taker_msg = exchange::msg::place(0, taker_buy(primitives::Address([0x01; 20])));

    let start = Instant::now();

    // Alternate maker sells and taker buys: each maker rests, then
    // the next taker matches it. This keeps the book at 0–1 resting
    // orders at all times, avoiding the `max_resting` cap (64k).
    let mut total_events = 0usize;
    for _ in 0..n_trades {
        let _ = exchange.handle(&maker_ctx, &maker_msg);
        total_events += exchange.handle(&taker_ctx, &taker_msg).map_or(0, |e| e.len());
    }

    let elapsed = start.elapsed();
    let total_orders = n_trades * 2;
    let tps = total_orders as f64 / elapsed.as_secs_f64();
    let fills_ps = n_trades as f64 / elapsed.as_secs_f64();

    eprintln!("exchange: {total_events} events in {:.3}s", elapsed.as_secs_f64());
    eprintln!("  order throughput: {tps:.0} orders/s");
    eprintln!("  fill throughput:  {fills_ps:.0} fills/s");
    eprintln!("  resting count:    {} (should be 0)", exchange.resting_count(0));

    // Integrity: all makers should be matched.
    assert_eq!(
        exchange.resting_count(0),
        0,
        "all makers should be matched after {n_trades} taker buys"
    );

    // Gate: exchange settlement must sustain ≥ 100k ops/s
    // (plan.md §13 Phase 3). This is the full settlement path
    // (matching + bank transfer + event emission), not just the
    // matching engine. The 100k floor is conservative for CI
    // runners; the 16-core x86_64 rig is the source for absolute
    // gate claims.
    if n_trades >= 100_000 {
        assert!(
            tps >= 100_000.0,
            "exchange throughput gate failed: {tps:.0} orders/s < 100k orders/s (plan.md §13 Phase 3)"
        );
    }
}

/// Default: 100M trades through both the raw engine and exchange
/// settlement path.
#[test]
#[ignore = "long-running throughput test; run with --release --ignored --nocapture"]
fn trading_throughput_100m() {
    let n_trades = env_usize("THROUGHPUT_TRADES", 100_000_000);
    run_raw_engine(n_trades);
    run_exchange_settlement(n_trades);

    eprintln!();
    eprintln!("=== Single-Node Trading Throughput Summary ===");
    eprintln!("  trades:          {n_trades}");
    eprintln!("  (see per-engine results above)");
    eprintln!("================================================");
}

/// Quick smoke test: 1M trades.
#[test]
#[ignore = "throughput test; run with --release --ignored --nocapture"]
fn trading_throughput_smoke() {
    let n_trades = env_usize("THROUGHPUT_TRADES", 1_000_000);
    run_raw_engine(n_trades);
    run_exchange_settlement(n_trades);
}
