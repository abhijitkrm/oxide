use super::*;
use crate::book::DenseBook;

use primitives::fixed::{Price, Qty};
// Fixture market: tick 0.01 raw 1e6, lot 0.001 raw 1e3,
// band [10.00, 10.64] → 65 levels, small arena for tests.
fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 1,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(1_064_000_000),
        max_resting: 64,
    }
}

fn engine() -> MatchingEngine {
    let book = DenseBook::new(cfg().validated().unwrap()).unwrap();
    MatchingEngine::new(cfg().validated().unwrap(), book).unwrap()
}

fn order(
    side: Side,
    order_type: OrderType,
    tif: TimeInForce,
    price_raw: u64,
    qty_raw: u64,
    owner: u8,
) -> NewOrder {
    NewOrder {
        side,
        order_type,
        tif,
        price: Price(price_raw),
        qty: Qty(qty_raw),
        owner: Address([owner; 20]),
        stp: StpMode::None,
    }
}

/// The foundational behavior: a marketable order matches a
/// resting order, both sides see correct outcomes and balances.
#[test]
fn marketable_limit_fills_resting_maker() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Maker rests a sell at 10.50.
    let out = e
        .place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
            &mut fills,
        )
        .unwrap();
    assert_eq!(
        out,
        OrderOutcome::Resting {
            order_id: OrderId(0),
            price: Price(1_050_000_000),
            resting_qty: Qty(5_000)
        }
    );

    // Taker buys 3.0 at 10.50 (crosses).
    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 3_000, 2),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Filled);

    assert_eq!(fills.len(), 1);
    assert_eq!(fills[0].price, Price(1_050_000_000));
    assert_eq!(fills[0].qty, Qty(3_000));
    assert_eq!(fills[0].maker_order_id, OrderId(0));
    assert_eq!(fills[0].taker_order_id, OrderId(1));
    assert_eq!(fills[0].taker_side, Side::Buy);

    // Maker's remainder is still resting.
    let mut entries = Vec::new();
    e.resting_entries(&mut entries);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].qty, Qty(2_000));
}

#[test]
fn price_time_priority_fifo_within_level() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Two makers at the same price, different owners.
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 3_000, 2),
        &mut fills,
    )
    .unwrap();

    // A taker sweeps the whole level: the FIRST maker fills first.
    e.place(order(Side::Buy, OrderType::Market, TimeInForce::Ioc, 0, 5_000, 3), &mut fills)
        .unwrap();

    assert_eq!(fills.len(), 2);
    assert_eq!(fills[0].maker_order_id, OrderId(0), "first arrival must fill first");
    assert_eq!(fills[0].qty, Qty(2_000));
    assert_eq!(fills[1].maker_order_id, OrderId(1));
    assert_eq!(fills[1].qty, Qty(3_000));
    assert_eq!(e.resting_count(), 0);
}

#[test]
fn sweep_walks_levels_best_first() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Ask ladder: 10.50 (1k), 10.51 (2k), 10.52 (4k).
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 1),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 2_000, 1),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_052_000_000, 4_000, 1),
        &mut fills,
    )
    .unwrap();

    // Buy 5k at limit 10.52: sweeps 1k @ 10.50, 2k @ 10.51, then
    // 2k of the 4k @ 10.52 — the 10.52 maker keeps 2k resting.
    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_052_000_000, 5_000, 2),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Filled);
    assert_eq!(fills.len(), 3);
    assert_eq!(fills[0].price, Price(1_050_000_000));
    assert_eq!(fills[1].price, Price(1_051_000_000));
    assert_eq!(fills[2].price, Price(1_052_000_000));
    assert_eq!(fills[2].qty, Qty(2_000), "last level fills partially");
    assert_eq!(e.resting_count(), 1, "10.52 maker partially consumed");
    assert_eq!(e.best_ask(), Some((Price(1_052_000_000), Qty(2_000))));
}

#[test]
fn limit_above_market_rests_partial() {
    let mut e = engine();
    let mut fills = Vec::new();

    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
        &mut fills,
    )
    .unwrap();
    // Buy 5k at 10.50: fills 2k, rests 3k.
    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 2),
            &mut fills,
        )
        .unwrap();
    assert_eq!(
        out,
        OrderOutcome::Resting {
            order_id: OrderId(1),
            price: Price(1_050_000_000),
            resting_qty: Qty(3_000)
        }
    );
    // Best bid is now our remainder.
    assert_eq!(e.best_bid(), Some((Price(1_050_000_000), Qty(3_000))));
}

#[test]
fn ioc_remainder_canceled_not_resting() {
    let mut e = engine();
    let mut fills = Vec::new();

    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
        &mut fills,
    )
    .unwrap();
    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Ioc, 1_050_000_000, 5_000, 2),
            &mut fills,
        )
        .unwrap();
    assert_eq!(
        out,
        OrderOutcome::CanceledRemainder { order_id: OrderId(1), filled_qty: Qty(2_000) }
    );
    assert_eq!(e.resting_count(), 0);
    assert_eq!(e.best_bid(), None, "IOC remainder must not rest");
}

#[test]
fn fok_fully_fillable_executes() {
    let mut e = engine();
    let mut fills = Vec::new();

    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
        &mut fills,
    )
    .unwrap();
    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Fok, 1_050_000_000, 5_000, 2),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Filled);
    assert_eq!(fills.len(), 1);
}

#[test]
fn fok_insufficient_liquidity_kills_without_fills() {
    let mut e = engine();
    let mut fills = Vec::new();

    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
        &mut fills,
    )
    .unwrap();
    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Fok, 1_050_000_000, 5_000, 2),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Killed);
    assert!(fills.is_empty(), "FOK kill must not execute anything");
    // Maker untouched.
    assert_eq!(e.best_ask(), Some((Price(1_050_000_000), Qty(2_000))));
}

#[test]
fn fok_respects_price_limit() {
    let mut e = engine();
    let mut fills = Vec::new();

    // 5k available at 10.52 — but the FOK limit is 10.51.
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_052_000_000, 5_000, 1),
        &mut fills,
    )
    .unwrap();
    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Fok, 1_051_000_000, 5_000, 2),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Killed);
    assert!(fills.is_empty());
}

#[test]
fn post_only_rejects_crossing_order() {
    let mut e = engine();
    let mut fills = Vec::new();

    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
        &mut fills,
    )
    .unwrap();
    // A post-only buy AT the ask would cross → rejected.
    let out = e
        .place(
            order(Side::Buy, OrderType::PostOnly, TimeInForce::Gtc, 1_050_000_000, 2_000, 2),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Rejected(RejectReason::PostOnlyWouldCross));
    // A post-only buy below the ask rests.
    let out = e
        .place(
            order(Side::Buy, OrderType::PostOnly, TimeInForce::Gtc, 1_049_000_000, 2_000, 2),
            &mut fills,
        )
        .unwrap();
    assert!(matches!(out, OrderOutcome::Resting { .. }));
}

#[test]
fn cancel_removes_order_and_restores_capacity() {
    let mut e = engine();
    let mut fills = Vec::new();

    let out = e
        .place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
            &mut fills,
        )
        .unwrap();
    let OrderOutcome::Resting { order_id, .. } = out else { panic!("must rest") };

    let canceled = e.cancel(order_id).unwrap();
    assert_eq!(canceled.qty, Qty(2_000));
    assert_eq!(canceled.owner, Address([1; 20]));
    assert_eq!(e.resting_count(), 0);
    assert_eq!(e.best_ask(), None);

    // Canceling again fails loudly.
    assert_eq!(e.cancel(order_id), Err(TradingError::OrderNotFound));
}

#[test]
fn validation_rejections_reach_caller() {
    let mut e = engine();
    let mut fills = Vec::new();

    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_500, 2_000, 1),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Rejected(RejectReason::PriceOffTick));

    let out = e
        .place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_500, 1),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Rejected(RejectReason::InvalidQty));
}

#[test]
fn market_order_on_empty_book_cancels_remainder() {
    let mut e = engine();
    let mut fills = Vec::new();

    let out = e
        .place(order(Side::Buy, OrderType::Market, TimeInForce::Ioc, 0, 5_000, 1), &mut fills)
        .unwrap();
    assert_eq!(out, OrderOutcome::CanceledRemainder { order_id: OrderId(0), filled_qty: Qty(0) });
}

#[test]
fn ids_are_assigned_at_submission_in_order() {
    let mut e = engine();
    let mut fills = Vec::new();

    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 1),
        &mut fills,
    )
    .unwrap();
    e.place(order(Side::Sell, OrderType::Market, TimeInForce::Ioc, 0, 1_000, 1), &mut fills)
        .unwrap();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 1_000, 1),
        &mut fills,
    )
    .unwrap();
    // Even the market order (which never rests) consumed id 1.
    assert_eq!(e.next_order_id(), 3);
}

#[test]
fn book_full_rejects_at_capacity() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Fill the arena (max_resting = 64) with distinct in-band
    // prices (ticks 0..=63 — tick 64 is the band ceiling, kept
    // for the post-cancel refill below).
    for i in 0..64u64 {
        let price = 1_000_000_000 + i * 1_000_000;
        let out = e
            .place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, price, 1_000, 1),
                &mut fills,
            )
            .unwrap();
        assert!(matches!(out, OrderOutcome::Resting { .. }), "order {i} must rest");
    }
    let out = e
        .place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_064_000_000, 1_000, 1),
            &mut fills,
        )
        .unwrap();
    assert_eq!(out, OrderOutcome::Rejected(RejectReason::BookFull));

    // Cancel one → capacity frees (tick 64 is in-band).
    e.cancel(OrderId(0)).unwrap();
    let out = e
        .place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_064_000_000, 1_000, 1),
            &mut fills,
        )
        .unwrap();
    assert!(matches!(out, OrderOutcome::Resting { .. }));
}

#[test]
fn no_crossed_book_after_any_operation() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Interleave resting bids and asks at non-crossing prices.
    for i in 0..10u64 {
        let bid = 1_040_000_000 - i * 1_000_000;
        let ask = 1_050_000_000 + i * 1_000_000;
        e.place(order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, bid, 1_000, 1), &mut fills)
            .unwrap();
        e.place(order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, ask, 1_000, 2), &mut fills)
            .unwrap();
        if let (Some((b, _)), Some((a, _))) = (e.best_bid(), e.best_ask()) {
            assert!(b < a, "book must never be crossed: {:?} >= {:?}", b.0, a.0);
        }
    }
}

/// Regression test: `cancel` on a non-existent order id returns
/// an error instead of panicking. Before the fix, `resting -= 1`
/// could underflow and panic in debug builds.
#[test]
fn cancel_nonexistent_order_returns_error_not_panic() {
    let mut e = engine();
    let result = e.cancel(OrderId(999));
    assert!(result.is_err(), "cancel of non-existent order must error");
    assert_eq!(e.resting_count(), 0, "resting count must not underflow");
}

/// Regression test: the matching engine must not panic when
/// processing orders that would have triggered `.expect()` or
/// `.unwrap()` in the old code. This test exercises the
/// `remove_maker` path (which previously used `.expect()` on
/// `ids.remove`) by filling and then matching a resting order.
#[test]
fn remove_maker_does_not_panic_on_invariant_violation() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Place a resting sell order.
    let out = e
        .place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 1),
            &mut fills,
        )
        .unwrap();
    let OrderOutcome::Resting { order_id, .. } = out else { panic!("must rest") };

    // Cancel it (exercises the `remove_maker` / `cancel` path).
    let canceled = e.cancel(order_id).unwrap();
    assert_eq!(canceled.order_id, order_id);

    // Cancel again — must error, not panic.
    let result = e.cancel(order_id);
    assert!(result.is_err(), "double-cancel must error not panic");
    assert_eq!(e.resting_count(), 0, "resting must be 0 after cancel");
}

/// Regression test: FOK pre-scan must exclude the taker's own
/// resting orders when STP is active. Before the fix, the FOK
/// pre-scan counted the taker's own orders as fillable, so a
/// FOK that should have been killed (because STP would skip
/// the taker's own orders) was instead accepted and then
/// canceled mid-sweep — violating the FOK guarantee.
#[test]
fn fok_pre_scan_excludes_self_trades_under_stp() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Owner 1 rests a sell at 10.50 for 5,000 lots.
    let out = e
        .place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
            &mut fills,
        )
        .unwrap();
    assert!(matches!(out, OrderOutcome::Resting { .. }));

    // Owner 1 submits a FOK buy for 5,000 at 10.50 with STP
    // CancelNewest. The only resting sell is owner 1's own
    // order, so the STP-aware fillable quantity is 0 (the
    // own order is excluded). The FOK must be killed.
    let fok_req = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Fok,
        price: Price(1_050_000_000),
        qty: Qty(5_000),
        owner: Address([1; 20]),
        stp: StpMode::CancelNewest,
    };
    let out = e.place(fok_req, &mut fills).unwrap();
    assert_eq!(out, OrderOutcome::Killed, "FOK with only self-trades must be killed under STP");
    assert!(fills.is_empty(), "killed FOK must not produce fills");

    // The resting order must still be in the book.
    assert_eq!(e.resting_count(), 1, "resting order must not be removed by killed FOK");
}

/// Regression test: FOK pre-scan with STP None must count
/// all orders (including the taker's own). This verifies the
/// non-STP path is unchanged.
#[test]
fn fok_pre_scan_counts_all_orders_without_stp() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Owner 1 rests a sell at 10.50 for 5,000 lots.
    let out = e
        .place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
            &mut fills,
        )
        .unwrap();
    assert!(matches!(out, OrderOutcome::Resting { .. }));

    // Owner 1 submits a FOK buy for 5,000 at 10.50 with STP
    // None. The own order counts as fillable, so the FOK
    // passes the pre-scan and executes (self-trade happens).
    let fok_req = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Fok,
        price: Price(1_050_000_000),
        qty: Qty(5_000),
        owner: Address([1; 20]),
        stp: StpMode::None,
    };
    let out = e.place(fok_req, &mut fills).unwrap();
    // With STP None, the self-trade executes and the order fills.
    assert_eq!(out, OrderOutcome::Filled, "FOK without STP must fill against own order");
    assert!(!fills.is_empty(), "FOK without STP must produce fills");
}

/// Regression: `CancelNewest` stops the sweep at the FIRST
/// self-owned maker — liquidity beyond it is unreachable. A
/// book of external, then self, then external liquidity must
/// not pass the pre-scan on the beyond-self quantity.
#[test]
fn fok_pre_scan_stops_at_self_order_under_cancel_newest() {
    let mut e = engine();
    let mut fills = Vec::new();

    // External sell 5 @10.50, self sell 5 @10.51, external sell
    // 10 @10.52 — 15 non-self in range, but only 5 reachable.
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 2),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 5_000, 1),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_052_000_000, 10_000, 2),
        &mut fills,
    )
    .unwrap();

    // FOK buy 15 @10.52, owner 1, CancelNewest: the sweep fills
    // 5 then cancels at the self order — fillable is 5, not 15.
    let fok_req = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Fok,
        price: Price(1_052_000_000),
        qty: Qty(15_000),
        owner: Address([1; 20]),
        stp: StpMode::CancelNewest,
    };
    let out = e.place(fok_req, &mut fills).unwrap();
    assert_eq!(out, OrderOutcome::Killed, "liquidity past the self order is unreachable");
    assert!(fills.is_empty(), "a killed FOK books nothing");
    assert_eq!(e.resting_count(), 3, "a killed FOK leaves the book untouched");
}

/// Regression: `DecrementAndCancel` spends taker quantity on
/// self makers without a fill — the pre-scan must count only
/// real fills, so a self decrement cannot hide a shortfall.
#[test]
fn fok_pre_scan_counts_fills_not_self_decrement() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Self sell 4 @10.50 at the level head, external sell 10
    // @10.51: 10 non-self, but the self decrement burns 4 of the
    // taker's qty — only 6 can actually fill.
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 4_000, 1),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 10_000, 2),
        &mut fills,
    )
    .unwrap();

    let fok_req = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Fok,
        price: Price(1_051_000_000),
        qty: Qty(10_000),
        owner: Address([1; 20]),
        stp: StpMode::DecrementAndCancel,
    };
    let out = e.place(fok_req, &mut fills).unwrap();
    assert_eq!(out, OrderOutcome::Killed, "self decrement must not count toward FOK fillable");
    assert!(fills.is_empty());
    // The self order is untouched too — a kill mutates nothing.
    assert_eq!(e.resting_count(), 2);
}

/// Snapshot restore: an engine rebuilt from `write_canonical_state`
/// bytes must re-encode to byte-identical output and keep trading
/// correctly (next id continues, resting orders are cancellable).
#[test]
fn canonical_state_round_trip_restores_book() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Two resting sells at different prices, one partially filled,
    // plus a resting bid — a non-trivial book shape.
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 2_000, 2),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_010_000_000, 7_000, 3),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 4),
        &mut fills,
    )
    .unwrap(); // partially fills the first sell
    assert_eq!(e.resting_count(), 3);
    assert_eq!(e.next_order_id(), 4);

    let mut bytes = Vec::new();
    let mut scratch = Vec::new();
    e.write_canonical_state(&mut bytes, &mut scratch);

    let mut restored =
        MatchingEngine::from_canonical_state(&bytes, |c| DenseBook::new(*c)).unwrap();
    let mut bytes2 = Vec::new();
    restored.write_canonical_state(&mut bytes2, &mut scratch);
    assert_eq!(bytes, bytes2, "restored engine must re-encode byte-identically");

    // Live operation continues correctly: next id is 4, and a
    // restored order cancels by id.
    assert_eq!(restored.next_order_id(), 4);
    let canceled = restored.cancel(OrderId(2)).expect("restored order must cancel");
    assert_eq!(canceled.price, Price(1_010_000_000));
    assert_eq!(restored.resting_count(), 2);
}

/// `decode_canonical_state` must reject truncated, inconsistent,
/// or non-canonical input — never panic, never restore silently.
#[test]
fn canonical_state_decode_rejects_malformed() {
    let mut e = engine();
    let mut fills = Vec::new();
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
        &mut fills,
    )
    .unwrap();
    let mut bytes = Vec::new();
    let mut scratch = Vec::new();
    e.write_canonical_state(&mut bytes, &mut scratch);

    // Truncation at every prefix length.
    for cut in 0..bytes.len() {
        assert!(
            decode_canonical_state(&bytes[..cut]).is_none(),
            "prefix of len {cut} must not decode"
        );
    }
    // Trailing garbage.
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(decode_canonical_state(&padded).is_none());

    // resting field ≠ entries count. Layout: cfg(38B = u16 +
    // 4×u64 + u32) next_id(8) resting(4) count(8) entries —
    // flip the resting field.
    let mut bad = bytes.clone();
    bad[38 + 8] ^= 0xFF;
    assert!(decode_canonical_state(&bad).is_none(), "resting must equal entries count");

    // An entry id ≥ next_id is impossible in a live book.
    let mut bad = bytes.clone();
    // Entry 0's id (offset 38+8+4+8 = 58) — set it to next_id.
    let nid = u64::from_le_bytes(bytes[38..46].try_into().unwrap());
    bad[58..66].copy_from_slice(&nid.to_le_bytes());
    assert!(decode_canonical_state(&bad).is_none(), "id ≥ next_id must be rejected");
}

/// Test leaf: pack the committed fields into 32 bytes — no crypto
/// needed, the fold contract only requires a deterministic
/// per-entry value to XOR.
fn test_leaf(e: &RestingEntry) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..8].copy_from_slice(&e.id.0.to_le_bytes());
    h[8..16].copy_from_slice(&e.price.0.to_le_bytes());
    h[16..24].copy_from_slice(&e.qty.0.to_le_bytes());
    h[24] = e.side as u8;
    h[25..32].copy_from_slice(&e.owner.0[..7]);
    h
}

/// Recompute the fold authoritatively from `resting_entries` —
/// the reference every maintained-fold assertion compares against.
fn recompute_fold(e: &MatchingEngine) -> [u8; 32] {
    let mut entries = Vec::new();
    e.resting_entries(&mut entries);
    let mut f = [0u8; 32];
    for en in &entries {
        let h = test_leaf(en);
        for (a, b) in f.iter_mut().zip(h.iter()) {
            *a ^= *b;
        }
    }
    f
}

/// The maintained resting fold must equal the XOR of the leaf
/// over `resting_entries` after every mutation — place, cancel,
/// partial fill (qty replace), STP decrement, full fill, and
/// snapshot restore all update the fold in lockstep. This is the
/// invariant `state_root`'s O(1) book commitment relies on (7.4).
#[test]
fn resting_fold_tracks_every_mutation() {
    let mut e = engine();
    let mut fills = Vec::new();

    // Disabled: no maintenance, fold stays ZERO.
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
        &mut fills,
    )
    .unwrap();
    assert_eq!(e.resting_fold(), [0; 32], "disabled fold must not move");

    // Enabling folds the already-resting set once.
    e.enable_resting_fold(test_leaf);
    assert_eq!(e.resting_fold(), recompute_fold(&e));

    // Place inserts.
    e.place(
        order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 2_000, 2),
        &mut fills,
    )
    .unwrap();
    e.place(
        order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_010_000_000, 7_000, 3),
        &mut fills,
    )
    .unwrap();
    assert_eq!(e.resting_fold(), recompute_fold(&e));

    // Partial fill: the maker's qty change folds out-then-in.
    e.place(
        order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 4),
        &mut fills,
    )
    .unwrap();
    assert_eq!(e.resting_fold(), recompute_fold(&e));

    // Full fill: the exhausted maker leaves the fold entirely.
    e.place(
        order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 2_000, 5),
        &mut fills,
    )
    .unwrap();
    assert_eq!(e.resting_fold(), recompute_fold(&e));

    // STP decrement: the self-maker's qty shrinks in place.
    let mut stp_req = order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_010_000_000, 1_000, 3);
    stp_req.stp = StpMode::DecrementAndCancel;
    e.place(stp_req, &mut fills).unwrap();
    assert_eq!(e.resting_fold(), recompute_fold(&e));

    // Cancel removes.
    e.cancel(OrderId(0)).unwrap();
    assert_eq!(e.resting_fold(), recompute_fold(&e));

    // Snapshot restore: a re-decoded engine folds to the same
    // value once enabled (the staged-verify path).
    let mut bytes = Vec::new();
    let mut scratch = Vec::new();
    e.write_canonical_state(&mut bytes, &mut scratch);
    let mut restored =
        MatchingEngine::from_canonical_state(&bytes, |c| DenseBook::new(*c)).unwrap();
    restored.enable_resting_fold(test_leaf);
    assert_eq!(restored.resting_fold(), e.resting_fold());
}
