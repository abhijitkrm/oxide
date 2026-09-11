#![no_main]
//! Fuzz target: trading matching engine.
//!
//! Feeds arbitrary sequences of orders to the matching engine and
//! asserts no panics. The engine must never crash on any order
//! sequence — invalid orders are rejected, valid orders are matched
//! or rested, and the book invariant (best bid < best ask) is
//! maintained.
//!
//! The fuzzer derives order fields from the input bytes: side,
//! order type, time-in-force, price, quantity. The market config
//! is fixed (tick 1M, lot 1K, [$1B, $2B], 64 max resting) — the
//! same default as the exchange module.

use trading::{
    DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderType, Side, StpMode,
    TimeInForce,
};
use primitives::fixed::{Price, Qty};

/// Fixed market configuration for fuzzing. Matches the exchange
/// module's default market.
const FUZZ_CFG: MarketConfig = MarketConfig {
    market_id: 0,
    tick_size: 1_000_000,
    lot_size: 1_000,
    min_price: 1_000_000_000,
    max_price: 2_000_000_000,
    max_resting: 64,
};

/// Derive an order from a slice of fuzz bytes.
///
/// Byte 0: side (bit 0 = Buy/Sell).
/// Byte 1: order type (bits 0-1 = Limit/Market/PostOnly).
/// Byte 2: TIF (bits 0-1 = Gtc/Ioc/Fok).
/// Bytes 3-10: price (u64 LE, clamped to [min, max]).
/// Bytes 11-18: qty (u64 LE, rounded to lot boundary).
fn parse_order(data: &[u8]) -> Option<NewOrder> {
    if data.len() < 19 {
        return None;
    }
    let side = if data[0] & 1 == 0 { Side::Buy } else { Side::Sell };
    let order_type = match data[1] % 3 {
        0 => OrderType::Limit,
        1 => OrderType::Market,
        _ => OrderType::PostOnly,
    };
    let tif = match data[2] % 3 {
        0 => TimeInForce::Gtc,
        1 => TimeInForce::Ioc,
        _ => TimeInForce::Fok,
    };
    let raw_price = u64::from_le_bytes(data[3..11].try_into().ok()?);
    let raw_qty = u64::from_le_bytes(data[11..19].try_into().ok()?);
    // Clamp price to [min, max] and align to tick.
    let price = raw_price
        .max(FUZZ_CFG.min_price)
        .min(FUZZ_CFG.max_price);
    let price = price - (price % FUZZ_CFG.tick_size);
    // Align qty to lot boundary (at least 1 lot).
    let qty = if raw_qty == 0 { FUZZ_CFG.lot_size } else { raw_qty - (raw_qty % FUZZ_CFG.lot_size) };
    let qty = if qty == 0 { FUZZ_CFG.lot_size } else { qty };
    Some(NewOrder {
        side,
        order_type,
        tif,
        price: Price(price),
        qty: Qty(qty),
        owner: primitives::Address([0u8; 20]),
        stp: StpMode::CancelOldest,
    })
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let book = match DenseBook::new(FUZZ_CFG) {
        Ok(b) => b,
        Err(_) => return,
    };
    let mut engine = match MatchingEngine::<DenseBook>::new(FUZZ_CFG, book) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut fills = Vec::<FillEvent>::new();

    // Feed orders in 19-byte chunks.
    for chunk in data.chunks(19) {
        if let Some(order) = parse_order(chunk) {
            fills.clear();
            let _ = engine.place(order, &mut fills);
        }
    }

    // After the sequence, verify the book invariant: if both a
    // best bid and best ask exist, the best bid must be strictly
    // less than the best ask (no crossed book).
    if let (Some((bp, _)), Some((ap, _))) = (engine.best_bid(), engine.best_ask()) {
        assert!(bp.0 < ap.0, "crossed book: bid {bp:?} >= ask {ap:?}");
    }
});
