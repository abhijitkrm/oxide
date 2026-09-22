#![no_main]
//! Fuzz target: trading order validation.
//!
//! Feeds arbitrary `NewOrder` fields to `NewOrder::validate` and
//! asserts no panics. The validator must accept or reject every
//! possible field combination without crashing — invalid orders
//! return `RejectReason`, valid orders return `Ok(())`.

use primitives::fixed::{Price, Qty};
use trading::{NewOrder, OrderType, RejectReason, Side, StpMode, TimeInForce};

/// Fixed market parameters for validation.
const TICK: Price = Price(1_000_000);
const LOT: Qty = Qty(1_000);
const MIN_PRICE: Price = Price(1_000_000_000);
const MAX_PRICE: Price = Price(2_000_000_000);

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Fuzz fix: need at least 19 bytes to safely slice data[11..19].
    if data.len() < 19 {
        return;
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
    let price = u64::from_le_bytes(data[3..11].try_into().unwrap_or([0u8; 8]));
    let qty = u64::from_le_bytes(data[11..19].try_into().unwrap_or([0u8; 8]));

    let order = NewOrder {
        side,
        order_type,
        tif,
        price: Price(price),
        qty: Qty(qty),
        owner: primitives::Address([0u8; 20]),
        stp: StpMode::CancelOldest,
    };

    // Must never panic — only return Ok or Err(RejectReason).
    let result: Result<(), RejectReason> = order.validate(TICK, LOT, MIN_PRICE, MAX_PRICE);
    let _ = result;
});
