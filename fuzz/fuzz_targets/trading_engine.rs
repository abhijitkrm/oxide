#![no_main]
//! Fuzz target: trading matching engine.
//!
//! Feeds arbitrary op streams — places AND cancels — to the matching
//! engine over randomized market configurations, and asserts the
//! engine's invariants after EVERY op, not just at the end:
//!
//! - the book never crosses (`best_bid < best_ask`),
//! - fills never exceed the requested quantity,
//! - fill prices stay inside the taker's limit (limit orders),
//! - resting state is sane at the end (unique ids, nonzero qty).
//!
//! ## Input layout
//!
//! - Bytes 0..8: market config — tick, lot, band depth, resting
//!   capacity, and owner count all derive from small tables, so the
//!   corpus sweeps market geometries (including single-owner books
//!   that exercise pure self-trade flow and 16-owner books where
//!   ordinary fills dominate).
//! - Bytes 8..: 24-byte ops. Byte 23 selects the op kind (~20%
//!   cancels); the rest derive side, order type, TIF, STP mode,
//!   owner, price, and quantity. Prices/quantities are only loosely
//!   aligned — some ops intentionally fail validation to exercise
//!   the rejection path; `place` must reject, never panic.

use primitives::fixed::{Price, Qty};
use trading::{
    DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderId, OrderOutcome, OrderType,
    Side, StpMode, TimeInForce,
};

/// Small parameter tables — validity is guaranteed by construction
/// (every entry is legal), so `DenseBook::new`/`MatchingEngine::new`
/// failures would themselves be bugs worth reporting.
const TICKS: [u64; 4] = [1, 100, 1_000_000, 10_000_000];
const LOTS: [u64; 4] = [1, 10, 1_000, 100_000];
const LEVELS: [u64; 4] = [8, 64, 512, 4_096];
const RESTING: [u32; 4] = [4, 64, 512, 4_096];
const OWNERS: [u8; 4] = [1, 4, 16, 255];

/// Derive the market config from the input header (8 bytes).
fn parse_config(h: &[u8]) -> MarketConfig {
    let tick = TICKS[(h[0] % 4) as usize];
    let lot = LOTS[(h[1] % 4) as usize];
    let levels = LEVELS[(h[2] % 4) as usize];
    let max_resting = RESTING[(h[3] % 4) as usize];
    // min_price sits at 1024 ticks — nonzero, tick-aligned, with a
    // band of `levels` rungs above it.
    let min_price = tick.saturating_mul(1024);
    let max_price = min_price.saturating_add(levels.saturating_mul(tick));
    MarketConfig {
        market_id: u16::from(h[4]),
        tick_size: tick,
        lot_size: lot,
        min_price,
        max_price,
        max_resting,
    }
}

/// A generated op: place an order, or cancel by id.
enum FuzzOp {
    Place(NewOrder),
    Cancel(u64),
}

/// Derive an op from a 24-byte chunk.
///
/// - Byte 0: side (bit 0), order type (bits 1-2), TIF (bits 3-4),
///   STP mode (bits 5-6).
/// - Byte 1: owner index (mod owner_count).
/// - Bytes 2-9: cancel selector / spare entropy.
/// - Bytes 10-17: price (u64 LE, clamped to the band; bit 7 of the
///   control byte leaves it unaligned to exercise rejection).
/// - Bytes 18-22: quantity (u64 LE, loosely lot-aligned).
/// - Byte 23: op kind — `% 5 == 4` cancels (~20%).
fn parse_op(chunk: &[u8], live: &[u64], owners: u8, cfg: &MarketConfig) -> Option<FuzzOp> {
    if chunk.len() < 24 {
        return None;
    }
    let raw_sel = u64::from_le_bytes(chunk[2..10].try_into().ok()?);
    if chunk[23] % 5 == 4 {
        // Cancel: mostly pick a live resting id (real cancels), else
        // a raw small id (phantom-cancel path).
        let id = if live.is_empty() || raw_sel % 4 == 0 {
            raw_sel % 512
        } else {
            live[(raw_sel as usize) % live.len()]
        };
        return Some(FuzzOp::Cancel(id));
    }
    let side = if chunk[0] & 1 == 0 { Side::Buy } else { Side::Sell };
    let order_type = match (chunk[0] >> 1) % 3 {
        0 => OrderType::Limit,
        1 => OrderType::Market,
        _ => OrderType::PostOnly,
    };
    let tif = match (chunk[0] >> 3) % 3 {
        0 => TimeInForce::Gtc,
        1 => TimeInForce::Ioc,
        _ => TimeInForce::Fok,
    };
    let stp = match (chunk[0] >> 5) % 4 {
        0 => StpMode::None,
        1 => StpMode::CancelNewest,
        2 => StpMode::CancelOldest,
        _ => StpMode::DecrementAndCancel,
    };
    let owner = primitives::Address([chunk[1] % owners; 20]);
    let raw_price = u64::from_le_bytes(chunk[10..18].try_into().ok()?);
    let raw_qty = u64::from_le_bytes([chunk[18], chunk[19], chunk[20], chunk[21], chunk[22], 0, 0, 0]);
    // Clamp to the band; ~1/4 of ops skip tick alignment so
    // `place`'s own validation is fuzzed too.
    let mut price = raw_price.max(cfg.min_price).min(cfg.max_price);
    if raw_sel & 3 != 0 {
        price -= price % cfg.tick_size;
    }
    // 40-bit quantities — big enough to overflow naive accounting,
    // small enough for lots of lots.
    let qty = if raw_qty == 0 { cfg.lot_size } else { raw_qty };
    Some(FuzzOp::Place(NewOrder { side, order_type, tif, price: Price(price), qty: Qty(qty), owner, stp }))
}

/// The engine's hard invariants, checked after every op.
fn assert_invariants(
    engine: &MatchingEngine<DenseBook>,
    req: &NewOrder,
    fills: &[FillEvent],
) {
    // Never crossed.
    if let (Some((bp, _)), Some((ap, _))) = (engine.best_bid(), engine.best_ask()) {
        assert!(bp.0 < ap.0, "crossed book: bid {bp:?} >= ask {ap:?}");
    }
    // Fills never exceed the request, stay inside the limit, and are
    // booked to the requesting taker.
    let filled: u64 = fills.iter().map(|f| f.qty.0).sum();
    assert!(filled <= req.qty.0, "fills {filled} exceed request {:?}", req.qty);
    for f in fills {
        assert_eq!(f.taker_owner, req.owner);
        if req.order_type != OrderType::Market {
            match req.side {
                Side::Buy => assert!(f.price.0 <= req.price.0, "buy fill above limit"),
                Side::Sell => assert!(f.price.0 >= req.price.0, "sell fill below limit"),
            }
        }
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let cfg = parse_config(&data[..8]);
    let owners = OWNERS[(data[5] % 4) as usize];
    let book = match DenseBook::new(cfg) {
        Ok(b) => b,
        Err(_) => return,
    };
    let mut engine = match MatchingEngine::<DenseBook>::new(cfg, book) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut fills = Vec::<FillEvent>::new();
    // Ids seen resting — cancel targets; stale entries exercise the
    // phantom-cancel path (ids already consumed by fills).
    let mut live: Vec<u64> = Vec::new();
    let empty_req = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(cfg.min_price),
        qty: Qty(0),
        owner: primitives::Address([0; 20]),
        stp: StpMode::None,
    };

    for chunk in data[8..].chunks(24) {
        match parse_op(chunk, &live, owners, &cfg) {
            Some(FuzzOp::Place(req)) => {
                fills.clear();
                match engine.place(req, &mut fills) {
                    Ok(outcome) => {
                        if let OrderOutcome::Resting { order_id, .. } = outcome {
                            live.push(order_id.0);
                            if live.len() > 512 {
                                live.drain(..256);
                            }
                        }
                        assert_invariants(&engine, &req, &fills);
                    }
                    // A rejected op must still leave a sane book.
                    Err(_) => assert_invariants(&engine, &empty_req, &[]),
                }
            }
            Some(FuzzOp::Cancel(id)) => {
                let _ = engine.cancel(OrderId(id));
                // Canceled ids leave the live list — re-cancel is a
                // valid phantom path.
                assert_invariants(&engine, &empty_req, &[]);
            }
            None => {}
        }
    }

    // Final resting sanity: unique ids, nonzero qty, book not crossed.
    let mut entries = Vec::new();
    engine.resting_entries(&mut entries);
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    for e in &entries {
        assert!(e.qty.0 > 0, "resting order with zero qty");
        assert!(seen.insert(e.id.0), "duplicate resting id {}", e.id.0);
    }
    assert_invariants(&engine, &empty_req, &[]);
});
