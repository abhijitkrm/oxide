//! Wire codec for the exchange module — message parsing,
//! canonical encoders, and event builders.
//!
//! Split from `lib.rs` around the wire-format invariant: every
//! `parse_*` is the single schema owner for its message type,
//! every `encode_*` the single owner of its canonical byte form,
//! and the `*_event` helpers the single mapping from domain
//! outcomes to [`Event`]s — handlers and settlement never build
//! bytes or events ad hoc.

use super::{
    Address, CANCEL_BODY_LEN, CanceledOrder, Event, ExchangeModule, FillEvent,
    LIST_MARKET_BODY_LEN, MarketConfig, NewOrder, OrderId, OrderOutcome, OrderType, PLACE_BODY_LEN,
    Price, Qty, Side, StpMode, TimeInForce,
};

impl ExchangeModule {
    /// Parse a place-order message body (tag already consumed).
    pub(crate) fn parse_place(msg: &[u8]) -> Option<(u8, NewOrder, Address)> {
        if msg.len() != PLACE_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let side = decode_side(msg[1])?;
        let order_type = decode_order_type(msg[2])?;
        let tif = decode_tif(msg[3])?;
        let stp = decode_stp(msg[4])?;
        let price = u64::from_le_bytes(msg[5..13].try_into().ok()?);
        let qty = u64::from_le_bytes(msg[13..21].try_into().ok()?);
        // The owner is the tx sender, not in the body. The caller
        // supplies it separately.
        let _ = (market, side, order_type, tif, stp, price, qty);
        // We return the parsed fields; the owner is set by the caller.
        // The `Address` here is a placeholder — the caller overwrites it.
        Some((
            market,
            NewOrder {
                side,
                order_type,
                tif,
                price: Price(price),
                qty: Qty(qty),
                owner: Address([0; 20]),
                stp,
            },
            Address([0; 20]),
        ))
    }

    /// Parse a cancel-order message body (tag already consumed).
    pub(crate) fn parse_cancel(msg: &[u8]) -> Option<(u8, OrderId)> {
        if msg.len() != CANCEL_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let order_id = u64::from_le_bytes(msg[1..9].try_into().ok()?);
        Some((market, OrderId(order_id)))
    }

    /// Parse a list-market message body (tag already consumed).
    pub(crate) fn parse_list_market(msg: &[u8]) -> Option<MarketConfig> {
        if msg.len() != LIST_MARKET_BODY_LEN {
            return None;
        }
        let tick_size = u64::from_le_bytes(msg[0..8].try_into().ok()?);
        let lot_size = u64::from_le_bytes(msg[8..16].try_into().ok()?);
        let min_price = u64::from_le_bytes(msg[16..24].try_into().ok()?);
        let max_price = u64::from_le_bytes(msg[24..32].try_into().ok()?);
        let max_resting = u32::from_le_bytes(msg[32..36].try_into().ok()?);
        Some(MarketConfig { market_id: 0, tick_size, lot_size, min_price, max_price, max_resting })
    }
}

#[inline]
pub(crate) fn w64(b: &[u8; 20], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

#[inline]
pub(crate) fn w32(b: &[u8; 20], off: usize) -> u64 {
    u64::from(u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]))
}

/// Build a pair-scoped settlement event (`batch_fill` on a settled
/// pair, `settlement_failed` on a voided one):
/// `[buyer:20][seller:20][amount:8]`.
pub(crate) fn pair_event(
    kind: &'static str,
    buyer: &Address,
    seller: &Address,
    amount: u64,
) -> Event {
    let mut data = Vec::with_capacity(20 + 20 + 8);
    data.extend_from_slice(&buyer.0);
    data.extend_from_slice(&seller.0);
    data.extend_from_slice(&amount.to_le_bytes());
    Event { module: "exchange", kind, data }
}

// ── Event helpers ────────────────────────────────────────────────────

/// Convert a [`FillEvent`] into an executor [`Event`] for the event log.
///
/// This is a free function (not an `impl FillEvent`) because `FillEvent`
/// is defined in the `trading` crate — implementing a method on it here
/// would violate the orphan rule.
pub(crate) fn fill_event(fill: FillEvent) -> Event {
    let mut data = Vec::with_capacity(8 + 8 + 8 + 8 + 20 + 20 + 1);
    data.extend_from_slice(&fill.price.0.to_le_bytes());
    data.extend_from_slice(&fill.qty.0.to_le_bytes());
    data.extend_from_slice(&fill.maker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.taker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.maker_owner.0);
    data.extend_from_slice(&fill.taker_owner.0);
    data.push(encode_side(fill.taker_side));
    Event { module: "exchange", kind: "fill", data }
}

/// Encode an [`OrderOutcome`] as an event.
pub(crate) fn outcome_event(market: u8, outcome: OrderOutcome) -> Event {
    let (kind, data) = match outcome {
        OrderOutcome::Filled => ("filled", vec![]),
        OrderOutcome::Resting { order_id, price, resting_qty } => {
            let mut d = Vec::with_capacity(1 + 8 + 8 + 8);
            d.push(market);
            d.extend_from_slice(&order_id.0.to_le_bytes());
            d.extend_from_slice(&price.0.to_le_bytes());
            d.extend_from_slice(&resting_qty.0.to_le_bytes());
            ("resting", d)
        }
        OrderOutcome::CanceledRemainder { order_id, filled_qty } => {
            let mut d = Vec::with_capacity(1 + 8 + 8);
            d.push(market);
            d.extend_from_slice(&order_id.0.to_le_bytes());
            d.extend_from_slice(&filled_qty.0.to_le_bytes());
            ("canceled_remainder", d)
        }
        OrderOutcome::Killed => ("killed", vec![]),
        OrderOutcome::Rejected(reason) => ("rejected", vec![encode_reject_reason(reason)]),
    };
    Event { module: "exchange", kind, data }
}

/// Encode a non-fill book change (STP removal or decrement) as an
/// event: `[market][order_id][side][price][removed_qty][remaining][owner]`.
/// `remaining == 0` means the order is gone (`stp_cancel`), `> 0` a
/// decrement (`stp_decrement`).
pub(crate) fn removal_event(market: u8, r: trading::MakerRemoval) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 1 + 8 + 8 + 8 + 20);
    data.push(market);
    data.extend_from_slice(&r.order_id.0.to_le_bytes());
    data.push(encode_side(r.side));
    data.extend_from_slice(&r.price.to_le_bytes());
    data.extend_from_slice(&r.removed_qty.to_le_bytes());
    data.extend_from_slice(&r.remaining.to_le_bytes());
    data.extend_from_slice(&r.owner.0);
    let kind = if r.remaining == 0 { "stp_cancel" } else { "stp_decrement" };
    Event { module: "exchange", kind, data }
}

/// Encode a [`CanceledOrder`] as an event.
pub(crate) fn cancel_event(market: u8, canceled: CanceledOrder) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 1 + 8 + 8 + 20);
    data.push(market);
    data.extend_from_slice(&canceled.order_id.0.to_le_bytes());
    data.push(encode_side(canceled.side));
    data.extend_from_slice(&canceled.price.0.to_le_bytes());
    data.extend_from_slice(&canceled.qty.0.to_le_bytes());
    data.extend_from_slice(&canceled.owner.0);
    Event { module: "exchange", kind: "canceled", data }
}

// ── Codec helpers ────────────────────────────────────────────────────

/// Encode a [`Side`] as a single byte.
pub(crate) fn encode_side(s: Side) -> u8 {
    match s {
        Side::Buy => 0,
        Side::Sell => 1,
    }
}

/// Encode an [`OrderType`] as a single byte.
pub(crate) fn encode_order_type(t: OrderType) -> u8 {
    match t {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
    }
}

/// Encode a [`TimeInForce`] as a single byte.
pub(crate) fn encode_tif(t: TimeInForce) -> u8 {
    match t {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    }
}

/// Encode an [`StpMode`] as a single byte.
pub(crate) fn encode_stp(s: StpMode) -> u8 {
    match s {
        StpMode::None => 0,
        StpMode::CancelNewest => 1,
        StpMode::CancelOldest => 2,
        StpMode::DecrementAndCancel => 3,
    }
}

/// Encode a [`RejectReason`] byte. The encoding is an explicit match
/// (not `as u8`) because `RejectReason` is not `#[repr(u8)]` — a
/// discriminant reorder in the trading crate must surface as a test
/// failure here, not a silent wire-format change.
pub(crate) fn encode_reject_reason(r: trading::RejectReason) -> u8 {
    match r {
        trading::RejectReason::InvalidQty => 0,
        trading::RejectReason::PriceOffTick => 1,
        trading::RejectReason::PriceOutOfRange => 2,
        trading::RejectReason::InvalidTifForType => 3,
        trading::RejectReason::PostOnlyWouldCross => 4,
        trading::RejectReason::BookFull => 5,
    }
}

/// KV key for a market's config blob.
pub(crate) fn market_config_key(market: u8) -> Vec<u8> {
    vec![b'm', market]
}

/// Encode a `MarketConfig` into a storage blob (for state-root replay).
pub(crate) fn encode_market_config(cfg: &MarketConfig) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    v.extend_from_slice(&cfg.tick_size.to_le_bytes());
    v.extend_from_slice(&cfg.lot_size.to_le_bytes());
    v.extend_from_slice(&cfg.min_price.to_le_bytes());
    v.extend_from_slice(&cfg.max_price.to_le_bytes());
    v.extend_from_slice(&cfg.max_resting.to_le_bytes());
    v
}

/// Decode a [`Side`] from a single byte.
pub(crate) const fn decode_side(b: u8) -> Option<Side> {
    match b {
        0 => Some(Side::Buy),
        1 => Some(Side::Sell),
        _ => None,
    }
}

/// Decode an [`OrderType`] from a single byte.
pub(crate) const fn decode_order_type(b: u8) -> Option<OrderType> {
    match b {
        0 => Some(OrderType::Limit),
        1 => Some(OrderType::Market),
        2 => Some(OrderType::PostOnly),
        _ => None,
    }
}

/// Decode a [`TimeInForce`] from a single byte.
pub(crate) const fn decode_tif(b: u8) -> Option<TimeInForce> {
    match b {
        0 => Some(TimeInForce::Gtc),
        1 => Some(TimeInForce::Ioc),
        2 => Some(TimeInForce::Fok),
        _ => None,
    }
}

/// Decode an [`StpMode`] from a single byte.
pub(crate) const fn decode_stp(b: u8) -> Option<StpMode> {
    match b {
        0 => Some(StpMode::None),
        1 => Some(StpMode::CancelNewest),
        2 => Some(StpMode::CancelOldest),
        3 => Some(StpMode::DecrementAndCancel),
        _ => None,
    }
}
