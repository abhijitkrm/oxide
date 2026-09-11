//! Binary TCP order protocol — the fastest order entry path.
//!
//! Wire format (little-endian, no padding):
//!
//! ```text
//! ┌───────── Request (42 bytes) ─────────┐
//! │ magic:    u16  = 0x4F58 ("OX")       │
//! │ version:  u8   = 1                   │
//! │ market:   u8                         │
//! │ side:     u8   (0=Buy, 1=Sell)       │
//! │ type:     u8   (0=Limit, 1=Market)   │
//! │ tif:      u8   (0=Gtc, 1=Ioc, 2=Fok) │
//! │ price:    u64  (scale-8)             │
//! │ qty:      u64  (scale-6)             │
//! │ owner:    [u8; 20]                   │
//! └──────────────────────────────────────┘
//!
//! ┌───────── Response (9 bytes) ─────────┐
//! │ status:   u8   (0=Filled, 1=Resting, │
//! │                2=Rejected)            │
//! │ fills:    u32  (fill count)           │
//! │ order_id: u32  (if resting)           │
//! │ reject:  u8   (if rejected)           │
//! └──────────────────────────────────────┘
//! ```
//!
//! Total request: 42 bytes. Total response: 9 bytes.
//! No JSON, no text parsing, no allocation — pure binary.

use primitives::fixed::{Price, Qty};
use trading::{OrderType, Side, TimeInForce};

/// Protocol magic bytes: "OX" = 0x4F58.
pub const MAGIC: u16 = 0x4F58;

/// Protocol version.
pub const VERSION: u8 = 1;

/// Request size on the wire (fixed).
/// 2 (magic) + 1 (version) + 1 (market) + 1 (side) + 1 (type) +
/// 1 (tif) + 8 (price) + 8 (qty) + 20 (owner) = 43 bytes.
pub const REQUEST_SIZE: usize = 43;

/// Response size on the wire (fixed).
pub const RESPONSE_SIZE: usize = 13;

/// An order request — the decoded form of a wire request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderRequest {
    /// Market ID (0 in v0).
    pub market: u8,
    /// Buy or sell.
    pub side: Side,
    /// Order type (limit, market).
    pub order_type: OrderType,
    /// Time in force (GTC, IOC, FOK).
    pub tif: TimeInForce,
    /// Limit price (scale-8).
    pub price: Price,
    /// Order quantity (scale-6).
    pub qty: Qty,
    /// Owner address (20 bytes).
    pub owner: primitives::Address,
}

/// The response to an order request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderResponse {
    /// Was the order rejected?
    pub rejected: bool,
    /// Number of fills produced.
    pub fills_count: u32,
    /// Resting order ID (if the order is resting).
    pub order_id: u64,
    /// Reject reason (if rejected).
    pub reject_reason: Option<RejectReason>,
}

/// The reason an order was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectReason {
    /// Insufficient balance for a buy order.
    InsufficientBalance = 0,
    /// Engine error (internal).
    EngineError = 1,
    /// Engine rejected (e.g. post-only would cross).
    EngineRejected = 2,
    /// FOK killed (not enough liquidity).
    Killed = 3,
    /// Malformed request.
    Malformed = 4,
}

impl OrderResponse {
    /// Build a "filled" response.
    pub fn filled(fills_count: u32) -> Self {
        Self { rejected: false, fills_count, order_id: 0, reject_reason: None }
    }

    /// Build a "resting" response.
    pub fn resting(order_id: trading::OrderId, fills_count: u32) -> Self {
        Self { rejected: false, fills_count, order_id: order_id.0, reject_reason: None }
    }

    /// Build a "rejected" response.
    pub fn rejected(reason: RejectReason) -> Self {
        Self { rejected: true, fills_count: 0, order_id: 0, reject_reason: Some(reason) }
    }
}

/// Encode an order request to 42 bytes.
pub fn encode_request(req: &OrderRequest) -> [u8; REQUEST_SIZE] {
    let mut buf = [0u8; REQUEST_SIZE];
    buf[0..2].copy_from_slice(&MAGIC.to_le_bytes());
    buf[2] = VERSION;
    buf[3] = req.market;
    buf[4] = match req.side {
        Side::Buy => 0,
        Side::Sell => 1,
    };
    buf[5] = match req.order_type {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
    };
    buf[6] = match req.tif {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    };
    buf[7..15].copy_from_slice(&req.price.0.to_le_bytes());
    buf[15..23].copy_from_slice(&req.qty.0.to_le_bytes());
    buf[23..43].copy_from_slice(&req.owner.0);
    buf
}

/// Decode an order request from 42 bytes.
///
/// Returns `None` if the magic bytes or version don't match.
pub fn decode_request(buf: &[u8]) -> Option<OrderRequest> {
    if buf.len() < REQUEST_SIZE {
        return None;
    }
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    if magic != MAGIC {
        return None;
    }
    if buf[2] != VERSION {
        return None;
    }
    let market = buf[3];
    let side = match buf[4] {
        0 => Side::Buy,
        1 => Side::Sell,
        _ => return None,
    };
    let order_type = match buf[5] {
        0 => OrderType::Limit,
        1 => OrderType::Market,
        2 => OrderType::PostOnly,
        _ => return None,
    };
    let tif = match buf[6] {
        0 => TimeInForce::Gtc,
        1 => TimeInForce::Ioc,
        2 => TimeInForce::Fok,
        _ => return None,
    };
    let price = Price(u64::from_le_bytes(buf[7..15].try_into().ok()?));
    let qty = Qty(u64::from_le_bytes(buf[15..23].try_into().ok()?));
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&buf[23..43]);
    Some(OrderRequest {
        market,
        side,
        order_type,
        tif,
        price,
        qty,
        owner: primitives::Address(owner),
    })
}

/// Encode an order response to 13 bytes.
pub fn encode_response(resp: &OrderResponse) -> [u8; RESPONSE_SIZE] {
    let mut buf = [0u8; RESPONSE_SIZE];
    buf[0] = if resp.rejected { 2 } else { u8::from(resp.order_id > 0) };
    buf[1..5].copy_from_slice(&resp.fills_count.to_le_bytes());
    buf[5..13].copy_from_slice(&resp.order_id.to_le_bytes());
    // If rejected, overwrite order_id with reject reason.
    if resp.rejected {
        buf[5] = resp.reject_reason.map_or(0xFF, |r| r as u8);
    }
    buf
}

/// Decode an order response from 13 bytes.
pub fn decode_response(buf: &[u8]) -> Option<OrderResponse> {
    if buf.len() < RESPONSE_SIZE {
        return None;
    }
    let status = buf[0];
    let fills_count = u32::from_le_bytes(buf[1..5].try_into().ok()?);
    let order_id = u64::from_le_bytes(buf[5..13].try_into().ok()?);
    match status {
        0 => Some(OrderResponse { rejected: false, fills_count, order_id: 0, reject_reason: None }),
        1 => Some(OrderResponse { rejected: false, fills_count, order_id, reject_reason: None }),
        2 => {
            let reason = match buf[5] {
                0 => RejectReason::InsufficientBalance,
                1 => RejectReason::EngineError,
                2 => RejectReason::EngineRejected,
                3 => RejectReason::Killed,
                4 => RejectReason::Malformed,
                _ => return None,
            };
            Some(OrderResponse {
                rejected: true,
                fills_count: 0,
                order_id: 0,
                reject_reason: Some(reason),
            })
        }
        _ => None,
    }
}

// ── Batch protocol (v2) ──────────────────────────────────────────────

/// Batch flag: when the `market` byte in a request is `0xFF`, the
/// request is a batch order (multiple orders in one message).
pub const BATCH_FLAG: u8 = 0xFF;

/// Size of a single order entry within a batch request (excluding the
/// batch header): market:1 + side:1 + type:1 + tif:1 + price:8 + qty:8
/// + owner:20 = 40 bytes.
pub const BATCH_ENTRY_SIZE: usize = 40;

/// Encode a batch of order requests into a single wire message.
///
/// Format: `[magic:2][version:1][0xFF][count:4 LE][entry:40 × count]`
///
/// # Panics
///
/// Panics if `orders` is empty or contains more than `u32::MAX` orders.
pub fn encode_batch_request(orders: &[OrderRequest]) -> Vec<u8> {
    assert!(!orders.is_empty(), "batch request requires at least one order");
    let count = u32::try_from(orders.len()).unwrap_or(u32::MAX);
    let mut buf = Vec::with_capacity(REQUEST_SIZE + 4 + orders.len() * BATCH_ENTRY_SIZE);
    // Header: magic + version + batch flag + count.
    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.push(VERSION);
    buf.push(BATCH_FLAG);
    buf.extend_from_slice(&count.to_le_bytes());
    // Entries: each order without magic/version (those are in the header).
    for req in orders {
        buf.push(req.market);
        buf.push(match req.side {
            Side::Buy => 0,
            Side::Sell => 1,
        });
        buf.push(match req.order_type {
            OrderType::Limit => 0,
            OrderType::Market => 1,
            OrderType::PostOnly => 2,
        });
        buf.push(match req.tif {
            TimeInForce::Gtc => 0,
            TimeInForce::Ioc => 1,
            TimeInForce::Fok => 2,
        });
        buf.extend_from_slice(&req.price.0.to_le_bytes());
        buf.extend_from_slice(&req.qty.0.to_le_bytes());
        buf.extend_from_slice(&req.owner.0);
    }
    buf
}

/// Decode a batch request from a wire message. Returns the parsed
/// orders, or `None` if the message is malformed.
pub fn decode_batch_request(buf: &[u8]) -> Option<Vec<OrderRequest>> {
    if buf.len() < REQUEST_SIZE {
        return None;
    }
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    if magic != MAGIC {
        return None;
    }
    if buf[2] != VERSION {
        return None;
    }
    if buf[3] != BATCH_FLAG {
        return None;
    }
    let count = u32::from_le_bytes(buf[4..8].try_into().ok()?) as usize;
    let needed = 8 + count * BATCH_ENTRY_SIZE;
    if buf.len() < needed {
        return None;
    }
    let mut orders = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * BATCH_ENTRY_SIZE;
        let entry = &buf[off..off + BATCH_ENTRY_SIZE];
        let market = entry[0];
        let side = match entry[1] {
            0 => Side::Buy,
            1 => Side::Sell,
            _ => return None,
        };
        let order_type = match entry[2] {
            0 => OrderType::Limit,
            1 => OrderType::Market,
            2 => OrderType::PostOnly,
            _ => return None,
        };
        let tif = match entry[3] {
            0 => TimeInForce::Gtc,
            1 => TimeInForce::Ioc,
            2 => TimeInForce::Fok,
            _ => return None,
        };
        let price = Price(u64::from_le_bytes(entry[4..12].try_into().ok()?));
        let qty = Qty(u64::from_le_bytes(entry[12..20].try_into().ok()?));
        let mut owner = [0u8; 20];
        owner.copy_from_slice(&entry[20..40]);
        orders.push(OrderRequest {
            market,
            side,
            order_type,
            tif,
            price,
            qty,
            owner: primitives::Address(owner),
        });
    }
    Some(orders)
}

/// Encode a batch of responses into a single wire message.
///
/// Format: `[0xFF][count:4 LE][response:13 × count]`
pub fn encode_batch_response(responses: &[OrderResponse]) -> Vec<u8> {
    let count = u32::try_from(responses.len()).unwrap_or(u32::MAX);
    let mut buf = Vec::with_capacity(5 + responses.len() * RESPONSE_SIZE);
    buf.push(BATCH_FLAG);
    buf.extend_from_slice(&count.to_le_bytes());
    for resp in responses {
        buf.extend_from_slice(&encode_response(resp));
    }
    buf
}

/// Decode a batch response from a wire message. Returns the parsed
/// responses, or `None` if the message is malformed.
pub fn decode_batch_response(buf: &[u8]) -> Option<Vec<OrderResponse>> {
    if buf.len() < 5 || buf[0] != BATCH_FLAG {
        return None;
    }
    let count = u32::from_le_bytes(buf[1..5].try_into().ok()?) as usize;
    let needed = 5 + count * RESPONSE_SIZE;
    if buf.len() < needed {
        return None;
    }
    let mut responses = Vec::with_capacity(count);
    for i in 0..count {
        let off = 5 + i * RESPONSE_SIZE;
        let resp = decode_response(&buf[off..off + RESPONSE_SIZE])?;
        responses.push(resp);
    }
    Some(responses)
}

/// Check if a buffer starts with a batch request (batch flag = 0xFF
/// in the market field).
pub fn is_batch_request(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[3] == BATCH_FLAG
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> primitives::Address {
        primitives::Address([byte; 20])
    }

    #[test]
    fn request_roundtrip() {
        let req = OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(0x42),
        };
        let encoded = encode_request(&req);
        let decoded = decode_request(&encoded).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn response_filled_roundtrip() {
        let resp = OrderResponse::filled(3);
        let encoded = encode_response(&resp);
        let decoded = decode_response(&encoded).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn response_rejected_roundtrip() {
        let resp = OrderResponse::rejected(RejectReason::InsufficientBalance);
        let encoded = encode_response(&resp);
        let decoded = decode_response(&encoded).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = encode_request(&OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1),
            qty: Qty(1),
            owner: addr(0),
        });
        buf[0] = 0xFF; // Bad magic.
        assert!(decode_request(&buf).is_none());
    }
}
