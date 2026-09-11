//! Binary TCP order protocol — the fastest order entry path.
//!
//! Wire format (little-endian, no padding):
//!
//! ```text
//! ┌───────── Request (147 bytes) ──────────┐
//! │ magic:    u16  = 0x4F58 ("OX")           │
//! │ version:  u8   = 2                       │
//! │ market:   u8                             │
//! │ side:     u8   (0=Buy, 1=Sell)           │
//! │ type:     u8   (0=Limit, 1=Market)       │
//! │ tif:      u8   (0=Gtc, 1=Ioc, 2=Fok)     │
//! │ price:    u64  (scale-8)                 │
//! │ qty:      u64  (scale-6)                 │
//! │ nonce:    u64  (replay protection)       │
//! │ owner:    [u8; 20]                       │
//! │ pubkey:   [u8; 32]  (Ed25519)            │
//! │ signature:[u8; 64]  (Ed25519)            │
//! └──────────────────────────────────────────┘
//!
//! ┌───────── Response (13 bytes) ───────────┐
//! │ status:   u8   (0=Filled, 1=Resting,     │
//! │                2=Rejected)               │
//! │ fills:    u32  (fill count)              │
//! │ order_id: u32  (if resting)              │
//! │ reject:  u8   (if rejected)              │
//! └──────────────────────────────────────────┘
//! ```
//!
//! Total request: 147 bytes. Total response: 13 bytes.
//! No JSON, no text parsing, no allocation — pure binary.
//!
//! # Authentication (v2)
//!
//! Every order carries an Ed25519 signature over the signing domain
//! (see `SIGNING_DOMAIN`), the chain ID, the order fields, and the
//! nonce. The matcher verifies the signature before any balance or
//! risk check, binding the `owner` address to the signing key. This
//! prevents spoofing: an attacker cannot submit orders as another
//! account without that account's secret key.
//!
//! # Replay protection
//!
//! The `nonce` is a monotonically increasing per-account counter. The
//! matcher rejects orders with a nonce lower than or equal to the
//! last-seen nonce for that account. This prevents replaying a
//! captured order.

use primitives::fixed::{Price, Qty};
use trading::{OrderType, Side, TimeInForce};

/// Protocol magic bytes: "OX" = 0x4F58.
pub const MAGIC: u16 = 0x4F58;

/// Protocol version 2: adds Ed25519 signature, nonce, and `chain_id`.
pub const VERSION: u8 = 2;

/// Chain ID for the devnet. Used in the signing domain to prevent
/// cross-chain replay. In production this comes from genesis config.
pub const CHAIN_ID: u64 = 1;

/// Signing domain separator: prevents signature reuse across
/// different Oxide message types (orders, cancels, governance, etc.).
/// This is the ASCII string "oxide-order-v2" — 14 bytes.
pub const SIGNING_DOMAIN: &[u8] = b"oxide-order-v2";

/// Request size on the wire (fixed).
/// 2 (magic) + 1 (version) + 1 (market) + 1 (side) + 1 (type) +
/// 1 (tif) + 8 (price) + 8 (qty) + 8 (nonce) + 20 (owner) +
/// 32 (pubkey) + 64 (signature) = 147 bytes.
pub const REQUEST_SIZE: usize = 147;

/// Response size on the wire (fixed).
pub const RESPONSE_SIZE: usize = 13;

/// An order request — the decoded form of a wire request.
///
/// The `signature` and `pubkey` fields authenticate the `owner`. The
/// matcher verifies the signature before processing the order.
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
    /// Per-account nonce for replay protection.
    pub nonce: u64,
    /// Owner address (20 bytes).
    pub owner: primitives::Address,
    /// Ed25519 public key (32 bytes) that signed this order.
    pub pubkey: [u8; 32],
    /// Ed25519 signature (64 bytes) over the signing domain.
    pub signature: [u8; 64],
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
    /// Invalid signature — the order is not authentic.
    BadSignature = 5,
    /// Stale nonce — replay attempt or out-of-order delivery.
    StaleNonce = 6,
    /// The referenced order does not exist (cancel/amend/replace on
    /// an order that is not resting, or the requester is not the
    /// owner).
    OrderNotFound = 7,
    /// Rate-limited: the account has exceeded the max orders/sec.
    RateLimited = 8,
    /// Order quantity exceeds the maximum allowed.
    OrderTooLarge = 9,
    /// Price deviates too far from mid (fat-finger guard).
    FatFinger = 10,
    /// Account has too many resting orders on the book.
    TooManyResting = 11,
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

/// Compute the signing message for an order. This is the byte sequence
/// that the Ed25519 signature covers. The caller signs this with their
/// secret key; the matcher verifies it with the included public key.
///
/// The message includes:
/// - `SIGNING_DOMAIN` (domain separation)
/// - `CHAIN_ID` (cross-chain replay protection)
/// - All order fields except `signature` and `pubkey` (the pubkey is
///   verified separately — the signature proves the signer owns the
///   pubkey, and the owner is bound to the pubkey via registration)
///
/// # Arguments
///
/// - `req`: the order request (signature field is ignored)
#[must_use]
pub fn signing_message(req: &OrderRequest) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGNING_DOMAIN.len() + 8 + 1 + 1 + 1 + 1 + 8 + 8 + 8 + 20);
    msg.extend_from_slice(SIGNING_DOMAIN);
    msg.extend_from_slice(&CHAIN_ID.to_le_bytes());
    msg.push(req.market);
    msg.push(match req.side {
        Side::Buy => 0,
        Side::Sell => 1,
    });
    msg.push(match req.order_type {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
    });
    msg.push(match req.tif {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    });
    msg.extend_from_slice(&req.price.0.to_le_bytes());
    msg.extend_from_slice(&req.qty.0.to_le_bytes());
    msg.extend_from_slice(&req.nonce.to_le_bytes());
    msg.extend_from_slice(&req.owner.0);
    msg
}

/// Verify the Ed25519 signature on an order request.
///
/// Returns `true` if the signature is valid for the included public
/// key and the signing message. Returns `false` if the signature is
/// invalid, the public key is malformed, or any crypto error occurs.
///
/// This is the authentication gate: the matcher calls this before
/// any balance or risk check. A `false` result means the order is
/// not authentic and must be rejected with `BadSignature`.
#[must_use]
pub fn verify_order(req: &OrderRequest) -> bool {
    let Ok(pubkey) = crypto::ed25519::Ed25519PublicKey::from_bytes(&req.pubkey) else {
        return false;
    };
    let Ok(signature) = crypto::ed25519::Ed25519Signature::from_slice(&req.signature) else {
        return false;
    };
    let msg = signing_message(req);
    crypto::ed25519::verify_message(&pubkey, &msg, &signature).is_ok()
}

/// Sign an order request with an Ed25519 secret key. Fills in the
/// `pubkey` and `signature` fields.
///
/// This is used by clients (and test helpers) to produce authentic
/// orders. The matcher never calls this — it only verifies.
pub fn sign_order(req: &mut OrderRequest, secret: &crypto::ed25519::Ed25519SecretKey) {
    req.pubkey = secret.verifying_key().to_bytes();
    let msg = signing_message(req);
    let sig = crypto::ed25519::sign_message(secret, &msg);
    req.signature = sig.to_bytes();
}

/// Encode an order request to `REQUEST_SIZE` bytes.
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
    buf[23..31].copy_from_slice(&req.nonce.to_le_bytes());
    buf[31..51].copy_from_slice(&req.owner.0);
    buf[51..83].copy_from_slice(&req.pubkey);
    buf[83..147].copy_from_slice(&req.signature);
    buf
}

/// Decode an order request from `REQUEST_SIZE` bytes.
///
/// Returns `None` if the magic bytes or version don't match, or if
/// any field has an invalid value.
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
    let nonce = u64::from_le_bytes(buf[23..31].try_into().ok()?);
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&buf[31..51]);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&buf[51..83]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&buf[83..147]);
    Some(OrderRequest {
        market,
        side,
        order_type,
        tif,
        price,
        qty,
        nonce,
        owner: primitives::Address(owner),
        pubkey,
        signature,
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
                5 => RejectReason::BadSignature,
                6 => RejectReason::StaleNonce,
                7 => RejectReason::OrderNotFound,
                8 => RejectReason::RateLimited,
                9 => RejectReason::OrderTooLarge,
                10 => RejectReason::FatFinger,
                11 => RejectReason::TooManyResting,
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
/// + nonce:8 + owner:20 + pubkey:32 + signature:64 = 144 bytes.
pub const BATCH_ENTRY_SIZE: usize = 144;

/// Encode a batch of order requests into a single wire message.
///
/// Format: `[magic:2][version:1][0xFF][count:4 LE][entry:104 × count]`
///
/// # Panics
///
/// Panics if `orders` is empty or contains more than `u32::MAX` orders.
pub fn encode_batch_request(orders: &[OrderRequest]) -> Vec<u8> {
    assert!(!orders.is_empty(), "batch request requires at least one order");
    let count = u32::try_from(orders.len()).unwrap_or(u32::MAX);
    let mut buf = Vec::with_capacity(8 + orders.len() * BATCH_ENTRY_SIZE);
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
        buf.extend_from_slice(&req.nonce.to_le_bytes());
        buf.extend_from_slice(&req.owner.0);
        buf.extend_from_slice(&req.pubkey);
        buf.extend_from_slice(&req.signature);
    }
    buf
}

/// Decode a batch request from a wire message. Returns the parsed
/// orders, or `None` if the message is malformed.
pub fn decode_batch_request(buf: &[u8]) -> Option<Vec<OrderRequest>> {
    if buf.len() < 8 {
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
        let nonce = u64::from_le_bytes(entry[20..28].try_into().ok()?);
        let mut owner = [0u8; 20];
        owner.copy_from_slice(&entry[28..48]);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&entry[48..80]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&entry[80..144]);
        orders.push(OrderRequest {
            market,
            side,
            order_type,
            tif,
            price,
            qty,
            nonce,
            owner: primitives::Address(owner),
            pubkey,
            signature,
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

// ── Order action protocol (cancel / amend / replace) ──────────────────

/// Action flag: when the `market` byte in a request is `0xFE`, the
/// message is an order action request (cancel, amend, or replace),
/// not a new order. This reuses the market-byte position that
/// `BATCH_FLAG` (0xFF) already overloads, keeping the dispatch logic
/// in the server uniform.
pub const ACTION_FLAG: u8 = 0xFE;

/// The kind of order action being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActionType {
    /// Cancel a resting order by id.
    Cancel = 0,
    /// Amend a resting order: cancel + re-submit with new price/qty.
    Amend = 1,
    /// Replace a resting order: cancel + submit a brand-new order
    /// atomically (the new order may differ in side, type, and tif).
    Replace = 2,
}

impl ActionType {
    /// Decode an action type from its wire byte.
    #[must_use]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(ActionType::Cancel),
            1 => Some(ActionType::Amend),
            2 => Some(ActionType::Replace),
            _ => None,
        }
    }
}

/// An action on an existing order (cancel, amend, or replace).
///
/// This is the high-level, decoded form consumed by
/// [`crate::MatchingServer::submit_action`]. The wire form is
/// [`ActionRequest`] (flat, fixed-size, authenticated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderAction {
    /// Cancel a resting order by id. The `owner` must match the
    /// resting order's owner (authorization).
    Cancel {
        /// The engine-assigned id of the order to cancel.
        order_id: u64,
        /// The requesting owner (must match the resting order's owner).
        owner: primitives::Address,
    },
    /// Amend a resting order: cancel it and re-submit with the new
    /// price and/or quantity. The side, order type, and time-in-force
    /// are preserved from the original order (resting orders are
    /// always GTC; the re-submission uses Limit/GTC).
    Amend {
        /// The engine-assigned id of the order to amend.
        order_id: u64,
        /// The requesting owner (must match the resting order's owner).
        owner: primitives::Address,
        /// The new limit price (scale-8).
        new_price: Price,
        /// The new order quantity (scale-6).
        new_qty: Qty,
    },
    /// Replace a resting order: cancel it and submit a brand-new order
    /// atomically. The new order may differ from the original in every
    /// field (side, type, tif, price, qty). If the cancel fails, the
    /// new order is not submitted.
    Replace {
        /// The engine-assigned id of the order to cancel.
        order_id: u64,
        /// The requesting owner (must match the resting order's owner).
        owner: primitives::Address,
        /// The new order to submit after the cancel succeeds.
        new_order: OrderRequest,
    },
}

/// A flat, fixed-size, authenticated action request — the wire form of
/// [`OrderAction`].
///
/// Wire format (little-endian, no padding):
///
/// ```text
/// ┌───────── Action Request (156 bytes) ──────────┐
/// │ magic:      u16  = 0x4F58 ("OX")               │
/// │ version:    u8   = 2                           │
/// │ action_flag:u8   = 0xFE                        │
/// │ action_type:u8   (0=Cancel, 1=Amend, 2=Replace)│
/// │ order_id:   u64  (the order to act on)         │
/// │ new_price:  u64  (scale-8; Amend/Replace only) │
/// │ new_qty:    u64  (scale-6; Amend/Replace only) │
/// │ side:       u8   (0=Buy, 1=Sell; Replace only) │
/// │ type:       u8   (0=Limit,1=Market,2=PostOnly) │
/// │ tif:        u8   (0=Gtc, 1=Ioc, 2=Fok)         │
/// │ nonce:      u64  (replay protection)           │
/// │ owner:      [u8; 20]                           │
/// │ pubkey:     [u8; 32]  (Ed25519)                │
/// │ signature:  [u8; 64]  (Ed25519)                │
/// └─────────────────────────────────────────────────┘
/// ```
///
/// For `Cancel`, the `new_price`/`new_qty`/`side`/`type`/`tif` fields
/// are zero (ignored). For `Amend`, `side`/`type`/`tif` are zero
/// (ignored — the original order's values are preserved). For
/// `Replace`, all fields are used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRequest {
    /// The kind of action (cancel, amend, replace).
    pub action_type: ActionType,
    /// The engine-assigned id of the order to act on.
    pub order_id: u64,
    /// New limit price (scale-8) — Amend/Replace only.
    pub new_price: Price,
    /// New order quantity (scale-6) — Amend/Replace only.
    pub new_qty: Qty,
    /// New order side — Replace only.
    pub side: Side,
    /// New order type — Replace only.
    pub order_type: OrderType,
    /// New order time-in-force — Replace only.
    pub tif: TimeInForce,
    /// Per-account nonce for replay protection.
    pub nonce: u64,
    /// Owner address (20 bytes) — must match the resting order's owner.
    pub owner: primitives::Address,
    /// Ed25519 public key (32 bytes) that signed this action.
    pub pubkey: [u8; 32],
    /// Ed25519 signature (64 bytes) over the signing domain.
    pub signature: [u8; 64],
}

/// Action request size on the wire (fixed).
/// 2 (magic) + 1 (version) + 1 (`action_flag`) + 1 (`action_type`) +
/// 8 (`order_id`) + 8 (`new_price`) + 8 (`new_qty`) + 1 (side) +
/// 1 (type) + 1 (tif) + 8 (nonce) + 20 (owner) + 32 (pubkey) +
/// 64 (signature) = 156 bytes.
pub const ACTION_REQUEST_SIZE: usize = 156;

/// Signing domain for order actions: prevents signature reuse across
/// message types (orders use "oxide-order-v2"; actions use this).
pub const ACTION_SIGNING_DOMAIN: &[u8] = b"oxide-action-v1";

/// Compute the signing message for an action request. This is the
/// byte sequence that the Ed25519 signature covers.
///
/// Includes the action signing domain, chain id, and all action fields
/// except `signature` and `pubkey`.
#[must_use]
pub fn signing_message_action(req: &ActionRequest) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(ACTION_SIGNING_DOMAIN.len() + 8 + 1 + 8 + 8 + 8 + 1 + 1 + 1 + 8 + 20);
    msg.extend_from_slice(ACTION_SIGNING_DOMAIN);
    msg.extend_from_slice(&CHAIN_ID.to_le_bytes());
    msg.push(req.action_type as u8);
    msg.extend_from_slice(&req.order_id.to_le_bytes());
    msg.extend_from_slice(&req.new_price.0.to_le_bytes());
    msg.extend_from_slice(&req.new_qty.0.to_le_bytes());
    msg.push(match req.side {
        Side::Buy => 0,
        Side::Sell => 1,
    });
    msg.push(match req.order_type {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
    });
    msg.push(match req.tif {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    });
    msg.extend_from_slice(&req.nonce.to_le_bytes());
    msg.extend_from_slice(&req.owner.0);
    msg
}

/// Verify the Ed25519 signature on an action request.
///
/// Returns `true` if the signature is valid for the included public
/// key and the signing message. This is the authentication gate for
/// cancel/amend/replace — a `false` result means the action is not
/// authentic and must be rejected with `BadSignature`.
#[must_use]
pub fn verify_action(req: &ActionRequest) -> bool {
    let Ok(pubkey) = crypto::ed25519::Ed25519PublicKey::from_bytes(&req.pubkey) else {
        return false;
    };
    let Ok(signature) = crypto::ed25519::Ed25519Signature::from_slice(&req.signature) else {
        return false;
    };
    let msg = signing_message_action(req);
    crypto::ed25519::verify_message(&pubkey, &msg, &signature).is_ok()
}

/// Sign an action request with an Ed25519 secret key. Fills in the
/// `pubkey` and `signature` fields. Used by clients and test helpers.
pub fn sign_action(req: &mut ActionRequest, secret: &crypto::ed25519::Ed25519SecretKey) {
    req.pubkey = secret.verifying_key().to_bytes();
    let msg = signing_message_action(req);
    let sig = crypto::ed25519::sign_message(secret, &msg);
    req.signature = sig.to_bytes();
}

/// Encode an action request to `ACTION_REQUEST_SIZE` bytes.
pub fn encode_action_request(req: &ActionRequest) -> [u8; ACTION_REQUEST_SIZE] {
    let mut buf = [0u8; ACTION_REQUEST_SIZE];
    buf[0..2].copy_from_slice(&MAGIC.to_le_bytes());
    buf[2] = VERSION;
    buf[3] = ACTION_FLAG;
    buf[4] = req.action_type as u8;
    buf[5..13].copy_from_slice(&req.order_id.to_le_bytes());
    buf[13..21].copy_from_slice(&req.new_price.0.to_le_bytes());
    buf[21..29].copy_from_slice(&req.new_qty.0.to_le_bytes());
    buf[29] = match req.side {
        Side::Buy => 0,
        Side::Sell => 1,
    };
    buf[30] = match req.order_type {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
    };
    buf[31] = match req.tif {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    };
    buf[32..40].copy_from_slice(&req.nonce.to_le_bytes());
    buf[40..60].copy_from_slice(&req.owner.0);
    buf[60..92].copy_from_slice(&req.pubkey);
    buf[92..156].copy_from_slice(&req.signature);
    buf
}

/// Decode an action request from `ACTION_REQUEST_SIZE` bytes.
///
/// Returns `None` if the magic, version, or action flag don't match,
/// or if any field has an invalid value.
pub fn decode_action_request(buf: &[u8]) -> Option<ActionRequest> {
    if buf.len() < ACTION_REQUEST_SIZE {
        return None;
    }
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    if magic != MAGIC {
        return None;
    }
    if buf[2] != VERSION {
        return None;
    }
    if buf[3] != ACTION_FLAG {
        return None;
    }
    let action_type = ActionType::from_byte(buf[4])?;
    let order_id = u64::from_le_bytes(buf[5..13].try_into().ok()?);
    let new_price = Price(u64::from_le_bytes(buf[13..21].try_into().ok()?));
    let new_qty = Qty(u64::from_le_bytes(buf[21..29].try_into().ok()?));
    let side = match buf[29] {
        0 => Side::Buy,
        1 => Side::Sell,
        _ => return None,
    };
    let order_type = match buf[30] {
        0 => OrderType::Limit,
        1 => OrderType::Market,
        2 => OrderType::PostOnly,
        _ => return None,
    };
    let tif = match buf[31] {
        0 => TimeInForce::Gtc,
        1 => TimeInForce::Ioc,
        2 => TimeInForce::Fok,
        _ => return None,
    };
    let nonce = u64::from_le_bytes(buf[32..40].try_into().ok()?);
    let mut owner = [0u8; 20];
    owner.copy_from_slice(&buf[40..60]);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&buf[60..92]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&buf[92..156]);
    Some(ActionRequest {
        action_type,
        order_id,
        new_price,
        new_qty,
        side,
        order_type,
        tif,
        nonce,
        owner: primitives::Address(owner),
        pubkey,
        signature,
    })
}

/// Convert a wire `ActionRequest` into the high-level `OrderAction`
/// consumed by [`crate::MatchingServer::submit_action`].
///
/// For `Replace`, the new order's `market` is set to 0 (the action
/// protocol is single-market in v0; multi-market routing is external).
/// The new order inherits the action's `owner`, `nonce`, `pubkey`, and
/// `signature`.
#[must_use]
pub fn action_request_to_order_action(req: &ActionRequest) -> OrderAction {
    match req.action_type {
        ActionType::Cancel => OrderAction::Cancel { order_id: req.order_id, owner: req.owner },
        ActionType::Amend => OrderAction::Amend {
            order_id: req.order_id,
            owner: req.owner,
            new_price: req.new_price,
            new_qty: req.new_qty,
        },
        ActionType::Replace => {
            let new_order = OrderRequest {
                market: 0,
                side: req.side,
                order_type: req.order_type,
                tif: req.tif,
                price: req.new_price,
                qty: req.new_qty,
                nonce: req.nonce,
                owner: req.owner,
                pubkey: req.pubkey,
                signature: req.signature,
            };
            OrderAction::Replace { order_id: req.order_id, owner: req.owner, new_order }
        }
    }
}

/// Check if a buffer starts with an action request (action flag =
/// 0xFE in the market field).
pub fn is_action_request(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[3] == ACTION_FLAG
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> primitives::Address {
        primitives::Address([byte; 20])
    }

    /// Build a signed order for testing.
    fn signed_order(nonce: u64, owner_byte: u8) -> OrderRequest {
        let (secret, _) = crypto::ed25519::generate_keypair_for_test();
        let mut req = OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            nonce,
            owner: addr(owner_byte),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        sign_order(&mut req, &secret);
        req
    }

    #[test]
    fn request_roundtrip() {
        let req = signed_order(1, 0x42);
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
    fn response_bad_signature_roundtrip() {
        let resp = OrderResponse::rejected(RejectReason::BadSignature);
        let encoded = encode_response(&resp);
        let decoded = decode_response(&encoded).expect("decode");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut buf = encode_request(&signed_order(1, 0));
        buf[0] = 0xFF; // Bad magic.
        assert!(decode_request(&buf).is_none());
    }

    #[test]
    fn verify_authentic_order() {
        let req = signed_order(1, 0x42);
        assert!(verify_order(&req), "authentic order must verify");
    }

    #[test]
    fn verify_rejects_tampered_price() {
        let mut req = signed_order(1, 0x42);
        req.price = Price(req.price.0 + 1);
        assert!(!verify_order(&req), "tampered order must not verify");
    }

    #[test]
    fn verify_rejects_tampered_owner() {
        let mut req = signed_order(1, 0x42);
        req.owner = addr(0x99);
        assert!(!verify_order(&req), "tampered owner must not verify");
    }

    #[test]
    fn verify_rejects_tampered_nonce() {
        let mut req = signed_order(1, 0x42);
        req.nonce = 999;
        assert!(!verify_order(&req), "tampered nonce must not verify");
    }

    #[test]
    fn batch_roundtrip() {
        let orders = vec![signed_order(1, 0x10), signed_order(2, 0x20)];
        let encoded = encode_batch_request(&orders);
        let decoded = decode_batch_request(&encoded).expect("decode batch");
        assert_eq!(decoded, orders);
    }

    // ── Action protocol tests ─────────────────────────────────────

    fn signed_cancel(nonce: u64, owner_byte: u8, order_id: u64) -> ActionRequest {
        let (secret, _) = crypto::ed25519::generate_keypair_for_test();
        let mut req = ActionRequest {
            action_type: ActionType::Cancel,
            order_id,
            new_price: Price(0),
            new_qty: Qty(0),
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            nonce,
            owner: addr(owner_byte),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        sign_action(&mut req, &secret);
        req
    }

    fn signed_amend(
        nonce: u64,
        owner_byte: u8,
        order_id: u64,
        new_price: u64,
        new_qty: u64,
    ) -> ActionRequest {
        let (secret, _) = crypto::ed25519::generate_keypair_for_test();
        let mut req = ActionRequest {
            action_type: ActionType::Amend,
            order_id,
            new_price: Price(new_price),
            new_qty: Qty(new_qty),
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            nonce,
            owner: addr(owner_byte),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        sign_action(&mut req, &secret);
        req
    }

    #[test]
    fn action_cancel_roundtrip() {
        let req = signed_cancel(1, 0x42, 7);
        let encoded = encode_action_request(&req);
        let decoded = decode_action_request(&encoded).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn action_amend_roundtrip() {
        let req = signed_amend(2, 0x42, 3, 1_600_000_000, 2_000);
        let encoded = encode_action_request(&req);
        let decoded = decode_action_request(&encoded).expect("decode");
        assert_eq!(decoded, req);
    }

    #[test]
    fn action_verify_authentic() {
        let req = signed_cancel(1, 0x42, 5);
        assert!(verify_action(&req), "authentic action must verify");
    }

    #[test]
    fn action_verify_rejects_tampered_order_id() {
        let mut req = signed_cancel(1, 0x42, 5);
        req.order_id = 999;
        assert!(!verify_action(&req), "tampered action must not verify");
    }

    #[test]
    fn action_verify_rejects_tampered_owner() {
        let mut req = signed_cancel(1, 0x42, 5);
        req.owner = addr(0x99);
        assert!(!verify_action(&req), "tampered owner must not verify");
    }

    #[test]
    fn action_request_to_order_action_cancel() {
        let req = signed_cancel(1, 0x42, 7);
        let action = action_request_to_order_action(&req);
        match action {
            OrderAction::Cancel { order_id, owner } => {
                assert_eq!(order_id, 7);
                assert_eq!(owner, addr(0x42));
            }
            _ => panic!("expected Cancel"),
        }
    }

    #[test]
    fn action_request_to_order_action_amend() {
        let req = signed_amend(2, 0x42, 3, 1_600_000_000, 2_000);
        let action = action_request_to_order_action(&req);
        match action {
            OrderAction::Amend { order_id, owner, new_price, new_qty } => {
                assert_eq!(order_id, 3);
                assert_eq!(owner, addr(0x42));
                assert_eq!(new_price.0, 1_600_000_000);
                assert_eq!(new_qty.0, 2_000);
            }
            _ => panic!("expected Amend"),
        }
    }

    #[test]
    fn is_action_request_detects_flag() {
        let req = signed_cancel(1, 0x42, 0);
        let encoded = encode_action_request(&req);
        assert!(is_action_request(&encoded));
        // A regular order request has a market byte (0..255, not 0xFE).
        let order = signed_order(1, 0x42);
        let order_encoded = encode_request(&order);
        assert!(!is_action_request(&order_encoded));
    }

    #[test]
    fn order_not_found_reject_reason_roundtrip() {
        let resp = OrderResponse::rejected(RejectReason::OrderNotFound);
        let encoded = encode_response(&resp);
        let decoded = decode_response(&encoded).expect("decode");
        assert_eq!(decoded, resp);
    }
}
