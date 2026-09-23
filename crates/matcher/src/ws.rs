//! WebSocket order protocol — JSON over WebSocket.
//!
//! Accepts orders as JSON messages over a WebSocket connection.
//! Slower than binary TCP (JSON parsing + WS framing overhead) but
//! browser-compatible and useful for web-based trading UIs.
//!
//! # Message format
//!
//! ```json
//! {
//!   "method": "oxide_placeOrder",
//!   "params": {
//!     "market": 0,
//!     "side": "buy",
//!     "type": "limit",
//!     "tif": "gtc",
//!     "price": "1500000000",
//!     "qty": "1000",
//!     "owner": "0x4242424242424242424242424242424242424242"
//!   },
//!   "id": 1
//! }
//! ```
//!
//! Response:
//! ```json
//! {
//!   "jsonrpc": "2.0",
//!   "result": {
//!     "status": "filled",
//!     "fills": 1,
//!     "orderId": "0"
//!   },
//!   "id": 1
//! }
//! ```

use crate::protocol::{ActionRequest, ActionType, OrderRequest, OrderResponse, RejectReason};
use primitives::fixed::{Price, Qty};
use trading::{OrderType, Side, TimeInForce};

/// Parse a JSON order request into an `OrderRequest`.
///
/// This is a minimal hand-rolled parser — avoids pulling in a full
/// JSON parser dependency for the hot path. Expects the exact
/// field layout documented above.
pub fn parse_ws_order(json: &str) -> Option<OrderRequest> {
    let market = extract_u8(json, "market")?;
    let side = match extract_str(json, "side")? {
        "buy" | "Buy" | "BUY" => Side::Buy,
        "sell" | "Sell" | "SELL" => Side::Sell,
        _ => return None,
    };
    let order_type = match extract_str(json, "type")? {
        "limit" | "Limit" => OrderType::Limit,
        "market" | "Market" => OrderType::Market,
        "postonly" | "PostOnly" => OrderType::PostOnly,
        _ => return None,
    };
    let tif = match extract_str(json, "tif")? {
        "gtc" | "Gtc" => TimeInForce::Gtc,
        "ioc" | "Ioc" => TimeInForce::Ioc,
        "fok" | "Fok" => TimeInForce::Fok,
        _ => return None,
    };
    let price = Price(extract_u64(json, "price")?);
    let qty = Qty(extract_u64(json, "qty")?);
    let nonce = extract_u64(json, "nonce").unwrap_or(0);
    let owner = parse_address(extract_str(json, "owner")?)?;
    let pubkey = parse_hex_32(extract_str(json, "pubkey")?)?;
    let signature = parse_hex_64(extract_str(json, "signature")?)?;
    Some(OrderRequest {
        market,
        side,
        order_type,
        tif,
        price,
        qty,
        nonce,
        owner,
        pubkey,
        signature,
    })
}

/// Parse a JSON order-action request (cancel/amend/replace) into an
/// `ActionRequest`.
///
/// Message format (cancel):
/// ```json
/// {
///   "method": "oxide_cancelOrder",
///   "params": {
///     "orderId": "7",
///     "owner": "0x4242...4242",
///     "nonce": 2,
///     "pubkey": "0x...",
///     "signature": "0x..."
///   },
///   "id": 1
/// }
/// ```
///
/// For amend, add `"newPrice"` and `"newQty"`. For replace, add
/// `"newPrice"`, `"newQty"`, `"side"`, `"type"`, and `"tif"`.
pub fn parse_ws_action(json: &str) -> Option<ActionRequest> {
    let action_type = match extract_str(json, "action")? {
        "cancel" | "Cancel" | "CANCEL" => ActionType::Cancel,
        "amend" | "Amend" | "AMEND" => ActionType::Amend,
        "replace" | "Replace" | "REPLACE" => ActionType::Replace,
        _ => return None,
    };
    let order_id = extract_u64(json, "orderId")?;
    let owner = parse_address(extract_str(json, "owner")?)?;
    let nonce = extract_u64(json, "nonce").unwrap_or(0);
    let new_price = Price(extract_u64(json, "newPrice").unwrap_or(0));
    let new_qty = Qty(extract_u64(json, "newQty").unwrap_or(0));
    // Case-insensitive matching via `eq_ignore_ascii_case` — the
    // protocol tokens are ASCII, so this covers every casing the old
    // `to_lowercase()` compare did without the String allocation.
    let side = match extract_str(json, "side") {
        Some(s) if s.eq_ignore_ascii_case("sell") => Side::Sell,
        _ => Side::Buy, // Default for cancel/amend (ignored).
    };
    let order_type = match extract_str(json, "type") {
        Some(s) if s.eq_ignore_ascii_case("market") => OrderType::Market,
        Some(s) if s.eq_ignore_ascii_case("postonly") || s.eq_ignore_ascii_case("post_only") => {
            OrderType::PostOnly
        }
        _ => OrderType::Limit, // Default for cancel/amend (ignored).
    };
    let tif = match extract_str(json, "tif") {
        Some(s) if s.eq_ignore_ascii_case("ioc") => TimeInForce::Ioc,
        Some(s) if s.eq_ignore_ascii_case("fok") => TimeInForce::Fok,
        _ => TimeInForce::Gtc, // Default for cancel/amend (ignored).
    };
    let pubkey = parse_hex_32(extract_str(json, "pubkey")?)?;
    let signature = parse_hex_64(extract_str(json, "signature")?)?;
    Some(ActionRequest {
        action_type,
        order_id,
        new_price,
        new_qty,
        side,
        order_type,
        tif,
        nonce,
        owner,
        pubkey,
        signature,
    })
}

/// Format an order response as a JSON-RPC response string.
pub fn format_ws_response(resp: &OrderResponse, id: u64) -> String {
    if resp.rejected {
        let reason = resp.reject_reason.map_or("unknown", reject_reason_str);
        format!(
            r#"{{"jsonrpc":"2.0","error":{{"code":-32000,"message":"order rejected: {reason}"}},"id":{id}}}"#
        )
    } else {
        let status = if resp.order_id > 0 { "resting" } else { "filled" };
        format!(
            r#"{{"jsonrpc":"2.0","result":{{"status":"{status}","fills":{},"orderId":"{}"}},"id":{id}}}"#,
            resp.fills_count, resp.order_id
        )
    }
}

fn reject_reason_str(r: RejectReason) -> &'static str {
    match r {
        RejectReason::InsufficientBalance => "insufficient balance",
        RejectReason::EngineError => "engine error",
        RejectReason::EngineRejected => "engine rejected",
        RejectReason::Killed => "killed",
        RejectReason::Malformed => "malformed",
        RejectReason::BadSignature => "bad signature",
        RejectReason::StaleNonce => "stale nonce",
        RejectReason::OrderNotFound => "order not found",
        RejectReason::RateLimited => "rate limited",
        RejectReason::OrderTooLarge => "order too large",
        RejectReason::FatFinger => "fat finger",
        RejectReason::TooManyResting => "too many resting",
    }
}

/// Borrowed-slice field extraction — the old version built an owned
/// `format!("\"{key}\"")` needle plus a `String` value per field
/// (~2 allocs × ~10 fields per message). This returns `&str` slices
/// into the input buffer: zero allocations.
///
/// Semantics preserved: the first quoted `"key"` occurrence wins
/// (same as `find("\"key\"")` on the old needle — including the
/// edge case where a value string literally contains `"key"`),
/// then the value runs to the next `,`, `}`, or `]` unquoted or to
/// the closing quote for string values.
fn extract_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let bytes = json.as_bytes();
    let mut search_from = 0usize;
    loop {
        let pos = json[search_from..].find(key)? + search_from;
        // Require the match to be exactly `"key"` — the byte before
        // and after must be the quotes.
        if pos > 0
            && bytes[pos - 1] == b'"'
            && pos + key.len() < bytes.len()
            && bytes[pos + key.len()] == b'"'
        {
            let rest = &json[pos + key.len() + 1..];
            let colon = rest.find(':')?;
            let rest = rest[colon + 1..].trim_start();
            return if let Some(inner) = rest.strip_prefix('"') {
                // Quoted string value.
                let end = inner.find('"')?;
                Some(&inner[..end])
            } else {
                // Unquoted value (number, boolean, null) — read until
                // the next comma, brace, or bracket.
                let end = rest.find([',', '}', ']']).unwrap_or(rest.len());
                Some(rest[..end].trim())
            };
        }
        search_from = pos + 1;
    }
}

fn extract_u64(json: &str, key: &str) -> Option<u64> {
    let s = extract_str(json, key)?;
    if let Some(stripped) = s.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn extract_u8(json: &str, key: &str) -> Option<u8> {
    extract_u64(json, key).and_then(|v| u8::try_from(v).ok())
}

fn parse_address(s: &str) -> Option<primitives::Address> {
    Some(primitives::Address(crate::protocol::parse_hex_fixed::<20>(s)?))
}

/// Parse a 32-byte hex string (Ed25519 public key).
fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    crate::protocol::parse_hex_fixed::<32>(s)
}

/// Parse a 64-byte hex string (Ed25519 signature).
fn parse_hex_64(s: &str) -> Option<[u8; 64]> {
    crate::protocol::parse_hex_fixed::<64>(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_buy_order() {
        let json = r#"{"method":"oxide_placeOrder","params":{"market":0,"side":"buy","type":"limit","tif":"gtc","price":"1500000000","qty":"1000","owner":"0x4242424242424242424242424242424242424242","nonce":1,"pubkey":"0x0000000000000000000000000000000000000000000000000000000000000000","signature":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"id":1}"#;
        let req = parse_ws_order(json).expect("parse");
        assert_eq!(req.side, Side::Buy);
        assert_eq!(req.price.0, 1_500_000_000);
        assert_eq!(req.qty.0, 1_000);
        assert_eq!(req.owner.0, [0x42; 20]);
    }

    #[test]
    fn format_filled_response() {
        let resp = OrderResponse::filled(1);
        let json = format_ws_response(&resp, 42);
        assert!(json.contains("\"status\":\"filled\""));
        assert!(json.contains("\"fills\":1"));
        assert!(json.contains("\"id\":42"));
    }

    #[test]
    fn format_rejected_response() {
        let resp = OrderResponse::rejected(RejectReason::InsufficientBalance);
        let json = format_ws_response(&resp, 1);
        assert!(json.contains("insufficient balance"));
    }

    #[test]
    fn parse_cancel_action() {
        let json = r#"{"method":"oxide_cancelOrder","params":{"action":"cancel","orderId":"7","owner":"0x4242424242424242424242424242424242424242","nonce":2,"pubkey":"0x0000000000000000000000000000000000000000000000000000000000000000","signature":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"id":1}"#;
        let req = parse_ws_action(json).expect("parse");
        assert_eq!(req.action_type, ActionType::Cancel);
        assert_eq!(req.order_id, 7);
        assert_eq!(req.owner.0, [0x42; 20]);
    }

    #[test]
    fn parse_amend_action() {
        let json = r#"{"method":"oxide_amendOrder","params":{"action":"amend","orderId":"3","newPrice":"1600000000","newQty":"2000","owner":"0x4242424242424242424242424242424242424242","nonce":2,"pubkey":"0x0000000000000000000000000000000000000000000000000000000000000000","signature":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"id":1}"#;
        let req = parse_ws_action(json).expect("parse");
        assert_eq!(req.action_type, ActionType::Amend);
        assert_eq!(req.order_id, 3);
        assert_eq!(req.new_price.0, 1_600_000_000);
        assert_eq!(req.new_qty.0, 2_000);
    }
}
