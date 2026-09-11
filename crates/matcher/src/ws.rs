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

use crate::protocol::{OrderRequest, OrderResponse, RejectReason};
use primitives::fixed::{Price, Qty};
use trading::{OrderType, Side, TimeInForce};

/// Parse a JSON order request into an `OrderRequest`.
///
/// This is a minimal hand-rolled parser — avoids pulling in a full
/// JSON parser dependency for the hot path. Expects the exact
/// field layout documented above.
pub fn parse_ws_order(json: &str) -> Option<OrderRequest> {
    let market = extract_u8(json, "market")?;
    let side = match extract_str(json, "side")?.as_str() {
        "buy" | "Buy" | "BUY" => Side::Buy,
        "sell" | "Sell" | "SELL" => Side::Sell,
        _ => return None,
    };
    let order_type = match extract_str(json, "type")?.as_str() {
        "limit" | "Limit" => OrderType::Limit,
        "market" | "Market" => OrderType::Market,
        "postonly" | "PostOnly" => OrderType::PostOnly,
        _ => return None,
    };
    let tif = match extract_str(json, "tif")?.as_str() {
        "gtc" | "Gtc" => TimeInForce::Gtc,
        "ioc" | "Ioc" => TimeInForce::Ioc,
        "fok" | "Fok" => TimeInForce::Fok,
        _ => return None,
    };
    let price = Price(extract_u64(json, "price")?);
    let qty = Qty(extract_u64(json, "qty")?);
    let owner_str = extract_str(json, "owner")?;
    let owner = parse_address(&owner_str)?;
    Some(OrderRequest { market, side, order_type, tif, price, qty, owner })
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
    }
}

fn extract_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    let colon = rest.find(':')?;
    let rest = &rest[colon + 1..];
    let rest = rest.trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        // Quoted string value.
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        // Unquoted value (number, boolean, null) — read until
        // the next comma, brace, or bracket.
        let end = rest.find([',', '}', ']']).unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
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
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return None;
    }
    let mut addr = [0u8; 20];
    for (i, byte) in s.as_bytes().chunks(2).enumerate() {
        if i >= 20 {
            return None;
        }
        let hex = std::str::from_utf8(byte).ok()?;
        addr[i] = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(primitives::Address(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_buy_order() {
        let json = r#"{"method":"oxide_placeOrder","params":{"market":0,"side":"buy","type":"limit","tif":"gtc","price":"1500000000","qty":"1000","owner":"0x4242424242424242424242424242424242424242"},"id":1}"#;
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
}
