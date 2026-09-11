//! JSON-RPC order method — HTTP-compatible order submission.
//!
//! Adds `oxide_placeOrder` as a JSON-RPC 2.0 method, compatible
//! with the existing RPC server. This lets standard HTTP clients
//! (curl, web apps, existing EVM tooling) submit orders without a
//! dedicated binary protocol.
//!
//! # Method: `oxide_placeOrder`
//!
//! Params (positional or named):
//! - `market` (u8): market ID (0 in v0).
//! - `side` (string): "buy" or "sell".
//! - `type` (string): "limit", "market", "postonly".
//! - `tif` (string): "gtc", "ioc", "fok".
//! - `price` (string): price in scale-8 (hex or decimal).
//! - `qty` (string): quantity in scale-6 (hex or decimal).
//! - `owner` (string): 0x-prefixed 20-byte address.
//!
//! Returns:
//! - `status` (string): "filled", "resting", or "rejected".
//! - `fills` (u32): number of fills.
//! - `orderId` (string): resting order ID (if resting).
//! - `rejectReason` (string, optional): rejection reason.

use crate::protocol::{OrderRequest, OrderResponse, RejectReason};
use primitives::fixed::{Price, Qty};
use trading::{OrderType, Side, TimeInForce};

/// The JSON-RPC method name for order placement.
pub const METHOD_PLACE_ORDER: &str = "oxide_placeOrder";

/// Parse a JSON-RPC `oxide_placeOrder` request.
///
/// Accepts both named params (`{"market": 0, "side": "buy", ...}`)
/// and positional params (`[0, "buy", "limit", "gtc", "...", "...", "..."]`).
pub fn parse_jsonrpc_order(params: &serde_json::Value) -> Option<OrderRequest> {
    if let serde_json::Value::Object(map) = params {
        let market = u8::try_from(map.get("market")?.as_u64()?).ok()?;
        let side = parse_side(map.get("side")?.as_str()?)?;
        let order_type = parse_order_type(map.get("type")?.as_str()?)?;
        let tif = parse_tif(map.get("tif")?.as_str()?)?;
        let price = Price(parse_u64_value(map.get("price")?)?);
        let qty = Qty(parse_u64_value(map.get("qty")?)?);
        let owner = parse_address(map.get("owner")?.as_str()?)?;
        Some(OrderRequest { market, side, order_type, tif, price, qty, owner })
    } else if let serde_json::Value::Array(arr) = params {
        if arr.len() < 7 {
            return None;
        }
        let market = u8::try_from(arr[0].as_u64()?).ok()?;
        let side = parse_side(arr[1].as_str()?)?;
        let order_type = parse_order_type(arr[2].as_str()?)?;
        let tif = parse_tif(arr[3].as_str()?)?;
        let price = Price(parse_u64_value(&arr[4])?);
        let qty = Qty(parse_u64_value(&arr[5])?);
        let owner = parse_address(arr[6].as_str()?)?;
        Some(OrderRequest { market, side, order_type, tif, price, qty, owner })
    } else {
        None
    }
}

/// Format an order response as a JSON-RPC result value.
pub fn format_jsonrpc_response(resp: &OrderResponse) -> serde_json::Value {
    if resp.rejected {
        let reason = resp.reject_reason.map_or("unknown", reject_reason_str);
        serde_json::json!({
            "status": "rejected",
            "rejectReason": reason,
        })
    } else {
        let status = if resp.order_id > 0 { "resting" } else { "filled" };
        serde_json::json!({
            "status": status,
            "fills": resp.fills_count,
            "orderId": resp.order_id.to_string(),
        })
    }
}

fn parse_side(s: &str) -> Option<Side> {
    match s.to_lowercase().as_str() {
        "buy" => Some(Side::Buy),
        "sell" => Some(Side::Sell),
        _ => None,
    }
}

fn parse_order_type(s: &str) -> Option<OrderType> {
    match s.to_lowercase().as_str() {
        "limit" => Some(OrderType::Limit),
        "market" => Some(OrderType::Market),
        "postonly" | "post_only" => Some(OrderType::PostOnly),
        _ => None,
    }
}

fn parse_tif(s: &str) -> Option<TimeInForce> {
    match s.to_lowercase().as_str() {
        "gtc" => Some(TimeInForce::Gtc),
        "ioc" => Some(TimeInForce::Ioc),
        "fok" => Some(TimeInForce::Fok),
        _ => None,
    }
}

fn parse_u64_value(v: &serde_json::Value) -> Option<u64> {
    match v {
        serde_json::Value::String(s) => {
            if let Some(stripped) = s.strip_prefix("0x") {
                u64::from_str_radix(stripped, 16).ok()
            } else {
                s.parse().ok()
            }
        }
        serde_json::Value::Number(n) => n.as_u64(),
        _ => None,
    }
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

fn reject_reason_str(r: RejectReason) -> &'static str {
    match r {
        RejectReason::InsufficientBalance => "insufficient_balance",
        RejectReason::EngineError => "engine_error",
        RejectReason::EngineRejected => "engine_rejected",
        RejectReason::Killed => "killed",
        RejectReason::Malformed => "malformed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_named_params() {
        let params = serde_json::json!({
            "market": 0,
            "side": "buy",
            "type": "limit",
            "tif": "gtc",
            "price": "1500000000",
            "qty": "1000",
            "owner": "0x4242424242424242424242424242424242424242"
        });
        let req = parse_jsonrpc_order(&params).expect("parse");
        assert_eq!(req.side, Side::Buy);
        assert_eq!(req.price.0, 1_500_000_000);
    }

    #[test]
    fn parse_positional_params() {
        let params = serde_json::json!([
            0,
            "buy",
            "limit",
            "gtc",
            "1500000000",
            "1000",
            "0x4242424242424242424242424242424242424242"
        ]);
        let req = parse_jsonrpc_order(&params).expect("parse");
        assert_eq!(req.side, Side::Buy);
        assert_eq!(req.qty.0, 1000);
    }

    #[test]
    fn format_filled_response() {
        let resp = OrderResponse::filled(1);
        let result = format_jsonrpc_response(&resp);
        assert_eq!(result["status"], "filled");
        assert_eq!(result["fills"], 1);
    }
}
