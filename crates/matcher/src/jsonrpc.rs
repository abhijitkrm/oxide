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

use crate::protocol::{ActionRequest, ActionType, OrderRequest, OrderResponse, RejectReason};
use primitives::fixed::{Price, Qty};
use trading::{OrderType, Side, TimeInForce};

/// The JSON-RPC method name for order placement.
pub const METHOD_PLACE_ORDER: &str = "oxide_placeOrder";

/// The JSON-RPC method name for order actions (cancel/amend/replace).
pub const MANAGE_ORDER: &str = "oxide_manageOrder";

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
        let nonce = parse_u64_value(map.get("nonce")?).unwrap_or(0);
        let owner = parse_address(map.get("owner")?.as_str()?)?;
        let pubkey = parse_hex_bytes_32(map.get("pubkey")?.as_str()?)?;
        let signature = parse_hex_bytes_64(map.get("signature")?.as_str()?)?;
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
    } else if let serde_json::Value::Array(arr) = params {
        if arr.len() < 10 {
            return None;
        }
        let market = u8::try_from(arr[0].as_u64()?).ok()?;
        let side = parse_side(arr[1].as_str()?)?;
        let order_type = parse_order_type(arr[2].as_str()?)?;
        let tif = parse_tif(arr[3].as_str()?)?;
        let price = Price(parse_u64_value(&arr[4])?);
        let qty = Qty(parse_u64_value(&arr[5])?);
        let nonce = parse_u64_value(&arr[6]).unwrap_or(0);
        let owner = parse_address(arr[7].as_str()?)?;
        let pubkey = parse_hex_bytes_32(arr[8].as_str()?)?;
        let signature = parse_hex_bytes_64(arr[9].as_str()?)?;
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
    } else {
        None
    }
}

/// Parse a JSON-RPC `oxide_manageOrder` request (cancel/amend/replace).
///
/// Accepts named params:
/// - `action` (string): "cancel", "amend", or "replace".
/// - `orderId` (string/u64): the order to act on.
/// - `owner` (string): 0x-prefixed 20-byte address.
/// - `newPrice` (string/u64, optional): new price (amend/replace).
/// - `newQty` (string/u64, optional): new qty (amend/replace).
/// - `side` (string, optional): new order side (replace).
/// - `type` (string, optional): new order type (replace).
/// - `tif` (string, optional): new time-in-force (replace).
/// - `nonce` (string/u64): replay protection nonce.
/// - `pubkey` (string): 32-byte hex Ed25519 public key.
/// - `signature` (string): 64-byte hex Ed25519 signature.
pub fn parse_jsonrpc_action(params: &serde_json::Value) -> Option<ActionRequest> {
    let serde_json::Value::Object(map) = params else {
        return None;
    };
    let action_type = match map.get("action")?.as_str()? {
        "cancel" => ActionType::Cancel,
        "amend" => ActionType::Amend,
        "replace" => ActionType::Replace,
        _ => return None,
    };
    let order_id = parse_u64_value(map.get("orderId")?)?;
    let owner = parse_address(map.get("owner")?.as_str()?)?;
    let nonce = parse_u64_value(map.get("nonce")?).unwrap_or(0);
    // newPrice/newQty are optional (Cancel doesn't include them).
    let new_price = Price(map.get("newPrice").and_then(parse_u64_value).unwrap_or(0));
    let new_qty = Qty(map.get("newQty").and_then(parse_u64_value).unwrap_or(0));
    let side = map.get("side").and_then(|v| v.as_str()).and_then(parse_side).unwrap_or(Side::Buy);
    let order_type = map
        .get("type")
        .and_then(|v| v.as_str())
        .and_then(parse_order_type)
        .unwrap_or(OrderType::Limit);
    let tif =
        map.get("tif").and_then(|v| v.as_str()).and_then(parse_tif).unwrap_or(TimeInForce::Gtc);
    let pubkey = parse_hex_bytes_32(map.get("pubkey")?.as_str()?)?;
    let signature = parse_hex_bytes_64(map.get("signature")?.as_str()?)?;
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

/// Parse a 32-byte hex string (Ed25519 public key).
fn parse_hex_bytes_32(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let mut buf = [0u8; 32];
    for (i, byte) in s.as_bytes().chunks(2).enumerate() {
        if i >= 32 {
            return None;
        }
        let hex = std::str::from_utf8(byte).ok()?;
        buf[i] = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(buf)
}

/// Parse a 64-byte hex string (Ed25519 signature).
fn parse_hex_bytes_64(s: &str) -> Option<[u8; 64]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 128 {
        return None;
    }
    let mut buf = [0u8; 64];
    for (i, byte) in s.as_bytes().chunks(2).enumerate() {
        if i >= 64 {
            return None;
        }
        let hex = std::str::from_utf8(byte).ok()?;
        buf[i] = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(buf)
}

fn reject_reason_str(r: RejectReason) -> &'static str {
    match r {
        RejectReason::InsufficientBalance => "insufficient_balance",
        RejectReason::EngineError => "engine_error",
        RejectReason::EngineRejected => "engine_rejected",
        RejectReason::Killed => "killed",
        RejectReason::Malformed => "malformed",
        RejectReason::BadSignature => "bad_signature",
        RejectReason::StaleNonce => "stale_nonce",
        RejectReason::OrderNotFound => "order_not_found",
        RejectReason::RateLimited => "rate_limited",
        RejectReason::OrderTooLarge => "order_too_large",
        RejectReason::FatFinger => "fat_finger",
        RejectReason::TooManyResting => "too_many_resting",
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
            "owner": "0x4242424242424242424242424242424242424242",
            "nonce": 1,
            "pubkey": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "signature": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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
            1,
            "0x4242424242424242424242424242424242424242",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
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

    #[test]
    fn parse_cancel_action() {
        let params = serde_json::json!({
            "action": "cancel",
            "orderId": "7",
            "owner": "0x4242424242424242424242424242424242424242",
            "nonce": 2,
            "pubkey": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "signature": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });
        let req = parse_jsonrpc_action(&params).expect("parse");
        assert_eq!(req.action_type, ActionType::Cancel);
        assert_eq!(req.order_id, 7);
    }

    #[test]
    fn parse_amend_action() {
        let params = serde_json::json!({
            "action": "amend",
            "orderId": "3",
            "newPrice": "1600000000",
            "newQty": "2000",
            "owner": "0x4242424242424242424242424242424242424242",
            "nonce": 2,
            "pubkey": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "signature": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });
        let req = parse_jsonrpc_action(&params).expect("parse");
        assert_eq!(req.action_type, ActionType::Amend);
        assert_eq!(req.new_price.0, 1_600_000_000);
        assert_eq!(req.new_qty.0, 2_000);
    }
}
