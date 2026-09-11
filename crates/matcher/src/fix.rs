//! FIX 4.4 protocol adapter — order entry via FIX sessions.
//!
//! Parses FIX `NewOrderSingle` (MsgType=D) messages into
//! `OrderRequest`s. This is the protocol used by institutional
//! trading desks, prime brokers, and OMS/EMS systems.
//!
//! # Supported FIX tags
//!
//! | Tag | Name | Mapping |
//! |-----|------|---------|
//! | 11  | `ClOrdID` | (ignored — client order ID) |
//! | 54  | `Side` | 1=Buy, 2=Sell |
//! | 40  | `OrdType` | 2=Limit, 1=Market |
//! | 59  | `TimeInForce` | 0=Day(GTC), 3=IOC, 4=FOK |
//! | 44  | `Price` | scale-8 (price * 1e8) |
//! | 38  | `OrderQty` | scale-6 (qty * 1e6) |
//! | 1   | `Account` | 20-byte hex address (owner) |
//! | 55  | `Symbol` | (ignored — market mapping is external) |
//!
//! # Limitations
//!
//! v0 supports `NewOrderSingle` (D) only. Cancel (F) and
//! cancel-replace (G) are deferred. FIX session-level (logon,
//! heartbeat, resend) is handled by the external FIX gateway
//! (e.g. `QuickFIX`, FIX8); this module only parses the application-
//! layer order message.

use crate::protocol::{OrderRequest, OrderResponse, RejectReason};
use primitives::fixed::{Price, Qty};
use std::fmt::Write;
use trading::{OrderType, Side, TimeInForce};

/// FIX `MsgType` for `NewOrderSingle`.
pub const MSG_TYPE_NEW_ORDER: &str = "D";

/// Parse a FIX `NewOrderSingle` (MsgType=D) message into an
/// `OrderRequest`.
///
/// The input is the raw FIX message body (tag=value pairs separated
/// by SOH `\x01`). The caller is responsible for session-level
/// handling (Logon, Heartbeat, etc.).
///
/// Returns `None` if required tags are missing or invalid.
pub fn parse_fix_order(body: &str) -> Option<OrderRequest> {
    let tags = parse_fix_tags(body);

    // Side (tag 54): 1=Buy, 2=Sell.
    let side = match tags.get("54")?.as_str() {
        "1" => Side::Buy,
        "2" => Side::Sell,
        _ => return None,
    };

    // OrdType (tag 40): 2=Limit, 1=Market.
    let order_type = match tags.get("40")?.as_str() {
        "2" => OrderType::Limit,
        "1" => OrderType::Market,
        _ => return None,
    };

    // TimeInForce (tag 59): 0=Day(GTC), 3=IOC, 4=FOK.
    let tif = match tags.get("59").map_or("0", std::string::String::as_str) {
        "0" => TimeInForce::Gtc,
        "3" => TimeInForce::Ioc,
        "4" => TimeInForce::Fok,
        _ => return None,
    };

    // Price (tag 44): decimal string → scale-8.
    let price_str = tags.get("44")?;
    let price = parse_fix_price(price_str)?;

    // OrderQty (tag 38): decimal string → scale-6.
    let qty_str = tags.get("38")?;
    let qty = parse_fix_qty(qty_str)?;

    // Account (tag 1): 20-byte hex address.
    let owner_str = tags.get("1")?;
    let owner = parse_fix_address(owner_str)?;

    Some(OrderRequest { market: 0, side, order_type, tif, price, qty, owner })
}

/// Format an order response as a FIX `ExecutionReport` (MsgType=8).
pub fn format_fix_execution_report(resp: &OrderResponse, cl_ord_id: &str) -> String {
    let exec_type = if resp.rejected {
        "8"
    } else if resp.order_id > 0 {
        "0"
    } else {
        "2"
    };
    let ord_status = if resp.rejected {
        "8" // Rejected.
    } else if resp.order_id > 0 {
        "0" // New (resting).
    } else {
        "2" // Filled.
    };

    let mut msg = String::with_capacity(256);
    msg.push_str("35=8\x01"); // MsgType=ExecutionReport.
    let _ = write!(msg, "11={cl_ord_id}\x01"); // ClOrdID.
    let _ = write!(msg, "150={exec_type}\x01"); // ExecType.
    let _ = write!(msg, "39={ord_status}\x01"); // OrdStatus.

    if resp.rejected {
        let reason = resp.reject_reason.map_or("99", fix_reject_code);
        let _ = write!(msg, "103={reason}\x01"); // OrdRejReason.
    } else {
        let _ = write!(msg, "151={}\x01", resp.fills_count); // LeavesQty (simplified).
        let _ = write!(msg, "14={}\x01", resp.fills_count); // CumQty.
    }

    msg
}

fn parse_fix_tags(body: &str) -> std::collections::HashMap<String, String> {
    let mut tags = std::collections::HashMap::new();
    for field in body.split('\x01') {
        if let Some(eq) = field.find('=') {
            let (tag, value) = field.split_at(eq);
            tags.insert(tag.to_string(), value[1..].to_string());
        }
    }
    tags
}

fn parse_fix_price(s: &str) -> Option<Price> {
    // FIX prices are decimal (e.g. "15.00"). Convert to scale-8:
    // 15.00 → 1_500_000_000.
    let scaled = parse_decimal_to_scaled(s, 100_000_000)?;
    Some(Price(scaled))
}

fn parse_fix_qty(s: &str) -> Option<Qty> {
    // FIX quantities are decimal (e.g. "0.001"). Convert to scale-6:
    // 0.001 → 1_000.
    let scaled = parse_decimal_to_scaled(s, 1_000_000)?;
    Some(Qty(scaled))
}

/// Parse a decimal string (e.g. "15.00") and scale it by `multiplier`
/// (e.g. `100_000_000` for scale-8). Returns `None` on parse failure.
/// Uses integer arithmetic to avoid f64 precision loss.
fn parse_decimal_to_scaled(s: &str, multiplier: u64) -> Option<u64> {
    let (int_part, frac_part) = s.split_once('.')?;
    let int_val: u64 = int_part.parse().ok()?;
    let frac_trimmed = frac_part.trim_end_matches('0');
    let multiplier_str = multiplier.to_string();
    let scale_digits = multiplier_str.len() - 1; // e.g. 1e8 → 8 digits.
    let frac_padded = format!("{frac_trimmed:0<scale_digits$}");
    let frac_val: u64 = frac_padded.parse().ok()?;
    Some(int_val * multiplier + frac_val)
}

fn parse_fix_address(s: &str) -> Option<primitives::Address> {
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

fn fix_reject_code(r: RejectReason) -> &'static str {
    match r {
        RejectReason::InsufficientBalance => "0", // BrokerOption.
        RejectReason::EngineError => "99",        // Other.
        RejectReason::EngineRejected => "5",      // UnknownSymbol.
        RejectReason::Killed => "1",              // UnknownOrder.
        RejectReason::Malformed => "6",           // UnsupportedOrderCharacteristic.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_order_single() {
        let body = "11=ORD001\x0154=1\x0140=2\x0159=0\x0144=15.00\x0138=0.001\x0155=OXIDE\x011=0x4242424242424242424242424242424242424242\x01";
        let req = parse_fix_order(body).expect("parse");
        assert_eq!(req.side, Side::Buy);
        assert_eq!(req.order_type, OrderType::Limit);
        assert_eq!(req.tif, TimeInForce::Gtc);
        assert_eq!(req.price.0, 1_500_000_000);
        assert_eq!(req.qty.0, 1_000);
        assert_eq!(req.owner.0, [0x42; 20]);
    }

    #[test]
    fn format_execution_report_filled() {
        let resp = OrderResponse::filled(1);
        let msg = format_fix_execution_report(&resp, "ORD001");
        assert!(msg.contains("35=8"));
        assert!(msg.contains("150=2")); // ExecType=Fill.
        assert!(msg.contains("39=2")); // OrdStatus=Filled.
    }

    #[test]
    fn format_execution_report_rejected() {
        let resp = OrderResponse::rejected(RejectReason::InsufficientBalance);
        let msg = format_fix_execution_report(&resp, "ORD001");
        assert!(msg.contains("150=8")); // ExecType=Rejected.
        assert!(msg.contains("39=8")); // OrdStatus=Rejected.
        assert!(msg.contains("103=0")); // OrdRejReason.
    }
}
