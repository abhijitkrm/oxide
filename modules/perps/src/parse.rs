//! Wire-format decoders for the perps module.
//!
//! Split from `lib.rs` around the decode invariant: each
//! `parse_*` is the single schema owner for its message type —
//! the handle layer never touches raw bytes. A malformed message
//! is rejected here, before any state is read.

use super::{
    Address, CANCEL_BODY_LEN, FLAG_REDUCE_ONLY, FUNDING_BODY_LEN, LIST_MARKET_BODY_LEN,
    MARGIN_BODY_LEN, MarketConfig, NewOrder, OrderId, PLACE_BODY_LEN, PerpsMarketConfig,
    PerpsModule, Price, Qty, SET_MARK_BODY_LEN, decode_order_type, decode_side, decode_stp,
    decode_tif,
};

impl PerpsModule {
    pub(crate) fn parse_place(msg: &[u8]) -> Option<(u8, NewOrder, u8)> {
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
        let flags = msg[21];
        // Unknown flag bits are rejected, not ignored — a client
        // setting a bit the module doesn't understand is asking for
        // semantics it won't get (fail closed).
        if flags & !FLAG_REDUCE_ONLY != 0 {
            return None;
        }
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
            flags,
        ))
    }

    pub(crate) fn parse_cancel(msg: &[u8]) -> Option<(u8, OrderId)> {
        if msg.len() != CANCEL_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let order_id = u64::from_le_bytes(msg[1..9].try_into().ok()?);
        Some((market, OrderId(order_id)))
    }

    pub(crate) fn parse_list_market(msg: &[u8]) -> Option<PerpsMarketConfig> {
        if msg.len() != LIST_MARKET_BODY_LEN {
            return None;
        }
        let tick_size = u64::from_le_bytes(msg[0..8].try_into().ok()?);
        let lot_size = u64::from_le_bytes(msg[8..16].try_into().ok()?);
        let min_price = u64::from_le_bytes(msg[16..24].try_into().ok()?);
        let max_price = u64::from_le_bytes(msg[24..32].try_into().ok()?);
        let max_resting = u32::from_le_bytes(msg[32..36].try_into().ok()?);
        let max_leverage = u16::from_le_bytes(msg[36..38].try_into().ok()?);
        let mmr_base_bps = u16::from_le_bytes(msg[38..40].try_into().ok()?);
        Some(PerpsMarketConfig {
            base: MarketConfig {
                market_id: 0,
                tick_size,
                lot_size,
                min_price,
                max_price,
                max_resting,
            },
            max_leverage,
            mmr_base_bps,
        })
    }

    pub(crate) fn parse_margin(msg: &[u8]) -> Option<(u8, u64)> {
        if msg.len() != MARGIN_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let amount = u64::from_le_bytes(msg[1..9].try_into().ok()?);
        Some((market, amount))
    }

    pub(crate) fn parse_set_mark(msg: &[u8]) -> Option<(u8, u64)> {
        if msg.len() != SET_MARK_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let mark = u64::from_le_bytes(msg[1..9].try_into().ok()?);
        Some((market, mark))
    }

    pub(crate) fn parse_funding(msg: &[u8]) -> Option<(u8, [u8; 8])> {
        if msg.len() != FUNDING_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let rate_bytes: [u8; 8] = msg[1..9].try_into().ok()?;
        Some((market, rate_bytes))
    }
}
