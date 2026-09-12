//! Order vocabulary: sides, types, time-in-force, self-trade modes,
//! and the validated [`NewOrder`] request the engine accepts.
//!
//! ## Why a closed, `Copy` type vocabulary
//!
//! Every field here is one byte on the wire and one byte in the slab
//! node. Closed enums (instead of flags or strings) keep the match
//! loop branch-predictable and make invalid states unrepresentable —
//! e.g. a `Market` order can never carry a `Gtc` time-in-force because
//! [`NewOrder::validate`] rejects the combination before any
//! structure is touched.

use primitives::Address;
use primitives::fixed::{Price, Qty};

use crate::error::RejectReason;

/// Trading side. One byte on the wire; ordering is irrelevant (sides
/// are never compared, only matched).
///
/// `#[repr(u8)]` ensures the enum is exactly 1 byte, which is
/// critical for slab node layout (cache-line alignment). Without it,
/// the compiler could choose a larger representation, bloating the
/// `OrderNode` struct and reducing cache density.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Side {
    /// Buying the base asset (taking from asks).
    Buy,
    /// Selling the base asset (taking from bids).
    Sell,
}

impl Side {
    /// The opposite side — used to select which half of the book an
    /// incoming order sweeps.
    #[inline]
    #[must_use]
    pub const fn opposite(self) -> Side {
        match self {
            Side::Buy => Side::Sell,
            Side::Sell => Side::Buy,
        }
    }
}

/// Execution style of the order (plan.md §9.1 "Order types").
///
/// `Market` and `PostOnly` are specializations of `Limit` for
/// matching purposes: a market order is a limit sweep with no price
/// bound; a post-only order is a limit order that must rest.
///
/// `#[repr(u8)]` ensures the enum is exactly 1 byte for slab layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OrderType {
    /// Rests at `price` unless fully matched on entry; remainder
    /// rests (subject to [`TimeInForce`]).
    Limit,
    /// Sweeps the opposite book immediately; any unfilled remainder
    /// is canceled (market orders never rest).
    Market,
    /// Must rest: rejected outright if it would cross the book.
    /// Protects liquidity providers from taking their own spread.
    PostOnly,
}

/// How long the (resting remainder of an) order stays alive
/// (plan.md §9.1 "TIF").
///
/// `Day`/`GTD` expiries are height-driven and arrive with the
/// exchange module's order lifecycle; the engine core only needs to
/// know whether a remainder may rest.
///
/// `#[repr(u8)]` ensures the enum is exactly 1 byte for slab layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TimeInForce {
    /// Good-til-canceled: remainder rests until matched or canceled.
    Gtc,
    /// Immediate-or-cancel: remainder is canceled after the entry
    /// sweep (partial fills stand).
    Ioc,
    /// Fill-or-kill: either the *entire* quantity fills on entry or
    /// nothing executes at all.
    Fok,
}

/// Self-trade-prevention mode applied when an incoming order would
/// match against a resting order of the same owner (plan.md §9.1
/// "STP modes").
///
/// `#[repr(u8)]` ensures the enum is exactly 1 byte for slab layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StpMode {
    /// No prevention: self-trades execute like any other trade.
    /// Cheapest path (no owner compare skipped, but no special case).
    None,
    /// Cancel the *newest* order: the incoming taker's remainder is
    /// canceled on first self-touch (fills already booked stand).
    CancelNewest,
    /// Cancel the *oldest* order: the resting maker is removed
    /// (unfilled), and the taker continues matching later makers.
    CancelOldest,
    /// Cancel the smaller remaining quantity and decrement the larger
    /// by it: if the maker is smaller it is fully removed and the
    /// taker continues; if the taker is smaller its remainder is
    /// consumed decrementing the maker (no fill is booked).
    /// This is Hyperliquid's default mode.
    DecrementAndCancel,
}

/// Engine-assigned order identifier.
///
/// Assigned monotonically per market at *submission* (before matching),
/// so every order — even one that never rests — has a stable id for
/// event correlation. `u64` sequence; sequential assignment also makes
/// the [`crate::IdMap`] probe distances near-zero by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct OrderId(
    /// Raw sequence value, starting at 0.
    pub u64,
);

impl std::fmt::Display for OrderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// A validated new-order request.
///
/// Built by the gateway/module from a wire message and checked by
/// [`NewOrder::validate`] *before* the engine's match loop sees it
/// (plan.md §9.1: all validation before the match loop; zero
/// validation inside matching).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewOrder {
    /// Buy or sell.
    pub side: Side,
    /// Execution style.
    pub order_type: OrderType,
    /// Time in force. Must be `Ioc` for `Market`, `Gtc` for `PostOnly`.
    pub tif: TimeInForce,
    /// Limit price. Ignored for `Market` orders.
    pub price: Price,
    /// Order quantity, in raw scale-6 units.
    pub qty: Qty,
    /// Owning account (self-trade checks compare against this).
    pub owner: Address,
    /// Self-trade-prevention mode.
    pub stp: StpMode,
}

impl NewOrder {
    /// Validate the request against a market's tick/lot/band rules.
    ///
    /// # Errors
    /// [`RejectReason`] describing the first violated rule. Order of
    /// checks is fixed (qty → tif/type → price band → tick grid) so
    /// rejection messages are deterministic across validators.
    pub fn validate(
        &self,
        tick: u64,
        lot: u64,
        min_price: u64,
        max_price: u64,
    ) -> Result<(), RejectReason> {
        // Quantity: positive and a whole number of lots. Zero-qty and
        // sub-lot orders can never produce a well-formed fill.
        if self.qty.0 == 0 || self.qty.0 % lot != 0 {
            return Err(RejectReason::InvalidQty);
        }
        // Type/TIF coherence: market orders never rest (Ioc only);
        // post-only always rests (Gtc only).
        let coherent = match (self.order_type, self.tif) {
            (OrderType::Market, TimeInForce::Ioc)
            | (OrderType::PostOnly, TimeInForce::Gtc)
            | (OrderType::Limit, _) => true,
            (OrderType::Market | OrderType::PostOnly, _) => false,
        };
        if !coherent {
            return Err(RejectReason::InvalidTifForType);
        }
        // Price band + grid, only for priced order types.
        if self.order_type != OrderType::Market {
            let p = self.price.0;
            if p < min_price || p > max_price {
                return Err(RejectReason::PriceOutOfRange);
            }
            // Off-grid check relative to the band's floor: a price is
            // on-grid iff (p - min) is a whole number of ticks.
            if (p - min_price) % tick != 0 {
                return Err(RejectReason::PriceOffTick);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A market-shaped fixture: tick 0.01 (raw 1e6), lot 0.001 (raw
    // 1e3), band [10.00, 20.00] raw → 10e8..20e8.
    const TICK: u64 = 1_000_000;
    const LOT: u64 = 1_000;
    const MIN_P: u64 = 1_000_000_000;
    const MAX_P: u64 = 2_000_000_000;

    fn base_order() -> NewOrder {
        NewOrder {
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(5_000),
            owner: Address([1; 20]),
            stp: StpMode::None,
        }
    }

    #[test]
    fn valid_limit_order_passes() {
        assert_eq!(base_order().validate(TICK, LOT, MIN_P, MAX_P), Ok(()));
    }

    #[test]
    fn zero_qty_rejected() {
        let mut o = base_order();
        o.qty = Qty(0);
        assert_eq!(o.validate(TICK, LOT, MIN_P, MAX_P), Err(RejectReason::InvalidQty));
    }

    #[test]
    fn sub_lot_qty_rejected() {
        let mut o = base_order();
        o.qty = Qty(1_500); // 1.5 lots
        assert_eq!(o.validate(TICK, LOT, MIN_P, MAX_P), Err(RejectReason::InvalidQty));
    }

    #[test]
    fn market_with_gtc_rejected() {
        let mut o = base_order();
        o.order_type = OrderType::Market;
        o.tif = TimeInForce::Gtc;
        assert_eq!(o.validate(TICK, LOT, MIN_P, MAX_P), Err(RejectReason::InvalidTifForType));
    }

    #[test]
    fn post_only_with_ioc_rejected() {
        let mut o = base_order();
        o.order_type = OrderType::PostOnly;
        o.tif = TimeInForce::Ioc;
        assert_eq!(o.validate(TICK, LOT, MIN_P, MAX_P), Err(RejectReason::InvalidTifForType));
    }

    #[test]
    fn off_tick_price_rejected() {
        let mut o = base_order();
        o.price = Price(1_500_500_000); // half a tick above grid
        assert_eq!(o.validate(TICK, LOT, MIN_P, MAX_P), Err(RejectReason::PriceOffTick));
    }

    #[test]
    fn out_of_band_price_rejected() {
        let mut o = base_order();
        o.price = Price(2_500_000_000);
        assert_eq!(o.validate(TICK, LOT, MIN_P, MAX_P), Err(RejectReason::PriceOutOfRange));
    }

    #[test]
    fn market_order_skips_price_checks() {
        // A market order with nonsense price fields is still valid —
        // price is ignored for that type.
        let mut o = base_order();
        o.order_type = OrderType::Market;
        o.tif = TimeInForce::Ioc;
        o.price = Price(9_999_999_999);
        assert_eq!(o.validate(TICK, LOT, MIN_P, MAX_P), Ok(()));
    }

    #[test]
    fn side_opposite_round_trips() {
        assert_eq!(Side::Buy.opposite(), Side::Sell);
        assert_eq!(Side::Sell.opposite(), Side::Buy);
    }
}
