//! Error types for the trading core.
//!
//! Two error families, kept deliberately separate (production-rust
//! skill §3: *user mistakes* must be distinguishable from *system
//! misconfiguration*):
//!
//! - [`TradingError`] — system-level failures: invalid market
//!   configuration, or internal capacity/consistency violations.
//!   These reject a transaction *and* alert the operator, because a
//!   valid chain should never produce them at runtime.
//! - [`RejectReason`] — order-level rejections: the order itself is
//!   malformed, unpriceable, or would violate a placement rule. These
//!   are returned to the submitter as a normal, expected outcome
//!   (venues call this "order rejected"), never as a system fault.
//!
//! Invariants:
//! - Both types are `Copy` and allocation-free: they appear on the
//!   per-order hot path and must never allocate in `Display`.
//! - No `String` payloads — every variant carries structured data so
//!   callers (the exchange module, the risk engine) can branch on the
//!   exact cause without parsing text.

use std::fmt;

/// System-level failure in the trading core.
///
/// A `TradingError` at runtime means one of:
/// 1. Market configuration was invalid at construction (genesis bug),
/// 2. An internal capacity or arithmetic bound was hit (config bug),
/// 3. A referenced order does not exist (caller logic bug).
///
/// All three indicate misconfiguration or software fault — never
/// normal user behavior. The exchange module maps these to
/// `ExecError::ModuleRejected` (transaction rejected, state
/// unchanged) and, for case 1, refuses to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TradingError {
    /// The market configuration is internally inconsistent.
    ///
    /// Carries the offending field name as a `&'static str` (not a
    /// `String`: config validation is a cold path, but the error type
    /// stays `Copy` for hot-path uniformity).
    InvalidConfig(&'static str),
    /// A resting order with the given id does not exist (already
    /// filled, canceled, or never rested).
    OrderNotFound,
    /// The order pool's configured capacity would be exceeded by the
    /// requested operation.
    ///
    /// Capacity is fixed at market construction (plan.md §9.1: "2^20
    /// resting orders default"); hitting it is a capacity-planning
    /// bug to fix in genesis config, not a runtime condition to
    /// absorb silently.
    BookFull,
    /// A fixed-point computation overflowed its destination.
    ///
    /// Overflow in order math is a consensus input bug (market bounds
    /// should make it impossible); it is rejected loudly rather than
    /// saturating, because saturation would fork validators.
    Overflow,
}

impl fmt::Display for TradingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TradingError::InvalidConfig(field) => {
                write!(f, "invalid market config: {field}")
            }
            TradingError::OrderNotFound => {
                write!(f, "order not found (filled, canceled, or never rested)")
            }
            TradingError::BookFull => {
                write!(f, "resting-order capacity exceeded (max_resting in MarketConfig)")
            }
            TradingError::Overflow => {
                write!(f, "fixed-point overflow in order math")
            }
        }
    }
}

impl std::error::Error for TradingError {}

/// Order-level rejection: the submitted order is invalid as-is.
///
/// Rejections are *expected outcomes*, not faults: a venue rejects
/// fat-finger prices and zero quantities all day long. The exchange
/// module reports these to the submitter in the order-ack event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Quantity was zero (or not a positive multiple of the lot size).
    ///
    /// Orders must carry `qty >= lot_size` and `qty % lot_size == 0`
    /// (plan.md §9.1 order lifecycle: lot rules are enforced before
    /// the match loop).
    InvalidQty,
    /// A limit/post-only price was not on the market's tick grid.
    ///
    /// Off-tick prices are unmatchable by construction — rejecting at
    /// parse time keeps the tick ladder a pure array index.
    PriceOffTick,
    /// A limit/post-only price was outside `[min_price, max_price]`.
    PriceOutOfRange,
    /// The time-in-force is not valid for the order type
    /// (e.g. `Market` with `Gtc`, or `PostOnly` with `Ioc`).
    InvalidTifForType,
    /// A post-only order would have crossed the book.
    ///
    /// Post-only orders must *add* liquidity; matching one would
    /// violate the submitter's own intent (plan.md §9.1 order types).
    PostOnlyWouldCross,
    /// The market's resting-order capacity is full.
    ///
    /// Mirrors [`TradingError::BookFull`] at the order level: the
    /// placement is rejected (the submitter can retry after cancels),
    /// but the condition is also a config-capacity signal.
    BookFull,
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RejectReason::InvalidQty => write!(f, "qty must be a positive multiple of lot size"),
            RejectReason::PriceOffTick => write!(f, "price not on tick grid"),
            RejectReason::PriceOutOfRange => write!(f, "price outside [min, max] band"),
            RejectReason::InvalidTifForType => write!(f, "time-in-force invalid for order type"),
            RejectReason::PostOnlyWouldCross => write!(f, "post-only order would cross"),
            RejectReason::BookFull => write!(f, "resting-order capacity full"),
        }
    }
}

impl std::error::Error for RejectReason {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant renders a non-empty, distinct message — the
    /// gateway logs these verbatim, so a blank or duplicated Display
    /// would make operator triage impossible.
    #[test]
    fn display_messages_are_distinct_and_nonempty() {
        let errors = [
            TradingError::InvalidConfig("tick"),
            TradingError::OrderNotFound,
            TradingError::BookFull,
            TradingError::Overflow,
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
        let rejections = [
            RejectReason::InvalidQty,
            RejectReason::PriceOffTick,
            RejectReason::PriceOutOfRange,
            RejectReason::InvalidTifForType,
            RejectReason::PostOnlyWouldCross,
            RejectReason::BookFull,
        ];
        for r in &rejections {
            assert!(!r.to_string().is_empty());
        }
        // Distinctness within each family.
        for i in 0..errors.len() {
            for j in (i + 1)..errors.len() {
                assert_ne!(errors[i].to_string(), errors[j].to_string());
            }
        }
        for i in 0..rejections.len() {
            for j in (i + 1)..rejections.len() {
                assert_ne!(rejections[i].to_string(), rejections[j].to_string());
            }
        }
    }
}
