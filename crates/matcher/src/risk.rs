//! Risk engine — pre-trade risk controls for the matching server.
//!
//! Implements four risk gates that run *before* the balance check
//! and matching-engine placement:
//!
//! 1. **Rate limiting** — per-account token bucket (orders/sec).
//!    Prevents a single account from flooding the matching engine
//!    and starving other traders.
//! 2. **Order-size cap** — rejects orders whose quantity exceeds a
//!    configurable maximum. Catches fat-finger quantity errors
//!    before they reach the book.
//! 3. **Fat-finger price band** — rejects limit orders whose price
//!    deviates more than a configurable percentage from the current
//!    mid-price. Prevents accidental trades at absurd prices.
//! 4. **Resting-order cap** — rejects new orders from accounts that
//!    already have too many resting orders. Prevents book spam.
//!
//! All checks are O(1) and allocation-free on the hot path. The
//! rate limiter uses a sliding-window counter per account; the
//! resting-order counter is maintained by the matching server
//! (incremented on rest, decremented on cancel/fill).
//!
//! # Design notes
//!
//! The risk engine is intentionally simple and conservative. It
//! rejects on any doubt — a false positive (rejecting a valid order)
//! is far less damaging than a false negative (letting a fat-finger
//! trade through). The thresholds are configurable at construction
//! time and can be tuned per-market or per-account in future
//! versions.

use std::collections::{HashMap, VecDeque};

use primitives::Address;

use crate::protocol::RejectReason;

/// A risk-control decision returned by [`RiskEngine::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskDecision {
    /// The order passed all risk checks.
    Allow,
    /// The order was rejected; the [`RejectReason`] explains why.
    Reject(RejectReason),
}

impl RiskDecision {
    /// Returns `true` if the decision is `Allow`.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the decision is `Reject`.
    #[must_use]
    pub const fn is_reject(&self) -> bool {
        matches!(self, Self::Reject(_))
    }
}

/// Configuration for the risk engine. All thresholds are per-account
/// unless otherwise noted.
#[derive(Debug, Clone, Copy)]
pub struct RiskConfig {
    /// Maximum orders per second per account. 0 = unlimited.
    pub max_orders_per_second: u64,
    /// Maximum order quantity (in raw qty units, scale-6). 0 = unlimited.
    pub max_order_qty: u64,
    /// Maximum price deviation from mid, in basis points
    /// (e.g. 1000 = 10%). 0 = no price-band check.
    pub max_price_deviation_bps: u64,
    /// Maximum resting orders per account. 0 = unlimited.
    pub max_resting_per_account: u32,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            // 100 orders/sec is generous for a human trader; HFT
            // clients can request a higher limit.
            max_orders_per_second: 100,
            // 1_000_000 qty units = 1 base unit (scale-6). Large
            // enough for normal trading, small enough to catch
            // fat-finger quantities.
            max_order_qty: 1_000_000_000,
            // 10% price band — rejects orders more than 10% from mid.
            max_price_deviation_bps: 1_000,
            // 1000 resting orders per account — prevents book spam.
            max_resting_per_account: 1_000,
        }
    }
}

/// A per-account rate limiter using a sliding-window counter.
///
/// Tracks the timestamps (in milliseconds) of recent order
/// submissions. When the count of timestamps within the last
/// `window_ms` exceeds `max_orders_per_second`, the next order is
/// rejected.
///
/// The window is cleaned lazily on each `check` call — old entries
/// are popped from the front of the deque. This keeps the data
/// structure bounded and O(1) amortized.
pub struct RateLimiter {
    /// Maximum orders within the sliding window.
    max_per_window: u64,
    /// The sliding window length in milliseconds (always 1000 for
    /// "per second", but parameterized for flexibility).
    window_ms: u64,
    /// Per-account deque of order timestamps (ms).
    recent: HashMap<[u8; 20], VecDeque<u64>>,
}

impl RateLimiter {
    /// Create a rate limiter with the given max orders per second.
    #[must_use]
    pub fn new(max_per_second: u64) -> Self {
        Self { max_per_window: max_per_second, window_ms: 1_000, recent: HashMap::new() }
    }

    /// Check if an order from `addr` at timestamp `now_ms` is within
    /// the rate limit. If allowed, the timestamp is recorded.
    ///
    /// Returns `true` if the order is allowed, `false` if rate-limited.
    pub fn check(&mut self, addr: &Address, now_ms: u64) -> bool {
        if self.max_per_window == 0 {
            return true; // unlimited
        }
        let deque = self.recent.entry(addr.0).or_default();
        // Evict entries older than the window.
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while deque.front().is_some_and(|&t| t < cutoff) {
            deque.pop_front();
        }
        if u64::try_from(deque.len()).unwrap_or(u64::MAX) >= self.max_per_window {
            return false;
        }
        deque.push_back(now_ms);
        true
    }
}

/// The risk engine — a collection of pre-trade risk controls.
pub struct RiskEngine {
    /// Configuration (thresholds).
    config: RiskConfig,
    /// Per-account rate limiter.
    rate_limiter: RateLimiter,
    /// Per-account resting-order counts (maintained by the matching
    /// server via `inc_resting` / `dec_resting`).
    resting_counts: HashMap<[u8; 20], u32>,
}

impl RiskEngine {
    /// Create a risk engine with the given configuration.
    #[must_use]
    pub fn new(config: RiskConfig) -> Self {
        let max_per_sec = config.max_orders_per_second;
        Self { config, rate_limiter: RateLimiter::new(max_per_sec), resting_counts: HashMap::new() }
    }

    /// Create a risk engine with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(RiskConfig::default())
    }

    /// Run all risk checks for a new order. Returns `Allow` or
    /// `Reject(reason)`. The `now_ms` parameter is the current
    /// timestamp in milliseconds (used for rate limiting). The
    /// `mid_price` is the current mid-price (0 if no mid available,
    /// in which case the price-band check is skipped). The
    /// `order_price` and `order_qty` are the order's limit price
    /// and quantity.
    ///
    /// This is called *before* the balance check in `submit_order`.
    /// If any check fails, the order is rejected immediately — no
    /// balance is reserved, no engine placement is attempted.
    pub fn check(
        &mut self,
        addr: &Address,
        now_ms: u64,
        order_price: u64,
        order_qty: u64,
        mid_price: u64,
    ) -> RiskDecision {
        // 1. Rate limit.
        if !self.rate_limiter.check(addr, now_ms) {
            return RiskDecision::Reject(RejectReason::RateLimited);
        }

        // 2. Order-size cap.
        if self.config.max_order_qty > 0 && order_qty > self.config.max_order_qty {
            return RiskDecision::Reject(RejectReason::OrderTooLarge);
        }

        // 3. Fat-finger price band.
        if self.config.max_price_deviation_bps > 0 && mid_price > 0 && order_price > 0 {
            // deviation = |order_price - mid| / mid * 10_000
            let diff = order_price.abs_diff(mid_price);
            // Use u128 to avoid overflow: diff * 10_000 vs mid * bps.
            let deviation_bps = u128::from(diff) * 10_000 / u128::from(mid_price);
            if deviation_bps > u128::from(self.config.max_price_deviation_bps) {
                return RiskDecision::Reject(RejectReason::FatFinger);
            }
        }

        // 4. Resting-order cap.
        if self.config.max_resting_per_account > 0 {
            let count = self.resting_counts.get(&addr.0).copied().unwrap_or(0);
            if count >= self.config.max_resting_per_account {
                return RiskDecision::Reject(RejectReason::TooManyResting);
            }
        }

        RiskDecision::Allow
    }

    /// Increment the resting-order count for an account. Called by
    /// the matching server when an order rests on the book.
    pub fn inc_resting(&mut self, addr: &Address) {
        self.resting_counts.entry(addr.0).and_modify(|c| *c = c.saturating_add(1)).or_insert(1);
    }

    /// Decrement the resting-order count for an account. Called by
    /// the matching server when a resting order is canceled or
    /// fully filled.
    pub fn dec_resting(&mut self, addr: &Address) {
        if let Some(c) = self.resting_counts.get_mut(&addr.0) {
            *c = c.saturating_sub(1);
        }
    }

    /// Get the current resting-order count for an account.
    #[must_use]
    pub fn resting_count(&self, addr: &Address) -> u32 {
        self.resting_counts.get(&addr.0).copied().unwrap_or(0)
    }
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address([byte; 20])
    }

    #[test]
    fn rate_limiter_allows_under_limit() {
        let mut rl = RateLimiter::new(5);
        let a = addr(1);
        // 5 orders at t=0 should all be allowed.
        for _ in 0..5 {
            assert!(rl.check(&a, 0), "orders under limit should be allowed");
        }
    }

    #[test]
    fn rate_limiter_rejects_over_limit() {
        let mut rl = RateLimiter::new(3);
        let a = addr(1);
        for _ in 0..3 {
            assert!(rl.check(&a, 0), "first 3 orders allowed");
        }
        // 4th order at the same timestamp should be rejected.
        assert!(!rl.check(&a, 0), "4th order should be rate-limited");
    }

    #[test]
    fn rate_limiter_window_slides() {
        let mut rl = RateLimiter::new(3);
        let a = addr(1);
        // 3 orders at t=0.
        for _ in 0..3 {
            assert!(rl.check(&a, 0));
        }
        // 4th at t=1001 (window of 1000ms has fully slid past t=0)
        // should be allowed.
        assert!(rl.check(&a, 1_001), "order after window slide should be allowed");
    }

    #[test]
    fn rate_limiter_unlimited_when_zero() {
        let mut rl = RateLimiter::new(0);
        let a = addr(1);
        for _ in 0..100 {
            assert!(rl.check(&a, 0), "unlimited rate limiter should always allow");
        }
    }

    #[test]
    fn rate_limiter_independent_per_account() {
        let mut rl = RateLimiter::new(2);
        let a = addr(1);
        let b = addr(2);
        assert!(rl.check(&a, 0));
        assert!(rl.check(&a, 0));
        assert!(!rl.check(&a, 0), "account a is rate-limited");
        // Account b is independent.
        assert!(rl.check(&b, 0), "account b is not rate-limited");
    }

    #[test]
    fn risk_engine_rejects_order_too_large() {
        let mut engine = RiskEngine::new(RiskConfig {
            max_orders_per_second: 0, // unlimited
            max_order_qty: 1_000,
            max_price_deviation_bps: 0,
            max_resting_per_account: 0,
        });
        let decision = engine.check(&addr(1), 0, 1_000_000_000, 2_000, 1_000_000_000);
        assert!(decision.is_reject());
        match decision {
            RiskDecision::Reject(RejectReason::OrderTooLarge) => {}
            other => panic!("expected OrderTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn risk_engine_rejects_fat_finger() {
        let mut engine = RiskEngine::new(RiskConfig {
            max_orders_per_second: 0,
            max_order_qty: 0,
            max_price_deviation_bps: 1_000, // 10%
            max_resting_per_account: 0,
        });
        // Mid = 1.5B, order at 2.0B → deviation = 33% > 10%.
        let decision = engine.check(&addr(1), 0, 2_000_000_000, 1_000, 1_500_000_000);
        assert!(decision.is_reject());
        match decision {
            RiskDecision::Reject(RejectReason::FatFinger) => {}
            other => panic!("expected FatFinger, got {other:?}"),
        }
    }

    #[test]
    fn risk_engine_allows_within_price_band() {
        let mut engine = RiskEngine::new(RiskConfig {
            max_orders_per_second: 0,
            max_order_qty: 0,
            max_price_deviation_bps: 1_000, // 10%
            max_resting_per_account: 0,
        });
        // Mid = 1.5B, order at 1.55B → deviation = 3.3% < 10%.
        let decision = engine.check(&addr(1), 0, 1_550_000_000, 1_000, 1_500_000_000);
        assert!(decision.is_allow(), "order within band should be allowed");
    }

    #[test]
    fn risk_engine_skips_price_band_when_no_mid() {
        let mut engine = RiskEngine::new(RiskConfig {
            max_orders_per_second: 0,
            max_order_qty: 0,
            max_price_deviation_bps: 1_000,
            max_resting_per_account: 0,
        });
        // mid_price = 0 → skip price-band check.
        let decision = engine.check(&addr(1), 0, 999_999_999_999, 1_000, 0);
        assert!(decision.is_allow(), "should allow when no mid price available");
    }

    #[test]
    fn risk_engine_rejects_too_many_resting() {
        let mut engine = RiskEngine::new(RiskConfig {
            max_orders_per_second: 0,
            max_order_qty: 0,
            max_price_deviation_bps: 0,
            max_resting_per_account: 3,
        });
        let a = addr(1);
        engine.inc_resting(&a);
        engine.inc_resting(&a);
        engine.inc_resting(&a);
        // Now at 3 resting — next order should be rejected.
        let decision = engine.check(&a, 0, 1_500_000_000, 1_000, 1_500_000_000);
        assert!(decision.is_reject());
        match decision {
            RiskDecision::Reject(RejectReason::TooManyResting) => {}
            other => panic!("expected TooManyResting, got {other:?}"),
        }
    }

    #[test]
    fn risk_engine_dec_resting_on_cancel() {
        let mut engine = RiskEngine::new(RiskConfig::default());
        let a = addr(1);
        engine.inc_resting(&a);
        engine.inc_resting(&a);
        assert_eq!(engine.resting_count(&a), 2);
        engine.dec_resting(&a);
        assert_eq!(engine.resting_count(&a), 1);
    }

    #[test]
    fn risk_engine_allows_normal_order() {
        let mut engine = RiskEngine::with_defaults();
        let decision = engine.check(&addr(1), 0, 1_500_000_000, 1_000, 1_500_000_000);
        assert!(decision.is_allow(), "normal order should pass all checks");
    }

    #[test]
    fn risk_engine_rejects_rate_limited() {
        let mut engine = RiskEngine::new(RiskConfig {
            max_orders_per_second: 2,
            max_order_qty: 0,
            max_price_deviation_bps: 0,
            max_resting_per_account: 0,
        });
        let a = addr(1);
        assert!(engine.check(&a, 0, 1_500_000_000, 1_000, 1_500_000_000).is_allow());
        assert!(engine.check(&a, 0, 1_500_000_000, 1_000, 1_500_000_000).is_allow());
        // Third order at the same timestamp → rate-limited.
        let decision = engine.check(&a, 0, 1_500_000_000, 1_000, 1_500_000_000);
        assert!(decision.is_reject());
        match decision {
            RiskDecision::Reject(RejectReason::RateLimited) => {}
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }
}
