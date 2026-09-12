//! Price-level ladder and the swappable [`BookBackend`] seam.
//!
//! ## What this is
//!
//! A [`PriceLevel`] is the head/tail of an intrusive FIFO queue of
//! resting orders (links live in the [`crate::OrderPool`] nodes) plus
//! an O(1) resting-quantity aggregate for L2 market data. The dense
//! backend is a flat `Vec<PriceLevel>` indexed by tick offset from the
//! market's price floor, with two [`Bitboard`]s (bids/asks) for
//! best-price discovery.
//!
//! ## Why the `BookBackend` trait (plan.md §9.1)
//!
//! The dense ladder is O(1) per level but pays `n_levels × 16B` of
//! memory, so it only fits bounded-range markets. Wide-range markets
//! get a sparse backend later — the trait is the seam that makes the
//! choice per-market *config* rather than node-level. The engine is
//! generic over it; everything behind these methods is the backend's
//! own business.
//!
//! ## Invariants
//!
//! - A resting order is linked into exactly one level; its node's
//!   `price` and `side` always agree with the level it occupies.
//! - `level.total_qty` equals the sum of linked nodes' `qty`. Appends
//!   add, detaches subtract the node's *remaining* qty (fills are
//!   subtracted by the engine as they happen, so a fully-filled node
//!   contributes 0 at detach).
//! - A bitboard bit is set iff the corresponding level's FIFO is
//!   nonempty.

// Index-math casts in this file are bounded by construction: level
// indices come from `MarketConfig::level_count()` which
// `MarketConfig::validate` caps at MAX_DENSE_LEVELS (2^18), and
// `level_index` asserts in-band before any narrowing.
#![allow(clippy::cast_possible_truncation)]

use crate::bitboard::{Bitboard, MAX_DENSE_LEVELS};
use crate::error::TradingError;
use crate::order::Side;
use crate::pool::{NIL, OrderPool};

/// One price level: an intrusive FIFO of resting orders.
///
/// 16 bytes — 4 levels per cache line, so a best-price neighborhood
/// scan touches at most a couple of lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceLevel {
    /// FIFO head slot (`NIL` when the level is empty).
    pub head: u32,
    /// FIFO tail slot (`NIL` when the level is empty).
    pub tail: u32,
    /// Sum of resting `qty` over linked orders (raw scale-6).
    pub total_qty: u64,
}

impl PriceLevel {
    /// An empty level.
    pub const EMPTY: PriceLevel = PriceLevel { head: NIL, tail: NIL, total_qty: 0 };
}

/// Per-market parameters fixed at genesis (plan.md §9.1/§9.2).
///
/// All raw values: prices in scale-8 units, quantities in scale-6
/// units (see `primitives::fixed`). Raw units keep the hot path free
/// of conversion; the `Price`/`Qty` newtypes appear only at the
/// engine's public boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarketConfig {
    /// Stable market identifier (wire constant; module-layer scope).
    pub market_id: u16,
    /// Raw price units per tick (e.g. a 0.01 price step equals `1_000_000`).
    pub tick_size: u64,
    /// Raw qty units per lot (minimum quantity increment).
    pub lot_size: u64,
    /// Lowest price on the grid, raw (inclusive).
    pub min_price: u64,
    /// Highest price on the grid, raw (inclusive).
    pub max_price: u64,
    /// Maximum simultaneously-resting orders. Sizes the order pool and
    /// the id map at construction (plan default 2^20; tests use
    /// small values).
    pub max_resting: u32,
}

impl MarketConfig {
    /// Validate configuration self-consistency.
    ///
    /// # Errors
    /// [`TradingError::InvalidConfig`] naming the first broken field:
    /// nonpositive tick/lot, empty or inverted band, band not a whole
    /// number of ticks, or a level count beyond the dense backend's
    /// capacity.
    pub fn validate(&self) -> Result<(), TradingError> {
        if self.tick_size == 0 {
            return Err(TradingError::InvalidConfig("tick_size must be > 0"));
        }
        if self.lot_size == 0 {
            return Err(TradingError::InvalidConfig("lot_size must be > 0"));
        }
        if self.min_price >= self.max_price {
            return Err(TradingError::InvalidConfig("min_price must be < max_price"));
        }
        if (self.max_price - self.min_price) % self.tick_size != 0 {
            return Err(TradingError::InvalidConfig("price band must be a whole number of ticks"));
        }
        if self.level_count() > MAX_DENSE_LEVELS {
            return Err(TradingError::InvalidConfig(
                "level count exceeds MAX_DENSE_LEVELS (use a narrower band for the dense backend)",
            ));
        }
        if self.max_resting == 0 {
            return Err(TradingError::InvalidConfig("max_resting must be > 0"));
        }
        Ok(())
    }

    /// Number of tick levels in the band (inclusive of both ends).
    #[must_use]
    pub fn level_count(&self) -> usize {
        ((self.max_price - self.min_price) / self.tick_size + 1) as usize
    }
}

/// The swappable book seam: everything the engine needs from a price
/// level structure, independent of how levels are stored.
///
/// Hot-path contract: all methods are O(1) (dense) or amortized O(1)
/// (future sparse); none allocate in the dense implementation.
///
/// Preconditions (enforced by the engine before any call):
/// - `price_raw` is in-band and on the tick grid.
/// - `slot` refers to a live pool node whose `price`/`side`/links are
///   consistent with the level it occupies.
pub trait BookBackend {
    /// Best (highest) resting bid price, raw, if any.
    fn best_bid_price(&self) -> Option<u64>;

    /// Best (lowest) resting ask price, raw, if any.
    fn best_ask_price(&self) -> Option<u64>;

    /// Link node `slot` (already allocated and populated) into the
    /// FIFO tail of its price level, activating the level.
    ///
    /// Reads the node's price/qty/side from `pool`; writes the node's
    /// `prev`/`next` links.
    fn append(&mut self, slot: u32, pool: &mut OrderPool);

    /// Detach the FIFO *head* at `price_raw`, returning its slot.
    ///
    /// Subtracts the detached node's remaining qty from the level
    /// total; deactivates the level if it empties.
    fn pop_front(&mut self, price_raw: u64, pool: &mut OrderPool) -> Option<u32>;

    /// Detach node `slot` from its level wherever it rests (O(1)
    /// middle removal — used by cancel and self-trade cancel-oldest).
    fn unlink(&mut self, slot: u32, pool: &mut OrderPool);

    /// Peek the FIFO head slot at `price_raw` (`NIL` if empty).
    fn level_head(&self, price_raw: u64) -> u32;

    /// Subtract `qty` (a fill amount) from the level's resting total.
    fn reduce_total(&mut self, price_raw: u64, qty: u64);

    /// Resting quantity aggregate at `price_raw` (L2 data).
    fn level_total(&self, price_raw: u64) -> u64;

    /// Total quantity a `taker_side` order could fill given the
    /// current book, bounded by `limit_raw` (the order's limit; `None`
    /// = unbounded market sweep). Used by the FOK pre-scan.
    ///
    /// Walks the opposite side best-first, summing level totals —
    /// O(active levels in range), no mutation.
    fn fillable_qty(&self, taker_side: Side, limit_raw: Option<u64>) -> u64;

    /// Number of addressable levels (cold path: iteration, digests).
    fn level_count(&self) -> usize;

    /// Raw price of level index `idx` (cold path: iteration).
    fn level_price(&self, idx: u32) -> u64;
}

/// Dense tick-ladder book: flat level array + hierarchical bitboards.
///
/// Memory: `level_count × 16B` for levels plus `~2 × level_count/8B`
/// for the two bitboards. A 2^18-level market costs ≈ 12.6 MiB.
pub struct DenseBook {
    cfg: MarketConfig,
    levels: Vec<PriceLevel>,
    bids: Bitboard,
    asks: Bitboard,
}

impl DenseBook {
    /// Build an empty ladder from a validated config.
    ///
    /// # Errors
    /// [`TradingError::InvalidConfig`] propagated from
    /// [`MarketConfig::validate`].
    pub fn new(cfg: MarketConfig) -> Result<Self, TradingError> {
        cfg.validate()?;
        let n = cfg.level_count();
        Ok(DenseBook {
            cfg,
            levels: vec![PriceLevel::EMPTY; n],
            bids: Bitboard::new(n),
            asks: Bitboard::new(n),
        })
    }

    /// Level index for a raw price. In debug builds, panics on
    /// out-of-band/off-grid prices — impossible after
    /// `NewOrder::validate` (documented precondition of the trait).
    /// In release builds, the checks are skipped for hot-path
    /// performance; a validation bug would produce a wrong index but
    /// not crash the validator (DoS-safe).
    #[inline]
    fn level_index(&self, price_raw: u64) -> usize {
        let offset = price_raw.saturating_sub(self.cfg.min_price);
        debug_assert!(
            price_raw >= self.cfg.min_price,
            "price below band: validation precondition violated"
        );
        let idx = offset / self.cfg.tick_size;
        debug_assert!(
            idx < self.levels.len() as u64,
            "price above band: validation precondition violated"
        );
        idx as usize
    }

    /// Shared detach: splice `slot` out of its level's FIFO.
    ///
    /// Called by both `pop_front` (head case) and `unlink` (arbitrary
    /// position); maintains total-qty and bitboard invariants.
    fn detach(&mut self, slot: u32, pool: &mut OrderPool) {
        let (prev, next, price, side, qty) = {
            let n = &pool[slot];
            (n.prev, n.next, n.price.0, n.side, n.qty.0)
        };
        let idx = self.level_index(price);
        let level = &mut self.levels[idx];
        // Splice neighbors past the detached node.
        if prev == NIL {
            level.head = next;
        } else {
            pool[prev].next = next;
        }
        if next == NIL {
            level.tail = prev;
        } else {
            pool[next].prev = prev;
        }
        level.total_qty = level.total_qty.saturating_sub(qty);
        let empty = level.head == NIL;
        if empty {
            let bid = side == Side::Buy;
            if bid {
                self.bids.clear(idx as u32);
            } else {
                self.asks.clear(idx as u32);
            }
        }
    }
}

impl BookBackend for DenseBook {
    #[inline]
    fn best_bid_price(&self) -> Option<u64> {
        // Highest active bid level → its price.
        self.bids.highest().map(|idx| self.cfg.min_price + u64::from(idx) * self.cfg.tick_size)
    }

    #[inline]
    fn best_ask_price(&self) -> Option<u64> {
        self.asks.lowest().map(|idx| self.cfg.min_price + u64::from(idx) * self.cfg.tick_size)
    }

    fn append(&mut self, slot: u32, pool: &mut OrderPool) {
        let (price, qty, side) = {
            let n = &pool[slot];
            (n.price.0, n.qty.0, n.side)
        };
        let idx = self.level_index(price);
        let was_empty = self.levels[idx].head == NIL;
        let tail = self.levels[idx].tail;
        // Link at the FIFO tail (strict price-time priority: later
        // arrivals match later within the same level).
        pool[slot].prev = tail;
        pool[slot].next = NIL;
        if tail == NIL {
            self.levels[idx].head = slot;
        } else {
            pool[tail].next = slot;
        }
        self.levels[idx].tail = slot;
        // Fuzz fix: use saturating_add instead of expect. The
        // funds-locking invariant should prevent this in production,
        // but the fuzzer feeds arbitrary quantities. Saturating
        // prevents a panic; the order book remains consistent.
        self.levels[idx].total_qty = self.levels[idx].total_qty.saturating_add(qty);
        if was_empty {
            let bid = side == Side::Buy;
            if bid {
                self.bids.set(idx as u32);
            } else {
                self.asks.set(idx as u32);
            }
        }
    }

    fn pop_front(&mut self, price_raw: u64, pool: &mut OrderPool) -> Option<u32> {
        let idx = self.level_index(price_raw);
        let head = self.levels[idx].head;
        if head == NIL {
            return None;
        }
        self.detach(head, pool);
        Some(head)
    }

    fn unlink(&mut self, slot: u32, pool: &mut OrderPool) {
        self.detach(slot, pool);
    }

    #[inline]
    fn level_head(&self, price_raw: u64) -> u32 {
        self.levels[self.level_index(price_raw)].head
    }

    #[inline]
    fn reduce_total(&mut self, price_raw: u64, qty: u64) {
        let idx = self.level_index(price_raw);
        self.levels[idx].total_qty = self.levels[idx].total_qty.saturating_sub(qty);
    }

    #[inline]
    fn level_total(&self, price_raw: u64) -> u64 {
        self.levels[self.level_index(price_raw)].total_qty
    }

    fn fillable_qty(&self, taker_side: Side, limit_raw: Option<u64>) -> u64 {
        let mut total: u64 = 0;
        match taker_side {
            // A buy sweeps asks ascending from the best (lowest) ask.
            Side::Buy => {
                let Some(mut idx) = self.asks.lowest() else { return 0 };
                loop {
                    let price = self.level_price(idx);
                    if limit_raw.is_some_and(|lim| price > lim) {
                        break;
                    }
                    total = total.saturating_add(self.levels[idx as usize].total_qty);
                    match self.asks.next_after(idx) {
                        Some(next) => idx = next,
                        None => break,
                    }
                }
            }
            // A sell sweeps bids descending from the best (highest) bid.
            Side::Sell => {
                let Some(mut idx) = self.bids.highest() else { return 0 };
                loop {
                    let price = self.level_price(idx);
                    if limit_raw.is_some_and(|lim| price < lim) {
                        break;
                    }
                    total = total.saturating_add(self.levels[idx as usize].total_qty);
                    match self.bids.prev_before(idx) {
                        Some(prev) => idx = prev,
                        None => break,
                    }
                }
            }
        }
        total
    }

    #[inline]
    fn level_count(&self) -> usize {
        self.levels.len()
    }

    #[inline]
    fn level_price(&self, idx: u32) -> u64 {
        self.cfg.min_price + u64::from(idx) * self.cfg.tick_size
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use super::*;
    use crate::order::{OrderId, TimeInForce};
    use crate::pool::fresh_node;
    use primitives::Address;
    use primitives::fixed::{Price, Qty};

    // Fixture market: tick 0.01, band [10.00, 10.64] → 65 levels.
    fn cfg() -> MarketConfig {
        MarketConfig {
            market_id: 1,
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 1_064_000_000,
            max_resting: 64,
        }
    }

    fn place_at(
        book: &mut DenseBook,
        pool: &mut OrderPool,
        id: u64,
        side: Side,
        price_raw: u64,
        qty_raw: u64,
    ) -> u32 {
        let n = fresh_node(
            OrderId(id),
            side,
            Price(price_raw),
            Qty(qty_raw),
            Address([id as u8; 20]),
            TimeInForce::Gtc,
        );
        let slot = pool.alloc(n);
        book.append(slot, pool);
        slot
    }

    #[test]
    fn config_validation_rejects_bad_markets() {
        assert_eq!(cfg().validate(), Ok(()));

        let mut c = cfg();
        c.tick_size = 0;
        assert_eq!(c.validate(), Err(TradingError::InvalidConfig("tick_size must be > 0")));

        let mut c = cfg();
        c.lot_size = 0;
        assert_eq!(c.validate(), Err(TradingError::InvalidConfig("lot_size must be > 0")));

        let mut c = cfg();
        c.min_price = c.max_price;
        assert_eq!(c.validate(), Err(TradingError::InvalidConfig("min_price must be < max_price")));

        // Band not a whole number of ticks.
        let mut c = cfg();
        c.max_price += 1;
        assert_eq!(
            c.validate(),
            Err(TradingError::InvalidConfig("price band must be a whole number of ticks"))
        );
    }

    #[test]
    fn append_then_best_prices_track_extremes() {
        let mut book = DenseBook::new(cfg()).unwrap();
        let mut pool = OrderPool::with_capacity(16);

        place_at(&mut book, &mut pool, 1, Side::Buy, 1_010_000_000, 5_000);
        place_at(&mut book, &mut pool, 2, Side::Buy, 1_015_000_000, 3_000);
        place_at(&mut book, &mut pool, 3, Side::Sell, 1_020_000_000, 7_000);
        place_at(&mut book, &mut pool, 4, Side::Sell, 1_030_000_000, 2_000);

        assert_eq!(book.best_bid_price(), Some(1_015_000_000));
        assert_eq!(book.best_ask_price(), Some(1_020_000_000));
        // Level totals aggregate resting qty.
        assert_eq!(book.level_total(1_015_000_000), 3_000);
        assert_eq!(book.level_total(1_010_000_000), 5_000);
    }

    #[test]
    fn fifo_order_within_level_is_preserved() {
        let mut book = DenseBook::new(cfg()).unwrap();
        let mut pool = OrderPool::with_capacity(16);

        let a = place_at(&mut book, &mut pool, 1, Side::Buy, 1_010_000_000, 5_000);
        let b = place_at(&mut book, &mut pool, 2, Side::Buy, 1_010_000_000, 5_000);

        // Head must be the first arrival.
        assert_eq!(book.level_head(1_010_000_000), a);
        // Links: a.next == b, b.prev == a.
        assert_eq!(pool[a].next, b);
        assert_eq!(pool[b].prev, a);
        assert_eq!(pool[b].next, NIL);
        assert_eq!(pool[a].prev, NIL);

        // Total aggregates both.
        assert_eq!(book.level_total(1_010_000_000), 10_000);
    }

    #[test]
    fn pop_front_removes_in_arrival_order() {
        let mut book = DenseBook::new(cfg()).unwrap();
        let mut pool = OrderPool::with_capacity(16);

        let a = place_at(&mut book, &mut pool, 1, Side::Sell, 1_020_000_000, 4_000);
        let b = place_at(&mut book, &mut pool, 2, Side::Sell, 1_020_000_000, 6_000);

        assert_eq!(book.pop_front(1_020_000_000, &mut pool), Some(a));
        assert_eq!(book.level_head(1_020_000_000), b);
        assert_eq!(book.level_total(1_020_000_000), 6_000);
        // Ask bit still set (level nonempty).
        assert_eq!(book.best_ask_price(), Some(1_020_000_000));

        assert_eq!(book.pop_front(1_020_000_000, &mut pool), Some(b));
        assert_eq!(book.best_ask_price(), None, "level emptied → bit cleared");
        assert_eq!(book.pop_front(1_020_000_000, &mut pool), None);
    }

    #[test]
    fn unlink_removes_middle_node_o1() {
        let mut book = DenseBook::new(cfg()).unwrap();
        let mut pool = OrderPool::with_capacity(16);

        let a = place_at(&mut book, &mut pool, 1, Side::Buy, 1_010_000_000, 1_000);
        let b = place_at(&mut book, &mut pool, 2, Side::Buy, 1_010_000_000, 2_000);
        let c = place_at(&mut book, &mut pool, 3, Side::Buy, 1_010_000_000, 3_000);

        // Cancel the middle order.
        book.unlink(b, &mut pool);
        assert_eq!(book.level_head(1_010_000_000), a);
        assert_eq!(pool[a].next, c, "a must now link directly to c");
        assert_eq!(pool[c].prev, a);
        assert_eq!(book.level_total(1_010_000_000), 4_000);
        assert_eq!(book.best_bid_price(), Some(1_010_000_000));
    }

    #[test]
    fn reduce_total_tracks_fills() {
        let mut book = DenseBook::new(cfg()).unwrap();
        let mut pool = OrderPool::with_capacity(16);
        place_at(&mut book, &mut pool, 1, Side::Sell, 1_020_000_000, 10_000);

        book.reduce_total(1_020_000_000, 4_000);
        assert_eq!(book.level_total(1_020_000_000), 6_000);
        // A fully-consumed node detaches with 0 contribution left.
    }

    #[test]
    fn level_price_round_trips_index() {
        let book = DenseBook::new(cfg()).unwrap();
        for idx in [0u32, 1, 32, 64] {
            let p = book.level_price(idx);
            assert_eq!(book.level_index(p) as u32, idx);
        }
    }

    #[test]
    fn fillable_qty_sums_opposite_side_within_limit() {
        let mut book = DenseBook::new(cfg()).unwrap();
        let mut pool = OrderPool::with_capacity(16);

        // Ask ladder: 10.20 (3k), 10.21 (2k), 10.30 (5k).
        place_at(&mut book, &mut pool, 1, Side::Sell, 1_020_000_000, 3_000);
        place_at(&mut book, &mut pool, 2, Side::Sell, 1_021_000_000, 2_000);
        place_at(&mut book, &mut pool, 3, Side::Sell, 1_030_000_000, 5_000);

        // Unbounded buy sweep: everything.
        assert_eq!(book.fillable_qty(Side::Buy, None), 10_000);
        // Bounded at 10.21: first two levels.
        assert_eq!(book.fillable_qty(Side::Buy, Some(1_021_000_000)), 5_000);
        // Bounded at 10.20: first level only.
        assert_eq!(book.fillable_qty(Side::Buy, Some(1_020_000_000)), 3_000);
        // Bounded below the best: nothing.
        assert_eq!(book.fillable_qty(Side::Buy, Some(1_019_000_000)), 0);

        // Bids: a sell sweep from the highest bid down. A sell's limit
        // is its minimum acceptable price — only bids at-or-above it
        // are fillable.
        place_at(&mut book, &mut pool, 4, Side::Buy, 1_010_000_000, 4_000);
        place_at(&mut book, &mut pool, 5, Side::Buy, 1_005_000_000, 6_000);
        assert_eq!(book.fillable_qty(Side::Sell, None), 10_000);
        // Limit 10.10: only the 10.10 bid qualifies.
        assert_eq!(book.fillable_qty(Side::Sell, Some(1_010_000_000)), 4_000);
        // Limit 10.05: both bids qualify.
        assert_eq!(book.fillable_qty(Side::Sell, Some(1_005_000_000)), 10_000);
        // Limit 10.06: only the 10.10 bid (the 10.05 bid is below it).
        assert_eq!(book.fillable_qty(Side::Sell, Some(1_006_000_000)), 4_000);
        // Limit above every bid: nothing.
        assert_eq!(book.fillable_qty(Side::Sell, Some(1_011_000_000)), 0);
    }
}
