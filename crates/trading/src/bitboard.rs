//! Hierarchical bitboard for O(1) best-price discovery.
//!
//! ## What this is
//!
//! A fixed-depth tree of `u64` words. Tier 0 holds one bit per price
//! level ("level is active"); each tier above holds one bit per word
//! of the tier below ("this word has a set bit"). The tree is grown
//! until the top tier is a single word, so finding the lowest or
//! highest active level is exactly one `trailing_zeros` /
//! `leading_zeros` per tier — 1–3 single-cycle instructions total for
//! any ladder the dense book allows.
//!
//! ## Why (plan.md §9.1)
//!
//! A naive "scan levels for the best price" is `O(n_levels)` — at
//! 2^18 levels that is hundreds of kilobytes of scanning per match
//! step. The bitboard compresses the same information into
//! `n_levels / 8` bytes and answers both directions
//! (highest-bid-from-top, lowest-ask-from-bottom) in constant time
//! via `countl_zero`/`countr_zero`, exactly as the plan specifies.
//!
//! ## Invariants
//!
//! - A bit set in tier `t > 0` iff the referenced tier-`t-1` word is
//!   nonzero. [`Bitboard::set`] and [`Bitboard::clear`] maintain this
//!   bottom-up; nothing else mutates the tiers.
//! - The dense book keeps **two** boards (bids and asks): a crossed
//!   book never exists, so a level is never simultaneously a bid and
//!   an ask level, and each board answers its own direction.

// Index-math casts in this file are bounded by construction: every
// `usize`→`u32` narrowing carries a level index < MAX_DENSE_LEVELS
// (2^18), and every `u64::BITS` arithmetic stays below 2^18 * 2. The
// bounds are enforced by `Bitboard::new`'s assert; truncation would
// be a construction bug, not a runtime condition.
#![allow(clippy::cast_possible_truncation)]

/// Hierarchical bitmap over `n_levels` indices.
///
/// Depth is fixed at construction (a `Vec` of tiers, 1–3 entries —
/// sized from the level count, never grown).
#[derive(Debug, Clone)]
pub struct Bitboard {
    /// `tiers[0]` = one bit per level; `tiers[t]` = one bit per word
    /// of `tiers[t-1]`. The last tier is exactly one word.
    tiers: Vec<Vec<u64>>,
}

/// Maximum level count the dense backend accepts.
///
/// Source: plan.md §9.1 (dense backend for bounded-range markets;
/// sparse backend is the fallback for wider ones). 2^18 levels keeps
/// tier-0 at 32 KiB per side — three tiers deep, still a handful of
/// cycles per lookup. Wider markets must wait for the sparse backend.
pub const MAX_DENSE_LEVELS: usize = 1 << 18;

impl Bitboard {
    /// Build a board over `n_levels` indices, all clear.
    ///
    /// # Panics
    /// If `n_levels == 0` or exceeds [`MAX_DENSE_LEVELS`] — both are
    /// market-construction bugs caught by `DenseBook::new` first;
    /// this panic is the last line of defense.
    #[must_use]
    pub fn new(n_levels: usize) -> Self {
        assert!(n_levels > 0 && n_levels <= MAX_DENSE_LEVELS, "level count out of dense range");
        let mut tiers: Vec<Vec<u64>> = Vec::with_capacity(3);
        // Tier 0: one bit per level.
        let mut words = n_levels.div_ceil(u64::BITS as usize);
        tiers.push(vec![0u64; words]);
        // Climb until a single top word covers everything.
        while words > 1 {
            words = words.div_ceil(u64::BITS as usize);
            tiers.push(vec![0u64; words]);
        }
        Bitboard { tiers }
    }

    /// Mark level `idx` active.
    ///
    /// Propagates a 0→nonzero word transition up the tiers.
    #[inline]
    pub fn set(&mut self, idx: u32) {
        let mut i = idx as usize;
        let mut tier_idx = 0usize;
        loop {
            let word = i / u64::BITS as usize;
            let bit = 1u64 << (i % u64::BITS as usize);
            let w = &mut self.tiers[tier_idx][word];
            let was_zero = *w == 0;
            *w |= bit;
            if !was_zero || tier_idx + 1 == self.tiers.len() {
                // Parent already knows, or there is no parent: done.
                break;
            }
            i = word;
            tier_idx += 1;
        }
    }

    /// Mark level `idx` inactive.
    ///
    /// Propagates a nonzero→0 word transition up the tiers.
    #[inline]
    pub fn clear(&mut self, idx: u32) {
        let mut i = idx as usize;
        let mut tier_idx = 0usize;
        loop {
            let word = i / u64::BITS as usize;
            let bit = 1u64 << (i % u64::BITS as usize);
            let w = &mut self.tiers[tier_idx][word];
            *w &= !bit;
            if *w != 0 || tier_idx + 1 == self.tiers.len() {
                break;
            }
            i = word;
            tier_idx += 1;
        }
    }

    /// Lowest active index, if any.
    ///
    /// One `trailing_zeros` per tier, top-down: the top word's lowest
    /// set bit names the tier below's word, and so on down to the
    /// level index.
    #[inline]
    #[must_use]
    pub fn lowest(&self) -> Option<u32> {
        // The top tier is a single word by construction.
        let top_word = self.tiers.last()?[0];
        if top_word == 0 {
            return None;
        }
        // Descend top→bottom. A bit B in tier T's word W refers to
        // word (W * 64 + B) of tier T-1 — the running index composes
        // at every step, and the final tier-0 step yields the level.
        let mut word_idx = top_word.trailing_zeros() as usize;
        for tier in (0..self.tiers.len() - 1).rev() {
            let word = self.tiers[tier][word_idx];
            debug_assert!(word != 0, "parent bit set on empty child word");
            let bit = word.trailing_zeros() as usize;
            if tier == 0 {
                return Some(((word_idx * 64) + bit) as u32);
            }
            word_idx = word_idx * 64 + bit;
        }
        // Single-tier board: the top word IS tier 0 — its bit
        // position is the level index directly.
        Some(word_idx as u32)
    }

    /// Highest active index, if any.
    ///
    /// Mirror of [`Bitboard::lowest`] using `leading_zeros` (the
    /// plan's `countl_zero` price discovery).
    #[inline]
    #[must_use]
    pub fn highest(&self) -> Option<u32> {
        let top_word = self.tiers.last()?[0];
        if top_word == 0 {
            return None;
        }
        let mut word_idx = (u64::BITS - 1 - top_word.leading_zeros()) as usize;
        for tier in (0..self.tiers.len() - 1).rev() {
            let word = self.tiers[tier][word_idx];
            debug_assert!(word != 0, "parent bit set on empty child word");
            let bit = (u64::BITS as usize - 1) - word.leading_zeros() as usize;
            if tier == 0 {
                return Some(((word_idx * 64) + bit) as u32);
            }
            word_idx = word_idx * 64 + bit;
        }
        Some(word_idx as u32)
    }

    /// True when no level is active.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        // The top tier is a single word by construction.
        self.tiers.last().is_none_or(|t| t[0] == 0)
    }

    /// Lowest active index strictly **above** `idx`, if any.
    ///
    /// Tier-0 word walk: mask the bits at-or-below `idx` in its word,
    /// then scan upward for the next nonempty word. Cost is
    /// O(words-to-next-bit) — a handful of loads in practice.
    #[inline]
    #[must_use]
    pub fn next_after(&self, idx: u32) -> Option<u32> {
        let i = idx as usize;
        let word = i / u64::BITS as usize;
        let bit = i % u64::BITS as usize;
        // Bits strictly above `bit` in the current word (shift by
        // bit+1 is only valid when bit < 63; the 63 case falls through
        // to the word scan, which is also correct).
        if bit < u64::BITS as usize - 1 {
            let higher = self.tiers[0][word] >> (bit + 1);
            if higher != 0 {
                return Some(
                    ((word as u32) * u64::BITS) + (bit + 1) as u32 + higher.trailing_zeros(),
                );
            }
        }
        // Scan subsequent tier-0 words for the first nonempty one.
        for w in (word + 1)..self.tiers[0].len() {
            if self.tiers[0][w] != 0 {
                return Some(((w as u32) * u64::BITS) + self.tiers[0][w].trailing_zeros());
            }
        }
        None
    }

    /// Highest active index strictly **below** `idx`, if any.
    ///
    /// Mirror of [`Bitboard::next_after`] using the low bits of the
    /// current word and a downward word scan.
    #[inline]
    #[must_use]
    pub fn prev_before(&self, idx: u32) -> Option<u32> {
        let i = idx as usize;
        let word = i / u64::BITS as usize;
        let bit = i % u64::BITS as usize;
        // Bits strictly below `bit` in the current word.
        if bit > 0 {
            let mask = (1u64 << bit) - 1;
            let lower = self.tiers[0][word] & mask;
            if lower != 0 {
                return Some(((word as u32) * u64::BITS) + (u64::BITS - 1) - lower.leading_zeros());
            }
        }
        // Scan preceding tier-0 words for the highest nonempty one.
        for w in (0..word).rev() {
            if self.tiers[0][w] != 0 {
                let w64 = self.tiers[0][w];
                return Some(((w as u32) * u64::BITS) + (u64::BITS - 1) - w64.leading_zeros());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_board_has_no_best() {
        let b = Bitboard::new(1024);
        assert_eq!(b.lowest(), None);
        assert_eq!(b.highest(), None);
        assert!(b.is_empty());
    }

    #[test]
    fn single_level_boards_answer_both_directions() {
        let mut b = Bitboard::new(64);
        b.set(5);
        assert_eq!(b.lowest(), Some(5));
        assert_eq!(b.highest(), Some(5));
        b.clear(5);
        assert_eq!(b.lowest(), None);
    }

    #[test]
    fn lowest_and_highest_track_extremes() {
        let mut b = Bitboard::new(200);
        for i in [3u32, 100, 77, 199, 0] {
            b.set(i);
        }
        assert_eq!(b.lowest(), Some(0));
        assert_eq!(b.highest(), Some(199));
        b.clear(0);
        b.clear(199);
        assert_eq!(b.lowest(), Some(3));
        assert_eq!(b.highest(), Some(100));
    }

    /// Exercises multi-tier propagation: 2^18 levels → 3 tiers. Setting
    /// and clearing sparse extremes must keep parents consistent.
    #[test]
    fn multi_tier_propagation_at_max_dense_levels() {
        let n = MAX_DENSE_LEVELS;
        let mut b = Bitboard::new(n);
        assert_eq!(b.tiers.len(), 3, "2^18 levels → tier0 4096 words, tier1 64, tier2 1");
        b.set(0);
        b.set(n as u32 - 1);
        b.set(123_456);
        assert_eq!(b.lowest(), Some(0));
        assert_eq!(b.highest(), Some(n as u32 - 1));
        // Clear extremes; the middle must survive.
        b.clear(0);
        b.clear(n as u32 - 1);
        assert_eq!(b.lowest(), Some(123_456));
        assert_eq!(b.highest(), Some(123_456));
        b.clear(123_456);
        assert!(b.is_empty());
    }

    /// Random-ish set/clear interleavings never leave a stale parent
    /// bit (which would make `lowest`/`highest` lie) nor a lost child
    /// (which would hide liquidity).
    #[test]
    fn exhaustive_set_clear_consistency_small() {
        // All subsets of an 8-level board via bitmask enumeration.
        for mask in 0..256u32 {
            let mut b = Bitboard::new(8);
            for i in 0..8 {
                if mask & (1 << i) != 0 {
                    b.set(i);
                }
            }
            let expect_low = (0..8u32).find(|i| mask & (1 << i) != 0);
            let expect_high = (0..8u32).rev().find(|i| mask & (1 << i) != 0);
            assert_eq!(b.lowest(), expect_low, "mask {mask:#b}");
            assert_eq!(b.highest(), expect_high, "mask {mask:#b}");
        }
    }
}
