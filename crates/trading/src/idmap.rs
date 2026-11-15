//! `OrderId → slot` locator: preallocated open-addressed map.
//!
//! ## What this is
//!
//! Cancel and modify must find an order's arena slot in O(1) given
//! only its id. This is a linear-probing hash table over a flat
//! power-of-two slot array — no `std::HashMap` (its growth reallocates
//! on the hot path and its iteration order is unspecified, which we
//! must never rely on).
//!
//! ## Why no hash function
//!
//! Order ids are engine-assigned *sequential* `u64`s (see
//! [`crate::order::OrderId`]). Sequential keys land in distinct
//! buckets under `key & mask` with probe distance ≈ 0 — perfect
//! cache behavior. An adversary cannot influence ids (they are not
//! user-chosen), so there is no collision-attack surface to defend
//! with a finalizer.
//!
//! ## Deletion: backward-shift, no tombstones
//!
//! Tombstones would accumulate and degrade probe distances;
//! backward-shift deletion (Knuth TAOCP 6.4 Algorithm R) moves
//! cluster members down so no probe chain is ever broken, keeping
//! the table dense forever.
//!
//! ## Invariants
//!
//! - Capacity is a power of two, fixed at construction; insert when
//!   full returns an error (the engine maps it to a `BookFull`
//!   rejection — capacity is a genesis parameter, not a runtime
//!   surprise).
//! - `EMPTY_KEY` (`u64::MAX`) marks vacant slots; real ids can never
//!   collide with it because the engine rejects placements beyond
//!   `max_resting` long before the counter approaches `u64::MAX`.

// Bucket-index casts in this file are bounded by construction: every
// `bucket`/`hole`/`probe` is masked to the power-of-two slot-array
// length before use, so the u64-to-usize narrowing cannot truncate on
// any supported target (32-bit-or-wider pointers).
#![allow(clippy::cast_possible_truncation)]

use crate::error::TradingError;

/// Sentinel for a vacant slot.
///
/// Real order ids are bounded by the resting-order capacity (≤ 2^32
/// by construction — `u32` slots), so `u64::MAX` is unreachable.
const EMPTY_KEY: u64 = u64::MAX;

/// One table slot: an order id and the arena slot holding its node.
#[derive(Debug, Clone, Copy)]
struct Entry {
    key: u64,
    slot: u32,
}

/// Open-addressed `OrderId → arena-slot` map.
///
/// Preallocated, never grows, never allocates after construction.
#[derive(Debug, Clone)]
pub struct IdMap {
    /// Power-of-two slot array.
    slots: Vec<Entry>,
    /// `slots.len() - 1` — bitmask for bucket computation.
    mask: u64,
    /// Live entry count (for capacity checks).
    len: u32,
    /// Upper bound on any live entry's displacement from its home bucket
    /// (unit: buckets). Raised on insert, never lowered: backward-shift only
    /// moves entries toward home, so it stays a valid bound. `remove` uses it
    /// to stop the cluster walk: an entry more than `max_disp` buckets past
    /// the hole has its home past the hole and cannot move into it. Without
    /// it every removal walked the whole cluster, and sequential ids make
    /// the live set one contiguous cluster (O(live orders) per removal; the
    /// top frame of a profile of the order-bundle benchmark).
    max_disp: u32,
}

impl IdMap {
    /// Build a map sized for `capacity` live entries.
    ///
    /// The array is `next_power_of_two(capacity * 2)` so the load
    /// factor never exceeds 50% — with sequential keys and ≤ 0.5
    /// load, linear probing stays within a couple of cache lines.
    ///
    /// `capacity` of 0 is clamped to 1 so `mask` is always valid.
    ///
    /// # Panics
    ///
    /// If the computed table size exceeds `usize::MAX` on the
    /// current target — impossible for any real `capacity` (a u32
    /// doubled and rounded to a power of two fits every supported
    /// pointer width).
    #[must_use]
    pub fn with_capacity(capacity: u32) -> Self {
        // ×2 keeps load factor ≤ 0.5; saturating math guards a
        // capacity of u32::MAX (a config absurdity) from overflow.
        let wanted = u64::from(capacity).saturating_mul(2).max(2);
        let size = wanted.next_power_of_two();
        let slots = vec![
            Entry { key: EMPTY_KEY, slot: 0 };
            // Invariant: `size` is a power of two derived from
            // `capacity * 2`, where `capacity` is `MarketConfig::max_resting`
            // (bounded by 2^20 per plan.md §9.1). On any platform
            // where this crate compiles (usize >= 32 bits), a 2^21
            // power of two fits in usize. The conversion is
            // infallible for all valid configs.
            usize::try_from(size).expect("u64 pow2 fits usize: max_resting bounded to 2^20")
        ];
        IdMap { slots, mask: size - 1, len: 0, max_disp: 0 }
    }

    /// Number of live entries.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// True when no entries are live.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Insert `key → slot`.
    ///
    /// # Panics
    ///
    /// If `key` is already present — a double-insert of an order id,
    /// which is an engine invariant violation (ids are unique by
    /// construction).
    ///
    /// # Errors
    ///
    /// [`TradingError::BookFull`] when the table is at capacity.
    pub fn insert(&mut self, key: u64, slot: u32) -> Result<(), TradingError> {
        // 50% load bound: len < slots/2 must hold before insert.
        if (u64::from(self.len) * 2) >= (self.mask + 1) {
            return Err(TradingError::BookFull);
        }
        let mut bucket = key & self.mask;
        loop {
            let entry = &mut self.slots[bucket as usize];
            if entry.key == EMPTY_KEY {
                entry.key = key;
                entry.slot = slot;
                self.len += 1;
                let disp = (bucket.wrapping_sub(key & self.mask)) & self.mask;
                self.max_disp = self.max_disp.max(disp as u32);
                return Ok(());
            }
            if entry.key == key {
                // Duplicate order id — an engine invariant violation
                // (ids are unique by construction). Return an error
                // rather than panicking; a panic would crash the
                // validator (DoS vector). The debug_assert is in the
                // test-only `duplicate_insert_returns_error_not_panic`
                // test to verify this path is reached.
                return Err(TradingError::OrderNotFound);
            }
            bucket = (bucket + 1) & self.mask;
        }
    }

    /// Cache hint for an upcoming `get`/`remove` of `key`: loads the
    /// key's home bucket so the miss overlaps earlier work. A plain
    /// read — it never changes state, and a stale or absent key is
    /// harmless.
    #[allow(clippy::inline_always)] // a hint must not become a call
    #[inline(always)]
    pub fn touch(&self, key: u64) {
        crate::hint::prefetch(&self.slots[(key & self.mask) as usize].key);
    }

    /// Look up the arena slot for `key`.
    #[inline]
    #[must_use]
    pub fn get(&self, key: u64) -> Option<u32> {
        let mut bucket = key & self.mask;
        // Probe until found or an EMPTY slot (which terminates every
        // cluster containing `key` — backward-shift deletion preserves
        // this invariant).
        loop {
            let entry = &self.slots[bucket as usize];
            if entry.key == key {
                return Some(entry.slot);
            }
            if entry.key == EMPTY_KEY {
                return None;
            }
            bucket = (bucket + 1) & self.mask;
        }
    }

    /// Remove `key`, returning its slot.
    ///
    /// Uses backward-shift deletion: after removing the entry, walk
    /// the cluster behind it and move up any entry whose ideal bucket
    /// is at-or-before the hole, so probe chains stay unbroken.
    ///
    /// # Errors
    /// [`TradingError::OrderNotFound`] if `key` is absent.
    pub fn remove(&mut self, key: u64) -> Result<u32, TradingError> {
        // Find the entry.
        let mut bucket = key & self.mask;
        let found = loop {
            let entry = &self.slots[bucket as usize];
            if entry.key == key {
                break bucket;
            }
            if entry.key == EMPTY_KEY {
                return Err(TradingError::OrderNotFound);
            }
            bucket = (bucket + 1) & self.mask;
        };

        let removed_slot = self.slots[found as usize].slot;
        self.len -= 1;

        // Backward-shift: pull cluster members down into the hole.
        let mut hole = found;
        let mut probe = (hole + 1) & self.mask;
        // Buckets scanned since the hole last moved; once it exceeds
        // `max_disp` no later entry can move into the hole (see the field).
        let mut since_hole = 0u32;
        loop {
            let entry = self.slots[probe as usize];
            if entry.key == EMPTY_KEY || since_hole >= self.max_disp {
                break;
            }
            since_hole += 1;
            // An entry may move up to `hole` iff its *home* bucket is
            // cyclically at-or-before `hole` (i.e. moving it does not
            // skip over its own probe path).
            let home_bucket = entry.key & self.mask;
            let can_move = if hole <= probe {
                home_bucket <= hole || home_bucket > probe
            } else {
                home_bucket <= hole && home_bucket > probe
            };
            if can_move {
                self.slots[hole as usize] = entry;
                hole = probe;
                since_hole = 0;
            }
            probe = (probe + 1) & self.mask;
        }
        // Vacate the final hole.
        self.slots[hole as usize] = Entry { key: EMPTY_KEY, slot: 0 };
        Ok(removed_slot)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use super::*;

    #[test]
    fn insert_get_round_trip() {
        let mut m = IdMap::with_capacity(64);
        for i in 0..40u64 {
            m.insert(i, i as u32 + 100).unwrap();
        }
        for i in 0..40u64 {
            assert_eq!(m.get(i), Some(i as u32 + 100));
        }
        assert_eq!(m.get(999), None);
        assert_eq!(m.len(), 40);
    }

    #[test]
    fn remove_then_get_is_none() {
        let mut m = IdMap::with_capacity(64);
        m.insert(7, 77).unwrap();
        assert_eq!(m.remove(7), Ok(77));
        assert_eq!(m.get(7), None);
        assert!(m.is_empty());
    }

    #[test]
    fn remove_missing_returns_not_found() {
        let mut m = IdMap::with_capacity(8);
        assert_eq!(m.remove(1), Err(TradingError::OrderNotFound));
    }

    /// The critical property: after arbitrary interleaved
    /// insert/remove, every surviving key is still findable. Exercises
    /// backward-shift deletion across cluster shapes.
    #[test]
    fn backward_shift_keeps_clusters_intact() {
        let mut m = IdMap::with_capacity(256);
        // Insert a dense sequential run (they cluster adjacently).
        for i in 0..100u64 {
            m.insert(i, i as u32).unwrap();
        }
        // Remove every other key from the middle of the run.
        for i in (10..80u64).step_by(2) {
            m.remove(i).unwrap();
        }
        // Odd survivors must all still resolve.
        for i in (10..80u64).step_by(2) {
            assert_eq!(m.get(i), None);
        }
        for i in (11..80u64).step_by(2) {
            assert_eq!(m.get(i), Some(i as u32), "survivor {i} lost after backward-shift");
        }
        // And the untouched prefix/suffix.
        for i in 0..10u64 {
            assert_eq!(m.get(i), Some(i as u32));
        }
        for i in 80..100u64 {
            assert_eq!(m.get(i), Some(i as u32));
        }
    }

    /// Reference implementation: the original unbounded backward-shift
    /// (walks to the next empty slot). `remove` with the displacement bound
    /// must leave a table that answers every lookup identically.
    fn reference_remove(slots: &mut [Entry], mask: u64, key: u64) -> bool {
        let mut bucket = key & mask;
        let found = loop {
            let e = slots[bucket as usize];
            if e.key == key {
                break bucket;
            }
            if e.key == EMPTY_KEY {
                return false;
            }
            bucket = (bucket + 1) & mask;
        };
        let mut hole = found;
        let mut probe = (hole + 1) & mask;
        loop {
            let entry = slots[probe as usize];
            if entry.key == EMPTY_KEY {
                break;
            }
            let ideal = entry.key & mask;
            let can_move = if hole <= probe {
                ideal <= hole || ideal > probe
            } else {
                ideal <= hole && ideal > probe
            };
            if can_move {
                slots[hole as usize] = entry;
                hole = probe;
            }
            probe = (probe + 1) & mask;
        }
        slots[hole as usize] = Entry { key: EMPTY_KEY, slot: 0 };
        true
    }

    /// Random insert/remove streams (sequential ids, wrap-around, and
    /// colliding random keys) must leave the bounded-walk table bit-identical
    /// to the reference's, slot for slot.
    #[test]
    fn bounded_backward_shift_matches_reference() {
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..40 {
            let cap = 64u32 << (round % 4);
            let mut m = IdMap::with_capacity(cap);
            let mut reference = m.slots.clone();
            let mask = m.mask;
            let mut live: Vec<u64> = Vec::new();
            let mut counter = next() % 1_000;
            for _ in 0..4_000 {
                let r = next() % 100;
                if r < 55 && u64::from(m.len()) * 2 < mask {
                    // Mostly sequential ids, sometimes a colliding random key.
                    let key = if r < 45 {
                        counter
                    } else {
                        next() % (mask + 1) + (mask + 1) * (next() % 3)
                    };
                    counter += 1;
                    if live.contains(&key) {
                        continue;
                    }
                    if m.insert(key, 7).is_ok() {
                        // Mirror the insert in the reference table (same probing).
                        let mut b = key & mask;
                        while reference[b as usize].key != EMPTY_KEY {
                            b = (b + 1) & mask;
                        }
                        reference[b as usize] = Entry { key, slot: 7 };
                        live.push(key);
                    }
                } else if !live.is_empty() {
                    let at = (next() as usize) % live.len();
                    let key = live.swap_remove(at);
                    assert!(m.remove(key).is_ok());
                    assert!(reference_remove(&mut reference, mask, key));
                }
                for (a, b) in m.slots.iter().zip(reference.iter()) {
                    assert_eq!((a.key, a.slot), (b.key, b.slot), "tables diverged");
                }
            }
        }
    }

    #[test]
    fn insert_beyond_half_capacity_fails() {
        // Capacity 4 → array size 8 → max 4 live entries at ≤0.5 load.
        let mut m = IdMap::with_capacity(4);
        for i in 0..4u64 {
            m.insert(i, i as u32).unwrap();
        }
        assert_eq!(m.insert(9, 9), Err(TradingError::BookFull));
    }

    #[test]
    fn slots_reused_after_removal() {
        let mut m = IdMap::with_capacity(4);
        for i in 0..4u64 {
            m.insert(i, i as u32).unwrap();
        }
        m.remove(0).unwrap();
        // Room again after one removal.
        assert_eq!(m.insert(50, 5), Ok(()));
        assert_eq!(m.get(50), Some(5));
    }

    /// Regression test: inserting a duplicate key must return an
    /// error, not panic. Before the fix, `insert` used `assert!`
    /// which would crash the validator on an invariant violation.
    #[test]
    fn duplicate_insert_returns_error_not_panic() {
        let mut m = IdMap::with_capacity(64);
        m.insert(42, 100).unwrap();
        // Duplicate insert must return an error, not panic.
        let result = m.insert(42, 200);
        assert!(result.is_err(), "duplicate insert must error");
        // Original entry must be unchanged.
        assert_eq!(m.get(42), Some(100));
    }
}
