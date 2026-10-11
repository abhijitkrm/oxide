//! Slab-arena order storage with intrusive doubly-linked FIFO links.
//!
//! ## What this is
//!
//! Every resting order lives in one flat `Vec` of 64-byte,
//! cache-line-aligned [`OrderNode`]s. Price levels do not own heap
//! allocations — they own *indices* into this arena, and the nodes
//! themselves carry the `prev`/`next` links of the level's FIFO queue
//! (an intrusive linked list). Cancellation unlinks in O(1) by
//! splicing `prev ↔ next`; freed slots are recycled through a free
//! list so steady-state matching performs **zero heap allocation**.
//!
//! ## Why (plan.md §9.1)
//!
//! Pointer-based linked lists chase pointers across the heap; on every
//! match step the CPU would stall on a dependent cache miss. Index-
//! based intrusive lists keep all nodes in one contiguous arena, so a
//! level's FIFO walk is a linear scan through (mostly) resident cache
//! lines. `u32` indices halve link width versus pointers and stay
//! valid across `Vec` growth because the arena never moves live nodes
//! (growth only appends; slots are addressed by index, never by
//! reference).
//!
//! ## Invariants
//!
//! - `NIL` (`u32::MAX`) is the only sentinel; a link equal to `NIL`
//!   means "no neighbor".
//! - A slot returned by [`OrderPool::release`] must not be read again
//!   until [`OrderPool::alloc`] hands it back (the engine enforces this;
//!   debug builds assert on use of `NIL`/out-of-range indices, release
//!   builds panic on them via the slice bounds check).

use primitives::Address;
use primitives::fixed::{Price, Qty};

use crate::order::{OrderId, Side, TimeInForce};

/// The "no link" sentinel for intrusive-list indices.
///
/// `u32::MAX` rather than `0` so that slot 0 is a usable slot (no
/// wasted node) and so any valid index is strictly less than the
/// arena length, making bounds checks catch sentinel misuse.
pub const NIL: u32 = u32::MAX;

/// One resting order: exactly one 64-byte cache line.
///
/// Field order is deliberate (performance-first skill §5,
/// hot→cold):
/// - `qty` first: the match loop reads and writes it every fill.
/// - `id`, `price`, `owner` next: fill events and level bookkeeping.
/// - `prev`/`next` links: FIFO splicing.
/// - side/tif last (one byte each, cold-ish but tiny).
///
/// `#[repr(C, align(64))]` pins the size to exactly one cache line —
/// two orders never share a line, so a fill touching `qty` cannot
/// invalidate another order's line.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderNode {
    /// Remaining unfilled quantity (raw scale-6). Decremented on fill.
    pub qty: Qty,
    /// Limit price (raw scale-8). The level this node is linked into.
    pub price: Price,
    /// Engine-assigned order id (submission sequence).
    pub id: OrderId,
    /// Owning account — fill attribution and self-trade checks.
    pub owner: Address,
    /// Intrusive FIFO link to the previous order at this price
    /// (toward the head; `NIL` at the head).
    pub prev: u32,
    /// Intrusive FIFO link to the next order at this price
    /// (toward the tail; `NIL` at the tail).
    pub next: u32,
    /// Buy or sell.
    pub side: Side,
    /// Time in force (only the resting remainder's policy matters).
    pub tif: TimeInForce,
}

// Static layout claim: one node per cache line. If a field is ever
// added that pushes the struct past 64 bytes, the alignment silently
// doubles the footprint — this test catches that before review does.
const _: () = {
    assert!(std::mem::size_of::<OrderNode>() == 64, "OrderNode must be exactly one cache line");
};

/// Slab arena of resting orders with a free list.
///
/// Slots are addressed by `u32` index; `Index`/`IndexMut` provide the
/// ergonomic access the engine uses. Allocation is O(1) (free-list
/// pop or `Vec::push`), release is O(1).
///
/// # Capacity note
///
/// The arena grows on demand; the *engine* enforces the market's
/// `max_resting` bound before resting (returning a rejection), so a
/// well-configured market never grows past its genesis capacity —
/// growth only happens under config change and is a visible
/// allocation, not a hot-path one.
#[derive(Debug, Clone)]
pub struct OrderPool {
    nodes: Vec<OrderNode>,
    free: Vec<u32>,
}

impl OrderPool {
    /// Build an arena with capacity reserved for `capacity` nodes.
    ///
    /// Reserving at construction (rather than growing during matching)
    /// keeps steady-state allocation at zero; `capacity` comes from
    /// the market's `max_resting` genesis parameter (plan.md §9.1:
    /// 2^20 default).
    #[must_use]
    pub fn with_capacity(capacity: u32) -> Self {
        // `+1` headroom: engine checks the configured bound itself; a
        // single slot of slack avoids a boundary off-by-one rejecting
        // the last configured order.
        let cap = (capacity as usize).saturating_add(1);
        OrderPool { nodes: Vec::with_capacity(cap), free: Vec::with_capacity(cap / 4) }
    }

    /// Number of live (allocated) nodes.
    #[inline]
    #[must_use]
    pub fn live(&self) -> u32 {
        // Live = allocated slots - recycled-but-unused slots. Both
        // counters are exact, so the difference needs no wrap guard.
        // Narrowing is bounded by the arena's u32 slot space.
        #[allow(clippy::cast_possible_truncation)]
        let live = (self.nodes.len() - self.free.len()) as u32;
        live
    }

    /// Allocate a slot and store `node` in it, returning the slot
    /// index.
    ///
    /// Recycles from the free list first (LIFO — best cache reuse:
    /// the most recently freed slot is the hottest).
    #[must_use]
    pub fn alloc(&mut self, node: OrderNode) -> u32 {
        if let Some(slot) = self.free.pop() {
            // `slot as usize` is lossless on every target we ship
            // (u32 indices into a ≤2^32-element arena).
            self.nodes[slot as usize] = node;
            return slot;
        }
        // Capacity check happens in the engine (config bound); here,
        // growth is the honest fallback for tests and config changes.
        // The narrowing is exact: the new slot index equals the
        // pre-push Vec length, which the u32 slot space bounds.
        #[allow(clippy::cast_possible_truncation)]
        let slot = self.nodes.len() as u32;
        self.nodes.push(node);
        slot
    }

    /// Return a slot to the free list.
    ///
    /// The node's links need not be cleared: the only legal next reader
    /// is `alloc`, which overwrites the whole node. (Engine asserts
    /// this discipline in debug builds.)
    pub fn release(&mut self, slot: u32) {
        debug_assert!(
            (slot as usize) < self.nodes.len() && !self.free.contains(&slot),
            "release of invalid or double-freed slot {slot}"
        );
        self.free.push(slot);
    }
}

// Compile-time guard that every `u32` slot index converts to `usize`
// losslessly, so `slot as usize` in the arena accessors can never
// truncate and alias another slot. Fails the build on a 16-bit
// target rather than miscompiling the book there.
const _: () = assert!(usize::BITS >= u32::BITS);

impl std::ops::Index<u32> for OrderPool {
    type Output = OrderNode;

    /// Immutable node access.
    ///
    /// `NIL` or an out-of-range slot is an engine logic bug (a
    /// freed/unlinked node read after detach). Debug builds report it
    /// with the slot and arena length; release builds still panic via
    /// the slice bounds check — never a silent read of another
    /// order's node. (The previous `usize::try_from(slot)
    /// .unwrap_or(0)` would have aliased slot 0 on a failed
    /// conversion; the conversion is now lossless by the
    /// module-level compile-time guard — hft-audit-2 T-13.)
    #[inline]
    fn index(&self, slot: u32) -> &OrderNode {
        let idx = slot as usize;
        debug_assert!(
            idx < self.nodes.len(),
            "slot {slot} out of range (len {})",
            self.nodes.len()
        );
        &self.nodes[idx]
    }
}

impl std::ops::IndexMut<u32> for OrderPool {
    /// Mutable node access, same panic discipline as `Index`.
    #[inline]
    fn index_mut(&mut self, slot: u32) -> &mut OrderNode {
        let idx = slot as usize;
        debug_assert!(
            idx < self.nodes.len(),
            "slot {slot} out of range (len {})",
            self.nodes.len()
        );
        &mut self.nodes[idx]
    }
}

/// Convenience constructor for a fresh, unlinked node.
///
/// Links are `NIL` on both sides: the book's `append` links it into a
/// level's FIFO immediately; a node is never observable mid-linking.
#[must_use]
pub fn fresh_node(
    id: OrderId,
    side: Side,
    price: Price,
    qty: Qty,
    owner: Address,
    tif: TimeInForce,
) -> OrderNode {
    OrderNode { qty, price, id, owner, prev: NIL, next: NIL, side, tif }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation)]
    use super::*;

    fn node(id: u64) -> OrderNode {
        fresh_node(
            OrderId(id),
            Side::Buy,
            Price(100),
            Qty(1_000),
            Address([id as u8; 20]),
            TimeInForce::Gtc,
        )
    }

    #[test]
    fn alloc_returns_sequential_slots_then_recycles() {
        let mut pool = OrderPool::with_capacity(16);
        let a = pool.alloc(node(1));
        let b = pool.alloc(node(2));
        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(pool.live(), 2);

        // Free the newest; the next alloc must reuse it (LIFO).
        pool.release(b);
        assert_eq!(pool.live(), 1);
        let c = pool.alloc(node(3));
        assert_eq!(c, b, "freed slot must be recycled");

        // And a distinct id survives the round-trip.
        assert_eq!(pool[c].id, OrderId(3));
    }

    #[test]
    fn live_count_tracks_release() {
        let mut pool = OrderPool::with_capacity(8);
        let slots: Vec<u32> = (0..5).map(|i| pool.alloc(node(i))).collect();
        assert_eq!(pool.live(), 5);
        for s in &slots {
            pool.release(*s);
        }
        assert_eq!(pool.live(), 0, "all released");
        assert_eq!(pool.nodes.len(), 5, "arena length unchanged (slots recycled)");
    }

    #[test]
    fn node_is_exactly_one_cache_line() {
        // Compile-time assert in const context above; repeat here so
        // the property shows up in `cargo test` output by name.
        assert_eq!(std::mem::size_of::<OrderNode>(), 64);
        assert_eq!(std::mem::align_of::<OrderNode>(), 64);
    }

    /// An out-of-range slot must panic, not alias slot 0 (hft-audit-2
    /// T-13). `NIL` is the most likely bogus index — a link followed
    /// past the end of a level.
    #[test]
    // Both the debug message ("slot N out of range") and the release
    // slice bounds-check message name the bogus index, NIL = u32::MAX.
    #[should_panic(expected = "4294967295")]
    fn index_of_nil_panics_instead_of_aliasing_slot_zero() {
        let mut pool = OrderPool::with_capacity(4);
        let _ = pool.alloc(node(1));
        let _ = &pool[NIL];
    }

    #[test]
    fn fresh_node_starts_unlinked() {
        let n = node(9);
        assert_eq!(n.prev, NIL);
        assert_eq!(n.next, NIL);
    }
}
