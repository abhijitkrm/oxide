//! Flat-array balance cache for the off-chain matching server.
//!
//! Uses a `Vec<u64>` indexed by the first 4 bytes of the address
//! (interpreted as a `u32` account index). This gives O(1) direct
//! indexed access — no hash, no probe, no allocation on the hot
//! path. For 1M accounts this is 8 MB of `u64`s, which fits in L2
//! cache on modern server CPUs.
//!
//! # Why not `HashMap`?
//!
//! `HashMap<[u8; 20], u64>` does a `SipHash` on the 20-byte key (~20-30
//! ns), then linear-probes buckets (~10-30 ns). For 1B orders, that's
//! 2-5 seconds of pure hash overhead. The flat array eliminates this:
//! the account index IS the address (first 4 bytes), so there's no
//! hash computation — just a bounds check and an array access (~5 ns).
//!
//! # Why not the shared ledger directly?
//!
//! A generic account map allocates a `Vec` key on
//! every lookup and does a tree traversal (O(log n)). For 1M
//! accounts and 1B orders, that's 1B `Vec` allocations + 1B tree
//! traversals — the GC pressure alone would dominate throughput.
//!
//! # Fallback for sparse addresses
//!
//! If an address's first-4-bytes index exceeds the flat array
//! capacity, the cache falls back to a `HashMap` for that address.
//! This handles arbitrary 20-byte addresses while keeping the hot
//! path (sequential account indices) on the flat array.

use primitives::Address;
use std::collections::HashMap;

/// Default flat array capacity (1M accounts = 8 MB of u64s).
const DEFAULT_CAPACITY: usize = 1_000_000;

/// Extract the account index from an address: the first 4 bytes
/// interpreted as a little-endian `u32`.
///
/// This is the identity function for sequential accounts (our
/// benchmark/test convention: `addr[..4] = index.to_le_bytes()`).
/// For arbitrary addresses, this produces a deterministic index
/// that may exceed the flat array capacity — the `HashMap` fallback
/// handles those.
#[inline]
fn addr_index(addr: &Address) -> usize {
    u32::from_le_bytes([addr.0[0], addr.0[1], addr.0[2], addr.0[3]]) as usize
}

/// Whether an address lives in the flat array (vs the sparse map).
///
/// Flat residency requires BOTH:
/// - `idx < capacity` — the slot exists, and
/// - `addr.0[4..]` is all zeros — the address is in canonical
///   sequential form (`[u32 index LE][0; 16]`).
///
/// The second condition is the collision fix: previously residency
/// depended only on the index, so two DIFFERENT addresses sharing
/// their first 4 bytes silently aliased the same balance slot —
/// `addr([i][0xAA; 16])` and `addr([i][0xBB; 16])` read and wrote
/// each other's funds. Any non-canonical address goes to the
/// sparse map, which is keyed by the FULL 20 bytes and cannot
/// collide.
#[inline]
fn is_flat(addr: &Address, capacity: usize) -> bool {
    addr_index(addr) < capacity && addr.0[4..].iter().all(|&b| b == 0)
}

/// A flat-array balance cache: `Vec<u64>` for sequential accounts,
/// `HashMap` fallback for sparse addresses.
///
/// The flat array is the hot path — O(1) direct indexed access.
/// The `HashMap` is the cold path — only used for addresses whose
/// first-4-bytes index exceeds the array capacity.
pub struct BalanceCache {
    /// Flat array: `balances[i]` = balance of account `i`.
    /// Grows on demand when `addr_index` exceeds capacity.
    balances: Vec<u64>,
    /// Fallback for addresses whose index exceeds the array.
    /// In practice this is only used for non-sequential addresses.
    sparse: HashMap<[u8; 20], u64>,
}

impl BalanceCache {
    /// Create an empty cache with the given initial flat-array
    /// capacity. The `HashMap` fallback starts empty.
    pub fn with_capacity(capacity: usize) -> Self {
        Self { balances: vec![0u64; capacity.max(1)], sparse: HashMap::new() }
    }

    /// Get an account's balance (0 if not funded).
    ///
    /// Hot path: direct array access (`balances[idx]`). Cold path:
    /// `HashMap` lookup for sparse addresses.
    #[inline]
    pub fn get(&self, addr: &Address) -> u64 {
        if is_flat(addr, self.balances.len()) {
            self.balances[addr_index(addr)]
        } else {
            self.sparse.get(&addr.0).copied().unwrap_or(0)
        }
    }

    /// Set an account's balance (fund or overwrite).
    #[inline]
    pub fn set(&mut self, addr: &Address, amount: u64) {
        if is_flat(addr, self.balances.len()) {
            self.balances[addr_index(addr)] = amount;
        } else {
            self.sparse.insert(addr.0, amount);
        }
    }

    /// Debit an account (subtract from balance). Does NOT check
    /// for underflow — the caller must pre-check with `get`.
    #[inline]
    pub fn debit(&mut self, addr: &Address, amount: u64) {
        if is_flat(addr, self.balances.len()) {
            let idx = addr_index(addr);
            self.balances[idx] = self.balances[idx].saturating_sub(amount);
        } else {
            let entry = self.sparse.entry(addr.0).or_insert(0);
            *entry = entry.saturating_sub(amount);
        }
    }

    /// Credit an account (add to balance).
    #[inline]
    pub fn credit(&mut self, addr: &Address, amount: u64) {
        if is_flat(addr, self.balances.len()) {
            let idx = addr_index(addr);
            self.balances[idx] = self.balances[idx].saturating_add(amount);
        } else {
            let entry = self.sparse.entry(addr.0).or_insert(0);
            *entry = entry.saturating_add(amount);
        }
    }

    /// Number of accounts with non-zero balance (flat + sparse).
    /// Sparse entries can hold 0 (a debit that drained to zero
    /// leaves the map entry behind), so count nonzero only —
    /// consistent with `iter`.
    pub fn len(&self) -> usize {
        self.balances.iter().filter(|&&b| b > 0).count()
            + self.sparse.values().filter(|&&b| b > 0).count()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all (address, balance) pairs — flat array AND
    /// sparse map, nonzero balances only. Previously sparse entries
    /// were silently excluded, so any full iteration (snapshot,
    /// drain, reconciliation) lost those balances.
    pub fn iter(&self) -> impl Iterator<Item = ([u8; 20], u64)> + '_ {
        let flat = self.balances.iter().enumerate().filter_map(|(i, &b)| {
            if b > 0 {
                let mut addr = [0u8; 20];
                addr[..4].copy_from_slice(&u32::try_from(i).unwrap_or(u32::MAX).to_le_bytes());
                Some((addr, b))
            } else {
                None
            }
        });
        let sparse = self.sparse.iter().filter(|&(_, &b)| b > 0).map(|(&k, &b)| (k, b));
        flat.chain(sparse)
    }
}

impl Default for BalanceCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

// ── AtomicBalanceCache ───────────────────────────────────────────────

/// A thread-safe balance cache: a flat array of per-account
/// `AtomicU64`s plus a locked `HashMap` fallback for non-canonical
/// addresses.
///
/// Used by the multi-market parallel matcher where N worker threads
/// (one per market) share a single balance store. This replaces the
/// earlier per-shard `Mutex<HashMap>` design: shard locks serialized
/// threads that only collided on a shard (1/64 of accounts) rather
/// than on the actual account, capping 8-thread throughput at
/// ~22M ops/s (`benches/balance_contention.rs`). Per-account
/// atomics make false sharing impossible — two threads conflict
/// only when they touch the SAME account, which is the real race
/// the risk gate exists for.
///
/// # Concurrency model
///
/// - **Read/credit/debit on one flat account**: a single atomic
///   operation on that account's word. No locks, no cross-account
///   coordination.
/// - **Check-and-debit**: one `fetch_update` CAS loop — the
///   sufficient-balance check and the subtraction are one atomic
///   step, so two workers trading the same account on different
///   markets cannot overdraw.
/// - **Transfer**: CAS-debit `from` first; on success, credit `to`
///   (the credit is a saturating add — it cannot fail). The
///   operation linearizes at the debit; the credit lands a few
///   instructions later. That transient "in-flight" state is safe
///   for a risk cache: a concurrent `check_and_debit` on `to` sees
///   the pre-credit balance and conservatively rejects — funds can
///   never be double-spent or created.
/// - **Sparse addresses** (non-canonical form): all sparse ops run
///   under one `Mutex<HashMap>`. Mixed flat↔sparse transfers take
///   the sparse lock for the sparse side only — the flat side is
///   already atomic.
///
/// # Memory ordering
///
/// `Acquire` on reads and `AcqRel` on read-modify-writes. For a pure
/// accounting word `Relaxed` would suffice today — the balance IS
/// the state, with no dependent invariants — but the stronger
/// ordering is free on x86/ARM here and protects against future
/// code that keys off balance values.
///
/// # Capacity
///
/// The flat array is sized at construction (default 1M accounts =
/// 8 MB of atomics) and does NOT grow — `Vec` reallocation would be
/// unsound under shared `&` access. Non-canonical or out-of-range
/// addresses transparently use the sparse map.
pub struct AtomicBalanceCache {
    /// `flat[i]` = balance of canonical account `i` (address form
    /// `[u32 index LE][0; 16]`).
    flat: Vec<std::sync::atomic::AtomicU64>,
    /// Fallback for non-canonical addresses: full 20-byte key, so
    /// arbitrary addresses can never alias a flat slot.
    sparse: std::sync::Mutex<HashMap<[u8; 20], u64>>,
}

/// Backwards-compatible alias: the type was previously a
/// per-shard `Mutex<HashMap>` design named `ShardedBalanceCache`.
/// The constructor's argument changed meaning (was shard count, is
/// now flat capacity) — see [`AtomicBalanceCache::new`].
pub type ShardedBalanceCache = AtomicBalanceCache;

/// Default flat-array capacity: 1M accounts = 8 MB of `AtomicU64`.
/// Matches `DEFAULT_CAPACITY` for the single-threaded cache.
pub const DEFAULT_SHARD_COUNT: usize = 1_000_000;

impl AtomicBalanceCache {
    /// Create a cache whose flat array holds `capacity` accounts.
    /// The parameter previously meant "shard count" when this type
    /// was lock-based; it is now a flat capacity — pass the number
    /// of funded sequential accounts (or more).
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is 0.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "flat capacity must be at least 1");
        let mut flat = Vec::with_capacity(capacity);
        flat.resize_with(capacity, || std::sync::atomic::AtomicU64::new(0));
        Self { flat, sparse: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Create with the default capacity (1M accounts).
    #[must_use]
    pub fn with_default_shards() -> Self {
        Self::new(DEFAULT_SHARD_COUNT)
    }

    /// Get an account's balance (0 if not funded). Flat path: one
    /// atomic load. Sparse path: locked `HashMap` read.
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned (sparse addresses only).
    #[inline]
    pub fn get(&self, addr: &Address) -> u64 {
        if is_flat(addr, self.flat.len()) {
            self.flat[addr_index(addr)].load(std::sync::atomic::Ordering::Acquire)
        } else {
            self.sparse
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&addr.0)
                .copied()
                .unwrap_or(0)
        }
    }

    /// Set an account's balance (fund or overwrite). Flat path: one
    /// atomic store. Intended for funding/setup; concurrent `set`s
    /// on the same account have no ordering guarantee beyond the
    /// final value being one of the stored ones.
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned (sparse addresses only).
    #[inline]
    pub fn set(&self, addr: &Address, amount: u64) {
        if is_flat(addr, self.flat.len()) {
            self.flat[addr_index(addr)].store(amount, std::sync::atomic::Ordering::Release);
        } else {
            self.sparse
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(addr.0, amount);
        }
    }

    /// Credit an account (add to balance). Flat path: one CAS that
    /// saturates at `u64::MAX` instead of wrapping — matching the
    /// old `saturating_add` semantics (an account at MAX cannot be
    /// credited further; value is not silently wrapped).
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned (sparse addresses only).
    #[inline]
    pub fn credit(&self, addr: &Address, amount: u64) {
        if is_flat(addr, self.flat.len()) {
            let idx = addr_index(addr);
            // `fetch_update` retries the CAS under contention; the
            // closure always returns Some so this cannot fail.
            let _ = self.flat[idx].fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |b| Some(b.saturating_add(amount)),
            );
        } else {
            let mut sparse = self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = sparse.entry(addr.0).or_insert(0);
            *entry = entry.saturating_add(amount);
        }
    }

    /// Debit an account (subtract from balance, saturating at 0).
    /// Does NOT check sufficiency — the caller must pre-check with
    /// `get` or use [`Self::check_and_debit`].
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned (sparse addresses only).
    #[inline]
    pub fn debit(&self, addr: &Address, amount: u64) {
        if is_flat(addr, self.flat.len()) {
            let idx = addr_index(addr);
            let _ = self.flat[idx].fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |b| Some(b.saturating_sub(amount)),
            );
        } else {
            let mut sparse = self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = sparse.entry(addr.0).or_insert(0);
            *entry = entry.saturating_sub(amount);
        }
    }

    /// Atomically check that the account has at least `amount` and
    /// debit it. Returns `true` if the debit succeeded, `false` if
    /// the balance was insufficient. Flat path: one `fetch_update`
    /// CAS — the check and the subtraction are a single atomic step,
    /// so two workers trading the same account cannot overdraw.
    ///
    /// This is the anti-spam gate for buy orders.
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned (sparse addresses only).
    #[inline]
    pub fn check_and_debit(&self, addr: &Address, amount: u64) -> bool {
        if is_flat(addr, self.flat.len()) {
            let idx = addr_index(addr);
            self.flat[idx]
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |b| b.checked_sub(amount),
                )
                .is_ok()
        } else {
            let mut sparse = self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = sparse.entry(addr.0).or_insert(0);
            if *entry >= amount {
                *entry -= amount;
                true
            } else {
                false
            }
        }
    }

    /// Transfer `amount` from `from` to `to`. Returns `false` — with
    /// NOTHING moved — if `from` cannot cover `amount`.
    ///
    /// Flat↔flat: CAS-debit `from` (the linearization point), then
    /// saturating-credit `to`. The credit cannot fail, so the
    /// transfer cannot be left half-applied; a concurrent observer
    /// may see the debit before the credit lands — a transient
    /// in-flight state that is conservative for a risk cache.
    ///
    /// Sparse involvement: the sparse side runs under the sparse
    /// mutex; the flat side stays atomic.
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned (sparse addresses only).
    pub fn transfer(&self, from: &Address, to: &Address, amount: u64) -> bool {
        let from_flat = is_flat(from, self.flat.len());
        let to_flat = is_flat(to, self.flat.len());
        match (from_flat, to_flat) {
            (true, true) => {
                if !self.check_and_debit(from, amount) {
                    return false; // insolvent — nothing moved
                }
                self.credit(to, amount);
                true
            }
            (true, false) => {
                if !self.check_and_debit(from, amount) {
                    return false;
                }
                let mut sparse =
                    self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let entry = sparse.entry(to.0).or_insert(0);
                *entry = entry.saturating_add(amount);
                true
            }
            (false, true) => {
                // Debit the sparse side under its lock first; only
                // then credit the flat side — keeps the
                // insolvency-check atomic w.r.t. other sparse ops.
                {
                    let mut sparse =
                        self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    let entry = sparse.entry(from.0).or_insert(0);
                    if *entry < amount {
                        return false;
                    }
                    *entry -= amount;
                }
                self.credit(to, amount);
                true
            }
            (false, false) => {
                let mut sparse =
                    self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let from_entry = sparse.entry(from.0).or_insert(0);
                if *from_entry < amount {
                    return false;
                }
                *from_entry -= amount;
                let to_entry = sparse.entry(to.0).or_insert(0);
                *to_entry = to_entry.saturating_add(amount);
                true
            }
        }
    }

    /// Number of accounts with non-zero balance (flat + sparse).
    /// `O(capacity)` on the flat array — a debug/stats path, not
    /// hot.
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned.
    pub fn len(&self) -> usize {
        let flat =
            self.flat.iter().filter(|a| a.load(std::sync::atomic::Ordering::Acquire) > 0).count();
        let sparse = self
            .sparse
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|&&b| b > 0)
            .count();
        flat + sparse
    }

    /// Is the cache empty?
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Flat-array capacity in accounts (was `num_shards` — kept the
    /// getter name out of the hot path's way; the cache is no longer
    /// sharded).
    #[must_use]
    pub fn num_shards(&self) -> usize {
        self.flat.len()
    }
}

impl Default for AtomicBalanceCache {
    fn default() -> Self {
        Self::with_default_shards()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn addr_idx(i: u32) -> Address {
        let mut a = [0u8; 20];
        a[..4].copy_from_slice(&i.to_le_bytes());
        Address(a)
    }

    #[test]
    fn fund_and_check_balance() {
        let mut cache = BalanceCache::with_capacity(100);
        cache.set(&addr_idx(1), 1_000_000);
        assert_eq!(cache.get(&addr_idx(1)), 1_000_000);
        assert_eq!(cache.get(&addr_idx(2)), 0, "unfunded account is 0");
    }

    #[test]
    fn sparse_address_uses_hashmap() {
        // Address with non-sequential first-4-bytes (large index).
        let mut a = [0xFF; 20];
        a[0] = 0xFF;
        a[1] = 0xFF;
        a[2] = 0xFF;
        a[3] = 0xFF; // index = u32::MAX — exceeds array capacity
        let sparse_addr = Address(a);
        let mut cache = BalanceCache::with_capacity(10);
        cache.set(&sparse_addr, 999);
        assert_eq!(cache.get(&sparse_addr), 999);
    }

    #[test]
    fn debit_and_credit() {
        let mut cache = BalanceCache::with_capacity(100);
        cache.set(&addr_idx(1), 1_000_000);
        cache.debit(&addr_idx(1), 300_000);
        assert_eq!(cache.get(&addr_idx(1)), 700_000);
        cache.credit(&addr_idx(1), 500_000);
        assert_eq!(cache.get(&addr_idx(1)), 1_200_000);
    }

    #[test]
    fn debit_unfunded_account_saturates_to_zero() {
        let mut cache = BalanceCache::with_capacity(100);
        cache.debit(&addr_idx(9), 1_000);
        assert_eq!(cache.get(&addr_idx(9)), 0, "debit on unfunded account saturates to 0");
    }

    #[test]
    fn one_million_accounts() {
        let mut cache = BalanceCache::with_capacity(1_000_000);
        for i in 0..1_000_000u32 {
            cache.set(&addr_idx(i), 1_000_000_000);
        }
        assert_eq!(cache.len(), 1_000_000);
        assert_eq!(cache.get(&addr_idx(500_000)), 1_000_000_000);
    }

    // ── AtomicBalanceCache tests ────────────────────────────────

    #[test]
    fn atomic_fund_and_check() {
        let cache = AtomicBalanceCache::new(8);
        cache.set(&addr_idx(1), 1_000_000);
        assert_eq!(cache.get(&addr_idx(1)), 1_000_000);
        assert_eq!(cache.get(&addr_idx(2)), 0, "unfunded is 0");
    }

    #[test]
    fn atomic_credit_and_debit() {
        let cache = AtomicBalanceCache::new(8);
        cache.set(&addr_idx(1), 1_000_000);
        cache.credit(&addr_idx(1), 500_000);
        assert_eq!(cache.get(&addr_idx(1)), 1_500_000);
        assert!(cache.check_and_debit(&addr_idx(1), 300_000));
        assert_eq!(cache.get(&addr_idx(1)), 1_200_000);
    }

    #[test]
    fn atomic_check_and_debit_rejects_overdraw() {
        let cache = AtomicBalanceCache::new(8);
        cache.set(&addr_idx(1), 1_000);
        // Cannot debit more than balance.
        assert!(!cache.check_and_debit(&addr_idx(1), 2_000));
        // Balance unchanged after failed debit.
        assert_eq!(cache.get(&addr_idx(1)), 1_000);
    }

    #[test]
    fn atomic_transfer_same_shard() {
        let cache = AtomicBalanceCache::new(8);
        // addr_idx(0) and addr_idx(8) both map to shard 0 (0 % 8 = 0,
        // 8 % 8 = 0).
        cache.set(&addr_idx(0), 1_000_000);
        assert!(cache.transfer(&addr_idx(0), &addr_idx(8), 300_000));
        assert_eq!(cache.get(&addr_idx(0)), 700_000);
        assert_eq!(cache.get(&addr_idx(8)), 300_000);
    }

    #[test]
    fn atomic_transfer_cross_shard() {
        let cache = AtomicBalanceCache::new(8);
        // addr_idx(0) → shard 0, addr_idx(1) → shard 1 — different.
        cache.set(&addr_idx(0), 1_000_000);
        assert!(cache.transfer(&addr_idx(0), &addr_idx(1), 300_000));
        assert_eq!(cache.get(&addr_idx(0)), 700_000);
        assert_eq!(cache.get(&addr_idx(1)), 300_000);
    }

    /// Regression test: an underfunded transfer must fail WITHOUT
    /// moving anything. Before the fix the debit saturated to zero
    /// while the full amount was credited — minting the difference.
    #[test]
    fn atomic_transfer_insolvent_moves_nothing() {
        // Same shard.
        let cache = AtomicBalanceCache::new(8);
        cache.set(&addr_idx(0), 100);
        assert!(!cache.transfer(&addr_idx(0), &addr_idx(8), 300));
        assert_eq!(cache.get(&addr_idx(0)), 100, "debit must not happen");
        assert_eq!(cache.get(&addr_idx(8)), 0, "credit must not happen");

        // Cross shard.
        let cache = AtomicBalanceCache::new(8);
        cache.set(&addr_idx(0), 100);
        assert!(!cache.transfer(&addr_idx(0), &addr_idx(1), 300));
        assert_eq!(cache.get(&addr_idx(0)), 100);
        assert_eq!(cache.get(&addr_idx(1)), 0);
    }

    /// Regression test: two different addresses that share their
    /// first 4 bytes must NOT alias the same balance slot. Before
    /// the fix both indexed `balances[idx]` — one account's funds
    /// read and wrote the other's.
    #[test]
    fn same_index_prefix_addresses_do_not_collide() {
        let mut cache = BalanceCache::with_capacity(100);
        // Canonical sequential address for index 5.
        let canonical = addr_idx(5);
        // A different address sharing the first-4-bytes index 5.
        let mut raw = [0xEE; 20];
        raw[..4].copy_from_slice(&5u32.to_le_bytes());
        let collider = Address(raw);

        cache.set(&canonical, 1_000);
        cache.set(&collider, 2_000);

        assert_eq!(cache.get(&canonical), 1_000, "canonical slot untouched");
        assert_eq!(cache.get(&collider), 2_000, "sparse entry independent");
        // Mutations on one must not leak into the other.
        cache.debit(&collider, 500);
        cache.credit(&canonical, 250);
        assert_eq!(cache.get(&canonical), 1_250);
        assert_eq!(cache.get(&collider), 1_500);
    }

    /// Regression test: `iter` must include sparse entries —
    /// previously a full iteration silently dropped every
    /// non-canonical balance (lost in snapshots/reconciliation).
    #[test]
    fn iter_includes_sparse_entries() {
        let mut cache = BalanceCache::with_capacity(10);
        cache.set(&addr_idx(3), 700);
        let mut raw = [0xEE; 20];
        raw[..4].copy_from_slice(&42u32.to_le_bytes()); // idx 42 > cap → sparse
        let sparse_addr = Address(raw);
        cache.set(&sparse_addr, 900);

        let entries: std::collections::HashMap<[u8; 20], u64> = cache.iter().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries.get(&addr_idx(3).0), Some(&700));
        assert_eq!(entries.get(&sparse_addr.0), Some(&900));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn atomic_concurrent_transfers_no_overdraw() {
        // 16 threads each try to debit the same account by 100.
        // Account starts with 1000 — only 10 should succeed.
        let cache = Arc::new(AtomicBalanceCache::new(8));
        cache.set(&addr_idx(0), 1_000);
        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || cache.check_and_debit(&addr_idx(0), 100)));
        }
        let mut successes = 0;
        for h in handles {
            if h.join().unwrap() {
                successes += 1;
            }
        }
        assert_eq!(successes, 10, "exactly 10 debits of 100 should succeed");
        assert_eq!(cache.get(&addr_idx(0)), 0, "account should be drained");
    }
}
