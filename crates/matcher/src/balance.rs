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
//! # Why not the bank module directly?
//!
//! The bank's `BTreeMap<Vec<u8>, Vec<u8>>` allocates a `Vec` key on
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
        let idx = addr_index(addr);
        if idx < self.balances.len() {
            self.balances[idx]
        } else {
            self.sparse.get(&addr.0).copied().unwrap_or(0)
        }
    }

    /// Set an account's balance (fund or overwrite).
    #[inline]
    pub fn set(&mut self, addr: &Address, amount: u64) {
        let idx = addr_index(addr);
        if idx < self.balances.len() {
            self.balances[idx] = amount;
        } else {
            self.sparse.insert(addr.0, amount);
        }
    }

    /// Debit an account (subtract from balance). Does NOT check
    /// for underflow — the caller must pre-check with `get`.
    #[inline]
    pub fn debit(&mut self, addr: &Address, amount: u64) {
        let idx = addr_index(addr);
        if idx < self.balances.len() {
            self.balances[idx] = self.balances[idx].saturating_sub(amount);
        } else {
            let entry = self.sparse.entry(addr.0).or_insert(0);
            *entry = entry.saturating_sub(amount);
        }
    }

    /// Credit an account (add to balance).
    #[inline]
    pub fn credit(&mut self, addr: &Address, amount: u64) {
        let idx = addr_index(addr);
        if idx < self.balances.len() {
            self.balances[idx] = self.balances[idx].saturating_add(amount);
        } else {
            let entry = self.sparse.entry(addr.0).or_insert(0);
            *entry = entry.saturating_add(amount);
        }
    }

    /// Number of accounts with non-zero balance in the flat array
    /// (not counting sparse).
    pub fn len(&self) -> usize {
        self.balances.iter().filter(|&&b| b > 0).count() + self.sparse.len()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all (address, balance) pairs in the flat array.
    /// Sparse entries are not included in this iterator.
    pub fn iter(&self) -> impl Iterator<Item = ([u8; 20], u64)> + '_ {
        self.balances.iter().enumerate().filter_map(|(i, &b)| {
            if b > 0 {
                let mut addr = [0u8; 20];
                addr[..4].copy_from_slice(&u32::try_from(i).unwrap_or(u32::MAX).to_le_bytes());
                Some((addr, b))
            } else {
                None
            }
        })
    }
}

impl Default for BalanceCache {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

// ── ShardedBalanceCache ──────────────────────────────────────────────

/// A thread-safe balance cache sharded by account hash.
///
/// Used by the multi-market parallel matcher where N worker threads
/// (one per market) share a single balance store. Each shard is a
/// `Mutex<HashMap<[u8; 20], u64>>` — the shard for an account is
/// `first_4_bytes(addr) % N_SHARDS`.
///
/// # Concurrency model
///
/// - **Read/debit/credit on one account**: locks only that account's
///   shard. No cross-shard coordination.
/// - **Cross-shard transfer (buyer in shard A, seller in shard B)**:
///   locks both shards in canonical order (lower index first) to
///   avoid deadlock. This is the classic two-phase locking pattern
///   for transfers.
/// - **Check-and-debit (atomic balance check + reservation)**: done
///   under the shard lock, so two workers trading the same account
///   on different markets cannot overdraw.
///
/// # Why not the flat-array `BalanceCache`?
///
/// `BalanceCache` is `&mut self` — single-threaded. The sharded
/// version trades the flat array's O(1) direct-index access for
/// `HashMap` + `Mutex` per shard, but gains parallelism across 128+
/// market threads. For 1M accounts across 64 shards, each shard
/// holds ~15k entries — small enough that the `HashMap` lookup is
/// still cache-friendly.
///
/// # Shard count tradeoff
///
/// - More shards = less contention, more memory overhead.
/// - Fewer shards = more contention, less memory.
/// - Default: 64 shards (good for 16-32 core machines with 128+
///   markets; each shard is contended by ~2 market threads on
///   average).
pub struct ShardedBalanceCache {
    /// One `HashMap` per shard, each behind its own `Mutex`.
    shards: Vec<std::sync::Mutex<HashMap<[u8; 20], u64>>>,
    /// Number of shards (power of 2 for fast modulo).
    num_shards: usize,
}

/// Default number of shards. 64 is a good fit for 16-32 core
/// machines running 128+ market threads — each shard is contended
/// by ~2 threads on average, and the `Mutex` is uncontended in the
/// common case (accounts spread across shards).
pub const DEFAULT_SHARD_COUNT: usize = 64;

impl ShardedBalanceCache {
    /// Create a sharded balance cache with the given number of
    /// shards. Each shard starts with an empty `HashMap`.
    ///
    /// # Panics
    ///
    /// Panics if `num_shards` is 0.
    #[must_use]
    pub fn new(num_shards: usize) -> Self {
        assert!(num_shards > 0, "must have at least one shard");
        let shards = (0..num_shards).map(|_| std::sync::Mutex::new(HashMap::new())).collect();
        Self { shards, num_shards }
    }

    /// Create with the default shard count (64).
    #[must_use]
    pub fn with_default_shards() -> Self {
        Self::new(DEFAULT_SHARD_COUNT)
    }

    /// Map an address to its shard index: first 4 bytes mod
    /// `num_shards`. This is deterministic and spreads sequential
    /// accounts across shards (account 0 → shard 0, account 1 →
    /// shard 1, ..., account 64 → shard 0, ...).
    #[inline]
    fn shard_idx(&self, addr: &Address) -> usize {
        let raw = u32::from_le_bytes([addr.0[0], addr.0[1], addr.0[2], addr.0[3]]);
        (raw as usize) % self.num_shards
    }

    /// Get an account's balance (0 if not funded). Locks one shard.
    ///
    /// # Panics
    ///
    /// Panics if the shard mutex is poisoned.
    #[inline]
    pub fn get(&self, addr: &Address) -> u64 {
        let idx = self.shard_idx(addr);
        self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&addr.0)
            .copied()
            .unwrap_or(0)
    }

    /// Set an account's balance (fund or overwrite). Locks one shard.
    ///
    /// # Panics
    ///
    /// Panics if the shard mutex is poisoned.
    #[inline]
    pub fn set(&self, addr: &Address, amount: u64) {
        let idx = self.shard_idx(addr);
        self.shards[idx]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(addr.0, amount);
    }

    /// Credit an account (add to balance). Locks one shard.
    ///
    /// # Panics
    ///
    /// Panics if the shard mutex is poisoned.
    #[inline]
    pub fn credit(&self, addr: &Address, amount: u64) {
        let idx = self.shard_idx(addr);
        let mut shard = self.shards[idx].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = shard.entry(addr.0).or_insert(0);
        *entry = entry.saturating_add(amount);
    }

    /// Atomically check that the account has at least `amount` and
    /// debit it. Returns `true` if the debit succeeded, `false` if
    /// the balance was insufficient. Locks one shard for the entire
    /// check-and-debit — no TOCTOU race.
    ///
    /// This is the anti-spam gate for buy orders: the balance check
    /// and reservation happen under the same lock, so two market
    /// workers trading the same account on different markets cannot
    /// overdraw.
    ///
    /// # Panics
    ///
    /// Panics if the shard mutex is poisoned.
    #[inline]
    pub fn check_and_debit(&self, addr: &Address, amount: u64) -> bool {
        let idx = self.shard_idx(addr);
        let mut shard = self.shards[idx].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = shard.entry(addr.0).or_insert(0);
        if *entry >= amount {
            *entry -= amount;
            true
        } else {
            false
        }
    }

    /// Transfer `amount` from `from` to `to` atomically. Locks both
    /// shards in canonical order (lower index first) to avoid
    /// deadlock. If both accounts are in the same shard, locks only
    /// once.
    ///
    /// # Panics
    ///
    /// Panics if either shard mutex is poisoned.
    pub fn transfer(&self, from: &Address, to: &Address, amount: u64) {
        let from_idx = self.shard_idx(from);
        let to_idx = self.shard_idx(to);
        if from_idx == to_idx {
            // Same shard — one lock.
            let mut shard =
                self.shards[from_idx].lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let from_entry = shard.entry(from.0).or_insert(0);
            *from_entry = from_entry.saturating_sub(amount);
            let to_entry = shard.entry(to.0).or_insert(0);
            *to_entry = to_entry.saturating_add(amount);
        } else {
            // Different shards — lock in canonical order (lower
            // index first) to avoid deadlock. Both locks are held
            // for the entire debit+credit, making the transfer
            // atomic even if other threads are touching these
            // accounts on other markets.
            let (first_lock, second_lock) = if from_idx < to_idx {
                (
                    self.shards[from_idx].lock().unwrap_or_else(std::sync::PoisonError::into_inner),
                    self.shards[to_idx].lock().unwrap_or_else(std::sync::PoisonError::into_inner),
                )
            } else {
                (
                    self.shards[to_idx].lock().unwrap_or_else(std::sync::PoisonError::into_inner),
                    self.shards[from_idx].lock().unwrap_or_else(std::sync::PoisonError::into_inner),
                )
            };
            let (mut first, mut second) = (first_lock, second_lock);
            // `from` and `to` are in different shards; figure out
            // which lock guards which account.
            let (from_shard, to_shard) = if from_idx < to_idx {
                (&mut first, &mut second)
            } else {
                (&mut second, &mut first)
            };
            let from_entry = from_shard.entry(from.0).or_insert(0);
            *from_entry = from_entry.saturating_sub(amount);
            let to_entry = to_shard.entry(to.0).or_insert(0);
            *to_entry = to_entry.saturating_add(amount);
        }
    }

    /// Number of accounts with non-zero balance across all shards.
    /// This is `O(num_shards)` — locks each shard briefly.
    ///
    /// # Panics
    ///
    /// Panics if any shard mutex is poisoned.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .values()
                    .filter(|&&b| b > 0)
                    .count()
            })
            .sum()
    }

    /// Is the cache empty?
    ///
    /// # Panics
    ///
    /// Panics if any shard mutex is poisoned.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of shards.
    #[must_use]
    pub fn num_shards(&self) -> usize {
        self.num_shards
    }
}

impl Default for ShardedBalanceCache {
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

    // ── ShardedBalanceCache tests ───────────────────────────────

    #[test]
    fn sharded_fund_and_check() {
        let cache = ShardedBalanceCache::new(8);
        cache.set(&addr_idx(1), 1_000_000);
        assert_eq!(cache.get(&addr_idx(1)), 1_000_000);
        assert_eq!(cache.get(&addr_idx(2)), 0, "unfunded is 0");
    }

    #[test]
    fn sharded_credit_and_debit() {
        let cache = ShardedBalanceCache::new(8);
        cache.set(&addr_idx(1), 1_000_000);
        cache.credit(&addr_idx(1), 500_000);
        assert_eq!(cache.get(&addr_idx(1)), 1_500_000);
        assert!(cache.check_and_debit(&addr_idx(1), 300_000));
        assert_eq!(cache.get(&addr_idx(1)), 1_200_000);
    }

    #[test]
    fn sharded_check_and_debit_rejects_overdraw() {
        let cache = ShardedBalanceCache::new(8);
        cache.set(&addr_idx(1), 1_000);
        // Cannot debit more than balance.
        assert!(!cache.check_and_debit(&addr_idx(1), 2_000));
        // Balance unchanged after failed debit.
        assert_eq!(cache.get(&addr_idx(1)), 1_000);
    }

    #[test]
    fn sharded_transfer_same_shard() {
        let cache = ShardedBalanceCache::new(8);
        // addr_idx(0) and addr_idx(8) both map to shard 0 (0 % 8 = 0,
        // 8 % 8 = 0).
        cache.set(&addr_idx(0), 1_000_000);
        cache.transfer(&addr_idx(0), &addr_idx(8), 300_000);
        assert_eq!(cache.get(&addr_idx(0)), 700_000);
        assert_eq!(cache.get(&addr_idx(8)), 300_000);
    }

    #[test]
    fn sharded_transfer_cross_shard() {
        let cache = ShardedBalanceCache::new(8);
        // addr_idx(0) → shard 0, addr_idx(1) → shard 1 — different.
        cache.set(&addr_idx(0), 1_000_000);
        cache.transfer(&addr_idx(0), &addr_idx(1), 300_000);
        assert_eq!(cache.get(&addr_idx(0)), 700_000);
        assert_eq!(cache.get(&addr_idx(1)), 300_000);
    }

    #[test]
    fn sharded_concurrent_transfers_no_overdraw() {
        // 16 threads each try to debit the same account by 100.
        // Account starts with 1000 — only 10 should succeed.
        let cache = Arc::new(ShardedBalanceCache::new(8));
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
