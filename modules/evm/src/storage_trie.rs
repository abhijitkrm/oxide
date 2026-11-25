//! Incremental storage roots for large contracts.
//!
//! The state-root update recomputes the storage root of every touched account. For a small contract that
//! is cheap, but the EIP-2935 history-storage contract is touched by *every* block (the parent-hash write)
//! and holds an 8,191-slot ring buffer, so each block hashed all 8,191 slot keys and rebuilt the whole
//! storage trie to change one leaf: ~14% of a validator's CPU in the consensus bench (Keccak), and the
//! same cost applies to any large token or order-book contract.
//!
//! This module keeps, for each *large* account, its storage trie as retained branches (exactly like the
//! state trie's `retained_branches`) plus its leaves, and updates only what changed:
//!
//! 1. **Diff against the cache's own contents.** The cache stores the `slot -> value` map it represents.
//!    Each block the account's current slots are compared to it (one pass of hash lookups, no hashing, no
//!    allocation unless something changed). Because the diff is against what the cached trie *contains*,
//!    never against an assumption about history, a rollback, a snapshot import or any other change to the
//!    account cache cannot yield a wrong root: the worst case is a larger diff (or a rebuild).
//! 2. **Sparse walk.** The changed slots' hashed keys are the touched set for
//!    [`crate::trie::sparse_walk`], the same walk the state trie uses: untouched subtrees contribute their
//!    stored hashes, so the work is O(changed * depth) instead of O(slots).
//!
//! The result is byte-identical to [`crate::trie::storage_root`] (differential tests below).
//! Small accounts, and a total cache above [`MAX_CACHED_SLOTS`], use the full computation as before.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use alloy_primitives::{B256, U256, keccak256};
use alloy_trie::{BranchNodeCompact, HashBuilder, Nibbles};
use revm::primitives::Address;

use crate::trie;

/// Accounts with fewer storage slots than this use the full recompute (unit: slots). Origin: below a
/// few hundred slots the full storage root costs well under the bookkeeping of a cache entry (three maps
/// per account), and most contracts are this small. The history contract (8,191 slots) and any real
/// token or order-book contract are above it. Raising it saves memory, lowering it trades memory for CPU
/// on mid-size contracts.
pub(crate) const LARGE_STORAGE_SLOTS: usize = 512;

/// Upper bound on the slots held across all cached tries (unit: slots). Origin: each cached slot costs
/// roughly 200 bytes (values map, leaf map, share of the retained branches), so 1M slots is ~200 MB on
/// top of the account cache that already holds every slot. A contract that would push the total past
/// this uses the full recompute (today's behavior), so the cap bounds memory, never correctness.
pub(crate) const MAX_CACHED_SLOTS: usize = 1_000_000;

/// When more than `len / REBUILD_DIVISOR` of a trie's slots changed in one block, rebuilding it from
/// scratch is cheaper than a sparse walk over most of it (unit: ratio). Origin: the sparse walk touches
/// O(changed * depth) nodes versus O(slots) for a rebuild, so they cross near a quarter of the leaves.
const REBUILD_DIVISOR: usize = 4;

/// One cached storage trie.
struct StorageTrie {
    /// The non-zero `slot -> value` pairs this trie represents (the diff baseline).
    values: HashMap<U256, U256>,
    /// `keccak256(slot)` -> RLP(value): the trie's leaves, keyed as the secure trie keys them.
    leaves: BTreeMap<B256, Vec<u8>>,
    /// Branch nodes retained from the last build, for the sparse walk.
    retained: HashMap<Nibbles, BranchNodeCompact>,
    /// Deepest retained prefix length (bounds the stale-branch sweep).
    depth: usize,
    /// The root of the trie as it stands.
    root: B256,
}

fn hashed_slot(slot: &U256) -> B256 {
    keccak256(slot.to_be_bytes::<32>())
}

fn leaf_rlp(value: &U256) -> Vec<u8> {
    alloy_rlp::encode_fixed_size(value).to_vec()
}

impl StorageTrie {
    /// Build from scratch (first sight of the account, or a rebuild).
    fn build(values: HashMap<U256, U256>) -> Self {
        let leaves: BTreeMap<B256, Vec<u8>> =
            values.iter().map(|(slot, v)| (hashed_slot(slot), leaf_rlp(v))).collect();
        let mut hb = HashBuilder::default().with_updates(true);
        for (key, rlp) in &leaves {
            hb.add_leaf(Nibbles::unpack(key), rlp);
        }
        let root = hb.root();
        let (_, updates) = hb.split();
        let retained: HashMap<Nibbles, BranchNodeCompact> = updates.into_iter().collect();
        let depth = retained.keys().map(Nibbles::len).max().unwrap_or(0);
        Self { values, leaves, retained, depth, root }
    }

    /// Apply `changed` (new or updated non-zero slots) and `removed` (slots now zero or gone), returning
    /// the new root. The caller has already decided this is cheaper than a rebuild.
    fn apply(&mut self, changed: &[(U256, U256)], removed: &[U256]) -> B256 {
        let mut touched: BTreeSet<B256> = BTreeSet::new();
        for (slot, value) in changed {
            let key = hashed_slot(slot);
            self.values.insert(*slot, *value);
            self.leaves.insert(key, leaf_rlp(value));
            touched.insert(key);
        }
        for slot in removed {
            let key = hashed_slot(slot);
            self.values.remove(slot);
            self.leaves.remove(&key);
            touched.insert(key);
        }

        let mut hb = HashBuilder::default().with_updates(true);
        let sparse = !self.retained.is_empty();
        if sparse {
            trie::sparse_walk(Nibbles::default(), &self.retained, &self.leaves, &touched, &mut hb);
        } else {
            // No retained branches (a tiny trie): feed every leaf, then the branches are all new.
            for (key, rlp) in &self.leaves {
                hb.add_leaf(Nibbles::unpack(key), rlp);
            }
        }
        let root = hb.root();
        let (_, updates) = hb.split();

        if sparse {
            // Drop stale branches on every touched path, then merge the rebuilt ones (the same
            // maintenance `assemble_root` does for the state trie).
            for key in &touched {
                let nibbles = Nibbles::unpack(key);
                for len in 0..=self.depth.min(nibbles.len().saturating_sub(1)) {
                    self.retained.remove(&nibbles.slice(..len));
                }
            }
            for (prefix, node) in updates {
                self.depth = self.depth.max(prefix.len());
                self.retained.insert(prefix, node);
            }
        } else {
            self.retained = updates.into_iter().collect();
            self.depth = self.retained.keys().map(Nibbles::len).max().unwrap_or(0);
        }
        self.root = root;
        root
    }
}

/// Cached storage tries of the large accounts, keyed by address. Owned by the execution stage (the only
/// place storage roots are computed), behind one lock on the module.
#[derive(Default)]
pub(crate) struct LargeStorageTries {
    by_addr: HashMap<Address, StorageTrie>,
    /// Slots held across all entries (for [`MAX_CACHED_SLOTS`]).
    cached_slots: usize,
}

impl LargeStorageTries {
    /// Drop the cached trie of `addr` (account deleted, or no longer large).
    pub(crate) fn forget(&mut self, addr: &Address) {
        if let Some(t) = self.by_addr.remove(addr) {
            self.cached_slots -= t.values.len();
        }
    }

    /// Number of accounts with a cached trie (tests and metrics).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_addr.len()
    }

    /// The storage root of `addr` given its current `storage` map (zero values are ignored: a zero slot
    /// and an absent slot are the same trie state). Identical to
    /// `trie::storage_root(non-zero slots, keyed as B256)`, computed incrementally when `addr` is large.
    pub(crate) fn storage_root<S: std::hash::BuildHasher>(
        &mut self,
        addr: &Address,
        storage: &HashMap<U256, U256, S>,
    ) -> B256 {
        if storage.len() < LARGE_STORAGE_SLOTS {
            self.forget(addr);
            return full_root(storage);
        }
        let Some(cached) = self.by_addr.get_mut(addr) else {
            let nonzero: HashMap<U256, U256> =
                storage.iter().filter(|(_, v)| !v.is_zero()).map(|(s, v)| (*s, *v)).collect();
            if self.cached_slots + nonzero.len() > MAX_CACHED_SLOTS {
                return full_root(storage);
            }
            let t = StorageTrie::build(nonzero);
            let root = t.root;
            self.cached_slots += t.values.len();
            self.by_addr.insert(*addr, t);
            return root;
        };

        // Diff the account's slots against what the cached trie holds.
        let mut changed: Vec<(U256, U256)> = Vec::new();
        let (mut unchanged, mut updated) = (0usize, 0usize);
        for (slot, value) in storage {
            if value.is_zero() {
                continue;
            }
            match cached.values.get(slot) {
                Some(old) if old == value => unchanged += 1,
                Some(_) => {
                    updated += 1;
                    changed.push((*slot, *value));
                }
                None => changed.push((*slot, *value)),
            }
        }
        // Cached slots no longer present: only scan for them if the counts say there are some.
        let mut removed: Vec<U256> = Vec::new();
        if cached.values.len() > unchanged + updated {
            removed = cached
                .values
                .keys()
                .filter(|s| storage.get(*s).is_none_or(U256::is_zero))
                .copied()
                .collect();
        }
        if changed.is_empty() && removed.is_empty() {
            return cached.root;
        }

        let before = cached.values.len();
        let new_len = before + (changed.len() - updated) - removed.len();
        if self.cached_slots - before + new_len > MAX_CACHED_SLOTS {
            self.forget(addr);
            return full_root(storage);
        }
        let root = if changed.len() + removed.len() > before.max(1) / REBUILD_DIVISOR {
            let nonzero: HashMap<U256, U256> =
                storage.iter().filter(|(_, v)| !v.is_zero()).map(|(s, v)| (*s, *v)).collect();
            *cached = StorageTrie::build(nonzero);
            cached.root
        } else {
            cached.apply(&changed, &removed)
        };
        self.cached_slots = self.cached_slots - before + cached.values.len();
        root
    }
}

/// The full storage root of a slot map (the pre-existing computation; also the reference in tests).
fn full_root<S: std::hash::BuildHasher>(storage: &HashMap<U256, U256, S>) -> B256 {
    trie::storage_root(
        storage
            .iter()
            .filter(|(_, value)| !value.is_zero())
            .map(|(slot, value)| (B256::from_slice(&slot.to_be_bytes::<32>()), *value)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift so failures reproduce without a rand dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn addr() -> Address {
        Address::from([0xAB; 20])
    }

    fn storage_of(n: u64) -> revm::primitives::HashMap<U256, U256> {
        (0..n).map(|i| (U256::from(i), U256::from(i * 7 + 1))).collect()
    }

    /// The cached root equals the full recompute for the first build and after every single-slot update
    /// (the history contract's pattern: one slot of an 8,191-slot ring changes per block).
    #[test]
    fn ring_buffer_updates_match_the_full_root() {
        let mut tries = LargeStorageTries::default();
        let mut storage = storage_of(8_191);
        assert_eq!(tries.storage_root(&addr(), &storage), full_root(&storage), "first build");
        for h in 1..=200u64 {
            storage.insert(U256::from(h % 8_191), U256::from(h.wrapping_mul(0x9E37_79B9)));
            assert_eq!(tries.storage_root(&addr(), &storage), full_root(&storage), "block {h}");
        }
        assert_eq!(tries.len(), 1);
    }

    /// Random inserts, updates, deletions (to zero and by removal) and bulk changes, interleaved with
    /// reads at every step: always the full root.
    #[test]
    fn random_mutations_match_the_full_root() {
        for seed in 1..=6u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut tries = LargeStorageTries::default();
            let mut storage = storage_of(2_000);
            for step in 0..120 {
                let ops = match rng.next() % 4 {
                    0 => 1,
                    1 => 8,
                    2 => 60,
                    _ => 700, // exceeds the rebuild threshold
                };
                for _ in 0..ops {
                    let slot = U256::from(rng.next() % 4_000);
                    match rng.next() % 5 {
                        0 => {
                            storage.remove(&slot);
                        }
                        1 => {
                            storage.insert(slot, U256::ZERO); // a zero write deletes
                        }
                        _ => {
                            storage.insert(slot, U256::from(rng.next() | 1));
                        }
                    }
                }
                assert_eq!(
                    tries.storage_root(&addr(), &storage),
                    full_root(&storage),
                    "seed {seed} step {step}"
                );
            }
        }
    }

    /// The cache is checked against the real storage each time, so state going backwards (a rollback or
    /// a snapshot import replacing the account) still gives the right root.
    #[test]
    fn a_rolled_back_account_still_gives_the_right_root() {
        let mut tries = LargeStorageTries::default();
        let mut storage = storage_of(3_000);
        let _ = tries.storage_root(&addr(), &storage);
        let snapshot = storage.clone();
        for i in 0..40u64 {
            storage.insert(U256::from(i), U256::from(1_000_000 + i));
        }
        let _ = tries.storage_root(&addr(), &storage);
        // Roll the account back to the snapshot, and then to something unrelated.
        assert_eq!(tries.storage_root(&addr(), &snapshot), full_root(&snapshot));
        let unrelated: revm::primitives::HashMap<U256, U256> =
            (10_000..13_000u64).map(|i| (U256::from(i), U256::from(i))).collect();
        assert_eq!(tries.storage_root(&addr(), &unrelated), full_root(&unrelated));
    }

    /// An account that shrinks below the threshold, or empties, leaves the cache and still hashes right;
    /// the empty root is the empty-trie constant.
    #[test]
    fn shrinking_below_the_threshold_drops_the_cache_entry() {
        let mut tries = LargeStorageTries::default();
        let mut storage = storage_of(1_500);
        let _ = tries.storage_root(&addr(), &storage);
        assert_eq!(tries.len(), 1);
        storage.retain(|slot, _| *slot < U256::from(100u64));
        assert_eq!(tries.storage_root(&addr(), &storage), full_root(&storage));
        assert_eq!(tries.len(), 0, "a small account holds no cache entry");
        storage.clear();
        assert_eq!(tries.storage_root(&addr(), &storage), trie::EMPTY_ROOT);
    }

    /// A trie that loses almost all its slots but stays above the threshold, then grows back.
    #[test]
    fn heavy_shrink_then_regrow_matches() {
        let mut tries = LargeStorageTries::default();
        let mut storage = storage_of(4_000);
        let _ = tries.storage_root(&addr(), &storage);
        storage.retain(|slot, _| *slot < U256::from(520u64));
        assert_eq!(tries.storage_root(&addr(), &storage), full_root(&storage));
        for i in 5_000..9_000u64 {
            storage.insert(U256::from(i), U256::from(i + 1));
        }
        assert_eq!(tries.storage_root(&addr(), &storage), full_root(&storage));
    }

    /// Past the global slot budget an account falls back to the full computation (and stays correct).
    #[test]
    fn the_slot_budget_falls_back_to_the_full_root() {
        let mut tries =
            LargeStorageTries { cached_slots: MAX_CACHED_SLOTS - 100, ..Default::default() };
        let storage = storage_of(1_000);
        assert_eq!(tries.storage_root(&addr(), &storage), full_root(&storage));
        assert_eq!(tries.len(), 0, "over budget: no entry is created");
    }

    /// Two accounts keep independent tries.
    #[test]
    fn accounts_do_not_share_state() {
        let (a, b) = (Address::from([1; 20]), Address::from([2; 20]));
        let mut tries = LargeStorageTries::default();
        let (mut sa, sb) = (storage_of(2_000), storage_of(3_000));
        assert_eq!(tries.storage_root(&a, &sa), full_root(&sa));
        assert_eq!(tries.storage_root(&b, &sb), full_root(&sb));
        sa.insert(U256::from(5u64), U256::from(99u64));
        assert_eq!(tries.storage_root(&a, &sa), full_root(&sa));
        assert_eq!(tries.storage_root(&b, &sb), full_root(&sb), "b is unaffected by a's change");
    }

    /// Timing, not a gate: one-slot updates of an 8,191-slot ring, incremental versus full.
    /// `cargo test -p evm --release storage_trie_timing -- --ignored --nocapture`
    #[test]
    #[ignore = "timing report"]
    fn storage_trie_timing() {
        let mut storage = storage_of(8_191);
        let mut tries = LargeStorageTries::default();
        let _ = tries.storage_root(&addr(), &storage);
        let n = 2_000u32;
        let t = std::time::Instant::now();
        for h in 1..=u64::from(n) {
            storage.insert(U256::from(h % 8_191), U256::from(h.wrapping_mul(0x9E37_79B9)));
            std::hint::black_box(tries.storage_root(&addr(), &storage));
        }
        let inc = t.elapsed();
        let t = std::time::Instant::now();
        for h in 1..=u64::from(n) {
            storage.insert(U256::from(h % 8_191), U256::from(h.wrapping_mul(0x9E37_79B9)));
            std::hint::black_box(full_root(&storage));
        }
        let full = t.elapsed();
        println!(
            "8,191-slot ring, one slot per block: incremental {:.1} us/block, full {:.1} us/block, {:.1}x",
            inc.as_secs_f64() * 1e6 / f64::from(n),
            full.as_secs_f64() * 1e6 / f64::from(n),
            full.as_secs_f64() / inc.as_secs_f64()
        );
    }
}
