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
/// - **Registered addresses** (non-canonical, hash-derived — i.e.
///   every real account): a lock-free probe of the insert-only
///   [`RegTable`] (acquire loads only, no RMW — readers never touch
///   a shared mutable word) plus the same per-account atomic ops as
///   the flat tier. Registration happens once per address under a
///   claim mutex; all subsequent ops on that account are as
///   concurrent as flat ops. Previously every production address
///   serialized on a single `Mutex<HashMap>` — one global lock
///   across all markets — so the published multi-market numbers
///   did not describe real-address traffic at all.
/// - **Sparse overflow** (registered ids beyond `reg` capacity):
///   the `Mutex<HashMap>` remains only for that unreachable-at-
///   sane-capacity case.
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
    /// `reg[i]` = balance of the non-canonical address assigned id
    /// `i` by [`Self::resolve`]. Same atomic ops as `flat`, behind
    /// one registry lookup — this is the tier real (hash-derived)
    /// accounts actually run on.
    reg: Vec<std::sync::atomic::AtomicU64>,
    /// `address → reg slot` registry: a fixed-capacity, insert-only,
    /// lock-free-read table. Without this tier every production
    /// address serializes on the one sparse mutex — a global lock
    /// across all markets (the sparse map used to be that path).
    /// A `RwLock<HashMap>` here was measured to be strictly worse
    /// than even that mutex: `std::sync::RwLock::read` is a
    /// read-modify-write on one shared word, so N threads ping a
    /// single cache line per op (plus Darwin's pthread-rwlock fast
    /// path is slower than a mutex acquire to begin with).
    reg_ids: RegTable,
    /// Overflow when `reg` is exhausted (registered accounts >
    /// capacity). Full 20-byte key, so arbitrary addresses can
    /// never alias a flat or reg slot.
    sparse: std::sync::Mutex<HashMap<[u8; 20], u64>>,
}

/// Backwards-compatible alias: the type was previously a
/// per-shard `Mutex<HashMap>` design named `ShardedBalanceCache`.
/// The constructor's argument changed meaning (was shard count, is
/// now flat capacity) — see [`AtomicBalanceCache::new`].
pub type ShardedBalanceCache = AtomicBalanceCache;

/// Cell state word values for [`RegTable`]. The low 2 bits carry
/// the state; once `CELL_READY` the high 32 bits carry `key_hi`.
const CELL_EMPTY: u64 = 0;
const CELL_CLAIMING: u64 = 1;
const CELL_READY: u64 = 2;
/// State-word mask for the low state bits.
const CELL_STATE_MASK: u64 = 3;

/// Fixed-capacity, insert-only, open-addressing `address → slot`
/// table with lock-free reads.
///
/// # Design
///
/// Each cell is four `AtomicU64` words: `[state|key_hi, key_lo,
/// key_mid, slot]` — the state word doubles as the publication flag
/// and carries the top 4 key bytes, so a single acquire load both
/// gates the read and supplies a third of the key. Addresses are
/// immutable after insertion and cells are never deleted, so a
/// reader can trust a `READY` cell's contents forever — the whole
/// read path is a hash, one or two acquire loads, and a compare:
/// no read-modify-write, no locks, no cache-line bouncing.
///
/// Insertion is once per address for the life of the cache and runs
/// under `claim_mu` (cold path only): CAS the state word
/// `EMPTY → CLAIMING`, write the key/slot words, then publish with
/// a `READY` release store. A reader that lands on a `CLAIMING`
/// cell spins — the publisher is ~4 stores away, so the wait is
/// bounded and there is no unwind point between claim and publish.
///
/// Probing is linear. Because cells never return to `EMPTY`, an
/// `EMPTY` cell on a key's probe sequence proves the key absent:
/// any earlier claimant for it would have taken that cell first.
///
/// # Capacity
///
/// `cells` is sized to the next power of two above `2 × reg`
/// capacity, keeping the load factor ≤ 0.5 (≈1–2 probes per
/// lookup). Registration beyond that gives up and the caller falls
/// back to the sparse map — correctness never depends on the
/// table having room.
struct RegTable {
    /// `[state|key_hi, key_lo, key_mid, slot]` per cell; `cells.len()`
    /// is a power of two so `hash & mask` probes wrap cheaply.
    cells: Vec<[std::sync::atomic::AtomicU64; 4]>,
    /// `cells.len() - 1`, applied to the probe hash.
    mask: usize,
    /// Next `reg` slot to hand out. Assigned at cell-claim time —
    /// one per inserted address, never reused. Ordering is handled
    /// by the cell's release/acquire publication, so Relaxed here.
    next: std::sync::atomic::AtomicUsize,
    /// Serializes claimants. Only taken on the first sighting of an
    /// address — steady-state ops never touch it.
    claim_mu: std::sync::Mutex<()>,
}

impl RegTable {
    /// Build a table sized for `reg_capacity` accounts (load ≤ 0.5).
    fn new(reg_capacity: usize) -> Self {
        let len = (reg_capacity.saturating_mul(2)).max(16).next_power_of_two();
        let mut cells = Vec::with_capacity(len);
        cells.resize_with(len, Default::default);
        Self {
            mask: len - 1,
            cells,
            next: std::sync::atomic::AtomicUsize::new(0),
            claim_mu: std::sync::Mutex::new(()),
        }
    }

    /// Split an address into the `(lo, mid, hi)` key triple — the
    /// full 20 bytes, so distinct addresses can never alias.
    #[inline]
    fn key(addr: &[u8; 20]) -> (u64, u64, u32) {
        (
            u64::from_le_bytes([
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
            ]),
            u64::from_le_bytes([
                addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
            ]),
            u32::from_le_bytes([addr[16], addr[17], addr[18], addr[19]]),
        )
    }

    /// Probe-start hash. Production addresses are already
    /// hash-shaped (near-uniform), so a single multiply-mix of the
    /// folded key parts is enough — no avalanche needed for a
    /// linear-probe start index.
    #[inline]
    fn hash(lo: u64, mid: u64, hi: u32) -> u64 {
        // Fibonacci hashing constant (2^64 / φ); mixes the folded
        // key into the high bits that `& mask` then selects.
        const MIX: u64 = 0x9E37_79B9_7F4A_7C15;
        (lo ^ mid.rotate_left(31) ^ u64::from(hi).rotate_left(47)).wrapping_mul(MIX)
    }

    /// `hash % cells.len()` as a usize — the mask bounds the value
    /// to the table length, which fits `usize` by construction.
    #[inline]
    fn probe_start(&self, lo: u64, mid: u64, hi: u32) -> usize {
        usize::try_from(Self::hash(lo, mid, hi) & self.mask as u64).unwrap_or(0)
    }

    /// Read a cell's slot word — stored from a `u32`, so the
    /// `try_from` fallback is unreachable; `u32::MAX` maps to
    /// `Slot::Sparse` anyway, so even a torn read can't alias.
    #[inline]
    fn cell_slot(cell: &[std::sync::atomic::AtomicU64; 4]) -> u32 {
        u32::try_from(cell[3].load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(u32::MAX)
    }

    /// Look up `addr`. `Some(slot)` if registered; `None` if provably
    /// absent (first `EMPTY` cell on its probe sequence).
    ///
    /// Lock-free: only acquire/relaxed loads — this is the hot path
    /// shared by every balance op on a registered address.
    #[inline]
    fn get(&self, addr: &[u8; 20]) -> Option<u32> {
        let (lo, mid, hi) = Self::key(addr);
        let mut i = self.probe_start(lo, mid, hi);
        // Bounded scan: a full table has no EMPTY terminator, so
        // stop after one lap instead of probing forever.
        for _ in 0..self.cells.len() {
            let cell = &self.cells[i];
            let state = cell[0].load(std::sync::atomic::Ordering::Acquire);
            match state & CELL_STATE_MASK {
                CELL_EMPTY => return None,
                CELL_CLAIMING => {
                    // Publisher is mid-insert (~4 stores away, no
                    // unwind point) — spin the same cell rather than
                    // skip a possible match.
                    std::hint::spin_loop();
                }
                _ => {
                    // READY: the acquire load above pairs with the
                    // publisher's release store, ordering the key and
                    // slot writes before this read.
                    if u32::try_from(state >> 32).unwrap_or(u32::MAX) == hi
                        && cell[1].load(std::sync::atomic::Ordering::Relaxed) == lo
                        && cell[2].load(std::sync::atomic::Ordering::Relaxed) == mid
                    {
                        return Some(Self::cell_slot(cell));
                    }
                    i = (i + 1) & self.mask;
                }
            }
        }
        None
    }

    /// Look up `addr`, registering it to a fresh `reg` slot on first
    /// sight. `None` only when the table itself is full — the caller
    /// then routes the address to the sparse overflow map.
    fn get_or_register(&self, addr: &[u8; 20]) -> Option<u32> {
        if let Some(slot) = self.get(addr) {
            return Some(slot);
        }
        // Cold path: serialize claimants, then re-check (another
        // thread may have registered the same address while we
        // waited — the registry must stay a bijection).
        let _guard = self.claim_mu.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = self.get(addr) {
            return Some(slot);
        }
        let (lo, mid, hi) = Self::key(addr);
        let mut i = self.probe_start(lo, mid, hi);
        for _ in 0..self.cells.len() {
            let cell = &self.cells[i];
            let state = cell[0].load(std::sync::atomic::Ordering::Acquire);
            match state & CELL_STATE_MASK {
                CELL_EMPTY => {
                    // Under `claim_mu` no other claimant exists; a
                    // spurious CAS failure cannot occur, but a retry
                    // costs nothing either way.
                    if cell[0]
                        .compare_exchange(
                            CELL_EMPTY,
                            CELL_CLAIMING,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }
                    let slot =
                        u32::try_from(self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                            .unwrap_or(u32::MAX);
                    cell[1].store(lo, std::sync::atomic::Ordering::Relaxed);
                    cell[2].store(mid, std::sync::atomic::Ordering::Relaxed);
                    cell[3].store(u64::from(slot), std::sync::atomic::Ordering::Relaxed);
                    // Publish last: the release store orders all key/
                    // slot writes before any reader's acquire on
                    // this word can observe READY.
                    cell[0].store(
                        (u64::from(hi) << 32) | CELL_READY,
                        std::sync::atomic::Ordering::Release,
                    );
                    return Some(slot);
                }
                CELL_CLAIMING => {
                    // Unreachable under the mutex (claims never
                    // unwind mid-sequence), but spin to a definite
                    // state rather than trusting that.
                    std::hint::spin_loop();
                }
                _ => {
                    if u32::try_from(state >> 32).unwrap_or(u32::MAX) == hi
                        && cell[1].load(std::sync::atomic::Ordering::Relaxed) == lo
                        && cell[2].load(std::sync::atomic::Ordering::Relaxed) == mid
                    {
                        // Same address, mid-probe match — must not
                        // happen after the re-check above, but a
                        // double-claim would alias two slots to one
                        // address. Returning the existing slot is
                        // always the safe answer.
                        return Some(Self::cell_slot(cell));
                    }
                    i = (i + 1) & self.mask;
                }
            }
        }
        None
    }

    /// Number of registered addresses (test/statistics path).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.next.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Which balance word an address resolves to — see
/// [`AtomicBalanceCache::resolve`].
enum Slot {
    /// Direct index into `flat` — canonical `[u32 LE][0;16]`
    /// addresses (benchmark/test convention).
    Flat(usize),
    /// Registry id into `reg` — a hash-derived address that claimed
    /// a real atomic slot at first sight.
    Reg(u32),
    /// No atomic word — the address lives in the sparse overflow
    /// map (only when `reg` capacity is exhausted).
    Sparse,
}

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
        // `reg` mirrors `flat`'s capacity: the registry can seat as
        // many hash-derived accounts as canonical ones before any
        // traffic reaches the sparse overflow map.
        let mut reg = Vec::with_capacity(capacity);
        reg.resize_with(capacity, || std::sync::atomic::AtomicU64::new(0));
        Self {
            flat,
            reg,
            reg_ids: RegTable::new(capacity),
            sparse: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Create with the default capacity (1M accounts).
    #[must_use]
    pub fn with_default_shards() -> Self {
        Self::new(DEFAULT_SHARD_COUNT)
    }

    /// Where an address's balance word lives — resolved once per
    /// operation. `Flat`/`Reg` are plain atomic slots; `Sparse` is
    /// the mutex map (overflow only).
    #[inline]
    fn resolve(&self, addr: &Address) -> Slot {
        if is_flat(addr, self.flat.len()) {
            return Slot::Flat(addr_index(addr));
        }
        // Hot path for real accounts: lock-free registry probe —
        // a handful of acquire loads, no RMW, no locks — then a
        // plain atomic op on the account's `reg` word. First sight
        // of an address claims a slot on the cold path
        // (`claim_mu`), once per address for the life of the cache.
        match self.reg_ids.get_or_register(&addr.0) {
            Some(id) => self.slot_for_id(id),
            // Registry table itself full (≫ capacity accounts):
            // unregistered addresses land on the sparse map, which
            // is keyed by the full 20-byte address — no aliasing.
            None => Slot::Sparse,
        }
    }

    /// Map a registry id to its tier: inside `reg` capacity it is a
    /// real atomic slot; beyond it, the sparse overflow map.
    #[inline]
    fn slot_for_id(&self, id: u32) -> Slot {
        if (id as usize) < self.reg.len() { Slot::Reg(id) } else { Slot::Sparse }
    }

    /// The atomic word behind a resolved slot, or `None` for the
    /// sparse overflow map (which has no single word).
    #[inline]
    fn word(&self, slot: Slot) -> Option<&std::sync::atomic::AtomicU64> {
        match slot {
            Slot::Flat(i) => Some(&self.flat[i]),
            Slot::Reg(i) => Some(&self.reg[i as usize]),
            Slot::Sparse => None,
        }
    }

    /// Get an account's balance (0 if not funded). Flat/registered
    /// path: one shared registry read + one atomic load. Sparse
    /// path: locked `HashMap` read.
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex or the registry lock is poisoned.
    #[inline]
    pub fn get(&self, addr: &Address) -> u64 {
        match self.word(self.resolve(addr)) {
            Some(word) => word.load(std::sync::atomic::Ordering::Acquire),
            None => self
                .sparse
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&addr.0)
                .copied()
                .unwrap_or(0),
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
        match self.word(self.resolve(addr)) {
            Some(word) => word.store(amount, std::sync::atomic::Ordering::Release),
            None => {
                self.sparse
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(addr.0, amount);
            }
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
        let Some(word) = self.word(self.resolve(addr)) else {
            let mut sparse = self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = sparse.entry(addr.0).or_insert(0);
            *entry = entry.saturating_add(amount);
            return;
        };
        // `fetch_update` retries the CAS under contention; the
        // closure always returns Some so this cannot fail.
        let _ = word.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |b| Some(b.saturating_add(amount)),
        );
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
        let Some(word) = self.word(self.resolve(addr)) else {
            let mut sparse = self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = sparse.entry(addr.0).or_insert(0);
            *entry = entry.saturating_sub(amount);
            return;
        };
        let _ = word.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |b| Some(b.saturating_sub(amount)),
        );
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
        let Some(word) = self.word(self.resolve(addr)) else {
            let mut sparse = self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = sparse.entry(addr.0).or_insert(0);
            if *entry >= amount {
                *entry -= amount;
                return true;
            }
            return false;
        };
        word.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |b| b.checked_sub(amount),
        )
        .is_ok()
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
        // `word()` yields `None` exactly for the sparse overflow
        // tier, so matching on the resolved words makes the four
        // cases exhaustive without an unwrap: `None` arms are the
        // sparse side.
        match (self.word(self.resolve(from)), self.word(self.resolve(to))) {
            (None, None) => {
                // Both ends in the overflow map: one lock covers the
                // check-and-move atomically.
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
            (None, Some(to_word)) => {
                // Debit the sparse side under its lock first (the
                // insolvency check is atomic w.r.t. other sparse
                // ops); only then credit the atomic side.
                {
                    let mut sparse =
                        self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    let entry = sparse.entry(from.0).or_insert(0);
                    if *entry < amount {
                        return false;
                    }
                    *entry -= amount;
                }
                let _ = to_word.fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |b| Some(b.saturating_add(amount)),
                );
                true
            }
            (Some(from_word), None) => {
                // CAS-debit the atomic side first; on success credit
                // the sparse side under its lock.
                if from_word
                    .fetch_update(
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                        |b| b.checked_sub(amount),
                    )
                    .is_err()
                {
                    return false;
                }
                let mut sparse =
                    self.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let entry = sparse.entry(to.0).or_insert(0);
                *entry = entry.saturating_add(amount);
                true
            }
            (Some(from_word), Some(to_word)) => {
                // Both ends are atomic words (any flat/reg mix):
                // CAS-debit `from` — the linearization point — then
                // saturating-credit `to`, which cannot fail.
                if from_word
                    .fetch_update(
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                        |b| b.checked_sub(amount),
                    )
                    .is_err()
                {
                    return false; // insolvent — nothing moved
                }
                let _ = to_word.fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |b| Some(b.saturating_add(amount)),
                );
                true
            }
        }
    }

    /// Number of accounts with non-zero balance across all three
    /// tiers (flat, registered, sparse). `O(capacity)` on both atomic
    /// arrays — a debug/stats path, not hot.
    ///
    /// # Panics
    ///
    /// Panics if the sparse mutex is poisoned.
    pub fn len(&self) -> usize {
        let count = |arr: &[std::sync::atomic::AtomicU64]| {
            arr.iter().filter(|a| a.load(std::sync::atomic::Ordering::Acquire) > 0).count()
        };
        let sparse = self
            .sparse
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|&&b| b > 0)
            .count();
        count(&self.flat) + count(&self.reg) + sparse
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

    // ── Registered-address (reg) tier tests ─────────────────────
    //
    // Production addresses are Ed25519-key-derived — hash-shaped,
    // non-zero tail — so `is_flat` rejects them. Before the registry
    // tier they all serialized on the single sparse mutex.

    /// A hash-shaped address: index bytes from `seed`, tail non-zero
    /// so `is_flat` is false regardless of the index value.
    fn hash_addr(seed: u64) -> Address {
        let mut a = [0u8; 20];
        a[..8].copy_from_slice(&seed.to_le_bytes());
        for b in &mut a[8..] {
            *b = 0xAB;
        }
        Address(a)
    }

    /// Registered hash addresses get real atomic slots: the op must
    /// NOT route through the sparse mutex map.
    #[test]
    fn registered_address_uses_reg_slot_not_sparse() {
        let cache = AtomicBalanceCache::new(8);
        let addr = hash_addr(1);
        cache.set(&addr, 7_000);
        assert_eq!(cache.get(&addr), 7_000);
        assert!(
            cache.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_empty(),
            "a registered address must not touch the sparse map"
        );
        // One registration entry, stable across repeated ops.
        cache.credit(&addr, 1);
        cache.debit(&addr, 1);
        assert_eq!(cache.reg_ids.len(), 1);
        assert_eq!(cache.get(&addr), 7_000);
    }

    /// Two distinct hash addresses must claim distinct slots — full
    /// 20-byte identity, no aliasing even when index bytes collide
    /// with the flat range.
    #[test]
    fn registered_addresses_do_not_alias() {
        let cache = AtomicBalanceCache::new(8);
        let a = hash_addr(1);
        let b = hash_addr(2);
        // Same first-4 index as `a`, different tail — must not share
        // a's slot, and must not alias the flat slot for that index.
        let mut raw = a.0;
        raw[19] ^= 0xFF;
        let c = Address(raw);

        cache.set(&a, 100);
        cache.set(&b, 200);
        cache.set(&c, 300);
        assert_eq!(cache.get(&a), 100);
        assert_eq!(cache.get(&b), 200);
        assert_eq!(cache.get(&c), 300);
        assert_eq!(cache.reg_ids.len(), 3);
        cache.debit(&c, 50);
        assert_eq!(cache.get(&a), 100, "mutating c must not touch a");
        assert_eq!(cache.get(&c), 250);
    }

    /// Once `reg` capacity is exhausted, further addresses fall back
    /// to the sparse map — and still behave correctly.
    #[test]
    fn registry_exhaustion_falls_back_to_sparse() {
        let cache = AtomicBalanceCache::new(1); // flat = reg = 1 slot
        let seated = hash_addr(1);
        let overflow = hash_addr(2);
        cache.set(&seated, 1_000);
        cache.set(&overflow, 2_000);

        assert_eq!(cache.get(&seated), 1_000);
        assert_eq!(cache.get(&overflow), 2_000);
        assert_eq!(
            cache.sparse.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len(),
            1,
            "exactly the overflow account must live in sparse"
        );
        // Ops on the overflow account still work.
        assert!(cache.check_and_debit(&overflow, 500));
        assert!(!cache.check_and_debit(&overflow, 10_000));
        assert_eq!(cache.get(&overflow), 1_500);
    }

    /// Transfers across every tier combination: flat↔reg↔sparse.
    #[test]
    fn transfer_across_tiers() {
        let cache = AtomicBalanceCache::new(1); // reg holds one address
        let flat = addr_idx(0);
        let reg = hash_addr(1);
        let sparse = hash_addr(2); // reg exhausted → sparse
        cache.set(&flat, 1_000);
        cache.set(&reg, 1_000);
        cache.set(&sparse, 1_000);

        // flat → reg
        assert!(cache.transfer(&flat, &reg, 100));
        // reg → sparse
        assert!(cache.transfer(&reg, &sparse, 200));
        // sparse → flat
        assert!(cache.transfer(&sparse, &flat, 300));
        // insolvent across tiers moves nothing
        assert!(!cache.transfer(&flat, &sparse, 99_999));

        assert_eq!(cache.get(&flat), 1_000 - 100 + 300);
        assert_eq!(cache.get(&reg), 1_000 + 100 - 200);
        assert_eq!(cache.get(&sparse), 1_000 + 200 - 300);
    }

    /// Same-account debits on a registered address: identical
    /// concurrency semantics to flat — no overdraw, no serialization
    /// visible to the caller.
    #[test]
    fn concurrent_debit_on_registered_account() {
        let cache = Arc::new(AtomicBalanceCache::new(64));
        let addr = hash_addr(7);
        cache.set(&addr, 1_000);
        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || cache.check_and_debit(&addr, 100)));
        }
        let successes = handles.into_iter().map(|h| h.join().unwrap()).filter(|ok| *ok).count();
        assert_eq!(successes, 10);
        assert_eq!(cache.get(&addr), 0);
    }

    /// Many threads registering distinct addresses concurrently:
    /// every address gets its own slot (or a sparse fallback), never
    /// a shared balance.
    #[test]
    fn concurrent_registration_never_aliases() {
        let cache = Arc::new(AtomicBalanceCache::new(256));
        let mut handles = Vec::new();
        for seed in 0..64u64 {
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || {
                let addr = hash_addr(seed);
                cache.set(&addr, seed + 1);
                cache.credit(&addr, 1);
                cache.get(&addr)
            }));
        }
        for (seed, h) in handles.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), seed as u64 + 2, "seed {seed} lost its balance");
        }
        assert_eq!(cache.reg_ids.len(), 64);
    }

    /// `len` counts funded accounts across all three tiers.
    #[test]
    fn len_counts_all_tiers() {
        let cache = AtomicBalanceCache::new(1);
        cache.set(&addr_idx(0), 10); // flat
        cache.set(&hash_addr(1), 20); // reg
        cache.set(&hash_addr(2), 30); // sparse (reg exhausted)
        cache.set(&hash_addr(3), 0); // sparse, zero balance — not counted
        assert_eq!(cache.len(), 3);
        assert!(!cache.is_empty());
    }
}
