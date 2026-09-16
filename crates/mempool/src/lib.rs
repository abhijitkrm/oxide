//! Oxide mempool — fee-priority transaction pool.
//!
//! The mempool is the application's intake buffer: transactions arrive
//! here (via `submit_tx`), are deduplicated by hash, indexed by sender
//! for nonce ordering, and selected by fee priority when the leader
//! calls `prepare_proposal`.
//!
//! # Design (plan.md §1, §6)
//!
//! - **Fee-priority selection:** transactions are ranked by fee density
//!   (fee per byte) so the leader maximizes value per block.
//! - **Per-account nonce queues:** each sender's transactions are kept
//!   in nonce order; the leader drains them sequentially. This prevents
//!   nonce gaps and matches the EVM account model.
//! - **Dedup:** transactions with the same hash are acknowledged but
//!   not double-counted (OAI §2, `ingest_tx` idempotence).
//! - **Eviction:** when the pool is full, the lowest-fee transactions
//!   are evicted to make room for higher-fee ones.
//!
//! # Hot-path discipline
//!
//! The mempool is NOT on the per-order matching hot path (that's the
//! trading engine). It IS on the per-block proposal path, which runs
//! at 50–100ms cadence. Allocations here are per-block, not per-tx:
//! the pool reuses its `Vec` capacity across `prepare_proposal` calls.
//! The `select` method returns a `Vec<TxBytes>` by draining selected
//! entries; the caller owns the allocation.
//!
//! # Phase 1 scope
//!
//! v0 is a simple in-memory pool with fee-priority selection and
//! per-account nonce tracking. No rate limiting, no eviction policy
//! beyond size cap, no mempool gossip. Those arrive in Phase 2+.

use std::collections::{BTreeMap, HashMap};

use primitives::{Address, Hash};
use types::TxBytes;

use crypto::hash::{Domain, Hasher};

/// A transaction in the mempool, with its precomputed hash and fee
/// metadata.
///
/// The hash is precomputed on insertion to avoid re-hashing on every
/// dedup check and selection pass. The fee and nonce are parsed from
/// the transaction bytes; in v0 we use a simple fixed-layout encoding
/// (see `parse_tx`).
#[derive(Debug, Clone)]
struct PoolEntry {
    /// The transaction bytes, as submitted.
    tx: TxBytes,
    /// Precomputed hash for dedup.
    #[allow(dead_code)]
    hash: Hash,
    /// The sender's address.
    sender: Address,
    /// The account nonce this tx consumes.
    nonce: u64,
    /// The fee (in raw units) the tx pays.
    fee: u64,
    /// The serialized size in bytes (precomputed).
    size: u64,
}

/// The mempool: a fee-priority transaction pool with per-account nonce
/// queues and dedup.
///
/// All state is in plain `HashMap`/`BTreeMap` — this is per-block
/// cadence, not per-order. The pool is owned by the app and accessed
/// via `&mut self` (no `Mutex` needed — the app is single-threaded
/// in the deterministic runtime).
pub struct Mempool {
    /// All entries, indexed by tx hash for O(1) dedup.
    by_hash: HashMap<Hash, PoolEntry>,
    /// Per-sender nonce-ordered queues. `BTreeMap<nonce, hash>` gives
    /// us nonce-ordered iteration per sender for free.
    by_sender: HashMap<Address, BTreeMap<u64, Hash>>,
    /// The fee-priority index: fee density (fee/size) → set of tx
    /// hashes at that density. `BTreeMap` ordered by key gives us
    /// highest-fee-first iteration by reversing.
    by_fee: BTreeMap<FeeDensity, Vec<Hash>>,
    /// Maximum number of transactions in the pool. Beyond this, the
    /// lowest-fee entries are evicted.
    max_entries: usize,
    /// Maximum txs a single sender can occupy in one `select` call.
    /// Without a cap, one sender submitting N sequential nonces (at
    /// top fee) monopolizes the whole block — a liveness `DoS` on
    /// every other account. The cap bounds any sender's block
    /// share regardless of fee.
    max_per_sender: usize,
    /// Per-sender last executed nonce (HIGH fix). The mempool
    /// anchors selection to `executed_nonce + 1` — a tx with a
    /// lower nonce is stale (already executed) and a tx with a
    /// higher nonce can't be selected until the gap is filled.
    /// Without this, `select` started at the minimum queued nonce,
    /// which could be a mid-chain nonce after earlier txs executed,
    /// creating a nonce gap in the block.
    executed_nonces: HashMap<Address, u64>,
}

/// Default per-sender selection cap: 1000 txs per block.
///
/// Bounds any single account to at most 1000 txs in a proposed
/// block — at the typical 1 MB block budget and ~120 B min-tx
/// size that's ~1/8 of block capacity, so even a top-fee spammer
/// cannot starve every other sender. Raise it via
/// [`Mempool::with_max_per_sender`] if a single-account workload
/// (e.g. a sequencer-owned settlement lane) legitimately needs
/// more.
pub const DEFAULT_MAX_PER_SENDER: usize = 1000;

/// Fee density: fee per byte. Higher is better. We store `(fee, size)`
/// and implement `Ord` by cross-multiplication (fee₁·size₂ vs
/// fee₂·size₁) so that `BTreeMap`'s natural ordering (ascending) gives
/// us lowest-density-first; we reverse to get highest-first.
///
/// # Why cross-multiplication, not integer division
///
/// The prior implementation derived `Ord` structurally over `(fee,
/// size)`, which sorts by absolute fee first — not fee-per-byte. Two
/// transactions with fees 100/size 10 (density 10) and 200/size 50
/// (density 4) would rank 200/50 above 100/10 because `200 > 100`,
/// even though 100/10 has the higher density. The doc comment claimed
/// fee-per-byte ordering, but the derived `Ord` did not implement it.
///
/// Cross-multiplication (fee₁·size₂ vs fee₂·size₁) compares the exact
/// rational fee/size without floating point or integer-division
/// truncation. The multiplication is done in `u128` to avoid overflow
/// (max product: `u64::MAX² ≈ 3.4×10³⁸`, which fits in `u128`).
///
/// # Tie-breaking
///
/// When two densities are exactly equal (same fee/size ratio), we
/// tie-break by `(fee, size)` ascending — a deterministic, stable
/// order that does not depend on insertion order or hash randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FeeDensity {
    /// The fee in raw units.
    fee: u64,
    /// The serialized size in bytes.
    size: u64,
}

impl PartialOrd for FeeDensity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FeeDensity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Cross-multiply in u128 to compare fee/size ratios exactly.
        // self.fee / self.size  vs  other.fee / other.size
        // ⟺  self.fee * other.size  vs  other.fee * self.size
        let lhs = u128::from(self.fee) * u128::from(other.size);
        let rhs = u128::from(other.fee) * u128::from(self.size);
        lhs.cmp(&rhs)
            // Tie-break by (fee, size) ascending for deterministic order.
            .then(self.fee.cmp(&other.fee))
            .then(self.size.cmp(&other.size))
    }
}

impl FeeDensity {
    /// Compare two densities by fee-per-byte (descending). We invert
    /// the natural `Ord` by storing as `BTreeMap` and iterating in
    /// reverse.
    #[allow(dead_code)]
    fn density(&self) -> u64 {
        self.fee.checked_div(self.size).unwrap_or(self.fee)
    }
}

/// Minimum fee bump required to replace a pending same-nonce tx.
///
/// geth's legacypool uses `PriceBumpPercent = 10`: a replacement must
/// pay at least 110% of the displaced tx's fee. Without a bump floor,
/// an attacker could replace a victim's pending tx with a same-nonce
/// tx paying 1 wei less, and wallets' "speed up" resubmits would
/// randomly lose to the old entry.
///
/// Compared as `new_fee * 10 >= old_fee * 11` in `u128` (exact, no
/// division truncation, no overflow at u64 fee range).
const REPLACEMENT_BUMP_NUMERATOR: u128 = 11;
const REPLACEMENT_BUMP_DENOMINATOR: u128 = 10;

/// Error returned by `submit`. A rejected transaction is acknowledged
/// but not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// The transaction is already in the pool (dedup hit).
    Duplicate,
    /// The pool is full and this tx's fee is too low to evict anything.
    PoolFull,
    /// The transaction bytes are malformed (couldn't parse sender/nonce/fee).
    Malformed,
    /// A same-nonce tx from this sender is already pending and the
    /// replacement's fee is below the required bump (≥110% of the
    /// displaced fee — geth legacypool `ErrReplaceUnderpriced`).
    ReplacementUnderpriced,
}

/// A simple v0 transaction format: `[sender: 20 bytes][nonce: 8 bytes
/// LE][fee: 8 bytes LE][payload: ...]`. This is NOT the final wire
/// format — it's a test/dev format until the `modules` crate defines
/// the real `Tx` envelope with signatures.
const TX_MIN_SIZE: usize = 20 + 8 + 8;

/// Parse a v0 transaction's sender, nonce, and fee from its bytes.
///
/// Format: `[sender: 20B][nonce: 8B LE][fee: 8B LE][payload: ...]`.
/// Returns `None` if the bytes are too short or the sender is not a
/// valid 20-byte address.
fn parse_tx(bytes: &[u8]) -> Option<(Address, u64, u64)> {
    if bytes.len() < TX_MIN_SIZE {
        return None;
    }
    let sender = Address::from_slice(&bytes[..20]).ok()?;
    let nonce = u64::from_le_bytes(bytes[20..28].try_into().ok()?);
    let fee = u64::from_le_bytes(bytes[28..36].try_into().ok()?);
    Some((sender, nonce, fee))
}

impl Mempool {
    /// Construct an empty mempool with the given capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            by_hash: HashMap::new(),
            by_sender: HashMap::new(),
            by_fee: BTreeMap::new(),
            max_entries,
            max_per_sender: DEFAULT_MAX_PER_SENDER,
            executed_nonces: HashMap::new(),
        }
    }

    /// Set the per-sender selection cap (txs per `select` call).
    #[must_use]
    pub fn with_max_per_sender(mut self, cap: usize) -> Self {
        self.max_per_sender = cap;
        self
    }

    /// Record the last executed nonce for a sender (HIGH fix).
    /// The mempool anchors selection to `executed_nonce + 1` —
    /// transactions with a lower nonce are stale and transactions
    /// with a higher nonce can't be selected until the gap is
    /// filled. Call this after each block commits to keep the
    /// mempool's nonce anchoring fresh.
    pub fn set_executed_nonce(&mut self, sender: Address, nonce: u64) {
        self.executed_nonces.insert(sender, nonce);
    }

    /// Submit a transaction to the pool. Returns `Ok(())` if accepted,
    /// `Err(MempoolError)` if rejected (duplicate, full, or malformed).
    ///
    /// Dedup is by tx hash: a duplicate submission is acknowledged
    /// (OAI §2 idempotence) but not stored twice.
    ///
    /// # Errors
    ///
    /// Returns [`MempoolError::Duplicate`] if the tx is already in the
    /// pool, [`MempoolError::Malformed`] if the bytes can't be parsed,
    /// or [`MempoolError::PoolFull`] if the pool is full and the tx's
    /// fee is too low to evict anything.
    pub fn submit(&mut self, tx: TxBytes) -> Result<(), MempoolError> {
        let bytes = tx.as_bytes();
        let hash = Hasher::hash_one(Domain::Transaction, bytes);

        // Dedup: if we've seen this hash, it's a duplicate.
        if self.by_hash.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }

        // Parse sender, nonce, fee.
        let (sender, nonce, fee) = parse_tx(bytes).ok_or(MempoolError::Malformed)?;
        let size = bytes.len() as u64;
        let density = FeeDensity { fee, size };

        // Same-nonce replacement (geth legacypool semantics): if this
        // sender already has a pending tx at this nonce, the new tx
        // may replace it only if its fee is at least 110% of the old
        // one. The displaced tx is removed from every index — the
        // previous implementation just overwrote the `by_sender` slot,
        // leaking the old entry in `by_hash`/`by_fee` forever (it kept
        // counting toward `max_entries` and could be "evicted" as a
        // ghost) and letting a *lower*-fee resubmit shadow a
        // higher-fee tx.
        if let Some(&old_hash) = self.by_sender.get(&sender).and_then(|q| q.get(&nonce)) {
            if let Some(old) = self.by_hash.get(&old_hash) {
                let bumped = u128::from(fee) * REPLACEMENT_BUMP_DENOMINATOR
                    >= u128::from(old.fee) * REPLACEMENT_BUMP_NUMERATOR;
                if !bumped {
                    return Err(MempoolError::ReplacementUnderpriced);
                }
                // The bump check passed — displace the old entry from
                // all indices. A replacement frees its own slot, so
                // the capacity check below sees the post-removal size.
                self.remove(&old_hash);
            }
            // If `by_sender` holds a hash `by_hash` doesn't know
            // (inconsistent state), the `insert` below overwrites the
            // slot — no orphan is created.
        }

        // If the pool is full, try to evict the lowest-fee entry —
        // but only if the new tx has a higher fee than the lowest.
        if self.by_hash.len() >= self.max_entries {
            // Find the lowest fee density in the pool.
            let lowest_density = self.by_fee.keys().next().copied();
            match lowest_density {
                Some(lowest) if density > lowest => {
                    self.evict_lowest_fee();
                }
                _ => {
                    // Pool is full and the new tx can't outbid anyone.
                    return Err(MempoolError::PoolFull);
                }
            }
        }

        // Insert into all indices.
        let entry = PoolEntry { tx, hash, sender, nonce, fee, size };
        self.by_hash.insert(hash, entry);
        self.by_sender.entry(sender).or_default().insert(nonce, hash);
        self.by_fee.entry(density).or_default().push(hash);
        Ok(())
    }

    /// Submit a batch of transactions to the pool. Returns a Vec of
    /// results, one per input tx, in order. Each result is `Ok(())`
    /// if accepted, `Err(MempoolError)` if rejected.
    ///
    /// This is the batch equivalent of [`submit`](Self::submit). It
    /// amortizes the per-tx overhead (hash computation, index lookups)
    /// across the batch and pre-allocates the result Vec.
    ///
    /// # Errors
    ///
    /// Each tx is processed independently — a rejection for one tx
    /// does not affect the others. See [`submit`](Self::submit) for
    /// the per-tx error cases.
    pub fn submit_batch(&mut self, txs: Vec<TxBytes>) -> Vec<Result<(), MempoolError>> {
        let mut results = Vec::with_capacity(txs.len());
        for tx in txs {
            results.push(self.submit(tx));
        }
        results
    }

    /// Evict the lowest-fee entry from the pool. Returns `true` if an
    /// entry was evicted, `false` if the pool was empty.
    fn evict_lowest_fee(&mut self) -> bool {
        // The lowest fee density is the first key in `by_fee` (ascending).
        let Some(lowest_density) = self.by_fee.keys().next().copied() else {
            return false;
        };
        // Get the hash list for this fee density. The key exists
        // (we just got it from `keys().next()`), but use `?`-style
        // guards instead of `expect` to avoid panicking on a
        // corrupted internal state — return `false` (no eviction)
        // and let the caller retry.
        let Some(hashes) = self.by_fee.get_mut(&lowest_density) else {
            return false;
        };
        // `by_fee` is lazily pruned — `select` no longer filters
        // buckets per block, so a bucket may hold hashes already
        // selected out of the pool. Skip stale entries and only
        // evict a hash that still exists in `by_hash`.
        let hash = loop {
            match hashes.pop() {
                Some(h) if self.by_hash.contains_key(&h) => break h,
                Some(_) => {} // stale — already selected
                None => {
                    // Bucket drained (all stale) — remove it and
                    // report no eviction; the caller can retry.
                    self.by_fee.remove(&lowest_density);
                    return false;
                }
            }
        };
        if hashes.is_empty() {
            self.by_fee.remove(&lowest_density);
        }
        // Remove from by_hash and by_sender.
        if let Some(entry) = self.by_hash.remove(&hash) {
            if let Some(queue) = self.by_sender.get_mut(&entry.sender) {
                queue.remove(&entry.nonce);
                if queue.is_empty() {
                    self.by_sender.remove(&entry.sender);
                }
            }
        }
        true
    }

    /// Select up to `max_bytes` of transactions, ordered by fee
    /// density (highest first), respecting per-account nonce ordering.
    ///
    /// Returns the selected transactions as a `Vec<TxBytes>`. The
    /// selected entries are removed from the pool.
    ///
    /// The selection algorithm:
    /// 1. Iterate fee densities from highest to lowest.
    /// 2. For each density, iterate the tx hashes.
    /// 3. For each tx, check that its nonce is the next expected
    ///    nonce for its sender (no gaps). If not, skip it (it will
    ///    be selected once its predecessor is included).
    /// 4. If the tx fits in the remaining byte budget, select it
    ///    and advance the sender's expected nonce.
    /// 5. Stop when the budget is full or no more txs are available.
    ///
    /// # Per-sender cap
    ///
    /// At most `max_per_sender` txs from one account are selected
    /// per call — the rest stay in the pool for the next block.
    /// Without the cap a single high-fee sender with sequential
    /// nonces monopolizes the whole block (liveness `DoS`).
    ///
    /// # Removal complexity
    ///
    /// Selection records hashes in order, then MOVES each entry out
    /// of `by_hash` in that order — no `TxBytes` clone (the previous
    /// `selected.push(entry.tx.clone())` copied every selected tx).
    /// `by_sender` queues drop the selected nonces in one pass each;
    /// `by_fee` buckets are filtered once via `BTreeMap::retain`.
    pub fn select(&mut self, max_bytes: u64) -> Vec<TxBytes> {
        let mut total_bytes = 0u64;
        // Sender-fair fee-priority selection: a max-heap of
        // (head fee density, sender) — the density of each sender's
        // lowest pending nonce. Repeatedly pop the highest-density
        // sender and take its contiguous nonce chain (bounded by the
        // per-sender cap).
        //
        // Complexity: O(senders + selected·log senders). The old
        // `by_fee` bucket scan was O(pool size) per call — at a
        // multi-million-entry same-fee pool, every block proposal
        // hashed the whole pool. Few senders with long nonce chains
        // (the common trading workload) now cost ~O(selected).
        let mut heap: std::collections::BinaryHeap<(FeeDensity, Address)> =
            std::collections::BinaryHeap::with_capacity(self.by_sender.len());
        for (sender, queue) in &self.by_sender {
            if let Some(&hash) = queue.values().next() {
                if let Some(entry) = self.by_hash.get(&hash) {
                    heap.push((FeeDensity { fee: entry.fee, size: entry.size }, *sender));
                }
            }
        }

        let mut selected_order: Vec<Hash> = Vec::new();
        let per_sender_cap = u64::try_from(self.max_per_sender).unwrap_or(u64::MAX);

        'senders: while let Some((_density, sender)) = heap.pop() {
            if total_bytes >= max_bytes {
                break;
            }
            let Some(queue) = self.by_sender.get(&sender) else {
                continue;
            };
            // HIGH fix: anchor the start nonce to `executed_nonce + 1`
            // if we know the executed nonce for this sender. This
            // prevents selecting mid-chain nonces after earlier txs
            // have executed (which would create a nonce gap in the
            // block). If we don't know the executed nonce, start at
            // the minimum queued nonce (the old behavior).
            let start_nonce = match self.executed_nonces.get(&sender) {
                Some(&executed) => executed + 1,
                None => match queue.keys().next() {
                    Some(&min) => min,
                    None => continue,
                },
            };
            let mut nonce = start_nonce;
            let mut count = 0u64;
            // Follow the contiguous nonce chain up to the per-sender
            // cap. Stop on a gap (later nonces aren't contiguous, so
            // they can't be selected this block anyway), on the cap
            // (rest stay for the next block), or on the byte budget
            // (the chain is nonce-contiguous, so nothing further
            // from this sender is selectable — other senders' txs
            // may still fit, so keep popping the heap).
            while count < per_sender_cap {
                let Some(&hash) = queue.get(&nonce) else {
                    break;
                };
                let Some(entry) = self.by_hash.get(&hash) else {
                    break;
                };
                if total_bytes.saturating_add(entry.size) > max_bytes {
                    continue 'senders;
                }
                total_bytes += entry.size;
                selected_order.push(hash);
                count += 1;
                nonce = nonce.saturating_add(1);
            }
        }

        // Batch-remove all selected entries in a single pass over each
        // index. This is O(total pool size) — each fee bucket is
        // filtered at most once, each sender queue is filtered at most
        // once, and `by_hash` is drained in one pass.
        // Move selected txs out of `by_hash` in selection order —
        // no clone. Collect (sender, nonce) for index cleanup while
        // already touching the entries.
        let mut selected = Vec::with_capacity(selected_order.len());
        let mut sender_cleanups: Vec<(Address, u64)> = Vec::with_capacity(selected_order.len());
        for hash in selected_order {
            if let Some(entry) = self.by_hash.remove(&hash) {
                sender_cleanups.push((entry.sender, entry.nonce));
                selected.push(entry.tx);
            }
        }

        // Clean the per-sender queues for the selected txs. `by_fee`
        // needs no per-block maintenance: it exists only for
        // pool-full eviction (`evict_lowest_fee`), which lazily skips
        // stale hashes — removing the per-block O(pool) retain pass
        // was the point of the heap-walk select.
        for (sender, nonce) in sender_cleanups {
            if let Some(queue) = self.by_sender.get_mut(&sender) {
                queue.remove(&nonce);
                if queue.is_empty() {
                    self.by_sender.remove(&sender);
                }
            }
        }

        selected
    }

    /// Snapshot the pool for `txpool_*`-style introspection.
    ///
    /// Returns `(sender, nonce, tx_bytes, is_pending)` for every
    /// pooled transaction. The pending/queued split follows geth's
    /// `txpool_content` rule: starting at `executed_nonce + 1` (or
    /// the sender's minimum queued nonce when no execution record
    /// exists), each contiguous nonce is *pending* — executable in
    /// the next block; the first gap makes every later nonce
    /// *queued*. Entries below the start nonce are stale and
    /// omitted (they can't execute — `select` skips them too).
    ///
    /// Takes `&self`: this is a cold-path read for the RPC layer —
    /// it clones `TxBytes` (bytes up to pool size) and must never
    /// appear on the block path.
    #[must_use]
    pub fn txpool_snapshot(&self) -> Vec<(Address, u64, TxBytes, bool)> {
        let mut out = Vec::with_capacity(self.by_hash.len());
        for (sender, queue) in &self.by_sender {
            let mut next_expected = match self.executed_nonces.get(sender) {
                Some(&executed) => Some(executed + 1),
                None => queue.keys().next().copied(),
            };
            for (&nonce, hash) in queue {
                let Some(entry) = self.by_hash.get(hash) else { continue };
                let pending = match next_expected {
                    // Below the start nonce: stale — can't execute.
                    Some(expected) if nonce < expected => continue,
                    Some(expected) if nonce == expected => {
                        next_expected = Some(expected + 1);
                        true
                    }
                    // Gap opened (or no executed-nonce anchor) — this
                    // and all later nonces queue behind the hole.
                    _ => false,
                };
                out.push((*sender, nonce, entry.tx.clone(), pending));
            }
        }
        out
    }

    /// Remove a single transaction by hash from all indices. This is
    /// the per-tx removal path — used by same-nonce replacement in
    /// [`submit`](Self::submit) and when a specific tx needs to be
    /// dropped (e.g. after a failed proposal or mempool eviction).
    /// [`select`](Self::select) removes in bulk for the block path.
    fn remove(&mut self, hash: &Hash) {
        if let Some(entry) = self.by_hash.remove(hash) {
            let density = FeeDensity { fee: entry.fee, size: entry.size };
            if let Some(hashes) = self.by_fee.get_mut(&density) {
                hashes.retain(|h| h != hash);
                if hashes.is_empty() {
                    self.by_fee.remove(&density);
                }
            }
            if let Some(queue) = self.by_sender.get_mut(&entry.sender) {
                queue.remove(&entry.nonce);
                if queue.is_empty() {
                    self.by_sender.remove(&entry.sender);
                }
            }
        }
    }

    /// Number of transactions currently in the pool.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// Check whether a transaction with the given hash is in the pool.
    pub fn contains(&self, hash: &Hash) -> bool {
        self.by_hash.contains_key(hash)
    }
}

/// Build a v0 transaction from sender, nonce, fee, and payload bytes.
/// Useful for tests and devnet.
pub fn build_tx(sender: Address, nonce: u64, fee: u64, payload: &[u8]) -> TxBytes {
    let mut bytes = Vec::with_capacity(TX_MIN_SIZE + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.extend_from_slice(payload);
    TxBytes::new(bytes)
}

/// The high bit of the `module_id` byte marking a signed envelope
/// (v1). Mirrors `executor`'s `SIGNED_FLAG` — kept here so test and
/// devnet code can build signed envelopes without depending on the
/// executor crate's internals.
const SIGNED_FLAG: u8 = 0x80;

/// Build a signed (v1) native transaction: an envelope whose
/// `module_id` byte carries the signed flag and whose signature is
/// a secp256k1 ECDSA signature over the EIP-712 typed-data digest of
/// `(chain_id, sender, nonce, fee, module_id, module_payload)` —
/// see `crypto::eip712`.
///
/// Wire layout: `[sender:20][nonce:8LE][fee:8LE][module_id|0x80:1]
/// [sig:65B][module_payload]`, where `sig = r ‖ s ‖ v` and `v` is
/// the recovery ID (0 or 1 — `MetaMask`'s 27/28 is normalized by
/// subtracting 27).
///
/// The sender is derived from `privkey` — passing a key that doesn't
/// correspond to an intended account produces a correctly-signed tx
/// for the key's own address, never a forgery.
///
/// For tests and devnet tooling. Production signing happens in the
/// user's wallet; nodes only verify.
///
/// # Errors
///
/// Returns `None` if the private key is invalid for secp256k1.
#[must_use]
pub fn build_signed_tx(
    privkey: &[u8],
    chain_id: u64,
    nonce: u64,
    fee: u64,
    module_id: u8,
    module_payload: &[u8],
) -> Option<TxBytes> {
    // Derive the sender from the private key so the declared sender
    // can never disagree with the signing key.
    let sender = crypto::secp::signable_pubkey_address(privkey)?;
    let digest =
        crypto::eip712::tx_signing_digest(chain_id, &sender, nonce, fee, module_id, module_payload);
    let sig = crypto::secp::sign(privkey, &digest).ok()?;
    let mut bytes = Vec::with_capacity(TX_MIN_SIZE + 1 + 65 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id | SIGNED_FLAG);
    bytes.extend_from_slice(&sig.sig);
    bytes.push(sig.recid.as_u8());
    bytes.extend_from_slice(module_payload);
    Some(TxBytes::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address([byte; 20])
    }

    #[test]
    fn submit_and_select_basic() {
        let mut pool = Mempool::new(100);
        let tx = build_tx(addr(1), 0, 100, &[1, 2, 3]);
        assert!(pool.submit(tx).is_ok());
        assert_eq!(pool.len(), 1);
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 1);
        assert_eq!(pool.len(), 0, "selected txs are removed");
    }

    #[test]
    fn submit_batch_accepts_multiple() {
        let mut pool = Mempool::new(100);
        let txs = vec![
            build_tx(addr(1), 0, 100, &[1]),
            build_tx(addr(1), 1, 200, &[2]),
            build_tx(addr(2), 0, 150, &[3]),
        ];
        let results = pool.submit_batch(txs);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(Result::is_ok), "all txs should be accepted");
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn submit_batch_handles_duplicates() {
        let mut pool = Mempool::new(100);
        let tx = build_tx(addr(1), 0, 100, &[1]);
        let txs = vec![tx.clone(), tx];
        let results = pool.submit_batch(txs);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok(), "first tx should be accepted");
        assert!(results[1].is_err(), "duplicate should be rejected");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn dedup_rejects_duplicate() {
        let mut pool = Mempool::new(100);
        let tx = build_tx(addr(1), 0, 100, &[1]);
        assert!(pool.submit(tx.clone()).is_ok());
        assert_eq!(pool.submit(tx), Err(MempoolError::Duplicate));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn fee_priority_selects_highest_first() {
        let mut pool = Mempool::new(100);
        // Three txs from different senders, different fees.
        pool.submit(build_tx(addr(1), 0, 10, &[0])).unwrap();
        pool.submit(build_tx(addr(2), 0, 100, &[0])).unwrap();
        pool.submit(build_tx(addr(3), 0, 50, &[0])).unwrap();
        let selected = pool.select(1 << 20);
        // Highest fee first: 100, 50, 10.
        assert_eq!(selected.len(), 3);
        // The first selected should be the one with fee 100 (addr 2).
        let (_, nonce, fee) = parse_tx(selected[0].as_bytes()).unwrap();
        assert_eq!(fee, 100);
        assert_eq!(nonce, 0);
    }

    #[test]
    fn nonce_ordering_enforced() {
        let mut pool = Mempool::new(100);
        // Submit nonce 1 before nonce 0. The mempool must not select
        // nonce 1 before nonce 0. With the nonce-chain follower,
        // selecting nonce 0 immediately follows the chain to nonce 1
        // in the same `select()` call — this is correct (nonce 0
        // executes before nonce 1 within the block) and better for
        // throughput (more txs per block).
        pool.submit(build_tx(addr(1), 1, 100, &[1])).unwrap();
        pool.submit(build_tx(addr(1), 0, 100, &[0])).unwrap();
        let selected = pool.select(1 << 20);
        // Both nonces are selected: nonce 0 first, then nonce 1 via
        // the chain follower.
        assert_eq!(selected.len(), 2);
        let (_, nonce0, _) = parse_tx(selected[0].as_bytes()).unwrap();
        assert_eq!(nonce0, 0);
        let (_, nonce1, _) = parse_tx(selected[1].as_bytes()).unwrap();
        assert_eq!(nonce1, 1);
        // Both txs are removed from the pool.
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn byte_budget_respected() {
        let mut pool = Mempool::new(100);
        // Each tx is 48 + 10 = 58 bytes.
        pool.submit(build_tx(addr(1), 0, 100, &[0; 10])).unwrap();
        pool.submit(build_tx(addr(2), 0, 100, &[0; 10])).unwrap();
        // Budget for only one tx (58 bytes).
        let selected = pool.select(58);
        assert_eq!(selected.len(), 1);
        assert_eq!(pool.len(), 1, "one tx remains");
    }

    #[test]
    fn eviction_when_full() {
        let mut pool = Mempool::new(2);
        pool.submit(build_tx(addr(1), 0, 10, &[0])).unwrap();
        pool.submit(build_tx(addr(2), 0, 20, &[0])).unwrap();
        assert_eq!(pool.len(), 2);
        // Submit a higher-fee tx — should evict the lowest-fee (10).
        pool.submit(build_tx(addr(3), 0, 100, &[0])).unwrap();
        assert_eq!(pool.len(), 2, "still 2 after eviction");
        // The lowest-fee tx (addr 1, fee 10) should be gone.
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 2);
        // Verify addr 1's tx is not in the selection.
        for tx in &selected {
            let (sender, _, _) = parse_tx(tx.as_bytes()).unwrap();
            assert_ne!(sender, addr(1), "lowest-fee tx should have been evicted");
        }
    }

    #[test]
    fn malformed_tx_rejected() {
        let mut pool = Mempool::new(100);
        // Too short.
        assert_eq!(pool.submit(TxBytes::new(vec![1, 2, 3])), Err(MempoolError::Malformed));
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn empty_pool_selects_nothing() {
        let mut pool = Mempool::new(100);
        let selected = pool.select(1 << 20);
        assert!(selected.is_empty());
    }

    #[test]
    fn pool_full_rejects_low_fee() {
        let mut pool = Mempool::new(1);
        pool.submit(build_tx(addr(1), 0, 100, &[0])).unwrap();
        // Pool is full; a new tx with lower fee can't evict.
        assert_eq!(pool.submit(build_tx(addr(2), 0, 10, &[0])), Err(MempoolError::PoolFull));
        // A higher-fee tx should evict the existing one.
        assert!(pool.submit(build_tx(addr(3), 0, 200, &[0])).is_ok());
    }

    #[test]
    fn multi_sender_selection() {
        let mut pool = Mempool::new(100);
        // Two senders, each with 2 txs in nonce order.
        pool.submit(build_tx(addr(1), 0, 100, &[0])).unwrap();
        pool.submit(build_tx(addr(1), 1, 100, &[0])).unwrap();
        pool.submit(build_tx(addr(2), 0, 200, &[0])).unwrap();
        pool.submit(build_tx(addr(2), 1, 200, &[0])).unwrap();
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 4, "all 4 txs selected");
        // addr 2's txs have higher fee, so they should come first.
        let (sender0, _, _) = parse_tx(selected[0].as_bytes()).unwrap();
        assert_eq!(sender0, addr(2));
    }

    // ---- FeeDensity ordering fix tests ----

    /// Prove that `FeeDensity` orders by fee-per-byte (cross-
    /// multiplication), not by absolute fee. Before the fix, the
    /// derived `Ord` ranked 200/50 above 100/10 because `200 > 100`,
    /// even though 100/10 has density 10 and 200/50 has density 4.
    #[test]
    fn fee_density_orders_by_fee_per_byte_not_absolute_fee() {
        // density 10 (100/10) should be GREATER than density 4 (200/50)
        let high_density = FeeDensity { fee: 100, size: 10 };
        let low_density = FeeDensity { fee: 200, size: 50 };
        assert!(
            high_density > low_density,
            "100/10 (density 10) must rank higher than 200/50 (density 4)"
        );
    }

    /// Prove that selection respects fee density, not absolute fee.
    /// A tx with fee 100 and size 36 (density ~2.78) should be
    /// selected before a tx with fee 200 and size 100 (density 2),
    /// even though the latter has a higher absolute fee.
    #[test]
    fn select_prefers_higher_density_over_higher_absolute_fee() {
        let mut pool = Mempool::new(100);
        // low density: fee 200, size 100 → density 2
        // payload 64 bytes → 36 + 64 = 100 bytes
        pool.submit(build_tx(addr(1), 0, 200, &[0; 64])).unwrap();
        // high density: fee 100, size 36 → density ~2.78
        // payload 0 bytes → 36 + 0 = 36 bytes
        pool.submit(build_tx(addr(2), 0, 100, &[])).unwrap();
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 2);
        // The first selected should be the higher-density tx (addr 2).
        let (sender0, _, fee0) = parse_tx(selected[0].as_bytes()).unwrap();
        assert_eq!(sender0, addr(2), "higher-density tx should be selected first");
        assert_eq!(fee0, 100);
    }

    /// Prove that equal-density txs are tie-broken deterministically
    /// by (fee, size) ascending.
    #[test]
    fn fee_density_tiebreak_is_deterministic() {
        // Both have density 10, but different (fee, size).
        let a = FeeDensity { fee: 10, size: 1 };
        let b = FeeDensity { fee: 20, size: 2 };
        // Same density (10/1 == 20/2), tie-break by fee ascending:
        // a (fee 10) < b (fee 20).
        assert!(a < b, "equal density: lower fee should sort first");
    }

    // ---- Batch removal tests ----

    /// Prove that selecting many txs from the same fee bucket is
    /// correct (the batch removal path handles same-bucket entries).
    #[test]
    fn select_many_from_same_fee_bucket() {
        let mut pool = Mempool::new(100);
        // 10 txs from different senders, all with the same fee and
        // size (same fee bucket).
        for i in 0..10u8 {
            pool.submit(build_tx(addr(i), 0, 100, &[0])).unwrap();
        }
        assert_eq!(pool.len(), 10);
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 10, "all 10 txs should be selected");
        assert_eq!(pool.len(), 0, "pool should be empty after selection");
    }

    /// Prove that batch removal correctly cleans up sender queues
    /// (no orphaned entries left in `by_sender`).
    #[test]
    fn batch_removal_cleans_up_sender_queues() {
        let mut pool = Mempool::new(100);
        // Submit 3 txs from one sender in nonce order.
        pool.submit(build_tx(addr(1), 0, 100, &[0])).unwrap();
        pool.submit(build_tx(addr(1), 1, 100, &[0])).unwrap();
        pool.submit(build_tx(addr(1), 2, 100, &[0])).unwrap();
        // Select all — batch removal should clean up the sender queue.
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 3);
        assert_eq!(pool.len(), 0);
        // The sender's queue should be gone (no orphaned entries).
        // Verify by submitting a new tx from the same sender — it
        // should be accepted (nonce 0 again, since the queue was
        // cleaned up and the pool starts fresh).
        assert!(pool.submit(build_tx(addr(1), 0, 100, &[0])).is_ok());
    }

    // ---- Per-sender cap tests ----

    /// Prove that a single high-fee sender cannot monopolize a
    /// block: with a cap of 2, only 2 of the spammer's 5 contiguous
    /// nonces are selected — the rest stay in the pool for the next
    /// block, leaving room for other senders.
    #[test]
    fn per_sender_cap_bounds_block_share() {
        let mut pool = Mempool::new(100).with_max_per_sender(2);
        // Spammer: 5 contiguous nonces at top fee.
        for nonce in 0..5u64 {
            pool.submit(build_tx(addr(1), nonce, 1_000_000, &[0])).unwrap();
        }
        // Victim: 1 tx at lower fee.
        pool.submit(build_tx(addr(2), 0, 100, &[0])).unwrap();

        let selected = pool.select(1 << 20);
        let spammer_txs =
            selected.iter().filter(|tx| parse_tx(tx.as_bytes()).unwrap().0 == addr(1)).count();
        assert_eq!(spammer_txs, 2, "cap must bound the spammer to 2 txs");
        assert_eq!(pool.len(), 3, "3 spammer txs remain after the capped selection");
        // The victim's tx is selected too (room left after capping).
        assert!(
            selected.iter().any(|tx| parse_tx(tx.as_bytes()).unwrap().0 == addr(2)),
            "the victim's tx must not be starved"
        );
        // Next select drains the spammer's remaining nonce chain.
        let selected2 = pool.select(1 << 20);
        assert_eq!(selected2.len(), 2, "next block takes the next 2 capped txs");
    }

    // ---- Same-nonce replacement (geth legacypool price-bump) ----

    /// A same-nonce resubmit with a ≥110% fee replaces the pending
    /// tx — the wallet "speed up" path. The displaced tx must leave
    /// every index: `by_hash` (len/dedup), `by_fee` (eviction order),
    /// and `by_sender` (selection).
    #[test]
    fn replacement_with_bump_displaces_old_tx() {
        let mut pool = Mempool::new(100);
        let old_tx = build_tx(addr(1), 0, 100, &[1]);
        let old_hash = Hasher::hash_one(Domain::Transaction, old_tx.as_bytes());
        pool.submit(old_tx).unwrap();
        // Same nonce, fee 110 ≥ 100 × 1.1 → replaces.
        pool.submit(build_tx(addr(1), 0, 110, &[2])).unwrap();
        assert_eq!(pool.len(), 1, "replaced tx must not linger in by_hash");
        assert!(!pool.contains(&old_hash), "displaced tx must leave dedup index");
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 1);
        let (_, _, fee) = parse_tx(selected[0].as_bytes()).unwrap();
        assert_eq!(fee, 110, "the replacement must be selected");
    }

    /// A same-nonce resubmit below the bump floor is rejected and the
    /// original stays — without this, an attacker could shadow a
    /// victim's pending tx with a cheaper one.
    #[test]
    fn replacement_underpriced_is_rejected() {
        let mut pool = Mempool::new(100);
        pool.submit(build_tx(addr(1), 0, 100, &[1])).unwrap();
        // Fee 109 < 110 required → rejected, original survives.
        assert_eq!(
            pool.submit(build_tx(addr(1), 0, 109, &[2])),
            Err(MempoolError::ReplacementUnderpriced)
        );
        assert_eq!(pool.len(), 1);
        let selected = pool.select(1 << 20);
        let (_, _, fee) = parse_tx(selected[0].as_bytes()).unwrap();
        assert_eq!(fee, 100, "original tx must still be pending");
    }

    /// Equal-fee and lower-fee resubmits are also rejected.
    #[test]
    fn replacement_equal_and_lower_fee_rejected() {
        let mut pool = Mempool::new(100);
        pool.submit(build_tx(addr(1), 0, 100, &[1])).unwrap();
        assert_eq!(
            pool.submit(build_tx(addr(1), 0, 100, &[2])),
            Err(MempoolError::ReplacementUnderpriced)
        );
        assert_eq!(
            pool.submit(build_tx(addr(1), 0, 50, &[3])),
            Err(MempoolError::ReplacementUnderpriced)
        );
        assert_eq!(pool.len(), 1);
    }

    /// Replacement doesn't consume an extra slot: a replacement in a
    /// full pool succeeds even though the pool is at capacity (the
    /// displaced tx frees the slot it occupied).
    #[test]
    fn replacement_works_in_full_pool() {
        let mut pool = Mempool::new(1);
        pool.submit(build_tx(addr(1), 0, 100, &[1])).unwrap();
        assert!(pool.submit(build_tx(addr(1), 0, 200, &[2])).is_ok());
        assert_eq!(pool.len(), 1, "pool size unchanged by replacement");
    }

    /// A different nonce from the same sender is NOT a replacement —
    /// it inserts alongside, preserving the nonce chain.
    #[test]
    fn different_nonce_inserts_normally() {
        let mut pool = Mempool::new(100);
        pool.submit(build_tx(addr(1), 0, 100, &[1])).unwrap();
        // Same sender, nonce 1, lower fee — not a replacement.
        pool.submit(build_tx(addr(1), 1, 10, &[2])).unwrap();
        assert_eq!(pool.len(), 2);
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 2);
        let (_, n0, _) = parse_tx(selected[0].as_bytes()).unwrap();
        let (_, n1, _) = parse_tx(selected[1].as_bytes()).unwrap();
        assert_eq!((n0, n1), (0, 1), "nonce chain preserved");
    }

    /// Prove the cap is enforced mid-chain: the nonce chain stops
    /// at the cap even when more contiguous nonces exist.
    #[test]
    fn per_sender_cap_stops_nonce_chain() {
        let mut pool = Mempool::new(100).with_max_per_sender(3);
        for nonce in 0..6u64 {
            pool.submit(build_tx(addr(1), nonce, 1_000, &[0])).unwrap();
        }
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 3, "chain stops at cap even with more nonces");
        // Nonces 0..2 selected, 3..5 remain.
        assert_eq!(pool.len(), 3);
    }
}
