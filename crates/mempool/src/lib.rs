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
//! `select` is a peek — it clones the chosen `TxBytes` and leaves
//! every entry pooled until `remove_committed` runs at block
//! finality, so losing a proposal round can never lose the txs in it.
//!
//! # Phase 1 scope
//!
//! v0 is a simple in-memory pool with fee-priority selection and
//! per-account nonce tracking. No rate limiting, no eviction policy
//! beyond size cap, no mempool gossip. Those arrive in Phase 2+.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

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
    /// The module's gas estimate, precomputed at insert time. The
    /// proposal gas-cap loop reads this instead of re-parsing the
    /// envelope and re-estimating per candidate — at a 40k-tx
    /// backlog that loop was ~17ms per proposal (parse 0.3µs +
    /// estimate 0.12µs per tx), the largest single term in the
    /// leader's propose path.
    gas: u64,
}

/// A transaction with everything the pool's indices need, computed
/// once by the intake's parallel phase instead of re-derived per
/// insert. `submit_prepared` skips the hash, the envelope re-parse,
/// and the gas estimate — the batch intake already paid for all
/// three.
pub struct PreparedTx {
    /// The transaction bytes, as submitted.
    pub tx: TxBytes,
    /// BLAKE3 [`Domain::Transaction`] hash of `tx` — the dedup key.
    pub hash: Hash,
    /// The envelope sender.
    pub sender: Address,
    /// The envelope nonce.
    pub nonce: u64,
    /// The envelope fee.
    pub fee: u64,
    /// The target module's gas estimate.
    pub gas: u64,
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
    /// highest-fee-first iteration by reversing. Buckets are
    /// `BTreeSet`s so member removal is O(log n): every removal
    /// path (`remove`, `remove_committed`, `refresh_anchors`
    /// pruning) keeps `by_fee` exactly in sync with `by_hash` — no
    /// tombstones may accumulate, which is what bounds the index's
    /// memory under steady-state throughput (a hash left behind by
    /// a draining selection pass would otherwise linger until an
    /// eviction happened to reach it).
    by_fee: BTreeMap<FeeDensity, BTreeSet<Hash>>,
    /// Maximum number of transactions in the pool. Beyond this, the
    /// lowest-fee entries are evicted.
    max_entries: usize,
    /// Maximum txs a single sender can occupy in one `select` call.
    /// Without a cap, one sender submitting N sequential nonces (at
    /// top fee) monopolizes the whole block — a liveness `DoS` on
    /// every other account. The cap bounds any sender's block
    /// share regardless of fee.
    max_per_sender: usize,
    /// Pool-level per-sender bound, checked on insert: at most this
    /// many pending txs per sender, and no nonce more than this far
    /// past the sender's last executed nonce (when known). Distinct
    /// from `max_per_sender` (a per-*block* share): the pool
    /// deliberately holds several blocks' worth per sender so
    /// pipelined proposals can continue a nonce chain.
    max_pending_per_sender: usize,
    /// Per-sender last executed nonce (HIGH fix). The mempool
    /// anchors selection to `executed_nonce + 1` — a tx with a
    /// lower nonce is stale (already executed) and a tx with a
    /// higher nonce can't be selected until the gap is filled.
    /// Without this, `select` started at the minimum queued nonce,
    /// which could be a mid-chain nonce after earlier txs executed,
    /// creating a nonce gap in the block.
    executed_nonces: HashMap<Address, u64>,
    /// Per-sender committed-but-unexecuted nonces: `(nonce ->
    /// committed height)`. `remove_committed` vacates a committed tx
    /// from the queue immediately, but the lane-side
    /// `refresh_anchors` only rebuilds `executed_nonces` after the
    /// block *executes* — under execution-lane lag the two clocks
    /// diverge and the sender's queue shows a phantom gap between
    /// `executed + 1` and the next live entry. `select` bridges
    /// exactly the nonces recorded here (all of which are decided —
    /// consumed or deterministically skipped — never free), and
    /// `refresh_anchors` expires every entry at or below the just-
    /// executed height: a consumed entry is covered by the refreshed
    /// anchor, a skipped one un-bridges so the sender's refilled
    /// nonce becomes selectable again.
    pending_commit: HashMap<Address, BTreeMap<u64, u64>>,
    /// Per-sender nonces carried by observed uncommitted chain
    /// blocks: `(nonce -> proposal height)`. Under pipelined
    /// consensus the sender's nonce chain is contiguous across the
    /// *chain*, not across any one validator's pool: block h4 can
    /// legitimately carry nonce 4 while uncommitted ancestors h2/h3
    /// carry nonces 2 and 3 — all proposed to (and pooled by)
    /// different leaders. The `executed_nonces` anchor alone sees
    /// that as a gap and breaks the walk, producing empty proposals.
    ///
    /// `process_proposal` — which runs on every vote-path proposal,
    /// not just this node's own — records the observed coverage via
    /// `note_in_chain`, and `select` bridges a local queue miss
    /// whose nonce a live ancestor carries. Entries expire in
    /// `refresh_anchors` two ways: the rebuilt anchor passing the
    /// nonce (resolved by execution), or the covering height falling
    /// `CHAIN_COVER_TTL` behind the executed tip (the branch died —
    /// the gap is real again and the walk stops bridging it).
    in_chain: HashMap<Address, BTreeMap<u64, u64>>,
    /// Tx hashes already carried by an uncommitted proposal — one
    /// set per outstanding proposal position, oldest first.
    ///
    /// `select` is a peek (entries leave the pool only at
    /// finalization), so without this marker every pipelined
    /// `prepare_proposal` re-selects the same head of each sender's
    /// nonce chain — the duplicate then commits as a deterministic
    /// nonce skip and wastes the block space. `select` skips
    /// in-flight hashes, `note_proposed` records each built
    /// proposal's set, and `remove_committed` resolves the oldest
    /// position per commit: positions commit strictly in order and
    /// a descendant can only commit if its parent did, so the
    /// front of the deque is always the next position to resolve.
    /// If the committed block carried these txs they are already
    /// gone from the pool; if a different branch won the position,
    /// the txs become selectable again.
    proposed: VecDeque<HashSet<Hash>>,
}

/// Maximum outstanding proposal positions tracked for in-flight
/// exclusion.
///
/// The pipeline keeps ~2 uncommitted positions; a deque deeper than
/// this means commits have stalled across many proposals, so the
/// oldest set releases early rather than grow the bookkeeping
/// without bound (early release can only re-select — it can never
/// censor a tx).
const MAX_IN_FLIGHT_PROPOSALS: usize = 16;

/// Heights an `in_chain` nonce-cover stays valid (unit: blocks).
///
/// A proposed block resolves — commits or dies with its branch —
/// inside the pipeline's in-flight window; twice that bound covers
/// any honest resolution path while still expiring dead-branch
/// coverage promptly (a lingering cover would falsely bridge a real
/// gap and burn a proposal slot on a deterministically-skipped tx).
const CHAIN_COVER_TTL: u64 = 2 * MAX_IN_FLIGHT_PROPOSALS as u64;

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

/// Default pool-level bound on one sender's pending txs (and on how
/// far its nonces may run ahead of the last executed one): four
/// blocks' worth at [`DEFAULT_MAX_PER_SENDER`], enough to keep a
/// pipelined nonce chain fed while stopping one account — which only
/// has to be funded, not honest — from filling the pool with
/// far-future nonces that never execute and are never pruned.
pub const DEFAULT_MAX_PENDING_PER_SENDER: usize = 4 * DEFAULT_MAX_PER_SENDER;

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
    /// The sender already holds `max_pending_per_sender` pending
    /// txs, or the nonce sits further than that past its last
    /// executed nonce. Without this bound one account could fill the
    /// whole pool with far-future nonces that never execute and are
    /// never pruned.
    SenderLimit,
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
            max_pending_per_sender: DEFAULT_MAX_PENDING_PER_SENDER,
            executed_nonces: HashMap::new(),
            pending_commit: HashMap::new(),
            in_chain: HashMap::new(),
            proposed: VecDeque::new(),
        }
    }

    /// Set the per-sender selection cap (txs per `select` call).
    #[must_use]
    pub fn with_max_per_sender(mut self, cap: usize) -> Self {
        self.max_per_sender = cap;
        self
    }

    /// Override the pool-level per-sender bound
    /// ([`DEFAULT_MAX_PENDING_PER_SENDER`]).
    #[must_use]
    pub fn with_max_pending_per_sender(mut self, cap: usize) -> Self {
        self.max_pending_per_sender = cap;
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
        let (sender, nonce, fee) = parse_tx(bytes).ok_or(MempoolError::Malformed)?;
        // The standalone path has no module context — the gas
        // estimate is not available, so the entry carries 0 and the
        // proposal gas-cap loop falls back to per-candidate
        // estimation for it (see `select_with_gas`).
        self.insert_prepared(PreparedTx { tx, hash, sender, nonce, fee, gas: 0 })
    }

    /// Submit a transaction whose hash, envelope fields, and gas
    /// estimate the caller already computed — the batch intake's
    /// parallel phase produces exactly this. Skips the per-tx
    /// re-hash (~0.22µs), re-parse (~0.1µs), and gas re-estimate
    /// (~0.12µs) that [`submit`](Self::submit) would redo.
    ///
    /// # Errors
    ///
    /// Same contract as [`submit`](Self::submit).
    pub fn submit_prepared(&mut self, prepared: PreparedTx) -> Result<(), MempoolError> {
        self.insert_prepared(prepared)
    }

    /// The shared insert body behind [`submit`](Self::submit) and
    /// [`submit_prepared`](Self::submit_prepared): dedup, same-nonce
    /// replacement, capacity eviction, then the three-index insert.
    fn insert_prepared(&mut self, prepared: PreparedTx) -> Result<(), MempoolError> {
        let PreparedTx { tx, hash, sender, nonce, fee, gas } = prepared;
        let bytes = tx.as_bytes();

        // Dedup: if we've seen this hash, it's a duplicate.
        if self.by_hash.contains_key(&hash) {
            return Err(MempoolError::Duplicate);
        }

        let size = bytes.len() as u64;
        let density = FeeDensity { fee, size };

        // Per-sender admission bound (replacements reuse their slot,
        // so they are exempt from the count): at most
        // `max_pending_per_sender` pending txs, within that many
        // nonces of the last executed one when the anchor is known.
        let cap = u64::try_from(self.max_pending_per_sender).unwrap_or(u64::MAX);
        let queue = self.by_sender.get(&sender);
        let is_replacement = queue.is_some_and(|q| q.contains_key(&nonce));
        if !is_replacement && queue.is_some_and(|q| q.len() >= self.max_pending_per_sender) {
            return Err(MempoolError::SenderLimit);
        }
        if let Some(&executed) = self.executed_nonces.get(&sender)
            && nonce > executed.saturating_add(cap)
        {
            return Err(MempoolError::SenderLimit);
        }

        // Same-nonce replacement (geth legacypool semantics): if this
        // sender already has a pending tx at this nonce, the new tx
        // may replace it only if its fee is at least 110% of the old
        // one. The displaced tx is removed from every index — the
        // previous implementation just overwrote the `by_sender` slot,
        // leaking the old entry in `by_hash`/`by_fee` forever (it kept
        // counting toward `max_entries` and could be "evicted" as a
        // ghost) and letting a *lower*-fee resubmit shadow a
        // higher-fee tx.
        if let Some(&old_hash) = self.by_sender.get(&sender).and_then(|q| q.get(&nonce))
            && let Some(old) = self.by_hash.get(&old_hash)
        {
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

        // If the pool is full, evict the lowest-fee entries until
        // there is room — but only while the new tx outbids the
        // current lowest density. `evict_lowest_fee` can report
        // "nothing evicted" when the lowest bucket turned out to be
        // all tombstones: that outcome is retried (the bucket is
        // gone, so the next iteration re-checks the new lowest
        // density), and the loop exits with `PoolFull` only when no
        // live entry is outbiddable. The previous code ignored the
        // result and inserted anyway, letting the pool exceed
        // `max_entries` by one entry per stale-bucket drain.
        while self.by_hash.len() >= self.max_entries {
            let lowest_density = self.by_fee.keys().next().copied();
            match lowest_density {
                Some(lowest) if density > lowest => {
                    // Live evict or stale-bucket drain — either way
                    // the loop re-checks capacity and the new lowest.
                    self.evict_lowest_fee();
                }
                _ => {
                    // Pool is full and the new tx can't outbid anyone.
                    return Err(MempoolError::PoolFull);
                }
            }
        }

        // Insert into all indices.
        let entry = PoolEntry { tx, hash, sender, nonce, fee, size, gas };
        self.by_hash.insert(hash, entry);
        self.by_sender.entry(sender).or_default().insert(nonce, hash);
        self.by_fee.entry(density).or_default().insert(hash);
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

    /// Evict the lowest-fee entry from the pool. Returns `true` if a
    /// live entry was evicted, `false` if there was nothing evictable
    /// — an empty index or a lowest bucket that turned out to hold
    /// only stale hashes (drained so the caller can re-check the new
    /// lowest density). Callers MUST handle `false`: inserting
    /// anyway would grow the pool past `max_entries`.
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
        // Every removal path keeps `by_fee` in sync with `by_hash`,
        // so a bucket should only ever hold live hashes. The
        // contains-key check is defence-in-depth for a corrupted
        // internal state (a stale hash is skipped rather than
        // evicting a ghost slot and reporting success).
        let hash = loop {
            match hashes.pop_first() {
                Some(h) if self.by_hash.contains_key(&h) => break h,
                Some(_) => {} // stale — inconsistent state, skip
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
        if let Some(entry) = self.by_hash.remove(&hash)
            && let Some(queue) = self.by_sender.get_mut(&entry.sender)
        {
            queue.remove(&entry.nonce);
            if queue.is_empty() {
                self.by_sender.remove(&entry.sender);
            }
        }
        true
    }

    /// Select up to `max_bytes` of transactions, ordered by fee
    /// density (highest first), respecting per-account nonce ordering.
    ///
    /// Returns the selected transactions as a `Vec<TxBytes>` —
    /// **without removing them from the pool**. Selection is a peek:
    /// a proposed-but-uncommitted tx must survive a lost round, a
    /// gas-filtered candidate must survive to the next block, and
    /// the pool's job is to hold txs until they are *finalized*.
    /// Removal happens in [`remove_committed`](Self::remove_committed)
    /// when the executor finalizes a block, and in
    /// [`refresh_anchors`](Self::refresh_anchors) for entries whose
    /// nonce was consumed by a different tx. The previous remove-on-
    /// select behaviour dropped every selected tx the moment a
    /// proposal was built: a lost proposal or a gas-filter skip
    /// erased the tx permanently — a silent liveness leak.
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
        self.select_with_gas(max_bytes).into_iter().map(|(tx, _gas)| tx).collect()
    }

    /// [`select`](Self::select) with each candidate's precomputed gas
    /// estimate — the proposal gas-cap loop reads `gas` instead of
    /// re-parsing the envelope and calling `estimate_gas` per
    /// candidate (~0.42µs/tx saved; ~17ms per proposal at a 40k-tx
    /// backlog). Entries inserted via [`submit`](Self::submit) carry
    /// `gas = 0` (no module context at that site) — the caller falls
    /// back to per-candidate estimation for those.
    ///
    /// The walk is identical to `select`'s; only the projection
    /// differs, so the two can never diverge on ORDER.
    pub fn select_with_gas(&mut self, max_bytes: u64) -> Vec<(TxBytes, u64)> {
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
            if let Some(&hash) = queue.values().next()
                && let Some(entry) = self.by_hash.get(&hash)
            {
                heap.push((FeeDensity { fee: entry.fee, size: entry.size }, *sender));
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
                // `executed` is a decoded u64 nonce — an adversarial
                // tx with nonce u64::MAX would wrap `executed + 1`
                // to 0 (panic in debug), re-anchoring selection at
                // nonce 0. No valid nonce follows MAX: skip the
                // sender entirely.
                Some(&executed) => match executed.checked_add(1) {
                    Some(next) => next,
                    None => continue,
                },
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
                    // A miss is not necessarily a gap. Two covers let
                    // the walk step over it: `pending_commit` — the
                    // commit path vacated the nonce but the execution
                    // lane hasn't confirmed — and `in_chain` — an
                    // uncommitted ancestor block carries the nonce, so
                    // it executes before this position and the chain
                    // stays contiguous (the pipelined-consensus case
                    // where each leader only pools its own round's
                    // txs). A nonce in neither place is a real gap:
                    // stop the chain.
                    if self
                        .pending_commit
                        .get(&sender)
                        .is_some_and(|pending| pending.contains_key(&nonce))
                        || self
                            .in_chain
                            .get(&sender)
                            .is_some_and(|cover| cover.contains_key(&nonce))
                    {
                        nonce = nonce.saturating_add(1);
                        continue;
                    }
                    break;
                };
                // In-flight: an earlier uncommitted proposal
                // already carries this tx — re-selecting it would
                // commit as a deterministic nonce skip and waste
                // the slot. Skip the hash but keep walking the
                // nonce chain: positions commit in order, so a
                // later proposal position may carry this sender's
                // next nonces (that is the pipelining win). The
                // skip is safe on a dead branch — a descendant
                // position can only commit after its parent, so
                // this tx's position always resolves before any
                // proposal carrying the later nonces commits.
                if self.proposed.iter().any(|set| set.contains(&hash)) {
                    nonce = nonce.saturating_add(1);
                    continue;
                }
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

        // Peek: clone the selected txs out in selection order —
        // entries stay in every index until `remove_committed` runs
        // at finalization. `TxBytes` is a `Vec<u8>`, so this copies
        // up to `max_bytes` of payload per proposal; at block
        // cadence that memcpy is the price of keeping proposed txs
        // alive across lost rounds (the alternative — removing at
        // selection — silently dropped every tx in a losing
        // proposal and every gas-filtered candidate).
        let mut selected = Vec::with_capacity(selected_order.len());
        for hash in selected_order {
            if let Some(entry) = self.by_hash.get(&hash) {
                selected.push((entry.tx.clone(), entry.gas));
            }
        }

        selected
    }

    /// Record a built proposal's tx set as in-flight.
    ///
    /// `select` is a peek, so a pipelined `prepare_proposal` for the
    /// next position would otherwise re-select the same head of each
    /// sender's nonce chain — every duplicate commits as a
    /// deterministic nonce skip and wastes the block space. Marking
    /// each proposal's contents closes that window while keeping the
    /// liveness property the peek was built for: the txs stay pooled,
    /// so a lost proposal's work re-selects once its position
    /// resolves on commit (see `proposed`).
    ///
    /// The set is pushed unconditionally — even for an empty
    /// proposal — because `remove_committed` resolves exactly one
    /// position per call and the deque's order must stay aligned
    /// with the chain's position order. A missed push would release
    /// a later set early (re-admitting its txs for one position —
    /// the duplicate-skip this exists to prevent); an extra push
    /// only delays a release past its position, which is the safe
    /// direction.
    ///
    /// Hashes are recomputed here because `Proposal` carries only
    /// `TxBytes`: O(proposal txs) hashing on the proposal path —
    /// the same price `remove_committed` pays at finalization.
    pub fn note_proposed(&mut self, txs: &[TxBytes]) {
        let set: HashSet<Hash> =
            txs.iter().map(|tx| Hasher::hash_one(Domain::Transaction, tx.as_bytes())).collect();
        self.proposed.push_back(set);
        while self.proposed.len() > MAX_IN_FLIGHT_PROPOSALS {
            self.proposed.pop_front();
        }
    }

    /// Record the nonce coverage of an *observed* chain proposal —
    /// called from the app's `process_proposal` for every accepted
    /// proposal, this node's own and foreign leaders' alike.
    ///
    /// This is the information [`select`](Self::select) needs that
    /// the local queue structurally lacks: which sender nonces are
    /// already carried by uncommitted ancestor blocks. A re-
    /// proposal at a later height refreshes the entry's TTL (`max`
    /// keeps the newest cover — the dead-height can't out-live the
    /// live one). Entries with an unparseable tx are skipped — a
    /// malformed proposal is rejected before this runs, so the loop
    /// sees only statically valid txs.
    ///
    /// O(txs) parse + `BTreeMap` insert on the vote path — cold
    /// relative to per-tx signature checks already paid there.
    pub fn note_in_chain(&mut self, txs: &[TxBytes], height: u64) {
        for tx in txs {
            if let Some((sender, nonce, _fee)) = parse_tx(tx.as_bytes()) {
                self.in_chain
                    .entry(sender)
                    .or_default()
                    .entry(nonce)
                    .and_modify(|h| *h = (*h).max(height))
                    .or_insert(height);
            }
        }
    }

    /// Remove committed transactions from the pool. Called by the
    /// executor at block finalization (`finalize_block`) with the
    /// block's tx list: a committed tx — whether it executed or was
    /// skipped inside the block — has left the mempool's custody,
    /// and re-proposing it can only waste block space (a nonce-
    /// consumed copy is rejected by the executor's continuity gate;
    /// a deterministically-skipped copy skips again). Entries are
    /// removed from all three indices through the same path as
    /// eviction and replacement, so `by_fee` never accumulates
    /// tombstones — the steady-state leak the lazy-pruning scheme
    /// allowed when selection drained the pool without touching the
    /// fee index.
    ///
    /// Hashes are recomputed here because `FinalizedBlock` carries
    /// only `TxBytes`: O(block txs) hashing on the commit path.
    ///
    /// Also resolves the oldest outstanding proposal position: the
    /// commit answers whether that proposal's txs committed (they
    /// are already gone via `remove` below) or must re-select (a
    /// different branch won the position — the released set is
    /// eligible again on the next `select`).
    /// `height` is the committing block's height: `pending_commit`
    /// entries are expired by *executed* height in
    /// [`refresh_anchors`](Self::refresh_anchors), which needs the
    /// commit height to tell "still in the lane" from "resolved".
    pub fn remove_committed(&mut self, txs: &[TxBytes], height: u64) {
        self.proposed.pop_front();
        for tx in txs {
            let hash = Hasher::hash_one(Domain::Transaction, tx.as_bytes());
            // Record the vacated nonce as committed-but-unexecuted so
            // `select` can bridge the phantom gap an execution-lane
            // lag would otherwise leave between the stale anchor and
            // the next queued nonce (empty proposals under load —
            // the devnet fault-injection flake). Recorded from the
            // committed *bytes*, not pool membership: a validator
            // that never held the tx (it was proposed by another
            // leader) still needs the bridge. A nonce committed twice
            // keeps the later height — either copy executing first
            // resolves the slot identically.
            if let Some((sender, nonce, _fee)) = parse_tx(tx.as_bytes()) {
                self.pending_commit.entry(sender).or_default().insert(nonce, height);
            }
            self.remove(&hash);
        }
    }

    /// Refresh the executed-nonce anchors from the executor's
    /// post-block nonce map, and prune entries whose nonce was
    /// already consumed.
    ///
    /// The executor calls this once per executed block with its
    /// `executed_nonce` map — the live update path the anchor
    /// mechanism was built for (without it, `select` always
    /// anchored at the sender's minimum queued nonce and could
    /// re-propose already-executed nonces).
    ///
    /// # Map semantics: next-expected in, last-executed stored
    ///
    /// The executor's map stores the *next expected* nonce per
    /// sender (`expected + 1` after each executed tx) while this
    /// pool's `executed_nonces` — like `set_executed_nonce` —
    /// records the *last executed* nonce (`select` starts at
    /// `anchor + 1`). Refresh converts: `last = next - 1`. Only
    /// senders with pooled transactions need an anchor, so the map
    /// is *rebuilt* from `by_sender`'s keys each block: entries for
    /// senders that left the pool are dropped, keeping the map
    /// bounded by pool occupancy rather than growing forever with
    /// every account ever executed.
    ///
    /// `next_expected` is a lookup, not a map: the executor's
    /// post-block nonce state is a delta over the committed map
    /// (never materialized as one `HashMap`), so the pool queries
    /// the effective value per pooled sender — O(pool occupancy),
    /// never O(accounts).
    ///
    /// Pruning drops queued entries with `nonce < next_expected`:
    /// their nonce slot is already spent (a different tx consumed
    /// it — e.g. a same-nonce replacement that won in a competing
    /// block), so they can never execute and would otherwise occupy
    /// pool space until a size-cap eviction reached them.
    /// `executed_height` is the height this refresh executed: every
    /// `pending_commit` entry at or below it has been resolved by
    /// execution — consumed (covered by the rebuilt anchor) or
    /// skipped (dead slot: un-bridging it lets a nonce refill
    /// become selectable again). Entries above it remain in flight.
    pub fn refresh_anchors(
        &mut self,
        executed_height: u64,
        next_expected: impl Fn(&Address) -> Option<u64>,
    ) {
        self.executed_nonces = self
            .by_sender
            .keys()
            .filter_map(|sender| {
                next_expected(sender)
                    // `next - 1` = last executed. A `next` of 0 is
                    // corrupt (a consumed nonce is at least 1) —
                    // skip the anchor rather than underflow.
                    .and_then(|next| next.checked_sub(1))
                    .map(|last| (*sender, last))
            })
            .collect();
        // Expire resolved bridges — `<= executed_height` covers both
        // outcomes: consumed slots are inside the refreshed anchor,
        // skipped ones must stop shadowing the sender's nonce floor.
        self.pending_commit.retain(|_, pending| {
            pending.retain(|_, committed_height| *committed_height > executed_height);
            !pending.is_empty()
        });
        // Same for observed chain coverage: a cover dies when the
        // rebuilt anchor passes its nonce (execution resolved the
        // slot — the pool no longer needs the bridge) or when its
        // proposal height falls CHAIN_COVER_TTL behind the executed
        // tip (the covering block never committed — its branch is
        // dead and the gap is real). A sender whose queue emptied is
        // absent from the rebuilt anchor; its entries ride the TTL
        // until expiry.
        self.in_chain.retain(|sender, cover| {
            let anchor = self.executed_nonces.get(sender).copied().unwrap_or(0);
            cover.retain(|nonce, h| *nonce > anchor && *h + CHAIN_COVER_TTL > executed_height);
            !cover.is_empty()
        });
        // Collect stale hashes first — `by_sender` can't be mutated
        // while its queues are borrowed for the range scan.
        let mut stale: Vec<Hash> = Vec::new();
        for (sender, queue) in &self.by_sender {
            if let Some(next) = next_expected(sender) {
                stale.extend(queue.range(..next).map(|(_, &hash)| hash));
            }
        }
        for hash in stale {
            self.remove(&hash);
        }
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
                // `executed + 1` must not wrap: an executed nonce of
                // u64::MAX leaves no valid successor, so every queued
                // nonce is stale — `None` marks them all non-pending.
                Some(&executed) => executed.checked_add(1),
                None => queue.keys().next().copied(),
            };
            for (&nonce, hash) in queue {
                let Some(entry) = self.by_hash.get(hash) else { continue };
                let pending = match next_expected {
                    // Below the start nonce: stale — can't execute.
                    Some(expected) if nonce < expected => continue,
                    Some(expected) if nonce == expected => {
                        // `expected == nonce == u64::MAX` → no valid
                        // successor; `None` marks the rest non-pending.
                        next_expected = expected.checked_add(1);
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
    /// [`submit`](Self::submit), by [`remove_committed`](
    /// Self::remove_committed) at finalization, by
    /// [`refresh_anchors`](Self::refresh_anchors) pruning, and by
    /// pool-full eviction. Keeping every removal on this one path is
    /// what guarantees `by_fee` stays exactly in sync with
    /// `by_hash`.
    fn remove(&mut self, hash: &Hash) {
        if let Some(entry) = self.by_hash.remove(hash) {
            let density = FeeDensity { fee: entry.fee, size: entry.size };
            if let Some(hashes) = self.by_fee.get_mut(&density) {
                hashes.remove(hash);
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
        // Selection is a peek — the tx stays pooled until the block
        // finalizes, so a losing proposal can't lose it.
        assert_eq!(pool.len(), 1, "peek select leaves entries pooled");
        pool.remove_committed(&selected, 1);
        assert_eq!(pool.len(), 0, "finalization removes committed txs");
    }

    /// Regression: the per-sender cap was only applied when building
    /// a block, so one account could occupy the entire pool.
    #[test]
    fn submit_enforces_per_sender_limit() {
        let mut pool = Mempool::new(100).with_max_pending_per_sender(3);
        for nonce in 0..3 {
            assert!(pool.submit(build_tx(addr(1), nonce, 100, &[])).is_ok());
        }
        assert_eq!(
            pool.submit(build_tx(addr(1), 3, 100, &[])),
            Err(MempoolError::SenderLimit),
            "a fourth pending tx exceeds the cap"
        );
        assert!(
            pool.submit(build_tx(addr(1), 2, 200, &[])).is_ok(),
            "a replacement reuses its slot"
        );
        assert!(pool.submit(build_tx(addr(2), 0, 100, &[])).is_ok(), "other senders unaffected");

        pool.set_executed_nonce(addr(3), 10);
        assert!(pool.submit(build_tx(addr(3), 13, 100, &[])).is_ok());
        assert_eq!(
            pool.submit(build_tx(addr(3), 14, 100, &[])),
            Err(MempoolError::SenderLimit),
            "nonce too far ahead of the executed anchor"
        );
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
        // Both txs stay pooled until finalization removes them.
        pool.remove_committed(&selected, 1);
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
        assert_eq!(pool.len(), 2, "peek: both txs stay pooled");
        // After the selected tx commits, one remains for next block.
        pool.remove_committed(&selected, 1);
        assert_eq!(pool.len(), 1, "one tx remains after commit");
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
        pool.remove_committed(&selected, 1);
        assert_eq!(pool.len(), 0, "pool should be empty after commit");
        // Committing drained every index — a `by_fee` tombstone
        // would leave a non-empty bucket behind.
        assert!(pool.by_fee.is_empty(), "fee index fully drained");
        assert!(pool.by_sender.is_empty(), "sender index fully drained");
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
        // Commit all — removal should clean up the sender queue.
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 3);
        pool.remove_committed(&selected, 1);
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
        // The victim's tx is selected too (room left after capping).
        assert!(
            selected.iter().any(|tx| parse_tx(tx.as_bytes()).unwrap().0 == addr(2)),
            "the victim's tx must not be starved"
        );
        // Peek: nothing leaves the pool until the block commits.
        assert_eq!(pool.len(), 6, "peek keeps all entries pooled");
        // Commit the selected txs, then the next select takes the
        // spammer's next two capped nonces.
        pool.remove_committed(&selected, 1);
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
        // Peek: nonces `0..2` selected, all 6 stay pooled; commit
        // removes the selected three.
        pool.remove_committed(&selected, 1);
        assert_eq!(pool.len(), 3);
    }

    /// Regression: an executed nonce of `u64::MAX` must not wrap the
    /// `executed + 1` anchor back to 0 — no valid nonce follows `MAX`,
    /// so the sender's queued txs stay unselected and non-pending.
    #[test]
    fn executed_nonce_max_does_not_wrap_anchor() {
        let mut pool = Mempool::new(100);
        pool.submit(build_tx(addr(1), 0, 100, &[1])).unwrap();
        pool.submit(build_tx(addr(1), u64::MAX, 100, &[2])).unwrap();
        pool.set_executed_nonce(addr(1), u64::MAX);
        // Selection: nothing follows `MAX` — the sender is skipped.
        let selected = pool.select(1 << 20);
        assert!(selected.is_empty(), "no nonce follows u64::MAX");
        // Snapshot: both queued txs report non-pending (never
        // executable) rather than wrapping the anchor to nonce 0.
        let snap = pool.txpool_snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().all(|(_, _, _, pending)| !pending));
    }

    // ---- Finalization-custody tests (peek select + commit removal) ----

    /// A tx in a losing proposal must survive: `select` is a peek,
    /// so the same candidate is re-proposed until a block commits
    /// it. The old remove-on-select behaviour silently dropped every
    /// tx in any proposal that didn't win.
    #[test]
    fn losing_proposal_keeps_txs() {
        let mut pool = Mempool::new(100);
        pool.submit(build_tx(addr(1), 0, 100, &[1])).unwrap();
        let first = pool.select(1 << 20);
        assert_eq!(first.len(), 1);
        // The proposal loses (no `remove_committed`) — the next
        // selection must still offer the tx.
        let second = pool.select(1 << 20);
        assert_eq!(second, first, "uncommitted txs stay re-proposable");
        // And when a block DOES commit it, it leaves for good.
        pool.remove_committed(&second, 1);
        assert!(pool.select(1 << 20).is_empty());
    }

    /// `remove_committed` drains every index — no `by_fee` tombstone
    /// may survive steady-state propose→commit cycles (the leak the
    /// lazy-pruning scheme allowed).
    #[test]
    fn commit_cycles_leave_no_fee_tombstones() {
        let mut pool = Mempool::new(100);
        for round in 0..5u64 {
            for i in 0..4u8 {
                pool.submit(build_tx(addr(i), round, 100 + round, &[0])).unwrap();
            }
            let selected = pool.select(1 << 20);
            pool.remove_committed(&selected, 1);
        }
        assert_eq!(pool.len(), 0);
        assert!(
            pool.by_fee.values().all(BTreeSet::is_empty),
            "every fee bucket must be empty after commit removal"
        );
        assert!(pool.by_fee.is_empty(), "no empty-bucket keys may linger either");
    }

    /// A `by_fee` bucket made entirely of stale hashes must not let
    /// the pool exceed `max_entries`: the submit loop retries the
    /// eviction until a *live* entry is removed or a real `PoolFull`
    /// is decided against the next bucket's density.
    #[test]
    fn eviction_retries_past_stale_bucket() {
        let mut pool = Mempool::new(2);
        pool.submit(build_tx(addr(1), 0, 50, &[0])).unwrap();
        pool.submit(build_tx(addr(2), 0, 60, &[0])).unwrap();
        // Corrupt the index the way the old lazy-prune scheme left
        // it: a tombstone hash in the lowest bucket, present in
        // `by_fee` but absent from `by_hash`.
        let ghost = Hasher::hash_one(Domain::Transaction, b"ghost");
        pool.by_fee.entry(FeeDensity { fee: 1, size: 1 }).or_default().insert(ghost);
        // A new tx outbidding the live floor must still get in — the
        // stale bucket drains, then a real entry is evicted.
        pool.submit(build_tx(addr(3), 0, 70, &[0])).unwrap();
        assert_eq!(pool.len(), 2, "pool stays at capacity");
        assert!(!pool.contains(&ghost), "tombstone bucket is gone");
    }

    /// `refresh_anchors` wires the executor's post-block nonce map
    /// into selection: consumed nonces are pruned outright, and the
    /// anchor re-bases the sender's chain at `executed + 1`.
    #[test]
    fn refresh_anchors_prunes_consumed_nonces() {
        let mut pool = Mempool::new(100);
        for nonce in 0..3u64 {
            pool.submit(build_tx(addr(1), nonce, 100, &[0])).unwrap();
        }
        pool.submit(build_tx(addr(2), 0, 100, &[0])).unwrap();
        // A block consumed addr(1) nonces 0 and 1 — the executor's
        // map reports the *next* expected nonce (2).
        let next_expected = HashMap::from([(addr(1), 2u64)]);
        pool.refresh_anchors(1, |a| next_expected.get(a).copied());
        assert_eq!(pool.len(), 2, "nonces 0 and 1 are pruned");
        // The next selection starts at nonce 2 — the consumed
        // entries can't be re-proposed.
        let selected = pool.select(1 << 20);
        assert_eq!(selected.len(), 2);
        let (s0, n0, _) = parse_tx(selected[0].as_bytes()).unwrap();
        assert_eq!((s0, n0), (addr(2), 0), "equal density: higher address wins the heap tie-break");
        let (s1, n1, _) = parse_tx(selected[1].as_bytes()).unwrap();
        assert_eq!((s1, n1), (addr(1), 2), "addr(1)'s chain re-bases at nonce 2");
    }

    /// Anchors for senders that left the pool are dropped on
    /// refresh, so `executed_nonces` stays bounded by pool
    /// occupancy rather than every account ever executed.
    #[test]
    fn refresh_anchors_drops_departed_senders() {
        let mut pool = Mempool::new(100);
        pool.submit(build_tx(addr(1), 5, 100, &[0])).unwrap();
        pool.set_executed_nonce(addr(1), 4);
        pool.set_executed_nonce(addr(9), 10); // not pooled
        let next_expected = HashMap::from([(addr(1), 4u64), (addr(9), 10u64)]);
        pool.refresh_anchors(1, |a| next_expected.get(a).copied());
        assert_eq!(pool.executed_nonces.len(), 1, "only pooled senders keep an anchor");
        assert!(pool.executed_nonces.contains_key(&addr(1)));
    }

    fn nonces_of(selected: &[TxBytes]) -> Vec<u64> {
        selected.iter().map(|tx| parse_tx(tx.as_bytes()).unwrap().1).collect()
    }

    /// Execution-lane lag must not starve selection: commit vacates
    /// a tx from the queue immediately, but `refresh_anchors` only
    /// rebuilds the executed anchor when the lane finishes the block.
    /// Between the two the sender's queue has a phantom gap —
    /// `select` must bridge it through `pending_commit` instead of
    /// emitting an empty proposal (the devnet fault-injection flake:
    /// "leader should propose" with `work_outstanding=false`).
    #[test]
    fn select_bridges_committed_unexecuted_gap() {
        let mut pool = Mempool::new(100);
        // Sender 1's executed anchor is stale (lane still owes the
        // blocks) while commits already vacated nonces 1 and 2.
        pool.set_executed_nonce(addr(1), 0);
        pool.remove_committed(&[build_tx(addr(1), 1, 100, &[0])], 1);
        pool.remove_committed(&[build_tx(addr(1), 2, 100, &[0])], 2);
        // The live tx queues at nonce 3 — the phantom gap at 1..3.
        pool.submit(build_tx(addr(1), 3, 100, &[0])).unwrap();
        let selected = pool.select(1 << 20);
        assert_eq!(nonces_of(&selected), vec![3], "the bridge covers the vacated nonces");

        // Once the lane executes through the committing heights the
        // bridges expire: the refreshed anchor (nonces ≤ 2 consumed)
        // carries the chain and `pending_commit` empties. The live
        // nonce-3 tx is still queued and stays selectable.
        let next_expected = HashMap::from([(addr(1), 3u64)]);
        pool.refresh_anchors(2, |a| next_expected.get(a).copied());
        assert!(!pool.pending_commit.contains_key(&addr(1)));
        assert_eq!(nonces_of(&pool.select(1 << 20)), vec![3]);
    }

    /// A committed nonce that *skips* at execution (its nonce never
    /// consumed) must un-bridge once that height executes — keeping
    /// it would dead-lock the sender's refilled nonce forever.
    #[test]
    fn skipped_committed_nonce_unbridges_on_execution() {
        let mut pool = Mempool::new(100);
        pool.set_executed_nonce(addr(1), 0);
        // Nonce 1 commits but skips at execution (next_expected
        // stays 1) — its bridge must not outlive the executed height.
        pool.remove_committed(&[build_tx(addr(1), 1, 100, &[0])], 1);
        // The user refills nonce 1 — the bridge must not hide it.
        pool.submit(build_tx(addr(1), 1, 200, &[1])).unwrap();
        let next_expected = HashMap::from([(addr(1), 1u64)]);
        pool.refresh_anchors(1, |a| next_expected.get(a).copied());
        assert_eq!(
            nonces_of(&pool.select(1 << 20)),
            vec![1],
            "refill at the skipped nonce is selectable again"
        );
    }

    /// The pipelined-consensus gap: each leader only pools its own
    /// submissions, so a validator whose mempool anchors at the
    /// executed nonce sees a hole where uncommitted ancestor blocks
    /// (proposed by other leaders) carry the missing nonces. Without
    /// `in_chain` coverage the walk broke at the hole and the leader
    /// proposed an empty block — the devnet fault-injection flake
    /// ("leader should propose" at the flush round with
    /// `work_outstanding=false`).
    #[test]
    fn select_bridges_in_flight_ancestor_gap() {
        let mut pool = Mempool::new(100);
        pool.set_executed_nonce(addr(1), 0);
        // Nonces 1 and 2 were observed in accepted proposals at
        // heights 1 and 2 — foreign leaders' blocks this validator
        // voted on but never pooled.
        pool.note_in_chain(&[build_tx(addr(1), 1, 100, &[0])], 1);
        pool.note_in_chain(&[build_tx(addr(1), 2, 100, &[0])], 2);
        // The validator holds only nonce 3, submitted to it directly.
        pool.submit(build_tx(addr(1), 3, 100, &[0])).unwrap();
        assert_eq!(
            nonces_of(&pool.select(1 << 20)),
            vec![3],
            "the ancestor cover bridges nonces 1 and 2"
        );

        // The covers expire once the covering heights fall behind
        // the executed tip: if those ancestor blocks never committed
        // (dead branch), the gap is real again and selection must
        // stop bridging it.
        let next_expected = HashMap::from([(addr(1), 1u64)]);
        pool.refresh_anchors(CHAIN_COVER_TTL + 2, |a| next_expected.get(a).copied());
        assert!(!pool.in_chain.contains_key(&addr(1)), "dead-branch covers expire");
        assert_eq!(pool.select(1 << 20).len(), 0, "a real gap breaks the walk");
    }

    /// The defect this guards: `select` is a peek, so a pipelined
    /// `prepare_proposal` at the next position used to re-select the
    /// same mempool head — every duplicate committed as a nonce
    /// skip and wasted block space. After `note_proposed`, a second
    /// select must skip the in-flight txs and continue the sender's
    /// nonce chain with the next unproposed entries.
    #[test]
    fn pipelined_select_skips_in_flight_and_continues_chain() {
        let mut pool = Mempool::new(100).with_max_per_sender(2);
        for nonce in 0..4u64 {
            pool.submit(build_tx(addr(1), nonce, 100, &[u8::try_from(nonce).unwrap_or(0xff)]))
                .unwrap();
        }
        pool.submit(build_tx(addr(2), 0, 100, &[9])).unwrap();

        let first = pool.select(1 << 20);
        pool.note_proposed(&first);
        // cap=2 → the first proposal carries addr(1) nonces 0,1 and
        // addr(2) nonce 0 (fee ties order across senders; collect
        // nonces per sender instead of asserting an interleave).
        assert_eq!(first.len(), 3);

        let second = pool.select(1 << 20);
        // The in-flight txs must not re-appear; addr(1)'s chain
        // continues at nonce 2 past the in-flight prefix — that
        // continuation is the pipelining win.
        assert_eq!(
            nonces_of(&second),
            vec![2, 3],
            "second proposal extends the chain past in-flight entries"
        );
    }

    /// A dead proposal's txs must re-select: `remove_committed`
    /// resolves the oldest outstanding position, so a commit that
    /// carried none of them releases the set.
    #[test]
    fn in_flight_releases_when_position_commits() {
        let mut pool = Mempool::new(100);
        for nonce in 0..3u64 {
            pool.submit(build_tx(addr(1), nonce, 100, &[u8::try_from(nonce).unwrap_or(0xff)]))
                .unwrap();
        }
        let first = pool.select(1 << 20);
        pool.note_proposed(&first);
        assert!(
            pool.select(1 << 20).is_empty(),
            "in-flight head is excluded while its position is open"
        );

        // A different branch won the position: the commit carries
        // none of the proposed txs. The set releases.
        pool.remove_committed(&[], 1);
        let reselected = pool.select(1 << 20);
        assert_eq!(
            nonces_of(&reselected),
            vec![0, 1, 2],
            "released txs re-select after their position resolves"
        );
        assert_eq!(pool.len(), 3, "release does not drop pooled txs");
    }

    /// Committing a block that did carry the proposed txs removes
    /// them from the pool and releases the position — subsequent
    /// selects see only the uncommitted remainder.
    #[test]
    fn committed_proposal_drains_and_releases() {
        let mut pool = Mempool::new(100).with_max_per_sender(2);
        for nonce in 0..4u64 {
            pool.submit(build_tx(addr(1), nonce, 100, &[u8::try_from(nonce).unwrap_or(0xff)]))
                .unwrap();
        }
        let first = pool.select(1 << 20);
        pool.note_proposed(&first);
        let second = pool.select(1 << 20);
        pool.note_proposed(&second);

        // Position 1 commits its proposal: those txs leave the
        // pool, and the position resolves.
        pool.remove_committed(&first, 1);
        assert_eq!(pool.len(), 2);
        // Position 2 still open: nonces 2,3 stay in-flight.
        assert!(pool.select(1 << 20).is_empty());
        // Position 2 resolves the same way.
        pool.remove_committed(&second, 1);
        assert_eq!(pool.len(), 0);
    }

    /// Commits resolve outstanding proposal positions oldest-first:
    /// a released position's txs re-select while a still-open
    /// position's stay excluded — the deque order tracks the chain's
    /// position order.
    #[test]
    fn commits_resolve_positions_oldest_first() {
        let mut pool = Mempool::new(100).with_max_per_sender(1);
        pool.submit(build_tx(addr(1), 0, 100, &[0])).unwrap();
        pool.submit(build_tx(addr(1), 1, 100, &[1])).unwrap();

        let first = pool.select(1 << 20); // carries nonce 0
        pool.note_proposed(&first);
        let second = pool.select(1 << 20); // continues past it: nonce 1
        pool.note_proposed(&second);
        assert_eq!(nonces_of(&second), vec![1]);

        // An alien block won position 1: the first set releases,
        // the second stays in-flight.
        pool.remove_committed(&[], 1);
        let third = pool.select(1 << 20);
        assert_eq!(
            nonces_of(&third),
            vec![0],
            "released position-1 tx re-selects while position 2 is open"
        );
        pool.note_proposed(&third);

        // Position 2 resolves on the next commit — its tx releases.
        pool.remove_committed(&[], 1);
        let fourth = pool.select(1 << 20);
        assert_eq!(nonces_of(&fourth), vec![1], "position 2 resolves on its own commit");
    }
}
