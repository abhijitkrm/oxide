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
}

/// Fee density: fee per byte. Higher is better. We use a tuple
/// `(fee, size)` so that `BTreeMap`'s natural ordering (ascending)
/// gives us lowest-first; we reverse to get highest-first.
///
/// The `Ord` implementation compares by `fee / size` (integer
/// division), then by `fee` as a tiebreaker. This is the fee-density
/// ranking used by the leader to maximize value per block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FeeDensity {
    /// The fee in raw units.
    fee: u64,
    /// The serialized size in bytes.
    size: u64,
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
        }
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

    /// Evict the lowest-fee entry from the pool. Returns `true` if an
    /// entry was evicted, `false` if the pool was empty.
    fn evict_lowest_fee(&mut self) -> bool {
        // The lowest fee density is the first key in `by_fee` (ascending).
        let Some(lowest_density) = self.by_fee.keys().next().copied() else {
            return false;
        };
        let hashes = self.by_fee.get_mut(&lowest_density).expect("key exists");
        let hash = hashes.pop().expect("non-empty fee bucket");
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
    pub fn select(&mut self, max_bytes: u64) -> Vec<TxBytes> {
        let mut selected = Vec::new();
        let mut total_bytes = 0u64;
        // Track the next expected nonce per sender. Initialize from
        // the pool's per-sender minimum nonce — not 0 — so that
        // across multiple `select` calls, the expected nonce advances
        // correctly. After the first `select` removes nonce 0, the
        // pool's minimum nonce for that sender is 1, so the next
        // `select` call starts expecting nonce 1.
        let mut next_nonce: HashMap<Address, u64> = HashMap::new();
        for (sender, queue) in &self.by_sender {
            if let Some(&min_nonce) = queue.keys().next() {
                next_nonce.insert(*sender, min_nonce);
            }
        }

        // Iterate fee densities highest-first by walking the BTreeMap
        // in reverse. The BTreeMap is already sorted by `FeeDensity`
        // (ascending), so reverse iteration gives us highest-first
        // without collecting into a Vec and sorting — O(n) iteration
        // with zero allocation, vs the old O(n log n) sort.
        //
        // We collect hashes to remove after iteration (can't mutate
        // `by_fee` while iterating it).
        let mut to_remove: Vec<Hash> = Vec::new();

        for (_density, hashes) in self.by_fee.iter().rev() {
            for &hash in hashes {
                if total_bytes >= max_bytes {
                    break;
                }
                let Some(entry) = self.by_hash.get(&hash) else {
                    continue;
                };
                // Check nonce ordering: the tx's nonce must equal the
                // sender's next expected nonce.
                let expected = next_nonce.entry(entry.sender).or_insert(0);
                if entry.nonce != *expected {
                    continue;
                }
                // Check byte budget.
                if total_bytes + entry.size > max_bytes {
                    continue;
                }
                // Select this tx.
                total_bytes += entry.size;
                selected.push(entry.tx.clone());
                *expected += 1;
                to_remove.push(hash);
            }
            if total_bytes >= max_bytes {
                break;
            }
        }

        // Remove selected entries from the pool.
        for hash in &to_remove {
            self.remove(hash);
        }

        selected
    }

    /// Remove a transaction by hash from all indices.
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
        // Submit nonce 1 before nonce 0 — nonce 1 should be skipped.
        pool.submit(build_tx(addr(1), 1, 100, &[1])).unwrap();
        pool.submit(build_tx(addr(1), 0, 100, &[0])).unwrap();
        let selected = pool.select(1 << 20);
        // Only nonce 0 is selected (nonce 1 is skipped until 0 is included).
        assert_eq!(selected.len(), 1);
        let (_, nonce, _) = parse_tx(selected[0].as_bytes()).unwrap();
        assert_eq!(nonce, 0);
        // After selecting nonce 0, nonce 1 is still in the pool.
        assert_eq!(pool.len(), 1);
        // Select again — now nonce 1 should be available.
        let selected2 = pool.select(1 << 20);
        assert_eq!(selected2.len(), 1);
        let (_, nonce2, _) = parse_tx(selected2[0].as_bytes()).unwrap();
        assert_eq!(nonce2, 1);
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
}
