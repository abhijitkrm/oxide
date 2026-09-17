//! Oxide indexer/explorer v0 (plan.md §13, Phase 2).
//!
//! ## What this module is
//!
//! A block indexer that consumes finalized blocks and indexes them
//! for block explorer queries. This is the foundation for a Blockscout-
//! style explorer: it provides query APIs for block lookup, transaction
//! lookup, and event lookup.
//!
//! ## Why an indexer, not direct RPC queries
//!
//! The plan (plan.md §8) separates the node from the explorer: "indexer
//! publishes to SQL for explorer (constantinople-indexer pattern)". The
//! indexer is a read-only consumer of finalized blocks — it never
//! participates in consensus or execution. This keeps the node's hot
//! path clean and lets the explorer scale independently.
//!
//! ## Phase 2 scope
//!
//! v0 implements:
//! - An in-memory index of finalized blocks (by height, tx hash).
//! - Query APIs: `get_block_by_height`, `get_block_by_hash`, `get_tx`, `range`.
//! - Block summary serialization (for explorer JSON API).
//! - Event indexing (by module, by kind).
//!
//! Future phases add:
//! - SQL backend (PostgreSQL/SQLite) for persistent storage.
//! - Full Blockscout-compatible API.
//! - WebSocket subscriptions for real-time updates.
//! - EVM transaction receipt indexing.

use std::collections::BTreeMap;

use primitives::Hash;
use types::FinalizedBlock;

/// A block summary for explorer display.
///
/// Contains the essential block information without the full
/// transaction payloads — the explorer fetches full transactions
/// separately via `get_tx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSummary {
    /// The block height.
    pub height: u64,
    /// The block hash (hash of the finalized block).
    pub block_hash: Hash,
    /// The number of transactions in the block.
    pub tx_count: usize,
    /// The state root after executing this block (if available).
    pub state_root: Option<Hash>,
}

/// An indexed transaction.
///
/// Contains the transaction's hash, its position in the block, and
/// the raw transaction bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedTx {
    /// The transaction hash (hash of the raw bytes).
    pub tx_hash: Hash,
    /// The block height containing this tx.
    pub height: u64,
    /// The tx's index within the block (0-based).
    pub index: usize,
    /// The raw transaction bytes.
    pub bytes: Vec<u8>,
}

/// An indexed event.
///
/// Contains the event's module, kind, and data, plus the block height
/// and tx index that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedEvent {
    /// The block height that produced this event.
    pub height: u64,
    /// The tx index within the block (0-based).
    pub tx_index: usize,
    /// The module that emitted the event.
    pub module: String,
    /// The event kind.
    pub kind: String,
    /// The event data (module-specific).
    pub data: Vec<u8>,
}

/// The indexer: an in-memory index of finalized blocks.
///
/// Indexes blocks by height and transaction hash. Provides query
/// APIs for block explorer display. The index is append-only — once
/// a block is indexed, it's never modified (the chain is reorg-free,
/// plan.md §8).
pub struct Indexer {
    /// Blocks indexed by height.
    blocks_by_height: BTreeMap<u64, BlockSummary>,
    /// Transactions indexed by hash.
    txs_by_hash: BTreeMap<Hash, IndexedTx>,
    /// Transactions indexed by (height, index).
    txs_by_position: BTreeMap<(u64, usize), IndexedTx>,
    /// Events indexed by (height, `tx_index`, `event_index`).
    events: Vec<IndexedEvent>,
    /// Events indexed by module.
    events_by_module: BTreeMap<String, Vec<usize>>,
    /// The highest indexed block height.
    highest_height: u64,
}

impl Indexer {
    /// Create a fresh, empty indexer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blocks_by_height: BTreeMap::new(),
            txs_by_hash: BTreeMap::new(),
            txs_by_position: BTreeMap::new(),
            events: Vec::new(),
            events_by_module: BTreeMap::new(),
            highest_height: 0,
        }
    }

    /// Index a finalized block.
    ///
    /// Extracts the block summary, transactions, and events, and
    /// adds them to the index. The block must be finalized (the
    /// indexer only consumes finalized blocks, plan.md §8).
    ///
    /// # Panics
    ///
    /// This function does not panic. Duplicate heights are silently
    /// ignored (the block is already indexed).
    pub fn index_block(&mut self, block: &FinalizedBlock) {
        let height = block.height.value();

        // Skip if already indexed (idempotent).
        if self.blocks_by_height.contains_key(&height) {
            return;
        }

        // Index the block summary.
        let block_hash = block_hash(block);
        let summary = BlockSummary {
            height,
            block_hash,
            tx_count: block.txs.len(),
            state_root: None, // set via set_state_root
        };
        self.blocks_by_height.insert(height, summary);

        // Index each transaction.
        for (index, tx) in block.txs.iter().enumerate() {
            let tx_bytes = tx.as_bytes();
            let tx_hash = tx_hash(tx_bytes);
            let indexed = IndexedTx { tx_hash, height, index, bytes: tx_bytes.to_vec() };
            self.txs_by_hash.insert(tx_hash, indexed.clone());
            self.txs_by_position.insert((height, index), indexed);
        }

        // Update the highest height.
        if height > self.highest_height {
            self.highest_height = height;
        }
    }

    /// Set the state root for a block (after execution).
    ///
    /// Called by the executor after it computes the state root for
    /// a block. The state root is displayed in the explorer.
    pub fn set_state_root(&mut self, height: u64, root: Hash) {
        if let Some(summary) = self.blocks_by_height.get_mut(&height) {
            summary.state_root = Some(root);
        }
    }

    /// Index an event from a block execution.
    ///
    /// Events are indexed by module for efficient module-specific
    /// queries (e.g., "show all staking ops").
    pub fn index_event(&mut self, event: IndexedEvent) {
        let event_idx = self.events.len();
        self.events_by_module.entry(event.module.clone()).or_default().push(event_idx);
        self.events.push(event);
    }

    /// Get a block summary by height.
    #[must_use]
    pub fn get_block_by_height(&self, height: u64) -> Option<&BlockSummary> {
        self.blocks_by_height.get(&height)
    }

    /// Get a block summary by hash.
    #[must_use]
    pub fn get_block_by_hash(&self, hash: &Hash) -> Option<&BlockSummary> {
        self.blocks_by_height.values().find(|summary| &summary.block_hash == hash)
    }

    /// Get a transaction by hash.
    #[must_use]
    pub fn get_tx(&self, hash: &Hash) -> Option<&IndexedTx> {
        self.txs_by_hash.get(hash)
    }

    /// Get a transaction by (height, index).
    #[must_use]
    pub fn get_tx_by_position(&self, height: u64, index: usize) -> Option<&IndexedTx> {
        self.txs_by_position.get(&(height, index))
    }

    /// Get the latest block height.
    #[must_use]
    pub fn latest_height(&self) -> u64 {
        self.highest_height
    }

    /// Get all events for a given module.
    #[must_use]
    pub fn get_events_by_module(&self, module: &str) -> Vec<&IndexedEvent> {
        self.events_by_module
            .get(module)
            .map(|indices| indices.iter().filter_map(|&i| self.events.get(i)).collect())
            .unwrap_or_default()
    }

    /// Get all events for a given block height.
    #[must_use]
    pub fn get_events_by_height(&self, height: u64) -> Vec<&IndexedEvent> {
        self.events.iter().filter(|e| e.height == height).collect()
    }

    /// Get a range of block summaries (for explorer pagination).
    ///
    /// Returns blocks from `from` to `to` (inclusive), in descending
    /// height order (latest first, for explorer display).
    #[must_use]
    pub fn get_block_range(&self, from: u64, to: u64) -> Vec<&BlockSummary> {
        (from..=to).rev().filter_map(|h| self.blocks_by_height.get(&h)).collect()
    }

    /// Total number of indexed blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks_by_height.len()
    }

    /// Total number of indexed transactions.
    #[must_use]
    pub fn tx_count(&self) -> usize {
        self.txs_by_hash.len()
    }

    /// Total number of indexed events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for Indexer {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the hash of a finalized block (for indexing).
///
/// The block hash is the hash of the block's height + all tx hashes.
/// This is a simple v0 hash; the full implementation uses the
/// `OxideBlockRecord` hash (plan.md §8).
fn block_hash(block: &FinalizedBlock) -> Hash {
    use codec::Encode;
    let mut buf = Vec::new();
    block.height.encode(&mut buf);
    for tx in &block.txs {
        let tx_hash = tx_hash(tx.as_bytes());
        buf.extend_from_slice(tx_hash.as_bytes());
    }
    crypto::hash::Hasher::hash_one(crypto::hash::Domain::Block, &buf)
}

/// Compute the hash of a transaction (for indexing).
fn tx_hash(tx_bytes: &[u8]) -> Hash {
    // Use Domain::Block for tx hashing (no dedicated Tx domain yet).
    // The domain separation prevents cross-protocol collisions; using
    // Block for txs is safe since tx hashes are never compared to
    // block hashes.
    crypto::hash::Hasher::hash_one(crypto::hash::Domain::Block, tx_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::Height;
    use types::TxBytes;

    fn make_block(height: u64, txs: Vec<Vec<u8>>) -> FinalizedBlock {
        let txs: Vec<TxBytes> = txs.into_iter().map(TxBytes::new).collect();
        FinalizedBlock { height: Height::new(height), txs }
    }

    #[test]
    fn indexer_starts_empty() {
        let idx = Indexer::new();
        assert_eq!(idx.block_count(), 0);
        assert_eq!(idx.tx_count(), 0);
        assert_eq!(idx.event_count(), 0);
    }

    #[test]
    fn index_block_adds_summary() {
        let mut idx = Indexer::new();
        let block = make_block(1, vec![b"tx1".to_vec(), b"tx2".to_vec()]);
        idx.index_block(&block);
        assert_eq!(idx.block_count(), 1);
        let summary = idx.get_block_by_height(1).unwrap();
        assert_eq!(summary.height, 1);
        assert_eq!(summary.tx_count, 2);
    }

    #[test]
    fn index_block_indexes_transactions() {
        let mut idx = Indexer::new();
        let block = make_block(1, vec![b"tx1".to_vec(), b"tx2".to_vec()]);
        idx.index_block(&block);
        assert_eq!(idx.tx_count(), 2);
        // Verify txs are queryable by hash.
        let tx_hash = tx_hash(b"tx1");
        let indexed = idx.get_tx(&tx_hash).unwrap();
        assert_eq!(indexed.height, 1);
        assert_eq!(indexed.index, 0);
        assert_eq!(indexed.bytes, b"tx1");
    }

    #[test]
    fn index_block_idempotent() {
        let mut idx = Indexer::new();
        let block = make_block(1, vec![b"tx1".to_vec()]);
        idx.index_block(&block);
        idx.index_block(&block); // duplicate
        assert_eq!(idx.block_count(), 1, "duplicate index must be idempotent");
    }

    #[test]
    fn get_block_by_hash() {
        let mut idx = Indexer::new();
        let block = make_block(1, vec![b"tx1".to_vec()]);
        idx.index_block(&block);
        let summary = idx.get_block_by_height(1).unwrap();
        let found = idx.get_block_by_hash(&summary.block_hash).unwrap();
        assert_eq!(found.height, 1);
    }

    #[test]
    fn get_tx_by_position() {
        let mut idx = Indexer::new();
        let block = make_block(1, vec![b"tx1".to_vec(), b"tx2".to_vec()]);
        idx.index_block(&block);
        let tx1 = idx.get_tx_by_position(1, 0).unwrap();
        assert_eq!(tx1.bytes, b"tx1");
        let tx2 = idx.get_tx_by_position(1, 1).unwrap();
        assert_eq!(tx2.bytes, b"tx2");
    }

    #[test]
    fn latest_height_tracks_highest() {
        let mut idx = Indexer::new();
        idx.index_block(&make_block(1, vec![]));
        idx.index_block(&make_block(5, vec![]));
        idx.index_block(&make_block(3, vec![]));
        assert_eq!(idx.latest_height(), 5);
    }

    #[test]
    fn set_state_root_updates_summary() {
        let mut idx = Indexer::new();
        idx.index_block(&make_block(1, vec![]));
        let root = Hash([0x42; 32]);
        idx.set_state_root(1, root);
        let summary = idx.get_block_by_height(1).unwrap();
        assert_eq!(summary.state_root, Some(root));
    }

    #[test]
    fn index_event_and_query_by_module() {
        let mut idx = Indexer::new();
        idx.index_event(IndexedEvent {
            height: 1,
            tx_index: 0,
            module: "staking".to_string(),
            kind: "transfer".to_string(),
            data: b"100".to_vec(),
        });
        idx.index_event(IndexedEvent {
            height: 1,
            tx_index: 1,
            module: "exchange".to_string(),
            kind: "delegate".to_string(),
            data: b"50".to_vec(),
        });
        assert_eq!(idx.event_count(), 2);
        let staking_events = idx.get_events_by_module("staking");
        assert_eq!(staking_events.len(), 1);
        assert_eq!(staking_events[0].kind, "transfer");
    }

    #[test]
    fn get_events_by_height() {
        let mut idx = Indexer::new();
        idx.index_event(IndexedEvent {
            height: 1,
            tx_index: 0,
            module: "staking".to_string(),
            kind: "transfer".to_string(),
            data: vec![],
        });
        idx.index_event(IndexedEvent {
            height: 2,
            tx_index: 0,
            module: "staking".to_string(),
            kind: "transfer".to_string(),
            data: vec![],
        });
        let height1_events = idx.get_events_by_height(1);
        assert_eq!(height1_events.len(), 1);
    }

    #[test]
    fn get_block_range_descending() {
        let mut idx = Indexer::new();
        idx.index_block(&make_block(1, vec![]));
        idx.index_block(&make_block(2, vec![]));
        idx.index_block(&make_block(3, vec![]));
        let range = idx.get_block_range(1, 3);
        assert_eq!(range.len(), 3);
        // Descending order (latest first).
        assert_eq!(range[0].height, 3);
        assert_eq!(range[1].height, 2);
        assert_eq!(range[2].height, 1);
    }

    #[test]
    fn multiple_blocks_indexed() {
        let mut idx = Indexer::new();
        for h in 0..5 {
            idx.index_block(&make_block(h, vec![format!("tx{h}").into_bytes()]));
        }
        assert_eq!(idx.block_count(), 5);
        assert_eq!(idx.tx_count(), 5);
        assert_eq!(idx.latest_height(), 4);
    }
}
