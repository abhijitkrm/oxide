//! Executed-block history for Ethereum JSON-RPC queries.
//!
//! The EVM module records every executed transaction — its decoded
//! metadata and its receipt — into a bounded, per-height history. This
//! is what `eth_getTransactionByHash`, `eth_getTransactionReceipt`,
//! `eth_getBlockByNumber`, and `eth_getLogs` read from.
//!
//! # Why the history lives in the module
//!
//! Block execution is deferred (`Executor::finalize_block` stores the
//! block; `end_block` runs inside `execute_block`), so the only place
//! that sees the transaction *and* its receipt together is the module
//! itself. Consensus-side metadata (canonical height/hash, proposer)
//! lives in the `commit_listener` path; the RPC layer joins on height.
//!
//! # Ethereum block hashes
//!
//! `seal_block` computes a real Ethereum `blockHash` —
//! `keccak256(rlp(header))` over a Prague header — plus
//! `transactionsRoot` and `receiptsRoot` via `alloy_trie`. This makes
//! `eth_getBlockByNumber.hash`, `log.blockHash`, and `blockHash` log
//! filters hash-stable and independently verifiable by tooling
//! (Foundry, ethers, web3).
//!
//! # Retention
//!
//! `History` retains the newest `capacity` sealed blocks (default
//! [`DEFAULT_HISTORY_BLOCKS`], matching cosmos-evm's
//! `history_serve_window`). Older blocks are evicted from both the
//! block map and the transaction index. This is a serving window for
//! RPC, not the canonical record — durable history belongs to the
//! storage backend / journal.

use std::collections::{BTreeMap, HashMap};

use alloy_primitives::{Address, B256, U256};

use crate::receipts::{self, Receipt};
use crate::tx;

/// Default number of sealed blocks retained for RPC queries.
///
/// Matches cosmos-evm's `history_serve_window` default (8192). At
/// ~1s block times this serves ~2.3 hours of history; at Oxide's
/// devnet rate (~50 blk/s) it is ~2.7 minutes. Raising the value
/// costs O(block size) memory per retained block — the dominant
/// terms are tx input bytes and receipt logs.
pub const DEFAULT_HISTORY_BLOCKS: usize = 8192;

/// `keccak256(rlp([]))` — the header `ommersHash` for a chain that
/// never produces uncles (all post-merge chains; EIP-3675).
const EMPTY_OMMERS_HASH: B256 = B256::new([
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
]);

/// `keccak256(rlp([]))` — the empty-MPT root used for `withdrawalsRoot`
/// when the block carries no withdrawals (EIP-4895 field present from
/// Shanghai; our engine has no withdrawal concept).
const EMPTY_TRIE_ROOT: B256 = B256::new([
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xc5, 0x5a, 0x6f, 0xf8, 0x34, 0x5e, 0x69, 0x2c, 0x0f, 0x86, 0xe5,
    0xb4, 0x8e, 0x01, 0xb9, 0x96, 0xca, 0xdc, 0x00, 0x16, 0x22, 0xfb, 0x5e, 0x36, 0x3b, 0x42, 0x1,
]);

/// EIP-7685 `requestsHash` for a block with zero requests.
///
/// `CalcRequestsHash` (geth `core/types/block.go`) folds
/// `sha256(item)` per request into a running sha256; an empty request
/// list therefore hashes as `sha256("")` — the well-known empty-sha256
/// constant `0xe3b0c4…b855`, which is what every post-Prague mainnet
/// block without requests carries.
const EMPTY_REQUESTS_HASH: B256 = B256::new([
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
]);

/// Gas-price-oracle sampling window — geth's `GpoConfig.CheckBlocks`
/// default (the newest 20 sealed blocks).
const GPO_CHECK_BLOCKS: usize = 20;

/// Transactions sampled per block — geth's `GpoConfig.SampleNumber`
/// default (3). Sampling the *cheapest* included txs keeps the
/// estimate at the inclusion floor rather than the market top.
const GPO_SAMPLE_PER_BLOCK: usize = 3;

/// Sample percentile — geth's `GpoConfig.Percentile` default (60).
const GPO_PERCENTILE: usize = 60;

/// Tip returned when no samples exist — geth's `GpoConfig.Default`
/// (1 gwei).
const GPO_DEFAULT_TIP: u128 = 1_000_000_000;

/// Hard ceiling on the suggested tip — geth's `GpoConfig.MaxPrice`
/// (500 gwei).
const GPO_MAX_TIP: u128 = 500_000_000_000;

/// The metadata of a single executed transaction, retained for RPC
/// `eth_getTransactionByHash` / `eth_getBlockByNumber` responses.
///
/// All fields come from the decoded [`tx::SignedTx`]; the canonical
/// hash is `keccak256(raw_rlp)` computed at decode time. The raw RLP
/// itself is *not* retained past `seal_block` — it is needed only to
/// compute `transactionsRoot`, and `input`/`v`/`r`/`s` cover every
/// response field. Keeping ~110–200 B per tx in the window would cost
/// ~50 MB per 500k-tx block for zero RPC benefit.
#[derive(Debug, Clone)]
pub struct StoredTx {
    /// `keccak256(raw_rlp)` — the canonical Ethereum transaction hash.
    pub hash: B256,
    /// Position of this transaction within the block (0-based over the
    /// block's EVM transactions — non-EVM module txs are not indexed).
    /// Stamped by [`History::record`] — callers pass 0.
    pub tx_index: u32,
    /// Recovered sender (secp256k1 / EIP-155).
    pub from: Address,
    /// `Some` for a call, `None` for a contract creation.
    pub to: Option<Address>,
    /// Sender nonce at execution time.
    pub nonce: u64,
    /// The transaction's gas limit.
    pub gas_limit: u64,
    /// Legacy/EIP-2930 gas price; for EIP-1559 this is the
    /// `max_fee_per_gas` cap.
    pub gas_price: u128,
    /// EIP-1559 `max_priority_fee_per_gas` (0 for legacy/2930).
    pub max_priority_fee_per_gas: u128,
    /// Wei value transferred.
    pub value: U256,
    /// Calldata / initcode bytes.
    pub input: Vec<u8>,
    /// EIP-2718 transaction type (0=legacy, 1=EIP-2930, 2=EIP-1559,
    /// 4=EIP-7702).
    pub tx_type: u8,
    /// The EIP-7702 authorization list — empty for every other type.
    /// Retained verbatim so `eth_getTransaction*` can return the
    /// `authorizationList` field geth/reth emit for type-4 txs.
    pub authorization_list: Vec<tx::TxAuthorization>,
    /// `v`, `r`, `s` signature components — needed verbatim for the
    /// `eth_getTransactionByHash` response. For typed txs `v` is the
    /// `y_parity` (0/1); for legacy it is the full EIP-155 `v`
    /// (`35 + 2*chain_id + recid`).
    pub v: U256,
    /// Signature `r` (32 bytes).
    pub r: U256,
    /// Signature `s` (32 bytes).
    pub s: U256,
}

/// A sealed block's EVM-side record: every transaction executed in
/// block order plus its receipt, the block bloom, the trie roots, and
/// the computed Ethereum header hash.
#[derive(Debug, Clone)]
pub struct ExecutedBlock {
    /// `keccak256(rlp(header))` — the Ethereum `blockHash`.
    pub hash: B256,
    /// The parent's Ethereum `blockHash`, or `B256::ZERO` for the
    /// first block this node sealed (genesis-adjacent or post-restart).
    pub parent_hash: B256,
    /// Block height (== Ethereum block number).
    pub number: u64,
    /// Block timestamp the module executed under — the consensus-
    /// committed header timestamp in whole seconds on real blocks
    /// (`begin_block_ctx`), or the height-derived deterministic
    /// stand-in for context-less blocks (`begin_block`).
    pub timestamp: u64,
    /// Total gas consumed by all EVM txs in the block.
    pub gas_used: u64,
    /// The block gas limit the module enforced.
    pub gas_limit: u64,
    /// EIP-1559 base fee in effect for this block (wei per gas).
    pub base_fee: u64,
    /// Fee recipient address used for this block.
    pub coinbase: Address,
    /// Logs bloom over all receipts in the block (EIP-234), stored
    /// as 256 bytes (2048 bits) like `receipts::Bloom`.
    pub bloom: [u8; 256],
    /// Transactions trie root (Ethereum `transactionsRoot`).
    pub tx_root: B256,
    /// Receipts trie root for the block (Ethereum `receiptsRoot`).
    pub receipts_root: B256,
    /// Post-execution EVM state root (Ethereum `stateRoot` — the
    /// module's MPT root, which for Oxide is the EVM subtree root).
    pub state_root: B256,
    /// Executed EVM transactions in block order.
    pub txs: Vec<StoredTx>,
    /// One receipt per entry in `txs`, same order. `logs` carry
    /// per-tx data; block/tx indices are joined at query time.
    pub receipts: Vec<Receipt>,
    /// One call-tree trace per entry in `txs`, same order — recorded
    /// at execution time by the `CallRecorder` inspector (see
    /// `trace.rs`). `None` only when a tx ran without producing a
    /// frame, which cannot happen for an executed tx; `None` entries
    /// exist solely so a buggy recorder can't misalign the index.
    /// `debug_traceTransaction`/`debug_traceBlock*` read these —
    /// tracing is a history lookup, not a re-execution, so it needs
    /// no archive state.
    pub traces: Vec<Option<crate::trace::CallFrame>>,
}

/// Per-block accumulator used between `begin_block` and `end_block`.
/// `record` appends; `seal_block` folds it into an [`ExecutedBlock`].
#[derive(Debug, Default)]
struct Pending {
    /// Transactions recorded so far this block (block order).
    txs: Vec<StoredTx>,
    /// Receipts in the same order as `txs`.
    receipts: Vec<Receipt>,
    /// Raw signed-RLP bytes in the same order — retained only for the
    /// block's duration to compute `transactionsRoot` at seal.
    raws: Vec<Vec<u8>>,
    /// Call-tree traces in the same order — recorded by the
    /// `CallRecorder` inspector during execution and moved into the
    /// sealed block at `seal_block`.
    traces: Vec<Option<crate::trace::CallFrame>>,
}

/// One topic-position matcher in an `eth_getLogs` filter.
///
/// Ethereum's positional semantics: `topics[i]` may be `null`
/// (wildcard), a single hash, or an array of hashes (OR within the
/// position, AND across positions).
#[derive(Debug, Clone)]
pub enum TopicMatcher {
    /// `null` — any topic value (including none) matches.
    Any,
    /// Exact single topic.
    One(B256),
    /// OR-set: the log's topic at this position must equal one entry.
    AnyOf(Vec<B256>),
}

/// An `eth_getLogs` filter: block range (or single `blockHash`),
/// address OR-set, and positional topic matchers.
#[derive(Debug, Clone, Default)]
pub struct LogFilter {
    /// Inclusive lower bound; ignored when `block_hash` is set.
    pub from_block: u64,
    /// Inclusive upper bound; ignored when `block_hash` is set.
    pub to_block: u64,
    /// Restrict to a single block by its Ethereum `blockHash`.
    /// Mutually exclusive with the range (per the JSON-RPC spec).
    pub block_hash: Option<B256>,
    /// OR-set of emitting contract addresses. Empty = any address.
    pub addresses: Vec<Address>,
    /// Positional matchers, at most 4 (EVM logs carry ≤4 topics).
    /// Missing positions (shorter vec) are wildcards.
    pub topics: Vec<TopicMatcher>,
}

/// A single log entry matching a [`LogFilter`], with the positional
/// metadata `eth_getLogs` requires.
#[derive(Debug, Clone)]
pub struct LogMatch {
    /// The block that emitted the log.
    pub block_number: u64,
    /// The block's Ethereum `blockHash`.
    pub block_hash: B256,
    /// The emitting transaction's hash.
    pub tx_hash: B256,
    /// Transaction position within the block.
    pub tx_index: u32,
    /// Log position within the block (across all txs — geth counts
    /// block-wide, not per-tx).
    pub log_index: u32,
    /// Emitting contract.
    pub address: Address,
    /// Log topics (≤4).
    pub topics: Vec<B256>,
    /// Log data payload.
    pub data: Vec<u8>,
}

/// Bounded, height-keyed store of executed EVM blocks.
///
/// All methods take `&mut self` for writes; the owning `EvmModule`
/// holds it behind a `Mutex` so the block-execution thread (writer)
/// and RPC handlers (readers) can share it via `Arc`.
#[derive(Debug)]
pub struct History {
    /// Sealed blocks keyed by height. `BTreeMap` keeps heights ordered
    /// for range scans (`eth_getLogs`, `eth_feeHistory`) and O(log n)
    /// eviction of the oldest entry.
    blocks: BTreeMap<u64, ExecutedBlock>,
    /// `block_hash -> height` for `eth_getBlockByHash` and `blockHash`
    /// log filters. Evicted alongside the block.
    hash_index: HashMap<B256, u64>,
    /// `tx_hash -> (block_height, tx_index)` lookup for
    /// `eth_getTransactionByHash`/`eth_getTransactionReceipt`.
    tx_index: HashMap<B256, (u64, u32)>,
    /// Accumulator for the currently-executing block.
    pending: Pending,
    /// Maximum number of sealed blocks retained.
    capacity: usize,
}

impl History {
    /// Create an empty history retaining `capacity` sealed blocks.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            blocks: BTreeMap::new(),
            hash_index: HashMap::new(),
            tx_index: HashMap::new(),
            pending: Pending::default(),
            capacity: capacity.max(1),
        }
    }

    /// Record one executed transaction + its receipt into the pending
    /// block accumulator. Called once per EVM tx by the module's
    /// execution paths (`handle`, `execute_decoded`,
    /// `execute_parallel_decoded`).
    ///
    /// The `tx_index` is assigned here from the pending position —
    /// callers pass 0 in `stored_tx` and this method stamps the real
    /// block position, guaranteeing index == block order even when
    /// parallel paths complete out of order (they re-sort before
    /// recording).
    ///
    /// `raw` is the signed-RLP bytes, kept only until `seal_block`
    /// computes `transactionsRoot` and then dropped. `trace` is the
    /// `CallRecorder` root frame drained from the EVM inspector —
    /// retained for `debug_trace*`, dropped only by window eviction.
    pub fn record(
        &mut self,
        mut tx: StoredTx,
        receipt: Receipt,
        raw: &[u8],
        trace: Option<crate::trace::CallFrame>,
    ) {
        // A block cannot hold more than u32::MAX txs by gas-limit
        // arithmetic alone (10 GG / 21k ≈ 476k) — saturate instead of
        // truncate on the unreachable path.
        tx.tx_index = u32::try_from(self.pending.txs.len()).unwrap_or(u32::MAX);
        self.pending.txs.push(tx);
        self.pending.receipts.push(receipt);
        self.pending.raws.push(raw.to_vec());
        self.pending.traces.push(trace);
    }

    /// Seal the pending accumulator as block `number` and insert it
    /// into the retained window. Called from `end_block`.
    ///
    /// Every block seals an entry — including empty blocks — so RPC
    /// consumers can distinguish "block with no EVM txs" from "block
    /// not yet executed".
    ///
    /// `state_root` is the module's post-execution MPT root, already
    /// computed by `end_block`'s flush/state-root path.
    ///
    /// Returns the heights evicted by the retention window — the
    /// caller (`end_block`) issues matching backend `Delete`s so the
    /// persisted records track the in-memory window exactly.
    pub fn seal_block(
        &mut self,
        number: u64,
        timestamp: u64,
        gas_limit: u64,
        base_fee: u64,
        coinbase: Address,
        state_root: B256,
    ) -> Vec<u64> {
        let pending = std::mem::take(&mut self.pending);
        let cumulative = Receipt::cumulative_gas(&pending.receipts);
        let gas_used = cumulative.last().copied().unwrap_or(0);
        // The block bloom is the bitwise OR of all receipt blooms
        // (each receipt already contains the bloom over its own logs).
        let mut bloom = [0u8; 256];
        for receipt in &pending.receipts {
            for (b, r) in bloom.iter_mut().zip(receipt.bloom.iter()) {
                *b |= r;
            }
        }
        let receipts_root = receipts::receipts_root(&pending.receipts);
        // transactionsRoot: ordered trie over the *raw signed RLP*
        // (Ethereum keys by index, values are the canonical encodings).
        let tx_root = if pending.raws.is_empty() {
            EMPTY_TRIE_ROOT
        } else {
            alloy_trie::root::ordered_trie_root(&pending.raws)
        };
        // Parent linkage: the previously sealed block at `number - 1`.
        // `B256::ZERO` for the first sealed block (genesis-adjacent or
        // first block after a restart with a fresh history window).
        let parent_hash = self.blocks.get(&number.saturating_sub(1)).map_or(B256::ZERO, |b| b.hash);
        for (i, tx) in pending.txs.iter().enumerate() {
            self.tx_index.insert(tx.hash, (number, u32::try_from(i).unwrap_or(u32::MAX)));
        }
        let mut block = ExecutedBlock {
            hash: B256::ZERO,
            parent_hash,
            number,
            timestamp,
            gas_used,
            gas_limit,
            base_fee,
            coinbase,
            bloom,
            tx_root,
            receipts_root,
            state_root,
            txs: pending.txs,
            receipts: pending.receipts,
            traces: pending.traces,
        };
        block.hash = block_hash(&block);
        self.hash_index.insert(block.hash, number);
        self.blocks.insert(number, block);
        self.evict()
    }

    /// Insert a previously-persisted block record on startup —
    /// [`seal_block`] without recomputing the hash (the record's
    /// hash is authoritative: it was derived from the same fields
    /// by the writer). Rebuilds the tx/hash indexes and applies the
    /// retention window.
    ///
    /// Returns evicted heights like `seal_block`; on restore the
    /// caller deletes the corresponding backend records so stale
    /// on-disk entries don't outlive the window.
    pub fn restore_block(&mut self, block: ExecutedBlock) -> Vec<u64> {
        for (i, tx) in block.txs.iter().enumerate() {
            self.tx_index.insert(tx.hash, (block.number, u32::try_from(i).unwrap_or(u32::MAX)));
        }
        self.hash_index.insert(block.hash, block.number);
        self.blocks.insert(block.number, block);
        self.evict()
    }

    /// Drop the oldest sealed blocks beyond `capacity`, removing their
    /// transaction and block-hash index entries. Returns the evicted
    /// heights (ascending).
    fn evict(&mut self) -> Vec<u64> {
        let mut evicted = Vec::new();
        while self.blocks.len() > self.capacity {
            // `BTreeMap` iterates ascending — `first_key_value` is the
            // oldest (lowest) height.
            if let Some((height, block)) = self.blocks.first_key_value() {
                let height = *height;
                let hash = block.hash;
                for tx in &block.txs {
                    self.tx_index.remove(&tx.hash);
                }
                self.blocks.remove(&height);
                self.hash_index.remove(&hash);
                evicted.push(height);
            } else {
                break;
            }
        }
        evicted
    }

    /// The highest sealed block height, if any.
    #[must_use]
    pub fn latest(&self) -> Option<u64> {
        self.blocks.keys().next_back().copied()
    }

    /// The lowest sealed block height — the retention floor the
    /// versioned-state window prunes to.
    #[must_use]
    pub fn blocks_floor(&self) -> Option<u64> {
        self.blocks.keys().next().copied()
    }

    /// Look up a sealed block by height.
    #[must_use]
    pub fn block(&self, number: u64) -> Option<&ExecutedBlock> {
        self.blocks.get(&number)
    }

    /// Look up a sealed block by its Ethereum `blockHash`.
    #[must_use]
    pub fn block_by_hash(&self, hash: &B256) -> Option<&ExecutedBlock> {
        self.hash_index.get(hash).and_then(|h| self.blocks.get(h))
    }

    /// Suggest a priority-fee cap for `eth_maxPriorityFeePerGas` /
    /// `eth_gasPrice` — geth's `GasPriceOracle` sampling scheme.
    ///
    /// From each of the last [`GPO_CHECK_BLOCKS`] sealed blocks, take
    /// the [`GPO_SAMPLE_PER_BLOCK`] *lowest* effective tips (a tx's
    /// `effective_gas_price − base_fee`) — geth samples the cheapest
    /// included txs so the estimate tracks the inclusion floor, not
    /// the top of the market. The answer is the
    /// [`GPO_PERCENTILE`]th percentile of the pooled samples,
    /// capped at [`GPO_MAX_TIP`]; with no samples (young chain,
    /// all-empty blocks) it returns [`GPO_DEFAULT_TIP`].
    #[must_use]
    pub fn suggest_gas_tip(&self) -> u128 {
        let mut samples: Vec<u128> = Vec::new();
        for block in self.blocks.values().rev().take(GPO_CHECK_BLOCKS) {
            let mut tips: Vec<u128> = block
                .txs
                .iter()
                .map(|stx| {
                    effective_gas_price(stx, block.base_fee)
                        .saturating_sub(u128::from(block.base_fee))
                })
                .collect();
            tips.sort_unstable();
            samples.extend(tips.into_iter().take(GPO_SAMPLE_PER_BLOCK));
        }
        if samples.is_empty() {
            return GPO_DEFAULT_TIP;
        }
        samples.sort_unstable();
        // geth's index: `(len-1) * percentile / 100` — the p60 of
        // 60 samples is index 35, etc.
        samples[(samples.len() - 1) * GPO_PERCENTILE / 100].min(GPO_MAX_TIP)
    }

    /// Look up `(block, tx_index)` for a transaction hash.
    #[must_use]
    pub fn tx_location(&self, hash: &B256) -> Option<(u64, u32)> {
        self.tx_index.get(hash).copied()
    }

    /// Collect log entries matching `filter` across the retained
    /// window.
    ///
    /// Block-level blooms short-circuit: a block whose bloom lacks
    /// every address/topic term is skipped without touching its
    /// receipts. `log_index` counts block-wide across all txs (geth
    /// semantics).
    ///
    /// Bounds (range length, result count) are enforced by the RPC
    /// layer — this method scans whatever window the filter asks for
    /// within the retained blocks.
    #[must_use]
    pub fn logs(&self, filter: &LogFilter) -> Vec<LogMatch> {
        let mut out = Vec::new();
        let iter: Box<dyn Iterator<Item = &ExecutedBlock> + '_> =
            if let Some(hash) = filter.block_hash {
                Box::new(self.block_by_hash(&hash).into_iter())
            } else {
                Box::new(self.blocks.range(filter.from_block..=filter.to_block).map(|(_, b)| b))
            };
        for block in iter {
            if !block_may_match(&block.bloom, filter) {
                continue;
            }
            let mut log_index = 0u32;
            for (tx, receipt) in block.txs.iter().zip(block.receipts.iter()) {
                for log in &receipt.logs {
                    let idx = log_index;
                    log_index += 1;
                    if !filter.addresses.is_empty() && !filter.addresses.contains(&log.address) {
                        continue;
                    }
                    if !topics_match(filter, log.topics()) {
                        continue;
                    }
                    out.push(LogMatch {
                        block_number: block.number,
                        block_hash: block.hash,
                        tx_hash: tx.hash,
                        tx_index: tx.tx_index,
                        log_index: idx,
                        address: log.address,
                        topics: log.topics().to_vec(),
                        data: log.data.data.to_vec(),
                    });
                }
            }
        }
        out
    }

    /// Number of sealed blocks retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether no blocks are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Block-level bloom short-circuit: `false` means no log in this
/// block can match `filter` (blooms have no false negatives).
fn block_may_match(bloom: &[u8; 256], filter: &LogFilter) -> bool {
    // Address constraint: if set is non-empty, at least one member
    // must be in the bloom.
    if !filter.addresses.is_empty()
        && !filter.addresses.iter().any(|a| bloom_check(bloom, a.as_slice()))
    {
        return false;
    }
    // Per-position topic constraint: `One`/`AnyOf` positions must each
    // have a member in the bloom; `Any` is unconstrained.
    for matcher in &filter.topics {
        let hits = match matcher {
            TopicMatcher::Any => true,
            TopicMatcher::One(t) => bloom_check(bloom, t.as_slice()),
            TopicMatcher::AnyOf(set) => set.iter().any(|t| bloom_check(bloom, t.as_slice())),
        };
        if !hits {
            return false;
        }
    }
    true
}

impl LogFilter {
    /// Check whether a single [`LogMatch`] satisfies this filter's
    /// address OR-set and positional topic matchers.
    ///
    /// Block-range fields (`from_block`/`to_block`/`block_hash`) are
    /// ignored: callers use this at subscription-publish time, where
    /// the scan is already restricted to the newly finalized block.
    /// A `block_hash`-only filter never matches a stream push — that
    /// shape is only meaningful for `eth_getLogs` point queries.
    #[must_use]
    pub fn matches(&self, log: &LogMatch) -> bool {
        (self.addresses.is_empty() || self.addresses.contains(&log.address))
            && topics_match(self, &log.topics)
    }
}

/// Per-log topic matching: position i of the filter constrains the
/// log's topic i. A filter position beyond the log's topic count can
/// only match when it is `Any`.
fn topics_match(filter: &LogFilter, topics: &[B256]) -> bool {
    for (i, matcher) in filter.topics.iter().enumerate() {
        match matcher {
            TopicMatcher::Any => {}
            TopicMatcher::One(t) => {
                if topics.get(i) != Some(t) {
                    return false;
                }
            }
            TopicMatcher::AnyOf(set) => match topics.get(i) {
                Some(actual) if set.contains(actual) => {}
                _ => return false,
            },
        }
    }
    true
}

/// Single-term bloom check — the same 3×11-bit indexing
/// `receipts::bloom_from_logs` writes.
fn bloom_check(bloom: &[u8; 256], data: &[u8]) -> bool {
    let hash = alloy_primitives::keccak256(data);
    let h = hash.as_slice();
    for i in 0..3 {
        let bit = (((usize::from(h[i * 2]) & 0x07) << 8) | usize::from(h[i * 2 + 1])) & 0x7FF;
        if bloom[bit / 8] & (1 << (bit % 8)) == 0 {
            return false;
        }
    }
    true
}

/// Compute the Ethereum `blockHash` for a sealed block:
/// `keccak256(rlp(header))` over the full Prague header field list.
///
/// Post-merge fields that Oxide has no notion of carry their empty
/// constants: `ommersHash`, `withdrawalsRoot`, `blobGasUsed`,
/// `excessBlobGas`, `parentBeaconBlockRoot`, `requestsHash`,
/// `difficulty`, `mixHash`, `nonce`, `extraData`.
///
/// The field list (21 items, Prague / EIP-7685):
/// `parentHash, ommersHash, beneficiary, stateRoot, transactionsRoot,
/// receiptsRoot, logsBloom, difficulty, number, gasLimit, gasUsed,
/// timestamp, extraData, mixHash, nonce, baseFeePerGas,
/// withdrawalsRoot, blobGasUsed, excessBlobGas, parentBeaconBlockRoot,
/// requestsHash`.
fn block_hash(block: &ExecutedBlock) -> B256 {
    use alloy_rlp::Encodable;

    let mut payload = Vec::with_capacity(640);
    block.parent_hash.encode(&mut payload);
    EMPTY_OMMERS_HASH.encode(&mut payload);
    block.coinbase.encode(&mut payload);
    block.state_root.encode(&mut payload);
    block.tx_root.encode(&mut payload);
    block.receipts_root.encode(&mut payload);
    // logsBloom: 256-byte string.
    alloy_rlp::Header { list: false, payload_length: 256 }.encode(&mut payload);
    payload.extend_from_slice(&block.bloom);
    // difficulty: 0 post-merge (EIP-3675).
    0u64.encode(&mut payload);
    block.number.encode(&mut payload);
    block.gas_limit.encode(&mut payload);
    block.gas_used.encode(&mut payload);
    block.timestamp.encode(&mut payload);
    // extraData: empty.
    alloy_rlp::Header { list: false, payload_length: 0 }.encode(&mut payload);
    // mixHash: zero post-merge.
    B256::ZERO.encode(&mut payload);
    // nonce: B64 — post-merge blocks carry 0x0000000000000000.
    alloy_rlp::Header { list: false, payload_length: 8 }.encode(&mut payload);
    payload.extend_from_slice(&[0u8; 8]);
    block.base_fee.encode(&mut payload);
    EMPTY_TRIE_ROOT.encode(&mut payload); // withdrawalsRoot
    0u64.encode(&mut payload); // blobGasUsed
    0u64.encode(&mut payload); // excessBlobGas
    B256::ZERO.encode(&mut payload); // parentBeaconBlockRoot
    EMPTY_REQUESTS_HASH.encode(&mut payload);

    let mut out = Vec::with_capacity(payload.len() + 9);
    alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    alloy_primitives::keccak256(&out)
}

/// Build the [`StoredTx`] metadata for a decoded signed transaction.
///
/// `hash` is `keccak256(raw_rlp)` computed by the caller at decode
/// time (the raw bytes themselves are passed separately to
/// [`History::record`] and not retained past the seal).
#[must_use]
pub fn stored_tx(signed: &tx::SignedTx, from: Address, hash: B256, tx_index: u32) -> StoredTx {
    let (to, sig) = match signed {
        tx::SignedTx::Legacy(t, s) => (t.fields.to, s),
        tx::SignedTx::Eip2930(t, s) => (t.fields.to, s),
        tx::SignedTx::Eip1559(t, s) => (t.fields.to, s),
        tx::SignedTx::Eip7702(t, s) => (t.fields.to, s),
    };
    let to = match to {
        tx::TxKind::Call(addr) => Some(addr),
        tx::TxKind::Create => None,
    };
    // Reconstruct the JSON `v` value: typed txs expose y_parity
    // directly; legacy txs use the EIP-155 embedding
    // (`35 + 2*chain_id + recid`, or `27 + recid` for unprotected).
    let recid = u64::from(sig.recid.as_u8());
    let v = match signed {
        tx::SignedTx::Legacy(t, _) => {
            if t.fields.chain_id == 0 {
                U256::from(27 + recid)
            } else {
                U256::from(35 + 2 * t.fields.chain_id + recid)
            }
        }
        _ => U256::from(recid),
    };
    StoredTx {
        hash,
        tx_index,
        from,
        to,
        nonce: signed.nonce(),
        gas_limit: signed.gas_limit(),
        gas_price: u128::try_from(signed.max_fee_per_gas()).unwrap_or(u128::MAX),
        max_priority_fee_per_gas: u128::try_from(signed.max_priority_fee_per_gas())
            .unwrap_or(u128::MAX),
        value: signed.value(),
        input: signed.data().to_vec(),
        tx_type: signed.tx_type(),
        authorization_list: signed.authorization_list().to_vec(),
        v,
        r: sig.r,
        s: sig.s,
    }
}

/// The effective gas price paid for a transaction under EIP-1559.
///
/// - Legacy / EIP-2930: the flat `gas_price`.
/// - EIP-1559: `min(max_fee_per_gas, base_fee + max_priority_fee)`.
///
/// Matches revm's internal accounting (which burns `base_fee` and
/// tips `effective - base_fee` to the coinbase).
#[must_use]
pub fn effective_gas_price(stx: &StoredTx, base_fee: u64) -> u128 {
    if stx.tx_type == 2 {
        stx.gas_price.min(stx.max_priority_fee_per_gas.saturating_add(u128::from(base_fee)))
    } else {
        stx.gas_price
    }
}

use super::{
    AccountProof, Arc, CacheDB, CallError, CallOutcome, CallRequest, DatabaseRef, EmptyDB,
    EvmModule, ExecError, Mutex, StateError, StorageProof, alloy_primitives_address, history,
    overrides, trie, versioned,
};

// ── Height-indexed state queries ────────────────────────────
// `impl EvmModule` lives here because these methods serve the
// same RPC surface this module exists for: historical reads.
impl EvmModule {
    // ── Historical state reads (undo-log window) ────────────────

    /// Validate `h` against the servable window.
    ///
    /// - `h > latest` → [`StateError::TooNew`] ("header not found").
    /// - `h == latest` → always servable (live `CacheDB`).
    /// - `h < latest` → servable iff the undo log covers `(h, latest]`,
    ///   i.e. `h >= floor - 1` where `floor` is the oldest retained
    ///   height; otherwise [`StateError::Pruned`] ("missing trie
    ///   node", geth's non-archive behavior).
    pub(crate) fn check_state_height(&self, h: u64) -> Result<u64, StateError> {
        let latest =
            framework::lock_state(&self.history).latest().unwrap_or_else(|| self.current_height());
        if h > latest {
            return Err(StateError::TooNew { requested: h, latest });
        }
        if h == latest {
            return Ok(h);
        }
        let versioned = framework::lock_state(&self.versioned);
        // `floor - 1` is the oldest servable height; an empty index
        // means nothing is retained — only `latest` answers.
        let min = versioned.floor().map_or(latest, |f| f.saturating_sub(1));
        if h < min {
            return Err(StateError::Pruned { requested: h, floor: min });
        }
        Ok(h)
    }

    /// Map a requested height onto the `simulate` `at_height` arg:
    /// `None` for `latest` (the live-db fast path), `Some(h)` for a
    /// historical overlay.
    pub(crate) fn resolve_at(&self, h: u64) -> Result<Option<u64>, StateError> {
        let h = self.check_state_height(h)?;
        let latest =
            framework::lock_state(&self.history).latest().unwrap_or_else(|| self.current_height());
        Ok(if h == latest { None } else { Some(h) })
    }

    /// [`StateError`] → [`CallError`] for the simulation entry
    /// points (which surface height errors through `Rejected`).
    pub(crate) fn state_as_call_err(e: StateError) -> CallError {
        CallError::Rejected(ExecError::ModuleRejected(format!(
            "state for block {} unavailable: {e:?}",
            e.requested()
        )))
    }

    /// A [`versioned::StateView`] at `h` over the live db and undo
    /// index. Callers hold both guards for the view's lifetime.
    pub(crate) fn state_view<'a>(
        db: &'a CacheDB<EmptyDB>,
        versioned: &'a versioned::VersionedState,
        history: &'a Mutex<history::History>,
        h: u64,
    ) -> versioned::StateView<'a> {
        versioned::StateView::new(db, versioned, history, h)
    }

    /// `eth_getBalance` at height `h`.
    ///
    /// # Errors
    ///
    /// [`StateError`] when `h` is outside the retained window.
    pub fn balance_at(&self, addr: &primitives::Address, h: u64) -> Result<u128, StateError> {
        self.check_state_height(h)?;
        // Pin a committed-state snapshot under a short db lock,
        // then release it — the undo index is locked next (it only
        // advances, so it covers at least the snapshot's height) and
        // the view reads the snapshot instead of holding the db
        // mutex through the query.
        let snap = {
            let db = framework::lock_state(&self.db);
            Arc::clone(&db)
        };
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&snap, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);
        Ok(view
            .basic_ref(evm_addr)
            .unwrap_or_default()
            .map_or(0, |a| u128::try_from(a.balance).unwrap_or(u128::MAX)))
    }

    /// `eth_getTransactionCount` at height `h`.
    ///
    /// # Errors
    ///
    /// [`StateError`] when `h` is outside the retained window.
    pub fn nonce_at(&self, addr: &primitives::Address, h: u64) -> Result<u64, StateError> {
        self.check_state_height(h)?;
        // Pin a committed-state snapshot under a short db lock,
        // then release it — the undo index is locked next (it only
        // advances, so it covers at least the snapshot's height) and
        // the view reads the snapshot instead of holding the db
        // mutex through the query.
        let snap = {
            let db = framework::lock_state(&self.db);
            Arc::clone(&db)
        };
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&snap, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);
        Ok(view.basic_ref(evm_addr).unwrap_or_default().map_or(0, |a| a.nonce))
    }

    /// `eth_getCode` at height `h`. Old bytecode is always servable —
    /// `cache.contracts` retains every deployed blob keyed by hash.
    ///
    /// # Errors
    ///
    /// [`StateError`] when `h` is outside the retained window.
    pub fn code_at(&self, addr: &primitives::Address, h: u64) -> Result<Vec<u8>, StateError> {
        self.check_state_height(h)?;
        // Pin a committed-state snapshot under a short db lock,
        // then release it — the undo index is locked next (it only
        // advances, so it covers at least the snapshot's height) and
        // the view reads the snapshot instead of holding the db
        // mutex through the query.
        let snap = {
            let db = framework::lock_state(&self.db);
            Arc::clone(&db)
        };
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&snap, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);
        let Some(info) = view.basic_ref(evm_addr).unwrap_or_default() else {
            return Ok(Vec::new());
        };
        if let Some(code) = &info.code {
            return Ok(code.original_bytes().to_vec());
        }
        Ok(view.code_by_hash_ref(info.code_hash).unwrap_or_default().original_bytes().to_vec())
    }

    /// `eth_getStorageAt` at height `h`.
    ///
    /// # Errors
    ///
    /// [`StateError`] when `h` is outside the retained window.
    pub fn storage_at_height(
        &self,
        addr: &primitives::Address,
        slot: &revm::primitives::U256,
        h: u64,
    ) -> Result<revm::primitives::U256, StateError> {
        self.check_state_height(h)?;
        // Pin a committed-state snapshot under a short db lock,
        // then release it — the undo index is locked next (it only
        // advances, so it covers at least the snapshot's height) and
        // the view reads the snapshot instead of holding the db
        // mutex through the query.
        let snap = {
            let db = framework::lock_state(&self.db);
            Arc::clone(&db)
        };
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&snap, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);
        Ok(view.storage_ref(evm_addr, *slot).unwrap_or_default())
    }

    /// `eth_call` at height `h` — the historical form of
    /// [`call_read`](Self::call_read). The simulation runs over a
    /// `CacheDB<StateView>`: identical code path to `latest`, with
    /// reads served by the undo overlay and the block env taken from
    /// `h`'s sealed record.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window or the block record is missing; otherwise the same
    /// [`CallError`] variants as `call_read`.
    pub fn call_read_at(&self, req: &CallRequest, h: u64) -> Result<CallOutcome, CallError> {
        let at = self.resolve_at(h).map_err(Self::state_as_call_err)?;
        self.call_read_impl(req, at, &overrides::StateOverrides::new())
    }

    /// `eth_getProof` (EIP-1186): the account's Merkle-Patricia proof
    /// plus one proof per requested storage key, all at height `h`.
    ///
    /// The state trie is not persisted — the proof is produced by
    /// rebuilding the trie from the state at `h` while a
    /// [`alloy_trie::proof::ProofRetainer`] keeps the nodes on the
    /// target path. This is `O(accounts + touched_since_h)` per call —
    /// expensive, but bounded, and proofs are a cold-path archive
    /// query (bridges/light clients hit `latest` almost always).
    ///
    /// Absent accounts/slots return proofs of non-inclusion (geth
    /// parity), not errors.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window.
    #[allow(clippy::too_many_lines)]
    pub fn account_proof(
        &self,
        addr: &primitives::Address,
        slots: &[revm::primitives::B256],
        h: u64,
    ) -> Result<AccountProof, CallError> {
        let h = self.check_state_height(h).map_err(|e| {
            CallError::Rejected(ExecError::ModuleRejected(format!(
                "state for block {} unavailable: {e:?}",
                e.requested()
            )))
        })?;
        // Pin a committed-state snapshot under a short db lock,
        // then release it — the undo index is locked next (it only
        // advances, so it covers at least the snapshot's height) and
        // the view reads the snapshot instead of holding the db
        // mutex through the query.
        let snap = {
            let db = framework::lock_state(&self.db);
            Arc::clone(&db)
        };
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&snap, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);

        // ── Account-trie proof ──────────────────────────────────
        // Materialize every account at `h`: latest map ∪ undo-known
        // addresses (the union covers accounts deleted since `h`).
        // Each entry contributes `keccak(addr) → rlp(TrieAccount)`.
        let mut leaves: std::collections::BTreeMap<revm::primitives::B256, Vec<u8>> =
            std::collections::BTreeMap::new();
        let addrs: std::collections::BTreeSet<revm::primitives::Address> = snap
            .cache
            .accounts
            .keys()
            .copied()
            .chain(versioned.known_accounts().copied())
            .collect();
        let mut storage_root_cache = framework::lock_state(&self.storage_root_cache);
        for a in addrs {
            let Some(info) = view.info_at(&a) else { continue };
            // Storage root at `h`: the undo map when the account was
            // rewritten above `h`, else the latest map. The cached
            // root is only reused on the untouched path.
            let storage_map = view.storage_map_at(&a).unwrap_or_default();
            let sroot = if storage_map.is_empty() {
                trie::EMPTY_ROOT
            } else if versioned.entry_at(&a, h).is_none() {
                // Untouched since `h` — the cached root is valid.
                if let Some(r) = storage_root_cache.get(&a) {
                    *r
                } else {
                    let r = trie::storage_root(
                        storage_map
                            .iter()
                            .filter(|(_, v)| !v.is_zero())
                            .map(|(k, v)| (revm::primitives::B256::from(*k), *v)),
                    );
                    storage_root_cache.insert(a, r);
                    r
                }
            } else {
                trie::storage_root(
                    storage_map
                        .iter()
                        .filter(|(_, v)| !v.is_zero())
                        .map(|(k, v)| (revm::primitives::B256::from(*k), *v)),
                )
            };
            let trie_account =
                trie::build_trie_account(info.nonce, info.balance, sroot, info.code_hash);
            let mut leaf = Vec::with_capacity(80);
            alloy_rlp::Encodable::encode(&trie_account, &mut leaf);
            leaves.insert(alloy_primitives::keccak256(a), leaf);
        }
        drop(storage_root_cache);

        let target = alloy_trie::Nibbles::unpack(alloy_primitives::keccak256(evm_addr));
        let retainer = alloy_trie::proof::ProofRetainer::new(vec![target]);
        let mut hb = alloy_trie::hash_builder::HashBuilder::default().with_proof_retainer(retainer);
        for (hashed, leaf) in &leaves {
            hb.add_leaf(alloy_trie::Nibbles::unpack(*hashed), leaf);
        }
        hb.root();
        let account_proof: Vec<revm::primitives::Bytes> = hb
            .take_proof_nodes()
            .matching_nodes_sorted(&target)
            .into_iter()
            .map(|(_, node)| node)
            .collect();

        // ── Account fields at `h` ───────────────────────────────
        let info = view.info_at(&evm_addr);
        let storage_map = view.storage_map_at(&evm_addr).unwrap_or_default();
        let storage_hash = if storage_map.is_empty() {
            trie::EMPTY_ROOT
        } else {
            trie::storage_root(
                storage_map
                    .iter()
                    .filter(|(_, v)| !v.is_zero())
                    .map(|(k, v)| (revm::primitives::B256::from(*k), *v)),
            )
        };

        // ── Storage proofs ──────────────────────────────────────
        // One storage trie serves all requested keys — build it
        // once with every requested slot as a retainer target.
        let mut storage_proofs = Vec::with_capacity(slots.len());
        if !slots.is_empty() {
            let targets: Vec<alloy_trie::Nibbles> = slots
                .iter()
                .map(|s| alloy_trie::Nibbles::unpack(alloy_primitives::keccak256(*s)))
                .collect();
            let retainer = alloy_trie::proof::ProofRetainer::new(targets.clone());
            let mut shb =
                alloy_trie::hash_builder::HashBuilder::default().with_proof_retainer(retainer);
            // Storage leaves: hashed_slot → rlp(value) — zero slots
            // are never stored (EVM sparse-storage convention).
            let mut sleaves: std::collections::BTreeMap<revm::primitives::B256, Vec<u8>> =
                std::collections::BTreeMap::new();
            for (slot, value) in &storage_map {
                if value.is_zero() {
                    continue;
                }
                let mut leaf = Vec::with_capacity(40);
                alloy_rlp::Encodable::encode(&alloy_primitives::U256::from(*value), &mut leaf);
                sleaves
                    .insert(alloy_primitives::keccak256(revm::primitives::B256::from(*slot)), leaf);
            }
            for (hashed, leaf) in &sleaves {
                shb.add_leaf(alloy_trie::Nibbles::unpack(*hashed), leaf);
            }
            shb.root();
            let nodes = shb.take_proof_nodes();
            for (slot, target) in slots.iter().zip(targets.iter()) {
                let proof: Vec<revm::primitives::Bytes> =
                    nodes.matching_nodes_sorted(target).into_iter().map(|(_, n)| n).collect();
                let slot_u256 = revm::primitives::U256::from_be_bytes(slot.0);
                storage_proofs.push(StorageProof {
                    key: *slot,
                    value: storage_map.get(&slot_u256).copied().unwrap_or_default(),
                    proof,
                });
            }
        }

        Ok(AccountProof {
            address: evm_addr,
            balance: info.as_ref().map_or(revm::primitives::U256::ZERO, |i| i.balance),
            code_hash: info.as_ref().map_or(revm::primitives::KECCAK_EMPTY, |i| i.code_hash),
            nonce: info.as_ref().map_or(0, |i| i.nonce),
            storage_hash,
            account_proof,
            storage_proofs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx(hash_byte: u8) -> StoredTx {
        StoredTx {
            hash: B256::from([hash_byte; 32]),
            tx_index: 0,
            from: Address::ZERO,
            to: None,
            nonce: 0,
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            max_priority_fee_per_gas: 0,
            value: U256::ZERO,
            input: Vec::new(),
            tx_type: 0,
            authorization_list: Vec::new(),
            v: U256::ZERO,
            r: U256::ZERO,
            s: U256::ZERO,
        }
    }

    fn dummy_receipt(gas_used: u64) -> Receipt {
        Receipt {
            tx_type: 0,
            status: true,
            gas_used,
            logs: Vec::new(),
            bloom: [0u8; 256],
            contract_address: None,
        }
    }

    fn seal(h: &mut History, number: u64) {
        h.seal_block(number, number, 30_000_000, 1_000_000_000, Address::ZERO, B256::ZERO);
    }

    #[test]
    fn seal_and_lookup_block() {
        let mut h = History::new(4);
        h.record(dummy_tx(0xAA), dummy_receipt(21_000), &[0xde, 0xad], None);
        seal(&mut h, 1);
        let block = h.block(1).expect("block sealed");
        assert_eq!(block.txs.len(), 1);
        assert_eq!(block.txs[0].tx_index, 0, "record stamps block position");
        assert_eq!(block.gas_used, 21_000);
        assert_eq!(
            h.tx_location(&B256::from([0xAA; 32])),
            Some((1, 0)),
            "tx index must map hash -> (height, index)"
        );
    }

    #[test]
    fn block_hash_chains_parents() {
        let mut h = History::new(8);
        seal(&mut h, 1);
        let b1 = h.block(1).unwrap().hash;
        assert_ne!(b1, B256::ZERO, "sealed block gets a real hash");
        seal(&mut h, 2);
        let b2 = h.block(2).unwrap();
        assert_eq!(b2.parent_hash, b1, "child links to parent's hash");
        assert_ne!(b2.hash, b1, "distinct blocks hash distinctly");
        assert_eq!(h.block_by_hash(&b1).unwrap().number, 1);
        assert_eq!(h.block_by_hash(&b2.hash).unwrap().number, 2);
    }

    #[test]
    fn evicts_oldest_beyond_capacity() {
        let mut h = History::new(2);
        for height in 1..=4u64 {
            let tag = u8::try_from(height).unwrap();
            h.record(dummy_tx(tag), dummy_receipt(21_000), &[tag], None);
            seal(&mut h, height);
        }
        assert_eq!(h.len(), 2, "capacity bound must hold");
        assert!(h.block(1).is_none(), "height 1 evicted");
        assert!(h.block(4).is_some(), "height 4 retained");
        assert_eq!(h.latest(), Some(4));
        // Evicted tx hashes leave the index.
        assert_eq!(h.tx_location(&B256::from([1u8; 32])), None);
    }

    #[test]
    fn empty_blocks_seal() {
        let mut h = History::new(8);
        seal(&mut h, 1);
        let block = h.block(1).expect("empty block sealed");
        assert!(block.txs.is_empty());
        assert_eq!(block.gas_used, 0);
        assert_eq!(block.tx_root, EMPTY_TRIE_ROOT);
    }

    #[test]
    fn logs_filter_by_address_and_topic() {
        use alloy_primitives::{Log, LogData};
        let contract = Address::from([0x42; 20]);
        let topic = B256::from([0x77; 32]);
        let mut h = History::new(8);

        // Block 1: one matching log + one wrong-address log.
        let mut receipt = dummy_receipt(21_000);
        receipt.logs.push(Log {
            address: contract,
            data: LogData::new(vec![topic], vec![0x01].into()).unwrap(),
        });
        receipt.logs.push(Log {
            address: Address::from([0x99; 20]),
            data: LogData::new(vec![topic], vec![0x02].into()).unwrap(),
        });
        receipt.bloom = receipts::bloom_from_logs(&receipt.logs);
        h.record(dummy_tx(0x11), receipt, &[0x01], None);
        seal(&mut h, 1);

        // Block 2: matching address but wrong topic.
        let mut receipt2 = dummy_receipt(21_000);
        receipt2.logs.push(Log {
            address: contract,
            data: LogData::new(vec![B256::from([0x55; 32])], vec![0x03].into()).unwrap(),
        });
        receipt2.bloom = receipts::bloom_from_logs(&receipt2.logs);
        h.record(dummy_tx(0x22), receipt2, &[0x02], None);
        seal(&mut h, 2);

        let filter = LogFilter {
            from_block: 1,
            to_block: 2,
            block_hash: None,
            addresses: vec![contract],
            topics: vec![TopicMatcher::One(topic)],
        };
        let matches = h.logs(&filter);
        assert_eq!(matches.len(), 1, "only block 1's contract+topic log matches");
        assert_eq!(matches[0].block_number, 1);
        assert_eq!(matches[0].tx_hash, B256::from([0x11; 32]));
        assert_eq!(matches[0].log_index, 0);
        assert_eq!(matches[0].data, vec![0x01]);

        // Wildcard topic matches both blocks' contract logs.
        let filter = LogFilter {
            from_block: 1,
            to_block: 2,
            block_hash: None,
            addresses: vec![contract],
            topics: vec![TopicMatcher::Any],
        };
        let matches = h.logs(&filter);
        assert_eq!(matches.len(), 2, "wildcard topic matches both blocks");
        assert_eq!(matches[1].log_index, 0, "block 2's log is index 0 of its block");

        // blockHash restriction returns only that block's logs.
        let b1_hash = h.block(1).unwrap().hash;
        let filter = LogFilter {
            from_block: 0,
            to_block: 0,
            block_hash: Some(b1_hash),
            addresses: Vec::new(),
            topics: Vec::new(),
        };
        let matches = h.logs(&filter);
        assert_eq!(matches.len(), 2, "block 1 has both logs unfiltered");
    }

    #[test]
    fn effective_price_1559_caps_at_max_fee() {
        // max_fee=10, priority=2, base=7 -> min(10, 9) = 9
        let mut stx = dummy_tx(1);
        stx.tx_type = 2;
        stx.gas_price = 10;
        stx.max_priority_fee_per_gas = 2;
        assert_eq!(effective_gas_price(&stx, 7), 9);
        // max_fee=8 -> min(8, 9) = 8
        stx.gas_price = 8;
        assert_eq!(effective_gas_price(&stx, 7), 8);
        // legacy: flat gas price regardless of base fee
        stx.tx_type = 0;
        stx.gas_price = 5;
        assert_eq!(effective_gas_price(&stx, 7), 5);
    }
}
