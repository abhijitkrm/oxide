//! Oxide executor v0 — sequential block executor with module router.
//!
//! The executor is the application's execution lane (plan.md §6). It
//! consumes finalized blocks from consensus, executes transactions
//! sequentially through the module router, and produces state roots
//! for the execution certificate.
//!
//! # Phase 1 scope (v0)
//!
//! v0 is a **sequential** executor: one tx at a time, in block order.
//! No parallel execution, no OCC, no EVM. The module router dispatches
//! native messages to registered modules (bank, staking, etc.). EVM
//! integration arrives in Phase 2.
//!
//! # Architecture
//!
//! ```text
//! FinalizedBlock → Executor → for each tx:
//!   parse Tx envelope → route to Module → Module::handle() → Events
//!                                       ↓
//!   StateRoot = hash of all module state roots
//! ```
//!
//! The executor owns the `StorageBackend` (via the app) and drives
//! module `begin_block` / `handle` / `end_block` hooks. Each module
//! owns a subtree of the storage.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

pub mod divergence;
pub mod occ;

use ports::AppInterface;
use primitives::{Hash, Height};
use types::{CommitAck, FinalizedBlock, MempoolAck, Proposal, StateAttestation, TxBytes, Verdict};

use crypto::hash::{Domain, Hasher};

/// A module execution error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The tx envelope is malformed.
    Malformed,
    /// The module is not registered.
    UnknownModule(u8),
    /// The module rejected the message.
    ModuleRejected(String),
    /// Insufficient gas.
    OutOfGas,
}

/// Transaction context passed to modules during `handle`.
///
/// Carries the sender, nonce, and fee parsed from the tx envelope.
/// This is the C2 fix: before, `handle` received only the message
/// bytes and had no way to know who sent the tx — so the bank module
/// could only mint to the recipient, never debit the sender. Now
/// modules have the sender's identity and can enforce balance
/// checks, nonce ordering, and fee deduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxContext {
    /// The sender's address (20 bytes, parsed from the tx envelope).
    pub sender: primitives::Address,
    /// The tx nonce (8 bytes LE, parsed from the tx envelope).
    pub nonce: u64,
    /// The tx fee (8 bytes LE, parsed from the tx envelope).
    pub fee: u64,
}

/// A transaction with a pre-recovered sender.
///
/// The sender is recovered from the transaction's signature at
/// mempool ingestion time (via `Module::preverify_batch`). The
/// execution layer trusts this sender without re-verifying —
/// skipping secp256k1 recovery on the block execution hot path.
///
/// # Security
///
/// The pre-recovered sender must come from a trusted source (the
/// local mempool's `preverify_batch` call). A byzantine proposer
/// could provide wrong senders, but this is detectable by state
/// root comparison across validators. For production multi-validator
/// deployment, pair this with verification sampling.
#[derive(Debug, Clone)]
pub struct PreverifiedTx {
    /// The raw module payload bytes (e.g. RLP-encoded signed EVM tx).
    pub raw: Vec<u8>,
    /// The sender recovered from the signature (20 bytes).
    pub sender: [u8; 20],
}

/// A module: a Cosmos-SDK-style state machine that handles messages.
///
/// Each module owns a subtree of the storage and exposes `handle` for
/// message dispatch. The executor calls `begin_block` before any txs,
/// `handle` for each tx, and `end_block` after all txs.
pub trait Module: Send + Sync {
    /// The module's name (used as a storage prefix and for routing).
    fn name(&self) -> &'static str;

    /// The module's dispatch ID (used in the tx envelope to route).
    fn id(&self) -> u8;

    /// Called at the beginning of each block, before any txs.
    fn begin_block(&self, height: Height);

    /// Validate a message for mempool admission. This is the
    /// admission gate: it runs *before* `handle`, on every tx
    /// submitted to the mempool. It must be:
    ///
    /// - **Pure:** no state mutation, no side effects. It may read
    ///   module state (e.g. to check the sender's nonce and balance)
    ///   but must not write.
    /// - **Cheap:** it runs on every submitted tx, so it must be
    ///   fast enough to handle the full mempool ingress rate.
    /// - **Conservative:** a tx that passes `validate` may still fail
    ///   in `handle` (e.g. out-of-gas, revert). But a tx that fails
    ///   `validate` must never reach `handle`.
    ///
    /// The default implementation accepts all well-formed messages.
    /// Modules override this to enforce signature, nonce, gas, and
    /// balance checks before the tx enters the pool.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message can't be
    /// parsed, [`ExecError::ModuleRejected`] if the message is
    /// well-formed but fails a validation rule (bad nonce,
    /// insufficient balance, etc.).
    fn validate(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<(), ExecError> {
        Ok(())
    }

    /// Handle a message. Returns events on success, or an error.
    ///
    /// The `ctx` carries the sender, nonce, and fee parsed from the
    /// tx envelope. Modules use `ctx.sender` to debit balances, check
    /// nonces, and attribute fees.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message can't be parsed,
    /// [`ExecError::ModuleRejected`] if the module rejects the message,
    /// or [`ExecError::OutOfGas`] if the message exceeds the gas budget.
    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError>;

    /// Handle a batch of messages. Returns a vector of results, one
    /// per input message, in the same order as the input.
    ///
    /// The default implementation loops over the messages and calls
    /// [`handle`](Self::handle) for each. Modules with a faster batch
    /// path (e.g. EVM with parallel sender recovery or pre-verified
    /// senders) override this to avoid per-tx overhead.
    ///
    /// Each message is paired with its `TxContext` (parsed from the
    /// tx envelope by the executor). The module receives the
    /// *payload* — the bytes after the `[sender:20B][nonce:8B]
    /// [fee:8B][module_id:1B]` envelope header.
    ///
    /// # Errors
    ///
    /// Each result is either a vector of events (success) or an
    /// `ExecError` (failure). A failed message does not abort the
    /// batch — subsequent messages are still executed.
    fn handle_batch(&self, msgs: &[(TxContext, &[u8])]) -> Vec<Result<Vec<Event>, ExecError>> {
        msgs.iter().map(|(ctx, msg)| self.handle(ctx, msg)).collect()
    }

    /// Pre-recover senders from a batch of raw transaction payloads.
    ///
    /// This is called at mempool ingestion time to amortize
    /// secp256k1 recovery (the single most expensive per-tx
    /// operation, ~30 µs/tx) across the tx's lifetime in the pool.
    /// The pre-recovered senders are cached and reused at block
    /// execution time via [`handle_batch_preverified`](Self::handle_batch_preverified),
    /// skipping recovery entirely on the execution hot path.
    ///
    /// The default implementation returns `PreverifiedTx` with a
    /// zero sender (no pre-recovery). Modules that support
    /// pre-verification (e.g. EVM) override this to recover the
    /// sender from the transaction's signature.
    ///
    /// # Errors
    ///
    /// Returns `Err(ExecError::Malformed)` for each transaction
    /// that cannot be parsed or whose signature is invalid.
    fn preverify_batch(&self, msgs: &[&[u8]]) -> Vec<Result<PreverifiedTx, ExecError>> {
        msgs.iter().map(|raw| Ok(PreverifiedTx { raw: raw.to_vec(), sender: [0u8; 20] })).collect()
    }

    /// Execute a batch of transactions with pre-recovered senders.
    ///
    /// This is the highest-throughput serial execution path. The
    /// caller has already recovered the sender for each tx via
    /// [`preverify_batch`](Self::preverify_batch). This method
    /// skips secp256k1 recovery entirely — only RLP decoding and
    /// chain ID validation remain.
    ///
    /// The default implementation falls back to [`handle_batch`](Self::handle_batch).
    /// Modules with a pre-verified path (e.g. EVM) override this
    /// to skip sender recovery.
    ///
    /// # Errors
    ///
    /// Each result is either a vector of events (success) or an
    /// `ExecError` (failure). A failed transaction does not abort
    /// the batch.
    fn handle_batch_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        let batch: Vec<(TxContext, &[u8])> =
            txs.iter().map(|pv| (*ctx, pv.raw.as_slice())).collect();
        self.handle_batch(&batch)
    }

    /// Execute a batch of pre-verified transactions in parallel.
    ///
    /// This is the speculative parallel execution path. Transactions
    /// are grouped by sender to avoid write conflicts, and each
    /// group is executed on a separate rayon thread. Results are
    /// merged in original block order.
    ///
    /// The default implementation falls back to
    /// [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// (serial). Modules with a parallel path (e.g. EVM) override
    /// this to use rayon for speculative parallel execution.
    ///
    /// # Errors
    ///
    /// Each result is either a vector of events (success) or an
    /// `ExecError` (failure). A failed transaction does not abort
    /// the batch.
    fn handle_batch_parallel_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        self.handle_batch_preverified(ctx, txs)
    }

    /// Called at the end of each block, after all txs.
    fn end_block(&self, height: Height);

    /// Compute the module's state root (over its storage subtree).
    fn state_root(&self) -> Hash;
}

/// An event emitted by a module during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The module that emitted this event.
    pub module: &'static str,
    /// The event type (e.g. "transfer", "delegate").
    pub kind: String,
    /// The event data (module-specific).
    pub data: Vec<u8>,
}

/// The v0 tx envelope payload format. The full tx is owned by the
/// mempool: `[sender: 20B][nonce: 8B LE][fee: 8B LE][payload]`. The
/// executor routes on the first byte of `payload`:
/// `[module_id: 1B][module_payload: ...]`.
const MODULE_ID_OFFSET: usize = 36; // 20 + 8 + 8

/// Parse the module ID from a tx's payload section.
fn parse_module_id(bytes: &[u8]) -> Option<u8> {
    if bytes.len() < MODULE_ID_OFFSET + 1 {
        return None;
    }
    Some(bytes[MODULE_ID_OFFSET])
}

/// Extract the module payload from a tx (everything after `module_id`).
fn module_payload(bytes: &[u8]) -> &[u8] {
    if bytes.len() <= MODULE_ID_OFFSET + 1 {
        return &[];
    }
    &bytes[MODULE_ID_OFFSET + 1..]
}

/// Parse the tx context (sender, nonce, fee) from the tx envelope.
///
/// The v0 tx format is: `[sender: 20B][nonce: 8B LE][fee: 8B LE]
/// [module_id: 1B][module_payload: ...]`. This extracts the first
/// 36 bytes into a `TxContext`. Returns `None` if the tx is too
/// short or the sender is not a valid 20-byte address.
fn parse_tx_context(bytes: &[u8]) -> Option<TxContext> {
    if bytes.len() < TX_MIN_SIZE {
        return None;
    }
    let sender = primitives::Address::from_slice(&bytes[..20]).ok()?;
    let nonce = u64::from_le_bytes(bytes[20..28].try_into().ok()?);
    let fee = u64::from_le_bytes(bytes[28..36].try_into().ok()?);
    Some(TxContext { sender, nonce, fee })
}

/// Minimum tx batch size to use the parallel speculative execution
/// path. Below this threshold, serial execution is faster (avoids
/// rayon thread-pool overhead). Source: benchmark results showing
/// parallel execution wins above ~100 txs due to `CacheDB` clone cost.
/// See `modules/evm/benches/tps_rw.rs`.
///
/// This is the default value used when no explicit config is provided.
/// Production code should use [`Executor::with_config`] to set this
/// from the [`config`](::config) crate's `ExecutorConfig`.
pub const DEFAULT_PARALLEL_THRESHOLD: usize = 100;

/// Minimum tx size: sender (20) + nonce (8) + fee (8) = 36 bytes.
const TX_MIN_SIZE: usize = 20 + 8 + 8;

/// The executor: a sequential block executor with a module router.
///
/// Owns the registered modules and drives them through the block
/// lifecycle. Implements `AppInterface` so it can be wired behind any
/// `ConsensusEngine`.
pub struct Executor {
    /// Registered modules, indexed by their dispatch ID (0–255).
    ///
    /// A flat array gives O(1) dispatch with no pointer-chasing (vs
    /// `BTreeMap`'s tree traversal). Module IDs are `u8`, so the
    /// array has exactly 256 slots. The memory cost (256 × 8 bytes =
    /// 2 KiB on 64-bit) is negligible and the lookup is a single
    /// indexed load.
    modules: [Option<Arc<dyn Module>>; 256],
    /// The mempool (owned, so the executor is the app's intake).
    /// Behind `Mutex` because `AppInterface` methods take `&self`.
    mempool: Mutex<mempool::Mempool>,
    /// Finalized blocks, keyed by height.
    finalized: Mutex<BTreeMap<u64, FinalizedBlock>>,
    /// State roots per finalized height.
    state_roots: Mutex<BTreeMap<u64, Hash>>,
    /// The next proposal height.
    next_proposal_height: Mutex<u64>,
    /// Pending events from the current block (cleared each block).
    events: Mutex<Vec<Event>>,
    /// Pre-recovered senders, keyed by tx hash. Populated at
    /// `ingest_tx` time via `Module::preverify_batch`. Consumed at
    /// `execute_block` time to skip secp256k1 recovery on the
    /// execution hot path.
    ///
    /// Entries are removed after the block containing the tx is
    /// finalized (they are no longer needed — re-execution would
    /// re-preverify). This bounds the cache size to the mempool's
    /// capacity.
    preverify_cache: Mutex<HashMap<Hash, PreverifiedTx>>,
    /// Minimum batch size to use the parallel speculative execution
    /// path. Configurable via [`Executor::with_config`]. Default:
    /// [`DEFAULT_PARALLEL_THRESHOLD`] (100 txs).
    parallel_threshold: usize,
}

impl Executor {
    /// Construct a fresh executor with no modules and an empty mempool.
    ///
    /// Uses the default parallel threshold (100 txs). For custom
    /// configuration, use [`Executor::with_config`].
    pub fn new(max_mempool_entries: usize) -> Self {
        Self::with_config(max_mempool_entries, DEFAULT_PARALLEL_THRESHOLD)
    }

    /// Construct a fresh executor with explicit config values.
    ///
    /// # Arguments
    ///
    /// - `max_mempool_entries`: the maximum number of entries in the
    ///   mempool.
    /// - `parallel_threshold`: the minimum batch size to use the
    ///   parallel speculative execution path. Below this threshold,
    ///   serial execution is used.
    pub fn with_config(max_mempool_entries: usize, parallel_threshold: usize) -> Self {
        Self {
            modules: std::array::from_fn(|_| None),
            mempool: Mutex::new(mempool::Mempool::new(max_mempool_entries)),
            finalized: Mutex::new(BTreeMap::new()),
            state_roots: Mutex::new(BTreeMap::new()),
            next_proposal_height: Mutex::new(0),
            events: Mutex::new(Vec::new()),
            preverify_cache: Mutex::new(HashMap::new()),
            parallel_threshold,
        }
    }

    /// Register a module. The module's `ID` must be unique.
    ///
    /// # Panics
    ///
    /// Panics if a module with the same `ID` is already registered.
    pub fn register_module(&mut self, module: Arc<dyn Module>) {
        let id = module.id() as usize;
        assert!(self.modules[id].is_none(), "module with `ID` {id} already registered");
        self.modules[id] = Some(module);
    }

    /// Execute a finalized block: call `begin_block`, group txs by
    /// module, call `handle_batch` per module group, call `end_block`,
    /// compute the state root.
    ///
    /// Txs are grouped by module ID, preserving block order within
    /// each group. Each module's group is passed to `handle_batch`
    /// in one call — this lets modules with batch-optimized paths
    /// (e.g. EVM parallel sender recovery, pre-verified senders)
    /// amortize per-tx overhead across the whole group.
    ///
    /// Modules are independent (each owns its storage subtree), so
    /// grouping by module produces identical state roots to the
    /// per-tx interleaved execution. Events are grouped by module
    /// rather than interleaved, but state roots are unchanged.
    fn execute_block(&self, block: &FinalizedBlock) -> Hash {
        // Single lock acquisition for the events vector: clear at start,
        // extend after execution. The lock is released between the clear
        // and the extend because module execution can take milliseconds
        // and we don't want to hold the lock during that time. The
        // clear is here only to discard stale events from a previous
        // block; the extend publishes this block's events.
        self.events.lock().unwrap().clear();

        // begin_block for all modules.
        for module in self.modules.iter().flatten() {
            module.begin_block(block.height);
        }

        // Group txs by module ID, preserving block order within each
        // group. Each entry is (ctx, payload_bytes). We collect the
        // payload as a Vec<u8> so we can pass a slice of slices to
        // handle_batch.
        //
        // We use a BTreeMap so module groups are processed in a
        // deterministic order (sorted by module ID).
        let mut groups: BTreeMap<u8, Vec<(TxContext, Vec<u8>)>> = BTreeMap::new();
        for tx in &block.txs {
            let bytes = tx.as_bytes();
            let Some(ctx) = parse_tx_context(bytes) else {
                continue; // skip malformed txs
            };
            let Some(module_id) = parse_module_id(bytes) else {
                continue; // skip malformed txs
            };
            let payload = module_payload(bytes).to_vec();
            groups.entry(module_id).or_default().push((ctx, payload));
        }

        // Execute each module's txs as a batch.
        let mut block_events: Vec<Event> = Vec::new();

        // Clear the preverify cache after the block is executed —
        // the cached senders are no longer needed (re-execution would
        // re-preverify). We move the cache out in one lock acquisition
        // (zero-copy: `mem::take` swaps in an empty map, no clone).
        let mut preverify_cache = std::mem::take(&mut *self.preverify_cache.lock().unwrap());

        for (module_id, group) in &groups {
            let Some(module) = self.modules[*module_id as usize].as_ref() else {
                continue; // unknown module — skip
            };

            // Look up pre-recovered senders from the cache. If all
            // txs in this group have cached senders, use the
            // pre-verified execution path (skip secp256k1 recovery).
            // Otherwise, fall back to `handle_batch` (which recovers
            // senders internally).
            let preverified: Vec<PreverifiedTx> = group
                .iter()
                .map(|(_ctx, payload)| {
                    let tx_hash = Hasher::hash_one(Domain::Transaction, payload);
                    preverify_cache
                        .remove(&tx_hash)
                        .unwrap_or(PreverifiedTx { raw: payload.clone(), sender: [0u8; 20] })
                })
                .collect();

            // Check if all senders are non-zero (pre-recovered).
            let all_preverified = preverified.iter().all(|pv| pv.sender != [0u8; 20]);

            let results = if all_preverified {
                // Use the pre-verified path. For large batches, use
                // the parallel speculative path; for small batches,
                // serial is faster (avoids rayon overhead).
                if group.len() >= self.parallel_threshold {
                    module.handle_batch_parallel_preverified(&group[0].0, &preverified)
                } else {
                    module.handle_batch_preverified(&group[0].0, &preverified)
                }
            } else {
                // Fall back to the recovery path.
                let batch: Vec<(TxContext, &[u8])> =
                    group.iter().map(|(ctx, payload)| (*ctx, payload.as_slice())).collect();
                module.handle_batch(&batch)
            };
            for events in results.into_iter().flatten() {
                block_events.extend(events);
            }
        }
        // Publish all events from this block in one lock acquisition.
        self.events.lock().unwrap().extend(block_events);

        // end_block for all modules.
        for module in self.modules.iter().flatten() {
            module.end_block(block.height);
        }

        // Compute the state root: hash all module state roots.
        let mut root_data = Vec::new();
        for module in self.modules.iter().flatten() {
            let mr = module.state_root();
            root_data.extend_from_slice(mr.as_bytes());
        }
        Hasher::hash_one(Domain::Block, &root_data)
    }
}

impl AppInterface for Executor {
    fn ingest_tx(&self, tx: TxBytes) -> MempoolAck {
        // A4: route mempool admission through `Module::validate`.
        // Before storing the tx in the mempool, we parse the envelope,
        // find the target module, and call its `validate` method. This
        // rejects invalid txs (bad signature, wrong chain ID, bad
        // nonce, insufficient balance) before they enter the pool —
        // keeping the pool clean and the execution path fast.
        let bytes = tx.as_bytes();
        let Some(ctx) = parse_tx_context(bytes) else {
            return MempoolAck::Rejected { reason: "malformed: tx context".to_string() };
        };
        let Some(module_id) = parse_module_id(bytes) else {
            return MempoolAck::Rejected { reason: "malformed: no module ID".to_string() };
        };
        let Some(module) = self.modules[module_id as usize].as_ref() else {
            return MempoolAck::Rejected { reason: format!("unknown module {module_id}") };
        };
        let payload = module_payload(bytes);
        if let Err(e) = module.validate(&ctx, payload) {
            return MempoolAck::Rejected { reason: format!("validate: {e:?}") };
        }

        // Pre-recover the sender at ingestion time and cache it.
        // This amortizes secp256k1 recovery (~30 µs/tx) across the
        // tx's lifetime in the mempool. At block execution time, the
        // cached sender is used to skip recovery entirely — the
        // execution hot path sees only RLP decode + chain ID check.
        //
        // For modules without a preverify implementation (default
        // returns a zero sender), this is a no-op that stores a
        // placeholder. The execution path falls back to `handle_batch`
        // when the sender is zero.
        let preverify_result = module.preverify_batch(&[payload]);
        if let Ok(preverified) = &preverify_result[0] {
            let tx_hash =
                crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, tx.as_bytes());
            self.preverify_cache.lock().unwrap().insert(tx_hash, preverified.clone());
        }

        match self.mempool.lock().unwrap().submit(tx) {
            Ok(()) => MempoolAck::Accepted,
            Err(e) => MempoolAck::Rejected { reason: format!("{e:?}") },
        }
    }

    fn prepare_proposal(&self, budget: &types::BlockBudget) -> Proposal {
        // Select txs from the mempool by fee priority.
        let txs = self.mempool.lock().unwrap().select(budget.max_bytes);
        let height = Height::new(*self.next_proposal_height.lock().unwrap());
        Proposal { height, txs, attestation: None }
    }

    fn process_proposal(&self, proposal: &Proposal) -> Verdict {
        // M2 fix: validate each tx's static structure. Previously
        // this accepted all proposals unconditionally, which meant
        // a byzantine leader could propose a block with malformed
        // txs and they'd be silently skipped during execution.
        //
        // Static validity checks (no state access):
        // 1. Each tx must be long enough to have a sender, nonce,
        //    fee, and module ID (≥ 37 bytes).
        // 2. Each tx's module ID must be a registered module.
        //
        // Dynamic checks (nonce ordering, balance, signature) are
        // not done here — they require state access and are checked
        // during execution. Signature verification arrives when the
        // tx envelope format includes signatures (Phase 2).
        for tx in &proposal.txs {
            let bytes = tx.as_bytes();
            // Check that the tx context is parseable (sender, nonce,
            // fee). This also implicitly checks the minimum size
            // (TX_MIN_SIZE = 36 bytes).
            if parse_tx_context(bytes).is_none() {
                return Verdict::Reject {
                    reason: "tx context (sender/nonce/fee) is malformed".to_string(),
                };
            }
            // Check that the tx has a module ID byte.
            if bytes.len() < MODULE_ID_OFFSET + 1 {
                return Verdict::Reject { reason: "tx too short for module ID".to_string() };
            }
            // Check that the module is registered.
            let Some(module_id) = parse_module_id(bytes) else {
                return Verdict::Reject { reason: "tx has no module ID".to_string() };
            };
            if self.modules[module_id as usize].is_none() {
                return Verdict::Reject { reason: format!("unknown module ID {module_id}") };
            }
        }
        Verdict::Accept
    }

    fn finalize_block(&self, block: &FinalizedBlock) -> CommitAck {
        // Execute the block and record the state root.
        let root = self.execute_block(block);
        self.state_roots.lock().unwrap().insert(block.height.value(), root);
        self.finalized.lock().unwrap().insert(block.height.value(), block.clone());
        *self.next_proposal_height.lock().unwrap() = block.height.value() + 1;
        CommitAck { height: block.height }
    }

    fn attest_state(&self, height: Height) -> StateAttestation {
        let root =
            self.state_roots.lock().unwrap().get(&height.value()).copied().unwrap_or(Hash::ZERO);
        StateAttestation { height, root }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus::SequencerEngine;
    use ports::ConsensusEngine;
    use primitives::Address;

    /// A trivial test module that counts messages.
    struct CounterModule {
        count: Mutex<u64>,
    }

    impl CounterModule {
        fn new() -> Self {
            Self { count: Mutex::new(0) }
        }
    }

    impl Module for CounterModule {
        fn name(&self) -> &'static str {
            "counter"
        }
        fn id(&self) -> u8 {
            1
        }

        fn begin_block(&self, _height: Height) {}

        fn handle(&self, _ctx: &TxContext, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            let mut c = self.count.lock().unwrap();
            *c += 1;
            Ok(vec![Event { module: "counter", kind: "increment".to_string(), data: vec![] }])
        }

        fn end_block(&self, _height: Height) {}

        fn state_root(&self) -> Hash {
            let c = *self.count.lock().unwrap();
            let byte = u8::try_from(c).unwrap_or(0xff);
            Hash([byte; 32])
        }
    }

    fn make_tx(module_id: u8, payload: &[u8]) -> TxBytes {
        // Build a tx in the mempool's v0 format:
        // [sender: 20B][nonce: 8B LE][fee: 8B LE][module_id: 1B][payload].
        let sender = Address([0u8; 20]);
        let nonce = 0u64;
        let fee = 100u64;
        let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
        bytes.extend_from_slice(&sender.0);
        bytes.extend_from_slice(&nonce.to_le_bytes());
        bytes.extend_from_slice(&fee.to_le_bytes());
        bytes.push(module_id);
        bytes.extend_from_slice(payload);
        TxBytes::new(bytes)
    }

    #[test]
    fn executor_executes_block_and_produces_state_root() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Submit a tx to the executor's mempool (via AppInterface).
        let tx = make_tx(1, &[42]);
        executor.ingest_tx(tx);

        // Prepare a proposal.
        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert_eq!(proposal.txs.len(), 1);

        // Finalize the block.
        let block = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        let ack = executor.finalize_block(&block);
        assert_eq!(ack.height, Height::new(0));

        // The state root should be non-zero (the counter incremented).
        let attestation = executor.attest_state(Height::new(0));
        assert_ne!(attestation.root, Hash::ZERO);
    }

    #[test]
    fn executor_with_sequencer_engine_end_to_end() {
        // Wire the executor behind a SequencerEngine and run the full
        // OAI flow: submit → propose → finalize → attest.
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Wrap in Arc for the engine.
        let app: Arc<dyn AppInterface> = Arc::new(executor);
        let mut engine = SequencerEngine::new(app);

        // Submit a tx through the engine.
        let tx = make_tx(1, &[1]);
        engine.submit_tx(tx);
        engine.run_until_idle();

        // The engine should have finalized a block.
        assert!(engine.finalized_height().is_some());

        // The state root should be non-zero.
        let app = engine.app();
        let attestation = app.attest_state(Height::new(0));
        assert_ne!(attestation.root, Hash::ZERO, "state root should be non-zero after execution");
    }

    #[test]
    fn executor_skips_unknown_module() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));

        // Submit a tx for an unregistered module (ID 99).
        let tx = make_tx(99, &[1]);
        executor.ingest_tx(tx);

        let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        let block = FinalizedBlock { height: Height::new(0), txs: proposal.txs };
        executor.finalize_block(&block);

        // The unknown module's tx should be silently skipped.
        // The counter module should not have been called.
        let attestation = executor.attest_state(Height::new(0));
        // State root is the hash of the counter's state root (0).
        assert_ne!(attestation.root, Hash::ZERO, "state root should reflect counter=0");
    }

    #[test]
    fn executor_multiple_blocks_state_advances() {
        let mut executor = Executor::new(100);
        let counter = Arc::new(CounterModule::new());
        executor.register_module(counter.clone());

        // Execute 3 blocks, each with 1 tx.
        for h in 0..3u64 {
            let h_byte = u8::try_from(h).unwrap_or(0xff);
            let tx = make_tx(1, &[h_byte]);
            executor.ingest_tx(tx);
            let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
            let proposal = executor.prepare_proposal(&budget);
            let block = FinalizedBlock { height: Height::new(h), txs: proposal.txs };
            executor.finalize_block(&block);
        }

        // The counter should have been called 3 times.
        let count = *counter.count.lock().unwrap();
        assert_eq!(count, 3, "counter should have been incremented 3 times");

        // Each block should have a different state root.
        let root0 = executor.attest_state(Height::new(0)).root;
        let root1 = executor.attest_state(Height::new(1)).root;
        let root2 = executor.attest_state(Height::new(2)).root;
        assert_ne!(root0, root1, "state roots should differ across blocks");
        assert_ne!(root1, root2, "state roots should differ across blocks");
    }

    // ---- M2 fix: process_proposal validation tests ----

    #[test]
    fn process_proposal_accepts_valid_tx() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let tx = make_tx(1, &[42]);
        let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
        assert!(matches!(executor.process_proposal(&proposal), Verdict::Accept));
    }

    #[test]
    fn process_proposal_rejects_too_short_tx() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let proposal = Proposal {
            height: Height::new(0),
            txs: vec![TxBytes::new(vec![1, 2, 3])], // way too short
            attestation: None,
        };
        match executor.process_proposal(&proposal) {
            Verdict::Reject { reason } => assert!(reason.contains("malformed")),
            Verdict::Accept => panic!("should reject too-short tx"),
        }
    }

    #[test]
    fn process_proposal_rejects_unknown_module() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));
        let tx = make_tx(99, &[1]); // module 99 is not registered
        let proposal = Proposal { height: Height::new(0), txs: vec![tx], attestation: None };
        match executor.process_proposal(&proposal) {
            Verdict::Reject { reason } => assert!(reason.contains("unknown module")),
            Verdict::Accept => panic!("should reject unknown module"),
        }
    }

    #[test]
    fn process_proposal_rejects_malformed_context() {
        let mut executor = Executor::new(100);
        executor.register_module(Arc::new(CounterModule::new()));
        // A tx with 37 bytes (minimum for module ID) but with a
        // malformed sender (not a valid address — but actually
        // any 20 bytes is a valid Address, so we need to test a
        // different malformation). Let's use a tx that's exactly
        // 36 bytes (no module ID byte) — this should be rejected
        // as "too short for module ID".
        let mut bytes = vec![0u8; 36]; // 20 + 8 + 8, no module ID
        bytes.push(1); // add module ID
        // Actually this is valid. Let's make a tx with a bad nonce
        // section — but u64::from_le_bytes never fails on 8 bytes.
        // The real malformation is a tx shorter than 36 bytes.
        let short_tx = TxBytes::new(vec![0u8; 30]); // < 36 bytes
        let proposal = Proposal { height: Height::new(0), txs: vec![short_tx], attestation: None };
        match executor.process_proposal(&proposal) {
            Verdict::Reject { reason } => assert!(reason.contains("malformed")),
            Verdict::Accept => panic!("should reject malformed tx"),
        }
    }
}
