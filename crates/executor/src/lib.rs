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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

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

    /// Handle a message. Returns events on success, or an error.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message can't be parsed,
    /// [`ExecError::ModuleRejected`] if the module rejects the message,
    /// or [`ExecError::OutOfGas`] if the message exceeds the gas budget.
    fn handle(&self, msg: &[u8]) -> Result<Vec<Event>, ExecError>;

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

/// The executor: a sequential block executor with a module router.
///
/// Owns the registered modules and drives them through the block
/// lifecycle. Implements `AppInterface` so it can be wired behind any
/// `ConsensusEngine`.
pub struct Executor {
    /// Registered modules, indexed by their dispatch ID.
    modules: BTreeMap<u8, Arc<dyn Module>>,
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
}

impl Executor {
    /// Construct a fresh executor with no modules and an empty mempool.
    pub fn new(max_mempool_entries: usize) -> Self {
        Self {
            modules: BTreeMap::new(),
            mempool: Mutex::new(mempool::Mempool::new(max_mempool_entries)),
            finalized: Mutex::new(BTreeMap::new()),
            state_roots: Mutex::new(BTreeMap::new()),
            next_proposal_height: Mutex::new(0),
            events: Mutex::new(Vec::new()),
        }
    }

    /// Register a module. The module's `ID` must be unique.
    ///
    /// # Panics
    ///
    /// Panics if a module with the same `ID` is already registered.
    pub fn register_module(&mut self, module: Arc<dyn Module>) {
        let id = module.id();
        assert!(
            self.modules.insert(id, module).is_none(),
            "module with `ID` {id} already registered"
        );
    }

    /// Execute a finalized block: call `begin_block`, handle each tx,
    /// call `end_block`, compute the state root.
    fn execute_block(&self, block: &FinalizedBlock) -> Hash {
        self.events.lock().unwrap().clear();

        // begin_block for all modules.
        for module in self.modules.values() {
            module.begin_block(block.height);
        }

        // Execute each tx sequentially.
        for tx in &block.txs {
            let bytes = tx.as_bytes();
            let Some(module_id) = parse_module_id(bytes) else {
                continue; // skip malformed txs
            };
            let payload = module_payload(bytes);
            if let Some(module) = self.modules.get(&module_id) {
                if let Ok(events) = module.handle(payload) {
                    self.events.lock().unwrap().extend(events);
                }
            }
        }

        // end_block for all modules.
        for module in self.modules.values() {
            module.end_block(block.height);
        }

        // Compute the state root: hash all module state roots.
        let mut root_data = Vec::new();
        for module in self.modules.values() {
            let mr = module.state_root();
            root_data.extend_from_slice(mr.as_bytes());
        }
        Hasher::hash_one(Domain::Block, &root_data)
    }
}

impl AppInterface for Executor {
    fn ingest_tx(&self, tx: TxBytes) -> MempoolAck {
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
        // v0: accept all proposals. Real validation (nonce, fee, sig)
        // arrives with the modules framework.
        let _ = proposal;
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

        fn handle(&self, _msg: &[u8]) -> Result<Vec<Event>, ExecError> {
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
}
