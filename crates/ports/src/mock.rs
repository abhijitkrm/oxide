//! Reference implementation: a `MockApp` and a `MockEngine`.
//!
//! These exist for three reasons (oai-spec.md §2, testing-standards §3):
//!
//! 1. **Conformance baseline.** The [`conformance`] suite runs against
//!    `MockEngine` first; every other engine must pass the same suite.
//! 2. **OAI exercise.** A working end-to-end OAI flow (submit → propose
//!    → process → finalize → attest) proves the traits are sufficient
//!    before any real engine is built against them.
//! 3. **Simulation substrate.** Deterministic swarm simulations
//!    (Phase 1) start from `MockEngine` and graduate to oxideBFT.
//!
//! # Mock semantics
//!
//! `MockEngine` is a single-leader, no-voting engine: every
//! `run_until_idle` with pending transactions produces exactly one block
//! containing all pending txs (up to budget), at the next height. It
//! performs no networking, no signatures, no views — it is the
//! degenerate case of the OAI contract, which is exactly what makes it
//! a useful specification of that contract.

use std::collections::BTreeMap;
use std::sync::Mutex;

use primitives::{Hash, Height};
use types::{
    BlockBudget, CommitAck, FinalizedBlock, MempoolAck, Proposal, StateAttestation, TxBytes,
    Verdict,
};

use crate::AppInterface;

/// A trivial-but-real application: a mempool, a finalized-height →
/// state-root map, and a proposal-height counter that advances in
/// lockstep with the engine.
///
/// All state is behind `Mutex` so `AppInterface`'s `&self` methods can
/// mutate — matching how a real app backs the trait with channels into
/// async lanes rather than `&mut self`.
pub struct MockApp {
    /// Pending transactions not yet consumed by `prepare_proposal`.
    mempool: Mutex<Vec<TxBytes>>,
    /// Mock state roots keyed by finalized height. A real app computes
    /// these from execution; the mock derives a deterministic placeholder.
    state_roots: Mutex<BTreeMap<u64, Hash>>,
    /// The next height `prepare_proposal` will assemble for. Incremented
    /// once per proposal so the engine and app stay in lockstep.
    next_proposal_height: Mutex<u64>,
    /// Staged validator-set transitions, drained one per
    /// `take_epoch_changes` call — the mock half of the epoch
    /// protocol: a real app produces these from executed staking
    /// transactions; the mock lets a test script them.
    pending_epoch_changes: Mutex<Vec<types::EpochChanges>>,
}

impl MockApp {
    /// Construct an empty mock app at genesis (next proposal height 0).
    pub fn new() -> Self {
        Self {
            mempool: Mutex::new(Vec::new()),
            state_roots: Mutex::new(BTreeMap::new()),
            next_proposal_height: Mutex::new(0),
            pending_epoch_changes: Mutex::new(Vec::new()),
        }
    }

    /// Stage a validator-set transition for the next
    /// `take_epoch_changes` drain — tests use this to drive the
    /// engine's epoch lifecycle the way a staking module would.
    ///
    /// # Panics
    /// When the staging queue's mutex is poisoned — the same
    /// fail-loud policy as every other `MockApp` lock.
    pub fn queue_epoch_changes(&self, changes: types::EpochChanges) {
        primitives::sync::lock_state(&self.pending_epoch_changes).push(changes);
    }
}

impl Default for MockApp {
    fn default() -> Self {
        Self::new()
    }
}

impl AppInterface for MockApp {
    fn ingest_tx(&self, tx: TxBytes) -> MempoolAck {
        primitives::sync::lock_state(&self.mempool).push(tx);
        MempoolAck::Accepted
    }

    fn prepare_proposal(&self, budget: &BlockBudget) -> Proposal {
        let mut mempool = primitives::sync::lock_state(&self.mempool);
        let next_height = primitives::sync::lock_state(&self.next_proposal_height);

        // Drain the mempool into the proposal, respecting the byte
        // budget. A real app applies gas/nonce/fee selection here; the
        // mock takes txs in arrival order until the budget is full.
        let mut txs = Vec::new();
        let mut total_bytes = 0u64;
        let mut taken = 0;
        for tx in mempool.iter() {
            let len = tx.as_bytes().len() as u64;
            if total_bytes + len > budget.max_bytes {
                break;
            }
            total_bytes += len;
            txs.push(tx.clone());
            taken += 1;
        }
        mempool.drain(0..taken);

        // Read (do not advance) the next height: the counter only moves
        // when a proposal is actually finalized (see `finalize_block`).
        // Advancing here would desync the app from the engine whenever
        // the engine calls prepare_proposal to check for pending work
        // and then drops the (empty) proposal — a real bug caught by the
        // conformance suite's gap-free-heights assertion.
        let height = Height::new(*next_height);

        Proposal { height, txs, attestation: None }
    }

    fn has_queued_txs(&self) -> bool {
        !primitives::sync::lock_state(&self.mempool).is_empty()
    }

    fn process_proposal(&self, proposal: &Proposal) -> Verdict {
        // Static validity only. Never executes — a proposal that would
        // revert is still accepted (oai-spec.md §3, rule 4).
        //
        // Empty proposals are accepted: pipelined engines (e.g. oxideBFT
        // with 2-chain commit) propose empty blocks to advance the
        // pipeline and commit pending blocks. Rejecting empty proposals
        // would break the pipeline flush.
        let _ = proposal;
        Verdict::Accept
    }

    fn finalize_block(&self, block: &FinalizedBlock) -> CommitAck {
        // Record a deterministic mock state root. A real app computes
        // this from execution; the mock uses a height-derived placeholder
        // so attest_state is stable and inspectable.
        let root = mock_state_root(block.height);
        primitives::sync::lock_state(&self.state_roots).insert(block.height.value(), root);
        // Advance the proposal counter now that this height is
        // committed. This is the only place the counter moves, keeping
        // it in lockstep with the engine's `next_height` (which advances
        // on the same finalization event).
        *primitives::sync::lock_state(&self.next_proposal_height) = block.height.value() + 1;
        CommitAck { height: block.height }
    }

    fn attest_state(&self, height: Height) -> Option<StateAttestation> {
        // The mock reports a deterministic root for *every* height —
        // finalized or not — so tests can attest arbitrary heights
        // without driving finalization first. A real app returns
        // `None` for unexecuted heights; engine tests that need the
        // `None` path use a dedicated stub.
        let root = primitives::sync::lock_state(&self.state_roots)
            .get(&height.value())
            .copied()
            .unwrap_or_else(|| mock_state_root(height));
        Some(StateAttestation { height, root })
    }

    /// One staged transition per call — mirroring a real app's
    /// destructive drain: once consumed, a record is gone.
    fn take_epoch_changes(&self) -> types::EpochChanges {
        primitives::sync::lock_state(&self.pending_epoch_changes).pop().unwrap_or_default()
    }

    fn attest_latest(&self) -> Option<StateAttestation> {
        // Newest executed height: the mock records one root per
        // finalized block, so the max key is the execution tip.
        // `None` before the first block, matching the real
        // executor's "nothing executed" signal.
        primitives::sync::lock_state(&self.state_roots)
            .iter()
            .next_back()
            .map(|(h, root)| StateAttestation { height: Height::new(*h), root: *root })
    }
}

/// A deterministic, height-derived mock state root. Not a real hash —
/// just a stable, inspectable placeholder so the OAI attestation flow
/// can be tested without depending on a hashing crate here. The real
/// executor (Phase 1) replaces this with a merkleized state root.
///
/// Only the low byte of the height is used (heights beyond 255 are
/// absurd for a test mock); the `try_from` keeps the cast explicit and
/// clippy-clean rather than a bare `as u8`.
fn mock_state_root(height: Height) -> Hash {
    let v = height.value();
    let byte = u8::try_from(v).unwrap_or(0xff);
    Hash([byte; 32])
}

/// The reference engine: single-leader, no-voting, no-network.
///
/// Owns its [`MockApp`] so the conformance suite can construct a fully
/// isolated engine+app pair per run (the determinism assertion needs
/// fresh state each run). Exposes the app via [`MockEngine::app`] for
/// post-run inspection.
pub struct MockEngine {
    app: MockApp,
    /// The next height at which a block will be finalized.
    next_height: Height,
    /// Finalized blocks keyed by height. `BTreeMap` for ordered
    /// iteration (the conformance suite checks the height sequence).
    finalized: BTreeMap<u64, FinalizedBlock>,
}

impl MockEngine {
    /// Construct a fresh engine with a fresh app at genesis.
    pub fn new() -> Self {
        Self { app: MockApp::new(), next_height: Height::new(0), finalized: BTreeMap::new() }
    }

    /// The budget the mock uses when assembling proposals. Generous on
    /// purpose: the mock is testing the OAI flow, not mempool
    /// selection. A real engine receives the budget from chain config.
    const BUDGET: BlockBudget = BlockBudget {
        max_bytes: 1 << 20, // 1 MiB
        max_gas: 1 << 30,   // 1 gigagas — the plan's headline capacity
    };

    /// Access the embedded app for post-run inspection (conformance,
    /// e2e tests).
    pub fn app(&self) -> &MockApp {
        &self.app
    }
}

impl Default for MockEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::ConsensusEngine for MockEngine {
    fn submit_tx(&mut self, tx: TxBytes) -> MempoolAck {
        // Default path: forward to the app's mempool.
        self.app.ingest_tx(tx)
    }

    fn run_until_idle(&mut self) {
        // Produce blocks until the mempool is empty. Each iteration:
        // propose → process → finalize → record → advance height.
        loop {
            let proposal = self.app.prepare_proposal(&Self::BUDGET);
            // No pending txs and not genesis → nothing to propose.
            if proposal.txs.is_empty() && self.next_height != Height::new(0) {
                break;
            }
            match self.app.process_proposal(&proposal) {
                Verdict::Accept => {}
                Verdict::Reject { reason } => {
                    // The mock never rejects a non-empty proposal; a
                    // rejection here is a bug in the mock itself. Panic
                    // rather than silently dropping a block — this is
                    // test infrastructure, not production code.
                    panic!("MockEngine: proposal rejected: {reason}");
                }
            }
            // Mock engine attributes no signers — attendance is
            // meaningless without real consensus; empty = no data.
            // The execution context is the all-zero sentinel: a
            // clockless mock commits no timestamp/beneficiary, and
            // modules keep configured defaults under it — the
            // conformance suite's cross-engine block comparisons
            // stay engine-agnostic on the context.
            let block = FinalizedBlock {
                height: proposal.height,
                txs: proposal.txs,
                signers: Vec::new(),
                context: types::BlockContext::default(),
            };
            self.app.finalize_block(&block);
            self.finalized.insert(block.height.value(), block);
            self.next_height = Height::new(self.next_height.value() + 1);
        }
    }

    fn finalized_height(&self) -> Option<Height> {
        self.finalized.keys().next_back().map(|&h| Height::new(h))
    }

    fn finalized_block(&self, height: Height) -> Option<FinalizedBlock> {
        self.finalized.get(&height.value()).cloned()
    }
}
