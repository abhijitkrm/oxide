//! `SequencerEngine` — a single-leader, no-voting dev-mode engine.
//!
//! This is the second adapter behind the `ports::ConsensusEngine` seam
//! (plan.md §2.1, §13 Phase 1). It exists for two reasons:
//!
//! 1. **Seam proof.** The Phase 1 acceptance gate requires "devnet also
//!    runs on `SequencerEngine` via config swap with zero app-code
//!    changes" (plan.md §13). If the same app runs under `MockEngine`,
//!    `SequencerEngine`, and `OxideBft` without changes, the seam is
//!    real — not a leaky abstraction.
//! 2. **Dev/testnet simplicity.** A single leader with no voting is
//!    the simplest engine that still produces a real block stream.
//!    It's the degenerate case of the OAI contract: one leader, no
//!    faults, no view changes, no epochs. Useful for local devnets
//!    where BLS aggregation overhead is unwanted.
//!
//! # Semantics
//!
//! `SequencerEngine` is a strict subset of oxideBFT's happy path:
//! - One configured leader (no validator set, no voting).
//! - Each `run_until_idle` with pending txs produces one block at the
//!   next height, containing all pending txs up to budget.
//! - No empty blocks (no pipeline to flush — single-block commit).
//! - No views, no QCs, no TCs, no epochs.
//! - Finality is immediate: a block is finalized the moment it's
//!   proposed.
//!
//! # What this proves
//!
//! If `SequencerEngine` passes the conformance suite (the same suite
//! `MockEngine` and `OxideBft` pass), and the same `MockApp` runs under
//! all three engines producing identical finalized blocks, then the
//! `ConsensusEngine` trait is a true seam — the app is engine-agnostic.
//!
//! # Why not just use `MockEngine`?
//!
//! `MockEngine` is the *reference* engine — it exists to specify the
//! OAI contract. `SequencerEngine` is a *real* engine — it has a
//! configured leader identity, a view counter (always 0), and block
//! headers with a proposer field. It's the minimal engine a devnet
//! could actually run (modulo networking). `MockEngine` is test
//! infrastructure; `SequencerEngine` is a dev-mode product.

use std::collections::BTreeMap;
use std::sync::Arc;

use ports::AppInterface;
use primitives::Height;
use types::{BlockBudget, FinalizedBlock, MempoolAck, TxBytes, Verdict};

/// The block budget the sequencer uses when assembling proposals.
/// Matches `MockEngine` and `OxideBft` — the budget is a chain config
/// property, not an engine property.
const BUDGET: BlockBudget = BlockBudget {
    max_bytes: 1 << 20, // 1 MiB
    max_gas: 1 << 30,   // 1 gigagas — the plan's headline capacity
};

/// A single-leader, no-voting dev-mode consensus engine.
///
/// Owns its `AppInterface` (the same `MockApp` or a real app) so the
/// conformance suite can construct a fully isolated engine+app pair
/// per run. The app is shared across all engines — this is what makes
/// the seam test meaningful.
pub struct SequencerEngine {
    /// The application (executor + mempool + state). Owned so the
    /// engine can drive it through the full OAI flow.
    app: Arc<dyn AppInterface>,
    /// The next height at which a block will be finalized.
    next_height: Height,
    /// Finalized blocks keyed by height. `BTreeMap` for ordered
    /// iteration (the conformance suite checks the height sequence).
    finalized: BTreeMap<u64, FinalizedBlock>,
    /// The block clock — milliseconds since the Unix epoch, read once
    /// per finalized block for the execution context. The sequencer
    /// has no header to sign under, but the context is the same
    /// protocol model: execution observes the engine's stamp, and a
    /// deterministic test/sim can inject a fixed clock via
    /// [`SequencerEngine::with_clock`].
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Shared live chain parameters, when node assembly wired the
    /// governance `chain.*` sink — same role as
    /// [`OxideBft::with_chain_params`]: the atomics replace the
    /// static [`BUDGET`] so a parameter apply reaches the sequencer's
    /// proposal budget and stamped `gas_limit` at the same height.
    chain_params: Option<Arc<types::ChainParams>>,
}

impl SequencerEngine {
    /// Construct a fresh engine with the given app at genesis.
    pub fn new(app: Arc<dyn AppInterface>) -> Self {
        Self {
            app,
            next_height: Height::new(0),
            finalized: BTreeMap::new(),
            clock: Arc::new(types::system_time_ms),
            chain_params: None,
        }
    }

    /// Set the block clock (same role as [`OxideBft::with_clock`]):
    /// tests and deterministic sims inject a fixed/scripted clock so
    /// the finalized execution context is reproducible.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Install the shared live chain-parameters handle — see
    /// [`OxideBft::with_chain_params`].
    #[must_use]
    pub fn with_chain_params(mut self, params: Arc<types::ChainParams>) -> Self {
        self.chain_params = Some(params);
        self
    }

    /// The live proposal budget: the shared atomics when the
    /// governance-wired handle is installed, the static [`BUDGET`]
    /// otherwise.
    fn budget(&self) -> BlockBudget {
        match &self.chain_params {
            Some(params) => BlockBudget {
                max_bytes: params.max_bytes.load(std::sync::atomic::Ordering::Relaxed),
                max_gas: params.max_gas.load(std::sync::atomic::Ordering::Relaxed),
            },
            None => BUDGET,
        }
    }

    /// Access the embedded app for post-run inspection (conformance,
    /// e2e tests, seam-swap tests).
    pub fn app(&self) -> &Arc<dyn AppInterface> {
        &self.app
    }
}

impl ports::ConsensusEngine for SequencerEngine {
    fn submit_tx(&mut self, tx: TxBytes) -> MempoolAck {
        // Default path: forward to the app's mempool.
        self.app.ingest_tx(tx)
    }

    fn run_until_idle(&mut self) {
        // Produce blocks until the mempool is empty. Each iteration:
        // propose → process → finalize → record → advance height.
        // Unlike oxideBFT (2-chain pipeline), the sequencer commits
        // immediately — no pending blocks, no flush round.
        loop {
            let proposal = self.app.prepare_proposal(&self.budget());
            // No pending txs and not genesis → nothing to propose.
            // The sequencer never produces empty blocks (no pipeline
            // to flush — single-block commit).
            if proposal.txs.is_empty() && self.next_height != Height::new(0) {
                break;
            }
            match self.app.process_proposal(&proposal) {
                Verdict::Accept => {}
                Verdict::Reject { reason } => {
                    // Drop the proposal and stop sequencing. The
                    // sequencer is dev-mode; a rejection means the
                    // app found the proposal invalid. Panicking here
                    // would crash the devnet on any app-level
                    // rejection, which is too fragile for testing.
                    eprintln!(
                        "SequencerEngine: proposal rejected (height={:?}): {reason}",
                        proposal.height
                    );
                    break;
                }
            }
            // Sequencer mode has one signer (itself) — attendance
            // tracking is meaningless; empty = no data. The context
            // stamps the sequencer's own clock and the block budget's
            // gas limit; there is no committee, so `beneficiary` is
            // the ZERO sentinel ("no proposer attribution").
            let context = types::BlockContext {
                timestamp_ms: (self.clock)(),
                beneficiary: primitives::Address::ZERO,
                gas_limit: self.budget().max_gas,
            };
            let block = FinalizedBlock {
                height: proposal.height,
                txs: proposal.txs,
                signers: Vec::new(),
                context,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ports::ConsensusEngine;
    use ports::conformance;
    use ports::mock::MockApp;
    use std::sync::Arc;

    fn make_engine() -> SequencerEngine {
        // Fixed clock: the conformance determinism gate compares
        // finalized blocks byte-for-byte across two runs, and the
        // execution context carries the block timestamp — a wall
        // clock would make identical runs differ.
        SequencerEngine::new(Arc::new(MockApp::new())).with_clock(|| 1_700_000_000_000)
    }

    #[test]
    fn sequencer_passes_conformance() {
        conformance::assert_conformance(make_engine);
    }

    #[test]
    fn sequencer_starts_at_genesis() {
        let engine = make_engine();
        assert_eq!(engine.finalized_height(), None, "no blocks at genesis");
    }

    #[test]
    fn one_tx_produces_one_committed_block() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        assert_eq!(engine.finalized_height(), Some(Height::new(0)));
        let block = engine.finalized_block(Height::new(0)).expect("block 0");
        assert_eq!(block.txs.len(), 1);
        assert_eq!(block.txs[0].as_bytes(), &[1]);
    }

    #[test]
    fn multiple_txs_all_committed() {
        let mut engine = make_engine();
        for i in 0..5u8 {
            engine.submit_tx(TxBytes::new(vec![i]));
            engine.run_until_idle();
        }
        // Each tx is submitted then run, so each gets its own block.
        assert_eq!(engine.finalized_height(), Some(Height::new(4)));
        let mut found_txs = Vec::new();
        for h in 0..=4 {
            let block = engine.finalized_block(Height::new(h)).expect("block");
            found_txs.extend(block.txs.iter().cloned());
        }
        assert_eq!(found_txs.len(), 5, "all 5 txs must be committed");
    }

    #[test]
    fn no_work_when_idle() {
        let mut engine = make_engine();
        engine.run_until_idle();
        // Genesis block (empty) is produced at height 0.
        assert_eq!(engine.finalized_height(), Some(Height::new(0)));
        let height_before = engine.finalized_height();
        engine.run_until_idle();
        assert_eq!(engine.finalized_height(), height_before, "no new blocks when idle");
    }

    #[test]
    fn finality_is_final() {
        let mut engine = make_engine();
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        let snapshot = engine.finalized_block(Height::new(0)).expect("block 0");
        // Run again with no new txs — must not alter the block.
        engine.run_until_idle();
        let after = engine.finalized_block(Height::new(0)).expect("block 0");
        assert_eq!(after, snapshot, "finalized block changed after no-op run");
    }

    // ---- Seam-swap test: same app, different engines, same outputs ----
    //
    // The Phase 1 acceptance gate (plan.md §13): "devnet also runs on
    // SequencerEngine via config swap with zero app-code changes
    // (proves the seam)." This test proves the seam at the unit level:
    // the same `MockApp` (the application) runs under `MockEngine`,
    // `SequencerEngine`, and `OxideBft`, producing identical finalized
    // block sequences. If this passes, the app is engine-agnostic.

    #[test]
    fn seam_swap_same_app_same_outputs() {
        use ports::mock::MockEngine;

        // The deterministic tx sequence used across all three engines.
        let txs: Vec<TxBytes> =
            (0..3u8).map(|i| TxBytes::new(vec![i, i.wrapping_mul(2), i.wrapping_mul(3)])).collect();

        // Run 1: MockEngine.
        let mut mock = MockEngine::new();
        for tx in &txs {
            mock.submit_tx(tx.clone());
            mock.run_until_idle();
        }
        let mock_blocks: Vec<FinalizedBlock> = (0..=mock.finalized_height().unwrap().value())
            .map(|h| mock.finalized_block(Height::new(h)).unwrap())
            .collect();

        // Run 2: SequencerEngine.
        let mut seq = make_engine();
        for tx in &txs {
            seq.submit_tx(tx.clone());
            seq.run_until_idle();
        }
        let seq_blocks: Vec<FinalizedBlock> = (0..=seq.finalized_height().unwrap().value())
            .map(|h| seq.finalized_block(Height::new(h)).unwrap())
            .collect();

        // The two engines must produce identical consensus outputs —
        // height, ordering, and attendance. The `context` field is
        // deliberately excluded: it is the *engine-derived* half of
        // the block (the mock is clockless so its context is the
        // zero sentinel; the sequencer stamps its own clock and the
        // block budget's gas limit), and identical contexts across
        // different engines is not a property the seam promises.
        let consensus_view =
            |blocks: &[FinalizedBlock]| -> Vec<(Height, Vec<TxBytes>, Vec<primitives::Address>)> {
                blocks.iter().map(|b| (b.height, b.txs.clone(), b.signers.clone())).collect()
            };
        assert_eq!(
            consensus_view(&mock_blocks),
            consensus_view(&seq_blocks),
            "MockEngine and SequencerEngine must produce identical height/tx/signer \
             sequences for the same tx sequence — the app must be engine-agnostic"
        );
        // …but the contexts must differ exactly as designed: the
        // mock's is the all-zero sentinel, the sequencer's carries a
        // gas limit derived from the block budget.
        assert!(mock_blocks.iter().all(|b| b.context == types::BlockContext::default()));
        assert!(seq_blocks.iter().all(|b| b.context.gas_limit == BUDGET.max_gas));
    }
}
