//! Adapter conformance suite — the contract every `ConsensusEngine`
//! must honor (oai-spec.md §3).
//!
//! # How engines use this
//!
//! An engine's test suite calls [`assert_conformance`] with a factory
//! that constructs a fresh, isolated engine. The suite exercises the
//! behavioral rules against that engine. `MockEngine` passes it
//! (see `tests/conformance.rs`); oxideBFT will pass it before it ships.
//!
//! # What is asserted
//!
//! - **Liveness** (rule implied by §3): submitted transactions become
//!   finalized blocks.
//! - **Heights are a sequence** (§3 rule 2): finalized heights are
//!   strictly increasing from genesis (0) with no gaps.
//! - **Finality is final** (§3 rule 1): re-running the engine does not
//!   alter or add finalized blocks at already-finalized heights.
//! - **Determinism** (§3 rule 3): two engines fed the same tx submission
//!   sequence produce byte-identical finalized blocks.
//!
//! Rules 4 (ordering-only) and 5 (attestations opaque) are exercised
//! in the end-to-end OAI test (`tests/oai_e2e.rs`), which needs
//! engine+app cooperation that a generic engine factory cannot provide.

use primitives::Height;
use types::{FinalizedBlock, TxBytes};

use crate::ConsensusEngine;

/// Run the full conformance suite against an engine produced by
/// `make_engine`.
///
/// `make_engine` must construct a **fresh, isolated** engine each call
/// (fresh app, fresh state) — the determinism assertion compares two
/// independent runs, so any shared state between them would defeat it.
pub fn assert_conformance<E: ConsensusEngine>(make_engine: impl Fn() -> E) {
    liveness_and_sequence(&make_engine);
    finality_is_final(&make_engine);
    determinism(&make_engine);
}

/// A fixed, deterministic transaction sequence used across runs so the
/// determinism assertion compares identical inputs.
fn sample_txs() -> Vec<TxBytes> {
    (0..3u8).map(|i| TxBytes::new(vec![i, i.wrapping_mul(2), i.wrapping_mul(3)])).collect()
}

/// Submit `txs` one per `run_until_idle`, finalizing one block per tx.
/// Driving one-tx-per-run makes the height sequence explicit and
/// independent of the engine's block-packing policy.
fn submit_and_run<E: ConsensusEngine>(engine: &mut E, txs: &[TxBytes]) {
    for tx in txs {
        engine.submit_tx(tx.clone());
        engine.run_until_idle();
    }
}

/// Liveness + strictly-increasing, gap-free heights from genesis.
fn liveness_and_sequence<E: ConsensusEngine>(make_engine: &impl Fn() -> E) {
    let mut engine = make_engine();
    let txs = sample_txs();
    submit_and_run(&mut engine, &txs);

    // Every tx must be finalized somewhere; with one-tx-per-run we
    // expect heights 0..txs.len(), each block containing one tx.
    let mut expected_height = 0u64;
    while let Some(block) = engine.finalized_block(Height::new(expected_height)) {
        assert_eq!(
            block.height,
            Height::new(expected_height),
            "block at index {expected_height} reports the wrong height"
        );
        // One tx per run → one tx per block (for engines that honor the
        // one-tx-per-run driving contract; MockEngine does).
        assert!(
            !block.txs.is_empty(),
            "finalized block at height {expected_height} has no transactions"
        );
        expected_height += 1;
    }
    let finalized_count =
        usize::try_from(expected_height).expect("a finalized-height count always fits usize");
    assert_eq!(
        finalized_count,
        txs.len(),
        "expected {} finalized blocks (one per submitted tx), got {expected_height}",
        txs.len()
    );
    // Heights are a sequence: 0..N with no gaps (verified by the loop
    // above walking contiguous heights until the first missing one).
    assert_eq!(
        engine.finalized_height(),
        Some(Height::new((txs.len() - 1) as u64)),
        "finalized_height must be the highest contiguous height"
    );
}

/// Re-running the engine does not alter already-finalized blocks.
fn finality_is_final<E: ConsensusEngine>(make_engine: &impl Fn() -> E) {
    let mut engine = make_engine();
    let txs = sample_txs();
    submit_and_run(&mut engine, &txs);

    // Snapshot the finalized blocks.
    let snapshot: Vec<FinalizedBlock> = (0..txs.len() as u64)
        .map(|h| engine.finalized_block(Height::new(h)).expect("finalized"))
        .collect();

    // Run again with no new txs — must be a no-op for finalization.
    engine.run_until_idle();
    engine.run_until_idle();

    for (h, original) in snapshot.iter().enumerate() {
        let after = engine.finalized_block(Height::new(h as u64)).expect("block must still exist");
        assert_eq!(
            after, *original,
            "finalized block at height {h} changed after a no-op run — finality violated"
        );
    }
}

/// Two independent engines, same tx sequence → byte-identical blocks.
fn determinism<E: ConsensusEngine>(make_engine: &impl Fn() -> E) {
    let txs = sample_txs();

    let mut first = make_engine();
    submit_and_run(&mut first, &txs);
    let first_blocks: Vec<FinalizedBlock> = (0..txs.len() as u64)
        .map(|h| first.finalized_block(Height::new(h)).expect("finalized"))
        .collect();

    let mut second = make_engine();
    submit_and_run(&mut second, &txs);
    let second_blocks: Vec<FinalizedBlock> = (0..txs.len() as u64)
        .map(|h| second.finalized_block(Height::new(h)).expect("finalized"))
        .collect();

    assert_eq!(
        first_blocks, second_blocks,
        "two runs with identical inputs must produce byte-identical finalized blocks; \
         the engine's ordering must be a pure function of the tx submission sequence"
    );
}
