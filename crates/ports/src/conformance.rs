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
//! - **Liveness** (rule implied by §3): every submitted transaction
//!   appears in exactly one finalized block. Pipelined engines (e.g.
//!   oxideBFT) may produce additional empty blocks to advance the
//!   pipeline — those are valid finalized blocks, just without txs.
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

use std::collections::HashSet;

use primitives::Hash;
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

/// Submit `txs` one per `run_until_idle`. Pipelined engines may need
/// multiple `run_until_idle` calls to flush the pipeline; the caller
/// drives one tx at a time to make the submission order explicit.
fn submit_and_run<E: ConsensusEngine>(engine: &mut E, txs: &[TxBytes]) {
    for tx in txs {
        engine.submit_tx(tx.clone());
        engine.run_until_idle();
    }
}

/// Collect all finalized blocks as a contiguous sequence from height 0.
/// Returns `(blocks, count)`. Stops at the first gap (height with no
/// block), which is the engine's `finalized_height` + 1.
fn collect_finalized<E: ConsensusEngine>(engine: &E) -> Vec<FinalizedBlock> {
    let mut blocks = Vec::new();
    let mut h = 0u64;
    while let Some(block) = engine.finalized_block(primitives::Height::new(h)) {
        assert_eq!(
            block.height,
            primitives::Height::new(h),
            "block at index {h} reports the wrong height"
        );
        blocks.push(block);
        h += 1;
    }
    blocks
}

/// Liveness + strictly-increasing, gap-free heights from genesis.
///
/// Liveness checks that every submitted tx appears in exactly one
/// finalized block. Pipelined engines may produce empty blocks to
/// advance the pipeline; those are valid but don't count toward the
/// tx-inclusion check.
fn liveness_and_sequence<E: ConsensusEngine>(make_engine: &impl Fn() -> E) {
    let mut engine = make_engine();
    let txs = sample_txs();
    submit_and_run(&mut engine, &txs);

    let blocks = collect_finalized(&engine);

    // Heights are a sequence: 0..N with no gaps (verified by
    // `collect_finalized` walking contiguous heights).
    assert!(!blocks.is_empty(), "no blocks were finalized — liveness violated");

    // Every submitted tx must appear in exactly one finalized block.
    // Collect all tx hashes from finalized blocks and check coverage.
    let mut seen_tx_hashes: HashSet<Hash> = HashSet::new();
    for block in &blocks {
        for tx in &block.txs {
            let tx_hash =
                crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, tx.as_bytes());
            assert!(
                seen_tx_hashes.insert(tx_hash),
                "tx appears in multiple finalized blocks — double-inclusion"
            );
        }
    }
    for tx in &txs {
        let tx_hash =
            crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, tx.as_bytes());
        assert!(
            seen_tx_hashes.contains(&tx_hash),
            "submitted tx not found in any finalized block — liveness violated"
        );
    }

    // `finalized_height` must be the highest contiguous height.
    let expected_final = primitives::Height::new((blocks.len() - 1) as u64);
    assert_eq!(
        engine.finalized_height(),
        Some(expected_final),
        "finalized_height must be the highest contiguous height"
    );
}

/// Re-running the engine does not alter already-finalized blocks.
fn finality_is_final<E: ConsensusEngine>(make_engine: &impl Fn() -> E) {
    let mut engine = make_engine();
    let txs = sample_txs();
    submit_and_run(&mut engine, &txs);

    // Snapshot the finalized blocks.
    let snapshot = collect_finalized(&engine);

    // Run again with no new txs — must be a no-op for finalization.
    engine.run_until_idle();
    engine.run_until_idle();

    let after = collect_finalized(&engine);
    assert_eq!(after, snapshot, "finalized blocks changed after a no-op run — finality violated");
}

/// Two independent engines, same tx sequence → byte-identical blocks.
fn determinism<E: ConsensusEngine>(make_engine: &impl Fn() -> E) {
    let txs = sample_txs();

    let mut first = make_engine();
    submit_and_run(&mut first, &txs);
    let first_blocks = collect_finalized(&first);

    let mut second = make_engine();
    submit_and_run(&mut second, &txs);
    let second_blocks = collect_finalized(&second);

    assert_eq!(
        first_blocks, second_blocks,
        "two runs with identical inputs must produce byte-identical finalized blocks; \
         the engine's ordering must be a pure function of the tx submission sequence"
    );
}
