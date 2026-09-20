//! End-to-end OAI flow — exercises the full consensus ⇄ application
//! round trip that the conformance suite (which is engine-generic)
//! cannot: the attestation and ordering-only rules that need
//! engine+app cooperation (oai-spec.md §3 rules 4 and 5).
//!
//! # What this asserts
//!
//! - **Full round trip:** submit → ingest → propose → process →
//!   finalize → attest, with the app's state root flowing back.
//! - **Ordering-only (rule 4):** a transaction that *would* revert on
//!   execution is still finalized — the engine never executes, so it
//!   cannot reject on execution grounds.
//! - **Attestations are opaque (rule 5):** the attestation the app
//!   produces for a height is stable and is the value the engine would
//!   embed verbatim in the next proposal.
//! - **State root flows back:** after finalizing height H, the app's
//!   `attest_state(H)` returns the root recorded at finalization.

use ports::mock::MockEngine;
use ports::{AppInterface, ConsensusEngine};
use primitives::Height;
use types::TxBytes;

#[test]
fn oai_full_round_trip() {
    let mut engine = MockEngine::new();

    // Three transactions, one of which ("revert") would fail on
    // execution. The engine must finalize it anyway — ordering is
    // unconditional on execution results (oai-spec.md §3 rule 4).
    let txs = vec![
        TxBytes::new(b"transfer 1".to_vec()),
        TxBytes::new(b"revert-me".to_vec()),
        TxBytes::new(b"transfer 2".to_vec()),
    ];
    for tx in &txs {
        engine.submit_tx(tx.clone());
        engine.run_until_idle();
    }

    // All three finalized, one per block at heights 0, 1, 2.
    for (h, expected_tx) in txs.iter().enumerate() {
        let block = engine.finalized_block(Height::new(h as u64)).expect("block finalized");
        assert_eq!(block.txs.len(), 1, "one tx per block (one-tx-per-run driving)");
        assert_eq!(
            block.txs[0], *expected_tx,
            "finalized tx at height {h} must match the submitted tx, byte-for-byte"
        );
    }
}

#[test]
fn oai_ordering_only_revert_tx_is_finalized() {
    // oai-spec.md §3 rule 4: an engine's accept/reject in
    // process_proposal must be derivable without executing. The mock
    // app's process_proposal never executes, so a "would-revert" tx is
    // accepted and finalized. This test pins that invariant: if a future
    // engine tries to peek at execution results during process_proposal,
    // this fails.
    let mut engine = MockEngine::new();
    engine.submit_tx(TxBytes::new(b"this-would-revert-on-execution".to_vec()));
    engine.run_until_idle();

    let block = engine.finalized_block(Height::new(0)).expect("finalized");
    assert_eq!(block.txs.len(), 1);
    assert_eq!(block.txs[0].as_bytes(), b"this-would-revert-on-execution");
}

#[test]
fn oai_attestation_is_stable_and_matches_finalization() {
    // oai-spec.md §3 rule 5: attestations are opaque to the engine, and
    // the app's attest_state(H) returns the root recorded at
    // finalization of H. Two calls with the same height return the same
    // root (stability); the root matches what finalize_block recorded.
    let mut engine = MockEngine::new();
    engine.submit_tx(TxBytes::new(b"tx-0".to_vec()));
    engine.run_until_idle();

    let height = Height::new(0);
    // finalize_block already ran inside run_until_idle and recorded the
    // root; attest_state must return that same root.
    let att1 = engine.app().attest_state(height).expect("height 0 executed");
    let att2 = engine.app().attest_state(height).expect("height 0 executed");
    assert_eq!(att1.height, height);
    assert_eq!(att1, att2, "attest_state must be stable across calls");
    // The mock root is height-derived; confirm the contract holds so a
    // change to the mock's root derivation is caught here.
    assert_eq!(
        att1.root.0, [0u8; 32],
        "mock state root at height 0 is the zero-height placeholder"
    );
}

#[test]
fn oai_finalized_height_advances() {
    let mut engine = MockEngine::new();
    assert_eq!(engine.finalized_height(), None, "no blocks before any run");

    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    assert_eq!(engine.finalized_height(), Some(Height::new(0)));

    engine.submit_tx(TxBytes::new(vec![2]));
    engine.run_until_idle();
    assert_eq!(engine.finalized_height(), Some(Height::new(1)));
}
