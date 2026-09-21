//! Smoke tests for the `oxide-spammer` binary (audit session 24,
//! gap 2: binaries had zero tests).
//!
//! The spammer submits a batch of transactions and verifies they
//! finalize. This exercises the same `Node::assemble` +
//! batch-submit path the binary's `main()` uses.

use node::{ConsensusConfig, Node, NodeConfig};
use ports::AppInterface;
use primitives::Address;

/// Build a signed staking-delegate tx with a given nonce — devnet
/// identity 0 signs; `Address::ZERO` is genesis-registered by
/// `Node::assemble` and stays the delegate target.
fn build_staking_tx(nonce: u64) -> types::TxBytes {
    let payload = staking::msg::delegate(Address::ZERO, 1);
    devnet::txs::signed_tx(0, nonce, 100, framework::module_id::STAKING, &payload)
}

/// Submit 100 staking-delegate txs and verify at least one block
/// finalizes with a non-zero state root. This is the spammer's
/// core flow: batch submit -> run to completion -> verify.
#[test]
fn smoke_spammer_batch_100_txs() {
    // The default config — signed envelopes enforced, mirroring the
    // spammer binary's own wiring.
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 10_000,
        ..NodeConfig::default()
    };
    let mut node = Node::assemble(&config);
    // Devnet identity 0 pays the envelope fees.
    node.fund_evm_account(&devnet::txs::identity_addr(0), u128::MAX);

    for nonce in 0..100u64 {
        node.engine().submit_tx(build_staking_tx(nonce));
    }
    node.engine().run_until_idle();

    let height = node.engine().finalized_height();
    assert!(height.is_some(), "at least one block should finalize");

    let attestation = node.app().attest_state(height.unwrap()).expect("executed");
    assert_ne!(attestation.root, primitives::Hash::ZERO, "state root must be non-zero");
}
