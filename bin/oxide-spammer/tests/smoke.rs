//! Smoke tests for the `oxide-spammer` binary (audit session 24,
//! gap 2: binaries had zero tests).
//!
//! The spammer submits a batch of transactions and verifies they
//! finalize. This exercises the same `Node::assemble` +
//! batch-submit path the binary's `main()` uses.

use node::{ConsensusConfig, Node, NodeConfig};
use ports::AppInterface;
use primitives::Address;

/// Build a staking-delegate tx with a given nonce.
/// `Address::ZERO` is genesis-registered by `Node::assemble`.
fn build_staking_tx(nonce: u64) -> types::TxBytes {
    let payload = staking::msg::delegate(Address::ZERO, 1);
    let sender = Address([0u8; 20]);
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::STAKING);
    bytes.extend_from_slice(&payload);
    types::TxBytes::new(bytes)
}

/// Submit 100 staking-delegate txs and verify at least one block
/// finalizes with a non-zero state root. This is the spammer's
/// core flow: batch submit -> run to completion -> verify.
#[test]
fn smoke_spammer_batch_100_txs() {
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 10_000,
        ..NodeConfig::default()
    };
    let mut node = Node::assemble(&config);

    for nonce in 0..100u64 {
        node.engine().submit_tx(build_staking_tx(nonce));
    }
    node.engine().run_until_idle();

    let height = node.engine().finalized_height();
    assert!(height.is_some(), "at least one block should finalize");

    let attestation = node.app().attest_state(height.unwrap());
    assert_ne!(attestation.root, primitives::Hash::ZERO, "state root must be non-zero");
}
