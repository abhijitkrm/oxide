//! Smoke tests for the `oxide-validator` binary (audit session 24,
//! gap 2: binaries had zero tests).
//!
//! These tests exercise the same `DevnetNode::assemble` +
//! `AppInterface` path the binary's `main()` uses, verifying the
//! stack assembles, a transaction finalizes, and the state root is
//! non-zero — under both engine configs.

use devnet::{ConsensusConfig, DevnetNode, NodeConfig};
use ports::AppInterface;
use primitives::Address;

/// Build a bank-transfer tx in the same wire format the binary uses.
fn build_bank_tx(nonce: u64) -> types::TxBytes {
    let to = Address([2u8; 20]);
    let payload = bank::msg::transfer(to, 100);
    let sender = Address([0u8; 20]);
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::BANK);
    bytes.extend_from_slice(&payload);
    types::TxBytes::new(bytes)
}

/// The validator stack assembles under the sequencer engine and is
/// ready to accept transactions (no blocks finalized yet).
#[test]
fn smoke_assemble_sequencer() {
    let config = NodeConfig { consensus: ConsensusConfig::Sequencer, max_mempool_entries: 10_000 };
    let mut node = DevnetNode::assemble(&config);
    assert!(node.engine().finalized_height().is_none(), "no blocks before any tx");
}

/// The full submit → finalize → state-root pipeline works under the
/// sequencer engine: a bank transfer finalizes in one block and the
/// state root is non-zero.
#[test]
fn smoke_submit_finalize_state_root_sequencer() {
    let config = NodeConfig::default();
    let mut node = DevnetNode::assemble(&config);

    node.engine().submit_tx(build_bank_tx(0));
    node.engine().run_until_idle();

    let height = node.engine().finalized_height();
    assert!(height.is_some(), "a block should be finalized");

    let attestation = node.app().attest_state(height.unwrap());
    assert_ne!(attestation.root, primitives::Hash::ZERO, "state root must be non-zero");
}

/// The same pipeline works under oxideBFT (single-validator mode):
/// the engine self-proposes, self-votes, and commits via the 2-chain
/// rule. This proves the binary's `--engine oxideBFT` path works.
#[test]
fn smoke_submit_finalize_state_root_oxidebft() {
    let config = NodeConfig { consensus: ConsensusConfig::OxideBft, max_mempool_entries: 10_000 };
    let mut node = DevnetNode::assemble(&config);

    node.engine().submit_tx(build_bank_tx(0));
    node.engine().run_until_idle();

    let height = node.engine().finalized_height();
    assert!(height.is_some(), "oxideBFT should finalize a block");

    let attestation = node.app().attest_state(height.unwrap());
    assert_ne!(attestation.root, primitives::Hash::ZERO, "state root must be non-zero");
}
