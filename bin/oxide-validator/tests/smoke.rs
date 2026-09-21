//! Smoke tests for the `oxide-validator` binary (audit session 24,
//! gap 2: binaries had zero tests).
//!
//! These tests exercise the same `Node::assemble` +
//! `AppInterface` path the binary's `main()` uses, verifying the
//! stack assembles, a transaction finalizes, and the state root is
//! non-zero — under both engine configs.

use node::{ConsensusConfig, Node, NodeConfig};
use ports::AppInterface;
use primitives::Address;

/// Build a *signed* staking-delegate tx in the v1 envelope format
/// the binary now requires by default (`[sender][nonce][fee]
/// [module_id|0x80][sig:65][payload]`). `Address::ZERO` is
/// genesis-registered by `Node::assemble`; the sender is the signing
/// key's derived address and must be funded before the delegate can
/// bond.
fn build_signed_staking_tx(privkey: &[u8], sender: Address, chain_id: u64) -> types::TxBytes {
    let payload = staking::msg::delegate(Address::ZERO, 100);
    let nonce = 0u64;
    let fee = 100u64;
    let sig = crypto::eip712::sign_tx(
        privkey,
        chain_id,
        &sender,
        nonce,
        fee,
        framework::module_id::STAKING,
        &payload,
    )
    .expect("test key must sign");
    let mut bytes = Vec::with_capacity(36 + 1 + 65 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::STAKING | 0x80);
    bytes.extend_from_slice(&sig.sig);
    bytes.push(sig.recid.as_u8());
    bytes.extend_from_slice(&payload);
    types::TxBytes::new(bytes)
}

/// The validator stack assembles under the sequencer engine and is
/// ready to accept transactions (no blocks finalized yet).
#[test]
fn smoke_assemble_sequencer() {
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 10_000,
        ..NodeConfig::default()
    };
    let mut node = Node::assemble(&config);
    assert!(node.engine().finalized_height().is_none(), "no blocks before any tx");
}

/// The full submit -> finalize -> state-root pipeline works under the
/// sequencer engine: a staking delegate finalizes in one block and the
/// state root is non-zero.
#[test]
fn smoke_submit_finalize_state_root_sequencer() {
    let config = NodeConfig::default();
    let mut node = Node::assemble(&config);

    // The default node requires signed envelopes — the tx is signed
    // and its sender funded, mirroring a real submitter.
    let (privkey, sender) = crypto::secp::generate_keypair_for_test();
    node.fund_evm_account(&sender, 1_000_000_000_000_000_000);
    node.engine().submit_tx(build_signed_staking_tx(&privkey, sender, config.chain_id));
    node.engine().run_until_idle();

    let height = node.engine().finalized_height();
    assert!(height.is_some(), "a block should be finalized");

    let attestation = node.app().attest_state(height.unwrap()).expect("executed");
    assert_ne!(attestation.root, primitives::Hash::ZERO, "state root must be non-zero");
}

/// The same pipeline works under oxideBFT (single-validator mode):
/// the engine self-proposes, self-votes, and commits via the 2-chain
/// rule. This proves the binary's `--engine oxideBFT` path works.
#[test]
fn smoke_submit_finalize_state_root_oxidebft() {
    let config = NodeConfig {
        consensus: ConsensusConfig::OxideBft,
        max_mempool_entries: 10_000,
        ..NodeConfig::default()
    };
    let mut node = Node::assemble(&config);

    let (privkey, sender) = crypto::secp::generate_keypair_for_test();
    node.fund_evm_account(&sender, 1_000_000_000_000_000_000);
    node.engine().submit_tx(build_signed_staking_tx(&privkey, sender, config.chain_id));
    node.engine().run_until_idle();

    let height = node.engine().finalized_height();
    assert!(height.is_some(), "oxideBFT should finalize a block");

    let attestation = node.app().attest_state(height.unwrap()).expect("executed");
    assert_ne!(attestation.root, primitives::Hash::ZERO, "state root must be non-zero");
}
