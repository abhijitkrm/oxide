//! Standalone EVM-only chain test (session 26).
//!
//! This test verifies the EVM module can operate as the sole
//! application state machine — no bank, staking, core, or trading
//! modules. It registers only the EVM module in an executor, runs
//! 50 finalized blocks, and verifies nonzero, evolving state roots.
//!
//! This is the "EVM as a standalone blockchain" validation: if the
//! EVM module can produce correct state roots across 50 blocks
//! without any native modules, it can serve as the chain's sole
//! application layer.
//!
//! Reference: reth's standalone execution mode (see
//! `.devin/skills/evm-reference/SKILL.md`) — same concept: the EVM
//! execution engine should produce correct state roots without
//! depending on external modules.
//!
//! Phase A: all transactions are now signed (secp256k1 recovery).
//! The tx envelope format is: `[sender: 20B][nonce: 8B LE][fee: 8B LE]
//! [module_id: 1B][signed_evm_tx: ...]`. The EVM module recovers the
//! sender from the signature, ignoring the envelope's sender field.

#![allow(clippy::cast_precision_loss)]

use crypto::secp;
use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::Executor;
use ports::AppInterface;
use primitives::{Address, Hash, Height};
use revm::primitives::{Bytes, U256};
use std::sync::Arc;
use storage::Volatile;
use types::{BlockBudget, FinalizedBlock, TxBytes};

/// Simple deploy bytecode: PUSH1 0x01, PUSH1 0x00, SSTORE, STOP.
const DEPLOY_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
const GAS_LIMIT: u64 = 30_000_000;

/// Build a signed deploy tx (RLP-encoded).
fn signed_deploy(privkey: &[u8], nonce: u64) -> Vec<u8> {
    let tx = TxLegacy {
        fields: TxFields {
            nonce,
            gas_limit: GAS_LIMIT,
            to: TxKind::Create,
            value: U256::ZERO,
            data: Bytes::copy_from_slice(DEPLOY_BYTECODE),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    SignedTx::sign_legacy(tx, privkey).expect("sign must succeed").encode_to_bytes()
}

/// Build a tx in the v0 envelope format:
/// `[sender: 20B][nonce: 8B LE][fee: 8B LE][module_id: 1B][payload]`.
///
/// The EVM module's payload is a signed EVM transaction (RLP-encoded).
/// The envelope's sender field is ignored by the EVM module — it
/// recovers the sender from the signature.
fn make_evm_tx(envelope_sender: Address, nonce: u64, signed_evm_tx: &[u8]) -> TxBytes {
    let mut bytes = Vec::with_capacity(36 + 1 + signed_evm_tx.len());
    bytes.extend_from_slice(&envelope_sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&100u64.to_le_bytes());
    bytes.push(framework::module_id::EVM);
    bytes.extend_from_slice(signed_evm_tx);
    TxBytes::new(bytes)
}

/// Run 50 blocks of EVM-only execution via the `Executor`. This
/// verifies the EVM integrates correctly with the block execution
/// pipeline as the sole module.
///
/// The test is `#[ignore]`d because it takes >1s and is meant for
/// nightly CI or manual validation.
#[test]
#[ignore = "standalone chain test takes >1s; run with cargo test -- --ignored"]
fn standalone_evm_only_50_blocks() {
    // Generate a test keypair for signing transactions.
    let (privkey, sender) = secp::generate_keypair_for_test();
    let sender_addr = Address(sender.0);

    // Create an EVM module with durable storage.
    let backend = Box::new(Volatile::new());
    let evm = EvmModule::with_storage(1, 7, backend);
    evm.fund_account_for_test(&sender_addr, u128::MAX);

    // Register ONLY the EVM module — no bank, staking, core, or
    // trading modules. This proves the EVM can run standalone.
    let mut executor = Executor::new(10_000);
    executor.register_module(Arc::new(evm));

    let num_blocks = 50u64;
    let num_blocks_usize = usize::try_from(num_blocks).expect("fits in usize");
    let mut roots = Vec::with_capacity(num_blocks_usize);

    for block in 0..num_blocks {
        // Build a signed EVM deploy tx.
        let signed = signed_deploy(&privkey, block);
        // Wrap in the v0 envelope. The envelope sender is a dummy —
        // the EVM module recovers the real sender from the signature.
        let tx = make_evm_tx(Address([0u8; 20]), block, &signed);
        executor.ingest_tx(tx);

        // Prepare and finalize the block.
        let budget = BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert!(!proposal.txs.is_empty(), "block {block} proposal must contain the tx");
        let finalized =
            FinalizedBlock { height: Height::new(block), txs: proposal.txs, signers: Vec::new() };
        executor.finalize_block(&finalized);

        let attestation = executor.attest_state(Height::new(block));
        roots.push(attestation.root);
    }

    // All blocks must finalize with a state root.
    assert_eq!(roots.len(), num_blocks_usize, "all 50 blocks must produce a state root");

    // Block 0 state root must be nonzero — the EVM created a contract.
    assert_ne!(roots[0], Hash::ZERO, "block 0 state root must be nonzero (EVM created state)");

    // State root must evolve across blocks.
    let mut changes = 0;
    for i in 1..num_blocks_usize {
        if roots[i] != roots[i - 1] {
            changes += 1;
        }
    }
    assert!(
        changes > num_blocks_usize / 2,
        "state root must evolve in >50% of blocks (got {changes}/{num_blocks})"
    );

    // Final state root must be nonzero.
    assert_ne!(roots[num_blocks_usize - 1], Hash::ZERO, "final state root must be nonzero");

    eprintln!(
        "standalone EVM: 50 blocks finalized, {changes}/{num_blocks} state root changes, final root = {}",
        roots[num_blocks_usize - 1]
    );
}
