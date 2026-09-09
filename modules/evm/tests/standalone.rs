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

#![allow(clippy::cast_precision_loss)]

use evm::EvmModule;
use executor::Executor;
use ports::AppInterface;
use primitives::{Address, Hash, Height};
use std::sync::Arc;
use storage::Volatile;
use types::{BlockBudget, FinalizedBlock, TxBytes};

/// Simple deploy bytecode: PUSH1 0x01, PUSH1 0x00, SSTORE, STOP.
const DEPLOY_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];

/// A fixed sender address.
fn sender() -> Address {
    Address([0x11; 20])
}

/// Build a tx in the v0 envelope format:
/// `[sender: 20B][nonce: 8B LE][fee: 8B LE][module_id: 1B][payload]`.
///
/// The EVM module's payload is `[to: 20B][calldata: ...]`.
fn make_evm_tx(nonce: u64, to: [u8; 20], calldata: &[u8]) -> TxBytes {
    let mut bytes = Vec::with_capacity(36 + 1 + 20 + calldata.len());
    bytes.extend_from_slice(&sender().0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&100u64.to_le_bytes());
    bytes.push(framework::module_id::EVM);
    bytes.extend_from_slice(&to);
    bytes.extend_from_slice(calldata);
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
    // Create an EVM module with durable storage.
    let backend = Box::new(Volatile::new());
    let evm = EvmModule::with_storage(1, 7, backend);

    // Register ONLY the EVM module — no bank, staking, core, or
    // trading modules. This proves the EVM can run standalone.
    let mut executor = Executor::new(10_000);
    executor.register_module(Arc::new(evm));

    let num_blocks = 50u64;
    let num_blocks_usize = usize::try_from(num_blocks).expect("fits in usize");
    let mut roots = Vec::with_capacity(num_blocks_usize);

    for block in 0..num_blocks {
        // Build an EVM deploy tx: `to = zeros` (deploy) + bytecode.
        let tx = make_evm_tx(block, [0u8; 20], DEPLOY_BYTECODE);
        executor.ingest_tx(tx);

        // Prepare and finalize the block.
        let budget = BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
        let proposal = executor.prepare_proposal(&budget);
        assert!(!proposal.txs.is_empty(), "block {block} proposal must contain the tx");
        let finalized = FinalizedBlock { height: Height::new(block), txs: proposal.txs };
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
