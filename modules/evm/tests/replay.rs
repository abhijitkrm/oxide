//! EVM replay integrity tests (session 26).
//!
//! These tests verify that replaying the same sequence of blocks
//! produces identical state roots at every block — the core consensus
//! guarantee. They also verify that storage-backed replay (loading
//! state from `StorageBackend` and continuing) produces the same
//! roots as in-memory replay.
//!
//! Reference: reth's replay integrity guarantees (see
//! `.devin/skills/evm-reference/SKILL.md`) — same invariant: given
//! the same blocks, every node must arrive at the same state root.

use evm::EvmModule;
use executor::{Module, TxContext};
use primitives::{Address, Hash, Height};
use storage::Volatile;

/// Simple deploy bytecode: PUSH1 0x01, PUSH1 0x00, SSTORE, STOP.
const DEPLOY_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];

/// Build an EVM deploy message.
fn deploy_msg(calldata: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; 20];
    msg.extend_from_slice(calldata);
    msg
}

/// A fixed sender address.
fn sender() -> Address {
    Address([0x11; 20])
}

/// Execute a sequence of blocks and return the state root after each.
fn run_chain(module: &EvmModule, num_blocks: u64) -> Vec<Hash> {
    let mut roots = Vec::with_capacity(usize::try_from(num_blocks).expect("fits in usize"));
    for i in 0..num_blocks {
        module.begin_block(Height::new(i));
        let ctx = TxContext { sender: sender(), nonce: i, fee: 100 };
        let msg = deploy_msg(DEPLOY_BYTECODE);
        module.handle(&ctx, &msg).expect("handle must succeed");
        module.end_block(Height::new(i));
        roots.push(module.state_root());
    }
    roots
}

/// Replay 20 blocks and verify identical state roots at every block.
///
/// Two independent modules execute the same 20 blocks. The state
/// root after each block must be identical — this is the
/// determinism guarantee that makes consensus possible.
#[test]
fn replay_produces_identical_state_roots() {
    let module_a = EvmModule::new(1, 7);
    let module_b = EvmModule::new(1, 7);

    let roots_a = run_chain(&module_a, 20);
    let roots_b = run_chain(&module_b, 20);

    assert_eq!(roots_a.len(), 20, "must produce 20 roots");
    assert_eq!(roots_a, roots_b, "replay must produce identical state roots at every block");

    // State root must evolve (not stuck at genesis).
    for i in 1..20 {
        assert_ne!(roots_a[i], roots_a[i - 1], "state root must evolve at block {i}");
    }
}

/// Storage-backed replay: execute 10 blocks, flush to storage, create
/// a new module with the same storage, and replay blocks 10–20. Then
/// execute a fresh 20-block chain and verify the roots match at every
/// block — including the ones after the storage reload.
#[test]
fn storage_backed_replay_matches_in_memory_replay() {
    // Phase 1: execute 10 blocks with storage, collecting roots.
    let backend = Box::new(Volatile::new());
    let module_storage = EvmModule::with_storage(1, 7, backend);
    let roots_storage = run_chain(&module_storage, 10);

    // Phase 2: extract backend, create new module, continue blocks 10–20.
    let backend_ref = module_storage.backend_for_test();
    let module_reloaded = EvmModule::with_storage(1, 7, backend_ref);

    let mut roots_reloaded = roots_storage.clone();
    for i in 10..20u64 {
        module_reloaded.begin_block(Height::new(i));
        let ctx = TxContext { sender: sender(), nonce: i, fee: 100 };
        let msg = deploy_msg(DEPLOY_BYTECODE);
        module_reloaded.handle(&ctx, &msg).expect("handle must succeed");
        module_reloaded.end_block(Height::new(i));
        roots_reloaded.push(module_reloaded.state_root());
    }

    // Phase 3: execute a fresh 20-block chain (no storage) and compare.
    let module_fresh = EvmModule::new(1, 7);
    let roots_fresh = run_chain(&module_fresh, 20);

    // Every block's state root must match — the storage reload must
    // not change the state root trajectory.
    assert_eq!(
        roots_reloaded, roots_fresh,
        "storage-backed replay must match in-memory replay at every block"
    );
}
