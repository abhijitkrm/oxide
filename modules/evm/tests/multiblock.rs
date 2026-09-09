//! Multi-block EVM execution + integrity tests (session 26).
//!
//! These tests verify the EVM module runs correctly across multiple
//! blocks: state root evolution, nonce progression, gas accounting,
//! and state persistence via `StorageBackend`. They complement the
//! single-block unit tests and the adversarial exploit suite.
//!
//! Reference: reth's block execution pipeline (see
//! `.devin/skills/evm-reference/SKILL.md`) — we verify the same
//! invariants reth guarantees: state evolves monotonically, nonces
//! increment per-tx, gas is accounted per-block, and state persists
//! across restarts.

use evm::EvmModule;
use executor::{Module, TxContext};
use primitives::{Address, Hash, Height};
use storage::Volatile;

/// Simple deploy bytecode: PUSH1 0x01, PUSH1 0x00, SSTORE, STOP.
/// Stores the value 1 at storage slot 0 of the new contract.
const DEPLOY_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];

/// Build an EVM deploy message: `to = zeros` (deploy) + calldata.
fn deploy_msg(calldata: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; 20]; // `to` = all zeros = deploy
    msg.extend_from_slice(calldata);
    msg
}

/// Build an EVM call message: `to = address` + calldata.
#[allow(dead_code)]
fn call_msg(to: Address, calldata: &[u8]) -> Vec<u8> {
    let mut msg = to.0.to_vec();
    msg.extend_from_slice(calldata);
    msg
}

/// A fixed sender address for test txs.
fn sender() -> Address {
    Address([0x11; 20])
}

/// Build a `TxContext` for a given nonce.
fn ctx(nonce: u64) -> TxContext {
    TxContext { sender: sender(), nonce, fee: 100 }
}

/// Execute a single-tx block on the module: begin, handle, end.
fn exec_block(module: &EvmModule, height: u64, msg: &[u8], nonce: u64) {
    module.begin_block(Height::new(height));
    module.handle(&ctx(nonce), msg).expect("handle must succeed");
    module.end_block(Height::new(height));
}

/// Execute 100 blocks, each with one deploy tx. State root must
/// evolve (each block changes the state) and be deterministic
/// (re-running produces the same sequence).
#[test]
fn multi_block_100_blocks_state_root_evolution() {
    let module = EvmModule::new(1, 7);
    let mut roots = Vec::with_capacity(100);

    for i in 0..100u64 {
        let msg = deploy_msg(DEPLOY_BYTECODE);
        exec_block(&module, i, &msg, i);
        roots.push(module.state_root());
    }

    // State root must evolve: each block creates a new contract.
    for i in 1..100 {
        assert_ne!(roots[i], roots[i - 1], "state root must change at block {i}");
    }

    // Determinism: re-run with a fresh module and verify same roots.
    let module2 = EvmModule::new(1, 7);
    for i in 0..100u64 {
        let msg = deploy_msg(DEPLOY_BYTECODE);
        exec_block(&module2, i, &msg, i);
        assert_eq!(
            module2.state_root(),
            roots[usize::try_from(i).expect("fits in usize")],
            "state root must be deterministic at block {i}"
        );
    }
}

/// Nonce must increment by 1 per deploy and persist across blocks.
#[test]
fn multi_block_nonce_progression_across_blocks() {
    let module = EvmModule::new(1, 7);

    for i in 0..10u64 {
        assert_eq!(module.nonce(&sender()), i, "nonce before block {i}");
        let msg = deploy_msg(DEPLOY_BYTECODE);
        exec_block(&module, i, &msg, i);
    }

    assert_eq!(module.nonce(&sender()), 10, "nonce must be 10 after 10 deploys");
}

/// Gas used must be consistent for the same tx across blocks.
#[test]
fn multi_block_gas_accounting_per_block() {
    let module = EvmModule::new(1, 7);
    let mut gas_used_per_block = Vec::with_capacity(10);

    for i in 0..10u64 {
        module.begin_block(Height::new(i));
        let events = module.handle(&ctx(i), &deploy_msg(DEPLOY_BYTECODE)).expect("handle");
        module.end_block(Height::new(i));

        // Extract gas_used from the event data: "gas_used=N status=..."
        let data_str = std::str::from_utf8(&events[0].data).expect("utf8");
        let gas_str = data_str
            .split("gas_used=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .expect("gas_used in event");
        let gas: u64 = gas_str.parse().expect("gas is a number");
        gas_used_per_block.push(gas);
    }

    // Same tx → same gas in every block (EVM determinism).
    let first = gas_used_per_block[0];
    for (i, &gas) in gas_used_per_block.iter().enumerate() {
        assert_eq!(gas, first, "gas must be consistent at block {i}");
    }
}

/// State persisted via `StorageBackend` must survive a round-trip:
/// execute blocks, flush, create a new module with the same backend,
/// and verify the state root matches.
#[test]
fn state_persistence_round_trip() {
    let backend = Box::new(Volatile::new());
    let module = EvmModule::with_storage(1, 7, backend);

    // Execute 5 blocks of deploys.
    for i in 0..5u64 {
        let msg = deploy_msg(DEPLOY_BYTECODE);
        exec_block(&module, i, &msg, i);
    }
    let root_after = module.state_root();
    assert_ne!(root_after, Hash::ZERO, "state root must be non-zero");

    // The backend was flushed in end_block. Extract it and create
    // a new module with the same backend.
    let backend_ref = module.backend_for_test();
    let module2 = EvmModule::with_storage(1, 7, backend_ref);

    // The new module's state root must match the first module's.
    assert_eq!(module2.state_root(), root_after, "state root must match after round-trip");

    // Nonces must also match.
    assert_eq!(module2.nonce(&sender()), 5, "nonce must be 5 after 5 deploys");
}

/// State must survive a "restart": execute blocks, drop the module,
/// create a new one with the same storage, and continue executing.
#[test]
fn state_persistence_survives_restart() {
    let backend = Box::new(Volatile::new());
    let module = EvmModule::with_storage(1, 7, backend);

    // Execute 3 blocks.
    for i in 0..3u64 {
        let msg = deploy_msg(DEPLOY_BYTECODE);
        exec_block(&module, i, &msg, i);
    }
    let root_before_restart = module.state_root();
    let nonce_before_restart = module.nonce(&sender());

    // Simulate restart: extract backend, drop module, create new one.
    let backend_ref = module.backend_for_test();
    drop(module);
    let module2 = EvmModule::with_storage(1, 7, backend_ref);

    // State must match what we had before the restart.
    assert_eq!(module2.state_root(), root_before_restart, "state root must survive restart");
    assert_eq!(module2.nonce(&sender()), nonce_before_restart, "nonce must survive restart");

    // Continue executing — state must evolve from the loaded state.
    let msg = deploy_msg(DEPLOY_BYTECODE);
    exec_block(&module2, 3, &msg, 3);
    let root_after_continue = module2.state_root();
    assert_ne!(
        root_after_continue, root_before_restart,
        "state must evolve after restart + new block"
    );
    assert_eq!(module2.nonce(&sender()), 4, "nonce must be 4 after continuing");
}
