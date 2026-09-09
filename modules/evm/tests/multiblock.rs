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
//!
//! Phase A: all transactions are now signed (secp256k1 recovery).
//! The sender is recovered from the signature, not trusted from the
//! envelope.

use crypto::secp;
use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::{Module, TxContext};
use primitives::{Address, Hash, Height};
use revm::primitives::{Bytes, U256};
use storage::Volatile;

/// Simple deploy bytecode: PUSH1 0x01, PUSH1 0x00, SSTORE, STOP.
/// Stores the value 1 at storage slot 0 of the new contract.
const DEPLOY_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];

/// Default gas limit for test transactions.
const GAS_LIMIT: u64 = 30_000_000;

/// A test keypair (private key + address).
struct TestKey {
    privkey: [u8; 32],
    addr: Address,
}

impl TestKey {
    fn new() -> Self {
        let (privkey, addr) = secp::generate_keypair_for_test();
        Self { privkey, addr: Address(addr.0) }
    }
}

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

/// A `TxContext` with a dummy sender (the EVM module recovers the
/// real sender from the signature).
fn dummy_ctx() -> TxContext {
    TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 }
}

/// Execute a single-tx block on the module: begin, handle, end.
fn exec_block(module: &EvmModule, height: u64, msg: &[u8]) {
    module.begin_block(Height::new(height));
    module.handle(&dummy_ctx(), msg).expect("handle must succeed");
    module.end_block(Height::new(height));
}

/// Fund the test key's account with a large balance.
fn fund(module: &EvmModule, key: &TestKey) {
    module.fund_account_for_test(&key.addr, u128::MAX);
}

/// Execute 100 blocks, each with one deploy tx. State root must
/// evolve (each block changes the state) and be deterministic
/// (re-running produces the same sequence).
#[test]
fn multi_block_100_blocks_state_root_evolution() {
    let key = TestKey::new();
    let module = EvmModule::new(1, 7);
    fund(&module, &key);
    let mut roots = Vec::with_capacity(100);

    for i in 0..100u64 {
        let msg = signed_deploy(&key.privkey, i);
        exec_block(&module, i, &msg);
        roots.push(module.state_root());
    }

    // State root must evolve: each block creates a new contract.
    for i in 1..100 {
        assert_ne!(roots[i], roots[i - 1], "state root must change at block {i}");
    }

    // Determinism: re-run with a fresh module and verify same roots.
    let module2 = EvmModule::new(1, 7);
    fund(&module2, &key);
    for i in 0..100u64 {
        let msg = signed_deploy(&key.privkey, i);
        exec_block(&module2, i, &msg);
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
    let key = TestKey::new();
    let module = EvmModule::new(1, 7);
    fund(&module, &key);

    for i in 0..10u64 {
        assert_eq!(module.nonce(&key.addr), i, "nonce before block {i}");
        let msg = signed_deploy(&key.privkey, i);
        exec_block(&module, i, &msg);
    }

    assert_eq!(module.nonce(&key.addr), 10, "nonce must be 10 after 10 deploys");
}

/// Gas used must be consistent for the same tx across blocks.
#[test]
fn multi_block_gas_accounting_per_block() {
    let key = TestKey::new();
    let module = EvmModule::new(1, 7);
    fund(&module, &key);
    let mut gas_used_per_block = Vec::with_capacity(10);

    for i in 0..10u64 {
        module.begin_block(Height::new(i));
        let msg = signed_deploy(&key.privkey, i);
        let events = module.handle(&dummy_ctx(), &msg).expect("handle");
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
    let key = TestKey::new();
    let backend = Box::new(Volatile::new());
    let module = EvmModule::with_storage(1, 7, backend);
    fund(&module, &key);

    // Execute 5 blocks of deploys.
    for i in 0..5u64 {
        let msg = signed_deploy(&key.privkey, i);
        exec_block(&module, i, &msg);
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
    assert_eq!(module2.nonce(&key.addr), 5, "nonce must be 5 after 5 deploys");
}

/// State must survive a "restart": execute blocks, drop the module,
/// create a new one with the same storage, and continue executing.
#[test]
fn state_persistence_survives_restart() {
    let key = TestKey::new();
    let backend = Box::new(Volatile::new());
    let module = EvmModule::with_storage(1, 7, backend);
    fund(&module, &key);

    // Execute 3 blocks.
    for i in 0..3u64 {
        let msg = signed_deploy(&key.privkey, i);
        exec_block(&module, i, &msg);
    }
    let root_before_restart = module.state_root();
    let nonce_before_restart = module.nonce(&key.addr);

    // Simulate restart: extract backend, drop module, create new one.
    let backend_ref = module.backend_for_test();
    drop(module);
    let module2 = EvmModule::with_storage(1, 7, backend_ref);

    // State must match what we had before the restart.
    assert_eq!(module2.state_root(), root_before_restart, "state root must survive restart");
    assert_eq!(module2.nonce(&key.addr), nonce_before_restart, "nonce must survive restart");

    // Continue executing — state must evolve from the loaded state.
    let msg = signed_deploy(&key.privkey, 3);
    exec_block(&module2, 3, &msg);
    let root_after_continue = module2.state_root();
    assert_ne!(
        root_after_continue, root_before_restart,
        "state must evolve after restart + new block"
    );
    assert_eq!(module2.nonce(&key.addr), 4, "nonce must be 4 after continuing");
}
