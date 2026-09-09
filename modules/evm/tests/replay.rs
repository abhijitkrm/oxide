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
//!
//! Phase A: all transactions are now signed (secp256k1 recovery).

use crypto::secp;
use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::{Module, TxContext};
use primitives::{Address, Hash, Height};
use revm::primitives::{Bytes, U256};
use storage::Volatile;

/// Simple deploy bytecode: PUSH1 0x01, PUSH1 0x00, SSTORE, STOP.
const DEPLOY_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
const GAS_LIMIT: u64 = 30_000_000;

/// A test keypair.
fn test_key() -> ([u8; 32], Address) {
    let (privkey, addr) = secp::generate_keypair_for_test();
    (privkey, Address(addr.0))
}

/// Build a signed deploy tx.
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

fn dummy_ctx() -> TxContext {
    TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 }
}

/// Fund the test key's account with a large balance.
fn fund(module: &EvmModule, addr: &Address) {
    module.fund_account_for_test(addr, u128::MAX);
}

/// Execute a sequence of blocks and return the state root after each.
fn run_chain(module: &EvmModule, privkey: &[u8], addr: &Address, num_blocks: u64) -> Vec<Hash> {
    fund(module, addr);
    let mut roots = Vec::with_capacity(usize::try_from(num_blocks).expect("fits in usize"));
    for i in 0..num_blocks {
        module.begin_block(Height::new(i));
        let msg = signed_deploy(privkey, i);
        module.handle(&dummy_ctx(), &msg).expect("handle must succeed");
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
    let (privkey, addr) = test_key();
    let module_a = EvmModule::new(1, 7);
    let module_b = EvmModule::new(1, 7);

    let roots_a = run_chain(&module_a, &privkey, &addr, 20);
    let roots_b = run_chain(&module_b, &privkey, &addr, 20);

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
    let (privkey, addr) = test_key();

    // Phase 1: execute 10 blocks with storage, collecting roots.
    let backend = Box::new(Volatile::new());
    let module_storage = EvmModule::with_storage(1, 7, backend);
    let roots_storage = run_chain(&module_storage, &privkey, &addr, 10);

    // Phase 2: extract backend, create new module, continue blocks 10–20.
    // Note: we do NOT re-fund the reloaded module — it already has the
    // correct balance from the storage flush. Re-funding would set the
    // balance back to u128::MAX, diverging from the fresh chain.
    let backend_ref = module_storage.backend_for_test();
    let module_reloaded = EvmModule::with_storage(1, 7, backend_ref);

    let mut roots_reloaded = roots_storage.clone();
    for i in 10..20u64 {
        module_reloaded.begin_block(Height::new(i));
        let msg = signed_deploy(&privkey, i);
        module_reloaded.handle(&dummy_ctx(), &msg).expect("handle must succeed");
        module_reloaded.end_block(Height::new(i));
        roots_reloaded.push(module_reloaded.state_root());
    }

    // Phase 3: execute a fresh 20-block chain (no storage) and compare.
    let module_fresh = EvmModule::new(1, 7);
    let roots_fresh = run_chain(&module_fresh, &privkey, &addr, 20);

    // Every block's state root must match — the storage reload must
    // not change the state root trajectory.
    assert_eq!(
        roots_reloaded, roots_fresh,
        "storage-backed replay must match in-memory replay at every block"
    );
}
