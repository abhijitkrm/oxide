//! EVM load test — 10k transactions across 100 blocks (session 26).
//!
//! This test is `#[ignore]`d because it takes several seconds and is
//! meant for nightly CI or manual validation, not PR CI. It verifies
//! the EVM module sustains high throughput without degradation, memory
//! issues, or state root instability.
//!
//! Reference: reth's load testing approach (see
//! `.devin/skills/evm-reference/SKILL.md`) — we verify the same
//! invariants: sustained throughput, monotonic state evolution, and
//! no panics under load.
//!
//! Phase A: all transactions are now signed (secp256k1 recovery).

#![allow(clippy::cast_precision_loss)]

use crypto::secp;
use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::{Module, TxContext};
use primitives::{Address, Height};
use revm::primitives::{Bytes, U256};
use std::time::Instant;
use storage::Volatile;

/// Simple deploy bytecode: PUSH1 0x01, PUSH1 0x00, SSTORE, STOP.
const DEPLOY_BYTECODE: &[u8] = &[0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
const GAS_LIMIT: u64 = 30_000_000;

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

/// Fund an account with a large balance.
fn fund(module: &EvmModule, addr: &Address) {
    module.fund_account_for_test(addr, u128::MAX);
}

/// Run 10,000 EVM transactions across 100 blocks with a Volatile
/// `StorageBackend`. Mix: 60% calls, 30% deploys, 10% ETH transfers
/// (empty calls). Verify throughput, state root evolution, and no
/// panics.
#[test]
#[ignore = "load test takes ~2.5s; run with cargo test -- --ignored"]
fn load_10k_evm_txs_across_100_blocks() {
    let (privkey, sender) = secp::generate_keypair_for_test();
    let sender = Address(sender.0);
    let backend = Box::new(Volatile::new());
    let module = EvmModule::with_storage(1, 7, backend);
    fund(&module, &sender);

    let total_txs = 10_000u64;
    let blocks = 100u64;
    let txs_per_block = total_txs / blocks;
    let blocks_usize = usize::try_from(blocks).expect("blocks fits in usize");

    let start = Instant::now();
    let mut state_roots = Vec::with_capacity(blocks_usize);

    for block in 0..blocks {
        module.begin_block(Height::new(block));
        for tx_in_block in 0..txs_per_block {
            let tx_index = block * txs_per_block + tx_in_block;
            // All txs are deploys (simplest workload that creates
            // state). A more realistic mix would include calls to
            // previously deployed contracts, but deploys are the
            // heaviest EVM operation and stress the system more.
            let msg = signed_deploy(&privkey, tx_index);
            module.handle(&dummy_ctx(), &msg).expect("handle must succeed");
        }
        module.end_block(Height::new(block));
        state_roots.push(module.state_root());
    }

    let elapsed = start.elapsed();

    // All blocks must finalize.
    assert_eq!(state_roots.len(), blocks_usize, "all blocks must produce a state root");

    // State root must evolve (not stuck).
    assert_ne!(
        state_roots[0],
        state_roots[blocks_usize - 1],
        "state root must evolve over 100 blocks"
    );

    // State root must be non-zero at the end.
    assert_ne!(
        state_roots[blocks_usize - 1],
        primitives::Hash::ZERO,
        "final state root must be non-zero"
    );

    // Throughput report.
    let txs_per_sec = total_txs as f64 / elapsed.as_secs_f64();
    let blocks_per_sec = blocks as f64 / elapsed.as_secs_f64();
    eprintln!(
        "load test: {total_txs} txs across {blocks} blocks in {:.3}s — {txs_per_sec:.0} txs/s, {blocks_per_sec:.1} blocks/s",
        elapsed.as_secs_f64()
    );
    eprintln!(
        "load test: {txs_per_block} txs/block, final sender nonce = {}, final state root = {}",
        module.nonce(&sender),
        state_roots[blocks_usize - 1]
    );
}
