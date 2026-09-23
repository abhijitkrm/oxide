#![no_main]
//! Fuzz target: differential equivalence of the EVM's execution
//! paths.
//!
//! For the same transaction batch, serial `handle`, serial
//! `handle_batch`, and `handle_batch_parallel` must produce the
//! identical consensus state root — a validator must not be able to
//! influence its state by choosing an execution engine. The
//! generated workload is contract-heavy on purpose: contracts carry
//! pre-existing storage and generated calls read, write, and zero
//! shared slots, which is exactly where the speculative merge can
//! diverge (regression: a validated merge used to replace whole
//! `DbAccount`s, erasing storage the tx had not loaded).
//!
//! Input format: a byte stream parsed into 10-byte tx records —
//! `[sender:1][op:1][arg:8]`. `sender % 4` picks a deterministic
//! identity key; `op % 4` picks the operation:
//!   0 → transfer `arg` wei to a fixed EOA recipient
//!   1 → WRITER call, SSTORE(slot = arg[0], value = arg[1])
//!   2 → zero-calldata call to contract `arg[0] % N_CONTRACTS`
//!   3 → CREATE minimal init code
//! Nonces are assigned sequentially per sender.

use alloy_primitives::{Bytes, U256};
use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::{Module, TxContext};
use primitives::{Address, Height};

/// SSTORE(slot = calldata[0..32], value = calldata[32..64]); STOP.
const WRITER: &[u8] = &[0x60, 0x20, 0x35, 0x60, 0x00, 0x35, 0x55, 0x00];
/// SSTORE(4, SLOAD(1) + 1); STOP — read/write split in one tx.
const READER_WRITER: &[u8] = &[0x60, 0x01, 0x54, 0x60, 0x01, 0x01, 0x60, 0x04, 0x55, 0x00];
/// SSTORE(2, 0); STOP — zeroes a pre-existing slot.
const ZEROER: &[u8] = &[0x60, 0x00, 0x60, 0x02, 0x55, 0x00];
/// REVERT(0, 0) — reverts after paying gas.
const REVERTER: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0xfd];
/// SELFDESTRUCT(0xBB..) — pre-existing contract: post-Cancun this
/// moves the balance but keeps the account and its storage.
const SELFDESTRUCTER: &[u8] = &[
    0x73, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xff,
];

/// `(runtime, initial storage, genesis balance)` per contract.
const CONTRACTS: &[(&[u8], &[(u64, u64)], u128)] = &[
    (WRITER, &[(1, 42), (2, 43)], 0),
    (READER_WRITER, &[(1, 7)], 0),
    (ZEROER, &[(2, 77)], 0),
    (REVERTER, &[], 0),
    (SELFDESTRUCTER, &[(9, 99)], 7),
];

fn contract_address(idx: usize) -> Address {
    let mut a = [0xC0u8; 20];
    a[19] = idx as u8;
    Address(a)
}

fn setup() -> EvmModule {
    let m = EvmModule::new(1, 7);
    for (i, (code, storage, balance)) in CONTRACTS.iter().enumerate() {
        let storage =
            storage.iter().map(|(k, v)| (U256::from(*k), U256::from(*v))).collect();
        m.genesis_insert_account(&contract_address(i), *balance, 1, code.to_vec(), storage);
    }
    for i in 0..4u8 {
        let addr = crypto::secp::test_identity_address(i).expect("identity keys are valid");
        m.fund_account_for_test(&addr, u128::MAX);
    }
    m
}

fn sign(pk: &[u8; 32], nonce: u64, to: TxKind, data: Bytes, value: u64) -> Vec<u8> {
    SignedTx::sign_legacy(
        TxLegacy {
            fields: TxFields {
                nonce,
                gas_limit: 1_000_000,
                to,
                value: U256::from(value),
                data,
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000u64),
        },
        pk,
    )
    .expect("sign")
    .encode_to_bytes()
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Parse records and materialize signed txs (sequential nonces
    // per sender so every tx is admissible).
    let mut txs = Vec::new();
    let mut next_nonce = [0u64; 4];
    for chunk in data.chunks_exact(10) {
        let sender = usize::from(chunk[0] % 4);
        let pk = crypto::secp::test_identity_key(chunk[0] % 4);
        let nonce = next_nonce[sender];
        next_nonce[sender] += 1;
        let arg = u64::from_be_bytes(chunk[2..10].try_into().expect("8-byte slice"));
        txs.push(match chunk[1] % 4 {
            0 => {
                let mut to = [0x77u8; 20];
                to[19] = chunk[2];
                sign(&pk, nonce, TxKind::Call(to.into()), Bytes::new(), arg % 1_000_000)
            }
            1 => {
                let mut calldata = vec![0u8; 64];
                calldata[31] = chunk[2];
                calldata[63] = chunk[3];
                sign(
                    &pk,
                    nonce,
                    TxKind::Call(alloy_primitives::Address::from(contract_address(0).0)),
                    Bytes::from(calldata),
                    0,
                )
            }
            2 => {
                let c = usize::from(chunk[2]) % CONTRACTS.len();
                sign(
                    &pk,
                    nonce,
                    TxKind::Call(alloy_primitives::Address::from(contract_address(c).0)),
                    Bytes::new(),
                    0,
                )
            }
            _ => sign(&pk, nonce, TxKind::Create, Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52]), 0),
        });
    }
    if txs.is_empty() {
        return;
    }

    let ctx = TxContext { sender: Address([0; 20]), nonce: 0, fee: 0 };

    let serial = setup();
    serial.begin_block(Height::new(1));
    for raw in &txs {
        let _ = serial.handle(&ctx, raw);
    }
    serial.end_block(Height::new(1));

    let batch = setup();
    batch.begin_block(Height::new(1));
    let _ = batch.handle_batch(&ctx, &txs);
    batch.end_block(Height::new(1));

    let parallel = setup();
    parallel.begin_block(Height::new(1));
    let _ = parallel.handle_batch_parallel(&ctx, &txs);
    parallel.end_block(Height::new(1));

    let root = serial.state_root();
    assert_eq!(batch.state_root(), root, "handle_batch diverged");
    assert_eq!(parallel.state_root(), root, "handle_batch_parallel diverged");
});
