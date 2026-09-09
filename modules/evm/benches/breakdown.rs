//! EVM execution breakdown benchmark — isolates each step of the
//! transaction execution path to identify the dominant cost.
//!
//! Steps measured independently:
//! 1. RLP decode
//! 2. secp256k1 sender recovery
//! 3. `TxEnv` construction
//! 4. EVM context build + `transact_commit` (the revm execution)
//! 5. Full `handle()` path (all steps combined)
//! 6. Mutex lock overhead
//!
//! This benchmark exists to guide optimization: we can only optimize
//! what we measure.

#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use crypto::secp;
use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::Module;
use primitives::Address;
use revm::primitives::{Bytes, U256};

const GAS_LIMIT: u64 = 30_000_000;

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

fn signed_transfer(
    privkey: &[u8],
    nonce: u64,
    to: revm::primitives::Address,
    value: u128,
) -> Vec<u8> {
    let tx = TxLegacy {
        fields: TxFields {
            nonce,
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(to),
            value: U256::from(value),
            data: Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(10_000_000_000u64),
    };
    SignedTx::sign_legacy(tx, privkey).expect("sign must succeed").encode_to_bytes()
}

fn fund(module: &EvmModule, addr: &Address) {
    module.fund_account_for_test(addr, 10u128.pow(20));
}

fn dummy_ctx() -> executor::TxContext {
    executor::TxContext { sender: Address([0xff; 20]), nonce: 0, fee: 0 }
}

/// Benchmark: isolate each step of the tx execution path.
fn bench_execution_breakdown(c: &mut Criterion) {
    let key = TestKey::new();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);
    let raw = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);

    let mut group = c.benchmark_group("execution_breakdown");

    // Step 1: RLP decode only.
    group.bench_function("1_rlp_decode", |b| {
        b.iter(|| {
            let mut buf = black_box(&raw[..]);
            let _signed: SignedTx =
                alloy_rlp::Decodable::decode(&mut buf).expect("decode must succeed");
        });
    });

    // Step 2: RLP decode + secp256k1 recovery.
    group.bench_function("2_decode_and_recover", |b| {
        b.iter(|| {
            let mut buf = black_box(&raw[..]);
            let signed: SignedTx =
                alloy_rlp::Decodable::decode(&mut buf).expect("decode must succeed");
            let _sender = signed.recover_sender().expect("recover must succeed");
        });
    });

    // Step 3: Full handle() path (decode + recover + execute + touched tracking).
    group.bench_function("5_full_handle", |b| {
        b.iter_batched(
            || {
                let module = EvmModule::new(1, 7_000_000_000);
                fund(&module, &key.addr);
                let raw = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);
                (module, raw)
            },
            |(module, raw)| {
                module.handle(black_box(&dummy_ctx()), black_box(&raw)).expect("tx must succeed");
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Step 4: Full handle() with pre-funded module (no fund overhead in setup).
    // This measures the steady-state cost: same module, incrementing nonce.
    group.bench_function("6_steady_state_batch_100", |b| {
        b.iter_batched(
            || {
                let module = EvmModule::new(1, 7_000_000_000);
                fund(&module, &key.addr);
                let txs: Vec<Vec<u8>> = (0u64..100)
                    .map(|i| signed_transfer(&key.privkey, i, recipient, 1_000_000_000))
                    .collect();
                (module, txs)
            },
            |(module, txs)| {
                for raw in &txs {
                    module.handle(&dummy_ctx(), raw).expect("tx must succeed");
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Step 5: secp256k1 recovery only (no RLP decode).
    group.bench_function("7_secp_recover_only", |b| {
        // Pre-decode the signed tx.
        let mut buf = &raw[..];
        let signed: SignedTx = alloy_rlp::Decodable::decode(&mut buf).expect("decode must succeed");
        b.iter(|| {
            let _sender = black_box(&signed).recover_sender().expect("recover must succeed");
        });
    });

    group.finish();
}

criterion_group!(benches, bench_execution_breakdown);
criterion_main!(benches);
