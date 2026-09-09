//! EVM TPS and read/write operations benchmarks.
//!
//! This benchmark suite measures the EVM module's performance for:
//! - **TPS**: transactions per second (simple transfers, contract
//!   deployments, contract calls).
//! - **Read ops**: balance reads, nonce reads, storage reads.
//! - **Write ops**: state root computation, account flush.
//!
//! ## Acceptance gates
//!
//! - Simple transfer TPS: > 1,000 tx/s (single-threaded, no
//!   networking). This is the floor for a usable L1.
//! - Balance read: < 1 µs (hot path for RPC queries).
//! - Nonce read: < 1 µs (hot path for mempool validation).
//! - State root (1k accounts): < 10 ms (block commit path).
//!
//! ## What this measures
//!
//! These benchmarks measure the EVM module's *execution* throughput
//! — not the full node stack (no networking, no consensus, no
//! mempool). They establish the execution-layer ceiling that the
//! full stack must approach.

#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use crypto::secp;
use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::Module;
use primitives::{Address, Height};
use revm::primitives::{Bytes, U256};

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

/// Build a signed transfer tx (RLP-encoded).
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

/// Fund an account with a large balance for testing.
fn fund(module: &EvmModule, addr: &Address) {
    module.fund_account_for_test(addr, 10u128.pow(20));
}

/// Dummy tx context for handle calls.
fn dummy_ctx() -> executor::TxContext {
    executor::TxContext { sender: Address([0xff; 20]), nonce: 0, fee: 0 }
}

/// Benchmark: simple value transfer TPS.
///
/// Measures the throughput of executing simple transfer
/// transactions (21,000 gas each). This is the EVM execution
/// floor — no networking, no consensus, no mempool.
fn bench_tps_simple_transfer(c: &mut Criterion) {
    let key = TestKey::new();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let mut group = c.benchmark_group("tps_simple_transfer");
    group.sample_size(100);

    group.bench_function("1_tx", |b| {
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

    group.bench_function("10_txs_batch", |b| {
        b.iter_batched(
            || {
                let module = EvmModule::new(1, 7_000_000_000);
                fund(&module, &key.addr);
                let txs: Vec<Vec<u8>> = (0u64..10)
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

    group.finish();
}

/// Benchmark: contract deployment TPS.
fn bench_tps_contract_deploy(c: &mut Criterion) {
    let key = TestKey::new();
    let bytecode = [0x60u8, 0x42, 0x60, 0x00, 0x55, 0x00];

    let mut group = c.benchmark_group("tps_contract_deploy");
    group.sample_size(50);

    group.bench_function("1_deploy", |b| {
        let module = EvmModule::new(1, 7_000_000_000);
        fund(&module, &key.addr);
        let tx = TxLegacy {
            fields: TxFields {
                nonce: 0,
                gas_limit: 1_000_000,
                to: TxKind::Create,
                value: U256::ZERO,
                data: Bytes::copy_from_slice(&bytecode),
                chain_id: 1,
            },
            gas_price: U256::from(10_000_000_000u64),
        };
        let raw = SignedTx::sign_legacy(tx, &key.privkey).expect("sign").encode_to_bytes();
        b.iter(|| {
            // Note: we can't actually deploy the same contract
            // repeatedly (nonce would be stale). This measures
            // the execution cost of a single deploy.
            let module = EvmModule::new(1, 7_000_000_000);
            fund(&module, &key.addr);
            module.handle(black_box(&dummy_ctx()), black_box(&raw)).expect("deploy");
        });
    });

    group.finish();
}

/// Benchmark: read operations (balance, nonce, storage).
fn bench_read_ops(c: &mut Criterion) {
    let key = TestKey::new();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);
    let recipient_oxide = Address(recipient.0.into());

    let mut group = c.benchmark_group("read_ops");

    // Set up a module with a funded account.
    let module = EvmModule::new(1, 7_000_000_000);
    fund(&module, &key.addr);
    let raw = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);
    module.handle(&dummy_ctx(), &raw).expect("tx must succeed");

    group.bench_function("balance_read", |b| {
        b.iter(|| {
            let balance = module.balance(black_box(&recipient_oxide));
            black_box(balance);
        });
    });

    group.bench_function("nonce_read", |b| {
        b.iter(|| {
            let nonce = module.nonce(black_box(&key.addr));
            black_box(nonce);
        });
    });

    group.bench_function("state_root_read", |b| {
        b.iter(|| {
            let root = module.state_root();
            black_box(root);
        });
    });

    group.finish();
}

/// Benchmark: write operations (state root, `end_block` flush).
fn bench_write_ops(c: &mut Criterion) {
    let key = TestKey::new();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let mut group = c.benchmark_group("write_ops");

    // State root after 1, 10, 100 accounts.
    for &n_txs in &[1u64, 10, 100] {
        group.bench_function(format!("state_root_after_{n_txs}_txs"), |b| {
            b.iter_batched(
                || {
                    let module = EvmModule::new(1, 7_000_000_000);
                    fund(&module, &key.addr);
                    for i in 0u64..n_txs {
                        let raw = signed_transfer(&key.privkey, i, recipient, 1_000_000_000);
                        module.handle(&dummy_ctx(), &raw).expect("tx must succeed");
                    }
                    module
                },
                |module| {
                    let root = module.state_root();
                    black_box(root);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    // End block (flush) after 1, 10, 100 txs.
    for &n_txs in &[1u64, 10, 100] {
        group.bench_function(format!("end_block_after_{n_txs}_txs"), |b| {
            b.iter_batched(
                || {
                    let module = EvmModule::new(1, 7_000_000_000);
                    fund(&module, &key.addr);
                    for i in 0u64..n_txs {
                        let raw = signed_transfer(&key.privkey, i, recipient, 1_000_000_000);
                        module.handle(&dummy_ctx(), &raw).expect("tx must succeed");
                    }
                    module
                },
                |module| {
                    module.end_block(Height::new(1));
                    black_box(());
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark: full block cycle (begin + N txs + end + `state_root`).
fn bench_full_block_cycle(c: &mut Criterion) {
    let key = TestKey::new();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let mut group = c.benchmark_group("full_block_cycle");

    for &n_txs in &[10u64, 100, 1000] {
        group.bench_function(format!("{n_txs}_txs"), |b| {
            b.iter_batched(
                || {
                    let module = EvmModule::new(1, 7_000_000_000);
                    fund(&module, &key.addr);
                    let txs: Vec<Vec<u8>> = (0u64..n_txs)
                        .map(|i| signed_transfer(&key.privkey, i, recipient, 1_000_000_000))
                        .collect();
                    (module, txs)
                },
                |(module, txs)| {
                    module.begin_block(Height::new(1));
                    for raw in &txs {
                        module.handle(&dummy_ctx(), raw).expect("tx must succeed");
                    }
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_tps_simple_transfer,
    bench_tps_contract_deploy,
    bench_read_ops,
    bench_write_ops,
    bench_full_block_cycle,
);
criterion_main!(benches);
