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
use evm::PreverifiedTx;
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

/// Benchmark: batch execution with parallel sender recovery.
///
/// This is the optimized path: `handle_batch` recovers all senders
/// in parallel using rayon, then executes sequentially. Compare
/// against the serial `handle` path above.
///
/// Gate: > 100k tx/s for 10k txs (single-sender, parallel recovery
/// only). Baseline: serial `handle` path (~28k tx/s).
fn bench_batch_parallel(c: &mut Criterion) {
    let key = TestKey::new();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let mut group = c.benchmark_group("batch_parallel");

    for &n_txs in &[10u64, 100, 1000, 10000] {
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
                    let results = module.handle_batch(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark: parallel speculative execution with multiple senders.
///
/// This is the `handle_batch_parallel` path: transactions from
/// multiple senders execute in parallel on per-sender-group
/// copy-on-write nested caches. This is the realistic blockchain
/// workload — a real block contains txs from many different senders.
///
/// Gate: > 128k tx/s for 10k txs with 100 senders (must match the
/// single-sender `batch_parallel` baseline). Baseline:
/// `batch_parallel` (~128k tx/s, single sender, parallel recovery
/// only). Measured: ~128k tx/s (parity with serial).
///
/// Workload: `n_senders` senders, each sending `n_txs / n_senders`
/// transfers to distinct recipients. This is the conflict-free case
/// (each sender has its own recipient). The conflict-heavy case is
/// benchmarked separately in `bench_batch_parallel_conflict`.
fn bench_batch_parallel_multi_sender(c: &mut Criterion) {
    // Generate 100 senders. For 10k txs, each sender sends 100 txs.
    const N_SENDERS: usize = 100;
    let keys: Vec<TestKey> = (0..N_SENDERS).map(|_| TestKey::new()).collect();
    let recipients: Vec<revm::primitives::Address> = (0..N_SENDERS)
        .map(|i| {
            revm::primitives::Address::from_slice(
                &[0x42 + u8::try_from(i).expect("N_SENDERS fits in u8"); 20],
            )
        })
        .collect();

    let mut group = c.benchmark_group("batch_parallel_multi_sender");

    for &n_txs in &[100usize, 1000, 10000] {
        group.bench_function(format!("{n_txs}_txs_{N_SENDERS}_senders"), |b| {
            b.iter_batched(
                || {
                    let module = EvmModule::new(1, 7_000_000_000);
                    for key in &keys {
                        fund(&module, &key.addr);
                    }
                    let txs_per_sender = (n_txs / N_SENDERS) as u64;
                    let mut txs: Vec<Vec<u8>> = Vec::with_capacity(n_txs);
                    for (i, key) in keys.iter().enumerate() {
                        for j in 0..txs_per_sender {
                            txs.push(signed_transfer(
                                &key.privkey,
                                j,
                                recipients[i],
                                1_000_000_000,
                            ));
                        }
                    }
                    (module, txs)
                },
                |(module, txs)| {
                    module.begin_block(Height::new(1));
                    let results = module.handle_batch_parallel(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark: parallel speculative execution with conflicts.
///
/// All senders transfer to the SAME recipient, forcing conflict
/// detection and sequential re-execution. This measures the
/// overhead of the conflict detection and fallback path.
///
/// Gate: should not be more than 15% slower than `batch_parallel`
/// (single-sender sequential execution). Baseline: `batch_parallel`
/// (~128k tx/s). Measured: ~114k tx/s (13% slower than serial).
fn bench_batch_parallel_conflict(c: &mut Criterion) {
    const N_SENDERS: usize = 100;
    let keys: Vec<TestKey> = (0..N_SENDERS).map(|_| TestKey::new()).collect();
    let shared_recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let mut group = c.benchmark_group("batch_parallel_conflict");

    for &n_txs in &[100usize, 1000, 10000] {
        group.bench_function(format!("{n_txs}_txs_{N_SENDERS}_senders"), |b| {
            b.iter_batched(
                || {
                    let module = EvmModule::new(1, 7_000_000_000);
                    for key in &keys {
                        fund(&module, &key.addr);
                    }
                    let txs_per_sender = (n_txs / N_SENDERS) as u64;
                    let mut txs: Vec<Vec<u8>> = Vec::with_capacity(n_txs);
                    for key in &keys {
                        for j in 0..txs_per_sender {
                            txs.push(signed_transfer(
                                &key.privkey,
                                j,
                                shared_recipient,
                                1_000_000_000,
                            ));
                        }
                    }
                    (module, txs)
                },
                |(module, txs)| {
                    module.begin_block(Height::new(1));
                    let results = module.handle_batch_parallel(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark: native fast path vs revm for simple transfers.
///
/// This is the "prove it was worth building" comparison. The native
/// fast path bypasses revm for simple ETH transfers (empty calldata,
/// EOA recipient) — just balance + nonce updates. This benchmark
/// compares:
///
/// - `handle_batch` (native fast path): parallel sender recovery +
///   native balance/nonce updates. No revm execution.
/// - `handle` per tx (revm only): parallel sender recovery + full
///   revm EVM execution per tx.
///
/// Gate: native path must be ≥ 3x faster than revm for 10k simple
/// transfers. Expected: ~10-50x based on breakdown analysis (revm
/// execution is ~3.7 µs/tx; native is ~0.1-0.3 µs/tx).
///
/// Workload: 10k simple transfers from a single sender to a single
/// recipient. This is the best case for the native fast path — all
/// txs qualify (empty calldata, EOA recipient).
fn bench_native_vs_revm(c: &mut Criterion) {
    let key = TestKey::new();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let mut group = c.benchmark_group("native_vs_revm");

    for &n_txs in &[1000u64, 10000] {
        // Native fast path (handle_batch).
        group.bench_function(format!("{n_txs}_txs_native"), |b| {
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
                    let results = module.handle_batch(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        // revm only (handle per tx — no native fast path).
        group.bench_function(format!("{n_txs}_txs_revm"), |b| {
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

/// Benchmark: pre-verified sender recovery vs full recovery.
///
/// This is the "prove it was worth building" comparison for the
/// pre-verified sender recovery optimization. The pre-verified path
/// skips secp256k1 recovery entirely (the caller pre-recovered
/// senders at mempool ingestion time). This benchmark compares:
///
/// - `handle_batch` (recovery): parallel decode + secp256k1 recovery
///   + native execution.
/// - `handle_batch_preverified` (pre-verified): parallel decode only
///   (no recovery) + native execution.
///
/// Gate: pre-verified path must be ≥ 3x faster than recovery for 10k
/// simple transfers. Expected: ~5-8x based on breakdown analysis
/// (recovery is ~30 µs/tx parallelized to ~3.7 µs/tx on 8 cores;
/// skipping it removes the dominant cost).
///
/// Workload: 10k simple transfers from a single sender to a single
/// recipient. Both paths use the native fast path for execution;
/// the only difference is whether sender recovery is performed.
fn bench_preverified_vs_recovery(c: &mut Criterion) {
    let key = TestKey::new();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let mut group = c.benchmark_group("preverified_vs_recovery");

    for &n_txs in &[1000u64, 10000] {
        // Full recovery (handle_batch — recovers senders internally).
        group.bench_function(format!("{n_txs}_txs_recovery"), |b| {
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
                    let results = module.handle_batch(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        // Pre-verified (handle_batch_preverified — skips recovery).
        group.bench_function(format!("{n_txs}_txs_preverified"), |b| {
            b.iter_batched(
                || {
                    let module = EvmModule::new(1, 7_000_000_000);
                    fund(&module, &key.addr);
                    let txs: Vec<Vec<u8>> = (0u64..n_txs)
                        .map(|i| signed_transfer(&key.privkey, i, recipient, 1_000_000_000))
                        .collect();
                    // Pre-recover senders (simulates mempool ingestion).
                    let preverified: Vec<PreverifiedTx> = module
                        .preverify_batch(&txs)
                        .into_iter()
                        .map(|r| r.expect("preverify must succeed"))
                        .collect();
                    (module, preverified)
                },
                |(module, preverified)| {
                    module.begin_block(Height::new(1));
                    let results = module.handle_batch_preverified(&dummy_ctx(), &preverified);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Benchmark: pre-verified parallel execution vs full recovery parallel.
///
/// Same comparison as `bench_preverified_vs_recovery` but for the
/// parallel speculative execution path (`handle_batch_parallel` vs
/// `handle_batch_parallel_preverified`). Uses 100 senders to exercise
/// the parallel grouping and conflict detection.
///
/// Gate: pre-verified parallel must be ≥ 2x faster than recovery
/// parallel for 10k txs with 100 senders.
fn bench_preverified_parallel_vs_recovery(c: &mut Criterion) {
    const N_SENDERS: usize = 100;
    let keys: Vec<TestKey> = (0..N_SENDERS).map(|_| TestKey::new()).collect();
    let recipients: Vec<revm::primitives::Address> = (0..N_SENDERS)
        .map(|i| {
            revm::primitives::Address::from_slice(
                &[0x42 + u8::try_from(i).expect("N_SENDERS fits in u8"); 20],
            )
        })
        .collect();

    let mut group = c.benchmark_group("preverified_parallel_vs_recovery");

    for &n_txs in &[1000usize, 10000] {
        // Full recovery (handle_batch_parallel).
        group.bench_function(format!("{n_txs}_txs_{N_SENDERS}_senders_recovery"), |b| {
            b.iter_batched(
                || {
                    let module = EvmModule::new(1, 7_000_000_000);
                    for key in &keys {
                        fund(&module, &key.addr);
                    }
                    let txs_per_sender = (n_txs / N_SENDERS) as u64;
                    let mut txs: Vec<Vec<u8>> = Vec::with_capacity(n_txs);
                    for (i, key) in keys.iter().enumerate() {
                        for j in 0..txs_per_sender {
                            txs.push(signed_transfer(
                                &key.privkey,
                                j,
                                recipients[i],
                                1_000_000_000,
                            ));
                        }
                    }
                    (module, txs)
                },
                |(module, txs)| {
                    module.begin_block(Height::new(1));
                    let results = module.handle_batch_parallel(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        // Pre-verified (handle_batch_parallel_preverified).
        group.bench_function(format!("{n_txs}_txs_{N_SENDERS}_senders_preverified"), |b| {
            b.iter_batched(
                || {
                    let module = EvmModule::new(1, 7_000_000_000);
                    for key in &keys {
                        fund(&module, &key.addr);
                    }
                    let txs_per_sender = (n_txs / N_SENDERS) as u64;
                    let mut txs: Vec<Vec<u8>> = Vec::with_capacity(n_txs);
                    for (i, key) in keys.iter().enumerate() {
                        for j in 0..txs_per_sender {
                            txs.push(signed_transfer(
                                &key.privkey,
                                j,
                                recipients[i],
                                1_000_000_000,
                            ));
                        }
                    }
                    let preverified: Vec<PreverifiedTx> = module
                        .preverify_batch(&txs)
                        .into_iter()
                        .map(|r| r.expect("preverify must succeed"))
                        .collect();
                    (module, preverified)
                },
                |(module, preverified)| {
                    module.begin_block(Height::new(1));
                    let results =
                        module.handle_batch_parallel_preverified(&dummy_ctx(), &preverified);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
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
    bench_batch_parallel,
    bench_batch_parallel_multi_sender,
    bench_batch_parallel_conflict,
    bench_native_vs_revm,
    bench_preverified_vs_recovery,
    bench_preverified_parallel_vs_recovery,
);
criterion_main!(benches);
