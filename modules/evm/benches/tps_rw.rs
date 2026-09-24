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
#![allow(clippy::doc_markdown)]

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

/// A minimal ERC-20-style balance-mapping contract:
/// `balances[caller] -= calldata[0..32]; balances[calldata[32..64]] +=
/// calldata[0..32]`, where `balances[x]` lives at
/// `keccak256(pad32(x) || pad32(0))` — the exact storage layout a real
/// ERC-20 `mapping(address => uint256) balances` produces. Each call
/// performs two dependent slot read-modify-writes on the SAME contract
/// — the workload that defeated account-granular conflict detection
/// (every tx touched and wrote the token's account).
///
/// Layout: mem[0..32]=addr, mem[32..64]=0, slot = SHA3(mem[0..64]).
/// `CALLER PUSH1 0 MSTORE  PUSH1 0 PUSH1 32 MSTORE  PUSH1 64 PUSH1 0
///  SHA3  DUP1 SLOAD  PUSH1 0 CALLDATALOAD  SWAP1 SUB  SSTORE
///  PUSH1 32 CALLDATALOAD  PUSH1 0 MSTORE  PUSH1 64 PUSH1 0 SHA3
///  DUP1 SLOAD  PUSH1 0 CALLDATALOAD  ADD  SSTORE  STOP`
const ERC20_RUNTIME: &[u8] = &[
    // balances[caller] -= v: SHA3(mem[0..64]) → slot; SLOAD; subtract
    // calldata v; SWAP1 puts the slot on top for SSTORE(key, value).
    0x33, 0x60, 0x00, 0x52, 0x60, 0x00, 0x60, 0x20, 0x52, 0x60, 0x40, 0x60, 0x00, 0x20, 0x80, 0x54,
    0x60, 0x00, 0x35, 0x90, 0x03, 0x90, 0x55,
    // balances[to] += v: same with the calldata recipient.
    0x60, 0x20, 0x35, 0x60, 0x00, 0x52, 0x60, 0x40, 0x60, 0x00, 0x20, 0x80, 0x54, 0x60, 0x00, 0x35,
    0x01, 0x90, 0x55, 0x00,
];

/// `keccak256(pad32(addr) || pad32(0))` — the storage slot of
/// `balances[addr]` in a mapping at position 0 (Solidity layout).
fn balance_slot(addr: revm::primitives::Address) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(addr.as_slice());
    U256::from_be_bytes(revm::primitives::keccak256(preimage).0)
}

/// Build a signed `Call` to the ERC-20-style contract:
/// `calldata = [value: 32B][recipient: 32B]`.
fn signed_token_transfer(
    privkey: &[u8],
    nonce: u64,
    token: revm::primitives::Address,
    value: u64,
    recipient: revm::primitives::Address,
) -> Vec<u8> {
    let mut data = [0u8; 64];
    data[31] = u8::try_from(value).expect("bench value fits u8");
    data[44..64].copy_from_slice(recipient.as_slice());
    let tx = TxLegacy {
        fields: TxFields {
            nonce,
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(token),
            value: U256::ZERO,
            data: Bytes::copy_from_slice(&data),
            chain_id: 1,
        },
        gas_price: U256::from(10_000_000_000u64),
    };
    SignedTx::sign_legacy(tx, privkey).expect("sign must succeed").encode_to_bytes()
}

/// Benchmark: parallel execution on a shared hot contract with
/// disjoint storage access — the ERC-20 mix.
///
/// Every tx calls the SAME token contract, debiting the sender's
/// `balances` slot and crediting a per-sender recipient's slot. All
/// `(contract, slot)` writes are pairwise disjoint, so slot-granular
/// conflict detection merges every speculation; under the displaced
/// account-granular scheme every tx conflicted on the contract's
/// account and re-executed.
///
/// Rows: `serial` is `handle_batch` (single-writer sequential —
/// the reference), `parallel` is `handle_batch_parallel`,
/// `parallel_shared_slot` sends every credit to ONE recipient so the
/// shared balance slot serializes the batch (worst case: every tx
/// re-executes).
///
/// Measured (8-core, 1000 txs): `parallel` 12.5 ms vs `serial`
/// 12.3 ms vs account-granular `parallel` 16.4 ms — slot tracking
/// removes the 34% speculation waste and reaches parity with serial;
/// `shared_slot` stays ~17 ms either way (real conflicts must
/// serialize). The residual serial cost is the canonical-order merge
/// (Phase 5), which a multi-version store would be needed to
/// parallelize further.
fn bench_batch_parallel_hot_contract(c: &mut Criterion) {
    const N_SENDERS: usize = 50;
    let keys: Vec<TestKey> = (0..N_SENDERS).map(|_| TestKey::new()).collect();
    let token = revm::primitives::Address::from_slice(&[0xAA; 20]);
    let token_oxide = Address([0xAA; 20]);
    // One distinct recipient per sender — their balance slots never
    // overlap, so the whole batch is pairwise conflict-free.
    let recipients: Vec<revm::primitives::Address> = (0..N_SENDERS)
        .map(|i| {
            let mut a = [0x55u8; 20];
            a[18..20]
                .copy_from_slice(&u16::try_from(i).expect("sender index fits u16").to_be_bytes());
            revm::primitives::Address::from_slice(&a)
        })
        .collect();
    let sender_slots: Vec<U256> =
        keys.iter().map(|k| balance_slot(revm::primitives::Address::from(k.addr.0))).collect();

    let setup = |shared_recipient: Option<revm::primitives::Address>, n_txs: usize| {
        let module = EvmModule::new(1, 7_000_000_000);
        // Seed each sender's `balances` slot so the debit doesn't
        // wrap — cosmetic for throughput, but keeps the workload
        // semantically a real transfer.
        let seeded: Vec<(U256, U256)> =
            sender_slots.iter().map(|s| (*s, U256::from(10u64.pow(18)))).collect();
        module.genesis_insert_account(&token_oxide, 0, 1, ERC20_RUNTIME.to_vec(), seeded);
        for key in &keys {
            fund(&module, &key.addr);
        }
        let txs_per_sender = n_txs / N_SENDERS;
        let mut txs: Vec<Vec<u8>> = Vec::with_capacity(n_txs);
        for (i, key) in keys.iter().enumerate() {
            let to = shared_recipient.unwrap_or(recipients[i]);
            for j in 0..txs_per_sender {
                txs.push(signed_token_transfer(&key.privkey, j as u64, token, 1, to));
            }
        }
        (module, txs)
    };

    // One-time probe: prove the disjoint workload really is
    // conflict-free under the slot-granular detector.
    {
        let (module, txs) = setup(None, 1_000);
        let results = module.handle_batch_parallel(&dummy_ctx(), &txs);
        assert!(results.iter().all(std::result::Result::is_ok), "probe txs must succeed");
        eprintln!(
            "hot_contract probe: {} txs, {} re-executions",
            txs.len(),
            module.parallel_reexec_count_for_test()
        );
    }

    let mut group = c.benchmark_group("batch_parallel_hot_contract");

    for &n_txs in &[100usize, 1000] {
        group.bench_function(format!("serial_{n_txs}_txs_{N_SENDERS}_senders"), |b| {
            b.iter_batched(
                || setup(None, n_txs),
                |(module, txs)| {
                    module.begin_block(Height::new(1));
                    let results = module.handle_batch(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    black_box(module.state_root());
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });
        group.bench_function(format!("parallel_{n_txs}_txs_{N_SENDERS}_senders"), |b| {
            b.iter_batched(
                || setup(None, n_txs),
                |(module, txs)| {
                    module.begin_block(Height::new(1));
                    let results = module.handle_batch_parallel(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    black_box(module.state_root());
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });
        group.bench_function(format!("shared_slot_{n_txs}_txs_{N_SENDERS}_senders"), |b| {
            b.iter_batched(
                || setup(Some(recipients[0]), n_txs),
                |(module, txs)| {
                    module.begin_block(Height::new(1));
                    let results = module.handle_batch_parallel(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    black_box(module.state_root());
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
                    // Keep the senders only — the borrowed
                    // `PreverifiedTx`s are built inside the measured
                    // routine because they borrow `txs`.
                    let senders: Vec<revm::primitives::Address> = module
                        .preverify_batch(&txs.iter().map(Vec::as_slice).collect::<Vec<_>>())
                        .into_iter()
                        .map(|r| r.expect("preverify must succeed").sender)
                        .collect();
                    (module, txs, senders)
                },
                |(module, txs, senders)| {
                    module.begin_block(Height::new(1));
                    let preverified: Vec<PreverifiedTx<'_>> = txs
                        .iter()
                        .zip(&senders)
                        .map(|(raw, &sender)| PreverifiedTx { raw: raw.as_slice(), sender })
                        .collect();
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
                    // Keep senders only — borrowed `PreverifiedTx`s
                    // are built inside the measured routine (they
                    // borrow `txs`).
                    let senders: Vec<revm::primitives::Address> = module
                        .preverify_batch(&txs.iter().map(Vec::as_slice).collect::<Vec<_>>())
                        .into_iter()
                        .map(|r| r.expect("preverify must succeed").sender)
                        .collect();
                    (module, txs, senders)
                },
                |(module, txs, senders)| {
                    module.begin_block(Height::new(1));
                    let preverified: Vec<PreverifiedTx<'_>> = txs
                        .iter()
                        .zip(&senders)
                        .map(|(raw, &sender)| PreverifiedTx { raw: raw.as_slice(), sender })
                        .collect();
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

/// Benchmark: parallel vs serial for read-write conflict workloads.
///
/// This is the differential benchmark for the read-write conflict
/// detection fix (session: EVM read-write conflict detection). The
/// `accessed_accounts` tracking we added has a cost: every account
/// loaded by a speculative group is added to a `HashSet<Address>`,
/// and conflict detection checks this set against prior committed
/// writes. This bench proves the overhead doesn't regress throughput
/// compared to serial execution.
///
/// ## Workload
///
/// Two senders: sender A transfers ETH to recipient R, sender B
/// transfers ETH to a different recipient. Both txs are in the same
/// block. This is the conflict-free multi-sender case — the access
/// sets don't overlap, so no re-execution is needed. The bench
/// measures the cost of building and checking the access sets.
///
/// ## Gate
///
/// Parallel path must not be more than 20% slower than serial for
/// 1,000 txs. The 20% headroom accounts for the HashSet construction
/// and membership checks that serial doesn't need. If the overhead
/// exceeds 20%, the access tracking implementation needs optimization
/// (e.g., bloom filter, bitset, or a cheaper set structure).
///
/// ## Baseline
///
/// Serial `handle_batch` (sequential, no access tracking, no
/// conflict detection). The parallel path adds: per-group HashSet
/// construction, conflict detection, and COW cache management.
/// Parity is the goal; a small overhead is acceptable.
fn bench_read_write_conflict_parallel_vs_serial(c: &mut Criterion) {
    const N_SENDERS: usize = 100;
    let keys: Vec<TestKey> = (0..N_SENDERS).map(|_| TestKey::new()).collect();
    // Each sender transfers to a distinct recipient (conflict-free).
    let recipients: Vec<revm::primitives::Address> = (0..N_SENDERS)
        .map(|i| {
            revm::primitives::Address::from_slice(&[0x42 + u8::try_from(i).unwrap_or(255); 20])
        })
        .collect();

    let mut group = c.benchmark_group("read_write_conflict_parallel_vs_serial");

    for &n_txs in &[100usize, 1000, 10000] {
        // Serial path: handle_batch (sequential, no access tracking).
        group.bench_function(format!("{n_txs}_txs_serial"), |b| {
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
                    let results = module.handle_batch(&dummy_ctx(), &txs);
                    module.end_block(Height::new(1));
                    let root = module.state_root();
                    black_box(root);
                    black_box(results);
                },
                criterion::BatchSize::SmallInput,
            );
        });

        // Parallel path: handle_batch_parallel (with access tracking).
        group.bench_function(format!("{n_txs}_txs_parallel"), |b| {
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
    bench_batch_parallel_hot_contract,
    bench_native_vs_revm,
    bench_preverified_vs_recovery,
    bench_preverified_parallel_vs_recovery,
    bench_read_write_conflict_parallel_vs_serial,
);
criterion_main!(benches);
