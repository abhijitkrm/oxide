//! Real-contract EVM benchmark — the audit's 7.1 residual.
//!
//! Prior benches measured plain 21k-gas transfers (`tps_rw`) or a
//! single hot contract (`batch_parallel_hot_contract`). This suite
//! runs the workload the audit asked for: **signed transactions
//! against deployed contracts, charged at actual executed gas, over
//! a realistic mix — a shared pool, an ERC-20 mapping transfer with
//! logs, and reverting calls — with receipts, state roots, and the
//! persistence flush in the measured path.**
//!
//! ## The mix (per sender, round-robin on nonce)
//!
//! - 70% `transfer` calls on one ERC-20-style token contract —
//!   `balances[caller] -= v; balances[to] += v` on real
//!   `keccak256(pad32(addr) ‖ pad32(0))` mapping slots, plus a
//!   `Transfer` LOG1. Each sender credits a distinct recipient, so
//!   balance slots are pairwise disjoint — the parallel-friendly
//!   share of the mix.
//! - 20% `swap` calls on one Uniswap-pair-style pool contract —
//!   `reserve0 -= amt; reserve1 += amt` on SHARED slots 0/1 plus a
//!   `Sync` LOG1. Every sender's swap writes the same two slots —
//!   the contended share that must serialize under any correct
//!   speculative scheme.
//! - 10% calls into a contract that SSTOREs then REVERTs — the
//!   write must roll back, gas is still charged, and the receipt
//!   records `status = false`.
//!
//! ## What is asserted (not just measured)
//!
//! The one-time probe runs the mix through `handle_batch_parallel`
//! and checks the execution *product*, not only the wall clock:
//! every tx accepted, one receipt per tx, ~90% carrying logs, ~10%
//! `status = false` reverts, non-zero `gas_used`, and non-zero
//! `receipts_root`/`state_root` — i.e. the numbers below are real
//! revm execution on real storage, not a scheduler simulation.
//!
//! ## Acceptance gate
//!
//! `parallel` must not regress versus `serial` (`handle_batch`,
//! the single-writer reference) on the same mix — the honest form
//! of "parallel is worth its complexity" when 20% of the batch is
//! genuinely contended. The `parallel_persist` row adds the
//! `Volatile` storage backend so the `end_block` account flush +
//! sealed-block write is inside the measurement.
//!
//! ## Measured (8-core Apple Silicon, release)
//!
//! | row | 100 txs | 1000 txs |
//! |---|---|---|
//! | serial | 1.80 ms | 13.86 ms |
//! | parallel | 1.97 ms | 17.03 ms |
//! | parallel_persist | — | 17.21 ms |
//!
//! Serial: ~72.2k tx/s ≈ 2.49 GG/s of *executed* contract gas
//! (34.5M gas/1000-tx block). Parallel: ~58.7k tx/s ≈ 2.03 GG/s —
//! **23% slower than serial** on this mix: 637 of 1000 speculative
//! executions re-ran (the 200 shared-pool swaps contend on slots
//! 0/1 and the coinbase/fee accounts every tx touches conflict on
//! top). The disjoint-transfer benches showed parity; a real mix
//! shows speculation costs more than it saves until the
//! multi-version store (Phase 5 residual) removes the
//! canonical-order merge. Persistence adds ~1% — the flush is
//! amortized across the whole batch.
#![allow(missing_docs)]
#![allow(clippy::doc_markdown)]

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

/// Fund an account with a large balance for testing.
fn fund(module: &EvmModule, addr: &Address) {
    module.fund_account_for_test(addr, 10u128.pow(20));
}

/// Dummy tx context for handle calls.
fn dummy_ctx() -> executor::TxContext {
    executor::TxContext { sender: Address([0xff; 20]), nonce: 0, fee: 0 }
}

// ── Contract bytecodes ────────────────────────────────────────────
// Hand-assembled EVM runtime code. Each contract does dependent
// storage read-modify-writes (the real cost center a transfer bench
// never touches) and the first two emit a log so receipts carry
// real `logs`/`bloom` data.

/// ERC-20-style mapping transfer + `Transfer` log:
/// `balances[caller] -= calldata[0..32]` then
/// `balances[calldata[32..64]] += calldata[0..32]`, where
/// `balances[x]` lives at `keccak256(pad32(x) ‖ pad32(0))` — the
/// exact storage layout Solidity gives `mapping(address =>
/// uint256)`. Two dependent slot read-modify-writes per call, then
/// `LOG1(amount)` with the real `Transfer(address,address,uint256)`
/// topic so receipts exercise the logs path.
const TOKEN_RUNTIME: &[u8] = &[
    // balances[caller] -= v: SHA3(mem[0..64]) → slot; SLOAD; SUB v.
    0x33, 0x60, 0x00, 0x52, 0x60, 0x00, 0x60, 0x20, 0x52, 0x60, 0x40, 0x60, 0x00, 0x20, 0x80, 0x54,
    0x60, 0x00, 0x35, 0x90, 0x03, 0x90, 0x55,
    // balances[to] += v: same with the calldata recipient.
    0x60, 0x20, 0x35, 0x60, 0x00, 0x52, 0x60, 0x40, 0x60, 0x00, 0x20, 0x80, 0x54, 0x60, 0x00, 0x35,
    0x01, 0x90, 0x55, // mem[0x80] = v; LOG1(offset=0x80, size=32, topic=Transfer).
    0x60, 0x00, 0x35, 0x60, 0x80, 0x52, 0x7f, 0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69,
    0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28,
    0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef, 0x60, 0x20, 0x60, 0x80, 0xa1, 0x00,
];

/// Uniswap-pair-style `swap`: `reserve0 -= amt; reserve1 += amt` on
/// shared slots 0/1, then a `Sync` log. Both slots are hot — every
/// swap in the batch contends on the same two storage keys, the
/// shape that forces speculative re-execution.
const POOL_RUNTIME: &[u8] = &[
    // slot0 = SLOAD(0) - amt.
    0x60, 0x00, 0x54, 0x60, 0x00, 0x35, 0x03, 0x60, 0x00, 0x55,
    // slot1 = SLOAD(1) + amt.
    0x60, 0x01, 0x54, 0x60, 0x00, 0x35, 0x01, 0x60, 0x01, 0x55,
    // mem[0x80] = amt; LOG1(offset=0x80, size=32, topic=Sync).
    0x60, 0x00, 0x35, 0x60, 0x80, 0x52, 0x7f, 0x1c, 0x41, 0x1e, 0x9a, 0x96, 0xe0, 0x71, 0x24, 0x1c,
    0x2f, 0x21, 0xf7, 0x72, 0x6b, 0x17, 0xae, 0x89, 0xe3, 0xca, 0xb4, 0xc7, 0x8b, 0xe5, 0x0e, 0x06,
    0x2b, 0x03, 0xa9, 0xff, 0xfb, 0xba, 0xd1, 0x60, 0x20, 0x60, 0x80, 0xa1, 0x00,
];

/// Writes slot 9 then REVERTs — gas is charged, the SSTORE must
/// roll back, and the receipt records `status = false`. The
/// realistic "failed transaction" share of a real block.
const REVERTER_RUNTIME: &[u8] = &[
    0x60, 0x01, 0x60, 0x09, 0x55, // SSTORE(9) = 1
    0x60, 0x00, 0x60, 0x00, 0xfd, // REVERT(0, 0)
];

/// `keccak256(pad32(addr) ‖ pad32(0))` — the storage slot of
/// `balances[addr]` in a mapping at position 0 (Solidity layout).
fn balance_slot(addr: revm::primitives::Address) -> U256 {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(addr.as_slice());
    U256::from_be_bytes(revm::primitives::keccak256(preimage).0)
}

/// Build a signed legacy `Call` to `to` with the given calldata.
fn signed_call(privkey: &[u8], nonce: u64, to: revm::primitives::Address, data: &[u8]) -> Vec<u8> {
    let tx = TxLegacy {
        fields: TxFields {
            nonce,
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(to),
            value: U256::ZERO,
            data: Bytes::copy_from_slice(data),
            chain_id: 1,
        },
        gas_price: U256::from(10_000_000_000u64),
    };
    SignedTx::sign_legacy(tx, privkey).expect("sign must succeed").encode_to_bytes()
}

/// Calldata for a token transfer: `[v: 32B][recipient: 32B]`.
fn token_calldata(v: u64, recipient: revm::primitives::Address) -> [u8; 64] {
    let mut data = [0u8; 64];
    data[31] = u8::try_from(v).expect("bench value fits u8");
    data[44..64].copy_from_slice(recipient.as_slice());
    data
}

/// Calldata for a pool swap: `[amt: 32B]`.
fn pool_calldata(amt: u64) -> [u8; 32] {
    let mut data = [0u8; 32];
    data[31] = u8::try_from(amt).expect("bench value fits u8");
    data
}

/// The three contract addresses of the mix.
const TOKEN: revm::primitives::Address = revm::primitives::Address::new([0xAA; 20]);
const POOL: revm::primitives::Address = revm::primitives::Address::new([0xBB; 20]);
const REVERTER: revm::primitives::Address = revm::primitives::Address::new([0xCC; 20]);

/// Which leg of the mix a tx index belongs to.
enum Kind {
    Token,
    Pool,
    Revert,
}

/// 70/20/10 split on `j % 10` — every sender contributes the same
/// proportions, so the mix holds at any `n_txs`.
fn kind_of(j: u64) -> Kind {
    match j % 10 {
        0..=6 => Kind::Token,
        7 | 8 => Kind::Pool,
        _ => Kind::Revert,
    }
}

/// Build the module + signed batch for the mix. `persist` attaches
/// a `Volatile` storage backend so `end_block` runs the real
/// account/history flush inside the measurement.
fn setup(
    keys: &[TestKey],
    recipients: &[revm::primitives::Address],
    sender_slots: &[U256],
    n_txs: usize,
    persist: bool,
) -> (EvmModule, Vec<Vec<u8>>) {
    let module = if persist {
        EvmModule::with_storage(1, 7_000_000_000, Box::new(storage::Volatile::new()))
    } else {
        EvmModule::new(1, 7_000_000_000)
    };
    // Deploy the three contracts at genesis with real code and
    // seeded storage: sender balance slots so the debit can't wrap,
    // and non-zero pool reserves.
    let seeded: Vec<(U256, U256)> =
        sender_slots.iter().map(|s| (*s, U256::from(10u64.pow(18)))).collect();
    module.genesis_insert_account(&Address(TOKEN.0.0), 0, 1, TOKEN_RUNTIME.to_vec(), seeded);
    module.genesis_insert_account(
        &Address(POOL.0.0),
        0,
        1,
        POOL_RUNTIME.to_vec(),
        vec![(U256::ZERO, U256::from(1_000_000u64)), (U256::from(1u64), U256::from(1_000_000u64))],
    );
    module.genesis_insert_account(
        &Address(REVERTER.0.0),
        0,
        1,
        REVERTER_RUNTIME.to_vec(),
        Vec::new(),
    );
    for key in keys {
        fund(&module, &key.addr);
    }

    let n_senders = keys.len();
    let txs_per_sender = n_txs / n_senders;
    let mut txs: Vec<Vec<u8>> = Vec::with_capacity(txs_per_sender * n_senders);
    for (i, key) in keys.iter().enumerate() {
        for j in 0..txs_per_sender as u64 {
            let raw = match kind_of(j) {
                Kind::Token => {
                    signed_call(&key.privkey, j, TOKEN, &token_calldata(1, recipients[i]))
                }
                Kind::Pool => signed_call(&key.privkey, j, POOL, &pool_calldata(1)),
                Kind::Revert => signed_call(&key.privkey, j, REVERTER, &[]),
            };
            txs.push(raw);
        }
    }
    (module, txs)
}

/// Benchmark: the real-contract mix, serial vs parallel.
///
/// Rows: `serial` runs `handle_batch` (single-writer reference),
/// `parallel` runs `handle_batch_parallel`, and `parallel_persist`
/// adds a `Volatile` storage backend so `end_block`'s atomic
/// account/history/undo flush is inside the measurement.
fn bench_contract_mix(c: &mut Criterion) {
    const N_SENDERS: usize = 50;
    let keys: Vec<TestKey> = (0..N_SENDERS).map(|_| TestKey::new()).collect();
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

    // One-time probe: prove the mix produces the real execution
    // product — receipts with logs, reverts, and gas — before any
    // number below is quoted.
    {
        let (module, txs) = setup(&keys, &recipients, &sender_slots, 1_000, false);
        module.begin_block(Height::new(1));
        let results = module.handle_batch_parallel(&dummy_ctx(), &txs);
        module.end_block(Height::new(1));
        assert!(results.iter().all(std::result::Result::is_ok), "mix txs must execute");
        let history = module.history();
        let block = history.block(1).expect("sealed block");
        assert_eq!(block.receipts.len(), txs.len(), "one receipt per tx");
        let logged = block.receipts.iter().filter(|r| !r.logs.is_empty()).count();
        let reverted = block.receipts.iter().filter(|r| !r.status).count();
        // 90% of the mix emits a log (token + pool legs); reverts
        // are the other 10% — allow ±2% for off-by-one rounding.
        assert!((870..=920).contains(&logged), "expected ~90% logged receipts, got {logged}");
        assert!((80..=120).contains(&reverted), "expected ~10% reverts, got {reverted}");
        assert!(block.gas_used > 0, "real gas must be charged");
        assert_ne!(block.receipts_root, alloy_primitives::B256::ZERO);
        assert_ne!(block.state_root, alloy_primitives::B256::ZERO);
        eprintln!(
            "contract_mix probe: {} txs, {} gas, {} logged, {} reverted, {} reexec",
            txs.len(),
            block.gas_used,
            logged,
            reverted,
            module.parallel_reexec_count_for_test()
        );
    }

    let mut group = c.benchmark_group("contract_mix");

    for &n_txs in &[100usize, 1000] {
        group.bench_function(format!("serial_{n_txs}_txs_{N_SENDERS}_senders"), |b| {
            b.iter_batched(
                || setup(&keys, &recipients, &sender_slots, n_txs, false),
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
                || setup(&keys, &recipients, &sender_slots, n_txs, false),
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

    // The persistence row: same parallel mix, but `end_block`
    // flushes accounts + sealed block + undo through a real
    // `StorageBackend::apply_batch` (Volatile — the storage path
    // without disk fsync).
    group.bench_function(format!("parallel_persist_1000_txs_{N_SENDERS}_senders"), |b| {
        b.iter_batched(
            || setup(&keys, &recipients, &sender_slots, 1_000, true),
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

    group.finish();
}

criterion_group!(benches, bench_contract_mix);
criterion_main!(benches);
