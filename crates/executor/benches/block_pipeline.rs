//! End-to-end block pipeline benchmark (plan.md §14, "meso").
//!
//! ## What this benchmark is
//!
//! Measures the full block pipeline latency:
//! `prepare_proposal → process_proposal → finalize_block → attest_state`.
//!
//! This is the "meso" benchmark the plan calls for: the time from
//! "the leader assembles a block from the mempool" to "the state
//! root is available for the next proposal." It includes:
//!
//! - Mempool selection (fee-priority sort, nonce check).
//! - Static proposal validation (module ID, envelope structure).
//! - Block execution (module dispatch, state transitions).
//! - State root computation (hash of all module roots).
//!
//! ## What is measured
//!
//! - `block_pipeline/{10,100,1000}_txs`: full pipeline for a block
//!   with N staking-delegate transactions.
//! - `propose_only/{10,100,1000}_txs`: just `prepare_proposal`
//!   (mempool pull), isolating proposal assembly cost.
//! - `execute_only/{10,100,1000}_txs`: just `finalize_block`
//!   (execution + root), isolating execution cost.
//!
//! ## Gate
//!
//! plan.md §13 Phase 1: "50–100ms blocks". The full pipeline for a
//! 1000-tx block must complete in **< 50 ms** (leaving 50ms+ for
//! consensus + network in a 100ms block-time cadence). This is a
//! release-build gate; debug builds will be slower.
//!
//! ## Baseline
//!
//! The sum of `propose_only + execute_only` should approximately
//! equal `block_pipeline` (the pipeline has no significant overhead
//! beyond its components).
//!
//! ## Payload
//!
//! Staking-delegate transactions (module_id::STAKING) — the
//! heaviest realistic native transaction: it moves funds into the
//! bonded pool through the EVM account ledger.

#![allow(missing_docs)]
#![allow(clippy::doc_markdown)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use executor::Executor;
use ports::AppInterface;
use primitives::{Address, Height};
use std::hint::black_box;
use std::sync::Arc;
use types::{BlockBudget, FinalizedBlock, TxBytes};

/// Build a staking-delegate tx in the Oxide envelope format:
/// `[sender: 20B][nonce: 8B LE][fee: 8B LE][module_id: 1B][payload]`.
/// Delegation exercises the real ledger path (an EVM account
/// transfer into the bonded pool) — the heaviest native-module op.
fn make_delegate_tx(sender: Address, nonce: u64, fee: u64, amount: u64) -> TxBytes {
    make_delegate_to_tx(sender, sender, nonce, fee, amount)
}

/// Same envelope as [`make_delegate_tx`] but the delegation target is
/// explicit — the history-growth setup needs many distinct senders
/// delegating to the one genesis validator.
fn make_delegate_to_tx(
    sender: Address,
    validator: Address,
    nonce: u64,
    fee: u64,
    amount: u64,
) -> TxBytes {
    let payload = staking::msg::delegate(validator, amount);
    let mut bytes = Vec::with_capacity(37 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::STAKING);
    bytes.extend_from_slice(&payload);
    TxBytes::new(bytes)
}

/// Build an executor with the EVM ledger + staking module and
/// `n_txs` transactions pre-loaded into the mempool.
fn setup_executor(n_txs: usize) -> Executor {
    let mut executor =
        Executor::new(n_txs + 100).with_unsigned_tx_policy(executor::UnsignedTxPolicy::Allow);

    // The EVM account store is the native-token ledger: fund the
    // sender so delegates can bond and fees can debit.
    let evm = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    let sender = Address([0u8; 20]);
    framework::Balances::mint(evm.as_ref(), &sender, u64::MAX / 2);
    executor.register_module(evm.clone());
    executor.set_fee_module(framework::module_id::EVM);
    let staking_module = staking::StakingModule::new();
    staking_module.set_ledger(evm);
    staking_module.genesis_register_validator(sender, 1);
    executor.register_module(Arc::new(staking_module));

    // Submit txs to the mempool via ingest_tx (validates + preverifies).
    for i in 0..n_txs {
        let tx = make_delegate_tx(sender, i as u64, 100, 1);
        let ack = executor.ingest_tx(tx);
        assert_eq!(ack, types::MempoolAck::Accepted, "tx {i} must be accepted");
    }
    executor
}

/// The block budget: 1 MB max bytes, 1 GG max gas. Generous enough
/// that the mempool selection is by tx count, not by budget.
const BUDGET: BlockBudget = BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };

/// Run the full block pipeline: propose → validate → finalize → attest.
/// Returns the elapsed time for the full pipeline.
fn run_full_pipeline(executor: &Executor, height: u64) {
    let proposal = executor.prepare_proposal(&BUDGET);
    black_box(&proposal);

    let verdict = executor.process_proposal(&proposal);
    black_box(&verdict);

    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(height),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    let ack = executor.finalize_block(&block);
    black_box(&ack);

    let attestation = executor.attest_state(Height::new(height));
    black_box(&attestation);
}

/// Bench: full block pipeline (propose → validate → finalize → attest).
fn bench_full_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_pipeline");
    for &n_txs in &[10usize, 100, 1000] {
        group.throughput(Throughput::Elements(n_txs as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_txs), &n_txs, |b, &n| {
            b.iter_batched(
                || setup_executor(n),
                // The routine returns the executor so criterion drops
                // it in the untimed `drop(black_box(output))` section —
                // consuming it inside the routine would charge its
                // teardown (per-account/per-leaf frees) to the
                // measured call.
                |executor| {
                    run_full_pipeline(&executor, 1);
                    executor
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Bench: proposal assembly only (mempool selection).
fn bench_propose_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("propose_only");
    for &n_txs in &[10usize, 100, 1000] {
        group.throughput(Throughput::Elements(n_txs as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_txs), &n_txs, |b, &n| {
            b.iter_batched(
                || setup_executor(n),
                |executor| {
                    let proposal = executor.prepare_proposal(&BUDGET);
                    black_box(&proposal);
                    executor
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Bench: execution + state root only (finalize_block + attest_state).
/// Pre-builds the proposal outside the timed loop.
fn bench_execute_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("execute_only");
    for &n_txs in &[10usize, 100, 1000] {
        group.throughput(Throughput::Elements(n_txs as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n_txs), &n_txs, |b, &n| {
            b.iter_batched(
                || {
                    let executor = setup_executor(n);
                    let proposal = executor.prepare_proposal(&BUDGET);
                    (executor, proposal)
                },
                |(executor, proposal)| {
                    let block = FinalizedBlock {
                        context: types::BlockContext::default(),
                        height: Height::new(1),
                        txs: proposal.txs,
                        signers: Vec::new(),
                    };
                    let ack = executor.finalize_block(&block);
                    black_box(&ack);
                    let attestation = executor.attest_state(Height::new(1));
                    black_box(&attestation);
                    executor
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Deterministic address from an index (distinct funded accounts).
fn addr_from_index(i: u32) -> Address {
    let mut a = [0u8; 20];
    a[..4].copy_from_slice(&i.to_le_bytes());
    Address(a)
}

/// The fixed measured workload for the state-scaling rows:
/// `finalize_block` + `attest_state` on a block already pulled from
/// the mempool — the state-touching half of the pipeline (mempool
/// selection does not depend on committed state).
fn run_execute_attest(executor: &Executor, height: u64) {
    let proposal = executor.prepare_proposal(&BUDGET);
    let block = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(height),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    let ack = executor.finalize_block(&block);
    black_box(&ack);
    let attestation = executor.attest_state(Height::new(height));
    black_box(&attestation);
}

/// Executor with `n_accounts` funded-but-idle accounts in the EVM
/// ledger plus `n_txs` delegate txs queued from a single sender.
///
/// The genesis finalize at height 1 is setup, not measurement: the
/// EVM `state_root` leaf map builds on first use (O(population),
/// once per construction/import) and `touched` clears per block —
/// minting the population without a flush would charge the whole
/// trie build to the measured block. The measured block at height 2
/// hits the incremental path a production chain actually runs —
/// O(touched) leaf patches plus an O(touched·log n) sparse
/// retained-branch walk; the only population-scale cost left is the
/// once-per-process cold build inside setup.
fn setup_executor_with_accounts(n_txs: usize, n_accounts: usize) -> Executor {
    let mut executor =
        Executor::new(n_txs + 100).with_unsigned_tx_policy(executor::UnsignedTxPolicy::Allow);
    let evm = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    let sender = Address([0u8; 20]);
    framework::Balances::mint(evm.as_ref(), &sender, u64::MAX / 4);
    executor.register_module(evm.clone());
    executor.set_fee_module(framework::module_id::EVM);
    let staking_module = staking::StakingModule::new();
    staking_module.set_ledger(evm.clone());
    staking_module.genesis_register_validator(sender, 1);
    executor.register_module(Arc::new(staking_module));
    for i in 0..n_accounts {
        let a = addr_from_index(u32::try_from(i).unwrap_or(u32::MAX).saturating_add(1));
        framework::Balances::mint(evm.as_ref(), &a, 1);
    }
    // Warm-up block flushes the minted population into the trie and
    // consumes nonce 0 of the bench sender.
    let warmup = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: vec![make_delegate_tx(sender, 0, 100, 1)],
        signers: Vec::new(),
    };
    executor.finalize_block(&warmup);
    for i in 0..n_txs {
        let tx = make_delegate_tx(sender, (i + 1) as u64, 100, 1);
        let ack = executor.ingest_tx(tx);
        assert_eq!(ack, types::MempoolAck::Accepted, "tx {i} must be accepted");
    }
    executor
}

/// Executor whose committed history holds `n_history` distinct
/// senders, plus `n_txs` queued from fresh senders. `delegations`
/// selects what each historical tx wrote:
///
/// - `false` (nonce-only growth): every historical tx delegates to an
///   UNREGISTERED validator — the charge succeeds and the nonce is
///   consumed at plan time, but the module rejects before writing
///   any delegation record. This isolates `executed_nonces` + sender
///   accounts from module-state growth — the population the delta
///   overlay and nonce root must stay O(touched) against.
/// - `true` (full history): every historical tx delegates to the
///   genesis validator — each writes a staking delegation record on
///   top of the nonce + account entries, so the difference vs the
///   `false` axis attributes the module `state_root` walk.
fn setup_executor_with_history(n_txs: usize, n_history: usize, delegations: bool) -> Executor {
    let mut executor = Executor::new(n_history + n_txs + 100)
        .with_unsigned_tx_policy(executor::UnsignedTxPolicy::Allow);
    let evm = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    let validator = Address([0u8; 20]);
    // Never registered — the nonce-history txs target this and fail
    // inside the module (fee charged, nonce consumed, nothing written).
    let ghost = Address([0xEE; 20]);
    framework::Balances::mint(evm.as_ref(), &validator, u64::MAX / 4);
    executor.register_module(evm.clone());
    executor.set_fee_module(framework::module_id::EVM);
    let staking_module = staking::StakingModule::new();
    staking_module.set_ledger(evm.clone());
    staking_module.genesis_register_validator(validator, 1);
    executor.register_module(Arc::new(staking_module));
    // History: `n_history` distinct funded senders, one tx each.
    // Batched into ~2k-tx blocks (delegate txs are ~45 B against the
    // 1 MB budget).
    let mut height = 0u64;
    for chunk in (0..n_history).collect::<Vec<_>>().chunks(2_000) {
        height += 1;
        let target = if delegations { validator } else { ghost };
        let txs: Vec<TxBytes> = chunk
            .iter()
            .map(|&i| {
                let sender =
                    addr_from_index(u32::try_from(i).unwrap_or(u32::MAX).saturating_add(1));
                framework::Balances::mint(evm.as_ref(), &sender, u64::MAX / 4);
                make_delegate_to_tx(sender, target, 0, 100, 1)
            })
            .collect();
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(height),
            txs,
            signers: Vec::new(),
        };
        executor.finalize_block(&block);
    }
    // Measured block: `n_txs` fresh senders (nonce 0 each) — the
    // workload stays constant while committed history grows behind it.
    for i in 0..n_txs {
        let sender = addr_from_index(u32::try_from(n_history + i + 1).unwrap_or(u32::MAX));
        framework::Balances::mint(evm.as_ref(), &sender, u64::MAX / 4);
        let tx = make_delegate_to_tx(sender, validator, 0, 100, 1);
        let ack = executor.ingest_tx(tx);
        assert_eq!(ack, types::MempoolAck::Accepted, "tx {i} must be accepted");
    }
    executor
}

/// Bench: a fixed transaction workload against growing committed
/// state — the audit-7.4 "eventual scaling cost" measurement. The
/// block is held constant (100 delegate txs, ~4.5 kB); the axes are
/// the populations behind it:
///
/// - `accounts/*`: funded-but-idle EVM accounts — the state-trie
///   population `state_root` assembles over. The per-block path is
///   O(touched); these rows verify it stays flat in population.
/// - `nonce_history/*`: senders whose single tx was consumed but
///   rejected in-module — committed `executed_nonces` + accounts
///   grow, delegation state does not. The delta vs `accounts`
///   attributes the nonce-map term.
/// - `delegated_history/*`: senders whose delegate tx executed —
///   nonces + accounts + one staking delegation each. The delta vs
///   `nonce_history` attributes the canonical module `state_root`
///   serialization (staking rewrites every delegation record).
///
/// No gate: this bench exists to *report* scaling, so a headline
/// claim can cite the measured slope rather than a warmed-small-state
/// number.
fn bench_state_scaling(c: &mut Criterion) {
    const TXS: usize = 100;
    let mut group = c.benchmark_group("state_scaling");
    group.throughput(Throughput::Elements(TXS as u64));
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    for &n in &[1_000usize, 10_000, 100_000] {
        group.bench_with_input(BenchmarkId::new("accounts", n), &n, |b, &n| {
            b.iter_batched(
                || setup_executor_with_accounts(TXS, n),
                // Returning the executor keeps its teardown (the
                // per-account `DbAccount` and per-leaf `Vec<u8>`
                // frees — O(population), ~5 ms at 100k) in criterion's
                // untimed output-drop section instead of the measured
                // call.
                |executor| {
                    run_execute_attest(&executor, 2);
                    executor
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    for &(name, delegations) in &[("nonce_history", false), ("delegated_history", true)] {
        for &n in &[1_000usize, 10_000, 100_000] {
            group.bench_with_input(BenchmarkId::new(name, n), &n, |b, &n| {
                b.iter_batched(
                    || setup_executor_with_history(TXS, n, delegations),
                    |executor| {
                        run_execute_attest(&executor, 1 + (n as u64).div_ceil(2_000));
                        executor
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }
    group.finish();
}

/// Executor with `n_accounts` committed funded accounts plus
/// `n_txs` pre-built delegate txs (NOT ingested — the interference
/// bench builds `FinalizedBlock`s directly so each measured block is
/// exactly `TXS` wide; `prepare_proposal` would pack the whole queued
/// backlog into block 1 and leave later iterations empty).
fn setup_executor_for_snapshot(n_txs: usize, n_accounts: usize) -> (Executor, Vec<TxBytes>) {
    let mut executor =
        Executor::new(n_txs + 100).with_unsigned_tx_policy(executor::UnsignedTxPolicy::Allow);
    let evm = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    let sender = Address([0u8; 20]);
    framework::Balances::mint(evm.as_ref(), &sender, u64::MAX / 4);
    executor.register_module(evm.clone());
    executor.set_fee_module(framework::module_id::EVM);
    let staking_module = staking::StakingModule::new();
    staking_module.set_ledger(evm.clone());
    staking_module.genesis_register_validator(sender, 1);
    executor.register_module(Arc::new(staking_module));
    for i in 0..n_accounts {
        let a = addr_from_index(u32::try_from(i).unwrap_or(u32::MAX).saturating_add(1));
        framework::Balances::mint(evm.as_ref(), &a, 1);
    }
    // Warm-up block flushes the minted population into the committed
    // trie so the snapshot exports settled state, not setup residue.
    let warmup = FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: vec![make_delegate_tx(sender, 0, 100, 1)],
        signers: Vec::new(),
    };
    executor.finalize_block(&warmup);
    let txs = (0..n_txs).map(|i| make_delegate_tx(sender, (i + 1) as u64, 100, 1)).collect();
    (executor, txs)
}

/// Bench: `export_snapshot` latency against growing committed state —
/// the audit-7.5 "snapshot export" cost itself. The export drains the
/// exec lane (a no-op here — no lane installed), recomputes the
/// aggregate root, and serializes every module's full KV state, so
/// the measured latency is the state-sync read the production node
/// performs while peers catch up.
///
/// No gate: this row reports the slope a snapshot-serving node pays
/// per export; the interference half of the residual is measured by
/// `snapshot_vs_exec` below.
fn bench_snapshot_export(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_export");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));
    for &n in &[1_000usize, 10_000, 100_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_batched(
                || setup_executor_for_snapshot(0, n).0,
                |executor| {
                    let snap = executor.export_snapshot();
                    // Same drop-exclusion: the export's cost is
                    // producing the blob; executor and blob teardown
                    // are the consumer's problem, not the export's.
                    (executor, snap)
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Bench: block latency while a snapshot export is in flight — the
/// audit-7.5 "snapshot export competing with execution" residual.
///
/// The exec lane is installed (the production shape): `finalize_block`
/// enqueues and the worker applies blocks while `export_snapshot`
/// serializes module state on its own thread after `wait_exec_idle`
/// releases. Both sides touch the same module mutexes, so the export
/// stalls block application for its read duration — the measured
/// value is end-to-end block latency (`finalize_block` → executed →
/// `attest_state` returns the root) with vs without a back-to-back
/// export loop on a scoped thread.
///
/// `TXS`-tx delegate blocks at `n` committed accounts; `off` rows are
/// the lane-installed baseline (distinct from `state_scaling`, which
/// runs the synchronous commit path).
fn bench_snapshot_vs_exec(c: &mut Criterion) {
    const TXS: usize = 100;
    let mut group = c.benchmark_group("snapshot_vs_exec");
    group.throughput(Throughput::Elements(TXS as u64));
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(5));

    for &n in &[10_000usize, 100_000] {
        for exporting in [false, true] {
            let name = if exporting { format!("exporting_{n}") } else { format!("idle_{n}") };
            group.bench_function(name, |b| {
                b.iter_custom(|iters| {
                    let (executor, txs) = setup_executor_for_snapshot(
                        usize::try_from(iters).expect("iteration count fits usize") * TXS,
                        n,
                    );
                    let executor = Arc::new(executor);
                    executor.spawn_exec_lane();
                    let stop = std::sync::atomic::AtomicBool::new(false);
                    // Exports completed during the measured loop —
                    // asserted nonzero for the `exporting` rows so a
                    // "no interference" reading is proven to be real
                    // contention-free overlap, not the export thread
                    // starving on `wait_exec_idle` behind the block
                    // stream.
                    let exports_done = std::sync::atomic::AtomicU64::new(0);
                    std::thread::scope(|s| {
                        if exporting {
                            let executor = Arc::clone(&executor);
                            let stop = &stop;
                            let exports_done = &exports_done;
                            s.spawn(move || {
                                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                                    black_box(executor.export_snapshot());
                                    exports_done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            });
                        }
                        let start = std::time::Instant::now();
                        for i in 0..iters {
                            let first =
                                usize::try_from(i).expect("iteration count fits usize") * TXS;
                            let block = FinalizedBlock {
                                context: types::BlockContext::default(),
                                height: Height::new(2 + i),
                                txs: txs[first..first + TXS].to_vec(),
                                signers: Vec::new(),
                            };
                            let ack = executor.finalize_block(&block);
                            black_box(&ack);
                            let attestation = executor.attest_state(Height::new(2 + i));
                            black_box(&attestation);
                        }
                        let elapsed = start.elapsed();
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        // Let a live export observe `stop` before the
                        // scope exits — the join is inside scope's
                        // implicit barrier.
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        if exporting {
                            assert!(
                                exports_done.load(std::sync::atomic::Ordering::Relaxed) > 0,
                                "export thread starved: zero exports completed during {iters} \
                                 measured blocks — the row measured absence, not interference"
                            );
                        }
                        elapsed
                    })
                });
            });
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_full_pipeline,
    bench_propose_only,
    bench_execute_only,
    bench_state_scaling,
    bench_snapshot_export,
    bench_snapshot_vs_exec
);
criterion_main!(benches);
