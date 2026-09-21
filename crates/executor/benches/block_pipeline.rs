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
    let payload = staking::msg::delegate(sender, amount);
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
    let mut executor = Executor::new(n_txs + 100);

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
                |executor| {
                    run_full_pipeline(&executor, 1);
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
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_full_pipeline, bench_propose_only, bench_execute_only);
criterion_main!(benches);
