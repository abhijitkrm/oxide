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
//!   with N bank-transfer transactions.
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
//! Bank-transfer transactions (module_id::BANK, 33-byte payload:
//! 20-byte recipient + 8-byte amount + 5-byte transfer opcode).
//! This is the simplest realistic Oxide native transaction.

#![allow(missing_docs)]
#![allow(clippy::doc_markdown)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use executor::Executor;
use ports::AppInterface;
use primitives::{Address, Height};
use std::hint::black_box;
use std::sync::Arc;
use types::{BlockBudget, FinalizedBlock, TxBytes};

/// Build a bank-transfer tx in the Oxide envelope format:
/// `[sender: 20B][nonce: 8B LE][fee: 8B LE][module_id: 1B][payload]`.
fn make_bank_tx(sender: Address, nonce: u64, fee: u64, recipient: Address, amount: u64) -> TxBytes {
    let payload = bank::msg::transfer(recipient, amount);
    let mut bytes = Vec::with_capacity(37 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::BANK);
    bytes.extend_from_slice(&payload);
    TxBytes::new(bytes)
}

/// Build an executor with the bank module registered and `n_txs`
/// transactions pre-loaded into the mempool.
fn setup_executor(n_txs: usize) -> Executor {
    let mut executor = Executor::new(n_txs + 100);

    // Create the bank module and fund the sender so transfers can debit.
    let bank = Arc::new(bank::BankModule::new());
    let sender = Address([0u8; 20]);
    bank.mint(&sender, u64::MAX / 2);
    executor.register_module(bank);

    // Submit txs to the mempool via ingest_tx (validates + preverifies).
    let recipient = Address([1u8; 20]);
    for i in 0..n_txs {
        let tx = make_bank_tx(sender, i as u64, 100, recipient, 1);
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

    let block = FinalizedBlock { height: Height::new(height), txs: proposal.txs };
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
                    let block = FinalizedBlock { height: Height::new(1), txs: proposal.txs };
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
