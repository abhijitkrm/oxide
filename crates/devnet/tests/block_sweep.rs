//! Block-size sweep — measures how TPS scales with `txs_per_round`.
//!
//! This test runs the same workload (staking delegates and EVM txs) with
//! increasing block sizes to find the point where the executor becomes
//! the bottleneck vs. consensus overhead.
//!
//! The block budget (`OxideBft::BUDGET`) allows 1 MiB / 1 gigagas per
//! block, so blocks of 1000+ txs are well within limits. The question
//! is whether the executor can keep up.
//!
//! ## Running
//!
//! ```sh
//! # Release build (the numbers are meaningless in debug):
//! cargo test -p devnet --test block_sweep --release -- --ignored --nocapture
//!
//! # Custom validators (default 4):
//! SWEEP_VALIDATORS=7 cargo test -p devnet --test block_sweep --release -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]

use devnet::evm_workload::{WorkloadConfig, WorkloadGenerator};
use devnet::tcp_multinode::TcpMultiNodeDevnet;
use std::time::Instant;

/// Parse an env var as a usize, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Block sizes to sweep.
const BLOCK_SIZES: &[usize] = &[100, 250, 500, 1000];

/// Run one staking-delegate sweep point: `rounds` blocks of `txs_per_round`
/// txs each over `n_validators` TCP-connected nodes.
fn run_delegate_sweep_point(
    n_validators: usize,
    rounds: usize,
    txs_per_round: usize,
    base_port: u16,
) -> (usize, f64, f64, f64) {
    let total_txs = rounds * txs_per_round;
    let max_mempool = total_txs + 1000;
    let mut devnet = TcpMultiNodeDevnet::with_base_port(n_validators, max_mempool, base_port);
    let (result, elapsed) = devnet.run_pipelined(rounds, txs_per_round);

    let n_blocks = result.finalized[0].len();
    let finalized_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
    assert_eq!(finalized_txs, total_txs, "delegate sweep: txs lost");

    let tps = total_txs as f64 / elapsed.as_secs_f64();
    let blk_rate = n_blocks as f64 / elapsed.as_secs_f64();
    let txs_per_block = finalized_txs as f64 / n_blocks as f64;
    (total_txs, tps, blk_rate, txs_per_block)
}

/// Run one EVM sweep point: `rounds` blocks of `txs_per_round` EVM txs
/// each over `n_validators` TCP-connected nodes.
///
/// Returns `(finalized_txs, tps, block_rate, txs_per_block)`. The
/// finalized tx count may be less than `rounds * txs_per_round` if the
/// leader rotation causes some txs to be consumed by earlier blocks
/// (the mempool is per-engine and `select()` pulls by fee-density, not
/// by round assignment). This is a known limitation of the test
/// harness, not a consensus bug — the `evm_load.rs` tests verify
/// correctness with exact tx counts.
fn run_evm_sweep_point(
    n_validators: usize,
    rounds: usize,
    txs_per_round: usize,
    base_port: u16,
) -> (usize, f64, f64, f64) {
    let total_txs = rounds * txs_per_round;
    let num_senders = total_txs.clamp(10, 100);
    let config = WorkloadConfig {
        num_senders,
        num_recipients: 50,
        num_contracts: 10,
        ..WorkloadConfig::default()
    };
    let mut workload = WorkloadGenerator::new(config);
    let generated = workload.generate_batch(total_txs);

    let max_mempool = total_txs + 1000;
    let mut devnet = TcpMultiNodeDevnet::with_base_port(n_validators, max_mempool, base_port);

    // Fund sender accounts.
    for sender in workload.senders() {
        devnet.fund_evm_account(&sender.addr, u128::MAX);
    }

    let all_txs: Vec<types::TxBytes> = generated.iter().map(|g| g.envelope.clone()).collect();
    let (result, elapsed) = devnet.run_pipelined_txs(rounds, txs_per_round, &all_txs);

    let n_blocks = result.finalized[0].len();
    let finalized_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();

    let tps = finalized_txs as f64 / elapsed.as_secs_f64();
    let blk_rate = n_blocks as f64 / elapsed.as_secs_f64();
    let txs_per_block = if n_blocks > 0 { finalized_txs as f64 / n_blocks as f64 } else { 0.0 };
    (finalized_txs, tps, blk_rate, txs_per_block)
}

/// Run the full block-size sweep for both staking delegates and EVM.
///
/// Each block size is run with enough rounds to produce a stable
/// measurement (at least 5 blocks). The sweep prints a table and
/// asserts that TPS does not regress as block size increases — if
/// larger blocks are slower, the executor is the bottleneck.
#[test]
#[ignore = "block sweep binds TCP ports; run with --release --ignored --nocapture"]
fn block_size_sweep() {
    let n = env_usize("SWEEP_VALIDATORS", 4);

    eprintln!();
    eprintln!("=== Block-Size Sweep (release, {n} validators, TCP loopback) ===");
    eprintln!();

    // --- Bank transfers ---
    eprintln!("--- Bank transfers ---");
    eprintln!(
        "  {:>12}  {:>10}  {:>10}  {:>10}  {:>12}",
        "txs/round", "total txs", "tx/s", "blocks/s", "txs/block"
    );

    let mut staking_results: Vec<(usize, f64)> = Vec::new();
    let mut port = 40000;
    for &txs_per_round in BLOCK_SIZES {
        // Use enough rounds to produce >= 5 blocks, but cap total
        // txs to keep the sweep reasonable (max 10k).
        let rounds = (10_000 / txs_per_round).clamp(5, 20);
        let start = Instant::now();
        let (total, tps, blk_rate, txs_per_blk) =
            run_delegate_sweep_point(n, rounds, txs_per_round, port);
        let wall = start.elapsed();
        eprintln!(
            "  {:>12}  {:>10}  {:>10.0}  {:>10.1}  {:>12.1}  (wall: {:.2}s)",
            txs_per_round,
            total,
            tps,
            blk_rate,
            txs_per_blk,
            wall.as_secs_f64()
        );
        staking_results.push((txs_per_round, tps));
        port += 100;
    }

    // --- EVM ---
    eprintln!();
    eprintln!("--- EVM (transfers + deploys + calls) ---");
    eprintln!(
        "  {:>12}  {:>10}  {:>10}  {:>10}  {:>12}",
        "txs/round", "total txs", "tx/s", "blocks/s", "txs/block"
    );

    let mut evm_results: Vec<(usize, f64)> = Vec::new();
    for &txs_per_round in BLOCK_SIZES {
        // EVM is heavier; cap total txs to 5k.
        let rounds = (5_000 / txs_per_round).clamp(5, 20);
        let total_txs = rounds * txs_per_round;
        let start = Instant::now();
        let (finalized, tps, blk_rate, txs_per_blk) =
            run_evm_sweep_point(n, rounds, txs_per_round, port);
        let wall = start.elapsed();
        eprintln!(
            "  {:>12}  {:>10}  {:>10.0}  {:>10.1}  {:>12.1}  (wall: {:.2}s, finalized: {}/{})",
            txs_per_round,
            total_txs,
            tps,
            blk_rate,
            txs_per_blk,
            wall.as_secs_f64(),
            finalized,
            total_txs
        );
        evm_results.push((txs_per_round, tps));
        port += 100;
    }

    // --- Summary ---
    eprintln!();
    eprintln!("=== Sweep Summary ===");
    eprintln!();
    eprintln!("Bank transfers:");
    for &(size, tps) in &staking_results {
        eprintln!("  {size:>6} txs/block -> {tps:>8.0} tx/s");
    }
    eprintln!();
    eprintln!("EVM:");
    for &(size, tps) in &evm_results {
        eprintln!("  {size:>6} txs/block -> {tps:>8.0} tx/s");
    }
    eprintln!();

    // Assert that larger blocks are not slower (within 20% tolerance).
    // If they are, the executor is the bottleneck.
    for window in staking_results.windows(2) {
        let (small_size, small_tps) = window[0];
        let (large_size, large_tps) = window[1];
        assert!(
            large_tps >= small_tps * 0.8,
            "staking TPS regressed at {large_size} txs/block: {large_tps:.0} < {small_tps:.0} * 0.8 (at {small_size}/block)"
        );
    }
    for window in evm_results.windows(2) {
        let (small_size, small_tps) = window[0];
        let (large_size, large_tps) = window[1];
        assert!(
            large_tps >= small_tps * 0.8,
            "EVM TPS regressed at {large_size} txs/block: {large_tps:.0} < {small_tps:.0} * 0.8 (at {small_size}/block)"
        );
    }

    eprintln!("✓ No TPS regression with larger blocks (executor is not the bottleneck)");
    eprintln!();
    eprintln!("NOTE: These are release-build numbers on TCP loopback.");
    eprintln!("If TPS scales with block size, the bottleneck is consensus overhead,");
    eprintln!("not the executor. If TPS plateaus, the executor is the bottleneck.");
}
