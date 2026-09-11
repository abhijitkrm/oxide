//! Networked TPS test — real multi-node oxideBFT consensus over TCP.
//!
//! This test spins up N validator nodes in-process, connected over real
//! TCP loopback connections, submits a large batch of bank-transfer
//! transactions, runs consensus to finality, and reports end-to-end
//! throughput.
//!
//! This is the honest TPS number: it includes consensus overhead
//! (propose, vote, QC formation, QC broadcast), network I/O (TCP
//! framing, per-peer writer channels), and execution (module dispatch,
//! bank transfer, state root computation).
//!
//! # Why this matters
//!
//! The single-node spammer (`oxide-spammer`) measures in-process
//! execution throughput without consensus or networking. This test
//! measures the full pipeline: a tx must be submitted, proposed in a
//! block, voted on by all validators over TCP, the QC must be formed
//! and broadcast, and the block must be finalized and executed on
//! every node.
//!
//! # Running
//!
//! ```sh
//! # Default: 4 validators, 10 rounds, 100 txs/round = 1000 txs
//! cargo test -p devnet --test tps -- --ignored --nocapture
//!
//! # Larger run: 4 validators, 50 rounds, 200 txs/round = 10000 txs
//! TPS_VALIDATORS=4 TPS_ROUNDS=50 TPS_TXS_PER_ROUND=200 \
//!   cargo test -p devnet --test tps -- --ignored --nocapture
//!
//! # Release build (much faster):
//! cargo test -p devnet --test tps --release -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]

use devnet::tcp_multinode::TcpMultiNodeDevnet;
use std::time::Instant;

/// Parse an env var as a usize, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Run a networked TPS test with the given parameters.
///
/// Spins up `n_validators` nodes over TCP, submits `rounds *
/// txs_per_round` bank-transfer txs, runs consensus to finality,
/// and asserts that all validators agree on the same finalized blocks.
///
/// `base_port` must be unique per test to avoid port collisions when
/// tests run in parallel.
///
/// `min_tps` is the TPS floor. The test fails if measured throughput
/// falls below this. The floor is conservative for debug builds and
/// should be tightened in release. Set to 0 to disable the floor
/// (useful for exploratory runs).
fn run_networked_tps(
    n_validators: usize,
    rounds: usize,
    txs_per_round: usize,
    base_port: u16,
    min_tps: f64,
) {
    let total_txs = rounds * txs_per_round;
    eprintln!(
        "networked TPS test: {n_validators} validators, {rounds} rounds, {txs_per_round} txs/round = {total_txs} total txs"
    );

    let max_mempool = total_txs + 1000;

    eprintln!("networked TPS test: assembling {n_validators} validators on ports {base_port}+...");
    let assemble_start = Instant::now();
    let mut devnet = TcpMultiNodeDevnet::with_base_port(n_validators, max_mempool, base_port);
    let assemble_elapsed = assemble_start.elapsed();
    eprintln!(
        "networked TPS test: assembled in {:.3}s ({} TCP connections)",
        assemble_elapsed.as_secs_f64(),
        n_validators * (n_validators - 1),
    );

    // Run the consensus rounds (pipelined: overlaps vote collection
    // and QC delivery across views — no 1ms sleep polls).
    eprintln!("networked TPS test: running {rounds} rounds (pipelined)...");
    let (result, elapsed) = devnet.run_pipelined(rounds, txs_per_round);
    eprintln!("networked TPS test: completed in {:.3}s", elapsed.as_secs_f64());

    // Verify all validators agree on the same finalized blocks.
    let n_blocks = result.finalized[0].len();
    assert!(n_blocks > 0, "should have finalized at least one block");
    for (i, blocks) in result.finalized.iter().enumerate() {
        assert_eq!(
            blocks.len(),
            n_blocks,
            "validator {i} has {n_blocks} blocks expected, got {}",
            blocks.len()
        );
    }

    // Count total finalized txs across all blocks.
    let finalized_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
    eprintln!("networked TPS test: finalized {n_blocks} blocks, {finalized_txs} txs");

    // Verify all txs were finalized.
    assert_eq!(
        finalized_txs, total_txs,
        "all {total_txs} txs must be finalized, got {finalized_txs}"
    );

    // Verify all validators agree on tx contents (not just counts).
    let reference = &result.finalized[0];
    for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
        for (j, (a, b)) in reference.iter().zip(blocks.iter()).enumerate() {
            assert_eq!(a.height, b.height, "validator {i} block {j}: height mismatch");
            assert_eq!(a.txs, b.txs, "validator {i} block {j}: txs mismatch");
        }
    }

    // Report TPS.
    let tps = total_txs as f64 / elapsed.as_secs_f64();
    let blocks_per_sec = n_blocks as f64 / elapsed.as_secs_f64();
    let txs_per_block = finalized_txs as f64 / n_blocks as f64;
    eprintln!();
    eprintln!("=== Networked TPS Results ===");
    eprintln!("  validators:      {n_validators}");
    eprintln!("  total txs:       {total_txs}");
    eprintln!("  blocks finalized: {n_blocks}");
    eprintln!("  txs/block:       {txs_per_block:.1}");
    eprintln!("  elapsed:         {:.3}s", elapsed.as_secs_f64());
    eprintln!("  throughput:      {tps:.0} tx/s");
    eprintln!("  block rate:      {blocks_per_sec:.1} blocks/s");
    eprintln!("  TPS floor:       {min_tps:.0} tx/s");
    eprintln!("=============================");

    // Enforce the TPS floor. This is the production gate: if
    // throughput regresses below the floor, the test fails. The
    // floor is set conservatively for debug builds; release builds
    // should run 5–20× faster. Override with `TPS_MIN_FLOOR=0` to
    // disable for exploratory runs.
    let env_floor = std::env::var("TPS_MIN_FLOOR").ok().and_then(|v| v.parse::<f64>().ok());
    let effective_floor = env_floor.unwrap_or(min_tps);
    if effective_floor > 0.0 {
        assert!(
            tps >= effective_floor,
            "networked TPS {tps:.0} below floor {effective_floor:.0} tx/s \
             ({n_validators} validators, {total_txs} txs, {:.3}s)",
            elapsed.as_secs_f64()
        );
        eprintln!("  ✓ TPS floor met ({tps:.0} >= {effective_floor:.0})");
    }
}

/// Default networked TPS test: 4 validators, 10 rounds, 500 txs/round.
///
/// This is `#[ignore]`d because it takes a few seconds and binds TCP
/// ports. Run with `cargo test -p devnet --test tps -- --ignored --nocapture`.
///
/// The default block size is 500 txs/round. The block-size sweep
/// showed bank-transfer TPS scales linearly with block size
/// (100→1000 txs/block gives 6.3× TPS). The block budget allows
/// 1 MiB / 1 gigagas, so 500 bank txs (~18 KB) fit easily.
///
/// The TPS floor is 500 tx/s for debug builds — conservative because
/// debug-mode consensus + TCP framing is 5–20× slower than release.
/// In release, this should easily exceed 10,000+ tx/s. Override with
/// `TPS_MIN_FLOOR=0` to disable.
#[test]
#[ignore = "networked TPS test binds TCP ports; run with --ignored --nocapture"]
fn networked_tps_default() {
    let n = env_usize("TPS_VALIDATORS", 4);
    let rounds = env_usize("TPS_ROUNDS", 10);
    let txs_per_round = env_usize("TPS_TXS_PER_ROUND", 500);
    run_networked_tps(n, rounds, txs_per_round, 30000, 500.0);
}

/// Larger networked TPS test: 4 validators, 20 rounds, 1000 txs/round
/// = 20,000 txs. Run with:
/// `cargo test -p devnet --test tps --release -- --ignored networked_tps_10k --nocapture`
///
/// The floor is 1,000 tx/s — this test runs more txs so the per-tx
/// overhead is amortized over a longer run, justifying a higher floor.
#[test]
#[ignore = "large networked TPS test; run with --release --ignored"]
fn networked_tps_10k() {
    let n = env_usize("TPS_VALIDATORS", 4);
    let rounds = env_usize("TPS_ROUNDS", 20);
    let txs_per_round = env_usize("TPS_TXS_PER_ROUND", 1000);
    run_networked_tps(n, rounds, txs_per_round, 31000, 1000.0);
}

/// Single-validator networked TPS test (quorum=1, but still over TCP).
/// This isolates execution + framing overhead from consensus overhead.
///
/// The floor is 1,000 tx/s — without consensus overhead, the single
/// validator should be faster than the 4-validator case.
#[test]
#[ignore = "networked TPS test binds TCP ports; run with --ignored --nocapture"]
fn networked_tps_single_validator() {
    let n = 1;
    let rounds = env_usize("TPS_ROUNDS", 10);
    let txs_per_round = env_usize("TPS_TXS_PER_ROUND", 500);
    run_networked_tps(n, rounds, txs_per_round, 32000, 1000.0);
}

/// 7-validator networked TPS test (tests scaling with more validators).
///
/// The floor is 300 tx/s — more validators means more QC aggregation
/// and network fan-out, so the floor is lower than the 4-validator
/// case.
#[test]
#[ignore = "networked TPS test binds TCP ports; run with --ignored --nocapture"]
fn networked_tps_7_validators() {
    let n = 7;
    let rounds = env_usize("TPS_ROUNDS", 10);
    let txs_per_round = env_usize("TPS_TXS_PER_ROUND", 500);
    run_networked_tps(n, rounds, txs_per_round, 33000, 300.0);
}
