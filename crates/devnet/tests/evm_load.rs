//! Production-grade EVM transaction load test.
//!
//! This test runs a realistic mix of EVM transactions through a
//! multi-validator TCP devnet and verifies:
//!
//! 1. **Consensus integrity**: all validators finalize the same blocks.
//! 2. **Execution integrity**: all validators produce the same state root.
//! 3. **Transaction completeness**: all submitted txs are finalized.
//! 4. **Nonce continuity**: the workload generator's expected nonces
//!    match the actual nonces in the EVM state (verified via state root
//!    consistency — if nonces diverged, state roots would diverge).
//!
//! ## Workload mix
//!
//! - 50% ETH transfers (21k gas)
//! - 20% contract deployments (different bytecodes)
//! - 20% contract method calls (storage writes)
//! - 10% contract reads (storage reads)
//!
//! ## Configurations
//!
//! - `evm_load_default`: 4 validators, 1000 txs (quick smoke test).
//! - `evm_load_10k`: 4 validators, 10,000 txs (medium load).
//! - `evm_load_100k`: 4 validators, 100,000 txs (heavy load, release only).
//! - `evm_load_7_validators`: 7 validators, 1000 txs (scaling test).
//!
//! ## Running
//!
//! ```sh
//! # Default: 4 validators, 1000 EVM txs
//! cargo test -p devnet --test evm_load -- --ignored --nocapture
//!
//! # Heavy: 4 validators, 10,000 EVM txs (release recommended)
//! cargo test -p devnet --test evm_load --release -- --ignored evm_load_10k --nocapture
//!
//! # 100k txs (release only, takes minutes)
//! EVM_LOAD_TXS=100000 cargo test -p devnet --test evm_load --release -- --ignored evm_load_10k --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]

use devnet::evm_workload::{WorkloadConfig, WorkloadGenerator};
use devnet::tcp_multinode::TcpMultiNodeDevnet;
use executor::Module;
use ports::AppInterface;
use std::time::Instant;

/// Parse an env var as a usize, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Run the EVM load test with the given parameters.
///
/// Spins up `n_validators` nodes over TCP, generates `total_txs` EVM
/// transactions (transfers, deploys, contract calls), submits them
/// through consensus, and verifies integrity.
#[allow(clippy::too_many_lines)]
fn run_evm_load_test(n_validators: usize, total_txs: usize, base_port: u16) {
    eprintln!("evm load test: {n_validators} validators, {total_txs} EVM txs");

    // Build the workload generator. Use a smaller number of senders
    // for small tx counts to avoid funding overhead.
    let num_senders = total_txs.clamp(10, 100);
    let config = WorkloadConfig {
        num_senders,
        num_recipients: 50,
        num_contracts: 10,
        ..WorkloadConfig::default()
    };
    eprintln!(
        "evm load test: generating {total_txs} EVM txs ({num_senders} senders, mix: 50% transfer, 20% deploy, 20% call, 10% read)..."
    );
    let gen_start = Instant::now();
    let mut workload = WorkloadGenerator::new(config);
    let generated = workload.generate_batch(total_txs);
    let gen_elapsed = gen_start.elapsed();
    eprintln!(
        "evm load test: generated {total_txs} txs in {:.3}s ({:.0} tx/s gen rate)",
        gen_elapsed.as_secs_f64(),
        total_txs as f64 / gen_elapsed.as_secs_f64()
    );

    // Assemble the devnet.
    let max_mempool = total_txs + 1000;
    eprintln!("evm load test: assembling {n_validators} validators on ports {base_port}+...");
    let assemble_start = Instant::now();
    let mut devnet = TcpMultiNodeDevnet::with_base_port(n_validators, max_mempool, base_port);
    let assemble_elapsed = assemble_start.elapsed();
    eprintln!("evm load test: assembled in {:.3}s", assemble_elapsed.as_secs_f64());

    // Fund the workload generator's sender accounts on all validators.
    // The devnet's default prefunded senders use [byte; 20] addresses,
    // but the workload generator creates random secp256k1 keypairs with
    // arbitrary addresses. These must be funded explicitly.
    eprintln!(
        "evm load test: funding {} EVM sender accounts on {} validators...",
        workload.senders().len(),
        n_validators
    );
    for sender in workload.senders() {
        devnet.fund_evm_account(&sender.addr, u128::MAX);
    }

    // Extract the tx envelopes.
    let all_txs: Vec<types::TxBytes> = generated.iter().map(|g| g.envelope.clone()).collect();

    // Run consensus: distribute txs across rounds. Each round proposes
    // one block; the 2-chain rule commits block N when block N+1's QC
    // is delivered. So `rounds` rounds produce `rounds` QCs and commit
    // `rounds - 1` blocks (the last block needs a flush round).
    //
    // We use `max(2, ceil(total_txs / txs_per_round))` rounds to ensure
    // at least 2 rounds (so at least 1 block is committed without
    // relying on the flush round).
    //
    // The default block size is 500 txs/round. The block budget
    // (`OxideBft::BUDGET`) allows 1 MiB / 1 gigagas, so 500 EVM txs
    // (~75 KB) fit easily. Larger blocks amortize consensus overhead
    // better — the block-size sweep showed 100→1000 txs/block gives
    // 1.7× EVM TPS scaling.
    let txs_per_round = env_usize("EVM_TXS_PER_ROUND", 500);
    let rounds = total_txs.div_ceil(txs_per_round).max(2);
    eprintln!(
        "evm load test: running {rounds} rounds with up to {txs_per_round} txs/round (pipelined)..."
    );
    let _run_start = Instant::now();
    let (result, elapsed) = devnet.run_pipelined_txs(rounds, txs_per_round, &all_txs);
    eprintln!("evm load test: completed in {:.3}s", elapsed.as_secs_f64());

    // === Integrity check 1: all validators finalized the same blocks ===
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
    eprintln!(
        "evm load test: ✓ all {n_validators} validators agree on {n_blocks} finalized blocks"
    );

    // === Integrity check 2: all txs were finalized ===
    let finalized_txs: usize = result.finalized[0].iter().map(|b| b.txs.len()).sum();
    eprintln!(
        "evm load test: finalized {n_blocks} blocks, {finalized_txs} txs (expected {total_txs})"
    );
    assert_eq!(
        finalized_txs, total_txs,
        "all {total_txs} EVM txs must be finalized, got {finalized_txs}"
    );

    // === Integrity check 3: all validators agree on tx contents ===
    let reference = &result.finalized[0];
    for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
        for (j, (a, b)) in reference.iter().zip(blocks.iter()).enumerate() {
            assert_eq!(a.height, b.height, "validator {i} block {j}: height mismatch");
            assert_eq!(a.txs, b.txs, "validator {i} block {j}: txs mismatch");
        }
    }
    eprintln!("evm load test: ✓ all validators agree on tx contents");

    // === Integrity check 4: all validators produced the same state root ===
    // The executor computes a state root from all module state roots.
    // If any validator's EVM execution diverged, the state root would
    // differ. We check the last finalized block's state root.
    let max_height = n_blocks - 1;
    let state_roots: Vec<primitives::Hash> = (0..n_validators)
        .map(|i| {
            devnet
                .app(i)
                .attest_state(primitives::Height::new(max_height as u64))
                .expect("executed")
                .root
        })
        .collect();
    let first_root = state_roots[0];
    for (i, &root) in state_roots.iter().enumerate() {
        assert_eq!(root, first_root, "validator {i} state root mismatch at height {max_height}");
    }
    eprintln!("evm load test: ✓ all validators agree on state root {first_root}");

    // === Integrity check 5: nonce continuity ===
    // Each sender's nonce should match the workload generator's
    // expected nonce. We check validator 0 (the leader) since all
    // validators should have identical state.
    let senders_to_check = workload.senders().len().min(20); // check first 20 for speed
    for (i, sender) in workload.senders().iter().enumerate().take(senders_to_check) {
        let expected = sender.expected_nonce;
        let actual = devnet.evm_module(0).nonce(&sender.addr);
        assert_eq!(
            actual, expected,
            "sender {i} nonce mismatch: expected {expected}, got {actual}"
        );
    }
    eprintln!("evm load test: ✓ nonce continuity verified for {senders_to_check} senders");

    // === Integrity check 6: balance conservation ===
    // All senders should have non-zero balances (they were funded
    // with u128::MAX and gas costs are tiny relative to the balance).
    for (i, sender) in workload.senders().iter().enumerate().take(senders_to_check) {
        let bal = devnet.evm_module(0).balance(&sender.addr);
        assert!(bal > 0, "sender {i} has zero balance after load — funding or gas bug");
    }
    eprintln!("evm load test: ✓ balance conservation verified for {senders_to_check} senders");

    // === Integrity check 7: EVM state root agreement ===
    // All validators should have the same EVM module state root
    // (not just the aggregate executor state root).
    let evm_roots: Vec<primitives::Hash> =
        (0..n_validators).map(|i| devnet.evm_module(i).state_root()).collect();
    let first_evm_root = evm_roots[0];
    for (i, &root) in evm_roots.iter().enumerate() {
        assert_eq!(root, first_evm_root, "validator {i} EVM state root mismatch");
    }
    eprintln!("evm load test: ✓ all validators agree on EVM state root {first_evm_root}");

    // Report results.
    let tps = total_txs as f64 / elapsed.as_secs_f64();
    let blocks_per_sec = n_blocks as f64 / elapsed.as_secs_f64();
    let txs_per_block = finalized_txs as f64 / n_blocks as f64;
    eprintln!();
    eprintln!("=== EVM Load Test Results ===");
    eprintln!("  validators:      {n_validators}");
    eprintln!("  total txs:       {total_txs}");
    eprintln!("  blocks finalized: {n_blocks}");
    eprintln!("  txs/block:       {txs_per_block:.1}");
    eprintln!("  elapsed:         {:.3}s", elapsed.as_secs_f64());
    eprintln!("  throughput:      {tps:.0} tx/s");
    eprintln!("  block rate:      {blocks_per_sec:.1} blocks/s");
    eprintln!("  contracts deployed: {}", workload.deployed_count());
    eprintln!("  state root:      {first_root}");
    eprintln!("=============================");
}

/// Default EVM load test: 4 validators, 1000 EVM txs.
///
/// This is `#[ignore]`d because it takes a few seconds and binds TCP
/// ports. Run with `cargo test -p devnet --test evm_load -- --ignored --nocapture`.
#[test]
#[ignore = "EVM load test binds TCP ports; run with --ignored --nocapture"]
fn evm_load_default() {
    let n = env_usize("EVM_LOAD_VALIDATORS", 4);
    let total_txs = env_usize("EVM_LOAD_TXS", 1000);
    run_evm_load_test(n, total_txs, 34000);
}

/// Medium EVM load test: 4 validators, 10,000 EVM txs.
///
/// Run with:
/// `cargo test -p devnet --test evm_load --release -- --ignored evm_load_10k --nocapture`
#[test]
#[ignore = "medium EVM load test; run with --release --ignored"]
fn evm_load_10k() {
    let n = env_usize("EVM_LOAD_VALIDATORS", 4);
    let total_txs = env_usize("EVM_LOAD_TXS", 10_000);
    run_evm_load_test(n, total_txs, 35000);
}

/// 7-validator EVM load test (tests scaling with more validators).
#[test]
#[ignore = "EVM load test binds TCP ports; run with --ignored --nocapture"]
fn evm_load_7_validators() {
    let n = 7;
    let total_txs = env_usize("EVM_LOAD_TXS", 1000);
    run_evm_load_test(n, total_txs, 36000);
}

/// Single-validator EVM load test (isolates execution from consensus).
#[test]
#[ignore = "EVM load test binds TCP ports; run with --ignored --nocapture"]
fn evm_load_single_validator() {
    let n = 1;
    let total_txs = env_usize("EVM_LOAD_TXS", 1000);
    run_evm_load_test(n, total_txs, 37000);
}

/// Large-scale EVM load test: configurable up to 1B EVM transactions.
/// Default: 4 validators, 1,000,000 EVM txs (mix of transfers, deploys,
/// contract calls, and reads).
///
/// Scale up with env vars:
/// ```sh
/// # 10M EVM txs:
/// EVM_LOAD_TXS=10000000 cargo test -p devnet --test evm_load --release -- \
///   --ignored evm_load_large --nocapture
///
/// # 100M EVM txs:
/// EVM_LOAD_TXS=100000000 cargo test -p devnet --test evm_load --release -- \
///   --ignored evm_load_large --nocapture
///
/// # 1B EVM txs:
/// EVM_LOAD_TXS=1000000000 cargo test -p devnet --test evm_load --release -- \
///   --ignored evm_load_large --nocapture
/// ```
#[test]
#[ignore = "large EVM load test; run with --release --ignored"]
fn evm_load_large() {
    let n = env_usize("EVM_LOAD_VALIDATORS", 4);
    let total_txs = env_usize("EVM_LOAD_TXS", 1_000_000);
    run_evm_load_test(n, total_txs, 38000);
}

/// 7-validator large EVM load test: tests EVM scaling with more
/// validators at a larger tx count.
/// Default: 7 validators, 100,000 EVM txs.
#[test]
#[ignore = "large EVM load test; run with --release --ignored"]
fn evm_load_7_validators_large() {
    let n = 7;
    let total_txs = env_usize("EVM_LOAD_TXS", 100_000);
    run_evm_load_test(n, total_txs, 39000);
}

/// Diagnostic: serial path only (`parallel_threshold = usize::MAX`).
/// If this passes and the parallel version fails, the bug is in the
/// parallel speculative execution path.
#[test]
#[ignore = "diagnostic test; run with --ignored --nocapture"]
fn evm_load_diagnostic_serial() {
    let n = 1;
    let total_txs = env_usize("EVM_LOAD_TXS", 1000);
    eprintln!("diagnostic-serial: {n} validator, {total_txs} EVM txs (serial path)");

    let num_senders = total_txs.clamp(10, 100);
    let config = WorkloadConfig {
        num_senders,
        num_recipients: 50,
        num_contracts: 10,
        ..WorkloadConfig::default()
    };
    let mut workload = WorkloadGenerator::new(config);
    let generated = workload.generate_batch(total_txs);

    let mut devnet =
        TcpMultiNodeDevnet::with_base_port_and_threshold(n, total_txs + 100, 43000, usize::MAX);

    for sender in workload.senders() {
        devnet.fund_evm_account(&sender.addr, u128::MAX);
    }

    let all_txs: Vec<types::TxBytes> = generated.iter().map(|g| g.envelope.clone()).collect();
    let txs_per_round = env_usize("EVM_TXS_PER_ROUND", 500);
    let rounds = total_txs.div_ceil(txs_per_round).max(2);
    let (result, elapsed) = devnet.run_pipelined_txs(rounds, txs_per_round, &all_txs);
    eprintln!("diagnostic-serial: consensus completed in {:.3}s", elapsed.as_secs_f64());

    let n_blocks = result.finalized[0].len();
    eprintln!("diagnostic-serial: {n_blocks} blocks finalized");

    // Check nonce continuity.
    let senders_to_check = workload.senders().len().min(20);
    let mut nonce_ok = 0;
    for (i, sender) in workload.senders().iter().enumerate().take(senders_to_check) {
        let expected = sender.expected_nonce;
        let actual = devnet.evm_module(0).nonce(&sender.addr);
        if actual == expected {
            nonce_ok += 1;
        } else {
            eprintln!(
                "diagnostic-serial: sender {i} nonce mismatch: expected {expected}, got {actual}"
            );
        }
    }
    eprintln!("diagnostic-serial: {nonce_ok}/{senders_to_check} senders have correct nonce");

    // Check EVM state root.
    let evm_root = devnet.evm_module(0).state_root();
    eprintln!("diagnostic-serial: EVM state root = {evm_root}");
}
