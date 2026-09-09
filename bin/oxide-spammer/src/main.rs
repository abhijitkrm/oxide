//! oxide-spammer — the load generator binary.
//!
//! Submits transactions to a local Oxide validator node at a
//! configurable rate and reports throughput. Used for load testing
//! the consensus + executor pipeline.
//!
//! Usage: `oxide-spammer [--txs N] [--engine sequencer|oxideBFT]`
//!
//! Default: 10,000 bank-transfer txs on the sequencer engine. The
//! spammer builds a single-validator devnet in-process (no
//! networking), submits txs to the mempool, runs the engine to
//! finality, and reports txs/s.
//!
//! The workload is bank transfers from a genesis-funded sender to a
//! fixed recipient. Each tx increments the sender's nonce. The
//! sender is genesis-funded by the devnet's assemble path.

use std::env;

use devnet::{ConsensusConfig, DevnetNode, NodeConfig};
use ports::AppInterface;

/// Default number of transactions to submit.
const DEFAULT_TXS: usize = 10_000;

fn main() {
    #![allow(clippy::cast_precision_loss)]
    let mut txs = DEFAULT_TXS;
    let mut engine = ConsensusConfig::Sequencer;
    for arg in env::args().skip(1) {
        if let Some(v) = arg.strip_prefix("--txs=") {
            txs = v.parse().unwrap_or(DEFAULT_TXS);
        } else if let Some(v) = arg.strip_prefix("--engine=") {
            engine = ConsensusConfig::parse(v).unwrap_or(ConsensusConfig::Sequencer);
        }
    }

    println!("oxide-spammer: engine = {}, txs = {txs}", engine.as_str());

    let config = NodeConfig { consensus: engine, max_mempool_entries: txs + 100 };
    let mut node = DevnetNode::assemble(&config);
    println!("oxide-spammer: devnet assembled (executor + modules)");

    // Build and submit txs.
    let to = primitives::Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, 1);
    let start = std::time::Instant::now();
    for i in 0..txs {
        let tx = build_tx(framework::module_id::BANK, &module_payload, i as u64);
        node.engine().submit_tx(tx);
    }
    let submit_elapsed = start.elapsed();
    println!(
        "oxide-spammer: submitted {txs} txs in {:.3}ms ({:.0} tx/s submit rate)",
        submit_elapsed.as_secs_f64() * 1000.0,
        txs as f64 / submit_elapsed.as_secs_f64()
    );

    // Run the engine to finality.
    let exec_start = std::time::Instant::now();
    node.engine().run_until_idle();
    let exec_elapsed = exec_start.elapsed();

    // Report results.
    let height = node.engine().finalized_height();
    let finalized_txs: usize = if let Some(h) = height {
        node.engine().finalized_block(h).map_or(0, |b| b.txs.len())
    } else {
        0
    };
    let total_elapsed = start.elapsed();
    let throughput = txs as f64 / total_elapsed.as_secs_f64();
    println!("oxide-spammer: finalized height = {height:?}, last block txs = {finalized_txs}");
    println!(
        "oxide-spammer: {txs} txs in {:.3}ms = {throughput:.0} tx/s total",
        total_elapsed.as_secs_f64() * 1000.0
    );
    println!(
        "oxide-spammer: exec time = {:.3}ms ({:.0} tx/s exec rate)",
        exec_elapsed.as_secs_f64() * 1000.0,
        txs as f64 / exec_elapsed.as_secs_f64()
    );

    // State root at the final height.
    if let Some(h) = height {
        let attestation = node.app().attest_state(h);
        println!("oxide-spammer: state root at height {} = {}", h.value(), attestation.root);
    }
    println!("oxide-spammer: load test complete");
}

/// Build a bank-transfer tx with the given nonce.
fn build_tx(module_id: u8, module_payload: &[u8], nonce: u64) -> types::TxBytes {
    let sender = primitives::Address([0u8; 20]);
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(module_payload);
    types::TxBytes::new(bytes)
}
