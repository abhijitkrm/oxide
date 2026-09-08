//! oxide-validator — the validator node binary.
//!
//! Assembles and runs a full Oxide validator node: consensus engine +
//! executor + modules. The engine is selected by config (default:
//! `sequencer` for local devnet; `oxideBFT` for production).
//!
//! Usage: `oxide-validator [--engine sequencer|oxideBFT]`
//!
//! In v0, the validator runs in-process (no networking). It submits
//! a smoke-test transaction, finalizes a block, and reports the state
//! root. Multi-node networking arrives in Phase 2.

use std::env;

use devnet::{ConsensusConfig, DevnetNode, NodeConfig};
use ports::AppInterface;

fn main() {
    let engine = env::args()
        .nth(1)
        .and_then(|s| ConsensusConfig::parse(&s))
        .unwrap_or(ConsensusConfig::Sequencer);

    println!("oxide-validator: starting with engine = {}", engine.as_str());

    let config = NodeConfig { consensus: engine, max_mempool_entries: 10_000 };
    let mut node = DevnetNode::assemble(&config);

    println!("oxide-validator: assembled stack (executor + core/bank/staking modules)");

    // Submit a smoke-test bank transfer.
    let to = primitives::Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, 100);
    let tx = build_tx(framework::module_id::BANK, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();

    let height = node.engine().finalized_height();
    println!("oxide-validator: finalized height = {height:?}");

    if let Some(h) = height {
        let attestation = node.app().attest_state(h);
        println!("oxide-validator: state root at height {} = {}", h.value(), attestation.root);
    }

    println!("oxide-validator: smoke test complete");
}

fn build_tx(module_id: u8, module_payload: &[u8]) -> types::TxBytes {
    let sender = primitives::Address([0u8; 20]);
    let nonce = 0u64;
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(module_payload);
    types::TxBytes::new(bytes)
}
