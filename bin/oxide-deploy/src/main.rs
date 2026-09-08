//! oxide-deploy — the devnet deployment tool.
//!
//! Assembles and runs a local in-process devnet. In v0, this runs the
//! smoke test: assemble a node, submit a tx, finalize a block, report
//! the state root. Multi-node deployment with networking arrives in
//! Phase 2.
//!
//! Usage: `oxide-deploy [--engine sequencer|oxideBFT]`

use std::env;

use devnet::{ConsensusConfig, NodeConfig};

fn main() {
    let engine = env::args()
        .nth(1)
        .and_then(|s| ConsensusConfig::parse(&s))
        .unwrap_or(ConsensusConfig::Sequencer);

    println!("oxide-deploy: deploying local devnet with engine = {}", engine.as_str());

    let _ = NodeConfig { consensus: engine, max_mempool_entries: 10_000 };

    // Run the smoke test.
    devnet::run_devnet_smoke_test();

    println!("oxide-deploy: devnet smoke test passed");
}
