//! oxide-fullnode — the full node binary.
//!
//! Runs the executor + modules without a consensus engine (read-only
//! follower mode). In v0, this is a placeholder that assembles the
//! stack and reports readiness. Real full-node sync (following a
//! validator's finalized blocks) arrives in Phase 2 with networking.

use devnet::{ConsensusConfig, DevnetNode, NodeConfig};

fn main() {
    println!("oxide-fullnode: starting (follower mode)");

    let config = NodeConfig { consensus: ConsensusConfig::Sequencer, max_mempool_entries: 10_000 };
    let _node = DevnetNode::assemble(&config);

    println!("oxide-fullnode: assembled stack (executor + core/bank/staking modules)");
    println!("oxide-fullnode: ready (sync not yet implemented — Phase 2)");
}
