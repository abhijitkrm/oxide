//! Smoke tests for the `oxide-fullnode` binary (audit session 24,
//! gap 2: binaries had zero tests).
//!
//! The fullnode assembles the executor + modules stack without
//! driving consensus (follower mode). This test verifies the stack
//! assembles without panic and the app is inspectable.

use node::{Node, NodeConfig};

/// The fullnode stack assembles and the app (executor) is accessible
/// for state inspection — the minimum a follower needs.
#[test]
fn smoke_fullnode_assembles() {
    let config = NodeConfig::default();
    let node = Node::assemble(&config);
    // The app must be inspectable (a fullnode serves RPC queries
    // against the executor state).
    let _ = node.app();
}
