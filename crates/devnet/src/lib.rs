//! Oxide test harness — multi-node devnet runners, workload generators,
//! and integration test infrastructure.
//!
//! This crate is the **test harness** for Oxide. It provides:
//!
//! - [`multinode::MultiNodeDevnet`] — in-process multi-node runner (no TCP).
//! - [`tcp_multinode::TcpMultiNodeDevnet`] — TCP loopback multi-node runner.
//! - [`multiprocess::MultiProcessDevnet`] — multi-process launcher (spawns
//!   `oxide-validator` binaries).
//! - [`evm_workload`] — EVM transaction workload generator for load tests.
//!
//! Production node assembly lives in the [`node`] crate. This crate
//! re-exports `node::{Node, NodeConfig, ConsensusConfig}` for backward
//! compatibility with existing test code that imports `devnet::Node`.
//!
//! # Relationship to `node`
//!
//! `node` is the production crate — it assembles the executor, modules,
//! and consensus engine. `devnet` depends on `node` and adds the
//! multi-node test harness on top. Binaries that need production node
//! assembly depend on `node`; tests and load generators depend on
//! `devnet`.

pub use node::{ConsensusConfig, Node, NodeConfig, run_node_smoke_test};

pub mod byzantine;
pub mod evm_workload;
pub mod multinode;
pub mod multiprocess;
pub mod tcp_multinode;

// ── Backward-compat aliases ───────────────────────────────────────
//
// Existing code imports `devnet::DevnetNode`. The type is now
// `node::Node`, but we provide a type alias so existing imports keep
// working without a mass rename.

/// Backward-compat alias for [`Node`].
///
/// Prefer `node::Node` in new code. This alias exists so existing
/// imports of `devnet::DevnetNode` continue to compile.
#[deprecated(note = "use `node::Node` instead; `DevnetNode` is a backward-compat alias")]
pub type DevnetNode = Node;

/// Backward-compat alias for [`run_node_smoke_test`].
///
/// Prefer `node::run_node_smoke_test` in new code.
#[deprecated(note = "use `node::run_node_smoke_test` instead")]
pub fn run_devnet_smoke_test() {
    run_node_smoke_test();
}
