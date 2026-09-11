//! Smoke tests for the `oxide-deploy` binary (audit session 24,
//! gap 2: binaries had zero tests).
//!
//! The deploy binary calls `node::run_node_smoke_test()`, which
//! assembles a node, submits a tx, finalizes a block, and asserts
//! the state root is non-zero. This test verifies that path works.

/// The node smoke test — the same function `oxide-deploy` calls
/// in its `main()` — completes without panic.
#[test]
fn smoke_node_smoke_test() {
    node::run_node_smoke_test();
}
