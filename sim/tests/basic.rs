//! Integration test for the `oxide-sim` crate (audit session 24,
//! gap 1: the `sim/` directory was referenced in docs but did not
//! exist).

/// The echo sim entry point must be callable without panic. The
/// real echo simulation runs in `crates/runtime/tests/echo.rs`; this
/// test verifies the `oxide-sim` crate compiles and its public API
/// is accessible.
#[test]
fn echo_sim_entry_point_exists() {
    // The stub function completes without panic — the real sim
    // logic lives in the runtime crate's integration test.
    oxide_sim::run_echo_sim();
}
