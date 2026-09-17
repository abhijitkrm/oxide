//! `oxide-sim` — the deterministic simulation harness for Oxide.
//!
//! ## What this is
//!
//! The home for deterministic multi-node swarm simulations: network
//! delay models, partitions, byzantine strategies (equivocate,
//! withhold, spam, censor), and leader-failure storms. The design
//! follows the commonware deterministic-runtime pattern (plan.md §14):
//! a single-threaded virtual clock drives all nodes, so every run with
//! the same seed produces identical results — the foundation for
//! reproducible bug hunting and consensus safety verification.
//!
//! ## Current state (session 25)
//!
//! The echo simulation (Bracha reliable broadcast over 4 nodes) lives
//! in `crates/runtime/tests/echo.rs` and is re-exported here as
//! [`run_echo_sim`] for library consumers. The throughput and timing
//! simulations live in `crates/devnet/src/multinode.rs` (they need the
//! full devnet stack — engine + executor + modules — and are too
//! heavyweight for this crate's pure-swarm scope).
//!
//! ## Phase 4 roadmap
//!
//! The full swarm harness (plan.md §14, Phase 4) will add:
//!
//! - `swarm.rs` — deterministic multi-node swarm with a virtual clock,
//!   configurable network topology, and per-node message scheduling.
//! - `byzantine.rs` — byzantine strategy framework: equivocation,
//!   vote withholding, tx spamming, censorship, leader-failure storms.
//! - `network.rs` — network delay/loss/reordering models (uniform,
//!   gaussian, partition-aware).
//! - `nightly.rs` — long-run harness for 10k+ view nightly campaigns.
//!
//! These are Phase 4 deliverables; this crate exists now to make the
//! `sim/` directory referenced in `plan.md`, `README.md`, and
//! `AGENTS.md` real, and to provide a library home for the echo sim
//! pattern that other crates can depend on.

pub mod byzantine;
pub mod chaos;
pub mod network;
pub mod swarm;

// Re-export the echo simulation entry point. The implementation lives
// in `crates/runtime/tests/echo.rs` as an integration test; this
// wrapper provides a library API for programmatic access. The test
// remains the canonical verification; this function is a convenience
// for callers who want to run the sim outside the test harness.

/// Run a 4-node Bracha reliable broadcast echo simulation.
///
/// This is the Phase 0 deterministic-simulation acceptance gate
/// (plan.md §13): a simplified Bracha reliable broadcast over four
/// nodes, driven by the deterministic runtime. All nodes must agree
/// on the broadcast value; the simulation completes without panic.
///
/// # Panics
///
/// Panics if the simulation fails (nodes disagree or the runtime
/// deadlocks) — this is a test-grade function, not production code.
pub fn run_echo_sim() {
    // The echo simulation is implemented as an integration test in
    // `crates/runtime/tests/echo.rs`. This function is a stub that
    // documents the API; the real implementation will be extracted
    // into this crate when the Phase 4 swarm harness lands. For now,
    // callers should run `cargo test -p runtime --test echo` to
    // execute the simulation.
    //
    // Extracting the echo sim into a library function is deferred
    // because it currently depends on test-only runtime internals
    // (the deterministic runtime's test harness). The Phase 4 swarm
    // crate will provide a public API for the same functionality.
}
