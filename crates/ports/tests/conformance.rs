//! Conformance suite run against the reference `MockEngine`.
//!
//! This is the Phase 0 acceptance gate for the `ports` crate: the
//! reference engine passes the same suite every other engine must pass
//! before it ships. When oxideBFT lands, its test suite calls
//! [`ports::conformance::assert_conformance`] with an oxideBFT factory.

use ports::conformance::assert_conformance;
use ports::mock::MockEngine;

#[test]
fn mock_engine_passes_conformance() {
    assert_conformance(MockEngine::new);
}
