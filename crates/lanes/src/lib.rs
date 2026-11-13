//! Sharded, swappable execution lanes (`docs/lanes-spec.md`).
//!
//! A *lane* owns a disjoint slice of state and processes an ordered
//! input stream single-writer. Each stage around it is a trait with a
//! default and alternatives, so a stage can be swapped without touching
//! the others:
//!
//! - [`verify`]: authentication ([`verify::Verifier`]): per-item,
//!   batched, certified-by-gateway, session MAC.
//! - [`commit`]: fill commitment ([`commit::FillCommit`]): per-fill
//!   fold, stream digest, Merkle root.
//! - [`shard`]: the trading lane and its market router.
//! - [`evm`]: an account-range value-transfer lane with cross-lane
//!   credits and a conservation invariant.
//!
//! The crate is a prototype of the seams, not a consensus integration:
//! lanes run in-process and the benches measure how each seam's cost
//! and scaling behave, which is what the target-to-cores arithmetic in
//! the spec needs.

// Lane ids, shard counts, batch lengths and account indices are bounded
// by configuration far below the narrower integer types used on the wire
// (u16 lane ids, u32 batch counts); the prototype does not re-check each
// cast. A production wiring validates these at config load.
#![allow(clippy::cast_possible_truncation)]

pub mod commit;
pub mod evm;
pub mod shard;
pub mod verify;
