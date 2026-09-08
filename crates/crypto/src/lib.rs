//! Cryptographic primitives for the Oxide blockchain.
//!
//! Two concerns, one crate:
//!
//! - [`hash`] — domain-separated BLAKE3 hashing. Centralizes the
//!   domain-tag discipline that [`storage`](crate) applied inline so
//!   every component (consensus, executor, trading) hashes with the
//!   same domain tags and never confuses, say, a block hash with a
//!   vote hash. Domain separation is mandatory for consensus safety
//!   (production-rust skill §6: every hash input carries a domain tag).
//!
//! - [`bls`] — BLS12-381 signature type stubs for oxideBFT (Phase 1).
//!   Phase 0 defines the *types* and *traits* oxideBFT will program
//!   against; the actual signing/verification (via `blst` or
//!   `bls12_381`) lands in Phase 1 when the first consumer exists.
//!   This avoids pulling a BLS dependency before there is code that
//!   uses it, while ensuring the type shape is settled.
//!
//! # Why BLAKE3
//!
//! BLAKE3 is the chain's hash function (plan.md §3): fast, parallel,
//!   GPL-3.0-compatible (Apache-2.0), and mature. The storage crate
//!   already uses it for MMR nodes; this crate owns the API so the
//!   domain tags are consistent across the whole codebase.

pub mod bls;
pub mod hash;

pub use bls::{AggregateSignature, PublicKey, Signature, ValidatorIndex};
pub use hash::{Domain, Hasher};
