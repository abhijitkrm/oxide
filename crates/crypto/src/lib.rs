//! Cryptographic primitives for the Oxide blockchain.
//!
//! Three concerns, one crate:
//!
//! - [`hash`] — domain-separated BLAKE3 hashing. Centralizes the
//!   domain-tag discipline that [`storage`](crate) applied inline so
//!   every component (consensus, executor, trading) hashes with the
//!   same domain tags and never confuses, say, a block hash with a
//!   vote hash. Domain separation is mandatory for consensus safety
//!   (production-rust skill §6: every hash input carries a domain tag).
//!
//! - [`bls`] — BLS12-381 signature wire types for oxideBFT (Phase 1).
//!   Defines the *types* (`PublicKey`, `Signature`, `AggregateSignature`)
//!   and their codec impls; the actual signing/verification lives in
//!   [`bls_signer`].
//!
//! - [`bls_signer`] — BLS12-381 signing, verification, and aggregation
//!   via `blst` (Phase 1 stage 5). This is the production BLS layer:
//!   sign votes, aggregate quorum certificates, verify them. The
//!   wire types from [`bls`] carry the bytes; this module operates on
//!   them.
//!
//! # Why BLAKE3
//!
//! BLAKE3 is the chain's hash function (plan.md §3): fast, parallel,
//!   GPL-3.0-compatible (Apache-2.0), and mature. The storage crate
//!   already uses it for MMR nodes; this crate owns the API so the
//!   domain tags are consistent across the whole codebase.

pub mod bls;
pub mod bls_signer;
pub mod hash;
pub mod secp;

pub use bls::{AggregateSignature, PublicKey, Signature, ValidatorIndex};
pub use bls_signer::{BlsError, BlsSecretKey, aggregate, aggregate_verify, verify};
pub use hash::{Domain, Hasher};
pub use secp::{
    RecoverableSignature, RecoveryId, SecpError, generate_keypair_for_test, keccak256,
    recover_sender, sign,
};
