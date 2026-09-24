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
//! - [`bls`] — BLS12-381 signature wire types for oxideBFT.
//!   Defines the *types* (`PublicKey`, `Signature`, `AggregateSignature`)
//!   and their codec impls; the actual signing/verification lives in
//!   [`bls_signer`].
//!
//! - [`bls_signer`] — BLS12-381 signing, verification, aggregation,
//!   and proof-of-possession via `blst`. This is the production BLS
//!   layer: sign votes, aggregate quorum certificates, verify them,
//!   and prove/verify key possession (`pop_prove`/`pop_verify`) — the
//!   admission gate that makes same-message aggregate verification
//!   safe against rogue keys. The wire types from [`bls`] carry the
//!   bytes; this module operates on them.
//!
//! # Why BLAKE3
//!
//! BLAKE3 is the chain's hash function (plan.md §3): fast, parallel,
//!   GPL-3.0-compatible (Apache-2.0), and mature. The storage crate
//!   already uses it for MMR nodes; this crate owns the API so the
//!   domain tags are consistent across the whole codebase.

pub mod bls;
pub mod bls_signer;
pub mod ed25519;
pub mod eip712;
pub mod hash;
/// Passphrase-encrypted key files — behind `keystore` (dep:
/// aws-lc-rs) so pure-Rust consumers never pull the C toolchain.
#[cfg(feature = "keystore")]
pub mod keystore;
pub mod secp;

pub use bls::{AggregateSignature, PublicKey, Signature, ValidatorIndex};
pub use bls_signer::{
    BlsError, BlsSecretKey, ConsensusSigner, SignContext, SignerError, aggregate, aggregate_verify,
    pop_verify, verify,
};
pub use ed25519::{
    Ed25519Error, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, derive_public,
    generate_keypair_for_test as generate_ed25519_keypair, sign_message, verify_message,
};
pub use hash::{Domain, Hasher};
pub use secp::{
    RecoverableSignature, RecoveryId, SecpError, generate_keypair_for_test, generate_secret_key,
    is_test_identity_key, keccak256, recover_sender, sign, signable_pubkey_address,
};

/// Fill `out` with bytes from the OS-seeded thread RNG.
///
/// Used for handshake challenge nonces — values an attacker must
/// not be able to predict or replay. `secp256k1::rand` re-exports
/// `rand` (OsRng-seeded `ThreadRng`), already a dependency, so no
/// new crate is pulled in for entropy.
pub fn fill_random(out: &mut [u8]) {
    secp256k1::rand::Rng::fill(&mut secp256k1::rand::rng(), out);
}

/// A fresh unpredictable 32-byte challenge nonce — see
/// [`fill_random`].
#[must_use]
pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    fill_random(&mut nonce);
    nonce
}
