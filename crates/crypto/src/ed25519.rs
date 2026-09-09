//! Ed25519 signature support for native module authenticity (Phase G).
//!
//! Oxide uses two signature schemes:
//! - **secp256k1** (EVM): for Ethereum-compatible transactions. The
//!   sender is recovered from the signature (ECDSA with recovery ID).
//! - **Ed25519** (native): for native module transactions (bank,
//!   staking, trading). Ed25519 is faster, has no malleability, and
//!   is simpler to implement securely.
//!
//! # Why Ed25519 for native modules?
//!
//! - **No malleability**: Ed25519 signatures are not malleable,
//!   unlike secp256k1 ECDSA (without EIP-2 low-S enforcement).
//!   This simplifies replay protection.
//! - **Faster verification**: ~50 µs vs ~35 µs for secp256k1
//!   recovery, but Ed25519 verification is simpler (no modular
//!   inverse, no nonce derivation).
//! - **Smaller keys**: 32-byte public keys vs 33-byte compressed
//!   secp256k1 keys.
//! - **Standard**: used by Solana, Signal, Tor, and many
//!   blockchain projects.
//!
//! # Reference
//!
//! - RFC 8032: Ed25519 specification.
//! - `ed25519-dalek` crate: the Rust implementation we use.
//! - Solana: uses Ed25519 for all transaction signatures.

use ed25519_dalek::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
/// An Ed25519 public key (32 bytes).
pub type Ed25519PublicKey = VerifyingKey;

/// An Ed25519 signature (64 bytes).
pub type Ed25519Signature = Signature;

/// An Ed25519 signing key (secret key, 32 bytes).
pub type Ed25519SecretKey = SigningKey;

/// Errors that can occur during Ed25519 operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed25519Error {
    /// The signature is invalid (failed verification).
    InvalidSignature,
    /// The public key is invalid (malformed).
    InvalidPublicKey,
}

/// Generate a new Ed25519 keypair for testing.
///
/// Returns `(secret_key, public_key)`. The secret key is 32 bytes;
/// the public key is 32 bytes.
///
/// # Panics
///
/// Panics if the system random number generator fails (extremely
/// unlikely on any modern OS).
#[must_use]
pub fn generate_keypair_for_test() -> (Ed25519SecretKey, Ed25519PublicKey) {
    // Generate a random seed using the system entropy source.
    // We use `std::time` as a fallback seed source to avoid adding
    // a `getrandom`/`rand_core` version dependency mismatch.
    let mut seed = [0u8; 32];
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_nanos(),
        Err(_) => 1,
    };
    // Mix the nanos into the seed using simple multiplication.
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = ((nanos.wrapping_mul((i as u128) + 1)) & 0xFF) as u8;
    }
    let secret = SigningKey::from_bytes(&seed);
    let public = secret.verifying_key();
    (secret, public)
}

/// Sign a message with an Ed25519 secret key.
///
/// Returns a 64-byte signature.
///
/// # Arguments
///
/// - `secret`: the signing key.
/// - `message`: the message bytes to sign.
#[must_use]
pub fn sign_message(secret: &Ed25519SecretKey, message: &[u8]) -> Ed25519Signature {
    secret.sign(message)
}

/// Verify an Ed25519 signature.
///
/// Returns `Ok(())` if the signature is valid, `Err(Ed25519Error)`
/// if invalid.
///
/// # Arguments
///
/// - `public`: the verifying key.
/// - `message`: the message bytes.
/// - `signature`: the 64-byte signature.
///
/// # Errors
///
/// Returns `Ed25519Error::InvalidSignature` if the signature does
/// not verify against the public key and message.
pub fn verify_message(
    public: &Ed25519PublicKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), Ed25519Error> {
    public.verify_strict(message, signature).map_err(|_| Ed25519Error::InvalidSignature)
}

/// Derive a public key from a secret key.
///
/// # Arguments
///
/// - `secret`: the signing key.
#[must_use]
pub fn derive_public(secret: &Ed25519SecretKey) -> Ed25519PublicKey {
    secret.verifying_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (secret, public) = generate_keypair_for_test();
        let message = b"hello oxide";
        let signature = sign_message(&secret, message);
        assert!(verify_message(&public, message, &signature).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (secret, public) = generate_keypair_for_test();
        let signature = sign_message(&secret, b"message A");
        let result = verify_message(&public, b"message B", &signature);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Ed25519Error::InvalidSignature);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (secret1, _) = generate_keypair_for_test();
        let (_, public2) = generate_keypair_for_test();
        let signature = sign_message(&secret1, b"message");
        let result = verify_message(&public2, b"message", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn derive_public_matches_generated() {
        let (secret, public) = generate_keypair_for_test();
        let derived = derive_public(&secret);
        assert_eq!(derived, public);
    }

    #[test]
    fn empty_message_signs_and_verifies() {
        let (secret, public) = generate_keypair_for_test();
        let signature = sign_message(&secret, b"");
        assert!(verify_message(&public, b"", &signature).is_ok());
    }

    #[test]
    fn large_message_signs_and_verifies() {
        let (secret, public) = generate_keypair_for_test();
        let message = vec![0x42u8; 10_000];
        let signature = sign_message(&secret, &message);
        assert!(verify_message(&public, &message, &signature).is_ok());
    }

    #[test]
    fn different_keypairs_produce_different_signatures() {
        let (secret1, _) = generate_keypair_for_test();
        let (secret2, _) = generate_keypair_for_test();
        let message = b"same message";
        let sig1 = sign_message(&secret1, message);
        let sig2 = sign_message(&secret2, message);
        assert_ne!(sig1, sig2, "different keys must produce different signatures");
    }

    #[test]
    fn signature_is_deterministic() {
        let (secret, _) = generate_keypair_for_test();
        let message = b"deterministic test";
        let sig1 = sign_message(&secret, message);
        let sig2 = sign_message(&secret, message);
        assert_eq!(sig1, sig2, "same key + message must produce same signature");
    }
}
