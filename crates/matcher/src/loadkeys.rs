//! Deterministic identities for load generation and benchmarks.
//!
//! **Development and benchmarking only.** Every key here is derivable by
//! anyone, so any account funded at one of these addresses can be spent by
//! anyone. The module exists only with the `dev-identities` feature, which a
//! production build does not enable, and `oxide-matcher` only funds these
//! accounts when started with `--fund-loadgen-keys` (and built with its own
//! `dev-identities` feature).
//!
//! `oxide-matcher` funds the *derived owner addresses* of these keys and
//! `oxide-loadgen` signs with them, which is how the standalone pair
//! exercises the real authenticated path (an order's `owner` must be the
//! address its key derives).

use crypto::ed25519::{Ed25519SecretKey, owner_address};
use primitives::Address;

/// The session key every loadgen session uses (a benchmark constant).
pub const SESSION_KEY: [u8; 32] = [0x5e; 32];

/// Account `i`'s ed25519 trading key: seed = `i` little-endian, zero padded.
#[must_use]
pub fn ed_key(i: u32) -> Ed25519SecretKey {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&i.to_le_bytes());
    Ed25519SecretKey::from_bytes(&seed)
}

/// Account `i`'s ed25519-derived owner address.
#[must_use]
pub fn ed_owner(i: u32) -> Address {
    owner_address(&ed_key(i).verifying_key())
}

/// Account `i`'s EVM (secp256k1) secret key. The marker byte keeps it
/// nonzero, hence a valid key, for every `i`.
#[must_use]
pub fn evm_key(i: u32) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..4].copy_from_slice(&i.to_le_bytes());
    k[4] = 0xE1;
    k
}

/// Account `i`'s EVM address.
///
/// # Panics
///
/// Never for keys from [`evm_key`] (always a valid secp256k1 secret).
#[must_use]
pub fn evm_address(i: u32) -> Address {
    crypto::secp::signable_pubkey_address(&evm_key(i)).expect("evm_key is a valid secp256k1 secret")
}

/// The gateway key loadgen certifies batches with (`oxide-loadgen
/// --print-gateway-key` prints its public half for `--gateway-keys`).
#[must_use]
pub fn gateway_key() -> Ed25519SecretKey {
    Ed25519SecretKey::from_bytes(&[0xAB; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_deterministic_distinct_and_valid() {
        assert_eq!(ed_owner(3), ed_owner(3));
        assert_ne!(ed_owner(3), ed_owner(4));
        assert_ne!(evm_address(3), evm_address(4));
        assert_ne!(ed_owner(3), evm_address(3));
        // evm keys must be valid for a wide range of indices
        for i in [0u32, 1, 255, 65_535, u32::MAX] {
            let _ = evm_address(i);
        }
    }
}
