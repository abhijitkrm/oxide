//! EIP-712 typed-data hashing for native module transaction signing.
//!
//! Native (non-EVM) module transactions — bank transfers, staking
//! delegations, exchange orders — are authenticated by a secp256k1
//! signature over an [EIP-712] typed-data digest. This is the same
//! signing scheme `MetaMask` implements as `eth_signTypedData_v4`, so a
//! hardware wallet or browser wallet can sign a native transaction
//! without any chain-specific plugin.
//!
//! # Why secp256k1 + EIP-712 for native txs
//!
//! The crypto crate also ships Ed25519 (`ed25519` module), which is
//! faster to verify and has no malleability. We authenticate native
//! txs with secp256k1 anyway for two reasons:
//!
//! 1. **Wallet support**: `eth_signTypedData_v4` is the only
//!    structured-data signing method `MetaMask` and Ledger expose. An
//!    Ed25519 scheme would need custom wallet software before any
//!    user could sign a delegation or an order.
//! 2. **Unified account space**: the recovered signer is an
//!    Ethereum-style address (`keccak256(pubkey)[12..]`), identical
//!    to the EVM account space — one keypair controls the EVM
//!    account *and* the native bank/staking/exchange identity (the
//!    cosmos-evm model).
//!
//! # Typed-data schema
//!
//! Domain (chain-bound, per EIP-712):
//! `EIP712Domain(string name,string version,uint256 chainId)` with
//! `name = "Oxide"`, `version = "1"`, `chainId` from chain config.
//!
//! Message (envelope-level — the payload is opaque to the signer
//! but bound byte-exactly):
//! `Tx(address sender,uint64 nonce,uint64 fee,uint8 moduleId,bytes payload)`
//!
//! The digest the wallet signs is
//! `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash(message))`.
//! Because `payload` is hashed into the struct, the signature binds
//! the exact module message — a relayer cannot swap in a different
//! message for the same signer. `nonce`, `fee`, and `moduleId` are
//! likewise bound, and `chainId` in the domain separator prevents
//! cross-chain replay.
//!
//! # Per-message typed schemas
//!
//! This is the envelope-level schema: `MetaMask` displays `nonce`,
//! `fee`, `moduleId`, and the `payload` hex. Richer per-message
//! display (e.g. showing "Delegate 100 OXIDE to validator X" instead
//! of opaque payload bytes) requires each module to map its binary
//! messages onto additional EIP-712 types — that is a wallet-UX
//! refinement layered on top of this format, not a change to the
//! wire format or verification path (the module's message bytes are
//! already committed by `payload`).
//!
//! # Reference
//!
//! - [EIP-712: Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)

use primitives::Address;

use crate::secp::{self, RecoverableSignature, SecpError};

/// The EIP-712 domain type string we implement.
///
/// Only `name`, `version`, and `chainId` are bound — the
/// `verifyingContract` field is omitted because there is no
/// verifying contract: the domain is the chain itself. Omitting
/// unused fields is permitted by the EIP-712 spec (the type string
/// is hashed verbatim, so whatever fields we declare are what the
/// wallet must supply).
const DOMAIN_TYPE_STR: &str = "EIP712Domain(string name,string version,uint256 chainId)";

/// The transaction message type string.
///
/// Field order and types are part of the signing protocol: changing
/// any of them changes `tx_type_hash` and therefore every produced
/// and verified digest — this string must never be edited in place.
/// A schema change requires a new type string and a new envelope
/// version.
const TX_TYPE_STR: &str = "Tx(address sender,uint64 nonce,uint64 fee,uint8 moduleId,bytes payload)";

/// The domain name shown to the user by the wallet and mixed into
/// the domain separator. This is the chain's public name.
const DOMAIN_NAME: &str = "Oxide";

/// The domain version. Bump this only on a breaking change to the
/// signing schema — wallets cache domain parameters and a version
/// bump invalidates previously signed messages.
const DOMAIN_VERSION: &str = "1";

/// keccak256 of `DOMAIN_TYPE_STR`, the `EIP712Domain` type hash.
fn domain_type_hash() -> [u8; 32] {
    secp::keccak256(DOMAIN_TYPE_STR.as_bytes())
}

/// keccak256 of `TX_TYPE_STR`, the `Tx` message type hash.
fn tx_type_hash() -> [u8; 32] {
    secp::keccak256(TX_TYPE_STR.as_bytes())
}

/// ABI-encode a `u64` as an EIP-712/ABI word (32-byte big-endian).
fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// ABI-encode a `u8` as a 32-byte big-endian word.
fn word_u8(v: u8) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[31] = v;
    w
}

/// ABI-encode a 20-byte address as a 32-byte left-padded word.
fn word_addr(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a.0);
    w
}

/// The EIP-712 domain separator for the given chain ID.
///
/// `domainSeparator = keccak256(typeHash ‖ keccak256(name) ‖
/// keccak256(version) ‖ chainId)` — the ABI word encodings of the
/// hashed strings plus the 32-byte chain ID, hashed as a
/// 4-word preimage per the spec.
#[must_use]
pub fn domain_separator(chain_id: u64) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(4 * 32);
    preimage.extend_from_slice(&domain_type_hash());
    preimage.extend_from_slice(&secp::keccak256(DOMAIN_NAME.as_bytes()));
    preimage.extend_from_slice(&secp::keccak256(DOMAIN_VERSION.as_bytes()));
    preimage.extend_from_slice(&word_u64(chain_id));
    secp::keccak256(&preimage)
}

/// The EIP-712 struct hash of a `Tx` message.
///
/// `structHash = keccak256(txTypeHash ‖ sender ‖ nonce ‖ fee ‖
/// moduleId ‖ keccak256(payload))` — six 32-byte words where the
/// dynamic `bytes payload` member is replaced by its hash, per the
/// spec's rule for variable-length members.
#[must_use]
pub fn tx_struct_hash(
    sender: &Address,
    nonce: u64,
    fee: u64,
    module_id: u8,
    payload: &[u8],
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(6 * 32);
    preimage.extend_from_slice(&tx_type_hash());
    preimage.extend_from_slice(&word_addr(sender));
    preimage.extend_from_slice(&word_u64(nonce));
    preimage.extend_from_slice(&word_u64(fee));
    preimage.extend_from_slice(&word_u8(module_id));
    preimage.extend_from_slice(&secp::keccak256(payload));
    secp::keccak256(&preimage)
}

/// The full EIP-712 signing digest for a native transaction:
/// `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)`.
///
/// This is the 32-byte value a wallet produces via
/// `eth_signTypedData_v4` and the value the verifier feeds to
/// [`secp::recover_sender`].
#[must_use]
pub fn tx_signing_digest(
    chain_id: u64,
    sender: &Address,
    nonce: u64,
    fee: u64,
    module_id: u8,
    payload: &[u8],
) -> [u8; 32] {
    let struct_hash = tx_struct_hash(sender, nonce, fee, module_id, payload);
    let mut preimage = Vec::with_capacity(2 + 64);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(&domain_separator(chain_id));
    preimage.extend_from_slice(&struct_hash);
    secp::keccak256(&preimage)
}

/// Sign a native transaction with a secp256k1 private key.
///
/// For tests, tooling, and the reference signer — production
/// signing happens in the user's wallet (`MetaMask` / Ledger), not
/// in this crate.
///
/// # Errors
///
/// Returns [`SecpError::InvalidSignature`] if the private key is
/// malformed.
pub fn sign_tx(
    privkey: &[u8],
    chain_id: u64,
    sender: &Address,
    nonce: u64,
    fee: u64,
    module_id: u8,
    payload: &[u8],
) -> Result<RecoverableSignature, SecpError> {
    let digest = tx_signing_digest(chain_id, sender, nonce, fee, module_id, payload);
    secp::sign(privkey, &digest)
}

/// Verify a native transaction signature and return the recovered
/// signer address.
///
/// The caller compares the returned address against the envelope's
/// declared sender — equality is what authenticates the sender
/// field.
///
/// # Errors
///
/// Returns [`SecpError`] if the signature is malformed, has a
/// high-s value (EIP-2 malleability), or an invalid recovery ID.
pub fn verify_tx_sender(
    chain_id: u64,
    sender: &Address,
    nonce: u64,
    fee: u64,
    module_id: u8,
    payload: &[u8],
    sig: &RecoverableSignature,
) -> Result<Address, SecpError> {
    let digest = tx_signing_digest(chain_id, sender, nonce, fee, module_id, payload);
    secp::recover_sender(&digest, &sig.sig, sig.recid.as_u8())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp::{self, RecoveryId};

    fn hex(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The canonical EIP-712 known-answer test: the `Mail` example
    /// domain separator from the spec.
    ///
    /// The spec's domain uses a 4-field `EIP712Domain` (with
    /// `verifyingContract`) — this test re-encodes that domain with
    /// the same word-at-a-time scheme our production path uses and
    /// checks it against the published vector
    /// `0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f`.
    /// Matching the spec's own vector proves our primitive encoding
    /// (typeHash ‖ keccak(name) ‖ keccak(version) ‖ chainId) is
    /// byte-exact.
    #[test]
    fn eip712_encoding_matches_spec_mail_vector() {
        let domain_type = secp::keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let mut preimage = Vec::with_capacity(5 * 32);
        preimage.extend_from_slice(&domain_type);
        preimage.extend_from_slice(&secp::keccak256(b"Ether Mail"));
        preimage.extend_from_slice(&secp::keccak256(b"1"));
        preimage.extend_from_slice(&word_u64(1));
        // 0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC left-padded to 32.
        let contract = hex("CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC");
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&contract);
        preimage.extend_from_slice(&word);
        let sep = secp::keccak256(&preimage);
        assert_eq!(
            sep.as_slice(),
            &hex("f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f")[..],
            "encoding must reproduce the EIP-712 spec's Mail domainSeparator"
        );
    }

    /// Known-answer test for our own domain separator (chain 1) and
    /// a full `Tx` signing digest — computed independently against
    /// the spec's encoding rules (see devlog).
    #[test]
    fn domain_separator_and_digest_known_answer() {
        assert_eq!(
            domain_separator(1).as_slice(),
            &hex("68f9dc83056daa9742a3399bc39fcc7f1b9d49e8ddeb63a2a4adcbc0c33c2a17")[..],
        );
        // sender = 0x1111…, nonce = 5, fee = 100, moduleId = 1,
        // payload = [0x01] ‖ 0x2222… ‖ 1000_u64_le (a bank transfer).
        let sender = Address([0x11; 20]);
        let mut payload = vec![1u8];
        payload.extend_from_slice(&[0x22; 20]);
        payload.extend_from_slice(&1000u64.to_le_bytes());
        let digest = tx_signing_digest(1, &sender, 5, 100, 1, &payload);
        assert_eq!(
            digest.as_slice(),
            &hex("b19179617c0e678139f7b0afaf0f4374d9449fb9c7b38d13e477130b16ec04f6")[..],
        );
    }

    /// A signature produced for a transaction verifies and recovers
    /// the signer's address.
    #[test]
    fn sign_and_verify_roundtrip() {
        let (privkey, sender) = secp::generate_keypair_for_test();
        let payload = b"delegate-msg";
        let sig = sign_tx(&privkey, 1, &sender, 7, 50, 2, payload).expect("signing must succeed");
        let recovered =
            verify_tx_sender(1, &sender, 7, 50, 2, payload, &sig).expect("verify must succeed");
        assert_eq!(recovered, sender);
    }

    /// Mutating any signed field must fail verification — the
    /// signature binds nonce, fee, module ID, and payload.
    #[test]
    fn tampered_fields_fail_verification() {
        let (privkey, sender) = secp::generate_keypair_for_test();
        let payload = b"payload-bytes";
        let sig = sign_tx(&privkey, 1, &sender, 3, 10, 5, payload).unwrap();
        // Wrong nonce.
        assert_ne!(verify_tx_sender(1, &sender, 4, 10, 5, payload, &sig), Ok(sender));
        // Wrong fee.
        assert_ne!(verify_tx_sender(1, &sender, 3, 11, 5, payload, &sig), Ok(sender));
        // Wrong module.
        assert_ne!(verify_tx_sender(1, &sender, 3, 10, 4, payload, &sig), Ok(sender));
        // Wrong payload.
        assert_ne!(verify_tx_sender(1, &sender, 3, 10, 5, b"other", &sig), Ok(sender));
        // Wrong declared sender (same signature — digest binds the
        // declared sender, so recovery yields a different address).
        let other = Address([0xAB; 20]);
        assert_ne!(verify_tx_sender(1, &other, 3, 10, 5, payload, &sig), Ok(other));
    }

    /// Cross-chain replay: a signature made for chain 1 must not
    /// verify on chain 2 — the domain separator binds the chain ID.
    #[test]
    fn signature_is_chain_bound() {
        let (privkey, sender) = secp::generate_keypair_for_test();
        let sig = sign_tx(&privkey, 1, &sender, 0, 0, 1, b"x").unwrap();
        // Same chain verifies.
        assert_eq!(verify_tx_sender(1, &sender, 0, 0, 1, b"x", &sig).unwrap(), sender);
        // A different chain ID changes the digest — recovery produces
        // a different (deterministic garbage) address, so the tx is
        // rejected on that chain.
        assert_ne!(verify_tx_sender(2, &sender, 0, 0, 1, b"x", &sig).unwrap(), sender);
    }

    /// A valid signature for one sender never verifies as another.
    #[test]
    fn signature_does_not_transfer_to_other_sender() {
        let (priv_a, sender_a) = secp::generate_keypair_for_test();
        let (_priv_b, sender_b) = secp::generate_keypair_for_test();
        let sig = sign_tx(&priv_a, 1, &sender_a, 0, 0, 1, b"m").unwrap();
        assert_ne!(verify_tx_sender(1, &sender_b, 0, 0, 1, b"m", &sig).unwrap(), sender_b);
    }

    /// The recovery ID must be 0/1 in the canonical wire form —
    /// `RecoveryId::try_from_u8` rejects 2/3 at the type level, and
    /// the executor rejects anything > 1 before constructing the
    /// signature. Flipping the valid recovery ID (0 ↔ 1) must fail
    /// verification, not recover the same address.
    #[test]
    fn recid_out_of_range_fails() {
        // The type-level guard: recovery IDs 2/3 cannot be built.
        assert!(RecoveryId::try_from_u8(2).is_err());
        assert!(RecoveryId::try_from_u8(3).is_err());
        let (privkey, sender) = secp::generate_keypair_for_test();
        let sig = sign_tx(&privkey, 1, &sender, 0, 0, 1, b"x").unwrap();
        // Flipping 0↔1 recovers the complementary-but-wrong point.
        let flipped = RecoveryId::new(1 - sig.recid.as_u8());
        let bad = RecoverableSignature { sig: sig.sig, recid: flipped };
        assert_ne!(verify_tx_sender(1, &sender, 0, 0, 1, b"x", &bad).unwrap_or(sender), sender);
    }
}
