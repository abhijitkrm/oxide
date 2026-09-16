//! secp256k1 ECDSA recovery for EVM transactions.
//!
//! This module provides sender recovery from signed EVM transactions
//! (Phase A of the EVM production-readiness program). The EVM module
//! never trusts the envelope sender — it recovers the sender from the
//! signature inside `handle()`, so security is enforced at the only
//! place that matters: execution.
//!
//! # Why secp256k1 (C bindings), not k256 (pure Rust)
//!
//! `secp256k1` (the C-vetted libsecp256k1 binding) is reth's exact
//! choice, is already a transitive dependency via revm, and is
//! ~2-3x faster than the pure-Rust `k256` crate for recovery. Using
//! the same library as our reference implementation (reth) eliminates
//! a class of subtle compatibility bugs.
//!
//! # Invariants
//!
//! - `recover_sender` is deterministic: the same (`msg_hash`, `sig`, `recid`)
//!   always yields the same address or `Err`.
//! - Recovered addresses are Ethereum-compatible: the address is the
//!   last 20 bytes of `keccak256(pubkey)`.
//! - Errors distinguish byzantine behavior (invalid signature — penalize
//!   the peer) from operational failures (should not happen with valid
//!   input).

use primitives::Address;

/// secp256k1 recovery and signing errors.
///
/// Byzantine errors (invalid signature, invalid recovery ID) indicate
/// a peer sent garbage — the caller should penalize or disconnect.
/// Operational errors (should not occur with valid input) indicate
/// a bug in our code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecpError {
    /// The signature is malformed or does not verify against the
    /// message hash. Byzantine — the signer is faulty or malicious.
    InvalidSignature,
    /// The recovery ID (v) is not 0, 1, 2, or 3. Byzantine.
    InvalidRecoveryId(u8),
    /// The message hash is not 32 bytes. Operational — caller bug.
    InvalidMessageHashLen(usize),
}

impl std::fmt::Display for SecpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "invalid secp256k1 signature"),
            Self::InvalidRecoveryId(v) => write!(f, "invalid recovery id: {v}"),
            Self::InvalidMessageHashLen(n) => write!(f, "message hash must be 32 bytes, got {n}"),
        }
    }
}

impl std::error::Error for SecpError {}

/// The recovery ID (`v` in Ethereum tx signatures).
///
/// For legacy transactions: `v = 27 + recovery_id` (pre-EIP-155) or
/// `v = 35 + 2 * chain_id + recovery_id` (EIP-155). For EIP-1559/2930:
/// `v = recovery_id` (0 or 1, stored as a `u8` in the RLP).
///
/// Only values 0 and 1 are valid for standard ECDSA recovery. Values
/// 2 and 3 exist in the secp256k1 library for completeness (provably
/// unused keys) but never appear in Ethereum signatures. Accepting
/// them would allow a malicious peer to submit signatures that
/// recover to arbitrary/unused pubkeys, enabling signature
/// malleability and `DoS` vectors. We reject them at the parse boundary
/// so they never reach `recover_ecdsa`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryId(u8);

impl RecoveryId {
    /// Create a recovery ID from a raw byte. Returns `Err` if the
    /// value is not 0 or 1 — the only valid Ethereum recovery IDs.
    ///
    /// # Errors
    ///
    /// Returns [`SecpError::InvalidRecoveryId`] if `v > 1`. Values 2
    /// and 3 are rejected to prevent signature malleability (they
    /// correspond to provably-unused keys and never appear in real
    /// Ethereum signatures).
    pub const fn try_from_u8(v: u8) -> Result<Self, SecpError> {
        if v <= 1 { Ok(Self(v)) } else { Err(SecpError::InvalidRecoveryId(v)) }
    }

    /// Create a recovery ID, panicking on invalid input. For tests
    /// and const contexts only.
    ///
    /// # Panics
    ///
    /// Panics if `v > 1`.
    #[must_use]
    pub const fn new(v: u8) -> Self {
        assert!(v <= 1, "recovery id must be 0 or 1");
        Self(v)
    }

    /// The raw byte value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Convert to the secp256k1 library's `RecoveryId` enum.
    ///
    /// `self.0` is guaranteed to be 0 or 1 by the constructors, so
    /// the 2/3 arms are unreachable.
    fn to_secp(self) -> secp256k1::ecdsa::RecoveryId {
        match self.0 {
            0 => secp256k1::ecdsa::RecoveryId::Zero,
            1 => secp256k1::ecdsa::RecoveryId::One,
            // Unreachable: `try_from_u8` and `new` reject 2/3.
            _ => unreachable!("recovery id 2/3 rejected at construction"),
        }
    }

    /// Convert from the secp256k1 library's `RecoveryId` enum.
    ///
    /// # Panics
    ///
    /// Panics on `RecoveryId::Two`/`Three`. These never occur in
    /// practice for valid secp256k1 keys (they correspond to
    /// provably-unused keys) and are rejected at the parse boundary
    /// by [`RecoveryId::try_from_u8`]. This is a defense-in-depth
    /// assertion: if the signing library ever yields 2/3, that is a
    /// bug worth surfacing loudly rather than silently producing a
    /// malleable signature.
    fn from_secp(recid: secp256k1::ecdsa::RecoveryId) -> Self {
        match recid {
            secp256k1::ecdsa::RecoveryId::Zero => Self(0),
            secp256k1::ecdsa::RecoveryId::One => Self(1),
            secp256k1::ecdsa::RecoveryId::Two => {
                panic!("secp256k1 yielded recovery id 2 (provably-unused key)")
            }
            secp256k1::ecdsa::RecoveryId::Three => {
                panic!("secp256k1 yielded recovery id 3 (provably-unused key)")
            }
        }
    }
}

/// A recoverable ECDSA signature: 64 bytes (r ‖ s) plus a recovery ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverableSignature {
    /// The 64-byte compact signature: `r` (32 bytes) ‖ `s` (32 bytes).
    pub sig: [u8; 64],
    /// The recovery ID (0 or 1 for standard Ethereum signatures).
    pub recid: RecoveryId,
}

impl RecoverableSignature {
    /// Create from raw bytes and a recovery ID. Returns `Err` if the
    /// signature is not 64 bytes or the recovery ID is invalid.
    ///
    /// # Errors
    ///
    /// Returns [`SecpError::InvalidSignature`] if `sig.len() != 64`.
    /// Returns [`SecpError::InvalidRecoveryId`] if `recid > 3`.
    pub fn from_bytes(sig: &[u8], recid: u8) -> Result<Self, SecpError> {
        if sig.len() != 64 {
            return Err(SecpError::InvalidSignature);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig);
        Ok(Self { sig: sig_arr, recid: RecoveryId::try_from_u8(recid)? })
    }
}

/// Recover an Ethereum address from a signed message.
///
/// Given the keccak256 hash of the signed payload, the 64-byte compact
/// signature (r ‖ s), and the recovery ID, this returns the 20-byte
/// Ethereum address (last 20 bytes of `keccak256(recovered_pubkey)`).
///
/// This is the core of EVM transaction authentication: the EVM module
/// calls this inside `handle()` to establish the true sender, never
/// trusting the envelope.
///
/// # Arguments
///
/// - `msg_hash`: 32-byte keccak256 hash of the signed payload.
/// - `sig`: 64-byte compact signature (r ‖ s).
/// - `recid`: Recovery ID (0 or 1 for standard Ethereum sigs).
///
/// # Errors
///
/// Returns [`SecpError::InvalidSignature`] if the signature is
/// malformed or does not verify.
/// Returns [`SecpError::InvalidRecoveryId`] if `recid > 3`.
/// Returns [`SecpError::InvalidMessageHashLen`] if `msg_hash.len() != 32`.
///
/// # Performance
///
/// Budget (criterion, `benches/tx_recover.rs`, M1 dev machine):
///   p50 ≈ 40µs single-thread (≥25k recoveries/s/core).
/// Gate: p50 < 50µs (plan.md §13 Phase A gate).
/// This is a hot path (per-tx in the mempool and per-tx in execution).
pub fn recover_sender(msg_hash: &[u8], sig: &[u8], recid: u8) -> Result<Address, SecpError> {
    // `n / 2` for secp256k1: 0x7FFF...B20A0 (computed from CURVE_ORDER).
    // Used for EIP-2 low-s enforcement (reject malleable high-s sigs).
    const HALF_ORDER: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];

    if msg_hash.len() != 32 {
        return Err(SecpError::InvalidMessageHashLen(msg_hash.len()));
    }
    let recid = RecoveryId::try_from_u8(recid)?;
    let recoverable = secp256k1::ecdsa::RecoverableSignature::from_compact(sig, recid.to_secp())
        .map_err(|_| SecpError::InvalidSignature)?;

    // EIP-2 low-s enforcement: reject signatures where `s` is in
    // the upper half of the curve order. High-s signatures are
    // malleable — `(r, s)` and `(r, n-s)` both verify against the
    // same message, producing two valid transaction hashes from
    // one signature. We extract `s` from the compact serialization
    // (bytes 32..64) and compare it to `n / 2` (half the secp256k1
    // curve order). Rejecting rather than silently normalizing lets
    // the caller see the original byzantine input.
    let standard_sig = recoverable.to_standard();
    let compact = standard_sig.serialize_compact();
    let s_bytes = &compact[32..64];
    if s_bytes > &HALF_ORDER[..] {
        return Err(SecpError::InvalidSignature);
    }

    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(msg_hash);
    let msg = secp256k1::Message::from_digest(hash_arr);

    let pubkey = secp256k1::SECP256K1
        .recover_ecdsa(msg, &recoverable)
        .map_err(|_| SecpError::InvalidSignature)?;

    // Ethereum address = last 20 bytes of keccak256(uncompressed pubkey
    // without the 0x04 prefix). The uncompressed pubkey is 65 bytes
    // (0x04 ‖ X ‖ Y); we hash bytes 1..65 (X ‖ Y, 64 bytes).
    let serialized = pubkey.serialize_uncompressed();
    let hash = keccak256(&serialized[1..65]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Ok(Address(addr))
}

/// Sign a message hash with a private key. For tests and tooling only
/// — production nodes never sign inside the crypto crate (the wallet
/// or validator key manager does that).
///
/// # Arguments
///
/// - `privkey`: 32-byte secp256k1 private key.
/// - `msg_hash`: 32-byte keccak256 hash of the payload to sign.
///
/// # Errors
///
/// Returns [`SecpError::InvalidSignature`] if the private key is
/// invalid or signing fails (extremely rare with valid input).
/// Returns [`SecpError::InvalidMessageHashLen`] if `msg_hash.len() != 32`.
pub fn sign(privkey: &[u8], msg_hash: &[u8]) -> Result<RecoverableSignature, SecpError> {
    if msg_hash.len() != 32 {
        return Err(SecpError::InvalidMessageHashLen(msg_hash.len()));
    }
    if privkey.len() != 32 {
        return Err(SecpError::InvalidSignature);
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(privkey);
    let secret =
        secp256k1::SecretKey::from_byte_array(key_arr).map_err(|_| SecpError::InvalidSignature)?;
    let mut hash_arr = [0u8; 32];
    hash_arr.copy_from_slice(msg_hash);
    let msg = secp256k1::Message::from_digest(hash_arr);
    let recoverable = secp256k1::SECP256K1.sign_ecdsa_recoverable(msg, &secret);
    let (recid, sig) = recoverable.serialize_compact();
    Ok(RecoverableSignature { sig, recid: RecoveryId::from_secp(recid) })
}

/// Derive the Ethereum address for a secp256k1 private key.
///
/// The address is the last 20 bytes of `keccak256` of the
/// uncompressed public key (bytes 1..65, skipping the 0x04 prefix).
/// Used by transaction builders so the declared sender is always the
/// signing key's own address — never a forged one.
///
/// # Errors
///
/// Returns `None` if the key is not a valid 32-byte secp256k1
/// secret.
#[must_use]
pub fn signable_pubkey_address(privkey: &[u8]) -> Option<Address> {
    if privkey.len() != 32 {
        return None;
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(privkey);
    let secret = secp256k1::SecretKey::from_byte_array(key_arr).ok()?;
    let pubkey = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &secret);
    let serialized = pubkey.serialize_uncompressed();
    let hash = keccak256(&serialized[1..65]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Some(Address(addr))
}

/// Generate a random private key for testing. Not for production use.
///
/// # Panics
///
/// Panics if the system RNG fails (indicates a broken test environment).
#[must_use]
pub fn generate_keypair_for_test() -> ([u8; 32], Address) {
    let mut rng = secp256k1::rand::rng();
    let (secret, pubkey) = secp256k1::SECP256K1.generate_keypair(&mut rng);
    let serialized = pubkey.serialize_uncompressed();
    let hash = keccak256(&serialized[1..65]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(&secret.secret_bytes());
    (privkey, Address(addr))
}

/// keccak-256 hash. Uses the `sha3` crate's `Keccak256` digest, which
/// is Ethereum's keccak256 (not NIST SHA3-256 — the padding differs).
/// Already a transitive dep via revm; declared explicitly here.
///
/// For EVM transaction hashing and address derivation, this is the
/// correct hash function.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A known-answer test using a fixed key and message. This pins
    /// the recovery implementation against a specific expected address.
    #[test]
    fn recover_sender_known_answer() {
        let (privkey, expected_addr) = generate_keypair_for_test();
        let msg = b"hello oxide";
        let msg_hash = keccak256(msg);
        let sig = sign(&privkey, &msg_hash).expect("sign must succeed");
        let recovered =
            recover_sender(&msg_hash, &sig.sig, sig.recid.as_u8()).expect("recover must succeed");
        assert_eq!(recovered, expected_addr, "recovered address must match keypair address");
    }

    #[test]
    fn recover_sender_round_trip_multiple_messages() {
        let (privkey, expected_addr) = generate_keypair_for_test();
        let msgs: &[&[u8]] = &[b"msg1", b"msg2", b"longer message here", b""];
        for msg in msgs {
            let hash = keccak256(msg);
            let sig = sign(&privkey, &hash).expect("sign must succeed");
            let recovered =
                recover_sender(&hash, &sig.sig, sig.recid.as_u8()).expect("recover must succeed");
            assert_eq!(recovered, expected_addr, "address must match for msg {msg:?}");
        }
    }

    #[test]
    fn recover_sender_rejects_tampered_signature() {
        let (privkey, expected_addr) = generate_keypair_for_test();
        let msg = b"hello";
        let hash = keccak256(msg);
        let mut sig = sign(&privkey, &hash).expect("sign must succeed");
        // Flip one bit in r. The tampered signature may still recover to
        // *some* public key (ECDSA admits many valid signatures for a
        // given message), but it must not recover to the original sender.
        sig.sig[0] ^= 0x01;
        match recover_sender(&hash, &sig.sig, sig.recid.as_u8()) {
            Err(SecpError::InvalidSignature) => { /* good: rejected */ }
            Ok(recovered) => {
                assert_ne!(
                    recovered, expected_addr,
                    "tampered sig must not recover to original sender"
                );
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn recover_sender_rejects_invalid_recovery_id() {
        let (privkey, _) = generate_keypair_for_test();
        let msg = b"hello";
        let hash = keccak256(msg);
        let sig = sign(&privkey, &hash).expect("sign must succeed");
        let result = recover_sender(&hash, &sig.sig, 4);
        assert!(matches!(result, Err(SecpError::InvalidRecoveryId(4))));
    }

    #[test]
    fn recover_sender_rejects_short_message_hash() {
        let (privkey, _) = generate_keypair_for_test();
        let msg = b"hello";
        let hash = keccak256(msg);
        let sig = sign(&privkey, &hash).expect("sign must succeed");
        let result = recover_sender(b"too short", &sig.sig, sig.recid.as_u8());
        assert!(matches!(result, Err(SecpError::InvalidMessageHashLen(9))));
    }

    #[test]
    fn recover_sender_rejects_short_signature() {
        let msg = b"hello";
        let hash = keccak256(msg);
        let result = recover_sender(&hash, b"too short", 0);
        assert!(matches!(result, Err(SecpError::InvalidSignature)));
    }

    #[test]
    fn keccak256_known_answer_empty_input() {
        // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let hash = keccak256(b"");
        let expected: [u8; 32] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(hash, expected, "keccak256(\"\") must match known answer");
    }

    #[test]
    fn keccak256_known_answer_abc() {
        // keccak256("abc") = 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
        let hash = keccak256(b"abc");
        let expected: [u8; 32] = [
            0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8,
            0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f,
            0xa1, 0x2d, 0x6c, 0x45,
        ];
        assert_eq!(hash, expected, "keccak256(\"abc\") must match known answer");
    }

    #[test]
    fn recovery_id_try_from_u8_bounds() {
        assert!(RecoveryId::try_from_u8(0).is_ok());
        assert!(RecoveryId::try_from_u8(1).is_ok());
        // Recovery IDs 2 and 3 are rejected to prevent signature
        // malleability (they correspond to provably-unused keys and
        // never appear in valid Ethereum signatures).
        assert!(RecoveryId::try_from_u8(2).is_err());
        assert!(RecoveryId::try_from_u8(3).is_err());
        assert!(RecoveryId::try_from_u8(4).is_err());
        assert!(RecoveryId::try_from_u8(255).is_err());
    }

    #[test]
    fn recovery_id_new_rejects_2_and_3() {
        // `new` is const and panics on invalid input; verify the
        // panic message for 2/3 (defense-in-depth against malleability).
        assert!(std::panic::catch_unwind(|| RecoveryId::new(2)).is_err());
        assert!(std::panic::catch_unwind(|| RecoveryId::new(3)).is_err());
        assert!(std::panic::catch_unwind(|| RecoveryId::new(4)).is_err());
        // 0 and 1 must not panic.
        let _ = RecoveryId::new(0);
        let _ = RecoveryId::new(1);
    }

    #[test]
    fn different_keys_recover_to_different_addresses() {
        let (privkey1, addr1) = generate_keypair_for_test();
        let (privkey2, addr2) = generate_keypair_for_test();
        assert_ne!(privkey1, privkey2, "RNG must produce different keys");
        assert_ne!(addr1, addr2, "different keys must have different addresses");
        let msg = b"same message";
        let hash = keccak256(msg);
        let sig1 = sign(&privkey1, &hash).expect("sign 1");
        let sig2 = sign(&privkey2, &hash).expect("sign 2");
        let rec1 = recover_sender(&hash, &sig1.sig, sig1.recid.as_u8()).expect("recover 1");
        let rec2 = recover_sender(&hash, &sig2.sig, sig2.recid.as_u8()).expect("recover 2");
        assert_eq!(rec1, addr1);
        assert_eq!(rec2, addr2);
        assert_ne!(rec1, rec2, "different keys must recover to different addresses");
    }
}
