//! BLS12-381 signature type stubs for oxideBFT (Phase 1).
//!
//! # Phase 0 scope
//!
//! Phase 0 defines the *types* and *traits* oxideBFT will program
//! against. The actual signing and verification (via `blst` or
//! `bls12_381`) lands in Phase 1 when the first consumer (oxideBFT's
//! vote/QC pipeline) exists. This avoids pulling a BLS dependency
//! before there is code that uses it, while ensuring the type shape
//! is settled — Phase 1 fills in the trait impls, not the types.
//!
//! # Why BLS12-381
//!
//! BLS on the BLS12-381 curve supports signature aggregation: N
//! validators' votes compress to one group element, and verification
//! is one pairing check. This is the throughput lever for oxideBFT's
//! quorum certificates (docs/oxidebft-spec.md §3). Ed25519 QCs are a
//! list of N signatures — N× the wire size and N× the verify cost.
//!
//! # Wire format
//!
//! Public keys and signatures travel as their compressed forms (48
//! and 96 bytes respectively), via the codec's fixed-width encoding.
//! The lengths are part of the type, so no length prefix on the wire.
//! Aggregate signatures are also 96 bytes (one compressed group
//! element); the signer set is carried separately as a bitmap.

use codec::{Decode, DecodeError, Encode, Reader};
use primitives::Hash;

/// A BLS12-381 public key in compressed form (48 bytes).
///
/// Used to verify signatures and identify validators in the quorum
/// certificate's signer bitmap. The compressed form is the wire
/// format; Phase 1's `blst` integration decompresses for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; PublicKey::LEN]);

impl PublicKey {
    /// Compressed BLS12-381 public key length in bytes.
    pub const LEN: usize = 48;

    /// Construct from exactly 48 bytes.
    ///
    /// # Errors
    /// Returns [`WrongSliceLength`](primitives::WrongSliceLength) if
    /// the slice is not exactly 48 bytes. No truncation, ever — a
    /// short attacker-controlled slice must not masquerade as a key.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, primitives::WrongSliceLength> {
        let fixed = bytes
            .try_into()
            .map_err(|_| primitives::WrongSliceLength { expected: Self::LEN, got: bytes.len() })?;
        Ok(Self(fixed))
    }

    /// Constant bytes view.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for PublicKey {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl<'a> Decode<'a> for PublicKey {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let bytes = reader.read_slice(Self::LEN)?;
        Self::from_slice(bytes)
            .map_err(|e| DecodeError::WrongSliceLength { expected: e.expected, got: e.got })
    }
}

/// A BLS12-381 signature in compressed form (96 bytes).
///
/// A single validator's signature over a domain-separated hash (see
/// [`crate::hash`]). Phase 1's `blst` integration provides `verify`;
/// Phase 0 carries the type so the wire format and codec are settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature(pub [u8; Signature::LEN]);

impl Signature {
    /// Compressed BLS12-381 signature length in bytes.
    pub const LEN: usize = 96;

    /// Construct from exactly 96 bytes.
    ///
    /// # Errors
    /// Returns [`WrongSliceLength`](primitives::WrongSliceLength) if
    /// the slice is not exactly 96 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, primitives::WrongSliceLength> {
        let fixed = bytes
            .try_into()
            .map_err(|_| primitives::WrongSliceLength { expected: Self::LEN, got: bytes.len() })?;
        Ok(Self(fixed))
    }

    /// Constant bytes view.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for Signature {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl<'a> Decode<'a> for Signature {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let bytes = reader.read_slice(Self::LEN)?;
        Self::from_slice(bytes)
            .map_err(|e| DecodeError::WrongSliceLength { expected: e.expected, got: e.got })
    }
}

/// An aggregate BLS12-381 signature (96 bytes — one compressed group
/// element). The signer set is carried separately as a bitmap in the
/// quorum certificate; the aggregate is the sum of the individual
/// signatures over the same message.
///
/// Verification (Phase 1): check that the aggregate signature is valid
/// under the aggregate of the signers' public keys, over the
/// domain-separated message. This is the single-pairing check that
/// makes BLS QCs cheap to verify regardless of validator count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AggregateSignature(pub [u8; AggregateSignature::LEN]);

impl AggregateSignature {
    /// Compressed aggregate signature length in bytes (same as a
    /// single signature — one group element).
    pub const LEN: usize = 96;

    /// Construct from exactly 96 bytes.
    ///
    /// # Errors
    /// Returns [`WrongSliceLength`](primitives::WrongSliceLength) if
    /// the slice is not exactly 96 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, primitives::WrongSliceLength> {
        let fixed = bytes
            .try_into()
            .map_err(|_| primitives::WrongSliceLength { expected: Self::LEN, got: bytes.len() })?;
        Ok(Self(fixed))
    }

    /// Constant bytes view.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The all-zero aggregate signature — a placeholder for "no
    /// signatures" (e.g. a genesis QC with no signers). Phase 1
    /// verification rejects this as invalid; it exists so genesis
    /// blocks can carry a syntactically valid QC field.
    pub const ZERO: Self = Self([0u8; Self::LEN]);
}

impl Encode for AggregateSignature {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl<'a> Decode<'a> for AggregateSignature {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let bytes = reader.read_slice(Self::LEN)?;
        Self::from_slice(bytes)
            .map_err(|e| DecodeError::WrongSliceLength { expected: e.expected, got: e.got })
    }
}

/// An index into the epoch's validator set. Used in the quorum
/// certificate's signer bitmap to identify which validators signed.
/// `u16` supports up to 65535 validators — well beyond the 20–50
/// Phase 1 target and the ~1000-validator ceiling of comparable BFT
/// chains.
pub type ValidatorIndex = u16;

/// A message that can be signed by a BLS signer. Implemented by
/// consensus objects (votes, timeout messages) that carry a
/// domain-separated hash. Phase 1's signer calls `signing_hash` to
/// get the message to sign.
///
/// This trait decouples the signing primitive from the consensus
/// types: oxideBFT signs votes and timeouts, but the BLS crate doesn't
/// need to know about those types — it hashes whatever implements
/// `Signable`.
pub trait Signable {
    /// The domain separation tag for this message type.
    fn domain(&self) -> crate::hash::Domain;

    /// The bytes to be hashed (after the domain tag). The domain tag
    /// is prepended by the hasher; this method returns only the payload.
    fn signing_bytes(&self) -> &[u8];

    /// Convenience: the domain-separated hash to sign. Phase 1's
    /// `blst` integration signs this 32-byte digest.
    fn signing_hash(&self) -> Hash {
        crate::hash::Hasher::hash_one(self.domain(), self.signing_bytes())
    }
}

#[cfg(test)]
mod tests {
    //! Wire-form pinning and round-trip for BLS types. The actual
    //! sign/verify/aggregate operations are Phase 1; Phase 0 pins the
    //! types and their codec so the wire format is settled before
    //! oxideBFT is built.

    use super::*;

    fn roundtrip<T>(value: &T, wire: &[u8])
    where
        T: for<'a> codec::Codec<'a> + PartialEq + std::fmt::Debug + Clone,
    {
        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(buf, wire, "wire form mismatch");
        let mut r = Reader::new(&buf);
        let decoded = T::decode(&mut r).expect("decode");
        assert_eq!(&decoded, value, "round-trip");
        assert!(r.is_empty(), "decode must consume exactly its bytes");
    }

    #[test]
    fn public_key_wire() {
        let pk = PublicKey([0xAB; PublicKey::LEN]);
        roundtrip(&pk, &[0xAB; PublicKey::LEN]);
    }

    #[test]
    fn signature_wire() {
        let sig = Signature([0xCD; Signature::LEN]);
        roundtrip(&sig, &[0xCD; Signature::LEN]);
    }

    #[test]
    fn aggregate_signature_wire() {
        let agg = AggregateSignature([0xEF; AggregateSignature::LEN]);
        roundtrip(&agg, &[0xEF; AggregateSignature::LEN]);
    }

    #[test]
    fn aggregate_signature_zero_is_all_zeros() {
        assert_eq!(AggregateSignature::ZERO.0, [0u8; AggregateSignature::LEN]);
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(PublicKey::from_slice(&[0u8; 47]).is_err());
        assert!(PublicKey::from_slice(&[0u8; 49]).is_err());
        assert!(Signature::from_slice(&[0u8; 95]).is_err());
        assert!(Signature::from_slice(&[0u8; 97]).is_err());
        assert!(AggregateSignature::from_slice(&[0u8; 95]).is_err());
        assert!(AggregateSignature::from_slice(&[0u8; 97]).is_err());
    }

    #[test]
    fn from_slice_accepts_exact_length() {
        assert!(PublicKey::from_slice(&[0u8; PublicKey::LEN]).is_ok());
        assert!(Signature::from_slice(&[0u8; Signature::LEN]).is_ok());
        assert!(AggregateSignature::from_slice(&[0u8; AggregateSignature::LEN]).is_ok());
    }

    /// A trivial `Signable` for testing the `signing_hash` helper.
    struct DummyMessage {
        payload: Vec<u8>,
    }

    impl Signable for DummyMessage {
        fn domain(&self) -> crate::hash::Domain {
            crate::hash::Domain::Vote
        }
        fn signing_bytes(&self) -> &[u8] {
            &self.payload
        }
    }

    #[test]
    fn signing_hash_is_domain_separated() {
        let msg = DummyMessage { payload: b"vote-payload".to_vec() };
        let h = msg.signing_hash();
        // The signing hash must equal hash_one(Vote, payload) —
        // i.e. the domain tag is applied. A bare blake3 of the payload
        // (no domain tag) must differ.
        let expected = crate::hash::Hasher::hash_one(crate::hash::Domain::Vote, b"vote-payload");
        assert_eq!(h, expected);
        let bare = crate::hash::Hasher::hash_one(crate::hash::Domain::Block, b"vote-payload");
        assert_ne!(h, bare, "domain tag must affect the hash");
    }
}
