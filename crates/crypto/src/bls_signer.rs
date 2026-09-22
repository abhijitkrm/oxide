//! BLS12-381 signing, verification, aggregation, and
//! proof-of-possession via `blst`.
//!
//! This module provides the cryptographic operations that the oxideBFT
//! engine uses to sign votes, form quorum certificates, and verify
//! them. The wire types ([`PublicKey`], [`Signature`],
//! [`AggregateSignature`]) are defined in [`crate::bls`]; this module
//! adds the operations.
//!
//! # Why `blst`
//!
//! `blst` is the Supranational BLS12-381 library — the production
//! standard used by Ethereum 2.0, Algorand, and others. It's the
//! fastest BLS implementation in Rust (constant-time, assembly-optimized
//! for `x86_64` and `aarch64`). The `min_pk` profile (48-byte PKs, 96-byte
//! sigs) matches our wire types.
//!
//! # Domain separation
//!
//! All signing uses a DST (domain separation tag) derived from
//! [`crate::hash::Domain`]. The DST is the domain's name as a UTF-8
//! string, ensuring cross-domain signature non-malleability (a vote
//! signature can't be replayed as a timeout signature).
//!
//! # Aggregation
//!
//! BLS aggregation compresses N validators' signatures over the *same*
//! message into one 96-byte aggregate. Verification is one pairing
//! check regardless of N — the throughput lever for oxideBFT QCs. For
//! votes over *different* messages, use `aggregate_verify` (which
//! does N pairings internally).

use blst::BLST_ERROR;
use blst::min_pk::{
    AggregateSignature as BlstAggSig, PublicKey as BlstPk, SecretKey, Signature as BlstSig,
};

use crate::bls::{AggregateSignature, PublicKey, Signature};
use crate::hash::Domain;

/// The DST (domain separation tag) for a [`Domain`].
///
/// BLS signing requires a DST to prevent cross-protocol signature
/// reuse. We use the domain's name as a fixed string — this is
/// simpler than the domain's numeric discriminant and equally
/// unforgeable (the name is part of the consensus contract).
fn dst(domain: Domain) -> &'static [u8] {
    match domain {
        Domain::Block => b"oxide/block",
        Domain::Transaction => b"oxide/transaction",
        Domain::Vote => b"oxide/vote",
        Domain::QuorumCertificate => b"oxide/qc",
        Domain::Timeout => b"oxide/timeout",
        Domain::MmrNode => b"oxide/mmr-node",
        Domain::MmrLeaf => b"oxide/mmr-leaf",
        Domain::StateRoot => b"oxide/state-root",
        Domain::MmrRoot => b"oxide/mmr-root",
        Domain::Proposal => b"oxide/proposal",
        Domain::ValidatorAddress => b"oxide/validator-address",
        Domain::StateSyncChunk => b"oxide/statesync-chunk",
        Domain::BodyShardLeaf => b"oxide/body-shard-leaf",
        Domain::BodyShardNode => b"oxide/body-shard-node",
        Domain::ExecAttest => b"oxide/exec-attest",
        Domain::BlsPop => b"oxide/bls-pop",
        // Never used for BLS signing (Ed25519 owner derivation hashes
        // via BLAKE3, not this DST) — the arm exists only because the
        // match is exhaustive over `Domain`.
        Domain::Ed25519Owner => b"oxide/ed25519-owner",
        // Never signed either — nonce-leaf hashes are BLAKE3, not
        // BLS. Present for exhaustiveness.
        Domain::ExecutedNonceLeaf => b"oxide/executed-nonce-leaf",
    }
}

/// A BLS12-381 secret key (32 bytes). Used to sign messages.
///
/// This is a wrapper around `blst::min_pk::SecretKey` that produces
/// signatures compatible with our wire [`Signature`] type.
#[derive(Debug, Clone)]
pub struct BlsSecretKey {
    inner: SecretKey,
}

impl BlsSecretKey {
    /// Deterministically generate a secret key from key material
    /// (≥32 bytes). The same `ikm` always produces the same key —
    /// useful for deterministic tests.
    ///
    /// # Errors
    /// Returns `BlsError::InvalidKeyMaterial` if `ikm` is < 32 bytes.
    pub fn from_ikm(ikm: &[u8]) -> Result<Self, BlsError> {
        let inner = SecretKey::key_gen(ikm, b"oxide")?;
        Ok(Self { inner })
    }

    /// Derive the public key for this secret key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let pk = self.inner.sk_to_pk();
        let bytes = pk.compress();
        PublicKey(bytes)
    }

    /// Sign a message under this key. The `domain` provides the DST.
    /// The `msg` is the raw bytes to sign (typically a domain-
    /// separated hash, but any bytes are accepted).
    #[must_use]
    pub fn sign(&self, domain: Domain, msg: &[u8]) -> Signature {
        let sig = self.inner.sign(msg, dst(domain), b"");
        let bytes = sig.compress();
        Signature(bytes)
    }

    /// Produce a proof-of-possession for this key's public key: a
    /// signature over the compressed public key under
    /// [`Domain::BlsPop`].
    ///
    /// This is the BLS `PoP` scheme (`draft-irtf-cfrg-bls-signature`
    /// §3.3) specialized to Oxide's domain: `pop = Sign(sk, pk)`. A
    /// verifier checks it with [`pop_verify`]. Presenting a valid
    /// `PoP` proves the presenter knows the secret key for `pk` —
    /// which is exactly what a rogue public key (constructed as a
    /// linear combination of honest keys to corrupt
    /// `fast_aggregate_verify`) *cannot* produce, because its
    /// discrete log is unknown to the attacker.
    ///
    /// The `PoP` is mandatory at every consensus-key admission point:
    /// `fast_aggregate_verify` (the QC/TC verification path) is only
    /// secure when every signer key either proves possession or signs
    /// a distinct message. Oxide aggregates votes over the *same*
    /// message, so `PoP` admission is the load-bearing precondition.
    #[must_use]
    pub fn pop_prove(&self) -> Signature {
        self.sign(Domain::BlsPop, self.public_key().as_bytes())
    }

    /// Serialize the secret key to 32 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Deserialize a secret key from 32 bytes.
    ///
    /// # Errors
    /// Returns `BlsError::InvalidKeyMaterial` if the bytes are not a
    /// valid secret key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        let inner = SecretKey::from_bytes(bytes)?;
        Ok(Self { inner })
    }
}

/// Verify a single signature against a public key.
///
/// # Errors
/// Returns `BlsError::InvalidSignature` if the signature is invalid.
pub fn verify(sig: &Signature, domain: Domain, msg: &[u8], pk: &PublicKey) -> Result<(), BlsError> {
    let blst_sig = BlstSig::from_bytes(sig.as_bytes())?;
    let blst_pk = BlstPk::from_bytes(pk.as_bytes())?;
    let result = blst_sig.verify(false, msg, dst(domain), b"", &blst_pk, true);
    if result == BLST_ERROR::BLST_SUCCESS { Ok(()) } else { Err(BlsError::InvalidSignature) }
}

/// Verify a proof-of-possession: `pop` must be a valid signature over
/// the compressed `pk` under [`Domain::BlsPop`], produced by
/// [`BlsSecretKey::pop_prove`].
///
/// A valid `PoP` proves the presenter knows the secret key for `pk`.
/// This is the admission gate every consensus key must pass before
/// joining a [`consensus::ValidatorSet`]: without it, an attacker
/// could register a rogue key — a public key crafted as a linear
/// combination of honest validators' keys — and forge QC/TC
/// aggregate signatures that `fast_aggregate_verify` accepts over
/// the honest bitmap. The rogue key's discrete log is unknowable, so
/// it cannot produce a `PoP`; the attack dies at admission.
///
/// The signature's `verify` call also validates that `pk` is a
/// well-formed group element in the correct subgroup (blst
/// `pk_validate`), so malformed keys are rejected here too.
///
/// # Errors
/// Returns `BlsError::InvalidSignature` if `pop` does not verify
/// against `pk`, or `BlsError::InvalidKeyMaterial` if either input
/// is not a well-formed group element.
pub fn pop_verify(pk: &PublicKey, pop: &Signature) -> Result<(), BlsError> {
    verify(pop, Domain::BlsPop, pk.as_bytes(), pk)
}

/// Aggregate multiple signatures (over the same message) into one
/// aggregate signature.
///
/// # Errors
/// Returns `BlsError::EmptyAggregation` if `sigs` is empty.
pub fn aggregate(sigs: &[Signature]) -> Result<AggregateSignature, BlsError> {
    if sigs.is_empty() {
        return Err(BlsError::EmptyAggregation);
    }
    let mut agg = BlstAggSig::from_signature(&BlstSig::from_bytes(sigs[0].as_bytes())?);
    for sig in &sigs[1..] {
        let blst_sig = BlstSig::from_bytes(sig.as_bytes())?;
        agg.add_signature(&blst_sig, false).map_err(|_| BlsError::InvalidSignature)?;
    }
    let bytes = agg.to_signature().compress();
    Ok(AggregateSignature(bytes))
}

/// Verify an aggregate signature against a set of public keys, all
/// over the same message. This is the fast path for QC verification
/// (one pairing check regardless of validator count).
///
/// # Allocation
///
/// This function allocates one `Vec<BlstPk>` to deserialize the
/// public keys and one `Vec<&BlstPk>` to pass references to blst.
/// Both are pre-sized to `pks.len()` to avoid reallocation. For
/// hot-path callers that verify many QCs, consider caching the
/// deserialized PKs at the caller and using a lower-level API.
///
/// # Errors
/// Returns `BlsError::InvalidSignature` if the aggregate signature is
/// invalid, or `BlsError::EmptyAggregation` if `pks` is empty.
pub fn aggregate_verify(
    agg_sig: &AggregateSignature,
    domain: Domain,
    msg: &[u8],
    pks: &[PublicKey],
) -> Result<(), BlsError> {
    if pks.is_empty() {
        return Err(BlsError::EmptyAggregation);
    }
    let blst_agg = BlstSig::from_bytes(agg_sig.as_bytes())?;
    // Pre-size both Vecs to avoid reallocation. The deserialized
    // PKs and the reference slice are exactly pks.len() long.
    let mut blst_pks: Vec<BlstPk> = Vec::with_capacity(pks.len());
    for pk in pks {
        blst_pks.push(BlstPk::from_bytes(pk.as_bytes())?);
    }
    let pk_refs: Vec<&BlstPk> = blst_pks.iter().collect();
    let result = blst_agg.fast_aggregate_verify(true, msg, dst(domain), &pk_refs);
    if result == BLST_ERROR::BLST_SUCCESS { Ok(()) } else { Err(BlsError::InvalidSignature) }
}

/// Validate that a compressed [`PublicKey`] decodes to a well-formed
/// BLS12-381 group element in the correct subgroup.
///
/// Admission paths prove more than this — [`pop_verify`] implies it —
/// but state-restore and genesis paths install keys without a `PoP` in
/// hand; this is the check that keeps a crafted snapshot blob or a
/// typo'd genesis entry from lodging a point that can never verify,
/// which would wedge every QC that maps to it.
///
/// Cold path only — decode/genesis boundaries, never the vote loop.
///
/// # Errors
/// Returns `BlsError::InvalidKeyMaterial` if the bytes do not decode
/// to a subgroup member.
pub fn validate_point(pk: &PublicKey) -> Result<(), BlsError> {
    let blst_pk = BlstPk::from_bytes(pk.as_bytes())?;
    // `from_bytes` proves the encoding is a curve point; `validate`
    // adds the subgroup check — both halves are required.
    blst_pk.validate().map_err(|_| BlsError::InvalidKeyMaterial)
}

/// A BLS12-381 public key proven to decode to a group element in
/// the correct subgroup — "validated on admission" encoded in the
/// type system.
///
/// [`PublicKey`] is a bare 48-byte wire blob: [`PublicKey::from_slice`]
/// checks length only, so a raw `PublicKey` value proves nothing
/// about the point it encodes. That distinction matters at the
/// module → executor → consensus seam: validator-set deltas travel
/// through `types::EpochChanges` and `executor::ValidatorChanges`,
/// and before this type existed they crossed as `Vec<u8>` that the
/// engine decoded with the length-only check — a non-point key
/// admitted that way would wedge every QC mapped to it only when
/// signatures began failing.
///
/// Every constructor runs [`validate_point`], so a
/// `ValidatedPublicKey` reaching `OxideBft::apply_key_changes` /
/// `apply_validator_changes` *is* the proof that admission ran —
/// a future code path cannot push an unchecked key across the
/// seam without the type complaining. PoP-verified admissions
/// additionally prove key ownership; this token proves the weaker
/// (but necessary) property every stored key needs: the bytes are
/// a real group element.
///
/// The token is deliberately scoped to the live admission seam.
/// A node's own durable state (WAL, snapshots) is the trust
/// interior — decode paths re-validate via [`Self::from_bytes`]
/// as defense in depth, but `ValidatorSet` itself keeps bare
/// `PublicKey` members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidatedPublicKey(PublicKey);

impl ValidatedPublicKey {
    /// Validate `pk` (curve-point decode + subgroup check) and wrap
    /// it in the proof token.
    ///
    /// This is the only constructor — the signature *is* the
    /// contract that the stored key is a real group element.
    ///
    /// # Errors
    /// [`BlsError::InvalidKeyMaterial`] if `pk` does not decode to
    /// a subgroup member.
    pub fn new(pk: PublicKey) -> Result<Self, BlsError> {
        validate_point(&pk)?;
        Ok(Self(pk))
    }

    /// Validate compressed key bytes (length + curve-point decode +
    /// subgroup check). The decode-boundary constructor for state
    /// restore paths that hold raw bytes — snapshot decode, genesis
    /// JSON, wire payloads.
    ///
    /// # Errors
    /// [`BlsError::InvalidKeyMaterial`] if `bytes` is not exactly
    /// 48 bytes or does not decode to a subgroup member.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        let pk = PublicKey::from_slice(bytes).map_err(|_| BlsError::InvalidKeyMaterial)?;
        Self::new(pk)
    }

    /// The validated key as the wire [`PublicKey`] — for consumers
    /// (validator sets, signature verification) that store and use
    /// the compressed form.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.0
    }

    /// The compressed 48-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::ops::Deref for ValidatedPublicKey {
    type Target = PublicKey;

    /// Deref to the inner [`PublicKey`] — a validated key can be
    /// used anywhere the wire type is expected, but not the
    /// reverse.
    fn deref(&self) -> &PublicKey {
        &self.0
    }
}

impl From<ValidatedPublicKey> for PublicKey {
    /// Unwrap the proof — the wire type forgets validation status,
    /// which is fine for storage inside a boundary that already
    /// checked it.
    fn from(key: ValidatedPublicKey) -> Self {
        key.0
    }
}

/// Errors from BLS operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// The key material or signature bytes are malformed.
    InvalidKeyMaterial,
    /// The signature is invalid (failed verification).
    InvalidSignature,
    /// Aggregation was called with an empty set.
    EmptyAggregation,
}

impl From<BLST_ERROR> for BlsError {
    fn from(err: BLST_ERROR) -> Self {
        match err {
            BLST_ERROR::BLST_SUCCESS => BlsError::InvalidSignature, // shouldn't happen
            _ => BlsError::InvalidKeyMaterial,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Test real BLS sign/verify/aggregate operations.
    //!
    //! These tests use deterministic key generation (from fixed IKM)
    //! so they're reproducible. They prove the `blst` integration
    //! works end-to-end: `sign` → `verify` → `aggregate` → `aggregate_verify`.

    use super::*;

    fn sk(byte: u8) -> BlsSecretKey {
        let ikm = vec![byte; 32];
        BlsSecretKey::from_ikm(&ikm).expect("key gen")
    }

    #[test]
    fn sign_and_verify() {
        let key = sk(1);
        let pk = key.public_key();
        let msg = b"hello oxide";
        let sig = key.sign(Domain::Vote, msg);
        assert!(verify(&sig, Domain::Vote, msg, &pk).is_ok(), "valid signature must verify");
    }

    #[test]
    fn wrong_message_fails() {
        let key = sk(1);
        let pk = key.public_key();
        let sig = key.sign(Domain::Vote, b"hello");
        assert!(
            verify(&sig, Domain::Vote, b"goodbye", &pk).is_err(),
            "signature over wrong message must fail"
        );
    }

    #[test]
    fn wrong_domain_fails() {
        let key = sk(1);
        let pk = key.public_key();
        let sig = key.sign(Domain::Vote, b"hello");
        assert!(
            verify(&sig, Domain::Timeout, b"hello", &pk).is_err(),
            "signature with wrong domain must fail"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = sk(1);
        let key2 = sk(2);
        let pk2 = key2.public_key();
        let sig = key1.sign(Domain::Vote, b"hello");
        assert!(
            verify(&sig, Domain::Vote, b"hello", &pk2).is_err(),
            "signature with wrong key must fail"
        );
    }

    #[test]
    fn aggregate_and_verify() {
        let key1 = sk(1);
        let key2 = sk(2);
        let key3 = sk(3);
        let pk1 = key1.public_key();
        let pk2 = key2.public_key();
        let pk3 = key3.public_key();
        let msg = b"qc payload";
        let sig1 = key1.sign(Domain::QuorumCertificate, msg);
        let sig2 = key2.sign(Domain::QuorumCertificate, msg);
        let sig3 = key3.sign(Domain::QuorumCertificate, msg);
        let agg = aggregate(&[sig1, sig2, sig3]).expect("aggregate");
        assert!(
            aggregate_verify(&agg, Domain::QuorumCertificate, msg, &[pk1, pk2, pk3]).is_ok(),
            "aggregate signature must verify"
        );
    }

    #[test]
    fn aggregate_with_missing_signer_fails() {
        let key1 = sk(1);
        let key2 = sk(2);
        let key3 = sk(3);
        let pk1 = key1.public_key();
        let pk2 = key2.public_key();
        let pk3 = key3.public_key();
        let msg = b"qc payload";
        // Only 2 of 3 sign.
        let sig1 = key1.sign(Domain::QuorumCertificate, msg);
        let sig2 = key2.sign(Domain::QuorumCertificate, msg);
        let agg = aggregate(&[sig1, sig2]).expect("aggregate");
        // Verify against all 3 keys — must fail (key3 didn't sign).
        assert!(
            aggregate_verify(&agg, Domain::QuorumCertificate, msg, &[pk1, pk2, pk3]).is_err(),
            "aggregate with missing signer must fail"
        );
    }

    #[test]
    fn empty_aggregation_fails() {
        assert!(aggregate(&[]).is_err());
    }

    #[test]
    fn empty_aggregate_verify_fails() {
        let agg = AggregateSignature::ZERO;
        assert!(aggregate_verify(&agg, Domain::Vote, b"msg", &[]).is_err());
    }

    #[test]
    fn secret_key_round_trip() {
        let key = sk(42);
        let bytes = key.to_bytes();
        let restored = BlsSecretKey::from_bytes(&bytes).expect("deserialize");
        assert_eq!(key.public_key(), restored.public_key(), "key must round-trip");
    }

    #[test]
    fn different_keys_produce_different_pks() {
        let key1 = sk(1);
        let key2 = sk(2);
        assert_ne!(key1.public_key(), key2.public_key(), "different keys → different PKs");
    }

    #[test]
    fn pop_prove_and_verify() {
        let key = sk(7);
        let pk = key.public_key();
        let pop = key.pop_prove();
        assert!(pop_verify(&pk, &pop).is_ok(), "valid PoP must verify");
    }

    #[test]
    fn pop_verify_rejects_wrong_key() {
        let key1 = sk(1);
        let key2 = sk(2);
        let pop1 = key1.pop_prove();
        // key1's PoP must not verify under key2's public key.
        assert!(pop_verify(&key2.public_key(), &pop1).is_err());
        // And key2's PoP is a different signature (BLS is deterministic,
        // so the proof binds to the key, not the presenter).
        assert_ne!(pop1, key2.pop_prove());
    }

    #[test]
    fn pop_verify_rejects_garbage() {
        let key = sk(1);
        let pop = key.pop_prove();
        // Malformed pk bytes and malformed pop bytes both fail —
        // either deserialization or verification must error.
        assert!(pop_verify(&PublicKey([0x00; PublicKey::LEN]), &pop).is_err());
        assert!(pop_verify(&key.public_key(), &Signature([0x00; Signature::LEN])).is_err());
    }

    /// The attack `PoP` admission exists to stop. Without `PoP`, an
    /// attacker can register a *rogue key* — `pk_rogue = pk_evil −
    /// pk_honest` — so that `pk_honest + pk_rogue = pk_evil`. A
    /// single signature by the attacker then verifies as a
    /// quorum-certificate aggregate over the honest signer's bitmap
    /// slot. `PoP` kills it: the attacker cannot produce `Sign(sk_rogue,
    /// pk_rogue)` because `sk_rogue` is not computable from the
    /// public points.
    #[test]
    fn rogue_key_attack_forges_aggregate_but_not_pop() {
        let honest = sk(10);
        let evil = sk(11);
        let pk_honest = honest.public_key();
        let pk_evil = evil.public_key();

        // Construct the rogue key: pk_rogue = pk_evil − pk_honest.
        // This is pure public-group algebra — no secret knowledge of
        // sk_rogue required, which is exactly the attack.
        let mut rogue = blst::min_pk::AggregatePublicKey::from_public_key(
            &blst::min_pk::PublicKey::from_bytes(pk_evil.as_bytes()).expect("pk_evil"),
        );
        rogue.sub_aggregate(&blst::min_pk::AggregatePublicKey::from_public_key(
            &blst::min_pk::PublicKey::from_bytes(pk_honest.as_bytes()).expect("pk_honest"),
        ));
        let pk_rogue = PublicKey(rogue.to_public_key().compress());
        assert_ne!(pk_rogue, pk_evil);
        assert_ne!(pk_rogue, pk_honest);

        // The attack: a single evil signature verifies as the
        // "aggregate" over [honest, rogue] — because
        // pk_honest + pk_rogue = pk_evil.
        let msg = b"vote payload";
        let sig_evil = evil.sign(Domain::Vote, msg);
        let forged = aggregate(&[sig_evil]).expect("aggregate");
        assert!(
            aggregate_verify(&forged, Domain::Vote, msg, &[pk_honest, pk_rogue]).is_ok(),
            "rogue key admits a forged quorum aggregate — this is the vulnerability PoP closes",
        );

        // The defense: the attacker cannot produce a PoP for the
        // rogue key. Signing over the rogue pk's bytes with sk_evil
        // produces a signature that does not verify under pk_rogue
        // (the PoP check binds the signature to the key itself).
        let fake_pop = evil.sign(Domain::BlsPop, pk_rogue.as_bytes());
        assert!(
            pop_verify(&pk_rogue, &fake_pop).is_err(),
            "rogue key must fail PoP verification — admission rejected",
        );
        // Even the evil key's own genuine PoP does not cover the
        // rogue key.
        assert!(pop_verify(&pk_rogue, &evil.pop_prove()).is_err());
    }
}
