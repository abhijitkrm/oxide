//! Domain-separated BLAKE3 hashing.
//!
//! # Why domain separation
//!
//! Consensus safety requires that a block hash can never collide with a
//! vote hash, a QC hash, or a transaction hash — even if the underlying
//! bytes happen to be identical. Every hash input carries a one-byte
//! domain tag as its first byte, so `H(0x01 ‖ block_bytes)` and
//! `H(0x02 ‖ vote_bytes)` are in different hash spaces regardless of
//! the payload. This is the standard technique (used by Diem/Aptos,
//! Ethereum 2.0, and HotStuff-family engines) and is mandatory per the
//! production-rust skill §6.
//!
//! # The [`Domain`] enum
//!
//! Every hashing call site names its domain explicitly — there is no
//! default. This makes the domain tag a compile-time-checked part of
//! the API, not a magic byte buried in a preimage. Adding a new domain
//! is a one-line change to the enum; the tag byte is derived from the
//! variant's discriminant.
//!
//! # The [`Hasher`] API
//!
//! Two shapes:
//!
//! - [`Hasher::hash_one`] — single-shot hash of a domain tag + one
//!   byte slice. This is the common case (hash a block, a vote, a tx).
//! - [`Hasher::new`] → `update` → `finalize` — streaming hash for
//!   multi-part preimages (e.g. an MMR node is `domain ‖ left ‖ right`).
//!   The domain tag is written first, unconditionally, by `new`.
//!
//! Both produce a [`primitives::Hash`], the chain's 32-byte digest type.

use primitives::Hash;

/// A domain separation tag. Every hash input begins with one byte
/// identifying what kind of thing is being hashed, so hashes from
/// different domains can never collide.
///
/// The tag byte is the variant's discriminant (0-indexed). New
/// variants must be appended (never inserted or reordered) — the tag
/// byte is part of the wire consensus contract, and changing it would
/// fork the chain. The `#[repr(u8)]` ensures the discriminant is
/// exactly the byte value.
///
/// # Current domains
///
/// | Variant | Tag | Used by |
/// |---|---|---|
/// | `Block` | 0 | block header hashing (Phase 1) |
/// | `Transaction` | 1 | transaction ID / tx-root (Phase 1) |
/// | `Vote` | 2 | oxideBFT vote signing (Phase 1) |
/// | `QuorumCertificate` | 3 | oxideBFT QC hashing (Phase 1) |
/// | `Timeout` | 4 | oxideBFT timeout certificate (Phase 1) |
/// | `MmrNode` | 5 | MMR internal node (storage) |
/// | `MmrLeaf` | 6 | MMR leaf (storage) |
/// | `StateRoot` | 7 | execution state root (Phase 2) |
/// | `MmrRoot` | 8 | MMR root finalization (storage) |
/// | `Proposal` | 9 | block proposal signing (C3 fix) |
/// | `ValidatorAddress` | 10 | staking address derivation |
/// | `StateSyncChunk` | 11 | state-sync snapshot chunks |
/// | `BodyShardLeaf` | 12 | dispersed-block shard leaf (Phase 5) |
/// | `BodyShardNode` | 13 | dispersed-block shard tree node (Phase 5) |
/// | `ExecAttest` | 14 | execution attestation signing (Phase 5) |
/// | `BlsPop` | 15 | BLS proof-of-possession (validator key admission) |
/// | `Ed25519Owner` | 16 | matcher account derivation from Ed25519 key |
/// | `ExecutedNonceLeaf` | 17 | executed-nonce map leaf (executor state root) |
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    /// A block header.
    Block = 0,
    /// A transaction (for tx IDs and tx-roots).
    Transaction = 1,
    /// A consensus vote (prepare / pre-commit / commit).
    Vote = 2,
    /// A quorum certificate (aggregate of votes).
    QuorumCertificate = 3,
    /// A timeout certificate (pacemaker view change).
    Timeout = 4,
    /// An MMR internal node: `H(tag ‖ left ‖ right)`.
    MmrNode = 5,
    /// An MMR leaf: `H(tag ‖ leaf_bytes)`.
    MmrLeaf = 6,
    /// An execution state root.
    StateRoot = 7,
    /// An MMR root finalization: `H(tag ‖ bagged_peaks ‖ leaf_count)`.
    /// Appended after `StateRoot` — never renumber.
    MmrRoot = 8,
    /// A block proposal (leader's signature over the header).
    /// Appended after `MmrRoot` — never renumber.
    Proposal = 9,
    /// A validator's staking address, derived from their BLS public
    /// key (`validator_address(pk)`). Appended after `Proposal` —
    /// never renumber.
    ValidatorAddress = 10,
    /// A state-sync snapshot chunk (`H(tag ‖ chunk_bytes)` in the
    /// manifest's `chunk_hashes`). Appended after
    /// `ValidatorAddress` — never renumber.
    StateSyncChunk = 11,
    /// A dispersed-block shard leaf: `H(tag ‖ index ‖ total ‖ bytes)`.
    /// Appended after `StateSyncChunk` — never renumber. Leaf and
    /// node domains differ so a leaf hash can never collide with an
    /// internal node in the shard commitment tree.
    BodyShardLeaf = 12,
    /// A dispersed-block shard-tree internal node:
    /// `H(tag ‖ left ‖ right)`. Appended after `BodyShardLeaf` —
    /// never renumber.
    BodyShardNode = 13,
    /// A validator's execution attestation: the signature over
    /// `(height, state_root, epoch)` carried on a consensus vote and
    /// aggregated into an [`types::ExecCertificate`]. Appended after
    /// `BodyShardNode` — never renumber. Distinct from `Vote` so an
    /// attestation signature can never be reinterpreted as a block
    /// vote (and vice versa).
    ExecAttest = 14,
    /// A BLS proof-of-possession: `sign(sk, pk_bytes)` presented when
    /// a validator's consensus key is admitted (`validator_add` /
    /// `key_change`). Appended after `ExecAttest` — never renumber.
    /// Its own domain so a `PoP` can never be reinterpreted as a
    /// vote, timeout, or attestation signature over the same bytes.
    BlsPop = 15,
    /// A matcher account address derived from an Ed25519 public key:
    /// `H(tag ‖ pk_bytes)[..20]`. Appended after `BlsPop` — never
    /// renumber. The Ed25519 key IS the trading account: the
    /// matcher's `owner` field must equal this derivation, which
    /// binds the signing key to the account with no registry.
    /// Distinct from `ValidatorAddress` so a consensus identity can
    /// never alias a trading account (and vice versa).
    Ed25519Owner = 16,
    /// One leaf of the executor's executed-nonce commitment:
    /// `H(tag ‖ address ‖ nonce_le)`. The nonce root is the XOR-fold
    /// of these leaves — an incrementally updatable set commitment —
    /// so leaf bytes must never collide with any other domain's
    /// preimage. Appended after `Ed25519Owner` — never renumber.
    ExecutedNonceLeaf = 17,
    /// One leaf of a [`framework::CommittedMap`] set commitment:
    /// `H(tag ‖ map_tag_le ‖ key_bytes ‖ value_bytes)`. The map's
    /// root is the XOR-fold of these leaves — an incrementally
    /// updatable set commitment over canonical (key, value) encodings.
    /// The `map_tag` inside the preimage separates leaves of
    /// different committed maps so a (key, value) pair can never
    /// alias across maps even when their encodings coincide.
    /// Appended after `ExecutedNonceLeaf` — never renumber.
    CommittedLeaf = 18,
}

/// A domain-separated BLAKE3 hasher. The domain tag is written first,
/// unconditionally, on construction; subsequent `update` calls append
/// the preimage parts. Call `finalize` to produce the digest.
///
/// For single-shot hashing of one byte slice, prefer [`Hasher::hash_one`].
pub struct Hasher {
    inner: blake3::Hasher,
}

impl Hasher {
    /// Begin a new hash in `domain`. The domain tag is written as the
    /// first byte immediately — callers never forget it.
    pub fn new(domain: Domain) -> Self {
        let mut inner = blake3::Hasher::new();
        // The domain tag is a single byte; write it before any payload
        // so the preimage always starts with the tag, regardless of
        // how many update calls follow.
        inner.update(&[domain as u8]);
        Self { inner }
    }

    /// Append bytes to the preimage. May be called multiple times for
    /// multi-part preimages (e.g. MMR nodes: `update(left); update(right)`).
    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    /// Finalize and return the 32-byte digest.
    pub fn finalize(&self) -> Hash {
        let out = self.inner.finalize();
        Hash(out.into())
    }

    /// Single-shot: hash `domain ‖ bytes` and return the digest. This is
    /// the common case (one payload, one hash) and avoids constructing
    /// an intermediate `Hasher` for readability without sacrificing
    /// performance — BLAKE3's single-shot path is the same internally.
    pub fn hash_one(domain: Domain, bytes: &[u8]) -> Hash {
        let mut h = Self::new(domain);
        h.update(bytes);
        h.finalize()
    }

    /// Hash two parts (common for Merkle nodes: `domain ‖ left ‖ right`).
    /// Convenience over `new` + two `update` calls; the intent (a binary
    /// node) is named at the call site.
    pub fn hash_pair(domain: Domain, left: &[u8], right: &[u8]) -> Hash {
        let mut h = Self::new(domain);
        h.update(left);
        h.update(right);
        h.finalize()
    }
}

#[cfg(test)]
mod tests {
    //! Domain separation is a consensus invariant: the tests pin that
    //! (a) different domains never collide, (b) the same domain + same
    //! bytes always produce the same digest, and (c) the tag byte is
    //! exactly the variant discriminant (part of the wire contract).

    use super::*;

    #[test]
    fn same_domain_same_bytes_same_hash() {
        let a = Hasher::hash_one(Domain::Block, b"hello");
        let b = Hasher::hash_one(Domain::Block, b"hello");
        assert_eq!(a, b, "deterministic: same domain + same bytes → same hash");
    }

    #[test]
    fn different_domains_never_collide() {
        // The same payload under different domains must produce
        // different hashes — this is the whole point of domain
        // separation. If this fails, two consensus objects could have
        // the same hash and be confused.
        let block = Hasher::hash_one(Domain::Block, b"same payload");
        let vote = Hasher::hash_one(Domain::Vote, b"same payload");
        let qc = Hasher::hash_one(Domain::QuorumCertificate, b"same payload");
        let tx = Hasher::hash_one(Domain::Transaction, b"same payload");
        assert_ne!(block, vote);
        assert_ne!(block, qc);
        assert_ne!(block, tx);
        assert_ne!(vote, qc);
        assert_ne!(vote, tx);
        assert_ne!(qc, tx);
    }

    #[test]
    fn different_bytes_different_hash() {
        let a = Hasher::hash_one(Domain::Block, b"hello");
        let b = Hasher::hash_one(Domain::Block, b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_pair_matches_streaming() {
        // hash_pair(domain, left, right) must equal
        // new(domain).update(left).update(right).finalize().
        let left = [1u8; 32];
        let right = [2u8; 32];
        let pair = Hasher::hash_pair(Domain::MmrNode, &left, &right);
        let mut h = Hasher::new(Domain::MmrNode);
        h.update(&left);
        h.update(&right);
        let streamed = h.finalize();
        assert_eq!(pair, streamed, "hash_pair must be equivalent to streaming");
    }

    #[test]
    fn domain_tag_is_discriminant() {
        // The tag byte is part of the wire consensus contract. This
        // test pins it to the variant's discriminant so reordering or
        // inserting variants is caught.
        assert_eq!(Domain::Block as u8, 0);
        assert_eq!(Domain::Transaction as u8, 1);
        assert_eq!(Domain::Vote as u8, 2);
        assert_eq!(Domain::QuorumCertificate as u8, 3);
        assert_eq!(Domain::Timeout as u8, 4);
        assert_eq!(Domain::MmrNode as u8, 5);
        assert_eq!(Domain::MmrLeaf as u8, 6);
        assert_eq!(Domain::StateRoot as u8, 7);
    }

    #[test]
    fn empty_input_is_valid() {
        // An empty payload under a domain is a valid, deterministic
        // hash (used for empty-block placeholders). It must not panic
        // and must differ from the empty input under a different domain.
        let h = Hasher::hash_one(Domain::Block, b"");
        assert_ne!(h, Hash::ZERO, "empty input is not the zero hash");
        assert_ne!(h, Hasher::hash_one(Domain::Vote, b""));
    }

    #[test]
    fn digest_is_32_bytes() {
        let h = Hasher::hash_one(Domain::Block, b"x");
        assert_eq!(h.as_bytes().len(), 32);
    }
}
