//! Dispersed block-body broadcast (DispersedSimplex-style).
//!
//! A leader never sends the full proposal body to every follower —
//! that serializes multi-MiB payloads through the leader's single
//! egress link per view. Instead the body is split into `n` shards
//! (one per validator), each shard is committed to by a Merkle-style
//! tree whose root travels inside the signed `BlockHeader` as
//! `body_commitment`, and the leader disperses *one* shard +
//! inclusion proof to each validator. Validators verify their own
//! shard against the commitment, vote on the block commitment
//! immediately (notarization needs only the header + a valid own
//! shard — never the full body), relay their shard to peers, and
//! reconstruct the body lazily: it is required only at commit time,
//! not vote time.
//!
//! Safety sketch: the vote binds to `block_hash`, which covers the
//! signed header including `body_commitment`. Two different bodies
//! produce different commitments (collision resistance), so a quorum
//! can only notarize one body per block. An equivocating leader that
//! disperses inconsistent shards across validators produces
//! inconsistent reconstructed bodies — which fail the commitment
//! check at `supply_body` and can never be finalized.
//!
//! Reconstruction currently needs all `n` shards (k = n, simple
//! chunking — no Reed–Solomon parity yet). That is a liveness
//! tradeoff, not a safety one: a withheld shard stalls certification
//! exactly like a withheld full body did before, and the commitment
//! format leaves room for parity shards (reconstruct-from-any-k)
//! without a wire change.
//!
//! Shard proofs are sibling hashes on the path leaf→root; the tree
//! pads to a power of two by duplicating the last leaf (standard
//! sparse-Merkle convention — the `total` field bound into every
//! leaf prevents padding ambiguity).

use codec::{Decode, DecodeError, Encode, Reader, write};
use crypto::hash::{Domain, Hasher};
use primitives::Hash;

/// One shard of a dispersed block body plus its inclusion proof.
///
/// `proof` holds the sibling hashes on the path from this shard's
/// leaf to the commitment root (bottom-up order); it is empty only
/// when `total == 1` (a lone leaf is its own root).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    /// This shard's position in the dispersed set (`0..total`).
    pub index: u32,
    /// Total shard count for the body (= validator count at
    /// dispersal time). Bound into every leaf hash so shards from
    /// different shardings can never mix.
    pub total: u32,
    /// The shard payload bytes.
    pub bytes: Vec<u8>,
    /// Merkle-style sibling path, leaf level upward.
    pub proof: Vec<Hash>,
}

/// Hash one shard leaf: `H(BodyShardLeaf ‖ index ‖ total ‖ bytes)`.
/// Index and total are bound in so a shard is valid only in its own
/// position of its own sharding — swapped or foreign shards fail the
/// root check at verification.
fn leaf_hash(index: u32, total: u32, bytes: &[u8]) -> Hash {
    let mut h = Hasher::new(Domain::BodyShardLeaf);
    h.update(&index.to_le_bytes());
    h.update(&total.to_le_bytes());
    h.update(bytes);
    h.finalize()
}

/// Hash one internal tree node: `H(BodyShardNode ‖ left ‖ right)`.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Hasher::new(Domain::BodyShardNode);
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    h.finalize()
}

/// Build the commitment root + per-leaf proofs with explicit index
/// tracking — the straightforward O(n log n) form. Pads the leaf row
/// to a power of two by duplicating the last leaf (standard
/// sparse-tree convention); the `total` field inside every leaf hash
/// binds the real count so padding can never be confused for real
/// shards.
fn build_tree(leaves: &[Hash]) -> (Hash, Vec<Vec<Hash>>) {
    debug_assert!(!leaves.is_empty());
    if leaves.len() == 1 {
        return (leaves[0], vec![Vec::new()]);
    }
    let width = leaves.len().next_power_of_two();
    let mut level: Vec<Hash> = leaves.to_vec();
    level.resize(width, *leaves.last().unwrap_or(&Hash::ZERO));
    let mut proofs: Vec<Vec<Hash>> = vec![Vec::new(); leaves.len()];
    let mut depth = 0usize;
    while level.len() > 1 {
        for (i, proof) in proofs.iter_mut().enumerate() {
            // Position of leaf i at `depth` levels above the leaf row.
            let pos = i >> depth;
            let sib = (pos ^ 1).min(level.len() - 1);
            proof.push(level[sib]);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        level = next;
        depth += 1;
    }
    (level[0], proofs)
}

/// The commitment root for `body` dispersed into `total` shards —
/// identical to the root [`disperse_body`] returns, but computed over
/// the body in place (zero shard copies). This is what the proposer
/// stamps into `BlockHeader.body_commitment` and what `supply_body`
/// recomputes over a reconstructed body.
pub fn commitment(body: &[u8], total: usize) -> Hash {
    let total = total.max(1).min(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
    let total_u32 = u32::try_from(total).unwrap_or(u32::MAX);
    let shard_len = body.len().div_ceil(total);
    let mut leaves = Vec::with_capacity(total);
    for i in 0..total {
        let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
        let start = i.saturating_mul(shard_len).min(body.len());
        let end = (start + shard_len).min(body.len());
        leaves.push(leaf_hash(i_u32, total_u32, &body[start..end]));
    }
    build_tree(&leaves).0
}

/// Split `body` into `total` contiguous shards and compute the
/// commitment root plus each shard's inclusion proof. The last shard
/// takes the remainder (`body.len()` need not divide `total`).
///
/// `total` is clamped to ≥1; a `total` larger than `body.len()`
/// yields empty tail shards — still committed and verifiable.
pub fn disperse_body(body: &[u8], total: usize) -> (Hash, Vec<Shard>) {
    // `total` is the validator count — always far below u32::MAX in
    // any real committee, but clamp anyway so index casts stay exact.
    let total = total.max(1).min(usize::try_from(u32::MAX).unwrap_or(usize::MAX));
    let total_u32 = u32::try_from(total).unwrap_or(u32::MAX);
    // Ceil division: shards 0..total-1 are `shard_len` bytes, the
    // last takes whatever remains (may be shorter, never longer).
    let shard_len = body.len().div_ceil(total);
    let mut leaves = Vec::with_capacity(total);
    let mut shards = Vec::with_capacity(total);
    for i in 0..total {
        let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
        let start = i.saturating_mul(shard_len).min(body.len());
        let end = (start + shard_len).min(body.len());
        let bytes = body[start..end].to_vec();
        leaves.push(leaf_hash(i_u32, total_u32, &bytes));
        shards.push((i_u32, bytes));
    }
    let (root, proofs) = build_tree(&leaves);
    let out = shards
        .into_iter()
        .zip(proofs)
        .map(|((index, bytes), proof)| Shard { index, total: total_u32, bytes, proof })
        .collect();
    (root, out)
}

/// Verify `shard`'s inclusion proof against `commitment` — the value
/// carried by the signed `BlockHeader`. Recomputes the root from the
/// leaf and sibling path; constant-time concerns don't apply (the
/// proof is public data, the check is a hash comparison).
pub fn verify_shard(commitment: &Hash, shard: &Shard) -> bool {
    if shard.index >= shard.total || shard.total == 0 {
        return false;
    }
    let mut acc = leaf_hash(shard.index, shard.total, &shard.bytes);
    let mut pos = usize::try_from(shard.index).unwrap_or(usize::MAX);
    // The tree was padded to next_pow2(total); siblings beyond the
    // real leaf count are duplicates of the last leaf — the proof
    // simply carries them.
    for sib in &shard.proof {
        acc = if pos % 2 == 0 { node_hash(&acc, sib) } else { node_hash(sib, &acc) };
        pos /= 2;
    }
    &acc == commitment
}

/// Accumulating shard set for one block body — the receiver-side
/// state. Shards are placed by `index`; duplicates and out-of-range
/// indices are rejected up front by [`verify_shard`] at ingest.
pub struct ShardSet {
    slots: Vec<Option<Shard>>,
}

impl ShardSet {
    /// Empty set for a `total`-shard body.
    pub fn new(total: usize) -> Self {
        Self { slots: vec![None; total] }
    }

    /// Store a verified shard. Returns `true` exactly once — when the
    /// insert completes the set (all `total` shards present).
    pub fn insert(&mut self, shard: Shard) -> bool {
        let idx = usize::try_from(shard.index).unwrap_or(usize::MAX);
        if idx >= self.slots.len() {
            return false;
        }
        self.slots[idx] = Some(shard);
        self.slots.iter().all(Option::is_some)
    }

    /// How many shards are stored so far.
    pub fn received(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Concatenate shard bytes in index order once the set is
    /// complete; `None` while any shard is missing.
    pub fn reconstruct(&self) -> Option<Vec<u8>> {
        if self.slots.iter().any(Option::is_none) {
            return None;
        }
        let total_len: usize =
            self.slots.iter().map(|s| s.as_ref().map_or(0, |sh| sh.bytes.len())).sum();
        let mut body = Vec::with_capacity(total_len);
        for shard in self.slots.iter().flatten() {
            body.extend_from_slice(&shard.bytes);
        }
        Some(body)
    }
}

impl Encode for Shard {
    /// Wire format: `[index u32][total u32][proof_len varint]
    /// [proof hashes][bytes]`. Lengths are varints per codec rules.
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.index.to_le_bytes());
        buf.extend_from_slice(&self.total.to_le_bytes());
        write::varint(buf, self.proof.len() as u64);
        for h in &self.proof {
            h.encode(buf);
        }
        write::bytes(buf, &self.bytes);
    }
}

impl<'a> Decode<'a> for Shard {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let index = reader.read_u32()?;
        let total = reader.read_u32()?;
        let claimed = reader.read_varint()?;
        // A proof longer than 64 levels implies a shard count over
        // 2^64 — impossible; reject before allocating rather than
        // trusting the peer's length prefix.
        if claimed > 64 {
            return Err(DecodeError::LengthPrefixTooLarge {
                claimed,
                remaining: reader.remaining() as u64,
            });
        }
        let proof_len = usize::try_from(claimed).map_err(|_| {
            DecodeError::LengthPrefixTooLarge { claimed, remaining: reader.remaining() as u64 }
        })?;
        let mut proof = Vec::with_capacity(proof_len);
        for _ in 0..proof_len {
            proof.push(Hash::decode(reader)?);
        }
        let bytes = reader.read_bytes()?.to_vec();
        Ok(Self { index, total, bytes, proof })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect()
    }

    #[test]
    fn disperse_verify_reconstruct_roundtrip() {
        for n in [1usize, 2, 3, 4, 5, 7, 8, 16] {
            for len in [0usize, 1, 100, 4096, 3_800_000] {
                let b = body(len);
                let (root, shards) = disperse_body(&b, n);
                assert_eq!(shards.len(), n);
                for shard in &shards {
                    assert!(verify_shard(&root, shard), "n={n} len={len} shard={}", shard.index);
                }
                let mut set = ShardSet::new(n);
                let mut done = false;
                for shard in shards {
                    done = set.insert(shard);
                }
                assert_eq!(done, n >= 1);
                assert_eq!(set.reconstruct().as_deref(), Some(b.as_slice()));
            }
        }
    }

    #[test]
    fn commitment_matches_disperse_root() {
        // The zero-copy helper must produce the exact root the
        // dispersing path commits to — this is the invariant
        // `supply_body` relies on when checking a reconstructed body.
        for n in [1usize, 3, 8] {
            for len in [0usize, 1, 1024, 65_536] {
                let b = body(len);
                let (root, _) = disperse_body(&b, n);
                assert_eq!(root, commitment(&b, n), "n={n} len={len}");
            }
        }
    }

    #[test]
    fn verify_rejects_wrong_commitment() {
        let (root, shards) = disperse_body(&body(1024), 8);
        let (other_root, _) = disperse_body(&body(1025), 8);
        assert_ne!(root, other_root);
        assert!(!verify_shard(&other_root, &shards[0]));
        // Mutated shard bytes fail.
        let mut bad = shards[1].clone();
        bad.bytes[0] ^= 0xFF;
        assert!(!verify_shard(&root, &bad));
        // Out-of-range index fails.
        let mut bad2 = shards[0].clone();
        bad2.index = 99;
        assert!(!verify_shard(&root, &bad2));
    }

    #[test]
    fn reconstruct_incomplete_is_none() {
        let (_, shards) = disperse_body(&body(512), 4);
        let mut set = ShardSet::new(4);
        for shard in &shards[..3] {
            assert!(!set.insert(shard.clone()));
        }
        assert_eq!(set.received(), 3);
        assert!(set.reconstruct().is_none());
    }

    #[test]
    fn shard_encode_roundtrip() {
        let (_, shards) = disperse_body(&body(777), 5);
        for shard in &shards {
            let mut buf = Vec::new();
            shard.encode(&mut buf);
            let mut reader = Reader::new(&buf);
            let back = Shard::decode(&mut reader).expect("decodes");
            assert_eq!(*shard, back);
        }
    }
}
