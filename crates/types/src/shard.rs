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
//! Reconstruction is erasure-coded: the body is split into `k`
//! data shards plus `m = n − k` Reed–Solomon parity shards over
//! GF(256), and any `k` of the `n` shards reconstruct it. `k`
//! derives from the committee's fault model (see
//! [`erasure_params`]): Byzantine validators together hold less
//! than the quorum deficit of stake, so at most `f_count` of them
//! can exist — and the remaining `n − f_count = k` validators are
//! honest, keep their assigned shard, and serve it on request.
//! Up to `m = f_count` withheld or lost shards therefore cannot
//! stall certification, while an equivocating dispersal still
//! fails the `body_commitment` check at `supply_body`.
//!
//! Shard proofs are sibling hashes on the path leaf→root; the tree
//! pads to a power of two by duplicating the last leaf (standard
//! sparse-Merkle convention — the `total` field bound into every
//! leaf prevents padding ambiguity).

use codec::{Decode, DecodeError, Encode, Reader, write};
use crypto::hash::{Domain, Hasher};
use primitives::Hash;

use crate::rs::ReedSolomon;

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
        for pair in level.as_chunks::<2>().0 {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        level = next;
        depth += 1;
    }
    (level[0], proofs)
}

/// `(data_shards, parity_shards)` for a committee that holds one
/// shard per validator, under the stake fault model: any `k` of
/// `n = stakes.len()` shards reconstruct the body, and up to
/// `m = n − k` shards may be withheld without losing it.
///
/// Deriving `k`: Byzantine validators together hold less than the
/// quorum deficit `total_stake − quorum_stake` of stake — more
/// would let them form a certificate alone, which the two-thirds
/// model excludes. The largest coalition they can field is the
/// greedily-counted smallest validators whose stakes fit that
/// budget; call it `f_count`. Every remaining validator is
/// honest, keeps its assigned shard, and serves it on request, so
/// at least `n − f_count` distinct shards are guaranteed
/// retrievable. `k = n − f_count` is therefore the threshold that
/// tolerates exactly the fault model's maximum withholding.
///
/// Equal stake reduces this to `n − f` with `f = ⌊(n−1)/3⌋` — for
/// `n = 3f + 1` the classic `2f+1`-of-`3f+1` code. A committee
/// whose quorum rests on few large stakeholders yields a small
/// `k` — down to `k = 1`, plain replication, which is the honest
/// answer when a single validator can be the whole honest quorum.
#[must_use]
pub fn erasure_params(stakes: &[u64], quorum_stake: u64) -> (usize, usize) {
    let n = stakes.len();
    let total = stakes.iter().fold(0u128, |acc, s| acc + u128::from(*s));
    let total = u64::try_from(total).unwrap_or(u64::MAX);
    let byz_budget = total.saturating_sub(quorum_stake);
    // Count the smallest stakes fitting the Byzantine budget —
    // the largest possible Byzantine *count*. Ascending order is
    // optimal: replacing a chosen member by any larger one can
    // only shrink the coalition.
    let mut sorted = stakes.to_vec();
    sorted.sort_unstable();
    let mut f_count = 0usize;
    let mut acc = 0u128;
    for &s in &sorted {
        if acc + u128::from(s) <= u128::from(byz_budget) {
            acc += u128::from(s);
            f_count += 1;
        } else {
            break;
        }
    }
    // `k` below 1 would claim availability with no honest holders
    // at all; every committee keeps at least one data shard.
    let k = (n - f_count).max(1);
    (k, n - k)
}

/// The `total` shard payloads for `body` — the single encoding
/// step behind [`disperse_body`] and [`commitment`], so the root
/// the proposer signs and the root `supply_body` recomputes are
/// byte-identical by construction.
///
/// The wire payload is `varint(body.len()) ‖ body`, so a
/// reconstructed `k·shard_size` buffer can be un-padded exactly.
/// With `k < total` the payload is padded to `k` equal slices and
/// Reed–Solomon-encoded into `total` uniform shards (first `k`
/// systematic = data, remaining `total − k` parity). With
/// `k == total` no validator can be Byzantine under the fault
/// model, so plain contiguous chunks suffice — the `f_count = 0`
/// case needs no parity at all.
fn encode_shards(body: &[u8], total: usize, k: usize) -> Vec<Vec<u8>> {
    let total = total.clamp(1, 255);
    let k = k.clamp(1, total);
    let mut payload = Vec::with_capacity(body.len() + 10);
    write::varint(&mut payload, body.len() as u64);
    payload.extend_from_slice(body);
    if k == total {
        let shard_len = payload.len().div_ceil(total);
        return (0..total)
            .map(|i| {
                let start = i.saturating_mul(shard_len).min(payload.len());
                let end = (start + shard_len).min(payload.len());
                payload[start..end].to_vec()
            })
            .collect();
    }
    let shard_size = payload.len().div_ceil(k);
    payload.resize(k * shard_size, 0);
    ReedSolomon::new(k, total - k).encode(&payload, shard_size)
}

/// The commitment root for `body` dispersed into `total` shards —
/// identical to the root [`disperse_body`] returns, but computed
/// over the shard payloads directly (no `Shard` structs). This is
/// what the proposer stamps into `BlockHeader.body_commitment`
/// and what `supply_body` recomputes over a reconstructed body.
pub fn commitment(body: &[u8], total: usize, k: usize) -> Hash {
    let total = total.clamp(1, 255);
    let total_u32 = u32::try_from(total).unwrap_or(u32::MAX);
    let shards = encode_shards(body, total, k);
    let mut leaves = Vec::with_capacity(total);
    for (i, bytes) in shards.iter().enumerate() {
        let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
        leaves.push(leaf_hash(i_u32, total_u32, bytes));
    }
    build_tree(&leaves).0
}

/// Split `body` into `total` erasure-coded shards and compute the
/// commitment root plus each shard's inclusion proof. `k` is the
/// reconstruction threshold from [`erasure_params`]: shards
/// `0..k` are systematic data, shards `k..total` parity, and any
/// `k` of them rebuild the body.
pub fn disperse_body(body: &[u8], total: usize, k: usize) -> (Hash, Vec<Shard>) {
    let total = total.clamp(1, 255);
    let total_u32 = u32::try_from(total).unwrap_or(u32::MAX);
    let encoded = encode_shards(body, total, k);
    let mut leaves = Vec::with_capacity(total);
    for (i, bytes) in encoded.iter().enumerate() {
        let i_u32 = u32::try_from(i).unwrap_or(u32::MAX);
        leaves.push(leaf_hash(i_u32, total_u32, bytes));
    }
    let (root, proofs) = build_tree(&leaves);
    let out = encoded
        .into_iter()
        .zip(proofs)
        .enumerate()
        .map(|(i, (bytes, proof))| Shard {
            index: u32::try_from(i).unwrap_or(u32::MAX),
            total: total_u32,
            bytes,
            proof,
        })
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
/// `k` is the reconstruction threshold the dispersal used — the
/// same [`erasure_params`] output every validator derives from
/// the committee's stakes and quorum.
pub struct ShardSet {
    slots: Vec<Option<Shard>>,
    k: usize,
}

impl ShardSet {
    /// Empty set for a `total`-shard body that reconstructs from
    /// any `k` shards.
    pub fn new(total: usize, k: usize) -> Self {
        Self { slots: vec![None; total], k: k.clamp(1, total.max(1)) }
    }

    /// Store a verified shard. Returns `true` exactly once — when
    /// the insert makes `k` distinct shards available and the body
    /// becomes reconstructible.
    pub fn insert(&mut self, shard: Shard) -> bool {
        let idx = usize::try_from(shard.index).unwrap_or(usize::MAX);
        if idx >= self.slots.len() {
            return false;
        }
        let duplicate = self.slots[idx].is_some();
        self.slots[idx] = Some(shard);
        !duplicate && self.received() == self.k
    }

    /// How many distinct shards are stored so far.
    pub fn received(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// The reconstructed body once `k` distinct shards are
    /// present; `None` below the threshold or when the decoded
    /// length prefix disagrees with the data.
    pub fn reconstruct(&self) -> Option<Vec<u8>> {
        let available: Vec<(usize, &[u8])> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|sh| (i, sh.bytes.as_slice())))
            .collect();
        if available.len() < self.k {
            return None;
        }
        let payload = if self.k == self.slots.len() {
            // No parity — the plain-chunk encoding: concatenate
            // every shard in index order.
            let total_len: usize = available.iter().map(|(_, b)| b.len()).sum();
            let mut buf = Vec::with_capacity(total_len);
            for (_, bytes) in &available {
                buf.extend_from_slice(bytes);
            }
            buf
        } else {
            let shard_size = available[0].1.len();
            let shards: Vec<(usize, Vec<u8>)> =
                available[..self.k].iter().map(|&(i, b)| (i, b.to_vec())).collect();
            ReedSolomon::new(self.k, self.slots.len() - self.k).reconstruct(&shards, shard_size)?
        };
        // The payload is `varint(body.len()) ‖ body` — decode the
        // prefix and slice the padding away. An erasure-coded
        // payload is padded to `k·shard_size`, so trailing zero
        // bytes are expected; a prefix claiming *more* than what
        // is present is malformed.
        let mut reader = Reader::new(&payload);
        let len = usize::try_from(reader.read_varint().ok()?).ok()?;
        if reader.remaining() < len {
            return None;
        }
        Some(reader.read_slice(len).ok()?.to_vec())
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

    /// Equal stake of 1: `quorum_stake` mirrors `ValidatorSet`'s
    /// `⌊2T/3⌋ + 1` rule.
    fn uniform_quorum(n: usize) -> u64 {
        let t = n as u64;
        t - t / 3 + u64::from(t.is_multiple_of(3))
    }

    #[test]
    fn erasure_params_uniform_stake_is_n_minus_f() {
        // Equal stake: the threshold is the classic `n − f`
        // (`2f+1` of `3f+1` at the bound).
        for (n, want_k) in [(1usize, 1), (4, 3), (7, 5), (8, 6), (10, 7), (16, 11)] {
            let (k, m) = erasure_params(&vec![1; n], uniform_quorum(n));
            assert_eq!((k, m), (want_k, n - want_k), "n={n}");
        }
    }

    #[test]
    fn erasure_params_skewed_stake_counts_by_power() {
        // One whale of 70 and nine minnows of ~3: Byzantine stake
        // budget is ~33, so all nine minnows could be Byzantine —
        // the honest quorum is the whale alone and only
        // replication (k = 1) guarantees it the body.
        let (k, m) = erasure_params(&[70, 4, 4, 4, 4, 4, 4, 3, 3, 3], 67);
        assert_eq!((k, m), (1, 9));
        // Two mid-sized + two small, quorum 6 of 8: budget 2
        // admits both small validators (1 + 1 ≤ 2) → k = 2.
        let (k, m) = erasure_params(&[3, 3, 1, 1], 6);
        assert_eq!((k, m), (2, 2));
        // Same committee, quorum raised to 7: budget 1 admits
        // only one small validator → k = 3.
        let (k, m) = erasure_params(&[3, 3, 1, 1], 7);
        assert_eq!((k, m), (3, 1));
        // Quorum = total stake: no Byzantine coalition fits the
        // zero budget → k = n, plain chunks, no parity.
        let (k, m) = erasure_params(&[3, 3, 1, 1], 8);
        assert_eq!((k, m), (4, 0));
    }

    #[test]
    fn disperse_verify_reconstruct_roundtrip() {
        for n in [1usize, 2, 3, 4, 5, 7, 8, 16] {
            let (k, _) = erasure_params(&vec![1; n], uniform_quorum(n));
            for len in [0usize, 1, 100, 4096, 3_800_000] {
                let b = body(len);
                let (root, shards) = disperse_body(&b, n, k);
                assert_eq!(shards.len(), n);
                for shard in &shards {
                    assert!(verify_shard(&root, shard), "n={n} len={len} shard={}", shard.index);
                }
                let mut set = ShardSet::new(n, k);
                let mut done = false;
                for shard in shards {
                    done = set.insert(shard) || done;
                }
                assert!(done);
                assert_eq!(set.reconstruct().as_deref(), Some(b.as_slice()));
            }
        }
    }

    /// The availability contract the audit asked to be proven:
    /// withholding up to `m = n − k` shards — the fault model's
    /// maximum — never loses the body, for EVERY choice of which
    /// shards are withheld.
    #[test]
    fn reconstruct_survives_max_byzantine_withholding() {
        for n in [4usize, 7] {
            let (k, m) = erasure_params(&vec![1; n], uniform_quorum(n));
            let b = body(10_000);
            let (root, shards) = disperse_body(&b, n, k);
            // Enumerate every (n − m)-subset = every k-subset.
            for mask in 0u32..(1 << n) {
                if mask.count_ones() as usize != k {
                    continue;
                }
                let mut set = ShardSet::new(n, k);
                for (i, shard) in shards.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        set.insert(shard.clone());
                    }
                }
                assert_eq!(set.received(), k);
                assert_eq!(
                    set.reconstruct().as_deref(),
                    Some(b.as_slice()),
                    "subset {mask:05b} of n={n} must reconstruct"
                );
            }
            // And one more withheld shard beyond the budget DOES
            // stall — the threshold is exact, not padded.
            let mut set = ShardSet::new(n, k);
            for shard in &shards[..k - 1] {
                set.insert(shard.clone());
            }
            assert!(set.reconstruct().is_none());
            let _ = root;
            let _ = m;
        }
    }

    #[test]
    fn commitment_matches_disperse_root() {
        // The direct helper must produce the exact root the
        // dispersing path commits to — this is the invariant
        // `supply_body` relies on when checking a reconstructed body.
        for n in [1usize, 3, 8] {
            for k in 1..=n {
                for len in [0usize, 1, 1024, 65_536] {
                    let b = body(len);
                    let (root, _) = disperse_body(&b, n, k);
                    assert_eq!(root, commitment(&b, n, k), "n={n} k={k} len={len}");
                }
            }
        }
    }

    #[test]
    fn verify_rejects_wrong_commitment() {
        let (root, shards) = disperse_body(&body(1024), 8, 5);
        let (other_root, _) = disperse_body(&body(1025), 8, 5);
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
    fn shard_encode_roundtrip() {
        let (_, shards) = disperse_body(&body(777), 5, 3);
        for shard in &shards {
            let mut buf = Vec::new();
            shard.encode(&mut buf);
            let mut reader = Reader::new(&buf);
            let back = Shard::decode(&mut reader).expect("decodes");
            assert_eq!(*shard, back);
        }
    }
}
