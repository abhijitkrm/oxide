//! Merkle Mountain Range over leaf hashes — the authentication
//! primitive for the append-only journal (docs/storage-spec.md §3).
//!
//! ## What this module does
//!
//! [`Mmr`] accumulates pre-hashed 32-byte leaves, maintaining its node
//! forest incrementally: [`Mmr::push`] is O(1) amortized (leaf append +
//! mountain merges as heights collide), [`Mmr::root`] bags the current
//! peaks into one 32-byte commitment, and [`Mmr::proof`] produces an
//! O(log n) inclusion proof for any leaf that [`Mmr::verify`] checks
//! against a root alone — no trusted tree required.
//!
//! ## Why an MMR (and not a trie)
//!
//! The journal only ever appends; an MMR's shape is exactly append-only
//! (new leaves touch only the right edge — no re-hashing of cold
//! history, no key-ordered structure to maintain). This is the QMDB
//! insight (plan.md §8 L1): merklization with little memory and no
//! disk access on the commit path.
//!
//! ## Layout (canonical, Grin-lineage)
//!
//! Nodes live in one vector in **append order**: pushing a leaf appends
//! its hash, then, while the two rightmost mountains have equal height,
//! appends `parent = H(left ‖ right)`. For `n` leaves the forest holds
//! `2n − popcount(n)` nodes. Peaks are tracked incrementally in a small
//! side vector, so `push` never re-derives the forest shape.
//!
//! ## Hashing (BLAKE3-256, domain-separated)
//!
//! | Input | Preimage |
//! |---|---|
//! | leaf | `H(Domain::MmrLeaf ‖ preimage)` |
//! | internal node | `H(Domain::MmrNode ‖ left ‖ right)` |
//! | root | `H(Domain::MmrRoot ‖ bagged_peaks ‖ leaf_count (u64 LE))` |
//!
//! Domain tags come from `crypto::hash::Domain` — the canonical
//! chain-wide domain separation enum. This ensures MMR hashes can
//! never collide with transaction, vote, or block hashes.
//!
//! Peak bagging folds right-to-left (`acc = H(peak ‖ acc)` from the
//! rightmost peak). Binding `leaf_count` into the root makes two
//! different-sized forests unambiguously different commitments.
//!
//! ## Invariants (property-tested)
//!
//! 1. Every leaf in `[0, n)` proves against the root for that exact `n`.
//! 2. Verification fails on: wrong leaf, tampered step, wrong index,
//!    wrong leaf count, wrong peak.
//! 3. Identical push sequences yield identical roots, forever.

use crypto::hash::{Domain, Hasher};
use primitives::Hash;

/// Preimage width of an internal-node hash: domain tag + two 32-byte digests.
const NODE_PREIMAGE_LEN: usize = 65;
/// Preimage width of the root finalization: domain tag + digest + u64 count.
const ROOT_PREIMAGE_LEN: usize = 41;

/// A Merkle Mountain Range over pre-hashed leaves.
///
/// `peaks` is the incremental forest shape: `(absolute node index,
/// height, hash)` for each mountain, left to right. The hash is
/// carried inline so a checkpointed MMR — reconstructed from
/// `(leaf_count, peak hashes)` alone — can keep pushing without
/// the pruned node history. `nodes` holds only nodes appended
/// *since* `node_base` (0 for a fresh MMR, the node count at
/// checkpoint for a resumed one); proofs for leaves inside the
/// checkpointed prefix return `None` — pruning forfeits per-leaf
/// proofs for the dropped history.
#[derive(Debug, Default, Clone)]
pub struct Mmr {
    /// Node hashes appended since `node_base`, in append order.
    /// Index `i` maps to absolute index `node_base + i`.
    nodes: Vec<Hash>,
    /// Absolute index of `nodes[0]` — the node count at checkpoint
    /// time (`2·leaf_count − popcount(leaf_count)`), 0 when fresh.
    node_base: usize,
    /// Mountain peaks (absolute index, height, hash), left to right.
    peaks: Vec<(usize, u32, Hash)>,
    /// Number of leaves committed (includes checkpointed prefix).
    leaf_count: u64,
    /// Leaves covered by the checkpoint (proofs refuse these).
    checkpointed_leaves: u64,
}

/// One step of an inclusion path: the sibling hash at this level and
/// which side the *proven target* sits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathStep {
    /// Sibling hash at this level of the path.
    pub sibling: Hash,
    /// `true` = the target (or its subtree) is the LEFT child here.
    pub target_is_left: bool,
}

/// A self-contained inclusion proof: reconstructs the target's peak,
/// checks it against the supplied peaks, bags, and compares roots.
#[derive(Clone, Debug)]
pub struct MmrProof {
    /// Index of the proven leaf (0-based).
    pub leaf_index: u64,
    /// Leaf count at proof time — binds the forest shape.
    pub leaf_count: u64,
    /// Sibling path, leaf → peak (bottom-up order).
    pub path: Vec<PathStep>,
    /// All peak hashes at proof time, left to right.
    pub peaks: Vec<Hash>,
}

/// Hash an internal node: `H(Domain::MmrNode ‖ left ‖ right)`.
///
/// The preimage is assembled in a fixed stack buffer and hashed in one
/// single-shot call — byte-identical to a chained-update formulation
/// but faster on short inputs (no hasher-state setup, no per-update
/// block buffering; see devlog session 3, bug q). Public because the
/// bench exposes this as the hash floor every push amortizes to (the
/// gate decomposition in docs/storage-spec.md §3).
pub fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut preimage = [0u8; NODE_PREIMAGE_LEN];
    preimage[0] = Domain::MmrNode as u8;
    preimage[1..33].copy_from_slice(left.as_bytes());
    preimage[33..65].copy_from_slice(right.as_bytes());
    Hash(blake3::hash(&preimage).into())
}

/// Bag peaks right-to-left and finalize the root:
/// `H(Domain::MmrRoot ‖ bag ‖ leaf_count LE)`.
fn bag_root(peaks: &[Hash], leaf_count: u64) -> Hash {
    // An empty forest commits to the zero hash with leaf_count 0 —
    // documented, deterministic, and only reachable pre-genesis.
    if peaks.is_empty() {
        return Hash::ZERO;
    }
    let mut acc = peaks[peaks.len() - 1];
    // Fold from the second-rightmost peak leftward: acc = H(peak ‖ acc).
    for peak in peaks[..peaks.len() - 1].iter().rev() {
        acc = hash_node(peak, &acc);
    }
    let mut preimage = [0u8; ROOT_PREIMAGE_LEN];
    preimage[0] = Domain::MmrRoot as u8;
    preimage[1..33].copy_from_slice(acc.as_bytes());
    preimage[33..41].copy_from_slice(&leaf_count.to_le_bytes());
    Hash(blake3::hash(&preimage).into())
}

/// Pure function: peak `(root index, height)` pairs for a forest of
/// `n` leaves (spec §3 layout). Heights are log2 of each mountain's
/// leaf count; each mountain's nodes occupy `2^(h+1) − 1` consecutive
/// slots and its **root** is the last of them — the root index is what
/// proof descent and the incremental peak stack both need (a first-node
/// index would make `left_child = root − 2^h` underflow; this exact
/// mismatch was devlog session 3, bug p).
#[allow(clippy::cast_possible_truncation)]
// Justification: node indexes are memory-bounded — a forest larger
// than `usize::MAX` nodes cannot exist in the address space that holds
// it. Validator targets are 64-bit; the cast is a width formality.
pub fn peak_positions(n: u64) -> Vec<(usize, u32)> {
    let mut out = Vec::new();
    let mut first: u64 = 0;
    // Walk set bits of n from the most significant down: each set bit
    // is one mountain, sized by its bit position.
    let mut rest = n;
    while rest > 0 {
        let height = rest.ilog2();
        // Overflow safety (fuzz mmr-proof-verify, audit session 24):
        // for n ≥ 2^63 the mountain node count 2^(h+1) − 1 exceeds
        // u64, and plain `2 * (1 << height) - 1` panicked under
        // libFuzzer. Such a forest cannot exist in memory — the
        // only caller that feeds untrusted counts is `Mmr::verify`
        // with a forged `proof.leaf_count` — so we compute with
        // checked arithmetic and fall back to `u64::MAX`, which is
        // exactly the correct value at height 63. A forged count
        // now simply fails verification instead of crashing the
        // node.
        let mountain_nodes =
            (1u64 << height).checked_mul(2).and_then(|v| v.checked_sub(1)).unwrap_or(u64::MAX);
        let root = first.saturating_add(mountain_nodes).saturating_sub(1);
        out.push((root as usize, height));
        first = first.saturating_add(mountain_nodes);
        rest ^= 1u64 << height;
    }
    out
}

impl Mmr {
    /// Empty forest.
    pub fn new() -> Self {
        Mmr {
            nodes: Vec::new(),
            node_base: 0,
            peaks: Vec::new(),
            leaf_count: 0,
            checkpointed_leaves: 0,
        }
    }

    /// Resume an MMR from a checkpoint: `leaf_count` leaves already
    /// committed (their node history pruned) and the `peak_hashes`
    /// of the forest at that point. The result pushes and roots
    /// identically to the unpruned MMR — peaks are the only state
    /// appends ever consult.
    ///
    /// # Panics
    ///
    /// Panics if `peak_hashes.len()` disagrees with the forest shape
    /// implied by `leaf_count` — a malformed checkpoint is a caller
    /// bug, not recoverable data.
    #[must_use]
    pub fn from_checkpoint(leaf_count: u64, peak_hashes: &[Hash]) -> Self {
        let positions = peak_positions(leaf_count);
        assert_eq!(
            positions.len(),
            peak_hashes.len(),
            "checkpoint peaks must match the forest shape for leaf_count"
        );
        let node_base = usize::try_from(2 * leaf_count - u64::from(leaf_count.count_ones()))
            .unwrap_or(usize::MAX);
        Self {
            nodes: Vec::new(),
            node_base,
            peaks: positions
                .iter()
                .zip(peak_hashes.iter())
                .map(|(&(idx, h), &hash)| (idx, h, hash))
                .collect(),
            leaf_count,
            checkpointed_leaves: leaf_count,
        }
    }

    /// The current peak hashes, left to right — the serializable
    /// state a journal checkpoint record carries so [`Mmr::from_checkpoint`]
    /// can resume the log after segment pruning.
    #[must_use]
    pub fn peak_hashes(&self) -> Vec<Hash> {
        self.peaks.iter().map(|&(_, _, h)| h).collect()
    }

    /// Number of leaves committed.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Total node count (leaves + internal) — the structural law
    /// `2n − popcount(n)` from spec §3, exposed so tests and the
    /// conformance suite can assert it against any forest state.
    /// For a checkpointed MMR this counts only post-checkpoint nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Append one pre-hashed leaf; O(1) amortized.
    ///
    /// The leaf is pushed, then mountains merge while the two rightmost
    /// have equal height — each merge appends one internal-node hash.
    /// Over `n` pushes this does exactly `n − popcount_draining` hashes
    /// (amortized ≤ 1 per push): the hash count is information-theoretic
    /// for a Merkle structure, so the *structure* overhead here is the
    /// vector push plus a couple of peak-stack pops.
    pub fn push(&mut self, leaf: Hash) {
        self.nodes.push(leaf);
        self.peaks.push((self.node_base + self.nodes.len() - 1, 0, leaf));
        self.leaf_count += 1;
        // Merge cascade: while the two rightmost mountains are equal
        // height, their parent becomes the new rightmost mountain.
        while self.peaks.len() >= 2 {
            let (_right_index, right_height, right_hash) = self.peaks[self.peaks.len() - 1];
            let (_left_index, left_height, left_hash) = self.peaks[self.peaks.len() - 2];
            if right_height != left_height {
                break;
            }
            let parent = hash_node(&left_hash, &right_hash);
            self.nodes.push(parent);
            self.peaks.pop();
            self.peaks.pop();
            self.peaks.push((self.node_base + self.nodes.len() - 1, right_height + 1, parent));
        }
    }

    /// The root commitment: bagged peaks finalized with `leaf_count`.
    ///
    /// O(#peaks) hashes (~log n); maintained incrementally by [`push`],
    /// so calling this after every append costs the bagging only.
    pub fn root(&self) -> Hash {
        let peak_hashes: Vec<Hash> = self.peaks.iter().map(|&(_, _, h)| h).collect();
        bag_root(&peak_hashes, self.leaf_count)
    }

    /// Build an inclusion proof for leaf `leaf_index` (0-based).
    ///
    /// Strategy: locate the mountain containing the leaf (mountains
    /// cover leaf ranges left to right), then descend from that peak to
    /// the leaf, recording each sibling; the recorded path is reversed
    /// to bottom-up order. Descending from the peak avoids the
    /// error-prone "is this index a left or right child" index algebra
    /// entirely — child positions are always local to a subtree:
    /// `left_child(parent) = parent − 2^parent_height`,
    /// `right_child(parent) = parent − 1`.
    ///
    /// # Errors
    /// `None` if `leaf_index >= leaf_count` (out of range).
    #[must_use]
    pub fn proof(&self, leaf_index: u64) -> Option<MmrProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }
        // Leaves covered by a checkpoint have no node history — the
        // proof can't be built. `None` is honest: pruned means
        // unprovable.
        if leaf_index < self.checkpointed_leaves {
            return None;
        }
        let peaks = peak_positions(self.leaf_count);
        // Find the mountain whose leaf range contains leaf_index, and
        // the leaf's offset within that mountain. Mountain leaf ranges
        // partition [0, leaf_count), so a valid index always matches —
        // the `found` guard keeps that argument local and explicit.
        let mut leaf_start = 0u64;
        let mut found = None;
        for &(index, height) in &peaks {
            let mountain_leaves = 1u64 << height;
            if leaf_index < leaf_start + mountain_leaves {
                found = Some((index, height, leaf_index - leaf_start));
                break;
            }
            leaf_start += mountain_leaves;
        }
        // `?` on the Option: an in-range leaf always finds its mountain
        // (ranges partition [0, leaf_count)), but the operator keeps
        // that argument structural instead of a hand-rolled else.
        let (mut node, height, mut local) = found?;
        // Descend peak → leaf, collecting siblings top-down. A sibling
        // inside the checkpointed prefix is unprovable unless it is a
        // still-current peak — `node_at` returns `None` for pruned
        // nodes, and the whole proof returns `None` honestly.
        let mut path_down = Vec::with_capacity(height as usize);
        let mut h = height;
        while h > 0 {
            let left_child = node - (1usize << h);
            let right_child = node - 1;
            let left_leaves = 1u64 << (h - 1);
            if local < left_leaves {
                // Target is in the LEFT child; sibling is the right child.
                let sibling = self.node_at(right_child)?;
                path_down.push(PathStep { sibling, target_is_left: true });
                node = left_child;
            } else {
                // Target is in the RIGHT child; sibling is the left child.
                let sibling = self.node_at(left_child)?;
                path_down.push(PathStep { sibling, target_is_left: false });
                local -= left_leaves;
                node = right_child;
            }
            h -= 1;
        }
        // The descent consumed exactly `height` steps (loop structure);
        // reversing yields the bottom-up order `verify` folds.
        let path: Vec<PathStep> = path_down.into_iter().rev().collect();
        Some(MmrProof {
            leaf_index,
            leaf_count: self.leaf_count,
            path,
            peaks: self.peaks.iter().map(|&(_, _, hash)| hash).collect(),
        })
    }

    /// Resolve an absolute node index to its hash: post-checkpoint
    /// nodes live in `nodes` (offset by `node_base`); a checkpointed
    /// node is only known if it is still a current peak — anything
    /// else was pruned and is honestly unprovable.
    fn node_at(&self, index: usize) -> Option<Hash> {
        if index >= self.node_base {
            self.nodes.get(index - self.node_base).copied()
        } else {
            self.peaks.iter().find(|&&(i, _, _)| i == index).map(|&(_, _, h)| h)
        }
    }

    /// Verify `leaf` is committed by `root` according to `proof`.
    ///
    /// Reconstructs the target's peak from the path, checks it against
    /// the proof's peaks at the position implied by `leaf_index` and
    /// `leaf_count`, bags, and compares to `root`. Self-contained: no
    /// tree access, so it is exactly what a light client runs.
    #[must_use]
    pub fn verify(leaf: &Hash, proof: &MmrProof, root: &Hash) -> bool {
        if proof.leaf_index >= proof.leaf_count {
            return false;
        }
        let peaks = peak_positions(proof.leaf_count);
        if peaks.len() != proof.peaks.len() {
            return false;
        }
        // Which mountain contains the leaf, and its leaf-range start.
        let mut leaf_start = 0u64;
        let mut mountain = None;
        for (m, &(_, height)) in peaks.iter().enumerate() {
            let mountain_leaves = 1u64 << height;
            if proof.leaf_index < leaf_start + mountain_leaves {
                mountain = Some(m);
                break;
            }
            leaf_start += mountain_leaves;
        }
        let Some(m) = mountain else { return false };
        // The path must be exactly the mountain's height (one sibling
        // per level) — a wrong-length path is malformed, not false-y.
        if proof.path.len() != peaks[m].1 as usize {
            return false;
        }
        // Fold bottom-up: acc = leaf, then combine with each sibling.
        let mut acc = *leaf;
        for step in &proof.path {
            acc = if step.target_is_left {
                hash_node(&acc, &step.sibling)
            } else {
                hash_node(&step.sibling, &acc)
            };
        }
        // `acc` is now the target mountain's peak hash.
        if acc != proof.peaks[m] {
            return false;
        }
        // Bag the (checked-at-m, supplied-elsewhere) peaks.
        bag_root(&proof.peaks, proof.leaf_count) == *root
    }
}

/// Hash a leaf preimage with BLAKE3-256 under `Domain::MmrLeaf` — the
/// canonical way callers produce the pre-hashed leaves [`Mmr::push`]
/// consumes. Domain separation ensures MMR leaf hashes can never
/// collide with transaction, vote, or block hashes.
pub fn hash_leaf(preimage: &[u8]) -> Hash {
    Hasher::hash_one(Domain::MmrLeaf, preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic test leaves: blake3 of the index.
    fn leaf(i: u64) -> Hash {
        hash_leaf(&i.to_le_bytes())
    }

    /// Regression test: MMR domain-separated hashes must not collide
    /// with transaction, vote, or block hashes for the same input.
    /// Before the fix, MMR used raw prefix 0x01 (colliding with
    /// `Domain::Transaction`) and 0x02 (colliding with `Domain::Vote`).
    #[test]
    fn mmr_domains_do_not_collide_with_consensus_domains() {
        let payload = b"test payload";

        // MMR leaf hash uses Domain::MmrLeaf (tag 6).
        let mmr_leaf = hash_leaf(payload);

        // Transaction hash uses Domain::Transaction (tag 1).
        let tx_hash = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, payload);

        // Vote hash uses Domain::Vote (tag 2).
        let vote_hash = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Vote, payload);

        // Block hash uses Domain::Block (tag 0).
        let block_hash = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Block, payload);

        assert_ne!(mmr_leaf, tx_hash, "MMR leaf must not collide with transaction hash");
        assert_ne!(mmr_leaf, vote_hash, "MMR leaf must not collide with vote hash");
        assert_ne!(mmr_leaf, block_hash, "MMR leaf must not collide with block hash");

        // MMR node hash uses Domain::MmrNode (tag 5).
        let mmr_node = hash_node(&Hash::ZERO, &Hash::ZERO);
        let tx_node = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, &[0u8; 64]);
        assert_ne!(mmr_node, tx_node, "MMR node must not collide with transaction hash");
    }

    /// Regression (fuzz mmr-proof-verify, audit session 24):
    /// `peak_positions` must never panic on any u64 leaf count —
    /// including counts ≥ 2^63 where `2 * (1 << height)` overflows.
    /// A forged proof with an insane `leaf_count` must make `verify`
    /// return `false`, not crash the node. Found by libFuzzer.
    #[test]
    fn test_peak_positions_never_panics_on_huge_counts() {
        // Every power of two up to 2^63, plus the pathological
        // extremes: the fuzz crasher used n = u64::MAX (height 63).
        for n in [1u64 << 63, u64::MAX, (1u64 << 63) | 1, (1u64 << 62) | 3] {
            let _ = peak_positions(n); // must not panic
        }
    }

    /// Regression (fuzz mmr-proof-verify, audit session 24):
    /// a forged proof claiming `u64::MAX` leaves must fail
    /// verification cleanly (return false), never panic.
    #[test]
    fn test_verify_rejects_insane_leaf_count_without_panic() {
        let mut mmr = Mmr::new();
        for i in 0u8..8 {
            mmr.push(Hash([i; 32]));
        }
        let root = mmr.root();
        let forged = MmrProof {
            leaf_index: 0,
            leaf_count: u64::MAX, // ← fuzz crasher input
            path: Vec::new(),
            peaks: Vec::new(),
        };
        // Must return false (not panic): the claimed forest cannot
        // match the real root.
        assert!(!Mmr::verify(&Hash([0u8; 32]), &forged, &root));
    }

    /// Structural law: `n` leaves ⇒ `2n − popcount(n)` nodes, and the
    /// incrementally-maintained peaks equal the pure derivation.
    #[test]
    fn test_forest_shape_matches_law() {
        let mut mmr = Mmr::new();
        for n in 1u64..=1024 {
            mmr.push(leaf(n));
            let expected_nodes = 2 * n - u64::from(n.count_ones());
            assert_eq!(mmr.nodes.len() as u64, expected_nodes, "node count law at n={n}");
            let pure = peak_positions(n);
            assert_eq!(mmr.peaks.len(), pure.len(), "peak count at n={n}");
            for (a, b) in mmr.peaks.iter().zip(pure.iter()) {
                assert_eq!((a.0, a.1), *b, "peak positions agree at n={n}");
            }
        }
    }

    /// Exhaustive small-n: every leaf proves, and tampering anywhere in
    /// the proof (leaf, one step, peaks, counts) fails verification.
    #[test]
    fn test_every_leaf_proves_and_tamper_fails() {
        for n in 1u64..=64 {
            let mut mmr = Mmr::new();
            for i in 0..n {
                mmr.push(leaf(i));
            }
            let root = mmr.root();
            for i in 0..n {
                let proof = mmr.proof(i).expect("in-range leaf has a proof");
                assert!(Mmr::verify(&leaf(i), &proof, &root), "n={n} leaf={i} proves");

                // Wrong leaf hash.
                let bad_leaf = leaf(i + 1_000);
                assert!(
                    !Mmr::verify(&bad_leaf, &proof, &root),
                    "wrong leaf rejected (n={n},i={i})"
                );
                // Tampered sibling (each step, if the path is non-empty).
                for s in 0..proof.path.len() {
                    let mut tampered = proof.clone();
                    tampered.path[s].sibling = Hash([0xEE; 32]);
                    assert!(
                        !Mmr::verify(&leaf(i), &tampered, &root),
                        "tampered step rejected (n={n},i={i},step={s})"
                    );
                }
                // Wrong leaf count (forest-shape lie).
                let mut wrong_count = proof.clone();
                wrong_count.leaf_count += 1;
                assert!(!Mmr::verify(&leaf(i), &wrong_count, &root), "wrong count rejected");
                // Tampered peak.
                if !proof.peaks.is_empty() {
                    let mut bad_peak = proof.clone();
                    bad_peak.peaks[0] = Hash([0xDD; 32]);
                    assert!(!Mmr::verify(&leaf(i), &bad_peak, &root), "tampered peak rejected");
                }
            }
            // Out-of-range index produces no proof.
            assert!(mmr.proof(n).is_none(), "n={n}: out-of-range rejected");
        }
    }

    /// Root determinism: identical sequence ⇒ identical root; a
    /// different final leaf ⇒ different root.
    #[test]
    fn test_root_determinism_and_sensitivity() {
        let build = |final_leaf: u64| {
            let mut m = Mmr::new();
            for i in 0..9u64 {
                m.push(leaf(if i == 8 { final_leaf } else { i }));
            }
            m.root()
        };
        assert_eq!(build(9), build(9), "same sequence, same root");
        assert_ne!(build(9), build(10), "different leaf, different root");
    }

    /// Empty forest: zero root, no proofs, zero leaves.
    #[test]
    fn test_empty_forest() {
        let m = Mmr::new();
        assert_eq!(m.root(), Hash::ZERO);
        assert_eq!(m.leaf_count(), 0);
        assert!(m.proof(0).is_none());
    }

    /// Larger forest spot-check (powers of two and neighbors — the
    /// boundary shapes where mountain math is most error-prone).
    #[test]
    fn test_power_of_two_boundaries() {
        for &n in &[1023u64, 1024, 1025, 4095, 4096, 4097] {
            let mut m = Mmr::new();
            for i in 0..n {
                m.push(leaf(i));
            }
            let root = m.root();
            for &i in &[0, n / 2, n - 1] {
                let proof = m.proof(i).unwrap();
                assert!(Mmr::verify(&leaf(i), &proof, &root), "n={n}, i={i}");
            }
        }
    }

    /// Checkpoint resume: `from_checkpoint(leaf_count, peaks)` must
    /// produce a byte-identical root and identical subsequent roots —
    /// peaks are the only state appends ever consult.
    #[test]
    fn test_checkpoint_resume_produces_identical_roots() {
        for checkpoint_at in [0u64, 1, 3, 4, 5, 7, 8, 15, 16] {
            let mut full = Mmr::new();
            for i in 0..checkpoint_at {
                full.push(leaf(i));
            }
            let peaks = full.peak_hashes();

            // Resume from the checkpoint and push the same suffix.
            let mut resumed = Mmr::from_checkpoint(checkpoint_at, &peaks);
            assert_eq!(resumed.root(), full.root(), "resumed root matches at n={checkpoint_at}");
            for i in checkpoint_at..checkpoint_at + 10 {
                full.push(leaf(i));
                resumed.push(leaf(i));
                assert_eq!(
                    resumed.root(),
                    full.root(),
                    "root stays identical after resume (n={checkpoint_at}, +{i})"
                );
            }
        }
    }

    /// Proofs for leaves inside the checkpointed prefix return `None`
    /// (pruned = unprovable); leaves in post-checkpoint mountains
    /// whose siblings are all known still prove.
    #[test]
    fn test_checkpointed_leaves_are_unprovable() {
        let mut full = Mmr::new();
        for i in 0..4u64 {
            full.push(leaf(i));
        }
        let peaks = full.peak_hashes();
        let mut resumed = Mmr::from_checkpoint(4, &peaks);

        // Checkpointed leaves: no proof.
        assert!(resumed.proof(0).is_none());
        assert!(resumed.proof(3).is_none());

        // A leaf whose proof needs only post-checkpoint nodes still
        // proves (push 4,5 — mountain {4,5} is fully post-checkpoint).
        for i in 4..6u64 {
            resumed.push(leaf(i));
        }
        let root = resumed.root();
        let p5 = resumed.proof(5).expect("leaf 5's siblings are all post-checkpoint");
        assert!(Mmr::verify(&leaf(5), &p5, &root));
    }
}
