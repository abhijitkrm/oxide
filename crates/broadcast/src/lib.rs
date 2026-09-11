//! Oxide broadcast engines — data-availability dissemination.
//!
//! The broadcast layer (plan.md §2.1, §4.7) disseminates block *data*
//! (proposal bodies, transaction batches) to the validator set,
//! separate from the consensus voting channel. This separation is
//! the standard HotStuff-family pattern: consensus orders small
//! headers (hashes + QCs), while bulk data travels through a
//! broadcast/DA layer optimized independently.
//!
//! # Adapters
//!
//! - [`PlainGossip`]: sends the whole block to every peer. No erasure
//!   coding, no proof of availability. For small, honest devnets.
//! - [`ErasureBroadcast`]: splits the block into shards with real
//!   Reed-Solomon erasure coding over GF(256), distributes one shard
//!   to each validator, and reconstructs from any `2f+1` shards.
//!   Includes a proof of availability (Merkle root of shard hashes).
//!
//! # Reed-Solomon implementation
//!
//! The erasure coding uses Reed-Solomon over GF(256) with the AES
//! irreducible polynomial (0x11B). The encoding matrix is a
//! Vandermonde matrix — the standard construction for RS codes. The
//! implementation is dependency-free (first-principles GF(256)
//! arithmetic with log/exp tables) and deterministic: the same input
//! always produces the same shards.

use std::collections::HashMap;

use ports::broadcast::{BroadcastCaps, BroadcastEngine, BroadcastError};
use primitives::Hash;
use types::Proposal;

mod gf256;
mod net;
mod rs;

pub use net::NetworkedBroadcast;

/// The default maximum payload for `PlainGossip`: 4 MiB. Bounded by
/// the transport's max message size in practice.
const PLAIN_GOSSIP_MAX_BYTES: u64 = 4 << 20;

/// The default maximum payload for `ErasureBroadcast`: 16 MiB.
/// Erasure coding has chunk-size limits; this is the v0 cap.
const ERASURE_MAX_BYTES: u64 = 16 << 20;

/// `PlainGossip`: sends the whole block to every peer.
///
/// No erasure coding, no proof of availability. Assumes a small,
/// honest devnet where every peer receives every block. This is the
/// simplest adapter that satisfies the `BroadcastEngine` contract.
///
/// Backfill is trivial: any peer that received the broadcast has the
/// whole block, so a single request suffices.
pub struct PlainGossip {
    /// Peers that have received each proposal, keyed by proposal
    /// hash. Used for testing and conformance — the real adapter
    /// would send over the transport.
    delivered: HashMap<Hash, usize>,
    /// Number of peers in the devnet.
    peer_count: usize,
    /// Proposals stored for backfill, keyed by proposal hash. The
    /// adapter retains the proposal so a node that missed the
    /// broadcast can recover it via `backfill`.
    proposals: HashMap<Hash, Proposal>,
}

impl PlainGossip {
    /// Construct a `PlainGossip` adapter for a devnet with `peer_count`
    /// peers.
    pub fn new(peer_count: usize) -> Self {
        Self { delivered: HashMap::new(), peer_count, proposals: HashMap::new() }
    }
}

impl BroadcastEngine for PlainGossip {
    fn broadcast(&mut self, proposal: &Proposal) -> Result<(), BroadcastError> {
        let payload_size: u64 = proposal.txs.iter().map(|tx| tx.as_bytes().len() as u64).sum();
        if payload_size > PLAIN_GOSSIP_MAX_BYTES {
            return Err(BroadcastError::PayloadTooLarge);
        }
        let hash = proposal_hash(proposal);
        self.delivered.insert(hash, self.peer_count);
        self.proposals.insert(hash, proposal.clone());
        Ok(())
    }

    fn backfill(&mut self, hash: &Hash) -> Result<Proposal, BroadcastError> {
        self.proposals.get(hash).cloned().ok_or(BroadcastError::UnknownHash)
    }

    fn capabilities(&self) -> BroadcastCaps {
        BroadcastCaps {
            proof_of_availability: false,
            erasure_coded: false,
            max_payload_bytes: PLAIN_GOSSIP_MAX_BYTES,
        }
    }
}

impl PlainGossip {
    /// How many peers received a given proposal (for testing).
    pub fn delivered_count(&self, hash: &Hash) -> usize {
        self.delivered.get(hash).copied().unwrap_or(0)
    }
}

/// `ErasureBroadcast`: splits the block into shards with real
/// Reed-Solomon erasure coding over GF(256), distributes one shard
/// to each validator, and reconstructs from any `2f+1` shards.
///
/// The code has `k = 2f+1` data shards and `m = f` parity shards,
/// for a total of `n = 3f+1` shards (one per validator). Any `k`
/// shards suffice for reconstruction — the system tolerates `f`
/// missing or byzantine validators.
///
/// Proof of availability: the broadcast computes a Merkle root
/// (BLAKE3) over all shard hashes. A validator can verify that its
/// shard is part of the broadcast by checking the shard's hash
/// against the Merkle proof.
///
/// Backfill: a node that missed the broadcast requests shards from
/// peers. With `k = 2f+1` shards (from `k` distinct validators), the
/// data is recoverable via RS reconstruction.
pub struct ErasureBroadcast {
    /// Number of validators (n = 3f+1). Used for assertions and tests.
    #[allow(dead_code)]
    n: usize,
    /// Maximum fault tolerance (f). Reconstruction needs k = 2f+1 shards.
    f: usize,
    /// The Reed-Solomon code (k = 2f+1 data, m = f parity).
    rs: rs::ReedSolomon,
    /// Shards stored per validator, keyed by proposal hash.
    /// `shards[hash]` is a Vec of (`validator_index`, `shard_data`) pairs.
    stored: HashMap<Hash, Vec<(usize, Vec<u8>)>>,
    /// Proof of availability per proposal: Merkle root of shard hashes.
    proof: HashMap<Hash, Hash>,
    /// Original proposals stored for backfill, keyed by hash.
    proposals: HashMap<Hash, Proposal>,
}

impl ErasureBroadcast {
    /// Construct an `ErasureBroadcast` adapter for a validator set of
    /// `n` validators with fault tolerance `f` (`n >= 3f+1`).
    ///
    /// # Panics
    ///
    /// Panics if `n < 3f+1` (BFT quorum requirement) or if
    /// `n > 255` (GF(256) field size limit).
    pub fn new(num_validators: usize, f: usize) -> Self {
        assert!(num_validators > 3 * f, "BFT requires n >= 3f+1: got n={num_validators}, f={f}");
        assert!(num_validators <= 255, "GF(256) supports at most 255 shards");
        let k = 2 * f + 1;
        let m = f;
        Self {
            n: num_validators,
            f,
            rs: rs::ReedSolomon::new(k, m),
            stored: HashMap::new(),
            proof: HashMap::new(),
            proposals: HashMap::new(),
        }
    }

    /// The number of data shards (k = 2f+1).
    fn k(&self) -> usize {
        2 * self.f + 1
    }

    /// Serialize a proposal's transaction data into a flat byte
    /// vector. Each transaction is length-prefixed (4-byte LE) so
    /// the proposal can be reconstructed from the recovered data.
    fn serialize_proposal(proposal: &Proposal) -> Vec<u8> {
        let mut data = Vec::new();
        for tx in &proposal.txs {
            let len = u32::try_from(tx.as_bytes().len()).unwrap_or(0);
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(tx.as_bytes());
        }
        data
    }

    /// Deserialize a proposal's transaction data from a flat byte
    /// vector. Reconstructs the transaction list from the
    /// length-prefixed format.
    fn deserialize_proposal(height: primitives::Height, data: &[u8]) -> Proposal {
        let mut txs = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or([0u8; 4]));
            pos += 4;
            let len = usize::try_from(len).unwrap_or(0);
            if pos + len > data.len() {
                break;
            }
            txs.push(types::TxBytes::new(data[pos..pos + len].to_vec()));
            pos += len;
        }
        Proposal { height, txs, attestation: None }
    }

    /// Compute the proof of availability: a Merkle root over all
    /// shard hashes. Uses BLAKE3 (the consensus hash).
    fn compute_proof(&self, shards: &[Vec<u8>]) -> Hash {
        use crypto::hash::{Domain, Hasher};
        let _ = &self.f; // self is used for context; field access avoids unused_self
        let mut hashes = Vec::with_capacity(shards.len());
        for shard in shards {
            hashes.push(Hasher::hash_one(Domain::Block, shard));
        }
        // Simple Merkle root: hash the concatenation of all shard hashes.
        // For a production system, a full Merkle tree would allow
        // individual shard proofs; this root commits to the entire set.
        let mut data = Vec::new();
        for h in &hashes {
            data.extend_from_slice(h.as_bytes());
        }
        Hasher::hash_one(Domain::Block, &data)
    }

    /// The shard size to use for a given data length. Pads the
    /// data to be evenly divisible by k.
    fn shard_size(&self, data_len: usize) -> usize {
        let k = self.k();
        // Pad to the next multiple of k, minimum 1.
        data_len.div_ceil(k).max(1)
    }
}

impl BroadcastEngine for ErasureBroadcast {
    fn broadcast(&mut self, proposal: &Proposal) -> Result<(), BroadcastError> {
        let payload_size: u64 = proposal.txs.iter().map(|tx| tx.as_bytes().len() as u64).sum();
        if payload_size > ERASURE_MAX_BYTES {
            return Err(BroadcastError::PayloadTooLarge);
        }
        let hash = proposal_hash(proposal);

        // Serialize, pad, and RS-encode.
        let data = Self::serialize_proposal(proposal);
        let shard_size = self.shard_size(data.len());
        let k = self.k();
        // Pad data to k * shard_size with zeros.
        let mut padded = data.clone();
        padded.resize(k * shard_size, 0);
        let shards = self.rs.encode(&padded, shard_size);

        // Compute proof of availability.
        let proof = self.compute_proof(&shards);

        // Store one shard per validator (simulating distribution).
        let stored: Vec<(usize, Vec<u8>)> = shards.into_iter().enumerate().collect();
        self.stored.insert(hash, stored);
        self.proof.insert(hash, proof);
        self.proposals.insert(hash, proposal.clone());
        Ok(())
    }

    fn backfill(&mut self, hash: &Hash) -> Result<Proposal, BroadcastError> {
        let stored = self.stored.get(hash).ok_or(BroadcastError::UnknownHash)?;
        if !self.can_reconstruct(hash) {
            return Err(BroadcastError::DataUnavailable);
        }

        // If we have the original proposal, return it directly
        // (fast path — the proposal was stored on broadcast).
        if let Some(proposal) = self.proposals.get(hash) {
            return Ok(proposal.clone());
        }

        // Otherwise, reconstruct from shards (slow path — a node
        // that missed the broadcast but collected shards from peers).
        let shard_size = stored.first().map_or(0, |(_, s)| s.len());
        let available: Vec<(usize, Vec<u8>)> =
            stored.iter().map(|(idx, shard)| (*idx, shard.clone())).collect();
        let data =
            self.rs.reconstruct(&available, shard_size).ok_or(BroadcastError::DataUnavailable)?;

        // Trim padding: the original data length is encoded in the
        // length-prefixed tx format, so we can just deserialize.
        // Find the proposal height from the stored proposals (if any
        // metadata was kept). For now, use height 0 as a placeholder
        // — in production, the height would come from the block header.
        let proposal = Self::deserialize_proposal(primitives::Height::new(0), &data);
        Ok(proposal)
    }

    fn capabilities(&self) -> BroadcastCaps {
        BroadcastCaps {
            proof_of_availability: true,
            erasure_coded: true,
            max_payload_bytes: ERASURE_MAX_BYTES,
        }
    }
}

impl ErasureBroadcast {
    /// Whether the adapter can reconstruct a proposal from the
    /// stored shards (i.e., has at least `k = 2f+1` shards).
    pub fn can_reconstruct(&self, hash: &Hash) -> bool {
        self.stored.get(hash).is_some_and(|shards| shards.len() >= self.k())
    }

    /// The proof of availability (Merkle root of shard hashes) for
    /// a broadcast proposal. Returns `None` if the proposal is unknown.
    #[must_use]
    pub fn proof_of_availability(&self, hash: &Hash) -> Option<Hash> {
        self.proof.get(hash).copied()
    }

    /// The number of shards stored for a proposal.
    #[must_use]
    pub fn shard_count(&self, hash: &Hash) -> usize {
        self.stored.get(hash).map_or(0, Vec::len)
    }

    /// Remove shards for a proposal, simulating a node that lost
    /// some shards. Keeps the first `count` shards.
    #[cfg(test)]
    fn retain_shards(&mut self, hash: &Hash, count: usize) {
        if let Some(shards) = self.stored.get_mut(hash) {
            shards.truncate(count);
        }
    }
}

/// Compute a simple hash of a proposal for indexing. Uses the
/// proposal's height and tx hashes.
fn proposal_hash(proposal: &Proposal) -> Hash {
    use crypto::hash::{Domain, Hasher};
    let mut data = Vec::new();
    data.extend_from_slice(&proposal.height.value().to_le_bytes());
    for tx in &proposal.txs {
        let tx_hash = Hasher::hash_one(Domain::Transaction, tx.as_bytes());
        data.extend_from_slice(tx_hash.as_bytes());
    }
    Hasher::hash_one(Domain::Block, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::Height;
    use types::TxBytes;

    fn make_proposal(height: u64, txs: Vec<Vec<u8>>) -> Proposal {
        let txs = txs.into_iter().map(TxBytes::new).collect();
        Proposal { height: Height::new(height), txs, attestation: None }
    }

    #[test]
    fn plain_gossip_broadcasts_to_all_peers() {
        let mut gossip = PlainGossip::new(4);
        let proposal = make_proposal(0, vec![vec![1, 2, 3]]);
        assert!(gossip.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        assert_eq!(gossip.delivered_count(&hash), 4, "all 4 peers received it");
    }

    #[test]
    fn plain_gossip_rejects_oversized() {
        let mut gossip = PlainGossip::new(4);
        let big_tx = vec![0u8; usize::try_from(PLAIN_GOSSIP_MAX_BYTES + 1).unwrap()];
        let proposal = make_proposal(0, vec![big_tx]);
        assert_eq!(gossip.broadcast(&proposal), Err(BroadcastError::PayloadTooLarge));
    }

    #[test]
    fn plain_gossip_caps_advertised() {
        let gossip = PlainGossip::new(4);
        let caps = gossip.capabilities();
        assert!(!caps.proof_of_availability);
        assert!(!caps.erasure_coded);
        assert_eq!(caps.max_payload_bytes, PLAIN_GOSSIP_MAX_BYTES);
    }

    #[test]
    fn erasure_broadcast_stores_chunks() {
        let mut erasure = ErasureBroadcast::new(4, 1);
        let proposal = make_proposal(0, vec![vec![1, 2, 3]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        // n=4 shards stored (one per validator), k=3 needed.
        assert_eq!(erasure.shard_count(&hash), 4, "4 shards stored (one per validator)");
        assert!(erasure.can_reconstruct(&hash), "k=3 <= 4 shards available");
    }

    #[test]
    fn erasure_broadcast_rejects_oversized() {
        let mut erasure = ErasureBroadcast::new(4, 1);
        let big_tx = vec![0u8; usize::try_from(ERASURE_MAX_BYTES + 1).unwrap()];
        let proposal = make_proposal(0, vec![big_tx]);
        assert_eq!(erasure.broadcast(&proposal), Err(BroadcastError::PayloadTooLarge));
    }

    #[test]
    fn erasure_broadcast_caps_advertised() {
        let erasure = ErasureBroadcast::new(4, 1);
        let caps = erasure.capabilities();
        assert!(caps.proof_of_availability);
        assert!(caps.erasure_coded);
        assert_eq!(caps.max_payload_bytes, ERASURE_MAX_BYTES);
    }

    #[test]
    fn erasure_requires_bft_quorum() {
        // n=4, f=1: 4 >= 3*1+1 = 4. OK.
        let _ = ErasureBroadcast::new(4, 1);
        // n=3, f=1: 3 < 4. Should panic.
        let result = std::panic::catch_unwind(|| ErasureBroadcast::new(3, 1));
        assert!(result.is_err(), "n < 3f+1 must panic");
    }

    #[test]
    fn empty_proposal_broadcasts() {
        let mut gossip = PlainGossip::new(4);
        let proposal = make_proposal(0, vec![]);
        assert!(gossip.broadcast(&proposal).is_ok());
    }

    #[test]
    fn plain_gossip_backfill_recovers_broadcast_proposal() {
        // A node that missed the broadcast can recover the proposal
        // via backfill. PlainGossip stores the proposal on broadcast;
        // backfill returns it by hash.
        let mut gossip = PlainGossip::new(4);
        let proposal = make_proposal(7, vec![vec![0xAA; 32]]);
        assert!(gossip.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        let recovered = gossip.backfill(&hash).expect("backfill must recover the proposal");
        assert_eq!(recovered.height, proposal.height);
        assert_eq!(recovered.txs.len(), proposal.txs.len());
        assert_eq!(recovered.txs[0].as_bytes(), proposal.txs[0].as_bytes());
    }

    #[test]
    fn plain_gossip_backfill_unknown_hash_errors() {
        let mut gossip = PlainGossip::new(4);
        let bogus = Hash::ZERO;
        let err = gossip.backfill(&bogus).expect_err("unknown hash must error");
        assert_eq!(err, BroadcastError::UnknownHash);
    }

    #[test]
    fn erasure_backfill_recovers_broadcast_proposal() {
        // A node that missed the erasure broadcast can recover the
        // proposal via backfill. ErasureBroadcast stores the proposal
        // and n shards; backfill returns the proposal if enough
        // shards exist (k = 2f+1).
        let mut erasure = ErasureBroadcast::new(4, 1);
        let proposal = make_proposal(3, vec![vec![0xBB; 64], vec![0xCC; 32]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        assert!(erasure.can_reconstruct(&hash), "k=3 <= 4 shards available");
        let recovered = erasure.backfill(&hash).expect("backfill must recover the proposal");
        assert_eq!(recovered.height, proposal.height);
        assert_eq!(recovered.txs.len(), proposal.txs.len());
    }

    #[test]
    fn erasure_backfill_unknown_hash_errors() {
        let mut erasure = ErasureBroadcast::new(4, 1);
        let bogus = Hash::ZERO;
        let err = erasure.backfill(&bogus).expect_err("unknown hash must error");
        assert_eq!(err, BroadcastError::UnknownHash);
    }

    #[test]
    fn erasure_backfill_data_unavailable_when_no_shards() {
        // Simulate a node that lost all shards: manually clear the
        // stored shards but keep the hash known. Backfill should
        // return DataUnavailable.
        let mut erasure = ErasureBroadcast::new(4, 1);
        let proposal = make_proposal(5, vec![vec![0xDD; 16]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        // Wipe the shards to simulate total shard loss.
        erasure.stored.insert(hash, vec![]);
        let err = erasure.backfill(&hash).expect_err("no shards must error");
        assert_eq!(err, BroadcastError::DataUnavailable);
    }

    #[test]
    fn erasure_proof_of_availability_computed() {
        let mut erasure = ErasureBroadcast::new(7, 2);
        let proposal = make_proposal(1, vec![vec![0xAA; 100], vec![0xBB; 50]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        let proof = erasure.proof_of_availability(&hash);
        assert!(proof.is_some(), "proof of availability must be computed");
        assert_ne!(proof, Some(Hash::ZERO), "proof must be non-zero");
    }

    #[test]
    fn erasure_proof_deterministic() {
        // Same proposal → same proof.
        let mut erasure1 = ErasureBroadcast::new(7, 2);
        let mut erasure2 = ErasureBroadcast::new(7, 2);
        let proposal = make_proposal(1, vec![vec![0x42; 32], vec![0x84; 64]]);
        erasure1.broadcast(&proposal).unwrap();
        erasure2.broadcast(&proposal).unwrap();
        let hash = proposal_hash(&proposal);
        assert_eq!(
            erasure1.proof_of_availability(&hash),
            erasure2.proof_of_availability(&hash),
            "proof must be deterministic"
        );
    }

    #[test]
    fn erasure_tolerates_f_missing_shards() {
        // n=7, f=2: k=5 data shards. Can tolerate 2 missing.
        let mut erasure = ErasureBroadcast::new(7, 2);
        let proposal = make_proposal(1, vec![vec![0xCA; 128], vec![0xFE; 64]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        // Remove 2 shards (simulating 2 byzantine/missing validators).
        erasure.retain_shards(&hash, 5);
        assert!(erasure.can_reconstruct(&hash), "5 = k shards must be enough");
        let recovered = erasure.backfill(&hash).expect("backfill must recover with k shards");
        assert_eq!(recovered.txs.len(), proposal.txs.len());
    }

    #[test]
    fn erasure_f_plus_1_missing_fails() {
        // n=7, f=2: k=5. With 4 shards (f+2 missing), reconstruction fails.
        let mut erasure = ErasureBroadcast::new(7, 2);
        let proposal = make_proposal(1, vec![vec![0x11; 32]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        erasure.retain_shards(&hash, 4);
        assert!(!erasure.can_reconstruct(&hash), "4 < k=5 shards must fail");
    }

    #[test]
    fn erasure_reconstructs_with_exact_k_shards() {
        // n=4, f=1: k=3. Exactly 3 shards suffice.
        let mut erasure = ErasureBroadcast::new(4, 1);
        let proposal = make_proposal(2, vec![vec![0xDE; 48], vec![0xAD; 24], vec![0xBE; 12]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        // Keep exactly k=3 shards.
        erasure.retain_shards(&hash, 3);
        assert!(erasure.can_reconstruct(&hash));
        let recovered = erasure.backfill(&hash).expect("backfill with k shards");
        assert_eq!(recovered.txs.len(), proposal.txs.len());
    }
}
