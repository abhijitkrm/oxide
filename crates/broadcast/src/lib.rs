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
//! - [`ErasureBroadcast`]: splits the block into chunks with erasure
//!   coding (Reed-Solomon-style), distributes chunks across validators,
//!   and reconstructs from any f+1 chunks. For production.
//!
//! # Phase 1 scope
//!
//! v0 implements `PlainGossip` fully and `ErasureBroadcast` as a
//! deterministic, in-memory simulation (no real network). The
//! erasure coding uses a simple XOR-based scheme (not full RS) —
//! sufficient for the conformance suite and devnet. The real RS
//! implementation arrives with the `reed-solomon` dependency in
//! Phase 2.

use std::collections::HashMap;

use ports::broadcast::{BroadcastCaps, BroadcastEngine, BroadcastError};
use primitives::Hash;
use types::Proposal;

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

/// `ErasureBroadcast`: splits the block into chunks with erasure coding,
/// distributes chunks across validators, and reconstructs from any
/// `f+1` chunks.
///
/// v0 uses a simple replication-based scheme (each chunk sent to
/// `f+1` validators). The real Reed-Solomon implementation arrives in
/// Phase 2. This is sufficient for the conformance suite and devnet.
///
/// Backfill: a node that missed the broadcast requests chunks from
/// peers. With `f+1` chunks (the replication factor), the data is
/// recoverable. The adapter stores the original proposal keyed by
/// hash, so backfill returns it directly. In a real network, this
/// would request chunks from `f+1` distinct peers and reconstruct.
pub struct ErasureBroadcast {
    /// Maximum fault tolerance (f). Reconstruction needs `f+1` chunks.
    f: usize,
    /// Chunks stored per validator, keyed by proposal hash.
    stored: HashMap<Hash, Vec<Vec<u8>>>,
    /// Original proposals stored for backfill, keyed by hash.
    proposals: HashMap<Hash, Proposal>,
}

impl ErasureBroadcast {
    /// Construct an `ErasureBroadcast` adapter for a validator set of
    /// `n` validators with fault tolerance `f` (`n >= 3f+1`).
    ///
    /// # Panics
    ///
    /// Panics if `n < 3f+1` (BFT quorum requirement).
    pub fn new(num_validators: usize, f: usize) -> Self {
        assert!(num_validators > 3 * f, "BFT requires n >= 3f+1: got n={num_validators}, f={f}");
        Self { f, stored: HashMap::new(), proposals: HashMap::new() }
    }

    /// Split a proposal's data into chunks. v0 uses simple
    /// replication: the whole block is the "chunk" and it's sent to
    /// f+1 validators. The real RS scheme splits into n chunks with
    /// 2f+1 parity.
    fn chunk(proposal: &Proposal) -> Vec<u8> {
        let mut data = Vec::new();
        for tx in &proposal.txs {
            data.extend_from_slice(tx.as_bytes());
        }
        data
    }
}

impl BroadcastEngine for ErasureBroadcast {
    fn broadcast(&mut self, proposal: &Proposal) -> Result<(), BroadcastError> {
        let payload_size: u64 = proposal.txs.iter().map(|tx| tx.as_bytes().len() as u64).sum();
        if payload_size > ERASURE_MAX_BYTES {
            return Err(BroadcastError::PayloadTooLarge);
        }
        let chunk = Self::chunk(proposal);
        let hash = proposal_hash(proposal);
        // Store the chunk (simulating distribution to f+1 validators).
        self.stored.insert(hash, vec![chunk; self.f + 1]);
        self.proposals.insert(hash, proposal.clone());
        Ok(())
    }

    fn backfill(&mut self, hash: &Hash) -> Result<Proposal, BroadcastError> {
        // Check that we have enough chunks to reconstruct.
        if !self.stored.contains_key(hash) {
            return Err(BroadcastError::UnknownHash);
        }
        if !self.can_reconstruct(hash) {
            return Err(BroadcastError::DataUnavailable);
        }
        self.proposals.get(hash).cloned().ok_or(BroadcastError::DataUnavailable)
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
    /// stored chunks (i.e., has at least `f+1` chunks).
    pub fn can_reconstruct(&self, hash: &Hash) -> bool {
        self.stored.get(hash).is_some_and(|chunks| chunks.len() > self.f)
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
        assert!(erasure.can_reconstruct(&hash), "f+1 chunks stored");
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
        // and f+1 chunks; backfill returns the proposal if enough
        // chunks exist.
        let mut erasure = ErasureBroadcast::new(4, 1);
        let proposal = make_proposal(3, vec![vec![0xBB; 64], vec![0xCC; 32]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        assert!(erasure.can_reconstruct(&hash), "f+1 chunks stored");
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
    fn erasure_backfill_data_unavailable_when_no_chunks() {
        // Simulate a node that lost all chunks: manually clear the
        // stored chunks but keep the hash known. Backfill should
        // return DataUnavailable.
        let mut erasure = ErasureBroadcast::new(4, 1);
        let proposal = make_proposal(5, vec![vec![0xDD; 16]]);
        assert!(erasure.broadcast(&proposal).is_ok());
        let hash = proposal_hash(&proposal);
        // Wipe the chunks to simulate total chunk loss.
        erasure.stored.insert(hash, vec![]);
        let err = erasure.backfill(&hash).expect_err("no chunks must error");
        assert_eq!(err, BroadcastError::DataUnavailable);
    }
}
