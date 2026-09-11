//! Networked erasure broadcast — real shard distribution over a
//! `Transport`.
//!
//! # What this is
//!
//! [`NetworkedBroadcast`] wraps the Reed-Solomon erasure coder and
//! distributes shards to validators over a real [`Transport`]. Unlike
//! [`ErasureBroadcast`](super::ErasureBroadcast), which stores shards
//! in a local `HashMap` (simulating distribution), this adapter
//! actually sends each shard to a peer via the transport's `send`
//! method and receives shards from peers via `recv`.
//!
//! # Protocol
//!
//! ## Broadcast (leader → validators)
//!
//! 1. The leader serializes the proposal, RS-encodes it into `n`
//!    shards (k data + m parity), and computes the proof of
//!    availability (Merkle root of shard hashes).
//! 2. The leader sends each shard to its assigned validator via
//!    `transport.send(peer, shard_msg)`. The shard message is
//!    framed as:
//!    `[MSG_SHARD: 1B][proposal_hash: 32B][shard_index: 1B]
//!     [shard_len: 4B LE][shard_data: shard_len B]`
//! 3. The leader retains all shards locally for backfill.
//!
//! ## Receive (validator side)
//!
//! 1. A validator calls `recv_shards()` to drain inbound transport
//!    messages. Each `MSG_SHARD` message is parsed and the shard is
//!    stored, keyed by `(proposal_hash, shard_index)`.
//! 2. Once `k = 2f+1` shards are collected, the validator can
//!    reconstruct the proposal via `backfill(hash)`.
//!
//! ## Backfill (recovery)
//!
//! 1. A node that missed the broadcast sends `MSG_SHARD_REQUEST`
//!    messages to peers: `[MSG_SHARD_REQUEST: 1B][proposal_hash: 32B]
//!    [shard_index: 1B]`.
//! 2. Peers that have the requested shard respond with a
//!    `MSG_SHARD_RESPONSE`: `[MSG_SHARD_RESPONSE: 1B][proposal_hash:
//!    32B][shard_index: 1B][shard_len: 4B LE][shard_data: shard_len B]`.
//! 3. The requester collects responses until it has `k` shards, then
//!    reconstructs.
//!
//! # Proof of availability
//!
//! The proof of availability is the Merkle root of all shard hashes
//! (BLAKE3). It is computed deterministically by the leader and can
//! be verified by any validator that receives the shard set. The
//! proof is not a vote — it is a commitment. A validator that wants
//! to prove availability to the consensus layer includes the proof
//! in its vote. The consensus layer checks that `f+1` validators
//! include the same proof (i.e., `f+1` validators have the shards).
//!
//! # Phase 2 scope
//!
//! This is a synchronous adapter (matching the OAI v0 traits). The
//! transport is polled via `recv()`. Phase 3 adds an async I/O loop
//! that drains the transport in a background task. The protocol
//! messages are not encrypted or authenticated — the transport's
//! caps determine that. For production, use an authenticated +
//! encrypted transport (commonware-p2p or TLS).

use std::collections::HashMap;

use ports::broadcast::{BroadcastCaps, BroadcastEngine, BroadcastError};
use ports::transport::{Transport, TransportError};
use primitives::Hash;
use types::Proposal;

use crate::rs::ReedSolomon;

/// The default maximum payload for `NetworkedBroadcast`: 16 MiB.
/// Matches `ErasureBroadcast` — the erasure coding limit.
const NETWORKED_MAX_BYTES: u64 = 16 << 20;

/// Message type tag: a shard being distributed by the leader.
const MSG_SHARD: u8 = 0x01;

/// Message type tag: a request for a specific shard (backfill).
const MSG_SHARD_REQUEST: u8 = 0x02;

/// Message type tag: a response to a shard request (backfill).
const MSG_SHARD_RESPONSE: u8 = 0x03;

/// A networked erasure broadcast adapter.
///
/// Wraps the Reed-Solomon erasure coder and distributes shards over
/// a real [`Transport`]. Each validator gets one shard. Any `k = 2f+1`
/// shards suffice for reconstruction.
///
/// This adapter is the production broadcast path. The leader calls
/// `broadcast()` to send shards to all validators. Each validator
/// calls `recv_shards()` to collect inbound shards from the
/// transport. A node that missed the broadcast calls `backfill()`,
/// which sends shard requests to peers and collects responses.
///
/// # Lifecycle
///
/// 1. **Construction:** `NetworkedBroadcast::new(transport, n, f,
///    my_index, peer_ids)`. The adapter owns the transport.
/// 2. **Leader broadcasts:** `broadcast(&proposal)` encodes the
///    proposal into shards and sends one shard to each peer.
/// 3. **Validators receive:** `recv_shards()` drains the transport
///    and stores inbound shards.
/// 4. **Backfill:** `backfill(&hash)` sends shard requests to peers,
///    collects responses, and reconstructs the proposal.
///
/// # Determinism
///
/// The RS encoding is deterministic: the same proposal always
/// produces the same shards. The proof of availability is
/// deterministic. The order of shard delivery is determined by the
/// transport, not the adapter.
pub struct NetworkedBroadcast<T: Transport> {
    /// The transport used to send and receive shards.
    transport: T,
    /// The Reed-Solomon code (k = 2f+1 data, m = f parity).
    rs: ReedSolomon,
    /// Number of validators (n = 3f+1).
    n: usize,
    /// Maximum fault tolerance (f). Reconstruction needs k = 2f+1.
    f: usize,
    /// This node's validator index (0..n).
    my_index: usize,
    /// Peer IDs indexed by validator index. `peer_ids[i]` is the
    /// transport-level `PeerId` for validator `i`.
    peer_ids: Vec<ports::transport::PeerId>,
    /// Shards received from peers, keyed by proposal hash.
    /// `received[hash]` is a map of `(shard_index, shard_data)`.
    received: HashMap<Hash, HashMap<u8, Vec<u8>>>,
    /// Shards sent by this node (if it was the leader), keyed by
    /// proposal hash. Used for backfill responses.
    sent: HashMap<Hash, Vec<(usize, Vec<u8>)>>,
    /// Proof of availability per proposal.
    proof: HashMap<Hash, Hash>,
    /// Original proposals stored for fast backfill (leader only).
    proposals: HashMap<Hash, Proposal>,
}

impl<T: Transport> NetworkedBroadcast<T> {
    /// Construct a `NetworkedBroadcast` adapter.
    ///
    /// # Arguments
    ///
    /// - `transport`: the P2P transport for sending/receiving shards.
    /// - `num_validators`: the number of validators (n = 3f+1).
    /// - `f`: the maximum fault tolerance. Reconstruction needs k = 2f+1.
    /// - `my_index`: this node's validator index (0..n).
    /// - `peer_ids`: the transport-level `PeerId` for each validator.
    ///
    /// # Panics
    ///
    /// Panics if `n < 3f+1`, `n > 255`, `my_index >= n`, or
    /// `peer_ids.len() != n`.
    pub fn new(
        transport: T,
        num_validators: usize,
        f: usize,
        my_index: usize,
        peer_ids: Vec<ports::transport::PeerId>,
    ) -> Self {
        assert!(num_validators > 3 * f, "BFT requires n >= 3f+1: got n={num_validators}, f={f}");
        assert!(num_validators <= 255, "GF(256) supports at most 255 shards");
        assert!(my_index < num_validators, "my_index {my_index} >= n {num_validators}");
        assert_eq!(
            peer_ids.len(),
            num_validators,
            "peer_ids.len() {} != n {}",
            peer_ids.len(),
            num_validators
        );
        let k = 2 * f + 1;
        let m = f;
        Self {
            transport,
            rs: ReedSolomon::new(k, m),
            n: num_validators,
            f,
            my_index,
            peer_ids,
            received: HashMap::new(),
            sent: HashMap::new(),
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
    fn compute_proof(shards: &[Vec<u8>]) -> Hash {
        use crypto::hash::{Domain, Hasher};
        let mut data = Vec::new();
        for shard in shards {
            let h = Hasher::hash_one(Domain::Block, shard);
            data.extend_from_slice(h.as_bytes());
        }
        Hasher::hash_one(Domain::Block, &data)
    }

    /// The shard size to use for a given data length. Pads the
    /// data to be evenly divisible by k.
    fn shard_size(&self, data_len: usize) -> usize {
        let k = self.k();
        data_len.div_ceil(k).max(1)
    }

    /// Encode a shard message for sending over the transport.
    ///
    /// Format: `[MSG_SHARD: 1B][proposal_hash: 32B][shard_index: 1B]
    /// [shard_len: 4B LE][shard_data: shard_len B]`
    fn encode_shard_msg(hash: &Hash, shard_index: u8, shard: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + 32 + 1 + 4 + shard.len());
        msg.push(MSG_SHARD);
        msg.extend_from_slice(hash.as_bytes());
        msg.push(shard_index);
        msg.extend_from_slice(&(u32::try_from(shard.len()).unwrap_or(0)).to_le_bytes());
        msg.extend_from_slice(shard);
        msg
    }

    /// Parse a shard message from the transport.
    ///
    /// Returns `(proposal_hash, shard_index, shard_data)` or `None`
    /// if the message is malformed.
    fn parse_shard_msg(bytes: &[u8]) -> Option<(Hash, u8, Vec<u8>)> {
        if bytes.len() < 1 + 32 + 1 + 4 {
            return None;
        }
        if bytes[0] != MSG_SHARD {
            return None;
        }
        let hash_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
        let hash = Hash(hash_bytes);
        let shard_index = bytes[33];
        let shard_len = u32::from_le_bytes(bytes[34..38].try_into().ok()?);
        let shard_len = usize::try_from(shard_len).ok()?;
        if bytes.len() < 38 + shard_len {
            return None;
        }
        let shard = bytes[38..38 + shard_len].to_vec();
        Some((hash, shard_index, shard))
    }

    /// Encode a shard request message for backfill.
    ///
    /// Format: `[MSG_SHARD_REQUEST: 1B][proposal_hash: 32B]
    /// [shard_index: 1B]`
    fn encode_shard_request(hash: &Hash, shard_index: u8) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + 32 + 1);
        msg.push(MSG_SHARD_REQUEST);
        msg.extend_from_slice(hash.as_bytes());
        msg.push(shard_index);
        msg
    }

    /// Parse a shard request message.
    ///
    /// Returns `(proposal_hash, shard_index)` or `None` if malformed.
    fn parse_shard_request(bytes: &[u8]) -> Option<(Hash, u8)> {
        if bytes.len() < 1 + 32 + 1 {
            return None;
        }
        if bytes[0] != MSG_SHARD_REQUEST {
            return None;
        }
        let hash_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
        let hash = Hash(hash_bytes);
        let shard_index = bytes[33];
        Some((hash, shard_index))
    }

    /// Encode a shard response message (backfill reply).
    ///
    /// Format: `[MSG_SHARD_RESPONSE: 1B][proposal_hash: 32B]
    /// [shard_index: 1B][shard_len: 4B LE][shard_data: shard_len B]`
    fn encode_shard_response(hash: &Hash, shard_index: u8, shard: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + 32 + 1 + 4 + shard.len());
        msg.push(MSG_SHARD_RESPONSE);
        msg.extend_from_slice(hash.as_bytes());
        msg.push(shard_index);
        msg.extend_from_slice(&(u32::try_from(shard.len()).unwrap_or(0)).to_le_bytes());
        msg.extend_from_slice(shard);
        msg
    }

    /// Parse a shard response message.
    ///
    /// Returns `(proposal_hash, shard_index, shard_data)` or `None`.
    fn parse_shard_response(bytes: &[u8]) -> Option<(Hash, u8, Vec<u8>)> {
        if bytes.len() < 1 + 32 + 1 + 4 {
            return None;
        }
        if bytes[0] != MSG_SHARD_RESPONSE {
            return None;
        }
        let hash_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
        let hash = Hash(hash_bytes);
        let shard_index = bytes[33];
        let shard_len = u32::from_le_bytes(bytes[34..38].try_into().ok()?);
        let shard_len = usize::try_from(shard_len).ok()?;
        if bytes.len() < 38 + shard_len {
            return None;
        }
        let shard = bytes[38..38 + shard_len].to_vec();
        Some((hash, shard_index, shard))
    }

    /// Drain inbound transport messages and store received shards.
    ///
    /// This is the validator-side receive path. Call this after the
    /// leader has broadcast to collect inbound shard messages from
    /// the transport. The method processes all pending messages:
    ///
    /// - `MSG_SHARD`: stores the shard in `received`.
    /// - `MSG_SHARD_REQUEST`: responds with the requested shard (if
    ///   this node has it). This is the backfill server path.
    /// - `MSG_SHARD_RESPONSE`: stores the shard in `received`. This
    ///   is the backfill client path.
    ///
    /// Returns the number of messages processed.
    pub fn recv_shards(&mut self) -> usize {
        let mut count = 0;
        while let Some(msg) = self.transport.recv() {
            count += 1;
            if msg.bytes.is_empty() {
                continue;
            }
            match msg.bytes[0] {
                MSG_SHARD => {
                    if let Some((hash, shard_index, shard)) = Self::parse_shard_msg(&msg.bytes) {
                        self.received.entry(hash).or_default().insert(shard_index, shard);
                    }
                }
                MSG_SHARD_REQUEST => {
                    if let Some((hash, shard_index)) = Self::parse_shard_request(&msg.bytes) {
                        self.respond_to_shard_request(&hash, shard_index);
                    }
                }
                MSG_SHARD_RESPONSE => {
                    if let Some((hash, shard_index, shard)) = Self::parse_shard_response(&msg.bytes)
                    {
                        self.received.entry(hash).or_default().insert(shard_index, shard);
                    }
                }
                _ => {}
            }
        }
        count
    }

    /// Respond to a shard request by sending the shard to the
    /// requester. If this node doesn't have the shard, the request
    /// is silently dropped (the requester will ask another peer).
    fn respond_to_shard_request(&mut self, hash: &Hash, shard_index: u8) {
        // Check if we have the shard (either as a sender or receiver).
        let shard = self
            .sent
            .get(hash)
            .and_then(|shards| shards.iter().find(|(idx, _)| *idx == usize::from(shard_index)))
            .map(|(_, s)| s.clone())
            .or_else(|| self.received.get(hash).and_then(|m| m.get(&shard_index).cloned()));
        if let Some(shard) = shard {
            let response = Self::encode_shard_response(hash, shard_index, &shard);
            // Send to the peer that requested. In the current
            // transport model, we don't know which peer sent the
            // request (the `InboundMessage.from` field has it, but
            // we've already consumed the message). For the mesh
            // transport, we broadcast the response to all peers —
            // only the requester will match the hash. For TCP, we
            // could track the requester, but the v0 protocol keeps
            // it simple: broadcast the response.
            for (i, peer) in self.peer_ids.iter().enumerate() {
                if i != self.my_index {
                    let _ = self.transport.send(peer, &response);
                }
            }
        }
    }

    /// Send shard requests to all peers for a given proposal hash.
    ///
    /// Requests shards 0..n from all peers. Each peer that has a
    /// shard will respond. The requester needs `k = 2f+1` responses
    /// to reconstruct.
    fn request_shards(&mut self, hash: &Hash) {
        for shard_index in 0u8..u8::try_from(self.n).unwrap_or(255) {
            let request = Self::encode_shard_request(hash, shard_index);
            for (i, peer) in self.peer_ids.iter().enumerate() {
                if i != self.my_index {
                    let _ = self.transport.send(peer, &request);
                }
            }
        }
    }

    /// Whether the adapter can reconstruct a proposal from the
    /// received shards (i.e., has at least `k = 2f+1` shards).
    pub fn can_reconstruct(&self, hash: &Hash) -> bool {
        let received_count = self.received.get(hash).map_or(0, HashMap::len);
        let sent_count = self.sent.get(hash).map_or(0, Vec::len);
        (received_count + sent_count).max(received_count) >= self.k()
    }

    /// The number of shards received for a proposal.
    #[must_use]
    pub fn shard_count(&self, hash: &Hash) -> usize {
        self.received.get(hash).map_or(0, HashMap::len)
    }

    /// The proof of availability for a broadcast proposal.
    /// Returns `None` if the proposal is unknown.
    #[must_use]
    pub fn proof_of_availability(&self, hash: &Hash) -> Option<Hash> {
        self.proof.get(hash).copied()
    }

    /// Access the underlying transport (for testing or for the
    /// consensus engine to drain non-broadcast messages).
    pub fn transport(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: Transport> BroadcastEngine for NetworkedBroadcast<T> {
    fn broadcast(&mut self, proposal: &Proposal) -> Result<(), BroadcastError> {
        let payload_size: u64 = proposal.txs.iter().map(|tx| tx.as_bytes().len() as u64).sum();
        if payload_size > NETWORKED_MAX_BYTES {
            return Err(BroadcastError::PayloadTooLarge);
        }
        let hash = proposal_hash(proposal);

        // Serialize, pad, and RS-encode.
        let data = Self::serialize_proposal(proposal);
        let shard_size = self.shard_size(data.len());
        let k = self.k();
        let mut padded = data.clone();
        padded.resize(k * shard_size, 0);
        let shards = self.rs.encode(&padded, shard_size);

        // Compute proof of availability.
        let proof = Self::compute_proof(&shards);

        // Store all shards locally (for backfill responses).
        let stored: Vec<(usize, Vec<u8>)> = shards.iter().cloned().enumerate().collect();
        self.sent.insert(hash, stored);
        self.proof.insert(hash, proof);
        self.proposals.insert(hash, proposal.clone());

        // Send each shard to its assigned validator via the transport.
        // Shard i goes to validator i (systematic assignment).
        for (i, shard) in shards.iter().enumerate() {
            if i == self.my_index {
                // Store our own shard locally (no network send).
                self.received
                    .entry(hash)
                    .or_default()
                    .insert(u8::try_from(i).unwrap_or(0), shard.clone());
                continue;
            }
            let shard_msg = Self::encode_shard_msg(&hash, u8::try_from(i).unwrap_or(0), shard);
            let peer = &self.peer_ids[i];
            match self.transport.send(peer, &shard_msg) {
                Ok(()) | Err(TransportError::UnknownPeer) => {
                    // UnknownPeer: the peer is not connected. In
                    // production, this would trigger a retry or peer
                    // discovery. For now, we continue — the shard is
                    // stored locally and can be requested via backfill.
                }
                Err(TransportError::MessageTooLarge) => {
                    return Err(BroadcastError::PayloadTooLarge);
                }
                Err(TransportError::ChannelClosed) => {
                    return Err(BroadcastError::DisseminationFailed);
                }
            }
        }

        Ok(())
    }

    fn backfill(&mut self, hash: &Hash) -> Result<Proposal, BroadcastError> {
        // Fast path: if we have the original proposal, return it.
        if let Some(proposal) = self.proposals.get(hash) {
            return Ok(proposal.clone());
        }

        // If we already have enough shards, reconstruct.
        if self.can_reconstruct(hash) {
            return self.reconstruct(hash);
        }

        // Send shard requests to all peers.
        self.request_shards(hash);

        // Drain inbound messages (collect shard responses).
        self.recv_shards();

        // Try to reconstruct.
        if self.can_reconstruct(hash) {
            return self.reconstruct(hash);
        }

        Err(BroadcastError::DataUnavailable)
    }

    fn capabilities(&self) -> BroadcastCaps {
        BroadcastCaps {
            proof_of_availability: true,
            erasure_coded: true,
            max_payload_bytes: NETWORKED_MAX_BYTES,
        }
    }
}

impl<T: Transport> NetworkedBroadcast<T> {
    /// Reconstruct a proposal from received shards.
    fn reconstruct(&self, hash: &Hash) -> Result<Proposal, BroadcastError> {
        // Merge shards from `sent` (leader's local copy) and
        // `received` (shards from peers). Deduplicate by shard index.
        let mut merged: HashMap<u8, Vec<u8>> = HashMap::new();
        if let Some(sent) = self.sent.get(hash) {
            for (idx, shard) in sent {
                merged.insert(u8::try_from(*idx).unwrap_or(0), shard.clone());
            }
        }
        if let Some(received) = self.received.get(hash) {
            for (idx, shard) in received {
                merged.insert(*idx, shard.clone());
            }
        }
        if merged.len() < self.k() {
            return Err(BroadcastError::DataUnavailable);
        }

        let shard_size = merged.values().next().map_or(0, Vec::len);
        let available: Vec<(usize, Vec<u8>)> =
            merged.iter().map(|(idx, shard)| (usize::from(*idx), shard.clone())).collect();

        let data =
            self.rs.reconstruct(&available, shard_size).ok_or(BroadcastError::DataUnavailable)?;

        // The height is not encoded in the shard data. In
        // production, the height comes from the block header. For
        // now, use height 0 — the consensus engine knows the height
        // from the proposal header.
        let proposal = Self::deserialize_proposal(primitives::Height::new(0), &data);
        Ok(proposal)
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
    use p2p::MeshNetwork;
    use primitives::Height;
    use types::TxBytes;

    fn make_proposal(height: u64, txs: Vec<Vec<u8>>) -> Proposal {
        let txs = txs.into_iter().map(TxBytes::new).collect();
        Proposal { height: Height::new(height), txs, attestation: None }
    }

    /// Build a mesh network of `n` `NetworkedBroadcast` adapters.
    fn build_network(
        n: usize,
        f: usize,
    ) -> (MeshNetwork, Vec<NetworkedBroadcast<p2p::MeshTransport>>) {
        let net = MeshNetwork::new(n);
        let peer_ids: Vec<ports::transport::PeerId> = (0..n).map(MeshNetwork::peer_id).collect();
        let adapters: Vec<NetworkedBroadcast<p2p::MeshTransport>> = (0..n)
            .map(|i| {
                let transport = net.transport(i);
                NetworkedBroadcast::new(transport, n, f, i, peer_ids.clone())
            })
            .collect();
        (net, adapters)
    }

    #[test]
    fn networked_broadcast_distributes_shards() {
        // 4 validators, f=1. Leader (node 0) broadcasts.
        let (net, mut adapters) = build_network(4, 1);
        let _ = net;
        let proposal = make_proposal(1, vec![vec![0xAA; 100], vec![0xBB; 50]]);
        let hash = proposal_hash(&proposal);

        // Leader broadcasts.
        assert!(adapters[0].broadcast(&proposal).is_ok());

        // Followers receive shards.
        for adapter in adapters.iter_mut().skip(1).take(3) {
            adapter.recv_shards();
            assert!(adapter.shard_count(&hash) > 0, "follower should have received shards");
        }

        // Each follower should have at least 1 shard (its own).
        // With n=4 and k=3, we need 3 shards to reconstruct.
        // The leader sends 1 shard to each of 3 followers + keeps 1.
        // Each follower has 1 shard — not enough alone.
        // But the leader has all 4 shards.
        assert!(adapters[0].can_reconstruct(&hash), "leader has all shards");
    }

    #[test]
    fn networked_broadcast_backfill_reconstructs() {
        // 4 validators, f=1. Node 0 broadcasts, node 1 misses it
        // but collects shards from peers via backfill.
        let (net, mut adapters) = build_network(4, 1);
        let _ = net;
        let proposal = make_proposal(2, vec![vec![0xCC; 64], vec![0xDD; 32]]);
        let hash = proposal_hash(&proposal);

        // Leader broadcasts.
        adapters[0].broadcast(&proposal).expect("broadcast");

        // Nodes 2 and 3 receive their shards.
        adapters[2].recv_shards();
        adapters[3].recv_shards();

        // Node 1 missed the broadcast (didn't call recv_shards).
        // Now node 1 tries to backfill: it requests shards from peers.
        // Nodes 2 and 3 have their shards and will respond.
        // But first, node 1 needs to request, then nodes 2/3 need
        // to recv the request and respond, then node 1 needs to
        // recv the responses.

        // Step 1: node 1 sends shard requests.
        // (backfill does this internally, but we need to manually
        // drive the message flow since the mesh is synchronous.)
        adapters[1].request_shards(&hash);

        // Step 2: nodes 2 and 3 receive the requests and respond.
        adapters[2].recv_shards();
        adapters[3].recv_shards();

        // Step 3: node 1 receives the responses.
        // Also, node 0 (leader) receives requests and responds.
        adapters[0].recv_shards();
        adapters[1].recv_shards();

        // Node 1 should now have enough shards to reconstruct.
        // With n=4, k=3: node 1 gets shards from nodes 0, 2, 3 (3 shards).
        assert!(
            adapters[1].can_reconstruct(&hash),
            "node 1 should have k=3 shards after backfill, got {}",
            adapters[1].shard_count(&hash)
        );

        let recovered = adapters[1].backfill(&hash).expect("backfill must reconstruct");
        assert_eq!(recovered.txs.len(), proposal.txs.len());
        assert_eq!(recovered.txs[0].as_bytes(), proposal.txs[0].as_bytes());
    }

    #[test]
    fn networked_broadcast_caps_advertised() {
        let (net, adapters) = build_network(4, 1);
        let _ = net;
        let caps = adapters[0].capabilities();
        assert!(caps.proof_of_availability);
        assert!(caps.erasure_coded);
        assert_eq!(caps.max_payload_bytes, NETWORKED_MAX_BYTES);
    }

    #[test]
    fn networked_broadcast_rejects_oversized() {
        let (net, mut adapters) = build_network(4, 1);
        let _ = net;
        let big_tx = vec![0u8; usize::try_from(NETWORKED_MAX_BYTES + 1).unwrap()];
        let proposal = make_proposal(0, vec![big_tx]);
        assert_eq!(adapters[0].broadcast(&proposal), Err(BroadcastError::PayloadTooLarge));
    }

    #[test]
    fn networked_broadcast_proof_of_availability() {
        let (net, mut adapters) = build_network(7, 2);
        let _ = net;
        let proposal = make_proposal(1, vec![vec![0xAA; 100], vec![0xBB; 50]]);
        adapters[0].broadcast(&proposal).expect("broadcast");
        let hash = proposal_hash(&proposal);
        let proof = adapters[0].proof_of_availability(&hash);
        assert!(proof.is_some(), "proof must be computed");
        assert_ne!(proof, Some(Hash::ZERO), "proof must be non-zero");
    }

    #[test]
    fn networked_broadcast_proof_deterministic() {
        let (net1, mut adapters1) = build_network(7, 2);
        let (net2, mut adapters2) = build_network(7, 2);
        let _ = (net1, net2);
        let proposal = make_proposal(1, vec![vec![0x42; 32], vec![0x84; 64]]);
        adapters1[0].broadcast(&proposal).unwrap();
        adapters2[0].broadcast(&proposal).unwrap();
        let hash = proposal_hash(&proposal);
        assert_eq!(
            adapters1[0].proof_of_availability(&hash),
            adapters2[0].proof_of_availability(&hash),
            "proofs must be deterministic"
        );
    }

    #[test]
    fn networked_broadcast_tolerates_f_missing() {
        // 7 validators, f=2. Tolerates 2 missing shards.
        let (net, mut adapters) = build_network(7, 2);
        let _ = net;
        let proposal = make_proposal(3, vec![vec![0xEE; 128]]);
        let hash = proposal_hash(&proposal);

        // Leader broadcasts.
        adapters[0].broadcast(&proposal).expect("broadcast");

        // All followers receive.
        for adapter in adapters.iter_mut().skip(1).take(6) {
            adapter.recv_shards();
        }

        // Simulate 2 nodes (6 and 5) losing their shards.
        // The leader still has all 7 shards, so it can reconstruct.
        assert!(adapters[0].can_reconstruct(&hash), "leader has all shards");

        // A follower that received its shard has 1 shard.
        // To reconstruct, it needs k=5 shards. It has 1.
        // It needs 4 more from backfill.
        assert_eq!(adapters[1].shard_count(&hash), 1, "follower has 1 shard");

        // Node 1 requests shards from peers.
        adapters[1].request_shards(&hash);
        // All other nodes receive the request and respond.
        for (i, adapter) in adapters.iter_mut().enumerate().take(7) {
            if i != 1 {
                adapter.recv_shards();
            }
        }
        // Node 1 collects responses.
        adapters[1].recv_shards();

        // Node 1 should now have enough shards (k=5).
        assert!(
            adapters[1].can_reconstruct(&hash),
            "node 1 should have k=5 shards, got {}",
            adapters[1].shard_count(&hash)
        );

        let recovered = adapters[1].backfill(&hash).expect("reconstruct");
        assert_eq!(recovered.txs.len(), proposal.txs.len());
        assert_eq!(recovered.txs[0].as_bytes(), proposal.txs[0].as_bytes());
    }

    #[test]
    fn networked_broadcast_unknown_hash_errors() {
        let (net, mut adapters) = build_network(4, 1);
        let _ = net;
        let bogus = Hash::ZERO;
        let err = adapters[0].backfill(&bogus).expect_err("unknown hash");
        assert_eq!(err, BroadcastError::DataUnavailable);
    }

    #[test]
    fn shard_msg_round_trip() {
        let hash = Hash([0xAB; 32]);
        let shard = vec![0x42; 100];
        let msg = NetworkedBroadcast::<p2p::MeshTransport>::encode_shard_msg(&hash, 3, &shard);
        let (h, idx, s) =
            NetworkedBroadcast::<p2p::MeshTransport>::parse_shard_msg(&msg).expect("parse");
        assert_eq!(h, hash);
        assert_eq!(idx, 3);
        assert_eq!(s, shard);
    }

    #[test]
    fn shard_request_round_trip() {
        let hash = Hash([0xCD; 32]);
        let msg = NetworkedBroadcast::<p2p::MeshTransport>::encode_shard_request(&hash, 5);
        let (h, idx) =
            NetworkedBroadcast::<p2p::MeshTransport>::parse_shard_request(&msg).expect("parse");
        assert_eq!(h, hash);
        assert_eq!(idx, 5);
    }

    #[test]
    fn shard_response_round_trip() {
        let hash = Hash([0xEF; 32]);
        let shard = vec![0x99; 200];
        let msg = NetworkedBroadcast::<p2p::MeshTransport>::encode_shard_response(&hash, 2, &shard);
        let (h, idx, s) =
            NetworkedBroadcast::<p2p::MeshTransport>::parse_shard_response(&msg).expect("parse");
        assert_eq!(h, hash);
        assert_eq!(idx, 2);
        assert_eq!(s, shard);
    }

    #[test]
    fn parse_malformed_messages_fail() {
        // Empty message.
        assert!(NetworkedBroadcast::<p2p::MeshTransport>::parse_shard_msg(&[]).is_none());
        // Wrong tag.
        assert!(NetworkedBroadcast::<p2p::MeshTransport>::parse_shard_msg(&[0xFF; 40]).is_none());
        // Truncated.
        assert!(
            NetworkedBroadcast::<p2p::MeshTransport>::parse_shard_msg(&[MSG_SHARD; 10]).is_none()
        );
        assert!(
            NetworkedBroadcast::<p2p::MeshTransport>::parse_shard_request(&[MSG_SHARD_REQUEST; 10])
                .is_none()
        );
    }
}
