//! Peer discovery for the TCP transport.
//!
//! # What this is
//!
//! A simple gossip-based peer discovery protocol. Each node
//! maintains a list of known peer addresses. When two nodes
//! connect, they exchange peer lists. Each node then connects to
//! the newly discovered peers.
//!
//! # Why this exists
//!
//! Static peer configuration requires every node to know every
//! other node's address at startup. This doesn't scale: adding a
//! new node requires updating every node's config. Peer discovery
//! allows nodes to find each other dynamically — a new node only
//! needs to know one bootstrap node.
//!
//! # Protocol
//!
//! 1. A node connects to its bootstrap peers (from config).
//! 2. After the connection is established, it sends a
//!    [`DiscoveryMessage::PeerList`] with its known peers.
//! 3. The peer responds with its own [`DiscoveryMessage::PeerList`].
//! 4. Both nodes add the newly discovered peers to their peer store.
//! 5. The transport's `add_peer` method is called for each new peer.
//! 6. Steps 2-5 repeat for each new connection.
//!
//! # Limitations
//!
//! - No peer reputation or banning (Phase 2)
//! - No DHT-based discovery (Phase 2)
//! - No DNS-based discovery (Phase 2)
//! - Peer lists are not authenticated (Phase 2 — TLS helps)

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::tcp::TcpAddr;
use ports::transport::PeerId;

/// A peer discovery message exchanged between nodes.
///
/// Serialized as a length-prefixed frame over the transport. The
/// first byte is the message type; the rest is the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMessage {
    /// A request for the peer's known peer list.
    ///
    /// Payload: empty.
    RequestPeerList,

    /// A response with the peer's known peer list.
    ///
    /// Payload: a list of `(peer_id, addr)` pairs.
    PeerList(Vec<(PeerId, TcpAddr)>),
}

impl DiscoveryMessage {
    /// The message type byte for `RequestPeerList`.
    const TYPE_REQUEST: u8 = 0x01;

    /// The message type byte for `PeerList`.
    const TYPE_PEER_LIST: u8 = 0x02;

    /// Serialize the discovery message to bytes.
    ///
    /// Format: `[type: 1 byte][payload]`
    ///
    /// For `RequestPeerList`: `[0x01]`
    /// For `PeerList`: `[0x02][count: 4 bytes BE u32][[peer_id_len: 2 bytes BE u16][peer_id][addr_len: 2 bytes BE u16][addr]]...`
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::RequestPeerList => vec![Self::TYPE_REQUEST],
            Self::PeerList(peers) => {
                let mut buf = Vec::with_capacity(1 + 4 + peers.len() * 64);
                buf.push(Self::TYPE_PEER_LIST);
                buf.extend_from_slice(
                    &(u32::try_from(peers.len()).unwrap_or(u32::MAX)).to_be_bytes(),
                );
                for (id, addr) in peers {
                    buf.extend_from_slice(
                        &(u16::try_from(id.len()).unwrap_or(u16::MAX)).to_be_bytes(),
                    );
                    buf.extend_from_slice(id);
                    buf.extend_from_slice(
                        &(u16::try_from(addr.len()).unwrap_or(u16::MAX)).to_be_bytes(),
                    );
                    buf.extend_from_slice(addr.as_bytes());
                }
                buf
            }
        }
    }

    /// Deserialize a discovery message from bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the bytes are malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, DiscoveryError> {
        if bytes.is_empty() {
            return Err(DiscoveryError::Empty);
        }
        match bytes[0] {
            Self::TYPE_REQUEST => Ok(Self::RequestPeerList),
            Self::TYPE_PEER_LIST => {
                let rest = &bytes[1..];
                if rest.len() < 4 {
                    return Err(DiscoveryError::TooShort);
                }
                let count = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                let mut pos = 4;
                let mut peers = Vec::with_capacity(count);
                for _ in 0..count {
                    if pos + 2 > rest.len() {
                        return Err(DiscoveryError::TooShort);
                    }
                    let id_len = u16::from_be_bytes([rest[pos], rest[pos + 1]]) as usize;
                    pos += 2;
                    if pos + id_len > rest.len() {
                        return Err(DiscoveryError::TooShort);
                    }
                    let id = rest[pos..pos + id_len].to_vec();
                    pos += id_len;
                    if pos + 2 > rest.len() {
                        return Err(DiscoveryError::TooShort);
                    }
                    let addr_len = u16::from_be_bytes([rest[pos], rest[pos + 1]]) as usize;
                    pos += 2;
                    if pos + addr_len > rest.len() {
                        return Err(DiscoveryError::TooShort);
                    }
                    let addr = String::from_utf8(rest[pos..pos + addr_len].to_vec())
                        .map_err(|e| DiscoveryError::InvalidUtf8(e.to_string()))?;
                    pos += addr_len;
                    peers.push((id, addr));
                }
                Ok(Self::PeerList(peers))
            }
            _ => Err(DiscoveryError::UnknownMessageType(bytes[0])),
        }
    }
}

/// Errors that can occur during discovery message parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    /// The message is empty.
    #[error("discovery message is empty")]
    Empty,

    /// The message is too short for its declared type.
    #[error("discovery message is too short")]
    TooShort,

    /// The message type byte is unknown.
    #[error("unknown discovery message type: {0}")]
    UnknownMessageType(u8),

    /// The peer address contains invalid UTF-8.
    #[error("invalid UTF-8 in peer address: {0}")]
    InvalidUtf8(String),
}

/// A thread-safe store of known peer addresses.
///
/// Tracks peers that have been discovered but not yet connected,
/// and peers that are currently connected. Used by the discovery
/// protocol to avoid re-connecting to known peers.
pub struct PeerStore {
    /// All known peer addresses: peer ID → address.
    known: Mutex<HashMap<PeerId, TcpAddr>>,
    /// Peers we are currently connected to.
    connected: Mutex<HashSet<PeerId>>,
}

impl PeerStore {
    /// Create a new empty peer store.
    #[must_use]
    pub fn new() -> Self {
        Self { known: Mutex::new(HashMap::new()), connected: Mutex::new(HashSet::new()) }
    }

    /// Create a peer store pre-populated with bootstrap peers.
    #[must_use]
    pub fn with_bootstrap(peers: Vec<(PeerId, TcpAddr)>) -> Self {
        let store = Self::new();
        for (id, addr) in peers {
            store.add_peer(id, addr);
        }
        store
    }

    /// Add a peer to the known list. Does nothing if already known.
    ///
    /// # Panics
    ///
    /// Panics if the known-peers mutex is poisoned.
    pub fn add_peer(&self, peer_id: PeerId, addr: TcpAddr) {
        primitives::sync::lock_state(&self.known).entry(peer_id).or_insert(addr);
    }

    /// Mark a peer as connected.
    ///
    /// # Panics
    ///
    /// Panics if the connected-peers mutex is poisoned.
    pub fn mark_connected(&self, peer_id: &PeerId) {
        primitives::sync::lock_state(&self.connected).insert(peer_id.clone());
    }

    /// Mark a peer as disconnected.
    ///
    /// # Panics
    ///
    /// Panics if the connected-peers mutex is poisoned.
    pub fn mark_disconnected(&self, peer_id: &PeerId) {
        primitives::sync::lock_state(&self.connected).remove(peer_id);
    }

    /// Returns the peers that are known but not yet connected.
    ///
    /// These are candidates for new outbound connections.
    ///
    /// # Panics
    ///
    /// Panics if either mutex is poisoned.
    pub fn unconnected_peers(&self) -> Vec<(PeerId, TcpAddr)> {
        let known = primitives::sync::lock_state(&self.known);
        let connected = primitives::sync::lock_state(&self.connected);
        known
            .iter()
            .filter(|(id, _)| !connected.contains(id.as_slice()))
            .map(|(id, addr)| (id.clone(), addr.clone()))
            .collect()
    }

    /// Returns all known peers (connected + unconnected).
    ///
    /// # Panics
    ///
    /// Panics if the known-peers mutex is poisoned.
    pub fn all_peers(&self) -> Vec<(PeerId, TcpAddr)> {
        primitives::sync::lock_state(&self.known)
            .iter()
            .map(|(id, addr)| (id.clone(), addr.clone()))
            .collect()
    }

    /// Returns the number of known peers.
    ///
    /// # Panics
    ///
    /// Panics if the known-peers mutex is poisoned.
    pub fn len(&self) -> usize {
        primitives::sync::lock_state(&self.known).len()
    }

    /// Returns `true` if the store has no known peers.
    ///
    /// # Panics
    ///
    /// Panics if the known-peers mutex is poisoned.
    pub fn is_empty(&self) -> bool {
        primitives::sync::lock_state(&self.known).is_empty()
    }
}

impl Default for PeerStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encoding and decoding a `RequestPeerList` round-trips.
    #[test]
    fn request_peer_list_round_trip() {
        let msg = DiscoveryMessage::RequestPeerList;
        let encoded = msg.encode();
        assert_eq!(encoded, vec![0x01]);
        let decoded = DiscoveryMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    /// Encoding and decoding a `PeerList` round-trips.
    #[test]
    fn peer_list_round_trip() {
        let msg = DiscoveryMessage::PeerList(vec![
            (vec![0u8], "127.0.0.1:9000".to_string()),
            (vec![1u8], "127.0.0.1:9001".to_string()),
        ]);
        let encoded = msg.encode();
        let decoded = DiscoveryMessage::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    /// Decoding an empty message fails.
    #[test]
    fn decode_empty_fails() {
        assert_eq!(DiscoveryMessage::decode(&[]), Err(DiscoveryError::Empty));
    }

    /// Decoding an unknown message type fails.
    #[test]
    fn decode_unknown_type_fails() {
        assert_eq!(
            DiscoveryMessage::decode(&[0xFF]),
            Err(DiscoveryError::UnknownMessageType(0xFF))
        );
    }

    /// Decoding a truncated `PeerList` fails.
    #[test]
    fn decode_truncated_peer_list_fails() {
        // Type byte + count (4 bytes) but no peer data.
        let bytes = vec![0x02, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(DiscoveryMessage::decode(&bytes), Err(DiscoveryError::TooShort));
    }

    /// `PeerStore` tracks known and connected peers.
    #[test]
    fn peer_store_tracks_peers() {
        let store = PeerStore::with_bootstrap(vec![
            (vec![0u8], "127.0.0.1:9000".to_string()),
            (vec![1u8], "127.0.0.1:9001".to_string()),
        ]);
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());

        // Initially, no peers are connected.
        let unconnected = store.unconnected_peers();
        assert_eq!(unconnected.len(), 2);

        // Mark one as connected.
        store.mark_connected(&vec![0u8]);
        let unconnected = store.unconnected_peers();
        assert_eq!(unconnected.len(), 1);
        assert_eq!(unconnected[0].0, vec![1u8]);

        // Add a new peer.
        store.add_peer(vec![2u8], "127.0.0.1:9002".to_string());
        assert_eq!(store.len(), 3);

        // All peers.
        let all = store.all_peers();
        assert_eq!(all.len(), 3);
    }

    /// `PeerStore::add_peer` is idempotent.
    #[test]
    fn add_peer_idempotent() {
        let store = PeerStore::new();
        store.add_peer(vec![0u8], "127.0.0.1:9000".to_string());
        store.add_peer(vec![0u8], "127.0.0.1:9999".to_string()); // different addr, same ID
        assert_eq!(store.len(), 1);
        // The first address is kept (entry().or_insert).
        let all = store.all_peers();
        assert_eq!(all[0].1, "127.0.0.1:9000");
    }
}
