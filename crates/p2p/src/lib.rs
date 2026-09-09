//! Oxide transport implementations — the in-process mesh for devnet/sim.
//!
//! # What this is
//!
//! The default Phase 1 [`Transport`](ports::Transport) implementation:
//! an in-process mesh of N nodes, each with a FIFO queue. Sending to
//! peer X appends to X's queue; receiving pops from your own queue.
//! No real networking, no async I/O, no system calls — just
//! `VecDeque` behind a `Mutex`. This is the dev/test mock the
//! transport port docs describe.
//!
//! # Why this first
//!
//! The plan (plan.md §13 Phase 1) requires a 4–50 node local devnet
//! that sustains 50–100ms blocks on oxideBFT. The real
//! commonware-p2p adapter is post-testnet; the in-process mesh
//! proves the [`Transport`](ports::Transport) seam end-to-end and
//! enables the multi-node devnet without pulling a heavy networking
//! dependency. When the real adapter lands, it implements the same
//! trait and the devnet swaps it via config.
//!
//! # Determinism contract
//!
//! The mesh is deterministic: messages are delivered in send order
//! (FIFO per receiver). The sender order is determined by the
//! simulation's scheduler (the deterministic runtime), not by the
//! mesh. This matches the [`runtime::Mailbox`] determinism contract:
//! the queue preserves order; the scheduler determines it.
//!
//! # Caps
//!
//! `MeshTransport` advertises `authenticated = false`,
//! `encrypted = false` — it is a devnet/sim transport, not a
//! production one. The conformance suite checks that a real transport
//! advertises both as `true`; the mesh is exempt (it is never used
//! outside devnet/sim).
//!
//! # Phase 1 scope
//!
//! v0 is a fully-connected mesh (every node can send to every other).
//! Peer scoring, topology restrictions, and ingress buffering land
//! with the commonware-p2p adapter (post-testnet).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use ports::transport::{InboundMessage, PeerId, Transport, TransportCaps, TransportError};

/// The default maximum message size for the mesh: 16 MiB. Matches
/// the broadcast crate's `ERASURE_MAX_BYTES` — a full erasure-coded
/// block chunk fits in one mesh message.
const MESH_MAX_MESSAGE_BYTES: u64 = 16 << 20;

/// A shared mesh network: N FIFO queues, one per node, behind a
/// single `Arc` so all `MeshTransport` handles share the same
/// routing table.
///
/// The mesh is fully-connected: any node can send to any other by
/// index. The `PeerId` for node `i` is `i.to_le_bytes().to_vec()`
/// (a 1-byte, 2-byte, 4-byte, or 8-byte little-endian integer
/// depending on the index — see [`MeshNetwork::peer_id`]).
struct MeshNetworkInner {
    /// One FIFO queue per node, indexed by node index.
    queues: Vec<Mutex<VecDeque<InboundMessage>>>,
}

/// The shared mesh network. Clone this to hand out `MeshTransport`
/// handles to each node.
#[derive(Clone)]
pub struct MeshNetwork {
    inner: Arc<MeshNetworkInner>,
    /// Number of nodes in the mesh.
    n: usize,
}

impl MeshNetwork {
    /// Construct a fully-connected mesh of `n` nodes.
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` (a mesh with no nodes is meaningless).
    pub fn new(n: usize) -> Self {
        assert!(n > 0, "mesh must have at least one node");
        let queues = (0..n).map(|_| Mutex::new(VecDeque::new())).collect();
        Self { inner: Arc::new(MeshNetworkInner { queues }), n }
    }

    /// The number of nodes in the mesh.
    pub fn n(&self) -> usize {
        self.n
    }

    /// The `PeerId` for node `index`. Little-endian bytes of the
    /// `usize` index — compact for small node counts (1 byte for
    /// n ≤ 255, 2 for n ≤ 65535, etc.).
    pub fn peer_id(index: usize) -> PeerId {
        index.to_le_bytes().to_vec()
    }

    /// Parse a `PeerId` back to a node index. Returns `None` if the
    /// bytes are not a valid little-endian `usize`.
    fn parse_peer_id(pid: &PeerId) -> Option<usize> {
        match pid.len() {
            1 => Some(usize::from(pid[0])),
            2 => Some(u16::from_le_bytes([pid[0], pid[1]]) as usize),
            4 => Some(u32::from_le_bytes([pid[0], pid[1], pid[2], pid[3]]) as usize),
            8 => Some(usize::try_from(u64::from_le_bytes([
                pid[0], pid[1], pid[2], pid[3], pid[4], pid[5], pid[6], pid[7],
            ])).ok()?),
            _ => None,
        }
    }

    /// Build a `MeshTransport` handle for node `index`. The handle
    /// can send to any peer and receive from its own queue.
    ///
    /// # Panics
    ///
    /// Panics if `index >= n`.
    pub fn transport(&self, index: usize) -> MeshTransport {
        assert!(index < self.n, "node index {index} out of range (n={})", self.n);
        MeshTransport { network: self.clone(), index }
    }
}

/// A single node's handle into a [`MeshNetwork`]. Implements
/// [`Transport`]: send to any peer, receive from own queue.
///
/// The handle is `Clone` (the underlying network is `Arc`-shared),
/// but each node should have exactly one handle to preserve the
/// single-consumer queue contract.
pub struct MeshTransport {
    network: MeshNetwork,
    /// This node's index in the mesh.
    index: usize,
}

impl MeshTransport {
    /// This node's index in the mesh.
    pub fn index(&self) -> usize {
        self.index
    }

    /// This node's `PeerId`.
    pub fn peer_id(&self) -> PeerId {
        MeshNetwork::peer_id(self.index)
    }
}

impl Transport for MeshTransport {
    fn send(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), TransportError> {
        let Some(target) = MeshNetwork::parse_peer_id(peer) else {
            return Err(TransportError::UnknownPeer);
        };
        if target >= self.network.n {
            return Err(TransportError::UnknownPeer);
        }
        if bytes.len() as u64 > MESH_MAX_MESSAGE_BYTES {
            return Err(TransportError::MessageTooLarge);
        }
        let msg = InboundMessage { from: self.peer_id(), bytes: bytes.to_vec() };
        self.network.inner.queues[target].lock().unwrap().push_back(msg);
        Ok(())
    }

    fn recv(&mut self) -> Option<InboundMessage> {
        self.network.inner.queues[self.index].lock().unwrap().pop_front()
    }

    fn capabilities(&self) -> TransportCaps {
        TransportCaps {
            authenticated: false,
            encrypted: false,
            max_message_bytes: MESH_MAX_MESSAGE_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Basic send/recv: node 0 sends to node 1, node 1 receives.
    #[test]
    fn mesh_basic_send_recv() {
        let net = MeshNetwork::new(2);
        let mut t0 = net.transport(0);
        let mut t1 = net.transport(1);

        t0.send(&MeshNetwork::peer_id(1), b"hello").unwrap();
        let msg = t1.recv().expect("node 1 should receive");
        assert_eq!(msg.from, MeshNetwork::peer_id(0));
        assert_eq!(msg.bytes, b"hello");
    }

    /// FIFO order: multiple messages arrive in send order.
    #[test]
    fn mesh_fifo_order() {
        let net = MeshNetwork::new(2);
        let mut t0 = net.transport(0);
        let mut t1 = net.transport(1);

        for i in 0..10 {
            t0.send(&MeshNetwork::peer_id(1), &[i]).unwrap();
        }
        for i in 0..10 {
            let msg = t1.recv().expect("should have message");
            assert_eq!(msg.bytes, &[i]);
        }
    }

    /// Unknown peer: sending to a non-existent peer fails.
    #[test]
    fn mesh_unknown_peer() {
        let net = MeshNetwork::new(2);
        let mut t0 = net.transport(0);
        let bad_pid = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(t0.send(&bad_pid, b"x"), Err(TransportError::UnknownPeer));
    }

    /// Out-of-range index: sending to index >= n fails.
    #[test]
    fn mesh_index_out_of_range() {
        let net = MeshNetwork::new(3);
        let mut t0 = net.transport(0);
        // Index 99 in a 3-node mesh.
        let pid = MeshNetwork::peer_id(99);
        assert_eq!(t0.send(&pid, b"x"), Err(TransportError::UnknownPeer));
    }

    /// Message too large: sending a message over the cap fails.
    #[test]
    fn mesh_message_too_large() {
        let net = MeshNetwork::new(2);
        let mut t0 = net.transport(0);
        let big = vec![0u8; usize::try_from(MESH_MAX_MESSAGE_BYTES + 1).unwrap()];
        assert_eq!(t0.send(&MeshNetwork::peer_id(1), &big), Err(TransportError::MessageTooLarge));
    }

    /// Empty recv: returns `None` when no messages are queued.
    #[test]
    fn mesh_empty_recv() {
        let net = MeshNetwork::new(2);
        let mut t0 = net.transport(0);
        assert!(t0.recv().is_none());
    }

    /// Capabilities: the mesh advertises unauthenticated, unencrypted.
    #[test]
    fn mesh_capabilities() {
        let net = MeshNetwork::new(2);
        let t0 = net.transport(0);
        let caps = t0.capabilities();
        assert!(!caps.authenticated);
        assert!(!caps.encrypted);
        assert_eq!(caps.max_message_bytes, MESH_MAX_MESSAGE_BYTES);
    }

    /// Multi-node mesh: node 0 broadcasts to all others.
    #[test]
    fn mesh_broadcast() {
        let net = MeshNetwork::new(4);
        let mut t0 = net.transport(0);
        let mut t1 = net.transport(1);
        let mut t2 = net.transport(2);
        let mut t3 = net.transport(3);

        for i in 1..4 {
            t0.send(&MeshNetwork::peer_id(i), b"broadcast").unwrap();
        }
        for t in [&mut t1, &mut t2, &mut t3] {
            let msg = t.recv().expect("should receive broadcast");
            assert_eq!(msg.from, MeshNetwork::peer_id(0));
            assert_eq!(msg.bytes, b"broadcast");
        }
    }

    /// Bidirectional: node 0 and node 1 exchange messages.
    #[test]
    fn mesh_bidirectional() {
        let net = MeshNetwork::new(2);
        let mut t0 = net.transport(0);
        let mut t1 = net.transport(1);

        t0.send(&MeshNetwork::peer_id(1), b"ping").unwrap();
        t1.send(&MeshNetwork::peer_id(0), b"pong").unwrap();

        assert_eq!(t1.recv().unwrap().bytes, b"ping");
        assert_eq!(t0.recv().unwrap().bytes, b"pong");
    }

    /// `PeerId` round-trip: parse(encode(i)) == i for small indices.
    #[test]
    fn mesh_peer_id_roundtrip() {
        for i in [0usize, 1, 100, 255] {
            let pid = MeshNetwork::peer_id(i);
            assert_eq!(MeshNetwork::parse_peer_id(&pid), Some(i));
        }
    }

    /// Self-send: a node can send to itself.
    #[test]
    fn mesh_self_send() {
        let net = MeshNetwork::new(2);
        let mut t0 = net.transport(0);
        t0.send(&MeshNetwork::peer_id(0), b"self").unwrap();
        let msg = t0.recv().expect("should receive self-message");
        assert_eq!(msg.bytes, b"self");
    }
}
