//! The transport (peer-to-peer networking) port.
//!
//! # What this is
//!
//! The seam by which consensus and broadcast messages reach other
//! validators. The default is commonware-p2p authenticated transport
//! (plan.md §2.1); a libp2p/QUIC adapter is planned post-testnet. The
//! trait makes the swap a configuration choice.
//!
//! # Why a port
//!
//! Consensus engines and broadcast adapters should not know whether
//! they are talking over commonware-p2p, libp2p/QUIC, or an in-process
//! mock for deterministic simulation. The transport port abstracts
//! that away: send a message to a peer, receive the next message from
//! any peer. The deterministic runtime's [`runtime::Mailbox`] is the
//! simulation substrate; the real transports wrap TCP/QUIC.
//!
//! # Phase 0 scope
//!
//! Trait + capability flags only. The first real implementation
//! (commonware-p2p) lands in Phase 1. The `runtime` crate's `Mailbox`
//! serves as the in-process mock for deterministic simulation today.

/// A peer's network identifier. Opaque to the transport trait — the
/// concrete transport defines what this means (public key, peer ID,
/// index). `Vec<u8>` rather than a fixed type so different transports
/// can use different identity schemes without the trait assuming one.
///
/// On the hot path this is a reference (borrowed from the caller's
/// peer table); allocation is the caller's responsibility, not the
/// transport's.
pub type PeerId = Vec<u8>;

/// Capability flags a [`Transport`] advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCaps {
    /// `true` if the transport authenticates peers (mutual
    /// authentication, no spoofable peer IDs). commonware-p2p does;
    /// a plain TCP mock would not.
    pub authenticated: bool,
    /// `true` if the transport encrypts the channel (TLS, Noise).
    /// Authenticated + encrypted is the production minimum.
    pub encrypted: bool,
    /// Maximum message size the transport accepts, in bytes. Larger
    /// messages must be chunked by a higher layer (the broadcast
    /// adapter handles this for block data).
    pub max_message_bytes: u64,
}

/// An inbound message from a peer: who sent it, and the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundMessage {
    /// The sender's peer identifier.
    pub from: PeerId,
    /// The message bytes. Opaque to the transport — the consensus
    /// engine and broadcast adapter define the payload format.
    pub bytes: Vec<u8>,
}

/// The transport (peer-to-peer networking) port. Implemented by the
/// default commonware-p2p transport and by dev/test mocks.
///
/// v0 is synchronous (matching the OAI v0 traits); Phase 1 revisits
/// the boundary shape with oxideBFT's real I/O loop. The `send`/`recv`
/// shape mirrors [`runtime::Mailbox`] so the deterministic runtime
/// can serve as a zero-code-change mock.
pub trait Transport: Send {
    /// Send `bytes` to `peer`. Returns `Ok(())` if the message was
    /// handed to the transport (not necessarily delivered yet —
    /// transports are async under the hood); `Err` on a synchronous
    /// failure (unknown peer, message too large, channel closed).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UnknownPeer`] if the peer is not in
    /// the transport's peer table, [`TransportError::MessageTooLarge`]
    /// if the message exceeds `max_message_bytes`, or
    /// [`TransportError::ChannelClosed`] if the transport is shut down.
    fn send(&mut self, peer: &PeerId, bytes: &[u8]) -> Result<(), TransportError>;

    /// Receive the next inbound message, blocking until one arrives.
    /// Returns `None` if the transport is shut down. The deterministic
    /// mock returns immediately if a message is queued, else blocks
    /// the runtime's poll loop (yields `Pending`).
    fn recv(&mut self) -> Option<InboundMessage>;

    /// The capabilities this adapter provides. Checked at wiring time
    /// (config validation) and by the conformance suite.
    fn capabilities(&self) -> TransportCaps;
}

/// Ways a transport send can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The peer is not known to the transport (not connected, not
    /// in the peer table).
    UnknownPeer,
    /// The message exceeded the transport's `max_message_bytes`.
    MessageTooLarge,
    /// The transport channel is closed (shut down, irrecoverable
    /// error). Phase 1 splits this into per-cause variants.
    ChannelClosed,
    /// The outbound channel is full (backpressure). The caller
    /// should retry or shed load. This protects against a slow
    /// peer causing unbounded outbound queue growth (OOM).
    ChannelFull,
}
