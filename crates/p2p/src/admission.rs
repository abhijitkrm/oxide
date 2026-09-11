//! Admission control — the gatekeeper for inbound connections and
//! messages.
//!
//! # What this is
//!
//! A unified admission policy that combines three protections:
//! - **Reputation checks:** banned peers are rejected at connection
//!   time and their messages are dropped.
//! - **Connection caps:** the number of simultaneous peer connections
//!   is bounded to prevent resource exhaustion.
//! - **Rate limiting:** per-peer ingress is throttled by a token
//!   bucket (see [`rate_limit`](super::rate_limit)).
//!
//! # Why this exists
//!
//! The TCP transport (`tcp.rs`) accepts all incoming connections and
//! delivers all messages to the consensus layer. Without admission
//! control, a byzantine peer can:
//! 1. Open many connections to exhaust file descriptors / threads.
//! 2. Reconnect immediately after being banned.
//! 3. Flood the node with high-frequency messages.
//!
//! The admission control layer sits between the TCP listener and the
//! inbound message channel, enforcing all three protections in one
//! place.
//!
//! # Design
//!
//! `AdmissionControl` is a single struct that holds:
//! - A [`PeerReputationStore`] for ban checks.
//! - A [`RateLimiter`] for per-peer ingress throttling.
//! - A connection counter and cap.
//!
//! The TCP transport calls `admit_connection` before accepting a new
//! connection and `admit_message` before delivering a message to the
//! inbound channel. Both return `true` if the connection/message is
//! admitted, `false` if it should be rejected/dropped.
//!
//! # Thread safety
//!
//! `AdmissionControl` is `Send` but not `Sync`. It's designed to be
//! wrapped in a `Mutex` when shared across threads (the accept thread
//! and the main thread). The lock is held only for brief checks, not
//! during I/O.
//!
//! # Phase scope
//!
//! Phase 3: static connection cap, reputation-based banning, token-
//! bucket rate limiting. No adaptive limits, no per-IP caps, no
//! circuit breaker. Those arrive in Phase 4+ with the production
//! networking stack.

use std::sync::Mutex;

use ports::transport::PeerId;

use crate::rate_limit::RateLimiter;
use crate::reputation::{PeerReputationStore, ReputationEvent};

/// The default maximum number of simultaneous peer connections.
///
/// Origin: a production validator typically connects to 50–200 peers.
/// 256 is generous for a testnet and bounds the thread/FD overhead
/// (one reader thread + one FD per connection). The tradeoff: higher
/// cap = more peers but more resource exposure; lower cap = fewer
/// peers but less exposure.
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// A unified admission control policy for inbound connections and
/// messages.
///
/// Wraps reputation tracking, rate limiting, and a connection cap
/// into a single gatekeeper. The TCP transport calls
/// [`admit_connection`](Self::admit_connection) before accepting a
/// new peer and [`admit_message`](Self::admit_message) before
/// delivering an inbound message.
pub struct AdmissionControl {
    /// Peer reputation tracker (ban checks).
    reputation: PeerReputationStore,
    /// Per-peer ingress rate limiter.
    rate_limiter: RateLimiter,
    /// The maximum number of simultaneous connections.
    max_connections: usize,
    /// The current number of connections (tracked via admit/release).
    current_connections: usize,
}

impl AdmissionControl {
    /// Construct an admission control policy with default parameters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reputation: PeerReputationStore::new(),
            rate_limiter: RateLimiter::new(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            current_connections: 0,
        }
    }

    /// Construct an admission control policy with a custom connection
    /// cap and rate limiter capacity.
    ///
    /// # Arguments
    ///
    /// * `max_connections` — Maximum simultaneous peer connections.
    /// * `rate_capacity` — Token bucket capacity per peer (bytes).
    /// * `rate_refill` — Token refill rate per peer (bytes/sec).
    #[must_use]
    pub fn with_limits(max_connections: usize, rate_capacity: u64, rate_refill: u64) -> Self {
        Self {
            reputation: PeerReputationStore::new(),
            rate_limiter: RateLimiter::with_capacity(rate_capacity, rate_refill),
            max_connections,
            current_connections: 0,
        }
    }

    /// Check whether a new connection from `peer` should be admitted.
    ///
    /// Returns `true` if the connection is admitted, `false` if it
    /// should be rejected. A connection is rejected if:
    /// - The peer is banned (reputation below threshold).
    /// - The connection cap is reached.
    ///
    /// On success, the connection counter is incremented.
    pub fn admit_connection(&mut self, peer: &PeerId) -> bool {
        // Reject banned peers.
        if self.reputation.is_banned(peer) {
            return false;
        }
        // Enforce connection cap.
        if self.current_connections >= self.max_connections {
            return false;
        }
        self.current_connections += 1;
        true
    }

    /// Check whether an inbound message from `peer` of `bytes` length
    /// should be admitted.
    ///
    /// Returns `true` if the message is admitted, `false` if it
    /// should be dropped. A message is dropped if:
    /// - The peer is banned.
    /// - The rate limiter rejects the message (bucket empty).
    ///
    /// On success, the peer's reputation is incremented (valid
    /// message). On failure due to rate limiting, the reputation is
    /// not changed (rate limiting is not misbehavior, just throttling).
    pub fn admit_message(&mut self, peer: &PeerId, bytes: usize) -> bool {
        // Reject messages from banned peers.
        if self.reputation.is_banned(peer) {
            return false;
        }
        // Check rate limit.
        if !self.rate_limiter.check(peer, bytes) {
            return false;
        }
        // Record positive reputation for valid message.
        self.reputation.record_event(peer, ReputationEvent::ValidMessage);
        true
    }

    /// Record a negative event for a peer (invalid message, timeout,
    /// disconnect). Returns `true` if the peer was banned as a result.
    pub fn record_misbehavior(&self, peer: &PeerId, event: ReputationEvent) -> bool {
        self.reputation.record_event(peer, event)
    }

    /// Release a connection slot (called when a peer disconnects).
    pub fn release_connection(&mut self) {
        if self.current_connections > 0 {
            self.current_connections -= 1;
        }
    }

    /// The current number of active connections.
    pub fn current_connections(&self) -> usize {
        self.current_connections
    }

    /// The maximum number of connections.
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.reputation.is_banned(peer)
    }

    /// Get a peer's reputation score.
    pub fn peer_score(&self, peer: &PeerId) -> i64 {
        self.reputation.score(peer)
    }

    /// Get the number of tracked peers in the rate limiter.
    pub fn tracked_peers(&self) -> usize {
        self.rate_limiter.peer_count()
    }
}

impl Default for AdmissionControl {
    fn default() -> Self {
        Self::new()
    }
}

/// A thread-safe wrapper around `AdmissionControl` for sharing across
/// the accept thread and the main thread.
///
/// The lock is held only for brief checks (reputation lookup, rate
/// limit check, counter increment), not during I/O.
pub struct SharedAdmissionControl(Mutex<AdmissionControl>);

impl SharedAdmissionControl {
    /// Construct a shared admission control policy.
    #[must_use]
    pub fn new(ac: AdmissionControl) -> Self {
        Self(Mutex::new(ac))
    }

    /// Check whether a new connection from `peer` should be admitted.
    /// See [`AdmissionControl::admit_connection`].
    pub fn admit_connection(&self, peer: &PeerId) -> bool {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).admit_connection(peer)
    }

    /// Check whether an inbound message should be admitted.
    /// See [`AdmissionControl::admit_message`].
    pub fn admit_message(&self, peer: &PeerId, bytes: usize) -> bool {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).admit_message(peer, bytes)
    }

    /// Record a misbehavior event. See
    /// [`AdmissionControl::record_misbehavior`].
    pub fn record_misbehavior(&self, peer: &PeerId, event: ReputationEvent) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_misbehavior(peer, event)
    }

    /// Release a connection slot. See
    /// [`AdmissionControl::release_connection`].
    pub fn release_connection(&self) {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).release_connection();
    }

    /// The current number of active connections.
    pub fn current_connections(&self) -> usize {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).current_connections()
    }

    /// Check if a peer is banned.
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).is_banned(peer)
    }

    /// Get a peer's reputation score.
    pub fn peer_score(&self, peer: &PeerId) -> i64 {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).peer_score(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        vec![byte]
    }

    #[test]
    fn admit_connection_under_cap() {
        let mut ac = AdmissionControl::with_limits(5, 1000, 100);
        assert!(ac.admit_connection(&peer(1)));
        assert!(ac.admit_connection(&peer(2)));
        assert_eq!(ac.current_connections(), 2);
    }

    #[test]
    fn reject_connection_over_cap() {
        let mut ac = AdmissionControl::with_limits(2, 1000, 100);
        assert!(ac.admit_connection(&peer(1)));
        assert!(ac.admit_connection(&peer(2)));
        assert!(!ac.admit_connection(&peer(3)), "third connection should be rejected");
        assert_eq!(ac.current_connections(), 2);
    }

    #[test]
    fn release_connection_allows_new() {
        let mut ac = AdmissionControl::with_limits(1, 1000, 100);
        assert!(ac.admit_connection(&peer(1)));
        ac.release_connection();
        assert!(ac.admit_connection(&peer(2)), "new connection after release");
    }

    #[test]
    fn banned_peer_rejected() {
        let mut ac = AdmissionControl::new();
        // Ban the peer by recording many negative events.
        for _ in 0..100 {
            ac.record_misbehavior(&peer(1), ReputationEvent::InvalidMessage);
        }
        assert!(ac.is_banned(&peer(1)), "peer should be banned");
        assert!(!ac.admit_connection(&peer(1)), "banned peer should be rejected");
    }

    #[test]
    fn banned_peer_message_dropped() {
        let mut ac = AdmissionControl::new();
        // Ban the peer.
        for _ in 0..100 {
            ac.record_misbehavior(&peer(1), ReputationEvent::InvalidMessage);
        }
        assert!(!ac.admit_message(&peer(1), 100), "message from banned peer should be dropped");
    }

    #[test]
    fn rate_limited_message_dropped() {
        let mut ac = AdmissionControl::with_limits(10, 100, 10);
        ac.admit_connection(&peer(1));
        // First message uses most of the budget.
        assert!(ac.admit_message(&peer(1), 90));
        // Second message exceeds remaining budget — dropped.
        assert!(!ac.admit_message(&peer(1), 90), "rate-limited message should be dropped");
    }

    #[test]
    fn valid_message_increases_reputation() {
        let mut ac = AdmissionControl::new();
        ac.admit_connection(&peer(1));
        ac.admit_message(&peer(1), 100);
        assert!(ac.peer_score(&peer(1)) > 0, "reputation should increase for valid message");
    }

    #[test]
    fn shared_admission_control_thread_safe() {
        let ac = SharedAdmissionControl::new(AdmissionControl::with_limits(10, 1000, 100));
        assert!(ac.admit_connection(&peer(1)));
        assert!(ac.admit_message(&peer(1), 100));
        assert_eq!(ac.current_connections(), 1);
        ac.release_connection();
        assert_eq!(ac.current_connections(), 0);
    }

    #[test]
    fn shared_admission_control_ban_check() {
        let ac = SharedAdmissionControl::new(AdmissionControl::new());
        // Ban the peer.
        for _ in 0..100 {
            ac.record_misbehavior(&peer(1), ReputationEvent::InvalidMessage);
        }
        assert!(ac.is_banned(&peer(1)));
        assert!(!ac.admit_connection(&peer(1)), "banned peer rejected");
    }

    #[test]
    fn connection_cap_zero_rejects_all() {
        let mut ac = AdmissionControl::with_limits(0, 1000, 100);
        assert!(!ac.admit_connection(&peer(1)), "zero cap rejects all");
    }

    #[test]
    fn release_below_zero_clamped() {
        let mut ac = AdmissionControl::new();
        ac.release_connection(); // would underflow without clamping
        assert_eq!(ac.current_connections(), 0);
    }
}
