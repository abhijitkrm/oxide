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
//! bucket rate limiting, and a per-source-IP cap enforced at the
//! listener (`SourceCaps` below — the only identity available before
//! a peer's authenticated greeting is the socket's source address).
//! No adaptive limits or circuit breaker; those arrive in Phase 4+
//! with the production networking stack.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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
        primitives::sync::lock_state(&self.0).admit_connection(peer)
    }

    /// Check whether an inbound message should be admitted.
    /// See [`AdmissionControl::admit_message`].
    pub fn admit_message(&self, peer: &PeerId, bytes: usize) -> bool {
        primitives::sync::lock_state(&self.0).admit_message(peer, bytes)
    }

    /// Record a misbehavior event. See
    /// [`AdmissionControl::record_misbehavior`].
    pub fn record_misbehavior(&self, peer: &PeerId, event: ReputationEvent) -> bool {
        primitives::sync::lock_state(&self.0).record_misbehavior(peer, event)
    }

    /// Release a connection slot. See
    /// [`AdmissionControl::release_connection`].
    pub fn release_connection(&self) {
        primitives::sync::lock_state(&self.0).release_connection();
    }

    /// The current number of active connections.
    pub fn current_connections(&self) -> usize {
        primitives::sync::lock_state(&self.0).current_connections()
    }

    /// Check if a peer is banned.
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        primitives::sync::lock_state(&self.0).is_banned(peer)
    }

    /// Get a peer's reputation score.
    pub fn peer_score(&self, peer: &PeerId) -> i64 {
        primitives::sync::lock_state(&self.0).peer_score(peer)
    }
}

/// A per-source-IP bucket key for inbound connection accounting.
///
/// IPv4 addresses key verbatim. IPv6 collapses to the /64 prefix —
/// the de-facto host allocation — so an attacker cannot rotate
/// through the 2^64 interface identifiers of one subnet to reset
/// the cap.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SourceKey {
    /// An IPv4 address, stored as its big-endian `u32`.
    V4(u32),
    /// The high 64 bits of an IPv6 address (the /64 subnet prefix).
    V6(u64),
}

impl SourceKey {
    /// Derive the bucket key for a peer's source address.
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => Self::V4(u32::from(a)),
            IpAddr::V6(a) => {
                let s = a.segments();
                Self::V6(
                    (u64::from(s[0]) << 48)
                        | (u64::from(s[1]) << 32)
                        | (u64::from(s[2]) << 16)
                        | u64::from(s[3]),
                )
            }
        }
    }
}

/// Per-source-IP connection counts, shared between the listener's
/// accept loop and every connection's teardown path.
///
/// # Why this exists
///
/// [`AdmissionControl`] caps *total* connections, but its check runs
/// after the greeting — a flood from ONE address can still saturate
/// the global cap before the flood's peer IDs are even known, and
/// can pin every handshake worker with stalled sockets. `SourceCaps`
/// is the listener-level bound: each source bucket holds at most
/// `max_per_source` live connections regardless of the identity the
/// greeting later claims. It does not replace the peer-ID admission
/// check — it bounds what is knowable before one exists.
///
/// # Invariants
///
/// - Every counted connection holds a [`SourceLease`]; acquire and
///   release run under the same mutex, so a lease is a counted
///   reference — never a stale hint a replacement connection could
///   trip over.
/// - Entries are removed when a count reaches zero, so the map is
///   bounded by the number of live connections, which is bounded by
///   [`AdmissionControl`]'s global cap — the tracker cannot grow
///   into its own `DoS` vector under a multi-source flood.
struct SourceCaps {
    /// Live connection count per source bucket.
    counts: HashMap<SourceKey, usize>,
    /// Maximum live connections from one source bucket. See
    /// [`SharedSourceCaps::new`] for the default's rationale.
    max_per_source: usize,
}

/// Thread-safe handle to [`SourceCaps`]. Cheap to clone — every
/// clone shares one mutex-guarded counter table.
///
/// The lock is held only for a hash lookup and counter update —
/// never across socket I/O — so the accept loop cannot be stalled
/// by a slow connection.
#[derive(Clone)]
pub struct SharedSourceCaps(Arc<Mutex<SourceCaps>>);

impl SharedSourceCaps {
    /// Construct a shared per-source-IP cap allowing at most
    /// `max_per_source` live connections from any one source bucket.
    #[must_use]
    pub fn new(max_per_source: usize) -> Self {
        Self(Arc::new(Mutex::new(SourceCaps { counts: HashMap::new(), max_per_source })))
    }

    /// Try to take a lease for `addr`'s bucket: returns `Some` with
    /// the count incremented, or `None` when the bucket is already
    /// at cap. A `None` result takes no state — dropping the socket
    /// is the complete rejection.
    pub fn try_acquire(&self, addr: IpAddr) -> Option<SourceLease> {
        let key = SourceKey::of(addr);
        let mut caps = primitives::sync::lock_state(&self.0);
        let max = caps.max_per_source;
        let count = caps.counts.entry(key).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(SourceLease { caps: Arc::clone(&self.0), key })
    }

    /// The number of live leases held by `addr`'s bucket.
    #[cfg(test)]
    pub fn inflight(&self, addr: IpAddr) -> usize {
        let caps = primitives::sync::lock_state(&self.0);
        caps.counts.get(&SourceKey::of(addr)).copied().unwrap_or(0)
    }

    /// The number of source buckets currently tracked — always ≤
    /// the number of live leases because empty buckets are removed.
    #[cfg(test)]
    pub fn tracked_sources(&self) -> usize {
        primitives::sync::lock_state(&self.0).counts.len()
    }
}

/// RAII permit for one live connection from a source bucket.
///
/// The lease moves with the connection it admitted: held by the
/// pending-accept record through the handshake, then by the reader
/// thread for the connection's lifetime. Dropping it — on handshake
/// rejection, spawn failure, or reader exit — decrements the bucket
/// exactly once. Because the release runs under the same mutex as
/// acquisition, a stale teardown can never release a slot that a
/// replacement connection now owns: each lease is its own count.
pub struct SourceLease {
    /// Shared counter table this lease is counted in.
    caps: Arc<Mutex<SourceCaps>>,
    /// The bucket this lease was counted under.
    key: SourceKey,
}

impl Drop for SourceLease {
    fn drop(&mut self) {
        let mut caps = primitives::sync::lock_state(&self.caps);
        if let Some(count) = caps.counts.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                caps.counts.remove(&self.key);
            }
        }
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

    /// The per-source cap binds exactly at `max_per_source`: the
    /// next lease from the same address is refused, and a dropped
    /// lease frees a slot for the very next attempt.
    #[test]
    fn source_cap_binds_and_releases() {
        use std::net::Ipv4Addr;

        let caps = SharedSourceCaps::new(2);
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        let l1 = caps.try_acquire(addr).expect("first lease");
        let l2 = caps.try_acquire(addr).expect("second lease");
        assert!(caps.try_acquire(addr).is_none(), "third lease exceeds the cap");
        assert_eq!(caps.inflight(addr), 2);

        drop(l1);
        assert_eq!(caps.inflight(addr), 1);
        let l3 = caps.try_acquire(addr).expect("slot freed by drop");
        drop((l2, l3));
        assert_eq!(caps.inflight(addr), 0);
        assert_eq!(caps.tracked_sources(), 0, "empty buckets are removed — no map growth");
    }

    /// Different source buckets have independent budgets: one
    /// source at cap never blocks a lease from another address.
    #[test]
    fn source_caps_are_per_bucket() {
        use std::net::Ipv4Addr;

        let caps = SharedSourceCaps::new(1);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

        let _la = caps.try_acquire(a).expect("a's lease");
        assert!(caps.try_acquire(a).is_none(), "a at cap");
        assert!(caps.try_acquire(b).is_some(), "b is unaffected by a's exhaustion");
    }

    /// IPv6 leases bucket on the /64 prefix: two addresses that
    /// differ only in the interface identifier share one budget —
    /// rotating the low 64 bits cannot reset the cap.
    #[test]
    fn source_cap_ipv6_buckets_by_subnet() {
        use std::net::Ipv6Addr;

        let caps = SharedSourceCaps::new(1);
        let a = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().expect("v6"));
        let same_subnet = IpAddr::V6("2001:db8::ffff".parse::<Ipv6Addr>().expect("v6"));
        let other_subnet = IpAddr::V6("2001:db8:0:1::1".parse::<Ipv6Addr>().expect("v6"));

        let _la = caps.try_acquire(a).expect("a's lease");
        assert!(caps.try_acquire(same_subnet).is_none(), "same /64 shares the bucket");
        assert!(caps.try_acquire(other_subnet).is_some(), "a different /64 has its own budget");
    }
}
