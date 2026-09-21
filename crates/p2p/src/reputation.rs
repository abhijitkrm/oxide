//! Peer reputation and banning — networking hardening.
//!
//! # What this is
//!
//! A peer reputation system that tracks the behavior of connected
//! peers and bans peers that misbehave. This protects the node from
//! byzantine peers, spam peers, and peers that send invalid messages.
//!
//! # Why this exists
//!
//! The discovery module (§discovery) added dynamic peer addition,
//! but without reputation tracking, a byzantine peer can reconnect
//! indefinitely or flood the node with invalid messages. The
//! reputation system provides:
//! - Per-peer reputation scores.
//! - Automatic banning when reputation drops below a threshold.
//! - Ban expiration (peers can reconnect after a cooldown).
//! - Event tracking for misbehavior categories.
//!
//! # Reputation model
//!
//! Each peer starts with a neutral reputation (0). Good behavior
//! (valid messages, timely responses) increases reputation. Bad
//! behavior (invalid messages, timeouts, disconnections) decreases
//! it. When reputation drops below `BAN_THRESHOLD`, the peer is
//! banned for `BAN_DURATION` seconds.
//!
//! Scoring is intentionally simple: each event adds or subtracts a
//! fixed score. This avoids floating-point and complex decay models
//! on the hot path. The scores are:
//!
//! | Event | Score change |
//! |---|---|
//! | Valid message | +1 |
//! | Invalid message | -10 |
//! | Timeout | -5 |
//! | Disconnect | -3 |
//! | Handshake success | +5 |

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The reputation score at which a peer is banned.
/// Below this threshold, the peer cannot connect.
const BAN_THRESHOLD: i64 = -50;

/// The duration of a ban (in seconds).
const BAN_DURATION_SECS: u64 = 300; // 5 minutes

/// The maximum reputation score (to prevent unbounded growth).
const MAX_REPUTATION: i64 = 100;

/// The minimum reputation score (to prevent underflow).
const MIN_REPUTATION: i64 = -100;

/// A peer's reputation score and ban status.
#[derive(Debug, Clone)]
pub struct PeerReputation {
    /// The current reputation score.
    score: i64,
    /// When the peer was banned (if banned).
    banned_at: Option<Instant>,
    /// The ban duration.
    ban_duration: Duration,
    /// Total events recorded.
    total_events: u64,
}

impl PeerReputation {
    /// Create a new reputation entry with a neutral score.
    #[must_use]
    pub fn new() -> Self {
        Self {
            score: 0,
            banned_at: None,
            ban_duration: Duration::from_secs(BAN_DURATION_SECS),
            total_events: 0,
        }
    }

    /// Returns the current reputation score.
    #[must_use]
    pub fn score(&self) -> i64 {
        self.score
    }

    /// Returns `true` if the peer is currently banned.
    #[must_use]
    pub fn is_banned(&self) -> bool {
        match self.banned_at {
            Some(banned_at) => banned_at.elapsed() < self.ban_duration,
            None => false,
        }
    }

    /// Returns `true` if the ban has expired and the peer can reconnect.
    #[must_use]
    pub fn ban_expired(&self) -> bool {
        match self.banned_at {
            Some(banned_at) => banned_at.elapsed() >= self.ban_duration,
            None => false,
        }
    }

    /// Returns the total number of events recorded.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Apply a score change, clamping to [`MIN_REPUTATION`] and [`MAX_REPUTATION`].
    /// Returns `true` if the peer should be banned after this change.
    fn apply_score(&mut self, delta: i64) -> bool {
        self.score = (self.score + delta).clamp(MIN_REPUTATION, MAX_REPUTATION);
        self.total_events += 1;
        self.score <= BAN_THRESHOLD
    }

    /// Record a positive event (valid message, handshake success).
    pub fn record_positive(&mut self, delta: i64) {
        self.apply_score(delta.max(0));
        // Clear ban if reputation recovers above threshold.
        if self.score > BAN_THRESHOLD && self.ban_expired() {
            self.banned_at = None;
        }
    }

    /// Record a negative event (invalid message, timeout, disconnect).
    /// Returns `true` if the peer should be banned.
    pub fn record_negative(&mut self, delta: i64) -> bool {
        let should_ban = self.apply_score(-delta.max(0));
        if should_ban && self.banned_at.is_none() {
            self.banned_at = Some(Instant::now());
        }
        self.is_banned()
    }

    /// Explicitly ban the peer for the given duration.
    pub fn ban(&mut self, duration: Duration) {
        self.banned_at = Some(Instant::now());
        self.ban_duration = duration;
    }

    /// Lift the ban (manual unban).
    pub fn unban(&mut self) {
        self.banned_at = None;
        self.score = 0; // reset to neutral
    }
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self::new()
    }
}

/// Reputation event types. Used for logging and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationEvent {
    /// A valid message was received.
    ValidMessage,
    /// An invalid message was received.
    InvalidMessage,
    /// A handshake completed successfully.
    HandshakeSuccess,
    /// A timeout occurred.
    Timeout,
    /// The peer disconnected.
    Disconnect,
    /// The peer sent a duplicate message.
    DuplicateMessage,
    /// The peer sent an oversized message.
    OversizedMessage,
}

impl ReputationEvent {
    /// Returns the score change for this event.
    #[must_use]
    pub fn score_delta(&self) -> i64 {
        match self {
            Self::ValidMessage => 1,
            Self::HandshakeSuccess => 5,
            Self::Timeout => -5,
            Self::Disconnect => -3,
            Self::DuplicateMessage => -2,
            Self::InvalidMessage | Self::OversizedMessage => -10,
        }
    }

    /// Returns `true` if this is a positive event.
    #[must_use]
    pub fn is_positive(&self) -> bool {
        self.score_delta() > 0
    }
}

/// A peer reputation store: tracks reputation for all known peers.
///
/// Thread-safe via `Mutex`. The store is designed to be checked on
/// the connection acceptance path and updated on the message
/// processing path.
pub struct PeerReputationStore {
    /// Per-peer reputation, keyed by peer ID.
    reputations: Mutex<HashMap<PeerId, PeerReputation>>,
}

impl PeerReputationStore {
    /// Create an empty reputation store.
    #[must_use]
    pub fn new() -> Self {
        Self { reputations: Mutex::new(HashMap::new()) }
    }

    /// Check if a peer is banned.
    ///
    /// # Panics
    ///
    /// Panics if the reputations mutex is poisoned.
    #[must_use]
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        let reputations = self.reputations.lock().unwrap();
        reputations.get(peer_id).is_some_and(PeerReputation::is_banned)
    }

    /// Check if a peer is allowed to connect (not banned, or ban expired).
    ///
    /// # Panics
    ///
    /// Panics if the reputations mutex is poisoned.
    #[must_use]
    pub fn can_connect(&self, peer_id: &PeerId) -> bool {
        let mut reputations = self.reputations.lock().unwrap();
        let rep = reputations.entry(peer_id.clone()).or_default();
        // If the ban has expired, allow connection.
        if rep.ban_expired() {
            rep.unban();
        }
        !rep.is_banned()
    }

    /// Record an event for a peer.
    ///
    /// Returns `true` if the peer should be banned after this event.
    ///
    /// # Panics
    ///
    /// Panics if the reputations mutex is poisoned.
    pub fn record_event(&self, peer_id: &PeerId, event: ReputationEvent) -> bool {
        let mut reputations = self.reputations.lock().unwrap();
        let rep = reputations.entry(peer_id.clone()).or_default();
        let delta = event.score_delta();
        if event.is_positive() {
            rep.record_positive(delta);
            false
        } else {
            rep.record_negative(delta.abs())
        }
    }

    /// Get a peer's reputation score.
    ///
    /// # Panics
    ///
    /// Panics if the reputations mutex is poisoned.
    #[must_use]
    pub fn score(&self, peer_id: &PeerId) -> i64 {
        let reputations = self.reputations.lock().unwrap();
        reputations.get(peer_id).map_or(0, PeerReputation::score)
    }

    /// Explicitly ban a peer for a given duration.
    ///
    /// # Panics
    ///
    /// Panics if the reputations mutex is poisoned.
    pub fn ban_peer(&self, peer_id: &PeerId, duration: Duration) {
        let mut reputations = self.reputations.lock().unwrap();
        let rep = reputations.entry(peer_id.clone()).or_default();
        rep.ban(duration);
    }

    /// Lift a ban on a peer.
    ///
    /// # Panics
    ///
    /// Panics if the reputations mutex is poisoned.
    pub fn unban_peer(&self, peer_id: &PeerId) {
        let mut reputations = self.reputations.lock().unwrap();
        if let Some(rep) = reputations.get_mut(peer_id) {
            rep.unban();
        }
    }

    /// Returns the number of tracked peers.
    ///
    /// # Panics
    ///
    /// Panics if the reputations mutex is poisoned.
    #[must_use]
    pub fn num_peers(&self) -> usize {
        self.reputations.lock().unwrap().len()
    }

    /// Returns the number of currently banned peers.
    ///
    /// # Panics
    ///
    /// Panics if the reputations mutex is poisoned.
    #[must_use]
    pub fn num_banned(&self) -> usize {
        self.reputations.lock().unwrap().values().filter(|rep| rep.is_banned()).count()
    }
}

impl Default for PeerReputationStore {
    fn default() -> Self {
        Self::new()
    }
}

/// A peer ID (re-exported for convenience).
type PeerId = Vec<u8>;

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_id(byte: u8) -> PeerId {
        vec![byte]
    }

    #[test]
    fn new_reputation_is_neutral() {
        let rep = PeerReputation::new();
        assert_eq!(rep.score(), 0);
        assert!(!rep.is_banned());
        assert_eq!(rep.total_events(), 0);
    }

    #[test]
    fn positive_events_increase_score() {
        let mut rep = PeerReputation::new();
        rep.record_positive(5);
        assert_eq!(rep.score(), 5);
        rep.record_positive(10);
        assert_eq!(rep.score(), 15);
    }

    #[test]
    fn negative_events_decrease_score() {
        let mut rep = PeerReputation::new();
        rep.record_negative(5);
        assert_eq!(rep.score(), -5);
        assert!(!rep.is_banned()); // not below threshold yet
    }

    #[test]
    fn ban_triggers_at_threshold() {
        let mut rep = PeerReputation::new();
        // BAN_THRESHOLD is -50, so 5 invalid messages (-10 each) = -50.
        for _ in 0..5 {
            rep.record_negative(10);
        }
        assert_eq!(rep.score(), -50);
        assert!(rep.is_banned());
    }

    #[test]
    fn score_clamps_to_min() {
        let mut rep = PeerReputation::new();
        rep.record_negative(200);
        assert_eq!(rep.score(), MIN_REPUTATION);
    }

    #[test]
    fn score_clamps_to_max() {
        let mut rep = PeerReputation::new();
        rep.record_positive(200);
        assert_eq!(rep.score(), MAX_REPUTATION);
    }

    #[test]
    fn ban_expires() {
        let mut rep = PeerReputation::new();
        // A live ban reports banned and not yet expired.
        rep.ban(Duration::from_secs(60));
        assert!(rep.is_banned());
        assert!(!rep.ban_expired());
        // A zero-length ban is expired the instant it is set — the
        // boundary is `elapsed >= duration`, so this is deterministic
        // where a sleep-based check races the scheduler.
        rep.ban(Duration::ZERO);
        assert!(rep.ban_expired());
        assert!(!rep.is_banned());
    }

    #[test]
    fn unban_resets_score() {
        let mut rep = PeerReputation::new();
        rep.record_negative(60);
        assert!(rep.is_banned());
        rep.unban();
        assert!(!rep.is_banned());
        assert_eq!(rep.score(), 0);
    }

    #[test]
    fn event_score_deltas() {
        assert_eq!(ReputationEvent::ValidMessage.score_delta(), 1);
        assert_eq!(ReputationEvent::HandshakeSuccess.score_delta(), 5);
        assert_eq!(ReputationEvent::InvalidMessage.score_delta(), -10);
        assert_eq!(ReputationEvent::Timeout.score_delta(), -5);
        assert_eq!(ReputationEvent::Disconnect.score_delta(), -3);
        assert_eq!(ReputationEvent::DuplicateMessage.score_delta(), -2);
        assert_eq!(ReputationEvent::OversizedMessage.score_delta(), -10);
    }

    #[test]
    fn event_is_positive() {
        assert!(ReputationEvent::ValidMessage.is_positive());
        assert!(ReputationEvent::HandshakeSuccess.is_positive());
        assert!(!ReputationEvent::InvalidMessage.is_positive());
        assert!(!ReputationEvent::Timeout.is_positive());
    }

    #[test]
    fn store_new_is_empty() {
        let store = PeerReputationStore::new();
        assert_eq!(store.num_peers(), 0);
        assert_eq!(store.num_banned(), 0);
    }

    #[test]
    fn store_can_connect_unknown_peer() {
        let store = PeerReputationStore::new();
        assert!(store.can_connect(&peer_id(1)));
    }

    #[test]
    fn store_record_positive_event() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        store.record_event(&peer, ReputationEvent::ValidMessage);
        assert_eq!(store.score(&peer), 1);
        assert!(!store.is_banned(&peer));
    }

    #[test]
    fn store_record_negative_event_bans() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        // 5 invalid messages = -50 = ban threshold.
        for _ in 0..5 {
            store.record_event(&peer, ReputationEvent::InvalidMessage);
        }
        assert!(store.is_banned(&peer));
        assert!(!store.can_connect(&peer));
        assert_eq!(store.num_banned(), 1);
    }

    #[test]
    fn store_explicit_ban() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        store.ban_peer(&peer, Duration::from_secs(60));
        assert!(store.is_banned(&peer));
        assert!(!store.can_connect(&peer));
    }

    #[test]
    fn store_unban() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        store.ban_peer(&peer, Duration::from_secs(60));
        assert!(store.is_banned(&peer));
        store.unban_peer(&peer);
        assert!(!store.is_banned(&peer));
        assert!(store.can_connect(&peer));
    }

    #[test]
    fn store_ban_expired_allows_connect() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        store.ban_peer(&peer, Duration::from_millis(1));
        assert!(!store.can_connect(&peer));
        // Wait for ban to expire.
        std::thread::sleep(Duration::from_millis(10));
        // can_connect should clear the expired ban.
        assert!(store.can_connect(&peer));
    }

    #[test]
    fn store_multiple_peers() {
        let store = PeerReputationStore::new();
        store.record_event(&peer_id(1), ReputationEvent::ValidMessage);
        store.record_event(&peer_id(2), ReputationEvent::InvalidMessage);
        store.record_event(&peer_id(3), ReputationEvent::HandshakeSuccess);
        assert_eq!(store.num_peers(), 3);
        assert_eq!(store.score(&peer_id(1)), 1);
        assert_eq!(store.score(&peer_id(2)), -10);
        assert_eq!(store.score(&peer_id(3)), 5);
    }

    #[test]
    fn store_timeout_event() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        store.record_event(&peer, ReputationEvent::Timeout);
        assert_eq!(store.score(&peer), -5);
        assert!(!store.is_banned(&peer));
    }

    #[test]
    fn store_disconnect_event() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        store.record_event(&peer, ReputationEvent::Disconnect);
        assert_eq!(store.score(&peer), -3);
    }

    #[test]
    fn store_oversized_message_event() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        store.record_event(&peer, ReputationEvent::OversizedMessage);
        assert_eq!(store.score(&peer), -10);
    }

    #[test]
    fn store_duplicate_message_event() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        store.record_event(&peer, ReputationEvent::DuplicateMessage);
        assert_eq!(store.score(&peer), -2);
    }

    #[test]
    fn store_mixed_events() {
        let store = PeerReputationStore::new();
        let peer = peer_id(1);
        // Start with handshake success (+5).
        store.record_event(&peer, ReputationEvent::HandshakeSuccess);
        assert_eq!(store.score(&peer), 5);
        // Some valid messages (+1 each).
        for _ in 0..10 {
            store.record_event(&peer, ReputationEvent::ValidMessage);
        }
        assert_eq!(store.score(&peer), 15);
        // An invalid message (-10).
        store.record_event(&peer, ReputationEvent::InvalidMessage);
        assert_eq!(store.score(&peer), 5);
        assert!(!store.is_banned(&peer));
    }
}
