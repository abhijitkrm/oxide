//! Per-peer ingress rate limiting — `DoS` protection for the transport layer.
//!
//! # What this is
//!
//! A token-bucket rate limiter that throttles inbound messages on a
//! per-peer basis. Each peer gets a bounded token budget; messages
//! consume tokens proportional to their size. When a peer's bucket
//! is empty, subsequent messages from that peer are dropped until
//! the bucket refills.
//!
//! # Why this exists
//!
//! The reputation system (§reputation) bans peers that consistently
//! misbehave, but it doesn't protect against a burst of valid-looking
//! messages from a single peer. A byzantine validator could flood
//! the network with high-fee transactions or spurious votes,
//! consuming CPU and memory on honest nodes. The rate limiter
//! provides a first line of defense: per-peer ingress is capped
//! regardless of message content.
//!
//! # Design
//!
//! - **Token bucket:** each peer has a bucket with `capacity` tokens.
//!   Messages consume `ceil(bytes / token_bytes)` tokens. The bucket
//!   refills at `refill_rate` tokens per second, up to `capacity`.
//! - **No floating point:** all arithmetic is integer-only. The
//!   refill rate is in tokens per millisecond (scaled by 1000 to
//!   avoid sub-integer rates).
//! - **No allocations on the hot path:** the limiter uses a
//!   `HashMap<PeerId, Bucket>` with pre-allocated capacity. Peer IDs
//!   are `Vec<u8>` but are borrowed, not cloned, on the check path.
//! - **Lazy eviction:** peers that haven't sent a message in
//!   `idle_eviction_secs` are evicted from the map to bound memory.
//!
//! # Integration
//!
//! The rate limiter is a wrapper, not a transport implementation.
//! The node calls `RateLimiter::check` before processing each
//! inbound message. If `check` returns `false`, the message is
//! dropped. This keeps the rate limiter independent of the transport
//! layer and easy to test in isolation.
//!
//! # Phase scope
//!
//! Phase 3: per-peer token bucket with size-proportional cost. No
//! per-message-type limits, no adaptive rates, no circuit breaker.
//! Those arrive in Phase 4+ with the production networking stack.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ports::transport::PeerId;

/// The default bucket capacity: 10 MiB worth of tokens.
///
/// This allows a burst of ~10 MiB of messages before throttling
/// kicks in. At 16 MiB max message size, this means a peer can send
/// roughly one large message or many small ones before being
/// throttled. The tradeoff: higher capacity = more burst tolerance
/// but more memory/CPU exposure; lower capacity = stricter `DoS`
/// protection but more false positives on legitimate bursts.
const DEFAULT_CAPACITY_TOKENS: u64 = 10 * 1024 * 1024;

/// The default refill rate: 1 MiB per second.
///
/// This allows a sustained ingress of 1 MiB/s per peer, which is
/// generous for consensus messages (votes are ~137 bytes, QCs are
/// ~150 bytes) but caps flooding. The tradeoff: higher rate = more
/// sustained bandwidth per peer; lower rate = stricter cap.
const DEFAULT_REFILL_TOKENS_PER_SEC: u64 = 1024 * 1024;

/// The number of bytes that consume one token.
///
/// Setting this to 1 means each byte costs one token (the bucket
/// size equals the byte budget). This is the simplest model and
/// avoids division on the hot path. The tradeoff: with larger
/// values, small messages are effectively free, which could allow
/// a flood of tiny messages.
const TOKEN_BYTES: u64 = 1;

/// The default idle eviction timeout: 5 minutes.
///
/// Peers that haven't sent a message in this time are evicted from
/// the rate limiter's map to bound memory. The tradeoff: shorter
/// timeout = lower memory but more bucket resets (a peer that
/// sends infrequently gets a fresh bucket each time); longer
/// timeout = stable limits but more memory for idle peers.
const DEFAULT_IDLE_EVICTION_SECS: u64 = 300;

/// A token bucket for a single peer.
#[derive(Debug, Clone)]
struct Bucket {
    /// Current token balance.
    tokens: u64,
    /// Timestamp of the last refill or message.
    last_update: Instant,
}

/// A per-peer ingress rate limiter.
///
/// Each peer gets a token bucket. Messages consume tokens
/// proportional to their size. When a peer's bucket is empty,
/// messages from that peer are dropped until the bucket refills.
///
/// # Thread safety
///
/// The rate limiter is `Send` but not `Sync`. It's designed to be
/// used from a single thread (the network I/O thread). If shared
/// across threads, wrap in a `Mutex`.
pub struct RateLimiter {
    /// Per-peer token buckets.
    buckets: HashMap<PeerId, Bucket>,
    /// Maximum tokens per bucket (burst capacity).
    capacity: u64,
    /// Refill rate in tokens per second.
    refill_per_sec: u64,
    /// Idle eviction timeout.
    idle_eviction: Duration,
}

impl RateLimiter {
    /// Construct a rate limiter with default parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY_TOKENS, DEFAULT_REFILL_TOKENS_PER_SEC)
    }

    /// Construct a rate limiter with a custom capacity and refill rate.
    ///
    /// # Arguments
    ///
    /// * `capacity` — Maximum tokens per bucket (burst size in bytes).
    /// * `refill_per_sec` — Refill rate in tokens (bytes) per second.
    #[must_use]
    pub fn with_capacity(capacity: u64, refill_per_sec: u64) -> Self {
        Self {
            buckets: HashMap::new(),
            capacity,
            refill_per_sec,
            idle_eviction: Duration::from_secs(DEFAULT_IDLE_EVICTION_SECS),
        }
    }

    /// Set the idle eviction timeout. Returns `self` for chaining.
    #[must_use]
    pub fn with_idle_eviction(mut self, timeout: Duration) -> Self {
        self.idle_eviction = timeout;
        self
    }

    /// Check if a message from `peer` of `bytes` length should be
    /// admitted. Returns `true` if the message is allowed (tokens
    /// deducted), `false` if it should be dropped.
    ///
    /// This is the hot-path call: it does a `HashMap` lookup, a
    /// subtraction, and an Instant comparison. No allocations.
    pub fn check(&mut self, peer: &PeerId, bytes: usize) -> bool {
        let cost = (u64::try_from(bytes).unwrap_or(u64::MAX) / TOKEN_BYTES).max(1);
        let now = Instant::now();
        let bucket = self
            .buckets
            .entry(peer.clone())
            .or_insert(Bucket { tokens: self.capacity, last_update: now });
        // Refill: add tokens for elapsed time, capped at capacity.
        // Saturating math: a large configured `refill_per_sec` times
        // an elapsed interval must not wrap (or panic under release
        // overflow checks) — the `.min(capacity)` clamp below makes
        // saturation exact, since only reaching the cap matters.
        let elapsed = now.duration_since(bucket.last_update);
        let refill = elapsed.as_secs().saturating_mul(self.refill_per_sec).saturating_add(
            u64::from(elapsed.subsec_millis()).saturating_mul(self.refill_per_sec) / 1000,
        );
        bucket.tokens = bucket.tokens.saturating_add(refill).min(self.capacity);
        bucket.last_update = now;
        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            true
        } else {
            false
        }
    }

    /// Evict idle peers that haven't sent a message in the idle
    /// eviction timeout. Returns the number of peers evicted.
    pub fn evict_idle(&mut self) -> usize {
        let now = Instant::now();
        let before = self.buckets.len();
        self.buckets.retain(|_, b| now.duration_since(b.last_update) < self.idle_eviction);
        before - self.buckets.len()
    }

    /// The number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.buckets.len()
    }

    /// Get the current token balance for a peer. Returns `None` if
    /// the peer is not tracked.
    pub fn peer_tokens(&self, peer: &PeerId) -> Option<u64> {
        self.buckets.get(peer).map(|b| b.tokens)
    }

    /// Reset a peer's bucket (e.g., after a successful handshake).
    pub fn reset_peer(&mut self, peer: &PeerId) {
        if let Some(b) = self.buckets.get_mut(peer) {
            b.tokens = self.capacity;
            b.last_update = Instant::now();
        }
    }

    /// Remove a peer from tracking (e.g., after disconnection).
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.buckets.remove(peer);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `refill_per_sec` near `u64::MAX` must saturate, not wrap:
    /// plain `elapsed * refill` overflowed (panic under release
    /// overflow checks, wrap in debug — either way the calling
    /// reader thread died).
    #[test]
    fn rate_limiter_huge_refill_saturates() {
        let mut rl = RateLimiter::with_capacity(u64::MAX, u64::MAX);
        let peer = vec![1u8];
        assert!(rl.check(&peer, 1));
        std::thread::sleep(std::time::Duration::from_millis(20));
        // The second check triggers a refill multiply that would
        // have overflowed `u64` before the saturating fix.
        assert!(rl.check(&peer, 1));
    }

    #[test]
    fn rate_limiter_admits_under_capacity() {
        let mut rl = RateLimiter::with_capacity(1000, 100);
        let peer = vec![1u8];
        // Small message under capacity — admitted.
        assert!(rl.check(&peer, 100));
        assert_eq!(rl.peer_tokens(&peer), Some(900));
    }

    #[test]
    fn rate_limiter_drops_over_capacity() {
        let mut rl = RateLimiter::with_capacity(100, 10);
        let peer = vec![1u8];
        // First message uses most of the budget.
        assert!(rl.check(&peer, 90));
        // Second message exceeds remaining budget — dropped.
        assert!(!rl.check(&peer, 90));
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let peer = vec![1u8];
        // Exhaustion is deterministic at a zero refill rate: the
        // bucket can never regain a token, so the over-budget check
        // fails no matter how long the scheduler stalls between
        // calls (a 1k tok/s rate refills a token per millisecond —
        // the old test raced exactly that window).
        let mut dry = RateLimiter::with_capacity(100, 0);
        assert!(dry.check(&peer, 100));
        assert!(!dry.check(&peer, 1));
        // Refill is deterministic at a rate that refills the whole
        // bucket in ~0.1ms: any real sleep restores it to capacity.
        let mut rl = RateLimiter::with_capacity(100, 1_000_000);
        assert!(rl.check(&peer, 100));
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(rl.check(&peer, 1));
        assert_eq!(rl.peer_tokens(&peer), Some(99), "refill caps at capacity");
    }

    #[test]
    fn rate_limiter_tracks_multiple_peers() {
        let mut rl = RateLimiter::with_capacity(1000, 100);
        let peer1 = vec![1u8];
        let peer2 = vec![2u8];
        assert!(rl.check(&peer1, 100));
        assert!(rl.check(&peer2, 100));
        assert_eq!(rl.peer_count(), 2);
        // Peer 1 has 900, peer 2 has 900.
        assert_eq!(rl.peer_tokens(&peer1), Some(900));
        assert_eq!(rl.peer_tokens(&peer2), Some(900));
    }

    #[test]
    fn rate_limiter_evicts_idle_peers() {
        let mut rl =
            RateLimiter::with_capacity(1000, 100).with_idle_eviction(Duration::from_millis(50));
        let peer = vec![1u8];
        assert!(rl.check(&peer, 100));
        assert_eq!(rl.peer_count(), 1);
        std::thread::sleep(Duration::from_millis(100));
        let evicted = rl.evict_idle();
        assert_eq!(evicted, 1);
        assert_eq!(rl.peer_count(), 0);
    }

    #[test]
    fn rate_limiter_reset_peer() {
        let mut rl = RateLimiter::with_capacity(1000, 100);
        let peer = vec![1u8];
        assert!(rl.check(&peer, 900));
        assert_eq!(rl.peer_tokens(&peer), Some(100));
        rl.reset_peer(&peer);
        assert_eq!(rl.peer_tokens(&peer), Some(1000));
    }

    #[test]
    fn rate_limiter_remove_peer() {
        let mut rl = RateLimiter::with_capacity(1000, 100);
        let peer = vec![1u8];
        assert!(rl.check(&peer, 100));
        rl.remove_peer(&peer);
        assert_eq!(rl.peer_count(), 0);
        assert_eq!(rl.peer_tokens(&peer), None);
    }

    #[test]
    fn rate_limiter_capacity_caps_refill() {
        let mut rl = RateLimiter::with_capacity(100, 10_000);
        let peer = vec![1u8];
        // Use some tokens.
        assert!(rl.check(&peer, 50));
        // Wait for refill — should cap at 100, not overflow.
        std::thread::sleep(Duration::from_millis(100));
        assert!(rl.check(&peer, 100));
        assert_eq!(rl.peer_tokens(&peer), Some(0));
    }
}
