//! WebSocket market data publisher — L1, L2, L3, and trade feeds.
//!
//! Provides real-time market data over WebSocket. Clients subscribe
//! to one or more feeds:
//!
//! - **L1**: top-of-book (best bid/ask price + qty). Published on
//!   every best-bid/best-ask change.
//! - **L2**: full order book depth (price levels). Published on
//!   every book change.
//! - **L3**: full order book (individual orders). Published on
//!   every order add/cancel/fill.
//! - **Trades**: executed trades. Published on every fill.
//!
//! # Design
//!
//! The publisher is a separate module from the order-entry WebSocket
//! server (`ws.rs`). Order entry and market data have different
//! scaling characteristics: order entry is low-volume, high-integrity
//! (authenticated, risk-checked); market data is high-volume,
//! read-only (no auth, no risk checks).
//!
//! The publisher maintains a list of subscriber handles (WebSocket
//! senders). When the matching engine produces a fill or a resting
//! order, the matching server calls `publish_l1`, `publish_trades`,
//! etc. Each publish call broadcasts the update to all subscribers
//! on the relevant feed.
//!
//! # Serialization
//!
//! Messages are serialized as JSON (via `serde_json`). This is the
//! universal wire format for WebSocket market data — every exchange
//! (Binance, Coinbase, Hyperliquid) uses JSON for WS market data.
//! In a future optimization, a binary format (e.g., `MessagePack` or
//! a custom flatbuffer) can be added for high-throughput L2/L3
//! feeds.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use primitives::fixed::{Price, Qty};
use serde::Serialize;
use tokio::sync::mpsc;

/// Market data feed type — clients subscribe to one or more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeedType {
    /// Top-of-book (best bid/ask).
    L1,
    /// Full order book depth (price levels).
    L2,
    /// Full order book (individual orders).
    L3,
    /// Executed trades.
    Trades,
}

impl FeedType {
    /// Convert to the string used in JSON subscription messages.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::L1 => "l1",
            Self::L2 => "l2",
            Self::L3 => "l3",
            Self::Trades => "trades",
        }
    }
}

/// An L1 update: top-of-book snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct L1Update {
    /// Feed type identifier ("l1").
    pub feed: &'static str,
    /// Market ID.
    pub market: u8,
    /// Best bid price (scale-8), or null if no bids.
    pub best_bid_price: Option<u64>,
    /// Best bid quantity (scale-6).
    pub best_bid_qty: Option<u64>,
    /// Best ask price (scale-8), or null if no asks.
    pub best_ask_price: Option<u64>,
    /// Best ask quantity (scale-6).
    pub best_ask_qty: Option<u64>,
    /// Monotonic sequence number for this market's L1 feed.
    pub seq: u64,
}

/// An L2 update: full depth snapshot (top N levels).
#[derive(Debug, Clone, Serialize)]
pub struct L2Update {
    /// Feed type identifier ("l2").
    pub feed: &'static str,
    /// Market ID.
    pub market: u8,
    /// Bid levels: (price, `total_qty`), sorted best-first.
    pub bids: Vec<(u64, u64)>,
    /// Ask levels: (price, `total_qty`), sorted best-first.
    pub asks: Vec<(u64, u64)>,
    /// Monotonic sequence number.
    pub seq: u64,
}

/// A trade (execution) message.
#[derive(Debug, Clone, Serialize)]
pub struct TradeMessage {
    /// Feed type identifier ("trades").
    pub feed: &'static str,
    /// Market ID.
    pub market: u8,
    /// Execution price (scale-8).
    pub price: u64,
    /// Executed quantity (scale-6).
    pub qty: u64,
    /// Taker side: "buy" or "sell".
    pub taker_side: &'static str,
    /// Monotonic sequence number.
    pub seq: u64,
}

/// A market data message — one of the feed types.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum MarketDataMessage {
    /// An L1 (top-of-book) update.
    L1(L1Update),
    /// An L2 (full depth) update.
    L2(L2Update),
    /// A trade (execution) message.
    Trade(TradeMessage),
}

/// Per-subscriber outbound queue depth, in messages.
///
/// Market-data messages are a few hundred bytes of JSON, so 256
/// queued messages bound a subscriber at ~128 KiB — and a client
/// that is 256 updates behind is already too stale to be useful.
/// The matching engine must never back-pressure on a slow socket,
/// so the queue is the only place a slow consumer can accumulate
/// cost; over this depth the subscriber is evicted (its send side
/// dropped), which closes the WebSocket task's `recv()` and ends
/// the connection — the standard exchange slow-consumer policy.
/// Raising it tolerates more client lag at more memory per lagging
/// subscriber; lowering it disconnects mildly slow clients.
const SUB_QUEUE_DEPTH: usize = 256;

/// A subscriber's subscription: which feeds and markets they want.
#[derive(Debug, Clone)]
struct Subscription {
    /// The feeds this subscriber wants (L1, L2, L3, Trades).
    feeds: Vec<FeedType>,
    /// The markets this subscriber wants (empty = all).
    markets: Vec<u8>,
    /// The bounded channel to send messages on — capacity
    /// [`SUB_QUEUE_DEPTH`].
    tx: mpsc::Sender<String>,
}

/// The market data publisher — owns subscriber list and per-market
/// sequence numbers.
///
/// Thread-safe via `std::sync::Mutex`. The publish path is called
/// from the matching server thread after each order; the subscribe
/// path is called from the WebSocket accept loop. Contention is low
/// (subscribers rarely change; publishes are frequent but hold the
/// lock only for the broadcast iteration).
pub struct MarketDataPublisher {
    /// Subscriber list (protected by a mutex).
    subscribers: std::sync::Mutex<Vec<Subscription>>,
    /// Per-market L1 sequence counter.
    l1_seq: Arc<AtomicU64>,
    /// Per-market L2 sequence counter.
    l2_seq: Arc<AtomicU64>,
    /// Per-market trades sequence counter.
    trades_seq: Arc<AtomicU64>,
    /// Subscribers evicted for a full queue or a closed receiver —
    /// the slow-consumer signal an operator watches to detect
    /// clients that cannot keep up with the feed rate.
    evicted_subscribers: Arc<AtomicU64>,
}

impl MarketDataPublisher {
    /// Create a new publisher with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscribers: std::sync::Mutex::new(Vec::new()),
            l1_seq: Arc::new(AtomicU64::new(0)),
            l2_seq: Arc::new(AtomicU64::new(0)),
            trades_seq: Arc::new(AtomicU64::new(0)),
            evicted_subscribers: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Subscribe a new client. Returns a bounded [`mpsc::Receiver`]
    /// (capacity [`SUB_QUEUE_DEPTH`]) that the caller polls for
    /// messages to send over the WebSocket. When the queue stays
    /// full the publisher evicts the subscription — the receiver's
    /// `recv()` then returns `None` and the connection task ends.
    ///
    /// The `feeds` parameter specifies which feeds the client wants.
    /// The `markets` parameter specifies which markets (empty = all).
    #[must_use]
    pub fn subscribe(&self, feeds: Vec<FeedType>, markets: Vec<u8>) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(SUB_QUEUE_DEPTH);
        let sub = Subscription { feeds, markets, tx };
        self.subscribers.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(sub);
        rx
    }

    /// Publish an L1 update (top-of-book) to all L1 subscribers.
    pub fn publish_l1(
        &self,
        market: u8,
        best_bid: Option<(Price, Qty)>,
        best_ask: Option<(Price, Qty)>,
    ) {
        let seq = self.l1_seq.fetch_add(1, Ordering::Relaxed);
        let msg = L1Update {
            feed: "l1",
            market,
            best_bid_price: best_bid.map(|(p, _)| p.0),
            best_bid_qty: best_bid.map(|(_, q)| q.0),
            best_ask_price: best_ask.map(|(p, _)| p.0),
            best_ask_qty: best_ask.map(|(_, q)| q.0),
            seq,
        };
        self.broadcast(market, FeedType::L1, &msg);
    }

    /// Publish an L2 update (full depth) to all L2 subscribers.
    pub fn publish_l2(&self, market: u8, bids: Vec<(u64, u64)>, asks: Vec<(u64, u64)>) {
        let seq = self.l2_seq.fetch_add(1, Ordering::Relaxed);
        let msg = L2Update { feed: "l2", market, bids, asks, seq };
        self.broadcast(market, FeedType::L2, &msg);
    }

    /// Publish a trade (execution) to all Trades subscribers.
    pub fn publish_trade(&self, market: u8, price: Price, qty: Qty, taker_side_buy: bool) {
        let seq = self.trades_seq.fetch_add(1, Ordering::Relaxed);
        let msg = TradeMessage {
            feed: "trades",
            market,
            price: price.0,
            qty: qty.0,
            taker_side: if taker_side_buy { "buy" } else { "sell" },
            seq,
        };
        self.broadcast(market, FeedType::Trades, &msg);
    }

    /// Broadcast a message to all subscribers matching the feed and
    /// market. Serializes once, sends the same string to all.
    fn broadcast<T: Serialize>(&self, market: u8, feed: FeedType, msg: &T) {
        let json = serde_json::to_string(msg).unwrap_or_default();
        let mut subs = self.subscribers.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut evict = 0usize;
        // `retain` walks the list once; `true` keeps the slot. The
        // eviction count doubles as an index-shift-free way to count
        // removals for the observability counter below.
        subs.retain(|sub| {
            // Check if this subscriber wants this feed.
            if !sub.feeds.contains(&feed) {
                return true;
            }
            // Check if this subscriber wants this market (empty = all).
            if !sub.markets.is_empty() && !sub.markets.contains(&market) {
                return true;
            }
            // `try_send` never blocks the matching engine on a slow
            // socket. A full queue means the client has fallen
            // [`SUB_QUEUE_DEPTH`] updates behind — stale beyond
            // usefulness — and a closed receiver means the WS task
            // is gone; either way the subscription is dead weight.
            // Evicting it (dropping the send side) ends the client
            // task and frees the slot: the explicit slow-consumer
            // policy is disconnect, not silent accumulation.
            if sub.tx.try_send(json.clone()).is_ok() {
                true
            } else {
                evict += 1;
                false
            }
        });
        if evict > 0 {
            self.evicted_subscribers.fetch_add(evict as u64, Ordering::Relaxed);
        }
    }

    /// Total subscribers evicted for full queues or closed
    /// receivers since startup — the operator-facing slow-consumer
    /// signal.
    #[must_use]
    pub fn evicted_subscriber_count(&self) -> u64 {
        self.evicted_subscribers.load(Ordering::Relaxed)
    }

    /// Get the current subscriber count (for monitoring).
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }
}

impl Default for MarketDataPublisher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l1_update_serializes_correctly() {
        let msg = L1Update {
            feed: "l1",
            market: 0,
            best_bid_price: Some(1_500_000_000),
            best_bid_qty: Some(1_000),
            best_ask_price: Some(1_500_010_000),
            best_ask_qty: Some(2_000),
            seq: 42,
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        assert!(json.contains("\"feed\":\"l1\""));
        assert!(json.contains("\"market\":0"));
        assert!(json.contains("\"best_bid_price\":1500000000"));
        assert!(json.contains("\"seq\":42"));
    }

    #[test]
    fn l1_update_with_empty_book() {
        let msg = L1Update {
            feed: "l1",
            market: 1,
            best_bid_price: None,
            best_bid_qty: None,
            best_ask_price: None,
            best_ask_qty: None,
            seq: 0,
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        assert!(json.contains("\"best_bid_price\":null"));
        assert!(json.contains("\"best_ask_price\":null"));
    }

    #[test]
    fn l2_update_serializes_correctly() {
        let msg = L2Update {
            feed: "l2",
            market: 0,
            bids: vec![(1_500_000_000, 5_000), (1_499_000_000, 3_000)],
            asks: vec![(1_501_000_000, 2_000)],
            seq: 1,
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        assert!(json.contains("\"bids\":[[1500000000,5000]"));
        assert!(json.contains("\"asks\":[[1501000000,2000]]"));
    }

    #[test]
    fn trade_message_serializes_correctly() {
        let msg = TradeMessage {
            feed: "trades",
            market: 0,
            price: 1_500_000_000,
            qty: 1_000,
            taker_side: "buy",
            seq: 1,
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        assert!(json.contains("\"feed\":\"trades\""));
        assert!(json.contains("\"taker_side\":\"buy\""));
        assert!(json.contains("\"price\":1500000000"));
    }

    #[tokio::test]
    async fn publish_l1_reaches_subscriber() {
        let publisher = MarketDataPublisher::new();
        let mut rx = publisher.subscribe(vec![FeedType::L1], vec![]);
        publisher.publish_l1(0, Some((Price(1_500_000_000), Qty(1_000))), None);
        let msg = rx.recv().await.expect("should receive message");
        assert!(msg.contains("\"feed\":\"l1\""));
        assert!(msg.contains("\"best_bid_price\":1500000000"));
        assert!(msg.contains("\"best_ask_price\":null"));
    }

    #[tokio::test]
    async fn publish_trade_reaches_subscriber() {
        let publisher = MarketDataPublisher::new();
        let mut rx = publisher.subscribe(vec![FeedType::Trades], vec![]);
        publisher.publish_trade(0, Price(1_500_000_000), Qty(1_000), true);
        let msg = rx.recv().await.expect("should receive trade");
        assert!(msg.contains("\"feed\":\"trades\""));
        assert!(msg.contains("\"taker_side\":\"buy\""));
    }

    #[tokio::test]
    async fn subscriber_filters_by_market() {
        let publisher = MarketDataPublisher::new();
        // Subscribe to market 1 only.
        let mut rx = publisher.subscribe(vec![FeedType::L1], vec![1]);
        // Publish on market 0 — should NOT reach this subscriber.
        publisher.publish_l1(0, Some((Price(1_500_000_000), Qty(1_000))), None);
        // Publish on market 1 — SHOULD reach this subscriber.
        publisher.publish_l1(1, Some((Price(1_600_000_000), Qty(2_000))), None);
        let msg = rx.recv().await.expect("should receive market 1 message");
        assert!(msg.contains("\"market\":1"));
        assert!(msg.contains("\"best_bid_price\":1600000000"));
    }

    #[tokio::test]
    async fn subscriber_filters_by_feed() {
        let publisher = MarketDataPublisher::new();
        // Subscribe to Trades only.
        let mut rx = publisher.subscribe(vec![FeedType::Trades], vec![]);
        // Publish L1 — should NOT reach this subscriber.
        publisher.publish_l1(0, Some((Price(1_500_000_000), Qty(1_000))), None);
        // Publish a trade — SHOULD reach this subscriber.
        publisher.publish_trade(0, Price(1_500_000_000), Qty(1_000), true);
        let msg = rx.recv().await.expect("should receive trade");
        assert!(msg.contains("\"feed\":\"trades\""));
    }

    #[tokio::test]
    async fn multiple_subscribers_all_receive() {
        let publisher = MarketDataPublisher::new();
        let mut rx1 = publisher.subscribe(vec![FeedType::L1], vec![]);
        let mut rx2 = publisher.subscribe(vec![FeedType::L1], vec![]);
        publisher.publish_l1(0, Some((Price(1_500_000_000), Qty(1_000))), None);
        let msg1 = rx1.recv().await.expect("subscriber 1 should receive");
        let msg2 = rx2.recv().await.expect("subscriber 2 should receive");
        assert_eq!(msg1, msg2, "both subscribers receive the same message");
    }

    #[test]
    fn subscriber_count_tracks_subscriptions() {
        let publisher = MarketDataPublisher::new();
        assert_eq!(publisher.subscriber_count(), 0);
        let _rx1 = publisher.subscribe(vec![FeedType::L1], vec![]);
        assert_eq!(publisher.subscriber_count(), 1);
        let _rx2 = publisher.subscribe(vec![FeedType::Trades], vec![]);
        assert_eq!(publisher.subscriber_count(), 2);
    }

    #[test]
    fn feed_type_as_str() {
        assert_eq!(FeedType::L1.as_str(), "l1");
        assert_eq!(FeedType::L2.as_str(), "l2");
        assert_eq!(FeedType::L3.as_str(), "l3");
        assert_eq!(FeedType::Trades.as_str(), "trades");
    }

    /// A subscriber that stops reading fills its bounded queue and
    /// is evicted: the publisher must never back-pressure the
    /// matching engine on a slow socket, so the documented
    /// slow-consumer policy is disconnect. The queue is the only
    /// place a slow consumer can accumulate memory — the unbounded
    /// channel this replaced let it grow without limit.
    #[test]
    fn slow_consumer_is_evicted_at_queue_depth() {
        let publisher = MarketDataPublisher::new();
        let mut rx = publisher.subscribe(vec![FeedType::L1], vec![]);
        // Fill exactly to capacity: every send must succeed — a full
        // queue alone is not yet an eviction.
        for _ in 0..SUB_QUEUE_DEPTH {
            publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
        }
        assert_eq!(publisher.subscriber_count(), 1);
        assert_eq!(publisher.evicted_subscriber_count(), 0);
        // One more update than the queue holds → evict.
        publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
        assert_eq!(publisher.subscriber_count(), 0);
        assert_eq!(publisher.evicted_subscriber_count(), 1);
        // Buffered messages stay receivable; once drained the
        // channel reports disconnection so the client task exits.
        for _ in 0..SUB_QUEUE_DEPTH {
            assert!(rx.try_recv().is_ok(), "queued messages survive eviction");
        }
        assert!(
            matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Disconnected)),
            "channel must report disconnection once the buffer drains"
        );
    }

    /// A subscriber whose receiver is gone is dead weight — the
    /// first publish that finds the closed channel evicts it, and
    /// the eviction counter records it for the operator.
    #[test]
    fn closed_receiver_is_evicted() {
        let publisher = MarketDataPublisher::new();
        let rx = publisher.subscribe(vec![FeedType::L1], vec![]);
        drop(rx);
        publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
        assert_eq!(publisher.subscriber_count(), 0);
        assert_eq!(publisher.evicted_subscriber_count(), 1);
    }

    /// Eviction is per-subscriber: a lagging L1 client is dropped
    /// while a healthy subscriber on another feed keeps receiving —
    /// feed and market filters must not turn one client's failure
    /// into everyone's disconnect.
    #[test]
    fn eviction_is_per_subscriber() {
        let publisher = MarketDataPublisher::new();
        let _lagging = publisher.subscribe(vec![FeedType::L1], vec![]);
        let mut healthy = publisher.subscribe(vec![FeedType::Trades], vec![]);
        for _ in 0..=SUB_QUEUE_DEPTH {
            publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
        }
        assert_eq!(publisher.subscriber_count(), 1, "only the lagging subscriber is evicted");
        assert_eq!(publisher.evicted_subscriber_count(), 1);
        publisher.publish_trade(0, Price(1), Qty(1), true);
        assert!(healthy.try_recv().is_ok(), "healthy subscriber still receives its feed");
    }

    /// Market filtering still applies under the bounded queue: a
    /// subscriber whose market filter excludes the update is never
    /// sent it — and so is never evicted by traffic it doesn't want.
    #[test]
    fn filtered_out_traffic_cannot_evict() {
        let publisher = MarketDataPublisher::new();
        let _rx = publisher.subscribe(vec![FeedType::L1], vec![1]);
        for _ in 0..=SUB_QUEUE_DEPTH {
            publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
        }
        assert_eq!(publisher.subscriber_count(), 1, "no send attempt → no eviction");
        assert_eq!(publisher.evicted_subscriber_count(), 0);
    }
}
