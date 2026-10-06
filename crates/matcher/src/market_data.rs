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
//! # Design — sequencer-safe by construction (hft-audit F-05)
//!
//! The publisher is split in two:
//!
//! - [`MarketDataPublisher`] is the PRODUCER handle the matching
//!   path calls. `publish_*` builds one small typed message and
//!   pushes it onto a bounded SPSC ring — ~20ns, no serialization,
//!   no lock, no per-subscriber work on the match path. A full ring
//!   drops the update and counts it: market data is a lossy feed by
//!   design — the book must never back-pressure on subscribers.
//! - [`MarketDataFanout`] is the CONSUMER: a dedicated task (spawned
//!   on the node runtime) that owns the subscriber list, serializes
//!   each update ONCE to an `Arc<str>`, and broadcasts the shared
//!   string — every subscriber clone is a refcount bump, not a
//!   `String` copy.
//!
//! Before this split, `publish_*` serialized JSON and iterated the
//! whole subscriber list under a mutex on the caller's thread — on
//! the matching sequencer that is ~µs of serde plus N channel sends
//! inside the order hot path. Now everything past the ring push is
//! the fanout task's problem.
//!
//! # Serialization
//!
//! Messages are serialized as JSON (via `serde_json`) on the fanout
//! task. This is the universal wire format for WebSocket market
//! data — every exchange (Binance, Coinbase, Hyperliquid) uses JSON
//! for WS market data. A binary format (`MessagePack`, flatbuffers)
//! can slot into the fanout without touching the producer path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use primitives::fixed::{Price, Qty};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::ring::{SpscReceiver, SpscSender, spsc_ring_with_notify};

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

/// A market data message — one of the feed types. The unit the
/// handoff ring carries: small, owned, and cheap to move (the L2
/// level vectors move by pointer — no payload copy on the ring).
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
/// The fanout must never back-pressure on a slow socket, so the
/// queue is the only place a slow consumer can accumulate cost;
/// over this depth the subscriber is evicted (its send side
/// dropped), which closes the WebSocket task's `recv()` and ends
/// the connection — the standard exchange slow-consumer policy.
/// Raising it tolerates more client lag at more memory per lagging
/// subscriber; lowering it disconnects mildly slow clients.
const SUB_QUEUE_DEPTH: usize = 256;

/// Depth of the sequencer→fanout handoff ring, in updates.
///
/// 1,024 updates ≈ a few hundred µs of fanout lag at serialization
/// cost (~µs per update worst case). Tradeoff: deeper tolerates
/// longer fanout stalls (WS stalls, eviction bursts) at more
/// buffered memory; shallower sheds updates sooner — safe either
/// way because market data is explicitly lossy.
const OUTBOUND_RING_DEPTH: usize = 1024;

/// A subscriber's subscription: which feeds and markets they want.
/// Sent to the fanout over a cold-path mpsc — subscribe rate is
/// human-scale, so an unbounded channel is acceptable here (unlike
/// the per-message data path, which is strictly bounded).
#[derive(Debug)]
struct Subscription {
    /// The feeds this subscriber wants (L1, L2, L3, Trades).
    feeds: Vec<FeedType>,
    /// The markets this subscriber wants (empty = all).
    markets: Vec<u8>,
    /// The bounded channel to send messages on — capacity
    /// [`SUB_QUEUE_DEPTH`], payload `Arc<str>` so N subscribers
    /// share one serialization (refcount bump, not a string copy).
    tx: mpsc::Sender<Arc<str>>,
}

/// The producer half of the market data pipeline — the handle the
/// matching path publishes through.
///
/// Everything on this type is wait-free: `publish_*` assigns a
/// sequence number (atomic fetch-add — the SPSC ring then preserves
/// publication order), builds the typed update, and pushes it to
/// the fanout ring. Serialization, subscriber iteration, and every
/// eviction decision happen on the fanout task — never here.
///
/// Observability: `dropped_update_count` counts updates shed when
/// the ring was full; `evicted_subscriber_count` counts slow
/// consumers the fanout disconnected — the two numbers an operator
/// watches for feed health.
pub struct MarketDataPublisher {
    /// Handoff ring to the fanout task.
    tx: SpscSender<MarketDataMessage>,
    /// Subscription commands to the fanout (cold path).
    sub_tx: mpsc::UnboundedSender<Subscription>,
    /// Per-market L1 sequence counter.
    l1_seq: AtomicU64,
    /// Per-market L2 sequence counter.
    l2_seq: AtomicU64,
    /// Per-market trades sequence counter.
    trades_seq: AtomicU64,
    /// Updates shed because the fanout fell `OUTBOUND_RING_DEPTH`
    /// behind — the lossy-feed backpressure valve.
    dropped_updates: Arc<AtomicU64>,
    /// Subscribers evicted for a full queue or a closed receiver —
    /// owned by the fanout, shared here for monitoring.
    evicted_subscribers: Arc<AtomicU64>,
    /// Live subscription count — owned by the fanout, shared here.
    subscriber_count: Arc<AtomicU64>,
}

/// The consumer half: owns the subscriber list and does all
/// serialization. Runs as a dedicated task — `run()` pops updates
/// off the handoff ring (awaiting its `Notify` between empties) and
/// services subscription commands between updates.
pub struct MarketDataFanout {
    /// Handoff ring from producers.
    rx: SpscReceiver<MarketDataMessage>,
    /// Subscription commands (cold path).
    sub_rx: mpsc::UnboundedReceiver<Subscription>,
    /// Live subscribers — fanout-local, never locked.
    subscribers: Vec<Subscription>,
    /// Eviction count shared back to the publisher handle.
    evicted_subscribers: Arc<AtomicU64>,
    /// Live count shared back for monitoring.
    subscriber_count: Arc<AtomicU64>,
}

/// Build the (publisher, fanout) pair. The publisher is what the
/// matching path holds; the fanout is spawned once on the runtime
/// (`tokio::spawn(fanout.run())`).
#[must_use]
pub fn market_data_channel() -> (MarketDataPublisher, MarketDataFanout) {
    let notify = Arc::new(tokio::sync::Notify::new());
    let (tx, rx) = spsc_ring_with_notify(OUTBOUND_RING_DEPTH, notify);
    let (sub_tx, sub_rx) = mpsc::unbounded_channel();
    let evicted_subscribers = Arc::new(AtomicU64::new(0));
    let subscriber_count = Arc::new(AtomicU64::new(0));
    (
        MarketDataPublisher {
            tx,
            sub_tx,
            l1_seq: AtomicU64::new(0),
            l2_seq: AtomicU64::new(0),
            trades_seq: AtomicU64::new(0),
            dropped_updates: Arc::new(AtomicU64::new(0)),
            evicted_subscribers: Arc::clone(&evicted_subscribers),
            subscriber_count: Arc::clone(&subscriber_count),
        },
        MarketDataFanout {
            rx,
            sub_rx,
            subscribers: Vec::new(),
            evicted_subscribers,
            subscriber_count,
        },
    )
}

impl MarketDataPublisher {
    /// Create a publisher + fanout pair; see [`market_data_channel`].
    #[must_use]
    pub fn new() -> (Self, MarketDataFanout) {
        market_data_channel()
    }

    /// Subscribe a new client. Returns a bounded [`mpsc::Receiver`]
    /// (capacity [`SUB_QUEUE_DEPTH`]) of shared-serialized messages
    /// the caller forwards over the WebSocket. When the queue stays
    /// full the fanout evicts the subscription — the receiver's
    /// `recv()` then returns `None` and the connection task ends.
    ///
    /// The `feeds` parameter specifies which feeds the client wants.
    /// The `markets` parameter specifies which markets (empty = all).
    ///
    /// The subscription itself is delivered to the fanout over a
    /// cold-path channel; it takes effect as the fanout drains —
    /// an update published concurrently may (correctly) miss a
    /// not-yet-installed subscriber.
    #[must_use]
    pub fn subscribe(&self, feeds: Vec<FeedType>, markets: Vec<u8>) -> mpsc::Receiver<Arc<str>> {
        let (tx, rx) = mpsc::channel(SUB_QUEUE_DEPTH);
        // Cold path: a failed send means the fanout task is gone —
        // the returned receiver then reports disconnection, which
        // ends the client task exactly like an eviction.
        let _ = self.sub_tx.send(Subscription { feeds, markets, tx });
        rx
    }

    /// Publish an L1 update (top-of-book) to all L1 subscribers.
    /// Wait-free: sequence bump + struct build + one ring push.
    pub fn publish_l1(
        &self,
        market: u8,
        best_bid: Option<(Price, Qty)>,
        best_ask: Option<(Price, Qty)>,
    ) {
        let seq = self.l1_seq.fetch_add(1, Ordering::Relaxed);
        let msg = MarketDataMessage::L1(L1Update {
            feed: "l1",
            market,
            best_bid_price: best_bid.map(|(p, _)| p.0),
            best_bid_qty: best_bid.map(|(_, q)| q.0),
            best_ask_price: best_ask.map(|(p, _)| p.0),
            best_ask_qty: best_ask.map(|(_, q)| q.0),
            seq,
        });
        self.dispatch(msg);
    }

    /// Publish an L2 update (full depth) to all L2 subscribers.
    /// The `bids`/`asks` vectors move onto the ring by pointer —
    /// no payload copy on the producer path.
    pub fn publish_l2(&self, market: u8, bids: Vec<(u64, u64)>, asks: Vec<(u64, u64)>) {
        let seq = self.l2_seq.fetch_add(1, Ordering::Relaxed);
        self.dispatch(MarketDataMessage::L2(L2Update { feed: "l2", market, bids, asks, seq }));
    }

    /// Publish a trade (execution) to all Trades subscribers.
    pub fn publish_trade(&self, market: u8, price: Price, qty: Qty, taker_side_buy: bool) {
        let seq = self.trades_seq.fetch_add(1, Ordering::Relaxed);
        self.dispatch(MarketDataMessage::Trade(TradeMessage {
            feed: "trades",
            market,
            price: price.0,
            qty: qty.0,
            taker_side: if taker_side_buy { "buy" } else { "sell" },
            seq,
        }));
    }

    /// One ring push; on a full ring the update is dropped and
    /// counted — the documented lossy-feed policy (the match path
    /// never slows for market data). A dead fanout likewise drops:
    /// no subscribers can exist without it.
    #[inline]
    fn dispatch(&self, msg: MarketDataMessage) {
        if self.tx.push(msg).is_err() {
            self.dropped_updates.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Updates dropped because the fanout fell behind — nonzero
    /// means the feed is shedding load faster than clients see.
    #[must_use]
    pub fn dropped_update_count(&self) -> u64 {
        self.dropped_updates.load(Ordering::Relaxed)
    }

    /// Total subscribers evicted for full queues or closed
    /// receivers since startup — the operator-facing slow-consumer
    /// signal.
    #[must_use]
    pub fn evicted_subscriber_count(&self) -> u64 {
        self.evicted_subscribers.load(Ordering::Relaxed)
    }

    /// Get the current subscriber count (for monitoring). Lagging
    /// by the fanout's command drain — subscribe/unsubscribe is not
    /// latency-critical.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        // `usize` is at least u32 on every supported target — the
        // u64 counter can't hold more subscribers than exist.
        usize::try_from(self.subscriber_count.load(Ordering::Relaxed)).unwrap_or(usize::MAX)
    }
}

impl MarketDataFanout {
    /// The fanout loop: pop every queued update, broadcast it, then
    /// park on the ring's data `Notify` (with the register-then-
    /// recheck pattern so a push between the empty check and the
    /// await is not missed). Subscription commands are serviced
    /// between updates and between waits.
    ///
    /// Runs until every publisher handle is dropped — the ring then
    /// reports `producer_gone` and the task exits cleanly.
    pub async fn run(mut self) {
        let data = Arc::clone(self.rx.data_notify());
        loop {
            // Drain pending subscription commands first — installs
            // are cheap and cold.
            while let Ok(sub) = self.sub_rx.try_recv() {
                self.subscribers.push(sub);
                self.subscriber_count.store(self.subscribers.len() as u64, Ordering::Relaxed);
            }
            if self.rx.producer_gone() {
                return;
            }
            // Drain the ring completely, then wait.
            let mut drained = false;
            while let Some(msg) = self.rx.pop() {
                self.broadcast(&msg);
                drained = true;
            }
            let notified = data.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            // Re-check both channels after arming — a command or a
            // push racing the arm must not sleep through.
            while let Ok(sub) = self.sub_rx.try_recv() {
                self.subscribers.push(sub);
                self.subscriber_count.store(self.subscribers.len() as u64, Ordering::Relaxed);
            }
            if self.rx.pop().is_some() || drained {
                continue;
            }
            if self.rx.producer_gone() {
                return;
            }
            notified.await;
        }
    }

    /// Serialize once into `Arc<str>` and broadcast to every
    /// matching subscriber. All the work that used to sit on the
    /// match thread lives here (F-05): serde, the subscriber scan,
    /// eviction.
    fn broadcast(&mut self, msg: &MarketDataMessage) {
        let (market, feed): (u8, FeedType) = match msg {
            MarketDataMessage::L1(u) => (u.market, FeedType::L1),
            MarketDataMessage::L2(u) => (u.market, FeedType::L2),
            MarketDataMessage::Trade(u) => (u.market, FeedType::Trades),
        };
        let json: Arc<str> = match serde_json::to_string(msg) {
            Ok(s) => Arc::from(s.as_str()),
            Err(_) => return, // serialization of these types cannot fail in practice
        };
        let mut evict = 0usize;
        // `retain` walks the list once; `true` keeps the slot.
        self.subscribers.retain(|sub| {
            // Check if this subscriber wants this feed.
            if !sub.feeds.contains(&feed) {
                return true;
            }
            // Check if this subscriber wants this market (empty = all).
            if !sub.markets.is_empty() && !sub.markets.contains(&market) {
                return true;
            }
            // `try_send` never blocks on a slow socket. A full queue
            // means the client is [`SUB_QUEUE_DEPTH`] updates behind —
            // stale beyond usefulness — and a closed receiver means
            // the WS task is gone; either way the subscription is
            // dead weight. Evicting it (dropping the send side) ends
            // the client task: slow-consumer policy is disconnect,
            // not silent accumulation.
            if sub.tx.try_send(Arc::clone(&json)).is_ok() {
                true
            } else {
                evict += 1;
                false
            }
        });
        if evict > 0 {
            self.evicted_subscribers.fetch_add(evict as u64, Ordering::Relaxed);
            self.subscriber_count.store(self.subscribers.len() as u64, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Start a publisher + fanout pair; the fanout runs on the
    /// tokio runtime the test is already on.
    fn start() -> (MarketDataPublisher, tokio::task::JoinHandle<()>) {
        let (pub_, fanout) = market_data_channel();
        let handle = tokio::spawn(fanout.run());
        (pub_, handle)
    }

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
        let (publisher, _fanout) = start();
        let mut rx = publisher.subscribe(vec![FeedType::L1], vec![]);
        // Give the fanout a scheduler slot to install the
        // subscription, then publish.
        tokio::task::yield_now().await;
        publisher.publish_l1(0, Some((Price(1_500_000_000), Qty(1_000))), None);
        let msg = rx.recv().await.expect("should receive message");
        assert!(msg.contains("\"feed\":\"l1\""));
        assert!(msg.contains("\"best_bid_price\":1500000000"));
        assert!(msg.contains("\"best_ask_price\":null"));
    }

    #[tokio::test]
    async fn publish_trade_reaches_subscriber() {
        let (publisher, _fanout) = start();
        let mut rx = publisher.subscribe(vec![FeedType::Trades], vec![]);
        tokio::task::yield_now().await;
        publisher.publish_trade(0, Price(1_500_000_000), Qty(1_000), true);
        let msg = rx.recv().await.expect("should receive trade");
        assert!(msg.contains("\"feed\":\"trades\""));
        assert!(msg.contains("\"taker_side\":\"buy\""));
    }

    #[tokio::test]
    async fn subscriber_filters_by_market() {
        let (publisher, _fanout) = start();
        // Subscribe to market 1 only.
        let mut rx = publisher.subscribe(vec![FeedType::L1], vec![1]);
        tokio::task::yield_now().await;
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
        let (publisher, _fanout) = start();
        // Subscribe to Trades only.
        let mut rx = publisher.subscribe(vec![FeedType::Trades], vec![]);
        tokio::task::yield_now().await;
        // Publish L1 — should NOT reach this subscriber.
        publisher.publish_l1(0, Some((Price(1_500_000_000), Qty(1_000))), None);
        // Publish a trade — SHOULD reach this subscriber.
        publisher.publish_trade(0, Price(1_500_000_000), Qty(1_000), true);
        let msg = rx.recv().await.expect("should receive trade");
        assert!(msg.contains("\"feed\":\"trades\""));
    }

    #[tokio::test]
    async fn multiple_subscribers_all_receive() {
        let (publisher, _fanout) = start();
        let mut rx1 = publisher.subscribe(vec![FeedType::L1], vec![]);
        let mut rx2 = publisher.subscribe(vec![FeedType::L1], vec![]);
        tokio::task::yield_now().await;
        publisher.publish_l1(0, Some((Price(1_500_000_000), Qty(1_000))), None);
        let msg1 = rx1.recv().await.expect("subscriber 1 should receive");
        let msg2 = rx2.recv().await.expect("subscriber 2 should receive");
        assert_eq!(msg1, msg2, "both subscribers receive the same message");
    }

    #[tokio::test]
    async fn subscriber_count_tracks_subscriptions() {
        let (publisher, _fanout) = start();
        assert_eq!(publisher.subscriber_count(), 0);
        let _rx1 = publisher.subscribe(vec![FeedType::L1], vec![]);
        let _rx2 = publisher.subscribe(vec![FeedType::Trades], vec![]);
        // The count lives on the fanout task — drain its command
        // queue by yielding until the fanout runs.
        for _ in 0..64 {
            tokio::task::yield_now().await;
            if publisher.subscriber_count() == 2 {
                return;
            }
        }
        panic!("fanout never installed the subscriptions");
    }

    #[test]
    fn feed_type_as_str() {
        assert_eq!(FeedType::L1.as_str(), "l1");
        assert_eq!(FeedType::L2.as_str(), "l2");
        assert_eq!(FeedType::L3.as_str(), "l3");
        assert_eq!(FeedType::Trades.as_str(), "trades");
    }

    /// A subscriber that stops reading fills its bounded queue and
    /// is evicted: the fanout must never back-pressure on a slow
    /// socket, so the documented slow-consumer policy is disconnect.
    /// The queue is the only place a slow consumer can accumulate
    /// memory.
    #[tokio::test]
    async fn slow_consumer_is_evicted_at_queue_depth() {
        let (publisher, _fanout) = start();
        let mut rx = publisher.subscribe(vec![FeedType::L1], vec![]);
        for _ in 0..64 {
            tokio::task::yield_now().await;
            if publisher.subscriber_count() == 1 {
                break;
            }
        }
        // Fill exactly to capacity: every send must succeed — a full
        // queue alone is not yet an eviction.
        for _ in 0..SUB_QUEUE_DEPTH {
            publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
            tokio::task::yield_now().await;
        }
        assert_eq!(publisher.evicted_subscriber_count(), 0);
        // One more update than the queue holds → evict.
        publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
        for _ in 0..64 {
            tokio::task::yield_now().await;
            if publisher.evicted_subscriber_count() == 1 {
                break;
            }
        }
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
    /// first publish that finds the closed channel evicts it.
    #[tokio::test]
    async fn closed_receiver_is_evicted() {
        let (publisher, _fanout) = start();
        let rx = publisher.subscribe(vec![FeedType::L1], vec![]);
        drop(rx);
        publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
        for _ in 0..64 {
            tokio::task::yield_now().await;
            if publisher.evicted_subscriber_count() == 1 {
                return;
            }
        }
        panic!("fanout never evicted the closed receiver");
    }

    /// Eviction is per-subscriber: a lagging L1 client is dropped
    /// while a healthy subscriber on another feed keeps receiving —
    /// feed and market filters must not turn one client's failure
    /// into everyone's disconnect.
    #[tokio::test]
    async fn eviction_is_per_subscriber() {
        let (publisher, _fanout) = start();
        let _lagging = publisher.subscribe(vec![FeedType::L1], vec![]);
        let mut healthy = publisher.subscribe(vec![FeedType::Trades], vec![]);
        for _ in 0..64 {
            tokio::task::yield_now().await;
            if publisher.subscriber_count() == 2 {
                break;
            }
        }
        for _ in 0..=SUB_QUEUE_DEPTH {
            publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
            tokio::task::yield_now().await;
        }
        for _ in 0..64 {
            tokio::task::yield_now().await;
            if publisher.evicted_subscriber_count() == 1 {
                break;
            }
        }
        assert_eq!(publisher.subscriber_count(), 1, "only the lagging subscriber is evicted");
        assert_eq!(publisher.evicted_subscriber_count(), 1);
        publisher.publish_trade(0, Price(1_500_000_000), Qty(1_000), true);
        let msg = healthy.recv().await.expect("healthy subscriber still receives");
        assert!(msg.contains("\"feed\":\"trades\""));
    }

    /// F-05 regression: publishing while the fanout stalls must
    /// never block or panic — the ring fills to depth, then updates
    /// shed and the drop counter records them. The match path's
    /// worst case is a wait-free push, always. (The fanout is held
    /// alive but never polled: a dropped consumer would instead
    /// report `Disconnected` on every push.)
    #[test]
    fn publish_with_stalled_fanout_sheds_and_counts() {
        let (publisher, fanout) = market_data_channel();
        let _fanout_kept_alive = fanout; // never spawned — ring fills
        for _ in 0..(OUTBOUND_RING_DEPTH + 10) {
            publisher.publish_l1(0, Some((Price(1), Qty(1))), None);
        }
        assert_eq!(publisher.dropped_update_count(), 10);
    }
}
