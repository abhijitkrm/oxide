//! Off-chain matching server — the HFT-grade order entry layer.
//!
//! This crate implements the off-chain matching architecture
//! (plan.md §9.5): a high-performance matching server that runs the
//! [`trading::MatchingEngine`] directly, accepts orders via four
//! protocols (binary TCP, WebSocket, JSON-RPC, FIX), enforces
//! pre-trade balance checks on every order, and batches fills for
//! on-chain settlement.
//!
//! # Architecture
//!
//! ```text
//!                       ┌─────────────────────────────┐
//!   Binary TCP ──────►  │                             │
//!   WebSocket ──────►  │   Protocol Adapters          │
//!   JSON-RPC ───────►  │   (decode → OrderRequest)     │
//!   FIX ────────────►  │                             │
//!                       └──────────┬──────────────────┘
//!                                  │
//!                                  ▼
//!                       ┌─────────────────────────────┐
//!                       │   Balance Cache              │
//!                       │   (HashMap<Address, u64>)    │
//!                       │   Pre-check: reject buys     │
//!                       │   with insufficient quote    │
//!                       └──────────┬──────────────────┘
//!                                  │
//!                                  ▼
//!                       ┌─────────────────────────────┐
//!                       │   MatchingEngine             │
//!                       │   (19M fills/s raw)           │
//!                       └──────────┬──────────────────┘
//!                                  │
//!                                  ▼
//!                       ┌─────────────────────────────┐
//!                       │   Fill Buffer                 │
//!                       │   → Update balance cache      │
//!                       │   → Batch for settlement       │
//!                       └─────────────────────────────┘
//! ```
//!
//! # Balance checks (anti-spam)
//!
//! Every order is balance-checked before matching:
//! - **Buy orders:** the buyer's available quote balance must cover
//!   `price * qty / PRICE_SCALE` (the notional in scale-6 quote).
//!   If insufficient, the order is rejected with `Reject::InsufficientBalance`.
//! - **Sell orders:** v0 does not track base-asset balances (the
//!   exchange module's v0 behaviour). Sell orders are accepted
//!   without a pre-check; settlement credits the seller on fill.
//!
//! The balance cache is a flat `HashMap<[u8; 20], u64>` — O(1)
//! lookup, no allocation (fixed 20-byte keys, not `Vec<u8>`). This
//! is ~10x faster than the bank's `BTreeMap<Vec<u8>, Vec<u8>>` for
//! the hot path.
//!
//! # Settlement
//!
//! Fills are accumulated in a batch buffer. Every `batch_interval`
//! (default 100ms), the batch is sealed and submitted as a single
//! settlement transaction to consensus. Validators verify the
//! batch (check balances, fill consistency) but do not re-match.

#![allow(clippy::module_name_repetitions)]

pub mod balance;
pub mod fix;
pub mod jsonrpc;
pub mod market_data;
pub mod protocol;
pub mod ring;
pub mod risk;
pub mod server;
pub mod ws;

pub use balance::{BalanceCache, DEFAULT_SHARD_COUNT, ShardedBalanceCache};
pub use protocol::{
    ActionRequest, ActionType, OrderAction, OrderRequest, OrderResponse, RejectReason,
};
pub use ring::{SpscReceiver, SpscSender, Wakeup, spsc_ring, spsc_ring_with_wakeup};
pub use risk::{RiskConfig, RiskDecision, RiskEngine};

use primitives::fixed::{Price, Qty};
use std::sync::Arc;
use trading::{
    DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderOutcome, OrderType, Side,
    StpMode, TimeInForce,
};

/// The price scale divisor: notional = price * qty / `PRICE_SCALE`.
/// Matches `modules/exchange/src/lib.rs`.
const PRICE_SCALE: u128 = 100_000_000;

/// A matched fill with settlement attribution.
#[derive(Debug, Clone, Copy)]
pub struct SettledFill {
    /// Execution price (scale-8).
    pub price: Price,
    /// Traded quantity (scale-6).
    pub qty: Qty,
    /// Buyer address.
    pub buyer: primitives::Address,
    /// Seller address.
    pub seller: primitives::Address,
    /// Quote amount debited from buyer / credited to seller (scale-6).
    pub quote_amount: u64,
}

/// The core matching server — owns the matching engine, balance
/// cache, and fill buffer. Single-threaded by design (the matching
/// engine takes `&mut self`); protocol adapters feed orders via a
/// channel or call `submit_order` directly.
pub struct MatchingServer {
    /// The matching engine (one market in v0).
    engine: MatchingEngine,
    /// The balance cache — fast `HashMap`, 1M+ accounts.
    balances: BalanceCache,
    /// Pre-trade risk engine (rate limits, fat-finger, size caps).
    risk: RiskEngine,
    /// Reusable fill buffer — zero alloc after the first order.
    fills: Vec<FillEvent>,
    /// Total orders processed.
    orders_processed: u64,
    /// Total fills produced.
    fills_produced: u64,
    /// Total orders rejected by balance check.
    balance_rejections: u64,
    /// Total orders rejected by engine.
    engine_rejections: u64,
    /// Total orders rejected by the risk engine.
    risk_rejections: u64,
    /// The pending settlement batch.
    settlement_batch: Vec<SettledFill>,
}

impl MatchingServer {
    /// Create a new matching server with the given market config and
    /// initial balance cache capacity.
    ///
    /// # Panics
    ///
    /// Panics if the matching engine or order book cannot be created
    /// from the given config (e.g. invalid tick/lot sizes).
    pub fn new(cfg: MarketConfig, balance_capacity: usize) -> Self {
        let engine = MatchingEngine::new(cfg, DenseBook::new(cfg).expect("book creation"))
            .expect("engine creation");
        Self {
            engine,
            balances: BalanceCache::with_capacity(balance_capacity),
            risk: RiskEngine::with_defaults(),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(10_000),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
        }
    }

    /// Create a new matching server with a custom risk-engine
    /// configuration. Use this when you need non-default rate
    /// limits, size caps, or price bands.
    ///
    /// # Panics
    ///
    /// Panics if the matching engine or order book cannot be created
    /// from the given config.
    pub fn with_risk_config(
        cfg: MarketConfig,
        balance_capacity: usize,
        risk_config: RiskConfig,
    ) -> Self {
        let engine = MatchingEngine::new(cfg, DenseBook::new(cfg).expect("book creation"))
            .expect("engine creation");
        Self {
            engine,
            balances: BalanceCache::with_capacity(balance_capacity),
            risk: RiskEngine::new(risk_config),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(10_000),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
        }
    }

    /// Fund an account with the given quote balance. Called during
    /// setup or when the balance cache is synced from the bank.
    pub fn fund_account(&mut self, addr: &primitives::Address, amount: u64) {
        self.balances.set(addr, amount);
    }

    /// Get an account's available balance.
    pub fn balance(&self, addr: &primitives::Address) -> u64 {
        self.balances.get(addr)
    }

    /// Submit an order for matching. Performs:
    /// 1. Risk-engine checks (rate limit, size cap, price band, resting cap).
    /// 2. Balance check (buy orders only).
    /// 3. Matching via `MatchingEngine::place`.
    /// 4. Settlement (update balance cache, accumulate fills).
    ///
    /// Returns the order response (filled, resting, or rejected).
    pub fn submit_order(&mut self, req: &OrderRequest) -> OrderResponse {
        self.orders_processed += 1;

        // ── Risk-engine checks ───────────────────────────────────
        // Run before the balance check so we reject spam and
        // fat-finger orders without reserving any balance. The
        // timestamp is derived from the order count (deterministic
        // for testing); in production, the caller would pass a
        // real timestamp. The mid-price comes from the engine's
        // best bid/ask.
        let mid = match (self.engine.best_bid(), self.engine.best_ask()) {
            (Some((bid, _)), Some((ask, _))) => u64::midpoint(bid.0, ask.0),
            _ => 0, // no mid available — skip price-band check
        };
        let now_ms = self.orders_processed; // deterministic stand-in
        let decision = self.risk.check(&req.owner, now_ms, req.price.0, req.qty.0, mid);
        if let RiskDecision::Reject(reason) = decision {
            self.risk_rejections += 1;
            return OrderResponse::rejected(reason);
        }

        // ── Balance check (buy orders only) ─────────────────────
        // Buy orders pay `price * qty / PRICE_SCALE` in quote.
        // This is the anti-spam gate: without sufficient balance,
        // the order is rejected before it reaches the engine.
        if req.side == Side::Buy && req.order_type != OrderType::Market {
            let notional = u128::from(req.price.0) * u128::from(req.qty.0);
            let quote_needed = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            let available = self.balances.get(&req.owner);
            if available < quote_needed {
                self.balance_rejections += 1;
                return OrderResponse::rejected(RejectReason::InsufficientBalance);
            }
            // Reserve the balance immediately (debit now; if the
            // order is rejected by the engine, we credit back).
            self.balances.debit(&req.owner, quote_needed);
        }

        // ── Build the order ─────────────────────────────────────
        let order = NewOrder {
            side: req.side,
            order_type: req.order_type,
            tif: req.tif,
            price: req.price,
            qty: req.qty,
            owner: req.owner,
            stp: StpMode::None,
        };

        // ── Match ───────────────────────────────────────────────
        self.fills.clear();
        let Ok(outcome) = self.engine.place(order, &mut self.fills) else {
            self.engine_rejections += 1;
            // Credit back the reserved balance (buy orders only).
            if req.side == Side::Buy && req.order_type != OrderType::Market {
                let notional = u128::from(req.price.0) * u128::from(req.qty.0);
                let quote_needed = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
                self.balances.credit(&req.owner, quote_needed);
            }
            return OrderResponse::rejected(RejectReason::EngineError);
        };

        // ── Settle fills ─────────────────────────────────────────
        // For each fill: credit the seller (sell orders receive
        // quote). The buyer was already debited in the pre-check;
        // if the fill is partial, we credit back the unfilled
        // portion.
        for f in &self.fills {
            self.fills_produced += 1;
            let notional = u128::from(f.price.0) * u128::from(f.qty.0);
            let quote_amount = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            let (buyer, seller) = if f.taker_side == Side::Buy {
                (f.taker_owner, f.maker_owner)
            } else {
                (f.maker_owner, f.taker_owner)
            };
            // Credit the seller.
            self.balances.credit(&seller, quote_amount);
            // Accumulate for batch settlement.
            self.settlement_batch.push(SettledFill {
                price: f.price,
                qty: f.qty,
                buyer,
                seller,
                quote_amount,
            });
        }

        // If the buy order was partially filled or rejected (e.g.
        // FOK killed), credit back the unfilled portion.
        if req.side == Side::Buy && req.order_type != OrderType::Market {
            let filled_qty: u64 = self.fills.iter().map(|f| f.qty.0).sum();
            let unfilled_qty = req.qty.0.saturating_sub(filled_qty);
            if unfilled_qty > 0 {
                let refund =
                    u64::try_from(u128::from(req.price.0) * u128::from(unfilled_qty) / PRICE_SCALE)
                        .unwrap_or(0);
                self.balances.credit(&req.owner, refund);
            }
        }

        // ── Build response ──────────────────────────────────────
        let fills_count = u32::try_from(self.fills.len()).unwrap_or(u32::MAX);
        match outcome {
            OrderOutcome::Filled => OrderResponse::filled(fills_count),
            OrderOutcome::Resting { order_id, .. } => {
                // Track the new resting order for the resting-cap
                // risk check.
                self.risk.inc_resting(&req.owner);
                OrderResponse::resting(order_id, fills_count)
            }
            OrderOutcome::Killed => {
                // FOK killed — already credited back above.
                OrderResponse::rejected(RejectReason::Killed)
            }
            OrderOutcome::CanceledRemainder { order_id, .. } => {
                // Partial fill + resting remainder: the remainder
                // is a new resting order.
                self.risk.inc_resting(&req.owner);
                OrderResponse::resting(order_id, fills_count)
            }
            OrderOutcome::Rejected(_) => {
                self.engine_rejections += 1;
                OrderResponse::rejected(RejectReason::EngineRejected)
            }
        }
    }

    /// Submit an order action (cancel, amend, or replace) for
    /// processing. This is the entry point for all order-management
    /// operations beyond new-order submission.
    ///
    /// # Cancel
    ///
    /// Cancels a resting order by id. The `owner` must match the
    /// resting order's owner (authorization). On success, returns
    /// `filled(0)`. On failure (order not found or owner mismatch),
    /// returns `rejected(OrderNotFound)`. For buy orders, the
    /// reserved balance is refunded.
    ///
    /// # Amend
    ///
    /// Cancels the resting order and re-submits with the new price
    /// and/or quantity. The side is preserved from the original order;
    /// the re-submission uses Limit/GTC (resting orders are always
    /// GTC). If the cancel succeeds but the re-submit fails (e.g.
    /// insufficient balance at the new price), the original order is
    /// already canceled — this is the documented cancel-then-resubmit
    /// semantics. Returns the re-submission's response.
    ///
    /// # Replace
    ///
    /// Cancels the resting order and submits a brand-new order
    /// atomically. If the cancel fails, the new order is not
    /// submitted. Returns the new order's response (or the cancel
    /// rejection).
    pub fn submit_action(&mut self, action: &OrderAction) -> OrderResponse {
        self.orders_processed += 1;
        match action {
            OrderAction::Cancel { order_id, owner } => self.cancel_order(*order_id, *owner),
            OrderAction::Amend { order_id, owner, new_price, new_qty } => {
                self.amend_order(*order_id, *owner, *new_price, *new_qty)
            }
            OrderAction::Replace { order_id, owner, new_order } => {
                self.replace_order(*order_id, *owner, new_order)
            }
        }
    }

    /// Cancel a resting order by id, checking ownership and refunding
    /// any reserved balance for buy orders.
    fn cancel_order(&mut self, order_id: u64, owner: primitives::Address) -> OrderResponse {
        // Authorization: verify the order exists and the requester
        // owns it. This must happen BEFORE the cancel so an
        // unauthorized requester cannot remove another account's
        // order.
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        // Decrement the resting-order counter for this account.
        self.risk.dec_resting(&canceled.owner);
        // Refund the reserved balance for buy orders. The canceled
        // order's `qty` is the remaining (unfilled) quantity; the
        // reserved notional was `price * qty / PRICE_SCALE`.
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        OrderResponse::filled(0)
    }

    /// Amend a resting order: cancel + re-submit with new price/qty.
    fn amend_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
        new_price: Price,
        new_qty: Qty,
    ) -> OrderResponse {
        // Authorization + cancel.
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        // Decrement resting count for the canceled order.
        self.risk.dec_resting(&canceled.owner);
        // Refund the reserved balance for buy orders (the cancel side).
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        // Re-submit with the new price/qty, preserving the original
        // side. Resting orders are always GTC; use Limit/GTC for the
        // re-submission (a PostOnly order that would cross is rejected
        // by the engine, which is acceptable amend behavior).
        let req = OrderRequest {
            market: 0,
            side: canceled.side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: new_price,
            qty: new_qty,
            nonce: 0,
            owner: canceled.owner,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        // Decrement orders_processed to avoid double-counting (the
        // re-submit via submit_order increments it again).
        self.orders_processed -= 1;
        self.submit_order(&req)
    }

    /// Replace a resting order: cancel + submit a new order atomically.
    fn replace_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
        new_order: &OrderRequest,
    ) -> OrderResponse {
        // Authorization + cancel. If the cancel fails, the new order
        // is NOT submitted (atomic semantics).
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        // Decrement resting count for the canceled order.
        self.risk.dec_resting(&canceled.owner);
        // Refund the reserved balance for buy orders.
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        // Submit the new order. Decrement orders_processed to avoid
        // double-counting (submit_order increments it again).
        self.orders_processed -= 1;
        self.submit_order(new_order)
    }

    /// Seal the current settlement batch and return it. The caller
    /// submits this batch to consensus for on-chain finalization.
    pub fn seal_batch(&mut self) -> Vec<SettledFill> {
        std::mem::take(&mut self.settlement_batch)
    }

    /// Total orders processed since creation.
    pub fn orders_processed(&self) -> u64 {
        self.orders_processed
    }

    /// Total fills produced since creation.
    pub fn fills_produced(&self) -> u64 {
        self.fills_produced
    }

    /// Total orders rejected by the balance check.
    pub fn balance_rejections(&self) -> u64 {
        self.balance_rejections
    }

    /// Total orders rejected by the engine.
    pub fn engine_rejections(&self) -> u64 {
        self.engine_rejections
    }

    /// Total orders rejected by the risk engine (rate limit,
    /// fat-finger, size cap, resting cap).
    pub fn risk_rejections(&self) -> u64 {
        self.risk_rejections
    }

    /// Number of resting orders in the book.
    pub fn resting_count(&self) -> u32 {
        self.engine.resting_count()
    }

    /// Number of pending fills in the settlement batch.
    pub fn pending_settlements(&self) -> usize {
        self.settlement_batch.len()
    }

    /// Get a snapshot of the server's stats.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn stats(&self) -> MatcherStats {
        MatcherStats {
            orders_processed: self.orders_processed,
            fills_produced: self.fills_produced,
            balance_rejections: self.balance_rejections,
            engine_rejections: self.engine_rejections,
            risk_rejections: self.risk_rejections,
            resting_count: self.engine.resting_count(),
            pending_settlements: self.settlement_batch.len(),
        }
    }
}

/// A shared, thread-safe matching server wrapper for protocol
/// adapters. The protocol handlers (TCP, WS, JSON-RPC, FIX) all
/// feed orders through a single channel to the matching server,
/// which runs on a dedicated thread.
///
/// # Performance
///
/// `SharedMatcher` uses `Mutex<MatchingServer>` — every order
/// acquires a lock. For the batch endpoint (500+ orders per lock),
/// this amortizes well. For per-order paths, use `RingMatcher`
/// instead — it eliminates the lock entirely via SPSC rings.
pub struct SharedMatcher {
    /// The inner matching server, behind a mutex. Public so the
    /// batch settler can access `seal_batch()`.
    pub inner: Arc<std::sync::Mutex<MatchingServer>>,
}

impl SharedMatcher {
    /// Create a shared matcher wrapping the given server.
    pub fn new(server: MatchingServer) -> Self {
        Self { inner: Arc::new(std::sync::Mutex::new(server)) }
    }

    /// Submit an order (called by protocol adapters).
    ///
    /// Returns an `EngineError` rejection if the internal mutex is
    /// poisoned (a thread panicked while holding the lock). A poisoned
    /// mutex means the matching server is in an inconsistent state —
    /// the operator should restart the process.
    pub fn submit(&self, req: &OrderRequest) -> OrderResponse {
        match self.inner.lock() {
            Ok(mut guard) => guard.submit_order(req),
            Err(_) => OrderResponse::rejected(crate::protocol::RejectReason::EngineError),
        }
    }

    /// Submit an order action (cancel/amend/replace) (called by
    /// protocol adapters).
    ///
    /// Returns an `EngineError` rejection if the internal mutex is
    /// poisoned.
    pub fn submit_action(&self, action: &OrderAction) -> OrderResponse {
        match self.inner.lock() {
            Ok(mut guard) => guard.submit_action(action),
            Err(_) => OrderResponse::rejected(crate::protocol::RejectReason::EngineError),
        }
    }

    /// Get a snapshot of the server's stats.
    ///
    /// Returns zeroed stats if the internal mutex is poisoned.
    pub fn stats(&self) -> MatcherStats {
        match self.inner.lock() {
            Ok(s) => MatcherStats {
                orders_processed: s.orders_processed(),
                fills_produced: s.fills_produced(),
                balance_rejections: s.balance_rejections(),
                engine_rejections: s.engine_rejections(),
                risk_rejections: s.risk_rejections(),
                resting_count: s.resting_count(),
                pending_settlements: s.pending_settlements(),
            },
            Err(_) => MatcherStats::default(),
        }
    }
}

/// The seam between the batch settler and whatever owns the matching
/// server. `SharedMatcher` implements this via the mutex;
/// `RingMatcher` implements it via a control-channel command to its
/// owner thread. Either way, `seal_batch` pulls fills from THE ONE
/// order book — there is never more than one book.
pub trait BatchSealer: Send + Sync {
    /// Seal the current settlement batch. Returns the fills accrued
    /// since the last seal (empty if none).
    fn seal_batch(&self) -> Vec<SettledFill>;
}

impl BatchSealer for SharedMatcher {
    /// Seal via the mutex: lock the server, take the batch.
    ///
    /// Returns an empty vec if the inner mutex is poisoned.
    fn seal_batch(&self) -> Vec<SettledFill> {
        match self.inner.lock() {
            Ok(mut guard) => guard.seal_batch(),
            Err(_) => Vec::new(),
        }
    }
}

/// A control command sent from the protocol layer to the matcher
/// thread (via the control channel). The matcher thread services
/// these between ring polls — they never contend with order rings.
enum ControlCommand {
    /// Seal the current settlement batch and send it back via the
    /// oneshot channel. Used by the batch settler.
    Seal(std::sync::mpsc::Sender<Vec<SettledFill>>),
    /// Snapshot matcher stats and send them back via the oneshot
    /// channel. Used by monitoring.
    Stats(std::sync::mpsc::Sender<MatcherStats>),
    /// Process an order action (cancel/amend/replace) and send the
    /// response back via the oneshot channel. Used by protocol
    /// adapters that route through the ring matcher.
    Action(OrderAction, std::sync::mpsc::Sender<OrderResponse>),
}

/// A lock-free matching server using SPSC rings (LMAX Disruptor
/// pattern). Replaces `SharedMatcher`'s mutex with per-connection
/// lock-free rings — zero contention on the order submission hot path.
///
/// # Architecture
///
/// ```text
/// Conn 0 ──→ [ring 0] ──→ Matcher Thread (owns MatchingServer)
/// Conn 1 ──→ [ring 1] ──→      (reads all rings round-robin)
/// Conn 2 ──→ [ring 2] ──→      (no locks, ever)
///   ...         ...
/// Conn N ──→ [ring N] ──→
///                 ↓
///           [control channel] ← batch settler / monitoring
/// ```
///
/// Each connection pushes WHOLE BATCHES to its own `SpscRing`. The
/// matcher thread pops from all rings in round-robin order, processes
/// them via `MatchingServer::submit_order`, and pushes batch
/// responses to the per-connection response ring.
///
/// # One order book, always
///
/// The matcher thread is the SOLE owner of the `MatchingServer` —
/// there is exactly one book. The batch settler reaches the same
/// book through the control channel (`seal_batch`), never through a
/// second server instance.
///
/// # Why this is faster than Mutex
///
/// - `Mutex::lock` = atomic CAS + cache line invalidation (~20-50ns
///   when contended, ~10ns uncontended).
/// - `SpscRing::push` = one atomic store + one array write (~5ns).
/// - The matcher thread never blocks on a lock — it spins on rings.
/// - For batch requests, the matcher processes all orders in a ring
///   before moving to the next — natural batching.
pub struct RingMatcher {
    /// The order rings (one per connection). Producer = connection,
    /// consumer = matcher thread. Each item is a WHOLE BATCH of
    /// orders (`Vec<OrderRequest>`) — one mpsc send per batch, not
    /// per order. This keeps the per-order overhead near zero.
    order_rings: Vec<ring::SpscSender<Vec<OrderRequest>>>,
    /// The response rings (one per connection). Producer = matcher,
    /// consumer = connection. Each item is a WHOLE BATCH of
    /// responses.
    response_rings: Vec<ring::SpscReceiver<Vec<OrderResponse>>>,
    /// Control channel sender (protocol side). The matcher thread
    /// polls the receiver between ring polls and services seal/stats
    /// commands without touching the order rings.
    control_tx: std::sync::mpsc::Sender<ControlCommand>,
    /// The matcher thread handle (kept for shutdown).
    _thread: std::thread::JoinHandle<()>,
}

impl RingMatcher {
    /// Create a ring-based matcher with `num_rings` ring pairs.
    /// Spawns a dedicated matcher thread that owns the
    /// `MatchingServer` and polls all rings.
    ///
    /// # Arguments
    /// - `server`: the matching server (moved to the matcher thread).
    /// - `num_rings`: number of ring pairs (one per connection).
    /// - `ring_capacity`: capacity of each ring (power of 2).
    ///
    /// # Panics
    ///
    /// Panics if `num_rings` is 0.
    #[must_use]
    pub fn new(server: MatchingServer, num_rings: usize, ring_capacity: usize) -> Self {
        assert!(num_rings > 0, "must have at least one ring");
        // Shared wakeup signal for all rings. A push on any ring
        // signals this, waking the consumer thread from its idle
        // `wait_for_work` block. This replaces the previous
        // `std::thread::yield_now()` busy-spin that burned a full
        // CPU core at 100% when the matcher was idle.
        let shared_wakeup = Arc::new(ring::Wakeup::new());
        // Create ring pairs: (order_tx, order_rx) and (resp_tx, resp_rx).
        let mut order_senders: Vec<ring::SpscSender<Vec<OrderRequest>>> =
            Vec::with_capacity(num_rings);
        let mut order_receivers: Vec<ring::SpscReceiver<Vec<OrderRequest>>> =
            Vec::with_capacity(num_rings);
        let mut response_senders: Vec<ring::SpscSender<Vec<OrderResponse>>> =
            Vec::with_capacity(num_rings);
        let mut response_receivers: Vec<ring::SpscReceiver<Vec<OrderResponse>>> =
            Vec::with_capacity(num_rings);
        for _ in 0..num_rings {
            let (o_tx, o_rx) =
                ring::spsc_ring_with_wakeup(ring_capacity, Arc::clone(&shared_wakeup));
            let (r_tx, r_rx) =
                ring::spsc_ring_with_wakeup(ring_capacity, Arc::clone(&shared_wakeup));
            order_senders.push(o_tx);
            order_receivers.push(o_rx);
            response_senders.push(r_tx);
            response_receivers.push(r_rx);
        }

        let mut server = server;
        let (control_tx, control_rx) = std::sync::mpsc::channel::<ControlCommand>();
        let thread = std::thread::spawn(move || {
            loop {
                let mut did_work = false;
                // Round-robin poll all rings.
                for (i, order_rx) in order_receivers.iter().enumerate() {
                    while let Some(batch) = order_rx.pop() {
                        // Process the WHOLE batch: submit every order
                        // back-to-back (no interleaving from other
                        // rings — the batch is atomic).
                        let responses: Vec<OrderResponse> =
                            batch.iter().map(|req| server.submit_order(req)).collect();
                        // Push the batch response to this connection's
                        // ring. If the ring is full, spin until the
                        // client drains it. If the client disconnected
                        // (connection dropped), drop the responses —
                        // there is nowhere to send them.
                        let mut pending = responses;
                        loop {
                            match response_senders[i].push(pending) {
                                Ok(()) => break,
                                Err(crate::ring::PushError::Disconnected(_)) => {
                                    // Client gone; discard responses.
                                    break;
                                }
                                Err(crate::ring::PushError::Full(returned)) => {
                                    pending = returned;
                                    std::hint::spin_loop();
                                }
                            }
                        }
                        did_work = true;
                    }
                }
                // Service control commands (seal/stats) between ring
                // polls. These come from the batch settler and
                // monitoring — never from the order hot path.
                while let Ok(cmd) = control_rx.try_recv() {
                    match cmd {
                        ControlCommand::Seal(reply) => {
                            let batch = server.seal_batch();
                            let _ = reply.send(batch);
                        }
                        ControlCommand::Stats(reply) => {
                            let stats = MatcherStats {
                                orders_processed: server.orders_processed(),
                                fills_produced: server.fills_produced(),
                                balance_rejections: server.balance_rejections(),
                                engine_rejections: server.engine_rejections(),
                                risk_rejections: server.risk_rejections(),
                                resting_count: server.resting_count(),
                                pending_settlements: server.pending_settlements(),
                            };
                            let _ = reply.send(stats);
                        }
                        ControlCommand::Action(action, reply) => {
                            let resp = server.submit_action(&action);
                            let _ = reply.send(resp);
                        }
                    }
                    did_work = true;
                }
                if !did_work {
                    // No work on any ring — block on the shared wakeup
                    // signal until a producer pushes or the 1 ms
                    // timeout elapses. The timeout ensures the control
                    // channel (seal/stats) is still serviced
                    // regularly. This replaces the previous
                    // `std::thread::yield_now()` busy-spin that burned
                    // a full CPU core at 100% when idle.
                    order_receivers[0].wait_for_work(std::time::Duration::from_millis(1));
                }
            }
        });

        Self {
            order_rings: order_senders,
            response_rings: response_receivers,
            control_tx,
            _thread: thread,
        }
    }

    /// Seal the settlement batch via a control-channel command to the
    /// matcher thread. This reads from THE SAME order book the
    /// protocols write to — there is exactly one book.
    ///
    /// Returns an empty vec if the control channel is disconnected
    /// (matcher thread died) or the reply fails.
    pub fn seal_batch(&self) -> Vec<SettledFill> {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self.control_tx.send(ControlCommand::Seal(reply_tx)).is_err() {
            return Vec::new();
        }
        reply_rx.recv().unwrap_or_default()
    }

    /// Snapshot matcher stats via a control-channel command.
    ///
    /// Returns zeroed stats if the control channel is disconnected
    /// (matcher thread died) or the reply fails.
    pub fn stats(&self) -> MatcherStats {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self.control_tx.send(ControlCommand::Stats(reply_tx)).is_err() {
            return MatcherStats::default();
        }
        reply_rx.recv().unwrap_or_default()
    }

    /// Submit an order action (cancel/amend/replace) via a
    /// control-channel command to the matcher thread. This reaches
    /// THE SAME order book the rings write to — there is exactly one
    /// book.
    ///
    /// Returns an `EngineError` rejection if the control channel is
    /// disconnected (matcher thread died) or the reply fails.
    pub fn submit_action(&self, action: OrderAction) -> OrderResponse {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self.control_tx.send(ControlCommand::Action(action, reply_tx)).is_err() {
            return OrderResponse::rejected(crate::protocol::RejectReason::EngineError);
        }
        reply_rx
            .recv()
            .unwrap_or_else(|_| OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
    }

    /// Get a connection's order sender (producer side of the order
    /// ring). The caller pushes WHOLE BATCHES (`Vec<OrderRequest>`)
    /// to this ring — one push per batch, not per order.
    pub fn order_sender(&self, ring_idx: usize) -> &ring::SpscSender<Vec<OrderRequest>> {
        &self.order_rings[ring_idx]
    }

    /// Get a connection's response receiver (consumer side of the
    /// response ring). The caller pops WHOLE BATCHES
    /// (`Vec<OrderResponse>`) from this ring.
    pub fn response_receiver(&self, ring_idx: usize) -> &ring::SpscReceiver<Vec<OrderResponse>> {
        &self.response_rings[ring_idx]
    }

    /// Number of ring pairs (connections supported).
    pub fn num_rings(&self) -> usize {
        self.order_rings.len()
    }
}

impl BatchSealer for RingMatcher {
    /// Seal via the control channel: the matcher thread (sole owner
    /// of the book) takes the batch and replies over the oneshot.
    ///
    /// # Panics
    ///
    /// Panics if the control channel is disconnected (matcher thread
    /// died) or the reply channel fails.
    fn seal_batch(&self) -> Vec<SettledFill> {
        RingMatcher::seal_batch(self)
    }
}

/// A snapshot of matcher statistics (for monitoring/reporting).
#[derive(Debug, Clone, Copy, Default)]
#[allow(missing_docs)]
pub struct MatcherStats {
    pub orders_processed: u64,
    pub fills_produced: u64,
    pub balance_rejections: u64,
    pub engine_rejections: u64,
    /// Orders rejected by the risk engine (rate limit, fat-finger,
    /// size cap, resting cap).
    pub risk_rejections: u64,
    pub resting_count: u32,
    pub pending_settlements: usize,
}

// ── MultiMarketMatcher ───────────────────────────────────────────────

/// A message sent to a market worker — either a batch of orders to
/// process or a control command (seal/stats). Merging these into one
/// channel avoids the worker blocking on `work_rx.recv()` while a
/// control command waits on a separate channel.
enum MarketMessage {
    /// A batch of orders to match and settle.
    Work(MarketWork),
    /// An order action (cancel/amend/replace) to process.
    Action(ActionWork),
    /// Seal this worker's settlement batch and return it.
    Seal(std::sync::mpsc::Sender<Vec<SettledFill>>),
    /// Snapshot this worker's stats.
    Stats(std::sync::mpsc::Sender<WorkerStats>),
}

/// A work item sent from a protocol handler to a market worker
/// thread. The worker processes the orders, sends the responses back
/// via `response_tx`, and accumulates fills for batch settlement.
struct MarketWork {
    /// The batch of orders (all for this market).
    orders: Vec<OrderRequest>,
    /// One-shot channel for the worker to return the responses.
    response_tx: std::sync::mpsc::Sender<Vec<OrderResponse>>,
}

/// An action work item: a single order action (cancel/amend/replace)
/// routed to the correct market worker.
struct ActionWork {
    /// The order action to process.
    action: OrderAction,
    /// One-shot channel for the worker to return the response.
    response_tx: std::sync::mpsc::Sender<OrderResponse>,
}

/// Per-worker stats (one market).
#[derive(Debug, Clone, Copy, Default)]
struct WorkerStats {
    orders_processed: u64,
    fills_produced: u64,
    balance_rejections: u64,
    engine_rejections: u64,
    risk_rejections: u64,
    resting_count: u32,
    pending_settlements: usize,
}

/// A multi-market parallel matcher: one worker thread per market,
/// each owning its own `MatchingEngine`, all sharing a single
/// `ShardedBalanceCache`.
///
/// # Architecture
///
/// ```text
///   Protocol handlers (TCP, WS, JSON-RPC, FIX)
///         │
///         ▼
///   ┌─────────────────────────────────────────────┐
///   │  Per-market order channels (MPSC)            │
///   │  market 0 → worker 0  (owns Engine 0)        │
///   │  market 1 → worker 1  (owns Engine 1)        │
///   │  ...                                         │
///   │  market N → worker N  (owns Engine N)        │
///   └─────────────────────────────────────────────┘
///         │                        │
///         ▼                        ▼
///   ┌──────────────┐    ┌──────────────────────┐
///   │ Each worker: │    │ ShardedBalanceCache  │
///   │ 1 Engine     │───►│ (64 shards, Mutex    │
///   │ 1 fill buf   │    │  per shard)           │
///   │ 1 settle buf │    └──────────────────────┘
///   └──────────────┘
/// ```
///
/// # Parallelism
///
/// Each market worker is an independent thread. Markets are
/// independent (no shared order book state), so N markets run on N
/// cores with zero contention on the matching hot path. The only
/// shared state is the balance cache, which is sharded by account
/// hash — contention only occurs when two markets trade the same
/// account simultaneously, and even then it's one shard lock.
///
/// # Determinism
///
/// Within each market, the worker processes orders in FIFO order
/// (MPSC channel preserves order). Across markets, ordering is
/// non-deterministic (threads run independently), but that's
/// correct — different markets are independent state machines.
///
/// # Settlement
///
/// Each worker accumulates fills in its own `settlement_batch` vec
/// (no shared lock on the fill path). The batch settler sends a
/// `Seal` command to every worker, collects all batches, and
/// concatenates them. This is lock-free on the hot path.
pub struct MultiMarketMatcher {
    /// One sender per market: protocol handlers push `MarketMessage`
    /// items here (either `Work` or `Seal`/`Stats` control commands).
    /// `mpsc::Sender` is cloneable, so multiple connections can feed
    /// the same market.
    market_senders: Vec<std::sync::mpsc::Sender<MarketMessage>>,
    /// Worker thread handles (kept for shutdown).
    _threads: Vec<std::thread::JoinHandle<()>>,
    /// Number of markets.
    num_markets: usize,
}

impl MultiMarketMatcher {
    /// Create a multi-market parallel matcher with the given market
    /// configs. Spawns one worker thread per market.
    ///
    /// # Arguments
    /// - `configs`: one `MarketConfig` per market (`market_id` = index).
    /// - `balances`: the shared sharded balance cache (fund accounts
    ///   before calling this).
    ///
    /// # Panics
    ///
    /// Panics if `configs` is empty or if any engine/book fails to
    /// create from the given config.
    #[must_use]
    pub fn new(configs: Vec<MarketConfig>, balances: Arc<ShardedBalanceCache>) -> Self {
        assert!(!configs.is_empty(), "must have at least one market");
        let num_markets = configs.len();
        let mut market_senders = Vec::with_capacity(num_markets);
        let mut threads = Vec::with_capacity(num_markets);

        for cfg in configs {
            let (tx, rx) = std::sync::mpsc::channel::<MarketMessage>();
            let balances = Arc::clone(&balances);
            let thread = std::thread::spawn(move || {
                MarketWorker::run(cfg, balances, rx);
            });
            market_senders.push(tx);
            threads.push(thread);
        }

        Self { market_senders, _threads: threads, num_markets }
    }

    /// Submit a batch of orders. All orders in the batch MUST be for
    /// the same market (the caller is responsible for grouping by
    /// market). Returns the responses in the same order as the
    /// requests.
    ///
    /// # Panics
    ///
    /// Panics if the market worker thread has died (channel
    /// disconnected) or the response channel fails.
    pub fn submit_batch(&self, orders: Vec<OrderRequest>) -> Vec<OrderResponse> {
        assert!(!orders.is_empty(), "batch must not be empty");
        let market = orders[0].market as usize;
        assert!(
            market < self.num_markets,
            "market {market} out of range (have {} markets)",
            self.num_markets
        );
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        if self.market_senders[market]
            .send(MarketMessage::Work(MarketWork { orders, response_tx }))
            .is_err()
        {
            return vec![OrderResponse::rejected(RejectReason::EngineError); 1];
        }
        response_rx
            .recv()
            .unwrap_or_else(|_| vec![OrderResponse::rejected(RejectReason::EngineError); 1])
    }

    /// Submit a single order. Routes to the correct market worker.
    ///
    /// Returns an `EngineError` rejection if the market worker thread
    /// has died.
    pub fn submit_one(&self, order: OrderRequest) -> OrderResponse {
        let mut responses = self.submit_batch(vec![order]);
        responses.pop().unwrap_or_else(|| OrderResponse::rejected(RejectReason::EngineError))
    }

    /// Submit an order action (cancel/amend/replace). Routes to the
    /// market worker that owns the order (determined by the market
    /// field in the action's new order for Replace, or market 0 for
    /// Cancel/Amend in v0).
    ///
    /// Returns an `EngineError` rejection if the market worker thread
    /// has died.
    pub fn submit_action(&self, action: OrderAction) -> OrderResponse {
        // Cancel/Amend are single-market (v0: market 0). Replace
        // carries a full OrderRequest with its own market field.
        let market = match &action {
            OrderAction::Replace { new_order, .. } => new_order.market as usize,
            _ => 0,
        };
        if market >= self.num_markets {
            return OrderResponse::rejected(RejectReason::EngineError);
        }
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        if self.market_senders[market]
            .send(MarketMessage::Action(ActionWork { action, response_tx }))
            .is_err()
        {
            return OrderResponse::rejected(RejectReason::EngineError);
        }
        response_rx.recv().unwrap_or_else(|_| OrderResponse::rejected(RejectReason::EngineError))
    }

    /// Seal the settlement batch across ALL markets. Sends a `Seal`
    /// message to every worker, collects all fills, and concatenates
    /// them. This is the `BatchSealer` implementation for the
    /// multi-market path.
    ///
    /// Returns fills only from live workers; dead workers contribute
    /// nothing.
    pub fn seal_batch(&self) -> Vec<SettledFill> {
        let mut all_fills = Vec::new();
        for tx in &self.market_senders {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            if tx.send(MarketMessage::Seal(reply_tx)).is_err() {
                continue;
            }
            if let Ok(fills) = reply_rx.recv() {
                all_fills.extend(fills);
            }
        }
        all_fills
    }

    /// Snapshot aggregate stats across ALL markets.
    ///
    /// Returns partial stats from live workers; dead workers
    /// contribute zeros.
    pub fn stats(&self) -> MatcherStats {
        let mut total = MatcherStats::default();
        for tx in &self.market_senders {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            if tx.send(MarketMessage::Stats(reply_tx)).is_err() {
                continue;
            }
            if let Ok(s) = reply_rx.recv() {
                total.orders_processed += s.orders_processed;
                total.fills_produced += s.fills_produced;
                total.balance_rejections += s.balance_rejections;
                total.engine_rejections += s.engine_rejections;
                total.risk_rejections += s.risk_rejections;
                total.resting_count += s.resting_count;
                total.pending_settlements += s.pending_settlements;
            }
        }
        total
    }

    /// Number of markets.
    #[must_use]
    pub fn num_markets(&self) -> usize {
        self.num_markets
    }
}

impl BatchSealer for MultiMarketMatcher {
    /// Seal across all markets: collect fills from every worker.
    ///
    /// # Panics
    ///
    /// Panics if any worker thread has died.
    fn seal_batch(&self) -> Vec<SettledFill> {
        MultiMarketMatcher::seal_batch(self)
    }
}

/// A single market worker thread — owns one `MatchingEngine` and
/// processes orders from its MPSC channel. Settlement fills are
/// accumulated locally (no shared lock); the batch settler collects
/// them via the control channel.
struct MarketWorker {
    /// The matching engine for this market (single-writer).
    engine: MatchingEngine,
    /// Shared sharded balance cache (cross-market).
    balances: Arc<ShardedBalanceCache>,
    /// Reusable fill buffer — zero alloc after the first order.
    fills: Vec<FillEvent>,
    /// The pending settlement batch (local to this worker).
    settlement_batch: Vec<SettledFill>,
    /// Total orders processed by this worker.
    orders_processed: u64,
    /// Total fills produced by this worker.
    fills_produced: u64,
    /// Total orders rejected by balance check.
    balance_rejections: u64,
    /// Total orders rejected by the engine.
    engine_rejections: u64,
}

impl MarketWorker {
    /// The worker loop: receive messages (work or control), process
    /// them. Blocks on the single channel — no polling, no missed
    /// control commands.
    fn run(
        cfg: MarketConfig,
        balances: Arc<ShardedBalanceCache>,
        rx: std::sync::mpsc::Receiver<MarketMessage>,
    ) {
        let engine = MatchingEngine::new(cfg, DenseBook::new(cfg).expect("book creation"))
            .expect("engine creation");
        let mut worker = MarketWorker {
            engine,
            balances,
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(10_000),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
        };

        loop {
            match rx.recv() {
                Ok(MarketMessage::Work(work)) => {
                    let responses = worker.process_batch(&work.orders);
                    let _ = work.response_tx.send(responses);
                }
                Ok(MarketMessage::Action(action_work)) => {
                    let resp = worker.submit_action(&action_work.action);
                    let _ = action_work.response_tx.send(resp);
                }
                Ok(MarketMessage::Seal(reply)) => {
                    let batch = std::mem::take(&mut worker.settlement_batch);
                    let _ = reply.send(batch);
                }
                Ok(MarketMessage::Stats(reply)) => {
                    let stats = WorkerStats {
                        orders_processed: worker.orders_processed,
                        fills_produced: worker.fills_produced,
                        balance_rejections: worker.balance_rejections,
                        engine_rejections: worker.engine_rejections,
                        risk_rejections: 0, // TODO: wire risk engine into multi-market workers
                        resting_count: worker.engine.resting_count(),
                        pending_settlements: worker.settlement_batch.len(),
                    };
                    let _ = reply.send(stats);
                }
                Err(_) => break, // All senders dropped — shutdown.
            }
        }
    }

    /// Process a batch of orders for this market. Returns responses
    /// in the same order as the requests.
    fn process_batch(&mut self, orders: &[OrderRequest]) -> Vec<OrderResponse> {
        let mut responses = Vec::with_capacity(orders.len());
        for req in orders {
            responses.push(self.submit_order(req));
        }
        responses
    }

    /// Submit one order: balance check, match, settle. Mirrors
    /// `MatchingServer::submit_order` but uses the shared
    /// `ShardedBalanceCache` instead of a local `BalanceCache`.
    fn submit_order(&mut self, req: &OrderRequest) -> OrderResponse {
        self.orders_processed += 1;

        // ── Balance check (buy orders only) ─────────────────────
        // Atomic check-and-debit under the shard lock — no TOCTOU
        // race even if another market trades this account.
        if req.side == Side::Buy && req.order_type != OrderType::Market {
            let notional = u128::from(req.price.0) * u128::from(req.qty.0);
            let quote_needed = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            if !self.balances.check_and_debit(&req.owner, quote_needed) {
                self.balance_rejections += 1;
                return OrderResponse::rejected(RejectReason::InsufficientBalance);
            }
        }

        // ── Build the order ─────────────────────────────────────
        let order = NewOrder {
            side: req.side,
            order_type: req.order_type,
            tif: req.tif,
            price: req.price,
            qty: req.qty,
            owner: req.owner,
            stp: StpMode::None,
        };

        // ── Match ───────────────────────────────────────────────
        self.fills.clear();
        let Ok(outcome) = self.engine.place(order, &mut self.fills) else {
            self.engine_rejections += 1;
            // Credit back the reserved balance (buy orders only).
            if req.side == Side::Buy && req.order_type != OrderType::Market {
                let notional = u128::from(req.price.0) * u128::from(req.qty.0);
                let quote_needed = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
                self.balances.credit(&req.owner, quote_needed);
            }
            return OrderResponse::rejected(RejectReason::EngineError);
        };

        // ── Settle fills ─────────────────────────────────────────
        // Credit the seller for each fill. The buyer was already
        // debited in the pre-check; partial fills get a refund.
        for f in &self.fills {
            self.fills_produced += 1;
            let notional = u128::from(f.price.0) * u128::from(f.qty.0);
            let quote_amount = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            let (buyer, seller) = if f.taker_side == Side::Buy {
                (f.taker_owner, f.maker_owner)
            } else {
                (f.maker_owner, f.taker_owner)
            };
            // Credit the seller (cross-shard if needed).
            self.balances.credit(&seller, quote_amount);
            // Accumulate for batch settlement.
            self.settlement_batch.push(SettledFill {
                price: f.price,
                qty: f.qty,
                buyer,
                seller,
                quote_amount,
            });
        }

        // Refund unfilled portion of buy orders.
        if req.side == Side::Buy && req.order_type != OrderType::Market {
            let filled_qty: u64 = self.fills.iter().map(|f| f.qty.0).sum();
            let unfilled_qty = req.qty.0.saturating_sub(filled_qty);
            if unfilled_qty > 0 {
                let refund =
                    u64::try_from(u128::from(req.price.0) * u128::from(unfilled_qty) / PRICE_SCALE)
                        .unwrap_or(0);
                self.balances.credit(&req.owner, refund);
            }
        }

        // ── Build response ──────────────────────────────────────
        let fills_count = u32::try_from(self.fills.len()).unwrap_or(u32::MAX);
        match outcome {
            OrderOutcome::Filled => OrderResponse::filled(fills_count),
            OrderOutcome::Resting { order_id, .. } => OrderResponse::resting(order_id, fills_count),
            OrderOutcome::Killed => OrderResponse::rejected(RejectReason::Killed),
            OrderOutcome::CanceledRemainder { order_id, .. } => {
                OrderResponse::resting(order_id, fills_count)
            }
            OrderOutcome::Rejected(_) => {
                self.engine_rejections += 1;
                OrderResponse::rejected(RejectReason::EngineRejected)
            }
        }
    }

    /// Submit an order action (cancel/amend/replace). Mirrors
    /// `MatchingServer::submit_action` but uses the shared
    /// `ShardedBalanceCache`.
    fn submit_action(&mut self, action: &OrderAction) -> OrderResponse {
        self.orders_processed += 1;
        match action {
            OrderAction::Cancel { order_id, owner } => self.cancel_order(*order_id, *owner),
            OrderAction::Amend { order_id, owner, new_price, new_qty } => {
                self.amend_order(*order_id, *owner, *new_price, *new_qty)
            }
            OrderAction::Replace { order_id, owner, new_order } => {
                self.replace_order(*order_id, *owner, new_order)
            }
        }
    }

    /// Cancel a resting order (multi-market path).
    fn cancel_order(&mut self, order_id: u64, owner: primitives::Address) -> OrderResponse {
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        OrderResponse::filled(0)
    }

    /// Amend a resting order (multi-market path).
    fn amend_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
        new_price: Price,
        new_qty: Qty,
    ) -> OrderResponse {
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        let req = OrderRequest {
            market: 0,
            side: canceled.side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: new_price,
            qty: new_qty,
            nonce: 0,
            owner: canceled.owner,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        self.orders_processed -= 1;
        self.submit_order(&req)
    }

    /// Replace a resting order (multi-market path).
    fn replace_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
        new_order: &OrderRequest,
    ) -> OrderResponse {
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        self.orders_processed -= 1;
        self.submit_order(new_order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::fixed::{Price, Qty};
    use trading::TimeInForce;

    fn cfg() -> MarketConfig {
        MarketConfig {
            market_id: 0,
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
            max_resting: 1 << 16,
        }
    }

    fn addr(byte: u8) -> primitives::Address {
        primitives::Address([byte; 20])
    }

    #[test]
    fn buy_order_rejected_with_insufficient_balance() {
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&addr(1), 1_000); // Not enough for 5 lots at $15.

        let req = OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(5_000),
            owner: addr(1),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };

        let resp = server.submit_order(&req);
        assert!(resp.rejected, "should reject insufficient balance");
        assert_eq!(resp.reject_reason, Some(RejectReason::InsufficientBalance));
        assert_eq!(server.balance(&addr(1)), 1_000, "balance unchanged");
    }

    #[test]
    fn buy_order_accepted_with_sufficient_balance() {
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&addr(9), 1_000_000_000); // Seller.
        server.fund_account(&addr(1), 1_000_000_000); // Buyer.

        // Rest a maker sell.
        let maker = OrderRequest {
            market: 0,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(9),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        server.submit_order(&maker);

        // Taker buy — should match the maker.
        let taker = OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(1),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let resp = server.submit_order(&taker);
        assert!(!resp.rejected, "should accept sufficient balance");
        assert_eq!(resp.fills_count, 1, "should have one fill");
        // Notional = 1_500_000_000 * 1_000 / 100_000_000 = 15_000.
        assert_eq!(server.balance(&addr(1)), 1_000_000_000 - 15_000);
        assert_eq!(server.balance(&addr(9)), 1_000_000_000 + 15_000);
    }

    #[test]
    fn spam_orders_rejected_without_balance() {
        // Use unlimited rate limit — this test checks balance
        // rejection, not rate limiting.
        let risk_cfg = RiskConfig {
            max_orders_per_second: 0,
            max_order_qty: 0,
            max_price_deviation_bps: 0,
            max_resting_per_account: 0,
        };
        let mut server = MatchingServer::with_risk_config(cfg(), 100, risk_cfg);

        // Submit 1000 buy orders with zero balance — all should be rejected.
        for _ in 0..1000 {
            let req = OrderRequest {
                market: 0,
                side: Side::Buy,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price(1_500_000_000),
                qty: Qty(1_000),
                owner: addr(1),
                nonce: 0,
                pubkey: [0u8; 32],
                signature: [0u8; 64],
            };
            let resp = server.submit_order(&req);
            assert!(resp.rejected, "spam order should be rejected");
        }
        assert_eq!(server.balance_rejections(), 1000);
        assert_eq!(server.orders_processed(), 1000);
        assert_eq!(server.fills_produced(), 0, "no fills from rejected orders");
    }

    #[test]
    fn ring_matcher_seals_from_the_one_book() {
        // The ring matcher's owner thread holds THE book. Submit
        // orders through the ring, then seal via the control channel
        // — the seal must return the SAME fills the protocols
        // produced (one book, never two).
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&addr(9), 1_000_000_000); // Seller.
        server.fund_account(&addr(1), 1_000_000_000); // Buyer.
        let ring = RingMatcher::new(server, 4, 1024);

        // Push a maker sell + taker buy as one batch through ring 0.
        let maker = OrderRequest {
            market: 0,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(9),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let taker = OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(1),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let sender = ring.order_sender(0);
        let receiver = ring.response_receiver(0);
        let mut batch = vec![maker, taker];
        while let Err(crate::ring::PushError::Full(returned)) = sender.push(batch) {
            batch = returned;
            std::hint::spin_loop();
        }
        let responses = loop {
            if let Some(r) = receiver.pop() {
                break r;
            }
            std::hint::spin_loop();
        };
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[1].fills_count, 1, "taker should fill against maker");

        // Seal through the control channel — must return the fill.
        let fills = ring.seal_batch();
        assert_eq!(fills.len(), 1, "seal returns the fill produced via the ring");
        assert_eq!(fills[0].qty, Qty(1_000));
        assert_eq!(fills[0].buyer, addr(1));
        assert_eq!(fills[0].seller, addr(9));

        // Stats via the control channel.
        let stats = ring.stats();
        assert_eq!(stats.orders_processed, 2);
        assert_eq!(stats.fills_produced, 1);
    }

    // ── MultiMarketMatcher tests ────────────────────────────────

    fn cfg_for(market_id: u8) -> MarketConfig {
        MarketConfig {
            market_id: u16::from(market_id),
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
            max_resting: 1 << 16,
        }
    }

    #[test]
    fn multi_market_two_markets_match_independently() {
        // Two markets, each with its own book. The same seller and
        // buyer trade on both — balances are shared (sharded), books
        // are independent.
        let balances = Arc::new(ShardedBalanceCache::new(8));
        balances.set(&addr(9), 1_000_000_000); // Seller.
        balances.set(&addr(1), 1_000_000_000); // Buyer.
        let configs = vec![cfg_for(0), cfg_for(1)];
        let matcher = MultiMarketMatcher::new(configs, balances);

        // Market 0: rest a maker sell, then a taker buy fills it.
        let maker0 = OrderRequest {
            market: 0,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(9),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let taker0 = OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(1),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let responses = matcher.submit_batch(vec![maker0, taker0]);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[1].fills_count, 1, "market 0 taker should fill");

        // Market 1: same pair, independent book — should also fill.
        let maker1 = OrderRequest {
            market: 1,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_600_000_000),
            qty: Qty(1_000),
            owner: addr(9),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let taker1 = OrderRequest {
            market: 1,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_600_000_000),
            qty: Qty(1_000),
            owner: addr(1),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let responses = matcher.submit_batch(vec![maker1, taker1]);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[1].fills_count, 1, "market 1 taker should fill");

        // Seal: should have 2 fills (one per market).
        let fills = matcher.seal_batch();
        assert_eq!(fills.len(), 2, "seal collects from both markets");

        // Aggregate stats: 4 orders, 2 fills.
        let stats = matcher.stats();
        assert_eq!(stats.orders_processed, 4);
        assert_eq!(stats.fills_produced, 2);
    }

    #[test]
    fn multi_market_balance_check_is_atomic_across_markets() {
        // Account 1 has exactly 15_000 quote (enough for ONE fill at
        // $15 × 1000 qty). Two markets try to debit simultaneously —
        // only one should succeed.
        let balances = Arc::new(ShardedBalanceCache::new(8));
        balances.set(&addr(9), 1_000_000_000); // Seller (funded).
        balances.set(&addr(1), 15_000); // Buyer: exactly one fill's worth.
        let configs = vec![cfg_for(0), cfg_for(1)];
        let matcher = MultiMarketMatcher::new(configs, balances);

        // Rest maker sells on both markets.
        let maker0 = OrderRequest {
            market: 0,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(9),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let maker1 = OrderRequest {
            market: 1,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(9),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        matcher.submit_batch(vec![maker0]);
        matcher.submit_batch(vec![maker1]);

        // Submit taker buys on both markets (same buyer, same balance).
        let taker0 = OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(1),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let taker1 = OrderRequest {
            market: 1,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(1),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let resp0 = matcher.submit_one(taker0);
        let resp1 = matcher.submit_one(taker1);

        // Exactly one should fill, the other should be rejected
        // (insufficient balance). The check_and_debit is atomic
        // under the shard lock.
        let fills0 = resp0.fills_count;
        let fills1 = resp1.fills_count;
        assert!(
            (fills0 == 1 && resp1.rejected) || (fills1 == 1 && resp0.rejected),
            "exactly one market should fill, the other reject; got fills0={fills0} rejected0={} fills1={fills1} rejected1={}",
            resp0.rejected,
            resp1.rejected
        );
    }
}
