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
//! is ~10x faster than a generic `BTreeMap<Vec<u8>, Vec<u8>>` for
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

pub use balance::{AtomicBalanceCache, BalanceCache, DEFAULT_SHARD_COUNT, ShardedBalanceCache};
pub use protocol::{
    ActionRequest, ActionType, OrderAction, OrderRequest, OrderResponse, RejectReason,
};
pub use ring::{SpscReceiver, SpscSender, Wakeup, spsc_ring, spsc_ring_with_wakeup};
pub use risk::{RiskConfig, RiskDecision, RiskEngine};

use primitives::fixed::{Price, Qty};
use std::collections::HashMap;
use std::sync::Arc;
use trading::{
    DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderOutcome, OrderType, Side,
    StpMode, TimeInForce,
};

/// The price scale divisor: notional = price * qty / `PRICE_SCALE`.
/// Matches `modules/exchange/src/lib.rs`.
const PRICE_SCALE: u128 = 100_000_000;

/// Settlement arithmetic for a buy order's reservation (C6).
///
/// `reservation` was debited at admission: `limit_price × qty` for
/// limit buys, the ask-ladder sweep bound for market buys — always
/// the WORST CASE the taker could owe. This returns how much of it
/// comes back:
///
/// - Fills cost their ACTUAL execution price (`fill.price`), not the
///   limit — the difference is taker price improvement, refunded
///   here. Each fill's quote is truncated at `/PRICE_SCALE` exactly
///   the way the seller credits are computed, so buyer-out equals
///   seller-in to the unit (no rounding drift).
/// - A `Resting` outcome keeps `limit_price × resting_qty` held —
///   precisely the amount `cancel_order` refunds later, exactly once.
///   The resting remainder IS the reservation; the book is the
///   reservation ledger.
/// - Every other terminal outcome (`Filled`, `Killed`,
///   `CanceledRemainder`, `Rejected`, engine `Err`) holds nothing —
///   an IOC/FOK remainder is dead, not resting, so its reservation
///   comes back in full.
///
/// `saturating_sub` guards the refund against arithmetic drift: a
/// refund can never exceed what was actually debited.
fn buy_reservation_refund(
    reservation: u64,
    limit_price: u64,
    outcome: &OrderOutcome,
    fills: &[FillEvent],
) -> u64 {
    let fill_cost: u64 = fills
        .iter()
        .map(|f| {
            u64::try_from(u128::from(f.price.0) * u128::from(f.qty.0) / PRICE_SCALE)
                .unwrap_or(u64::MAX)
        })
        .sum();
    let held = match outcome {
        OrderOutcome::Resting { resting_qty, .. } => {
            u64::try_from(u128::from(limit_price) * u128::from(resting_qty.0) / PRICE_SCALE)
                .unwrap_or(u64::MAX)
        }
        _ => 0,
    };
    reservation.saturating_sub(fill_cost.saturating_add(held))
}

/// A matched fill with settlement attribution.
#[derive(Debug, Clone, Copy)]
pub struct SettledFill {
    /// Market the fill executed on — included in the on-chain
    /// batch-settle leg so the chain can validate against the
    /// market's config.
    pub market: u16,
    /// Execution price (scale-8).
    pub price: Price,
    /// Traded quantity (scale-6).
    pub qty: Qty,
    /// Buyer address.
    pub buyer: primitives::Address,
    /// Seller address.
    pub seller: primitives::Address,
    /// Quote amount debited from buyer / credited to seller (scale-6)
    /// in the off-chain cache — recorded for reconciliation; the
    /// on-chain batch settles a recomputed amount, not this value.
    pub quote_amount: u64,
}

/// Per-owner nonce tracker — the replay gate at the admission
/// boundary.
///
/// Each admitted order/action carries a nonce strictly greater than
/// the last seen for its owner; anything at-or-below is a replay and
/// is rejected with `StaleNonce`. The nonce is consumed BEFORE any
/// later check fails (same semantics as Ethereum account nonces: a
/// transaction consumes its nonce even if it reverts), so a captured
/// request can never be replayed, including a rejected one.
///
/// `MatchingServer` owns one directly (single writer); the
/// multi-market workers share one `Arc<Mutex<NonceTracker>>` because
/// nonces are per-ACCOUNT, not per-market — an owner trading on
/// market A must not be able to replay the same nonce on market B.
struct NonceTracker {
    /// owner → last consumed nonce.
    last_seen: HashMap<primitives::Address, u64>,
}

impl NonceTracker {
    /// Create an empty tracker.
    fn new() -> Self {
        Self { last_seen: HashMap::new() }
    }

    /// Returns `true` and consumes `nonce` iff it is strictly
    /// greater than the last seen for `owner`; `false` on replay
    /// (the map is not modified). The first request from a new
    /// owner is always accepted.
    fn check_and_consume(&mut self, owner: &primitives::Address, nonce: u64) -> bool {
        if let Some(&last) = self.last_seen.get(owner) {
            if nonce <= last {
                return false;
            }
        }
        self.last_seen.insert(*owner, nonce);
        true
    }
}

/// The core matching server — owns the matching engine, balance
/// cache, and fill buffer. Single-threaded by design (the matching
/// engine takes `&mut self`); protocol adapters feed orders via a
/// channel or call `submit_order` directly.
///
/// # The admission boundary
///
/// `submit_order` / `submit_verified` / `submit_action` are THE
/// mandatory admission points — every wire path (TCP single/batch,
/// JSON-RPC, FIX, WS, ring, multi-market) and every direct caller
/// funnels through them. The sequence is always:
/// `authenticate → replay-check → risk → reserve → match`. There is
/// no public path that skips authentication: [`protocol::VerifiedOrder`]
/// is constructible only by passing [`protocol::verify_order`], and
/// internal resubmits (amend/replace) use the private
/// `execute_order` — safe only because the enclosing signed action
/// was already authenticated.
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
    /// Total requests rejected by authentication (bad signature or
    /// owner not derived from the request's public key).
    auth_rejections: u64,
    /// The pending settlement batch.
    settlement_batch: Vec<SettledFill>,
    /// Per-owner replay gate (see [`NonceTracker`]).
    nonces: NonceTracker,
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
            nonces: NonceTracker::new(),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
            auth_rejections: 0,
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
            nonces: NonceTracker::new(),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
            auth_rejections: 0,
        }
    }

    /// Fund an account with the given quote balance. Called during
    /// setup or when the balance cache is synced from the ledger.
    pub fn fund_account(&mut self, addr: &primitives::Address, amount: u64) {
        self.balances.set(addr, amount);
    }

    /// Get an account's available balance.
    pub fn balance(&self, addr: &primitives::Address) -> u64 {
        self.balances.get(addr)
    }

    /// Submit an order for matching — THE admission boundary for new
    /// orders.
    ///
    /// The pipeline is `authenticate → replay-check → risk → reserve
    /// → match → settle`:
    /// 1. Authentication ([`protocol::verify_order`]): the Ed25519
    ///    signature must verify AND the claimed `owner` must equal
    ///    the address derived from the request's public key.
    /// 2. Replay check: the nonce must be strictly greater than the
    ///    owner's last consumed nonce.
    /// 3. Risk-engine checks (rate limit, size cap, price band,
    ///    resting cap).
    /// 4. Balance reservation (buy orders only).
    /// 5. Matching via `MatchingEngine::place`.
    /// 6. Settlement (update balance cache, accumulate fills).
    ///
    /// Every wire path funnels through here or through
    /// [`Self::submit_verified`] (which only accepts a
    /// [`protocol::VerifiedOrder`] — constructible solely by passing
    /// the same authentication). There is no public path that skips
    /// authentication.
    ///
    /// Returns the order response (filled, resting, or rejected).
    pub fn submit_order(&mut self, req: &OrderRequest) -> OrderResponse {
        if let Some(verified) = protocol::VerifiedOrder::new(*req) {
            self.submit_verified(&verified)
        } else {
            self.auth_rejections += 1;
            OrderResponse::rejected(RejectReason::BadSignature)
        }
    }

    /// Submit an already-authenticated order — the entry point for
    /// ring channels and internal call sites that hold a
    /// [`protocol::VerifiedOrder`] (which can only be constructed by
    /// passing [`protocol::verify_order`], so this path cannot be
    /// reached with a forged order).
    ///
    /// The transport threads authenticate in parallel; this function
    /// performs the remaining boundary steps (replay-check → risk →
    /// reserve → match → settle) on the single matcher thread.
    pub fn submit_verified(&mut self, req: &protocol::VerifiedOrder) -> OrderResponse {
        self.orders_processed += 1;
        let req = req.request();

        // Replay check: each order must carry a nonce strictly
        // greater than the last seen for this owner. A replayed
        // order (same or lower nonce) is rejected with `StaleNonce`
        // before any balance reservation or engine state change.
        // This prevents a captured signed order from being
        // resubmitted. The nonce is consumed even if a later check
        // rejects — a spent nonce can never be replayed (same
        // semantics as Ethereum account nonces).
        if !self.nonces.check_and_consume(&req.owner, req.nonce) {
            return OrderResponse::rejected(RejectReason::StaleNonce);
        }

        self.execute_order(req)
    }

    /// Execute an authenticated, nonce-consumed order: risk →
    /// reserve → match → settle. Private — called by
    /// `submit_verified` and by the internal amend/replace resubmits
    /// (which are authenticated by their enclosing signed action and
    /// must NOT consume a second nonce).
    fn execute_order(&mut self, req: &OrderRequest) -> OrderResponse {
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

        // ── Reservation (buy orders only) ───────────────────────
        // Every buy debits its WORST-CASE quote cost up front:
        // limit buys reserve `price × qty` (fills can only cost
        // less — price improvement is refunded at settlement), and
        // market buys reserve the ask-ladder sweep bound from
        // `sweep_cost` (a market order pays whatever the book
        // charges — skipping this reservation let unfunded takers
        // drain makers, C6). The reservation is released piecewise
        // at settlement via `buy_reservation_refund`: fills pay
        // their actual price, a surviving resting remainder keeps
        // `price × resting_qty` held (exactly what cancel refunds
        // later — once), and dead remainders come back in full.
        let mut reservation = 0u64;
        if req.side == Side::Buy {
            let notional = match req.order_type {
                OrderType::Market => self.engine.sweep_cost(Side::Buy, req.qty.0, None),
                _ => u128::from(req.price.0) * u128::from(req.qty.0),
            };
            let quote_needed = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            let available = self.balances.get(&req.owner);
            if available < quote_needed {
                self.balance_rejections += 1;
                return OrderResponse::rejected(RejectReason::InsufficientBalance);
            }
            self.balances.debit(&req.owner, quote_needed);
            reservation = quote_needed;
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
            // Engine-level error: nothing matched, nothing rests —
            // the whole reservation comes back.
            if reservation > 0 {
                self.balances.credit(&req.owner, reservation);
            }
            return OrderResponse::rejected(RejectReason::EngineError);
        };

        // ── Settle fills ─────────────────────────────────────────
        // For each fill: credit the seller. The buyer's side of the
        // payment comes out of the reservation debited at admission
        // (buy orders) — see `buy_reservation_refund` below. Sell
        // takers simply receive quote; their fills' buyers are
        // resting makers whose own reservations paid at rest.
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
                market: self.engine.config().market_id,
                price: f.price,
                qty: f.qty,
                buyer,
                seller,
                quote_amount,
            });
        }

        // ── Release the reservation (buys) ──────────────────────
        // Everything not consumed by fills (at their actual price)
        // or held for a surviving resting remainder comes back —
        // exactly once. A resting buy keeps `price × resting_qty`
        // locked, which is what `cancel_order` refunds.
        if reservation > 0 {
            let refund = buy_reservation_refund(reservation, req.price.0, &outcome, &self.fills);
            if refund > 0 {
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
                // FOK killed — full reservation already refunded.
                OrderResponse::rejected(RejectReason::Killed)
            }
            OrderOutcome::CanceledRemainder { .. } => {
                // IOC/FOK entry or an STP self-touch: the remainder
                // is DEAD, not resting — no resting counter, and the
                // response must not claim a live order id. Report it
                // as a terminal fill result (partial fills are
                // visible in `fills_count`).
                OrderResponse::filled(fills_count)
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
    ///
    /// # The admission boundary (C5)
    ///
    /// `submit_action` is THE entry point for cancel/amend/replace —
    /// it takes the wire [`ActionRequest`] directly so authentication
    /// can never be skipped: `verify_action` (signature + owner
    /// binding) runs first, then the per-owner nonce check, then
    /// dispatch. The signed action's nonce is consumed here, which
    /// fixes the previous gap where a captured action could be
    /// replayed forever.
    pub fn submit_action(&mut self, req: &ActionRequest) -> OrderResponse {
        self.orders_processed += 1;
        // Authentication gate — identical policy to `submit_order`.
        if !protocol::verify_action(req) {
            self.auth_rejections += 1;
            return OrderResponse::rejected(RejectReason::BadSignature);
        }
        // Replay check on the signed action's nonce — this is the
        // nonce the "cancel/amend drops the signed action nonce"
        // finding referred to: it is now consumed here, before any
        // book mutation.
        if !self.nonces.check_and_consume(&req.owner, req.nonce) {
            return OrderResponse::rejected(RejectReason::StaleNonce);
        }
        let action = protocol::action_request_to_order_action(req);
        self.execute_action(&action)
    }

    /// Dispatch an authenticated, nonce-consumed action to the
    /// matching engine. Private — reachable only via
    /// `submit_action`.
    fn execute_action(&mut self, action: &OrderAction) -> OrderResponse {
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
        //
        // This is an INTERNAL resubmit: the enclosing signed action
        // was already authenticated and its nonce already consumed
        // by `submit_action`, so `execute_order` (which skips
        // authentication and the nonce check) is the correct entry —
        // not `submit_order`, which would (correctly) reject this
        // unsigned synthetic request.
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
        self.execute_order(&req)
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
        // Submit the new order via the internal path: the enclosing
        // signed action was already authenticated and its nonce
        // consumed — the replacement must not re-verify (its
        // signature is the ACTION signature, not an order signature)
        // nor consume a second nonce.
        self.execute_order(new_order)
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

    /// Total requests rejected by authentication — bad signature or
    /// an `owner` not derived from the request's public key.
    pub fn auth_rejections(&self) -> u64 {
        self.auth_rejections
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
            auth_rejections: self.auth_rejections,
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

    /// Submit an order (called by protocol adapters). Authentication
    /// runs inside `MatchingServer::submit_order` — this path can
    /// never admit a forged order.
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
    /// protocol adapters). Takes the wire `ActionRequest` so
    /// authentication runs inside the server — this path can never
    /// admit a forged action.
    ///
    /// Returns an `EngineError` rejection if the internal mutex is
    /// poisoned.
    pub fn submit_action(&self, req: &ActionRequest) -> OrderResponse {
        match self.inner.lock() {
            Ok(mut guard) => guard.submit_action(req),
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
                auth_rejections: s.auth_rejections(),
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
    /// response back via the oneshot channel. The wire
    /// `ActionRequest` travels to the matcher thread so
    /// authentication runs inside `MatchingServer::submit_action` —
    /// the control path can never admit a forged action.
    Action(ActionRequest, std::sync::mpsc::Sender<OrderResponse>),
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
    /// orders (`Vec<VerifiedOrder>`) — one mpsc send per batch, not
    /// per order. This keeps the per-order overhead near zero.
    ///
    /// The ring carries `VerifiedOrder` (proof-of-authentication),
    /// not raw requests: the producer's transport thread runs the
    /// expensive signature check in parallel with other connections,
    /// while the matcher thread trusts the type — a forged order
    /// can never be placed on the ring because `VerifiedOrder` is
    /// constructible only by passing `verify_order`.
    order_rings: Vec<ring::SpscSender<Vec<protocol::VerifiedOrder>>>,
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
        let mut order_senders: Vec<ring::SpscSender<Vec<protocol::VerifiedOrder>>> =
            Vec::with_capacity(num_rings);
        let mut order_receivers: Vec<ring::SpscReceiver<Vec<protocol::VerifiedOrder>>> =
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
                            batch.iter().map(|req| server.submit_verified(req)).collect();
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
                                auth_rejections: server.auth_rejections(),
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
    /// control-channel command to the matcher thread. Takes the wire
    /// `ActionRequest` so authentication runs inside the server's
    /// `submit_action` — this reaches THE SAME order book the rings
    /// write to, and can never admit a forged action.
    ///
    /// Returns an `EngineError` rejection if the control channel is
    /// disconnected (matcher thread died) or the reply fails.
    pub fn submit_action(&self, action: ActionRequest) -> OrderResponse {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self.control_tx.send(ControlCommand::Action(action, reply_tx)).is_err() {
            return OrderResponse::rejected(crate::protocol::RejectReason::EngineError);
        }
        reply_rx
            .recv()
            .unwrap_or_else(|_| OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
    }

    /// Get a connection's order sender (producer side of the order
    /// ring). The caller pushes WHOLE BATCHES of authenticated orders
    /// (`Vec<VerifiedOrder>`) to this ring — one push per batch, not
    /// per order. Only `VerifiedOrder`s can enter the ring, so the
    /// matcher thread never sees an unauthenticated order.
    pub fn order_sender(&self, ring_idx: usize) -> &ring::SpscSender<Vec<protocol::VerifiedOrder>> {
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
    /// Requests rejected by authentication (bad signature or owner
    /// not derived from the request's public key).
    pub auth_rejections: u64,
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
///
/// Orders arrive PRE-AUTHENTICATED: `MultiMarketMatcher::submit_batch`
/// verifies each request on the calling (transport) thread and packs
/// the survivors as [`protocol::VerifiedOrder`] — proof tokens that
/// can only be built by passing `verify_order`. The worker therefore
/// never executes an unauthenticated order AND never pays a second
/// signature verification (signature checks parallelize across the
/// submitting threads).
struct MarketWork {
    /// The authenticated orders (all for this market).
    orders: Vec<protocol::VerifiedOrder>,
    /// One-shot channel for the worker to return the responses.
    response_tx: std::sync::mpsc::Sender<Vec<OrderResponse>>,
}

/// An action work item: a single order action (cancel/amend/replace)
/// routed to the correct market worker. Carries the wire
/// `ActionRequest` so the worker authenticates it inside
/// `MarketWorker::submit_action` — the same boundary as orders.
struct ActionWork {
    /// The wire action request to process.
    action: ActionRequest,
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
    auth_rejections: u64,
    resting_count: u32,
    pending_settlements: usize,
}

/// A multi-market parallel matcher: one worker thread per market,
/// each owning its own `MatchingEngine`, all sharing a single
/// `AtomicBalanceCache` (aliased `ShardedBalanceCache`).
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
///   │ Each worker: │    │ AtomicBalanceCache   │
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
/// (MPSC channel preserves order). Across markets, execution order is
/// non-deterministic (threads run independently), but that's correct
/// — different markets are independent state machines. The one
/// cross-market invariant — per-account nonce ordering — IS
/// deterministic: `submit_batch` consumes nonces in batch order on
/// the calling thread before dispatch (see the `nonces` field).
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
    /// Shared per-account replay gate — the SAME tracker the workers
    /// hold. `submit_batch` consumes nonces HERE (in batch order, on
    /// the calling thread) rather than in the workers: a batch mixing
    /// markets for one account would otherwise have its nonces
    /// consumed by different workers in parallel, making admission
    /// order — and therefore `StaleNonce` vs accept — nondeterministic
    /// within a single call. Consuming at dispatch defines the batch's
    /// submission order as the admission order. (Races ACROSS
    /// concurrent `submit_batch` calls remain, which is correct —
    /// concurrent submissions have no defined order.)
    nonces: Arc<std::sync::Mutex<NonceTracker>>,
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
    pub fn new(configs: Vec<MarketConfig>, balances: Arc<AtomicBalanceCache>) -> Self {
        assert!(!configs.is_empty(), "must have at least one market");
        let num_markets = configs.len();
        let mut market_senders = Vec::with_capacity(num_markets);
        let mut threads = Vec::with_capacity(num_markets);
        // The nonce tracker is SHARED across workers: nonces are
        // per-account, not per-market, so a replayed nonce must be
        // rejected no matter which market it lands on. A short Mutex
        // is acceptable — the check runs once per admission and the
        // work already crosses an MPSC hop.
        let nonces = Arc::new(std::sync::Mutex::new(NonceTracker::new()));

        for cfg in configs {
            let (tx, rx) = std::sync::mpsc::channel::<MarketMessage>();
            let balances = Arc::clone(&balances);
            let nonces = Arc::clone(&nonces);
            let thread = std::thread::spawn(move || {
                MarketWorker::run(cfg, balances, nonces, rx);
            });
            market_senders.push(tx);
            threads.push(thread);
        }

        Self { market_senders, _threads: threads, num_markets, nonces }
    }

    /// Submit a batch of orders. Orders may span markets — each order
    /// is routed to the worker for its own `market` field. Returns
    /// the responses in the same order as the requests.
    ///
    /// Authentication runs HERE — on the calling (transport) thread —
    /// so signature verification parallelizes across submitters.
    /// Each request becomes a [`protocol::VerifiedOrder`] proof token
    /// (unforgeable outside `verify_order`); failed entries get an
    /// aligned `BadSignature` response at their original position and
    /// never reach the worker.
    ///
    /// Routing is by EACH order's market, not the batch head's:
    /// routing every order to `orders[0].market` would silently match
    /// mixed-market batches on the wrong book (the engine does not
    /// re-check the market field — the worker's engine IS the market).
    ///
    /// # Panics
    ///
    /// Panics if `orders` is empty, if any order's `market` is out of
    /// range, or if a market worker thread has died mid-batch.
    pub fn submit_batch(&self, orders: Vec<OrderRequest>) -> Vec<OrderResponse> {
        assert!(!orders.is_empty(), "batch must not be empty");
        // Authenticate + replay-check every order on this thread, IN
        // BATCH ORDER. `positions[i]` records the original index of
        // admitted order i so its response lands in the right slot.
        //
        // The nonce is consumed HERE — before dispatch — because the
        // workers run in parallel: if two same-account orders went to
        // different markets and each worker consumed its nonce on
        // arrival, whichever worker ran first would set the watermark
        // and the other order's result (StaleNonce vs accept) would
        // be nondeterministic within a single call. Consuming in
        // batch order makes the batch's submission order the
        // admission order. Order matters within the sequence:
        // signature verification runs BEFORE the nonce is consumed —
        // a forged request must never burn the victim's next nonce.
        let mut positions: Vec<usize> = Vec::with_capacity(orders.len());
        let mut verified: Vec<protocol::VerifiedOrder> = Vec::with_capacity(orders.len());
        let mut responses: Vec<Option<OrderResponse>> = Vec::with_capacity(orders.len());
        for (i, req) in orders.into_iter().enumerate() {
            match protocol::VerifiedOrder::new(req) {
                Some(vo) => {
                    let ok = match self.nonces.lock() {
                        Ok(mut tracker) => {
                            tracker.check_and_consume(&vo.request().owner, vo.request().nonce)
                        }
                        // A poisoned nonce mutex means a worker panicked
                        // mid-check — fail closed rather than admit a
                        // possible replay.
                        Err(_) => false,
                    };
                    if ok {
                        positions.push(i);
                        verified.push(vo);
                        responses.push(None);
                    } else {
                        responses.push(Some(OrderResponse::rejected(RejectReason::StaleNonce)));
                    }
                }
                None => {
                    responses.push(Some(OrderResponse::rejected(RejectReason::BadSignature)));
                }
            }
        }
        if verified.is_empty() {
            return responses
                .into_iter()
                .map(|r| r.unwrap_or_else(|| OrderResponse::rejected(RejectReason::EngineError)))
                .collect();
        }

        let first_market = usize::from(verified[0].request().market);
        if verified.iter().all(|v| usize::from(v.request().market) == first_market) {
            // Fast path: single market — one send, one recv, no
            // per-market grouping allocation.
            assert!(
                first_market < self.num_markets,
                "market {first_market} out of range (have {} markets)",
                self.num_markets
            );
            let (response_tx, response_rx) = std::sync::mpsc::channel();
            if self.market_senders[first_market]
                .send(MarketMessage::Work(MarketWork { orders: verified, response_tx }))
                .is_err()
            {
                return vec![OrderResponse::rejected(RejectReason::EngineError); 1];
            }
            let worker_responses = response_rx
                .recv()
                .unwrap_or_else(|_| vec![OrderResponse::rejected(RejectReason::EngineError); 1]);
            for (pos, resp) in positions.into_iter().zip(worker_responses) {
                responses[pos] = Some(resp);
            }
        } else {
            // Slow path: mixed markets — split verified orders by
            // market, dispatch every group BEFORE blocking on any
            // response channel so the workers run in parallel, then
            // merge each worker's responses by original batch index.
            // `by_market[m]` holds (orig_pos, order) pairs. Indexed by
            // market rather than a HashMap: `num_markets` is bounded
            // (u8) and the mixed path is already the rare path.
            let mut by_market: Vec<Vec<(usize, protocol::VerifiedOrder)>> =
                (0..self.num_markets).map(|_| Vec::new()).collect();
            for (pos, vo) in positions.iter().copied().zip(verified) {
                let m = usize::from(vo.request().market);
                assert!(
                    m < self.num_markets,
                    "market {m} out of range (have {} markets)",
                    self.num_markets
                );
                by_market[m].push((pos, vo));
            }
            let mut receivers = Vec::new();
            for (m, group) in by_market.into_iter().enumerate() {
                if group.is_empty() {
                    continue;
                }
                let (idxs, group_orders): (Vec<usize>, Vec<protocol::VerifiedOrder>) =
                    group.into_iter().unzip();
                let (response_tx, response_rx) = std::sync::mpsc::channel();
                if self.market_senders[m]
                    .send(MarketMessage::Work(MarketWork { orders: group_orders, response_tx }))
                    .is_err()
                {
                    for pos in idxs {
                        responses[pos] = Some(OrderResponse::rejected(RejectReason::EngineError));
                    }
                    continue;
                }
                receivers.push((idxs, response_rx));
            }
            for (idxs, rx) in receivers {
                let n = idxs.len();
                let worker_responses = rx.recv().unwrap_or_else(|_| {
                    vec![OrderResponse::rejected(RejectReason::EngineError); n]
                });
                for (pos, resp) in idxs.into_iter().zip(worker_responses) {
                    responses[pos] = Some(resp);
                }
            }
        }
        // Every slot is Some: verified entries got worker responses,
        // unverified got BadSignature at submit time.
        responses
            .into_iter()
            .map(|r| r.unwrap_or_else(|| OrderResponse::rejected(RejectReason::EngineError)))
            .collect()
    }

    /// Submit a single order. Routes to the correct market worker.
    ///
    /// Returns an `EngineError` rejection if the market worker thread
    /// has died.
    pub fn submit_one(&self, order: OrderRequest) -> OrderResponse {
        let mut responses = self.submit_batch(vec![order]);
        responses.pop().unwrap_or_else(|| OrderResponse::rejected(RejectReason::EngineError))
    }

    /// Submit an order action (cancel/amend/replace). Takes the wire
    /// `ActionRequest` so the worker authenticates it inside
    /// `MarketWorker::submit_action` — the same mandatory boundary as
    /// order admission. Routes to market 0 (the v0 action protocol
    /// is single-market; the wire format carries no market field).
    ///
    /// Returns an `EngineError` rejection if the market worker thread
    /// has died.
    pub fn submit_action(&self, action: &ActionRequest) -> OrderResponse {
        // v0: all actions route to market 0 — the wire `ActionRequest`
        // has no market field (multi-market routing is future work).
        let market = 0;
        if market >= self.num_markets {
            return OrderResponse::rejected(RejectReason::EngineError);
        }
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        if self.market_senders[market]
            .send(MarketMessage::Action(ActionWork { action: *action, response_tx }))
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
                total.auth_rejections += s.auth_rejections;
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
///
/// The worker enforces the SAME admission boundary as
/// `MatchingServer`: orders arrive pre-authenticated as
/// [`protocol::VerifiedOrder`] (signature + owner binding already
/// checked on the submitting thread), then the worker runs the
/// remaining steps — replay-check → risk → reserve → match — using
/// the SHARED nonce tracker (nonces are per-account across all
/// markets) and a per-market risk engine. Actions arrive as wire
/// `ActionRequest`s and are authenticated inside `submit_action`.
struct MarketWorker {
    /// The matching engine for this market (single-writer).
    engine: MatchingEngine,
    /// Shared sharded balance cache (cross-market).
    balances: Arc<AtomicBalanceCache>,
    /// Shared per-account replay gate — one sequence per owner
    /// across ALL markets (see `NonceTracker`).
    nonces: Arc<std::sync::Mutex<NonceTracker>>,
    /// Per-market risk engine (rate limits, fat-finger, size caps).
    /// Per-market rather than shared: an account's rate/resting
    /// budget is scoped to this market's book.
    risk: RiskEngine,
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
    /// Total orders rejected by the risk engine.
    risk_rejections: u64,
    /// Total requests rejected by authentication.
    auth_rejections: u64,
}

impl MarketWorker {
    /// The worker loop: receive messages (work or control), process
    /// them. Blocks on the single channel — no polling, no missed
    /// control commands.
    fn run(
        cfg: MarketConfig,
        balances: Arc<AtomicBalanceCache>,
        nonces: Arc<std::sync::Mutex<NonceTracker>>,
        rx: std::sync::mpsc::Receiver<MarketMessage>,
    ) {
        let engine = MatchingEngine::new(cfg, DenseBook::new(cfg).expect("book creation"))
            .expect("engine creation");
        let mut worker = MarketWorker {
            engine,
            balances,
            nonces,
            risk: RiskEngine::with_defaults(),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(10_000),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
            auth_rejections: 0,
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
                        risk_rejections: worker.risk_rejections,
                        auth_rejections: worker.auth_rejections,
                        resting_count: worker.engine.resting_count(),
                        pending_settlements: worker.settlement_batch.len(),
                    };
                    let _ = reply.send(stats);
                }
                Err(_) => break, // All senders dropped — shutdown.
            }
        }
    }

    /// Process a batch of authenticated orders for this market.
    /// Returns responses in the same order as the requests.
    fn process_batch(&mut self, orders: &[protocol::VerifiedOrder]) -> Vec<OrderResponse> {
        let mut responses = Vec::with_capacity(orders.len());
        for req in orders {
            responses.push(self.submit_verified(req));
        }
        responses
    }

    /// Check the shared nonce for `owner`/`nonce` — returns `false`
    /// on replay. One lock acquisition per admission.
    fn check_nonce(&self, owner: &primitives::Address, nonce: u64) -> bool {
        match self.nonces.lock() {
            Ok(mut tracker) => tracker.check_and_consume(owner, nonce),
            // A poisoned nonce mutex means a worker panicked
            // mid-check — the tracker may be inconsistent. Fail
            // closed: reject rather than admit a possible replay.
            Err(_) => false,
        }
    }

    /// Submit one authenticated, nonce-consumed order: risk →
    /// reserve → match → settle. The replay check already ran on the
    /// dispatching thread inside `MultiMarketMatcher::submit_batch`
    /// (in batch order — see that function's comment for why the
    /// consume cannot happen here: parallel workers would make
    /// cross-market admission order nondeterministic). `VerifiedOrder`
    /// can only arrive via `MarketWork`, which `submit_batch` builds
    /// exclusively — the worker boundary cannot be reached without
    /// passing authentication AND nonce consumption.
    fn submit_verified(&mut self, req: &protocol::VerifiedOrder) -> OrderResponse {
        self.orders_processed += 1;
        self.execute_order(req.request())
    }

    /// Execute an authenticated, nonce-consumed order: risk →
    /// reserve → match → settle. Private — also used by the internal
    /// amend/replace resubmits (authenticated by their enclosing
    /// signed action).
    fn execute_order(&mut self, req: &OrderRequest) -> OrderResponse {
        // ── Risk-engine checks ───────────────────────────────────
        // Per-market risk engine: rate limit, size cap, price band,
        // resting cap. Mirrors `MatchingServer::execute_order`.
        let mid = match (self.engine.best_bid(), self.engine.best_ask()) {
            (Some((bid, _)), Some((ask, _))) => u64::midpoint(bid.0, ask.0),
            _ => 0,
        };
        let now_ms = self.orders_processed; // deterministic stand-in
        if let RiskDecision::Reject(reason) =
            self.risk.check(&req.owner, now_ms, req.price.0, req.qty.0, mid)
        {
            self.risk_rejections += 1;
            return OrderResponse::rejected(reason);
        }

        // ── Reservation (buy orders only) ───────────────────────
        // Same accounting as `MatchingServer::execute_order`: limit
        // buys reserve `price × qty`, market buys reserve the
        // ask-ladder sweep bound (`sweep_cost`). Atomic
        // check-and-debit under the shard lock — no TOCTOU race
        // even if another market trades this account.
        let mut reservation = 0u64;
        if req.side == Side::Buy {
            let notional = match req.order_type {
                OrderType::Market => self.engine.sweep_cost(Side::Buy, req.qty.0, None),
                _ => u128::from(req.price.0) * u128::from(req.qty.0),
            };
            let quote_needed = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            if !self.balances.check_and_debit(&req.owner, quote_needed) {
                self.balance_rejections += 1;
                return OrderResponse::rejected(RejectReason::InsufficientBalance);
            }
            reservation = quote_needed;
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
            // Engine-level error: nothing matched, nothing rests —
            // the whole reservation comes back.
            if reservation > 0 {
                self.balances.credit(&req.owner, reservation);
            }
            return OrderResponse::rejected(RejectReason::EngineError);
        };

        // ── Settle fills ─────────────────────────────────────────
        // Credit the seller for each fill (cross-shard if needed).
        // The buyer's payment comes out of the reservation debited
        // at admission — released piecewise below via
        // `buy_reservation_refund`.
        for f in &self.fills {
            self.fills_produced += 1;
            let notional = u128::from(f.price.0) * u128::from(f.qty.0);
            let quote_amount = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            let (buyer, seller) = if f.taker_side == Side::Buy {
                (f.taker_owner, f.maker_owner)
            } else {
                (f.maker_owner, f.taker_owner)
            };
            self.balances.credit(&seller, quote_amount);
            // Accumulate for batch settlement.
            self.settlement_batch.push(SettledFill {
                market: self.engine.config().market_id,
                price: f.price,
                qty: f.qty,
                buyer,
                seller,
                quote_amount,
            });
        }

        // ── Release the reservation (buys) ──────────────────────
        // Fills pay their actual price (improvement refunded), a
        // surviving resting remainder keeps `price × resting_qty`
        // held (exactly what cancel refunds — once), dead
        // remainders come back in full.
        if reservation > 0 {
            let refund = buy_reservation_refund(reservation, req.price.0, &outcome, &self.fills);
            if refund > 0 {
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
            OrderOutcome::CanceledRemainder { .. } => {
                // IOC/FOK entry or STP self-touch: the remainder is
                // DEAD, not resting — no resting counter, and the
                // response must not claim a live order id.
                OrderResponse::filled(fills_count)
            }
            OrderOutcome::Killed => OrderResponse::rejected(RejectReason::Killed),
            OrderOutcome::Rejected(_) => {
                self.engine_rejections += 1;
                OrderResponse::rejected(RejectReason::EngineRejected)
            }
        }
    }

    /// Submit an order action (cancel/amend/replace). Takes the wire
    /// `ActionRequest` — the SAME mandatory boundary as
    /// `MatchingServer::submit_action`: `verify_action` (signature +
    /// owner binding) → shared nonce check → dispatch.
    fn submit_action(&mut self, req: &ActionRequest) -> OrderResponse {
        self.orders_processed += 1;
        if !protocol::verify_action(req) {
            self.auth_rejections += 1;
            return OrderResponse::rejected(RejectReason::BadSignature);
        }
        if !self.check_nonce(&req.owner, req.nonce) {
            return OrderResponse::rejected(RejectReason::StaleNonce);
        }
        let action = protocol::action_request_to_order_action(req);
        self.execute_action(&action)
    }

    /// Dispatch an authenticated, nonce-consumed action. Private —
    /// reachable only via `submit_action`.
    fn execute_action(&mut self, action: &OrderAction) -> OrderResponse {
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
        self.risk.dec_resting(&canceled.owner);
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
        self.risk.dec_resting(&canceled.owner);
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
        // Internal resubmit — authenticated by the enclosing action.
        self.execute_order(&req)
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
        self.risk.dec_resting(&canceled.owner);
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        // Internal resubmit — authenticated by the enclosing action.
        self.execute_order(new_order)
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

    /// A deterministic test account: `seed` derives the Ed25519
    /// signing key; the account address is the key's derived owner.
    fn test_account(seed: u8) -> (crypto::ed25519::Ed25519SecretKey, primitives::Address) {
        let secret = crypto::ed25519::Ed25519SecretKey::from_bytes(&[seed; 32]);
        let owner = crypto::ed25519::owner_address(&secret.verifying_key());
        (secret, owner)
    }

    /// Build a signed order for `secret`'s account.
    fn signed_req(
        secret: &crypto::ed25519::Ed25519SecretKey,
        market: u8,
        side: Side,
        nonce: u64,
        price: u64,
        qty: u64,
    ) -> OrderRequest {
        let mut req = OrderRequest {
            market,
            side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(price),
            qty: Qty(qty),
            nonce,
            owner: addr(0),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        crate::protocol::sign_order(&mut req, secret);
        req
    }

    /// Build a signed action for `secret`'s account.
    fn signed_action(
        secret: &crypto::ed25519::Ed25519SecretKey,
        action_type: ActionType,
        order_id: u64,
        nonce: u64,
    ) -> ActionRequest {
        let mut req = ActionRequest {
            action_type,
            order_id,
            new_price: Price(0),
            new_qty: Qty(0),
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            nonce,
            owner: addr(0),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        crate::protocol::sign_action(&mut req, secret);
        req
    }

    // ── C5 regression tests: the mandatory admission boundary ──────

    /// Regression (C5): `submit_order` used to execute orders with
    /// no signature verification at all — the binary-TCP single
    /// order path, JSON-RPC, FIX, and WS all submitted unverified
    /// requests. An unsigned (zero-signature) order must be rejected
    /// with `BadSignature` before any nonce/balance/book state
    /// changes.
    #[test]
    fn unsigned_order_rejected_with_bad_signature() {
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&addr(1), 1_000_000_000);

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
        assert!(resp.rejected, "unsigned order must be rejected");
        assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
        assert_eq!(server.resting_count(), 0, "no order may reach the book");
    }

    /// Regression (C5): a validly-signed order whose `owner` is NOT
    /// derived from the signing key must be rejected — the signature
    /// alone does not prove the key controls the claimed account.
    #[test]
    fn signed_order_with_foreign_owner_rejected() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (secret, _) = test_account(1);
        server.fund_account(&addr(0x77), 1_000_000_000); // the victim

        // Attacker signs a real order but claims the victim's owner.
        let mut req = signed_req(&secret, 0, Side::Buy, 1, 1_500_000_000, 1_000);
        req.owner = addr(0x77);
        // Re-sign so the signature covers the claimed owner verbatim —
        // this is the attack the owner-binding check exists to stop.
        let msg = crate::protocol::signing_message(&req);
        req.signature = crypto::ed25519::sign_message(&secret, &msg).to_bytes();

        let resp = server.submit_order(&req);
        assert!(resp.rejected);
        assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
        assert_eq!(server.balance(&addr(0x77)), 1_000_000_000, "victim balance untouched");
    }

    /// A properly signed order (owner derived from the key) passes
    /// the boundary and matches.
    #[test]
    fn signed_order_accepted_and_matched() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, _seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&buyer, 1_000_000_000);

        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&taker);
        assert!(!resp.rejected, "authentic order must be admitted");
        assert_eq!(resp.fills_count, 1);
        assert_eq!(server.balance(&buyer), 1_000_000_000 - 15_000);
    }

    /// Regression (C5): actions (cancel/amend/replace) were admitted
    /// without any nonce check — a captured signed action replayed
    /// forever. The same action nonce must be rejected as stale.
    #[test]
    fn replayed_action_nonce_rejected() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        server.fund_account(&seller, 0);

        // Rest a sell order so there is something to cancel.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&maker);
        assert!(!resp.rejected);
        let order_id = resp.order_id;
        assert_eq!(server.resting_count(), 1);

        // Cancel with nonce 1 — accepted.
        let cancel = signed_action(&seller_sk, ActionType::Cancel, order_id, 1);
        let resp = server.submit_action(&cancel);
        assert!(!resp.rejected, "first cancel must be admitted");

        // Rest a second order; replay the same cancel request
        // (same nonce) — must be rejected as stale, and the second
        // order must NOT be canceled.
        let maker2 = signed_req(&seller_sk, 0, Side::Sell, 2, 1_500_000_000, 1_000);
        let resp2 = server.submit_order(&maker2);
        assert!(!resp2.rejected);

        let replay = signed_action(&seller_sk, ActionType::Cancel, resp2.order_id, 1);
        let replay_resp = server.submit_action(&replay);
        assert!(replay_resp.rejected, "replayed action nonce must be rejected");
        assert_eq!(replay_resp.reject_reason, Some(RejectReason::StaleNonce));
        assert_eq!(server.resting_count(), 1, "second order must still be resting");
    }

    /// Regression (C5): an action with a bad signature must be
    /// rejected at the boundary — today `submit_action` took an
    /// `OrderAction` (already stripped of signature) so forged
    /// cancels could reach the engine directly.
    #[test]
    fn unsigned_action_rejected_with_bad_signature() {
        let mut server = MatchingServer::new(cfg(), 100);
        let req = ActionRequest {
            action_type: ActionType::Cancel,
            order_id: 1,
            new_price: Price(0),
            new_qty: Qty(0),
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            nonce: 0,
            owner: addr(1),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let resp = server.submit_action(&req);
        assert!(resp.rejected);
        assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
    }

    #[test]
    fn buy_order_rejected_with_insufficient_balance() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&buyer, 1_000); // Not enough for 5 lots at $15.

        let req = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 5_000);

        let resp = server.submit_order(&req);
        assert!(resp.rejected, "should reject insufficient balance");
        assert_eq!(resp.reject_reason, Some(RejectReason::InsufficientBalance));
        assert_eq!(server.balance(&buyer), 1_000, "balance unchanged");
    }

    #[test]
    fn buy_order_accepted_with_sufficient_balance() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 1_000_000_000);

        // Rest a maker sell.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);

        // Taker buy — should match the maker.
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&taker);
        assert!(!resp.rejected, "should accept sufficient balance");
        assert_eq!(resp.fills_count, 1, "should have one fill");
        // Notional = 1_500_000_000 * 1_000 / 100_000_000 = 15_000.
        assert_eq!(server.balance(&buyer), 1_000_000_000 - 15_000);
        assert_eq!(server.balance(&seller), 1_000_000_000 + 15_000);
    }

    /// Regression test (C7): a replayed order (same nonce from the
    /// same owner) must be rejected with `StaleNonce`. Before the
    /// fix, the matcher ignored the protocol nonce field — signed
    /// orders could be replayed indefinitely.
    #[test]
    fn replayed_order_rejected_with_stale_nonce() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&buyer, 1_000_000_000);

        let req = signed_req(&buyer_sk, 0, Side::Buy, 42, 1_500_000_000, 1_000);

        // First submission: accepted (nonce 42 is new).
        let resp = server.submit_order(&req);
        assert!(!resp.rejected, "first order with new nonce must be accepted");

        // Replay: same nonce, same owner — must be rejected.
        let replay = server.submit_order(&req);
        assert!(replay.rejected, "replayed order must be rejected");
        assert_eq!(
            replay.reject_reason,
            Some(RejectReason::StaleNonce),
            "replay must be rejected with StaleNonce"
        );

        // Higher nonce: accepted.
        let req2 = signed_req(&buyer_sk, 0, Side::Buy, 43, 1_500_000_000, 1_000);
        let resp2 = server.submit_order(&req2);
        assert!(!resp2.rejected, "order with higher nonce must be accepted");
    }

    #[test]
    fn spam_orders_rejected_without_balance() {
        let risk_cfg = RiskConfig {
            max_orders_per_second: 0,
            max_order_qty: 0,
            max_price_deviation_bps: 0,
            max_resting_per_account: 0,
        };
        let mut server = MatchingServer::with_risk_config(cfg(), 100, risk_cfg);
        let (buyer_sk, _buyer) = test_account(1);

        // Submit 1000 signed buy orders with zero balance — all
        // should be rejected at the balance check (they pass
        // authentication and the nonce gate, then fail reservation).
        for i in 0..1000u64 {
            let req = signed_req(&buyer_sk, 0, Side::Buy, i, 1_500_000_000, 1_000);
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
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 1_000_000_000);
        let ring = RingMatcher::new(server, 4, 1024);

        // Push a maker sell + taker buy as one batch through ring 0.
        // The ring only accepts `VerifiedOrder` proofs — transport
        // threads authenticate, the matcher thread never sees a raw
        // unauthenticated request.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let verified: Vec<crate::protocol::VerifiedOrder> = [maker, taker]
            .into_iter()
            .map(|req| crate::protocol::VerifiedOrder::new(req).expect("signed orders must verify"))
            .collect();
        let sender = ring.order_sender(0);
        let receiver = ring.response_receiver(0);
        let mut batch = verified;
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
        assert_eq!(fills[0].buyer, buyer);
        assert_eq!(fills[0].seller, seller);

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
        // are independent. Nonces are also shared (per-ACCOUNT, not
        // per-market): each account's nonces must increase across
        // markets.
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000);
        balances.set(&buyer, 1_000_000_000);
        let configs = vec![cfg_for(0), cfg_for(1)];
        let matcher = MultiMarketMatcher::new(configs, balances);

        // Market 0: rest a maker sell, then a taker buy fills it.
        let maker0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let taker0 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let responses = matcher.submit_batch(vec![maker0, taker0]);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[1].fills_count, 1, "market 0 taker should fill");

        // Market 1: same pair, independent book — should also fill.
        // Nonces continue per account (seller 1, buyer 1).
        let maker1 = signed_req(&seller_sk, 1, Side::Sell, 1, 1_600_000_000, 1_000);
        let taker1 = signed_req(&buyer_sk, 1, Side::Buy, 1, 1_600_000_000, 1_000);
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
        // The buyer has exactly 15_000 quote (enough for ONE fill at
        // $15 × 1000 qty). Two markets try to debit simultaneously —
        // only one should succeed.
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000); // Seller (funded).
        balances.set(&buyer, 15_000); // Buyer: exactly one fill's worth.
        let configs = vec![cfg_for(0), cfg_for(1)];
        let matcher = MultiMarketMatcher::new(configs, balances);

        // Rest maker sells on both markets (seller nonces 0, 1 —
        // shared per-account nonce tracker across markets).
        let maker0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let maker1 = signed_req(&seller_sk, 1, Side::Sell, 1, 1_500_000_000, 1_000);
        matcher.submit_batch(vec![maker0]);
        matcher.submit_batch(vec![maker1]);

        // Submit taker buys on both markets (same buyer, same
        // balance; buyer nonces 0, 1).
        let taker0 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let taker1 = signed_req(&buyer_sk, 1, Side::Buy, 1, 1_500_000_000, 1_000);
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

    /// Regression (C5): a batch with a bad-signature order between
    /// two valid orders must produce aligned responses —
    /// `[good, bad, good]` → `[result0, BadSignature, result1]`.
    /// The pre-fix transport filtered valid requests and prepended
    /// rejections, yielding `[BadSignature, result0, result1]` and
    /// misattributing every response after the bad entry.
    #[test]
    fn multi_market_batch_preserves_positions_with_bad_signature() {
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000);
        balances.set(&buyer, 1_000_000_000);
        let configs = vec![cfg_for(0), cfg_for(1)];
        let matcher = MultiMarketMatcher::new(configs, balances);

        let good0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        // A forged order: zero signature/pubkey — fails verify_order
        // outright regardless of the claimed owner.
        let bad = OrderRequest {
            market: 0,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            nonce: 0,
            owner: seller,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let good1 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);

        // The interleaved case: [good sell, forged, good buy].
        let responses = matcher.submit_batch(vec![good0, bad, good1]);
        assert_eq!(responses.len(), 3);
        assert!(!responses[0].rejected, "index 0 (good sell) must rest");
        assert!(responses[1].rejected, "index 1 (forged) must be rejected");
        assert_eq!(
            responses[1].reject_reason,
            Some(RejectReason::BadSignature),
            "the middle slot gets BadSignature at its own position"
        );
        assert_eq!(
            responses[2].fills_count, 1,
            "index 2 (good buy) fills against the resting sell"
        );
    }

    // ── C6 regression tests: reservation accounting ─────────────

    /// Regression (C6): a resting buy's reservation must STAY debited
    /// while the order rests. The old code refunded `price * unfilled`
    /// immediately — including the resting quantity — then `cancel`
    /// refunded it again, minting balance out of nothing (buy at
    /// `15_000`, cancel, end with `15_000` MORE than started).
    #[test]
    fn resting_buy_reservation_released_exactly_once() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&buyer, 100_000);

        // GTC limit buy, nothing to match against — rests.
        let req = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&req);
        assert!(!resp.rejected, "buy should rest");

        // Reservation = 1.5e9 * 1_000 / 1e8 = 15_000. The balance
        // must show the reservation is STILL held — if this shows
        // 100_000, the cancel below will refund a second time.
        let after_rest = server.balances.get(&buyer);
        assert_eq!(
            after_rest,
            100_000 - 15_000,
            "resting reservation must remain debited (got {after_rest})"
        );

        // Cancel via a signed action (nonce 1).
        let cancel = signed_action(&buyer_sk, ActionType::Cancel, resp.order_id, 1);
        let resp2 = server.submit_action(&cancel);
        assert!(!resp2.rejected, "cancel should succeed");

        // Conservation: started with 100_000, traded nothing —
        // must end with exactly 100_000. The double-refund bug
        // leaves 115_000.
        assert_eq!(
            server.balances.get(&buyer),
            100_000,
            "cancel must refund the reservation exactly once"
        );
    }

    /// Regression (C6): price improvement must be refunded. A taker
    /// limit buy debited at its LIMIT price but filled at a BETTER
    /// maker price keeps the difference today — the reservation
    /// silently overcharges the taker.
    #[test]
    fn price_improvement_is_refunded_to_taker() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 100_000);

        // Maker rests a sell at 1.5e9.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);

        // Taker buys with a 1.6e9 limit — fills at the maker's 1.5e9.
        // Reservation debits 16_000; actual cost 15_000.
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_600_000_000, 1_000);
        let resp = server.submit_order(&taker);
        assert_eq!(resp.fills_count, 1, "taker should fill at maker price");

        // The 1_000 improvement must come back.
        assert_eq!(
            server.balances.get(&buyer),
            100_000 - 15_000,
            "taker pays the fill price, not the limit price"
        );
        assert_eq!(
            server.balances.get(&seller),
            1_000_000_000 + 15_000,
            "seller receives the fill price"
        );
    }

    /// Regression (C6): market buys were never reserved — the
    /// `!= Market` guard skipped the debit while fills still
    /// credited sellers, minting quote on every market sweep.
    /// An unfunded market buy must reject BEFORE touching the book;
    /// a funded one must pay the actual sweep cost.
    #[test]
    fn market_buy_reserves_sweep_cost_and_settles() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (poor_sk, poor) = test_account(2);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&poor, 0);
        server.fund_account(&buyer, 100_000);

        // Maker rests a sell at 1.5e9.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);

        // Unfunded market buy: must reject WITHOUT consuming the
        // resting order.
        let mut poor_req = signed_req(&poor_sk, 0, Side::Buy, 0, 0, 1_000);
        poor_req.order_type = OrderType::Market;
        poor_req.tif = TimeInForce::Ioc; // Market requires Ioc.
        poor_req.price = Price(0);
        // Re-sign after mutation (signature covers price/type).
        crate::protocol::sign_order(&mut poor_req, &poor_sk);
        let resp = server.submit_order(&poor_req);
        assert!(resp.rejected, "unfunded market buy must reject");
        assert_eq!(resp.reject_reason, Some(RejectReason::InsufficientBalance));
        assert_eq!(server.resting_count(), 1, "the resting maker must survive a rejected sweep");

        // Funded market buy: pays the actual sweep cost (15_000).
        let mut mkt = signed_req(&buyer_sk, 0, Side::Buy, 0, 0, 1_000);
        mkt.order_type = OrderType::Market;
        mkt.tif = TimeInForce::Ioc;
        mkt.price = Price(0);
        crate::protocol::sign_order(&mut mkt, &buyer_sk);
        let resp = server.submit_order(&mkt);
        assert_eq!(resp.fills_count, 1, "market buy should sweep the ask");
        assert_eq!(
            server.balances.get(&buyer),
            100_000 - 15_000,
            "market taker pays the real fill cost"
        );
        assert_eq!(server.balances.get(&seller), 1_000_000_000 + 15_000);
    }

    /// Regression (C6): an IOC/FOK remainder is DEAD — it must not be
    /// counted or reported as resting. `CanceledRemainder` was
    /// mapped to `OrderResponse::resting` + `inc_resting`, inflating
    /// the resting cap and telling the client a dead order is live.
    #[test]
    fn ioc_remainder_does_not_rest() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 100_000);

        // Maker sells 1_000 (one lot); taker IOC buys 2_000 — fills
        // 1_000, the remaining 1_000 must die, not rest.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);

        let mut ioc = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 2_000);
        ioc.tif = TimeInForce::Ioc;
        crate::protocol::sign_order(&mut ioc, &buyer_sk);
        let resp = server.submit_order(&ioc);
        assert!(!resp.rejected);
        assert_eq!(resp.fills_count, 1, "IOC fills the 1_000 available");

        // The book must be empty and the resting counter at zero —
        // the remainder was canceled by IOC semantics.
        assert_eq!(server.resting_count(), 0, "IOC remainder must not rest");

        // Reservation: debited 30_000, paid 15_000, remainder dead
        // → 15_000 refunded (nothing stays reserved).
        assert_eq!(
            server.balances.get(&buyer),
            100_000 - 15_000,
            "dead remainder's reservation is fully refunded"
        );
    }

    /// Regression (C6): a partially-filled buy that then rests holds
    /// reservation ONLY for the resting remainder — and cancel
    /// refunds exactly that, once.
    #[test]
    fn partial_fill_buy_holds_only_remainder_reservation() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 100_000);

        // Maker sells 1_000; taker GTC buys 2_000 — fills 1_000,
        // rests 1_000.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 2_000);
        let resp = server.submit_order(&taker);
        assert_eq!(resp.fills_count, 1);

        // Paid 1_000×15 = 15_000; still holds 1_000×15 = 15_000 reserved.
        assert_eq!(
            server.balances.get(&buyer),
            100_000 - 15_000 - 15_000,
            "paid fills + held remainder reservation"
        );

        // Cancel the remainder: 15_000 comes back exactly once.
        let cancel = signed_action(&buyer_sk, ActionType::Cancel, resp.order_id, 1);
        server.submit_action(&cancel);
        assert_eq!(server.balances.get(&buyer), 100_000 - 15_000);
    }

    /// Regression (C5): `submit_batch` must route each verified order
    /// by ITS OWN `market` field — not `orders[0].market`. The pre-fix
    /// code sent the whole batch to the head order's worker, silently
    /// matching mixed-market batches on the wrong book. Distinct
    /// price bands make misrouting observable: market 1's price is
    /// out of band on market 0's engine, so a misrouted order would
    /// be rejected instead of filling.
    #[test]
    fn multi_market_batch_routes_by_each_orders_market() {
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000);
        balances.set(&buyer, 1_000_000_000);
        // Market 0 band: [1e9, 2e9]. Market 1 band: [3e9, 4e9] — no
        // overlap, so a market-1 order landing on market 0's engine
        // is rejected by price-band validation.
        let mut cfg0 = cfg_for(0);
        cfg0.min_price = 1_000_000_000;
        cfg0.max_price = 2_000_000_000;
        let mut cfg1 = cfg_for(1);
        cfg1.min_price = 3_000_000_000;
        cfg1.max_price = 4_000_000_000;
        let matcher = MultiMarketMatcher::new(vec![cfg0, cfg1], balances);

        // One mixed batch: market-1 orders INTERLEAVED after the
        // market-0 head. If routed by orders[0].market, both market-1
        // orders hit the [1e9,2e9] engine and are rejected.
        let orders = vec![
            signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000),
            signed_req(&seller_sk, 1, Side::Sell, 1, 3_500_000_000, 1_000),
            signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000),
            signed_req(&buyer_sk, 1, Side::Buy, 1, 3_500_000_000, 1_000),
        ];
        let responses = matcher.submit_batch(orders);
        assert_eq!(responses.len(), 4);
        assert!(
            !responses[0].rejected,
            "market-0 maker rests, got {:?}",
            responses[0].reject_reason
        );
        assert!(
            !responses[1].rejected,
            "market-1 maker must reach market 1's engine (its 3.5e9 \
             price is out of band on market 0 — a misroute would reject)"
        );
        assert_eq!(
            responses[2].fills_count, 1,
            "market-0 taker fills (rejected={} reason={:?})",
            responses[2].rejected, responses[2].reject_reason
        );
        assert_eq!(
            responses[3].fills_count, 1,
            "market-1 taker fills (rejected={} reason={:?})",
            responses[3].rejected, responses[3].reject_reason
        );

        let fills = matcher.seal_batch();
        assert_eq!(fills.len(), 2, "one fill per market");
    }
}
