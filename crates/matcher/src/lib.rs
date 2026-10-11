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
pub mod settler;
pub mod ws;

pub use balance::{AtomicBalanceCache, BalanceCache, DEFAULT_SHARD_COUNT, ShardedBalanceCache};
pub use protocol::{
    ActionRequest, ActionType, OrderAction, OrderRequest, OrderResponse, RejectReason,
};
pub use ring::{SequencerIdle, SpscReceiver, SpscSender, Wakeup, spsc_ring, spsc_ring_with_wakeup};
pub use risk::{RiskConfig, RiskDecision, RiskEngine};

mod multimarket;
mod nonce_wal;
mod settlement;

pub use multimarket::MultiMarketMatcher;

use primitives::fixed::{Price, Qty};
use std::collections::HashMap;
use std::sync::Arc;
use trading::{
    DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderOutcome, OrderType, Side,
    StpMode, TimeInForce,
};

pub use settlement::SettledFill;
pub(crate) use settlement::{
    LegCostAcc, LegId, NonceTracker, PRICE_SCALE, buy_reservation_refund, evict_gone_client_ids,
    fill_parties, gone_makers,
};

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
    /// Marginal per-leg cost accumulator — credits/charges deltas
    /// that telescope to the chain's merged-leg floors. Cleared by
    /// `seal_batch` (the same boundary the batch drains at).
    cost_acc: LegCostAcc,
    /// Per-owner replay gate (see [`NonceTracker`]).
    nonces: NonceTracker,
    /// Book order id → the client order id (request nonce) of the
    /// owner who placed it — kept for every resting order so a fill
    /// can carry the `(owner, client_id)` key the on-chain
    /// registered-order authorization model settles against.
    /// Entries are inserted when an order rests and evicted when it
    /// leaves the book (filled, cancelled, or removed).
    order_client_ids: HashMap<u64, u64>,
    /// Millisecond time source for the rate limiter — the limiter's
    /// sliding window only has meaning against real elapsed time.
    /// Injectable so tests control the window deterministically and
    /// deployments can swap in a monotonic clock.
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// The chain ID order/action signatures are verified against —
    /// configured per deployment so a signature produced for one
    /// chain can never replay on another. Defaults to the devnet
    /// [`protocol::CHAIN_ID`].
    chain_id: u64,
    /// Scratch for non-fill book removals the sweep reports —
    /// reused across orders like `fills` (zero alloc steady-state).
    removed: Vec<trading::MakerRemoval>,
}

/// Wall-clock milliseconds since the Unix epoch — the production
/// time source for risk controls. `map_or(0, …)` only if the system
/// clock predates the epoch (already handled as "no elapsed time").
pub(crate) fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
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
        let vcfg = cfg.validated().expect("market config must be valid");
        let engine = MatchingEngine::new(vcfg, DenseBook::new(vcfg).expect("book creation"))
            .expect("engine creation");
        Self {
            engine,
            balances: BalanceCache::with_capacity(balance_capacity),
            risk: RiskEngine::with_defaults(),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(settlement::SETTLEMENT_BATCH_CAPACITY),
            cost_acc: LegCostAcc::default(),
            nonces: NonceTracker::new(),
            order_client_ids: HashMap::with_capacity(65_536),
            clock: Arc::new(wall_clock_ms),
            chain_id: protocol::CHAIN_ID,
            removed: Vec::with_capacity(64),
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
        let vcfg = cfg.validated().expect("market config must be valid");
        let engine = MatchingEngine::new(vcfg, DenseBook::new(vcfg).expect("book creation"))
            .expect("engine creation");
        Self {
            engine,
            balances: BalanceCache::with_capacity(balance_capacity),
            risk: RiskEngine::new(risk_config),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(settlement::SETTLEMENT_BATCH_CAPACITY),
            cost_acc: LegCostAcc::default(),
            nonces: NonceTracker::new(),
            order_client_ids: HashMap::with_capacity(65_536),
            clock: Arc::new(wall_clock_ms),
            chain_id: protocol::CHAIN_ID,
            removed: Vec::with_capacity(64),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
            auth_rejections: 0,
        }
    }

    /// Swap in a different millisecond time source for the rate
    /// limiter — tests inject a controllable clock; deployments can
    /// supply a monotonic source.
    pub fn set_clock(&mut self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) {
        self.clock = clock;
    }

    /// The chain ID order and action signatures are verified
    /// against.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Configure the chain ID signatures verify against. Call this
    /// before serving traffic — signatures made under a different
    /// chain ID verify as forgeries (rejected `BadSignature`), which
    /// is exactly the cross-chain replay boundary.
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = chain_id;
    }

    /// Attach a durable checkpoint file for consumed nonces. Without
    /// it the replay gate is memory-only: every restart forgets all
    /// consumed nonces, so ANY captured signed request becomes
    /// replayable once. With a store attached (`path` plus a
    /// `<path>.wal` write-ahead log), consumed nonces are handed to a
    /// background durability thread every [`NONCE_FLUSH_EVERY`]
    /// admissions and on every [`Self::seal_batch`]. The replay window
    /// shrinks to the admissions not yet `fdatasync`ed, and the
    /// sequencer never touches the disk (hft-audit-2 M-1). Call
    /// before serving traffic.
    ///
    /// # Panics
    ///
    /// Panics if the checkpoint is corrupt, the log is unreadable, or
    /// the startup checkpoint cannot be written. A replay DB that
    /// cannot be verified or kept durable must fail closed, not
    /// silently reset.
    pub fn set_nonce_store(&mut self, path: std::path::PathBuf) {
        self.nonces.attach_store(path);
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
        if let Some(verified) = protocol::VerifiedOrder::with_chain_id(*req, self.chain_id) {
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
        // timestamp comes from the injected clock — the rate
        // limiter's sliding window measures ELAPSED time; feeding it
        // the order counter would make an account's allowance depend
        // on how fast the whole venue trades, not on real seconds.
        // The mid-price comes from the engine's best bid/ask.
        let mid = match (self.engine.best_bid(), self.engine.best_ask()) {
            (Some((bid, _)), Some((ask, _))) => u64::midpoint(bid.0, ask.0),
            _ => 0, // no mid available — skip price-band check
        };
        // The clock is read only when the rate limiter is on, the
        // check's sole consumer of time (M-15). With it off, `0` is
        // never looked at.
        let now_ms = if self.risk.needs_clock() { (self.clock)() } else { 0 };
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
        // `ObserveRemovals` never restricts a fill — it reports the
        // non-fill removals the resting-count bookkeeping below must
        // consume, so a maker deleted without a fill still releases
        // its resting slot.
        self.fills.clear();
        self.removed.clear();
        let Ok(outcome) = self.engine.place_with_cap(
            order,
            &mut self.fills,
            &mut trading::ObserveRemovals { removed: &mut self.removed },
        ) else {
            self.engine_rejections += 1;
            // Engine-level error: nothing matched, nothing rests —
            // the whole reservation comes back.
            if reservation > 0 {
                self.balances.credit(&req.owner, reservation);
            }
            return OrderResponse::rejected(RejectReason::EngineError);
        };

        // ── Settle fills ─────────────────────────────────────────
        // For each fill: credit the seller its MARGINAL leg cost —
        // the delta in the merged leg's floored total, so the sum
        // telescopes to exactly the `floor(price × Σqty / SCALE)`
        // the chain settles (see `LegCostAcc`). The buyer's side of
        // the payment comes out of the reservation debited at
        // admission (buy orders) — see `buy_reservation_refund`
        // below. Sell takers simply receive quote; their fills'
        // buyers are resting makers whose own reservations paid at
        // rest.
        let mut taker_fill_cost: u64 = 0;
        for f in &self.fills {
            self.fills_produced += 1;
            // The taker's client id is this request's nonce; the
            // maker's resolves through the resting-order map (see
            // `fill_parties` for the fallback rules).
            let (buyer, seller, buyer_id, seller_id) =
                fill_parties(f, req.nonce, &self.order_client_ids);
            let market = self.engine.config().market_id;
            let quote_amount = self
                .cost_acc
                .add(LegId::new(market, f.price.0, buyer, buyer_id, seller, seller_id), f.qty.0);
            // Credit the seller the marginal leg delta.
            self.balances.credit(&seller, quote_amount);
            // The taker's own cost accumulates the same marginals —
            // for a buy outcome every fill's buyer is the taker, so
            // this is exactly what the chain's legs will debit.
            // (Sell-taker outcomes ignore the value — their buyers
            // paid from resting reservations, not this request's.)
            taker_fill_cost = taker_fill_cost.saturating_add(quote_amount);
            // Accumulate for batch settlement.
            self.settlement_batch.push(SettledFill {
                market,
                price: f.price,
                qty: f.qty,
                buyer,
                buyer_id,
                seller,
                seller_id,
                quote_amount,
            });
        }

        // ── Release resting slots for makers that left the book ──
        // Fills and reported removals both retire resting orders;
        // `gone_makers` attributes each departure to its owner,
        // exactly once (see the helper for the accounting rules).
        for owner in gone_makers(&self.engine, &self.removed, &self.fills) {
            self.risk.dec_resting(&owner);
        }
        evict_gone_client_ids(&self.engine, &self.fills, &self.removed, &mut self.order_client_ids);

        // ── Release the reservation (buys) ──────────────────────
        // Everything not consumed by fills (at their actual price)
        // or held for a surviving resting remainder comes back —
        // exactly once. A resting buy keeps `price × resting_qty`
        // locked, which is what `cancel_order` refunds.
        if reservation > 0 {
            let refund =
                buy_reservation_refund(reservation, req.price.0, &outcome, taker_fill_cost);
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
                // Bind the book id to the request nonce — fills
                // against this maker resolve `(owner, client_id)`
                // through this entry.
                self.order_client_ids.insert(order_id.0, req.nonce);
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
        // Authentication gate — identical policy to `submit_order`,
        // including the configured chain ID.
        let Some(verified) = protocol::VerifiedAction::with_chain_id(*req, self.chain_id) else {
            self.orders_processed += 1;
            self.auth_rejections += 1;
            return OrderResponse::rejected(RejectReason::BadSignature);
        };
        self.submit_verified_action(verified)
    }

    /// Submit a pre-authenticated action — the [`protocol::VerifiedAction`]
    /// token is proof the signature + owner binding already passed, so
    /// the sequencer does not pay a second `verify_strict` (~80 µs per
    /// action on the single writer — the signature-bound throughput
    /// ceiling). Replay protection is NOT folded into the token: the
    /// per-owner nonce check still runs here so a captured action is
    /// consumed exactly once.
    ///
    /// Transports construct the token via
    /// [`protocol::VerifiedAction::with_chain_id`] with the same chain ID
    /// the server verifies against.
    pub fn submit_verified_action(&mut self, req: protocol::VerifiedAction) -> OrderResponse {
        self.orders_processed += 1;
        let req = req.request();
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
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
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
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
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
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
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
    ///
    /// Also checkpoints consumed nonces — the settler's seal cadence
    /// is a natural, off-hot-path durability point for the replay
    /// gate — and resets the marginal leg-cost accumulator: legs are
    /// re-formed per batch, so the telescoping must restart here
    /// (any residual below one unit is never a payment on either
    /// side — the chain's floor drops it identically).
    pub fn seal_batch(&mut self) -> Vec<SettledFill> {
        self.nonces.flush();
        self.cost_acc.legs.clear();
        settlement::take_presized_batch(&mut self.settlement_batch)
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

    /// Submit a pre-authenticated action — see
    /// [`MatchingServer::submit_verified_action`]. Transports that
    /// already verified the signature use this so the matcher thread
    /// does not pay a second `verify_strict`.
    ///
    /// Returns an `EngineError` rejection if the internal mutex is
    /// poisoned.
    pub fn submit_verified_action(&self, req: protocol::VerifiedAction) -> OrderResponse {
        match self.inner.lock() {
            Ok(mut guard) => guard.submit_verified_action(req),
            Err(_) => OrderResponse::rejected(crate::protocol::RejectReason::EngineError),
        }
    }

    /// The chain ID the inner server verifies signatures against —
    /// transports use it for their early (pre-dispatch) signature
    /// check so early-reject and the mandatory in-server re-verify
    /// can never disagree. Falls back to the devnet default if the
    /// mutex is poisoned.
    pub fn chain_id(&self) -> u64 {
        match self.inner.lock() {
            Ok(guard) => guard.chain_id(),
            Err(_) => crate::protocol::CHAIN_ID,
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
    /// response back via the oneshot channel. The command carries a
    /// [`protocol::VerifiedAction`] proof — authentication happens at
    /// the transport boundary, so the matcher thread never pays a
    /// second signature verification on the control path.
    Action(protocol::VerifiedAction, std::sync::mpsc::Sender<OrderResponse>),
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
    /// The order rings (one per in-flight exchange — an exclusive
    /// [`RingLease`] serializes who the connection-side producer is).
    /// Producer = lease-holding request handler,
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
    /// The response rings (one per in-flight exchange). Producer =
    /// matcher, consumer = the lease-holding request handler. Each
    /// item is a WHOLE BATCH of responses.
    response_rings: Vec<ring::SpscReceiver<Vec<OrderResponse>>>,
    /// One exclusive-occupancy flag per ring pair. A request handler
    /// must hold the lease for the WHOLE submit→response exchange:
    /// without it, two connections landing on the same ring index
    /// interleave order batches and — worse — race on the shared
    /// response ring, so a response batch addressed to request A can
    /// be consumed by request B. `true` = a lease holder owns the
    /// ring; acquisition is a `false→true` CAS.
    ring_leases: Vec<std::sync::atomic::AtomicBool>,
    /// Wakes one lease waiter when a ring is released. Async (`Notify`)
    /// because waiters run on tokio tasks — a condvar would block an
    /// executor thread.
    lease_notify: tokio::sync::Notify,
    /// Control channel sender (protocol side). The matcher thread
    /// polls the receiver between ring polls and services seal/stats
    /// commands without touching the order rings.
    control_tx: std::sync::mpsc::Sender<ControlCommand>,
    /// The sequencer's parked-flag wakeup — shared by every order
    /// ring and signalled explicitly by control senders so a
    /// seal/stats/action command lands on a sleeping sequencer in
    /// microseconds, not at the next timeout (hft-audit F-15).
    wakeup: Arc<ring::Wakeup>,
    /// The chain ID the embedded server verifies signatures
    /// against — copied at construction (the server moves to the
    /// matcher thread, so this can never diverge). Transport threads
    /// verify `VerifiedOrder` proofs with the same value.
    chain_id: u64,
    /// The matcher thread handle — its `is_finished` flag is the
    /// worker-liveness oracle for lease holders awaiting a response.
    worker_thread: std::thread::JoinHandle<()>,
}

impl RingMatcher {
    /// Create a ring-based matcher with `num_rings` ring pairs.
    /// Spawns a dedicated matcher thread that owns the
    /// `MatchingServer` and polls all rings.
    ///
    /// # Arguments
    /// - `server`: the matching server (moved to the matcher thread).
    /// - `num_rings`: number of ring pairs — the bound on
    ///   CONCURRENT submit→response exchanges (each holds an
    ///   exclusive [`RingLease`]); excess requesters wait for a
    ///   free ring rather than share one.
    /// - `ring_capacity`: capacity of each ring (power of 2).
    ///
    /// # Panics
    ///
    /// Panics if `num_rings` is 0.
    ///
    /// `sequencer_core` pins the sequencer thread (hft-audit F-02);
    /// `None` runs unpinned. A failed pin logs once — locality is a
    /// latency property, never a correctness one.
    #[must_use]
    pub fn new(
        server: MatchingServer,
        num_rings: usize,
        ring_capacity: usize,
        sequencer_core: Option<u32>,
    ) -> Self {
        Self::with_idle(server, num_rings, ring_capacity, sequencer_core, SequencerIdle::default())
    }

    /// [`RingMatcher::new`] with an explicit sequencer idle policy
    /// (hft-audit-2 M-2): [`SequencerIdle::Spin`] busy-polls the rings
    /// for [`ring::SEQUENCER_SPIN_BUDGET`] after the last unit of work
    /// before parking; [`SequencerIdle::Park`] parks on the first
    /// empty pass.
    ///
    /// # Panics
    ///
    /// Panics if `num_rings` is 0.
    #[must_use]
    pub fn with_idle(
        server: MatchingServer,
        num_rings: usize,
        ring_capacity: usize,
        sequencer_core: Option<u32>,
        idle: SequencerIdle,
    ) -> Self {
        assert!(num_rings > 0, "must have at least one ring");
        // Shared wakeup signal for all ORDER rings. A push on any
        // order ring signals this, waking the sequencer from its
        // parked wait — and control senders signal it explicitly so
        // seal/stats/action commands wake the sequencer immediately
        // rather than at the next timeout.
        let shared_wakeup = Arc::new(ring::Wakeup::new());
        // Create ring pairs: (order_tx, order_rx) and (resp_tx, resp_rx).
        // Order rings wake the (sync) sequencer via the shared parked
        // flag; response rings wake their (async) consumer task via a
        // per-ring `Notify` — a condvar would block an executor
        // thread, and a tokio task cannot sleep on one (F-15).
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
                ring::spsc_ring_with_notify(ring_capacity, Arc::new(tokio::sync::Notify::new()));
            order_senders.push(o_tx);
            order_receivers.push(o_rx);
            response_senders.push(r_tx);
            response_receivers.push(r_rx);
        }

        let chain_id = server.chain_id();
        let (control_tx, control_rx) = std::sync::mpsc::channel::<ControlCommand>();
        // A response batch the client has not yet drained. The lease
        // guarantees at most ONE exchange in flight per ring, so a
        // full response ring can only mean the client is lagging —
        // the sequencer must NOT spin for it (F-04: the old loop spun
        // forever and starved every other ring). The batch parks here
        // and is retried once per pass; a severed/disconnected client
        // frees it for real.
        let wake = Arc::clone(&shared_wakeup);
        // Critical: this thread IS the matcher — the single-writer
        // sequencer for every market's order book. A silent death
        // leaves clients connected to a server that never responds.
        // Pinned when `sequencer_core` is set: the engine's cache
        // working set (books, rings, accounts) stays hot on one core
        // instead of re-warming on every scheduler migration.
        let thread = primitives::supervision::spawn_supervised_pinned(
            "matcher-sequencer",
            true,
            sequencer_core,
            move || {
                run_sequencer(server, order_receivers, response_senders, control_rx, wake, idle);
            },
        )
        .expect("spawn matcher-sequencer thread");

        Self {
            order_rings: order_senders,
            response_rings: response_receivers,
            ring_leases: (0..num_rings)
                .map(|_| std::sync::atomic::AtomicBool::new(false))
                .collect(),
            lease_notify: tokio::sync::Notify::new(),
            control_tx,
            wakeup: shared_wakeup,
            chain_id,
            worker_thread: thread,
        }
    }

    /// Try to take the exclusive lease on one ring pair without
    /// waiting. `hint` biases the starting index so concurrent
    /// acquirers spread across rings instead of pile-driving ring 0.
    ///
    /// Returns `None` when every ring is leased — the caller decides
    /// whether to wait ([`acquire_ring`]) or shed load.
    #[must_use]
    pub fn try_acquire_ring(&self, hint: usize) -> Option<RingLease<'_>> {
        let n = self.order_rings.len();
        let start = hint % n;
        for offset in 0..n {
            let idx = (start + offset) % n;
            if self.ring_leases[idx]
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::Acquire,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
            {
                return Some(RingLease { matcher: self, ring_idx: idx });
            }
        }
        None
    }

    /// Take the exclusive lease on one ring pair, waiting until a
    /// ring frees. The lease MUST cover the whole submit→response
    /// exchange: it is the only thing that keeps two request
    /// handlers from sharing one ring and consuming each other's
    /// responses.
    ///
    /// `hint` is the caller's round-robin counter value — used as the
    /// scan start so load spreads across rings.
    ///
    /// Fairness: waiters re-scan all rings on wake in hint order, so
    /// a busy matcher can starve an unlucky waiter under sustained
    /// saturation. That is the intended bound — `num_rings`
    /// concurrent exchanges is the system's throughput limit, and
    /// excess requests wait rather than corrupt each other.
    ///
    /// SLO (hft-audit F-18): a waiter's queueing delay is unbounded
    /// in the worst case by design — there is no FIFO ticketing —
    /// so the venue-level contract is *throughput-bounded*, not
    /// latency-bounded: any request admitted while a ring is free
    /// gets `O(ring_cap)` turnaround, and saturation defers excess
    /// waiters instead of shedding them. Deployments that need a
    /// hard p99 should place the shed decision upstream (client
    /// timeout + retry across a second matcher endpoint); FIFO
    /// ticketing is revisit-worthy only if measured p99s demand it.
    pub async fn acquire_ring(&self, hint: usize) -> RingLease<'_> {
        let mut hint = hint;
        loop {
            if let Some(lease) = self.try_acquire_ring(hint) {
                return lease;
            }
            // Register interest BEFORE re-checking: a release landing
            // between the failed scan and `await` would otherwise be
            // missed and the waiter could sleep with a free ring.
            let notified = self.lease_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(lease) = self.try_acquire_ring(hint) {
                return lease;
            }
            notified.await;
            // Drift the scan start so a herd of waiters doesn't all
            // pile onto the same ring after each release.
            hint = hint.wrapping_add(1);
        }
    }

    /// The chain ID signatures are verified against — transports
    /// read this to produce `VerifiedOrder` proofs the embedded
    /// server will accept.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
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
        // Wake the sequencer — the control channel itself has no
        // wake edge, so without this a seal waits out the idle
        // timeout before being serviced (F-15).
        self.wakeup.signal();
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
        self.wakeup.signal();
        reply_rx.recv().unwrap_or_default()
    }

    /// Submit an order action (cancel/amend/replace) via a
    /// control-channel command to the matcher thread. Authenticates
    /// the wire `ActionRequest` HERE (caller thread) and ships the
    /// [`protocol::VerifiedAction`] proof to the matcher thread —
    /// the control path never pays a second signature verification
    /// and can never admit a forged action.
    ///
    /// Returns an `EngineError` rejection if the control channel is
    /// disconnected (matcher thread died) or the reply fails.
    pub fn submit_action(&self, action: ActionRequest) -> OrderResponse {
        let Some(verified) = protocol::VerifiedAction::with_chain_id(action, self.chain_id())
        else {
            return OrderResponse::rejected(crate::protocol::RejectReason::BadSignature);
        };
        self.submit_verified_action(verified)
    }

    /// Submit a pre-authenticated action — the caller constructed the
    /// [`protocol::VerifiedAction`] token itself (e.g. a transport that
    /// already verified the signature), so no re-verification happens
    /// anywhere.
    ///
    /// Returns an `EngineError` rejection if the control channel is
    /// disconnected (matcher thread died) or the reply fails.
    pub fn submit_verified_action(&self, action: protocol::VerifiedAction) -> OrderResponse {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self.control_tx.send(ControlCommand::Action(action, reply_tx)).is_err() {
            return OrderResponse::rejected(crate::protocol::RejectReason::EngineError);
        }
        self.wakeup.signal();
        reply_rx
            .recv()
            .unwrap_or_else(|_| OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
    }

    /// Get a connection's order sender (producer side of the order
    /// ring). The caller pushes WHOLE BATCHES of authenticated orders
    /// (`Vec<VerifiedOrder>`) to this ring — one push per batch, not
    /// per order. Only `VerifiedOrder`s can enter the ring, so the
    /// matcher thread never sees an unauthenticated order.
    ///
    /// CALLERS MUST HOLD the [`RingLease`] for `ring_idx` — pushing
    /// without it interleaves batches from concurrent requesters and
    /// breaks the response pairing the lease exists to guarantee.
    pub fn order_sender(&self, ring_idx: usize) -> &ring::SpscSender<Vec<protocol::VerifiedOrder>> {
        &self.order_rings[ring_idx]
    }

    /// Get a connection's response receiver (consumer side of the
    /// response ring). The caller pops WHOLE BATCHES
    /// (`Vec<OrderResponse>`) from this ring.
    ///
    /// CALLERS MUST HOLD the [`RingLease`] for `ring_idx` — the
    /// receiver is not `Clone`, but shared `&` access still lets two
    /// requesters race `pop`, and whichever loses gets the other's
    /// response batch (wrong order IDs to the wrong client).
    pub fn response_receiver(&self, ring_idx: usize) -> &ring::SpscReceiver<Vec<OrderResponse>> {
        &self.response_rings[ring_idx]
    }

    /// Number of ring pairs — the bound on concurrent in-flight
    /// exchanges (one exclusive lease each).
    pub fn num_rings(&self) -> usize {
        self.order_rings.len()
    }

    /// Whether the matcher worker thread is still running.
    ///
    /// A lease holder awaiting a response checks this to escape the
    /// wait: if the thread died mid-batch, its response senders are
    /// dropped and no response can ever arrive — the caller must
    /// bail rather than spin (and hold the ring) forever. crossbeam
    /// 0.5 has no receiver-side disconnect probe, so the
    /// `JoinHandle` is the liveness oracle.
    #[must_use]
    pub fn worker_is_alive(&self) -> bool {
        !self.worker_thread.is_finished()
    }
}

/// The sequencer's steady-state loop — extracted from
/// [`RingMatcher::new`] so construction stays readable and the hot
/// loop sits at module scope where its budget comments are visible.
///
/// Owns the order receivers, response senders, control channel, and
/// the shared wakeup; runs until every order sender disconnects (the
/// ring pop path returns `None` only on empty — teardown is the
/// process ending, so the loop is `loop {}`).
///
/// Idle protocol (hft-audit-2 M-2): an empty pass does not park
/// immediately under [`SequencerIdle::Spin`] — the loop keeps polling
/// for [`ring::SEQUENCER_SPIN_BUDGET`] so a burst's next order finds
/// a running thread; only then does it park on the shared
/// [`ring::Wakeup`].
///
/// Parking protocol (F-04): a response batch that can't push (client
/// hasn't drained its previous exchange — the lease caps in-flight
/// batches at one per ring) moves to `parked` and retries once per
/// pass, so a lagging client costs itself latency but can never
/// starve the other rings or the control channel.
fn run_sequencer(
    mut server: MatchingServer,
    order_receivers: Vec<ring::SpscReceiver<Vec<protocol::VerifiedOrder>>>,
    response_senders: Vec<ring::SpscSender<Vec<OrderResponse>>>,
    control_rx: std::sync::mpsc::Receiver<ControlCommand>,
    wake: Arc<ring::Wakeup>,
    idle: SequencerIdle,
) {
    let mut spinner = ring::IdleSpinner::new(idle);
    // Response batches that could not be pushed yet —
    // `(ring_idx, responses)`. Bounded by `num_rings` (one lease in
    // flight per ring). Parked instead of spun: the client is either
    // gone (push errors clear it) or lagging (retried each pass).
    let mut parked: Vec<(usize, Vec<OrderResponse>)> = Vec::new();
    loop {
        let mut did_work = false;
        // First: retry parked responses — a client that drained
        // between passes frees its batch here.
        parked.retain_mut(|(idx, batch)| {
            // `push` needs ownership on retry; take it and put it
            // back on failure.
            match response_senders[*idx].push(std::mem::take(batch)) {
                // Delivered un-parks; a disconnected client frees the
                // slot too (its batch is dead weight, not work owed).
                Ok(()) | Err(crate::ring::PushError::Disconnected(_)) => false,
                Err(crate::ring::PushError::Full(returned)) => {
                    *batch = returned;
                    true // still lagging — stay parked
                }
            }
        });
        // Round-robin poll all rings.
        for (i, order_rx) in order_receivers.iter().enumerate() {
            while let Some(batch) = order_rx.pop() {
                // Process the WHOLE batch: submit every order
                // back-to-back (no interleaving from other rings —
                // the batch is atomic).
                let responses: Vec<OrderResponse> =
                    batch.iter().map(|req| server.submit_verified(req)).collect();
                // Push the batch response to this connection's ring.
                // Full ⇒ the client has not drained its previous
                // response (the lease caps in-flight batches at one)
                // — PARK the batch and move on; a client that never
                // drains parks its own latency, never the sequencer's.
                if let Err(crate::ring::PushError::Full(batch)) =
                    response_senders[i].push(responses)
                {
                    parked.push((i, batch));
                }
                did_work = true;
            }
        }
        // Service control commands (seal/stats) between ring polls.
        // These come from the batch settler and monitoring — never
        // from the order hot path.
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
                    let resp = server.submit_verified_action(action);
                    let _ = reply.send(resp);
                }
            }
            did_work = true;
        }
        if did_work {
            spinner.on_work();
        } else if spinner.should_park() {
            // Spin window used up (or `SequencerIdle::Park`): announce
            // parking, then re-check ring occupancy inside the wakeup
            // so a push that raced the announcement is seen (the
            // parked-flag protocol covers the window). The 1 ms
            // timeout bounds control-channel latency for senders that
            // somehow missed the explicit signal — and anything else
            // anomalous.
            //
            // Until the window is used up the loop re-polls every ring
            // (and the control channel and the parked responses), so
            // an order arriving mid-spin is seen within one pass
            // without the producer touching the futex — `signal()` is
            // one swap while `parked == false` (hft-audit-2 M-2).
            wake.wait_for_work(std::time::Duration::from_millis(1), || {
                order_receivers.iter().any(|r| !r.is_empty())
            });
            spinner.on_work();
        }
    }
}

/// Exclusive ownership of one ring pair for a single
/// submit→response exchange.
///
/// Obtained from [`RingMatcher::acquire_ring`] or
/// [`RingMatcher::try_acquire_ring`]. While the guard lives, no other
/// requester can lease the same ring — the matcher thread's response
/// batch can only be popped by this holder. Release on `Drop`
/// (frees the ring and wakes one waiter), so the lease covers
/// exactly the lexical scope of the exchange — including early
/// returns and disconnect paths.
///
/// The guard borrows the `RingMatcher`; it cannot outlive the
/// matcher or move to another thread's exchange.
pub struct RingLease<'a> {
    /// The matcher that owns the leased ring (for release + notify).
    matcher: &'a RingMatcher,
    /// The leased ring pair index — pass to
    /// [`RingMatcher::order_sender`]/[`RingMatcher::response_receiver`].
    ring_idx: usize,
}

impl RingLease<'_> {
    /// The leased ring index.
    #[must_use]
    pub fn ring_idx(&self) -> usize {
        self.ring_idx
    }
}

impl Drop for RingLease<'_> {
    fn drop(&mut self) {
        // Release BEFORE notify so a woken waiter can never observe
        // the flag still held. Ordering pairs with acquire's CAS.
        self.matcher.ring_leases[self.ring_idx].store(false, std::sync::atomic::Ordering::Release);
        self.matcher.lease_notify.notify_one();
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

#[cfg(test)]
mod tests;
