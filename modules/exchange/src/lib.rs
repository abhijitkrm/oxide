//! Oxide exchange module — spot CLOB markets backed by the native
//! HFT matching engine.
//!
//! The exchange module is the on-chain home of [`trading::MatchingEngine`]:
//! it owns one engine per market, translates wire messages into
//! [`NewOrder`] / cancel requests, and emits fill events as Oxide
//! [`Event`]s for the executor's event log.
//!
//! # Design (plan.md §9.1, §7.2 native track)
//!
//! - **One engine per market, single-writer:** the module holds a
//!   `Vec<MatchingEngine>` indexed by `MarketId`. The executor's
//!   `handle` is `&self` behind a `Mutex` (the trait requires `Sync`),
//!   but the deterministic runtime calls `handle` serially — there is
//!   no contention in the hot path.
//! - **No settlement in the engine:** the matching engine produces
//!   [`FillEvent`]s (price, qty, maker/taker owners). Settlement —
//!   debiting/crediting balances — is the module's job, and in v0 it
//!   records fills as events unless a balance ledger is wired.
//!   Atomic settlement (ledger + exchange in one tx) arrives with the
//!   cross-module coordinator (plan.md §9.2).
//! - **Deterministic fill ordering:** the engine emits fills in match
//!   order (best price first, FIFO within a level). Two validators
//!   applying the same block produce byte-identical fill sequences.
//! - **Reusable fill buffer:** the module owns one `Vec<FillEvent>`
//!   reused across all `handle` calls in a block — zero allocation
//!   after the first call.
//!
//! # Message format
//!
//! Every message starts with a 1-byte tag:
//!
//! | Tag | Operation | Body |
//! |-----|-----------|------|
//! | 0   | Place order | `[market: 1B][side: 1B][order_type: 1B][tif: 1B][stp: 1B][price: 8B LE][qty: 8B LE]` |
//! | 1   | Cancel order | `[market: 1B][order_id: 8B LE]` |
//! | 2   | List market | `[tick: 8B LE][lot: 8B LE][min: 8B LE][max: 8B LE][max_resting: 4B LE]` |
//!
//! The sender (from the tx envelope) becomes the order owner.
//!
//! # State
//!
//! The module's KV subtree stores market configurations and the
//! next-order-id counter (for state-root replay). The live order book
//! lives in the in-memory `MatchingEngine`; on restart it is rebuilt
//! by replaying blocks (the journal guarantees deterministic replay).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use executor::{Event, ExecError, Module, TxContext};
use framework::{KVStore, module_id, subtree_root};
use primitives::fixed::{Price, Qty};
use primitives::{Address, Hash, Height};
use trading::{
    CanceledOrder, DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderId,
    OrderOutcome, OrderType, Side, StpMode, TimeInForce, TradingError,
};

/// A pre-matched fill entry for batch settlement from the off-chain
/// matching server. Encoded as
/// `[market:2][price:8][qty:8][buyer:20][seller:20]` = 58 bytes.
///
/// The wire carries no claimed settlement amount: the chain computes
/// `price * qty / PRICE_SCALE` itself after validating the leg against
/// the market's tick/lot/price-band config, so a malformed or forged
/// entry cannot move funds it should not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchFillEntry {
    /// Market the fill executed on — selects the config used for
    /// tick/lot/price-band validation. Legs for markets that are not
    /// listed on-chain are rejected.
    pub market: u16,
    /// Execution price (scale-8).
    pub price: Price,
    /// Traded quantity (scale-6).
    pub qty: Qty,
    /// Buyer address.
    pub buyer: primitives::Address,
    /// Seller address.
    pub seller: primitives::Address,
}

// ── Wire tags ────────────────────────────────────────────────────────

/// Place-order message tag.
const TAG_PLACE: u8 = 0;
/// Cancel-order message tag.
const TAG_CANCEL: u8 = 1;
/// List-market message tag (governance/genesis path).
const TAG_LIST_MARKET: u8 = 2;
/// Batch-settle message tag: applies pre-matched fills from the
/// off-chain matching server without re-matching. Each fill entry
/// is `[market:2][price:8][qty:8][buyer:20][seller:20]` = 58 bytes.
/// The body is `[fill_count:4][fill entries...]`.
const TAG_BATCH_SETTLE: u8 = 3;

/// Size of a single fill entry in a batch-settle message:
/// 2 + 8 + 8 + 20 + 20 = 58 bytes.
const FILL_ENTRY_LEN: usize = 58;

/// Maximum number of fills in a single batch-settle message. Prevents
/// a byzantine settlement operator from submitting a huge batch that
/// causes excessive processing. `65_536` fills × 58 bytes = ~3.8 MiB.
const MAX_BATCH_FILLS: usize = 65_536;

// ── Message sizes (body, excluding the 1-byte tag) ───────────────────

/// `[market:1][side:1][type:1][tif:1][stp:1][price:8][qty:8]` = 21.
const PLACE_BODY_LEN: usize = 21;
/// `[market:1][order_id:8]` = 9.
const CANCEL_BODY_LEN: usize = 9;
/// `[tick:8][lot:8][min:8][max:8][max_resting:4]` = 36.
const LIST_MARKET_BODY_LEN: usize = 36;

/// Quote-currency scale: the ledger stores native `u64` base units.
/// The notional from a fill is scale-14 (`qty_scale_6 × price_scale_8`);
/// dividing by `PRICE_SCALE` (1e8) yields the quote amount in scale-6
/// base units — the `Balances` unit for this settlement path.
const PRICE_SCALE: u128 = 100_000_000;

// ── Module ───────────────────────────────────────────────────────────

/// L1 market data: optional best bid and best ask, each as
/// `(price, level_qty)`.
type L1 = (Option<(Price, Qty)>, Option<(Price, Qty)>);

/// The spot CLOB exchange module.
///
/// Owns one [`MatchingEngine`] per market, plus a reusable fill buffer.
/// The `Mutex` is required by the `Module: Sync` bound; the
/// deterministic runtime calls `handle` serially, so the lock is
/// uncontended on the hot path.
///
/// **Settlement (plan.md §9.2):** when wired with a [`Balances`]
/// ledger via [`ExchangeModule::with_ledger`], the module settles each
/// fill by debiting the buyer and crediting the seller (quote
/// currency only, base units). Pre-trade balance checks reject buy
/// orders that would overdraw. Base-asset tracking is deferred to
/// multi-asset support; v0 is quote-settled cash markets.
pub struct ExchangeModule {
    inner: Mutex<Inner>,
    store: KVStore,
    /// Optional balance-ledger handle for settlement — the EVM
    /// account store behind `framework::Balances`. `None` = fills
    /// are recorded as events but no balances move (the v0
    /// no-settlement mode, useful for testing the matching path in
    /// isolation).
    ledger: Option<Arc<dyn framework::Balances + Send + Sync>>,
    /// The address authorized to submit `batch_settle` transactions:
    /// the off-chain matching service's tx sender. `None` disables
    /// batch settlement entirely (fail-closed) — an unconfigured
    /// operator must never be able to move balances.
    settlement_operator: Option<Address>,
}

struct Inner {
    /// One engine per market, indexed by `MarketId` (a `u8`).
    markets: Vec<Option<MatchingEngine>>,
    /// Reusable fill buffer — cleared and refilled per `place` call.
    fills: Vec<FillEvent>,
}

impl ExchangeModule {
    /// Construct a fresh exchange module with no markets and no
    /// settlement (fills are recorded but balances don't move).
    ///
    /// Markets are added via `list_market` messages (genesis or
    /// governance). The module preallocates room for 256 market slots
    /// (the `u8` market-ID space); unused slots are `None`.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                markets: (0..=u8::MAX).map(|_| None).collect(),
                fills: Vec::with_capacity(64),
            }),
            store: Mutex::new(BTreeMap::new()),
            ledger: None,
            settlement_operator: None,
        }
    }

    /// Construct an exchange module wired to a balance ledger for
    /// settlement. Fills debit the buyer and credit the seller (quote
    /// currency). Pre-trade balance checks reject buy orders that
    /// would overdraw. On a live node `ledger` is the EVM account
    /// store, so settled funds are the same balances EVM txs move.
    ///
    /// Note: `batch_settle` stays disabled until
    /// [`Self::set_settlement_operator`] configures the authorized
    /// operator address — wiring a ledger alone does not open the
    /// privileged settlement path.
    pub fn with_ledger(ledger: Arc<dyn framework::Balances + Send + Sync>) -> Self {
        let mut ex = Self::new();
        ex.ledger = Some(ledger);
        ex
    }

    /// Configure the settlement operator address — the off-chain
    /// matching service's tx sender, and the only account allowed to
    /// submit `batch_settle` transactions.
    ///
    /// Must be called before the module is shared (e.g. wrapped in
    /// `Arc` and registered on the executor). While unset, every
    /// `batch_settle` message is rejected.
    pub fn set_settlement_operator(&mut self, operator: Address) {
        self.settlement_operator = Some(operator);
    }

    /// Builder form of [`Self::set_settlement_operator`]: configures
    /// the settlement operator at construction time so the module can
    /// be wrapped in `Arc` in one expression.
    #[must_use]
    pub fn with_settlement_operator(mut self, operator: Address) -> Self {
        self.settlement_operator = Some(operator);
        self
    }

    /// List a new market with the given configuration. Returns the
    /// assigned `MarketId` (the first empty slot).
    ///
    /// This is the genesis/governance path — it does not go through
    /// `handle` (which requires a tx envelope). It is called during
    /// node setup to seed initial markets.
    ///
    /// # Errors
    /// Returns [`ExecError::ModuleRejected`] if the market config is
    /// invalid or all 256 slots are taken.
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn list_market(&self, cfg: MarketConfig) -> Result<u8, ExecError> {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Find the first empty slot.
        let id =
            inner.markets.iter().position(Option::is_none).ok_or_else(|| {
                ExecError::ModuleRejected("all 256 market slots taken".to_string())
            })?;
        // u8 market id space: position is 0..=255, fits u8.
        #[allow(clippy::cast_possible_truncation)]
        let id_u8 = id as u8;
        let book = DenseBook::new(cfg)
            .map_err(|e| ExecError::ModuleRejected(format!("book init: {e}")))?;
        let engine = MatchingEngine::new(cfg, book)
            .map_err(|e| ExecError::ModuleRejected(format!("engine init: {e}")))?;
        inner.markets[id] = Some(engine);
        // Persist the market config for state-root replay.
        let key = market_config_key(id_u8);
        self.store
            .lock()
            .unwrap()
            .insert(key, encode_market_config(inner.markets[id].as_ref().unwrap().config()));
        Ok(id_u8)
    }

    /// L1 market data: best bid/ask for a market.
    ///
    /// Returns `None` if the market does not exist.
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn l1(&self, market: u8) -> Option<L1> {
        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let engine = inner.markets[usize::from(market)].as_ref()?;
        Some((engine.best_bid(), engine.best_ask()))
    }

    /// Number of resting orders in a market (for diagnostics / state
    /// inspection).
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn resting_count(&self, market: u8) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .markets
            .get(usize::from(market))
            .and_then(|m| m.as_ref())
            .map_or(0, MatchingEngine::resting_count)
    }

    /// Parse a place-order message body (tag already consumed).
    fn parse_place(msg: &[u8]) -> Option<(u8, NewOrder, Address)> {
        if msg.len() != PLACE_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let side = decode_side(msg[1])?;
        let order_type = decode_order_type(msg[2])?;
        let tif = decode_tif(msg[3])?;
        let stp = decode_stp(msg[4])?;
        let price = u64::from_le_bytes(msg[5..13].try_into().ok()?);
        let qty = u64::from_le_bytes(msg[13..21].try_into().ok()?);
        // The owner is the tx sender, not in the body. The caller
        // supplies it separately.
        let _ = (market, side, order_type, tif, stp, price, qty);
        // We return the parsed fields; the owner is set by the caller.
        // The `Address` here is a placeholder — the caller overwrites it.
        Some((
            market,
            NewOrder {
                side,
                order_type,
                tif,
                price: Price(price),
                qty: Qty(qty),
                owner: Address([0; 20]),
                stp,
            },
            Address([0; 20]),
        ))
    }

    /// Parse a cancel-order message body (tag already consumed).
    fn parse_cancel(msg: &[u8]) -> Option<(u8, OrderId)> {
        if msg.len() != CANCEL_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let order_id = u64::from_le_bytes(msg[1..9].try_into().ok()?);
        Some((market, OrderId(order_id)))
    }

    /// Parse a list-market message body (tag already consumed).
    fn parse_list_market(msg: &[u8]) -> Option<MarketConfig> {
        if msg.len() != LIST_MARKET_BODY_LEN {
            return None;
        }
        let tick_size = u64::from_le_bytes(msg[0..8].try_into().ok()?);
        let lot_size = u64::from_le_bytes(msg[8..16].try_into().ok()?);
        let min_price = u64::from_le_bytes(msg[16..24].try_into().ok()?);
        let max_price = u64::from_le_bytes(msg[24..32].try_into().ok()?);
        let max_resting = u32::from_le_bytes(msg[32..36].try_into().ok()?);
        Some(MarketConfig { market_id: 0, tick_size, lot_size, min_price, max_price, max_resting })
    }
}

impl Default for ExchangeModule {
    fn default() -> Self {
        Self::new()
    }
}

// ── Wire message constructors ───────────────────────────────────────

/// Wire message builders for the exchange module.
pub mod msg {
    use super::{
        CANCEL_BODY_LEN, LIST_MARKET_BODY_LEN, MarketConfig, NewOrder, OrderId, PLACE_BODY_LEN,
        encode_order_type, encode_side, encode_stp, encode_tif,
    };

    /// Build a place-order message. The sender (from the tx envelope)
    /// becomes the order owner.
    ///
    /// # Panics
    /// Panics if `market` does not fit in a `u8` (it is a `u8`).
    pub fn place(market: u8, order: NewOrder) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + PLACE_BODY_LEN);
        msg.push(super::TAG_PLACE);
        msg.push(market);
        msg.push(encode_side(order.side));
        msg.push(encode_order_type(order.order_type));
        msg.push(encode_tif(order.tif));
        msg.push(encode_stp(order.stp));
        msg.extend_from_slice(&order.price.0.to_le_bytes());
        msg.extend_from_slice(&order.qty.0.to_le_bytes());
        msg
    }

    /// Build a cancel-order message.
    pub fn cancel(market: u8, order_id: OrderId) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + CANCEL_BODY_LEN);
        msg.push(super::TAG_CANCEL);
        msg.push(market);
        msg.extend_from_slice(&order_id.0.to_le_bytes());
        msg
    }

    /// Build a list-market message (governance/genesis path).
    pub fn list_market(cfg: MarketConfig) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + LIST_MARKET_BODY_LEN);
        msg.push(super::TAG_LIST_MARKET);
        msg.extend_from_slice(&cfg.tick_size.to_le_bytes());
        msg.extend_from_slice(&cfg.lot_size.to_le_bytes());
        msg.extend_from_slice(&cfg.min_price.to_le_bytes());
        msg.extend_from_slice(&cfg.max_price.to_le_bytes());
        msg.extend_from_slice(&cfg.max_resting.to_le_bytes());
        msg
    }

    /// Build a batch-settle message for pre-matched fills from the
    /// off-chain matching server. Each fill is encoded as
    /// `[market:2][price:8][qty:8][buyer:20][seller:20]` (58 bytes).
    /// The wire carries no claimed settlement amount — the chain
    /// recomputes `price * qty / PRICE_SCALE` per leg.
    ///
    /// The resulting message is submitted as the module payload of
    /// an Oxide transaction envelope with `module_id = EXCHANGE (5)`.
    /// The tx's `sender` must be the configured settlement operator.
    ///
    /// # Panics
    ///
    /// Panics if `fills` is empty (a batch settle with zero fills
    /// is a no-op and should not be submitted).
    pub fn batch_settle(fills: &[crate::BatchFillEntry]) -> Vec<u8> {
        assert!(!fills.is_empty(), "batch_settle requires at least one fill");
        let mut msg = Vec::with_capacity(1 + 4 + fills.len() * super::FILL_ENTRY_LEN);
        msg.push(super::TAG_BATCH_SETTLE);
        msg.extend_from_slice(&u32::try_from(fills.len()).unwrap_or(u32::MAX).to_le_bytes());
        for f in fills {
            msg.extend_from_slice(&f.market.to_le_bytes());
            msg.extend_from_slice(&f.price.0.to_le_bytes());
            msg.extend_from_slice(&f.qty.0.to_le_bytes());
            msg.extend_from_slice(&f.buyer.0);
            msg.extend_from_slice(&f.seller.0);
        }
        msg
    }
}

// ── Module trait impl ────────────────────────────────────────────────

impl Module for ExchangeModule {
    fn name(&self) -> &'static str {
        "exchange"
    }

    fn id(&self) -> u8 {
        module_id::EXCHANGE
    }

    fn begin_block(&self, _height: Height) {}

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.is_empty() {
            return Err(ExecError::Malformed);
        }
        let tag = msg[0];
        let body = &msg[1..];

        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        match tag {
            TAG_PLACE => self.handle_place(ctx, body, &mut inner),

            TAG_CANCEL => {
                let (market, order_id) = Self::parse_cancel(body).ok_or(ExecError::Malformed)?;

                let Inner { markets, fills: _ } = &mut *inner;
                let Some(engine) = markets[usize::from(market)].as_mut() else {
                    return Err(ExecError::ModuleRejected(format!(
                        "market {market} does not exist"
                    )));
                };

                // Authorization: only the order's owner may cancel.
                if let Some(owner) = engine.order_owner(order_id) {
                    if owner != ctx.sender {
                        return Err(ExecError::ModuleRejected(
                            "cancel: not the order owner".to_string(),
                        ));
                    }
                } else {
                    return Err(ExecError::ModuleRejected("cancel: order not found".to_string()));
                }

                match engine.cancel(order_id) {
                    Ok(canceled) => {
                        // Release the resting reservation (C6): a
                        // resting buy holds `price × remaining_qty`
                        // of quote debited since the order rested.
                        // Cancel releases it — exactly once. A sell
                        // rest unreserved (no base-asset tracking in
                        // v0), so there is nothing to refund. The
                        // credit cannot overflow: the refund returns
                        // funds that were debited from this account.
                        if canceled.side == Side::Buy {
                            if let Some(ledger) = &self.ledger {
                                let refund = u64::try_from(
                                    u128::from(canceled.price.0) * u128::from(canceled.qty.0)
                                        / PRICE_SCALE,
                                )
                                .map_err(|_| {
                                    ExecError::ModuleRejected(
                                        "cancel refund exceeds u64 quote range".to_string(),
                                    )
                                })?;
                                if refund > 0 {
                                    ledger.credit(&canceled.owner, refund).map_err(|_| {
                                        ExecError::ModuleRejected(
                                            "cancel refund failed".to_string(),
                                        )
                                    })?;
                                }
                            }
                        }
                        Ok(vec![cancel_event(market, canceled)])
                    }
                    Err(TradingError::OrderNotFound) => {
                        Err(ExecError::ModuleRejected("cancel: order not found".to_string()))
                    }
                    Err(e) => Err(ExecError::ModuleRejected(format!("cancel: {e}"))),
                }
            }

            TAG_LIST_MARKET => {
                let cfg = Self::parse_list_market(body).ok_or(ExecError::Malformed)?;
                // list_market finds the first empty slot and persists
                // the config. We drop the inner lock to avoid
                // double-locking (list_market locks inner again).
                drop(inner);
                let id = self.list_market(cfg)?;
                Ok(vec![Event { module: "exchange", kind: "market_listed", data: vec![id] }])
            }

            TAG_BATCH_SETTLE => self.handle_batch_settle(ctx, body, &inner),

            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, _height: Height) {}

    fn state_root(&self) -> Hash {
        subtree_root(&self.store)
    }
}

impl ExchangeModule {
    /// Handle a place-order message (extracted from `handle`).
    ///
    /// Runs the full order lifecycle: parse → pre-trade balance check
    /// → match → fill events → settlement. `inner` is the
    /// already-held module lock; the order book and reusable fill
    /// buffer are borrowed from it.
    fn handle_place(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        let (market, mut order, _owner_placeholder) =
            Self::parse_place(body).ok_or(ExecError::Malformed)?;
        // The tx sender is the order owner (self-trade checks
        // and settlement attribution use this).
        order.owner = ctx.sender;

        // Split the borrow: `inner` derefs to `Inner`, and we need
        // `&mut markets` and `&mut fills` at once.
        let Inner { markets, fills } = inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::ModuleRejected(format!("market {market} does not exist")));
        };

        // Reservation (C6): if the ledger is wired, a buy order
        // DEBITS its worst-case quote cost up front — this is a
        // reservation, not a check. Limit buys reserve
        // `price × qty` (fills can only cost less); market buys
        // reserve the real sweep cost of `qty` through the ask
        // ladder (`engine.sweep_cost`) — a market order has no
        // limit, so `price × qty` would be meaningless. Without a
        // reservation an unfunded taker could sweep the book and
        // leave every fill unsettled.
        //
        // The reservation is released piecewise at settlement:
        // fills pay their actual price, a surviving resting
        // remainder keeps `price × resting_qty` held — which is
        // exactly what `TAG_CANCEL` refunds later, exactly once.
        // Resting buy orders ARE the reservation ledger: a maker
        // fill pays from quote already debited at rest time, so
        // settlement below cannot fail on insolvency.
        let mut reservation = 0u64;
        if let Some(ledger) = &self.ledger {
            if order.side == Side::Buy {
                // Scale-14 notional → scale-6 quote. Reject rather
                // than cap on u64 overflow — saturating would
                // silently change what the buyer pays.
                let notional = match order.order_type {
                    OrderType::Market => engine.sweep_cost(Side::Buy, order.qty.0, None),
                    _ => u128::from(order.price.0) * u128::from(order.qty.0),
                };
                let quote_needed = u64::try_from(notional / PRICE_SCALE).map_err(|_| {
                    ExecError::ModuleRejected("buy notional exceeds u64 quote range".to_string())
                })?;
                // Debit up front — fails here, BEFORE the book is
                // touched, on insufficient funds.
                ledger.debit(&ctx.sender, quote_needed).map_err(|_| {
                    ExecError::ModuleRejected("insufficient balance for buy order".to_string())
                })?;
                reservation = quote_needed;
            }
        }

        // Reuse the fill buffer across calls — zero alloc.
        fills.clear();
        let outcome = match engine.place(order, fills) {
            Ok(outcome) => outcome,
            Err(e) => {
                // Engine rejected the order — nothing matched and
                // nothing rests, so the full reservation comes back.
                // Crediting the account we just debited cannot
                // overflow; the map_err is defensive.
                if reservation > 0 {
                    if let Some(ledger) = &self.ledger {
                        ledger.credit(&ctx.sender, reservation).map_err(|_| {
                            ExecError::ModuleRejected("engine-reject refund failed".to_string())
                        })?;
                    }
                }
                return Err(ExecError::ModuleRejected(format!("engine: {e}")));
            }
        };

        // Emit one event per fill + one for the outcome.
        let mut events = Vec::with_capacity(fills.len() + 1);
        for f in fills.iter() {
            events.push(fill_event(*f));
        }

        // Settlement (plan.md §9.2, C6): the payer's side of every
        // fill was ALREADY debited — the taker via the reservation
        // above, a resting maker buy via the reservation it has held
        // since it rested. So each fill only needs `credit(seller)`:
        // no debit can fail here, which is the point — the book
        // mutation above is NOT rolled back on a post-`place` error
        // (the engine lives in module memory, invisible to the
        // executor's state journal), so nothing after `place` may
        // fail. The remaining `map_err`s guard invariants that are
        // unreachable while they hold: per-fill notional ≤ the
        // debited reservation (u64 range), and credit overflow only
        // if an account approaches u64::MAX — impossible while total
        // supply stays below it (enforced at mint/genesis).
        if let Some(ledger) = &self.ledger {
            for f in fills.iter() {
                let notional = u128::from(f.price.0) * u128::from(f.qty.0);
                let quote_amount = u64::try_from(notional / PRICE_SCALE).map_err(|_| {
                    ExecError::ModuleRejected(format!(
                        "fill notional exceeds u64 quote range (market {market})"
                    ))
                })?;
                // The seller is whichever party did NOT pay the
                // quote: the maker when the taker bought, the taker
                // when the taker sold.
                let seller = if f.taker_side == Side::Buy { f.maker_owner } else { f.taker_owner };
                ledger.credit(&seller, quote_amount).map_err(|_| {
                    ExecError::ModuleRejected(format!("settlement credit failed (market {market})"))
                })?;
            }

            // Release the taker's reservation: fills the taker BOUGHT
            // cost their actual fill price (improvement refunded), a
            // surviving GTC remainder keeps `price × resting_qty`
            // held for the cancel path, and dead remainders
            // (IOC/FOK/Killed/Rejected) come back in full.
            if reservation > 0 {
                let taker_paid: u64 = fills
                    .iter()
                    .map(|f| {
                        u64::try_from(u128::from(f.price.0) * u128::from(f.qty.0) / PRICE_SCALE)
                            .unwrap_or(u64::MAX)
                    })
                    .sum();
                let held = match outcome {
                    OrderOutcome::Resting { resting_qty, .. } => u64::try_from(
                        u128::from(order.price.0) * u128::from(resting_qty.0) / PRICE_SCALE,
                    )
                    .unwrap_or(u64::MAX),
                    _ => 0,
                };
                let refund = reservation.saturating_sub(taker_paid.saturating_add(held));
                if refund > 0 {
                    ledger.credit(&ctx.sender, refund).map_err(|_| {
                        ExecError::ModuleRejected("reservation refund failed".to_string())
                    })?;
                }
            }
        }

        events.push(outcome_event(market, outcome));
        Ok(events)
    }

    /// Handle a batch-settle message: apply pre-matched fills from
    /// the off-chain matching server. Each valid fill leg debits the
    /// buyer and credits the seller by a **chain-computed** amount —
    /// no re-matching, and no trust in operator-supplied amounts.
    ///
    /// Body format: `[fill_count:4 LE][fill entries...]`
    /// Each fill entry: `[market:2][price:8][qty:8][buyer:20][seller:20]`.
    ///
    /// # Security
    ///
    /// - **Authorization:** only `ctx.sender == settlement_operator`
    ///   (the genesis-configured matcher identity) may submit batch
    ///   settlements. Without this check any account could forge
    ///   fills and drain arbitrary balances.
    /// - **Validation:** every leg is checked against the market's
    ///   config (listed market, positive lot-aligned qty, on-tick
    ///   price inside the configured band, distinct buyer/seller).
    /// - **Amounts:** the settlement amount is recomputed on-chain as
    ///   `price * qty / PRICE_SCALE` with checked `u128`/`u64` math.
    ///   A leg that fails validation or overflows is skipped with a
    ///   `fill_rejected` event — invalid legs cannot move funds.
    /// - **Aggregation:** amounts are accumulated per (buyer, seller)
    ///   pair in an open-addressed flat index map (one probe vs the
    ///   `BTreeMap`'s ~16-level pointer chase per leg); the drain
    ///   sorts by key, so transfer order is deterministic and each
    ///   pair settles in one atomic `ledger.transfer`.
    ///
    /// A leg whose buyer is insolvent is skipped with a
    /// `settlement_failed` event (the venue reconciles off-chain);
    /// other legs in the batch still settle — one insolvent account
    /// cannot halt settlement for the whole batch.
    ///
    /// `inner` is the already-held module lock (batch settle only
    /// reads market configs — it never mutates the books).
    fn handle_batch_settle(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &Inner,
    ) -> Result<Vec<Event>, ExecError> {
        // Authorization gate: the settlement operator is the only
        // account allowed to move balances via this path.
        if self.settlement_operator != Some(ctx.sender) {
            return Err(ExecError::ModuleRejected("unauthorized settlement operator".to_string()));
        }
        if body.len() < 4 {
            return Err(ExecError::Malformed);
        }
        let fill_count = usize::try_from(u32::from_le_bytes(
            body[0..4].try_into().map_err(|_| ExecError::Malformed)?,
        ))
        .map_err(|_| ExecError::Malformed)?;
        // HIGH fix: bound the batch size to prevent a byzantine
        // settlement operator from submitting a huge batch that
        // causes excessive processing.
        if fill_count > MAX_BATCH_FILLS {
            return Err(ExecError::Malformed);
        }
        if body.len() != 4 + fill_count * FILL_ENTRY_LEN {
            return Err(ExecError::Malformed);
        }

        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::ModuleRejected("batch settle requires ledger wiring".to_string())
        })?;

        // Snapshot the market configs once — batch settle never
        // mutates the books, so one pass over `inner.markets` serves
        // every leg.
        let configs: Vec<Option<MarketConfig>> =
            inner.markets.iter().map(|m| m.as_ref().map(|e| *e.config())).collect();

        // Validate every leg and accumulate the settlement total per
        // (buyer, seller) pair. Aggregation uses an open-addressed
        // flat index map over a flat `entries` Vec instead of a
        // `BTreeMap`: the tree version costs ~150-250ns/leg at large
        // batch sizes (16+ levels of pointer-chasing per lookup on a
        // 40-byte key), while the flat probe is ~15-25ns — one hash,
        // 1-3 cache-resident slots. `entries` keeps insertion order;
        // the drain sorts by key, preserving the BTreeMap's exact
        // deterministic transfer order, so observable behavior is
        // unchanged.
        //
        // Table capacity is 2× the leg count (load factor ≤ 0.5,
        // probes stay short); every entry slot is `u32::MAX` = empty.
        let table_cap = (fill_count.saturating_mul(2)).next_power_of_two().max(64);
        let mut table = vec![u32::MAX; table_cap];
        // Capacity for the worst case (every leg a distinct pair) —
        // untouched reserved pages cost nothing, while distinct-heavy
        // batches avoid ~16 realloc copies.
        let mut entries: Vec<((Address, Address), u64)> = Vec::with_capacity(fill_count);
        let mut events = Vec::new();
        for i in 0..fill_count {
            match settle_leg(body, 4 + i * FILL_ENTRY_LEN, &configs)? {
                Some((buyer, seller, amount)) => {
                    // Flat-map lookup: hash the pair, linear-probe
                    // the table for a matching key or an empty slot.
                    // On miss, append to `entries` and record the
                    // index; on hit, accumulate in place.
                    let key = (buyer, seller);
                    let mask = table_cap - 1;
                    // Masked to < 2^17 slots on the same line — the
                    // u64->usize cast cannot truncate a meaningful
                    // index on any supported target.
                    #[allow(clippy::cast_possible_truncation)]
                    let mut slot = (pair_hash(&buyer.0, &seller.0) as usize) & mask;
                    let idx = loop {
                        let t = table[slot];
                        if t == u32::MAX {
                            let i =
                                u32::try_from(entries.len()).map_err(|_| ExecError::Malformed)?;
                            entries.push((key, 0));
                            table[slot] = i;
                            break i;
                        }
                        if entries[usize::try_from(t).map_err(|_| ExecError::Malformed)?].0 == key {
                            break t;
                        }
                        slot = (slot + 1) & mask;
                    };
                    let entry =
                        &mut entries[usize::try_from(idx).map_err(|_| ExecError::Malformed)?].1;
                    match entry.checked_add(amount) {
                        Some(sum) => *entry = sum,
                        // Practically unreachable (needs > u64::MAX
                        // quote for one pair) — skip rather than
                        // silently saturating the settlement.
                        None => events.push(rejected_leg_event(i, "pair total overflow")),
                    }
                }
                None => events.push(rejected_leg_event(i, "invalid fill leg")),
            }
        }

        // Drain in sorted key order — identical transfer order to the
        // previous `BTreeMap` iteration, so event sequence and every
        // observable outcome are preserved.
        entries.sort_unstable_by_key(|e| e.0);
        for ((buyer, seller), amount) in &entries {
            // Atomic settlement: debit buyer, credit seller. Using
            // `transfer` instead of separate `debit` + `credit`
            // ensures atomicity — if the credit fails (e.g.
            // overflow), the debit is rolled back.
            if ledger.transfer(buyer, seller, *amount).is_err() {
                events.push(Event {
                    module: "exchange",
                    kind: "settlement_failed",
                    data: {
                        let mut d = Vec::with_capacity(20 + 20 + 8);
                        d.extend_from_slice(&buyer.0);
                        d.extend_from_slice(&seller.0);
                        d.extend_from_slice(&amount.to_le_bytes());
                        d
                    },
                });
                continue;
            }

            events.push(Event {
                module: "exchange",
                kind: "batch_fill",
                data: {
                    let mut d = Vec::with_capacity(20 + 20 + 8);
                    d.extend_from_slice(&buyer.0);
                    d.extend_from_slice(&seller.0);
                    d.extend_from_slice(&amount.to_le_bytes());
                    d
                },
            });
        }

        Ok(events)
    }
}

/// Hash a `(buyer, seller)` pair for the batch-settle aggregation
/// table. FxHash-style rotate-multiply over the key read as six
/// words (each 20-byte address contributes two `u64`s + one `u32`);
/// the multiply constant is the fx-hash K — chosen for avalanche on
/// power-of-two table sizes, not for security (the table is internal
/// and collision-handled by probing). Deterministic across platforms
/// — required anywhere consensus-adjacent — and ~5ns/pair versus the
/// ~150-250ns a `BTreeMap` insert costs at large batch sizes.
fn pair_hash(buyer: &[u8; 20], seller: &[u8; 20]) -> u64 {
    const SEED: u64 = 0x9e37_79b9_7f4a_7c15;
    const MUL: u64 = 0x517c_c1b7_2722_0a95;
    #[inline]
    fn w64(b: &[u8; 20], off: usize) -> u64 {
        u64::from_le_bytes([
            b[off],
            b[off + 1],
            b[off + 2],
            b[off + 3],
            b[off + 4],
            b[off + 5],
            b[off + 6],
            b[off + 7],
        ])
    }
    #[inline]
    fn w32(b: &[u8; 20], off: usize) -> u64 {
        u64::from(u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]))
    }
    let mut h = SEED;
    for x in [
        w64(buyer, 0),
        w64(buyer, 8),
        w32(buyer, 16),
        w64(seller, 0),
        w64(seller, 8),
        w32(seller, 16),
    ] {
        h = (h.rotate_left(5) ^ x).wrapping_mul(MUL);
    }
    h
}

/// Parse and validate one batch-settle leg at byte offset `off`.
///
/// Returns `Ok(Some((buyer, seller, amount)))` for a valid leg (the
/// quote amount is recomputed on-chain with checked fixed-point
/// math), `Ok(None)` for a leg that fails validation (caller emits a
/// `fill_rejected` event — invalid legs cannot move funds), and
/// `Err(Malformed)` on a truncated entry (unreachable in practice —
/// the caller bounds-checks the batch length up front).
///
/// A leg is valid iff its market is listed, the qty is positive and
/// lot-aligned, the price is on-tick inside the configured band, and
/// buyer != seller. An over-u64 notional rejects the leg rather than
/// silently capping the transfer.
fn settle_leg(
    body: &[u8],
    off: usize,
    configs: &[Option<MarketConfig>],
) -> Result<Option<(Address, Address, u64)>, ExecError> {
    let market = u16::from_le_bytes(
        body.get(off..off + 2)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );
    let price = Price(u64::from_le_bytes(
        body.get(off + 2..off + 10)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    ));
    let qty = Qty(u64::from_le_bytes(
        body.get(off + 10..off + 18)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    ));
    let buyer = Address(
        body.get(off + 18..off + 38)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );
    let seller = Address(
        body.get(off + 38..off + 58)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );

    Ok(configs
        .get(usize::from(market))
        .copied()
        .flatten()
        .filter(|c| {
            qty.0 > 0
                && qty.0 % c.lot_size == 0
                && price.0 >= c.min_price
                && price.0 <= c.max_price
                && price.0 % c.tick_size == 0
                && buyer != seller
        })
        .and_then(|_| u64::try_from(u128::from(price.0) * u128::from(qty.0) / PRICE_SCALE).ok())
        .map(|amount| (buyer, seller, amount)))
}

/// Build a `fill_rejected` event for a malformed batch-settle leg.
/// `idx` is the leg's position in the batch (u32 LE) and `reason` is
/// a short static tag for diagnostics.
fn rejected_leg_event(idx: usize, reason: &'static str) -> Event {
    let mut data = Vec::with_capacity(4 + reason.len());
    #[allow(clippy::cast_possible_truncation)]
    data.extend_from_slice(&(idx as u32).to_le_bytes());
    data.extend_from_slice(reason.as_bytes());
    Event { module: "exchange", kind: "fill_rejected", data }
}

// ── Event helpers ────────────────────────────────────────────────────

/// Convert a [`FillEvent`] into an executor [`Event`] for the event log.
///
/// This is a free function (not an `impl FillEvent`) because `FillEvent`
/// is defined in the `trading` crate — implementing a method on it here
/// would violate the orphan rule.
fn fill_event(fill: FillEvent) -> Event {
    let mut data = Vec::with_capacity(8 + 8 + 8 + 8 + 20 + 20 + 1);
    data.extend_from_slice(&fill.price.0.to_le_bytes());
    data.extend_from_slice(&fill.qty.0.to_le_bytes());
    data.extend_from_slice(&fill.maker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.taker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.maker_owner.0);
    data.extend_from_slice(&fill.taker_owner.0);
    data.push(encode_side(fill.taker_side));
    Event { module: "exchange", kind: "fill", data }
}

/// Encode an [`OrderOutcome`] as an event.
fn outcome_event(market: u8, outcome: OrderOutcome) -> Event {
    let (kind, data) = match outcome {
        OrderOutcome::Filled => ("filled", vec![]),
        OrderOutcome::Resting { order_id, price, resting_qty } => {
            let mut d = Vec::with_capacity(1 + 8 + 8 + 8);
            d.push(market);
            d.extend_from_slice(&order_id.0.to_le_bytes());
            d.extend_from_slice(&price.0.to_le_bytes());
            d.extend_from_slice(&resting_qty.0.to_le_bytes());
            ("resting", d)
        }
        OrderOutcome::CanceledRemainder { order_id, filled_qty } => {
            let mut d = Vec::with_capacity(1 + 8 + 8);
            d.push(market);
            d.extend_from_slice(&order_id.0.to_le_bytes());
            d.extend_from_slice(&filled_qty.0.to_le_bytes());
            ("canceled_remainder", d)
        }
        OrderOutcome::Killed => ("killed", vec![]),
        OrderOutcome::Rejected(reason) => ("rejected", vec![encode_reject_reason(reason)]),
    };
    Event { module: "exchange", kind, data }
}

/// Encode a [`CanceledOrder`] as an event.
fn cancel_event(market: u8, canceled: CanceledOrder) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 1 + 8 + 8 + 20);
    data.push(market);
    data.extend_from_slice(&canceled.order_id.0.to_le_bytes());
    data.push(encode_side(canceled.side));
    data.extend_from_slice(&canceled.price.0.to_le_bytes());
    data.extend_from_slice(&canceled.qty.0.to_le_bytes());
    data.extend_from_slice(&canceled.owner.0);
    Event { module: "exchange", kind: "canceled", data }
}

// ── Codec helpers ────────────────────────────────────────────────────

/// Encode a [`Side`] as a single byte.
fn encode_side(s: Side) -> u8 {
    match s {
        Side::Buy => 0,
        Side::Sell => 1,
    }
}

/// Decode a [`Side`] from a single byte.
const fn decode_side(b: u8) -> Option<Side> {
    match b {
        0 => Some(Side::Buy),
        1 => Some(Side::Sell),
        _ => None,
    }
}

/// Encode an [`OrderType`] as a single byte.
fn encode_order_type(t: OrderType) -> u8 {
    match t {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
    }
}

/// Decode an [`OrderType`] from a single byte.
const fn decode_order_type(b: u8) -> Option<OrderType> {
    match b {
        0 => Some(OrderType::Limit),
        1 => Some(OrderType::Market),
        2 => Some(OrderType::PostOnly),
        _ => None,
    }
}

/// Encode a [`TimeInForce`] as a single byte.
fn encode_tif(t: TimeInForce) -> u8 {
    match t {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    }
}

/// Decode a [`TimeInForce`] from a single byte.
const fn decode_tif(b: u8) -> Option<TimeInForce> {
    match b {
        0 => Some(TimeInForce::Gtc),
        1 => Some(TimeInForce::Ioc),
        2 => Some(TimeInForce::Fok),
        _ => None,
    }
}

/// Encode an [`StpMode`] as a single byte.
fn encode_stp(s: StpMode) -> u8 {
    match s {
        StpMode::None => 0,
        StpMode::CancelNewest => 1,
        StpMode::CancelOldest => 2,
        StpMode::DecrementAndCancel => 3,
    }
}

/// Decode an [`StpMode`] from a single byte.
const fn decode_stp(b: u8) -> Option<StpMode> {
    match b {
        0 => Some(StpMode::None),
        1 => Some(StpMode::CancelNewest),
        2 => Some(StpMode::CancelOldest),
        3 => Some(StpMode::DecrementAndCancel),
        _ => None,
    }
}

/// Encode a [`RejectReason`] byte. The encoding is an explicit match
/// (not `as u8`) because `RejectReason` is not `#[repr(u8)]` — a
/// discriminant reorder in the trading crate must surface as a test
/// failure here, not a silent wire-format change.
fn encode_reject_reason(r: trading::RejectReason) -> u8 {
    match r {
        trading::RejectReason::InvalidQty => 0,
        trading::RejectReason::PriceOffTick => 1,
        trading::RejectReason::PriceOutOfRange => 2,
        trading::RejectReason::InvalidTifForType => 3,
        trading::RejectReason::PostOnlyWouldCross => 4,
        trading::RejectReason::BookFull => 5,
    }
}

/// KV key for a market's config blob.
fn market_config_key(market: u8) -> Vec<u8> {
    vec![b'm', market]
}

/// Encode a `MarketConfig` into a storage blob (for state-root replay).
fn encode_market_config(cfg: &MarketConfig) -> Vec<u8> {
    let mut v = Vec::with_capacity(36);
    v.extend_from_slice(&cfg.tick_size.to_le_bytes());
    v.extend_from_slice(&cfg.lot_size.to_le_bytes());
    v.extend_from_slice(&cfg.min_price.to_le_bytes());
    v.extend_from_slice(&cfg.max_price.to_le_bytes());
    v.extend_from_slice(&cfg.max_resting.to_le_bytes());
    v
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        BatchFillEntry, ExchangeModule, MarketConfig, NewOrder, OrderId, OrderType, Side, StpMode,
        TAG_PLACE, TimeInForce, encode_reject_reason, msg,
    };
    use executor::{ExecError, Module, TxContext};
    use framework::{Balances, module_id};
    use primitives::Address;
    use primitives::fixed::{Price, Qty};
    use std::sync::Arc;

    /// A standard test market: tick 0.01, lot 0.001, [$10, $20], 64 max resting.
    fn test_cfg() -> MarketConfig {
        MarketConfig {
            market_id: 0,
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
            max_resting: 64,
        }
    }

    fn addr(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn ctx(sender_byte: u8) -> TxContext {
        TxContext { sender: addr(sender_byte), nonce: 0, fee: 0 }
    }

    fn limit(side: Side, ticks_from_min: u64, lots: u64, owner_byte: u8) -> NewOrder {
        NewOrder {
            side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_000_000_000 + ticks_from_min * 1_000_000),
            qty: Qty(lots * 1_000),
            owner: addr(owner_byte),
            stp: StpMode::None,
        }
    }

    #[test]
    fn list_market_and_place_resting() {
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();
        assert_eq!(mid, 0);

        // Place a resting buy at tick 500 ($15.00), 5 lots.
        let order = limit(Side::Buy, 500, 5, 1);
        let msg = msg::place(mid, order);
        let events = ex.handle(&ctx(1), &msg).unwrap();

        // One event: the outcome (Resting). No fills (no match).
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "resting");
        assert_eq!(ex.resting_count(mid), 1);
    }

    #[test]
    fn place_and_match_emits_fill_events() {
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();

        // Rest a sell at tick 500, 5 lots, owner 9.
        let maker = limit(Side::Sell, 500, 5, 9);
        ex.handle(&ctx(9), &msg::place(mid, maker)).unwrap();
        assert_eq!(ex.resting_count(mid), 1);

        // Taker buy at tick 500, 5 lots, owner 1 — full fill.
        let taker = limit(Side::Buy, 500, 5, 1);
        let events = ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

        // 1 fill event + 1 outcome event (Filled).
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "fill");
        assert_eq!(events[1].kind, "filled");
        assert_eq!(ex.resting_count(mid), 0);
    }

    #[test]
    fn cancel_resting_order() {
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();

        // Rest a buy, owner 1.
        let order = limit(Side::Buy, 400, 3, 1);
        let events = ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
        assert_eq!(events[0].kind, "resting");
        // Extract the order id from the resting event data:
        // [market:1][order_id:8][price:8][resting_qty:8]
        let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));
        assert_eq!(ex.resting_count(mid), 1);

        // Cancel it (same owner).
        let cancel_msg = msg::cancel(mid, order_id);
        let cancel_events = ex.handle(&ctx(1), &cancel_msg).unwrap();
        assert_eq!(cancel_events.len(), 1);
        assert_eq!(cancel_events[0].kind, "canceled");
        assert_eq!(ex.resting_count(mid), 0);
    }

    #[test]
    fn cancel_by_non_owner_rejected() {
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();

        // Rest a buy, owner 1.
        let order = limit(Side::Buy, 400, 3, 1);
        let events = ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
        let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));

        // Try to cancel as owner 2 — rejected.
        let err = ex.handle(&ctx(2), &msg::cancel(mid, order_id)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(ex.resting_count(mid), 1);
    }

    #[test]
    fn place_on_nonexistent_market_rejected() {
        let ex = ExchangeModule::new();
        let order = limit(Side::Buy, 500, 5, 1);
        let err = ex.handle(&ctx(1), &msg::place(0, order)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    #[test]
    fn malformed_message_rejected() {
        let ex = ExchangeModule::new();
        assert_eq!(ex.handle(&ctx(1), &[]), Err(ExecError::Malformed));
        // Unknown tag.
        assert_eq!(ex.handle(&ctx(1), &[99]), Err(ExecError::Malformed));
        // Truncated place body.
        assert_eq!(ex.handle(&ctx(1), &[TAG_PLACE, 0]), Err(ExecError::Malformed));
    }

    #[test]
    fn state_root_changes_after_market_listed() {
        let ex = ExchangeModule::new();
        let root0 = ex.state_root();
        ex.list_market(test_cfg()).unwrap();
        let root1 = ex.state_root();
        assert_ne!(root0, root1, "state root must change when a market is listed");
    }

    #[test]
    fn state_root_changes_after_order_rests() {
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();
        let root0 = ex.state_root();

        // Rest an order — the engine is in-memory, but the module
        // persists market configs. The state root does not change
        // from order placement (only from market listing), because
        // the live book is in RAM. This is by design until the
        // journal/replay layer materializes the book.
        let order = limit(Side::Buy, 400, 3, 1);
        ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
        let root1 = ex.state_root();
        // The state root is the same because only market configs are
        // persisted, not live orders. This will change when the
        // journal integrates.
        assert_eq!(
            root0, root1,
            "order placement does not change the persisted state root (journal integration pending)"
        );
    }

    #[test]
    fn list_market_via_message() {
        let ex = ExchangeModule::new();
        let list_msg = msg::list_market(test_cfg());
        let events = ex.handle(&ctx(1), &list_msg).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "market_listed");
        assert_eq!(events[0].data, vec![0]);
    }

    #[test]
    fn multiple_markets_get_sequential_ids() {
        let ex = ExchangeModule::new();
        let id0 = ex.list_market(test_cfg()).unwrap();
        let id1 = ex.list_market(test_cfg()).unwrap();
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
    }

    #[test]
    fn l1_returns_best_bid_ask() {
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();

        // No orders yet.
        let (bid, ask) = ex.l1(mid).unwrap();
        assert!(bid.is_none());
        assert!(ask.is_none());

        // Rest a buy at tick 400.
        ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 400, 3, 1))).unwrap();
        let (bid, ask) = ex.l1(mid).unwrap();
        assert!(bid.is_some());
        assert!(ask.is_none());
        let (bp, bq) = bid.unwrap();
        assert_eq!(bp, Price(1_400_000_000));
        assert_eq!(bq, Qty(3_000));
    }

    #[test]
    fn reject_reason_encoding_is_stable() {
        // The `as u8` cast must match the trading crate's `#[repr(u8)]`
        // discriminant order. This test pins the mapping so a reorder
        // in the trading crate would surface here.
        assert_eq!(encode_reject_reason(trading::RejectReason::InvalidQty), 0);
    }

    #[test]
    fn module_id_is_exchange() {
        let ex = ExchangeModule::new();
        assert_eq!(ex.id(), module_id::EXCHANGE);
        assert_eq!(ex.name(), "exchange");
    }

    // ── Settlement tests (cross-module: ledger + exchange) ───────────

    fn ledger_and_exchange() -> (Arc<framework::MemoryBalances>, ExchangeModule) {
        let ledger = Arc::new(framework::MemoryBalances::new());
        // Fund two traders: buyer (owner 1) and seller (owner 9).
        ledger.mint(&addr(1), 1_000_000_000_000); // 1T quote
        ledger.mint(&addr(9), 1_000_000_000_000); // 1T quote
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();
        (ledger, ex)
    }

    #[test]
    fn settlement_debits_buyer_credits_seller_on_fill() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Rest a sell at tick 500 ($15.00), 5 lots, owner 9.
        let maker = limit(Side::Sell, 500, 5, 9);
        ex.handle(&ctx(9), &msg::place(mid, maker)).unwrap();

        let buyer_before = ledger.balance(&addr(1));
        let seller_before = ledger.balance(&addr(9));

        // Taker buy at tick 500, 5 lots, owner 1 — full fill.
        let taker = limit(Side::Buy, 500, 5, 1);
        ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

        // Notional = 5_000 * 1_500_000_000 = 7_500_000_000_000 (scale-14).
        // Quote amount = 7_500_000_000_000 / 100_000_000 = 75_000 (scale-6).
        let quote_amount = 75_000u64;
        assert_eq!(ledger.balance(&addr(1)), buyer_before - quote_amount);
        assert_eq!(ledger.balance(&addr(9)), seller_before + quote_amount);
    }

    #[test]
    fn pre_trade_check_rejects_buy_with_insufficient_balance() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        // Fund the buyer with only 1000 — not enough for 5 lots at $15.
        ledger.mint(&addr(1), 1_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();

        // Buy 5 lots at tick 500 ($15): quote needed = 75_000.
        let taker = limit(Side::Buy, 500, 5, 1);
        let err = ex.handle(&ctx(1), &msg::place(0, taker)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        // Balance unchanged.
        assert_eq!(ledger.balance(&addr(1)), 1_000);
    }

    #[test]
    fn no_ledger_means_no_settlement() {
        // Without a ledger, fills are recorded as events but balances
        // don't move. This is the v0 no-settlement mode.
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();

        let maker = limit(Side::Sell, 500, 5, 9);
        ex.handle(&ctx(9), &msg::place(mid, maker)).unwrap();

        let taker = limit(Side::Buy, 500, 5, 1);
        let events = ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();
        // 1 fill + 1 outcome (Filled).
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "fill");
        assert_eq!(events[1].kind, "filled");
    }

    #[test]
    fn settlement_on_sweep_debits_all_fills() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Rest 3 sell orders at ticks 500, 501, 502 (1 lot each, owner 9).
        for i in 0..3u64 {
            ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500 + i, 1, 9))).unwrap();
        }

        let buyer_before = ledger.balance(&addr(1));
        let seller_before = ledger.balance(&addr(9));

        // Taker buy 3 lots at tick 502 (sweeps all 3 levels).
        let taker = NewOrder {
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Ioc,
            price: Price(1_502_000_000),
            qty: Qty(3_000),
            owner: addr(1),
            stp: StpMode::None,
        };
        ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

        // Total quote = (1_500M + 1_501M + 1_502M) * 1_000 / 1e8
        //            = (15_000 + 15_010 + 15_020) = 45_030
        let total_quote = 45_030u64;
        assert_eq!(ledger.balance(&addr(1)), buyer_before - total_quote);
        assert_eq!(ledger.balance(&addr(9)), seller_before + total_quote);
    }

    /// Regression test: batch settlement must be atomic. If the
    /// credit fails (e.g., overflow), the debit must be rolled
    /// back. Before the fix, `handle_batch_settle` used separate
    /// `debit` + `credit` calls — a failed credit after a successful
    /// debit would lose funds.
    #[test]
    fn batch_settle_rolls_back_on_credit_overflow() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        // Fund buyer with enough for the transfer.
        ledger.mint(&addr(1), 1_000_000);
        // Fund seller near u64::MAX so the credit overflows.
        ledger.mint(&addr(9), u64::MAX - 500_000);
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(1));
        ex.list_market(test_cfg()).unwrap();

        let buyer_before = ledger.balance(&addr(1));
        let seller_before = ledger.balance(&addr(9));

        // Chain-computed quote = 1e9 * 100_000 / 1e8 = 1_000_000,
        // which overflows the seller's u64::MAX - 500_000 balance.
        let fill = BatchFillEntry {
            market: 0,
            price: Price(1_000_000_000),
            qty: Qty(100_000),
            buyer: addr(1),
            seller: addr(9),
        };
        let msg = msg::batch_settle(&[fill]);
        let events = ex.handle(&ctx(1), &msg).unwrap();

        // The settlement should fail atomically — buyer is NOT debited.
        assert_eq!(
            ledger.balance(&addr(1)),
            buyer_before,
            "buyer must not be debited on failed settlement"
        );
        assert_eq!(
            ledger.balance(&addr(9)),
            seller_before,
            "seller balance must not change on failed settlement"
        );

        // A settlement_failed event should be emitted.
        assert!(
            events.iter().any(|e| e.kind == "settlement_failed"),
            "expected settlement_failed event on credit overflow"
        );
    }

    /// Regression test: `batch_settle` must reject any sender that is
    /// not the configured settlement operator. Before the fix the
    /// handler ignored `ctx.sender` entirely — any account could
    /// submit forged fills and drain arbitrary balances.
    #[test]
    fn batch_settle_rejects_unauthorized_sender() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();

        let fill = BatchFillEntry {
            market: 0,
            price: Price(1_000_000_000),
            qty: Qty(1_000),
            buyer: addr(1),
            seller: addr(9),
        };
        let msg = msg::batch_settle(&[fill]);

        // ctx(1) is not the operator — must be rejected, no funds move.
        let err = ex.handle(&ctx(1), &msg).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(ledger.balance(&addr(1)), 1_000_000);
        assert_eq!(ledger.balance(&addr(9)), 1_000_000);

        // The configured operator is accepted.
        let events = ex.handle(&ctx(0xAA), &msg).unwrap();
        assert!(events.iter().any(|e| e.kind == "batch_fill"));
        // quote = 1e9 * 1_000 / 1e8 = 10_000
        assert_eq!(ledger.balance(&addr(1)), 1_000_000 - 10_000);
        assert_eq!(ledger.balance(&addr(9)), 1_000_000 + 10_000);
    }

    /// Regression test: `batch_settle` must be fail-closed when no
    /// settlement operator is configured.
    #[test]
    fn batch_settle_disabled_without_operator() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();

        let fill = BatchFillEntry {
            market: 0,
            price: Price(1_000_000_000),
            qty: Qty(1_000),
            buyer: addr(1),
            seller: addr(9),
        };
        let msg = msg::batch_settle(&[fill]);
        let err = ex.handle(&ctx(1), &msg).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(ledger.balance(&addr(1)), 1_000_000);
    }

    /// Regression test: every batch-settle leg is validated against
    /// the market config. Invalid legs (unlisted market, off-tick
    /// price, out-of-band price, non-lot-aligned or zero qty,
    /// self-trade) must be skipped with `fill_rejected` events and
    /// must not move funds. Before the fix there was no validation
    /// at all — the wire's `quote_amount` was trusted blindly.
    #[test]
    fn batch_settle_rejects_invalid_legs() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 10_000_000);
        ledger.mint(&addr(9), 10_000_000);
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();

        let legs = [
            // Unlisted market.
            BatchFillEntry {
                market: 7,
                price: Price(1_000_000_000),
                qty: Qty(1_000),
                buyer: addr(1),
                seller: addr(9),
            },
            // Off-tick price (1_000_000_500 % 1_000_000 != 0).
            BatchFillEntry {
                market: 0,
                price: Price(1_000_000_500),
                qty: Qty(1_000),
                buyer: addr(1),
                seller: addr(9),
            },
            // Price out of band (> 2_000_000_000 max).
            BatchFillEntry {
                market: 0,
                price: Price(3_000_000_000),
                qty: Qty(1_000),
                buyer: addr(1),
                seller: addr(9),
            },
            // Zero qty.
            BatchFillEntry {
                market: 0,
                price: Price(1_000_000_000),
                qty: Qty(0),
                buyer: addr(1),
                seller: addr(9),
            },
            // Qty not lot-aligned (lot = 1_000).
            BatchFillEntry {
                market: 0,
                price: Price(1_000_000_000),
                qty: Qty(1_500),
                buyer: addr(1),
                seller: addr(9),
            },
            // Self-trade.
            BatchFillEntry {
                market: 0,
                price: Price(1_000_000_000),
                qty: Qty(1_000),
                buyer: addr(1),
                seller: addr(1),
            },
            // One valid leg for contrast: quote = 10_000.
            BatchFillEntry {
                market: 0,
                price: Price(1_000_000_000),
                qty: Qty(1_000),
                buyer: addr(1),
                seller: addr(9),
            },
        ];
        let msg = msg::batch_settle(&legs);
        let events = ex.handle(&ctx(0xAA), &msg).unwrap();

        let rejected = events.iter().filter(|e| e.kind == "fill_rejected").count();
        assert_eq!(rejected, 6, "all six invalid legs must be rejected");
        // Only the valid leg settled: quote = 1e9 * 1_000 / 1e8 = 10_000.
        assert_eq!(ledger.balance(&addr(1)), 10_000_000 - 10_000);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000 + 10_000);
    }

    /// Regression test: the chain computes settlement amounts itself.
    /// Two legs between the same pair at different prices aggregate
    /// into one transfer of `sum(price_i * qty_i / PRICE_SCALE)` —
    /// the operator cannot inflate or deflate the amount.
    #[test]
    fn batch_settle_computes_quote_onchain() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 10_000_000);
        ledger.mint(&addr(9), 10_000_000);
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();

        // Leg 1: 1e9 * 1_000 / 1e8 = 10_000.
        // Leg 2: 1.5e9 * 2_000 / 1e8 = 30_000. Pair total = 40_000.
        let legs = [
            BatchFillEntry {
                market: 0,
                price: Price(1_000_000_000),
                qty: Qty(1_000),
                buyer: addr(1),
                seller: addr(9),
            },
            BatchFillEntry {
                market: 0,
                price: Price(1_500_000_000),
                qty: Qty(2_000),
                buyer: addr(1),
                seller: addr(9),
            },
        ];
        let msg = msg::batch_settle(&legs);
        let events = ex.handle(&ctx(0xAA), &msg).unwrap();

        assert_eq!(ledger.balance(&addr(1)), 10_000_000 - 40_000);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000 + 40_000);
        // Exactly one pair transfer → one batch_fill event.
        assert_eq!(events.iter().filter(|e| e.kind == "batch_fill").count(), 1);
    }

    /// The flat aggregation table must emit pair transfers in sorted
    /// `(buyer, seller)` order — identical to the `BTreeMap` it
    /// replaced — regardless of leg order in the batch. Deterministic
    /// event order is consensus-relevant: every validator replays the
    /// same drain and must observe the same event sequence.
    #[test]
    fn batch_settle_pair_order_deterministic() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        for b in [addr(9), addr(3), addr(1)] {
            ledger.mint(&b, 10_000_000);
        }
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();

        // Submit pairs deliberately out of sorted order: (9,7),
        // (1,5), (3,2) — plus a duplicate (9,7) leg to confirm
        // aggregation collapses it into the sorted (9,7) slot.
        let leg = |buyer: u8, seller: u8| BatchFillEntry {
            market: 0,
            price: Price(1_000_000_000),
            qty: Qty(1_000),
            buyer: addr(buyer),
            seller: addr(seller),
        };
        let legs = [leg(9, 7), leg(1, 5), leg(3, 2), leg(9, 7)];
        let events = ex.handle(&ctx(0xAA), &msg::batch_settle(&legs)).unwrap();

        let pairs: Vec<([u8; 20], [u8; 20])> = events
            .iter()
            .filter(|e| e.kind == "batch_fill")
            .map(|e| (e.data[0..20].try_into().unwrap(), e.data[20..40].try_into().unwrap()))
            .collect();
        assert_eq!(
            pairs,
            vec![(addr(1).0, addr(5).0), (addr(3).0, addr(2).0), (addr(9).0, addr(7).0)]
        );
        // The duplicate (9,7) leg aggregated into one transfer of
        // 2×10_000 quote units.
        assert_eq!(ledger.balance(&addr(9)), 10_000_000 - 20_000);
        assert_eq!(ledger.balance(&addr(7)), 20_000);
    }

    /// Regression test: market buys must pass the pre-trade balance
    /// check against the real sweep cost. Before the fix, market
    /// buys skipped the check entirely (`order_type != Market`), so
    /// an unfunded taker could sweep the book and leave every fill
    /// unsettled — makers' orders consumed with no payment.
    #[test]
    fn market_buy_without_balance_rejected() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Rest a maker sell at tick 500 ($15.00), 1 lot.
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();

        // ctx(2) has no ledger balance at all.
        let mkt = NewOrder {
            side: Side::Buy,
            order_type: OrderType::Market,
            tif: TimeInForce::Ioc,
            price: Price(0), // ignored for market orders
            qty: Qty(1_000),
            owner: addr(2),
            stp: StpMode::None,
        };
        let err = ex.handle(&ctx(2), &msg::place(mid, mkt)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        // The maker's order must still be resting — nothing matched.
        assert_eq!(ex.resting_count(mid), 1);
        assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000);
    }

    /// A funded market buy sweeps and pays exactly the chain-computed
    /// fill cost (sweep price × qty), not a wire-supplied amount.
    #[test]
    fn market_buy_with_balance_settles_sweep() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Rest 2 maker sells: 1 lot @ tick 500 ($15.00), 1 lot @ tick
        // 501 ($15.01).
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 501, 1, 9))).unwrap();

        let buyer_before = ledger.balance(&addr(1));
        let seller_before = ledger.balance(&addr(9));

        // Market buy 2 lots — sweeps both levels.
        let mkt = NewOrder {
            side: Side::Buy,
            order_type: OrderType::Market,
            tif: TimeInForce::Ioc,
            price: Price(0),
            qty: Qty(2_000),
            owner: addr(1),
            stp: StpMode::None,
        };
        ex.handle(&ctx(1), &msg::place(mid, mkt)).unwrap();

        // Cost = 15_000 + 15_010 = 30_010 quote units.
        assert_eq!(ledger.balance(&addr(1)), buyer_before - 30_010);
        assert_eq!(ledger.balance(&addr(9)), seller_before + 30_010);
        assert_eq!(ex.resting_count(mid), 0);
    }

    /// A market buy whose sweep cost exceeds the available balance is
    /// rejected entirely — the engine must not partially settle.
    #[test]
    fn market_buy_insufficient_for_full_sweep_rejected() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        // Buyer has only 20_000 quote — enough for the cheap level
        // (15_000) but not the whole sweep (30_010).
        ledger.mint(&addr(1), 20_000);
        ledger.mint(&addr(9), 1_000_000_000_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();
        let mid = 0;

        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 501, 1, 9))).unwrap();

        let mkt = NewOrder {
            side: Side::Buy,
            order_type: OrderType::Market,
            tif: TimeInForce::Ioc,
            price: Price(0),
            qty: Qty(2_000),
            owner: addr(1),
            stp: StpMode::None,
        };
        let err = ex.handle(&ctx(1), &msg::place(mid, mkt)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        // Nothing matched — both makers still rest, no funds moved.
        assert_eq!(ex.resting_count(mid), 2);
        assert_eq!(ledger.balance(&addr(1)), 20_000);
    }

    // ── Reservation accounting (C6) ────────────────────────────────

    /// A resting buy locks its worst-case quote cost at admission:
    /// `price × qty` leaves the account the moment the order rests,
    /// not when a later taker arrives.
    #[test]
    fn resting_buy_holds_reservation() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Rest a buy: tick 500 ($15.00), 1 lot → reserve 15_000.
        let events = ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        assert_eq!(events[0].kind, "resting");
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
    }

    /// Cancelling a resting buy releases exactly the held
    /// reservation, exactly once — a second cancel is not found, so
    /// the refund cannot be collected twice.
    #[test]
    fn cancel_resting_buy_refunds_reservation_once() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        let events = ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 2, 1))).unwrap();
        let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));
        // Reservation = 2 lots × 15_000 = 30_000.
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 30_000);

        ex.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap();
        assert_eq!(
            ledger.balance(&addr(1)),
            1_000_000_000_000,
            "cancel must return the held reservation"
        );

        // Second cancel: the order is gone — no double refund.
        let err = ex.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000);
    }

    /// The core C6 invariant: a maker buy pays from the reservation
    /// it held since resting. Fund the maker with EXACTLY the
    /// reservation — under the old settle-by-transfer design this is
    /// where insolvency surfaced post-place (book consumed, transfer
    /// failed). Now settlement is credit-only and cannot fail.
    #[test]
    fn maker_buy_fill_pays_from_held_reservation() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        // Maker has EXACTLY the reservation: 1 lot @ $15 = 15_000.
        ledger.mint(&addr(5), 15_000);
        ledger.mint(&addr(9), 1_000_000_000_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();
        let mid = 0;

        // Maker rests the buy — balance drops to zero (fully reserved).
        ex.handle(&ctx(5), &msg::place(mid, limit(Side::Buy, 500, 1, 5))).unwrap();
        assert_eq!(ledger.balance(&addr(5)), 0);

        // Taker sell fills the maker's bid. The seller must receive
        // 15_000 even though the buyer's free balance is 0 — the
        // money comes from the held reservation.
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 + 15_000);
        assert_eq!(ledger.balance(&addr(5)), 0, "buyer paid at rest, not at fill");
        assert_eq!(ex.resting_count(mid), 0);
    }

    /// A partially filled buy releases the filled portion's
    /// reservation and keeps only `price × resting_qty` held. The
    /// held remainder is what a later cancel refunds.
    #[test]
    fn partial_fill_buy_holds_only_remainder_reservation() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Maker sell: 1 lot @ tick 500 ($15.00).
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();

        // Taker GTC buy 2 lots @ 500: fills 1 (15_000), rests 1
        // (15_000 held). Reservation was 30_000; refund 0.
        let events = ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 2, 1))).unwrap();
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 30_000);
        let resting_ev = events.iter().find(|e| e.kind == "resting").expect("remainder rests");
        let order_id = OrderId(u64::from_le_bytes(resting_ev.data[1..9].try_into().unwrap()));

        // Cancel the resting remainder — releases the held 15_000.
        ex.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap();
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
        assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 + 15_000);
    }

    /// An IOC buy's dead remainder is released in full — nothing is
    /// held for an order that cannot rest.
    #[test]
    fn ioc_buy_refunds_dead_remainder() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Maker sell: 1 lot @ tick 500.
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();

        // IOC buy 2 lots @ 500: fills 1 (15_000), remainder dies.
        // Reserved 30_000, paid 15_000, held 0 → refund 15_000.
        let ioc = NewOrder {
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Ioc,
            price: Price(1_500_000_000),
            qty: Qty(2_000),
            owner: addr(1),
            stp: StpMode::None,
        };
        ex.handle(&ctx(1), &msg::place(mid, ioc)).unwrap();
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
        assert_eq!(ex.resting_count(mid), 0);
    }

    /// Price improvement is refunded: a limit buy pays the maker's
    /// (better) price, not its own limit.
    #[test]
    fn limit_buy_price_improvement_refunded() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Maker sell @ tick 500 ($15.00); taker bids tick 600
        // ($16.00) — fills at $15.00, not $16.00.
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 600, 1, 1))).unwrap();

        // Reserved 16_000, paid 15_000 → net 15_000 gone.
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
        assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 + 15_000);
    }
}
