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

/// The on-chain identity of a registered order: `(owner, client_id)`.
///
/// The owner is the account that submitted the `register_order`
/// transaction (the tx signature is the order's authorization), and
/// `client_id` is the owner-chosen order identifier — the same value
/// the off-chain matching server sees as the order request's
/// per-account nonce, so a fill can name both parties' orders without
/// the matcher learning chain-assigned ids. Keys are unique per owner:
/// a second registration under the same key is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OrderKey {
    /// Order owner — the account that signed the registration.
    pub owner: primitives::Address,
    /// Owner-chosen client order id (the matcher order-request nonce).
    pub client_id: u64,
}

/// A pre-matched fill entry for batch settlement from the off-chain
/// matching server. Encoded as
/// `[market:2][price:8][qty:8][buy_owner:20][buy_id:8][sell_owner:20][sell_id:8]`
/// = 74 bytes.
///
/// The wire carries no claimed settlement amount and no bare
/// counterparties: each leg names the two [`OrderKey`]s it fills, and
/// the chain derives buyer and seller from the registered orders —
/// orders the owners themselves signed on-chain. The settlement amount
/// is recomputed as `price * qty / PRICE_SCALE` after validating the
/// leg against the market config AND both orders' limits and remaining
/// quantities, so a forged or replayed entry cannot move funds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchFillEntry {
    /// Market the fill executed on — selects the config used for
    /// tick/lot/price-band validation and must match both orders'
    /// registered market.
    pub market: u16,
    /// Execution price (scale-8). Must satisfy both limits:
    /// `sell.limit <= price <= buy.limit`.
    pub price: Price,
    /// Traded quantity (scale-6). Consumes both orders' remaining
    /// quantity and may not exceed either.
    pub qty: Qty,
    /// The registered buy order being filled.
    pub buy: OrderKey,
    /// The registered sell order being filled.
    pub sell: OrderKey,
}

/// A resting off-chain-matched order registered on-chain.
///
/// Registration is the authorization the batch-settle path verifies:
/// the owner's signed tx fixed `market`, `side`, `limit_price`, and
/// `qty`, and every fill against the order consumes `remaining`. A
/// buy order additionally escrows its worst-case quote cost at
/// registration (`limit_price × qty / PRICE_SCALE`, debited into
/// `reserved`), so batch settlement can never fail on buyer
/// insolvency — the funds are already held. `reserved` is released
/// piecewise per fill (`limit × fill_qty`, split into the seller's
/// payment and the buyer's price-improvement rebate) and the residue
/// is refunded when the order completes or is canceled.
///
/// Sell orders carry `reserved == 0` in v0: there is no base-asset
/// custody, so a sell's obligation is untracked (quote-only settlement,
/// same as the on-chain book path).
#[derive(Debug, Clone, Copy)]
struct RegisteredOrder {
    /// Market the order is authorized on (must be listed).
    market: u16,
    /// Buy or sell — a fill leg must name a buy key and a sell key.
    side: Side,
    /// The owner's limit price (scale-8): the maximum a buy pays,
    /// the minimum a sell accepts.
    limit_price: u64,
    /// Unfilled authorized quantity (scale-6).
    remaining: u64,
    /// Quote units still escrowed for this order (scale-6). Buys
    /// only; equals the as-yet-unreleased portion of the
    /// registration-time debit.
    reserved: u64,
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
/// is `[market:2][price:8][qty:8][buy_owner:20][buy_id:8][sell_owner:20][sell_id:8]`
/// = 74 bytes, naming the two registered orders it consumes. The body
/// is `[fill_count:4][fill entries...]`.
const TAG_BATCH_SETTLE: u8 = 3;

/// Register-order message tag: puts an off-chain-matched order's
/// authorization on-chain so batch-settle legs can reference it.
/// Body: `[market:2][side:1][price:8][qty:8][client_id:8]` = 27
/// bytes; the tx sender is the owner and the signature is the
/// authorization. A buy debits `price × qty / PRICE_SCALE` of quote
/// into the order's escrow at registration.
const TAG_REGISTER_ORDER: u8 = 4;

/// Cancel-registered-order message tag: removes the sender's
/// registered order and refunds its remaining escrow.
/// Body: `[client_id:8]` = 8 bytes.
const TAG_CANCEL_REGISTERED: u8 = 5;

/// Size of a single fill entry in a batch-settle message:
/// 2 + 8 + 8 + 20 + 8 + 20 + 8 = 74 bytes.
const FILL_ENTRY_LEN: usize = 74;

/// Maximum number of fills in a single batch-settle message. Prevents
/// a byzantine settlement operator from submitting a huge batch that
/// causes excessive processing. `65_536` fills × 74 bytes = ~4.8 MiB.
const MAX_BATCH_FILLS: usize = 65_536;

/// Maximum live registered orders module-wide.
///
/// Registered orders are committed state: `state_root` and snapshot
/// export iterate the whole map every block, so an uncapped registry
/// would be a free state-bloat vector for sell orders (which escrow
/// nothing). `65_536` matches the book-side `max_resting` default and
/// bounds the canon section at ~3.5 MiB worst case — the same order
/// as a fully populated book. Buy orders are additionally
/// economically bounded by their escrow, but the cap is what stops a
/// registration spammer from crowding out the map.
const MAX_REGISTERED_ORDERS: usize = 65_536;

// ── Message sizes (body, excluding the 1-byte tag) ───────────────────

/// `[market:1][side:1][type:1][tif:1][stp:1][price:8][qty:8]` = 21.
const PLACE_BODY_LEN: usize = 21;
/// `[market:1][order_id:8]` = 9.
const CANCEL_BODY_LEN: usize = 9;
/// `[tick:8][lot:8][min:8][max:8][max_resting:4]` = 36.
const LIST_MARKET_BODY_LEN: usize = 36;
/// `[market:2][side:1][price:8][qty:8][client_id:8]` = 27.
const REGISTER_BODY_LEN: usize = 27;
/// `[client_id:8]` = 8.
const CANCEL_REGISTERED_BODY_LEN: usize = 8;

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
    /// The validator-committee handle gating the `TAG_LIST_MARKET`
    /// transaction path. `None` (bare `new()`) means the tx path is
    /// *closed*: only the in-process `list_market` call (genesis /
    /// node setup) works. That is the safe default — an
    /// unauthenticated listing eagerly allocates the market's
    /// `max_resting` arenas (~96 MiB at the protocol bound), so the
    /// tx path must require committee quorum before one executes.
    committee: Option<Arc<dyn framework::Committee + Send + Sync>>,
    /// Committee endorsements for pending `TAG_LIST_MARKET`
    /// proposals — the full tagged message is the action payload, so
    /// byte-identical configs accumulate voting power and the market
    /// is listed only once endorsing power strictly exceeds
    /// two-thirds of the committee. One validator's signature is a
    /// vote, never a command.
    endorsements: framework::Endorsements,
}

struct Inner {
    /// One engine per market, indexed by `MarketId` (a `u8`).
    markets: Vec<Option<MatchingEngine>>,
    /// Reusable fill buffer — cleared and refilled per `place` call.
    fills: Vec<FillEvent>,
    /// On-chain authorizations for off-chain-matched orders, keyed by
    /// `(owner, client_id)`. Every batch-settle leg consumes from two
    /// of these — the operator can only settle fills the owners
    /// themselves signed for. Committed state (canonical section).
    registered: BTreeMap<OrderKey, RegisteredOrder>,
}

/// The committed state a snapshot decodes into — the per-market
/// engines, pending governance endorsements, and the registered-order
/// map, in canonical layout order.
type CommittedState =
    (Vec<Option<MatchingEngine>>, framework::Endorsements, BTreeMap<OrderKey, RegisteredOrder>);

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
                registered: BTreeMap::new(),
            }),
            store: Mutex::new(BTreeMap::new()),
            ledger: None,
            settlement_operator: None,
            committee: None,
            endorsements: framework::Endorsements::new(),
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

    /// Attach the validator-committee handle that authorizes the
    /// `TAG_LIST_MARKET` transaction path. Each list-market tx then
    /// records a committee endorsement for its exact config payload;
    /// the market is listed only when endorsing power strictly
    /// exceeds two-thirds.
    ///
    /// Without a committee the tx path rejects everything — closed
    /// by default, since a listing eagerly allocates the market's
    /// `max_resting` arenas and an unauthenticated listing is a
    /// memory-exhaustion primitive.
    #[must_use]
    pub fn with_committee(
        mut self,
        committee: Arc<dyn framework::Committee + Send + Sync>,
    ) -> Self {
        self.committee = Some(committee);
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

    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut entries = Vec::new();
        let mut book_bytes = Vec::new();
        w.put_count(inner.markets.len());
        for engine in &inner.markets {
            match engine {
                Some(e) => {
                    w.put_u8(1);
                    book_bytes.clear();
                    e.write_canonical_state(&mut book_bytes, &mut entries);
                    w.put_bytes(&book_bytes);
                }
                None => {
                    w.put_u8(0);
                }
            }
        }
        // Pending list-market endorsements are future-affecting
        // state: the tally decides whether the next endorsement
        // lists a market, so replicas holding different tallies must
        // diverge in the root.
        self.endorsements.write_canonical(w);
        // Registered off-chain-matched orders are committed state:
        // they decide whether the next batch-settle leg is
        // authorized, and their `remaining`/`reserved` move real
        // escrow — two replicas holding different registries would
        // settle differently. Encoded sorted by `(owner, client_id)`
        // (BTreeMap order is the canonical order). Trailing section —
        // decoders written before this field existed reject the
        // extra bytes via the staged reader's end-of-stream check,
        // while this decoder treats an absent section as an empty
        // registry.
        w.put_count(inner.registered.len());
        for (key, order) in &inner.registered {
            w.put_addr(&key.owner);
            w.put_u64(key.client_id);
            w.put_u16(order.market);
            w.put_u8(encode_side(order.side));
            w.put_u64(order.limit_price);
            w.put_u64(order.remaining);
            w.put_u64(order.reserved);
        }
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema.
    ///
    /// `slots` is the destination's fixed market-slot count: a blob
    /// claiming a different array length cannot represent this
    /// module's state.
    fn decode_committed(
        r: &mut framework::CanonicalReader<'_>,
        store: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
        slots: usize,
    ) -> Option<CommittedState> {
        let n = r.get_count()?;
        if n != slots {
            return None;
        }
        let mut markets = Vec::with_capacity(n);
        for i in 0..n {
            match r.get_u8()? {
                0 => markets.push(None),
                1 => {
                    let bytes = r.get_bytes()?;
                    let engine =
                        MatchingEngine::from_canonical_state(bytes, |c| DenseBook::new(*c)).ok()?;
                    // Store↔engine binding: a listed market must carry
                    // its byte-identical config under `m/{id}`. Without
                    // this check a crafted blob could pair engines with
                    // mismatched store entries and still hash to a
                    // self-consistent root.
                    let key = market_config_key(u8::try_from(i).ok()?);
                    match store.get(&key) {
                        Some(v) if *v == encode_market_config(engine.config()) => {}
                        _ => return None,
                    }
                    markets.push(Some(engine));
                }
                _ => return None,
            }
        }
        // Reverse direction: every `m/{id}` store key must name a
        // listed market — a config without an engine is dead state
        // no live code path produces.
        for key in store.keys() {
            if let [b'm', id] = key.as_slice() {
                match markets.get(usize::from(*id)) {
                    Some(Some(_)) => {}
                    _ => return None,
                }
            }
        }
        // Trailing section: the pending-endorsement tally written by
        // `write_committed`. Decode is strict (duplicates rejected)
        // so a crafted blob cannot smuggle a second opinion about
        // who endorsed what.
        let endorsements = framework::Endorsements::read_canonical(r)?;
        // Final trailing section: the registered-order map. Tolerant
        // tail — a blob written before the section existed decodes as
        // an empty registry, while the staged reader still rejects a
        // truncated or non-canonical one. Duplicate keys are rejected
        // (a `BTreeMap` insert would silently absorb them).
        let mut registered = BTreeMap::new();
        if r.remaining() > 0 {
            let count = r.get_count()?;
            for _ in 0..count {
                let key = OrderKey { owner: r.get_addr()?, client_id: r.get_u64()? };
                let order = RegisteredOrder {
                    market: r.get_u16()?,
                    side: decode_side(r.get_u8()?)?,
                    limit_price: r.get_u64()?,
                    remaining: r.get_u64()?,
                    reserved: r.get_u64()?,
                };
                if registered.insert(key, order).is_some() {
                    return None; // Duplicate key — non-canonical.
                }
            }
        }
        Some((markets, endorsements, registered))
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

    /// Build a register-order message: authorize an off-chain-matched
    /// order on-chain under `(sender, client_id)`. The sender's
    /// signature is the order's authorization; batch-settle legs can
    /// only fill within the registered market/side/limit/qty.
    ///
    /// `client_id` is the owner-chosen order id — the same value the
    /// matching server sees as the order request's per-account nonce.
    /// A buy escrows `price × qty / PRICE_SCALE` of quote at
    /// registration.
    #[allow(clippy::too_many_arguments)]
    pub fn register_order(
        market: u16,
        side: trading::Side,
        price: u64,
        qty: u64,
        client_id: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::REGISTER_BODY_LEN);
        msg.push(super::TAG_REGISTER_ORDER);
        msg.extend_from_slice(&market.to_le_bytes());
        msg.push(encode_side(side));
        msg.extend_from_slice(&price.to_le_bytes());
        msg.extend_from_slice(&qty.to_le_bytes());
        msg.extend_from_slice(&client_id.to_le_bytes());
        msg
    }

    /// Build a cancel-registered message: remove the sender's
    /// registered order and refund its remaining escrow.
    pub fn cancel_registered(client_id: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::CANCEL_REGISTERED_BODY_LEN);
        msg.push(super::TAG_CANCEL_REGISTERED);
        msg.extend_from_slice(&client_id.to_le_bytes());
        msg
    }

    /// Build a batch-settle message for pre-matched fills from the
    /// off-chain matching server. Each fill is encoded as
    /// `[market:2][price:8][qty:8][buy_owner:20][buy_id:8][sell_owner:20][sell_id:8]`
    /// (74 bytes) — the two [`OrderKey`](crate::OrderKey)s the leg
    /// consumes, not bare counterparties. The wire carries no claimed
    /// settlement amount — the chain recomputes
    /// `price * qty / PRICE_SCALE` per leg out of the buy order's
    /// escrow.
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
            msg.extend_from_slice(&f.buy.owner.0);
            msg.extend_from_slice(&f.buy.client_id.to_le_bytes());
            msg.extend_from_slice(&f.sell.owner.0);
            msg.extend_from_slice(&f.sell.client_id.to_le_bytes());
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

                let Inner { markets, .. } = &mut *inner;
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
                // Reject an invalid config before recording an
                // endorsement — pending actions are a bounded set, so
                // a proposal that can never apply must not occupy a
                // slot. This also bounds the allocation `list_market`
                // performs at quorum: `validate` caps `max_resting`
                // at `MAX_RESTING_LIMIT`.
                cfg.validate()
                    .map_err(|e| ExecError::ModuleRejected(format!("list_market: {e}")))?;
                drop(inner);
                // Committee-quorum gate: a listing eagerly allocates
                // the market's order-pool and id-map arenas, so an
                // unauthenticated listing is a memory-exhaustion
                // primitive. Each tx endorses the exact tagged
                // message; the market lists only once endorsing power
                // strictly exceeds two-thirds of the committee.
                let Some(committee) = self.committee.clone() else {
                    return Err(ExecError::ModuleRejected(
                        "list_market: no committee wired".to_string(),
                    ));
                };
                match self.endorsements.record(msg, &ctx.sender, committee.as_ref())? {
                    framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                        module: "exchange",
                        kind: "list_market_endorse",
                        data: body.to_vec(),
                    }]),
                    framework::EndorsementOutcome::Quorum => match self.list_market(cfg) {
                        Ok(id) => Ok(vec![Event {
                            module: "exchange",
                            kind: "market_listed",
                            data: vec![id],
                        }]),
                        // Quorum reached but the listing no longer
                        // applies (e.g. all slots filled while the
                        // proposal accumulated votes).
                        Err(_) => Ok(vec![Event {
                            module: "exchange",
                            kind: "list_market_stale",
                            data: body.to_vec(),
                        }]),
                    },
                }
            }

            TAG_BATCH_SETTLE => self.handle_batch_settle(ctx, body, &mut inner),

            TAG_REGISTER_ORDER => self.handle_register(ctx, body, &mut inner),

            TAG_CANCEL_REGISTERED => self.handle_cancel_registered(ctx, body, &mut inner),

            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, _height: Height) {}

    fn state_root(&self) -> Hash {
        // C8: commit EVERY field that can affect future execution.
        // The KV store (market configs) is only part of it — the
        // live order books decide future fills, cancels, and
        // settlement, so identical roots across validators must
        // prove identical books. Section order is fixed and
        // consensus-critical.
        //
        // Excluded: `fills` (per-call scratch), `ledger` /
        // `settlement_operator` (assembly wiring, not tx-mutated
        // state).
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        w.root()
    }

    /// Export the committed state as one canonical blob —
    /// `canon ‖ store`. The canon section is the `state_root`
    /// preimage, so a peer can verify the claimed root before
    /// installing anything (audit 3.2).
    fn export_state(&self) -> Option<storage::Snapshot> {
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        Some(storage::Snapshot {
            height: 0,
            entries: vec![(
                framework::state_blob_key(),
                framework::encode_state_blob(w.as_bytes(), &self.store),
            )],
        })
    }

    /// Verify a staged snapshot's claimed root without mutating:
    /// decode the blob, check the store section hashes to the
    /// committed subtree root, fully decode the fields, then hash
    /// the canonical preimage.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let slots =
            self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).markets.len();
        let (canon, _decoded, _store) = framework::stage_blob_snapshot(snapshot, |r, store| {
            Self::decode_committed(r, store, slots)
        })?;
        Ok(framework::canon_root(canon))
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then the fields swap in
    /// atomically (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let slots =
            self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).markets.len();
        let (_canon, (markets, endorsements, registered), store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        *self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = store;
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.markets = markets;
        inner.registered = registered;
        // `fills` is per-call scratch — clear it so a buffer left
        // mid-transaction cannot leak across the import boundary.
        inner.fills.clear();
        drop(inner);
        // Restore the pending-endorsement tally so an in-flight
        // listing resumes accumulating exactly where the snapshot
        // left it — the tally is committed state, not local cache.
        self.endorsements.replace_with(endorsements);
        Ok(())
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
        let Inner { markets, fills, .. } = inner;
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
        // `ObserveRemovals` never restricts a fill — it records
        // every maker the sweep shrank or removed without one (STP
        // prevention), so the quote those orders held at rest can be
        // released below. A resting buy IS its reservation; a maker
        // the engine deletes unreported would strand that quote
        // forever.
        let mut removed: Vec<trading::MakerRemoval> = Vec::new();
        let outcome = match engine.place_with_cap(
            order,
            fills,
            &mut trading::ObserveRemovals { removed: &mut removed },
        ) {
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
        // Release maker holds + report every non-fill book change
        // the sweep applied, so downstream accounting sees each
        // obligation the book released — a maker the engine deleted
        // silently would be invisible to settlement reconciliation.
        self.release_maker_holds(market, &removed, &mut events)?;
        Ok(events)
    }

    /// Release quote the sweep freed without a fill and emit one
    /// event per removal/decrement: a removed resting buy held
    /// `price × removed_qty` since it rested; a decremented one
    /// holds `price × remaining` now, so the released slice is
    /// `price × removed_qty` in both cases. Resting sells hold no
    /// quote reservation (base-asset custody is a separate build) —
    /// nothing to refund there. The credit cannot overflow: it
    /// returns funds debited from this same account at rest time.
    fn release_maker_holds(
        &self,
        market: u8,
        removed: &[trading::MakerRemoval],
        events: &mut Vec<Event>,
    ) -> Result<(), ExecError> {
        if let Some(ledger) = &self.ledger {
            for r in removed {
                if r.side == Side::Buy && r.removed_qty > 0 {
                    let refund = u64::try_from(
                        u128::from(r.price) * u128::from(r.removed_qty) / PRICE_SCALE,
                    )
                    .map_err(|_| {
                        ExecError::ModuleRejected("STP release exceeds u64 quote range".to_string())
                    })?;
                    if refund > 0 {
                        ledger.credit(&r.owner, refund).map_err(|_| {
                            ExecError::ModuleRejected("STP release refund failed".to_string())
                        })?;
                    }
                }
            }
        }
        for r in removed {
            events.push(removal_event(market, *r));
        }
        Ok(())
    }

    /// Handle a register-order message: put an off-chain-matched
    /// order's authorization on-chain under `(sender, client_id)`.
    ///
    /// Registration is what makes a batch-settle leg authorized: the
    /// sender's signature fixes `market`, `side`, `limit_price`, and
    /// `qty`, so the settlement operator can later fill the order
    /// only within those bounds. A buy additionally escrows
    /// `price × qty / PRICE_SCALE` quote at registration — the
    /// reservation every later fill pays out of, which is why batch
    /// settlement can never fail on buyer insolvency.
    ///
    /// Rejects: malformed body, unlisted market, non-positive or
    /// off-config price/qty (same tick/lot/band rules as a fill
    /// leg), a duplicate `(owner, client_id)` key, the module-wide
    /// registered-order cap, missing ledger wiring, and (buys) an
    /// escrow the sender cannot cover.
    fn handle_register(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != REGISTER_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let market = u16::from_le_bytes(body[0..2].try_into().map_err(|_| ExecError::Malformed)?);
        let side = decode_side(body[2]).ok_or(ExecError::Malformed)?;
        let price = u64::from_le_bytes(body[3..11].try_into().map_err(|_| ExecError::Malformed)?);
        let qty = u64::from_le_bytes(body[11..19].try_into().map_err(|_| ExecError::Malformed)?);
        let client_id =
            u64::from_le_bytes(body[19..27].try_into().map_err(|_| ExecError::Malformed)?);

        let Inner { markets, registered, .. } = &mut *inner;
        let cfg = markets
            .get(usize::from(market))
            .and_then(Option::as_ref)
            .map(|e| *e.config())
            .ok_or_else(|| ExecError::ModuleRejected(format!("market {market} does not exist")))?;
        // The order itself must be placeable: same tick/lot/band
        // rules a fill leg enforces, applied at authorization time so
        // an off-book order can never be registered.
        if qty == 0
            || qty % cfg.lot_size != 0
            || price < cfg.min_price
            || price > cfg.max_price
            || price % cfg.tick_size != 0
        {
            return Err(ExecError::ModuleRejected(
                "register: price/qty outside market config".to_string(),
            ));
        }

        let key = OrderKey { owner: ctx.sender, client_id };
        if registered.contains_key(&key) {
            return Err(ExecError::ModuleRejected(
                "register: duplicate client order id".to_string(),
            ));
        }
        if registered.len() >= MAX_REGISTERED_ORDERS {
            return Err(ExecError::ModuleRejected("register: order registry full".to_string()));
        }

        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::ModuleRejected("register requires ledger wiring".to_string())
        })?;

        // Escrow (buys): debit `limit × qty` up front — every fill
        // against this order pays out of the escrow, so settlement
        // can never draw on an insolvent buyer. Reject rather than
        // cap on u64 overflow: saturating would silently change what
        // the buyer authorized.
        let reserved = if side == Side::Buy {
            let amount =
                u64::try_from(u128::from(price) * u128::from(qty) / PRICE_SCALE).map_err(|_| {
                    ExecError::ModuleRejected(
                        "register: escrow exceeds u64 quote range".to_string(),
                    )
                })?;
            ledger.debit(&ctx.sender, amount).map_err(|_| {
                ExecError::ModuleRejected(
                    "register: insufficient balance for buy escrow".to_string(),
                )
            })?;
            amount
        } else {
            0
        };

        registered.insert(
            key,
            RegisteredOrder { market, side, limit_price: price, remaining: qty, reserved },
        );
        Ok(vec![Event {
            module: "exchange",
            kind: "order_registered",
            data: {
                let mut d = Vec::with_capacity(20 + 8 + 2 + 1 + 8 + 8);
                d.extend_from_slice(&ctx.sender.0);
                d.extend_from_slice(&client_id.to_le_bytes());
                d.extend_from_slice(&market.to_le_bytes());
                d.push(encode_side(side));
                d.extend_from_slice(&price.to_le_bytes());
                d.extend_from_slice(&qty.to_le_bytes());
                d
            },
        }])
    }

    /// Handle a cancel-registered message: remove the sender's order
    /// and refund its remaining escrow.
    ///
    /// The escrow refund is credited BEFORE the order is removed, so
    /// a credit failure (balance overflow — impossible while supply
    /// stays under `u64::MAX`) leaves the order live rather than
    /// stranding its escrow.
    fn handle_cancel_registered(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != CANCEL_REGISTERED_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let client_id =
            u64::from_le_bytes(body[0..8].try_into().map_err(|_| ExecError::Malformed)?);
        let key = OrderKey { owner: ctx.sender, client_id };
        let Some(order) = inner.registered.get(&key) else {
            return Err(ExecError::ModuleRejected("cancel: order not found".to_string()));
        };
        let refund = order.reserved;
        if refund > 0 {
            let ledger = self.ledger.as_ref().ok_or_else(|| {
                ExecError::ModuleRejected("cancel requires ledger wiring".to_string())
            })?;
            ledger.credit(&ctx.sender, refund).map_err(|_| {
                ExecError::ModuleRejected("cancel: escrow refund failed".to_string())
            })?;
        }
        inner.registered.remove(&key);
        Ok(vec![Event {
            module: "exchange",
            kind: "order_canceled",
            data: {
                let mut d = Vec::with_capacity(20 + 8 + 8);
                d.extend_from_slice(&ctx.sender.0);
                d.extend_from_slice(&client_id.to_le_bytes());
                d.extend_from_slice(&refund.to_le_bytes());
                d
            },
        }])
    }

    /// Handle a batch-settle message: apply pre-matched fills from
    /// the off-chain matching server against on-chain registered
    /// orders. Each valid fill leg credits the seller a
    /// **chain-computed** amount out of the buy order's escrow and
    /// returns the buyer's price-improvement rebate — no re-matching,
    /// no trust in operator-supplied amounts, and no bare
    /// counterparties: the operator can only settle between orders
    /// the owners themselves signed for.
    ///
    /// Body format: `[fill_count:4 LE][fill entries...]`
    /// Each fill entry:
    /// `[market:2][price:8][qty:8][buy_owner:20][buy_id:8][sell_owner:20][sell_id:8]`.
    ///
    /// # Security
    ///
    /// - **Authorization:** only `ctx.sender == settlement_operator`
    ///   (the genesis-configured matcher identity) may submit batch
    ///   settlements. But the operator is NOT a balance-transfer
    ///   authority: every leg must name two live registered orders,
    ///   and the fill is checked against what those owners signed
    ///   for — market, side, limit price, and remaining quantity.
    ///   A leg that fails validation is skipped with a
    ///   `fill_rejected` event — unauthorized legs cannot move funds.
    /// - **Replay safety:** a fill consumes both orders'
    ///   `remaining`. Resubmitting the same batch (or the same fills
    ///   re-encoded under a new batch) re-references orders whose
    ///   quantity is already consumed, so every replayed leg fails
    ///   its remaining-quantity check — unique fills come from
    ///   consumption, not an unbounded fill-id set.
    /// - **Amounts:** the settlement amount is recomputed on-chain as
    ///   `price * qty / PRICE_SCALE` with checked `u128`/`u64` math.
    ///   The buy side is never debited at settle time: its escrow was
    ///   debited at registration, so a leg credits the seller and
    ///   rebates the buyer's price improvement out of the escrow
    ///   slice `buy.limit * qty / PRICE_SCALE` — insolvency during
    ///   settlement is impossible by construction.
    /// - **Aggregation:** seller payments accumulate per (buyer,
    ///   seller) pair in an open-addressed flat index map (one probe
    ///   vs the `BTreeMap`'s ~16-level pointer chase per leg); the
    ///   drain sorts by key, so credit order is deterministic and
    ///   each pair settles in one `ledger.credit`. Buyer rebates and
    ///   per-order consumption accumulate the same way and apply in
    ///   sorted order.
    ///
    /// A pair whose seller credit fails is skipped with a
    /// `settlement_failed` event and its legs are voided wholesale —
    /// no order quantity is consumed and no rebate released, so a
    /// failed leg has exactly zero economic effect. Other legs in
    /// the batch still settle — one overflowing account cannot halt
    /// settlement for the whole batch.
    ///
    /// `inner` is the already-held module lock (batch settle never
    /// mutates the books — only the registered-order map).
    fn handle_batch_settle(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        // Authorization gate: the settlement operator is the only
        // account allowed to submit fills — but only against orders
        // the owners signed for (see `settle_leg`).
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

        let Inner { markets, registered, .. } = &mut *inner;

        // Snapshot the market configs once — batch settle never
        // mutates the books, so one pass over `markets` serves every
        // leg.
        let configs: Vec<Option<MarketConfig>> =
            markets.iter().map(|m| m.as_ref().map(|e| *e.config())).collect();

        // ── Pass 1: parse + validate every leg ────────────────────
        // Each valid leg produces a `LegPlan` and accumulates its
        // seller payment into the (buyer, seller) pair map. The
        // `consumed` scratch bounds each order's cumulative quantity
        // across the whole batch BEFORE anything mutates, so two
        // legs can never spend the same authorized quantity.
        //
        // Pair aggregation uses an open-addressed flat index map
        // over a flat `entries` Vec instead of a `BTreeMap`: the
        // tree version costs ~150-250ns/leg at large batch sizes
        // (16+ levels of pointer-chasing per lookup on a 40-byte
        // key), while the flat probe is ~15-25ns — one hash, 1-3
        // cache-resident slots. `entries` keeps insertion order; the
        // drain sorts by key, preserving the BTreeMap's exact
        // deterministic credit order, so observable behavior is
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
        let mut plans: Vec<LegPlan> = Vec::with_capacity(fill_count);
        let mut consumed: BTreeMap<OrderKey, u64> = BTreeMap::new();
        let mut events = Vec::new();
        for i in 0..fill_count {
            match settle_leg(body, 4 + i * FILL_ENTRY_LEN, &configs, registered, &mut consumed)? {
                Some(plan) => {
                    // Flat-map lookup: hash the pair, linear-probe
                    // the table for a matching key or an empty slot.
                    // On miss, append to `entries` and record the
                    // index; on hit, accumulate in place.
                    let key = (plan.buyer, plan.seller);
                    let mask = table_cap - 1;
                    // Masked to < 2^17 slots on the same line — the
                    // u64->usize cast cannot truncate a meaningful
                    // index on any supported target.
                    #[allow(clippy::cast_possible_truncation)]
                    let mut slot = (pair_hash(&plan.buyer.0, &plan.seller.0) as usize) & mask;
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
                    match entry.checked_add(plan.pays) {
                        Some(sum) => {
                            *entry = sum;
                            plans.push(plan);
                        }
                        // Practically unreachable (needs > u64::MAX
                        // quote for one pair) — void the leg rather
                        // than silently saturating the settlement.
                        None => events.push(rejected_leg_event(i, "pair total overflow")),
                    }
                }
                None => events.push(rejected_leg_event(i, "invalid fill leg")),
            }
        }

        // ── Drain 1: pay sellers, one credit per pair ─────────────
        // Sorted key order — identical to the previous `BTreeMap`
        // iteration, so event sequence is deterministic. The buyer
        // side needs no debit: the escrow was taken at registration.
        // A pair whose credit fails is voided wholesale below — its
        // legs consume nothing.
        entries.sort_unstable_by_key(|e| e.0);
        let mut failed_pairs: std::collections::BTreeSet<(Address, Address)> =
            std::collections::BTreeSet::new();
        for ((buyer, seller), amount) in &entries {
            if ledger.credit(seller, *amount).is_err() {
                failed_pairs.insert((*buyer, *seller));
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

        // ── Pass 2 + drains: apply the surviving legs ────────────
        // Order consumption, buyer rebates, and residue refunds run
        // in `consume_and_release` — every mutation is derived from
        // the validated plans, so a voided pair's legs consume
        // nothing.
        consume_and_release(&plans, &failed_pairs, registered, ledger, &mut events);

        Ok(events)
    }
}

/// Apply validated fill legs to the registered-order map: consume
/// `remaining`, release buy-side escrow, pay price-improvement
/// rebates, and refund the residue of fully consumed orders.
///
/// Phases (all iteration is over sorted `BTreeMap`s — deterministic
/// event order):
///
/// 1. **Accumulate** each surviving leg into per-order deltas
///    (quantity consumed, escrow released, rebate portion tracked
///    separately) and per-buyer rebate totals.
/// 2. **Rebate drain**: credit each buyer's rebate. A failed credit
///    withholds that buyer's rebate — the payment still settled, but
///    the rebate stays in the order's escrow (refunded with the
///    residue) rather than vanishing.
/// 3. **Consumption**: `remaining` drops by the consumed quantity,
///    `reserved` by the released slice minus any withheld rebate. A
///    fully consumed order is removed and its residue — floor-
///    division dust plus any withheld rebate — refunded.
fn consume_and_release(
    plans: &[LegPlan],
    failed_pairs: &std::collections::BTreeSet<(Address, Address)>,
    registered: &mut BTreeMap<OrderKey, RegisteredOrder>,
    ledger: &Arc<dyn framework::Balances + Send + Sync>,
    events: &mut Vec<Event>,
) {
    // ── Accumulate deltas ───────────────────────────────────────
    // Per order: quantity consumed, escrow released, and the
    // rebate portion of the release (tracked separately so a
    // failed rebate credit can leave it escrowed). Per buyer:
    // total rebate to release.
    let mut deltas: BTreeMap<OrderKey, OrderDelta> = BTreeMap::new();
    let mut rebates: BTreeMap<Address, u64> = BTreeMap::new();
    for plan in plans {
        if failed_pairs.contains(&(plan.buyer, plan.seller)) {
            continue;
        }
        let buy = deltas.entry(plan.buy).or_default();
        buy.consumed += plan.qty;
        buy.released += plan.release;
        buy.rebate += plan.release - plan.pays;
        deltas.entry(plan.sell).or_default().consumed += plan.qty;
        let rebate = plan.release - plan.pays;
        if rebate > 0 {
            *rebates.entry(plan.buyer).or_default() += rebate;
        }
    }

    // ── Rebate drain ────────────────────────────────────────────
    // Sorted address order. A rebate credit that fails is withheld.
    let mut failed_rebates: std::collections::BTreeSet<Address> = std::collections::BTreeSet::new();
    for (buyer, amount) in &rebates {
        if ledger.credit(buyer, *amount).is_err() {
            failed_rebates.insert(*buyer);
            events.push(Event {
                module: "exchange",
                kind: "reservation_release_failed",
                data: {
                    let mut d = Vec::with_capacity(20 + 8);
                    d.extend_from_slice(&buyer.0);
                    d.extend_from_slice(&amount.to_le_bytes());
                    d
                },
            });
            continue;
        }
        events.push(Event {
            module: "exchange",
            kind: "reservation_released",
            data: {
                let mut d = Vec::with_capacity(20 + 8);
                d.extend_from_slice(&buyer.0);
                d.extend_from_slice(&amount.to_le_bytes());
                d
            },
        });
    }

    // ── Consumption + residue refunds ───────────────────────────
    let mut completed: Vec<(OrderKey, Address, u64)> = Vec::new();
    for (key, delta) in &deltas {
        let Some(order) = registered.get_mut(key) else { continue };
        order.remaining = order.remaining.saturating_sub(delta.consumed);
        let withheld = if failed_rebates.contains(&key.owner) { delta.rebate } else { 0 };
        order.reserved = order.reserved.saturating_sub(delta.released.saturating_sub(withheld));
        if order.remaining == 0 {
            completed.push((*key, key.owner, order.reserved));
        }
    }
    for (key, owner, residue) in completed {
        registered.remove(&key);
        if residue == 0 {
            continue;
        }
        if ledger.credit(&owner, residue).is_err() {
            // The order is dead; a refund failure strands its
            // residue. Impossible while supply stays below
            // `u64::MAX` — the event keeps it visible.
            events.push(Event {
                module: "exchange",
                kind: "reservation_release_failed",
                data: {
                    let mut d = Vec::with_capacity(20 + 8);
                    d.extend_from_slice(&owner.0);
                    d.extend_from_slice(&residue.to_le_bytes());
                    d
                },
            });
            continue;
        }
        events.push(Event {
            module: "exchange",
            kind: "escrow_refunded",
            data: {
                let mut d = Vec::with_capacity(20 + 8 + 8);
                d.extend_from_slice(&owner.0);
                d.extend_from_slice(&key.client_id.to_le_bytes());
                d.extend_from_slice(&residue.to_le_bytes());
                d
            },
        });
    }
}

/// A validated batch-settle leg, planned but not yet applied.
///
/// Constructed only after `settle_leg` has resolved both orders and
/// checked market, sides, crossing, config, and the batch-wide
/// remaining-quantity bound.
struct LegPlan {
    /// The buy order being consumed (`buy.owner` is the buyer).
    buy: OrderKey,
    /// The sell order being consumed (`sell.owner` is the seller).
    sell: OrderKey,
    /// Buyer address (== `buy.owner`) — kept for the pair key and
    /// rebate drain without a second map lookup.
    buyer: Address,
    /// Seller address (== `sell.owner`).
    seller: Address,
    /// Filled quantity (scale-6).
    qty: u64,
    /// The seller's payment: `floor(price × qty / PRICE_SCALE)`.
    pays: u64,
    /// The escrow slice this leg releases:
    /// `floor(buy.limit × qty / PRICE_SCALE)`. Always `>= pays`
    /// (`price <= buy.limit` is a leg-validity rule); the difference
    /// is the buyer's price-improvement rebate.
    release: u64,
}

/// Per-order accumulated effects of the legs that survived the
/// seller-credit drain.
#[derive(Default)]
struct OrderDelta {
    /// Total quantity consumed (scale-6).
    consumed: u64,
    /// Total escrow released by those legs (buys only).
    released: u64,
    /// The rebate portion of `released` — tracked separately so a
    /// failed rebate credit leaves exactly that much still escrowed.
    rebate: u64,
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

/// Parse and validate one batch-settle leg at byte offset `off`,
/// resolving both order keys against the registered-order map.
///
/// Returns `Ok(Some(LegPlan))` for a valid leg, `Ok(None)` for a leg
/// that fails validation (caller emits a `fill_rejected` event —
/// invalid legs cannot move funds), and `Err(Malformed)` on a
/// truncated entry (unreachable in practice — the caller
/// bounds-checks the batch length up front).
///
/// A leg is valid iff:
/// - both order keys name live registered orders — a buy and a sell
///   respectively, both on the leg's market, with distinct owners;
/// - the price crosses: `sell.limit <= price <= buy.limit` (each
///   party only ever fills inside the price they signed for);
/// - market config holds: positive lot-aligned qty, on-tick price
///   inside the configured band;
/// - neither order's `remaining` is exceeded by the leg PLUS the
///   quantity earlier legs in this batch already consumed — the
///   `consumed` scratch is what makes two legs in one batch unable
///   to spend the same authorized quantity, and what makes a
///   replayed batch fail outright.
///
/// `pays`/`release` are recomputed on-chain with checked
/// fixed-point math; an over-u64 notional rejects the leg rather
/// than silently capping the transfer.
fn settle_leg(
    body: &[u8],
    off: usize,
    configs: &[Option<MarketConfig>],
    registered: &BTreeMap<OrderKey, RegisteredOrder>,
    consumed: &mut BTreeMap<OrderKey, u64>,
) -> Result<Option<LegPlan>, ExecError> {
    let market = u16::from_le_bytes(
        body.get(off..off + 2)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );
    let price = u64::from_le_bytes(
        body.get(off + 2..off + 10)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );
    let qty = u64::from_le_bytes(
        body.get(off + 10..off + 18)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );
    let buy = OrderKey {
        owner: Address(
            body.get(off + 18..off + 38)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ),
        client_id: u64::from_le_bytes(
            body.get(off + 38..off + 46)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ),
    };
    let sell = OrderKey {
        owner: Address(
            body.get(off + 46..off + 66)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ),
        client_id: u64::from_le_bytes(
            body.get(off + 66..off + 74)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ),
    };

    let (Some(buy_order), Some(sell_order)) = (registered.get(&buy), registered.get(&sell)) else {
        return Ok(None); // A leg naming no live order is unauthorized.
    };

    // Role + market binding: the buy key must be a buy order, the
    // sell key a sell order, both on this leg's market — and never
    // the same account on both sides.
    if buy_order.side != Side::Buy
        || sell_order.side != Side::Sell
        || buy_order.market != market
        || sell_order.market != market
        || buy.owner == sell.owner
    {
        return Ok(None);
    }

    // Crossing: the fill price must lie inside both limits — the
    // buyer never pays above their limit, the seller never accepts
    // below theirs. `sell.limit > buy.limit` (no crossing) rejects.
    if price < sell_order.limit_price || price > buy_order.limit_price {
        return Ok(None);
    }

    // Market config: listed market, positive lot-aligned qty,
    // on-tick price inside the band.
    let cfg_ok = configs.get(usize::from(market)).copied().flatten().is_some_and(|c| {
        qty > 0
            && qty % c.lot_size == 0
            && price >= c.min_price
            && price <= c.max_price
            && price % c.tick_size == 0
    });
    if !cfg_ok {
        return Ok(None);
    }

    // Batch-wide remaining bound: this leg plus everything earlier
    // legs already took from each order must fit its `remaining`.
    // `consumed` is updated only for valid legs, so a rejected leg
    // consumes nothing.
    let buy_used = consumed.get(&buy).copied().unwrap_or(0);
    let sell_used = consumed.get(&sell).copied().unwrap_or(0);
    let Some(buy_total) = buy_used.checked_add(qty) else { return Ok(None) };
    let Some(sell_total) = sell_used.checked_add(qty) else { return Ok(None) };
    if buy_total > buy_order.remaining || sell_total > sell_order.remaining {
        return Ok(None);
    }

    // Amounts: pays at the fill price, release at the buy limit —
    // checked u128 math; over-u64 notionals reject the leg.
    let (Some(pays), Some(release)) = (
        u64::try_from(u128::from(price) * u128::from(qty) / PRICE_SCALE).ok(),
        u64::try_from(u128::from(buy_order.limit_price) * u128::from(qty) / PRICE_SCALE).ok(),
    ) else {
        return Ok(None);
    };

    consumed.insert(buy, buy_total);
    consumed.insert(sell, sell_total);
    Ok(Some(LegPlan { buy, sell, buyer: buy.owner, seller: sell.owner, qty, pays, release }))
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

/// Encode a non-fill book change (STP removal or decrement) as an
/// event: `[market][order_id][side][price][removed_qty][remaining][owner]`.
/// `remaining == 0` means the order is gone (`stp_cancel`), `> 0` a
/// decrement (`stp_decrement`).
fn removal_event(market: u8, r: trading::MakerRemoval) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 1 + 8 + 8 + 8 + 20);
    data.push(market);
    data.extend_from_slice(&r.order_id.0.to_le_bytes());
    data.push(encode_side(r.side));
    data.extend_from_slice(&r.price.to_le_bytes());
    data.extend_from_slice(&r.removed_qty.to_le_bytes());
    data.extend_from_slice(&r.remaining.to_le_bytes());
    data.extend_from_slice(&r.owner.0);
    let kind = if r.remaining == 0 { "stp_cancel" } else { "stp_decrement" };
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

    /// Register an off-chain-matched order on-chain under
    /// `(owner_byte, client_id)` on market 0. `price`/`qty` are raw
    /// scale-8/scale-6 values; a buy escrows `price × qty /
    /// PRICE_SCALE` at registration.
    fn register(ex: &ExchangeModule, owner: u8, client_id: u64, side: Side, price: u64, qty: u64) {
        ex.handle(&ctx(owner), &msg::register_order(0, side, price, qty, client_id))
            .expect("registration must succeed");
    }

    /// A fill leg between two registered orders.
    fn leg(
        market: u16,
        price: u64,
        qty: u64,
        buy_owner: u8,
        buy_id: u64,
        sell_owner: u8,
        sell_id: u64,
    ) -> BatchFillEntry {
        BatchFillEntry {
            market,
            price: Price(price),
            qty: Qty(qty),
            buy: crate::OrderKey { owner: addr(buy_owner), client_id: buy_id },
            sell: crate::OrderKey { owner: addr(sell_owner), client_id: sell_id },
        }
    }

    /// The standard fixture: a funded buyer and seller with orders
    /// registered on market 0 — buy `(1, 1)` at `buy_price`, sell
    /// `(9, 1)` at `sell_price`, each for `qty` units.
    fn registered_pair(
        ledger: &Arc<framework::MemoryBalances>,
        ex: &ExchangeModule,
        buy_price: u64,
        sell_price: u64,
        qty: u64,
    ) {
        ledger.mint(&addr(1), 10_000_000_000);
        ledger.mint(&addr(9), 10_000_000_000);
        register(ex, 1, 1, Side::Buy, buy_price, qty);
        register(ex, 9, 1, Side::Sell, sell_price, qty);
    }

    /// A committee stub treating `addr(1)` as the sole validator —
    /// the tx-path tests for the gated `TAG_LIST_MARKET` listing.
    struct SingleValidatorCommittee;

    impl framework::Committee for SingleValidatorCommittee {
        fn is_active_validator(&self, a: &Address) -> bool {
            *a == addr(1)
        }
        fn active_validator_count(&self) -> usize {
            1
        }
        fn power(&self, a: &Address) -> u64 {
            u64::from(self.is_active_validator(a))
        }
        fn total_power(&self) -> u64 {
            1
        }
    }

    /// A two-member committee stub — `addr(1)` and `addr(2)` each
    /// carry one unit of power, so neither reaches the two-thirds
    /// quorum alone: endorsement-gated paths need both.
    struct TwoValidatorCommittee;

    impl framework::Committee for TwoValidatorCommittee {
        fn is_active_validator(&self, a: &Address) -> bool {
            *a == addr(1) || *a == addr(2)
        }
        fn active_validator_count(&self) -> usize {
            2
        }
        fn power(&self, a: &Address) -> u64 {
            u64::from(self.is_active_validator(a))
        }
        fn total_power(&self) -> u64 {
            2
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

        // C8: a resting order is future-affecting state — it can
        // match, be canceled, or settle — so it MUST move the state
        // root even though the book lives in memory rather than the
        // KV store. Identical roots across validators must prove
        // identical books.
        let order = limit(Side::Buy, 400, 3, 1);
        ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
        let root1 = ex.state_root();
        assert_ne!(root0, root1, "a resting order must change the state root");
    }

    #[test]
    fn state_root_changes_after_cancel() {
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();
        let order = limit(Side::Buy, 400, 3, 1);
        let events = ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
        let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));
        let root0 = ex.state_root();
        ex.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap();
        let root1 = ex.state_root();
        assert_ne!(root0, root1, "canceling a resting order must change the state root");
    }

    #[test]
    fn state_root_changes_after_fill() {
        let ex = ExchangeModule::new();
        let mid = ex.list_market(test_cfg()).unwrap();
        // Rest a 5-lot sell; a 3-lot taker buy partially consumes it
        // — the surviving resting qty is different book state.
        let maker = limit(Side::Sell, 500, 5, 9);
        ex.handle(&ctx(9), &msg::place(mid, maker)).unwrap();
        let root0 = ex.state_root();
        let taker = limit(Side::Buy, 500, 3, 1);
        ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();
        let root1 = ex.state_root();
        assert_ne!(root0, root1, "a fill must change the state root");
    }

    #[test]
    fn list_market_via_message() {
        // A single-validator committee reaches quorum on the first
        // endorsement — the tx path then lists exactly like the
        // in-process call.
        let ex = ExchangeModule::new().with_committee(Arc::new(SingleValidatorCommittee));
        let list_msg = msg::list_market(test_cfg());
        let events = ex.handle(&ctx(1), &list_msg).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "market_listed");
        assert_eq!(events[0].data, vec![0]);
    }

    /// The `TAG_LIST_MARKET` tx path is fail-closed without a
    /// committee: an unauthenticated listing eagerly allocates the
    /// market's `max_resting` arenas, so a bare module must reject
    /// it outright rather than allocate on any sender's word.
    #[test]
    fn list_market_tx_rejected_without_committee() {
        let ex = ExchangeModule::new();
        let list_msg = msg::list_market(test_cfg());
        let err = ex.handle(&ctx(1), &list_msg).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
        assert_eq!(ex.resting_count(0), 0, "no market may be listed");
    }

    /// A listing is a governance action: one validator's signature
    /// endorses the exact config payload; the market lists only once
    /// endorsing power strictly exceeds two-thirds of the committee.
    #[test]
    fn list_market_requires_committee_quorum() {
        let ex = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
        let list_msg = msg::list_market(test_cfg());

        let events = ex.handle(&ctx(1), &list_msg).unwrap();
        assert_eq!(events[0].kind, "list_market_endorse", "one endorsement must not list");
        assert!(ex.l1(0).is_none(), "no market exists yet");

        let events = ex.handle(&ctx(2), &list_msg).unwrap();
        assert_eq!(events[0].kind, "market_listed", "quorum lists the market");
        assert_eq!(events[0].data, vec![0]);
    }

    /// A non-validator's tx cannot even start a listing proposal —
    /// `power == 0` senders are rejected before an endorsement
    /// occupies the bounded pending-action set.
    #[test]
    fn list_market_rejects_powerless_sender() {
        let ex = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
        let err = ex.handle(&ctx(9), &msg::list_market(test_cfg())).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
    }

    /// The bounded pending set must never hold a proposal that
    /// cannot apply: a config failing `MarketConfig::validate` —
    /// here a `max_resting` above the protocol's `MAX_RESTING_LIMIT`,
    /// which would make `list_market` reserve oversized arenas — is
    /// rejected before an endorsement is recorded.
    #[test]
    fn list_market_tx_rejects_unbounded_max_resting() {
        let ex = ExchangeModule::new().with_committee(Arc::new(SingleValidatorCommittee));
        let mut cfg = test_cfg();
        cfg.max_resting = trading::MAX_RESTING_LIMIT + 1;
        let err = ex.handle(&ctx(1), &msg::list_market(cfg)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
    }

    /// Pending endorsements are future-affecting state: a replica
    /// that has not recorded the first validator's vote must diverge
    /// in `state_root`, or it would silently disagree about whether
    /// the next endorsement lists a market.
    #[test]
    fn list_market_endorsement_changes_state_root() {
        let ex = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
        let root0 = ex.state_root();
        ex.handle(&ctx(1), &msg::list_market(test_cfg())).unwrap();
        let root1 = ex.state_root();
        assert_ne!(root0, root1, "a recorded endorsement is committed state");
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

    /// Regression test: a failed seller credit must void the leg
    /// wholesale — no quantity consumed, no escrow released. The buy
    /// side's escrow was debited at registration, so the proof is
    /// that the full `reserved` comes back at cancel afterward.
    #[test]
    fn batch_settle_failed_credit_voids_leg() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        // Fund buyer with exactly the escrow the order will debit:
        // 1e9 * 100_000 / 1e8 = 1_000_000.
        ledger.mint(&addr(1), 1_000_000);
        // Fund seller near u64::MAX so the credit overflows.
        ledger.mint(&addr(9), u64::MAX - 500_000);
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(1));
        ex.list_market(test_cfg()).unwrap();

        register(&ex, 1, 1, Side::Buy, 1_000_000_000, 100_000);
        register(&ex, 9, 1, Side::Sell, 1_000_000_000, 100_000);
        // Registration escrowed the full 1_000_000.
        assert_eq!(ledger.balance(&addr(1)), 0);

        // Chain-computed quote = 1e9 * 100_000 / 1e8 = 1_000_000,
        // which overflows the seller's u64::MAX - 500_000 balance.
        let fill = leg(0, 1_000_000_000, 100_000, 1, 1, 9, 1);
        let events = ex.handle(&ctx(1), &msg::batch_settle(&[fill])).unwrap();
        assert!(
            events.iter().any(|e| e.kind == "settlement_failed"),
            "expected settlement_failed event on credit overflow"
        );
        assert_eq!(
            ledger.balance(&addr(9)),
            u64::MAX - 500_000,
            "seller balance must not change on failed settlement"
        );

        // The leg was voided wholesale: the order still holds its
        // full remaining quantity and escrow — canceling it refunds
        // the entire 1_000_000, proving nothing was consumed.
        let ev = ex.handle(&ctx(1), &msg::cancel_registered(1)).unwrap();
        assert_eq!(ev[0].kind, "order_canceled");
        assert_eq!(ledger.balance(&addr(1)), 1_000_000);
    }

    /// Regression test: `batch_settle` must reject any sender that is
    /// not the configured settlement operator. Before the fix the
    /// handler ignored `ctx.sender` entirely — any account could
    /// submit forged fills and drain arbitrary balances.
    #[test]
    fn batch_settle_rejects_unauthorized_sender() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 1_000);
        // Buy escrow debited at registration: 1e9 * 1_000 / 1e8 = 10_000.
        let buyer_after_register = ledger.balance(&addr(1));

        let fill = leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1);
        let msg = msg::batch_settle(&[fill]);

        // ctx(1) is not the operator — must be rejected, no funds move.
        let err = ex.handle(&ctx(1), &msg).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(ledger.balance(&addr(1)), buyer_after_register);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000);

        // The configured operator is accepted.
        let events = ex.handle(&ctx(0xAA), &msg).unwrap();
        assert!(events.iter().any(|e| e.kind == "batch_fill"));
        // Fill at the limit → zero rebate: the whole 10_000 escrow
        // slice pays the seller.
        assert_eq!(ledger.balance(&addr(1)), buyer_after_register);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 + 10_000);
    }

    /// Regression test: `batch_settle` must be fail-closed when no
    /// settlement operator is configured.
    #[test]
    fn batch_settle_disabled_without_operator() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();
        registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 1_000);

        let fill = leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1);
        let msg = msg::batch_settle(&[fill]);
        let err = ex.handle(&ctx(1), &msg).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        // Nothing moved: the seller never got paid and the buy
        // order's escrow stays held.
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000);
    }

    /// Regression test: every batch-settle leg is validated against
    /// the market config AND the registered orders' authorization.
    /// Legs failing either layer (unlisted market, off-tick price,
    /// out-of-band price, non-lot-aligned or zero qty, self-trade,
    /// unknown order key, wrong side for the key, price outside an
    /// order's limit, quantity beyond the order's remaining) are
    /// skipped with `fill_rejected` events and move no funds.
    #[test]
    fn batch_settle_rejects_invalid_legs() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();

        // Working pair: buy (1,1) limit $15 qty 100k, sell (9,1)
        // limit $10 qty 100k — the valid leg and the config-invalid
        // legs all reference it.
        registered_pair(&ledger, &ex, 1_500_000_000, 1_000_000_000, 100_000);
        // Self-trade pair: owner 1 holds a sell order too.
        register(&ex, 1, 2, Side::Sell, 1_000_000_000, 10_000);
        // Small pair for the over-remaining leg: 1 lot authorized.
        ledger.mint(&addr(3), 10_000_000_000);
        ledger.mint(&addr(4), 10_000_000_000);
        register(&ex, 3, 1, Side::Buy, 1_500_000_000, 1_000);
        register(&ex, 4, 1, Side::Sell, 1_000_000_000, 1_000);
        // Non-crossing pair for the limit violations: buy $12 max.
        ledger.mint(&addr(5), 10_000_000_000);
        ledger.mint(&addr(6), 10_000_000_000);
        register(&ex, 5, 1, Side::Buy, 1_200_000_000, 10_000);
        register(&ex, 6, 1, Side::Sell, 1_000_000_000, 10_000);
        // High sell limit for the below-limit leg.
        ledger.mint(&addr(8), 10_000_000_000);
        register(&ex, 8, 1, Side::Sell, 1_800_000_000, 10_000);

        let legs = [
            // Unlisted market (orders live on market 0).
            leg(7, 1_000_000_000, 1_000, 1, 1, 9, 1),
            // Off-tick price (1_000_000_500 % 1_000_000 != 0).
            leg(0, 1_000_000_500, 1_000, 1, 1, 9, 1),
            // Price out of band (> 2_000_000_000 max).
            leg(0, 3_000_000_000, 1_000, 1, 1, 9, 1),
            // Zero qty.
            leg(0, 1_000_000_000, 0, 1, 1, 9, 1),
            // Qty not lot-aligned (lot = 1_000).
            leg(0, 1_000_000_000, 1_500, 1, 1, 9, 1),
            // Self-trade: same owner on both sides.
            leg(0, 1_000_000_000, 1_000, 1, 1, 1, 2),
            // Unregistered order key (1, 99) was never registered.
            leg(0, 1_000_000_000, 1_000, 1, 99, 9, 1),
            // Wrong role: the sell order (9,1) as the buy key.
            leg(0, 1_000_000_000, 1_000, 9, 1, 1, 2),
            // Price above the buy's $12 limit.
            leg(0, 1_500_000_000, 1_000, 5, 1, 6, 1),
            // Price below the sell's $18 limit (crossing exists:
            // buy limit $15 ≥ sell $10 but fill is below $18).
            leg(0, 1_500_000_000, 1_000, 1, 1, 8, 1),
            // Qty beyond both orders' remaining (1 lot authorized).
            leg(0, 1_000_000_000, 2_000, 3, 1, 4, 1),
            // One valid leg for contrast: quote = 1e9*1000/1e8 = 10_000.
            leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1),
        ];
        let msg = msg::batch_settle(&legs);
        let events = ex.handle(&ctx(0xAA), &msg).unwrap();

        let rejected = events.iter().filter(|e| e.kind == "fill_rejected").count();
        assert_eq!(rejected, 11, "all eleven invalid legs must be rejected");
        // Only the valid leg settled: seller got 10_000 of quote.
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 + 10_000);
    }

    /// Regression test: the chain computes settlement amounts itself.
    /// Two legs between the same pair at different prices aggregate
    /// into one credit of `sum(price_i * qty_i / PRICE_SCALE)` —
    /// the operator cannot inflate or deflate the amount.
    #[test]
    fn batch_settle_computes_quote_onchain() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        // Buy limit $15 covers both legs; escrow = 1.5e9*3_000/1e8 =
        // 45_000 at registration.
        registered_pair(&ledger, &ex, 1_500_000_000, 1_000_000_000, 3_000);

        // Leg 1: 1e9 * 1_000 / 1e8 = 10_000 (rebate 5_000).
        // Leg 2: 1.5e9 * 2_000 / 1e8 = 30_000 (rebate 0).
        // Seller total = 40_000; released escrow = 45_000.
        let legs =
            [leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1), leg(0, 1_500_000_000, 2_000, 1, 1, 9, 1)];
        let msg = msg::batch_settle(&legs);
        let events = ex.handle(&ctx(0xAA), &msg).unwrap();

        // Buyer net = −40_000 from the post-registration balance
        // (escrow 45_000 − rebate 5_000 − pays 40_000).
        assert_eq!(ledger.balance(&addr(1)), 10_000_000_000 - 40_000);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 + 40_000);
        // Exactly one pair credit → one batch_fill event; one buyer
        // rebate → one reservation_released event.
        assert_eq!(events.iter().filter(|e| e.kind == "batch_fill").count(), 1);
        assert_eq!(events.iter().filter(|e| e.kind == "reservation_released").count(), 1);
    }

    /// The flat aggregation table must emit pair transfers in sorted
    /// `(buyer, seller)` order — identical to the `BTreeMap` it
    /// replaced — regardless of leg order in the batch. Deterministic
    /// event order is consensus-relevant: every validator replays the
    /// same drain and must observe the same event sequence.
    #[test]
    fn batch_settle_pair_order_deterministic() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        // Register an order pair per counterparty: buys (9,1), (1,1),
        // (3,1); sells (7,1), (5,1), (2,1).
        for (buyer, seller) in [(9u8, 7u8), (1, 5), (3, 2)] {
            ledger.mint(&addr(buyer), 10_000_000_000);
            ledger.mint(&addr(seller), 10_000_000_000);
            register(&ex, buyer, 1, Side::Buy, 1_000_000_000, 10_000);
            register(&ex, seller, 1, Side::Sell, 1_000_000_000, 10_000);
        }

        // Submit pairs deliberately out of sorted order: (9,7),
        // (1,5), (3,2) — plus a duplicate (9,7) leg to confirm
        // aggregation collapses it into the sorted (9,7) slot.
        let legs = [
            leg(0, 1_000_000_000, 1_000, 9, 1, 7, 1),
            leg(0, 1_000_000_000, 1_000, 1, 1, 5, 1),
            leg(0, 1_000_000_000, 1_000, 3, 1, 2, 1),
            leg(0, 1_000_000_000, 1_000, 9, 1, 7, 1),
        ];
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
        // The duplicate (9,7) leg aggregated into one credit of
        // 2×10_000 quote units paid out of the buy order's escrow.
        assert_eq!(ledger.balance(&addr(7)), 10_000_000_000 + 20_000);
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

    /// An STP-removed resting buy releases its held quote — a
    /// resting buy IS its reservation, so deleting the order
    /// without reporting the removal would strand `price × qty`
    /// forever.
    #[test]
    fn stp_cancel_oldest_releases_maker_reservation() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        // Owner 1 rests a buy: 10 lots @ tick 500 → holds 150_000.
        let maker = limit(Side::Buy, 500, 10, 1);
        ex.handle(&ctx(1), &msg::place(mid, maker)).unwrap();
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 150_000);

        // The same owner sells with CancelOldest: the resting buy is
        // removed with no fill — its reservation must come back.
        let taker = NewOrder { stp: StpMode::CancelOldest, ..limit(Side::Sell, 500, 10, 1) };
        let events = ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000);
        assert!(events.iter().any(|e| e.kind == "stp_cancel"));
        // The resting buy is gone; the taker's sell rests instead.
        assert_eq!(ex.resting_count(mid), 1);
    }

    /// A partial STP decrement releases only the consumed slice —
    /// the maker's remaining reservation tracks the live book qty.
    #[test]
    fn stp_decrement_releases_consumed_slice() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        let maker = limit(Side::Buy, 500, 10, 1);
        ex.handle(&ctx(1), &msg::place(mid, maker)).unwrap();

        // Same owner sells 4 lots with DecrementAndCancel: the
        // maker shrinks 10 → 6 with no fill; refund 4 lots = 60_000.
        let taker = NewOrder { stp: StpMode::DecrementAndCancel, ..limit(Side::Sell, 500, 4, 1) };
        let events = ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 90_000);
        let dec = events.iter().find(|e| e.kind == "stp_decrement").expect("decrement event");
        // Data tail: [removed_qty:8][remaining:8][owner:20].
        let remaining = u64::from_le_bytes(dec.data[26..34].try_into().unwrap());
        assert_eq!(remaining, 6_000);

        // A later cancel refunds only what the book still holds:
        // price × 6 lots = 90_000 — no double-release of the
        // consumed slice.
        ex.handle(&ctx(1), &msg::cancel(mid, OrderId(0))).unwrap();
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000);
    }

    /// Snapshot round-trip: a market with resting orders on both
    /// sides must export, verify, and re-import byte-identically —
    /// the imported module's root must equal the source's (audit
    /// 3.2).
    #[test]
    fn state_snapshot_round_trips() {
        let src = ExchangeModule::new();
        let mid = src.list_market(test_cfg()).unwrap();
        src.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 5, 9))).unwrap();
        src.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 300, 2, 1))).unwrap();
        src.handle(&ctx(2), &msg::place(mid, limit(Side::Buy, 300, 3, 2))).unwrap();

        let snapshot = src.export_state().expect("exchange exports state");
        assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

        let dst = ExchangeModule::new();
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), src.state_root());
        assert_eq!(dst.resting_count(mid), 3);
        assert_eq!(dst.l1(mid), src.l1(mid));
    }

    /// A pending list-market endorsement is committed state: after
    /// a snapshot round-trip the imported module resumes the tally
    /// exactly where the source left it — the second validator's
    /// endorsement must reach quorum and list.
    #[test]
    fn state_snapshot_preserves_pending_endorsements() {
        let src = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
        src.handle(&ctx(1), &msg::list_market(test_cfg())).unwrap();

        let snapshot = src.export_state().expect("exchange exports state");
        assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

        let dst = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), src.state_root());

        let events = dst.handle(&ctx(2), &msg::list_market(test_cfg())).unwrap();
        assert_eq!(events[0].kind, "market_listed", "restored tally reaches quorum");
    }

    /// A truncated blob and a non-canonical stream must both fail
    /// inspection — the claimed root is never trusted over the bytes.
    #[test]
    fn state_snapshot_rejects_corruption() {
        let src = ExchangeModule::new();
        src.list_market(test_cfg()).unwrap();
        let mut snapshot = src.export_state().unwrap();
        snapshot.entries[0].1.truncate(12);
        assert!(src.inspect_state(&snapshot).is_err());
        assert!(ExchangeModule::new().import_state(&snapshot).is_err());
    }

    // ── Registered-order authorization (batch settlement) ─────────

    /// Registration escrows the buy's worst-case cost up front and
    /// records the order under `(owner, client_id)`. A duplicate key
    /// is rejected — replayed registrations cannot double-authorize.
    #[test]
    fn register_order_escrows_and_dedups() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();

        // Buy 5 lots at $15: escrow = 1.5e9 * 5_000 / 1e8 = 75_000.
        let events = ex
            .handle(&ctx(1), &msg::register_order(0, Side::Buy, 1_500_000_000, 5_000, 7))
            .unwrap();
        assert_eq!(events[0].kind, "order_registered");
        assert_eq!(ledger.balance(&addr(1)), 1_000_000 - 75_000);

        // Same key again → rejected (a second signed tx with the
        // same client_id is a new authorization attempt, never a
        // silent overwrite).
        let err = ex
            .handle(&ctx(1), &msg::register_order(0, Side::Buy, 1_500_000_000, 5_000, 7))
            .unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));

        // Sells escrow nothing.
        ex.handle(&ctx(9), &msg::register_order(0, Side::Sell, 1_000_000_000, 5_000, 3)).unwrap();
        assert_eq!(ledger.balance(&addr(9)), 0);
    }

    /// Registration validates the order itself: unlisted market,
    /// off-config price/qty, and a buy escrow the sender cannot
    /// cover are all rejected — an off-book or unfunded order can
    /// never become fillable.
    #[test]
    fn register_order_validates() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();

        // Unlisted market.
        assert!(matches!(
            ex.handle(&ctx(1), &msg::register_order(7, Side::Sell, 1_000_000_000, 1_000, 1))
                .unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        // Off-tick price.
        assert!(matches!(
            ex.handle(&ctx(1), &msg::register_order(0, Side::Sell, 1_000_000_500, 1_000, 1))
                .unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        // Zero qty.
        assert!(matches!(
            ex.handle(&ctx(1), &msg::register_order(0, Side::Sell, 1_000_000_000, 0, 1))
                .unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        // Buy escrow exceeds the sender's balance (needs 10_000,
        // has 1_000).
        assert!(matches!(
            ex.handle(&ctx(1), &msg::register_order(0, Side::Buy, 1_000_000_000, 1_000, 1))
                .unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        // The failed registration must not have debited anything.
        assert_eq!(ledger.balance(&addr(1)), 1_000);
    }

    /// A leg that references an order the owner never registered is
    /// rejected and moves no funds — the operator cannot fabricate
    /// authorization.
    #[test]
    fn batch_settle_rejects_unregistered_order() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        ledger.mint(&addr(1), 10_000_000_000);
        ledger.mint(&addr(9), 10_000_000_000);
        register(&ex, 9, 1, Side::Sell, 1_000_000_000, 10_000);

        // The buy key (1,1) was never registered — the operator
        // cannot conjure a buyer.
        let events = ex
            .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
            .unwrap();
        assert!(events.iter().any(|e| e.kind == "fill_rejected"));
        assert!(!events.iter().any(|e| e.kind == "batch_fill"));
        assert_eq!(ledger.balance(&addr(1)), 10_000_000_000);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000);
    }

    /// Replay safety: a settled batch cannot settle twice. The second
    /// submission re-references orders whose `remaining` is already
    /// consumed — every replayed leg fails its quantity check. This
    /// is the "unique fill" property: consumption, not a fill-id
    /// registry, prevents double settlement.
    #[test]
    fn batch_settle_replay_consumed_orders() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 2_000);

        let msg = msg::batch_settle(&[leg(0, 1_000_000_000, 2_000, 1, 1, 9, 1)]);
        let first = ex.handle(&ctx(0xAA), &msg).unwrap();
        assert_eq!(first.iter().filter(|e| e.kind == "batch_fill").count(), 1);
        let seller_after = ledger.balance(&addr(9));

        // The identical batch again: both orders are fully consumed
        // — the buy order is gone entirely, so the leg fails.
        let second = ex.handle(&ctx(0xAA), &msg).unwrap();
        assert_eq!(second.iter().filter(|e| e.kind == "batch_fill").count(), 0);
        assert!(second.iter().any(|e| e.kind == "fill_rejected"));
        assert_eq!(ledger.balance(&addr(9)), seller_after);
    }

    /// Two legs in one batch cannot spend the same authorized
    /// quantity — the batch-wide `consumed` bound applies the second
    /// time the order is referenced, not just against the map.
    #[test]
    fn batch_settle_cannot_overspend_within_batch() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        // Both orders authorize exactly 1 lot; two 1-lot legs in the
        // same batch would double-spend them.
        registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 1_000);

        let legs =
            [leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1), leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)];
        let events = ex.handle(&ctx(0xAA), &msg::batch_settle(&legs)).unwrap();
        assert_eq!(events.iter().filter(|e| e.kind == "batch_fill").count(), 1);
        assert_eq!(events.iter().filter(|e| e.kind == "fill_rejected").count(), 1);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 + 10_000);
    }

    /// Price improvement: a fill below the buy's limit releases the
    /// escrow slice at the LIMIT and returns the difference to the
    /// buyer — the seller is paid the fill price, the buyer keeps
    /// the improvement.
    #[test]
    fn batch_settle_price_improvement_rebate() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        // Buy limit $15, sell limit $10, fill at $10, 2 lots.
        // Escrow: 1.5e9*2_000/1e8 = 30_000. Pays: 20_000. Rebate: 10_000.
        registered_pair(&ledger, &ex, 1_500_000_000, 1_000_000_000, 2_000);
        let after_register = ledger.balance(&addr(1));

        let events = ex
            .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 2_000, 1, 1, 9, 1)]))
            .unwrap();
        assert!(events.iter().any(|e| e.kind == "reservation_released"));
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 + 20_000);
        assert_eq!(ledger.balance(&addr(1)), after_register + 10_000);
    }

    /// Cancel refunds the remaining escrow exactly once — a
    /// partially filled buy returns `limit × remaining`, and the
    /// canceled order can no longer be filled.
    #[test]
    fn cancel_registered_refunds_residual() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 5_000);
        // Escrow at registration: 50_000. Fill 2 lots (releases
        // 20_000, all to the seller at-limit) → 30_000 remains.
        ex.handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 2_000, 1, 1, 9, 1)]))
            .unwrap();
        let before_cancel = ledger.balance(&addr(1));

        let events = ex.handle(&ctx(1), &msg::cancel_registered(1)).unwrap();
        assert_eq!(events[0].kind, "order_canceled");
        assert_eq!(ledger.balance(&addr(1)), before_cancel + 30_000);

        // The canceled order cannot be filled anymore — a leg
        // referencing it is rejected.
        let events = ex
            .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
            .unwrap();
        assert!(events.iter().any(|e| e.kind == "fill_rejected"));
        // And canceling it twice is rejected too.
        assert!(matches!(
            ex.handle(&ctx(1), &msg::cancel_registered(1)).unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        // Only the owner can cancel — anyone else's cancel misses.
        register(&ex, 9, 9, Side::Sell, 1_000_000_000, 1_000);
        assert!(matches!(
            ex.handle(&ctx(2), &msg::cancel_registered(9)).unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
    }

    /// Registered orders are committed state: registration must move
    /// the state root, and a snapshot round-trip must restore the
    /// registry so the imported module authorizes fills identically.
    #[test]
    fn registered_orders_survive_snapshot() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut src = ExchangeModule::with_ledger(ledger.clone());
        src.set_settlement_operator(addr(0xAA));
        src.list_market(test_cfg()).unwrap();
        let root0 = src.state_root();
        registered_pair(&ledger, &src, 1_000_000_000, 1_000_000_000, 5_000);
        let root1 = src.state_root();
        assert_ne!(root0, root1, "a registered order is committed state");

        let snapshot = src.export_state().expect("exports state");
        assert_eq!(src.inspect_state(&snapshot).unwrap(), root1);

        let mut dst = ExchangeModule::with_ledger(ledger);
        dst.set_settlement_operator(addr(0xAA));
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), root1);

        // The restored registry authorizes the same fill.
        let events = dst
            .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
            .unwrap();
        assert!(events.iter().any(|e| e.kind == "batch_fill"));
    }
}
