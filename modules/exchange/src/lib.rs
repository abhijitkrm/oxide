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
//!   debiting/crediting balances — is the module's job, and it only
//!   moves funds when a balance ledger is wired (bare `new()` is a
//!   matching-only test mode that records fills as events).
//!   Atomic settlement (ledger + exchange in one tx) arrives with the
//!   cross-module coordinator (plan.md §9.2).
//! - **Two assets per market:** the quote asset is the chain's native
//!   token held by [`framework::Balances`]; the base asset is a
//!   per-market custodial asset whose asset id IS the market id.
//!   Base units enter custody via `deposit_base` (debit native 1:1 —
//!   every base unit in custody is backed by native held by the
//!   module) and leave via `withdraw_base`. A future multi-asset
//!   ledger can replace the base side wholesale; the
//!   reservation/delivery structure below is unchanged by it.
//! - **Delivery-versus-payment:** both sides of a trade are escrowed
//!   before it can execute. A buy reserves its worst-case quote cost
//!   (book path: `price × qty` debited at admission; registered
//!   path: `limit × qty` escrowed at registration). A sell locks its
//!   full quantity of base out of the owner's free custody into a
//!   hold (book path) or the order's `reserved` field (registered
//!   path). A fill then swaps atomically: buyer's quote → seller
//!   (minus the protocol fee), seller's base → buyer's custody. A
//!   sell that cannot prove base custody cannot rest, register, or
//!   settle — unbacked fills settle as void, never as paid.
//! - **Fees:** every fill charges [`FEE_BPS`] on the seller's quote
//!   proceeds; accruals land in the committed per-market
//!   `fee_vault`. A governance withdrawal path is a deliberate
//!   residual (the vault is a sink until then).
//! - **Conservation:** `Σ base_balances + Σ base_holds + Σ sell-side
//!   registered `reserved` == native deposited for base − withdrawn`,
//!   enforced by construction — base units are created only by a
//!   paired ledger debit and every transfer moves whole units
//!   between those three committed maps. The property tests assert
//!   the invariant over randomized op sequences.
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
//! | 3   | Batch settle | `[fill_count: 4B LE][fill entries: 74B each]` |
//! | 4   | Register order | `[market: 2B][side: 1B][price: 8B LE][qty: 8B LE][client_id: 8B LE]` |
//! | 5   | Cancel registered | `[client_id: 8B LE]` |
//! | 6   | Deposit base | `[market: 1B][amount: 8B LE]` |
//! | 7   | Withdraw base | `[market: 1B][amount: 8B LE]` |
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
/// `qty`, and every fill against the order consumes `remaining`. Both
/// sides escrow their obligation at registration:
///
/// - A **buy** escrows its worst-case quote cost (`limit_price × qty
///   / PRICE_SCALE`, debited from the ledger into `reserved`), so
///   batch settlement can never fail on buyer insolvency — the funds
///   are already held. `reserved` is released piecewise per fill
///   (`limit × fill_qty`, split into the seller's payment and the
///   buyer's price-improvement rebate) and the residue is refunded to
///   the ledger when the order completes or is canceled.
/// - A **sell** escrows its full base quantity (`qty`, moved out of
///   the owner's free base custody into `reserved`), so a leg can
///   never pay a seller who did not deliver. `reserved` shrinks
///   qty-for-qty per fill and the residue returns to the owner's free
///   base custody (not the ledger) on cancel or completion.
///
/// The `reserved` field is therefore denominated in the side's
/// escrowed asset: quote for buys, base for sells.
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
    /// Escrowed units of the side's obligation asset (scale-6):
    /// quote for buys, base for sells.
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

/// Deposit-base message tag: move native tokens into the sender's
/// per-market base custody so they can back sell orders.
/// Body: `[market:1][amount:8]` = 9 bytes. The base asset of a
/// market is a custodial unit minted 1:1 against the native debit —
/// the module never creates unbacked base.
const TAG_DEPOSIT_BASE: u8 = 6;

/// Withdraw-base message tag: return free base custody to native
/// balance. Reserved/escrowed base cannot be withdrawn — it must be
/// released by a fill, cancel, or book removal first.
/// Body: `[market:1][amount:8]` = 9 bytes.
const TAG_WITHDRAW_BASE: u8 = 7;

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
/// `[market:1][amount:8]` = 9 (deposit-base and withdraw-base
/// share the same body shape).
const CUSTODY_BODY_LEN: usize = 9;

/// Quote-currency scale: the ledger stores native `u64` base units.
/// The notional from a fill is scale-14 (`qty_scale_6 × price_scale_8`);
/// dividing by `PRICE_SCALE` (1e8) yields the quote amount in scale-6
/// base units — the `Balances` unit for this settlement path.
const PRICE_SCALE: u128 = 100_000_000;

/// Protocol fee on the seller's quote proceeds per fill, in basis
/// points (10 bps = 0.1%). Charged on both settlement paths — the
/// on-chain book and registered-order batch settlement — and accrued
/// into the committed per-market `fee_vault`. Floor-rounded per fill
/// (`pays × FEE_BPS / 10_000`), so a fill can never overcharge the
/// seller: `seller_net = pays − fee` with `fee ≤ pays` always. A
/// constant (not per-market config) in this revision — fee policy is
/// protocol-level until a governance set-fee path exists.
const FEE_BPS: u64 = 10;
/// Basis-point denominator for [`FEE_BPS`].
const BPS_DENOM: u64 = 10_000;

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
/// ledger via [`ExchangeModule::with_ledger`], the module settles
/// each fill delivery-versus-payment: the buyer's reserved quote pays
/// the seller (minus the [`FEE_BPS`] protocol fee, accrued to the
/// per-market `fee_vault`) and the seller's reserved base moves into
/// the buyer's per-market custody. Pre-trade checks reject orders
/// that cannot prove their obligation — buys without quote, sells
/// without base custody. Both assets are escrowed before a fill can
/// execute, so settlement cannot fail on insolvency after the book
/// has matched.
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
    /// Free base-asset custody: `(owner, market) → unreserved base
    /// qty` (scale-6). Units enter via `TAG_DEPOSIT_BASE` — each one
    /// backed 1:1 by a native-token ledger debit the module holds —
    /// and leave via `TAG_WITHDRAW_BASE`. Sell orders draw this down
    /// into `base_holds` (book path) or `RegisteredOrder::reserved`
    /// (registered path); fills deliver out of those holds into the
    /// buyer's entry here. Committed state.
    base_balances: BTreeMap<(Address, u8), u64>,
    /// Base locked by this account's resting sell orders on the
    /// book path: `(owner, market) → Σ unfilled sell qty`. A resting
    /// sell contributes its full remaining qty at rest; fills
    /// decrement into the buyer's `base_balances`, and cancels /
    /// non-fill book removals release back to `base_balances`. The
    /// invariant `holds[(o,m)] == Σ unfilled qty of o's resting sells
    /// on m` is maintained at every mutation point. Committed state.
    base_holds: BTreeMap<(Address, u8), u64>,
    /// Accrued protocol fees per market, in quote units — the
    /// committed sink every fill's `FEE_BPS` slice lands in. A
    /// governance withdrawal path is a deliberate residual; until it
    /// exists the vault only grows (bounded by cumulative volume, so
    /// `checked_add` guards are honored rather than assumed).
    /// Committed state.
    fee_vault: BTreeMap<u8, u64>,
}

/// The committed state a snapshot decodes into — the per-market
/// engines, pending governance endorsements, the registered-order
/// map, and the base-asset custody maps, in canonical layout order.
type CommittedState = (
    Vec<Option<MatchingEngine>>,
    framework::Endorsements,
    BTreeMap<OrderKey, RegisteredOrder>,
    BTreeMap<(Address, u8), u64>,
    BTreeMap<(Address, u8), u64>,
    BTreeMap<u8, u64>,
);

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
                base_balances: BTreeMap::new(),
                base_holds: BTreeMap::new(),
                fee_vault: BTreeMap::new(),
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

    /// The account's free (unreserved) base custody on a market —
    /// withdrawable via `TAG_WITHDRAW_BASE`, drawable by sell
    /// orders. Zero when the account never deposited.
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn base_balance(&self, owner: Address, market: u8) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .base_balances
            .get(&(owner, market))
            .copied()
            .unwrap_or(0)
    }

    /// The account's base locked by resting sells on a market.
    /// Fills draw it down; cancels and book removals release it.
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn base_hold(&self, owner: Address, market: u8) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .base_holds
            .get(&(owner, market))
            .copied()
            .unwrap_or(0)
    }

    /// Protocol fees accrued to a market's vault (quote units).
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn fee_vault(&self, market: u8) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fee_vault
            .get(&market)
            .copied()
            .unwrap_or(0)
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
        // Base-asset custody state — committed because it decides
        // every future sell's admissibility and every fill's delivery:
        // two replicas disagreeing on custody would settle different
        // trades. Trailing section; decoders predate it read an empty
        // custody set (see `decode_committed` for what that means for
        // legacy orders).
        w.put_count(inner.base_balances.len());
        for ((owner, market), amount) in &inner.base_balances {
            w.put_addr(owner);
            w.put_u8(*market);
            w.put_u64(*amount);
        }
        w.put_count(inner.base_holds.len());
        for ((owner, market), amount) in &inner.base_holds {
            w.put_addr(owner);
            w.put_u8(*market);
            w.put_u64(*amount);
        }
        w.put_count(inner.fee_vault.len());
        for (market, amount) in &inner.fee_vault {
            w.put_u8(*market);
            w.put_u64(*amount);
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
        // Final trailing section: base custody (`base_balances`,
        // `base_holds`, `fee_vault`). Tolerant tail — a blob written
        // before custody existed decodes with empty maps. That is
        // fail-closed for legacy orders: a pre-upgrade resting sell
        // carries no hold, so the next fill against it settles void
        // (`unbacked_sell_fill`), and a pre-upgrade registered sell
        // has `reserved == 0`, so `settle_leg` rejects every leg
        // naming it — naked sells can be canceled but never paid.
        let mut base_balances = BTreeMap::new();
        let mut base_holds = BTreeMap::new();
        let mut fee_vault = BTreeMap::new();
        if r.remaining() > 0 {
            let count = r.get_count()?;
            for _ in 0..count {
                let key = (r.get_addr()?, r.get_u8()?);
                if base_balances.insert(key, r.get_u64()?).is_some() {
                    return None; // Duplicate key — non-canonical.
                }
            }
            let count = r.get_count()?;
            for _ in 0..count {
                let key = (r.get_addr()?, r.get_u8()?);
                if base_holds.insert(key, r.get_u64()?).is_some() {
                    return None; // Duplicate key — non-canonical.
                }
            }
            let count = r.get_count()?;
            for _ in 0..count {
                let market = r.get_u8()?;
                if fee_vault.insert(market, r.get_u64()?).is_some() {
                    return None; // Duplicate key — non-canonical.
                }
            }
        }
        Some((markets, endorsements, registered, base_balances, base_holds, fee_vault))
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

    /// Build a deposit-base message: move `amount` of native tokens
    /// into the sender's base custody on `market`. The deposit debits
    /// the ledger 1:1 — every custodial base unit is native-backed.
    pub fn deposit_base(market: u8, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::CUSTODY_BODY_LEN);
        msg.push(super::TAG_DEPOSIT_BASE);
        msg.push(market);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// Build a withdraw-base message: return `amount` of the sender's
    /// free base custody on `market` to native balance. Reserved
    /// (resting/registered sell) base is not free and cannot be
    /// withdrawn.
    pub fn withdraw_base(market: u8, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::CUSTODY_BODY_LEN);
        msg.push(super::TAG_WITHDRAW_BASE);
        msg.push(market);
        msg.extend_from_slice(&amount.to_le_bytes());
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

            TAG_CANCEL => self.handle_cancel(ctx, body, &mut inner),

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

            TAG_DEPOSIT_BASE => self.handle_deposit_base(ctx, body, &mut inner),

            TAG_WITHDRAW_BASE => self.handle_withdraw_base(ctx, body, &mut inner),

            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }

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
        let (_canon, (markets, endorsements, registered, balances, holds, fees), store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        *self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = store;
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.markets = markets;
        inner.registered = registered;
        inner.base_balances = balances;
        inner.base_holds = holds;
        inner.fee_vault = fees;
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
    /// Handle a cancel-order message (extracted from `handle`):
    /// remove the resting order and release its reservation — quote
    /// for buys, base for sells — exactly once.
    fn handle_cancel(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        let (market, order_id) = Self::parse_cancel(body).ok_or(ExecError::Malformed)?;

        let Inner { markets, base_balances, base_holds, .. } = inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::ModuleRejected(format!("market {market} does not exist")));
        };

        // Authorization: only the order's owner may cancel.
        if let Some(owner) = engine.order_owner(order_id) {
            if owner != ctx.sender {
                return Err(ExecError::ModuleRejected("cancel: not the order owner".to_string()));
            }
        } else {
            return Err(ExecError::ModuleRejected("cancel: order not found".to_string()));
        }

        match engine.cancel(order_id) {
            Ok(canceled) => {
                // Release the resting reservation (C6 + DvP): a
                // resting buy holds `price × remaining_qty` of quote
                // debited since it rested; a resting sell holds
                // `remaining_qty` of base in `base_holds`. Cancel
                // releases each — exactly once. The quote credit
                // cannot overflow: the refund returns funds debited
                // from this same account. The base release clamps to
                // the hold actually present (a pre-custody sell
                // holds nothing and releases nothing).
                match canceled.side {
                    Side::Buy => {
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
                                    ExecError::ModuleRejected("cancel refund failed".to_string())
                                })?;
                            }
                        }
                    }
                    Side::Sell => {
                        let key = (canceled.owner, market);
                        let release =
                            base_holds.get(&key).copied().unwrap_or(0).min(canceled.qty.0);
                        if release > 0 {
                            *base_holds.get_mut(&key).ok_or(ExecError::Malformed)? -= release;
                            *base_balances.entry(key).or_insert(0) += release;
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

        // Split the borrow: `inner` derefs to `Inner`, and the
        // settlement code below needs the book maps and the base
        // custody maps disjointly.
        let Inner { markets, fills, base_balances, base_holds, fee_vault, .. } = inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::ModuleRejected(format!("market {market} does not exist")));
        };

        // Reservations (C6 + DvP): if the ledger is wired, BOTH sides
        // escrow their obligation up front — a reservation, not a
        // check.
        //
        // A buy DEBITS its worst-case quote cost: limit buys reserve
        // `price × qty` (fills can only cost less); market buys
        // reserve the real sweep cost of `qty` through the ask
        // ladder (`engine.sweep_cost`) — a market order has no
        // limit, so `price × qty` would be meaningless. Without a
        // reservation an unfunded taker could sweep the book and
        // leave every fill unsettled.
        //
        // A sell moves its full `qty` out of the owner's free base
        // custody (`base_balances`) into `taker_base` — the
        // deliverable side of every fill the order produces. A sell
        // whose owner cannot prove base custody cannot rest or
        // execute at all.
        //
        // Both reservations release piecewise at settlement: fills
        // deliver their actual quantity, a surviving resting
        // remainder keeps `price × resting_qty` quote / `resting_qty`
        // base held — which is exactly what `TAG_CANCEL` refunds
        // later, exactly once. Resting orders ARE the reservation
        // ledger (buys implicitly via `price × qty`, sells via
        // `base_holds`): a maker fill pays from obligations already
        // escrowed at rest time, so settlement below cannot fail on
        // insolvency.
        let mut reservation = 0u64;
        let mut taker_base = 0u64;
        if self.ledger.is_some() {
            match order.side {
                Side::Buy => {
                    let ledger = self.ledger.as_ref().ok_or(ExecError::Malformed)?;
                    // Scale-14 notional → scale-6 quote. Reject rather
                    // than cap on u64 overflow — saturating would
                    // silently change what the buyer pays.
                    let notional = match order.order_type {
                        OrderType::Market => engine.sweep_cost(Side::Buy, order.qty.0, None),
                        _ => u128::from(order.price.0) * u128::from(order.qty.0),
                    };
                    let quote_needed = u64::try_from(notional / PRICE_SCALE).map_err(|_| {
                        ExecError::ModuleRejected(
                            "buy notional exceeds u64 quote range".to_string(),
                        )
                    })?;
                    // Debit up front — fails here, BEFORE the book is
                    // touched, on insufficient funds.
                    ledger.debit(&ctx.sender, quote_needed).map_err(|_| {
                        ExecError::ModuleRejected("insufficient balance for buy order".to_string())
                    })?;
                    reservation = quote_needed;
                }
                Side::Sell => {
                    // Deduct the order's full qty from free base
                    // custody. Custody only exists once deposits are
                    // made — and deposits require the ledger — so
                    // inside `self.ledger.is_some()` a zero entry is
                    // an honest rejection, not a test-mode artifact.
                    let key = (ctx.sender, market);
                    let free = base_balances.get(&key).copied().unwrap_or(0);
                    if free < order.qty.0 {
                        return Err(ExecError::ModuleRejected(
                            "insufficient base custody for sell order".to_string(),
                        ));
                    }
                    // `free >= qty` was just proven — cannot underflow.
                    *base_balances.get_mut(&key).ok_or(ExecError::Malformed)? -= order.qty.0;
                    taker_base = order.qty.0;
                }
            }
        }

        // Reuse the fill buffer across calls — zero alloc.
        fills.clear();
        // `ObserveRemovals` never restricts a fill — it records
        // every maker the sweep shrank or removed without one (STP
        // prevention), so the obligations those orders held at rest
        // can be released below. A resting order IS its reservation;
        // a maker the engine deletes unreported would strand that
        // escrow forever.
        let mut removed: Vec<trading::MakerRemoval> = Vec::new();
        let outcome = match engine.place_with_cap(
            order,
            fills,
            &mut trading::ObserveRemovals { removed: &mut removed },
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                // Engine rejected the order — nothing matched and
                // nothing rests, so both reservations come back in
                // full. Crediting the account we just debited cannot
                // overflow; the map_err is defensive.
                if reservation > 0 {
                    if let Some(ledger) = &self.ledger {
                        ledger.credit(&ctx.sender, reservation).map_err(|_| {
                            ExecError::ModuleRejected("engine-reject refund failed".to_string())
                        })?;
                    }
                }
                if taker_base > 0 {
                    *base_balances.entry((ctx.sender, market)).or_insert(0) += taker_base;
                }
                return Err(ExecError::ModuleRejected(format!("engine: {e}")));
            }
        };

        // Emit one event per fill + one for the outcome.
        let mut events = Vec::with_capacity(fills.len() + 1);
        for f in fills.iter() {
            events.push(fill_event(*f));
        }

        // Settlement (plan.md §9.2, C6 + DvP): BOTH sides of every
        // fill were ALREADY escrowed — the buyer's quote via the
        // reservation above (taker) or the debit it has held since
        // resting (maker), the seller's base via `taker_base` or the
        // maker's `base_holds` entry. Each fill therefore swaps
        // obligations that provably exist: no debit can fail here,
        // which is the point — the book mutation above is NOT rolled
        // back on a post-`place` error (the engine lives in module
        // memory, invisible to the executor's state journal), so
        // nothing after `place` may fail. The remaining `map_err`s
        // guard invariants that are unreachable while they hold:
        // per-fill notional ≤ the debited reservation (u64 range),
        // and credit overflow only if an account approaches
        // u64::MAX — impossible while total supply stays below it
        // (enforced at mint/genesis).
        //
        // A maker sell whose hold cannot cover its fill is the one
        // provably-impossible case this code still handles: state
        // imported from before custody existed carries resting sells
        // with no hold. Such a fill settles VOID — the book consumed
        // the order, but no quote moves and no base is minted — the
        // `unbacked_sell_fill` event keeps the anomaly auditable.
        if let Some(ledger) = &self.ledger {
            BookSettlement { ledger, base_balances, base_holds, fee_vault, events: &mut events }
                .apply(
                    market,
                    TakerCtx {
                        price: order.price,
                        owner: ctx.sender,
                        reservation,
                        base: taker_base,
                    },
                    outcome,
                    fills,
                )?;
        }

        events.push(outcome_event(market, outcome));
        // Release maker holds + report every non-fill book change
        // the sweep applied, so downstream accounting sees each
        // obligation the book released — a maker the engine deleted
        // silently would be invisible to settlement reconciliation.
        self.release_maker_holds(market, &removed, base_balances, base_holds, &mut events)?;
        Ok(events)
    }

    /// Release the obligations the sweep freed without a fill and
    /// emit one event per removal/decrement.
    ///
    /// - A resting **buy** held `price × removed_qty` of quote since
    ///   it rested; a decremented one holds `price × remaining` now,
    ///   so the released slice is `price × removed_qty` in both
    ///   cases. The ledger credit cannot overflow: it returns funds
    ///   debited from this same account at rest time.
    /// - A resting **sell** holds `removed_qty` of base in
    ///   `base_holds` — released back to the owner's free custody.
    ///   `min(hold, removed_qty)` clamps the release to what is
    ///   actually held: a sell imported from before custody existed
    ///   holds nothing, so it releases nothing.
    fn release_maker_holds(
        &self,
        market: u8,
        removed: &[trading::MakerRemoval],
        base_balances: &mut BTreeMap<(Address, u8), u64>,
        base_holds: &mut BTreeMap<(Address, u8), u64>,
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
            if r.side == Side::Sell && r.removed_qty > 0 {
                let key = (r.owner, market);
                let release = base_holds.get(&key).copied().unwrap_or(0).min(r.removed_qty);
                if release > 0 {
                    *base_holds.get_mut(&key).ok_or(ExecError::Malformed)? -= release;
                    *base_balances.entry(key).or_insert(0) += release;
                }
            }
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
    /// only within those bounds. Both sides escrow at registration:
    /// a buy escrows `price × qty / PRICE_SCALE` of quote (the
    /// reservation every later fill pays out of, so settlement can
    /// never fail on buyer insolvency) and a sell escrows `qty` of
    /// base custody (the delivery every later fill demands, so a
    /// leg can never pay an undelivering seller).
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

        let Inner { markets, registered, base_balances, .. } = &mut *inner;
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

        // Escrow — both sides, denominated in the side's obligation
        // asset (`reserved` is quote for buys, base for sells):
        //
        // - A buy debits `limit × qty` of ledger quote up front —
        //   every fill against this order pays out of the escrow, so
        //   settlement can never draw on an insolvent buyer. Reject
        //   rather than cap on u64 overflow: saturating would
        //   silently change what the buyer authorized.
        // - A sell moves `qty` of base out of the owner's free
        //   custody into `reserved` — the delivery a fill can demand.
        //   Without the ledger no deposit path exists, so the free
        //   balance is always zero and the check rejects naturally.
        let reserved = match side {
            Side::Buy => {
                let ledger = self.ledger.as_ref().ok_or_else(|| {
                    ExecError::ModuleRejected("register requires ledger wiring".to_string())
                })?;
                let amount = u64::try_from(u128::from(price) * u128::from(qty) / PRICE_SCALE)
                    .map_err(|_| {
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
            }
            Side::Sell => {
                // `u8` conversion cannot fail: the market-existence
                // check above bounds `market` to the 256-slot engine
                // space.
                let m = u8::try_from(market).map_err(|_| {
                    ExecError::ModuleRejected("register: market out of range".to_string())
                })?;
                let key = (ctx.sender, m);
                let free = base_balances.get(&key).copied().unwrap_or(0);
                if free < qty {
                    return Err(ExecError::ModuleRejected(
                        "register: insufficient base custody for sell".to_string(),
                    ));
                }
                *base_balances.get_mut(&key).ok_or(ExecError::Malformed)? -= qty;
                qty
            }
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
        match order.side {
            // Buy escrow is ledger quote — refund to the ledger.
            Side::Buy => {
                if refund > 0 {
                    let ledger = self.ledger.as_ref().ok_or_else(|| {
                        ExecError::ModuleRejected("cancel requires ledger wiring".to_string())
                    })?;
                    ledger.credit(&ctx.sender, refund).map_err(|_| {
                        ExecError::ModuleRejected("cancel: escrow refund failed".to_string())
                    })?;
                }
            }
            // Sell escrow is base custody — refund to the owner's
            // free base balance on the order's market, not the
            // ledger. `u8` conversion is safe: registration rejected
            // any market beyond the 256-slot engine space.
            Side::Sell => {
                if refund > 0 {
                    let market = u8::try_from(order.market).map_err(|_| {
                        ExecError::ModuleRejected("cancel: market out of range".to_string())
                    })?;
                    *inner.base_balances.entry((ctx.sender, market)).or_insert(0) += refund;
                }
            }
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

    /// Handle a deposit-base message: debit `amount` of native token
    /// from the sender's ledger balance into their free base custody
    /// on `market` — the 1:1 backing that makes custodial base a real
    /// asset rather than an unbacked module mint.
    ///
    /// Rejects: malformed body, zero amount, unlisted market (base
    /// for a market that does not exist is dead state), missing
    /// ledger wiring (nothing to back the deposit), and a ledger
    /// debit the sender cannot cover. A custody-entry overflow
    /// refunds the debit and rejects — conservation is never broken
    /// to admit a deposit.
    fn handle_deposit_base(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != CUSTODY_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let market = body[0];
        let amount = u64::from_le_bytes(body[1..9].try_into().map_err(|_| ExecError::Malformed)?);
        if amount == 0 {
            return Err(ExecError::ModuleRejected("deposit: zero amount".to_string()));
        }
        if inner.markets[usize::from(market)].is_none() {
            return Err(ExecError::ModuleRejected(format!("market {market} does not exist")));
        }
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::ModuleRejected("deposit requires ledger wiring".to_string())
        })?;
        ledger
            .debit(&ctx.sender, amount)
            .map_err(|_| ExecError::ModuleRejected("deposit: insufficient balance".to_string()))?;
        let entry = inner.base_balances.entry((ctx.sender, market)).or_insert(0);
        if let Some(v) = entry.checked_add(amount) {
            *entry = v;
        } else {
            // Unreachable while total native supply < u64::MAX
            // (custody is native-backed). Refund the debit so the
            // failed deposit is a no-op, not a loss.
            ledger
                .credit(&ctx.sender, amount)
                .map_err(|_| ExecError::ModuleRejected("deposit: refund failed".to_string()))?;
            return Err(ExecError::ModuleRejected("deposit: base custody overflow".to_string()));
        }
        Ok(vec![Event {
            module: "exchange",
            kind: "base_deposited",
            data: {
                let mut d = Vec::with_capacity(20 + 1 + 8);
                d.extend_from_slice(&ctx.sender.0);
                d.push(market);
                d.extend_from_slice(&amount.to_le_bytes());
                d
            },
        }])
    }

    /// Handle a withdraw-base message: return `amount` of the
    /// sender's free base custody on `market` to their ledger
    /// balance. Only `base_balances` (free) is drawable — base locked
    /// in `base_holds` or a registered order's `reserved` must be
    /// released by a fill or cancel first.
    ///
    /// The ledger credit runs BEFORE the custody decrement, so a
    /// credit failure (impossible while supply < `u64::MAX` — the
    /// units were debited out of circulation at deposit) leaves
    /// custody untouched.
    ///
    /// Rejects: malformed body, zero amount, missing ledger wiring,
    /// and a free balance that does not cover the withdrawal.
    fn handle_withdraw_base(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != CUSTODY_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let market = body[0];
        let amount = u64::from_le_bytes(body[1..9].try_into().map_err(|_| ExecError::Malformed)?);
        if amount == 0 {
            return Err(ExecError::ModuleRejected("withdraw: zero amount".to_string()));
        }
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::ModuleRejected("withdraw requires ledger wiring".to_string())
        })?;
        let free = inner.base_balances.get(&(ctx.sender, market)).copied().unwrap_or(0);
        if free < amount {
            return Err(ExecError::ModuleRejected("withdraw: insufficient free base".to_string()));
        }
        ledger
            .credit(&ctx.sender, amount)
            .map_err(|_| ExecError::ModuleRejected("withdraw: credit failed".to_string()))?;
        // `free >= amount` was just proven — the decrement cannot
        // underflow.
        *inner.base_balances.get_mut(&(ctx.sender, market)).ok_or(ExecError::Malformed)? -= amount;
        Ok(vec![Event {
            module: "exchange",
            kind: "base_withdrawn",
            data: {
                let mut d = Vec::with_capacity(20 + 1 + 8);
                d.extend_from_slice(&ctx.sender.0);
                d.push(market);
                d.extend_from_slice(&amount.to_le_bytes());
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
    ///   Neither side is debited at settle time: the buy's quote and
    ///   the sell's base were both escrowed at registration. A leg
    ///   pays the seller `pays − fee` out of the escrow slice
    ///   `buy.limit * qty / PRICE_SCALE` (the remainder rebating the
    ///   buyer's price improvement), delivers `qty` of base into the
    ///   buyer's custody, and accrues `fee` into the market vault —
    ///   insolvency during settlement is impossible by construction,
    ///   on both legs.
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
        // Authorization: only the settlement operator may submit
        // fills — and only against orders the owners signed for.
        if self.settlement_operator != Some(ctx.sender) {
            return Err(ExecError::ModuleRejected("unauthorized settlement operator".to_string()));
        }
        let fill_count = usize::try_from(u32::from_le_bytes(
            body.get(0..4)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ))
        .map_err(|_| ExecError::Malformed)?;
        // Bound the batch: a byzantine operator must not be able to
        // submit arbitrarily large fill sets.
        if fill_count > MAX_BATCH_FILLS {
            return Err(ExecError::Malformed);
        }
        if body.len() != 4 + fill_count * FILL_ENTRY_LEN {
            return Err(ExecError::Malformed);
        }

        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::ModuleRejected("batch settle requires ledger wiring".to_string())
        })?;

        let Inner { markets, registered, base_balances, fee_vault, .. } = &mut *inner;

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
                    // The pair credit is the seller's NET payment —
                    // gross minus the fee (the fee accrues per
                    // market in `consume_and_release`).
                    if let Some(sum) = entry.checked_add(plan.pays - plan.fee) {
                        *entry = sum;
                        plans.push(plan);
                    } else {
                        // Practically unreachable — void the leg
                        // rather than silently saturating.
                        events.push(rejected_leg_event(i, "pair total overflow"));
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
                events.push(pair_event("settlement_failed", buyer, seller, *amount));
                continue;
            }
            events.push(pair_event("batch_fill", buyer, seller, *amount));
        }

        // ── Pass 2 + drains: apply the surviving legs ────────────
        // Order consumption, buyer rebates, base deliveries, fee
        // accrual, and residue refunds run in `consume_and_release`
        // — every mutation is derived from the validated plans, so
        // a voided pair's legs consume nothing.
        consume_and_release(
            &plans,
            &failed_pairs,
            registered,
            base_balances,
            fee_vault,
            ledger,
            &mut events,
        );

        Ok(events)
    }
}

/// The taker's side of a book-path settlement — everything `apply`
/// needs from the admitted order and its admission-time escrows.
struct TakerCtx {
    /// Taker limit price — bounds the buy-side reservation residue.
    price: Price,
    /// Taker owner — recipient of refunds and taker-side deliveries.
    owner: Address,
    /// Quote units reserved at admission (buys only; 0 for sells).
    reservation: u64,
    /// Base units reserved at admission (sells only; 0 for buys).
    base: u64,
}

/// The mutable settlement surfaces a book-path place touches,
/// bundled so the fill loop borrows one value instead of five
/// disjoint `Inner` fields. All custody mutations go through here.
struct BookSettlement<'a> {
    /// The native ledger — quote credits and reservation refunds.
    ledger: &'a Arc<dyn framework::Balances + Send + Sync>,
    /// Free base custody (buyer deliveries land here).
    base_balances: &'a mut BTreeMap<(Address, u8), u64>,
    /// Resting-sell base holds (maker deliveries draw from here).
    base_holds: &'a mut BTreeMap<(Address, u8), u64>,
    /// Per-market protocol-fee sink (quote units).
    fee_vault: &'a mut BTreeMap<u8, u64>,
    /// The event sink every settlement-visible mutation appends to.
    events: &'a mut Vec<Event>,
}

impl BookSettlement<'_> {
    /// Settle every fill the engine produced, then release the
    /// taker's leftover reservations.
    ///
    /// Per fill, `DvP`: the seller's base moves into the buyer's free
    /// custody and the buyer's quote pays the seller minus the
    /// [`FEE_BPS`] protocol fee (accrued to `fee_vault`). Delivery
    /// is proven BEFORE payment: a maker sell whose `base_holds`
    /// entry cannot cover the fill settles VOID — the book consumed
    /// the order, but no quote moves and no base is minted. Only
    /// state imported from before custody existed can produce that
    /// shape; the `unbacked_sell_fill` event keeps it auditable.
    /// The remaining `map_err`s guard invariants unreachable while
    /// they hold: per-fill notional ≤ the debited reservation (u64
    /// range), and credit overflow only if an account approaches
    /// `u64::MAX` — impossible while total supply stays below it
    /// (enforced at mint/genesis).
    fn apply(
        &mut self,
        market: u8,
        taker: TakerCtx,
        outcome: OrderOutcome,
        fills: &[FillEvent],
    ) -> Result<(), ExecError> {
        // `taker_paid` accumulates only fills that actually settled
        // — a voided fill neither pays nor receives.
        let mut taker_paid = 0u64;
        let mut taker_base = taker.base;
        for f in fills {
            let notional = u128::from(f.price.0) * u128::from(f.qty.0);
            let quote_amount = u64::try_from(notional / PRICE_SCALE).map_err(|_| {
                ExecError::ModuleRejected(format!(
                    "fill notional exceeds u64 quote range (market {market})"
                ))
            })?;
            // Buyer and seller from the taker's side: the maker
            // sells when the taker buys and vice versa.
            let (buyer, seller) = if f.taker_side == Side::Buy {
                (f.taker_owner, f.maker_owner)
            } else {
                (f.maker_owner, f.taker_owner)
            };

            // ── Base leg: prove delivery BEFORE paying ──
            // A taker sell always covers (its qty was reserved at
            // admission); a maker sell must still hold the fill
            // qty in `base_holds`.
            let maker_covered = f.taker_side == Side::Sell
                || self.base_holds.get(&(f.maker_owner, market)).copied().unwrap_or(0) >= f.qty.0;
            if !maker_covered {
                self.events.push(unbacked_sell_fill_event(market, *f));
                continue;
            }
            let bkey = (buyer, market);
            let Some(buyer_next) =
                self.base_balances.get(&bkey).copied().unwrap_or(0).checked_add(f.qty.0)
            else {
                // Unreachable while Σ custody < u64::MAX (custody is
                // native-backed). Void rather than mint.
                self.events.push(fill_voided_event(market, *f));
                continue;
            };
            if f.taker_side == Side::Buy {
                // `maker_covered` proved the entry exists with
                // enough held.
                *self
                    .base_holds
                    .get_mut(&(f.maker_owner, market))
                    .ok_or(ExecError::Malformed)? -= f.qty.0;
            } else {
                // Admission reserved `qty`; Σ fills ≤ qty by engine
                // contract — `checked_sub` documents it.
                taker_base = taker_base.checked_sub(f.qty.0).ok_or(ExecError::Malformed)?;
            }
            *self.base_balances.entry(bkey).or_insert(0) = buyer_next;
            if f.taker_side == Side::Buy {
                taker_paid = taker_paid.saturating_add(quote_amount);
            }

            // ── Quote leg: seller receives notional minus the
            // protocol fee; the fee accrues to the market's
            // committed vault.
            let fee = u64::try_from(
                u128::from(quote_amount) * u128::from(FEE_BPS) / u128::from(BPS_DENOM),
            )
            .map_err(|_| ExecError::ModuleRejected(format!("fee overflow (market {market})")))?;
            self.ledger.credit(&seller, quote_amount - fee).map_err(|_| {
                ExecError::ModuleRejected(format!("settlement credit failed (market {market})"))
            })?;
            let vault = self.fee_vault.entry(market).or_insert(0);
            match vault.checked_add(fee) {
                Some(v) => *vault = v,
                // Saturation burns the excess (the units were
                // deducted from the seller's payment regardless) —
                // reachable only past u64::MAX cumulative fees.
                None => self.events.push(fee_overflow_event(market, fee)),
            }
        }

        // Release the taker's quote reservation (buys): settled fills
        // cost their actual price (improvement refunded), a
        // surviving GTC remainder keeps `price × resting_qty` held
        // for the cancel path, and dead remainders
        // (IOC/FOK/Killed/Rejected) come back in full.
        if taker.reservation > 0 {
            let held = match outcome {
                OrderOutcome::Resting { resting_qty, .. } => u64::try_from(
                    u128::from(taker.price.0) * u128::from(resting_qty.0) / PRICE_SCALE,
                )
                .unwrap_or(u64::MAX),
                _ => 0,
            };
            let refund = taker.reservation.saturating_sub(taker_paid.saturating_add(held));
            if refund > 0 {
                self.ledger.credit(&taker.owner, refund).map_err(|_| {
                    ExecError::ModuleRejected("reservation refund failed".to_string())
                })?;
            }
        }

        // Release the taker's base reservation (sells): the unfilled
        // remainder either becomes the resting order's hold (GTC
        // remainder) or returns to free custody
        // (IOC/FOK/Killed/STP-consumed). `resting_qty` is the
        // engine's reported remainder; any STP-consumed slice
        // (`taker_base − resting_qty`) books no fill and is
        // released free.
        if taker_base > 0 {
            let resting = match outcome {
                OrderOutcome::Resting { resting_qty, .. } => resting_qty.0,
                _ => 0,
            };
            if resting > 0 {
                *self.base_holds.entry((taker.owner, market)).or_insert(0) += resting;
            }
            let release = taker_base.saturating_sub(resting);
            if release > 0 {
                *self.base_balances.entry((taker.owner, market)).or_insert(0) += release;
            }
        }
        Ok(())
    }
}

/// Apply validated fill legs to the registered-order map: consume
/// `remaining`, release buy-side escrow, pay price-improvement
/// rebates, deliver base to buyers, accrue fees, and refund the
/// residue of fully consumed orders.
///
/// Phases (all iteration is over sorted `BTreeMap`s — deterministic
/// event order):
///
/// 1. **Accumulate** each surviving leg into per-order deltas
///    (quantity consumed, escrow released, rebate portion tracked
///    separately), per-buyer rebate totals, per-(buyer, market)
///    base deliveries, and per-market fee accruals.
/// 2. **Rebate drain**: credit each buyer's rebate. A failed credit
///    withholds that buyer's rebate — the payment still settled, but
///    the rebate stays in the order's escrow (refunded with the
///    residue) rather than vanishing.
/// 3. **Base delivery**: each surviving leg's `qty` moves into the
///    buyer's free custody — the delivery half of the swap. The seller's
///    side was escrowed at registration (`reserved`), so delivery
///    cannot fail for want of base.
/// 4. **Fee accrual**: the per-market `FEE_BPS` total lands in the
///    committed `fee_vault`.
/// 5. **Consumption**: `remaining` drops by the consumed quantity;
///    `reserved` drops by the released slice (buys: released minus
///    withheld rebate; sells: qty-for-qty with consumption). A
///    fully consumed order is removed and its residue — floor-
///    division dust plus any withheld rebate — refunded to the
///    asset's home: ledger quote for buys, free base custody for
///    sells.
fn consume_and_release(
    plans: &[LegPlan],
    failed_pairs: &std::collections::BTreeSet<(Address, Address)>,
    registered: &mut BTreeMap<OrderKey, RegisteredOrder>,
    base_balances: &mut BTreeMap<(Address, u8), u64>,
    fee_vault: &mut BTreeMap<u8, u64>,
    ledger: &Arc<dyn framework::Balances + Send + Sync>,
    events: &mut Vec<Event>,
) {
    // ── Accumulate deltas ───────────────────────────────────────
    // Per order: quantity consumed, escrow released, and the
    // rebate portion of the release (tracked separately so a
    // failed rebate credit can leave it escrowed). Per buyer:
    // total rebate to release and base to receive. Per market:
    // total fee to accrue.
    let mut deltas: BTreeMap<OrderKey, OrderDelta> = BTreeMap::new();
    let mut rebates: BTreeMap<Address, u64> = BTreeMap::new();
    let mut deliveries: BTreeMap<(Address, u8), u64> = BTreeMap::new();
    let mut fees: BTreeMap<u8, u64> = BTreeMap::new();
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
        *deliveries.entry((plan.buyer, plan.market)).or_default() += plan.qty;
        *fees.entry(plan.market).or_default() += plan.fee;
    }

    // ── Rebate drain ────────────────────────────────────────────
    // Sorted address order. A rebate credit that fails is withheld.
    let mut failed_rebates: std::collections::BTreeSet<Address> = std::collections::BTreeSet::new();
    for (buyer, amount) in &rebates {
        if !credit_or_stranded(ledger, *buyer, *amount, events) {
            failed_rebates.insert(*buyer);
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

    deliver_base(&deliveries, base_balances, events);
    accrue_fees(&fees, fee_vault, events);

    // ── Consumption + residue refunds ───────────────────────────
    let mut completed: Vec<(OrderKey, Side, u16, u64)> = Vec::new();
    for (key, delta) in &deltas {
        let Some(order) = registered.get_mut(key) else { continue };
        order.remaining = order.remaining.saturating_sub(delta.consumed);
        match order.side {
            // Buys: release the escrow slice, minus any withheld
            // rebate that stays escrowed for the residue refund.
            Side::Buy => {
                let withheld = if failed_rebates.contains(&key.owner) { delta.rebate } else { 0 };
                order.reserved =
                    order.reserved.saturating_sub(delta.released.saturating_sub(withheld));
            }
            // Sells: `reserved` IS the remaining base escrow — it
            // shrinks qty-for-qty with consumption.
            Side::Sell => {
                order.reserved = order.reserved.saturating_sub(delta.consumed);
            }
        }
        if order.remaining == 0 {
            completed.push((*key, order.side, order.market, order.reserved));
        }
    }
    for (key, side, market, residue) in completed {
        registered.remove(&key);
        if residue == 0 {
            continue;
        }
        match side {
            // The order is dead; a refund failure strands its
            // residue. Impossible while supply stays below
            // `u64::MAX` — the event keeps it visible.
            Side::Buy => {
                credit_or_stranded(ledger, key.owner, residue, events);
            }
            // Sell residue is base escrow — it returns to the
            // owner's free custody, not the ledger. `u8` conversion
            // is safe (registration bounded markets to 256 slots);
            // the add-back cannot overflow (the units came from
            // this same custody pool).
            Side::Sell => {
                let Ok(m) = u8::try_from(market) else {
                    // Unreachable: registration bounds markets to
                    // the 256-slot engine space. Stranding the
                    // residue beats misrouting it to a wrong
                    // market — and the order is already removed.
                    continue;
                };
                *base_balances.entry((key.owner, m)).or_insert(0) += residue;
            }
        }
        events.push(Event {
            module: "exchange",
            kind: "escrow_refunded",
            data: {
                let mut d = Vec::with_capacity(20 + 8 + 8);
                d.extend_from_slice(&key.owner.0);
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
    /// The market the fill settles on — keys the buyer's base
    /// custody credit and the fee vault. `u8`-bounded: validation
    /// rejects any market outside the 256-slot engine space.
    market: u8,
    /// Filled quantity (scale-6).
    qty: u64,
    /// The seller's gross payment: `floor(price × qty / PRICE_SCALE)`.
    pays: u64,
    /// The protocol fee carved out of `pays`:
    /// `floor(pays × FEE_BPS / BPS_DENOM)` — the pair drain credits
    /// `pays − fee`, the vault accrues `fee`.
    fee: u64,
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

/// Build a pair-scoped settlement event (`batch_fill` on a settled
/// pair, `settlement_failed` on a voided one):
/// `[buyer:20][seller:20][amount:8]`.
fn pair_event(kind: &'static str, buyer: &Address, seller: &Address, amount: u64) -> Event {
    let mut data = Vec::with_capacity(20 + 20 + 8);
    data.extend_from_slice(&buyer.0);
    data.extend_from_slice(&seller.0);
    data.extend_from_slice(&amount.to_le_bytes());
    Event { module: "exchange", kind, data }
}

/// Parse an `OrderKey` (`[owner:20][client_id:8]` = 28 bytes) out of
/// a batch-settle leg at byte offset `off`.
fn leg_key(body: &[u8], off: usize) -> Result<OrderKey, ExecError> {
    Ok(OrderKey {
        owner: Address(
            body.get(off..off + 20)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ),
        client_id: u64::from_le_bytes(
            body.get(off + 20..off + 28)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ),
    })
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
    let buy = leg_key(body, off + 18)?;
    let sell = leg_key(body, off + 46)?;

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
    // Delivery-versus-payment: the sell order must still hold enough
    // escrowed base — `reserved` on a sell is its base custody, which
    // registration filled qty-for-qty with `remaining`. This is what
    // stops a leg from paying a seller who cannot deliver — including
    // a pre-custody registered sell (`reserved == 0`), which is now
    // unfillable but still cancelable.
    if sell_total > sell_order.reserved {
        return Ok(None);
    }

    // Amounts: pays at the fill price, release at the buy limit —
    // checked u128 math; over-u64 notionals reject the leg. The fee
    // is `pays`-bounded (`FEE_BPS < BPS_DENOM`), so `pays − fee` can
    // never underflow.
    let (Some(pays), Some(release)) = (
        u64::try_from(u128::from(price) * u128::from(qty) / PRICE_SCALE).ok(),
        u64::try_from(u128::from(buy_order.limit_price) * u128::from(qty) / PRICE_SCALE).ok(),
    ) else {
        return Ok(None);
    };
    let Some(fee) =
        u64::try_from(u128::from(pays) * u128::from(FEE_BPS) / u128::from(BPS_DENOM)).ok()
    else {
        return Ok(None); // Unreachable: `pays`-bounded.
    };
    let Ok(market_u8) = u8::try_from(market) else {
        return Ok(None); // Post-validation unreachable — engines are u8-indexed.
    };

    consumed.insert(buy, buy_total);
    consumed.insert(sell, sell_total);
    Ok(Some(LegPlan {
        buy,
        sell,
        buyer: buy.owner,
        seller: sell.owner,
        market: market_u8,
        qty,
        pays,
        fee,
        release,
    }))
}

/// Credit `owner` `amount` of ledger quote, emitting a
/// `reservation_release_failed` event (and returning `false`) if the
/// credit fails — the shared rebate/residue drain pattern. A failed
/// credit strands the funds in place: the caller decides what the
/// residue does next. Impossible while total supply stays below
/// `u64::MAX` — the event keeps it visible regardless.
fn credit_or_stranded(
    ledger: &Arc<dyn framework::Balances + Send + Sync>,
    owner: Address,
    amount: u64,
    events: &mut Vec<Event>,
) -> bool {
    if ledger.credit(&owner, amount).is_err() {
        events.push(Event {
            module: "exchange",
            kind: "reservation_release_failed",
            data: {
                let mut d = Vec::with_capacity(20 + 8);
                d.extend_from_slice(&owner.0);
                d.extend_from_slice(&amount.to_le_bytes());
                d
            },
        });
        return false;
    }
    true
}

/// Deliver accumulated base quantities into buyer custody — the
/// delivery half of the trade for batch settlement. Sorted (buyer, market)
/// order. The credit cannot fail against a shortfall — the seller
/// escrowed the qty at registration — only on a buyer-custody
/// overflow, which is unreachable while Σ custody < `u64::MAX`; the
/// event keeps it visible regardless.
fn deliver_base(
    deliveries: &BTreeMap<(Address, u8), u64>,
    base_balances: &mut BTreeMap<(Address, u8), u64>,
    events: &mut Vec<Event>,
) {
    for ((buyer, market), qty) in deliveries {
        let entry = base_balances.entry((*buyer, *market)).or_insert(0);
        if let Some(v) = entry.checked_add(*qty) {
            *entry = v;
            events.push(Event {
                module: "exchange",
                kind: "base_delivered",
                data: {
                    let mut d = Vec::with_capacity(20 + 1 + 8);
                    d.extend_from_slice(&buyer.0);
                    d.push(*market);
                    d.extend_from_slice(&qty.to_le_bytes());
                    d
                },
            });
        } else {
            events.push(Event {
                module: "exchange",
                kind: "base_delivery_overflow",
                data: {
                    let mut d = Vec::with_capacity(20 + 1 + 8);
                    d.extend_from_slice(&buyer.0);
                    d.push(*market);
                    d.extend_from_slice(&qty.to_le_bytes());
                    d
                },
            });
        }
    }
}

/// Accrue per-market fees into the committed `fee_vault`. Sorted
/// market order. Vault saturation burns the excess (the fee was
/// already deducted from the seller's payment) — reachable only past
/// `u64::MAX` cumulative quote volume.
fn accrue_fees(
    fees: &BTreeMap<u8, u64>,
    fee_vault: &mut BTreeMap<u8, u64>,
    events: &mut Vec<Event>,
) {
    for (market, fee) in fees {
        let vault = fee_vault.entry(*market).or_insert(0);
        if let Some(v) = vault.checked_add(*fee) {
            *vault = v;
        } else {
            events.push(fee_overflow_event(*market, *fee));
        }
    }
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

/// Build an `unbacked_sell_fill` event: a book-path fill whose maker
/// sell held less base than the fill quantity — only reachable for
/// orders imported from before custody existed. The fill settles
/// void: the book consumed the order but no quote moves and no base
/// is minted.
fn unbacked_sell_fill_event(market: u8, fill: FillEvent) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 8 + 20);
    data.push(market);
    data.extend_from_slice(&fill.maker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.qty.0.to_le_bytes());
    data.extend_from_slice(&fill.maker_owner.0);
    Event { module: "exchange", kind: "unbacked_sell_fill", data }
}

/// Build a `fill_voided` event: a fill skipped because the buyer's
/// base custody credit would overflow — unreachable while total
/// custody stays under `u64::MAX`, emitted rather than silently
/// clamped.
fn fill_voided_event(market: u8, fill: FillEvent) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(market);
    data.extend_from_slice(&fill.maker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.qty.0.to_le_bytes());
    Event { module: "exchange", kind: "fill_voided", data }
}

/// Build a `fee_vault_overflow` event: a fill's fee could not accrue
/// because the market's vault is saturated — reachable only past
/// `u64::MAX` cumulative quote volume. The excess fee is burned (it
/// was already deducted from the seller's payment).
fn fee_overflow_event(market: u8, fee: u64) -> Event {
    let mut data = Vec::with_capacity(1 + 8);
    data.push(market);
    data.extend_from_slice(&fee.to_le_bytes());
    Event { module: "exchange", kind: "fee_vault_overflow", data }
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
        TAG_PLACE, TimeInForce, encode_reject_reason, encode_side, msg,
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
    /// PRICE_SCALE` of quote and a sell escrows `qty` of base
    /// custody at registration.
    fn register(ex: &ExchangeModule, owner: u8, client_id: u64, side: Side, price: u64, qty: u64) {
        ex.handle(&ctx(owner), &msg::register_order(0, side, price, qty, client_id))
            .expect("registration must succeed");
    }

    /// Deposit `amount` of base custody for `owner` on market 0 —
    /// the native debit backing every sell-side obligation.
    fn deposit(ex: &ExchangeModule, owner: u8, amount: u64) {
        ex.handle(&ctx(owner), &msg::deposit_base(0, amount)).expect("deposit must succeed");
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
    /// `(9, 1)` at `sell_price`, each for `qty` units. The seller
    /// deposits `qty` of base custody first — a sell can only
    /// register against base the owner actually holds.
    fn registered_pair(
        ledger: &Arc<framework::MemoryBalances>,
        ex: &ExchangeModule,
        buy_price: u64,
        sell_price: u64,
        qty: u64,
    ) {
        ledger.mint(&addr(1), 10_000_000_000);
        ledger.mint(&addr(9), 10_000_000_000);
        deposit(ex, 9, qty);
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
        // Both hold base custody too — owner 9 is the usual seller,
        // owner 1 sells in the self-trade tests. Deposits debit
        // native 1:1, so each keeps 1T of quote and 1T of base.
        ledger.mint(&addr(1), 1_000_000_000_000);
        ledger.mint(&addr(9), 1_000_000_000_000);
        deposit(&ex, 1, 1_000_000_000_000);
        deposit(&ex, 9, 1_000_000_000_000);
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
        // Quote amount = 7_500_000_000_000 / 100_000_000 = 75_000
        // (scale-6). The seller nets 75_000 − 75 fee = 74_925 and
        // the buyer received 5_000 base into custody.
        let quote_amount = 75_000u64;
        assert_eq!(ledger.balance(&addr(1)), buyer_before - quote_amount);
        assert_eq!(ledger.balance(&addr(9)), seller_before + quote_amount - 75);
        assert_eq!(ex.base_balance(addr(1), mid), 1_000_000_000_000 + 5_000);
        assert_eq!(ex.fee_vault(mid), 75);
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
        // Fees per fill: 15 + 15 + 15 = 45 (floor per fill).
        let total_quote = 45_030u64;
        assert_eq!(ledger.balance(&addr(1)), buyer_before - total_quote);
        assert_eq!(ledger.balance(&addr(9)), seller_before + total_quote - 45);
        assert_eq!(ex.base_balance(addr(1), mid), 1_000_000_000_000 + 3_000);
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
        // The sell needs base custody: deposit the qty first (the
        // debit drops the seller to u64::MAX - 600_000, still close
        // enough to overflow on the fill's net payment).
        deposit(&ex, 9, 100_000);
        register(&ex, 9, 1, Side::Sell, 1_000_000_000, 100_000);
        // Registration escrowed the full 1_000_000.
        assert_eq!(ledger.balance(&addr(1)), 0);

        // Chain-computed quote = 1e9 * 100_000 / 1e8 = 1_000_000,
        // minus the 10bps fee = 999_000 — still overflows the
        // seller's u64::MAX - 600_000 balance.
        let fill = leg(0, 1_000_000_000, 100_000, 1, 1, 9, 1);
        let events = ex.handle(&ctx(1), &msg::batch_settle(&[fill])).unwrap();
        assert!(
            events.iter().any(|e| e.kind == "settlement_failed"),
            "expected settlement_failed event on credit overflow"
        );
        assert_eq!(
            ledger.balance(&addr(9)),
            u64::MAX - 600_000,
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
        // The fixture deposited 1_000 of base for the seller.
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 1_000);

        // The configured operator is accepted.
        let events = ex.handle(&ctx(0xAA), &msg).unwrap();
        assert!(events.iter().any(|e| e.kind == "batch_fill"));
        // Fill at the limit → zero rebate: the whole 10_000 escrow
        // slice pays out — the seller nets 10_000 − 10 fee.
        assert_eq!(ledger.balance(&addr(1)), buyer_after_register);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 1_000 + 9_990);
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
        // order's escrow stays held. (The fixture's 1_000 base
        // deposit was already debited at registration.)
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 1_000);
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
        deposit(&ex, 1, 10_000);
        register(&ex, 1, 2, Side::Sell, 1_000_000_000, 10_000);
        // Small pair for the over-remaining leg: 1 lot authorized.
        ledger.mint(&addr(3), 10_000_000_000);
        ledger.mint(&addr(4), 10_000_000_000);
        deposit(&ex, 4, 1_000);
        register(&ex, 3, 1, Side::Buy, 1_500_000_000, 1_000);
        register(&ex, 4, 1, Side::Sell, 1_000_000_000, 1_000);
        // Non-crossing pair for the limit violations: buy $12 max.
        ledger.mint(&addr(5), 10_000_000_000);
        ledger.mint(&addr(6), 10_000_000_000);
        deposit(&ex, 6, 10_000);
        register(&ex, 5, 1, Side::Buy, 1_200_000_000, 10_000);
        register(&ex, 6, 1, Side::Sell, 1_000_000_000, 10_000);
        // High sell limit for the below-limit leg.
        ledger.mint(&addr(8), 10_000_000_000);
        deposit(&ex, 8, 10_000);
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
        // Only the valid leg settled: seller netted 10_000 − 10 fee
        // = 9_990 of quote (the fixture's 100_000 base deposit was
        // already debited from its ledger balance).
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 100_000 + 9_990);
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
        // (escrow 45_000 − rebate 5_000 − pays 40_000). Seller nets
        // 40_000 − 40 fee = 39_960; its ledger balance also carried
        // the fixture's 3_000 base deposit.
        assert_eq!(ledger.balance(&addr(1)), 10_000_000_000 - 40_000);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 3_000 + 39_960);
        // The 40 quote of fees accrued to market 0's vault.
        assert_eq!(ex.fee_vault(0), 40);
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
            deposit(&ex, seller, 10_000);
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
        // 2×(10_000 − 10 fee) = 19_980 quote units net, paid out of
        // the buy order's escrow (the seller's 10_000 base deposit
        // was already debited).
        assert_eq!(ledger.balance(&addr(7)), 10_000_000_000 - 10_000 + 19_980);
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

        // Cost = 15_000 + 15_010 = 30_010 quote units; seller nets
        // 30_010 − (15 + 15) fees = 29_980 and delivers 2_000 base.
        assert_eq!(ledger.balance(&addr(1)), buyer_before - 30_010);
        assert_eq!(ledger.balance(&addr(9)), seller_before + 30_010 - 30);
        assert_eq!(ex.base_balance(addr(1), mid), 1_000_000_000_000 + 2_000);
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
        deposit(&ex, 9, 2_000);

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
        deposit(&ex, 9, 1_000);

        // Maker rests the buy — balance drops to zero (fully reserved).
        ex.handle(&ctx(5), &msg::place(mid, limit(Side::Buy, 500, 1, 5))).unwrap();
        assert_eq!(ledger.balance(&addr(5)), 0);

        // Taker sell fills the maker's bid. The seller must receive
        // 15_000 − 15 fee even though the buyer's free balance is 0 —
        // the money comes from the held reservation.
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 - 1_000 + 14_985);
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
        // Seller netted 15_000 − 15 fee for the filled lot.
        assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 + 15_000 - 15);
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

        // Reserved 16_000, paid 15_000 → net 15_000 gone. The seller
        // nets 15_000 − 15 fee.
        assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
        assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 + 15_000 - 15);
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

        // Sells escrow base custody, not quote: owner 9 deposits
        // 5_000 base, registers the sell, and its ledger balance is
        // untouched while the base moves into the order's `reserved`.
        ledger.mint(&addr(9), 5_000);
        deposit(&ex, 9, 5_000);
        assert_eq!(ledger.balance(&addr(9)), 0);
        ex.handle(&ctx(9), &msg::register_order(0, Side::Sell, 1_000_000_000, 5_000, 3)).unwrap();
        assert_eq!(ledger.balance(&addr(9)), 0);
        assert_eq!(ex.base_balance(addr(9), 0), 0, "sell escrowed the full qty");
        // Cancel returns the escrow to free custody (not the ledger).
        ex.handle(&ctx(9), &msg::cancel_registered(3)).unwrap();
        assert_eq!(ex.base_balance(addr(9), 0), 5_000);
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
        deposit(&ex, 9, 10_000);
        register(&ex, 9, 1, Side::Sell, 1_000_000_000, 10_000);

        // The buy key (1,1) was never registered — the operator
        // cannot conjure a buyer.
        let events = ex
            .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
            .unwrap();
        assert!(events.iter().any(|e| e.kind == "fill_rejected"));
        assert!(!events.iter().any(|e| e.kind == "batch_fill"));
        assert_eq!(ledger.balance(&addr(1)), 10_000_000_000);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 10_000);
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
        // 1_000 base deposit + 10_000 − 10 fee netted.
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 1_000 + 9_990);
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
        // Seller nets 20_000 − 20 fee; its 2_000 base deposit was
        // already debited at registration.
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 2_000 + 19_980);
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
        // (Owner 9's earlier 5_000 deposit is fully escrowed by the
        // live sell; deposit more before registering a second.)
        deposit(&ex, 9, 1_000);
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

    // ── Base-asset custody (DvP) ────────────────────────────────────

    /// Sum every committed base-custody slot: free balances, book
    /// holds, and sell-side `reserved` on registered orders. Tests
    /// assert this equals deposits minus withdrawals — the custody
    /// conservation invariant.
    fn total_base_custody(ex: &ExchangeModule) -> u64 {
        let inner = ex.inner.lock().unwrap();
        let free: u64 = inner.base_balances.values().sum();
        let held: u64 = inner.base_holds.values().sum();
        let escrowed: u64 =
            inner.registered.values().filter(|o| o.side == Side::Sell).map(|o| o.reserved).sum();
        free + held + escrowed
    }

    /// A deposit debits native 1:1 into free base custody — the
    /// module never mints unbacked base.
    #[test]
    fn deposit_base_debits_native_into_custody() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(2), 50_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();

        let events = ex.handle(&ctx(2), &msg::deposit_base(0, 20_000)).unwrap();
        assert_eq!(events[0].kind, "base_deposited");
        assert_eq!(ledger.balance(&addr(2)), 30_000);
        assert_eq!(ex.base_balance(addr(2), 0), 20_000);
    }

    /// Deposits debit the sender's ledger balance into custody and
    /// withdrawals reverse it — rejected shapes (zero, unlisted
    /// market, overdrawn custody) move nothing.
    #[test]
    fn deposit_withdraw_base_edges() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(2), 50_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();
        let mid = 0;

        deposit(&ex, 2, 20_000);
        assert_eq!(ledger.balance(&addr(2)), 30_000);
        assert_eq!(ex.base_balance(addr(2), mid), 20_000);

        ex.handle(&ctx(2), &msg::withdraw_base(mid, 8_000)).unwrap();
        assert_eq!(ledger.balance(&addr(2)), 38_000);
        assert_eq!(ex.base_balance(addr(2), mid), 12_000);

        // Overdraft: only 12_000 free.
        assert!(matches!(
            ex.handle(&ctx(2), &msg::withdraw_base(mid, 12_001)).unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        // Zero amounts and unlisted markets are rejected.
        assert!(matches!(
            ex.handle(&ctx(2), &msg::deposit_base(mid, 0)).unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        assert!(matches!(
            ex.handle(&ctx(2), &msg::withdraw_base(mid, 0)).unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        assert!(matches!(
            ex.handle(&ctx(2), &msg::deposit_base(200, 1_000)).unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        // Deposit beyond the ledger balance is rejected.
        assert!(matches!(
            ex.handle(&ctx(2), &msg::deposit_base(mid, 99_000_000)).unwrap_err(),
            ExecError::ModuleRejected(_)
        ));
        assert_eq!(ex.base_balance(addr(2), mid), 12_000);
    }

    /// A sell order on the book path must prove base custody: no
    /// deposit → no order. The book is untouched by the rejection.
    #[test]
    fn sell_rejected_without_base_custody() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(9), 1_000_000_000_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();
        let mid = 0;

        // Owner 9 has quote but no base custody — the sell must
        // reject BEFORE the book is touched.
        let err = ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(ex.resting_count(mid), 0);

        // Depositing less than the order needs still rejects.
        deposit(&ex, 9, 999);
        assert!(
            ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).is_err(),
            "999 < 1_000 required"
        );
        deposit(&ex, 9, 1);
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        assert_eq!(ex.resting_count(mid), 1);
        // The full qty moved from free custody into the hold.
        assert_eq!(ex.base_balance(addr(9), mid), 0);
        assert_eq!(ex.base_hold(addr(9), mid), 1_000);
    }

    /// Cancel releases a resting sell's base hold back to free
    /// custody — symmetric with the buy-side quote refund.
    #[test]
    fn cancel_resting_sell_releases_base_hold() {
        let (_ledger, ex) = ledger_and_exchange();
        let mid = 0;
        let free_before = ex.base_balance(addr(9), mid);

        let events = ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 2, 9))).unwrap();
        let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));
        assert_eq!(ex.base_hold(addr(9), mid), 2_000);
        assert_eq!(ex.base_balance(addr(9), mid), free_before - 2_000);

        ex.handle(&ctx(9), &msg::cancel(mid, order_id)).unwrap();
        assert_eq!(ex.base_hold(addr(9), mid), 0);
        assert_eq!(ex.base_balance(addr(9), mid), free_before);
    }

    /// The core `DvP` property on the book path: a fill moves base
    /// seller→buyer AND quote buyer→seller in one state transition.
    /// The seller's ledger gain is net of the protocol fee; the fee
    /// lands in the market vault.
    #[test]
    fn book_fill_is_delivery_versus_payment() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;
        let seller_free = ex.base_balance(addr(9), mid);
        let buyer_free = ex.base_balance(addr(1), mid);

        // Maker sell 4 lots, taker buy fills 3, remainder rests.
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 4, 9))).unwrap();
        assert_eq!(ex.base_hold(addr(9), mid), 4_000);
        assert_eq!(ex.base_balance(addr(9), mid), seller_free - 4_000);
        let seller_quote = ledger.balance(&addr(9));
        let buyer_quote = ledger.balance(&addr(1));

        let ioc = NewOrder {
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Ioc,
            price: Price(1_500_000_000),
            qty: Qty(3_000),
            owner: addr(1),
            stp: StpMode::None,
        };
        ex.handle(&ctx(1), &msg::place(mid, ioc)).unwrap();

        // Base: 3_000 delivered to the buyer; the maker's hold keeps
        // the 1_000 remainder for its still-resting sell.
        assert_eq!(ex.base_balance(addr(1), mid), buyer_free + 3_000);
        assert_eq!(ex.base_hold(addr(9), mid), 1_000);
        // Quote: buyer paid 45_000 gross; seller netted 45_000 − 45.
        assert_eq!(ledger.balance(&addr(1)), buyer_quote - 45_000);
        assert_eq!(ledger.balance(&addr(9)), seller_quote + 45_000 - 45);
        assert_eq!(ex.fee_vault(mid), 45);
    }

    /// A taker sell delivers its admission-reserved base to the
    /// resting maker buy — and an IOC remainder comes back free.
    #[test]
    fn taker_sell_delivers_reserved_base() {
        let (ledger, ex) = ledger_and_exchange();
        let mid = 0;

        ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        let taker_free = ex.base_balance(addr(9), mid);
        let maker_free = ex.base_balance(addr(1), mid);
        let seller_quote = ledger.balance(&addr(9));

        // IOC sell 3 lots vs a 1-lot bid: 1 fills, 2 die unfilled.
        let ioc = NewOrder {
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Ioc,
            price: Price(1_000_000_000),
            qty: Qty(3_000),
            owner: addr(9),
            stp: StpMode::None,
        };
        ex.handle(&ctx(9), &msg::place(mid, ioc)).unwrap();

        // 1_000 delivered to the maker; the 2_000 dead remainder
        // released back to the taker's free custody.
        assert_eq!(ex.base_balance(addr(9), mid), taker_free - 1_000);
        assert_eq!(ex.base_balance(addr(1), mid), maker_free + 1_000);
        assert_eq!(ex.base_hold(addr(9), mid), 0);
        assert_eq!(ledger.balance(&addr(9)), seller_quote + 15_000 - 15);
    }

    /// A GTC sell's unfilled remainder becomes the resting order's
    /// hold — not free custody, not stranded.
    #[test]
    fn gtc_sell_remainder_becomes_hold() {
        let (_ledger, ex) = ledger_and_exchange();
        let mid = 0;
        let free_before = ex.base_balance(addr(9), mid);

        ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 3, 9))).unwrap();

        // 1 lot filled+delivered, 2 rest as the maker hold.
        assert_eq!(ex.base_hold(addr(9), mid), 2_000);
        assert_eq!(ex.base_balance(addr(9), mid), free_before - 3_000);
        assert_eq!(ex.resting_count(mid), 1);
    }

    /// Registered sells escrow base at registration; cancel refunds
    /// to free custody, never the ledger.
    #[test]
    fn registered_sell_escrow_is_base() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(9), 10_000_000_000);
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();

        // A sell registration without base custody is rejected.
        assert!(matches!(
            ex.handle(&ctx(9), &msg::register_order(0, Side::Sell, 1_000_000_000, 5_000, 1))
                .unwrap_err(),
            ExecError::ModuleRejected(_)
        ));

        deposit(&ex, 9, 5_000);
        register(&ex, 9, 1, Side::Sell, 1_000_000_000, 5_000);
        assert_eq!(ex.base_balance(addr(9), 0), 0);

        ex.handle(&ctx(9), &msg::cancel_registered(1)).unwrap();
        assert_eq!(ex.base_balance(addr(9), 0), 5_000);
        assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 5_000);
    }

    /// The batch path delivers base seller→buyer custody alongside
    /// the quote credit, consumes the sell's escrow qty-for-qty, and
    /// accrues the fee — all in one committed transition.
    #[test]
    fn batch_settle_delivers_base_and_fee() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 5_000);
        // The fixture deposited 5_000 for the sell — all escrowed.
        assert_eq!(ex.base_balance(addr(9), 0), 0);

        // Fill 2 lots at $10: pays 20_000, fee 20.
        let ev = ex
            .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 2_000, 1, 1, 9, 1)]))
            .unwrap();
        assert!(ev.iter().any(|e| e.kind == "batch_fill"));
        assert!(ev.iter().any(|e| e.kind == "base_delivered"));
        assert_eq!(ex.base_balance(addr(1), 0), 2_000);
        assert_eq!(ex.fee_vault(0), 20);

        // The sell's remaining escrow is 3_000 — cancelable back to
        // free custody.
        ex.handle(&ctx(9), &msg::cancel_registered(1)).unwrap();
        assert_eq!(ex.base_balance(addr(9), 0), 3_000);
    }

    /// Conservation: free custody + book holds + sell-side escrow
    /// always equal deposits minus withdrawals, across a mixed
    /// sequence of places, fills, cancels, deposits, withdrawals,
    /// and a batch settle. The complementary native-side invariant:
    /// total minted = Σ free ledger balances + Σ base custody +
    /// buy-side escrows + the fee vault (resting book buys hold
    /// `limit × remaining` implicitly — none rest at the end here).
    #[test]
    fn base_custody_conserves_across_mixed_ops() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let mut ex = ExchangeModule::with_ledger(ledger.clone());
        ex.set_settlement_operator(addr(0xAA));
        ex.list_market(test_cfg()).unwrap();
        ledger.mint(&addr(1), 10_000_000_000);
        ledger.mint(&addr(9), 10_000_000_000);
        ledger.mint(&addr(3), 10_000_000_000);
        let mid = 0;
        let minted = 30_000_000_000u64;

        // Deposits: 7_000 + 4_000 + 2_000 = 13_000 custodied.
        deposit(&ex, 9, 7_000);
        deposit(&ex, 1, 4_000);
        deposit(&ex, 3, 2_000);
        assert_eq!(total_base_custody(&ex), 13_000);

        // Rest a 4-lot sell (9) and a 2-lot sell (3); partially fill
        // 9's order with a taker buy; withdraw some free custody.
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 4, 9))).unwrap();
        ex.handle(&ctx(3), &msg::place(mid, limit(Side::Sell, 501, 2, 3))).unwrap();
        assert_eq!(total_base_custody(&ex), 13_000);
        ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 2, 1))).unwrap();
        assert_eq!(total_base_custody(&ex), 13_000);
        ex.handle(&ctx(1), &msg::withdraw_base(mid, 1_000)).unwrap();
        assert_eq!(total_base_custody(&ex), 12_000);

        // Registered pair + batch fill of 1 lot.
        deposit(&ex, 9, 3_000);
        register(&ex, 1, 7, Side::Buy, 1_000_000_000, 1_000);
        register(&ex, 9, 7, Side::Sell, 1_000_000_000, 1_000);
        assert_eq!(total_base_custody(&ex), 15_000);
        ex.handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 7, 9, 7)]))
            .unwrap();
        assert_eq!(total_base_custody(&ex), 15_000);

        // Sweep the best ask — 9's 2-lot remainder @500 — with a
        // taker buy: the maker's hold drains into the buyer's
        // custody; total unchanged.
        ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 501, 2, 1))).unwrap();
        assert_eq!(total_base_custody(&ex), 15_000);

        // Native-side conservation: supply = free ledger + base
        // custody + buy escrows + fee vault. No book buys rest at
        // the end (the sweep filled all asks within its limit) and
        // the registered buy was fully consumed, so no implicit
        // quote holds remain.
        let ledger_total: u64 = [addr(1), addr(3), addr(9)].iter().map(|a| ledger.balance(a)).sum();
        let custody = total_base_custody(&ex);
        let buy_escrow: u64 = ex
            .inner
            .lock()
            .unwrap()
            .registered
            .values()
            .filter(|o| o.side == Side::Buy)
            .map(|o| o.reserved)
            .sum();
        assert_eq!(
            minted,
            ledger_total + custody + buy_escrow + ex.fee_vault(0),
            "supply == free + base custody + buy escrows + fee vault"
        );
    }

    /// Custody maps are committed state: a snapshot round-trip must
    /// restore free balances, book holds, and the fee vault — a
    /// replica that lost them would settle different fills.
    #[test]
    fn custody_state_survives_snapshot() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 10_000_000_000);
        ledger.mint(&addr(9), 10_000_000_000);
        let mut src = ExchangeModule::with_ledger(ledger.clone());
        src.set_settlement_operator(addr(0xAA));
        src.list_market(test_cfg()).unwrap();
        deposit(&src, 9, 10_000);
        deposit(&src, 1, 5_000);
        // Rest a sell (hold 4_000), fill 1 lot via a registered pair
        // (fee accrues), leave free balances behind.
        src.handle(&ctx(9), &msg::place(0, limit(Side::Sell, 500, 4, 9))).unwrap();
        register(&src, 1, 1, Side::Buy, 1_000_000_000, 1_000);
        register(&src, 9, 1, Side::Sell, 1_000_000_000, 1_000);
        src.handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
            .unwrap();
        let root = src.state_root();

        let snapshot = src.export_state().expect("exports state");
        let mut dst = ExchangeModule::with_ledger(ledger);
        dst.set_settlement_operator(addr(0xAA));
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), root, "custody state is committed");
        assert_eq!(dst.base_hold(addr(9), 0), 4_000);
        assert_eq!(dst.base_balance(addr(1), 0), 5_000 + 1_000);
        assert_eq!(dst.fee_vault(0), 10);
    }

    /// Pre-custody blobs decode with empty custody maps — and a
    /// registered sell that predates custody (`reserved == 0`) is
    /// unfillable but cancelable. Fail-closed, not grandfathered.
    #[test]
    fn pre_custody_sell_orders_cannot_settle() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 10_000_000_000);
        ledger.mint(&addr(9), 10_000_000_000);
        let mut src = ExchangeModule::with_ledger(ledger.clone());
        src.set_settlement_operator(addr(0xAA));
        src.list_market(test_cfg()).unwrap();
        // A live buy with real escrow stays fillable post-import.
        register(&src, 1, 1, Side::Buy, 1_000_000_000, 5_000);

        // Hand-craft a pre-custody blob: decode the source's own
        // export, inject a naked sell (`reserved == 0`, the legacy
        // shape), and re-encode WITHOUT the trailing custody
        // section — exactly what a pre-upgrade blob contains.
        let snapshot = src.export_state().expect("exports state");
        let (canon_bytes, store_map) =
            framework::decode_state_blob(&snapshot.entries[0].1).expect("blob decodes");
        let mut r = framework::CanonicalReader::new(canon_bytes);
        // `stage_blob_snapshot` consumes the store-subtree root
        // before handing the reader to the module decoder.
        assert_eq!(
            r.get_root().expect("root"),
            framework::subtree_root_map(&store_map),
            "store section must hash to the committed root"
        );
        let (markets, endorsements, mut registered, _, _, _) =
            ExchangeModule::decode_committed(&mut r, &store_map, 256).expect("decodes");
        registered.insert(
            crate::OrderKey { owner: addr(9), client_id: 9 },
            crate::RegisteredOrder {
                market: 0,
                side: Side::Sell,
                limit_price: 1_000_000_000,
                remaining: 5_000,
                reserved: 0,
            },
        );
        let mut w = framework::CanonicalState::new();
        w.put_root(&framework::subtree_root_map(&store_map));
        w.put_count(markets.len());
        let mut book_bytes = Vec::new();
        let mut entries = Vec::new();
        for engine in &markets {
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
        endorsements.write_canonical(&mut w);
        w.put_count(registered.len());
        for (key, order) in &registered {
            w.put_addr(&key.owner);
            w.put_u64(key.client_id);
            w.put_u16(order.market);
            w.put_u8(encode_side(order.side));
            w.put_u64(order.limit_price);
            w.put_u64(order.remaining);
            w.put_u64(order.reserved);
        }
        // No custody tail — the pre-upgrade blob shape.
        let kv: framework::KVStore = std::sync::Mutex::new(store_map);
        let snapshot = storage::Snapshot {
            height: 0,
            entries: vec![(
                framework::state_blob_key(),
                framework::encode_state_blob(w.as_bytes(), &kv),
            )],
        };

        let mut dst = ExchangeModule::with_ledger(ledger.clone());
        dst.set_settlement_operator(addr(0xAA));
        dst.import_state(&snapshot).unwrap();

        // The legacy sell cannot settle — `reserved` (0) < any qty.
        let events = dst
            .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 9)]))
            .unwrap();
        assert!(events.iter().any(|e| e.kind == "fill_rejected"));
        assert!(!events.iter().any(|e| e.kind == "batch_fill"));

        // …but it can still be canceled (refund = 0 base, harmless).
        dst.handle(&ctx(9), &msg::cancel_registered(9)).unwrap();
    }

    // ── Property tests ───────────────────────────────────────────
    //
    // The fixed tests above pin specific sequences; these sweep the
    // op space itself. The property under test is the custody
    // conservation invariant: the committed base maps (free custody
    // + book holds + sell-side `reserved`) always equal deposits
    // minus withdrawals — the module can neither mint nor lose a
    // base unit, regardless of the order in which fills, cancels,
    // STP removals, and dead remainders interleave.

    use proptest::prelude::*;

    // One random op: `(owner_idx, kind, amount, tick)` where `kind`
    // selects deposit/withdraw/limit-sell/limit-buy/IOC-sell/IOC-
    // buy/cancel. Amounts and ticks are deliberately small and
    // lot-aligned so most orders are admissible — the invariant
    // must hold through successes AND rejections alike.
    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(48))]

        #[test]
        fn base_custody_conserved_over_random_ops(
            ops in proptest::collection::vec(
                (0u8..3, 0u8..7, 1_000u64..50_000, 0u64..3),
                1..192,
            ),
        ) {
            let ledger = Arc::new(framework::MemoryBalances::new());
            let ex = ExchangeModule::with_ledger(ledger.clone());
            ex.list_market(test_cfg()).unwrap();
            let owners = [1u8, 9, 3];
            for w in owners {
                ledger.mint(&addr(w), u64::MAX / 4);
            }
            let mid = 0u8;
            // Each owner's live resting orders — cancels draw only
            // from this set so they exercise the release path.
            let mut resting: [Vec<OrderId>; 3] = [Vec::new(), Vec::new(), Vec::new()];
            let mut custodied = 0u64;

            for (who, op, amount, tick) in ops {
                let wi = usize::from(who);
                let lots = (amount / 1_000 % 8) + 1;
                let res = match op {
                    0 => ex.handle(&ctx(who), &msg::deposit_base(mid, amount)),
                    1 => ex.handle(&ctx(who), &msg::withdraw_base(mid, amount)),
                    2 => ex.handle(&ctx(who), &msg::place(mid, limit(Side::Sell, tick, lots, who))),
                    3 => ex.handle(&ctx(who), &msg::place(mid, limit(Side::Buy, tick, lots, who))),
                    4 => ex.handle(
                        &ctx(who),
                        &msg::place(
                            mid,
                            NewOrder {
                                side: Side::Sell,
                                order_type: OrderType::Limit,
                                tif: TimeInForce::Ioc,
                                price: Price(1_000_000_000 + tick * 1_000_000),
                                qty: Qty(lots * 1_000),
                                owner: addr(who),
                                stp: StpMode::None,
                            },
                        ),
                    ),
                    5 => ex.handle(
                        &ctx(who),
                        &msg::place(
                            mid,
                            NewOrder {
                                side: Side::Buy,
                                order_type: OrderType::Limit,
                                tif: TimeInForce::Ioc,
                                price: Price(1_000_000_000 + tick * 1_000_000),
                                qty: Qty(lots * 1_000),
                                owner: addr(who),
                                stp: StpMode::None,
                            },
                        ),
                    ),
                    _ => {
                        // Cancel the owner's oldest tracked resting
                        // order, if any; otherwise a harmless no-op.
                        match resting[wi].first().copied() {
                            Some(id) => {
                                let r = ex.handle(&ctx(who), &msg::cancel(mid, id));
                                // Err means the id is dead (filled
                                // or already canceled) — either way
                                // it is no longer live, so untrack.
                                resting[wi].remove(0);
                                r
                            }
                            None => continue,
                        }
                    }
                };
                let Ok(events) = res else {
                    // Rejected ops move nothing — still assert.
                    prop_assert_eq!(total_base_custody(&ex), custodied);
                    continue;
                };
                match op {
                    0 => custodied += amount,
                    1 => custodied -= amount,
                    2 | 3 => {
                        // A GTC place that rests emits its order id
                        // in the trailing "resting" outcome event.
                        if let Some(e) = events.iter().find(|e| e.kind == "resting") {
                            let id = OrderId(u64::from_le_bytes(
                                e.data[1..9].try_into().unwrap(),
                            ));
                            resting[wi].push(id);
                        }
                        // Filled orders may drop other owners' ids —
                        // prune anything no longer cancelable lazily:
                        // a stale id just makes cancel return Err,
                        // which the `is_ok` gate already filters.
                    }
                    _ => {}
                }
                prop_assert_eq!(total_base_custody(&ex), custodied);
            }
        }
    }
}
