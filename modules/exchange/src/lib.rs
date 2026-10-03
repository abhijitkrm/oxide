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

use executor::{Event, ExecError, Module, RejectCategory, TxContext};
use framework::module_id;
use primitives::fixed::{Price, Qty, qty_add, qty_sub};
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
    /// The owner's limit price: the maximum a buy pays, the minimum
    /// a sell accepts.
    limit_price: Price,
    /// Unfilled authorized quantity of the market's base asset.
    remaining: Qty,
    /// The escrowed obligation, carrying its denomination in the
    /// variant — the side is *derived* from it (`RegisteredOrder::
    /// side`), so the escrow's unit can never disagree with the
    /// direction it secures.
    reserved: Reserved,
}

/// A trading-key linkage entry: the committed record binding an
/// Ed25519-derived trading `owner` to the secp256k1 ledger account
/// authorized to operate it. Written only by `TAG_LINK_TRADING_KEY`
/// (consent-verified) and `TAG_UNLINK_TRADING_KEY` (tombstones the
/// link by zeroing `secp` while preserving `epoch` for replay
/// protection — the entry is never removed so a captured consent
/// can never re-bind a revoked epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkedEntry {
    /// The secp256k1 ledger address the trading key consented to —
    /// the only envelope sender the link-gated handlers accept for
    /// this owner. `Address::ZERO` marks a revoked link.
    secp: Address,
    /// Monotonic per-owner counter: the epoch of the last applied
    /// link/unlink. Signatures bind `stored + 1`, so every applied
    /// message advances it and no captured signature can replay —
    /// relinking after a revocation needs a fresh consent at the
    /// next epoch.
    epoch: u64,
}

/// The escrowed obligation of a [`RegisteredOrder`], denominated in
/// the side's obligation asset — quote units for buys (ledger-held
/// worst-case cost), base qty for sells (custody-held delivery).
/// Carrying the denomination in the type makes `side: Sell` paired
/// with quote-denominated escrow unrepresentable, and every release/
/// refund site matches on the denomination rather than trusting a
/// separate `side` field to agree (audit §9.B, available-vs-reserved
/// and side-denominated units).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reserved {
    /// Worst-case quote cost (`limit × qty / PRICE_SCALE`), debited
    /// from the owner's ledger balance at registration — scale-6
    /// quote units, released per fill at the limit price.
    Quote(u64),
    /// The full base quantity moved out of the owner's free base
    /// custody at registration — a `Qty` of the market's base asset,
    /// consumed qty-for-qty per fill.
    Base(Qty),
}

impl Reserved {
    /// The side this escrow secures — buys escrow quote, sells
    /// escrow base. `RegisteredOrder::side` delegates here, so the
    /// denomination and the direction are one fact, not two fields
    /// that could diverge.
    const fn side(self) -> Side {
        match self {
            Self::Quote(_) => Side::Buy,
            Self::Base(_) => Side::Sell,
        }
    }

    /// The escrowed amount in the denomination's own units. The raw
    /// `u64` is only meaningful to a caller that knows the
    /// denomination — from `side()` or by matching the variant.
    const fn get(self) -> u64 {
        match self {
            Self::Quote(v) => v,
            Self::Base(v) => v.0,
        }
    }
}

impl RegisteredOrder {
    /// Buy or sell — derived from the escrow's denomination, so the
    /// answer can never disagree with the units `reserved` holds.
    const fn side(&self) -> Side {
        self.reserved.side()
    }
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

// ── Trading-key linkage (venue egress, system-audit S2) ──────────────
//
// The off-chain matcher's trading credential is Ed25519; the chain's
// ledger credential is secp256k1. The two share the 20-byte address
// namespace but are cryptographically unrelated — byte equality proves
// nothing (a crafted Ed25519 key cannot produce a secp256k1 signature
// for the same bytes and vice versa). Settlement therefore books
// custody under Ed25519-derived owners that no tx envelope can ever
// sign for. The linkage registry closes that: a secp256k1 sender binds
// itself to a trading key via an Ed25519-signed consent, and
// link-gated messages then let the linked ledger account operate —
// and withdraw from — the trading owner's committed state.

/// Link-trading-key message tag: the secp256k1 sender registers
/// itself as the ledger operator of an Ed25519 trading owner.
/// Body: `[pubkey:32][consent_sig:64]` = 96 bytes; `consent_sig`
/// covers `LINK_CONSENT_DOMAIN || sender || pubkey || epoch` where
/// `epoch` is the owner's next link epoch. Latest wins — a relink
/// to a different ledger account only needs the trading key's
/// consent for the new epoch.
const TAG_LINK_TRADING_KEY: u8 = 8;

/// Unlink-trading-key message tag: sever the link so no ledger
/// account may act for the trading owner. Any sender may relay it —
/// the Ed25519 signature inside is the authorization.
/// Body: `[pubkey:32][sig:64]` = 96 bytes; `sig` covers
/// `UNLINK_CONSENT_DOMAIN || pubkey || epoch`.
const TAG_UNLINK_TRADING_KEY: u8 = 9;

/// Deposit-base-for message tag: like `TAG_DEPOSIT_BASE` but the
/// custody beneficiary is an explicit `owner` (a linked trading
/// account). Permissionless — funding someone else's custody can
/// only increase what their link can withdraw.
/// Body: `[owner:20][market:1][amount:8]` = 29 bytes.
const TAG_DEPOSIT_BASE_FOR: u8 = 10;

/// Withdraw-linked message tag: the sender pulls free base custody
/// out of a trading `owner`'s `(owner, market)` entry into the
/// sender's own ledger balance. Requires `linked[owner] == sender`.
/// Body: `[owner:20][market:1][amount:8]` = 29 bytes.
const TAG_WITHDRAW_LINKED: u8 = 11;

/// Sweep-linked message tag: the sender moves `amount` of the
/// trading `owner`'s *ledger* balance (buy-escrow refunds and
/// settlement rebates credit it) into the sender's own balance.
/// Requires `linked[owner] == sender`. Without this, quote
/// returning to a linked owner would be stranded — an Ed25519
/// address can never submit a signed tx itself.
/// Body: `[owner:20][amount:8]` = 28 bytes.
const TAG_SWEEP_LINKED: u8 = 12;

/// Register-linked message tag: register an off-chain-matched
/// order under a linked `owner` — the registered-order settlement
/// path is otherwise unreachable for Ed25519 identities, since
/// `TAG_REGISTER_ORDER` keys the sender. Escrows draw on the
/// *owner's* ledger (buys) and base custody (sells), identically
/// to self-registration.
/// Body: `[owner:20][market:2][side:1][price:8][qty:8]
/// [client_id:8]` = 47 bytes.
const TAG_REGISTER_LINKED: u8 = 13;

/// Cancel-linked message tag: cancel a linked owner's registered
/// order, refunding its escrow to the owner. Without it, escrow
/// under a linked account could only ever be consumed by fills.
/// Body: `[owner:20][client_id:8]` = 28 bytes.
const TAG_CANCEL_LINKED: u8 = 14;

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
/// `[pubkey:32][signature:64]` = 96 (link and unlink share the
/// same body shape).
const LINK_BODY_LEN: usize = 96;
/// `[owner:20][market:1][amount:8]` = 29 (deposit-for and
/// withdraw-linked share the same body shape).
const LINKED_CUSTODY_BODY_LEN: usize = 29;
/// `[owner:20][amount:8]` = 28 (sweep-linked).
const SWEEP_LINKED_BODY_LEN: usize = 28;
/// `[owner:20][market:2][side:1][price:8][qty:8][client_id:8]` = 47.
const REGISTER_LINKED_BODY_LEN: usize = 47;
/// `[owner:20][client_id:8]` = 28.
const CANCEL_LINKED_BODY_LEN: usize = 28;

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
    /// The module's KV subtree — market configs and the
    /// next-order-id counter. `CommittedStore` keeps its subtree
    /// fold maintained per write; `state_root` reads the fold.
    store: Mutex<framework::CommittedStore>,
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

/// Per-map domain separation for the committed-map leaf preimages —
/// a `(key, value)` encoding can never alias into another map's
/// fold even when two maps share field types. Module-local
/// numbering: folds never mix across modules.
const MAP_TAG_STORE: u64 = 1;
const MAP_TAG_REGISTERED: u64 = 2;
const MAP_TAG_BASE_BALANCES: u64 = 3;
const MAP_TAG_BASE_HOLDS: u64 = 4;
const MAP_TAG_FEE_VAULT: u64 = 5;
const MAP_TAG_BOOK: u64 = 6;
const MAP_TAG_LINKED: u64 = 7;

/// Signing domain for the trading key's link consent — separates
/// these signatures from order signatures (`oxide-order-v2`) and
/// every other Ed25519 message in the system so a consent can never
/// be transplanted into a different context.
const LINK_CONSENT_DOMAIN: &[u8] = b"oxide-link-key-v1";

/// Signing domain for the trading key's unlink authorization.
const UNLINK_CONSENT_DOMAIN: &[u8] = b"oxide-unlink-key-v1";

/// The committed KV-subtree leaf — the same record shape
/// `subtree_root_map` folds sequentially.
// The `fn(&K, &V) -> Hash` signature is fixed by `CommittedMap`'s
// leaf slot — borrowing `Vec<u8>` is the uniform shape, not a
// style choice.
#[allow(clippy::ptr_arg)]
fn store_leaf(k: &Vec<u8>, v: &Vec<u8>) -> Hash {
    framework::committed_store_leaf(MAP_TAG_STORE, k, v)
}

/// `(owner ‖ client_id ‖ market ‖ side ‖ limit ‖ remaining ‖
/// reserved)` — the same field order `write_committed` writes into
/// the canonical stream, so the fold commits the same information
/// the serialized section does.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn registered_leaf(k: &OrderKey, v: &RegisteredOrder) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(&k.owner)
        .put_u64(k.client_id)
        .put_u16(v.market)
        .put_u8(codec::encode_side(v.side()))
        .put_u64(v.limit_price.0)
        .put_u64(v.remaining.0)
        .put_u64(v.reserved.get());
    framework::committed_leaf(MAP_TAG_REGISTERED, w.as_bytes())
}

/// `(owner ‖ market ‖ qty_le)` — mirrors `base_balances`'s record.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn base_balances_leaf(k: &(Address, u8), v: &Qty) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(&k.0).put_u8(k.1).put_u64(v.0);
    framework::committed_leaf(MAP_TAG_BASE_BALANCES, w.as_bytes())
}

/// `(owner ‖ market ‖ qty_le)` — mirrors `base_holds`'s record.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn base_holds_leaf(k: &(Address, u8), v: &Qty) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(&k.0).put_u8(k.1).put_u64(v.0);
    framework::committed_leaf(MAP_TAG_BASE_HOLDS, w.as_bytes())
}

/// `(market ‖ amount_le)` — mirrors `fee_vault`'s record.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn fee_vault_leaf(k: &u8, v: &u64) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_u8(*k).put_u64(*v);
    framework::committed_leaf(MAP_TAG_FEE_VAULT, w.as_bytes())
}

/// `(owner ‖ secp ‖ epoch)` — mirrors `linked`'s record.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn linked_leaf(k: &Address, v: &LinkedEntry) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(k).put_addr(&v.secp).put_u64(v.epoch);
    framework::committed_leaf(MAP_TAG_LINKED, w.as_bytes())
}

/// `(id ‖ side ‖ price ‖ qty ‖ owner)` — the same record shape
/// `write_canonical_state` appends per resting order, folded into
/// the engine's incremental `resting_fold` instead of being
/// re-serialized per block. Returns the raw leaf bytes for the
/// engine's `fn(&RestingEntry) -> [u8; 32]` slot — `trading` is a
/// dependency-free hot-path crate, so the hash itself stays in the
/// module.
fn book_resting_leaf(e: &trading::RestingEntry) -> [u8; 32] {
    let mut w = framework::CanonicalState::new();
    w.put_u64(e.id.0)
        .put_u8(codec::encode_side(e.side))
        .put_u64(e.price.0)
        .put_u64(e.qty.0)
        .put_addr(&e.owner);
    framework::committed_leaf(MAP_TAG_BOOK, w.as_bytes()).0
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
    /// `CommittedMap` keeps the map's root fold in lockstep with the
    /// contents — `state_root` reads the fold instead of
    /// re-serializing every registration.
    registered: framework::CommittedMap<OrderKey, RegisteredOrder>,
    /// Free base-asset custody: `(owner, market) → unreserved base
    /// qty` (scale-6). Units enter via `TAG_DEPOSIT_BASE` — each one
    /// backed 1:1 by a native-token ledger debit the module holds —
    /// and leave via `TAG_WITHDRAW_BASE`. Sell orders draw this down
    /// into `base_holds` (book path) or `RegisteredOrder::reserved`
    /// (registered path); fills deliver out of those holds into the
    /// buyer's entry here. Committed state.
    base_balances: framework::CommittedMap<(Address, u8), Qty>,
    /// Base locked by this account's resting sell orders on the
    /// book path: `(owner, market) → Σ unfilled sell qty`. A resting
    /// sell contributes its full remaining qty at rest; fills
    /// decrement into the buyer's `base_balances`, and cancels /
    /// non-fill book removals release back to `base_balances`. The
    /// invariant `holds[(o,m)] == Σ unfilled qty of o's resting sells
    /// on m` is maintained at every mutation point. Committed state.
    base_holds: framework::CommittedMap<(Address, u8), Qty>,
    /// Accrued protocol fees per market, in quote units — the
    /// committed sink every fill's `FEE_BPS` slice lands in. A
    /// governance withdrawal path is a deliberate residual; until it
    /// exists the vault only grows (bounded by cumulative volume, so
    /// `checked_add` guards are honored rather than assumed).
    /// Committed state.
    fee_vault: framework::CommittedMap<u8, u64>,
    /// Trading-key linkage: Ed25519-derived trading owner → the
    /// secp256k1 ledger account authorized to operate it (system-
    /// audit S2). Gated writes only — `TAG_LINK_TRADING_KEY` /
    /// `TAG_UNLINK_TRADING_KEY` — and read by every `*_LINKED`
    /// authorization check. Committed state: replicas disagreeing
    /// on links would authorize different withdrawals.
    linked: framework::CommittedMap<Address, LinkedEntry>,
}

/// The committed state a snapshot decodes into — the per-market
/// engines, pending governance endorsements, the registered-order
/// map, the base-asset custody maps, and the linkage registry, in
/// canonical layout order.
type CommittedState = (
    Vec<Option<MatchingEngine>>,
    framework::Endorsements,
    BTreeMap<OrderKey, RegisteredOrder>,
    BTreeMap<(Address, u8), Qty>,
    BTreeMap<(Address, u8), Qty>,
    BTreeMap<u8, u64>,
    BTreeMap<Address, LinkedEntry>,
);

mod codec;
mod decode;
mod handlers;
mod module_impl;
mod settle;

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
                registered: framework::CommittedMap::new(registered_leaf),
                base_balances: framework::CommittedMap::new(base_balances_leaf),
                base_holds: framework::CommittedMap::new(base_holds_leaf),
                fee_vault: framework::CommittedMap::new(fee_vault_leaf),
                linked: framework::CommittedMap::new(linked_leaf),
            }),
            store: Mutex::new(framework::CommittedStore::new(store_leaf)),
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
        let mut inner = framework::lock_state(&self.inner);
        // Find the first empty slot.
        let id = inner.markets.iter().position(Option::is_none).ok_or_else(|| {
            ExecError::rejected(RejectCategory::Precondition, "all 256 market slots taken")
        })?;
        // u8 market id space: position is 0..=255, fits u8.
        #[allow(clippy::cast_possible_truncation)]
        let id_u8 = id as u8;
        // Apply-time revalidation: the quorum path already rejected
        // invalid configs, but the decoded bytes are checked again so
        // a corrupted store cannot pair an unchecked config with an
        // engine — the proof type makes the check structural.
        let vcfg = cfg.validated().map_err(|e| {
            ExecError::rejected(RejectCategory::Internal, format!("market config: {e}"))
        })?;
        let book = DenseBook::new(vcfg).map_err(|e| {
            ExecError::rejected(RejectCategory::Internal, format!("book init: {e}"))
        })?;
        let mut engine = MatchingEngine::new(vcfg, book).map_err(|e| {
            ExecError::rejected(RejectCategory::Internal, format!("engine init: {e}"))
        })?;
        // Committed engines always carry the incremental book fold —
        // `state_root` reads `resting_fold()` instead of re-walking
        // the book. Enabled before any orders rest, so the fold is
        // ZERO until the first placement.
        engine.enable_resting_fold(book_resting_leaf);
        inner.markets[id] = Some(engine);
        // Persist the market config for state-root replay.
        let key = crate::codec::market_config_key(id_u8);
        framework::lock_state(&self.store).insert(
            key,
            crate::codec::encode_market_config(inner.markets[id].as_ref().unwrap().config()),
        );
        Ok(id_u8)
    }

    /// L1 market data: best bid/ask for a market.
    ///
    /// Returns `None` if the market does not exist.
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn l1(&self, market: u8) -> Option<L1> {
        let inner = framework::lock_state(&self.inner);
        let engine = inner.markets[usize::from(market)].as_ref()?;
        Some((engine.best_bid(), engine.best_ask()))
    }

    /// Number of resting orders in a market (for diagnostics / state
    /// inspection).
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn resting_count(&self, market: u8) -> u32 {
        framework::lock_state(&self.inner)
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
    pub fn base_balance(&self, owner: Address, market: u8) -> Qty {
        framework::lock_state(&self.inner)
            .base_balances
            .get(&(owner, market))
            .copied()
            .unwrap_or_default()
    }

    /// The account's base locked by resting sells on a market.
    /// Fills draw it down; cancels and book removals release it.
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn base_hold(&self, owner: Address, market: u8) -> Qty {
        framework::lock_state(&self.inner)
            .base_holds
            .get(&(owner, market))
            .copied()
            .unwrap_or_default()
    }

    /// Protocol fees accrued to a market's vault (quote units).
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    pub fn fee_vault(&self, market: u8) -> u64 {
        framework::lock_state(&self.inner).fee_vault.get(&market).copied().unwrap_or(0)
    }

    /// Quote escrow held on `market`: the implied `price × qty /
    /// PRICE_SCALE` reservation of every resting bid plus the
    /// `reserved` field of every live registered buy. Combined with
    /// [`base_balance`](Self::base_balance),
    /// [`base_hold`](Self::base_hold), [`fee_vault`](Self::fee_vault),
    /// and [`escrowed_base`](Self::escrowed_base), this closes the
    /// module's money-conservation equation from the outside —
    /// harnesses assert `Σ ledger + Σ all buckets == minted` instead
    /// of trusting internals.
    ///
    /// `#[doc(hidden)]`: a conservation probe for tests/fuzzers, not
    /// part of the query surface clients should depend on.
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    #[doc(hidden)]
    pub fn escrowed_quote(&self, market: u8) -> u64 {
        let inner = framework::lock_state(&self.inner);
        let mut total = 0u64;
        if let Some(Some(engine)) = inner.markets.get(usize::from(market)) {
            let mut entries = Vec::new();
            engine.resting_entries(&mut entries);
            for e in entries.iter().filter(|e| e.side == Side::Buy) {
                let q = u128::from(e.price.0) * u128::from(e.qty.0) / PRICE_SCALE;
                total = total.saturating_add(u64::try_from(q).unwrap_or(u64::MAX));
            }
        }
        for o in inner.registered.values() {
            if o.market == u16::from(market)
                && let Reserved::Quote(q) = o.reserved
            {
                total = total.saturating_add(q);
            }
        }
        total
    }

    /// Base-asset escrow on `market` held inside live registered
    /// sell orders' `reserved` fields. Book-path sells lock into
    /// `base_holds` instead — both buckets plus `base_balances` close
    /// the base conservation equation.
    ///
    /// `#[doc(hidden)]`: a conservation probe for tests/fuzzers.
    ///
    /// # Panics
    /// Panics if the inner mutex is poisoned.
    #[doc(hidden)]
    pub fn escrowed_base(&self, market: u8) -> u64 {
        framework::lock_state(&self.inner)
            .registered
            .values()
            .filter(|o| o.market == u16::from(market))
            .fold(0u64, |acc, o| match o.reserved {
                Reserved::Base(q) => acc.saturating_add(q.0),
                Reserved::Quote(_) => acc,
            })
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
    };
    use crate::codec::{encode_order_type, encode_side, encode_stp, encode_tif};

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
        msg.extend_from_slice(&cfg.tick_size.0.to_le_bytes());
        msg.extend_from_slice(&cfg.lot_size.0.to_le_bytes());
        msg.extend_from_slice(&cfg.min_price.0.to_le_bytes());
        msg.extend_from_slice(&cfg.max_price.0.to_le_bytes());
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

    /// Build the exact bytes an Ed25519 trading key signs to consent
    /// to a link: `LINK_CONSENT_DOMAIN ‖ secp ‖ pubkey ‖ epoch`.
    /// `epoch` must equal the owner's next epoch — `1` for a first
    /// link, otherwise the stored epoch `+ 1` (query the module's
    /// committed `linked` map). Shared by the signer and the module
    /// so the verification preimage can never drift.
    #[must_use]
    pub fn link_consent_message(secp: &super::Address, pubkey: &[u8; 32], epoch: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(super::LINK_CONSENT_DOMAIN.len() + 20 + 32 + 8);
        m.extend_from_slice(super::LINK_CONSENT_DOMAIN);
        m.extend_from_slice(&secp.0);
        m.extend_from_slice(pubkey);
        m.extend_from_slice(&epoch.to_le_bytes());
        m
    }

    /// Build the exact bytes an Ed25519 trading key signs to revoke
    /// a link: `UNLINK_CONSENT_DOMAIN ‖ pubkey ‖ epoch` with the
    /// same epoch rule as [`link_consent_message`].
    #[must_use]
    pub fn unlink_consent_message(pubkey: &[u8; 32], epoch: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(super::UNLINK_CONSENT_DOMAIN.len() + 32 + 8);
        m.extend_from_slice(super::UNLINK_CONSENT_DOMAIN);
        m.extend_from_slice(pubkey);
        m.extend_from_slice(&epoch.to_le_bytes());
        m
    }

    /// Build a link-trading-key message: the envelope sender
    /// registers itself as the ledger operator of the trading owner
    /// `crypto::ed25519::owner_address(pubkey)`. `consent_sig` is
    /// the Ed25519 signature over [`link_consent_message`].
    pub fn link_trading_key(pubkey: &[u8; 32], consent_sig: &[u8; 64]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::LINK_BODY_LEN);
        msg.push(super::TAG_LINK_TRADING_KEY);
        msg.extend_from_slice(pubkey);
        msg.extend_from_slice(consent_sig);
        msg
    }

    /// Build an unlink-trading-key message. Permissionless — any
    /// sender can relay it; the Ed25519 signature inside authorizes.
    pub fn unlink_trading_key(pubkey: &[u8; 32], sig: &[u8; 64]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::LINK_BODY_LEN);
        msg.push(super::TAG_UNLINK_TRADING_KEY);
        msg.extend_from_slice(pubkey);
        msg.extend_from_slice(sig);
        msg
    }

    /// Build a deposit-base-for message: the sender's ledger is
    /// debited and `owner` receives the base custody on `market` —
    /// how a linked trading account's custody is funded.
    pub fn deposit_base_for(owner: super::Address, market: u8, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::LINKED_CUSTODY_BODY_LEN);
        msg.push(super::TAG_DEPOSIT_BASE_FOR);
        msg.extend_from_slice(&owner.0);
        msg.push(market);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// Build a withdraw-linked message: the sender (the owner's
    /// linked ledger account) pulls `amount` of `owner`'s free base
    /// custody on `market` into its own ledger balance.
    pub fn withdraw_linked(owner: super::Address, market: u8, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::LINKED_CUSTODY_BODY_LEN);
        msg.push(super::TAG_WITHDRAW_LINKED);
        msg.extend_from_slice(&owner.0);
        msg.push(market);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// Build a sweep-linked message: the sender moves `amount` of
    /// `owner`'s native ledger balance into its own — the egress
    /// path for quote that settlement credits a linked owner.
    pub fn sweep_linked(owner: super::Address, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::SWEEP_LINKED_BODY_LEN);
        msg.push(super::TAG_SWEEP_LINKED);
        msg.extend_from_slice(&owner.0);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// Build a register-linked message: register an off-chain-
    /// matched order under the linked `owner`, escrowing the
    /// owner's funds exactly as a self-registration would.
    #[allow(clippy::too_many_arguments)]
    pub fn register_linked(
        owner: super::Address,
        market: u16,
        side: trading::Side,
        price: u64,
        qty: u64,
        client_id: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::REGISTER_LINKED_BODY_LEN);
        msg.push(super::TAG_REGISTER_LINKED);
        msg.extend_from_slice(&owner.0);
        msg.extend_from_slice(&market.to_le_bytes());
        msg.push(encode_side(side));
        msg.extend_from_slice(&price.to_le_bytes());
        msg.extend_from_slice(&qty.to_le_bytes());
        msg.extend_from_slice(&client_id.to_le_bytes());
        msg
    }

    /// Build a cancel-linked message: cancel `owner`'s registered
    /// order, refunding its escrow to the owner.
    pub fn cancel_linked(owner: super::Address, client_id: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + super::CANCEL_LINKED_BODY_LEN);
        msg.push(super::TAG_CANCEL_LINKED);
        msg.extend_from_slice(&owner.0);
        msg.extend_from_slice(&client_id.to_le_bytes());
        msg
    }
}

// ── Tests ────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests;
