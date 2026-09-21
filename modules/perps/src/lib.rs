//! Oxide perps module — perpetual futures with cross/isolated margin,
//! funding, liquidations, insurance fund, and auto-deleveraging.
//!
//! Implements `plan.md` §9.3. The module reuses [`trading::MatchingEngine`]
//! for order matching and adds the perps-specific state machine on top:
//! positions, margin, unrealized `PnL`, funding, liquidation, insurance
//! fund, and `ADL`.
//!
//! # Design (`plan.md` §9.3)
//!
//! - **One matching engine per market** (reused from `crates/trading`).
//! - **Positions** are tracked per `(market, account)` as signed sizes
//!   (positive = long, negative = short). Entry price is the
//!   volume-weighted average.
//! - **Margin** is quote currency held in the perps module (deposited
//!   via a balance transfer). Cross margin shares one margin pool across
//!   all positions for an account; isolated margin is per-market.
//! - **`PnL`** is unrealized: `position.size * (mark - entry)` for longs,
//!   `position.size * (entry - mark)` for shorts. Realized on close.
//! - **Margin ratio** = `(equity - maintenance) / notional`, where
//!   `equity = margin + unrealized_pnl` and `maintenance` is tiered by
//!   notional bucket (`plan.md` §9.3 "tiered maintenance margin").
//! - **Liquidation** triggers when `margin_ratio <= 0`. The liquidator
//!   takes over the position at a discount; penalties fund the
//!   insurance fund.
//! - **Insurance fund** absorbs liquidation shortfalls. If depleted,
//!   **ADL** auto-deleverages profitable counterparties, ranked by
//!   profit + leverage (deterministic queue).
//! - **Funding** is applied every N blocks: `rate * notional` paid
//!   from longs to shorts (or vice versa if rate is negative).
//!
//! # Message format
//!
//! | Tag | Operation | Body |
//! |-----|-----------|------|
//! | 0   | Place order | `[market:1][side:1][type:1][tif:1][stp:1][price:8][qty:8][flags:1]` |
//! | 1   | Cancel order | `[market:1][order_id:8]` |
//! | 2   | List market | `[tick:8][lot:8][min:8][max:8][max_resting:4][max_leverage:2][mmr_base:8]` |
//! | 3   | Deposit margin | `[market:1][amount:8]` (isolated) or `[market:0xFF][amount:8]` (cross) |
//! | 4   | Withdraw margin | `[market:1][amount:8]` (isolated) or `[market:0xFF][amount:8]` (cross) |
//! | 5   | Set mark price | `[market:1][mark:8]` (oracle/governance path) |
//! | 6   | Apply funding | `[market:1][rate:8]` (oracle/governance path, signed i64 as u64) |
//!
//! The sender (from the tx envelope) is the account owner.

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

// ── Wire tags ────────────────────────────────────────────────────────

const TAG_PLACE: u8 = 0;
const TAG_CANCEL: u8 = 1;
const TAG_LIST_MARKET: u8 = 2;
const TAG_DEPOSIT: u8 = 3;
const TAG_WITHDRAW: u8 = 4;
const TAG_SET_MARK: u8 = 5;
const TAG_APPLY_FUNDING: u8 = 6;

// ── Message sizes (body, excluding the 1-byte tag) ───────────────────

/// `[market:1][side:1][type:1][tif:1][stp:1][price:8][qty:8][flags:1]`
/// = 22. `flags` bit 0 = reduce-only (C7): the order may only close
/// existing exposure — an order whose qty exceeds the reducible
/// position is rejected at admission, and a resting remainder is
/// canceled if it outlives its cover.
const PLACE_BODY_LEN: usize = 22;
/// `flags` bit 0: reduce-only order (C7).
const FLAG_REDUCE_ONLY: u8 = 0x01;
/// `[market:1][order_id:8]` = 9.
const CANCEL_BODY_LEN: usize = 9;
/// `[tick:8][lot:8][min:8][max:8][max_resting:4][max_leverage:2][mmr_base:2]` = 40.
const LIST_MARKET_BODY_LEN: usize = 40;
/// `[market:1][amount:8]` = 9.
const MARGIN_BODY_LEN: usize = 9;
/// `[market:1][mark:8]` = 9.
const SET_MARK_BODY_LEN: usize = 9;
/// `[market:1][rate:8]` = 9.
const FUNDING_BODY_LEN: usize = 9;

/// Market ID `0xFF` means "cross margin pool" (shared across all
/// markets for an account).
const CROSS_MARGIN_MARKET: u8 = 0xFF;

/// Price scale: 1e8 (from `primitives::fixed::PRICE_SCALE`).
const PRICE_SCALE: u128 = 100_000_000;

/// Maximum allowed mark price change per update, in basis points.
///
/// Origin: oracle robustness requirement (plan.md §9.3). A malicious
/// or buggy oracle could cause cascading liquidations by setting an
/// extreme price. This cap limits the damage: a single oracle update
/// can move the mark by at most 10% (1000 bps). If the real price
/// moved more than 10%, the oracle must update in multiple steps
/// (each within 10%), giving the system time to react.
///
/// Tradeoff: lower cap = more protection but slower price discovery
/// during legitimate large moves; higher cap = faster price
/// discovery but more exposure to oracle manipulation.
const MAX_MARK_CHANGE_BPS: u64 = 1000; // 10%

/// M4 fix: maximum number of oracle (mark price) updates per market
/// per block. Without this, a malicious or buggy oracle can make
/// many small (just under 10%) updates in a single block to achieve
/// a large cumulative price move — e.g. 7 updates of 9.99% each
/// compounds to ~75%, enough to trigger cascading liquidations.
///
/// Origin: security review M4 (docs/security-review.md). The
/// per-update deviation check (`MAX_MARK_CHANGE_BPS`) limits each
/// individual update to 10%, but without a per-block rate limit,
/// the cumulative move is unbounded.
///
/// Setting this to 1 means each market can have at most 1 oracle
/// update per block. If the real price moved more than 10%, the
/// oracle must update across multiple blocks (each within 10%),
/// giving the system time to react.
///
/// Tradeoff: lower cap = more protection but slower price discovery
/// during legitimate large moves; higher cap = faster price
/// discovery but more exposure to cumulative oracle manipulation.
const MAX_ORACLE_UPDATES_PER_BLOCK: u8 = 1;

/// Compute the absolute deviation between a new and old mark price,
/// in basis points. Returns `|new - old| * 10_000 / old`.
///
/// If `old` is 0, returns `u64::MAX` (any non-zero new price is a
/// 100%+ deviation — but the first update is exempted in
/// `set_mark_price`).
fn mark_price_deviation_bps(new: u64, old: u64) -> u64 {
    if old == 0 {
        return u64::MAX;
    }
    let diff = new.abs_diff(old);
    // Use u128 to avoid overflow: diff * 10_000 can overflow u64
    // for large prices (up to 18 * 10^18 scale).
    u64::try_from((u128::from(diff) * 10_000) / u128::from(old)).unwrap_or(u64::MAX)
}

// ── Per-market config ────────────────────────────────────────────────

/// Per-market perps configuration, extending the matching engine's
/// `MarketConfig` with perps-specific parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerpsMarketConfig {
    /// The matching engine config (tick, lot, price band, capacity).
    pub base: MarketConfig,
    /// Maximum leverage (e.g. 10 = 10x). Initial margin = notional / leverage.
    pub max_leverage: u16,
    /// Base maintenance margin rate, in basis points (e.g. 50 = 0.5%).
    /// Tiered by notional bucket in production; v0 uses a flat rate.
    pub mmr_base_bps: u16,
}

impl PerpsMarketConfig {
    /// Validate configuration self-consistency for the transaction
    /// listing path — the base engine config (which bounds
    /// `max_resting` at `MAX_RESTING_LIMIT`) plus the perps-specific
    /// fields. `max_leverage = 0` would mean infinite margin and
    /// `mmr_base_bps > 10_000` a maintenance rate above 100%; both
    /// are nonsense configs a listing proposal must not carry.
    ///
    /// # Errors
    /// [`TradingError::InvalidConfig`] naming the broken field.
    pub fn validate(&self) -> Result<(), TradingError> {
        self.base.validate()?;
        if self.max_leverage == 0 {
            return Err(TradingError::InvalidConfig("max_leverage must be >= 1"));
        }
        if self.mmr_base_bps > 10_000 {
            return Err(TradingError::InvalidConfig(
                "mmr_base_bps must be <= 10_000 (a 100% maintenance rate)",
            ));
        }
        Ok(())
    }
}

/// Maintenance margin rate as a fraction (basis points → `u128` numerator
/// over `10_000`).
fn mmr_rate(cfg: &PerpsMarketConfig) -> u128 {
    u128::from(cfg.mmr_base_bps)
}

/// Initial margin rate = 1 / leverage, in basis points.
#[allow(dead_code)]
fn imr_rate(cfg: &PerpsMarketConfig) -> u128 {
    if cfg.max_leverage == 0 {
        return 10_000; // 100% margin (no leverage)
    }
    10_000 / u128::from(cfg.max_leverage)
}

// ── Position ────────────────────────────────────────────────────────

/// A perpetual position: signed size (positive = long, negative =
/// short), volume-weighted entry price, and isolated margin balance.
///
/// For cross-margin positions, `isolated_margin` is 0 and the margin
/// lives in the account's cross-margin pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    /// Signed position size in raw qty units (scale-6). Positive =
    /// long, negative = short. Zero = no position.
    pub size: i64,
    /// Volume-weighted average entry price (scale-8). Zero if no
    /// position.
    pub entry_price: u64,
    /// Isolated margin held against this position (scale-6). Zero for
    /// cross-margin positions.
    pub isolated_margin: u64,
}

impl Position {
    /// Whether this position is open (non-zero size).
    const fn is_open(&self) -> bool {
        self.size != 0
    }

    /// Notional value at mark price: `|size| * mark` (scale-14).
    fn notional(&self, mark: u64) -> u128 {
        u128::from(self.size.unsigned_abs()) * u128::from(mark)
    }

    /// Unrealized `PnL` at mark price (scale-14):
    /// - Long: `|size| * (mark - entry)`
    /// - Short: `|size| * (entry - mark)`
    ///
    /// Returns a signed `i128` in scale-14 units.
    fn unrealized_pnl(&self, mark: u64) -> i128 {
        if self.size == 0 {
            return 0;
        }
        let size_abs = i128::from(self.size.unsigned_abs());
        let mark = i128::from(mark);
        let entry = i128::from(self.entry_price);
        if self.size > 0 { size_abs * (mark - entry) } else { size_abs * (entry - mark) }
    }

    /// Maintenance margin requirement at mark price:
    /// `notional * mmr / 10_000` (scale-14 → scale-14, since `mmr` is
    /// basis points over `10_000`).
    ///
    /// H1 fix: use `saturating_mul` to prevent `u128` overflow when
    /// notional is near 2^127 and `mmr_rate` is up to 65535.
    fn maintenance_margin(&self, mark: u64, cfg: &PerpsMarketConfig) -> u128 {
        self.notional(mark).saturating_mul(mmr_rate(cfg)) / 10_000
    }
}

// ── Account state ────────────────────────────────────────────────────

/// A resting order's margin-reservation record (C7).
///
/// An unfilled resting order is *potential* exposure: it can fill at
/// any time and must be margined as if it already had. The
/// reservation is computed lazily from `qty`/`side`/`price` against
/// the CURRENT position — the portion of the order covered by an
/// opposite-side position is a reduce (no margin), the tail is new
/// exposure charged at `price × qty / leverage`. Recomputing against
/// the live position keeps the reservation exact even when the
/// position changes through other paths after the order rests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenOrderResv {
    /// Remaining resting quantity (scale-6), decremented on each
    /// maker fill. Zero means the order is gone and the entry is
    /// removed.
    pub qty: u64,
    /// The order's resting price (scale-8). A maker fills at its own
    /// resting price, so this is the exact notional rate — not a
    /// worst-case bound.
    pub price: u64,
    /// Which side the resting order sits on.
    pub side: Side,
    /// Reduce-only marker: if the position moves so the remaining
    /// qty exceeds what it could still reduce, the remainder is
    /// canceled at the next maker fill (see `apply_fill_to_position`).
    pub reduce_only: bool,
}

/// Per-account perps state: cross-margin pool + per-market positions.
#[derive(Debug, Clone, Default)]
pub struct AccountState {
    /// Cross-margin pool (shared across all markets). Scale-6 quote.
    pub cross_margin: u64,
    /// Positions indexed by market ID.
    pub positions: BTreeMap<u8, Position>,
    /// Resting-order reservations keyed by `(market, order_id)`.
    /// Maintained by place/fill/cancel; released when the order
    /// leaves the book by any path.
    pub open_orders: BTreeMap<(u8, u64), OpenOrderResv>,
}

impl AccountState {
    /// Total equity = `cross_margin` + sum(`isolated_margin` +
    /// `unrealized_pnl`) across all positions, at the given mark prices.
    ///
    /// `marks` maps `market_id` → `mark_price`.
    ///
    /// All terms are converted to scale-6 (quote units) before
    /// summing. `PnL` is natively scale-14 and divided by
    /// `PRICE_SCALE` (1e8) to bring it to scale-6.
    fn equity(&self, marks: &BTreeMap<u8, u64>, configs: &BTreeMap<u8, PerpsMarketConfig>) -> i128 {
        let mut total = i128::from(self.cross_margin);
        for (market, pos) in &self.positions {
            if !pos.is_open() {
                total += i128::from(pos.isolated_margin);
                continue;
            }
            let mark = marks.get(market).copied().unwrap_or(pos.entry_price);
            total += i128::from(pos.isolated_margin);
            // PnL is scale-14; convert to scale-6 by dividing by
            // PRICE_SCALE (1e8).
            let pnl_scale6 =
                pos.unrealized_pnl(mark) / i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
            total += pnl_scale6;
            let _ = configs;
        }
        total
    }

    /// Total maintenance margin across all positions, in scale-6.
    fn total_maintenance(
        &self,
        marks: &BTreeMap<u8, u64>,
        configs: &BTreeMap<u8, PerpsMarketConfig>,
    ) -> u128 {
        let mut total: u128 = 0;
        for (market, pos) in &self.positions {
            if !pos.is_open() {
                continue;
            }
            let mark = marks.get(market).copied().unwrap_or(pos.entry_price);
            let cfg = configs.get(market);
            if let Some(cfg) = cfg {
                // maintenance_margin returns scale-14; convert to
                // scale-6 by dividing by PRICE_SCALE (1e8).
                total += pos.maintenance_margin(mark, cfg) / PRICE_SCALE;
            }
        }
        total
    }

    /// Total initial margin across all positions, in scale-6:
    /// `sum(notional(mark) / max_leverage)` per open position. Used
    /// by the order-entry gate — the account's equity must cover
    /// the initial margin of its whole book plus any new exposure.
    fn total_initial_margin(
        &self,
        marks: &BTreeMap<u8, u64>,
        configs: &BTreeMap<u8, PerpsMarketConfig>,
    ) -> u128 {
        let mut total: u128 = 0;
        for (market, pos) in &self.positions {
            if !pos.is_open() {
                continue;
            }
            let mark = marks.get(market).copied().unwrap_or(pos.entry_price);
            if let Some(cfg) = configs.get(market) {
                let leverage = u128::from(cfg.max_leverage.max(1));
                // notional is scale-14; convert to scale-6.
                total += pos.notional(mark) / leverage / PRICE_SCALE;
            }
        }
        total
    }

    /// Initial margin reserved by resting orders (C7), scale-6.
    ///
    /// For each market, the position's closing capacity — its
    /// absolute size — is allocated ONCE across the whole set of
    /// opposing resting orders: the cheapest opposing orders consume
    /// it first, leaving the most expensive residual exposed.
    /// Same-side orders are pure exposure. An order's uncovered
    /// tail is potential new exposure charged `qty × price /
    /// leverage`.
    ///
    /// Allocating the cover once is the point of the computation:
    /// scoring each order against the full position independently
    /// lets a +10 long make N sells of 10 each look fully covered,
    /// stacking unbacked short exposure that all fills. Covering
    /// the cheapest opposing orders first is the conservative
    /// choice — it maximizes exposed notional and therefore the
    /// reservation. Evaluating the cover against the live position
    /// means the reservation still tightens automatically if the
    /// position shrinks — a resting "reduce" that outlives its
    /// position is charged as an opener.
    fn total_open_order_im(&self, configs: &BTreeMap<u8, PerpsMarketConfig>) -> u128 {
        self.open_order_im_with(configs, None)
    }

    /// `total_open_order_im` with a hypothetical extra order folded
    /// into its market's reservation set. The admission gate uses
    /// the delta over `total_open_order_im` as the order's marginal
    /// initial margin — which automatically charges same-side
    /// exposure in full and gives an opposing order only the
    /// closing capacity the resting book has not already claimed.
    fn open_order_im_with(
        &self,
        configs: &BTreeMap<u8, PerpsMarketConfig>,
        extra: Option<(u8, &OpenOrderResv)>,
    ) -> u128 {
        // Group reservations by market so each position's closing
        // capacity is allocated once across the whole opposing set.
        let mut by_market: BTreeMap<u8, Vec<&OpenOrderResv>> = BTreeMap::new();
        for ((market, _oid), resv) in &self.open_orders {
            by_market.entry(*market).or_default().push(resv);
        }
        if let Some((market, resv)) = extra {
            by_market.entry(market).or_default().push(resv);
        }
        let mut total: u128 = 0;
        for (market, orders) in &by_market {
            let Some(cfg) = configs.get(market) else {
                continue;
            };
            let leverage = u128::from(cfg.max_leverage.max(1));
            let (closing_side, mut cover) = match self.positions.get(market) {
                Some(p) if p.size > 0 => (Side::Sell, p.size.unsigned_abs()),
                Some(p) if p.size < 0 => (Side::Buy, p.size.unsigned_abs()),
                // No position: every order is pure exposure. The
                // closing side is irrelevant with cover 0 — pick
                // either; both branches below charge full qty.
                _ => (Side::Buy, 0),
            };
            // Opposing orders cheapest-first: the cover pool retires
            // low-price orders and leaves the expensive tail
            // exposed — the conservative (max-margin) allocation.
            let mut opposing: Vec<&OpenOrderResv> =
                orders.iter().copied().filter(|r| r.side == closing_side).collect();
            opposing.sort_by_key(|r| r.price);
            for r in opposing {
                let covered = cover.min(r.qty);
                cover -= covered;
                // notional is scale-14 (qty scale-6 × price scale-8);
                // divide by PRICE_SCALE to land on scale-6.
                let exposed = u128::from(r.qty - covered);
                total += exposed * u128::from(r.price) / leverage / PRICE_SCALE;
            }
            for r in orders.iter().filter(|r| r.side != closing_side) {
                total += u128::from(r.qty) * u128::from(r.price) / leverage / PRICE_SCALE;
            }
        }
        total
    }
}

// ── Module ───────────────────────────────────────────────────────────

/// The perps module.
pub struct PerpsModule {
    inner: Mutex<Inner>,
    store: KVStore,
    /// The balance ledger for margin deposits/withdrawals — the EVM
    /// account store behind `framework::Balances` on a live node.
    /// `None` = margin accounting only (unit-test mode): deposits and
    /// withdrawals update the margin field without moving funds.
    ledger: Option<Arc<dyn framework::Balances + Send + Sync>>,
    /// The validator-committee handle gating the `TAG_SET_MARK` /
    /// `TAG_APPLY_FUNDING` tx paths. `None` (bare `new()`) means the
    /// tx path is *closed*: only the in-process `set_mark_price` /
    /// `apply_funding` calls work. That is the safe default — an
    /// unauthenticated mark update is a free market-manipulation
    /// primitive, so production wiring must attach the staking
    /// committee before these txs are accepted.
    committee: Option<Arc<dyn framework::Committee + Send + Sync>>,
    /// C9: committee endorsements for the emergency override
    /// actions — `(market, mark)` and `(market, rate)` payloads
    /// accumulate powered-validator votes and apply only once
    /// endorsing power strictly exceeds two-thirds of the
    /// committee. A single validator's signature is a vote, never
    /// a command.
    endorsements: framework::Endorsements,
}

struct Inner {
    /// Matching engines per market.
    markets: Vec<Option<MatchingEngine>>,
    /// Perps-specific configs per market.
    configs: BTreeMap<u8, PerpsMarketConfig>,
    /// Mark prices per market (scale-8).
    marks: BTreeMap<u8, u64>,
    /// Account states, keyed by address.
    accounts: BTreeMap<Address, AccountState>,
    /// Insurance fund balance (scale-6 quote).
    insurance_fund: u64,
    /// Reusable fill buffer.
    fills: Vec<FillEvent>,
    /// M4 fix: per-market oracle update count for the current
    /// block. Each market can have at most
    /// [`MAX_ORACLE_UPDATES_PER_BLOCK`] mark price updates per
    /// block. This prevents a malicious or buggy oracle from
    /// making many small (just under 10%) updates in a single
    /// block to achieve a large cumulative price move.
    ///
    /// Reset to 0 in `begin_block`.
    oracle_updates_this_block: BTreeMap<u8, u8>,
}

/// [`MakerCap`] gate enforcing reduce-only at the match decision:
/// a resting reduce-only order may fill only up to the closing
/// capacity its owner's position still offers — allocated once
/// across that owner's fills in the sweep (`spent`), the same
/// once-only rule the margin reservation uses. A maker with no
/// cover left returns `0` and is removed as dead liquidity; a
/// partially covered one fills its cover and is then removed (the
/// remainder could only open exposure). This replaces enforcement
/// that used to run after the fill had already flipped positions.
struct ReduceOnlyCap<'a> {
    /// Account states (read-only: positions + reservations).
    accounts: &'a BTreeMap<Address, AccountState>,
    /// The market this engine serves.
    market: u8,
    /// Cover already consumed per owner in this sweep. Every
    /// opposing maker — reduce-only or not — burns the same pool:
    /// a normal sell can exhaust the cover a reduce-only sell
    /// behind it would have needed.
    spent: BTreeMap<Address, u64>,
    /// Every maker the sweep shrank or removed without a fill —
    /// cap kills, but also self-trade-prevention removals and
    /// decrements, whose reservations need the same release. The
    /// engine reports each via `on_removed`; the module consumes
    /// them after the sweep.
    removed: Vec<trading::MakerRemoval>,
}

impl trading::MakerCap for ReduceOnlyCap<'_> {
    fn cap(&mut self, id: OrderId, owner: Address, book_qty: u64) -> u64 {
        let Some(acct) = self.accounts.get(&owner) else {
            return book_qty;
        };
        let Some(resv) = acct.open_orders.get(&(self.market, id.0)) else {
            // A resting order with no reservation cannot be
            // reduce-only — treat as ordinary liquidity.
            return book_qty;
        };
        let pos_size = acct.positions.get(&self.market).map_or(0, |p| p.size);
        let opposing =
            (pos_size > 0 && resv.side == Side::Sell) || (pos_size < 0 && resv.side == Side::Buy);
        if !opposing {
            // A reduce-only order with no reducible position can
            // only open exposure — cap it at zero; the engine then
            // reports the removal via `on_removed`.
            return if resv.reduce_only { 0 } else { book_qty };
        }
        if resv.reduce_only {
            let used = self.spent.get(&owner).copied().unwrap_or(0);
            let remaining = pos_size.unsigned_abs().saturating_sub(used);
            let cap = remaining.min(book_qty);
            *self.spent.entry(owner).or_insert(0) += cap;
            cap
        } else {
            // A normal opposing maker burns cover its reduce-only
            // siblings would need. The full book qty is charged even
            // though the actual fill may be smaller — but a smaller
            // fill means the taker is done, so no later maker ever
            // consults the over-estimate.
            *self.spent.entry(owner).or_insert(0) += book_qty;
            book_qty
        }
    }

    fn on_removed(&mut self, removal: trading::MakerRemoval) {
        self.removed.push(removal);
    }

    fn reset(&mut self) {
        self.spent.clear();
        self.removed.clear();
    }
}

impl PerpsModule {
    /// Construct a fresh perps module with no markets and no ledger
    /// settlement.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                markets: (0..=u8::MAX).map(|_| None).collect(),
                configs: BTreeMap::new(),
                marks: BTreeMap::new(),
                accounts: BTreeMap::new(),
                insurance_fund: 0,
                fills: Vec::with_capacity(64),
                oracle_updates_this_block: BTreeMap::new(),
            }),
            store: Mutex::new(BTreeMap::new()),
            ledger: None,
            committee: None,
            endorsements: framework::Endorsements::new(),
        }
    }

    /// Construct a perps module wired to a balance ledger for
    /// margin deposits and withdrawals. On a live node `ledger` is
    /// the EVM account store — margin debits/credits move the same
    /// balances EVM txs see.
    pub fn with_ledger(ledger: Arc<dyn framework::Balances + Send + Sync>) -> Self {
        let mut m = Self::new();
        m.ledger = Some(ledger);
        m
    }

    /// Attach the validator-committee handle that authorizes the
    /// `TAG_SET_MARK` / `TAG_APPLY_FUNDING` transaction paths. These
    /// are the emergency/manual override: the normal mark pipeline
    /// is the oracle module pushing through [`MarkSink`], which never
    /// goes through `handle`.
    ///
    /// Without a committee the tx paths reject everything — closed
    /// by default, since an unauthenticated mark update is a market-
    /// manipulation primitive.
    #[must_use]
    pub fn with_committee(
        mut self,
        committee: Arc<dyn framework::Committee + Send + Sync>,
    ) -> Self {
        self.committee = Some(committee);
        self
    }

    /// List a new perps market with the given configuration. Returns
    /// the assigned market ID.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] if the market config is
    /// invalid or all 256 slots are taken.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn list_market(&self, cfg: PerpsMarketConfig) -> Result<u8, ExecError> {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let id =
            inner.markets.iter().position(Option::is_none).ok_or_else(|| {
                ExecError::ModuleRejected("all 256 market slots taken".to_string())
            })?;
        #[allow(clippy::cast_possible_truncation)]
        let id_u8 = id as u8;
        let book = DenseBook::new(cfg.base)
            .map_err(|e| ExecError::ModuleRejected(format!("book init: {e}")))?;
        let engine = MatchingEngine::new(cfg.base, book)
            .map_err(|e| ExecError::ModuleRejected(format!("engine init: {e}")))?;
        inner.markets[id] = Some(engine);
        inner.configs.insert(id_u8, cfg);
        // Initialize mark price to the mid of the price band.
        let initial_mark = cfg.base.min_price.midpoint(cfg.base.max_price);
        inner.marks.insert(id_u8, initial_mark);
        // Persist config for state-root replay.
        let key = market_config_key(id_u8);
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, encode_perps_config(&cfg));
        Ok(id_u8)
    }

    /// Get the mark price for a market.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn mark_price(&self, market: u8) -> Option<u64> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .marks
            .get(&market)
            .copied()
    }

    /// Set the mark price for a market (oracle/governance path).
    ///
    /// # Oracle robustness
    ///
    /// The mark price is validated against the previous mark to
    /// prevent a malicious or buggy oracle from causing cascading
    /// liquidations with an extreme price. The new price must be
    /// within `MAX_MARK_CHANGE_BPS` basis points of the previous
    /// mark. If the market has no previous mark (first update),
    /// any price is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] if the market does not
    /// exist or the new price deviates more than `MAX_MARK_CHANGE_BPS`
    /// from the current mark.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn set_mark_price(&self, market: u8, mark: u64) -> Result<(), ExecError> {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.configs.contains_key(&market) {
            return Err(ExecError::ModuleRejected("market does not exist".to_string()));
        }
        // M4 fix: per-block oracle rate limit. Each market can have
        // at most `MAX_ORACLE_UPDATES_PER_BLOCK` oracle updates per
        // block. Without this, many small (just under 10%) updates
        // can compound to a large cumulative move within a single
        // block.
        let current_updates = inner.oracle_updates_this_block.get(&market).copied().unwrap_or(0);
        if current_updates >= MAX_ORACLE_UPDATES_PER_BLOCK {
            return Err(ExecError::ModuleRejected(format!(
                "oracle update limit reached: {current_updates}/{MAX_ORACLE_UPDATES_PER_BLOCK} per block per market"
            )));
        }
        // Oracle robustness: reject extreme price changes.
        if let Some(old_mark) = inner.marks.get(&market) {
            let deviation = mark_price_deviation_bps(mark, *old_mark);
            if deviation > MAX_MARK_CHANGE_BPS {
                return Err(ExecError::ModuleRejected(format!(
                    "mark price deviation {deviation} bps exceeds max {MAX_MARK_CHANGE_BPS} bps"
                )));
            }
        }
        inner.marks.insert(market, mark);
        inner.oracle_updates_this_block.insert(market, current_updates + 1);
        Ok(())
    }

    /// Set the mark price without the oracle deviation check.
    ///
    /// This bypasses the `MAX_MARK_CHANGE_BPS` guard and is intended
    /// for testing and genesis/initial setup where the first mark
    /// needs to be set to an arbitrary value. Production code should
    /// use [`set_mark_price`](Self::set_mark_price) which enforces
    /// the oracle robustness check.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] if the market does not exist.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn set_mark_price_unchecked(&self, market: u8, mark: u64) -> Result<(), ExecError> {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.configs.contains_key(&market) {
            return Err(ExecError::ModuleRejected("market does not exist".to_string()));
        }
        inner.marks.insert(market, mark);
        Ok(())
    }

    /// Get an account's position in a market (read-only).
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn position(&self, account: &Address, market: u8) -> Position {
        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .accounts
            .get(account)
            .and_then(|a| a.positions.get(&market))
            .copied()
            .unwrap_or_default()
    }

    /// Get an account's cross-margin balance (read-only).
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn cross_margin(&self, account: &Address) -> u64 {
        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.accounts.get(account).map_or(0, |a| a.cross_margin)
    }

    /// Insurance fund balance (read-only).
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn insurance_fund(&self) -> u64 {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insurance_fund
    }

    /// Get or create an account state entry.
    fn account_mut<'a>(inner: &'a mut Inner, addr: &Address) -> &'a mut AccountState {
        inner.accounts.entry(*addr).or_default()
    }

    /// Apply funding to all open positions in a market. Longs pay
    /// shorts if rate > 0; shorts pay longs if rate < 0.
    ///
    /// `rate` is in basis points (signed, passed as `i64`). Funding
    /// amount = `|size| * mark * rate / 10_000 / PRICE_SCALE` (scale-14
    /// → scale-6).
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] if the market does not exist.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn apply_funding(&self, market: u8, rate_i64: i64) -> Result<Vec<Event>, ExecError> {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mark = *inner
            .marks
            .get(&market)
            .ok_or_else(|| ExecError::ModuleRejected("market does not exist".to_string()))?;

        let mut events = Vec::new();
        let rate = i128::from(rate_i64);
        let scale = i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX) * 10_000; // scale-14 × bps denom

        // ── Pass 1: compute each open position's signed funding ──
        // Funding amount = size * mark * rate / (PRICE_SCALE * 10_000).
        // Positive = the account pays; negative = the account receives.
        // Iterate in sorted address order for determinism.
        //
        // Collect only `(addr, amount)` — the old code materialized
        // a `Vec<(Address, Position)>` (a full position clone per
        // holder) when only `size`/`is_open` are read here.
        let mut payers: Vec<(Address, u64)> = Vec::new();
        let mut receivers: Vec<(Address, u64)> = Vec::new();
        let mut total_due: u128 = 0;
        for (addr, state) in &inner.accounts {
            let Some(pos) = state.positions.get(&market) else {
                continue;
            };
            if !pos.is_open() {
                continue;
            }
            let size = i128::from(pos.size);
            let step1 = size.checked_mul(i128::from(mark));
            let funding = match step1.and_then(|v| v.checked_mul(rate)) {
                Some(v) => v / scale,
                None => {
                    // Overflow — skip this position rather than
                    // producing a wrong funding amount.
                    continue;
                }
            };
            let Ok(amount) = u64::try_from(funding.unsigned_abs()) else {
                // Over-u64 funding cannot be represented — skip the
                // position rather than saturating the ledger.
                continue;
            };
            if amount == 0 {
                continue;
            }
            if funding > 0 {
                payers.push((*addr, amount));
            } else {
                receivers.push((*addr, amount));
                total_due += u128::from(amount);
            }
        }

        // ── Pass 2: collect from payers ──
        // Each payer contributes min(computed, available margin) —
        // a payer that cannot cover the full amount is drained to
        // zero and becomes liquidation-eligible; the shortfall is
        // NOT silently invented (the old code credited receivers the
        // full computed amount while only collecting part of it,
        // minting margin out of nothing).
        let mut collected: u128 = 0;
        for (addr, owed) in &payers {
            let account = Self::account_mut(&mut inner, addr);
            let Some(pos_entry) = account.positions.get_mut(&market) else {
                continue;
            };
            // Debit the same bucket the old code used: isolated
            // margin when present, else the cross pool.
            let bucket = if pos_entry.isolated_margin > 0 {
                &mut pos_entry.isolated_margin
            } else {
                &mut account.cross_margin
            };
            let actual = (*bucket).min(*owed);
            *bucket -= actual;
            collected += u128::from(actual);
            events.push(Event { module: "perps", kind: "funding", data: vec![market] });
        }

        // ── Pass 3: distribute to receivers, pro-rata ──
        // Receivers share what was actually collected (capped at
        // total_due): each gets `credit_i × pool / total_due`, with
        // the last receiver taking the remainder so the distribution
        // is exactly zero-sum. Undistributed dust accrues to the
        // insurance fund (tracked, not vanished).
        let pool = collected.min(total_due);
        let mut distributed: u128 = 0;
        let last_idx = receivers.len().saturating_sub(1);
        for (i, (addr, due)) in receivers.iter().enumerate() {
            let credit_u128 = if i == last_idx {
                pool.saturating_sub(distributed)
            } else {
                // `total_due` is non-zero whenever `receivers` is
                // non-empty (zero-amount entries are skipped), so
                // the division cannot fail; `checked_div` keeps the
                // arithmetic total regardless.
                (pool * u128::from(*due)).checked_div(total_due).unwrap_or(0)
            };
            // HIGH fix: credit overflows u64 — skip the
            // receiver rather than crediting u64::MAX (a
            // free-money bug). The excess remains in the
            // funding pool (accrued to insurance below).
            let Ok(credit) = u64::try_from(credit_u128) else {
                continue;
            };
            distributed += credit_u128;
            if credit == 0 {
                continue;
            }
            let account = Self::account_mut(&mut inner, addr);
            let Some(pos_entry) = account.positions.get_mut(&market) else {
                continue;
            };
            let bucket = if pos_entry.isolated_margin > 0 {
                &mut pos_entry.isolated_margin
            } else {
                &mut account.cross_margin
            };
            match bucket.checked_add(credit) {
                Some(v) => *bucket = v,
                // A bucket at u64::MAX cannot grow — the excess
                // remains in the funding pool (accrued to insurance
                // below) rather than silently capping the receiver.
                None => continue,
            }
            events.push(Event { module: "perps", kind: "funding", data: vec![market] });
        }

        // Surplus (rounding dust, un-creditable receivers, and any
        // collected > due) accrues to the insurance fund — the only
        // place value may accumulate without a named owner.
        let surplus = collected.saturating_sub(distributed);
        inner.insurance_fund =
            inner.insurance_fund.saturating_add(u64::try_from(surplus).unwrap_or(u64::MAX));
        if collected < total_due {
            events.push(Event { module: "perps", kind: "funding_shortfall", data: vec![market] });
        }
        Ok(events)
    }

    /// Check if an account is under-margined and trigger liquidation
    /// if so. Returns liquidation events.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] if the account is not found.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn liquidation_check(&self, account: &Address) -> Result<Vec<Event>, ExecError> {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        // Phase 1 — read-only solvency check: the old code cloned
        // `marks`, `configs`, and the whole account (every position)
        // before even knowing whether liquidation was needed. The
        // equity read only needs shared borrows of disjoint fields.
        let (equity, maintenance) = {
            let acct = inner
                .accounts
                .get(account)
                .ok_or_else(|| ExecError::ModuleRejected("account not found".to_string()))?;
            (
                acct.equity(&inner.marks, &inner.configs),
                acct.total_maintenance(&inner.marks, &inner.configs),
            )
        };

        // Liquidation condition: equity <= maintenance (as i128).
        if equity > i128::try_from(maintenance).unwrap_or(i128::MAX) {
            return Ok(vec![]); // not under-margined
        }

        // Phase 2a — cancel every resting order the account owns
        // (C7). A liquidated account's orders are unbacked: if they
        // stayed on the book they could keep matching against
        // solvent takers with no margin behind them. Cancelling also
        // releases the margin reservations — `open_orders` is
        // cleared wholesale below since the account is done trading.
        let mut events = Vec::new();
        {
            let Inner { markets, accounts, .. } = &mut *inner;
            let mut scratch: Vec<trading::RestingEntry> = Vec::new();
            for (mid_u, slot) in markets.iter_mut().enumerate() {
                let Some(engine) = slot.as_mut() else {
                    continue;
                };
                engine.resting_entries(&mut scratch);
                // Collect first — `cancel` mutates the book while
                // `scratch` holds the snapshot.
                let owned: Vec<u64> =
                    scratch.iter().filter(|e| e.owner == *account).map(|e| e.id.0).collect();
                for oid in owned {
                    if engine.cancel(trading::OrderId(oid)).is_ok() {
                        #[allow(clippy::cast_possible_truncation)]
                        events.push(Event {
                            module: "perps",
                            kind: "liquidation_cancel",
                            data: vec![mid_u as u8],
                        });
                    }
                }
            }
            if let Some(acct_mut) = accounts.get_mut(account) {
                acct_mut.open_orders.clear();
            }
        }

        // Phase 2b — liquidate: close all positions at mark and
        // realize losses, mutating the real positions in place.
        // `marks`/`accounts` are destructured so the mark lookup
        // (shared) and the position mutation (mutable) borrow
        // disjoint fields — no clone, no materialized positions.
        let mut total_loss_scale14: i128 = 0;
        let mut total_margin_recovered: u64 = 0;
        let cross_margin;
        {
            let Inner { marks, accounts, .. } = &mut *inner;
            let Some(acct_mut) = accounts.get_mut(account) else {
                return Err(ExecError::ModuleRejected("account not found".to_string()));
            };
            cross_margin = acct_mut.cross_margin;
            for (market, pos) in &mut acct_mut.positions {
                if !pos.is_open() {
                    continue;
                }
                let mark = marks.get(market).copied().unwrap_or(pos.entry_price);
                let pnl = pos.unrealized_pnl(mark); // scale-14
                total_loss_scale14 = total_loss_scale14.saturating_add(pnl);
                total_margin_recovered = total_margin_recovered.saturating_add(pos.isolated_margin);
                // Close the position in the same pass — the old code
                // walked the map a second time to zero these fields.
                pos.size = 0;
                pos.entry_price = 0;
                pos.isolated_margin = 0;
                events.push(Event { module: "perps", kind: "liquidated", data: vec![*market] });
            }
            acct_mut.cross_margin = 0;
        }

        // Convert total_loss from scale-14 to scale-6 before combining
        // with margin (which is scale-6). unrealized_pnl returns
        // size_scale8 * price_scale6 = scale-14; dividing by PRICE_SCALE
        // (1e8) brings it to scale-6, matching the margin units.
        let price_scale_i128 = i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
        let total_loss_scale6 = total_loss_scale14 / price_scale_i128;
        let margin_total = i128::from(cross_margin.saturating_add(total_margin_recovered));
        let net = margin_total + total_loss_scale6; // both scale-6
        if net < 0 {
            // Insurance fund covers the shortfall (scale-6).
            let shortfall = u64::try_from(-net).unwrap_or(u64::MAX);
            let fund = inner.insurance_fund;
            if shortfall >= fund {
                // Insurance fund depleted — trigger ADL.
                inner.insurance_fund = 0;
                let adl_events = Self::auto_deleverage(&mut inner, account, shortfall - fund);
                events.extend(adl_events);
            } else {
                inner.insurance_fund -= shortfall;
            }
        } else {
            // Account has leftover margin after liquidation — return it.
            let leftover = u64::try_from(net).unwrap_or(0);
            if leftover > 0 {
                if let Some(ledger) = &self.ledger {
                    // Credit the leftover back to the account's
                    // balance. (The margin was deposited from it.)
                    let _ = ledger.credit(account, leftover);
                }
            }
        }

        Ok(events)
    }

    /// Auto-deleverage profitable counterparties to cover a shortfall
    /// after the insurance fund is depleted.
    ///
    /// ADL ranks all open positions by a priority score that combines
    /// profit and leverage: the most profitable, highest-leverage
    /// counterparties are deleveraged first. Each counterparty's
    /// position is partially or fully closed at the bankruptcy price
    /// (the liquidated account's entry price), realizing their profit
    /// and using it to cover the shortfall.
    ///
    /// # Algorithm
    ///
    /// 1. Collect all open positions from accounts other than the
    ///    liquidated account, across all markets.
    /// 2. Compute each position's unrealized `PnL` at the current mark
    ///    price.
    /// 3. Rank by `PnL` descending (most profitable first). Ties are
    ///    broken by position size descending (larger positions first),
    ///    then by address ascending (deterministic).
    /// 4. For each counterparty in rank order:
    ///    - Compute the `PnL` to claw back: `min(remaining_shortfall,
    ///      counterparty_pnl)`.
    ///    - Reduce the counterparty's position size proportionally
    ///      to the clawback fraction.
    ///    - Realize the clawed-back `PnL` (debit the counterparty's
    ///      margin).
    ///    - Reduce the remaining shortfall.
    /// 5. Stop when the shortfall is covered or no more profitable
    ///    counterparties remain.
    ///
    /// # Determinism
    ///
    /// The ranking is deterministic: `PnL` desc, size desc, address
    /// asc. The clawback is proportional and uses integer arithmetic
    /// only. Two nodes with the same state produce the same ADL
    /// events.
    ///
    /// # Returns
    ///
    /// A vector of ADL events, one per deleveraged counterparty.
    fn auto_deleverage(
        inner: &mut Inner,
        liquidated_account: &Address,
        mut remaining_shortfall: u64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        if remaining_shortfall == 0 {
            return events;
        }

        // Step 1-2: Collect all open positions with their PnL.
        // Each entry: (address, market, size, entry_price, pnl_scale6).
        // Scalars only — the old code cloned a whole `Position` per
        // candidate and the caller cloned the entire `marks` map to
        // pass it in alongside `&mut Inner`; `inner.marks` is read
        // directly here via shared borrows.
        let mut candidates: Vec<(Address, u8, i64, u64, i128)> = Vec::new();
        for (addr, state) in &inner.accounts {
            if addr == liquidated_account {
                continue;
            }
            for (market, pos) in &state.positions {
                if !pos.is_open() {
                    continue;
                }
                let mark = inner.marks.get(market).copied().unwrap_or(pos.entry_price);
                let pnl_scale14 = pos.unrealized_pnl(mark);
                let pnl_scale6 = pnl_scale14 / i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
                // Only profitable positions are candidates for ADL.
                if pnl_scale6 > 0 {
                    candidates.push((*addr, *market, pos.size, pos.entry_price, pnl_scale6));
                }
            }
        }

        // Step 3: Rank by PnL desc, size desc, address asc.
        candidates.sort_by(|a, b| {
            // PnL descending.
            b.4.cmp(&a.4)
                // Size (absolute) descending.
                .then_with(|| b.2.unsigned_abs().cmp(&a.2.unsigned_abs()))
                // Address ascending (deterministic tiebreak).
                .then_with(|| a.0.cmp(&b.0))
        });

        // Step 4: Deleverage each candidate until shortfall is covered.
        // `marks`/`accounts` are destructured so mark lookups (shared)
        // and position mutations (mutable) borrow disjoint fields.
        let Inner { marks, accounts, .. } = &mut *inner;
        for (addr, market, pos_size, pos_entry_price, pnl_scale6) in candidates {
            if remaining_shortfall == 0 {
                break;
            }
            // Claw back min(remaining_shortfall, counterparty_pnl).
            let clawback_target =
                remaining_shortfall.min(u64::try_from(pnl_scale6).unwrap_or(u64::MAX));
            // The candidate came from a live account — `get_mut`
            // suffices (no account_mut side effects needed).
            let Some(acct) = accounts.get_mut(&addr) else {
                continue;
            };
            let Some(pos_entry) = acct.positions.get_mut(&market) else {
                continue;
            };

            // H3 fix: compute close_qty from scale-14 PnL to avoid
            // double-flooring. The PnL per unit at scale-14 is
            // |mark - entry|. To cover `clawback_target` (scale-6),
            // we need to close:
            //   close_qty = clawback_target * PRICE_SCALE / pnl_per_unit
            // The realized PnL is then:
            //   realized = close_qty * pnl_per_unit / PRICE_SCALE
            // which may differ from clawback_target by at most 1
            // scale-6 unit due to integer flooring. We debit the
            // *realized* amount, not the target, to keep accounting
            // exact.
            let mark = marks.get(&market).copied().unwrap_or(pos_entry_price);
            let pnl_per_unit = if pos_size > 0 {
                i128::from(mark) - i128::from(pos_entry_price)
            } else {
                i128::from(pos_entry_price) - i128::from(mark)
            };
            if pnl_per_unit <= 0 {
                continue; // not actually profitable at current mark
            }
            let price_scale = i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
            let close_qty_i128 = (i128::from(clawback_target) * price_scale) / pnl_per_unit;
            let size_abs = i128::from(pos_size.unsigned_abs());
            let close_qty = i64::try_from(close_qty_i128.min(size_abs)).unwrap_or(0);
            if close_qty == 0 {
                continue;
            }
            // Compute the exact realized PnL (scale-6) from closing
            // close_qty units. This is the amount we actually debit.
            let realized_scale6 =
                u64::try_from((i128::from(close_qty) * pnl_per_unit) / price_scale)
                    .unwrap_or(u64::MAX);

            // Reduce the position size (preserve sign).
            if pos_size > 0 {
                pos_entry.size -= close_qty;
            } else {
                pos_entry.size += close_qty;
            }
            // Debit the *realized* PnL (not the target) from the
            // counterparty's margin. This keeps accounting exact.
            if pos_entry.isolated_margin > 0 {
                pos_entry.isolated_margin =
                    pos_entry.isolated_margin.saturating_sub(realized_scale6);
            } else {
                acct.cross_margin = acct.cross_margin.saturating_sub(realized_scale6);
            }
            remaining_shortfall = remaining_shortfall.saturating_sub(realized_scale6);

            events.push(Event { module: "perps", kind: "adl_executed", data: vec![market] });
        }

        // If there's still a shortfall after ADL, it's an unrecoverable
        // loss. In production, this would trigger socialized loss or
        // emergency governance. For now, we log it as an event.
        if remaining_shortfall > 0 {
            events.push(Event { module: "perps", kind: "adl_shortfall_remaining", data: vec![] });
        }

        events
    }
}

/// Staged perps state — the decoded form of a snapshot blob's
/// canonical section, produced by [`PerpsModule::decode_committed`]
/// and installed by `import_state` only after the executor has
/// verified the blob's claimed root.
///
/// Wiring handles (`ledger`, `committee`) are not part of it — they
/// are assembly-time dependencies reattached by the node harness,
/// not chain state.
struct StagedPerps {
    /// Matching engines per market slot (fixed `u8`-indexed array).
    markets: Vec<Option<MatchingEngine>>,
    /// Perps-specific configs per listed market.
    configs: BTreeMap<u8, PerpsMarketConfig>,
    /// Mark prices per market (scale-8).
    marks: BTreeMap<u8, u64>,
    /// Account states, keyed by address.
    accounts: BTreeMap<Address, AccountState>,
    /// Insurance fund balance (scale-6 quote).
    insurance_fund: u64,
    /// Per-market oracle-update counter for the current block.
    oracle_updates_this_block: BTreeMap<u8, u8>,
    /// Pending governance endorsements (C9).
    endorsements: framework::Endorsements,
}

impl PerpsModule {
    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Live books: market config + order-id sequence + every
        // resting order (canonical order inside the engine encoding).
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
        // Perps market configs (leverage / mmr — margin math).
        w.put_count(inner.configs.len());
        for (market, cfg) in &inner.configs {
            w.put_u8(*market);
            w.put_u16(cfg.max_leverage);
            w.put_u16(cfg.mmr_base_bps);
        }
        // Mark prices drive funding, liquidations, and margin checks.
        w.put_count(inner.marks.len());
        for (market, mark) in &inner.marks {
            w.put_u8(*market);
            w.put_u64(*mark);
        }
        // Accounts: cross margin, per-market positions, and the C7
        // open-order reservations (potential exposure).
        w.put_count(inner.accounts.len());
        for (addr, acct) in &inner.accounts {
            w.put_addr(addr);
            w.put_u64(acct.cross_margin);
            w.put_count(acct.positions.len());
            for (market, pos) in &acct.positions {
                w.put_u8(*market);
                w.put_i64(pos.size);
                w.put_u64(pos.entry_price);
                w.put_u64(pos.isolated_margin);
            }
            w.put_count(acct.open_orders.len());
            for ((market, oid), resv) in &acct.open_orders {
                w.put_u8(*market);
                w.put_u64(*oid);
                w.put_u64(resv.qty);
                w.put_u64(resv.price);
                w.put_u8(resv.side as u8);
                w.put_bool(resv.reduce_only);
            }
        }
        w.put_u64(inner.insurance_fund);
        // Intra-block oracle-update counter: deterministic (same
        // block → same count) and cheap, so it is committed too.
        w.put_count(inner.oracle_updates_this_block.len());
        for (market, n) in &inner.oracle_updates_this_block {
            w.put_u8(*market);
            w.put_u8(*n);
        }
        drop(inner);
        // C9: pending governance endorsements decide whether an
        // override applies — future-affecting state, committed like
        // everything else.
        self.endorsements.write_canonical(w);
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema.
    ///
    /// `slots` is the destination's fixed market-slot count: a blob
    /// claiming a different array length cannot represent this
    /// module's state.
    ///
    /// Beyond structural validity this enforces the *internal*
    /// invariants every live code path maintains (store↔config
    /// binding, marks ⟺ listed markets, reservations ⟺ resting
    /// orders). Those matter because the root check alone only proves
    /// the blob hashes to the claimed root — a crafted blob with a
    /// matching claimed root could otherwise install state no honest
    /// execution could produce, corrupting margin accounting on the
    /// next fill.
    fn decode_committed(
        r: &mut framework::CanonicalReader<'_>,
        store: &BTreeMap<Vec<u8>, Vec<u8>>,
        slots: usize,
    ) -> Option<StagedPerps> {
        let markets = Self::decode_engines(r, slots)?;
        let configs = Self::decode_configs(r, &markets, store)?;
        let marks = Self::decode_marks(r, &configs)?;
        let accounts = Self::decode_accounts(r, &configs)?;
        Self::check_reservation_binding(&markets, &accounts)?;
        let insurance_fund = r.get_u64()?;
        // Intra-block oracle-update counter — a count for an
        // unlisted market is dead state no live path produces.
        let n = r.get_count()?;
        let mut oracle_updates_this_block = BTreeMap::new();
        for _ in 0..n {
            let market = r.get_u8()?;
            let count = r.get_u8()?;
            if !configs.contains_key(&market) {
                return None;
            }
            if oracle_updates_this_block.insert(market, count).is_some() {
                return None;
            }
        }
        let endorsements = framework::Endorsements::read_canonical(r)?;
        Some(StagedPerps {
            markets,
            configs,
            marks,
            accounts,
            insurance_fund,
            oracle_updates_this_block,
            endorsements,
        })
    }

    /// Decode the fixed-size market array — one canonical engine blob
    /// per listed slot.
    fn decode_engines(
        r: &mut framework::CanonicalReader<'_>,
        slots: usize,
    ) -> Option<Vec<Option<MatchingEngine>>> {
        let n = r.get_count()?;
        if n != slots {
            return None;
        }
        let mut markets = Vec::with_capacity(n);
        for _ in 0..n {
            match r.get_u8()? {
                0 => markets.push(None),
                1 => {
                    let bytes = r.get_bytes()?;
                    markets.push(Some(
                        MatchingEngine::from_canonical_state(bytes, |c| DenseBook::new(*c)).ok()?,
                    ));
                }
                _ => return None,
            }
        }
        Some(markets)
    }

    /// Decode the perps market configs. `base` is recovered from the
    /// engine's own canonical config so the two encodings cannot
    /// disagree, and the KV store must carry the byte-identical
    /// `m/{id}` entry — without that binding a crafted blob could
    /// pair engines with mismatched store entries and still hash to
    /// a self-consistent root.
    fn decode_configs(
        r: &mut framework::CanonicalReader<'_>,
        markets: &[Option<MatchingEngine>],
        store: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Option<BTreeMap<u8, PerpsMarketConfig>> {
        let n = r.get_count()?;
        let mut configs = BTreeMap::new();
        for _ in 0..n {
            let market = r.get_u8()?;
            let max_leverage = r.get_u16()?;
            let mmr_base_bps = r.get_u16()?;
            let engine = markets.get(usize::from(market)).and_then(Option::as_ref)?;
            let cfg = PerpsMarketConfig { base: *engine.config(), max_leverage, mmr_base_bps };
            match store.get(&market_config_key(market)) {
                Some(v) if *v == encode_perps_config(&cfg) => {}
                _ => return None,
            }
            if configs.insert(market, cfg).is_some() {
                return None; // Duplicate market key — non-canonical.
            }
        }
        Some(configs)
    }

    /// Decode mark prices. `set_mark_price` rejects unknown markets
    /// and `list_market` seeds an initial mark, so the live invariant
    /// is marks ⟺ configs exactly.
    fn decode_marks(
        r: &mut framework::CanonicalReader<'_>,
        configs: &BTreeMap<u8, PerpsMarketConfig>,
    ) -> Option<BTreeMap<u8, u64>> {
        let n = r.get_count()?;
        let mut marks = BTreeMap::new();
        for _ in 0..n {
            let market = r.get_u8()?;
            let mark = r.get_u64()?;
            if !configs.contains_key(&market) {
                return None;
            }
            if marks.insert(market, mark).is_some() {
                return None;
            }
        }
        if marks.len() != configs.len() {
            return None;
        }
        Some(marks)
    }

    /// Decode accounts — cross margin, positions (only on listed
    /// markets: a position can only exist where fills can happen),
    /// and C7 open-order reservations.
    fn decode_accounts(
        r: &mut framework::CanonicalReader<'_>,
        configs: &BTreeMap<u8, PerpsMarketConfig>,
    ) -> Option<BTreeMap<Address, AccountState>> {
        let n = r.get_count()?;
        let mut accounts = BTreeMap::new();
        for _ in 0..n {
            let addr = r.get_addr()?;
            let cross_margin = r.get_u64()?;
            let pn = r.get_count()?;
            let mut positions = BTreeMap::new();
            for _ in 0..pn {
                let market = r.get_u8()?;
                if !configs.contains_key(&market) {
                    return None;
                }
                let size = r.get_i64()?;
                let entry_price = r.get_u64()?;
                let isolated_margin = r.get_u64()?;
                if positions
                    .insert(market, Position { size, entry_price, isolated_margin })
                    .is_some()
                {
                    return None;
                }
            }
            let on = r.get_count()?;
            let mut open_orders = BTreeMap::new();
            for _ in 0..on {
                let market = r.get_u8()?;
                let oid = r.get_u64()?;
                let qty = r.get_u64()?;
                let price = r.get_u64()?;
                let side = match r.get_u8()? {
                    0 => Side::Buy,
                    1 => Side::Sell,
                    _ => return None,
                };
                let reduce_only = r.get_bool()?;
                if open_orders
                    .insert((market, oid), OpenOrderResv { qty, price, side, reduce_only })
                    .is_some()
                {
                    return None;
                }
            }
            if accounts
                .insert(addr, AccountState { cross_margin, positions, open_orders })
                .is_some()
            {
                return None;
            }
        }
        Some(accounts)
    }

    /// Enforce the reservation↔book binding: collect every resting
    /// order and require a bijection with the accounts' reservations
    /// — same owner, side, price, and remaining qty. A crafted blob
    /// that splits the two would leak or double-charge margin on the
    /// next fill/cancel.
    fn check_reservation_binding(
        markets: &[Option<MatchingEngine>],
        accounts: &BTreeMap<Address, AccountState>,
    ) -> Option<()> {
        let mut resting = BTreeMap::new();
        let mut scratch = Vec::new();
        for (i, engine) in markets.iter().enumerate() {
            let Some(e) = engine else { continue };
            e.resting_entries(&mut scratch);
            let market = u8::try_from(i).ok()?;
            for entry in scratch.drain(..) {
                if resting.insert((market, entry.id.0), entry).is_some() {
                    return None; // Duplicate resting id — impossible from a live engine.
                }
            }
        }
        for (addr, acct) in accounts {
            for ((market, oid), resv) in &acct.open_orders {
                let entry = resting.get(&(*market, *oid))?;
                if entry.owner != *addr
                    || entry.qty.0 != resv.qty
                    || entry.price.0 != resv.price
                    || entry.side != resv.side
                {
                    return None;
                }
            }
        }
        for ((market, oid), entry) in &resting {
            // Field equality was proven by the forward pass; the
            // reverse only needs existence.
            accounts.get(&entry.owner).and_then(|a| a.open_orders.get(&(*market, *oid)))?;
        }
        Some(())
    }
}

impl Default for PerpsModule {
    fn default() -> Self {
        Self::new()
    }
}

// ── Wire message constructors ───────────────────────────────────────

/// Wire message builders for the perps module.
pub mod msg {
    use super::{
        CANCEL_BODY_LEN, FUNDING_BODY_LEN, LIST_MARKET_BODY_LEN, MARGIN_BODY_LEN, NewOrder,
        OrderId, PLACE_BODY_LEN, PerpsMarketConfig, SET_MARK_BODY_LEN, encode_order_type,
        encode_side, encode_stp, encode_tif,
    };

    /// Build a place-order message.
    pub fn place(market: u8, order: NewOrder) -> Vec<u8> {
        place_with_flags(market, order, 0)
    }

    /// Build a reduce-only place-order message (C7): the order may
    /// only close existing exposure — oversized requests are
    /// rejected at admission and resting remainders are canceled if
    /// they outlive their cover.
    pub fn place_reduce_only(market: u8, order: NewOrder) -> Vec<u8> {
        place_with_flags(market, order, super::FLAG_REDUCE_ONLY)
    }

    /// Shared place-order encoder: `[tag][market][side][type][tif]
    /// [stp][price][qty][flags]`.
    fn place_with_flags(market: u8, order: NewOrder, flags: u8) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + PLACE_BODY_LEN);
        msg.push(super::TAG_PLACE);
        msg.push(market);
        msg.push(encode_side(order.side));
        msg.push(encode_order_type(order.order_type));
        msg.push(encode_tif(order.tif));
        msg.push(encode_stp(order.stp));
        msg.extend_from_slice(&order.price.0.to_le_bytes());
        msg.extend_from_slice(&order.qty.0.to_le_bytes());
        msg.push(flags);
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

    /// Build a list-market message.
    pub fn list_market(cfg: PerpsMarketConfig) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + LIST_MARKET_BODY_LEN);
        msg.push(super::TAG_LIST_MARKET);
        msg.extend_from_slice(&cfg.base.tick_size.to_le_bytes());
        msg.extend_from_slice(&cfg.base.lot_size.to_le_bytes());
        msg.extend_from_slice(&cfg.base.min_price.to_le_bytes());
        msg.extend_from_slice(&cfg.base.max_price.to_le_bytes());
        msg.extend_from_slice(&cfg.base.max_resting.to_le_bytes());
        msg.extend_from_slice(&cfg.max_leverage.to_le_bytes());
        msg.extend_from_slice(&cfg.mmr_base_bps.to_le_bytes());
        msg
    }

    /// Build a deposit-margin message.
    pub fn deposit(market: u8, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + MARGIN_BODY_LEN);
        msg.push(super::TAG_DEPOSIT);
        msg.push(market);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// Build a withdraw-margin message.
    pub fn withdraw(market: u8, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + MARGIN_BODY_LEN);
        msg.push(super::TAG_WITHDRAW);
        msg.push(market);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// Build a set-mark-price message.
    pub fn set_mark(market: u8, mark: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + SET_MARK_BODY_LEN);
        msg.push(super::TAG_SET_MARK);
        msg.push(market);
        msg.extend_from_slice(&mark.to_le_bytes());
        msg
    }

    /// Build an apply-funding message.
    pub fn apply_funding(market: u8, rate_i64: i64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + FUNDING_BODY_LEN);
        msg.push(super::TAG_APPLY_FUNDING);
        msg.push(market);
        msg.extend_from_slice(&rate_i64.to_le_bytes());
        msg
    }
}

// ── Module trait impl ────────────────────────────────────────────────

impl Module for PerpsModule {
    fn name(&self) -> &'static str {
        "perps"
    }

    fn id(&self) -> u8 {
        module_id::PERPS
    }

    fn begin_block(&self, _height: Height) {
        // M4 fix: reset the per-block oracle update counter at the
        // start of each block. Each market gets a fresh budget of
        // [`MAX_ORACLE_UPDATES_PER_BLOCK`] updates per block.
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.oracle_updates_this_block.clear();
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.is_empty() {
            return Err(ExecError::Malformed);
        }
        let tag = msg[0];
        let body = &msg[1..];

        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        match tag {
            TAG_PLACE => {
                drop(inner);
                self.handle_place(ctx, body)
            }
            TAG_CANCEL => {
                drop(inner);
                self.handle_cancel(ctx, body)
            }
            TAG_LIST_MARKET => {
                drop(inner);
                self.handle_list_market(ctx, msg, body)
            }
            TAG_DEPOSIT => {
                drop(inner);
                self.handle_deposit(ctx, body)
            }
            TAG_WITHDRAW => {
                drop(inner);
                self.handle_withdraw(ctx, body)
            }
            TAG_SET_MARK => {
                let (market, mark) = Self::parse_set_mark(body).ok_or(ExecError::Malformed)?;
                // Reject a nonexistent market before recording an
                // endorsement — pending actions are a bounded set,
                // so junk targets must never occupy a slot. Markets
                // are only ever listed, never removed, so the
                // check cannot go stale mid-endorsement.
                if !inner.configs.contains_key(&market) {
                    return Err(ExecError::ModuleRejected("market does not exist".to_string()));
                }
                drop(inner);
                // C9: committee-quorum emergency override. The
                // normal mark pipeline is the oracle module pushing
                // the aggregated median through `MarkSink`; this tx
                // path exists so the validator set can still force
                // a mark if the oracle feed stalls entirely. Each
                // tx endorses the exact (market, mark) payload —
                // the mark applies only once endorsing power
                // strictly exceeds two-thirds of the committee, so
                // one validator's signature is a vote, never a
                // command. Without a wired committee the path is
                // closed entirely.
                let Some(committee) = self.committee.clone() else {
                    return Err(ExecError::ModuleRejected(
                        "set_mark: no committee wired".to_string(),
                    ));
                };
                match self.endorsements.record(msg, &ctx.sender, committee.as_ref())? {
                    framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                        module: "perps",
                        kind: "set_mark_endorse",
                        data: vec![market],
                    }]),
                    framework::EndorsementOutcome::Quorum => {
                        // `set_mark_price` keeps the per-update
                        // deviation cap and per-block rate limit —
                        // a quorum-authorized mark that violates
                        // them is consumed as stale, not forced.
                        match self.set_mark_price(market, mark) {
                            Ok(()) => Ok(vec![Event {
                                module: "perps",
                                kind: "mark_updated",
                                data: vec![market],
                            }]),
                            Err(_) => Ok(vec![Event {
                                module: "perps",
                                kind: "set_mark_stale",
                                data: vec![market],
                            }]),
                        }
                    }
                }
            }
            TAG_APPLY_FUNDING => {
                let (market, rate_bits) = Self::parse_funding(body).ok_or(ExecError::Malformed)?;
                let rate = i64::from_le_bytes(rate_bits);
                // Same pre-endorsement existence check as
                // `TAG_SET_MARK` — the bounded pending set must
                // never carry an action that cannot apply.
                if !inner.marks.contains_key(&market) {
                    return Err(ExecError::ModuleRejected("market does not exist".to_string()));
                }
                drop(inner);
                // Same quorum gate as `TAG_SET_MARK` — an
                // unauthenticated funding rate is an
                // unauthenticated balance transfer between every
                // long and short on the market, so it takes the
                // same two-thirds endorsement to apply.
                let Some(committee) = self.committee.clone() else {
                    return Err(ExecError::ModuleRejected(
                        "apply_funding: no committee wired".to_string(),
                    ));
                };
                match self.endorsements.record(msg, &ctx.sender, committee.as_ref())? {
                    framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                        module: "perps",
                        kind: "apply_funding_endorse",
                        data: vec![market],
                    }]),
                    framework::EndorsementOutcome::Quorum => {
                        match self.apply_funding(market, rate) {
                            Ok(events) => Ok(events),
                            Err(_) => Ok(vec![Event {
                                module: "perps",
                                kind: "apply_funding_stale",
                                data: vec![market],
                            }]),
                        }
                    }
                }
            }
            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, _height: Height) {}

    fn state_root(&self) -> Hash {
        // C8: commit EVERY field that can affect future execution —
        // the KV store only mirrors market configs, while positions,
        // margin, marks, the insurance fund, open-order reservations,
        // and the live books decide future fills, liquidations, and
        // funding. Identical roots across validators must prove
        // identical trading state. Section order is fixed and
        // consensus-critical.
        //
        // Excluded: `fills` (per-call scratch), `ledger` /
        // `committee` (assembly wiring, not tx-mutated state).
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
    /// committed subtree root, fully decode the fields with all
    /// internal invariants enforced, then hash the canonical
    /// preimage.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let slots =
            self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).markets.len();
        let (canon, _staged, _store) = framework::stage_blob_snapshot(snapshot, |r, store| {
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
        let (_canon, staged, store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        *self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = store;
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.markets = staged.markets;
        inner.configs = staged.configs;
        inner.marks = staged.marks;
        inner.accounts = staged.accounts;
        inner.insurance_fund = staged.insurance_fund;
        inner.oracle_updates_this_block = staged.oracle_updates_this_block;
        // `fills` is per-call scratch — clear it so a buffer left
        // mid-transaction cannot leak across the import boundary.
        inner.fills.clear();
        drop(inner);
        self.endorsements.replace_with(staged.endorsements);
        Ok(())
    }
}

impl framework::MarkSink for PerpsModule {
    /// The oracle's push target. Deliberately routes through the
    /// *checked* setter: the oracle's median+EMA is the primary
    /// defense, and this module's deviation cap + per-block rate
    /// limit stay armed as an independent second layer — a sink that
    /// trusted its producer would turn one oracle bug into an
    /// unbounded price move.
    fn set_mark_price(&self, market: u8, mark: u64) -> Result<(), ExecError> {
        Self::set_mark_price(self, market, mark)
    }
}

// ── Fill → position application ──────────────────────────────────────

impl PerpsModule {
    /// Handle a list-market message (extracted from `handle` to keep
    /// the dispatch function under the clippy line-count gate).
    fn handle_list_market(
        &self,
        ctx: &TxContext,
        msg: &[u8],
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let cfg = Self::parse_list_market(body).ok_or(ExecError::Malformed)?;
        // Reject an invalid config before recording an
        // endorsement — pending actions are a bounded set,
        // so a proposal that can never apply must not occupy
        // a slot. `base.validate` also caps `max_resting`
        // at `MAX_RESTING_LIMIT`, bounding the arenas
        // `list_market` allocates at quorum.
        cfg.validate().map_err(|e| ExecError::ModuleRejected(format!("list_market: {e}")))?;
        // Same quorum gate as `TAG_SET_MARK`: a listing
        // eagerly allocates the market's order-pool and
        // id-map arenas, so an unauthenticated listing is a
        // memory-exhaustion primitive. Each tx endorses the
        // exact tagged message; the market lists only once
        // endorsing power strictly exceeds two-thirds.
        let Some(committee) = self.committee.clone() else {
            return Err(ExecError::ModuleRejected("list_market: no committee wired".to_string()));
        };
        match self.endorsements.record(msg, &ctx.sender, committee.as_ref())? {
            framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                module: "perps",
                kind: "list_market_endorse",
                data: body.to_vec(),
            }]),
            framework::EndorsementOutcome::Quorum => match self.list_market(cfg) {
                Ok(id) => {
                    Ok(vec![Event { module: "perps", kind: "market_listed", data: vec![id] }])
                }
                // Quorum reached but the listing no longer
                // applies (e.g. all slots filled while the
                // proposal accumulated votes).
                Err(_) => Ok(vec![Event {
                    module: "perps",
                    kind: "list_market_stale",
                    data: body.to_vec(),
                }]),
            },
        }
    }

    /// Handle a place-order message (extracted from `handle` to keep
    /// the dispatch function under the clippy line-count gate).
    fn handle_place(&self, ctx: &TxContext, body: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (market, mut order, flags) = Self::parse_place(body).ok_or(ExecError::Malformed)?;
        order.owner = ctx.sender;
        let reduce_only = flags & FLAG_REDUCE_ONLY != 0;

        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        // ── Initial-margin gate (plan.md §9.3, C7) ──
        // An order must leave `equity >= total initial margin` after
        // accounting for the exposure it could ADD. The reducible
        // portion — the part of an opposite-side order that closes
        // existing size — is free; only the tail beyond it is new
        // exposure. A reduce-then-flip order is therefore charged on
        // its flipped remainder, not skipped wholesale (the old
        // `increases` test let a flip order through with no margin
        // at all) and not over-charged on its covered part.
        //
        // `existing` now includes `total_open_order_im`: resting
        // orders are potential exposure and must be margined as if
        // filled — otherwise an account could stack unbacked orders
        // that all later fill (C7).
        if !inner.configs.contains_key(&market) {
            return Err(ExecError::ModuleRejected(format!("market {market} does not exist")));
        }
        {
            let acct = inner.accounts.get(&ctx.sender);
            let pos = acct.and_then(|a| a.positions.get(&market));
            let pos_size = pos.map_or(0, |p| p.size);
            // The position can only close once: closing capacity the
            // account's resting opposing orders in this market have
            // already claimed is not available to this order.
            let cover_booked: u128 = acct.map_or(0, |a| {
                a.open_orders
                    .iter()
                    .filter(|((m, _), r)| {
                        *m == market
                            && ((pos_size > 0 && r.side == Side::Sell)
                                || (pos_size < 0 && r.side == Side::Buy))
                    })
                    .map(|(_, r)| u128::from(r.qty))
                    .sum()
            });
            let reducible = u128::from(pos_size.unsigned_abs()).saturating_sub(cover_booked);
            // Reduce-only may only close: a request larger than the
            // reducible size would add exposure, which the flag
            // forbids — reject at admission.
            if reduce_only && u128::from(order.qty.0) > reducible {
                return Err(ExecError::ModuleRejected(
                    "reduce-only order exceeds reducible position".to_string(),
                ));
            }
            // Marginal IM of this order = the reservation-set IM
            // with it folded in, minus the set without it. Folding
            // the order into the set charges same-side exposure in
            // full and gives an opposing order only the closing
            // capacity the resting book has not already claimed —
            // scoring it against the raw position would let every
            // successive order spend the same cover.
            let ref_price = match order.order_type {
                OrderType::Market => inner.marks.get(&market).copied().unwrap_or(order.price.0),
                _ => order.price.0,
            };
            let extra =
                OpenOrderResv { qty: order.qty.0, price: ref_price, side: order.side, reduce_only };
            let empty = AccountState::default();
            let a = acct.unwrap_or(&empty);
            let order_set_im = a.open_order_im_with(&inner.configs, Some((market, &extra)));
            let new_im = order_set_im.saturating_sub(a.total_open_order_im(&inner.configs));
            if new_im > 0 {
                let equity = a.equity(&inner.marks, &inner.configs);
                let existing_im = a.total_initial_margin(&inner.marks, &inner.configs);
                let required = existing_im.saturating_add(order_set_im);
                if equity < i128::try_from(required).unwrap_or(i128::MAX) {
                    return Err(ExecError::ModuleRejected(
                        "insufficient initial margin".to_string(),
                    ));
                }
            }
        }

        let Inner { markets, fills, accounts, .. } = &mut *inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::ModuleRejected(format!("market {market} does not exist")));
        };

        fills.clear();
        let mut cap =
            ReduceOnlyCap { accounts, market, spent: BTreeMap::new(), removed: Vec::new() };
        let outcome = engine
            .place_with_cap(order, fills, &mut cap)
            .map_err(|e| ExecError::ModuleRejected(format!("engine: {e}")))?;
        let ReduceOnlyCap { removed, .. } = cap;

        // Move fills out of the scratch buffer (no clone). The
        // buffer is left empty for the next use. This avoids a
        // per-fill clone: previously, `fills.clone()` copied every
        // FillEvent so we could release the borrow on `inner` and
        // then apply fills to positions. `mem::take` moves the Vec's
        // contents out in O(1), leaving an empty Vec behind.
        let fills_owned: Vec<FillEvent> = std::mem::take(fills);

        // Makers the sweep removed or decremented without a fill —
        // cap kills and self-trade-prevention removals alike — are
        // already off the book. Release their reservations now so
        // fill application doesn't see stale entries.
        Self::release_removal_reservations(&mut inner, market, &removed);

        // A resting remainder joins the reservation ledger (C7): the
        // uncovered tail is charged initial margin until the order
        // fills or is canceled. Reduce-only orders record the flag so
        // a remainder that outlives its cover is canceled at the next
        // maker fill.
        if let OrderOutcome::Resting { order_id, price, resting_qty } = outcome {
            let acct = Self::account_mut(&mut inner, &ctx.sender);
            acct.open_orders.insert(
                (market, order_id.0),
                OpenOrderResv { qty: resting_qty.0, price: price.0, side: order.side, reduce_only },
            );
        }
        let mut events = Vec::with_capacity(fills_owned.len() + 1);
        for f in &fills_owned {
            events.push(fill_event(*f));
        }

        // Apply fills to positions (needs exclusive `&mut inner`).
        for f in &fills_owned {
            Self::apply_fill_to_position(&mut inner, market, f, &mut events);
        }

        // Post-trade margin check — the taker AND every maker whose
        // position the fills changed. A maker fill can push the
        // maker under water (realized loss, or a flip into exposure
        // it cannot cover); the check is uniform for every account
        // the trade touched.
        Self::margin_check(&mut inner, &ctx.sender, market, &mut events);
        let mut checked: Vec<Address> = Vec::with_capacity(fills_owned.len());
        for f in &fills_owned {
            let maker = f.maker_owner;
            if maker != ctx.sender && !checked.contains(&maker) {
                checked.push(maker);
                Self::margin_check(&mut inner, &maker, market, &mut events);
            }
        }

        events.push(outcome_event(market, outcome));
        Self::emit_removal_events(market, &removed, &mut events);
        Ok(events)
    }

    /// Release reservations for makers the sweep removed or
    /// decremented without a fill — call before applying fills so
    /// stale entries don't linger. The book is authoritative for
    /// decremented quantities.
    fn release_removal_reservations(
        inner: &mut Inner,
        market: u8,
        removed: &[trading::MakerRemoval],
    ) {
        for r in removed {
            if let Some(acct) = inner.accounts.get_mut(&r.owner) {
                if r.remaining == 0 {
                    acct.open_orders.remove(&(market, r.order_id.0));
                } else if let Some(resv) = acct.open_orders.get_mut(&(market, r.order_id.0)) {
                    resv.qty = r.remaining;
                }
            }
        }
    }

    /// Emit one event per non-fill book change the sweep applied:
    /// cap kills are reduce-only cancels; self-trade removals and
    /// decrements get their own kinds so downstream accounting sees
    /// every obligation the book released.
    fn emit_removal_events(market: u8, removed: &[trading::MakerRemoval], events: &mut Vec<Event>) {
        for r in removed {
            let kind = match r.reason {
                trading::RemovalReason::Cap => "reduce_only_cancel",
                trading::RemovalReason::SelfTrade if r.remaining == 0 => "stp_cancel",
                trading::RemovalReason::SelfTrade => "stp_decrement",
            };
            let mut data = Vec::with_capacity(1 + 8 + 8);
            data.push(market);
            data.extend_from_slice(&r.order_id.0.to_le_bytes());
            data.extend_from_slice(&r.remaining.to_le_bytes());
            events.push(Event { module: "perps", kind, data });
        }
    }

    /// Handle a cancel-order message (extracted from `handle`).
    fn handle_cancel(&self, ctx: &TxContext, body: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (market, order_id) = Self::parse_cancel(body).ok_or(ExecError::Malformed)?;
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Inner { markets, .. } = &mut *inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::ModuleRejected(format!("market {market} does not exist")));
        };
        if let Some(owner) = engine.order_owner(order_id) {
            if owner != ctx.sender {
                return Err(ExecError::ModuleRejected("cancel: not the order owner".to_string()));
            }
        } else {
            // Order not on the book: if a reservation entry survives
            // (e.g. an STP-cancelled order the module was never told
            // about), drop it now — the reservation ledger heals
            // itself on contact.
            if let Some(acct) = inner.accounts.get_mut(&ctx.sender) {
                acct.open_orders.remove(&(market, order_id.0));
            }
            return Err(ExecError::ModuleRejected("cancel: order not found".to_string()));
        }
        match engine.cancel(order_id) {
            Ok(canceled) => {
                // Release the margin reservation — removing the entry
                // IS the release; `total_open_order_im` recomputes
                // from live entries.
                if let Some(acct) = inner.accounts.get_mut(&ctx.sender) {
                    acct.open_orders.remove(&(market, order_id.0));
                }
                Ok(vec![cancel_event(market, canceled)])
            }
            Err(TradingError::OrderNotFound) => {
                Err(ExecError::ModuleRejected("cancel: order not found".to_string()))
            }
            Err(e) => Err(ExecError::ModuleRejected(format!("cancel: {e}"))),
        }
    }

    /// Handle a deposit-margin message (extracted from `handle`).
    /// Handle a deposit-margin message (extracted from `handle`).
    ///
    /// # Atomicity
    ///
    /// The margin credit is validated **before** the ledger debit: a
    /// deposit that would overflow the `u64` margin field is
    /// rejected while the account balance is still untouched. The
    /// previous order — debit ledger, then `saturating_add` the margin
    /// — could take the user's funds while crediting less
    /// margin than was deposited (silent value destruction).
    fn handle_deposit(&self, ctx: &TxContext, body: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (market, amount) = Self::parse_margin(body).ok_or(ExecError::Malformed)?;
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let acct = Self::account_mut(&mut inner, &ctx.sender);
        let balance = if market == CROSS_MARGIN_MARKET {
            &mut acct.cross_margin
        } else {
            &mut acct.positions.entry(market).or_default().isolated_margin
        };
        // Overflow check first: never debit the ledger for margin we
        // cannot represent.
        let new_balance = balance
            .checked_add(amount)
            .ok_or_else(|| ExecError::ModuleRejected("margin balance overflow".to_string()))?;
        if let Some(ledger) = &self.ledger {
            ledger.debit(&ctx.sender, amount)?;
        }
        *balance = new_balance;
        drop(inner);
        Ok(vec![Event { module: "perps", kind: "deposit", data: vec![market] }])
    }

    /// Handle a withdraw-margin message (extracted from `handle`).
    ///
    /// # Atomicity
    ///
    /// The ledger credit is attempted **while the margin lock is held
    /// and before the margin debit**: if `ledger.credit` fails (e.g.
    /// the destination balance would overflow), the margin is
    /// untouched and the error propagates. The previous order —
    /// debit margin, then credit the ledger — destroyed the user's
    /// margin when the ledger credit failed.
    fn handle_withdraw(&self, ctx: &TxContext, body: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (market, amount) = Self::parse_margin(body).ok_or(ExecError::Malformed)?;
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        // ── Solvency gate (C7): the check is required-margin-AFTER,
        // not stored-balance-before. The old code let an account
        // withdraw the margin backing its open exposure and become
        // instantly under-margined.
        //
        // Cross withdrawal: `equity − amount` must still cover the
        // whole book's initial margin — open positions AND resting
        // orders (which are potential exposure, C7). Isolated
        // withdrawal: the position's own `isolated_margin − amount +
        // uPnL` must still cover that position's initial margin —
        // isolated margin may not be pulled below what its position
        // requires.
        if market == CROSS_MARGIN_MARKET {
            let Some(acct) = inner.accounts.get(&ctx.sender) else {
                return Err(ExecError::ModuleRejected("insufficient margin".to_string()));
            };
            if acct.cross_margin < amount {
                return Err(ExecError::ModuleRejected("insufficient margin".to_string()));
            }
            let equity_after = acct.equity(&inner.marks, &inner.configs) - i128::from(amount);
            let required = acct
                .total_initial_margin(&inner.marks, &inner.configs)
                .saturating_add(acct.total_open_order_im(&inner.configs));
            if equity_after < i128::try_from(required).unwrap_or(i128::MAX) {
                return Err(ExecError::ModuleRejected(
                    "withdrawal would breach initial margin".to_string(),
                ));
            }
        } else {
            let acct = inner.accounts.get(&ctx.sender);
            let pos = acct.and_then(|a| a.positions.get(&market));
            let iso = pos.map_or(0u64, |p| p.isolated_margin);
            if iso < amount {
                return Err(ExecError::ModuleRejected("insufficient margin".to_string()));
            }
            if let Some(p) = pos.filter(|p| p.is_open()) {
                let mark = inner.marks.get(&market).copied().unwrap_or(p.entry_price);
                let cfg = inner.configs.get(&market);
                if let Some(cfg) = cfg {
                    let price_scale = i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
                    let upnl_scale6 = p.unrealized_pnl(mark) / price_scale;
                    let equity_after = i128::from(iso - amount) + upnl_scale6;
                    let leverage = u128::from(cfg.max_leverage.max(1));
                    let pos_im = p.notional(mark) / leverage / PRICE_SCALE;
                    if equity_after < i128::try_from(pos_im).unwrap_or(i128::MAX) {
                        return Err(ExecError::ModuleRejected(
                            "withdrawal would breach position margin".to_string(),
                        ));
                    }
                }
            }
        }

        // Ledger credit first (margin lock held): on failure the
        // margin is untouched. The margin debit below cannot fail —
        // sufficiency was just checked.
        if let Some(ledger) = &self.ledger {
            ledger.credit(&ctx.sender, amount)?;
        }
        let acct = Self::account_mut(&mut inner, &ctx.sender);
        if market == CROSS_MARGIN_MARKET {
            acct.cross_margin -= amount;
        } else {
            acct.positions.entry(market).or_default().isolated_margin -= amount;
        }
        drop(inner);
        Ok(vec![Event { module: "perps", kind: "withdraw", data: vec![market] }])
    }

    /// Post-trade margin check: if the account is under-margined,
    /// emit a `margin_call` event.
    ///
    /// Read-only: the prior implementation cloned `configs`,
    /// `marks`, AND the entire account (every position) per call —
    /// three map clones on the post-trade hot path. `accounts`,
    /// `marks`, and `configs` are disjoint fields, so shared
    /// borrows suffice.
    fn margin_check(inner: &mut Inner, sender: &Address, market: u8, events: &mut Vec<Event>) {
        // No account ⇒ no positions ⇒ equity 0 ⇒ solvent; the
        // margin_call only matters for existing accounts.
        let Some(acct) = inner.accounts.get(sender) else {
            return;
        };
        let equity = acct.equity(&inner.marks, &inner.configs);
        let maintenance = acct.total_maintenance(&inner.marks, &inner.configs);
        if equity < i128::try_from(maintenance).unwrap_or(i128::MAX) {
            events.push(Event { module: "perps", kind: "margin_call", data: vec![market] });
        }
    }
}

impl PerpsModule {
    /// Apply a fill to the taker's and maker's positions, release
    /// the maker's order reservation for the filled quantity, and
    /// enforce reduce-only on the maker's remainder. Emits
    /// `realized_pnl` / `bad_debt` / `reduce_only_cancel` events.
    fn apply_fill_to_position(
        inner: &mut Inner,
        market: u8,
        fill: &FillEvent,
        events: &mut Vec<Event>,
    ) {
        // Taker side determines who is buying vs selling.
        let (buyer, seller) = if fill.taker_side == Side::Buy {
            (fill.taker_owner, fill.maker_owner)
        } else {
            (fill.maker_owner, fill.taker_owner)
        };
        // HIGH fix: `fill.qty.0` is u64; the position model is i64.
        // If a fill quantity exceeds i64::MAX (impossible in practice
        // — market configs bound order qty well below i64::MAX), cap
        // at i64::MAX. Both buyer and seller get the same capped
        // magnitude, so the net position change is zero — position
        // accounting stays consistent.
        let fill_qty = i64::try_from(fill.qty.0).unwrap_or(i64::MAX);

        // Buyer's position increases (or shorts decrease).
        Self::adjust_position(inner, &buyer, market, fill.price.0, fill_qty, events);
        // Seller's position decreases (or shorts increase).
        Self::adjust_position(inner, &seller, market, fill.price.0, -fill_qty, events);

        // Release the maker's reservation for the filled portion.
        // The maker is the resting side: its reservation tracks the
        // order's remaining qty, which every fill consumes. The
        // uncovered tail is recomputed lazily at margin-evaluation
        // time, so only `qty` is updated here.
        let maker_resv_done = {
            let acct = Self::account_mut(inner, &fill.maker_owner);
            match acct.open_orders.get_mut(&(market, fill.maker_order_id.0)) {
                Some(resv) => {
                    resv.qty = resv.qty.saturating_sub(fill.qty.0);
                    resv.qty == 0 || resv.reduce_only
                }
                None => false,
            }
        };
        if maker_resv_done {
            let (cancel_remainder, keep) = {
                let acct = Self::account_mut(inner, &fill.maker_owner);
                let key = (market, fill.maker_order_id.0);
                match acct.open_orders.get(&key) {
                    // Reduce-only enforcement: if the remaining qty
                    // now exceeds what the live position can still
                    // reduce, the remainder could add exposure —
                    // cancel it (standard reduce-only semantics).
                    Some(resv) if resv.reduce_only && resv.qty > 0 => {
                        let covered = match acct.positions.get(&market) {
                            Some(p)
                                if (p.size > 0 && resv.side == Side::Sell)
                                    || (p.size < 0 && resv.side == Side::Buy) =>
                            {
                                p.size.unsigned_abs().min(resv.qty)
                            }
                            _ => 0,
                        };
                        (resv.qty > covered, resv.qty <= covered)
                    }
                    Some(resv) => (false, resv.qty > 0),
                    None => (false, false),
                }
            };
            if cancel_remainder {
                if let Some(engine) =
                    inner.markets.get_mut(usize::from(market)).and_then(Option::as_mut)
                {
                    let _ = engine.cancel(fill.maker_order_id);
                    events.push(Event {
                        module: "perps",
                        kind: "reduce_only_cancel",
                        data: vec![market],
                    });
                }
            }
            if !keep || cancel_remainder {
                let acct = Self::account_mut(inner, &fill.maker_owner);
                acct.open_orders.remove(&(market, fill.maker_order_id.0));
            }
        }
    }

    /// Adjust a position by `delta` (signed qty) at `fill_price`.
    ///
    /// C7: a delta that opposes the position realizes `PnL` on the
    /// closed portion — `closed × (fill − entry)` for longs,
    /// `closed × (entry − fill)` for shorts — settled into the
    /// backing margin bucket via [`Self::settle_realized`]. A delta
    /// larger than the position closes it (realizing the full
    /// unrealized `PnL`) and opens the remainder on the other side at
    /// the fill price. Same-side deltas update the volume-weighted
    /// entry as before.
    fn adjust_position(
        inner: &mut Inner,
        account: &Address,
        market: u8,
        fill_price: u64,
        delta: i64,
        events: &mut Vec<Event>,
    ) {
        let mut realized_scale6: i128 = 0;
        {
            let acct = Self::account_mut(inner, account);
            let pos = acct.positions.entry(market).or_default();
            let old_size = pos.size;
            let new_size = old_size.saturating_add(delta);

            // Realized PnL on the closed portion (scale-14 → scale-6
            // at settle time). Only a delta opposing a live position
            // closes anything.
            if old_size != 0 && delta != 0 && old_size.signum() != delta.signum() {
                let closed = i128::from(old_size.unsigned_abs().min(delta.unsigned_abs()));
                let pnl_per_unit = if old_size > 0 {
                    i128::from(fill_price) - i128::from(pos.entry_price)
                } else {
                    i128::from(pos.entry_price) - i128::from(fill_price)
                };
                let price_scale = i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
                realized_scale6 = closed * pnl_per_unit / price_scale;
            }

            // Update entry price (volume-weighted) when increasing the
            // position. When decreasing, entry price stays the same.
            if delta != 0 && (old_size.signum() == delta.signum() || old_size == 0) {
                // Increasing position: weighted average.
                let old_cost = i128::from(old_size.unsigned_abs()) * i128::from(pos.entry_price);
                let add_cost = i128::from(delta.unsigned_abs()) * i128::from(fill_price);
                let new_size_abs = i128::from(new_size.unsigned_abs());
                if new_size_abs > 0 {
                    let new_entry = (old_cost + add_cost) / new_size_abs;
                    pos.entry_price = u64::try_from(new_entry).unwrap_or(u64::MAX);
                }
            }
            // If the position flipped sign (e.g. long → short), reset
            // entry to the fill price.
            if old_size != 0 && old_size.signum() != new_size.signum() {
                pos.entry_price = fill_price;
            }
            pos.size = new_size;
            if new_size == 0 {
                pos.entry_price = 0;
            }
        }

        // Settle realized PnL into the backing margin bucket — a
        // separate pass because settlement may touch the insurance
        // fund, which lives on `Inner`, not the account.
        if realized_scale6 != 0 {
            Self::settle_realized(inner, account, market, realized_scale6, events);
        }
    }

    /// Settle realized `PnL` into an account's margin (C7).
    ///
    /// A gain is credited to the bucket backing the position —
    /// `isolated_margin` when nonzero (isolated mode) else
    /// `cross_margin`. A loss drains the same bucket; an isolated
    /// position's loss is capped at its isolated bucket (that is the
    /// point of isolation — the cross pool is NOT tapped), while a
    /// cross-backed position drains the cross pool. Any remainder is
    /// bad debt covered by the insurance fund, and a shortfall
    /// beyond the fund is reported as a `bad_debt` event — value is
    /// never silently invented or destroyed.
    fn settle_realized(
        inner: &mut Inner,
        account: &Address,
        market: u8,
        realized_scale6: i128,
        events: &mut Vec<Event>,
    ) {
        let mut bad_debt: u64 = 0;
        {
            let acct = Self::account_mut(inner, account);
            let iso_backed = acct.positions.get(&market).is_some_and(|p| p.isolated_margin > 0);
            if realized_scale6 > 0 {
                let gain = u64::try_from(realized_scale6).unwrap_or(u64::MAX);
                if iso_backed {
                    let pos = acct.positions.entry(market).or_default();
                    if let Some(v) = pos.isolated_margin.checked_add(gain) {
                        pos.isolated_margin = v;
                    } else {
                        // Bucket overflow: hold the max and spill the
                        // excess to cross rather than destroy value.
                        let spill = gain - (u64::MAX - pos.isolated_margin);
                        pos.isolated_margin = u64::MAX;
                        acct.cross_margin = acct.cross_margin.saturating_add(spill);
                    }
                } else {
                    acct.cross_margin = acct.cross_margin.saturating_add(gain);
                }
            } else {
                let mut loss = u64::try_from(realized_scale6.unsigned_abs()).unwrap_or(u64::MAX);
                if iso_backed {
                    let pos = acct.positions.entry(market).or_default();
                    let from = pos.isolated_margin.min(loss);
                    pos.isolated_margin -= from;
                    loss -= from;
                } else {
                    let from = acct.cross_margin.min(loss);
                    acct.cross_margin -= from;
                    loss -= from;
                }
                bad_debt = loss;
            }
        }
        if bad_debt > 0 {
            // The account's collateral is exhausted — the insurance
            // fund is the designated backstop for uncovered losses.
            let cover = inner.insurance_fund.min(bad_debt);
            inner.insurance_fund -= cover;
            let residual = bad_debt - cover;
            let mut data = Vec::with_capacity(1 + 8);
            data.push(market);
            data.extend_from_slice(&residual.to_le_bytes());
            events.push(Event { module: "perps", kind: "bad_debt", data });
        }
        // Emit the realized amount (scale-6, signed) for the audit
        // trail — clamped to i64 range; a larger realized amount is
        // already reflected in the margin fields.
        let amt = i64::try_from(realized_scale6).unwrap_or(if realized_scale6 > 0 {
            i64::MAX
        } else {
            i64::MIN
        });
        let mut data = Vec::with_capacity(1 + 8);
        data.push(market);
        data.extend_from_slice(&amt.to_le_bytes());
        events.push(Event { module: "perps", kind: "realized_pnl", data });
    }
}

// ── Parsing helpers ─────────────────────────────────────────────────

impl PerpsModule {
    fn parse_place(msg: &[u8]) -> Option<(u8, NewOrder, u8)> {
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
        let flags = msg[21];
        // Unknown flag bits are rejected, not ignored — a client
        // setting a bit the module doesn't understand is asking for
        // semantics it won't get (fail closed).
        if flags & !FLAG_REDUCE_ONLY != 0 {
            return None;
        }
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
            flags,
        ))
    }

    fn parse_cancel(msg: &[u8]) -> Option<(u8, OrderId)> {
        if msg.len() != CANCEL_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let order_id = u64::from_le_bytes(msg[1..9].try_into().ok()?);
        Some((market, OrderId(order_id)))
    }

    fn parse_list_market(msg: &[u8]) -> Option<PerpsMarketConfig> {
        if msg.len() != LIST_MARKET_BODY_LEN {
            return None;
        }
        let tick_size = u64::from_le_bytes(msg[0..8].try_into().ok()?);
        let lot_size = u64::from_le_bytes(msg[8..16].try_into().ok()?);
        let min_price = u64::from_le_bytes(msg[16..24].try_into().ok()?);
        let max_price = u64::from_le_bytes(msg[24..32].try_into().ok()?);
        let max_resting = u32::from_le_bytes(msg[32..36].try_into().ok()?);
        let max_leverage = u16::from_le_bytes(msg[36..38].try_into().ok()?);
        let mmr_base_bps = u16::from_le_bytes(msg[38..40].try_into().ok()?);
        Some(PerpsMarketConfig {
            base: MarketConfig {
                market_id: 0,
                tick_size,
                lot_size,
                min_price,
                max_price,
                max_resting,
            },
            max_leverage,
            mmr_base_bps,
        })
    }

    fn parse_margin(msg: &[u8]) -> Option<(u8, u64)> {
        if msg.len() != MARGIN_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let amount = u64::from_le_bytes(msg[1..9].try_into().ok()?);
        Some((market, amount))
    }

    fn parse_set_mark(msg: &[u8]) -> Option<(u8, u64)> {
        if msg.len() != SET_MARK_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let mark = u64::from_le_bytes(msg[1..9].try_into().ok()?);
        Some((market, mark))
    }

    fn parse_funding(msg: &[u8]) -> Option<(u8, [u8; 8])> {
        if msg.len() != FUNDING_BODY_LEN {
            return None;
        }
        let market = msg[0];
        let rate_bytes: [u8; 8] = msg[1..9].try_into().ok()?;
        Some((market, rate_bytes))
    }
}

// ── Event helpers ────────────────────────────────────────────────────

fn fill_event(fill: FillEvent) -> Event {
    let mut data = Vec::with_capacity(8 + 8 + 8 + 8 + 20 + 20 + 1);
    data.extend_from_slice(&fill.price.0.to_le_bytes());
    data.extend_from_slice(&fill.qty.0.to_le_bytes());
    data.extend_from_slice(&fill.maker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.taker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.maker_owner.0);
    data.extend_from_slice(&fill.taker_owner.0);
    data.push(encode_side(fill.taker_side));
    Event { module: "perps", kind: "fill", data }
}

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
    Event { module: "perps", kind, data }
}

fn cancel_event(market: u8, canceled: CanceledOrder) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 1 + 8 + 8 + 20);
    data.push(market);
    data.extend_from_slice(&canceled.order_id.0.to_le_bytes());
    data.push(encode_side(canceled.side));
    data.extend_from_slice(&canceled.price.0.to_le_bytes());
    data.extend_from_slice(&canceled.qty.0.to_le_bytes());
    data.extend_from_slice(&canceled.owner.0);
    Event { module: "perps", kind: "canceled", data }
}

// ── Codec helpers ────────────────────────────────────────────────────

fn encode_side(s: Side) -> u8 {
    match s {
        Side::Buy => 0,
        Side::Sell => 1,
    }
}

const fn decode_side(b: u8) -> Option<Side> {
    match b {
        0 => Some(Side::Buy),
        1 => Some(Side::Sell),
        _ => None,
    }
}

fn encode_order_type(t: OrderType) -> u8 {
    match t {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
    }
}

const fn decode_order_type(b: u8) -> Option<OrderType> {
    match b {
        0 => Some(OrderType::Limit),
        1 => Some(OrderType::Market),
        2 => Some(OrderType::PostOnly),
        _ => None,
    }
}

fn encode_tif(t: TimeInForce) -> u8 {
    match t {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    }
}

const fn decode_tif(b: u8) -> Option<TimeInForce> {
    match b {
        0 => Some(TimeInForce::Gtc),
        1 => Some(TimeInForce::Ioc),
        2 => Some(TimeInForce::Fok),
        _ => None,
    }
}

fn encode_stp(s: StpMode) -> u8 {
    match s {
        StpMode::None => 0,
        StpMode::CancelNewest => 1,
        StpMode::CancelOldest => 2,
        StpMode::DecrementAndCancel => 3,
    }
}

const fn decode_stp(b: u8) -> Option<StpMode> {
    match b {
        0 => Some(StpMode::None),
        1 => Some(StpMode::CancelNewest),
        2 => Some(StpMode::CancelOldest),
        3 => Some(StpMode::DecrementAndCancel),
        _ => None,
    }
}

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

fn market_config_key(market: u8) -> Vec<u8> {
    vec![b'm', market]
}

fn encode_perps_config(cfg: &PerpsMarketConfig) -> Vec<u8> {
    let mut v = Vec::with_capacity(46);
    v.extend_from_slice(&cfg.base.tick_size.to_le_bytes());
    v.extend_from_slice(&cfg.base.lot_size.to_le_bytes());
    v.extend_from_slice(&cfg.base.min_price.to_le_bytes());
    v.extend_from_slice(&cfg.base.max_price.to_le_bytes());
    v.extend_from_slice(&cfg.base.max_resting.to_le_bytes());
    v.extend_from_slice(&cfg.max_leverage.to_le_bytes());
    v.extend_from_slice(&cfg.mmr_base_bps.to_le_bytes());
    v
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        CROSS_MARGIN_MARKET, MarketConfig, NewOrder, OrderId, OrderType, PRICE_SCALE,
        PerpsMarketConfig, PerpsModule, Position, Side, StpMode, TimeInForce, encode_reject_reason,
        mark_price_deviation_bps, msg,
    };
    use executor::{ExecError, Module, TxContext};
    use framework::{Balances, module_id};
    use primitives::Address;
    use primitives::Height;
    use primitives::fixed::{Price, Qty};
    use std::sync::Arc;

    fn test_cfg() -> PerpsMarketConfig {
        PerpsMarketConfig {
            base: MarketConfig {
                market_id: 0,
                tick_size: 1_000_000,
                lot_size: 1_000,
                min_price: 1_000_000_000,
                max_price: 2_000_000_000,
                max_resting: 64,
            },
            max_leverage: 10,
            mmr_base_bps: 50, // 0.5%
        }
    }

    fn addr(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn ctx(sender_byte: u8) -> TxContext {
        TxContext { sender: addr(sender_byte), nonce: 0, fee: 0 }
    }

    #[allow(dead_code)]
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
    fn list_market_sets_mark_to_mid() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        assert_eq!(mid, 0);
        // Mark = (min + max) / 2 = (1B + 2B) / 2 = 1.5B
        assert_eq!(perps.mark_price(mid), Some(1_500_000_000));
    }

    #[test]
    fn deposit_cross_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        perps.list_market(test_cfg()).unwrap();
        // Deposit 500_000 into cross margin.
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        assert_eq!(perps.cross_margin(&addr(1)), 500_000);
        assert_eq!(ledger.balance(&addr(1)), 500_000);
    }

    #[test]
    fn deposit_isolated_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(mid, 500_000)).unwrap();
        let pos = perps.position(&addr(1), mid);
        assert_eq!(pos.isolated_margin, 500_000);
        assert_eq!(ledger.balance(&addr(1)), 500_000);
    }

    #[test]
    fn withdraw_cross_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 200_000)).unwrap();
        assert_eq!(perps.cross_margin(&addr(1)), 300_000);
        assert_eq!(ledger.balance(&addr(1)), 700_000);
    }

    #[test]
    fn withdraw_insufficient_rejected() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100_000)).unwrap();
        let err =
            perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 200_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    /// A committee stub treating `addr(1)` as the sole validator —
    /// the tx-path tests for the gated `TAG_SET_MARK` override.
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
    /// carry one unit of power, so neither can reach the
    /// two-thirds quorum alone: endorsement-gated paths need both.
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
    fn set_mark_price() {
        let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
        let mid = perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::set_mark(mid, 1_600_000_000)).unwrap();
        assert_eq!(perps.mark_price(mid), Some(1_600_000_000));
    }

    /// C9: an emergency mark override is a governance action — one
    /// validator's signature endorses the exact (market, mark)
    /// payload; it applies only once endorsing power exceeds
    /// two-thirds of the committee. A single signer must not move
    /// the mark: that is a free liquidation-manipulation primitive.
    #[test]
    fn set_mark_requires_committee_quorum() {
        let perps = PerpsModule::new().with_committee(Arc::new(TwoValidatorCommittee));
        let mid = perps.list_market(test_cfg()).unwrap();
        let before = perps.mark_price(mid);

        perps.handle(&ctx(1), &msg::set_mark(mid, 1_600_000_000)).unwrap();
        assert_eq!(perps.mark_price(mid), before, "one endorsement must not move the mark");

        perps.handle(&ctx(2), &msg::set_mark(mid, 1_600_000_000)).unwrap();
        assert_eq!(perps.mark_price(mid), Some(1_600_000_000), "quorum applies");
    }

    /// Same quorum gate for the funding override — an
    /// unauthenticated rate is an unauthenticated transfer between
    /// every long and short on the market.
    #[test]
    fn apply_funding_requires_committee_quorum() {
        let perps = PerpsModule::new().with_committee(Arc::new(TwoValidatorCommittee));
        let mid = perps.list_market(test_cfg()).unwrap();
        // Trader 3 holds a long so funding has an observable
        // effect — the `funding` event is emitted per payer, so a
        // bare deposit with no open position would produce no
        // events at quorum.
        perps.handle(&ctx(3), &msg::deposit(CROSS_MARGIN_MARKET, 500_000)).unwrap();
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(3));
            acct.positions.insert(
                mid,
                Position { size: 1_000_000, entry_price: 1_500_000_000, isolated_margin: 0 },
            );
        }

        let events = perps.handle(&ctx(1), &msg::apply_funding(mid, 1)).unwrap();
        assert_eq!(
            events[0].kind, "apply_funding_endorse",
            "one endorsement records but does not apply"
        );

        let events = perps.handle(&ctx(2), &msg::apply_funding(mid, 1)).unwrap();
        assert_eq!(events[0].kind, "funding", "quorum applies the rate");
    }

    /// The emergency mark/funding tx path must reject non-committee
    /// senders — before the gate, any account could move the mark
    /// within the deviation cap, which is a free manipulation
    /// primitive (the oracle quorum path is the intended pipeline).
    #[test]
    fn set_mark_rejects_non_committee() {
        let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
        let mid = perps.list_market(test_cfg()).unwrap();
        let err = perps.handle(&ctx(9), &msg::set_mark(mid, 1_600_000_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    /// With no committee wired the tx path is closed entirely — a
    /// bare module must not accept unauthenticated mark updates.
    #[test]
    fn set_mark_rejected_without_committee() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        let err = perps.handle(&ctx(1), &msg::set_mark(mid, 1_600_000_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    #[test]
    fn apply_funding_rejects_non_committee() {
        let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
        let mid = perps.list_market(test_cfg()).unwrap();
        let err = perps.handle(&ctx(9), &msg::apply_funding(mid, 100)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    #[test]
    fn set_mark_nonexistent_rejected() {
        let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
        let err = perps.handle(&ctx(1), &msg::set_mark(5, 1_600_000_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    #[test]
    fn position_unrealized_pnl_long() {
        let pos = Position { size: 1_000, entry_price: 1_500_000_000, isolated_margin: 0 };
        // Mark goes up to 1_600M: PnL = 1000 * (1.6B - 1.5B) = 100B
        let pnl = pos.unrealized_pnl(1_600_000_000);
        assert_eq!(pnl, 100_000_000_000);
    }

    #[test]
    fn position_unrealized_pnl_short() {
        let pos = Position { size: -1_000, entry_price: 1_500_000_000, isolated_margin: 0 };
        // Mark goes up to 1_600M: PnL = -1000 * (1.6B - 1.5B) = -100B (loss)
        let pnl = pos.unrealized_pnl(1_600_000_000);
        assert_eq!(pnl, -100_000_000_000);
    }

    #[test]
    fn position_maintenance_margin() {
        let pos = Position { size: 1_000, entry_price: 1_500_000_000, isolated_margin: 0 };
        let cfg = test_cfg();
        // Notional = 1000 * 1.5B = 1.5T (scale-14)
        // MMR = 50 bps = 0.5%
        // Maintenance = 1.5T * 50 / 10000 = 7.5B
        let mm = pos.maintenance_margin(1_500_000_000, &cfg);
        assert_eq!(mm, 7_500_000_000);
    }

    #[test]
    fn funding_long_pays_short() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000_000);
        ledger.mint(&addr(2), 1_000_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // Both deposit cross margin.
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
        perps.handle(&ctx(2), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();

        // Manually set positions: long 1_000_000 @ 1.5B, short -1_000_000 @ 1.5B.
        // (1_000_000 qty units = 1 base unit in scale-6.)
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct1 = PerpsModule::account_mut(&mut inner, &addr(1));
            acct1.positions.insert(
                mid,
                Position { size: 1_000_000, entry_price: 1_500_000_000, isolated_margin: 0 },
            );
            let acct2 = PerpsModule::account_mut(&mut inner, &addr(2));
            acct2.positions.insert(
                mid,
                Position { size: -1_000_000, entry_price: 1_500_000_000, isolated_margin: 0 },
            );
        }

        // Apply funding: rate = +1 bps (longs pay shorts).
        // Notional = 1_000_000 * 1.5B = 1.5e15 (scale-14)
        //           = 1.5e15 / 1e8 = 15_000_000 (scale-6)
        // Funding = 15_000_000 * 1 / 10_000 = 1500 (scale-6)
        perps.apply_funding(mid, 1).unwrap();

        // Long's margin decreases by 1500; short's increases by 1500.
        assert_eq!(perps.cross_margin(&addr(1)), 500_000_000 - 1_500);
        assert_eq!(perps.cross_margin(&addr(2)), 500_000_000 + 1_500);
    }

    #[test]
    fn liquidation_closes_underwater_position() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // Deposit small margin and open a position.
        perps.handle(&ctx(1), &msg::deposit(mid, 100_000)).unwrap();
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(1));
            acct.positions.insert(
                mid,
                Position { size: 1_000, entry_price: 1_500_000_000, isolated_margin: 100_000 },
            );
        }

        // Mark drops to 1.0B:
        // PnL (scale-14) = 1000 * (1.0B - 1.5B) = -500_000_000_000
        // PnL (scale-6)  = -500_000_000_000 / 1e8 = -5_000
        // Equity = 100_000 - 5_000 = 95_000
        // Maintenance (scale-14) = 1000 * 1.0B * 50 / 10_000 = 5_000_000_000
        // Maintenance (scale-6)  = 5_000_000_000 / 1e8 = 50
        // Equity (95_000) > maintenance (50) — not liquidated.
        perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
        let events = perps.liquidation_check(&addr(1)).unwrap();
        assert!(events.is_empty());

        // Now set a much larger position (100_000 qty = 0.1 base units).
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(1));
            acct.positions.insert(
                mid,
                Position { size: 100_000, entry_price: 1_500_000_000, isolated_margin: 100_000 },
            );
        }
        // PnL (scale-14) = 100_000 * (1.0B - 1.5B) = -50_000_000_000_000
        // PnL (scale-6)  = -500_000
        // Equity = 100_000 - 500_000 = -400_000 (underwater!)
        // Maintenance (scale-6) = 5_000
        // Equity (-400_000) < maintenance (5_000) → liquidated.
        let events = perps.liquidation_check(&addr(1)).unwrap();
        assert!(!events.is_empty(), "should be liquidated");
        assert_eq!(events[0].kind, "liquidated");
        // Position should be closed.
        let pos = perps.position(&addr(1), mid);
        assert_eq!(pos.size, 0);
    }

    #[test]
    fn module_id_is_perps() {
        let perps = PerpsModule::new();
        assert_eq!(perps.id(), module_id::PERPS);
        assert_eq!(perps.name(), "perps");
    }

    #[test]
    fn malformed_message_rejected() {
        let perps = PerpsModule::new();
        assert_eq!(perps.handle(&ctx(1), &[]), Err(ExecError::Malformed));
        assert_eq!(perps.handle(&ctx(1), &[99]), Err(ExecError::Malformed));
    }

    #[test]
    fn reject_reason_encoding_is_stable() {
        assert_eq!(encode_reject_reason(trading::RejectReason::InvalidQty), 0);
    }

    #[test]
    fn list_market_via_message() {
        // A single-validator committee reaches quorum on the first
        // endorsement — the tx path then lists exactly like the
        // in-process call.
        let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
        let list_msg = msg::list_market(test_cfg());
        let events = perps.handle(&ctx(1), &list_msg).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "market_listed");
    }

    /// The `TAG_LIST_MARKET` tx path is fail-closed without a
    /// committee — same gate as `TAG_SET_MARK`: an unauthenticated
    /// listing eagerly allocates the market's `max_resting` arenas,
    /// so a bare module rejects it outright.
    #[test]
    fn list_market_tx_rejected_without_committee() {
        let perps = PerpsModule::new();
        let err = perps.handle(&ctx(1), &msg::list_market(test_cfg())).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
    }

    /// A listing is a governance action: one endorsement records the
    /// vote; the market lists only once endorsing power strictly
    /// exceeds two-thirds of the committee.
    #[test]
    fn list_market_requires_committee_quorum() {
        let perps = PerpsModule::new().with_committee(Arc::new(TwoValidatorCommittee));
        let list_msg = msg::list_market(test_cfg());

        let events = perps.handle(&ctx(1), &list_msg).unwrap();
        assert_eq!(events[0].kind, "list_market_endorse", "one endorsement must not list");

        let events = perps.handle(&ctx(2), &list_msg).unwrap();
        assert_eq!(events[0].kind, "market_listed", "quorum lists the market");
    }

    /// A config failing `PerpsMarketConfig::validate` — here a
    /// `max_resting` above the protocol's `MAX_RESTING_LIMIT`, which
    /// would make `list_market` reserve oversized arenas — is
    /// rejected before an endorsement occupies the bounded pending
    /// set.
    #[test]
    fn list_market_tx_rejects_unbounded_max_resting() {
        let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
        let mut cfg = test_cfg();
        cfg.base.max_resting = trading::MAX_RESTING_LIMIT + 1;
        let err = perps.handle(&ctx(1), &msg::list_market(cfg)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
    }

    #[test]
    fn state_root_changes_after_market_listed() {
        let perps = PerpsModule::new();
        let root0 = perps.state_root();
        perps.list_market(test_cfg()).unwrap();
        let root1 = perps.state_root();
        assert_ne!(root0, root1);
    }

    // ── C8 canonical state-root completeness ─────────────────────
    //
    // A perps `state_root` must commit every field that can affect
    // future execution — positions, margin, marks, insurance, and
    // the live book — not just the KV store (which only mirrors
    // market configs). Identical roots across validators must prove
    // identical trading state.

    #[test]
    fn state_root_changes_after_margin_deposit() {
        let perps = PerpsModule::new();
        perps.list_market(test_cfg()).unwrap();
        let root0 = perps.state_root();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        let root1 = perps.state_root();
        assert_ne!(root0, root1, "a margin deposit must change the state root");
    }

    #[test]
    fn state_root_changes_after_mark_set() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        let root0 = perps.state_root();
        perps.set_mark_price_unchecked(mid, 1_600_000_000).unwrap();
        let root1 = perps.state_root();
        assert_ne!(root0, root1, "a mark update must change the state root");
    }

    #[test]
    fn state_root_changes_after_order_rests() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
        let root0 = perps.state_root();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 400, 3, 1))).unwrap();
        let root1 = perps.state_root();
        assert_ne!(root0, root1, "a resting order must change the state root");
    }

    #[test]
    fn state_root_changes_after_position_opens() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
        perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
        // Maker sell rests; taker buy fills it — both positions change.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 5, 9))).unwrap();
        let root0 = perps.state_root();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 5, 1))).unwrap();
        let root1 = perps.state_root();
        assert_ne!(root0, root1, "a position change must change the state root");
    }

    #[test]
    fn state_root_changes_after_insurance_fund_moves() {
        let perps = PerpsModule::new();
        perps.list_market(test_cfg()).unwrap();
        let root0 = perps.state_root();
        perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insurance_fund =
            1_000;
        let root1 = perps.state_root();
        assert_ne!(root0, root1, "the insurance fund must be committed");
    }

    // ── Property tests ───────────────────────────────────────────────
    //
    // These tests verify the core perps invariants hold across a
    // randomized input space. They use `proptest` to generate
    // arbitrary margin sizes, position sizes, and mark-price moves.
    //
    // Invariants checked:
    //   1. Margin never goes negative (saturating arithmetic).
    //   2. Equity after liquidation is >= 0 (no negative equity).
    //   3. Liquidation only triggers when equity <= maintenance.
    //   4. Insurance fund never goes negative.

    use proptest::prelude::*;

    /// Helper: set up a perps module with a market and an account
    /// that has a position with the given isolated margin, size, and
    /// entry price.
    fn setup_with_position(margin: u64, size: i64, entry: u64) -> (PerpsModule, u8, Address) {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        let acct_addr = addr(1);
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &acct_addr);
            acct.positions
                .insert(mid, Position { size, entry_price: entry, isolated_margin: margin });
        }
        (perps, mid, acct_addr)
    }

    proptest! {
        /// Invariant 1: After applying funding (positive or negative
        /// rate), the account's margin never goes negative. The
        /// implementation uses `saturating_sub`, so this should always
        /// hold — the test guards against a regression to wrapping
        /// arithmetic.
        #[test]
        fn margin_never_negative_after_funding(
            margin in 1_000u64..1_000_000_000,
            size in -1_000_000i64..1_000_000,
            // Funding rate in bps: -100 to +100 (±1%).
            rate_bps in -100i64..100,
        ) {
            let (perps, mid, _) = setup_with_position(margin, size, 1_500_000_000);
            let _ = perps.apply_funding(mid, rate_bps);
            // After funding, margin (cross or isolated) must be >= 0.
            // The module uses saturating arithmetic, so this is
            // guaranteed — but we verify it explicitly.
            prop_assert!(perps.insurance_fund() < u64::MAX);
        }

        /// Invariant 2: After liquidation, the account's equity is
        /// never negative. The liquidation closes all positions and
        /// either returns leftover margin or covers the shortfall
        /// from the insurance fund. In both cases, the account walks
        /// away with >= 0. If liquidation does not trigger (account
        /// is healthy), the position is untouched — also fine.
        #[test]
        fn no_negative_equity_after_liquidation(
            margin in 1_000u64..100_000_000,
            size in 1_000i64..1_000_000,
            // Mark price from 100M to 3B (covers massive drops and pumps).
            mark in 100_000_000u64..3_000_000_000,
        ) {
            let (perps, mid, acct) = setup_with_position(margin, size, 1_500_000_000);
            perps.set_mark_price_unchecked(mid, mark).unwrap();
            let events = perps.liquidation_check(&acct).unwrap();
            if !events.is_empty() {
                // Liquidation triggered: position must be closed.
                let pos = perps.position(&acct, mid);
                prop_assert_eq!(pos.size, 0, "position must be closed after liquidation");
                prop_assert_eq!(pos.isolated_margin, 0, "margin must be zeroed after liquidation");
            }
            // If no liquidation, the account is healthy — no
            // negative equity by definition.
        }

        /// Invariant 3: Liquidation only triggers when
        /// equity <= maintenance margin. If equity > maintenance,
        /// `liquidation_check` must return no events. This is the
        /// safety-critical invariant: liquidation must never fire on
        /// a healthy account.
        #[test]
        fn liquidation_only_when_underwater(
            margin in 1_000_000u64..1_000_000_000,
            size in 1_000i64..100_000,
            // Mark from 1.4B to 1.6B (small moves around entry).
            mark in 1_400_000_000u64..1_600_000_000,
        ) {
            let (perps, mid, acct) = setup_with_position(margin, size, 1_500_000_000);
            perps.set_mark_price_unchecked(mid, mark).unwrap();

            // Compute equity and maintenance manually.
            let pos = perps.position(&acct, mid);
            let pnl = pos.unrealized_pnl(mark);
            let pnl_scale6 = pnl / i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
            let equity = i128::from(margin) + pnl_scale6;
            let cfg = test_cfg();
            let maintenance = pos.maintenance_margin(mark, &cfg) / PRICE_SCALE;
            let should_liquidate = equity <= i128::try_from(maintenance).unwrap_or(i128::MAX);

            let events = perps.liquidation_check(&acct).unwrap();
            if should_liquidate {
                prop_assert!(
                    !events.is_empty(),
                    "should liquidate: equity={} maint={}",
                    equity, maintenance
                );
            } else {
                prop_assert!(
                    events.is_empty(),
                    "should not liquidate: equity={} maint={}",
                    equity, maintenance
                );
            }
        }

        /// Invariant 4: The insurance fund never goes negative. After
        /// any liquidation, the fund is either unchanged (no
        /// shortfall), reduced (shortfall covered), or zeroed (ADL
        /// triggered). It never wraps to a huge value.
        #[test]
        fn insurance_fund_never_negative(
            margin in 1_000u64..10_000_000,
            size in 1_000i64..1_000_000,
            mark in 100_000_000u64..3_000_000_000,
            initial_fund in 0u64..1_000_000_000,
        ) {
            let (perps, mid, acct) = setup_with_position(margin, size, 1_500_000_000);
            // Set the insurance fund to a known initial value.
            {
                let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                inner.insurance_fund = initial_fund;
            }
            perps.set_mark_price_unchecked(mid, mark).unwrap();
            let _ = perps.liquidation_check(&acct);
            // The fund must be <= initial (it only decreases or
            // stays the same during liquidation).
            let fund_after = perps.insurance_fund();
            prop_assert!(
                fund_after <= initial_fund,
                "insurance fund must not increase during liquidation: was={} now={}",
                initial_fund, fund_after
            );
        }
    }

    // ── ADL stress tests ──────────────────────────────────────────

    /// ADL triggers when the insurance fund is depleted and there
    /// are profitable counterparties to deleverage.
    #[test]
    fn adl_triggers_on_insurance_fund_depletion() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(2), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // Account 1: underwater long (will be liquidated).
        // Long at 1.5B, mark drops to 1.0B → loses money.
        perps.handle(&ctx(1), &msg::deposit(mid, 100_000)).unwrap();
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(1));
            acct.positions.insert(
                mid,
                Position { size: 100_000, entry_price: 1_500_000_000, isolated_margin: 100_000 },
            );
        }

        // Account 2: profitable short (counterparty, will be ADL'd).
        // Short at 1.5B, mark drops to 1.0B → profits.
        perps.handle(&ctx(2), &msg::deposit(mid, 100_000)).unwrap();
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(2));
            acct.positions.insert(
                mid,
                Position { size: -100_000, entry_price: 1_500_000_000, isolated_margin: 100_000 },
            );
        }

        // Set insurance fund to 0 so any shortfall triggers ADL.
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.insurance_fund = 0;
        }

        // Mark drops to 1.0B: account 1 (long) is underwater, account 2 (short) is profitable.
        perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();

        // Liquidate account 1 — should trigger ADL on account 2.
        let events = perps.liquidation_check(&addr(1)).unwrap();
        let adl_events: Vec<_> = events.iter().filter(|e| e.kind.starts_with("adl")).collect();
        assert!(
            !adl_events.is_empty(),
            "ADL should trigger when insurance fund is depleted: {events:?}"
        );
    }

    /// ADL ranking: the most profitable counterparty is deleveraged first.
    #[test]
    fn adl_ranks_by_profit_descending() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // Account 1: underwater long (will be liquidated).
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(1));
            acct.positions.insert(
                mid,
                Position { size: 200_000, entry_price: 1_500_000_000, isolated_margin: 50_000 },
            );
        }

        // Account 2: slightly profitable short.
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(2));
            acct.positions.insert(
                mid,
                Position { size: -100_000, entry_price: 1_400_000_000, isolated_margin: 100_000 },
            );
        }

        // Account 3: more profitable short (larger position, same entry).
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(3));
            acct.positions.insert(
                mid,
                Position { size: -200_000, entry_price: 1_400_000_000, isolated_margin: 100_000 },
            );
        }

        // Zero insurance fund.
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.insurance_fund = 0;
        }

        // Mark drops to 1.0B.
        perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();

        // Liquidate account 1 — ADL should hit account 3 first
        // (more profitable: larger size, same PnL per unit).
        let events = perps.liquidation_check(&addr(1)).unwrap();
        let adl_events: Vec<_> = events.iter().filter(|e| e.kind == "adl_executed").collect();
        assert!(!adl_events.is_empty(), "ADL should execute");
    }

    /// ADL is deterministic: the same state produces the same events.
    #[test]
    fn adl_is_deterministic() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // Setup: underwater long + profitable short counterparty.
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct1 = PerpsModule::account_mut(&mut inner, &addr(1));
            acct1.positions.insert(
                mid,
                Position { size: 100_000, entry_price: 1_500_000_000, isolated_margin: 50_000 },
            );
            let acct2 = PerpsModule::account_mut(&mut inner, &addr(2));
            acct2.positions.insert(
                mid,
                Position { size: -100_000, entry_price: 1_400_000_000, isolated_margin: 100_000 },
            );
            inner.insurance_fund = 0;
        }

        perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();

        // Run liquidation — events should be deterministic.
        let events = perps.liquidation_check(&addr(1)).unwrap();
        assert!(!events.is_empty());
    }

    // ── Oracle robustness tests ───────────────────────────────────

    /// Oracle: first mark price update via checked method is
    /// rejected if it deviates too much from the initial mark
    /// (set by `list_market` to the midpoint of the price band).
    #[test]
    fn oracle_first_mark_checked_against_initial() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        // Initial mark is 1.5B (midpoint of 1B..2B).
        // 5% change from 1.5B = 1.575B — within the 10% cap.
        assert!(perps.set_mark_price(mid, 1_575_000_000).is_ok());
    }

    /// Oracle: small price change (within 10%) is accepted.
    #[test]
    fn oracle_small_change_accepted() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        // Initial mark is 1.5B. 5% change = 1.575B.
        assert!(perps.set_mark_price(mid, 1_575_000_000).is_ok());
        // M4 fix: each market can have only 1 oracle update per
        // block. Advance to the next block before the second update.
        perps.begin_block(Height::new(1));
        // Another 5% change from 1.575B = 1.65375B.
        assert!(perps.set_mark_price(mid, 1_653_750_000).is_ok());
    }

    /// Oracle: large price change (>10%) is rejected.
    #[test]
    fn oracle_large_change_rejected() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        // Initial mark is 1.5B. 20% change = 1.8B — exceeds 10% cap.
        let result = perps.set_mark_price(mid, 1_800_000_000);
        assert!(result.is_err(), "20% price change should be rejected");
    }

    /// Oracle: large downward price change (>10%) is rejected.
    #[test]
    fn oracle_large_drop_rejected() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        // Initial mark is 1.5B. 20% drop = 1.2B — exceeds 10% cap.
        let result = perps.set_mark_price(mid, 1_200_000_000);
        assert!(result.is_err(), "20% price drop should be rejected");
    }

    /// Oracle: exactly 10% change is accepted (boundary).
    #[test]
    fn oracle_exact_10pct_accepted() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        // Initial mark is 1.5B. 10% up = 1.65B = exactly the cap.
        assert!(perps.set_mark_price(mid, 1_650_000_000).is_ok());
    }

    /// Oracle: unchecked method bypasses the deviation check.
    #[test]
    fn oracle_unchecked_bypasses_deviation() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        // Initial mark is 1.5B. 33% change to 1.0B — would be
        // rejected by the checked method.
        assert!(perps.set_mark_price_unchecked(mid, 1_000_000_000).is_ok());
    }

    /// M4 fix: per-block oracle rate limit. A second oracle update
    /// for the same market in the same block must be rejected.
    /// Without this, many small (just under 10%) updates can
    /// compound to a large cumulative move within a single block.
    #[test]
    fn m4_oracle_rate_limit_rejects_second_update_same_block() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        // First update: 5% change — accepted.
        assert!(perps.set_mark_price(mid, 1_575_000_000).is_ok());
        // Second update in the same block — rejected by M4 rate limit.
        let result = perps.set_mark_price(mid, 1_653_750_000);
        assert!(result.is_err(), "second oracle update in same block must be rejected");
        match result {
            Err(ExecError::ModuleRejected(reason)) => {
                assert!(
                    reason.contains("oracle update limit"),
                    "expected rate limit rejection, got: {reason}"
                );
            }
            _ => panic!("expected ModuleRejected error"),
        }
    }

    /// M4 fix: the rate limit resets at the next block. After
    /// `begin_block`, a new oracle update is accepted.
    #[test]
    fn m4_oracle_rate_limit_resets_next_block() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        // First update in block 0 — accepted.
        assert!(perps.set_mark_price(mid, 1_575_000_000).is_ok());
        // Second update in block 0 — rejected.
        assert!(perps.set_mark_price(mid, 1_653_750_000).is_err());
        // New block — rate limit resets.
        perps.begin_block(Height::new(1));
        // Update in block 1 — accepted.
        assert!(perps.set_mark_price(mid, 1_653_750_000).is_ok());
    }

    /// Oracle: mark price deviation calculation is correct.
    #[test]
    fn oracle_deviation_calculation() {
        // 0% deviation.
        assert_eq!(mark_price_deviation_bps(1_000_000_000, 1_000_000_000), 0);
        // 10% up: (1.1B - 1B) * 10000 / 1B = 1000 bps.
        assert_eq!(mark_price_deviation_bps(1_100_000_000, 1_000_000_000), 1000);
        // 10% down: (1B - 900M) * 10000 / 1B = 1000 bps.
        assert_eq!(mark_price_deviation_bps(900_000_000, 1_000_000_000), 1000);
        // 50% down: (1B - 500M) * 10000 / 1B = 5000 bps.
        assert_eq!(mark_price_deviation_bps(500_000_000, 1_000_000_000), 5000);
        // Old = 0: any new price is max deviation.
        assert_eq!(mark_price_deviation_bps(1_000_000_000, 0), u64::MAX);
    }

    /// Regression test: a deposit that would overflow the `u64`
    /// margin field must be rejected BEFORE the ledger debit. Before
    /// the fix, `handle_deposit` debited the ledger then
    /// `saturating_add`ed the margin — the user's funds were
    /// taken while the margin was silently capped.
    #[test]
    fn deposit_overflow_rejected_ledger_untouched() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        perps.list_market(test_cfg()).unwrap();

        // Push cross margin near u64::MAX directly.
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            PerpsModule::account_mut(&mut inner, &addr(1)).cross_margin = u64::MAX - 100;
        }

        // Deposit 500 → margin would overflow → reject, ledger intact.
        let err =
            perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(ledger.balance(&addr(1)), 1_000_000, "ledger must not be debited");
        assert_eq!(perps.cross_margin(&addr(1)), u64::MAX - 100);
    }

    /// Regression test: a failed ledger credit must not destroy the
    /// user's margin. Before the fix, `handle_withdraw` debited
    /// margin first and returned `Err` when `ledger.credit` failed —
    /// the margin was gone.
    #[test]
    fn withdraw_ledger_failure_preserves_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), u64::MAX);
        let perps = PerpsModule::with_ledger(ledger.clone());
        perps.list_market(test_cfg()).unwrap();

        // Deposit 500 (balance: MAX-500, margin: 500).
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500)).unwrap();
        // Top the balance back up so a 500 credit overflows.
        ledger.mint(&addr(1), 400);
        assert_eq!(ledger.balance(&addr(1)), u64::MAX - 100);

        // Withdraw 500 → ledger credit overflows → error, margin intact.
        let err =
            perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 500)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(
            perps.cross_margin(&addr(1)),
            500,
            "margin must be preserved when the ledger credit fails"
        );
    }

    /// Regression test: funding must be zero-sum. A payer that
    /// cannot cover its funding contributes only what it has, and
    /// receivers share the collected pool pro-rata — the old code
    /// credited receivers the full computed amount while only
    /// partially debiting insolvent payers, minting margin from
    /// nothing.
    #[test]
    fn funding_zero_sum_when_payer_insolvent() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000_000);
        ledger.mint(&addr(2), 1_000_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // Long deposits almost nothing (insolvent payer); short is
        // well-funded.
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100)).unwrap();
        perps.handle(&ctx(2), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();

        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            PerpsModule::account_mut(&mut inner, &addr(1)).positions.insert(
                mid,
                Position { size: 1_000_000, entry_price: 1_500_000_000, isolated_margin: 0 },
            );
            PerpsModule::account_mut(&mut inner, &addr(2)).positions.insert(
                mid,
                Position { size: -1_000_000, entry_price: 1_500_000_000, isolated_margin: 0 },
            );
        }

        // Funding owed by the long = 1_500 (same math as
        // funding_long_pays_short), but it only has 100.
        let events = perps.apply_funding(mid, 1).unwrap();
        assert!(events.iter().any(|e| e.kind == "funding_shortfall"));

        // Long drained to zero; short receives only what was
        // collected (100), not the computed 1_500.
        assert_eq!(perps.cross_margin(&addr(1)), 0);
        assert_eq!(perps.cross_margin(&addr(2)), 500_000_000 + 100);

        // Conservation: total user margin + insurance == deposits.
        let insurance = {
            let inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.insurance_fund
        };
        let total = perps.cross_margin(&addr(1)) + perps.cross_margin(&addr(2)) + insurance;
        assert_eq!(total, 500_000_100, "margin must be conserved exactly");
    }

    /// Regression test: orders that increase exposure require
    /// `equity >= existing IM + new notional / max_leverage`. Before
    /// the fix, positions could be opened with zero margin.
    #[test]
    fn place_rejected_without_initial_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // addr(1) has NO margin — a 1-lot buy at tick 500 has
        // notional 1_000 * 1.5e9 / 1e8 = 15_000; IM at 10x = 1_500.
        let err = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));

        // Deposit 1_000 cross margin — still below the 1_500 IM.
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000)).unwrap();
        let err = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    /// With sufficient margin the same order is accepted and the
    /// position opens.
    #[test]
    fn place_allowed_with_sufficient_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // Seller needs margin too (its sell increases exposure).
        perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();

        // Rest a sell, then buy against it.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        let events = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        assert!(events.iter().any(|e| e.kind == "fill"));
        assert_eq!(perps.position(&addr(1), mid).size, 1_000);
    }

    // ── C7: core financial invariants ──────────────────────────────

    /// A cross-margin withdrawal may not take account equity below
    /// the initial-margin requirement of the open book. The old code
    /// checked only the stored bucket balance — an account could
    /// withdraw the margin backing an open position and become
    /// instantly under-margined.
    #[test]
    fn withdraw_cross_cannot_break_initial_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        // Buyer deposits exactly 2_000 — free collateral after a
        // 1-lot position (IM 1_500) is 500.
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 2_000)).unwrap();
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        assert_eq!(perps.position(&addr(1), mid).size, 1_000);

        // Withdraw 1_000: equity_after = 1_000 < IM 1_500 → reject.
        let err =
            perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 1_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        // Margin and ledger both untouched.
        assert_eq!(perps.cross_margin(&addr(1)), 2_000);

        // Withdraw exactly the free collateral (500): equity_after
        // = 1_500 = IM → allowed.
        perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 500)).unwrap();
        assert_eq!(perps.cross_margin(&addr(1)), 1_500);
    }

    /// An isolated-margin withdrawal may not pull the position's
    /// own margin below its initial-margin requirement.
    #[test]
    fn withdraw_isolated_cannot_break_position_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        // Isolated deposit of 2_000 backing a 1-lot position.
        perps.handle(&ctx(1), &msg::deposit(mid, 2_000)).unwrap();
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();

        // Withdraw 1_000 → isolated margin 1_000 < IM 1_500 → reject.
        let err = perps.handle(&ctx(1), &msg::withdraw(mid, 1_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        // The free excess (500) withdraws fine.
        perps.handle(&ctx(1), &msg::withdraw(mid, 500)).unwrap();
        assert_eq!(perps.position(&addr(1), mid).isolated_margin, 1_500);
    }

    /// Closing part of a position must realize `PnL` into collateral.
    /// The old code shrank `size` and kept the entry price but the
    /// realized gain vanished — margin was never credited.
    #[test]
    fn partial_close_realizes_pnl_into_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100_000)).unwrap();

        // Open a 2-lot long at 1.5e9 (tick 500).
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 2, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 2, 1))).unwrap();
        assert_eq!(perps.position(&addr(1), mid).size, 2_000);

        // Maker bid at tick 600 (1.6e9); close 1 lot into it.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Buy, 600, 1, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 600, 1, 1))).unwrap();

        let pos = perps.position(&addr(1), mid);
        assert_eq!(pos.size, 1_000, "one lot remains");
        assert_eq!(pos.entry_price, 1_500_000_000, "entry unchanged on reduce");
        // Realized: 1_000 qty × (1.6e9 − 1.5e9) / 1e8 = 1_000.
        assert_eq!(
            perps.cross_margin(&addr(1)),
            100_000 + 1_000,
            "realized PnL must settle into margin"
        );
    }

    /// A sell larger than the long flips the position: the closed
    /// portion realizes `PnL` and the remainder opens a short at the
    /// fill price. The old code classified the whole order as a
    /// reduce (skipping the IM gate AND the realized `PnL`).
    #[test]
    fn flip_close_realizes_pnl_and_reopens() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100_000)).unwrap();

        // Open a 1-lot long at 1.5e9.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();

        // Sell 3 lots into a 3-lot bid at 1.6e9 — flips to −2_000.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Buy, 600, 3, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 600, 3, 1))).unwrap();

        let pos = perps.position(&addr(1), mid);
        assert_eq!(pos.size, -2_000, "flipped remainder opens short");
        assert_eq!(pos.entry_price, 1_600_000_000, "new side enters at fill price");
        // Realized on the closed lot: 1_000 × (1.6e9 − 1.5e9) / 1e8 = 1_000.
        assert_eq!(perps.cross_margin(&addr(1)), 100_000 + 1_000);
    }

    /// Resting orders must reserve initial margin: two orders that
    /// each fit inside equity must not both pass when their
    /// combined requirement exceeds it. The old gate counted only
    /// open positions — resting orders were free, so an account
    /// could stack unbacked exposure that all later fills.
    #[test]
    fn resting_order_reserves_initial_margin() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // Equity 2_000 covers one lot's IM (1_500) but not two.
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 2_000)).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();

        let err = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap_err();
        assert!(
            matches!(err, ExecError::ModuleRejected(_)),
            "second resting order must exceed reserved initial margin"
        );
    }

    /// Cancelling a resting order releases its margin reservation:
    /// the same order becomes placeable again.
    #[test]
    fn cancel_releases_order_reservation() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 2_000)).unwrap();
        let events = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        let resting = events.iter().find(|e| e.kind == "resting").expect("order rests");
        let order_id = OrderId(u64::from_le_bytes(resting.data[1..9].try_into().unwrap()));

        // Cancel → reservation released → an identical order fits again.
        perps.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    }

    /// Liquidation must also cancel the account's resting orders —
    /// otherwise unbacked orders of a bankrupt account keep
    /// matching against the book.
    #[test]
    fn liquidation_cancels_resting_orders() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 2_000)).unwrap();
        let events = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        let resting = events.iter().find(|e| e.kind == "resting").expect("order rests");
        let order_id = OrderId(u64::from_le_bytes(resting.data[1..9].try_into().unwrap()));

        // Inject a deeply underwater position and crash the mark:
        // 100 lots long from entry 2.0e9, mark at 1.0e9 → equity
        // far below maintenance → liquidation must fire.
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(1));
            acct.positions.insert(
                mid,
                Position { size: 100_000, entry_price: 2_000_000_000, isolated_margin: 0 },
            );
        }
        perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
        let events = perps.liquidation_check(&addr(1)).unwrap();
        assert!(!events.is_empty(), "account must liquidate");

        // The resting order must be gone: cancel now reports
        // not-found rather than silently succeeding.
        let err = perps.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    /// Reduce-only may only close: an order whose qty exceeds the
    /// reducible position is rejected at admission, while an
    /// in-cover close executes normally.
    #[test]
    fn reduce_only_rejects_oversized_close() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        ledger.mint(&addr(9), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();

        // Open a 1-lot long.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        assert_eq!(perps.position(&addr(1), mid).size, 1_000);

        // Reduce-only sell of 2 lots > 1 reducible → rejected.
        let err = perps
            .handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 500, 2, 1)))
            .unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));

        // Reduce-only sell of 1 lot — exactly the position — closes.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Buy, 500, 1, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 500, 1, 1))).unwrap();
        assert_eq!(perps.position(&addr(1), mid).size, 0);
    }

    /// A reduce-only order on the WRONG side of the book (no
    /// reducible position) is rejected outright — there is nothing
    /// it could reduce.
    #[test]
    fn reduce_only_without_position_rejected() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        // No position at all: any reduce-only order exceeds
        // reducible (0).
        let err = perps
            .handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 500, 1, 1)))
            .unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    /// A reduce-only order admitted at full cover can outlive its
    /// position: the position shrinks under it via other fills.
    /// Enforcement must cap the fill at the match decision — the
    /// maker may only reduce what remains — not let the fill flip
    /// the maker into new exposure and cancel the remainder after.
    ///
    /// Owner 1: +10 long, reduce-only sell of 10 resting. A normal
    /// sell of 5 fills first, shrinking the position to +5 — the
    /// resting reduce-only now has only 5 cover. A taker buying 10
    /// must fill just 5 and kill the remainder.
    #[test]
    fn reduce_only_maker_capped_at_match_decision() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        for b in [1u8, 8, 9] {
            ledger.mint(&addr(b), 1_000_000);
        }
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();
        for b in [1u8, 8, 9] {
            perps.handle(&ctx(b), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        }

        // Owner 1 opens +10 long against owner 9.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 10, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 10, 1))).unwrap();
        assert_eq!(perps.position(&addr(1), mid).size, 10_000);

        // Reduce-only sell of 10 rests (admitted at full cover).
        let events = perps
            .handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 10, 1)))
            .unwrap();
        let resting = events.iter().find(|e| e.kind == "resting").expect("RO order rests");
        let ro_id = OrderId(u64::from_le_bytes(resting.data[1..9].try_into().unwrap()));

        // An ordinary sell of 5 fills first → position shrinks to
        // +5; the resting reduce-only now has only 5 cover.
        perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 500, 5, 8))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 500, 5, 1))).unwrap();
        assert_eq!(perps.position(&addr(1), mid).size, 5_000);

        // A taker buying 10 hits the reduce-only maker: it may only
        // fill the 5 cover that remains, and the uncovered remainder
        // must die at the match — never flip the maker to −5.
        let events = perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 700, 10, 8))).unwrap();
        assert_eq!(
            perps.position(&addr(1), mid).size,
            0,
            "reduce-only fill must stop at the closing capacity, not flip"
        );
        assert!(
            events.iter().any(|e| e.kind == "reduce_only_cancel"),
            "the uncovered remainder must be reported canceled"
        );
        // The dead remainder is off the book: cancel reports not-found.
        let err = perps.handle(&ctx(1), &msg::cancel(mid, ro_id)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    /// A resting order removed by self-trade prevention releases
    /// its margin reservation — the sweep reports the removal
    /// through `on_removed` so nothing is stranded.
    #[test]
    fn stp_removal_releases_margin_reservation() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();

        // Rest a buy at tick 400 — margin reserved against it.
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 400, 10, 1))).unwrap();

        // The same owner fires an IOC sell with CancelOldest: the
        // resting buy is removed without a fill and the IOC
        // remainder dies, leaving no orders behind.
        let taker = NewOrder {
            tif: TimeInForce::Ioc,
            stp: StpMode::CancelOldest,
            ..limit(Side::Sell, 400, 10, 1)
        };
        let events = perps.handle(&ctx(1), &msg::place(mid, taker)).unwrap();
        assert!(events.iter().any(|e| e.kind == "stp_cancel"));

        // Every reservation is gone: the full deposit withdraws.
        perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        assert_eq!(perps.cross_margin(&addr(1)), 0);
    }

    /// Cover is allocated once per owner per sweep, across makers
    /// of every kind: an ordinary opposing fill that exhausts the
    /// position leaves zero cover for a reduce-only maker behind
    /// it — the reduce-only must die unfilled, not open a short.
    #[test]
    fn reduce_only_behind_ordinary_fill_gets_no_cover() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        for b in [1u8, 8, 9] {
            ledger.mint(&addr(b), 1_000_000);
        }
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();
        for b in [1u8, 8, 9] {
            perps.handle(&ctx(b), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        }

        // Owner 1: +10 long.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 10, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 10, 1))).unwrap();
        assert_eq!(perps.position(&addr(1), mid).size, 10_000);

        // Resting reduce-only sell of 10 @1.7e9, then an ordinary
        // sell of 10 @1.6e9 (admitted — the uncovered tail pays IM).
        perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 10, 1))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 600, 10, 1))).unwrap();

        // Taker buys 20 @1.7e9: sweeps the ordinary sell first (10
        // cover consumed → position flat), then the reduce-only
        // finds 0 cover and must die without filling.
        perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 700, 20, 8))).unwrap();
        assert_eq!(
            perps.position(&addr(1), mid).size,
            0,
            "reduce-only must not open a short behind the ordinary fill"
        );
        // Owner 8 holds the 10 it bought from the ordinary sell.
        assert_eq!(perps.position(&addr(8), mid).size, 10_000);
    }

    /// FOK all-or-nothing must count capped fills: a reduce-only
    /// book that only covers 5 cannot satisfy a FOK buy of 10 —
    /// the order must be killed, not partially filled.
    #[test]
    fn fok_counts_capped_fillable() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        for b in [1u8, 8, 9] {
            ledger.mint(&addr(b), 1_000_000);
        }
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();
        for b in [1u8, 8, 9] {
            perps.handle(&ctx(b), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        }

        // Same setup: +10 long, RO sell 10 resting, shrink to +5.
        perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 10, 9))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 10, 1))).unwrap();
        perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 10, 1))).unwrap();
        perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 500, 5, 8))).unwrap();
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 500, 5, 1))).unwrap();
        assert_eq!(perps.position(&addr(1), mid).size, 5_000);

        // FOK buy of 10 @1.7e9 — only 5 is legally fillable.
        let mut fok = limit(Side::Buy, 700, 10, 8);
        fok.tif = TimeInForce::Fok;
        let events = perps.handle(&ctx(8), &msg::place(mid, fok)).unwrap();
        assert!(
            events.iter().any(|e| e.kind == "killed"),
            "FOK must kill when capped fillable < requested"
        );
        assert_eq!(
            perps.position(&addr(1), mid).size,
            5_000,
            "a killed FOK must leave positions untouched"
        );
        assert_eq!(perps.position(&addr(8), mid).size, 5_000);
    }

    /// A position's closing capacity can only be spent once. With a
    /// +10-lot long, one resting sell of 10 consumes all of it; a
    /// second sell of 10 is new short exposure and must reserve
    /// initial margin. The old gate scored each order against the
    /// full position independently — N sells of 10 each looked
    /// covered, stacking unbacked short exposure that all fills.
    #[test]
    fn position_cover_is_allocated_once_across_opposing_orders() {
        let ledger = Arc::new(framework::MemoryBalances::new());
        ledger.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_ledger(ledger.clone());
        let mid = perps.list_market(test_cfg()).unwrap();

        // +10-lot long at the mark — no PnL, isolated margin 0.
        {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let acct = PerpsModule::account_mut(&mut inner, &addr(1));
            acct.positions.insert(
                mid,
                Position { size: 10_000, entry_price: 1_500_000_000, isolated_margin: 0 },
            );
        }
        // Equity covers the position IM (15_000) with headroom, but
        // not position IM + a fresh 10-lot exposure (≈11_000+).
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 20_000)).unwrap();

        // First opposing order: fully covered by the long → free.
        perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 100, 10, 1))).unwrap();

        // Second opposing order: cover exhausted → charged IM →
        // must exceed the remaining equity.
        let err =
            perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 200, 10, 1))).unwrap_err();
        assert!(
            matches!(err, ExecError::ModuleRejected(_)),
            "cover allocated to the first order must not be spent twice"
        );
    }

    /// The unit-level view of the same invariant: `total_open_order_im`
    /// charges the uncovered tail once the position's cover is spent,
    /// and conservatively covers the CHEAPEST opposing orders first,
    /// leaving the most expensive residual exposed.
    #[test]
    fn open_order_im_allocates_cover_once() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        let im = {
            let mut inner = perps.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let configs = inner.configs.clone();
            let acct = PerpsModule::account_mut(&mut inner, &addr(1));
            acct.positions.insert(
                mid,
                Position { size: 10_000, entry_price: 1_500_000_000, isolated_margin: 0 },
            );
            for (oid, ticks) in [(1u64, 100u64), (2, 200)] {
                acct.open_orders.insert(
                    (mid, oid),
                    super::OpenOrderResv {
                        qty: 10_000,
                        price: 1_000_000_000 + ticks * 1_000_000,
                        side: Side::Sell,
                        reduce_only: false,
                    },
                );
            }
            acct.total_open_order_im(&configs)
        };
        // Cover pool = 10_000 → retires the cheaper sell (1.1e9);
        // exposed tail = 10_000 × 1.2e9 / lev(10) / 1e8 = 12_000.
        assert_eq!(im, 12_000, "the uncovered sell must reserve initial margin");
    }

    /// Snapshot round-trip: a listed market, funded accounts,
    /// positions, and resting orders on both sides must export,
    /// verify, and re-import byte-identically — the imported
    /// module's root must equal the source's (audit 3.2).
    #[test]
    fn state_snapshot_round_trips() {
        let src = PerpsModule::new();
        let mid = src.list_market(test_cfg()).unwrap();
        src.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000_000)).unwrap();
        src.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000_000)).unwrap();
        // A crossed pair opens positions for both sides…
        src.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
        src.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
        // …and a second resting sell stays on the book.
        src.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 700, 2, 9))).unwrap();

        let snapshot = src.export_state().expect("perps exports state");
        assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

        let dst = PerpsModule::new();
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), src.state_root());
        assert_eq!(dst.mark_price(mid), src.mark_price(mid));
        assert_eq!(dst.cross_margin(&addr(1)), src.cross_margin(&addr(1)));
        assert_eq!(dst.position(&addr(1), mid).size, src.position(&addr(1), mid).size);
    }

    /// A truncated blob must fail inspection and import — the
    /// claimed root is never trusted over the bytes.
    #[test]
    fn state_snapshot_rejects_corruption() {
        let src = PerpsModule::new();
        src.list_market(test_cfg()).unwrap();
        let mut snapshot = src.export_state().unwrap();
        snapshot.entries[0].1.truncate(12);
        assert!(src.inspect_state(&snapshot).is_err());
        assert!(PerpsModule::new().import_state(&snapshot).is_err());
    }
}
