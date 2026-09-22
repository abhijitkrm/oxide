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
//! | 6   | Apply funding | `[market:1][rate:8]` (oracle/governance path, signed i64 as u64 — quorum-endorsed, applies at the next `FUNDING_PERIOD_BLOCKS` boundary) |
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
/// `[account: 20B]` — permissionless liquidation trigger. Any
/// sender may submit it; the module runs `liquidation_check` on
/// `account` — a no-op (fee-burning) tx on a solvent account, a
/// full liquidation on an underwater one. This is the live path
/// the audit called missing: liquidation used to exist only as a
/// test/sim/bench entry point.
const TAG_LIQUIDATE: u8 = 7;

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

/// Mark staleness horizon, in blocks: a mark last accepted more
/// than this many blocks ago is STALE. Non-reduce-only orders
/// against the market are rejected at admission — the market is in
/// reduce-only mode until a fresh mark lands.
///
/// Mirrors the oracle module's `STALE_AFTER_BLOCKS = 60`: the two
/// bounds measure the same thing from different sides of the
/// `MarkSink` push (oracle: time since ITS last successful publish;
/// perps: time since the last mark IT accepted). Keeping the
/// constant local — not importing oracle's — is deliberate: the
/// perps bound must hold even when no oracle is wired (the
/// committee-override path refreshes marks directly).
const MAX_MARK_STALENESS_BLOCKS: u64 = 60;

/// `end_block` liquidation sweep budget: the maximum number of
/// accounts checked for under-margin per block. 32 keeps the
/// sweep's worst-case cost bounded (~32 × O(positions + resting
/// orders)) regardless of account count, while the rotating cursor
/// still covers the whole account set every `accounts/32` blocks —
/// ~100 blocks (~30 s) at 3,200 accounts. The permissionless
/// `TAG_LIQUIDATE` path covers the urgent cases between sweep
/// visits.
const LIQUIDATION_SWEEP_BUDGET: usize = 32;

/// Backstop unwind slippage allowance, in basis points: the IOC
/// exit order's limit is the mark moved AGAINST the fund by this
/// much — a long sells down to `mark·(1−1%)`, a short buys up to
/// `mark·(1+1%)`. Bids/asks between mark and the bound fill, so the
/// backstop still exits a book that has gapped away from the last
/// mark instead of stranding while unrealized losses accrue.
///
/// Origin: audit residual — a mark-only exit never fills once bids
/// fall below mark, so a fast-falling book left the fund holding a
/// depreciating inventory indefinitely. 100 bps is deliberately an
/// order of magnitude under `MAX_MARK_CHANGE_BPS`: the fund pays at
/// most ~1% of notional per unwind pass — a bounded, known cost —
/// while the mark itself can keep tracking the fall.
///
/// Tradeoff: a larger allowance exits faster in deeper gaps but
/// bleeds more fund capital per block; a smaller one preserves
/// capital but re-strands inventory whenever the book gaps wider.
const BACKSTOP_UNWIND_SLIPPAGE_BPS: u64 = 100;

/// Bound on the absolute funding rate a quorum-endorsed
/// `TAG_APPLY_FUNDING` may apply, in basis points: 500 = 5% per
/// period. The endorsement authenticates the rate but cannot bound
/// its magnitude — without a cap, a quorum bug or compromised
/// committee could move an arbitrary fraction of every open
/// position's notional between longs and shorts in one block.
/// 5%/period is far above honest funding (venues clamp near ±2%)
/// yet converts "unbounded transfer" into "bounded loss".
const MAX_FUNDING_RATE_BPS: i64 = 500;

/// The funding period, in blocks: endorsed rates apply only at
/// block heights divisible by this value — one application per
/// market per period, at a boundary every participant can
/// predict. A quorum-endorsed `TAG_APPLY_FUNDING` records
/// `pending_funding[market]` (bounded by [`MAX_FUNDING_RATE_BPS`]
/// at record time); the next boundary applies it once and clears
/// it, so funding never lands mid-block at quorum-chosen timing
/// and a stale rate cannot charge forever — each period needs a
/// fresh endorsement. `3_600` blocks ≈ 1h at the ~1s block cadence
/// (venue convention is hourly funding). A boundary during an
/// oracle outage skips the period entirely — `apply_funding`
/// rejects stale marks and the consumed rate must be re-endorsed.
const FUNDING_PERIOD_BLOCKS: u64 = 3_600;

/// The module-owned clearing account — the counterparty of last
/// resort in the clearing model (audit 5.1).
///
/// Every unilateral position change is mirrored here so net
/// position per market stays zero *including* this account:
/// liquidation transfers the seized inventory to it at mark, and
/// ADL lands the clawed counterparty quantity on it. Its
/// collateral is the insurance fund — [`settle_realized`] settles
/// its realized `PnL` against the fund directly — and `end_block`
/// unwinds its inventory into the book with IOC orders at mark.
///
/// The address has no private key: it cannot sign and `handle`
/// rejects it as a sender, so only internal module paths move it.
/// The byte pattern is arbitrary — any reserved constant works —
/// but it must not collide with a plausible user address.
const CLEARING_ACCOUNT: Address = Address([0xEE; 20]);

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

/// Which margin wallet backs a position. [`Position::margin_class`]
/// is the ONLY interpretation of `isolated_margin` — never compare
/// the raw field against zero at a call site.
///
/// The drain rule (the "nonzero balance implies isolated mode"
/// convention made explicit): a position is [`Self::Isolated`] while
/// it carries any isolated margin; when the wallet drains to zero,
/// funding debits and `PnL` credits route to the cross pool — an
/// empty isolated wallet *demotes* rather than leaves a
/// zero-capacity bucket every path must special-case. The sentinel
/// stays inside this enum's constructor so the demotion rule lives
/// in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarginClass {
    /// `isolated_margin > 0`: margin lives on the position.
    Isolated,
    /// `isolated_margin == 0`: margin lives in the account's
    /// cross-margin pool.
    Cross,
}

/// A perpetual position: signed size (positive = long, negative =
/// short), volume-weighted entry price, and isolated margin balance.
///
/// For cross-margin positions, `isolated_margin` is 0 and the margin
/// lives in the account's cross-margin pool. Read [`Position::margin_class`]
/// instead of comparing the field — the zero-balance demotion rule
/// is part of the type's contract, not a call-site convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    /// Signed position size in raw qty units (scale-6). Positive =
    /// long, negative = short. Zero = no position.
    pub size: i64,
    /// Volume-weighted average entry price (scale-8). Zero if no
    /// position.
    pub entry_price: u64,
    /// Isolated margin held against this position (scale-6). Zero for
    /// cross-margin positions — and for an isolated wallet that has
    /// drained, which thereafter routes like cross (see
    /// [`MarginClass`]).
    pub isolated_margin: u64,
}

impl Position {
    /// Whether this position is open (non-zero size).
    const fn is_open(&self) -> bool {
        self.size != 0
    }

    /// Which margin wallet backs this position — the single
    /// interpretation of `isolated_margin` (see [`MarginClass`]).
    /// `pub(crate)`: the funding debit and `PnL` routes read it.
    pub(crate) const fn margin_class(&self) -> MarginClass {
        if self.isolated_margin > 0 { MarginClass::Isolated } else { MarginClass::Cross }
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
    /// Losses the margin→insurance→ADL cascade could not allocate
    /// (scale-6 quote). This is where unpaid losses LIVE: a real,
    /// committed liability — not an event. Future insurance-fund
    /// inflows retire it before accruing to the fund
    /// ([`Self::fund_inflow`]), so it is the socialized-loss claim
    /// the audit requires: a first-priority draw on the fund's
    /// next revenue, not a number logged and forgotten.
    unfunded_bad_debt: u64,
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
    /// The height of the block currently executing, captured at
    /// `begin_block`. Mark staleness and the liquidation sweep are
    /// computed against it. `0` outside block execution (unit tests
    /// driving `handle` directly) — which makes every mark read
    /// fresh, so direct-call tests see the pre-staleness behavior.
    current_height: u64,
    /// The block height at which each market's mark was last
    /// ACCEPTED — set by `set_mark_price`, `set_mark_price_unchecked`,
    /// and `list_market` seeding. This is the module's OWN freshness
    /// record, independent of the oracle's: a healthy oracle feeding
    /// a rejected update still means a stale mark here, and the
    /// committee-override path is a legitimate refresh. Committed —
    /// staleness decisions must agree across nodes.
    mark_updated_at: BTreeMap<u8, u64>,
    /// Rotating cursor for the bounded `end_block` liquidation
    /// sweep: the last account checked. `None` = next sweep starts
    /// from the first account. Committed — the sweep position is
    /// consensus-visible state (two nodes sweeping different
    /// windows produce different liquidation sets).
    liquidation_cursor: Option<Address>,
    /// Quorum-endorsed funding rates awaiting the next period
    /// boundary (`TAG_APPLY_FUNDING` records; `end_block` applies
    /// at `height % FUNDING_PERIOD_BLOCKS == 0`). Committed — the
    /// pending set decides what applies at the next boundary, so
    /// two nodes disagreeing on it would diverge there.
    pending_funding: BTreeMap<u8, i64>,
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

mod accounting;
mod decode;
mod handlers;
mod module_impl;
mod parse;

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
                unfunded_bad_debt: 0,
                fills: Vec::with_capacity(64),
                oracle_updates_this_block: BTreeMap::new(),
                current_height: 0,
                mark_updated_at: BTreeMap::new(),
                liquidation_cursor: None,
                pending_funding: BTreeMap::new(),
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
        let mut inner = framework::lock_state(&self.inner);
        let id =
            inner.markets.iter().position(Option::is_none).ok_or_else(|| {
                ExecError::ModuleRejected("all 256 market slots taken".to_string())
            })?;
        #[allow(clippy::cast_possible_truncation)]
        let id_u8 = id as u8;
        let vbase = cfg
            .base
            .validated()
            .map_err(|e| ExecError::ModuleRejected(format!("market config: {e}")))?;
        let book = DenseBook::new(vbase)
            .map_err(|e| ExecError::ModuleRejected(format!("book init: {e}")))?;
        let engine = MatchingEngine::new(vbase, book)
            .map_err(|e| ExecError::ModuleRejected(format!("engine init: {e}")))?;
        inner.markets[id] = Some(engine);
        inner.configs.insert(id_u8, cfg);
        // Initialize mark price to the mid of the price band — a
        // fresh mark, so the market trades for its first
        // [`MAX_MARK_STALENESS_BLOCKS`] blocks even before the
        // first oracle update lands.
        let initial_mark = cfg.base.min_price.midpoint(cfg.base.max_price);
        inner.marks.insert(id_u8, initial_mark);
        let h = inner.current_height;
        inner.mark_updated_at.insert(id_u8, h);
        // Persist config for state-root replay.
        let key = market_config_key(id_u8);
        framework::lock_state(&self.store).insert(key, encode_perps_config(&cfg));
        Ok(id_u8)
    }

    /// Get the mark price for a market.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn mark_price(&self, market: u8) -> Option<u64> {
        framework::lock_state(&self.inner).marks.get(&market).copied()
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
        let mut inner = framework::lock_state(&self.inner);
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
        // An ACCEPTED update refreshes the mark's age — even a
        // no-change mark means the feed is alive.
        let h = inner.current_height;
        inner.mark_updated_at.insert(market, h);
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
        let mut inner = framework::lock_state(&self.inner);
        if !inner.configs.contains_key(&market) {
            return Err(ExecError::ModuleRejected("market does not exist".to_string()));
        }
        inner.marks.insert(market, mark);
        let h = inner.current_height;
        inner.mark_updated_at.insert(market, h);
        Ok(())
    }

    /// Whether `market`'s mark is stale: last accepted more than
    /// [`MAX_MARK_STALENESS_BLOCKS`] ago, or never accepted at all.
    ///
    /// Staleness puts the market in reduce-only mode — see the
    /// admission gate in `handle_place`. Liquidations still run at
    /// the last mark: freezing risk-reduction during an oracle
    /// outage would strand underwater accounts exactly when they
    /// need closing.
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    #[must_use]
    pub fn mark_is_stale(&self, market: u8) -> bool {
        let inner = framework::lock_state(&self.inner);
        match inner.mark_updated_at.get(&market) {
            // No accepted update on record — an untracked mark
            // cannot be proven fresh, so fail closed. (Snapshot
            // decode seeds ages for imported marks, and
            // `list_market` seeds at listing, so `None` only occurs
            // for markets that never received a mark at all.)
            None => true,
            Some(&updated) => {
                inner.current_height.saturating_sub(updated) > MAX_MARK_STALENESS_BLOCKS
            }
        }
    }

    /// Get an account's position in a market (read-only).
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn position(&self, account: &Address, market: u8) -> Position {
        let inner = framework::lock_state(&self.inner);
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
        let inner = framework::lock_state(&self.inner);
        inner.accounts.get(account).map_or(0, |a| a.cross_margin)
    }

    /// Insurance fund balance (read-only).
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn insurance_fund(&self) -> u64 {
        framework::lock_state(&self.inner).insurance_fund
    }

    /// Unpaid-loss liability the margin→insurance→ADL cascade could
    /// not allocate (read-only). See [`Inner::unfunded_bad_debt`].
    ///
    /// # Panics
    ///
    /// Panics if the inner mutex is poisoned.
    pub fn unfunded_bad_debt(&self) -> u64 {
        framework::lock_state(&self.inner).unfunded_bad_debt
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
        let mut inner = framework::lock_state(&self.inner);
        let mark = *inner
            .marks
            .get(&market)
            .ok_or_else(|| ExecError::ModuleRejected("market does not exist".to_string()))?;

        // Bound the applied rate: the quorum gate authenticates the
        // rate but cannot bound its magnitude — an out-of-range rate
        // is rejected (mapped to `apply_funding_stale` upstream),
        // converting "unbounded transfer between longs and shorts"
        // into "bounded loss".
        // `i64::MIN` has no positive abs — checked_abs maps it to
        // out-of-range rather than panicking.
        if rate_i64.checked_abs().is_none_or(|a| a > MAX_FUNDING_RATE_BPS) {
            return Err(ExecError::ModuleRejected(format!(
                "funding rate {rate_i64} bps exceeds bound ±{MAX_FUNDING_RATE_BPS} bps"
            )));
        }

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
            let bucket = if pos_entry.margin_class() == MarginClass::Isolated {
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
            let bucket = if pos_entry.margin_class() == MarginClass::Isolated {
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
        // place value may accumulate without a named owner. Routed
        // through `fund_inflow` so outstanding `unfunded_bad_debt`
        // retires before the fund balance grows.
        let surplus = collected.saturating_sub(distributed);
        Self::fund_inflow(&mut inner, u64::try_from(surplus).unwrap_or(u64::MAX));
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
        // The clearing account is module-owned — the counterparty of
        // last resort that holds seized inventory. It cannot be
        // liquidated: its collateral is the insurance fund itself,
        // so "is it solvent" and "who pays its losses" are the same
        // question, and liquidating it would be circular. Its risk
        // is managed by the unwind in `end_block`, not by seizure.
        if account == &CLEARING_ACCOUNT {
            return Ok(vec![]);
        }
        let mut inner = framework::lock_state(&self.inner);

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
        //
        // Each seized position is collected for transfer to the
        // clearing account — the exposure does not vanish, it moves
        // to the backstop at mark so net position per market stays
        // zero (audit 5.1's "where do liquidated positions go").
        let mut total_loss_scale14: i128 = 0;
        let mut total_margin_recovered: u64 = 0;
        let cross_margin;
        let mut seized: Vec<(u8, i64, u64)> = Vec::new(); // (market, size, mark)
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
                // i128 accumulators: saturation needs cumulative PnL
                // beyond ±1.7e38 — past any funded position's reach.
                // If it ever fired, the clamp drives `net` to the
                // extreme and the residual lands in
                // `unfunded_bad_debt` — the named deficit account —
                // so the terminal state is "everything is owed",
                // which is the honest reading of an
                // unrepresentable loss.
                total_loss_scale14 = total_loss_scale14.saturating_add(pnl);
                total_margin_recovered = total_margin_recovered.saturating_add(pos.isolated_margin);
                // Record the transfer BEFORE zeroing — `size` is the
                // signed quantity the clearing account inherits.
                seized.push((*market, pos.size, mark));
                // Close the position in the same pass — the old code
                // walked the map a second time to zero these fields.
                pos.size = 0;
                pos.entry_price = 0;
                pos.isolated_margin = 0;
                events.push(Event { module: "perps", kind: "liquidated", data: vec![*market] });
            }
            acct_mut.cross_margin = 0;
        }

        // Transfer each seized position to the clearing account at
        // the same mark used for the `PnL` computation. The backstop
        // inherits the exposure with `entry = mark`, so its future
        // `PnL` is pure mark-tracking settled against the insurance
        // fund. Runs after the account borrow above is released —
        // `adjust_position` re-borrows `accounts` internally and may
        // net the incoming position against inventory the clearing
        // account already holds in the same market (the realized
        // piece then settles to the fund via `settle_realized`).
        for (market, size, mark) in seized {
            Self::adjust_position(&mut inner, &CLEARING_ACCOUNT, market, mark, size, &mut events);
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
            // Insurance fund covers the shortfall (scale-6); what
            // it cannot pay runs the residual cascade — ADL against
            // profitable counterparties, then the tracked
            // `unfunded_bad_debt` liability.
            let shortfall = u64::try_from(-net).unwrap_or(u64::MAX);
            let fund = inner.insurance_fund;
            let cover = fund.min(shortfall);
            inner.insurance_fund = fund - cover;
            let residual = shortfall - cover;
            if residual > 0 {
                Self::socialize_residual(&mut inner, account, residual, &mut events);
            }
        } else {
            // Account has leftover margin after liquidation — return it.
            let leftover = u64::try_from(net).unwrap_or(0);
            if leftover > 0
                && let Some(ledger) = &self.ledger
            {
                // Credit the leftover back to the account's
                // balance. (The margin was deposited from it.)
                let _ = ledger.credit(account, leftover);
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
    /// position is partially closed at mark — the destroyed
    /// unrealized-profit claim on the closed portion is the clawback
    /// (worth exactly the realized `PnL`), and the closed exposure
    /// transfers to the clearing account so net position stays zero.
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
    ///      to the clawback fraction — the destroyed profit claim
    ///      is the extraction (margin untouched).
    ///    - Transfer the closed quantity to the clearing account
    ///      at mark (net position stays zero).
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
    /// The ADL events plus the shortfall ADL could not cover —
    /// the caller books the remainder as `unfunded_bad_debt`.
    fn auto_deleverage(
        inner: &mut Inner,
        liquidated_account: &Address,
        mut remaining_shortfall: u64,
    ) -> (Vec<Event>, u64) {
        let mut events = Vec::new();
        if remaining_shortfall == 0 {
            return (events, 0);
        }

        // Step 1-2: Collect all open positions with their PnL.
        // Each entry: (address, market, size, entry_price, pnl_scale6).
        // Scalars only — the old code cloned a whole `Position` per
        // candidate and the caller cloned the entire `marks` map to
        // pass it in alongside `&mut Inner`; `inner.marks` is read
        // directly here via shared borrows.
        let mut candidates: Vec<(Address, u8, i64, u64, i128)> = Vec::new();
        for (addr, state) in &inner.accounts {
            // Skip the liquidated account (it is the loss-bearer,
            // not a profitable counterparty) and the clearing
            // account — the backstop's "profit" is insurance-fund
            // property, so clawing it would move value from the
            // fund to the fund while shrinking its inventory for
            // no coverage gained.
            if addr == liquidated_account || addr == &CLEARING_ACCOUNT {
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
        // `marks`/`accounts`/`configs` are destructured so mark and
        // lot-size lookups (shared) and position mutations (mutable)
        // borrow disjoint fields.
        //
        // Each clawed quantity is collected for transfer to the
        // clearing account — the closed exposure moves to the
        // backstop at mark so net position stays zero.
        let mut clawed: Vec<(u8, i64, u64)> = Vec::new(); // (market, signed_qty, mark)
        {
            let Inner { marks, accounts, configs, .. } = &mut *inner;
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
                // Lot-align partial claws: a sub-lot transfer would
                // strand untradeable dust on the clearing account —
                // `unwind_clearing` exits whole lots only — so the
                // claw rounds DOWN to the lot grid. A target covering
                // the entire position takes it whole instead: closing
                // removes a dusty position outright rather than
                // leaving the remainder untradeable on either side.
                // A claw that floors to zero contributes nothing and
                // the shortfall moves to the next candidate.
                let lot = i128::from(configs.get(&market).map_or(1, |c| c.base.lot_size.max(1)));
                let capped = close_qty_i128.min(size_abs);
                let close_qty = if capped >= size_abs {
                    i64::try_from(capped).unwrap_or(0)
                } else {
                    i64::try_from(capped - capped % lot).unwrap_or(0)
                };
                if close_qty == 0 {
                    continue;
                }
                // Compute the exact realized PnL (scale-6) from closing
                // close_qty units — the destroyed profit claim, and
                // the amount credited against the shortfall.
                let realized_scale6 =
                    u64::try_from((i128::from(close_qty) * pnl_per_unit) / price_scale)
                        .unwrap_or(u64::MAX);

                // Shrink the counterparty's position (preserve sign).
                // The destroyed unrealized-profit claim on the closed
                // portion IS the extraction — worth exactly
                // `realized_scale6`. The margin is deliberately
                // untouched: the old code ALSO debited `realized` from
                // the margin bucket, taking the clawback twice — once
                // as a confiscated claim and again as cash — an
                // over-extraction that silently destroyed value
                // whenever the margin sufficed.
                if pos_size > 0 {
                    pos_entry.size -= close_qty;
                } else {
                    pos_entry.size += close_qty;
                }
                // The clearing account inherits the closed exposure
                // in the same direction (long stays long, short
                // stays short) — transferred at mark below.
                let signed_qty = if pos_size > 0 { close_qty } else { -close_qty };
                clawed.push((market, signed_qty, mark));
                remaining_shortfall = remaining_shortfall.saturating_sub(realized_scale6);

                events.push(Event { module: "perps", kind: "adl_executed", data: vec![market] });
            }
        }

        // Transfer the clawed exposure to the clearing account at
        // mark — second pass, since `adjust_position` re-borrows
        // `accounts` internally.
        for (market, signed_qty, mark) in clawed {
            Self::adjust_position(inner, &CLEARING_ACCOUNT, market, mark, signed_qty, &mut events);
        }

        // A shortfall ADL could not cover is booked by the caller
        // as `unfunded_bad_debt` — the event marks that boundary.
        if remaining_shortfall > 0 {
            events.push(Event { module: "perps", kind: "adl_shortfall_remaining", data: vec![] });
        }

        (events, remaining_shortfall)
    }

    /// The residual-allocation cascade for a loss the insurance
    /// fund could not cover: claw profitable counterparties (ADL),
    /// then book whatever remains as [`Inner::unfunded_bad_debt`] —
    /// the committed, named place unpaid losses live (audit 5.1).
    /// `excluded` is the loss-bearer, kept out of the ADL candidate
    /// set. Returns the unallocated remainder — the amount booked
    /// into the liability — for the caller's `bad_debt` audit event.
    fn socialize_residual(
        inner: &mut Inner,
        excluded: &Address,
        shortfall: u64,
        events: &mut Vec<Event>,
    ) -> u64 {
        let (mut adl_events, remaining) = Self::auto_deleverage(inner, excluded, shortfall);
        events.append(&mut adl_events);
        if remaining > 0 {
            // The debt counter is a u64 like every balance — its
            // sum cannot exceed total losses ever realized, which
            // real (u64-bounded) money keeps below the clamp. At
            // the unreachable cap the semantics stay honest:
            // everything is owed.
            inner.unfunded_bad_debt = inner.unfunded_bad_debt.saturating_add(remaining);
            let mut data = Vec::with_capacity(8);
            data.extend_from_slice(&remaining.to_le_bytes());
            events.push(Event { module: "perps", kind: "unfunded_bad_debt", data });
        }
        remaining
    }

    /// Route an insurance-fund inflow. `unfunded_bad_debt` is a
    /// senior claim on the fund — every inflow first retires the
    /// tracked liability, and only the remainder accrues to the
    /// fund balance. This is what makes the liability *funded*
    /// rather than an event: the module's next revenue is already
    /// spoken for.
    fn fund_inflow(inner: &mut Inner, amount: u64) {
        let repay = inner.unfunded_bad_debt.min(amount);
        inner.unfunded_bad_debt -= repay;
        // The fund only ever receives real inflows — bounded by the
        // u64 money supply — so the saturating add cannot fire in a
        // consistent ledger. It stays as the defensive bound because
        // a clamped fund is "holds everything," which is the
        // direction a receiver-side overflow must err toward.
        inner.insurance_fund = inner.insurance_fund.saturating_add(amount - repay);
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
    /// Trailing section (v2): last-accepted-mark height per market.
    /// Absent in pre-upgrade blobs — decode seeds age 0, which
    /// reads as STALE at any real chain height: fail closed on an
    /// unverifiable mark age (the next live update clears it).
    mark_updated_at: BTreeMap<u8, u64>,
    /// Trailing section (v2): the liquidation-sweep cursor.
    /// Absent in pre-upgrade blobs — `None` = sweep from the start.
    liquidation_cursor: Option<Address>,
    /// Trailing section (v3): unpaid-loss liability the
    /// margin→insurance→ADL cascade could not allocate. Absent in
    /// pre-upgrade blobs — `0` = nothing owed (the pre-upgrade
    /// module emitted the same losses as events and forgot them;
    /// there is no honest non-zero default to reconstruct).
    unfunded_bad_debt: u64,
    /// Trailing section (v4): quorum-endorsed funding rates
    /// awaiting the next [`FUNDING_PERIOD_BLOCKS`] boundary.
    /// Absent in pre-upgrade blobs — `empty` = nothing pending
    /// (the pre-upgrade path applied at endorsement time, so no
    /// queued rate can be lost to the upgrade).
    pending_funding: BTreeMap<u8, i64>,
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

    /// Build a permissionless liquidation message: `[tag][account:
    /// 20B]`. Any sender may submit it — the module runs
    /// `liquidation_check` on `account`: a no-op on a solvent
    /// account (the sender still pays the tx fee, which prices the
    /// spam vector) and a full liquidation on an underwater one.
    pub fn liquidate(account: &primitives::Address) -> Vec<u8> {
        let mut msg = Vec::with_capacity(21);
        msg.push(super::TAG_LIQUIDATE);
        msg.extend_from_slice(&account.0);
        msg
    }
}

// ── Module trait impl ────────────────────────────────────────────────

// ── Fill → position application ──────────────────────────────────────

// ── Parsing helpers ─────────────────────────────────────────────────

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
mod tests;
