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

impl PerpsModule {
    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        let inner = framework::lock_state(&self.inner);
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
        // ── Trailing section (v2) ── appended after endorsements
        // so pre-upgrade blobs decode with the defaults below:
        // mark ages + the liquidation-sweep cursor. Both are
        // consensus-visible state — staleness decisions and the
        // sweep window must agree across nodes.
        let inner = framework::lock_state(&self.inner);
        w.put_count(inner.mark_updated_at.len());
        for (market, updated) in &inner.mark_updated_at {
            w.put_u8(*market);
            w.put_u64(*updated);
        }
        match inner.liquidation_cursor {
            Some(addr) => {
                w.put_u8(1);
                w.put_addr(&addr);
            }
            None => {
                w.put_u8(0);
            }
        }
        // ── Trailing section (v3) ── the unpaid-loss liability is
        // consensus-visible state: future fund inflows split between
        // retiring it and growing the fund, so two nodes disagreeing
        // on it would diverge on the next funding round.
        w.put_u64(inner.unfunded_bad_debt);
        // ── Trailing section (v4) ── the pending funding set is
        // consensus-visible: it decides what applies at the next
        // period boundary, so disagreement there diverges the
        // moment the boundary lands.
        w.put_count(inner.pending_funding.len());
        for (market, rate) in &inner.pending_funding {
            w.put_u8(*market);
            w.put_i64(*rate);
        }
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
        // ── Trailing section (v2), tolerant of pre-upgrade blobs ──
        // `remaining() == 0` means the blob predates mark ages and
        // the sweep cursor: marks decode at age 0 — stale at real
        // heights until refreshed — and a `None` cursor sweeps from
        // the first account.
        let mut mark_updated_at = BTreeMap::new();
        let mut liquidation_cursor = None;
        let mut unfunded_bad_debt = 0;
        let mut pending_funding = BTreeMap::new();
        if r.remaining() != 0 {
            let n = r.get_count()?;
            for _ in 0..n {
                let market = r.get_u8()?;
                let updated = r.get_u64()?;
                if !configs.contains_key(&market) {
                    return None; // mark age for an unlisted market is dead state
                }
                if mark_updated_at.insert(market, updated).is_some() {
                    return None;
                }
            }
            liquidation_cursor = match r.get_u8()? {
                0 => None,
                1 => Some(r.get_addr()?),
                _ => return None,
            };
            // Trailing v3: pre-v3 blobs end at the cursor. `0` is
            // the only honest default — the pre-upgrade code forgot
            // residual losses entirely, so there is no non-zero
            // liability to reconstruct.
            if r.remaining() != 0 {
                unfunded_bad_debt = r.get_u64()?;
            }
            // Trailing v4: pre-v4 blobs end at the debt. Empty is
            // the only honest default — the pre-upgrade path applied
            // funding at endorsement time, so nothing could be
            // queued. A pending rate outside the bound is
            // non-canonical: the record-time check makes such state
            // unproducible.
            if r.remaining() != 0 {
                let n = r.get_count()?;
                for _ in 0..n {
                    let market = r.get_u8()?;
                    let rate = r.get_i64()?;
                    if !configs.contains_key(&market) {
                        return None; // pending funding for an unlisted market is dead state
                    }
                    if rate.unsigned_abs() > u64::try_from(MAX_FUNDING_RATE_BPS).unwrap_or(0) {
                        return None;
                    }
                    if pending_funding.insert(market, rate).is_some() {
                        return None;
                    }
                }
            }
        }
        // A mark with no recorded age — pre-upgrade blobs — is
        // seeded at height 0: stale at any real chain height until
        // a live update lands. Fail closed on unknown age (the
        // safe direction; the opposite would forgive a dead feed),
        // and recovery is cheap: a healthy oracle clears it in one
        // block.
        for m in marks.keys() {
            mark_updated_at.entry(*m).or_insert(0);
        }
        Some(StagedPerps {
            markets,
            configs,
            marks,
            accounts,
            insurance_fund,
            oracle_updates_this_block,
            endorsements,
            mark_updated_at,
            liquidation_cursor,
            unfunded_bad_debt,
            pending_funding,
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

impl Module for PerpsModule {
    fn name(&self) -> &'static str {
        "perps"
    }

    fn id(&self) -> u8 {
        module_id::PERPS
    }

    fn begin_block(&self, height: Height) {
        // M4 fix: reset the per-block oracle update counter at the
        // start of each block. Each market gets a fresh budget of
        // [`MAX_ORACLE_UPDATES_PER_BLOCK`] updates per block.
        let mut inner = framework::lock_state(&self.inner);
        inner.oracle_updates_this_block.clear();
        // The executing height drives mark-staleness decisions
        // (`mark_is_stale`) for every tx this block.
        inner.current_height = height.value();
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.is_empty() {
            return Err(ExecError::Malformed);
        }
        Self::reject_clearing_sender(ctx)?;
        let tag = msg[0];
        let body = &msg[1..];

        let inner = framework::lock_state(&self.inner);

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
                drop(inner);
                self.handle_apply_funding(ctx, msg, body)
            }
            TAG_LIQUIDATE => {
                // `[account: 20B]` — permissionless trigger: the
                // sender pays the tx fee, which prices the spam
                // vector; the check is bounded by the target's
                // positions + orders.
                let Ok(account) = <[u8; 20]>::try_from(body) else {
                    return Err(ExecError::Malformed);
                };
                drop(inner);
                self.liquidation_check(&primitives::Address(account))
            }
            _ => Err(ExecError::Malformed),
        }
    }

    /// Bounded rotating liquidation sweep: check up to
    /// [`LIQUIDATION_SWEEP_BUDGET`] accounts past the committed
    /// cursor and emit whatever the checks produce. The cursor
    /// makes coverage deterministic across nodes — every validator
    /// sweeps the same window per block — and bounds the sweep's
    /// worst-case cost regardless of account count. Urgent cases
    /// don't wait for the sweep: `TAG_LIQUIDATE` is permissionless
    /// and checks a specific account immediately.
    ///
    /// Stale-mark note: the sweep still runs during an oracle
    /// outage — liquidation is risk-reducing, and the last accepted
    /// mark is the best estimate available. Freezing the sweep on
    /// staleness would strand underwater accounts exactly when they
    /// need closing.
    fn end_block(&self, height: Height) -> Vec<Event> {
        // Funding boundary: on `FUNDING_PERIOD_BLOCKS` multiples,
        // apply every quorum-endorsed pending rate — one application
        // per market per period, at a schedule every participant can
        // predict, before the sweep so this block's liquidations see
        // post-funding margin. A stale mark consumes the rate
        // without applying it (`apply_funding_stale`) — an oracle
        // outage at the boundary skips the period rather than
        // funding on prices nobody trusts.
        let mut events = Vec::new();
        if height.value().is_multiple_of(FUNDING_PERIOD_BLOCKS) {
            let due: Vec<(u8, i64)> = {
                let inner = framework::lock_state(&self.inner);
                inner.pending_funding.iter().map(|(m, r)| (*m, *r)).collect()
            };
            if !due.is_empty() {
                for (market, rate) in due {
                    match self.apply_funding(market, rate) {
                        Ok(applied) => events.extend(applied),
                        Err(_) => events.push(Event {
                            module: "perps",
                            kind: "apply_funding_stale",
                            data: vec![market],
                        }),
                    }
                }
                framework::lock_state(&self.inner).pending_funding.clear();
            }
        }

        // Collect this block's sweep window under a short lock:
        // `liquidation_check` takes the same mutex internally, so
        // the address list must be materialized first.
        let batch: Vec<Address> = {
            let inner = framework::lock_state(&self.inner);
            match inner.liquidation_cursor {
                Some(cursor) => inner
                    .accounts
                    .range((std::ops::Bound::Excluded(cursor), std::ops::Bound::Unbounded))
                    .take(LIQUIDATION_SWEEP_BUDGET)
                    .map(|(addr, _)| *addr)
                    .collect(),
                None => inner.accounts.keys().take(LIQUIDATION_SWEEP_BUDGET).copied().collect(),
            }
        };

        for account in &batch {
            // The only error the check produces is
            // `ModuleRejected("account not found")` — the account
            // vanished between the scan and the check; skip it
            // and keep sweeping.
            if let Ok(ev) = self.liquidation_check(account) {
                events.extend(ev);
            }
        }
        let mut inner = framework::lock_state(&self.inner);
        // Exit path for the backstop: sell this block's seized
        // inventory (and anything carried over) into the book at
        // mark before advancing the cursor.
        Self::unwind_clearing(&mut inner, &mut events);
        // An empty batch means the cursor passed the last account —
        // wrap so the next block restarts coverage from the
        // beginning.
        inner.liquidation_cursor = batch.last().copied();
        events
    }

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
        let slots = framework::lock_state(&self.inner).markets.len();
        let (canon, _staged, _store) = framework::stage_blob_snapshot(snapshot, |r, store| {
            Self::decode_committed(r, store, slots)
        })?;
        Ok(framework::canon_root(canon))
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then the fields swap in
    /// atomically (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let slots = framework::lock_state(&self.inner).markets.len();
        let (_canon, staged, store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        *framework::lock_state(&self.store) = store;
        let mut inner = framework::lock_state(&self.inner);
        inner.markets = staged.markets;
        inner.configs = staged.configs;
        inner.marks = staged.marks;
        inner.accounts = staged.accounts;
        inner.insurance_fund = staged.insurance_fund;
        inner.oracle_updates_this_block = staged.oracle_updates_this_block;
        inner.mark_updated_at = staged.mark_updated_at;
        inner.liquidation_cursor = staged.liquidation_cursor;
        inner.unfunded_bad_debt = staged.unfunded_bad_debt;
        inner.pending_funding = staged.pending_funding;
        // Block-transient: refreshed by the next `begin_block`.
        inner.current_height = 0;
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

    /// Handle an apply-funding message (extracted from `handle` to
    /// keep the dispatch under the line-count gate). Quorum-endorsed
    /// rates are staged, not applied — `end_block` applies them at
    /// the next [`FUNDING_PERIOD_BLOCKS`] boundary.
    fn handle_apply_funding(
        &self,
        ctx: &TxContext,
        msg: &[u8],
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let (market, rate_bits) = Self::parse_funding(body).ok_or(ExecError::Malformed)?;
        let rate = i64::from_le_bytes(rate_bits);
        // Same pre-endorsement existence check as `TAG_SET_MARK` —
        // the bounded pending set must never carry an action that
        // cannot apply.
        if !framework::lock_state(&self.inner).marks.contains_key(&market) {
            return Err(ExecError::ModuleRejected("market does not exist".to_string()));
        }
        // Same quorum gate as `TAG_SET_MARK` — an unauthenticated
        // funding rate is an unauthenticated balance transfer
        // between every long and short on the market, so it takes
        // the same two-thirds endorsement to schedule.
        let Some(committee) = self.committee.clone() else {
            return Err(ExecError::ModuleRejected("apply_funding: no committee wired".to_string()));
        };
        match self.endorsements.record(msg, &ctx.sender, committee.as_ref())? {
            framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                module: "perps",
                kind: "apply_funding_endorse",
                data: vec![market],
            }]),
            framework::EndorsementOutcome::Quorum => {
                // Bound-check at record time — committed state must
                // never carry a rate that could not apply (the
                // decode path enforces the same bound as a
                // canonicity rule).
                if rate.unsigned_abs() > u64::try_from(MAX_FUNDING_RATE_BPS).unwrap_or(0) {
                    return Err(ExecError::ModuleRejected(format!(
                        "funding rate {rate} bps exceeds bound ±{MAX_FUNDING_RATE_BPS} bps"
                    )));
                }
                // Scheduled, not immediate: the rate waits in
                // `pending_funding` for the next
                // `FUNDING_PERIOD_BLOCKS` boundary, where
                // `end_block` applies it. A later endorsement
                // before the boundary replaces it — the committee
                // can correct a fat-fingered rate inside the same
                // period.
                framework::lock_state(&self.inner).pending_funding.insert(market, rate);
                Ok(vec![Event { module: "perps", kind: "funding_scheduled", data: vec![market] }])
            }
        }
    }

    /// Handle a place-order message (extracted from `handle` to keep
    /// the dispatch function under the clippy line-count gate).
    fn handle_place(&self, ctx: &TxContext, body: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (market, mut order, flags) = Self::parse_place(body).ok_or(ExecError::Malformed)?;
        order.owner = ctx.sender;
        let reduce_only = flags & FLAG_REDUCE_ONLY != 0;

        let mut inner = framework::lock_state(&self.inner);

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
        // Oracle-staleness gate (live-pipeline risk control): a
        // market whose mark is older than
        // [`MAX_MARK_STALENESS_BLOCKS`] is in reduce-only mode — new
        // exposure against a price nobody has vouched for recently
        // cannot be margined honestly. Only reduce-only orders
        // pass: closing exposure must never be blocked by a feed
        // outage. Liquidations similarly keep running at the last
        // mark — freezing risk-reduction during an outage would
        // strand underwater accounts exactly when they need
        // closing.
        let stale = inner.mark_updated_at.get(&market).is_none_or(|&updated| {
            inner.current_height.saturating_sub(updated) > MAX_MARK_STALENESS_BLOCKS
        });
        if stale && !reduce_only {
            return Err(ExecError::ModuleRejected(format!(
                "market {market} mark is stale (no update in {MAX_MARK_STALENESS_BLOCKS}+ blocks); reduce-only orders only"
            )));
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
        let mut inner = framework::lock_state(&self.inner);
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
        let mut inner = framework::lock_state(&self.inner);
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
        let mut inner = framework::lock_state(&self.inner);

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

    /// Reject the module-owned clearing account as a tx sender.
    /// No private key exists for it, so an authenticated sender can
    /// never equal it — but a forged-sender path (unsigned devnet
    /// txs) must not move backstop collateral or inventory through
    /// the ordinary message surface. Only internal module paths may
    /// touch the account.
    fn reject_clearing_sender(ctx: &TxContext) -> Result<(), ExecError> {
        if ctx.sender == CLEARING_ACCOUNT {
            return Err(ExecError::ModuleRejected("clearing account cannot transact".to_string()));
        }
        Ok(())
    }

    /// Unwind the clearing account's inventory into the book —
    /// the exit path of the backstop model (audit 5.1). Seized and
    /// ADL-clawed positions would otherwise sit on the clearing
    /// account forever: funded by the insurance fund but growing
    /// without bound. Each call fires one IOC limit order at mark
    /// per inventory market, closing as much as the book takes at
    /// mark-or-better; the unfilled remainder is killed by the IOC
    /// and retried on the next call. The realized `PnL` settles to
    /// the fund via `settle_realized`'s clearing branch.
    ///
    /// The order price is the mark moved against the fund by at
    /// most [`BACKSTOP_UNWIND_SLIPPAGE_BPS`], snapped to the tick
    /// grid toward mark (a sell floor rounds up, a buy cap down) and
    /// clamped to the market's absolute band. A backstop that swept
    /// the whole book would pay arbitrary slippage out of the fund;
    /// a mark-only exit strands inventory the moment the book gaps.
    /// The bound sits between them: the fund pays at most ~1% of
    /// notional to leave, and bids/asks resting between mark and the
    /// bound now fill the unwind.
    ///
    /// `qty` is floored to a whole lot: position sizes are
    /// lot-aligned from fills and ADL claws are floored to the lot
    /// grid at the source, so the only sub-lot inventory left is
    /// dust predating that rule — strictly under one lot, unable to
    /// trade, and carried until a same-direction transfer merges it
    /// back to a lot boundary.
    fn unwind_clearing(inner: &mut Inner, events: &mut Vec<Event>) {
        // Collect the backstop's open inventory (market, signed
        // size) under a shared borrow — the order pass mutates.
        let inventory: Vec<(u8, i64)> =
            inner.accounts.get(&CLEARING_ACCOUNT).map_or_else(Vec::new, |acct| {
                acct.positions
                    .iter()
                    .filter(|(_, p)| p.is_open())
                    .map(|(m, p)| (*m, p.size))
                    .collect()
            });
        for (market, size) in inventory {
            let Some(cfg) = inner.configs.get(&market) else { continue };
            // `lot_size` is validated nonzero at listing; `max(1)`
            // keeps the division total for hand-built states.
            let lot = cfg.base.lot_size.max(1);
            let qty = size.unsigned_abs() - (size.unsigned_abs() % lot);
            if qty == 0 {
                continue;
            }
            let mark = inner.marks.get(&market).copied().unwrap_or(0);
            if mark == 0 {
                continue; // no mark — nothing to price the exit at
            }
            // Exit limit = mark ± the slippage allowance, computed in
            // u128 so a huge mark cannot overflow mid-multiply. The
            // snap direction is conservative on purpose: a sell floor
            // rounds UP (less depth allowed), a buy cap rounds DOWN —
            // the fund can never pay beyond the allowance just to hit
            // the tick grid.
            let tick = cfg.base.tick_size.max(1);
            let raw_limit = if size > 0 {
                u64::try_from(
                    u128::from(mark) * u128::from(10_000u64 - BACKSTOP_UNWIND_SLIPPAGE_BPS)
                        / 10_000,
                )
                .unwrap_or(0)
            } else {
                u64::try_from(
                    u128::from(mark) * u128::from(10_000u64 + BACKSTOP_UNWIND_SLIPPAGE_BPS)
                        / 10_000,
                )
                .unwrap_or(u64::MAX)
            };
            let limit_price = if size > 0 {
                raw_limit.div_ceil(tick).saturating_mul(tick).max(cfg.base.min_price)
            } else {
                (raw_limit / tick).saturating_mul(tick).min(cfg.base.max_price)
            };
            let order = NewOrder {
                side: if size > 0 { Side::Sell } else { Side::Buy },
                order_type: OrderType::Limit,
                tif: TimeInForce::Ioc,
                price: Price(limit_price),
                qty: Qty(qty),
                owner: CLEARING_ACCOUNT,
                stp: StpMode::None,
            };
            // `markets`/`fills`/`accounts` are destructured so the
            // engine (mutable), the fill buffer, and the maker-cap
            // account read borrow disjoint fields. The block yields
            // the fills and cap removals; both are consumed after
            // the borrows die, matching `handle_place`'s two-pass
            // structure.
            let (fills_owned, removed) = {
                let Inner { markets, fills, accounts, .. } = &mut *inner;
                let Some(engine) = markets.get_mut(usize::from(market)).and_then(Option::as_mut)
                else {
                    continue;
                };
                fills.clear();
                let mut cap =
                    ReduceOnlyCap { accounts, market, spent: BTreeMap::new(), removed: Vec::new() };
                let _ = engine.place_with_cap(order, fills, &mut cap);
                (std::mem::take(fills), cap.removed)
            };
            // Makers the sweep removed or decremented — cap kills
            // and self-trade removals — release their reservations
            // before fill application, the same order `handle_place`
            // uses, so fills never see stale entries.
            Self::release_removal_reservations(inner, market, &removed);
            for fill in &fills_owned {
                Self::apply_fill_to_position(inner, market, fill, events);
            }
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
            if cancel_remainder
                && let Some(engine) =
                    inner.markets.get_mut(usize::from(market)).and_then(Option::as_mut)
            {
                let _ = engine.cancel(fill.maker_order_id);
                events.push(Event {
                    module: "perps",
                    kind: "reduce_only_cancel",
                    data: vec![market],
                });
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
            // Saturating is a deliberate bound, not error handling:
            // |size| exceeding i64::MAX needs ~9.2e18 lots against
            // u64-bounded margin — unreachable for funded positions.
            // If it ever fired, clamping is the least-bad terminal
            // (a panic mid-liquidation is a consensus halt; a
            // rejection here would strand the sweep half-applied).
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
    /// cross-backed position drains the cross pool. The remainder
    /// runs the loss cascade — insurance fund, then ADL, then the
    /// committed `unfunded_bad_debt` liability — so an unpaid loss
    /// always lands in a funded account, never just an event.
    ///
    /// The clearing account settles against the fund directly: its
    /// collateral IS the fund, so its gains are fund inflows and its
    /// losses run the same cascade from the fund step down.
    fn settle_realized(
        inner: &mut Inner,
        account: &Address,
        market: u8,
        realized_scale6: i128,
        events: &mut Vec<Event>,
    ) {
        if account == &CLEARING_ACCOUNT {
            // The backstop's collateral IS the insurance fund — its
            // realized PnL settles against the fund directly rather
            // than margin buckets. A gain is a fund inflow (retiring
            // `unfunded_bad_debt` first, like every inflow); a loss
            // the fund cannot cover runs the same residual cascade
            // every other unpaid loss runs — ADL, then the tracked
            // liability.
            if realized_scale6 > 0 {
                let gain = u64::try_from(realized_scale6).unwrap_or(u64::MAX);
                Self::fund_inflow(inner, gain);
            } else {
                let loss = u64::try_from(realized_scale6.unsigned_abs()).unwrap_or(u64::MAX);
                let cover = inner.insurance_fund.min(loss);
                inner.insurance_fund -= cover;
                let residual = loss - cover;
                if residual > 0 {
                    let unpaid = Self::socialize_residual(inner, account, residual, events);
                    let mut data = Vec::with_capacity(1 + 8);
                    data.push(market);
                    data.extend_from_slice(&unpaid.to_le_bytes());
                    events.push(Event { module: "perps", kind: "bad_debt", data });
                }
            }
        } else {
            let mut bad_debt: u64 = 0;
            {
                let acct = Self::account_mut(inner, account);
                let iso_backed = acct
                    .positions
                    .get(&market)
                    .is_some_and(|p| p.margin_class() == MarginClass::Isolated);
                if realized_scale6 > 0 {
                    let gain = u64::try_from(realized_scale6).unwrap_or(u64::MAX);
                    if iso_backed {
                        let pos = acct.positions.entry(market).or_default();
                        if let Some(v) = pos.isolated_margin.checked_add(gain) {
                            pos.isolated_margin = v;
                        } else {
                            // Bucket overflow: hold the max and spill
                            // the excess to cross rather than destroy
                            // value.
                            let spill = gain - (u64::MAX - pos.isolated_margin);
                            pos.isolated_margin = u64::MAX;
                            acct.cross_margin = acct.cross_margin.saturating_add(spill);
                        }
                    } else {
                        acct.cross_margin = acct.cross_margin.saturating_add(gain);
                    }
                } else {
                    let mut loss =
                        u64::try_from(realized_scale6.unsigned_abs()).unwrap_or(u64::MAX);
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
                // The account's collateral is exhausted — the
                // insurance fund is the designated backstop. What
                // the fund cannot cover runs the residual cascade:
                // ADL against profitable counterparties, then the
                // `unfunded_bad_debt` liability. The event reports
                // the post-cascade remainder — the amount that
                // became a tracked liability this transaction.
                let cover = inner.insurance_fund.min(bad_debt);
                inner.insurance_fund -= cover;
                let residual = bad_debt - cover;
                let unpaid = if residual > 0 {
                    Self::socialize_residual(inner, account, residual, events)
                } else {
                    0
                };
                let mut data = Vec::with_capacity(1 + 8);
                data.push(market);
                data.extend_from_slice(&unpaid.to_le_bytes());
                events.push(Event { module: "perps", kind: "bad_debt", data });
            }
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
mod tests;
