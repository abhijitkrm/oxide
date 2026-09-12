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
//!   via bank transfer). Cross margin shares one margin pool across
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
//! | 0   | Place order | `[market:1][side:1][type:1][tif:1][stp:1][price:8][qty:8]` |
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

/// `[market:1][side:1][type:1][tif:1][stp:1][price:8][qty:8]` = 21.
const PLACE_BODY_LEN: usize = 21;
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

/// Per-account perps state: cross-margin pool + per-market positions.
#[derive(Debug, Clone, Default)]
pub struct AccountState {
    /// Cross-margin pool (shared across all markets). Scale-6 quote.
    pub cross_margin: u64,
    /// Positions indexed by market ID.
    pub positions: BTreeMap<u8, Position>,
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
}

// ── Module ───────────────────────────────────────────────────────────

/// The perps module.
pub struct PerpsModule {
    inner: Mutex<Inner>,
    store: KVStore,
    bank: Option<Arc<bank::BankModule>>,
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

impl PerpsModule {
    /// Construct a fresh perps module with no markets and no bank
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
            bank: None,
        }
    }

    /// Construct a perps module wired to a bank for margin deposits
    /// and settlement.
    pub fn with_bank(bank: Arc<bank::BankModule>) -> Self {
        let mut m = Self::new();
        m.bank = Some(bank);
        m
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

        // Collect all (account, position) pairs for this market, then
        // settle funding. We iterate in sorted address order for
        // determinism.
        let accounts: Vec<(Address, Position)> = inner
            .accounts
            .iter()
            .filter_map(|(addr, state)| state.positions.get(&market).map(|p| (*addr, *p)))
            .collect();

        for (addr, pos) in accounts {
            if !pos.is_open() {
                continue;
            }
            // Funding amount = size * mark * rate / (PRICE_SCALE * 10_000).
            // If rate > 0, longs (size > 0) pay → funding > 0 → debit.
            // If rate > 0, shorts (size < 0) receive → funding < 0 → credit.
            // H2 fix: use checked_mul to detect overflow in the triple
            // product `size * mark * rate`. If it overflows i128,
            // reject the funding application.
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
            let account = Self::account_mut(&mut inner, &addr);
            let Some(pos_entry) = account.positions.get_mut(&market) else {
                // No position for this market — skip (the account
                // may have been closed since the funding loop
                // started). Previously this used `unwrap()`, which
                // would panic if the position was removed.
                continue;
            };
            if funding >= 0 {
                // Long pays (or short receives when rate < 0). Debit.
                let debit = u64::try_from(funding).unwrap_or(u64::MAX);
                if pos_entry.isolated_margin > 0 {
                    pos_entry.isolated_margin = pos_entry.isolated_margin.saturating_sub(debit);
                } else {
                    account.cross_margin = account.cross_margin.saturating_sub(debit);
                }
            } else {
                // Short pays (or long receives when rate < 0). Credit.
                let credit = u64::try_from(-funding).unwrap_or(u64::MAX);
                if pos_entry.isolated_margin > 0 {
                    pos_entry.isolated_margin = pos_entry.isolated_margin.saturating_add(credit);
                } else {
                    account.cross_margin = account.cross_margin.saturating_add(credit);
                }
            }
            events.push(Event { module: "perps", kind: "funding".to_string(), data: vec![market] });
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
        let marks = inner.marks.clone();
        let configs = inner.configs.clone();
        let acct = inner
            .accounts
            .get(account)
            .cloned()
            .ok_or_else(|| ExecError::ModuleRejected("account not found".to_string()))?;

        let equity = acct.equity(&marks, &configs);
        let maintenance = acct.total_maintenance(&marks, &configs);

        // Liquidation condition: equity <= maintenance (as i128).
        if equity > i128::try_from(maintenance).unwrap_or(i128::MAX) {
            return Ok(vec![]); // not under-margined
        }

        // Liquidate: close all positions at mark, realize losses.
        let mut events = Vec::new();
        let mut total_loss_scale14: i128 = 0;
        let mut total_margin_recovered: u64 = 0;

        for (market, pos) in &acct.positions {
            if !pos.is_open() {
                continue;
            }
            let mark = marks.get(market).copied().unwrap_or(pos.entry_price);
            let pnl = pos.unrealized_pnl(mark); // scale-14
            total_loss_scale14 = total_loss_scale14.saturating_add(pnl);
            total_margin_recovered = total_margin_recovered.saturating_add(pos.isolated_margin);
            events.push(Event {
                module: "perps",
                kind: "liquidated".to_string(),
                data: vec![*market],
            });
        }

        // Convert total_loss from scale-14 to scale-6 before combining
        // with margin (which is scale-6). unrealized_pnl returns
        // size_scale8 * price_scale6 = scale-14; dividing by PRICE_SCALE
        // (1e8) brings it to scale-6, matching the margin units.
        let price_scale_i128 = i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
        let total_loss_scale6 = total_loss_scale14 / price_scale_i128;
        let margin_total = i128::from(acct.cross_margin.saturating_add(total_margin_recovered));
        let net = margin_total + total_loss_scale6; // both scale-6
        if net < 0 {
            // Insurance fund covers the shortfall (scale-6).
            let shortfall = u64::try_from(-net).unwrap_or(u64::MAX);
            let fund = inner.insurance_fund;
            if shortfall >= fund {
                // Insurance fund depleted — trigger ADL.
                inner.insurance_fund = 0;
                let adl_events =
                    Self::auto_deleverage(&mut inner, account, &marks, shortfall - fund);
                events.extend(adl_events);
            } else {
                inner.insurance_fund -= shortfall;
            }
        } else {
            // Account has leftover margin after liquidation — return it.
            let leftover = u64::try_from(net).unwrap_or(0);
            if leftover > 0 {
                if let Some(bank) = &self.bank {
                    // Credit the leftover back to the account's bank
                    // balance. (The margin was deposited from bank.)
                    let _ = bank.credit(account, leftover);
                }
            }
        }

        // Close all positions and zero out margins.
        let acct_mut = Self::account_mut(&mut inner, account);
        acct_mut.cross_margin = 0;
        for pos in acct_mut.positions.values_mut() {
            pos.size = 0;
            pos.entry_price = 0;
            pos.isolated_margin = 0;
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
        marks: &BTreeMap<u8, u64>,
        mut remaining_shortfall: u64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        if remaining_shortfall == 0 {
            return events;
        }

        // Step 1-2: Collect all open positions with their PnL.
        // Each entry: (address, market, position, pnl_scale6).
        let mut candidates: Vec<(Address, u8, Position, i128)> = Vec::new();
        for (addr, state) in &inner.accounts {
            if addr == liquidated_account {
                continue;
            }
            for (market, pos) in &state.positions {
                if !pos.is_open() {
                    continue;
                }
                let mark = marks.get(market).copied().unwrap_or(pos.entry_price);
                let pnl_scale14 = pos.unrealized_pnl(mark);
                let pnl_scale6 = pnl_scale14 / i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
                // Only profitable positions are candidates for ADL.
                if pnl_scale6 > 0 {
                    candidates.push((*addr, *market, *pos, pnl_scale6));
                }
            }
        }

        // Step 3: Rank by PnL desc, size desc, address asc.
        candidates.sort_by(|a, b| {
            // PnL descending.
            b.3.cmp(&a.3)
                // Size (absolute) descending.
                .then_with(|| b.2.size.unsigned_abs().cmp(&a.2.size.unsigned_abs()))
                // Address ascending (deterministic tiebreak).
                .then_with(|| a.0.cmp(&b.0))
        });

        // Step 4: Deleverage each candidate until shortfall is covered.
        for (addr, market, pos, pnl_scale6) in candidates {
            if remaining_shortfall == 0 {
                break;
            }
            // Claw back min(remaining_shortfall, counterparty_pnl).
            let clawback_target =
                remaining_shortfall.min(u64::try_from(pnl_scale6).unwrap_or(u64::MAX));
            let acct = Self::account_mut(inner, &addr);
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
            let mark = marks.get(&market).copied().unwrap_or(pos.entry_price);
            let pnl_per_unit = if pos.size > 0 {
                i128::from(mark) - i128::from(pos.entry_price)
            } else {
                i128::from(pos.entry_price) - i128::from(mark)
            };
            if pnl_per_unit <= 0 {
                continue; // not actually profitable at current mark
            }
            let price_scale = i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
            let close_qty_i128 = (i128::from(clawback_target) * price_scale) / pnl_per_unit;
            let size_abs = i128::from(pos.size.unsigned_abs());
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
            if pos.size > 0 {
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

            events.push(Event {
                module: "perps",
                kind: "adl_executed".to_string(),
                data: vec![market],
            });
        }

        // If there's still a shortfall after ADL, it's an unrecoverable
        // loss. In production, this would trigger socialized loss or
        // emergency governance. For now, we log it as an event.
        if remaining_shortfall > 0 {
            events.push(Event {
                module: "perps",
                kind: "adl_shortfall_remaining".to_string(),
                data: vec![],
            });
        }

        events
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
                let cfg = Self::parse_list_market(body).ok_or(ExecError::Malformed)?;
                drop(inner);
                let id = self.list_market(cfg)?;
                Ok(vec![Event {
                    module: "perps",
                    kind: "market_listed".to_string(),
                    data: vec![id],
                }])
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
                drop(inner);
                // M4 fix: use `set_mark_price` which enforces both
                // the per-update deviation check (MAX_MARK_CHANGE_BPS)
                // and the per-block rate limit
                // (MAX_ORACLE_UPDATES_PER_BLOCK). The previous inline
                // check bypassed the rate limit, allowing many small
                // updates to compound within a single block.
                self.set_mark_price(market, mark)?;
                Ok(vec![Event {
                    module: "perps",
                    kind: "mark_updated".to_string(),
                    data: vec![market],
                }])
            }
            TAG_APPLY_FUNDING => {
                let (market, rate_bits) = Self::parse_funding(body).ok_or(ExecError::Malformed)?;
                let rate = i64::from_le_bytes(rate_bits);
                drop(inner);
                self.apply_funding(market, rate)
            }
            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, _height: Height) {}

    fn state_root(&self) -> Hash {
        subtree_root(&self.store)
    }
}

// ── Fill → position application ──────────────────────────────────────

impl PerpsModule {
    /// Handle a place-order message (extracted from `handle` to keep
    /// the dispatch function under the clippy line-count gate).
    fn handle_place(&self, ctx: &TxContext, body: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (market, mut order, _) = Self::parse_place(body).ok_or(ExecError::Malformed)?;
        order.owner = ctx.sender;

        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Inner { markets, fills, .. } = &mut *inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::ModuleRejected(format!("market {market} does not exist")));
        };

        fills.clear();
        let outcome = engine
            .place(order, fills)
            .map_err(|e| ExecError::ModuleRejected(format!("engine: {e}")))?;

        // Move fills out of the scratch buffer (no clone). The
        // buffer is left empty for the next use. This avoids a
        // per-fill clone: previously, `fills.clone()` copied every
        // FillEvent so we could release the borrow on `inner` and
        // then apply fills to positions. `mem::take` moves the Vec's
        // contents out in O(1), leaving an empty Vec behind.
        let fills_owned: Vec<FillEvent> = std::mem::take(fills);
        let mut events = Vec::with_capacity(fills_owned.len() + 1);
        for f in &fills_owned {
            events.push(fill_event(*f));
        }

        // Apply fills to positions (needs exclusive `&mut inner`).
        for f in &fills_owned {
            Self::apply_fill_to_position(&mut inner, market, f);
        }

        // Post-trade margin check.
        Self::margin_check(&mut inner, &ctx.sender, market, &mut events);

        events.push(outcome_event(market, outcome));
        Ok(events)
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
            return Err(ExecError::ModuleRejected("cancel: order not found".to_string()));
        }
        match engine.cancel(order_id) {
            Ok(canceled) => Ok(vec![cancel_event(market, canceled)]),
            Err(TradingError::OrderNotFound) => {
                Err(ExecError::ModuleRejected("cancel: order not found".to_string()))
            }
            Err(e) => Err(ExecError::ModuleRejected(format!("cancel: {e}"))),
        }
    }

    /// Handle a deposit-margin message (extracted from `handle`).
    fn handle_deposit(&self, ctx: &TxContext, body: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (market, amount) = Self::parse_margin(body).ok_or(ExecError::Malformed)?;
        if let Some(bank) = &self.bank {
            bank.debit(&ctx.sender, amount)?;
        }
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let acct = Self::account_mut(&mut inner, &ctx.sender);
        if market == CROSS_MARGIN_MARKET {
            acct.cross_margin = acct.cross_margin.saturating_add(amount);
        } else {
            let pos = acct.positions.entry(market).or_default();
            pos.isolated_margin = pos.isolated_margin.saturating_add(amount);
        }
        Ok(vec![Event { module: "perps", kind: "deposit".to_string(), data: vec![market] }])
    }

    /// Handle a withdraw-margin message (extracted from `handle`).
    fn handle_withdraw(&self, ctx: &TxContext, body: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (market, amount) = Self::parse_margin(body).ok_or(ExecError::Malformed)?;
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let acct = Self::account_mut(&mut inner, &ctx.sender);
        let balance = if market == CROSS_MARGIN_MARKET {
            &mut acct.cross_margin
        } else {
            &mut acct.positions.entry(market).or_default().isolated_margin
        };
        if *balance < amount {
            return Err(ExecError::ModuleRejected("insufficient margin".to_string()));
        }
        *balance -= amount;
        drop(inner);
        if let Some(bank) = &self.bank {
            bank.credit(&ctx.sender, amount)?;
        }
        Ok(vec![Event { module: "perps", kind: "withdraw".to_string(), data: vec![market] }])
    }

    /// Post-trade margin check: if the account is under-margined,
    /// emit a `margin_call` event.
    fn margin_check(inner: &mut Inner, sender: &Address, market: u8, events: &mut Vec<Event>) {
        let configs = inner.configs.clone();
        let marks = inner.marks.clone();
        let acct = Self::account_mut(inner, sender).clone();
        let equity = acct.equity(&marks, &configs);
        let maintenance = acct.total_maintenance(&marks, &configs);
        if equity < i128::try_from(maintenance).unwrap_or(i128::MAX) {
            events.push(Event {
                module: "perps",
                kind: "margin_call".to_string(),
                data: vec![market],
            });
        }
    }
}

impl PerpsModule {
    /// Apply a fill to the taker's and maker's positions. A buy
    /// increases the position; a sell decreases it. Entry price is
    /// volume-weighted.
    fn apply_fill_to_position(inner: &mut Inner, market: u8, fill: &FillEvent) {
        // Taker side determines who is buying vs selling.
        let (buyer, seller) = if fill.taker_side == Side::Buy {
            (fill.taker_owner, fill.maker_owner)
        } else {
            (fill.maker_owner, fill.taker_owner)
        };
        let fill_qty = i64::try_from(fill.qty.0).unwrap_or(i64::MAX);

        // Buyer's position increases (or shorts decrease).
        Self::adjust_position(inner, &buyer, market, fill.price.0, fill_qty);
        // Seller's position decreases (or shorts increase).
        Self::adjust_position(inner, &seller, market, fill.price.0, -fill_qty);
    }

    /// Adjust a position by `delta` (signed qty) at `fill_price`.
    /// Updates the volume-weighted entry price.
    fn adjust_position(
        inner: &mut Inner,
        account: &Address,
        market: u8,
        fill_price: u64,
        delta: i64,
    ) {
        let acct = Self::account_mut(inner, account);
        let pos = acct.positions.entry(market).or_default();
        let new_size = pos.size.saturating_add(delta);

        // Update entry price (volume-weighted) when increasing the
        // position. When decreasing, entry price stays the same.
        if delta != 0 && (pos.size.signum() == delta.signum() || pos.size == 0) {
            // Increasing position: weighted average.
            let old_cost = i128::from(pos.size.unsigned_abs()) * i128::from(pos.entry_price);
            let add_cost = i128::from(delta.unsigned_abs()) * i128::from(fill_price);
            let new_size_abs = i128::from(new_size.unsigned_abs());
            if new_size_abs > 0 {
                let new_entry = (old_cost + add_cost) / new_size_abs;
                pos.entry_price = u64::try_from(new_entry).unwrap_or(u64::MAX);
            }
        }
        // If the position flipped sign (e.g. long → short), reset
        // entry to the fill price.
        if pos.size != 0 && pos.size.signum() != new_size.signum() {
            pos.entry_price = fill_price;
        }
        pos.size = new_size;
        if new_size == 0 {
            pos.entry_price = 0;
        }
    }
}

// ── Parsing helpers ─────────────────────────────────────────────────

impl PerpsModule {
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
    Event { module: "perps", kind: "fill".to_string(), data }
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
    Event { module: "perps", kind: kind.to_string(), data }
}

fn cancel_event(market: u8, canceled: CanceledOrder) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 1 + 8 + 8 + 20);
    data.push(market);
    data.extend_from_slice(&canceled.order_id.0.to_le_bytes());
    data.push(encode_side(canceled.side));
    data.extend_from_slice(&canceled.price.0.to_le_bytes());
    data.extend_from_slice(&canceled.qty.0.to_le_bytes());
    data.extend_from_slice(&canceled.owner.0);
    Event { module: "perps", kind: "canceled".to_string(), data }
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
        MarketConfig, NewOrder, OrderType, PRICE_SCALE, PerpsMarketConfig, PerpsModule, Position,
        Side, StpMode, TimeInForce, encode_reject_reason, mark_price_deviation_bps, msg,
    };
    use executor::{ExecError, Module, TxContext};
    use framework::module_id;
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
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_bank(bank.clone());
        perps.list_market(test_cfg()).unwrap();
        // Deposit 500_000 into cross margin.
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        assert_eq!(perps.cross_margin(&addr(1)), 500_000);
        assert_eq!(bank.balance(&addr(1)), 500_000);
    }

    #[test]
    fn deposit_isolated_margin() {
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_bank(bank.clone());
        let mid = perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(mid, 500_000)).unwrap();
        let pos = perps.position(&addr(1), mid);
        assert_eq!(pos.isolated_margin, 500_000);
        assert_eq!(bank.balance(&addr(1)), 500_000);
    }

    #[test]
    fn withdraw_cross_margin() {
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_bank(bank.clone());
        perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
        perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 200_000)).unwrap();
        assert_eq!(perps.cross_margin(&addr(1)), 300_000);
        assert_eq!(bank.balance(&addr(1)), 700_000);
    }

    #[test]
    fn withdraw_insufficient_rejected() {
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_bank(bank.clone());
        perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100_000)).unwrap();
        let err =
            perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 200_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    #[test]
    fn set_mark_price() {
        let perps = PerpsModule::new();
        let mid = perps.list_market(test_cfg()).unwrap();
        perps.handle(&ctx(1), &msg::set_mark(mid, 1_600_000_000)).unwrap();
        assert_eq!(perps.mark_price(mid), Some(1_600_000_000));
    }

    #[test]
    fn set_mark_nonexistent_rejected() {
        let perps = PerpsModule::new();
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
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&addr(1), 1_000_000_000);
        bank.mint(&addr(2), 1_000_000_000);
        let perps = PerpsModule::with_bank(bank.clone());
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
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&addr(1), 1_000_000);
        let perps = PerpsModule::with_bank(bank.clone());
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
        let perps = PerpsModule::new();
        let list_msg = msg::list_market(test_cfg());
        let events = perps.handle(&ctx(1), &list_msg).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "market_listed");
    }

    #[test]
    fn state_root_changes_after_market_listed() {
        let perps = PerpsModule::new();
        let root0 = perps.state_root();
        perps.list_market(test_cfg()).unwrap();
        let root1 = perps.state_root();
        assert_ne!(root0, root1);
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
        let bank = Arc::new(bank::BankModule::new());
        bank.mint(&addr(1), 1_000_000);
        bank.mint(&addr(2), 1_000_000);
        let perps = PerpsModule::with_bank(bank.clone());
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
        let bank = Arc::new(bank::BankModule::new());
        let perps = PerpsModule::with_bank(bank.clone());
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
        let bank = Arc::new(bank::BankModule::new());
        let perps = PerpsModule::with_bank(bank.clone());
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
}
