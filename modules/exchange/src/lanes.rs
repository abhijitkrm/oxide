//! Per-market parallel execution of a run of book-path transactions
//! (`docs/multi-market-lanes-spec.md`).
//!
//! Orders on different markets share no matching or custody state; the only shared state is the
//! native ledger. A run is executed in parallel lanes (one rayon task per group of markets) only
//! when it is provably order-independent: every transaction is a limit-or-sell `place`, a
//! `cancel`, or a bundle of those, and every sender's balance at run start covers all of that
//! sender's fees and buy reservations in the run. Then no ledger debit can fail in any
//! interleaving, debits and credits commute, and per-account net deltas applied after the run
//! equal the serial result exactly. Anything else declines (`None`) before touching state and the
//! serial path runs.
//!
//! The order logic is not duplicated: lanes call the same `place_core` / `cancel_core` /
//! `bundle_core` the serial path uses, over [`LaneBook`] (an overlay on the committed maps plus
//! ledger deltas) instead of the live maps.

use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::Ordering;

use executor::{Event, ExecError, LaneTx, RejectCategory, TxContext};
use primitives::Address;
use primitives::fixed::Qty;
use rayon::prelude::*;
use trading::{FillEvent, MatchingEngine, OrderType, Side};

use super::{ExchangeModule, PRICE_SCALE, TAG_BUNDLE, TAG_CANCEL, TAG_PLACE};
use crate::book_view::BookView;

/// A fast, per-process-keyed hasher for the lane maps. Lane overlays are short-lived, merged into
/// order-insensitive committed maps and never iterated for consensus decisions, so they do not
/// need `SipHash`'s cryptographic strength; they do need to resist engineered collisions, so the
/// multiplier mix is seeded with a random per-process key (an attacker cannot grind addresses that
/// collide without knowing it). Measured: `SipHash` was ~30% of lane CPU (docs/devlog.md, 25 Nov).
#[derive(Clone, Copy)]
pub(crate) struct FastState(u64);

impl Default for FastState {
    fn default() -> Self {
        static KEY: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        Self(*KEY.get_or_init(|| std::hash::RandomState::new().hash_one(0x6C61_6E65_u64)))
    }
}

impl BuildHasher for FastState {
    type Hasher = FastHasher;
    fn build_hasher(&self) -> FastHasher {
        FastHasher(self.0)
    }
}

/// The hasher behind [`FastState`]: one multiply-rotate per 8 input bytes.
pub(crate) struct FastHasher(u64);

impl FastHasher {
    fn mix(&mut self, word: u64) {
        self.0 = (self.0 ^ word).wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(29);
    }
}

impl Hasher for FastHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while let Some((chunk, tail)) = rest.split_first_chunk::<8>() {
            self.mix(u64::from_le_bytes(*chunk));
            rest = tail;
        }
        if !rest.is_empty() {
            let mut b = [0u8; 8];
            b[..rest.len()].copy_from_slice(rest);
            self.mix(u64::from_le_bytes(b));
        }
    }
    fn write_u8(&mut self, i: u8) {
        self.mix(u64::from(i));
    }
    fn write_usize(&mut self, i: usize) {
        self.mix(i as u64);
    }
    fn finish(&self) -> u64 {
        let x = self.0;
        (x ^ (x >> 32)).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (x >> 29)
    }
}

/// A `HashMap` with the fast keyed hasher.
type FastMap<K, V> = HashMap<K, V, FastState>;

/// Smallest run, in orders (bundle items count), that pays for forking lanes.
/// Unit: orders. Origin: measured fork/merge cost of the EVM lanes (`LANE_MIN_TXS = 512`); below
/// this the serial path is faster. Raising it keeps small runs serial; lowering it risks a net loss.
pub(crate) const LANE_MIN_ORDERS: usize = 512;

/// Most lanes one run is split into. Unit: lanes. The effective count is also capped by the rayon
/// pool size and the number of independent market components, so this only bounds the largest box.
/// Origin: was 8 (the 8-core rung of the hardware ladder); raised to 32 after the 12-core box showed
/// the 8 cap flattening throughput between 8 and 12 markets (docs/devlog.md, 25 Nov).
pub(crate) const MAX_LANES: usize = 32;

/// Names of the lane phases, in `lane_ns` order (observability: where a run's time goes).
pub(crate) const PHASES: [&str; 7] =
    ["plan", "components", "funds", "fees", "lanes", "merge", "ledger"];

/// What the planner needs to know about one transaction, computed in parallel.
struct TxPlan {
    /// Markets the transaction touches, as a 256-bit set.
    markets: [u64; 4],
    /// Orders it carries (bundle items count): the lane load unit.
    orders: u32,
    /// Worst-case native-token outflow: the envelope fee plus every buy item's reservation.
    spend: u128,
}

impl TxPlan {
    fn mark(&mut self, market: u8) {
        self.markets[usize::from(market >> 6)] |= 1u64 << (market & 63);
    }
}

/// A buy's reservation exactly as `place_core` computes it for a limit order; saturated to the
/// largest value when it overflows `u64` (the serial path rejects such an order before debiting,
/// so over-counting only declines the lane path).
fn buy_reservation(price: u64, qty: u64) -> u128 {
    let q = u128::from(price) * u128::from(qty) / PRICE_SCALE;
    if q > u128::from(u64::MAX) { u128::from(u64::MAX) } else { q }
}

/// Plan one `place` body; `None` when the order cannot take the lane path (a market buy: its
/// reservation depends on the live book).
fn plan_place(body: &[u8], p: &mut TxPlan) -> Option<()> {
    if let Some((market, order, _)) = ExchangeModule::parse_place(body) {
        if order.side == Side::Buy {
            if order.order_type == OrderType::Market {
                return None;
            }
            p.spend += buy_reservation(order.price.0, order.qty.0);
        }
        p.mark(market);
        p.orders += 1;
    }
    Some(())
}

/// Plan one `cancel` body (a malformed body touches nothing and just fails in its lane).
fn plan_cancel(body: &[u8], p: &mut TxPlan) {
    if let Some((market, _)) = ExchangeModule::parse_cancel(body) {
        p.mark(market);
        p.orders += 1;
    }
}

/// Plan one transaction; `None` when it cannot take the lane path.
fn plan_tx(tx: &LaneTx<'_>) -> Option<TxPlan> {
    let mut p = TxPlan { markets: [0; 4], orders: 0, spend: u128::from(tx.ctx.fee) };
    let Some((&tag, body)) = tx.payload.split_first() else {
        return Some(p);
    };
    match tag {
        TAG_PLACE => plan_place(body, &mut p)?,
        TAG_CANCEL => plan_cancel(body, &mut p),
        TAG_BUNDLE => {
            // A malformed bundle fails whole with no effect, exactly as the serial path.
            if let Ok(spans) = ExchangeModule::bundle_spans(body) {
                for (a, b) in spans {
                    let item = &body[a..b];
                    match item[0] {
                        TAG_PLACE => plan_place(&item[1..], &mut p)?,
                        TAG_CANCEL => plan_cancel(&item[1..], &mut p),
                        _ => return None,
                    }
                }
            }
        }
        _ => return None,
    }
    Some(p)
}

/// Union-find over the 256 market ids; a bundle that touches several markets merges them.
struct Dsu([u16; 256]);

impl Dsu {
    fn new() -> Self {
        let mut p = [0u16; 256];
        for (i, v) in p.iter_mut().enumerate() {
            *v = u16::try_from(i).unwrap_or(0);
        }
        Self(p)
    }
    fn find(&mut self, mut x: u16) -> u16 {
        while self.0[usize::from(x)] != x {
            let up = self.0[usize::from(self.0[usize::from(x)])];
            self.0[usize::from(x)] = up;
            x = up;
        }
        x
    }
    fn union(&mut self, a: u16, b: u16) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.0[usize::from(ra.max(rb))] = ra.min(rb);
        }
    }
}

/// The markets set in a 256-bit mask, ascending.
fn markets_of(mask: &[u64; 4]) -> impl Iterator<Item = u8> + '_ {
    (0..=u8::MAX).filter(move |m| mask[usize::from(m >> 6)] >> (m & 63) & 1 == 1)
}

/// The lane backend of [`BookView`]: reads fall through to the (immutable) committed maps, writes
/// go to a private overlay, ledger movements are recorded as net deltas. Keys carry the market, so
/// overlays of different lanes are disjoint; ledger deltas commute (see the module docs).
struct LaneBook<'a> {
    maps: Maps<'a>,
    bal: FastMap<(Address, u8), Qty>,
    hold: FastMap<(Address, u8), Qty>,
    vault: FastMap<u8, u64>,
    delta: FastMap<Address, i128>,
}

impl BookView for LaneBook<'_> {
    fn debit(&mut self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        // Cannot fail: the planner proved every sender's balance covers the run's outflow.
        *self.delta.entry(*addr).or_insert(0) -= i128::from(amount);
        Ok(())
    }
    fn credit(&mut self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        *self.delta.entry(*addr).or_insert(0) += i128::from(amount);
        Ok(())
    }
    fn bal(&self, key: &(Address, u8)) -> Option<Qty> {
        self.bal.get(key).copied().or_else(|| self.maps.bal.get(key).copied())
    }
    fn set_bal(&mut self, key: (Address, u8), value: Qty) {
        self.bal.insert(key, value);
    }
    fn hold(&self, key: &(Address, u8)) -> Option<Qty> {
        self.hold.get(key).copied().or_else(|| self.maps.hold.get(key).copied())
    }
    fn set_hold(&mut self, key: (Address, u8), value: Qty) {
        self.hold.insert(key, value);
    }
    fn vault(&self, market: u8) -> Option<u64> {
        self.vault.get(&market).copied().or_else(|| self.maps.vault.get(&market).copied())
    }
    fn set_vault(&mut self, market: u8, value: u64) {
        self.vault.insert(market, value);
    }
}

/// Read-only views of the committed maps the lanes fall through to. The maps' own type holds a
/// lazily-flushed fold behind a `RefCell` (not `Sync`), but reads never touch it, so lanes read the
/// underlying ordered maps directly.
#[derive(Clone, Copy)]
struct Maps<'a> {
    bal: &'a BTreeMap<(Address, u8), Qty>,
    hold: &'a BTreeMap<(Address, u8), Qty>,
    vault: &'a BTreeMap<u8, u64>,
}

/// One lane's input: the transactions (indices, canonical order) and the engines it owns.
struct LaneWork {
    idxs: Vec<usize>,
    engines: FastMap<u8, MatchingEngine>,
}

/// One lane's output.
struct LaneOut {
    results: Vec<(usize, Result<Vec<Event>, ExecError>)>,
    engines: FastMap<u8, MatchingEngine>,
    bal: FastMap<(Address, u8), Qty>,
    hold: FastMap<(Address, u8), Qty>,
    vault: FastMap<u8, u64>,
    delta: FastMap<Address, i128>,
}

fn missing_market(market: u8) -> ExecError {
    ExecError::rejected(RejectCategory::NotFound, format!("market {market} does not exist"))
}

fn lane_place(
    sender: Address,
    body: &[u8],
    engines: &mut FastMap<u8, MatchingEngine>,
    fills: &mut Vec<FillEvent>,
    book: &mut LaneBook<'_>,
) -> Result<Vec<Event>, ExecError> {
    let (market, mut order, _) = ExchangeModule::parse_place(body).ok_or(ExecError::Malformed)?;
    order.owner = sender;
    let engine = engines.get_mut(&market).ok_or_else(|| missing_market(market))?;
    ExchangeModule::place_core(true, sender, market, order, engine, fills, book)
}

fn lane_cancel(
    sender: Address,
    body: &[u8],
    engines: &mut FastMap<u8, MatchingEngine>,
    book: &mut LaneBook<'_>,
) -> Result<Vec<Event>, ExecError> {
    let (market, order_id) = ExchangeModule::parse_cancel(body).ok_or(ExecError::Malformed)?;
    let engine = engines.get_mut(&market).ok_or_else(|| missing_market(market))?;
    ExchangeModule::cancel_core(true, sender, market, order_id, engine, book)
}

/// Execute one transaction on a lane: the lane twin of `ExchangeModule::handle`.
fn lane_tx(
    tx: &LaneTx<'_>,
    engines: &mut FastMap<u8, MatchingEngine>,
    fills: &mut Vec<FillEvent>,
    book: &mut LaneBook<'_>,
) -> Result<Vec<Event>, ExecError> {
    let Some((&tag, body)) = tx.payload.split_first() else {
        return Err(ExecError::Malformed);
    };
    let sender = tx.ctx.sender;
    match tag {
        TAG_PLACE => lane_place(sender, body, engines, fills, book),
        TAG_CANCEL => lane_cancel(sender, body, engines, book),
        TAG_BUNDLE => ExchangeModule::bundle_core(body, |t, rest| match t {
            TAG_PLACE => lane_place(sender, rest, engines, fills, book),
            TAG_CANCEL => lane_cancel(sender, rest, engines, book),
            // Amend inside a bundle is ineligible (planner), so this is unreachable.
            _ => Err(ExecError::Malformed),
        }),
        _ => Err(ExecError::Malformed),
    }
}

fn run_lane(work: LaneWork, txs: &[LaneTx<'_>], skipped: &[bool], maps: Maps<'_>) -> LaneOut {
    let LaneWork { idxs, mut engines } = work;
    let mut book = LaneBook {
        maps,
        bal: FastMap::default(),
        hold: FastMap::default(),
        vault: FastMap::default(),
        delta: FastMap::default(),
    };
    let mut fills: Vec<FillEvent> = Vec::with_capacity(64);
    let mut results = Vec::with_capacity(idxs.len());
    for i in idxs {
        if skipped[i] {
            continue;
        }
        results.push((i, lane_tx(&txs[i], &mut engines, &mut fills, &mut book)));
    }
    let LaneBook { bal, hold, vault, delta, .. } = book;
    LaneOut { results, engines, bal, hold, vault, delta }
}

impl ExchangeModule {
    /// Turn per-market parallel execution of eligible runs on or off (default on).
    pub fn set_exec_lanes(&self, on: bool) {
        self.exec_lanes.store(on, Ordering::Relaxed);
    }

    /// Nanoseconds per lane phase summed over runs, with the phase names (benches).
    pub fn lane_phase_ns(&self) -> Vec<(&'static str, u64)> {
        PHASES.iter().zip(&self.lane_ns).map(|(n, a)| (*n, a.load(Ordering::Relaxed))).collect()
    }

    fn tick(&self, phase: usize, since: &mut std::time::Instant) {
        let now = std::time::Instant::now();
        let ns = u64::try_from(now.duration_since(*since).as_nanos()).unwrap_or(u64::MAX);
        self.lane_ns[phase].fetch_add(ns, Ordering::Relaxed);
        *since = now;
    }

    /// How many runs the lane path executed (tests and benches).
    pub fn lane_runs_for_test(&self) -> u64 {
        self.lane_runs.load(Ordering::Relaxed)
    }

    /// The lane executor behind `Module::handle_run_lanes`; see the module docs for the contract.
    pub(crate) fn run_lanes(
        &self,
        txs: &[LaneTx<'_>],
        charge: &mut dyn FnMut(&TxContext) -> bool,
    ) -> Option<executor::LaneRunResults> {
        if !self.exec_lanes.load(Ordering::Relaxed) {
            return None;
        }
        let ledger = self.ledger.as_ref()?;
        let mut t = std::time::Instant::now();
        // Plan every transaction in parallel; any ineligible one declines the whole run.
        let plans: Vec<TxPlan> = txs.par_iter().map(plan_tx).collect::<Option<Vec<_>>>()?;
        let total_orders: usize = plans.iter().map(|p| p.orders as usize).sum();
        if total_orders < LANE_MIN_ORDERS {
            return None;
        }

        self.tick(0, &mut t);
        // Independent market components: a bundle touching several markets merges them.
        let mut dsu = Dsu::new();
        for p in &plans {
            let mut it = markets_of(&p.markets);
            if let Some(first) = it.next() {
                for m in it {
                    dsu.union(u16::from(first), u16::from(m));
                }
            }
        }
        let mut load: FastMap<u16, u64> = FastMap::default();
        for p in &plans {
            if let Some(first) = markets_of(&p.markets).next() {
                *load.entry(dsu.find(u16::from(first))).or_insert(0) += u64::from(p.orders);
            }
        }
        if load.len() < 2 {
            return None;
        }
        let lanes = MAX_LANES.min(rayon::current_num_threads()).min(load.len());
        if lanes < 2 {
            return None;
        }

        self.tick(1, &mut t);
        // Funds proof: every sender's balance covers the run's whole outflow, so no debit can
        // fail in any interleaving (credits received meanwhile are ignored: conservative).
        let mut spend: FastMap<Address, u128> = FastMap::default();
        for (tx, p) in txs.iter().zip(&plans) {
            *spend.entry(tx.ctx.sender).or_insert(0) += p.spend;
        }
        if spend
            .iter()
            .any(|(a, need)| u128::from(framework::Balances::balance(&**ledger, a)) < *need)
        {
            return None;
        }

        self.tick(2, &mut t);
        // Greedy balance: heaviest component to the least-loaded lane (deterministic).
        let mut comps: Vec<(u16, u64)> = load.into_iter().collect();
        comps.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut lane_load = vec![0u64; lanes];
        let mut lane_of_root: FastMap<u16, usize> = FastMap::default();
        for (root, l) in comps {
            let (best, _) = lane_load.iter().enumerate().min_by_key(|(i, w)| (**w, *i))?;
            lane_load[best] += l;
            lane_of_root.insert(root, best);
        }
        let mut works: Vec<LaneWork> = (0..lanes)
            .map(|_| LaneWork { idxs: Vec::new(), engines: FastMap::default() })
            .collect();
        let mut guard = framework::lock_state(&self.inner);
        for (i, p) in plans.iter().enumerate() {
            let lane = markets_of(&p.markets)
                .next()
                .and_then(|m| lane_of_root.get(&dsu.find(u16::from(m))).copied())
                .unwrap_or(0);
            works[lane].idxs.push(i);
        }
        for m in 0..=u8::MAX {
            if let Some(&lane) = lane_of_root.get(&dsu.find(u16::from(m)))
                && let Some(e) = guard.markets[usize::from(m)].take()
            {
                works[lane].engines.insert(m, e);
            }
        }

        self.tick(1, &mut t);
        Self::charge_fees(txs, charge);
        let skipped = vec![false; txs.len()];

        self.tick(3, &mut t);
        let maps = Maps {
            bal: guard.base_balances.inner(),
            hold: guard.base_holds.inner(),
            vault: guard.fee_vault.inner(),
        };
        let outs: Vec<LaneOut> =
            works.into_par_iter().map(|w| run_lane(w, txs, &skipped, maps)).collect();

        self.tick(4, &mut t);
        let results = self.merge_lanes(guard, outs, txs.len(), ledger, &mut t);
        self.lane_runs.fetch_add(1, Ordering::Relaxed);
        Some(results)
    }

    /// Charge every sender's fees once, as the sum, in address order. Fees commute and cannot
    /// fail after the funds proof, so one ledger touch per sender replaces one per transaction. A
    /// fee module reads only the sender and the fee; the aggregate context carries nonce 0.
    fn charge_fees(txs: &[LaneTx<'_>], charge: &mut dyn FnMut(&TxContext) -> bool) {
        let mut fees: Vec<(Address, u64)> = {
            let mut m: FastMap<Address, u64> = FastMap::default();
            for t in txs {
                if t.ctx.fee > 0 {
                    let e = m.entry(t.ctx.sender).or_insert(0);
                    *e = e.saturating_add(t.ctx.fee);
                }
            }
            m.into_iter().collect()
        };
        fees.sort_unstable_by_key(|(a, _)| *a);
        for (sender, fee) in fees {
            let charged = charge(&TxContext { sender, nonce: 0, fee });
            // Unreachable: the funds proof covers every sender's fees.
            debug_assert!(charged, "aggregate fee charge failed after the funds proof");
        }
    }

    /// Merge lane outputs: engines back, overlays into the committed maps (keys are disjoint across
    /// lanes), net ledger deltas in address order, results to their transaction index.
    fn merge_lanes(
        &self,
        mut guard: std::sync::MutexGuard<'_, super::Inner>,
        outs: Vec<LaneOut>,
        n: usize,
        ledger: &std::sync::Arc<dyn framework::Balances + Send + Sync>,
        t: &mut std::time::Instant,
    ) -> executor::LaneRunResults {
        let mut results: executor::LaneRunResults = (0..n).map(|_| None).collect();
        let mut deltas: FastMap<Address, i128> = FastMap::default();
        for out in outs {
            for (m, e) in out.engines {
                guard.markets[usize::from(m)] = Some(e);
            }
            for (k, v) in out.bal {
                guard.base_balances.insert(k, v);
            }
            for (k, v) in out.hold {
                guard.base_holds.insert(k, v);
            }
            for (k, v) in out.vault {
                guard.fee_vault.insert(k, v);
            }
            for (a, d) in out.delta {
                *deltas.entry(a).or_insert(0) += d;
            }
            for (i, r) in out.results {
                results[i] = Some(r);
            }
        }
        drop(guard);
        self.tick(5, t);
        let mut deltas: Vec<(Address, i128)> =
            deltas.into_iter().filter(|(_, d)| *d != 0).collect();
        deltas.sort_unstable_by_key(|(a, _)| *a);
        for (a, d) in deltas {
            let applied = if d > 0 {
                u64::try_from(d).ok().map(|x| ledger.credit(&a, x))
            } else {
                u64::try_from(-d).ok().map(|x| ledger.debit(&a, x))
            };
            // Unreachable: the funds proof covers every debit and supply stays below u64::MAX.
            debug_assert!(matches!(applied, Some(Ok(()))), "lane ledger delta failed");
        }
        self.tick(6, t);
        results
    }
}
