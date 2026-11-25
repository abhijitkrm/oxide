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

use super::{ExchangeModule, PRICE_SCALE, TAG_BUNDLE, TAG_CANCEL, TAG_DBUNDLE, TAG_PLACE};
use crate::book_view::BookView;
use crate::delegation::authorize_item;

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

/// `lane_of_market` entry of a market no item touches.
const NO_LANE: u8 = u8::MAX;

/// Work-item index meaning "this whole bundle, on one lane": the lane runs every item in order and
/// assembles the transaction result itself (in parallel with the other lanes).
const WHOLE: u32 = u32::MAX;

/// A bundle item's pending result while lanes report.
type Slot = Option<Result<Vec<Event>, ExecError>>;

/// How a transaction's result is assembled from its items' results.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// One place or cancel: the item's result IS the transaction's result.
    Single,
    /// A bundle (own account) or delegated bundle: item events in order, a failed item becomes a
    /// `bundle_item_rejected` event carrying its index.
    Bundle,
    /// Fails whole with no effect (empty payload, bad bundle framing): `Err(Malformed)`.
    Dead,
}

/// One place or cancel to execute: the unit of lane work. Items of different markets commute under
/// the funds proof, so a bundle's items may run on different lanes; items of one market keep their
/// canonical (transaction, item) order.
struct Item {
    /// The account the order is for (the envelope sender, or the owner of a delegated item).
    owner: Address,
    /// Message span inside the transaction payload, tag byte included.
    start: u32,
    end: u32,
    /// The market it touches; `None` for a body that fails to parse (it fails with no effect).
    market: Option<u8>,
    /// A delegated item needs its delegation checked before it runs.
    delegated: bool,
}

/// What the planner needs to know about one transaction, computed in parallel.
struct TxPlan {
    shape: Shape,
    items: Vec<Item>,
    /// Worst-case native-token outflow of the envelope sender: the fee plus every buy item's
    /// reservation for the sender's own account.
    spend: u128,
    /// Reservations of a delegated bundle's buy items, keyed by the OWNER whose balance funds them
    /// (empty for every other transaction: no allocation on the single-order path).
    owner_spend: Vec<(Address, u128)>,
}

/// A buy's reservation exactly as `place_core` computes it for a limit order; saturated to the
/// largest value when it overflows `u64` (the serial path rejects such an order before debiting,
/// so over-counting only declines the lane path).
fn buy_reservation(price: u64, qty: u64) -> u128 {
    let q = u128::from(price) * u128::from(qty) / PRICE_SCALE;
    if q > u128::from(u64::MAX) { u128::from(u64::MAX) } else { q }
}

/// Plan one item whose message is `payload[start..end]`; `None` when it cannot take the lane path
/// (a market buy, whose reservation depends on the live book; an amend or any other kind).
fn plan_item(
    payload: &[u8],
    start: usize,
    end: usize,
    owner: Address,
    delegated: bool,
    p: &mut TxPlan,
) -> Option<()> {
    let msg = &payload[start..end];
    let (&tag, rest) = msg.split_first()?;
    let market = match tag {
        TAG_PLACE => {
            let parsed = ExchangeModule::parse_place(rest);
            if let Some((_, order, _)) = &parsed
                && order.side == Side::Buy
            {
                if order.order_type == OrderType::Market {
                    return None;
                }
                let reserve = buy_reservation(order.price.0, order.qty.0);
                if delegated {
                    p.owner_spend.push((owner, reserve));
                } else {
                    p.spend += reserve;
                }
            }
            parsed.map(|(m, _, _)| m)
        }
        TAG_CANCEL => ExchangeModule::parse_cancel(rest).map(|(m, _)| m),
        _ => return None,
    };
    p.items.push(Item {
        owner,
        start: u32::try_from(start).ok()?,
        end: u32::try_from(end).ok()?,
        market,
        delegated,
    });
    Some(())
}

/// Plan one transaction; `None` when it cannot take the lane path.
fn plan_tx(tx: &LaneTx<'_>) -> Option<TxPlan> {
    let payload = tx.payload;
    let mut p = TxPlan {
        shape: Shape::Dead,
        items: Vec::new(),
        spend: u128::from(tx.ctx.fee),
        owner_spend: Vec::new(),
    };
    let Some((&tag, body)) = payload.split_first() else {
        return Some(p);
    };
    match tag {
        TAG_PLACE | TAG_CANCEL => {
            p.shape = Shape::Single;
            plan_item(payload, 0, payload.len(), tx.ctx.sender, false, &mut p)?;
        }
        TAG_BUNDLE => {
            // A malformed bundle fails whole with no effect, exactly as the serial path.
            if let Ok(spans) = ExchangeModule::bundle_spans(body) {
                p.shape = Shape::Bundle;
                p.items.reserve(spans.len());
                for (a, b) in spans {
                    plan_item(payload, a + 1, b + 1, tx.ctx.sender, false, &mut p)?;
                }
            }
        }
        TAG_DBUNDLE => {
            if let Ok(spans) = ExchangeModule::dbundle_spans(body) {
                p.shape = Shape::Bundle;
                p.items.reserve(spans.len());
                for (owner, a, b) in spans {
                    plan_item(payload, a + 1, b + 1, owner, owner != tx.ctx.sender, &mut p)?;
                }
            }
        }
        _ => return None,
    }
    Some(p)
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
    /// The committed key-value store (delegations live here).
    dlg: &'a BTreeMap<Vec<u8>, Vec<u8>>,
    /// Block height, for delegation expiry.
    height: u64,
    bal: &'a BTreeMap<(Address, u8), Qty>,
    hold: &'a BTreeMap<(Address, u8), Qty>,
    vault: &'a BTreeMap<u8, u64>,
}

/// One lane's input: its work items `(transaction, item)` in canonical order, and the engines of
/// the markets it owns.
struct LaneWork {
    items: Vec<(u32, u32)>,
    engines: FastMap<u8, MatchingEngine>,
}

/// One executed item's outcome.
struct ItemOut {
    tx: u32,
    item: u32,
    result: Result<Vec<Event>, ExecError>,
}

/// One lane's output.
struct LaneOut {
    results: Vec<ItemOut>,
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

/// Execute one item on a lane: authorize it if delegated, then run it as `owner`.
fn lane_item(
    agent: &Address,
    payload: &[u8],
    item: &Item,
    engines: &mut FastMap<u8, MatchingEngine>,
    fills: &mut Vec<FillEvent>,
    book: &mut LaneBook<'_>,
) -> Result<Vec<Event>, ExecError> {
    let msg = &payload[item.start as usize..item.end as usize];
    let (tag, rest) = (msg[0], &msg[1..]);
    if item.delegated {
        authorize_item(book.maps.dlg, book.maps.height, agent, &item.owner, tag, rest)?;
    }
    match tag {
        TAG_PLACE => lane_place(item.owner, rest, engines, fills, book),
        _ => lane_cancel(item.owner, rest, engines, book),
    }
}

fn run_lane(work: LaneWork, txs: &[LaneTx<'_>], plans: &[TxPlan], maps: Maps<'_>) -> LaneOut {
    let LaneWork { items, mut engines } = work;
    let mut book = LaneBook {
        maps,
        bal: FastMap::default(),
        hold: FastMap::default(),
        vault: FastMap::default(),
        delta: FastMap::default(),
    };
    let mut fills: Vec<FillEvent> = Vec::with_capacity(64);
    let mut results = Vec::with_capacity(items.len());
    for (tx, idx) in items {
        let t = &txs[tx as usize];
        let plan = &plans[tx as usize];
        let result = if idx == WHOLE {
            // The whole bundle: every item in order, failed items reported as the serial path does.
            let mut events = Vec::new();
            for (i, item) in plan.items.iter().enumerate() {
                match lane_item(&t.ctx.sender, t.payload, item, &mut engines, &mut fills, &mut book)
                {
                    Ok(evs) => events.extend(evs),
                    Err(e) => events.push(ExchangeModule::item_rejected_event(i, &e)),
                }
            }
            Ok(events)
        } else {
            let item = &plan.items[idx as usize];
            lane_item(&t.ctx.sender, t.payload, item, &mut engines, &mut fills, &mut book)
        };
        results.push(ItemOut { tx, item: idx, result });
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
        let total_items: usize = plans.iter().map(|p| p.items.len()).sum();
        if total_items < LANE_MIN_ORDERS {
            return None;
        }

        self.tick(0, &mut t);
        // Load per market (items are the unit: a bundle's items split across lanes by market).
        let mut load = [0u64; 256];
        for it in plans.iter().flat_map(|p| &p.items) {
            if let Some(m) = it.market {
                load[usize::from(m)] += 1;
            }
        }
        let active = load.iter().filter(|l| **l > 0).count();
        let lanes = MAX_LANES.min(rayon::current_num_threads()).min(active);
        if lanes < 2 {
            return None;
        }

        self.tick(1, &mut t);
        // Funds proof: every account's balance covers the run's whole outflow, so no debit can fail
        // in any interleaving (credits received meanwhile are ignored: conservative).
        let mut spend: FastMap<Address, u128> = FastMap::default();
        for (tx, p) in txs.iter().zip(&plans) {
            *spend.entry(tx.ctx.sender).or_insert(0) += p.spend;
            for (owner, v) in &p.owner_spend {
                *spend.entry(*owner).or_insert(0) += *v;
            }
        }
        if spend
            .iter()
            .any(|(a, need)| u128::from(framework::Balances::balance(&**ledger, a)) < *need)
        {
            return None;
        }

        self.tick(2, &mut t);
        // Greedy balance: heaviest market to the least-loaded lane (deterministic).
        let mut markets: Vec<(u8, u64)> = (0..=u8::MAX)
            .filter(|m| load[usize::from(*m)] > 0)
            .map(|m| (m, load[usize::from(m)]))
            .collect();
        markets.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut lane_load = vec![0u64; lanes];
        let mut lane_of_market = [NO_LANE; 256];
        for (m, l) in markets {
            let (best, _) = lane_load.iter().enumerate().min_by_key(|(i, w)| (**w, *i))?;
            lane_load[best] += l;
            lane_of_market[usize::from(m)] = u8::try_from(best).ok()?;
        }
        let per_lane = total_items / lanes + 16;
        let mut works: Vec<LaneWork> = (0..lanes)
            .map(|_| LaneWork { items: Vec::with_capacity(per_lane), engines: FastMap::default() })
            .collect();
        for (ti, p) in plans.iter().enumerate() {
            let ti = u32::try_from(ti).ok()?;
            // An item that touches no market fails with no effect; any lane can say so.
            let lane_of =
                |it: &Item| it.market.map(|m| usize::from(lane_of_market[usize::from(m)]));
            if p.shape == Shape::Bundle {
                // A bundle whose items all land on one lane stays whole (assembled inside the lane,
                // in parallel); otherwise its items are scattered and reassembled after the lanes.
                let mut lanes_hit = p.items.iter().filter_map(lane_of);
                let first = lanes_hit.next();
                if lanes_hit.all(|l| Some(l) == first) {
                    works[first.unwrap_or(0)].items.push((ti, WHOLE));
                    continue;
                }
            }
            for (ii, it) in p.items.iter().enumerate() {
                works[lane_of(it).unwrap_or(0)].items.push((ti, u32::try_from(ii).ok()?));
            }
        }
        let mut guard = framework::lock_state(&self.inner);
        for m in 0..=u8::MAX {
            let lane = lane_of_market[usize::from(m)];
            if lane != NO_LANE
                && let Some(e) = guard.markets[usize::from(m)].take()
            {
                works[usize::from(lane)].engines.insert(m, e);
            }
        }

        self.tick(1, &mut t);
        Self::charge_fees(txs, charge);

        self.tick(3, &mut t);
        let store = framework::lock_state(&self.store);
        let maps = Maps {
            dlg: store.inner(),
            height: self.height.load(Ordering::Relaxed),
            bal: guard.base_balances.inner(),
            hold: guard.base_holds.inner(),
            vault: guard.fee_vault.inner(),
        };
        let outs: Vec<LaneOut> =
            works.into_par_iter().map(|w| run_lane(w, txs, &plans, maps)).collect();

        drop(store);
        self.tick(4, &mut t);
        let results = self.merge_lanes(guard, outs, &plans, ledger, &mut t);
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
    /// lanes), net ledger deltas in address order, item results assembled into transaction results.
    fn merge_lanes(
        &self,
        mut guard: std::sync::MutexGuard<'_, super::Inner>,
        outs: Vec<LaneOut>,
        plans: &[TxPlan],
        ledger: &std::sync::Arc<dyn framework::Balances + Send + Sync>,
        t: &mut std::time::Instant,
    ) -> executor::LaneRunResults {
        let mut results: executor::LaneRunResults = (0..plans.len()).map(|_| None).collect();
        // Per-bundle slots, indexed by item, created on the first scattered item of a bundle (a bundle
        // run whole on one lane never needs them).
        let mut slots: Vec<Vec<Slot>> = (0..plans.len()).map(|_| Vec::new()).collect();
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
            for ItemOut { tx, item, result } in out.results {
                let tx = tx as usize;
                if plans[tx].shape == Shape::Bundle && item != WHOLE {
                    if slots[tx].is_empty() {
                        slots[tx] = (0..plans[tx].items.len()).map(|_| None).collect();
                    }
                    slots[tx][item as usize] = Some(result);
                } else {
                    results[tx] = Some(result);
                }
            }
        }
        // Transaction results. An unplayable transaction fails whole. A bundle scattered across
        // lanes gets its events in item order (a failed item becomes the same rejection event the
        // serial path emits); the copying runs on the pool, one bundle per task.
        let mut split: Vec<(usize, Vec<Slot>)> = Vec::new();
        for (i, p) in plans.iter().enumerate() {
            match p.shape {
                Shape::Single => {}
                Shape::Dead => results[i] = Some(Err(ExecError::Malformed)),
                Shape::Bundle => {
                    if results[i].is_none() {
                        split.push((i, std::mem::take(&mut slots[i])));
                    }
                }
            }
        }
        let assembled: Vec<(usize, Vec<Event>)> = split
            .into_par_iter()
            .map(|(i, slots)| {
                let mut events = Vec::new();
                for (idx, slot) in slots.into_iter().enumerate() {
                    match slot {
                        Some(Ok(evs)) => events.extend(evs),
                        Some(Err(e)) => events.push(Self::item_rejected_event(idx, &e)),
                        // Unreachable: every item is assigned to exactly one lane.
                        None => debug_assert!(false, "bundle item never executed"),
                    }
                }
                (i, events)
            })
            .collect();
        for (i, events) in assembled {
            results[i] = Some(Ok(events));
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
