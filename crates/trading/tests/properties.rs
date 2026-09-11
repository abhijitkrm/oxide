//! Property tests: matching engine vs. a naive sequential-model
//! oracle (testing-standards skill, layer 2; plan.md §13 Phase 3
//! acceptance: "matching: book ops == sequential model oracle for
//! arbitrary order sequences").
//!
//! ## The oracle
//!
//! `ModelBook` is a deliberately naive reimplementation: per-side
//! `BTreeMap<price, VecDeque<order>>` plus an id→location map,
//! allocation-heavy, no bitboards, no intrusive lists, no arena.
//! Because its data structures share nothing with the engine's,
//! correlated bugs are vanishingly unlikely — if both agree on
//! outcomes, fills, and resting state for arbitrary op sequences,
//! the engine is faithful to its specification.
//!
//! ## Properties enforced
//!
//! 1. **Outcome equivalence:** every `place` produces the same
//!    outcome on engine and oracle.
//! 2. **Fill equivalence:** identical fill sequences (price, qty,
//!    maker/taker ids, owners, side).
//! 3. **Book-state equivalence:** identical best bid/ask after every
//!    op; identical resting-order sets (price ascending, FIFO within
//!    level) at the end.
//! 4. **Never crossed:** `best_bid < best_ask` after every op.
//! 5. **Id discipline:** engine ids are exactly sequential.

use primitives::Address;
use primitives::fixed::{Price, Qty};
use proptest::prelude::*;
use trading::{
    DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderId, OrderOutcome, OrderType,
    RejectReason, Side, StpMode, TimeInForce,
};

/// Fixture market: tick 0.01, lot 0.001, band [$10, $10.31] → 32
/// levels (dense multi-level sweep coverage in a small ladder).
fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 1,
        tick_size: 1_000_000,
        lot_size: 1_000,
        min_price: 1_000_000_000,
        max_price: 1_031_000_000,
        max_resting: 256,
    }
}

fn engine() -> MatchingEngine {
    MatchingEngine::new(cfg(), DenseBook::new(cfg()).unwrap()).unwrap()
}

/// A deterministic op in the generated stream.
#[derive(Debug, Clone, Copy)]
enum Op {
    /// Submit an order.
    Place(NewOrder),
    /// Cancel the order with this id (may be phantom).
    Cancel(u64),
}

/// Strategy: place ops with all knobs in small, collision-rich
/// ranges — owners 0..4 (self-trades common), prices on a 6-tick
/// window around the band middle, quantities 1..=4 lots.
fn place_strategy() -> impl Strategy<Value = Op> {
    (
        0u8..4,    // owner
        0u64..2,   // side
        0u64..3,   // style: 0 limit, 1 market, 2 post-only
        0u64..3,   // tif: 0 gtc, 1 ioc, 2 fok
        12u64..20, // tick offset (window around mid)
        1u64..5,   // lots
        0u64..4,   // stp mode
    )
        .prop_map(|(owner, side, style, tif, ticks, lots, stp)| {
            let (order_type, tif) = match (style, tif) {
                (1, _) => (OrderType::Market, TimeInForce::Ioc),
                (2, _) => (OrderType::PostOnly, TimeInForce::Gtc),
                (_, 0) => (OrderType::Limit, TimeInForce::Gtc),
                (_, 1) => (OrderType::Limit, TimeInForce::Ioc),
                _ => (OrderType::Limit, TimeInForce::Fok),
            };
            Op::Place(NewOrder {
                side: if side == 0 { Side::Buy } else { Side::Sell },
                order_type,
                tif,
                price: Price(1_000_000_000 + ticks * 1_000_000),
                qty: Qty(lots * 1_000),
                owner: Address([owner; 20]),
                stp: match stp {
                    0 => StpMode::None,
                    1 => StpMode::CancelNewest,
                    2 => StpMode::CancelOldest,
                    _ => StpMode::DecrementAndCancel,
                },
            })
        })
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => place_strategy(),
        1 => (0u64..48).prop_map(Op::Cancel),
    ]
}

// ─── The naive oracle ─────────────────────────────────────────────

/// A resting order in the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ModelOrder {
    id: u64,
    owner: Address,
    qty: u64,
}

/// Where a model order rests.
#[derive(Debug, Clone, Copy)]
struct ModelLoc {
    side: Side,
    price: u64,
}

/// BTreeMap-based reference book implementing the engine's
/// specification as plainly as possible.
struct ModelBook {
    /// Per side: price → FIFO of resting orders.
    bids: std::collections::BTreeMap<u64, std::collections::VecDeque<ModelOrder>>,
    asks: std::collections::BTreeMap<u64, std::collections::VecDeque<ModelOrder>>,
    /// id → location, for cancels.
    loc: std::collections::HashMap<u64, ModelLoc>,
    next_id: u64,
}

impl ModelBook {
    fn new() -> Self {
        ModelBook {
            bids: std::collections::BTreeMap::new(),
            asks: std::collections::BTreeMap::new(),
            loc: std::collections::HashMap::new(),
            next_id: 0,
        }
    }

    fn map(
        &self,
        side: Side,
    ) -> &std::collections::BTreeMap<u64, std::collections::VecDeque<ModelOrder>> {
        match side {
            Side::Buy => &self.bids,
            Side::Sell => &self.asks,
        }
    }

    fn map_mut(
        &mut self,
        side: Side,
    ) -> &mut std::collections::BTreeMap<u64, std::collections::VecDeque<ModelOrder>> {
        match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        }
    }

    fn best(&self, side: Side) -> Option<u64> {
        match side {
            Side::Buy => self.bids.keys().next_back().copied(),
            Side::Sell => self.asks.keys().next().copied(),
        }
    }

    /// Remove the FIFO head at `price` on `side`.
    fn pop_maker(&mut self, side: Side, price: u64) -> Option<ModelOrder> {
        let deque = self.map_mut(side).get_mut(&price)?;
        let head = deque.pop_front()?;
        if deque.is_empty() {
            self.map_mut(side).remove(&price);
        }
        self.loc.remove(&head.id);
        Some(head)
    }

    /// Rest an order.
    fn rest(&mut self, side: Side, price: u64, order: ModelOrder) {
        self.loc.insert(order.id, ModelLoc { side, price });
        self.map_mut(side).entry(price).or_default().push_back(order);
    }

    /// Is `price` marketable for a `taker_side` order with limit
    /// `limit` (None = market, unbounded)?
    fn marketable(taker_side: Side, price: u64, limit: Option<u64>) -> bool {
        match (taker_side, limit) {
            (Side::Buy, Some(lim)) => price <= lim,
            (Side::Sell, Some(lim)) => price >= lim,
            (_, None) => true,
        }
    }

    /// Replay a placement per the engine's specification.
    // The oracle's `place` deliberately mirrors the engine's sweep
    // structure 1:1 (testing-standards: correlated-bug avoidance
    // comes from different data structures, not different control
    // flow); the labeled-loop shape is required for the mid-sweep
    // STP exits.
    #[allow(clippy::too_many_lines, clippy::while_let_loop)]
    fn place(&mut self, req: &NewOrder) -> (OrderOutcome, Vec<FillEvent>) {
        let taker_id = self.next_id;
        self.next_id += 1;
        let mut fills = Vec::new();
        let mut rem = req.qty.0;
        let opposite = req.side.opposite();
        let limit = match req.order_type {
            OrderType::Market => None,
            _ => Some(req.price.0),
        };

        // Post-only: reject if it would cross.
        if req.order_type == OrderType::PostOnly {
            let would = match req.side {
                Side::Buy => self.best(Side::Sell).is_some_and(|a| a <= req.price.0),
                Side::Sell => self.best(Side::Buy).is_some_and(|b| b >= req.price.0),
            };
            if would {
                return (OrderOutcome::Rejected(RejectReason::PostOnlyWouldCross), fills);
            }
        }

        // FOK pre-scan (STP-blind, matching the engine's documented
        // behavior).
        if req.tif == TimeInForce::Fok {
            let mut fillable = 0u64;
            let prices: Vec<u64> = self.map(opposite).keys().copied().collect();
            // Best-first iteration.
            let ordered: Vec<u64> = match opposite {
                Side::Buy => prices.into_iter().rev().collect(),
                Side::Sell => prices,
            };
            for price in ordered {
                if !Self::marketable(req.side, price, limit) {
                    break;
                }
                fillable += self
                    .map(opposite)
                    .get(&price)
                    .map_or(0, |d| d.iter().map(|o| o.qty).sum::<u64>());
                if fillable >= rem {
                    break;
                }
            }
            if fillable < rem {
                return (OrderOutcome::Killed, fills);
            }
        }

        // Match loop: sweep best opposite levels, FIFO within level.
        'sweep: loop {
            let Some(opp_price) = self.best(opposite) else { break };
            if !Self::marketable(req.side, opp_price, limit) {
                break;
            }
            loop {
                // Read the head by value (scoped borrow).
                let head = {
                    let Some(deque) = self.map(opposite).get(&opp_price) else { break };
                    match deque.front() {
                        Some(h) => *h,
                        None => break,
                    }
                };
                let m_id = head.id;
                let m_qty = head.qty;
                let m_owner = head.owner;

                // Self-trade prevention.
                if m_owner == req.owner {
                    match req.stp {
                        StpMode::CancelNewest => {
                            // The taker's remainder is canceled — never
                            // rested, regardless of TIF.
                            return (
                                OrderOutcome::CanceledRemainder {
                                    order_id: OrderId(taker_id),
                                    filled_qty: Qty(req.qty.0 - rem),
                                },
                                fills,
                            );
                        }
                        StpMode::CancelOldest => {
                            self.pop_maker(opposite, opp_price);
                            continue;
                        }
                        StpMode::DecrementAndCancel => {
                            if m_qty <= rem {
                                self.pop_maker(opposite, opp_price);
                                rem -= m_qty;
                            } else {
                                // Taker consumed decrementing the maker.
                                let deque = self.map_mut(opposite).get_mut(&opp_price).unwrap();
                                deque.front_mut().unwrap().qty -= rem;
                                rem = 0;
                            }
                            if rem == 0 {
                                break 'sweep;
                            }
                            continue;
                        }
                        StpMode::None => {}
                    }
                }

                // Normal fill.
                let fill = rem.min(m_qty);
                fills.push(FillEvent {
                    price: Price(opp_price),
                    qty: Qty(fill),
                    maker_order_id: OrderId(m_id),
                    maker_owner: m_owner,
                    taker_order_id: OrderId(taker_id),
                    taker_owner: req.owner,
                    taker_side: req.side,
                });
                {
                    let deque = self.map_mut(opposite).get_mut(&opp_price).unwrap();
                    deque.front_mut().unwrap().qty -= fill;
                }
                rem -= fill;
                if fill == m_qty {
                    self.pop_maker(opposite, opp_price);
                }
                if rem == 0 {
                    break 'sweep;
                }
            }
        }

        // Remainder disposition.
        if rem > 0 && req.tif == TimeInForce::Gtc {
            self.rest(
                req.side,
                req.price.0,
                ModelOrder { id: taker_id, owner: req.owner, qty: rem },
            );
        }
        (Self::outcome(taker_id, req, rem), fills)
    }

    fn outcome(taker_id: u64, req: &NewOrder, rem: u64) -> OrderOutcome {
        if rem == 0 {
            return OrderOutcome::Filled;
        }
        match req.tif {
            TimeInForce::Gtc => OrderOutcome::Resting {
                order_id: OrderId(taker_id),
                price: req.price,
                resting_qty: Qty(rem),
            },
            TimeInForce::Ioc | TimeInForce::Fok => OrderOutcome::CanceledRemainder {
                order_id: OrderId(taker_id),
                filled_qty: Qty(req.qty.0 - rem),
            },
        }
    }

    fn cancel(&mut self, id: u64) -> Option<ModelLoc> {
        let loc = self.loc.remove(&id)?;
        let deque = self.map_mut(loc.side).get_mut(&loc.price)?;
        if let Some(pos) = deque.iter().position(|o| o.id == id) {
            deque.remove(pos);
        }
        if deque.is_empty() {
            self.map_mut(loc.side).remove(&loc.price);
        }
        Some(loc)
    }

    /// Resting orders in engine order (price ascending, FIFO within
    /// level — FIFO == id order because ids are assigned on arrival).
    fn resting_set(&self) -> Vec<(u64, Side, u64, u64, Address)> {
        let mut out: Vec<(u64, Side, u64, u64, Address)> = Vec::new();
        for (price, deque) in self.bids.iter().chain(self.asks.iter()) {
            for o in deque {
                let side = if self.bids.contains_key(price) { Side::Buy } else { Side::Sell };
                out.push((o.id, side, *price, o.qty, o.owner));
            }
        }
        // Bids iterate before asks; merge by price (a price is never
        // both a bid and an ask level — the book is never crossed),
        // then by id (FIFO).
        out.sort_by_key(|(id, _, price, _, _)| (*price, *id));
        out
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The master property (plan.md §13 Phase 3): engine and oracle
    /// agree on outcomes, fills, and resting state over arbitrary op
    /// sequences; the book is never crossed; ids are sequential.
    #[test]
    fn engine_matches_sequential_model_oracle(ops in prop::collection::vec(op_strategy(), 1..120)) {
        let mut e = engine();
        let mut model = ModelBook::new();
        let mut fills_engine = Vec::new();
        let mut next_expected_id: u64 = 0;

        for op in &ops {
            match op {
                Op::Place(req) => {
                    // Skip orders the engine statically rejects — the
                    // oracle doesn't model tick/lot validation (that
                    // is unit-tested in order.rs).
                    if req.validate(cfg().tick_size, cfg().lot_size, cfg().min_price, cfg().max_price).is_err() {
                        continue;
                    }

                    fills_engine.clear();
                    let out_e = e.place(*req, &mut fills_engine).unwrap();
                    let (out_m, fills_m) = model.place(req);

                    // Id discipline: one id consumed per placement.
                    next_expected_id += 1;
                    prop_assert_eq!(e.next_order_id(), next_expected_id);

                    // Outcome equivalence.
                    prop_assert_eq!(out_e, out_m, "outcome mismatch at op {}", next_expected_id);

                    // Fill equivalence (order and content).
                    prop_assert_eq!(fills_engine.as_slice(), fills_m.as_slice(), "fill mismatch at op {}", next_expected_id);
                }
                Op::Cancel(id) => {
                    let res_e = e.cancel(OrderId(*id));
                    let res_m = model.cancel(*id);
                    // Both must agree on existence.
                    prop_assert_eq!(res_e.is_ok(), res_m.is_some(), "cancel existence mismatch for id {}", id);
                }
            }

            // Book-state equivalence after every op: best bid/ask.
            prop_assert_eq!(e.best_bid().map(|(p, _)| p.0), model.best(Side::Buy));
            prop_assert_eq!(e.best_ask().map(|(p, _)| p.0), model.best(Side::Sell));

            // Never crossed.
            if let (Some((b, _)), Some((a, _))) = (e.best_bid(), e.best_ask()) {
                prop_assert!(b.0 < a.0, "crossed book: bid {:?} >= ask {:?}", b.0, a.0);
            }
        }

        // Final resting-state equivalence: level order + FIFO.
        let mut engine_entries = Vec::new();
        e.resting_entries(&mut engine_entries);
        let model_entries = model.resting_set();
        prop_assert_eq!(engine_entries.len(), model_entries.len());
        for (ge, me) in engine_entries.iter().zip(model_entries.iter()) {
            prop_assert_eq!((ge.id.0, ge.side, ge.price.0, ge.qty.0, ge.owner), *me);
        }
    }
}
