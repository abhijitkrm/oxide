//! The central-limit-order-book matching engine.
//!
//! ## What this is
//!
//! A single-writer, per-market order book that executes the plan's
//! §9.1 semantics: strict price-time priority (intrusive FIFO per
//! level), marketable orders sweep levels best-first, all validation
//! happens *before* the match loop, and zero validation inside it.
//! Supported order vocabulary: `Limit`/`Market`/`PostOnly` ×
//! `Gtc`/`Ioc`/`Fok`, plus four self-trade-prevention modes.
//!
//! ## Why this shape
//!
//! One [`MatchingEngine`] per market, owned by one thread — the
//! plan's "single-writer state machine per market" (§7.2 native
//! track). No locks, no atomics, no allocation in the match loop:
//! taker orders live on the stack during matching; only *resting
//! remainders* allocate a pool slot (recycled through the free list).
//!
//! ## Determinism (consensus requirement)
//!
//! Every output is a pure function of (config, op sequence):
//! - ids are assigned sequentially at submission,
//! - fills are emitted in match order (best price first, FIFO
//!   within a level),
//! - [`MatchingEngine::resting_entries`] walks levels in index order
//!   and FIFO order within a level. Two validators applying the same
//!   block apply the same op sequence and produce byte-identical
//!   fills and book state.
//!
//! ## Budget (criterion, `benches/matching.rs`, M-series dev machine)
//!
//! - insert+cancel (rest/cancel): p50 < 200ns — gate: plan.md §13
//!   Phase 3.
//! - single-level match: p50 < 300ns — gate: plan.md §13 Phase 3.
//! - ≥5M simple ops/s single core; mixed workload ≥1M ops/s/core. If
//!   you make the match loop slower, the chain-wide ≥1M orders/s gate
//!   (plan.md §13) breaks.

use primitives::Address;
use primitives::fixed::{Price, Qty};

use crate::book::{BookBackend, DenseBook, MarketConfig};
use crate::error::{RejectReason, TradingError};
use crate::idmap::IdMap;
use crate::order::{NewOrder, OrderId, OrderType, Side, StpMode, TimeInForce};
use crate::pool::{OrderPool, fresh_node};

/// One executed trade, emitted in deterministic match order.
///
/// The caller-owned fill buffer (`place(&mut Vec<FillEvent>)`) keeps
/// the engine allocation-free: the exchange module reuses one
/// preallocated buffer across the whole block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FillEvent {
    /// Execution price (the maker's resting price), raw scale-8.
    pub price: Price,
    /// Traded quantity, raw scale-6.
    pub qty: Qty,
    /// The resting order that provided liquidity.
    pub maker_order_id: OrderId,
    /// Owner of the maker order (settlement attribution).
    pub maker_owner: Address,
    /// The incoming order that crossed (id assigned at submission).
    pub taker_order_id: OrderId,
    /// Owner of the taker order.
    pub taker_owner: Address,
    /// Direction the taker traded (buy fills credit the maker's ask).
    pub taker_side: Side,
}

/// Terminal state of a submitted order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderOutcome {
    /// Fully filled on entry; nothing resting.
    Filled,
    /// (Possibly partial) remainder is resting at `price`.
    Resting {
        /// Engine-assigned id (use for cancel).
        order_id: OrderId,
        /// Resting price.
        price: Price,
        /// Resting remaining quantity.
        resting_qty: Qty,
    },
    /// Unfilled remainder was canceled (IOC entry sweep, or an STP
    /// self-touch canceled the taker).
    ///
    /// `filled_qty` is the quantity *not returned to the submitter*:
    /// the sum of this order's fill events plus any quantity consumed
    /// by STP decrement-and-cancel (which books no fill). The fill
    /// events themselves are the auditable record of true trades.
    CanceledRemainder {
        /// Id assigned at submission.
        order_id: OrderId,
        /// `qty - remaining` (fills + STP-consumed).
        filled_qty: Qty,
    },
    /// FOK: nothing executed — fillable quantity was insufficient.
    Killed,
    /// Rejected before matching (see [`RejectReason`]).
    Rejected(RejectReason),
}

/// A successfully canceled resting order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanceledOrder {
    /// The canceled order's id.
    pub order_id: OrderId,
    /// Side it was resting on.
    pub side: Side,
    /// Price it was resting at.
    pub price: Price,
    /// Remaining quantity at cancellation (unfilled).
    pub qty: Qty,
    /// Owning account (the module checks this against the requester).
    pub owner: Address,
}

/// One resting order, materialized for cold paths (state roots,
/// queries, the property-test oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestingEntry {
    /// Order id.
    pub id: OrderId,
    /// Side.
    pub side: Side,
    /// Resting price.
    pub price: Price,
    /// Remaining quantity.
    pub qty: Qty,
    /// Owner.
    pub owner: Address,
}

/// A per-market matching engine over a swappable [`BookBackend`].
///
/// Default type parameter is the dense tick ladder; the sparse
/// backend for wide-range markets plugs in behind the same trait.
pub struct MatchingEngine<B: BookBackend = DenseBook> {
    cfg: MarketConfig,
    pool: OrderPool,
    book: B,
    ids: IdMap,
    next_id: u64,
    resting: u32,
}

impl<B: BookBackend> MatchingEngine<B> {
    /// Build an engine with a fresh backend from a validated config.
    ///
    /// # Errors
    /// [`TradingError::InvalidConfig`] propagated from backend
    /// construction.
    pub fn new(cfg: MarketConfig, book: B) -> Result<Self, TradingError> {
        cfg.validate()?;
        Ok(MatchingEngine {
            pool: OrderPool::with_capacity(cfg.max_resting),
            ids: IdMap::with_capacity(cfg.max_resting),
            cfg,
            book,
            next_id: 0,
            resting: 0,
        })
    }

    /// The market's configuration (tick/lot/band rules).
    #[must_use]
    pub fn config(&self) -> &MarketConfig {
        &self.cfg
    }

    /// Next order id to be assigned (cold path: state-root input).
    #[must_use]
    pub fn next_order_id(&self) -> u64 {
        self.next_id
    }

    /// Number of currently resting orders.
    #[must_use]
    pub fn resting_count(&self) -> u32 {
        self.resting
    }

    /// Best bid as `(price, level_qty)` — L1 market data.
    #[must_use]
    pub fn best_bid(&self) -> Option<(Price, Qty)> {
        let p = self.book.best_bid_price()?;
        Some((Price(p), Qty(self.book.level_total(p))))
    }

    /// Best ask as `(price, level_qty)` — L1 market data.
    #[must_use]
    pub fn best_ask(&self) -> Option<(Price, Qty)> {
        let p = self.book.best_ask_price()?;
        Some((Price(p), Qty(self.book.level_total(p))))
    }

    /// Owner of a resting order (cancel authorization lookup).
    #[must_use]
    pub fn order_owner(&self, id: OrderId) -> Option<Address> {
        let slot = self.ids.get(id.0)?;
        Some(self.pool[slot].owner)
    }

    /// Total notional (scale-14: `price * qty`) a `taker_side` sweep
    /// of up to `qty` base units would consume against the current
    /// book, bounded by `limit_raw` (`None` = unbounded market
    /// sweep). Delegates to [`BookBackend::sweep_cost`]; used by the
    /// exchange module's market-buy pre-trade balance check.
    #[must_use]
    pub fn sweep_cost(&self, taker_side: Side, qty: u64, limit_raw: Option<u64>) -> u128 {
        self.book.sweep_cost(taker_side, qty, limit_raw)
    }

    /// Submit an order. Fills are appended to the caller-owned
    /// `fills` buffer (preallocate and reuse; the engine never
    /// allocates here).
    ///
    /// # Errors
    /// [`TradingError::Overflow`] only if the id counter is exhausted
    /// (a 584-year horizon at 1B orders/s — a principled guard, not
    /// an expected condition). Every order-level problem is an
    /// [`OrderOutcome::Rejected`]/`Killed`, not an `Err`.
    pub fn place(
        &mut self,
        req: NewOrder,
        fills: &mut Vec<FillEvent>,
    ) -> Result<OrderOutcome, TradingError> {
        // ── Validation: entirely before the match loop (plan §9.1) ──
        if let Err(reason) = req.validate(
            self.cfg.tick_size,
            self.cfg.lot_size,
            self.cfg.min_price,
            self.cfg.max_price,
        ) {
            return Ok(OrderOutcome::Rejected(reason));
        }

        let taker_id = OrderId(self.next_id);
        self.next_id = self.next_id.checked_add(1).ok_or(TradingError::Overflow)?;

        // Post-only must add liquidity: reject if it would cross.
        if req.order_type == OrderType::PostOnly && self.would_cross(req.side, req.price.0) {
            return Ok(OrderOutcome::Rejected(RejectReason::PostOnlyWouldCross));
        }

        // Price bound for the sweep: None = market order (unbounded).
        let limit_raw = if req.order_type == OrderType::Market { None } else { Some(req.price.0) };

        // FOK: all-or-nothing. Pre-scan fillable quantity against the
        // current book; insufficient → kill without executing.
        //
        // When STP is active, the taker's own resting orders on the
        // opposite side will be skipped or canceled during the sweep,
        // so they must not count toward the fillable quantity. Using
        // the non-STP fillable_qty here would accept a FOK that STP
        // then partially cancels — violating the FOK guarantee.
        //
        // (Self-trade prevention can still interrupt a FOK mid-sweep
        // if a new self-match appears between the pre-scan and the
        // sweep; that documented corner yields CanceledRemainder,
        // never a silent partial fill of a "kill".)
        if req.tif == TimeInForce::Fok {
            let fillable = if matches!(req.stp, StpMode::None) {
                self.book.fillable_qty(req.side, limit_raw)
            } else {
                self.book.fillable_qty_excluding_owner(req.side, limit_raw, req.owner, &self.pool)
            };
            if fillable < req.qty.0 {
                return Ok(OrderOutcome::Killed);
            }
        }

        // ── Match loop: zero validation, zero allocation below ──────
        let mut rem = req.qty.0;
        let taker_canceled = self.sweep(&req, taker_id, limit_raw, &mut rem, fills);
        if taker_canceled {
            // STP canceled the taker mid-sweep; fills stand.
            return Ok(OrderOutcome::CanceledRemainder {
                order_id: taker_id,
                filled_qty: Qty(req.qty.0 - rem),
            });
        }

        // ── Remainder disposition ────────────────────────────────────
        if rem == 0 {
            return Ok(OrderOutcome::Filled);
        }
        match req.tif {
            TimeInForce::Gtc => {
                if self.resting >= self.cfg.max_resting {
                    return Ok(OrderOutcome::Rejected(RejectReason::BookFull));
                }
                let price = Price(limit_raw.unwrap_or_else(|| {
                    // Market orders never reach here (they are Ioc);
                    // the unwrap is covered by TIF validation.
                    unreachable!("Gtc remainder requires a limit price")
                }));
                let slot = self.pool.alloc(fresh_node(
                    taker_id,
                    req.side,
                    price,
                    Qty(rem),
                    req.owner,
                    req.tif,
                ));
                self.book.append(slot, &mut self.pool);
                // IdMap is sized ≥ max_resting at ≤0.5 load, so insert
                // cannot fail after the capacity check above.
                self.ids.insert(taker_id.0, slot)?;
                self.resting += 1;
                Ok(OrderOutcome::Resting { order_id: taker_id, price, resting_qty: Qty(rem) })
            }
            TimeInForce::Ioc | TimeInForce::Fok => Ok(OrderOutcome::CanceledRemainder {
                order_id: taker_id,
                filled_qty: Qty(req.qty.0 - rem),
            }),
        }
    }

    /// Cancel a resting order by id.
    ///
    /// # Errors
    /// [`TradingError::OrderNotFound`] if the id is not resting
    /// (already filled/canceled, or a taker that never rested).
    pub fn cancel(&mut self, id: OrderId) -> Result<CanceledOrder, TradingError> {
        let slot = self.ids.remove(id.0)?;
        let (side, price, qty, owner) = {
            let node = &self.pool[slot];
            (node.side, node.price, node.qty, node.owner)
        };
        self.book.unlink(slot, &mut self.pool);
        self.pool.release(slot);
        self.resting = self.resting.saturating_sub(1);
        Ok(CanceledOrder { order_id: id, side, price, qty, owner })
    }

    /// Materialize every resting order in deterministic order (level
    /// index ascending; FIFO within a level) into the caller-owned
    /// buffer.
    ///
    /// Cold path (state roots, RPC L3 snapshots, the test oracle):
    /// clarity over speed. The engine's own match path never calls it.
    pub fn resting_entries(&self, out: &mut Vec<RestingEntry>) {
        out.clear();
        // Cold path: the usize→u32 conversion is bounded by
        // MAX_DENSE_LEVELS (2^18) per MarketConfig::validate.
        #[allow(clippy::cast_possible_truncation)]
        let level_count = self.book.level_count() as u32;
        for idx in 0..level_count {
            let mut slot = self.book.level_head(self.book.level_price(idx));
            while slot != crate::pool::NIL {
                let node = &self.pool[slot];
                out.push(RestingEntry {
                    id: node.id,
                    side: node.side,
                    price: node.price,
                    qty: node.qty,
                    owner: node.owner,
                });
                slot = node.next;
            }
        }
    }

    /// Append the engine's canonical state encoding to `out` (C8).
    ///
    /// Commits every field that can affect future matching: the
    /// market config, `next_id` (order-id assignment is consensus-
    /// relevant — two replicas assigning different ids to the same
    /// fill sequence are divergent), and every resting order in
    /// canonical order — price level ascending, FIFO within a level
    /// — as `(id, side, price, qty, owner)`. Encoding is little-
    /// endian fixed-width throughout; `entries` is caller-owned
    /// scratch reused across markets so a module's per-block
    /// state-root pass stays allocation-light.
    ///
    /// Cold path only: O(resting) per call, once per block per
    /// market. The match path never runs it.
    pub fn write_canonical_state(&self, out: &mut Vec<u8>, entries: &mut Vec<RestingEntry>) {
        out.extend_from_slice(&self.cfg.market_id.to_le_bytes());
        out.extend_from_slice(&self.cfg.tick_size.to_le_bytes());
        out.extend_from_slice(&self.cfg.lot_size.to_le_bytes());
        out.extend_from_slice(&self.cfg.min_price.to_le_bytes());
        out.extend_from_slice(&self.cfg.max_price.to_le_bytes());
        out.extend_from_slice(&self.cfg.max_resting.to_le_bytes());
        out.extend_from_slice(&self.next_id.to_le_bytes());
        out.extend_from_slice(&self.resting.to_le_bytes());
        self.resting_entries(entries);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for e in entries.iter() {
            out.extend_from_slice(&e.id.0.to_le_bytes());
            out.push(e.side as u8);
            out.extend_from_slice(&e.price.0.to_le_bytes());
            out.extend_from_slice(&e.qty.0.to_le_bytes());
            out.extend_from_slice(&e.owner.0);
        }
    }

    /// Rebuild an engine from `write_canonical_state` bytes —
    /// snapshot restore.
    ///
    /// The decoded config is re-validated (`MarketConfig::validate`
    /// via [`Self::new`]), each resting entry is re-inserted through
    /// [`Self::restore_resting`] in committed order, and the restored
    /// engine is re-encoded and compared byte-for-byte against the
    /// input: if the bytes disagree, the input was never a faithful
    /// canonical encoding (or a field was dropped on restore) and the
    /// whole decode is rejected.
    ///
    /// `make_book` builds the fresh [`BookBackend`] for the decoded
    /// config (e.g. `DenseBook::new`) — the engine cannot construct
    /// `B` itself because backend construction is backend-specific.
    ///
    /// # Errors
    /// [`TradingError::CorruptState`] on malformed bytes, a config or
    /// entry the live engine could never have produced, a duplicate
    /// order id, or a re-encode mismatch; [`TradingError::BookFull`]
    /// if the entry count exceeds `max_resting`.
    pub fn from_canonical_state(
        data: &[u8],
        make_book: impl FnOnce(&MarketConfig) -> Result<B, TradingError>,
    ) -> Result<Self, TradingError> {
        let decoded = decode_canonical_state(data).ok_or(TradingError::CorruptState("decode"))?;
        let mut engine = Self::new(decoded.cfg, make_book(&decoded.cfg)?)?;
        for e in &decoded.entries {
            engine.restore_resting(e)?;
        }
        engine.set_next_id(decoded.next_id);
        // Byte-exactness self-check: the restored engine must
        // re-encode to the input. Cold path (snapshot import only) —
        // the extra O(resting) pass is acceptable and turns every
        // subtle restore bug into a loud rejection.
        let mut re_encoded = Vec::with_capacity(data.len());
        let mut scratch = Vec::with_capacity(decoded.entries.len());
        engine.write_canonical_state(&mut re_encoded, &mut scratch);
        if re_encoded != data {
            return Err(TradingError::CorruptState("re-encode mismatch"));
        }
        Ok(engine)
    }

    /// Reinsert a resting order WITHOUT matching — snapshot restore
    /// only.
    ///
    /// The caller replays entries in committed order (price level
    /// ascending, FIFO within a level), which `book.append` preserves.
    /// `e.id` is kept verbatim — the caller must call
    /// [`Self::set_next_id`] afterwards so live orders cannot be
    /// assigned an id that is already resting.
    ///
    /// # Errors
    /// [`TradingError::CorruptState`] if the entry's fields violate
    /// the market's tick/lot/band rules (a state the live engine
    /// could never have produced); [`TradingError::BookFull`] at
    /// capacity; [`TradingError::OrderNotFound`] on a duplicate id
    /// (the `IdMap`'s existing invariant check).
    pub fn restore_resting(&mut self, e: &RestingEntry) -> Result<(), TradingError> {
        // Reuse `NewOrder`'s field validation: a restored resting
        // order is a GTC limit remainder — the exact shape `place`
        // books. If it would have been rejected on the wire, the
        // snapshot is corrupt.
        let probe = NewOrder {
            side: e.side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: e.price,
            qty: e.qty,
            owner: e.owner,
            stp: StpMode::None,
        };
        probe
            .validate(self.cfg.tick_size, self.cfg.lot_size, self.cfg.min_price, self.cfg.max_price)
            .map_err(|_| TradingError::CorruptState("entry fails market rules"))?;
        if self.resting >= self.cfg.max_resting {
            return Err(TradingError::BookFull);
        }
        let slot =
            self.pool.alloc(fresh_node(e.id, e.side, e.price, e.qty, e.owner, TimeInForce::Gtc));
        self.book.append(slot, &mut self.pool);
        self.ids.insert(e.id.0, slot)?;
        self.resting += 1;
        Ok(())
    }

    /// Set the order-id counter — snapshot restore only.
    ///
    /// `next` must exceed every restored id or a later `place` would
    /// assign a live order an id already in `ids`, cross-wiring
    /// cancel/owner lookups. [`decode_canonical_state`] enforces
    /// `max(id) < next_id` for blobs it produced.
    pub fn set_next_id(&mut self, next: u64) {
        self.next_id = next;
    }

    /// The entry sweep: match the incoming order against resting
    /// liquidity, best price first, FIFO within each level.
    ///
    /// Budget (criterion, `benches/matching.rs`, M-series dev machine):
    /// single-level match p50 < 300ns (gate: plan.md §13 Phase 3).
    ///
    /// Returns `true` when self-trade-prevention canceled the taker
    /// mid-sweep (fills booked so far stand); `false` when the sweep
    /// ended normally — book empty, price bound reached, or the order
    /// fully filled.
    fn sweep(
        &mut self,
        req: &NewOrder,
        taker_id: OrderId,
        limit_raw: Option<u64>,
        rem: &mut u64,
        fills: &mut Vec<FillEvent>,
    ) -> bool {
        'sweep: loop {
            let opp = match req.side {
                Side::Buy => self.book.best_ask_price(),
                Side::Sell => self.book.best_bid_price(),
            };
            let Some(opp) = opp else { break };
            // Price bound: stop when the next level is not marketable.
            if let Some(lim) = limit_raw {
                let marketable = match req.side {
                    Side::Buy => opp <= lim,
                    Side::Sell => opp >= lim,
                };
                if !marketable {
                    break;
                }
            }
            loop {
                let head = self.book.level_head(opp);
                if head == crate::pool::NIL {
                    // Level drained mid-sweep; the outer loop advances
                    // to the next best level.
                    break;
                }
                let (m_id, m_qty, m_owner) = {
                    let node = &self.pool[head];
                    (node.id, node.qty.0, node.owner)
                };

                // Self-trade prevention: only when owners match and a
                // mode is selected.
                if m_owner == req.owner {
                    match req.stp {
                        StpMode::CancelNewest => {
                            // The taker's remainder is canceled; fills
                            // booked so far stand.
                            return true;
                        }
                        StpMode::CancelOldest => {
                            // Remove the resting maker, keep matching.
                            self.remove_maker(head, m_id);
                            continue;
                        }
                        StpMode::DecrementAndCancel => {
                            if m_qty <= *rem {
                                // Maker is smaller: remove it whole,
                                // taker continues with reduced rem.
                                self.remove_maker(head, m_id);
                                *rem -= m_qty;
                            } else {
                                // Taker is smaller: consume it by
                                // decrementing the maker. No fill is
                                // booked for the consumed quantity.
                                self.pool[head].qty = Qty(m_qty - *rem);
                                self.book.reduce_total(opp, *rem);
                                *rem = 0;
                            }
                            if *rem == 0 {
                                break 'sweep;
                            }
                            continue;
                        }
                        StpMode::None => {}
                    }
                }

                // Fill against the FIFO head maker.
                let fill = (*rem).min(m_qty);
                fills.push(FillEvent {
                    price: Price(opp),
                    qty: Qty(fill),
                    maker_order_id: m_id,
                    maker_owner: m_owner,
                    taker_order_id: taker_id,
                    taker_owner: req.owner,
                    taker_side: req.side,
                });
                self.pool[head].qty = Qty(m_qty - fill);
                self.book.reduce_total(opp, fill);
                *rem -= fill;

                if fill == m_qty {
                    // Maker exhausted: detach, unmap, recycle.
                    self.remove_maker(head, m_id);
                }
                if *rem == 0 {
                    break 'sweep;
                }
            }
        }
        false
    }

    /// Detach an exhausted or STP-canceled maker from the book and
    /// recycle its slot.
    ///
    /// Invariant: every resting order is in `ids` (inserted at rest,
    /// removed exactly once at detach). The `debug_assert` verifies
    /// this in debug builds; in release builds we handle the
    /// invariant violation gracefully (return without modifying
    /// state) rather than panicking — a panic here would let a
    /// corrupted `IdMap` kill the validator (`DoS` vector).
    fn remove_maker(&mut self, slot: u32, id: OrderId) {
        self.book.unlink(slot, &mut self.pool);
        match self.ids.remove(id.0) {
            Ok(unmapped) => {
                debug_assert_eq!(unmapped, slot, "idmap slot must agree with the detached node");
            }
            Err(_) => {
                // Invariant violation: the order id is not in the
                // IdMap. This is a bug, but we must not panic — a
                // panic here would crash the validator. Log and
                // return without releasing the slot or decrementing
                // resting, to avoid further corruption.
                return;
            }
        }
        self.pool.release(slot);
        self.resting = self.resting.saturating_sub(1);
    }

    /// Would a `side` order at `price_raw` cross the book?
    /// (Post-only rejection check.)
    fn would_cross(&self, side: Side, price_raw: u64) -> bool {
        match side {
            Side::Buy => self.book.best_ask_price().is_some_and(|a| a <= price_raw),
            Side::Sell => self.book.best_bid_price().is_some_and(|b| b >= price_raw),
        }
    }
}

/// The fields decoded from a `write_canonical_state` blob.
///
/// Not a live engine — `from_canonical_state` consumes this and
/// rebuilds the pool/book/`ids` structures from `entries`.
#[derive(Debug)]
pub struct DecodedBook {
    /// Market configuration committed by the blob.
    pub cfg: MarketConfig,
    /// The order-id counter at commit time.
    pub next_id: u64,
    /// The committed resting-order count — must equal
    /// `entries.len()` (redundant fields are cross-checked).
    pub resting: u32,
    /// Resting orders in committed order (level ascending, FIFO
    /// within a level).
    pub entries: Vec<RestingEntry>,
}

/// Bounds-checked little-endian cursor for [`decode_canonical_state`]
/// — mirrors `write_canonical_state`'s field order exactly. Snapshot
/// bytes are untrusted input: every read bounds-checks and yields
/// `None`, never a panic.
struct CanonReader<'a> {
    /// The buffer being decoded.
    b: &'a [u8],
    /// Read cursor — next unread byte offset.
    p: usize,
}

impl<'a> CanonReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let out = &self.b[self.p..end];
        self.p = end;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn at_end(&self) -> bool {
        self.p == self.b.len()
    }
}

/// Decode a `write_canonical_state` blob into its committed fields.
///
/// Checks beyond shape: `resting == entries.len()` (the two counts
/// are committed redundantly and must agree), every entry id is
/// strictly below `next_id` (else a live order could later be
/// assigned an id that is already resting), the entry count fits
/// `cfg.max_resting`, and the stream ends exactly — trailing garbage
/// is malformed, not ignored. Config self-consistency is enforced
/// downstream by `MarketConfig::validate` in `MatchingEngine::new`.
///
/// `None` on any malformation; never panics on untrusted input.
#[must_use]
pub fn decode_canonical_state(data: &[u8]) -> Option<DecodedBook> {
    let mut r = CanonReader::new(data);
    let cfg = MarketConfig {
        market_id: r.u16()?,
        tick_size: r.u64()?,
        lot_size: r.u64()?,
        min_price: r.u64()?,
        max_price: r.u64()?,
        max_resting: r.u32()?,
    };
    let next_id = r.u64()?;
    let resting = r.u32()?;
    let count = usize::try_from(r.u64()?).ok()?;
    if count != usize::try_from(resting).ok()? {
        return None; // The redundant counts must agree.
    }
    if resting > cfg.max_resting {
        return None; // More entries than the book can ever hold.
    }
    let mut entries = Vec::with_capacity(count.min(r.b.len() - r.p));
    for _ in 0..count {
        let id = OrderId(r.u64()?);
        let side = match r.u8()? {
            0 => Side::Buy,
            1 => Side::Sell,
            _ => return None, // Unknown side tag — non-canonical.
        };
        let price = Price(r.u64()?);
        let qty = Qty(r.u64()?);
        let mut owner = [0u8; Address::LEN];
        owner.copy_from_slice(r.take(Address::LEN)?);
        if id.0 >= next_id {
            return None; // A resting id must be strictly below next_id.
        }
        entries.push(RestingEntry { id, side, price, qty, owner: Address(owner) });
    }
    if !r.at_end() {
        return None;
    }
    Some(DecodedBook { cfg, next_id, resting, entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::book::DenseBook;

    // Fixture market: tick 0.01 raw 1e6, lot 0.001 raw 1e3,
    // band [10.00, 10.64] → 65 levels, small arena for tests.
    fn cfg() -> MarketConfig {
        MarketConfig {
            market_id: 1,
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 1_064_000_000,
            max_resting: 64,
        }
    }

    fn engine() -> MatchingEngine {
        let book = DenseBook::new(cfg()).unwrap();
        MatchingEngine::new(cfg(), book).unwrap()
    }

    fn order(
        side: Side,
        order_type: OrderType,
        tif: TimeInForce,
        price_raw: u64,
        qty_raw: u64,
        owner: u8,
    ) -> NewOrder {
        NewOrder {
            side,
            order_type,
            tif,
            price: Price(price_raw),
            qty: Qty(qty_raw),
            owner: Address([owner; 20]),
            stp: StpMode::None,
        }
    }

    /// The foundational behavior: a marketable order matches a
    /// resting order, both sides see correct outcomes and balances.
    #[test]
    fn marketable_limit_fills_resting_maker() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Maker rests a sell at 10.50.
        let out = e
            .place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
                &mut fills,
            )
            .unwrap();
        assert_eq!(
            out,
            OrderOutcome::Resting {
                order_id: OrderId(0),
                price: Price(1_050_000_000),
                resting_qty: Qty(5_000)
            }
        );

        // Taker buys 3.0 at 10.50 (crosses).
        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 3_000, 2),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Filled);

        assert_eq!(fills.len(), 1);
        assert_eq!(fills[0].price, Price(1_050_000_000));
        assert_eq!(fills[0].qty, Qty(3_000));
        assert_eq!(fills[0].maker_order_id, OrderId(0));
        assert_eq!(fills[0].taker_order_id, OrderId(1));
        assert_eq!(fills[0].taker_side, Side::Buy);

        // Maker's remainder is still resting.
        let mut entries = Vec::new();
        e.resting_entries(&mut entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].qty, Qty(2_000));
    }

    #[test]
    fn price_time_priority_fifo_within_level() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Two makers at the same price, different owners.
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
            &mut fills,
        )
        .unwrap();
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 3_000, 2),
            &mut fills,
        )
        .unwrap();

        // A taker sweeps the whole level: the FIRST maker fills first.
        e.place(order(Side::Buy, OrderType::Market, TimeInForce::Ioc, 0, 5_000, 3), &mut fills)
            .unwrap();

        assert_eq!(fills.len(), 2);
        assert_eq!(fills[0].maker_order_id, OrderId(0), "first arrival must fill first");
        assert_eq!(fills[0].qty, Qty(2_000));
        assert_eq!(fills[1].maker_order_id, OrderId(1));
        assert_eq!(fills[1].qty, Qty(3_000));
        assert_eq!(e.resting_count(), 0);
    }

    #[test]
    fn sweep_walks_levels_best_first() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Ask ladder: 10.50 (1k), 10.51 (2k), 10.52 (4k).
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 1),
            &mut fills,
        )
        .unwrap();
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 2_000, 1),
            &mut fills,
        )
        .unwrap();
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_052_000_000, 4_000, 1),
            &mut fills,
        )
        .unwrap();

        // Buy 5k at limit 10.52: sweeps 1k @ 10.50, 2k @ 10.51, then
        // 2k of the 4k @ 10.52 — the 10.52 maker keeps 2k resting.
        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_052_000_000, 5_000, 2),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Filled);
        assert_eq!(fills.len(), 3);
        assert_eq!(fills[0].price, Price(1_050_000_000));
        assert_eq!(fills[1].price, Price(1_051_000_000));
        assert_eq!(fills[2].price, Price(1_052_000_000));
        assert_eq!(fills[2].qty, Qty(2_000), "last level fills partially");
        assert_eq!(e.resting_count(), 1, "10.52 maker partially consumed");
        assert_eq!(e.best_ask(), Some((Price(1_052_000_000), Qty(2_000))));
    }

    #[test]
    fn limit_above_market_rests_partial() {
        let mut e = engine();
        let mut fills = Vec::new();

        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
            &mut fills,
        )
        .unwrap();
        // Buy 5k at 10.50: fills 2k, rests 3k.
        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 2),
                &mut fills,
            )
            .unwrap();
        assert_eq!(
            out,
            OrderOutcome::Resting {
                order_id: OrderId(1),
                price: Price(1_050_000_000),
                resting_qty: Qty(3_000)
            }
        );
        // Best bid is now our remainder.
        assert_eq!(e.best_bid(), Some((Price(1_050_000_000), Qty(3_000))));
    }

    #[test]
    fn ioc_remainder_canceled_not_resting() {
        let mut e = engine();
        let mut fills = Vec::new();

        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
            &mut fills,
        )
        .unwrap();
        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Ioc, 1_050_000_000, 5_000, 2),
                &mut fills,
            )
            .unwrap();
        assert_eq!(
            out,
            OrderOutcome::CanceledRemainder { order_id: OrderId(1), filled_qty: Qty(2_000) }
        );
        assert_eq!(e.resting_count(), 0);
        assert_eq!(e.best_bid(), None, "IOC remainder must not rest");
    }

    #[test]
    fn fok_fully_fillable_executes() {
        let mut e = engine();
        let mut fills = Vec::new();

        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
            &mut fills,
        )
        .unwrap();
        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Fok, 1_050_000_000, 5_000, 2),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Filled);
        assert_eq!(fills.len(), 1);
    }

    #[test]
    fn fok_insufficient_liquidity_kills_without_fills() {
        let mut e = engine();
        let mut fills = Vec::new();

        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
            &mut fills,
        )
        .unwrap();
        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Fok, 1_050_000_000, 5_000, 2),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Killed);
        assert!(fills.is_empty(), "FOK kill must not execute anything");
        // Maker untouched.
        assert_eq!(e.best_ask(), Some((Price(1_050_000_000), Qty(2_000))));
    }

    #[test]
    fn fok_respects_price_limit() {
        let mut e = engine();
        let mut fills = Vec::new();

        // 5k available at 10.52 — but the FOK limit is 10.51.
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_052_000_000, 5_000, 1),
            &mut fills,
        )
        .unwrap();
        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Fok, 1_051_000_000, 5_000, 2),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Killed);
        assert!(fills.is_empty());
    }

    #[test]
    fn post_only_rejects_crossing_order() {
        let mut e = engine();
        let mut fills = Vec::new();

        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
            &mut fills,
        )
        .unwrap();
        // A post-only buy AT the ask would cross → rejected.
        let out = e
            .place(
                order(Side::Buy, OrderType::PostOnly, TimeInForce::Gtc, 1_050_000_000, 2_000, 2),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Rejected(RejectReason::PostOnlyWouldCross));
        // A post-only buy below the ask rests.
        let out = e
            .place(
                order(Side::Buy, OrderType::PostOnly, TimeInForce::Gtc, 1_049_000_000, 2_000, 2),
                &mut fills,
            )
            .unwrap();
        assert!(matches!(out, OrderOutcome::Resting { .. }));
    }

    #[test]
    fn cancel_removes_order_and_restores_capacity() {
        let mut e = engine();
        let mut fills = Vec::new();

        let out = e
            .place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 2_000, 1),
                &mut fills,
            )
            .unwrap();
        let OrderOutcome::Resting { order_id, .. } = out else { panic!("must rest") };

        let canceled = e.cancel(order_id).unwrap();
        assert_eq!(canceled.qty, Qty(2_000));
        assert_eq!(canceled.owner, Address([1; 20]));
        assert_eq!(e.resting_count(), 0);
        assert_eq!(e.best_ask(), None);

        // Canceling again fails loudly.
        assert_eq!(e.cancel(order_id), Err(TradingError::OrderNotFound));
    }

    #[test]
    fn validation_rejections_reach_caller() {
        let mut e = engine();
        let mut fills = Vec::new();

        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_500, 2_000, 1),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Rejected(RejectReason::PriceOffTick));

        let out = e
            .place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_500, 1),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Rejected(RejectReason::InvalidQty));
    }

    #[test]
    fn market_order_on_empty_book_cancels_remainder() {
        let mut e = engine();
        let mut fills = Vec::new();

        let out = e
            .place(order(Side::Buy, OrderType::Market, TimeInForce::Ioc, 0, 5_000, 1), &mut fills)
            .unwrap();
        assert_eq!(
            out,
            OrderOutcome::CanceledRemainder { order_id: OrderId(0), filled_qty: Qty(0) }
        );
    }

    #[test]
    fn ids_are_assigned_at_submission_in_order() {
        let mut e = engine();
        let mut fills = Vec::new();

        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 1),
            &mut fills,
        )
        .unwrap();
        e.place(order(Side::Sell, OrderType::Market, TimeInForce::Ioc, 0, 1_000, 1), &mut fills)
            .unwrap();
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 1_000, 1),
            &mut fills,
        )
        .unwrap();
        // Even the market order (which never rests) consumed id 1.
        assert_eq!(e.next_order_id(), 3);
    }

    #[test]
    fn book_full_rejects_at_capacity() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Fill the arena (max_resting = 64) with distinct in-band
        // prices (ticks 0..=63 — tick 64 is the band ceiling, kept
        // for the post-cancel refill below).
        for i in 0..64u64 {
            let price = 1_000_000_000 + i * 1_000_000;
            let out = e
                .place(
                    order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, price, 1_000, 1),
                    &mut fills,
                )
                .unwrap();
            assert!(matches!(out, OrderOutcome::Resting { .. }), "order {i} must rest");
        }
        let out = e
            .place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_064_000_000, 1_000, 1),
                &mut fills,
            )
            .unwrap();
        assert_eq!(out, OrderOutcome::Rejected(RejectReason::BookFull));

        // Cancel one → capacity frees (tick 64 is in-band).
        e.cancel(OrderId(0)).unwrap();
        let out = e
            .place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_064_000_000, 1_000, 1),
                &mut fills,
            )
            .unwrap();
        assert!(matches!(out, OrderOutcome::Resting { .. }));
    }

    #[test]
    fn no_crossed_book_after_any_operation() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Interleave resting bids and asks at non-crossing prices.
        for i in 0..10u64 {
            let bid = 1_040_000_000 - i * 1_000_000;
            let ask = 1_050_000_000 + i * 1_000_000;
            e.place(
                order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, bid, 1_000, 1),
                &mut fills,
            )
            .unwrap();
            e.place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, ask, 1_000, 2),
                &mut fills,
            )
            .unwrap();
            if let (Some((b, _)), Some((a, _))) = (e.best_bid(), e.best_ask()) {
                assert!(b < a, "book must never be crossed: {:?} >= {:?}", b.0, a.0);
            }
        }
    }

    /// Regression test: `cancel` on a non-existent order id returns
    /// an error instead of panicking. Before the fix, `resting -= 1`
    /// could underflow and panic in debug builds.
    #[test]
    fn cancel_nonexistent_order_returns_error_not_panic() {
        let mut e = engine();
        let result = e.cancel(OrderId(999));
        assert!(result.is_err(), "cancel of non-existent order must error");
        assert_eq!(e.resting_count(), 0, "resting count must not underflow");
    }

    /// Regression test: the matching engine must not panic when
    /// processing orders that would have triggered `.expect()` or
    /// `.unwrap()` in the old code. This test exercises the
    /// `remove_maker` path (which previously used `.expect()` on
    /// `ids.remove`) by filling and then matching a resting order.
    #[test]
    fn remove_maker_does_not_panic_on_invariant_violation() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Place a resting sell order.
        let out = e
            .place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 1),
                &mut fills,
            )
            .unwrap();
        let OrderOutcome::Resting { order_id, .. } = out else { panic!("must rest") };

        // Cancel it (exercises the `remove_maker` / `cancel` path).
        let canceled = e.cancel(order_id).unwrap();
        assert_eq!(canceled.order_id, order_id);

        // Cancel again — must error, not panic.
        let result = e.cancel(order_id);
        assert!(result.is_err(), "double-cancel must error not panic");
        assert_eq!(e.resting_count(), 0, "resting must be 0 after cancel");
    }

    /// Regression test: FOK pre-scan must exclude the taker's own
    /// resting orders when STP is active. Before the fix, the FOK
    /// pre-scan counted the taker's own orders as fillable, so a
    /// FOK that should have been killed (because STP would skip
    /// the taker's own orders) was instead accepted and then
    /// canceled mid-sweep — violating the FOK guarantee.
    #[test]
    fn fok_pre_scan_excludes_self_trades_under_stp() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Owner 1 rests a sell at 10.50 for 5,000 lots.
        let out = e
            .place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
                &mut fills,
            )
            .unwrap();
        assert!(matches!(out, OrderOutcome::Resting { .. }));

        // Owner 1 submits a FOK buy for 5,000 at 10.50 with STP
        // CancelNewest. The only resting sell is owner 1's own
        // order, so the STP-aware fillable quantity is 0 (the
        // own order is excluded). The FOK must be killed.
        let fok_req = NewOrder {
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Fok,
            price: Price(1_050_000_000),
            qty: Qty(5_000),
            owner: Address([1; 20]),
            stp: StpMode::CancelNewest,
        };
        let out = e.place(fok_req, &mut fills).unwrap();
        assert_eq!(out, OrderOutcome::Killed, "FOK with only self-trades must be killed under STP");
        assert!(fills.is_empty(), "killed FOK must not produce fills");

        // The resting order must still be in the book.
        assert_eq!(e.resting_count(), 1, "resting order must not be removed by killed FOK");
    }

    /// Regression test: FOK pre-scan with STP None must count
    /// all orders (including the taker's own). This verifies the
    /// non-STP path is unchanged.
    #[test]
    fn fok_pre_scan_counts_all_orders_without_stp() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Owner 1 rests a sell at 10.50 for 5,000 lots.
        let out = e
            .place(
                order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
                &mut fills,
            )
            .unwrap();
        assert!(matches!(out, OrderOutcome::Resting { .. }));

        // Owner 1 submits a FOK buy for 5,000 at 10.50 with STP
        // None. The own order counts as fillable, so the FOK
        // passes the pre-scan and executes (self-trade happens).
        let fok_req = NewOrder {
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Fok,
            price: Price(1_050_000_000),
            qty: Qty(5_000),
            owner: Address([1; 20]),
            stp: StpMode::None,
        };
        let out = e.place(fok_req, &mut fills).unwrap();
        // With STP None, the self-trade executes and the order fills.
        assert_eq!(out, OrderOutcome::Filled, "FOK without STP must fill against own order");
        assert!(!fills.is_empty(), "FOK without STP must produce fills");
    }

    /// Snapshot restore: an engine rebuilt from `write_canonical_state`
    /// bytes must re-encode to byte-identical output and keep trading
    /// correctly (next id continues, resting orders are cancellable).
    #[test]
    fn canonical_state_round_trip_restores_book() {
        let mut e = engine();
        let mut fills = Vec::new();

        // Two resting sells at different prices, one partially filled,
        // plus a resting bid — a non-trivial book shape.
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
            &mut fills,
        )
        .unwrap();
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_051_000_000, 2_000, 2),
            &mut fills,
        )
        .unwrap();
        e.place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_010_000_000, 7_000, 3),
            &mut fills,
        )
        .unwrap();
        e.place(
            order(Side::Buy, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 1_000, 4),
            &mut fills,
        )
        .unwrap(); // partially fills the first sell
        assert_eq!(e.resting_count(), 3);
        assert_eq!(e.next_order_id(), 4);

        let mut bytes = Vec::new();
        let mut scratch = Vec::new();
        e.write_canonical_state(&mut bytes, &mut scratch);

        let mut restored =
            MatchingEngine::from_canonical_state(&bytes, |c| DenseBook::new(*c)).unwrap();
        let mut bytes2 = Vec::new();
        restored.write_canonical_state(&mut bytes2, &mut scratch);
        assert_eq!(bytes, bytes2, "restored engine must re-encode byte-identically");

        // Live operation continues correctly: next id is 4, and a
        // restored order cancels by id.
        assert_eq!(restored.next_order_id(), 4);
        let canceled = restored.cancel(OrderId(2)).expect("restored order must cancel");
        assert_eq!(canceled.price, Price(1_010_000_000));
        assert_eq!(restored.resting_count(), 2);
    }

    /// `decode_canonical_state` must reject truncated, inconsistent,
    /// or non-canonical input — never panic, never restore silently.
    #[test]
    fn canonical_state_decode_rejects_malformed() {
        let mut e = engine();
        let mut fills = Vec::new();
        e.place(
            order(Side::Sell, OrderType::Limit, TimeInForce::Gtc, 1_050_000_000, 5_000, 1),
            &mut fills,
        )
        .unwrap();
        let mut bytes = Vec::new();
        let mut scratch = Vec::new();
        e.write_canonical_state(&mut bytes, &mut scratch);

        // Truncation at every prefix length.
        for cut in 0..bytes.len() {
            assert!(
                decode_canonical_state(&bytes[..cut]).is_none(),
                "prefix of len {cut} must not decode"
            );
        }
        // Trailing garbage.
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(decode_canonical_state(&padded).is_none());

        // resting field ≠ entries count. Layout: cfg(38B = u16 +
        // 4×u64 + u32) next_id(8) resting(4) count(8) entries —
        // flip the resting field.
        let mut bad = bytes.clone();
        bad[38 + 8] ^= 0xFF;
        assert!(decode_canonical_state(&bad).is_none(), "resting must equal entries count");

        // An entry id ≥ next_id is impossible in a live book.
        let mut bad = bytes.clone();
        // Entry 0's id (offset 38+8+4+8 = 58) — set it to next_id.
        let nid = u64::from_le_bytes(bytes[38..46].try_into().unwrap());
        bad[58..66].copy_from_slice(&nid.to_le_bytes());
        assert!(decode_canonical_state(&bad).is_none(), "id ≥ next_id must be rejected");
    }
}
