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

use crate::book::{BookBackend, DenseBook, MarketConfig, ValidatedMarketConfig};
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

/// Per-maker fill gate consulted inside the sweep, before each fill
/// is booked — caller policy enforced at the match decision, not as
/// post-trade repair.
///
/// [`MatchingEngine::place_with_cap`] calls [`MakerCap::cap`] once
/// per maker the sweep reaches (after self-trade handling, before
/// the fill). The return value is the quantity the maker may fill
/// now:
///
/// - `0` — the maker cannot legally fill: it is removed from the
///   book as dead liquidity (e.g. a reduce-only order whose position
///   no longer exists) and matching continues to the next order.
/// - `1..book_qty` — the maker fills exactly that much, then its
///   remainder is removed: it can never legally execute further.
/// - `>= book_qty` — uncapped; the ordinary fill path.
///
/// [`MakerCap::reset`] is invoked between a FOK pre-scan (which
/// consults `cap` in simulation, so a capped book still honours
/// all-or-nothing) and the real sweep, giving implementations a
/// point to clear sweep-local accounting.
///
/// `UNCAPPED` marks the trivial implementation; the generic code
/// resolves the fast paths at compile time, so [`NoCap`] monomorphizes
/// to a literal no-op on the hot `place` path.
pub trait MakerCap {
    /// `true` for implementations that never restrict a fill.
    const UNCAPPED: bool = false;

    /// Maximum quantity this maker may fill in the current sweep.
    fn cap(&mut self, id: OrderId, owner: Address, book_qty: u64) -> u64;

    /// Called for every maker the sweep shrank or removed *without*
    /// a fill — fills are reported separately via `FillEvent`, so
    /// this is the channel through which every other book mutation
    /// reaches the caller. Obligations held against resting orders
    /// (quote holds, margin reservations) must be released here:
    /// an order that vanishes unreported strands whatever it had
    /// locked.
    fn on_removed(&mut self, _removal: MakerRemoval) {}

    /// Clear state accumulated for the simulated pre-scan sweep.
    fn reset(&mut self) {}
}

/// Why the sweep shrank or removed a resting maker without filling it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalReason {
    /// Self-trade prevention: the taker's own resting order was in
    /// the way (`CancelOldest` removal, or a `DecrementAndCancel` that
    /// consumed quantity without a trade).
    SelfTrade,
    /// The `MakerCap` gate killed the order — dead liquidity, or a
    /// remainder that can never legally fill.
    Cap,
}

/// How an STP interaction between the taker and its own resting
/// order resolved — internal control flow for `sweep`/`stp_maker`.
enum StpAction {
    /// The maker was removed or decremented; the taker keeps matching.
    MakerResolved,
    /// The taker's remaining qty was consumed — the sweep is done,
    /// not self-canceled (outcome reports the fills).
    TakerConsumed,
    /// `CancelNewest`: the taker's remainder is canceled mid-sweep.
    TakerCanceled,
}

/// A resting order the sweep decremented or removed *without* a
/// fill — the complement of `FillEvent` for book mutations.
#[derive(Debug, Clone, Copy)]
pub struct MakerRemoval {
    /// The resting order affected.
    pub order_id: OrderId,
    /// Its owner (obligation attribution).
    pub owner: Address,
    /// Side it was resting on.
    pub side: Side,
    /// Its resting price.
    pub price: u64,
    /// Quantity released without a fill — the refund basis for any
    /// obligation held against the order.
    pub removed_qty: u64,
    /// Quantity still resting (0 = the order is gone entirely).
    pub remaining: u64,
    /// Why the sweep did it.
    pub reason: RemovalReason,
}

/// Every maker fills its full book quantity — the default
/// [`MatchingEngine::place`] gate.
pub struct NoCap;

impl MakerCap for NoCap {
    const UNCAPPED: bool = true;

    fn cap(&mut self, _id: OrderId, _owner: Address, book_qty: u64) -> u64 {
        book_qty
    }
}

/// A [`MakerCap`] that never restricts fills but records every
/// maker the sweep shrank or removed — for callers that hold
/// obligations against resting orders and must release them when
/// the book changes without a fill (self-trade prevention).
pub struct ObserveRemovals<'a> {
    /// Removals in match order.
    pub removed: &'a mut Vec<MakerRemoval>,
}

impl MakerCap for ObserveRemovals<'_> {
    const UNCAPPED: bool = true;

    fn cap(&mut self, _id: OrderId, _owner: Address, book_qty: u64) -> u64 {
        book_qty
    }

    fn on_removed(&mut self, removal: MakerRemoval) {
        self.removed.push(removal);
    }
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
    /// Caller-supplied leaf hash for the incremental resting
    /// commitment (7.4): `Some` means every resting-order mutation
    /// folds its `RestingEntry` leaf into `resting_fold`, so the
    /// committed-state root costs O(1) per book instead of
    /// re-serializing every resting order per block. `None`
    /// disables the fold — matcher and test engines pay nothing.
    /// The function pointer keeps this crate dependency-free.
    fold_leaf: Option<fn(&RestingEntry) -> [u8; 32]>,
    /// `⊕ fold_leaf(entry)` over all resting orders — insertion and
    /// removal are the same operation under XOR, so the fold is
    /// maintained in O(1) per mutation and always equals the fold
    /// of exactly the live resting set.
    resting_fold: [u8; 32],
}

impl<B: BookBackend> MatchingEngine<B> {
    /// Build an engine with a fresh backend from a validated config.
    /// The [`ValidatedMarketConfig`] proof makes the admission-side
    /// check mandatory — no caller can construct an engine on an
    /// unchecked config.
    ///
    /// # Errors
    /// [`TradingError::InvalidConfig`] is not reachable — validation
    /// ran before the proof existed. `Result` is retained for the
    /// construction shape.
    pub fn new(cfg: ValidatedMarketConfig, book: B) -> Result<Self, TradingError> {
        Ok(MatchingEngine {
            pool: OrderPool::with_capacity(cfg.max_resting),
            ids: IdMap::with_capacity(cfg.max_resting),
            cfg: *cfg,
            book,
            next_id: 0,
            resting: 0,
            fold_leaf: None,
            resting_fold: [0; 32],
        })
    }

    /// Enable the incremental resting commitment with `leaf` —
    /// the module wires its domain-separated `committed_leaf`
    /// hash once at assembly (or after snapshot decode). Any
    /// already-resting entries are folded in one pass — O(resting),
    /// the same cost the walk it replaces already pays.
    ///
    /// Measured budget: the fold costs ~one domain-separated hash
    /// per resting-order mutation — ~160 ns on the dev bench, a
    /// real but bounded hot-path tax gated by the
    /// `rest_cancel_pair_folded`/`mixed_workload_folded` rows
    /// (both inside the match gates).
    pub fn enable_resting_fold(&mut self, leaf: fn(&RestingEntry) -> [u8; 32]) {
        self.fold_leaf = Some(leaf);
        self.resting_fold = [0; 32];
        // Fold the already-resting set once — snapshot installs
        // arrive populated, and an enabled fold must equal the
        // fold of exactly the live set.
        let mut entries = Vec::with_capacity(self.resting as usize);
        self.resting_entries(&mut entries);
        for e in &entries {
            self.fold_entry(e);
        }
    }

    /// The maintained resting-fold — `⊕ leaf(entry)` over every
    /// resting order (`[0; 32]` while the fold is disabled).
    #[must_use]
    pub fn resting_fold(&self) -> [u8; 32] {
        self.resting_fold
    }

    /// The pool node's committed view — the same `(id, side,
    /// price, qty, owner)` shape `resting_entries` serializes.
    fn node_entry(&self, slot: u32) -> RestingEntry {
        let node = &self.pool[slot];
        RestingEntry {
            id: node.id,
            side: node.side,
            price: node.price,
            qty: node.qty,
            owner: node.owner,
        }
    }

    /// XOR `leaf(entry)` into `resting_fold` — insertion and
    /// removal are the same operation under XOR. No-op while the
    /// fold is disabled.
    #[inline]
    fn fold_entry(&mut self, e: &RestingEntry) {
        if let Some(leaf) = self.fold_leaf {
            let h = leaf(e);
            for (a, b) in self.resting_fold.iter_mut().zip(h.iter()) {
                *a ^= *b;
            }
        }
    }

    /// Replace `old`'s leaf with `new`'s in one call — the
    /// partial-fill/STP-decrement path where a resting order keeps
    /// its slot but changes quantity.
    #[inline]
    fn fold_replace(&mut self, old: &RestingEntry, new: &RestingEntry) {
        self.fold_entry(old);
        self.fold_entry(new);
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
        self.place_with_cap(req, fills, &mut NoCap)
    }

    /// `place` with a [`MakerCap`] gate consulted per maker fill —
    /// the caller enforces policy (e.g. reduce-only cover) at the
    /// match decision, before the fill is booked, instead of
    /// repairing positions afterward.
    ///
    /// # Errors
    /// Same contract as [`Self::place`].
    pub fn place_with_cap<C: MakerCap>(
        &mut self,
        req: NewOrder,
        fills: &mut Vec<FillEvent>,
        cap: &mut C,
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
        // opposite side change what can fill: skipped or canceled
        // makers never trade, `CancelNewest` makes everything past
        // the first self order unreachable, and `DecrementAndCancel`
        // spends taker quantity on self makers without a fill. The
        // pre-scan therefore evaluates the exact STP behavior — a
        // scan that counted only non-self liquidity would accept a
        // FOK the sweep then partially cancels, violating the
        // all-or-nothing guarantee.
        if req.tif == TimeInForce::Fok {
            let fillable = if C::UNCAPPED {
                match req.stp {
                    StpMode::None => self.book.fillable_qty(req.side, limit_raw),
                    // Self orders are removed and the sweep keeps
                    // matching — every external order in range is
                    // reachable, so the level-total scan is exact.
                    StpMode::CancelOldest => self
                        .book
                        .fillable_qty_excluding_owner(req.side, limit_raw, req.owner, &self.pool),
                    // `CancelNewest` stops the sweep at the first
                    // self maker and `DecrementAndCancel` spends
                    // taker quantity on self makers without a fill —
                    // level totals cannot express either, so replay
                    // the sweep read-only (the cap probe with a
                    // no-op cap).
                    StpMode::CancelNewest | StpMode::DecrementAndCancel => {
                        self.capped_fillable(&req, limit_raw, cap)
                    }
                }
            } else {
                // A cap can shrink or kill a maker fill — the
                // optimized book scans know nothing about it, so the
                // pre-scan must replay the sweep's decisions
                // read-only (same order, same STP rules, same caps).
                self.capped_fillable(&req, limit_raw, cap)
            };
            // The pre-scan fed `cap` a simulated sweep; reset its
            // sweep-local state before the real one.
            cap.reset();
            if fillable < req.qty.0 {
                return Ok(OrderOutcome::Killed);
            }
        }

        // ── Match loop: zero validation, zero allocation below ──────
        let mut rem = req.qty.0;
        let taker_canceled = self.sweep(&req, taker_id, limit_raw, &mut rem, fills, cap);
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
                // Fold right after append: the fold tracks book
                // membership — `resting_entries` (what staged verify
                // re-folds) emits whatever the book holds, even if a
                // later step below returns early.
                self.fold_entry(&self.node_entry(slot));
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
        self.fold_entry(&self.node_entry(slot));
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
    /// Cold path only: O(resting) per call — now the snapshot
    /// blob path only; `state_root` reads [`Self::resting_fold`]
    /// instead of this walk. The match path never runs it.
    pub fn write_canonical_state(&self, out: &mut Vec<u8>, entries: &mut Vec<RestingEntry>) {
        self.write_canonical_header(out);
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

    /// Append the canonical header — everything `write_canonical_state`
    /// commits ahead of the entry list: the market config, `next_id`,
    /// and the resting count.
    ///
    /// The module's incremental root preimage writes this same header
    /// followed by [`Self::resting_fold`] in place of the entry list,
    /// so both encodings share one field-order definition — a header
    /// field added here lands in both the snapshot bytes and the root
    /// preimage automatically.
    pub fn write_canonical_header(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.cfg.market_id.to_le_bytes());
        out.extend_from_slice(&self.cfg.tick_size.0.to_le_bytes());
        out.extend_from_slice(&self.cfg.lot_size.0.to_le_bytes());
        out.extend_from_slice(&self.cfg.min_price.0.to_le_bytes());
        out.extend_from_slice(&self.cfg.max_price.0.to_le_bytes());
        out.extend_from_slice(&self.cfg.max_resting.to_le_bytes());
        out.extend_from_slice(&self.next_id.to_le_bytes());
        out.extend_from_slice(&self.resting.to_le_bytes());
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
    /// The decoded config is re-validated here and the proof is
    /// handed to the builder, so a corrupted snapshot cannot smuggle
    /// an unchecked config into a restored engine.
    ///
    /// # Errors
    /// [`TradingError::CorruptState`] on malformed bytes, a config or
    /// entry the live engine could never have produced, a duplicate
    /// order id, or a re-encode mismatch; [`TradingError::BookFull`]
    /// if the entry count exceeds `max_resting`.
    pub fn from_canonical_state(
        data: &[u8],
        make_book: impl FnOnce(&ValidatedMarketConfig) -> Result<B, TradingError>,
    ) -> Result<Self, TradingError> {
        let decoded = decode_canonical_state(data).ok_or(TradingError::CorruptState("decode"))?;
        let cfg = decoded
            .cfg
            .validated()
            .map_err(|_| TradingError::CorruptState("config fails market rules"))?;
        let mut engine = Self::new(cfg, make_book(&cfg)?)?;
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
        self.fold_entry(&self.node_entry(slot));
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
    fn sweep<C: MakerCap>(
        &mut self,
        req: &NewOrder,
        taker_id: OrderId,
        limit_raw: Option<u64>,
        rem: &mut u64,
        fills: &mut Vec<FillEvent>,
        cap: &mut C,
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
                let (m_id, m_qty, m_side, m_owner) = {
                    let node = &self.pool[head];
                    (node.id, node.qty.0, node.side, node.owner)
                };

                // Self-trade prevention: only when owners match and a
                // mode is selected.
                if m_owner == req.owner && req.stp != StpMode::None {
                    match self.stp_maker(req, head, opp, rem, cap) {
                        StpAction::MakerResolved => continue,
                        StpAction::TakerConsumed => break 'sweep,
                        StpAction::TakerCanceled => return true,
                    }
                }

                // The maker-cap gate decides, at the match decision,
                // how much of this maker may legally fill: `0`
                // removes it as dead (e.g. reduce-only with no cover
                // left), a partial cap fills that much then removes
                // the now-unfillable remainder, `>= m_qty` is the
                // ordinary path.
                let cap_qty = cap.cap(m_id, m_owner, m_qty);
                if cap_qty == 0 {
                    // The gate declares the whole order dead (e.g. a
                    // reduce-only with no cover left). Report it so
                    // obligations held against it are released.
                    cap.on_removed(MakerRemoval {
                        order_id: m_id,
                        owner: m_owner,
                        side: m_side,
                        price: opp,
                        removed_qty: m_qty,
                        remaining: 0,
                        reason: RemovalReason::Cap,
                    });
                    self.remove_maker(head, m_id);
                    continue;
                }
                // Fill against the FIFO head maker.
                let fill = (*rem).min(m_qty).min(cap_qty);
                fills.push(FillEvent {
                    price: Price(opp),
                    qty: Qty(fill),
                    maker_order_id: m_id,
                    maker_owner: m_owner,
                    taker_order_id: taker_id,
                    taker_owner: req.owner,
                    taker_side: req.side,
                });
                {
                    let old = self.node_entry(head);
                    self.pool[head].qty = Qty(m_qty - fill);
                    self.book.reduce_total(opp, fill);
                    let new = self.node_entry(head);
                    self.fold_replace(&old, &new);
                }
                *rem -= fill;

                if fill == m_qty {
                    // Maker exhausted — the fill event above covers
                    // the whole order, so no removal report.
                    self.remove_maker(head, m_id);
                } else if fill == cap_qty {
                    // The maker hit its cap with book quantity left:
                    // the remainder can never legally fill — dead
                    // liquidity, removed and reported.
                    cap.on_removed(MakerRemoval {
                        order_id: m_id,
                        owner: m_owner,
                        side: m_side,
                        price: opp,
                        removed_qty: m_qty - fill,
                        remaining: 0,
                        reason: RemovalReason::Cap,
                    });
                    self.remove_maker(head, m_id);
                }
                if *rem == 0 {
                    break 'sweep;
                }
            }
        }
        false
    }

    /// Apply self-trade prevention for a head maker owned by the
    /// taker, reporting every removal/decrement through `cap`.
    ///
    /// Separated from `sweep` for readability — and so the
    /// reporting contract (every non-fill mutation emits
    /// `on_removed` exactly once) lives in one audited place.
    fn stp_maker<C: MakerCap>(
        &mut self,
        req: &NewOrder,
        head: u32,
        opp: u64,
        rem: &mut u64,
        cap: &mut C,
    ) -> StpAction {
        let (m_id, m_qty, m_side, m_owner) = {
            let node = &self.pool[head];
            (node.id, node.qty.0, node.side, node.owner)
        };
        match req.stp {
            StpMode::CancelNewest => {
                // The taker's remainder is canceled; fills booked so
                // far stand.
                StpAction::TakerCanceled
            }
            StpMode::CancelOldest => {
                // Remove the resting maker, keep matching. No fill
                // books for this quantity — report the removal so
                // obligations held against the order release once.
                cap.on_removed(MakerRemoval {
                    order_id: m_id,
                    owner: m_owner,
                    side: m_side,
                    price: opp,
                    removed_qty: m_qty,
                    remaining: 0,
                    reason: RemovalReason::SelfTrade,
                });
                self.remove_maker(head, m_id);
                StpAction::MakerResolved
            }
            StpMode::DecrementAndCancel => {
                if m_qty <= *rem {
                    // Maker is smaller: remove it whole, taker
                    // continues with reduced rem.
                    cap.on_removed(MakerRemoval {
                        order_id: m_id,
                        owner: m_owner,
                        side: m_side,
                        price: opp,
                        removed_qty: m_qty,
                        remaining: 0,
                        reason: RemovalReason::SelfTrade,
                    });
                    self.remove_maker(head, m_id);
                    *rem -= m_qty;
                    if *rem == 0 { StpAction::TakerConsumed } else { StpAction::MakerResolved }
                } else {
                    // Taker is smaller: consume it by decrementing
                    // the maker. No fill books for the consumed
                    // quantity — report the decrement so the maker's
                    // obligation tracks the live qty.
                    let new_qty = m_qty - *rem;
                    cap.on_removed(MakerRemoval {
                        order_id: m_id,
                        owner: m_owner,
                        side: m_side,
                        price: opp,
                        removed_qty: *rem,
                        remaining: new_qty,
                        reason: RemovalReason::SelfTrade,
                    });
                    {
                        let old = self.node_entry(head);
                        self.pool[head].qty = Qty(new_qty);
                        self.book.reduce_total(opp, *rem);
                        let new = self.node_entry(head);
                        self.fold_replace(&old, &new);
                    }
                    *rem = 0;
                    StpAction::TakerConsumed
                }
            }
            StpMode::None => {
                // The caller only invokes this for a mode other than
                // `None`; a defensive fallthrough keeps matching.
                StpAction::MakerResolved
            }
        }
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
        self.fold_entry(&self.node_entry(slot));
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

    /// Read-only fillable-quantity probe for the FOK pre-scan when a
    /// [`MakerCap`] gate is active. The optimized book scans know
    /// nothing about caps, so this replays the sweep's decisions in
    /// order — opposing levels best-first, FIFO within a level, the
    /// same self-trade rules, and the same `cap` calls — so the
    /// fillable total is exactly what the real sweep would book.
    ///
    /// Cold path (FOK + caps only): O(levels touched). Levels are
    /// homogeneous by construction — a price that would host both
    /// sides has already crossed — so a level's head side decides
    /// whether it is opposing at all.
    fn capped_fillable<C: MakerCap>(
        &self,
        req: &NewOrder,
        limit_raw: Option<u64>,
        cap: &mut C,
    ) -> u64 {
        let mut fillable = 0u64;
        let mut rem = req.qty.0;
        // Cold path: usize→u32 is bounded by MAX_DENSE_LEVELS per
        // MarketConfig::validate (same bound `resting_entries` uses).
        #[allow(clippy::cast_possible_truncation)]
        let level_count = self.book.level_count() as u32;
        // Sweep direction: a buy consumes asks ascending, a sell
        // consumes bids descending — best price first.
        let opposing = match req.side {
            Side::Buy => Side::Sell,
            Side::Sell => Side::Buy,
        };
        let (mut idx, step): (i64, i64) = match req.side {
            Side::Buy => (0, 1),
            Side::Sell => (i64::from(level_count) - 1, -1),
        };
        while idx >= 0 && idx < i64::from(level_count) {
            // The loop guard keeps idx inside 0..level_count — the
            // cast can neither truncate nor go negative.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let price = self.book.level_price(idx as u32);
            if let Some(lim) = limit_raw {
                let marketable = match req.side {
                    Side::Buy => price <= lim,
                    Side::Sell => price >= lim,
                };
                // Levels are visited in match order: once the bound
                // is passed, nothing beyond can fill.
                if !marketable {
                    break;
                }
            }
            let mut slot = self.book.level_head(price);
            while slot != crate::pool::NIL {
                let node = &self.pool[slot];
                let (m_id, m_qty, m_owner) = (node.id, node.qty.0, node.owner);
                slot = node.next;
                // Levels are homogeneous: a wrong-side level never
                // matches this taker.
                if node.side != opposing {
                    continue;
                }
                // Self-trade handling mirrors the sweep exactly —
                // STP-skipped makers never reach the cap gate.
                if m_owner == req.owner {
                    match req.stp {
                        // The sweep cancels the taker here — fills
                        // booked so far stand, nothing further counts.
                        StpMode::CancelNewest => return fillable,
                        StpMode::CancelOldest => continue,
                        StpMode::DecrementAndCancel => {
                            if m_qty <= rem {
                                rem -= m_qty;
                            } else {
                                rem = 0;
                            }
                            if rem == 0 {
                                return fillable;
                            }
                            continue;
                        }
                        StpMode::None => {}
                    }
                }
                let c = cap.cap(m_id, m_owner, m_qty);
                if c == 0 {
                    continue;
                }
                let f = rem.min(m_qty).min(c);
                fillable += f;
                rem -= f;
                if rem == 0 {
                    return fillable;
                }
            }
            idx += step;
        }
        fillable
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
        tick_size: Price(r.u64()?),
        lot_size: Qty(r.u64()?),
        min_price: Price(r.u64()?),
        max_price: Price(r.u64()?),
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
mod tests;
