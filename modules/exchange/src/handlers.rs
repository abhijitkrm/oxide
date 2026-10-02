//! Transaction handlers for the exchange module.
//!
//! Split from `lib.rs` around the admission invariant: every
//! user transaction enters through a `handle_*` here — place,
//! cancel, register, deposit, withdraw, batch-settle — and each
//! handler is the sole place its message type may mutate state.
//! Escrow holds are taken at admission and released exactly once
//! (`release_maker_holds`), so conservation is auditable here.

use super::{
    Address, BTreeMap, CANCEL_REGISTERED_BODY_LEN, CUSTODY_BODY_LEN, Event, ExchangeModule,
    ExecError, FILL_ENTRY_LEN, Inner, MAX_BATCH_FILLS, MAX_REGISTERED_ORDERS, MarketConfig,
    OrderKey, OrderType, PRICE_SCALE, Price, Qty, REGISTER_BODY_LEN, RegisteredOrder,
    RejectCategory, Reserved, Side, TradingError, TxContext, qty_add, qty_sub,
};
use crate::codec::{
    cancel_event, decode_side, encode_side, fill_event, outcome_event, pair_event, removal_event,
};
use crate::settle::{
    BookSettlement, LegPlan, TakerCtx, consume_and_release, pair_hash, rejected_leg_event,
    settle_leg,
};

impl ExchangeModule {
    /// Handle a cancel-order message (extracted from `handle`):
    /// remove the resting order and release its reservation — quote
    /// for buys, base for sells — exactly once.
    pub(crate) fn handle_cancel(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        let (market, order_id) = Self::parse_cancel(body).ok_or(ExecError::Malformed)?;

        let Inner { markets, base_balances, base_holds, .. } = inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                format!("market {market} does not exist"),
            ));
        };

        // Authorization: only the order's owner may cancel.
        if let Some(owner) = engine.order_owner(order_id) {
            if owner != ctx.sender {
                return Err(ExecError::rejected(
                    RejectCategory::Unauthorized,
                    "cancel: not the order owner",
                ));
            }
        } else {
            return Err(ExecError::rejected(RejectCategory::NotFound, "cancel: order not found"));
        }

        match engine.cancel(order_id) {
            Ok(canceled) => {
                // Release the resting reservation (C6 + DvP): a
                // resting buy holds `price × remaining_qty` of quote
                // debited since it rested; a resting sell holds
                // `remaining_qty` of base in `base_holds`. Cancel
                // releases each — exactly once. The quote credit
                // cannot overflow: the refund returns funds debited
                // from this same account. The base release clamps to
                // the hold actually present (a pre-custody sell
                // holds nothing and releases nothing).
                match canceled.side {
                    Side::Buy => {
                        if let Some(ledger) = &self.ledger {
                            let refund = u64::try_from(
                                u128::from(canceled.price.0) * u128::from(canceled.qty.0)
                                    / PRICE_SCALE,
                            )
                            .map_err(|_| {
                                ExecError::rejected(
                                    RejectCategory::Internal,
                                    "cancel refund exceeds u64 quote range",
                                )
                            })?;
                            if refund > 0 {
                                ledger.credit(&canceled.owner, refund).map_err(|_| {
                                    ExecError::rejected(
                                        RejectCategory::Internal,
                                        "cancel refund failed",
                                    )
                                })?;
                            }
                        }
                    }
                    Side::Sell => {
                        let key = (canceled.owner, market);
                        let release =
                            base_holds.get(&key).copied().unwrap_or_default().min(canceled.qty);
                        if release.0 > 0 {
                            let held = base_holds.get(&key).copied().ok_or(ExecError::Malformed)?;
                            base_holds
                                .insert(key, qty_sub(held, release).ok_or(ExecError::Malformed)?);
                            let free = base_balances.get(&key).copied().unwrap_or_default();
                            base_balances
                                .insert(key, qty_add(free, release).ok_or(ExecError::Malformed)?);
                        }
                    }
                }
                Ok(vec![cancel_event(market, canceled)])
            }
            Err(TradingError::OrderNotFound) => {
                Err(ExecError::rejected(RejectCategory::NotFound, "cancel: order not found"))
            }
            Err(e) => Err(ExecError::rejected(RejectCategory::Internal, format!("cancel: {e}"))),
        }
    }

    /// Handle a place-order message (extracted from `handle`).
    ///
    /// Runs the full order lifecycle: parse → pre-trade balance check
    /// → match → fill events → settlement. `inner` is the
    /// already-held module lock; the order book and reusable fill
    /// buffer are borrowed from it.
    pub(crate) fn handle_place(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        let (market, mut order, _owner_placeholder) =
            Self::parse_place(body).ok_or(ExecError::Malformed)?;
        // The tx sender is the order owner (self-trade checks
        // and settlement attribution use this).
        order.owner = ctx.sender;

        // Split the borrow: `inner` derefs to `Inner`, and the
        // settlement code below needs the book maps and the base
        // custody maps disjointly.
        let Inner { markets, fills, base_balances, base_holds, fee_vault, .. } = inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                format!("market {market} does not exist"),
            ));
        };

        // Reservations (C6 + DvP): if the ledger is wired, BOTH sides
        // escrow their obligation up front — a reservation, not a
        // check.
        //
        // A buy DEBITS its worst-case quote cost: limit buys reserve
        // `price × qty` (fills can only cost less); market buys
        // reserve the real sweep cost of `qty` through the ask
        // ladder (`engine.sweep_cost`) — a market order has no
        // limit, so `price × qty` would be meaningless. Without a
        // reservation an unfunded taker could sweep the book and
        // leave every fill unsettled.
        //
        // A sell moves its full `qty` out of the owner's free base
        // custody (`base_balances`) into `taker_base` — the
        // deliverable side of every fill the order produces. A sell
        // whose owner cannot prove base custody cannot rest or
        // execute at all.
        //
        // Both reservations release piecewise at settlement: fills
        // deliver their actual quantity, a surviving resting
        // remainder keeps `price × resting_qty` quote / `resting_qty`
        // base held — which is exactly what `TAG_CANCEL` refunds
        // later, exactly once. Resting orders ARE the reservation
        // ledger (buys implicitly via `price × qty`, sells via
        // `base_holds`): a maker fill pays from obligations already
        // escrowed at rest time, so settlement below cannot fail on
        // insolvency.
        let mut reservation = 0u64;
        let mut taker_base = Qty(0);
        if self.ledger.is_some() {
            match order.side {
                Side::Buy => {
                    let ledger = self.ledger.as_ref().ok_or(ExecError::Malformed)?;
                    // Scale-14 notional → scale-6 quote. Reject rather
                    // than cap on u64 overflow — saturating would
                    // silently change what the buyer pays.
                    let notional = match order.order_type {
                        OrderType::Market => engine.sweep_cost(Side::Buy, order.qty.0, None),
                        _ => u128::from(order.price.0) * u128::from(order.qty.0),
                    };
                    let quote_needed = u64::try_from(notional / PRICE_SCALE).map_err(|_| {
                        ExecError::rejected(
                            RejectCategory::InvalidInput,
                            "buy notional exceeds u64 quote range",
                        )
                    })?;
                    // Debit up front — fails here, BEFORE the book is
                    // touched, on insufficient funds.
                    ledger.debit(&ctx.sender, quote_needed).map_err(|_| {
                        ExecError::rejected(
                            RejectCategory::InsufficientFunds,
                            "insufficient balance for buy order",
                        )
                    })?;
                    reservation = quote_needed;
                }
                Side::Sell => {
                    // Deduct the order's full qty from free base
                    // custody. Custody only exists once deposits are
                    // made — and deposits require the ledger — so
                    // inside `self.ledger.is_some()` a zero entry is
                    // an honest rejection, not a test-mode artifact.
                    let key = (ctx.sender, market);
                    let free = base_balances.get(&key).copied().unwrap_or_default();
                    if free < order.qty {
                        return Err(ExecError::rejected(
                            RejectCategory::InsufficientFunds,
                            "insufficient base custody for sell order",
                        ));
                    }
                    // `free >= qty` was just proven — cannot underflow.
                    let bal = base_balances.get(&key).copied().ok_or(ExecError::Malformed)?;
                    base_balances.insert(key, qty_sub(bal, order.qty).ok_or(ExecError::Malformed)?);
                    taker_base = order.qty;
                }
            }
        }

        // Reuse the fill buffer across calls — zero alloc.
        fills.clear();
        // `ObserveRemovals` never restricts a fill — it records
        // every maker the sweep shrank or removed without one (STP
        // prevention), so the obligations those orders held at rest
        // can be released below. A resting order IS its reservation;
        // a maker the engine deletes unreported would strand that
        // escrow forever.
        let mut removed: Vec<trading::MakerRemoval> = Vec::new();
        let outcome = match engine.place_with_cap(
            order,
            fills,
            &mut trading::ObserveRemovals { removed: &mut removed },
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                // Engine rejected the order — nothing matched and
                // nothing rests, so both reservations come back in
                // full. Crediting the account we just debited cannot
                // overflow; the map_err is defensive.
                if reservation > 0
                    && let Some(ledger) = &self.ledger
                {
                    ledger.credit(&ctx.sender, reservation).map_err(|_| {
                        ExecError::rejected(RejectCategory::Internal, "engine-reject refund failed")
                    })?;
                }
                if taker_base.0 > 0 {
                    let free =
                        base_balances.get(&(ctx.sender, market)).copied().unwrap_or_default();
                    base_balances.insert(
                        (ctx.sender, market),
                        qty_add(free, taker_base).ok_or(ExecError::Malformed)?,
                    );
                }
                return Err(ExecError::rejected(RejectCategory::Internal, format!("engine: {e}")));
            }
        };

        // Emit one event per fill + one for the outcome.
        let mut events = Vec::with_capacity(fills.len() + 1);
        for f in fills.iter() {
            events.push(fill_event(*f));
        }

        // Settlement (plan.md §9.2, C6 + DvP): BOTH sides of every
        // fill were ALREADY escrowed — the buyer's quote via the
        // reservation above (taker) or the debit it has held since
        // resting (maker), the seller's base via `taker_base` or the
        // maker's `base_holds` entry. Each fill therefore swaps
        // obligations that provably exist: no debit can fail here,
        // which is the point — the book mutation above is NOT rolled
        // back on a post-`place` error (the engine lives in module
        // memory, invisible to the executor's state journal), so
        // nothing after `place` may fail. The remaining `map_err`s
        // guard invariants that are unreachable while they hold:
        // per-fill notional ≤ the debited reservation (u64 range),
        // and credit overflow only if an account approaches
        // u64::MAX — impossible while total supply stays below it
        // (enforced at mint/genesis).
        //
        // A maker sell whose hold cannot cover its fill is the one
        // provably-impossible case this code still handles: state
        // imported from before custody existed carries resting sells
        // with no hold. Such a fill settles VOID — the book consumed
        // the order, but no quote moves and no base is minted — the
        // `unbacked_sell_fill` event keeps the anomaly auditable.
        if let Some(ledger) = &self.ledger {
            BookSettlement { ledger, base_balances, base_holds, fee_vault, events: &mut events }
                .apply(
                    market,
                    TakerCtx {
                        price: order.price,
                        owner: ctx.sender,
                        reservation,
                        base: taker_base,
                    },
                    outcome,
                    fills,
                )?;
        }

        events.push(outcome_event(market, outcome));
        // Release maker holds + report every non-fill book change
        // the sweep applied, so downstream accounting sees each
        // obligation the book released — a maker the engine deleted
        // silently would be invisible to settlement reconciliation.
        self.release_maker_holds(market, &removed, base_balances, base_holds, &mut events)?;
        Ok(events)
    }

    /// Release the obligations the sweep freed without a fill and
    /// emit one event per removal/decrement.
    ///
    /// - A resting **buy** held `price × removed_qty` of quote since
    ///   it rested; a decremented one holds `price × remaining` now,
    ///   so the released slice is `price × removed_qty` in both
    ///   cases. The ledger credit cannot overflow: it returns funds
    ///   debited from this same account at rest time.
    /// - A resting **sell** holds `removed_qty` of base in
    ///   `base_holds` — released back to the owner's free custody.
    ///   `min(hold, removed_qty)` clamps the release to what is
    ///   actually held: a sell imported from before custody existed
    ///   holds nothing, so it releases nothing.
    pub(crate) fn release_maker_holds(
        &self,
        market: u8,
        removed: &[trading::MakerRemoval],
        base_balances: &mut framework::CommittedMap<(Address, u8), Qty>,
        base_holds: &mut framework::CommittedMap<(Address, u8), Qty>,
        events: &mut Vec<Event>,
    ) -> Result<(), ExecError> {
        if let Some(ledger) = &self.ledger {
            for r in removed {
                if r.side == Side::Buy && r.removed_qty > 0 {
                    let refund = u64::try_from(
                        u128::from(r.price) * u128::from(r.removed_qty) / PRICE_SCALE,
                    )
                    .map_err(|_| {
                        ExecError::rejected(
                            RejectCategory::Internal,
                            "STP release exceeds u64 quote range",
                        )
                    })?;
                    if refund > 0 {
                        ledger.credit(&r.owner, refund).map_err(|_| {
                            ExecError::rejected(
                                RejectCategory::Internal,
                                "STP release refund failed",
                            )
                        })?;
                    }
                }
            }
        }
        for r in removed {
            if r.side == Side::Sell && r.removed_qty > 0 {
                let key = (r.owner, market);
                let release =
                    base_holds.get(&key).copied().unwrap_or_default().min(Qty(r.removed_qty));
                if release.0 > 0 {
                    let held = base_holds.get(&key).copied().ok_or(ExecError::Malformed)?;
                    base_holds.insert(key, qty_sub(held, release).ok_or(ExecError::Malformed)?);
                    let free = base_balances.get(&key).copied().unwrap_or_default();
                    base_balances.insert(key, qty_add(free, release).ok_or(ExecError::Malformed)?);
                }
            }
            events.push(removal_event(market, *r));
        }
        Ok(())
    }

    /// Handle a register-order message: put an off-chain-matched
    /// order's authorization on-chain under `(sender, client_id)`.
    ///
    /// Registration is what makes a batch-settle leg authorized: the
    /// sender's signature fixes `market`, `side`, `limit_price`, and
    /// `qty`, so the settlement operator can later fill the order
    /// only within those bounds. Both sides escrow at registration:
    /// a buy escrows `price × qty / PRICE_SCALE` of quote (the
    /// reservation every later fill pays out of, so settlement can
    /// never fail on buyer insolvency) and a sell escrows `qty` of
    /// base custody (the delivery every later fill demands, so a
    /// leg can never pay an undelivering seller).
    ///
    /// Rejects: malformed body, unlisted market, non-positive or
    /// off-config price/qty (same tick/lot/band rules as a fill
    /// leg), a duplicate `(owner, client_id)` key, the module-wide
    /// registered-order cap, missing ledger wiring, and (buys) an
    /// escrow the sender cannot cover.
    /// Admission checks on the order registry: the `(owner,
    /// client_id)` pair must be fresh and the bounded table must
    /// have a slot free. Both are `Precondition` — state-dependent,
    /// retryable once the registry changes.
    fn check_order_slot(
        registered: &framework::CommittedMap<OrderKey, RegisteredOrder>,
        key: &OrderKey,
    ) -> Result<(), ExecError> {
        if registered.contains_key(key) {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "register: duplicate client order id",
            ));
        }
        if registered.len() >= MAX_REGISTERED_ORDERS {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "register: order registry full",
            ));
        }
        Ok(())
    }

    pub(crate) fn handle_register(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != REGISTER_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let market = u16::from_le_bytes(body[0..2].try_into().map_err(|_| ExecError::Malformed)?);
        let side = decode_side(body[2]).ok_or(ExecError::Malformed)?;
        let price = u64::from_le_bytes(body[3..11].try_into().map_err(|_| ExecError::Malformed)?);
        let qty = u64::from_le_bytes(body[11..19].try_into().map_err(|_| ExecError::Malformed)?);
        let client_id =
            u64::from_le_bytes(body[19..27].try_into().map_err(|_| ExecError::Malformed)?);

        let Inner { markets, registered, base_balances, .. } = &mut *inner;
        let cfg = markets
            .get(usize::from(market))
            .and_then(Option::as_ref)
            .map(|e| *e.config())
            .ok_or_else(|| {
                ExecError::rejected(
                    RejectCategory::NotFound,
                    format!("market {market} does not exist"),
                )
            })?;
        // The order itself must be placeable: same tick/lot/band
        // rules a fill leg enforces, applied at authorization time so
        // an off-book order can never be registered.
        if qty == 0
            || !qty.is_multiple_of(cfg.lot_size.0)
            || price < cfg.min_price.0
            || price > cfg.max_price.0
            || !price.is_multiple_of(cfg.tick_size.0)
        {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                "register: price/qty outside market config",
            ));
        }

        let key = OrderKey { owner: ctx.sender, client_id };
        Self::check_order_slot(registered, &key)?;

        // Escrow — both sides, denominated in the side's obligation
        // asset (`reserved` is quote for buys, base for sells):
        //
        // - A buy debits `limit × qty` of ledger quote up front —
        //   every fill against this order pays out of the escrow, so
        //   settlement can never draw on an insolvent buyer. Reject
        //   rather than cap on u64 overflow: saturating would
        //   silently change what the buyer authorized.
        // - A sell moves `qty` of base out of the owner's free
        //   custody into `reserved` — the delivery a fill can demand.
        //   Without the ledger no deposit path exists, so the free
        //   balance is always zero and the check rejects naturally.
        let reserved = match side {
            Side::Buy => {
                let ledger = self.ledger.as_ref().ok_or_else(|| {
                    ExecError::rejected(RejectCategory::Internal, "register requires ledger wiring")
                })?;
                let amount = u64::try_from(u128::from(price) * u128::from(qty) / PRICE_SCALE)
                    .map_err(|_| {
                        ExecError::rejected(
                            RejectCategory::Precondition,
                            "register: escrow exceeds u64 quote range",
                        )
                    })?;
                ledger.debit(&ctx.sender, amount).map_err(|_| {
                    ExecError::rejected(
                        RejectCategory::InsufficientFunds,
                        "register: insufficient balance for buy escrow",
                    )
                })?;
                Reserved::Quote(amount)
            }
            Side::Sell => {
                // `u8` conversion cannot fail: the market-existence
                // check above bounds `market` to the 256-slot engine
                // space.
                let m = u8::try_from(market).map_err(|_| {
                    ExecError::rejected(
                        RejectCategory::InvalidInput,
                        "register: market out of range",
                    )
                })?;
                let key = (ctx.sender, m);
                let free = base_balances.get(&key).copied().unwrap_or_default();
                if free < Qty(qty) {
                    return Err(ExecError::rejected(
                        RejectCategory::InsufficientFunds,
                        "register: insufficient base custody for sell",
                    ));
                }
                let bal = base_balances.get(&key).copied().ok_or(ExecError::Malformed)?;
                base_balances.insert(key, qty_sub(bal, Qty(qty)).ok_or(ExecError::Malformed)?);
                Reserved::Base(Qty(qty))
            }
        };

        registered.insert(
            key,
            RegisteredOrder { market, limit_price: Price(price), remaining: Qty(qty), reserved },
        );
        Ok(vec![Event {
            module: "exchange",
            kind: "order_registered",
            data: {
                let mut d = Vec::with_capacity(20 + 8 + 2 + 1 + 8 + 8);
                d.extend_from_slice(&ctx.sender.0);
                d.extend_from_slice(&client_id.to_le_bytes());
                d.extend_from_slice(&market.to_le_bytes());
                d.push(encode_side(side));
                d.extend_from_slice(&price.to_le_bytes());
                d.extend_from_slice(&qty.to_le_bytes());
                d
            },
        }])
    }

    /// Handle a cancel-registered message: remove the sender's order
    /// and refund its remaining escrow.
    ///
    /// The escrow refund is credited BEFORE the order is removed, so
    /// a credit failure (balance overflow — impossible while supply
    /// stays under `u64::MAX`) leaves the order live rather than
    /// stranding its escrow.
    pub(crate) fn handle_cancel_registered(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != CANCEL_REGISTERED_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let client_id =
            u64::from_le_bytes(body[0..8].try_into().map_err(|_| ExecError::Malformed)?);
        let key = OrderKey { owner: ctx.sender, client_id };
        let Some(order) = inner.registered.get(&key) else {
            return Err(ExecError::rejected(RejectCategory::NotFound, "cancel: order not found"));
        };
        // The denomination carries the routing: quote escrow returns
        // to the ledger, base escrow returns to free base custody.
        let refund = order.reserved.get();
        match order.reserved {
            // Buy escrow is ledger quote — refund to the ledger.
            Reserved::Quote(_) => {
                if refund > 0 {
                    let ledger = self.ledger.as_ref().ok_or_else(|| {
                        ExecError::rejected(
                            RejectCategory::Internal,
                            "cancel requires ledger wiring",
                        )
                    })?;
                    ledger.credit(&ctx.sender, refund).map_err(|_| {
                        ExecError::rejected(
                            RejectCategory::Internal,
                            "cancel: escrow refund failed",
                        )
                    })?;
                }
            }
            // Sell escrow is base custody — refund to the owner's
            // free base balance on the order's market, not the
            // ledger. `u8` conversion is safe: registration rejected
            // any market beyond the 256-slot engine space.
            Reserved::Base(residue) => {
                if residue.0 > 0 {
                    let market = u8::try_from(order.market).map_err(|_| {
                        ExecError::rejected(
                            RejectCategory::InvalidInput,
                            "cancel: market out of range",
                        )
                    })?;
                    let free =
                        inner.base_balances.get(&(ctx.sender, market)).copied().unwrap_or_default();
                    inner.base_balances.insert(
                        (ctx.sender, market),
                        qty_add(free, residue).ok_or(ExecError::Malformed)?,
                    );
                }
            }
        }
        inner.registered.remove(&key);
        Ok(vec![Event {
            module: "exchange",
            kind: "order_canceled",
            data: {
                let mut d = Vec::with_capacity(20 + 8 + 8);
                d.extend_from_slice(&ctx.sender.0);
                d.extend_from_slice(&client_id.to_le_bytes());
                d.extend_from_slice(&refund.to_le_bytes());
                d
            },
        }])
    }

    /// Handle a deposit-base message: debit `amount` of native token
    /// from the sender's ledger balance into their free base custody
    /// on `market` — the 1:1 backing that makes custodial base a real
    /// asset rather than an unbacked module mint.
    ///
    /// Rejects: malformed body, zero amount, unlisted market (base
    /// for a market that does not exist is dead state), missing
    /// ledger wiring (nothing to back the deposit), and a ledger
    /// debit the sender cannot cover. A custody-entry overflow
    /// refunds the debit and rejects — conservation is never broken
    /// to admit a deposit.
    pub(crate) fn handle_deposit_base(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != CUSTODY_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let market = body[0];
        let amount = u64::from_le_bytes(body[1..9].try_into().map_err(|_| ExecError::Malformed)?);
        if amount == 0 {
            return Err(ExecError::rejected(RejectCategory::InvalidInput, "deposit: zero amount"));
        }
        if inner.markets[usize::from(market)].is_none() {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                format!("market {market} does not exist"),
            ));
        }
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::rejected(RejectCategory::Internal, "deposit requires ledger wiring")
        })?;
        ledger.debit(&ctx.sender, amount).map_err(|_| {
            ExecError::rejected(RejectCategory::InsufficientFunds, "deposit: insufficient balance")
        })?;
        let entry = inner.base_balances.get(&(ctx.sender, market)).copied().unwrap_or_default();
        // The 1:1 denomination bridge: `amount` native base units
        // become `amount` scale-6 base micro-units of custody — the
        // module's documented backing choice (the base asset trades
        // in the native unit's own granularity).
        if let Some(v) = qty_add(entry, Qty(amount)) {
            inner.base_balances.insert((ctx.sender, market), v);
        } else {
            // Unreachable while total native supply < u64::MAX
            // (custody is native-backed). Refund the debit so the
            // failed deposit is a no-op, not a loss.
            ledger.credit(&ctx.sender, amount).map_err(|_| {
                ExecError::rejected(RejectCategory::Internal, "deposit: refund failed")
            })?;
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "deposit: base custody overflow",
            ));
        }
        Ok(vec![Event {
            module: "exchange",
            kind: "base_deposited",
            data: {
                let mut d = Vec::with_capacity(20 + 1 + 8);
                d.extend_from_slice(&ctx.sender.0);
                d.push(market);
                d.extend_from_slice(&amount.to_le_bytes());
                d
            },
        }])
    }

    /// Handle a withdraw-base message: return `amount` of the
    /// sender's free base custody on `market` to their ledger
    /// balance. Only `base_balances` (free) is drawable — base locked
    /// in `base_holds` or a registered order's `reserved` must be
    /// released by a fill or cancel first.
    ///
    /// The ledger credit runs BEFORE the custody decrement, so a
    /// credit failure (impossible while supply < `u64::MAX` — the
    /// units were debited out of circulation at deposit) leaves
    /// custody untouched.
    ///
    /// Rejects: malformed body, zero amount, missing ledger wiring,
    /// and a free balance that does not cover the withdrawal.
    pub(crate) fn handle_withdraw_base(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != CUSTODY_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let market = body[0];
        let amount = u64::from_le_bytes(body[1..9].try_into().map_err(|_| ExecError::Malformed)?);
        if amount == 0 {
            return Err(ExecError::rejected(RejectCategory::InvalidInput, "withdraw: zero amount"));
        }
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::rejected(RejectCategory::Internal, "withdraw requires ledger wiring")
        })?;
        let free = inner.base_balances.get(&(ctx.sender, market)).copied().unwrap_or_default();
        // Same 1:1 bridge as the deposit: `amount` native units
        // equals `amount` base micro-units of custody.
        if free < Qty(amount) {
            return Err(ExecError::rejected(
                RejectCategory::InsufficientFunds,
                "withdraw: insufficient free base",
            ));
        }
        ledger.credit(&ctx.sender, amount).map_err(|_| {
            ExecError::rejected(RejectCategory::Internal, "withdraw: credit failed")
        })?;
        // `free >= amount` was just proven — the decrement cannot
        // underflow.
        let bal =
            inner.base_balances.get(&(ctx.sender, market)).copied().ok_or(ExecError::Malformed)?;
        inner
            .base_balances
            .insert((ctx.sender, market), qty_sub(bal, Qty(amount)).ok_or(ExecError::Malformed)?);
        Ok(vec![Event {
            module: "exchange",
            kind: "base_withdrawn",
            data: {
                let mut d = Vec::with_capacity(20 + 1 + 8);
                d.extend_from_slice(&ctx.sender.0);
                d.push(market);
                d.extend_from_slice(&amount.to_le_bytes());
                d
            },
        }])
    }

    /// Handle a batch-settle message: apply pre-matched fills from
    /// the off-chain matching server against on-chain registered
    /// orders. Each valid fill leg credits the seller a
    /// **chain-computed** amount out of the buy order's escrow and
    /// returns the buyer's price-improvement rebate — no re-matching,
    /// no trust in operator-supplied amounts, and no bare
    /// counterparties: the operator can only settle between orders
    /// the owners themselves signed for.
    ///
    /// Body format: `[fill_count:4 LE][fill entries...]`
    /// Each fill entry:
    /// `[market:2][price:8][qty:8][buy_owner:20][buy_id:8][sell_owner:20][sell_id:8]`.
    ///
    /// # Security
    ///
    /// - **Authorization:** only `ctx.sender == settlement_operator`
    ///   (the genesis-configured matcher identity) may submit batch
    ///   settlements. But the operator is NOT a balance-transfer
    ///   authority: every leg must name two live registered orders,
    ///   and the fill is checked against what those owners signed
    ///   for — market, side, limit price, and remaining quantity.
    ///   A leg that fails validation is skipped with a
    ///   `fill_rejected` event — unauthorized legs cannot move funds.
    /// - **Replay safety:** a fill consumes both orders'
    ///   `remaining`. Resubmitting the same batch (or the same fills
    ///   re-encoded under a new batch) re-references orders whose
    ///   quantity is already consumed, so every replayed leg fails
    ///   its remaining-quantity check — unique fills come from
    ///   consumption, not an unbounded fill-id set.
    /// - **Amounts:** the settlement amount is recomputed on-chain as
    ///   `price * qty / PRICE_SCALE` with checked `u128`/`u64` math.
    ///   Neither side is debited at settle time: the buy's quote and
    ///   the sell's base were both escrowed at registration. A leg
    ///   pays the seller `pays − fee` out of the escrow slice
    ///   `buy.limit * qty / PRICE_SCALE` (the remainder rebating the
    ///   buyer's price improvement), delivers `qty` of base into the
    ///   buyer's custody, and accrues `fee` into the market vault —
    ///   insolvency during settlement is impossible by construction,
    ///   on both legs.
    /// - **Aggregation:** seller payments accumulate per (buyer,
    ///   seller) pair in an open-addressed flat index map (one probe
    ///   vs the `BTreeMap`'s ~16-level pointer chase per leg); the
    ///   drain sorts by key, so credit order is deterministic and
    ///   each pair settles in one `ledger.credit`. Buyer rebates and
    ///   per-order consumption accumulate the same way and apply in
    ///   sorted order.
    ///
    /// A pair whose seller credit fails is skipped with a
    /// `settlement_failed` event and its legs are voided wholesale —
    /// no order quantity is consumed and no rebate released, so a
    /// failed leg has exactly zero economic effect. Other legs in
    /// the batch still settle — one overflowing account cannot halt
    /// settlement for the whole batch.
    ///
    /// `inner` is the already-held module lock (batch settle never
    /// mutates the books — only the registered-order map).
    pub(crate) fn handle_batch_settle(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        // Authorization: only the settlement operator may submit
        // fills — and only against orders the owners signed for.
        if self.settlement_operator != Some(ctx.sender) {
            return Err(ExecError::rejected(
                RejectCategory::Unauthorized,
                "unauthorized settlement operator",
            ));
        }
        let fill_count = usize::try_from(u32::from_le_bytes(
            body.get(0..4)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ))
        .map_err(|_| ExecError::Malformed)?;
        // Bound the batch: a byzantine operator must not be able to
        // submit arbitrarily large fill sets.
        if fill_count > MAX_BATCH_FILLS {
            return Err(ExecError::Malformed);
        }
        if body.len() != 4 + fill_count * FILL_ENTRY_LEN {
            return Err(ExecError::Malformed);
        }

        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::rejected(RejectCategory::Internal, "batch settle requires ledger wiring")
        })?;

        let Inner { markets, registered, base_balances, fee_vault, .. } = &mut *inner;

        // Snapshot the market configs once — batch settle never
        // mutates the books, so one pass over `markets` serves every
        // leg.
        let configs: Vec<Option<MarketConfig>> =
            markets.iter().map(|m| m.as_ref().map(|e| *e.config())).collect();

        // ── Pass 1: parse + validate every leg ────────────────────
        // Each valid leg produces a `LegPlan` and accumulates its
        // seller payment into the (buyer, seller) pair map. The
        // `consumed` scratch bounds each order's cumulative quantity
        // across the whole batch BEFORE anything mutates, so two
        // legs can never spend the same authorized quantity.
        //
        // Pair aggregation uses an open-addressed flat index map
        // over a flat `entries` Vec instead of a `BTreeMap`: the
        // tree version costs ~150-250ns/leg at large batch sizes
        // (16+ levels of pointer-chasing per lookup on a 40-byte
        // key), while the flat probe is ~15-25ns — one hash, 1-3
        // cache-resident slots. `entries` keeps insertion order; the
        // drain sorts by key, preserving the BTreeMap's exact
        // deterministic credit order, so observable behavior is
        // unchanged.
        //
        // Table capacity is 2× the leg count (load factor ≤ 0.5,
        // probes stay short); every entry slot is `u32::MAX` = empty.
        let table_cap = (fill_count.saturating_mul(2)).next_power_of_two().max(64);
        let mut table = vec![u32::MAX; table_cap];
        // Capacity for the worst case (every leg a distinct pair) —
        // untouched reserved pages cost nothing, while distinct-heavy
        // batches avoid ~16 realloc copies.
        let mut entries: Vec<((Address, Address), u64)> = Vec::with_capacity(fill_count);
        let mut plans: Vec<LegPlan> = Vec::with_capacity(fill_count);
        let mut consumed: BTreeMap<OrderKey, Qty> = BTreeMap::new();
        let mut events = Vec::new();
        for i in 0..fill_count {
            match settle_leg(body, 4 + i * FILL_ENTRY_LEN, &configs, registered, &mut consumed)? {
                Some(plan) => {
                    // Flat-map lookup: hash the pair, linear-probe
                    // the table for a matching key or an empty slot.
                    // On miss, append to `entries` and record the
                    // index; on hit, accumulate in place.
                    let key = (plan.buyer, plan.seller);
                    let mask = table_cap - 1;
                    // Masked to < 2^17 slots on the same line — the
                    // u64->usize cast cannot truncate a meaningful
                    // index on any supported target.
                    #[allow(clippy::cast_possible_truncation)]
                    let mut slot = (pair_hash(&plan.buyer.0, &plan.seller.0) as usize) & mask;
                    let idx = loop {
                        let t = table[slot];
                        if t == u32::MAX {
                            let i =
                                u32::try_from(entries.len()).map_err(|_| ExecError::Malformed)?;
                            entries.push((key, 0));
                            table[slot] = i;
                            break i;
                        }
                        if entries[usize::try_from(t).map_err(|_| ExecError::Malformed)?].0 == key {
                            break t;
                        }
                        slot = (slot + 1) & mask;
                    };
                    let entry =
                        &mut entries[usize::try_from(idx).map_err(|_| ExecError::Malformed)?].1;
                    // The pair credit is the seller's NET payment —
                    // gross minus the fee (the fee accrues per
                    // market in `consume_and_release`).
                    if let Some(sum) = entry.checked_add(plan.pays - plan.fee) {
                        *entry = sum;
                        plans.push(plan);
                    } else {
                        // Practically unreachable — void the leg
                        // rather than silently saturating.
                        events.push(rejected_leg_event(i, "pair total overflow"));
                    }
                }
                None => events.push(rejected_leg_event(i, "invalid fill leg")),
            }
        }

        // ── Drain 1: pay sellers, one credit per pair ─────────────
        // Sorted key order — identical to the previous `BTreeMap`
        // iteration, so event sequence is deterministic. The buyer
        // side needs no debit: the escrow was taken at registration.
        // A pair whose credit fails is voided wholesale below — its
        // legs consume nothing.
        entries.sort_unstable_by_key(|e| e.0);
        let mut failed_pairs: std::collections::BTreeSet<(Address, Address)> =
            std::collections::BTreeSet::new();
        for ((buyer, seller), amount) in &entries {
            if ledger.credit(seller, *amount).is_err() {
                failed_pairs.insert((*buyer, *seller));
                events.push(pair_event("settlement_failed", buyer, seller, *amount));
                continue;
            }
            events.push(pair_event("batch_fill", buyer, seller, *amount));
        }

        // ── Pass 2 + drains: apply the surviving legs ────────────
        // Order consumption, buyer rebates, base deliveries, fee
        // accrual, and residue refunds run in `consume_and_release`
        // — every mutation is derived from the validated plans, so
        // a voided pair's legs consume nothing.
        consume_and_release(
            &plans,
            &failed_pairs,
            registered,
            base_balances,
            fee_vault,
            ledger,
            &mut events,
        );

        Ok(events)
    }
}
