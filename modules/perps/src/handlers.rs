//! Transaction handlers for the perps module.
//!
//! Split from `lib.rs` around the admission invariant: every
//! user transaction enters through a `handle_*` here, and each
//! handler is the sole place its message type may mutate state —
//! margin checks, reservation release, and clearing-account
//! rejection all live at this boundary so the ordering is
//! auditable in one file.

use super::{
    AccountState, Address, BACKSTOP_UNWIND_SLIPPAGE_BPS, BTreeMap, CLEARING_ACCOUNT,
    CROSS_MARGIN_MARKET, Event, ExecError, FLAG_REDUCE_ONLY, FillEvent, Inner,
    MAX_FUNDING_RATE_BPS, MAX_MARK_STALENESS_BLOCKS, NewOrder, OpenOrderResv, OrderId,
    OrderOutcome, OrderType, PRICE_SCALE, PerpsModule, Price, Qty, ReduceOnlyCap, RejectCategory,
    Side, SignedQty, StpMode, TimeInForce, TradingError, TxContext, cancel_event, fill_event,
    outcome_event,
};
use std::collections::BTreeSet;

impl PerpsModule {
    /// Handle a list-market message (extracted from `handle` to keep
    /// the dispatch function under the clippy line-count gate).
    pub(crate) fn handle_list_market(
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
        cfg.validate().map_err(|e| {
            ExecError::rejected(RejectCategory::Internal, format!("list_market: {e}"))
        })?;
        // Same quorum gate as `TAG_SET_MARK`: a listing
        // eagerly allocates the market's order-pool and
        // id-map arenas, so an unauthenticated listing is a
        // memory-exhaustion primitive. Each tx endorses the
        // exact tagged message; the market lists only once
        // endorsing power strictly exceeds two-thirds.
        let Some(committee) = self.committee.clone() else {
            return Err(ExecError::rejected(
                RejectCategory::Unauthorized,
                "list_market: no committee wired",
            ));
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
    pub(crate) fn handle_apply_funding(
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
            return Err(ExecError::rejected(RejectCategory::NotFound, "market does not exist"));
        }
        // Same quorum gate as `TAG_SET_MARK` — an unauthenticated
        // funding rate is an unauthenticated balance transfer
        // between every long and short on the market, so it takes
        // the same two-thirds endorsement to schedule.
        let Some(committee) = self.committee.clone() else {
            return Err(ExecError::rejected(
                RejectCategory::Unauthorized,
                "apply_funding: no committee wired",
            ));
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
                    return Err(ExecError::rejected(
                        RejectCategory::InvalidInput,
                        format!(
                            "funding rate {rate} bps exceeds bound ±{MAX_FUNDING_RATE_BPS} bps"
                        ),
                    ));
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

    /// The market gate for new orders: the market must exist, and a
    /// market whose mark is older than [`MAX_MARK_STALENESS_BLOCKS`]
    /// is in reduce-only mode (live-pipeline risk control). New
    /// exposure against a price nobody has vouched for recently
    /// cannot be margined honestly, so only reduce-only orders pass:
    /// closing exposure must never be blocked by a feed outage.
    /// Liquidations similarly keep running at the last mark —
    /// freezing risk-reduction during an outage would strand
    /// underwater accounts exactly when they need closing.
    fn check_market_accepts_order(
        inner: &Inner,
        market: u8,
        reduce_only: bool,
    ) -> Result<(), ExecError> {
        if !inner.configs.contains_key(&market) {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                format!("market {market} does not exist"),
            ));
        }
        let stale = inner.mark_updated_at.get(&market).is_none_or(|&updated| {
            inner.current_height.saturating_sub(updated) > MAX_MARK_STALENESS_BLOCKS
        });
        if stale && !reduce_only {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                format!(
                    "market {market} mark is stale (no update in {MAX_MARK_STALENESS_BLOCKS}+ blocks); reduce-only orders only"
                ),
            ));
        }
        Ok(())
    }

    /// Handle a place-order message (extracted from `handle` to keep
    /// the dispatch function under the clippy line-count gate).
    pub(crate) fn handle_place(
        &self,
        ctx: &TxContext,
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
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
        Self::check_market_accepts_order(&inner, market, reduce_only)?;
        {
            let acct = inner.accounts.get(&ctx.sender);
            let pos = acct.and_then(|a| a.positions.get(&market));
            let pos_size = pos.map_or(SignedQty::ZERO, |p| p.size);
            // The position can only close once: closing capacity the
            // account's resting opposing orders in this market have
            // already claimed is not available to this order.
            let cover_booked: u128 = acct.map_or(0, |a| {
                a.open_orders
                    .iter()
                    .filter(|((m, _), r)| {
                        *m == market
                            && ((pos_size.is_long() && r.side == Side::Sell)
                                || (pos_size.is_short() && r.side == Side::Buy))
                    })
                    .map(|(_, r)| u128::from(r.qty))
                    .sum()
            });
            let reducible = u128::from(pos_size.abs_qty().0).saturating_sub(cover_booked);
            // Reduce-only may only close: a request larger than the
            // reducible size would add exposure, which the flag
            // forbids — reject at admission.
            if reduce_only && u128::from(order.qty.0) > reducible {
                return Err(ExecError::rejected(
                    RejectCategory::Precondition,
                    "reduce-only order exceeds reducible position",
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
                    return Err(ExecError::rejected(
                        RejectCategory::InsufficientFunds,
                        "insufficient initial margin",
                    ));
                }
            }
        }

        let Inner { markets, fills, accounts, .. } = &mut *inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                format!("market {market} does not exist"),
            ));
        };

        fills.clear();
        let mut cap =
            ReduceOnlyCap { accounts, market, spent: BTreeMap::new(), removed: Vec::new() };
        let outcome = engine
            .place_with_cap(order, fills, &mut cap)
            .map_err(|e| ExecError::rejected(RejectCategory::Internal, format!("engine: {e}")))?;
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
            Self::record_resting_reservation(
                &mut inner,
                market,
                ctx.sender,
                order_id,
                price,
                resting_qty,
                order.side,
                reduce_only,
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

        Self::margin_check_trade_parties(&mut inner, ctx, market, &fills_owned, &mut events);

        events.push(outcome_event(market, outcome));
        Self::emit_removal_events(market, &removed, &mut events);
        Ok(events)
    }

    /// Post-trade margin check — the taker AND every maker whose
    /// position the fills changed. A maker fill can push the
    /// maker under water (realized loss, or a flip into exposure
    /// it cannot cover); the check is uniform for every account
    /// the trade touched.
    ///
    /// Makers are checked once each, in first-fill order — the order
    /// is consensus-visible (each check may emit events and
    /// liquidate), so the dedupe must not reorder. A `BTreeSet` of
    /// already-checked owners keeps that order at O(fills · log
    /// makers); the previous `Vec::contains` scan was O(fills²) on a
    /// deep sweep (hft-audit-2 T-14).
    fn margin_check_trade_parties(
        inner: &mut Inner,
        ctx: &TxContext,
        market: u8,
        fills_owned: &[FillEvent],
        events: &mut Vec<Event>,
    ) {
        Self::margin_check(inner, &ctx.sender, market, events);
        let mut checked: BTreeSet<Address> = BTreeSet::new();
        for f in fills_owned {
            let maker = f.maker_owner;
            if maker != ctx.sender && checked.insert(maker) {
                Self::margin_check(inner, &maker, market, events);
            }
        }
    }

    /// Release reservations for makers the sweep removed or
    /// decremented without a fill — call before applying fills so
    /// stale entries don't linger. The book is authoritative for
    /// decremented quantities.
    pub(crate) fn release_removal_reservations(
        inner: &mut Inner,
        market: u8,
        removed: &[trading::MakerRemoval],
    ) {
        for r in removed {
            if let Some(mut acct) = inner.accounts.get(&r.owner).cloned() {
                if r.remaining == 0 {
                    acct.open_orders.remove(&(market, r.order_id.0));
                } else if let Some(resv) = acct.open_orders.get_mut(&(market, r.order_id.0)) {
                    resv.qty = r.remaining;
                }
                inner.accounts.insert(r.owner, acct);
            }
        }
    }

    /// Record a resting remainder's margin reservation — extracted
    /// from `handle_place` so the place path stays under the
    /// function-length gate. The fold-safe `with_account_mut`
    /// carries the account in and out of the committed map.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_resting_reservation(
        inner: &mut Inner,
        market: u8,
        owner: Address,
        order_id: OrderId,
        price: Price,
        resting_qty: Qty,
        side: Side,
        reduce_only: bool,
    ) {
        Self::with_account_mut(inner, &owner, |acct| {
            acct.open_orders.insert(
                (market, order_id.0),
                OpenOrderResv { qty: resting_qty.0, price: price.0, side, reduce_only },
            );
        });
    }

    /// Emit one event per non-fill book change the sweep applied:
    /// cap kills are reduce-only cancels; self-trade removals and
    /// decrements get their own kinds so downstream accounting sees
    /// every obligation the book released.
    pub(crate) fn emit_removal_events(
        market: u8,
        removed: &[trading::MakerRemoval],
        events: &mut Vec<Event>,
    ) {
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
    pub(crate) fn handle_cancel(
        &self,
        ctx: &TxContext,
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let (market, order_id) = Self::parse_cancel(body).ok_or(ExecError::Malformed)?;
        let mut inner = framework::lock_state(&self.inner);
        let Inner { markets, .. } = &mut *inner;
        let Some(engine) = markets[usize::from(market)].as_mut() else {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                format!("market {market} does not exist"),
            ));
        };
        if let Some(owner) = engine.order_owner(order_id) {
            if owner != ctx.sender {
                return Err(ExecError::rejected(
                    RejectCategory::Unauthorized,
                    "cancel: not the order owner",
                ));
            }
        } else {
            // Order not on the book: if a reservation entry survives
            // (e.g. an STP-cancelled order the module was never told
            // about), drop it now — the reservation ledger heals
            // itself on contact.
            if let Some(mut acct) = inner.accounts.get(&ctx.sender).cloned() {
                acct.open_orders.remove(&(market, order_id.0));
                inner.accounts.insert(ctx.sender, acct);
            }
            return Err(ExecError::rejected(RejectCategory::NotFound, "cancel: order not found"));
        }
        match engine.cancel(order_id) {
            Ok(canceled) => {
                // Release the margin reservation — removing the entry
                // IS the release; `total_open_order_im` recomputes
                // from live entries.
                if let Some(mut acct) = inner.accounts.get(&ctx.sender).cloned() {
                    acct.open_orders.remove(&(market, order_id.0));
                    inner.accounts.insert(ctx.sender, acct);
                }
                Ok(vec![cancel_event(market, canceled)])
            }
            Err(TradingError::OrderNotFound) => {
                Err(ExecError::rejected(RejectCategory::NotFound, "cancel: order not found"))
            }
            Err(e) => Err(ExecError::rejected(RejectCategory::Internal, format!("cancel: {e}"))),
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
    pub(crate) fn handle_deposit(
        &self,
        ctx: &TxContext,
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let (market, amount) = Self::parse_margin(body).ok_or(ExecError::Malformed)?;
        let mut inner = framework::lock_state(&self.inner);
        let mut acct = inner.accounts.get(&ctx.sender).cloned().unwrap_or_default();
        let balance = if market == CROSS_MARGIN_MARKET {
            &mut acct.cross_margin
        } else {
            &mut acct.positions.entry(market).or_default().isolated_margin
        };
        // Overflow check first: never debit the ledger for margin we
        // cannot represent.
        let new_balance = balance.checked_add(amount).ok_or_else(|| {
            ExecError::rejected(RejectCategory::Precondition, "margin balance overflow")
        })?;
        if let Some(ledger) = &self.ledger {
            ledger.debit(&ctx.sender, amount)?;
        }
        *balance = new_balance;
        // Fold the credited account back — the `?` exits above
        // never reach this insert, so a rejected debit leaves the
        // account untouched exactly as before.
        inner.accounts.insert(ctx.sender, acct);
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
    pub(crate) fn handle_withdraw(
        &self,
        ctx: &TxContext,
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
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
                return Err(ExecError::rejected(
                    RejectCategory::InsufficientFunds,
                    "insufficient margin",
                ));
            };
            if acct.cross_margin < amount {
                return Err(ExecError::rejected(
                    RejectCategory::InsufficientFunds,
                    "insufficient margin",
                ));
            }
            let equity_after = acct.equity(&inner.marks, &inner.configs) - i128::from(amount);
            let required = acct
                .total_initial_margin(&inner.marks, &inner.configs)
                .saturating_add(acct.total_open_order_im(&inner.configs));
            if equity_after < i128::try_from(required).unwrap_or(i128::MAX) {
                return Err(ExecError::rejected(
                    RejectCategory::InsufficientFunds,
                    "withdrawal would breach initial margin",
                ));
            }
        } else {
            let acct = inner.accounts.get(&ctx.sender);
            let pos = acct.and_then(|a| a.positions.get(&market));
            let iso = pos.map_or(0u64, |p| p.isolated_margin);
            if iso < amount {
                return Err(ExecError::rejected(
                    RejectCategory::InsufficientFunds,
                    "insufficient margin",
                ));
            }
            if let Some(p) = pos.filter(|p| p.is_open()) {
                let mark = inner.marks.get(&market).copied().unwrap_or(p.entry_price);
                let cfg = inner.configs.get(&market);
                if let Some(cfg) = cfg {
                    let price_scale = i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
                    let upnl_scale6 = p.unrealized_pnl(mark) / price_scale;
                    // `iso >= amount` was proven above — saturating is
                    // the same value and stays panic-free under release
                    // `overflow-checks`.
                    let equity_after =
                        i128::from(iso.saturating_sub(amount)).saturating_add(upnl_scale6);
                    let leverage = u128::from(cfg.max_leverage.max(1));
                    let pos_im = p.notional(mark) / leverage / PRICE_SCALE;
                    if equity_after < i128::try_from(pos_im).unwrap_or(i128::MAX) {
                        return Err(ExecError::rejected(
                            RejectCategory::InsufficientFunds,
                            "withdrawal would breach position margin",
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
        Self::with_account_mut(&mut inner, &ctx.sender, |acct| {
            // Sufficiency was proven by the solvency gate above —
            // saturating debits the same value and fails closed
            // rather than panicking mid-withdraw.
            if market == CROSS_MARGIN_MARKET {
                acct.cross_margin = acct.cross_margin.saturating_sub(amount);
            } else {
                let pos = acct.positions.entry(market).or_default();
                pos.isolated_margin = pos.isolated_margin.saturating_sub(amount);
            }
        });
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
    pub(crate) fn margin_check(
        inner: &mut Inner,
        sender: &Address,
        market: u8,
        events: &mut Vec<Event>,
    ) {
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
    pub(crate) fn reject_clearing_sender(ctx: &TxContext) -> Result<(), ExecError> {
        if ctx.sender == CLEARING_ACCOUNT {
            return Err(ExecError::rejected(
                RejectCategory::Unauthorized,
                "clearing account cannot transact",
            ));
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
    pub(crate) fn unwind_clearing(inner: &mut Inner, events: &mut Vec<Event>) {
        // Collect the backstop's open inventory (market, signed
        // size) under a shared borrow — the order pass mutates.
        let inventory: Vec<(u8, SignedQty)> =
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
            let lot = cfg.base.lot_size.0.max(1);
            let qty = size.abs_qty().0 - (size.abs_qty().0 % lot);
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
            let tick = cfg.base.tick_size.0.max(1);
            let raw_limit = if size.is_long() {
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
            let limit_price = if size.is_long() {
                raw_limit.div_ceil(tick).saturating_mul(tick).max(cfg.base.min_price.0)
            } else {
                (raw_limit / tick).saturating_mul(tick).min(cfg.base.max_price.0)
            };
            let order = NewOrder {
                side: if size.is_long() { Side::Sell } else { Side::Buy },
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
