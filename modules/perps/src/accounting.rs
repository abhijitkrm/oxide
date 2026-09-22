//! Position accounting for the perps module.
//!
//! Split from `lib.rs` around the conservation invariant:
//! `apply_fill_to_position` / `adjust_position` /
//! `settle_realized` are the only functions that move value
//! between position margin, realized `PnL`, and the insurance
//! fund — every fill flows through here, so the conservation
//! argument has exactly three functions to audit.

use super::{
    Address, CLEARING_ACCOUNT, Event, FillEvent, Inner, MarginClass, PRICE_SCALE, PerpsModule, Side,
};

impl PerpsModule {
    /// Apply a fill to the taker's and maker's positions, release
    /// the maker's order reservation for the filled quantity, and
    /// enforce reduce-only on the maker's remainder. Emits
    /// `realized_pnl` / `bad_debt` / `reduce_only_cancel` events.
    pub(crate) fn apply_fill_to_position(
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
    pub(crate) fn adjust_position(
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
    pub(crate) fn settle_realized(
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
