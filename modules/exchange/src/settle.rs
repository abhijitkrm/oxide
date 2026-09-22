//! Book-path settlement machinery for the exchange module.
//!
//! Split from `lib.rs` around the settlement invariant:
//! [`BookSettlement::apply`] is the single function that turns an
//! admitted taker order plus maker fills into ledger movements —
//! `TakerCtx` carries everything the admitted order needs,
//! `LegPlan`/`OrderDelta` accumulate per-leg and per-order deltas,
//! and conservation (taker pays exactly what makers receive, plus
//! fee) is checkable in this file alone.

use super::{
    Address, Arc, BPS_DENOM, BTreeMap, Event, ExecError, FEE_BPS, FillEvent, MarketConfig,
    OrderKey, OrderOutcome, PRICE_SCALE, Price, RegisteredOrder, Reserved, Side,
};
use crate::codec::{w32, w64};

/// The taker's side of a book-path settlement — everything `apply`
/// needs from the admitted order and its admission-time escrows.
pub(crate) struct TakerCtx {
    /// Taker limit price — bounds the buy-side reservation residue.
    pub(crate) price: Price,
    /// Taker owner — recipient of refunds and taker-side deliveries.
    pub(crate) owner: Address,
    /// Quote units reserved at admission (buys only; 0 for sells).
    pub(crate) reservation: u64,
    /// Base units reserved at admission (sells only; 0 for buys).
    pub(crate) base: u64,
}

/// The mutable settlement surfaces a book-path place touches,
/// bundled so the fill loop borrows one value instead of five
/// disjoint `Inner` fields. All custody mutations go through here.
pub(crate) struct BookSettlement<'a> {
    /// The native ledger — quote credits and reservation refunds.
    pub(crate) ledger: &'a Arc<dyn framework::Balances + Send + Sync>,
    /// Free base custody (buyer deliveries land here).
    pub(crate) base_balances: &'a mut BTreeMap<(Address, u8), u64>,
    /// Resting-sell base holds (maker deliveries draw from here).
    pub(crate) base_holds: &'a mut BTreeMap<(Address, u8), u64>,
    /// Per-market protocol-fee sink (quote units).
    pub(crate) fee_vault: &'a mut BTreeMap<u8, u64>,
    /// The event sink every settlement-visible mutation appends to.
    pub(crate) events: &'a mut Vec<Event>,
}

impl BookSettlement<'_> {
    /// Settle every fill the engine produced, then release the
    /// taker's leftover reservations.
    ///
    /// Per fill, `DvP`: the seller's base moves into the buyer's free
    /// custody and the buyer's quote pays the seller minus the
    /// [`FEE_BPS`] protocol fee (accrued to `fee_vault`). Delivery
    /// is proven BEFORE payment: a maker sell whose `base_holds`
    /// entry cannot cover the fill settles VOID — the book consumed
    /// the order, but no quote moves and no base is minted. Only
    /// state imported from before custody existed can produce that
    /// shape; the `unbacked_sell_fill` event keeps it auditable.
    /// The remaining `map_err`s guard invariants unreachable while
    /// they hold: per-fill notional ≤ the debited reservation (u64
    /// range), and credit overflow only if an account approaches
    /// `u64::MAX` — impossible while total supply stays below it
    /// (enforced at mint/genesis).
    pub(crate) fn apply(
        &mut self,
        market: u8,
        taker: TakerCtx,
        outcome: OrderOutcome,
        fills: &[FillEvent],
    ) -> Result<(), ExecError> {
        // `taker_paid` accumulates only fills that actually settled
        // — a voided fill neither pays nor receives.
        let mut taker_paid = 0u64;
        let mut taker_base = taker.base;
        for f in fills {
            let notional = u128::from(f.price.0) * u128::from(f.qty.0);
            let quote_amount = u64::try_from(notional / PRICE_SCALE).map_err(|_| {
                ExecError::ModuleRejected(format!(
                    "fill notional exceeds u64 quote range (market {market})"
                ))
            })?;
            // Buyer and seller from the taker's side: the maker
            // sells when the taker buys and vice versa.
            let (buyer, seller) = if f.taker_side == Side::Buy {
                (f.taker_owner, f.maker_owner)
            } else {
                (f.maker_owner, f.taker_owner)
            };

            // ── Base leg: prove delivery BEFORE paying ──
            // A taker sell always covers (its qty was reserved at
            // admission); a maker sell must still hold the fill
            // qty in `base_holds`.
            let maker_covered = f.taker_side == Side::Sell
                || self.base_holds.get(&(f.maker_owner, market)).copied().unwrap_or(0) >= f.qty.0;
            if !maker_covered {
                self.events.push(unbacked_sell_fill_event(market, *f));
                continue;
            }
            let bkey = (buyer, market);
            let Some(buyer_next) =
                self.base_balances.get(&bkey).copied().unwrap_or(0).checked_add(f.qty.0)
            else {
                // Unreachable while Σ custody < u64::MAX (custody is
                // native-backed). Void rather than mint.
                self.events.push(fill_voided_event(market, *f));
                continue;
            };
            if f.taker_side == Side::Buy {
                // `maker_covered` proved the entry exists with
                // enough held.
                *self
                    .base_holds
                    .get_mut(&(f.maker_owner, market))
                    .ok_or(ExecError::Malformed)? -= f.qty.0;
            } else {
                // Admission reserved `qty`; Σ fills ≤ qty by engine
                // contract — `checked_sub` documents it.
                taker_base = taker_base.checked_sub(f.qty.0).ok_or(ExecError::Malformed)?;
            }
            *self.base_balances.entry(bkey).or_insert(0) = buyer_next;
            if f.taker_side == Side::Buy {
                taker_paid = taker_paid.saturating_add(quote_amount);
            }

            // ── Quote leg: seller receives notional minus the
            // protocol fee; the fee accrues to the market's
            // committed vault.
            let fee = u64::try_from(
                u128::from(quote_amount) * u128::from(FEE_BPS) / u128::from(BPS_DENOM),
            )
            .map_err(|_| ExecError::ModuleRejected(format!("fee overflow (market {market})")))?;
            self.ledger.credit(&seller, quote_amount - fee).map_err(|_| {
                ExecError::ModuleRejected(format!("settlement credit failed (market {market})"))
            })?;
            let vault = self.fee_vault.entry(market).or_insert(0);
            match vault.checked_add(fee) {
                Some(v) => *vault = v,
                // Saturation burns the excess (the units were
                // deducted from the seller's payment regardless) —
                // reachable only past u64::MAX cumulative fees.
                None => self.events.push(fee_overflow_event(market, fee)),
            }
        }

        // Release the taker's quote reservation (buys): settled fills
        // cost their actual price (improvement refunded), a
        // surviving GTC remainder keeps `price × resting_qty` held
        // for the cancel path, and dead remainders
        // (IOC/FOK/Killed/Rejected) come back in full.
        if taker.reservation > 0 {
            // `held` is the resting remainder's quote requirement at
            // the limit price — computed in u128 and clamped to
            // u64::MAX, which errs toward holding *more* than the
            // remainder needs (refund shrinks, nothing is created).
            // The clamp needs `price × qty > u64::MAX × PRICE_SCALE`
            // — beyond the u64 money supply for any funded order.
            let held = match outcome {
                OrderOutcome::Resting { resting_qty, .. } => u64::try_from(
                    u128::from(taker.price.0) * u128::from(resting_qty.0) / PRICE_SCALE,
                )
                .unwrap_or(u64::MAX),
                _ => 0,
            };
            // The floor at zero is the same direction: a `paid +
            // held` total above the reservation retains the excess
            // in custody rather than minting a refund.
            let refund = taker.reservation.saturating_sub(taker_paid.saturating_add(held));
            if refund > 0 {
                self.ledger.credit(&taker.owner, refund).map_err(|_| {
                    ExecError::ModuleRejected("reservation refund failed".to_string())
                })?;
            }
        }

        // Release the taker's base reservation (sells): the unfilled
        // remainder either becomes the resting order's hold (GTC
        // remainder) or returns to free custody
        // (IOC/FOK/Killed/STP-consumed). `resting_qty` is the
        // engine's reported remainder; any STP-consumed slice
        // (`taker_base − resting_qty`) books no fill and is
        // released free.
        if taker_base > 0 {
            let resting = match outcome {
                OrderOutcome::Resting { resting_qty, .. } => resting_qty.0,
                _ => 0,
            };
            if resting > 0 {
                *self.base_holds.entry((taker.owner, market)).or_insert(0) += resting;
            }
            let release = taker_base.saturating_sub(resting);
            if release > 0 {
                *self.base_balances.entry((taker.owner, market)).or_insert(0) += release;
            }
        }
        Ok(())
    }
}

/// Apply validated fill legs to the registered-order map: consume
/// `remaining`, release buy-side escrow, pay price-improvement
/// rebates, deliver base to buyers, accrue fees, and refund the
/// residue of fully consumed orders.
///
/// Phases (all iteration is over sorted `BTreeMap`s — deterministic
/// event order):
///
/// 1. **Accumulate** each surviving leg into per-order deltas
///    (quantity consumed, escrow released, rebate portion tracked
///    separately), per-buyer rebate totals, per-(buyer, market)
///    base deliveries, and per-market fee accruals.
/// 2. **Rebate drain**: credit each buyer's rebate. A failed credit
///    withholds that buyer's rebate — the payment still settled, but
///    the rebate stays in the order's escrow (refunded with the
///    residue) rather than vanishing.
/// 3. **Base delivery**: each surviving leg's `qty` moves into the
///    buyer's free custody — the delivery half of the swap. The seller's
///    side was escrowed at registration (`reserved`), so delivery
///    cannot fail for want of base.
/// 4. **Fee accrual**: the per-market `FEE_BPS` total lands in the
///    committed `fee_vault`.
/// 5. **Consumption**: `remaining` drops by the consumed quantity;
///    `reserved` drops by the released slice (buys: released minus
///    withheld rebate; sells: qty-for-qty with consumption). A
///    fully consumed order is removed and its residue — floor-
///    division dust plus any withheld rebate — refunded to the
///    asset's home: ledger quote for buys, free base custody for
///    sells.
pub(crate) fn consume_and_release(
    plans: &[LegPlan],
    failed_pairs: &std::collections::BTreeSet<(Address, Address)>,
    registered: &mut BTreeMap<OrderKey, RegisteredOrder>,
    base_balances: &mut BTreeMap<(Address, u8), u64>,
    fee_vault: &mut BTreeMap<u8, u64>,
    ledger: &Arc<dyn framework::Balances + Send + Sync>,
    events: &mut Vec<Event>,
) {
    // ── Accumulate deltas ───────────────────────────────────────
    // Per order: quantity consumed, escrow released, and the
    // rebate portion of the release (tracked separately so a
    // failed rebate credit can leave it escrowed). Per buyer:
    // total rebate to release and base to receive. Per market:
    // total fee to accrue.
    let mut deltas: BTreeMap<OrderKey, OrderDelta> = BTreeMap::new();
    let mut rebates: BTreeMap<Address, u64> = BTreeMap::new();
    let mut deliveries: BTreeMap<(Address, u8), u64> = BTreeMap::new();
    let mut fees: BTreeMap<u8, u64> = BTreeMap::new();
    for plan in plans {
        if failed_pairs.contains(&(plan.buyer, plan.seller)) {
            continue;
        }
        let buy = deltas.entry(plan.buy).or_default();
        buy.consumed += plan.qty;
        buy.released += plan.release;
        buy.rebate += plan.release - plan.pays;
        deltas.entry(plan.sell).or_default().consumed += plan.qty;
        let rebate = plan.release - plan.pays;
        if rebate > 0 {
            *rebates.entry(plan.buyer).or_default() += rebate;
        }
        *deliveries.entry((plan.buyer, plan.market)).or_default() += plan.qty;
        *fees.entry(plan.market).or_default() += plan.fee;
    }

    // ── Rebate drain ────────────────────────────────────────────
    // Sorted address order. A rebate credit that fails is withheld.
    let mut failed_rebates: std::collections::BTreeSet<Address> = std::collections::BTreeSet::new();
    for (buyer, amount) in &rebates {
        if !credit_or_stranded(ledger, *buyer, *amount, events) {
            failed_rebates.insert(*buyer);
            continue;
        }
        events.push(Event {
            module: "exchange",
            kind: "reservation_released",
            data: {
                let mut d = Vec::with_capacity(20 + 8);
                d.extend_from_slice(&buyer.0);
                d.extend_from_slice(&amount.to_le_bytes());
                d
            },
        });
    }

    deliver_base(&deliveries, base_balances, events);
    accrue_fees(&fees, fee_vault, events);

    // ── Consumption + residue refunds ───────────────────────────
    let mut completed: Vec<(OrderKey, Reserved, u16)> = Vec::new();
    for (key, delta) in &deltas {
        let Some(order) = registered.get_mut(key) else { continue };
        order.remaining = order.remaining.saturating_sub(delta.consumed);
        match &mut order.reserved {
            // Buys: release the escrow slice, minus any withheld
            // rebate that stays escrowed for the residue refund.
            Reserved::Quote(escrow) => {
                let withheld = if failed_rebates.contains(&key.owner) { delta.rebate } else { 0 };
                *escrow = escrow.saturating_sub(delta.released.saturating_sub(withheld));
            }
            // Sells: the escrow IS the remaining base custody — it
            // shrinks qty-for-qty with consumption.
            Reserved::Base(escrow) => {
                *escrow = escrow.saturating_sub(delta.consumed);
            }
        }
        if order.remaining == 0 {
            completed.push((*key, order.reserved, order.market));
        }
    }
    for (key, reserved, market) in completed {
        registered.remove(&key);
        let residue = reserved.get();
        if residue == 0 {
            continue;
        }
        match reserved {
            // The order is dead; a refund failure strands its
            // residue. Impossible while supply stays below
            // `u64::MAX` — the event keeps it visible.
            Reserved::Quote(_) => {
                credit_or_stranded(ledger, key.owner, residue, events);
            }
            // Sell residue is base escrow — it returns to the
            // owner's free custody, not the ledger. `u8` conversion
            // is safe (registration bounded markets to 256 slots);
            // the add-back cannot overflow (the units came from
            // this same custody pool).
            Reserved::Base(_) => {
                let Ok(m) = u8::try_from(market) else {
                    // Unreachable: registration bounds markets to
                    // the 256-slot engine space. Stranding the
                    // residue beats misrouting it to a wrong
                    // market — and the order is already removed.
                    continue;
                };
                *base_balances.entry((key.owner, m)).or_insert(0) += residue;
            }
        }
        events.push(Event {
            module: "exchange",
            kind: "escrow_refunded",
            data: {
                let mut d = Vec::with_capacity(20 + 8 + 8);
                d.extend_from_slice(&key.owner.0);
                d.extend_from_slice(&key.client_id.to_le_bytes());
                d.extend_from_slice(&residue.to_le_bytes());
                d
            },
        });
    }
}

/// A validated batch-settle leg, planned but not yet applied.
///
/// Constructed only after `settle_leg` has resolved both orders and
/// checked market, sides, crossing, config, and the batch-wide
/// remaining-quantity bound.
pub(crate) struct LegPlan {
    /// The buy order being consumed (`buy.owner` is the buyer).
    pub(crate) buy: OrderKey,
    /// The sell order being consumed (`sell.owner` is the seller).
    pub(crate) sell: OrderKey,
    /// Buyer address (== `buy.owner`) — kept for the pair key and
    /// rebate drain without a second map lookup.
    pub(crate) buyer: Address,
    /// Seller address (== `sell.owner`).
    pub(crate) seller: Address,
    /// The market the fill settles on — keys the buyer's base
    /// custody credit and the fee vault. `u8`-bounded: validation
    /// rejects any market outside the 256-slot engine space.
    pub(crate) market: u8,
    /// Filled quantity (scale-6).
    pub(crate) qty: u64,
    /// The seller's gross payment: `floor(price × qty / PRICE_SCALE)`.
    pub(crate) pays: u64,
    /// The protocol fee carved out of `pays`:
    /// `floor(pays × FEE_BPS / BPS_DENOM)` — the pair drain credits
    /// `pays − fee`, the vault accrues `fee`.
    pub(crate) fee: u64,
    /// The escrow slice this leg releases:
    /// `floor(buy.limit × qty / PRICE_SCALE)`. Always `>= pays`
    /// (`price <= buy.limit` is a leg-validity rule); the difference
    /// is the buyer's price-improvement rebate.
    pub(crate) release: u64,
}

/// Per-order accumulated effects of the legs that survived the
/// seller-credit drain.
#[derive(Default)]
pub(crate) struct OrderDelta {
    /// Total quantity consumed (scale-6).
    pub(crate) consumed: u64,
    /// Total escrow released by those legs (buys only).
    pub(crate) released: u64,
    /// The rebate portion of `released` — tracked separately so a
    /// failed rebate credit leaves exactly that much still escrowed.
    pub(crate) rebate: u64,
}

/// Hash a `(buyer, seller)` pair for the batch-settle aggregation
/// table. FxHash-style rotate-multiply over the key read as six
/// words (each 20-byte address contributes two `u64`s + one `u32`);
/// the multiply constant is the fx-hash K — chosen for avalanche on
/// power-of-two table sizes, not for security (the table is internal
/// and collision-handled by probing). Deterministic across platforms
/// — required anywhere consensus-adjacent — and ~5ns/pair versus the
/// ~150-250ns a `BTreeMap` insert costs at large batch sizes.
pub(crate) fn pair_hash(buyer: &[u8; 20], seller: &[u8; 20]) -> u64 {
    const SEED: u64 = 0x9e37_79b9_7f4a_7c15;
    const MUL: u64 = 0x517c_c1b7_2722_0a95;
    let mut h = SEED;
    for x in [
        w64(buyer, 0),
        w64(buyer, 8),
        w32(buyer, 16),
        w64(seller, 0),
        w64(seller, 8),
        w32(seller, 16),
    ] {
        h = (h.rotate_left(5) ^ x).wrapping_mul(MUL);
    }
    h
}

/// Parse an `OrderKey` (`[owner:20][client_id:8]` = 28 bytes) out of
/// a batch-settle leg at byte offset `off`.
pub(crate) fn leg_key(body: &[u8], off: usize) -> Result<OrderKey, ExecError> {
    Ok(OrderKey {
        owner: Address(
            body.get(off..off + 20)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ),
        client_id: u64::from_le_bytes(
            body.get(off + 20..off + 28)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ),
    })
}

/// Parse and validate one batch-settle leg at byte offset `off`,
/// resolving both order keys against the registered-order map.
///
/// Returns `Ok(Some(LegPlan))` for a valid leg, `Ok(None)` for a leg
/// that fails validation (caller emits a `fill_rejected` event —
/// invalid legs cannot move funds), and `Err(Malformed)` on a
/// truncated entry (unreachable in practice — the caller
/// bounds-checks the batch length up front).
///
/// A leg is valid iff:
/// - both order keys name live registered orders — a buy and a sell
///   respectively, both on the leg's market, with distinct owners;
/// - the price crosses: `sell.limit <= price <= buy.limit` (each
///   party only ever fills inside the price they signed for);
/// - market config holds: positive lot-aligned qty, on-tick price
///   inside the configured band;
/// - neither order's `remaining` is exceeded by the leg PLUS the
///   quantity earlier legs in this batch already consumed — the
///   `consumed` scratch is what makes two legs in one batch unable
///   to spend the same authorized quantity, and what makes a
///   replayed batch fail outright.
///
/// `pays`/`release` are recomputed on-chain with checked
/// fixed-point math; an over-u64 notional rejects the leg rather
/// than silently capping the transfer.
pub(crate) fn settle_leg(
    body: &[u8],
    off: usize,
    configs: &[Option<MarketConfig>],
    registered: &BTreeMap<OrderKey, RegisteredOrder>,
    consumed: &mut BTreeMap<OrderKey, u64>,
) -> Result<Option<LegPlan>, ExecError> {
    let market = u16::from_le_bytes(
        body.get(off..off + 2)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );
    let price = u64::from_le_bytes(
        body.get(off + 2..off + 10)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );
    let qty = u64::from_le_bytes(
        body.get(off + 10..off + 18)
            .ok_or(ExecError::Malformed)?
            .try_into()
            .map_err(|_| ExecError::Malformed)?,
    );
    let buy = leg_key(body, off + 18)?;
    let sell = leg_key(body, off + 46)?;

    let (Some(buy_order), Some(sell_order)) = (registered.get(&buy), registered.get(&sell)) else {
        return Ok(None); // A leg naming no live order is unauthorized.
    };

    // Role + market binding: the buy key must be a buy order, the
    // sell key a sell order, both on this leg's market — and never
    // the same account on both sides.
    if buy_order.side() != Side::Buy
        || sell_order.side() != Side::Sell
        || buy_order.market != market
        || sell_order.market != market
        || buy.owner == sell.owner
    {
        return Ok(None);
    }

    // Crossing: the fill price must lie inside both limits — the
    // buyer never pays above their limit, the seller never accepts
    // below theirs. `sell.limit > buy.limit` (no crossing) rejects.
    if price < sell_order.limit_price || price > buy_order.limit_price {
        return Ok(None);
    }

    // Market config: listed market, positive lot-aligned qty,
    // on-tick price inside the band.
    let cfg_ok = configs.get(usize::from(market)).copied().flatten().is_some_and(|c| {
        qty > 0
            && qty % c.lot_size == 0
            && price >= c.min_price
            && price <= c.max_price
            && price % c.tick_size == 0
    });
    if !cfg_ok {
        return Ok(None);
    }

    // Batch-wide remaining bound: this leg plus everything earlier
    // legs already took from each order must fit its `remaining`.
    // `consumed` is updated only for valid legs, so a rejected leg
    // consumes nothing.
    let buy_used = consumed.get(&buy).copied().unwrap_or(0);
    let sell_used = consumed.get(&sell).copied().unwrap_or(0);
    let Some(buy_total) = buy_used.checked_add(qty) else { return Ok(None) };
    let Some(sell_total) = sell_used.checked_add(qty) else { return Ok(None) };
    if buy_total > buy_order.remaining || sell_total > sell_order.remaining {
        return Ok(None);
    }
    // Delivery-versus-payment: the sell order must still hold enough
    // escrowed base — a `Reserved::Base` is its base custody, which
    // registration filled qty-for-qty with `remaining`. This is what
    // stops a leg from paying a seller who cannot deliver — including
    // a pre-custody registered sell (zero escrow), which is now
    // unfillable but still cancelable. The `side()` check above
    // already proved the `Base` denomination.
    if sell_total > sell_order.reserved.get() {
        return Ok(None);
    }

    // Amounts: pays at the fill price, release at the buy limit —
    // checked u128 math; over-u64 notionals reject the leg. The fee
    // is `pays`-bounded (`FEE_BPS < BPS_DENOM`), so `pays − fee` can
    // never underflow.
    let (Some(pays), Some(release)) = (
        u64::try_from(u128::from(price) * u128::from(qty) / PRICE_SCALE).ok(),
        u64::try_from(u128::from(buy_order.limit_price) * u128::from(qty) / PRICE_SCALE).ok(),
    ) else {
        return Ok(None);
    };
    let Some(fee) =
        u64::try_from(u128::from(pays) * u128::from(FEE_BPS) / u128::from(BPS_DENOM)).ok()
    else {
        return Ok(None); // Unreachable: `pays`-bounded.
    };
    let Ok(market_u8) = u8::try_from(market) else {
        return Ok(None); // Post-validation unreachable — engines are u8-indexed.
    };

    consumed.insert(buy, buy_total);
    consumed.insert(sell, sell_total);
    Ok(Some(LegPlan {
        buy,
        sell,
        buyer: buy.owner,
        seller: sell.owner,
        market: market_u8,
        qty,
        pays,
        fee,
        release,
    }))
}

/// Credit `owner` `amount` of ledger quote, emitting a
/// `reservation_release_failed` event (and returning `false`) if the
/// credit fails — the shared rebate/residue drain pattern. A failed
/// credit strands the funds in place: the caller decides what the
/// residue does next. Impossible while total supply stays below
/// `u64::MAX` — the event keeps it visible regardless.
pub(crate) fn credit_or_stranded(
    ledger: &Arc<dyn framework::Balances + Send + Sync>,
    owner: Address,
    amount: u64,
    events: &mut Vec<Event>,
) -> bool {
    if ledger.credit(&owner, amount).is_err() {
        events.push(Event {
            module: "exchange",
            kind: "reservation_release_failed",
            data: {
                let mut d = Vec::with_capacity(20 + 8);
                d.extend_from_slice(&owner.0);
                d.extend_from_slice(&amount.to_le_bytes());
                d
            },
        });
        return false;
    }
    true
}

/// Deliver accumulated base quantities into buyer custody — the
/// delivery half of the trade for batch settlement. Sorted (buyer, market)
/// order. The credit cannot fail against a shortfall — the seller
/// escrowed the qty at registration — only on a buyer-custody
/// overflow, which is unreachable while Σ custody < `u64::MAX`; the
/// event keeps it visible regardless.
pub(crate) fn deliver_base(
    deliveries: &BTreeMap<(Address, u8), u64>,
    base_balances: &mut BTreeMap<(Address, u8), u64>,
    events: &mut Vec<Event>,
) {
    for ((buyer, market), qty) in deliveries {
        let entry = base_balances.entry((*buyer, *market)).or_insert(0);
        if let Some(v) = entry.checked_add(*qty) {
            *entry = v;
            events.push(Event {
                module: "exchange",
                kind: "base_delivered",
                data: {
                    let mut d = Vec::with_capacity(20 + 1 + 8);
                    d.extend_from_slice(&buyer.0);
                    d.push(*market);
                    d.extend_from_slice(&qty.to_le_bytes());
                    d
                },
            });
        } else {
            events.push(Event {
                module: "exchange",
                kind: "base_delivery_overflow",
                data: {
                    let mut d = Vec::with_capacity(20 + 1 + 8);
                    d.extend_from_slice(&buyer.0);
                    d.push(*market);
                    d.extend_from_slice(&qty.to_le_bytes());
                    d
                },
            });
        }
    }
}

/// Accrue per-market fees into the committed `fee_vault`. Sorted
/// market order. Vault saturation burns the excess (the fee was
/// already deducted from the seller's payment) — reachable only past
/// `u64::MAX` cumulative quote volume.
pub(crate) fn accrue_fees(
    fees: &BTreeMap<u8, u64>,
    fee_vault: &mut BTreeMap<u8, u64>,
    events: &mut Vec<Event>,
) {
    for (market, fee) in fees {
        let vault = fee_vault.entry(*market).or_insert(0);
        if let Some(v) = vault.checked_add(*fee) {
            *vault = v;
        } else {
            events.push(fee_overflow_event(*market, *fee));
        }
    }
}

/// Build a `fill_rejected` event for a malformed batch-settle leg.
/// `idx` is the leg's position in the batch (u32 LE) and `reason` is
/// a short static tag for diagnostics.
pub(crate) fn rejected_leg_event(idx: usize, reason: &'static str) -> Event {
    let mut data = Vec::with_capacity(4 + reason.len());
    #[allow(clippy::cast_possible_truncation)]
    data.extend_from_slice(&(idx as u32).to_le_bytes());
    data.extend_from_slice(reason.as_bytes());
    Event { module: "exchange", kind: "fill_rejected", data }
}

/// Build an `unbacked_sell_fill` event: a book-path fill whose maker
/// sell held less base than the fill quantity — only reachable for
/// orders imported from before custody existed. The fill settles
/// void: the book consumed the order but no quote moves and no base
/// is minted.
pub(crate) fn unbacked_sell_fill_event(market: u8, fill: FillEvent) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 8 + 20);
    data.push(market);
    data.extend_from_slice(&fill.maker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.qty.0.to_le_bytes());
    data.extend_from_slice(&fill.maker_owner.0);
    Event { module: "exchange", kind: "unbacked_sell_fill", data }
}

/// Build a `fill_voided` event: a fill skipped because the buyer's
/// base custody credit would overflow — unreachable while total
/// custody stays under `u64::MAX`, emitted rather than silently
/// clamped.
pub(crate) fn fill_voided_event(market: u8, fill: FillEvent) -> Event {
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(market);
    data.extend_from_slice(&fill.maker_order_id.0.to_le_bytes());
    data.extend_from_slice(&fill.qty.0.to_le_bytes());
    Event { module: "exchange", kind: "fill_voided", data }
}

/// Build a `fee_vault_overflow` event: a fill's fee could not accrue
/// because the market's vault is saturated — reachable only past
/// `u64::MAX` cumulative quote volume. The excess fee is burned (it
/// was already deducted from the seller's payment).
pub(crate) fn fee_overflow_event(market: u8, fee: u64) -> Event {
    let mut data = Vec::with_capacity(1 + 8);
    data.push(market);
    data.extend_from_slice(&fee.to_le_bytes());
    Event { module: "exchange", kind: "fee_vault_overflow", data }
}
