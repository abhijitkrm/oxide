//! `framework::Module` adapter for the perps module.
//!
//! Split from `lib.rs` around the adapter invariant: the
//! consensus-facing lifecycle (`begin_block` / `handle` /
//! `end_block` / `commit` / snapshot hooks) is the only place the
//! chain drives module state — keeping it in one file makes the
//! ordering auditable end-to-end.

use super::{
    Address, Event, ExecError, FUNDING_PERIOD_BLOCKS, Hash, Height, LIQUIDATION_SWEEP_BUDGET,
    Module, PerpsModule, RejectCategory, TAG_APPLY_FUNDING, TAG_CANCEL, TAG_DEPOSIT, TAG_LIQUIDATE,
    TAG_LIST_MARKET, TAG_PLACE, TAG_SET_MARK, TAG_WITHDRAW, TxContext, module_id,
};
use crate::decode;
use crate::{encode_perps_config, market_config_key};

impl Module for PerpsModule {
    fn name(&self) -> &'static str {
        "perps"
    }

    fn id(&self) -> u8 {
        module_id::PERPS
    }

    fn begin_block(&self, height: Height) {
        // M4 fix: reset the per-block oracle update counter at the
        // start of each block. Each market gets a fresh budget of
        // [`MAX_ORACLE_UPDATES_PER_BLOCK`] updates per block.
        let mut inner = framework::lock_state(&self.inner);
        inner.oracle_updates_this_block.clear();
        // The executing height drives mark-staleness decisions
        // (`mark_is_stale`) for every tx this block.
        inner.current_height = height.value();
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.is_empty() {
            return Err(ExecError::Malformed);
        }
        Self::reject_clearing_sender(ctx)?;
        let tag = msg[0];
        let body = &msg[1..];

        let inner = framework::lock_state(&self.inner);

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
                drop(inner);
                self.handle_list_market(ctx, msg, body)
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
                // Reject a nonexistent market before recording an
                // endorsement — pending actions are a bounded set,
                // so junk targets must never occupy a slot. Markets
                // are only ever listed, never removed, so the
                // check cannot go stale mid-endorsement.
                if !inner.configs.contains_key(&market) {
                    return Err(ExecError::rejected(
                        RejectCategory::NotFound,
                        "market does not exist",
                    ));
                }
                drop(inner);
                // C9: committee-quorum emergency override. The
                // normal mark pipeline is the oracle module pushing
                // the aggregated median through `MarkSink`; this tx
                // path exists so the validator set can still force
                // a mark if the oracle feed stalls entirely. Each
                // tx endorses the exact (market, mark) payload —
                // the mark applies only once endorsing power
                // strictly exceeds two-thirds of the committee, so
                // one validator's signature is a vote, never a
                // command. Without a wired committee the path is
                // closed entirely.
                let Some(committee) = self.committee.clone() else {
                    return Err(ExecError::rejected(
                        RejectCategory::Unauthorized,
                        "set_mark: no committee wired",
                    ));
                };
                match self.endorsements.record(msg, &ctx.sender, committee.as_ref())? {
                    framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                        module: "perps",
                        kind: "set_mark_endorse",
                        data: vec![market],
                    }]),
                    framework::EndorsementOutcome::Quorum => {
                        // `set_mark_price` keeps the per-update
                        // deviation cap and per-block rate limit —
                        // a quorum-authorized mark that violates
                        // them is consumed as stale, not forced.
                        match self.set_mark_price(market, mark) {
                            Ok(()) => Ok(vec![Event {
                                module: "perps",
                                kind: "mark_updated",
                                data: vec![market],
                            }]),
                            Err(_) => Ok(vec![Event {
                                module: "perps",
                                kind: "set_mark_stale",
                                data: vec![market],
                            }]),
                        }
                    }
                }
            }
            TAG_APPLY_FUNDING => {
                drop(inner);
                self.handle_apply_funding(ctx, msg, body)
            }
            TAG_LIQUIDATE => {
                // `[account: 20B]` — permissionless trigger: the
                // sender pays the tx fee, which prices the spam
                // vector; the check is bounded by the target's
                // positions + orders.
                let Ok(account) = <[u8; 20]>::try_from(body) else {
                    return Err(ExecError::Malformed);
                };
                drop(inner);
                self.liquidation_check(&primitives::Address(account))
            }
            _ => Err(ExecError::Malformed),
        }
    }

    /// Bounded rotating liquidation sweep: check up to
    /// [`LIQUIDATION_SWEEP_BUDGET`] accounts past the committed
    /// cursor and emit whatever the checks produce. The cursor
    /// makes coverage deterministic across nodes — every validator
    /// sweeps the same window per block — and bounds the sweep's
    /// worst-case cost regardless of account count. Urgent cases
    /// don't wait for the sweep: `TAG_LIQUIDATE` is permissionless
    /// and checks a specific account immediately.
    ///
    /// Stale-mark note: the sweep still runs during an oracle
    /// outage — liquidation is risk-reducing, and the last accepted
    /// mark is the best estimate available. Freezing the sweep on
    /// staleness would strand underwater accounts exactly when they
    /// need closing.
    fn end_block(&self, height: Height) -> Vec<Event> {
        // Funding boundary: on `FUNDING_PERIOD_BLOCKS` multiples,
        // apply every quorum-endorsed pending rate — one application
        // per market per period, at a schedule every participant can
        // predict, before the sweep so this block's liquidations see
        // post-funding margin. A stale mark consumes the rate
        // without applying it (`apply_funding_stale`) — an oracle
        // outage at the boundary skips the period rather than
        // funding on prices nobody trusts.
        let mut events = Vec::new();
        if height.value().is_multiple_of(FUNDING_PERIOD_BLOCKS) {
            let due: Vec<(u8, i64)> = {
                let inner = framework::lock_state(&self.inner);
                inner.pending_funding.iter().map(|(m, r)| (*m, *r)).collect()
            };
            if !due.is_empty() {
                for (market, rate) in due {
                    match self.apply_funding(market, rate) {
                        Ok(applied) => events.extend(applied),
                        Err(_) => events.push(Event {
                            module: "perps",
                            kind: "apply_funding_stale",
                            data: vec![market],
                        }),
                    }
                }
                framework::lock_state(&self.inner).pending_funding.clear();
            }
        }

        // Collect this block's sweep window under a short lock:
        // `liquidation_check` takes the same mutex internally, so
        // the address list must be materialized first.
        let batch: Vec<Address> = {
            let inner = framework::lock_state(&self.inner);
            match inner.liquidation_cursor {
                Some(cursor) => inner
                    .accounts
                    .inner()
                    .range((std::ops::Bound::Excluded(cursor), std::ops::Bound::Unbounded))
                    .take(LIQUIDATION_SWEEP_BUDGET)
                    .map(|(addr, _)| *addr)
                    .collect(),
                None => {
                    inner.accounts.inner().keys().take(LIQUIDATION_SWEEP_BUDGET).copied().collect()
                }
            }
        };

        for account in &batch {
            // The only error the check produces is
            // `ModuleRejected("account not found")` — the account
            // vanished between the scan and the check; skip it
            // and keep sweeping.
            if let Ok(ev) = self.liquidation_check(account) {
                events.extend(ev);
            }
        }
        let mut inner = framework::lock_state(&self.inner);
        // Exit path for the backstop: sell this block's seized
        // inventory (and anything carried over) into the book at
        // mark before advancing the cursor.
        Self::unwind_clearing(&mut inner, &mut events);
        // An empty batch means the cursor passed the last account —
        // wrap so the next block restarts coverage from the
        // beginning.
        inner.liquidation_cursor = batch.last().copied();
        events
    }

    fn state_root(&self) -> Hash {
        // C8: commit EVERY field that can affect future execution —
        // the KV store only mirrors market configs, while positions,
        // margin, marks, the insurance fund, open-order reservations,
        // and the live books decide future fills, liquidations, and
        // funding. Identical roots across validators must prove
        // identical trading state. Section order is fixed and
        // consensus-critical.
        //
        // Excluded: `fills` (per-call scratch), `ledger` /
        // `committee` (assembly wiring, not tx-mutated state).
        //
        // The root preimage is `write_root_preimage` (7.4): the
        // store, `accounts`, and each book's resting set contribute
        // maintained fold roots instead of serializations —
        // `write_committed` remains the snapshot blob's payload.
        let store = framework::lock_state(&self.store);
        let inner = framework::lock_state(&self.inner);
        let view = decode::RootView {
            store_fold: store.root(),
            markets: &inner.markets,
            configs: &inner.configs,
            marks: &inner.marks,
            accounts_fold: inner.accounts.root(),
            insurance_fund: inner.insurance_fund,
            oracle_updates_this_block: &inner.oracle_updates_this_block,
            endorsements: &self.endorsements,
            mark_updated_at: &inner.mark_updated_at,
            liquidation_cursor: inner.liquidation_cursor,
            unfunded_bad_debt: inner.unfunded_bad_debt,
            pending_funding: &inner.pending_funding,
        };
        let mut w = framework::CanonicalState::new();
        decode::write_root_preimage(&view, &mut w);
        w.root()
    }

    /// Export the committed state as one canonical blob —
    /// `canon ‖ store`. The canon section is the `state_root`
    /// preimage, so a peer can verify the claimed root before
    /// installing anything (audit 3.2).
    fn export_state(&self) -> Option<storage::Snapshot> {
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        Some(storage::Snapshot {
            height: 0,
            entries: vec![(
                framework::state_blob_key(),
                framework::encode_state_blob(
                    w.as_bytes(),
                    framework::lock_state(&self.store).inner(),
                ),
            )],
        })
    }

    /// Verify a staged snapshot's claimed root without mutating:
    /// decode the blob, check the store section hashes to the
    /// committed subtree root, fully decode the fields with all
    /// internal invariants enforced, then recompute the incremental
    /// root over the staged state — folded maps fold over the
    /// staged `BTreeMap`s (`fold_map`), folded books re-fold via
    /// `decode_engines`, serialized sections serialize the staged
    /// fields, so the result equals the `state_root` this state
    /// would produce once installed.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let slots = framework::lock_state(&self.inner).markets.len();
        let (_canon, staged, store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        let view = decode::RootView {
            store_fold: framework::CommittedStore::fold_map(&store, crate::perps_store_leaf),
            markets: &staged.markets,
            configs: &staged.configs,
            marks: &staged.marks,
            accounts_fold: framework::CommittedMap::fold_map(
                &staged.accounts,
                crate::accounts_leaf,
            ),
            insurance_fund: staged.insurance_fund,
            oracle_updates_this_block: &staged.oracle_updates_this_block,
            endorsements: &staged.endorsements,
            mark_updated_at: &staged.mark_updated_at,
            liquidation_cursor: staged.liquidation_cursor,
            unfunded_bad_debt: staged.unfunded_bad_debt,
            pending_funding: &staged.pending_funding,
        };
        let mut w = framework::CanonicalState::new();
        decode::write_root_preimage(&view, &mut w);
        Ok(w.root())
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then the fields swap in
    /// atomically (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let slots = framework::lock_state(&self.inner).markets.len();
        let (_canon, staged, store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        *framework::lock_state(&self.store) =
            framework::CommittedStore::from_map(store, crate::perps_store_leaf);
        let mut inner = framework::lock_state(&self.inner);
        inner.markets = staged.markets;
        inner.configs = staged.configs;
        inner.marks = staged.marks;
        inner.accounts = framework::CommittedMap::from_map(staged.accounts, crate::accounts_leaf);
        inner.insurance_fund = staged.insurance_fund;
        inner.oracle_updates_this_block = staged.oracle_updates_this_block;
        inner.mark_updated_at = staged.mark_updated_at;
        inner.liquidation_cursor = staged.liquidation_cursor;
        inner.unfunded_bad_debt = staged.unfunded_bad_debt;
        inner.pending_funding = staged.pending_funding;
        // Block-transient: refreshed by the next `begin_block`.
        inner.current_height = 0;
        // `fills` is per-call scratch — clear it so a buffer left
        // mid-transaction cannot leak across the import boundary.
        inner.fills.clear();
        drop(inner);
        self.endorsements.replace_with(staged.endorsements);
        Ok(())
    }
}

impl framework::MarkSink for PerpsModule {
    /// The oracle's push target. Deliberately routes through the
    /// *checked* setter: the oracle's median+EMA is the primary
    /// defense, and this module's deviation cap + per-block rate
    /// limit stay armed as an independent second layer — a sink that
    /// trusted its producer would turn one oracle bug into an
    /// unbounded price move.
    fn set_mark_price(&self, market: u8, mark: u64) -> Result<(), ExecError> {
        Self::set_mark_price(self, market, mark)
    }
}

/// The `perps.*` parameter keyspace — governed market-risk knobs.
/// Value layout for both keys is `[market:1][u16 LE]` (3 bytes):
/// the market the config belongs to, plus the new value.
///
/// - `perps.max_leverage`: replaces the market's
///   `PerpsMarketConfig.max_leverage` — initial margin is
///   `notional / leverage`, so this is the leverage ceiling
///   governance tunes when volatility regime changes.
/// - `perps.mmr_base_bps`: replaces the flat maintenance-margin
///   rate in basis points (≤ `10_000`).
///
/// The mutated config is re-validated through
/// [`PerpsMarketConfig::validate`] and written to BOTH halves of the
/// config's state: the live `inner.configs` map the margin math
/// reads, and the committed `market_config_key` store record the
/// canonical state root and replay path serialize — the same pair
/// `list_market` maintains, so an apply takes effect immediately
/// and still round-trips snapshot restore. A rejected validation
/// lands the proposal in `ApplyFailed` without touching either.
impl framework::ParameterSink for PerpsModule {
    fn apply_param(&self, key: &[u8], value: &[u8]) -> Result<(), ExecError> {
        enum Field {
            MaxLeverage,
            MmrBaseBps,
        }
        let field = match key {
            b"perps.max_leverage" => Field::MaxLeverage,
            b"perps.mmr_base_bps" => Field::MmrBaseBps,
            _ => {
                return Err(ExecError::rejected(
                    RejectCategory::NotFound,
                    "perps: unknown governed parameter",
                ));
            }
        };
        if value.len() != 3 {
            return Err(ExecError::Malformed);
        }
        let market = value[0];
        let v = u16::from_le_bytes([value[1], value[2]]);
        let mut inner = framework::lock_state(&self.inner);
        let Some(mut cfg) = inner.configs.get(&market).copied() else {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                format!("perps param: market {market} not listed"),
            ));
        };
        match field {
            Field::MaxLeverage => cfg.max_leverage = v,
            Field::MmrBaseBps => cfg.mmr_base_bps = v,
        }
        cfg.validate().map_err(|e| {
            ExecError::rejected(RejectCategory::InvalidInput, format!("perps param: {e}"))
        })?;
        inner.configs.insert(market, cfg);
        drop(inner);
        // Committed half: the store record is what `state_root` and
        // snapshot replay read for configs — mutating only
        // `inner.configs` would leave the canonical state describing
        // the pre-apply value.
        framework::lock_state(&self.store)
            .insert(market_config_key(market), encode_perps_config(&cfg));
        Ok(())
    }
}
