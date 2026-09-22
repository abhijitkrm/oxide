//! Snapshot codec for the perps module.
//!
//! Split from `lib.rs` around the persistence invariant:
//! [`PerpsModule::write_committed`] owns the canonical write
//! schema and the `decode_*` family owns the read schema — they
//! live in one file so the two can never drift. Decoders enforce
//! the internal invariants live code maintains (engine mirror,
//! reservation binding): a blob's claimed root only proves the
//! bytes hash, so a crafted blob with a matching root could
//! otherwise install state no honest execution produces.

use super::{
    AccountState, Address, BTreeMap, DenseBook, MAX_FUNDING_RATE_BPS, MatchingEngine,
    OpenOrderResv, PerpsMarketConfig, PerpsModule, Position, Side, StagedPerps,
    encode_perps_config, market_config_key, subtree_root,
};

impl PerpsModule {
    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    pub(crate) fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        let inner = framework::lock_state(&self.inner);
        // Live books: market config + order-id sequence + every
        // resting order (canonical order inside the engine encoding).
        let mut entries = Vec::new();
        let mut book_bytes = Vec::new();
        w.put_count(inner.markets.len());
        for engine in &inner.markets {
            match engine {
                Some(e) => {
                    w.put_u8(1);
                    book_bytes.clear();
                    e.write_canonical_state(&mut book_bytes, &mut entries);
                    w.put_bytes(&book_bytes);
                }
                None => {
                    w.put_u8(0);
                }
            }
        }
        // Perps market configs (leverage / mmr — margin math).
        w.put_count(inner.configs.len());
        for (market, cfg) in &inner.configs {
            w.put_u8(*market);
            w.put_u16(cfg.max_leverage);
            w.put_u16(cfg.mmr_base_bps);
        }
        // Mark prices drive funding, liquidations, and margin checks.
        w.put_count(inner.marks.len());
        for (market, mark) in &inner.marks {
            w.put_u8(*market);
            w.put_u64(*mark);
        }
        // Accounts: cross margin, per-market positions, and the C7
        // open-order reservations (potential exposure).
        w.put_count(inner.accounts.len());
        for (addr, acct) in &inner.accounts {
            w.put_addr(addr);
            w.put_u64(acct.cross_margin);
            w.put_count(acct.positions.len());
            for (market, pos) in &acct.positions {
                w.put_u8(*market);
                w.put_i64(pos.size);
                w.put_u64(pos.entry_price);
                w.put_u64(pos.isolated_margin);
            }
            w.put_count(acct.open_orders.len());
            for ((market, oid), resv) in &acct.open_orders {
                w.put_u8(*market);
                w.put_u64(*oid);
                w.put_u64(resv.qty);
                w.put_u64(resv.price);
                w.put_u8(resv.side as u8);
                w.put_bool(resv.reduce_only);
            }
        }
        w.put_u64(inner.insurance_fund);
        // Intra-block oracle-update counter: deterministic (same
        // block → same count) and cheap, so it is committed too.
        w.put_count(inner.oracle_updates_this_block.len());
        for (market, n) in &inner.oracle_updates_this_block {
            w.put_u8(*market);
            w.put_u8(*n);
        }
        drop(inner);
        // C9: pending governance endorsements decide whether an
        // override applies — future-affecting state, committed like
        // everything else.
        self.endorsements.write_canonical(w);
        // ── Trailing section (v2) ── appended after endorsements
        // so pre-upgrade blobs decode with the defaults below:
        // mark ages + the liquidation-sweep cursor. Both are
        // consensus-visible state — staleness decisions and the
        // sweep window must agree across nodes.
        let inner = framework::lock_state(&self.inner);
        w.put_count(inner.mark_updated_at.len());
        for (market, updated) in &inner.mark_updated_at {
            w.put_u8(*market);
            w.put_u64(*updated);
        }
        match inner.liquidation_cursor {
            Some(addr) => {
                w.put_u8(1);
                w.put_addr(&addr);
            }
            None => {
                w.put_u8(0);
            }
        }
        // ── Trailing section (v3) ── the unpaid-loss liability is
        // consensus-visible state: future fund inflows split between
        // retiring it and growing the fund, so two nodes disagreeing
        // on it would diverge on the next funding round.
        w.put_u64(inner.unfunded_bad_debt);
        // ── Trailing section (v4) ── the pending funding set is
        // consensus-visible: it decides what applies at the next
        // period boundary, so disagreement there diverges the
        // moment the boundary lands.
        w.put_count(inner.pending_funding.len());
        for (market, rate) in &inner.pending_funding {
            w.put_u8(*market);
            w.put_i64(*rate);
        }
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema.
    ///
    /// `slots` is the destination's fixed market-slot count: a blob
    /// claiming a different array length cannot represent this
    /// module's state.
    ///
    /// Beyond structural validity this enforces the *internal*
    /// invariants every live code path maintains (store↔config
    /// binding, marks ⟺ listed markets, reservations ⟺ resting
    /// orders). Those matter because the root check alone only proves
    /// the blob hashes to the claimed root — a crafted blob with a
    /// matching claimed root could otherwise install state no honest
    /// execution could produce, corrupting margin accounting on the
    /// next fill.
    pub(crate) fn decode_committed(
        r: &mut framework::CanonicalReader<'_>,
        store: &BTreeMap<Vec<u8>, Vec<u8>>,
        slots: usize,
    ) -> Option<StagedPerps> {
        let markets = Self::decode_engines(r, slots)?;
        let configs = Self::decode_configs(r, &markets, store)?;
        let marks = Self::decode_marks(r, &configs)?;
        let accounts = Self::decode_accounts(r, &configs)?;
        Self::check_reservation_binding(&markets, &accounts)?;
        let insurance_fund = r.get_u64()?;
        // Intra-block oracle-update counter — a count for an
        // unlisted market is dead state no live path produces.
        let n = r.get_count()?;
        let mut oracle_updates_this_block = BTreeMap::new();
        for _ in 0..n {
            let market = r.get_u8()?;
            let count = r.get_u8()?;
            if !configs.contains_key(&market) {
                return None;
            }
            if oracle_updates_this_block.insert(market, count).is_some() {
                return None;
            }
        }
        let endorsements = framework::Endorsements::read_canonical(r)?;
        // ── Trailing section (v2), tolerant of pre-upgrade blobs ──
        // `remaining() == 0` means the blob predates mark ages and
        // the sweep cursor: marks decode at age 0 — stale at real
        // heights until refreshed — and a `None` cursor sweeps from
        // the first account.
        let mut mark_updated_at = BTreeMap::new();
        let mut liquidation_cursor = None;
        let mut unfunded_bad_debt = 0;
        let mut pending_funding = BTreeMap::new();
        if r.remaining() != 0 {
            let n = r.get_count()?;
            for _ in 0..n {
                let market = r.get_u8()?;
                let updated = r.get_u64()?;
                if !configs.contains_key(&market) {
                    return None; // mark age for an unlisted market is dead state
                }
                if mark_updated_at.insert(market, updated).is_some() {
                    return None;
                }
            }
            liquidation_cursor = match r.get_u8()? {
                0 => None,
                1 => Some(r.get_addr()?),
                _ => return None,
            };
            // Trailing v3: pre-v3 blobs end at the cursor. `0` is
            // the only honest default — the pre-upgrade code forgot
            // residual losses entirely, so there is no non-zero
            // liability to reconstruct.
            if r.remaining() != 0 {
                unfunded_bad_debt = r.get_u64()?;
            }
            // Trailing v4: pre-v4 blobs end at the debt. Empty is
            // the only honest default — the pre-upgrade path applied
            // funding at endorsement time, so nothing could be
            // queued. A pending rate outside the bound is
            // non-canonical: the record-time check makes such state
            // unproducible.
            if r.remaining() != 0 {
                let n = r.get_count()?;
                for _ in 0..n {
                    let market = r.get_u8()?;
                    let rate = r.get_i64()?;
                    if !configs.contains_key(&market) {
                        return None; // pending funding for an unlisted market is dead state
                    }
                    if rate.unsigned_abs() > u64::try_from(MAX_FUNDING_RATE_BPS).unwrap_or(0) {
                        return None;
                    }
                    if pending_funding.insert(market, rate).is_some() {
                        return None;
                    }
                }
            }
        }
        // A mark with no recorded age — pre-upgrade blobs — is
        // seeded at height 0: stale at any real chain height until
        // a live update lands. Fail closed on unknown age (the
        // safe direction; the opposite would forgive a dead feed),
        // and recovery is cheap: a healthy oracle clears it in one
        // block.
        for m in marks.keys() {
            mark_updated_at.entry(*m).or_insert(0);
        }
        Some(StagedPerps {
            markets,
            configs,
            marks,
            accounts,
            insurance_fund,
            oracle_updates_this_block,
            endorsements,
            mark_updated_at,
            liquidation_cursor,
            unfunded_bad_debt,
            pending_funding,
        })
    }

    /// Decode the fixed-size market array — one canonical engine blob
    /// per listed slot.
    pub(crate) fn decode_engines(
        r: &mut framework::CanonicalReader<'_>,
        slots: usize,
    ) -> Option<Vec<Option<MatchingEngine>>> {
        let n = r.get_count()?;
        if n != slots {
            return None;
        }
        let mut markets = Vec::with_capacity(n);
        for _ in 0..n {
            match r.get_u8()? {
                0 => markets.push(None),
                1 => {
                    let bytes = r.get_bytes()?;
                    markets.push(Some(
                        MatchingEngine::from_canonical_state(bytes, |c| DenseBook::new(*c)).ok()?,
                    ));
                }
                _ => return None,
            }
        }
        Some(markets)
    }

    /// Decode the perps market configs. `base` is recovered from the
    /// engine's own canonical config so the two encodings cannot
    /// disagree, and the KV store must carry the byte-identical
    /// `m/{id}` entry — without that binding a crafted blob could
    /// pair engines with mismatched store entries and still hash to
    /// a self-consistent root.
    pub(crate) fn decode_configs(
        r: &mut framework::CanonicalReader<'_>,
        markets: &[Option<MatchingEngine>],
        store: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Option<BTreeMap<u8, PerpsMarketConfig>> {
        let n = r.get_count()?;
        let mut configs = BTreeMap::new();
        for _ in 0..n {
            let market = r.get_u8()?;
            let max_leverage = r.get_u16()?;
            let mmr_base_bps = r.get_u16()?;
            let engine = markets.get(usize::from(market)).and_then(Option::as_ref)?;
            let cfg = PerpsMarketConfig { base: *engine.config(), max_leverage, mmr_base_bps };
            match store.get(&market_config_key(market)) {
                Some(v) if *v == encode_perps_config(&cfg) => {}
                _ => return None,
            }
            if configs.insert(market, cfg).is_some() {
                return None; // Duplicate market key — non-canonical.
            }
        }
        Some(configs)
    }

    /// Decode mark prices. `set_mark_price` rejects unknown markets
    /// and `list_market` seeds an initial mark, so the live invariant
    /// is marks ⟺ configs exactly.
    pub(crate) fn decode_marks(
        r: &mut framework::CanonicalReader<'_>,
        configs: &BTreeMap<u8, PerpsMarketConfig>,
    ) -> Option<BTreeMap<u8, u64>> {
        let n = r.get_count()?;
        let mut marks = BTreeMap::new();
        for _ in 0..n {
            let market = r.get_u8()?;
            let mark = r.get_u64()?;
            if !configs.contains_key(&market) {
                return None;
            }
            if marks.insert(market, mark).is_some() {
                return None;
            }
        }
        if marks.len() != configs.len() {
            return None;
        }
        Some(marks)
    }

    /// Decode accounts — cross margin, positions (only on listed
    /// markets: a position can only exist where fills can happen),
    /// and C7 open-order reservations.
    pub(crate) fn decode_accounts(
        r: &mut framework::CanonicalReader<'_>,
        configs: &BTreeMap<u8, PerpsMarketConfig>,
    ) -> Option<BTreeMap<Address, AccountState>> {
        let n = r.get_count()?;
        let mut accounts = BTreeMap::new();
        for _ in 0..n {
            let addr = r.get_addr()?;
            let cross_margin = r.get_u64()?;
            let pn = r.get_count()?;
            let mut positions = BTreeMap::new();
            for _ in 0..pn {
                let market = r.get_u8()?;
                if !configs.contains_key(&market) {
                    return None;
                }
                let size = r.get_i64()?;
                let entry_price = r.get_u64()?;
                let isolated_margin = r.get_u64()?;
                if positions
                    .insert(market, Position { size, entry_price, isolated_margin })
                    .is_some()
                {
                    return None;
                }
            }
            let on = r.get_count()?;
            let mut open_orders = BTreeMap::new();
            for _ in 0..on {
                let market = r.get_u8()?;
                let oid = r.get_u64()?;
                let qty = r.get_u64()?;
                let price = r.get_u64()?;
                let side = match r.get_u8()? {
                    0 => Side::Buy,
                    1 => Side::Sell,
                    _ => return None,
                };
                let reduce_only = r.get_bool()?;
                if open_orders
                    .insert((market, oid), OpenOrderResv { qty, price, side, reduce_only })
                    .is_some()
                {
                    return None;
                }
            }
            if accounts
                .insert(addr, AccountState { cross_margin, positions, open_orders })
                .is_some()
            {
                return None;
            }
        }
        Some(accounts)
    }

    /// Enforce the reservation↔book binding: collect every resting
    /// order and require a bijection with the accounts' reservations
    /// — same owner, side, price, and remaining qty. A crafted blob
    /// that splits the two would leak or double-charge margin on the
    /// next fill/cancel.
    pub(crate) fn check_reservation_binding(
        markets: &[Option<MatchingEngine>],
        accounts: &BTreeMap<Address, AccountState>,
    ) -> Option<()> {
        let mut resting = BTreeMap::new();
        let mut scratch = Vec::new();
        for (i, engine) in markets.iter().enumerate() {
            let Some(e) = engine else { continue };
            e.resting_entries(&mut scratch);
            let market = u8::try_from(i).ok()?;
            for entry in scratch.drain(..) {
                if resting.insert((market, entry.id.0), entry).is_some() {
                    return None; // Duplicate resting id — impossible from a live engine.
                }
            }
        }
        for (addr, acct) in accounts {
            for ((market, oid), resv) in &acct.open_orders {
                let entry = resting.get(&(*market, *oid))?;
                if entry.owner != *addr
                    || entry.qty.0 != resv.qty
                    || entry.price.0 != resv.price
                    || entry.side != resv.side
                {
                    return None;
                }
            }
        }
        for ((market, oid), entry) in &resting {
            // Field equality was proven by the forward pass; the
            // reverse only needs existence.
            accounts.get(&entry.owner).and_then(|a| a.open_orders.get(&(*market, *oid)))?;
        }
        Some(())
    }
}
