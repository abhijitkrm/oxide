//! Snapshot codec for the exchange module.
//!
//! Split from `lib.rs` around the persistence invariant:
//! [`ExchangeModule::write_committed`] owns the canonical write
//! schema and [`ExchangeModule::decode_committed`] the read
//! schema — side by side so they can never drift. Decode enforces
//! the invariants live code maintains; a blob's claimed root only
//! proves the bytes hash.

use super::{
    BTreeMap, CommittedState, DenseBook, ExchangeModule, MatchingEngine, OrderKey, RegisteredOrder,
    subtree_root,
};
use crate::codec::{decode_side, encode_market_config, encode_side, market_config_key};

impl ExchangeModule {
    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    pub(crate) fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        let inner = framework::lock_state(&self.inner);
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
        // Pending list-market endorsements are future-affecting
        // state: the tally decides whether the next endorsement
        // lists a market, so replicas holding different tallies must
        // diverge in the root.
        self.endorsements.write_canonical(w);
        // Registered off-chain-matched orders are committed state:
        // they decide whether the next batch-settle leg is
        // authorized, and their `remaining`/`reserved` move real
        // escrow — two replicas holding different registries would
        // settle differently. Encoded sorted by `(owner, client_id)`
        // (BTreeMap order is the canonical order). Trailing section —
        // decoders written before this field existed reject the
        // extra bytes via the staged reader's end-of-stream check,
        // while this decoder treats an absent section as an empty
        // registry.
        w.put_count(inner.registered.len());
        for (key, order) in &inner.registered {
            w.put_addr(&key.owner);
            w.put_u64(key.client_id);
            w.put_u16(order.market);
            w.put_u8(encode_side(order.side));
            w.put_u64(order.limit_price);
            w.put_u64(order.remaining);
            w.put_u64(order.reserved);
        }
        // Base-asset custody state — committed because it decides
        // every future sell's admissibility and every fill's delivery:
        // two replicas disagreeing on custody would settle different
        // trades. Trailing section; decoders predate it read an empty
        // custody set (see `decode_committed` for what that means for
        // legacy orders).
        w.put_count(inner.base_balances.len());
        for ((owner, market), amount) in &inner.base_balances {
            w.put_addr(owner);
            w.put_u8(*market);
            w.put_u64(*amount);
        }
        w.put_count(inner.base_holds.len());
        for ((owner, market), amount) in &inner.base_holds {
            w.put_addr(owner);
            w.put_u8(*market);
            w.put_u64(*amount);
        }
        w.put_count(inner.fee_vault.len());
        for (market, amount) in &inner.fee_vault {
            w.put_u8(*market);
            w.put_u64(*amount);
        }
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema.
    ///
    /// `slots` is the destination's fixed market-slot count: a blob
    /// claiming a different array length cannot represent this
    /// module's state.
    pub(crate) fn decode_committed(
        r: &mut framework::CanonicalReader<'_>,
        store: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>,
        slots: usize,
    ) -> Option<CommittedState> {
        let n = r.get_count()?;
        if n != slots {
            return None;
        }
        let mut markets = Vec::with_capacity(n);
        for i in 0..n {
            match r.get_u8()? {
                0 => markets.push(None),
                1 => {
                    let bytes = r.get_bytes()?;
                    let engine =
                        MatchingEngine::from_canonical_state(bytes, |c| DenseBook::new(*c)).ok()?;
                    // Store↔engine binding: a listed market must carry
                    // its byte-identical config under `m/{id}`. Without
                    // this check a crafted blob could pair engines with
                    // mismatched store entries and still hash to a
                    // self-consistent root.
                    let key = market_config_key(u8::try_from(i).ok()?);
                    match store.get(&key) {
                        Some(v) if *v == encode_market_config(engine.config()) => {}
                        _ => return None,
                    }
                    markets.push(Some(engine));
                }
                _ => return None,
            }
        }
        // Reverse direction: every `m/{id}` store key must name a
        // listed market — a config without an engine is dead state
        // no live code path produces.
        for key in store.keys() {
            if let [b'm', id] = key.as_slice() {
                match markets.get(usize::from(*id)) {
                    Some(Some(_)) => {}
                    _ => return None,
                }
            }
        }
        // Trailing section: the pending-endorsement tally written by
        // `write_committed`. Decode is strict (duplicates rejected)
        // so a crafted blob cannot smuggle a second opinion about
        // who endorsed what.
        let endorsements = framework::Endorsements::read_canonical(r)?;
        // Final trailing section: the registered-order map. Tolerant
        // tail — a blob written before the section existed decodes as
        // an empty registry, while the staged reader still rejects a
        // truncated or non-canonical one. Duplicate keys are rejected
        // (a `BTreeMap` insert would silently absorb them).
        let mut registered = BTreeMap::new();
        if r.remaining() > 0 {
            let count = r.get_count()?;
            for _ in 0..count {
                let key = OrderKey { owner: r.get_addr()?, client_id: r.get_u64()? };
                let order = RegisteredOrder {
                    market: r.get_u16()?,
                    side: decode_side(r.get_u8()?)?,
                    limit_price: r.get_u64()?,
                    remaining: r.get_u64()?,
                    reserved: r.get_u64()?,
                };
                if registered.insert(key, order).is_some() {
                    return None; // Duplicate key — non-canonical.
                }
            }
        }
        // Final trailing section: base custody (`base_balances`,
        // `base_holds`, `fee_vault`). Tolerant tail — a blob written
        // before custody existed decodes with empty maps. That is
        // fail-closed for legacy orders: a pre-upgrade resting sell
        // carries no hold, so the next fill against it settles void
        // (`unbacked_sell_fill`), and a pre-upgrade registered sell
        // has `reserved == 0`, so `settle_leg` rejects every leg
        // naming it — naked sells can be canceled but never paid.
        let mut base_balances = BTreeMap::new();
        let mut base_holds = BTreeMap::new();
        let mut fee_vault = BTreeMap::new();
        if r.remaining() > 0 {
            let count = r.get_count()?;
            for _ in 0..count {
                let key = (r.get_addr()?, r.get_u8()?);
                if base_balances.insert(key, r.get_u64()?).is_some() {
                    return None; // Duplicate key — non-canonical.
                }
            }
            let count = r.get_count()?;
            for _ in 0..count {
                let key = (r.get_addr()?, r.get_u8()?);
                if base_holds.insert(key, r.get_u64()?).is_some() {
                    return None; // Duplicate key — non-canonical.
                }
            }
            let count = r.get_count()?;
            for _ in 0..count {
                let market = r.get_u8()?;
                if fee_vault.insert(market, r.get_u64()?).is_some() {
                    return None; // Duplicate key — non-canonical.
                }
            }
        }
        Some((markets, endorsements, registered, base_balances, base_holds, fee_vault))
    }
}
