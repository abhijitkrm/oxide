//! The trading lane (`docs/lanes-spec.md` §5): one market shard.
//!
//! A [`ShardLane`] owns a [`trading::MatchingEngine`], a [`Verifier`]
//! and a [`FillCommit`]. For each [`Batch`] it authenticates the items,
//! decodes the accepted ones into engine commands, runs
//! [`MatchingEngine::apply_batch`] and emits a [`LaneBatch`] carrying
//! the input digest and the fill commitment.
//!
//! Shards share nothing, so throughput scales with the shard count up
//! to the machine's cores (measured in `benches/lanes.rs`).

use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::{
    Command, DenseBook, MarketConfig, MatchingEngine, NewOrder, OrderType, Side, StpMode,
    TimeInForce,
};

use crate::commit::FillCommit;
use crate::verify::{BODY_LEN, Batch, Verifier, batch_digest};

/// Price grid unit: `Price(1_000_000)` is one tick (0.01).
pub const TICK: u64 = 1_000_000;
/// Quantity grid unit: `Qty(1_000)` is one lot.
pub const LOT: u64 = 1_000;

/// Encode an order into its wire body.
///
/// Layout: `[side][type][tif][stp][price:8][qty:8][owner:20]`, with
/// side 0=buy 1=sell, type 0=limit, tif 0=GTC 1=IOC, stp 0=none.
#[must_use]
pub fn encode_body(
    side: Side,
    ioc: bool,
    price: Price,
    qty: Qty,
    owner: Address,
) -> [u8; BODY_LEN] {
    let mut b = [0u8; BODY_LEN];
    b[0] = u8::from(side == Side::Sell);
    b[2] = u8::from(ioc);
    b[4..12].copy_from_slice(&price.0.to_le_bytes());
    b[12..20].copy_from_slice(&qty.0.to_le_bytes());
    b[20..40].copy_from_slice(&owner.0);
    b
}

/// Decode a wire body. `None` for any field outside the supported set
/// (the lane drops it, like a failed authentication).
#[must_use]
pub fn decode_body(b: &[u8; BODY_LEN]) -> Option<NewOrder> {
    let side = match b[0] {
        0 => Side::Buy,
        1 => Side::Sell,
        _ => return None,
    };
    if b[1] != 0 || b[3] != 0 {
        return None;
    }
    let tif = match b[2] {
        0 => TimeInForce::Gtc,
        1 => TimeInForce::Ioc,
        _ => return None,
    };
    let mut p = [0u8; 8];
    let mut q = [0u8; 8];
    let mut o = [0u8; 20];
    p.copy_from_slice(&b[4..12]);
    q.copy_from_slice(&b[12..20]);
    o.copy_from_slice(&b[20..40]);
    Some(NewOrder {
        side,
        order_type: OrderType::Limit,
        tif,
        price: Price(u64::from_le_bytes(p)),
        qty: Qty(u64::from_le_bytes(q)),
        owner: Address(o),
        stp: StpMode::None,
    })
}

/// Synthetic order flow for benches and tests: `n` limit orders
/// within `mid ± 3` ticks, random side and size, a quarter IOC, from
/// 256 owners, so a book that stays shallow because most orders cross.
/// Deterministic in `seed`.
#[must_use]
pub fn synth_bodies(n: usize, seed: u64, mid_ticks: u64) -> Vec<[u8; BODY_LEN]> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let side = if x & 1 == 0 { Side::Buy } else { Side::Sell };
            let tick = mid_ticks - 3 + (x >> 8) % 7;
            let qty = ((x >> 20) % 10 + 1) * LOT;
            let ioc = (x >> 40).is_multiple_of(4);
            encode_body(side, ioc, Price(tick * TICK), Qty(qty), Address([(x >> 50) as u8; 20]))
        })
        .collect()
}

/// Maps a market to a shard. Shards are fixed by config and change only
/// at epoch boundaries.
#[derive(Clone, Copy)]
pub struct ByMarket {
    /// Number of shards (at least 1).
    pub shards: u16,
}

impl ByMarket {
    /// Shard owning `market`.
    #[must_use]
    pub fn shard(&self, market: u16) -> u16 {
        market % self.shards.max(1)
    }
}

/// What a lane reports for one processed batch; the global header
/// commits `(lane, seq, input_digest, fill_root)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneBatch {
    /// Lane (shard) id.
    pub lane: u16,
    /// Contiguous per-lane batch sequence, from 0.
    pub seq: u64,
    /// Items presented.
    pub items: u32,
    /// Items that authenticated and decoded.
    pub accepted: u32,
    /// Fills produced.
    pub fills: u64,
    /// Digest over the presented bodies.
    pub input_digest: [u8; 32],
    /// Fill commitment.
    pub fill_root: [u8; 32],
    /// Orders resting after the batch.
    pub resting: u32,
}

/// One trading shard.
pub struct ShardLane<V: Verifier, C: FillCommit> {
    lane: u16,
    engine: MatchingEngine,
    verifier: V,
    commit: C,
    seq: u64,
    ok: Vec<bool>,
    cmds: Vec<Command>,
}

impl<V: Verifier, C: FillCommit> ShardLane<V, C> {
    /// Build a shard for `market` with a price band of `mid ± band_ticks`.
    ///
    /// # Panics
    ///
    /// Panics if the derived market configuration is invalid (a bug in
    /// the caller's parameters, e.g. `band_ticks >= mid_ticks`).
    #[must_use]
    pub fn new(
        lane: u16,
        market: u16,
        mid_ticks: u64,
        band_ticks: u64,
        max_resting: u32,
        verifier: V,
        commit: C,
    ) -> Self {
        let cfg = MarketConfig {
            market_id: market,
            tick_size: Price(TICK),
            lot_size: Qty(LOT),
            min_price: Price((mid_ticks - band_ticks) * TICK),
            max_price: Price((mid_ticks + band_ticks) * TICK),
            max_resting,
        };
        let v = cfg.validated().expect("valid shard market config");
        let engine = MatchingEngine::new(v, DenseBook::new(v).expect("dense book"))
            .expect("matching engine");
        Self { lane, engine, verifier, commit, seq: 0, ok: Vec::new(), cmds: Vec::new() }
    }

    /// Process one batch: authenticate, decode, match, commit.
    pub fn process(&mut self, batch: &Batch<'_>) -> LaneBatch {
        self.verifier.verify(batch, &mut self.ok);
        self.cmds.clear();
        for (it, ok) in batch.items.iter().zip(&self.ok) {
            if *ok && let Some(o) = decode_body(&it.body) {
                self.cmds.push(Command::Place(o));
            }
        }
        self.engine.apply_batch(&self.cmds, &mut self.commit, |_, _| {});
        let (fill_root, fills) = self.commit.finish();
        let out = LaneBatch {
            lane: self.lane,
            seq: self.seq,
            items: batch.items.len() as u32,
            accepted: self.cmds.len() as u32,
            fills,
            input_digest: batch_digest(batch.items),
            fill_root,
            resting: self.engine.resting_count(),
        };
        self.seq += 1;
        out
    }

    /// The verifier (for counters such as audit failures).
    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    /// Mutable verifier access (session setup, bench rewinds).
    pub fn verifier_mut(&mut self) -> &mut V {
        &mut self.verifier
    }
}

#[cfg(test)]
#[allow(clippy::many_single_char_names, clippy::similar_names)]
mod tests {
    use super::*;
    use crate::commit::{Merkle, PerFill, Stream};
    use crate::verify::{Auth, Batched, Item, NoVerify, PerItem, SessionMac, session_tag};
    use crypto::ed25519;

    const MID: u64 = 500_000;

    fn workload(n: usize, seed: u64) -> Vec<[u8; BODY_LEN]> {
        synth_bodies(n, seed, MID)
    }

    fn lane<V: Verifier, C: FillCommit>(v: V, c: C) -> ShardLane<V, C> {
        ShardLane::new(0, 1, MID, 100, 1 << 12, v, c)
    }

    #[test]
    fn body_round_trips() {
        let b = encode_body(Side::Sell, true, Price(5 * TICK), Qty(7 * LOT), Address([9; 20]));
        let o = decode_body(&b).expect("decodes");
        assert_eq!(o.side, Side::Sell);
        assert_eq!(o.tif, TimeInForce::Ioc);
        assert_eq!((o.price, o.qty, o.owner), (Price(5 * TICK), Qty(7 * LOT), Address([9; 20])));
        let mut bad = b;
        bad[0] = 5;
        assert!(decode_body(&bad).is_none());
    }

    /// The verifier seam must not change what the lane does with
    /// authentic input: every authentication mode yields the same
    /// batches (digest, fills, commitment) as the trusted control.
    #[test]
    fn verifier_swap_gives_identical_lane_output() {
        let bodies = workload(2000, 7);
        let (sk, pk) = ed25519::generate_keypair_for_test();
        let sig_items: Vec<Item> = bodies
            .iter()
            .map(|b| Item {
                body: *b,
                auth: Auth::Sig { key: pk, sig: ed25519::sign_message(&sk, b) },
            })
            .collect();
        let key = [3u8; 32];
        let mac_items: Vec<Item> = bodies
            .iter()
            .enumerate()
            .map(|(i, b)| Item {
                body: *b,
                auth: Auth::Mac {
                    session: 0,
                    counter: i as u64 + 1,
                    tag: session_tag(&key, 0, i as u64 + 1, b),
                },
            })
            .collect();
        let none_items: Vec<Item> =
            bodies.iter().map(|b| Item { body: *b, auth: Auth::Certified }).collect();

        let mut ctl = lane(NoVerify, Stream::default());
        let want: Vec<LaneBatch> =
            none_items.chunks(500).map(|c| ctl.process(&Batch { items: c, cert: None })).collect();

        let mut a = lane(PerItem, Stream::default());
        let got_a: Vec<_> =
            sig_items.chunks(500).map(|c| a.process(&Batch { items: c, cert: None })).collect();
        let mut b = lane(Batched::default(), Stream::default());
        let got_b: Vec<_> =
            sig_items.chunks(500).map(|c| b.process(&Batch { items: c, cert: None })).collect();
        let mut mac = SessionMac::default();
        mac.open(key);
        let mut m = lane(mac, Stream::default());
        let got_m: Vec<_> =
            mac_items.chunks(500).map(|c| m.process(&Batch { items: c, cert: None })).collect();
        assert_eq!(got_a, want);
        assert_eq!(got_b, want);
        assert_eq!(got_m, want);
        assert!(want.iter().map(|w| w.fills).sum::<u64>() > 0, "workload must cross");
    }

    #[test]
    fn commit_swap_keeps_fills_and_state_identical() {
        let bodies = workload(3000, 11);
        let items: Vec<Item> =
            bodies.iter().map(|b| Item { body: *b, auth: Auth::Certified }).collect();
        let mut s = lane(NoVerify, Stream::default());
        let mut m = lane(NoVerify, Merkle::default());
        let mut p = lane(NoVerify, PerFill::default());
        for c in items.chunks(300) {
            let bs = Batch { items: c, cert: None };
            let (a, b, d) = (s.process(&bs), m.process(&bs), p.process(&bs));
            assert_eq!((a.fills, a.resting, a.accepted), (b.fills, b.resting, b.accepted));
            assert_eq!((a.fills, a.resting, a.accepted), (d.fills, d.resting, d.accepted));
            assert_eq!(a.input_digest, b.input_digest);
        }
    }

    #[test]
    fn bad_auth_is_dropped_before_the_engine() {
        let bodies = workload(10, 3);
        let (sk, pk) = ed25519::generate_keypair_for_test();
        let (_, other) = ed25519::generate_keypair_for_test();
        let mut items: Vec<Item> = bodies
            .iter()
            .map(|b| Item {
                body: *b,
                auth: Auth::Sig { key: pk, sig: ed25519::sign_message(&sk, b) },
            })
            .collect();
        // Item 4: signature valid, but for a different key.
        items[4].auth = Auth::Sig { key: other, sig: ed25519::sign_message(&sk, &items[4].body) };
        for v in [Box::new(PerItem) as Box<dyn Verifier>, Box::new(Batched::default())] {
            let mut v = v;
            let mut ok = Vec::new();
            v.verify(&Batch { items: &items, cert: None }, &mut ok);
            let want: Vec<bool> = (0..10).map(|i| i != 4).collect();
            assert_eq!(ok, want, "{}", v.name());
        }
    }

    fn certified_batch(
        gw_sk: &ed25519::Ed25519SecretKey,
        gw_pk: ed25519::Ed25519PublicKey,
        items: &[Item],
    ) -> crate::verify::BatchCert {
        let digest = crate::verify::batch_digest(items);
        crate::verify::BatchCert {
            gateway: gw_pk,
            digest,
            sig: ed25519::sign_message(gw_sk, &digest),
        }
    }

    #[test]
    fn certified_accepts_good_and_fails_closed_on_every_defect() {
        use crate::verify::Certified;
        let bodies = workload(64, 5);
        let (gw_sk, gw_pk) = ed25519::generate_keypair_for_test();
        let (sk, pk) = ed25519::generate_keypair_for_test();
        let good: Vec<Item> = bodies
            .iter()
            .map(|b| Item {
                body: *b,
                auth: Auth::Sig { key: pk, sig: ed25519::sign_message(&sk, b) },
            })
            .collect();
        let cert = certified_batch(&gw_sk, gw_pk, &good);
        let mut ok = Vec::new();

        // audit_every = 1 audits every item: a clean batch passes.
        let mut v = Certified::new(vec![gw_pk], 1);
        v.verify(&Batch { items: &good, cert: Some(&cert) }, &mut ok);
        assert!(ok.iter().all(|o| *o));
        assert_eq!(v.audit_failures, 0);

        // Missing cert, untrusted gateway, tampered body, bad cert signature.
        let (_, rogue) = ed25519::generate_keypair_for_test();
        let mut tampered = good.clone();
        tampered[3].body[5] ^= 1;
        let mut bad_sig = cert;
        bad_sig.sig = ed25519::sign_message(&sk, &cert.digest);
        for (name, items, c) in [
            ("no cert", &good[..], None),
            ("untrusted", &good[..], Some(certified_batch(&gw_sk, rogue, &good))),
            ("tampered body", &tampered[..], Some(cert)),
            ("bad cert sig", &good[..], Some(bad_sig)),
        ] {
            let mut v = Certified::new(vec![gw_pk], 1);
            v.verify(&Batch { items, cert: c.as_ref() }, &mut ok);
            assert!(ok.iter().all(|o| !*o), "{name} must reject the whole batch");
            assert_eq!(v.audit_failures, 1, "{name}");
        }

        // A forged item is caught when it falls in the audit sample, and
        // the sample is a deterministic function of the digest.
        let mut forged = good.clone();
        forged[10].auth = Auth::Sig { key: pk, sig: ed25519::sign_message(&sk, b"other") };
        let cert_f = certified_batch(&gw_sk, gw_pk, &forged);
        let mut v1 = Certified::new(vec![gw_pk], 4);
        let mut v2 = Certified::new(vec![gw_pk], 4);
        let mut ok2 = Vec::new();
        v1.verify(&Batch { items: &forged, cert: Some(&cert_f) }, &mut ok);
        v2.verify(&Batch { items: &forged, cert: Some(&cert_f) }, &mut ok2);
        assert_eq!(ok, ok2, "every validator audits the same items");
        // With audit_every = 1 the forgery is certain to be caught.
        let mut all = Certified::new(vec![gw_pk], 1);
        all.verify(&Batch { items: &forged, cert: Some(&cert_f) }, &mut ok);
        assert!(ok.iter().all(|o| !*o));
    }

    #[test]
    fn session_mac_rejects_replay_reorder_wrong_key_and_unknown_session() {
        let key = [7u8; 32];
        let b = workload(1, 1)[0];
        let mk = |session, counter, k: &[u8; 32]| Item {
            body: b,
            auth: Auth::Mac { session, counter, tag: session_tag(k, session, counter, &b) },
        };
        let mut m = SessionMac::default();
        m.open(key);
        let mut ok = Vec::new();
        let items = [
            mk(0, 1, &key),     // ok
            mk(0, 1, &key),     // replay
            mk(0, 3, &key),     // ok (gaps allowed, must increase)
            mk(0, 2, &key),     // reorder
            mk(0, 4, &[8; 32]), // wrong key
            mk(9, 5, &key),     // unknown session
            mk(0, 5, &key),     // ok
        ];
        m.verify(&Batch { items: &items, cert: None }, &mut ok);
        assert_eq!(ok, [true, false, true, false, false, false, true]);
    }

    #[test]
    fn router_is_total_and_stable() {
        let r = ByMarket { shards: 4 };
        for m in 0..100u16 {
            assert!(r.shard(m) < 4);
            assert_eq!(r.shard(m), r.shard(m));
        }
    }
}
