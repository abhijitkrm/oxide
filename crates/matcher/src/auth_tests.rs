//! Tests for the pluggable authenticators (`crate::auth`): every scheme
//! accepts what it should and fails closed on everything else, the
//! default is bit-identical to the historical path, and each scheme
//! works end to end through the matcher (orders AND actions).
#![allow(clippy::many_single_char_names, clippy::similar_names)]

use std::sync::Arc;

use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::{MarketConfig, OrderType, Side, TimeInForce};

use crate::auth::{
    AuthConfig, AuthKind, Authenticator, Certified, Ed25519Batch, Ed25519PerItem, EvmRecover,
    MarketScope, Multi, Schemes, SessionError, SessionMac, SessionOpen, certify, classify,
    sign_action_evm, sign_action_session, sign_order_evm, sign_order_session,
};
use crate::protocol::{
    ActionRequest, ActionType, CHAIN_ID, OrderRequest, RejectReason, VerifiedOrder, sign_action,
    sign_order,
};
use crate::{AtomicBalanceCache, MultiMarketMatcher};

const CHAIN: u64 = CHAIN_ID;

fn blank(market: u8, side: Side, nonce: u64) -> OrderRequest {
    OrderRequest {
        market,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce,
        owner: Address([0; 20]),
        pubkey: [0; 32],
        signature: [0; 64],
    }
}

fn blank_action(order_id: u64, nonce: u64) -> ActionRequest {
    ActionRequest {
        action_type: ActionType::Cancel,
        order_id,
        new_price: Price(0),
        new_qty: Qty(0),
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        nonce,
        owner: Address([0; 20]),
        pubkey: [0; 32],
        signature: [0; 64],
    }
}

fn ed(seed: u8) -> (crypto::ed25519::Ed25519SecretKey, Address) {
    let sk = crypto::ed25519::Ed25519SecretKey::from_bytes(&[seed; 32]);
    let a = crypto::ed25519::owner_address(&sk.verifying_key());
    (sk, a)
}

fn evm_key(seed: u8) -> [u8; 32] {
    let mut k = [seed; 32];
    k[0] = 1; // keep it comfortably inside the curve order
    k
}

fn ed_order(seed: u8, nonce: u64) -> OrderRequest {
    let (sk, _) = ed(seed);
    let mut r = blank(0, Side::Buy, nonce);
    sign_order(&mut r, &sk);
    r
}

fn evm_order(seed: u8, nonce: u64) -> OrderRequest {
    let mut r = blank(0, Side::Buy, nonce);
    sign_order_evm(&mut r, &evm_key(seed), CHAIN);
    r
}

fn ok(v: &[Option<VerifiedOrder>]) -> Vec<bool> {
    v.iter().map(Option::is_some).collect()
}

#[test]
fn default_is_bit_identical_to_the_historical_batch_path() {
    let mut reqs: Vec<OrderRequest> = (1..=9u8).map(|s| ed_order(s, 1)).collect();
    reqs[3].qty = Qty(2_000); // tampered after signing
    reqs[6].owner = Address([9; 20]); // foreign owner
    reqs[8].signature = [0; 64];
    let want = VerifiedOrder::batch_with_chain_id(&reqs, CHAIN);
    assert_eq!(Ed25519Batch.orders(&reqs, CHAIN), want);
    assert_eq!(ok(&Ed25519PerItem.orders(&reqs, CHAIN)), ok(&want));
    assert_eq!(ok(&want), [true, true, true, false, true, true, false, true, false]);
}

#[test]
fn classification_routes_by_credential_shape() {
    assert_eq!(
        classify(&ed_order(1, 1).pubkey, &ed_order(1, 1).signature),
        crate::auth::Scheme::Ed25519
    );
    let e = evm_order(1, 1);
    assert_eq!(classify(&e.pubkey, &e.signature), crate::auth::Scheme::Evm);
    let mut m = blank(0, Side::Buy, 1);
    sign_order_session(&mut m, 300, &[7; 32], CHAIN);
    assert_eq!(classify(&m.pubkey, &m.signature), crate::auth::Scheme::SessionMac);
    // Small session ids collide with the EVM pubkey shape; the zero
    // upper signature half still routes them to the MAC.
    sign_order_session(&mut m, 1, &[7; 32], CHAIN);
    assert_eq!(classify(&m.pubkey, &m.signature), crate::auth::Scheme::SessionMac);
}

#[test]
fn evm_accepts_valid_and_rejects_every_defect() {
    let a = EvmRecover::default();
    let good = evm_order(5, 1);
    let mut wrong_qty = good;
    wrong_qty.qty = Qty(9_000);
    let mut wrong_owner = good;
    wrong_owner.owner = Address([3; 20]);
    let mut wrong_recid = good;
    wrong_recid.pubkey[0] ^= 1;
    let mut junk_pubkey = good;
    junk_pubkey.pubkey[5] = 1;
    let reqs = [good, wrong_qty, wrong_owner, wrong_recid, junk_pubkey];
    assert_eq!(ok(&a.orders(&reqs, CHAIN)), [true, false, false, false, false]);
    assert_eq!(ok(&a.orders(&[good], CHAIN + 1)), [false], "chain-bound");
    // An ed25519 order is not an EVM order.
    assert_eq!(ok(&a.orders(&[ed_order(1, 1)], CHAIN)), [false]);
}

#[test]
fn evm_parallel_equals_serial() {
    let mut reqs: Vec<OrderRequest> =
        (0..150u8).map(|i| evm_order(i % 40 + 1, u64::from(i) + 1)).collect();
    reqs[10].qty = Qty(77_000);
    reqs[149].owner = Address([1; 20]);
    let serial = ok(&EvmRecover { threads: 1 }.orders(&reqs, CHAIN));
    for t in [2, 3, 8] {
        assert_eq!(ok(&EvmRecover { threads: t }.orders(&reqs, CHAIN)), serial, "threads={t}");
    }
    assert_eq!(serial.iter().filter(|b| !**b).count(), 2);
}

#[test]
fn evm_action_round_trips() {
    let a = EvmRecover::default();
    let mut act = blank_action(5, 1);
    sign_action_evm(&mut act, &evm_key(2), CHAIN);
    assert!(a.action(act, CHAIN).is_some());
    let mut bad = act;
    bad.order_id = 6;
    assert!(a.action(bad, CHAIN).is_none());
}

fn open_ed(a: &dyn Authenticator, seed: u8, key: [u8; 32], scope: MarketScope) -> u32 {
    let (sk, _) = ed(seed);
    a.open_session(&SessionOpen::sign_ed25519(&sk, key, scope, CHAIN), CHAIN).expect("open")
}

#[test]
fn session_mac_accepts_in_scope_and_fails_closed_otherwise() {
    let a = SessionMac::default();
    let (_, owner) = ed(4);
    let key = [0x42; 32];
    let id = open_ed(&a, 4, key, MarketScope::only(&[0, 3]));

    let mk = |market: u8, nonce: u64| {
        let mut r = blank(market, Side::Buy, nonce);
        r.owner = owner;
        sign_order_session(&mut r, id, &key, CHAIN);
        r
    };
    let in_scope = mk(0, 1);
    let out_of_scope = mk(5, 2);
    let mut tampered = mk(3, 3);
    tampered.qty = Qty(5_000);
    // The dangerous case: the session holder MACs correctly, but for an
    // account that is not the session's owner.
    let mut stolen_owner = blank(0, Side::Buy, 4);
    stolen_owner.owner = Address([8; 20]);
    sign_order_session(&mut stolen_owner, id, &key, CHAIN);
    let mut wrong_key = blank(0, Side::Buy, 5);
    wrong_key.owner = owner;
    sign_order_session(&mut wrong_key, id, &[0x43; 32], CHAIN);
    let mut unknown = mk(0, 6);
    unknown.pubkey[0] = 77;
    let mut dirty_tail = mk(0, 7);
    dirty_tail.signature[40] = 1;

    let reqs = [in_scope, out_of_scope, tampered, stolen_owner, wrong_key, unknown, dirty_tail];
    assert_eq!(ok(&a.orders(&reqs, CHAIN)), [true, false, false, false, false, false, false]);
    assert_eq!(ok(&a.orders(&[in_scope], CHAIN + 1)), [false], "chain-bound");

    // Revocation is immediate.
    assert!(a.close_session(id));
    assert_eq!(ok(&a.orders(&[in_scope], CHAIN)), [false]);
    assert!(!a.close_session(id));
}

#[test]
fn session_open_must_be_authorized_by_the_owner() {
    let a = SessionMac::default();
    let key = [1; 32];
    let (sk, owner) = ed(4);
    let mut open = SessionOpen::sign_ed25519(&sk, key, MarketScope::all(), CHAIN);
    // Claim someone else's account: the signature no longer covers it.
    open.owner = Address([9; 20]);
    assert_eq!(a.open_session(&open, CHAIN), Err(SessionError::BadAuthorization));
    // Widening the scope after signing is also caught.
    let mut open = SessionOpen::sign_ed25519(&sk, key, MarketScope::only(&[1]), CHAIN);
    open.scope = MarketScope::all();
    assert_eq!(a.open_session(&open, CHAIN), Err(SessionError::BadAuthorization));
    // Wrong chain.
    let open = SessionOpen::sign_ed25519(&sk, key, MarketScope::all(), CHAIN);
    assert_eq!(a.open_session(&open, CHAIN + 1), Err(SessionError::BadAuthorization));
    // A session MAC cannot open sessions (that would let it widen itself).
    let id = open_ed(&a, 4, key, MarketScope::all());
    let mut forged = SessionOpen::sign_ed25519(&sk, key, MarketScope::all(), CHAIN);
    forged.pubkey = [0; 32];
    forged.pubkey[..4].copy_from_slice(&id.to_le_bytes());
    forged.signature = [0; 64];
    forged.owner = owner;
    assert_eq!(a.open_session(&forged, CHAIN), Err(SessionError::BadAuthorization));
    // An EVM key can open one, and the session then trades for the EVM address.
    let ek = evm_key(6);
    let eaddr = crypto::secp::signable_pubkey_address(&ek).expect("key");
    let id = a
        .open_session(&SessionOpen::sign_evm(&ek, [5; 32], MarketScope::all(), CHAIN), CHAIN)
        .expect("evm-authorized open");
    let mut r = blank(0, Side::Sell, 1);
    r.owner = eaddr;
    sign_order_session(&mut r, id, &[5; 32], CHAIN);
    assert_eq!(ok(&a.orders(&[r], CHAIN)), [true]);
}

#[test]
fn session_actions_work_and_are_owner_bound() {
    let a = SessionMac::default();
    let (_, owner) = ed(4);
    let id = open_ed(&a, 4, [3; 32], MarketScope::only(&[0]));
    let mut act = blank_action(9, 1);
    act.owner = owner;
    sign_action_session(&mut act, id, &[3; 32], CHAIN);
    assert!(a.action(act, CHAIN).is_some());
    // Valid MAC, wrong account: must still be refused.
    let mut other = blank_action(9, 3);
    other.owner = Address([1; 20]);
    sign_action_session(&mut other, id, &[3; 32], CHAIN);
    assert!(a.action(other, CHAIN).is_none());
    // A session with an empty scope may not act at all.
    let empty = open_ed(&a, 4, [4; 32], MarketScope::only(&[]));
    let mut act2 = blank_action(9, 2);
    act2.owner = owner;
    sign_action_session(&mut act2, empty, &[4; 32], CHAIN);
    assert!(a.action(act2, CHAIN).is_none());
}

fn cert_auth(gw: &crypto::ed25519::Ed25519SecretKey, audit_every: u32) -> Certified {
    Certified::new(vec![gw.verifying_key().to_bytes()], audit_every, Box::new(Ed25519Batch))
}

#[test]
fn certified_accepts_and_fails_closed() {
    let (gw, _) = ed(99);
    let reqs: Vec<OrderRequest> = (1..=8u8).map(|s| ed_order(s, 1)).collect();
    let good = certify(&gw, &reqs, CHAIN);

    let a = cert_auth(&gw, 1);
    assert!(a.certified_orders(&reqs, &good, CHAIN).iter().all(Option::is_some));
    assert_eq!(a.audit_failures(), 0);

    // Tampered order (digest no longer matches), foreign gateway, wrong chain.
    let mut tampered = reqs.clone();
    tampered[2].qty = Qty(9_000);
    let (rogue, _) = ed(98);
    for (name, rs, cert) in [
        ("tampered", &tampered[..], good),
        ("untrusted gateway", &reqs[..], certify(&rogue, &reqs, CHAIN)),
        ("wrong chain", &reqs[..], certify(&gw, &reqs, CHAIN + 1)),
    ] {
        let a = cert_auth(&gw, 1);
        assert!(a.certified_orders(rs, &cert, CHAIN).iter().all(Option::is_none), "{name}");
        assert_eq!(a.audit_failures(), 1, "{name}");
    }

    // A gateway that vouches for a forged order is caught by the audit
    // when the forgery lands in the sample (audit_every = 1: certain).
    let mut forged = reqs.clone();
    forged[4].signature = [1; 64];
    let cert = certify(&gw, &forged, CHAIN);
    let a = cert_auth(&gw, 1);
    assert!(a.certified_orders(&forged, &cert, CHAIN).iter().all(Option::is_none));
    assert_eq!(a.audit_failures(), 1);
    // Uncertified traffic still goes through the inner authenticator.
    assert_eq!(ok(&a.orders(&reqs, CHAIN)), vec![true; 8]);
}

#[test]
fn multi_routes_each_scheme_and_honours_the_allow_list() {
    let m = Multi::new(Schemes::all(), 2, None);
    let (_, owner) = ed(4);
    let key = [9; 32];
    let id = m
        .open_session(&SessionOpen::sign_ed25519(&ed(4).0, key, MarketScope::all(), CHAIN), CHAIN)
        .expect("open");
    let mut mac = blank(0, Side::Buy, 3);
    mac.owner = owner;
    sign_order_session(&mut mac, id, &key, CHAIN);
    let mut bad_ed = ed_order(2, 4);
    bad_ed.qty = Qty(1);
    let reqs = [ed_order(1, 1), evm_order(1, 2), mac, bad_ed, ed_order(3, 5), evm_order(2, 6)];
    assert_eq!(ok(&m.orders(&reqs, CHAIN)), [true, true, true, false, true, true]);

    let only_evm = Multi::new(Schemes::parse("evm").expect("parse"), 1, None);
    assert_eq!(ok(&only_evm.orders(&reqs, CHAIN)), [false, true, false, false, false, true]);
    let no_mac = Multi::new(Schemes::parse("ed25519,evm").expect("parse"), 1, None);
    assert!(
        no_mac
            .open_session(
                &SessionOpen::sign_ed25519(&ed(4).0, key, MarketScope::all(), CHAIN),
                CHAIN
            )
            .is_err()
    );

    // Actions route the same way.
    let mut ea = blank_action(1, 1);
    sign_action_evm(&mut ea, &evm_key(1), CHAIN);
    let mut da = blank_action(1, 2);
    sign_action(&mut da, &ed(1).0);
    assert!(m.action(ea, CHAIN).is_some() && m.action(da, CHAIN).is_some());
    assert!(only_evm.action(da, CHAIN).is_none());
}

#[test]
fn config_selects_the_scheme_and_there_is_no_accept_all() {
    for (name, want) in [
        ("ed25519_batch", "ed25519_batch"),
        ("ed25519", "ed25519"),
        ("evm", "evm_recover"),
        ("session_mac", "session_mac"),
        ("certified", "certified"),
        ("multi", "multi"),
    ] {
        let cfg =
            AuthConfig { kind: AuthKind::parse(name).expect("known"), ..AuthConfig::default() };
        assert_eq!(cfg.build().name(), want);
    }
    assert_eq!(AuthConfig::default().build().name(), "ed25519_batch");
    assert!(AuthKind::parse("none").is_err() && AuthKind::parse("off").is_err());
    assert!(Schemes::parse("ed25519,bogus").is_err());
}

// ── end to end through the matcher ─────────────────────────────────

fn market() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 12,
    }
}

fn matcher_with(a: Arc<dyn Authenticator>, funded: &[Address]) -> MultiMarketMatcher {
    let balances = Arc::new(AtomicBalanceCache::new(8));
    for f in funded {
        balances.set(f, 1_000_000_000_000);
    }
    MultiMarketMatcher::new(vec![market()], balances).with_authenticator(a)
}

#[test]
fn every_scheme_trades_end_to_end_and_the_default_refuses_the_others() {
    let evm_a = crypto::secp::signable_pubkey_address(&evm_key(1)).expect("key");
    let (_, ed_a) = ed(7);
    let (_, mac_a) = ed(8);
    let multi = Arc::new(Multi::new(Schemes::all(), 1, None));
    let m = matcher_with(multi.clone(), &[evm_a, ed_a, mac_a]);

    // The session key owner is `mac_a`.
    let key = [0x55; 32];
    let id = multi
        .open_session(&SessionOpen::sign_ed25519(&ed(8).0, key, MarketScope::all(), CHAIN), CHAIN)
        .expect("open");

    // EVM seller rests, ed25519 buyer takes, session buyer takes the rest.
    let mut sell = blank(0, Side::Sell, 1);
    sign_order_evm(&mut sell, &evm_key(1), CHAIN);
    sell.qty = Qty(2_000);
    sign_order_evm(&mut sell, &evm_key(1), CHAIN); // re-sign after the qty change
    let r = m.submit_batch(vec![sell]);
    assert!(!r[0].rejected, "evm-authenticated order must be admitted: {:?}", r[0]);

    let ed_buy = ed_order(7, 1);
    let r = m.submit_batch(vec![ed_buy]);
    assert_eq!(r[0].fills_count, 1, "ed25519 buyer fills against the EVM seller");

    let mut mac_buy = blank(0, Side::Buy, 1);
    mac_buy.owner = mac_a;
    sign_order_session(&mut mac_buy, id, &key, CHAIN);
    let r = m.submit_batch(vec![mac_buy]);
    assert_eq!(r[0].fills_count, 1, "session buyer fills the remainder");

    // An EVM-authenticated cancel of a resting order.
    let mut rest = blank(0, Side::Sell, 2);
    rest.price = Price(1_900_000_000);
    sign_order_evm(&mut rest, &evm_key(1), CHAIN);
    let r = m.submit_batch(vec![rest]);
    assert!(!r[0].rejected, "resting order admitted: {:?}", r[0]);
    let order_id = r[0].order_id;
    let mut c = blank_action(order_id, 3);
    sign_action_evm(&mut c, &evm_key(1), CHAIN);
    assert!(!m.submit_action(&c).rejected, "EVM-authenticated cancel");

    // The default (ed25519) matcher refuses the EVM and session credentials.
    let d = matcher_with(Arc::new(Ed25519Batch), &[evm_a, mac_a]);
    let mut e = blank(0, Side::Sell, 1);
    sign_order_evm(&mut e, &evm_key(1), CHAIN);
    let r = d.submit_batch(vec![e]);
    assert_eq!(r[0].reject_reason, Some(RejectReason::BadSignature));
}

#[test]
fn replay_protection_still_holds_for_every_scheme() {
    let evm_a = crypto::secp::signable_pubkey_address(&evm_key(1)).expect("key");
    let m = matcher_with(Arc::new(EvmRecover::default()), &[evm_a]);
    let o = evm_order(1, 1);
    assert!(!m.submit_batch(vec![o])[0].rejected);
    // The identical signed order again: authentic, but the nonce is spent.
    assert_eq!(m.submit_batch(vec![o])[0].reject_reason, Some(RejectReason::StaleNonce));
}
