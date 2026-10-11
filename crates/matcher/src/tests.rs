//! Unit tests — extracted from the implementation file so the
//! production code reads top-to-bottom without the test bulk
//! (split-giant-modules pass: every entry point's enforcement
//! stays visible).

use super::*;
use primitives::fixed::{Price, Qty};
use trading::TimeInForce;

fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 16,
    }
}

fn addr(byte: u8) -> primitives::Address {
    primitives::Address([byte; 20])
}

/// A deterministic test account: `seed` derives the Ed25519
/// signing key; the account address is the key's derived owner.
fn test_account(seed: u8) -> (crypto::ed25519::Ed25519SecretKey, primitives::Address) {
    let secret = crypto::ed25519::Ed25519SecretKey::from_bytes(&[seed; 32]);
    let owner = crypto::ed25519::owner_address(&secret.verifying_key());
    (secret, owner)
}

/// Build a signed order for `secret`'s account.
fn signed_req(
    secret: &crypto::ed25519::Ed25519SecretKey,
    market: u8,
    side: Side,
    nonce: u64,
    price: u64,
    qty: u64,
) -> OrderRequest {
    let mut req = OrderRequest {
        market,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(price),
        qty: Qty(qty),
        nonce,
        owner: addr(0),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    crate::protocol::sign_order(&mut req, secret);
    req
}

/// Build a signed action for `secret`'s account.
fn signed_action(
    secret: &crypto::ed25519::Ed25519SecretKey,
    action_type: ActionType,
    order_id: u64,
    nonce: u64,
) -> ActionRequest {
    let mut req = ActionRequest {
        action_type,
        order_id,
        new_price: Price(0),
        new_qty: Qty(0),
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        nonce,
        owner: addr(0),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    crate::protocol::sign_action(&mut req, secret);
    req
}

// ── C5 regression tests: the mandatory admission boundary ──────

/// Regression (C5): `submit_order` used to execute orders with
/// no signature verification at all — the binary-TCP single
/// order path, JSON-RPC, FIX, and WS all submitted unverified
/// requests. An unsigned (zero-signature) order must be rejected
/// with `BadSignature` before any nonce/balance/book state
/// changes.
#[test]
fn unsigned_order_rejected_with_bad_signature() {
    let mut server = MatchingServer::new(cfg(), 100);
    server.fund_account(&addr(1), 1_000_000_000);

    let req = OrderRequest {
        market: 0,
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner: addr(1),
        nonce: 0,
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    let resp = server.submit_order(&req);
    assert!(resp.rejected, "unsigned order must be rejected");
    assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
    assert_eq!(server.resting_count(), 0, "no order may reach the book");
}

/// Regression (C5): a validly-signed order whose `owner` is NOT
/// derived from the signing key must be rejected — the signature
/// alone does not prove the key controls the claimed account.
#[test]
fn signed_order_with_foreign_owner_rejected() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (secret, _) = test_account(1);
    server.fund_account(&addr(0x77), 1_000_000_000); // the victim

    // Attacker signs a real order but claims the victim's owner.
    let mut req = signed_req(&secret, 0, Side::Buy, 1, 1_500_000_000, 1_000);
    req.owner = addr(0x77);
    // Re-sign so the signature covers the claimed owner verbatim —
    // this is the attack the owner-binding check exists to stop.
    let msg = crate::protocol::signing_message(&req);
    req.signature = crypto::ed25519::sign_message(&secret, &msg).to_bytes();

    let resp = server.submit_order(&req);
    assert!(resp.rejected);
    assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
    assert_eq!(server.balance(&addr(0x77)), 1_000_000_000, "victim balance untouched");
}

/// A properly signed order (owner derived from the key) passes
/// the boundary and matches.
#[test]
fn signed_order_accepted_and_matched() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (seller_sk, _seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&buyer, 1_000_000_000);

    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    server.submit_order(&maker);
    let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
    let resp = server.submit_order(&taker);
    assert!(!resp.rejected, "authentic order must be admitted");
    assert_eq!(resp.fills_count, 1);
    assert_eq!(server.balance(&buyer), 1_000_000_000 - 15_000);
}

/// Regression (C5): actions (cancel/amend/replace) were admitted
/// without any nonce check — a captured signed action replayed
/// forever. The same action nonce must be rejected as stale.
#[test]
fn replayed_action_nonce_rejected() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (seller_sk, seller) = test_account(9);
    server.fund_account(&seller, 0);

    // Rest a sell order so there is something to cancel.
    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    let resp = server.submit_order(&maker);
    assert!(!resp.rejected);
    let order_id = resp.order_id;
    assert_eq!(server.resting_count(), 1);

    // Cancel with nonce 1 — accepted.
    let cancel = signed_action(&seller_sk, ActionType::Cancel, order_id, 1);
    let resp = server.submit_action(&cancel);
    assert!(!resp.rejected, "first cancel must be admitted");

    // Rest a second order; replay the same cancel request
    // (same nonce) — must be rejected as stale, and the second
    // order must NOT be canceled.
    let maker2 = signed_req(&seller_sk, 0, Side::Sell, 2, 1_500_000_000, 1_000);
    let resp2 = server.submit_order(&maker2);
    assert!(!resp2.rejected);

    let replay = signed_action(&seller_sk, ActionType::Cancel, resp2.order_id, 1);
    let replay_resp = server.submit_action(&replay);
    assert!(replay_resp.rejected, "replayed action nonce must be rejected");
    assert_eq!(replay_resp.reject_reason, Some(RejectReason::StaleNonce));
    assert_eq!(server.resting_count(), 1, "second order must still be resting");
}

/// Regression (C5): an action with a bad signature must be
/// rejected at the boundary — today `submit_action` took an
/// `OrderAction` (already stripped of signature) so forged
/// cancels could reach the engine directly.
#[test]
fn unsigned_action_rejected_with_bad_signature() {
    let mut server = MatchingServer::new(cfg(), 100);
    let req = ActionRequest {
        action_type: ActionType::Cancel,
        order_id: 1,
        new_price: Price(0),
        new_qty: Qty(0),
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        nonce: 0,
        owner: addr(1),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    let resp = server.submit_action(&req);
    assert!(resp.rejected);
    assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
}

#[test]
fn buy_order_rejected_with_insufficient_balance() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&buyer, 1_000); // Not enough for 5 lots at $15.

    let req = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 5_000);

    let resp = server.submit_order(&req);
    assert!(resp.rejected, "should reject insufficient balance");
    assert_eq!(resp.reject_reason, Some(RejectReason::InsufficientBalance));
    assert_eq!(server.balance(&buyer), 1_000, "balance unchanged");
}

#[test]
fn buy_order_accepted_with_sufficient_balance() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&seller, 1_000_000_000);
    server.fund_account(&buyer, 1_000_000_000);

    // Rest a maker sell.
    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    server.submit_order(&maker);

    // Taker buy — should match the maker.
    let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
    let resp = server.submit_order(&taker);
    assert!(!resp.rejected, "should accept sufficient balance");
    assert_eq!(resp.fills_count, 1, "should have one fill");
    // Notional = 1_500_000_000 * 1_000 / 100_000_000 = 15_000.
    assert_eq!(server.balance(&buyer), 1_000_000_000 - 15_000);
    assert_eq!(server.balance(&seller), 1_000_000_000 + 15_000);
}

/// Regression test (C7): a replayed order (same nonce from the
/// same owner) must be rejected with `StaleNonce`. Before the
/// fix, the matcher ignored the protocol nonce field — signed
/// orders could be replayed indefinitely.
#[test]
fn replayed_order_rejected_with_stale_nonce() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&buyer, 1_000_000_000);

    let req = signed_req(&buyer_sk, 0, Side::Buy, 42, 1_500_000_000, 1_000);

    // First submission: accepted (nonce 42 is new).
    let resp = server.submit_order(&req);
    assert!(!resp.rejected, "first order with new nonce must be accepted");

    // Replay: same nonce, same owner — must be rejected.
    let replay = server.submit_order(&req);
    assert!(replay.rejected, "replayed order must be rejected");
    assert_eq!(
        replay.reject_reason,
        Some(RejectReason::StaleNonce),
        "replay must be rejected with StaleNonce"
    );

    // Higher nonce: accepted.
    let req2 = signed_req(&buyer_sk, 0, Side::Buy, 43, 1_500_000_000, 1_000);
    let resp2 = server.submit_order(&req2);
    assert!(!resp2.rejected, "order with higher nonce must be accepted");
}

#[test]
fn spam_orders_rejected_without_balance() {
    let risk_cfg = RiskConfig {
        max_orders_per_second: 0,
        max_order_qty: 0,
        max_price_deviation_bps: 0,
        max_resting_per_account: 0,
    };
    let mut server = MatchingServer::with_risk_config(cfg(), 100, risk_cfg);
    let (buyer_sk, _buyer) = test_account(1);

    // Submit 1000 signed buy orders with zero balance — all
    // should be rejected at the balance check (they pass
    // authentication and the nonce gate, then fail reservation).
    for i in 0..1000u64 {
        let req = signed_req(&buyer_sk, 0, Side::Buy, i, 1_500_000_000, 1_000);
        let resp = server.submit_order(&req);
        assert!(resp.rejected, "spam order should be rejected");
    }
    assert_eq!(server.balance_rejections(), 1000);
    assert_eq!(server.orders_processed(), 1000);
    assert_eq!(server.fills_produced(), 0, "no fills from rejected orders");
}

#[test]
fn ring_matcher_seals_from_the_one_book() {
    ring_matcher_seals_from_the_one_book_with(crate::SequencerIdle::Spin);
}

/// hft-audit-2 M-2: the pre-M-2 park-immediately policy must stay a
/// fully working sequencer (every pass parks; wakes come only from
/// the producer's `signal` / control-channel signals).
#[test]
fn ring_matcher_park_policy_serves_orders_and_control() {
    ring_matcher_seals_from_the_one_book_with(crate::SequencerIdle::Park);
}

fn ring_matcher_seals_from_the_one_book_with(idle: crate::SequencerIdle) {
    // The ring matcher's owner thread holds THE book. Submit
    // orders through the ring, then seal via the control channel
    // — the seal must return the SAME fills the protocols
    // produced (one book, never two).
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let mut server = MatchingServer::new(cfg(), 100);
    server.fund_account(&seller, 1_000_000_000);
    server.fund_account(&buyer, 1_000_000_000);
    let ring = RingMatcher::with_idle(server, 4, 1024, None, idle);

    // Push a maker sell + taker buy as one batch through ring 0.
    // The ring only accepts `VerifiedOrder` proofs — transport
    // threads authenticate, the matcher thread never sees a raw
    // unauthenticated request. Distinct request nonces (5 and 7)
    // let the fill assertions prove the (owner, client_id)
    // plumbing: a fill's buyer_id/seller_id must carry the
    // request nonces the owners registered on-chain.
    let maker = signed_req(&seller_sk, 0, Side::Sell, 5, 1_500_000_000, 1_000);
    let taker = signed_req(&buyer_sk, 0, Side::Buy, 7, 1_500_000_000, 1_000);
    let verified: Vec<crate::protocol::VerifiedOrder> = [maker, taker]
        .into_iter()
        .map(|req| crate::protocol::VerifiedOrder::new(req).expect("signed orders must verify"))
        .collect();
    // Hold the ring lease for the exchange — the same contract
    // the production submit path follows.
    let lease = ring.try_acquire_ring(0).expect("a free ring must lease");
    let sender = ring.order_sender(lease.ring_idx());
    let receiver = ring.response_receiver(lease.ring_idx());
    let mut batch = verified;
    while let Err(crate::ring::PushError::Full(returned)) = sender.push(batch) {
        batch = returned;
        std::hint::spin_loop();
    }
    let responses = loop {
        if let Some(r) = receiver.pop() {
            break r;
        }
        std::hint::spin_loop();
    };
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1].fills_count, 1, "taker should fill against maker");

    // Seal through the control channel — must return the fill.
    let fills = ring.seal_batch();
    assert_eq!(fills.len(), 1, "seal returns the fill produced via the ring");
    assert_eq!(fills[0].qty, Qty(1_000));
    assert_eq!(fills[0].buyer, buyer);
    assert_eq!(fills[0].seller, seller);
    // The fill carries each side's request nonce as its client
    // id — the (owner, client_id) key the on-chain batch leg
    // resolves to a registered order.
    assert_eq!(fills[0].buyer_id, 7);
    assert_eq!(fills[0].seller_id, 5);

    // Stats via the control channel.
    let stats = ring.stats();
    assert_eq!(stats.orders_processed, 2);
    assert_eq!(stats.fills_produced, 1);
}

/// The ring lease grants exclusive use of a ring pair: a second
/// acquisition on the same ring must fail while the lease lives,
/// and succeed after the holder drops it. This is what stops two
/// requesters sharing a response ring.
#[test]
fn ring_lease_grants_exclusive_ownership() {
    let server = MatchingServer::new(cfg(), 100);
    let ring = RingMatcher::new(server, 2, 64, None);

    let lease = ring.try_acquire_ring(0).expect("a free ring leases");
    let held_idx = lease.ring_idx();

    // With 2 rings the other index is still free — the lease
    // excludes per-ring, not globally.
    let other = ring.try_acquire_ring(held_idx).expect("the other ring is free");
    assert_ne!(other.ring_idx(), held_idx);
    drop(other);

    // Every ring now free except the held one: scanning from the
    // held index must skip it and find the other.
    let other2 = ring.try_acquire_ring(held_idx).expect("scan finds the free ring");
    assert_ne!(other2.ring_idx(), held_idx);
    drop(other2);

    // Drop the held lease — its ring becomes leasable again.
    drop(lease);
    let reacquired = ring.try_acquire_ring(held_idx);
    assert_eq!(reacquired.map(|l| l.ring_idx()), Some(held_idx));
}

/// With a single ring, a held lease leaves NO free ring —
/// `try_acquire_ring` must report exhaustion rather than share.
#[test]
fn ring_lease_exhaustion_waits() {
    let server = MatchingServer::new(cfg(), 100);
    let ring = RingMatcher::new(server, 1, 64, None);
    let lease = ring.try_acquire_ring(0).expect("first lease");
    assert!(ring.try_acquire_ring(0).is_none(), "held ring cannot re-lease");
    drop(lease);
    assert!(ring.try_acquire_ring(0).is_some(), "drop frees the ring");
}

// ── MultiMarketMatcher tests ────────────────────────────────

fn cfg_for(market_id: u8) -> MarketConfig {
    MarketConfig {
        market_id: u16::from(market_id),
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 16,
    }
}

#[test]
fn multi_market_two_markets_match_independently() {
    // Two markets, each with its own book. The same seller and
    // buyer trade on both — balances are shared (sharded), books
    // are independent. Nonces are also shared (per-ACCOUNT, not
    // per-market): each account's nonces must increase across
    // markets.
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let balances = Arc::new(AtomicBalanceCache::new(8));
    balances.set(&seller, 1_000_000_000);
    balances.set(&buyer, 1_000_000_000);
    let configs = vec![cfg_for(0), cfg_for(1)];
    let matcher = MultiMarketMatcher::new(configs, balances);

    // Market 0: rest a maker sell, then a taker buy fills it.
    let maker0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    let taker0 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
    let responses = matcher.submit_batch(vec![maker0, taker0]);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1].fills_count, 1, "market 0 taker should fill");

    // Market 1: same pair, independent book — should also fill.
    // Nonces continue per account (seller 1, buyer 1).
    let maker1 = signed_req(&seller_sk, 1, Side::Sell, 1, 1_600_000_000, 1_000);
    let taker1 = signed_req(&buyer_sk, 1, Side::Buy, 1, 1_600_000_000, 1_000);
    let responses = matcher.submit_batch(vec![maker1, taker1]);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1].fills_count, 1, "market 1 taker should fill");

    // Seal: should have 2 fills (one per market).
    let fills = matcher.seal_batch();
    assert_eq!(fills.len(), 2, "seal collects from both markets");

    // Aggregate stats: 4 orders, 2 fills.
    let stats = matcher.stats();
    assert_eq!(stats.orders_processed, 4);
    assert_eq!(stats.fills_produced, 2);
}

#[test]
fn multi_market_balance_check_is_atomic_across_markets() {
    // The buyer has exactly 15_000 quote (enough for ONE fill at
    // $15 × 1000 qty). Two markets try to debit simultaneously —
    // only one should succeed.
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let balances = Arc::new(AtomicBalanceCache::new(8));
    balances.set(&seller, 1_000_000_000); // Seller (funded).
    balances.set(&buyer, 15_000); // Buyer: exactly one fill's worth.
    let configs = vec![cfg_for(0), cfg_for(1)];
    let matcher = MultiMarketMatcher::new(configs, balances);

    // Rest maker sells on both markets (seller nonces 0, 1 —
    // shared per-account nonce tracker across markets).
    let maker0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    let maker1 = signed_req(&seller_sk, 1, Side::Sell, 1, 1_500_000_000, 1_000);
    matcher.submit_batch(vec![maker0]);
    matcher.submit_batch(vec![maker1]);

    // Submit taker buys on both markets (same buyer, same
    // balance; buyer nonces 0, 1).
    let taker0 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
    let taker1 = signed_req(&buyer_sk, 1, Side::Buy, 1, 1_500_000_000, 1_000);
    let resp0 = matcher.submit_one(taker0);
    let resp1 = matcher.submit_one(taker1);

    // Exactly one should fill, the other should be rejected
    // (insufficient balance). The check_and_debit is atomic
    // under the shard lock.
    let fills0 = resp0.fills_count;
    let fills1 = resp1.fills_count;
    assert!(
        (fills0 == 1 && resp1.rejected) || (fills1 == 1 && resp0.rejected),
        "exactly one market should fill, the other reject; got fills0={fills0} rejected0={} fills1={fills1} rejected1={}",
        resp0.rejected,
        resp1.rejected
    );
}

/// Regression (C5): a batch with a bad-signature order between
/// two valid orders must produce aligned responses —
/// `[good, bad, good]` → `[result0, BadSignature, result1]`.
/// The pre-fix transport filtered valid requests and prepended
/// rejections, yielding `[BadSignature, result0, result1]` and
/// misattributing every response after the bad entry.
#[test]
fn multi_market_batch_preserves_positions_with_bad_signature() {
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let balances = Arc::new(AtomicBalanceCache::new(8));
    balances.set(&seller, 1_000_000_000);
    balances.set(&buyer, 1_000_000_000);
    let configs = vec![cfg_for(0), cfg_for(1)];
    let matcher = MultiMarketMatcher::new(configs, balances);

    let good0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    // A forged order: zero signature/pubkey — fails verify_order
    // outright regardless of the claimed owner.
    let bad = OrderRequest {
        market: 0,
        side: Side::Sell,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce: 0,
        owner: seller,
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    let good1 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);

    // The interleaved case: [good sell, forged, good buy].
    let responses = matcher.submit_batch(vec![good0, bad, good1]);
    assert_eq!(responses.len(), 3);
    assert!(!responses[0].rejected, "index 0 (good sell) must rest");
    assert!(responses[1].rejected, "index 1 (forged) must be rejected");
    assert_eq!(
        responses[1].reject_reason,
        Some(RejectReason::BadSignature),
        "the middle slot gets BadSignature at its own position"
    );
    assert_eq!(responses[2].fills_count, 1, "index 2 (good buy) fills against the resting sell");
}

// ── C6 regression tests: reservation accounting ─────────────

/// Regression (C6): a resting buy's reservation must STAY debited
/// while the order rests. The old code refunded `price * unfilled`
/// immediately — including the resting quantity — then `cancel`
/// refunded it again, minting balance out of nothing (buy at
/// `15_000`, cancel, end with `15_000` MORE than started).
#[test]
fn resting_buy_reservation_released_exactly_once() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&buyer, 100_000);

    // GTC limit buy, nothing to match against — rests.
    let req = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
    let resp = server.submit_order(&req);
    assert!(!resp.rejected, "buy should rest");

    // Reservation = 1.5e9 * 1_000 / 1e8 = 15_000. The balance
    // must show the reservation is STILL held — if this shows
    // 100_000, the cancel below will refund a second time.
    let after_rest = server.balances.get(&buyer);
    assert_eq!(
        after_rest,
        100_000 - 15_000,
        "resting reservation must remain debited (got {after_rest})"
    );

    // Cancel via a signed action (nonce 1).
    let cancel = signed_action(&buyer_sk, ActionType::Cancel, resp.order_id, 1);
    let resp2 = server.submit_action(&cancel);
    assert!(!resp2.rejected, "cancel should succeed");

    // Conservation: started with 100_000, traded nothing —
    // must end with exactly 100_000. The double-refund bug
    // leaves 115_000.
    assert_eq!(
        server.balances.get(&buyer),
        100_000,
        "cancel must refund the reservation exactly once"
    );
}

/// Regression (C6): price improvement must be refunded. A taker
/// limit buy debited at its LIMIT price but filled at a BETTER
/// maker price keeps the difference today — the reservation
/// silently overcharges the taker.
#[test]
fn price_improvement_is_refunded_to_taker() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&seller, 1_000_000_000);
    server.fund_account(&buyer, 100_000);

    // Maker rests a sell at 1.5e9.
    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    server.submit_order(&maker);

    // Taker buys with a 1.6e9 limit — fills at the maker's 1.5e9.
    // Reservation debits 16_000; actual cost 15_000.
    let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_600_000_000, 1_000);
    let resp = server.submit_order(&taker);
    assert_eq!(resp.fills_count, 1, "taker should fill at maker price");

    // The 1_000 improvement must come back.
    assert_eq!(
        server.balances.get(&buyer),
        100_000 - 15_000,
        "taker pays the fill price, not the limit price"
    );
    assert_eq!(
        server.balances.get(&seller),
        1_000_000_000 + 15_000,
        "seller receives the fill price"
    );
}

/// Regression (C6): market buys were never reserved — the
/// `!= Market` guard skipped the debit while fills still
/// credited sellers, minting quote on every market sweep.
/// An unfunded market buy must reject BEFORE touching the book;
/// a funded one must pay the actual sweep cost.
#[test]
fn market_buy_reserves_sweep_cost_and_settles() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (seller_sk, seller) = test_account(9);
    let (poor_sk, poor) = test_account(2);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&seller, 1_000_000_000);
    server.fund_account(&poor, 0);
    server.fund_account(&buyer, 100_000);

    // Maker rests a sell at 1.5e9.
    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    server.submit_order(&maker);

    // Unfunded market buy: must reject WITHOUT consuming the
    // resting order.
    let mut poor_req = signed_req(&poor_sk, 0, Side::Buy, 0, 0, 1_000);
    poor_req.order_type = OrderType::Market;
    poor_req.tif = TimeInForce::Ioc; // Market requires Ioc.
    poor_req.price = Price(0);
    // Re-sign after mutation (signature covers price/type).
    crate::protocol::sign_order(&mut poor_req, &poor_sk);
    let resp = server.submit_order(&poor_req);
    assert!(resp.rejected, "unfunded market buy must reject");
    assert_eq!(resp.reject_reason, Some(RejectReason::InsufficientBalance));
    assert_eq!(server.resting_count(), 1, "the resting maker must survive a rejected sweep");

    // Funded market buy: pays the actual sweep cost (15_000).
    let mut mkt = signed_req(&buyer_sk, 0, Side::Buy, 0, 0, 1_000);
    mkt.order_type = OrderType::Market;
    mkt.tif = TimeInForce::Ioc;
    mkt.price = Price(0);
    crate::protocol::sign_order(&mut mkt, &buyer_sk);
    let resp = server.submit_order(&mkt);
    assert_eq!(resp.fills_count, 1, "market buy should sweep the ask");
    assert_eq!(
        server.balances.get(&buyer),
        100_000 - 15_000,
        "market taker pays the real fill cost"
    );
    assert_eq!(server.balances.get(&seller), 1_000_000_000 + 15_000);
}

/// Regression (C6): an IOC/FOK remainder is DEAD — it must not be
/// counted or reported as resting. `CanceledRemainder` was
/// mapped to `OrderResponse::resting` + `inc_resting`, inflating
/// the resting cap and telling the client a dead order is live.
#[test]
fn ioc_remainder_does_not_rest() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&seller, 1_000_000_000);
    server.fund_account(&buyer, 100_000);

    // Maker sells 1_000 (one lot); taker IOC buys 2_000 — fills
    // 1_000, the remaining 1_000 must die, not rest.
    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    server.submit_order(&maker);

    let mut ioc = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 2_000);
    ioc.tif = TimeInForce::Ioc;
    crate::protocol::sign_order(&mut ioc, &buyer_sk);
    let resp = server.submit_order(&ioc);
    assert!(!resp.rejected);
    assert_eq!(resp.fills_count, 1, "IOC fills the 1_000 available");

    // The book must be empty and the resting counter at zero —
    // the remainder was canceled by IOC semantics.
    assert_eq!(server.resting_count(), 0, "IOC remainder must not rest");

    // Reservation: debited 30_000, paid 15_000, remainder dead
    // → 15_000 refunded (nothing stays reserved).
    assert_eq!(
        server.balances.get(&buyer),
        100_000 - 15_000,
        "dead remainder's reservation is fully refunded"
    );
}

/// Regression (C6): a partially-filled buy that then rests holds
/// reservation ONLY for the resting remainder — and cancel
/// refunds exactly that, once.
#[test]
fn partial_fill_buy_holds_only_remainder_reservation() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&seller, 1_000_000_000);
    server.fund_account(&buyer, 100_000);

    // Maker sells 1_000; taker GTC buys 2_000 — fills 1_000,
    // rests 1_000.
    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    server.submit_order(&maker);
    let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 2_000);
    let resp = server.submit_order(&taker);
    assert_eq!(resp.fills_count, 1);

    // Paid 1_000×15 = 15_000; still holds 1_000×15 = 15_000 reserved.
    assert_eq!(
        server.balances.get(&buyer),
        100_000 - 15_000 - 15_000,
        "paid fills + held remainder reservation"
    );

    // Cancel the remainder: 15_000 comes back exactly once.
    let cancel = signed_action(&buyer_sk, ActionType::Cancel, resp.order_id, 1);
    server.submit_action(&cancel);
    assert_eq!(server.balances.get(&buyer), 100_000 - 15_000);
}

/// Regression (C5): `submit_batch` must route each verified order
/// by ITS OWN `market` field — not `orders[0].market`. The pre-fix
/// code sent the whole batch to the head order's worker, silently
/// matching mixed-market batches on the wrong book. Distinct
/// price bands make misrouting observable: market 1's price is
/// out of band on market 0's engine, so a misrouted order would
/// be rejected instead of filling.
#[test]
fn multi_market_batch_routes_by_each_orders_market() {
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let balances = Arc::new(AtomicBalanceCache::new(8));
    balances.set(&seller, 1_000_000_000);
    balances.set(&buyer, 1_000_000_000);
    // Market 0 band: [1e9, 2e9]. Market 1 band: [3e9, 4e9] — no
    // overlap, so a market-1 order landing on market 0's engine
    // is rejected by price-band validation.
    let mut cfg0 = cfg_for(0);
    cfg0.min_price = Price(1_000_000_000);
    cfg0.max_price = Price(2_000_000_000);
    let mut cfg1 = cfg_for(1);
    cfg1.min_price = Price(3_000_000_000);
    cfg1.max_price = Price(4_000_000_000);
    let matcher = MultiMarketMatcher::new(vec![cfg0, cfg1], balances);

    // One mixed batch: market-1 orders INTERLEAVED after the
    // market-0 head. If routed by orders[0].market, both market-1
    // orders hit the [1e9,2e9] engine and are rejected.
    let orders = vec![
        signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000),
        signed_req(&seller_sk, 1, Side::Sell, 1, 3_500_000_000, 1_000),
        signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000),
        signed_req(&buyer_sk, 1, Side::Buy, 1, 3_500_000_000, 1_000),
    ];
    let responses = matcher.submit_batch(orders);
    assert_eq!(responses.len(), 4);
    assert!(!responses[0].rejected, "market-0 maker rests, got {:?}", responses[0].reject_reason);
    assert!(
        !responses[1].rejected,
        "market-1 maker must reach market 1's engine (its 3.5e9 \
         price is out of band on market 0 — a misroute would reject)"
    );
    assert_eq!(
        responses[2].fills_count, 1,
        "market-0 taker fills (rejected={} reason={:?})",
        responses[2].rejected, responses[2].reject_reason
    );
    assert_eq!(
        responses[3].fills_count, 1,
        "market-1 taker fills (rejected={} reason={:?})",
        responses[3].rejected, responses[3].reject_reason
    );

    let fills = matcher.seal_batch();
    assert_eq!(fills.len(), 2, "one fill per market");
}

// ── Risk-control accounting: time source + resting counts ────

/// A test clock the caller advances explicitly — the rate
/// limiter must measure THESE milliseconds, never the server's
/// order counter.
fn test_clock() -> (Arc<std::sync::atomic::AtomicU64>, Arc<dyn Fn() -> u64 + Send + Sync>) {
    let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reader = Arc::clone(&now);
    let clock: Arc<dyn Fn() -> u64 + Send + Sync> =
        Arc::new(move || reader.load(std::sync::atomic::Ordering::Relaxed));
    (now, clock)
}

/// Regression: `execute_order` fed `orders_processed` — a
/// GLOBAL counter — to the rate limiter as its millisecond
/// timestamp. Every order submitted anywhere advanced every
/// account's "time", so unrelated traffic could slide a
/// rate-limited trader's window open while zero real time had
/// passed, and real elapsed time had no effect on the limit.
#[test]
fn rate_limiter_uses_clock_not_order_counter() {
    let mut server = MatchingServer::with_risk_config(
        cfg(),
        100,
        RiskConfig {
            max_orders_per_second: 2,
            max_order_qty: 0,
            max_price_deviation_bps: 0,
            max_resting_per_account: 0,
        },
    );
    let (now, clock) = test_clock();
    server.set_clock(clock);

    let (trader_sk, trader) = test_account(3);
    let (other_sk, other) = test_account(4);
    server.fund_account(&trader, 1_000_000_000_000);
    server.fund_account(&other, 1_000_000_000_000);

    // Two orders at t=0 pass; the third is rate-limited.
    for nonce in 0..2 {
        let req = signed_req(&trader_sk, 0, Side::Buy, nonce, 1_500_000_000, 1_000);
        assert!(!server.submit_order(&req).rejected);
    }
    let req = signed_req(&trader_sk, 0, Side::Buy, 2, 1_500_000_000, 1_000);
    let resp = server.submit_order(&req);
    assert_eq!(resp.reject_reason, Some(RejectReason::RateLimited));

    // 1_500 orders from ANOTHER account. With the counter fed
    // as milliseconds this pushed "now" ~1.5s forward and slid
    // the trader's window open — even though the clock has not
    // moved at all. (Each flood order is itself rejected after
    // the second one, but `orders_processed` counted them all.)
    for nonce in 0..1_500 {
        let req = signed_req(&other_sk, 0, Side::Sell, nonce, 1_500_000_000, 1_000);
        server.submit_order(&req);
    }
    let req = signed_req(&trader_sk, 0, Side::Buy, 3, 1_500_000_000, 1_000);
    let resp = server.submit_order(&req);
    assert_eq!(
        resp.reject_reason,
        Some(RejectReason::RateLimited),
        "other accounts' order flow must not slide the window"
    );

    // Real elapsed time does slide it: +1001ms exceeds the
    // one-second window and the next order passes.
    now.store(1_001, std::sync::atomic::Ordering::Relaxed);
    let req = signed_req(&trader_sk, 0, Side::Buy, 4, 1_500_000_000, 1_000);
    assert!(!server.submit_order(&req).rejected, "order after the window slid must be allowed");
}

/// Regression: a maker filled to zero left the book but kept
/// its resting-order slot — active market makers accumulated
/// phantom counts until the per-account cap rejected them.
#[test]
fn filled_maker_releases_resting_count() {
    let mut server = MatchingServer::with_risk_config(
        cfg(),
        100,
        RiskConfig {
            max_orders_per_second: 0,
            max_order_qty: 0,
            max_price_deviation_bps: 0,
            max_resting_per_account: 1,
        },
    );
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&seller, 1_000_000_000);
    server.fund_account(&buyer, 1_000_000_000_000);

    // Maker rests — its slot is taken (a second resting order
    // would exceed the cap of 1).
    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    assert!(!server.submit_order(&maker).rejected);
    assert_eq!(server.risk.resting_count(&seller), 1);
    let blocked = signed_req(&seller_sk, 0, Side::Sell, 1, 1_500_000_000, 1_000);
    assert_eq!(server.submit_order(&blocked).reject_reason, Some(RejectReason::TooManyResting));

    // A taker fills the maker completely — the slot frees and
    // the account can rest again.
    let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
    assert_eq!(server.submit_order(&taker).fills_count, 1);
    assert_eq!(
        server.risk.resting_count(&seller),
        0,
        "a fully filled maker must release its resting slot"
    );
    let again = signed_req(&seller_sk, 0, Side::Sell, 2, 1_500_000_000, 1_000);
    assert!(!server.submit_order(&again).rejected);
}

/// A partially filled maker still rests — it must keep its
/// slot. Only orders that leave the book release one.
#[test]
fn partially_filled_maker_keeps_resting_count() {
    let mut server = MatchingServer::new(cfg(), 100);
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    server.fund_account(&seller, 1_000_000_000);
    server.fund_account(&buyer, 1_000_000_000_000);

    let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 2_000);
    assert!(!server.submit_order(&maker).rejected);
    assert_eq!(server.risk.resting_count(&seller), 1);

    // Fill half — the other half still rests at 1.5e9.
    let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
    assert_eq!(server.submit_order(&taker).fills_count, 1);
    assert_eq!(server.risk.resting_count(&seller), 1, "a surviving maker remainder keeps its slot");
}

/// The worker path shares the accounting: a maker filled away
/// on a `MultiMarketMatcher` must be able to rest again. The
/// maker floods the book to the default 1000-order cap; a
/// single sweep fills them all; the next order must not see
/// `TooManyResting`. The injected clock advances 1001ms between
/// bursts so the 100/sec limiter never engages — this also
/// exercises `MultiMarketMatcher::with_clock`.
#[test]
fn worker_releases_filled_maker_resting_count() {
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let balances = Arc::new(AtomicBalanceCache::new(8));
    balances.set(&seller, 1_000_000_000);
    balances.set(&buyer, u64::MAX / 2);
    let (now, clock) = test_clock();
    // The cap under test is the resting-order ceiling — set it
    // explicitly rather than relying on a default (the production
    // default moved to venue-scale 10k in F-23, which this many
    // orders can't reach).
    let risk = RiskConfig { max_resting_per_account: 1_000, ..RiskConfig::default() };
    let matcher = MultiMarketMatcher::with_options(
        vec![cfg_for(0)],
        balances,
        clock,
        protocol::CHAIN_ID,
        None,
        risk,
        None,
    );

    // 1_000 resting sells = the configured per-account cap. Ten
    // batches of 100 with a full window slide between them stay
    // under any rate limit (the default is unlimited anyway).
    let mut nonce = 0u64;
    for _ in 0..10 {
        let batch: Vec<OrderRequest> = (0..100)
            .map(|_| {
                let req = signed_req(&seller_sk, 0, Side::Sell, nonce, 1_500_000_000, 1_000);
                nonce += 1;
                req
            })
            .collect();
        for resp in matcher.submit_batch(batch) {
            assert!(!resp.rejected, "maker order rejected: {:?}", resp.reject_reason);
        }
        now.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed);
    }
    // The cap is real: one more resting order is rejected.
    now.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed);
    let extra = signed_req(&seller_sk, 0, Side::Sell, nonce, 1_500_000_000, 1_000);
    nonce += 1;
    let resp = matcher.submit_batch(vec![extra]);
    assert_eq!(resp[0].reject_reason, Some(RejectReason::TooManyResting));

    // One taker sweeps all 1_000 makers (1_000 × 1_000 qty).
    now.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed);
    let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000_000);
    let resp = matcher.submit_batch(vec![taker]);
    assert_eq!(resp[0].fills_count, 1_000);

    // Every slot released: the maker rests again instead of
    // hitting the phantom cap.
    now.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed);
    let again = signed_req(&seller_sk, 0, Side::Sell, nonce, 1_500_000_000, 1_000);
    let resp = matcher.submit_batch(vec![again]);
    assert!(
        !resp[0].rejected,
        "maker must rest again after the sweep freed its slots, got {:?}",
        resp[0].reject_reason
    );
}

/// Regression: the chain ID is the signature domain — an order
/// signed for chain A must not replay on chain B. The server
/// verifies against its CONFIGURED chain ID, not a hardcoded
/// constant.
#[test]
fn order_signed_for_other_chain_rejected() {
    let mut server = MatchingServer::new(cfg(), 100);
    server.set_chain_id(42);
    let (trader_sk, trader) = test_account(5);
    server.fund_account(&trader, 1_000_000_000);

    // Signed under the devnet default (1): verifies as a forgery
    // on chain 42 — exactly the cross-chain replay boundary.
    let req = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    let resp = server.submit_order(&req);
    assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));

    // The same request re-signed for chain 42 verifies and rests.
    // (The BadSignature rejection never consumed the nonce.)
    let mut req2 = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    crate::protocol::sign_order_with_chain_id(&mut req2, &trader_sk, 42);
    let resp2 = server.submit_order(&req2);
    assert!(
        !resp2.rejected,
        "order signed for the server's chain must verify, got {:?}",
        resp2.reject_reason
    );
}

/// The worker path shares the domain: a `MultiMarketMatcher`
/// configured for chain 42 must reject devnet-signed orders and
/// accept chain-42 signatures.
#[test]
fn worker_verifies_configured_chain_id() {
    let (trader_sk, trader) = test_account(5);
    let balances = Arc::new(AtomicBalanceCache::new(8));
    balances.set(&trader, 1_000_000_000);
    let matcher = MultiMarketMatcher::with_options(
        vec![cfg_for(0)],
        balances,
        Arc::new(wall_clock_ms),
        42,
        None,
        RiskConfig::default(),
        None,
    );

    let bad = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    let resp = matcher.submit_batch(vec![bad]);
    assert_eq!(resp[0].reject_reason, Some(RejectReason::BadSignature));

    let mut good = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    crate::protocol::sign_order_with_chain_id(&mut good, &trader_sk, 42);
    let resp = matcher.submit_batch(vec![good]);
    assert!(
        !resp[0].rejected,
        "chain-42 order must verify on the chain-42 worker, got {:?}",
        resp[0].reject_reason
    );
}

/// Regression: without a durable checkpoint, every restart
/// forgot all consumed nonces — a captured signed order became
/// replayable once per restart, forever. `set_nonce_store`
/// bounds the window to the checkpoint interval.
#[test]
fn nonce_store_survives_restart() {
    let dir = std::env::temp_dir().join(format!("oxnc-test-{}", std::process::id()));
    let path = dir.join("nonces.oxnc");
    std::fs::create_dir_all(&dir).unwrap_or_default();
    let (trader_sk, trader) = test_account(6);
    {
        let mut server = MatchingServer::new(cfg(), 100);
        server.set_nonce_store(path.clone());
        server.fund_account(&trader, 1_000_000_000);
        let req = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        assert!(!server.submit_order(&req).rejected);
        // Checkpoint via the seal-cadence flush (the 64-mutation
        // amortized flush has not been reached).
        server.seal_batch();
    }

    // "Restart": a fresh server over the same checkpoint must
    // still reject the replayed nonce — before the store, this
    // was accepted because the gate restarted empty.
    let mut server2 = MatchingServer::new(cfg(), 100);
    server2.set_nonce_store(path.clone());
    server2.fund_account(&trader, 1_000_000_000);
    let replay = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
    let resp = server2.submit_order(&replay);
    assert_eq!(
        resp.reject_reason,
        Some(RejectReason::StaleNonce),
        "consumed nonce must stay consumed across restart"
    );
    // And a genuinely new nonce still works.
    let fresh = signed_req(&trader_sk, 0, Side::Sell, 1, 1_500_000_000, 1_000);
    assert!(!server2.submit_order(&fresh).rejected);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A corrupt checkpoint must fail closed at startup — the
/// alternative (silently resetting the gate) reopens the replay
/// window for every captured signature.
#[test]
fn corrupt_nonce_store_fails_closed() {
    let dir = std::env::temp_dir().join(format!("oxnc-bad-{}", std::process::id()));
    let path = dir.join("bad.oxnc");
    std::fs::create_dir_all(&dir).unwrap_or_default();
    std::fs::write(&path, b"definitely-not-a-checkpoint").unwrap_or_default();
    let result = std::panic::catch_unwind(|| {
        let mut tracker = NonceTracker::new();
        tracker.attach_store(path.clone());
    });
    assert!(result.is_err(), "corrupt nonce store must panic, not reset the gate");
    let _ = std::fs::remove_dir_all(&dir);
}

/// hft-audit-2 M-1: admission never touches the disk. Consuming
/// thousands of nonces stays on the in-memory path (the writer
/// thread does the I/O), and once `sync_durable` returns, a crash
/// (state read straight off disk while the tracker and its writer
/// are still alive, with no clean-shutdown checkpoint) still holds
/// every consumed nonce, including the partial buffer below the
/// 64-admission hand-off.
#[test]
fn nonce_durability_survives_crash_after_sync() {
    let dir = std::env::temp_dir().join(format!("oxnc-m1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_default();
    let path = dir.join("nonces.oxnc");
    let mut tracker = NonceTracker::new();
    tracker.attach_store(path.clone());
    // 1000 owners × 3 nonces = 3000 admissions: 46 full hand-offs
    // plus a partial buffer of 56 that only `sync_durable` hands off.
    for n in 1..=3u64 {
        for o in 0..1000u32 {
            let mut a = [0u8; 20];
            a[..4].copy_from_slice(&o.to_le_bytes());
            assert!(tracker.check_and_consume(&primitives::Address(a), n));
        }
    }
    tracker.sync_durable();
    let on_disk = crate::nonce_wal::recover(&path).expect("recover");
    assert_eq!(on_disk.len(), 1000);
    assert!(on_disk.values().all(|&n| n == 3), "every owner's last nonce must be durable");
    // A tracker restarted over the same files rejects every replay.
    drop(tracker);
    let mut restarted = NonceTracker::new();
    restarted.attach_store(path.clone());
    let mut a = [0u8; 20];
    a[..4].copy_from_slice(&999u32.to_le_bytes());
    assert!(!restarted.check_and_consume(&primitives::Address(a), 3));
    assert!(restarted.check_and_consume(&primitives::Address(a), 4));
    drop(restarted);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two fills between the same registered order pair at the same
/// price merge into ONE chain leg — `floor(price × Σqty / SCALE)`,
/// not `Σ floor(price × qty_i / SCALE)`. The marginal-cost
/// accumulator must telescope to the merged value exactly: each
/// fill contributes the delta in the leg's floored total.
#[test]
fn leg_cost_acc_telescopes_to_merged_floor() {
    let mut acc = LegCostAcc::default();
    let (buyer, seller) = (addr(1), addr(9));
    // price 60_000_000 (0.6 quote/lot, scale-8), qty 1+1
    // (scale-6): per-fill floors are 0 and 0 — sum 0. The
    // merged leg floors 60_000_000 × 2 / 1e8 = 1.2 → 1, so the
    // second fill's marginal must carry the whole unit.
    let leg = LegId {
        market: 0,
        price: 60_000_000,
        buyer: buyer.0,
        buyer_id: 1,
        seller: seller.0,
        seller_id: 2,
    };
    let m1 = acc.add(leg, 1);
    let m2 = acc.add(leg, 1);
    assert_eq!((m1, m2), (0, 1), "marginals telescope to the merged floor");
    assert_eq!(m1 + m2, 60_000_000u64 * 2 / 100_000_000);
    // A third fill lifts the merged floor again — marginals
    // keep tracking the running total, not per-fill floors.
    let m3 = acc.add(leg, 1);
    assert_eq!(m1 + m2 + m3, 60_000_000u64 * 3 / 100_000_000);
    // A different price forms a different leg — no cross-talk
    // between keys.
    let other = acc.add(LegId { price: 100_000_000, ..leg }, 1);
    assert_eq!(other, 1, "distinct legs floor independently");
}

/// `seal_batch` is the leg-formation boundary — the accumulator
/// must reset with the drained batch or the NEXT batch's
/// marginals would keep accumulating into legs that no longer
/// exist on-chain.
#[test]
fn seal_batch_resets_leg_cost_accumulator() {
    let mut server = MatchingServer::new(cfg(), 100);
    server.cost_acc.add(
        LegId {
            market: 0,
            price: 60_000_000,
            buyer: addr(1).0,
            buyer_id: 1,
            seller: addr(9).0,
            seller_id: 2,
        },
        1,
    );
    assert!(!server.cost_acc.legs.is_empty());
    let _ = server.seal_batch();
    assert!(server.cost_acc.legs.is_empty(), "seal must reset the accumulator");
}
