//! End-to-end multi-market parallel matcher test.
//!
//! Verifies that the multi-market parallel matcher:
//! - Routes orders to the correct market by `OrderRequest.market`.
//! - Maintains independent books per market (no cross-market matching).
//! - Preserves balance invariants across shared sharded balances.
//! - Aggregates fills and stats correctly across all market workers.
//! - Handles mixed-market batches (the slow path) correctly.
//!
//! # Running
//!
//! ```sh
//! cargo test -p matcher --release --test e2e_multi_market -- --nocapture
//! ```

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use crypto::ed25519::{Ed25519SecretKey, owner_address};
use matcher::protocol::{OrderRequest, sign_order};
use matcher::{AtomicBalanceCache, MultiMarketMatcher};
use primitives::fixed::{Price, Qty};
use std::sync::Arc;
use trading::{MarketConfig, OrderType, Side, TimeInForce};

fn cfg_for(market_id: u8) -> MarketConfig {
    MarketConfig {
        market_id: u16::from(market_id),
        tick_size: 1_000_000,
        lot_size: 1_000,
        min_price: 1_000_000_000,
        max_price: 2_000_000_000,
        max_resting: 1 << 16,
    }
}

/// A deterministic test account: `seed` derives the Ed25519 signing
/// key; the account address is the key's derived owner. Every order
/// must authenticate — the admission boundary verifies
/// `owner == owner_address(pubkey)` and the signature.
fn test_account(seed: u8) -> (Ed25519SecretKey, primitives::Address) {
    let secret = Ed25519SecretKey::from_bytes(&[seed; 32]);
    let owner = owner_address(&secret.verifying_key());
    (secret, owner)
}

/// Build a signed order for `secret`'s account. Nonces are
/// per-ACCOUNT across all markets (the workers share one
/// `NonceTracker`), so the caller threads an increasing nonce per
/// account through the whole test.
fn make_order(
    secret: &Ed25519SecretKey,
    market: u8,
    side: Side,
    nonce: u64,
    price: u64,
) -> OrderRequest {
    let mut req = OrderRequest {
        market,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(price),
        qty: Qty(1_000),
        nonce,
        owner: primitives::Address([0; 20]),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    sign_order(&mut req, secret);
    req
}

/// Set up a matcher with `n_markets` markets and two funded accounts.
/// Returns the account keys — the caller funds the DERIVED owner
/// addresses, not arbitrary bytes.
fn setup(n_markets: u8) -> (MultiMarketMatcher, Arc<AtomicBalanceCache>) {
    let (_seller_sk, seller) = test_account(9);
    let (_buyer_sk, buyer) = test_account(1);
    let balances = Arc::new(AtomicBalanceCache::new(8));
    balances.set(&seller, 1_000_000_000_000);
    balances.set(&buyer, 1_000_000_000_000);
    let configs: Vec<MarketConfig> = (0..n_markets).map(cfg_for).collect();
    let matcher = MultiMarketMatcher::new(configs, Arc::clone(&balances));
    (matcher, balances)
}

#[test]
fn multi_market_e2e_basic_match_per_market() {
    // 4 markets, each gets a maker sell + taker buy at a different
    // price. Each market should produce exactly 1 fill.
    let (matcher, _balances) = setup(4);
    let (seller_sk, _seller) = test_account(9);
    let (buyer_sk, _buyer) = test_account(1);

    for m in 0..4u8 {
        let price = 1_500_000_000 + u64::from(m) * 10_000_000;
        // Per-account nonces increase across markets.
        let maker = make_order(&seller_sk, m, Side::Sell, u64::from(m), price);
        let taker = make_order(&buyer_sk, m, Side::Buy, u64::from(m), price);
        let responses = matcher.submit_batch(vec![maker, taker]);
        assert_eq!(responses.len(), 2);
        assert!(!responses[0].rejected, "maker should rest");
        assert_eq!(responses[1].fills_count, 1, "taker on market {m} should fill");
    }

    let fills = matcher.seal_batch();
    assert_eq!(fills.len(), 4, "one fill per market");

    let stats = matcher.stats();
    assert_eq!(stats.orders_processed, 8);
    assert_eq!(stats.fills_produced, 4);
}

#[test]
fn multi_market_e2e_no_cross_market_matching() {
    // Rest a maker sell on market 0 at $15. Submit a taker buy on
    // market 1 at $15. They should NOT match — different books.
    let (matcher, _balances) = setup(2);
    let (seller_sk, _seller) = test_account(9);
    let (buyer_sk, _buyer) = test_account(1);

    let maker0 = make_order(&seller_sk, 0, Side::Sell, 0, 1_500_000_000);
    matcher.submit_batch(vec![maker0]);

    let taker1 = make_order(&buyer_sk, 1, Side::Buy, 0, 1_500_000_000);
    let responses = matcher.submit_batch(vec![taker1]);
    // The taker on market 1 should rest (no maker on market 1).
    assert!(!responses[0].rejected, "taker on empty market 1 should rest, not reject");
    assert_eq!(
        responses[0].fills_count, 0,
        "no cross-market matching: market 1 taker must not match market 0 maker"
    );

    let fills = matcher.seal_batch();
    assert_eq!(fills.len(), 0, "no fills — orders on different markets");
}

#[test]
fn multi_market_e2e_mixed_batch_slow_path() {
    // Submit a single batch containing orders for multiple markets.
    // This exercises the slow path (split by market, re-sort).
    let (matcher, _balances) = setup(3);
    let (seller_sk, _seller) = test_account(9);
    let (buyer_sk, _buyer) = test_account(1);

    // Build a mixed batch: maker on 0, maker on 1, taker on 0, taker
    // on 1. Seller nonces 0-1, buyer nonces 0-1 (per-account).
    let orders = vec![
        make_order(&seller_sk, 0, Side::Sell, 0, 1_500_000_000),
        make_order(&seller_sk, 1, Side::Sell, 1, 1_600_000_000),
        make_order(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000),
        make_order(&buyer_sk, 1, Side::Buy, 1, 1_600_000_000),
    ];
    let responses = matcher.submit_batch(orders);
    assert_eq!(responses.len(), 4);
    // Responses should be in the original order.
    // Index 0: maker on 0 — rests.
    assert!(!responses[0].rejected);
    assert_eq!(responses[0].fills_count, 0);
    // Index 1: maker on 1 — rests.
    assert!(!responses[1].rejected);
    assert_eq!(responses[1].fills_count, 0);
    // Index 2: taker on 0 — fills against maker on 0.
    assert_eq!(responses[2].fills_count, 1);
    // Index 3: taker on 1 — fills against maker on 1.
    assert_eq!(responses[3].fills_count, 1);

    let fills = matcher.seal_batch();
    assert_eq!(fills.len(), 2);
}

#[test]
fn multi_market_e2e_balance_conservation() {
    // Total balance (buyer + seller) should be conserved across all
    // fills. Verify by checking the sum before and after.
    let (matcher, balances) = setup(2);
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);

    let seller_before = balances.get(&seller);
    let buyer_before = balances.get(&buyer);

    // Trade on both markets (per-account nonces 0-1).
    for m in 0..2u8 {
        let price = 1_500_000_000 + u64::from(m) * 100_000_000;
        let maker = make_order(&seller_sk, m, Side::Sell, u64::from(m), price);
        let taker = make_order(&buyer_sk, m, Side::Buy, u64::from(m), price);
        matcher.submit_batch(vec![maker, taker]);
    }

    let _fills = matcher.seal_batch();

    let seller_after = balances.get(&seller);
    let buyer_after = balances.get(&buyer);

    // Conservation: seller gain = buyer loss.
    let seller_gain = seller_after - seller_before;
    let buyer_loss = buyer_before - buyer_after;
    assert_eq!(seller_gain, buyer_loss, "balance conservation: seller gain must equal buyer loss");
    assert!(seller_gain > 0, "seller should gain from fills");
    assert!(buyer_loss > 0, "buyer should lose from fills");
}

#[test]
fn multi_market_e2e_128_markets_stress() {
    // Stress test: 128 markets, each with a maker + taker. Verify
    // all 128 markets produce exactly 1 fill each.
    let n_markets = 128u8;
    let (matcher, _balances) = setup(n_markets);
    let (seller_sk, _seller) = test_account(9);
    let (buyer_sk, _buyer) = test_account(1);

    for m in 0..n_markets {
        let price = 1_000_000_000 + u64::from(m) * 1_000_000;
        let maker = make_order(&seller_sk, m, Side::Sell, u64::from(m), price);
        let taker = make_order(&buyer_sk, m, Side::Buy, u64::from(m), price);
        let responses = matcher.submit_batch(vec![maker, taker]);
        assert_eq!(responses[1].fills_count, 1, "market {m} should produce exactly 1 fill");
    }

    let fills = matcher.seal_batch();
    assert_eq!(fills.len() as u64, u64::from(n_markets));

    let stats = matcher.stats();
    assert_eq!(stats.orders_processed, 2 * u64::from(n_markets));
    assert_eq!(stats.fills_produced, u64::from(n_markets));
}

#[test]
fn multi_market_e2e_rejection_does_not_block_other_markets() {
    // If one market rejects (e.g. insufficient balance), other
    // markets should still process normally.
    let (seller_sk, seller) = test_account(9);
    let (broke_sk, broke_buyer) = test_account(1);
    let (funded_sk, funded_buyer) = test_account(2);
    let balances = Arc::new(AtomicBalanceCache::new(8));
    balances.set(&seller, 1_000_000_000_000);
    balances.set(&broke_buyer, 0); // Buyer 1: NO balance.
    balances.set(&funded_buyer, 1_000_000_000_000); // Buyer 2: funded.
    let configs: Vec<MarketConfig> = (0..2).map(cfg_for).collect();
    let matcher = MultiMarketMatcher::new(configs, Arc::clone(&balances));

    // Rest makers on both markets (seller nonces 0, 1).
    let maker0 = make_order(&seller_sk, 0, Side::Sell, 0, 1_500_000_000);
    let maker1 = make_order(&seller_sk, 1, Side::Sell, 1, 1_500_000_000);
    matcher.submit_batch(vec![maker0]);
    matcher.submit_batch(vec![maker1]);

    // Buyer 1 (no balance) tries market 0 — should reject.
    let taker0_broke = make_order(&broke_sk, 0, Side::Buy, 0, 1_500_000_000);
    let resp0 = matcher.submit_batch(vec![taker0_broke]);
    assert!(resp0[0].rejected, "broke buyer should be rejected");

    // Buyer 2 (funded) tries market 1 — should fill.
    let taker1_funded = make_order(&funded_sk, 1, Side::Buy, 0, 1_500_000_000);
    let resp1 = matcher.submit_batch(vec![taker1_funded]);
    assert!(!resp1[0].rejected, "funded buyer should not be rejected");
    assert_eq!(resp1[0].fills_count, 1, "funded buyer should fill on market 1");

    let fills = matcher.seal_batch();
    assert_eq!(fills.len(), 1, "only one fill (market 1)");
}
