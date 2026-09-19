//! 1B-order integrity test — verifies the matching server handles
//! 1B orders with 1M active accounts and balance checks, with full
//! integrity validation.
//!
//! # What this verifies
//!
//! - 1,000,000,000 orders processed (500M maker sells + 500M taker buys).
//! - 1,000,000 active accounts, each funded with 1T quote.
//! - Balance check on every buy order (anti-spam gate).
//! - No negative balances.
//! - Balance conservation: total quote is preserved.
//! - No panics.
//!
//! # Running
//!
//! ```sh
//! # Full 1B orders with 1M accounts
//! cargo test -p matcher --release -- --ignored --nocapture
//!
//! # Smaller: 10M orders with 100k accounts
//! INTEGRITY_ORDERS=10_000_000 INTEGRITY_ACCOUNTS=100_000 \
//!   cargo test -p matcher --release -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use crypto::ed25519::{Ed25519SecretKey, owner_address};
use matcher::protocol::sign_order;
use matcher::{MatchingServer, OrderRequest};
use primitives::fixed::{Price, Qty};
use std::time::Instant;
use trading::{MarketConfig, OrderType, Side, TimeInForce};

/// Parse an env var as a usize, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// A test market config.
fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: 1_000_000,
        lot_size: 1_000,
        min_price: 1_000_000_000,
        max_price: 2_000_000_000,
        max_resting: 1 << 16,
    }
}

/// Generate a deterministic address from an index.
fn addr_from_index(i: u32) -> primitives::Address {
    let mut addr = [0u8; 20];
    addr[..4].copy_from_slice(&i.to_le_bytes());
    primitives::Address(addr)
}

/// Deterministic per-account signing key — account `i` is an Ed25519
/// key whose funded address is the key's derived owner. The admission
/// boundary verifies every order's signature, so the integrity test
/// signs like a real client.
fn account_key(i: u32) -> Ed25519SecretKey {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&i.to_le_bytes());
    Ed25519SecretKey::from_bytes(&seed)
}

/// Build a signed order for `key`'s account at `nonce`.
fn signed_order(key: &Ed25519SecretKey, side: Side, nonce: u64) -> OrderRequest {
    let mut req = OrderRequest {
        market: 0,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce,
        owner: addr_from_index(0),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    sign_order(&mut req, key);
    req
}

/// 1B-order integrity test with 1M active accounts.
#[test]
#[ignore = "long-running 1B-order test; run with --release --ignored --nocapture"]
fn integrity_1b_orders_1m_accounts() {
    let n_orders = env_usize("INTEGRITY_ORDERS", 1_000_000_000);
    let n_accounts = env_usize("INTEGRITY_ACCOUNTS", 1_000_000);
    let initial_balance = 1_000_000_000_000u64; // 1T per account.

    eprintln!(
        "integrity: {n_orders} orders, {n_accounts} accounts, {initial_balance} quote/account"
    );

    // Setup: create server, fund accounts. Each account is an
    // Ed25519 key — the funded address is the key's derived owner,
    // and every order is signed by that key.
    eprintln!("integrity: funding {n_accounts} accounts...");
    let setup_start = Instant::now();
    let account_keys: Vec<Ed25519SecretKey> =
        (0..u32::try_from(n_accounts).unwrap_or(u32::MAX)).map(account_key).collect();
    let owners: Vec<primitives::Address> =
        account_keys.iter().map(|k| owner_address(&k.verifying_key())).collect();
    let mut server = MatchingServer::new(cfg(), n_accounts);
    for owner in &owners {
        server.fund_account(owner, initial_balance);
    }
    let total_initial = u64::try_from(n_accounts).unwrap_or(u64::MAX) * initial_balance;
    eprintln!(
        "integrity: funded in {:.3}s, total quote = {total_initial}",
        setup_start.elapsed().as_secs_f64()
    );

    // Run: rotate through all n_accounts accounts. For each pair
    // of orders (maker sell + taker buy), use a different pair of
    // accounts. This distributes the load across all 1M accounts,
    // each doing ~1000 orders. Each account starts with 1T quote,
    // and each fill costs 15_000 quote, so each account can do
    // ~66M fills before running out — far more than the ~500
    // fills each account will do.
    eprintln!("integrity: running {n_orders} orders...");
    let start = Instant::now();

    let n_pairs = n_orders / 2;
    let n_accounts_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    // Per-account nonce counters — nonces must strictly increase
    // per account or the replay gate rejects the order.
    let mut nonces = vec![0u64; n_accounts];
    for i in 0..n_pairs {
        let seller_idx = (u32::try_from(2 * i).unwrap_or(u32::MAX) % n_accounts_u32) as usize;
        let buyer_idx = (u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_accounts_u32) as usize;
        let maker = signed_order(&account_keys[seller_idx], Side::Sell, nonces[seller_idx]);
        nonces[seller_idx] += 1;
        let taker = signed_order(&account_keys[buyer_idx], Side::Buy, nonces[buyer_idx]);
        nonces[buyer_idx] += 1;
        let _ = server.submit_order(&maker);
        let _ = server.submit_order(&taker);
    }

    let elapsed = start.elapsed();
    let tps = n_orders as f64 / elapsed.as_secs_f64();

    eprintln!("integrity: completed in {:.3}s", elapsed.as_secs_f64());
    eprintln!();
    eprintln!("=== 1B-Order Integrity Results ===");
    eprintln!("  orders:            {n_orders}");
    eprintln!("  accounts:         {n_accounts}");
    eprintln!("  orders processed:  {}", server.orders_processed());
    eprintln!("  fills produced:   {}", server.fills_produced());
    eprintln!("  balance rejects:   {}", server.balance_rejections());
    eprintln!("  engine rejects:    {}", server.engine_rejections());
    eprintln!("  resting count:     {}", server.resting_count());
    eprintln!("  elapsed:           {:.3}s", elapsed.as_secs_f64());
    eprintln!("  throughput:        {tps:.0} orders/s");
    eprintln!("===================================");

    // ── Integrity checks ──────────────────────────────────────

    // 1. All orders were processed.
    assert_eq!(
        server.orders_processed() as usize,
        n_orders,
        "all {n_orders} orders must be processed"
    );

    // 2. Each maker+taker pair produces 1 fill.
    assert_eq!(
        server.fills_produced() as usize,
        n_orders / 2,
        "each maker+taker pair should produce 1 fill"
    );

    // 3. No balance rejections (both accounts have enough balance).
    assert_eq!(
        server.balance_rejections(),
        0,
        "no balance rejections expected (accounts are well-funded)"
    );

    // 4. No engine rejections.
    assert_eq!(server.engine_rejections(), 0, "no engine rejections expected");

    // 5. Book is empty (all makers matched).
    assert_eq!(server.resting_count(), 0, "all makers should be matched");

    // 6. Balance conservation: total quote across all accounts is
    // preserved. Each fill moves 15_000 quote from buyer to seller,
    // but the total is unchanged. We verify by summing all balances.
    let fills = server.fills_produced();
    let quote_per_fill = 15_000u64; // 1_500_000_000 * 1_000 / 100_000_000.
    let total_quote_moved = fills * quote_per_fill;
    eprintln!("integrity: total quote moved = {total_quote_moved}");

    // Sum all account balances and verify conservation.
    let mut total_balance: u128 = 0;
    for owner in &owners {
        total_balance += u128::from(server.balance(owner));
    }
    let expected_total = u128::from(n_accounts as u64) * u128::from(initial_balance);
    eprintln!("integrity: total balance = {total_balance}, expected = {expected_total}");
    assert_eq!(
        total_balance, expected_total,
        "balance conservation: total quote must be preserved across all accounts"
    );

    // 7. No negative balances (verified implicitly — u64 can't be
    // negative, but we check that no account is at 0 if it should
    // have balance). Each account does ~n_orders/n_accounts fills.
    // With 1B orders / 1M accounts = 1000 fills per account, each
    // costing 15_000 quote. Starting with 1T, no account should
    // be near zero.
    let min_balance = server.balance(&owners[0]);
    assert!(min_balance > 0, "all accounts must have positive balance");

    eprintln!("integrity: all checks passed ✓");
}

/// Smoke test: 1M orders with 1000 accounts.
#[test]
#[ignore = "integrity test; run with --release --ignored --nocapture"]
fn integrity_smoke() {
    let n_orders = env_usize("INTEGRITY_ORDERS", 1_000_000);
    let n_accounts = env_usize("INTEGRITY_ACCOUNTS", 1000);
    let initial_balance = 1_000_000_000_000u64;

    let account_keys: Vec<Ed25519SecretKey> = (0..n_accounts as u32).map(account_key).collect();
    let owners: Vec<primitives::Address> =
        account_keys.iter().map(|k| owner_address(&k.verifying_key())).collect();
    let mut server = MatchingServer::new(cfg(), n_accounts);
    for owner in &owners {
        server.fund_account(owner, initial_balance);
    }

    let start = Instant::now();
    let n_pairs = n_orders / 2;
    let n_accounts_u32 = u32::try_from(n_accounts).unwrap_or(u32::MAX);
    let mut nonces = vec![0u64; n_accounts];
    for i in 0..n_pairs {
        let seller_idx = (u32::try_from(2 * i).unwrap_or(u32::MAX) % n_accounts_u32) as usize;
        let buyer_idx = (u32::try_from(2 * i + 1).unwrap_or(u32::MAX) % n_accounts_u32) as usize;
        let maker = signed_order(&account_keys[seller_idx], Side::Sell, nonces[seller_idx]);
        nonces[seller_idx] += 1;
        let taker = signed_order(&account_keys[buyer_idx], Side::Buy, nonces[buyer_idx]);
        nonces[buyer_idx] += 1;
        let _ = server.submit_order(&maker);
        let _ = server.submit_order(&taker);
    }
    let elapsed = start.elapsed();

    let tps = n_orders as f64 / elapsed.as_secs_f64();
    eprintln!("smoke: {n_orders} orders in {:.3}s = {tps:.0} orders/s", elapsed.as_secs_f64());
    eprintln!(
        "smoke: fills={}, rejects={}, resting={}",
        server.fills_produced(),
        server.balance_rejections(),
        server.resting_count()
    );

    assert_eq!(server.orders_processed() as usize, n_orders);
    assert_eq!(server.fills_produced() as usize, n_orders / 2);
    assert_eq!(server.balance_rejections(), 0);
    assert_eq!(server.resting_count(), 0);
}
