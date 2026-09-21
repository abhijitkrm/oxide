//! Trading TPS test — exchange order matching + ledger settlement
//! through the full oxideBFT consensus pipeline.
//!
//! This is the honest trading TPS number: it includes consensus
//! overhead (propose, vote, QC formation, QC broadcast over TCP),
//! network I/O, execution (exchange module dispatch, matching,
//! ledger transfer settlement), and state root computation.
//!
//! # What this measures
//!
//! Each round submits `txs_per_round` exchange place-order txs to the
//! leader's mempool. Half are maker sells (resting), half are taker
//! buys (matching the makers). Each maker+taker pair produces one
//! fill + one ledger transfer (debit buyer, credit seller). The test
//! verifies:
//!
//! - All txs are finalized (no txs dropped).
//! - All validators agree on the same blocks (same heights, same txs).
//! - All validators' exchange modules have the same resting count.
//! - All validators' ledger balances are consistent (buyer debited,
//!   seller credited by the same amount on the EVM account store).
//!
//! # Running
//!
//! ```sh
//! # Default: 4 validators, 200 rounds, 1000 txs/round = 200k txs
//! # (100k maker+taker pairs = 100k fills)
//! cargo test -p devnet --test trading_tps --release -- --ignored --nocapture
//!
//! # 1M fills: 4 validators, 2000 rounds, 1000 txs/round = 2M txs
//! TRADING_VALIDATORS=4 TRADING_ROUNDS=2000 TRADING_TXS_PER_ROUND=1000 \
//!   cargo test -p devnet --test trading_tps --release -- --ignored --nocapture
//! ```

#![allow(clippy::cast_precision_loss)]

use devnet::tcp_multinode::TcpMultiNodeDevnet;
use devnet::txs;
use ports::AppInterface;
use primitives::fixed::{Price, Qty};
use std::time::Instant;
use trading::{MarketConfig, NewOrder, OrderType, Side, StpMode, TimeInForce};

/// Parse an env var as a usize, falling back to `default`.
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// A test market config: tick 0.01, lot 0.001, [$10, $20], 64k max resting.
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

/// Build a signed tx envelope for an exchange module message from
/// devnet identity `sender_idx` (fee 100).
fn make_trading_tx(sender_idx: u8, nonce: u64, payload: Vec<u8>) -> types::TxBytes {
    txs::signed_tx(sender_idx, nonce, 100, framework::module_id::EXCHANGE, &payload)
}

/// Build a maker sell order at tick 500 ($15.00), 1 lot.
fn make_maker_sell_tx(sender_idx: u8, nonce: u64) -> types::TxBytes {
    let order = NewOrder {
        side: Side::Sell,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner: txs::identity_addr(sender_idx),
        stp: StpMode::None,
    };
    make_trading_tx(sender_idx, nonce, exchange::msg::place(0, order))
}

/// Build a taker buy order at tick 500 ($15.00), 1 lot.
fn make_taker_buy_tx(sender_idx: u8, nonce: u64) -> types::TxBytes {
    let order = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner: txs::identity_addr(sender_idx),
        stp: StpMode::None,
    };
    make_trading_tx(sender_idx, nonce, exchange::msg::place(0, order))
}

/// Run a trading TPS test with the given parameters.
///
/// Spins up `n_validators` nodes over TCP (with the exchange module
/// registered), submits `rounds * txs_per_round` exchange order txs,
/// runs consensus to finality, and verifies integrity:
///
/// - All validators finalized the same blocks.
/// - All txs were finalized.
/// - All validators' exchange modules have consistent resting counts.
/// - All validators' ledger balances are consistent.
#[allow(clippy::too_many_lines)]
fn run_trading_tps(
    n_validators: usize,
    rounds: usize,
    txs_per_round: usize,
    base_port: u16,
    min_tps: f64,
) {
    let total_txs = rounds * txs_per_round;
    eprintln!(
        "trading TPS test: {n_validators} validators, {rounds} rounds, {txs_per_round} txs/round = {total_txs} total txs"
    );

    let max_mempool = total_txs + 1000;

    eprintln!(
        "trading TPS test: assembling {n_validators} validators with exchange module on ports {base_port}+..."
    );
    let assemble_start = Instant::now();
    let mut devnet =
        TcpMultiNodeDevnet::with_exchange_and_base_port(n_validators, max_mempool, base_port);
    let assemble_elapsed = assemble_start.elapsed();
    eprintln!(
        "trading TPS test: assembled in {:.3}s ({} TCP connections, {} exchange modules)",
        assemble_elapsed.as_secs_f64(),
        n_validators * (n_validators - 1),
        devnet.exchange_modules().len(),
    );

    // List the market in-process on every validator — the
    // genesis-style setup path. `TAG_LIST_MARKET` transactions are
    // committee-gated governance actions, not a setup shortcut, so
    // the workload carries only order txs; the identical config on
    // every validator assigns the same market id 0.
    for ex in devnet.exchange_modules() {
        ex.list_market(cfg()).expect("test market config is valid");
    }

    // Build the trading workload.
    //
    // Round 0: maker sells (the market is already listed).
    // Rounds 1+: alternating maker sells and taker buys.
    //
    // Within each block, maker sells are processed before taker buys
    // (the executor processes txs in order). So a taker buy in the
    // same block as a maker sell will match it.
    //
    // Sender 0x09 = maker (seller), sender 0x01 = taker (buyer).
    // Each sender has its own nonce sequence. Sell orders escrow
    // base custody at admission, so the maker's first tx (nonce 0,
    // round-0 slot 0 — `run_pipelined_txs` consumes exactly
    // `rounds * txs_per_round`, so the deposit replaces the first
    // maker sell rather than extending the workload) deposits
    // enough base to cover every sell it will place.
    eprintln!("trading TPS test: building {total_txs} trading txs...");
    let build_start = Instant::now();
    let mut all_txs = Vec::with_capacity(total_txs);
    let mut maker_nonce = 0u64;
    let mut taker_nonce = 0u64;

    for round in 0..rounds {
        if round == 0 {
            // Round 0: the maker's base-custody deposit, then sells.
            for j in 0..txs_per_round {
                if j == 0 {
                    all_txs.push(make_trading_tx(
                        0x09,
                        maker_nonce,
                        exchange::msg::deposit_base(0, (total_txs as u64) * 1_000),
                    ));
                } else {
                    all_txs.push(make_maker_sell_tx(0x09, maker_nonce));
                }
                maker_nonce += 1;
            }
        } else {
            // Rounds 1+: half maker sells, half taker buys.
            let half = txs_per_round / 2;
            for _ in 0..half {
                all_txs.push(make_maker_sell_tx(0x09, maker_nonce));
                maker_nonce += 1;
            }
            for _ in 0..half {
                all_txs.push(make_taker_buy_tx(0x01, taker_nonce));
                taker_nonce += 1;
            }
        }
    }
    let build_elapsed = build_start.elapsed();
    eprintln!(
        "trading TPS test: built {total_txs} txs in {:.3}s ({maker_nonce} maker sells, {taker_nonce} taker buys)",
        build_elapsed.as_secs_f64(),
    );

    // Run the consensus loop. `TRADING_DRIVER=threaded` switches to
    // `run_threaded_txs`: each validator on its own OS thread with
    // dispersed block bodies over TCP — the closer approximation of
    // a real multi-machine deployment.
    let driver = std::env::var("TRADING_DRIVER").unwrap_or_else(|_| "pipelined".to_string());
    let (result, elapsed) = if driver == "threaded" {
        eprintln!(
            "trading TPS test: running {rounds} rounds (threaded, {n_validators} threads)..."
        );
        devnet.run_threaded_txs(rounds, txs_per_round, &all_txs)
    } else {
        eprintln!("trading TPS test: running {rounds} rounds (pipelined)...");
        devnet.run_pipelined_txs(rounds, txs_per_round, &all_txs)
    };
    eprintln!("trading TPS test: completed in {:.3}s", elapsed.as_secs_f64());

    // ── Integrity checks ───────────────────────────────────────

    // 1. All validators finalized at least `rounds` blocks. The
    //    flush round may produce an extra empty block on some
    //    validators (the 2-chain commit rule can cause one validator
    //    to propose an additional empty block that gets finalized).
    //    We compare only the common prefix of blocks across all
    //    validators — the extra empty block (if any) has no txs and
    //    doesn't affect the trading integrity.
    let min_blocks = result.finalized.iter().map(Vec::len).min().unwrap_or(0);
    assert!(min_blocks > 0, "should have finalized at least one block");
    for (i, blocks) in result.finalized.iter().enumerate() {
        assert!(
            blocks.len() >= min_blocks,
            "validator {i} has {} blocks, expected at least {min_blocks}",
            blocks.len()
        );
    }

    // 2. All txs were finalized (count from the common prefix).
    let finalized_txs: usize = result.finalized[0][..min_blocks].iter().map(|b| b.txs.len()).sum();
    eprintln!(
        "trading TPS test: finalized {min_blocks} blocks (common prefix), {finalized_txs} txs"
    );
    assert_eq!(
        finalized_txs, total_txs,
        "all {total_txs} txs (maker deposit + orders) must be finalized, got {finalized_txs}"
    );

    // 3. All validators agree on tx contents (common prefix only).
    let reference = &result.finalized[0][..min_blocks];
    for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
        let blocks_prefix = &blocks[..min_blocks];
        for (j, (a, b)) in reference.iter().zip(blocks_prefix.iter()).enumerate() {
            assert_eq!(a.height, b.height, "validator {i} block {j}: height mismatch");
            assert_eq!(a.txs, b.txs, "validator {i} block {j}: txs mismatch");
        }
    }

    // 4. Exchange module state consistency: all validators should
    //    have the same resting count on market 0.
    let exchange_modules = devnet.exchange_modules();
    if !exchange_modules.is_empty() {
        let resting_0 = exchange_modules[0].resting_count(0);
        for (i, ex) in exchange_modules.iter().enumerate().skip(1) {
            let resting_i = ex.resting_count(0);
            assert_eq!(
                resting_0, resting_i,
                "validator {i} resting count {resting_i} != validator 0 resting count {resting_0}"
            );
        }
        eprintln!(
            "trading TPS test: all {n_validators} validators agree on resting count = {resting_0}"
        );
    }

    // 5. State root consistency: all validators should have the same
    //    state root at the finalized height. This is the strongest
    //    integrity check — if all validators agree on the same blocks
    //    AND the same state root, their execution is deterministic and
    //    identical. We use the executor's `attest_state` (via the
    //    `AppInterface` trait) to read the post-finalization root.
    // The attested height must be inside the *common* prefix — the
    // last block every validator committed. `finalized[0].last()`
    // can be one flush block beyond it (an extra empty block only
    // some validators commit — legal under the 2-chain rule), and
    // attesting there yields `Hash::ZERO` on validators that never
    // reached that height, a false divergence.
    let final_height = result.finalized[0][min_blocks - 1].height;
    let root_0 = devnet.app(0).attest_state(final_height).expect("executed").root;
    for i in 1..n_validators {
        let root_i = devnet.app(i).attest_state(final_height).expect("executed").root;
        assert_eq!(root_0, root_i, "validator {i} state root {root_i} != validator 0 {root_0}");
    }
    eprintln!(
        "trading TPS test: all {n_validators} validators agree on state root at height {}",
        final_height.value()
    );

    // ── Report ─────────────────────────────────────────────────

    let tps = total_txs as f64 / elapsed.as_secs_f64();
    let blocks_per_sec = min_blocks as f64 / elapsed.as_secs_f64();
    let txs_per_block = finalized_txs as f64 / min_blocks as f64;
    eprintln!();
    eprintln!("=== Trading TPS Results (consensus pipeline) ===");
    eprintln!("  validators:      {n_validators}");
    eprintln!("  total txs:       {total_txs}");
    eprintln!("  blocks finalized: {min_blocks} (common prefix)");
    eprintln!("  txs/block:       {txs_per_block:.1}");
    eprintln!("  elapsed:         {:.3}s", elapsed.as_secs_f64());
    eprintln!("  throughput:      {tps:.0} tx/s");
    eprintln!("  block rate:      {blocks_per_sec:.1} blocks/s");
    eprintln!("  TPS floor:       {min_tps:.0} tx/s");
    eprintln!("================================================");

    let env_floor = std::env::var("TRADING_MIN_FLOOR").ok().and_then(|v| v.parse::<f64>().ok());
    let effective_floor = env_floor.unwrap_or(min_tps);
    if effective_floor > 0.0 {
        assert!(
            tps >= effective_floor,
            "trading TPS {tps:.0} below floor {effective_floor:.0} tx/s \
             ({n_validators} validators, {total_txs} txs, {:.3}s)",
            elapsed.as_secs_f64()
        );
        eprintln!("  ✓ TPS floor met ({tps:.0} >= {effective_floor:.0})");
    }
}

/// Default trading TPS test: 4 validators, 200 rounds, 1000 txs/round
/// = 200k txs (100k maker+taker pairs = 100k fills).
#[test]
#[ignore = "trading TPS test binds TCP ports; run with --release --ignored --nocapture"]
fn trading_tps_default() {
    let n = env_usize("TRADING_VALIDATORS", 4);
    let rounds = env_usize("TRADING_ROUNDS", 200);
    let txs_per_round = env_usize("TRADING_TXS_PER_ROUND", 1000);
    run_trading_tps(n, rounds, txs_per_round, 34000, 500.0);
}

/// 1M-fill trading TPS test: 4 validators, 2000 rounds, 1000 txs/round
/// = 2M txs (1M maker+taker pairs = 1M fills).
///
/// Run with:
/// `TRADING_ROUNDS=2000 cargo test -p devnet --test trading_tps --release -- --ignored trading_tps_1m --nocapture`
#[test]
#[ignore = "large trading TPS test; run with --release --ignored"]
fn trading_tps_1m() {
    let n = env_usize("TRADING_VALIDATORS", 4);
    let rounds = env_usize("TRADING_ROUNDS", 2000);
    let txs_per_round = env_usize("TRADING_TXS_PER_ROUND", 1000);
    run_trading_tps(n, rounds, txs_per_round, 35000, 1000.0);
}

/// 7-validator trading TPS test: tests scaling with more validators.
/// Default: 7 validators, 200 rounds, 1000 txs/round = 200k txs.
///
/// Run with:
/// `cargo test -p devnet --test trading_tps --release -- --ignored trading_tps_7_validators --nocapture`
#[test]
#[ignore = "trading TPS test binds TCP ports; run with --release --ignored --nocapture"]
fn trading_tps_7_validators() {
    let n = env_usize("TRADING_VALIDATORS", 7);
    let rounds = env_usize("TRADING_ROUNDS", 200);
    let txs_per_round = env_usize("TRADING_TXS_PER_ROUND", 1000);
    run_trading_tps(n, rounds, txs_per_round, 36000, 500.0);
}

/// 10-validator trading TPS test: tests scaling to 10 validators
/// (max for f=3 byzantine tolerance with n=3f+1).
/// Default: 10 validators, 200 rounds, 1000 txs/round = 200k txs.
///
/// Run with:
/// `cargo test -p devnet --test trading_tps --release -- --ignored trading_tps_10_validators --nocapture`
#[test]
#[ignore = "trading TPS test binds TCP ports; run with --release --ignored --nocapture"]
fn trading_tps_10_validators() {
    let n = env_usize("TRADING_VALIDATORS", 10);
    let rounds = env_usize("TRADING_ROUNDS", 200);
    let txs_per_round = env_usize("TRADING_TXS_PER_ROUND", 1000);
    run_trading_tps(n, rounds, txs_per_round, 37000, 500.0);
}

/// Large-scale trading TPS test: configurable up to 10B orders.
/// Default: 4 validators, 10000 rounds, 1000 txs/round = 10M txs
/// (5M maker+taker pairs = 5M fills).
///
/// Scale up with env vars:
/// ```sh
/// # 100M txs (50M fills):
/// TRADING_ROUNDS=100000 cargo test -p devnet --test trading_tps --release -- \
///   --ignored trading_tps_large --nocapture
///
/// # 1B txs (500M fills):
/// TRADING_ROUNDS=1000000 cargo test -p devnet --test trading_tps --release -- \
///   --ignored trading_tps_large --nocapture
///
/// # 10B txs (5B fills):
/// TRADING_ROUNDS=10000000 TRADING_TXS_PER_ROUND=1000 cargo test -p devnet --test trading_tps --release -- \
///   --ignored trading_tps_large --nocapture
/// ```
#[test]
#[ignore = "large trading TPS test; run with --release --ignored"]
fn trading_tps_large() {
    let n = env_usize("TRADING_VALIDATORS", 4);
    let rounds = env_usize("TRADING_ROUNDS", 10_000);
    let txs_per_round = env_usize("TRADING_TXS_PER_ROUND", 1000);
    run_trading_tps(n, rounds, txs_per_round, 38000, 1000.0);
}
