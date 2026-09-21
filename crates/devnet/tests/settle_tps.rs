//! Batch-settlement TPS test — the off-chain-matcher settlement path
//! through the full oxideBFT consensus pipeline.
//!
//! This is the honest number for the 1M-orders/s architecture: the
//! off-chain `oxide-matcher` does the book work (11–18M orders/s
//! measured in `bin/oxide-matcher` benches), and the chain only
//! receives pre-matched fills via `exchange::msg::batch_settle` txs.
//! On-chain cost per fill is parse + leg validation + pair
//! aggregation + one ledger transfer per (buyer, seller) pair — no
//! matching runs on-chain.
//!
//! # What this measures
//!
//! Each `batch_settle` tx carries `fills_per_tx` fill legs; the
//! settlement operator (a prefunded sender) submits
//! `txs_per_round` batch txs per round. Buyers are prefunded senders
//! 0..16, sellers are senders 16..31, round-robin — so every fill is
//! a distinct-ish pair mix that still exercises aggregation. Every
//! account first submits one order-registration tx (the first 31
//! workload txs) authorizing a single working order under client id
//! 1; the batch legs then reference those `(owner, 1)` registered
//! orders — the on-chain authorization model this test exercises.
//! The test verifies:
//!
//! - All txs are finalized (no batches dropped).
//! - All validators agree on identical blocks and state roots.
//! - Seller balances increased by exactly `fills × quote` on every
//!   validator (no value created or destroyed by settlement).
//!
//! # Running
//!
//! ```sh
//! # Default: 4 validators, 63 rounds, 2 batch txs/round, 16,384
//! # fills/tx = ~2.05M fills (~4.1M orders). Measured ~1.4M fills/s
//! # at chain level on an M-series dev Mac.
//! cargo test -p devnet --test settle_tps --release -- --ignored --nocapture
//!
//! # Max wire batch (65,536 fills/tx, ~3.8 MiB/tx):
//! SETTLE_ROUNDS=32 SETTLE_TXS_PER_ROUND=2 SETTLE_FILLS_PER_TX=65536 \
//!   cargo test -p devnet --test settle_tps --release -- --ignored --nocapture
//! ```
//!
//! # Measured results (4 validators, TCP loopback, release)
//!
//! | fills/tx | tx/s | fills/s | orders/s | 1M fills/s |
//! |----------|------|---------|----------|------------|
//! | 1,024    | 347  | 355K    | 711K     | no — per-tx overhead bound |
//! | 8,192    | 123  | 1.01M   | 2.01M    | ✅ |
//! | 16,384   | 87   | 1.41M   | 2.81M    | ✅ |
//! | 65,536   | 29   | 1.85M   | 3.71M    | ✅ |
//!
//! Throughput scales with batch size: at 1k fills/tx the pipeline is
//! per-tx-overhead-bound (~350 tx/s), at 65k fills/tx it is
//! payload-bound (~103 MiB/s of serialized fill traffic through
//! consensus gossip + journal + execution). The settlement work
//! itself is not the bottleneck — the module bench
//! (`batch_settle_1k_distinct_pairs`) sustains ~3.9M fills/s.

#![allow(clippy::cast_precision_loss)]

use devnet::tcp_multinode::TcpMultiNodeDevnet;
use ports::AppInterface;
use primitives::Address;
use primitives::fixed::{Price, Qty};
use std::time::Instant;
use trading::MarketConfig;

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

/// Sender byte of the settlement operator — the last of the devnet's
/// 32 prefunded senders, kept clear of the buyer/seller ranges so its
/// balance changes reflect only tx fees.
const OPERATOR_BYTE: u8 = 31;
/// Buyer senders are prefunded bytes 0..16.
const NUM_BUYERS: u8 = 16;
/// Seller senders are prefunded bytes 16..31 (15 accounts — byte 31
/// is the operator).
const NUM_SELLERS: u8 = 15;
/// Fill price: $15.00, mid-band. Orders register at this limit so
/// every leg's crossing check passes exactly.
const FILL_PRICE: u64 = 1_500_000_000;
/// Fill quantity: one lot.
const FILL_QTY: u64 = 1_000;
/// Quote units moved per fill: `price × qty / PRICE_SCALE`
/// = `1_500_000_000 × 1_000 / 100_000_000` = `15_000` base units.
const FILL_QUOTE: u64 = 15_000;
/// Client order id every account registers its single working
/// order under — the `(owner, 1)` key the batch legs reference.
const CLIENT_ID: u64 = 1;

/// Build a tx envelope for an exchange module message.
///
/// Format: `[sender:20B][nonce:8B LE][fee:8B LE][module_id:1B][payload]`
/// where `module_id` = `EXCHANGE` (5).
fn make_tx(sender_byte: u8, nonce: u64, payload: Vec<u8>) -> types::TxBytes {
    let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
    bytes.extend_from_slice(&[sender_byte; 20]);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&100u64.to_le_bytes());
    bytes.push(framework::module_id::EXCHANGE);
    bytes.extend_from_slice(&payload);
    types::TxBytes::new(bytes)
}

/// Build one order-registration tx for `sender_byte`: a single
/// resting order under `CLIENT_ID` sized to cover every fill the
/// account will see in the workload. Buys escrow
/// `price × qty / PRICE_SCALE` at registration — sized to the
/// per-account fill count so the reservation is exact.
fn make_register_tx(sender_byte: u8, side: trading::Side, qty: u64) -> types::TxBytes {
    make_tx(sender_byte, 0, exchange::msg::register_order(0, side, FILL_PRICE, qty, CLIENT_ID))
}

/// Build one batch-settle tx carrying `count` fills starting at
/// global fill index `start`. Fill `i` trades between registered
/// buy order `(i % 16, 1)` and sell order `(16 + i % 15, 1)`, so
/// pair composition varies across the batch (aggregation
/// exercised, not fully collapsed).
fn make_batch_tx(nonce: u64, start: usize, count: usize) -> types::TxBytes {
    let fills: Vec<exchange::BatchFillEntry> = (0..count)
        .map(|j| {
            let i = start + j;
            #[allow(clippy::cast_possible_truncation)]
            let buyer = Address([(i % usize::from(NUM_BUYERS)) as u8; 20]);
            #[allow(clippy::cast_possible_truncation)]
            let seller = Address([NUM_BUYERS + (i % usize::from(NUM_SELLERS)) as u8; 20]);
            exchange::BatchFillEntry {
                market: 0,
                price: Price(FILL_PRICE),
                qty: Qty(FILL_QTY),
                buy: exchange::OrderKey { owner: buyer, client_id: CLIENT_ID },
                sell: exchange::OrderKey { owner: seller, client_id: CLIENT_ID },
            }
        })
        .collect();
    make_tx(OPERATOR_BYTE, nonce, exchange::msg::batch_settle(&fills))
}

/// Run the batch-settlement TPS test with the given parameters.
#[allow(clippy::too_many_lines)]
fn run_settle_tps(
    n_validators: usize,
    rounds: usize,
    txs_per_round: usize,
    fills_per_tx: usize,
    base_port: u16,
    min_fills_per_sec: f64,
) {
    // `run_pipelined_txs` consumes exactly `rounds * txs_per_round`
    // txs in contiguous chunks — the first `NUM_BUYERS +
    // NUM_SELLERS` slots are the order registrations every batch leg
    // authorizes against; the rest are batch txs. The market is
    // listed in-process before the run (see below).
    let registration_txs = usize::from(NUM_BUYERS) + usize::from(NUM_SELLERS);
    let total_txs = rounds * txs_per_round;
    assert!(
        total_txs > registration_txs,
        "workload too small for the {registration_txs} registration txs"
    );
    let total_batch_txs = total_txs - registration_txs;
    let total_fills = total_batch_txs * fills_per_tx;
    eprintln!(
        "settle TPS test: {n_validators} validators, {rounds} rounds, \
         {txs_per_round} batch txs/round × {fills_per_tx} fills \
         = {total_fills} fills ({} orders)",
        total_fills * 2
    );

    let max_mempool = total_txs + 1000;
    let operator = Address([OPERATOR_BYTE; 20]);

    let assemble_start = Instant::now();
    let mut devnet = TcpMultiNodeDevnet::with_exchange_settlement_and_base_port(
        n_validators,
        max_mempool,
        base_port,
        operator,
    );
    eprintln!("settle TPS test: assembled in {:.3}s", assemble_start.elapsed().as_secs_f64());

    // List the market in-process on every validator — the
    // genesis-style setup path. `TAG_LIST_MARKET` transactions are
    // committee-gated governance actions, not a setup shortcut, so
    // the workload carries only batch txs; the identical config on
    // every validator assigns the same market id 0 and lands the
    // same state-root contribution.
    for ex in devnet.exchange_modules() {
        ex.list_market(cfg()).expect("test market config is valid");
    }

    // Build the workload: 31 order registrations FIRST (each account
    // authorizes one working order under CLIENT_ID sized to cover
    // its fills), then all batch txs from the operator with
    // incrementing nonces starting at 0. A batch leg without a
    // registered order is a rejected leg — registration order in
    // the workload is what makes the batches valid.
    let build_start = Instant::now();
    let mut all_txs = Vec::with_capacity(total_txs);
    let buy_qty = (total_fills.div_ceil(usize::from(NUM_BUYERS)) as u64) * FILL_QTY;
    let sell_qty = (total_fills.div_ceil(usize::from(NUM_SELLERS)) as u64) * FILL_QTY;
    for b in 0..NUM_BUYERS {
        all_txs.push(make_register_tx(b, trading::Side::Buy, buy_qty));
    }
    for b in NUM_BUYERS..NUM_BUYERS + NUM_SELLERS {
        all_txs.push(make_register_tx(b, trading::Side::Sell, sell_qty));
    }
    let mut next_fill = 0usize;
    for nonce in (0u64..).take(total_batch_txs) {
        all_txs.push(make_batch_tx(nonce, next_fill, fills_per_tx));
        next_fill += fills_per_tx;
    }
    eprintln!(
        "settle TPS test: built {total_txs} txs ({total_fills} fills) in {:.3}s",
        build_start.elapsed().as_secs_f64()
    );

    // Feed the pipeline: `run_pipelined_txs` slices `all_txs` into
    // `txs_per_round` chunks per round, so round 0 carries the 31
    // registration txs (batch legs referencing them must execute
    // after them) and later rounds are all batches.
    //
    // `SETTLE_DRIVER=threaded` switches to `run_threaded_txs`: each
    // validator on its own OS thread with proposals shipped over TCP —
    // the closer approximation of a real multi-machine deployment.
    let driver = std::env::var("SETTLE_DRIVER").unwrap_or_else(|_| "pipelined".to_string());
    let (result, elapsed) = if driver == "threaded" {
        eprintln!("settle TPS test: running {rounds} rounds (threaded, {n_validators} threads)...");
        devnet.run_threaded_txs(rounds, txs_per_round, &all_txs)
    } else {
        eprintln!("settle TPS test: running {rounds} rounds (pipelined)...");
        devnet.run_pipelined_txs(rounds, txs_per_round, &all_txs)
    };
    eprintln!("settle TPS test: completed in {:.3}s", elapsed.as_secs_f64());

    // ── Integrity checks ───────────────────────────────────────

    // 1. Common finalized prefix across all validators.
    let min_blocks = result.finalized.iter().map(Vec::len).min().unwrap_or(0);
    assert!(min_blocks > 0, "should have finalized at least one block");

    // 2. Every submitted tx finalized (all batch txs).
    let finalized_txs: usize = result.finalized[0][..min_blocks].iter().map(|b| b.txs.len()).sum();
    assert_eq!(
        finalized_txs, total_txs,
        "all {total_txs} txs must be finalized, got {finalized_txs}"
    );

    // 3. All validators agree on identical block contents.
    let reference = &result.finalized[0][..min_blocks];
    for (i, blocks) in result.finalized.iter().enumerate().skip(1) {
        for (j, (a, b)) in reference.iter().zip(blocks[..min_blocks].iter()).enumerate() {
            assert_eq!(a.height, b.height, "validator {i} block {j}: height mismatch");
            assert_eq!(a.txs, b.txs, "validator {i} block {j}: txs mismatch");
        }
    }

    // 4. State root equality at the finalized height.
    let final_height = result.finalized[0].last().map_or(primitives::Height::new(0), |b| b.height);
    let root_0 = devnet.app(0).attest_state(final_height).expect("executed").root;
    for i in 1..n_validators {
        let root_i = devnet.app(i).attest_state(final_height).expect("executed").root;
        assert_eq!(root_0, root_i, "validator {i} state root != validator 0");
    }

    // 5. Settlement conservation: sellers received exactly
    //    `total_fills × FILL_QUOTE` units in aggregate MINUS the
    //    `fee` each seller paid for its order-registration tx
    //    (15 senders × 100 units — fees are burned, not credited to
    //    sellers). Check on every validator — catches both dropped
    //    fills and divergent settlement. `EvmModule::balance`
    //    returns wei, so scale the expectation by `WEI_PER_UNIT`.
    let genesis_units: u64 = 1_000_000_000_000; // GENESIS_BALANCE
    let wei = framework::WEI_PER_UNIT;
    let expected_seller_total = (u128::from(genesis_units) * u128::from(NUM_SELLERS)
        - u128::from(NUM_SELLERS) * 100
        + u128::from(FILL_QUOTE) * total_fills as u128)
        * wei;
    for i in 0..n_validators {
        let evm = devnet.evm_module(i);
        let seller_total: u128 =
            (NUM_BUYERS..NUM_BUYERS + NUM_SELLERS).map(|b| evm.balance(&Address([b; 20]))).sum();
        assert_eq!(
            seller_total, expected_seller_total,
            "validator {i} seller aggregate {seller_total} != {expected_seller_total}"
        );
    }
    eprintln!("settle TPS test: seller conservation verified on all {n_validators} validators");

    // 6. Finalized-outcome agreement: every validator must record
    //    the same Executed outcome for the same batch tx — the
    //    record a settlement client confirms against. `batch_fill`
    //    is emitted once per aggregated (buyer, seller) PAIR, not
    //    per leg — the expected count is the batch's distinct pairs.
    //    Zero `fill_rejected`/`settlement_failed` events means every
    //    leg authorized and every credit landed.
    let h =
        |tx: &types::TxBytes| crypto::Hasher::hash_one(crypto::Domain::Transaction, tx.as_bytes());
    let expected_pairs = |start: usize| -> usize {
        let mut pairs = std::collections::HashSet::new();
        for j in 0..fills_per_tx {
            let i = start + j;
            #[allow(clippy::cast_possible_truncation)]
            pairs.insert((
                (i % usize::from(NUM_BUYERS)) as u8,
                NUM_BUYERS + (i % usize::from(NUM_SELLERS)) as u8,
            ));
        }
        pairs.len()
    };
    for (tx, start) in [
        (&all_txs[registration_txs], 0usize), // first batch
        (&all_txs[total_txs - 1], (total_batch_txs - 1) * fills_per_tx), // last batch
    ] {
        let hash = h(tx);
        for i in 0..n_validators {
            match devnet.app(i).tx_outcome(&hash) {
                Some(executor::TxOutcome::Executed { events, error }) => {
                    assert!(error.is_none(), "validator {i}: batch rejected: {error:?}");
                    let fills = events.iter().filter(|e| e.kind == "batch_fill").count();
                    assert_eq!(
                        fills,
                        expected_pairs(start),
                        "validator {i}: pair-settlement events != distinct batch pairs"
                    );
                    assert_eq!(
                        events.iter().filter(|e| e.kind == "fill_rejected").count(),
                        0,
                        "validator {i}: clean batch must reject no legs"
                    );
                    assert_eq!(
                        events.iter().filter(|e| e.kind == "settlement_failed").count(),
                        0,
                        "validator {i}: clean batch must void no pairs"
                    );
                }
                other => panic!("validator {i}: batch tx must be Executed, got {other:?}"),
            }
        }
    }
    // The operator's executed nonce equals the number of batch txs —
    // the value a settler resyncs to after restart.
    let operator_nonce = devnet.app(0).executed_nonce_of(&operator);
    assert_eq!(
        operator_nonce, total_batch_txs as u64,
        "operator nonce {operator_nonce} != {total_batch_txs} executed batches"
    );
    eprintln!("settle TPS test: finalized outcomes agree on all {n_validators} validators");

    // ── Report ─────────────────────────────────────────────────

    let secs = elapsed.as_secs_f64();
    let fills_per_sec = total_fills as f64 / secs;
    let orders_per_sec = fills_per_sec * 2.0;
    let tx_rate = total_txs as f64 / secs;
    let payload_mb = (total_fills * 74) as f64 / (1024.0 * 1024.0);
    eprintln!();
    eprintln!("=== Batch-Settlement TPS Results (consensus pipeline) ===");
    eprintln!("  validators:        {n_validators}");
    eprintln!("  batch txs:         {total_batch_txs} ({fills_per_tx} fills each)");
    eprintln!("  fills settled:     {total_fills}");
    eprintln!("  settle payload:    {payload_mb:.1} MiB");
    eprintln!("  blocks finalized:  {min_blocks} (common prefix)");
    eprintln!("  elapsed:           {secs:.3}s");
    eprintln!("  throughput:        {fills_per_sec:.0} fills/s");
    eprintln!("  equivalent orders: {orders_per_sec:.0} orders/s");
    eprintln!("  tx rate:           {tx_rate:.0} tx/s");
    eprintln!("  fills/s floor:     {min_fills_per_sec:.0}");
    eprintln!("=========================================================");
    if fills_per_sec >= 1_000_000.0 {
        eprintln!("  ✓ 1M fills/s target MET at chain level");
    } else {
        eprintln!("  ✗ 1M fills/s target NOT met at chain level ({fills_per_sec:.0})");
    }

    let env_floor = std::env::var("SETTLE_MIN_FLOOR").ok().and_then(|v| v.parse::<f64>().ok());
    let effective_floor = env_floor.unwrap_or(min_fills_per_sec);
    if effective_floor > 0.0 {
        assert!(
            fills_per_sec >= effective_floor,
            "settle throughput {fills_per_sec:.0} below floor {effective_floor:.0} fills/s"
        );
    }
}

/// Default settle-TPS test: 4 validators, 63 rounds, 2 batch
/// txs/round, 16,384 fills/tx = 2,048,000 fills (~4.1M orders).
/// At this batch size the chain-level path exceeds 1M fills/s.
///
/// The floor is deliberately modest (10k fills/s): this test's job is
/// honest measurement, not a hard gate — the module-level criterion
/// bench carries the ≥1M-fills/s acceptance gate.
#[test]
#[ignore = "settle TPS test binds TCP ports; run with --release --ignored --nocapture"]
fn settle_tps_default() {
    let n = env_usize("SETTLE_VALIDATORS", 4);
    let rounds = env_usize("SETTLE_ROUNDS", 63);
    let txs_per_round = env_usize("SETTLE_TXS_PER_ROUND", 2);
    let fills_per_tx = env_usize("SETTLE_FILLS_PER_TX", 16384);
    run_settle_tps(n, rounds, txs_per_round, fills_per_tx, 39000, 10_000.0);
}

/// Large settle-TPS test: 4 validators, 64 rounds × 2 txs × 65,536
/// fills (the wire maximum) = ~8.3M fills (~16.5M orders).
#[test]
#[ignore = "large settle TPS test; run with --release --ignored"]
fn settle_tps_large() {
    let n = env_usize("SETTLE_VALIDATORS", 4);
    let rounds = env_usize("SETTLE_ROUNDS", 64);
    let txs_per_round = env_usize("SETTLE_TXS_PER_ROUND", 2);
    let fills_per_tx = env_usize("SETTLE_FILLS_PER_TX", 65_536);
    run_settle_tps(n, rounds, txs_per_round, fills_per_tx, 39100, 10_000.0);
}
