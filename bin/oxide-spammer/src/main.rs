//! oxide-spammer — the load generator binary.
//!
//! Submits transactions to a local Oxide validator node at a
//! configurable rate and reports throughput. Used for load testing
//! the consensus + executor pipeline.
//!
//! Usage: `oxide-spammer [--txs N] [--engine sequencer|oxideBFT] [--evm]`
//!
//! Default: 10,000 staking-delegate txs on the sequencer engine. The
//! spammer builds a single-validator devnet in-process (no
//! networking), submits txs to the mempool, runs the engine to
//! finality, and reports txs/s.
//!
//! ## Modes
//!
//! - **Staking** (default): delegate txs bonding 1 unit to the
//!   genesis validator from a funded sender. Each tx increments the
//!   sender's nonce.
//! - **EVM** (`--evm`): signed EVM transactions (transfers, deploys,
//!   contract calls) from secp256k1-funded senders. Uses the
//!   `devnet::evm_workload` generator to build a realistic tx mix.

#![allow(clippy::cast_precision_loss)]

use std::env;

use devnet::evm_workload::{WorkloadConfig, WorkloadGenerator};
use node::{ConsensusConfig, Node, NodeConfig};
use ports::AppInterface;

/// Default number of transactions to submit.
const DEFAULT_TXS: usize = 10_000;

fn main() {
    let mut txs = DEFAULT_TXS;
    let mut engine = ConsensusConfig::Sequencer;
    let mut evm_mode = false;
    let mut orders_mode = false;
    for arg in env::args().skip(1) {
        if let Some(v) = arg.strip_prefix("--txs=") {
            txs = v.parse().unwrap_or(DEFAULT_TXS);
        } else if let Some(v) = arg.strip_prefix("--engine=") {
            engine = ConsensusConfig::parse(v).unwrap_or(ConsensusConfig::Sequencer);
        } else if arg == "--evm" {
            evm_mode = true;
        } else if arg == "--orders" {
            orders_mode = true;
        }
    }

    let mode = if orders_mode {
        "orders"
    } else if evm_mode {
        "evm"
    } else {
        "staking"
    };
    println!("oxide-spammer: engine = {}, mode = {}, txs = {txs}", engine.as_str(), mode);

    let config =
        NodeConfig { consensus: engine, max_mempool_entries: txs + 100, ..NodeConfig::default() };
    let mut node = Node::assemble(&config);
    println!("oxide-spammer: devnet assembled (executor + modules)");

    let start = std::time::Instant::now();

    if orders_mode {
        run_order_load(&mut node, txs);
    } else if evm_mode {
        run_evm_load(&mut node, txs);
    } else {
        run_staking_load(&mut node, txs);
    }

    let total_elapsed = start.elapsed();
    let throughput = txs as f64 / total_elapsed.as_secs_f64();

    // Report results.
    let height = node.engine().finalized_height();
    let finalized_txs: usize = if let Some(h) = height {
        node.engine().finalized_block(h).map_or(0, |b| b.txs.len())
    } else {
        0
    };
    println!("oxide-spammer: finalized height = {height:?}, last block txs = {finalized_txs}");
    println!(
        "oxide-spammer: {txs} txs in {:.3}ms = {throughput:.0} tx/s total",
        total_elapsed.as_secs_f64() * 1000.0
    );

    // State root at the final height.
    if let Some(h) = height {
        let attestation = node.app().attest_state(h);
        println!("oxide-spammer: state root at height {} = {}", h.value(), attestation.root);
    }
    println!("oxide-spammer: load test complete");
}

/// Run staking-delegate load: submit `txs` delegates and run the
/// engine to finality.
fn run_staking_load(node: &mut Node, txs: usize) {
    let module_payload = staking::msg::delegate(primitives::Address::ZERO, 1);
    let submit_start = std::time::Instant::now();
    for i in 0..txs {
        let tx = build_module_tx(
            primitives::Address([0u8; 20]),
            i as u64,
            framework::module_id::STAKING,
            &module_payload,
        );
        node.engine().submit_tx(tx);
    }
    let submit_elapsed = submit_start.elapsed();
    println!(
        "oxide-spammer: submitted {txs} txs in {:.3}ms ({:.0} tx/s submit rate)",
        submit_elapsed.as_secs_f64() * 1000.0,
        txs as f64 / submit_elapsed.as_secs_f64()
    );

    let exec_start = std::time::Instant::now();
    node.engine().run_until_idle();
    let exec_elapsed = exec_start.elapsed();
    println!(
        "oxide-spammer: exec time = {:.3}ms ({:.0} tx/s exec rate)",
        exec_elapsed.as_secs_f64() * 1000.0,
        txs as f64 / exec_elapsed.as_secs_f64()
    );
}

/// Run order-load: submit `txs` exchange place-order txs against the
/// node's default spot market (market 0, tick 1M, lot 1000, band
/// [1e9, 2e9]) and run the engine to finality.
///
/// Order flow is deterministic and fill-heavy: senders are split in
/// half — the first `NUM_ORDER_SENDERS/2` place resting asks at the
/// mid price, the rest place crossing buys — so every buy produces a
/// fill against a resting ask (different owners, so self-trade checks
/// never trigger). Per-sender nonces stay contiguous (`i / N` for
/// sender `i % N`), matching the mempool's nonce ordering.
fn run_order_load(node: &mut Node, txs: usize) {
    use primitives::fixed::{Price, Qty};
    use trading::{NewOrder, OrderType, Side, StpMode, TimeInForce};

    /// Number of distinct funded senders — enough that per-sender
    /// nonce chains stay short while the mempool's parallel
    /// preverification has real work to split.
    const NUM_ORDER_SENDERS: u64 = 100;
    /// The default market's mid price — inside the [1e9, 2e9] band
    /// and a multiple of the 1M tick.
    const MID_PRICE: u64 = 1_500_000_000;
    /// One lot — the smallest valid quantity.
    const LOT: u64 = 1_000;

    // Fund every sender: buys need `price·qty` quote, everyone pays
    // the envelope fee.
    for i in 0..NUM_ORDER_SENDERS {
        node.fund_evm_account(
            &primitives::Address([u8::try_from(i).unwrap_or_default(); 20]),
            u128::MAX,
        );
    }
    println!("oxide-spammer: funded {NUM_ORDER_SENDERS} order senders");

    let submit_start = std::time::Instant::now();
    for i in 0..txs as u64 {
        let sender_idx = i % NUM_ORDER_SENDERS;
        let nonce = i / NUM_ORDER_SENDERS;
        // First half of the sender space sells (resting asks), second
        // half buys — the buy crosses the standing asks → a fill.
        let side = if sender_idx < NUM_ORDER_SENDERS / 2 { Side::Sell } else { Side::Buy };
        let order = NewOrder {
            side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(MID_PRICE),
            qty: Qty(LOT),
            owner: primitives::Address([0u8; 20]), // overwritten by ctx.sender
            stp: StpMode::None,
        };
        let payload = exchange::msg::place(0, order);
        let tx = build_module_tx(
            primitives::Address([u8::try_from(sender_idx).unwrap_or_default(); 20]),
            nonce,
            framework::module_id::EXCHANGE,
            &payload,
        );
        node.engine().submit_tx(tx);
    }
    let submit_elapsed = submit_start.elapsed();
    println!(
        "oxide-spammer: submitted {txs} orders in {:.3}ms ({:.0} orders/s submit rate)",
        submit_elapsed.as_secs_f64() * 1000.0,
        txs as f64 / submit_elapsed.as_secs_f64()
    );

    let exec_start = std::time::Instant::now();
    node.engine().run_until_idle();
    let exec_elapsed = exec_start.elapsed();
    println!(
        "oxide-spammer: exec time = {:.3}ms ({:.0} orders/s exec rate)",
        exec_elapsed.as_secs_f64() * 1000.0,
        txs as f64 / exec_elapsed.as_secs_f64()
    );
}

/// Run EVM load: generate `txs` signed EVM transactions (transfers,
/// deploys, contract calls), submit them, and run the engine to
/// finality.
///
/// The EVM workload uses the `devnet::evm_workload::WorkloadGenerator`
/// to build a realistic mix of EVM transactions. Senders are
/// secp256k1 keypairs funded via `EvmModule::fund_account_for_test`.
fn run_evm_load(node: &mut Node, txs: usize) {
    // The Node doesn't register an EVM module by default.
    // We need to access the executor and register one. Since
    // Node doesn't expose the executor for module registration
    // after assembly, we use a workaround: build the EVM txs and
    // submit them. The EVM module must be registered by the devnet
    // assembly path.
    //
    // For the spammer, we use the devnet's TcpMultiNodeDevnet which
    // does register the EVM module. But the spammer uses Node
    // (single-node). So we need to either:
    // 1. Add EVM module registration to Node::assemble, or
    // 2. Use a different approach.
    //
    // For now, we generate the EVM workload and report the generation
    // throughput. Full EVM spamming requires Node to register
    // the EVM module, which is a separate change.

    let num_senders = txs.clamp(10, 100);
    let config = WorkloadConfig {
        num_senders,
        num_recipients: 50,
        num_contracts: 10,
        ..WorkloadConfig::default()
    };
    println!(
        "oxide-spammer: generating {txs} EVM txs ({num_senders} senders, mix: 50% transfer, 20% deploy, 20% call, 10% read)..."
    );
    let gen_start = std::time::Instant::now();
    let mut workload = WorkloadGenerator::new(config);
    let generated = workload.generate_batch(txs);
    let gen_elapsed = gen_start.elapsed();
    println!(
        "oxide-spammer: generated {txs} EVM txs in {:.3}s ({:.0} tx/s gen rate)",
        gen_elapsed.as_secs_f64(),
        txs as f64 / gen_elapsed.as_secs_f64()
    );
    println!("oxide-spammer: {} contracts deployed in workload", workload.deployed_count());

    // Fund the workload generator's sender accounts.
    for sender in workload.senders() {
        node.fund_evm_account(&sender.addr, u128::MAX);
    }
    println!("oxide-spammer: funded {} EVM sender accounts", workload.senders().len());

    // Submit txs to the engine.
    let submit_start = std::time::Instant::now();
    for g in &generated {
        node.engine().submit_tx(g.envelope.clone());
    }
    let submit_elapsed = submit_start.elapsed();
    println!(
        "oxide-spammer: submitted {txs} EVM txs in {:.3}ms ({:.0} tx/s submit rate)",
        submit_elapsed.as_secs_f64() * 1000.0,
        txs as f64 / submit_elapsed.as_secs_f64()
    );

    let exec_start = std::time::Instant::now();
    node.engine().run_until_idle();
    let exec_elapsed = exec_start.elapsed();
    println!(
        "oxide-spammer: exec time = {:.3}ms ({:.0} tx/s exec rate)",
        exec_elapsed.as_secs_f64() * 1000.0,
        txs as f64 / exec_elapsed.as_secs_f64()
    );
}

/// Build a module tx with the given sender + nonce.
fn build_module_tx(
    sender: primitives::Address,
    nonce: u64,
    module_id: u8,
    module_payload: &[u8],
) -> types::TxBytes {
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(module_payload);
    types::TxBytes::new(bytes)
}
