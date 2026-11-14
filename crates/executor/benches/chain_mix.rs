//! Chain-path throughput by transaction type: signed EVM transfers, CLOB
//! orders sent as signed transactions, and a mix, all through the real
//! executor (mempool admission with signature recovery, proposal, validation,
//! block execution, state root).
//!
//! Unlike `block_pipeline` (unsigned envelopes, `UnsignedTxPolicy::Allow`) every
//! transaction here carries a real secp256k1 signature that admission recovers:
//!
//! - `transfer`: legacy EVM transfers (21k gas), RLP-signed, wrapped in the EVM
//!   envelope; the EVM module recovers the sender.
//! - `clob`: exchange `place` messages (limit orders, alternating sell/buy at one
//!   price so every order crosses) in the v1 EIP-712-signed envelope
//!   `[sender][nonce][fee][module_id|0x80][sig:64][recid:1][payload]`.
//! - `mixed`: half of the senders do each.
//!
//! Phases are timed separately: **ingest** (parallel across `--threads` threads:
//! signature recovery + admission), **propose** (mempool selection), and
//! **finalize** (block execution + state root, single-writer per module). Total
//! is the wall time of all three. After the run the bench checks that every
//! sender's nonce advanced by exactly its transaction count (all executed) and
//! prints the CLOB's resting-order count (a crossing mix leaves few).
//!
//! Output CSV: `mix,threads,txs,ingest_tps,propose_tps,finalize_tps,total_tps,executed,resting`.
//! Gate: informational.
//!
//! ```sh
//! cargo bench -p executor --bench chain_mix -- [--mix transfer,clob,mixed] [--txs 100000] \
//!     [--threads 1,4,16] [--accounts 512]
//! ```

#![allow(
    missing_docs,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::sync::Arc;
use std::time::Instant;

use crypto::{eip712, secp};
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use evm::{EvmModule, wrap_evm_tx_envelope};
use exchange::{ExchangeModule, msg};
use executor::{Executor, Module, TxContext};
use ports::AppInterface;
use primitives::fixed::{Price, Qty};
use primitives::{Address, Height};
use revm::primitives::{Bytes, U256};
use trading::{MarketConfig, NewOrder, OrderType, Side, StpMode, TimeInForce};
use types::{BlockBudget, FinalizedBlock, MempoolAck, TxBytes};

/// Per-tx fee in the envelope (same as `block_pipeline`).
const FEE: u64 = 100;
/// EVM gas price for transfers (above the 7 gwei base fee the module is built with).
const GAS_PRICE: u64 = 10_000_000_000;
/// Block budget: bytes and gas generous enough that a block holds every pending tx up to this size.
const BUDGET: BlockBudget = BlockBudget { max_bytes: 8 << 20, max_gas: 1 << 40 };

struct Account {
    key: [u8; 32],
    addr: Address,
}

fn accounts(n: usize) -> Vec<Account> {
    (0..n)
        .map(|_| {
            let (key, addr) = secp::generate_keypair_for_test();
            Account { key, addr: Address(addr.0) }
        })
        .collect()
}

fn evm_transfer(acct: &Account, nonce: u64, to: Address) -> TxBytes {
    let tx = TxLegacy {
        fields: TxFields {
            nonce,
            gas_limit: 21_000,
            to: TxKind::Call(revm::primitives::Address::from(to.0)),
            value: U256::from(1u64),
            data: Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(GAS_PRICE),
    };
    let rlp = SignedTx::sign_legacy(tx, &acct.key).expect("sign").encode_to_bytes();
    TxBytes::new(wrap_evm_tx_envelope(&acct.addr, nonce, GAS_PRICE, &rlp))
}

/// v1 envelope: header, module id with the signed bit, 65-byte signature, payload.
fn signed_native(acct: &Account, nonce: u64, module_id: u8, payload: &[u8]) -> TxBytes {
    let sig =
        eip712::sign_tx(&acct.key, 1, &acct.addr, nonce, FEE, module_id, payload).expect("sign");
    let mut b = Vec::with_capacity(37 + 65 + payload.len());
    b.extend_from_slice(&acct.addr.0);
    b.extend_from_slice(&nonce.to_le_bytes());
    b.extend_from_slice(&FEE.to_le_bytes());
    b.push(module_id | 0x80);
    b.extend_from_slice(&sig.sig);
    b.push(sig.recid.as_u8());
    b.extend_from_slice(payload);
    TxBytes::new(b)
}

fn clob_cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 20,
    }
}

fn order(side: Side, owner: Address) -> NewOrder {
    NewOrder {
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        owner,
        stp: StpMode::None,
    }
}

struct Rig {
    executor: Executor,
    exchange: Arc<ExchangeModule>,
}

fn rig(accts: &[Account], capacity: usize) -> Rig {
    let mut executor = Executor::new(capacity + 100);
    let evm = Arc::new(EvmModule::new(1, 7_000_000_000));
    for a in accts {
        // Native ledger balance (fees, escrow, base custody) and EVM balance (transfers).
        framework::Balances::mint(evm.as_ref(), &a.addr, u64::MAX / 4);
        evm.fund_account_for_test(&a.addr, 10u128.pow(22));
    }
    executor.register_module(evm.clone());
    executor.set_fee_module(framework::module_id::EVM);
    let ledger: Arc<dyn framework::Balances + Send + Sync> = evm;
    let ex = ExchangeModule::with_ledger(ledger);
    ex.list_market(clob_cfg()).expect("list market");
    // Sellers need base custody before they can place sell orders.
    for (i, a) in accts.iter().enumerate() {
        if i % 2 == 0 {
            let ctx = TxContext { sender: a.addr, nonce: 0, fee: 0 };
            ex.handle(&ctx, &msg::deposit_base(0, 1 << 40)).expect("deposit base");
        }
    }
    let exchange = Arc::new(ex);
    executor.register_module(exchange.clone());
    Rig { executor, exchange }
}

/// Build every account's transactions in nonce order: `(account index, txs)`.
/// Whether account `i` sends CLOB orders in `mix` (the rest send EVM transfers).
fn is_clob(mix: &str, i: usize) -> bool {
    match mix {
        "transfer" => false,
        "clob" => true,
        _ => i % 4 >= 2, // mixed: half the senders trade
    }
}

fn build(mix: &str, accts: &[Account], per_acct: usize) -> Vec<Vec<TxBytes>> {
    accts
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let clob = is_clob(mix, i);
            (0..per_acct as u64)
                .map(|n| {
                    if clob {
                        // Even accounts sell, odd buy, all at one price: every order crosses.
                        let side = if i % 2 == 0 { Side::Sell } else { Side::Buy };
                        signed_native(
                            a,
                            n,
                            framework::module_id::EXCHANGE,
                            &msg::place(0, order(side, a.addr)),
                        )
                    } else {
                        evm_transfer(a, n, accts[(i + 1) % accts.len()].addr)
                    }
                })
                .collect()
        })
        .collect()
}

fn run(mix: &str, threads: usize, total: usize, n_accts: usize) {
    let accts = accounts(n_accts);
    let per = (total / n_accts).max(1);
    let txs = build(mix, &accts, per);
    let n: usize = txs.iter().map(Vec::len).sum();
    let r = rig(&accts, n);

    // Ingest: `threads` workers each take a contiguous slice of accounts.
    let chunk = n_accts.div_ceil(threads);
    let t0 = Instant::now();
    let accepted: usize = std::thread::scope(|s| {
        let hs: Vec<_> = txs
            .chunks(chunk)
            .map(|group| {
                let ex = &r.executor;
                s.spawn(move || {
                    let mut ok = 0usize;
                    for list in group {
                        for t in list {
                            ok += usize::from(ex.ingest_tx(t.clone()) == MempoolAck::Accepted);
                        }
                    }
                    ok
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().expect("ingest thread")).sum()
    });
    let ingest = t0.elapsed().as_secs_f64();

    // Propose + finalize until the mempool is drained.
    let (mut propose, mut finalize) = (0.0f64, 0.0f64);
    let mut height = 1u64;
    let mut executed_txs = 0usize;
    loop {
        let t = Instant::now();
        let proposal = r.executor.prepare_proposal(&BUDGET);
        propose += t.elapsed().as_secs_f64();
        if proposal.txs.is_empty() {
            break;
        }
        executed_txs += proposal.txs.len();
        let t = Instant::now();
        let _ = r.executor.process_proposal(&proposal);
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(height),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        let _ = r.executor.finalize_block(&block);
        let _ = r.executor.attest_state(Height::new(height));
        finalize += t.elapsed().as_secs_f64();
        height += 1;
    }

    // Native (CLOB) senders: the executor's nonce must have advanced by exactly their tx count.
    // EVM senders track nonces inside the EVM module, so for them we require that every
    // transaction was admitted and went through proposal and finalization.
    let executed_ok = accepted == n
        && executed_txs == n
        && accts
            .iter()
            .enumerate()
            .filter(|(i, _)| is_clob(mix, *i))
            .all(|(_, a)| r.executor.executed_nonce_of(&a.addr) == per as u64);
    let resting = r.exchange.resting_count(0);
    let rate = |count: usize, secs: f64| count as f64 / secs;
    println!(
        "{mix},{threads},{n},{:.0},{:.0},{:.0},{:.0},{},{resting}",
        rate(accepted, ingest),
        rate(executed_txs, propose),
        rate(executed_txs, finalize),
        rate(executed_txs, ingest + propose + finalize),
        if executed_ok { "all" } else { "MISMATCH" },
    );
}

fn main() {
    let mut mixes = vec!["transfer".to_string(), "clob".into(), "mixed".into()];
    let mut threads = vec![1usize, 4];
    let mut total = 100_000usize;
    let mut n_accts = 512usize;
    let a: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < a.len() {
        let v = a.get(i + 1);
        match a[i].as_str() {
            "--mix" => {
                if let Some(x) = v {
                    mixes = x.split(',').map(str::to_owned).collect();
                }
            }
            "--threads" => {
                if let Some(x) = v {
                    threads = x.split(',').filter_map(|t| t.parse().ok()).collect();
                }
            }
            "--txs" => total = v.and_then(|x| x.parse().ok()).unwrap_or(total),
            "--accounts" => n_accts = v.and_then(|x| x.parse().ok()).unwrap_or(n_accts),
            _ => {
                i += 1;
                continue;
            }
        }
        i += 2;
    }
    println!(
        "mix,ingest_threads,txs,ingest_tps,propose_tps,finalize_tps,total_tps,executed,resting"
    );
    for m in &mixes {
        for &t in &threads {
            run(m, t, total, n_accts);
        }
    }
}
