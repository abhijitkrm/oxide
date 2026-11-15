//! Root stage (docs/root-stage-spec.md): the pipelined exec lane must
//! produce the same state root at every height as the synchronous path,
//! on a signed EVM-transfer + CLOB mix through the real executor.

#![allow(missing_docs, clippy::too_many_lines)]

use std::sync::Arc;

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
const BUDGET: BlockBudget = BlockBudget { max_bytes: 40_000, max_gas: 1 << 40 };

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

/// A recipient address that is nobody's sender: derived from the tx's coordinates.
fn fresh_recipient(i: usize, n: u64) -> Address {
    let mut a = [0u8; 20];
    a[..8].copy_from_slice(&(i as u64).to_le_bytes());
    a[8..16].copy_from_slice(&n.to_le_bytes());
    a[19] = 0xFE;
    Address(a)
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
    executor.register_module(Arc::new(ex));
    Rig { executor }
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

fn build(mix: &str, accts: &[Account], per_acct: usize, ring: bool) -> Vec<Vec<TxBytes>> {
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
                        // `ring`: pay the next sender (every account both sends and receives: the
                        // worst case for speculative parallelism). Default: a fresh recipient.
                        let to = if ring {
                            accts[(i + 1) % accts.len()].addr
                        } else {
                            fresh_recipient(i, n)
                        };
                        evm_transfer(a, n, to)
                    }
                })
                .collect()
        })
        .collect()
}

fn feed_block(r: &Rig, txs: &[Vec<TxBytes>]) {
    for list in txs {
        for t in list {
            assert_eq!(r.executor.ingest_tx(t.clone()), MempoolAck::Accepted);
        }
    }
}

fn fresh_rig(accts: &[Account], capacity: usize) -> Rig {
    rig(accts, capacity)
}

#[test]
fn root_stage_lane_matches_synchronous_roots() {
    let accts = accounts(48);
    let txs = build("mixed", &accts, 40, false);
    let n: usize = txs.iter().map(Vec::len).sum();

    // Reference: synchronous execution, blocks cut by its own proposer.
    let reference = fresh_rig(&accts, n);
    feed_block(&reference, &txs);
    let mut blocks = Vec::new();
    let mut want = Vec::new();
    let mut height = 1u64;
    loop {
        let proposal = reference.executor.prepare_proposal(&BUDGET);
        if proposal.txs.is_empty() {
            break;
        }
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(height),
            txs: proposal.txs,
            signers: Vec::new(),
        };
        let _ = reference.executor.finalize_block(&block);
        want.push(reference.executor.attest_state(Height::new(height)).expect("sync root").root);
        blocks.push(block);
        height += 1;
    }
    assert!(
        blocks.len() >= 2,
        "need several blocks to exercise the pipeline, got {}",
        blocks.len()
    );

    // Under test: same blocks through the root-stage lane.
    let mut staged = fresh_rig(&accts, n);
    staged.executor = staged.executor.with_root_stage(true);
    let exec = Arc::new(staged.executor);
    exec.spawn_exec_lane();
    for block in &blocks {
        let _ = exec.finalize_block(block);
    }
    for (i, want_root) in want.iter().enumerate() {
        let h = Height::new(i as u64 + 1);
        let got = exec.attest_state(h).expect("staged root").root;
        assert_eq!(got, *want_root, "root-stage root diverged at height {}", i + 1);
    }
}
