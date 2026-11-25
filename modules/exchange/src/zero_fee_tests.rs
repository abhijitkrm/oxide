//! Orders are free, everything else pays: the fee-floor exemption and the admission funds check
//! (`admission.rs`), including an end-to-end run through the executor with a non-zero chain floor.

use std::sync::Arc;

use crypto::hash::{Domain, Hasher};
use executor::{Executor, Module, TxContext, TxOutcome, TxSkipReason, UnsignedTxPolicy};
use framework::{Balances, MemoryBalances, module_id};
use ports::AppInterface;
use primitives::fixed::{Price, Qty};
use primitives::{Address, Height};
use types::{BlockBudget, FinalizedBlock, MempoolAck, TxBytes};

use super::{
    ExchangeModule, MarketConfig, NewOrder, OrderId, OrderType, Side, StpMode, TimeInForce, msg,
};

const RICH: u64 = 1_000_000_000_000;
const DEPOSIT: u64 = 1_000_000;

fn addr(b: u8) -> Address {
    Address([b; 20])
}

fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 4096,
    }
}

fn order(side: Side, order_type: OrderType) -> NewOrder {
    NewOrder {
        side,
        order_type,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(2_000),
        owner: addr(1),
        stp: StpMode::None,
    }
}

fn ctx(sender: Address) -> TxContext {
    TxContext { sender, nonce: 0, fee: 0 }
}

/// A module with owner 1 funded and holding base custody, owner 2 funded with no custody, owner 3 poor.
fn rig() -> (Arc<MemoryBalances>, ExchangeModule) {
    let ledger = Arc::new(MemoryBalances::new());
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(cfg()).expect("market");
    ledger.mint(&addr(1), RICH);
    ledger.mint(&addr(2), RICH);
    ledger.mint(&addr(3), 1);
    ex.handle(&ctx(addr(1)), &msg::deposit_base(0, DEPOSIT)).expect("deposit");
    (ledger, ex)
}

#[test]
fn only_orders_are_free() {
    let free = [
        msg::place(0, order(Side::Buy, OrderType::Limit)),
        msg::cancel(0, OrderId(0)),
        msg::bundle(&[msg::cancel(0, OrderId(0))]).unwrap(),
        msg::dbundle(&[(addr(1), msg::cancel(0, OrderId(0)))]).unwrap(),
    ];
    for m in &free {
        assert_eq!(ExchangeModule::order_fee_floor(m), Some(0), "{:?} must be free", m[0]);
    }
    let paid = [
        msg::deposit_base(0, 1),
        msg::withdraw_base(0, 1),
        msg::delegate(addr(9), 3, 10, 0),
        msg::revoke_delegate(addr(9)),
        msg::list_market(cfg()),
    ];
    for m in &paid {
        assert_eq!(
            ExchangeModule::order_fee_floor(m),
            None,
            "{:?} must follow the chain floor",
            m[0]
        );
    }
}

#[test]
fn admission_requires_the_sender_to_fund_the_order() {
    let (_ledger, ex) = rig();
    let buy = msg::place(0, order(Side::Buy, OrderType::Limit));
    let sell = msg::place(0, order(Side::Sell, OrderType::Limit));
    let market_buy = msg::place(0, order(Side::Buy, OrderType::Market));
    // Funded buy and a sell backed by custody are admitted.
    assert!(ex.validate(&ctx(addr(1)), &buy).is_ok());
    assert!(ex.validate(&ctx(addr(1)), &sell).is_ok());
    assert!(ex.validate(&ctx(addr(1)), &market_buy).is_ok());
    // Owner 3 holds 1 unit: a 3-unit limit buy is refused.
    assert!(ex.validate(&ctx(addr(3)), &buy).is_err(), "unfunded buy");
    // Owner 2 is rich in quote but has no base custody: a sell is refused.
    assert!(ex.validate(&ctx(addr(2)), &sell).is_err(), "sell without custody");
    // A market buy needs some balance; a stranger with none is refused.
    assert!(ex.validate(&ctx(addr(99)), &market_buy).is_err(), "market buy with no balance");
    // A truncated place body is refused at admission instead of burning block space.
    assert!(ex.validate(&ctx(addr(1)), &[super::TAG_PLACE, 0, 0]).is_err());
    // Cancels and other kinds are not funds-checked.
    assert!(ex.validate(&ctx(addr(3)), &msg::cancel(0, OrderId(0))).is_ok());
    assert!(ex.validate(&ctx(addr(3)), &msg::deposit_base(0, 1)).is_ok());
}

#[test]
fn bundles_and_delegated_bundles_are_checked_per_payer() {
    let (_ledger, ex) = rig();
    let buy = msg::place(0, order(Side::Buy, OrderType::Limit));
    // An own-account bundle is refused when ONE of its buys is unfundable in aggregate.
    let two = msg::bundle(&[buy.clone(), buy.clone()]).unwrap();
    assert!(ex.validate(&ctx(addr(1)), &two).is_ok());
    assert!(ex.validate(&ctx(addr(3)), &two).is_err());
    // A delegated bundle is funded by its OWNERS: owner 3 (poor) refuses it, owner 2 does not, and
    // an item without a delegation is refused whole.
    let agent = addr(200);
    ex.handle(&ctx(addr(2)), &msg::delegate(agent, 3, u64::MAX, 0)).unwrap();
    ex.handle(&ctx(addr(3)), &msg::delegate(agent, 3, u64::MAX, 0)).unwrap();
    let ok = msg::dbundle(&[(addr(2), buy.clone())]).unwrap();
    let poor = msg::dbundle(&[(addr(2), buy.clone()), (addr(3), buy.clone())]).unwrap();
    let stranger = msg::dbundle(&[(addr(1), buy)]).unwrap();
    assert!(ex.validate(&ctx(agent), &ok).is_ok());
    assert!(ex.validate(&ctx(agent), &poor).is_err(), "an unfunded owner refuses the bundle");
    assert!(ex.validate(&ctx(agent), &stranger).is_err(), "no delegation from owner 1");
}

fn envelope(sender: Address, nonce: u64, fee: u64, payload: &[u8]) -> TxBytes {
    let mut b = Vec::with_capacity(37 + payload.len());
    b.extend_from_slice(&sender.0);
    b.extend_from_slice(&nonce.to_le_bytes());
    b.extend_from_slice(&fee.to_le_bytes());
    b.push(module_id::EXCHANGE);
    b.extend_from_slice(payload);
    TxBytes::new(b)
}

#[test]
fn through_the_executor_orders_run_at_fee_zero_and_deposits_do_not() {
    let (ledger, ex) = rig();
    let ex = Arc::new(ex);
    let mut executor = Executor::new(1_000)
        .with_unsigned_tx_policy(UnsignedTxPolicy::Allow)
        // A chain floor of 5: everything not exempted must declare at least 5.
        .with_min_fee(5);
    executor.register_module(ex.clone());
    let sender = addr(1);
    let order_tx = envelope(sender, 0, 0, &msg::place(0, order(Side::Buy, OrderType::Limit)));
    let deposit_tx = envelope(sender, 1, 0, &msg::deposit_base(0, 10));
    let paid_deposit_tx = envelope(sender, 1, 5, &msg::deposit_base(0, 10));
    for tx in [&order_tx, &deposit_tx] {
        assert!(matches!(executor.ingest_tx(tx.clone()), MempoolAck::Accepted));
    }
    let budget = BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    });
    let hash = |t: &TxBytes| Hasher::hash_one(Domain::Transaction, t.as_bytes());
    // The order paid nothing and executed; the zero-fee deposit was refused by the floor.
    assert!(matches!(executor.tx_outcome(&hash(&order_tx)), Some(TxOutcome::Executed { .. })));
    assert!(matches!(
        executor.tx_outcome(&hash(&deposit_tx)),
        Some(TxOutcome::Skipped { reason: TxSkipReason::FeeFloor })
    ));
    assert_eq!(ex.resting_count(0), 1, "the free order rests on the book");
    let after_order = ledger.balance(&sender);
    assert!(after_order < RICH - DEPOSIT, "the buy's escrow, not a fee, left the balance");
    // The same deposit declaring the floor goes through.
    assert!(matches!(executor.ingest_tx(paid_deposit_tx.clone()), MempoolAck::Accepted));
    let proposal = executor.prepare_proposal(&budget);
    executor.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: proposal.txs,
        signers: Vec::new(),
    });
    assert!(matches!(
        executor.tx_outcome(&hash(&paid_deposit_tx)),
        Some(TxOutcome::Executed { .. })
    ));
}

#[test]
fn an_unfunded_order_is_refused_at_ingest_even_at_zero_fee() {
    let (_ledger, ex) = rig();
    let mut executor = Executor::new(1_000).with_unsigned_tx_policy(UnsignedTxPolicy::Allow);
    executor.register_module(Arc::new(ex));
    let poor = addr(3);
    let tx = envelope(poor, 0, 0, &msg::place(0, order(Side::Buy, OrderType::Limit)));
    assert!(
        matches!(executor.ingest_tx(tx), MempoolAck::Rejected { .. }),
        "an order its sender cannot fund must not enter the pool"
    );
}

#[test]
fn a_sell_right_after_a_deposit_is_not_refused_for_want_of_custody() {
    // Owner 2 is rich in quote but holds no base custody. A sell with nothing ahead of it is refused at
    // admission; the same sell queued behind a deposit (nonce 1 after nonce 0, same pass) must be admitted,
    // because the custody it needs is about to land. Found by the node governance test, which deposits and
    // sells in one block.
    let (_ledger, ex) = rig();
    let mut executor = Executor::new(1_000).with_unsigned_tx_policy(UnsignedTxPolicy::Allow);
    executor.register_module(Arc::new(ex));
    let trader = addr(2);
    let sell = msg::place(0, order(Side::Sell, OrderType::Limit));
    // Alone (nonce 0, nothing ahead): refused.
    assert!(matches!(
        executor.ingest_tx(envelope(trader, 0, 0, &sell)),
        MempoolAck::Rejected { .. }
    ));
    // Behind a deposit (nonce 0), the sell at nonce 1 is admitted.
    assert!(matches!(
        executor.ingest_tx(envelope(trader, 0, 0, &msg::deposit_base(0, 10_000))),
        MempoolAck::Accepted
    ));
    assert!(
        matches!(executor.ingest_tx(envelope(trader, 1, 0, &sell)), MempoolAck::Accepted),
        "a sell queued behind a deposit must be admitted"
    );
}
