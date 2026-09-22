use super::{
    BatchFillEntry, ExchangeModule, MarketConfig, NewOrder, OrderId, OrderType, Side, StpMode,
    TAG_PLACE, TimeInForce, msg,
};
use crate::codec::{encode_reject_reason, encode_side};
use executor::{ExecError, Module, TxContext};
use framework::{Balances, module_id};
use primitives::Address;
use primitives::fixed::{Price, Qty};
use std::sync::Arc;

/// A standard test market: tick 0.01, lot 0.001, [$10, $20], 64 max resting.
fn test_cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: 1_000_000,
        lot_size: 1_000,
        min_price: 1_000_000_000,
        max_price: 2_000_000_000,
        max_resting: 64,
    }
}

fn addr(byte: u8) -> Address {
    Address([byte; 20])
}

fn ctx(sender_byte: u8) -> TxContext {
    TxContext { sender: addr(sender_byte), nonce: 0, fee: 0 }
}

fn limit(side: Side, ticks_from_min: u64, lots: u64, owner_byte: u8) -> NewOrder {
    NewOrder {
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_000_000_000 + ticks_from_min * 1_000_000),
        qty: Qty(lots * 1_000),
        owner: addr(owner_byte),
        stp: StpMode::None,
    }
}

/// Register an off-chain-matched order on-chain under
/// `(owner_byte, client_id)` on market 0. `price`/`qty` are raw
/// scale-8/scale-6 values; a buy escrows `price × qty /
/// PRICE_SCALE` of quote and a sell escrows `qty` of base
/// custody at registration.
fn register(ex: &ExchangeModule, owner: u8, client_id: u64, side: Side, price: u64, qty: u64) {
    ex.handle(&ctx(owner), &msg::register_order(0, side, price, qty, client_id))
        .expect("registration must succeed");
}

/// Deposit `amount` of base custody for `owner` on market 0 —
/// the native debit backing every sell-side obligation.
fn deposit(ex: &ExchangeModule, owner: u8, amount: u64) {
    ex.handle(&ctx(owner), &msg::deposit_base(0, amount)).expect("deposit must succeed");
}

/// A fill leg between two registered orders.
fn leg(
    market: u16,
    price: u64,
    qty: u64,
    buy_owner: u8,
    buy_id: u64,
    sell_owner: u8,
    sell_id: u64,
) -> BatchFillEntry {
    BatchFillEntry {
        market,
        price: Price(price),
        qty: Qty(qty),
        buy: crate::OrderKey { owner: addr(buy_owner), client_id: buy_id },
        sell: crate::OrderKey { owner: addr(sell_owner), client_id: sell_id },
    }
}

/// The standard fixture: a funded buyer and seller with orders
/// registered on market 0 — buy `(1, 1)` at `buy_price`, sell
/// `(9, 1)` at `sell_price`, each for `qty` units. The seller
/// deposits `qty` of base custody first — a sell can only
/// register against base the owner actually holds.
fn registered_pair(
    ledger: &Arc<framework::MemoryBalances>,
    ex: &ExchangeModule,
    buy_price: u64,
    sell_price: u64,
    qty: u64,
) {
    ledger.mint(&addr(1), 10_000_000_000);
    ledger.mint(&addr(9), 10_000_000_000);
    deposit(ex, 9, qty);
    register(ex, 1, 1, Side::Buy, buy_price, qty);
    register(ex, 9, 1, Side::Sell, sell_price, qty);
}

/// A committee stub treating `addr(1)` as the sole validator —
/// the tx-path tests for the gated `TAG_LIST_MARKET` listing.
struct SingleValidatorCommittee;

impl framework::Committee for SingleValidatorCommittee {
    fn is_active_validator(&self, a: &Address) -> bool {
        *a == addr(1)
    }
    fn active_validator_count(&self) -> usize {
        1
    }
    fn power(&self, a: &Address) -> u64 {
        u64::from(self.is_active_validator(a))
    }
    fn total_power(&self) -> u64 {
        1
    }
}

/// A two-member committee stub — `addr(1)` and `addr(2)` each
/// carry one unit of power, so neither reaches the two-thirds
/// quorum alone: endorsement-gated paths need both.
struct TwoValidatorCommittee;

impl framework::Committee for TwoValidatorCommittee {
    fn is_active_validator(&self, a: &Address) -> bool {
        *a == addr(1) || *a == addr(2)
    }
    fn active_validator_count(&self) -> usize {
        2
    }
    fn power(&self, a: &Address) -> u64 {
        u64::from(self.is_active_validator(a))
    }
    fn total_power(&self) -> u64 {
        2
    }
}

#[test]
fn list_market_and_place_resting() {
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();
    assert_eq!(mid, 0);

    // Place a resting buy at tick 500 ($15.00), 5 lots.
    let order = limit(Side::Buy, 500, 5, 1);
    let msg = msg::place(mid, order);
    let events = ex.handle(&ctx(1), &msg).unwrap();

    // One event: the outcome (Resting). No fills (no match).
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "resting");
    assert_eq!(ex.resting_count(mid), 1);
}

#[test]
fn place_and_match_emits_fill_events() {
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();

    // Rest a sell at tick 500, 5 lots, owner 9.
    let maker = limit(Side::Sell, 500, 5, 9);
    ex.handle(&ctx(9), &msg::place(mid, maker)).unwrap();
    assert_eq!(ex.resting_count(mid), 1);

    // Taker buy at tick 500, 5 lots, owner 1 — full fill.
    let taker = limit(Side::Buy, 500, 5, 1);
    let events = ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

    // 1 fill event + 1 outcome event (Filled).
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, "fill");
    assert_eq!(events[1].kind, "filled");
    assert_eq!(ex.resting_count(mid), 0);
}

#[test]
fn cancel_resting_order() {
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();

    // Rest a buy, owner 1.
    let order = limit(Side::Buy, 400, 3, 1);
    let events = ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
    assert_eq!(events[0].kind, "resting");
    // Extract the order id from the resting event data:
    // [market:1][order_id:8][price:8][resting_qty:8]
    let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));
    assert_eq!(ex.resting_count(mid), 1);

    // Cancel it (same owner).
    let cancel_msg = msg::cancel(mid, order_id);
    let cancel_events = ex.handle(&ctx(1), &cancel_msg).unwrap();
    assert_eq!(cancel_events.len(), 1);
    assert_eq!(cancel_events[0].kind, "canceled");
    assert_eq!(ex.resting_count(mid), 0);
}

#[test]
fn cancel_by_non_owner_rejected() {
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();

    // Rest a buy, owner 1.
    let order = limit(Side::Buy, 400, 3, 1);
    let events = ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
    let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));

    // Try to cancel as owner 2 — rejected.
    let err = ex.handle(&ctx(2), &msg::cancel(mid, order_id)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    assert_eq!(ex.resting_count(mid), 1);
}

#[test]
fn place_on_nonexistent_market_rejected() {
    let ex = ExchangeModule::new();
    let order = limit(Side::Buy, 500, 5, 1);
    let err = ex.handle(&ctx(1), &msg::place(0, order)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

#[test]
fn malformed_message_rejected() {
    let ex = ExchangeModule::new();
    assert_eq!(ex.handle(&ctx(1), &[]), Err(ExecError::Malformed));
    // Unknown tag.
    assert_eq!(ex.handle(&ctx(1), &[99]), Err(ExecError::Malformed));
    // Truncated place body.
    assert_eq!(ex.handle(&ctx(1), &[TAG_PLACE, 0]), Err(ExecError::Malformed));
}

#[test]
fn state_root_changes_after_market_listed() {
    let ex = ExchangeModule::new();
    let root0 = ex.state_root();
    ex.list_market(test_cfg()).unwrap();
    let root1 = ex.state_root();
    assert_ne!(root0, root1, "state root must change when a market is listed");
}

#[test]
fn state_root_changes_after_order_rests() {
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();
    let root0 = ex.state_root();

    // C8: a resting order is future-affecting state — it can
    // match, be canceled, or settle — so it MUST move the state
    // root even though the book lives in memory rather than the
    // KV store. Identical roots across validators must prove
    // identical books.
    let order = limit(Side::Buy, 400, 3, 1);
    ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
    let root1 = ex.state_root();
    assert_ne!(root0, root1, "a resting order must change the state root");
}

#[test]
fn state_root_changes_after_cancel() {
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();
    let order = limit(Side::Buy, 400, 3, 1);
    let events = ex.handle(&ctx(1), &msg::place(mid, order)).unwrap();
    let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));
    let root0 = ex.state_root();
    ex.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap();
    let root1 = ex.state_root();
    assert_ne!(root0, root1, "canceling a resting order must change the state root");
}

#[test]
fn state_root_changes_after_fill() {
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();
    // Rest a 5-lot sell; a 3-lot taker buy partially consumes it
    // — the surviving resting qty is different book state.
    let maker = limit(Side::Sell, 500, 5, 9);
    ex.handle(&ctx(9), &msg::place(mid, maker)).unwrap();
    let root0 = ex.state_root();
    let taker = limit(Side::Buy, 500, 3, 1);
    ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();
    let root1 = ex.state_root();
    assert_ne!(root0, root1, "a fill must change the state root");
}

#[test]
fn list_market_via_message() {
    // A single-validator committee reaches quorum on the first
    // endorsement — the tx path then lists exactly like the
    // in-process call.
    let ex = ExchangeModule::new().with_committee(Arc::new(SingleValidatorCommittee));
    let list_msg = msg::list_market(test_cfg());
    let events = ex.handle(&ctx(1), &list_msg).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "market_listed");
    assert_eq!(events[0].data, vec![0]);
}

/// The `TAG_LIST_MARKET` tx path is fail-closed without a
/// committee: an unauthenticated listing eagerly allocates the
/// market's `max_resting` arenas, so a bare module must reject
/// it outright rather than allocate on any sender's word.
#[test]
fn list_market_tx_rejected_without_committee() {
    let ex = ExchangeModule::new();
    let list_msg = msg::list_market(test_cfg());
    let err = ex.handle(&ctx(1), &list_msg).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
    assert_eq!(ex.resting_count(0), 0, "no market may be listed");
}

/// A listing is a governance action: one validator's signature
/// endorses the exact config payload; the market lists only once
/// endorsing power strictly exceeds two-thirds of the committee.
#[test]
fn list_market_requires_committee_quorum() {
    let ex = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    let list_msg = msg::list_market(test_cfg());

    let events = ex.handle(&ctx(1), &list_msg).unwrap();
    assert_eq!(events[0].kind, "list_market_endorse", "one endorsement must not list");
    assert!(ex.l1(0).is_none(), "no market exists yet");

    let events = ex.handle(&ctx(2), &list_msg).unwrap();
    assert_eq!(events[0].kind, "market_listed", "quorum lists the market");
    assert_eq!(events[0].data, vec![0]);
}

/// A non-validator's tx cannot even start a listing proposal —
/// `power == 0` senders are rejected before an endorsement
/// occupies the bounded pending-action set.
#[test]
fn list_market_rejects_powerless_sender() {
    let ex = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    let err = ex.handle(&ctx(9), &msg::list_market(test_cfg())).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
}

/// The bounded pending set must never hold a proposal that
/// cannot apply: a config failing `MarketConfig::validate` —
/// here a `max_resting` above the protocol's `MAX_RESTING_LIMIT`,
/// which would make `list_market` reserve oversized arenas — is
/// rejected before an endorsement is recorded.
#[test]
fn list_market_tx_rejects_unbounded_max_resting() {
    let ex = ExchangeModule::new().with_committee(Arc::new(SingleValidatorCommittee));
    let mut cfg = test_cfg();
    cfg.max_resting = trading::MAX_RESTING_LIMIT + 1;
    let err = ex.handle(&ctx(1), &msg::list_market(cfg)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
}

/// Pending endorsements are future-affecting state: a replica
/// that has not recorded the first validator's vote must diverge
/// in `state_root`, or it would silently disagree about whether
/// the next endorsement lists a market.
#[test]
fn list_market_endorsement_changes_state_root() {
    let ex = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    let root0 = ex.state_root();
    ex.handle(&ctx(1), &msg::list_market(test_cfg())).unwrap();
    let root1 = ex.state_root();
    assert_ne!(root0, root1, "a recorded endorsement is committed state");
}

#[test]
fn multiple_markets_get_sequential_ids() {
    let ex = ExchangeModule::new();
    let id0 = ex.list_market(test_cfg()).unwrap();
    let id1 = ex.list_market(test_cfg()).unwrap();
    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
}

#[test]
fn l1_returns_best_bid_ask() {
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();

    // No orders yet.
    let (bid, ask) = ex.l1(mid).unwrap();
    assert!(bid.is_none());
    assert!(ask.is_none());

    // Rest a buy at tick 400.
    ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 400, 3, 1))).unwrap();
    let (bid, ask) = ex.l1(mid).unwrap();
    assert!(bid.is_some());
    assert!(ask.is_none());
    let (bp, bq) = bid.unwrap();
    assert_eq!(bp, Price(1_400_000_000));
    assert_eq!(bq, Qty(3_000));
}

#[test]
fn reject_reason_encoding_is_stable() {
    // The `as u8` cast must match the trading crate's `#[repr(u8)]`
    // discriminant order. This test pins the mapping so a reorder
    // in the trading crate would surface here.
    assert_eq!(encode_reject_reason(trading::RejectReason::InvalidQty), 0);
}

#[test]
fn module_id_is_exchange() {
    let ex = ExchangeModule::new();
    assert_eq!(ex.id(), module_id::EXCHANGE);
    assert_eq!(ex.name(), "exchange");
}

// ── Settlement tests (cross-module: ledger + exchange) ───────────

fn ledger_and_exchange() -> (Arc<framework::MemoryBalances>, ExchangeModule) {
    let ledger = Arc::new(framework::MemoryBalances::new());
    // Fund two traders: buyer (owner 1) and seller (owner 9).
    ledger.mint(&addr(1), 1_000_000_000_000); // 1T quote
    ledger.mint(&addr(9), 1_000_000_000_000); // 1T quote
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();
    // Both hold base custody too — owner 9 is the usual seller,
    // owner 1 sells in the self-trade tests. Deposits debit
    // native 1:1, so each keeps 1T of quote and 1T of base.
    ledger.mint(&addr(1), 1_000_000_000_000);
    ledger.mint(&addr(9), 1_000_000_000_000);
    deposit(&ex, 1, 1_000_000_000_000);
    deposit(&ex, 9, 1_000_000_000_000);
    (ledger, ex)
}

#[test]
fn settlement_debits_buyer_credits_seller_on_fill() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Rest a sell at tick 500 ($15.00), 5 lots, owner 9.
    let maker = limit(Side::Sell, 500, 5, 9);
    ex.handle(&ctx(9), &msg::place(mid, maker)).unwrap();

    let buyer_before = ledger.balance(&addr(1));
    let seller_before = ledger.balance(&addr(9));

    // Taker buy at tick 500, 5 lots, owner 1 — full fill.
    let taker = limit(Side::Buy, 500, 5, 1);
    ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

    // Notional = 5_000 * 1_500_000_000 = 7_500_000_000_000 (scale-14).
    // Quote amount = 7_500_000_000_000 / 100_000_000 = 75_000
    // (scale-6). The seller nets 75_000 − 75 fee = 74_925 and
    // the buyer received 5_000 base into custody.
    let quote_amount = 75_000u64;
    assert_eq!(ledger.balance(&addr(1)), buyer_before - quote_amount);
    assert_eq!(ledger.balance(&addr(9)), seller_before + quote_amount - 75);
    assert_eq!(ex.base_balance(addr(1), mid), 1_000_000_000_000 + 5_000);
    assert_eq!(ex.fee_vault(mid), 75);
}

#[test]
fn pre_trade_check_rejects_buy_with_insufficient_balance() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    // Fund the buyer with only 1000 — not enough for 5 lots at $15.
    ledger.mint(&addr(1), 1_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();

    // Buy 5 lots at tick 500 ($15): quote needed = 75_000.
    let taker = limit(Side::Buy, 500, 5, 1);
    let err = ex.handle(&ctx(1), &msg::place(0, taker)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    // Balance unchanged.
    assert_eq!(ledger.balance(&addr(1)), 1_000);
}

#[test]
fn no_ledger_means_no_settlement() {
    // Without a ledger, fills are recorded as events but balances
    // don't move. This is the v0 no-settlement mode.
    let ex = ExchangeModule::new();
    let mid = ex.list_market(test_cfg()).unwrap();

    let maker = limit(Side::Sell, 500, 5, 9);
    ex.handle(&ctx(9), &msg::place(mid, maker)).unwrap();

    let taker = limit(Side::Buy, 500, 5, 1);
    let events = ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();
    // 1 fill + 1 outcome (Filled).
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, "fill");
    assert_eq!(events[1].kind, "filled");
}

#[test]
fn settlement_on_sweep_debits_all_fills() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Rest 3 sell orders at ticks 500, 501, 502 (1 lot each, owner 9).
    for i in 0..3u64 {
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500 + i, 1, 9))).unwrap();
    }

    let buyer_before = ledger.balance(&addr(1));
    let seller_before = ledger.balance(&addr(9));

    // Taker buy 3 lots at tick 502 (sweeps all 3 levels).
    let taker = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Ioc,
        price: Price(1_502_000_000),
        qty: Qty(3_000),
        owner: addr(1),
        stp: StpMode::None,
    };
    ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

    // Total quote = (1_500M + 1_501M + 1_502M) * 1_000 / 1e8
    //            = (15_000 + 15_010 + 15_020) = 45_030
    // Fees per fill: 15 + 15 + 15 = 45 (floor per fill).
    let total_quote = 45_030u64;
    assert_eq!(ledger.balance(&addr(1)), buyer_before - total_quote);
    assert_eq!(ledger.balance(&addr(9)), seller_before + total_quote - 45);
    assert_eq!(ex.base_balance(addr(1), mid), 1_000_000_000_000 + 3_000);
}

/// Regression test: a failed seller credit must void the leg
/// wholesale — no quantity consumed, no escrow released. The buy
/// side's escrow was debited at registration, so the proof is
/// that the full `reserved` comes back at cancel afterward.
#[test]
fn batch_settle_failed_credit_voids_leg() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    // Fund buyer with exactly the escrow the order will debit:
    // 1e9 * 100_000 / 1e8 = 1_000_000.
    ledger.mint(&addr(1), 1_000_000);
    // Fund seller near u64::MAX so the credit overflows.
    ledger.mint(&addr(9), u64::MAX - 500_000);
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(1));
    ex.list_market(test_cfg()).unwrap();

    register(&ex, 1, 1, Side::Buy, 1_000_000_000, 100_000);
    // The sell needs base custody: deposit the qty first (the
    // debit drops the seller to u64::MAX - 600_000, still close
    // enough to overflow on the fill's net payment).
    deposit(&ex, 9, 100_000);
    register(&ex, 9, 1, Side::Sell, 1_000_000_000, 100_000);
    // Registration escrowed the full 1_000_000.
    assert_eq!(ledger.balance(&addr(1)), 0);

    // Chain-computed quote = 1e9 * 100_000 / 1e8 = 1_000_000,
    // minus the 10bps fee = 999_000 — still overflows the
    // seller's u64::MAX - 600_000 balance.
    let fill = leg(0, 1_000_000_000, 100_000, 1, 1, 9, 1);
    let events = ex.handle(&ctx(1), &msg::batch_settle(&[fill])).unwrap();
    assert!(
        events.iter().any(|e| e.kind == "settlement_failed"),
        "expected settlement_failed event on credit overflow"
    );
    assert_eq!(
        ledger.balance(&addr(9)),
        u64::MAX - 600_000,
        "seller balance must not change on failed settlement"
    );

    // The leg was voided wholesale: the order still holds its
    // full remaining quantity and escrow — canceling it refunds
    // the entire 1_000_000, proving nothing was consumed.
    let ev = ex.handle(&ctx(1), &msg::cancel_registered(1)).unwrap();
    assert_eq!(ev[0].kind, "order_canceled");
    assert_eq!(ledger.balance(&addr(1)), 1_000_000);
}

/// Regression test: `batch_settle` must reject any sender that is
/// not the configured settlement operator. Before the fix the
/// handler ignored `ctx.sender` entirely — any account could
/// submit forged fills and drain arbitrary balances.
#[test]
fn batch_settle_rejects_unauthorized_sender() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 1_000);
    // Buy escrow debited at registration: 1e9 * 1_000 / 1e8 = 10_000.
    let buyer_after_register = ledger.balance(&addr(1));

    let fill = leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1);
    let msg = msg::batch_settle(&[fill]);

    // ctx(1) is not the operator — must be rejected, no funds move.
    let err = ex.handle(&ctx(1), &msg).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    assert_eq!(ledger.balance(&addr(1)), buyer_after_register);
    // The fixture deposited 1_000 of base for the seller.
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 1_000);

    // The configured operator is accepted.
    let events = ex.handle(&ctx(0xAA), &msg).unwrap();
    assert!(events.iter().any(|e| e.kind == "batch_fill"));
    // Fill at the limit → zero rebate: the whole 10_000 escrow
    // slice pays out — the seller nets 10_000 − 10 fee.
    assert_eq!(ledger.balance(&addr(1)), buyer_after_register);
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 1_000 + 9_990);
}

/// Regression test: `batch_settle` must be fail-closed when no
/// settlement operator is configured.
#[test]
fn batch_settle_disabled_without_operator() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();
    registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 1_000);

    let fill = leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1);
    let msg = msg::batch_settle(&[fill]);
    let err = ex.handle(&ctx(1), &msg).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    // Nothing moved: the seller never got paid and the buy
    // order's escrow stays held. (The fixture's 1_000 base
    // deposit was already debited at registration.)
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 1_000);
}

/// Regression test: every batch-settle leg is validated against
/// the market config AND the registered orders' authorization.
/// Legs failing either layer (unlisted market, off-tick price,
/// out-of-band price, non-lot-aligned or zero qty, self-trade,
/// unknown order key, wrong side for the key, price outside an
/// order's limit, quantity beyond the order's remaining) are
/// skipped with `fill_rejected` events and move no funds.
#[test]
fn batch_settle_rejects_invalid_legs() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();

    // Working pair: buy (1,1) limit $15 qty 100k, sell (9,1)
    // limit $10 qty 100k — the valid leg and the config-invalid
    // legs all reference it.
    registered_pair(&ledger, &ex, 1_500_000_000, 1_000_000_000, 100_000);
    // Self-trade pair: owner 1 holds a sell order too.
    deposit(&ex, 1, 10_000);
    register(&ex, 1, 2, Side::Sell, 1_000_000_000, 10_000);
    // Small pair for the over-remaining leg: 1 lot authorized.
    ledger.mint(&addr(3), 10_000_000_000);
    ledger.mint(&addr(4), 10_000_000_000);
    deposit(&ex, 4, 1_000);
    register(&ex, 3, 1, Side::Buy, 1_500_000_000, 1_000);
    register(&ex, 4, 1, Side::Sell, 1_000_000_000, 1_000);
    // Non-crossing pair for the limit violations: buy $12 max.
    ledger.mint(&addr(5), 10_000_000_000);
    ledger.mint(&addr(6), 10_000_000_000);
    deposit(&ex, 6, 10_000);
    register(&ex, 5, 1, Side::Buy, 1_200_000_000, 10_000);
    register(&ex, 6, 1, Side::Sell, 1_000_000_000, 10_000);
    // High sell limit for the below-limit leg.
    ledger.mint(&addr(8), 10_000_000_000);
    deposit(&ex, 8, 10_000);
    register(&ex, 8, 1, Side::Sell, 1_800_000_000, 10_000);

    let legs = [
        // Unlisted market (orders live on market 0).
        leg(7, 1_000_000_000, 1_000, 1, 1, 9, 1),
        // Off-tick price (1_000_000_500 % 1_000_000 != 0).
        leg(0, 1_000_000_500, 1_000, 1, 1, 9, 1),
        // Price out of band (> 2_000_000_000 max).
        leg(0, 3_000_000_000, 1_000, 1, 1, 9, 1),
        // Zero qty.
        leg(0, 1_000_000_000, 0, 1, 1, 9, 1),
        // Qty not lot-aligned (lot = 1_000).
        leg(0, 1_000_000_000, 1_500, 1, 1, 9, 1),
        // Self-trade: same owner on both sides.
        leg(0, 1_000_000_000, 1_000, 1, 1, 1, 2),
        // Unregistered order key (1, 99) was never registered.
        leg(0, 1_000_000_000, 1_000, 1, 99, 9, 1),
        // Wrong role: the sell order (9,1) as the buy key.
        leg(0, 1_000_000_000, 1_000, 9, 1, 1, 2),
        // Price above the buy's $12 limit.
        leg(0, 1_500_000_000, 1_000, 5, 1, 6, 1),
        // Price below the sell's $18 limit (crossing exists:
        // buy limit $15 ≥ sell $10 but fill is below $18).
        leg(0, 1_500_000_000, 1_000, 1, 1, 8, 1),
        // Qty beyond both orders' remaining (1 lot authorized).
        leg(0, 1_000_000_000, 2_000, 3, 1, 4, 1),
        // One valid leg for contrast: quote = 1e9*1000/1e8 = 10_000.
        leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1),
    ];
    let msg = msg::batch_settle(&legs);
    let events = ex.handle(&ctx(0xAA), &msg).unwrap();

    let rejected = events.iter().filter(|e| e.kind == "fill_rejected").count();
    assert_eq!(rejected, 11, "all eleven invalid legs must be rejected");
    // Only the valid leg settled: seller netted 10_000 − 10 fee
    // = 9_990 of quote (the fixture's 100_000 base deposit was
    // already debited from its ledger balance).
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 100_000 + 9_990);
}

/// Regression test: the chain computes settlement amounts itself.
/// Two legs between the same pair at different prices aggregate
/// into one credit of `sum(price_i * qty_i / PRICE_SCALE)` —
/// the operator cannot inflate or deflate the amount.
#[test]
fn batch_settle_computes_quote_onchain() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    // Buy limit $15 covers both legs; escrow = 1.5e9*3_000/1e8 =
    // 45_000 at registration.
    registered_pair(&ledger, &ex, 1_500_000_000, 1_000_000_000, 3_000);

    // Leg 1: 1e9 * 1_000 / 1e8 = 10_000 (rebate 5_000).
    // Leg 2: 1.5e9 * 2_000 / 1e8 = 30_000 (rebate 0).
    // Seller total = 40_000; released escrow = 45_000.
    let legs = [leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1), leg(0, 1_500_000_000, 2_000, 1, 1, 9, 1)];
    let msg = msg::batch_settle(&legs);
    let events = ex.handle(&ctx(0xAA), &msg).unwrap();

    // Buyer net = −40_000 from the post-registration balance
    // (escrow 45_000 − rebate 5_000 − pays 40_000). Seller nets
    // 40_000 − 40 fee = 39_960; its ledger balance also carried
    // the fixture's 3_000 base deposit.
    assert_eq!(ledger.balance(&addr(1)), 10_000_000_000 - 40_000);
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 3_000 + 39_960);
    // The 40 quote of fees accrued to market 0's vault.
    assert_eq!(ex.fee_vault(0), 40);
    // Exactly one pair credit → one batch_fill event; one buyer
    // rebate → one reservation_released event.
    assert_eq!(events.iter().filter(|e| e.kind == "batch_fill").count(), 1);
    assert_eq!(events.iter().filter(|e| e.kind == "reservation_released").count(), 1);
}

/// The flat aggregation table must emit pair transfers in sorted
/// `(buyer, seller)` order — identical to the `BTreeMap` it
/// replaced — regardless of leg order in the batch. Deterministic
/// event order is consensus-relevant: every validator replays the
/// same drain and must observe the same event sequence.
#[test]
fn batch_settle_pair_order_deterministic() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    // Register an order pair per counterparty: buys (9,1), (1,1),
    // (3,1); sells (7,1), (5,1), (2,1).
    for (buyer, seller) in [(9u8, 7u8), (1, 5), (3, 2)] {
        ledger.mint(&addr(buyer), 10_000_000_000);
        ledger.mint(&addr(seller), 10_000_000_000);
        deposit(&ex, seller, 10_000);
        register(&ex, buyer, 1, Side::Buy, 1_000_000_000, 10_000);
        register(&ex, seller, 1, Side::Sell, 1_000_000_000, 10_000);
    }

    // Submit pairs deliberately out of sorted order: (9,7),
    // (1,5), (3,2) — plus a duplicate (9,7) leg to confirm
    // aggregation collapses it into the sorted (9,7) slot.
    let legs = [
        leg(0, 1_000_000_000, 1_000, 9, 1, 7, 1),
        leg(0, 1_000_000_000, 1_000, 1, 1, 5, 1),
        leg(0, 1_000_000_000, 1_000, 3, 1, 2, 1),
        leg(0, 1_000_000_000, 1_000, 9, 1, 7, 1),
    ];
    let events = ex.handle(&ctx(0xAA), &msg::batch_settle(&legs)).unwrap();

    let pairs: Vec<([u8; 20], [u8; 20])> = events
        .iter()
        .filter(|e| e.kind == "batch_fill")
        .map(|e| (e.data[0..20].try_into().unwrap(), e.data[20..40].try_into().unwrap()))
        .collect();
    assert_eq!(pairs, vec![(addr(1).0, addr(5).0), (addr(3).0, addr(2).0), (addr(9).0, addr(7).0)]);
    // The duplicate (9,7) leg aggregated into one credit of
    // 2×(10_000 − 10 fee) = 19_980 quote units net, paid out of
    // the buy order's escrow (the seller's 10_000 base deposit
    // was already debited).
    assert_eq!(ledger.balance(&addr(7)), 10_000_000_000 - 10_000 + 19_980);
}

/// Regression test: market buys must pass the pre-trade balance
/// check against the real sweep cost. Before the fix, market
/// buys skipped the check entirely (`order_type != Market`), so
/// an unfunded taker could sweep the book and leave every fill
/// unsettled — makers' orders consumed with no payment.
#[test]
fn market_buy_without_balance_rejected() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Rest a maker sell at tick 500 ($15.00), 1 lot.
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();

    // ctx(2) has no ledger balance at all.
    let mkt = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Market,
        tif: TimeInForce::Ioc,
        price: Price(0), // ignored for market orders
        qty: Qty(1_000),
        owner: addr(2),
        stp: StpMode::None,
    };
    let err = ex.handle(&ctx(2), &msg::place(mid, mkt)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    // The maker's order must still be resting — nothing matched.
    assert_eq!(ex.resting_count(mid), 1);
    assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000);
}

/// A funded market buy sweeps and pays exactly the chain-computed
/// fill cost (sweep price × qty), not a wire-supplied amount.
#[test]
fn market_buy_with_balance_settles_sweep() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Rest 2 maker sells: 1 lot @ tick 500 ($15.00), 1 lot @ tick
    // 501 ($15.01).
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 501, 1, 9))).unwrap();

    let buyer_before = ledger.balance(&addr(1));
    let seller_before = ledger.balance(&addr(9));

    // Market buy 2 lots — sweeps both levels.
    let mkt = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Market,
        tif: TimeInForce::Ioc,
        price: Price(0),
        qty: Qty(2_000),
        owner: addr(1),
        stp: StpMode::None,
    };
    ex.handle(&ctx(1), &msg::place(mid, mkt)).unwrap();

    // Cost = 15_000 + 15_010 = 30_010 quote units; seller nets
    // 30_010 − (15 + 15) fees = 29_980 and delivers 2_000 base.
    assert_eq!(ledger.balance(&addr(1)), buyer_before - 30_010);
    assert_eq!(ledger.balance(&addr(9)), seller_before + 30_010 - 30);
    assert_eq!(ex.base_balance(addr(1), mid), 1_000_000_000_000 + 2_000);
    assert_eq!(ex.resting_count(mid), 0);
}

/// A market buy whose sweep cost exceeds the available balance is
/// rejected entirely — the engine must not partially settle.
#[test]
fn market_buy_insufficient_for_full_sweep_rejected() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    // Buyer has only 20_000 quote — enough for the cheap level
    // (15_000) but not the whole sweep (30_010).
    ledger.mint(&addr(1), 20_000);
    ledger.mint(&addr(9), 1_000_000_000_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();
    let mid = 0;
    deposit(&ex, 9, 2_000);

    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 501, 1, 9))).unwrap();

    let mkt = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Market,
        tif: TimeInForce::Ioc,
        price: Price(0),
        qty: Qty(2_000),
        owner: addr(1),
        stp: StpMode::None,
    };
    let err = ex.handle(&ctx(1), &msg::place(mid, mkt)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    // Nothing matched — both makers still rest, no funds moved.
    assert_eq!(ex.resting_count(mid), 2);
    assert_eq!(ledger.balance(&addr(1)), 20_000);
}

// ── Reservation accounting (C6) ────────────────────────────────

/// A resting buy locks its worst-case quote cost at admission:
/// `price × qty` leaves the account the moment the order rests,
/// not when a later taker arrives.
#[test]
fn resting_buy_holds_reservation() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Rest a buy: tick 500 ($15.00), 1 lot → reserve 15_000.
    let events = ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    assert_eq!(events[0].kind, "resting");
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
}

/// Cancelling a resting buy releases exactly the held
/// reservation, exactly once — a second cancel is not found, so
/// the refund cannot be collected twice.
#[test]
fn cancel_resting_buy_refunds_reservation_once() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    let events = ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 2, 1))).unwrap();
    let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));
    // Reservation = 2 lots × 15_000 = 30_000.
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 30_000);

    ex.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap();
    assert_eq!(
        ledger.balance(&addr(1)),
        1_000_000_000_000,
        "cancel must return the held reservation"
    );

    // Second cancel: the order is gone — no double refund.
    let err = ex.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000);
}

/// The core C6 invariant: a maker buy pays from the reservation
/// it held since resting. Fund the maker with EXACTLY the
/// reservation — under the old settle-by-transfer design this is
/// where insolvency surfaced post-place (book consumed, transfer
/// failed). Now settlement is credit-only and cannot fail.
#[test]
fn maker_buy_fill_pays_from_held_reservation() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    // Maker has EXACTLY the reservation: 1 lot @ $15 = 15_000.
    ledger.mint(&addr(5), 15_000);
    ledger.mint(&addr(9), 1_000_000_000_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();
    let mid = 0;
    deposit(&ex, 9, 1_000);

    // Maker rests the buy — balance drops to zero (fully reserved).
    ex.handle(&ctx(5), &msg::place(mid, limit(Side::Buy, 500, 1, 5))).unwrap();
    assert_eq!(ledger.balance(&addr(5)), 0);

    // Taker sell fills the maker's bid. The seller must receive
    // 15_000 − 15 fee even though the buyer's free balance is 0 —
    // the money comes from the held reservation.
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 - 1_000 + 14_985);
    assert_eq!(ledger.balance(&addr(5)), 0, "buyer paid at rest, not at fill");
    assert_eq!(ex.resting_count(mid), 0);
}

/// A partially filled buy releases the filled portion's
/// reservation and keeps only `price × resting_qty` held. The
/// held remainder is what a later cancel refunds.
#[test]
fn partial_fill_buy_holds_only_remainder_reservation() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Maker sell: 1 lot @ tick 500 ($15.00).
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();

    // Taker GTC buy 2 lots @ 500: fills 1 (15_000), rests 1
    // (15_000 held). Reservation was 30_000; refund 0.
    let events = ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 2, 1))).unwrap();
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 30_000);
    let resting_ev = events.iter().find(|e| e.kind == "resting").expect("remainder rests");
    let order_id = OrderId(u64::from_le_bytes(resting_ev.data[1..9].try_into().unwrap()));

    // Cancel the resting remainder — releases the held 15_000.
    ex.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap();
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
    // Seller netted 15_000 − 15 fee for the filled lot.
    assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 + 15_000 - 15);
}

/// An IOC buy's dead remainder is released in full — nothing is
/// held for an order that cannot rest.
#[test]
fn ioc_buy_refunds_dead_remainder() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Maker sell: 1 lot @ tick 500.
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();

    // IOC buy 2 lots @ 500: fills 1 (15_000), remainder dies.
    // Reserved 30_000, paid 15_000, held 0 → refund 15_000.
    let ioc = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Ioc,
        price: Price(1_500_000_000),
        qty: Qty(2_000),
        owner: addr(1),
        stp: StpMode::None,
    };
    ex.handle(&ctx(1), &msg::place(mid, ioc)).unwrap();
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
    assert_eq!(ex.resting_count(mid), 0);
}

/// Price improvement is refunded: a limit buy pays the maker's
/// (better) price, not its own limit.
#[test]
fn limit_buy_price_improvement_refunded() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Maker sell @ tick 500 ($15.00); taker bids tick 600
    // ($16.00) — fills at $15.00, not $16.00.
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 600, 1, 1))).unwrap();

    // Reserved 16_000, paid 15_000 → net 15_000 gone. The seller
    // nets 15_000 − 15 fee.
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 15_000);
    assert_eq!(ledger.balance(&addr(9)), 1_000_000_000_000 + 15_000 - 15);
}

/// An STP-removed resting buy releases its held quote — a
/// resting buy IS its reservation, so deleting the order
/// without reporting the removal would strand `price × qty`
/// forever.
#[test]
fn stp_cancel_oldest_releases_maker_reservation() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    // Owner 1 rests a buy: 10 lots @ tick 500 → holds 150_000.
    let maker = limit(Side::Buy, 500, 10, 1);
    ex.handle(&ctx(1), &msg::place(mid, maker)).unwrap();
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 150_000);

    // The same owner sells with CancelOldest: the resting buy is
    // removed with no fill — its reservation must come back.
    let taker = NewOrder { stp: StpMode::CancelOldest, ..limit(Side::Sell, 500, 10, 1) };
    let events = ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000);
    assert!(events.iter().any(|e| e.kind == "stp_cancel"));
    // The resting buy is gone; the taker's sell rests instead.
    assert_eq!(ex.resting_count(mid), 1);
}

/// A partial STP decrement releases only the consumed slice —
/// the maker's remaining reservation tracks the live book qty.
#[test]
fn stp_decrement_releases_consumed_slice() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    let maker = limit(Side::Buy, 500, 10, 1);
    ex.handle(&ctx(1), &msg::place(mid, maker)).unwrap();

    // Same owner sells 4 lots with DecrementAndCancel: the
    // maker shrinks 10 → 6 with no fill; refund 4 lots = 60_000.
    let taker = NewOrder { stp: StpMode::DecrementAndCancel, ..limit(Side::Sell, 500, 4, 1) };
    let events = ex.handle(&ctx(1), &msg::place(mid, taker)).unwrap();

    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000 - 90_000);
    let dec = events.iter().find(|e| e.kind == "stp_decrement").expect("decrement event");
    // Data tail: [removed_qty:8][remaining:8][owner:20].
    let remaining = u64::from_le_bytes(dec.data[26..34].try_into().unwrap());
    assert_eq!(remaining, 6_000);

    // A later cancel refunds only what the book still holds:
    // price × 6 lots = 90_000 — no double-release of the
    // consumed slice.
    ex.handle(&ctx(1), &msg::cancel(mid, OrderId(0))).unwrap();
    assert_eq!(ledger.balance(&addr(1)), 1_000_000_000_000);
}

/// Snapshot round-trip: a market with resting orders on both
/// sides must export, verify, and re-import byte-identically —
/// the imported module's root must equal the source's (audit
/// 3.2).
#[test]
fn state_snapshot_round_trips() {
    let src = ExchangeModule::new();
    let mid = src.list_market(test_cfg()).unwrap();
    src.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 5, 9))).unwrap();
    src.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 300, 2, 1))).unwrap();
    src.handle(&ctx(2), &msg::place(mid, limit(Side::Buy, 300, 3, 2))).unwrap();

    let snapshot = src.export_state().expect("exchange exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

    let dst = ExchangeModule::new();
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    assert_eq!(dst.resting_count(mid), 3);
    assert_eq!(dst.l1(mid), src.l1(mid));
}

/// A pending list-market endorsement is committed state: after
/// a snapshot round-trip the imported module resumes the tally
/// exactly where the source left it — the second validator's
/// endorsement must reach quorum and list.
#[test]
fn state_snapshot_preserves_pending_endorsements() {
    let src = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    src.handle(&ctx(1), &msg::list_market(test_cfg())).unwrap();

    let snapshot = src.export_state().expect("exchange exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

    let dst = ExchangeModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());

    let events = dst.handle(&ctx(2), &msg::list_market(test_cfg())).unwrap();
    assert_eq!(events[0].kind, "market_listed", "restored tally reaches quorum");
}

/// A truncated blob and a non-canonical stream must both fail
/// inspection — the claimed root is never trusted over the bytes.
#[test]
fn state_snapshot_rejects_corruption() {
    let src = ExchangeModule::new();
    src.list_market(test_cfg()).unwrap();
    let mut snapshot = src.export_state().unwrap();
    snapshot.entries[0].1.truncate(12);
    assert!(src.inspect_state(&snapshot).is_err());
    assert!(ExchangeModule::new().import_state(&snapshot).is_err());
}

// ── Registered-order authorization (batch settlement) ─────────

/// Registration escrows the buy's worst-case cost up front and
/// records the order under `(owner, client_id)`. A duplicate key
/// is rejected — replayed registrations cannot double-authorize.
#[test]
fn register_order_escrows_and_dedups() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();

    // Buy 5 lots at $15: escrow = 1.5e9 * 5_000 / 1e8 = 75_000.
    let events =
        ex.handle(&ctx(1), &msg::register_order(0, Side::Buy, 1_500_000_000, 5_000, 7)).unwrap();
    assert_eq!(events[0].kind, "order_registered");
    assert_eq!(ledger.balance(&addr(1)), 1_000_000 - 75_000);

    // Same key again → rejected (a second signed tx with the
    // same client_id is a new authorization attempt, never a
    // silent overwrite).
    let err = ex
        .handle(&ctx(1), &msg::register_order(0, Side::Buy, 1_500_000_000, 5_000, 7))
        .unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));

    // Sells escrow base custody, not quote: owner 9 deposits
    // 5_000 base, registers the sell, and its ledger balance is
    // untouched while the base moves into the order's `reserved`.
    ledger.mint(&addr(9), 5_000);
    deposit(&ex, 9, 5_000);
    assert_eq!(ledger.balance(&addr(9)), 0);
    ex.handle(&ctx(9), &msg::register_order(0, Side::Sell, 1_000_000_000, 5_000, 3)).unwrap();
    assert_eq!(ledger.balance(&addr(9)), 0);
    assert_eq!(ex.base_balance(addr(9), 0), 0, "sell escrowed the full qty");
    // Cancel returns the escrow to free custody (not the ledger).
    ex.handle(&ctx(9), &msg::cancel_registered(3)).unwrap();
    assert_eq!(ex.base_balance(addr(9), 0), 5_000);
    assert_eq!(ledger.balance(&addr(9)), 0);
}

/// Registration validates the order itself: unlisted market,
/// off-config price/qty, and a buy escrow the sender cannot
/// cover are all rejected — an off-book or unfunded order can
/// never become fillable.
#[test]
fn register_order_validates() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();

    // Unlisted market.
    assert!(matches!(
        ex.handle(&ctx(1), &msg::register_order(7, Side::Sell, 1_000_000_000, 1_000, 1))
            .unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    // Off-tick price.
    assert!(matches!(
        ex.handle(&ctx(1), &msg::register_order(0, Side::Sell, 1_000_000_500, 1_000, 1))
            .unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    // Zero qty.
    assert!(matches!(
        ex.handle(&ctx(1), &msg::register_order(0, Side::Sell, 1_000_000_000, 0, 1)).unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    // Buy escrow exceeds the sender's balance (needs 10_000,
    // has 1_000).
    assert!(matches!(
        ex.handle(&ctx(1), &msg::register_order(0, Side::Buy, 1_000_000_000, 1_000, 1))
            .unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    // The failed registration must not have debited anything.
    assert_eq!(ledger.balance(&addr(1)), 1_000);
}

/// A leg that references an order the owner never registered is
/// rejected and moves no funds — the operator cannot fabricate
/// authorization.
#[test]
fn batch_settle_rejects_unregistered_order() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    ledger.mint(&addr(1), 10_000_000_000);
    ledger.mint(&addr(9), 10_000_000_000);
    deposit(&ex, 9, 10_000);
    register(&ex, 9, 1, Side::Sell, 1_000_000_000, 10_000);

    // The buy key (1,1) was never registered — the operator
    // cannot conjure a buyer.
    let events = ex
        .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
        .unwrap();
    assert!(events.iter().any(|e| e.kind == "fill_rejected"));
    assert!(!events.iter().any(|e| e.kind == "batch_fill"));
    assert_eq!(ledger.balance(&addr(1)), 10_000_000_000);
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 10_000);
}

/// Replay safety: a settled batch cannot settle twice. The second
/// submission re-references orders whose `remaining` is already
/// consumed — every replayed leg fails its quantity check. This
/// is the "unique fill" property: consumption, not a fill-id
/// registry, prevents double settlement.
#[test]
fn batch_settle_replay_consumed_orders() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 2_000);

    let msg = msg::batch_settle(&[leg(0, 1_000_000_000, 2_000, 1, 1, 9, 1)]);
    let first = ex.handle(&ctx(0xAA), &msg).unwrap();
    assert_eq!(first.iter().filter(|e| e.kind == "batch_fill").count(), 1);
    let seller_after = ledger.balance(&addr(9));

    // The identical batch again: both orders are fully consumed
    // — the buy order is gone entirely, so the leg fails.
    let second = ex.handle(&ctx(0xAA), &msg).unwrap();
    assert_eq!(second.iter().filter(|e| e.kind == "batch_fill").count(), 0);
    assert!(second.iter().any(|e| e.kind == "fill_rejected"));
    assert_eq!(ledger.balance(&addr(9)), seller_after);
}

/// Two legs in one batch cannot spend the same authorized
/// quantity — the batch-wide `consumed` bound applies the second
/// time the order is referenced, not just against the map.
#[test]
fn batch_settle_cannot_overspend_within_batch() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    // Both orders authorize exactly 1 lot; two 1-lot legs in the
    // same batch would double-spend them.
    registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 1_000);

    let legs = [leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1), leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)];
    let events = ex.handle(&ctx(0xAA), &msg::batch_settle(&legs)).unwrap();
    assert_eq!(events.iter().filter(|e| e.kind == "batch_fill").count(), 1);
    assert_eq!(events.iter().filter(|e| e.kind == "fill_rejected").count(), 1);
    // 1_000 base deposit + 10_000 − 10 fee netted.
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 1_000 + 9_990);
}

/// Price improvement: a fill below the buy's limit releases the
/// escrow slice at the LIMIT and returns the difference to the
/// buyer — the seller is paid the fill price, the buyer keeps
/// the improvement.
#[test]
fn batch_settle_price_improvement_rebate() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    // Buy limit $15, sell limit $10, fill at $10, 2 lots.
    // Escrow: 1.5e9*2_000/1e8 = 30_000. Pays: 20_000. Rebate: 10_000.
    registered_pair(&ledger, &ex, 1_500_000_000, 1_000_000_000, 2_000);
    let after_register = ledger.balance(&addr(1));

    let events = ex
        .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 2_000, 1, 1, 9, 1)]))
        .unwrap();
    assert!(events.iter().any(|e| e.kind == "reservation_released"));
    // Seller nets 20_000 − 20 fee; its 2_000 base deposit was
    // already debited at registration.
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 2_000 + 19_980);
    assert_eq!(ledger.balance(&addr(1)), after_register + 10_000);
}

/// Cancel refunds the remaining escrow exactly once — a
/// partially filled buy returns `limit × remaining`, and the
/// canceled order can no longer be filled.
#[test]
fn cancel_registered_refunds_residual() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 5_000);
    // Escrow at registration: 50_000. Fill 2 lots (releases
    // 20_000, all to the seller at-limit) → 30_000 remains.
    ex.handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 2_000, 1, 1, 9, 1)])).unwrap();
    let before_cancel = ledger.balance(&addr(1));

    let events = ex.handle(&ctx(1), &msg::cancel_registered(1)).unwrap();
    assert_eq!(events[0].kind, "order_canceled");
    assert_eq!(ledger.balance(&addr(1)), before_cancel + 30_000);

    // The canceled order cannot be filled anymore — a leg
    // referencing it is rejected.
    let events = ex
        .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
        .unwrap();
    assert!(events.iter().any(|e| e.kind == "fill_rejected"));
    // And canceling it twice is rejected too.
    assert!(matches!(
        ex.handle(&ctx(1), &msg::cancel_registered(1)).unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    // Only the owner can cancel — anyone else's cancel misses.
    // (Owner 9's earlier 5_000 deposit is fully escrowed by the
    // live sell; deposit more before registering a second.)
    deposit(&ex, 9, 1_000);
    register(&ex, 9, 9, Side::Sell, 1_000_000_000, 1_000);
    assert!(matches!(
        ex.handle(&ctx(2), &msg::cancel_registered(9)).unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
}

/// Registered orders are committed state: registration must move
/// the state root, and a snapshot round-trip must restore the
/// registry so the imported module authorizes fills identically.
#[test]
fn registered_orders_survive_snapshot() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut src = ExchangeModule::with_ledger(ledger.clone());
    src.set_settlement_operator(addr(0xAA));
    src.list_market(test_cfg()).unwrap();
    let root0 = src.state_root();
    registered_pair(&ledger, &src, 1_000_000_000, 1_000_000_000, 5_000);
    let root1 = src.state_root();
    assert_ne!(root0, root1, "a registered order is committed state");

    let snapshot = src.export_state().expect("exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), root1);

    let mut dst = ExchangeModule::with_ledger(ledger);
    dst.set_settlement_operator(addr(0xAA));
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), root1);

    // The restored registry authorizes the same fill.
    let events = dst
        .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
        .unwrap();
    assert!(events.iter().any(|e| e.kind == "batch_fill"));
}

// ── Base-asset custody (DvP) ────────────────────────────────────

/// Sum every committed base-custody slot: free balances, book
/// holds, and sell-side `reserved` on registered orders. Tests
/// assert this equals deposits minus withdrawals — the custody
/// conservation invariant.
fn total_base_custody(ex: &ExchangeModule) -> u64 {
    let inner = framework::lock_state(&ex.inner);
    let free: u64 = inner.base_balances.values().sum();
    let held: u64 = inner.base_holds.values().sum();
    let escrowed: u64 =
        inner.registered.values().filter(|o| o.side == Side::Sell).map(|o| o.reserved).sum();
    free + held + escrowed
}

/// A deposit debits native 1:1 into free base custody — the
/// module never mints unbacked base.
#[test]
fn deposit_base_debits_native_into_custody() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(2), 50_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();

    let events = ex.handle(&ctx(2), &msg::deposit_base(0, 20_000)).unwrap();
    assert_eq!(events[0].kind, "base_deposited");
    assert_eq!(ledger.balance(&addr(2)), 30_000);
    assert_eq!(ex.base_balance(addr(2), 0), 20_000);
}

/// Deposits debit the sender's ledger balance into custody and
/// withdrawals reverse it — rejected shapes (zero, unlisted
/// market, overdrawn custody) move nothing.
#[test]
fn deposit_withdraw_base_edges() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(2), 50_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();
    let mid = 0;

    deposit(&ex, 2, 20_000);
    assert_eq!(ledger.balance(&addr(2)), 30_000);
    assert_eq!(ex.base_balance(addr(2), mid), 20_000);

    ex.handle(&ctx(2), &msg::withdraw_base(mid, 8_000)).unwrap();
    assert_eq!(ledger.balance(&addr(2)), 38_000);
    assert_eq!(ex.base_balance(addr(2), mid), 12_000);

    // Overdraft: only 12_000 free.
    assert!(matches!(
        ex.handle(&ctx(2), &msg::withdraw_base(mid, 12_001)).unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    // Zero amounts and unlisted markets are rejected.
    assert!(matches!(
        ex.handle(&ctx(2), &msg::deposit_base(mid, 0)).unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    assert!(matches!(
        ex.handle(&ctx(2), &msg::withdraw_base(mid, 0)).unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    assert!(matches!(
        ex.handle(&ctx(2), &msg::deposit_base(200, 1_000)).unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    // Deposit beyond the ledger balance is rejected.
    assert!(matches!(
        ex.handle(&ctx(2), &msg::deposit_base(mid, 99_000_000)).unwrap_err(),
        ExecError::ModuleRejected(_)
    ));
    assert_eq!(ex.base_balance(addr(2), mid), 12_000);
}

/// A sell order on the book path must prove base custody: no
/// deposit → no order. The book is untouched by the rejection.
#[test]
fn sell_rejected_without_base_custody() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(9), 1_000_000_000_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();
    let mid = 0;

    // Owner 9 has quote but no base custody — the sell must
    // reject BEFORE the book is touched.
    let err = ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    assert_eq!(ex.resting_count(mid), 0);

    // Depositing less than the order needs still rejects.
    deposit(&ex, 9, 999);
    assert!(
        ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).is_err(),
        "999 < 1_000 required"
    );
    deposit(&ex, 9, 1);
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    assert_eq!(ex.resting_count(mid), 1);
    // The full qty moved from free custody into the hold.
    assert_eq!(ex.base_balance(addr(9), mid), 0);
    assert_eq!(ex.base_hold(addr(9), mid), 1_000);
}

/// Cancel releases a resting sell's base hold back to free
/// custody — symmetric with the buy-side quote refund.
#[test]
fn cancel_resting_sell_releases_base_hold() {
    let (_ledger, ex) = ledger_and_exchange();
    let mid = 0;
    let free_before = ex.base_balance(addr(9), mid);

    let events = ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 2, 9))).unwrap();
    let order_id = OrderId(u64::from_le_bytes(events[0].data[1..9].try_into().unwrap()));
    assert_eq!(ex.base_hold(addr(9), mid), 2_000);
    assert_eq!(ex.base_balance(addr(9), mid), free_before - 2_000);

    ex.handle(&ctx(9), &msg::cancel(mid, order_id)).unwrap();
    assert_eq!(ex.base_hold(addr(9), mid), 0);
    assert_eq!(ex.base_balance(addr(9), mid), free_before);
}

/// The core `DvP` property on the book path: a fill moves base
/// seller→buyer AND quote buyer→seller in one state transition.
/// The seller's ledger gain is net of the protocol fee; the fee
/// lands in the market vault.
#[test]
fn book_fill_is_delivery_versus_payment() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;
    let seller_free = ex.base_balance(addr(9), mid);
    let buyer_free = ex.base_balance(addr(1), mid);

    // Maker sell 4 lots, taker buy fills 3, remainder rests.
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 4, 9))).unwrap();
    assert_eq!(ex.base_hold(addr(9), mid), 4_000);
    assert_eq!(ex.base_balance(addr(9), mid), seller_free - 4_000);
    let seller_quote = ledger.balance(&addr(9));
    let buyer_quote = ledger.balance(&addr(1));

    let ioc = NewOrder {
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Ioc,
        price: Price(1_500_000_000),
        qty: Qty(3_000),
        owner: addr(1),
        stp: StpMode::None,
    };
    ex.handle(&ctx(1), &msg::place(mid, ioc)).unwrap();

    // Base: 3_000 delivered to the buyer; the maker's hold keeps
    // the 1_000 remainder for its still-resting sell.
    assert_eq!(ex.base_balance(addr(1), mid), buyer_free + 3_000);
    assert_eq!(ex.base_hold(addr(9), mid), 1_000);
    // Quote: buyer paid 45_000 gross; seller netted 45_000 − 45.
    assert_eq!(ledger.balance(&addr(1)), buyer_quote - 45_000);
    assert_eq!(ledger.balance(&addr(9)), seller_quote + 45_000 - 45);
    assert_eq!(ex.fee_vault(mid), 45);
}

/// A taker sell delivers its admission-reserved base to the
/// resting maker buy — and an IOC remainder comes back free.
#[test]
fn taker_sell_delivers_reserved_base() {
    let (ledger, ex) = ledger_and_exchange();
    let mid = 0;

    ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    let taker_free = ex.base_balance(addr(9), mid);
    let maker_free = ex.base_balance(addr(1), mid);
    let seller_quote = ledger.balance(&addr(9));

    // IOC sell 3 lots vs a 1-lot bid: 1 fills, 2 die unfilled.
    let ioc = NewOrder {
        side: Side::Sell,
        order_type: OrderType::Limit,
        tif: TimeInForce::Ioc,
        price: Price(1_000_000_000),
        qty: Qty(3_000),
        owner: addr(9),
        stp: StpMode::None,
    };
    ex.handle(&ctx(9), &msg::place(mid, ioc)).unwrap();

    // 1_000 delivered to the maker; the 2_000 dead remainder
    // released back to the taker's free custody.
    assert_eq!(ex.base_balance(addr(9), mid), taker_free - 1_000);
    assert_eq!(ex.base_balance(addr(1), mid), maker_free + 1_000);
    assert_eq!(ex.base_hold(addr(9), mid), 0);
    assert_eq!(ledger.balance(&addr(9)), seller_quote + 15_000 - 15);
}

/// A GTC sell's unfilled remainder becomes the resting order's
/// hold — not free custody, not stranded.
#[test]
fn gtc_sell_remainder_becomes_hold() {
    let (_ledger, ex) = ledger_and_exchange();
    let mid = 0;
    let free_before = ex.base_balance(addr(9), mid);

    ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 3, 9))).unwrap();

    // 1 lot filled+delivered, 2 rest as the maker hold.
    assert_eq!(ex.base_hold(addr(9), mid), 2_000);
    assert_eq!(ex.base_balance(addr(9), mid), free_before - 3_000);
    assert_eq!(ex.resting_count(mid), 1);
}

/// Registered sells escrow base at registration; cancel refunds
/// to free custody, never the ledger.
#[test]
fn registered_sell_escrow_is_base() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(9), 10_000_000_000);
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.list_market(test_cfg()).unwrap();

    // A sell registration without base custody is rejected.
    assert!(matches!(
        ex.handle(&ctx(9), &msg::register_order(0, Side::Sell, 1_000_000_000, 5_000, 1))
            .unwrap_err(),
        ExecError::ModuleRejected(_)
    ));

    deposit(&ex, 9, 5_000);
    register(&ex, 9, 1, Side::Sell, 1_000_000_000, 5_000);
    assert_eq!(ex.base_balance(addr(9), 0), 0);

    ex.handle(&ctx(9), &msg::cancel_registered(1)).unwrap();
    assert_eq!(ex.base_balance(addr(9), 0), 5_000);
    assert_eq!(ledger.balance(&addr(9)), 10_000_000_000 - 5_000);
}

/// The batch path delivers base seller→buyer custody alongside
/// the quote credit, consumes the sell's escrow qty-for-qty, and
/// accrues the fee — all in one committed transition.
#[test]
fn batch_settle_delivers_base_and_fee() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    registered_pair(&ledger, &ex, 1_000_000_000, 1_000_000_000, 5_000);
    // The fixture deposited 5_000 for the sell — all escrowed.
    assert_eq!(ex.base_balance(addr(9), 0), 0);

    // Fill 2 lots at $10: pays 20_000, fee 20.
    let ev = ex
        .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 2_000, 1, 1, 9, 1)]))
        .unwrap();
    assert!(ev.iter().any(|e| e.kind == "batch_fill"));
    assert!(ev.iter().any(|e| e.kind == "base_delivered"));
    assert_eq!(ex.base_balance(addr(1), 0), 2_000);
    assert_eq!(ex.fee_vault(0), 20);

    // The sell's remaining escrow is 3_000 — cancelable back to
    // free custody.
    ex.handle(&ctx(9), &msg::cancel_registered(1)).unwrap();
    assert_eq!(ex.base_balance(addr(9), 0), 3_000);
}

/// Conservation: free custody + book holds + sell-side escrow
/// always equal deposits minus withdrawals, across a mixed
/// sequence of places, fills, cancels, deposits, withdrawals,
/// and a batch settle. The complementary native-side invariant:
/// total minted = Σ free ledger balances + Σ base custody +
/// buy-side escrows + the fee vault (resting book buys hold
/// `limit × remaining` implicitly — none rest at the end here).
#[test]
fn base_custody_conserves_across_mixed_ops() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(addr(0xAA));
    ex.list_market(test_cfg()).unwrap();
    ledger.mint(&addr(1), 10_000_000_000);
    ledger.mint(&addr(9), 10_000_000_000);
    ledger.mint(&addr(3), 10_000_000_000);
    let mid = 0;
    let minted = 30_000_000_000u64;

    // Deposits: 7_000 + 4_000 + 2_000 = 13_000 custodied.
    deposit(&ex, 9, 7_000);
    deposit(&ex, 1, 4_000);
    deposit(&ex, 3, 2_000);
    assert_eq!(total_base_custody(&ex), 13_000);

    // Rest a 4-lot sell (9) and a 2-lot sell (3); partially fill
    // 9's order with a taker buy; withdraw some free custody.
    ex.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 4, 9))).unwrap();
    ex.handle(&ctx(3), &msg::place(mid, limit(Side::Sell, 501, 2, 3))).unwrap();
    assert_eq!(total_base_custody(&ex), 13_000);
    ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 2, 1))).unwrap();
    assert_eq!(total_base_custody(&ex), 13_000);
    ex.handle(&ctx(1), &msg::withdraw_base(mid, 1_000)).unwrap();
    assert_eq!(total_base_custody(&ex), 12_000);

    // Registered pair + batch fill of 1 lot.
    deposit(&ex, 9, 3_000);
    register(&ex, 1, 7, Side::Buy, 1_000_000_000, 1_000);
    register(&ex, 9, 7, Side::Sell, 1_000_000_000, 1_000);
    assert_eq!(total_base_custody(&ex), 15_000);
    ex.handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 7, 9, 7)])).unwrap();
    assert_eq!(total_base_custody(&ex), 15_000);

    // Sweep the best ask — 9's 2-lot remainder @500 — with a
    // taker buy: the maker's hold drains into the buyer's
    // custody; total unchanged.
    ex.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 501, 2, 1))).unwrap();
    assert_eq!(total_base_custody(&ex), 15_000);

    // Native-side conservation: supply = free ledger + base
    // custody + buy escrows + fee vault. No book buys rest at
    // the end (the sweep filled all asks within its limit) and
    // the registered buy was fully consumed, so no implicit
    // quote holds remain.
    let ledger_total: u64 = [addr(1), addr(3), addr(9)].iter().map(|a| ledger.balance(a)).sum();
    let custody = total_base_custody(&ex);
    let buy_escrow: u64 = framework::lock_state(&ex.inner)
        .registered
        .values()
        .filter(|o| o.side == Side::Buy)
        .map(|o| o.reserved)
        .sum();
    assert_eq!(
        minted,
        ledger_total + custody + buy_escrow + ex.fee_vault(0),
        "supply == free + base custody + buy escrows + fee vault"
    );
}

/// Custody maps are committed state: a snapshot round-trip must
/// restore free balances, book holds, and the fee vault — a
/// replica that lost them would settle different fills.
#[test]
fn custody_state_survives_snapshot() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 10_000_000_000);
    ledger.mint(&addr(9), 10_000_000_000);
    let mut src = ExchangeModule::with_ledger(ledger.clone());
    src.set_settlement_operator(addr(0xAA));
    src.list_market(test_cfg()).unwrap();
    deposit(&src, 9, 10_000);
    deposit(&src, 1, 5_000);
    // Rest a sell (hold 4_000), fill 1 lot via a registered pair
    // (fee accrues), leave free balances behind.
    src.handle(&ctx(9), &msg::place(0, limit(Side::Sell, 500, 4, 9))).unwrap();
    register(&src, 1, 1, Side::Buy, 1_000_000_000, 1_000);
    register(&src, 9, 1, Side::Sell, 1_000_000_000, 1_000);
    src.handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 1)]))
        .unwrap();
    let root = src.state_root();

    let snapshot = src.export_state().expect("exports state");
    let mut dst = ExchangeModule::with_ledger(ledger);
    dst.set_settlement_operator(addr(0xAA));
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), root, "custody state is committed");
    assert_eq!(dst.base_hold(addr(9), 0), 4_000);
    assert_eq!(dst.base_balance(addr(1), 0), 5_000 + 1_000);
    assert_eq!(dst.fee_vault(0), 10);
}

/// Pre-custody blobs decode with empty custody maps — and a
/// registered sell that predates custody (`reserved == 0`) is
/// unfillable but cancelable. Fail-closed, not grandfathered.
#[test]
fn pre_custody_sell_orders_cannot_settle() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 10_000_000_000);
    ledger.mint(&addr(9), 10_000_000_000);
    let mut src = ExchangeModule::with_ledger(ledger.clone());
    src.set_settlement_operator(addr(0xAA));
    src.list_market(test_cfg()).unwrap();
    // A live buy with real escrow stays fillable post-import.
    register(&src, 1, 1, Side::Buy, 1_000_000_000, 5_000);

    // Hand-craft a pre-custody blob: decode the source's own
    // export, inject a naked sell (`reserved == 0`, the legacy
    // shape), and re-encode WITHOUT the trailing custody
    // section — exactly what a pre-upgrade blob contains.
    let snapshot = src.export_state().expect("exports state");
    let (canon_bytes, store_map) =
        framework::decode_state_blob(&snapshot.entries[0].1).expect("blob decodes");
    let mut r = framework::CanonicalReader::new(canon_bytes);
    // `stage_blob_snapshot` consumes the store-subtree root
    // before handing the reader to the module decoder.
    assert_eq!(
        r.get_root().expect("root"),
        framework::subtree_root_map(&store_map),
        "store section must hash to the committed root"
    );
    let (markets, endorsements, mut registered, _, _, _) =
        ExchangeModule::decode_committed(&mut r, &store_map, 256).expect("decodes");
    registered.insert(
        crate::OrderKey { owner: addr(9), client_id: 9 },
        crate::RegisteredOrder {
            market: 0,
            side: Side::Sell,
            limit_price: 1_000_000_000,
            remaining: 5_000,
            reserved: 0,
        },
    );
    let mut w = framework::CanonicalState::new();
    w.put_root(&framework::subtree_root_map(&store_map));
    w.put_count(markets.len());
    let mut book_bytes = Vec::new();
    let mut entries = Vec::new();
    for engine in &markets {
        match engine {
            Some(e) => {
                w.put_u8(1);
                book_bytes.clear();
                e.write_canonical_state(&mut book_bytes, &mut entries);
                w.put_bytes(&book_bytes);
            }
            None => {
                w.put_u8(0);
            }
        }
    }
    endorsements.write_canonical(&mut w);
    w.put_count(registered.len());
    for (key, order) in &registered {
        w.put_addr(&key.owner);
        w.put_u64(key.client_id);
        w.put_u16(order.market);
        w.put_u8(encode_side(order.side));
        w.put_u64(order.limit_price);
        w.put_u64(order.remaining);
        w.put_u64(order.reserved);
    }
    // No custody tail — the pre-upgrade blob shape.
    let kv: framework::KVStore = std::sync::Mutex::new(store_map);
    let snapshot = storage::Snapshot {
        height: 0,
        entries: vec![(
            framework::state_blob_key(),
            framework::encode_state_blob(w.as_bytes(), &kv),
        )],
    };

    let mut dst = ExchangeModule::with_ledger(ledger.clone());
    dst.set_settlement_operator(addr(0xAA));
    dst.import_state(&snapshot).unwrap();

    // The legacy sell cannot settle — `reserved` (0) < any qty.
    let events = dst
        .handle(&ctx(0xAA), &msg::batch_settle(&[leg(0, 1_000_000_000, 1_000, 1, 1, 9, 9)]))
        .unwrap();
    assert!(events.iter().any(|e| e.kind == "fill_rejected"));
    assert!(!events.iter().any(|e| e.kind == "batch_fill"));

    // …but it can still be canceled (refund = 0 base, harmless).
    dst.handle(&ctx(9), &msg::cancel_registered(9)).unwrap();
}

// ── Property tests ───────────────────────────────────────────
//
// The fixed tests above pin specific sequences; these sweep the
// op space itself. The property under test is the custody
// conservation invariant: the committed base maps (free custody
// + book holds + sell-side `reserved`) always equal deposits
// minus withdrawals — the module can neither mint nor lose a
// base unit, regardless of the order in which fills, cancels,
// STP removals, and dead remainders interleave.

use proptest::prelude::*;

// One random op: `(owner_idx, kind, amount, tick)` where `kind`
// selects deposit/withdraw/limit-sell/limit-buy/IOC-sell/IOC-
// buy/cancel. Amounts and ticks are deliberately small and
// lot-aligned so most orders are admissible — the invariant
// must hold through successes AND rejections alike.
proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(48))]

    #[test]
    fn base_custody_conserved_over_random_ops(
        ops in proptest::collection::vec(
            (0u8..3, 0u8..7, 1_000u64..50_000, 0u64..3),
            1..192,
        ),
    ) {
        let ledger = Arc::new(framework::MemoryBalances::new());
        let ex = ExchangeModule::with_ledger(ledger.clone());
        ex.list_market(test_cfg()).unwrap();
        let owners = [1u8, 9, 3];
        for w in owners {
            ledger.mint(&addr(w), u64::MAX / 4);
        }
        let mid = 0u8;
        // Each owner's live resting orders — cancels draw only
        // from this set so they exercise the release path.
        let mut resting: [Vec<OrderId>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        let mut custodied = 0u64;

        for (who, op, amount, tick) in ops {
            let wi = usize::from(who);
            let lots = (amount / 1_000 % 8) + 1;
            let res = match op {
                0 => ex.handle(&ctx(who), &msg::deposit_base(mid, amount)),
                1 => ex.handle(&ctx(who), &msg::withdraw_base(mid, amount)),
                2 => ex.handle(&ctx(who), &msg::place(mid, limit(Side::Sell, tick, lots, who))),
                3 => ex.handle(&ctx(who), &msg::place(mid, limit(Side::Buy, tick, lots, who))),
                4 => ex.handle(
                    &ctx(who),
                    &msg::place(
                        mid,
                        NewOrder {
                            side: Side::Sell,
                            order_type: OrderType::Limit,
                            tif: TimeInForce::Ioc,
                            price: Price(1_000_000_000 + tick * 1_000_000),
                            qty: Qty(lots * 1_000),
                            owner: addr(who),
                            stp: StpMode::None,
                        },
                    ),
                ),
                5 => ex.handle(
                    &ctx(who),
                    &msg::place(
                        mid,
                        NewOrder {
                            side: Side::Buy,
                            order_type: OrderType::Limit,
                            tif: TimeInForce::Ioc,
                            price: Price(1_000_000_000 + tick * 1_000_000),
                            qty: Qty(lots * 1_000),
                            owner: addr(who),
                            stp: StpMode::None,
                        },
                    ),
                ),
                _ => {
                    // Cancel the owner's oldest tracked resting
                    // order, if any; otherwise a harmless no-op.
                    match resting[wi].first().copied() {
                        Some(id) => {
                            let r = ex.handle(&ctx(who), &msg::cancel(mid, id));
                            // Err means the id is dead (filled
                            // or already canceled) — either way
                            // it is no longer live, so untrack.
                            resting[wi].remove(0);
                            r
                        }
                        None => continue,
                    }
                }
            };
            let Ok(events) = res else {
                // Rejected ops move nothing — still assert.
                prop_assert_eq!(total_base_custody(&ex), custodied);
                continue;
            };
            match op {
                0 => custodied += amount,
                1 => custodied -= amount,
                2 | 3 => {
                    // A GTC place that rests emits its order id
                    // in the trailing "resting" outcome event.
                    if let Some(e) = events.iter().find(|e| e.kind == "resting") {
                        let id = OrderId(u64::from_le_bytes(
                            e.data[1..9].try_into().unwrap(),
                        ));
                        resting[wi].push(id);
                    }
                    // Filled orders may drop other owners' ids —
                    // prune anything no longer cancelable lazily:
                    // a stale id just makes cancel return Err,
                    // which the `is_ok` gate already filters.
                }
                _ => {}
            }
            prop_assert_eq!(total_base_custody(&ex), custodied);
        }
    }
}

// ── Governance parameter sink ────────────────────────────────
// The fee vault's only exit is the governance apply path: a
// deposited, quorum-decided, timelocked proposal delivers
// `exchange.fee_vault.withdraw` → `[market][dest][amount]`.

/// Encode a `fee_vault.withdraw` value: `[market:1B][dest:20B]
/// [amount:8B LE]`.
fn withdraw_value(market: u8, dest: u8, amount: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(29);
    v.push(market);
    v.extend_from_slice(&addr(dest).0);
    v.extend_from_slice(&amount.to_le_bytes());
    v
}

/// A passed governance withdrawal pays the vault's accrued fees
/// out of custody to the mandated destination — and the vault
/// decrements exactly, so the committed accounting stays closed.
#[test]
fn fee_vault_withdrawal_pays_out_via_governance() {
    let (ledger, ex) = ledger_and_exchange();
    // Accrue 75 in fees with a real fill (sell 5 lots @500 vs
    // buy 5 lots @500 — fee = FEE_BPS of the 75_000 quote leg).
    ex.handle(&ctx(9), &msg::place(0, limit(Side::Sell, 500, 5, 9))).unwrap();
    ex.handle(&ctx(1), &msg::place(0, limit(Side::Buy, 500, 5, 1))).unwrap();
    assert_eq!(ex.fee_vault(0), 75);

    let dest = addr(0x42);
    let before = ledger.balance(&dest);
    framework::ParameterSink::apply_param(
        &ex,
        b"exchange.fee_vault.withdraw",
        &withdraw_value(0, 0x42, 50),
    )
    .unwrap();
    assert_eq!(ledger.balance(&dest), before + 50);
    assert_eq!(ex.fee_vault(0), 25, "vault decremented by the paid amount");

    // Drain the rest — the vault goes to zero, never negative.
    framework::ParameterSink::apply_param(
        &ex,
        b"exchange.fee_vault.withdraw",
        &withdraw_value(0, 0x42, 25),
    )
    .unwrap();
    assert_eq!(ex.fee_vault(0), 0);
    assert!(
        framework::ParameterSink::apply_param(
            &ex,
            b"exchange.fee_vault.withdraw",
            &withdraw_value(0, 0x42, 1),
        )
        .is_err()
    );
    assert_eq!(ex.fee_vault(0), 0, "failed withdrawal left the vault untouched");
}

/// The sink owns its keyspace: foreign keys, malformed values,
/// zero amounts, and vault overdrafts all reject — governance
/// records `ApplyFailed`, never a partial or silent effect.
#[test]
fn fee_vault_sink_rejects_bad_applies() {
    let (ledger, ex) = ledger_and_exchange();
    ex.handle(&ctx(9), &msg::place(0, limit(Side::Sell, 500, 5, 9))).unwrap();
    ex.handle(&ctx(1), &msg::place(0, limit(Side::Buy, 500, 5, 1))).unwrap();
    assert_eq!(ex.fee_vault(0), 75);
    let dest = addr(0x42);
    let before = ledger.balance(&dest);

    // A key the exchange does not own — the prefix routed here
    // but the path is foreign.
    assert!(
        framework::ParameterSink::apply_param(
            &ex,
            b"exchange.orderbook.steal",
            &withdraw_value(0, 0x42, 1),
        )
        .is_err()
    );
    // Malformed value lengths.
    assert!(
        framework::ParameterSink::apply_param(&ex, b"exchange.fee_vault.withdraw", &[1, 2, 3],)
            .is_err()
    );
    // Zero amount — a no-op withdrawal is meaningless.
    assert!(
        framework::ParameterSink::apply_param(
            &ex,
            b"exchange.fee_vault.withdraw",
            &withdraw_value(0, 0x42, 0),
        )
        .is_err()
    );
    // Overdraft — the vault holds 75.
    assert!(
        framework::ParameterSink::apply_param(
            &ex,
            b"exchange.fee_vault.withdraw",
            &withdraw_value(0, 0x42, 76),
        )
        .is_err()
    );
    // An unlisted market has no vault — implicitly insufficient.
    assert!(
        framework::ParameterSink::apply_param(
            &ex,
            b"exchange.fee_vault.withdraw",
            &withdraw_value(9, 0x42, 1),
        )
        .is_err()
    );
    assert_eq!(ex.fee_vault(0), 75);
    assert_eq!(ledger.balance(&dest), before, "rejections moved nothing");
}
