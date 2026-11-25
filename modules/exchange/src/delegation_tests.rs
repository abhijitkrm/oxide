//! Tests for delegations and delegated bundles (`docs/delegated-bundle-spec.md` section 4).

use std::sync::Arc;

use executor::{Event, ExecError, Module, TxContext};
use framework::{Balances, MemoryBalances};
use primitives::Address;
use primitives::fixed::{Price, Qty};

use super::{
    ExchangeModule, MarketConfig, NewOrder, OrderId, OrderType, Side, StpMode, TimeInForce, msg,
};

const OWNERS: u8 = 8;
const MARKETS: u8 = 3;
const RICH: u64 = 1_000_000_000_000_000;
const DEPOSIT: u64 = 1_000_000_000;

fn addr(b: u8) -> Address {
    Address([b; 20])
}

fn agent() -> Address {
    addr(200)
}

fn cfg(id: u8) -> MarketConfig {
    MarketConfig {
        market_id: u16::from(id),
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 4096,
    }
}

fn ctx(sender: Address) -> TxContext {
    TxContext { sender, nonce: 0, fee: 0 }
}

/// A module with owners `1..=OWNERS` funded, with base custody on every market, and the agent funded too.
fn rig() -> (Arc<MemoryBalances>, ExchangeModule) {
    let ledger = Arc::new(MemoryBalances::new());
    let ex = ExchangeModule::with_ledger(ledger.clone());
    for m in 0..MARKETS {
        ex.list_market(cfg(m)).expect("list market");
    }
    for a in (1..=OWNERS).chain([200]) {
        ledger.mint(&addr(a), RICH + DEPOSIT * u64::from(MARKETS));
        for m in 0..MARKETS {
            ex.handle(&ctx(addr(a)), &msg::deposit_base(m, DEPOSIT)).expect("deposit base");
        }
    }
    (ledger, ex)
}

fn order(side: Side, ticks: u64, lots: u64) -> NewOrder {
    NewOrder {
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_000_000_000 + ticks * 1_000_000),
        qty: Qty(lots * 1_000),
        owner: addr(1),
        stp: StpMode::None,
    }
}

fn delegate_all(ex: &ExchangeModule, flags: u8, expiry: u64, cap: u64) {
    for o in 1..=OWNERS {
        ex.handle(&ctx(addr(o)), &msg::delegate(agent(), flags, expiry, cap)).expect("delegate");
    }
}

fn snapshot(
    ledger: &MemoryBalances,
    ex: &ExchangeModule,
) -> (Vec<u64>, Vec<u32>, primitives::Hash) {
    (
        (1..=OWNERS).chain([200]).map(|a| ledger.balance(&addr(a))).collect(),
        (0..MARKETS).map(|m| ex.resting_count(m)).collect(),
        ex.state_root(),
    )
}

/// A stream of (owner, place-or-cancel message) items across owners and markets.
fn items() -> Vec<(Address, Vec<u8>)> {
    let mut out = Vec::new();
    for i in 0..60u64 {
        let owner = addr(1 + u8::try_from(i % u64::from(OWNERS)).unwrap());
        let market = u8::try_from(i % u64::from(MARKETS)).unwrap();
        let side = if i % 2 == 0 { Side::Buy } else { Side::Sell };
        if i % 7 == 6 {
            out.push((owner, msg::cancel(market, OrderId(1 + i % 5))));
        } else {
            out.push((owner, msg::place(market, order(side, 495 + i % 10, 1 + i % 3))));
        }
    }
    out
}

fn event_dump(r: &Result<Vec<Event>, ExecError>) -> String {
    format!("{r:?}")
}

#[test]
fn delegated_bundle_equals_owner_signed_transactions() {
    let (la, a) = rig();
    let (lb, b) = rig();
    delegate_all(&a, 3, u64::MAX, 0);
    delegate_all(&b, 3, u64::MAX, 0);
    // Owner 1 rests a far-from-mid buy on market 0 (the first order of a fresh engine: id 0) in both
    // modules; the stream's first item cancels it, so the comparison covers a real cancel.
    for ex in [&a, &b] {
        ex.handle(&ctx(addr(1)), &msg::place(0, order(Side::Buy, 1, 1))).expect("resting buy");
    }
    let mut items = items();
    items.insert(0, (addr(1), msg::cancel(0, OrderId(0))));
    // Delegated: one bundle signed by the agent.
    let bundle = msg::dbundle(&items).expect("dbundle");
    let delegated = a.handle(&ctx(agent()), &bundle).expect("dbundle runs");
    // Reference: the same items as separate owner-signed transactions, in order.
    let mut separate: Vec<Event> = Vec::new();
    for (owner, item) in &items {
        match b.handle(&ctx(*owner), item) {
            Ok(evs) => separate.extend(evs),
            Err(e) => {
                // A failed item shows up as a rejection event in a bundle; mirror its shape.
                let _ = e;
                separate.push(Event {
                    module: "exchange",
                    kind: "bundle_item_rejected",
                    data: Vec::new(),
                });
            }
        }
    }
    // Compare outcomes ignoring the rejection payloads (indices and error text differ in shape).
    let norm = |evs: &[Event]| -> Vec<String> {
        evs.iter()
            .map(|e| {
                if e.kind == "bundle_item_rejected" {
                    "rejected".to_string()
                } else {
                    format!("{}:{}:{:?}", e.module, e.kind, e.data)
                }
            })
            .collect()
    };
    assert!(
        delegated.iter().filter(|e| e.kind == "fill").count() >= 5,
        "the stream must cross enough to be a meaningful comparison"
    );
    assert!(delegated.iter().any(|e| e.kind == "canceled"), "the stream must include cancels");
    assert_eq!(norm(&delegated), norm(&separate), "events differ");
    assert_eq!(snapshot(&la, &a), snapshot(&lb, &b), "balances, books or state root differ");
}

#[test]
fn items_without_a_valid_delegation_are_rejected_and_move_nothing() {
    let (ledger, ex) = rig();
    let before = snapshot(&ledger, &ex);
    let item = (addr(1), msg::place(0, order(Side::Buy, 500, 1)));
    // 1. No delegation at all.
    let evs =
        ex.handle(&ctx(agent()), &msg::dbundle(std::slice::from_ref(&item)).unwrap()).unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].kind, "bundle_item_rejected");
    assert_eq!(snapshot(&ledger, &ex), before, "an unauthorized item must move nothing");
    // 2. Expired: valid while height < expiry; the module is at height 0, expiry 0.
    ex.handle(&ctx(addr(1)), &msg::delegate(agent(), 3, 0, 0)).unwrap();
    let evs =
        ex.handle(&ctx(agent()), &msg::dbundle(std::slice::from_ref(&item)).unwrap()).unwrap();
    assert_eq!(evs[0].kind, "bundle_item_rejected");
    // 3. Wrong flag: place-only delegation cannot cancel.
    ex.handle(&ctx(addr(1)), &msg::delegate(agent(), 1, u64::MAX, 0)).unwrap();
    let cancel = (addr(1), msg::cancel(0, OrderId(1)));
    let evs = ex.handle(&ctx(agent()), &msg::dbundle(&[cancel]).unwrap()).unwrap();
    assert_eq!(evs[0].kind, "bundle_item_rejected");
    // 4. Notional cap: price 1.5 x qty 1.0 = 1.5 quote; a cap of 1 refuses it.
    ex.handle(&ctx(addr(1)), &msg::delegate(agent(), 3, u64::MAX, 1)).unwrap();
    let before_cap = snapshot(&ledger, &ex);
    let evs =
        ex.handle(&ctx(agent()), &msg::dbundle(std::slice::from_ref(&item)).unwrap()).unwrap();
    assert_eq!(evs[0].kind, "bundle_item_rejected");
    assert_eq!(snapshot(&ledger, &ex), before_cap);
    // 5. The same delegation with a roomy cap accepts it, and the OWNER's balance pays.
    ex.handle(&ctx(addr(1)), &msg::delegate(agent(), 3, u64::MAX, 1_000_000_000)).unwrap();
    let agent_before = ledger.balance(&agent());
    let owner_before = ledger.balance(&addr(1));
    let evs =
        ex.handle(&ctx(agent()), &msg::dbundle(std::slice::from_ref(&item)).unwrap()).unwrap();
    assert_ne!(evs[0].kind, "bundle_item_rejected", "{evs:?}");
    assert_eq!(ledger.balance(&agent()), agent_before, "the agent is not debited");
    assert!(ledger.balance(&addr(1)) < owner_before, "the owner funds the order");
    // 6. Revoked: the next bundle is rejected again.
    ex.handle(&ctx(addr(1)), &msg::revoke_delegate(agent())).unwrap();
    let evs = ex.handle(&ctx(agent()), &msg::dbundle(&[item]).unwrap()).unwrap();
    assert_eq!(evs[0].kind, "bundle_item_rejected");
}

#[test]
fn an_agent_may_trade_its_own_account_without_a_delegation() {
    let (_ledger, ex) = rig();
    let item = (agent(), msg::place(0, order(Side::Buy, 500, 1)));
    let evs = ex.handle(&ctx(agent()), &msg::dbundle(&[item]).unwrap()).unwrap();
    assert_ne!(evs[0].kind, "bundle_item_rejected", "{evs:?}");
}

#[test]
fn malformed_delegations_and_bundles_are_refused() {
    let (_ledger, ex) = rig();
    // Self-delegation, no flags, unknown flag bits.
    assert!(ex.handle(&ctx(addr(1)), &msg::delegate(addr(1), 3, 10, 0)).is_err());
    assert!(ex.handle(&ctx(addr(1)), &msg::delegate(agent(), 0, 10, 0)).is_err());
    assert!(ex.handle(&ctx(addr(1)), &msg::delegate(agent(), 4, 10, 0)).is_err());
    // Truncated delegate; empty and over-long delegated bundles; an amend item; a truncated item.
    assert!(ex.handle(&ctx(addr(1)), &msg::delegate(agent(), 3, 10, 0)[..10]).is_err());
    assert!(ex.handle(&ctx(agent()), &[super::TAG_DBUNDLE, 0, 0]).is_err());
    let amend =
        (addr(1), msg::amend(0, OrderId(1), Price(1_500_000_000), Qty(1_000), StpMode::None));
    assert!(ex.handle(&ctx(agent()), &msg::dbundle(&[amend]).unwrap()).is_err());
    let mut bad = msg::dbundle(&[(addr(1), msg::cancel(0, OrderId(1)))]).unwrap();
    bad.truncate(bad.len() - 3);
    assert!(ex.handle(&ctx(agent()), &bad).is_err());
    assert_eq!(event_dump(&Err(ExecError::Malformed)), "Err(Malformed)");
}

#[test]
fn delegation_is_part_of_the_committed_state_root() {
    let (_l, ex) = rig();
    let before = ex.state_root();
    ex.handle(&ctx(addr(1)), &msg::delegate(agent(), 3, 100, 0)).unwrap();
    let with = ex.state_root();
    assert_ne!(before, with, "a delegation must change the root");
    ex.handle(&ctx(addr(1)), &msg::revoke_delegate(agent())).unwrap();
    assert_eq!(ex.state_root(), before, "revoking restores the root");
}
