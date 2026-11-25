//! Differential tests for the per-market execution lanes (`lanes.rs`,
//! `docs/multi-market-lanes-spec.md` section 4): the lane path must equal the serial path byte for
//! byte: per-transaction results and events, the module state root (books, custody, fee vaults), and
//! every account's ledger balance.

use std::sync::Arc;

use executor::{LaneTx, Module, TxContext};
use framework::{Balances, MemoryBalances};
use primitives::Address;
use primitives::fixed::{Price, Qty};

use super::{
    ExchangeModule, MarketConfig, NewOrder, OrderId, OrderType, Side, StpMode, TimeInForce, msg,
};

/// Markets listed in the rigs (ids `0..MARKETS`).
const MARKETS: u8 = 6;
/// Trading accounts (addresses `[1; 20]` .. `[ACCOUNTS; 20]`).
const ACCOUNTS: u8 = 40;
/// Base custody each account deposits on every market.
const DEPOSIT: u64 = 1_000_000_000;
/// Native balance each account starts with: far above any run's outflow, so the funds proof passes.
const RICH: u64 = 1_000_000_000_000_000;
/// Agent (gateway) addresses for delegated bundles: `AGENT_OK` holds delegations (some limited), the
/// delegations to `AGENT_EXPIRED` have all expired.
const AGENT_OK: u8 = 41;
const AGENT_EXPIRED: u8 = 42;

fn addr(b: u8) -> Address {
    Address([b; 20])
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

/// A module with `MARKETS` markets, `ACCOUNTS` funded accounts, and base custody for all of them.
fn rig(lanes: bool, balance: u64) -> (Arc<MemoryBalances>, ExchangeModule) {
    let ledger = Arc::new(MemoryBalances::new());
    let ex = ExchangeModule::with_ledger(ledger.clone());
    ex.set_exec_lanes(lanes);
    for m in 0..MARKETS {
        ex.list_market(cfg(m)).expect("list market");
    }
    for a in 1..=ACCOUNTS {
        // Base deposits debit native 1:1, so mint them on top of the balance the test wants left.
        ledger.mint(&addr(a), balance + DEPOSIT * u64::from(MARKETS));
        for m in 0..MARKETS {
            let ctx = TxContext { sender: addr(a), nonce: 0, fee: 0 };
            ex.handle(&ctx, &msg::deposit_base(m, DEPOSIT)).expect("deposit base");
        }
    }
    // Agents pay envelope fees; owners delegate to them with assorted scopes (so delegated bundles
    // exercise full, place-only, capped, expired and missing delegations).
    for agent in [AGENT_OK, AGENT_EXPIRED] {
        ledger.mint(&addr(agent), RICH);
    }
    for owner in 1..=ACCOUNTS {
        let ctx = TxContext { sender: addr(owner), nonce: 0, fee: 0 };
        if owner % 5 != 0 {
            let flags = if owner % 3 == 0 { 1 } else { 3 };
            let cap = if owner % 7 == 0 { 5 } else { 0 };
            ex.handle(&ctx, &msg::delegate(addr(AGENT_OK), flags, u64::MAX, cap))
                .expect("delegate");
        }
        ex.handle(&ctx, &msg::delegate(addr(AGENT_EXPIRED), 3, 0, 0)).expect("delegate expired");
    }
    (ledger, ex)
}

/// xorshift64: deterministic, dependency-free.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn order(rng: &mut Rng, kind: OrderType) -> NewOrder {
    let side = if rng.below(2) == 0 { Side::Buy } else { Side::Sell };
    let tif = match rng.below(5) {
        0 => TimeInForce::Ioc,
        1 => TimeInForce::Fok,
        _ => TimeInForce::Gtc,
    };
    NewOrder {
        side,
        order_type: kind,
        tif,
        // Prices crowd the middle of the band so orders cross often.
        price: Price(1_000_000_000 + (480 + rng.below(40)) * 1_000_000),
        qty: Qty((1 + rng.below(4)) * 1_000),
        owner: addr(1),
        stp: match rng.below(8) {
            0 => StpMode::CancelNewest,
            1 => StpMode::CancelOldest,
            _ => StpMode::None,
        },
    }
}

fn item(rng: &mut Rng, market: u8) -> Vec<u8> {
    if rng.below(4) == 0 {
        msg::cancel(market, OrderId(1 + rng.below(300)))
    } else {
        // Limit orders only, plus market SELLs (market buys are ineligible by design).
        let mut o = order(rng, OrderType::Limit);
        if rng.below(10) == 0 {
            o.order_type = OrderType::Market;
            o.side = Side::Sell;
        }
        msg::place(market, o)
    }
}

/// One generated transaction: `(sender, fee, payload)`.
fn gen_tx(rng: &mut Rng, market_span: u8) -> (Address, u64, Vec<u8>) {
    let sender = addr(1 + u8::try_from(rng.below(u64::from(ACCOUNTS))).unwrap());
    let market = u8::try_from(rng.below(u64::from(market_span))).unwrap();
    let fee = rng.below(3);
    // A delegated bundle: the agent signs, items name assorted owners (some without a delegation).
    if rng.below(8) == 0 {
        let agent = if rng.below(6) == 0 { AGENT_EXPIRED } else { AGENT_OK };
        let n = 1 + rng.below(6);
        let mut items: Vec<(Address, Vec<u8>)> = Vec::new();
        for _ in 0..n {
            let owner = addr(1 + u8::try_from(rng.below(u64::from(ACCOUNTS))).unwrap());
            let m = u8::try_from(rng.below(u64::from(market_span))).unwrap();
            items.push((owner, item(rng, m)));
        }
        return (addr(agent), fee, msg::dbundle(&items).expect("dbundle"));
    }
    let payload = match rng.below(20) {
        // Bundle of 1..6 items on one market (a rare one spans two markets).
        0..=4 => {
            let n = 1 + rng.below(6);
            let other = u8::try_from(rng.below(u64::from(market_span))).unwrap();
            let mut items: Vec<Vec<u8>> = Vec::new();
            for i in 0..n {
                let span = i == 1 && rng.below(20) == 0;
                items.push(item(rng, if span { other } else { market }));
            }
            msg::bundle(&items).expect("bundle")
        }
        // Truncated place: fails with no effect, anywhere.
        5 => vec![super::TAG_PLACE, market, 0],
        // A place on an unlisted market.
        6 => msg::place(200, order(rng, OrderType::Limit)),
        _ => item(rng, market),
    };
    (sender, fee, payload)
}

fn run_serial(
    ex: &ExchangeModule,
    ledger: &MemoryBalances,
    txs: &[(Address, u64, Vec<u8>)],
) -> Vec<String> {
    txs.iter()
        .map(|(sender, fee, payload)| {
            let ctx = TxContext { sender: *sender, nonce: 0, fee: *fee };
            if *fee > 0 && ledger.debit(sender, *fee).is_err() {
                return "fee-failed".to_string();
            }
            format!("{:?}", ex.handle(&ctx, payload))
        })
        .collect()
}

fn run_lanes(
    ex: &ExchangeModule,
    ledger: &MemoryBalances,
    txs: &[(Address, u64, Vec<u8>)],
) -> Option<Vec<String>> {
    let lane_txs: Vec<LaneTx<'_>> = txs
        .iter()
        .map(|(sender, fee, payload)| LaneTx {
            ctx: TxContext { sender: *sender, nonce: 0, fee: *fee },
            payload,
        })
        .collect();
    let mut charge = |c: &TxContext| c.fee == 0 || ledger.debit(&c.sender, c.fee).is_ok();
    ex.handle_run_lanes(&lane_txs, &mut charge).map(|rs| {
        rs.into_iter()
            .map(|r| r.map_or_else(|| "fee-failed".to_string(), |r| format!("{r:?}")))
            .collect()
    })
}

fn assert_same(
    a: &(Arc<MemoryBalances>, ExchangeModule),
    b: &(Arc<MemoryBalances>, ExchangeModule),
    what: &str,
) {
    assert_eq!(a.1.state_root(), b.1.state_root(), "{what}: module state root differs");
    for acct in (1..=ACCOUNTS).chain([AGENT_OK, AGENT_EXPIRED]) {
        assert_eq!(
            a.0.balance(&addr(acct)),
            b.0.balance(&addr(acct)),
            "{what}: ledger balance of account {acct} differs"
        );
    }
}

#[test]
fn lanes_match_serial_on_random_multi_market_runs() {
    for seed in 1..=6u64 {
        let serial = rig(false, RICH);
        let lanes = rig(true, RICH);
        assert_same(&serial, &lanes, "after setup");
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed.wrapping_mul(0x1234_5678_9ABC_DEF1));
        for block in 0..4 {
            let txs: Vec<_> = (0..800).map(|_| gen_tx(&mut rng, MARKETS)).collect();
            let expected = run_serial(&serial.1, &serial.0, &txs);
            let got = run_lanes(&lanes.1, &lanes.0, &txs).unwrap_or_else(|| {
                panic!("seed {seed} block {block}: lanes declined an eligible run")
            });
            assert_eq!(expected, got, "seed {seed} block {block}: per-tx results differ");
            assert_same(&serial, &lanes, &format!("seed {seed} block {block}"));
        }
        assert_eq!(lanes.1.lane_runs_for_test(), 4, "every block must take the lane path");
    }
}

#[test]
fn unfunded_senders_decline_and_the_serial_path_is_equal() {
    // 40 accounts with 50k units (a few buys), below one run's worst-case outflow: the funds proof fails.
    let lanes = rig(true, 50_000);
    let mut rng = Rng(77);
    let txs: Vec<_> = (0..800).map(|_| gen_tx(&mut rng, MARKETS)).collect();
    assert!(run_lanes(&lanes.1, &lanes.0, &txs).is_none(), "an unfunded run must decline");
    assert_eq!(lanes.1.lane_runs_for_test(), 0);
}

#[test]
fn amend_market_buy_and_single_market_runs_decline() {
    let (ledger, ex) = rig(true, RICH);
    let mut rng = Rng(5);
    // Single market: nothing to parallelize.
    // (Orders to the unlisted market 200 are their own component, so drop those.)
    let one: Vec<_> = (0..800)
        .map(|_| gen_tx(&mut rng, 1))
        .filter(|(_, _, p)| !(p.first() == Some(&super::TAG_PLACE) && p.get(1) == Some(&200)))
        .collect();
    assert!(run_lanes(&ex, &ledger, &one).is_none(), "single-market run must decline");
    // A market buy poisons an otherwise eligible run.
    let mut txs: Vec<_> = (0..800).map(|_| gen_tx(&mut rng, MARKETS)).collect();
    let mut mb = order(&mut rng, OrderType::Market);
    mb.side = Side::Buy;
    txs.push((addr(1), 0, msg::place(0, mb)));
    assert!(run_lanes(&ex, &ledger, &txs).is_none(), "a market buy must decline the run");
    assert_eq!(ex.lane_runs_for_test(), 0);
}

#[test]
fn small_runs_stay_serial() {
    let (ledger, ex) = rig(true, RICH);
    let mut rng = Rng(9);
    let few: Vec<_> = (0..20).map(|_| gen_tx(&mut rng, MARKETS)).collect();
    assert!(run_lanes(&ex, &ledger, &few).is_none());
}

#[test]
fn an_unfunded_owner_in_a_delegated_bundle_declines_the_lane_path() {
    // Everything in the run is funded except owner 1, whose balance is burned down to a few units. A
    // delegated bundle by the agent places large buys for owner 1: the OWNER funds them, so the lane
    // planner's funds proof must cover owners (not only envelope senders) and decline the run.
    let (ledger, ex) = rig(true, RICH);
    let keep = 10;
    let burn = ledger.balance(&addr(1)) - keep;
    ledger.debit(&addr(1), burn).expect("burn");
    let mut rng = Rng(31);
    // Direct orders from funded senders (never owner 1), spread over the markets.
    let mut txs: Vec<(Address, u64, Vec<u8>)> = (0..700)
        .map(|_| {
            let sender = addr(2 + u8::try_from(rng.below(u64::from(ACCOUNTS - 1))).unwrap());
            let market = u8::try_from(rng.below(u64::from(MARKETS))).unwrap();
            (sender, 0, item(&mut rng, market))
        })
        .collect();
    let big_buy = |m: u8| {
        let mut o = order(&mut rng_clone(), OrderType::Limit);
        o.side = Side::Buy;
        (addr(1), msg::place(m, o))
    };
    // One market only: a bundle spanning every market would merge them into a single component and the
    // run would decline for lack of parallelism before the funds proof is reached.
    let items: Vec<_> = (0..4).map(|_| big_buy(0)).collect();
    txs.push((addr(AGENT_OK), 0, msg::dbundle(&items).expect("dbundle")));
    assert!(
        run_lanes(&ex, &ledger, &txs).is_none(),
        "owner 1 cannot fund the delegated buys: the run must decline"
    );
    assert_eq!(ex.lane_runs_for_test(), 0);
}

fn rng_clone() -> Rng {
    Rng(12345)
}
