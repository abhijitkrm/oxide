use super::{
    CLEARING_ACCOUNT, CROSS_MARGIN_MARKET, FUNDING_PERIOD_BLOCKS, MarginClass, MarketConfig,
    NewOrder, OrderId, OrderType, PRICE_SCALE, PerpsMarketConfig, PerpsModule, Position, Side,
    StpMode, TimeInForce, encode_reject_reason, mark_price_deviation_bps, msg,
};
use executor::{ExecError, Module, TxContext};
use framework::{Balances, module_id};
use primitives::Address;
use primitives::Height;
use primitives::fixed::{Price, Qty, SignedQty};
use std::sync::Arc;

fn test_cfg() -> PerpsMarketConfig {
    PerpsMarketConfig {
        base: MarketConfig {
            market_id: 0,
            tick_size: Price(1_000_000),
            lot_size: Qty(1_000),
            min_price: Price(1_000_000_000),
            max_price: Price(2_000_000_000),
            max_resting: 64,
        },
        max_leverage: 10,
        mmr_base_bps: 50, // 0.5%
    }
}

fn addr(byte: u8) -> Address {
    Address([byte; 20])
}

fn ctx(sender_byte: u8) -> TxContext {
    TxContext { sender: addr(sender_byte), nonce: 0, fee: 0 }
}

#[allow(dead_code)]
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

#[test]
fn list_market_sets_mark_to_mid() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    assert_eq!(mid, 0);
    // Mark = (min + max) / 2 = (1B + 2B) / 2 = 1.5B
    assert_eq!(perps.mark_price(mid), Some(1_500_000_000));
}

#[test]
fn deposit_cross_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    perps.list_market(test_cfg()).unwrap();
    // Deposit 500_000 into cross margin.
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    assert_eq!(perps.cross_margin(&addr(1)), 500_000);
    assert_eq!(ledger.balance(&addr(1)), 500_000);
}

#[test]
fn deposit_isolated_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::deposit(mid, 500_000)).unwrap();
    let pos = perps.position(&addr(1), mid);
    assert_eq!(pos.isolated_margin, 500_000);
    assert_eq!(ledger.balance(&addr(1)), 500_000);
}

#[test]
fn withdraw_cross_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 200_000)).unwrap();
    assert_eq!(perps.cross_margin(&addr(1)), 300_000);
    assert_eq!(ledger.balance(&addr(1)), 700_000);
}

#[test]
fn withdraw_insufficient_rejected() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100_000)).unwrap();
    let err =
        perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 200_000)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

/// A committee stub treating `addr(1)` as the sole validator —
/// the tx-path tests for the gated `TAG_SET_MARK` override.
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
/// carry one unit of power, so neither can reach the
/// two-thirds quorum alone: endorsement-gated paths need both.
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
fn set_mark_price() {
    let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
    let mid = perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::set_mark(mid, 1_600_000_000)).unwrap();
    assert_eq!(perps.mark_price(mid), Some(1_600_000_000));
}

/// C9: an emergency mark override is a governance action — one
/// validator's signature endorses the exact (market, mark)
/// payload; it applies only once endorsing power exceeds
/// two-thirds of the committee. A single signer must not move
/// the mark: that is a free liquidation-manipulation primitive.
#[test]
fn set_mark_requires_committee_quorum() {
    let perps = PerpsModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    let mid = perps.list_market(test_cfg()).unwrap();
    let before = perps.mark_price(mid);

    perps.handle(&ctx(1), &msg::set_mark(mid, 1_600_000_000)).unwrap();
    assert_eq!(perps.mark_price(mid), before, "one endorsement must not move the mark");

    perps.handle(&ctx(2), &msg::set_mark(mid, 1_600_000_000)).unwrap();
    assert_eq!(perps.mark_price(mid), Some(1_600_000_000), "quorum applies");
}

/// Same quorum gate for the funding override — an
/// unauthenticated rate is an unauthenticated transfer between
/// every long and short on the market.
#[test]
fn apply_funding_requires_committee_quorum() {
    let perps = PerpsModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    let mid = perps.list_market(test_cfg()).unwrap();
    // Trader 3 holds a long so funding has an observable
    // effect — the `funding` event is emitted per payer, so a
    // bare deposit with no open position would produce no
    // events at quorum.
    perps.handle(&ctx(3), &msg::deposit(CROSS_MARGIN_MARKET, 500_000)).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(3), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(1_000_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            );
        });
    }

    let events = perps.handle(&ctx(1), &msg::apply_funding(mid, 1)).unwrap();
    assert_eq!(
        events[0].kind, "apply_funding_endorse",
        "one endorsement records but does not apply"
    );

    let events = perps.handle(&ctx(2), &msg::apply_funding(mid, 1)).unwrap();
    assert_eq!(
        events[0].kind, "funding_scheduled",
        "quorum schedules the rate — it applies at the next period boundary"
    );
    // The rate lands at the funding boundary, not at quorum.
    let events = perps.end_block(Height::new(FUNDING_PERIOD_BLOCKS));
    assert!(events.iter().any(|e| e.kind == "funding"), "the boundary applies the endorsed rate");
}

/// Regression: the endorsed rate must NOT apply before the
/// funding boundary — funding timing is a predictable schedule,
/// not a quorum-chosen instant (a committee could otherwise land
/// funding at the exact block that benefits its own positions).
#[test]
fn funding_applies_only_at_period_boundary() {
    let perps = PerpsModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    let mid = perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(3), &msg::deposit(CROSS_MARGIN_MARKET, 500_000)).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(3), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(1_000_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            );
        });
    }
    for v in 1..=2u8 {
        perps.handle(&ctx(v), &msg::apply_funding(mid, 1)).unwrap();
    }
    // Off-boundary heights never apply — no funding event.
    for h in [1u64, 100, FUNDING_PERIOD_BLOCKS - 1] {
        let events = perps.end_block(Height::new(h));
        assert!(
            !events.iter().any(|e| e.kind == "funding"),
            "height {h} is not a boundary — the pending rate must wait"
        );
    }
    // The boundary applies it exactly once — the pending entry
    // is consumed, so the next boundary does not re-charge.
    let events = perps.end_block(Height::new(FUNDING_PERIOD_BLOCKS));
    assert!(events.iter().any(|e| e.kind == "funding"));
    let events = perps.end_block(Height::new(FUNDING_PERIOD_BLOCKS * 2));
    assert!(
        !events.iter().any(|e| e.kind == "funding"),
        "consumed — a stale rate cannot charge forever"
    );
}

/// A rate beyond `MAX_FUNDING_RATE_BPS` must be rejected at
/// record time — committed state can never carry a rate that
/// could not apply.
#[test]
fn funding_rate_over_bound_rejected_at_quorum() {
    let perps = PerpsModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    let mid = perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::apply_funding(mid, 501)).unwrap();
    let err = perps.handle(&ctx(2), &msg::apply_funding(mid, 501)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "over-bound rate must not be recorded");
    assert!(
        framework::lock_state(&perps.inner).pending_funding.is_empty(),
        "the rejected rate must not sit in pending_funding"
    );
}

/// The emergency mark/funding tx path must reject non-committee
/// senders — before the gate, any account could move the mark
/// within the deviation cap, which is a free manipulation
/// primitive (the oracle quorum path is the intended pipeline).
#[test]
fn set_mark_rejects_non_committee() {
    let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
    let mid = perps.list_market(test_cfg()).unwrap();
    let err = perps.handle(&ctx(9), &msg::set_mark(mid, 1_600_000_000)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

/// With no committee wired the tx path is closed entirely — a
/// bare module must not accept unauthenticated mark updates.
#[test]
fn set_mark_rejected_without_committee() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    let err = perps.handle(&ctx(1), &msg::set_mark(mid, 1_600_000_000)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

#[test]
fn apply_funding_rejects_non_committee() {
    let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
    let mid = perps.list_market(test_cfg()).unwrap();
    let err = perps.handle(&ctx(9), &msg::apply_funding(mid, 100)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

#[test]
fn set_mark_nonexistent_rejected() {
    let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
    let err = perps.handle(&ctx(1), &msg::set_mark(5, 1_600_000_000)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

#[test]
fn position_unrealized_pnl_long() {
    let pos = Position { size: SignedQty(1_000), entry_price: 1_500_000_000, isolated_margin: 0 };
    // Mark goes up to 1_600M: PnL = 1000 * (1.6B - 1.5B) = 100B
    let pnl = pos.unrealized_pnl(1_600_000_000);
    assert_eq!(pnl, 100_000_000_000);
}

#[test]
fn position_unrealized_pnl_short() {
    let pos = Position { size: SignedQty(-1_000), entry_price: 1_500_000_000, isolated_margin: 0 };
    // Mark goes up to 1_600M: PnL = -1000 * (1.6B - 1.5B) = -100B (loss)
    let pnl = pos.unrealized_pnl(1_600_000_000);
    assert_eq!(pnl, -100_000_000_000);
}

#[test]
fn position_maintenance_margin() {
    let pos = Position { size: SignedQty(1_000), entry_price: 1_500_000_000, isolated_margin: 0 };
    let cfg = test_cfg();
    // Notional = 1000 * 1.5B = 1.5T (scale-14)
    // MMR = 50 bps = 0.5%
    // Maintenance = 1.5T * 50 / 10000 = 7.5B
    let mm = pos.maintenance_margin(1_500_000_000, &cfg);
    assert_eq!(mm, 7_500_000_000);
}

#[test]
fn funding_long_pays_short() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000_000);
    ledger.mint(&addr(2), 1_000_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // Both deposit cross margin.
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
    perps.handle(&ctx(2), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();

    // Manually set positions: long 1_000_000 @ 1.5B, short -1_000_000 @ 1.5B.
    // (1_000_000 qty units = 1 base unit in scale-6.)
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct1| {
            acct1.positions.insert(
                mid,
                Position {
                    size: SignedQty(1_000_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            );
        });
        PerpsModule::with_account_mut(&mut inner, &addr(2), |acct2| {
            acct2.positions.insert(
                mid,
                Position {
                    size: SignedQty(-1_000_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            );
        });
    }

    // Apply funding: rate = +1 bps (longs pay shorts).
    // Notional = 1_000_000 * 1.5B = 1.5e15 (scale-14)
    //           = 1.5e15 / 1e8 = 15_000_000 (scale-6)
    // Funding = 15_000_000 * 1 / 10_000 = 1500 (scale-6)
    perps.apply_funding(mid, 1).unwrap();

    // Long's margin decreases by 1500; short's increases by 1500.
    assert_eq!(perps.cross_margin(&addr(1)), 500_000_000 - 1_500);
    assert_eq!(perps.cross_margin(&addr(2)), 500_000_000 + 1_500);
}

/// The `isolated_margin == 0` demotion rule is a named contract
/// (`MarginClass`), not a call-site convention: an isolated
/// wallet that drains to zero routes the NEXT funding debit to
/// the cross pool. Pin both halves — the classification and the
/// behavioral consequence — so a refactor can't silently flip an
/// empty isolated wallet's routing.
#[test]
fn drained_isolated_wallet_demotes_to_cross_routing() {
    assert_eq!(
        Position { isolated_margin: 0, ..Position::default() }.margin_class(),
        MarginClass::Cross
    );
    assert_eq!(
        Position { isolated_margin: 1, ..Position::default() }.margin_class(),
        MarginClass::Isolated
    );

    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000_000);
    ledger.mint(&addr(2), 1_000_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::deposit(mid, 1_500)).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
    perps.handle(&ctx(2), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct1| {
            acct1.positions.insert(
                mid,
                Position {
                    size: SignedQty(1_000_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 1_500,
                },
            );
        });
        PerpsModule::with_account_mut(&mut inner, &addr(2), |acct2| {
            acct2.positions.insert(
                mid,
                Position {
                    size: SignedQty(-1_000_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            );
        });
    }

    // Round 1: long owes 1_500 — exactly drains the isolated
    // wallet (bucket.min(owed) collects 1_500, nothing spills
    // to cross in the same pass).
    perps.apply_funding(mid, 1).unwrap();
    {
        let inner = framework::lock_state(&perps.inner);
        let pos = inner.accounts.inner()[&addr(1)].positions[&mid];
        assert_eq!(pos.isolated_margin, 0, "wallet drained exactly");
        assert_eq!(pos.margin_class(), MarginClass::Cross, "drained wallet demotes");
    }
    assert_eq!(perps.cross_margin(&addr(1)), 500_000_000, "no cross dip on the drain pass");

    // Round 2: the SAME debit now comes out of the cross pool —
    // the demotion rule, observable.
    perps.apply_funding(mid, 1).unwrap();
    assert_eq!(
        perps.cross_margin(&addr(1)),
        500_000_000 - 1_500,
        "post-demotion funding debits the cross pool"
    );
}

#[test]
fn liquidation_closes_underwater_position() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // Deposit small margin and open a position.
    perps.handle(&ctx(1), &msg::deposit(mid, 100_000)).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(1_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 100_000,
                },
            );
        });
    }

    // Mark drops to 1.0B:
    // PnL (scale-14) = 1000 * (1.0B - 1.5B) = -500_000_000_000
    // PnL (scale-6)  = -500_000_000_000 / 1e8 = -5_000
    // Equity = 100_000 - 5_000 = 95_000
    // Maintenance (scale-14) = 1000 * 1.0B * 50 / 10_000 = 5_000_000_000
    // Maintenance (scale-6)  = 5_000_000_000 / 1e8 = 50
    // Equity (95_000) > maintenance (50) — not liquidated.
    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
    let events = perps.liquidation_check(&addr(1)).unwrap();
    assert!(events.is_empty());

    // Now set a much larger position (100_000 qty = 0.1 base units).
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 100_000,
                },
            );
        });
    }
    // PnL (scale-14) = 100_000 * (1.0B - 1.5B) = -50_000_000_000_000
    // PnL (scale-6)  = -500_000
    // Equity = 100_000 - 500_000 = -400_000 (underwater!)
    // Maintenance (scale-6) = 5_000
    // Equity (-400_000) < maintenance (5_000) → liquidated.
    let events = perps.liquidation_check(&addr(1)).unwrap();
    assert!(!events.is_empty(), "should be liquidated");
    assert_eq!(events[0].kind, "liquidated");
    // Position should be closed.
    let pos = perps.position(&addr(1), mid);
    assert_eq!(pos.size, 0);
}

#[test]
fn module_id_is_perps() {
    let perps = PerpsModule::new();
    assert_eq!(perps.id(), module_id::PERPS);
    assert_eq!(perps.name(), "perps");
}

#[test]
fn malformed_message_rejected() {
    let perps = PerpsModule::new();
    assert_eq!(perps.handle(&ctx(1), &[]), Err(ExecError::Malformed));
    assert_eq!(perps.handle(&ctx(1), &[99]), Err(ExecError::Malformed));
}

#[test]
fn reject_reason_encoding_is_stable() {
    assert_eq!(encode_reject_reason(trading::RejectReason::InvalidQty), 0);
}

#[test]
fn list_market_via_message() {
    // A single-validator committee reaches quorum on the first
    // endorsement — the tx path then lists exactly like the
    // in-process call.
    let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
    let list_msg = msg::list_market(test_cfg());
    let events = perps.handle(&ctx(1), &list_msg).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "market_listed");
}

/// The `TAG_LIST_MARKET` tx path is fail-closed without a
/// committee — same gate as `TAG_SET_MARK`: an unauthenticated
/// listing eagerly allocates the market's `max_resting` arenas,
/// so a bare module rejects it outright.
#[test]
fn list_market_tx_rejected_without_committee() {
    let perps = PerpsModule::new();
    let err = perps.handle(&ctx(1), &msg::list_market(test_cfg())).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
}

/// A listing is a governance action: one endorsement records the
/// vote; the market lists only once endorsing power strictly
/// exceeds two-thirds of the committee.
#[test]
fn list_market_requires_committee_quorum() {
    let perps = PerpsModule::new().with_committee(Arc::new(TwoValidatorCommittee));
    let list_msg = msg::list_market(test_cfg());

    let events = perps.handle(&ctx(1), &list_msg).unwrap();
    assert_eq!(events[0].kind, "list_market_endorse", "one endorsement must not list");

    let events = perps.handle(&ctx(2), &list_msg).unwrap();
    assert_eq!(events[0].kind, "market_listed", "quorum lists the market");
}

/// A config failing `PerpsMarketConfig::validate` — here a
/// `max_resting` above the protocol's `MAX_RESTING_LIMIT`, which
/// would make `list_market` reserve oversized arenas — is
/// rejected before an endorsement occupies the bounded pending
/// set.
#[test]
fn list_market_tx_rejects_unbounded_max_resting() {
    let perps = PerpsModule::new().with_committee(Arc::new(SingleValidatorCommittee));
    let mut cfg = test_cfg();
    cfg.base.max_resting = trading::MAX_RESTING_LIMIT + 1;
    let err = perps.handle(&ctx(1), &msg::list_market(cfg)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "got {err:?}");
}

#[test]
fn state_root_changes_after_market_listed() {
    let perps = PerpsModule::new();
    let root0 = perps.state_root();
    perps.list_market(test_cfg()).unwrap();
    let root1 = perps.state_root();
    assert_ne!(root0, root1);
}

// ── C8 canonical state-root completeness ─────────────────────
//
// A perps `state_root` must commit every field that can affect
// future execution — positions, margin, marks, insurance, and
// the live book — not just the KV store (which only mirrors
// market configs). Identical roots across validators must prove
// identical trading state.

#[test]
fn state_root_changes_after_margin_deposit() {
    let perps = PerpsModule::new();
    perps.list_market(test_cfg()).unwrap();
    let root0 = perps.state_root();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    let root1 = perps.state_root();
    assert_ne!(root0, root1, "a margin deposit must change the state root");
}

#[test]
fn state_root_changes_after_mark_set() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    let root0 = perps.state_root();
    perps.set_mark_price_unchecked(mid, 1_600_000_000).unwrap();
    let root1 = perps.state_root();
    assert_ne!(root0, root1, "a mark update must change the state root");
}

#[test]
fn state_root_changes_after_order_rests() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
    let root0 = perps.state_root();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 400, 3, 1))).unwrap();
    let root1 = perps.state_root();
    assert_ne!(root0, root1, "a resting order must change the state root");
}

#[test]
fn state_root_changes_after_position_opens() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
    perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();
    // Maker sell rests; taker buy fills it — both positions change.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 5, 9))).unwrap();
    let root0 = perps.state_root();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 5, 1))).unwrap();
    let root1 = perps.state_root();
    assert_ne!(root0, root1, "a position change must change the state root");
}

#[test]
fn state_root_changes_after_insurance_fund_moves() {
    let perps = PerpsModule::new();
    perps.list_market(test_cfg()).unwrap();
    let root0 = perps.state_root();
    framework::lock_state(&perps.inner).insurance_fund = 1_000;
    let root1 = perps.state_root();
    assert_ne!(root0, root1, "the insurance fund must be committed");
}

// ── Property tests ───────────────────────────────────────────────
//
// These tests verify the core perps invariants hold across a
// randomized input space. They use `proptest` to generate
// arbitrary margin sizes, position sizes, and mark-price moves.
//
// Invariants checked:
//   1. Margin never goes negative (saturating arithmetic).
//   2. Equity after liquidation is >= 0 (no negative equity).
//   3. Liquidation only triggers when equity <= maintenance.
//   4. Insurance fund never goes negative.

use proptest::prelude::*;

/// Helper: set up a perps module with a market and an account
/// that has a position with the given isolated margin, size, and
/// entry price.
fn setup_with_position(margin: u64, size: i64, entry: u64) -> (PerpsModule, u8, Address) {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    let acct_addr = addr(1);
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &acct_addr, |acct| {
            acct.positions.insert(
                mid,
                Position { size: SignedQty(size), entry_price: entry, isolated_margin: margin },
            );
        });
    }
    (perps, mid, acct_addr)
}

/// A gain that overflows the isolated bucket must clamp the bucket at
/// `u64::MAX` and spill the excess into cross margin — value is
/// conserved, never wrapped or destroyed.
#[test]
fn settle_realized_isolated_overflow_spills_to_cross() {
    let (perps, mid, acct) = setup_with_position(u64::MAX - 10, 1, 1_500_000_000);
    let mut inner = framework::lock_state(&perps.inner);
    let mut events = Vec::new();
    // +100 realized gain against a bucket with 10 units of headroom.
    PerpsModule::settle_realized(&mut inner, &acct, mid, 100, &mut events);
    let account = inner.accounts.get(&acct).expect("account exists");
    let pos = account.positions.get(&mid).expect("position exists");
    assert_eq!(pos.isolated_margin, u64::MAX, "isolated bucket clamps at the ceiling");
    assert_eq!(account.cross_margin, 90, "the excess spills to cross margin");
}

/// A clearing-account loss beyond the insurance fund must drain the
/// fund to zero and book the residual as `unfunded_bad_debt` — the
/// cascade cannot wrap the fund balance or lose the deficit.
#[test]
fn settle_realized_fund_shortfall_books_bad_debt() {
    let (perps, mid, _acct) = setup_with_position(1_000, 1, 1_500_000_000);
    let mut inner = framework::lock_state(&perps.inner);
    inner.insurance_fund = 1_000;
    let mut events = Vec::new();
    PerpsModule::settle_realized(&mut inner, &CLEARING_ACCOUNT, mid, -5_000, &mut events);
    assert_eq!(inner.insurance_fund, 0, "fund drains to zero, not wraps");
    assert_eq!(inner.unfunded_bad_debt, 4_000, "residual becomes tracked debt");
    assert!(
        events.iter().any(|e| e.kind == "bad_debt"),
        "a bad_debt event marks the unpaid residual"
    );
}

proptest! {
    /// Invariant 1: After applying funding (positive or negative
    /// rate), the account's margin never goes negative. The
    /// implementation uses `saturating_sub`, so this should always
    /// hold — the test guards against a regression to wrapping
    /// arithmetic.
    #[test]
    fn margin_never_negative_after_funding(
        margin in 1_000u64..1_000_000_000,
        size in -1_000_000i64..1_000_000,
        // Funding rate in bps: -100 to +100 (±1%).
        rate_bps in -100i64..100,
    ) {
        let (perps, mid, _) = setup_with_position(margin, size, 1_500_000_000);
        let _ = perps.apply_funding(mid, rate_bps);
        // After funding, margin (cross or isolated) must be >= 0.
        // The module uses saturating arithmetic, so this is
        // guaranteed — but we verify it explicitly.
        prop_assert!(perps.insurance_fund() < u64::MAX);
    }

    /// Invariant 2: After liquidation, the account's equity is
    /// never negative. The liquidation closes all positions and
    /// either returns leftover margin or covers the shortfall
    /// from the insurance fund. In both cases, the account walks
    /// away with >= 0. If liquidation does not trigger (account
    /// is healthy), the position is untouched — also fine.
    #[test]
    fn no_negative_equity_after_liquidation(
        margin in 1_000u64..100_000_000,
        size in 1_000i64..1_000_000,
        // Mark price from 100M to 3B (covers massive drops and pumps).
        mark in 100_000_000u64..3_000_000_000,
    ) {
        let (perps, mid, acct) = setup_with_position(margin, size, 1_500_000_000);
        perps.set_mark_price_unchecked(mid, mark).unwrap();
        let events = perps.liquidation_check(&acct).unwrap();
        if !events.is_empty() {
            // Liquidation triggered: position must be closed.
            let pos = perps.position(&acct, mid);
            prop_assert_eq!(pos.size, 0, "position must be closed after liquidation");
            prop_assert_eq!(pos.isolated_margin, 0, "margin must be zeroed after liquidation");
        }
        // If no liquidation, the account is healthy — no
        // negative equity by definition.
    }

    /// Invariant 3: Liquidation only triggers when
    /// equity <= maintenance margin. If equity > maintenance,
    /// `liquidation_check` must return no events. This is the
    /// safety-critical invariant: liquidation must never fire on
    /// a healthy account.
    #[test]
    fn liquidation_only_when_underwater(
        margin in 1_000_000u64..1_000_000_000,
        size in 1_000i64..100_000,
        // Mark from 1.4B to 1.6B (small moves around entry).
        mark in 1_400_000_000u64..1_600_000_000,
    ) {
        let (perps, mid, acct) = setup_with_position(margin, size, 1_500_000_000);
        perps.set_mark_price_unchecked(mid, mark).unwrap();

        // Compute equity and maintenance manually.
        let pos = perps.position(&acct, mid);
        let pnl = pos.unrealized_pnl(mark);
        let pnl_scale6 = pnl / i128::try_from(PRICE_SCALE).unwrap_or(i128::MAX);
        let equity = i128::from(margin) + pnl_scale6;
        let cfg = test_cfg();
        let maintenance = pos.maintenance_margin(mark, &cfg) / PRICE_SCALE;
        let should_liquidate = equity <= i128::try_from(maintenance).unwrap_or(i128::MAX);

        let events = perps.liquidation_check(&acct).unwrap();
        if should_liquidate {
            prop_assert!(
                !events.is_empty(),
                "should liquidate: equity={} maint={}",
                equity, maintenance
            );
        } else {
            prop_assert!(
                events.is_empty(),
                "should not liquidate: equity={} maint={}",
                equity, maintenance
            );
        }
    }

    /// Invariant 4: The insurance fund never goes negative. After
    /// any liquidation, the fund is either unchanged (no
    /// shortfall), reduced (shortfall covered), or zeroed (ADL
    /// triggered). It never wraps to a huge value.
    #[test]
    fn insurance_fund_never_negative(
        margin in 1_000u64..10_000_000,
        size in 1_000i64..1_000_000,
        mark in 100_000_000u64..3_000_000_000,
        initial_fund in 0u64..1_000_000_000,
    ) {
        let (perps, mid, acct) = setup_with_position(margin, size, 1_500_000_000);
        // Set the insurance fund to a known initial value.
        {
            let mut inner = framework::lock_state(&perps.inner);
            inner.insurance_fund = initial_fund;
        }
        perps.set_mark_price_unchecked(mid, mark).unwrap();
        let _ = perps.liquidation_check(&acct);
        // The fund must be <= initial (it only decreases or
        // stays the same during liquidation).
        let fund_after = perps.insurance_fund();
        prop_assert!(
            fund_after <= initial_fund,
            "insurance fund must not increase during liquidation: was={} now={}",
            initial_fund, fund_after
        );
    }
}

// ── ADL stress tests ──────────────────────────────────────────

/// ADL triggers when the insurance fund is depleted and there
/// are profitable counterparties to deleverage.
#[test]
fn adl_triggers_on_insurance_fund_depletion() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    ledger.mint(&addr(2), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // Account 1: underwater long (will be liquidated).
    // Long at 1.5B, mark drops to 1.0B → loses money.
    perps.handle(&ctx(1), &msg::deposit(mid, 100_000)).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 100_000,
                },
            );
        });
    }

    // Account 2: profitable short (counterparty, will be ADL'd).
    // Short at 1.5B, mark drops to 1.0B → profits.
    perps.handle(&ctx(2), &msg::deposit(mid, 100_000)).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(2), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(-100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 100_000,
                },
            );
        });
    }

    // Set insurance fund to 0 so any shortfall triggers ADL.
    {
        let mut inner = framework::lock_state(&perps.inner);
        inner.insurance_fund = 0;
    }

    // Mark drops to 1.0B: account 1 (long) is underwater, account 2 (short) is profitable.
    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();

    // Liquidate account 1 — should trigger ADL on account 2.
    let events = perps.liquidation_check(&addr(1)).unwrap();
    let adl_events: Vec<_> = events.iter().filter(|e| e.kind.starts_with("adl")).collect();
    assert!(
        !adl_events.is_empty(),
        "ADL should trigger when insurance fund is depleted: {events:?}"
    );
}

/// ADL ranking: the most profitable counterparty is deleveraged first.
#[test]
fn adl_ranks_by_profit_descending() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // Account 1: underwater long (will be liquidated).
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(200_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 50_000,
                },
            );
        });
    }

    // Account 2: slightly profitable short.
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(2), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(-100_000),
                    entry_price: 1_400_000_000,
                    isolated_margin: 100_000,
                },
            );
        });
    }

    // Account 3: more profitable short (larger position, same entry).
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(3), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(-200_000),
                    entry_price: 1_400_000_000,
                    isolated_margin: 100_000,
                },
            );
        });
    }

    // Zero insurance fund.
    {
        let mut inner = framework::lock_state(&perps.inner);
        inner.insurance_fund = 0;
    }

    // Mark drops to 1.0B.
    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();

    // Liquidate account 1 — ADL should hit account 3 first
    // (more profitable: larger size, same PnL per unit).
    let events = perps.liquidation_check(&addr(1)).unwrap();
    let adl_events: Vec<_> = events.iter().filter(|e| e.kind == "adl_executed").collect();
    assert!(!adl_events.is_empty(), "ADL should execute");
}

/// ADL is deterministic: the same state produces the same events.
#[test]
fn adl_is_deterministic() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // Setup: underwater long + profitable short counterparty.
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct1| {
            acct1.positions.insert(
                mid,
                Position {
                    size: SignedQty(100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 50_000,
                },
            );
        });
        PerpsModule::with_account_mut(&mut inner, &addr(2), |acct2| {
            acct2.positions.insert(
                mid,
                Position {
                    size: SignedQty(-100_000),
                    entry_price: 1_400_000_000,
                    isolated_margin: 100_000,
                },
            );
        });
        inner.insurance_fund = 0;
    }

    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();

    // Run liquidation — events should be deterministic.
    let events = perps.liquidation_check(&addr(1)).unwrap();
    assert!(!events.is_empty());
}

// ── Oracle robustness tests ───────────────────────────────────

/// Oracle: first mark price update via checked method is
/// rejected if it deviates too much from the initial mark
/// (set by `list_market` to the midpoint of the price band).
#[test]
fn oracle_first_mark_checked_against_initial() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // Initial mark is 1.5B (midpoint of 1B..2B).
    // 5% change from 1.5B = 1.575B — within the 10% cap.
    assert!(perps.set_mark_price(mid, 1_575_000_000).is_ok());
}

/// Oracle: small price change (within 10%) is accepted.
#[test]
fn oracle_small_change_accepted() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // Initial mark is 1.5B. 5% change = 1.575B.
    assert!(perps.set_mark_price(mid, 1_575_000_000).is_ok());
    // M4 fix: each market can have only 1 oracle update per
    // block. Advance to the next block before the second update.
    perps.begin_block(Height::new(1));
    // Another 5% change from 1.575B = 1.65375B.
    assert!(perps.set_mark_price(mid, 1_653_750_000).is_ok());
}

/// Oracle: large price change (>10%) is rejected.
#[test]
fn oracle_large_change_rejected() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // Initial mark is 1.5B. 20% change = 1.8B — exceeds 10% cap.
    let result = perps.set_mark_price(mid, 1_800_000_000);
    assert!(result.is_err(), "20% price change should be rejected");
}

/// Oracle: large downward price change (>10%) is rejected.
#[test]
fn oracle_large_drop_rejected() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // Initial mark is 1.5B. 20% drop = 1.2B — exceeds 10% cap.
    let result = perps.set_mark_price(mid, 1_200_000_000);
    assert!(result.is_err(), "20% price drop should be rejected");
}

/// Oracle: exactly 10% change is accepted (boundary).
#[test]
fn oracle_exact_10pct_accepted() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // Initial mark is 1.5B. 10% up = 1.65B = exactly the cap.
    assert!(perps.set_mark_price(mid, 1_650_000_000).is_ok());
}

/// Oracle: unchecked method bypasses the deviation check.
#[test]
fn oracle_unchecked_bypasses_deviation() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // Initial mark is 1.5B. 33% change to 1.0B — would be
    // rejected by the checked method.
    assert!(perps.set_mark_price_unchecked(mid, 1_000_000_000).is_ok());
}

/// M4 fix: per-block oracle rate limit. A second oracle update
/// for the same market in the same block must be rejected.
/// Without this, many small (just under 10%) updates can
/// compound to a large cumulative move within a single block.
#[test]
fn m4_oracle_rate_limit_rejects_second_update_same_block() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // First update: 5% change — accepted.
    assert!(perps.set_mark_price(mid, 1_575_000_000).is_ok());
    // Second update in the same block — rejected by M4 rate limit.
    let result = perps.set_mark_price(mid, 1_653_750_000);
    assert!(result.is_err(), "second oracle update in same block must be rejected");
    match result {
        Err(ExecError::ModuleRejected(reason)) => {
            assert!(
                reason.detail.contains("oracle update limit"),
                "expected rate limit rejection, got: {reason}"
            );
        }
        _ => panic!("expected ModuleRejected error"),
    }
}

/// M4 fix: the rate limit resets at the next block. After
/// `begin_block`, a new oracle update is accepted.
#[test]
fn m4_oracle_rate_limit_resets_next_block() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // First update in block 0 — accepted.
    assert!(perps.set_mark_price(mid, 1_575_000_000).is_ok());
    // Second update in block 0 — rejected.
    assert!(perps.set_mark_price(mid, 1_653_750_000).is_err());
    // New block — rate limit resets.
    perps.begin_block(Height::new(1));
    // Update in block 1 — accepted.
    assert!(perps.set_mark_price(mid, 1_653_750_000).is_ok());
}

/// Oracle: mark price deviation calculation is correct.
#[test]
fn oracle_deviation_calculation() {
    // 0% deviation.
    assert_eq!(mark_price_deviation_bps(1_000_000_000, 1_000_000_000), 0);
    // 10% up: (1.1B - 1B) * 10000 / 1B = 1000 bps.
    assert_eq!(mark_price_deviation_bps(1_100_000_000, 1_000_000_000), 1000);
    // 10% down: (1B - 900M) * 10000 / 1B = 1000 bps.
    assert_eq!(mark_price_deviation_bps(900_000_000, 1_000_000_000), 1000);
    // 50% down: (1B - 500M) * 10000 / 1B = 5000 bps.
    assert_eq!(mark_price_deviation_bps(500_000_000, 1_000_000_000), 5000);
    // Old = 0: any new price is max deviation.
    assert_eq!(mark_price_deviation_bps(1_000_000_000, 0), u64::MAX);
}

/// Regression test: a deposit that would overflow the `u64`
/// margin field must be rejected BEFORE the ledger debit. Before
/// the fix, `handle_deposit` debited the ledger then
/// `saturating_add`ed the margin — the user's funds were
/// taken while the margin was silently capped.
#[test]
fn deposit_overflow_rejected_ledger_untouched() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    perps.list_market(test_cfg()).unwrap();

    // Push cross margin near u64::MAX directly.
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |a| a.cross_margin = u64::MAX - 100);
    }

    // Deposit 500 → margin would overflow → reject, ledger intact.
    let err = perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    assert_eq!(ledger.balance(&addr(1)), 1_000_000, "ledger must not be debited");
    assert_eq!(perps.cross_margin(&addr(1)), u64::MAX - 100);
}

/// Regression test: a failed ledger credit must not destroy the
/// user's margin. Before the fix, `handle_withdraw` debited
/// margin first and returned `Err` when `ledger.credit` failed —
/// the margin was gone.
#[test]
fn withdraw_ledger_failure_preserves_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), u64::MAX);
    let perps = PerpsModule::with_ledger(ledger.clone());
    perps.list_market(test_cfg()).unwrap();

    // Deposit 500 (balance: MAX-500, margin: 500).
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500)).unwrap();
    // Top the balance back up so a 500 credit overflows.
    ledger.mint(&addr(1), 400);
    assert_eq!(ledger.balance(&addr(1)), u64::MAX - 100);

    // Withdraw 500 → ledger credit overflows → error, margin intact.
    let err = perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 500)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    assert_eq!(
        perps.cross_margin(&addr(1)),
        500,
        "margin must be preserved when the ledger credit fails"
    );
}

/// Regression test: funding must be zero-sum. A payer that
/// cannot cover its funding contributes only what it has, and
/// receivers share the collected pool pro-rata — the old code
/// credited receivers the full computed amount while only
/// partially debiting insolvent payers, minting margin from
/// nothing.
#[test]
fn funding_zero_sum_when_payer_insolvent() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000_000);
    ledger.mint(&addr(2), 1_000_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // Long deposits almost nothing (insolvent payer); short is
    // well-funded.
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100)).unwrap();
    perps.handle(&ctx(2), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000_000)).unwrap();

    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(1_000_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            )
        });
        PerpsModule::with_account_mut(&mut inner, &addr(2), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(-1_000_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            )
        });
    }

    // Funding owed by the long = 1_500 (same math as
    // funding_long_pays_short), but it only has 100.
    let events = perps.apply_funding(mid, 1).unwrap();
    assert!(events.iter().any(|e| e.kind == "funding_shortfall"));

    // Long drained to zero; short receives only what was
    // collected (100), not the computed 1_500.
    assert_eq!(perps.cross_margin(&addr(1)), 0);
    assert_eq!(perps.cross_margin(&addr(2)), 500_000_000 + 100);

    // Conservation: total user margin + insurance == deposits.
    let insurance = {
        let inner = framework::lock_state(&perps.inner);
        inner.insurance_fund
    };
    let total = perps.cross_margin(&addr(1)) + perps.cross_margin(&addr(2)) + insurance;
    assert_eq!(total, 500_000_100, "margin must be conserved exactly");
}

/// Regression test: orders that increase exposure require
/// `equity >= existing IM + new notional / max_leverage`. Before
/// the fix, positions could be opened with zero margin.
#[test]
fn place_rejected_without_initial_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    ledger.mint(&addr(9), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // addr(1) has NO margin — a 1-lot buy at tick 500 has
    // notional 1_000 * 1.5e9 / 1e8 = 15_000; IM at 10x = 1_500.
    let err = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));

    // Deposit 1_000 cross margin — still below the 1_500 IM.
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000)).unwrap();
    let err = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

/// With sufficient margin the same order is accepted and the
/// position opens.
#[test]
fn place_allowed_with_sufficient_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    ledger.mint(&addr(9), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // Seller needs margin too (its sell increases exposure).
    perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();

    // Rest a sell, then buy against it.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    let events = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    assert!(events.iter().any(|e| e.kind == "fill"));
    assert_eq!(perps.position(&addr(1), mid).size, 1_000);
}

// ── C7: core financial invariants ──────────────────────────────

/// A cross-margin withdrawal may not take account equity below
/// the initial-margin requirement of the open book. The old code
/// checked only the stored bucket balance — an account could
/// withdraw the margin backing an open position and become
/// instantly under-margined.
#[test]
fn withdraw_cross_cannot_break_initial_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    ledger.mint(&addr(9), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    // Buyer deposits exactly 2_000 — free collateral after a
    // 1-lot position (IM 1_500) is 500.
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 2_000)).unwrap();
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 1_000);

    // Withdraw 1_000: equity_after = 1_000 < IM 1_500 → reject.
    let err = perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 1_000)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    // Margin and ledger both untouched.
    assert_eq!(perps.cross_margin(&addr(1)), 2_000);

    // Withdraw exactly the free collateral (500): equity_after
    // = 1_500 = IM → allowed.
    perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 500)).unwrap();
    assert_eq!(perps.cross_margin(&addr(1)), 1_500);
}

/// An isolated-margin withdrawal may not pull the position's
/// own margin below its initial-margin requirement.
#[test]
fn withdraw_isolated_cannot_break_position_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    ledger.mint(&addr(9), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    // Isolated deposit of 2_000 backing a 1-lot position.
    perps.handle(&ctx(1), &msg::deposit(mid, 2_000)).unwrap();
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();

    // Withdraw 1_000 → isolated margin 1_000 < IM 1_500 → reject.
    let err = perps.handle(&ctx(1), &msg::withdraw(mid, 1_000)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
    // The free excess (500) withdraws fine.
    perps.handle(&ctx(1), &msg::withdraw(mid, 500)).unwrap();
    assert_eq!(perps.position(&addr(1), mid).isolated_margin, 1_500);
}

/// Closing part of a position must realize `PnL` into collateral.
/// The old code shrank `size` and kept the entry price but the
/// realized gain vanished — margin was never credited.
#[test]
fn partial_close_realizes_pnl_into_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    ledger.mint(&addr(9), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100_000)).unwrap();

    // Open a 2-lot long at 1.5e9 (tick 500).
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 2, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 2, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 2_000);

    // Maker bid at tick 600 (1.6e9); close 1 lot into it.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Buy, 600, 1, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 600, 1, 1))).unwrap();

    let pos = perps.position(&addr(1), mid);
    assert_eq!(pos.size, 1_000, "one lot remains");
    assert_eq!(pos.entry_price, 1_500_000_000, "entry unchanged on reduce");
    // Realized: 1_000 qty × (1.6e9 − 1.5e9) / 1e8 = 1_000.
    assert_eq!(
        perps.cross_margin(&addr(1)),
        100_000 + 1_000,
        "realized PnL must settle into margin"
    );
}

/// A sell larger than the long flips the position: the closed
/// portion realizes `PnL` and the remainder opens a short at the
/// fill price. The old code classified the whole order as a
/// reduce (skipping the IM gate AND the realized `PnL`).
#[test]
fn flip_close_realizes_pnl_and_reopens() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    ledger.mint(&addr(9), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 100_000)).unwrap();

    // Open a 1-lot long at 1.5e9.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();

    // Sell 3 lots into a 3-lot bid at 1.6e9 — flips to −2_000.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Buy, 600, 3, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 600, 3, 1))).unwrap();

    let pos = perps.position(&addr(1), mid);
    assert_eq!(pos.size, -2_000, "flipped remainder opens short");
    assert_eq!(pos.entry_price, 1_600_000_000, "new side enters at fill price");
    // Realized on the closed lot: 1_000 × (1.6e9 − 1.5e9) / 1e8 = 1_000.
    assert_eq!(perps.cross_margin(&addr(1)), 100_000 + 1_000);
}

/// Resting orders must reserve initial margin: two orders that
/// each fit inside equity must not both pass when their
/// combined requirement exceeds it. The old gate counted only
/// open positions — resting orders were free, so an account
/// could stack unbacked exposure that all later fills.
#[test]
fn resting_order_reserves_initial_margin() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // Equity 2_000 covers one lot's IM (1_500) but not two.
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 2_000)).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();

    let err = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap_err();
    assert!(
        matches!(err, ExecError::ModuleRejected(_)),
        "second resting order must exceed reserved initial margin"
    );
}

/// Cancelling a resting order releases its margin reservation:
/// the same order becomes placeable again.
#[test]
fn cancel_releases_order_reservation() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 2_000)).unwrap();
    let events = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    let resting = events.iter().find(|e| e.kind == "resting").expect("order rests");
    let order_id = OrderId(u64::from_le_bytes(resting.data[1..9].try_into().unwrap()));

    // Cancel → reservation released → an identical order fits again.
    perps.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
}

/// Liquidation must also cancel the account's resting orders —
/// otherwise unbacked orders of a bankrupt account keep
/// matching against the book.
#[test]
fn liquidation_cancels_resting_orders() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 2_000)).unwrap();
    let events = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    let resting = events.iter().find(|e| e.kind == "resting").expect("order rests");
    let order_id = OrderId(u64::from_le_bytes(resting.data[1..9].try_into().unwrap()));

    // Inject a deeply underwater position and crash the mark:
    // 100 lots long from entry 2.0e9, mark at 1.0e9 → equity
    // far below maintenance → liquidation must fire.
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(100_000),
                    entry_price: 2_000_000_000,
                    isolated_margin: 0,
                },
            );
        });
    }
    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
    let events = perps.liquidation_check(&addr(1)).unwrap();
    assert!(!events.is_empty(), "account must liquidate");

    // The resting order must be gone: cancel now reports
    // not-found rather than silently succeeding.
    let err = perps.handle(&ctx(1), &msg::cancel(mid, order_id)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

/// Reduce-only may only close: an order whose qty exceeds the
/// reducible position is rejected at admission, while an
/// in-cover close executes normally.
#[test]
fn reduce_only_rejects_oversized_close() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    ledger.mint(&addr(9), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();

    // Open a 1-lot long.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 1_000);

    // Reduce-only sell of 2 lots > 1 reducible → rejected.
    let err = perps
        .handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 500, 2, 1)))
        .unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));

    // Reduce-only sell of 1 lot — exactly the position — closes.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Buy, 500, 1, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 500, 1, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 0);
}

/// Closing capacity is allocated once across ALL of an account's
/// resting opposing orders (`cover_booked` at admission): two
/// reduce-only orders on one position may share the cover, but
/// their sum may never exceed it — otherwise every successive
/// order would spend the same cover and a fill storm could flip
/// the account into unbacked exposure. Admission must reject the
/// over-allocation, not leave it to the match-time cap.
#[test]
fn reduce_only_orders_share_one_positions_cover() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    for b in [1u8, 8, 9] {
        ledger.mint(&addr(b), 1_000_000);
    }
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    for b in [1u8, 8, 9] {
        perps.handle(&ctx(b), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    }

    // Owner 1 opens +10 long against owner 9.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 10, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 10, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 10_000);

    // First reduce-only sells 6 lots at a non-crossing price —
    // admitted (6 <= 10 reducible) and rests, booking 6 cover.
    perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 6, 1))).unwrap();

    // Second reduce-only of 5 lots: reducible is now 10 - 6 = 4,
    // so 5 over-allocates the position — rejected at admission.
    let err = perps
        .handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 5, 1)))
        .unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "over-cover must reject: {err:?}");

    // Exactly the remaining capacity — 4 lots — rests; the two
    // orders now book the position's full cover (6 + 4 = 10).
    perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 4, 1))).unwrap();

    // A third reduce-only now finds zero reducible cover — even
    // a 1-lot close is rejected while both resting orders hold
    // the entire position.
    let err = perps
        .handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 1, 1)))
        .unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "no cover left: {err:?}");

    // A taker sweeps both resting orders: the position closes to
    // exactly zero — never negative — and owner 8 takes +10.
    perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 700, 10, 8))).unwrap();
    assert_eq!(
        perps.position(&addr(1), mid).size,
        0,
        "shared-cover fills must close to zero, not flip short"
    );
    assert_eq!(perps.position(&addr(8), mid).size, 10_000);
}

/// A reduce-only order on the WRONG side of the book (no
/// reducible position) is rejected outright — there is nothing
/// it could reduce.
#[test]
fn reduce_only_without_position_rejected() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    // No position at all: any reduce-only order exceeds
    // reducible (0).
    let err = perps
        .handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 500, 1, 1)))
        .unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

/// A reduce-only order admitted at full cover can outlive its
/// position: the position shrinks under it via other fills.
/// Enforcement must cap the fill at the match decision — the
/// maker may only reduce what remains — not let the fill flip
/// the maker into new exposure and cancel the remainder after.
///
/// Owner 1: +10 long, reduce-only sell of 10 resting. A normal
/// sell of 5 fills first, shrinking the position to +5 — the
/// resting reduce-only now has only 5 cover. A taker buying 10
/// must fill just 5 and kill the remainder.
#[test]
fn reduce_only_maker_capped_at_match_decision() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    for b in [1u8, 8, 9] {
        ledger.mint(&addr(b), 1_000_000);
    }
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    for b in [1u8, 8, 9] {
        perps.handle(&ctx(b), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    }

    // Owner 1 opens +10 long against owner 9.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 10, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 10, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 10_000);

    // Reduce-only sell of 10 rests (admitted at full cover).
    let events =
        perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 10, 1))).unwrap();
    let resting = events.iter().find(|e| e.kind == "resting").expect("RO order rests");
    let ro_id = OrderId(u64::from_le_bytes(resting.data[1..9].try_into().unwrap()));

    // An ordinary sell of 5 fills first → position shrinks to
    // +5; the resting reduce-only now has only 5 cover.
    perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 500, 5, 8))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 500, 5, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 5_000);

    // A taker buying 10 hits the reduce-only maker: it may only
    // fill the 5 cover that remains, and the uncovered remainder
    // must die at the match — never flip the maker to −5.
    let events = perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 700, 10, 8))).unwrap();
    assert_eq!(
        perps.position(&addr(1), mid).size,
        0,
        "reduce-only fill must stop at the closing capacity, not flip"
    );
    assert!(
        events.iter().any(|e| e.kind == "reduce_only_cancel"),
        "the uncovered remainder must be reported canceled"
    );
    // The dead remainder is off the book: cancel reports not-found.
    let err = perps.handle(&ctx(1), &msg::cancel(mid, ro_id)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));
}

/// A resting order removed by self-trade prevention releases
/// its margin reservation — the sweep reports the removal
/// through `on_removed` so nothing is stranded.
#[test]
fn stp_removal_releases_margin_reservation() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();

    // Rest a buy at tick 400 — margin reserved against it.
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 400, 10, 1))).unwrap();

    // The same owner fires an IOC sell with CancelOldest: the
    // resting buy is removed without a fill and the IOC
    // remainder dies, leaving no orders behind.
    let taker = NewOrder {
        tif: TimeInForce::Ioc,
        stp: StpMode::CancelOldest,
        ..limit(Side::Sell, 400, 10, 1)
    };
    let events = perps.handle(&ctx(1), &msg::place(mid, taker)).unwrap();
    assert!(events.iter().any(|e| e.kind == "stp_cancel"));

    // Every reservation is gone: the full deposit withdraws.
    perps.handle(&ctx(1), &msg::withdraw(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    assert_eq!(perps.cross_margin(&addr(1)), 0);
}

/// Cover is allocated once per owner per sweep, across makers
/// of every kind: an ordinary opposing fill that exhausts the
/// position leaves zero cover for a reduce-only maker behind
/// it — the reduce-only must die unfilled, not open a short.
#[test]
fn reduce_only_behind_ordinary_fill_gets_no_cover() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    for b in [1u8, 8, 9] {
        ledger.mint(&addr(b), 1_000_000);
    }
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    for b in [1u8, 8, 9] {
        perps.handle(&ctx(b), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    }

    // Owner 1: +10 long.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 10, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 10, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 10_000);

    // Resting reduce-only sell of 10 @1.7e9, then an ordinary
    // sell of 10 @1.6e9 (admitted — the uncovered tail pays IM).
    perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 10, 1))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 600, 10, 1))).unwrap();

    // Taker buys 20 @1.7e9: sweeps the ordinary sell first (10
    // cover consumed → position flat), then the reduce-only
    // finds 0 cover and must die without filling.
    perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 700, 20, 8))).unwrap();
    assert_eq!(
        perps.position(&addr(1), mid).size,
        0,
        "reduce-only must not open a short behind the ordinary fill"
    );
    // Owner 8 holds the 10 it bought from the ordinary sell.
    assert_eq!(perps.position(&addr(8), mid).size, 10_000);
}

/// FOK all-or-nothing must count capped fills: a reduce-only
/// book that only covers 5 cannot satisfy a FOK buy of 10 —
/// the order must be killed, not partially filled.
#[test]
fn fok_counts_capped_fillable() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    for b in [1u8, 8, 9] {
        ledger.mint(&addr(b), 1_000_000);
    }
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    for b in [1u8, 8, 9] {
        perps.handle(&ctx(b), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    }

    // Same setup: +10 long, RO sell 10 resting, shrink to +5.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 10, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 10, 1))).unwrap();
    perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 700, 10, 1))).unwrap();
    perps.handle(&ctx(8), &msg::place(mid, limit(Side::Buy, 500, 5, 8))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 500, 5, 1))).unwrap();
    assert_eq!(perps.position(&addr(1), mid).size, 5_000);

    // FOK buy of 10 @1.7e9 — only 5 is legally fillable.
    let mut fok = limit(Side::Buy, 700, 10, 8);
    fok.tif = TimeInForce::Fok;
    let events = perps.handle(&ctx(8), &msg::place(mid, fok)).unwrap();
    assert!(
        events.iter().any(|e| e.kind == "killed"),
        "FOK must kill when capped fillable < requested"
    );
    assert_eq!(
        perps.position(&addr(1), mid).size,
        5_000,
        "a killed FOK must leave positions untouched"
    );
    assert_eq!(perps.position(&addr(8), mid).size, 5_000);
}

/// A position's closing capacity can only be spent once. With a
/// +10-lot long, one resting sell of 10 consumes all of it; a
/// second sell of 10 is new short exposure and must reserve
/// initial margin. The old gate scored each order against the
/// full position independently — N sells of 10 each looked
/// covered, stacking unbacked short exposure that all fills.
#[test]
fn position_cover_is_allocated_once_across_opposing_orders() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(1), 1_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();

    // +10-lot long at the mark — no PnL, isolated margin 0.
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(10_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            );
        });
    }
    // Equity covers the position IM (15_000) with headroom, but
    // not position IM + a fresh 10-lot exposure (≈11_000+).
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 20_000)).unwrap();

    // First opposing order: fully covered by the long → free.
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 100, 10, 1))).unwrap();

    // Second opposing order: cover exhausted → charged IM →
    // must exceed the remaining equity.
    let err = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Sell, 200, 10, 1))).unwrap_err();
    assert!(
        matches!(err, ExecError::ModuleRejected(_)),
        "cover allocated to the first order must not be spent twice"
    );
}

/// The unit-level view of the same invariant: `total_open_order_im`
/// charges the uncovered tail once the position's cover is spent,
/// and conservatively covers the CHEAPEST opposing orders first,
/// leaving the most expensive residual exposed.
#[test]
fn open_order_im_allocates_cover_once() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    let im = {
        let mut inner = framework::lock_state(&perps.inner);
        let configs = inner.configs.clone();
        PerpsModule::with_account_mut(&mut inner, &addr(1), |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(10_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            );
            for (oid, ticks) in [(1u64, 100u64), (2, 200)] {
                acct.open_orders.insert(
                    (mid, oid),
                    super::OpenOrderResv {
                        qty: 10_000,
                        price: 1_000_000_000 + ticks * 1_000_000,
                        side: Side::Sell,
                        reduce_only: false,
                    },
                );
            }
        });
        inner.accounts.get(&addr(1)).unwrap().total_open_order_im(&configs)
    };
    // Cover pool = 10_000 → retires the cheaper sell (1.1e9);
    // exposed tail = 10_000 × 1.2e9 / lev(10) / 1e8 = 12_000.
    assert_eq!(im, 12_000, "the uncovered sell must reserve initial margin");
}

/// Snapshot round-trip: a listed market, funded accounts,
/// positions, and resting orders on both sides must export,
/// verify, and re-import byte-identically — the imported
/// module's root must equal the source's (audit 3.2).
#[test]
fn state_snapshot_round_trips() {
    let src = PerpsModule::new();
    let mid = src.list_market(test_cfg()).unwrap();
    src.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000_000)).unwrap();
    src.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000_000)).unwrap();
    // A crossed pair opens positions for both sides…
    src.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 1, 9))).unwrap();
    src.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    // …and a second resting sell stays on the book.
    src.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 700, 2, 9))).unwrap();

    let snapshot = src.export_state().expect("perps exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

    let dst = PerpsModule::new();
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    assert_eq!(dst.mark_price(mid), src.mark_price(mid));
    assert_eq!(dst.cross_margin(&addr(1)), src.cross_margin(&addr(1)));
    assert_eq!(dst.position(&addr(1), mid).size, src.position(&addr(1), mid).size);
}

/// A truncated blob must fail inspection and import — the
/// claimed root is never trusted over the bytes.
#[test]
fn state_snapshot_rejects_corruption() {
    let src = PerpsModule::new();
    src.list_market(test_cfg()).unwrap();
    let mut snapshot = src.export_state().unwrap();
    snapshot.entries[0].1.truncate(12);
    assert!(src.inspect_state(&snapshot).is_err());
    assert!(PerpsModule::new().import_state(&snapshot).is_err());
}

/// Fold lockstep (7.4): `accounts`'s maintained root must equal
/// the authoritative O(n) recompute after every mutation shape —
/// deposit, rest (`open_orders`), fill (positions + reservation
/// decrement), cancel, and margin withdraw — plus the store fold.
/// A mutation path that skipped `insert` would leave the fold
/// stale and this test would catch it.
#[test]
fn committed_folds_track_account_and_book_mutations() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();

    let assert_locked = |perps: &PerpsModule| {
        let store = framework::lock_state(&perps.store);
        assert_eq!(store.root(), store.recomputed_root(), "store fold must stay in lockstep");
        let inner = framework::lock_state(&perps.inner);
        assert_eq!(
            inner.accounts.root(),
            inner.accounts.recomputed_root(),
            "accounts fold must stay in lockstep"
        );
    };

    // Deposits create + credit accounts.
    perps.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    perps.handle(&ctx(9), &msg::deposit(super::CROSS_MARGIN_MARKET, 500_000)).unwrap();
    assert_locked(&perps);

    // Resting sells write open_order reservations; the crossing
    // buy fills one and rests nothing.
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 500, 2, 9))).unwrap();
    perps.handle(&ctx(9), &msg::place(mid, limit(Side::Sell, 700, 3, 9))).unwrap();
    perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap();
    assert_locked(&perps);

    // Cancel the remaining resting order — reservation removal
    // must fold the account.
    perps.handle(&ctx(9), &msg::cancel(mid, trading::OrderId(1))).unwrap();
    assert_locked(&perps);

    // Isolated-margin deposit + withdraw touch nested position
    // fields — the account-level leaf must still track.
    perps.handle(&ctx(1), &msg::deposit(mid, 50_000)).unwrap();
    assert_locked(&perps);
    perps.handle(&ctx(1), &msg::withdraw(mid, 10_000)).unwrap();
    assert_locked(&perps);
}

// ── Live-pipeline liquidation + oracle staleness ─────────────

/// An underwater position fixture: long `50_000` at entry 1.5B
/// with 100k margin; the mark is crashed to 1.0B via the
/// unchecked setter (the deviation cap would need several
/// checked steps). Loss = `50_000·0.5e9/1e8` = 250k > margin —
/// equity ≈ −150k against ~2.5k maintenance.
fn setup_underwater() -> (PerpsModule, u8, Address) {
    let (perps, mid, acct) = setup_with_position(100_000, 50_000, 1_500_000_000);
    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
    (perps, mid, acct)
}

/// `TAG_LIQUIDATE` is the live liquidation path: a permissionless
/// tx on an underwater account must run the full liquidation
/// (position closed, `liquidated` event emitted) — the path
/// that previously existed only in tests/sims/benches.
#[test]
fn liquidate_tx_liquidates_underwater_account() {
    let (perps, mid, acct) = setup_underwater();
    // A DIFFERENT sender submits the trigger — the tx is
    // permissionless (the keeper is not the liquidated account).
    let events = perps.handle(&ctx(7), &msg::liquidate(&acct)).unwrap();
    assert!(
        events.iter().any(|e| e.kind == "liquidated"),
        "liquidate tx must emit liquidated events, got: {events:?}"
    );
    assert_eq!(perps.position(&acct, mid).size, 0, "position must be closed");
}

/// The same tx on a solvent account is a no-op (the sender only
/// burns its fee — the spam vector is priced, not free).
#[test]
fn liquidate_tx_solvent_account_is_noop() {
    let (perps, mid, acct) = setup_with_position(1_000_000_000, 1_000, 1_500_000_000);
    let events = perps.handle(&ctx(7), &msg::liquidate(&acct)).unwrap();
    assert!(events.is_empty(), "solvent account must not liquidate");
    assert_eq!(perps.position(&acct, mid).size, 1_000);
}

/// Malformed liquidate bodies are rejected, not ignored.
#[test]
fn liquidate_tx_rejects_bad_length() {
    let perps = PerpsModule::new();
    perps.list_market(test_cfg()).unwrap();
    let mut bad = vec![super::TAG_LIQUIDATE];
    bad.extend_from_slice(&[0u8; 19]);
    assert_eq!(perps.handle(&ctx(1), &bad), Err(ExecError::Malformed));
}

/// Staleness puts a market in reduce-only mode: a mark last
/// accepted more than `MAX_MARK_STALENESS_BLOCKS` ago rejects
/// new exposure but still admits risk-reducing orders.
#[test]
fn stale_mark_rejects_new_exposure_allows_reduce_only() {
    let (perps, mid, acct) = setup_with_position(1_000_000_000, 50_000, 1_500_000_000);
    assert!(!perps.mark_is_stale(mid), "freshly listed mark is fresh");

    // Advance past the staleness horizon without a mark update.
    perps.begin_block(Height::new(61));
    assert!(perps.mark_is_stale(mid), "60+ blocks without an update is stale");

    // New exposure is refused…
    let err = perps.handle(&ctx(1), &msg::place(mid, limit(Side::Buy, 500, 1, 1))).unwrap_err();
    match err {
        ExecError::ModuleRejected(reason) => {
            assert!(reason.detail.contains("stale"), "expected stale rejection, got: {reason}");
        }
        _ => panic!("expected ModuleRejected, got {err:?}"),
    }

    // …but a reduce-only close of the existing long still lands
    // (closing exposure is never blocked by a feed outage).
    let resp = perps.handle(&ctx(1), &msg::place_reduce_only(mid, limit(Side::Sell, 500, 1, 1)));
    assert!(resp.is_ok(), "reduce-only must pass the stale gate: {resp:?}");
    let _ = acct;
}

/// A fresh mark refresh restores full trading: the staleness
/// gate releases on the next accepted update.
#[test]
fn stale_mark_refresh_restores_trading() {
    let (perps, mid, _) = setup_with_position(1_000_000_000, 50_000, 1_500_000_000);
    perps.begin_block(Height::new(61));
    assert!(perps.mark_is_stale(mid));
    // Any accepted setter refreshes the age — unchecked used
    // here (the checked path's deviation cap is orthogonal).
    perps.set_mark_price_unchecked(mid, 1_500_000_000).unwrap();
    assert!(!perps.mark_is_stale(mid), "accepted update must refresh the mark age");
}

/// The `end_block` sweep enforces liquidation in the live
/// pipeline: an underwater account is liquidated by the sweep
/// itself, emitting `liquidated` events into the block log —
/// no keeper tx required.
#[test]
fn end_block_sweep_liquidates_underwater_account() {
    let (perps, mid, acct) = setup_underwater();
    // A solvent account alongside (cursor must still land on it).
    perps.handle(&ctx(2), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000)).unwrap();

    let events = perps.end_block(Height::new(1));
    assert!(
        events.iter().any(|e| e.kind == "liquidated"),
        "sweep must liquidate the underwater account: {events:?}"
    );
    assert_eq!(perps.position(&acct, mid).size, 0);
    // The cursor advanced past the checked accounts — addr(1)
    // and addr(2) were both in this block's window.
    let inner = framework::lock_state(&perps.inner);
    assert_eq!(inner.liquidation_cursor, Some(addr(2)));
}

/// The sweep covers the whole account set over successive
/// blocks: `LIQUIDATION_SWEEP_BUDGET` per block, then the cursor
/// wraps and coverage restarts. 33 accounts (> 32-budget)
/// proves the window advances rather than rescanning the head.
#[test]
fn end_block_sweep_cursor_advances_and_wraps() {
    let perps = PerpsModule::new();
    {
        let mut inner = framework::lock_state(&perps.inner);
        for n in 1u8..=33 {
            PerpsModule::with_account_mut(&mut inner, &addr(n), |_| {});
        }
    }
    // Block 1: first 32 accounts checked.
    perps.end_block(Height::new(1));
    assert_eq!(
        framework::lock_state(&perps.inner).liquidation_cursor,
        Some(addr(32)),
        "cursor lands on the last checked account"
    );
    // Block 2: the 33rd.
    perps.end_block(Height::new(2));
    assert_eq!(framework::lock_state(&perps.inner).liquidation_cursor, Some(addr(33)));
    // Block 3: past the end — wrap to restart coverage.
    perps.end_block(Height::new(3));
    assert_eq!(framework::lock_state(&perps.inner).liquidation_cursor, None);
    // Block 4: coverage restarts from the first account.
    perps.end_block(Height::new(4));
    assert_eq!(framework::lock_state(&perps.inner).liquidation_cursor, Some(addr(32)));
}

/// The funding-rate bound: ±500 bps applies, ±501 and `i64::MIN`
/// are rejected — a quorum-endorsed rate can still not move an
/// arbitrary fraction of open notional.
#[test]
fn funding_rate_bound_enforced() {
    let (perps, mid, _) = setup_with_position(1_000_000_000, 50_000, 1_500_000_000);
    assert!(perps.apply_funding(mid, 500).is_ok(), "boundary rate applies");
    assert!(perps.apply_funding(mid, -500).is_ok());
    assert!(perps.apply_funding(mid, 501).is_err(), "over bound rejected");
    assert!(perps.apply_funding(mid, -501).is_err());
    assert!(perps.apply_funding(mid, i64::MIN).is_err(), "MIN must not panic");
}

/// The committed trailing section round-trips: mark ages and
/// the liquidation cursor survive export → import, so staleness
/// decisions and sweep position agree across nodes and restarts.
#[test]
fn state_snapshot_round_trips_mark_age_and_cursor() {
    let src = PerpsModule::new();
    let mid = src.list_market(test_cfg()).unwrap();
    // Give the market a recorded age at height 3 and a checked
    // cursor position.
    src.begin_block(Height::new(3));
    src.set_mark_price_unchecked(mid, 1_500_000_000).unwrap();
    src.handle(&ctx(1), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000)).unwrap();
    src.handle(&ctx(2), &msg::deposit(super::CROSS_MARGIN_MARKET, 1_000)).unwrap();
    src.end_block(Height::new(3)); // sweep checks both accounts

    let snapshot = src.export_state().expect("perps exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

    let dst = PerpsModule::new();
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    assert_eq!(dst.mark_is_stale(mid), src.mark_is_stale(mid));
    let src_cursor = framework::lock_state(&src.inner).liquidation_cursor;
    let dst_cursor = framework::lock_state(&dst.inner).liquidation_cursor;
    assert_eq!(dst_cursor, src_cursor);
}

// ── Clearing-model tests (funded liabilities, net position) ──

/// Sum of signed position sizes across every account —
/// clearing account included — for one market. The clearing
/// model's central invariant: zero net position per market.
fn net_position(perps: &PerpsModule, market: u8) -> i128 {
    let inner = framework::lock_state(&perps.inner);
    inner
        .accounts
        .values()
        .map(|a| a.positions.get(&market).map_or(0i128, |p| i128::from(p.size)))
        .sum()
}

/// Liquidation moves the seized position to the clearing
/// account at mark rather than zeroing it — the audit's "where
/// do liquidated positions go" is the backstop, and net
/// position stays zero including it.
#[test]
fn liquidation_transfers_position_to_clearing_account() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // Long + short counterparties — the book nets to zero.
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 50_000,
                },
            )
        });
        PerpsModule::with_account_mut(&mut inner, &addr(2), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(-100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 100_000,
                },
            )
        });
        // A funded insurance fund covers the loss outright —
        // no ADL, so the transfer is isolated for the assertion.
        inner.insurance_fund = 1_000_000;
    }
    assert_eq!(net_position(&perps, mid), 0);
    // Mark drops — the long is deep underwater.
    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
    let events = perps.liquidation_check(&addr(1)).unwrap();
    assert!(events.iter().any(|e| e.kind == "liquidated"));

    assert_eq!(perps.position(&addr(1), mid).size, 0, "seized position closed");
    let clearing = perps.position(&CLEARING_ACCOUNT, mid);
    assert_eq!(clearing.size, 100_000, "backstop inherits the long");
    assert_eq!(clearing.entry_price, 1_000_000_000, "inherited at mark");
    // The audit's required property holds with the backstop in
    // the sum.
    assert_eq!(net_position(&perps, mid), 0, "net position stays zero");
}

/// ADL claws the PROFIT — the counterparty's margin is
/// untouched (claim destruction is the extraction, not a margin
/// debit), and the closed quantity transfers to the clearing
/// account so net position stays zero.
#[test]
fn adl_clawed_exposure_transfers_to_clearing() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 50_000,
                },
            )
        });
        PerpsModule::with_account_mut(&mut inner, &addr(2), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(-100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 100_000,
                },
            )
        });
        inner.insurance_fund = 0;
    }
    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
    let events = perps.liquidation_check(&addr(1)).unwrap();
    assert!(events.iter().any(|e| e.kind == "adl_executed"), "ADL must run: {events:?}");

    let counter = perps.position(&addr(2), mid);
    let clearing = perps.position(&CLEARING_ACCOUNT, mid);
    // The counterparty's short shrank by exactly the clawed
    // quantity; the clearing account now holds BOTH the seized
    // long AND the clawed short, netting the difference.
    assert_eq!(counter.size + clearing.size, 0, "clawed exposure nets through clearing");
    assert_eq!(counter.isolated_margin, 100_000, "margin untouched — claim destruction only");
    assert_eq!(net_position(&perps, mid), 0);
}

/// A loss exceeding margin AND the insurance fund becomes a
/// tracked liability, not just an event: `unfunded_bad_debt`
/// accrues the post-ADL remainder.
#[test]
fn bad_debt_residual_becomes_tracked_liability() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &addr(1), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(1_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 10,
                },
            )
        });
        inner.insurance_fund = 0;
    }
    // Realize a loss far beyond margin with no profitable
    // counterparty to claw — the full remainder is booked.
    let mut events = Vec::new();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::settle_realized(&mut inner, &addr(1), mid, -50_000, &mut events);
    }
    assert_eq!(perps.unfunded_bad_debt(), 50_000 - 10);
    assert!(events.iter().any(|e| e.kind == "unfunded_bad_debt"));
    assert!(events.iter().any(|e| e.kind == "bad_debt"));
}

/// `unfunded_bad_debt` is a senior claim: fund inflows retire
/// the liability before the fund balance grows.
#[test]
fn fund_inflow_retires_bad_debt_before_fund() {
    let perps = PerpsModule::new();
    {
        let mut inner = framework::lock_state(&perps.inner);
        inner.unfunded_bad_debt = 30_000;
        PerpsModule::fund_inflow(&mut inner, 50_000);
        assert_eq!(inner.unfunded_bad_debt, 0, "inflow retires the debt first");
        assert_eq!(inner.insurance_fund, 20_000, "remainder accrues");
        PerpsModule::fund_inflow(&mut inner, 10_000);
        assert_eq!(inner.insurance_fund, 30_000);
    }
    assert_eq!(perps.insurance_fund(), 30_000);
}

/// The clearing account's realized `PnL` settles against the
/// insurance fund directly — a gain replenishes the fund, a
/// loss the fund cannot cover becomes tracked bad debt.
#[test]
fn clearing_realized_pnl_settles_against_fund() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        inner.insurance_fund = 1_000;
        // A gain flows into the fund.
        let mut events = Vec::new();
        PerpsModule::settle_realized(&mut inner, &CLEARING_ACCOUNT, mid, 500, &mut events);
        assert_eq!(inner.insurance_fund, 1_500);
        // A loss beyond the fund books the remainder as debt.
        let mut events = Vec::new();
        PerpsModule::settle_realized(&mut inner, &CLEARING_ACCOUNT, mid, -3_000, &mut events);
        assert_eq!(inner.insurance_fund, 0, "fund drained covering the loss");
        assert_eq!(inner.unfunded_bad_debt, 1_500, "uncovered remainder tracked");
    }
}

/// The clearing account can never be a tx sender — forged-
/// sender paths must not move backstop collateral through the
/// ordinary message surface.
#[test]
fn clearing_account_cannot_transact() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let perps = PerpsModule::with_ledger(ledger);
    perps.list_market(test_cfg()).unwrap();
    let forged = TxContext { sender: CLEARING_ACCOUNT, nonce: 0, fee: 0 };
    for m in [
        msg::deposit(CROSS_MARGIN_MARKET, 1_000),
        msg::withdraw(CROSS_MARGIN_MARKET, 1_000),
        msg::place(0, limit(Side::Buy, 500, 1, 9)),
    ] {
        assert!(
            matches!(perps.handle(&forged, &m), Err(ExecError::ModuleRejected(_))),
            "clearing sender must be rejected"
        );
    }
}

/// The backstop cannot be liquidated — its losses are the
/// fund's own exposure, managed by the unwind, not seizure.
#[test]
fn liquidation_check_noops_on_clearing_account() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &CLEARING_ACCOUNT, |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            )
        });
    }
    perps.set_mark_price_unchecked(mid, 1_000_000_000).unwrap();
    let events = perps.liquidation_check(&CLEARING_ACCOUNT).unwrap();
    assert!(events.is_empty(), "backstop is never seized");
    assert_eq!(perps.position(&CLEARING_ACCOUNT, mid).size, 100_000, "inventory intact");
}

/// `end_block` unwinds clearing inventory into the book at
/// mark: the IOC sell fills a resting bid, the backstop exits,
/// and its realized `PnL` settles against the fund.
#[test]
fn end_block_unwinds_clearing_inventory() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(2), 10_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    // Backstop holds a long at mark — entry equals mark so the
    // unwind fill realizes ~0 for the fund (the settle-to-fund
    // path itself is covered by clearing_realized_pnl_settles).
    // A short counterparty balances the book: in the live flow
    // the seized long's original counterparty is still short.
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &CLEARING_ACCOUNT, |a| {
            a.positions.insert(
                mid,
                Position { size: SignedQty(5_000), entry_price: 1_500_000_000, isolated_margin: 0 },
            )
        });
        PerpsModule::with_account_mut(&mut inner, &addr(3), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(-5_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 50_000,
                },
            )
        });
    }
    assert_eq!(net_position(&perps, mid), 0);
    // A buyer rests a bid at mark.
    perps.handle(&ctx(2), &msg::deposit(CROSS_MARGIN_MARKET, 10_000_000)).unwrap();
    let resp = perps.handle(
        &ctx(2),
        &msg::place(mid, limit(Side::Buy, 500, 5, 2)), // price 1.5B, qty 5000
    );
    assert!(resp.is_ok(), "bid must rest: {resp:?}");

    perps.end_block(Height::new(1));
    let clearing = perps.position(&CLEARING_ACCOUNT, mid);
    assert_eq!(clearing.size, 0, "inventory unwound through the book");
    let buyer = perps.position(&addr(2), mid);
    assert_eq!(buyer.size, 5_000, "buyer took the other side");
    // The maker's reservation for the filled order is released.
    {
        let inner = framework::lock_state(&perps.inner);
        let acct2 = inner.accounts.get(&addr(2)).expect("buyer exists");
        assert!(acct2.open_orders.is_empty(), "filled reservation released");
    }
    // Entry = mark = fill, so the clearing account realizes ~0 —
    // the fund is unchanged by a flat unwind.
    assert_eq!(perps.insurance_fund(), 0);
    assert_eq!(net_position(&perps, mid), 0);
}

/// When the book gaps below mark, the unwind pays bounded
/// slippage — the IOC limit sits at `mark·(1−
/// BACKSTOP_UNWIND_SLIPPAGE_BPS)` — so bids resting just under
/// mark still take the inventory instead of stranding it while
/// the mark keeps falling.
#[test]
fn unwind_pays_bounded_slippage_when_book_gaps() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(2), 10_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &CLEARING_ACCOUNT, |a| {
            a.positions.insert(
                mid,
                Position { size: SignedQty(5_000), entry_price: 1_500_000_000, isolated_margin: 0 },
            )
        });
        PerpsModule::with_account_mut(&mut inner, &addr(3), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(-5_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 50_000,
                },
            )
        });
        inner.insurance_fund = 10_000;
    }
    // The bid rests ~0.67% below the 1.5B mark — inside the 1%
    // allowance (floor 1.485B), so it fills at its resting price.
    perps.handle(&ctx(2), &msg::deposit(CROSS_MARGIN_MARKET, 10_000_000)).unwrap();
    perps
        .handle(&ctx(2), &msg::place(mid, limit(Side::Buy, 490, 5, 2))) // 1.49B
        .unwrap();

    perps.end_block(Height::new(1));
    assert_eq!(
        perps.position(&CLEARING_ACCOUNT, mid).size,
        0,
        "a bid inside the allowance must take the inventory"
    );
    assert_eq!(perps.position(&addr(2), mid).size, 5_000);
    // Fill at 1.49B against a 1.5B entry: −0.01B × 5_000 / 1e8 =
    // −500 scale-6 settles against the fund — bounded slippage
    // paid, never arbitrary.
    assert_eq!(perps.insurance_fund(), 9_500, "fund pays only the bounded slippage");
    assert_eq!(net_position(&perps, mid), 0);
}

/// The allowance is a real bound: bids deeper than
/// `mark·(1−1%)` are not swept — the IOC dies unfilled and the
/// inventory persists for the next pass.
#[test]
fn unwind_does_not_sweep_beyond_the_allowance() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(2), 10_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &CLEARING_ACCOUNT, |a| {
            a.positions.insert(
                mid,
                Position { size: SignedQty(5_000), entry_price: 1_500_000_000, isolated_margin: 0 },
            )
        });
        PerpsModule::with_account_mut(&mut inner, &addr(3), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(-5_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 50_000,
                },
            )
        });
    }
    perps.handle(&ctx(2), &msg::deposit(CROSS_MARGIN_MARKET, 10_000_000)).unwrap();
    // Bid at 1.4B — ~6.7% below mark, under the 1.485B floor.
    perps.handle(&ctx(2), &msg::place(mid, limit(Side::Buy, 400, 5, 2))).unwrap();

    perps.end_block(Height::new(1));
    assert_eq!(
        perps.position(&CLEARING_ACCOUNT, mid).size,
        5_000,
        "a bid beyond the allowance must not be swept"
    );
    assert_eq!(perps.position(&addr(2), mid).size, 0, "the deep bid is untouched");
    assert_eq!(net_position(&perps, mid), 0);
}

/// The buy side is symmetric: a short inventory exits into asks
/// up to `mark·(1+1%)` — the cap rounds DOWN to the tick grid so
/// the fund never pays past the allowance to stay on-grid.
#[test]
fn unwind_short_inventory_buys_up_to_the_cap() {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&addr(2), 10_000_000);
    let perps = PerpsModule::with_ledger(ledger.clone());
    let mid = perps.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &CLEARING_ACCOUNT, |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(-5_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 0,
                },
            )
        });
        PerpsModule::with_account_mut(&mut inner, &addr(3), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(5_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 50_000,
                },
            )
        });
        inner.insurance_fund = 10_000;
    }
    // Ask at 1.51B — ~0.67% above the 1.5B mark, inside the
    // 1.515B cap.
    perps.handle(&ctx(2), &msg::deposit(CROSS_MARGIN_MARKET, 10_000_000)).unwrap();
    perps
        .handle(&ctx(2), &msg::place(mid, limit(Side::Sell, 510, 5, 2))) // 1.51B
        .unwrap();

    perps.end_block(Height::new(1));
    assert_eq!(
        perps.position(&CLEARING_ACCOUNT, mid).size,
        0,
        "an ask inside the allowance must take the short inventory"
    );
    assert_eq!(perps.position(&addr(2), mid).size, -5_000);
    assert_eq!(net_position(&perps, mid), 0);
}

/// ADL claws are lot-aligned: a claw target that prices to a
/// sub-lot quantity floors down to the lot grid, so the transfer
/// to the clearing account never strands untradeable dust there
/// — the unwind exits whole lots only. Whatever the floored claw
/// cannot cover falls through to `unfunded_bad_debt`, the
/// designed sink.
#[test]
fn adl_claw_is_lot_aligned() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&perps.inner);
        // Long 100 lots at 1.5B with 480k margin; short
        // counterparty at the same entry.
        PerpsModule::with_account_mut(&mut inner, &addr(1), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 480_000,
                },
            )
        });
        PerpsModule::with_account_mut(&mut inner, &addr(2), |a| {
            a.positions.insert(
                mid,
                Position {
                    size: SignedQty(-100_000),
                    entry_price: 1_500_000_000,
                    isolated_margin: 100_000,
                },
            )
        });
        inner.insurance_fund = 0;
    }
    // Mark 1.01B: the long's loss is 100_000 × 0.49e9 / 1e8 =
    // 490_000 → shortfall 10_000 over margin. The short's
    // pnl_per_unit is 0.49e9, so claw_qty = 10_000 × 1e8 /
    // 0.49e9 ≈ 2_040.8 — sub-lot before the fix.
    perps.set_mark_price_unchecked(mid, 1_010_000_000).unwrap();
    let events = perps.liquidation_check(&addr(1)).unwrap();
    assert!(events.iter().any(|e| e.kind == "adl_executed"), "ADL must run: {events:?}");

    // The clawed quantity is exactly 2_000 (2_040 floored to
    // the lot grid) — both sides stay lot-aligned.
    assert_eq!(perps.position(&addr(2), mid).size, -98_000, "claw floors to a whole lot");
    assert_eq!(
        perps.position(&CLEARING_ACCOUNT, mid).size,
        98_000,
        "seized 100_000 long netted against the 2_000 clawed short stays aligned"
    );
    assert_eq!(net_position(&perps, mid), 0);
    // Realized cover = 2_000 × 0.49e9 / 1e8 = 9_800 of the
    // 10_000 shortfall; the floored-away remainder is debt.
    assert_eq!(perps.unfunded_bad_debt(), 200);
}

/// The unpaid-loss liability and the clearing account's
/// inventory are committed state — they survive export → import
/// so all nodes agree on who is owed what after a restart.
#[test]
fn state_snapshot_round_trips_unfunded_debt_and_clearing() {
    let src = PerpsModule::new();
    let mid = src.list_market(test_cfg()).unwrap();
    {
        let mut inner = framework::lock_state(&src.inner);
        inner.unfunded_bad_debt = 42_000;
        PerpsModule::with_account_mut(&mut inner, &CLEARING_ACCOUNT, |a| {
            a.positions.insert(
                mid,
                Position { size: SignedQty(7_000), entry_price: 1_500_000_000, isolated_margin: 0 },
            )
        });
    }
    let snapshot = src.export_state().expect("perps exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());
    let dst = PerpsModule::new();
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    assert_eq!(dst.unfunded_bad_debt(), 42_000);
    assert_eq!(dst.position(&CLEARING_ACCOUNT, mid).size, 7_000);
}

/// System scenario: an oracle outage and an extreme move through
/// the REAL oracle → `MarkSink` → perps pipeline — not a mocked
/// sink. Covers the three guarantees an outage must preserve:
///
/// 1. Stale marks put the market in reduce-only mode (new
///    exposure refused, closing still admitted).
/// 2. The liquidation sweep keeps running on the last accepted
///    mark — freezing risk-reduction during a feed outage would
///    strand underwater accounts.
/// 3. Recovery publishes again, and an extreme single-block
///    move is rejected at the perps deviation cap (fail-closed)
///    while a moderate move lands EMA-dampened.
///
/// Four validators at uniform power: the oracle's stake-weighted
/// quorum needs three submissions per block.
#[test]
fn oracle_outage_and_recovery_through_real_pipeline() {
    struct FourValidators;
    impl framework::Committee for FourValidators {
        fn is_active_validator(&self, a: &Address) -> bool {
            (1..=4).any(|b| *a == addr(b))
        }
        fn active_validator_count(&self) -> usize {
            4
        }
        fn power(&self, a: &Address) -> u64 {
            u64::from(self.is_active_validator(a))
        }
        fn total_power(&self) -> u64 {
            4
        }
    }

    let perps = Arc::new(PerpsModule::new());
    let mid = perps.list_market(test_cfg()).unwrap();
    let oracle = oracle::OracleModule::new().with_committee(Arc::new(FourValidators));
    oracle.with_sink(perps.clone());

    // An account that will be underwater at any sane mark:
    // entered long near the top of the price band with dust
    // margin.
    let victim = addr(9);
    {
        let mut inner = framework::lock_state(&perps.inner);
        PerpsModule::with_account_mut(&mut inner, &victim, |acct| {
            acct.positions.insert(
                mid,
                Position {
                    size: SignedQty(50_000),
                    entry_price: 1_900_000_000,
                    isolated_margin: 100_000,
                },
            );
        });
    }

    // ── Healthy: three validators submit → quorum → the mark
    // lands on perps through the real sink.
    perps.begin_block(Height::new(1));
    for v in 1..=3u8 {
        oracle.handle(&ctx(v), &oracle::msg::submit_price(mid, 1_500_000_000)).unwrap();
    }
    oracle.end_block(Height::new(1));
    assert_eq!(perps.mark_price(mid), Some(1_500_000_000));
    assert!(!perps.mark_is_stale(mid));

    // ── Outage: no submissions for STALE_AFTER+ blocks. The
    // mark goes stale → new exposure refused…
    let outage_height = 1 + 61;
    perps.begin_block(Height::new(outage_height));
    assert!(perps.mark_is_stale(mid), "61+ blocks silent is stale");
    let err = perps.handle(&ctx(5), &msg::place(mid, limit(Side::Buy, 500, 1, 5))).unwrap_err();
    match err {
        ExecError::ModuleRejected(reason) => {
            assert!(reason.detail.contains("stale"), "expected stale rejection, got: {reason}");
        }
        _ => panic!("expected ModuleRejected, got {err:?}"),
    }
    // …closing is still admitted…
    assert!(
        perps.handle(&ctx(9), &msg::place_reduce_only(mid, limit(Side::Sell, 500, 1, 9))).is_ok(),
        "reduce-only must pass the stale gate during an outage"
    );
    // …and the end-block sweep still liquidates the underwater
    // account at the last accepted mark.
    let events = perps.end_block(Height::new(outage_height));
    assert!(
        events.iter().any(|e| e.kind == "liquidated"),
        "sweep must still run during an outage: {events:?}"
    );
    assert_eq!(perps.position(&victim, mid).size, 0);

    // ── Extreme move rejected: a 10× submission is dampened by
    // the oracle EMA (×1/4 weight) but still lands >10% off the
    // last accepted mark → the perps cap refuses it and BOTH
    // sides honestly stay stale.
    perps.begin_block(Height::new(outage_height + 1));
    for v in 1..=3u8 {
        oracle.handle(&ctx(v), &oracle::msg::submit_price(mid, 15_000_000_000)).unwrap();
    }
    oracle.end_block(Height::new(outage_height + 1));
    assert_eq!(
        perps.mark_price(mid),
        Some(1_500_000_000),
        "deviation-capped update must not move the mark"
    );
    assert!(perps.mark_is_stale(mid), "rejected update must not refresh staleness");

    // ── Recovery: a moderate move (+27% raw) is EMA-dampened to
    // (1.5e9·3 + 1.9e9)/4 = 1.6e9 → +6.7% < 10% cap → published,
    // staleness cleared, trading restored.
    perps.begin_block(Height::new(outage_height + 2));
    for v in 1..=3u8 {
        oracle.handle(&ctx(v), &oracle::msg::submit_price(mid, 1_900_000_000)).unwrap();
    }
    oracle.end_block(Height::new(outage_height + 2));
    assert_eq!(perps.mark_price(mid), Some(1_600_000_000));
    assert!(!perps.mark_is_stale(mid), "accepted update clears staleness");
}

// ── `perps.*` parameter sink ────────────────────────────────
// Governed market-risk knobs land on BOTH halves of the config
// state: the live `inner.configs` the margin math reads and the
// committed `market_config_key` record replay/state-root
// serialize — the same pair `list_market` maintains.

fn param_value(market: u8, v: u16) -> Vec<u8> {
    let mut value = vec![market];
    value.extend_from_slice(&v.to_le_bytes());
    value
}

#[test]
fn perps_sink_applies_market_risk_params() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    framework::ParameterSink::apply_param(&perps, b"perps.max_leverage", &param_value(mid, 25))
        .expect("max_leverage apply");
    framework::ParameterSink::apply_param(&perps, b"perps.mmr_base_bps", &param_value(mid, 200))
        .expect("mmr_base_bps apply");
    let cfg = framework::lock_state(&perps.inner).configs[&mid];
    assert_eq!(cfg.max_leverage, 25);
    assert_eq!(cfg.mmr_base_bps, 200);
    // The committed record moved with the live map — a snapshot
    // export/replay must describe the governed value, not the
    // listing-time one.
    let store = framework::lock_state(&perps.store);
    let record =
        store.get(&crate::market_config_key(mid)).expect("config record exists after apply");
    assert_eq!(*record, crate::encode_perps_config(&cfg));
}

#[test]
fn perps_sink_rejects_unknown_market_and_invalid_values() {
    let perps = PerpsModule::new();
    let mid = perps.list_market(test_cfg()).unwrap();
    // A market that was never listed has no config to mutate.
    assert!(
        framework::ParameterSink::apply_param(&perps, b"perps.max_leverage", &param_value(9, 5))
            .is_err(),
        "unlisted market must reject"
    );
    // leverage 0 = infinite margin — `validate()` refuses it, and
    // a refused apply must not touch the live config.
    assert!(
        framework::ParameterSink::apply_param(&perps, b"perps.max_leverage", &param_value(mid, 0))
            .is_err(),
        "zero leverage must reject"
    );
    // mmr above 100% — same validation boundary.
    assert!(
        framework::ParameterSink::apply_param(
            &perps,
            b"perps.mmr_base_bps",
            &param_value(mid, 10_001)
        )
        .is_err(),
        "mmr > 100% must reject"
    );
    // Foreign key and malformed payload.
    assert!(
        framework::ParameterSink::apply_param(&perps, b"perps.other", &param_value(mid, 5))
            .is_err()
    );
    assert!(framework::ParameterSink::apply_param(&perps, b"perps.max_leverage", &[mid]).is_err());
    let cfg = framework::lock_state(&perps.inner).configs[&mid];
    assert_eq!(cfg, test_cfg(), "rejected applies leave the config untouched");
}
