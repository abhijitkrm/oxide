//! End to end: the settler's committed batch settle is accepted by the
//! real exchange module, settles the same legs as a plain one, and the
//! `batch_commit` event carries the root the matcher computed over the
//! raw fills plus the chain's own root over the legs.

use std::sync::{Arc, Mutex};

use executor::{Module, TxContext};
use framework::Balances;
use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::MarketConfig;
use types::TxBytes;

use crate::SettledFill;
use crate::commit::fills_root;
use crate::settler::{BatchSettler, TxConfirmer, TxSubmitter};

struct OneShot(Mutex<Option<Vec<SettledFill>>>);
impl crate::BatchSealer for OneShot {
    fn seal_batch(&self) -> Vec<SettledFill> {
        self.0.lock().unwrap().take().unwrap_or_default()
    }
}

#[derive(Default)]
struct Capture(Mutex<Vec<Vec<u8>>>);
impl TxSubmitter for Capture {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        self.0.lock().unwrap().push(tx.0);
        Ok(())
    }
}

struct Never;
impl TxConfirmer for Never {
    fn tx_outcome(&self, _: &primitives::Hash) -> Option<executor::TxOutcome> {
        None
    }
    fn executed_nonce(&self, _: &Address) -> u64 {
        0
    }
}

fn fills() -> Vec<SettledFill> {
    // Two raw fills on one pair that aggregate into one leg, plus a
    // third on another pair.
    let f = |price, qty, buyer: u8, seller: u8| SettledFill {
        market: 0,
        price: Price(price),
        qty: Qty(qty),
        buyer: Address([buyer; 20]),
        buyer_id: 1,
        seller: Address([seller; 20]),
        seller_id: 1,
        quote_amount: price / 100_000 * qty / 1_000,
    };
    vec![
        f(1_000_000_000, 1_000, 1, 9),
        f(1_000_000_000, 2_000, 1, 9),
        f(1_100_000_000, 1_000, 2, 8),
    ]
}

fn settle(commit: bool, nonce: u64) -> (Vec<u8>, crate::settler::SettleReport) {
    let capture = Arc::new(Capture::default());
    let mut s = BatchSettler::new(
        Arc::new(OneShot(Mutex::new(Some(fills())))),
        capture.clone(),
        Arc::new(Never),
        1000,
        Address([0xAA; 20]),
        nonce,
    );
    if commit {
        s = s.with_commitment();
    }
    let report = s.settle_now().expect("submits");
    let envelopes = capture.0.lock().unwrap();
    assert_eq!(envelopes.len(), 1);
    (envelopes[0].clone(), report)
}

/// Unsigned envelope: sender 20, nonce 8, fee 8, module id 1, payload.
fn payload(envelope: &[u8]) -> &[u8] {
    &envelope[37..]
}

fn exchange() -> exchange::ExchangeModule {
    let ledger = Arc::new(framework::MemoryBalances::new());
    let mut ex = exchange::ExchangeModule::with_ledger(ledger);
    ex.set_settlement_operator(Address([0xAA; 20]));
    ex.list_market(MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 10,
    })
    .expect("list");
    ex
}

#[test]
fn committed_payload_carries_the_matchers_root_and_the_batch_sequence() {
    let (env, report) = settle(true, 41);
    let (root, raw) = fills_root(&fills());
    assert_eq!(report.fills_root, Some(root));
    let p = payload(&env);
    assert_eq!(p[0], 16, "tag 16: committed batch settle");
    assert_eq!(&p[1..9], &41u64.to_le_bytes(), "envelope nonce is the batch seq");
    assert_eq!(&p[9..41], &root);
    assert_eq!(&p[41..45], &raw.to_le_bytes());
    assert_eq!(raw, 3, "raw fills, not aggregated legs");
}

#[test]
fn plain_settlement_is_unchanged_when_commitment_is_off() {
    let (env, report) = settle(false, 7);
    assert_eq!(report.fills_root, None);
    assert_eq!(payload(&env)[0], 3, "tag 3: plain batch settle");
}

#[test]
fn the_real_exchange_accepts_the_committed_payload_and_commits_both_roots() {
    let (env, _) = settle(true, 41);
    let (root, _) = fills_root(&fills());
    let ex = exchange();
    let ctx = TxContext { sender: Address([0xAA; 20]), nonce: 41, fee: 100 };
    let events = ex.handle(&ctx, payload(&env)).expect("exchange accepts tag 16 from the settler");
    let ev = events.last().expect("events");
    assert_eq!((ev.module, ev.kind), ("exchange", "batch_commit"));
    assert_eq!(&ev.data[0..8], &41u64.to_le_bytes());
    assert_eq!(&ev.data[8..40], &root, "operator-attested raw-fill root passes through");
    assert_eq!(&ev.data[40..44], &3u32.to_le_bytes());
    assert_eq!(&ev.data[76..80], &2u32.to_le_bytes(), "two aggregated legs");
    // The same legs through plain tag 3 produce the same leg events.
    let (plain_env, _) = settle(false, 41);
    let ex2 = exchange();
    let plain = ex2.handle(&ctx, payload(&plain_env)).expect("plain accepted");
    assert_eq!(events.len(), plain.len() + 1);
}

// ── the settler's real output against the real dispute path ────────

fn bonded_exchange() -> (exchange::ExchangeModule, Arc<framework::MemoryBalances>) {
    let ledger = Arc::new(framework::MemoryBalances::new());
    ledger.mint(&Address([0xAA; 20]), 10_000);
    let mut ex = exchange::ExchangeModule::with_ledger(ledger.clone());
    ex.set_settlement_operator(Address([0xAA; 20]));
    ex.set_dispute_config(exchange::dispute::DisputeConfig { min_bond: 1_000, window_blocks: 20 });
    ex.list_market(MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 10,
    })
    .expect("list");
    (ex, ledger)
}

fn op_ctx(nonce: u64) -> TxContext {
    TxContext { sender: Address([0xAA; 20]), nonce, fee: 100 }
}

#[test]
fn an_honest_settlers_batch_cannot_be_successfully_disputed() {
    let (ex, ledger) = bonded_exchange();
    ex.handle(&op_ctx(1), &exchange::msg::bond_deposit(5_000)).expect("bond");
    let (env, _) = settle(true, 41);
    ex.handle(&op_ctx(41), payload(&env)).expect("committed settle accepted");
    assert!(ex.has_batch_record(41));

    // The auditor replays the same fills and disputes: nothing to prove.
    let dispute = crate::commit::dispute_payload(41, &fills());
    let err = ex
        .handle(&TxContext { sender: Address([7; 20]), nonce: 0, fee: 0 }, &dispute)
        .expect_err("an honest batch survives");
    assert!(format!("{err:?}").contains("consistent"), "{err:?}");
    assert_eq!(ex.operator_bond(), 5_000);
    assert!(!ex.operator_suspended());
    assert_eq!(ledger.balance(&Address([7; 20])), 0);
}

#[test]
fn a_settler_that_submits_different_legs_than_it_attested_is_slashed() {
    use exchange::dispute::{RAW_FILL_LEN, RawFill};
    let (ex, ledger) = bonded_exchange();
    ex.handle(&op_ctx(1), &exchange::msg::bond_deposit(5_000)).expect("bond");

    // A dishonest operator keeps the honest attestation (header) but
    // swaps in different legs: here, the first leg's quantity is doubled.
    let (env, _) = settle(true, 41);
    let mut forged = payload(&env).to_vec();
    // [tag 1][seq 8][fills_root 32][raw 4][leg_count 4][legs...]: first leg's qty at +10.
    let qty_at = 1 + 8 + 32 + 4 + 4 + 2 + 8;
    let q = u64::from_le_bytes(forged[qty_at..qty_at + 8].try_into().unwrap());
    forged[qty_at..qty_at + 8].copy_from_slice(&(q * 2).to_le_bytes());
    ex.handle(&op_ctx(41), &forged).expect("the chain cannot tell without the raw fills");

    // Anyone with the matcher's journal replays the fills and disputes.
    let raw: Vec<RawFill> = fills().iter().map(crate::commit::to_raw).collect();
    assert_eq!(raw.len() * RAW_FILL_LEN, 3 * RAW_FILL_LEN);
    let ev = ex
        .handle(
            &TxContext { sender: Address([7; 20]), nonce: 0, fee: 0 },
            &crate::commit::dispute_payload(41, &fills()),
        )
        .expect("dispute proves the lie");
    assert!(ev.iter().any(|e| e.kind == "operator_slashed"));
    assert_eq!(ledger.balance(&Address([7; 20])), 5_000);
    assert!(ex.operator_suspended());
}
