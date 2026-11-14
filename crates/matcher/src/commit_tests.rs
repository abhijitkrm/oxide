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

// ── oversized seals are split into batches the chain accepts ───────

/// A chain that executes whatever is submitted: records each envelope and reports it
/// executed with no error, advancing the executed nonce one per transaction.
#[derive(Default)]
struct EagerChain {
    envelopes: Mutex<Vec<Vec<u8>>>,
    executed: Mutex<std::collections::HashSet<primitives::Hash>>,
}
impl TxSubmitter for EagerChain {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        self.envelopes.lock().unwrap().push(tx.0);
        Ok(())
    }
}
impl TxConfirmer for EagerChain {
    fn tx_outcome(&self, h: &primitives::Hash) -> Option<executor::TxOutcome> {
        let known = self
            .envelopes
            .lock()
            .unwrap()
            .iter()
            .any(|e| crypto::Hasher::hash_one(crypto::Domain::Transaction, e) == *h);
        known.then(|| {
            self.executed.lock().unwrap().insert(*h);
            executor::TxOutcome::Executed { events: Vec::new().into(), error: None }
        })
    }
    fn executed_nonce(&self, _: &Address) -> u64 {
        self.executed.lock().unwrap().len() as u64
    }
}

/// `n` fills that aggregate to `n` distinct legs (distinct order ids).
fn many_fills(n: u64) -> Vec<SettledFill> {
    (0..n)
        .map(|i| SettledFill {
            market: 0,
            price: Price(1_000_000_000),
            qty: Qty(1_000),
            buyer: Address([1; 20]),
            buyer_id: i,
            seller: Address([2; 20]),
            seller_id: i,
            quote_amount: 10,
        })
        .collect()
}

/// Drive `settle_now` until the settler has nothing in flight and nothing deferred.
fn drain(settler: &BatchSettler, chain: &EagerChain, max_ticks: usize) -> Vec<Vec<u8>> {
    for _ in 0..max_ticks {
        settler.settle_now().expect("tick");
        if !settler.has_pending() && settler.deferred_pairs() == 0 {
            break;
        }
    }
    chain.envelopes.lock().unwrap().clone()
}

fn settler_over(fills: Vec<SettledFill>, chain: Arc<EagerChain>, commit: bool) -> BatchSettler {
    let s = BatchSettler::new(
        Arc::new(OneShot(Mutex::new(Some(fills)))),
        chain.clone(),
        chain,
        1000,
        Address([0xAA; 20]),
        0,
    );
    if commit { s.with_commitment() } else { s }
}

fn legs_of(payload: &[u8], header: usize) -> Vec<Vec<u8>> {
    let count = u32::from_le_bytes(payload[1 + header..5 + header].try_into().unwrap()) as usize;
    payload[5 + header..5 + header + count * exchange::FILL_ENTRY_LEN]
        .chunks(exchange::FILL_ENTRY_LEN)
        .map(<[u8]>::to_vec)
        .collect()
}

#[test]
fn an_oversized_seal_is_split_into_batches_the_chain_accepts() {
    use crate::settler::MAX_PAIRS_PER_BATCH;
    let total = MAX_PAIRS_PER_BATCH as u64 * 2 + 18_928;
    let fills = many_fills(total);

    // The bug: the whole seal in one message is rejected as malformed by the real exchange.
    let (ex, _ledger) = bonded_exchange();
    let all_legs = crate::settler::aggregate_fills(&fills).unwrap();
    assert_eq!(all_legs.len() as u64, total);
    let ctx = |n| TxContext { sender: Address([0xAA; 20]), nonce: n, fee: 100 };
    let one_big = exchange::msg::batch_settle(&all_legs);
    assert!(ex.handle(&ctx(1), &one_big).is_err(), "a >65,536-leg message must be refused");

    // The fix: chunks of at most MAX_PAIRS_PER_BATCH, every one accepted, together the same legs.
    let chain = Arc::new(EagerChain::default());
    let settler = settler_over(fills, chain.clone(), false);
    let envelopes = drain(&settler, &chain, 20);
    assert_eq!(envelopes.len(), 3, "65,536 + 65,536 + 18,928 legs");
    let mut got: Vec<Vec<u8>> = Vec::new();
    for (i, env) in envelopes.iter().enumerate() {
        let payload = &env[37..];
        assert_eq!(payload[0], 3, "plain batch settle");
        let legs = legs_of(payload, 0);
        assert!(legs.len() <= MAX_PAIRS_PER_BATCH);
        ex.handle(&ctx(100 + i as u64), payload).expect("the chain accepts every chunk");
        got.extend(legs);
    }
    let mut want: Vec<Vec<u8>> =
        all_legs.iter().map(|l| exchange::dispute::leg_bytes(l).to_vec()).collect();
    want.sort();
    got.sort();
    assert_eq!(got, want, "every leg settles exactly once");
    assert!(!settler.has_pending());
}

#[test]
fn chunks_of_an_oversized_seal_each_carry_a_root_over_exactly_their_own_fills() {
    use crate::settler::MAX_PAIRS_PER_BATCH;
    use exchange::dispute::{aggregate_raw_fills, legs_root};
    let total = MAX_PAIRS_PER_BATCH as u64 + 5_000;
    let fills = many_fills(total);
    let chain = Arc::new(EagerChain::default());
    let settler = settler_over(fills.clone(), chain.clone(), true);
    let envelopes = drain(&settler, &chain, 20);
    assert_eq!(envelopes.len(), 2);

    let (ex, _ledger) = bonded_exchange();
    ex.handle(&op_ctx(1), &exchange::msg::bond_deposit(5_000)).expect("bond");
    for (i, env) in envelopes.iter().enumerate() {
        let p = &env[37..];
        assert_eq!(p[0], 16, "committed batch settle");
        // [tag][seq 8][fills_root 32][raw count 4] then [leg count][legs]
        let seq = u64::from_le_bytes(p[1..9].try_into().unwrap());
        let raw_count = u32::from_le_bytes(p[41..45].try_into().unwrap()) as usize;
        let legs = legs_of(p, 44);
        assert_eq!(raw_count, legs.len(), "one raw fill per leg here: the chunk's own fills");
        ex.handle(&TxContext { sender: Address([0xAA; 20]), nonce: seq, fee: 100 }, p)
            .expect("committed chunk accepted");

        // The chunk's own raw fills, found by leg key, must re-aggregate to the chunk's legs ...
        let keys: std::collections::HashSet<(Vec<u8>, Vec<u8>, Vec<u8>)> = legs
            .iter()
            .map(|l| (l[..2].to_vec(), l[18..38].to_vec(), l[38..46].to_vec()))
            .collect();
        let raw: Vec<_> = fills
            .iter()
            .map(crate::commit::to_raw)
            .filter(|r| {
                keys.contains(&(
                    r.market.to_le_bytes().to_vec(),
                    r.buy.owner.0.to_vec(),
                    r.buy.client_id.to_le_bytes().to_vec(),
                ))
            })
            .collect();
        assert_eq!(raw.len(), raw_count);
        let rebuilt = aggregate_raw_fills(&raw).unwrap();
        assert_eq!(legs_root(&rebuilt).1 as usize, legs.len());
        // ... and the chain must find the honest chunk consistent when disputed.
        let dispute = exchange::msg::dispute(seq, &raw);
        let err = ex
            .handle(&TxContext { sender: Address([7; 20]), nonce: 0, fee: 0 }, &dispute)
            .expect_err("an honest chunk survives a dispute");
        assert!(format!("{err:?}").contains("consistent"), "chunk {i}: {err:?}");
    }
    assert!(!ex.operator_suspended());
}

#[test]
fn a_rejected_batch_reports_how_many_pairs_it_held() {
    // The log used to say "batch of 0 pairs rejected" for any rejection.
    struct Rejecting(Mutex<Vec<Vec<u8>>>);
    impl TxSubmitter for Rejecting {
        fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
            self.0.lock().unwrap().push(tx.0);
            Ok(())
        }
    }
    impl TxConfirmer for Rejecting {
        fn tx_outcome(&self, _: &primitives::Hash) -> Option<executor::TxOutcome> {
            Some(executor::TxOutcome::Executed {
                events: Vec::new().into(),
                error: Some("malformed transaction".into()),
            })
        }
        fn executed_nonce(&self, _: &Address) -> u64 {
            0
        }
    }
    let chain = Arc::new(Rejecting(Mutex::new(Vec::new())));
    let s = BatchSettler::new(
        Arc::new(OneShot(Mutex::new(Some(many_fills(40))))),
        chain.clone(),
        chain,
        1000,
        Address([0xAA; 20]),
        0,
    );
    s.settle_now().expect("submits");
    let report = s.settle_now().expect("resolves");
    assert!(report.batch_rejected.is_some());
    assert_eq!(report.rejected_pairs, 40);
}
