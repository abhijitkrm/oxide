//! Unit tests — extracted from the implementation file so the
//! production code reads top-to-bottom without the test bulk
//! (split-giant-modules pass: every entry point's enforcement
//! stays visible).

use super::*;
use crate::settler::{MAX_PENDING_RETRIES, SettleReport};
use crate::{MatchingServer, OrderRequest};
use primitives::fixed::{Price, Qty};
use trading::{MarketConfig, OrderType, Side, TimeInForce};
use types::TxBytes;

fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 16,
    }
}

fn addr(byte: u8) -> primitives::Address {
    primitives::Address([byte; 20])
}

/// A deterministic test account: `seed` derives the Ed25519
/// signing key; the account address is the key's derived owner.
fn test_account(seed: u8) -> (crypto::ed25519::Ed25519SecretKey, primitives::Address) {
    let secret = crypto::ed25519::Ed25519SecretKey::from_bytes(&[seed; 32]);
    let owner = crypto::ed25519::owner_address(&secret.verifying_key());
    (secret, owner)
}

/// Build a signed order for `secret`'s account — every request
/// reaching `submit_order` must now authenticate.
fn signed_req(secret: &crypto::ed25519::Ed25519SecretKey, side: Side, nonce: u64) -> OrderRequest {
    let mut req = OrderRequest {
        market: 0,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce,
        owner: addr(0),
        pubkey: [0u8; 32],
        signature: [0u8; 64],
    };
    crate::protocol::sign_order(&mut req, secret);
    req
}

/// A mock tx submitter that records submissions.
struct MockSubmitter {
    submissions: std::sync::Mutex<Vec<TxBytes>>,
}

impl MockSubmitter {
    fn new() -> Self {
        Self { submissions: std::sync::Mutex::new(Vec::new()) }
    }

    fn count(&self) -> usize {
        primitives::sync::lock_state(&self.submissions).len()
    }
}

impl TxSubmitter for MockSubmitter {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        primitives::sync::lock_state(&self.submissions).push(tx);
        Ok(())
    }
}

/// A mock finality oracle: outcomes are injected per tx hash,
/// and the "executor's" expected nonce is set directly.
struct MockConfirmer {
    outcomes: std::sync::Mutex<std::collections::HashMap<primitives::Hash, executor::TxOutcome>>,
    nonce: std::sync::atomic::AtomicU64,
}

impl MockConfirmer {
    fn new() -> Self {
        Self {
            outcomes: std::sync::Mutex::new(std::collections::HashMap::new()),
            nonce: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The confirmer key for a submitted envelope — the same
    /// `Domain::Transaction` hash the executor records under.
    fn hash_of(tx: &TxBytes) -> primitives::Hash {
        crypto::Hasher::hash_one(crypto::Domain::Transaction, tx.as_bytes())
    }

    /// Inject a finalized outcome for `tx` (as a block executing
    /// it would), and set the post-execution expected nonce.
    fn execute(&self, tx: &TxBytes, outcome: executor::TxOutcome, next_nonce: u64) {
        primitives::sync::lock_state(&self.outcomes).insert(Self::hash_of(tx), outcome);
        self.nonce.store(next_nonce, std::sync::atomic::Ordering::Relaxed);
    }
}

impl TxConfirmer for MockConfirmer {
    fn tx_outcome(&self, tx_hash: &primitives::Hash) -> Option<executor::TxOutcome> {
        primitives::sync::lock_state(&self.outcomes).get(tx_hash).cloned()
    }

    fn executed_nonce(&self, _sender: &primitives::Address) -> u64 {
        self.nonce.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Build a settler + its mock submitter/confirmer handles.
fn settler_harness(
    shared: &Arc<SharedMatcher>,
) -> (BatchSettler, Arc<MockSubmitter>, Arc<MockConfirmer>) {
    let submitter = Arc::new(MockSubmitter::new());
    let confirmer = Arc::new(MockConfirmer::new());
    let settler = BatchSettler::new(
        Arc::clone(shared) as Arc<dyn crate::BatchSealer>,
        Arc::clone(&submitter) as Arc<dyn TxSubmitter>,
        Arc::clone(&confirmer) as Arc<dyn TxConfirmer>,
        100,
        addr(0),
        0,
    );
    (settler, submitter, confirmer)
}

/// The `Executed` outcome for a clean batch — one `batch_fill`
/// event per settled pair (kinds are what the exchange emits).
fn clean_outcome(pair_count: usize) -> executor::TxOutcome {
    executor::TxOutcome::Executed {
        events: (0..pair_count)
            .map(|_| executor::Event { module: "exchange", kind: "batch_fill", data: vec![] })
            .collect(),
        error: None,
    }
}

#[test]
fn batch_settler_seals_and_submits() {
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let mut server = MatchingServer::new(cfg(), 100);
    server.fund_account(&seller, 1_000_000_000_000);
    server.fund_account(&buyer, 1_000_000_000_000);

    // Rest a maker sell, then a taker buy — should match.
    server.submit_order(&signed_req(&seller_sk, Side::Sell, 0));
    server.submit_order(&signed_req(&buyer_sk, Side::Buy, 0));

    // There should be 1 fill in the batch.
    assert_eq!(server.pending_settlements(), 1);

    // Create the shared matcher and settler.
    let shared = Arc::new(SharedMatcher::new(server));
    let (settler, counter, confirmer) = settler_harness(&shared);

    // Settle now — mempool acceptance only. `submitted` counts
    // the in-flight batch; `confirmed` stays 0 until the
    // finalized outcome lands.
    let report = settler.settle_now().expect("settle");
    assert_eq!(report.submitted, 1, "should submit 1 fill batch");
    assert_eq!(report.confirmed, 0, "submission is not settlement");
    assert_eq!(counter.count(), 1, "should submit 1 tx");
    assert_eq!(shared.stats().pending_settlements, 0, "batch should be empty after settle");

    // The batch executes — the outcome confirms it and the
    // nonce resyncs to the executor's post-execution value.
    let tx = primitives::sync::lock_state(&counter.submissions)[0].clone();
    confirmer.execute(&tx, clean_outcome(1), 1);
    let report = settler.settle_now().expect("confirm");
    assert_eq!(report.confirmed, 1, "executed batch confirms");
}

#[test]
fn batch_settler_empty_batch_is_noop() {
    let server = MatchingServer::new(cfg(), 100);
    let shared = Arc::new(SharedMatcher::new(server));
    let (settler, _counter, _confirmer) = settler_harness(&shared);

    let report = settler.settle_now().expect("settle");
    assert_eq!(report, SettleReport::default(), "empty batch should be a no-op");
}

/// A submitter that fails the first `fail_count` submissions,
/// then accepts — and records every attempt.
struct FlakySubmitter {
    fail_remaining: std::sync::Mutex<u32>,
    submissions: std::sync::Mutex<Vec<TxBytes>>,
}

impl TxSubmitter for FlakySubmitter {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        primitives::sync::lock_state(&self.submissions).push(tx);
        let mut remaining = primitives::sync::lock_state(&self.fail_remaining);
        if *remaining > 0 {
            *remaining -= 1;
            return Err("mempool full".to_string());
        }
        Ok(())
    }
}

/// Regression test: a failed `submit_tx` must NOT lose the
/// sealed fills or burn the nonce. Before the fix the batch was
/// drained and the nonce already incremented, so the retry
/// carried nonce N+1 while the executor still expected N —
/// every subsequent settlement was nonce-skipped forever.
#[test]
fn batch_settler_retries_failed_batch_same_envelope() {
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let mut server = MatchingServer::new(cfg(), 100);
    server.fund_account(&seller, 1_000_000_000_000);
    server.fund_account(&buyer, 1_000_000_000_000);
    server.submit_order(&signed_req(&seller_sk, Side::Sell, 0));
    server.submit_order(&signed_req(&buyer_sk, Side::Buy, 0));
    assert_eq!(server.pending_settlements(), 1);

    let shared = Arc::new(SharedMatcher::new(server));
    let flaky = Arc::new(FlakySubmitter {
        fail_remaining: std::sync::Mutex::new(1),
        submissions: std::sync::Mutex::new(Vec::new()),
    });
    let confirmer = Arc::new(MockConfirmer::new());
    let settler = BatchSettler::new(
        Arc::clone(&shared) as Arc<dyn crate::BatchSealer>,
        Arc::clone(&flaky) as Arc<dyn TxSubmitter>,
        Arc::clone(&confirmer) as Arc<dyn TxConfirmer>,
        100,
        addr(0),
        0,
    );

    // First submission fails — the fills must be kept in
    // `pending`, not dropped.
    assert!(settler.settle_now().is_err());
    assert_eq!(primitives::sync::lock_state(&flaky.submissions).len(), 1);

    // The retry resubmits the SAME envelope (same nonce — the
    // executor still expects it) and is accepted into the
    // mempool — still in flight, not settled.
    let report = settler.settle_now().expect("retry must succeed");
    assert_eq!(report.submitted, 1);
    assert_eq!(report.confirmed, 0);
    let subs = primitives::sync::lock_state(&flaky.submissions);
    assert_eq!(subs.len(), 2, "one original + one retry");
    assert_eq!(
        subs[0].as_bytes(),
        subs[1].as_bytes(),
        "the retry must resubmit the identical envelope (nonce baked in)"
    );
    let retried = subs[1].clone();
    drop(subs);

    // Execution confirms the batch and advances the nonce — the
    // sequence stayed contiguous because a failed submit never
    // consumed one.
    confirmer.execute(&retried, clean_outcome(1), 1);
    let report = settler.settle_now().expect("confirm");
    assert_eq!(report.confirmed, 1);

    // The next batch gets the NEXT nonce — the sequence stayed
    // contiguous because the failed submit never consumed one.
    server_refill(&shared);
    let report = settler.settle_now().expect("second batch");
    assert_eq!(report.submitted, 1);
    let subs = primitives::sync::lock_state(&flaky.submissions);
    assert_eq!(subs.len(), 3);
    assert_ne!(subs[1].as_bytes(), subs[2].as_bytes(), "the next batch carries the next nonce");
}

/// Submit another matched pair so `seal_batch` returns a fill.
/// Each account's second order uses nonce 1 (nonce 0 was the
/// first fill's pair).
fn server_refill(shared: &SharedMatcher) {
    let (seller_sk, _) = test_account(9);
    let (buyer_sk, _) = test_account(1);
    shared.submit(&signed_req(&seller_sk, Side::Sell, 1));
    shared.submit(&signed_req(&buyer_sk, Side::Buy, 1));
}

/// Regression test: a permanently-rejected envelope must NOT be
/// dropped after `MAX_PENDING_RETRIES`. Dropping would cause
/// cache/chain divergence (the off-chain cache already reflects
/// the fills from `seal_batch`, but the on-chain settlement never
/// landed). Instead, the envelope stays pending so the operator
/// can intervene and the settlement can land when the chain
/// recovers. The nonce is NOT advanced (the tx never executed).
#[test]
fn batch_settler_keeps_pending_after_max_retries() {
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let mut server = MatchingServer::new(cfg(), 100);
    server.fund_account(&seller, 1_000_000_000_000);
    server.fund_account(&buyer, 1_000_000_000_000);
    server.submit_order(&signed_req(&seller_sk, Side::Sell, 0));
    server.submit_order(&signed_req(&buyer_sk, Side::Buy, 0));

    let shared = Arc::new(SharedMatcher::new(server));
    // Fail forever — the batch is retried but NOT dropped.
    let flaky = Arc::new(FlakySubmitter {
        fail_remaining: std::sync::Mutex::new(u32::MAX),
        submissions: std::sync::Mutex::new(Vec::new()),
    });
    let confirmer = Arc::new(MockConfirmer::new());
    let settler = BatchSettler::new(
        Arc::clone(&shared) as Arc<dyn crate::BatchSealer>,
        Arc::clone(&flaky) as Arc<dyn TxSubmitter>,
        Arc::clone(&confirmer) as Arc<dyn TxConfirmer>,
        100,
        addr(0),
        0,
    );

    // 1 initial failure + (MAX-1) retries — all fail, but the
    // pending envelope is NOT dropped.
    for _ in 0..MAX_PENDING_RETRIES {
        assert!(settler.settle_now().is_err());
    }
    // One more call: pending is still there, so the SAME envelope
    // is retried (not a new batch). The nonce is NOT advanced.
    assert!(settler.settle_now().is_err());
    let subs = primitives::sync::lock_state(&flaky.submissions);
    // All submissions carry the same nonce (the same envelope
    // is retried, never dropped).
    let first_nonce = &subs[0].as_bytes()[20..28];
    let last_nonce = &subs[subs.len() - 1].as_bytes()[20..28];
    assert_eq!(first_nonce, last_nonce, "nonce must not advance while pending");
}

/// Seed the shared matcher's book with one matched pair.
fn matched_pair() -> (Arc<SharedMatcher>, u64) {
    let (seller_sk, seller) = test_account(9);
    let (buyer_sk, buyer) = test_account(1);
    let mut server = MatchingServer::new(cfg(), 100);
    server.fund_account(&seller, 1_000_000_000_000);
    server.fund_account(&buyer, 1_000_000_000_000);
    server.submit_order(&signed_req(&seller_sk, Side::Sell, 0));
    server.submit_order(&signed_req(&buyer_sk, Side::Buy, 0));
    (Arc::new(SharedMatcher::new(server)), 1)
}

/// The submitted envelope's nonce field (bytes 20..28).
fn envelope_nonce(tx: &TxBytes) -> u64 {
    u64::from_le_bytes(tx.as_bytes()[20..28].try_into().unwrap())
}

/// Regression: a terminal execution-time skip must dead-letter
/// the batch — loudly — WITHOUT consuming the nonce. The next
/// sealed batch reuses the same nonce value, which is exactly
/// what the executor still expects.
#[test]
fn batch_settler_dead_letter_reuses_nonce() {
    let (shared, _) = matched_pair();
    let (settler, submitter, confirmer) = settler_harness(&shared);

    let report = settler.settle_now().expect("submit");
    assert_eq!(report.submitted, 1);
    let tx = primitives::sync::lock_state(&submitter.submissions)[0].clone();
    assert_eq!(envelope_nonce(&tx), 0);

    // The block executes but the tx is gate-skipped — e.g. an
    // unsigned envelope under a Reject policy. Terminal reason:
    // the same bytes can never pass that gate.
    confirmer.execute(
        &tx,
        executor::TxOutcome::Skipped { reason: executor::TxSkipReason::BadSignature },
        0,
    );
    let report = settler.settle_now().expect("resolve");
    assert_eq!(report.dead_lettered.as_deref(), Some("BadSignature"));
    assert_eq!(report.confirmed, 0);

    // The nonce was NOT consumed — the next batch reuses nonce 0
    // (the executor's expected value), un-wedging the sequence.
    server_refill(&shared);
    let report = settler.settle_now().expect("next batch");
    assert_eq!(report.submitted, 1);
    let subs = primitives::sync::lock_state(&submitter.submissions);
    assert_eq!(envelope_nonce(&subs[1]), 0, "dead-lettered batch must not burn a nonce");
}

/// Regression: a batch whose module call returned `Err` executed
/// (fee + nonce consumed) but settled nothing. The report must
/// carry the rejection and the nonce must still advance — the
/// sequence continues past the dead batch.
#[test]
fn batch_settler_batch_rejected_advances_nonce() {
    let (shared, _) = matched_pair();
    let (settler, submitter, confirmer) = settler_harness(&shared);

    settler.settle_now().expect("submit");
    let tx = primitives::sync::lock_state(&submitter.submissions)[0].clone();
    confirmer.execute(
        &tx,
        executor::TxOutcome::Executed {
            events: vec![].into(),
            error: Some("settle: sender is not the settlement operator".to_string()),
        },
        1,
    );
    let report = settler.settle_now().expect("resolve");
    assert!(report.batch_rejected.is_some(), "module rejection must surface");
    assert_eq!(report.confirmed, 0);

    // The nonce WAS consumed — the next batch carries nonce 1.
    server_refill(&shared);
    settler.settle_now().expect("next batch");
    let subs = primitives::sync::lock_state(&submitter.submissions);
    assert_eq!(envelope_nonce(&subs[1]), 1, "executed batch consumed its nonce");
}

/// Regression: `settlement_failed`/`fill_rejected` events inside
/// an applied batch are reconciled into the report — the chain
/// can void individual pairs even when the batch succeeds.
#[test]
fn batch_settler_reconciles_partial_failures() {
    let (shared, _) = matched_pair();
    let (settler, submitter, confirmer) = settler_harness(&shared);

    settler.settle_now().expect("submit");
    let tx = primitives::sync::lock_state(&submitter.submissions)[0].clone();
    confirmer.execute(
        &tx,
        executor::TxOutcome::Executed {
            events: vec![
                executor::Event { module: "exchange", kind: "settlement_failed", data: vec![] },
                executor::Event { module: "exchange", kind: "fill_rejected", data: vec![] },
            ]
            .into(),
            error: None,
        },
        1,
    );
    let report = settler.settle_now().expect("resolve");
    assert_eq!(report.confirmed, 1, "the batch applied");
    assert_eq!(report.failed_pairs, 1);
    assert_eq!(report.rejected_legs, 1);
}

/// Regression: a retryable skip (block gas limit) keeps the
/// batch in flight — the pooled tx lands in a later block and
/// the eventual `Executed` outcome confirms it.
#[test]
fn batch_settler_retryable_skip_keeps_waiting() {
    let (shared, _) = matched_pair();
    let (settler, submitter, confirmer) = settler_harness(&shared);

    settler.settle_now().expect("submit");
    let tx = primitives::sync::lock_state(&submitter.submissions)[0].clone();
    confirmer.execute(
        &tx,
        executor::TxOutcome::Skipped { reason: executor::TxSkipReason::GasLimit },
        0,
    );
    let report = settler.settle_now().expect("gas-skip tick");
    assert_eq!(report, SettleReport::default(), "retryable skip just keeps waiting");
    assert!(settler.has_pending(), "batch stays in flight");

    // A later block executes it — the updated outcome confirms.
    confirmer.execute(&tx, clean_outcome(1), 1);
    let report = settler.settle_now().expect("confirm");
    assert_eq!(report.confirmed, 1);
}

/// Regression: the durable outbox restores an in-flight batch
/// across a settler restart — the outcome is checked BEFORE any
/// resubmission, so a batch that executed during the downtime is
/// reconciled, not replayed.
#[test]
fn batch_settler_outbox_restores_pending() {
    let dir = std::env::temp_dir().join(format!("oxso-test-{}", std::process::id()));
    let _ = std::fs::remove_file(&dir);
    let (shared, _) = matched_pair();
    let (settler, submitter, confirmer) = settler_harness(&shared);
    let settler = settler.with_outbox(dir.clone());

    settler.settle_now().expect("submit");
    let tx = primitives::sync::lock_state(&submitter.submissions)[0].clone();
    drop(settler); // simulate a restart: in-memory state is gone

    // Rebuild with the same outbox — the pending batch resumes.
    let restored = BatchSettler::new(
        Arc::clone(&shared) as Arc<dyn crate::BatchSealer>,
        Arc::clone(&submitter) as Arc<dyn TxSubmitter>,
        Arc::clone(&confirmer) as Arc<dyn TxConfirmer>,
        100,
        addr(0),
        0,
    )
    .with_outbox(dir.clone());
    assert!(restored.has_pending(), "outbox restore must resume the in-flight batch");

    // The batch executed during the downtime — the outcome check
    // reconciles it without any resubmission.
    confirmer.execute(&tx, clean_outcome(1), 1);
    let report = restored.settle_now().expect("resolve restored");
    assert_eq!(report.confirmed, 1);
    assert_eq!(submitter.count(), 1, "no replay — the outcome resolved it");

    let _ = std::fs::remove_file(&dir);
}

/// Regression: `with_signing` produces the executor's v1 signed
/// envelope — flagged module byte, 65-byte signature, and a
/// recovered signer equal to the key-derived sender.
#[test]
fn batch_settler_signed_envelope_layout() {
    let (shared, _) = matched_pair();
    let (settler, submitter, _confirmer) = settler_harness(&shared);
    let (privkey, operator) = crypto::secp::generate_keypair_for_test();
    let settler = settler.with_signing(privkey, 777);

    settler.settle_now().expect("submit signed");
    let subs = primitives::sync::lock_state(&submitter.submissions);
    let env = subs[0].as_bytes();
    // v1 layout: sender(20) nonce(8) fee(8) module|0x80 sig(65) payload.
    assert_eq!(env[36] & 0x80, 0x80, "signed flag on the module byte");
    assert_eq!(&env[0..20], &operator.0, "sender is the key-derived address");
    let sig = crypto::secp::RecoverableSignature::from_bytes(&env[37..101], env[101])
        .expect("65-byte recoverable sig");
    let payload = &env[102..];
    let nonce = u64::from_le_bytes(env[20..28].try_into().unwrap());
    let fee = u64::from_le_bytes(env[28..36].try_into().unwrap());
    let recovered = crypto::eip712::verify_tx_sender(
        777,
        &operator,
        nonce,
        fee,
        framework::module_id::EXCHANGE,
        payload,
        &sig,
    )
    .expect("signature must verify");
    assert_eq!(recovered, operator, "signer must equal the declared sender");
}

/// Regression: concurrent requests that land on the SAME ring
/// index must never consume each other's responses. Eight tasks
/// submit through ONE ring (maximal contention); task `i` sends
/// `i + 1` orders so a stolen response is a length mismatch.
/// Before the ring lease, every task cloned the same receiver
/// and raced `pop` — any task could take another's batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ring_concurrent_exchanges_isolate_responses() {
    let mut server = MatchingServer::new(cfg(), 100);
    // Fund 8 distinct accounts, one per task.
    let accounts: Vec<_> = (0u8..8).map(test_account).collect();
    for (_, owner) in &accounts {
        server.fund_account(owner, 1_000_000_000_000);
    }
    // ONE ring: every request contends on the same pair — the
    // exact shape of the old round-robin collision.
    let ring = std::sync::Arc::new(crate::RingMatcher::new(server, 1, 64, None));
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut handles = Vec::new();
    for (i, (secret, _)) in accounts.into_iter().enumerate() {
        let ring = std::sync::Arc::clone(&ring);
        let counter = std::sync::Arc::clone(&counter);
        handles.push(tokio::spawn(async move {
            // Task i sends i+1 sell orders at a task-distinct
            // price — no bids exist, so every order rests and
            // the response batch length identifies it.
            let price = 1_500_000_000u64 + i as u64 * 1_000_000;
            let reqs: Vec<OrderRequest> = (0..=i)
                .map(|n| {
                    let mut req = signed_req(&secret, Side::Sell, (n + 1) as u64);
                    req.price = Price(price);
                    crate::protocol::sign_order(&mut req, &secret);
                    req
                })
                .collect();
            let expected = reqs.len();
            let responses = submit_batch_ring(&ring, &counter, &reqs).await;
            (i, expected, responses)
        }));
    }
    for handle in handles {
        let (i, expected, responses) = handle.await.expect("task panicked");
        assert_eq!(
            responses.len(),
            expected,
            "task {i}: response batch must be ITS OWN — a stolen \
             batch has a different length"
        );
        assert!(
            responses.iter().all(|r| !r.rejected),
            "task {i}: funded sell orders must all be accepted"
        );
    }
}
