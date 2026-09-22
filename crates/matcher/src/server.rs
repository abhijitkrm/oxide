//! Network server endpoints for the off-chain matching server.
//!
//! Provides four order-entry protocols:
//! - **Binary TCP** — the fastest path (43-byte requests, 13-byte responses).
//! - **WebSocket** — JSON over WebSocket (browser-compatible).
//! - **JSON-RPC** — HTTP-compatible (`oxide_placeOrder` method).
//! - **FIX 4.4** — institutional trading desk protocol.
//!
//! All protocols feed orders to a shared `MatchingServer` via
//! `SharedMatcher`. The matching server runs on a dedicated thread;
//! protocol handlers send orders through the shared matcher and
//! return responses to clients.
//!
//! # Batch settlement
//!
//! The `BatchSettler` periodically seals the fill buffer and submits
//! a batch settlement transaction to consensus via the `TxSubmitter`
//! trait. This is the bridge between off-chain matching and on-chain
//! settlement.

use crate::protocol::{
    OrderRequest, OrderResponse, RejectReason, decode_action_request, decode_request,
    encode_response, is_action_request,
};
use crate::{MatchingServer, SharedMatcher};
use exchange::BatchFillEntry;
use futures_util::{SinkExt, StreamExt};
use primitives::fixed::{Price, Qty};
use std::sync::Arc;
use std::time::Duration;
use trading::MarketConfig;
use types::TxBytes;

/// Submit a batch of orders through the ring matcher's SPSC rings
/// (no mutex). Acquires an exclusive ring lease, pushes the WHOLE
/// batch as one item, and pops the batch response — all under the
/// same lease, so no other requester can interleave a batch or
/// steal this exchange's responses.
///
/// This is the lock-free submission path shared by all protocol
/// servers. The lease — not the round-robin counter — is what makes
/// each exchange single-producer/single-consumer: more concurrent
/// requests than `num_rings` wait for a free ring rather than share
/// one and consume each other's responses.
///
/// # Errors
///
/// Returns a vector of `EngineError` rejections (one per order) if
/// the matcher worker thread has died and the ring is disconnected.
/// This is a terminal condition — the caller should close the
/// connection.
async fn submit_batch_ring(
    ring: &crate::RingMatcher,
    ring_counter: &std::sync::atomic::AtomicUsize,
    orders: Vec<OrderRequest>,
) -> Vec<OrderResponse> {
    // Authenticate on THIS transport thread: Ed25519 verification
    // parallelizes across connections, and the ring only accepts
    // `VerifiedOrder` proof tokens (unforgeable outside
    // `VerifiedOrder::new`), so the matcher thread can never execute
    // an unauthenticated order. `positions[i]` is the original batch
    // index of verified order i; failed entries keep an aligned
    // `BadSignature` response and never touch the ring.
    let mut positions: Vec<usize> = Vec::with_capacity(orders.len());
    let mut verified: Vec<crate::protocol::VerifiedOrder> = Vec::with_capacity(orders.len());
    let mut responses: Vec<Option<OrderResponse>> = Vec::with_capacity(orders.len());
    // Verify against the ring's configured chain ID — the embedded
    // server re-checks nothing for `VerifiedOrder`, so the transport
    // MUST use the same domain or valid orders die here as
    // `BadSignature`.
    let chain_id = ring.chain_id();
    for (i, req) in orders.into_iter().enumerate() {
        match crate::protocol::VerifiedOrder::with_chain_id(req, chain_id) {
            Some(vo) => {
                positions.push(i);
                verified.push(vo);
                responses.push(None);
            }
            None => {
                responses.push(Some(OrderResponse::rejected(
                    crate::protocol::RejectReason::BadSignature,
                )));
            }
        }
    }
    if !verified.is_empty() {
        // Lease a ring for the WHOLE exchange — without the lease,
        // two handlers landing on the same ring index push
        // interleaved batches and race `pop` on the shared response
        // ring, so a response batch addressed to request A can be
        // consumed by request B. The counter only seeds the scan
        // start; exclusivity comes from the lease, not the index.
        let lease = ring
            .acquire_ring(ring_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            .await;
        let ring_idx = lease.ring_idx();
        let order_sender = ring.order_sender(ring_idx);
        let response_receiver = ring.response_receiver(ring_idx);
        let mut pending = verified;
        let sent = loop {
            match order_sender.push(pending) {
                Ok(()) => break true,
                Err(crate::ring::PushError::Disconnected(_)) => {
                    // Worker thread died — verified slots fall through
                    // to EngineError below.
                    break false;
                }
                Err(crate::ring::PushError::Full(returned)) => {
                    pending = returned;
                    tokio::task::yield_now().await;
                }
            }
        };
        if sent {
            let worker_responses = loop {
                if let Some(r) = response_receiver.pop() {
                    break Some(r);
                }
                // The response ring's senders live on the matcher
                // thread — if it died mid-batch no response can ever
                // arrive, so bail instead of holding the lease (and
                // spinning) forever.
                if !ring.worker_is_alive() {
                    break None;
                }
                tokio::task::yield_now().await;
            };
            if let Some(worker_responses) = worker_responses {
                for (pos, resp) in positions.into_iter().zip(worker_responses) {
                    responses[pos] = Some(resp);
                }
            }
        }
        drop(lease); // release the ring before response mapping
    }
    // Every slot is Some: verified entries got worker responses,
    // unverified got BadSignature, dead-worker entries get
    // EngineError — all at their original batch positions.
    responses
        .into_iter()
        .map(|r| {
            r.unwrap_or_else(|| OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
        })
        .collect()
}

/// The chain ID the target matcher verifies signatures against —
/// ring mode reads it off the `RingMatcher`, mutex mode off the
/// `SharedMatcher`. Early transport verifies MUST use the same
/// domain as the mandatory in-server re-verify.
fn transport_chain_id(
    matcher: &SharedMatcher,
    ring_matcher: Option<&Arc<crate::RingMatcher>>,
) -> u64 {
    ring_matcher.map_or_else(|| matcher.chain_id(), |rm| rm.chain_id())
}

/// Submit a single order through the ring matcher (batch of one).
async fn submit_one_ring(
    ring: &crate::RingMatcher,
    ring_counter: &std::sync::atomic::AtomicUsize,
    req: OrderRequest,
) -> OrderResponse {
    let mut responses = submit_batch_ring(ring, ring_counter, vec![req]).await;
    responses.pop().unwrap_or(OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
}

/// Submit an order action (cancel/amend/replace) through the ring
/// matcher's control channel. The control channel reaches THE SAME
/// order book the rings write to — there is no second book — and the
/// matcher thread services it between ring polls, so an action's
/// latency is bounded by poll cadence plus queue depth.
///
/// Cancel/replace traffic is NOT rare on an HFT venue — it is
/// frequently the dominant message class (cancel-to-order ratios of
/// 10:1+ are normal), so this path is load-bearing, not a corner.
/// The `recv` is still synchronous (`std::sync::mpsc` — the matcher
/// thread is not async), but it runs on `spawn_blocking`: the wait
/// occupies a blocking-pool thread instead of stalling the async
/// worker that owns the client connection. Book work itself stays
/// single-writer inside the matcher thread — contention is the
/// channel, not a lock.
async fn submit_action_ring(
    ring: &Arc<crate::RingMatcher>,
    req: crate::protocol::ActionRequest,
) -> OrderResponse {
    // The wire `ActionRequest` crosses the channel intact — the
    // matching server authenticates it (signature + owner binding +
    // nonce) inside `submit_action` before dispatching.
    let ring = Arc::clone(ring);
    tokio::task::spawn_blocking(move || ring.submit_action(req))
        .await
        .unwrap_or_else(|_| OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
}

// ── TxSubmitter / TxConfirmer traits ─────────────────────────────────

/// A handle that submits transactions to the consensus mempool.
/// Mirrors `rpc::TxSubmitter` but lives in the matcher crate to
/// avoid a circular dependency.
pub trait TxSubmitter: Send + Sync {
    /// Submit a wrapped Oxide transaction envelope to the mempool.
    ///
    /// `Ok` means ONLY that the bytes passed mempool admission — it
    /// is not inclusion, not execution, and not settlement. A
    /// submitted tx can still be gate-skipped at execution (stale
    /// nonce, bad signature, block gas limit) or rejected by its
    /// module. Settlement is only real once a [`TxConfirmer`]
    /// reports the finalized outcome.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` if the mempool rejects the transaction.
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String>;
}

/// A handle that reads FINALIZED execution outcomes — the settler's
/// finality oracle. Implemented in-process by the executor handle;
/// a remote deployment would back it with a node query API.
pub trait TxConfirmer: Send + Sync {
    /// The finalized outcome for `tx_hash` (the `Domain::Transaction`
    /// hash of the full envelope), or `None` while the tx is in
    /// flight — still pooled, proposed-but-unexecuted, or aged out
    /// of the executor's bounded outcome window.
    fn tx_outcome(&self, tx_hash: &primitives::Hash) -> Option<executor::TxOutcome>;

    /// The next nonce the executor expects from `sender` — the
    /// authoritative resync anchor. The settler's local nonce only
    /// ever tracks this value; querying it on every resolution makes
    /// drift (restart, dead-lettered batch) self-healing.
    fn executed_nonce(&self, sender: &primitives::Address) -> u64;
}

// ── BatchSettler ─────────────────────────────────────────────────────

/// What one `settle_now` tick accomplished, split across the three
/// stages the old bare `usize` conflated: mempool-submitted,
/// execution-CONFIRMED, and reconciled failures. A tick that
/// submitted a batch reports `submitted > 0` and `confirmed == 0` —
/// the batch is in flight, not settled.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SettleReport {
    /// Pairs in a batch whose envelope was accepted by the mempool
    /// this tick. Acceptance is NOT settlement — the batch stays in
    /// flight until an outcome lands.
    pub submitted: usize,
    /// Pairs whose batch EXECUTED this tick (the module returned
    /// `Ok`). This is the settlement boundary — the chain applied
    /// the batch. Partial failures inside it are reported
    /// separately below; they do not subtract from `confirmed`.
    pub confirmed: usize,
    /// Fill legs the exchange rejected inside an applied batch
    /// (`fill_rejected` events — a leg failed validation; its pair
    /// settlement is voided). Nonzero means the matched book said
    /// "fill" but the chain said "no" — investigate.
    pub rejected_legs: usize,
    /// Pair settlements that failed economically inside an applied
    /// batch (`settlement_failed` events — the pair's legs were
    /// voided atomically; escrow stays withheld pending residue
    /// refunds). Same severity as `rejected_legs`.
    pub failed_pairs: usize,
    /// A batch the module rejected wholesale (`handle` returned
    /// `Err`): the fee was charged and the nonce consumed, but NO
    /// leg settled — a revert, not a skip. The fills are lost
    /// on-chain; the operator must re-issue the affected orders.
    pub batch_rejected: Option<String>,
    /// A batch that can never execute was dead-lettered (a terminal
    /// `TxSkipReason` — malformed envelope, bad signature, stale
    /// nonce, unknown module, fee floor). Same loss semantics as
    /// `batch_rejected`, but the nonce was NOT consumed — the next
    /// sealed batch reuses it.
    pub dead_lettered: Option<String>,
}

/// A settlement envelope in flight — mempool-submitted (or
/// awaiting resubmission) but not yet confirmed by execution.
struct PendingBatch {
    /// The full encoded tx envelope (nonce baked in).
    envelope: Vec<u8>,
    /// `Domain::Transaction` hash of `envelope` — the confirmer key.
    tx_hash: primitives::Hash,
    /// Aggregated pair count (reported when the batch confirms).
    pair_count: usize,
    /// Failed submission attempts so far.
    attempts: u32,
    /// Whether the last `submit_tx` returned `Ok`. `false` means the
    /// envelope is awaiting (re)submission — a fresh outbox restore
    /// also lands here, since the pool's copy may not have survived.
    submitted: bool,
    /// Ticks spent waiting for an outcome with none recorded. At
    /// [`RESUBMIT_AFTER_TICKS`] the envelope is resubmitted — the
    /// pooled copy may have been evicted without ever executing.
    wait_ticks: u32,
}

/// Maximum retries before a pending batch is flagged: 60.
///
/// At the default 100 ms settle interval this is ~6 seconds of
/// retry — long enough to ride out a transient mempool-full or a
/// consensus reconnect, short enough that a permanently-rejected
/// envelope doesn't wedge the settlement lane forever. After this
/// many retries, the settler logs a critical alert but does NOT
/// drop the pending envelope — dropping would cause cache/chain
/// divergence (the off-chain cache already reflects the fills from
/// `seal_batch`, but the on-chain settlement never landed). Instead,
/// the envelope stays pending so the operator can intervene and the
/// settlement can eventually land when the chain recovers.
const MAX_PENDING_RETRIES: u32 = 60;

/// Ticks to wait for an execution outcome before resubmitting the
/// pending envelope: 100 (~10 s at the default interval).
///
/// A pooled tx that was never proposed survives indefinitely (the
/// mempool keeps it), so `None` outcomes normally mean "still in
/// flight". But an executor restart drops the mempool — the pooled
/// copy is gone and no outcome will ever land. Resubmitting the
/// verbatim envelope re-pools it; the envelope's baked-in nonce is
/// still the one the executor expects, so a duplicate in the pool
/// (hash-identical) is either deduplicated or rejected harmlessly.
const RESUBMIT_AFTER_TICKS: u32 = 100;

/// Whether a pre-execution skip can still land if the tx stays
/// pooled. `GasLimit`/`FeeCharge` resolve themselves (the next block
/// has a fresh budget; a later funding fixes the charge). Everything
/// else is a deterministic property of the envelope bytes — the same
/// tx can never pass that gate.
fn is_retryable_skip(reason: executor::TxSkipReason) -> bool {
    matches!(reason, executor::TxSkipReason::GasLimit | executor::TxSkipReason::FeeCharge)
}

/// Aggregate sealed fills by (market, price, buy order, sell order):
/// legs at the same price between the same REGISTERED order pair
/// merge into one entry — merging across different order keys is not
/// possible because each key authorizes only its own remaining
/// quantity. The wire carries no claimed settlement amount — the
/// chain recomputes `price * qty / PRICE_SCALE` per leg.
///
/// `BTreeMap` keeps the encoded entry order deterministic and
/// reproducible for a given fill sequence. Because fills carry
/// MARGINAL leg-cost deltas (`LegCostAcc`), their `quote_amount`s
/// sum to exactly the leg's `floor(price × Σqty / SCALE)` — the
/// cache's accounting is bit-identical to the chain's, not just
/// bounded-dust close.
fn aggregate_fills(fills: &[crate::SettledFill]) -> Result<Vec<BatchFillEntry>, String> {
    let mut aggregated: std::collections::BTreeMap<
        (u16, Price, exchange::OrderKey, exchange::OrderKey),
        Qty,
    > = std::collections::BTreeMap::new();
    for f in fills {
        let key = (
            f.market,
            f.price,
            exchange::OrderKey { owner: f.buyer, client_id: f.buyer_id },
            exchange::OrderKey { owner: f.seller, client_id: f.seller_id },
        );
        match aggregated.get_mut(&key) {
            Some(q) => {
                // A qty sum above u64::MAX is unreachable in practice
                // (would require ~1.8e13 lots traded in one batch);
                // fail loudly rather than saturate.
                *q = Qty(q
                    .0
                    .checked_add(f.qty.0)
                    .ok_or_else(|| "fill qty aggregation overflow".to_string())?);
            }
            None => {
                aggregated.insert(key, f.qty);
            }
        }
    }
    Ok(aggregated
        .into_iter()
        .map(|((market, price, buy, sell), qty)| BatchFillEntry { market, price, qty, buy, sell })
        .collect())
}

/// The settler's secp256k1 identity for signing settlement
/// envelopes — required when the executor enforces
/// `UnsignedTxPolicy::Reject`, and correct in any case because the
/// exchange gates batch settlement on the declared sender matching
/// the configured settlement operator.
struct SigningConfig {
    /// The operator's 32-byte secret key.
    privkey: [u8; 32],
    /// EIP-712 chain ID bound into the signature.
    chain_id: u64,
}

/// The batch settler: periodically seals the fill buffer and
/// submits a batch settlement transaction to consensus — then waits
/// for the transaction's FINALIZED execution outcome before calling
/// it settled.
///
/// Runs on a dedicated tokio task. Every `interval` milliseconds it
/// resolves any in-flight batch (outcome check → resubmit → confirm
/// or dead-letter), then seals and submits the next batch. At most
/// one batch is ever in flight: the executor's nonce gate makes a
/// second envelope unreachable while the first is pending, and the
/// pause lets fills keep accumulating in the sealer's buffer.
pub struct BatchSettler {
    /// The batch sealer — either the mutex path (`SharedMatcher`) or
    /// the ring owner thread (`RingMatcher`). Both seal from THE ONE
    /// order book.
    sealer: Arc<dyn crate::BatchSealer>,
    submitter: Arc<dyn TxSubmitter>,
    /// The finalized-outcome oracle — the difference between
    /// "accepted into the mempool" and "executed on-chain".
    confirmer: Arc<dyn TxConfirmer>,
    interval: Duration,
    /// The sender address for settlement txs (the matcher operator).
    /// When `signing` is configured this is the key-derived address
    /// — the three views of identity (declared sender, recovered
    /// signer, exchange operator) can never diverge.
    sender: primitives::Address,
    /// Optional envelope signing (EIP-712 + secp256k1, executor v1
    /// layout). `None` produces v0 unsigned envelopes — fine for the
    /// devnet `UnsignedTxPolicy::Allow`, rejected under `Reject`.
    signing: Option<SigningConfig>,
    /// Next settlement nonce — advanced ONLY when the confirmer
    /// proves the previous batch executed (or was terminally
    /// skipped), never at submit time. It is resynced from
    /// `confirmer.executed_nonce` on every resolution, so restart
    /// drift and dead-lettered batches cannot gap the sequence.
    nonce: std::sync::atomic::AtomicU64,
    /// The in-flight envelope awaiting its execution outcome. At
    /// most one — see the struct doc.
    pending: std::sync::Mutex<Option<PendingBatch>>,
    /// Durable checkpoint of `{next_nonce, pending}` — survives a
    /// matcher restart so an in-flight batch is resolved, not
    /// forgotten. `None` keeps the legacy memory-only behavior
    /// (a restart mid-flight then falls back to the executor's
    /// `executed_nonce` resync on the next resolution).
    outbox: std::sync::Mutex<Option<SettlementOutbox>>,
}

impl BatchSettler {
    /// Create a new batch settler.
    ///
    /// # Arguments
    /// - `sealer`: the batch sealer (`SharedMatcher` or `RingMatcher` —
    ///   both seal from the single order book).
    /// - `submitter`: the consensus tx submitter.
    /// - `confirmer`: the finalized-outcome oracle — usually the same
    ///   in-process executor handle as `submitter`.
    /// - `interval_ms`: how often to seal and submit batches.
    /// - `sender`: the matcher operator's address (for tx envelope).
    ///   Ignored when `with_signing` is used — the sender is derived
    ///   from the key so the envelope can never name a different
    ///   account than the signer.
    /// - `start_nonce`: the initial nonce for settlement txs. Ignored
    ///   when an outbox is attached — the checkpoint's value wins.
    #[must_use]
    pub fn new(
        sealer: Arc<dyn crate::BatchSealer>,
        submitter: Arc<dyn TxSubmitter>,
        confirmer: Arc<dyn TxConfirmer>,
        interval_ms: u64,
        sender: primitives::Address,
        start_nonce: u64,
    ) -> Self {
        Self {
            sealer,
            submitter,
            confirmer,
            interval: Duration::from_millis(interval_ms),
            sender,
            signing: None,
            nonce: std::sync::atomic::AtomicU64::new(start_nonce),
            pending: std::sync::Mutex::new(None),
            outbox: std::sync::Mutex::new(None),
        }
    }

    /// Sign settlement envelopes with `privkey` under `chain_id`.
    /// The sender becomes the key-derived address: the declared
    /// sender, the recovered signer, and the exchange's configured
    /// settlement operator can never diverge.
    ///
    /// # Panics
    ///
    /// Panics if `privkey` is not a valid secp256k1 secret — a
    /// settler that cannot sign its own envelopes is a fatal
    /// misconfiguration, not a runtime condition.
    #[must_use]
    pub fn with_signing(mut self, privkey: [u8; 32], chain_id: u64) -> Self {
        self.sender = crypto::secp::signable_pubkey_address(&privkey)
            .expect("settlement key must be a valid secp256k1 secret");
        self.signing = Some(SigningConfig { privkey, chain_id });
        self
    }

    /// Attach a durable outbox checkpoint at `path`. Any previously
    /// checkpointed `{next_nonce, pending}` is restored: a batch
    /// in-flight across the restart is resumed (its outcome is
    /// checked before any resubmission, so a batch that executed
    /// during the downtime is reconciled, not replayed).
    ///
    /// # Panics
    ///
    /// Panics if the checkpoint exists but does not decode — a
    /// corrupt outbox must fail closed: starting with a forgotten
    /// in-flight batch would misreport its fills as unsettled forever
    /// or, worse, reuse a consumed nonce.
    #[must_use]
    pub fn with_outbox(self, path: std::path::PathBuf) -> Self {
        let state = SettlementOutbox::load(&path)
            .unwrap_or_else(|e| panic!("settlement outbox at {} is corrupt: {e}", path.display()));
        self.nonce.store(state.next_nonce, std::sync::atomic::Ordering::Relaxed);
        if let Some(p) = state.pending {
            *primitives::sync::lock_state(&self.pending) = Some(p);
        }
        *primitives::sync::lock_state(&self.outbox) = Some(SettlementOutbox { path });
        self
    }

    /// Checkpoint `{next_nonce, pending}` if an outbox is attached.
    /// Called on every settlement-lane state transition; a failed
    /// write is best-effort (the in-memory lane keeps working — the
    /// restart window just widens).
    fn persist(&self, pending: Option<&PendingBatch>) {
        let mut guard = primitives::sync::lock_state(&self.outbox);
        if let Some(store) = guard.as_mut() {
            let _ = store.save(self.nonce.load(std::sync::atomic::Ordering::Relaxed), pending);
        }
    }

    /// Reconcile an in-flight batch against its finalized outcome.
    /// Returns the populated report fields; `pending` is cleared on
    /// every terminal outcome and the nonce is resynced from the
    /// executor's authoritative counter.
    fn resolve_pending(
        &self,
        guard: &mut Option<PendingBatch>,
        report: &mut SettleReport,
        outcome: executor::TxOutcome,
    ) {
        match outcome {
            executor::TxOutcome::Executed { events, error } => {
                let pair_count = guard.as_ref().map_or(0, |p| p.pair_count);
                *guard = None;
                self.nonce.store(
                    self.confirmer.executed_nonce(&self.sender),
                    std::sync::atomic::Ordering::Relaxed,
                );
                match error {
                    None => {
                        report.confirmed = pair_count;
                        report.rejected_legs =
                            events.iter().filter(|e| e.kind == "fill_rejected").count();
                        report.failed_pairs =
                            events.iter().filter(|e| e.kind == "settlement_failed").count();
                    }
                    Some(e) => report.batch_rejected = Some(e),
                }
            }
            executor::TxOutcome::Skipped { reason } if is_retryable_skip(reason) => {
                // The tx stays pooled and can still land — keep
                // waiting rather than resubmitting a live copy.
            }
            executor::TxOutcome::Skipped { reason } => {
                *guard = None;
                // The skipped tx never consumed its nonce — resync
                // (a no-op unless out-of-band drift moved it) so the
                // next sealed batch reuses the same nonce value.
                self.nonce.store(
                    self.confirmer.executed_nonce(&self.sender),
                    std::sync::atomic::Ordering::Relaxed,
                );
                report.dead_lettered = Some(format!("{reason:?}"));
            }
        }
        self.persist(guard.as_ref());
    }

    /// Seal the current batch and submit it to consensus, then drive
    /// any in-flight batch toward its finalized outcome. Returns the
    /// tick's report — see [`SettleReport`] for the stage semantics.
    ///
    /// Aggregates fills by (market, price, buy order, sell order)
    /// before encoding — multiple fills at one price between the
    /// same registered order pair are combined into one leg. This
    /// reduces the number of ledger operations from `fill_count` to
    /// `unique_pair_count` (typically 2-5x fewer).
    ///
    /// # Errors
    ///
    /// Returns `Err` if a mempool (re)submission is rejected — the
    /// batch stays pending and the next tick retries.
    ///
    /// # Panics
    ///
    /// Panics if the underlying sealer's mutex/control channel is
    /// poisoned or disconnected.
    pub fn settle_now(&self) -> Result<SettleReport, String> {
        let mut report = SettleReport::default();
        {
            let mut pending = primitives::sync::lock_state(&self.pending);
            if let Some(p) = pending.as_mut() {
                // The outcome check runs before ANY (re)submission:
                // a batch that executed during a matcher restart —
                // or while a resubmit was queued — is reconciled from
                // the authoritative record instead of replayed.
                if let Some(outcome) = self.confirmer.tx_outcome(&p.tx_hash) {
                    self.resolve_pending(&mut pending, &mut report, outcome);
                    return Ok(report);
                }
                if p.submitted {
                    p.wait_ticks += 1;
                    if p.wait_ticks >= RESUBMIT_AFTER_TICKS {
                        // No outcome after ~10 s: the pooled copy may
                        // have been evicted (executor restart drops
                        // the mempool). Re-arm submission — the same
                        // envelope is resubmitted verbatim, so a
                        // still-pooled duplicate is a harmless no-op.
                        p.submitted = false;
                        p.wait_ticks = 0;
                    }
                } else {
                    match self.submitter.submit_tx(TxBytes::new(p.envelope.clone())) {
                        Ok(()) => {
                            p.submitted = true;
                            p.wait_ticks = 0;
                            report.submitted = p.pair_count;
                            self.persist(pending.as_ref());
                        }
                        Err(e) => {
                            p.attempts += 1;
                            let (attempts, pair_count) = (p.attempts, p.pair_count);
                            self.persist(pending.as_ref());
                            if attempts >= MAX_PENDING_RETRIES {
                                // Do NOT drop the pending envelope —
                                // dropping strands already-sealed fills
                                // (cache applied, chain never settled).
                                eprintln!(
                                    "batch settler: CRITICAL — batch of {pair_count} pairs failed {attempts} submissions, keeping pending: {e}"
                                );
                            }
                            return Err(e);
                        }
                    }
                }
                return Ok(report);
            }
        }

        // Seal the batch from the single order book.
        let fills = self.sealer.seal_batch();

        if fills.is_empty() {
            return Ok(report);
        }

        let entries = aggregate_fills(&fills)?;
        let pair_count = entries.len();

        // Encode as a batch-settle message.
        let module_payload = exchange::msg::batch_settle(&entries);

        // Wrap in an Oxide transaction envelope. The nonce is READ
        // here, not consumed — it advances only when the confirmer
        // proves execution, so a rejected submission or a terminal
        // skip leaves the sequence contiguous for the retry (and for
        // the next batch).
        let nonce = self.nonce.load(std::sync::atomic::Ordering::Relaxed);
        let fee = 100u64;
        let envelope = self.encode_envelope(nonce, fee, &module_payload)?;

        let tx_hash = crypto::Hasher::hash_one(crypto::Domain::Transaction, &envelope);
        match self.submitter.submit_tx(TxBytes::new(envelope.clone())) {
            Ok(()) => {
                report.submitted = pair_count;
                let mut pending = primitives::sync::lock_state(&self.pending);
                *pending = Some(PendingBatch {
                    envelope,
                    tx_hash,
                    pair_count,
                    attempts: 0,
                    submitted: true,
                    wait_ticks: 0,
                });
                self.persist(pending.as_ref());
            }
            Err(e) => {
                let mut pending = primitives::sync::lock_state(&self.pending);
                *pending = Some(PendingBatch {
                    envelope,
                    tx_hash,
                    pair_count,
                    attempts: 1,
                    submitted: false,
                    wait_ticks: 0,
                });
                self.persist(pending.as_ref());
                return Err(e);
            }
        }
        Ok(report)
    }

    /// Encode the tx envelope — v0 unsigned layout, or the v1 signed
    /// layout (`module_id|0x80`, then a 65-byte recoverable secp256k1
    /// signature over the EIP-712 digest) when `signing` is set.
    fn encode_envelope(
        &self,
        nonce: u64,
        fee: u64,
        module_payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let signed = self.signing.is_some();
        let mut envelope = Vec::with_capacity(37 + usize::from(signed) * 65 + module_payload.len());
        envelope.extend_from_slice(&self.sender.0);
        envelope.extend_from_slice(&nonce.to_le_bytes());
        envelope.extend_from_slice(&fee.to_le_bytes());
        if let Some(signing) = &self.signing {
            let sig = crypto::eip712::sign_tx(
                &signing.privkey,
                signing.chain_id,
                &self.sender,
                nonce,
                fee,
                framework::module_id::EXCHANGE,
                module_payload,
            )
            .map_err(|e| format!("sign settlement envelope: {e:?}"))?;
            envelope.push(framework::module_id::EXCHANGE | 0x80);
            envelope.extend_from_slice(&sig.sig);
            envelope.push(sig.recid.as_u8());
        } else {
            envelope.push(framework::module_id::EXCHANGE);
        }
        envelope.extend_from_slice(module_payload);
        Ok(envelope)
    }

    /// Whether a batch is currently in flight (submitted or awaiting
    /// resubmission, but not yet resolved by an outcome). Exposed for
    /// tests and operator introspection.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        primitives::sync::lock_state(&self.pending).is_some()
    }

    /// Run the batch settler loop. Seals and submits batches every
    /// `interval` until the matcher is dropped or the task is
    /// cancelled.
    pub async fn run(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            ticker.tick().await;
            match self.settle_now() {
                Err(e) => eprintln!("batch settler: submission failed: {e}"),
                Ok(report) => {
                    if let Some(e) = &report.batch_rejected {
                        eprintln!(
                            "batch settler: CRITICAL — batch of {} pairs rejected at execution: {e}",
                            report.submitted + report.confirmed
                        );
                    }
                    if let Some(reason) = &report.dead_lettered {
                        eprintln!(
                            "batch settler: CRITICAL — batch dead-lettered ({reason}); fills lost on-chain"
                        );
                    }
                    if report.rejected_legs > 0 || report.failed_pairs > 0 {
                        eprintln!(
                            "batch settler: batch confirmed with {} rejected legs, {} failed pairs",
                            report.rejected_legs, report.failed_pairs
                        );
                    }
                }
            }
        }
    }
}

/// A file-backed checkpoint of the settlement lane's `{next_nonce,
/// pending}` state — the same write-tmp-fsync-rename discipline as
/// `NonceStore`. Without it a matcher restart forgets an in-flight
/// batch: its fills were drained from the sealer but the settler
/// loses track of whether they ever settled.
struct SettlementOutbox {
    /// Checkpoint file path (`<path>.tmp` is the write scratch).
    path: std::path::PathBuf,
}

/// The decoded outbox state.
struct SettlementOutboxState {
    /// Next nonce the settler will seal with.
    next_nonce: u64,
    /// The in-flight batch, if one was pending at checkpoint time.
    pending: Option<PendingBatch>,
}

impl SettlementOutbox {
    /// Checkpoint format magic + version for strict decode.
    const MAGIC: &'static [u8; 4] = b"OXSO";
    /// Current format version.
    const VERSION: u32 = 1;
    /// Bound on a stored envelope — larger means corrupt or hostile;
    /// a batch-settle envelope is ~37 + 65 + legs bytes, nowhere
    /// near this ceiling.
    const MAX_ENVELOPE_LEN: usize = 1 << 20;

    /// Read the checkpoint. Missing file = empty state (first run).
    /// `Err` on ANY structural violation — the caller fails closed.
    fn load(path: &std::path::Path) -> Result<SettlementOutboxState, String> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SettlementOutboxState { next_nonce: 0, pending: None });
            }
            Err(e) => return Err(format!("read failed: {e}")),
        };
        // Header: magic(4) + version(4) + next_nonce(8) +
        // pending_flag(1) = 17 bytes.
        if bytes.len() < 17 {
            return Err(format!("truncated header ({} bytes)", bytes.len()));
        }
        if &bytes[0..4] != Self::MAGIC {
            return Err("bad magic".to_string());
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or_default());
        if version != Self::VERSION {
            return Err(format!("unsupported version {version}"));
        }
        let next_nonce = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or_default());
        let has_pending = bytes[16] != 0;
        if !has_pending {
            if bytes.len() != 17 {
                return Err(format!("trailing bytes without pending: {}", bytes.len()));
            }
            return Ok(SettlementOutboxState { next_nonce, pending: None });
        }
        // Pending section: envelope_len(4) + envelope + pair_count(8)
        // + attempts(4) + submitted(1).
        if bytes.len() < 21 {
            return Err(format!("truncated pending header ({} bytes)", bytes.len()));
        }
        let env_len = u32::from_le_bytes(bytes[17..21].try_into().unwrap_or_default()) as usize;
        if env_len > Self::MAX_ENVELOPE_LEN {
            return Err(format!("envelope len {env_len} exceeds bound"));
        }
        let end = 21 + env_len;
        if bytes.len() != end + 13 {
            return Err(format!("size mismatch: {} bytes, expected {}", bytes.len(), end + 13));
        }
        let envelope = bytes[21..end].to_vec();
        let pair_count =
            usize::try_from(u64::from_le_bytes(bytes[end..end + 8].try_into().unwrap_or_default()))
                .map_err(|_| "pair count overflows usize".to_string())?;
        let attempts = u32::from_le_bytes(bytes[end + 8..end + 12].try_into().unwrap_or_default());
        let submitted = bytes[end + 12] != 0;
        let tx_hash = crypto::Hasher::hash_one(crypto::Domain::Transaction, &envelope);
        Ok(SettlementOutboxState {
            next_nonce,
            pending: Some(PendingBatch {
                envelope,
                tx_hash,
                pair_count,
                attempts,
                submitted,
                wait_ticks: 0,
            }),
        })
    }

    /// Serialize and atomically replace the checkpoint.
    fn save(&mut self, next_nonce: u64, pending: Option<&PendingBatch>) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(30);
        buf.extend_from_slice(Self::MAGIC);
        buf.extend_from_slice(&Self::VERSION.to_le_bytes());
        buf.extend_from_slice(&next_nonce.to_le_bytes());
        match pending {
            None => buf.push(0),
            Some(p) => {
                buf.push(1);
                buf.extend_from_slice(
                    &u32::try_from(p.envelope.len()).unwrap_or(u32::MAX).to_le_bytes(),
                );
                buf.extend_from_slice(&p.envelope);
                buf.extend_from_slice(&(p.pair_count as u64).to_le_bytes());
                buf.extend_from_slice(&p.attempts.to_le_bytes());
                buf.push(u8::from(p.submitted));
            }
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &buf)?;
        if let Ok(f) = std::fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        std::fs::rename(&tmp, &self.path)
    }
}

// ── Binary TCP server ────────────────────────────────────────────────

/// Run a binary TCP order-entry server on the given port.
///
/// Accepts connections, reads 43-byte binary order requests, feeds
/// them to the shared matcher, and writes 13-byte responses. Each
/// connection is handled on its own tokio task. Also supports batch
/// requests (multiple orders in a single message) via the batch flag.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
///
/// # Panics
///
/// Panics if the inner matching server mutex is poisoned during
/// batch order processing.
pub async fn run_binary_tcp_server(matcher: Arc<SharedMatcher>, port: u16) -> std::io::Result<()> {
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run_binary_tcp_server_impl(matcher, port, None, ring_counter).await
}

/// Run a binary TCP order-entry server on the given port, using the
/// lock-free SPSC ring matcher instead of the mutex.
///
/// The `ring_matcher` is wrapped in `Arc<Mutex<Option<_>>>` so it can
/// be shared with the batch settler (which needs `seal_batch` via the
/// mutex path). Each connection is assigned a ring index; orders go
/// through the SPSC ring (no locks) and responses come back through
/// the per-connection response ring.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
///
/// # Panics
///
/// Panics if the inner matching server mutex is poisoned during
/// batch order processing.
pub async fn run_binary_tcp_server_ring(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Arc<crate::RingMatcher>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    run_binary_tcp_server_impl(matcher, port, Some(ring_matcher), ring_counter).await
}

/// Shared implementation for both TCP server variants. When
/// `ring_matcher` is `Some`, orders are routed through the SPSC
/// rings; otherwise they go through the mutex path.
async fn run_binary_tcp_server_impl(
    matcher: Arc<SharedMatcher>,
    port: u16,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("binary TCP server listening on 127.0.0.1:{port}");

    loop {
        let (socket, _addr) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        let ring_matcher = ring_matcher.clone();
        let ring_counter = Arc::clone(&ring_counter);
        tokio::spawn(handle_connection(socket, matcher, ring_matcher, ring_counter));
    }
}

/// Handle a single TCP connection: read requests (single or batch),
/// submit to the matching server (mutex or SPSC ring path), and
/// write responses. Runs until the client disconnects.
#[allow(clippy::too_many_lines)]
async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    matcher: Arc<SharedMatcher>,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Read the first 4 bytes to check if it's a batch or single request.
    let mut header = [0u8; 4];
    loop {
        if socket.read_exact(&mut header).await.is_err() {
            break;
        }
        // Check for batch flag (byte 3 = 0xFF).
        if header[3] == crate::protocol::BATCH_FLAG {
            // Batch request: read the rest of the header (count:4)
            // and then count × 40-byte entries.
            let mut count_buf = [0u8; 4];
            if socket.read_exact(&mut count_buf).await.is_err() {
                break;
            }
            let count = u32::from_le_bytes(count_buf) as usize;
            // HIGH fix: bound-check `count` BEFORE allocating. A
            // byzantine peer can send `u32::MAX` as the count, which
            // would cause a multi-GB allocation (OOM). The MAX_BATCH_SIZE
            // check in the protocol decoder runs after allocation;
            // we must check here first.
            if count > crate::protocol::MAX_BATCH_SIZE {
                break; // reject oversized batch
            }
            let entries_len = count * crate::protocol::BATCH_ENTRY_SIZE;
            let mut entries = vec![0u8; entries_len];
            if socket.read_exact(&mut entries).await.is_err() {
                break;
            }
            // Reconstruct the full batch message for decoding.
            let mut full_msg = Vec::with_capacity(8 + entries_len);
            full_msg.extend_from_slice(&header);
            full_msg.extend_from_slice(&count_buf);
            full_msg.extend_from_slice(&entries);
            // Decode the batch.
            let Some(orders) = crate::protocol::decode_batch_request(&full_msg) else {
                let resp = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&resp)).await;
                continue;
            };
            // Submit the whole batch. The ring path authenticates
            // each order on this thread and pushes only
            // `VerifiedOrder` proofs; the mutex path authenticates
            // inside `submit_order`. Both produce one response per
            // request — failed authentication yields an aligned
            // `BadSignature` in place, never a dropped or reordered
            // response.
            let responses: Vec<OrderResponse> = if let Some(rm) = &ring_matcher {
                submit_batch_ring(rm, &ring_counter, orders).await
            } else {
                match matcher.inner.lock() {
                    Ok(mut server) => orders.iter().map(|req| server.submit_order(req)).collect(),
                    Err(_) => orders
                        .iter()
                        .map(|_| {
                            OrderResponse::rejected(crate::protocol::RejectReason::EngineError)
                        })
                        .collect(),
                }
            };
            // Encode and send the batch response.
            let batch_resp = crate::protocol::encode_batch_response(&responses);
            if socket.write_all(&batch_resp).await.is_err() {
                break;
            }
        } else if is_action_request(&header) {
            // Action request (cancel/amend/replace): the market byte
            // is ACTION_FLAG (0xFE). Read the remaining
            // ACTION_REQUEST_SIZE - 4 bytes and decode.
            let mut rest = [0u8; crate::protocol::ACTION_REQUEST_SIZE - 4];
            if socket.read_exact(&mut rest).await.is_err() {
                break;
            }
            let mut full = Vec::with_capacity(crate::protocol::ACTION_REQUEST_SIZE);
            full.extend_from_slice(&header);
            full.extend_from_slice(&rest);
            let Some(action_req) = decode_action_request(&full) else {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            };
            // Signature verification before processing — with the
            // SAME chain ID the matcher will re-verify against.
            let action_chain_id =
                ring_matcher.as_ref().map_or_else(|| matcher.chain_id(), |rm| rm.chain_id());
            if !crate::protocol::verify_action_with_chain_id(&action_req, action_chain_id) {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::BadSignature);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            }
            // The wire `ActionRequest` is submitted intact — the
            // matching server re-authenticates it (signature + owner
            // binding + nonce) as the mandatory boundary before
            // dispatching. The verify above is only an early reject.
            let action_resp = if let Some(rm) = &ring_matcher {
                submit_action_ring(rm, action_req).await
            } else {
                matcher.submit_action(&action_req)
            };
            if socket.write_all(&encode_response(&action_resp)).await.is_err() {
                break;
            }
        } else {
            // Single request: read the remaining 39 bytes
            // (we already have the first 4).
            let mut rest = [0u8; crate::protocol::REQUEST_SIZE - 4];
            if socket.read_exact(&mut rest).await.is_err() {
                break;
            }
            let mut full = Vec::with_capacity(crate::protocol::REQUEST_SIZE);
            full.extend_from_slice(&header);
            full.extend_from_slice(&rest);
            // Decode the order.
            let Some(req) = decode_request(&full) else {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            };
            // Submit to the matching server — through the
            // SPSC ring if available, otherwise the mutex.
            let order_resp = if let Some(rm) = &ring_matcher {
                submit_one_ring(rm, &ring_counter, req).await
            } else {
                matcher.submit(&req)
            };
            // Write the response.
            if socket.write_all(&encode_response(&order_resp)).await.is_err() {
                break;
            }
        }
    }
}

// ── JSON-RPC over TCP server (simplified, no HTTP) ───────────────────

/// Run a JSON-RPC order-entry server on the given port (TCP, line-
/// delimited JSON). This is a simplified version that doesn't require
/// axum/hyper — each line is a JSON-RPC request, each response is a
/// JSON line.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
/// Run a JSON-RPC order-entry server on the given port (TCP, line-
/// delimited JSON) — mutex path.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_jsonrpc_tcp_server(matcher: Arc<SharedMatcher>, port: u16) -> std::io::Result<()> {
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run_jsonrpc_tcp_server_impl(matcher, None, ring_counter, port).await
}

/// Run a JSON-RPC order-entry server on the given port, routing
/// orders through the lock-free SPSC ring matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_jsonrpc_tcp_server_ring(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Arc<crate::RingMatcher>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    run_jsonrpc_tcp_server_impl(matcher, Some(ring_matcher), ring_counter, port).await
}

/// Shared implementation for the JSON-RPC server. When
/// `ring_matcher` is `Some`, orders route through the SPSC rings.
async fn run_jsonrpc_tcp_server_impl(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("JSON-RPC server listening on 127.0.0.1:{port}");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        let ring_matcher = ring_matcher.clone();
        let ring_counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = socket.split();
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // Parse the JSON-RPC request.
                let req: serde_json::Value = if let Ok(v) = serde_json::from_str(&line) {
                    v
                } else {
                    let _ = writer
                        .write_all(
                            br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}
"#,
                        )
                        .await;
                    continue;
                };
                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let params = req.get("params").cloned().unwrap_or(serde_json::Value::Null);

                if method == crate::jsonrpc::MANAGE_ORDER {
                    // Order action (cancel/amend/replace).
                    let Some(action_req) = crate::jsonrpc::parse_jsonrpc_action(&params) else {
                        let _ = writer
                            .write_all(
                                br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":null}
"#,
                            )
                            .await;
                        continue;
                    };
                    let action_chain_id = transport_chain_id(&matcher, ring_matcher.as_ref());
                    if !crate::protocol::verify_action_with_chain_id(&action_req, action_chain_id) {
                        let _ = writer
                            .write_all(
                                br#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"bad signature"},"id":null}
"#,
                            )
                            .await;
                        continue;
                    }
                    // Submit the wire `ActionRequest` intact — the
                    // core re-authenticates before dispatch.
                    let resp = if let Some(rm) = &ring_matcher {
                        submit_action_ring(rm, action_req).await
                    } else {
                        matcher.submit_action(&action_req)
                    };
                    let result = crate::jsonrpc::format_jsonrpc_response(&resp);
                    let response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": id,
                    });
                    let mut response_line = serde_json::to_string(&response).unwrap_or_default();
                    response_line.push('\n');
                    let _ = writer.write_all(response_line.as_bytes()).await;
                    continue;
                }

                if method != "oxide_placeOrder" {
                    let _ = writer
                        .write_all(
                            br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":null}
"#,
                        )
                        .await;
                    continue;
                }
                // Parse the order.
                let Some(order_req) = crate::jsonrpc::parse_jsonrpc_order(&params) else {
                    let _ = writer
                        .write_all(
                            br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":null}
"#,
                        )
                        .await;
                    continue;
                };
                // Submit to the matching server — through the SPSC
                // ring if available, otherwise the mutex.
                let resp = if let Some(rm) = &ring_matcher {
                    submit_one_ring(rm, &ring_counter, order_req).await
                } else {
                    matcher.submit(&order_req)
                };
                // Format the response.
                let result = crate::jsonrpc::format_jsonrpc_response(&resp);
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": result,
                    "id": id,
                });
                let mut response_line = serde_json::to_string(&response).unwrap_or_default();
                response_line.push('\n');
                let _ = writer.write_all(response_line.as_bytes()).await;
            }
        });
    }
}

// ── FIX server (simplified) ──────────────────────────────────────────

/// Run a FIX order-entry server on the given port. Accepts FIX
/// `NewOrderSingle` (MsgType=D) messages, feeds them to the shared
/// matcher, and returns `ExecutionReport` (MsgType=8) responses.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
/// Run a FIX order-entry server on the given port (mutex path).
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_fix_server(matcher: Arc<SharedMatcher>, port: u16) -> std::io::Result<()> {
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run_fix_server_impl(matcher, None, ring_counter, port).await
}

/// Run a FIX order-entry server on the given port, routing orders
/// through the lock-free SPSC ring matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_fix_server_ring(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Arc<crate::RingMatcher>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    run_fix_server_impl(matcher, Some(ring_matcher), ring_counter, port).await
}

/// Shared implementation for the FIX server.
async fn run_fix_server_impl(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("FIX server listening on 127.0.0.1:{port}");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        let ring_matcher = ring_matcher.clone();
        let ring_counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break, // EOF or error.
                    Ok(n) => n,
                };
                // FIX messages are SOH-delimited. Find complete
                // messages and process them.
                let data = &buf[..n];
                // Split on SOH (0x01) to find the message boundary.
                // A complete FIX message ends with a SOH after the
                // last tag. We look for the CheckSum tag (10=) as
                // the message terminator.
                let text = String::from_utf8_lossy(data);
                // Find the ClOrdID for the response.
                let cl_ord_id = text
                    .split('\x01')
                    .find_map(|f| f.strip_prefix("11=").map(str::to_string))
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                // Determine the FIX MsgType (tag 35) to dispatch.
                let msg_type = text
                    .split('\x01')
                    .find_map(|f| f.strip_prefix("35=").map(str::to_string))
                    .unwrap_or_default();

                if msg_type == crate::fix::MSG_TYPE_CANCEL
                    || msg_type == crate::fix::MSG_TYPE_CANCEL_REPLACE
                {
                    // Order cancel (F) or cancel-replace (G).
                    let action_req = if msg_type == crate::fix::MSG_TYPE_CANCEL {
                        crate::fix::parse_fix_cancel(&text)
                    } else {
                        crate::fix::parse_fix_cancel_replace(&text)
                    };
                    let Some(action_req) = action_req else {
                        // Malformed action — answer with a rejected
                        // ExecutionReport instead of dropping the
                        // message: a client blocking on a response
                        // per message must never be wedged by a
                        // parse failure.
                        let resp = OrderResponse::rejected(RejectReason::Malformed);
                        let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                        let _ = socket.write_all(report.as_bytes()).await;
                        continue;
                    };
                    let action_chain_id = transport_chain_id(&matcher, ring_matcher.as_ref());
                    if !crate::protocol::verify_action_with_chain_id(&action_req, action_chain_id) {
                        let resp = OrderResponse::rejected(RejectReason::BadSignature);
                        let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                        let _ = socket.write_all(report.as_bytes()).await;
                        continue;
                    }
                    // Submit the wire `ActionRequest` intact — the
                    // core re-authenticates before dispatch.
                    let resp = if let Some(rm) = &ring_matcher {
                        submit_action_ring(rm, action_req).await
                    } else {
                        matcher.submit_action(&action_req)
                    };
                    let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                    let _ = socket.write_all(report.as_bytes()).await;
                    continue;
                }

                // Default: parse as NewOrderSingle (D).
                let Some(req) = crate::fix::parse_fix_order(&text) else {
                    // Malformed order — answer with a rejected
                    // ExecutionReport instead of dropping the
                    // message: a client blocking on a response per
                    // message must never be wedged by a parse
                    // failure.
                    let resp = OrderResponse::rejected(RejectReason::Malformed);
                    let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                    let _ = socket.write_all(report.as_bytes()).await;
                    continue;
                };
                // Submit to the matching server — through the SPSC
                // ring if available, otherwise the mutex.
                let resp = if let Some(rm) = &ring_matcher {
                    submit_one_ring(rm, &ring_counter, req).await
                } else {
                    matcher.submit(&req)
                };
                // Format the FIX ExecutionReport.
                let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                let _ = socket.write_all(report.as_bytes()).await;
            }
        });
    }
}

// ── WebSocket server ─────────────────────────────────────────────────

/// Run a WebSocket order-entry server on the given port. Accepts
/// WebSocket connections, receives JSON order messages, feeds them
/// to the shared matcher, and sends JSON responses back.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
/// Run a WebSocket order-entry server on the given port (mutex path).
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_websocket_server(matcher: Arc<SharedMatcher>, port: u16) -> std::io::Result<()> {
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run_websocket_server_impl(matcher, None, ring_counter, port).await
}

/// Run a WebSocket order-entry server on the given port, routing
/// orders through the lock-free SPSC ring matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_websocket_server_ring(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Arc<crate::RingMatcher>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    run_websocket_server_impl(matcher, Some(ring_matcher), ring_counter, port).await
}

/// Shared implementation for the WebSocket server.
async fn run_websocket_server_impl(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("WebSocket server listening on 127.0.0.1:{port}");

    loop {
        let (socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        let ring_matcher = ring_matcher.clone();
        let ring_counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            use tokio_tungstenite::tungstenite::Message;
            let ws_stream = match tokio_tungstenite::accept_async(socket).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("WebSocket handshake failed: {e}");
                    return;
                }
            };
            let (mut ws_sender, mut ws_receiver) = ws_stream.split();

            while let Some(msg_result) = ws_receiver.next().await {
                let Ok(msg) = msg_result else { break };
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                    Message::Close(_) => break,
                    _ => continue,
                };

                // Check if this is an action request (has "action" field)
                // or a new order request.
                if text.contains("\"action\"") {
                    // Parse as an order action (cancel/amend/replace).
                    let Some(action_req) = crate::ws::parse_ws_action(&text) else {
                        let _ = ws_sender
                            .send(Message::Text(r#"{"error":"invalid action"}"#.into()))
                            .await;
                        continue;
                    };
                    let action_chain_id = transport_chain_id(&matcher, ring_matcher.as_ref());
                    if !crate::protocol::verify_action_with_chain_id(&action_req, action_chain_id) {
                        let resp = OrderResponse::rejected(RejectReason::BadSignature);
                        let response = crate::ws::format_ws_response(&resp, 0);
                        let _ = ws_sender.send(Message::Text(response.into())).await;
                        continue;
                    }
                    // Submit the wire `ActionRequest` intact — the
                    // core re-authenticates before dispatch.
                    let resp = if let Some(rm) = &ring_matcher {
                        submit_action_ring(rm, action_req).await
                    } else {
                        matcher.submit_action(&action_req)
                    };
                    let response = crate::ws::format_ws_response(&resp, 0);
                    if ws_sender.send(Message::Text(response.into())).await.is_err() {
                        break;
                    }
                    continue;
                }

                // Parse the WebSocket order.
                let Some(req) = crate::ws::parse_ws_order(&text) else {
                    let _ =
                        ws_sender.send(Message::Text(r#"{"error":"invalid order"}"#.into())).await;
                    continue;
                };
                // Submit to the matching server — through the SPSC
                // ring if available, otherwise the mutex.
                let resp = if let Some(rm) = &ring_matcher {
                    submit_one_ring(rm, &ring_counter, req).await
                } else {
                    matcher.submit(&req)
                };
                // Format the WebSocket response.
                let response = crate::ws::format_ws_response(&resp, 0);
                if ws_sender.send(Message::Text(response.into())).await.is_err() {
                    break;
                }
            }
        });
    }
}

// ── Multi-protocol server ────────────────────────────────────────────

/// Configuration for the multi-protocol matching server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Port for the binary TCP server.
    pub binary_tcp_port: u16,
    /// Port for the JSON-RPC server.
    pub jsonrpc_port: u16,
    /// Port for the FIX server.
    pub fix_port: u16,
    /// Port for the WebSocket server.
    pub websocket_port: u16,
    /// Batch settlement interval in milliseconds.
    pub batch_interval_ms: u64,
    /// The chain ID order/action signatures are verified against.
    /// Used only where this module constructs the matcher itself
    /// (`run_server_multi`) — otherwise the chain ID lives on the
    /// matcher object the caller built (`MatchingServer::set_chain_id`).
    /// Defaults to the devnet [`crate::protocol::CHAIN_ID`]; set it
    /// to the deployment's real chain ID.
    pub chain_id: u64,
    /// Durable checkpoint file for consumed nonces — bounds the
    /// restart replay window to the flush interval instead of
    /// "any captured request replays once after every restart".
    /// Same scope note as `chain_id`: used where this module builds
    /// the matcher (`run_server_multi`); `None` = memory-only gate.
    pub nonce_state_path: Option<std::path::PathBuf>,
    /// The settlement operator's secp256k1 secret — when set, batch
    /// envelopes are signed (EIP-712 v1 layout) and the sender is
    /// the key-derived address, which is what the exchange's
    /// `settlement_operator` gate must be configured with. `None`
    /// produces unsigned envelopes — accepted only under the
    /// executor's `UnsignedTxPolicy::Allow` (devnet).
    pub settlement_key: Option<[u8; 32]>,
    /// Durable checkpoint file for the settlement lane's
    /// `{next_nonce, pending}` state — survives restarts so an
    /// in-flight batch is resolved rather than forgotten. `None`
    /// keeps the memory-only behavior (a restart mid-flight then
    /// relies on the executor's `executed_nonce` resync).
    pub settlement_outbox: Option<std::path::PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            binary_tcp_port: 36000,
            jsonrpc_port: 36001,
            fix_port: 36002,
            websocket_port: 36003,
            batch_interval_ms: 100,
            chain_id: crate::protocol::CHAIN_ID,
            nonce_state_path: None,
            settlement_key: None,
            settlement_outbox: None,
        }
    }
}

/// Build the batch settler from a sealer + server config — shared
/// by all three server entry points so signing, confirmation, and
/// the durable outbox are wired identically on every path.
fn build_settler(
    sealer: Arc<dyn crate::BatchSealer>,
    submitter: Arc<dyn TxSubmitter>,
    confirmer: Arc<dyn TxConfirmer>,
    config: &ServerConfig,
    sender: primitives::Address,
) -> Arc<BatchSettler> {
    let mut settler =
        BatchSettler::new(sealer, submitter, confirmer, config.batch_interval_ms, sender, 0);
    if let Some(key) = config.settlement_key {
        settler = settler.with_signing(key, config.chain_id);
    }
    if let Some(path) = &config.settlement_outbox {
        settler = settler.with_outbox(path.clone());
    }
    Arc::new(settler)
}

/// Default number of ring pairs for the ring-backed server.
const DEFAULT_RING_COUNT: usize = 256;

/// Default ring capacity (items per ring; each item is one batch).
const DEFAULT_RING_CAPACITY: usize = 8192;

/// Run all protocol servers concurrently (mutex path). This is the
/// compatibility entry point — for new deployments use
/// [`run_server_ring`], which routes ALL protocols through the
/// lock-free SPSC rings while sharing THE SAME single order book.
///
/// # Arguments
/// - `matcher`: the shared matching server.
/// - `submitter`: the consensus tx submitter (for batch settlement).
/// - `confirmer`: the finalized-outcome oracle (usually the same
///   executor handle as `submitter`).
/// - `config`: server configuration (ports, batch interval,
///   settlement key/outbox).
/// - `sender`: the matcher operator's address (for settlement txs —
///   overridden by the key-derived address when
///   `config.settlement_key` is set).
pub async fn run_server(
    matcher: Arc<SharedMatcher>,
    submitter: Arc<dyn TxSubmitter>,
    confirmer: Arc<dyn TxConfirmer>,
    config: ServerConfig,
    sender: primitives::Address,
) {
    // Start the batch settler. `Arc<SharedMatcher>` coerces to
    // `Arc<dyn BatchSealer>` (the mutex-seal implementation).
    let sealer: Arc<dyn crate::BatchSealer> = Arc::clone(&matcher) as Arc<dyn crate::BatchSealer>;
    let settler = build_settler(sealer, submitter, confirmer, &config, sender);
    let settler_clone = Arc::clone(&settler);
    tokio::spawn(async move {
        settler_clone.run().await;
    });

    // Start the protocol servers.
    let tcp_matcher = Arc::clone(&matcher);
    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = run_binary_tcp_server(tcp_matcher, config.binary_tcp_port).await {
            eprintln!("binary TCP server error: {e}");
        }
    });

    let jsonrpc_matcher = Arc::clone(&matcher);
    let jsonrpc_handle = tokio::spawn(async move {
        if let Err(e) = run_jsonrpc_tcp_server(jsonrpc_matcher, config.jsonrpc_port).await {
            eprintln!("JSON-RPC server error: {e}");
        }
    });

    let fix_matcher = Arc::clone(&matcher);
    let fix_handle = tokio::spawn(async move {
        if let Err(e) = run_fix_server(fix_matcher, config.fix_port).await {
            eprintln!("FIX server error: {e}");
        }
    });

    let ws_matcher = Arc::clone(&matcher);
    let ws_handle = tokio::spawn(async move {
        if let Err(e) = run_websocket_server(ws_matcher, config.websocket_port).await {
            eprintln!("WebSocket server error: {e}");
        }
    });

    // Wait for all servers (they run forever).
    let _ = tokio::join!(tcp_handle, jsonrpc_handle, fix_handle, ws_handle);
}

/// Run all protocol servers concurrently with the lock-free SPSC
/// ring matcher as the production order path. This is the
/// recommended entry point.
///
/// # One order book
///
/// The `server` passed in is moved to the ring matcher's owner
/// thread — it is THE single order book. ALL protocols (binary TCP,
/// JSON-RPC, FIX, WebSocket) submit through the rings to this one
/// book, and the batch settler seals from the same book via the
/// control channel. There is never a second book.
///
/// # Arguments
/// - `server`: the funded matching server (moved to the owner thread).
/// - `submitter`: the consensus tx submitter (for batch settlement).
/// - `confirmer`: the finalized-outcome oracle.
/// - `config`: server configuration (ports, batch interval,
///   settlement key/outbox).
/// - `sender`: the matcher operator's address (for settlement txs).
pub async fn run_server_ring(
    server: MatchingServer,
    submitter: Arc<dyn TxSubmitter>,
    confirmer: Arc<dyn TxConfirmer>,
    config: ServerConfig,
    sender: primitives::Address,
) {
    // The ring matcher owns the server (and thus the one book).
    let ring = Arc::new(crate::RingMatcher::new(server, DEFAULT_RING_COUNT, DEFAULT_RING_CAPACITY));
    // Shared lease-scan hint: every request across ALL protocols
    // starts its free-ring search at a different index, so load
    // spreads across rings. Response isolation comes from the
    // exclusive ring lease — the counter only biases the scan.
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Batch settler seals from the same book via the control channel.
    let sealer: Arc<dyn crate::BatchSealer> = Arc::clone(&ring) as Arc<dyn crate::BatchSealer>;
    let settler = build_settler(sealer, submitter, confirmer, &config, sender);
    let settler_clone = Arc::clone(&settler);
    tokio::spawn(async move {
        settler_clone.run().await;
    });

    // Start the protocol servers, all routed through the rings.
    // The dummy SharedMatcher is the mutex-path fallback — it is
    // never touched when the ring is present, but the API requires
    // it. All actual order flow goes through the ring to THE one book.
    let dummy = Arc::new(SharedMatcher::new(MatchingServer::new(
        trading::MarketConfig {
            market_id: 0,
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
            max_resting: 1 << 16,
        },
        1,
    )));

    let tcp_handle = {
        let matcher = Arc::clone(&dummy);
        let ring = Arc::clone(&ring);
        let counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            if let Err(e) =
                run_binary_tcp_server_ring(matcher, ring, counter, config.binary_tcp_port).await
            {
                eprintln!("binary TCP server error: {e}");
            }
        })
    };

    let jsonrpc_handle = {
        let matcher = Arc::clone(&dummy);
        let ring = Arc::clone(&ring);
        let counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            if let Err(e) =
                run_jsonrpc_tcp_server_ring(matcher, ring, counter, config.jsonrpc_port).await
            {
                eprintln!("JSON-RPC server error: {e}");
            }
        })
    };

    let fix_handle = {
        let matcher = Arc::clone(&dummy);
        let ring = Arc::clone(&ring);
        let counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            if let Err(e) = run_fix_server_ring(matcher, ring, counter, config.fix_port).await {
                eprintln!("FIX server error: {e}");
            }
        })
    };

    let ws_handle = {
        let matcher = Arc::clone(&dummy);
        let ring = Arc::clone(&ring);
        let counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            if let Err(e) =
                run_websocket_server_ring(matcher, ring, counter, config.websocket_port).await
            {
                eprintln!("WebSocket server error: {e}");
            }
        })
    };

    // Wait for all servers (they run forever).
    let _ = tokio::join!(tcp_handle, jsonrpc_handle, fix_handle, ws_handle);
}

// ── Multi-market parallel server ─────────────────────────────────────

/// Submit a batch of orders through the multi-market parallel matcher.
/// Splits the batch by market, sends each sub-batch to the correct
/// market worker, and collects responses. Preserves the original
/// order by tagging each response with its index.
fn submit_batch_multi(
    matcher: &crate::MultiMarketMatcher,
    orders: Vec<OrderRequest>,
) -> Vec<OrderResponse> {
    if orders.is_empty() {
        return Vec::new();
    }
    // `submit_batch` authenticates every request on this thread,
    // routes each verified order by its own `market` field (single-
    // and mixed-market batches both), and merges responses at their
    // original positions — no transport-side grouping needed.
    matcher.submit_batch(orders)
}

/// Submit a single order through the multi-market parallel matcher.
fn submit_one_multi(matcher: &crate::MultiMarketMatcher, req: OrderRequest) -> OrderResponse {
    matcher.submit_one(req)
}

/// Run a binary TCP server backed by the multi-market parallel
/// matcher. Each connection reads orders and routes them to the
/// correct market worker.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_binary_tcp_server_multi(
    matcher: Arc<crate::MultiMarketMatcher>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("binary TCP (multi-market) server listening on 127.0.0.1:{port}");
    loop {
        let (socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        tokio::spawn(handle_connection_multi(socket, matcher));
    }
}

/// Handle a single TCP connection on the multi-market path.
async fn handle_connection_multi(
    mut socket: tokio::net::TcpStream,
    matcher: Arc<crate::MultiMarketMatcher>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut header = [0u8; 4];
    loop {
        if socket.read_exact(&mut header).await.is_err() {
            break;
        }
        if header[3] == crate::protocol::BATCH_FLAG {
            let mut count_buf = [0u8; 4];
            if socket.read_exact(&mut count_buf).await.is_err() {
                break;
            }
            let count = u32::from_le_bytes(count_buf) as usize;
            // HIGH fix: bound-check `count` BEFORE allocating (OOM
            // prevention — same as the async path above).
            if count > crate::protocol::MAX_BATCH_SIZE {
                break; // reject oversized batch
            }
            let entries_len = count * crate::protocol::BATCH_ENTRY_SIZE;
            let mut entries = vec![0u8; entries_len];
            if socket.read_exact(&mut entries).await.is_err() {
                break;
            }
            let mut full_msg = Vec::with_capacity(8 + entries_len);
            full_msg.extend_from_slice(&header);
            full_msg.extend_from_slice(&count_buf);
            full_msg.extend_from_slice(&entries);
            let Some(orders) = crate::protocol::decode_batch_request(&full_msg) else {
                let resp = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&resp)).await;
                continue;
            };
            let responses = submit_batch_multi(&matcher, orders);
            let batch_resp = crate::protocol::encode_batch_response(&responses);
            if socket.write_all(&batch_resp).await.is_err() {
                break;
            }
        } else if is_action_request(&header) {
            // Action request (cancel/amend/replace).
            let mut rest = [0u8; crate::protocol::ACTION_REQUEST_SIZE - 4];
            if socket.read_exact(&mut rest).await.is_err() {
                break;
            }
            let mut full = Vec::with_capacity(crate::protocol::ACTION_REQUEST_SIZE);
            full.extend_from_slice(&header);
            full.extend_from_slice(&rest);
            let Some(action_req) = decode_action_request(&full) else {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            };
            if !crate::protocol::verify_action_with_chain_id(&action_req, matcher.chain_id()) {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::BadSignature);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            }
            // The wire `ActionRequest` is routed intact — the market
            // worker authenticates it before dispatching.
            let action_resp = matcher.submit_action(&action_req);
            if socket.write_all(&encode_response(&action_resp)).await.is_err() {
                break;
            }
        } else {
            let mut rest = [0u8; crate::protocol::REQUEST_SIZE - 4];
            if socket.read_exact(&mut rest).await.is_err() {
                break;
            }
            let mut full = Vec::with_capacity(crate::protocol::REQUEST_SIZE);
            full.extend_from_slice(&header);
            full.extend_from_slice(&rest);
            let Some(req) = decode_request(&full) else {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            };
            let order_resp = submit_one_multi(&matcher, req);
            if socket.write_all(&encode_response(&order_resp)).await.is_err() {
                break;
            }
        }
    }
}

/// Run a JSON-RPC server backed by the multi-market parallel matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_jsonrpc_tcp_server_multi(
    matcher: Arc<crate::MultiMarketMatcher>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("JSON-RPC (multi-market) server listening on 127.0.0.1:{port}");
    loop {
        let (mut socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = socket.split();
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let req: serde_json::Value = if let Ok(v) = serde_json::from_str(&line) {
                    v
                } else {
                    let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}
"#).await;
                    continue;
                };
                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let params = req.get("params").cloned().unwrap_or(serde_json::Value::Null);

                if method == crate::jsonrpc::MANAGE_ORDER {
                    let Some(action_req) = crate::jsonrpc::parse_jsonrpc_action(&params) else {
                        let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":null}
"#).await;
                        continue;
                    };
                    if !crate::protocol::verify_action_with_chain_id(
                        &action_req,
                        matcher.chain_id(),
                    ) {
                        let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"bad signature"},"id":null}
"#).await;
                        continue;
                    }
                    // The wire `ActionRequest` is routed intact — the
                    // market worker authenticates it before dispatch.
                    let resp = matcher.submit_action(&action_req);
                    let result = crate::jsonrpc::format_jsonrpc_response(&resp);
                    let response =
                        serde_json::json!({ "jsonrpc": "2.0", "result": result, "id": id });
                    let mut response_line = serde_json::to_string(&response).unwrap_or_default();
                    response_line.push('\n');
                    let _ = writer.write_all(response_line.as_bytes()).await;
                    continue;
                }

                if method != "oxide_placeOrder" {
                    let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":null}
"#).await;
                    continue;
                }
                let Some(order_req) = crate::jsonrpc::parse_jsonrpc_order(&params) else {
                    let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":null}
"#).await;
                    continue;
                };
                let resp = submit_one_multi(&matcher, order_req);
                let result = crate::jsonrpc::format_jsonrpc_response(&resp);
                let response = serde_json::json!({ "jsonrpc": "2.0", "result": result, "id": id });
                let mut response_line = serde_json::to_string(&response).unwrap_or_default();
                response_line.push('\n');
                let _ = writer.write_all(response_line.as_bytes()).await;
            }
        });
    }
}

/// Run a FIX server backed by the multi-market parallel matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_fix_server_multi(
    matcher: Arc<crate::MultiMarketMatcher>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("FIX (multi-market) server listening on 127.0.0.1:{port}");
    loop {
        let (mut socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let text = String::from_utf8_lossy(&buf[..n]);
                let cl_ord_id = text
                    .split('\x01')
                    .find_map(|f| f.strip_prefix("11=").map(str::to_string))
                    .unwrap_or_else(|| "UNKNOWN".to_string());
                let msg_type = text
                    .split('\x01')
                    .find_map(|f| f.strip_prefix("35=").map(str::to_string))
                    .unwrap_or_default();
                if msg_type == crate::fix::MSG_TYPE_CANCEL
                    || msg_type == crate::fix::MSG_TYPE_CANCEL_REPLACE
                {
                    let action_req = if msg_type == crate::fix::MSG_TYPE_CANCEL {
                        crate::fix::parse_fix_cancel(&text)
                    } else {
                        crate::fix::parse_fix_cancel_replace(&text)
                    };
                    let Some(action_req) = action_req else {
                        // Malformed action — answer with a rejected
                        // ExecutionReport instead of dropping the
                        // message: a client blocking on a response
                        // per message must never be wedged by a
                        // parse failure.
                        let resp = OrderResponse::rejected(RejectReason::Malformed);
                        let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                        let _ = socket.write_all(report.as_bytes()).await;
                        continue;
                    };
                    if !crate::protocol::verify_action_with_chain_id(
                        &action_req,
                        matcher.chain_id(),
                    ) {
                        let resp = OrderResponse::rejected(RejectReason::BadSignature);
                        let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                        let _ = socket.write_all(report.as_bytes()).await;
                        continue;
                    }
                    // The wire `ActionRequest` is routed intact — the
                    // market worker authenticates it before dispatch.
                    let resp = matcher.submit_action(&action_req);
                    let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                    let _ = socket.write_all(report.as_bytes()).await;
                    continue;
                }
                let Some(req) = crate::fix::parse_fix_order(&text) else {
                    // Malformed order — answer with a rejected
                    // ExecutionReport instead of dropping the
                    // message: a client blocking on a response per
                    // message must never be wedged by a parse
                    // failure.
                    let resp = OrderResponse::rejected(RejectReason::Malformed);
                    let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                    let _ = socket.write_all(report.as_bytes()).await;
                    continue;
                };
                let resp = submit_one_multi(&matcher, req);
                let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                let _ = socket.write_all(report.as_bytes()).await;
            }
        });
    }
}

/// Run a WebSocket server backed by the multi-market parallel matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_websocket_server_multi(
    matcher: Arc<crate::MultiMarketMatcher>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("WebSocket (multi-market) server listening on 127.0.0.1:{port}");
    loop {
        let (socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            use tokio_tungstenite::tungstenite::Message;
            let ws_stream = match tokio_tungstenite::accept_async(socket).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("WebSocket handshake failed: {e}");
                    return;
                }
            };
            let (mut ws_sender, mut ws_receiver) = ws_stream.split();
            while let Some(msg_result) = ws_receiver.next().await {
                let Ok(msg) = msg_result else { break };
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                let Some(req) = crate::ws::parse_ws_order(&text) else {
                    let _ =
                        ws_sender.send(Message::Text(r#"{"error":"invalid order"}"#.into())).await;
                    continue;
                };
                let resp = submit_one_multi(&matcher, req);
                let response = crate::ws::format_ws_response(&resp, 0);
                if ws_sender.send(Message::Text(response.into())).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Run all protocol servers concurrently with the multi-market
/// parallel matcher. This is the production entry point for
/// high-throughput multi-market deployments: one worker thread per
/// market, shared sharded balances, all four protocols routed by
/// `OrderRequest.market`.
///
/// # Arguments
/// - `configs`: one `MarketConfig` per market.
/// - `balances`: the shared sharded balance cache (fund accounts
///   before calling this).
/// - `submitter`: the consensus tx submitter (for batch settlement).
/// - `confirmer`: the finalized-outcome oracle.
/// - `config`: server configuration (ports, batch interval,
///   settlement key/outbox).
/// - `sender`: the matcher operator's address (for settlement txs).
pub async fn run_server_multi(
    configs: Vec<MarketConfig>,
    balances: Arc<crate::ShardedBalanceCache>,
    submitter: Arc<dyn TxSubmitter>,
    confirmer: Arc<dyn TxConfirmer>,
    config: ServerConfig,
    sender: primitives::Address,
) {
    let matcher = Arc::new(crate::MultiMarketMatcher::with_options(
        configs,
        balances,
        Arc::new(crate::wall_clock_ms),
        config.chain_id,
        config.nonce_state_path.clone(),
    ));

    // Batch settler seals from ALL markets via the control channel.
    let sealer: Arc<dyn crate::BatchSealer> = Arc::clone(&matcher) as Arc<dyn crate::BatchSealer>;
    let settler = build_settler(sealer, submitter, confirmer, &config, sender);
    let settler_clone = Arc::clone(&settler);
    tokio::spawn(async move {
        settler_clone.run().await;
    });

    let tcp_handle = {
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            if let Err(e) = run_binary_tcp_server_multi(matcher, config.binary_tcp_port).await {
                eprintln!("binary TCP server error: {e}");
            }
        })
    };
    let jsonrpc_handle = {
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            if let Err(e) = run_jsonrpc_tcp_server_multi(matcher, config.jsonrpc_port).await {
                eprintln!("JSON-RPC server error: {e}");
            }
        })
    };
    let fix_handle = {
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            if let Err(e) = run_fix_server_multi(matcher, config.fix_port).await {
                eprintln!("FIX server error: {e}");
            }
        })
    };
    let ws_handle = {
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            if let Err(e) = run_websocket_server_multi(matcher, config.websocket_port).await {
                eprintln!("WebSocket server error: {e}");
            }
        })
    };
    let _ = tokio::join!(tcp_handle, jsonrpc_handle, fix_handle, ws_handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchingServer, OrderRequest};
    use primitives::fixed::{Price, Qty};
    use trading::{MarketConfig, OrderType, Side, TimeInForce};

    fn cfg() -> MarketConfig {
        MarketConfig {
            market_id: 0,
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
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
    fn signed_req(
        secret: &crypto::ed25519::Ed25519SecretKey,
        side: Side,
        nonce: u64,
    ) -> OrderRequest {
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
        outcomes:
            std::sync::Mutex<std::collections::HashMap<primitives::Hash, executor::TxOutcome>>,
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
                events: vec![],
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
                ],
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
        let ring = std::sync::Arc::new(crate::RingMatcher::new(server, 1, 64));
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
                let responses = submit_batch_ring(&ring, &counter, reqs).await;
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
}
