//! Batch-settlement pipeline: the bridge between off-chain
//! matching and on-chain settlement.
//!
//! `BatchSettler` periodically seals the matcher's fill buffer and
//! submits a settlement envelope through the [`TxSubmitter`] port;
//! [`TxConfirmer`] is the finality oracle that reports which
//! submissions the chain actually executed. The outbox
//! ([`SettlementOutbox`]) checkpoints the in-flight batch so a
//! restart resumes the pending envelope instead of dead-lettering
//! it — the durability boundary for the settlement lane.
//!
//! Split from `server.rs` around the submission invariant: the
//! settler is the ONLY writer of settlement envelopes, and every
//! outcome (submitted / confirmed / rejected-leg / failed-pair /
//! batch-rejected / dead-lettered) is accounted in
//! [`SettleReport`] — the off-chain cache already reflects fills at
//! `seal_batch` time, so an unlanded envelope is divergence, never
//! a no-op.

use std::sync::Arc;
use std::time::Duration;

use exchange::BatchFillEntry;
use primitives::fixed::{Price, Qty};
use types::TxBytes;

/// The settlement lane's failure classes — a typed boundary so a
/// caller (or an operator alert) can tell *what kind* of failure
/// stopped a tick instead of matching on message text.
///
/// Each variant names the state effect the caller must assume:
/// - [`Submission`](Self::Submission): the envelope stayed pending —
///   the lane retries next tick; nothing settled, nothing lost.
/// - [`AggregateOverflow`](Self::AggregateOverflow): the sealed fills
///   were NOT cleared — the sealer re-seals them next tick; a code
///   bug or impossible volume, not a transient.
/// - [`Sign`](Self::Sign): envelope encoding failed before
///   submission — nothing was sent, the nonce was not consumed.
#[derive(Debug)]
pub enum SettleError {
    /// The mempool rejected the envelope. The reason is opaque port
    /// text — the lane never branches on it, only logs it.
    Submission(String),
    /// A fill-qty sum exceeded `u64::MAX` during aggregation —
    /// unreachable at real volumes; fail loudly rather than clamp.
    AggregateOverflow,
    /// secp256k1 signing failed (malformed key material — a config
    /// bug, not a transient).
    Sign(String),
}

impl std::fmt::Display for SettleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Submission(e) => write!(f, "mempool rejected envelope: {e}"),
            Self::AggregateOverflow => write!(f, "fill qty aggregation overflow"),
            Self::Sign(e) => write!(f, "sign settlement envelope: {e}"),
        }
    }
}

impl std::error::Error for SettleError {}

/// Why a settlement-outbox checkpoint failed to decode — the
/// structural violations are enumerated so `with_outbox`'s
/// fail-closed panic message distinguishes "disk error" from
/// "corrupt/hostile bytes".
#[derive(Debug)]
pub(crate) enum OutboxError {
    /// The file could not be read (permissions, disappearing fs).
    Io(std::io::Error),
    /// The bytes violate the checkpoint format — each payload
    /// names the violated rule.
    Corrupt(String),
}

impl std::fmt::Display for OutboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "read failed: {e}"),
            Self::Corrupt(e) => write!(f, "corrupt checkpoint: {e}"),
        }
    }
}

impl std::error::Error for OutboxError {}

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
pub(crate) struct PendingBatch {
    /// The full encoded tx envelope (nonce baked in).
    pub(crate) envelope: Vec<u8>,
    /// `Domain::Transaction` hash of `envelope` — the confirmer key.
    pub(crate) tx_hash: primitives::Hash,
    /// Aggregated pair count (reported when the batch confirms).
    pub(crate) pair_count: usize,
    /// Failed submission attempts so far.
    pub(crate) attempts: u32,
    /// Whether the last `submit_tx` returned `Ok`. `false` means the
    /// envelope is awaiting (re)submission — a fresh outbox restore
    /// also lands here, since the pool's copy may not have survived.
    pub(crate) submitted: bool,
    /// Ticks spent waiting for an outcome with none recorded. At
    /// [`RESUBMIT_AFTER_TICKS`] the envelope is resubmitted — the
    /// pooled copy may have been evicted without ever executing.
    pub(crate) wait_ticks: u32,
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
pub(crate) const MAX_PENDING_RETRIES: u32 = 60;

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
pub(crate) const RESUBMIT_AFTER_TICKS: u32 = 100;

/// Whether a pre-execution skip can still land if the tx stays
/// pooled. `GasLimit`/`FeeCharge` resolve themselves (the next block
/// has a fresh budget; a later funding fixes the charge). Everything
/// else is a deterministic property of the envelope bytes — the same
/// tx can never pass that gate.
pub(crate) fn is_retryable_skip(reason: executor::TxSkipReason) -> bool {
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
pub(crate) fn aggregate_fills(
    fills: &[crate::SettledFill],
) -> Result<Vec<BatchFillEntry>, SettleError> {
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
                *q = Qty(q.0.checked_add(f.qty.0).ok_or(SettleError::AggregateOverflow)?);
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
pub(crate) struct SigningConfig {
    /// The operator's 32-byte secret key — `Zeroizing` so a dropped
    /// or reconfigured settler doesn't leave the secret in freed
    /// heap memory.
    pub(crate) privkey: zeroize::Zeroizing<[u8; 32]>,
    /// EIP-712 chain ID bound into the signature.
    pub(crate) chain_id: u64,
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
    pub(crate) sealer: Arc<dyn crate::BatchSealer>,
    pub(crate) submitter: Arc<dyn TxSubmitter>,
    /// The finalized-outcome oracle — the difference between
    /// "accepted into the mempool" and "executed on-chain".
    pub(crate) confirmer: Arc<dyn TxConfirmer>,
    pub(crate) interval: Duration,
    /// The sender address for settlement txs (the matcher operator).
    /// When `signing` is configured this is the key-derived address
    /// — the three views of identity (declared sender, recovered
    /// signer, exchange operator) can never diverge.
    pub(crate) sender: primitives::Address,
    /// Optional envelope signing (EIP-712 + secp256k1, executor v1
    /// layout). `None` produces v0 unsigned envelopes — fine for the
    /// devnet `UnsignedTxPolicy::Allow`, rejected under `Reject`.
    pub(crate) signing: Option<SigningConfig>,
    /// Next settlement nonce — advanced ONLY when the confirmer
    /// proves the previous batch executed (or was terminally
    /// skipped), never at submit time. It is resynced from
    /// `confirmer.executed_nonce` on every resolution, so restart
    /// drift and dead-lettered batches cannot gap the sequence.
    pub(crate) nonce: std::sync::atomic::AtomicU64,
    /// The in-flight envelope awaiting its execution outcome. At
    /// most one — see the struct doc.
    pub(crate) pending: std::sync::Mutex<Option<PendingBatch>>,
    /// Durable checkpoint of `{next_nonce, pending}` — survives a
    /// matcher restart so an in-flight batch is resolved, not
    /// forgotten. `None` keeps the legacy memory-only behavior
    /// (a restart mid-flight then falls back to the executor's
    /// `executed_nonce` resync on the next resolution).
    pub(crate) outbox: std::sync::Mutex<Option<SettlementOutbox>>,
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
        self.signing = Some(SigningConfig { privkey: zeroize::Zeroizing::new(privkey), chain_id });
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
    pub fn settle_now(&self) -> Result<SettleReport, SettleError> {
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
                            return Err(SettleError::Submission(e));
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
                return Err(SettleError::Submission(e));
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
    ) -> Result<Vec<u8>, SettleError> {
        let signed = self.signing.is_some();
        let mut envelope = Vec::with_capacity(37 + usize::from(signed) * 65 + module_payload.len());
        envelope.extend_from_slice(&self.sender.0);
        envelope.extend_from_slice(&nonce.to_le_bytes());
        envelope.extend_from_slice(&fee.to_le_bytes());
        if let Some(signing) = &self.signing {
            let sig = crypto::eip712::sign_tx(
                &signing.privkey[..],
                signing.chain_id,
                &self.sender,
                nonce,
                fee,
                framework::module_id::EXCHANGE,
                module_payload,
            )
            .map_err(|e| SettleError::Sign(format!("{e:?}")))?;
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
pub(crate) struct SettlementOutbox {
    /// Checkpoint file path (`<path>.tmp` is the write scratch).
    pub(crate) path: std::path::PathBuf,
}

/// The decoded outbox state.
pub(crate) struct SettlementOutboxState {
    /// Next nonce the settler will seal with.
    pub(crate) next_nonce: u64,
    /// The in-flight batch, if one was pending at checkpoint time.
    pub(crate) pending: Option<PendingBatch>,
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
    fn load(path: &std::path::Path) -> Result<SettlementOutboxState, OutboxError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(SettlementOutboxState { next_nonce: 0, pending: None });
            }
            Err(e) => return Err(OutboxError::Io(e)),
        };
        // Header: magic(4) + version(4) + next_nonce(8) +
        // pending_flag(1) = 17 bytes.
        if bytes.len() < 17 {
            return Err(OutboxError::Corrupt(format!("truncated header ({} bytes)", bytes.len())));
        }
        if &bytes[0..4] != Self::MAGIC {
            return Err(OutboxError::Corrupt("bad magic".to_string()));
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or_default());
        if version != Self::VERSION {
            return Err(OutboxError::Corrupt(format!("unsupported version {version}")));
        }
        let next_nonce = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or_default());
        let has_pending = bytes[16] != 0;
        if !has_pending {
            if bytes.len() != 17 {
                return Err(OutboxError::Corrupt(format!(
                    "trailing bytes without pending: {}",
                    bytes.len()
                )));
            }
            return Ok(SettlementOutboxState { next_nonce, pending: None });
        }
        // Pending section: envelope_len(4) + envelope + pair_count(8)
        // + attempts(4) + submitted(1).
        if bytes.len() < 21 {
            return Err(OutboxError::Corrupt(format!(
                "truncated pending header ({} bytes)",
                bytes.len()
            )));
        }
        let env_len = u32::from_le_bytes(bytes[17..21].try_into().unwrap_or_default()) as usize;
        if env_len > Self::MAX_ENVELOPE_LEN {
            return Err(OutboxError::Corrupt(format!("envelope len {env_len} exceeds bound")));
        }
        let end = 21 + env_len;
        if bytes.len() != end + 13 {
            return Err(OutboxError::Corrupt(format!(
                "size mismatch: {} bytes, expected {}",
                bytes.len(),
                end + 13
            )));
        }
        let envelope = bytes[21..end].to_vec();
        let pair_count =
            usize::try_from(u64::from_le_bytes(bytes[end..end + 8].try_into().unwrap_or_default()))
                .map_err(|_| OutboxError::Corrupt("pair count overflows usize".to_string()))?;
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
