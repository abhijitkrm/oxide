//! `AppInterface` adapter — the consensus↔executor boundary.
//!
//! Split from `lib.rs` around the port invariant: this impl is
//! the *only* surface consensus calls — mempool admission,
//! proposal building, block finalize, and snapshot hooks. Keeping
//! it in one file makes it auditable that everything consensus
//! can drive is listed here and nothing else leaks across the
//! boundary.

use super::{
    AcceptedTx, AppInterface, CommitAck, EXEC_LANE_DEPTH, Executor, FinalizedBlock, HashMap,
    Height, InsertRetained, MODULE_ID_OFFSET, MempoolAck, Proposal, StateAttestation, TxBytes,
    Verdict, is_signed_envelope, module_payload, parse_module_id, parse_tx_context,
};

impl AppInterface for Executor {
    fn ingest_tx(&self, tx: TxBytes) -> MempoolAck {
        // A4: route mempool admission through `Module::validate`.
        // Before storing the tx in the mempool, we parse the envelope,
        // find the target module, and call its `validate` method. This
        // rejects invalid txs (bad signature, wrong chain ID, bad
        // nonce, insufficient balance) before they enter the pool —
        // keeping the pool clean and the execution path fast.
        let bytes = tx.as_bytes();
        let Some(ctx) = parse_tx_context(bytes) else {
            return MempoolAck::Rejected { reason: "malformed: tx context".to_string() };
        };
        // H4 fix: replay protection. Reject txs whose nonce has
        // already been executed. Without this, a tx removed from the
        // mempool after block selection can be re-submitted and
        // re-executed — a replay attack.
        {
            let executed = primitives::sync::lock_state(&self.executed_nonce);
            let next_expected = executed.map.get(&ctx.sender).copied().unwrap_or(0);
            if ctx.nonce < next_expected {
                return MempoolAck::Rejected {
                    reason: format!("replay: nonce {} < next expected {next_expected}", ctx.nonce),
                };
            }
        }
        // Nonce u64::MAX is reserved: executing it would wrap the
        // next-expected counter (MAX + 1 → 0) and reopen the sender's
        // entire nonce range to replay. Rejecting it at admission
        // keeps `expected + 1` in `group_block_txs` overflow-free —
        // no honest account can exhaust 2^64 − 1 nonces anyway.
        if ctx.nonce == u64::MAX {
            return MempoolAck::Rejected { reason: "nonce `u64::MAX` is reserved".to_string() };
        }
        let Some(module_id) = parse_module_id(bytes) else {
            return MempoolAck::Rejected { reason: "malformed: no module ID".to_string() };
        };
        let Some(module) = self.modules[module_id as usize].as_ref() else {
            return MempoolAck::Rejected { reason: format!("unknown module {module_id}") };
        };
        // Envelope authentication: for modules that don't recover the
        // sender inside their own payload (everything but the EVM),
        // a signed envelope's secp256k1 signature must recover to the
        // declared sender — otherwise `ctx.sender` is just a claim.
        // Unsigned txs are admitted or rejected per
        // `unsigned_tx_policy`. The returned bool records whether a
        // signature actually verified — it decides what the preverify
        // cache may claim below.
        let envelope_verified =
            match self.check_envelope_auth(bytes, &ctx, module_id, module.as_ref(), None) {
                Ok(v) => v,
                Err(reason) => return MempoolAck::Rejected { reason: reason.to_string() },
            };
        let payload = module_payload(bytes);
        // Authenticate the module payload ONCE: for self-
        // authenticating modules (the EVM — the payload carries its
        // own secp256k1 signature) `preverify_batch` is the signature
        // check, and the recovered sender feeds
        // `validate_authenticated` so the stateful gates run without
        // a second recovery. The previous order — `validate`
        // recovering internally, then `preverify_batch` recovering
        // again for the cache — paid ~30 µs of secp256k1 twice per
        // admitted tx on the caller's thread, which for gossip and
        // injector traffic is the consensus pump.
        //
        // `msgs` must outlive `preverify_result` — the returned
        // `PreverifiedTx` borrows the payload slice.
        let msgs = [payload];
        let preverify_result = module.preverify_batch(&msgs);
        let recovered_sender = preverify_result[0]
            .as_ref()
            .ok()
            .and_then(|pv| (pv.sender != [0u8; 20]).then_some(pv.sender));
        if module.authenticates_sender() {
            // A failed preverify means the payload's own signature
            // did not recover — the same verdict `validate` returns
            // on these bytes, so reject before the stateful gates.
            let Some(sender) = recovered_sender else {
                return MempoolAck::Rejected { reason: "validate: malformed".to_string() };
            };
            if let Err(e) = module.validate_authenticated(&ctx, payload, &sender) {
                return MempoolAck::Rejected { reason: format!("validate: {e:?}") };
            }
        } else if let Err(e) = module.validate(&ctx, payload) {
            return MempoolAck::Rejected { reason: format!("validate: {e:?}") };
        }

        // Cache the authenticated sender so block execution skips
        // recovery entirely — the execution hot path then sees only
        // RLP decode + chain ID check.
        // A cache entry asserts "a trustworthy sender exists for this
        // exact tx hash" — `check_envelope_auth` treats a hit as
        // already-verified, and `execute_block` routes all-cached
        // groups through the preverified path. We therefore only
        // cache a sender that was actually authenticated:
        //
        // - a non-zero sender from `preverify_batch` means the module
        //   verified the payload itself (EVM signature recovery);
        // - otherwise, if the envelope signature verified, `ctx.sender`
        //   is the authenticated sender — cache it so the entry is
        //   honest rather than a zero placeholder;
        // - an admitted-unsigned tx with a zero placeholder sender
        //   has nothing verified to cache — skipping it keeps
        //   `all_cached` false, so the group takes the plain
        //   `handle_batch` path (correct per-tx contexts).
        //
        // Compute the cacheable entry now but insert it only if the
        // bounded intake accepts the tx below — a cache populated
        // ahead of admission grew on *rejected* submissions (an
        // intake-full flood filled it with senders for txs the pool
        // never held), the one intake-side map that wasn't bounded
        // by any capacity check. The hash is taken now because `tx`
        // moves into the channel below.
        let cacheable =
            recovered_sender.or_else(|| envelope_verified.then_some(ctx.sender.0)).map(|sender| {
                (crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, bytes), sender)
            });

        // Push to the bounded intake ring. The mempool submission
        // is deferred to `prepare_proposal` — this eliminates the
        // per-tx mempool lock on the ingestion hot path.
        //
        // We use `try_send` (non-blocking) instead of `send` (blocking)
        // because a blocking send would deadlock if the intake channel
        // is full and no consumer is draining it. This happens when the
        // consensus pipeline stalls (e.g., during view changes) — the
        // intake fills up, `send` blocks waiting for a consumer, but the
        // consumer (the propose phase) can't run because the submission
        // thread holds the test's main loop. `try_send` breaks the
        // deadlock: a full intake returns `Rejected` (backpressure)
        // instead of blocking forever. The caller can retry later.
        match self.mempool_intake_tx.try_send(tx) {
            Ok(()) => {
                if let Some((tx_hash, sender)) = cacheable {
                    // Only the sender is cached — the payload is
                    // re-borrowed from the block's tx at execution
                    // time.
                    primitives::sync::lock_state(&self.preverify_cache).insert(tx_hash, sender);
                }
                MempoolAck::Accepted
            }
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                MempoolAck::Rejected { reason: "intake ring full".to_string() }
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                MempoolAck::Rejected { reason: "intake ring closed".to_string() }
            }
        }
    }

    /// Phase E: batch mempool intake. Acquires the mempool lock once
    /// for the entire batch, amortizing the per-tx lock overhead.
    /// Validation and preverify are still per-tx (they call into
    /// module code), but the mempool insertion is batched.
    fn ingest_tx_batch(&self, txs: Vec<TxBytes>) -> Vec<MempoolAck> {
        let mut results = Vec::with_capacity(txs.len());
        // Validate and preverify each tx, collecting the accepted
        // ones for batch submission to the mempool. Each entry
        // carries its index into `results` (the accepted vec is
        // filtered — position `i` here is not position `i` in the
        // caller's batch) and an optional preverified
        // `(tx_hash, sender)` that is cached only if the pool
        // accepts the tx.
        let mut accepted_txs: Vec<AcceptedTx> = Vec::with_capacity(txs.len());
        for tx in txs {
            let bytes = tx.as_bytes();
            let Some(ctx) = parse_tx_context(bytes) else {
                results.push(MempoolAck::Rejected { reason: "malformed: tx context".to_string() });
                continue;
            };
            // H4 fix: replay protection. Reject txs whose nonce has
            // already been executed. This check exists in `ingest_tx`
            // but was missing from the batch path — a replay attack
            // vector. A tx removed from the mempool after block
            // selection could be re-submitted via the batch path and
            // re-executed.
            {
                let executed = primitives::sync::lock_state(&self.executed_nonce);
                let next_expected = executed.map.get(&ctx.sender).copied().unwrap_or(0);
                if ctx.nonce < next_expected {
                    results.push(MempoolAck::Rejected {
                        reason: format!(
                            "replay: nonce {} < next expected {next_expected}",
                            ctx.nonce
                        ),
                    });
                    continue;
                }
            }
            // Same reserved-nonce rule as `ingest_tx`.
            if ctx.nonce == u64::MAX {
                results.push(MempoolAck::Rejected {
                    reason: "nonce `u64::MAX` is reserved".to_string(),
                });
                continue;
            }
            let Some(module_id) = parse_module_id(bytes) else {
                results
                    .push(MempoolAck::Rejected { reason: "malformed: no module ID".to_string() });
                continue;
            };
            let Some(module) = self.modules[module_id as usize].as_ref() else {
                results
                    .push(MempoolAck::Rejected { reason: format!("unknown module {module_id}") });
                continue;
            };
            // Envelope authentication — same rules as `ingest_tx`.
            // The bool records whether a signature verified, which
            // decides what the preverify cache may claim below.
            let envelope_verified =
                match self.check_envelope_auth(bytes, &ctx, module_id, module.as_ref(), None) {
                    Ok(v) => v,
                    Err(reason) => {
                        results.push(MempoolAck::Rejected { reason: reason.to_string() });
                        continue;
                    }
                };
            let payload = module_payload(bytes);
            // Same single-authentication order as `ingest_tx`:
            // `preverify_batch` recovers the module-level signer once
            // and `validate_authenticated` consumes it for the
            // stateful gates — no second secp256k1 recovery per tx.
            // `msgs` must outlive `preverify_result` — the returned
            // `PreverifiedTx` borrows the payload slice.
            let msgs = [payload];
            let preverify_result = module.preverify_batch(&msgs);
            let recovered_sender = preverify_result[0]
                .as_ref()
                .ok()
                .and_then(|pv| (pv.sender != [0u8; 20]).then_some(pv.sender));
            if module.authenticates_sender() {
                // A failed preverify means the payload's own
                // signature did not recover — the same verdict
                // `validate` would return on these bytes.
                let Some(sender) = recovered_sender else {
                    results
                        .push(MempoolAck::Rejected { reason: "validate: malformed".to_string() });
                    continue;
                };
                if let Err(e) = module.validate_authenticated(&ctx, payload, &sender) {
                    results.push(MempoolAck::Rejected { reason: format!("validate: {e:?}") });
                    continue;
                }
            } else if let Err(e) = module.validate(&ctx, payload) {
                results.push(MempoolAck::Rejected { reason: format!("validate: {e:?}") });
                continue;
            }
            // Only cache a sender that was actually authenticated —
            // the module's own recovery (non-zero) or the
            // envelope-verified `ctx.sender`. A zero placeholder on
            // an admitted-unsigned tx is skipped so `all_cached`
            // stays false and the group keeps the plain
            // `handle_batch` path. The entry is *computed* here but
            // cached only after the pool accepts the tx below —
            // caching ahead of bounded admission let rejected
            // submissions grow the map past every capacity check.
            let cacheable = recovered_sender
                .or_else(|| envelope_verified.then_some(ctx.sender.0))
                .map(|sender| {
                    (
                        crypto::hash::Hasher::hash_one(
                            crypto::hash::Domain::Transaction,
                            tx.as_bytes(),
                        ),
                        sender,
                    )
                });
            accepted_txs.push(AcceptedTx { result_idx: results.len(), cacheable, tx });
            results.push(MempoolAck::Accepted);
        }
        // Batch-submit all accepted txs to the mempool in one lock
        // acquisition.
        if !accepted_txs.is_empty() {
            let mut mempool = primitives::sync::lock_state(&self.mempool);
            // `result_idx` is the tx's index in the *caller's*
            // batch — `accepted_txs` is filtered, so a positional
            // `enumerate()` would write pool rejections into the
            // wrong result slots (acknowledging a rejected tx as
            // Accepted and re-rejecting an unrelated one — the bug
            // this field fixes).
            for AcceptedTx { result_idx, cacheable, tx } in accepted_txs {
                match mempool.submit(tx) {
                    Ok(()) => {
                        // Admitted — now the preverified sender may
                        // be cached.
                        if let Some((tx_hash, sender)) = cacheable {
                            primitives::sync::lock_state(&self.preverify_cache)
                                .insert(tx_hash, sender);
                        }
                    }
                    Err(e) => {
                        // Overwrite the Accepted result with the rejection.
                        results[result_idx] = MempoolAck::Rejected { reason: format!("{e:?}") };
                    }
                }
            }
        }
        results
    }

    fn prepare_proposal(&self, budget: &types::BlockBudget) -> Proposal {
        let start = std::time::Instant::now();
        // Drain the lock-free intake ring into the mempool under a
        // single lock acquisition. This batches all pending txs into
        // the mempool before selection, eliminating the per-tx
        // mempool lock on the ingestion hot path.
        {
            let rx = primitives::sync::lock_state(&self.mempool_intake_rx);
            let mut pool = primitives::sync::lock_state(&self.mempool);
            while let Ok(tx) = rx.try_recv() {
                let _ = pool.submit(tx);
            }
        }
        // Coordinated halt: once the next height is past the
        // scheduled halt, propose empty blocks only — the chain
        // keeps committing (deterministic liveness) while state
        // stays frozen at the halt height.
        // `current + 1 > halt` ⟺ `current >= halt`, written without
        // the addition so a height of u64::MAX can't wrap.
        let past_halt = self.halt_height().is_some_and(|halt| self.current_height() >= halt);
        // Select txs from the mempool by fee priority.
        let candidates = if past_halt {
            Vec::new()
        } else {
            primitives::sync::lock_state(&self.mempool).select(budget.max_bytes)
        };
        // Enforce the block gas limit at proposal time. The binding
        // constraint is `min(budget.max_gas, block_gas_limit)` —
        // `process_proposal` rejects blocks over `block_gas_limit`,
        // and the consensus budget may ask for less. Without this
        // the proposer could build a block the validators reject
        // outright, wasting a round.
        //
        // Txs that would poison the proposal are skipped entirely:
        // an unparseable context, missing module id, or unregistered
        // module makes `process_proposal` reject the WHOLE block —
        // a single malformed mempool entry could otherwise stall
        // the chain by poisoning every proposal.
        let gas_cap = budget.max_gas.min(self.block_gas_limit());
        let mut total_gas: u64 = 0;
        let mut txs = Vec::with_capacity(candidates.len());
        for tx in candidates {
            let bytes = tx.as_bytes();
            let gas = match (parse_tx_context(bytes), parse_module_id(bytes)) {
                (Some(_), Some(module_id)) => self.modules[usize::from(module_id)]
                    .as_ref()
                    .map(|m| m.estimate_gas(module_payload(bytes))),
                _ => None,
            };
            let Some(gas) = gas else {
                continue;
            };
            // Skip (not stop): a tx that doesn't fit leaves room for
            // a smaller later tx.
            if total_gas.saturating_add(gas) > gas_cap {
                continue;
            }
            total_gas += gas;
            txs.push(tx);
        }
        // Mark the built proposal's contents in-flight: `select`
        // is a peek, so a pipelined proposal at the next position
        // would otherwise re-select this same mempool head and the
        // duplicate would commit as a nonce skip — wasted block
        // space. The set resolves on the next commit, so a lost
        // proposal's txs re-select rather than leak. Marked only
        // after the gas filter so filtered-out candidates stay
        // eligible.
        primitives::sync::lock_state(&self.mempool).note_proposed(&txs);
        let height = Height::new(*primitives::sync::lock_state(&self.next_proposal_height));
        if let Some(recorder) = &self.recorder {
            recorder.record("prepare_proposal", start.elapsed());
        }
        Proposal { height, txs, attestation: None }
    }

    /// `prepare_proposal` drains the intake ring into the pool before
    /// selecting, so by the time consensus calls this the pool depth
    /// already reflects every ingested tx — including ones `select`
    /// skipped for a nonce gap (the case the liveness gate exists for).
    fn has_queued_txs(&self) -> bool {
        self.mempool_len() > 0
    }

    fn process_proposal(&self, proposal: &Proposal) -> Verdict {
        // M2 fix: validate each tx's static structure. Previously
        // this accepted all proposals unconditionally, which meant
        // a byzantine leader could propose a block with malformed
        // txs and they'd be silently skipped during execution.
        //
        // Static validity checks (no state access):
        // 1. Each tx must be long enough to have a sender, nonce,
        //    fee, and module ID (≥ 37 bytes).
        // 2. Each tx's module ID must be a registered module.
        //
        // H5 fix: per-sender nonce ordering. A byzantine leader can
        // reorder same-account txs or insert gaps. We now enforce
        // that within a proposal, each sender's nonces are strictly
        // contiguous and increasing (no gaps, no reorderings).
        //
        // Cross-block nonce anchoring is NOT checked here because the
        // pipelined two-chain HotStuff consensus proposes a new block
        // before the previous block's execution completes. The
        // `executed_nonce` map may lag behind the proposal height, so
        // anchoring here would reject valid proposals. Instead, cross-
        // block anchoring is enforced at two other points:
        // 1. `ingest_tx` (mempool admission): rejects txs with
        //    `nonce < executed_nonce[sender]` (replay protection).
        // 2. `execute_block` (execution): skips txs with stale or
        //    out-of-order nonces (silent skip, not block rejection).
        //
        // Dynamic checks (balance, signature) are not done here —
        // they require state access or per-tx cryptography and are
        // enforced elsewhere: envelope signatures are verified at
        // `ingest_tx`/`ingest_tx_batch` (rejected) and `execute_block`
        // (skipped), so a bad-sig tx in an accepted proposal is a
        // deterministically-skipped no-op rather than a consensus
        // failure.
        let mut last_nonce: HashMap<primitives::Address, u64> = HashMap::new();
        let mut total_gas: u64 = 0;
        for tx in &proposal.txs {
            let bytes = tx.as_bytes();
            // Check that the tx context is parseable (sender, nonce,
            // fee). This also implicitly checks the minimum size
            // (TX_MIN_SIZE = 36 bytes).
            let Some(ctx) = parse_tx_context(bytes) else {
                return Verdict::Reject {
                    reason: "tx context (sender/nonce/fee) is malformed".to_string(),
                };
            };
            // H5: enforce per-sender nonce ordering within the
            // proposal. Each sender's nonces must be strictly
            // contiguous (n, n+1, n+2, ...). A gap or reordering
            // indicates a byzantine proposer.
            // Cross-block anchoring is NOT checked here (see comment
            // above — pipelined consensus means execution may lag).
            match last_nonce.get(&ctx.sender) {
                // `prev + 1` must not wrap: a previous nonce of
                // u64::MAX has no valid successor — `checked_add`
                // yields `None`, which falls through to `_` and
                // rejects the tx (the match arm ordering makes the
                // non-contiguous case the failure path).
                Some(&prev) if prev.checked_add(1).is_none_or(|next| ctx.nonce != next) => {
                    return Verdict::Reject {
                        reason: format!(
                            "nonce gap/reorder: sender {:?} expected {} got {}",
                            ctx.sender,
                            prev.wrapping_add(1),
                            ctx.nonce
                        ),
                    };
                }
                // Either no previous nonce (first tx from this
                // sender) or the nonce is contiguous (prev + 1) —
                // accepted. Cross-block continuity is enforced in
                // `ingest_tx` (mempool) and `execute_block`.
                _ => {}
            }
            last_nonce.insert(ctx.sender, ctx.nonce);
            // u64::MAX is a reserved nonce (see `group_block_txs`):
            // a block containing one is invalid.
            if ctx.nonce == u64::MAX {
                return Verdict::Reject { reason: "nonce `u64::MAX` is reserved".to_string() };
            }
            // Check that the tx has a module ID byte.
            if bytes.len() < MODULE_ID_OFFSET + 1 {
                return Verdict::Reject { reason: "tx too short for module ID".to_string() };
            }
            // Check that the module is registered.
            let Some(module_id) = parse_module_id(bytes) else {
                return Verdict::Reject { reason: "tx has no module ID".to_string() };
            };
            let Some(module) = self.modules[module_id as usize].as_ref() else {
                return Verdict::Reject { reason: format!("unknown module ID {module_id}") };
            };
            // Static malformed check: an envelope signature on a
            // self-authenticating module (EVM) is meaningless — the
            // flag shifts the payload offset, so the module's own
            // payload would be corrupted. This check is state-free
            // (module registration and the flag bit only), unlike
            // signature verification which is intentionally left to
            // `ingest_tx`/`execute_block` for cost reasons.
            if is_signed_envelope(bytes) && module.authenticates_sender() {
                return Verdict::Reject {
                    reason: "envelope signature on self-authenticating module".to_string(),
                };
            }
            // Enforce block gas limit: sum the gas estimate of each
            // tx and reject the block if the total exceeds the limit.
            // This prevents a byzantine proposer from including
            // unbounded computation in a single block.
            let payload = module_payload(bytes);
            let gas = module.estimate_gas(payload);
            total_gas = total_gas.saturating_add(gas);
            if total_gas > self.block_gas_limit() {
                return Verdict::Reject {
                    reason: format!(
                        "block gas limit exceeded: {total_gas} > {}",
                        self.block_gas_limit()
                    ),
                };
            }
        }
        Verdict::Accept
    }

    fn finalize_block(&self, block: &FinalizedBlock) -> CommitAck {
        let start = std::time::Instant::now();
        // Idempotent re-commit. After a restart the journal replays
        // to the durable tip while consensus still holds those same
        // heights as its uncommitted tail — its commit walk will
        // re-finalize them once new QCs close the links. Heights
        // below `next_proposal_height` are already journaled AND
        // executed (replay plants their roots and advances the
        // watermark past them), so re-running one would double-apply
        // its effects and append an out-of-order journal record the
        // next recovery rejects as a gap. Consensus finality makes
        // two different blocks at one height impossible, so the
        // watermark is a complete dedup key.
        if block.height.value() < *primitives::sync::lock_state(&self.next_proposal_height) {
            return CommitAck { height: block.height };
        }
        // Durability first: the block must be journaled before ANY
        // of its effects exist anywhere — mempool removal, module
        // state, or a lane hand-off — so a crash can only ever lose
        // work the journal still holds. The engine calls this before
        // it WALs its own commit record, keeping the journal a strict
        // superset of consensus-committed state. `journal_append` is
        // buffer-only; the fsync is deferred to the barriers named
        // on that method (execution pre-flush, the engine's
        // `commit_durability_barrier`, checkpoints/shutdown) — one
        // sync now covers a whole drain batch instead of one per
        // block.
        self.journal_append(block);
        // Remove the committed txs from the mempool at finality.
        // `select` is a peek — pooled entries outlive proposals — so
        // this is the single point where inclusion becomes permanent
        // and the pool releases custody. Doing it here (rather than
        // inside `execute_block`) also covers the async lane: a
        // committed tx can never be re-proposed by a `prepare` that
        // runs while the worker is still draining the backlog.
        primitives::sync::lock_state(&self.mempool).remove_committed(&block.txs);
        let lane_spawned = {
            let (lock, _cv) = &*self.exec_sync;
            primitives::sync::lock_state(lock).lane_spawned
        };
        if lane_spawned {
            // Async execution lane: `finalized` and the proposal
            // height advance now — they record *ordering* finality,
            // which consensus already settled — while `state_roots`
            // is written by the worker (or the inline backlog drain
            // below) when execution lands. `finalized` is inserted
            // BEFORE the hand-off so the backlog drain can see this
            // block too.
            self.insert_finalized(block.height.value(), block.clone());
            *primitives::sync::lock_state(&self.next_proposal_height) =
                block.height.value().saturating_add(1); // M2 fix
            let lane_dead = {
                let (lock, cv) = &*self.exec_sync;
                let mut s = primitives::sync::lock_state(lock);
                // Non-blocking hand-off: push to the pending deque
                // and wake the worker. A committed block can never
                // be dropped, so the deque is unbounded — the bound
                // lives in the `saturated` signal instead: crossing
                // `EXEC_LANE_DEPTH` flips it, and the engine
                // throttles new commits at the source (withheld
                // votes + deferred commit walks) instead of this
                // thread stalling inside a blocking channel send.
                // Consensus keeps pumping — catch-up, timeouts, QC
                // adoption all still work — while the backlog drains.
                s.pending.push_back(block.clone());
                s.enqueued = Some(block.height.value());
                // Capping the threshold at `retention - 1` keeps the
                // maximum backlog (deque + one in-flight) inside the
                // retained history window even for tiny custom
                // retentions — every unexecuted height stays
                // reachable by the inline backlog drain.
                let depth = EXEC_LANE_DEPTH.min(self.history_retention.saturating_sub(1)).max(1);
                if !s.saturated && s.pending.len() > depth {
                    s.saturated = true;
                    eprintln!(
                        "executor: execution lane saturated — {} committed blocks unexecuted; \
                         consensus will withhold votes and defer commits until the backlog drains",
                        s.pending.len()
                    );
                }
                cv.notify_all();
                s.lane_dead
            };
            if lane_dead {
                // The lane can never execute this block — drive
                // every committed-but-unexecuted height inline.
                // Executing only THIS block (the old behavior) left
                // the height the worker died on permanently
                // rootless: a hole no later commit can fill,
                // stalling every exec-cert that references it.
                // `pending` is cleared first: every queued block is
                // in `finalized`, so the drain covers them all and
                // no stale entry can be double-popped by a worker
                // that no longer exists. `saturated` clears with it —
                // the inline drain below IS the debt resolution, so a
                // stale flag would otherwise throttle a solo engine
                // into silence (its `step` gate pauses the very
                // commits that trigger this drain).
                {
                    let (lock, _cv) = &*self.exec_sync;
                    let mut s = primitives::sync::lock_state(lock);
                    s.pending.clear();
                    s.saturated = false;
                }
                self.execute_committed_backlog();
            }
        } else {
            // Synchronous execution (default): fail closed on a
            // partially applied block BEFORE executing, exactly as
            // the backlog drain does — a `Some(h)` marker with no
            // recorded root means a previous `execute_block` panicked
            // mid-mutation, and replaying over surviving writes would
            // double-apply fees/nonces/module effects.
            let poisoned = {
                let (lock, _cv) = &*self.exec_sync;
                primitives::sync::lock_state(lock)
                    .in_flight
                    .filter(|h| !primitives::sync::lock_state(&self.state_roots).contains_key(h))
            };
            if let Some(h) = poisoned {
                panic!(
                    "executor: synchronous execution of committed block {h} panicked \
                     mid-mutation; the block may be partially applied (fees/nonces/module \
                     state already mutated) and cannot be safely replayed in-process — \
                     halting; restart to recover from durable state"
                );
            }
            // Mark the height in-flight around `execute_block` exactly
            // as the backlog drain does: if the panic propagates, the
            // marker stays set and the NEXT `finalize_block` meets the
            // fail-closed check above instead of silently replaying.
            {
                let (lock, _cv) = &*self.exec_sync;
                primitives::sync::lock_state(lock).in_flight = Some(block.height.value());
            }
            // Journal ⊇ durable state: `execute_block`'s module
            // flushes (the EVM backend's per-block `apply_batch` +
            // `sync`) must never outrun the block's journal record.
            // With no worker to defer to, the sync runs here.
            self.journal_sync_pending();
            let root = self.execute_block(block);
            primitives::sync::lock_state(&self.state_roots).insert_retained(
                block.height.value(),
                root,
                self.history_retention,
            );
            {
                let (lock, _cv) = &*self.exec_sync;
                primitives::sync::lock_state(lock).in_flight = None;
            }
            // Keep the watermark honest in synchronous mode too:
            // the block was just executed, and `insert_finalized`
            // evicts only at-or-below it.
            {
                let (lock, _cv) = &*self.exec_sync;
                let mut s = primitives::sync::lock_state(lock);
                s.enqueued = Some(block.height.value());
                s.executed = Some(block.height.value());
            }
            self.insert_finalized(block.height.value(), block.clone());
            *primitives::sync::lock_state(&self.next_proposal_height) =
                block.height.value().saturating_add(1); // M2 fix
        }
        // Checkpoint cadence: every `checkpoint_interval` heights the
        // journal's replay base advances to `snapshot.bin` and the
        // covered segments are pruned — bounding both replay length
        // and journal size.
        self.maybe_checkpoint(block.height.value());
        if let Some(recorder) = &self.recorder {
            recorder.record("finalize_block", start.elapsed());
        }
        CommitAck { height: block.height }
    }

    fn attest_state(&self, height: Height) -> Option<StateAttestation> {
        let start = std::time::Instant::now();
        // Async lane: wait only while the height is owed to a LIVE
        // worker. A height never enqueued has no execution coming,
        // and a dead lane can never advance `executed` — both return
        // `None` ("not executed") rather than blocking forever. The
        // `lane_dead` check is what makes a worker panic propagate
        // instead of hanging every attester.
        {
            let (lock, cv) = &*self.exec_sync;
            let mut s = primitives::sync::lock_state(lock);
            while s.lane_spawned
                && !s.lane_dead
                && s.enqueued.is_some_and(|e| height.value() <= e)
                && s.executed.is_none_or(|x| x < height.value())
            {
                s = cv.wait(s).unwrap_or_else(|_| {
                    panic!("state mutex poisoned: a holder panicked mid-mutation")
                });
            }
        }
        let root = primitives::sync::lock_state(&self.state_roots).get(&height.value()).copied();
        if let Some(recorder) = &self.recorder {
            recorder.record("attest_state", start.elapsed());
        }
        root.map(|root| StateAttestation { height, root })
    }

    fn attest_state_bounded(
        &self,
        height: Height,
        max_wait: std::time::Duration,
    ) -> Option<StateAttestation> {
        let start = std::time::Instant::now();
        // Same wait condition as `attest_state`, but bounded: the
        // consensus vote path calls this while verifying a proposal's
        // exec cert, and an unbounded wait there stalls the pacemaker
        // behind a lagging lane. On expiry the withheld vote is the
        // honest outcome — the proposal may be re-delivered after the
        // lane catches up.
        {
            let deadline = start + max_wait;
            let (lock, cv) = &*self.exec_sync;
            let mut s = primitives::sync::lock_state(lock);
            loop {
                let done = !s.lane_spawned
                    || s.lane_dead
                    || s.enqueued.is_none_or(|e| height.value() > e)
                    || s.executed.is_some_and(|x| x >= height.value());
                if done {
                    break;
                }
                let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now())
                else {
                    break;
                };
                let (guard, _timeout) = cv.wait_timeout(s, remaining).unwrap_or_else(|_| {
                    panic!("state mutex poisoned: a holder panicked mid-mutation")
                });
                s = guard;
            }
        }
        let root = primitives::sync::lock_state(&self.state_roots).get(&height.value()).copied();
        if let Some(recorder) = &self.recorder {
            recorder.record("attest_state", start.elapsed());
        }
        root.map(|root| StateAttestation { height, root })
    }

    fn exec_saturated(&self) -> bool {
        // The lane's unexecuted debt exceeded `EXEC_LANE_DEPTH` —
        // `finalize_block` sets it under the same lock on push, and
        // the worker clears it only once the deque fully drains.
        let (lock, _cv) = &*self.exec_sync;
        primitives::sync::lock_state(lock).saturated
    }

    fn attest_latest(&self) -> Option<StateAttestation> {
        // Deliberately does NOT flush pending execution: the vote
        // path calls this on every vote and cannot afford to wait
        // on the execution lane. A stale attestation certifies an
        // older height — never a wrong one. `None` before the first
        // execution: there is no attestation to make.
        primitives::sync::lock_state(&self.state_roots)
            .iter()
            .next_back()
            .map(|(h, root)| StateAttestation { height: Height::new(*h), root: *root })
    }

    /// Drain both pending-transition queues as one atomic
    /// [`EpochChanges`] record — the consensus-facing half of the
    /// epoch protocol. The engine polls this each epoch-boundary
    /// pass; draining and rotating in the same pass keeps the
    /// module queues from re-reporting an enacted transition.
    fn take_epoch_changes(&self) -> types::EpochChanges {
        // One drain per queue — `take_pending_validator_changes`
        // clears the module queues, so a second call would report
        // empty and the removes would be lost.
        let val = self.take_pending_validator_changes();
        types::EpochChanges {
            key_changes: self.take_pending_key_changes(),
            adds: val.adds,
            removes: val.removes,
        }
    }

    fn commit_durability_barrier(&self) {
        // The engine is about to fsync commit-bearing WAL state
        // (a signature-gated append or a compaction checkpoint).
        // Flush pending journal records first so no committed height
        // can end up durable in consensus evidence while missing
        // from the journal — the hole a restart could never
        // re-finalize.
        self.journal_sync_pending();
    }
}
