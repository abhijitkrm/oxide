//! `AppInterface` adapter — the consensus↔executor boundary.
//!
//! Split from `lib.rs` around the port invariant: this impl is
//! the *only* surface consensus calls — mempool admission,
//! proposal building, block finalize, and snapshot hooks. Keeping
//! it in one file makes it auditable that everything consensus
//! can drive is listed here and nothing else leaks across the
//! boundary.

use super::{
    AcceptedTx, AppInterface, CommitAck, EXEC_LANE_DEPTH, ExecError, Executor, FinalizedBlock,
    HashMap, Height, InsertRetained, MODULE_ID_OFFSET, MempoolAck, Module, PreverifiedTx, Proposal,
    StateAttestation, TxBytes, TxContext, UnsignedTxPolicy, Verdict, envelope_signature,
    is_signed_envelope, module_payload, parse_module_id, parse_tx_context,
};
use primitives::{Address, Hash};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::sync::Arc;

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
        // Pre-recover the sender BEFORE validating: `preverify_batch`
        // decodes the payload and recovers its signature (the EVM's
        // ~43µs secp256k1 recovery — the single most expensive per-tx
        // intake operation), and `validate_preverified` then reuses
        // that sender instead of recovering again. The old order
        // (`validate` first, then `preverify_batch`) paid the
        // recovery twice per tx — measured 90µs/tx intake, halved
        // here and parallelized across the batch in
        // `ingest_tx_batch`.
        //
        // `msgs` must outlive `preverify_result` — the returned
        // `PreverifiedTx` borrows the payload slice.
        let msgs = [payload];
        let preverify_result = module.preverify_batch(&msgs);
        if let Err(e) =
            module.validate_preverified(&ctx, payload, preverify_result[0].as_ref().ok())
        {
            return MempoolAck::Rejected { reason: format!("validate: {e}") };
        }

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
        // The entry is *computed* now but inserted only if the
        // bounded intake accepts the tx below — a cache populated
        // ahead of admission grew on *rejected* submissions (an
        // intake-full flood filled it with senders for txs the pool
        // never held), the one intake-side map that wasn't bounded
        // by any capacity check. The hash is taken now because `tx`
        // moves into the channel below.
        let cacheable = preverify_result[0]
            .as_ref()
            .ok()
            .and_then(|preverified| {
                if preverified.sender != [0u8; 20] {
                    Some(preverified.sender)
                } else if envelope_verified {
                    Some(ctx.sender.0)
                } else {
                    None
                }
            })
            .map(|sender| {
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

    /// Phase E: batch mempool intake — the parallel admission path.
    ///
    /// Three phases:
    /// 1. **Route (serial, cheap):** envelope parse, module lookup,
    ///    and the envelope *shape* checks per tx — no crypto.
    /// 2. **Recover (parallel):** every secp256k1 recovery the batch
    ///    needs runs here — payload recovery through the module's
    ///    `preverify_batch` (the EVM's is rayon-parallel across the
    ///    group) and envelope recovery for signed native-module txs
    ///    (rayon across the batch). This is the phase that matters:
    ///    recovery is ~43µs/tx serial on the dev rig, and the old
    ///    path paid it TWICE per EVM tx (`validate` recovered, then
    ///    `preverify_batch` recovered the same payload again) with
    ///    zero cross-tx parallelism — measured 90µs/tx intake, the
    ///    60% share that capped the 4-validator chain at ~6k tx/s.
    /// 3. **Adjudicate (serial):** the executed-nonce replay check
    ///    under one lock for the whole batch, the envelope sender
    ///    compare, `validate_preverified` (reuses the recovered
    ///    sender — no second recovery), then the batched mempool
    ///    insert under one lock.
    ///
    /// Per-tx rejection reasons are byte-identical to `ingest_tx`.
    /// One documented precedence shift: a tx failing *both* the
    /// replay gate and a later gate now reports the later gate's
    /// reason (the replay check moved after routing so it can run
    /// under a single lock for the whole batch). The protection is
    /// identical — a replayed tx is rejected either way; only the
    /// reason string of a multi-failure tx changes.
    fn ingest_tx_batch(&self, mut txs: Vec<TxBytes>) -> Vec<MempoolAck> {
        let mut results: Vec<MempoolAck> = Vec::with_capacity(txs.len());
        // ── Phase 1: route (serial, cheap) ─────────────────────────
        let (routed, env_targets, groups) = self.route_batch(&txs, &mut results);
        // Group payloads hoisted HERE (not inside `recover_batch`)
        // so the preverify results returned below can borrow them:
        // `preverify_batch`'s returned `PreverifiedTx` anchors its
        // lifetime to the `msgs` slice reference, so that reference
        // must outlive every use of the results — a local inside the
        // helper would end it at the helper's return.
        let mut group_ids: Vec<u8> = groups.keys().copied().collect();
        group_ids.sort_unstable();
        let group_payloads: Vec<Vec<&[u8]>> = group_ids
            .iter()
            .map(|module_id| {
                groups[module_id]
                    .iter()
                    .map(|&ri| module_payload(txs[routed[ri].tx_idx].as_bytes()))
                    .collect()
            })
            .collect();
        // ── Phase 2: recover (parallel) ────────────────────────────
        let recovered =
            self.recover_batch(&txs, &routed, &env_targets, &groups, &group_ids, &group_payloads);
        // ── Phase 3: adjudicate (serial) ───────────────────────────
        let accepted_txs = self.adjudicate_batch(&txs, &routed, &mut results, &recovered);
        // ── Phase 4: pool insert (one lock) ────────────────────────
        // Every borrow into `txs` is dead above — move them in.
        if !accepted_txs.is_empty() {
            let mut mempool = primitives::sync::lock_state(&self.mempool);
            let mut cache_entries: Vec<(Hash, [u8; 20])> = Vec::new();
            for AcceptedTx { result_idx, tx_idx, hash, sender, nonce, fee, gas, cache_sender } in
                accepted_txs
            {
                // `submit_prepared` skips the mempool's own re-hash,
                // re-parse, and gas re-estimate — the intake's
                // parallel phase already produced all three.
                let prepared = mempool::PreparedTx {
                    tx: std::mem::take(&mut txs[tx_idx]),
                    hash,
                    sender,
                    nonce,
                    fee,
                    gas,
                };
                match mempool.submit_prepared(prepared) {
                    Ok(()) => {
                        if let Some(sender) = cache_sender {
                            cache_entries.push((hash, sender));
                        }
                    }
                    Err(e) => {
                        results[result_idx] = MempoolAck::Rejected { reason: format!("{e:?}") };
                    }
                }
            }
            // One lock for the whole batch's cache inserts (the old
            // path re-locked per tx).
            if !cache_entries.is_empty() {
                let mut cache = primitives::sync::lock_state(&self.preverify_cache);
                for (tx_hash, sender) in cache_entries {
                    cache.insert(tx_hash, sender);
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
            // `select_with_gas` returns each candidate's precomputed
            // gas estimate (cached in the pool entry at intake time)
            // — the gas-cap loop below reads it instead of
            // re-parsing the envelope and re-estimating per
            // candidate (~0.42µs/tx; ~17ms per proposal at a 40k-tx
            // backlog, the largest term in this path).
            primitives::sync::lock_state(&self.mempool).select_with_gas(budget.max_bytes)
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
        // the chain by poisoning every proposal. Entries inserted
        // through the drain path (`submit`, no module context)
        // carry `gas = 0` — those still pay the per-candidate
        // estimate here; batch-intake entries never do.
        let gas_cap = budget.max_gas.min(self.block_gas_limit());
        let mut total_gas: u64 = 0;
        let mut txs = Vec::with_capacity(candidates.len());
        for (tx, cached_gas) in candidates {
            let gas = if cached_gas > 0 {
                cached_gas
            } else {
                let bytes = tx.as_bytes();
                let estimated = match (parse_tx_context(bytes), parse_module_id(bytes)) {
                    (Some(_), Some(module_id)) => self.modules[usize::from(module_id)]
                        .as_ref()
                        .map(|m| m.estimate_gas(module_payload(bytes))),
                    _ => None,
                };
                match estimated {
                    Some(gas) => gas,
                    None => continue,
                }
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
        // Record this proposal's nonce coverage in the mempool. Under
        // pipelined consensus a block legitimately carries nonces this
        // validator's pool never saw (each leader only pools its own
        // submissions) — without the cover, `select` anchors at the
        // local executed nonce, sees a gap where an ancestor carries
        // the missing nonces, and proposes empty. Recorded only on the
        // accept path so rejected-by-static-rules proposals can't grow
        // the cover set; the map expires by height TTL in
        // `refresh_anchors` if the covering branch never commits.
        primitives::sync::lock_state(&self.mempool)
            .note_in_chain(&proposal.txs, proposal.height.value());
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
        // superset of consensus-committed state.
        self.journal_append(block);
        // Remove the committed txs from the mempool at finality.
        // `select` is a peek — pooled entries outlive proposals — so
        // this is the single point where inclusion becomes permanent
        // and the pool releases custody. Doing it here (rather than
        // inside `execute_block`) also covers the async lane: a
        // committed tx can never be re-proposed by a `prepare` that
        // runs while the worker is still draining the backlog.
        primitives::sync::lock_state(&self.mempool)
            .remove_committed(&block.txs, block.height.value());
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
}

impl Executor {
    /// Phase 1 of [`AppInterface::ingest_tx_batch`]: route (serial,
    /// cheap) — envelope parse, module lookup, and the envelope
    /// *shape* checks per tx, no crypto. The shape checks here are
    /// the ones `check_envelope_auth` makes before touching a
    /// signature, so the parallel phase only ever sees txs whose
    /// recovery is actually needed.
    ///
    /// Returns the routed candidates in tx order, the positions
    /// needing envelope recovery, and the per-module grouping.
    fn route_batch(
        &self,
        txs: &[TxBytes],
        results: &mut Vec<MempoolAck>,
    ) -> (Vec<Routed>, Vec<usize>, HashMap<u8, Vec<usize>>) {
        let mut routed: Vec<Routed> = Vec::with_capacity(txs.len());
        let mut env_targets: Vec<usize> = Vec::new();
        // module_id → routed positions, in tx order (stable grouping
        // keeps `preverify_batch` inputs deterministic).
        let mut groups: HashMap<u8, Vec<usize>> = HashMap::new();
        for (tx_idx, tx) in txs.iter().enumerate() {
            let bytes = tx.as_bytes();
            let Some(ctx) = parse_tx_context(bytes) else {
                results.push(MempoolAck::Rejected { reason: "malformed: tx context".to_string() });
                continue;
            };
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
            // Reserved nonce — same rule as `ingest_tx` (executing it
            // would wrap the next-expected counter and reopen the
            // sender's whole nonce range to replay).
            if ctx.nonce == u64::MAX {
                results.push(MempoolAck::Rejected {
                    reason: "nonce `u64::MAX` is reserved".to_string(),
                });
                continue;
            }
            // Envelope shape (no crypto): a self-authenticating
            // module must not carry an envelope signature (it would
            // shift the payload offset), and an unsigned tx is
            // admitted or rejected per the policy.
            let signed = is_signed_envelope(bytes);
            if module.authenticates_sender() {
                if signed {
                    results.push(MempoolAck::Rejected {
                        reason: "malformed: envelope signature on self-authenticating module"
                            .to_string(),
                    });
                    continue;
                }
            } else if !signed {
                match self.unsigned_tx_policy {
                    UnsignedTxPolicy::Allow => {}
                    UnsignedTxPolicy::Reject => {
                        results.push(MempoolAck::Rejected {
                            reason: "unsigned native tx (signature required)".to_string(),
                        });
                        continue;
                    }
                }
            }
            let result_idx = results.len();
            results.push(MempoolAck::Accepted);
            // Signed native txs recover the ENVELOPE signature (the
            // expensive part of `check_envelope_auth`); EVM payloads
            // recover inside `preverify_batch`. Both happen in the
            // parallel phase.
            let env_slot = if signed && !module.authenticates_sender() {
                env_targets.push(routed.len());
                Some(env_targets.len() - 1)
            } else {
                None
            };
            let group = groups.entry(module_id).or_default();
            let pv_slot = Some((usize::from(module_id), group.len()));
            group.push(routed.len());
            routed.push(Routed {
                result_idx,
                tx_idx,
                ctx,
                module_id,
                module: module.clone(),
                env_slot,
                pv_slot,
            });
        }
        (routed, env_targets, groups)
    }

    /// Phase 2 of [`AppInterface::ingest_tx_batch`]: recover
    /// (parallel) — every secp256k1 recovery the batch needs.
    ///
    /// 2a. Envelope recovery for signed native txs — one rayon pass
    /// over the whole batch; the compare against `ctx.sender` stays
    /// in phase 3 (it needs no crypto). 2b. Payload preverify per
    /// module group — the EVM's `preverify_batch` is rayon-parallel
    /// across the group; the default is sequential (no recovery to
    /// parallelize). Results borrow the payload slices, which borrow
    /// `txs` — every use is inside the caller, before the pool moves
    /// any tx.
    fn recover_batch<'a>(
        &self,
        txs: &[TxBytes],
        routed: &[Routed],
        env_targets: &[usize],
        groups: &HashMap<u8, Vec<usize>>,
        group_ids: &[u8],
        group_payloads: &'a [Vec<&'a [u8]>],
    ) -> Recovered<'a> {
        // The whole parallel phase runs on the intake's dedicated
        // pool (`install` also captures the modules' nested
        // `par_iter`s — the EVM's preverify — onto it). On the global
        // pool these tasks queued behind the async execution lane's
        // work: measured 10.6 → 39-60µs/tx once the lane started
        // executing the commit backlog. `None` (pool build failed)
        // falls back to the global pool — a latency property, never
        // a correctness one.
        let intake = self.intake_pool.as_ref();
        let env_recoveries: Vec<Result<Address, &'static str>> = match intake {
            Some(pool) => pool.install(|| {
                env_targets
                    .par_iter()
                    .map(|&ri| {
                        let r = &routed[ri];
                        recover_envelope_sender(
                            self.chain_id,
                            txs[r.tx_idx].as_bytes(),
                            &r.ctx,
                            r.module_id,
                        )
                    })
                    .collect()
            }),
            None => env_targets
                .par_iter()
                .map(|&ri| {
                    let r = &routed[ri];
                    recover_envelope_sender(
                        self.chain_id,
                        txs[r.tx_idx].as_bytes(),
                        &r.ctx,
                        r.module_id,
                    )
                })
                .collect(),
        };
        // Full-tx hashes for every routed candidate — the mempool's
        // dedup key and the preverify-cache key. Pure per-tx CPU, so
        // it rides the same parallel phase as the recoveries
        // (~0.22µs/tx serial → ~0.03µs/tx effective); the mempool
        // insert then skips its own re-hash via `submit_prepared`.
        let tx_hashes: Vec<Hash> = match intake {
            Some(pool) => pool.install(|| {
                routed
                    .par_iter()
                    .map(|r| {
                        crypto::hash::Hasher::hash_one(
                            crypto::hash::Domain::Transaction,
                            txs[r.tx_idx].as_bytes(),
                        )
                    })
                    .collect()
            }),
            None => routed
                .par_iter()
                .map(|r| {
                    crypto::hash::Hasher::hash_one(
                        crypto::hash::Domain::Transaction,
                        txs[r.tx_idx].as_bytes(),
                    )
                })
                .collect(),
        };
        let mut pv_results: Vec<Vec<Result<PreverifiedTx<'a>, ExecError>>> =
            Vec::with_capacity(group_ids.len());
        for (gi, module_id) in group_ids.iter().enumerate() {
            let members = &groups[module_id];
            let module = routed[members[0]].module.clone();
            let payloads = &group_payloads[gi];
            let results = match intake {
                // `install` captures the module's nested `par_iter`
                // (the EVM's preverify) onto the intake pool.
                Some(pool) => pool.install(|| module.preverify_batch(payloads)),
                None => module.preverify_batch(payloads),
            };
            pv_results.push(results);
        }
        // module_id → index into `pv_results`/`group_ids` — the
        // routed slots store the module id (the routing key), not
        // the group ordinal.
        let group_index: HashMap<usize, usize> =
            group_ids.iter().enumerate().map(|(gi, id)| (usize::from(*id), gi)).collect();
        Recovered { env_recoveries, pv_results, group_index, tx_hashes }
    }

    /// Phase 3 of [`AppInterface::ingest_tx_batch`]: adjudicate
    /// (serial) — the executed-nonce replay gate under one lock for
    /// the whole batch, the envelope sender compare, module
    /// validation with the pre-recovered sender, and the cacheable
    /// sender computation. Returns the accepted txs for the pool.
    fn adjudicate_batch<'t>(
        &self,
        txs: &'t [TxBytes],
        routed: &[Routed],
        results: &mut [MempoolAck],
        recovered: &Recovered<'t>,
    ) -> Vec<AcceptedTx> {
        let Recovered { env_recoveries, pv_results, group_index, tx_hashes } = recovered;
        // 3a. Replay gate — one lock for the whole batch (the old
        // path re-locked per tx; this map is read-mostly and the
        // write side is block execution, so a single short critical
        // section per batch beats N per-tx sections).
        {
            let executed = primitives::sync::lock_state(&self.executed_nonce);
            for r in routed {
                let next_expected = executed.map.get(&r.ctx.sender).copied().unwrap_or(0);
                if r.ctx.nonce < next_expected {
                    results[r.result_idx] = MempoolAck::Rejected {
                        reason: format!(
                            "replay: nonce {} < next expected {next_expected}",
                            r.ctx.nonce
                        ),
                    };
                }
            }
        }
        // 3b. Per-tx adjudication in batch order: envelope compare,
        // module validation with the recovered sender, cacheable
        // sender. Accepted txs collect for the pool.
        let mut accepted_txs: Vec<AcceptedTx> = Vec::with_capacity(routed.len());
        for (pos, r) in routed.iter().enumerate() {
            if matches!(results[r.result_idx], MempoolAck::Rejected { .. }) {
                continue;
            }
            // Envelope sender compare (non-EVM signed txs).
            let mut envelope_verified = false;
            if let Some(env_slot) = r.env_slot {
                match &env_recoveries[env_slot] {
                    Ok(recovered) if *recovered == r.ctx.sender => envelope_verified = true,
                    Ok(_) => {
                        results[r.result_idx] = MempoolAck::Rejected {
                            reason: "envelope signature does not match declared sender".to_string(),
                        };
                        continue;
                    }
                    Err(reason) => {
                        results[r.result_idx] = MempoolAck::Rejected { reason: reason.to_string() };
                        continue;
                    }
                }
            }
            // Module validation with the pre-recovered sender — the
            // recovery is paid once (phase 2), not twice.
            let payload = module_payload(txs[r.tx_idx].as_bytes());
            let preverified = r.pv_slot.as_ref().and_then(|(module_id, slot)| {
                let group = group_index.get(module_id).copied()?;
                pv_results
                    .get(group)
                    .and_then(|group_results| group_results.get(*slot))
                    .and_then(|res| res.as_ref().ok())
            });
            if let Err(e) = r.module.validate_preverified(&r.ctx, payload, preverified) {
                results[r.result_idx] = MempoolAck::Rejected { reason: format!("validate: {e}") };
                continue;
            }
            // Cacheable sender: the module's own recovery (non-zero)
            // or the envelope-verified `ctx.sender`. A zero
            // placeholder on an admitted-unsigned tx is skipped so
            // `all_cached` stays false and the group keeps the plain
            // `handle_batch` path. Computed now, cached only after
            // the pool accepts — caching ahead of bounded admission
            // let rejected submissions grow the map past every
            // capacity check.
            let cache_sender = preverified.and_then(|pre| {
                if pre.sender != [0u8; 20] {
                    Some(pre.sender)
                } else if envelope_verified {
                    Some(r.ctx.sender.0)
                } else {
                    None
                }
            });
            // Gas estimate for the pool entry — the proposal
            // gas-cap loop reads it instead of re-parsing +
            // re-estimating per candidate (~0.42µs/tx saved there;
            // ~0.12µs/tx paid here, per module dispatch).
            let gas = r.module.estimate_gas(payload);
            accepted_txs.push(AcceptedTx {
                result_idx: r.result_idx,
                tx_idx: r.tx_idx,
                hash: tx_hashes[pos],
                sender: r.ctx.sender,
                nonce: r.ctx.nonce,
                fee: r.ctx.fee,
                gas,
                cache_sender,
            });
        }
        accepted_txs
    }
}

/// Recover the signer of a signed native tx envelope — the parallel
/// intake's half of [`Executor::check_envelope_auth`].
///
/// `check_envelope_auth` recovers AND compares inline; the batch
/// path splits the two because the recovery (~43µs/tx, the single
/// most expensive per-tx intake operation) parallelizes across the
/// batch while the compare is trivial. The rejection reasons are
/// byte-identical to the inline path's, so a tx rejected by either
/// path reports the same string.
///
/// # Errors
///
/// Static rejection strings — the same ones `check_envelope_auth`
/// returns for a malformed or invalid envelope signature.
fn recover_envelope_sender(
    chain_id: u64,
    bytes: &[u8],
    ctx: &TxContext,
    module_id: u8,
) -> Result<Address, &'static str> {
    let Some(sig_bytes) = envelope_signature(bytes) else {
        return Err("malformed: truncated envelope signature");
    };
    // v is the last byte. Only 0/1 are accepted — the canonical
    // recovery IDs secp256k1 produces (2/3 are provably-unused keys,
    // 27/28 is the Ethereum convention submitters must normalize).
    let recid = sig_bytes[64];
    if recid > 1 {
        return Err("malformed: envelope signature recovery id must be 0 or 1");
    }
    let sig = crypto::secp::RecoverableSignature::from_bytes(&sig_bytes[..64], recid)
        .map_err(|_| "malformed: envelope signature")?;
    let payload = module_payload(bytes);
    crypto::eip712::verify_tx_sender(
        chain_id,
        &ctx.sender,
        ctx.nonce,
        ctx.fee,
        module_id,
        payload,
        &sig,
    )
    .map_err(|_| "invalid envelope signature")
}

/// Phase-2 output of [`AppInterface::ingest_tx_batch`]: the
/// envelope-recovery verdicts, the per-module preverify results
/// (borrowing the batch's payload slices), the module-id →
/// group-index map, and every routed tx's BLAKE3 hash.
struct Recovered<'t> {
    env_recoveries: Vec<Result<Address, &'static str>>,
    pv_results: Vec<Vec<Result<PreverifiedTx<'t>, ExecError>>>,
    group_index: HashMap<usize, usize>,
    tx_hashes: Vec<Hash>,
}

/// One batch tx that cleared phase-1 routing in
/// [`AppInterface::ingest_tx_batch`] — everything the parallel and
/// adjudication phases need, keyed back into the caller's batch.
struct Routed {
    /// Slot in `results` — the filtered accepted vec cannot stand in
    /// for it (the positional-write bug the old field documented).
    result_idx: usize,
    /// Index into the caller's `Vec<TxBytes>` — the tx is moved into
    /// the pool only after every borrow into the batch (payload
    /// slices in the preverify results) is dead.
    tx_idx: usize,
    /// The envelope context parsed at routing.
    ctx: TxContext,
    /// The routed module.
    module_id: u8,
    /// The routed module implementation.
    module: Arc<dyn Module>,
    /// Position in the envelope-recovery results for a signed native
    /// tx; `None` for EVM payloads (self-authenticating) and
    /// admitted-unsigned txs.
    env_slot: Option<usize>,
    /// `(module_id, slot)` into the per-module preverify results.
    pv_slot: Option<(usize, usize)>,
}
