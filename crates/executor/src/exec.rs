//! Block-execution hot path.
//!
//! Split from `lib.rs` around the execution invariant:
//! [`Executor::execute_block`] plans run groups
//! (`plan_block_runs`), authenticates envelopes
//! (`check_envelope_auth`), and dispatches each run
//! (`charge_and_execute_run` / `dispatch_run`), then
//! `record_group_outcomes` merges results in canonical order.
//! Every committed transaction's fee charge and state transition
//! flows through this file — nothing else may mutate state for a
//! committed block.

use super::{
    Arc, BlockNonces, Domain, Event, ExecError, ExecutedNonces, Executor, FinalizedBlock,
    GroupedTx, Hash, HashMap, Hasher, Module, PreverifiedTx, TxBytes, TxContext, TxOutcome,
    TxSkipReason, UnsignedTxPolicy, canonical_state_root, envelope_signature, is_signed_envelope,
    module_payload, parse_module_id, parse_tx_context,
};

/// A transaction that cleared every admission gate in
/// [`Executor::plan_block_runs`]: envelope parse, known module,
/// nonce continuity, signature verification (or a documented
/// bypass — self-authenticating module / `UnsignedTxPolicy::Allow`),
/// block-gas limit, and the fee floor.
///
/// The fields are private to this module — `plan_block_runs` is the
/// only mint site, after all gates pass — so a `PlannedTx` reaching
/// `dispatch_run`/`charge_and_execute_run` *is* the proof that
/// admission ran. Nothing downstream may be fed an unplanned tuple:
/// this type is what stops a future code path from dispatching a
/// parsed-but-unauthenticated context straight to `Module::handle`.
pub(crate) struct PlannedTx<'a> {
    /// The parsed envelope context — authenticated for
    /// envelope-signed txs; an ordering hint only for
    /// self-authenticating modules (they recover sender+nonce from
    /// their own payload during execution).
    ctx: TxContext,
    /// Zero-copy module payload borrowed from the block bytes.
    payload: &'a [u8],
    /// `Domain::Transaction` hash of the full envelope — the
    /// preverify-cache key `ingest_tx` used.
    tx_hash: Hash,
}

impl Executor {
    /// Check the envelope authentication of a tx routed to `module`.
    ///
    /// Returns:
    /// - `Ok(true)` — the envelope carries a signature and it
    ///   verified: the recovered signer equals `ctx.sender`. The
    ///   caller should record the tx hash in the preverify cache so
    ///   `execute_block` can skip re-verification.
    /// - `Ok(false)` — the envelope is unsigned and admitted (either
    ///   the module self-authenticates or the policy allows it).
    /// - `Err(reason)` — rejected: bad signature, sender mismatch,
    ///   malformed signature field, flag set on a self-authenticating
    ///   module, or unsigned tx under [`UnsignedTxPolicy::Reject`].
    ///
    /// The signature covers the EIP-712 digest of
    /// `(chain_id, sender, nonce, fee, module_id, payload)` — see
    /// [`crypto::eip712`]. Because `sender` is a field of the signed
    /// struct, verifying `recovered == ctx.sender` binds the whole
    /// envelope: the signer, the declared sender, and the exact
    /// module message bytes.
    ///
    /// This is deterministic and state-free, so all validators agree
    /// on the outcome — safe to run in `execute_block` (skip on
    /// failure) as well as at mempool admission (reject).
    pub(crate) fn check_envelope_auth(
        &self,
        bytes: &[u8],
        ctx: &TxContext,
        module_id: u8,
        module: &dyn Module,
        verified: Option<&HashMap<Hash, [u8; 20]>>,
    ) -> Result<bool, &'static str> {
        let signed = is_signed_envelope(bytes);
        if module.authenticates_sender() {
            // The module's payload carries its own signature (EVM
            // RLP). An envelope signature would shift the payload
            // offset and serves no purpose — reject as malformed so
            // the flag can never silently corrupt an EVM payload.
            return if signed {
                Err("malformed: envelope signature on self-authenticating module")
            } else {
                Ok(false)
            };
        }
        if !signed {
            return match self.unsigned_tx_policy {
                UnsignedTxPolicy::Allow => Ok(false),
                UnsignedTxPolicy::Reject => Err("unsigned native tx (signature required)"),
            };
        }
        // Signed envelope: recover and compare.
        //
        // If the caller supplies a `verified` map (the preverify
        // cache at execution time), a hit means this node's
        // `ingest_tx` already ran the secp256k1 recovery for these
        // exact tx bytes — the cache key is `Domain::Transaction` of
        // the full envelope, so a hit implies the signature was
        // verified. Skip re-verification (~40 µs saved per tx).
        if let Some(cache) = verified {
            let tx_hash = Hasher::hash_one(Domain::Transaction, bytes);
            if cache.contains_key(&tx_hash) {
                return Ok(true);
            }
        }
        let Some(sig_bytes) = envelope_signature(bytes) else {
            return Err("malformed: truncated envelope signature");
        };
        // v is the last byte. We accept only 0/1 — the canonical
        // recovery IDs secp256k1 produces. IDs 2/3 correspond to
        // provably-unused keys and 27/28 is the Ethereum `v`
        // convention; MetaMask returns 27/28, which submitters must
        // normalize to 0/1 before building the envelope.
        let recid = sig_bytes[64];
        if recid > 1 {
            return Err("malformed: envelope signature recovery id must be 0 or 1");
        }
        let sig = crypto::secp::RecoverableSignature::from_bytes(&sig_bytes[..64], recid)
            .map_err(|_| "malformed: envelope signature")?;
        let payload = module_payload(bytes);
        let recovered = crypto::eip712::verify_tx_sender(
            self.chain_id,
            &ctx.sender,
            ctx.nonce,
            ctx.fee,
            module_id,
            payload,
            &sig,
        )
        .map_err(|_| "invalid envelope signature")?;
        if recovered != ctx.sender {
            return Err("envelope signature does not match declared sender");
        }
        Ok(true)
    }

    /// Group a finalized block's txs by module for batch execution,
    /// applying the execution-time admission gates in block order.
    ///
    /// Each tx must pass, in order:
    /// 1. envelope parse — malformed bytes are skipped;
    /// 2. nonce continuity — `ctx.nonce` must equal the next expected
    ///    nonce for `ctx.sender` in the local copy of `executed_nonce`
    ///    (H5; closes the cross-block replay window for byzantine
    ///    proposers that bypass `process_proposal`);
    /// 3. known module — the routed module must be registered;
    /// 4. envelope authentication — `check_envelope_auth`; a tx in
    ///    `preverify_cache` was verified at this node's `ingest_tx`
    ///    (same full-tx-hash key), so it skips the ~40 µs recovery,
    ///    while a tx arriving via a foreign proposal is verified
    ///    inline. Failures skip the tx — deterministic across
    ///    validators, so all produce the same state root;
    /// 5. block gas limit — cumulative `estimate_gas` across the
    ///    block (execution-time enforcement of the proposal-time
    ///    check in `process_proposal`);
    /// 6. fee floor + fee charge — non-self-funded modules pay
    ///    `ctx.fee` via the configured fee module. The fee is kept
    ///    even if `handle` later fails (work was attempted — like
    ///    gas on revert), and the nonce only advances after the
    ///    charge succeeds.
    ///
    /// Entries are `(ctx, payload, full_tx_hash)`; the payload is a
    /// zero-copy borrow into the block bytes and the hash is the
    /// preverify-cache key.
    ///
    /// The plan preserves **committed block order**: the returned
    /// `Vec` is a sequence of contiguous same-module *runs* — a new
    /// run starts whenever the module id changes, so cross-module
    /// semantics are exactly sequential (an EVM transfer funding a
    /// later delegate is visible to it). Batching amortizes only
    /// where the committed order already made txs adjacent; it never
    /// reorders across modules. This replaces the old global
    /// `BTreeMap<module_id>` grouping, which was deterministic but
    /// NOT faithful to the ordering consensus finalized — modules
    /// share one balance ledger, so sorted-module execution could
    /// reorder a funding transfer past its dependent.
    ///
    /// The fee *floor* is a stateless gate and stays here; the fee
    /// *charge* does NOT — it debits the shared ledger, so it must
    /// observe the effects of every earlier tx. It runs at dispatch
    /// time, per run in block order (see `execute_block`).
    ///
    /// `skipped` collects the hash + gate for every proposed tx that
    /// never reaches a module — the caller records each as a
    /// [`TxOutcome::Skipped`] so a submitter can tell "dropped at a
    /// gate" apart from "executed and rejected".
    pub(crate) fn plan_block_runs<'b>(
        &self,
        txs: &'b [TxBytes],
        local_nonce: &mut BlockNonces<'_>,
        preverify_cache: &HashMap<Hash, [u8; 20]>,
        skipped: &mut Vec<(Hash, TxSkipReason)>,
    ) -> Vec<(u8, Vec<GroupedTx<'b>>)> {
        let mut runs: Vec<(u8, Vec<GroupedTx<'b>>)> = Vec::new();
        let mut cumulative_gas: u64 = 0;
        for tx in txs {
            let bytes = tx.as_bytes();
            // Hash once up front: grouped txs already paid for this
            // hash (preverify key), and skipped txs need it for the
            // outcome record. Skips are rare in honest traffic, so
            // the extra hash on a dropped tx costs nothing real.
            let tx_hash = Hasher::hash_one(Domain::Transaction, bytes);
            let Some(ctx) = parse_tx_context(bytes) else {
                skipped.push((tx_hash, TxSkipReason::Malformed));
                continue;
            };
            let Some(module_id) = parse_module_id(bytes) else {
                skipped.push((tx_hash, TxSkipReason::Malformed));
                continue;
            };
            let Some(module) = self.modules[module_id as usize].as_ref() else {
                skipped.push((tx_hash, TxSkipReason::UnknownModule));
                continue;
            };
            // A self-authenticating module (the EVM) recovers its real
            // sender and nonce from its own payload, so the envelope's
            // declared pair is a mempool ordering hint and nothing more.
            // Driving the executor's account-indexed nonce state from it
            // would let anyone advance *another* account's counter: wrap
            // your own valid signed payload in a victim's envelope and
            // the victim's `executed_nonce` moves while their balance and
            // their EVM account nonce never do. The executor's nonce gate
            // therefore applies only to modules that authenticate from
            // the envelope; a self-authenticating module enforces its own
            // nonce during execution.
            let self_authenticating = module.authenticates_sender();
            // H5: each tx's nonce must equal the next expected nonce
            // for its sender; txs that fail are skipped and do not
            // advance the counter. u64::MAX is reserved — skipping it
            // here keeps `expected + 1` below overflow-free (a MAX
            // nonce would wrap the counter to 0 and reopen the
            // sender's whole nonce range to replay).
            let expected = local_nonce.next_expected(&ctx.sender).unwrap_or(0);
            if !self_authenticating && (ctx.nonce != expected || ctx.nonce == u64::MAX) {
                skipped.push((tx_hash, TxSkipReason::StaleNonce));
                continue;
            }
            if self
                .check_envelope_auth(bytes, &ctx, module_id, module.as_ref(), Some(preverify_cache))
                .is_err()
            {
                skipped.push((tx_hash, TxSkipReason::BadSignature));
                continue;
            }
            let payload = module_payload(bytes);
            let gas = module.estimate_gas(payload);
            if cumulative_gas.saturating_add(gas) > self.block_gas_limit {
                skipped.push((tx_hash, TxSkipReason::GasLimit));
                continue;
            }
            // Fee floor gate: the envelope's fee field is
            // sender-declared, so `min_fee` is enforced here — a
            // pure predicate, no ledger effect. The charge itself
            // moved to dispatch (`execute_block`) so it observes the
            // balance effects of every earlier tx; charging it here
            // would debit all senders before ANY module ran — a
            // later tx's fee failing though an earlier tx funded
            // the account is exactly the reordering this plan
            // exists to eliminate. Self-funded modules (EVM: gas is
            // the fee) are exempt either way.
            if !module.pays_own_fee() && ctx.fee < self.min_fee {
                skipped.push((tx_hash, TxSkipReason::FeeFloor));
                continue;
            }
            // Advance the local nonce counter for this sender —
            // provisionally: a dispatch-time fee failure rewinds it
            // (see `execute_block`) so a failed charge never consumes
            // the nonce. `expected + 1` cannot overflow: the
            // reserved-nonce skip above keeps `expected ≤ u64::MAX -
            // 1`. Self-authenticating modules keep their own account
            // nonce (enforced inside the module), so the executor
            // tracks nothing for them.
            if !self_authenticating {
                local_nonce.bump(ctx.sender, expected + 1);
            }
            cumulative_gas = cumulative_gas.saturating_add(gas);
            // Zero-copy: the payload is borrowed from the block tx
            // bytes; the full-tx hash is the same key `ingest_tx`
            // used for the preverify cache.
            match runs.last_mut() {
                Some((run_module, run)) if *run_module == module_id => {
                    run.push(PlannedTx { ctx, payload, tx_hash });
                }
                _ => runs.push((module_id, vec![PlannedTx { ctx, payload, tx_hash }])),
            }
        }
        runs
    }

    /// Charge each tx's fee and execute it, interleaved per tx, in
    /// run order. The charge lives at dispatch time — not in
    /// `plan_block_runs` — because it debits the shared ledger and
    /// must observe every earlier tx's effects; within a run the
    /// charge→execute interleave extends that guarantee to same-run
    /// predecessors, so a tx whose sender's balance was consumed by
    /// an earlier same-run tx (e.g. a fill that debited the maker)
    /// is fee-rejected rather than executed on a stale balance.
    /// This is exact sequential semantics for every module that
    /// pays an executor fee. It costs nothing in practice: the only
    /// module with a real batch dispatch path (EVM: parallel sender
    /// recovery) is self-funded and never enters this path — for
    /// every other module `handle_batch` is the serial `handle`
    /// loop this loop performs anyway. A module that later adds a
    /// genuine batch override still gets it — but only for
    /// self-funded runs, where no executor fee interleaves.
    ///
    /// Returns the executed txs plus their results, index-aligned
    /// for `record_group_outcomes`. `broken_nonce` records the
    /// first failed-charge nonce per sender: under sequential
    /// semantics a failed charge consumes no nonce, so that
    /// sender's later txs are unreachable this block — they're
    /// skipped `StaleNonce` rather than executed with a gap.
    /// `local_nonce` is rewound to the failed nonce so
    /// `executed_nonce` reflects the last consumed nonce + 1 and
    /// the failed tx stays retryable. Self-funded modules (EVM:
    /// gas is the fee) skip charging entirely — the caller
    /// dispatches them as one batch.
    pub(crate) fn charge_and_execute_run<'b>(
        &self,
        run: Vec<GroupedTx<'b>>,
        module: &dyn Module,
        local_nonce: &mut BlockNonces<'_>,
        broken_nonce: &mut HashMap<primitives::Address, u64>,
        dispatch_skipped: &mut Vec<(Hash, TxSkipReason)>,
    ) -> (Vec<GroupedTx<'b>>, Vec<Result<Vec<Event>, ExecError>>) {
        let fee_module = self.fee_module.and_then(|id| self.modules[usize::from(id)].as_ref());
        let self_authenticating = module.authenticates_sender();
        let mut executed = Vec::with_capacity(run.len());
        let mut results = Vec::with_capacity(run.len());
        for entry in run {
            let ctx = entry.ctx;
            if let Some(&broken) = broken_nonce.get(&ctx.sender)
                && ctx.nonce >= broken
            {
                dispatch_skipped.push((entry.tx_hash, TxSkipReason::StaleNonce));
                continue;
            }
            let charged = fee_module.is_none_or(|m| m.charge_fee(&ctx).is_ok());
            if !charged {
                dispatch_skipped.push((entry.tx_hash, TxSkipReason::FeeCharge));
                broken_nonce.entry(ctx.sender).or_insert(ctx.nonce);
                if !self_authenticating {
                    local_nonce.bump(ctx.sender, ctx.nonce);
                }
                continue;
            }
            results.push(module.handle(&ctx, entry.payload));
            executed.push(entry);
        }
        (executed, results)
    }

    /// Dispatch one run to its module and return per-tx results.
    ///
    /// Phase E: zero-copy payload handling. If every tx in the run
    /// has a cached sender, borrowed `PreverifiedTx`s are built
    /// straight from the block bytes and the run goes through the
    /// preverified path — parallel when it clears
    /// `parallel_threshold` (speculation is sound inside a run:
    /// the planner only batches contiguous same-module txs). If any
    /// sender is uncached, the fallback `handle_batch` path is used
    /// directly — no preverified Vec constructed, no wasted clones.
    /// (Previously the preverified Vec was always built, cloning
    /// payloads for txs the fallback path never used.)
    pub(crate) fn dispatch_run(
        &self,
        module: &dyn Module,
        group: &[GroupedTx<'_>],
        preverify_cache: &mut HashMap<Hash, [u8; 20]>,
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        let all_cached = group.iter().all(|t| preverify_cache.contains_key(&t.tx_hash));
        if !all_cached {
            let batch: Vec<(TxContext, &[u8])> = group.iter().map(|t| (t.ctx, t.payload)).collect();
            return module.handle_batch(&batch);
        }
        // All senders are pre-recovered — build borrowed
        // `PreverifiedTx`s straight from the block bytes.
        let preverified: Vec<PreverifiedTx<'_>> = group
            .iter()
            .map(|t| PreverifiedTx {
                raw: t.payload,
                sender: preverify_cache.remove(&t.tx_hash).unwrap_or([0u8; 20]),
            })
            .collect();
        // Each tx keeps its own authenticated envelope context —
        // `ctxs[i]` pairs with `preverified[i]`. Passing `group[0].0`
        // here previously executed the whole group under the first
        // tx's identity.
        let ctxs: Vec<TxContext> = group.iter().map(|t| t.ctx).collect();
        if group.len() >= self.parallel_threshold {
            module.handle_batch_parallel_preverified(&ctxs, &preverified)
        } else {
            module.handle_batch_preverified(&ctxs, &preverified)
        }
    }

    /// Execute a finalized block: call `begin_block`, plan contiguous
    /// same-module runs (preserving committed block order), charge
    /// fees + dispatch each run via `handle_batch`, call `end_block`,
    /// compute the state root.
    ///
    /// Execution order is the committed block order at run
    /// granularity: a new run starts when the module id changes, so
    /// a tx always observes the ledger effects of every earlier
    /// cross-module tx — and of its own fee charge, which happens at
    /// dispatch time rather than during planning. Fee-paying runs
    /// execute charge→handle per tx (`charge_and_execute_run`), so
    /// the same-run guarantee is exact: each tx's fee observes all
    /// earlier effects, same module or not. Self-funded runs keep
    /// the module's batch dispatch (`handle_batch*`), preserving
    /// batch-optimized paths (EVM parallel sender recovery,
    /// pre-verified senders) where no executor fee interleaves.
    /// This replaces the old sort-by-module grouping, which was
    /// deterministic but not faithful to committed order — modules
    /// share one balance ledger, so "group then execute" was not
    /// equivalent to sequential execution.
    pub(crate) fn execute_block(&self, block: &FinalizedBlock) -> Hash {
        // Coordinated halt: above the scheduled height the chain is
        // frozen — no begin/handle/end_block, no fee charge, no
        // attendance record. The returned root is the state at the
        // halt height, so every replica freezes on identical state.
        // Deterministic across live and replayed execution (the
        // schedule lives in module state, journaled like any other).
        if let Some(halt) = self.halt_height()
            && block.height.value() > halt
        {
            return self.state_root_at(halt);
        }

        // Single lock acquisition for the events vector: clear at start,
        // extend after execution. The lock is released between the clear
        // and the extend because module execution can take milliseconds
        // and we don't want to hold the lock during that time. The
        // clear is here only to discard stale events from a previous
        // block; the extend publishes this block's events.
        primitives::sync::lock_state(&self.events).clear();

        // H5 fix: cross-block nonce continuity. Verify that each
        // sender's first tx in this block continues from the last
        // executed nonce. This closes the replay window across blocks
        // — a tx with a stale nonce from a previous block is rejected
        // here, not just in the mempool.
        //
        // We snapshot the committed nonce state as an `Arc` clone —
        // O(1), no map copy — and apply this block's advances into a
        // `BlockNonces` delta so a block pays O(touched senders), not
        // O(every account that ever transacted). The folded root
        // travels with the delta and lands committed at block end.
        let nonce_base: Arc<ExecutedNonces> = {
            let executed = primitives::sync::lock_state(&self.executed_nonce);
            Arc::clone(&executed)
        };
        let mut local_nonce = BlockNonces::new(&nonce_base);

        // begin_block for all modules — via `begin_block_ctx` so the
        // consensus-committed execution context (timestamp,
        // beneficiary, gas limit) reaches modules that consume it.
        for module in self.modules.iter().flatten() {
            module.begin_block_ctx(block.height, &block.context);
        }

        // Move the preverify cache out before the grouping loop —
        // the loop consults it to skip re-verifying envelope
        // signatures that were already verified at mempool
        // admission, and the dispatch loop below consumes it.
        // (`mem::take` swaps in an empty map — zero-copy, one lock
        // acquisition for the whole block.)
        let mut preverify_cache =
            std::mem::take(&mut *primitives::sync::lock_state(&self.preverify_cache));

        let mut skipped: Vec<(Hash, TxSkipReason)> = Vec::new();
        let mut runs =
            self.plan_block_runs(&block.txs, &mut local_nonce, &preverify_cache, &mut skipped);

        // Record finalized outcomes for txs that never reached a
        // module. These are the only outcomes a submitter can get
        // for a gate-dropped tx — the mempool no longer holds it
        // (it was proposed), so without this record a skipped tx is
        // indistinguishable from "still in flight" forever.
        {
            let mut outcomes = primitives::sync::lock_state(&self.tx_outcomes);
            for (hash, reason) in skipped {
                outcomes.record(hash, TxOutcome::Skipped { reason });
            }
        }

        // Execute each contiguous same-module run in committed block
        // order — sequential cross-module semantics. Fee-paying runs
        // interleave charge→execute per tx (`charge_and_execute_run`);
        // self-funded runs dispatch as one batch.
        let mut block_events: Vec<Event> = Vec::new();
        let mut broken_nonce: HashMap<primitives::Address, u64> = HashMap::new();
        let mut dispatch_skipped: Vec<(Hash, TxSkipReason)> = Vec::new();

        for (module_id, run) in &mut runs {
            let Some(module) = self.modules[*module_id as usize].as_ref() else {
                continue; // unknown module — skip
            };

            if module.pays_own_fee() {
                // Self-funded module (EVM: gas is the fee) — no
                // executor charge interleaves, so the run takes the
                // module's real batch dispatch (preverified /
                // parallel sender recovery).
                let group: Vec<GroupedTx<'_>> = std::mem::take(run);
                if group.is_empty() {
                    continue;
                }
                let results = self.dispatch_run(module.as_ref(), &group, &mut preverify_cache);
                self.record_group_outcomes(&group, results, &mut block_events);
            } else {
                // Fee-paying module — charge each tx and execute it
                // immediately so the next tx's charge observes this
                // tx's ledger effects (exact sequential semantics).
                let (group, results) = self.charge_and_execute_run(
                    std::mem::take(run),
                    module.as_ref(),
                    &mut local_nonce,
                    &mut broken_nonce,
                    &mut dispatch_skipped,
                );
                self.record_group_outcomes(&group, results, &mut block_events);
            }
        }
        if !dispatch_skipped.is_empty() {
            let mut outcomes = primitives::sync::lock_state(&self.tx_outcomes);
            for (hash, reason) in dispatch_skipped {
                outcomes.record(hash, TxOutcome::Skipped { reason });
            }
        }
        // Publish all events from this block in one lock acquisition.
        primitives::sync::lock_state(&self.events).extend(block_events);

        // end_block for all modules — same context as begin_block.
        // Module scheduled effects (liquidation sweeps, epoch work)
        // emit events that land in the block log AFTER every tx
        // event — same publish path, one extension.
        let end_block_events: Vec<Event> = self
            .modules
            .iter()
            .flatten()
            .flat_map(|module| module.end_block_ctx(block.height, &block.context))
            .collect();
        if !end_block_events.is_empty() {
            primitives::sync::lock_state(&self.events).extend(end_block_events);
        }

        // Attendance delivery, inside execute_block so journal
        // replay derives identical effects (see the trait doc).
        for module in self.modules.iter().flatten() {
            module.record_block_attendance(block.height, &block.signers);
        }

        // Compute the state root: ONE canonical commitment (C8) over
        // every module's canonical root plus the executed-nonce
        // root — the same definition `export_snapshot` /
        // `import_snapshot` use, so block, snapshot, and replay
        // roots always agree. `local_nonce` already holds the
        // post-block root (folded incrementally by `bump`), so this
        // block pays O(touched senders), not a full scan of every
        // account that ever transacted.
        let mut module_roots = Vec::new();
        for module in self.modules.iter().flatten() {
            module_roots.push(module.state_root());
        }

        // Push the fresh nonce anchors into the mempool — the live
        // update path the pool's `executed_nonces` anchoring was
        // built for. `refresh_anchors` also prunes pooled entries
        // whose nonce this block consumed (a losing same-nonce
        // candidate can never execute), so stale entries don't
        // linger until a size-cap eviction reaches them. The lookup
        // reads through the block's delta — the effective post-block
        // value for every pooled sender.
        primitives::sync::lock_state(&self.mempool)
            .refresh_anchors(|sender| local_nonce.next_expected(sender));

        // H4/H5: persist the updated nonce map. The delta applies in
        // place (`Arc::make_mut` — the base snapshot is dropped first
        // so the committed map is uniquely owned and the update is
        // O(delta), not a copy) in a single lock acquisition so the
        // next block's `execute_block` and the mempool's `ingest_tx`
        // see the updated state.
        let (nonce_delta, nonce_root) = local_nonce.finish();
        drop(nonce_base);
        {
            let mut committed = primitives::sync::lock_state(&self.executed_nonce);
            let committed = Arc::make_mut(&mut committed);
            committed.map.extend(nonce_delta);
            committed.root = nonce_root;
        }

        canonical_state_root(module_roots, nonce_root)
    }

    /// Record the finalized outcome for every tx in one module
    /// group and append the executed txs' events to `block_events`.
    /// `results` is index-aligned with `group` (every
    /// `handle_batch*` contract returns one result per input tx):
    /// `Ok` carries the module's events — which may still report
    /// per-leg failures for batch ops; `Err` means the module
    /// rejected the whole tx (fee charged, nonce consumed — a
    /// revert, not a skip). One lock acquisition per group keeps
    /// the outcome store off the per-tx path.
    pub(crate) fn record_group_outcomes(
        &self,
        group: &[GroupedTx<'_>],
        results: Vec<Result<Vec<Event>, ExecError>>,
        block_events: &mut Vec<Event>,
    ) {
        let mut outcomes = primitives::sync::lock_state(&self.tx_outcomes);
        for (t, result) in group.iter().zip(results) {
            let outcome = match result {
                Ok(events) => {
                    block_events.extend(events.iter().cloned());
                    TxOutcome::Executed { events, error: None }
                }
                Err(e) => TxOutcome::Executed { events: Vec::new(), error: Some(format!("{e:?}")) },
            };
            outcomes.record(t.tx_hash, outcome);
        }
    }
}
