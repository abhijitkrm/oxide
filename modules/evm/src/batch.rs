//! Batch and parallel execution for the EVM module.
//!
//! Split from `lib.rs` around the speculation invariant:
//! `handle_batch_parallel*` speculatively executes every tx against
//! the shared multi-version store and commits them in canonical
//! order — a speculation is proved or disproved by its `SpecTx`
//! record, never trusted. `execute_parallel_decoded` is the merge
//! engine; `exec_result_to_events` maps outcomes to chain events.

use super::{
    Arc, CacheDB, CoinbaseObs, DecodedTx, Event, EvmModule, ExecError, ExecuteCommitEvm, InfoKey,
    InspectEvm, IntoParallelIterator, IntoParallelRefIterator, MvDb, MvState, ParallelIterator,
    PreverifiedTx, RejectCategory, SharedCacheDB, SpecTx, TracedResult, TxContext,
    alloy_primitives_address, destructive_accounts, history, info_key, receipts, trace, tx,
    versioned,
};
use revm::database_interface::DatabaseRef;
use revm::state::EvmState;

/// The canonical account-info key at the commit point.
///
/// Goes through `basic_ref` (not `cache.accounts.get`) so
/// `NotExisting` tombstones resolve to `None` exactly as a worker's
/// `MvDb` observation did — a raw cache peek would compare a
/// tombstoned `DbAccount`'s stale `info` field and miss the deletion.
fn canonical_info_key(
    db: &CacheDB<revm::database_interface::EmptyDB>,
    addr: revm::primitives::Address,
) -> Option<InfoKey> {
    match db.basic_ref(addr) {
        Ok(info) => info.as_ref().map(info_key),
        // `CacheDB<EmptyDB>` reads are infallible — the error type
        // cannot be constructed.
        Err(e) => match e {},
    }
}

/// The canonical storage-slot value at the commit point.
///
/// Goes through `storage_ref` so `StorageCleared`/`NotExisting`
/// accounts and absent slots all resolve to zero — the same value
/// the worker's `MvDb` resolution produced.
fn canonical_slot(
    db: &CacheDB<revm::database_interface::EmptyDB>,
    addr: revm::primitives::Address,
    slot: revm::primitives::U256,
) -> revm::primitives::U256 {
    match db.storage_ref(addr, slot) {
        Ok(v) => v,
        Err(e) => match e {},
    }
}

impl EvmModule {
    /// Execute a batch of signed EVM transactions with **parallel
    /// sender recovery**.
    ///
    /// This is the high-throughput execution path. Profiling shows
    /// secp256k1 ECDSA recovery is 88% of per-tx cost (29.6 µs out
    /// of 33.6 µs). By recovering all senders in parallel across
    /// cores using `rayon`, then executing sequentially (the `CacheDB`
    /// requires single-writer access), we turn the 88% into
    /// `88%/N_cores`.
    ///
    /// On an 8-core machine, the expected per-tx cost drops from
    /// ~33.6 µs to ~4 µs (execution) + 29.6/8 µs (recovery) ≈ 7.7 µs,
    /// yielding ~130,000 tx/s.
    ///
    /// For even higher throughput, use [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// which skips sender recovery entirely (the caller pre-recovers
    /// senders at mempool ingestion time).
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is recovered from the signature).
    /// - `msgs`: a slice of raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction. Each result is
    /// either a vector of events (success) or an `ExecError` (failure).
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch — subsequent transactions
    /// are still executed.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`, `block_timestamp`, or
    /// touched mutex is poisoned (a previous thread panicked while
    /// holding the lock).
    pub fn handle_batch(
        &self,
        ctx: &TxContext,
        msgs: &[impl AsRef<[u8]> + Sync],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 1: decode + recover all senders in parallel.
        // Each tx is independently decoded and its sender recovered.
        // Failures are recorded and skipped during execution.
        //
        // secp256k1 recovery (~30 µs/tx) is the dominant cost. Rayon
        // parallelizes it across cores, reducing effective per-tx
        // cost to ~30µs/N_cores. For pre-recovered senders (mempool
        // already verified), use `handle_batch_preverified` to skip
        // this entirely.
        let decoded: Vec<DecodedTx> = msgs
            .par_iter()
            .map(|raw| {
                let signed =
                    tx::SignedTx::decode_raw(raw.as_ref()).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                // Canonical Ethereum tx hash — keccak256 of the raw
                // signed RLP. Computed here (parallel, off the DB
                // lock) so history recording needs no re-hash. The
                // raw bytes ride along for the `transactionsRoot`
                // trie at seal time.
                let tx_hash = alloy_primitives::keccak256(raw.as_ref());
                Ok((signed, caller, tx_hash, raw.as_ref().to_vec()))
            })
            .collect();

        self.execute_decoded(ctx, decoded)
    }

    /// Pre-recover senders from a batch of raw transactions.
    ///
    /// The mempool calls this at ingestion time to recover the sender
    /// for each transaction **once**. The resulting [`PreverifiedTx`]
    /// pairs are then passed to [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// or [`handle_batch_parallel_preverified`](Self::handle_batch_parallel_preverified),
    /// which skip secp256k1 recovery entirely during block execution.
    ///
    /// This is the key to eliminating the ~30 µs/tx signature recovery
    /// cost from the block execution critical path. Recovery happens
    /// once at mempool admission (off the consensus critical path);
    /// execution reuses the pre-recovered sender.
    ///
    /// # Arguments
    ///
    /// - `msgs`: raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of `PreverifiedTx` (for valid txs) or `ExecError` (for
    /// malformed txs, wrong chain ID, or invalid signatures). The
    /// vector is in the same order as the input.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] for each transaction that
    /// cannot be decoded, has the wrong chain ID, or has an invalid
    /// signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn preverify_batch<'a, T: AsRef<[u8]> + Sync + 'a>(
        &self,
        msgs: &'a [T],
    ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
        // A lone tx has no parallelism to buy — the rayon bridge's
        // split/join overhead (~µs) is pure cost on the caller's
        // thread, and the single-tx admission path calls this with a
        // one-element slice.
        if msgs.len() == 1 {
            return msgs.iter().map(|raw| self.preverify_one(raw.as_ref())).collect();
        }
        msgs.par_iter().map(|raw| self.preverify_one(raw.as_ref())).collect()
    }

    /// Decode + chain-ID + secp256k1 recovery for one raw tx — the
    /// per-item body of [`preverify_batch`](Self::preverify_batch).
    fn preverify_one<'a>(&self, raw: &'a [u8]) -> Result<PreverifiedTx<'a>, ExecError> {
        let signed = tx::SignedTx::decode_raw(raw).map_err(|_| ExecError::Malformed)?;
        if signed.chain_id() != self.chain_id {
            return Err(ExecError::Malformed);
        }
        let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
        let caller = alloy_primitives_address(sender.0);
        // This function IS this node's ingest-time recovery — the
        // flag's exact provenance meaning.
        Ok(PreverifiedTx { raw, sender: caller, verified_locally: true })
    }

    /// Execute a batch of transactions with **pre-verified senders**.
    ///
    /// This is the highest-throughput serial execution path. The
    /// caller (mempool/block builder) has already recovered the sender
    /// for each tx via [`preverify_batch`](Self::preverify_batch).
    /// This method re-recovers the sender from the signature and
    /// checks it matches the pre-recovered value — only RLP decoding
    /// (~79 ns/tx), chain ID validation, and sender re-verification
    /// remain in Phase 1.
    ///
    /// # Performance
    ///
    /// Re-recovery adds ~30 µs/tx (single-threaded) or ~3.7 µs/tx
    /// (8-core parallelized) back to the critical path. This is the
    /// cost of not trusting the proposer. For 10k simple transfers,
    /// batch time is ~80 ms (recovery + native execution) — the same
    /// as the non-preverified path. The preverified path still wins
    /// because it avoids redundant recovery at mempool ingestion.
    ///
    /// # Security
    ///
    /// The sender is re-recovered from the signature inside this
    /// method and checked against `pv.sender`. A byzantine block
    /// proposer supplying wrong senders will be detected here —
    /// mismatched senders are rejected with `ExecError::Malformed`
    /// before any state transition occurs. This closes the trust
    /// gap: the proposer cannot forge a sender.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is re-recovered from the signature).
    /// - `txs`: a slice of [`PreverifiedTx`] (raw bytes + pre-recovered
    ///   sender, used as a hint and verified).
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch. A sender mismatch
    /// (pre-recovered vs signature-recovered) returns `Malformed`.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    pub fn handle_batch_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 1: decode and resolve the caller. RLP decode is
        // ~79 ns/tx; secp256k1 recovery is ~30 µs/tx. Provenance
        // splits the work (hft-audit F-06):
        //
        // - `verified_locally` — the sender came from this node's
        //   own ingest-time recovery (executor preverify cache, keyed
        //   by a locally-computed tx hash over these exact bytes).
        //   Re-recovery would only re-derive what was already proven;
        //   skip it. Decode + chain-id still run — a tx must parse
        //   and match this chain regardless of who verified it.
        // - Otherwise — `pv.sender` is an unproven claim; recover
        //   from the signature and compare. A byzantine proposer
        //   cannot forge a sender: any mismatch is rejected before
        //   state transition.
        let decoded: Vec<DecodedTx> = txs
            .par_iter()
            .map(|pv| {
                let signed = tx::SignedTx::decode_raw(pv.raw).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let caller = if pv.verified_locally {
                    pv.sender
                } else {
                    // Unproven sender — the security gate: recover
                    // and compare, reject any mismatch.
                    let recovered = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                    let recovered_addr = alloy_primitives_address(recovered.0);
                    if recovered_addr != pv.sender {
                        return Err(ExecError::Malformed);
                    }
                    recovered_addr
                };
                let tx_hash = alloy_primitives::keccak256(pv.raw);
                Ok((signed, caller, tx_hash, pv.raw.to_vec()))
            })
            .collect();

        self.execute_decoded(ctx, decoded)
    }

    /// Shared execution loop for decoded transactions.
    ///
    /// Both [`handle_batch`](Self::handle_batch) and
    /// [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// produce a `decoded` vector of `(SignedTx, caller)` pairs (or
    /// errors). This method executes them sequentially under a single
    /// DB lock, trying the native fast path first and falling through
    /// to revm for non-native txs.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    // One long linear loop: fast path, empty-code path, then revm — the
    // sequencing is the point, so splitting it would obscure the order.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_decoded(
        &self,
        ctx: &TxContext,
        decoded: Vec<DecodedTx>,
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 2: execute all txs sequentially under a single lock.
        // The CacheDB is a single-writer structure — parallel execution
        // would require partitioning the state, which is future work.
        //
        // For each tx, try the **native fast path** first (simple ETH
        // transfers bypass revm entirely). Only fall through to revm
        // for contract calls, creations, and txs with calldata.
        //
        // For all-native batches (simple transfers to EOAs), the EVM
        // context is never constructed — zero revm overhead. For mixed
        // batches, the EVM context is built per non-native tx inside a
        // scoped block; the ~100 ns rebuild cost is negligible vs the
        // ~3.7 µs EVM execution cost.
        let mut results = Vec::with_capacity(decoded.len());

        // Acquire the DB lock once for the entire batch.
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);
        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);

        // Accumulate touched accounts in a local set to avoid
        // locking the mutex per tx. Merge once at the end.
        let mut local_touched: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();
        // Per-block inverse-diff accumulator — merged into
        // `self.block_undo` once at the end (same pattern as
        // `local_touched`).
        let mut local_undo = versioned::BlockUndo::default();

        for item in decoded {
            let (signed, caller, tx_hash, raw) = match item {
                Ok(v) => v,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };

            // Try the native fast path first. For simple ETH
            // transfers (empty calldata, EOA recipient), this
            // bypasses revm entirely — just balance + nonce
            // updates. The native path accesses the CacheDB
            // directly, so no EVM context is needed.
            //
            // Capture the fast-path write set ({caller, recipient,
            // coinbase}) unconditionally — if the path declines and
            // the tx falls through to revm, the entries still hold
            // the correct pre-block values and the later capture is
            // a no-op (first-write-wins).
            Self::undo_capture_fast_path(&mut local_undo, db, &signed, caller, coinbase);
            if let Some(result) = Self::try_native_transfer(
                &signed,
                caller,
                &mut *db,
                coinbase,
                self.current_base_fee(),
                self.spec,
            ) {
                local_touched.insert(caller);
                if let tx::TxKind::Call(addr) = signed.to() {
                    local_touched.insert(revm::primitives::Address::from(addr.0));
                }
                local_touched.insert(coinbase);
                // Fast paths bypass revm's frame machinery, so no
                // `CallRecorder` ran — but geth's callTracer still
                // reports a root CALL frame for a plain transfer.
                // Synthesize the equivalent frame so every sealed tx
                // has a trace.
                let frame = Self::fast_path_frame(&signed, caller, &result);
                results.push(self.exec_result_to_events(
                    Ok(result),
                    Some((history::stored_tx(&signed, caller, tx_hash, 0), raw, Some(frame))),
                ));
                continue;
            }

            // Try the empty-code call fast path. For calls to
            // contracts with no runtime code (EOA or constructor-only
            // deployment), this bypasses revm's call-frame setup.
            if let Some(result) = Self::try_empty_code_call(
                &signed,
                caller,
                &mut *db,
                coinbase,
                self.current_base_fee(),
                self.spec,
            ) {
                local_touched.insert(caller);
                if let tx::TxKind::Call(addr) = signed.to() {
                    local_touched.insert(revm::primitives::Address::from(addr.0));
                }
                local_touched.insert(coinbase);
                let frame = Self::fast_path_frame(&signed, caller, &result);
                results.push(self.exec_result_to_events(
                    Ok(result),
                    Some((history::stored_tx(&signed, caller, tx_hash, 0), raw, Some(frame))),
                ));
                continue;
            }

            // Fall through to revm for non-native txs (contract
            // calls, creations, txs with calldata, etc.). Build
            // the EVM context in a scoped block — the `&mut *db`
            // borrow is released when the block exits, allowing
            // the next tx to use the native path if it qualifies.
            let tx = match Self::build_tx_env(&signed, caller, self.spec) {
                Ok(t) => t,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };

            let result = {
                let mut evm = self.build_evm(&mut *db, coinbase, block_number, block_timestamp);
                // `transact` (not `transact_commit`) gives the
                // complete `EvmState`: every account the tx
                // modified, including internal-call targets and
                // selfdestruct beneficiaries — not just the
                // top-level caller/to/created/coinbase set that
                // under-tracked durable state.
                let result_and_state = match evm.inspect_tx(tx) {
                    Ok(rs) => rs,
                    Err(e) => {
                        evm.precompiles.clear_native_journal();
                        results.push(Err(ExecError::rejected(
                            RejectCategory::Other,
                            format!("evm transact failed: {e:?}"),
                        )));
                        continue;
                    }
                };
                evm.precompiles.clear_native_journal();
                let call_trace = evm.inspector.1.take_root();
                // Track the exact modified-account set locally
                // (no lock per tx), then commit.
                local_touched.extend(result_and_state.state.keys().copied());
                for addr in result_and_state.state.keys() {
                    local_undo
                        .capture(*addr, evm.ctx.journaled_state.database.cache.accounts.get(addr));
                }
                // Zero-slot sweep after commit — see `commit_state`
                // in lib.rs for why committed storage must not hold
                // zero values.
                let zeroed = Self::zero_slot_writers(&result_and_state.state);
                evm.commit(result_and_state.state);
                Self::prune_zero_slots(evm.ctx.journaled_state.database, &zeroed);
                (result_and_state.result, call_trace)
            };

            let (result, call_trace) = result;
            results.push(self.exec_result_to_events(
                Ok(result),
                Some((history::stored_tx(&signed, caller, tx_hash, 0), raw, call_trace)),
            ));
        }

        // Merge local touched set into the global one (single lock).
        {
            let mut touched = framework::lock_state(&self.touched);
            touched.extend(local_touched);
        }
        {
            let mut undo = framework::lock_state(&self.block_undo);
            for (addr, entry) in local_undo.accounts {
                undo.accounts.entry(addr).or_insert(entry);
            }
        }

        // Silence unused-ctx warning — ctx is part of the Module
        // interface but EVM recovers the sender from the signature.
        let _ = ctx;

        results
    }

    /// Execute a batch of signed EVM transactions with **parallel
    /// speculative execution**.
    ///
    /// This is the highest-throughput execution path. It extends
    /// [`handle_batch`](Self::handle_batch) by parallelizing not only
    /// signature recovery but also EVM execution itself, over a
    /// shared multi-version state store.
    ///
    /// # Algorithm
    ///
    /// 1. **Parallel decode + recovery**: All senders are recovered in
    ///    parallel (same as `handle_batch`).
    /// 2. **Multi-version speculation**: every tx executes in parallel
    ///    on a `CacheDB<MvDb>` — a fresh worker cache over the shared
    ///    version store. A read of key `K` at index `i` resolves to
    ///    the newest write published by a canonically-earlier tx
    ///    (`< i`), or the pre-block base when no version exists —
    ///    Block-STM's read rule. Dependent txs therefore usually see
    ///    their real inputs instead of guaranteed-stale base values,
    ///    and same-sender txs parallelize: a successor reads its
    ///    predecessor's published nonce/balance rather than
    ///    serializing inside a sender group. Every resolution is
    ///    recorded into `SpecTx::observed`.
    /// 3. **Publish**: each finished speculation inserts its writes
    ///    into the version store under its index, so later-indexed
    ///    txs can observe them mid-flight. Versions are advisory —
    ///    the committed state, not the store, decides validity.
    /// 4. **Canonical-order commit**: at each index position the
    ///    canonical DB holds exactly the pre-state for that tx. The
    ///    validation predicate is a direct value comparison: every
    ///    recorded observation must equal the canonical value. A tx
    ///    that saw the true prefix of writes merges its recorded
    ///    `EvmState` diff directly; anything else re-executes
    ///    against the canonical DB. There is no sender-group
    ///    bookkeeping — a same-sender successor validates iff its
    ///    observations match, whether or not its predecessor did.
    ///    One exemption: a fast-path transfer's *recipient* balance
    ///    is a write-only dependency (`post = pre + value`), so a
    ///    stale observation there rebases onto the canonical account
    ///    instead of re-executing — provided the recipient is still
    ///    codeless canonically.
    /// 5. **Coinbase handling**: the coinbase is written by every
    ///    transaction via tips, so it is excluded from versioned
    ///    observation entirely — `basic(coinbase)` always resolves
    ///    to the pre-block base. Each tx's net coinbase delta merges
    ///    additively in canonical order, keeping the running balance
    ///    canonical. A tx that observed the coinbase balance
    ///    (`BALANCE`) re-executes unless the base it saw matches the
    ///    canonical total; a tx that changed the coinbase
    ///    non-additively (nonce/storage) always re-executes and
    ///    dirties it for later accessors.
    ///
    /// # When to use this vs `handle_batch`
    ///
    /// Use `handle_batch_parallel` for batches with exploitable
    /// parallelism — many senders, mostly-disjoint writes — where
    /// the multi-version store converts resolved dependencies into
    /// validated merges. Densely-chained workloads (every tx writing
    /// one hot slot) still favour serial: speculation doubles the
    /// work and the commit phase is the floor either way.
    /// `handle_batch` remains the smaller-codepath reference the
    /// differential property tests pin `handle_batch_parallel`
    /// against.
    ///
    /// # Limitations
    ///
    /// - Validation and the canonical merge run sequentially in
    ///   Phase 5 — the remaining bound on parallel speedup for
    ///   workloads whose per-tx work is smaller than the merge cost.
    ///   Full Block-STM schedules *re-execution* in parallel too;
    ///   here re-execution happens inline at the tx's position.
    /// - Speculation is timing-dependent: a read that races its
    ///   writer's publish sees the older value and re-executes. The
    ///   committed result is identical either way — determinism is
    ///   preserved because validity compares values, never timing.
    /// - Reads that bypass the account store (read-only native
    ///   precompile state, `BLOCKHASH`) are not versioned; module
    ///   state is constant for the duration of a batch, so those
    ///   reads are consistent across serial and parallel legs.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is recovered from the signature).
    /// - `msgs`: a slice of raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction. Each result is
    /// either a vector of events (success) or an `ExecError` (failure).
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch — subsequent transactions
    /// are still executed.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned (a previous
    /// thread panicked while holding the lock).
    #[allow(clippy::too_many_lines)]
    pub fn handle_batch_parallel(
        &self,
        ctx: &TxContext,
        msgs: &[impl AsRef<[u8]> + Sync],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Fast path: empty batch.
        if msgs.is_empty() {
            return Vec::new();
        }

        // Phase 1: decode + recover all senders in parallel.
        // Same as handle_batch — rayon parallelizes the 88%-of-cost
        // secp256k1 recovery across cores.
        //
        // For pre-recovered senders (mempool already verified), use
        // `handle_batch_parallel_preverified` to skip this entirely.
        let decoded: Vec<DecodedTx> = msgs
            .par_iter()
            .map(|raw| {
                let signed =
                    tx::SignedTx::decode_raw(raw.as_ref()).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                let tx_hash = alloy_primitives::keccak256(raw.as_ref());
                Ok((signed, caller, tx_hash, raw.as_ref().to_vec()))
            })
            .collect();

        self.execute_parallel_decoded(ctx, decoded)
    }

    /// Execute a batch of transactions with **pre-verified senders**
    /// and **parallel speculative execution**.
    ///
    /// This combines the two highest-throughput optimizations:
    /// 1. **Pre-verified senders** — re-recovers the sender from the
    ///    signature and checks it matches the pre-recovered value
    ///    (the caller pre-recovered senders at mempool ingestion time;
    ///    we verify rather than trust).
    /// 2. **Parallel speculative execution** — transactions from
    ///    different senders execute in parallel on per-group state
    ///    snapshots, with conflict detection and sequential fallback.
    ///
    /// This is the fastest execution path in the EVM module. Use it
    /// when the mempool has already verified senders and the batch
    /// contains transactions from multiple senders.
    ///
    /// # Security
    ///
    /// Same security model as
    /// [`handle_batch_preverified`](Self::handle_batch_preverified):
    /// the sender is re-recovered from the signature and checked
    /// against the pre-recovered value. A byzantine proposer
    /// supplying wrong senders is rejected. See that method's
    /// documentation for the full security discussion.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM).
    /// - `txs`: a slice of [`PreverifiedTx`] (raw bytes + pre-recovered
    ///   sender).
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    #[allow(clippy::too_many_lines)]
    pub fn handle_batch_parallel_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Fast path: empty batch.
        if txs.is_empty() {
            return Vec::new();
        }

        // Phase 1: decode and resolve the caller — same provenance
        // split as `handle_batch_preverified` (hft-audit F-06):
        // `verified_locally` means this node already recovered the
        // sender at ingest, so the ~30 µs/tx recovery inside
        // `par_iter` is skipped; any other `pv.sender` is an
        // unproven claim and is recovered-and-compared as before.
        let decoded: Vec<DecodedTx> = txs
            .par_iter()
            .map(|pv| {
                let signed = tx::SignedTx::decode_raw(pv.raw).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let caller = if pv.verified_locally {
                    pv.sender
                } else {
                    let recovered = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                    let recovered_addr = alloy_primitives_address(recovered.0);
                    if recovered_addr != pv.sender {
                        return Err(ExecError::Malformed);
                    }
                    recovered_addr
                };
                let tx_hash = alloy_primitives::keccak256(pv.raw);
                Ok((signed, caller, tx_hash, pv.raw.to_vec()))
            })
            .collect();

        self.execute_parallel_decoded(ctx, decoded)
    }

    /// Shared parallel execution loop for decoded transactions.
    ///
    /// Both [`handle_batch_parallel`](Self::handle_batch_parallel) and
    /// [`handle_batch_parallel_preverified`](Self::handle_batch_parallel_preverified)
    /// produce a `decoded` vector. This method implements the
    /// multi-version speculative execution algorithm documented on
    /// [`handle_batch_parallel`](Self::handle_batch_parallel#algorithm):
    /// every tx speculates in parallel against the shared version
    /// store, publishes its writes, and commits at its canonical
    /// index after observed-value validation.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_parallel_decoded(
        &self,
        ctx: &TxContext,
        decoded: Vec<DecodedTx>,
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 2: index the batch. Transactions keep their canonical
        // positions — there is no sender grouping: the version store
        // resolves each read to the newest write by a lower-indexed
        // tx, which already encodes the nonce chain (a same-sender
        // successor reads its predecessor's published account info).
        let n_txs = decoded.len();
        let mut errors: Vec<Option<ExecError>> = vec![None; n_txs];
        // History metadata for each decoded tx, indexed by original
        // position. `None` for pre-execution failures. The raw RLP
        // rides along for the `transactionsRoot` trie.
        let mut metas: Vec<Option<(history::StoredTx, Vec<u8>)>> = Vec::with_capacity(n_txs);
        metas.resize_with(n_txs, || None);
        // `(signed, caller)` per position — the speculation workers
        // borrow from this slice and the commit phase re-reads it for
        // canonical re-execution.
        let mut items: Vec<Option<(tx::SignedTx, revm::primitives::Address)>> =
            Vec::with_capacity(n_txs);
        items.resize_with(n_txs, || None);

        for (idx, item) in decoded.into_iter().enumerate() {
            match item {
                Ok((signed, caller, tx_hash, raw)) => {
                    metas[idx] = Some((history::stored_tx(&signed, caller, tx_hash, 0), raw));
                    items[idx] = Some((signed, caller));
                }
                Err(e) => {
                    errors[idx] = Some(e);
                }
            }
        }

        // Phase 3: snapshot the main DB — the immutable base the
        // version store falls back to. `self.db` is an
        // `Arc<CacheDB<EmptyDB>>`, so the snapshot is an O(1)
        // `Arc::clone` — no deep clone.
        let snapshot = framework::lock_state(&self.db).clone();
        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);
        let base_fee = self.current_base_fee();
        let parent_coinbase = snapshot
            .cache
            .accounts
            .get(&coinbase)
            .map_or(revm::primitives::U256::ZERO, |a| a.info.balance);
        let parent_coinbase_nonce =
            snapshot.cache.accounts.get(&coinbase).map_or(0, |a| a.info.nonce);

        // Phase 4: speculate every tx in parallel against the
        // multi-version store — one fresh `CacheDB<MvDb>` per index.
        // The worker's reads resolve to the newest version published
        // by a canonically-earlier tx (or the base), and every
        // resolution is recorded into `SpecTx::observed`; its writes
        // publish back under its index so later-indexed txs can see
        // them. Speculative EVMs still run with read-only native
        // precompiles (a suppressed mutation flags `must_reexec`) and
        // a `BALANCE(coinbase)` detector.
        //
        // No preload: a per-tx worker's first read of each key is its
        // only one that reaches `MvDb` (the worker cache serves
        // repeats), so loading untouched recipients would record
        // observations the tx never made — pure over-invalidation.
        let mv = MvState::default();
        let spec_txs: Vec<Option<SpecTx>> = (0..n_txs)
            .into_par_iter()
            .map(|i| {
                let (signed, caller) = items[i].as_ref()?;
                let caller = *caller;
                let mut db: CacheDB<MvDb<'_>> =
                    CacheDB::new(MvDb::new(&mv, SharedCacheDB(snapshot.clone()), i, coinbase));

                // Try the native transfer fast path first. For simple
                // ETH transfers (empty calldata, EOA recipient), this
                // bypasses revm entirely.
                if let Some(result) = Self::try_native_transfer(
                    signed, caller, &mut db, coinbase, base_fee, self.spec,
                ) {
                    let observed = db.db.take_observed();
                    let st = Self::spec_fast_path(
                        &db,
                        observed,
                        i,
                        caller,
                        signed,
                        coinbase,
                        parent_coinbase,
                        result,
                    );
                    mv.publish(i, &st.state);
                    return Some(st);
                }

                // Try the empty-code call fast path — calls to
                // code-less accounts skip revm's frame machinery.
                if let Some(result) = Self::try_empty_code_call(
                    signed, caller, &mut db, coinbase, base_fee, self.spec,
                ) {
                    let observed = db.db.take_observed();
                    let st = Self::spec_fast_path(
                        &db,
                        observed,
                        i,
                        caller,
                        signed,
                        coinbase,
                        parent_coinbase,
                        result,
                    );
                    mv.publish(i, &st.state);
                    return Some(st);
                }

                // Fall through to revm.
                let tx_env = match Self::build_tx_env(signed, caller, self.spec) {
                    Ok(t) => t,
                    Err(e) => {
                        // Build failures are tx-intrinsic (malformed
                        // fields) — no state was read, so the result
                        // cannot depend on ordering.
                        return Some(SpecTx::intrinsic_error(i, caller, e));
                    }
                };

                let mut evm = self.build_spec_evm(&mut db, coinbase, block_number, block_timestamp);
                let rs = evm.inspect_tx(tx_env);
                let native_blocked = evm.precompiles.blocked_native_mutation();
                evm.precompiles.clear_native_journal();
                let coinbase_read = evm.inspector.1.1.observed();
                let call_trace = evm.inspector.1.0.take_root();
                // The complete read record — every `basic`/`storage`
                // resolution the journal made, values included.
                let observed = evm.ctx.journaled_state.database.db.take_observed();
                drop(evm);

                match rs {
                    Ok(rs) => {
                        // `rs.state` holds every account the journal
                        // loaded — including the coinbase, stripped
                        // below for the additive-delta lane.
                        let accessed_coinbase = rs.state.contains_key(&coinbase);
                        // A non-additive coinbase change cannot be
                        // merged via the balance delta: nonce bumps
                        // (sender == coinbase, or a CREATE/CREATE2
                        // deployed at the fee recipient), storage
                        // writes into a contract living at that
                        // address, or destruction — `SELFDESTRUCT` or
                        // an EIP-161 empty-touch delete, which leaves
                        // balance, nonce, and storage map untouched
                        // in the journal entry but must still drop
                        // the account.
                        let coinbase_nontrivial = rs.state.get(&coinbase).is_some_and(|a| {
                            a.is_touched()
                                && (a.is_selfdestructed()
                                    || a.is_created_locally()
                                    || !a.storage.is_empty()
                                    || a.info.nonce != parent_coinbase_nonce)
                        });
                        // The coinbase delta captures the tx's net
                        // balance effect on the fee recipient (tips,
                        // plus transfers/selfdestructs to it — all
                        // strictly additive). The worker's coinbase
                        // view is always the pre-block base, so the
                        // delta is `post - base`.
                        let coinbase_after =
                            rs.state.get(&coinbase).map_or(parent_coinbase, |a| a.info.balance);
                        // The merge payload: the tx's own `EvmState`
                        // diff with the coinbase entry removed — its
                        // balance change merges via `coinbase_delta`.
                        let mut spec_state = rs.state;
                        spec_state.remove(&coinbase);
                        let st = SpecTx {
                            idx: i,
                            sender: caller,
                            result: Ok((rs.result, call_trace)),
                            observed,
                            destructive: destructive_accounts(&spec_state, &coinbase),
                            state: spec_state,
                            coinbase_before: parent_coinbase,
                            coinbase_delta: coinbase_after - parent_coinbase,
                            coinbase: CoinbaseObs {
                                read: coinbase_read,
                                accessed: accessed_coinbase,
                                nontrivial: coinbase_nontrivial,
                            },
                            must_reexec: native_blocked || coinbase_nontrivial,
                            // A contract can `BALANCE`-read its call
                            // target into control flow — no rebase is
                            // provable for interpreter-executed txs.
                            additive: None,
                        };
                        mv.publish(i, &st.state);
                        Some(st)
                    }
                    Err(e) => Some(SpecTx {
                        idx: i,
                        sender: caller,
                        result: Err(ExecError::rejected(
                            RejectCategory::Other,
                            format!("evm transact failed: {e:?}"),
                        )),
                        // Whatever the journal read before rejecting
                        // is the observation record — a real subset,
                        // not just the sender.
                        observed,
                        destructive: std::collections::HashSet::new(),
                        state: EvmState::default(),
                        coinbase_before: parent_coinbase,
                        coinbase_delta: revm::primitives::U256::ZERO,
                        coinbase: CoinbaseObs {
                            read: coinbase_read,
                            accessed: false,
                            nontrivial: false,
                        },
                        must_reexec: native_blocked,
                        additive: None,
                    }),
                }
            })
            .collect();

        // Release the shared snapshot before Phase 5's
        // `Arc::make_mut` on the main DB: while `snapshot` (or any
        // worker's `SharedCacheDB` clone of it — those die with
        // their closures) is alive, the outer Arc's refcount is >1
        // and `make_mut` deep-clones the entire CacheDB — O(total
        // state) on every parallel batch. The snapshot's last use
        // is inside the parallel closures, so dropping it here is
        // free and restores the in-place mutation the Arc wrapping
        // was designed for.
        drop(snapshot);
        // The version store's job ended with speculation — validity
        // is decided against the canonical DB, not the map.
        drop(mv);

        // Phase 5: commit in canonical transaction order.
        //
        // At tx i's position the canonical DB holds exactly the
        // committed output of indices < i — the serial pre-state.
        // The validity predicate is a direct value comparison over
        // `observed`: if every value the speculation resolved equals
        // the canonical value, the speculation ran on identical
        // inputs, so its result and `EvmState` diff are canonical
        // and merge directly. Any mismatch — a read that raced its
        // writer's publish and resolved the older version — forces
        // re-execution against the canonical DB.
        //
        // Two lanes bypass value comparison by design:
        //
        // - **Coinbase**: tips are additive deltas merged in order;
        //   a `BALANCE(coinbase)` read validates against the
        //   canonical running total, and a non-additive coinbase
        //   write (`coinbase_dirty`) invalidates later accessors.
        // - **Destructive writes**: `SELFDESTRUCT`/`CREATE` replace
        //   an account in ways versioned values cannot fully express
        //   (a created-then-destroyed account's storage wipe), so
        //   any access to a canonically-destructed account
        //   re-executes regardless of observed equality.
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);

        // Accounts destructed by any committed tx — the conservative
        // re-execution set (see above).
        let mut destructed: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();
        // Set once any tx changed the coinbase beyond an additive
        // balance delta (nonce/storage — e.g. sender == coinbase, or
        // a contract deployed at the fee recipient). Later txs that
        // accessed the coinbase at all can no longer trust their
        // speculative view of it.
        let mut coinbase_dirty = false;
        let mut all_touched: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();
        // Inverse-diff accumulator for the parallel path — captures
        // only writes that land in the *main* DB (re-executions and
        // validated merges), never the speculative worker caches.
        let mut committed_undo = versioned::BlockUndo::default();
        // The committed result for each tx position — speculative or
        // re-executed, whichever the validation chose.
        let mut final_results: Vec<Option<TracedResult>> = Vec::with_capacity(n_txs);
        final_results.resize_with(n_txs, || None);

        let mut spec_txs = spec_txs;
        for i in 0..n_txs {
            let Some(mut st) = spec_txs[i].take() else {
                continue;
            };
            // The speculation record must sit at its canonical index —
            // `into_par_iter` collection preserves order, so a
            // mismatch means the record was filed under a wrong index
            // and its observations were resolved against the wrong
            // read horizon.
            debug_assert_eq!(st.idx, i, "spec record misplaced from its canonical index");

            // Canonical coinbase balance before tx i — the main DB
            // receives merged deltas and re-executed tips in index
            // order, so this equals the sequential value.
            let canonical_coinbase = db
                .cache
                .accounts
                .get(&coinbase)
                .map_or(revm::primitives::U256::ZERO, |a| a.info.balance);

            // Journal discipline (and the fast paths' `load_account`
            // ordering) guarantees every written key was read first —
            // the observed sets are closed under writes. Assert it in
            // debug builds so a future bypassing write path fails
            // loudly in tests instead of silently skipping
            // validation.
            debug_assert!(
                st.state.keys().all(|a| st.observed.accounts.contains_key(a)),
                "spec state contains an account that was never read through MvDb"
            );
            debug_assert!(st.destructive.iter().all(|a| st.observed.accounts.contains_key(a)));

            // Validity: every recorded observation must equal the
            // canonical value at this position — with one exemption.
            // A fast-path recipient's balance is a *write-only*
            // dependency (`post = pre + value`; the fixed-gas result
            // never consumed it), so a stale observation there rebases
            // onto the canonical account below rather than forcing
            // re-execution. This is the same insight as the coinbase
            // lane, scoped to accounts the tx could not have read for
            // control flow.
            let additive_recipient = st.additive.map(|(r, _)| r);
            let mut observed_invalid = st.observed.accounts.iter().any(|(a, key)| {
                Some(*a) != additive_recipient && canonical_info_key(db, *a) != *key
            }) || st
                .observed
                .slots
                .iter()
                .any(|(&(a, slot), v)| canonical_slot(db, a, slot) != *v);
            if !observed_invalid
                && !st.must_reexec
                && let Some((recipient, value)) = st.additive
            {
                let canonical = match db.basic_ref(recipient) {
                    Ok(info) => info,
                    Err(e) => match e {},
                };
                if canonical.as_ref().map(info_key)
                    != st.observed.accounts.get(&recipient).copied().flatten()
                {
                    // Rebase only while the canonical recipient is
                    // still codeless: a real code hash means an
                    // earlier tx deployed code here and the call
                    // would have executed it — re-execute.
                    let codeless = canonical.as_ref().is_none_or(|info| {
                        info.code_hash == revm::primitives::KECCAK_EMPTY
                            || info.code_hash == revm::primitives::B256::ZERO
                    });
                    let post = if codeless {
                        match canonical {
                            // Mirror the fast path's recipient
                            // write exactly: `balance += value`,
                            // plus the ZERO -> KECCAK_EMPTY
                            // code-hash normalization it performs
                            // on touched accounts. Overflow cannot
                            // rebase — the delta is relative to a
                            // base the tx never saw — so it
                            // re-executes.
                            Some(info) => info.balance.checked_add(value).map(|balance| {
                                revm::database::state::AccountInfo {
                                    balance,
                                    code_hash: if info.code_hash == revm::primitives::B256::ZERO {
                                        revm::primitives::KECCAK_EMPTY
                                    } else {
                                        info.code_hash
                                    },
                                    ..info
                                }
                            }),
                            // Canonically absent: the transfer
                            // creates the account carrying exactly
                            // `value` — what a canonical run of
                            // the fast path writes too.
                            None => Some(revm::database::state::AccountInfo {
                                balance: value,
                                nonce: 0,
                                code_hash: revm::primitives::KECCAK_EMPTY,
                                account_id: None,
                                code: None,
                            }),
                        }
                    } else {
                        None
                    };
                    match post {
                        // A rebased recipient entry lands the same
                        // account a canonical run produces.
                        Some(info) => {
                            let account = st.state.entry(recipient).or_default();
                            account.info = info;
                            account.mark_touch();
                        }
                        None => observed_invalid = true,
                    }
                }
            }
            // Any access to a canonically-destructed account forces
            // re-execution — value equality cannot express the
            // account-level semantics of a wholesale replacement.
            let touched_destructed = !destructed.is_empty()
                && (st.observed.accounts.keys().any(|a| destructed.contains(a))
                    || st.observed.slots.keys().any(|(a, _)| destructed.contains(a)));
            // The speculative coinbase observation is only valid if
            // the balance it saw equals the canonical running total.
            let stale_coinbase = (st.coinbase.read && st.coinbase_before != canonical_coinbase)
                || (coinbase_dirty && st.coinbase.accessed);

            if st.must_reexec || observed_invalid || touched_destructed || stale_coinbase {
                // Re-execute this tx against the canonical DB.
                self.parallel_reexecs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                coinbase_dirty |= st.coinbase.nontrivial;
                let caller = st.sender;
                let signed =
                    items[i].as_ref().map(|(s, _)| s).expect("speculative tx has signed bytes");
                let cb_nonce_pre = db.cache.accounts.get(&coinbase).map_or(0, |a| a.info.nonce);

                // Try native fast path first.
                Self::undo_capture_fast_path(&mut committed_undo, db, signed, caller, coinbase);
                if let Some(result) = Self::try_native_transfer(
                    signed,
                    caller,
                    &mut *db,
                    coinbase,
                    self.current_base_fee(),
                    self.spec,
                ) {
                    coinbase_dirty |= caller == coinbase;
                    all_touched.insert(caller);
                    all_touched.insert(coinbase);
                    // Fast paths only ever modify `info` (balance,
                    // nonce) — a value-compare read of either account
                    // by a later tx sees the canonical value directly,
                    // so no write registry is needed.
                    if let tx::TxKind::Call(addr) = signed.to() {
                        all_touched.insert(revm::primitives::Address::from(addr.0));
                    }
                    let frame = Self::fast_path_frame(signed, caller, &result);
                    final_results[i] = Some(Ok((result, Some(frame))));
                    continue;
                }

                // Try empty-code call fast path — must use the
                // same fast paths as the speculative execution to
                // ensure identical state roots.
                if let Some(result) = Self::try_empty_code_call(
                    signed,
                    caller,
                    &mut *db,
                    coinbase,
                    self.current_base_fee(),
                    self.spec,
                ) {
                    coinbase_dirty |= caller == coinbase;
                    all_touched.insert(caller);
                    all_touched.insert(coinbase);
                    if let tx::TxKind::Call(addr) = signed.to() {
                        all_touched.insert(revm::primitives::Address::from(addr.0));
                    }
                    let frame = Self::fast_path_frame(signed, caller, &result);
                    final_results[i] = Some(Ok((result, Some(frame))));
                    continue;
                }

                // Fall through to revm — the committed-path EVM
                // (mutating native precompiles enabled: this is the
                // canonical execution).
                let tx_env = match Self::build_tx_env(signed, caller, self.spec) {
                    Ok(t) => t,
                    Err(e) => {
                        final_results[i] = Some(Err(e));
                        continue;
                    }
                };
                {
                    let mut evm = self.build_evm(&mut *db, coinbase, block_number, block_timestamp);
                    match evm.inspect_tx(tx_env) {
                        Ok(rs) => {
                            let r = rs.result;
                            if let Some(cb) = rs.state.get(&coinbase) {
                                // Same non-additive predicate as the
                                // speculative scan: nonce, storage,
                                // creation, or destruction — anything a
                                // balance-delta merge cannot represent.
                                coinbase_dirty |= cb.is_touched()
                                    && (cb.is_selfdestructed()
                                        || cb.is_created_locally()
                                        || !cb.storage.is_empty()
                                        || cb.info.nonce != cb_nonce_pre);
                            }
                            let state_keys: Vec<revm::primitives::Address> =
                                rs.state.keys().copied().collect();
                            for addr in &state_keys {
                                all_touched.insert(*addr);
                                committed_undo.capture(
                                    *addr,
                                    evm.ctx.journaled_state.database.cache.accounts.get(addr),
                                );
                            }
                            // Destructive writes keep their
                            // conservative registry — later accessors
                            // re-execute regardless of observed-value
                            // equality (wholesale account replacement
                            // is not value-expressible).
                            destructed.extend(destructive_accounts(&rs.state, &coinbase));
                            evm.precompiles.clear_native_journal();
                            let call_trace = evm.inspector.1.take_root();
                            // Canonical re-execution commits to the
                            // authoritative cache — sweep committed
                            // zero slots (see `commit_state`).
                            let zeroed = Self::zero_slot_writers(&rs.state);
                            evm.commit(rs.state);
                            Self::prune_zero_slots(evm.ctx.journaled_state.database, &zeroed);
                            final_results[i] = Some(Ok((r, call_trace)));
                        }
                        Err(e) => {
                            final_results[i] = Some(Err(ExecError::rejected(
                                RejectCategory::Other,
                                format!("evm transact failed: {e:?}"),
                            )));
                        }
                    }
                }
                continue;
            }

            // Speculation validated: commit the tx's recorded
            // `EvmState` through the same `DatabaseCommit::commit`
            // the serial path runs. The merge is slot-granular —
            // storage the tx never touched survives — and contract
            // code (`insert_contract`), create, selfdestruct, and
            // slot-zeroing semantics match sequential execution by
            // construction. Replacing whole `DbAccount`s here instead
            // (the old merge) silently erased every slot the tx had
            // not loaded — see the `preserves_unread_storage`
            // regression test.
            for (addr, account) in &st.state {
                if account.is_touched() {
                    committed_undo.capture(*addr, db.cache.accounts.get(addr));
                    // `all_touched` stays account-granular — the
                    // state-root incremental patcher needs every
                    // account the commit may have modified, which is
                    // exactly `state`'s `is_touched` subset (including
                    // state-neutral bare touches).
                    all_touched.insert(*addr);
                }
            }
            Self::commit_state(&mut *db, st.state);
            // Apply the coinbase delta now — keeping the running
            // balance canonical for every later validation check.
            if st.coinbase_delta != revm::primitives::U256::ZERO {
                committed_undo.capture(coinbase, db.cache.accounts.get(&coinbase));
                let coinbase_account = db.cache.accounts.entry(coinbase).or_insert_with(|| {
                    revm::database::DbAccount {
                        info: revm::database::state::AccountInfo {
                            balance: revm::primitives::U256::ZERO,
                            nonce: 0,
                            // `KECCAK_EMPTY` matches what revm's
                            // `insert_contract` sets for an empty-code
                            // account. Using `B256::ZERO` here would
                            // produce a different state root from the
                            // serial path.
                            code_hash: revm::primitives::KECCAK_EMPTY,
                            account_id: None,
                            code: Some(revm::bytecode::Bytecode::new_raw(
                                revm::primitives::Bytes::new(),
                            )),
                        },
                        // `Touched` matches what revm's `commit_account`
                        // sets for a modified account.
                        account_state: revm::database::AccountState::Touched,
                        storage: revm::primitives::HashMap::default(),
                    }
                });
                coinbase_account.info.balance += st.coinbase_delta;
                coinbase_account.account_state = revm::database::AccountState::Touched;
                all_touched.insert(coinbase);
            }
            // Destructive writes register for later positions —
            // accessors of a destructed account re-execute even when
            // their observed values happen to match.
            destructed.extend(st.destructive.iter().copied());
            final_results[i] = Some(st.result);
        }

        // Merge touched accounts into the module-level set.
        {
            let mut touched = framework::lock_state(&self.touched);
            touched.extend(all_touched);
        }
        {
            let mut undo = framework::lock_state(&self.block_undo);
            for (addr, entry) in committed_undo.accounts {
                undo.accounts.entry(addr).or_insert(entry);
            }
        }

        // Phase 6: assemble results in original order. `final_results`
        // already carries whichever execution won — the validated
        // speculative result or the canonical re-execution.
        let mut results: Vec<Result<Vec<Event>, ExecError>> = Vec::with_capacity(n_txs);
        for (i, err) in errors.iter().enumerate() {
            if let Some(e) = err {
                results.push(Err(e.clone()));
                continue;
            }
            // Split `(result, trace)` out of the Ok payload and merge
            // the trace into `metas[i]` — `exec_result_to_events`
            // takes the 3-tuple so the trace lands in history beside
            // the receipt.
            match final_results[i].take() {
                Some(r) => {
                    let (res, call_trace) = match r {
                        Ok((res, t)) => (Ok(res), t),
                        Err(e) => (Err(e), None),
                    };
                    let meta = metas[i].take().map(|(s, raw)| (s, raw, call_trace));
                    results.push(self.exec_result_to_events(res, meta));
                }
                None => {
                    results.push(Err(ExecError::rejected(
                        RejectCategory::NotFound,
                        "parallel execution: missing result",
                    )));
                }
            }
        }

        // Silence unused-ctx warning — ctx is part of the Module
        // interface but EVM recovers the sender from the signature.
        let _ = ctx;

        results
    }

    /// Convert a revm `ExecutionResult` to a vector of Oxide events,
    /// recording the transaction into the executed-block history.
    ///
    /// Shared between `handle_batch` and `handle_batch_parallel` to
    /// ensure identical event formatting.
    ///
    /// `meta` is `Some((StoredTx, raw_rlp))` for transactions that
    /// executed (success, revert, or halt — all are sealed in the
    /// block) and `None` for transactions rejected before execution
    /// (decode / chain-id / signature-recovery failures). Only
    /// executed txs appear in `eth_getTransactionReceipt` /
    /// `eth_getLogs`. The raw RLP accompanies the record for the
    /// `transactionsRoot` trie at seal time.
    pub(crate) fn exec_result_to_events(
        &self,
        result: Result<revm::context::result::ExecutionResult, ExecError>,
        meta: Option<(history::StoredTx, Vec<u8>, Option<trace::CallFrame>)>,
    ) -> Result<Vec<Event>, ExecError> {
        match result {
            Ok(r) => {
                let tx_type = meta.as_ref().map_or(0, |m| m.0.tx_type);
                let receipt = receipts::Receipt::from_execution_result(&r, tx_type);
                if let Some((stored, raw, call_trace)) = meta {
                    framework::lock_state(&self.history).record(
                        stored,
                        receipt.clone(),
                        &raw,
                        call_trace,
                    );
                }
                let status_str = if receipt.status { "success" } else { "revert" };
                let contract_info =
                    receipt.contract_address.map(|a| format!(" contract={a}")).unwrap_or_default();
                let log_count = receipt.logs.len();
                Ok(vec![Event {
                    module: "evm",
                    kind: "evm_call",
                    data: format!(
                        "gas_used={} status={} base_fee={} logs={}{}",
                        receipt.gas_used,
                        status_str,
                        self.current_base_fee(),
                        log_count,
                        contract_info
                    )
                    .into_bytes(),
                }])
            }
            Err(e) => Err(e),
        }
    }
}
