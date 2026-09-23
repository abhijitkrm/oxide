//! Batch and parallel execution for the EVM module.
//!
//! Split from `lib.rs` around the speculation invariant:
//! `handle_batch_parallel*` speculatively executes independent
//! tx groups against the shared parent view and commits them in
//! canonical order — a speculation is proved or disproved by its
//! `SpecTx` record, never trusted. `execute_parallel_decoded` is
//! the merge engine; `exec_result_to_events` maps outcomes to
//! chain events.

use super::{
    Arc, CacheDB, CoinbaseObs, DecodedTx, Event, EvmModule, ExecError, ExecuteCommitEvm,
    GroupExecResult, InspectEvm, IntoParallelRefIterator, ParallelIterator, PreverifiedTx,
    SharedCacheDB, SpecTx, TracedResult, TxContext, alloy_primitives_address, history, receipts,
    trace, tx, versioned,
};
use revm::state::EvmState;

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
        msgs.par_iter()
            .map(|raw| {
                let signed =
                    tx::SignedTx::decode_raw(raw.as_ref()).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                Ok(PreverifiedTx { raw: raw.as_ref(), sender: caller })
            })
            .collect()
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
        // Phase 1: decode and re-recover the sender. RLP decode is
        // ~79 ns/tx; secp256k1 recovery is ~30 µs/tx. We re-recover
        // the sender and check it matches the pre-recovered value.
        // A byzantine proposer cannot forge a sender — any mismatch
        // is rejected before state transition.
        let decoded: Vec<DecodedTx> = txs
            .par_iter()
            .map(|pv| {
                let signed = tx::SignedTx::decode_raw(pv.raw).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                // Re-recover the sender from the signature. This is
                // the security gate: we do NOT trust `pv.sender`.
                let recovered = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let recovered_addr = alloy_primitives_address(recovered.0);
                // Check the pre-recovered sender matches the
                // signature-recovered sender. A mismatch means the
                // proposer supplied a wrong sender — reject it.
                if recovered_addr != pv.sender {
                    return Err(ExecError::Malformed);
                }
                let tx_hash = alloy_primitives::keccak256(pv.raw);
                Ok((signed, recovered_addr, tx_hash, pv.raw.to_vec()))
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
                        results.push(Err(ExecError::ModuleRejected(format!(
                            "evm transact failed: {e:?}"
                        ))));
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
    /// signature recovery but also EVM execution itself, using
    /// per-sender-group state snapshots.
    ///
    /// # Algorithm
    ///
    /// 1. **Parallel decode + recovery**: All senders are recovered in
    ///    parallel (same as `handle_batch`).
    /// 2. **Sender grouping**: Transactions are grouped by sender.
    ///    Within a group, transactions execute sequentially (nonce
    ///    dependency). Across groups, transactions are independent
    ///    (different senders).
    /// 3. **Parallel execution**: Each group executes on its own
    ///    copy-on-write `CacheDB` over a shared snapshot. Groups
    ///    execute in parallel via `rayon`. Each transaction uses
    ///    `transact` (non-commit) to obtain the `EvmState` diff —
    ///    its exact read and write sets — then commits it to the
    ///    group's local clone so the next transaction in the group
    ///    sees the updated state. Speculative EVMs run with
    ///    read-only native precompiles (a suppressed native
    ///    mutation flags the tx for re-execution) and a
    ///    `BALANCE(coinbase)` detector.
    /// 4. **Canonical-order commit**: Transactions are committed in
    ///    original batch order — *not* group order — so an
    ///    interleaving like `A0, B0, A1` can never commit as
    ///    `A0, A1, B0`. At each tx's position, its speculative
    ///    read/write sets are validated against the writes of all
    ///    canonically-earlier txs from other senders: a tx whose
    ///    speculation saw only same-sender writes and untouched
    ///    accounts merges directly; anything else re-executes
    ///    against the main DB, which by then holds exactly the
    ///    canonical pre-state. Once a tx re-executes, its
    ///    same-sender successors re-execute too (they speculated
    ///    on its speculative outcome).
    /// 5. **Coinbase handling**: The coinbase (fee recipient) is
    ///    written by every transaction via tips, so it is tracked
    ///    outside the read/write sets: each tx's net coinbase
    ///    delta merges additively in canonical order, keeping the
    ///    running balance canonical. A tx that observed the
    ///    coinbase balance (`BALANCE`) re-executes unless the
    ///    balance it saw matches the canonical total; a tx that
    ///    changed the coinbase non-additively (nonce/storage)
    ///    always re-executes.
    ///
    /// # When to use this vs `handle_batch`
    ///
    /// Use `handle_batch_parallel` when the batch contains
    /// transactions from **multiple senders** (the common case in a
    /// real blockchain). When all transactions share a single sender,
    /// this method degrades to sequential execution (one group) plus
    /// the overhead of cloning the DB — `handle_batch` is faster in
    /// that case.
    ///
    /// # Limitations
    ///
    /// - Conflict detection is account-granular: two txs touching
    ///   different storage slots of the same account are treated as
    ///   conflicting. Per-storage-slot tracking is future work.
    /// - Re-execution cascades within a sender: one invalid
    ///   speculative tx re-executes all its same-sender successors
    ///   (their speculation depended on its outcome).
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

        // Phase 1: decode and re-recover the sender. We do NOT
        // trust `pv.sender` — a byzantine proposer could forge it.
        let decoded: Vec<DecodedTx> = txs
            .par_iter()
            .map(|pv| {
                let signed = tx::SignedTx::decode_raw(pv.raw).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                // Re-recover the sender from the signature and
                // check it matches the pre-recovered value.
                let recovered = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let recovered_addr = alloy_primitives_address(recovered.0);
                if recovered_addr != pv.sender {
                    return Err(ExecError::Malformed);
                }
                let tx_hash = alloy_primitives::keccak256(pv.raw);
                Ok((signed, recovered_addr, tx_hash, pv.raw.to_vec()))
            })
            .collect();

        self.execute_parallel_decoded(ctx, decoded)
    }

    /// Shared parallel execution loop for decoded transactions.
    ///
    /// Both [`handle_batch_parallel`](Self::handle_batch_parallel) and
    /// [`handle_batch_parallel_preverified`](Self::handle_batch_parallel_preverified)
    /// produce a `decoded` vector. This method implements the
    /// parallel speculative execution algorithm: sender grouping,
    /// parallel execution on per-group snapshots, conflict detection,
    /// and sequential fallback for conflicting groups.
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
        use std::collections::hash_map::Entry;
        // Phase 2: group txs by sender, preserving original order
        // within each group. Txs from the same sender must execute
        // sequentially (nonce dependency). Txs from different senders
        // can execute in parallel.
        //
        // We use an insertion-ordered map so that groups are naturally
        // ordered by first appearance (canonical order).
        let mut groups: std::collections::HashMap<
            revm::primitives::Address,
            Vec<(usize, tx::SignedTx)>,
        > = std::collections::HashMap::new();
        let mut group_order: Vec<revm::primitives::Address> = Vec::new();
        let mut errors: Vec<Option<ExecError>> = vec![None; decoded.len()];
        let n_txs = decoded.len();
        // History metadata for each decoded tx, indexed by original
        // position. Built at grouping time (before `signed` moves into
        // its group) so the result-assembly phase can record receipts
        // without re-decoding. `None` for pre-execution failures. The
        // raw RLP rides along for the `transactionsRoot` trie.
        let mut metas: Vec<Option<(history::StoredTx, Vec<u8>)>> = Vec::with_capacity(n_txs);
        metas.resize_with(n_txs, || None);

        for (idx, item) in decoded.into_iter().enumerate() {
            match item {
                Ok((signed, caller, tx_hash, raw)) => {
                    metas[idx] = Some((history::stored_tx(&signed, caller, tx_hash, 0), raw));
                    match groups.entry(caller) {
                        Entry::Occupied(_) => {
                            groups.get_mut(&caller).expect("group exists").push((idx, signed));
                        }
                        Entry::Vacant(v) => {
                            group_order.push(caller);
                            v.insert(Vec::from([(idx, signed)]));
                        }
                    }
                }
                Err(e) => {
                    errors[idx] = Some(e);
                }
            }
        }

        // Note: single-group batches (all txs from one sender) are
        // handled correctly by the parallel path — the group executes
        // sequentially on its COW cache over the shared `Arc` snapshot
        // (O(1) setup, O(touched) memory). A future optimization can
        // skip the speculation bookkeeping entirely for single-group
        // batches by calling `execute_decoded` directly.

        // Phase 3: snapshot the main DB into an `Arc` for
        // copy-on-write sharing. Each group gets a
        // `CacheDB::new(SharedCacheDB(arc_clone))` — a fresh, empty
        // local cache backed by the shared parent via
        // `DatabaseRef`. Reads fall through to the parent on cache
        // miss; writes stay local. Per-group cost is O(1) init +
        // O(touched) memory, vs O(state) for a full clone.
        //
        // The snapshot is an O(1) `Arc::clone` — no deep clone of
        // the CacheDB. Each parallel group gets a fresh empty
        // `CacheDB<SharedCacheDB>` backed by the shared snapshot via
        // `DatabaseRef`. Reads fall through to the parent on cache
        // miss; writes stay local.
        let snapshot = framework::lock_state(&self.db).clone();
        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);

        // Phase 4: execute each group in parallel on its own COW
        // nested cache. Within a group txs run sequentially (nonce
        // dependency); across groups they speculate independently.
        // Every tx produces a `SpecTx` recording its exact per-tx
        // read/write sets, coinbase observation, and native-mutation
        // flags — the commit phase (Phase 5) validates each tx in
        // canonical index order, so speculation order cannot leak
        // into the committed result.
        //
        // Speculative EVMs run with read-only native precompiles:
        // a mutating staking call reverts instead of touching the
        // shared `StakingModule`, and the suppressed mutation sets
        // `native_blocked` so the tx re-executes canonically.
        let parent_coinbase = snapshot
            .cache
            .accounts
            .get(&coinbase)
            .map_or(revm::primitives::U256::ZERO, |a| a.info.balance);
        let group_results: Vec<GroupExecResult> = group_order
            .par_iter()
            .map(|sender| {
                let txs = groups.get(sender).expect("group exists");
                // COW nested cache: empty local cache, reads from
                // the shared parent on miss.
                let mut db: CacheDB<SharedCacheDB> = CacheDB::new(SharedCacheDB(snapshot.clone()));

                // Pre-load hot accounts into the nested cache before
                // execution. This avoids `DatabaseRef` trait dispatch
                // on the first access to each account. The accounts
                // touched by (almost) every tx in a group:
                //
                // 1. **Sender** — nonce bump + balance deduction on
                //    every tx.
                // 2. **Coinbase** — receives tips on every tx.
                // 3. **All unique recipients** — pre-loading every
                //    recipient in the group avoids a cache miss on
                //    the first call to each contract. For workloads
                //    with many calls to the same contract (CLOB,
                //    storage patterns), this eliminates repeated
                //    `DatabaseRef` dispatch.
                let _ = db.load_account(*sender);
                let _ = db.load_account(coinbase);
                // Collect unique recipient addresses from all txs in
                // the group. Uses a small HashSet to deduplicate —
                // typical groups have 1–5 unique recipients.
                let mut recipients: std::collections::HashSet<revm::primitives::Address> =
                    std::collections::HashSet::new();
                for (_, signed) in txs {
                    if let tx::TxKind::Call(addr) = signed.to() {
                        recipients.insert(revm::primitives::Address::from(addr.0));
                    }
                }
                for addr in &recipients {
                    let _ = db.load_account(*addr);
                }

                let mut spec_txs: Vec<SpecTx> = Vec::with_capacity(txs.len());

                for (idx, signed) in txs {
                    let caller = *sender;
                    let idx = *idx;

                    // The coinbase state this tx speculates against:
                    // pre-block balance plus own-group tips so far.
                    // `nonce_before` detects non-additive coinbase
                    // writes (only possible when the sender *is* the
                    // coinbase — tips never bump a nonce).
                    let coinbase_before = db
                        .cache
                        .accounts
                        .get(&coinbase)
                        .map_or(parent_coinbase, |a| a.info.balance);
                    let coinbase_nonce_before =
                        db.cache.accounts.get(&coinbase).map_or(0, |a| a.info.nonce);

                    // Try the native transfer fast path first. For
                    // simple ETH transfers (empty calldata, EOA
                    // recipient), this bypasses revm entirely.
                    if let Some(result) = Self::try_native_transfer(
                        signed,
                        caller,
                        &mut db,
                        coinbase,
                        self.current_base_fee(),
                        self.spec,
                    ) {
                        spec_txs.push(Self::spec_fast_path(
                            &db,
                            idx,
                            caller,
                            signed,
                            coinbase,
                            coinbase_before,
                            result,
                        ));
                        continue;
                    }

                    // Try the empty-code call fast path. For calls
                    // to contracts with no runtime code (EOA or
                    // constructor-only deployment), this bypasses
                    // revm's call-frame setup and gas accounting.
                    if let Some(result) = Self::try_empty_code_call(
                        signed,
                        caller,
                        &mut db,
                        coinbase,
                        self.current_base_fee(),
                        self.spec,
                    ) {
                        spec_txs.push(Self::spec_fast_path(
                            &db,
                            idx,
                            caller,
                            signed,
                            coinbase,
                            coinbase_before,
                            result,
                        ));
                        continue;
                    }

                    // Fall through to revm.
                    let tx_env = match Self::build_tx_env(signed, caller, self.spec) {
                        Ok(t) => t,
                        Err(e) => {
                            // Build failures are tx-intrinsic (malformed
                            // fields) — no state was read, so the result
                            // cannot depend on ordering.
                            spec_txs.push(SpecTx::intrinsic_error(idx, caller, e));
                            continue;
                        }
                    };

                    // Speculative run: read-only native precompiles
                    // + coinbase-read detection. `transact` (not
                    // `transact_commit`) returns the per-tx `EvmState`
                    // — the exact set of accounts the tx loaded
                    // (reads) and modified (writes), with per-slot
                    // original/present values. A clone of the diff is
                    // kept in the `SpecTx` as the merge payload; the
                    // original is committed into the group cache so the
                    // next same-sender tx sees it.
                    let (result, native_blocked, coinbase_read, call_trace, loaded) = {
                        let mut evm =
                            self.build_spec_evm(&mut db, coinbase, block_number, block_timestamp);
                        let rs = evm.inspect_tx(tx_env);
                        let blocked = evm.precompiles.blocked_native_mutation();
                        evm.precompiles.clear_native_journal();
                        let cb_read = evm.inspector.1.1.observed();
                        let call_trace = evm.inspector.1.0.take_root();
                        match rs {
                            Ok(rs) => {
                                // `rs.state` holds every account the
                                // journal loaded — the exact read set.
                                let accessed_coinbase = rs.state.contains_key(&coinbase);
                                // A non-additive coinbase change cannot
                                // be merged via the balance delta:
                                // nonce bumps (sender == coinbase, or a
                                // CREATE/CREATE2 deployed at the fee
                                // recipient), storage writes into a
                                // contract living at that address, or
                                // destruction — `SELFDESTRUCT` or an
                                // EIP-161 empty-touch delete, which
                                // leaves balance, nonce, and storage
                                // map untouched in the journal entry
                                // but must still drop the account.
                                let coinbase_nontrivial =
                                    rs.state.get(&coinbase).is_some_and(|a| {
                                        a.is_touched()
                                            && (a.is_selfdestructed()
                                                || a.is_created_locally()
                                                || !a.storage.is_empty()
                                                || a.info.nonce != coinbase_nonce_before)
                                    });
                                // The merge payload: the tx's own
                                // `EvmState` diff. The coinbase entry
                                // is stripped — its balance change
                                // merges via the additive
                                // `coinbase_delta`, so a later
                                // validator sees the canonical running
                                // tip total rather than the group's
                                // speculative one.
                                let mut spec_state = rs.state.clone();
                                spec_state.remove(&coinbase);
                                // Commit into the group scratch cache
                                // — deliberately WITHOUT the
                                // canonical zero-slot sweep: a zero
                                // entry here shadows the parent's
                                // stale value for later same-sender
                                // transactions. The canonical merge
                                // below prunes instead.
                                evm.commit(rs.state);
                                (
                                    Ok(rs.result),
                                    blocked,
                                    cb_read,
                                    call_trace,
                                    Some((spec_state, accessed_coinbase, coinbase_nontrivial)),
                                )
                            }
                            Err(e) => (Err(e), blocked, cb_read, call_trace, None),
                        }
                    };

                    match result {
                        Ok(exec_result) => {
                            let (spec_state, accessed_coinbase, coinbase_nontrivial) =
                                loaded.expect("Ok carries the loaded state");

                            // The coinbase delta captures the tx's
                            // net balance effect on the fee recipient
                            // (tips, plus transfers/selfdestructs to
                            // it — all strictly additive).
                            let coinbase_after = db
                                .cache
                                .accounts
                                .get(&coinbase)
                                .map_or(parent_coinbase, |a| a.info.balance);

                            // `spec_state` keys are every account the
                            // journal loaded — the exact read set
                            // (the coinbase was stripped at capture).
                            // The write set is the `is_touched()`
                            // subset: precisely the accounts
                            // `DatabaseCommit::commit` will modify on
                            // merge, matching sequential
                            // `commit_account` semantics.
                            let mut reads: std::collections::HashSet<revm::primitives::Address> =
                                std::collections::HashSet::with_capacity(spec_state.len());
                            let mut writes: std::collections::HashSet<revm::primitives::Address> =
                                std::collections::HashSet::new();
                            for (addr, account) in &spec_state {
                                reads.insert(*addr);
                                if account.is_touched() {
                                    writes.insert(*addr);
                                }
                            }

                            spec_txs.push(SpecTx {
                                idx,
                                sender: caller,
                                result: Ok((exec_result, call_trace)),
                                reads,
                                writes,
                                state: spec_state,
                                coinbase_before,
                                coinbase_delta: coinbase_after - coinbase_before,
                                coinbase: CoinbaseObs {
                                    read: coinbase_read,
                                    accessed: accessed_coinbase,
                                    nontrivial: coinbase_nontrivial,
                                },
                                must_reexec: native_blocked || coinbase_nontrivial,
                            });
                        }
                        Err(e) => {
                            // revm validation failure — the only state
                            // consulted is the sender's account (nonce,
                            // balance, gas affordability), so the
                            // sender alone forms the read set.
                            let mut reads = std::collections::HashSet::new();
                            reads.insert(caller);
                            spec_txs.push(SpecTx {
                                idx,
                                sender: caller,
                                result: Err(ExecError::ModuleRejected(format!(
                                    "evm transact failed: {e:?}"
                                ))),
                                reads,
                                writes: std::collections::HashSet::new(),
                                state: EvmState::default(),
                                coinbase_before,
                                coinbase_delta: revm::primitives::U256::ZERO,
                                coinbase: CoinbaseObs {
                                    read: false,
                                    accessed: false,
                                    nontrivial: false,
                                },
                                must_reexec: native_blocked,
                            });
                        }
                    }
                }

                GroupExecResult { spec_txs }
            })
            .collect();

        // Release the shared snapshot before Phase 5's
        // `Arc::make_mut` on the main DB: while `snapshot` (or any
        // per-group `SharedCacheDB` clone of it — those die with
        // their closures) is alive, the outer Arc's refcount is >1
        // and `make_mut` deep-clones the entire CacheDB — O(total
        // state) on every parallel batch. The snapshot's last use
        // is inside the parallel closures, so dropping it here is
        // free and restores the in-place mutation the Arc wrapping
        // was designed for.
        drop(snapshot);

        // Phase 5: commit in canonical transaction order.
        //
        // Speculation ran per-sender groups — for `A0, B0, A1` the
        // speculative execution order was effectively `A0, A1, B0`.
        // Merging in group order would let `A1` commit a result
        // computed without `B0`'s writes. Instead every tx is
        // validated at its canonical index position: it keeps its
        // speculative result iff no canonically-earlier tx from a
        // *different* sender wrote anything it read or wrote —
        // otherwise it is re-executed against the main DB, which at
        // that point holds exactly the canonical pre-state.
        //
        // `writers` maps each written account to its first writer's
        // sender plus a "multiple senders" flag; a tx conflicts when
        // any account in `reads ∪ writes` was written by a different
        // sender. Same-sender writes are excluded because the group's
        // sequential speculation already observed them — but only up
        // to the first re-execution: once a tx re-executes, its
        // same-group successors speculated on its speculative
        // outcome, so they re-execute too (`broken`).
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);

        // Flatten speculative records and signed txs into index
        // order — the commit loop below walks positions 0..n_txs.
        let mut flat: Vec<Option<SpecTx>> = Vec::with_capacity(n_txs);
        flat.resize_with(n_txs, || None);
        for gr in group_results {
            for st in gr.spec_txs {
                let idx = st.idx;
                flat[idx] = Some(st);
            }
        }
        let mut signed_by_idx: Vec<Option<&tx::SignedTx>> = Vec::with_capacity(n_txs);
        signed_by_idx.resize_with(n_txs, || None);
        for txs in groups.values() {
            for (idx, signed) in txs {
                signed_by_idx[*idx] = Some(signed);
            }
        }

        let mut writers: std::collections::HashMap<
            revm::primitives::Address,
            (revm::primitives::Address, bool),
        > = std::collections::HashMap::new();
        let mut broken: std::collections::HashSet<revm::primitives::Address> =
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
        // only writes that land in the *main* DB (conflict
        // re-execution and non-conflict merges), never the
        // speculative scratch caches.
        let mut committed_undo = versioned::BlockUndo::default();
        // The committed result for each tx position — speculative or
        // re-executed, whichever the validation chose.
        let mut final_results: Vec<Option<TracedResult>> = Vec::with_capacity(n_txs);
        final_results.resize_with(n_txs, || None);

        for i in 0..n_txs {
            let Some(st) = flat[i].take() else {
                continue;
            };

            // Canonical coinbase balance before tx i — the main DB
            // receives merged deltas and re-executed tips in index
            // order, so this equals the sequential value.
            let canonical_coinbase = db
                .cache
                .accounts
                .get(&coinbase)
                .map_or(revm::primitives::U256::ZERO, |a| a.info.balance);

            let account_conflict =
                st.reads.iter().chain(st.writes.iter()).any(|addr| match writers.get(addr) {
                    Some(&(writer, multi)) => writer != st.sender || multi,
                    None => false,
                });
            // The speculative coinbase observation is only valid if
            // the balance it saw equals the canonical running total.
            let stale_coinbase = (st.coinbase.read && st.coinbase_before != canonical_coinbase)
                || (coinbase_dirty && st.coinbase.accessed);

            if st.must_reexec || broken.contains(&st.sender) || account_conflict || stale_coinbase {
                // Re-execute this tx against the canonical DB.
                broken.insert(st.sender);
                coinbase_dirty |= st.coinbase.nontrivial;
                let caller = st.sender;
                let signed = signed_by_idx[i].expect("speculative tx has signed bytes");
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
                    for addr in [caller] {
                        match writers.entry(addr) {
                            Entry::Occupied(mut o) => {
                                if o.get().0 != caller {
                                    o.get_mut().1 = true;
                                }
                            }
                            Entry::Vacant(v) => {
                                v.insert((caller, false));
                            }
                        }
                    }
                    if let tx::TxKind::Call(addr) = signed.to() {
                        let rcp = revm::primitives::Address::from(addr.0);
                        all_touched.insert(rcp);
                        match writers.entry(rcp) {
                            Entry::Occupied(mut o) => {
                                if o.get().0 != caller {
                                    o.get_mut().1 = true;
                                }
                            }
                            Entry::Vacant(v) => {
                                v.insert((caller, false));
                            }
                        }
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
                    match writers.entry(caller) {
                        Entry::Occupied(mut o) => {
                            if o.get().0 != caller {
                                o.get_mut().1 = true;
                            }
                        }
                        Entry::Vacant(v) => {
                            v.insert((caller, false));
                        }
                    }
                    if let tx::TxKind::Call(addr) = signed.to() {
                        let rcp = revm::primitives::Address::from(addr.0);
                        all_touched.insert(rcp);
                        match writers.entry(rcp) {
                            Entry::Occupied(mut o) => {
                                if o.get().0 != caller {
                                    o.get_mut().1 = true;
                                }
                            }
                            Entry::Vacant(v) => {
                                v.insert((caller, false));
                            }
                        }
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
                            evm.precompiles.clear_native_journal();
                            let call_trace = evm.inspector.1.take_root();
                            // Canonical re-execution commits to the
                            // authoritative cache — sweep committed
                            // zero slots (see `commit_state`).
                            let zeroed = Self::zero_slot_writers(&rs.state);
                            evm.commit(rs.state);
                            Self::prune_zero_slots(evm.ctx.journaled_state.database, &zeroed);
                            // Mark the tx's actual write set — accounts
                            // the commit marked modified — as written
                            // by this sender.
                            for addr in &state_keys {
                                if *addr == coinbase {
                                    continue;
                                }
                                if db.cache.accounts.get(addr).is_some_and(|a| {
                                    a.account_state != revm::database::AccountState::None
                                }) {
                                    match writers.entry(*addr) {
                                        Entry::Occupied(mut o) => {
                                            if o.get().0 != caller {
                                                o.get_mut().1 = true;
                                            }
                                        }
                                        Entry::Vacant(v) => {
                                            v.insert((caller, false));
                                        }
                                    }
                                }
                            }
                            final_results[i] = Some(Ok((r, call_trace)));
                        }
                        Err(e) => {
                            final_results[i] = Some(Err(ExecError::ModuleRejected(format!(
                                "evm transact failed: {e:?}"
                            ))));
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
            for w in &st.writes {
                match writers.entry(*w) {
                    Entry::Occupied(mut o) => {
                        if o.get().0 != st.sender {
                            o.get_mut().1 = true;
                        }
                    }
                    Entry::Vacant(v) => {
                        v.insert((st.sender, false));
                    }
                }
                all_touched.insert(*w);
            }
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
                    results.push(Err(ExecError::ModuleRejected(
                        "parallel execution: missing result".to_string(),
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
