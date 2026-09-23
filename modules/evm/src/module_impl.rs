//! `framework::Module` trait adapter for the EVM module.
//!
//! Split from `lib.rs` around the adapter invariant: this is the
//! only place the consensus-facing lifecycle (`begin_block` /
//! `deliver_tx` / `end_block` / `commit` / snapshot export) touches
//! module internals. Keeping the adapter in one file makes it
//! auditable that every state transition the chain can drive goes
//! through the documented ordering — and that nothing else calls
//! into it.

use super::{
    Address, Arc, BLOCK_TIME_SECS, Balances, CHAIN_BLOCK_GAS_LIMIT, CacheDB, EmptyDB, Event,
    EvmModule, ExecError, HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS, Hash, Height,
    INTRINSIC_GAS_BASE, MODULE_ID, Module, PreverifiedTx, SpecId, TxContext,
    alloy_primitives_address, encode_trie_leaf, fee, history, persist, receipts, sparse_walk, trie,
    tx, versioned,
};

impl Module for EvmModule {
    fn name(&self) -> &'static str {
        "evm"
    }

    fn id(&self) -> u8 {
        MODULE_ID
    }

    fn begin_block(&self, height: Height) {
        // A6: set the block context for EVM execution. The block number
        // and timestamp are wired into revm's BlockEnv in `execute`.
        //
        // Height-derived timestamp (`h * BLOCK_TIME_SECS`): the
        // deterministic stand-in used when no consensus context is
        // available — direct `begin_block` callers (module-level
        // tests, clockless engines, pre-context journal replay).
        // The production path drives `begin_block_ctx`, which runs
        // this same logic and then overlays the header-committed
        // timestamp, so real blocks always carry consensus time.
        let h = height.value();
        *framework::lock_state(&self.block_height) = h;
        *framework::lock_state(&self.block_timestamp) = h.saturating_mul(BLOCK_TIME_SECS);

        // `touched` is deliberately NOT cleared here: marks made
        // before the first block (genesis `alloc`, preinstalls,
        // assembly-time funding) must survive into block 1's
        // `end_block` flush or genesis state would be committed to
        // the state root yet never persisted — a restart would serve
        // a different account set than the committed root covers.
        // `end_block` clears the set after flushing, so `touched`
        // still means exactly "accounts written since the last
        // durable commit" and stays block-bounded.

        // Start a fresh undo accumulator — any residue here means a
        // previous block never sealed, which is a bug, but dropping
        // it is safer than mixing two blocks' pre-values.
        framework::lock_state(&self.block_undo).accounts.clear();

        // EIP-2935: record the parent block's hash in the
        // history-storage contract's ring buffer. Geth performs this
        // as a gasless system call (caller `SYSTEM_ADDRESS`) at the
        // start of block processing — before any transaction — that
        // stores `parent_hash` at slot `(h-1) % HISTORY_SERVE_WINDOW`.
        // A direct storage write is state-equivalent (the system call
        // produces no transaction, receipt, or log) and is captured
        // into this block's undo like any other write, so historical
        // reads at `h-1` still observe the pre-write slot. Prague
        // gate: a pre-Prague spec must not mutate this storage or the
        // state root diverges from the real fork.
        if h > 0 && self.spec.is_enabled_in(SpecId::PRAGUE) {
            let parent_hash = framework::lock_state(&self.history).block(h - 1).map(|b| b.hash);
            if let Some(parent_hash) = parent_hash {
                let mut db_guard = framework::lock_state(&self.db);
                let db = Arc::make_mut(&mut *db_guard);
                framework::lock_state(&self.block_undo).capture(
                    HISTORY_STORAGE_ADDRESS,
                    db.cache.accounts.get(&HISTORY_STORAGE_ADDRESS),
                );
                let account =
                    db.cache.accounts.entry(HISTORY_STORAGE_ADDRESS).or_insert_with(|| {
                        revm::database::DbAccount {
                            info: revm::database::state::AccountInfo {
                                balance: revm::primitives::U256::ZERO,
                                nonce: 0,
                                code_hash: revm::primitives::KECCAK_EMPTY,
                                account_id: None,
                                code: Some(revm::bytecode::Bytecode::new_raw(
                                    revm::primitives::Bytes::new(),
                                )),
                            },
                            account_state: revm::database::AccountState::Touched,
                            storage: revm::primitives::HashMap::default(),
                        }
                    });
                let slot = revm::primitives::U256::from((h - 1) % HISTORY_SERVE_WINDOW);
                let value = revm::primitives::U256::from_be_bytes(parent_hash.0);
                // Sparse-storage invariant: a zero write deletes —
                // "slot = 0" and "slot absent" are the same MPT
                // state. A parent hash is a keccak output (never
                // zero in practice), but keep the rule uniform.
                if value.is_zero() {
                    account.storage.remove(&slot);
                } else {
                    account.storage.insert(slot, value);
                }
                account.account_state = revm::database::AccountState::Touched;
                drop(db_guard);
                framework::lock_state(&self.touched).insert(HISTORY_STORAGE_ADDRESS);
            }
        }
    }

    /// Apply the consensus-committed execution context on top of the
    /// legacy begin: the block timestamp, the fee beneficiary, and
    /// the block gas limit all come from the `FinalizedBlock`'s
    /// recorded context rather than local derivation. Every field
    /// keeps the legacy behavior when the context carries the zero
    /// sentinel — `0` means "no consensus value", never a real
    /// timestamp/beneficiary/limit.
    ///
    /// The full `begin_block` runs first so height bookkeeping, the
    /// undo reset, and the EIP-2935 parent-hash write stay identical
    /// on both paths; the context then overlays the three fields it
    /// actually governs.
    fn begin_block_ctx(&self, height: Height, ctx: &types::BlockContext) {
        self.begin_block(height);
        if ctx.timestamp_ms != 0 {
            // The header stamps milliseconds; `block.timestamp` is
            // seconds-granularity (Ethereum semantics) — truncate.
            *framework::lock_state(&self.block_timestamp) = ctx.timestamp_secs();
        }
        if ctx.beneficiary != primitives::Address::ZERO {
            // The proposer's staking address is the fee recipient:
            // priority-fee tips land with the validator that built
            // the block, matching every other module's identity
            // space (the attendance `signers` use the same set).
            *framework::lock_state(&self.coinbase) =
                revm::primitives::Address::from(ctx.beneficiary.0);
        }
        if ctx.gas_limit != 0 {
            // Consensus is the authority on block capacity: the
            // budget the block was produced under becomes the limit
            // revm enforces and the EIP-1559 target derives from.
            self.block_gas_limit.store(ctx.gas_limit, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Seal the block, then advance the EIP-1559 base fee for the
    /// next block from this block's measured gas usage.
    ///
    /// Ordering matters: `end_block` seals the history record with
    /// the fee this block was *executed under* (Ethereum semantics —
    /// `block.baseFee` describes the block itself), so the update
    /// runs strictly after sealing. `gas_used` comes back from the
    /// sealed record — the same number `eth_getBlock` reports — so
    /// the fee transition and the observable block always agree.
    ///
    /// A zero `ctx.gas_limit` keeps the running `max_gas`; a nonzero
    /// one re-targets the fee curve to the consensus-enforced limit
    /// (a governance block-budget change moves the fee with it).
    fn end_block_ctx(&self, height: Height, ctx: &types::BlockContext) -> Vec<Event> {
        self.end_block(height);
        let gas_used = {
            let history = framework::lock_state(&self.history);
            history.block(height.value()).map(|b| b.gas_used)
        };
        // The sealed block is written by `end_block` immediately
        // before this — `None` would mean sealing never ran, in
        // which case there is no measured usage to update from and
        // the fee must stay put rather than drift toward the floor.
        if let Some(gas_used) = gas_used {
            let mut fee_state = framework::lock_state(&self.fee_state);
            if ctx.gas_limit != 0 && ctx.gas_limit != fee_state.max_gas() {
                fee_state.set_max_gas(ctx.gas_limit);
            }
            fee_state.update(gas_used);
        }
        Vec::new()
    }

    /// A4: validate a signed EVM transaction for mempool admission.
    ///
    /// This is the admission gate. It runs on every submitted tx
    /// *before* the tx enters the mempool. It checks:
    ///
    /// 1. **RLP decode** — the message must be a valid RLP-encoded
    ///    signed transaction (Legacy, EIP-2930, or EIP-1559).
    /// 2. **Chain ID** — must match the module's chain ID (EIP-155
    ///    replay protection).
    /// 3. **Signature** — the secp256k1 signature must recover to a
    ///    valid sender address.
    /// 4. **Nonce** — the tx nonce must be ≥ the sender's current
    ///    account nonce (rejects stale txs; allows future nonces for
    ///    mempool queueing).
    /// 5. **Gas limit** — must be positive and within block limits.
    /// 6. **Intrinsic gas** — the gas limit must cover the tx's
    ///    intrinsic cost (21k base + calldata + access list).
    /// 7. **Balance** — the sender must have enough balance to cover
    ///    the gas cost (`gas_limit * max_fee_per_gas`) plus the
    ///    transferred value.
    ///
    /// This method is pure: it reads module state but does not mutate
    /// it. A tx that passes `validate` may still fail in `handle`
    /// (e.g. out-of-gas, revert). But a tx that fails `validate`
    /// never reaches `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] for RLP decode failures,
    /// wrong chain ID, or signature recovery failure. Returns
    /// [`ExecError::ModuleRejected`] for nonce, gas, or balance
    /// violations.
    fn validate(&self, _ctx: &TxContext, msg: &[u8]) -> Result<(), ExecError> {
        // 1. RLP decode — `decode_raw` enforces complete input
        // consumption: the trust boundary is exactly as strict as
        // the RPC parse, so a trailing-junk encoding that RPC
        // rejects can't enter through the mempool/executor path.
        let signed = tx::SignedTx::decode_raw(msg).map_err(|_| ExecError::Malformed)?;

        // 2. Chain ID (EIP-155 replay protection).
        if signed.chain_id() != self.chain_id {
            return Err(ExecError::Malformed);
        }

        // 3. Signature recovery.
        let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
        let sender_addr = Address(sender.0);

        // 4. Nonce: tx nonce must be ≥ current account nonce.
        //    This rejects stale (already-used) nonces. Future nonces
        //    are allowed for mempool queueing.
        let current_nonce = self.nonce(&sender_addr);
        if signed.nonce() < current_nonce {
            return Err(ExecError::ModuleRejected(format!(
                "nonce {nonce} < current {current_nonce}",
                nonce = signed.nonce()
            )));
        }

        // 5. Gas limit: must be positive.
        let gas_limit = signed.gas_limit();
        if gas_limit == 0 {
            return Err(ExecError::ModuleRejected("gas_limit is zero".to_string()));
        }

        // HIGH fix: gas_limit must fit within the block gas limit.
        // A tx with gas_limit > block_gas_limit can never be included
        // and should be rejected at admission to save mempool space.
        if gas_limit > self.block_gas_limit() {
            return Err(ExecError::ModuleRejected(format!(
                "gas_limit {gas_limit} > block_gas_limit {}",
                self.block_gas_limit()
            )));
        }

        // 6. Intrinsic gas: gas_limit must cover the intrinsic cost.
        //    The intrinsic cost is 21_000 (base) + calldata cost
        //    (16/byte for non-zero, 4/byte for zero) + access list
        //    cost. We use a conservative lower bound of 21_000 here;
        //    the full calldata-aware check arrives with the gas
        //    economics phase (A5).
        if gas_limit < INTRINSIC_GAS_BASE {
            return Err(ExecError::ModuleRejected(format!(
                "gas_limit {gas_limit} < intrinsic {INTRINSIC_GAS_BASE}"
            )));
        }

        // HIGH fix: EIP-1559 fee gates.
        //   a. max_fee >= base_fee: a tx with max_fee < base_fee
        //      can never be included (revm rejects it during
        //      execution). Reject at admission to save resources.
        //   b. priority_fee <= max_fee: EIP-1559 requires
        //      max_priority_fee_per_gas <= max_fee_per_gas. A tx
        //      with priority_fee > max_fee is invalid.
        let max_fee = u128::try_from(signed.max_fee_per_gas())
            .map_err(|_| ExecError::ModuleRejected("max_fee overflow u128".to_string()))?;
        let priority_fee = u128::try_from(signed.max_priority_fee_per_gas())
            .map_err(|_| ExecError::ModuleRejected("priority_fee overflow u128".to_string()))?;
        if max_fee < u128::from(self.current_base_fee()) {
            return Err(ExecError::ModuleRejected(format!(
                "max_fee {max_fee} < base_fee {}",
                self.current_base_fee()
            )));
        }
        if priority_fee > max_fee {
            return Err(ExecError::ModuleRejected(format!(
                "priority_fee {priority_fee} > max_fee {max_fee}"
            )));
        }

        // 7. Balance: sender must cover gas_cost + value.
        //    gas_cost = gas_limit * max_fee_per_gas (the worst-case
        //    fee the sender could pay). For legacy txs, gas_price is
        //    the max fee. For EIP-1559, max_fee_per_gas is the cap.
        let balance = self.balance(&sender_addr);
        let value = u128::try_from(signed.value())
            .map_err(|_| ExecError::ModuleRejected("value overflow u128".to_string()))?;
        // gas_cost = gas_limit * max_fee, checked for overflow.
        let gas_cost = u128::from(gas_limit)
            .checked_mul(max_fee)
            .ok_or_else(|| ExecError::ModuleRejected("gas cost overflow".to_string()))?;
        let total_needed = gas_cost
            .checked_add(value)
            .ok_or_else(|| ExecError::ModuleRejected("gas_cost + value overflow".to_string()))?;
        if balance < total_needed {
            return Err(ExecError::ModuleRejected(format!(
                "insufficient balance: have {balance}, need {total_needed}"
            )));
        }

        Ok(())
    }

    /// The EVM is self-funded: revm charges `gas_used × effective
    /// gas price` from the sender's account inside execution,
    /// bounded below by the block base fee (`GasPriceLessThanBasefee`
    /// rejects under-priced txs). Charging the envelope fee on top
    /// would double-charge every EVM user.
    fn pays_own_fee(&self) -> bool {
        true
    }

    /// The durable schema version this binary writes (`0x04` meta
    /// namespace). Bump when the on-disk account/history/undo
    /// encoding or cache layout changes in a way that needs a
    /// migration step; leave `migrate` to fill it in.
    fn state_version(&self) -> u32 {
        1
    }

    /// Charge the envelope fee from the sender's EVM balance. When
    /// the node configured a `fee_recipient` (the staking module's
    /// `FEE_POOL` in production wiring) the fee is *collected* —
    /// transferred to the pool for `end_block` distribution to
    /// validators and delegators. Without a recipient the fee is
    /// **burned** (debited, credited to nobody), matching
    /// Ethereum's base-fee semantics — the operator's policy choice.
    ///
    /// `ctx.fee` is in `u64` base units; the `Balances` impl
    /// converts to wei at [`WEI_PER_UNIT`](framework::WEI_PER_UNIT).
    /// Zero-fee txs skip the ledger touch entirely (fresh senders
    /// with `fee = 0` succeed without an account record — same
    /// admission behavior the old bank fee module had).
    fn charge_fee(&self, ctx: &TxContext) -> Result<(), ExecError> {
        if ctx.fee == 0 {
            return Ok(());
        }
        if let Some(recipient) = self.fee_recipient {
            self.transfer(&ctx.sender, &recipient, ctx.fee)
        } else {
            self.debit(&ctx.sender, ctx.fee)
        }
    }

    /// The EVM is self-authenticating: the sender is recovered from
    /// the secp256k1 signature inside the RLP transaction, so the
    /// envelope's declared `sender` is a mempool-ordering hint only.
    /// An envelope signature (`SIGNED_FLAG`) on an EVM tx is rejected
    /// as malformed — it would shift the payload offset and add a
    /// redundant recovery on top of the RLP's own verification.
    fn authenticates_sender(&self) -> bool {
        true
    }

    /// Gas estimate = the tx's declared `gas_limit`, decoded from
    /// the RLP payload. The default `1000 + len` proxy would let a
    /// tx with a 30M gas limit count as ~150 gas and blow through
    /// the block limit at execution time — the block gas limit must
    /// be enforced against *declared* limits (EIP-1559 semantics:
    /// `sum(tx.gas_limit) <= block.gas_limit`).
    ///
    /// An undecodable tx counts as `u64::MAX`: it cannot carry a
    /// valid gas limit, so any proposal containing it exceeds the
    /// limit and is rejected at `process_proposal` — the safe
    /// direction.
    fn estimate_gas(&self, msg: &[u8]) -> u64 {
        // `decode_raw` (exact-consumption): a tx with trailing junk
        // is undecodable here too, so its proposal is rejected at
        // `process_proposal` — the same treatment the RPC path gives.
        match tx::SignedTx::decode_raw(msg) {
            Ok(signed) => signed.gas_limit(),
            Err(_) => u64::MAX,
        }
    }

    fn handle(&self, _ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        // Perf: single RLP decode. Decode once to get both the tx
        // type (for the receipt) and the signed tx (for execution).
        // The old code decoded twice — once in handle() for the tx
        // type, once in execute() for execution. The decode is
        // ~1 µs, so this saves ~1 µs per tx on the cold path.
        let signed = tx::SignedTx::decode_raw(msg).map_err(|_| ExecError::Malformed)?;
        let tx_type = signed.tx_type();
        // The canonical Ethereum tx hash is keccak256 of the raw
        // RLP — the same value `eth_sendRawTransaction` returns.
        let tx_hash = alloy_primitives::keccak256(msg);
        let (result, caller, call_trace) = self.execute_signed(&signed)?;

        // Phase C: build a receipt from the execution result.
        // The receipt captures status, gas used, logs, bloom, and
        // (for CREATE) the created address. This is the data that
        // `eth_getTransactionReceipt` returns and that goes into the
        // block's receipts trie.
        let receipt = receipts::Receipt::from_execution_result(&result, tx_type);

        // Record into the executed-block history for RPC queries
        // (`eth_getTransactionByHash`, `eth_getTransactionReceipt`,
        // `eth_getLogs`). `record` assigns the tx_index from the
        // pending-block position; `msg` (the raw signed RLP) is kept
        // until `seal_block` computes `transactionsRoot`.
        framework::lock_state(&self.history).record(
            history::stored_tx(&signed, caller, tx_hash, 0),
            receipt.clone(),
            msg,
            call_trace,
        );

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

    /// Batch execution: delegate to the inherent `handle_batch` which
    /// recovers senders in parallel via rayon and uses the native fast
    /// path for simple transfers.
    ///
    /// The `ctx` (sender, nonce, fee) from the tx envelope is ignored
    /// — the EVM recovers the sender from the secp256k1 signature in
    /// the RLP-encoded payload. The envelope's sender/nonce/fee fields
    /// exist only for the mempool's v0 format compatibility.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch(&self, msgs: &[(TxContext, &[u8])]) -> Vec<Result<Vec<Event>, ExecError>> {
        // Borrow the raw RLP bytes from each (ctx, payload) pair —
        // no per-tx clone. The payload IS the RLP-encoded signed
        // transaction.
        let raw_txs: Vec<&[u8]> = msgs.iter().map(|(_, payload)| *payload).collect();
        let ctx = TxContext { sender: primitives::Address([0u8; 20]), nonce: 0, fee: 0 };
        // Call the inherent `handle_batch` (2 args: ctx, msgs) — Rust
        // resolves to the inherent method, not the trait method (1 arg)
        // because the signatures differ.
        self.handle_batch(&ctx, &raw_txs)
    }

    /// Pre-recover senders from RLP-encoded signed EVM transactions.
    ///
    /// Delegates to the inherent `preverify_batch` which uses rayon
    /// to parallelize secp256k1 recovery across cores. The
    /// pre-recovered senders are cached by the executor and reused
    /// at block execution time to skip recovery entirely.
    ///
    /// # Errors
    ///
    /// Returns `Err(ExecError::Malformed)` for each transaction
    /// that cannot be RLP-decoded, has a wrong chain ID, or whose
    /// signature is invalid.
    fn preverify_batch<'a>(
        &self,
        msgs: &'a [&'a [u8]],
    ) -> Vec<Result<executor::PreverifiedTx<'a>, ExecError>> {
        // Delegate to the inherent `preverify_batch` (which returns
        // `evm::PreverifiedTx` borrowing from `msgs`) and convert to
        // the executor's `PreverifiedTx` (which uses a generic
        // `[u8; 20]` sender). The borrow propagates — zero clones.
        let results = EvmModule::preverify_batch(self, msgs);
        results
            .into_iter()
            .map(|r| {
                r.map(|pv| executor::PreverifiedTx { raw: pv.raw, sender: pv.sender.into_array() })
            })
            .collect()
    }

    /// Execute a batch of pre-verified EVM transactions (serial).
    ///
    /// Delegates to the inherent `handle_batch_preverified` which
    /// skips secp256k1 recovery entirely — only RLP decoding and
    /// chain ID validation remain. This is the highest-throughput
    /// serial execution path.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch_preverified(
        &self,
        ctxs: &[TxContext],
        txs: &[executor::PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // The per-tx envelope contexts are unused — the EVM recovers
        // each sender from the transaction's own secp256k1 signature
        // and verifies it against `pv.sender`. A zero ctx (same
        // convention as `handle_batch` above) makes the ignoring
        // explicit rather than passing an arbitrary tx's context.
        let ctx = TxContext { sender: primitives::Address([0u8; 20]), nonce: 0, fee: 0 };
        let _ = ctxs;
        // Convert the executor's `PreverifiedTx` (generic [u8; 20]
        // sender) to the EVM's `PreverifiedTx` (revm Address sender).
        // The raw bytes stay borrowed — no per-tx clone.
        let evm_txs: Vec<PreverifiedTx<'_>> = txs
            .iter()
            .map(|pv| PreverifiedTx {
                raw: pv.raw,
                sender: revm::primitives::Address::from(pv.sender),
            })
            .collect();
        // Call the inherent `handle_batch_preverified` (3 args).
        EvmModule::handle_batch_preverified(self, &ctx, &evm_txs)
    }

    /// Execute a batch of pre-verified EVM transactions in parallel.
    ///
    /// Delegates to the inherent `handle_batch_parallel_preverified`
    /// which groups transactions by sender and executes each group on
    /// a separate rayon thread. Results are merged in original block
    /// order.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch_parallel_preverified(
        &self,
        ctxs: &[TxContext],
        txs: &[executor::PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Same convention as `handle_batch_preverified`: envelope
        // contexts are unused — senders come from the signatures.
        let ctx = TxContext { sender: primitives::Address([0u8; 20]), nonce: 0, fee: 0 };
        let _ = ctxs;
        // Convert the executor's `PreverifiedTx` to the EVM's.
        // The raw bytes stay borrowed — no per-tx clone.
        let evm_txs: Vec<PreverifiedTx<'_>> = txs
            .iter()
            .map(|pv| PreverifiedTx {
                raw: pv.raw,
                sender: revm::primitives::Address::from(pv.sender),
            })
            .collect();
        // Call the inherent `handle_batch_parallel_preverified` (3 args).
        EvmModule::handle_batch_parallel_preverified(self, &ctx, &evm_txs)
    }

    fn end_block(&self, height: Height) -> Vec<Event> {
        // Seal the executed-block history for RPC queries. Every
        // block seals an entry — including blocks with zero EVM txs —
        // so `eth_getBlockByNumber` can distinguish "empty block" from
        // "unknown block".
        //
        // `state_root` is computed incrementally (O(touched · log n)
        // via the sparse retained-trie walk). The executor calls
        // `state_root` again right after `end_block` for the block
        // attestation; clearing `touched` after computing lets that
        // second call hit the O(1) cached fast path
        // (`leaves_ready && touched.is_empty()`), so sealing adds no
        // extra trie work per block.
        let root = self.state_root();
        let timestamp = *framework::lock_state(&self.block_timestamp);
        let coinbase = *framework::lock_state(&self.coinbase);
        let (sealed_block, evicted) = {
            let mut history = framework::lock_state(&self.history);
            let evicted = history.seal_block(
                height.value(),
                timestamp,
                self.block_gas_limit(),
                self.current_base_fee(),
                coinbase,
                alloy_primitives::B256::from(root.0),
            );
            // Clone the sealed record for persistence — the clone is
            // once per block (cold path) and keeps the backend write
            // off the history lock's critical section.
            let sealed = history.block(height.value()).cloned();
            (sealed, evicted)
        };

        // Fold the block's captured pre-values into the versioned
        // index, then prune it to the same retention window as
        // `history` so the two stay aligned. Reads at heights below
        // the floor fail closed ("state not available") — see
        // `versioned.rs`.
        let undo = std::mem::take(&mut *framework::lock_state(&self.block_undo));
        // Serialize the undo blob only when a backend will consume
        // it — pointless work otherwise (per-block, cold path, but
        // free is better).
        let has_backend = framework::lock_state(&self.backend).is_some();
        let undo_blob = has_backend.then(|| persist::serialize_undo(&undo));
        let pruned_undo = {
            let mut versioned = framework::lock_state(&self.versioned);
            versioned.push(height.value(), undo);
            let history = framework::lock_state(&self.history);
            history.blocks_floor().map_or_else(Vec::new, |floor| versioned.prune_below(floor))
        };

        // If a StorageBackend is attached, flush accounts + the
        // sealed block record + the undo blob in ONE `apply_batch`.
        // Atomicity matters: a crash between the account flush and
        // the history write would otherwise leave durable state at
        // height N with durable history at N-1 — on restart the node
        // would then serve state-N answers labelled as height N-1.
        let mut backend_guard = framework::lock_state(&self.backend);
        if let Some(ref mut backend) = *backend_guard {
            let mut ops = self.account_flush_ops();
            if let Some(block) = sealed_block {
                ops.push(storage::Op::Set {
                    key: persist::block_key(height.value()),
                    value: persist::serialize_block(&block),
                });
            }
            if let Some(blob) = undo_blob {
                ops.push(storage::Op::Set { key: persist::undo_key(height.value()), value: blob });
            }
            // `evicted` (history window) and `pruned_undo` (undo
            // window) cover the same heights — the two indexes are
            // kept aligned — but they namespace different keys.
            for h in evicted {
                ops.push(storage::Op::Delete { key: persist::block_key(h) });
            }
            for h in pruned_undo {
                ops.push(storage::Op::Delete { key: persist::undo_key(h) });
            }
            // `end_block` cannot return an error (the `Module` trait
            // is infallible), so the flush goes through the pending
            // buffer: a failed batch keeps its ops queued for the
            // next block's retry instead of silently dropping the
            // block's state + history writes. The failure is latched
            // into `storage_error` for node health checks.
            let _ = self.flush_pending(backend.as_mut(), ops);
        }
        drop(backend_guard);

        framework::lock_state(&self.touched).clear();
        Vec::new()
    }

    #[allow(clippy::too_many_lines)]
    fn state_root(&self) -> Hash {
        // Phase B: compute the Ethereum-compatible Merkle-Patricia
        // Trie state root over all accounts in the CacheDB.
        //
        // The state trie is keyed by keccak256(address) with the
        // RLP-encoded `TrieAccount { nonce, balance, storage_root,
        // code_hash }` as the value. Each account's `storage_root`
        // is computed from its individual storage trie (keyed by
        // keccak256(slot)).
        //
        // # Incremental storage root cache
        //
        // The dominant cost of `state_root` is per-account storage
        // root computation (O(storage_size) per account). We cache
        // each account's storage root and only recompute it for
        // accounts in the `touched` set. This turns the per-block
        // cost from O(total_storage) to O(touched_storage +
        // total_accounts) — the trie assembly is still O(n) but
        // the storage root computation (the expensive part) is
        // incremental.
        //
        // # Panics
        //
        // Panics if the DB mutex is poisoned (a thread panicked while
        // holding the lock). This is unrecoverable and indicates a bug.
        let touched = framework::lock_state(&self.touched);
        let mut leaves = framework::lock_state(&self.trie_leaves);
        let mut leaves_ready = framework::lock_state(&self.trie_leaves_ready);
        let mut retained = framework::lock_state(&self.retained_branches);

        // Fast path: if the leaf map is built and nothing was
        // touched since the last computation, return the cached
        // root. This makes consecutive `state_root` calls with no
        // intervening execution O(1).
        if *leaves_ready
            && touched.is_empty()
            && let Some(cached) = *framework::lock_state(&self.cached_state_root)
        {
            return Hash(cached.0);
        }

        let db = framework::lock_state(&self.db);
        let mut storage_root_cache = framework::lock_state(&self.storage_root_cache);

        if *leaves_ready {
            // Incremental patch — only `touched` accounts are
            // re-encoded. `touched` is the complete modified set
            // (populated from `EvmState::keys()` post-commit), so
            // every changed account is patched; accounts absent
            // from the cache were removed from state.
            for addr in touched.iter() {
                let hashed = alloy_primitives::keccak256(addr);
                // `NotExisting` tombstones (selfdestruct, or a revm
                // `basic()` miss cached as absent) are NOT part of the
                // state trie — committing them as leaves would put the
                // root ahead of persisted state, which never carries
                // them (flush emits `Delete`). Two nodes that read a
                // missing account on different paths would then
                // compute different roots from identical state.
                if let Some(account) = db
                    .cache
                    .accounts
                    .get(addr)
                    .filter(|a| a.account_state != revm::database::AccountState::NotExisting)
                {
                    let storage_root = if account.storage.is_empty() {
                        trie::EMPTY_ROOT
                    } else {
                        // Touched → always recompute the
                        // storage root (its slots changed).
                        let storage_iter = account
                            .storage
                            .iter()
                            .filter(|(_, value)| !value.is_zero())
                            .map(|(slot, value)| {
                                (
                                    alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()),
                                    *value,
                                )
                            });
                        let root = trie::storage_root(storage_iter);
                        storage_root_cache.insert(*addr, root);
                        root
                    };
                    leaves.insert(hashed, encode_trie_leaf(account, storage_root));
                } else {
                    leaves.remove(&hashed);
                    storage_root_cache.remove(addr);
                }
            }
        } else {
            // Full build — first call after construction or
            // `import_state`. Hashes and encodes every account once
            // (same cost as the old path); subsequent calls patch
            // only `touched` accounts. `NotExisting` tombstones are
            // skipped — they are not part of the committed trie (see
            // the incremental path above).
            for (addr, account) in &db.cache.accounts {
                if account.account_state == revm::database::AccountState::NotExisting {
                    continue;
                }
                let storage_root = if account.storage.is_empty() {
                    trie::EMPTY_ROOT
                } else if touched.contains(addr) {
                    // Recompute for touched accounts.
                    let storage_iter = account
                        .storage
                        .iter()
                        .filter(|(_, value)| !value.is_zero())
                        .map(|(slot, value)| {
                            (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                        });
                    let root = trie::storage_root(storage_iter);
                    storage_root_cache.insert(*addr, root);
                    root
                } else {
                    // Reuse cached storage root for untouched accounts.
                    storage_root_cache.get(addr).copied().unwrap_or_else(|| {
                        let storage_iter = account
                            .storage
                            .iter()
                            .filter(|(_, value)| !value.is_zero())
                            .map(|(slot, value)| {
                                (
                                    alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()),
                                    *value,
                                )
                            });
                        let root = trie::storage_root(storage_iter);
                        storage_root_cache.insert(*addr, root);
                        root
                    })
                };
                leaves.insert(
                    alloy_primitives::keccak256(addr),
                    encode_trie_leaf(account, storage_root),
                );
            }
            *leaves_ready = true;
            // Clear retained branches on full rebuild — the trie
            // structure changed entirely.
            retained.clear();
        }

        // Ceiling 3: Sparse retained trie for O(touched · log n)
        // state root computation.
        //
        // The state root computation has three costs:
        // 1. Per-account storage root computation — O(storage_size)
        //    per account. Already incremental: only touched accounts
        //    recompute their storage roots (via `storage_root_cache`).
        // 2. Per-account leaf encoding — O(1) per account. Already
        //    incremental: only touched accounts are re-encoded in
        //    the `trie_leaves` BTreeMap.
        // 3. HashBuilder trie assembly — was O(n) over all leaves.
        //    Now O(touched · log n) via the sparse walk below.
        //
        // # Sparse walk algorithm
        //
        // After the first full build, `retained_branches` holds every
        // branch node's `BranchNodeCompact` (masks + child hashes),
        // keyed by nibble prefix. On subsequent calls, instead of
        // feeding all N leaves into `HashBuilder`, we walk the
        // retained branch tree depth-first:
        //
        // - For each branch node at prefix P, iterate its children
        //   (the set bits in `state_mask`).
        // - For a child at P+n that contains NO touched account:
        //   call `add_branch(P+n, child_hash, true)` — the entire
        //   subtree is skipped (O(1)).
        // - For a child that DOES contain touched accounts:
        //   - If the child is a stored branch (in `tree_mask` and
        //     present in `retained_branches`), recurse.
        //   - Otherwise (inline leaf/extension, or a shallow branch
        //     not in `retained_branches`), feed all leaves under
        //     that child prefix from `trie_leaves` (at most 16 for
        //     a shallow branch; O(1) for a leaf).
        //
        // The total work is O(touched · depth · 16) = O(touched ·
        // log n): at each of the ~log n levels, we visit at most 16
        // children per touched path, and each untouched child is
        // skipped in O(1) via `add_branch`.
        //
        // After the build, `HashBuilder::split()` returns the
        // rebuilt branch nodes. For the full build, these replace
        // `retained_branches` entirely. For the incremental build,
        // we first remove stale entries on the touched path (prefixes
        // of touched hashed keys that were in `retained_branches`),
        // then merge the new `BranchNodeCompact`s — this correctly
        // handles account insertions (new branches) and deletions
        // (branches that become leaves/extensions and are no longer
        // in the `split()` output).
        //
        // # `with_updates(true)` overhead
        //
        // Enabling update tracking adds a constant factor to each
        // branch node construction. For the full build this is a
        // one-time O(n) cost. For the incremental build the overhead
        // is O(touched · log n) — negligible compared to the savings.
        //
        // # Edge cases
        //
        // - Empty state (zero accounts): `retained_branches` is
        //   empty; the full-build path feeds zero leaves and returns
        //   `EMPTY_ROOT`.
        // - Single account: no branch nodes, `retained_branches` is
        //   empty; the sparse walk falls back to feeding all leaves
        //   (O(1)).
        // - Root is an extension (rare with keccak256 keys):
        //   `retained_branches[empty]` doesn't exist; we fall back to
        //   feeding all leaves for that call, and `split()` repopulates
        //   `retained_branches` for the next call.
        let mut hb = alloy_trie::HashBuilder::default().with_updates(true);

        let is_full_build = !*leaves_ready;
        let can_sparse = !is_full_build && !retained.is_empty();

        if can_sparse {
            // Sparse incremental walk — O(touched · log n).
            let touched_hashes: std::collections::BTreeSet<alloy_primitives::B256> =
                touched.iter().map(alloy_primitives::keccak256).collect();
            sparse_walk(
                alloy_trie::Nibbles::default(),
                &retained,
                &leaves,
                &touched_hashes,
                &mut hb,
            );
        } else {
            // Full build (or fallback when no retained branches):
            // feed every leaf in sorted hashed-key order.
            for (hashed_key, rlp) in leaves.iter() {
                hb.add_leaf(alloy_trie::Nibbles::unpack(hashed_key), rlp);
            }
        }

        let root = hb.root();
        let (_, branch_updates) = hb.split();

        if is_full_build {
            // Full build: replace the entire retained map.
            // `split()` returns `alloy_primitives::map::HashMap`
            // (hashbrown, DefaultHashBuilder); convert to the std
            // HashMap used by `retained_branches`.
            *retained = branch_updates.into_iter().collect();
        } else {
            // Incremental build: remove stale branches on the
            // touched path, then merge the rebuilt branches.
            // A branch is "on the touched path" if its nibble
            // prefix is a prefix of any touched hashed key. We
            // check all 64 prefix lengths per touched key; only
            // prefixes that exist in `retained` are removed.
            for addr in touched.iter() {
                let hashed = alloy_primitives::keccak256(addr);
                let nibbles = alloy_trie::Nibbles::unpack(hashed);
                for len in 0..nibbles.len() {
                    let prefix = nibbles.slice(..len);
                    retained.remove(&prefix);
                }
            }
            for (prefix, node) in branch_updates {
                retained.insert(prefix, node);
            }
        }

        // Cache the state root for the next call's fast path.
        *framework::lock_state(&self.cached_state_root) = Some(root);

        // Convert the alloy B256 root to Oxide's Hash type.
        Hash(root.0)
    }

    /// Export the EVM's committed state for snapshot sync.
    ///
    /// Returns `Some(snapshot)` if a `StorageBackend` is attached,
    /// `None` otherwise.
    ///
    /// The committed `state_root` covers the whole `CacheDB` account
    /// set — which can run ahead of the backend (genesis-funded and
    /// preinstalled accounts, for example, sit in the cache until the
    /// first `end_block` flush). A snapshot built from the backend
    /// alone would then be unable to reproduce the claimed root
    /// (audit 3.2). So the `0x01` account entries are serialized from
    /// the authoritative cache via the same
    /// [`Self::serialize_committed_account`] the flush uses, while the
    /// `0x02`/`0x03`/`0x04` namespaces (sealed history, undo window,
    /// schema meta — RPC data, not committed to the trie) are copied
    /// from the backend verbatim.
    fn export_state(&self) -> Option<storage::Snapshot> {
        let backend = framework::lock_state(&self.backend);
        let mut snap = backend.as_ref()?.snapshot_export();
        // Drop the backend's account entries — the cache is
        // authoritative for committed state and may hold accounts
        // the backend has not seen yet.
        snap.entries.retain(|(k, _)| k.0[0] != persist::NS_ACCOUNT);
        // Serialize the account set from an `Arc` snapshot taken
        // under a short lock — the O(accounts) walk must not hold
        // the db mutex against in-flight commits.
        let db_snap = {
            let db = framework::lock_state(&self.db);
            Arc::clone(&db)
        };
        snap.entries.reserve(db_snap.cache.accounts.len());
        for evm_addr in db_snap.cache.accounts.keys() {
            if let Some(value) = Self::serialize_committed_account(evm_addr, &db_snap) {
                let key = persist::account_key(&Address(evm_addr.0.into()));
                snap.entries.push((key, value));
            }
        }
        drop(db_snap);
        drop(backend);
        // The cache merge broke the backend's ascending key order —
        // `Snapshot` requires strictly sorted entries (verified by
        // `snapshot_import` and `parse_snapshot_entries`).
        snap.entries.sort_unstable_by_key(|e| e.0);
        Some(snap)
    }

    /// Verify a staged snapshot without mutating: strictly parse
    /// every entry by namespace, rebuild the account set in a
    /// scratch map, and recompute the Ethereum MPT root the same way
    /// `state_root`'s full-build path does. The returned root is
    /// checked against the snapshot's claimed module root — bytes
    /// that don't reproduce it never reach the backend (audit 3.2).
    ///
    /// The `0x02`/`0x03`/`0x04` namespaces (sealed blocks, undo
    /// blobs, schema meta) are RPC-window data — not committed to
    /// the account trie — but they are still schema-validated so a
    /// malformed record can't be installed silently.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let accounts = Self::parse_snapshot_entries(snapshot)?;
        // Rebuild the state trie from the staged accounts — the
        // same keying (keccak256(addr)) and leaf RLP as the live
        // `state_root` full-build path.
        let iter = accounts.iter().map(|(addr, acct)| {
            let storage_root = if acct.storage.is_empty() {
                trie::EMPTY_ROOT
            } else {
                trie::storage_root(acct.storage.iter().filter(|(_, value)| !value.is_zero()).map(
                    |(slot, value)| {
                        (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                    },
                ))
            };
            (
                alloy_primitives_address(addr.0),
                trie::build_trie_account(acct.nonce, acct.balance, storage_root, acct.code_hash),
            )
        });
        Ok(Hash(trie::state_root(iter).0))
    }

    /// Import a key-value snapshot, restoring the EVM's state.
    ///
    /// The snapshot is strictly re-validated before the backend is
    /// touched — `import_state` must never trust a prior inspection
    /// to have happened.
    ///
    /// Flushes the current in-memory state to the backend first, then
    /// replaces the backend's state with the snapshot, then reloads
    /// the in-memory cache from the backend.
    ///
    /// Returns `Ok(())` on success, or an error if the backend is
    /// not attached or the import fails.
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        // Strict structural validation before any mutation — the
        // executor's verify-then-mutate contract depends on
        // `inspect_state`, but `import_state` must not blindly trust
        // it ran (same pattern as the blob modules' re-staging).
        Self::parse_snapshot_entries(snapshot)?;
        // Flush the current state to the backend first (so we don't
        // lose any pending changes — though in practice, import
        // happens before consensus starts, so there are no pending
        // changes).
        {
            let mut backend = framework::lock_state(&self.backend);
            if let Some(ref mut b) = *backend {
                self.flush_to_storage(b.as_mut())
                    .map_err(|_| storage::SnapshotError::BackendError)?;
                b.snapshot_import(snapshot.clone())?;
            } else {
                return Err(storage::SnapshotError::BackendError);
            }
        }
        // Reload the in-memory views from the backend — onto EMPTY
        // views, not merges. `load_from_storage` inserts
        // account-by-account and record-by-record, so any entry
        // present in memory but absent from the snapshot would
        // survive the import: a restart whose redb backend had
        // flushed ahead of the checkpoint (crash between an EVM
        // flush and the snapshot write) would keep stale balances
        // and stale history, then double-apply on replay. The
        // backend was wholesale replaced above, so every in-memory
        // view of it must be wholesale replaced too.
        {
            let mut db_guard = framework::lock_state(&self.db);
            *db_guard = Arc::new(CacheDB::new(EmptyDB::new()));
        }
        framework::lock_state(&self.history).clear();
        *framework::lock_state(&self.versioned) = versioned::VersionedState::default();
        *framework::lock_state(&self.block_undo) = versioned::BlockUndo::default();
        framework::lock_state(&self.storage_root_cache).clear();
        // The EIP-1559 accumulator is in-memory state the snapshot
        // does not carry — reset it to the constructor seed, then
        // `load_from_storage` rehydrates it from the newest restored
        // sealed block exactly as a cold start would. Without this,
        // a backend that had flushed ahead of the checkpoint leaves
        // the tip's fee curve installed: replayed blocks would seal
        // with a different `baseFee`, corrupting every block hash.
        *framework::lock_state(&self.fee_state) =
            fee::BaseFeeState::new(self.initial_base_fee, CHAIN_BLOCK_GAS_LIMIT);
        *framework::lock_state(&self.block_height) = 0;
        *framework::lock_state(&self.block_timestamp) = 0;
        *framework::lock_state(&self.coinbase) = revm::primitives::Address::ZERO;
        self.block_gas_limit.store(CHAIN_BLOCK_GAS_LIMIT, std::sync::atomic::Ordering::Relaxed);
        // Flush ops queued for the pre-reset backend describe state
        // the snapshot replaced wholesale — replaying them onto the
        // fresh backend would resurrect stale records.
        framework::lock_state(&self.pending_flush).clear();
        let mut backend = framework::lock_state(&self.backend);
        if let Some(ref mut b) = *backend {
            self.load_from_storage(b.as_mut());
        }
        // The account set was wholesale replaced — the incremental
        // leaf map, retained branches, root cache, and any pending
        // `touched` marks all describe pre-import state. Reset them:
        // the next `state_root` rebuilds from scratch and the next
        // `end_block` flush must not re-emit ops for accounts the
        // snapshot already installed.
        *framework::lock_state(&self.trie_leaves_ready) = false;
        framework::lock_state(&self.trie_leaves).clear();
        framework::lock_state(&self.retained_branches).clear();
        *framework::lock_state(&self.cached_state_root) = None;
        framework::lock_state(&self.touched).clear();
        Ok(())
    }
}
