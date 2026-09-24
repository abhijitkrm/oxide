//! Fast-path execution for native transfers and empty-code
//! calls.
//!
//! Split from `lib.rs` around the shortcut invariant: a
//! native-token transfer or a call to an account with no code
//! takes a checked-arithmetic shortcut that skips full revm
//! interpretation — `execute_signed` tries the shortcut first and
//! falls through to the interpreter only when it can't apply.
//! Every shortcut must produce *identical* state to the slow
//! path; keeping them together makes the equivalence auditable.

use super::{
    Address, Arc, CacheDB, CoinbaseObs, DatabaseRef, EvmModule, ExecError, ExecuteCommitEvm,
    ExecutionResult, InspectEvm, Output, ResultGas, SpecId, SpecTx, SuccessReason, TX_GAS_TRANSFER,
    TxEnv, TxKind, alloy_primitives_address, trace, tx, versioned,
};

impl EvmModule {
    /// Execute a signed EVM transaction. The `msg` is a raw RLP-encoded
    /// signed transaction (Legacy, EIP-2930, or EIP-1559 per EIP-2718).
    ///
    /// The sender is recovered from the signature inside the transaction —
    /// **never** trusted from the outer envelope (`ctx.sender`). This is
    /// the core security boundary: authentication is enforced at
    /// execution, not admission.
    ///
    /// Returns the revm `ExecutionResult` containing gas used, status,
    /// logs, output, and (for CREATE) the created address.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message cannot be parsed
    /// as a valid signed transaction (RLP decode failure, invalid
    /// signature, wrong chain ID).
    /// Returns [`ExecError::ModuleRejected`] if the EVM execution fails.
    /// Execute a already-decoded signed transaction (Perf: single
    /// RLP decode). Used by `handle()` to avoid decoding the same
    /// RLP twice — `handle()` decodes once to get the tx type for
    /// the receipt, then calls this method.
    ///
    /// Returns the execution result and the recovered sender — the
    /// caller needs both to record the transaction into the
    /// executed-block history.
    pub(crate) fn execute_signed(
        &self,
        signed: &tx::SignedTx,
    ) -> Result<
        (
            revm::context::result::ExecutionResult,
            revm::primitives::Address,
            Option<trace::CallFrame>,
        ),
        ExecError,
    > {
        // Enforce chain ID (EIP-155 replay protection).
        if signed.chain_id() != self.chain_id {
            return Err(ExecError::Malformed);
        }

        // Recover the sender from the signature. This is the
        // authentication step — the EVM never trusts `ctx.sender`.
        let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
        let caller = alloy_primitives_address(sender.0);

        // Build the transaction environment from the signed tx fields.
        let tx = Self::build_tx_env(signed, caller, self.spec)?;

        // Build and run the EVM. `transact_commit` executes the tx and
        // commits the state changes to the CacheDB in one step.
        //
        // A5/A6: wire the block environment (base fee, coinbase, block
        // number, timestamp, gas limit) into revm. revm's internal gas
        // accounting then:
        //   1. Charges `gas_used * gas_price` from the sender.
        //   2. Burns `gas_used * base_fee` (removes from supply).
        //   3. Tips `gas_used * (gas_price - base_fee)` to the coinbase.
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);
        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);
        let mut evm = self.build_evm(db, coinbase, block_number, block_timestamp);

        // `transact` (not `transact_commit`) so we get the complete
        // `EvmState` — the exact set of accounts the tx modified.
        // The previous top-level-only tracking (caller + to +
        // created + coinbase) missed accounts changed by internal
        // calls, SELFDESTRUCT beneficiaries, and SSTORE writes to
        // third accounts — those accounts were updated in the
        // CacheDB but never flushed or reflected in the incremental
        // state root, diverging durable state from in-memory state.
        // `inspect_tx` is `transact` plus inspector hooks — the
        // native journal inspector replays precompile side-effect
        // undos when a frame reverts. Result/state semantics are
        // identical.
        let result_and_state = evm
            .inspect_tx(tx)
            .map_err(|e| ExecError::ModuleRejected(format!("evm transact failed: {e:?}")))?;
        evm.precompiles.clear_native_journal();
        // Drain the call-tree recorder before the Evm is dropped —
        // the trace lands in `history` beside this tx's receipt for
        // `debug_trace*` lookups.
        let call_trace = evm.inspector.1.take_root();

        // Phase D: track touched accounts for incremental flush.
        // `state` contains EVERY account revm modified (including
        // internal-call targets and selfdestruct beneficiaries);
        // `commit` then applies it to the CacheDB — identical
        // semantics to `transact_commit` but with the state
        // available for tracking first.
        {
            let mut touched = framework::lock_state(&self.touched);
            touched.extend(result_and_state.state.keys().copied());
        }
        // Capture every account the commit is about to overwrite —
        // the undo entry must hold the pre-block value, so it reads
        // the map before `commit` lands.
        {
            let mut undo = framework::lock_state(&self.block_undo);
            for addr in result_and_state.state.keys() {
                undo.capture(*addr, evm.ctx.journaled_state.database.cache.accounts.get(addr));
            }
        }
        // Collect zero-slot writers before `commit` consumes the
        // diff — afterwards `prune_zero_slots` sweeps the zeros the
        // commit installed so the committed map obeys "zero means
        // absent" (see `commit_state` in lib.rs).
        let zeroed = Self::zero_slot_writers(&result_and_state.state);
        evm.commit(result_and_state.state);
        Self::prune_zero_slots(evm.ctx.journaled_state.database, &zeroed);

        Ok((result_and_state.result, caller, call_trace))
    }

    /// Capture the fast-path write set into the block's undo
    /// accumulator.
    ///
    /// `try_native_transfer`/`try_empty_code_call` mutate exactly
    /// {caller, recipient, coinbase} — the same accounts the call
    /// sites already record as touched. Called *before* the fast-path
    /// attempt so the undo entry holds the pre-block value; if the
    /// fast path declines and revm runs instead, the entries remain
    /// correct (first-write-wins).
    pub(crate) fn undo_capture_fast_path<DB: DatabaseRef>(
        undo: &mut versioned::BlockUndo,
        db: &CacheDB<DB>,
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        coinbase: revm::primitives::Address,
    ) {
        undo.capture(caller, db.cache.accounts.get(&caller));
        if let tx::TxKind::Call(addr) = signed.to() {
            undo.capture(
                revm::primitives::Address::from(addr.0),
                db.cache.accounts.get(&revm::primitives::Address::from(addr.0)),
            );
        }
        undo.capture(coinbase, db.cache.accounts.get(&coinbase));
    }

    /// Try to execute a simple ETH transfer natively, bypassing revm.
    ///
    /// This is the **native fast path**: for simple value transfers
    /// (empty calldata, recipient is an EOA, no access list), the full
    /// EVM is unnecessary. A native balance+nonce update is ~10-50x
    /// faster than revm's stack-machine execution.
    ///
    /// # When the native path applies
    ///
    /// All of the following must be true:
    /// 1. `to` is `TxKind::Call` (not `Create`).
    /// 2. `data` is empty (no calldata).
    /// 3. Access list is empty (EIP-2930/1559).
    /// 4. Recipient has no code (`code_hash == KECCAK_EMPTY` or
    ///    account doesn't exist).
    /// 5. `gas_limit >= 21000` (intrinsic gas for a simple transfer).
    /// 6. Sender nonce matches the tx nonce.
    /// 7. Sender has sufficient balance for `value + gas_limit *
    ///    effective_gas_price`.
    /// 8. `effective_gas_price >= base_fee`.
    /// 9. `value`, `gas_price` fit in `u128` (Ethereum amounts always
    ///    do, but we check for safety).
    ///
    /// If any check fails, returns `None` and the caller falls through
    /// to revm, which handles the error identically.
    ///
    /// # Gas semantics
    ///
    /// For a simple transfer: `gas_used = 21000` (intrinsic gas, no
    /// execution). The effective gas price is computed per EIP-1559:
    /// - Legacy/EIP-2930: `effective = gas_price`
    /// - EIP-1559: `effective = min(max_fee, base_fee + priority_fee)`
    ///
    /// The coinbase receives `gas_used * (effective - base_fee)` (the
    /// tip). The base fee portion (`gas_used * base_fee`) is burned
    /// (removed from supply).
    ///
    /// # State changes (identical to revm)
    ///
    /// - `sender.balance -= value + gas_used * effective_gas_price`
    /// - `sender.nonce += 1`
    /// - `recipient.balance += value`
    /// - `coinbase.balance += gas_used * (effective_gas_price - base_fee)`
    ///
    /// # Arguments
    ///
    /// - `signed`: the signed transaction.
    /// - `caller`: the recovered sender address.
    /// - `db`: the cache database (reads via `DatabaseRef`, writes
    ///   via direct `cache.accounts` mutation).
    /// - `coinbase`: the block's coinbase address (tip recipient).
    /// - `base_fee`: the block's base fee (wei per gas unit).
    ///
    /// # Returns
    ///
    /// `Some(ExecutionResult)` if the native path was taken.
    /// `None` if the tx doesn't qualify (caller should use revm).
    ///
    /// # Panics
    ///
    /// Panics if the database mutex is poisoned (internal to
    /// `load_account`).
    /// Whether `recipient` is executed as a precompile rather than as an
    /// ordinary account.
    ///
    /// Precompiles have no account code, so the fast paths' "no code ⇒
    /// plain transfer" rule would otherwise treat them as EOAs and skip
    /// their execution entirely — returning empty output and charging
    /// calldata gas instead of the precompile's own gas and result. That
    /// is a consensus-visible divergence: `sha256` (0x02) called with
    /// empty input must return the 32-byte digest of empty input, and a
    /// call to `identity` must echo its calldata, whereas the shortcut
    /// would report success with no output at all.
    ///
    /// Both sets are checked: Ethereum's (fork-dependent, taken from
    /// revm so a future EIP precompile is covered automatically) and
    /// Oxide's native precompiles, which live in their own address space
    /// (`0x0000…OOXX`) and are unknown to revm.
    pub(crate) fn recipient_is_precompile(
        recipient: &revm::primitives::Address,
        spec: SpecId,
    ) -> bool {
        use revm::precompile::{PrecompileSpecId, Precompiles};
        if Precompiles::new(PrecompileSpecId::from(spec)).contains(recipient) {
            return true;
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(recipient.as_slice());
        crate::precompiles::is_precompile(&Address(bytes))
    }

    pub(crate) fn try_native_transfer<DB: DatabaseRef>(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        db: &mut CacheDB<DB>,
        coinbase: revm::primitives::Address,
        base_fee: u64,
        spec: SpecId,
    ) -> Option<ExecutionResult> {
        // ── Qualification checks ──────────────────────────────

        // 1. Must be a Call (not Create).
        let recipient = match signed.to() {
            tx::TxKind::Create => return None,
            tx::TxKind::Call(addr) => addr,
        };

        // 2. A precompile executes even though it has no account code,
        //    so it must never take the plain-transfer shortcut.
        if Self::recipient_is_precompile(&recipient, spec) {
            return None;
        }

        // 2. Empty calldata.
        if !signed.data().is_empty() {
            return None;
        }

        // 3. Empty access list and no EIP-7702 authorizations. A
        //    type-4 tx carries delegation tuples that must execute —
        //    a fast path that skips revm would silently drop them.
        if !signed.access_list().is_empty() || !signed.authorization_list().is_empty() {
            return None;
        }

        // 4. Recipient has no code (is an EOA).
        //    Check the cache directly — avoids the `AccountInfo`
        //    clone from `basic_ref`. If the account is not in the
        //    cache, it doesn't exist yet (no code, is an EOA).
        //    `B256::ZERO` is a sentinel used by test setup; treat
        //    it the same as `KECCAK_EMPTY` (no code).
        let recipient_has_code = match db.cache.accounts.get(&recipient) {
            Some(account) => {
                account.info.code_hash != revm::primitives::KECCAK_EMPTY
                    && account.info.code_hash != revm::primitives::B256::ZERO
            }
            None => false, // Account doesn't exist — no code.
        };
        if recipient_has_code {
            return None; // Recipient is a contract — needs EVM.
        }

        // 5. Gas limit >= intrinsic gas (21000 for a simple transfer).
        let gas_limit = signed.gas_limit();
        if gas_limit < TX_GAS_TRANSFER {
            return None; // Let revm handle the error.
        }

        // 9. Value and gas price must fit in u128.
        let value_u128: u128 = match signed.value().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let max_fee: u128 = match signed.max_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let priority_fee: u128 = match signed.max_priority_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };

        // Compute effective gas price per EIP-1559. The fee cap
        // fields are user-controlled u128s — a wrapped `base_fee +
        // priority_fee` would slide under the base-fee check below
        // and let a tx specify ~2^128 gas prices while paying a
        // wrapped reserve. revm computes reserves in U256 and
        // rejects; overflow defers to it.
        let fee_cap = u128::from(base_fee).checked_add(priority_fee)?;
        let effective_gas_price = std::cmp::min(max_fee, fee_cap);

        // 8. Effective gas price >= base fee.
        if effective_gas_price < u128::from(base_fee) {
            return None; // Let revm handle the error.
        }

        // Tip owed to the coinbase — computed before any account is
        // mutated. `None` below defers to revm, which re-executes on
        // the same `db`: a fallible step must not fire after the
        // sender/recipient writes or the fallback would double-apply.
        let tip = effective_gas_price.saturating_sub(u128::from(base_fee));
        let coinbase_tip = u128::from(TX_GAS_TRANSFER).checked_mul(tip)?;

        // ── Read + validate sender ─────────────────────────────
        //
        // We load the sender account, check nonce and balance, then
        // modify in place. The `load_account` call returns a `&mut
        // DbAccount` that borrows `db`; we scope it so the borrow is
        // released before we load other accounts.
        {
            let sender_account = db.load_account(caller).ok()?;

            // 6. Nonce must match.
            if sender_account.info.nonce != signed.nonce() {
                return None;
            }

            // 7. Sufficient balance for value + gas reserve.
            //    The EVM deducts `gas_limit * effective_gas_price`
            //    upfront as a gas reserve, then refunds the unused
            //    portion. The sender must have enough for both the
            //    reserve and the value transfer. Checked math: a
            //    wrapped reserve would pass the balance check with a
            //    near-zero requirement where revm's U256 math rejects
            //    the tx — divergent execution, so defer instead.
            let gas_reserve = u128::from(gas_limit).checked_mul(effective_gas_price)?;
            let total_needed = value_u128.checked_add(gas_reserve)?;
            if sender_account.info.balance < revm::primitives::U256::from(total_needed) {
                return None;
            }

            // ── All checks passed — execute natively ───────────
            //
            // Net gas cost = gas_used * effective_gas_price
            // (gas_limit - gas_used is refunded).
            let gas_cost = u128::from(TX_GAS_TRANSFER).checked_mul(effective_gas_price)?;
            let charge = value_u128.checked_add(gas_cost)?;
            sender_account.info.balance -= revm::primitives::U256::from(charge);
            sender_account.info.nonce += 1;
            // Normalize code_hash: revm sets KECCAK_EMPTY for EOAs
            // during execution. Test setup (fund_account_for_test)
            // may use B256::ZERO as a sentinel; revm fixes it, so we
            // must too to produce identical state roots.
            if sender_account.info.code_hash == revm::primitives::B256::ZERO {
                sender_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            sender_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Update recipient ───────────────────────────────────
        {
            let recipient_account = db.load_account(recipient).ok()?;
            recipient_account.info.balance += signed.value();
            if recipient_account.info.code_hash == revm::primitives::B256::ZERO {
                recipient_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            recipient_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Update coinbase (tip only, base fee is burned) ─────
        if coinbase_tip > 0 {
            let coinbase_account = db.load_account(coinbase).ok()?;
            coinbase_account.info.balance += revm::primitives::U256::from(coinbase_tip);
            if coinbase_account.info.code_hash == revm::primitives::B256::ZERO {
                coinbase_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            coinbase_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Build ExecutionResult ──────────────────────────────
        //
        // Identical to what revm produces for a successful simple
        // transfer: Success with gas_used=21000, no logs, no output.
        // EIP-7623 floor gas for empty calldata = 21000 + 0 = 21000,
        // same as standard gas. Setting floor_gas correctly prevents
        // free-gas stuffing: a tx with empty calldata pays at least
        // 21000 gas (the floor), not less.
        let result = ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::default()
                .with_total_gas_spent(TX_GAS_TRANSFER)
                .with_refunded(0)
                .with_floor_gas(TX_GAS_TRANSFER),
            logs: Vec::new(),
            output: Output::Call(revm::primitives::Bytes::new()),
        };

        Some(result)
    }

    /// Native fast path for calls to contracts with **no runtime code**.
    ///
    /// When a transaction sends calldata to an address that has no
    /// deployed code (an EOA or a contract whose constructor didn't
    /// return runtime bytecode), revm still creates a full call frame,
    /// loads the empty code, and immediately returns. This costs
    /// ~60–80 µs per tx in revm overhead (frame setup, gas accounting,
    /// state journal). This fast path performs the same state changes
    /// (nonce bump, gas deduction, coinbase tip) in ~200 ns — a
    /// ~300× speedup for this tx class.
    ///
    /// # Qualification
    ///
    /// The tx must:
    /// 1. Be a `Call` (not `Create`).
    /// 2. Have **non-empty** calldata (empty calldata is handled by
    ///    `try_native_transfer`).
    /// 3. Have an empty access list.
    /// 4. Target a recipient with no code (`KECCAK_EMPTY` or `B256::ZERO`).
    /// 5. Have `gas_limit >= 21000 + calldata_gas`.
    /// 6. Have a matching nonce and sufficient balance.
    ///
    /// # Gas model
    ///
    /// `gas_used = max(21000 + calldata_gas, 21000 + calldata_tokens × 10)`
    /// 4 per zero byte and 16 per non-zero byte (EIP-2028). This
    /// matches revm's intrinsic gas calculation for a transaction
    /// that executes no opcodes. The cold-access surcharge
    /// (EIP-2929, 2600 gas) is **not** charged because the
    /// `try_native_transfer` fast path (which produces matching
    /// state roots) also doesn't charge it — revm's 21000 base
    /// includes the recipient access cost for top-level transactions.
    ///
    /// Budget: ~200 ns per tx (vs ~60–80 µs through revm).
    pub(crate) fn try_empty_code_call<DB: DatabaseRef>(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        db: &mut CacheDB<DB>,
        coinbase: revm::primitives::Address,
        base_fee: u64,
        spec: SpecId,
    ) -> Option<ExecutionResult> {
        // 1. Must be a Call (not Create).
        let recipient = match signed.to() {
            tx::TxKind::Create => return None,
            tx::TxKind::Call(addr) => addr,
        };

        // 1b. A precompile has no account code but is not an EOA — its
        //     execution is the whole point of the call, so it must fall
        //     through to revm rather than being answered as an empty
        //     call with no output.
        if Self::recipient_is_precompile(&recipient, spec) {
            return None;
        }

        // 2. Must have non-empty calldata (empty → try_native_transfer).
        let data = signed.data();
        if data.is_empty() {
            return None;
        }

        // 3. Empty access list and no EIP-7702 authorizations (see
        //    `try_native_transfer` — a fast path would drop the
        //    delegation tuples).
        if !signed.access_list().is_empty() || !signed.authorization_list().is_empty() {
            return None;
        }

        // 4. Recipient has no code. Unlike `try_native_transfer`,
        //    we **must** load the account from the database (not just
        //    check the local cache) because the recipient might have
        //    code in the parent DB that hasn't been loaded into the
        //    local cache yet. For simple transfers this doesn't matter
        //    (code is irrelevant for balance updates), but for calls
        //    with calldata, skipping execution against real code would
        //    produce wrong state roots.
        //
        //    `load_account` checks the local cache first, then falls
        //    through to the parent on miss. It also caches the account
        //    for later use (the recipient touch below). The borrow is
        //    scoped so we can access `db` again for the sender.
        let recipient_has_code = {
            let recipient_account = db.load_account(recipient).ok()?;
            recipient_account.info.code_hash != revm::primitives::KECCAK_EMPTY
                && recipient_account.info.code_hash != revm::primitives::B256::ZERO
        };
        if recipient_has_code {
            return None;
        }

        // 5. Gas limit >= intrinsic gas.
        //    EIP-2028: 4 gas per zero byte, 16 per non-zero byte.
        //    EIP-7623 (Prague): floor gas = 21000 + calldata_tokens × 10,
        //    where calldata_tokens = zero_bytes×1 + non_zero_bytes×4.
        //    The actual gas used is max(standard_gas, floor_gas).
        //    For empty calldata, floor_gas == standard_gas == 21000,
        //    so `try_native_transfer` is unaffected. For non-empty
        //    calldata, floor_gas is usually higher.
        let zero_bytes = data.iter().fold(0u64, |acc, &b| acc + u64::from(b == 0));
        let non_zero_bytes = data.len() as u64 - zero_bytes;
        let calldata_gas = zero_bytes * 4 + non_zero_bytes * 16;
        let calldata_tokens = zero_bytes + non_zero_bytes * 4;
        let floor_gas = TX_GAS_TRANSFER + calldata_tokens * 10;
        let standard_gas = TX_GAS_TRANSFER + calldata_gas;
        let gas_used = std::cmp::max(standard_gas, floor_gas);
        let gas_limit = signed.gas_limit();
        if gas_limit < gas_used {
            return None;
        }

        // 6. Value and gas price must fit in u128.
        let value_u128: u128 = match signed.value().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let max_fee: u128 = match signed.max_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let priority_fee: u128 = match signed.max_priority_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };

        // 7. Effective gas price >= base fee (EIP-1559). The fee-cap
        // fields are user-controlled u128s — checked math defers to
        // revm's U256 semantics rather than wrapping the reserve.
        let fee_cap = u128::from(base_fee).checked_add(priority_fee)?;
        let effective_gas_price = std::cmp::min(max_fee, fee_cap);
        if effective_gas_price < u128::from(base_fee) {
            return None;
        }

        // Coinbase tip — computed before any account is mutated so
        // an overflow defers to revm instead of leaving writes
        // half-applied for the fallback to re-execute.
        let tip = effective_gas_price.saturating_sub(u128::from(base_fee));
        let coinbase_tip = u128::from(gas_used).checked_mul(tip)?;

        // ── All checks passed — execute natively ───────────────
        //
        // Same state changes as `try_native_transfer` but with
        // `gas_used = 21000 + calldata_gas` instead of 21000.

        // 8. Nonce must match + sufficient balance.
        {
            let sender_account = db.load_account(caller).ok()?;
            if sender_account.info.nonce != signed.nonce() {
                return None;
            }
            let gas_reserve = u128::from(gas_limit).checked_mul(effective_gas_price)?;
            let total_needed = value_u128.checked_add(gas_reserve)?;
            if sender_account.info.balance < revm::primitives::U256::from(total_needed) {
                return None;
            }

            // Deduct gas cost + value, increment nonce.
            let gas_cost = u128::from(gas_used).checked_mul(effective_gas_price)?;
            let charge = value_u128.checked_add(gas_cost)?;
            sender_account.info.balance -= revm::primitives::U256::from(charge);
            sender_account.info.nonce += 1;
            if sender_account.info.code_hash == revm::primitives::B256::ZERO {
                sender_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            sender_account.account_state = revm::database::AccountState::Touched;
        }

        // Update recipient. revm touches the callee account for all
        // calls (even zero-value, even to empty-code accounts) because
        // the CALL frame loads the account. We must match this.
        {
            let recipient_account = db.load_account(recipient).ok()?;
            if value_u128 > 0 {
                recipient_account.info.balance += signed.value();
            }
            if recipient_account.info.code_hash == revm::primitives::B256::ZERO {
                recipient_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            recipient_account.account_state = revm::database::AccountState::Touched;
        }

        // Update coinbase (tip only, base fee is burned).
        if coinbase_tip > 0 {
            let coinbase_account = db.load_account(coinbase).ok()?;
            coinbase_account.info.balance += revm::primitives::U256::from(coinbase_tip);
            if coinbase_account.info.code_hash == revm::primitives::B256::ZERO {
                coinbase_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            coinbase_account.account_state = revm::database::AccountState::Touched;
        }

        // Build ExecutionResult — identical to what revm produces for
        // a successful call to empty code: Success with no logs, no
        // output, gas_used = max(21000 + calldata_gas, floor_gas).
        // EIP-7623 floor gas prevents free-gas stuffing: a tx with
        // cheap calldata still pays at least the floor gas.
        let result = ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::default()
                .with_total_gas_spent(gas_used)
                .with_refunded(0)
                .with_floor_gas(floor_gas),
            logs: Vec::new(),
            output: Output::Call(revm::primitives::Bytes::new()),
        };

        Some(result)
    }

    /// Synthesize the geth-callTracer-equivalent root frame for a
    /// transaction that executed on a native fast path (no revm
    /// frame machinery ran, so the `CallRecorder` saw nothing).
    ///
    /// The fast paths only ever produce `Success` — every check that
    /// could fail falls through to revm — so `error` is always
    /// `None` and `output` is empty. `gas`/`gasUsed` use the tx-level
    /// values (the frame gas equals the tx gas for a single-frame
    /// call, and geth's callTracer reports the same).
    pub(crate) fn fast_path_frame(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        result: &ExecutionResult,
    ) -> trace::CallFrame {
        let to = match signed.to() {
            tx::TxKind::Call(addr) => Some(revm::primitives::Address::from(addr.0)),
            tx::TxKind::Create => None,
        };
        trace::CallFrame {
            kind: "CALL",
            from: caller,
            to,
            value: signed.value(),
            gas_limit: signed.gas_limit(),
            gas_used: result.tx_gas_used(),
            input: signed.data().clone(),
            output: revm::primitives::Bytes::new(),
            error: None,
            revert_reason: None,
            calls: Vec::new(),
        }
    }

    /// Build the [`SpecTx`] record for a transaction that ran on a
    /// native fast path (`try_native_transfer` or
    /// `try_empty_code_call`).
    ///
    /// The fast paths touch exactly three accounts — caller (nonce +
    /// balance), recipient (balance), and the coinbase (tip). The
    /// coinbase is tracked through `coinbase_delta` instead of the
    /// write set because every transaction writes it and the change
    /// is strictly additive. When the caller *is* the coinbase the
    /// nonce bump lands on the fee-recipient account — a
    /// non-additive change the delta cannot represent — so the tx is
    /// flagged `coinbase_nontrivial` and re-executes canonically.
    ///
    /// `coinbase_before` is the coinbase balance the group cache
    /// showed just before this tx ran — what any `BALANCE(coinbase)`
    /// would have observed (fast paths never execute opcodes, so
    /// `coinbase.read` only matters for the caller == coinbase case,
    /// which is already `must_reexec`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spec_fast_path<DB: DatabaseRef>(
        db: &CacheDB<DB>,
        idx: usize,
        caller: revm::primitives::Address,
        signed: &tx::SignedTx,
        coinbase: revm::primitives::Address,
        coinbase_before: revm::primitives::U256,
        result: ExecutionResult,
    ) -> SpecTx {
        let recipient = match signed.to() {
            tx::TxKind::Call(addr) => revm::primitives::Address::from(addr.0),
            // Both fast paths reject Create before reaching here.
            tx::TxKind::Create => revm::primitives::Address::ZERO,
        };
        let caller_is_coinbase = caller == coinbase;

        let mut reads: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::with_capacity(2);
        reads.insert(caller);
        reads.insert(recipient);

        // Fast paths only ever modify `info` (balance, nonce) — never
        // storage — so every write registers at info level and the
        // slot sets stay empty.
        let mut info_writes: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::with_capacity(2);
        // The merge payload: `EvmState` entries equivalent to what the
        // interpreter would record. The slot-wise `commit` merge
        // preserves every slot the account holds but this tx never
        // loaded. (`commit` extends storage; it never truncates it for
        // a merely-Touched account.)
        let mut state = revm::state::EvmState::default();
        for addr in [caller, recipient] {
            if addr == coinbase || !info_writes.insert(addr) {
                continue;
            }
            if let Some(dba) = db.cache.accounts.get(&addr) {
                let mut account = revm::state::Account::default();
                account.info = dba.info.clone();
                account.mark_touch();
                state.insert(addr, account);
            }
        }

        let coinbase_after =
            db.cache.accounts.get(&coinbase).map_or(coinbase_before, |a| a.info.balance);
        let frame = Self::fast_path_frame(signed, caller, &result);
        SpecTx {
            idx,
            sender: caller,
            result: Ok((result, Some(frame))),
            reads,
            slot_reads: std::collections::HashSet::new(),
            info_writes,
            slot_writes: std::collections::HashSet::new(),
            destructive: std::collections::HashSet::new(),
            state,
            coinbase_before,
            coinbase_delta: coinbase_after - coinbase_before,
            coinbase: CoinbaseObs {
                // The caller's balance-sufficiency check reads the
                // coinbase balance when caller == coinbase.
                read: caller_is_coinbase,
                accessed: caller_is_coinbase || recipient == coinbase,
                nontrivial: caller_is_coinbase,
            },
            must_reexec: caller_is_coinbase,
        }
    }

    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the `TxEnv` cannot be
    /// constructed from the signed tx fields.
    pub(crate) fn build_tx_env(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        spec: SpecId,
    ) -> Result<TxEnv, ExecError> {
        // EIP-7702 gate: type-4 transactions are only valid from the
        // Prague hardfork onward (EIP-7702 shipped in Prague). On
        // Ethereum, submitting a type-4 tx pre-Prague is a validity
        // failure, not a decode failure — mirror that here so the
        // rejection is deterministic at every entry point that
        // builds a TxEnv.
        if signed.tx_type() == 4 && !spec.is_enabled_in(SpecId::PRAGUE) {
            return Err(ExecError::Malformed);
        }
        let to = match signed.to() {
            tx::TxKind::Create => TxKind::Create,
            tx::TxKind::Call(addr) => TxKind::Call(revm::primitives::Address::from(addr.0)),
        };
        // A5: wire gas pricing from the signed tx into the TxEnv.
        // - Legacy/EIP-2930: `gas_price` is the exact fee per gas.
        // - EIP-1559: `max_fee_per_gas` is the cap; `max_priority_fee_per_gas`
        //   is the tip. revm uses these with the block's base fee to
        //   compute the effective gas price.
        // Fuzz fix: U256::to::<u128>() panics if the value doesn't fit
        // in u128. Use try_into and reject oversized values.
        let gas_price =
            u128::try_from(signed.max_fee_per_gas()).map_err(|_| ExecError::Malformed)?;
        let priority_fee =
            u128::try_from(signed.max_priority_fee_per_gas()).map_err(|_| ExecError::Malformed)?;
        // EIP-2930/1559 access list — wire it through so revm warms
        // the listed (address, slot) pairs. Dropping it would charge
        // cold-access gas for warm slots and diverge state roots from
        // Ethereum semantics.
        let access_list: revm::context_interface::transaction::AccessList = signed
            .access_list()
            .iter()
            .map(|item| revm::context_interface::transaction::AccessListItem {
                address: item.address,
                storage_keys: item.storage_keys.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        // EIP-7702 authorization list — convert each decoded tuple to
        // revm's `SignedAuthorization`. revm recovers each authority,
        // applies the delegation designator, and charges the
        // PER_EMPTY_ACCOUNT_COST intrinsic gas per authorization.
        let authorization_list: Vec<
            revm::context_interface::either::Either<
                revm::context_interface::transaction::SignedAuthorization,
                revm::context_interface::transaction::RecoveredAuthorization,
            >,
        > = signed
            .authorization_list()
            .iter()
            .map(|auth| {
                revm::context_interface::either::Either::Left(
                    revm::context_interface::transaction::SignedAuthorization::new_unchecked(
                        revm::context_interface::transaction::Authorization {
                            chain_id: auth.chain_id,
                            address: auth.address,
                            nonce: auth.nonce,
                        },
                        auth.sig.recid.as_u8(),
                        auth.sig.r,
                        auth.sig.s,
                    ),
                )
            })
            .collect();
        let tx = TxEnv::builder()
            .gas_limit(signed.gas_limit())
            .caller(caller)
            .kind(to)
            .data(signed.data().clone())
            .nonce(signed.nonce())
            .value(signed.value())
            .gas_price(gas_price)
            .gas_priority_fee(Some(priority_fee))
            .access_list(access_list)
            .tx_type(Some(signed.tx_type()))
            .authorization_list(authorization_list)
            .build()
            .map_err(|_| ExecError::Malformed)?;
        Ok(tx)
    }
}
