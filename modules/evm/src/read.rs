//! Read and simulate surface for the EVM module.
//!
//! Split from `lib.rs` around the read-only invariant: every method
//! here runs against a scratch state view and *never* commits —
//! `call_read`, gas estimation, `simulate`, traced calls, and
//! access-list construction all answer "what would this do" without
//! touching `pending_flush` or the committed store. Separating the
//! read surface from the consensus path makes it auditable that no
//! RPC can mutate state.

use super::{
    Address, Arc, CacheDB, CallError, CallOutcome, CallRequest, EvmModule, ExecError, InspectEvm,
    RejectCategory, SharedCacheDB, TxEnv, TxKind, alloy_primitives_address, overrides, precompiles,
    trace, tx, versioned,
};

impl EvmModule {
    /// Get an account's balance from the EVM state.
    ///
    /// Returns 0 for accounts not in the state (EVM convention).
    /// The EVM uses `U256` for balances; we truncate to `u128` (the
    /// upper 128 bits are always zero for any realistic balance).
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned (a thread panicked while
    /// holding the lock). This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn balance(&self, addr: &Address) -> u128 {
        let db = framework::lock_state(&self.db);
        let evm_addr = alloy_primitives_address(addr.0);
        // `to::<u128>` panics on balances above u128::MAX — reachable
        // via crafted state (e.g. snapshot import). Saturate instead:
        // a balance that large cannot be spent anyway, and this is a
        // query accessor, not a consensus path.
        db.cache
            .accounts
            .get(&evm_addr)
            .map_or(0, |a| u128::try_from(a.info.balance).unwrap_or(u128::MAX))
    }

    /// Get an account's nonce from the EVM state.
    ///
    /// Returns 0 for accounts not in the state.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned (a thread panicked while
    /// holding the lock). This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn nonce(&self, addr: &Address) -> u64 {
        let db = framework::lock_state(&self.db);
        let evm_addr = alloy_primitives_address(addr.0);
        db.cache.accounts.get(&evm_addr).map_or(0, |a| a.info.nonce)
    }

    /// Get the deployed bytecode of an account (`eth_getCode`).
    ///
    /// Returns an empty vec for EOAs, missing accounts, and
    /// not-yet-loaded code entries. Code lives in two places in the
    /// `CacheDB`: inline on the account (`info.code`) for freshly
    /// deployed/loaded accounts, and in the `contracts` map keyed by
    /// `code_hash` for accounts loaded from durable storage.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    #[must_use]
    pub fn code(&self, addr: &Address) -> Vec<u8> {
        let db = framework::lock_state(&self.db);
        let evm_addr = alloy_primitives_address(addr.0);
        let Some(account) = db.cache.accounts.get(&evm_addr) else {
            return Vec::new();
        };
        if let Some(code) = &account.info.code {
            return code.original_bytes().to_vec();
        }
        db.cache
            .contracts
            .get(&account.info.code_hash)
            .map(|c| c.original_bytes().to_vec())
            .unwrap_or_default()
    }

    /// Read one 32-byte storage slot (`eth_getStorageAt`).
    ///
    /// Returns `U256::ZERO` for missing accounts and untouched slots
    /// (EVM sparse-storage convention).
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    #[must_use]
    pub fn storage_at(
        &self,
        addr: &Address,
        slot: &revm::primitives::U256,
    ) -> revm::primitives::U256 {
        let db = framework::lock_state(&self.db);
        let evm_addr = alloy_primitives_address(addr.0);
        db.cache
            .accounts
            .get(&evm_addr)
            .and_then(|a| a.storage.get(slot))
            .copied()
            .unwrap_or_default()
    }

    /// Execute a read-only contract call against the current state
    /// (`eth_call`).
    ///
    /// Runs the full revm pipeline — including native read-only
    /// precompiles — with the simulation `CfgEnv` (nonce/base-fee/
    /// block-gas-limit/priority-fee/EIP-3607 checks disabled; balance
    /// and fee checks kept, matching geth's `DoCall`). The returned
    /// `EvmState` is **not** committed, so state cannot change.
    ///
    /// `transact` does not write the `CacheDB` — writes only flow
    /// through `commit`, which this path never calls — so holding the
    /// DB lock for the call's duration is safe and side-effect-free.
    ///
    /// `req.gas` defaults to the block gas limit; a supplied value is
    /// capped at it (a tx that needs more than a block's worth can
    /// never execute anyway).
    ///
    /// # Errors
    ///
    /// - [`CallError::Revert`] — the call hit REVERT; `output` carries
    ///   the revert data (including ABI `Error(string)` payloads).
    /// - [`CallError::Halt`] — out-of-gas, stack overflow, etc.
    /// - [`CallError::Rejected`] — validation failed before execution
    ///   (e.g. insufficient funds for `gas*price + value`).
    pub fn call_read(&self, req: &CallRequest) -> Result<CallOutcome, CallError> {
        self.call_read_impl(req, None, &overrides::StateOverrides::new())
    }

    /// `eth_call` with geth's `stateOverride` argument — `at`
    /// selects the height (`None` = latest, `Some(h)` = historical
    /// overlay), `ovr` the per-account replacements.
    ///
    /// # Errors
    ///
    /// Same [`CallError`] variants as `call_read`, plus
    /// [`CallError::Rejected`] when `h` is outside the window.
    pub fn call_read_with_overrides(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<CallOutcome, CallError> {
        let at = match at {
            Some(h) => self.resolve_at(h).map_err(Self::state_as_call_err)?,
            None => None,
        };
        self.call_read_impl(req, at, ovr)
    }

    /// Shared body of `call_read`/`call_read_at` — `at` is the
    /// `simulate` height selector (`None` = latest).
    pub(crate) fn call_read_impl(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<CallOutcome, CallError> {
        let (rs, _trace, timed_out) = self.simulate(
            req,
            req.gas.unwrap_or(self.block_gas_limit()),
            self.sim_deadline(),
            at,
            ovr,
        )?;
        let gas_used = rs.result.tx_gas_used();
        let result = rs.result;
        if timed_out {
            return Err(CallError::Halt { reason: "execution timed out".to_string(), gas_used });
        }
        match result {
            revm::context::result::ExecutionResult::Success { output, .. } => {
                Ok(CallOutcome { output: output.into_data().to_vec(), gas_used })
            }
            revm::context::result::ExecutionResult::Revert { output, .. } => {
                Err(CallError::Revert { output: output.to_vec(), gas_used })
            }
            revm::context::result::ExecutionResult::Halt { reason, .. } => {
                Err(CallError::Halt { reason: format!("{reason:?}"), gas_used })
            }
        }
    }

    /// Estimate the minimum gas a call needs to succeed
    /// (`eth_estimateGas`).
    ///
    /// Named `estimate_call_gas` to avoid colliding with the `Module`
    /// trait's `estimate_gas(&self, msg)` block-budget hook.
    ///
    /// Bounded binary search over [`call_read`](Self::call_read):
    /// first try the ceiling (`req.gas` capped at the block gas
    /// limit); if it fails there, no gas limit can succeed — the
    /// error propagates verbatim (geth does the same: "gas required
    /// exceeds allowance or always failing transaction" surfaces the
    /// revert reason). Otherwise binary-search `[0, cap)` for the
    /// smallest succeeding limit — at most ~34 iterations for a 10 GG
    /// cap.
    ///
    /// # Errors
    ///
    /// Same [`CallError`] variants as `call_read`.
    pub fn estimate_call_gas(&self, req: &CallRequest) -> Result<u64, CallError> {
        self.estimate_call_gas_impl(req, None, &overrides::StateOverrides::new())
    }

    /// `eth_estimateGas` at height `h` — historical form; same
    /// binary-search semantics over the undo-log overlay.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window; otherwise the same variants as `estimate_call_gas`.
    pub fn estimate_call_gas_at(&self, req: &CallRequest, h: u64) -> Result<u64, CallError> {
        let at = self.resolve_at(h).map_err(Self::state_as_call_err)?;
        self.estimate_call_gas_impl(req, at, &overrides::StateOverrides::new())
    }

    /// `eth_estimateGas` with geth's `stateOverride` argument.
    ///
    /// # Errors
    ///
    /// Same variants as `estimate_call_gas`/`call_read_with_overrides`.
    pub fn estimate_call_gas_with_overrides(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<u64, CallError> {
        let at = match at {
            Some(h) => self.resolve_at(h).map_err(Self::state_as_call_err)?,
            None => None,
        };
        self.estimate_call_gas_impl(req, at, ovr)
    }

    /// Shared body — `at` selects the state view (`None` = latest).
    fn estimate_call_gas_impl(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<u64, CallError> {
        let cap = req.gas.unwrap_or(self.block_gas_limit()).min(self.block_gas_limit());
        // One deadline bounds the whole request: geth's evmtimeout
        // covers `eth_estimateGas` end-to-end, not each probe. Sharing
        // the instant across binary-search iterations means a
        // timed-out estimate fails instead of silently converging on
        // a wrong bound.
        let deadline = self.sim_deadline();
        // If it cannot succeed at the cap, it can never succeed —
        // surface the failure (revert data included) immediately.
        // `simulate` returns `Ok` for Revert/Halt too (they are valid
        // execution outcomes), so check the variant, not just Ok/Err.
        let (rs, _trace, timed_out) = self.simulate(req, cap, deadline, at, ovr)?;
        if timed_out {
            return Err(CallError::Halt {
                reason: "execution timed out".to_string(),
                gas_used: rs.result.tx_gas_used(),
            });
        }
        match rs.result {
            revm::context::result::ExecutionResult::Success { .. } => {}
            revm::context::result::ExecutionResult::Revert { output, gas, .. } => {
                return Err(CallError::Revert {
                    output: output.to_vec(),
                    gas_used: gas.tx_gas_used(),
                });
            }
            revm::context::result::ExecutionResult::Halt { reason, gas, .. } => {
                return Err(CallError::Halt {
                    reason: format!("{reason:?}"),
                    gas_used: gas.tx_gas_used(),
                });
            }
        }
        let mut lo = 0u64;
        let mut hi = cap;
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            match self.simulate(req, mid, deadline, at, ovr) {
                Ok((rs, _, timed_out)) => {
                    if timed_out {
                        return Err(CallError::Halt {
                            reason: "execution timed out".to_string(),
                            gas_used: rs.result.tx_gas_used(),
                        });
                    }
                    if matches!(rs.result, revm::context::result::ExecutionResult::Success { .. }) {
                        hi = mid;
                    } else {
                        lo = mid;
                    }
                }
                Err(_) => lo = mid,
            }
        }
        Ok(hi)
    }

    /// Run one simulated execution at `gas_limit`. Shared by
    /// `call_read`, `estimate_call_gas`, `call_read_traced`, and
    /// `create_access_list`. Returns the full `ResultAndState` (the
    /// touched `EvmState` is the accessed-account/slot set that
    /// `eth_createAccessList` answers from) plus the recorded call
    /// tree (only the trace consumer uses it — dropping it costs
    /// nothing) and whether the wall-clock deadline fired
    /// (`timed_out` — the caller maps it to a timeout error).
    ///
    /// `at_height` selects the state view: `None` runs against an
    /// `Arc` snapshot of the committed `CacheDB` behind a scratch
    /// cache (latest); `Some(h)` runs against a
    /// [`versioned::StateView`] at `h` — the undo-log overlay — with
    /// the block env taken from `h`'s sealed history record
    /// (timestamp/coinbase/base fee), matching geth, which evaluates
    /// `eth_call` under the target block's env.
    ///
    /// `ovr` carries geth's `stateOverride` table — applied through
    /// [`overrides::OverrideView`], a read-only `DatabaseRef`
    /// wrapper, so fake state can never leak into the authoritative
    /// cache. Every arm runs on a `SharedCacheDB`-nested scratch
    /// (same trick the parallel executor uses): the authoritative
    /// `CacheDB` is never borrowed mutably on a read path — revm
    /// caches read misses into whichever db it executes against, and
    /// letting those land in the committed map would let RPC traffic
    /// change the state root and stall commits behind `sim_timeout`.
    fn simulate(
        &self,
        req: &CallRequest,
        gas_limit: u64,
        deadline: std::time::Instant,
        at_height: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<(revm::context::result::ResultAndState, Option<trace::CallFrame>, bool), CallError>
    {
        let caller =
            req.from.map_or(revm::primitives::Address::ZERO, |a| alloy_primitives_address(a.0));
        let kind = match req.to {
            Some(addr) => TxKind::Call(alloy_primitives_address(addr.0)),
            None => TxKind::Create,
        };
        // Fee fields: a plain `gasPrice` maps to both caps (geth
        // treats it as max_fee for calls); explicit EIP-1559 fields
        // take precedence.
        let max_fee = req.max_fee_per_gas.or(req.gas_price).unwrap_or(0);
        let priority_fee = req.max_priority_fee_per_gas.or(req.gas_price).unwrap_or(0);
        let access_list: revm::context_interface::transaction::AccessList = req
            .access_list
            .iter()
            .map(|item| revm::context_interface::transaction::AccessListItem {
                address: item.address,
                storage_keys: item.storage_keys.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        let tx_env = TxEnv::builder()
            .caller(caller)
            .gas_limit(gas_limit)
            .kind(kind)
            .data(req.data.clone().into())
            .value(req.value)
            .gas_price(max_fee)
            .gas_priority_fee(Some(priority_fee))
            .nonce(req.nonce.unwrap_or(0))
            .access_list(access_list)
            .build()
            .map_err(|_| CallError::Rejected(ExecError::Malformed))?;

        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);

        match at_height {
            None => {
                // Latest-state reads run on a scratch `CacheDB`
                // layered over an `Arc` snapshot — never on the
                // authoritative map. revm caches every read miss
                // into the `CacheDB` it executes against:
                // `NotExisting` tombstones for missing accounts and
                // zero-valued entries for unset slots. Executing on
                // the committed `CacheDB` would therefore mutate
                // consensus state (the next `state_root` would
                // include entries a peer without this read traffic
                // lacks) and would hold the db mutex for the call's
                // whole duration — up to `sim_timeout` — stalling
                // every commit in the meantime. So: clone the `Arc`
                // under a short lock, drop the guard, then simulate
                // against the snapshot. The snapshot is stable while
                // shared — commit-path `Arc::make_mut` clones rather
                // than mutating when a snapshot is alive — and the
                // scratch cache absorbs every read-miss insert.
                // `StateOverrides` ride inside `OverrideView`, a
                // read-only `DatabaseRef` wrapper (a pure passthrough
                // when empty), so fake state can never reach the
                // authoritative cache either.
                let snap = {
                    let db_guard = framework::lock_state(&self.db);
                    Arc::clone(&db_guard)
                };
                let base = SharedCacheDB(snap);
                let mut cache = CacheDB::new(overrides::OverrideView::new(base, ovr));
                let mut evm = self.build_sim_evm(
                    &mut cache,
                    coinbase,
                    block_number,
                    block_timestamp,
                    deadline,
                );
                // No `commit`: simulation state dies with the
                // EvmState. The call trace rides out alongside the
                // result for `debug_traceCall` —
                // `call_read`/`estimate_call_gas` ignore it.
                let result = evm.inspect_tx(tx_env).map_err(|e| {
                    CallError::Rejected(ExecError::rejected(
                        RejectCategory::Other,
                        format!("{e:?}"),
                    ))
                });
                // Inspector is ((NativeJournalInspector,
                // CallRecorder), DeadlineInspector): trace at `.0.1`,
                // timeout flag at `.1`.
                let timed_out = evm.inspector.1.timed_out();
                let call_trace = evm.inspector.0.1.take_root();
                evm.precompiles.clear_native_journal();
                result.map(|rs| (rs, call_trace, timed_out))
            }
            Some(h) => {
                // Historical simulation: serve reads through the
                // undo-log overlay and take the block env from the
                // sealed record at `h` (the env a tx in that block
                // actually ran under).
                let env = {
                    let history = framework::lock_state(&self.history);
                    history.block(h).map(|b| (b.timestamp, b.coinbase, b.number))
                };
                let Some((ts, cb, num)) = env else {
                    return Err(CallError::Rejected(ExecError::rejected(
                        RejectCategory::NotFound,
                        format!("state for block {h} unavailable"),
                    )));
                };
                // Same short-lock discipline: clone the committed
                // `Arc` under the db lock and release it
                // immediately. The clone must precede the
                // `versioned` lock — the undo index only advances,
                // so locking it after the clone guarantees the
                // index covers at least the snapshot's height and
                // the (snapshot, index) pair stays consistent for
                // the view's lifetime. `versioned` itself stays
                // locked for the sim — it is held by `end_block`
                // only for a push, whereas `db` is needed by every
                // commit in a block.
                let snap = {
                    let db_guard = framework::lock_state(&self.db);
                    Arc::clone(&db_guard)
                };
                let versioned = framework::lock_state(&self.versioned);
                let view = versioned::StateView::new(&snap, &versioned, &self.history, h);
                let mut cache = CacheDB::new(overrides::OverrideView::new(view, ovr));
                let mut evm = self.build_sim_evm(&mut cache, cb, num, ts, deadline);
                let result = evm.inspect_tx(tx_env).map_err(|e| {
                    CallError::Rejected(ExecError::rejected(
                        RejectCategory::Other,
                        format!("{e:?}"),
                    ))
                });
                let timed_out = evm.inspector.1.timed_out();
                let call_trace = evm.inspector.0.1.take_root();
                evm.precompiles.clear_native_journal();
                result.map(|rs| (rs, call_trace, timed_out))
            }
        }
    }

    /// The wall-clock deadline applied to the next simulation —
    /// `Instant::now() + sim_timeout`.
    fn sim_deadline(&self) -> std::time::Instant {
        std::time::Instant::now() + self.sim_timeout
    }

    /// `debug_traceCall` — run a simulated call and return the
    /// recorded call tree (geth `callTracer` shape).
    ///
    /// Same semantics as [`call_read`](Self::call_read) — latest
    /// state, no commit — plus the root [`trace::CallFrame`].
    ///
    /// Unlike `call_read`, a reverted or halted call is **not** an
    /// error: geth's `debug_traceCall` returns the trace with the
    /// frame's `error` field set — the revert *is* the answer the
    /// caller asked for. Only pre-execution rejection (malformed
    /// env, unpayable) is an `Err`. The `u64` is the total gas used
    /// for the root-frame `gasUsed` patch.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when the call cannot be simulated at
    /// all.
    pub fn call_read_traced(
        &self,
        req: &CallRequest,
    ) -> Result<(u64, Option<trace::CallFrame>), CallError> {
        self.call_read_traced_impl(req, None, &overrides::StateOverrides::new())
    }

    /// `debug_traceCall` at height `h` — historical form.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window; otherwise the same variants as `call_read_traced`.
    pub fn call_read_traced_at(
        &self,
        req: &CallRequest,
        h: u64,
    ) -> Result<(u64, Option<trace::CallFrame>), CallError> {
        let at = self.resolve_at(h).map_err(Self::state_as_call_err)?;
        self.call_read_traced_impl(req, at, &overrides::StateOverrides::new())
    }

    /// `debug_traceCall` with geth's `stateOverride` argument.
    ///
    /// # Errors
    ///
    /// Same variants as `call_read_traced`.
    pub fn call_read_traced_with_overrides(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<(u64, Option<trace::CallFrame>), CallError> {
        let at = match at {
            Some(h) => self.resolve_at(h).map_err(Self::state_as_call_err)?,
            None => None,
        };
        self.call_read_traced_impl(req, at, ovr)
    }

    /// Shared body — `at` selects the state view (`None` = latest).
    fn call_read_traced_impl(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<(u64, Option<trace::CallFrame>), CallError> {
        let (rs, call_trace, timed_out) = self.simulate(
            req,
            req.gas.unwrap_or(self.block_gas_limit()),
            self.sim_deadline(),
            at,
            ovr,
        )?;
        if timed_out {
            return Err(CallError::Halt {
                reason: "execution timed out".to_string(),
                gas_used: rs.result.tx_gas_used(),
            });
        }
        Ok((rs.result.tx_gas_used(), call_trace))
    }

    /// `eth_createAccessList` — generate the EIP-2930 access list a
    /// call would touch, plus the gas it used.
    ///
    /// The touched set is the journal's final `EvmState`: every
    /// account loaded (read *or* written — journal loads land in
    /// `state` either way) and every slot `sload`/`sstore` touched.
    /// Matching geth's `accessListTracer`, the caller, the call
    /// target, and all protocol-warmed precompiles (Ethereum's
    /// active set plus the native `0x0B_*`–`0x0E_*` range) are
    /// excluded — they come warm for free, so listing them buys
    /// nothing. Entries the caller supplied in `req.access_list`
    /// are kept verbatim and merged with the generated ones (geth
    /// preserves the provided list as the base).
    ///
    /// `gas_used` is the simulated execution's gas — i.e. measured
    /// *with* the caller-provided access list applied (empty if none
    /// was supplied), matching geth, which does not re-run the call
    /// with the generated list.
    ///
    /// # Errors
    ///
    /// Same [`CallError`] variants as `call_read` — a reverting call
    /// is an error here (geth fails `eth_createAccessList` on
    /// revert rather than returning a list).
    pub fn create_access_list(
        &self,
        req: &CallRequest,
    ) -> Result<(tx::AccessList, u64), CallError> {
        self.create_access_list_impl(req, None, &overrides::StateOverrides::new())
    }

    /// `eth_createAccessList` at height `h` — historical form.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window; otherwise the same variants as `create_access_list`.
    pub fn create_access_list_at(
        &self,
        req: &CallRequest,
        h: u64,
    ) -> Result<(tx::AccessList, u64), CallError> {
        let at = self.resolve_at(h).map_err(Self::state_as_call_err)?;
        self.create_access_list_impl(req, at, &overrides::StateOverrides::new())
    }

    /// Shared body — `at` selects the state view (`None` = latest).
    fn create_access_list_impl(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<(tx::AccessList, u64), CallError> {
        let (rs, _trace, timed_out) = self.simulate(
            req,
            req.gas.unwrap_or(self.block_gas_limit()),
            self.sim_deadline(),
            at,
            ovr,
        )?;
        let gas_used = rs.result.tx_gas_used();
        if timed_out {
            return Err(CallError::Halt { reason: "execution timed out".to_string(), gas_used });
        }
        match rs.result {
            revm::context::result::ExecutionResult::Success { .. } => {}
            revm::context::result::ExecutionResult::Revert { output, .. } => {
                return Err(CallError::Revert { output: output.to_vec(), gas_used });
            }
            revm::context::result::ExecutionResult::Halt { reason, .. } => {
                return Err(CallError::Halt { reason: format!("{reason:?}"), gas_used });
            }
        }

        // Map the journal's touched-account set onto geth's
        // opcode-level `accessListTracer` semantics
        // (`eth/tracers/logger/access_list_tracer.go`):
        //
        // - `excl` gates *address-level* entries only: {caller, `to`,
        //   precompiles}. `addSlot` ignores `excl`, so `to`'s storage
        //   keys still appear — hence `to` is excluded below only when
        //   it touched no slots.
        // - Coinbase is not in geth's `excl` but also never appears —
        //   tip crediting is not an opcode touch — so it is excluded
        //   here unconditionally.
        // - Every other journal account corresponds to an opcode-level
        //   access (EXT*/BALANCE/CALL-family targets, SLOAD/SSTORE
        //   storage owners, SELFDESTRUCT beneficiaries) and is emitted
        //   with its touched slot set — including entries with no
        //   slots, which geth also emits.
        let caller =
            req.from.map_or(revm::primitives::Address::ZERO, |a| alloy_primitives_address(a.0));
        let to = req.to.map(|a| alloy_primitives_address(a.0));
        let coinbase = *framework::lock_state(&self.coinbase);
        let mut excluded = precompiles::NativePrecompiles::warm_addresses_for(self.spec);
        excluded.insert(caller);
        excluded.insert(coinbase);
        // geth's `excl` set for *address-level* entries — the same
        // plus `to` — also filters the caller-provided acl
        // (`NewAccessListTracer` skips them when seeding `list`).
        let mut addr_excl = excluded.clone();
        if let Some(t) = to {
            addr_excl.insert(t);
        }

        // Base map = caller-provided entries (excl-filtered, as geth
        // seeds), then merge in every accessed slot per touched
        // account.
        let mut merged: std::collections::BTreeMap<
            revm::primitives::Address,
            std::collections::BTreeSet<revm::primitives::B256>,
        > = std::collections::BTreeMap::new();
        for item in &req.access_list {
            if addr_excl.contains(&item.address) {
                continue;
            }
            merged.entry(item.address).or_default().extend(item.storage_keys.iter().copied());
        }
        for (addr, account) in &rs.state {
            if excluded.contains(addr) {
                continue;
            }
            let is_to = Some(*addr) == to;
            if is_to && account.storage.is_empty() {
                // `to` is address-excluded in geth — it only appears
                // when the call actually touched its storage.
                continue;
            }
            // Journal storage keys are `U256` slot indices; the wire
            // format wants `B256`.
            merged
                .entry(*addr)
                .or_default()
                .extend(account.storage.keys().map(|k| revm::primitives::B256::from(*k)));
        }
        let list = merged
            .into_iter()
            .map(|(address, keys)| tx::AccessListItem {
                address,
                storage_keys: keys.into_iter().collect(),
            })
            .collect();
        Ok((list, gas_used))
    }
}
