//! Delegation lifecycle for the staking module.
//!
//! Split from `lib.rs` around the delegation invariant:
//! `delegate_for`/`undelegate_for` are the only paths that move
//! stake between a delegator and a validator, and the `undo_*`
//! variants are their exact inverses for failed-block rollback.
//! Reward accounting (`reward_per_token`/`reward_debt`) is
//! checkpointed on every transition — a delegation change that
//! skipped the checkpoint would leak or double-count rewards.

use super::{
    Address, BONDED_POOL, Balances, Event, ExecError, StakingModule, TxContext, UnbondingEntry,
};

impl StakingModule {
    /// The delegator's bonded amount with a validator.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn delegation(&self, delegator: &Address, validator: &Address) -> u64 {
        framework::lock_state(&self.delegations)
            .get(&(*delegator, *validator))
            .copied()
            .unwrap_or(0)
    }

    /// Record a stake + delegation mutation in the KV store so
    /// `state_root` covers it. Lock order: callers must already hold
    /// (or not need) `validators`/`delegations`; this only takes
    /// `store`.
    pub(crate) fn store_delegation_state(
        &self,
        validator: Address,
        delegator: Address,
        stake: u64,
        delegation: u64,
    ) {
        let mut store = framework::lock_state(&self.store);
        store.insert(validator.0.to_vec(), stake.to_le_bytes().to_vec());
        let mut key = Vec::with_capacity(4 + 40);
        key.extend_from_slice(b"del/");
        key.extend_from_slice(&delegator.0);
        key.extend_from_slice(&validator.0);
        store.insert(key, delegation.to_le_bytes().to_vec());
    }

    /// Handle a delegate message: move `amount` from the sender's
    /// balance into the bonded pool and record the delegation.
    ///
    /// Invariants enforced (shared by the native and EVM-precompile
    /// paths — both call `handle`):
    /// - The validator must be registered (`genesis_register_validator`
    ///   or `VALIDATOR_ADD`); delegation to an unknown validator is
    ///   rejected rather than silently fabricating consensus stake.
    /// - The sender's balance must cover `amount` — the ledger's
    ///   `transfer` enforces this, so the EVM precompile cannot inflate
    ///   stake for free.
    pub(crate) fn handle_delegate(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let ledger = self.require_ledger()?;
        self.delegate_for(ctx.sender, validator, amount, ledger.as_ref())?;
        Ok(vec![Event { module: "staking", kind: "delegate", data: msg.to_vec() }])
    }

    /// Bond `amount` of `delegator`'s balance to `validator` through
    /// `ledger`.
    ///
    /// This is the shared core of [`handle_delegate`] and the EVM
    /// staking precompile: identical invariant enforcement regardless
    /// of which path the request arrives on. The delegator is debited
    /// into [`BONDED_POOL`]; the validator must be registered.
    ///
    /// The `ledger` is a parameter, not `self.ledger`, because the
    /// two call sites need *different* revert scopes: a native
    /// `delegate` tx settles against the block-undo'd account cache
    /// (the `EvmModule` impl), while the EVM precompile must move the
    /// bond through revm's journal so a reverting frame restores both
    /// balances — refunding in `undo_delegate` would then double-pay
    /// the pool.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if the validator is unregistered,
    /// the transfer fails (insufficient balance), or stake/delegation
    /// arithmetic overflows.
    pub fn delegate_for(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
        ledger: &dyn Balances,
    ) -> Result<(), ExecError> {
        {
            let validators = framework::lock_state(&self.validators);
            if !validators.contains_key(&validator) {
                return Err(ExecError::ModuleRejected(
                    "delegate: validator not registered".to_string(),
                ));
            }
        }
        // Debit first: if the transfer fails nothing is recorded.
        ledger.transfer(&delegator, &BONDED_POOL, amount)?;

        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
        // Reward accounting must settle on the *pre-mutation*
        // position: the delegation earns rewards accrued while it
        // existed, and the validator's self-share shrinks as
        // `delegated_total` grows.
        let current_delegation = delegations.get(&(delegator, validator)).copied().unwrap_or(0);
        self.settle_delegation(delegator, validator, current_delegation);
        {
            let mut totals = framework::lock_state(&self.delegated_total);
            let stake_now = validators.get(&validator).copied().unwrap_or(0);
            let self_share =
                Self::self_share_of(stake_now, totals.get(&validator).copied().unwrap_or(0));
            self.settle_self_share(validator, self_share);
            *totals.entry(validator).or_insert(0) += amount;
        }
        framework::lock_state(&self.delegator_index)
            .entry(delegator)
            .or_default()
            .insert(validator);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("delegate: validator vanished".to_string()))?;
        *stake = stake
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("stake overflow".to_string()))?;
        let delegation = delegations.entry((delegator, validator)).or_insert(0);
        *delegation = delegation
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("delegation overflow".to_string()))?;
        self.store_delegation_state(validator, delegator, *stake, *delegation);
        Ok(())
    }

    /// Reverse a [`delegate_for`]'s *record* — used by the EVM
    /// native journal when the calling frame reverts.
    ///
    /// Subtracts stake/delegation only. The bonded funds need no
    /// refund here: the precompile moved them through revm's journal,
    /// so `checkpoint_revert` already restored both balances before
    /// this undo runs. Refunding again would double-pay the pool.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if the delegation is smaller than
    /// `amount` (the undo would make accounting inconsistent — this
    /// indicates a journal bug, not user error).
    pub fn undo_delegate(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), ExecError> {
        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
        let delegation = delegations
            .get_mut(&(delegator, validator))
            .ok_or(ExecError::ModuleRejected("undo_delegate: no delegation".to_string()))?;
        if *delegation < amount {
            return Err(ExecError::ModuleRejected(
                "undo_delegate: delegation smaller than undo amount".to_string(),
            ));
        }
        *delegation -= amount;
        let new_delegation = *delegation;
        if new_delegation == 0 {
            delegations.remove(&(delegator, validator));
            framework::lock_state(&self.delegator_index)
                .get_mut(&delegator)
                .map(|set| set.remove(&validator));
        }
        if let Some(t) = framework::lock_state(&self.delegated_total).get_mut(&validator) {
            *t = t.saturating_sub(amount);
        }
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undo_delegate: validator gone".to_string()))?;
        *stake -= amount;
        self.store_delegation_state(validator, delegator, *stake, new_delegation);
        Ok(())
    }

    /// Start unbonding `amount` of `delegator`'s own delegation to
    /// `validator` — shared core of [`handle_undelegate`] and the EVM
    /// staking precompile.
    ///
    /// Stake drops immediately; the amount enters the unbonding queue
    /// and is paid from the bonded pool at `completion_height`.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if `delegator` has no delegation to
    /// `validator` or it is smaller than `amount`.
    pub fn undelegate_for(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<u64, ExecError> {
        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
        let delegation = delegations.get_mut(&(delegator, validator)).ok_or_else(|| {
            ExecError::ModuleRejected(
                "undelegate: no delegation from this sender to this validator".to_string(),
            )
        })?;
        if *delegation < amount {
            return Err(ExecError::ModuleRejected(
                "undelegate: insufficient delegation".to_string(),
            ));
        }
        // Settle on the pre-mutation amounts: the full delegation
        // earned rewards up to now; the validator's self-share grows
        // as `delegated_total` shrinks.
        let old_delegation = *delegation;
        self.settle_delegation(delegator, validator, old_delegation);
        {
            let mut totals = framework::lock_state(&self.delegated_total);
            let stake_now = validators.get(&validator).copied().unwrap_or(0);
            let self_share =
                Self::self_share_of(stake_now, totals.get(&validator).copied().unwrap_or(0));
            self.settle_self_share(validator, self_share);
            if let Some(t) = totals.get_mut(&validator) {
                *t = t.saturating_sub(amount);
            }
        }
        *delegation -= amount;
        let new_delegation = *delegation;
        if new_delegation == 0 {
            delegations.remove(&(delegator, validator));
            framework::lock_state(&self.delegator_index)
                .get_mut(&delegator)
                .map(|set| set.remove(&validator));
        }
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undelegate: validator not found".to_string()))?;
        *stake -= amount; // delegation ≤ stake by construction
        self.store_delegation_state(validator, delegator, *stake, new_delegation);
        drop(delegations);
        drop(validators);

        let current = *framework::lock_state(&self.current_height);
        let completion = current.saturating_add(self.unbonding_period);
        framework::lock_state(&self.unbonding).push(UnbondingEntry {
            delegator,
            validator,
            amount,
            completion_height: completion,
        });
        Ok(completion)
    }

    /// Reverse an [`undelegate_for`] — EVM journal rollback. Removes
    /// the most recent matching unbonding entry and restores the
    /// delegation and stake.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if no matching unbonding entry
    /// exists (journal bug).
    pub fn undo_undelegate(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), ExecError> {
        {
            let mut unbonding = framework::lock_state(&self.unbonding);
            // Remove the *last* matching entry — journal undos run in
            // reverse order of mutation within the frame.
            let pos = unbonding
                .iter()
                .rposition(|e| {
                    e.delegator == delegator && e.validator == validator && e.amount == amount
                })
                .ok_or(ExecError::ModuleRejected(
                    "undo_undelegate: no matching unbonding entry".to_string(),
                ))?;
            unbonding.remove(pos);
        }
        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undo_undelegate: validator gone".to_string()))?;
        *stake = stake
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("stake overflow on undo".to_string()))?;
        let delegation = delegations.entry((delegator, validator)).or_insert(0);
        *delegation = delegation
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("delegation overflow on undo".to_string()))?;
        *framework::lock_state(&self.delegated_total).entry(validator).or_insert(0) += amount;
        framework::lock_state(&self.delegator_index)
            .entry(delegator)
            .or_default()
            .insert(validator);
        self.store_delegation_state(validator, delegator, *stake, *delegation);
        Ok(())
    }

    /// Handle an undelegate message: start unbonding `amount` of the
    /// **sender's own** delegation to `validator`.
    ///
    /// The delegation is removed immediately (stake drops now) and the
    /// amount enters the unbonding queue; at `completion_height`
    /// `end_block` pays it out of the bonded pool to the delegator.
    pub(crate) fn handle_undelegate(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        self.undelegate_for(ctx.sender, validator, amount)?;
        Ok(vec![Event { module: "staking", kind: "undelegate", data: msg.to_vec() }])
    }
}
