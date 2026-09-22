//! Reward distribution and settlement for the staking module.
//!
//! Split from `lib.rs` around the conservation invariant:
//! `collect_block_reward` mints the block reward and
//! `distribute_rewards` splits it pro-rata — u128 intermediates
//! so `total_reward × stake` can't silently wrap, and the dust
//! stays in the pool rather than drifting supply. The `settle_*`
//! family is the only path that pays rewards out to accounts.

use super::{
    Address, Balances, Event, ExecError, FEE_POOL, REWARD_POOL, RPT_SCALE, StakingModule, TxContext,
};

impl StakingModule {
    /// Handle a claim-reward message: withdraw accumulated rewards.
    ///
    /// If `amount` is 0, all accumulated rewards are claimed.
    /// Otherwise, up to `amount` rewards are claimed.
    ///
    /// The claimed amount is paid out of [`REWARD_POOL`] — the pool
    /// `end_block` funds with swept fees + issuance — so a claim is
    /// a transfer, never new minting at claim time. Validators claim
    /// their self-share; delegators claim their share of every
    /// delegation they hold.
    pub(crate) fn handle_claim_reward(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // An account claims only its own rewards — the pending
        // ledger is a claimable balance, not a public pool. (Matches
        // the key_change authorization model.) The `validator` field
        // is the *claimer* — delegators pass their own address.
        if ctx.sender != validator {
            return Err(ExecError::ModuleRejected(
                "claim_reward: only the account can claim its rewards".to_string(),
            ));
        }
        let ledger = self.require_ledger().map_err(|_| {
            ExecError::ModuleRejected("claim_reward: balance ledger not wired".to_string())
        })?;

        // Lazy accrual: settle every position the claimer holds so
        // `pending_rewards` reflects rewards through the last
        // `end_block` — delegations via `reward_debt`, self-share
        // via `self_debt`.
        self.settle_all(validator);

        let claim_amount = {
            let mut pending = framework::lock_state(&self.pending_rewards);
            let accumulated = pending.get(&validator).copied().unwrap_or(0);
            let claim_amount = if amount == 0 { accumulated } else { amount.min(accumulated) };
            if claim_amount == 0 {
                return Err(ExecError::ModuleRejected(
                    "claim_reward: no rewards to claim".to_string(),
                ));
            }
            *pending.entry(validator).or_insert(0) -= claim_amount;
            claim_amount
        };

        // Pay from the reward pool: pending_rewards only grows by
        // what `end_block` funded into the pool, so the transfer
        // cannot overdraw. Failure leaves `pending` decremented —
        // acceptable because the pool-conservation invariant makes
        // it unreachable; a poisoned ledger would have failed the
        // block earlier.
        ledger
            .transfer(&REWARD_POOL, &validator, claim_amount)
            .map_err(|_| ExecError::ModuleRejected("claim_reward: pool underfunded".to_string()))?;

        Ok(vec![Event { module: "staking", kind: "claim_reward", data: msg.to_vec() }])
    }

    /// The validator's self-share: bonded stake not attributable to
    /// any delegation record (genesis self-stake, validator-add
    /// stake). Accrues rewards to the validator through `self_debt`.
    ///
    /// Callers must hold `validators` and `delegated_total` (or pass
    /// the values in) — lock order is `validators → delegated_total
    /// → reward_per_token → reward_debt/self_debt → pending_rewards`.
    pub(crate) fn self_share_of(stake: u64, delegated_total: u64) -> u64 {
        stake.saturating_sub(delegated_total)
    }

    /// Settle one delegation position: move accrued rewards into
    /// `pending_rewards[delegator]` and stamp the debt at the
    /// current `reward_per_token`. Must run BEFORE the delegation
    /// amount changes — the accrual is a function of the position
    /// that existed while rewards were distributed.
    ///
    /// Lock order: callers may hold `validators`/`delegations`;
    /// this only takes `reward_per_token`, `reward_debt`,
    /// `pending_rewards` — always in that order.
    pub(crate) fn settle_delegation(
        &self,
        delegator: Address,
        validator: Address,
        delegation: u64,
    ) {
        let rpt = *framework::lock_state(&self.reward_per_token).get(&validator).unwrap_or(&0);
        let mut debts = framework::lock_state(&self.reward_debt);
        let debt = debts.entry((delegator, validator)).or_insert(0);
        if rpt > *debt && delegation > 0 {
            let accrued = u128::from(delegation).saturating_mul(rpt - *debt) / RPT_SCALE;
            if accrued > 0 {
                let mut pending = framework::lock_state(&self.pending_rewards);
                let current = pending.get(&delegator).copied().unwrap_or(0);
                pending.insert(
                    delegator,
                    current.saturating_add(u64::try_from(accrued).unwrap_or(u64::MAX)),
                );
            }
        }
        *debt = rpt;
    }

    /// Settle a validator's self-share position into
    /// `pending_rewards[validator]`. Same settle-before-mutate rule
    /// as [`Self::settle_delegation`].
    pub(crate) fn settle_self_share(&self, validator: Address, self_share: u64) {
        let rpt = *framework::lock_state(&self.reward_per_token).get(&validator).unwrap_or(&0);
        let mut debts = framework::lock_state(&self.self_debt);
        let debt = debts.entry(validator).or_insert(0);
        if rpt > *debt && self_share > 0 {
            let accrued = u128::from(self_share).saturating_mul(rpt - *debt) / RPT_SCALE;
            if accrued > 0 {
                let mut pending = framework::lock_state(&self.pending_rewards);
                let current = pending.get(&validator).copied().unwrap_or(0);
                pending.insert(
                    validator,
                    current.saturating_add(u64::try_from(accrued).unwrap_or(u64::MAX)),
                );
            }
        }
        *debt = rpt;
    }

    /// Settle every position an account holds — all delegations in
    /// `delegator_index[account]` plus the self-share if the account
    /// is a registered validator. Called by `claim_reward`.
    pub(crate) fn settle_all(&self, account: Address) {
        let delegator_vs: Vec<Address> = framework::lock_state(&self.delegator_index)
            .get(&account)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        let delegations = framework::lock_state(&self.delegations);
        for v in delegator_vs {
            let amount = delegations.get(&(account, v)).copied().unwrap_or(0);
            self.settle_delegation(account, v, amount);
        }
        drop(delegations);
        let validators = framework::lock_state(&self.validators);
        if let Some(&stake) = validators.get(&account) {
            let delegated = framework::lock_state(&self.delegated_total);
            let self_share =
                Self::self_share_of(stake, delegated.get(&account).copied().unwrap_or(0));
            self.settle_self_share(account, self_share);
        }
    }

    /// Sweep collected fees into [`REWARD_POOL`] and mint the block
    /// issuance, returning the total reward for this block.
    ///
    /// The fee component is a *transfer* (real, pre-collected funds
    /// in [`FEE_POOL`]); the issuance component is a *mint* (new
    /// supply authorized by the reward schedule). Both land in the
    /// reward pool so claims are always pool-funded — a claim can
    /// never overdraw because `pending_rewards` only grows by the
    /// same total distributed here (minus rounding dust, which is
    /// unclaimable).
    pub(crate) fn collect_block_reward(&self, ledger: &dyn Balances) -> u64 {
        let fee_collected = ledger.balance(&FEE_POOL);
        if fee_collected > 0 {
            // The pool can only hold what was deposited — the
            // transfer cannot fail; treat failure as zero collected
            // (defensive: a partially-wired ledger must not halt the
            // block).
            let _ = ledger.transfer(&FEE_POOL, &REWARD_POOL, fee_collected);
        }
        if self.block_reward > 0 {
            ledger.mint(&REWARD_POOL, self.block_reward);
        }
        fee_collected.saturating_add(self.block_reward)
    }

    /// Distribute `total_reward` to active validators proportional
    /// to their stake, growing each validator's
    /// `reward_per_token` accumulator.
    ///
    /// Called at `end_block` with the swept fees + issuance. The
    /// accumulator divides the reward across *all* bonded stake of
    /// the validator — delegations earn through `reward_debt`, the
    /// self-share earns through `self_debt` — so delegators and the
    /// validator's own bond share pro-rata with no commission
    /// parameter (v1 policy; a commission field can be added to the
    /// validator record later without changing the accounting).
    ///
    /// Validators pending removal stop earning — the removal
    /// decision is the point at which they "stop receiving block
    /// rewards" (module docs).
    ///
    /// Integer-division remainders are not distributed — they stay
    /// in [`REWARD_POOL`] as unclaimable dust (deterministic
    /// rounding burn).
    pub(crate) fn distribute_rewards(&self, total_reward: u64) {
        if total_reward == 0 {
            return;
        }
        let validators = framework::lock_state(&self.validators);
        let pending_removes = framework::lock_state(&self.pending_validator_removes);
        // Jailed validators stop earning too — jailing is exclusion
        // from consensus and rewards, not just consensus.
        let jailed = framework::lock_state(&self.jailed);
        let is_eligible =
            |a: &Address, s: u64| s > 0 && !pending_removes.contains(a) && !jailed.contains_key(a);
        let eligible: u64 =
            validators.iter().filter(|(a, s)| is_eligible(a, **s)).map(|(_, s)| *s).sum();
        if eligible == 0 {
            return;
        }
        let mut rpt = framework::lock_state(&self.reward_per_token);
        for (addr, stake) in validators.iter() {
            if !is_eligible(addr, *stake) {
                continue;
            }
            // Money math in u128, not u64 saturation: at realistic
            // token scale `total_reward * stake` overflows u64
            // (1e10 units × 1e10 stake = 1e20 > u64::MAX), and
            // saturating there under-pays a large validator to
            // `u64::MAX / eligible` — a silent obligation change,
            // exactly what saturation-as-error-handling hides. The
            // u128 product cannot overflow (two u64s), and since
            // `stake <= eligible` the quotient is ≤ `total_reward`,
            // so the narrowing is provably lossless.
            let reward =
                u64::try_from(u128::from(total_reward) * u128::from(*stake) / u128::from(eligible))
                    .unwrap_or(u64::MAX);
            if reward > 0 {
                *rpt.entry(*addr).or_insert(0) +=
                    u128::from(reward).saturating_mul(RPT_SCALE).saturating_div(u128::from(*stake));
            }
        }
    }
}
