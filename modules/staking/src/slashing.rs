//! Slashing, evidence, and jailing for the staking module.
//!
//! Split from `lib.rs` around the penalty invariant:
//! `apply_slash` is the only function that burns stake, and it
//! runs only under `handle_evidence` (byzantine proof) or
//! `handle_slash` (governance directive). `handle_unjail` and
//! `handle_schedule_halt` are the release valves — each checks
//! its own precondition, so the penalty surface is auditable end
//! to end in one file.

use super::{
    Address, BONDED_POOL, EVIDENCE_PAYLOAD_LEN, Event, ExecError, MIN_JAIL_BLOCKS, StakingModule,
    TxContext, msg, msg_type,
};

impl StakingModule {
    /// Handle a slash message: reduce `validator`'s stake by `amount`.
    ///
    /// Arbitrary-amount slashing is a governance action — the tx
    /// endorses the exact `(validator, amount)` action, which
    /// applies only once endorsing power strictly exceeds
    /// two-thirds of the committee (C9: a single signer's command
    /// is not committee authorization). The permissionless path is
    /// [`msg_type::EVIDENCE`], which authenticates itself with the
    /// proof it carries.
    pub(crate) fn handle_slash(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // The action must name a live validator before it can
        // collect endorsements — slashing an unknown address is
        // never meaningful.
        if !framework::lock_state(&self.validators).contains_key(&validator) {
            return Err(ExecError::ModuleRejected("slash: validator not found".to_string()));
        }
        match self.endorsements.record(msg, &ctx.sender, self)? {
            framework::EndorsementOutcome::Pending { .. } => {
                Ok(vec![Event { module: "staking", kind: "slash_endorse", data: msg.to_vec() }])
            }
            framework::EndorsementOutcome::Quorum => {
                let events = self.apply_slash(validator, amount, msg)?;
                // A slash that zeroed the target's stake can kill
                // pending removes whose "last powered member" guard
                // now fails — reclaim dead endorsement slots.
                self.sweep_dead_actions();
                Ok(events)
            }
        }
    }

    /// Reduce `validator`'s stake by `amount`, burning the same
    /// proportion from every delegation to it.
    ///
    /// Slashing must hit the delegations, not just the aggregate —
    /// otherwise the bonded pool still owes the full pre-slash amount
    /// (a slash would effectively refund itself on unbond). Each
    /// delegation loses `floor(amount · delegation / stake)`; the
    /// rounding remainder is distributed 1 unit per delegation in
    /// deterministic `(delegator, validator)` order so all replicas
    /// slash identically.
    ///
    /// Shared by `handle_slash` (committee governance) and
    /// `handle_evidence` (permissionless, proof-authenticated).
    pub(crate) fn apply_slash(
        &self,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("slash: validator not found".to_string()))?;
        let slash_amount = amount.min(*stake);
        let stake_before = *stake;

        // Reward accounting settles on the pre-slash positions: every
        // delegation earned its accrued share while it existed, and
        // the self-share settles before it shrinks. (Slash must not
        // confiscate already-earned rewards.)
        {
            let totals = framework::lock_state(&self.delegated_total);
            let self_share =
                Self::self_share_of(stake_before, totals.get(&validator).copied().unwrap_or(0));
            drop(totals);
            self.settle_self_share(validator, self_share);
            for ((d, v), a) in delegations.range(..).filter(|((_, v), _)| *v == validator) {
                self.settle_delegation(*d, *v, *a);
            }
        }

        *stake -= slash_amount;
        let new_stake = *stake;

        let mut burned_from_pool = 0u64;
        if slash_amount > 0 && stake_before > 0 {
            // floor-share each delegation, then hand out the remainder
            // one unit at a time in BTreeMap (sorted) order.
            let mut affected: Vec<(Address, u64)> = delegations
                .range(..)
                .filter(|((_, v), _)| *v == validator)
                .map(|((d, _), a)| (*d, *a))
                .collect();
            let mut applied = 0u64;
            let mut dust_keys = Vec::with_capacity(affected.len());
            for (d, a) in &mut affected {
                let share = u128::from(slash_amount) * u128::from(*a) / u128::from(stake_before);
                let share = u64::try_from(share).unwrap_or(u64::MAX).min(*a);
                *a -= share;
                applied = applied.saturating_add(share);
                if *a > 0 {
                    dust_keys.push(*d);
                }
            }
            // Leftover from flooring: at most `affected.len()` units.
            let mut rem = slash_amount.saturating_sub(applied);
            for d in &dust_keys {
                if rem == 0 {
                    break;
                }
                if let Some((_, a)) = affected.iter_mut().find(|(dd, _)| dd == d) {
                    *a -= 1;
                    rem -= 1;
                    applied += 1;
                }
            }
            for (d, a) in affected {
                if a == 0 {
                    delegations.remove(&(d, validator));
                    framework::lock_state(&self.delegator_index)
                        .get_mut(&d)
                        .map(|set| set.remove(&validator));
                } else {
                    delegations.insert((d, validator), a);
                }
                self.store_delegation_state(validator, d, new_stake, a);
            }
            if let Some(t) = framework::lock_state(&self.delegated_total).get_mut(&validator) {
                *t = t.saturating_sub(applied);
            }
            burned_from_pool = applied;
        }
        drop(delegations);
        drop(validators);

        // Burn only the amount removed from pool-backed delegations —
        // unattributed stake (genesis self-stake) was never in the
        // pool, so burning it would overdraw.
        if burned_from_pool > 0
            && let Some(ledger) = framework::lock_state(&self.ledger).clone()
        {
            // Burn = debit the pool with no credit — supply
            // shrinks (Ethereum burn semantics; cleaner than
            // accumulating at the zero address).
            let _ = ledger.debit(&BONDED_POOL, burned_from_pool);
        }

        Ok(vec![Event { module: "staking", kind: "slash", data: msg.to_vec() }])
    }

    /// Handle a double-sign evidence message:
    /// `[type: 0x08][validator: 20B][view: 8B][phase: 1B][epoch: 8B]`
    /// `[hash_a: 32B][sig_a: 96B][hash_b: 32B][sig_b: 96B]`.
    ///
    /// Permissionless — anyone may submit; the two BLS signatures
    /// are the authentication. Each is verified against ANY key the
    /// validator holds in `bls_keys` ∪ `retired_bls_keys` over the
    /// exact `vote_signing_message` layout the engine signs
    /// (`view LE | phase | block_hash | epoch LE`, `Domain::Vote`):
    /// a forged or misattributed proof fails verification and the
    /// reporter loses only their envelope fee. Retired-key coverage
    /// means a proof stays valid across a rotation — an offender
    /// cannot rotate away from evidence of its own offense.
    ///
    /// The replay guard keys on the CANONICAL OFFENSE —
    /// `(validator, view, phase, epoch)` — so penalties are per
    /// offense, not per payload: the same equivocation resubmitted
    /// with the votes swapped, or proven by a different conflicting
    /// pair at the same position, is a replay, not a second slash.
    ///
    /// On a valid proof: the offender is slashed
    /// [`double_sign_slash_amount`](msg::double_sign_slash_amount)
    /// (10%) and jailed — emitted as a `removes` entry at the next
    /// epoch rotation via `take_validator_changes`.
    pub(crate) fn handle_evidence(
        &self,
        _ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        if msg.len() != 21 + EVIDENCE_PAYLOAD_LEN {
            return Err(ExecError::ModuleRejected(format!(
                "evidence: expected {}-byte message, got {} bytes",
                21 + EVIDENCE_PAYLOAD_LEN,
                msg.len()
            )));
        }
        let view = u64::from_le_bytes(msg[21..29].try_into().map_err(|_| ExecError::Malformed)?);
        let phase = msg[29];
        let epoch = u64::from_le_bytes(msg[30..38].try_into().map_err(|_| ExecError::Malformed)?);
        let hash_a = &msg[38..70];
        let hash_b = &msg[166..198];
        // Equivocation is two votes for *different* blocks at the
        // same (view, phase, epoch). Identical hashes are just one
        // vote presented twice — no fault.
        if hash_a == hash_b {
            return Err(ExecError::ModuleRejected(
                "evidence: identical block hashes — no equivocation".to_string(),
            ));
        }
        let sig_a =
            crypto::bls::Signature::from_slice(&msg[70..166]).map_err(|_| ExecError::Malformed)?;
        let sig_b =
            crypto::bls::Signature::from_slice(&msg[198..294]).map_err(|_| ExecError::Malformed)?;

        // Candidate verification keys: the validator's CURRENT
        // consensus key plus its bounded retired history — evidence
        // can span a key rotation (the offense predates it), so
        // every key the validator has held inside the evidence
        // window is tried. A signature that verifies under ANY of
        // the validator's own keys is a real signature by that
        // validator — BLS unforgeability makes a foreign key's
        // signature impossible to fake.
        let mut candidates: Vec<Vec<u8>> = Vec::new();
        {
            let bls_keys = framework::lock_state(&self.bls_keys);
            if let Some(k) = bls_keys.get(&validator) {
                candidates.push(k.clone());
            }
        }
        {
            let retired = framework::lock_state(&self.retired_bls_keys);
            if let Some(keys) = retired.get(&validator) {
                candidates.extend(keys.iter().cloned());
            }
        }
        if candidates.is_empty() {
            return Err(ExecError::ModuleRejected(
                "evidence: no consensus key on record for validator".to_string(),
            ));
        }

        // Replay guard keyed by the CANONICAL OFFENSE IDENTITY —
        // `(validator, view, phase, epoch)` — not the raw payload.
        // Penalties are per offense: the same equivocation proven
        // by the swapped pair, or by a different conflicting pair
        // at the same position, is one offense and one penalty.
        // The v1 key hashed the ordered payload bytes, so a
        // resubmission with the votes swapped produced a fresh
        // identity and slashed a second time.
        let mut offense = Vec::with_capacity(37);
        offense.extend_from_slice(&validator.0);
        offense.extend_from_slice(&view.to_le_bytes());
        offense.push(phase);
        offense.extend_from_slice(&epoch.to_le_bytes());
        let offense_id = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Vote, &offense);
        {
            let seen = framework::lock_state(&self.seen_evidence);
            if seen.contains(&offense_id) {
                return Err(ExecError::ModuleRejected("evidence: already applied".to_string()));
            }
        }

        // Rebuild the exact 49-byte signing messages and verify
        // both signatures — a valid proof is two verifying
        // signatures over different block hashes. Each signature
        // is checked against every candidate independently: the
        // votes were cast at the same view, but a rotation mid-way
        // could in principle split them across keys, and the
        // offense is the validator signing conflicting votes
        // regardless of which of its keys signed which.
        let mut vote_msg_a = [0u8; 49];
        vote_msg_a[..8].copy_from_slice(&view.to_le_bytes());
        vote_msg_a[8] = phase;
        vote_msg_a[9..41].copy_from_slice(hash_a);
        vote_msg_a[41..49].copy_from_slice(&epoch.to_le_bytes());
        let mut vote_msg_b = [0u8; 49];
        vote_msg_b[..8].copy_from_slice(&view.to_le_bytes());
        vote_msg_b[8] = phase;
        vote_msg_b[9..41].copy_from_slice(hash_b);
        vote_msg_b[41..49].copy_from_slice(&epoch.to_le_bytes());
        let verifies = |sig: &crypto::bls::Signature, vote_msg: &[u8; 49]| {
            candidates.iter().any(|key| {
                crypto::bls::PublicKey::from_slice(key).is_ok_and(|pk| {
                    crypto::bls_signer::verify(sig, crypto::hash::Domain::Vote, vote_msg, &pk)
                        .is_ok()
                })
            })
        };
        if !verifies(&sig_a, &vote_msg_a) || !verifies(&sig_b, &vote_msg_b) {
            return Err(ExecError::ModuleRejected(
                "evidence: signature verification failed".to_string(),
            ));
        }

        // Proof verified — slash and jail. `apply_slash` resolves
        // "validator not found" with the same rejection it already
        // produces.
        let slash_amount = msg::double_sign_slash_amount(self.stake(&validator));
        let mut events = self.apply_slash(validator, slash_amount, msg)?;

        let height = *framework::lock_state(&self.current_height);
        let already_jailed =
            framework::lock_state(&self.jailed).insert(validator, height).is_some();
        if !already_jailed {
            framework::lock_state(&self.pending_jails).push(validator);
        }
        framework::lock_state(&self.seen_evidence).insert(offense_id);

        events.push(Event { module: "staking", kind: "evidence", data: msg.to_vec() });
        Ok(events)
    }

    /// Handle an unjail message: `[type: 0x09][validator: 20B]`.
    ///
    /// Re-admits a jailed validator to the set at the next epoch
    /// rotation. Sender must be the validator itself (same
    /// authorization model as `key_change`), the jail must have
    /// lasted at least [`MIN_JAIL_BLOCKS`], and the validator must
    /// still have stake and a consensus key on record — the engine
    /// cannot re-admit a keyless validator.
    pub(crate) fn handle_unjail(
        &self,
        ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        if ctx.sender != validator {
            return Err(ExecError::ModuleRejected(
                "unjail: only the validator can unjail itself".to_string(),
            ));
        }
        let jailed_at = framework::lock_state(&self.jailed)
            .get(&validator)
            .copied()
            .ok_or(ExecError::ModuleRejected("unjail: validator is not jailed".to_string()))?;
        let height = *framework::lock_state(&self.current_height);
        if height.saturating_sub(jailed_at) < MIN_JAIL_BLOCKS {
            return Err(ExecError::ModuleRejected(format!(
                "unjail: {MIN_JAIL_BLOCKS}-block jail period not elapsed"
            )));
        }
        if self.stake(&validator) == 0 {
            return Err(ExecError::ModuleRejected("unjail: validator has no stake".to_string()));
        }
        if !framework::lock_state(&self.bls_keys).contains_key(&validator) {
            return Err(ExecError::ModuleRejected(
                "unjail: no consensus key on record".to_string(),
            ));
        }

        framework::lock_state(&self.jailed).remove(&validator);
        framework::lock_state(&self.pending_unjails).push(validator);

        Ok(vec![Event { module: "staking", kind: "unjail", data: msg.to_vec() }])
    }

    /// Handle a schedule-halt message:
    /// `[type: 0x0A][validator: 20B][halt_height: 8B LE]`.
    ///
    /// Committee-quorum endorsement — coordinating an upgrade halt
    /// is a validator-set decision no single member may take. The
    /// endorsed action is `(SCHEDULE_HALT, halt_height)`: the
    /// `validator` field is only the message header's uniform
    /// address slot (the real sender is `ctx.sender`), so it does
    /// not participate in the action's identity.
    /// `halt_height` must be in the future (a past/present halt
    /// freezes immediately, which governance cannot intend
    /// mid-block); `0` clears the schedule.
    pub(crate) fn handle_schedule_halt(
        &self,
        ctx: &TxContext,
        _validator: Address,
        halt_height: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let current = *framework::lock_state(&self.current_height);
        if halt_height != 0 && halt_height <= current {
            return Err(ExecError::ModuleRejected(format!(
                "schedule_halt: height {halt_height} is not in the future (current {current})"
            )));
        }
        // Action identity = the type tag + the target height. A
        // stale-height action can still reach quorum after the tip
        // passes it, so the future check is re-evaluated at apply
        // time below.
        let mut action = Vec::with_capacity(9);
        action.push(msg_type::SCHEDULE_HALT);
        action.extend_from_slice(&halt_height.to_le_bytes());
        match self.endorsements.record(&action, &ctx.sender, self)? {
            framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                module: "staking",
                kind: "schedule_halt_endorse",
                data: msg.to_vec(),
            }]),
            framework::EndorsementOutcome::Quorum => {
                let now = *framework::lock_state(&self.current_height);
                let events = if halt_height != 0 && halt_height <= now {
                    vec![Event {
                        module: "staking",
                        kind: "schedule_halt_stale",
                        data: msg.to_vec(),
                    }]
                } else {
                    *framework::lock_state(&self.scheduled_halt) =
                        if halt_height == 0 { None } else { Some(halt_height) };
                    vec![Event { module: "staking", kind: "schedule_halt", data: msg.to_vec() }]
                };
                // Applying (or passing) a halt height kills pending
                // halt entries for heights the tip has passed.
                self.sweep_dead_actions();
                Ok(events)
            }
        }
    }
}
