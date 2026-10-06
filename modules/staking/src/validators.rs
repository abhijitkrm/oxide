//! Validator-set lifecycle for the staking module.
//!
//! Split from `lib.rs` around the membership invariant:
//! `handle_validator_add` stages a candidate behind its BLS `PoP`
//! and pending-action set; `handle_validator_remove` /
//! `apply_validator_remove` retire it; `cancel_pending_add` and
//! `sweep_dead_actions` keep the pending set honest. Consensus
//! reads the set only through `Committee`, so every mutation path
//! lives here.

use super::{
    Address, Event, ExecError, RejectCategory, StakingModule, TxContext, UnbondingEntry, msg_type,
};

impl StakingModule {
    /// Handle a key-change message: record a new BLS consensus key
    /// for `validator`.
    ///
    /// The message format is
    /// `[type: 0x05][validator: 20B][new_key: 48B][pop: 96B]`.
    /// The new key takes effect at the next epoch rotation — the
    /// consensus engine reads pending changes via `take_key_changes`.
    ///
    /// Only the validator itself can change its key (checked via
    /// `ctx.sender`). The sender must be the validator address.
    ///
    /// `pop` is a proof-of-possession for `new_key` — mandatory
    /// because QC verification uses `fast_aggregate_verify`, which is
    /// forgeable unless every signer key proves possession at
    /// admission (rogue-key attack). A key that cannot produce a `PoP`
    /// cannot enter the validator set.
    pub(crate) fn handle_key_change(
        &self,
        ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // The sender must be the validator changing its own key.
        if ctx.sender != validator {
            return Err(ExecError::rejected(
                RejectCategory::Unauthorized,
                "key_change: sender must be the validator",
            ));
        }
        // The validator must exist (have non-zero stake).
        let validators = framework::lock_state(&self.validators);
        if !validators.contains_key(&validator) {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                "key_change: validator not found",
            ));
        }
        // The new key is a 48-byte BLS12-381 compressed public key,
        // followed by its 96-byte proof-of-possession.
        if msg.len() != 21 + 48 + 96 {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                format!(
                    "key_change: expected 144-byte key+pop, got {} bytes",
                    msg.len().saturating_sub(21)
                ),
            ));
        }
        // PoP verification mints the validated-key token — the
        // pending queue and `bls_keys` store the proof, so the key
        // the epoch boundary hands to consensus cannot be an
        // unchecked byte string.
        let new_key = Self::verify_key_pop(&msg[21..69], &msg[69..165], "key_change")?;
        // A consensus key identifies exactly one staking address —
        // rotating to a key another member already holds would
        // collide identities at the rotation's duplicate check
        // (same gate `validator_add` applies at admission).
        if framework::lock_state(&self.bls_keys)
            .iter()
            .any(|(a, k)| *a != validator && *k == new_key)
        {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "key_change: consensus key already in use",
            ));
        }
        drop(validators); // release lock before acquiring pending_key_changes

        framework::lock_state(&self.pending_key_changes).insert(validator, new_key);

        Ok(vec![Event { module: "staking", kind: "key_change", data: msg.to_vec() }])
    }

    /// Verify a BLS proof-of-possession for a consensus key being
    /// admitted (`validator_add` or `key_change`).
    ///
    /// `PoP` admission is the precondition that makes
    /// `fast_aggregate_verify` safe for same-message QC aggregation:
    /// a rogue key — a public key crafted as a linear combination of
    /// honest keys so an attacker's lone signature verifies as a
    /// quorum aggregate — cannot produce `Sign(sk_rogue, pk)` because
    /// its discrete log is unknowable. Requiring the `PoP` here means
    /// every key that reaches `ValidatorSet` is a real key the
    /// presenter controls, not an algebraic forgery.
    ///
    /// # Errors
    /// `ExecError::ModuleRejected` if `key` is not a 48-byte
    /// compressed public key, `pop` is not a 96-byte signature, or
    /// the `PoP` fails verification.
    ///
    /// Returns the [`ValidatedPublicKey`] proof token — the key has
    /// both a verified `PoP` and a passing point + subgroup decode, so
    /// the caller stores the token rather than the raw bytes.
    pub(crate) fn verify_key_pop(
        key: &[u8],
        pop: &[u8],
        op: &str,
    ) -> Result<crypto::bls_signer::ValidatedPublicKey, ExecError> {
        let pk = crypto::bls::PublicKey::from_slice(key).map_err(|_| {
            ExecError::rejected(
                RejectCategory::InvalidInput,
                format!("{op}: malformed BLS public key"),
            )
        })?;
        let pop_sig = crypto::bls::Signature::from_slice(pop).map_err(|_| {
            ExecError::rejected(
                RejectCategory::InvalidInput,
                format!("{op}: malformed PoP signature"),
            )
        })?;
        crypto::bls_signer::pop_verify(&pk, &pop_sig).map_err(|_| {
            ExecError::rejected(
                RejectCategory::Unauthorized,
                format!("{op}: proof-of-possession verification failed"),
            )
        })?;
        // `pop_verify` already decoded the point; `new` runs the
        // subgroup check so the token's contract does not depend on
        // what the verify path happened to cover.
        crypto::bls_signer::ValidatedPublicKey::new(pk).map_err(|_| {
            ExecError::rejected(
                RejectCategory::InvalidInput,
                format!("{op}: BLS key is not a valid group element"),
            )
        })
    }

    /// Handle a validator-add message:
    /// `[type: 0x06][new_validator: 20B][bls_key: 48B][pop: 96B]`.
    ///
    /// The message is a committee *endorsement* of the exact
    /// `(new_validator, bls_key)` action: the sender must carry
    /// committee voting power, and the admission applies only once
    /// cumulative endorsing power strictly exceeds two-thirds of
    /// the committee — the same quorum a consensus QC requires
    /// (C9: consensus on inclusion is not governance
    /// authorization).
    ///
    /// Admission registers the candidate with **zero** stake — it
    /// declares membership, not collateral. Delegations bond real
    /// balance to the candidate, and the rotation seats it only if
    /// bonded stake exists at the epoch boundary; the activation
    /// stake is whatever the ledger proves, never anything the add
    /// message claimed.
    ///
    /// # Errors
    ///
    /// - `ModuleRejected` if the sender has no committee voting
    ///   power (not a member, jailed, pending, or unbonded).
    /// - `ModuleRejected` if the candidate is already registered,
    ///   already pending, or its BLS key is already in use.
    /// - `ModuleRejected` if the message is malformed or the `PoP`
    ///   does not verify.
    pub(crate) fn handle_validator_add(
        &self,
        ctx: &TxContext,
        new_validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // Parse [bls_key: 48B][pop: 96B] after the validator field.
        // The PoP is verified BEFORE an endorsement is recorded —
        // endorsements only accumulate for actions that could
        // apply, and a consensus key that cannot prove possession
        // must never reach the ValidatorSet (rogue-key
        // aggregate-forgery defense).
        if msg.len() != 21 + 48 + 96 {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                format!("validator_add: expected 165-byte message, got {} bytes", msg.len()),
            ));
        }
        let bls_key = Self::verify_key_pop(&msg[21..69], &msg[69..165], "validator_add")?;

        // Validate the action before recording: the candidate must
        // not already be registered or pending, and its consensus
        // key must not duplicate another member's (a BLS key
        // identifies exactly one staking address — the same
        // duplicate-identity check `ValidatorSet` enforces at
        // rotation, applied early so doomed actions never collect
        // endorsements).
        self.validate_add_action(&new_validator, &bls_key)?;

        // The endorsement binds the action payload — type +
        // address + key (the PoP is a proof, not part of the
        // action's identity: two different proofs for the same key
        // endorse the same action).
        match self.endorsements.record(&msg[..69], &ctx.sender, self)? {
            framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                module: "staking",
                kind: "validator_add_endorse",
                data: msg.to_vec(),
            }]),
            framework::EndorsementOutcome::Quorum => {
                // Re-validate at apply time — the set may have
                // changed since the first endorsement (a different
                // action may have registered the address or key).
                let events = if self.validate_add_action(&new_validator, &bls_key).is_err() {
                    vec![Event {
                        module: "staking",
                        kind: "validator_add_stale",
                        data: msg.to_vec(),
                    }]
                } else {
                    framework::lock_state(&self.validators).insert(new_validator, 0);
                    // Record the consensus key immediately — evidence
                    // submitted before the rotation still needs it
                    // for verification. A re-admission overwrites
                    // the previous live key — retire it rather
                    // than dropping the one a pending proof needs.
                    let displaced =
                        framework::lock_state(&self.bls_keys).insert(new_validator, bls_key);
                    if let Some(old) = displaced
                        && old != bls_key
                    {
                        self.retire_key(new_validator, old);
                    }
                    framework::lock_state(&self.pending_validator_adds)
                        .push((new_validator, bls_key));
                    vec![Event { module: "staking", kind: "validator_add", data: msg.to_vec() }]
                };
                // Registering the candidate killed every other
                // pending "admit this address" variant — reclaim
                // their endorsement slots before they leak.
                self.sweep_dead_actions();
                Ok(events)
            }
        }
    }

    /// Check that `(candidate, key)` may be admitted: not already
    /// registered, not already pending, and the key not in use by
    /// another address. Runs both before an endorsement is
    /// recorded and again when the action reaches quorum — the
    /// committee may have changed in between.
    pub(crate) fn validate_add_action(
        &self,
        candidate: &Address,
        key: &crypto::bls_signer::ValidatedPublicKey,
    ) -> Result<(), ExecError> {
        let validators = framework::lock_state(&self.validators);
        if validators.contains_key(candidate) {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "validator_add: validator already exists",
            ));
        }
        let pending_adds = framework::lock_state(&self.pending_validator_adds);
        if pending_adds.iter().any(|(a, _)| a == candidate) {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "validator_add: validator already pending",
            ));
        }
        let bls_keys = framework::lock_state(&self.bls_keys);
        if bls_keys.iter().any(|(a, k)| a != candidate && k == key) {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "validator_add: consensus key already in use",
            ));
        }
        Ok(())
    }

    /// Handle a validator-remove message: `[type: 0x07][validator: 20B]`.
    ///
    /// Committee-quorum endorsement, same model as
    /// `validator_add`: the remove applies only once endorsing
    /// power strictly exceeds two-thirds. Removing a
    /// quorum-admitted candidate that has not seated yet cancels
    /// its admission outright; removing an active member queues it
    /// for the next epoch rotation, where its stake enters
    /// unbonding.
    ///
    /// # Errors
    ///
    /// - `ModuleRejected` if the sender has no committee voting
    ///   power.
    /// - `ModuleRejected` if the validator is not registered or is
    ///   already pending removal.
    /// - `ModuleRejected` if removing this validator would leave
    ///   the set without powered members.
    pub(crate) fn handle_validator_remove(
        &self,
        ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        self.validate_remove_action(&validator)?;

        match self.endorsements.record(msg, &ctx.sender, self)? {
            framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                module: "staking",
                kind: "validator_remove_endorse",
                data: msg.to_vec(),
            }]),
            framework::EndorsementOutcome::Quorum => {
                let events = if self.validate_remove_action(&validator).is_err() {
                    vec![Event {
                        module: "staking",
                        kind: "validator_remove_stale",
                        data: msg.to_vec(),
                    }]
                } else {
                    self.apply_validator_remove(&validator);
                    vec![Event { module: "staking", kind: "validator_remove", data: msg.to_vec() }]
                };
                // Removing the target killed pending actions aimed
                // at it (e.g. a queued slash or remove variant) —
                // reclaim their endorsement slots.
                self.sweep_dead_actions();
                Ok(events)
            }
        }
    }

    /// Check that `validator` may be removed right now — run before
    /// an endorsement is recorded and again at quorum.
    pub(crate) fn validate_remove_action(&self, validator: &Address) -> Result<(), ExecError> {
        let validators = framework::lock_state(&self.validators);
        if !validators.contains_key(validator) {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                "validator_remove: validator not found",
            ));
        }
        let pending_removes = framework::lock_state(&self.pending_validator_removes);
        if pending_removes.contains(validator) {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "validator_remove: validator already pending removal",
            ));
        }
        // A pending-add candidate is removable — the remove cancels
        // the admission — so the "last validator" guard only applies
        // to powered members. Count powered members not already
        // queued for removal: removing the last one would leave the
        // chain with no committee.
        let jailed = framework::lock_state(&self.jailed);
        let staying_powered = validators
            .iter()
            .filter(|(a, s)| **s > 0 && !pending_removes.contains(*a) && !jailed.contains_key(*a))
            .count();
        if staying_powered <= 1
            && framework::lock_state(&self.pending_validator_adds)
                .iter()
                .all(|(a, _)| a != validator)
        {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "validator_remove: cannot remove last powered validator",
            ));
        }
        Ok(())
    }

    /// Apply a quorum-authorized removal: cancel a pending
    /// admission outright, or queue an active member for the next
    /// epoch rotation.
    pub(crate) fn apply_validator_remove(&self, validator: &Address) {
        let mut pending_adds = framework::lock_state(&self.pending_validator_adds);
        if let Some(pos) = pending_adds.iter().position(|(a, _)| a == validator) {
            pending_adds.remove(pos);
            drop(pending_adds);
            self.cancel_pending_add(validator);
            return;
        }
        drop(pending_adds);
        framework::lock_state(&self.pending_validator_removes).push(*validator);
    }

    /// Unwind a pending-add candidate that never seated: drop the
    /// registration and key, and move every delegation into
    /// unbonding so delegators recover their collateral after the
    /// period — the bonded pool pays out at `end_block` exactly as
    /// for a normal undelegation. Bonded admission (C9) lets real
    /// collateral accumulate while a candidate waits to seat, so
    /// cancelling is NOT the no-op it was when adds carried only a
    /// declared amount. Reward settlement is unnecessary: a pending
    /// candidate never entered the consensus set, so it accrued
    /// nothing.
    pub(crate) fn cancel_pending_add(&self, validator: &Address) {
        let current = *framework::lock_state(&self.current_height);
        let completion = current.saturating_add(self.unbonding_period());
        let mut delegations = framework::lock_state(&self.delegations);
        let affected: Vec<(Address, u64)> = delegations
            .iter()
            .filter(|((_, v), _)| v == validator)
            .map(|((d, _), amount)| (*d, *amount))
            .collect();
        {
            let mut unbonding = framework::lock_state(&self.unbonding);
            let mut delegator_index = framework::lock_state(&self.delegator_index);
            for (delegator, amount) in &affected {
                delegations.remove(&(*delegator, *validator));
                if let Some(mut set) = delegator_index.get(delegator).cloned() {
                    set.remove(validator);
                    delegator_index.insert(*delegator, set);
                }
                unbonding.push(UnbondingEntry {
                    delegator: *delegator,
                    validator: *validator,
                    amount: *amount,
                    completion_height: completion,
                });
            }
        }
        framework::lock_state(&self.delegated_total).remove(validator);
        framework::lock_state(&self.validators).remove(validator);
        // Retire rather than drop: the cancelled candidate's key
        // never went live, but a previous incarnation's key may be
        // what this entry held — the uniform retire rule applies.
        let removed_key = framework::lock_state(&self.bls_keys).remove(validator);
        if let Some(old) = removed_key {
            self.retire_key(*validator, old);
        }
        // Clear the store mirror so queries cannot report a phantom
        // stake or delegation for the cancelled candidate.
        {
            let mut store = framework::lock_state(&self.store);
            store.remove(&validator.0.to_vec());
            for (delegator, _) in &affected {
                let mut key = Vec::with_capacity(4 + 40);
                key.extend_from_slice(b"del/");
                key.extend_from_slice(&delegator.0);
                key.extend_from_slice(&validator.0);
                store.remove(&key);
            }
        }
    }

    /// Drop pending endorsements for actions that can never apply.
    ///
    /// Called after every quorum — the authorized state change can
    /// kill sibling actions: admitting validator X makes every
    /// other pending "admit X" variant permanently invalid, and a
    /// scheduled halt whose height the tip passes can never fire.
    /// Record-time validation already rejects *new* endorsements
    /// of dead actions, but the frozen entry would otherwise occupy
    /// the bounded [`framework::MAX_PENDING_ACTIONS`] set forever:
    /// unable to collect another endorsement, it can never reach
    /// quorum and be consumed. Governance txs are rare, so the
    /// O(pending) sweep is cheap insurance against cap exhaustion.
    pub(crate) fn sweep_dead_actions(&self) {
        self.endorsements.retain(|action| self.is_action_live(action));
    }

    /// `true` while `action` could still apply — the same checks the
    /// handlers run before recording an endorsement, reused so the
    /// sweep drops exactly the actions the record path would reject
    /// forever.
    pub(crate) fn is_action_live(&self, action: &[u8]) -> bool {
        match action.first() {
            // [type][validator: 20B][bls_key: 48B] — dead once the
            // address is registered/pending or the key is taken.
            Some(&msg_type::VALIDATOR_ADD) => {
                if action.len() != 1 + 20 + 48 {
                    return false;
                }
                let Ok(addr) = <[u8; 20]>::try_from(&action[1..21]) else { return false };
                // A key that no longer decodes to a valid point can
                // never apply — the action is dead.
                let Ok(key) = crypto::bls_signer::ValidatedPublicKey::from_bytes(&action[21..69])
                else {
                    return false;
                };
                self.validate_add_action(&Address(addr), &key).is_ok()
            }
            // [type][validator: 20B] — dead once the target is
            // unremovable (gone, already queued, or last powered
            // member). "Last member" is transient — a later add
            // could re-enable removal — but dropping a dead entry
            // only forces re-endorsement, never a wrong apply.
            Some(&msg_type::VALIDATOR_REMOVE) => {
                if action.len() != 1 + 20 {
                    return false;
                }
                let Ok(addr) = <[u8; 20]>::try_from(&action[1..21]) else { return false };
                self.validate_remove_action(&Address(addr)).is_ok()
            }
            // [type][validator: 20B][amount: 8B] — dead once the
            // target is no longer registered.
            Some(&msg_type::SLASH) => {
                if action.len() != 1 + 20 + 8 {
                    return false;
                }
                let Ok(addr) = <[u8; 20]>::try_from(&action[1..21]) else { return false };
                framework::lock_state(&self.validators).contains_key(&Address(addr))
            }
            // [type][height: 8B] — dead once the tip passes the
            // target height (height 0 = "cancel halt" never dies).
            Some(&msg_type::SCHEDULE_HALT) => {
                if action.len() != 1 + 8 {
                    return false;
                }
                let Ok(bits) = <[u8; 8]>::try_from(&action[1..9]) else { return false };
                let halt = u64::from_le_bytes(bits);
                let current = *framework::lock_state(&self.current_height);
                halt == 0 || halt > current
            }
            // Unknown payloads are kept — conservatively assume a
            // future action type rather than silently dropping
            // state a replica expects to reach quorum.
            _ => true,
        }
    }
}
