//! Write side of the staking snapshot codec.
//!
//! Split from `lib.rs` around the persistence invariant: the
//! `commit_*`/`write_committed` family owns the canonical write
//! schema — section order and field encoding — while `decode.rs`
//! owns the read side. Both sit in the same crate section so a
//! schema change touches one pair of files, never one side alone.

use super::{StakingModule, subtree_root};

impl StakingModule {
    /// Commit `validators`, `delegations`, and the `unbonding` queue
    /// to the canonical state encoding (C8). These decide consensus
    /// voting power and future unbond payouts.
    pub(crate) fn commit_stake_state(&self, w: &mut framework::CanonicalState) {
        {
            let validators = framework::lock_state(&self.validators);
            w.put_count(validators.len());
            for (a, s) in validators.iter() {
                w.put_addr(a).put_u64(*s);
            }
        }
        {
            let delegations = framework::lock_state(&self.delegations);
            w.put_count(delegations.len());
            for ((d, v), amt) in delegations.iter() {
                w.put_addr(d).put_addr(v).put_u64(*amt);
            }
        }
        {
            let unbonding = framework::lock_state(&self.unbonding);
            w.put_count(unbonding.len());
            for e in unbonding.iter() {
                w.put_addr(&e.delegator)
                    .put_addr(&e.validator)
                    .put_u64(e.amount)
                    .put_u64(e.completion_height);
            }
        }
    }

    /// Commit the reward accrual state (C8): `pending_rewards`,
    /// `reward_per_token`, `reward_debt`, `self_debt`,
    /// `delegator_index`, and `delegated_total` — the lazy-accrual
    /// bookkeeping that decides future payouts. `delegator_index`
    /// is technically derivable from `delegations`, but it is
    /// maintained as replicated state and committed alongside: a
    /// drift bug would produce divergent claims and SHOULD diverge
    /// the root.
    pub(crate) fn commit_reward_state(&self, w: &mut framework::CanonicalState) {
        {
            let pending = framework::lock_state(&self.pending_rewards);
            w.put_count(pending.len());
            for (a, r) in pending.iter() {
                w.put_addr(a).put_u64(*r);
            }
        }
        {
            let rpt = framework::lock_state(&self.reward_per_token);
            w.put_count(rpt.len());
            for (a, r) in rpt.iter() {
                w.put_addr(a).put_u128(*r);
            }
            let debt = framework::lock_state(&self.reward_debt);
            w.put_count(debt.len());
            for ((d, v), r) in debt.iter() {
                w.put_addr(d).put_addr(v).put_u128(*r);
            }
            let self_debt = framework::lock_state(&self.self_debt);
            w.put_count(self_debt.len());
            for (a, r) in self_debt.iter() {
                w.put_addr(a).put_u128(*r);
            }
            let index = framework::lock_state(&self.delegator_index);
            w.put_count(index.len());
            for (d, validators) in index.iter() {
                w.put_addr(d).put_count(validators.len());
                for v in validators {
                    w.put_addr(v);
                }
            }
            let totals = framework::lock_state(&self.delegated_total);
            w.put_count(totals.len());
            for (a, t) in totals.iter() {
                w.put_addr(a).put_u64(*t);
            }
        }
    }

    /// Commit the validator-set transition state (C8): pending key
    /// changes, pending adds/removes, live BLS keys, jails, and the
    /// pending jail/unjail queues — everything the next epoch
    /// rotation will act on.
    pub(crate) fn commit_set_state(&self, w: &mut framework::CanonicalState) {
        let pending_keys = framework::lock_state(&self.pending_key_changes);
        w.put_count(pending_keys.len());
        for (a, k) in pending_keys.iter() {
            w.put_addr(a).put_bytes(k.as_bytes());
        }
        let adds = framework::lock_state(&self.pending_validator_adds);
        w.put_count(adds.len());
        for (a, k) in adds.iter() {
            w.put_addr(a).put_bytes(k.as_bytes());
        }
        let removes = framework::lock_state(&self.pending_validator_removes);
        w.put_count(removes.len());
        for a in removes.iter() {
            w.put_addr(a);
        }
        let keys = framework::lock_state(&self.bls_keys);
        w.put_count(keys.len());
        for (a, k) in keys.iter() {
            w.put_addr(a).put_bytes(k.as_bytes());
        }
        let jailed = framework::lock_state(&self.jailed);
        w.put_count(jailed.len());
        for (a, h) in jailed.iter() {
            w.put_addr(a).put_u64(*h);
        }
        let pending_jails = framework::lock_state(&self.pending_jails);
        w.put_count(pending_jails.len());
        for a in pending_jails.iter() {
            w.put_addr(a);
        }
        let pending_unjails = framework::lock_state(&self.pending_unjails);
        w.put_count(pending_unjails.len());
        for a in pending_unjails.iter() {
            w.put_addr(a);
        }
        // C9: pending governance endorsements — an action that has
        // accumulated votes but not yet reached quorum is
        // future-affecting state: two replicas must diverge if one
        // has recorded an endorsement the other has not.
        self.endorsements.write_canonical(w);
    }

    /// Commit consensus-adjacent state (C8): the scheduled halt,
    /// seen-evidence replay set, per-validator attendance rings,
    /// and the current height marker.
    pub(crate) fn commit_consensus_state(&self, w: &mut framework::CanonicalState) {
        match *framework::lock_state(&self.scheduled_halt) {
            Some(h) => {
                w.put_u8(1).put_u64(h);
            }
            None => {
                w.put_u8(0);
            }
        }
        {
            let seen = framework::lock_state(&self.seen_evidence);
            w.put_count(seen.len());
            for h in seen.iter() {
                w.put_root(h);
            }
            let attendance = framework::lock_state(&self.attendance);
            w.put_count(attendance.len());
            for (a, ring) in attendance.iter() {
                w.put_addr(a).put_count(ring.len());
                for present in ring {
                    w.put_bool(*present);
                }
            }
        }
        w.put_u64(*framework::lock_state(&self.current_height));
        // ── Trailing section (v2): retired consensus keys ──
        // Evidence verification consults the retired set for
        // proofs spanning a key rotation — committed because two
        // replicas disagreeing on it disagree on whether a proof
        // verifies. Appended last so pre-upgrade blobs decode
        // with the empty-history default.
        {
            let retired = framework::lock_state(&self.retired_bls_keys);
            w.put_count(retired.len());
            for (a, keys) in retired.iter() {
                w.put_addr(a).put_count(keys.len());
                for k in keys {
                    w.put_bytes(k.as_bytes());
                }
            }
        }
    }

    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    pub(crate) fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        self.commit_stake_state(w);
        self.commit_reward_state(w);
        self.commit_set_state(w);
        self.commit_consensus_state(w);
    }
}
