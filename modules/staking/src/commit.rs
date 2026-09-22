//! Write side of the staking snapshot codec.
//!
//! Split from `lib.rs` around the persistence invariant: the
//! `commit_*`/`write_committed` family owns the canonical write
//! schema — section order and field encoding — while `decode.rs`
//! owns the read side. Both sit in the same crate section so a
//! schema change touches one pair of files, never one side alone.

use super::StakingModule;
use crypto::bls_signer::ValidatedPublicKey;
use primitives::{Address, Hash};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Borrowed view over every committed field — built either from the
/// live module's locked state or from a staged snapshot decode, so
/// [`write_root_preimage`] defines the root schema exactly once for
/// both `state_root` and `inspect_state`.
///
/// Delegator-scale maps arrive as [`CommittedMap`]s: their fold
/// root is O(1), so the preimage is `put_root` per map rather than
/// a serialization of every record — the 7.4 fix. Validator-scale
/// maps and small state arrive as the same references
/// `write_committed` serializes.
pub(crate) struct RootView<'a> {
    /// The KV subtree's fold root (`CommittedStore::root` live,
    /// `CommittedMap::fold_map` on a staged `StoreMap`).
    pub store_fold: Hash,
    /// `validators` — validator-scale; serialized as in `write_committed`.
    pub validators: &'a BTreeMap<Address, u64>,
    /// `delegations`' fold root — delegator-scale; fold only.
    /// (`CommittedMap::root` live, `fold_map` staged.)
    pub delegations_fold: Hash,
    /// `unbonding` queue — serialized (queue length is bounded by
    /// in-flight unbondings, not total delegation history).
    pub unbonding: &'a Vec<super::UnbondingEntry>,
    /// `pending_rewards`' fold root — delegator-scale.
    pub pending_rewards_fold: Hash,
    /// `reward_per_token` — validator-scale; serialized.
    pub reward_per_token: &'a BTreeMap<Address, u128>,
    /// `reward_debt`' fold root — delegator-scale.
    pub reward_debt_fold: Hash,
    /// `self_debt` — validator-scale; serialized.
    pub self_debt: &'a BTreeMap<Address, u128>,
    /// `delegator_index`' fold root — delegator-scale.
    pub delegator_index_fold: Hash,
    /// `delegated_total`' fold root — validator-scale count but
    /// delegator-driven churn; folded so a slash/delegate costs O(1)
    /// root work.
    pub delegated_total_fold: Hash,
    /// Pending key changes — serialized.
    pub pending_key_changes: &'a BTreeMap<Address, ValidatedPublicKey>,
    /// Pending validator additions — serialized (commit order).
    pub pending_validator_adds: &'a Vec<(Address, ValidatedPublicKey)>,
    /// Pending validator removals — serialized.
    pub pending_validator_removes: &'a Vec<Address>,
    /// Governance endorsements — serialized via its own writer.
    pub endorsements: &'a framework::Endorsements,
    /// Live BLS keys — serialized.
    pub bls_keys: &'a BTreeMap<Address, ValidatedPublicKey>,
    /// Retired key history — serialized.
    pub retired_bls_keys: &'a BTreeMap<Address, Vec<ValidatedPublicKey>>,
    /// Jailed validators — serialized.
    pub jailed: &'a BTreeMap<Address, u64>,
    /// Pending jails — serialized.
    pub pending_jails: &'a Vec<Address>,
    /// Pending unjails — serialized.
    pub pending_unjails: &'a Vec<Address>,
    /// Scheduled halt — serialized.
    pub scheduled_halt: Option<u64>,
    /// Seen-evidence replay set — serialized.
    pub seen_evidence: &'a BTreeSet<Hash>,
    /// Attendance rings — serialized.
    pub attendance: &'a BTreeMap<Address, VecDeque<bool>>,
    /// Current height — serialized.
    pub current_height: u64,
}

/// The incremental `state_root` preimage (7.4): every committed
/// field appears exactly once, in the same section order
/// `write_committed` uses — but delegator-scale maps contribute
/// their maintained fold root (`put_root`) instead of a
/// serialization of every record, so the root costs O(validator-
/// scale state) per block rather than O(all delegation history).
///
/// This preimage is a NEW root format: `canon_root` of it differs
/// from `canon_root` of `write_committed`'s bytes for the same
/// state. The canonical stream remains the snapshot *install*
/// payload; the root is what `state_root`/`inspect_state` agree on.
/// KEEP IN SYNC with `write_committed`: a field added there must
/// land here in the same position (serialized) or as a fold
/// (delegator-scale) — a missed field is a silent root divergence.
pub(crate) fn write_root_preimage(v: &RootView<'_>, w: &mut framework::CanonicalState) {
    w.put_root(&v.store_fold);
    {
        w.put_count(v.validators.len());
        for (a, s) in v.validators {
            w.put_addr(a).put_u64(*s);
        }
        w.put_root(&v.delegations_fold);
        w.put_count(v.unbonding.len());
        for e in v.unbonding {
            w.put_addr(&e.delegator)
                .put_addr(&e.validator)
                .put_u64(e.amount)
                .put_u64(e.completion_height);
        }
    }
    {
        w.put_root(&v.pending_rewards_fold);
        w.put_count(v.reward_per_token.len());
        for (a, r) in v.reward_per_token {
            w.put_addr(a).put_u128(*r);
        }
        w.put_root(&v.reward_debt_fold);
        w.put_count(v.self_debt.len());
        for (a, r) in v.self_debt {
            w.put_addr(a).put_u128(*r);
        }
        w.put_root(&v.delegator_index_fold);
        w.put_root(&v.delegated_total_fold);
    }
    {
        w.put_count(v.pending_key_changes.len());
        for (a, k) in v.pending_key_changes {
            w.put_addr(a).put_bytes(k.as_bytes());
        }
        w.put_count(v.pending_validator_adds.len());
        for (a, k) in v.pending_validator_adds {
            w.put_addr(a).put_bytes(k.as_bytes());
        }
        w.put_count(v.pending_validator_removes.len());
        for a in v.pending_validator_removes {
            w.put_addr(a);
        }
        w.put_count(v.bls_keys.len());
        for (a, k) in v.bls_keys {
            w.put_addr(a).put_bytes(k.as_bytes());
        }
        w.put_count(v.jailed.len());
        for (a, h) in v.jailed {
            w.put_addr(a).put_u64(*h);
        }
        w.put_count(v.pending_jails.len());
        for a in v.pending_jails {
            w.put_addr(a);
        }
        w.put_count(v.pending_unjails.len());
        for a in v.pending_unjails {
            w.put_addr(a);
        }
        v.endorsements.write_canonical(w);
    }
    {
        match v.scheduled_halt {
            Some(h) => {
                w.put_u8(1).put_u64(h);
            }
            None => {
                w.put_u8(0);
            }
        }
        w.put_count(v.seen_evidence.len());
        for h in v.seen_evidence {
            w.put_root(h);
        }
        w.put_count(v.attendance.len());
        for (a, ring) in v.attendance {
            w.put_addr(a).put_count(ring.len());
            for present in ring {
                w.put_bool(*present);
            }
        }
        w.put_u64(v.current_height);
        w.put_count(v.retired_bls_keys.len());
        for (a, keys) in v.retired_bls_keys {
            w.put_addr(a).put_count(keys.len());
            for k in keys {
                w.put_bytes(k.as_bytes());
            }
        }
    }
}

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
        w.put_root(&framework::subtree_root_map(framework::lock_state(&self.store).inner()));
        self.commit_stake_state(w);
        self.commit_reward_state(w);
        self.commit_set_state(w);
        self.commit_consensus_state(w);
    }
}
