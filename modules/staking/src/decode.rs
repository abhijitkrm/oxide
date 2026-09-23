//! Snapshot-decode machinery for the staking module.
//!
//! Split from `lib.rs` around the persistence invariant:
//! [`decode_committed`] is the single schema owner for the
//! canonical section — `inspect_state` (verify-only) and
//! `import_state` (install) share it so the two paths can never
//! disagree about the wire format. Beyond structural validity the
//! decoders enforce the *internal* invariants live code maintains
//! (store mirror, index/total mirrors, pending-action membership):
//! the blob's claimed root only proves the bytes hash correctly, so
//! a crafted blob with a matching root could otherwise install
//! state no honest execution produces.
//!
//! [`StagedStaking`] is the decoded form — installed by
//! `import_state` only after the executor verifies the claimed
//! root.

use std::collections::BTreeMap;

use primitives::{Address, Hash};

use crate::{EVIDENCE_KEY_HISTORY, UnbondingEntry};

/// Staged staking state — the decoded form of a snapshot blob's
/// canonical section, produced by [`StakingModule::decode_committed`]
/// and installed by `import_state` only after the executor has
/// verified the blob's claimed root.
///
/// The `ledger` handle is not part of it — assembly wiring reattached
/// by the node harness, not chain state.
#[derive(Default)]
pub(crate) struct StagedStaking {
    /// Validator stake: address → total bonded.
    pub(crate) validators: BTreeMap<Address, u64>,
    /// `(delegator, validator) → bonded amount`.
    pub(crate) delegations: BTreeMap<(Address, Address), u64>,
    /// FIFO unbonding queue.
    pub(crate) unbonding: Vec<UnbondingEntry>,
    /// Claimable rewards per delegator.
    pub(crate) pending_rewards: BTreeMap<Address, u64>,
    /// Lazy-accrual accumulator per validator.
    pub(crate) reward_per_token: BTreeMap<Address, u128>,
    /// Reward debt per `(delegator, validator)`.
    pub(crate) reward_debt: BTreeMap<(Address, Address), u128>,
    /// Self-share reward debt per validator.
    pub(crate) self_debt: BTreeMap<Address, u128>,
    /// Delegator → set of validators mirrored from `delegations`.
    pub(crate) delegator_index: BTreeMap<Address, std::collections::BTreeSet<Address>>,
    /// Total delegated into each validator.
    pub(crate) delegated_total: BTreeMap<Address, u64>,
    /// Pending consensus-key rotations.
    pub(crate) pending_key_changes: BTreeMap<Address, crypto::bls_signer::ValidatedPublicKey>,
    /// Endorsed validator admissions awaiting the epoch rotation.
    pub(crate) pending_validator_adds: Vec<(Address, crypto::bls_signer::ValidatedPublicKey)>,
    /// Endorsed removals awaiting the epoch rotation.
    pub(crate) pending_validator_removes: Vec<Address>,
    /// Pending governance endorsements (C9).
    pub(crate) endorsements: framework::Endorsements,
    /// Live BLS consensus keys — `ValidatedPublicKey` tokens: decode
    /// mints each through `from_bytes`, so the staged map itself is
    /// the proof that every key passed point + subgroup validation.
    pub(crate) bls_keys: BTreeMap<Address, crypto::bls_signer::ValidatedPublicKey>,
    /// Retired BLS consensus keys per validator (bounded history —
    /// [`EVIDENCE_KEY_HISTORY`]). Empty in pre-upgrade blobs.
    pub(crate) retired_bls_keys: BTreeMap<Address, Vec<crypto::bls_signer::ValidatedPublicKey>>,
    /// Jailed validators: address → height jailed.
    pub(crate) jailed: BTreeMap<Address, u64>,
    /// Jail events awaiting the next validator-set broadcast.
    pub(crate) pending_jails: Vec<Address>,
    /// Unjail events awaiting the next validator-set broadcast.
    pub(crate) pending_unjails: Vec<Address>,
    /// Governance-scheduled halt height.
    pub(crate) scheduled_halt: Option<u64>,
    /// Evidence hashes already acted on (replay guard).
    pub(crate) seen_evidence: std::collections::BTreeSet<Hash>,
    /// Per-validator attendance rings for downtime tracking.
    pub(crate) attendance: BTreeMap<Address, std::collections::VecDeque<bool>>,
    /// Last processed block height.
    pub(crate) current_height: u64,
}

/// Decode the canonical fields following the leading store root —
/// shared by `inspect_state` and `import_state` so verification
/// and installation can never disagree about the schema. Field
/// order mirrors `commit_stake_state` → `commit_consensus_state`
/// exactly.
///
/// Beyond structural validity this enforces the *internal*
/// invariants every live code path maintains (store mirror,
/// index/total mirrors, pending-action membership). Those matter
/// because the root check alone only proves the blob hashes to
/// the claimed root — a crafted blob with a matching claimed root
/// could otherwise install state no honest execution could
/// produce.
pub(crate) fn decode_committed(
    r: &mut framework::CanonicalReader<'_>,
    store: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Option<StagedStaking> {
    let mut staged = StagedStaking::default();
    decode_stake_state(r, &mut staged)?;
    decode_reward_state(r, &mut staged)?;
    decode_set_state(r, &mut staged)?;
    decode_consensus_state(r, &mut staged)?;
    check_replica_mirrors(&staged)?;
    check_store_binding(&staged, store)?;
    Some(staged)
}

/// Decode `validators`, `delegations`, and the `unbonding` queue —
/// the mirror of [`Self::commit_stake_state`].
pub(crate) fn decode_stake_state(
    r: &mut framework::CanonicalReader<'_>,
    out: &mut StagedStaking,
) -> Option<()> {
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        let stake = r.get_u64()?;
        if out.validators.insert(a, stake).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let d = r.get_addr()?;
        let v = r.get_addr()?;
        let amt = r.get_u64()?;
        // A delegation can only target a registered validator —
        // `delegate` requires membership and validator removal
        // drains every delegation into the unbonding queue.
        if !out.validators.contains_key(&v) {
            return None;
        }
        if out.delegations.insert((d, v), amt).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    // Order-preserving: the queue is FIFO by completion height;
    // `n.min(remaining/56)` bounds the allocation to what the
    // bytes could actually encode (each entry costs 56 bytes).
    out.unbonding.reserve(n.min(r.remaining() / 56));
    for _ in 0..n {
        out.unbonding.push(UnbondingEntry {
            delegator: r.get_addr()?,
            validator: r.get_addr()?,
            amount: r.get_u64()?,
            completion_height: r.get_u64()?,
        });
    }
    Some(())
}

/// Decode the reward-accrual bookkeeping — the mirror of
/// [`Self::commit_reward_state`].
pub(crate) fn decode_reward_state(
    r: &mut framework::CanonicalReader<'_>,
    out: &mut StagedStaking,
) -> Option<()> {
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        if out.pending_rewards.insert(a, r.get_u64()?).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        if out.reward_per_token.insert(a, r.get_u128()?).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let d = r.get_addr()?;
        let v = r.get_addr()?;
        if out.reward_debt.insert((d, v), r.get_u128()?).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        if out.self_debt.insert(a, r.get_u128()?).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let d = r.get_addr()?;
        let vn = r.get_count()?;
        let mut set = std::collections::BTreeSet::new();
        for _ in 0..vn {
            if !set.insert(r.get_addr()?) {
                return None;
            }
        }
        if out.delegator_index.insert(d, set).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        if out.delegated_total.insert(a, r.get_u64()?).is_some() {
            return None;
        }
    }
    Some(())
}

/// Decode the validator-set transition state — the mirror of
/// [`Self::commit_set_state`]. Membership in `out.validators` is
/// enforced where the live paths require it.
pub(crate) fn decode_set_state(
    r: &mut framework::CanonicalReader<'_>,
    out: &mut StagedStaking,
) -> Option<()> {
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        // `handle_key_change` requires the validator to exist.
        if !out.validators.contains_key(&a) {
            return None;
        }
        // The pending key crosses to consensus verbatim — decode
        // must mint the same validated token admission produced,
        // or a crafted blob could smuggle a non-point key past the
        // epoch boundary.
        let key = crypto::bls_signer::ValidatedPublicKey::from_bytes(r.get_bytes()?).ok()?;
        if out.pending_key_changes.insert(a, key).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    out.pending_validator_adds.reserve(n.min(r.remaining() / 20));
    for _ in 0..n {
        let a = r.get_addr()?;
        let key = crypto::bls_signer::ValidatedPublicKey::from_bytes(r.get_bytes()?).ok()?;
        // `validate_add_action` seats the candidate in
        // `validators` (0 stake) and records its key in
        // `bls_keys` at quorum time — both must hold.
        if !out.validators.contains_key(&a) {
            return None;
        }
        out.pending_validator_adds.push((a, key));
    }
    let n = r.get_count()?;
    out.pending_validator_removes.reserve(n.min(r.remaining() / 20));
    for _ in 0..n {
        let a = r.get_addr()?;
        // Removal is only ever queued for a live member.
        if !out.validators.contains_key(&a) {
            return None;
        }
        out.pending_validator_removes.push(a);
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        // The token constructor enforces everything at once:
        // 48-byte length, curve-point decode, subgroup membership.
        // The PoP gate ran at admission, but a crafted or corrupted
        // snapshot blob must not lodge a point that can never
        // verify — that would wedge every QC the key maps to.
        let key = crypto::bls_signer::ValidatedPublicKey::from_bytes(r.get_bytes()?).ok()?;
        if out.bls_keys.insert(a, key).is_some() {
            return None;
        }
    }
    for (a, key) in &out.pending_validator_adds {
        match out.bls_keys.get(a) {
            Some(k) if k == key => {}
            _ => return None,
        }
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        if out.jailed.insert(a, r.get_u64()?).is_some() {
            return None;
        }
    }
    let n = r.get_count()?;
    out.pending_jails.reserve(n.min(r.remaining() / 20));
    for _ in 0..n {
        out.pending_jails.push(r.get_addr()?);
    }
    let n = r.get_count()?;
    out.pending_unjails.reserve(n.min(r.remaining() / 20));
    for _ in 0..n {
        out.pending_unjails.push(r.get_addr()?);
    }
    out.endorsements = framework::Endorsements::read_canonical(r)?;
    Some(())
}

/// Decode consensus-adjacent state — the mirror of
/// [`Self::commit_consensus_state`].
pub(crate) fn decode_consensus_state(
    r: &mut framework::CanonicalReader<'_>,
    out: &mut StagedStaking,
) -> Option<()> {
    out.scheduled_halt = match r.get_u8()? {
        0 => None,
        1 => Some(r.get_u64()?),
        _ => return None,
    };
    let n = r.get_count()?;
    for _ in 0..n {
        if !out.seen_evidence.insert(r.get_root()?) {
            return None;
        }
    }
    let n = r.get_count()?;
    for _ in 0..n {
        let a = r.get_addr()?;
        let ring_len = r.get_count()?;
        let mut ring = std::collections::VecDeque::with_capacity(ring_len.min(r.remaining()));
        for _ in 0..ring_len {
            ring.push_back(r.get_bool()?);
        }
        if out.attendance.insert(a, ring).is_some() {
            return None;
        }
    }
    out.current_height = r.get_u64()?;
    // ── Trailing section (v2), tolerant of pre-upgrade blobs ──
    // Absent = the blob predates key-history retention: the
    // retired set decodes empty and evidence verifies only
    // against the live key — exactly the pre-upgrade bound.
    if r.remaining() != 0 {
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            let kn = r.get_count()?;
            // Live code only writes non-empty lists bounded at
            // EVIDENCE_KEY_HISTORY — anything else is crafted.
            if kn == 0 || kn > EVIDENCE_KEY_HISTORY {
                return None;
            }
            let mut keys = Vec::with_capacity(kn);
            for _ in 0..kn {
                // Same re-validation as the live map — a retired
                // key must still verify historical evidence, so a
                // non-point blob entry is rejected rather than
                // lodged.
                keys.push(crypto::bls_signer::ValidatedPublicKey::from_bytes(r.get_bytes()?).ok()?);
            }
            if out.retired_bls_keys.insert(a, keys).is_some() {
                return None;
            }
        }
    }
    Some(())
}

/// Enforce the replicated-state mirrors: `delegator_index` and
/// `delegated_total` are maintained alongside `delegations` and
/// must agree exactly — drift corrupts reward/delegation walks.
pub(crate) fn check_replica_mirrors(staged: &StagedStaking) -> Option<()> {
    for (d, v) in staged.delegations.keys() {
        match staged.delegator_index.get(d) {
            Some(set) if set.contains(v) => {}
            _ => return None,
        }
    }
    for (d, set) in &staged.delegator_index {
        for v in set {
            if !staged.delegations.contains_key(&(*d, *v)) {
                return None;
            }
        }
    }
    // `delegated_total[v]` is the sum of all delegations into
    // `v` — maintained on every delegate/undelegate/slash and
    // never re-derived, so it must match exactly.
    let mut totals = BTreeMap::<Address, u128>::new();
    for ((_, v), amt) in &staged.delegations {
        let entry = totals.entry(*v).or_default();
        *entry = entry.saturating_add(u128::from(*amt));
    }
    for (v, expected) in &totals {
        if staged.delegated_total.get(v).copied().unwrap_or(0) != u64::try_from(*expected).ok()? {
            return None;
        }
    }
    for (v, total) in &staged.delegated_total {
        // Entries are removed with the validator; a total for an
        // unregistered address is dead state.
        if !staged.validators.contains_key(v) {
            return None;
        }
        if u128::from(*total) != *totals.get(v).unwrap_or(&0) {
            return None;
        }
    }
    Some(())
}

/// Enforce the KV-store mirror. The binding is intentionally
/// asymmetric: `genesis_register_validator` never mirrors a
/// validator's stake into the store, so a bare 20-byte store key
/// must resolve to a live validator with the same stake, but a
/// validator WITHOUT a store entry is legitimate (genesis-only,
/// never delegated). `del/` entries are mirrored in both
/// directions because every delegation mutation goes through
/// `store_delegation_state`.
pub(crate) fn check_store_binding(
    staged: &StagedStaking,
    store: &BTreeMap<Vec<u8>, Vec<u8>>,
) -> Option<()> {
    for ((d, v), amt) in &staged.delegations {
        let mut key = Vec::with_capacity(4 + 40);
        key.extend_from_slice(b"del/");
        key.extend_from_slice(&d.0);
        key.extend_from_slice(&v.0);
        match store.get(&key) {
            Some(val) if *val == amt.to_le_bytes() => {}
            _ => return None,
        }
    }
    for (key, val) in store {
        if let Some(rest) = key.strip_prefix(b"del/") {
            if rest.len() != 40 {
                return None;
            }
            let d = Address(rest[..20].try_into().ok()?);
            let v = Address(rest[20..].try_into().ok()?);
            match staged.delegations.get(&(d, v)) {
                Some(amt) if *val == amt.to_le_bytes() => {}
                _ => return None,
            }
        } else {
            if key.len() != Address::LEN {
                return None;
            }
            let v = Address(key.as_slice().try_into().ok()?);
            match staged.validators.get(&v) {
                Some(stake) if *val == stake.to_le_bytes() => {}
                _ => return None,
            }
        }
    }
    Some(())
}
