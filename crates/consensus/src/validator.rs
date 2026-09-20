//! Validator set + leader election (docs/oxidebft-spec.md §5).
//!
//! The validator set is fixed within an epoch and rotates across
//! epochs (stage 6). Within an epoch, the leader for view *v* is
//! determined by a deterministic, stake-weighted round-robin — no VRF,
//! no randomness in the hot path (determinism contract, oai-spec.md
//! §3 rule 3).
//!
//! # Fault tolerance
//!
//! The protocol tolerates up to `f = ⌊(n−1)/3⌋` Byzantine faults — the
//! most any `n`-validator committee can sustain while guaranteeing a
//! quorum of honest progress. A quorum is `n − f` (equivalently
//! `⌊2n/3⌋ + 1`, a strict two-thirds supermajority): two quorums
//! always intersect in at least `2(n−f) − n = n − 2f ≥ f + 1`
//! validators, so at least one honest signer sits in every QC
//! intersection. These constants are derived from the validator set
//! size, never stored separately.

use crypto::bls::{PublicKey, validator_address};
use primitives::{Address, View};

/// An index into the epoch's validator set. Used in the quorum
/// certificate's signer bitmap to identify which validators signed.
/// Re-exported from `crypto::bls` for convenience.
pub type ValidatorIndex = crypto::bls::ValidatorIndex;

/// The active validator set for an epoch.
///
/// Invariant: `validators.len() == stakes.len() ==
/// validator_addresses.len()` and the set is non-empty. The
/// constructor enforces this; the fields are private so callers
/// cannot break the invariant.
///
/// `validator_addresses[i]` is the staking identity of the validator
/// whose consensus key is `validators[i]`. The address is derived
/// from the key by default (`validator_address(pk)`); `with_addresses`
/// accepts explicit addresses for setups where the staking identity
/// is independent of the consensus key (e.g. a cold wallet). The
/// address survives key rotation — `apply_key_change` replaces the
/// key but preserves the address.
#[derive(Debug, Clone)]
pub struct ValidatorSet {
    /// Public keys, indexed by `ValidatorIndex`.
    validators: Vec<PublicKey>,
    /// Stake for each validator, in the smallest unit (plan.md §9:
    /// fixed-point u64). Used for stake-weighted leader election.
    stakes: Vec<u64>,
    /// Staking address for each validator, indexed by
    /// `ValidatorIndex`. Derived from `validators` by default;
    /// `with_addresses` accepts explicit values.
    validator_addresses: Vec<Address>,
    /// One full leader-rotation cycle, precomputed at construction by
    /// [`build_leader_schedule`]. `leader(v)` indexes it at
    /// `v mod len`, so leader selection is O(1) and needs no state.
    leader_schedule: Vec<ValidatorIndex>,
    /// Total stake across all validators.
    total_stake: u64,
}

/// Maximum number of views in one leader-rotation cycle.
///
/// Unit: views. Origin: bounds the precomputed schedule to
/// `MAX_LEADER_CYCLE × 2 B = 8 KiB` per validator set while keeping each
/// validator's share accurate to within one cycle slot (≤ 1/4096 ≈
/// 0.024%). Tradeoff: raising it sharpens stake proportionality for
/// very large committees; lowering it shortens the schedule but coarsens
/// rounding for low-stake validators.
const MAX_LEADER_CYCLE: u64 = 4096;

/// Build one full leader-rotation cycle: a stake-weighted round-robin
/// schedule that spreads each validator's turns evenly.
///
/// Why not `view % total_stake` (the previous rule): consecutive views
/// map to the same validator for as many views as its *raw* stake. Stake
/// is denominated in token units, so a validator holding `1_000_000`
/// units led a million consecutive views — a failed leader stayed
/// scheduled for a million timeouts, and the rotation's shape depended
/// on the unit stake happened to be denominated in. This schedule fixes
/// both: stake is normalized to small integer weights (scale-invariant)
/// and those weights are interleaved smoothly.
///
/// The interleave is smooth weighted round-robin (the nginx algorithm):
/// each step every validator's running counter advances by its weight,
/// the largest counter wins the slot, and the winner's counter is
/// reduced by the cycle total. Per-cycle shares are exact and
/// consecutive runs stay short; equal weights degrade to plain
/// round-robin (`[0, 1, 2, …]`).
fn build_leader_schedule(stakes: &[u64], total_stake: u64) -> Vec<ValidatorIndex> {
    let n = stakes.len();
    let n_u64 = u64::try_from(n).unwrap_or(u64::MAX);
    // Committee larger than the cycle budget: one slot each (plain
    // round-robin). Stake weighting is meaningless once every validator
    // would receive less than a single slot per cycle.
    if n == 0 || n_u64 > MAX_LEADER_CYCLE {
        return (0..n).map(|i| ValidatorIndex::try_from(i).unwrap_or(0)).collect();
    }
    // Normalize stake to integer weights whose *sum* fits the cycle.
    // `scale` derives from the total (not the maximum) because the sum,
    // not any single weight, is what the budget bounds. Every validator
    // keeps at least one slot: a weight of zero would silently drop it
    // from the rotation entirely.
    let scale = total_stake.div_ceil(MAX_LEADER_CYCLE).max(1);
    let weights: Vec<u64> = stakes.iter().map(|s| (s / scale).max(1)).collect();
    let cycle: u64 = weights.iter().sum();
    // `cycle ≤ MAX_LEADER_CYCLE` by construction, so this narrowing
    // cannot truncate on any supported target.
    let cap = usize::try_from(cycle).unwrap_or(4096);
    let mut counters = vec![0i128; n];
    let mut schedule = Vec::with_capacity(cap);
    for _ in 0..cycle {
        let mut best = 0usize;
        for (i, w) in weights.iter().enumerate() {
            counters[i] += i128::from(*w);
            if counters[i] > counters[best] {
                best = i;
            }
        }
        counters[best] -= i128::from(cycle);
        schedule.push(ValidatorIndex::try_from(best).unwrap_or(0));
    }
    schedule
}

impl ValidatorSet {
    /// Construct a validator set from public keys and stakes.
    ///
    /// The staking address for each validator is derived from their
    /// BLS public key via [`validator_address`] — the standard
    /// pattern (Ethereum derives addresses from public keys). Use
    /// [`with_addresses`] for setups where the staking identity is
    /// independent of the consensus key.
    ///
    /// # Errors
    /// Returns a typed error if the set is empty or the lengths
    /// mismatch — both are caller bugs, not environment faults.
    pub fn new(validators: Vec<PublicKey>, stakes: Vec<u64>) -> Result<Self, ValidatorSetError> {
        let addresses = validators.iter().map(validator_address).collect();
        Self::with_addresses(validators, stakes, addresses)
    }

    /// Construct a validator set with explicit staking addresses.
    ///
    /// `validator_addresses[i]` is the staking identity of the
    /// validator whose consensus key is `validators[i]`. The address
    /// is independent of the key — it survives key rotation.
    ///
    /// # Errors
    /// Same as [`ValidatorSet::new`], plus `AddressMismatch` if
    /// `validator_addresses.len() != validators.len()`.
    pub fn with_addresses(
        validators: Vec<PublicKey>,
        stakes: Vec<u64>,
        validator_addresses: Vec<Address>,
    ) -> Result<Self, ValidatorSetError> {
        if validators.is_empty() {
            return Err(ValidatorSetError::Empty);
        }
        if validators.len() != stakes.len() {
            return Err(ValidatorSetError::LengthMismatch {
                validators: validators.len(),
                stakes: stakes.len(),
            });
        }
        if validators.len() != validator_addresses.len() {
            return Err(ValidatorSetError::AddressMismatch {
                validators: validators.len(),
                addresses: validator_addresses.len(),
            });
        }
        if stakes.contains(&0) {
            return Err(ValidatorSetError::ZeroStake);
        }
        // Uniqueness: each consensus key and each staking address may
        // occupy exactly one slot. A duplicate key would let one
        // signer claim two bitmap positions (and two stakes) for a
        // single BLS identity; a duplicate address collides the
        // staking identity used for rewards, evidence, and
        // `index_of`. Validator sets are small (<~1000), so the
        // O(n²) scan is fine — this runs at construction/rotation,
        // never on the hot path.
        for (i, pk) in validators.iter().enumerate() {
            if validators[..i].contains(pk) {
                return Err(ValidatorSetError::DuplicateKey { index: i });
            }
        }
        for (i, addr) in validator_addresses.iter().enumerate() {
            if validator_addresses[..i].contains(addr) {
                return Err(ValidatorSetError::DuplicateAddress { index: i });
            }
        }
        let mut acc = 0u64;
        for &s in &stakes {
            acc = acc.checked_add(s).ok_or(ValidatorSetError::StakeOverflow)?;
        }
        let total_stake = acc;
        let leader_schedule = build_leader_schedule(&stakes, total_stake);
        Ok(Self { validators, stakes, validator_addresses, leader_schedule, total_stake })
    }

    /// The public keys in this set, indexed by `ValidatorIndex`.
    #[must_use]
    pub fn public_keys(&self) -> &[PublicKey] {
        &self.validators
    }

    /// The stakes in this set, indexed by `ValidatorIndex`.
    #[must_use]
    pub fn stakes(&self) -> &[u64] {
        &self.stakes
    }

    /// The staking addresses in this set, indexed by
    /// `ValidatorIndex`. Parallel to `public_keys` —
    /// `validator_addresses[i]` is the identity of the validator
    /// whose consensus key is `public_keys[i]`.
    #[must_use]
    pub fn validator_addresses(&self) -> &[Address] {
        &self.validator_addresses
    }

    /// Find the validator index for a staking address.
    ///
    /// Linear scan — validator sets are small (typically <100) and
    /// this is called at epoch boundary, not on the hot path.
    #[must_use]
    pub fn index_of(&self, addr: &Address) -> Option<ValidatorIndex> {
        self.validator_addresses.iter().position(|a| a == addr).and_then(|i| u16::try_from(i).ok())
    }

    /// Apply a key change: return a new `ValidatorSet` with the
    /// consensus key at `index` replaced by `new_key`.
    ///
    /// The validator's staking address is preserved — the key
    /// rotates, not the identity.
    ///
    /// # Errors
    /// Returns `OutOfBounds` if `index` is past the end.
    pub fn apply_key_change(
        &self,
        index: ValidatorIndex,
        new_key: PublicKey,
    ) -> Result<Self, ValidatorSetError> {
        let mut validators = self.validators.clone();
        *validators
            .get_mut(usize::from(index))
            .ok_or(ValidatorSetError::OutOfBounds { index, n: self.n() })? = new_key;
        Self::with_addresses(validators, self.stakes.clone(), self.validator_addresses.clone())
    }

    /// Add a validator: return a new `ValidatorSet` with `pk`,
    /// `stake`, and `address` appended.
    ///
    /// The new validator is added at the end of the set (index `n`).
    /// The validator set size grows by 1 — the quorum threshold and
    /// leader-election weights are recomputed.
    ///
    /// # Errors
    /// Returns `ZeroStake` if `stake == 0`, or any construction error
    /// from [`with_addresses`](Self::with_addresses).
    pub fn add_validator(
        &self,
        pk: PublicKey,
        stake: u64,
        address: Address,
    ) -> Result<Self, ValidatorSetError> {
        let mut validators = self.validators.clone();
        let mut stakes = self.stakes.clone();
        let mut addresses = self.validator_addresses.clone();
        validators.push(pk);
        stakes.push(stake);
        addresses.push(address);
        Self::with_addresses(validators, stakes, addresses)
    }

    /// Remove a validator: return a new `ValidatorSet` with the
    /// validator at `index` removed.
    ///
    /// The validator set size shrinks by 1 — the quorum threshold and
    /// leader-election weights are recomputed. All validators after
    /// `index` shift down by one index.
    ///
    /// # Errors
    /// Returns `OutOfBounds` if `index` is past the end, or `Empty`
    /// if this would remove the last validator (a chain must have
    /// at least one validator).
    pub fn remove_validator(&self, index: ValidatorIndex) -> Result<Self, ValidatorSetError> {
        let idx = usize::from(index);
        if idx >= self.n() {
            return Err(ValidatorSetError::OutOfBounds { index, n: self.n() });
        }
        if self.n() == 1 {
            return Err(ValidatorSetError::Empty);
        }
        let mut validators = self.validators.clone();
        let mut stakes = self.stakes.clone();
        let mut addresses = self.validator_addresses.clone();
        validators.remove(idx);
        stakes.remove(idx);
        addresses.remove(idx);
        Self::with_addresses(validators, stakes, addresses)
    }

    /// Number of validators (`n`).
    #[must_use]
    pub fn n(&self) -> usize {
        self.validators.len()
    }

    /// Maximum Byzantine faults tolerated (`f = ⌊(n − 1) / 3⌋`).
    ///
    /// This is the largest `f` for which `n ≥ 3f + 1` — the BFT
    /// bound. For `n = 3f + 1` it is exactly `f`; for larger
    /// committees it rounds *down*, so e.g. `n = 8` still tolerates
    /// only `f = 2` (the third spare validator adds liveness headroom,
    /// not fault tolerance). For `n = 1` (single validator), `f = 0`.
    #[must_use]
    pub fn f(&self) -> usize {
        (self.n() - 1) / 3
    }

    /// Quorum size (`n − f`, equivalently `⌊2n/3⌋ + 1`) — the strict
    /// two-thirds supermajority needed for a QC or TC.
    ///
    /// The threshold must satisfy two properties:
    ///
    /// - **Safety (honest intersection):** any two quorums intersect
    ///   in at least `2q − n ≥ f + 1` validators — more than every
    ///   possible Byzantine — so two conflicting certificates can
    ///   never both form. `n − f` gives `2(n−f) − n = n − 2f ≥ f + 1`
    ///   because `n ≥ 3f + 1`.
    /// - **Liveness:** the `n − f` honest validators alone can form
    ///   a quorum even with all `f` Byzantine offline.
    ///
    /// The earlier `2f + 1` formula satisfies both only for
    /// `n = 3f + 1`. At `n = 8` it yields 5, and two quorums of 5 can
    /// intersect in just 2 validators — possibly *all* Byzantine —
    /// which voids the safety argument for every non-`3f+1` committee.
    /// `n − f` is the standard `>2/3` rule and reduces to `2f + 1`
    /// exactly when `n = 3f + 1`.
    ///
    /// **Use [`quorum_stake`](Self::quorum_stake) for all certificate
    /// validation.** This count is only the quorum when every
    /// validator's stake is equal; under unequal stake the
    /// authoritative threshold is voting *power*, not signer count.
    /// `quorum()` remains for sizing hints and equal-stake tests.
    #[must_use]
    pub fn quorum(&self) -> usize {
        self.n() - self.f()
    }

    /// Voting-power quorum: strictly more than two-thirds of
    /// `total_stake` — `⌊2·total_stake/3⌋ + 1`.
    ///
    /// A QC, TC, or execution certificate is valid only when the
    /// *stake* behind its signers reaches this threshold
    /// (docs/oxidebft-spec.md §3: "a validator with 10% stake
    /// contributes 10% to the quorum, not 1/N"). Under equal stake
    /// this equals `quorum()` in stake units; under unequal stake it
    /// is the authoritative threshold — a count of low-stake signers
    /// must not form a certificate, and one large-stake signer may
    /// carry more weight than several small ones.
    ///
    /// The honest-intersection argument transfers directly: any two
    /// quorums hold a combined `> 4T/3` of the `T` total stake, so
    /// they share `> T/3` — strictly more than the `≤ T/3` of stake
    /// a Byzantine minority can hold (the committee builder enforces
    /// `f < n/3`, and stake shares define the same bound in power).
    ///
    /// Overflow-free: `T − ⌊T/3⌋` equals `⌊2T/3⌋` whenever
    /// `T ≢ 0 (mod 3)` and is one short when `T ≡ 0 (mod 3)`, so the
    /// `+ 1` is added exactly in the divisible case.
    #[must_use]
    pub fn quorum_stake(&self) -> u64 {
        let t = self.total_stake;
        t - t / 3 + u64::from(t % 3 == 0)
    }

    /// Voting power carried by `bitmap`: the sum of the stakes of the
    /// validators whose bits are set.
    ///
    /// Bits beyond the validator set contribute nothing — an
    /// out-of-range bit cannot inflate a certificate's apparent
    /// power (signature verification rejects such bitmaps anyway).
    /// Saturating add: total stake cannot exceed `u64::MAX`, but a
    /// corrupt bitmap must never panic or wrap.
    #[must_use]
    pub fn signer_stake(&self, bitmap: &[u8]) -> u64 {
        let mut power = 0u64;
        for (i, byte) in bitmap.iter().enumerate() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    let contribution = u16::try_from(i * 8 + bit)
                        .ok()
                        .and_then(|idx| self.stake(idx).ok())
                        .unwrap_or(0);
                    power = power.saturating_add(contribution);
                }
            }
        }
        power
    }

    /// Total stake across all validators.
    #[must_use]
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// The validator at `index`.
    ///
    /// # Errors
    /// Returns `OutOfBounds` if the index is past the end.
    pub fn validator(&self, index: ValidatorIndex) -> Result<&PublicKey, ValidatorSetError> {
        self.validators
            .get(usize::from(index))
            .ok_or(ValidatorSetError::OutOfBounds { index, n: self.n() })
    }

    /// Stake of the validator at `index`.
    ///
    /// # Errors
    /// Returns `OutOfBounds` if the index is past the end.
    pub fn stake(&self, index: ValidatorIndex) -> Result<u64, ValidatorSetError> {
        self.stakes
            .get(usize::from(index))
            .copied()
            .ok_or(ValidatorSetError::OutOfBounds { index, n: self.n() })
    }

    /// The leader for `view` — stake-weighted round-robin
    /// (docs/oxidebft-spec.md §5).
    ///
    /// Indexes the precomputed [`leader_schedule`](Self::leader_schedule)
    /// cycle at `view mod cycle_len`. This is a deterministic function
    /// of the view and the validator set — no VRF, no randomness, no
    /// mutable state (determinism contract, oai-spec.md §3 rule 3).
    ///
    /// For equal stakes (the common Phase 1 case) the schedule is plain
    /// round-robin: `view mod n`. For unequal stakes a high-stake
    /// validator leads proportionally more often, with its turns
    /// *interleaved* rather than clustered — a validator holding 90% of
    /// the stake leads 90% of views without ever leading more than a few
    /// consecutive ones. See [`build_leader_schedule`] for why the
    /// previous raw-stake modulo rule was a liveness hazard.
    ///
    /// # Panics
    /// Never; returns validator index 0 for the degenerate case.
    #[must_use]
    pub fn leader(&self, view: View) -> ValidatorIndex {
        if self.n() == 1 {
            return 0;
        }
        // Cycle length is ≥ 1 for any valid set (every validator keeps
        // at least one slot), so the modulo cannot divide by zero.
        let len = u64::try_from(self.leader_schedule.len()).unwrap_or(1).max(1);
        let idx = usize::try_from(view.value() % len).unwrap_or(0);
        self.leader_schedule.get(idx).copied().unwrap_or(0)
    }

    /// Number of views in one leader-rotation cycle (cold path: tests
    /// and diagnostics).
    #[must_use]
    pub fn leader_cycle_len(&self) -> usize {
        self.leader_schedule.len()
    }
}

/// Everything that can go wrong constructing a [`ValidatorSet`].
#[derive(Debug)]
pub enum ValidatorSetError {
    /// An empty validator set cannot form a quorum.
    Empty,
    /// The validators and stakes vectors have different lengths.
    LengthMismatch {
        /// Number of public keys.
        validators: usize,
        /// Number of stake values.
        stakes: usize,
    },
    /// The validators and addresses vectors have different lengths.
    AddressMismatch {
        /// Number of public keys.
        validators: usize,
        /// Number of addresses.
        addresses: usize,
    },
    /// A validator with zero stake cannot lead or vote.
    ZeroStake,
    /// The same consensus public key appears twice — one BLS
    /// identity cannot hold two bitmap slots (it would count its
    /// signatures and stake twice and break key-uniqueness).
    DuplicateKey {
        /// The second index at which the key appeared.
        index: usize,
    },
    /// The same staking address appears twice — one staking identity
    /// cannot hold two validator slots.
    DuplicateAddress {
        /// The second index at which the address appeared.
        index: usize,
    },
    /// Total stake exceeds `u64` — the set is too large.
    StakeOverflow,
    /// A validator index is past the end of the set.
    OutOfBounds {
        /// The offending index.
        index: ValidatorIndex,
        /// The set size.
        n: usize,
    },
}

impl std::fmt::Display for ValidatorSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Empty => write!(f, "validator set is empty"),
            Self::LengthMismatch { validators, stakes } => {
                write!(f, "validators len {validators} != stakes len {stakes}")
            }
            Self::AddressMismatch { validators, addresses } => {
                write!(f, "validators len {validators} != addresses len {addresses}")
            }
            Self::ZeroStake => write!(f, "a validator has zero stake"),
            Self::DuplicateKey { index } => {
                write!(f, "duplicate consensus key at index {index}")
            }
            Self::DuplicateAddress { index } => {
                write!(f, "duplicate staking address at index {index}")
            }
            Self::StakeOverflow => write!(f, "total stake overflows u64"),
            Self::OutOfBounds { index, n } => {
                write!(f, "validator index {index} out of bounds (n={n})")
            }
        }
    }
}

impl std::error::Error for ValidatorSetError {}

#[cfg(test)]
mod tests {
    //! Unit tests for the validator set: fault tolerance, quorum,
    //! and leader election determinism + stake weighting.

    use super::*;

    fn pk(byte: u8) -> PublicKey {
        PublicKey([byte; PublicKey::LEN])
    }

    /// Quorum threshold across committee sizes — including every
    /// residue class mod 3, because `n − f` only coincides with the
    /// old `2f + 1` for `n = 3f + 1`. Sizes `≡ 2` and `≡ 0 (mod 3)`
    /// were under-threshold before: at `n = 8` two quorums of 5 could
    /// intersect in just 2 validators (possibly all Byzantine), and at
    /// `n = 2`/`n = 3` a single signer counted as a quorum.
    #[test]
    fn fault_tolerance_and_quorum() {
        // (n, f, quorum) — quorum = n − f = ⌊2n/3⌋ + 1.
        for (n, f, q) in [
            (1usize, 0usize, 1usize),
            (2, 0, 2),
            (3, 0, 3),
            (4, 1, 3),
            (5, 1, 4),
            (6, 1, 5),
            (7, 2, 5),
            (8, 2, 6),
            (9, 2, 7),
            (10, 3, 7),
        ] {
            let vs = ValidatorSet::new(
                (0u8..u8::try_from(n).unwrap_or(u8::MAX)).map(pk).collect(),
                vec![1; n],
            )
            .expect("validator set");
            assert_eq!(vs.n(), n);
            assert_eq!(vs.f(), f, "f for n={n}");
            assert_eq!(vs.quorum(), q, "quorum for n={n}");
            // Honest-intersection invariant: two quorums must
            // intersect in strictly more than f validators.
            assert!(2 * q - n > f, "quorums at n={n} must intersect in >f validators");
            // Liveness: the honest majority alone can reach quorum.
            assert!(n - f >= q, "honest validators at n={n} must reach quorum");
        }
    }

    /// Voting-power quorum across total-stake values — every residue
    /// class mod 3, because `⌊2T/3⌋ + 1` rounds differently for each.
    /// With all-equal stakes the power quorum must equal `quorum()`
    /// in stake units (each validator contributes its own stake).
    #[test]
    fn quorum_stake_is_strict_supermajority() {
        // (per-validator stake, n, expected quorum_stake)
        for (s, n, expected) in [
            (1u64, 1usize, 1u64), // T=1:  ⌊2/3⌋+1  = 1
            (1, 2, 2),            // T=2:  ⌊4/3⌋+1  = 2
            (1, 3, 3),            // T=3:  ⌊6/3⌋+1  = 3
            (1, 4, 3),            // T=4:  ⌊8/3⌋+1  = 3
            (1, 8, 6),            // T=8:  ⌊16/3⌋+1 = 6
            (1, 9, 7),            // T=9:  ⌊18/3⌋+1 = 7
            (1, 10, 7),           // T=10: ⌊20/3⌋+1 = 7
            (7, 4, 19),           // T=28: ⌊56/3⌋+1 = 19
        ] {
            let vs = ValidatorSet::new(
                (0u8..u8::try_from(n).unwrap_or(u8::MAX)).map(pk).collect(),
                vec![s; n],
            )
            .expect("validator set");
            assert_eq!(
                vs.quorum_stake(),
                expected,
                "quorum_stake for stake={s}, n={n} (T={})",
                s * n as u64
            );
            // The invariant: strictly more than two-thirds of T.
            let t = u64::try_from(n).unwrap_or(u64::MAX) * s;
            assert!(3 * vs.quorum_stake() > 2 * t, "must exceed 2T/3");
            // Equal-stake equivalence: the power held by quorum()
            // validators must meet the power quorum. (Not equal in
            // general — ⌊2n/3⌋+1 signers × s can overshoot ⌊2ns/3⌋+1
            // by up to s−1; for s=1 they coincide exactly.)
            assert!(
                vs.quorum() as u64 * s >= vs.quorum_stake(),
                "a count quorum of equal-stake validators must reach the power quorum"
            );
            if s == 1 {
                assert_eq!(vs.quorum_stake(), vs.quorum() as u64, "unit stake: power == count");
            }
        }
    }

    /// `signer_stake` sums only in-range bitmap bits — the power a
    /// certificate actually carries under unequal stake. This is the
    /// scenario count-based quorum got wrong: n=4 with stakes
    /// [100, 1, 1, 1] — the three small validators meet the count
    /// quorum (3 ≥ ⌊2·4/3⌋+1 = 3) but hold <3% of the voting power
    /// and must not form a certificate.
    #[test]
    fn signer_stake_unequal_power() {
        let vs = ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![100, 1, 1, 1])
            .expect("validator set");
        // T = 103 → quorum_stake = ⌊206/3⌋+1 = 68+1 = 69.
        assert_eq!(vs.quorum_stake(), 69);

        // Three low-stake signers: count quorum met, power quorum not.
        let small = [0b0000_1110u8];
        assert_eq!(vs.signer_stake(&small), 3);
        assert!(vs.signer_stake(&small) < vs.quorum_stake());

        // The dominant signer alone exceeds the power quorum.
        let big = [0b0000_0001u8];
        assert_eq!(vs.signer_stake(&big), 100);
        assert!(vs.signer_stake(&big) >= vs.quorum_stake());

        // Bits beyond the validator set contribute nothing — a
        // corrupt bitmap cannot inflate apparent power.
        let corrupt = [0b1111_0000u8];
        assert_eq!(vs.signer_stake(&corrupt), 0);
    }

    /// C3: a consensus key may occupy exactly one bitmap slot. Two
    /// slots sharing one BLS identity would let a single signer claim
    /// two positions (and two stakes) in every certificate — silently
    /// inflating its voting power and breaking the `signer_stake`
    /// accounting that quorum now depends on.
    #[test]
    fn duplicate_consensus_key_rejected() {
        let addrs = vec![Address([1; 20]), Address([2; 20]), Address([3; 20])];
        let result = ValidatorSet::with_addresses(
            vec![pk(7), pk(8), pk(7)], // index 2 repeats index 0's key
            vec![1, 1, 1],
            addrs,
        );
        assert!(
            matches!(result, Err(ValidatorSetError::DuplicateKey { index: 2 })),
            "second occurrence of a key must be rejected at its index"
        );
    }

    /// C3: a staking address may occupy exactly one slot — it is the
    /// identity used by `index_of` for rewards, evidence, jailing,
    /// and key rotation; a collision would make those operations
    /// ambiguous.
    #[test]
    fn duplicate_staking_address_rejected() {
        let result = ValidatorSet::with_addresses(
            vec![pk(7), pk(8), pk(9)],
            vec![1, 1, 1],
            vec![Address([1; 20]), Address([2; 20]), Address([1; 20])],
        );
        assert!(
            matches!(result, Err(ValidatorSetError::DuplicateAddress { index: 2 })),
            "second occurrence of an address must be rejected at its index"
        );
    }

    /// Rotating a validator's key onto another member's key would
    /// create a duplicate in the post-rotation set — the rotation
    /// must fail rather than let one BLS identity hold two slots.
    /// `apply_key_change` routes through `with_addresses`, so the
    /// uniqueness check fires here for free.
    #[test]
    fn key_rotation_onto_existing_key_rejected() {
        let vs = ValidatorSet::with_addresses(
            vec![pk(1), pk(2), pk(3)],
            vec![1, 1, 1],
            vec![Address([1; 20]), Address([2; 20]), Address([3; 20])],
        )
        .expect("validator set");
        // Validator 0 tries to rotate onto validator 2's key.
        let result = vs.apply_key_change(0, pk(3));
        assert!(
            matches!(result, Err(ValidatorSetError::DuplicateKey { .. })),
            "rotation onto an existing key must be rejected"
        );
        // A genuinely fresh key still rotates fine.
        let rotated = vs.apply_key_change(0, pk(9)).expect("fresh key rotates");
        assert_eq!(*rotated.validator(0).expect("validator 0"), pk(9));
    }

    /// Admitting a validator whose key is already in the set would
    /// duplicate a BLS identity — same bitmap-slot forgery as the
    /// direct-duplicate case, reached through the add path.
    #[test]
    fn validator_add_with_existing_key_rejected() {
        let vs = ValidatorSet::with_addresses(
            vec![pk(1), pk(2)],
            vec![1, 1],
            vec![Address([1; 20]), Address([2; 20])],
        )
        .expect("validator set");
        // New address, but validator 1's key.
        let result = vs.add_validator(pk(2), 5, Address([9; 20]));
        assert!(
            matches!(result, Err(ValidatorSetError::DuplicateKey { .. })),
            "add carrying an existing key must be rejected"
        );
        // New key but an existing address collides the staking
        // identity.
        let result = vs.add_validator(pk(9), 5, Address([1; 20]));
        assert!(
            matches!(result, Err(ValidatorSetError::DuplicateAddress { .. })),
            "add carrying an existing address must be rejected"
        );
        // Fresh key + fresh address succeeds.
        let grown = vs.add_validator(pk(9), 5, Address([9; 20])).expect("fresh add");
        assert_eq!(grown.n(), 3);
    }

    #[test]
    fn leader_round_robin_equal_stakes() {
        // With equal stakes, leader selection is pure round-robin:
        // view 0 → validator 0, view 1 → validator 1, etc.
        let vs = ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![1, 1, 1, 1])
            .expect("4 validators");
        assert_eq!(vs.leader(View::new(0)), 0);
        assert_eq!(vs.leader(View::new(1)), 1);
        assert_eq!(vs.leader(View::new(2)), 2);
        assert_eq!(vs.leader(View::new(3)), 3);
        assert_eq!(vs.leader(View::new(4)), 0); // wraps
    }

    #[test]
    fn leader_is_deterministic() {
        // Same view + same set → same leader, always.
        let vs =
            ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4), pk(5)], vec![10, 20, 30, 40, 50])
                .expect("5 validators");
        for v in 0..100u64 {
            let l1 = vs.leader(View::new(v));
            let l2 = vs.leader(View::new(v));
            assert_eq!(l1, l2, "leader must be deterministic for view {v}");
        }
    }

    #[test]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn leader_high_stake_leads_more() {
        // A validator with 90% of the stake should lead ~90% of the
        // time over a large sample.
        let vs = ValidatorSet::new(vec![pk(1), pk(2)], vec![1, 9])
            .expect("2 validators, 1:9 stake ratio");
        let mut high_stake_count = 0u64;
        for v in 0..1000u64 {
            if vs.leader(View::new(v)) == 1 {
                high_stake_count += 1;
            }
        }
        // Should be roughly 90% ± 5%; with 1000 samples the variance
        // is small enough that this bound is safe.
        let ratio = high_stake_count as f64 / 1000.0;
        assert!(
            (0.85..=0.95).contains(&ratio),
            "high-stake validator should lead ~90%, got {ratio:.3}",
        );
    }

    /// The rotation must not cluster a validator's turns. Stake is
    /// denominated in token units, so the previous `view % total_stake`
    /// rule scheduled validator 0 for a full `stake`-long run of views
    /// — at stake `1_000_000`, a failed leader stayed scheduled for a
    /// million timeouts instead of being bypassed after one.
    #[test]
    fn leader_turns_are_interleaved_not_clustered() {
        let vs = ValidatorSet::new(
            vec![pk(1), pk(2), pk(3), pk(4)],
            vec![1_000_000, 1_000_000, 1_000_000, 1_000_000],
        )
        .expect("4 equal-stake validators");
        let mut max_run = 0u32;
        let mut run = 0u32;
        let mut prev = None;
        for v in 0..4096u64 {
            let l = vs.leader(View::new(v));
            if Some(l) == prev {
                run += 1;
            } else {
                run = 1;
                prev = Some(l);
            }
            max_run = max_run.max(run);
        }
        assert_eq!(max_run, 1, "equal stakes must stay pure round-robin");
    }

    /// Even under a lopsided split the dominant validator's turns stay
    /// interleaved: a run is bounded by roughly its weight ratio, never
    /// by its raw stake.
    #[test]
    fn leader_runs_stay_short_under_lopsided_stake() {
        let vs = ValidatorSet::new(vec![pk(1), pk(2)], vec![9_000_000, 1_000_000])
            .expect("9:1 stake split");
        let cycle = vs.leader_cycle_len() as u64;
        let mut max_run = 0u64;
        let mut run = 0u64;
        let mut prev = None;
        for v in 0..cycle * 2 {
            let l = vs.leader(View::new(v));
            if Some(l) == prev {
                run += 1;
            } else {
                run = 1;
                prev = Some(l);
            }
            max_run = max_run.max(run);
        }
        assert!(max_run <= 16, "dominant leader must not cluster: max run {max_run}");
    }

    /// Per-cycle leader shares track stake to within one cycle slot.
    #[test]
    fn leader_share_tracks_stake() {
        let vs =
            ValidatorSet::new(vec![pk(1), pk(2), pk(3)], vec![2_000_000, 3_000_000, 5_000_000])
                .expect("3 unequal validators");
        let cycle = vs.leader_cycle_len() as u64;
        let mut counts = [0u64; 3];
        for v in 0..cycle {
            counts[usize::from(vs.leader(View::new(v)))] += 1;
        }
        for (i, expected_pct) in [(0usize, 20u64), (1, 30), (2, 50)] {
            let pct = counts[i] * 100 / cycle;
            assert!(
                pct.abs_diff(expected_pct) <= 1,
                "validator {i}: expected ~{expected_pct}% of views, got {pct}%"
            );
        }
    }

    /// Every staked validator appears in the rotation. A normalized
    /// weight of zero would silently drop a validator from leadership
    /// entirely, which is a liveness fault for that validator.
    #[test]
    fn leader_schedule_includes_every_validator() {
        let vs = ValidatorSet::new(vec![pk(1), pk(2), pk(3)], vec![1_000_000, 1_000_000, 1])
            .expect("one tiny validator");
        let cycle = vs.leader_cycle_len() as u64;
        let mut seen = std::collections::BTreeSet::new();
        for v in 0..cycle {
            seen.insert(vs.leader(View::new(v)));
        }
        assert_eq!(seen.len(), 3, "a staked validator must appear in the rotation");
    }

    #[test]
    fn rejects_empty_set() {
        assert!(ValidatorSet::new(vec![], vec![]).is_err());
    }

    #[test]
    fn rejects_length_mismatch() {
        assert!(ValidatorSet::new(vec![pk(1), pk(2)], vec![1]).is_err());
    }

    #[test]
    fn rejects_zero_stake() {
        assert!(ValidatorSet::new(vec![pk(1), pk(2)], vec![1, 0]).is_err());
    }
}
