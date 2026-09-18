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
    /// Cumulative stake for binary-search leader election. Computed
    /// once at construction; `leader(v)` is O(log n) thereafter.
    cumulative_stakes: Vec<u64>,
    /// Total stake across all validators.
    total_stake: u64,
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
        let mut cumulative_stakes = Vec::with_capacity(stakes.len());
        let mut acc = 0u64;
        for &s in &stakes {
            acc = acc.checked_add(s).ok_or(ValidatorSetError::StakeOverflow)?;
            cumulative_stakes.push(acc);
        }
        let total_stake = acc;
        Ok(Self { validators, stakes, validator_addresses, cumulative_stakes, total_stake })
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
    /// Maps the view to a point in `[0, total_stake)` via `view %
    /// total_stake`, then binary-searches the cumulative-stake array
    /// to find which validator owns that point. This is a
    /// deterministic function of the view and the validator set — no
    /// VRF, no randomness (determinism contract).
    ///
    /// For equal stakes (the common Phase 1 case), this reduces to
    /// `view mod n` — pure round-robin. For unequal stakes, a
    /// high-stake validator leads proportionally more often: a
    /// validator with 90% of the stake owns 90% of the points in
    /// `[0, total_stake)`, so it leads ~90% of views.
    ///
    /// # Panics
    /// Never; returns validator index 0 for the degenerate case.
    #[must_use]
    pub fn leader(&self, view: View) -> ValidatorIndex {
        if self.n() == 1 {
            return 0;
        }
        // Stake-weighted selection: pick a point in [0, total_stake)
        // deterministically from the view. `view % total_stake` cycles
        // through every point in the range, so each validator gets
        // selected proportionally to its stake.
        let point = view.value() % self.total_stake.max(1);
        // Binary search: find the first validator whose cumulative
        // stake exceeds `point`. This is O(log n).
        let idx = self.cumulative_stakes.partition_point(|&c| c <= point).min(self.n() - 1);
        u16::try_from(idx).unwrap_or(0)
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
