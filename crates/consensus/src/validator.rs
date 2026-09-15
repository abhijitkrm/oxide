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
//! With `n = 3f + 1` validators, the protocol tolerates `f` Byzantine
//! faults. A quorum is `2f + 1` (supermajority). These two constants
//! are derived from the validator set size, never stored separately.

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

    /// Maximum Byzantine faults tolerated (`f = (n - 1) / 3`).
    ///
    /// With `n = 3f + 1`, this is exactly `f`. The formula works for
    /// any `n >= 1`: for `n = 1` (single validator), `f = 0`.
    #[must_use]
    pub fn f(&self) -> usize {
        (self.n() - 1) / 3
    }

    /// Quorum size (`2f + 1`) — the supermajority needed for a QC or TC.
    #[must_use]
    pub fn quorum(&self) -> usize {
        2 * self.f() + 1
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

    #[test]
    fn fault_tolerance_and_quorum() {
        // n = 4 → f = 1, quorum = 3
        let vs = ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![1, 1, 1, 1])
            .expect("4 validators");
        assert_eq!(vs.n(), 4);
        assert_eq!(vs.f(), 1);
        assert_eq!(vs.quorum(), 3);

        // n = 7 → f = 2, quorum = 5
        let vs = ValidatorSet::new(
            vec![pk(1), pk(2), pk(3), pk(4), pk(5), pk(6), pk(7)],
            vec![1, 1, 1, 1, 1, 1, 1],
        )
        .expect("7 validators");
        assert_eq!(vs.f(), 2);
        assert_eq!(vs.quorum(), 5);

        // n = 1 → f = 0, quorum = 1 (single-validator devnet)
        let vs = ValidatorSet::new(vec![pk(1)], vec![1]).expect("1 validator");
        assert_eq!(vs.f(), 0);
        assert_eq!(vs.quorum(), 1);
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
