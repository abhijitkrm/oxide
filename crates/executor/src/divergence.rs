//! Execution divergence detection (plan.md §13, Phase 2).
//!
//! ## What this module is
//!
//! Detects corrupt executors by comparing the state roots they produce
//! after executing the same block. If a validator's state root differs
//! from the majority, it's flagged as divergent — the network detects
//! the mismatch via execution-certificate comparison (plan.md §13:
//! "divergence detection: corrupt one executor → network detects via
//! exec-cert mismatch").
//!
//! ## Why this matters
//!
//! In Oxide's architecture (plan.md §8), the execution lane runs
//! asynchronously: each validator executes block *h−1* while consensus
//! processes *h*. After execution, each validator signs a state root
//! (execution certificate) and embeds it in the next proposal. If a
//! validator's executor is corrupt (bug, malicious code, hardware
//! fault), its state root will differ from the honest majority. The
//! network detects this mismatch and can slash/sync the divergent
//! validator.
//!
//! ## The algorithm
//!
//! 1. **Collect**: gather state attestations from all validators for
//!    a given block height.
//! 2. **Compare**: find the majority state root (the root signed by
//!    ≥2f+1 validators, where f is the Byzantine fault tolerance
//!    threshold).
//! 3. **Detect**: any validator whose state root differs from the
//!    majority is flagged as divergent.
//! 4. **Report**: return a `DivergenceReport` with the majority root,
//!    the divergent validators, and their incorrect roots.

use std::collections::BTreeMap;

use primitives::{Address, Hash, Height};
use types::StateAttestation;

/// A validator's state attestation for a given block height.
///
/// Contains the validator's address and the state root they produced
/// after executing the block. This is the execution certificate that
/// gets compared across validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorAttestation {
    /// The validator's address.
    pub validator: Address,
    /// The state root the validator produced.
    pub attestation: StateAttestation,
}

/// The result of divergence detection for a single block height.
///
/// Contains the majority state root (if a quorum was reached), the
/// validators that agreed with the majority, and the validators that
/// diverged (with their incorrect roots).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceReport {
    /// The block height this report covers.
    pub height: Height,
    /// The majority state root (signed by ≥ quorum validators).
    /// `None` if no quorum was reached.
    pub majority_root: Option<Hash>,
    /// The validators that agreed with the majority root.
    pub agreeing: Vec<Address>,
    /// The validators that diverged (their root differs from the
    /// majority), with their incorrect roots.
    pub divergent: Vec<(Address, Hash)>,
}

impl DivergenceReport {
    /// Whether any divergent validators were detected.
    #[must_use]
    pub fn has_divergence(&self) -> bool {
        !self.divergent.is_empty()
    }

    /// The number of validators that agreed with the majority.
    #[must_use]
    pub fn agreement_count(&self) -> usize {
        self.agreeing.len()
    }

    /// The number of validators that diverged.
    #[must_use]
    pub fn divergence_count(&self) -> usize {
        self.divergent.len()
    }
}

/// Detect divergence in a set of validator attestations for a given
/// block height.
///
/// Given a list of validator attestations and a quorum threshold
/// (typically 2f+1 where f is the Byzantine fault tolerance threshold),
/// this function:
///
/// 1. Groups attestations by state root.
/// 2. Finds the root with the most votes.
/// 3. If that root has ≥ quorum votes, it's the majority root.
/// 4. Validators whose root differs from the majority are divergent.
///
/// # Arguments
///
/// - `attestations`: The validator attestations for a single block
///   height. All must be for the same height.
/// - `quorum`: The minimum number of votes needed for a majority
///   (typically 2f+1).
///
/// # Returns
///
/// A `DivergenceReport` with the majority root (if quorum was
/// reached), the agreeing validators, and the divergent validators.
///
/// # Panics
///
/// This function does not panic. If attestations is empty, the
/// report has no majority and no divergent validators.
#[must_use]
pub fn detect_divergence(attestations: &[ValidatorAttestation], quorum: usize) -> DivergenceReport {
    if attestations.is_empty() {
        return DivergenceReport {
            height: Height::new(0),
            majority_root: None,
            agreeing: Vec::new(),
            divergent: Vec::new(),
        };
    }

    let height = attestations[0].attestation.height;

    // Group validators by their state root.
    let mut root_groups: BTreeMap<Hash, Vec<Address>> = BTreeMap::new();
    for att in attestations {
        root_groups.entry(att.attestation.root).or_default().push(att.validator);
    }

    // Find the root with the most votes.
    let (majority_root, majority_validators) = root_groups
        .iter()
        .max_by_key(|(_, validators)| validators.len())
        .map_or((Hash::ZERO, Vec::new()), |(root, validators)| (*root, validators.clone()));

    // Check if the majority root reached quorum.
    let majority_reached = majority_validators.len() >= quorum;

    // Classify validators: agreeing vs divergent.
    let mut agreeing = Vec::new();
    let mut divergent = Vec::new();

    if majority_reached {
        // The majority root is established. Validators with a
        // different root are divergent.
        for att in attestations {
            if att.attestation.root == majority_root {
                agreeing.push(att.validator);
            } else {
                divergent.push((att.validator, att.attestation.root));
            }
        }
    } else {
        // No quorum reached. All validators with the most-common
        // root are "agreeing" (tentatively); others are divergent.
        for att in attestations {
            if att.attestation.root == majority_root {
                agreeing.push(att.validator);
            } else {
                divergent.push((att.validator, att.attestation.root));
            }
        }
    }

    DivergenceReport {
        height,
        majority_root: if majority_reached { Some(majority_root) } else { None },
        agreeing,
        divergent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(validator: u8, height: u64, root_byte: u8) -> ValidatorAttestation {
        ValidatorAttestation {
            validator: Address([validator; 20]),
            attestation: StateAttestation {
                height: Height::new(height),
                root: Hash([root_byte; 32]),
            },
        }
    }

    #[test]
    fn empty_attestations_no_divergence() {
        let report = detect_divergence(&[], 1);
        assert!(!report.has_divergence());
        assert_eq!(report.majority_root, None);
    }

    #[test]
    fn all_agree_no_divergence() {
        let attestations = vec![
            make_attestation(1, 0, 0x42),
            make_attestation(2, 0, 0x42),
            make_attestation(3, 0, 0x42),
        ];
        let report = detect_divergence(&attestations, 2);
        assert!(!report.has_divergence());
        assert_eq!(report.agreement_count(), 3);
        assert_eq!(report.divergence_count(), 0);
        assert_eq!(report.majority_root, Some(Hash([0x42; 32])));
    }

    #[test]
    fn one_divergent_validator_detected() {
        // 4 validators: 3 agree, 1 diverges.
        let attestations = vec![
            make_attestation(1, 0, 0x42),
            make_attestation(2, 0, 0x42),
            make_attestation(3, 0, 0x42),
            make_attestation(4, 0, 0x99), // divergent
        ];
        let report = detect_divergence(&attestations, 3);
        assert!(report.has_divergence());
        assert_eq!(report.agreement_count(), 3);
        assert_eq!(report.divergence_count(), 1);
        assert_eq!(report.majority_root, Some(Hash([0x42; 32])));
        // The divergent validator is #4 with root 0x99.
        assert_eq!(report.divergent[0].0, Address([4; 20]));
        assert_eq!(report.divergent[0].1, Hash([0x99; 32]));
    }

    #[test]
    fn multiple_divergent_validators_detected() {
        // 5 validators: 3 agree, 2 diverge (with different roots).
        let attestations = vec![
            make_attestation(1, 0, 0x42),
            make_attestation(2, 0, 0x42),
            make_attestation(3, 0, 0x42),
            make_attestation(4, 0, 0x99), // divergent
            make_attestation(5, 0, 0xAA), // divergent
        ];
        let report = detect_divergence(&attestations, 3);
        assert!(report.has_divergence());
        assert_eq!(report.agreement_count(), 3);
        assert_eq!(report.divergence_count(), 2);
    }

    #[test]
    fn no_quorum_no_majority() {
        // 3 validators with 3 different roots — no quorum.
        let attestations = vec![
            make_attestation(1, 0, 0x42),
            make_attestation(2, 0, 0x99),
            make_attestation(3, 0, 0xAA),
        ];
        let report = detect_divergence(&attestations, 2);
        // No quorum reached.
        assert_eq!(report.majority_root, None);
        // The most-common root (first one found) has 1 vote.
        assert_eq!(report.agreement_count(), 1);
        assert_eq!(report.divergence_count(), 2);
    }

    #[test]
    fn quorum_exactly_2f_plus_1() {
        // 4 validators, quorum = 3 (2f+1 with f=1).
        // 3 agree, 1 diverges.
        let attestations = vec![
            make_attestation(1, 0, 0x42),
            make_attestation(2, 0, 0x42),
            make_attestation(3, 0, 0x42),
            make_attestation(4, 0, 0x99),
        ];
        let report = detect_divergence(&attestations, 3);
        assert_eq!(report.majority_root, Some(Hash([0x42; 32])));
        assert!(report.has_divergence());
    }

    #[test]
    fn quorum_not_reached_no_majority() {
        // 4 validators, quorum = 3, but only 2 agree.
        let attestations = vec![
            make_attestation(1, 0, 0x42),
            make_attestation(2, 0, 0x42),
            make_attestation(3, 0, 0x99),
            make_attestation(4, 0, 0xAA),
        ];
        let report = detect_divergence(&attestations, 3);
        // No quorum (2 < 3).
        assert_eq!(report.majority_root, None);
    }

    #[test]
    fn report_height_matches_attestation_height() {
        let attestations = vec![make_attestation(1, 42, 0x42), make_attestation(2, 42, 0x42)];
        let report = detect_divergence(&attestations, 2);
        assert_eq!(report.height, Height::new(42));
    }

    #[test]
    fn corrupt_executor_scenario() {
        // Simulate the plan.md §13 acceptance gate scenario:
        // "corrupt one executor → network detects via exec-cert
        // mismatch".
        //
        // 4 validators (f=1, quorum=3). Validator 4 has a corrupt
        // executor that produces a wrong state root.
        let correct_root = Hash([0xAB; 32]);
        let corrupt_root = Hash([0xCD; 32]);

        let attestations = vec![
            ValidatorAttestation {
                validator: Address([1; 20]),
                attestation: StateAttestation { height: Height::new(10), root: correct_root },
            },
            ValidatorAttestation {
                validator: Address([2; 20]),
                attestation: StateAttestation { height: Height::new(10), root: correct_root },
            },
            ValidatorAttestation {
                validator: Address([3; 20]),
                attestation: StateAttestation { height: Height::new(10), root: correct_root },
            },
            ValidatorAttestation {
                validator: Address([4; 20]), // corrupt executor
                attestation: StateAttestation { height: Height::new(10), root: corrupt_root },
            },
        ];

        let report = detect_divergence(&attestations, 3);

        // The network detects the corrupt executor.
        assert!(report.has_divergence(), "network must detect the corrupt executor");
        assert_eq!(report.majority_root, Some(correct_root));
        assert_eq!(report.divergence_count(), 1, "exactly 1 divergent validator");
        assert_eq!(report.divergent[0].0, Address([4; 20]), "validator 4 is divergent");
        assert_eq!(report.divergent[0].1, corrupt_root, "validator 4's root is the corrupt root");
    }
}
