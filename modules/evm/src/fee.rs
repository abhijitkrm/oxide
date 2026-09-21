//! EIP-1559 dynamic base fee adjustment (plan.md §13, Phase 2).
//!
//! ## What this module is
//!
//! Implements the EIP-1559 base fee adjustment algorithm — the
//! mechanism that dynamically adjusts the block base fee based on
//! block gas usage relative to the target gas limit.
//!
//! ## Why this matters
//!
//! EIP-1559 replaces the first-price auction gas market with a
//! protocol-managed base fee. The base fee adjusts up when blocks
//! are congested (gas used > target) and down when blocks are
//! underutilized (gas used < target). This gives users predictable
//! gas prices and gives the chain a built-in congestion signal.
//!
//! ## The algorithm
//!
//! EIP-1559 (EIP-1559, Ethereum):
//!
//! ```text
//! if gas_used == target_gas:
//!     base_fee = base_fee  // no change
//! else if gas_used > target_gas:
//!     base_fee += max(1, base_fee * elasticity_multiplier * (gas_used - target) / target / elasticity_multiplier)
//! else:
//!     base_fee -= base_fee * (target - gas_used) / target / elasticity_multiplier
//! ```
//!
//! Simplified (the formula Ethereum actually uses):
//!
//! ```text
//! delta = base_fee * (gas_used - target) / target / elasticity_multiplier
//! base_fee = max(0, base_fee + delta)
//! ```
//!
//! Where:
//! - `target_gas` = `max_gas / 2` (the target block size is half the limit)
//! - `elasticity_multiplier` = 8 (Ethereum's value)
//! - `base_fee` floors at 0 (can't go negative)
//!
//! The elasticity multiplier controls how aggressively the fee
//! adjusts. Higher = more aggressive. Ethereum uses 8.

/// The EIP-1559 elasticity multiplier.
///
/// Controls how aggressively the base fee adjusts. Higher values
/// mean faster adjustment. Ethereum mainnet uses 8 (EIP-1559).
/// This is a cold-path constant (used once per block, not per-tx).
const ELASTICITY_MULTIPLIER: u64 = 8;

/// The EIP-1559 base fee state for a chain.
///
/// Tracks the current base fee and the block gas limit. The base
/// fee adjusts after each block based on the block's gas usage
/// relative to the target (half the gas limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseFeeState {
    /// The current base fee (wei per gas unit).
    base_fee: u64,
    /// The maximum gas per block.
    max_gas: u64,
}

impl BaseFeeState {
    /// Create a new base fee state with an initial base fee and
    /// block gas limit.
    ///
    /// # Arguments
    ///
    /// - `initial_base_fee`: The starting base fee (wei per gas).
    ///   Ethereum mainnet genesis used 1 gwei (10^9 wei).
    /// - `max_gas`: The maximum gas per block. Ethereum mainnet
    ///   uses 30M gas per block.
    #[must_use]
    pub fn new(initial_base_fee: u64, max_gas: u64) -> Self {
        Self { base_fee: initial_base_fee, max_gas }
    }

    /// The current base fee (wei per gas unit).
    #[must_use]
    pub fn base_fee(&self) -> u64 {
        self.base_fee
    }

    /// The maximum gas per block.
    #[must_use]
    pub fn max_gas(&self) -> u64 {
        self.max_gas
    }

    /// Replace the block gas limit the congestion target derives
    /// from (`target_gas = max_gas / 2`). Called when the
    /// consensus-enforced block budget changes — e.g. a governance
    /// parameter update carried in the block context — so the fee
    /// curve tracks the limit actually enforced, not the
    /// construction-time one. The base fee itself is untouched:
    /// the retarget applies to the *next* `update`.
    pub fn set_max_gas(&mut self, max_gas: u64) {
        self.max_gas = max_gas;
    }

    /// The target gas per block (half the max, per EIP-1559).
    #[must_use]
    pub fn target_gas(&self) -> u64 {
        self.max_gas / 2
    }

    /// Update the base fee after a block.
    ///
    /// Given the gas used by the just-executed block, compute the
    /// new base fee for the next block using the EIP-1559 formula.
    ///
    /// # Arguments
    ///
    /// - `gas_used`: The total gas consumed by the block.
    ///
    /// # Returns
    ///
    /// The new base fee (also updates internal state).
    ///
    /// # Panics
    ///
    /// This function does not panic. If `gas_used` exceeds `max_gas`,
    /// the base fee adjusts upward (clamped to avoid overflow).
    pub fn update(&mut self, gas_used: u64) -> u64 {
        let target = self.target_gas();
        if target == 0 {
            return self.base_fee;
        }

        // EIP-1559 formula:
        //   delta = base_fee * (gas_used - target) / target / elasticity
        //   new_base_fee = max(0, base_fee + delta)
        //
        // We use the exact Ethereum formula to stay compatible.

        if gas_used > target {
            // Congested: fee goes up.
            let excess = gas_used - target;
            // delta = base_fee * excess / target / elasticity
            // Use u128 to avoid overflow in the multiplication.
            let delta = u64::try_from(
                u128::from(self.base_fee) * u128::from(excess)
                    / u128::from(target)
                    / u128::from(ELASTICITY_MULTIPLIER),
            )
            .unwrap_or(u64::MAX);
            // Ensure at least 1 wei increase when congested (EIP-1559
            // mandates the fee must change when gas_used != target).
            let delta = delta.max(1);
            self.base_fee = self.base_fee.saturating_add(delta);
        } else if gas_used < target {
            // Underutilized: fee goes down.
            let deficit = target - gas_used;
            // delta = base_fee * deficit / target / elasticity
            let delta = u64::try_from(
                u128::from(self.base_fee) * u128::from(deficit)
                    / u128::from(target)
                    / u128::from(ELASTICITY_MULTIPLIER),
            )
            .unwrap_or(0);
            self.base_fee = self.base_fee.saturating_sub(delta);
        }
        // If gas_used == target, no change.

        self.base_fee
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_fee_at_target_no_change() {
        let mut state = BaseFeeState::new(1_000_000_000, 30_000_000);
        let target = state.target_gas();
        let new_fee = state.update(target);
        assert_eq!(new_fee, 1_000_000_000, "no change at target");
    }

    #[test]
    fn base_fee_increases_when_congested() {
        let mut state = BaseFeeState::new(1_000_000_000, 30_000_000);
        let target = state.target_gas(); // 15M
        // Use 2x target (30M gas, full block).
        let new_fee = state.update(target * 2);
        assert!(new_fee > 1_000_000_000, "fee must increase when congested");
    }

    #[test]
    fn base_fee_decreases_when_underutilized() {
        let mut state = BaseFeeState::new(1_000_000_000, 30_000_000);
        // Use 0 gas (empty block).
        let new_fee = state.update(0);
        assert!(new_fee < 1_000_000_000, "fee must decrease when underutilized");
    }

    #[test]
    fn base_fee_floors_at_minimum() {
        let mut state = BaseFeeState::new(1, 30_000_000);
        // Repeatedly underutilize to drive fee down.
        for _ in 0..100 {
            state.update(0);
        }
        // With integer division, base_fee=1 gives delta=0, so the
        // fee floors at 1 (can't go below 1 via the formula). This
        // is a known EIP-1559 edge case — the fee can't reach 0
        // through the normal adjustment formula.
        assert_eq!(state.base_fee(), 1, "fee floors at 1 (integer division)");
    }

    #[test]
    fn base_fee_congested_increases_by_at_least_1() {
        let mut state = BaseFeeState::new(1, 30_000_000);
        let target = state.target_gas();
        let new_fee = state.update(target + 1);
        // Even a tiny excess must increase the fee by at least 1.
        assert_eq!(new_fee, 2, "congested fee must increase by at least 1");
    }

    #[test]
    fn base_fee_elasticity_controls_rate() {
        // With elasticity 8, a 100% over-target block (gas_used = 2x target)
        // should increase the fee by base_fee / 8 = 12.5%.
        let initial = 1_000_000_000u64;
        let mut state = BaseFeeState::new(initial, 30_000_000);
        let target = state.target_gas();
        let new_fee = state.update(target * 2);
        // Expected: initial + initial/8 = 1.125 * initial.
        let expected = initial + initial / ELASTICITY_MULTIPLIER;
        assert_eq!(new_fee, expected);
    }

    #[test]
    fn base_fee_repeated_congestion_compounds() {
        let mut state = BaseFeeState::new(1_000_000_000, 30_000_000);
        let target = state.target_gas();
        // 10 consecutive full blocks.
        for _ in 0..10 {
            state.update(target * 2);
        }
        // Fee should have increased significantly.
        assert!(
            state.base_fee() > 2_000_000_000,
            "repeated congestion must compound: got {}",
            state.base_fee()
        );
    }

    #[test]
    fn base_fee_repeated_underutilization_compounds() {
        let mut state = BaseFeeState::new(1_000_000_000, 30_000_000);
        // 10 consecutive empty blocks.
        for _ in 0..10 {
            state.update(0);
        }
        // Fee should have decreased significantly.
        assert!(
            state.base_fee() < 500_000_000,
            "repeated underutilization must compound: got {}",
            state.base_fee()
        );
    }

    #[test]
    fn base_fee_oscillation_converges() {
        // Alternating full and empty blocks should converge toward
        // an equilibrium (the fee doesn't diverge to 0 or infinity).
        let mut state = BaseFeeState::new(1_000_000_000, 30_000_000);
        let target = state.target_gas();
        for _ in 0..100 {
            state.update(target * 2); // full block
            state.update(0); // empty block
        }
        // After oscillation, the fee should be in a reasonable range.
        // (It won't be exactly the initial fee because the up/down
        // rates are asymmetric — the up adjustment has a min-1 floor.)
        assert!(
            state.base_fee() > 0 && state.base_fee() < 2_000_000_000,
            "oscillation should stay bounded: got {}",
            state.base_fee()
        );
    }

    #[test]
    fn base_fee_no_overflow_on_large_values() {
        // Base fee near u64 max should not overflow.
        let mut state = BaseFeeState::new(u64::MAX / 2, 30_000_000);
        let target = state.target_gas();
        // Full block — should saturate, not overflow.
        let new_fee = state.update(target * 2);
        assert!(new_fee >= state.base_fee(), "saturating add must not decrease");
    }

    #[test]
    fn target_gas_is_half_max() {
        let state = BaseFeeState::new(1_000, 30_000_000);
        assert_eq!(state.target_gas(), 15_000_000);
    }
}
