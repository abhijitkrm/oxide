//! Network models for deterministic simulation.
//!
//! # What this is
//!
//! Configurable network delay, loss, and reordering models that
//! sit between consensus nodes in the deterministic simulation.
//! These let us test consensus under realistic (and adversarial)
//! network conditions.
//!
//! # Why this exists
//!
//! The `MeshNetwork` in the `p2p` crate supports partition/heal, but
//! not delay, loss, or reordering. Real networks have all three.
//! The chaos sim suite needs these to test consensus liveness under
//! asynchrony and partial network degradation.
//!
//! # Models
//!
//! - [`DelayModel::None`]: no delay (instant delivery).
//! - [`DelayModel::Uniform`]: fixed delay for all messages.
//! - [`DelayModel::Gaussian`]: delay drawn from a normal distribution
//!   (deterministic via a seeded PRNG).
//! - [`LossModel::None`]: no message loss.
//! - [`LossModel::Random`]: drop messages with a fixed probability
//!   (deterministic via a seeded PRNG).
//! - [`LossModel::Partition`]: drop all messages to/from specific nodes.

use std::collections::HashSet;

/// A simple deterministic PRNG (xorshift64) for reproducible network
/// simulation. We don't use `rand` because:
/// 1. We want exact reproducibility across platforms.
/// 2. We want no dependencies in the sim crate's hot path.
/// 3. xorshift64 is sufficient for network modeling (not crypto).
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    /// Create a new PRNG with the given seed.
    ///
    /// # Panics
    ///
    /// Panics if the seed is zero (xorshift requires a non-zero state).
    #[must_use]
    pub fn new(seed: u64) -> Self {
        assert!(seed != 0, "PRNG seed must be non-zero");
        Self { state: seed }
    }

    /// Next random u64.
    #[must_use]
    pub fn next_u64(&mut self) -> u64 {
        // xorshift64: George Marsaglia's algorithm.
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Next random f64 in [0.0, 1.0).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn next_f64(&mut self) -> f64 {
        let bits = self.next_u64();
        // Use the upper 53 bits for a value in [0, 1).
        (bits >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// A network delay model.
#[derive(Debug, Clone)]
pub enum DelayModel {
    /// No delay — instant delivery.
    None,
    /// Fixed delay (in virtual milliseconds) for all messages.
    Uniform(u64),
    /// Gaussian delay with mean and std dev (in virtual ms).
    /// Uses a seeded PRNG for deterministic draws.
    Gaussian {
        /// Mean delay in ms.
        mean_ms: u64,
        /// Std dev in ms.
        std_dev_ms: u64,
        /// The PRNG for drawing delays.
        rng: DeterministicRng,
    },
}

impl DelayModel {
    /// Compute the delay for the next message.
    ///
    /// For `Gaussian`, draws a new value from the PRNG. For other
    /// models, returns the fixed value.
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn delay_ms(&mut self) -> u64 {
        match self {
            Self::None => 0,
            Self::Uniform(ms) => *ms,
            Self::Gaussian { mean_ms, std_dev_ms, rng } => {
                // Box-Muller transform for a normal distribution.
                let u1 = rng.next_f64().max(f64::MIN_POSITIVE);
                let u2 = rng.next_f64();
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                let delay = *mean_ms as f64 + z * *std_dev_ms as f64;
                delay.max(0.0) as u64
            }
        }
    }
}

/// A message loss model.
#[derive(Debug, Clone)]
pub enum LossModel {
    /// No loss — all messages delivered.
    None,
    /// Drop messages with probability `p` (0.0 = never, 1.0 = always).
    /// Uses a seeded PRNG for deterministic draws.
    Random {
        /// Drop probability in [0.0, 1.0].
        p: f64,
        /// The PRNG for drawing drop decisions.
        rng: DeterministicRng,
    },
    /// Drop all messages to/from specific partitioned nodes.
    Partition {
        /// The set of partitioned node indices.
        partitioned: HashSet<usize>,
    },
}

impl LossModel {
    /// Returns `true` if a message from `from` to `to` should be dropped.
    #[must_use]
    pub fn should_drop(&mut self, from: usize, to: usize) -> bool {
        match self {
            Self::None => false,
            Self::Random { p, rng } => rng.next_f64() < *p,
            Self::Partition { partitioned } => {
                partitioned.contains(&from) || partitioned.contains(&to)
            }
        }
    }

    /// Partition a node: messages to/from it are dropped.
    pub fn partition(&mut self, index: usize) {
        if let Self::Partition { partitioned } = self {
            partitioned.insert(index);
        }
    }

    /// Heal a partitioned node.
    pub fn heal(&mut self, index: usize) {
        if let Self::Partition { partitioned } = self {
            partitioned.remove(&index);
        }
    }
}

/// A combined network model: delay + loss applied to each message.
#[derive(Debug, Clone)]
pub struct NetworkModel {
    /// The delay model.
    pub delay: DelayModel,
    /// The loss model.
    pub loss: LossModel,
}

impl NetworkModel {
    /// Create a perfect network (no delay, no loss).
    #[must_use]
    pub fn perfect() -> Self {
        Self { delay: DelayModel::None, loss: LossModel::None }
    }

    /// Create a network with uniform delay and no loss.
    #[must_use]
    pub fn with_delay(delay_ms: u64) -> Self {
        Self { delay: DelayModel::Uniform(delay_ms), loss: LossModel::None }
    }

    /// Create a network with random message loss.
    #[must_use]
    pub fn with_loss(p: f64, seed: u64) -> Self {
        Self {
            delay: DelayModel::None,
            loss: LossModel::Random { p, rng: DeterministicRng::new(seed) },
        }
    }

    /// Process a message: returns `None` if the message is dropped,
    /// or `Some(delay_ms)` if it should be delivered after `delay_ms`.
    #[must_use]
    pub fn process(&mut self, from: usize, to: usize) -> Option<u64> {
        if self.loss.should_drop(from, to) {
            return None;
        }
        Some(self.delay.delay_ms())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_deterministic() {
        let mut rng1 = DeterministicRng::new(42);
        let mut rng2 = DeterministicRng::new(42);
        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn rng_non_zero_seed_panics() {
        let result = std::panic::catch_unwind(|| DeterministicRng::new(0));
        assert!(result.is_err());
    }

    #[test]
    fn rng_next_f64_in_range() {
        let mut rng = DeterministicRng::new(42);
        for _ in 0..1000 {
            let f = rng.next_f64();
            assert!((0.0..1.0).contains(&f));
        }
    }

    #[test]
    fn delay_none() {
        let mut model = DelayModel::None;
        assert_eq!(model.delay_ms(), 0);
    }

    #[test]
    fn delay_uniform() {
        let mut model = DelayModel::Uniform(50);
        assert_eq!(model.delay_ms(), 50);
    }

    #[test]
    fn delay_gaussian_deterministic() {
        let mut model1 =
            DelayModel::Gaussian { mean_ms: 100, std_dev_ms: 20, rng: DeterministicRng::new(42) };
        let mut model2 =
            DelayModel::Gaussian { mean_ms: 100, std_dev_ms: 20, rng: DeterministicRng::new(42) };
        for _ in 0..100 {
            assert_eq!(model1.delay_ms(), model2.delay_ms());
        }
    }

    #[test]
    fn loss_none_never_drops() {
        let mut model = LossModel::None;
        for i in 0..10 {
            for j in 0..10 {
                assert!(!model.should_drop(i, j));
            }
        }
    }

    #[test]
    fn loss_partition_drops_partitioned() {
        let mut model = LossModel::Partition { partitioned: HashSet::from([3]) };
        // Messages to/from node 3 are dropped.
        assert!(model.should_drop(3, 0));
        assert!(model.should_drop(0, 3));
        // Messages between non-partitioned nodes are not dropped.
        assert!(!model.should_drop(0, 1));
        assert!(!model.should_drop(1, 2));
    }

    #[test]
    fn loss_partition_heal() {
        let mut model = LossModel::Partition { partitioned: HashSet::from([3]) };
        assert!(model.should_drop(3, 0));
        model.heal(3);
        assert!(!model.should_drop(3, 0));
    }

    #[test]
    fn loss_random_deterministic() {
        let mut model1 = LossModel::Random { p: 0.5, rng: DeterministicRng::new(42) };
        let mut model2 = LossModel::Random { p: 0.5, rng: DeterministicRng::new(42) };
        for _ in 0..100 {
            assert_eq!(model1.should_drop(0, 1), model2.should_drop(0, 1));
        }
    }

    #[test]
    fn loss_random_zero_prob_never_drops() {
        let mut model = LossModel::Random { p: 0.0, rng: DeterministicRng::new(42) };
        for _ in 0..100 {
            assert!(!model.should_drop(0, 1));
        }
    }

    #[test]
    fn loss_random_one_prob_always_drops() {
        let mut model = LossModel::Random { p: 1.0, rng: DeterministicRng::new(42) };
        for _ in 0..100 {
            assert!(model.should_drop(0, 1));
        }
    }

    #[test]
    fn network_model_perfect() {
        let mut model = NetworkModel::perfect();
        assert_eq!(model.process(0, 1), Some(0));
    }

    #[test]
    fn network_model_with_delay() {
        let mut model = NetworkModel::with_delay(50);
        assert_eq!(model.process(0, 1), Some(50));
    }

    #[test]
    fn network_model_with_loss() {
        let mut model = NetworkModel::with_loss(1.0, 42); // always drop
        assert_eq!(model.process(0, 1), None);
    }
}
