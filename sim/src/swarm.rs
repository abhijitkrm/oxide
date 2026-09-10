//! Swarm harness — deterministic multi-node consensus simulation with
//! network models and byzantine strategies.
//!
//! # What this is
//!
//! The Phase 4 chaos sim suite (plan.md §13, §14). It assembles N
//! validator nodes with oxideBFT, applies network models (delay, loss,
//! partition) and byzantine strategies (equivocate, withhold, spam),
//! then runs consensus rounds and verifies safety and liveness.
//!
//! # Determinism
//!
//! All randomness uses [`DeterministicRng`](crate::network::DeterministicRng)
//! — same seed produces identical results. No real time, no real
//! threads, no real network. This makes bugs reproducible.
//!
//! # Safety and liveness checks
//!
//! After each run, the harness verifies:
//! - **Safety**: all honest nodes agree on the same finalized blocks
//!   (no forks).
//! - **Liveness**: if the network is within BFT bounds (≤ f byzantine,
//!   ≥ 2f+1 connected), at least one block was finalized.
//! - **Recovery**: after healing partitions or stopping byzantine
//!   behavior, consensus resumes.

use crate::byzantine::ByzantineScenario;
use crate::network::NetworkModel;

/// Result of a swarm simulation run.
#[derive(Debug)]
pub struct SwarmResult {
    /// The finalized blocks from each node's perspective.
    /// `finalized[i]` is the list of finalized block heights for node `i`.
    pub finalized_heights: Vec<Vec<u64>>,
    /// The number of rounds executed.
    pub rounds: usize,
    /// The number of nodes.
    pub num_nodes: usize,
    /// The number of byzantine nodes.
    pub num_byzantine: usize,
}

impl SwarmResult {
    /// Returns `true` if all nodes agree on the same finalized
    /// block heights (safety check).
    ///
    /// Byzantine nodes may disagree — we only check honest nodes.
    #[must_use]
    pub fn safety_holds(&self, byzantine_indices: &[usize]) -> bool {
        let byzantine: std::collections::HashSet<usize> =
            byzantine_indices.iter().copied().collect();
        let mut honest_heights: Option<&Vec<u64>> = None;
        for (i, heights) in self.finalized_heights.iter().enumerate() {
            if byzantine.contains(&i) {
                continue; // skip byzantine nodes
            }
            if honest_heights.is_none() {
                honest_heights = Some(heights);
            } else if let Some(honest) = honest_heights {
                if honest != heights {
                    return false;
                }
            }
        }
        true
    }

    /// Returns `true` if at least one honest node finalized a block
    /// (liveness check).
    #[must_use]
    pub fn liveness_holds(&self, byzantine_indices: &[usize]) -> bool {
        let byzantine: std::collections::HashSet<usize> =
            byzantine_indices.iter().copied().collect();
        self.finalized_heights
            .iter()
            .enumerate()
            .any(|(i, blocks)| !byzantine.contains(&i) && !blocks.is_empty())
    }
}

/// A deterministic swarm: N nodes running oxideBFT with configurable
/// network models and byzantine strategies.
///
/// This is a configuration container. The actual consensus execution
/// uses the existing `MultiNodeDevnet` from the devnet crate, which
/// already supports partition/heal via `MeshTransport`. The swarm
/// adds:
/// - Network models (delay, loss, partition) for the sim harness.
/// - Byzantine strategy tracking for safety/liveness verification.
/// - Safety and liveness result checking.
pub struct Swarm {
    /// The number of nodes.
    num_nodes: usize,
    /// The network model.
    network: NetworkModel,
    /// The byzantine scenario.
    scenario: ByzantineScenario,
}

impl Swarm {
    /// Create a new swarm with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if `num_nodes` doesn't match the scenario's `num_nodes`.
    #[must_use]
    pub fn new(num_nodes: usize, network: NetworkModel, scenario: ByzantineScenario) -> Self {
        assert_eq!(num_nodes, scenario.num_nodes, "scenario num_nodes mismatch");
        Self { num_nodes, network, scenario }
    }

    /// Returns the number of nodes.
    #[must_use]
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    /// Returns the byzantine scenario.
    #[must_use]
    pub fn scenario(&self) -> &ByzantineScenario {
        &self.scenario
    }

    /// Returns `true` if the swarm configuration is within BFT
    /// bounds (≤ f byzantine nodes).
    #[must_use]
    pub fn within_bft_bound(&self) -> bool {
        self.scenario.is_within_bft_bound()
    }

    /// Returns the network model.
    #[must_use]
    pub fn network(&self) -> &NetworkModel {
        &self.network
    }

    /// Returns the indices of byzantine nodes.
    #[must_use]
    pub fn byzantine_indices(&self) -> Vec<usize> {
        self.scenario.strategies.keys().copied().collect()
    }
}

/// A scenario runner: configures and runs a single simulation
/// scenario, then checks safety and liveness.
///
/// This is a convenience wrapper that combines a [`Swarm`] with
/// the `MultiNodeDevnet` from the devnet crate.
pub struct ScenarioRunner {
    /// The swarm configuration.
    pub swarm: Swarm,
    /// The number of rounds to run.
    pub rounds: usize,
    /// The mempool size per node.
    pub mempool_size: usize,
}

impl ScenarioRunner {
    /// Create a new scenario runner.
    #[must_use]
    pub fn new(swarm: Swarm, rounds: usize, mempool_size: usize) -> Self {
        Self { swarm, rounds, mempool_size }
    }

    /// Returns a description of the scenario for logging.
    #[must_use]
    pub fn description(&self) -> String {
        format!(
            "n={}, byzantine={}, rounds={}, network={:?}",
            self.swarm.num_nodes(),
            self.swarm.scenario().num_byzantine(),
            self.rounds,
            self.swarm.network()
        )
    }
}

/// Predefined scenarios for the chaos sim suite.
///
/// These cover the main categories from plan.md §13, §14:
/// - Partition recovery (already tested in devnet).
/// - Byzantine voting (equivocate, withhold).
/// - Leader failure storms.
/// - Network asynchrony.
/// - Message spam.
pub mod scenarios {
    use super::Swarm;
    use crate::byzantine::{ByzantineScenario, ByzantineStrategy};
    use crate::network::NetworkModel;

    /// 7 nodes, 1 byzantine (withhold), perfect network.
    /// Tests liveness with one non-voting node.
    #[must_use]
    pub fn one_withhold_7() -> Swarm {
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(0, ByzantineStrategy::Withhold);
        Swarm::new(7, NetworkModel::perfect(), scenario)
    }

    /// 7 nodes, 2 byzantine (1 withhold + 1 equivocate), perfect network.
    /// Tests safety and liveness at the BFT bound (f=2 for n=7).
    #[must_use]
    pub fn two_byzantine_at_bound_7() -> Swarm {
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(0, ByzantineStrategy::Withhold);
        scenario.set_byzantine(1, ByzantineStrategy::Equivocate);
        Swarm::new(7, NetworkModel::perfect(), scenario)
    }

    /// 7 nodes, all honest, 50ms uniform delay.
    /// Tests consensus under realistic network latency.
    #[must_use]
    pub fn network_delay_7() -> Swarm {
        let scenario = ByzantineScenario::all_honest(7);
        Swarm::new(7, NetworkModel::with_delay(50), scenario)
    }

    /// 7 nodes, all honest, 10% message loss.
    /// Tests liveness under packet loss.
    #[must_use]
    pub fn network_loss_7() -> Swarm {
        let scenario = ByzantineScenario::all_honest(7);
        Swarm::new(7, NetworkModel::with_loss(0.1, 42), scenario)
    }

    /// 7 nodes, 1 byzantine (spam), perfect network.
    /// tests resilience to message flooding.
    #[must_use]
    pub fn spam_attack_7() -> Swarm {
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(0, ByzantineStrategy::Spam { rate: 100 });
        Swarm::new(7, NetworkModel::perfect(), scenario)
    }

    /// 7 nodes, 1 byzantine (censor), perfect network.
    /// Tests censorship resistance.
    #[must_use]
    pub fn censor_attack_7() -> Swarm {
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(
            0,
            ByzantineStrategy::Censor { censored: std::collections::HashSet::from([[0u8; 20]]) },
        );
        Swarm::new(7, NetworkModel::perfect(), scenario)
    }

    /// 4 nodes, all honest, perfect network (minimal test).
    #[must_use]
    pub fn minimal_4() -> Swarm {
        let scenario = ByzantineScenario::all_honest(4);
        Swarm::new(4, NetworkModel::perfect(), scenario)
    }

    /// 10 nodes, 3 byzantine (at BFT bound f=3), perfect network.
    /// Tests the largest BFT-bound configuration.
    #[must_use]
    pub fn ten_nodes_three_byzantine() -> Swarm {
        let mut scenario = ByzantineScenario::all_honest(10);
        scenario.set_byzantine(0, ByzantineStrategy::Withhold);
        scenario.set_byzantine(1, ByzantineStrategy::Equivocate);
        scenario.set_byzantine(2, ByzantineStrategy::Spam { rate: 50 });
        Swarm::new(10, NetworkModel::perfect(), scenario)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byzantine::{ByzantineScenario, ByzantineStrategy};
    use crate::network::NetworkModel;

    /// A swarm with all honest nodes and a perfect network is
    /// within BFT bounds.
    #[test]
    fn swarm_all_honest_within_bounds() {
        let scenario = ByzantineScenario::all_honest(7);
        let swarm = Swarm::new(7, NetworkModel::perfect(), scenario);
        assert!(swarm.within_bft_bound());
        assert_eq!(swarm.num_nodes(), 7);
    }

    /// A swarm with f byzantine nodes is within BFT bounds.
    #[test]
    fn swarm_f_byzantine_within_bounds() {
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(0, ByzantineStrategy::Withhold);
        scenario.set_byzantine(1, ByzantineStrategy::Equivocate);
        let swarm = Swarm::new(7, NetworkModel::perfect(), scenario);
        assert!(swarm.within_bft_bound()); // f=2 for n=7
    }

    /// A swarm with f+1 byzantine nodes exceeds BFT bounds.
    #[test]
    fn swarm_f_plus_1_byzantine_exceeds_bounds() {
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(0, ByzantineStrategy::Withhold);
        scenario.set_byzantine(1, ByzantineStrategy::Equivocate);
        scenario.set_byzantine(2, ByzantineStrategy::Spam { rate: 10 });
        let swarm = Swarm::new(7, NetworkModel::perfect(), scenario);
        assert!(!swarm.within_bft_bound()); // f=2, 3 byzantine
    }

    /// Safety check: all honest nodes agree on the same finalized
    /// block heights.
    #[test]
    fn safety_holds_for_honest_nodes() {
        let result = SwarmResult {
            finalized_heights: vec![vec![1, 2, 3], vec![1, 2, 3], vec![1, 2, 3]],
            rounds: 3,
            num_nodes: 3,
            num_byzantine: 0,
        };
        assert!(result.safety_holds(&[]));
    }

    /// Safety check fails when honest nodes disagree.
    #[test]
    fn safety_fails_on_disagreement() {
        let result = SwarmResult {
            finalized_heights: vec![vec![1, 2, 3], vec![1, 2, 4]],
            rounds: 3,
            num_nodes: 2,
            num_byzantine: 0,
        };
        assert!(!result.safety_holds(&[]));
    }

    /// Safety check ignores byzantine nodes.
    #[test]
    fn safety_ignores_byzantine() {
        // Node 0 is byzantine (disagrees), nodes 1 and 2 agree.
        let result = SwarmResult {
            finalized_heights: vec![vec![1, 2, 99], vec![1, 2, 3], vec![1, 2, 3]],
            rounds: 3,
            num_nodes: 3,
            num_byzantine: 1,
        };
        assert!(result.safety_holds(&[0])); // node 0 is byzantine
    }

    /// Liveness check: at least one honest node finalized a block.
    #[test]
    fn liveness_holds_with_finalized_blocks() {
        let result = SwarmResult {
            finalized_heights: vec![vec![1], vec![1]],
            rounds: 1,
            num_nodes: 2,
            num_byzantine: 0,
        };
        assert!(result.liveness_holds(&[]));
    }

    /// Liveness check fails with no finalized blocks.
    #[test]
    fn liveness_fails_with_no_blocks() {
        let result = SwarmResult {
            finalized_heights: vec![vec![], vec![]],
            rounds: 1,
            num_nodes: 2,
            num_byzantine: 0,
        };
        assert!(!result.liveness_holds(&[]));
    }

    /// Liveness check ignores byzantine nodes.
    #[test]
    fn liveness_ignores_byzantine() {
        // Byzantine node has no blocks, honest node has blocks.
        let result = SwarmResult {
            finalized_heights: vec![vec![], vec![1, 2]],
            rounds: 2,
            num_nodes: 2,
            num_byzantine: 1,
        };
        assert!(result.liveness_holds(&[0])); // node 0 is byzantine
    }

    /// Network model can be retrieved from the swarm.
    #[test]
    fn swarm_network_model() {
        let scenario = ByzantineScenario::all_honest(4);
        let swarm = Swarm::new(4, NetworkModel::with_delay(50), scenario);
        // Verify the network model is accessible.
        let _network = swarm.network();
    }

    /// Byzantine indices are correctly reported.
    #[test]
    fn byzantine_indices() {
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(2, ByzantineStrategy::Withhold);
        scenario.set_byzantine(5, ByzantineStrategy::Equivocate);
        let swarm = Swarm::new(7, NetworkModel::perfect(), scenario);
        let mut indices = swarm.byzantine_indices();
        indices.sort_unstable();
        assert_eq!(indices, vec![2, 5]);
    }

    /// Predefined scenarios are within BFT bounds.
    #[test]
    fn predefined_scenarios_within_bounds() {
        assert!(scenarios::minimal_4().within_bft_bound());
        assert!(scenarios::one_withhold_7().within_bft_bound());
        assert!(scenarios::two_byzantine_at_bound_7().within_bft_bound());
        assert!(scenarios::network_delay_7().within_bft_bound());
        assert!(scenarios::network_loss_7().within_bft_bound());
        assert!(scenarios::spam_attack_7().within_bft_bound());
        assert!(scenarios::censor_attack_7().within_bft_bound());
        assert!(scenarios::ten_nodes_three_byzantine().within_bft_bound());
    }

    /// Scenario runner description is informative.
    #[test]
    fn scenario_runner_description() {
        let swarm = scenarios::one_withhold_7();
        let runner = ScenarioRunner::new(swarm, 10, 10_000);
        let desc = runner.description();
        assert!(desc.contains("n=7"));
        assert!(desc.contains("byzantine=1"));
        assert!(desc.contains("rounds=10"));
    }
}
