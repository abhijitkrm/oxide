//! Byzantine strategy framework for deterministic simulation.
//!
//! # What this is
//!
//! A set of byzantine (adversarial) behaviors that can be injected
//! into consensus nodes during simulation. Each strategy defines how
//! a byzantine node deviates from the honest protocol.
//!
//! # Why this exists
//!
//! The plan (§13, Phase 4) requires "consensus safety zero-violations
//! in 10k randomized sim scenarios" including byzantine behaviors.
//! This framework provides the building blocks: each strategy is a
//! composable behavior that can be applied to any node.
//!
//! # Strategies
//!
//! - [`ByzantineStrategy::Honest`]: no deviation (control group).
//! - [`ByzantineStrategy::Equivocate`]: send different votes to
//!   different peers for the same view.
//! - [`ByzantineStrategy::Withhold`]: don't vote (silent).
//! - [`ByzantineStrategy::Spam`]: send excessive invalid proposals.
//! - [`ByzantineStrategy::Censor`]: drop transactions from specific
//!   senders when leader.
//! - [`ByzantineStrategy::DoubleVote`]: vote for two different
//!   proposals in the same view.

use std::collections::HashSet;

/// A byzantine strategy: how a node deviates from the honest protocol.
///
/// Each strategy is a pure description of the behavior. The sim
/// harness applies the strategy by intercepting the node's message
/// sending and voting.
#[derive(Debug, Clone)]
pub enum ByzantineStrategy {
    /// No deviation — honest behavior (control group).
    Honest,

    /// Equivocation: send different messages to different peers.
    ///
    /// For voting: send `vote(A)` to some peers and `vote(B)` to
    /// others for the same view. This is a safety violation if
    /// the network doesn't detect it via the QC structure.
    Equivocate,

    /// Vote withholding: don't send any votes.
    ///
    /// This tests liveness: the network must still finalize blocks
    /// as long as ≥ 2f+1 validators are honest and voting.
    Withhold,

    /// Spam: send excessive invalid proposals or messages.
    ///
    /// This tests the network's ability to handle message floods
    /// without stalling consensus.
    Spam {
        /// Number of invalid messages to send per round.
        rate: u32,
    },

    /// Censorship: when leader, drop transactions from specific senders.
    ///
    /// This tests censorship detectability: the mempool should
    /// detect missing transactions and the network should
    /// eventually include them (via a different leader).
    Censor {
        /// The set of censored sender addresses (20-byte).
        censored: HashSet<[u8; 20]>,
    },

    /// Double vote: vote for two different proposals in the same view.
    ///
    /// This is a safety violation. The QC verification should
    /// reject the second vote, and the signer should be slashed
    /// (post-testnet).
    DoubleVote,
}

impl ByzantineStrategy {
    /// Returns `true` if this strategy is honest (no deviation).
    #[must_use]
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::Honest)
    }

    /// Returns `true` if this strategy withholds votes.
    #[must_use]
    pub fn withholds_votes(&self) -> bool {
        matches!(self, Self::Withhold)
    }

    /// Returns `true` if this strategy equivocates.
    #[must_use]
    pub fn equivocates(&self) -> bool {
        matches!(self, Self::Equivocate | Self::DoubleVote)
    }
}

/// A scenario: assign byzantine strategies to specific nodes.
///
/// The sim harness uses this to configure which nodes are byzantine
/// and how. The remaining nodes are honest.
#[derive(Debug, Clone)]
pub struct ByzantineScenario {
    /// The total number of nodes.
    pub num_nodes: usize,
    /// The strategy for each node. Nodes not in this map are honest.
    pub strategies: std::collections::HashMap<usize, ByzantineStrategy>,
}

impl ByzantineScenario {
    /// Create a scenario with all honest nodes.
    #[must_use]
    pub fn all_honest(num_nodes: usize) -> Self {
        Self { num_nodes, strategies: std::collections::HashMap::new() }
    }

    /// Make a specific node byzantine with the given strategy.
    ///
    /// # Panics
    ///
    /// Panics if `index >= num_nodes`.
    pub fn set_byzantine(&mut self, index: usize, strategy: ByzantineStrategy) {
        assert!(index < self.num_nodes, "node index {index} out of range");
        self.strategies.insert(index, strategy);
    }

    /// Returns the strategy for a node, or `Honest` if not specified.
    #[must_use]
    pub fn strategy(&self, index: usize) -> &ByzantineStrategy {
        self.strategies.get(&index).unwrap_or(&ByzantineStrategy::Honest)
    }

    /// Returns the number of byzantine nodes.
    #[must_use]
    pub fn num_byzantine(&self) -> usize {
        self.strategies.len()
    }

    /// Returns the number of honest nodes.
    #[must_use]
    pub fn num_honest(&self) -> usize {
        self.num_nodes - self.strategies.len()
    }

    /// Returns `true` if the scenario has ≤ f byzantine nodes
    /// (the BFT safety bound).
    ///
    /// For n nodes, f = (n - 1) / 3. The network is safe if the
    /// number of byzantine nodes is ≤ f.
    #[must_use]
    pub fn is_within_bft_bound(&self) -> bool {
        let f = (self.num_nodes - 1) / 3;
        self.num_byzantine() <= f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_honest_scenario() {
        let scenario = ByzantineScenario::all_honest(7);
        assert_eq!(scenario.num_nodes, 7);
        assert_eq!(scenario.num_byzantine(), 0);
        assert_eq!(scenario.num_honest(), 7);
        assert!(scenario.is_within_bft_bound());
        assert!(scenario.strategy(0).is_honest());
    }

    #[test]
    fn set_byzantine_strategy() {
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(0, ByzantineStrategy::Withhold);
        scenario.set_byzantine(1, ByzantineStrategy::Equivocate);
        assert_eq!(scenario.num_byzantine(), 2);
        assert_eq!(scenario.num_honest(), 5);
        assert!(scenario.is_within_bft_bound()); // f=2 for n=7
        assert!(scenario.strategy(0).withholds_votes());
        assert!(scenario.strategy(1).equivocates());
        assert!(scenario.strategy(2).is_honest());
    }

    #[test]
    fn bft_bound() {
        // n=7, f=2. 2 byzantine is within bound.
        let mut scenario = ByzantineScenario::all_honest(7);
        scenario.set_byzantine(0, ByzantineStrategy::Withhold);
        scenario.set_byzantine(1, ByzantineStrategy::Equivocate);
        assert!(scenario.is_within_bft_bound());

        // 3 byzantine exceeds f=2.
        scenario.set_byzantine(2, ByzantineStrategy::Spam { rate: 10 });
        assert!(!scenario.is_within_bft_bound());
    }

    #[test]
    fn bft_bound_n4() {
        // n=4, f=1. 1 byzantine is within bound.
        let mut scenario = ByzantineScenario::all_honest(4);
        scenario.set_byzantine(0, ByzantineStrategy::Withhold);
        assert!(scenario.is_within_bft_bound());

        // 2 byzantine exceeds f=1.
        scenario.set_byzantine(1, ByzantineStrategy::Equivocate);
        assert!(!scenario.is_within_bft_bound());
    }

    #[test]
    fn strategy_predicates() {
        assert!(ByzantineStrategy::Honest.is_honest());
        assert!(!ByzantineStrategy::Honest.withholds_votes());
        assert!(!ByzantineStrategy::Honest.equivocates());

        assert!(ByzantineStrategy::Withhold.withholds_votes());
        assert!(!ByzantineStrategy::Withhold.equivocates());

        assert!(ByzantineStrategy::Equivocate.equivocates());
        assert!(ByzantineStrategy::DoubleVote.equivocates());
        assert!(!ByzantineStrategy::Equivocate.withholds_votes());
    }

    #[test]
    fn censor_strategy() {
        let censored = HashSet::from([devnet::txs::identity_addr(0).0]);
        let strategy = ByzantineStrategy::Censor { censored };
        assert!(!strategy.is_honest());
        assert!(!strategy.withholds_votes());
        assert!(!strategy.equivocates());
    }

    #[test]
    fn spam_strategy() {
        let strategy = ByzantineStrategy::Spam { rate: 100 };
        assert!(!strategy.is_honest());
        assert!(!strategy.withholds_votes());
        assert!(!strategy.equivocates());
    }
}
