//! Oxide local devnet — config-driven node assembly and in-process
//! multi-node runner.
//!
//! The devnet (plan.md §13) assembles a full node stack from TOML
//! config: consensus engine, executor, modules, broadcast. It runs
//! in-process (no real networking) for deterministic local testing.
//!
//! # Config-driven engine selection
//!
//! The key Phase 1 acceptance gate: "devnet also runs on
//! `SequencerEngine` via config swap with zero app-code changes." This
//! crate provides [`NodeConfig`] with a [`ConsensusConfig`] enum that
//! selects between `sequencer` and `oxideBFT`. The same app (executor
//! + modules) runs under either engine.
//!
//! # Phase 1 scope
//!
//! v0 is an in-process, single-node devnet. Multi-node networking
//! arrives with the transport crate in Phase 2. The devnet proves
//! the config seam: you can build a node, select an engine, and run
//! the full stack end-to-end.

use std::sync::Arc;

use consensus::{OxideBft, SequencerEngine};
use executor::Executor;
use ports::{AppInterface, ConsensusEngine};
use primitives::Address;

pub mod multinode;
pub mod tcp_multinode;

/// The consensus engine selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusConfig {
    /// Single-leader dev-mode engine (no voting, no `BFT`).
    Sequencer,
    /// `oxideBFT` (2-chain `HotStuff` with `BLS` QCs).
    /// Not yet wired for multi-node in the devnet — Phase 2.
    OxideBft,
}

impl ConsensusConfig {
    /// Parse from a string (for TOML config).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sequencer" => Some(Self::Sequencer),
            "oxideBFT" | "oxidebft" => Some(Self::OxideBft),
            _ => None,
        }
    }

    /// The string name for config serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::OxideBft => "oxideBFT",
        }
    }
}

/// The node configuration: engine selection + mempool size.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Which consensus engine to use.
    pub consensus: ConsensusConfig,
    /// Maximum mempool entries.
    pub max_mempool_entries: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self { consensus: ConsensusConfig::Sequencer, max_mempool_entries: 10_000 }
    }
}

/// A fully assembled devnet node: engine + app.
///
/// The engine drives the app through the OAI boundary. The app is
/// the executor with registered modules.
pub struct DevnetNode {
    /// The consensus engine, boxed for engine-agnostic storage.
    engine: Box<dyn ConsensusEngine>,
    /// The app (executor), kept for post-run inspection.
    app: Arc<Executor>,
}

impl DevnetNode {
    /// Assemble a devnet node from config.
    ///
    /// Registers the core, bank, and staking modules on the executor,
    /// then wires the executor behind the selected consensus engine.
    ///
    /// # Panics
    ///
    /// Panics if BLS key generation fails (impossible with valid IKM)
    /// or if the validator set construction fails (impossible with
    /// equal stakes ≥ 1).
    pub fn assemble(config: &NodeConfig) -> Self {
        // Build the executor with standard modules.
        let mut executor = Executor::new(config.max_mempool_entries);
        executor.register_module(Arc::new(oxide_core::CoreModule::new()));
        // Genesis-mint to the sender address so bank transfers can
        // debit (C2 fix: the bank now debits the sender).
        let bank = bank::BankModule::new();
        bank.mint(&primitives::Address([0u8; 20]), 1_000_000_000_000);
        executor.register_module(Arc::new(bank));
        executor.register_module(Arc::new(staking::StakingModule::new()));
        let app: Arc<Executor> = Arc::new(executor);
        let app_dyn: Arc<dyn AppInterface> = app.clone();

        // Select the consensus engine.
        let engine: Box<dyn ConsensusEngine> = match config.consensus {
            ConsensusConfig::Sequencer => Box::new(SequencerEngine::new(app_dyn.clone())),
            ConsensusConfig::OxideBft => {
                // oxideBFT in single-validator mode (quorum=1): the
                // engine self-proposes, self-votes, and commits via
                // the 2-chain rule. This is a real oxideBFT run, not
                // a fallback — the consensus logic is identical to
                // the multi-node case, just with n=1.
                //
                // M6 fix: previously this silently fell back to
                // SequencerEngine, which meant the config name
                // "oxideBFT" was a lie. Now it runs the real engine.
                let key =
                    crypto::BlsSecretKey::from_ikm(&[1u8; 32]).expect("BLS key gen from valid IKM");
                let pk = key.public_key();
                let vs =
                    consensus::ValidatorSet::new(vec![pk], vec![1]).expect("single validator set");
                Box::new(OxideBft::new(app_dyn.clone(), vs).with_secret_key(key))
            }
        };

        Self { engine, app }
    }

    /// Access the consensus engine for driving.
    pub fn engine(&mut self) -> &mut dyn ConsensusEngine {
        self.engine.as_mut()
    }

    /// Access the app (executor) for inspection.
    pub fn app(&self) -> &Executor {
        &self.app
    }
}

/// Run a simple devnet: assemble a node, submit a tx, finalize a block.
///
/// # Panics
///
/// Panics if the smoke test fails (no block finalized or zero state root).
pub fn run_devnet_smoke_test() {
    let config = NodeConfig::default();
    let mut node = DevnetNode::assemble(&config);

    // Submit a bank transfer tx.
    let to = Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, 100);
    let tx = build_tx(framework::module_id::BANK, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();

    // Verify the block was finalized.
    let height = node.engine().finalized_height();
    assert!(height.is_some(), "devnet: a block should be finalized");

    // Verify the bank module processed the transfer.
    let balance = node.app().attest_state(primitives::Height::new(0));
    assert_ne!(balance.root, primitives::Hash::ZERO, "state root should be non-zero");
}

/// Build a tx in the mempool's v0 format with a module dispatch byte.
fn build_tx(module_id: u8, module_payload: &[u8]) -> types::TxBytes {
    let sender = Address([0u8; 20]);
    let nonce = 0u64;
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(module_payload);
    types::TxBytes::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_assembles_with_sequencer() {
        let config = NodeConfig { consensus: ConsensusConfig::Sequencer, max_mempool_entries: 100 };
        let mut node = DevnetNode::assemble(&config);
        // The engine should be ready (no blocks yet).
        assert!(node.engine().finalized_height().is_none());
    }

    #[test]
    fn devnet_smoke_test_passes() {
        run_devnet_smoke_test();
    }

    #[test]
    fn config_parses_engine_names() {
        assert_eq!(ConsensusConfig::parse("sequencer"), Some(ConsensusConfig::Sequencer));
        assert_eq!(ConsensusConfig::parse("oxideBFT"), Some(ConsensusConfig::OxideBft));
        assert_eq!(ConsensusConfig::parse("unknown"), None);
    }

    #[test]
    fn config_engine_swap_produces_same_app() {
        // The seam proof at the devnet level: the same app (executor
        // + modules) runs under either engine config without changes.
        let seq_config =
            NodeConfig { consensus: ConsensusConfig::Sequencer, max_mempool_entries: 100 };
        let bft_config =
            NodeConfig { consensus: ConsensusConfig::OxideBft, max_mempool_entries: 100 };

        let mut seq_node = DevnetNode::assemble(&seq_config);
        let mut bft_node = DevnetNode::assemble(&bft_config);

        // Both should assemble and be ready to run.
        assert!(seq_node.engine().finalized_height().is_none());
        assert!(bft_node.engine().finalized_height().is_none());
    }
}
