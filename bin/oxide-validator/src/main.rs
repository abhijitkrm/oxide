//! oxide-validator — the validator node binary.
//!
//! Assembles and runs a full Oxide validator node: consensus engine +
//! executor + modules. Configuration is loaded from (in priority
//! order):
//!
//! 1. CLI flags (highest priority — overrides everything)
//! 2. Environment variables (overrides TOML)
//! 3. TOML config file (the base)
//! 4. Defaults (lowest priority — built into the `Config` struct)
//!
//! Usage:
//!
//! ```sh
//! # Default config (sequencer, 10k mempool)
//! oxide-validator
//!
//! # From a TOML config file
//! oxide-validator --config config/devnet.toml
//!
//! # Override the engine via CLI flag
//! oxide-validator --engine oxideBFT
//!
//! # Override the mempool size via env var
//! OXIDE_EXECUTOR_MAX_MEMPOOL_ENTRIES=50000 oxide-validator
//! ```

use std::env;
use std::path::PathBuf;

use devnet::{ConsensusConfig, DevnetNode, NodeConfig};
use ports::AppInterface;

fn main() {
    let config = load_config();
    println!("oxide-validator: starting with engine = {}", config.consensus.as_str());
    println!("oxide-validator: mempool size = {}", config.max_mempool_entries);

    let mut node = DevnetNode::assemble(&config);
    println!("oxide-validator: assembled stack (executor + core/bank/staking modules)");

    // Submit a smoke-test bank transfer.
    let to = primitives::Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, 100);
    let tx = build_tx(framework::module_id::BANK, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();

    let height = node.engine().finalized_height();
    println!("oxide-validator: finalized height = {height:?}");

    if let Some(h) = height {
        let attestation = node.app().attest_state(h);
        println!("oxide-validator: state root at height {} = {}", h.value(), attestation.root);
    }

    println!("oxide-validator: smoke test complete");
}

/// Load the node configuration from CLI flags, env vars, and TOML file.
///
/// Priority: CLI > env vars > TOML > defaults.
fn load_config() -> NodeConfig {
    let mut config = config::Config::default();

    // 1. Load from TOML file if --config is given.
    let config_path = parse_cli_flag("--config");
    if let Some(path) = config_path.clone() {
        let path = PathBuf::from(path);
        match config::Config::from_toml_file(&path) {
            Ok(loaded) => config = loaded,
            Err(e) => {
                eprintln!("oxide-validator: failed to load config from {}: {e}", path.display());
                std::process::exit(1);
            }
        }
    }

    // 2. Env vars are applied automatically by `from_toml_file`. For
    //    the default config (no --config), apply env vars manually.
    if config_path.is_none() {
        config.apply_env_vars();
    }

    // 3. CLI flags override everything.
    if let Some(engine_str) = parse_cli_flag("--engine") {
        if let Some(engine) = config::ConsensusEngineKind::parse(&engine_str) {
            config.consensus.engine = engine;
        }
    }

    // Convert the config crate's ConsensusEngineKind to devnet's
    // ConsensusConfig.
    let consensus = match config.consensus.engine {
        config::ConsensusEngineKind::Sequencer => ConsensusConfig::Sequencer,
        config::ConsensusEngineKind::OxideBft => ConsensusConfig::OxideBft,
    };

    NodeConfig { consensus, max_mempool_entries: config.executor.max_mempool_entries }
}

/// Parse a `--flag value` pair from CLI args.
///
/// Returns the value if the flag is found, `None` otherwise.
fn parse_cli_flag(flag: &str) -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == flag {
            return args.next();
        }
    }
    None
}

fn build_tx(module_id: u8, module_payload: &[u8]) -> types::TxBytes {
    let sender = primitives::Address([0u8; 20]);
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
