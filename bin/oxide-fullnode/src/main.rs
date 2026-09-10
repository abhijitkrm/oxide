//! oxide-fullnode — the full node binary.
//!
//! Runs the executor + modules without a consensus engine (read-only
//! follower mode). Configuration is loaded from TOML + env vars + CLI
//! flags (same layered model as `oxide-validator`).
//!
//! Usage:
//!
//! ```sh
//! oxide-fullnode --config config/devnet.toml
//! ```

use std::env;
use std::path::PathBuf;

use devnet::{ConsensusConfig, DevnetNode, NodeConfig};

fn main() {
    println!("oxide-fullnode: starting (follower mode)");

    let config = load_config();
    println!(
        "oxide-fullnode: engine = {}, mempool = {}",
        config.consensus.as_str(),
        config.max_mempool_entries
    );

    let _node = DevnetNode::assemble(&config);

    println!("oxide-fullnode: assembled stack (executor + core/bank/staking modules)");
    println!("oxide-fullnode: ready (sync not yet implemented — Phase 2)");
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
                eprintln!("oxide-fullnode: failed to load config from {}: {e}", path.display());
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
fn parse_cli_flag(flag: &str) -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == flag {
            return args.next();
        }
    }
    None
}
