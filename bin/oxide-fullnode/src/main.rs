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

use node::{ConsensusConfig, Node, NodeConfig};

fn main() {
    println!("oxide-fullnode: starting (follower mode)");

    let config = load_config();
    println!(
        "oxide-fullnode: engine = {}, mempool = {}",
        config.consensus.as_str(),
        config.max_mempool_entries
    );

    let mut node = Node::assemble(&config);
    bootstrap_state_sync(&mut node);

    println!("oxide-fullnode: assembled stack (executor + core/staking/evm modules)");
    println!("oxide-fullnode: ready (consensus sync not yet implemented — Phase 2)");
}

/// `--state-sync <host:port>` bootstrap: fetch a chunked snapshot
/// from a peer's `/snapshot/*` endpoints and import it.
///
/// The trust anchor is `--trusted-height` + `--trusted-root`
/// (0x-prefixed 32-byte hex) — a finalized (height, `state_root`)
/// the operator obtained from a source they already trust. Both
/// are required with `--state-sync`: syncing without them would
/// take whatever state the endpoint feels like serving.
///
/// Verified twice: the manifest must match before a byte of state
/// is downloaded (fail fast), and the imported root must recompute
/// to the trusted value after import (fail closed).
fn bootstrap_state_sync(node: &mut Node) {
    let Some(addr) = parse_cli_flag("--state-sync") else {
        return;
    };
    let height_str = parse_cli_flag("--trusted-height").unwrap_or_else(|| {
        panic!("--state-sync requires --trusted-height — refusing to sync unverified state")
    });
    let root_str = parse_cli_flag("--trusted-root").unwrap_or_else(|| {
        panic!("--state-sync requires --trusted-root — refusing to sync unverified state")
    });
    let trusted_height: u64 =
        height_str.parse().unwrap_or_else(|_| panic!("invalid --trusted-height {height_str}"));
    let root_hex = root_str.strip_prefix("0x").unwrap_or(&root_str);
    let root_bytes = hex_decode(root_hex).unwrap_or_else(|e| panic!("invalid --trusted-root: {e}"));
    let trusted_root = primitives::Hash(
        <[u8; 32]>::try_from(root_bytes.as_slice())
            .unwrap_or_else(|_| panic!("--trusted-root must be 32 bytes")),
    );

    let blob = statesync::fetch_snapshot(
        &addr,
        trusted_height,
        &trusted_root,
        executor::SNAPSHOT_FORMAT_VERSION,
    )
    .unwrap_or_else(|e| panic!("state sync from {addr} failed: {e}"));
    let mut reader = codec::Reader::new(&blob);
    let snapshot = <executor::ExecutorSnapshot as codec::Decode>::decode(&mut reader)
        .unwrap_or_else(|e| panic!("snapshot decode failed: {e}"));
    node.import_snapshot(&snapshot).unwrap_or_else(|e| panic!("snapshot import failed: {e}"));

    // Post-import anchor: the imported root at the trusted height
    // must equal what we already trusted — catches a snapshot whose
    // KV payload decoded and imported but doesn't recompute.
    let imported_root = node.app_handle().state_root_at(trusted_height);
    assert_eq!(
        imported_root, trusted_root,
        "imported state root does not match trusted root — refusing to run"
    );
    println!(
        "oxide-fullnode: state synced to height {trusted_height} ({} chunks, {} bytes)",
        blob.len().div_ceil(statesync::DEFAULT_CHUNK_SIZE),
        blob.len()
    );
}

/// Decode a bare hex string (no `0x` needed — CLI args).
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
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

    // Convert the config crate's ConsensusEngineKind to node's
    // ConsensusConfig.
    let consensus = match config.consensus.engine {
        config::ConsensusEngineKind::Sequencer => ConsensusConfig::Sequencer,
        config::ConsensusEngineKind::OxideBft => ConsensusConfig::OxideBft,
    };

    // The RPC config carries the chain ID — the executor needs it for
    // EIP-712 native-tx signature verification (domain separator).
    let chain_id = config.rpc.as_ref().map_or(1, |r| r.chain_id);

    NodeConfig {
        consensus,
        max_mempool_entries: config.executor.max_mempool_entries,
        parallel_threshold: config.executor.parallel_threshold,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id,
        require_signed_txs: env::args().any(|a| a == "--require-signed-txs"),
    }
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
