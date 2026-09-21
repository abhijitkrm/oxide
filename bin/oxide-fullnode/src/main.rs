//! oxide-fullnode — the full node binary.
//!
//! Runs the executor + modules without a consensus engine (read-only
//! follower mode). Configuration is loaded from TOML + env vars + CLI
//! flags (same layered model and the same `node::node_config_from`
//! conversion as `oxide-validator` — both binaries run identical
//! effective config).
//!
//! Follower mode (consensus sync from the network) is **not
//! implemented**: the only honest function today is
//! `--state-sync` + `--verify-only` — fetch a trusted snapshot,
//! verify it end-to-end, import it, and exit 0. Without
//! `--verify-only` the process exits non-zero rather than claim a
//! "ready" node that cannot follow the chain.
//!
//! Usage:
//!
//! ```sh
//! oxide-fullnode --config config/devnet.toml \
//!   --state-sync 127.0.0.1:8545 --trusted-height 100 \
//!   --trusted-root 0x<64-hex> --verify-only
//! ```

use std::env;
use std::path::PathBuf;

use node::{Node, NodeConfig};

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

    // Follower mode (consensus sync from the network) is not
    // implemented — the only thing this binary can honestly do today
    // is fetch, verify, and import a trusted snapshot. `--verify-only`
    // makes that the explicit contract: exit 0 after a verified
    // bootstrap. Without it, exiting 0 would claim the node is
    // "ready" when it cannot follow the chain — so the process exits
    // non-zero with an actionable message instead.
    if std::env::args().any(|a| a == "--verify-only") {
        println!("oxide-fullnode: verify-only complete");
        return;
    }
    eprintln!(
        "oxide-fullnode: consensus sync (follower mode) is not implemented — \
         the assembled node cannot follow the chain. \
         Re-run with --verify-only for the supported bootstrap-and-verify flow."
    );
    std::process::exit(1);
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
        } else {
            eprintln!(
                "oxide-fullnode: unknown --engine value {engine_str:?} \
                      (expected \"sequencer\" or \"oxidebft\")"
            );
            std::process::exit(1);
        }
    }

    // `--genesis-file`: same chain-state source the validator uses —
    // the shared conversion applies its validators and native
    // balances at assembly.
    let genesis_file = parse_cli_flag("--genesis-file").map(|p| {
        config::genesis::Genesis::from_json_file(&PathBuf::from(&p))
            .unwrap_or_else(|e| panic!("failed to load genesis file {p}: {e}"))
    });

    // `--data-dir` wins over `[storage] data_dir`.
    let data_dir =
        parse_cli_flag("--data-dir").map(PathBuf::from).or_else(|| config.storage.data_dir.clone());

    // The RPC config carries the chain ID and base fee — the
    // executor, the EVM module, and the RPC layer all read the same
    // source so advertised and enforced parameters cannot diverge.
    let rpc_config = config.rpc.clone().unwrap_or_default();

    // Genesis chain id must match the RPC chain id.
    if let Some(g) = &genesis_file {
        if g.chain_id != rpc_config.chain_id {
            eprintln!(
                "oxide-fullnode: genesis chain_id {} != rpc.chain_id {} — \
                 refusing to run a node whose signatures advertise a different chain",
                g.chain_id, rpc_config.chain_id
            );
            std::process::exit(1);
        }
    }

    let genesis = Some(match &genesis_file {
        Some(g) => {
            node::genesis_spec_from_file(g).unwrap_or_else(|e| panic!("invalid genesis file: {e}"))
        }
        None => node::genesis_spec_devnet(&config.genesis),
    });
    let overrides = node::AssemblyOverrides {
        allow_unsigned_txs: env::args().any(|a| a == "--unsafe-allow-unsigned-txs"),
        data_dir,
        genesis,
    };
    // The shared conversion — the same mapping the validator binary
    // uses, so both binaries run identical effective config.
    let node_config =
        node::node_config_from(&config, &rpc_config, &overrides, node::NodeMode::Single)
            .unwrap_or_else(|e| panic!("invalid configuration: {e}"));

    // Validate BEFORE building anything: unsupported settings fail,
    // overridden ones warn — never silently do nothing.
    let (warnings, errors) =
        node::validate_effective_config(&config, &node_config, node::NodeMode::Single);
    for w in &warnings {
        eprintln!("oxide-fullnode: config warning: {w}");
    }
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("oxide-fullnode: config error: {e}");
        }
        std::process::exit(1);
    }

    // Emit the effective configuration — the values actually running.
    println!("oxide-fullnode: effective node config: {node_config:?}");
    node_config
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
