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
//! ## Modes
//!
//! - **Normal mode** (default): runs a single-node devnet using
//!   `DevnetNode::assemble`.
//! - **Devnet node mode** (`--devnet-node <i>`): runs a single
//!   validator node that connects to other validator processes over
//!   TCP. Used by the multi-process devnet launcher.
//!
//! Usage:
//!
//! ```sh
//! # Normal mode (single-node devnet)
//! oxide-validator
//!
//! # From a TOML config file
//! oxide-validator --config config/devnet.toml
//!
//! # Devnet node mode (multi-process)
//! oxide-validator --devnet-node 0 --num-nodes 4 --base-port 22000
//! ```

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use devnet::{ConsensusConfig, DevnetNode, NodeConfig};
use ports::{AppInterface, ConsensusEngine};

fn main() {
    // Check for devnet-node mode.
    if let Some(node_index_str) = parse_cli_flag("--devnet-node") {
        run_devnet_node(&node_index_str);
        return;
    }

    // Normal mode: single-node devnet.
    run_single_node();
}

/// Run a single-node devnet (normal mode).
///
/// Assembles the stack, runs a smoke-test transaction, then starts
/// the JSON-RPC HTTP server (Ethereum-compatible endpoint for
/// MetaMask/Foundry/Blockscout). The RPC server runs on a tokio
/// runtime in a separate thread so the main thread can continue
/// to drive consensus if needed.
fn run_single_node() {
    let (node_config, rpc_config) = load_config();
    println!("oxide-validator: starting with engine = {}", node_config.consensus.as_str());
    println!("oxide-validator: mempool size = {}", node_config.max_mempool_entries);

    let mut node = DevnetNode::assemble(&node_config);
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

    // Start the JSON-RPC HTTP server.
    // The RPC server runs on a tokio multi-thread runtime in a
    // separate thread so it doesn't block the main thread.
    println!("oxide-validator: starting RPC server on http://{}", rpc_config.listen_addr);

    let rpc_server = rpc::RpcServer::new(rpc_config.chain_id, rpc_config.base_fee);
    let http_server = rpc::server::HttpServer::new(rpc_server, rpc_config.listen_addr.clone());

    // Run the tokio runtime in a separate thread.
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(http_server.serve());
    });

    println!("oxide-validator: RPC server running. Press Ctrl+C to stop.");

    // Wait for the RPC server thread (runs forever until killed).
    let _ = handle.join();
}

/// Run a single validator node in multi-process devnet mode.
///
/// This mode is used by the `MultiProcessDevnet` launcher. Each
/// process runs one validator node, connecting to the other nodes
/// over TCP.
///
/// # CLI flags
///
/// - `--devnet-node <i>`: this node's index (0-based).
/// - `--num-nodes <N>`: total number of validator nodes.
/// - `--base-port <port>`: base TCP port. Node `i` listens on
///   `127.0.0.1:{base_port + i}`.
fn run_devnet_node(node_index_str: &str) {
    let node_index: usize =
        node_index_str.parse().unwrap_or_else(|e| panic!("invalid --devnet-node index: {e}"));
    let num_nodes: usize = parse_cli_flag("--num-nodes").and_then(|s| s.parse().ok()).unwrap_or(4);
    let base_port: u16 =
        parse_cli_flag("--base-port").and_then(|s| s.parse().ok()).unwrap_or(22000);

    println!(
        "oxide-validator[{node_index}]: devnet node mode — index={node_index}, num_nodes={num_nodes}, base_port={base_port}"
    );

    // Generate BLS keys for all nodes (deterministic, same as
    // TcpMultiNodeDevnet). We need all public keys to construct the
    // validator set, but only use our own secret key.
    let secret_keys: Vec<crypto::BlsSecretKey> =
        (1..=u8::try_from(num_nodes).expect("num_nodes fits in u8")).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        secret_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let stakes = vec![1u64; num_nodes];
    let validator_set = consensus::ValidatorSet::new(pks, stakes).expect("validator set");

    let our_key = secret_keys[node_index].clone();
    let listen_port = base_port + u16::try_from(node_index).expect("port fits in u16");
    let listen_addr = format!("127.0.0.1:{listen_port}");

    // Build peer list: all other nodes.
    let peers: Vec<(Vec<u8>, String)> = (0..num_nodes)
        .filter(|&i| i != node_index)
        .map(|i| {
            let port = base_port + u16::try_from(i).expect("port fits in u16");
            (vec![u8::try_from(i).expect("peer id fits in u8")], format!("127.0.0.1:{port}"))
        })
        .collect();

    println!("oxide-validator[{node_index}]: listening on {listen_addr}, {} peers", peers.len());

    // Create the executor with modules.
    let mut executor = executor::Executor::new(10_000);
    executor.register_module(Arc::new(oxide_core::CoreModule::new()));
    let bank_module = bank::BankModule::new();
    for sender_byte in 0u8..32 {
        bank_module.mint(&primitives::Address([sender_byte; 20]), 1_000_000_000_000);
    }
    executor.register_module(Arc::new(bank_module));
    executor.register_module(Arc::new(staking::StakingModule::new()));
    let app: Arc<executor::Executor> = Arc::new(executor);
    let app_dyn: Arc<dyn ports::AppInterface> = app.clone();

    // Create the TCP transport. Keep it alive for the lifetime of
    // the node — the transport runs background threads.
    let _transport = p2p::tcp::TcpTransport::new(
        &listen_addr,
        vec![u8::try_from(node_index).expect("peer id fits in u8")],
        peers,
    );

    // Give connections time to establish.
    thread::sleep(Duration::from_millis(500));

    // Create the consensus engine.
    let mut engine = consensus::OxideBft::with_index(
        app_dyn,
        validator_set,
        u16::try_from(node_index).expect("index fits in u16"),
    )
    .with_secret_key(our_key);

    println!("oxide-validator[{node_index}]: consensus engine started, waiting for blocks...");

    // Submit a smoke-test transaction.
    let to = primitives::Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, 100);
    let tx = build_tx(framework::module_id::BANK, &module_payload);
    engine.submit_tx(tx);

    // Run the engine until idle, then report the finalized height.
    engine.run_until_idle();
    let height = engine.finalized_height();
    println!("oxide-validator[{node_index}]: finalized height = {height:?}");

    // Keep running until killed (in a real node, this would be the
    // main event loop).
    println!("oxide-validator[{node_index}]: node running (press Ctrl+C to stop)");
    loop {
        thread::sleep(Duration::from_secs(1));
        let height = engine.finalized_height();
        if height.is_some() {
            println!("oxide-validator[{node_index}]: height = {height:?}");
        }
    }
}

/// Generate a BLS secret key from a single byte (same as
/// `devnet::tcp_multinode::bls_key`).
fn bls_key(byte: u8) -> crypto::BlsSecretKey {
    let ikm = vec![byte; 32];
    crypto::BlsSecretKey::from_ikm(&ikm).expect("BLS key generation from valid IKM")
}

/// Load the node configuration from CLI flags, env vars, and TOML file.
///
/// Priority: CLI > env vars > TOML > defaults.
fn load_config() -> (NodeConfig, config::RpcConfig) {
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

    // Extract the RPC config (defaults to 127.0.0.1:8545 if not set).
    let rpc_config = config.rpc.clone().unwrap_or_default();

    // Convert the config crate's ConsensusEngineKind to devnet's
    // ConsensusConfig.
    let consensus = match config.consensus.engine {
        config::ConsensusEngineKind::Sequencer => ConsensusConfig::Sequencer,
        config::ConsensusEngineKind::OxideBft => ConsensusConfig::OxideBft,
    };

    (NodeConfig { consensus, max_mempool_entries: config.executor.max_mempool_entries }, rpc_config)
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
