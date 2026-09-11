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
//!   `Node::assemble`.
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

use node::{ConsensusConfig, Node, NodeConfig};
use ports::{AppInterface, ConsensusEngine};
use types::{MempoolAck, TxBytes};

mod driver;

/// Adapter that lets the RPC server submit transactions into the
/// executor's mempool via the `rpc::TxSubmitter` trait.
///
/// The executor already implements `AppInterface::ingest_tx`, which
/// validates, pre-verifies, and mempools a wrapped transaction. This
/// adapter translates the `MempoolAck` into the `Result<(), String>`
/// that the RPC layer expects, keeping the RPC crate free of a direct
/// dependency on the executor crate.
struct ExecutorTxSubmitter {
    executor: Arc<executor::Executor>,
}

impl rpc::TxSubmitter for ExecutorTxSubmitter {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        match self.executor.ingest_tx(tx) {
            MempoolAck::Accepted => Ok(()),
            MempoolAck::Rejected { reason } => Err(reason),
        }
    }
}

fn main() {
    // Initialize the tracing subscriber with `EnvFilter` so log levels
    // can be controlled via the `RUST_LOG` environment variable (e.g.
    // `RUST_LOG=oxide_validator=debug,rpc=info`).
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Subcommand dispatch (first positional arg).
    let args: Vec<String> = env::args().collect();
    if let Some(subcmd) = args.get(1).map(String::as_str) {
        match subcmd {
            "version" => {
                print_version();
                return;
            }
            "init" => {
                run_init();
                return;
            }
            "genesis" => {
                run_genesis(&args[2..]);
                return;
            }
            "help" | "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {} // fall through to normal mode
        }
    }

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
/// multi-thread runtime. The main task uses `tokio::select!` to wait
/// for either the server to exit or a SIGTERM/SIGINT shutdown signal,
/// enabling graceful shutdown.
fn run_single_node() {
    let (node_config, rpc_config) = load_config();
    tracing::info!(
        engine = node_config.consensus.as_str(),
        max_mempool_entries = node_config.max_mempool_entries,
        "oxide-validator: starting"
    );

    let mut node = Node::assemble(&node_config);
    tracing::info!("oxide-validator: assembled stack (executor + core/bank/staking modules)");

    // Submit a smoke-test bank transfer.
    let to = primitives::Address([2u8; 20]);
    let module_payload = bank::msg::transfer(to, 100);
    let tx = build_tx(framework::module_id::BANK, &module_payload);
    node.engine().submit_tx(tx);

    // Drive consensus once to finalize the smoke-test block.
    node.engine().run_until_idle();
    let height = node.engine().finalized_height();
    tracing::info!(?height, "oxide-validator: finalized height");

    if let Some(h) = height {
        let attestation = node.app().attest_state(h);
        tracing::info!(
            height = h.value(),
            state_root = %attestation.root,
            "oxide-validator: state root"
        );
    }

    tracing::info!("oxide-validator: smoke test complete");

    // Start the JSON-RPC HTTP server.
    tracing::info!(
        listen_addr = %rpc_config.listen_addr,
        "oxide-validator: starting RPC server"
    );

    // Create a shared latency recorder for the block pipeline and RPC.
    let recorder = Arc::new(metrics::Recorder::new());

    let mut rpc_server = rpc::RpcServer::new(rpc_config.chain_id, rpc_config.base_fee);
    // Wire the executor into the RPC so `eth_sendRawTransaction`
    // decodes, wraps, and submits EVM transactions into the mempool.
    rpc_server.set_tx_submitter(Arc::new(ExecutorTxSubmitter { executor: node.app_handle() }));
    // Attach the latency recorder for RPC handler metrics.
    rpc_server.set_recorder(recorder.clone());
    // Seed the metrics with the current block height and mempool size.
    if let Some(h) = height {
        rpc_server.set_block_height(h.value());
    }
    rpc_server.set_mempool_size(0);
    let http_server = rpc::server::HttpServer::new(rpc_server, rpc_config.listen_addr.clone());

    // Build a single tokio runtime for the consensus driver, HTTP
    // server, and signal handling.
    let runtime =
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");

    runtime.block_on(async {
        // Start the autonomous consensus driver. This continuously
        // drives the consensus engine in a background task,
        // finalizing blocks as transactions arrive.
        let consensus_driver = driver::ConsensusDriver::with_defaults();
        let driver_metrics = consensus_driver.metrics();
        consensus_driver.start(node);
        tracing::info!("oxide-validator: consensus driver started (autonomous mode)");

        // Spawn the HTTP server as a background task.
        let server_handle = tokio::spawn(async move {
            http_server.serve().await;
        });

        // Periodically sync driver metrics to the RPC server.
        let metrics_sync = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                // The driver_metrics handle is used to read the
                // current block height for logging; the RPC server
                // has its own atomic counters that are updated via
                // `set_block_height`. In a future refactor, the
                // driver and RPC can share the same atomic counters.
                let height = driver_metrics.block_height();
                tracing::debug!(
                    height,
                    txs = driver_metrics.tx_count(),
                    "metrics sync: driver stats"
                );
            }
        });

        // Shutdown signal handler: catches SIGTERM and SIGINT (Ctrl+C).
        let shutdown = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
                let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
                tokio::select! {
                    _ = sigterm.recv() => tracing::info!("received SIGTERM"),
                    _ = sigint.recv() => tracing::info!("received SIGINT (Ctrl+C)"),
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.expect("install Ctrl+C handler");
                tracing::info!("received shutdown signal");
            }
        };

        tokio::select! {
            _ = server_handle => {
                tracing::info!("RPC server exited");
            }
            () = shutdown => {
                tracing::info!("shutdown signal received, shutting down gracefully");
            }
        }
        metrics_sync.abort();
    });

    tracing::info!("oxide-validator: node stopped");
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

    (
        NodeConfig {
            consensus,
            max_mempool_entries: config.executor.max_mempool_entries,
            parallel_threshold: config.executor.parallel_threshold,
            evm_persistence: true,
            storage_path: None,
        },
        rpc_config,
    )
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

// ── Subcommands ───────────────────────────────────────────────────

/// Print the version string.
fn print_version() {
    println!("oxide-validator {}", env!("CARGO_PKG_VERSION"));
    println!("consensus: oxideBFT (2-chain HotStuff with BLS QCs)");
    println!("evm: revm-based, EIP-1559 compatible");
    println!("license: GPL-3.0");
}

/// Print help text.
fn print_help() {
    println!("oxide-validator — Oxide blockchain validator node");
    println!();
    println!("USAGE:");
    println!("    oxide-validator [SUBCOMMAND] [FLAGS]");
    println!();
    println!("SUBCOMMANDS:");
    println!("    (default)    Run a single-node devnet");
    println!("    init         Initialize a new node directory with config + genesis");
    println!("    genesis      Generate a genesis file");
    println!("    version      Print version information");
    println!("    help         Print this help message");
    println!();
    println!("FLAGS:");
    println!("    --config <path>          Load config from TOML file");
    println!("    --engine <kind>           Consensus engine (sequencer|oxidebft)");
    println!("    --devnet-node <i>         Devnet node index (multi-process mode)");
    println!("    --num-nodes <N>           Total devnet nodes");
    println!("    --base-port <port>        Base TCP port for devnet");
    println!();
    println!("EXAMPLES:");
    println!("    oxide-validator init --chain-id 1");
    println!("    oxide-validator genesis --chain-id 1 --validators 4");
    println!("    oxide-validator --config config/devnet.toml");
    println!("    oxide-validator --engine oxidebft");
}

/// `oxide-validator init` — initialize a new node directory.
///
/// Creates a node directory with:
/// - `config.toml` — default node configuration
/// - `genesis.json` — default genesis file
///
/// Flags:
/// - `--chain-id <id>`: chain ID (default: 1)
/// - `--validators <N>`: number of validators (default: 4)
/// - `--dir <path>`: target directory (default: ./oxide-node)
fn run_init() {
    let chain_id: u64 = parse_cli_flag("--chain-id").and_then(|s| s.parse().ok()).unwrap_or(1);
    let num_validators: usize =
        parse_cli_flag("--validators").and_then(|s| s.parse().ok()).unwrap_or(4);
    let dir = parse_cli_flag("--dir").unwrap_or_else(|| "oxide-node".to_string());

    let dir_path = PathBuf::from(&dir);
    if dir_path.exists() {
        eprintln!("oxide-validator init: directory {dir} already exists");
        std::process::exit(1);
    }
    std::fs::create_dir_all(&dir_path).expect("create node directory");

    // Write config.toml.
    let config = config::Config::default();
    let config_toml = toml::to_string(&config).expect("serialize config");
    let config_path = dir_path.join("config.toml");
    std::fs::write(&config_path, config_toml).expect("write config.toml");
    println!("oxide-validator init: wrote {}", config_path.display());

    // Write genesis.json.
    let genesis = config::genesis::Genesis::devnet(chain_id, num_validators, 32, 1_000_000_000_000);
    let genesis_path = dir_path.join("genesis.json");
    genesis.to_json_file(&genesis_path).expect("write genesis.json");
    println!("oxide-validator init: wrote {}", genesis_path.display());

    println!();
    println!("oxide-validator init: node directory initialized at {dir}");
    println!("oxide-validator init: next steps:");
    println!("  oxide-validator --config {dir}/config.toml");
}

/// `oxide-validator genesis` — generate a genesis file.
///
/// Flags:
/// - `--chain-id <id>`: chain ID (default: 1)
/// - `--validators <N>`: number of validators (default: 4)
/// - `--output <path>`: output file (default: genesis.json)
fn run_genesis(args: &[String]) {
    let mut chain_id: u64 = 1;
    let mut num_validators: usize = 4;
    let mut output = "genesis.json".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--chain-id" => {
                if let Some(v) = args.get(i + 1) {
                    chain_id = v.parse().unwrap_or(1);
                }
                i += 2;
            }
            "--validators" => {
                if let Some(v) = args.get(i + 1) {
                    num_validators = v.parse().unwrap_or(4);
                }
                i += 2;
            }
            "--output" | "-o" => {
                if let Some(v) = args.get(i + 1) {
                    output.clone_from(v);
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let genesis = config::genesis::Genesis::devnet(chain_id, num_validators, 32, 1_000_000_000_000);
    let path = PathBuf::from(&output);
    genesis.to_json_file(&path).expect("write genesis file");
    println!(
        "oxide-validator genesis: wrote {} (chain_id={chain_id}, validators={num_validators})",
        path.display()
    );
}
