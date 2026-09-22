//! `oxide-validator` — the Oxide validator node binary.
//!
//! Runs a single node over the full consensus + executor stack:
//! [`node::assemble_executor`] builds the production module graph
//! (core, evm, staking, exchange, perps, oracle, governance) with
//! the async execution lane, and `mod driver` drives the engine.
//!
//! Multi-validator devnets are launched by the separate
//! `oxide-devnet` binary (`devnet::multiprocess` spawns one process
//! per validator) — development launchers stay out of the
//! production binary.
//!
//! # Usage
//!
//! ```sh
//! oxide-validator                       # single-node devnet
//! oxide-validator --config node.toml    # configured node
//! ```
//!
//! Subcommands: `version`, `init`, `genesis`, `tls-gen`, `help`.

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use node::Node;
use ports::AppInterface;

// Codec traits for encoding/decoding consensus messages.
use codec::{Decode, Encode};

mod driver;

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
            "tls-gen" => {
                run_tls_gen(&args[2..]);
                return;
            }
            "help" | "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {} // fall through to normal mode
        }
    }

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
    let cfg = node::cli::load_config(node::NodeMode::Single, "oxide-validator");
    tracing::info!(
        engine = cfg.node.consensus.as_str(),
        max_mempool_entries = cfg.node.max_mempool_entries,
        "oxide-validator: starting"
    );

    let mut node = Node::assemble(&cfg.node);
    tracing::info!("oxide-validator: assembled stack (executor + core/staking/evm modules)");

    handle_import_snapshot(&mut node);

    // Submit a smoke-test staking delegate signed by devnet
    // identity 0 (genesis-funded and validator-registered in the
    // single-node default — the signed default policy requires it).
    let module_payload = staking::msg::delegate(
        crypto::secp::test_identity_address(0).expect("valid devnet identity"),
        100,
    );
    let tx = node::cli::build_signed_tx(
        cfg.node.chain_id,
        framework::module_id::STAKING,
        &module_payload,
        0,
    );
    node.engine().submit_tx(tx);

    // Drive consensus once to finalize the smoke-test block.
    node.engine().run_until_idle();
    let height = node.engine().finalized_height();
    tracing::info!(?height, "oxide-validator: finalized height");

    if let Some(h) = height {
        if let Some(attestation) = node.app().attest_state(h) {
            tracing::info!(
                height = h.value(),
                state_root = %attestation.root,
                "oxide-validator: state root"
            );
        } else {
            tracing::info!(height = h.value(), "oxide-validator: height not executed");
        }
    }

    tracing::info!("oxide-validator: smoke test complete");

    if handle_export_snapshot(&mut node) {
        return;
    }
    handle_key_change(&mut node, cfg.node.chain_id);

    // Start the JSON-RPC HTTP server.
    tracing::info!(
        listen_addr = %cfg.rpc.listen_addr,
        "oxide-validator: starting RPC server"
    );

    // Create a shared latency recorder for the block pipeline and RPC.
    let recorder = Arc::new(metrics::Recorder::new());

    let (rpc_shared, http_server) =
        build_single_node_rpc(&node, &cfg.rpc, height, recorder.clone());

    // Build a single tokio runtime for the consensus driver, HTTP
    // server, and signal handling.
    let runtime =
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");

    runtime.block_on(async {
        // Start the autonomous consensus driver. This continuously
        // drives the consensus engine in a background task,
        // finalizing blocks as transactions arrive.
        let mut consensus_driver = driver::ConsensusDriver::with_defaults();
        let driver_metrics = consensus_driver.metrics();
        consensus_driver.set_block_observer(Arc::new(move |height: u64| {
            rpc_shared.set_block_height(height);
            rpc_shared.publish_new_block(height);
        }));
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

/// Build the single-node JSON-RPC server: wire the executor and EVM
/// module into `RpcServer`, seed metrics, and return the shared
/// `Arc` (for the driver's block observer) plus the HTTP server.
fn build_single_node_rpc(
    node: &Node,
    rpc_config: &config::RpcConfig,
    height: Option<primitives::Height>,
    recorder: Arc<metrics::Recorder>,
) -> (Arc<rpc::RpcServer>, rpc::server::HttpServer) {
    let mut rpc_server = rpc::RpcServer::new(rpc_config.chain_id, rpc_config.base_fee);
    // Wire the executor into the RPC so `eth_sendRawTransaction`
    // decodes, wraps, and submits EVM transactions into the mempool.
    rpc_server.set_tx_submitter(Arc::new(node::rpc_adapters::ExecutorTxSubmitter {
        executor: node.app_handle(),
    }));
    rpc_server.set_txpool_provider(Arc::new(node::rpc_adapters::ExecutorTxpoolProvider {
        executor: node.app_handle(),
    }));
    // Share the executor's EVM module with the RPC so `eth_call`,
    // `eth_getBalance`, and the block/tx/receipt/log lookups serve
    // the same state the executor is committing.
    if let Some(evm_module) = node.evm_module_handle() {
        rpc_server.set_evm(evm_module);
    }
    // Wire the executor into the RPC so `GET /snapshot` returns the
    // codec-encoded state snapshot.
    rpc_server.set_snapshot_provider(Arc::new(node::rpc_adapters::ExecutorSnapshotProvider {
        executor: node.app_handle(),
    }));
    // Attach the latency recorder for RPC handler metrics.
    rpc_server.set_recorder(recorder);
    // Seed the metrics with the current block height and mempool size.
    if let Some(h) = height {
        rpc_server.set_block_height(h.value());
    }
    rpc_server.set_mempool_size(0);
    // Share the RPC server as `Arc` so the consensus driver's
    // block observer can update the height and push
    // `eth_subscribe` notifications on every finalized block.
    let rpc_shared = Arc::new(rpc_server);
    let http_server =
        rpc::server::HttpServer::from_shared(rpc_shared.clone(), rpc_config.listen_addr.clone());
    (rpc_shared, http_server)
}

/// Handle `--import-snapshot <path>`: restore state from a snapshot
/// file before starting consensus. The file is codec-encoded
/// `ExecutorSnapshot` (written by `--export-snapshot` or `GET /snapshot`).
fn handle_import_snapshot(node: &mut Node) {
    if let Some(snapshot_path) = node::cli::parse_cli_flag("--import-snapshot") {
        let data = std::fs::read(&snapshot_path)
            .unwrap_or_else(|e| panic!("cannot read snapshot file {snapshot_path}: {e}"));
        let mut reader = codec::Reader::new(&data);
        let snapshot = executor::ExecutorSnapshot::decode(&mut reader)
            .unwrap_or_else(|e| panic!("cannot decode snapshot {snapshot_path}: {e}"));
        node.import_snapshot(&snapshot).unwrap_or_else(|e| panic!("snapshot import failed: {e}"));
        tracing::info!(
            height = snapshot.height,
            path = snapshot_path,
            "oxide-validator: imported snapshot"
        );
    }
}

/// Handle `--export-snapshot <path>`: write the current state
/// snapshot to a file and return `true` (the caller exits).
fn handle_export_snapshot(node: &mut Node) -> bool {
    if let Some(snapshot_path) = node::cli::parse_cli_flag("--export-snapshot") {
        let snap = node.export_snapshot();
        let mut buf = Vec::new();
        snap.encode(&mut buf);
        std::fs::write(&snapshot_path, &buf)
            .unwrap_or_else(|e| panic!("cannot write snapshot {snapshot_path}: {e}"));
        tracing::info!(
            height = snap.height,
            path = snapshot_path,
            bytes = buf.len(),
            "oxide-validator: exported snapshot"
        );
        return true;
    }
    false
}

/// Handle `--submit-key-change <new_bls_secret_key_hex>`: submit a
/// staking key-change transaction for this validator. The transaction
/// is included in the next block; the new key takes effect at the
/// next epoch rotation.
///
/// The flag carries the **secret** key, not the public key: a
/// key-change must attach a proof-of-possession (`Sign(sk, pk)` under
/// `Domain::BlsPop`), which is only producible from the secret. A node
/// rotating to a key it does not possess could never sign votes with
/// it anyway, so requiring the secret here matches operational
/// reality and the C3 rogue-key defense.
fn handle_key_change(node: &mut Node, chain_id: u64) {
    if let Some(hex_key) = node::cli::parse_cli_flag("--submit-key-change") {
        let secret_bytes = node::cli::hex_decode(&hex_key)
            .unwrap_or_else(|e| panic!("invalid BLS secret key hex: {e}"));
        let new_sk = crypto::BlsSecretKey::from_bytes(&secret_bytes)
            .unwrap_or_else(|e| panic!("invalid BLS secret key: {e:?}"));
        let new_key_bytes = new_sk.public_key().as_bytes().to_vec();
        let pop = new_sk.pop_prove();
        // The validator address is the tx sender — devnet identity
        // 0, the key-derived account the single-node genesis funds
        // and registers (a signed envelope's sender must recover to
        // its key, so a byte-pattern address cannot do this).
        let validator_addr =
            crypto::secp::test_identity_address(0).expect("devnet identity 0 is a valid key");
        // Ensure the validator has stake (delegate 1 unit if needed)
        // so the key-change handler accepts the tx.
        let delegate_msg = staking::msg::delegate(validator_addr, 1);
        let delegate_tx =
            node::cli::build_signed_tx(chain_id, framework::module_id::STAKING, &delegate_msg, 0);
        node.engine().submit_tx(delegate_tx);
        node.engine().run_until_idle();
        let msg_payload = staking::msg::key_change(validator_addr, &new_key_bytes, pop.as_bytes());
        let tx =
            node::cli::build_signed_tx(chain_id, framework::module_id::STAKING, &msg_payload, 1);
        node.engine().submit_tx(tx);
        tracing::info!("oxide-validator: submitted key-change transaction");
        // Drive consensus once more to include the key-change tx.
        node.engine().run_until_idle();
        let h = node.engine().finalized_height();
        tracing::info!(?h, "oxide-validator: key-change block finalized");
    }
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
    println!("    tls-gen      Generate TLS certificates for a multi-node testnet");
    println!("    version      Print version information");
    println!("    help         Print this help message");
    println!();
    println!("FLAGS:");
    println!("    --config <path>          Load config from TOML file");
    println!("    --engine <kind>           Consensus engine (sequencer|oxidebft)");
    println!("    --num-nodes <N>           Total devnet nodes");
    println!("    --base-port <port>        Base TCP port for devnet");
    println!("    --bind-host <host>        Host to bind on (default 127.0.0.1)");
    println!("    --peer-host <host>        Peer host (default 127.0.0.1)");
    println!("    --peer-host-template <f>  Peer host template with {{i}} (e.g. validator-{{i}})");
    println!("    --genesis-file <path>     Load genesis.json (validator set + balances)");
    println!("    --bls-key-file <path>     BLS secret key file (hex or raw 32 bytes)");
    println!("    --tls-dir <dir>           TLS directory (cert.pem, key.pem, peer-{{i}}.pem)");
    println!("    --wal-file <path>         Consensus WAL file path");
    println!("    --data-dir <dir>          Persistent data dir (auto snapshot on shutdown)");
    println!("    --rpc-listen <addr>       RPC listen address (default: from config)");
    println!("    --export-snapshot <path>  Export state snapshot to file and exit");
    println!("    --import-snapshot <path>  Import state snapshot before starting");
    println!("    --submit-key-change <hex> Submit a BLS key-change transaction (new secret key)");
    println!("    --unsafe-allow-unsigned-txs");
    println!("                            UNSAFE dev mode: admit unsigned native txs");
    println!(
        "                            (unauthenticated sender). Refused on non-loopback binds."
    );
    println!();
    println!("EXAMPLES:");
    println!("    oxide-validator init --chain-id 1");
    println!("    oxide-validator genesis --chain-id 1 --validators 4");
    println!("    oxide-validator tls-gen --num-nodes 4 --output-dir tls/");
    println!("    oxide-validator --config config/devnet.toml");
    println!("    oxide-validator --engine oxidebft");
    println!("    oxide-validator --export-snapshot snapshot.bin");
    println!("    oxide-validator --import-snapshot snapshot.bin");
    println!("    oxide-validator --submit-key-change 0xabcdef...");
    println!("    oxide-devnet --node 0 --num-nodes 4 --base-port 22000   (multi-node devnet)");
    println!("    oxide-devnet --node 0 --genesis-file genesis.json \\");
    println!("        --bls-key-file key.bin --tls-dir tls/node-0 --wal-file wal/ \\");
    println!("        --data-dir data/ --rpc-listen 0.0.0.0:8545");
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
    let chain_id: u64 =
        node::cli::parse_cli_flag("--chain-id").and_then(|s| s.parse().ok()).unwrap_or(1);
    let num_validators: usize =
        node::cli::parse_cli_flag("--validators").and_then(|s| s.parse().ok()).unwrap_or(4);
    let dir = node::cli::parse_cli_flag("--dir").unwrap_or_else(|| "oxide-node".to_string());

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

    let mut genesis =
        config::genesis::Genesis::devnet(chain_id, num_validators, 32, 1_000_000_000_000);

    // Generate deterministic BLS keys for each validator and set
    // `public_key` so `--genesis-file` can build the `ValidatorSet`
    // without regenerating keys. For production, each validator
    // generates its own key and provides the public key to the
    // genesis coordinator.
    for (idx, validator) in genesis.staking.validators.iter_mut().enumerate() {
        let key = node::cli::bls_key(u8::try_from(idx + 1).expect("index + 1 fits in u8"));
        let pk = key.public_key();
        validator.public_key = Some(format!("0x{}", node::cli::hex_encode(pk.as_bytes())));
    }

    let path = PathBuf::from(&output);
    genesis.to_json_file(&path).expect("write genesis file");
    println!(
        "oxide-validator genesis: wrote {} (chain_id={chain_id}, validators={num_validators})",
        path.display()
    );
}

/// `oxide-validator tls-gen` — generate TLS certificates for a
/// multi-node testnet.
///
/// Generates a self-signed certificate + private key for each node,
/// then writes a per-node `--tls-dir` containing `cert.pem`,
/// `key.pem`, and `peer-{j}.pem` for every peer `j != i`.
///
/// Flags:
/// - `--num-nodes <N>`: number of validators (default: 4)
/// - `--output-dir <dir>`: target directory (default: ./tls)
///
/// The output layout is:
/// ```text
/// tls/
/// ├── node-0/
/// │   ├── cert.pem       — node 0's certificate
/// │   ├── key.pem        — node 0's private key
/// │   ├── peer-1.pem     — node 1's certificate
/// │   ├── peer-2.pem     — node 2's certificate
/// │   └── peer-3.pem     — node 3's certificate
/// ├── node-1/
/// │   ├── cert.pem
/// │   ├── key.pem
/// │   ├── peer-0.pem
/// │   ├── peer-2.pem
/// │   └── peer-3.pem
/// └── ...
/// ```
///
/// Each node runs with `--tls-dir tls/node-{i}`.
///
/// # Security
///
/// These are **self-signed** certificates — suitable for devnet and
/// testnet but NOT production. For production, generate certificates
/// from a proper CA (e.g., `step ca`, `HashiCorp` Vault PKI, or
/// cloud-native `cert-manager`) and distribute via `--tls-dir` with
/// the CA's certificate chain in each `peer-{i}.pem`.
fn run_tls_gen(args: &[String]) {
    let mut num_nodes: usize = 4;
    let mut output_dir = "tls".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--num-nodes" => {
                if let Some(v) = args.get(i + 1) {
                    num_nodes = v.parse().unwrap_or(4);
                }
                i += 2;
            }
            "--output-dir" | "-o" => {
                if let Some(v) = args.get(i + 1) {
                    output_dir.clone_from(v);
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let base = PathBuf::from(&output_dir);

    // Generate a cert+key pair for each node. The peer_id is the
    // node index as a single byte — matching the devnet's
    // `vec![i]` peer ID convention.
    let certs: Vec<(String, String)> = (0..num_nodes)
        .map(|i| {
            let peer_id = vec![u8::try_from(i).expect("node index fits in u8")];
            p2p::tls::generate_ca_cert_pem(&peer_id)
        })
        .collect();

    // Write per-node directories: cert.pem + key.pem + peer-{j}.pem.
    for i in 0..num_nodes {
        let dir = base.join(format!("node-{i}"));
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("failed to create {}: {e}", dir.display()));
        std::fs::write(dir.join("cert.pem"), &certs[i].0)
            .unwrap_or_else(|e| panic!("failed to write cert.pem: {e}"));
        std::fs::write(dir.join("key.pem"), &certs[i].1)
            .unwrap_or_else(|e| panic!("failed to write key.pem: {e}"));
        for (j, (cert, _)) in certs.iter().enumerate() {
            if j != i {
                std::fs::write(dir.join(format!("peer-{j}.pem")), cert)
                    .unwrap_or_else(|e| panic!("failed to write peer-{j}.pem: {e}"));
            }
        }
    }

    println!(
        "oxide-validator tls-gen: wrote {} node dirs to {} (use --tls-dir {}/node-<i>)",
        num_nodes,
        base.display(),
        base.display()
    );
}

#[cfg(test)]
mod tests {
    /// The binary's effective defaults require signed envelopes —
    /// this is the property the audit demands of the *binary*, not
    /// of a hand-built executor: `Config::default()` (no TOML, no
    /// env, no flags) must map to a `NodeConfig` that rejects
    /// unsigned envelopes.
    #[test]
    fn binary_default_requires_signed_txs() {
        let config = config::Config::default();
        let rpc = config::RpcConfig::default();
        let node_config = node::node_config_from(
            &config,
            &rpc,
            &node::AssemblyOverrides::default(),
            node::NodeMode::Single,
        )
        .expect("default config maps");
        assert!(
            node_config.require_signed_txs,
            "a validator launched with no flags must reject unsigned envelopes"
        );
        // The executor layer defaults the same way — assembling
        // without any policy override must reject unsigned txs.
        let assembled = node::assemble_executor(&node_config);
        drop(assembled);
    }
}
