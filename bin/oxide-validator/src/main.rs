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
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use node::{ConsensusConfig, Node, NodeConfig};
use ports::transport::Transport;
use ports::{AppInterface, ConsensusEngine};
use types::{MempoolAck, TxBytes};

// Codec traits for encoding/decoding consensus messages.
use codec::{Decode, Encode};

// ── Devnet message tags ───────────────────────────────────────────
// One-byte type tags for the devnet's TCP message framing. The
// first byte of each message identifies the payload type.
const MSG_PROPOSAL: u8 = 0x00;
const MSG_VOTE: u8 = 0x01;
const MSG_QC: u8 = 0x02;
const MSG_TIMEOUT: u8 = 0x03; // timeout signature (view-change init)
const MSG_TC: u8 = 0x04; // timeout certificate (view-change proof)
const MSG_TX: u8 = 0x05; // raw tx envelope gossip (mempool propagation)

/// Build the BLS vote signing message: `view` || `phase` || `block_hash` || `epoch`.
/// This must match the consensus engine's `vote_signing_message`.
fn vote_signing_message(
    view: primitives::View,
    phase: types::VotePhase,
    block_hash: &primitives::Hash,
    epoch: primitives::Epoch,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(49);
    msg.extend_from_slice(&view.value().to_le_bytes());
    msg.push(phase as u8);
    msg.extend_from_slice(block_hash.as_bytes());
    msg.extend_from_slice(&epoch.value().to_le_bytes());
    msg
}

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

/// `TxSubmitter` that additionally gossips accepted transactions to
/// all peers.
///
/// After the local mempool accepts a tx, the *envelope bytes* are
/// pushed onto a channel the consensus loop drains and broadcasts
/// as `MSG_TX` frames. Only locally submitted txs are gossiped —
/// received gossip is ingested but never re-broadcast, so in the
/// full-mesh validator topology each tx traverses exactly one hop
/// and no flood loop forms. The channel is bounded; a full channel
/// drops the gossip copy but never fails the local submission (the
/// originator's mempool still holds the tx, and the keep-alive path
/// ensures liveness for non-gossipped txs is unaffected — peers may
/// simply not see it until resubmission).
struct GossipingTxSubmitter {
    inner: ExecutorTxSubmitter,
    gossip: std::sync::mpsc::SyncSender<Vec<u8>>,
}

impl rpc::TxSubmitter for GossipingTxSubmitter {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        self.inner.submit_tx_ref(&tx)?;
        let _ = self.gossip.try_send(tx.as_bytes().to_vec());
        Ok(())
    }
}

impl ExecutorTxSubmitter {
    /// Submit without consuming `tx` — used by [`GossipingTxSubmitter`]
    /// to keep the bytes for the gossip frame.
    fn submit_tx_ref(&self, tx: &TxBytes) -> Result<(), String> {
        match self.executor.ingest_tx(TxBytes::new(tx.as_bytes().to_vec())) {
            MempoolAck::Accepted => Ok(()),
            MempoolAck::Rejected { reason } => Err(reason),
        }
    }
}

/// Adapter that lets the RPC server serve the `txpool_*` namespace
/// from the executor's mempool.
///
/// The executor's `txpool_snapshot` takes the mempool lock once and
/// clones the pooled envelopes — a cold-path read; the RPC layer
/// holds no lock across the snapshot and the block path is
/// unaffected. Keeping this an adapter (rather than having `rpc`
/// depend on `executor`) preserves the workspace's dependency
/// direction.
struct ExecutorTxpoolProvider {
    executor: Arc<executor::Executor>,
}

impl rpc::TxpoolProvider for ExecutorTxpoolProvider {
    fn txpool_snapshot(&self) -> Vec<rpc::TxpoolItem> {
        self.executor
            .txpool_snapshot()
            .into_iter()
            .map(|(sender, nonce, envelope, pending)| rpc::TxpoolItem {
                sender,
                nonce,
                envelope,
                pending,
            })
            .collect()
    }
}

/// Adapter that lets the RPC server export the executor's state
/// snapshot via the `rpc::SnapshotProvider` trait.
///
/// The executor's `export_snapshot` returns an `ExecutorSnapshot`;
/// this adapter codec-encodes it so the RPC layer can serve it as
/// hex bytes without a direct dependency on the executor crate's
/// internal types.
struct ExecutorSnapshotProvider {
    executor: Arc<executor::Executor>,
}

impl rpc::SnapshotProvider for ExecutorSnapshotProvider {
    fn export_snapshot(&self) -> Result<Vec<u8>, String> {
        let snap = self.executor.export_snapshot();
        let mut buf = Vec::new();
        snap.encode(&mut buf);
        Ok(buf)
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
    let (node_config, rpc_config, _genesis_config) = load_config();
    tracing::info!(
        engine = node_config.consensus.as_str(),
        max_mempool_entries = node_config.max_mempool_entries,
        "oxide-validator: starting"
    );

    let mut node = Node::assemble(&node_config);
    tracing::info!("oxide-validator: assembled stack (executor + core/staking/evm modules)");

    handle_import_snapshot(&mut node);

    // Submit a smoke-test staking delegate to the local validator
    // identity (`Address::ZERO` is genesis-registered on devnet).
    let module_payload = staking::msg::delegate(primitives::Address::ZERO, 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
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

    if handle_export_snapshot(&mut node) {
        return;
    }
    handle_key_change(&mut node);

    // Start the JSON-RPC HTTP server.
    tracing::info!(
        listen_addr = %rpc_config.listen_addr,
        "oxide-validator: starting RPC server"
    );

    // Create a shared latency recorder for the block pipeline and RPC.
    let recorder = Arc::new(metrics::Recorder::new());

    let (rpc_shared, http_server) =
        build_single_node_rpc(&node, &rpc_config, height, recorder.clone());

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
    rpc_server.set_tx_submitter(Arc::new(ExecutorTxSubmitter { executor: node.app_handle() }));
    rpc_server
        .set_txpool_provider(Arc::new(ExecutorTxpoolProvider { executor: node.app_handle() }));
    // Share the executor's EVM module with the RPC so `eth_call`,
    // `eth_getBalance`, and the block/tx/receipt/log lookups serve
    // the same state the executor is committing.
    if let Some(evm_module) = node.evm_module_handle() {
        rpc_server.set_evm(evm_module);
    }
    // Wire the executor into the RPC so `GET /snapshot` returns the
    // codec-encoded state snapshot.
    rpc_server
        .set_snapshot_provider(Arc::new(ExecutorSnapshotProvider { executor: node.app_handle() }));
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
    if let Some(snapshot_path) = parse_cli_flag("--import-snapshot") {
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
    if let Some(snapshot_path) = parse_cli_flag("--export-snapshot") {
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

/// Handle `--submit-key-change <new_bls_pubkey_hex>`: submit a
/// staking key-change transaction for this validator. The transaction
/// is included in the next block; the new key takes effect at the
/// next epoch rotation.
fn handle_key_change(node: &mut Node) {
    if let Some(hex_key) = parse_cli_flag("--submit-key-change") {
        let new_key_bytes =
            hex_decode(&hex_key).unwrap_or_else(|e| panic!("invalid BLS key hex: {e}"));
        // The validator address is the tx sender (Address([0u8; 20])
        // in devnet mode). In production this would be the node's
        // configured validator address.
        let validator_addr = primitives::Address([0u8; 20]);
        // Ensure the validator has stake (delegate 1 unit if needed)
        // so the key-change handler accepts the tx.
        let delegate_msg = staking::msg::delegate(validator_addr, 1);
        let delegate_tx = build_tx(framework::module_id::STAKING, &delegate_msg);
        node.engine().submit_tx(delegate_tx);
        node.engine().run_until_idle();
        let msg_payload = staking::msg::key_change(validator_addr, &new_key_bytes);
        let tx = build_tx(framework::module_id::STAKING, &msg_payload);
        node.engine().submit_tx(tx);
        tracing::info!("oxide-validator: submitted key-change transaction");
        // Drive consensus once more to include the key-change tx.
        node.engine().run_until_idle();
        let h = node.engine().finalized_height();
        tracing::info!(?h, "oxide-validator: key-change block finalized");
    }
}

/// Run a single validator node in a multi-process testnet.
///
/// This is the production deployment path for a validator node. It
/// uses the same `--config` TOML loading, `--genesis-file`, BLS key
/// file, TLS/mTLS, WAL persistence, RPC server, and graceful
/// shutdown infrastructure as `run_single_node`, plus multi-node
/// TCP networking for consensus message passing.
///
/// # Flags
///
/// | Flag | Description |
/// |------|-------------|
/// | `--devnet-node <i>` | This node's validator index (required) |
/// | `--num-nodes <N>` | Total validators (default: from genesis/config) |
/// | `--base-port <p>` | Base TCP port (default: from genesis/config) |
/// | `--bind-host <h>` | Bind address (default: `127.0.0.1`) |
/// | `--peer-host-template <fmt>` | Peer hostname template (`{i}` = index) |
/// | `--config <path>` | TOML config file |
/// | `--genesis-file <path>` | `genesis.json` (validator set + balances) |
/// | `--bls-key-file <path>` | BLS secret key (hex or raw 32 bytes) |
/// | `--tls-dir <dir>` | TLS directory (`cert.pem`, `key.pem`, `peer-{i}.pem`) |
/// | `--wal-file <path>` | Consensus WAL file path |
/// | `--rpc-listen <addr>` | RPC listen address (default: from config) |
/// | `--export-snapshot <path>` | Export snapshot to file and exit |
/// | `--import-snapshot <path>` | Import snapshot from file before starting |
/// | `--submit-key-change <hex>` | Submit a validator key-change tx |
///
/// # Key loading
///
/// `--bls-key-file` loads a 32-byte BLS secret key. The file can be
/// hex-encoded (64 hex chars, with or without `0x`) or raw binary.
/// If omitted, a deterministic key is generated from the node index
/// (devnet convention — **not suitable for production**).
///
/// # Genesis file
///
/// `--genesis-file` loads a `genesis.json` that specifies the
/// validator set (address, BLS public key, stake per validator) and
/// genesis balances. If omitted, a deterministic validator set is
/// generated from `--num-nodes` (devnet convention).
///
/// # TLS
///
/// `--tls-dir` points to a directory containing:
/// - `cert.pem` — this node's X.509 certificate (PEM)
/// - `key.pem` — this node's private key (PEM)
/// - `peer-{i}.pem` — peer `i`'s certificate (for each peer index)
///
/// mTLS is enforced: both sides of every connection authenticate
/// via certificates bound to peer IDs (C4).
///
/// # WAL
///
/// `--wal-file` persists safety-critical consensus state
/// (`last_voted_view`, `voted_at_height`, `high_qc`, `current_view`,
/// `next_height`, `epoch`) to a CRC32-protected file. On restart,
/// `recover_from_wal` restores the state, preventing double-voting
/// and conflicting votes (C9).
///
/// # RPC
///
/// `--rpc-listen` starts the JSON-RPC HTTP server with `eth_*`
/// endpoints, `/health`, `/metrics`, and `/snapshot`. If omitted,
/// the node's `rpc.listen_addr` config is used.
#[allow(clippy::too_many_lines)]
fn run_devnet_node(node_index_str: &str) {
    // Load base config (TOML + env vars + CLI overrides).
    let (node_config, rpc_config, genesis_config) = load_config();

    let node_index: usize =
        node_index_str.parse().unwrap_or_else(|e| panic!("invalid --devnet-node index: {e}"));
    let num_nodes: usize = parse_cli_flag("--num-nodes")
        .and_then(|s| s.parse().ok())
        .unwrap_or(genesis_config.num_validators);
    let base_port: u16 = parse_cli_flag("--base-port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(genesis_config.base_port);
    let bind_host = parse_cli_flag("--bind-host").unwrap_or_else(|| "127.0.0.1".to_string());
    let peer_host_template =
        parse_cli_flag("--peer-host-template").or_else(|| parse_cli_flag("--peer-host"));

    println!(
        "oxide-validator[{node_index}]: devnet node mode — index={node_index}, num_nodes={num_nodes}, base_port={base_port}, bind_host={bind_host}"
    );

    // BLS key: --bls-key-file or deterministic.
    let our_key = load_bls_key(node_index);

    // ValidatorSet: --genesis-file or deterministic.
    let validator_set = load_validator_set(num_nodes, node_index);

    let listen_port = base_port + u16::try_from(node_index).expect("port fits in u16");
    let listen_addr = format!("{bind_host}:{listen_port}");

    // Build peer list: all other nodes.
    let peers: Vec<(Vec<u8>, String)> = (0..num_nodes)
        .filter(|&i| i != node_index)
        .map(|i| {
            let port = base_port + u16::try_from(i).expect("port fits in u16");
            let host = match &peer_host_template {
                Some(tmpl) => tmpl.replace("{i}", &i.to_string()),
                None => "127.0.0.1".to_string(),
            };
            (vec![u8::try_from(i).expect("peer id fits in u8")], format!("{host}:{port}"))
        })
        .collect();

    println!("oxide-validator[{node_index}]: listening on {listen_addr}, {} peers", peers.len());

    // Create the executor with modules. If --genesis-file was given,
    // the staking module registers the genesis validators directly
    // (bypassing the delegate-transaction path — genesis state is
    // not a user tx).
    let genesis = parse_cli_flag("--genesis-file").map(|p| {
        config::genesis::Genesis::from_json_file(&PathBuf::from(&p))
            .unwrap_or_else(|e| panic!("failed to load genesis file {p}: {e}"))
    });
    let (executor, evm_module) =
        build_devnet_executor(&genesis_config, &node_config, &rpc_config, genesis.as_ref());
    let app: Arc<executor::Executor> = Arc::new(executor);
    let app_dyn: Arc<dyn ports::AppInterface> = app.clone();

    // Create the TCP transport: --tls-dir for mTLS, plain TCP
    // otherwise.
    let mut transport = build_transport(&listen_addr, node_index, peers);

    // Give connections time to establish. TLS handshakes take
    // longer than plain TCP — 2s gives all peers time to connect
    // and complete the handshake before the first proposal.
    thread::sleep(Duration::from_millis(2000));

    // Create the consensus engine.
    let validator_set_clone = validator_set.clone();
    let mut engine = consensus::OxideBft::with_index(
        app_dyn,
        validator_set,
        u16::try_from(node_index).expect("index fits in u16"),
    )
    .with_secret_key(our_key.clone());

    // WAL persistence: --wal-file.
    if let Some(wal_path) = parse_cli_flag("--wal-file") {
        let wal = consensus::wal::Wal::open(&wal_path).expect("wal open");
        engine = engine.with_wal(wal);
        engine.recover_from_wal().expect("wal recover");
        println!("oxide-validator[{node_index}]: WAL loaded from {wal_path}");
    }

    // Data directory: --data-dir <dir> enables auto-snapshot
    // persistence — on startup, if `<dir>/snapshot.bin` exists,
    // import it; on shutdown, export the current state to
    // `<dir>/snapshot.bin`.
    //
    // This gives a restarting validator full state persistence
    // without requiring manual `--export-snapshot` /
    // `--import-snapshot` flags. The WAL (if `--wal-file` is also
    // given) protects consensus safety state across the restart.
    let data_dir = parse_cli_flag("--data-dir");
    if let Some(ref dir) = data_dir {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed to create data dir {dir}: {e}"));
        let snap_path = format!("{dir}/snapshot.bin");
        if std::path::Path::new(&snap_path).exists() {
            let bytes = std::fs::read(&snap_path)
                .unwrap_or_else(|e| panic!("failed to read snapshot {snap_path}: {e}"));
            let mut reader = codec::Reader::new(&bytes);
            let snap = executor::ExecutorSnapshot::decode(&mut reader)
                .unwrap_or_else(|e| panic!("failed to decode snapshot {snap_path}: {e}"));
            app.import_snapshot(&snap)
                .unwrap_or_else(|e| panic!("failed to import snapshot {snap_path}: {e}"));
            println!(
                "oxide-validator[{node_index}]: imported snapshot from {snap_path} (height {})",
                snap.height
            );
        }
    }

    // Shared validator set — the consensus loop writes the updated
    // set after each epoch rotation; the RPC handler reads it for
    // `GET /validator-set`.
    let shared_validator_set = Arc::new(std::sync::RwLock::new(validator_set_clone.clone()));

    // Tx-gossip channel: the RPC submitter pushes accepted txs here;
    // the consensus loop drains it and broadcasts `MSG_TX` frames to
    // all peers. Bounded at 10k — a full channel drops the gossip
    // copy (local submission already succeeded) instead of blocking
    // the RPC thread.
    let (gossip_tx, gossip_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(10_000);

    // Start the RPC server if --rpc-listen or rpc.listen_addr is set.
    let rpc_handle = start_devnet_rpc(
        &rpc_config,
        &app,
        node_index,
        shared_validator_set.clone(),
        &evm_module,
        gossip_tx,
    );

    println!("oxide-validator[{node_index}]: consensus engine started, waiting for blocks...");

    // Submit a smoke-test transaction: a staking delegate to the
    // devnet validator identity `Address::ZERO` (registered at
    // genesis in `build_devnet_executor`).
    let module_payload = staking::msg::delegate(primitives::Address::ZERO, 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    engine.submit_tx(tx);

    let height = engine.finalized_height();
    println!("oxide-validator[{node_index}]: finalized height = {height:?}");
    println!("oxide-validator[{node_index}]: node running (press Ctrl+C to stop)");

    // Graceful shutdown: SIGINT/SIGTERM sets the shutdown flag, which
    // `run_consensus_loop` checks each iteration. On Unix, SIGTERM
    // is handled via `signal(SignalKind::terminate())`; on other
    // platforms, only SIGINT (Ctrl+C) is caught.
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("signal runtime");
        rt.block_on(async {
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("sigterm handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = sigterm.recv() => {},
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.expect("ctrl_c handler");
            }
            shutdown_clone.store(true, Ordering::Relaxed);
        });
    });

    // Run the consensus message pump loop.
    run_consensus_loop(
        &mut engine,
        &mut transport,
        &validator_set_clone,
        &our_key,
        node_index,
        num_nodes,
        shutdown.as_ref(),
        rpc_handle.as_deref(),
        &shared_validator_set,
        &gossip_rx,
    );

    // Graceful shutdown: if --data-dir is set, export the current
    // state to `<dir>/snapshot.bin` so a restart can resume with
    // the full chain state (not just the WAL).
    if let Some(ref dir) = data_dir {
        let snap = app.export_snapshot();
        let mut buf = Vec::new();
        snap.encode(&mut buf);
        let snap_path = format!("{dir}/snapshot.bin");
        std::fs::write(&snap_path, &buf)
            .unwrap_or_else(|e| panic!("failed to write snapshot {snap_path}: {e}"));
        println!(
            "oxide-validator[{node_index}]: exported snapshot to {snap_path} (height {})",
            snap.height
        );
    }
    println!("oxide-validator[{node_index}]: shutdown complete");
}

/// Load a BLS secret key: `--bls-key-file` (hex or raw 32 bytes) or
/// deterministic from node index (devnet fallback).
///
/// # Panics
///
/// Panics if `--bls-key-file` is given but the file cannot be read,
/// decoded, or parsed into a valid `BlsSecretKey`.
fn load_bls_key(index: usize) -> crypto::BlsSecretKey {
    if let Some(path) = parse_cli_flag("--bls-key-file") {
        let raw = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("failed to read BLS key file {path}: {e}"));
        // Try hex decode first (64 hex chars), fall back to raw bytes.
        let bytes: Vec<u8> = if raw.len() == 64 || (raw.len() == 66 && raw.starts_with(b"0x")) {
            let text = std::str::from_utf8(&raw).expect("hex BLS key is UTF-8");
            hex_decode(text).expect("hex decode BLS key")
        } else {
            raw
        };
        crypto::BlsSecretKey::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("invalid BLS secret key in {path}: {e:?}"))
    } else {
        // Deterministic devnet fallback — NOT suitable for production.
        bls_key(u8::try_from(index + 1).expect("index + 1 fits in u8"))
    }
}

/// Build a `ValidatorSet`: `--genesis-file` (from `genesis.json`) or
/// deterministic devnet convention.
///
/// # Panics
///
/// Panics if `--genesis-file` is given but the file cannot be loaded,
/// or if the genesis validator count doesn't match `--num-nodes`, or
/// if a validator's `public_key` is missing/invalid.
fn load_validator_set(num_nodes: usize, _node_index: usize) -> consensus::ValidatorSet {
    if let Some(path) = parse_cli_flag("--genesis-file") {
        let genesis = config::genesis::Genesis::from_json_file(&PathBuf::from(&path))
            .unwrap_or_else(|e| panic!("failed to load genesis file {path}: {e}"));
        let validators = &genesis.staking.validators;
        assert_eq!(
            validators.len(),
            num_nodes,
            "genesis validator count {} doesn't match --num-nodes {num_nodes}",
            validators.len()
        );
        let pks: Vec<crypto::bls::PublicKey> = validators
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let hex = v.public_key.as_ref().unwrap_or_else(|| {
                    panic!("genesis validator {i} missing public_key — required for multi-node")
                });
                let bytes = hex_decode(hex).unwrap_or_else(|e| {
                    panic!("genesis validator {i} invalid public_key hex: {e}")
                });
                crypto::bls::PublicKey::from_slice(&bytes)
                    .unwrap_or_else(|_| panic!("genesis validator {i} invalid BLS public key"))
            })
            .collect();
        let stakes: Vec<u64> = validators.iter().map(|v| v.stake).collect();
        let addresses: Vec<primitives::Address> = validators
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let bytes = hex_decode(&v.address)
                    .unwrap_or_else(|e| panic!("genesis validator {i} invalid address hex: {e}"));
                primitives::Address(
                    bytes.try_into().unwrap_or_else(|_| {
                        panic!("genesis validator {i} address must be 20 bytes")
                    }),
                )
            })
            .collect();
        consensus::ValidatorSet::with_addresses(pks, stakes, addresses)
            .expect("genesis validator set")
    } else {
        // Deterministic devnet fallback — NOT suitable for production.
        let secret_keys: Vec<crypto::BlsSecretKey> =
            (1..=u8::try_from(num_nodes).expect("num_nodes fits in u8")).map(bls_key).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            secret_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let stakes = vec![1u64; num_nodes];
        let addresses: Vec<primitives::Address> = (0..num_nodes)
            .map(|i| primitives::Address([u8::try_from(i).unwrap_or(0); 20]))
            .collect();
        consensus::ValidatorSet::with_addresses(pks, stakes, addresses).expect("validator set")
    }
}

/// Build the devnet executor with core, staking, and EVM modules.
///
/// The EVM account store is the single native-token ledger: it is
/// built first so staking settles through it, genesis `bank`
/// balances fold into `evm.alloc` (base units → wei), and the EVM
/// module collects native-module fees.
///
/// Uses `genesis_config` for the number of pre-funded senders and
/// genesis balance, `node_config` for executor params (mempool size,
/// parallel threshold), and `rpc_config` for the EVM chain ID and
/// base fee so `eth_chainId`/`eth_gasPrice` agree with execution.
///
/// Returns the executor and the shared `Arc<EvmModule>` so the RPC
/// server can serve `eth_*` reads against the same instance the
/// executor commits.
fn build_devnet_executor(
    genesis_config: &config::GenesisConfig,
    node_config: &NodeConfig,
    rpc_config: &config::RpcConfig,
    genesis: Option<&config::genesis::Genesis>,
) -> (executor::Executor, Arc<evm::EvmModule>) {
    let mut executor = executor::Executor::with_config(
        node_config.max_mempool_entries,
        node_config.parallel_threshold,
    )
    .with_chain_id(rpc_config.chain_id)
    .with_unsigned_tx_policy(if node_config.require_signed_txs {
        executor::UnsignedTxPolicy::Reject
    } else {
        executor::UnsignedTxPolicy::Allow
    });
    executor.register_module(Arc::new(oxide_core::CoreModule::new()));

    // EVM module first: it is the native-token ledger every other
    // module settles through, so it must exist before staking wires
    // its `Balances` handle. Uses the RPC-config chain ID/base fee
    // so the advertised and enforced parameters agree.
    let evm_module = Arc::new(evm::EvmModule::new(rpc_config.chain_id, rpc_config.base_fee));
    // Canonical preinstalls first — a user `alloc` entry below can
    // still intentionally override a preinstall address.
    evm_module.install_preinstalls();

    apply_genesis_balances(&evm_module, genesis_config, genesis);
    executor.register_module(evm_module.clone());
    // The EVM ledger collects fees for all native-module txs —
    // without this the module txs ran free.
    executor.set_fee_module(framework::module_id::EVM);

    // Staking module: register genesis validators directly if
    // --genesis-file was given; otherwise use deterministic devnet
    // validators (Address([i; 20]) with stake 1).
    let staking_module = staking::StakingModule::new();
    if let Some(genesis) = genesis {
        for v in &genesis.staking.validators {
            let addr_bytes = hex_decode(&v.address)
                .unwrap_or_else(|e| panic!("genesis validator invalid address: {e}"));
            let addr: [u8; 20] = addr_bytes
                .try_into()
                .unwrap_or_else(|_| panic!("genesis validator address must be 20 bytes"));
            staking_module.genesis_register_validator(primitives::Address(addr), v.stake);
        }
    } else {
        // Deterministic devnet fallback — NOT suitable for production.
        for i in 0..genesis_config.num_validators {
            let addr = primitives::Address([u8::try_from(i).unwrap_or(0); 20]);
            staking_module.genesis_register_validator(addr, 1_000_000);
        }
    }
    // Delegation is EVM-ledger-backed: `delegate` debits the
    // delegator into the bonded pool, unbonding refunds from it.
    // Genesis stake registered above is unattributed (declaration
    // stake, not pool-backed) and cannot be undelegated.
    staking_module.set_ledger(evm_module.clone());
    executor.register_module(Arc::new(staking_module));

    // Apply the genesis `alloc` map (Ethereum `genesis.json`
    // convention): balances, nonces, code, and storage for
    // pre-funded accounts and preinstalled contracts.
    if let Some(genesis) = genesis {
        for (addr_hex, account) in &genesis.evm.alloc {
            let addr_bytes = hex_decode(addr_hex)
                .unwrap_or_else(|e| panic!("genesis evm.alloc invalid address: {e}"));
            let addr: [u8; 20] = addr_bytes
                .try_into()
                .unwrap_or_else(|_| panic!("genesis evm.alloc address must be 20 bytes"));
            let balance = if let Some(hex) = account.balance.strip_prefix("0x") {
                u128::from_str_radix(hex, 16)
            } else {
                account.balance.parse::<u128>()
            }
            .unwrap_or_else(|e| panic!("genesis evm.alloc invalid balance: {e}"));
            let code = account
                .code
                .as_deref()
                .map(|c| hex_decode(c).unwrap_or_else(|e| panic!("evm.alloc code: {e}")))
                .unwrap_or_default();
            let storage = account
                .storage
                .iter()
                .map(|(slot, value)| {
                    let slot = alloy_primitives::U256::from_str_radix(
                        slot.strip_prefix("0x").unwrap_or(slot),
                        16,
                    )
                    .unwrap_or_else(|e| panic!("evm.alloc slot: {e}"));
                    let value = alloy_primitives::U256::from_str_radix(
                        value.strip_prefix("0x").unwrap_or(value),
                        16,
                    )
                    .unwrap_or_else(|e| panic!("evm.alloc storage value: {e}"));
                    (slot, value)
                })
                .collect();
            evm_module.genesis_insert_account(
                &primitives::Address(addr),
                balance,
                account.nonce,
                code,
                storage,
            );
        }
    }
    executor.register_module(evm_module.clone());
    (executor, evm_module)
}

/// Apply genesis native-token balances to the EVM account store.
///
/// With `--genesis-file`: the legacy `bank.balances` map (base
/// units) folds into the EVM ledger scaled to wei — the EVM store
/// is the single ledger, there is no separate bank. Without one:
/// the deterministic devnet pre-funded senders get
/// `genesis_config.genesis_balance` units each.
fn apply_genesis_balances(
    evm_module: &evm::EvmModule,
    genesis_config: &config::GenesisConfig,
    genesis: Option<&config::genesis::Genesis>,
) {
    if let Some(genesis) = genesis {
        for (addr_hex, balance_val) in &genesis.bank.balances {
            let balance = balance_val.as_u64().unwrap_or(0);
            if let Ok(bytes) = hex_decode(addr_hex) {
                if let Ok(addr) = <[u8; 20]>::try_from(bytes.as_slice()) {
                    evm_module.genesis_insert_account(
                        &primitives::Address(addr),
                        u128::from(balance) * framework::WEI_PER_UNIT,
                        0,
                        Vec::new(),
                        Vec::new(),
                    );
                }
            }
        }
    } else {
        for sender_byte in 0..genesis_config.num_prefunded_senders {
            evm_module.genesis_insert_account(
                &primitives::Address([sender_byte; 20]),
                u128::from(genesis_config.genesis_balance) * framework::WEI_PER_UNIT,
                0,
                Vec::new(),
                Vec::new(),
            );
        }
    }
}

/// Build the TCP transport: `--tls-dir` for mTLS, plain TCP otherwise.
///
/// # Panics
///
/// Panics if `--tls-dir` is given but the TLS config cannot be built
/// (missing cert/key files, invalid PEM, etc.).
fn build_transport(
    listen_addr: &str,
    node_index: usize,
    peers: Vec<(Vec<u8>, String)>,
) -> p2p::tcp::TcpTransport {
    if let Some(tls_dir) = parse_cli_flag("--tls-dir") {
        let cert_path = format!("{tls_dir}/cert.pem");
        let key_path = format!("{tls_dir}/key.pem");
        let trusted_peers: Vec<(Vec<u8>, String)> = peers
            .iter()
            .map(|(peer_id, _)| {
                let peer_num = peer_id[0] as usize;
                (peer_id.clone(), format!("{tls_dir}/peer-{peer_num}.pem"))
            })
            .collect();
        let trusted_peers_refs: Vec<(Vec<u8>, &str)> =
            trusted_peers.iter().map(|(id, path)| (id.clone(), path.as_str())).collect();
        let tls_config =
            p2p::tls::TlsConfig::from_files(&cert_path, &key_path, &trusted_peers_refs)
                .unwrap_or_else(|e| panic!("failed to build TLS config from {tls_dir}: {e}"));
        println!("oxide-validator[{node_index}]: mTLS enabled ({tls_dir})");
        p2p::tcp::TcpTransport::with_tls(
            listen_addr,
            vec![u8::try_from(node_index).expect("peer id fits in u8")],
            peers,
            p2p::tcp::TcpTransportConfig::default(),
            tls_config,
        )
    } else {
        p2p::tcp::TcpTransport::new(
            listen_addr,
            vec![u8::try_from(node_index).expect("peer id fits in u8")],
            peers,
        )
    }
}

/// A `ValidatorSetProvider` that reads from a shared
/// `Arc<RwLock<ValidatorSet>>` — the consensus loop writes the
/// updated set after each epoch rotation; the RPC handler reads it.
struct SharedValidatorSetProvider {
    /// The shared validator set — written by the consensus loop
    /// after `rotate_epoch`, read by the RPC handler.
    set: std::sync::Arc<std::sync::RwLock<consensus::ValidatorSet>>,
}

impl rpc::ValidatorSetProvider for SharedValidatorSetProvider {
    fn validator_set(&self) -> Result<Vec<rpc::ValidatorSetEntry>, String> {
        let set = self.set.read().map_err(|e| format!("validator set lock poisoned: {e}"))?;
        let entries = set
            .validator_addresses()
            .iter()
            .zip(set.public_keys().iter())
            .zip(set.stakes().iter())
            .map(|((addr, pk), stake)| rpc::ValidatorSetEntry {
                address: format!("0x{}", hex_encode(&addr.0)),
                public_key: format!("0x{}", hex_encode(pk.as_bytes())),
                stake: *stake,
            })
            .collect();
        Ok(entries)
    }
}

/// Start the RPC server for a devnet node: `--rpc-listen` overrides
/// the config's `rpc.listen_addr`.
///
/// Returns a handle to the `RpcServer` for metrics updates, or
/// `None` if no RPC address is configured.
///
/// The HTTP server is spawned on a dedicated tokio runtime thread so
/// the consensus loop can run on the main thread.
#[allow(clippy::too_many_arguments)]
fn start_devnet_rpc(
    rpc_config: &config::RpcConfig,
    app: &Arc<executor::Executor>,
    node_index: usize,
    shared_validator_set: Arc<std::sync::RwLock<consensus::ValidatorSet>>,
    evm_module: &Arc<evm::EvmModule>,
    gossip_tx: std::sync::mpsc::SyncSender<Vec<u8>>,
) -> Option<Arc<rpc::RpcServer>> {
    let listen = parse_cli_flag("--rpc-listen").or_else(|| {
        if rpc_config.listen_addr.is_empty() { None } else { Some(rpc_config.listen_addr.clone()) }
    })?;

    let mut rpc_server = rpc::RpcServer::new(rpc_config.chain_id, rpc_config.base_fee);
    // Gossip-aware submitter: accepted txs are broadcast to all peers
    // so a tx sent to a non-leader still reaches the current leader.
    rpc_server.set_tx_submitter(Arc::new(GossipingTxSubmitter {
        inner: ExecutorTxSubmitter { executor: app.clone() },
        gossip: gossip_tx,
    }));
    rpc_server.set_evm(evm_module.clone());
    rpc_server.set_txpool_provider(Arc::new(ExecutorTxpoolProvider { executor: app.clone() }));
    rpc_server.set_snapshot_provider(Arc::new(ExecutorSnapshotProvider { executor: app.clone() }));
    rpc_server.set_validator_set_provider(Arc::new(SharedValidatorSetProvider {
        set: shared_validator_set,
    }));
    let rpc = Arc::new(rpc_server);
    let http_server = rpc::server::HttpServer::from_shared(rpc.clone(), listen.clone());

    // Spawn the HTTP server on a dedicated tokio runtime thread so
    // the consensus loop can run on the main thread.
    let rpc_clone = rpc.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rpc runtime");
        rt.block_on(async move {
            http_server.serve().await;
        });
    });

    println!("oxide-validator[{node_index}]: RPC server on http://{listen}");
    Some(rpc_clone)
}

/// The consensus message pump loop: proposes, votes, drains the
/// transport, forms QCs, advances views, and syncs heights.
///
/// This is the distributed equivalent of the in-process devnet's
/// `pipelined_tick`. Each iteration:
/// 1. Leader proposes and broadcasts to followers.
/// 2. Followers vote on pending proposals.
/// 3. Drain inbound transport messages (proposals, votes, QCs).
/// 4. Form QC if quorum reached, broadcast to peers.
/// 5. Advance views and sync heights.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_consensus_loop(
    engine: &mut consensus::OxideBft,
    transport: &mut p2p::tcp::TcpTransport,
    validator_set: &consensus::ValidatorSet,
    our_key: &crypto::BlsSecretKey,
    node_index: usize,
    num_nodes: usize,
    shutdown: &AtomicBool,
    rpc: Option<&rpc::RpcServer>,
    shared_validator_set: &std::sync::RwLock<consensus::ValidatorSet>,
    gossip_rx: &std::sync::mpsc::Receiver<Vec<u8>>,
) {
    // Gossip dedup cap: tx hashes we've already ingested (ours +
    // peers'). 100k entries covers several blocks' worth of txs; a
    // duplicate arriving after eviction is re-ingested harmlessly
    // (the executor's nonce-replay check still applies).
    const GOSSIP_SEEN_CAP: usize = 100_000;
    // Track proposals received from the network. Followers vote on
    // these proposals; the leader proposes locally.
    let mut pending_proposals: Vec<(types::BlockHeader, types::Proposal)> = Vec::new();
    let mut voted_views: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut proposed_views: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut last_reported_height: u64 = 0;
    let mut iter_count: u64 = 0;
    // H4 fix: the executor now rejects replayed nonces. The keep-alive
    // tx must use an incrementing nonce so it's not rejected after
    // the first block finalizes nonce 0.
    let mut keepalive_nonce: u64 = 0;
    // View-change timeout tracking. The pacemaker has an internal
    // timeout duration (base 2s, exponential backoff). We track when
    // the current view started; if it hasn't advanced within the
    // timeout, we fire `on_timeout()` and broadcast the timeout
    // signature to all peers. This is essential for recovering from
    // a byzantine or crashed leader — without it, the consensus
    // stalls forever when the leader stops proposing.
    let mut view_start = std::time::Instant::now();
    let mut timeout_sent_for_view: Option<u64> = None;
    // Track the last epoch — when `engine.epoch()` increments, the
    // validator set was rotated by `complete_rotation`. Update the
    // shared set so `GET /validator-set` reflects the new set.
    let mut last_epoch = engine.epoch().value();
    let mut seen_txs: std::collections::HashSet<primitives::Hash> =
        std::collections::HashSet::with_capacity(GOSSIP_SEEN_CAP.min(4096));
    let mut seen_txs_fifo: std::collections::VecDeque<primitives::Hash> =
        std::collections::VecDeque::new();

    loop {
        // Graceful shutdown: SIGINT/SIGTERM sets the flag, we break
        // cleanly so the transport can flush and the WAL can be
        // closed by `Drop`.
        if shutdown.load(Ordering::Relaxed) {
            println!("oxide-validator[{node_index}]: shutdown signal received, stopping");
            break;
        }

        iter_count += 1;

        // Phase 0: submit a keep-alive transaction every 50 iterations
        // to ensure the mempool is never empty (the leader won't propose
        // empty blocks without pending txs).
        if iter_count % 50 == 1 {
            let module_payload = staking::msg::delegate(primitives::Address::ZERO, 1);
            let tx = build_tx_with_nonce(
                framework::module_id::STAKING,
                &module_payload,
                keepalive_nonce,
            );
            let _ack = engine.submit_tx(tx);
            keepalive_nonce += 1;
        }

        // Phase 1: propose (if leader and haven't proposed this view).
        let view = engine.current_view().value();
        let leader_idx = usize::from(validator_set.leader(engine.current_view()));
        if node_index == leader_idx && !proposed_views.contains(&view) {
            if view > 0 && engine.high_qc().is_none() {
                // Need the previous QC before proposing.
            } else if let Some((header, proposal)) = engine.propose() {
                let block_hash = consensus::OxideBft::block_hash(&header);
                let proposal_view = header.view.value();
                proposed_views.insert(proposal_view);
                pending_proposals.push((header.clone(), proposal.clone()));
                // Leader self-votes directly (no network).
                let msg = vote_signing_message(
                    header.view,
                    types::VotePhase::Prepare,
                    &block_hash,
                    engine.epoch(),
                );
                let sig = our_key.sign(crypto::hash::Domain::Vote, &msg);
                let leader_vote = types::Vote {
                    view: header.view,
                    phase: types::VotePhase::Prepare,
                    block_hash,
                    signature: sig,
                };
                let _ = engine.collect_vote(u16::try_from(node_index).unwrap(), leader_vote);
                voted_views.insert(proposal_view);
                // Broadcast proposal to followers.
                let mut buf = Vec::with_capacity(1 + 512);
                buf.push(MSG_PROPOSAL);
                header.encode(&mut buf);
                proposal.encode(&mut buf);
                for i in 0..num_nodes {
                    if i != node_index {
                        let _ = transport.send(&vec![u8::try_from(i).unwrap()], &buf);
                    }
                }
            }
        }

        // Phase 2: vote on pending proposals (followers).
        for (header, proposal) in &pending_proposals {
            let proposal_view = header.view.value();
            if voted_views.contains(&proposal_view) {
                continue;
            }
            let leader = usize::from(validator_set.leader(header.view));
            if node_index == leader {
                continue; // Leader already self-voted.
            }
            if let Some(vote) = engine.vote(header, proposal) {
                let mut buf = Vec::with_capacity(1 + 137);
                buf.push(MSG_VOTE);
                vote.encode(&mut buf);
                let _ = transport.send(&vec![u8::try_from(leader).unwrap()], &buf);
                voted_views.insert(proposal_view);
            }
        }

        // Phase 3: drain inbound transport messages.
        while let Some(msg) = transport.recv() {
            if msg.bytes.is_empty() {
                continue;
            }
            let tag = msg.bytes[0];
            let mut reader = codec::Reader::new(&msg.bytes[1..]);
            match tag {
                MSG_PROPOSAL => {
                    if let (Ok(header), Ok(proposal)) = (
                        types::BlockHeader::decode(&mut reader),
                        types::Proposal::decode(&mut reader),
                    ) {
                        // Sync our next_height from the proposal's
                        // height. Without this, a follower that
                        // becomes the leader after a view change
                        // would propose at a stale height,
                        // re-executing an already-finalized height
                        // with different transactions and corrupting
                        // chain state.
                        engine.observe_block_height(header.height);
                        pending_proposals.push((header, proposal));
                    }
                }
                MSG_VOTE => {
                    if let Ok(vote) = types::Vote::decode(&mut reader) {
                        let voter_idx = u16::from(msg.from[0]);
                        let _ = engine.collect_vote(voter_idx, vote);
                    }
                }
                MSG_QC => {
                    if let Ok(qc) = types::QuorumCertificate::decode(&mut reader) {
                        let _ = engine.deliver_qc(qc);
                    }
                }
                MSG_TX => {
                    // Raw tx envelope gossiped by a peer's RPC
                    // (`eth_sendRawTransaction`). Ingest into our
                    // mempool — the leader may be a different node,
                    // so without gossip a tx submitted to a non-leader
                    // would sit until that node's leader turn.
                    //
                    // Never re-broadcast: in the full-mesh validator
                    // topology a single hop reaches every peer, and
                    // re-gossip would loop indefinitely.
                    let payload = &msg.bytes[1..];
                    let tx_hash =
                        crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, payload);
                    if seen_txs.insert(tx_hash) {
                        seen_txs_fifo.push_back(tx_hash);
                        if seen_txs_fifo.len() > GOSSIP_SEEN_CAP
                            && let Some(old) = seen_txs_fifo.pop_front()
                        {
                            seen_txs.remove(&old);
                        }
                        let _ = engine.submit_tx(TxBytes::new(payload.to_vec()));
                        // Feed pending-tx subscribers/filters — the
                        // Ethereum hash is keccak256 of the signed
                        // RLP inside the envelope, not the envelope
                        // hash used for dedup.
                        if let Some(rpc) = rpc
                            && let Some(raw) = evm::unwrap_evm_tx_envelope(payload)
                        {
                            rpc.record_pending_tx(alloy_primitives::keccak256(raw));
                        }
                    }
                }
                MSG_TIMEOUT => {
                    // View-change timeout signature from a peer.
                    // Format: [voter_idx: 1B][view: 8B][epoch: 8B][signature: 96B]
                    if let Ok(voter_idx_byte) = reader.read_u8() {
                        if let Ok(sig_view) = reader.read_u64() {
                            if let Ok(sig_epoch) = reader.read_u64() {
                                if let Ok(sig) = crypto::Signature::decode(&mut reader) {
                                    let voter_idx = u16::from(voter_idx_byte);
                                    let my_epoch = engine.epoch().value();
                                    // Ignore timeout sigs from a different
                                    // epoch — they are not valid for this epoch.
                                    if sig_epoch != my_epoch {
                                        continue;
                                    }
                                    // If the sig is for a past view, ignore it
                                    // (stale — the sender is behind us).
                                    if sig_view < engine.current_view().value() {
                                        continue;
                                    }
                                    // If the sig is for a higher view, catch up
                                    // to that view. This lets validators that
                                    // fell behind (e.g., after a partition)
                                    // converge to the highest view among them,
                                    // so they can all sign for the same view and
                                    // form a TC. Without this, validators at
                                    // adjacent views can never collect each
                                    // other's sigs and the cluster stalls.
                                    if sig_view > engine.current_view().value() {
                                        engine.sync_to_view(primitives::View::new(sig_view));
                                        view_start = std::time::Instant::now();
                                        timeout_sent_for_view = None;
                                    }
                                    match engine.collect_timeout_signature(voter_idx, sig) {
                                        Ok(Some(tc)) => {
                                            // TC formed — broadcast to all peers.
                                            eprintln!(
                                                "oxide-validator[{node_index}]: TC formed after collecting timeout sig from voter={voter_idx} view={}",
                                                engine.current_view().value()
                                            );
                                            let mut tc_buf = Vec::with_capacity(1 + 200);
                                            tc_buf.push(MSG_TC);
                                            tc.encode(&mut tc_buf);
                                            for i in 0..num_nodes {
                                                if i != node_index {
                                                    let _ = transport.send(
                                                        &vec![u8::try_from(i).unwrap()],
                                                        &tc_buf,
                                                    );
                                                }
                                            }
                                            view_start = std::time::Instant::now();
                                            timeout_sent_for_view = None;
                                        }
                                        Ok(None) => {
                                            // Timeout sig collected but
                                            // no TC yet — no log needed
                                            // (this is the common case).
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "oxide-validator[{node_index}]: timeout sig from voter={voter_idx} rejected: {e:?}"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                MSG_TC => {
                    // Timeout certificate from a peer — advance the view.
                    if let Ok(tc) = types::TimeoutCertificate::decode(&mut reader) {
                        match engine.on_timeout_certificate(&tc) {
                            Ok(()) => {
                                view_start = std::time::Instant::now();
                                timeout_sent_for_view = None;
                            }
                            Err(e) => {
                                eprintln!("oxide-validator[{node_index}]: TC rejected: {e:?}");
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Phase 3b: drain the tx-gossip channel — the RPC submitter
        // pushes locally-accepted txs here; broadcast each as a
        // `MSG_TX` frame to every peer. Bounded by the channel cap
        // (10k), so worst case this drains 10k frames in one
        // iteration — each send is a channel push to the peer's
        // writer task, non-blocking.
        while let Ok(tx_bytes) = gossip_rx.try_recv() {
            // Record locally-originated txs in the dedup set too, so a
            // peer that somehow reflects our frame back is dropped.
            let tx_hash =
                crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, &tx_bytes);
            if seen_txs.insert(tx_hash) {
                seen_txs_fifo.push_back(tx_hash);
                if seen_txs_fifo.len() > GOSSIP_SEEN_CAP
                    && let Some(old) = seen_txs_fifo.pop_front()
                {
                    seen_txs.remove(&old);
                }
            }
            let mut buf = Vec::with_capacity(1 + tx_bytes.len());
            buf.push(MSG_TX);
            buf.extend_from_slice(&tx_bytes);
            for i in 0..num_nodes {
                if i != node_index {
                    let _ = transport.send(&vec![u8::try_from(i).unwrap()], &buf);
                }
            }
        }

        // Phase 4: form QC (if quorum reached).
        if let Some(qc) = engine.try_form_qc() {
            let mut qc_buf = Vec::with_capacity(1 + 150);
            qc_buf.push(MSG_QC);
            qc.encode(&mut qc_buf);
            for i in 0..num_nodes {
                if i != node_index {
                    let _ = transport.send(&vec![u8::try_from(i).unwrap()], &qc_buf);
                }
            }
            let _ = engine.deliver_qc(qc);
        }

        // Phase 5: advance views.
        let prev_view = engine.current_view().value();
        if let Some(hqc) = engine.high_qc() {
            if hqc.view == engine.current_view() {
                engine.advance_view();
            }
        }

        // Phase 5b: view-change timeout. If the current view hasn't
        // advanced within the pacemaker's timeout duration, fire
        // `on_timeout()`, broadcast the timeout signature to all
        // peers, and let the pacemaker collect signatures to form a
        // TC. This is the critical path for recovering from a
        // byzantine or crashed leader.
        let current_view_now = engine.current_view().value();
        if current_view_now != prev_view {
            // View advanced — reset the timer and clear the sent flag.
            view_start = std::time::Instant::now();
            timeout_sent_for_view = None;
        }
        let timeout_ms = engine.pacemaker_timeout_ms();
        let elapsed_ms = u64::try_from(view_start.elapsed().as_millis()).unwrap_or(0);
        if timeout_sent_for_view.is_none() && elapsed_ms >= timeout_ms {
            timeout_sent_for_view = Some(current_view_now);
            if let Some(sig) = engine.on_timeout() {
                eprintln!(
                    "oxide-validator[{node_index}]: view timeout view={current_view_now} elapsed={elapsed_ms}ms — broadcasting timeout sig"
                );
                let mut buf = Vec::with_capacity(1 + 1 + 8 + 8 + 96);
                buf.push(MSG_TIMEOUT);
                // Encode: voter_index (1 byte) + view (8 bytes) + epoch (8 bytes) + signature (96 bytes).
                // The view and epoch are included so the receiver can
                // verify the signature against the correct view and
                // ignore stale sigs from a different view (e.g., after
                // a partition when validators may be at different views).
                buf.push(u8::try_from(node_index).unwrap());
                buf.extend_from_slice(&current_view_now.to_le_bytes());
                buf.extend_from_slice(&engine.epoch().value().to_le_bytes());
                sig.encode(&mut buf);
                for i in 0..num_nodes {
                    if i != node_index {
                        let _ = transport.send(&vec![u8::try_from(i).unwrap()], &buf);
                    }
                }
                // Self-collect: feed our own timeout signature to the
                // engine so it counts toward the quorum.
                if let Ok(Some(tc)) =
                    engine.collect_timeout_signature(u16::try_from(node_index).unwrap(), sig)
                {
                    // TC formed immediately (unlikely with 1/4, but
                    // handle it). Broadcast the TC to all peers.
                    eprintln!(
                        "oxide-validator[{node_index}]: TC formed locally after self-timeout view={current_view_now}"
                    );
                    let mut tc_buf = Vec::with_capacity(1 + 200);
                    tc_buf.push(MSG_TC);
                    tc.encode(&mut tc_buf);
                    for i in 0..num_nodes {
                        if i != node_index {
                            let _ = transport.send(&vec![u8::try_from(i).unwrap()], &tc_buf);
                        }
                    }
                    view_start = std::time::Instant::now();
                    timeout_sent_for_view = None;
                }
            }
        }

        // Height sync is now handled inline when proposals are
        // received (MSG_PROPOSAL handler calls observe_block_height).
        // The previous self-sync (sync_next_height(next_height_value))
        // was a no-op — it synced the engine to its own value.

        // Report finalized height changes.
        let height = engine.finalized_height();
        if let Some(h) = height {
            let h_val = h.value();
            if h_val > last_reported_height {
                println!("oxide-validator[{node_index}]: finalized height = {h_val}");
                last_reported_height = h_val;
                // Update the RPC server's block height so
                // `eth_blockNumber` and `/metrics` reflect the
                // current finalized height, then push the block to
                // WebSocket subscribers (no-op when nobody is
                // subscribed or no EVM is attached).
                if let Some(rpc) = rpc {
                    rpc.set_block_height(h_val);
                    rpc.publish_new_block(h_val);
                }
            }
        }

        // Compact pending proposals (keep last 10 views).
        let current_view = engine.current_view().value();
        pending_proposals.retain(|(h, _)| h.view.value() >= current_view.saturating_sub(10));
        voted_views.retain(|v| *v >= current_view.saturating_sub(10));
        proposed_views.retain(|v| *v >= current_view.saturating_sub(10));

        // Epoch boundary: `commit_block` (called from `deliver_qc`
        // inside the drain loop and Phase 4) may have swapped the
        // validator set via `complete_rotation`. Update the shared
        // set so `GET /validator-set` reflects the new set for new
        // validators joining mid-epoch.
        if engine.epoch().value() != last_epoch {
            last_epoch = engine.epoch().value();
            if let Ok(mut shared) = shared_validator_set.write() {
                *shared = engine.validator_set().clone();
            }
        }

        // Yield to avoid busy-spinning when no messages are available.
        // `transport.recv()` uses non-blocking `try_recv()`, so the loop
        // would spin at 100% CPU without this sleep. A 1ms sleep keeps
        // CPU usage near-zero while providing ~1ms message latency,
        // 10x better than the previous `recv_timeout(10ms)` approach.
        // The consensus hot path (propose -> vote -> QC) is message-driven:
        // when messages arrive, `recv()` returns them immediately and
        // the sleep is never reached. The sleep only fires when the
        // transport is idle (waiting for the next network round).
        std::thread::sleep(std::time::Duration::from_millis(1));
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
fn load_config() -> (NodeConfig, config::RpcConfig, config::GenesisConfig) {
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
            settlement_operator: None,
            min_fee: 0,
            chain_id: rpc_config.chain_id,
            // `--require-signed-txs` enforces EIP-712 envelope
            // signatures on native-module txs. Default off because
            // devnet flows (key-change keep-alive, scripted test txs)
            // still submit unsigned envelopes — production must
            // enable it.
            require_signed_txs: env::args().any(|a| a == "--require-signed-txs"),
        },
        rpc_config,
        config.genesis,
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
    build_tx_with_nonce(module_id, module_payload, 0)
}

/// Encode bytes as a hex string (lowercase, no `0x` prefix).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
        write!(acc, "{b:02x}").expect("write to String cannot fail");
        acc
    })
}

/// Decode a hex string (with or without `0x` prefix) into bytes.
///
/// # Errors
///
/// Returns `Err` if the string is not valid hex or has an odd length.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at byte {}: {e}", i / 2))
        })
        .collect()
}

fn build_tx_with_nonce(module_id: u8, module_payload: &[u8], nonce: u64) -> types::TxBytes {
    let sender = primitives::Address([0u8; 20]);
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
    println!("    tls-gen      Generate TLS certificates for a multi-node testnet");
    println!("    version      Print version information");
    println!("    help         Print this help message");
    println!();
    println!("FLAGS:");
    println!("    --config <path>          Load config from TOML file");
    println!("    --engine <kind>           Consensus engine (sequencer|oxidebft)");
    println!("    --devnet-node <i>         Devnet node index (multi-process mode)");
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
    println!("    --submit-key-change <hex> Submit a BLS key-change transaction");
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
    println!("    oxide-validator --devnet-node 0 --num-nodes 4 --base-port 22000");
    println!("    oxide-validator --devnet-node 0 --genesis-file genesis.json \\");
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

    let mut genesis =
        config::genesis::Genesis::devnet(chain_id, num_validators, 32, 1_000_000_000_000);

    // Generate deterministic BLS keys for each validator and set
    // `public_key` so `--genesis-file` can build the `ValidatorSet`
    // without regenerating keys. For production, each validator
    // generates its own key and provides the public key to the
    // genesis coordinator.
    for (idx, validator) in genesis.staking.validators.iter_mut().enumerate() {
        let key = bls_key(u8::try_from(idx + 1).expect("index + 1 fits in u8"));
        let pk = key.public_key();
        validator.public_key = Some(format!("0x{}", hex_encode(pk.as_bytes())));
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
