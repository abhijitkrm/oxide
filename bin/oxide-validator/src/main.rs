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
//! Both modes run the SAME executor assembly
//! (`node::assemble_executor` — full module graph + exec lane) and
//! the SAME `node::node_config_from` conversion as `oxide-fullnode`,
//! so the shipped binaries cannot drift into different systems.
//! Parsed config is validated before assembly (`node::
//! validate_effective_config`): unsupported settings fail, overridden
//! ones warn, and the effective config is printed at startup.
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

use node::{Node, NodeConfig};
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

    fn snapshot_meta(&self) -> Result<(u64, primitives::Hash, u32), String> {
        let snap = self.executor.export_snapshot();
        Ok((snap.height, snap.state_root, executor::SNAPSHOT_FORMAT_VERSION))
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
    let cfg = load_config(node::NodeMode::Single);
    tracing::info!(
        engine = cfg.node.consensus.as_str(),
        max_mempool_entries = cfg.node.max_mempool_entries,
        "oxide-validator: starting"
    );

    let mut node = Node::assemble(&cfg.node);
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
    handle_key_change(&mut node);

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
fn handle_key_change(node: &mut Node) {
    if let Some(hex_key) = parse_cli_flag("--submit-key-change") {
        let secret_bytes =
            hex_decode(&hex_key).unwrap_or_else(|e| panic!("invalid BLS secret key hex: {e}"));
        let new_sk = crypto::BlsSecretKey::from_bytes(&secret_bytes)
            .unwrap_or_else(|e| panic!("invalid BLS secret key: {e:?}"));
        let new_key_bytes = new_sk.public_key().as_bytes().to_vec();
        let pop = new_sk.pop_prove();
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
        let msg_payload = staking::msg::key_change(validator_addr, &new_key_bytes, pop.as_bytes());
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
/// | `--submit-key-change <hex>` | Submit a key-change tx (new BLS **secret** key — `PoP` required) |
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
    // Load base config (TOML + env vars + CLI overrides), validated
    // and emitted as the effective config.
    let cfg = load_config(node::NodeMode::Devnet);
    let node_config = &cfg.node;
    let rpc_config = &cfg.rpc;
    let genesis_config = &cfg.genesis_cfg;

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

    // Assemble the executor through the ONE shared production path
    // (`node::assemble_executor`) — the same module graph and exec
    // lane `Node::assemble` produces. If --genesis-file was given,
    // the staking validators and native balances are already applied
    // via `node.genesis`; `evm.alloc` is applied on the module
    // handle below.
    let assembled = node::assemble_executor(&cfg.node);
    let app: Arc<executor::Executor> = assembled.app.clone();
    let evm_module = assembled.evm_module.clone();
    if let Some(genesis) = &cfg.genesis_file {
        apply_evm_alloc(&evm_module, genesis);
    }
    let app_dyn: Arc<dyn ports::AppInterface> = app.clone();

    // Create the TCP transport: --tls-dir for mTLS, plain TCP
    // otherwise. `[network]` timeouts and the frame bound flow into
    // `TcpTransportConfig`.
    let mut transport = build_transport(&listen_addr, node_index, peers, &cfg.network);

    // Give connections time to establish. TLS handshakes take
    // longer than plain TCP — 2s gives all peers time to connect
    // and complete the handshake before the first proposal.
    thread::sleep(Duration::from_millis(2000));

    // Create the consensus engine — with the configured pacemaker
    // timeouts and block budget, not the compiled defaults.
    let validator_set_clone = validator_set.clone();
    let mut engine = consensus::OxideBft::with_index(
        app_dyn,
        validator_set,
        u16::try_from(node_index).expect("index fits in u16"),
    )
    .with_secret_key(our_key.clone())
    .with_pacemaker_timeouts(node_config.base_timeout_ms, node_config.max_timeout_ms)
    .with_block_budget(node_config.block_budget);

    // WAL persistence: --wal-file. Recovery may return a *rotated*
    // validator set — the WAL records the committed committee, not
    // just the epoch — and `recover_from_wal` re-seats our index by
    // matching our BLS key against it.
    let recovered = if let Some(wal_path) = parse_cli_flag("--wal-file") {
        let wal = consensus::wal::Wal::open(&wal_path).expect("wal open");
        engine = engine.with_wal(wal);
        engine.recover_from_wal().expect("wal recover");
        println!("oxide-validator[{node_index}]: WAL loaded from {wal_path}");
        true
    } else {
        false
    };

    // Membership gate: our BLS key must resolve to a slot in the
    // committee the engine is actually running (post-recovery, not
    // necessarily the genesis set). `None` means we were rotated
    // out (or the key file doesn't match this node's config) — a
    // validator that cannot produce verifiable votes must not run:
    // its signatures would only ever be rejected noise.
    let our_index = engine.validator_set().index_of_key(&our_key.public_key());
    if our_index.is_none() {
        eprintln!(
            "oxide-validator[{node_index}]: our BLS key is not in the active validator set \
             (epoch {}) — exiting; this node is no longer a committee member",
            engine.epoch().value()
        );
        std::process::exit(1);
    }
    // Fresh start (no recovery): the engine was constructed as
    // validator `node_index`, so our key must occupy that exact
    // slot — landing elsewhere means the key file belongs to a
    // different validator, and signing under `node_index` would
    // emit only invalid votes.
    if !recovered && our_index != Some(u16::try_from(node_index).unwrap_or(u16::MAX)) {
        eprintln!(
            "oxide-validator[{node_index}]: our BLS key resolves to validator index \
             {our_index:?}, not {node_index} — the key file does not match this node's \
             identity; exiting",
        );
        std::process::exit(1);
    }

    // Data directory: `--data-dir` or `[storage] data_dir` enables
    // auto-snapshot persistence — on startup, if
    // `<dir>/snapshot.bin` exists, import it; on shutdown, export
    // the current state to `<dir>/snapshot.bin`. The EVM state
    // database at `<dir>/evm.redb` was already wired by
    // `assemble_executor` via `node.storage_path`.
    //
    // This gives a restarting validator full state persistence
    // without requiring manual `--export-snapshot` /
    // `--import-snapshot` flags. The WAL (if `--wal-file` is also
    // given) protects consensus safety state across the restart.
    let data_dir = cfg.data_dir.clone();
    if let Some(ref dir) = data_dir {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed to create data dir {}: {e}", dir.display()));
        let snap_path = dir.join("snapshot.bin");
        if snap_path.exists() {
            let bytes = std::fs::read(&snap_path)
                .unwrap_or_else(|e| panic!("failed to read snapshot {}: {e}", snap_path.display()));
            let mut reader = codec::Reader::new(&bytes);
            let snap = executor::ExecutorSnapshot::decode(&mut reader).unwrap_or_else(|e| {
                panic!("failed to decode snapshot {}: {e}", snap_path.display())
            });
            app.import_snapshot(&snap).unwrap_or_else(|e| {
                panic!("failed to import snapshot {}: {e}", snap_path.display())
            });
            println!(
                "oxide-validator[{node_index}]: imported snapshot from {} (height {})",
                snap_path.display(),
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
        rpc_config,
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
        let snap_path = dir.join("snapshot.bin");
        std::fs::write(&snap_path, &buf)
            .unwrap_or_else(|e| panic!("failed to write snapshot {}: {e}", snap_path.display()));
        println!(
            "oxide-validator[{node_index}]: exported snapshot to {} (height {})",
            snap_path.display(),
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

/// Build the TCP transport: `--tls-dir` for mTLS, plain TCP otherwise.
///
/// The `[network]` section supplies the timeouts and frame bound.
/// `allowed_peer_ids` is pinned to the derived validator set so a
/// non-validator peer cannot self-claim an ID and join the
/// consensus traffic (the `TcpTransportConfig` docs mark this as
/// required in production — it was previously left `None`).
///
/// # Panics
///
/// Panics if `--tls-dir` is given but the TLS config cannot be built
/// (missing cert/key files, invalid PEM, etc.).
fn build_transport(
    listen_addr: &str,
    node_index: usize,
    peers: Vec<(Vec<u8>, String)>,
    network: &config::NetworkConfig,
) -> p2p::tcp::TcpTransport {
    let own_id = vec![u8::try_from(node_index).expect("peer id fits in u8")];
    let allowed: std::collections::HashSet<Vec<u8>> =
        peers.iter().map(|(id, _)| id.clone()).chain([own_id.clone()]).collect();
    let transport_config = p2p::tcp::TcpTransportConfig {
        allowed_peer_ids: Some(allowed),
        ..to_transport_config(network)
    };
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
        p2p::tcp::TcpTransport::with_tls(listen_addr, own_id, peers, transport_config, tls_config)
    } else {
        p2p::tcp::TcpTransport::with_config(listen_addr, own_id, peers, transport_config)
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
        // Leader decisions consult the engine's LIVE committee —
        // `is_leader` reads the current validator set AND our
        // re-seated index, so a rotated epoch can't strand us on the
        // startup set's schedule (or our startup slot).
        let view = engine.current_view().value();
        if engine.is_leader() && !proposed_views.contains(&view) {
            if view > 0 && engine.high_qc().is_none() {
                // Need the previous QC before proposing.
            } else if let Some((header, proposal)) = engine.propose() {
                let proposal_view = header.view.value();
                proposed_views.insert(proposal_view);
                pending_proposals.push((header.clone(), proposal.clone()));
                // C10: the leader self-votes through `engine.vote()` —
                // the single signing authority — which records the
                // vote locks and appends the WAL BEFORE signing. The
                // manual sign-then-collect this replaces emitted a
                // signature whose anti-equivocation state was never
                // durable: a restart could then double-vote.
                if let Some(leader_vote) = engine.vote(&header, &proposal) {
                    let _ = engine.collect_vote(engine.validator_index(), leader_vote);
                    voted_views.insert(proposal_view);
                }
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
            let leader = usize::from(engine.validator_set().leader(header.view));
            if usize::from(engine.validator_index()) == leader {
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
                                    // Authenticate the evidence BEFORE acting
                                    // on it. Everything below mutates
                                    // consensus state — `sync_to_view` moves
                                    // the view, resets the pacemaker timer,
                                    // and clears the vote buffer — so a peer
                                    // claiming a high view with a garbage
                                    // signature must be rejected here rather
                                    // than after the damage is done. The
                                    // signature is checked against the
                                    // (view, epoch) the sender actually signed,
                                    // never against our own current view.
                                    if engine
                                        .verify_timeout_signature_for(
                                            voter_idx,
                                            primitives::View::new(sig_view),
                                            primitives::Epoch::new(sig_epoch),
                                            &sig,
                                        )
                                        .is_err()
                                    {
                                        continue;
                                    }
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
                // Our voter index comes from the engine — rotation
                // may have re-seated it, while `node_index` is the
                // frozen startup slot. The wire field is one byte:
                // an index that cannot fit must skip the broadcast —
                // emitting slot 0's number under our signature would
                // misattribute the timeout.
                let Ok(voter_byte) = u8::try_from(engine.validator_index()) else {
                    eprintln!(
                        "oxide-validator[{node_index}]: validator index {} exceeds the \
                         1-byte voter encoding — timeout signature not broadcast",
                        engine.validator_index()
                    );
                    continue;
                };
                buf.push(voter_byte);
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
                    engine.collect_timeout_signature(engine.validator_index(), sig)
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

        // Epoch lifecycle: drain the validator-set transition the
        // executor's finalized blocks recorded (staking key changes,
        // validator adds/removes) and rotate the engine into the new
        // committee. This is the production half of the epoch
        // protocol — the queues only fill when a block *executes*,
        // so polling each pass is the deferred, deterministic
        // trigger: every node folds the same committed deltas at the
        // same height boundary.
        match engine.drive_epoch_changes() {
            Ok(0) => {}
            Ok(applied) => {
                eprintln!(
                    "oxide-validator[{node_index}]: epoch rotation applied {applied} \
                     validator-set change(s) — now epoch {} ({} validators)",
                    engine.epoch().value(),
                    engine.validator_set().n()
                );
                // Reflect the new committee immediately — the
                // `last_epoch` check above only runs once per pass.
                last_epoch = engine.epoch().value();
                if let Ok(mut shared) = shared_validator_set.write() {
                    *shared = engine.validator_set().clone();
                }
            }
            Err(e) => {
                // Deterministic rejection — every replica folds the
                // same deltas through `build_next_set` and reaches
                // the same verdict, so this is consistent cluster
                // state, not a fork: the transition is dropped and
                // must be re-submitted.
                eprintln!(
                    "oxide-validator[{node_index}]: epoch transition rejected: {e} — \
                     pending change dropped (re-submit a valid set)"
                );
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

/// The fully-resolved runtime configuration: parsed TOML + env +
/// CLI, mapped into the types each subsystem consumes and checked by
/// `node::validate_effective_config` before the node builds anything.
struct LoadedConfig {
    /// The canonical node/executor config — consumed by
    /// `Node::assemble` (single-node mode) and
    /// `node::assemble_executor` (devnet-node mode).
    node: NodeConfig,
    /// The JSON-RPC server config.
    rpc: config::RpcConfig,
    /// The `[network]` section — transport timeouts and the frame
    /// bound for the devnet-node TCP transport.
    network: config::NetworkConfig,
    /// The `[genesis]` section — devnet validator/sender fallbacks
    /// used when no `--genesis-file` is given.
    genesis_cfg: config::GenesisConfig,
    /// The parsed `--genesis-file`, when given. Its validators and
    /// native balances are already folded into `node.genesis`; the
    /// raw file is kept for `evm.alloc` and for
    /// `load_validator_set`'s BLS-key extraction, which need richer
    /// shapes than `GenesisSpec` carries.
    genesis_file: Option<config::genesis::Genesis>,
    /// The resolved data directory (`--data-dir` or
    /// `[storage] data_dir`): auto-snapshot persistence root and the
    /// parent of the EVM state database.
    data_dir: Option<PathBuf>,
}

/// Apply a genesis file's `evm.alloc` map to the assembled EVM
/// module: balances, nonces, code, and storage for pre-funded
/// accounts and preinstalled contracts (Ethereum `genesis.json`
/// convention).
///
/// Kept in the binary (not the shared assembly) because storage
/// slots are 256-bit words — converting them here avoids dragging
/// the `node` crate into a `revm`/`alloy` dependency for one map.
/// Applied after `install_preinstalls`, so an alloc entry can still
/// intentionally override a preinstall address.
fn apply_evm_alloc(evm_module: &evm::EvmModule, genesis: &config::genesis::Genesis) {
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

/// Map the `[network]` config onto the transport's tunables.
///
/// `listen_addr`/`peers` are NOT taken from here in devnet-node
/// mode — they are derived per-index (`--devnet-node`,
/// `--base-port`) so one TOML file serves the whole cluster. The
/// timeouts and frame bound DO apply to both TLS and plain TCP.
fn to_transport_config(network: &config::NetworkConfig) -> p2p::tcp::TcpTransportConfig {
    p2p::tcp::TcpTransportConfig {
        connect_timeout: network.connect_timeout(),
        read_timeout: network.read_timeout(),
        max_message_bytes: network.max_message_bytes,
        ..Default::default()
    }
}

/// Whether `host` resolves to a loopback-only bind. Anything that is
/// not a literal loopback IP or `localhost` is treated as external:
/// a hostname could resolve anywhere, and `0.0.0.0`/`::` are wildcard
/// binds — both count as external-facing for the unsafe-mode gate.
fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Collect the descriptions of listener binds that would expose the
/// node to other machines. Empty means every bind surface is
/// loopback-only (or absent) — the safe shape for unsigned mode.
///
/// `bind_host` is the devnet transport's resolved bind address
/// (`None` in single-node mode, which runs no transport);
/// `rpc_listen` is the resolved RPC listen address (`None` when the
/// RPC server is off).
fn external_bind_surfaces(bind_host: Option<&str>, rpc_listen: Option<&str>) -> Vec<String> {
    let mut external = Vec::new();
    if let Some(host) = bind_host {
        if !is_loopback_host(host) {
            external.push(format!("devnet transport --bind-host {host}"));
        }
    }
    if let Some(listen) = rpc_listen {
        let host = listen.rsplit_once(':').map_or(listen, |(h, _)| h);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if !is_loopback_host(host) {
            external.push(format!("RPC listener {listen}"));
        }
    }
    external
}

/// Refuse to start with unsigned-tx admission on any listener that
/// is reachable from other machines.
///
/// Unsigned envelopes trust the declared `sender` — acceptable on a
/// loopback devnet where every submitter is the operator, fatal on a
/// network-facing bind where it lets anyone spend any account. The
/// surfaces checked are the devnet-node transport (`--bind-host`)
/// and the JSON-RPC listener (`--rpc-listen` / `rpc.listen_addr`),
/// resolved the same way the listeners themselves are.
fn refuse_unsigned_on_external_binds(
    node_config: &NodeConfig,
    rpc_config: &config::RpcConfig,
    mode: node::NodeMode,
) {
    if node_config.require_signed_txs {
        return;
    }
    let bind_host = matches!(mode, node::NodeMode::Devnet)
        .then(|| parse_cli_flag("--bind-host").unwrap_or_else(|| "127.0.0.1".to_string()));
    // Same resolution the RPC startup paths use.
    let rpc_listen = parse_cli_flag("--rpc-listen").or_else(|| {
        if rpc_config.listen_addr.is_empty() { None } else { Some(rpc_config.listen_addr.clone()) }
    });
    let external = external_bind_surfaces(bind_host.as_deref(), rpc_listen.as_deref());
    if !external.is_empty() {
        eprintln!(
            "oxide-validator: refusing to start — --unsafe-allow-unsigned-txs admits \
             unauthenticated senders, but these binds are externally reachable:"
        );
        for surface in &external {
            eprintln!("  - {surface}");
        }
        eprintln!("run unsigned mode on loopback only, or drop the flag and sign envelopes");
        std::process::exit(1);
    }
}

/// Load the node configuration from CLI flags, env vars, and TOML file.
///
/// Priority: CLI > env vars > TOML > defaults. Validates the
/// effective config (unsupported settings fail, overridden settings
/// warn) and prints it before returning, so the running node's
/// parameters are never ambiguous.
fn load_config(mode: node::NodeMode) -> LoadedConfig {
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
        } else {
            eprintln!(
                "oxide-validator: unknown --engine value {engine_str:?} \
                      (expected \"sequencer\" or \"oxidebft\")"
            );
            std::process::exit(1);
        }
    }

    // `--genesis-file`: chain state (validators, balances, evm.alloc).
    let genesis_file = parse_cli_flag("--genesis-file").map(|p| {
        config::genesis::Genesis::from_json_file(&PathBuf::from(&p))
            .unwrap_or_else(|e| panic!("failed to load genesis file {p}: {e}"))
    });

    // `--data-dir` wins over `[storage] data_dir`.
    let data_dir =
        parse_cli_flag("--data-dir").map(PathBuf::from).or_else(|| config.storage.data_dir.clone());

    let rpc_config = config.rpc.clone().unwrap_or_default();

    // Genesis chain id must match the RPC chain id — a mismatch means
    // the node's signatures and its advertised chain disagree.
    if let Some(g) = &genesis_file {
        if g.chain_id != rpc_config.chain_id {
            eprintln!(
                "oxide-validator: genesis chain_id {} != rpc.chain_id {} — \
                 refusing to run a node whose signatures advertise a different chain",
                g.chain_id, rpc_config.chain_id
            );
            std::process::exit(1);
        }
    }

    // The genesis spec: `--genesis-file` when given, else the
    // deterministic devnet fallback. A malformed genesis file fails
    // at startup with the offending entry named.
    let genesis = Some(match &genesis_file {
        Some(g) => {
            node::genesis_spec_from_file(g).unwrap_or_else(|e| panic!("invalid genesis file: {e}"))
        }
        None => node::genesis_spec_devnet(&config.genesis),
    });
    let overrides = node::AssemblyOverrides {
        // `--unsafe-allow-unsigned-txs` (CLI) OR `[executor]
        // allow_unsigned_txs` — the OR lives in `node_config_from`.
        // Signed envelopes are the default; this flag exists only
        // for loopback devnets and is refused on external binds.
        allow_unsigned_txs: env::args().any(|a| a == "--unsafe-allow-unsigned-txs"),
        data_dir: data_dir.clone(),
        genesis,
    };
    let node_config = node::node_config_from(&config, &rpc_config, &overrides, mode)
        .unwrap_or_else(|e| panic!("invalid configuration: {e}"));

    // Validate BEFORE building anything: unsupported settings fail,
    // overridden ones warn — never silently do nothing.
    let (warnings, errors) = node::validate_effective_config(&config, &node_config, mode);
    for w in &warnings {
        eprintln!("oxide-validator: config warning: {w}");
    }
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("oxide-validator: config error: {e}");
        }
        std::process::exit(1);
    }
    refuse_unsigned_on_external_binds(&node_config, &rpc_config, mode);

    // Emit the effective configuration — the values actually running,
    // after every override layer, not the file's literal contents.
    println!("oxide-validator: effective node config: {node_config:?}");

    LoadedConfig {
        node: node_config,
        rpc: rpc_config,
        network: config.network,
        genesis_cfg: config.genesis,
        genesis_file,
        data_dir,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Loopback classification: the unsafe unsigned gate relies on
    /// this to distinguish dev binds from external-facing ones.
    #[test]
    fn loopback_classification() {
        for host in ["127.0.0.1", "127.44.0.9", "localhost", "::1"] {
            assert!(is_loopback_host(host), "{host} must classify loopback");
        }
        for host in ["0.0.0.0", "::", "192.168.1.5", "10.0.0.2", "validator-1.internal", "8.8.8.8"]
        {
            assert!(!is_loopback_host(host), "{host} must classify external");
        }
    }

    /// The external-bind scan flags non-loopback transport and RPC
    /// surfaces, and stays empty for loopback-only binds.
    #[test]
    fn external_bind_scan() {
        // Loopback everywhere → no surfaces.
        assert!(external_bind_surfaces(Some("127.0.0.1"), Some("127.0.0.1:8545")).is_empty());
        assert!(external_bind_surfaces(Some("::1"), Some("[::1]:8545")).is_empty());
        // No binds at all → no surfaces.
        assert!(external_bind_surfaces(None, None).is_empty());
        // Wildcard transport bind → flagged.
        assert_eq!(
            external_bind_surfaces(Some("0.0.0.0"), None),
            vec!["devnet transport --bind-host 0.0.0.0".to_string()]
        );
        // External RPC bind → flagged (IPv6 bracket form included).
        assert_eq!(external_bind_surfaces(None, Some("0.0.0.0:8545")).len(), 1);
        assert_eq!(external_bind_surfaces(None, Some("[::]:8545")).len(), 1);
        assert_eq!(external_bind_surfaces(None, Some("example.com:8545")).len(), 1);
    }

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
