//! `oxide-validator` — the Oxide validator node binary.
//!
//! Runs a node over the full consensus + executor stack:
//! [`node::assemble_executor`] builds the production module graph
//! (core, evm, staking, exchange, perps, oracle, governance) with
//! the async execution lane, and `mod driver` drives the engine.
//!
//! Two run modes: default single-node (in-process engine, no
//! transport) and `--validator` — the production multi-validator
//! mode running oxideBFT over the TCP/mTLS transport with peers
//! from `[network] peers` (`addr=host:port`) and the committee from
//! `--genesis-file`. Multi-validator *devnets* still use the
//! separate `oxide-devnet` binary with its derivable fixtures.
//!
//! # Usage
//!
//! ```sh
//! oxide-validator                       # single-node devnet
//! oxide-validator --config node.toml    # configured node
//! oxide-validator --validator --config node.toml \
//!     --genesis-file genesis.json --bls-key-file key.hex --tls-dir tls/
//! ```
//!
//! Subcommands: `version`, `init`, `genesis`, `tls-gen`, `help`.

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use node::Node;
use ports::AppInterface;
use zeroize::Zeroize;

// Codec traits for encoding/decoding consensus messages.
use codec::{Decode, Encode};

mod driver;

fn main() {
    // Supervision before anything can spawn: a panic on a critical
    // actor's thread aborts the process so the supervisor restarts a
    // coherent node instead of running half-alive.
    primitives::supervision::install_panic_hook();

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
            "keygen" => {
                run_keygen(&args[2..]);
                return;
            }
            "signer" => {
                run_signer_daemon(&args[2..]);
                return;
            }
            "help" | "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {} // fall through to normal mode
        }
    }

    // `--validator` runs the production multi-validator mode: real
    // oxideBFT over the TCP/mTLS transport, committee and peer
    // endpoints from `--genesis-file` + `[network] peers`. Without
    // it, the binary runs the single-node in-process engine.
    if args.iter().any(|a| a == "--validator") {
        run_validator_node();
        return;
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

    // Drive consensus once so the startup log reports the recovered
    // tip and state root. No smoke transaction is submitted — a
    // validator must not emit transactions signed by the public
    // devnet identity.
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

    tracing::info!("oxide-validator: startup check complete");

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
        wire_driver_observers(&mut consensus_driver, &rpc_shared);
        let driver_handle = consensus_driver.start(node);
        // Critical: this task IS the consensus loop — its panic must
        // abort, not strand a validator that still holds its keys.
        supervise_task("consensus-driver", true, driver_handle);
        tracing::info!("oxide-validator: consensus driver started (autonomous mode)");

        // Spawn the HTTP server as a background task. Non-critical:
        // its death is itself the health signal (connection refused),
        // and `select!` below exits the process when it resolves.
        primitives::supervision::register("rpc-http", false);
        let server_handle = tokio::spawn(async move {
            http_server.serve().await;
        });

        // Periodically sync driver metrics to the RPC server.
        let metrics_abort = spawn_metrics_sync(driver_metrics);

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
            r = server_handle => {
                match &r {
                    Ok(()) => primitives::supervision::mark_exited("rpc-http"),
                    Err(_) => primitives::supervision::mark_panicked("rpc-http"),
                }
                tracing::info!("RPC server exited");
            }
            () = shutdown => {
                tracing::info!("shutdown signal received, shutting down gracefully");
            }
        }
        metrics_abort.abort();
    });

    tracing::info!("oxide-validator: node stopped");
}

/// Run the production multi-validator mode (`oxide-validator --validator`).
///
/// Same shared pump the devnet binary runs — [`node::validator_net`]
/// — but with production inputs: the committee comes from
/// `--genesis-file` (no derivable fallback exists in this binary),
/// the signing key from `--bls-key-file`, peer endpoints from
/// `[network] peers` (`addr=host:port`) plus repeatable `--peer`
/// overrides, and mTLS material from `--tls-dir`. The external-bind
/// posture gate in `load_config` already refused insecure defaults
/// before this function runs.
///
/// # Flags
///
/// | Flag | Description |
/// |------|-------------|
/// | `--validator` | Select multi-validator mode |
/// | `--config <path>` | TOML config — `[network] listen_addr`/`peers` are live |
/// | `--genesis-file <path>` | **Required.** `genesis.json` — the committee and chain state source |
/// | `--bls-key-file <path>` | **Required.** BLS secret key (hex, raw 32B, or OXKEY keystore) |
/// | `--tls-dir <dir>` | mTLS directory: `cert.pem`, `key.pem`, `peer-<addr-hex>.pem` per peer |
/// | `--peer <addr>=<host:port>` | Extra/override peer endpoint, repeatable |
/// | `--data-dir` / `--wal-file` | Durability paths |
/// | `--rpc-listen <addr>` | RPC bind override |
/// | `--export-snapshot` / `--import-snapshot` | Snapshot in/out |
/// | `--repair-peer <host:port>` | Peer RPC endpoint for certified state repair after a divergence halt, repeatable |
/// | `--unsafe-allow-insecure-posture` | Opt out of the external-bind refusal (private testnets) |
fn run_validator_node() {
    let cfg = node::cli::load_config(node::NodeMode::Validator, "oxide-validator");

    // The committee and genesis state come from the genesis file —
    // there is no derivable-validator-set fallback in the production
    // binary (that is the devnet convention this mode exists to not
    // repeat).
    let genesis = cfg.genesis_file.clone().unwrap_or_else(|| {
        eprintln!(
            "oxide-validator: --validator requires --genesis-file <genesis.json> — \
             the committee and initial state cannot be derived"
        );
        std::process::exit(1);
    });
    // The signing key is a local key file XOR a remote signer —
    // exactly one. A remote signer holds the secret in a fenced
    // daemon (`oxide-validator signer`); the validator process then
    // never touches it. There is no deterministic key derivation —
    // that surface is feature-gated out of production builds.
    let signer = resolve_signer();

    let validator_set = node::cli::validator_set_from_genesis(&genesis)
        .unwrap_or_else(|e| panic!("invalid genesis validator set: {e}"));
    // The committee seat is wherever OUR key is registered — never a
    // process index. A key outside the committee would boot and then
    // fail every peer handshake; refuse at startup instead.
    let our_pk = signer.public_key();
    let Some(our_seat) = validator_set.index_of_key(&our_pk) else {
        eprintln!(
            "oxide-validator: refusing to start — --bls-key-file is not in the \
             genesis validator set"
        );
        std::process::exit(1);
    };
    let our_addr = validator_set.validator_addresses()[usize::from(our_seat)];
    let peers = resolve_peers(&cfg.network.peers, &our_addr);
    let tls = resolve_tls_spec(&peers);

    // Graceful shutdown: SIGINT/SIGTERM sets the flag the pump polls.
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let _ = primitives::supervision::spawn_supervised("signal-handler", false, move || {
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
            shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    });

    let rpc_listen = node::cli::parse_cli_flag("--rpc-listen").or_else(|| {
        if cfg.rpc.listen_addr.is_empty() { None } else { Some(cfg.rpc.listen_addr.clone()) }
    });
    let wal_path = node::cli::parse_cli_flag("--wal-file").map(PathBuf::from);
    // Genesis `evm.alloc` — parsed here so `node` stays free of the
    // `alloy_primitives` U256 conversion.
    let genesis_alloc = Some(Box::new(move |m: &evm::EvmModule| apply_evm_alloc(m, &genesis))
        as Box<dyn FnOnce(&evm::EvmModule) + Send>);

    // Certified-repair peers: `--repair-peer <host:port>` repeatable,
    // naming peer RPC endpoints (the `/snapshot/*` surface), not
    // consensus transport addresses. Empty leaves the runbook's
    // manual repair path — the halt stays terminal.
    let repair_peers = node::cli::parse_cli_flags("--repair-peer");

    // Observer allowlist: `--observer-peer <addr_hex>=<bls_pubkey_hex>`
    // repeatable — non-committee endpoints (fullnode followers) that
    // may complete the peer handshake and pull certified history.
    let observer_peers = node::cli::parse_cli_flags("--observer-peer")
        .iter()
        .map(|entry| {
            node::cli::parse_observer_peer(entry)
                .unwrap_or_else(|e| panic!("invalid --observer-peer '{entry}': {e}"))
        })
        .collect();

    // `--evidence-key-file` wires the S1 equivocation pipeline:
    // the engine detects double-signs in every build, but the
    // records only become slashes once a funded secp256k1 account
    // carries them on-chain. Absent the flag the node still detects
    // (and logs what it declined to submit); a PUBLIC test-identity
    // key is refused outright — its "signature" authenticates as an
    // identity anyone can recompute, which would spam the evidence
    // lane with envelopes anyone could have sent.
    let evidence_reporter = node::cli::parse_cli_flag("--evidence-key-file").map(|path| {
        let key = node::cli::load_secret_key_file(&path, node::cli::SecretKind::Secp256k1)
            .unwrap_or_else(|e| panic!("invalid --evidence-key-file '{path}': {e}"));
        if crypto::is_test_identity_key(&key) {
            eprintln!(
                "oxide-validator: --evidence-key-file is a public test-identity scalar — \
                 a known key cannot authorize evidence submission"
            );
            std::process::exit(1);
        }
        node::validator_net::EvidenceReporter::new(key)
            .unwrap_or_else(|| panic!("--evidence-key-file '{path}' is not a valid secp256k1 key"))
    });

    node::validator_net::run(node::validator_net::ValidatorNetSpec {
        log_tag: "oxide-validator".to_string(),
        seat: usize::from(our_seat),
        validator_set,
        signer,
        node_config: cfg.node.clone(),
        wal_path,
        listen_addr: cfg.network.listen_addr.clone(),
        peers,
        tls,
        network: cfg.network.clone(),
        genesis_alloc,
        data_dir: cfg.data_dir.clone(),
        rpc_listen,
        rpc_config: cfg.rpc.clone(),
        smoke_tx: None,
        shutdown,
        repair_peers,
        observer_peers,
        // A production validator never originates transactions —
        // injection is a devnet/test-harness surface.
        tx_inject: None,
        evidence_reporter,
    });
}

/// Resolve peer endpoints for validator mode: `[network] peers`
/// entries (format-checked by `validate_effective_config` —
/// `addr=host:port`) plus repeatable `--peer addr=host:port`
/// overrides, which also admit non-committee endpoints (a pending
/// rotation member).
///
/// Returns `(peer_id, host:port)` pairs where `peer_id` is the
/// member's staking-address bytes. Our own address is skipped — a
/// config listing ourselves would open a self-connection.
fn resolve_peers(configured: &[String], our_addr: &primitives::Address) -> Vec<(Vec<u8>, String)> {
    let mut peers: Vec<(Vec<u8>, String)> = Vec::new();
    let mut seen_peers: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for entry in configured.iter().cloned().chain(node::cli::parse_cli_flags("--peer")) {
        let Some((addr_hex, hostport)) = entry.split_once('=') else {
            // Config-file entries were already validated; a bad one
            // here came from `--peer` argv.
            eprintln!("oxide-validator: invalid peer '{entry}' — expected <addr_hex>=<host:port>");
            std::process::exit(1);
        };
        let addr_bytes = node::cli::hex_decode(addr_hex)
            .unwrap_or_else(|e| panic!("invalid peer address '{addr_hex}': {e}"));
        let Ok(addr_arr): Result<[u8; 20], _> = addr_bytes.try_into() else {
            eprintln!("oxide-validator: peer address '{addr_hex}' must be 20 bytes");
            std::process::exit(1);
        };
        if addr_arr == our_addr.0 {
            continue;
        }
        let id = addr_arr.to_vec();
        if seen_peers.insert(id.clone()) {
            peers.push((id, hostport.to_string()));
        }
    }
    peers
}

/// Resolve the validator's signing identity: a local
/// `--bls-key-file` XOR a remote `--signer-addr`. Both absent or
/// both present is a startup refusal — the secret must live in
/// exactly one place, and this binary has no derivable fallback.
fn resolve_signer() -> Arc<dyn crypto::ConsensusSigner> {
    let key_path = node::cli::parse_cli_flag("--bls-key-file");
    let signer_addr = node::cli::parse_cli_flag("--signer-addr");
    match (key_path, signer_addr) {
        (Some(key_path), None) => {
            let key_bytes = node::cli::load_secret_key_file(&key_path, node::cli::SecretKind::Bls)
                .unwrap_or_else(|e| panic!("invalid BLS key file {key_path}: {e}"));
            let our_key = crypto::BlsSecretKey::from_bytes(&key_bytes[..])
                .unwrap_or_else(|e| panic!("invalid BLS secret key in {key_path}: {e:?}"));
            Arc::new(our_key)
        }
        (None, Some(addr)) => {
            // The link key is the client credential — without it
            // the daemon refuses the handshake before any request
            // reaches the fence. Same file the daemon was started
            // with (`signer --link-key-file`).
            let link_path =
                node::cli::parse_cli_flag("--signer-link-key-file").unwrap_or_else(|| {
                    eprintln!(
                        "oxide-validator: --signer-addr requires \
                         --signer-link-key-file <path> — the shared link \
                         secret that authenticates the signer connection"
                    );
                    std::process::exit(1);
                });
            let link_key =
                node::cli::load_secret_key_file(&link_path, node::cli::SecretKind::Generic)
                    .unwrap_or_else(|e| panic!("invalid link key file {link_path}: {e}"));
            let remote = node::remote_signer::RemoteSigner::connect(
                &addr,
                std::time::Duration::from_secs(5),
                *link_key,
            )
            .unwrap_or_else(|e| {
                eprintln!("oxide-validator: cannot reach signer at {addr}: {e}");
                std::process::exit(1);
            });
            println!("oxide-validator: remote signer at {addr} (key loaded in daemon)");
            Arc::new(remote)
        }
        (None, None) => {
            eprintln!(
                "oxide-validator: --validator requires --bls-key-file <path> or \
                 --signer-addr <host:port> — an operator key file (hex, raw 32 \
                 bytes, OXKEY keystore) or a fenced remote signer"
            );
            std::process::exit(1);
        }
        (Some(_), Some(_)) => {
            eprintln!(
                "oxide-validator: --bls-key-file and --signer-addr are exclusive — \
                 the key lives in exactly one place"
            );
            std::process::exit(1);
        }
    }
}

/// Resolve `--tls-dir` into a [`node::validator_net::TlsSpec`]:
/// `cert.pem`/`key.pem` for ourselves and one `peer-<addr-hex>.pem`
/// per peer — production naming is address-keyed, never
/// committee-indexed (a removal reshuffle would silently rebind
/// index-named certs to the wrong member).
fn resolve_tls_spec(peers: &[(Vec<u8>, String)]) -> Option<node::validator_net::TlsSpec> {
    node::cli::parse_cli_flag("--tls-dir").map(|tls_dir| {
        let trusted_peer_certs = peers
            .iter()
            .map(|(id, _)| {
                (
                    id.clone(),
                    PathBuf::from(format!("{tls_dir}/peer-{}.pem", node::cli::hex_encode(id))),
                )
            })
            .collect();
        node::validator_net::TlsSpec {
            cert_path: PathBuf::from(format!("{tls_dir}/cert.pem")),
            key_path: PathBuf::from(format!("{tls_dir}/key.pem")),
            trusted_peer_certs,
        }
    })
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
        let addr_bytes = node::cli::hex_decode(addr_hex)
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
            .map(|c| node::cli::hex_decode(c).unwrap_or_else(|e| panic!("evm.alloc code: {e}")))
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

/// Spawn the periodic driver-metrics sync task under supervision.
/// Returns the `AbortHandle` so shutdown can still cancel the inner
/// task without owning the monitored `JoinHandle`.
fn spawn_metrics_sync(driver_metrics: Arc<driver::DriverMetrics>) -> tokio::task::AbortHandle {
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            // The driver_metrics handle is used to read the
            // current block height for logging; the RPC server
            // has its own atomic counters that are updated via
            // `set_block_height`. In a future refactor, the
            // driver and RPC can share the same atomic counters.
            let height = driver_metrics.block_height();
            tracing::debug!(height, txs = driver_metrics.tx_count(), "metrics sync: driver stats");
        }
    });
    let abort = handle.abort_handle();
    supervise_task("metrics-sync", false, handle);
    abort
}

/// Monitor a supervised tokio task's `JoinHandle`: the process panic
/// hook can't map a task panic to an actor (the unwinding thread is
/// an anonymous runtime worker — the runtime catches the panic into
/// the `JoinHandle`), so this monitor awaits the handle and reports
/// the outcome. A panic on a `critical` task aborts the process —
/// fail-fast for the actors the node cannot run without; a clean
/// return or cancellation just marks the actor exited.
fn supervise_task(name: &'static str, critical: bool, handle: tokio::task::JoinHandle<()>) {
    primitives::supervision::register(name, critical);
    tokio::spawn(async move {
        match handle.await {
            Ok(()) => primitives::supervision::mark_exited(name),
            Err(e) if e.is_cancelled() => primitives::supervision::mark_exited(name),
            Err(_) => {
                primitives::supervision::mark_panicked(name);
                if critical {
                    eprintln!(
                        "critical task '{name}' panicked — aborting so the \
                         supervisor restarts a coherent process"
                    );
                    std::process::abort();
                }
            }
        }
    });
}

/// Build the single-node JSON-RPC server: wire the executor and EVM
/// module into `RpcServer`, seed metrics, and return the shared
/// `Arc` (for the driver's block observer) plus the HTTP server.
/// Wire the consensus driver's observers into the shared RPC
/// server: block finalization keeps `eth_blockNumber` and
/// `newHeads` pushes live, and the divergence latch flips `/health`
/// to 503 carrying the certified repair anchor while `/metrics`
/// exposes `oxide_exec_diverged`.
fn wire_driver_observers(
    consensus_driver: &mut driver::ConsensusDriver,
    rpc_shared: &Arc<rpc::RpcServer>,
) {
    let rpc_divergence = rpc_shared.clone();
    consensus_driver.set_divergence_observer(Arc::new(move |d| {
        rpc_divergence.set_exec_divergence(d);
    }));
    let rpc_blocks = rpc_shared.clone();
    consensus_driver.set_block_observer(Arc::new(move |height: u64| {
        rpc_blocks.set_block_height(height);
        rpc_blocks.publish_new_block(height);
    }));
    // Mirror quorum-signed execution certificates into RPC so
    // `GET /snapshot/cert/{height}` gives a syncing node a
    // cryptographic anchor for its snapshot download instead of an
    // operator-typed root.
    let rpc_certs = rpc_shared.clone();
    consensus_driver.set_cert_observer(Arc::new(move |certs| {
        rpc_certs.record_exec_certificates(certs);
    }));
}

fn build_single_node_rpc(
    node: &Node,
    rpc_config: &config::RpcConfig,
    height: Option<primitives::Height>,
    recorder: Arc<metrics::Recorder>,
) -> (Arc<rpc::RpcServer>, rpc::server::HttpServer) {
    let mut rpc_server = rpc::RpcServer::new(rpc_config.chain_id, rpc_config.base_fee)
        .with_debug_api(rpc_config.enable_debug_api);
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
/// `--submit-key-change <new-bls-secret-hex>` — rotate this node's
/// consensus key. The transaction must be signed by the staking
/// account it rotates: `--signer-key <secp256k1-hex>` names the
/// operator's key, and the tx's sender recovers to it. Test-identity
/// scalars are refused — a publicly known signer cannot authorize a
/// key rotation.
fn handle_key_change(node: &mut Node, chain_id: u64) {
    if let Some(hex_key) = node::cli::parse_cli_flag("--submit-key-change") {
        let mut hex_key = zeroize::Zeroizing::new(hex_key);
        let mut secret_bytes = node::cli::hex_decode(&hex_key)
            .unwrap_or_else(|e| panic!("invalid BLS secret key hex: {e}"));
        let new_sk = crypto::BlsSecretKey::from_bytes(&secret_bytes)
            .unwrap_or_else(|e| panic!("invalid BLS secret key: {e:?}"));
        // The secret now lives inside `blst`'s zeroize-on-drop key —
        // wipe the decoded buffer and the argv hex copy.
        secret_bytes.zeroize();
        hex_key.zeroize();
        let new_key_bytes = new_sk.public_key().as_bytes().to_vec();
        let pop = new_sk.pop_prove();

        // The signer may come from argv (hex) or a file — the file
        // form accepts an encrypted OXKEY keystore, so the staking
        // key never has to sit on a command line.
        // The signer key travels in `Zeroizing` from whichever source
        // produced it — argv hex and the decoded Vec are both wiped.
        let signer: zeroize::Zeroizing<[u8; 32]> =
            if let Some(file) = node::cli::parse_cli_flag("--signer-key-file") {
                node::cli::load_secret_key_file(&file, node::cli::SecretKind::Secp256k1)
                    .unwrap_or_else(|e| panic!("invalid --signer-key-file: {e}"))
            } else if let Some(signer_hex) = node::cli::parse_cli_flag("--signer-key") {
                let mut signer_hex = zeroize::Zeroizing::new(signer_hex);
                let mut signer_bytes = node::cli::hex_decode(&signer_hex)
                    .unwrap_or_else(|e| panic!("invalid --signer-key hex: {e}"));
                let arr: [u8; 32] = signer_bytes
                    .as_slice()
                    .try_into()
                    .unwrap_or_else(|_| panic!("--signer-key must be 32 bytes (64 hex chars)"));
                signer_bytes.zeroize();
                signer_hex.zeroize();
                zeroize::Zeroizing::new(arr)
            } else {
                eprintln!(
                    "oxide-validator: --submit-key-change requires --signer-key <secp256k1-hex> or \
                 --signer-key-file <path> (hex or OXKEY keystore) — the key-change tx must be \
                 signed by the staking account it rotates"
                );
                std::process::exit(1);
            };
        if crypto::is_test_identity_key(&signer) {
            eprintln!(
                "oxide-validator: --signer-key is a public test-identity scalar — a known key \
                 cannot authorize a key rotation"
            );
            std::process::exit(1);
        }
        let validator_addr = crypto::signable_pubkey_address(&signer[..])
            .expect("--signer-key must be a valid secp256k1 secret");

        // The account's executed nonce — the tx must carry the
        // sender's next sequence or the mempool rejects it.
        let nonce = node.app().executed_nonce_of(&validator_addr);
        let msg_payload = staking::msg::key_change(validator_addr, &new_key_bytes, pop.as_bytes());
        let tx = node::cli::build_signed_tx_with(
            &signer[..],
            validator_addr,
            chain_id,
            framework::module_id::STAKING,
            &msg_payload,
            nonce,
        );
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
    println!("    keygen       Generate a fresh BLS (or --secp) secret key file");
    println!("                   --encrypt writes an OXKEY passphrase-keystore");
    println!("    signer       Run the remote-signing daemon (fenced, holds the key)");
    println!("    version      Print version information");
    println!("    help         Print this help message");
    println!();
    println!("FLAGS (default run mode is single-node):");
    println!("    --config <path>          Load config from TOML file");
    println!("    --engine <kind>           Consensus engine (sequencer|oxidebft)");
    println!("    --genesis-file <path>     Load genesis.json (validator set + balances)");
    println!("    --wal-file <path>         Consensus WAL file path");
    println!("    --data-dir <dir>          Persistent data dir (auto snapshot on shutdown)");
    println!("    --rpc-listen <addr>       RPC listen address (default: from config)");
    println!("    --export-snapshot <path>  Export state snapshot to file and exit");
    println!("    --import-snapshot <path>  Import state snapshot before starting");
    println!("    --submit-key-change <hex> Submit a BLS key-change transaction (new secret key)");
    println!("    --signer-key <hex>        secp256k1 key signing the key-change tx");
    println!("    --signer-key-file <path>  same, from a file (hex or OXKEY keystore)");
    println!("    --unsafe-allow-unsigned-txs");
    println!("                            UNSAFE dev mode: admit unsigned native txs");
    println!(
        "                            (unauthenticated sender). Refused on non-loopback binds."
    );
    println!("    --unsafe-allow-insecure-posture");
    println!("                            UNSAFE: allow devnet defaults on public binds");
    println!();
    println!("VALIDATOR MODE (production multi-validator):");
    println!("    --validator              Run oxideBFT over TCP/mTLS with peers from");
    println!("                             [network] peers (addr=host:port) + --peer flags");
    println!("    --bls-key-file <path>    BLS secret key (hex/raw/OXKEY)");
    println!("    --signer-addr <host:port>  Use a remote signer daemon instead of");
    println!("                             a key file (exactly one of the two required)");
    println!("    --signer-link-key-file <path>  Shared 32-byte link secret for");
    println!("                             --signer-addr (same file as the daemon's");
    println!("                             --link-key-file)");
    println!("    --tls-dir <dir>          mTLS: cert.pem, key.pem, peer-<addr-hex>.pem");
    println!("    --peer <addr>=<host:port>  Extra/override peer endpoint (repeatable)");
    println!();
    println!("    In validator mode --genesis-file is required and [network]");
    println!("    listen_addr/peers are live. Devnet-only flags (--num-nodes,");
    println!("    --base-port, --bind-host, --peer-host*) belong to the");
    println!("    oxide-devnet binary.");
    println!();
    println!("EXAMPLES:");
    println!("    oxide-validator init --chain-id 1");
    println!("    oxide-validator genesis --chain-id 1 --validators 4");
    println!("    oxide-validator tls-gen --num-nodes 4 --output-dir tls/");
    println!("    oxide-validator tls-gen --genesis-file genesis.json -o tls/   (validator mode)");
    println!("    oxide-validator keygen --output node-0.key");
    println!("    oxide-validator --validator --config config.toml \\");
    println!("        --genesis-file genesis.json --bls-key-file val.key \\");
    println!("        --tls-dir tls/node-0 --data-dir data/                (multi-validator)");
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
/// - `--validator-pubkeys <path>`: file of BLS public keys, one
///   `0x`-prefixed 96-hex-character line per validator — the source
///   of truth for the committee's identity. The count must equal
///   `--validators`.
/// - `--devnet`: fill `public_key` from the deterministic devnet
///   derivation instead — the matching secrets are publicly
///   computable, so this is only for local/testnet genesis.
///
/// Without one of the last two the command refuses: a genesis that
/// silently embeds derivable keys hands anyone the whole committee.
fn run_genesis(args: &[String]) {
    let mut chain_id: u64 = 1;
    let mut num_validators: usize = 4;
    let mut output = "genesis.json".to_string();
    let mut devnet_keys = false;
    let mut pubkeys_path: Option<String> = None;
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
            "--validator-pubkeys" => {
                if let Some(v) = args.get(i + 1) {
                    pubkeys_path = Some(v.clone());
                }
                i += 2;
            }
            "--devnet" => {
                devnet_keys = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let mut genesis =
        config::genesis::Genesis::devnet(chain_id, num_validators, 32, 1_000_000_000_000);

    // `public_key` fills from either the operator-supplied pubkey
    // file or — explicitly opted in via `--devnet` — the
    // deterministic derivation whose secrets anyone can recompute.
    match (pubkeys_path, devnet_keys) {
        (Some(path), false) => {
            let pubkeys = read_pubkey_file(&path);
            assert_eq!(
                pubkeys.len(),
                num_validators,
                "{path}: {} public keys but --validators is {num_validators}",
                pubkeys.len()
            );
            for (validator, pk) in genesis.staking.validators.iter_mut().zip(pubkeys) {
                validator.public_key = Some(pk);
            }
        }
        (None, true) => {
            for (idx, validator) in genesis.staking.validators.iter_mut().enumerate() {
                let key = node::cli::bls_key(u8::try_from(idx + 1).expect("index + 1 fits in u8"));
                let pk = key.public_key();
                validator.public_key = Some(format!("0x{}", node::cli::hex_encode(pk.as_bytes())));
            }
        }
        (Some(_), true) => {
            eprintln!(
                "oxide-validator genesis: --validator-pubkeys and --devnet are exclusive — \
                 the pubkeys either come from real keys or the public derivation"
            );
            std::process::exit(1);
        }
        (None, false) => {
            eprintln!(
                "oxide-validator genesis: refusing to embed derivable keys — \
                 pass --validator-pubkeys <file> (one 0x-prefixed 96-hex BLS public key \
                 per validator, from `oxide-validator keygen`) or --devnet for the \
                 public deterministic test set"
            );
            std::process::exit(1);
        }
    }

    let path = PathBuf::from(&output);
    genesis.to_json_file(&path).expect("write genesis file");
    println!(
        "oxide-validator genesis: wrote {} (chain_id={chain_id}, validators={num_validators})",
        path.display()
    );
}

/// Read a validator public-key file: one `0x`-prefixed 96-hex-char
/// BLS12-381 public key per non-empty, non-`#`-comment line — the
/// format `keygen` prints.
fn read_pubkey_file(path: &str) -> Vec<String> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read --validator-pubkeys {path}: {e}"));
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .enumerate()
        .map(|(i, line)| {
            let bytes = node::cli::hex_decode(line)
                .unwrap_or_else(|e| panic!("{path} line {}: bad hex: {e}", i + 1));
            assert_eq!(
                bytes.len(),
                48,
                "{path} line {}: BLS public key must be 48 bytes (96 hex), got {}",
                i + 1,
                bytes.len()
            );
            // A 48-byte string is only a key if it decodes to a
            // subgroup member — validate now so a malformed line
            // fails at genesis time, not at validator boot.
            crypto::bls_signer::ValidatedPublicKey::from_bytes(&bytes)
                .unwrap_or_else(|_| panic!("{path} line {}: not a BLS public key", i + 1));
            // Normalize to the canonical 0x-prefixed form genesis
            // consumers read.
            format!("0x{}", node::cli::hex_encode(&bytes))
        })
        .collect()
}

/// `oxide-validator tls-gen` — generate TLS certificates for a
/// multi-node testnet.
///
/// Generates a self-signed certificate + private key for each node,
/// then writes a per-node `--tls-dir` containing `cert.pem`,
/// `key.pem`, and `peer-{j}.pem` for every peer `j != i`.
///
/// Flags:
/// - `--num-nodes <N>`: number of validators (default: 4, no-genesis path)
/// - `--output-dir <dir>`: target directory (default: ./tls)
/// - `--genesis-file <path>`: committee source — peer certs keyed by
///   staking address (`peer-<addr-hex>.pem`), the production naming
///   `oxide-validator --validator --tls-dir` consumes
///
/// The output layout is:
/// ```text
/// tls/
/// ├── node-0/
/// │   ├── cert.pem       — member 0's certificate
/// │   ├── key.pem        — member 0's private key
/// │   ├── peer-*.pem     — every other member's certificate
/// └── ...
/// ```
///
/// Each node runs with `--tls-dir tls/node-{i}` where `i` is the
/// committee index (devnet) or the member's position in the genesis
/// validator list (validator mode).
///
/// # Security
///
/// These are **self-signed** certificates — suitable for devnet and
/// testnet but NOT production. For production, generate certificates
/// from a proper CA (e.g., `step ca`, `HashiCorp` Vault PKI, or
/// cloud-native `cert-manager`) and distribute via `--tls-dir` with
/// the CA's certificate chain in each `peer-<id>.pem`.
/// - `--genesis-file <path>`: generate certs keyed by the genesis
///   committee's staking addresses — peer files are written as
///   `peer-<addr-hex>.pem` (the production `validator_net` naming)
///   and each cert's peer id is the member's 20-byte address. This
///   is the mode `oxide-validator --validator --tls-dir` and
///   `oxide-devnet --tls-dir` consume.
/// - Without `--genesis-file`: index-byte peer ids and
///   `peer-{j}.pem` files — a legacy layout kept for transport-level
///   debugging; no shipped binary consumes it anymore (devnet peer
///   ids are staking addresses too).
fn run_tls_gen(args: &[String]) {
    let mut num_nodes: usize = 4;
    let mut output_dir = "tls".to_string();
    let mut genesis_path: Option<String> = None;
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
            "--genesis-file" => {
                if let Some(v) = args.get(i + 1) {
                    genesis_path = Some(v.clone());
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let base = PathBuf::from(&output_dir);

    // Generate a cert+key pair per member. Peer ids: genesis mode
    // uses the member's staking address (what `validator_net`'s
    // transport expects); the no-genesis path keeps the legacy
    // index-byte convention — the cert's CN is cosmetic either way:
    // `TlsConfig` binds cert-DER → peer-id through its
    // trusted-peers map.
    let members: Vec<(Vec<u8>, String)> = if let Some(path) = genesis_path {
        let genesis = config::genesis::Genesis::from_json_file(&PathBuf::from(&path))
            .unwrap_or_else(|e| panic!("failed to load genesis file {path}: {e}"));
        let set = node::cli::validator_set_from_genesis(&genesis)
            .unwrap_or_else(|e| panic!("invalid genesis validator set: {e}"));
        set.validator_addresses()
            .iter()
            .map(|a| (a.0.to_vec(), node::cli::hex_encode(&a.0)))
            .collect()
    } else {
        (0..num_nodes)
            .map(|i| (vec![u8::try_from(i).expect("node index fits in u8")], i.to_string()))
            .collect()
    };
    let certs: Vec<(String, String)> =
        members.iter().map(|(peer_id, _)| p2p::tls::generate_ca_cert_pem(peer_id)).collect();

    // Write per-node directories: cert.pem + key.pem + peer certs.
    for (i, _) in members.iter().enumerate() {
        let dir = base.join(format!("node-{i}"));
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("failed to create {}: {e}", dir.display()));
        std::fs::write(dir.join("cert.pem"), &certs[i].0)
            .unwrap_or_else(|e| panic!("failed to write cert.pem: {e}"));
        std::fs::write(dir.join("key.pem"), &certs[i].1)
            .unwrap_or_else(|e| panic!("failed to write key.pem: {e}"));
        for (j, (cert, _)) in certs.iter().enumerate() {
            if j != i {
                std::fs::write(dir.join(format!("peer-{}.pem", members[j].1)), cert)
                    .unwrap_or_else(|e| panic!("failed to write peer cert: {e}"));
            }
        }
    }

    println!(
        "oxide-validator tls-gen: wrote {} node dirs to {} (use --tls-dir {}/node-<i>)",
        members.len(),
        base.display(),
        base.display()
    );
}

/// `oxide-validator signer` — run the remote-signing daemon.
///
/// Holds the consensus secret behind a TCP listener and a durable
/// high-watermark fence (`--state-file`): `Vote`/`Timeout`/
/// `Proposal`/`ExecAttest` requests sign only at monotonically
/// advancing `(epoch, mark, phase)` coordinates, and a conflicting
/// message at a repeated coordinate is refused — the
/// anti-equivocation property a validator failover pair gets by
/// pointing both processes at one daemon. The fence is persisted
/// before each signature is released, so a restarted daemon cannot
/// be made to equivocate either.
///
/// Flags:
/// - `--listen <host:port>`: bind address (default `127.0.0.1:26261`).
///   Every client must prove the `--link-key-file` secret in the
///   connect handshake — still bind loopback or a private interface
///   so the port stays off hostile networks.
/// - `--bls-key-file <path>`: the consensus secret (hex, raw 32B,
///   or OXKEY keystore). Required.
/// - `--state-file <path>`: the durable fence file. Required —
///   without it a restart would forget what was signed.
/// - `--link-key-file <path>`: the 32-byte shared link secret
///   authenticating validator connections (hex, raw, or OXKEY
///   `generic` keystore). Required — an unauthenticated signer
///   link is a signing oracle for anyone who can reach the port.
fn run_signer_daemon(args: &[String]) {
    let mut listen = "127.0.0.1:26261".to_string();
    let mut key_path: Option<String> = None;
    let mut state_path: Option<String> = None;
    let mut link_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                if let Some(v) = args.get(i + 1) {
                    listen.clone_from(v);
                }
                i += 2;
            }
            "--bls-key-file" => {
                if let Some(v) = args.get(i + 1) {
                    key_path = Some(v.clone());
                }
                i += 2;
            }
            "--state-file" => {
                if let Some(v) = args.get(i + 1) {
                    state_path = Some(v.clone());
                }
                i += 2;
            }
            "--link-key-file" => {
                if let Some(v) = args.get(i + 1) {
                    link_path = Some(v.clone());
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    let (Some(key_path), Some(state_path), Some(link_path)) = (key_path, state_path, link_path)
    else {
        eprintln!(
            "oxide-validator signer: requires --bls-key-file <path>, \
             --state-file <path>, and --link-key-file <path> — the key, \
             the durable fence, and the link credential are all mandatory \
             (an in-memory fence forgets what it signed; an unauthenticated \
             link is a signing oracle)"
        );
        std::process::exit(1);
    };
    let key_bytes = node::cli::load_secret_key_file(&key_path, node::cli::SecretKind::Bls)
        .unwrap_or_else(|e| panic!("invalid BLS key file {key_path}: {e}"));
    let key = crypto::BlsSecretKey::from_bytes(&key_bytes[..])
        .unwrap_or_else(|e| panic!("invalid BLS secret key in {key_path}: {e:?}"));
    let link_key = node::cli::load_secret_key_file(&link_path, node::cli::SecretKind::Generic)
        .unwrap_or_else(|e| panic!("invalid link key file {link_path}: {e}"));
    let daemon = node::remote_signer::SignerDaemon::new(key, PathBuf::from(&state_path), *link_key)
        .unwrap_or_else(|e| panic!("cannot open signer state {state_path}: {e}"));
    let daemon = std::sync::Arc::new(daemon);
    let listener = std::net::TcpListener::bind(&listen)
        .unwrap_or_else(|e| panic!("cannot bind signer listener {listen}: {e}"));
    println!(
        "oxide-validator signer: serving {} on {listen} (fence: {state_path})",
        node::cli::hex_encode(daemon.public_key().as_bytes())
    );
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let _ = primitives::supervision::spawn_supervised("signer-signal", false, move || {
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
            shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    });
    daemon.serve(listener, &shutdown);
    println!("oxide-validator signer: shutdown");
}

/// `oxide-validator keygen` — generate a fresh secret key from the
/// OS CSPRNG.
///
/// Flags:
/// - `--secp`: secp256k1 secret (transaction signing, settlement
///   operator). Default is BLS12-381 (consensus identity —
///   `--bls-key-file` format: 32-byte canonical scalar, hex).
/// - `--output|-o <path>`: destination file (default `key.hex`).
/// - `--encrypt`: write a passphrase-encrypted `OXKEY` keystore
///   instead of raw hex. The passphrase comes from the
///   `OXIDE_KEY_PASSPHRASE` environment variable — never argv, which
///   is world-readable in `ps`.
///
/// The file is written owner-only (mode 0600 on Unix) and the
/// command refuses to overwrite an existing path — keys are not
/// recyclable config. The public half prints to stdout so it can be
/// carried into a genesis file without the secret leaving the
/// machine.
fn run_keygen(args: &[String]) {
    let mut output = "key.hex".to_string();
    let mut secp = false;
    let mut encrypt = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secp" => {
                secp = true;
                i += 1;
            }
            "--encrypt" => {
                encrypt = true;
                i += 1;
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

    let (kind_name, kind, secret, public) = if secp {
        let key = crypto::generate_secret_key();
        let addr =
            crypto::signable_pubkey_address(&key).expect("a generated secp256k1 key is valid");
        (
            "secp256k1",
            crypto::keystore::KeyKind::Secp256k1,
            zeroize::Zeroizing::new(key),
            format!("address 0x{}", node::cli::hex_encode(&addr.0)),
        )
    } else {
        // BLS keygen is HKDF over an IKM — 32 OS-CSPRNG bytes in,
        // canonical scalar out (`--bls-key-file` reads this format).
        let mut ikm = zeroize::Zeroizing::new([0u8; 32]);
        crypto::fill_random(&mut ikm[..]);
        let key = crypto::BlsSecretKey::from_ikm(&ikm[..]).expect("32-byte IKM always keygens");
        let pk = key.public_key();
        (
            "BLS12-381",
            crypto::keystore::KeyKind::Bls,
            key.to_bytes(),
            format!("public key 0x{}", node::cli::hex_encode(pk.as_bytes())),
        )
    };

    let file_bytes: Vec<u8> = if encrypt {
        let pass = match crypto::keystore::passphrase_from_env() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("oxide-validator keygen --encrypt: {e}");
                std::process::exit(1);
            }
        };
        match crypto::keystore::seal(kind, &secret, &pass) {
            Ok(blob) => blob,
            Err(e) => {
                eprintln!("oxide-validator keygen --encrypt: {e}");
                std::process::exit(1);
            }
        }
    } else {
        node::cli::hex_encode(&secret[..]).into_bytes()
    };

    if let Err(e) = write_secret_key_file(&output, &file_bytes) {
        eprintln!("oxide-validator keygen: {e}");
        std::process::exit(1);
    }
    println!("oxide-validator keygen: wrote {kind_name} secret to {output}");
    println!("  {public}");
    if encrypt {
        println!(
            "  (encrypted keystore — unlock with OXIDE_KEY_PASSPHRASE; keep it mode 0600 anyway)"
        );
    } else {
        println!("  (the secret file is mode 0600 — never commit or copy it to another host)");
        println!("  (tip: --encrypt writes a passphrase-protected OXKEY keystore instead)");
    }
}

/// Write a generated secret key file: create-new (never overwrite)
/// and owner-only permissions. A key file that already exists is a
/// deliberate operator artifact — silently replacing it could rotate
/// a validator's identity mid-deployment.
fn write_secret_key_file(path: &str, contents: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            f.write_all(contents).map_err(|e| format!("failed to write key file {path}: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(format!("refusing to overwrite existing file {path}"))
        }
        Err(e) => Err(format!("failed to create key file {path}: {e}")),
    }
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

    /// `keygen` never clobbers an existing key file — a stale path
    /// must fail rather than silently rotate an identity, and the
    /// written file is owner-only.
    #[test]
    fn keygen_file_write_refuses_overwrite() {
        let path = std::env::temp_dir().join(format!(
            "oxide-keygen-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let path = path.to_str().expect("temp path is UTF-8").to_string();
        super::write_secret_key_file(&path, b"aa").expect("first write creates the file");
        let err = super::write_secret_key_file(&path, b"bb").expect_err("second write must refuse");
        assert!(err.contains("refusing to overwrite"), "{err}");
        // Contents unchanged — the refusal wrote nothing.
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "aa");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be owner-only");
        }
        std::fs::remove_file(&path).ok();
    }
}
