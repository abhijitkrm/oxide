//! `oxide-devnet` — the development multi-validator node binary.
//!
//! One process per validator in a multi-process devnet: consensus
//! over real TCP (or mTLS) transport, the production module graph
//! via [`node::assemble_executor`], JSON-RPC, tx gossip, WAL
//! persistence, and snapshot import/export.
//!
//! This is a **development harness**, not the production validator:
//! its default identities (`bls_key(byte)`) and addresses are
//! deterministic fixtures. It lives in its own binary so
//! `oxide-validator` carries no dev-only network mode — the audit's
//! "separate development launchers from production binaries" (6.5).
//! The launcher (`devnet::multiprocess`) spawns it as:
//!
//! ```sh
//! oxide-devnet --node 0 --num-nodes 4 --base-port 22000
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use ports::ConsensusEngine;
use ports::transport::Transport;
use types::TxBytes;

// Codec traits for encoding/decoding consensus messages.
use codec::{Decode, Encode};

fn main() {
    // Supervision before anything can spawn: a panic on a critical
    // actor's thread aborts the process so the supervisor restarts a
    // coherent node instead of running half-alive.
    primitives::supervision::install_panic_hook();

    // Initialize tracing so `RUST_LOG` controls log levels.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // `oxide-devnet --node <i>` is required: this binary is one
    // validator process in a multi-node devnet, spawned by
    // `devnet::multiprocess::MultiProcessDevnet` or by hand.
    let node_index_str = node::cli::parse_cli_flag("--node").unwrap_or_else(|| {
        eprintln!(
            "oxide-devnet: missing required --node <i> (validator index); \
             usage: oxide-devnet --node <i> --num-nodes <N> --base-port <P>"
        );
        std::process::exit(2);
    });
    run_node(&node_index_str);
}

// ── Devnet message tags ─────────────────────────────────
// One-byte type tags for the TCP message framing: the first
// byte of each message identifies the payload type.
const MSG_PROPOSAL: u8 = 0x00;
const MSG_VOTE: u8 = 0x01;
const MSG_QC: u8 = 0x02;
const MSG_TIMEOUT: u8 = 0x03; // timeout signature (view-change init)
const MSG_TC: u8 = 0x04; // timeout certificate (view-change proof)
const MSG_TX: u8 = 0x05; // raw tx envelope gossip (mempool propagation)

/// Idle heartbeat interval for the consensus pump (unit: wall-clock
/// time). A leader with no pending work still owes the network a
/// — usually empty — block on this cadence: followers cannot
/// distinguish "idle" from "dead", so silence would churn views
/// through timeout certificates forever. Must stay comfortably
/// below the pacemaker's base timeout (2s default) so a live idle
/// leader's heartbeats keep follower timers reset; 1s leaves a
/// full timeout of slack for scheduling jitter. Lower = more empty
/// blocks (fresher liveness evidence, more I/O); higher = fewer
/// blocks but closer to timeout churn.
const IDLE_HEARTBEAT: Duration = Duration::from_secs(1);

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
/// | `--node <i>` | This node's process slot — the port offset (`base_port + i`); committee seat comes from the key |
/// | `--num-nodes <N>` | Total validators (default: from genesis/config) |
/// | `--base-port <p>` | Base TCP port (default: from genesis/config) |
/// | `--bind-host <h>` | Bind address (default: `127.0.0.1`) |
/// | `--peer <addr>=<host:port>` | Explicit peer endpoint, repeatable — `addr` is the member's staking address (hex). Overrides the template for that member; also admits non-committee endpoints (e.g. a scheduled rotation's incoming member) |
/// | `--peer-host-template <fmt>` | Peer hostname template (`{i}` = committee index) — used when no `--peer` matches |
/// | `--config <path>` | TOML config file |
/// | `--genesis-file <path>` | `genesis.json` (validator set + balances) |
/// | `--bls-key-file <path>` | BLS secret key (hex or raw 32 bytes) |
/// | `--tls-dir <dir>` | TLS directory (`cert.pem`, `key.pem`, `peer-{i}.pem`) |
/// | `--wal-file <path>` | Consensus WAL file path |
/// | `--rpc-listen <addr>` | RPC listen address (default: from config) |
/// | `--export-snapshot <path>` | Export snapshot to file and exit |
/// | `--import-snapshot <path>` | Import snapshot from file before starting |
/// | `--submit-key-change <hex>` | Submit a key-change tx (new BLS **secret** key — `PoP` required) |
/// | `--unsafe-allow-insecure-posture` | Allow devnet defaults on non-loopback binds (private testnets only) |
///
/// # External binds
///
/// When `--bind-host` or the RPC listener is reachable from other
/// machines, startup refuses unless the deployment is explicitly
/// configured: an operator BLS key (`--bls-key-file`), mTLS
/// (`--tls-dir`), a genesis file (`--genesis-file`), a non-public
/// chain ID, and a non-zero `min_fee`. The refusal lists every
/// violation at once. `--unsafe-allow-insecure-posture` is the
/// opt-out for private testnets (e.g. a container bridge network
/// whose wildcard bind is not actually public).
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
/// - `peer-{i}.pem` — the certificate of committee member `i`
/// - `peer-<addr hex>.pem` — the certificate of a `--peer` endpoint
///   that is not a genesis committee member (e.g. a pending member
///   being admitted before its rotation activates)
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
fn run_node(node_index_str: &str) {
    // Load base config (TOML + env vars + CLI overrides), validated
    // and emitted as the effective config.
    let cfg = node::cli::load_config(node::NodeMode::Devnet, "oxide-devnet");
    let rpc_config = &cfg.rpc;
    let genesis_config = &cfg.genesis_cfg;

    let node_index: usize =
        node_index_str.parse().unwrap_or_else(|e| panic!("invalid --node index: {e}"));
    let num_nodes: usize = node::cli::parse_cli_flag("--num-nodes")
        .and_then(|s| s.parse().ok())
        .unwrap_or(genesis_config.num_validators);
    let base_port: u16 = node::cli::parse_cli_flag("--base-port")
        .and_then(|s| s.parse().ok())
        .unwrap_or(genesis_config.base_port);
    let bind_host =
        node::cli::parse_cli_flag("--bind-host").unwrap_or_else(|| "127.0.0.1".to_string());
    let peer_host_template = node::cli::parse_cli_flag("--peer-host-template")
        .or_else(|| node::cli::parse_cli_flag("--peer-host"));

    println!(
        "oxide-devnet[{node_index}]: devnet node mode — index={node_index}, num_nodes={num_nodes}, base_port={base_port}, bind_host={bind_host}"
    );

    // BLS key: --bls-key-file or deterministic.
    let our_key = load_bls_key(node_index);

    // ValidatorSet: --genesis-file or deterministic.
    let validator_set = load_validator_set(num_nodes, node_index);

    // The loaded key authenticates this node as whichever committee
    // member holds it — the peer handshake proves key ownership per
    // staking address, so a key not in the committee (or one a
    // rotation has since dropped) would boot cleanly and then have
    // every peer reject it. Fail at startup. `--node` stays the
    // process slot (port offset); the committee seat is the key's
    // position — post-rotation genesis files legitimately pair them
    // differently.
    let our_pk = our_key.public_key();
    let Some(our_seat) = validator_set.index_of_key(&our_pk) else {
        eprintln!(
            "oxide-devnet[{node_index}]: refusing to start — --bls-key-file is not in the \
             validator set (check --genesis-file / --bls-key-file pairing)"
        );
        std::process::exit(1);
    };
    // Peer identity is the validator's staking address — the stable
    // identity that survives index reshuffles on removal and key
    // replacement on rotation. Our own address (becomes our
    // transport peer id) is read from the committee, never derived.
    let our_addr = validator_set.validator_addresses()[usize::from(our_seat)];
    let own_id = our_addr.0.to_vec();

    let listen_port = base_port + u16::try_from(node_index).expect("port fits in u16");
    let listen_addr = format!("{bind_host}:{listen_port}");

    // Explicit peer endpoints: `--peer <addr_hex>=<host:port>`,
    // repeatable. These override the port template for the listed
    // committee members AND admit endpoints beyond the committee —
    // the pre-activation dial for a scheduled rotation's incoming
    // member (the transport authenticates membership live, so a
    // --peer that never joins the committee simply fails auth).
    let mut peer_overrides: std::collections::HashMap<primitives::Address, String> =
        std::collections::HashMap::new();
    for spec in node::cli::parse_cli_flags("--peer") {
        let Some((addr_hex, hostport)) = spec.split_once('=') else {
            eprintln!(
                "oxide-devnet[{node_index}]: invalid --peer '{spec}' — \
                 expected <addr_hex>=<host:port>"
            );
            std::process::exit(1);
        };
        let addr_bytes = node::cli::hex_decode(addr_hex).unwrap_or_else(|e| {
            eprintln!("oxide-devnet[{node_index}]: invalid --peer address '{addr_hex}': {e}");
            std::process::exit(1);
        });
        let Ok(addr_arr): Result<[u8; 20], _> = addr_bytes.try_into() else {
            eprintln!("oxide-devnet[{node_index}]: --peer address '{addr_hex}' must be 20 bytes");
            std::process::exit(1);
        };
        peer_overrides.insert(primitives::Address(addr_arr), hostport.to_string());
    }

    // Build peer list: every other committee member, endpoint from
    // the explicit override else the `base_port + committee index`
    // template (correct for slot-aligned genesis committees;
    // post-rotation committees use --peer), then any non-committee
    // overrides appended so pending members are reachable early.
    let mut peers: Vec<(Vec<u8>, String)> = Vec::new();
    // peer-id → TLS cert filename (peer-<i>.pem for committee
    // members; peer-<addr-hex>.pem for explicit extras) — the
    // transport consumes it when --tls-dir is set.
    let mut peer_cert_names: std::collections::HashMap<Vec<u8>, String> =
        std::collections::HashMap::new();
    for (i, addr) in validator_set.validator_addresses().iter().enumerate() {
        if i == usize::from(our_seat) {
            continue;
        }
        let hostport = peer_overrides.remove(addr).unwrap_or_else(|| {
            let host = match &peer_host_template {
                Some(tmpl) => tmpl.replace("{i}", &i.to_string()),
                None => "127.0.0.1".to_string(),
            };
            let port = base_port + u16::try_from(i).expect("port fits in u16");
            format!("{host}:{port}")
        });
        peer_cert_names.insert(addr.0.to_vec(), format!("peer-{i}.pem"));
        peers.push((addr.0.to_vec(), hostport));
    }
    for (addr, hostport) in peer_overrides {
        peer_cert_names.insert(addr.0.to_vec(), format!("peer-{}", node::cli::hex_encode(&addr.0)));
        peers.push((addr.0.to_vec(), hostport));
    }

    println!(
        "oxide-devnet[{node_index}]: listening on {listen_addr}, {} peers, seat {our_seat} of {}",
        peers.len(),
        validator_set.n()
    );

    // Assemble the node through the ONE shared production path —
    // `node::devnet::assemble_devnet_node` runs the same executor
    // graph, engine wiring (configured timeouts/budget), WAL
    // recovery, and membership gate the harnesses consume. If
    // --genesis-file was given, the staking validators and native
    // balances are already applied via `node.genesis`; `evm.alloc`
    // is applied on the module handle below.
    // `--wal-file` overrides the derived `<data_dir>/consensus.wal`
    // path; when neither is set the WAL stays in-memory.
    let wal_path = node::cli::parse_cli_flag("--wal-file").map(PathBuf::from);
    let node::devnet::DevnetNode {
        mut engine,
        app,
        evm_module,
        staking_module: _,
        exchange_module: _,
        recovered: _,
        recovery,
        wal_path: effective_wal_path,
    } = node::devnet::assemble_devnet_node(node::devnet::DevnetNodeSpec {
        // The engine seat is the committee position our key holds —
        // decoupled from `--node` (the process slot) so a
        // post-rotation genesis can seat a node at a different index
        // than its port offset.
        index: usize::from(our_seat),
        validator_set: validator_set.clone(),
        secret_key: our_key.clone(),
        config: cfg.node.clone(),
        clock: None, // production wall clock
        wal_path,
    })
    .unwrap_or_else(|e| {
        eprintln!("oxide-devnet[{node_index}]: {e} — exiting");
        std::process::exit(1);
    });
    let app: Arc<executor::Executor> = app;
    // `evm.alloc` is genesis state: it applies on a fresh start
    // only. `assemble_executor` already ran durable recovery, so a
    // restart arrives here holding the replayed tip — overwriting
    // alloc accounts now would rewind balances the chain moved.
    let fresh_start =
        recovery.as_ref().is_none_or(|r| r.snapshot_height.is_none() && r.blocks_replayed == 0);
    if fresh_start && let Some(genesis) = &cfg.genesis_file {
        apply_evm_alloc(&evm_module, genesis);
    }
    if let Some(ref wal_path) = effective_wal_path {
        println!("oxide-devnet[{node_index}]: WAL loaded from {}", wal_path.display());
    }

    // Shared validator set — created before the transport so the
    // handshake authenticator and the RPC provider both read the
    // same live committee. The consensus loop writes the rotated
    // set at each epoch boundary; readers always see the current
    // keys.
    let shared_validator_set = Arc::new(std::sync::RwLock::new(validator_set.clone()));
    // Shared pending set: while a rotation is scheduled, the
    // consensus loop publishes `engine.next_validator_set()` here so
    // `BlsPeerAuth` admits the incoming member's handshake BEFORE
    // its first consensus duty — a member admitted only at
    // activation would miss its opening views. `None` otherwise.
    let shared_next_validator_set =
        Arc::new(std::sync::RwLock::new(Option::<consensus::ValidatorSet>::None));

    // Create the TCP transport: --tls-dir for mTLS, plain TCP
    // otherwise. `[network]` timeouts and the frame bound flow into
    // `TcpTransportConfig`. Peer IDs are cryptographically bound to
    // committee keys via the signed greeting (`BlsPeerAuth`) — a
    // self-claimed ID can neither join nor displace a live peer.
    let mut transport = build_transport(
        &listen_addr,
        node_index,
        own_id,
        peers,
        peer_cert_names,
        &cfg.network,
        our_key.clone(),
        shared_validator_set.clone(),
        shared_next_validator_set.clone(),
    );

    // Give connections time to establish. TLS handshakes take
    // longer than plain TCP — 2s gives all peers time to connect
    // and complete the handshake before the first proposal.
    thread::sleep(Duration::from_millis(2000));

    // Data directory: `--data-dir` or `[storage] data_dir` enables
    // durable state — `<dir>/block-journal/` records every finalized
    // block and `<dir>/snapshot.bin` is the periodic checkpoint, both
    // already replayed by `assemble_executor` above (the `recovery`
    // report). The EVM state database at `<dir>/evm.redb` was wired
    // the same way via `node.storage_path`.
    //
    // This gives a restarting validator full state persistence
    // without requiring manual `--export-snapshot` /
    // `--import-snapshot` flags. The WAL (if `--wal-file` is also
    // given) protects consensus safety state across the restart.
    let data_dir = cfg.data_dir.clone();
    if let Some(ref dir) = data_dir {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed to create data dir {}: {e}", dir.display()));
        if let Some(report) = &recovery {
            if report.snapshot_height.is_some() || report.blocks_replayed > 0 {
                println!(
                    "oxide-devnet[{node_index}]: recovered durable state from {} \
                     (snapshot {:?}, replayed {} blocks, height {})",
                    dir.display(),
                    report.snapshot_height,
                    report.blocks_replayed,
                    report.recovered_height,
                );
            }
            if let Some(reason) = &report.snapshot_rejected {
                eprintln!(
                    "oxide-devnet[{node_index}]: snapshot.bin rejected ({reason}); \
                     recovered from the block journal alone"
                );
            }
        }
    }

    // Shared validator set — created above (before the transport)
    // so the handshake authenticator and the RPC handler read the
    // same live committee.

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

    println!("oxide-devnet[{node_index}]: consensus engine started, waiting for blocks...");

    // Smoke-test transaction, devnet genesis only: a staking
    // delegate signed by devnet identity 0 to itself. Under a real
    // `--genesis-file` the node must not emit transactions signed
    // by a public test identity — the account is not funded there
    // anyway, so the tx would be skipped work.
    if cfg.genesis_file.is_none() {
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
        engine.submit_tx(tx);
    }

    let height = engine.finalized_height();
    println!("oxide-devnet[{node_index}]: finalized height = {height:?}");
    println!("oxide-devnet[{node_index}]: node running (press Ctrl+C to stop)");

    // Graceful shutdown: SIGINT/SIGTERM sets the shutdown flag, which
    // `run_consensus_loop` checks each iteration. On Unix, SIGTERM
    // is handled via `signal(SignalKind::terminate())`; on other
    // platforms, only SIGINT (Ctrl+C) is caught.
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    // Non-critical: if the signal thread dies, the node keeps running
    // and only loses graceful-shutdown signaling — visible via the
    // registry, not fatal.
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
            shutdown_clone.store(true, Ordering::Relaxed);
        });
    });

    // Run the consensus message pump loop.
    run_consensus_loop(
        &mut engine,
        &mut transport,
        node_index,
        our_addr,
        shutdown.as_ref(),
        rpc_handle.as_deref(),
        &shared_validator_set,
        &shared_next_validator_set,
        &gossip_rx,
    );

    // Graceful shutdown: if --data-dir is set, export the current
    // state to `<dir>/snapshot.bin` so a restart can resume with
    // the full chain state (not just the WAL).
    if let Some(ref dir) = data_dir {
        let height = node::devnet::export_snapshot(&app, dir).unwrap_or_else(|e| panic!("{e}"));
        println!(
            "oxide-devnet[{node_index}]: exported snapshot to {} (height {height})",
            dir.join("snapshot.bin").display(),
        );
    }
    println!("oxide-devnet[{node_index}]: shutdown complete");
}

/// Load a BLS secret key: `--bls-key-file` (hex or raw 32 bytes) or
/// deterministic from node index (devnet fallback).
///
/// # Panics
///
/// Panics if `--bls-key-file` is given but the file cannot be read,
/// decoded, or parsed into a valid `BlsSecretKey`.
fn load_bls_key(index: usize) -> crypto::BlsSecretKey {
    if let Some(path) = node::cli::parse_cli_flag("--bls-key-file") {
        // Raw hex, raw bytes, or an encrypted `OXKEY` keystore —
        // `load_secret_key_file` sniffs the format (keystore needs
        // `OXIDE_KEY_PASSPHRASE` in the environment).
        let bytes = node::cli::load_secret_key_file(&path, node::cli::SecretKind::Bls)
            .unwrap_or_else(|e| panic!("invalid BLS key file: {e}"));
        crypto::BlsSecretKey::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("invalid BLS secret key in {path}: {e:?}"))
    } else {
        // Deterministic devnet fallback — NOT suitable for production.
        node::cli::bls_key(u8::try_from(index + 1).expect("index + 1 fits in u8"))
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
    if let Some(path) = node::cli::parse_cli_flag("--genesis-file") {
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
                let bytes = node::cli::hex_decode(hex).unwrap_or_else(|e| {
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
                let bytes = node::cli::hex_decode(&v.address)
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
        let secret_keys: Vec<crypto::BlsSecretKey> = (1..=u8::try_from(num_nodes)
            .expect("num_nodes fits in u8"))
            .map(node::cli::bls_key)
            .collect();
        let pks: Vec<crypto::bls::PublicKey> =
            secret_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        let stakes = vec![1u64; num_nodes];
        // Key-derived devnet identities (`test_identity_address(i)`)
        // so each validator's staking address is one it could sign
        // for — byte-pattern addresses can never authenticate.
        let addresses: Vec<primitives::Address> = (0..num_nodes)
            .map(|i| {
                crypto::secp::test_identity_address(u8::try_from(i).unwrap_or(0))
                    .expect("devnet identity is a valid key")
            })
            .collect();
        consensus::ValidatorSet::with_addresses(pks, stakes, addresses).expect("validator set")
    }
}

/// Build the TCP transport: `--tls-dir` for mTLS, plain TCP otherwise.
///
/// The `[network]` section supplies the timeouts and frame bound.
/// Admission is cryptographic, not list-based: `allowed_peer_ids`
/// stays `None` because a static set can never follow committee
/// rotations (a member added post-boot would be refused before the
/// handshake it must pass). `BlsPeerAuth` resolves each connection's
/// address-id against the LIVE validator set — plus the staged
/// `pending` set during a rotation's activation window — and
/// requires a `Domain::PeerHandshake` signature under that member's
/// registered key. A self-claimed id can neither join nor displace
/// a live peer, and a removed member's proofs die the moment the
/// new set activates.
///
/// `peer_cert_names` maps each peer id to its certificate filename
/// under `--tls-dir` — `peer-<committee index>.pem` for genesis
/// members, `peer-<addr hex>.pem` for explicit `--peer` endpoints.
/// A peer without a cert file gets no trusted-peers entry and so
/// can never complete mTLS.
///
/// # Panics
///
/// Panics if `--tls-dir` is given but the TLS config cannot be built
/// (missing cert/key files, invalid PEM, etc.).
#[allow(clippy::too_many_arguments)]
fn build_transport(
    listen_addr: &str,
    node_index: usize,
    own_id: Vec<u8>,
    peers: Vec<(Vec<u8>, String)>,
    peer_cert_names: std::collections::HashMap<Vec<u8>, String>,
    network: &config::NetworkConfig,
    our_key: crypto::BlsSecretKey,
    validators: Arc<std::sync::RwLock<consensus::ValidatorSet>>,
    pending: Arc<std::sync::RwLock<Option<consensus::ValidatorSet>>>,
) -> p2p::tcp::TcpTransport {
    // Signed greeting: peer IDs are staking addresses bound to
    // committee keys, so a connection claiming member `a` must sign
    // with the key registered for `a` — the ID can no longer be
    // self-claimed, and a duplicate connection is a
    // proven-same-identity reconnect, not a hijack. The shared sets
    // mean committee rotations take effect without a transport
    // restart.
    let auth: Arc<dyn p2p::tcp::PeerAuth> =
        Arc::new(node::peer_auth::BlsPeerAuth::new(our_key, validators, pending));
    let transport_config =
        p2p::tcp::TcpTransportConfig { peer_auth: Some(auth), ..to_transport_config(network) };
    // Admission control is always on in the shipped node: connection
    // caps, per-peer ingress rate limits, and reputation bans are not
    // optional defenses. Default limits (256 connections, 10 MiB
    // burst / 1 MiB/s per peer) comfortably fit consensus traffic.
    let admission =
        p2p::admission::SharedAdmissionControl::new(p2p::admission::AdmissionControl::new());
    if let Some(tls_dir) = node::cli::parse_cli_flag("--tls-dir") {
        let cert_path = format!("{tls_dir}/cert.pem");
        let key_path = format!("{tls_dir}/key.pem");
        let trusted_peers: Vec<(Vec<u8>, String)> = peers
            .iter()
            .filter_map(|(peer_id, _)| {
                peer_cert_names
                    .get(peer_id)
                    .map(|name| (peer_id.clone(), format!("{tls_dir}/{name}")))
            })
            .collect();
        let trusted_peers_refs: Vec<(Vec<u8>, &str)> =
            trusted_peers.iter().map(|(id, path)| (id.clone(), path.as_str())).collect();
        let tls_config =
            p2p::tls::TlsConfig::from_files(&cert_path, &key_path, &trusted_peers_refs)
                .unwrap_or_else(|e| panic!("failed to build TLS config from {tls_dir}: {e}"));
        println!("oxide-devnet[{node_index}]: mTLS enabled ({tls_dir})");
        p2p::tcp::TcpTransport::with_tls_and_admission(
            listen_addr,
            own_id,
            peers,
            transport_config,
            tls_config,
            admission,
        )
    } else {
        p2p::tcp::TcpTransport::with_admission(
            listen_addr,
            own_id,
            peers,
            transport_config,
            admission,
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
                address: format!("0x{}", node::cli::hex_encode(&addr.0)),
                public_key: format!("0x{}", node::cli::hex_encode(pk.as_bytes())),
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
    let listen = node::cli::parse_cli_flag("--rpc-listen").or_else(|| {
        if rpc_config.listen_addr.is_empty() { None } else { Some(rpc_config.listen_addr.clone()) }
    })?;

    let mut rpc_server = rpc::RpcServer::new(rpc_config.chain_id, rpc_config.base_fee)
        .with_debug_api(rpc_config.enable_debug_api);
    // Gossip-aware submitter: accepted txs are broadcast to all peers
    // so a tx sent to a non-leader still reaches the current leader.
    rpc_server.set_tx_submitter(Arc::new(node::rpc_adapters::GossipingTxSubmitter {
        inner: node::rpc_adapters::ExecutorTxSubmitter { executor: app.clone() },
        gossip: gossip_tx,
    }));
    rpc_server.set_evm(evm_module.clone());
    rpc_server.set_txpool_provider(Arc::new(node::rpc_adapters::ExecutorTxpoolProvider {
        executor: app.clone(),
    }));
    rpc_server.set_snapshot_provider(Arc::new(node::rpc_adapters::ExecutorSnapshotProvider {
        executor: app.clone(),
    }));
    rpc_server.set_validator_set_provider(Arc::new(SharedValidatorSetProvider {
        set: shared_validator_set,
    }));
    let rpc = Arc::new(rpc_server);
    let http_server = rpc::server::HttpServer::from_shared(rpc.clone(), listen.clone());

    // Spawn the HTTP server on a dedicated tokio runtime thread so
    // the consensus loop can run on the main thread. Non-critical:
    // a dead RPC leaves consensus running; health probes see a
    // refused connection.
    let rpc_clone = rpc.clone();
    let _ = primitives::supervision::spawn_supervised("rpc-http", false, move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rpc runtime");
        rt.block_on(async move {
            http_server.serve().await;
        });
    });

    println!("oxide-devnet[{node_index}]: RPC server on http://{listen}");
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
///
/// Routing convention: transport peer IDs are staking *addresses*,
/// not committee indexes. Sends resolve the live committee's
/// `validator_addresses()` — which follows rotations as soon as the
/// engine swaps the set — and inbound attribution resolves
/// `msg.from` (the handshake-authenticated address) back to a
/// committee index via `index_of`. An index baked into the peer id
/// would point at a different member the moment a removal reshuffled
/// the committee; the address cannot.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_consensus_loop(
    engine: &mut consensus::OxideBft,
    transport: &mut p2p::tcp::TcpTransport,
    node_index: usize,
    our_addr: primitives::Address,
    shutdown: &AtomicBool,
    rpc: Option<&rpc::RpcServer>,
    shared_validator_set: &std::sync::RwLock<consensus::ValidatorSet>,
    shared_next_validator_set: &std::sync::RwLock<Option<consensus::ValidatorSet>>,
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
    // Admitted-proposal dedupe: `(view, proposer)` pairs that
    // already occupy a pending slot. The key is claimed only by a
    // *verified* proposal (the intake runs `admit_proposal` before
    // inserting), so one entry per view is the honest maximum — an
    // equivocating leader's second signed body for the same view,
    // or a re-delivered identical header, is dropped here without
    // re-running any verification.
    let mut seen_proposals: std::collections::HashSet<(u64, primitives::Hash)> =
        std::collections::HashSet::new();
    // Per-sender budget on proposal *authentication attempts*:
    // `(last window start, frames admitted this second)` per
    // authenticated peer id. Every distinct admissible frame costs
    // one BLS verify inside `admit_proposal`; without a per-peer
    // bound a flooding member would hold the consensus thread in
    // verification while the real leader's proposal queues behind
    // the junk in the transport's merged recv queue. The key is the
    // handshake-proven peer id — a peer cannot spend another's
    // budget. Committee-sized map: only `allowed_peer_ids` can hold
    // a connection at all.
    let mut proposal_verify_budget: std::collections::HashMap<Vec<u8>, (std::time::Instant, u32)> =
        std::collections::HashMap::new();
    let mut voted_views: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut proposed_views: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut last_reported_height: u64 = 0;
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
            println!("oxide-devnet[{node_index}]: shutdown signal received, stopping");
            break;
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
            } else {
                // Idle mode is an explicit heartbeat, not silence:
                // `propose()` returns None when no work is pending, but
                // a silent leader is indistinguishable from a dead one —
                // followers' view timers would fire and views would
                // churn through timeout certificates without committing
                // anything. If this view has been idle past
                // `IDLE_HEARTBEAT`, propose anyway: the QC advances the
                // chain on the healthy path and commits the uncommitted
                // tail. (Replaces the keep-alive transaction, which
                // needed a funded test identity to fake real work.)
                let produced = engine.propose().or_else(|| {
                    if view_start.elapsed() >= IDLE_HEARTBEAT {
                        engine.propose_heartbeat()
                    } else {
                        None
                    }
                });
                if let Some((header, proposal)) = produced {
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
                    // Broadcast proposal to followers — every live
                    // committee member except us, addressed by the
                    // staking address that IS its peer id.
                    let mut buf = Vec::with_capacity(1 + 512);
                    buf.push(MSG_PROPOSAL);
                    header.encode(&mut buf);
                    proposal.encode(&mut buf);
                    for addr in engine.validator_set().validator_addresses() {
                        if *addr != our_addr {
                            let _ = transport.send(&addr.0.to_vec(), &buf);
                        }
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
                // The leader's peer id is its staking address —
                // `leader` is a committee index into the live set.
                if let Some(leader_addr) = engine.validator_set().validator_addresses().get(leader)
                {
                    let _ = transport.send(&leader_addr.0.to_vec(), &buf);
                }
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
                        // Intake gate, cheapest check first: a junk
                        // proposal must be dropped before it ever
                        // costs this single-threaded loop a BLS
                        // verify. `proposal_admissible` applies the
                        // view window (stale/premature churn) and the
                        // scheduled-leader compare — both pure, no
                        // crypto. Without this gate a Byzantine peer
                        // could push unbounded pending entries and
                        // have `vote()` re-verify all of them on
                        // every iteration.
                        let proposal_view = header.view.value();
                        if !engine.proposal_admissible(&header) {
                            continue;
                        }
                        // Per-sender verify budget before the one
                        // expensive step: a distinct admissible
                        // frame costs one BLS verify in
                        // `admit_proposal`. Charged per frame rather
                        // than per fresh verify — memo-hit
                        // redeliveries are cheap enough that the
                        // accounting stays simple and honest bursts
                        // (≤1 proposal per view per leader) sit far
                        // below the cap.
                        let budget = proposal_verify_budget
                            .entry(msg.from.clone())
                            .or_insert((std::time::Instant::now(), 0));
                        if budget.0.elapsed() >= std::time::Duration::from_secs(1) {
                            *budget = (std::time::Instant::now(), 0);
                        }
                        if budget.1 >= consensus::PROPOSAL_VERIFY_BUDGET_PER_SEC {
                            continue;
                        }
                        budget.1 += 1;
                        // Authenticate BEFORE the dedupe slot is
                        // claimed: `header.proposer` is a public
                        // claim, so junk can pass the leader compare
                        // while carrying a forged signature. If an
                        // unverified frame took the (view, proposer)
                        // key, junk that races ahead of the real
                        // leader would park it and the genuine
                        // proposal would be dropped as a "duplicate"
                        // — the flood becomes censorship. Only a
                        // verified proposal may occupy the slot;
                        // `admit_proposal` memoises both verdicts so
                        // re-deliveries are free.
                        if engine.admit_proposal(&header, &proposal)
                            && seen_proposals.insert((proposal_view, header.proposer))
                        {
                            pending_proposals.push((header, proposal));
                        }
                    }
                }
                MSG_VOTE => {
                    if let Ok(vote) = types::Vote::decode(&mut reader) {
                        // Attribute by the AUTHENTICATED peer id: the
                        // handshake proved the sender owns the staking
                        // address it claims, so `index_of` resolves the
                        // committee seat the signature must verify
                        // under. A removed member's address resolves to
                        // nothing — its vote dies here rather than
                        // collecting under whatever index it used to
                        // hold.
                        let voter = msg
                            .from
                            .as_slice()
                            .try_into()
                            .map(primitives::Address)
                            .ok()
                            .and_then(|a| engine.validator_set().index_of(&a));
                        if let Some(voter_idx) = voter {
                            let _ = engine.collect_vote(voter_idx, vote);
                        }
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
                    // Format: [voter_addr: 20B][view: 8B][epoch: 8B]
                    //         [has_qc: 1B][qc?][has_tc: 1B][tc?]
                    //         [signature: 96B]
                    // The certificate fields are the DiemBFT v4
                    // timeout evidence: entering view v is
                    // legitimate only via QC(v−1) or TC(v−1).
                    if let Ok(voter_bytes) = reader.read_slice(20)
                        && let Ok(sig_view) = reader.read_u64()
                        && let Ok(sig_epoch) = reader.read_u64()
                        && let Ok(has_qc) = reader.read_u8()
                    {
                        // The claimed voter must BE the authenticated
                        // sender — otherwise a member could attribute
                        // its timeout signature to any other seat.
                        let Ok(voter_arr): Result<[u8; 20], _> = voter_bytes.try_into() else {
                            continue;
                        };
                        if voter_arr.as_slice() != msg.from.as_slice() {
                            continue;
                        }
                        // Resolve the sender's address to its seat in
                        // the live committee; a non-member (or a
                        // removed member post-activation) collects
                        // nothing.
                        let voter_idx =
                            engine.validator_set().index_of(&primitives::Address(voter_arr));
                        let Some(voter_idx) = voter_idx else { continue };
                        // The wire interleaves each flag with its
                        // payload — has_qc then the QC bytes, then
                        // has_tc then the TC bytes. Reading both
                        // flags up front would consume the QC's
                        // first byte as `has_tc` and misalign every
                        // field after it, so the qc_ev the signature
                        // is verified against would never match what
                        // the sender signed.
                        let qc_ev = if has_qc == 1 {
                            types::QuorumCertificate::decode(&mut reader).ok()
                        } else {
                            None
                        };
                        let Ok(has_tc) = reader.read_u8() else { continue };
                        let tc_ev = if has_tc == 1 {
                            types::TimeoutCertificate::decode(&mut reader).ok()
                        } else {
                            None
                        };
                        if let Ok(sig) = crypto::Signature::decode(&mut reader) {
                            // Authenticate the evidence BEFORE acting
                            // on it. Everything below mutates
                            // consensus state — the pacemaker timer,
                            // the vote buffer, high_qc — so a peer
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
                                    qc_ev.as_ref(),
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
                            // Bounded catch-up: feed the attached
                            // certificate evidence through the
                            // verified ingestion paths first — a
                            // timeout signature alone cannot move
                            // our view; only real QC/TC evidence
                            // can. After this, a collectible sig
                            // must claim exactly our current view.
                            let view_before = engine.current_view().value();
                            engine.deliver_timeout_evidence(qc_ev.clone(), tc_ev);
                            // If the sig is for a past view, ignore it
                            // (stale — the sender is behind us); if it
                            // is for a view the evidence didn't reach,
                            // ignore it — an unjustified jump (the
                            // old code synced to the claimed view
                            // unconditionally, letting one peer pull
                            // the node to an arbitrary view).
                            if sig_view != engine.current_view().value() {
                                continue;
                            }
                            // Reset the view timer only when the
                            // evidence actually moved us — resetting
                            // on every same-view sig would let a peer
                            // starve our own timeout.
                            if engine.current_view().value() != view_before {
                                view_start = std::time::Instant::now();
                                timeout_sent_for_view = None;
                            }
                            match engine.collect_timeout_signature(voter_idx, sig, qc_ev) {
                                Ok(Some(tc)) => {
                                    // TC formed — broadcast to all peers.
                                    eprintln!(
                                        "oxide-devnet[{node_index}]: TC formed after collecting timeout sig from voter={voter_idx} view={}",
                                        engine.current_view().value()
                                    );
                                    let mut tc_buf = Vec::with_capacity(1 + 200);
                                    tc_buf.push(MSG_TC);
                                    tc.encode(&mut tc_buf);
                                    for addr in engine.validator_set().validator_addresses() {
                                        if *addr != our_addr {
                                            let _ = transport.send(&addr.0.to_vec(), &tc_buf);
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
                                        "oxide-devnet[{node_index}]: timeout sig from voter={voter_idx} rejected: {e:?}"
                                    );
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
                                eprintln!("oxide-devnet[{node_index}]: TC rejected: {e:?}");
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
            for addr in engine.validator_set().validator_addresses() {
                if *addr != our_addr {
                    let _ = transport.send(&addr.0.to_vec(), &buf);
                }
            }
        }

        // Phase 4: form QC (if quorum reached).
        if let Some(qc) = engine.try_form_qc() {
            let mut qc_buf = Vec::with_capacity(1 + 150);
            qc_buf.push(MSG_QC);
            qc.encode(&mut qc_buf);
            for addr in engine.validator_set().validator_addresses() {
                if *addr != our_addr {
                    let _ = transport.send(&addr.0.to_vec(), &qc_buf);
                }
            }
            let _ = engine.deliver_qc(qc);
        }

        // Phase 5: advance views.
        let prev_view = engine.current_view().value();
        if let Some(hqc) = engine.high_qc()
            && hqc.view == engine.current_view()
        {
            engine.advance_view();
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
                    "oxide-devnet[{node_index}]: view timeout view={current_view_now} elapsed={elapsed_ms}ms — broadcasting timeout sig"
                );
                // The certificate evidence that justifies our
                // presence at this view (DiemBFT v4 timeout fields):
                // receivers only honor a view claim backed by
                // QC(view−1) or TC(view−1) — a bare signature can no
                // longer pull a peer to an arbitrary view.
                let (high_qc_ev, last_tc_ev) = engine.timeout_evidence();
                let mut buf = Vec::with_capacity(1 + 20 + 8 + 8 + 2 + 96);
                buf.push(MSG_TIMEOUT);
                // Encode: voter_address (20B) + view (8B) + epoch (8B)
                // + [has_qc 1B][qc?] + [has_tc 1B][tc?] + sig (96B).
                // The voter field is our staking address — the same
                // bytes the transport proves ownership of at
                // handshake, so the receiver can cross-check the
                // claimed voter against the authenticated peer id
                // and resolve the committee seat that must have
                // signed. (An index here would misattribute the
                // signature the moment a removal reshuffled seats.)
                // The view and epoch are included so the receiver can
                // verify the signature against the correct view and
                // ignore stale sigs from a different view (e.g., after
                // a partition when validators may be at different views).
                buf.extend_from_slice(&our_addr.0);
                buf.extend_from_slice(&current_view_now.to_le_bytes());
                buf.extend_from_slice(&engine.epoch().value().to_le_bytes());
                // Evidence flags + optional certificates.
                match &high_qc_ev {
                    Some(qc) => {
                        buf.push(1u8);
                        qc.encode(&mut buf);
                    }
                    None => buf.push(0u8),
                }
                match &last_tc_ev {
                    Some(tc) => {
                        buf.push(1u8);
                        tc.encode(&mut buf);
                    }
                    None => buf.push(0u8),
                }
                sig.encode(&mut buf);
                for addr in engine.validator_set().validator_addresses() {
                    if *addr != our_addr {
                        let _ = transport.send(&addr.0.to_vec(), &buf);
                    }
                }
                // Self-collect: feed our own timeout signature to the
                // engine so it counts toward the quorum.
                if let Ok(Some(tc)) = engine.collect_timeout_signature(
                    engine.validator_index(),
                    sig,
                    high_qc_ev.clone(),
                ) {
                    // TC formed immediately (unlikely with 1/4, but
                    // handle it). Broadcast the TC to all peers.
                    eprintln!(
                        "oxide-devnet[{node_index}]: TC formed locally after self-timeout view={current_view_now}"
                    );
                    let mut tc_buf = Vec::with_capacity(1 + 200);
                    tc_buf.push(MSG_TC);
                    tc.encode(&mut tc_buf);
                    for addr in engine.validator_set().validator_addresses() {
                        if *addr != our_addr {
                            let _ = transport.send(&addr.0.to_vec(), &tc_buf);
                        }
                    }
                    view_start = std::time::Instant::now();
                    timeout_sent_for_view = None;
                }
            }
        }

        // Height sync is handled inside `vote()` — `authenticate_
        // proposal` calls `observe_block_height` once the header's
        // leader and signature check out. The previous self-sync
        // (sync_next_height(next_height_value)) was a no-op — it
        // synced the engine to its own value.

        // Report finalized height changes.
        let height = engine.finalized_height();
        if let Some(h) = height {
            let h_val = h.value();
            if h_val > last_reported_height {
                println!("oxide-devnet[{node_index}]: finalized height = {h_val}");
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

        // A confirmed execution divergence is terminal for this
        // process: the engine has already logged CRITICAL and
        // stopped signing; mirror the latch into RPC status so
        // `/health` flips to 503 and `/metrics` exposes the gauge —
        // otherwise the only signal is a stderr line a watchdog
        // never sees. Idempotent: the detail is write-once.
        if let (Some(rpc), Some(d)) = (rpc, engine.divergence()) {
            rpc.set_exec_divergence(*d);
        }

        // Mirror the engine's execution certificates into RPC so
        // `GET /snapshot/cert/{height}` can answer a syncing node's
        // certificate poll. Pushed every iteration (the mirror
        // dedups by height); a syncing client verifies the cert
        // against its own validator-set checkpoint, so serving the
        // bytes costs this node no trust assumption.
        if let Some(rpc) = rpc {
            rpc.record_exec_certificates(engine.exec_certificates());
        }

        // Compact proposal bookkeeping (keep last
        // PROPOSAL_PAST_VIEWS views — the same bound the intake
        // gate applies, so a set entry and its pending slot age
        // out together).
        let current_view = engine.current_view().value();
        let keep_from = current_view.saturating_sub(consensus::PROPOSAL_PAST_VIEWS);
        pending_proposals.retain(|(h, _)| h.view.value() >= keep_from);
        voted_views.retain(|v| *v >= keep_from);
        proposed_views.retain(|v| *v >= keep_from);
        seen_proposals.retain(|(v, _)| *v >= keep_from);

        // Epoch lifecycle: drain the validator-set transition the
        // executor's finalized blocks recorded (staking key changes,
        // validator adds/removes) and schedule the epoch rotation.
        // The drain is deterministic — the queues only fill when a
        // block *executes*, so every node stages the same committee
        // at the same committed height — and activation is deferred
        // to a certified boundary (`ROTATION_ACTIVATION_DELAY`
        // commits later), never immediate on a local queue.
        match engine.drive_epoch_changes() {
            Ok(0) => {}
            Ok(applied) => {
                eprintln!(
                    "oxide-devnet[{node_index}]: epoch rotation scheduled ({applied} \
                     validator-set change(s)) — activates at committed height {:?}",
                    engine.rotation_activation_height()
                );
            }
            Err(e) => {
                // Deterministic rejection — every replica folds the
                // same deltas through `build_next_set` and reaches
                // the same verdict, so this is consistent cluster
                // state, not a fork: the transition is dropped and
                // must be re-submitted.
                eprintln!(
                    "oxide-devnet[{node_index}]: epoch transition rejected: {e} — \
                     pending change dropped (re-submit a valid set)"
                );
            }
        }

        // Epoch boundary: `commit_block` (from `deliver_qc` in the
        // drain loop or Phase 4) and `drive_epoch_changes` (the
        // activation-height completion above) may both swap the
        // validator set — as can `adopt_certified_epoch` inside
        // `deliver_qc` when a verified higher-epoch QC lands. Publish
        // the live committee whenever the epoch moved so the
        // authenticator and `GET /validator-set` track it.
        if engine.epoch().value() != last_epoch {
            last_epoch = engine.epoch().value();
            if let Ok(mut shared) = shared_validator_set.write() {
                *shared = engine.validator_set().clone();
            }
            // The pump's view-keyed bookkeeping must die with the
            // epoch: the new epoch's view space restarts at 0, so a
            // retained `voted_views`/`proposed_views` entry for view 0
            // would suppress this node's first vote/proposal of the
            // epoch, and pending proposals signed under the old epoch
            // can never become votable. Mirrors the engine's own
            // `clear_epoch_scoped_state`.
            pending_proposals.clear();
            seen_proposals.clear();
            voted_views.clear();
            proposed_views.clear();
            view_start = std::time::Instant::now();
            timeout_sent_for_view = None;
        }

        // Publish the staged committee to the transport's handshake
        // authenticator for the whole schedule→activation window:
        // an incoming member's first connection must already pass
        // membership verification before its committee duties start.
        // `next_validator_set` returns `None` outside the window (and
        // clears itself at activation), so this is `None` most of the
        // time — the `!=` guard avoids paying a committee clone on
        // every pass.
        if let Ok(mut pending) = shared_next_validator_set.write() {
            let staged = engine.next_validator_set().cloned();
            if *pending != staged {
                *pending = staged;
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

/// Map the `[network]` config onto the transport's tunables.
///
/// `listen_addr`/`peers` are NOT taken from the file — they are
/// derived per-index (`--node`, `--base-port`) so one TOML file
/// serves the whole cluster. The
/// timeouts and frame bound DO apply to both TLS and plain TCP.
fn to_transport_config(network: &config::NetworkConfig) -> p2p::tcp::TcpTransportConfig {
    p2p::tcp::TcpTransportConfig {
        connect_timeout: network.connect_timeout(),
        read_timeout: network.read_timeout(),
        max_message_bytes: network.max_message_bytes,
        ..Default::default()
    }
}
