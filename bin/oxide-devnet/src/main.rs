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
use std::sync::atomic::Ordering;

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
    // replacement on rotation. Our own peer id is resolved inside
    // `validator_net::run` from `validator_set` + `seat`, never
    // derived.

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

    // mTLS material — devnet cert convention: `peer-<i>.pem` for
    // committee members, `peer-<addr hex>.pem` for explicit `--peer`
    // endpoints. A peer without a cert file gets no trusted-peers
    // entry and so can never complete mTLS.
    let tls = node::cli::parse_cli_flag("--tls-dir").map(|tls_dir| {
        let trusted_peer_certs = peer_cert_names
            .iter()
            .map(|(id, name)| (id.clone(), PathBuf::from(format!("{tls_dir}/{name}"))))
            .collect();
        node::validator_net::TlsSpec {
            cert_path: PathBuf::from(format!("{tls_dir}/cert.pem")),
            key_path: PathBuf::from(format!("{tls_dir}/key.pem")),
            trusted_peer_certs,
        }
    });

    println!(
        "oxide-devnet[{node_index}]: listening on {listen_addr}, {} peers, seat {our_seat} of {}",
        peers.len(),
        validator_set.n()
    );

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

    // Smoke-test transaction, devnet genesis only: a staking
    // delegate signed by devnet identity 0 to itself. Under a real
    // `--genesis-file` the node must not emit transactions signed
    // by a public test identity — the account is not funded there
    // anyway, so the tx would be skipped work.
    let smoke_tx = if cfg.genesis_file.is_none() {
        let module_payload = staking::msg::delegate(
            crypto::secp::test_identity_address(0).expect("valid devnet identity"),
            100,
        );
        Some(node::cli::build_signed_tx(
            cfg.node.chain_id,
            framework::module_id::STAKING,
            &module_payload,
            0,
        ))
    } else {
        None
    };

    // `--wal-file` overrides the derived `<data_dir>/consensus.wal`
    // path; when neither is set the WAL stays in-memory.
    let wal_path = node::cli::parse_cli_flag("--wal-file").map(PathBuf::from);
    // `--rpc-listen` overrides the configured RPC bind.
    let rpc_listen = node::cli::parse_cli_flag("--rpc-listen").or_else(|| {
        if rpc_config.listen_addr.is_empty() { None } else { Some(rpc_config.listen_addr.clone()) }
    });

    // Genesis `evm.alloc` application — the closure keeps the
    // hex→U256 parsing (and the alloy dep) in this binary; the
    // shared runner invokes it only on a fresh start.
    let genesis_alloc = cfg.genesis_file.clone().map(|g| {
        Box::new(move |m: &evm::EvmModule| apply_evm_alloc(m, &g))
            as Box<dyn FnOnce(&evm::EvmModule) + Send>
    });

    node::validator_net::run(node::validator_net::ValidatorNetSpec {
        log_tag: format!("oxide-devnet[{node_index}]"),
        seat: usize::from(our_seat),
        validator_set,
        signer: std::sync::Arc::new(our_key),
        node_config: cfg.node.clone(),
        wal_path,
        listen_addr,
        peers,
        tls,
        network: cfg.network.clone(),
        genesis_alloc,
        data_dir: cfg.data_dir.clone(),
        rpc_listen,
        rpc_config: rpc_config.clone(),
        smoke_tx,
        shutdown,
        // Devnet members have no repair peers: divergence there is a
        // test failure to debug, not a fault to paper over — the
        // halt must stay loud.
        repair_peers: Vec::new(),
    });
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
        node::cli::validator_set_from_genesis(&genesis)
            .unwrap_or_else(|e| panic!("{e} — required for multi-node"))
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
