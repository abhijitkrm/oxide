//! Operator-surface glue shared by the node binaries: the
//! TOML+env+CLI → [`crate::NodeConfig`] loader, the effective-config
//! validation/refusal gates, genesis `evm.alloc` application, and the
//! small CLI/hex/devnet-signing helpers both binaries use.
//!
//! One loader, one gate — a devnet launcher and the production
//! validator resolve and check configuration through the identical
//! path, so a setting's meaning can never differ between them.

use std::env;
use std::path::PathBuf;

use crate::NodeConfig;

/// The fully-resolved runtime configuration: parsed TOML + env +
/// CLI, mapped into the types each subsystem consumes and checked by
/// `crate::validate_effective_config` before the node builds anything.
pub struct LoadedConfig {
    /// The canonical node/executor config — consumed by
    /// `Node::assemble` (single-node mode) and
    /// `node::assemble_executor` (devnet mode).
    pub node: NodeConfig,
    /// The JSON-RPC server config.
    pub rpc: config::RpcConfig,
    /// The `[network]` section — transport timeouts and the frame
    /// bound for the devnet TCP transport.
    pub network: config::NetworkConfig,
    /// The `[genesis]` section — devnet validator/sender fallbacks
    /// used when no `--genesis-file` is given.
    pub genesis_cfg: config::GenesisConfig,
    /// The parsed `--genesis-file`, when given. Its validators and
    /// native balances are already folded into `node.genesis`; the
    /// raw file is kept for `evm.alloc` and for
    /// `load_validator_set`'s BLS-key extraction, which need richer
    /// shapes than `GenesisSpec` carries.
    pub genesis_file: Option<config::genesis::Genesis>,
    /// The resolved data directory (`--data-dir` or
    /// `[storage] data_dir`): auto-snapshot persistence root and the
    /// parent of the EVM state database.
    pub data_dir: Option<PathBuf>,
}

/// Whether `host` resolves to a loopback-only bind. Anything that is
/// not a literal loopback IP or `localhost` is treated as external:
/// a hostname could resolve anywhere, and `0.0.0.0`/`::` are wildcard
/// binds — both count as external-facing for the unsafe-mode gate.
pub fn is_loopback_host(host: &str) -> bool {
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
pub fn external_bind_surfaces(bind_host: Option<&str>, rpc_listen: Option<&str>) -> Vec<String> {
    let mut external = Vec::new();
    if let Some(host) = bind_host
        && !is_loopback_host(host)
    {
        external.push(format!("devnet transport --bind-host {host}"));
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

/// Resolve every listener surface reachable from other machines —
/// the consensus transport (`--bind-host` in Devnet mode,
/// `network.listen_addr` in Validator mode; Single runs none) and
/// the JSON-RPC listener (`--rpc-listen` / `rpc.listen_addr`),
/// resolved the same way the listeners themselves are.
pub fn external_surfaces(
    mode: crate::NodeMode,
    rpc_config: &config::RpcConfig,
    network: &config::NetworkConfig,
) -> Vec<String> {
    let bind_host = match mode {
        crate::NodeMode::Devnet => {
            Some(parse_cli_flag("--bind-host").unwrap_or_else(|| "127.0.0.1".to_string()))
        }
        // In validator mode the transport binds `network.listen_addr`
        // verbatim — its host part is the reachable surface.
        crate::NodeMode::Validator => network
            .listen_addr
            .rsplit_once(':')
            .map(|(h, _)| h.trim_start_matches('[').trim_end_matches(']').to_string()),
        crate::NodeMode::Single => None,
    };
    // `--rpc-listen` is already folded into `rpc_config.listen_addr`
    // by the loader — an empty address means the RPC server is off.
    let rpc_listen = if rpc_config.listen_addr.is_empty() {
        None
    } else {
        Some(rpc_config.listen_addr.as_str())
    };
    external_bind_surfaces(bind_host.as_deref(), rpc_listen)
}

/// Refuse to start with unsigned-tx admission on any listener that
/// is reachable from other machines.
///
/// Unsigned envelopes trust the declared `sender` — acceptable on a
/// loopback devnet where every submitter is the operator, fatal on a
/// network-facing bind where it lets anyone spend any account.
pub fn refuse_unsigned_on_external_binds(node_config: &NodeConfig, external: &[String], bin: &str) {
    if node_config.require_signed_txs || external.is_empty() {
        return;
    }
    eprintln!(
        "{bin}: refusing to start — --unsafe-allow-unsigned-txs admits \
         unauthenticated senders, but these binds are externally reachable:"
    );
    for surface in external {
        eprintln!("  - {surface}");
    }
    eprintln!("run unsigned mode on loopback only, or drop the flag and sign envelopes");
    std::process::exit(1);
}

/// Chain IDs claimed by public Ethereum-compatible networks. EIP-155
/// binds the chain ID into every signature, so an Oxide deployment
/// reusing one of these is replayable in both directions wherever
/// nonces align — transactions signed here execute on the public
/// network and vice versa.
pub const PUBLIC_CHAIN_IDS: &[u64] = &[
    1,          // Ethereum mainnet
    5,          // Goerli
    17000,      // Holesky
    11_155_111, // Sepolia
    10,         // OP Mainnet
    56,         // BNB Chain
    137,        // Polygon
    8453,       // Base
    42161,      // Arbitrum One
    43114,      // Avalanche C-Chain
];

/// Facts a node binary reports about its resolved startup so the
/// shared gate can decide whether exposing the node on a public
/// listener is safe. The loader cannot see how each binary sources
/// its key material — the caller resolves the flags it understands
/// and reports the outcomes here. Single-node mode has no peer
/// transport and signs no consensus messages, so it leaves the two
/// transport/key fields `false`.
#[derive(Debug, Default)]
pub struct ExternalPosture {
    /// Consensus identity is the deterministic devnet derivation —
    /// no operator-supplied key material (`--bls-key-file` absent).
    pub deterministic_consensus_key: bool,
    /// Peer transport would run without TLS (`--tls-dir` absent).
    pub transport_unencrypted: bool,
    /// No `--genesis-file` — the validator set and funded accounts
    /// are the built-in devnet defaults, publicly derivable.
    pub genesis_file_absent: bool,
    /// Effective EIP-155 chain ID (`NodeConfig::chain_id`).
    pub chain_id: u64,
    /// Effective native-module minimum fee (`NodeConfig::min_fee`).
    pub min_fee: u64,
}

/// Collect every reason this posture is unsafe to expose on a
/// listener reachable from other machines. Empty means safe.
pub fn insecure_posture_reasons(posture: &ExternalPosture) -> Vec<String> {
    let mut reasons = Vec::new();
    if posture.deterministic_consensus_key {
        reasons.push(
            "consensus key is the deterministic devnet derivation (--bls-key-file not given) \
             — the secret is publicly computable"
                .to_string(),
        );
    }
    if posture.transport_unencrypted {
        reasons.push("peer transport is unencrypted (--tls-dir not given)".to_string());
    }
    if posture.genesis_file_absent {
        reasons.push(
            "no --genesis-file — validator set and funded accounts are the public devnet \
             defaults"
                .to_string(),
        );
    }
    if PUBLIC_CHAIN_IDS.contains(&posture.chain_id) {
        reasons.push(format!(
            "chain_id {} is a public Ethereum-network ID — EIP-155 signatures replay \
             across the chains",
            posture.chain_id
        ));
    }
    if posture.min_fee == 0 {
        reasons.push(
            "min_fee is 0 — native-module transactions are unmetered (free spam)".to_string(),
        );
    }
    reasons
}

/// Refuse to start when the node would expose insecure defaults on a
/// listener reachable from other machines. Every violation is
/// listed — a deployment fixing one at a time should not need five
/// restarts to discover the rest. Loopback-only binds skip the gate
/// entirely: a local devnet is exactly what the defaults are for.
/// `--unsafe-allow-insecure-posture` is the explicit operator
/// opt-out for private testnets (for example a container bridge
/// network whose `0.0.0.0` bind is not actually public).
pub fn refuse_insecure_posture_on_external_binds(
    external: &[String],
    posture: &ExternalPosture,
    bin: &str,
) {
    if external.is_empty() {
        return;
    }
    let reasons = insecure_posture_reasons(posture);
    if reasons.is_empty() {
        return;
    }
    if env::args().any(|a| a == "--unsafe-allow-insecure-posture") {
        eprintln!(
            "{bin}: --unsafe-allow-insecure-posture: starting with {} insecure default(s) on \
             externally reachable binds",
            reasons.len()
        );
        return;
    }
    eprintln!("{bin}: refusing to start — insecure defaults on externally reachable binds:");
    for surface in external {
        eprintln!("  - {surface}");
    }
    for reason in &reasons {
        eprintln!("  - {reason}");
    }
    eprintln!(
        "fix the configuration, bind to loopback, or pass --unsafe-allow-insecure-posture \
         for a private testnet"
    );
    std::process::exit(1);
}

/// Load the node configuration from CLI flags, env vars, and TOML file.
///
/// Priority: CLI > env vars > TOML > defaults. Validates the
/// effective config (unsupported settings fail, overridden settings
/// warn) and prints it before returning, so the running node's
/// parameters are never ambiguous.
///
/// # Panics
///
/// Panics on a malformed `--genesis-file` or a genesis whose
/// contents fail conversion — a node must never boot on partially
/// applied genesis state.
pub fn load_config(mode: crate::NodeMode, bin: &str) -> LoadedConfig {
    let mut config = config::Config::default();

    // 1. Load from TOML file if --config is given.
    let config_path = parse_cli_flag("--config");
    if let Some(path) = config_path.clone() {
        let path = PathBuf::from(path);
        match config::Config::from_toml_file(&path) {
            Ok(loaded) => config = loaded,
            Err(e) => {
                eprintln!("{bin}: failed to load config from {}: {e}", path.display());
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

    let mut rpc_config = config.rpc.clone().unwrap_or_default();
    // `--rpc-listen` overrides the configured RPC bind. Folding it
    // here — rather than at each server's bind site — keeps the
    // effective value identical everywhere it is read, including the
    // external-bind gates below.
    if let Some(listen) = parse_cli_flag("--rpc-listen") {
        rpc_config.listen_addr = listen;
    }

    // Genesis chain id must match the RPC chain id — a mismatch means
    // the node's signatures and its advertised chain disagree.
    if let Some(g) = &genesis_file
        && g.chain_id != rpc_config.chain_id
    {
        eprintln!(
            "oxide-validator: genesis chain_id {} != rpc.chain_id {} — \
                 refusing to run a node whose signatures advertise a different chain",
            g.chain_id, rpc_config.chain_id
        );
        std::process::exit(1);
    }

    // The genesis spec: `--genesis-file` when given, else the
    // deterministic devnet fallback. A malformed genesis file fails
    // at startup with the offending entry named.
    let genesis = Some(match &genesis_file {
        Some(g) => {
            crate::genesis_spec_from_file(g).unwrap_or_else(|e| panic!("invalid genesis file: {e}"))
        }
        None => crate::genesis_spec_devnet(&config.genesis),
    });
    let overrides = crate::AssemblyOverrides {
        // `--unsafe-allow-unsigned-txs` (CLI) OR `[executor]
        // allow_unsigned_txs` — the OR lives in `node_config_from`.
        // Signed envelopes are the default; this flag exists only
        // for loopback devnets and is refused on external binds.
        allow_unsigned_txs: env::args().any(|a| a == "--unsafe-allow-unsigned-txs"),
        data_dir: data_dir.clone(),
        // `--wal-file` overrides the derived `<data_dir>/consensus.wal`
        // location — the consensus WAL is what lets a restart resume
        // the chain at its committed tip instead of re-proposing
        // heights the executor already recovered.
        wal_path: parse_cli_flag("--wal-file").map(PathBuf::from),
        genesis,
    };
    let node_config = crate::node_config_from(&config, &rpc_config, &overrides, mode)
        .unwrap_or_else(|e| panic!("invalid configuration: {e}"));

    // Validate BEFORE building anything: unsupported settings fail,
    // overridden ones warn — never silently do nothing.
    let (warnings, errors) = crate::validate_effective_config(&config, &node_config, mode);
    for w in &warnings {
        eprintln!("{bin}: config warning: {w}");
    }
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("{bin}: config error: {e}");
        }
        std::process::exit(1);
    }
    // Off-loopback, the defaults themselves are the attack surface.
    // Resolve the reachable surfaces once — both refusal gates read
    // the same list so they can never disagree about what is public.
    let external = external_surfaces(mode, &rpc_config, &config.network);
    refuse_unsigned_on_external_binds(&node_config, &external, bin);
    let posture = ExternalPosture {
        deterministic_consensus_key: matches!(
            mode,
            crate::NodeMode::Devnet | crate::NodeMode::Validator
        ) && parse_cli_flag("--bls-key-file").is_none()
            // A remote signer is not a deterministic key — the
            // secret lives in the fenced daemon, outside this
            // process entirely.
            && parse_cli_flag("--signer-addr").is_none(),
        transport_unencrypted: matches!(mode, crate::NodeMode::Devnet | crate::NodeMode::Validator)
            && parse_cli_flag("--tls-dir").is_none(),
        genesis_file_absent: genesis_file.is_none(),
        chain_id: node_config.chain_id,
        min_fee: node_config.min_fee,
    };
    refuse_insecure_posture_on_external_binds(&external, &posture, bin);

    // Emit the effective configuration — the values actually running,
    // after every override layer, not the file's literal contents.
    println!("{bin}: effective node config: {node_config:?}");

    LoadedConfig {
        node: node_config,
        rpc: rpc_config,
        network: config.network,
        genesis_cfg: config.genesis,
        genesis_file,
        data_dir,
    }
}

/// Install the standard shutdown-signal handler on `flag`: the
/// first SIGINT/SIGTERM sets it so the consumer can unwind
/// gracefully — WAL close, snapshot export — and a *second* signal
/// exits immediately.
///
/// The second-signal rule is what keeps the handler honest: with it
/// missing, the installed tokio disposition swallows every repeat —
/// a loaded node's graceful path (a state export over a multi-GB
/// redb) can take tens of seconds, during which the operator's
/// repeated SIGTERM does nothing and the process looks hung.
/// Snapshot writes are atomic, so exiting mid-export leaves the old
/// or the new file, never a torn one.
///
/// The handler is best-effort: if the supervised thread fails to
/// spawn, the node keeps running and loses only graceful-shutdown
/// signaling — visible via the registry — which beats refusing to
/// boot on a signal-emaciated platform.
///
/// # Panics
///
/// Panics on the handler thread if the tokio runtime or the signal
/// streams themselves fail to initialize — a broken OS signal
/// disposition is not something a node can compensate for, so the
/// supervised-thread registry records it loudly rather than letting
/// the operator believe graceful shutdown is armed.
pub fn install_shutdown_handler(flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
    let _ = primitives::supervision::spawn_supervised("signal-handler", false, move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("signal runtime");
        rt.block_on(async move {
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("sigterm handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = sigterm.recv() => {},
                }
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
                // The handler owns the process's signal disposition
                // now — nothing reaches the default action — so a
                // repeat has to be intercepted and acted on here.
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = sigterm.recv() => {},
                }
                eprintln!("second shutdown signal — exiting immediately");
                std::process::exit(1);
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.expect("ctrl_c handler");
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
                tokio::signal::ctrl_c().await.expect("ctrl_c handler");
                eprintln!("second shutdown signal — exiting immediately");
                std::process::exit(1);
            }
        });
    });
}

/// Parse a `--flag value` pair from CLI args.
///
/// Returns the value if the flag is found, `None` otherwise.
pub fn parse_cli_flag(flag: &str) -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == flag {
            return args.next();
        }
    }
    None
}

/// Parse every `--flag value` pair from CLI args — for repeatable
/// flags like `--peer`. Values are returned in argument order.
pub fn parse_cli_flags(flag: &str) -> Vec<String> {
    let mut args = env::args().skip(1);
    let mut values = Vec::new();
    while let Some(arg) = args.next() {
        if arg == flag
            && let Some(value) = args.next()
        {
            values.push(value);
        }
    }
    values
}

/// Build a signed v1 envelope from devnet identity 0 — the account
/// every devnet convenience flow (smoke tx, keep-alive delegate,
/// key-change) submits as. Signing is mandatory: the executor's
/// default `Reject` policy admits no unsigned native txs.
///
/// # Panics
///
/// Panics only if the built-in devnet identity is malformed or
/// refuses to sign — both impossible for the fixed test key.
///
/// Only exists with the crate's `dev-identities` feature — the
/// signer is publicly derivable, so production builds must not
/// contain this path at all.
#[cfg(feature = "dev-identities")]
pub fn build_signed_tx(
    chain_id: u64,
    module_id: u8,
    module_payload: &[u8],
    nonce: u64,
) -> types::TxBytes {
    let key = crypto::secp::test_identity_key(0);
    let sender = crypto::secp::test_identity_address(0).expect("valid devnet identity");
    build_signed_tx_with(&key, sender, chain_id, module_id, module_payload, nonce)
}

/// Build a signed v1 envelope for an arbitrary key/sender:
/// `[sender][nonce][fee][module_id|0x80][sig:65][payload]`. The
/// signature is the EIP-712 envelope signature wallets produce —
/// `crypto::eip712::sign_tx` — over the declared fields, so the
/// executor's `Reject`-default policy accepts it.
///
/// # Panics
///
/// Panics if `privkey` is not a valid secp256k1 secret key.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_tx_with(
    privkey: &[u8],
    sender: primitives::Address,
    chain_id: u64,
    module_id: u8,
    module_payload: &[u8],
    nonce: u64,
) -> types::TxBytes {
    let fee = 100u64;
    let sig =
        crypto::eip712::sign_tx(privkey, chain_id, &sender, nonce, fee, module_id, module_payload)
            .expect("key must sign");
    let mut bytes = Vec::with_capacity(36 + 1 + 65 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id | 0x80);
    bytes.extend_from_slice(&sig.sig);
    bytes.push(sig.recid.as_u8());
    bytes.extend_from_slice(module_payload);
    types::TxBytes::new(bytes)
}

/// Build a [`consensus::ValidatorSet`] from a genesis file's
/// `staking.validators` table.
///
/// Shared by `oxide-devnet` (`--genesis-file`) and `oxide-validator
/// --validator` — the committee construction must be identical in
/// both or the same genesis file would produce different validator
/// sets on different binaries.
///
/// # Errors
///
/// Returns `Err` naming the offending validator when an address or
/// `public_key` is missing, malformed, or not a valid BLS key.
pub fn validator_set_from_genesis(
    genesis: &config::genesis::Genesis,
) -> Result<consensus::ValidatorSet, String> {
    let validators = &genesis.staking.validators;
    let pks: Vec<crypto::bls::PublicKey> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let hex = v
                .public_key
                .as_ref()
                .ok_or_else(|| format!("genesis validator {i} missing public_key"))?;
            let bytes = hex_decode(hex)
                .map_err(|e| format!("genesis validator {i} invalid public_key hex: {e}"))?;
            crypto::bls::PublicKey::from_slice(&bytes)
                .map_err(|_| format!("genesis validator {i} invalid BLS public key"))
        })
        .collect::<Result<_, String>>()?;
    let stakes: Vec<u64> = validators.iter().map(|v| v.stake).collect();
    let addresses: Vec<primitives::Address> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let bytes = hex_decode(&v.address)
                .map_err(|e| format!("genesis validator {i} invalid address hex: {e}"))?;
            let arr: [u8; 20] = bytes
                .try_into()
                .map_err(|_| format!("genesis validator {i} address must be 20 bytes"))?;
            Ok(primitives::Address(arr))
        })
        .collect::<Result<_, String>>()?;
    consensus::ValidatorSet::with_addresses(pks, stakes, addresses)
        .map_err(|e| format!("invalid genesis validator set: {e}"))
}

/// Encode bytes as a hex string (lowercase, no `0x` prefix).
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
        write!(acc, "{b:02x}").expect("write to String cannot fail");
        acc
    })
}

/// Derive the deterministic BLS secret key for a devnet identity:
/// a single seed byte repeated to the 32-byte IKM. Used by
/// `--genesis-file` to reproduce the default validator keys and by
/// the devnet launcher for `--node <i>` identities — NOT for
/// production keys.
///
/// # Panics
///
/// Panics only if a 32-byte IKM is rejected by the BLS
/// implementation, which cannot happen.
pub fn bls_key(byte: u8) -> crypto::BlsSecretKey {
    let ikm = vec![byte; 32];
    crypto::BlsSecretKey::from_ikm(&ikm).expect("BLS key generation from valid IKM")
}

/// Decode a hex string (with or without `0x` prefix) into bytes.
///
/// # Errors
///
/// Returns `Err` if the string is not valid hex or has an odd length.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if !hex.len().is_multiple_of(2) {
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

/// Parse one `--observer-peer <addr_hex>=<bls_pubkey_hex>` entry into
/// the `(address, public key)` pair the transport's observer
/// allowlist consumes. The address is the follower's claimed peer
/// id (20 bytes); the key is what its handshake proof must verify
/// under — the allowlist binds *which* key a non-committee identity
/// must hold.
///
/// # Errors
///
/// Returns `Err` naming the malformed half — operator config errors
/// are fatal at startup, never silently ignored.
pub fn parse_observer_peer(
    entry: &str,
) -> Result<(primitives::Address, crypto::PublicKey), String> {
    let (addr_hex, key_hex) =
        entry.split_once('=').ok_or_else(|| "expected <addr_hex>=<bls_pubkey_hex>".to_string())?;
    let addr_bytes = hex_decode(addr_hex).map_err(|e| format!("address '{addr_hex}': {e}"))?;
    let addr = primitives::Address(
        <[u8; 20]>::try_from(addr_bytes.as_slice())
            .map_err(|_| format!("address '{addr_hex}' must be 20 bytes"))?,
    );
    let key_bytes = hex_decode(key_hex).map_err(|e| format!("key '{key_hex}': {e}"))?;
    let key = crypto::bls::PublicKey::from_slice(&key_bytes)
        .map_err(|_| format!("key '{key_hex}' is not a valid BLS public key"))?;
    Ok((addr, key))
}

/// Load a 32-byte secret key file in any accepted encoding:
///
/// - **Encrypted keystore** (`crypto::keystore` magic): decrypted
///   with the passphrase from `OXIDE_KEY_PASSPHRASE`; `want_kind`
///   pins the declared key type so a valid decryption of the wrong
///   key kind still fails loudly. Requires the crate's `keystore`
///   feature — without it a keystore file errors precisely rather
///   than falling back to misparsing.
/// - **Hex text**: 64 hex chars, optional `0x` prefix, optional
///   surrounding whitespace (echo-written files carry a newline).
/// - **Raw binary**: exactly 32 bytes.
///
/// `want_kind` is ignored for raw encodings — they carry no type
/// tag, so the caller's flag name is the only contract.
///
/// # Errors
///
/// `Err` names the path and the precise failure (read error, bad
/// hex, wrong length, keystore error verbatim — including the
/// missing-passphrase hint).
pub fn load_secret_key_file(path: &str, want_kind: SecretKind) -> Result<[u8; 32], String> {
    let raw = std::fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    parse_secret_key_bytes(&raw, want_kind).map_err(|e| format!("{path}: {e}"))
}

/// The key kind a file is expected to hold — mirrors
/// `crypto::keystore::KeyKind` without requiring the feature for the
/// raw paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// BLS12-381 consensus secret (`--bls-key-file`).
    Bls,
    /// secp256k1 secret (`--settlement-key-file`, `--signer-key-file`).
    Secp256k1,
    /// A raw 32-byte symmetric secret (`--signer-link-key-file`) —
    /// possession alone is the credential; there is no public half.
    Generic,
}

/// Decode a secret from raw file bytes — the shared sniff used by
/// [`load_secret_key_file`]. Separated for unit tests.
fn parse_secret_key_bytes(raw: &[u8], want_kind: SecretKind) -> Result<[u8; 32], String> {
    #[cfg(feature = "keystore")]
    if crypto::keystore::is_keystore(raw) {
        let pass = crypto::keystore::passphrase_from_env().map_err(|e| e.to_string())?;
        let (kind, secret) = crypto::keystore::open(raw, &pass).map_err(|e| e.to_string())?;
        let expected = match want_kind {
            SecretKind::Bls => crypto::keystore::KeyKind::Bls,
            SecretKind::Secp256k1 => crypto::keystore::KeyKind::Secp256k1,
            SecretKind::Generic => crypto::keystore::KeyKind::Generic,
        };
        if kind != expected {
            return Err(format!("keystore holds a {kind:?} key but {expected:?} was expected"));
        }
        return Ok(secret);
    }
    #[cfg(not(feature = "keystore"))]
    {
        // Without the keystore feature the magic still gets a precise
        // refusal — never a misparse as a raw 87-byte scalar.
        const OXKEY: &[u8; 5] = b"OXKEY";
        if raw.starts_with(OXKEY) {
            return Err(
                "encrypted keystore requires a build with the `keystore` feature".to_string()
            );
        }
        let _ = want_kind;
    }
    // Hex text: 64 hex chars (optional 0x) with surrounding
    // whitespace tolerated — `echo`/`$EDITOR` files carry newlines.
    if let Ok(text) = std::str::from_utf8(raw) {
        let text = text.trim();
        let hex = text.strip_prefix("0x").unwrap_or(text);
        if hex.len() == 64 {
            let bytes = hex_decode(hex)?;
            return bytes.try_into().map_err(|_| "expected 32 bytes".to_string());
        }
    }
    if raw.len() == 32 {
        return Ok(raw.try_into().expect("32-byte slice"));
    }
    Err(format!(
        "expected a 64-char hex key, 32 raw bytes, or an OXKEY keystore \
         (got {} bytes)",
        raw.len()
    ))
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

    /// Every insecure default is reported, and a fully-configured
    /// posture reports nothing.
    #[test]
    fn insecure_posture_reasons_cover_each_condition() {
        let insecure = ExternalPosture {
            deterministic_consensus_key: true,
            transport_unencrypted: true,
            genesis_file_absent: true,
            chain_id: 1,
            min_fee: 0,
        };
        let reasons = insecure_posture_reasons(&insecure);
        assert_eq!(reasons.len(), 5, "each insecure default is its own reason: {reasons:?}");

        let secure = ExternalPosture { chain_id: 31337, min_fee: 1, ..ExternalPosture::default() };
        assert!(insecure_posture_reasons(&secure).is_empty());
    }

    /// The public-ID table must cover at least the named Ethereum
    /// networks (mainnet + live testnets) — an ID missed there signs
    /// replayable transactions.
    #[test]
    fn public_chain_ids_cover_ethereum() {
        for id in [1u64, 5, 17000, 11_155_111] {
            assert!(PUBLIC_CHAIN_IDS.contains(&id), "chain id {id} must be refused");
        }
        // A private/dev chain id is not in the table.
        assert!(!PUBLIC_CHAIN_IDS.contains(&31337));
    }
}
