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

/// Refuse to start with unsigned-tx admission on any listener that
/// is reachable from other machines.
///
/// Unsigned envelopes trust the declared `sender` — acceptable on a
/// loopback devnet where every submitter is the operator, fatal on a
/// network-facing bind where it lets anyone spend any account. The
/// surfaces checked are the devnet transport (`--bind-host`)
/// and the JSON-RPC listener (`--rpc-listen` / `rpc.listen_addr`),
/// resolved the same way the listeners themselves are.
pub fn refuse_unsigned_on_external_binds(
    node_config: &NodeConfig,
    rpc_config: &config::RpcConfig,
    mode: crate::NodeMode,
    bin: &str,
) {
    if node_config.require_signed_txs {
        return;
    }
    let bind_host = matches!(mode, crate::NodeMode::Devnet)
        .then(|| parse_cli_flag("--bind-host").unwrap_or_else(|| "127.0.0.1".to_string()));
    // Same resolution the RPC startup paths use.
    let rpc_listen = parse_cli_flag("--rpc-listen").or_else(|| {
        if rpc_config.listen_addr.is_empty() { None } else { Some(rpc_config.listen_addr.clone()) }
    });
    let external = external_bind_surfaces(bind_host.as_deref(), rpc_listen.as_deref());
    if !external.is_empty() {
        eprintln!(
            "{bin}: refusing to start — --unsafe-allow-unsigned-txs admits \
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

    let rpc_config = config.rpc.clone().unwrap_or_default();

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
    refuse_unsigned_on_external_binds(&node_config, &rpc_config, mode, bin);

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

/// Build a signed v1 envelope from devnet identity 0 — the account
/// every devnet convenience flow (smoke tx, keep-alive delegate,
/// key-change) submits as. Signing is mandatory: the executor's
/// default `Reject` policy admits no unsigned native txs.
///
/// # Panics
///
/// Panics only if the built-in devnet identity is malformed or
/// refuses to sign — both impossible for the fixed test key.
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
}
