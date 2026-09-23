//! Oxide node configuration — layered TOML + env vars + CLI flags.
//!
//! # What this is
//!
//! The single source of truth for all node runtime parameters. Every
//! value that was previously hardcoded as a `const` in a crate is now
//! a field on a config struct, loaded from (in priority order):
//!
//! 1. **CLI flags** (highest priority — overrides everything)
//! 2. **Environment variables** (overrides TOML)
//! 3. **TOML config file** (the base)
//! 4. **Defaults** (lowest priority — built into the `Default` impl)
//!
//! This matches the layered config model used by geth/reth: a base
//! file for reproducibility, env vars for container deployments, and
//! CLI flags for ad-hoc overrides.
//!
//! # Why a config crate
//!
//! Production nodes need reproducible, auditable configuration. A
//! hardcoded `const` in a crate means recompiling to change a timeout;
//! a TOML file means `oxide-validator --config mainnet.toml`. Env vars
//! enable Docker/K8s deployments without mounting files. CLI flags
//! enable debugging overrides. All three layers are needed.
//!
//! # Structure
//!
//! The top-level [`Config`] struct is divided into sections:
//!
//! - [`NetworkConfig`]: TCP listen address, peer list, timeouts, max
//!   message size.
//! - [`ConsensusConfig`]: engine selection, pacemaker timeouts, block
//!   budget.
//! - [`ExecutorConfig`]: mempool size, parallel execution threshold.
//! - [`GenesisConfig`]: genesis balances, validator set.
//!
//! Each section has its own `Default` impl with documented constants.
//!
//! # Env var convention
//!
//! Env vars use the prefix `OXIDE_` followed by the field path with
//! underscores. Examples:
//!
//! - `OXIDE_NETWORK_LISTEN_ADDR=127.0.0.1:9000`
//! - `OXIDE_NETWORK_CONNECT_TIMEOUT_SECS=10`
//! - `OXIDE_CONSENSUS_BASE_TIMEOUT_MS=1000`
//! - `OXIDE_EXECUTOR_PARALLEL_THRESHOLD=200`
//! - `OXIDE_EXECUTOR_MAX_MEMPOOL_ENTRIES=50000`
//!
//! # CLI flag convention
//!
//! CLI flags use `--key value` pairs matching the TOML field names:
//!
//! - `--network.listen-addr 127.0.0.1:9000`
//! - `--consensus.base-timeout-ms 1000`
//! - `--executor.parallel-threshold 200`

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub mod genesis;

// ── Top-level config ─────────────────────────────────────────────

/// The top-level node configuration.
///
/// Loaded from a TOML file, with env var and CLI flag overrides applied
/// in that order (CLI > env > TOML > default).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Network / transport configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Consensus engine configuration.
    #[serde(default)]
    pub consensus: ConsensusConfig,

    /// Executor configuration.
    #[serde(default)]
    pub executor: ExecutorConfig,

    /// Storage / retention configuration.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Genesis state configuration.
    #[serde(default)]
    pub genesis: GenesisConfig,

    /// RPC server configuration (JSON-RPC HTTP endpoint).
    /// If `None`, the node does not start an RPC server.
    #[serde(default)]
    pub rpc: Option<RpcConfig>,

    /// Exchange module configuration (settlement operator).
    #[serde(default)]
    pub exchange: ExchangeConfig,
}

/// RPC server configuration (JSON-RPC HTTP endpoint for
/// MetaMask/Foundry/Blockscout integration).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcConfig {
    /// The listen address for the HTTP server (e.g. "127.0.0.1:8545").
    pub listen_addr: String,
    /// The chain ID for EIP-155 replay protection.
    pub chain_id: u64,
    /// The base fee in wei per gas (EIP-1559).
    pub base_fee: u64,
    /// Serve the `debug_trace*` namespace. Tracing re-executes whole
    /// blocks — the heaviest calls on the endpoint — so it defaults
    /// OFF: operators opt in on private deployments rather than pay
    /// the exposure by default (geth's `--http.api` excludes `debug`
    /// the same way). `OXIDE_RPC_ENABLE_DEBUG_API` overrides.
    #[serde(default)]
    pub enable_debug_api: bool,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8545".to_string(),
            chain_id: 1,
            base_fee: 1_000_000_000,
            enable_debug_api: false,
        }
    }
}

impl RpcConfig {
    /// Apply overrides from `get` (the process env in production).
    fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) {
        if let Some(v) = get("OXIDE_RPC_ENABLE_DEBUG_API")
            && let Ok(b) = v.parse::<bool>()
        {
            self.enable_debug_api = b;
        }
    }
}

impl Config {
    /// Load config from a TOML file, then apply env var overrides.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the file cannot be read or parsed.
    pub fn from_toml_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path)
            .map_err(|e| ConfigError::FileRead(path.display().to_string(), e.to_string()))?;
        let mut config: Self = toml::from_str(&contents)
            .map_err(|e| ConfigError::Parse(path.display().to_string(), e.to_string()))?;
        config.apply_env_vars();
        Ok(config)
    }

    /// Load config from a TOML string (for tests and embedded configs).
    ///
    /// Unlike [`from_toml_file`](Self::from_toml_file), this does NOT
    /// apply env var overrides — it returns the config exactly as
    /// parsed from the TOML string. This makes it deterministic for
    /// tests (env vars from other tests won't leak in).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string cannot be parsed.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse("<string>".to_string(), e.to_string()))
    }

    /// Apply env var overrides on top of the current config.
    ///
    /// Env vars use the prefix `OXIDE_` followed by the field path
    /// with underscores. See the module docs for examples.
    ///
    /// This is called automatically by [`from_toml_file`](Self::from_toml_file).
    /// Tests can call it manually after [`from_toml_str`](Self::from_toml_str)
    /// to verify env var override behavior.
    pub fn apply_env_vars(&mut self) {
        self.apply_env(&|k| env::var(k).ok());
    }

    /// Apply overrides from an arbitrary lookup instead of the
    /// process environment. `env::set_var` is unsafe in edition 2024
    /// — mutating the environment races with every other thread's
    /// `getenv` — so tests inject their values through this seam
    /// rather than touching `std::env`.
    fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) {
        self.network.apply_env(get);
        self.consensus.apply_env(get);
        self.executor.apply_env(get);
        self.storage.apply_env(get);
        self.genesis.apply_env(get);
        self.exchange.apply_env(get);
        // `rpc` is optional in TOML; an env-set RPC variable creates
        // the section (binaries construct `RpcConfig::default()` when
        // it's absent anyway, so this only makes env reachable).
        self.rpc.get_or_insert_default().apply_env(get);
    }
}

// ── Network config ───────────────────────────────────────────────

/// Network / transport configuration.
///
/// Controls the TCP transport: listen address, peer list, timeouts,
/// and max message size. All values were previously hardcoded as
/// `const` in `crates/p2p/src/tcp.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    /// The TCP address to listen on for incoming peer connections.
    /// Default: `127.0.0.1:20000` (localhost, suitable for local
    /// devnet). Production: `0.0.0.0:9000` or a specific bind address.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// The list of peer addresses to connect to (full mesh). Each
    /// entry is a TCP address string like `127.0.0.1:20001`.
    /// Default: empty (single-node devnet).
    #[serde(default)]
    pub peers: Vec<String>,

    /// The connect timeout for outbound TCP connections, in seconds.
    /// Short enough that a dead peer is detected quickly during
    /// startup. Default: 5 seconds.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// The read timeout for reader threads, in seconds. A safety net
    /// to prevent a stalled connection from holding a thread forever.
    /// Default: 30 seconds.
    #[serde(default = "default_read_timeout_secs")]
    pub read_timeout_secs: u64,

    /// The maximum message size the transport accepts, in bytes.
    /// Messages larger than this are rejected. Default: 16 MiB
    /// (matches the broadcast crate's erasure chunk size).
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: u64,
}

fn default_listen_addr() -> String {
    "127.0.0.1:20000".to_string()
}
fn default_connect_timeout_secs() -> u64 {
    5
}
fn default_read_timeout_secs() -> u64 {
    30
}
fn default_max_message_bytes() -> u64 {
    16 << 20
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            peers: Vec::new(),
            connect_timeout_secs: default_connect_timeout_secs(),
            read_timeout_secs: default_read_timeout_secs(),
            max_message_bytes: default_max_message_bytes(),
        }
    }
}

impl NetworkConfig {
    /// The connect timeout as a `Duration`.
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    /// The read timeout as a `Duration`.
    pub fn read_timeout(&self) -> Duration {
        Duration::from_secs(self.read_timeout_secs)
    }

    /// Apply overrides from `get` (the process env in production).
    fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) {
        if let Some(v) = get("OXIDE_NETWORK_LISTEN_ADDR") {
            self.listen_addr = v;
        }
        if let Some(v) = get("OXIDE_NETWORK_PEERS") {
            self.peers = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Some(v) = get("OXIDE_NETWORK_CONNECT_TIMEOUT_SECS")
            && let Ok(secs) = v.parse()
        {
            self.connect_timeout_secs = secs;
        }
        if let Some(v) = get("OXIDE_NETWORK_READ_TIMEOUT_SECS")
            && let Ok(secs) = v.parse()
        {
            self.read_timeout_secs = secs;
        }
        if let Some(v) = get("OXIDE_NETWORK_MAX_MESSAGE_BYTES")
            && let Ok(bytes) = v.parse()
        {
            self.max_message_bytes = bytes;
        }
    }
}

// ── Consensus config ─────────────────────────────────────────────

/// The consensus engine selection.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConsensusEngineKind {
    /// Single-leader dev-mode engine (no voting, no BFT).
    #[default]
    Sequencer,
    /// `oxideBFT` (2-chain `HotStuff` with `BLS` QCs).
    OxideBft,
}

impl ConsensusEngineKind {
    /// Parse from a string (for CLI args and env vars).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sequencer" => Some(Self::Sequencer),
            "oxidebft" => Some(Self::OxideBft),
            _ => None,
        }
    }

    /// The string name for config serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::OxideBft => "oxidebft",
        }
    }
}

/// Consensus engine configuration.
///
/// Controls the consensus engine selection and pacemaker timeouts.
/// All values were previously hardcoded as `const` in
/// `crates/consensus/src/pacemaker.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusConfig {
    /// Which consensus engine to use.
    #[serde(default)]
    pub engine: ConsensusEngineKind,

    /// Base timeout duration (milliseconds) for the first view.
    /// Origin: plan.md §4 — steady-state blocks are 50–100ms, but a
    /// view timeout must accommodate WAN RTT (~30ms) + vote
    /// aggregation (~15ms) + jitter. Default: 2000 ms.
    #[serde(default = "default_base_timeout_ms")]
    pub base_timeout_ms: u64,

    /// Maximum timeout duration (milliseconds) for exponential
    /// backoff. A stuck leader must not stall the chain for more than
    /// a few seconds. Default: 30000 ms.
    #[serde(default = "default_max_timeout_ms")]
    pub max_timeout_ms: u64,

    /// Maximum block size in bytes. Default: 1 MiB.
    #[serde(default = "default_max_block_bytes")]
    pub max_block_bytes: u64,

    /// Maximum block gas. Default: 1 billion gas.
    #[serde(default = "default_max_block_gas")]
    pub max_block_gas: u64,
}

fn default_base_timeout_ms() -> u64 {
    2_000
}
fn default_max_timeout_ms() -> u64 {
    30_000
}
fn default_max_block_bytes() -> u64 {
    1 << 20
}
fn default_max_block_gas() -> u64 {
    1_000_000_000
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            engine: ConsensusEngineKind::default(),
            base_timeout_ms: default_base_timeout_ms(),
            max_timeout_ms: default_max_timeout_ms(),
            max_block_bytes: default_max_block_bytes(),
            max_block_gas: default_max_block_gas(),
        }
    }
}

impl ConsensusConfig {
    /// Apply overrides from `get` (the process env in production).
    fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) {
        if let Some(v) = get("OXIDE_CONSENSUS_ENGINE")
            && let Some(engine) = ConsensusEngineKind::parse(&v)
        {
            self.engine = engine;
        }
        if let Some(v) = get("OXIDE_CONSENSUS_BASE_TIMEOUT_MS")
            && let Ok(ms) = v.parse()
        {
            self.base_timeout_ms = ms;
        }
        if let Some(v) = get("OXIDE_CONSENSUS_MAX_TIMEOUT_MS")
            && let Ok(ms) = v.parse()
        {
            self.max_timeout_ms = ms;
        }
        if let Some(v) = get("OXIDE_CONSENSUS_MAX_BLOCK_BYTES")
            && let Ok(bytes) = v.parse()
        {
            self.max_block_bytes = bytes;
        }
        if let Some(v) = get("OXIDE_CONSENSUS_MAX_BLOCK_GAS")
            && let Ok(gas) = v.parse()
        {
            self.max_block_gas = gas;
        }
    }
}

// ── Executor config ──────────────────────────────────────────────

/// Executor configuration.
///
/// Controls the executor's mempool size and parallel execution
/// threshold. All values were previously hardcoded as `const` in
/// `crates/executor/src/lib.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutorConfig {
    /// Maximum number of entries in the mempool. Default: 10,000.
    #[serde(default = "default_max_mempool_entries")]
    pub max_mempool_entries: usize,

    /// The minimum batch size to use the parallel speculative
    /// execution path. Below this threshold, serial execution is
    /// faster (avoids rayon thread-pool overhead). Default: 100.
    #[serde(default = "default_parallel_threshold")]
    pub parallel_threshold: usize,

    /// Minimum transaction fee (`ctx.fee`, base units) for
    /// native-module txs. Txs declaring less are skipped before
    /// execution — the fee field is sender-controlled, so without a
    /// floor every tx could declare 0 and execute for free.
    /// Self-funded modules (EVM: gas is the fee) are exempt.
    /// `0` = no floor. Default: 0 (devnet); production should set a
    /// positive floor.
    #[serde(default)]
    pub min_fee: u64,

    /// Admit unsigned transactions to non-self-authenticating
    /// modules (everything but the EVM), trusting `ctx.sender` as
    /// declared.
    ///
    /// `false` (default) requires every native-module envelope to
    /// carry a valid EIP-712 signature — the only safe setting for
    /// a network that faces untrusted submitters. `true` is an
    /// explicitly unsafe development mode: any account can be
    /// impersonated, so the binaries gate it behind
    /// `--unsafe-allow-unsigned-txs` and refuse to combine it with
    /// externally reachable transports.
    #[serde(default)]
    pub allow_unsigned_txs: bool,
}

fn default_max_mempool_entries() -> usize {
    10_000
}
fn default_parallel_threshold() -> usize {
    100
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_mempool_entries: default_max_mempool_entries(),
            parallel_threshold: default_parallel_threshold(),
            min_fee: 0,
            allow_unsigned_txs: false,
        }
    }
}

impl ExecutorConfig {
    /// Apply overrides from `get` (the process env in production).
    fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) {
        if let Some(v) = get("OXIDE_EXECUTOR_MAX_MEMPOOL_ENTRIES")
            && let Ok(n) = v.parse()
        {
            self.max_mempool_entries = n;
        }
        if let Some(v) = get("OXIDE_EXECUTOR_PARALLEL_THRESHOLD")
            && let Ok(n) = v.parse()
        {
            self.parallel_threshold = n;
        }
        if let Some(v) = get("OXIDE_EXECUTOR_MIN_FEE")
            && let Ok(n) = v.parse()
        {
            self.min_fee = n;
        }
        if let Some(v) = get("OXIDE_EXECUTOR_ALLOW_UNSIGNED_TXS") {
            self.allow_unsigned_txs = matches!(v.as_str(), "1" | "true" | "yes");
        }
    }
}

// ── Storage / retention config ──────────────────────────────────

/// Storage and pruning configuration.
///
/// Bounds how much history a node keeps. Everything here is a
/// retention *policy*: none of it changes consensus or execution,
/// only how much past state this node can serve after the fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageConfig {
    /// Journal segments to retain (count-based bound). Old sealed
    /// segments beyond this are deleted once their contents are
    /// checkpointed. Default: 1000 (~256 GiB at 256 MiB segments).
    /// Ignored when `archive` is set.
    #[serde(default = "default_journal_retain_segments")]
    pub journal_retain_segments: u32,

    /// Heights of finalized-block / state-root history the
    /// executor keeps in memory (`Executor::with_history_retention`).
    /// Default: 4096.
    #[serde(default = "default_history_retention")]
    pub history_retention: usize,

    /// Archive mode: keep ALL history — journal segments, executor
    /// state roots, module undo windows. An archive node is the
    /// cold-tier answer to pruning: queryable back to genesis,
    /// sized by adding disk rather than by keeping less.
    /// Default: false.
    #[serde(default)]
    pub archive: bool,

    /// The node's data directory. When set, the EVM state database
    /// is persisted to `<data_dir>/evm.redb` (durable across
    /// restarts) and auto-snapshot persistence uses
    /// `<data_dir>/snapshot.bin`. `None` = fully in-memory state.
    /// The `--data-dir` CLI flag overrides this value.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
}

fn default_journal_retain_segments() -> u32 {
    1000
}
fn default_history_retention() -> usize {
    4096
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            journal_retain_segments: default_journal_retain_segments(),
            history_retention: default_history_retention(),
            archive: false,
            data_dir: None,
        }
    }
}

impl StorageConfig {
    /// Apply overrides from `get` (the process env in production).
    fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) {
        if let Some(v) = get("OXIDE_JOURNAL_RETAIN_SEGMENTS")
            && let Ok(n) = v.parse()
        {
            self.journal_retain_segments = n;
        }
        if let Some(v) = get("OXIDE_HISTORY_RETENTION")
            && let Ok(n) = v.parse()
        {
            self.history_retention = n;
        }
        if let Some(v) = get("OXIDE_ARCHIVE") {
            self.archive = matches!(v.as_str(), "1" | "true" | "yes");
        }
        if let Some(v) = get("OXIDE_STORAGE_DATA_DIR") {
            self.data_dir = Some(PathBuf::from(v));
        }
    }
}

// ── Exchange config ──────────────────────────────────────────────

/// Exchange module configuration.
///
/// Controls who may submit batch-settlement transactions — the
/// off-chain matching service's on-chain identity.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExchangeConfig {
    /// The settlement operator address (`0x`-prefixed 20-byte hex).
    /// The only account allowed to submit exchange `batch_settle`
    /// transactions. `None` disables batch settlement entirely
    /// (fail-closed default — safe when no external matcher is
    /// attached to this node).
    #[serde(default)]
    pub settlement_operator: Option<String>,
}

impl ExchangeConfig {
    /// Apply overrides from `get` (the process env in production).
    fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) {
        if let Some(v) = get("OXIDE_EXCHANGE_SETTLEMENT_OPERATOR") {
            self.settlement_operator = if v.is_empty() { None } else { Some(v) };
        }
    }
}

// ── Genesis config ───────────────────────────────────────────────

/// Genesis state configuration.
///
/// Controls the initial balances and validator set. Values were
/// previously hardcoded in `crates/devnet/src/multinode.rs` and
/// `crates/devnet/src/tcp_multinode.rs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisConfig {
    /// The genesis balance minted to each sender on every validator's
    /// EVM account store (base units, scaled to wei). Large enough
    /// that the simulation never exhausts it. Default: 10^12.
    #[serde(default = "default_genesis_balance")]
    pub genesis_balance: u64,

    /// The number of pre-funded sender addresses. The genesis mints
    /// `genesis_balance` to addresses `[0u8; 20]` through
    /// `[n-1; 20]`. Default: 32.
    #[serde(default = "default_num_prefunded_senders")]
    pub num_prefunded_senders: u8,

    /// The number of validators in the devnet. Default: 4.
    #[serde(default = "default_num_validators")]
    pub num_validators: usize,

    /// The base TCP port for the devnet. Each validator listens on
    /// `base_port + i`. Default: 20000.
    #[serde(default = "default_base_port")]
    pub base_port: u16,
}

fn default_genesis_balance() -> u64 {
    1_000_000_000_000
}
fn default_num_prefunded_senders() -> u8 {
    32
}
fn default_num_validators() -> usize {
    4
}
fn default_base_port() -> u16 {
    20_000
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            genesis_balance: default_genesis_balance(),
            num_prefunded_senders: default_num_prefunded_senders(),
            num_validators: default_num_validators(),
            base_port: default_base_port(),
        }
    }
}

impl GenesisConfig {
    /// Apply overrides from `get` (the process env in production).
    fn apply_env(&mut self, get: &dyn Fn(&str) -> Option<String>) {
        if let Some(v) = get("OXIDE_GENESIS_BALANCE")
            && let Ok(b) = v.parse()
        {
            self.genesis_balance = b;
        }
        if let Some(v) = get("OXIDE_GENESIS_NUM_PREFUNDED_SENDERS")
            && let Ok(n) = v.parse()
        {
            self.num_prefunded_senders = n;
        }
        if let Some(v) = get("OXIDE_GENESIS_NUM_VALIDATORS")
            && let Ok(n) = v.parse()
        {
            self.num_validators = n;
        }
        if let Some(v) = get("OXIDE_GENESIS_BASE_PORT")
            && let Ok(p) = v.parse()
        {
            self.base_port = p;
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────

/// Configuration loading/parsing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The config file could not be read.
    FileRead(String, String),
    /// The config file could not be parsed.
    Parse(String, String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileRead(path, reason) => write!(f, "cannot read config file {path}: {reason}"),
            Self::Parse(path, reason) => write!(f, "cannot parse config file {path}: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Default config round-trips through TOML serialization.
    #[test]
    fn default_config_roundtrips() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).expect("serialize");
        let parsed: Config = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(config, parsed);
    }

    /// TOML parsing picks up all fields.
    #[test]
    fn toml_parse_all_fields() {
        let toml_str = r#"
[network]
listen_addr = "0.0.0.0:9000"
peers = ["127.0.0.1:9001", "127.0.0.1:9002"]
connect_timeout_secs = 10
read_timeout_secs = 60
max_message_bytes = 33_554_432

[consensus]
engine = "oxidebft"
base_timeout_ms = 1000
max_timeout_ms = 20000
max_block_bytes = 2_097_152
max_block_gas = 500_000_000

[executor]
max_mempool_entries = 50000
parallel_threshold = 200

[genesis]
genesis_balance = 500_000_000000
num_prefunded_senders = 16
num_validators = 7
base_port = 30000
"#;
        let config = Config::from_toml_str(toml_str).expect("parse");
        assert_eq!(config.network.listen_addr, "0.0.0.0:9000");
        assert_eq!(config.network.peers.len(), 2);
        assert_eq!(config.network.connect_timeout_secs, 10);
        assert_eq!(config.network.read_timeout_secs, 60);
        assert_eq!(config.network.max_message_bytes, 33_554_432);
        assert_eq!(config.consensus.engine, ConsensusEngineKind::OxideBft);
        assert_eq!(config.consensus.base_timeout_ms, 1000);
        assert_eq!(config.consensus.max_timeout_ms, 20000);
        assert_eq!(config.consensus.max_block_bytes, 2_097_152);
        assert_eq!(config.consensus.max_block_gas, 500_000_000);
        assert_eq!(config.executor.max_mempool_entries, 50000);
        assert_eq!(config.executor.parallel_threshold, 200);
        assert_eq!(config.genesis.genesis_balance, 500_000_000_000);
        assert_eq!(config.genesis.num_prefunded_senders, 16);
        assert_eq!(config.genesis.num_validators, 7);
        assert_eq!(config.genesis.base_port, 30000);
    }

    /// Partial TOML uses defaults for missing fields.
    #[test]
    fn toml_partial_uses_defaults() {
        let toml_str = r#"
[consensus]
engine = "oxidebft"
"#;
        let config = Config::from_toml_str(toml_str).expect("parse");
        assert_eq!(config.consensus.engine, ConsensusEngineKind::OxideBft);
        // Defaults for everything else.
        assert_eq!(config.network.listen_addr, "127.0.0.1:20000");
        assert_eq!(config.executor.max_mempool_entries, 10000);
        assert_eq!(config.executor.parallel_threshold, 100);
        assert_eq!(config.genesis.genesis_balance, 1_000_000_000_000);
    }

    /// Empty TOML uses all defaults.
    #[test]
    fn toml_empty_uses_all_defaults() {
        let config = Config::from_toml_str("").expect("parse");
        assert_eq!(config, Config::default());
    }

    /// Env vars override TOML values.
    ///
    /// The override seam takes an injected lookup so this test never
    /// mutates the process environment: `env::set_var` is unsafe in
    /// edition 2024 because it races with every other thread's
    /// `getenv`, and the cargo harness is multithreaded.
    #[test]
    fn env_vars_override_toml() {
        let env = |k: &str| -> Option<String> {
            match k {
                "OXIDE_NETWORK_LISTEN_ADDR" => Some("0.0.0.0:9999".to_string()),
                "OXIDE_EXECUTOR_PARALLEL_THRESHOLD" => Some("500".to_string()),
                _ => None,
            }
        };

        let toml_str = r#"
[network]
listen_addr = "127.0.0.1:20000"
"#;
        let mut config = Config::from_toml_str(toml_str).expect("parse");
        config.apply_env(&env);

        // Env var overrides TOML.
        assert_eq!(config.network.listen_addr, "0.0.0.0:9999");
        assert_eq!(config.executor.parallel_threshold, 500);
    }

    /// `ConsensusEngineKind` parses correctly.
    #[test]
    fn engine_kind_parse() {
        assert_eq!(ConsensusEngineKind::parse("sequencer"), Some(ConsensusEngineKind::Sequencer));
        assert_eq!(ConsensusEngineKind::parse("oxidebft"), Some(ConsensusEngineKind::OxideBft));
        assert_eq!(ConsensusEngineKind::parse("OxideBFT"), Some(ConsensusEngineKind::OxideBft));
        assert_eq!(ConsensusEngineKind::parse("invalid"), None);
    }

    /// `NetworkConfig` timeout helpers return correct durations.
    #[test]
    fn network_timeout_helpers() {
        let net =
            NetworkConfig { connect_timeout_secs: 10, read_timeout_secs: 60, ..Default::default() };
        assert_eq!(net.connect_timeout(), Duration::from_secs(10));
        assert_eq!(net.read_timeout(), Duration::from_secs(60));
    }

    /// TOML parsing picks up the fee policy, storage, and exchange
    /// fields — these reach the executor/module wiring via
    /// `node::node_config_from`.
    #[test]
    fn toml_parse_fee_storage_exchange_fields() {
        let toml_str = r#"
[executor]
min_fee = 7
allow_unsigned_txs = true

[storage]
data_dir = "/var/lib/oxide"

[exchange]
settlement_operator = "0xoperator"
"#;
        let config = Config::from_toml_str(toml_str).expect("parse");
        assert_eq!(config.executor.min_fee, 7);
        assert!(config.executor.allow_unsigned_txs);
        assert_eq!(
            config.storage.data_dir.as_deref(),
            Some(std::path::Path::new("/var/lib/oxide"))
        );
        assert_eq!(config.exchange.settlement_operator.as_deref(), Some("0xoperator"));
    }

    /// Env vars override the fee policy, storage, and exchange
    /// fields — including the empty-operator clear. Injected through
    /// `apply_env` so nothing touches the process environment (see
    /// `env_vars_override_toml` for why that matters).
    #[test]
    fn env_vars_override_fee_storage_exchange() {
        let env = |k: &str| -> Option<String> {
            match k {
                "OXIDE_EXECUTOR_MIN_FEE" => Some("42".to_string()),
                "OXIDE_EXECUTOR_ALLOW_UNSIGNED_TXS" => Some("true".to_string()),
                "OXIDE_STORAGE_DATA_DIR" => Some("/tmp/oxide-data".to_string()),
                "OXIDE_EXCHANGE_SETTLEMENT_OPERATOR" => Some("0xop".to_string()),
                _ => None,
            }
        };
        let mut config = Config::default();
        config.apply_env(&env);
        assert_eq!(config.executor.min_fee, 42);
        assert!(config.executor.allow_unsigned_txs);
        assert_eq!(
            config.storage.data_dir.as_deref(),
            Some(std::path::Path::new("/tmp/oxide-data"))
        );
        assert_eq!(config.exchange.settlement_operator.as_deref(), Some("0xop"));

        // An empty operator value clears the setting.
        let env = |k: &str| -> Option<String> {
            if k == "OXIDE_EXCHANGE_SETTLEMENT_OPERATOR" { Some(String::new()) } else { None }
        };
        let mut config = Config::default();
        config.apply_env(&env);
        assert_eq!(config.exchange.settlement_operator, None);
    }
}
