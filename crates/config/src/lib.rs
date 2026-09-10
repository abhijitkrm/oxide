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
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

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

    /// Genesis state configuration.
    #[serde(default)]
    pub genesis: GenesisConfig,
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
        self.network.apply_env_vars();
        self.consensus.apply_env_vars();
        self.executor.apply_env_vars();
        self.genesis.apply_env_vars();
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

    /// Apply env var overrides.
    fn apply_env_vars(&mut self) {
        if let Ok(v) = env::var("OXIDE_NETWORK_LISTEN_ADDR") {
            self.listen_addr = v;
        }
        if let Ok(v) = env::var("OXIDE_NETWORK_PEERS") {
            self.peers = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(v) = env::var("OXIDE_NETWORK_CONNECT_TIMEOUT_SECS") {
            if let Ok(secs) = v.parse() {
                self.connect_timeout_secs = secs;
            }
        }
        if let Ok(v) = env::var("OXIDE_NETWORK_READ_TIMEOUT_SECS") {
            if let Ok(secs) = v.parse() {
                self.read_timeout_secs = secs;
            }
        }
        if let Ok(v) = env::var("OXIDE_NETWORK_MAX_MESSAGE_BYTES") {
            if let Ok(bytes) = v.parse() {
                self.max_message_bytes = bytes;
            }
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
    /// Apply env var overrides.
    fn apply_env_vars(&mut self) {
        if let Ok(v) = env::var("OXIDE_CONSENSUS_ENGINE") {
            if let Some(engine) = ConsensusEngineKind::parse(&v) {
                self.engine = engine;
            }
        }
        if let Ok(v) = env::var("OXIDE_CONSENSUS_BASE_TIMEOUT_MS") {
            if let Ok(ms) = v.parse() {
                self.base_timeout_ms = ms;
            }
        }
        if let Ok(v) = env::var("OXIDE_CONSENSUS_MAX_TIMEOUT_MS") {
            if let Ok(ms) = v.parse() {
                self.max_timeout_ms = ms;
            }
        }
        if let Ok(v) = env::var("OXIDE_CONSENSUS_MAX_BLOCK_BYTES") {
            if let Ok(bytes) = v.parse() {
                self.max_block_bytes = bytes;
            }
        }
        if let Ok(v) = env::var("OXIDE_CONSENSUS_MAX_BLOCK_GAS") {
            if let Ok(gas) = v.parse() {
                self.max_block_gas = gas;
            }
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
        }
    }
}

impl ExecutorConfig {
    /// Apply env var overrides.
    fn apply_env_vars(&mut self) {
        if let Ok(v) = env::var("OXIDE_EXECUTOR_MAX_MEMPOOL_ENTRIES") {
            if let Ok(n) = v.parse() {
                self.max_mempool_entries = n;
            }
        }
        if let Ok(v) = env::var("OXIDE_EXECUTOR_PARALLEL_THRESHOLD") {
            if let Ok(n) = v.parse() {
                self.parallel_threshold = n;
            }
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
    /// bank module. Large enough that the simulation never exhausts
    /// it. Default: 10^12 (1 trillion).
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
    /// Apply env var overrides.
    fn apply_env_vars(&mut self) {
        if let Ok(v) = env::var("OXIDE_GENESIS_BALANCE") {
            if let Ok(b) = v.parse() {
                self.genesis_balance = b;
            }
        }
        if let Ok(v) = env::var("OXIDE_GENESIS_NUM_PREFUNDED_SENDERS") {
            if let Ok(n) = v.parse() {
                self.num_prefunded_senders = n;
            }
        }
        if let Ok(v) = env::var("OXIDE_GENESIS_NUM_VALIDATORS") {
            if let Ok(n) = v.parse() {
                self.num_validators = n;
            }
        }
        if let Ok(v) = env::var("OXIDE_GENESIS_BASE_PORT") {
            if let Ok(p) = v.parse() {
                self.base_port = p;
            }
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
#[allow(unsafe_code)]
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
    #[test]
    fn env_vars_override_toml() {
        // Set env vars. SAFETY: `set_var` is unsafe in Rust 2024
        // because it can cause data races in multi-threaded tests,
        // but this test is single-threaded and the env vars are
        // cleaned up at the end.
        unsafe {
            env::set_var("OXIDE_NETWORK_LISTEN_ADDR", "0.0.0.0:9999");
            env::set_var("OXIDE_EXECUTOR_PARALLEL_THRESHOLD", "500");
        }

        let toml_str = r#"
[network]
listen_addr = "127.0.0.1:20000"
"#;
        let mut config = Config::from_toml_str(toml_str).expect("parse");
        config.apply_env_vars();

        // Env var overrides TOML.
        assert_eq!(config.network.listen_addr, "0.0.0.0:9999");
        assert_eq!(config.executor.parallel_threshold, 500);

        // Clean up.
        unsafe {
            env::remove_var("OXIDE_NETWORK_LISTEN_ADDR");
            env::remove_var("OXIDE_EXECUTOR_PARALLEL_THRESHOLD");
        }
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
}
