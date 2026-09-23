//! Genesis file format — JSON genesis state for chain initialization.
//!
//! A genesis file defines the initial state of the chain at height 0:
//! - Chain ID and consensus parameters
//! - Pre-funded accounts (EVM `alloc` balances)
//! - Initial validator set (addresses + stakes)
//! - Staking parameters (unbonding period, block reward)
//!
//! # Format
//!
//! The genesis file is JSON (not TOML) to match the Ethereum
//! convention (`genesis.json`) and enable tooling compatibility
//! (Foundry, Hardhat, Blockscout all expect JSON genesis).
//!
//! # Example
//!
//! ```json
//! {
//!   "chain_id": 1,
//!   "consensus": {
//!     "engine": "oxidebft",
//!     "base_timeout_ms": 2000,
//!     "max_timeout_ms": 30000
//!   },
//!   "evm": {
//!     "alloc": {
//!       "0x0000000000000000000000000000000000000000":
//!         { "balance": "1000000000000000000000" },
//!       "0x0101010101010101010101010101010101010101":
//!         { "balance": "500000000000000000000" }
//!     }
//!   },
//!   "staking": {
//!     "validators": [
//!       { "address": "0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", "stake": 1000000 },
//!       { "address": "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "stake": 1000000 }
//!     ],
//!     "unbonding_period_blocks": 100,
//!     "block_reward": 1000000000
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::ConsensusEngineKind;

/// The genesis state — the initial state of the chain at height 0.
///
/// This is the JSON-serializable genesis file format. It's separate
/// from the node [`crate::Config`] (which is TOML and controls
/// runtime parameters, not chain state).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Genesis {
    /// The EIP-155 chain ID.
    pub chain_id: u64,
    /// Consensus engine and parameters.
    #[serde(default)]
    pub consensus: GenesisConsensus,
    /// Legacy balance map: pre-funded account balances in base
    /// units (1 unit = 10^9 wei). There is no bank module — the EVM
    /// account store is the single native-token ledger — so these
    /// are applied to `evm` accounts at genesis, scaled to wei.
    /// Kept for file compatibility with genesis files written before
    /// the ledger unification; new files should use `evm.alloc`.
    #[serde(default)]
    pub bank: GenesisBank,
    /// Staking module: initial validator set and parameters.
    #[serde(default)]
    pub staking: GenesisStaking,
    /// EVM module: `alloc` state (Ethereum `genesis.json` convention).
    #[serde(default)]
    pub evm: GenesisEvm,
}

/// Consensus parameters in the genesis file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisConsensus {
    /// The consensus engine to use.
    #[serde(default = "default_engine")]
    pub engine: ConsensusEngineKind,
    /// Base timeout for the first view (milliseconds).
    #[serde(default = "default_base_timeout_ms")]
    pub base_timeout_ms: u64,
    /// Maximum timeout for exponential backoff (milliseconds).
    #[serde(default = "default_max_timeout_ms")]
    pub max_timeout_ms: u64,
}

impl Default for GenesisConsensus {
    fn default() -> Self {
        Self {
            engine: default_engine(),
            base_timeout_ms: default_base_timeout_ms(),
            max_timeout_ms: default_max_timeout_ms(),
        }
    }
}

fn default_engine() -> ConsensusEngineKind {
    ConsensusEngineKind::OxideBft
}
fn default_base_timeout_ms() -> u64 {
    2_000
}
fn default_max_timeout_ms() -> u64 {
    30_000
}

/// Legacy balance map in genesis: pre-funded account balances in
/// base units. Applied to the EVM account store (scaled to wei).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisBank {
    /// Pre-funded account balances, keyed by hex address.
    /// Address format: `0x` + 40 hex chars (20 bytes).
    pub balances: serde_json::Map<String, serde_json::Value>,
}

/// Staking module genesis state: initial validator set and parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisStaking {
    /// The initial validator set.
    #[serde(default)]
    pub validators: Vec<GenesisValidator>,
    /// The unbonding period in blocks.
    #[serde(default = "default_unbonding_period")]
    pub unbonding_period_blocks: u64,
    /// The block reward in atomic units.
    #[serde(default = "default_block_reward")]
    pub block_reward: u64,
}

impl Default for GenesisStaking {
    fn default() -> Self {
        Self {
            validators: Vec::new(),
            unbonding_period_blocks: default_unbonding_period(),
            block_reward: default_block_reward(),
        }
    }
}

/// EVM module genesis state: the Ethereum `alloc` map.
///
/// Follows the `genesis.json` convention used by geth/reth/Foundry:
/// each key is a hex address, each value carries `balance`, `nonce`,
/// `code`, and `storage` so a genesis can declare contracts and
/// preinstalls (e.g. the Create2 factory, Multicall3) at canonical
/// addresses.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisEvm {
    /// Account allocations, keyed by hex address (`0x` + 40 chars).
    #[serde(default)]
    pub alloc: std::collections::BTreeMap<String, GenesisEvmAccount>,
}

/// One `alloc` entry: the account's initial state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisEvmAccount {
    /// Wei balance — hex quantity (`"0x…"`) or decimal string.
    #[serde(default)]
    pub balance: String,
    /// Account nonce.
    #[serde(default)]
    pub nonce: u64,
    /// Runtime bytecode as a hex string (preinstalled contracts).
    #[serde(default)]
    pub code: Option<String>,
    /// Initial storage slots, `hex slot → hex value` (32-byte each).
    #[serde(default)]
    pub storage: std::collections::BTreeMap<String, String>,
}

fn default_unbonding_period() -> u64 {
    100
}
fn default_block_reward() -> u64 {
    1_000_000_000
}

/// A validator in the genesis validator set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisValidator {
    /// The validator's address as a hex string (`0x` + 40 hex chars).
    /// This is the staking identity — it survives BLS key rotation.
    pub address: String,
    /// The validator's BLS public key as a hex string (`0x` + 96 hex
    /// chars = 48 bytes). Required for multi-node genesis — the
    /// `ValidatorSet` needs the public key to verify vote/QC
    /// signatures. Optional for single-node devnet (a key is
    /// generated deterministically).
    #[serde(default)]
    pub public_key: Option<String>,
    /// The validator's initial stake.
    pub stake: u64,
}

/// A weak-subjectivity validator-set checkpoint: the `(epoch, set)`
/// pair a state-sync client trusts to verify the quorum-signed
/// execution certificate that anchors a downloaded snapshot.
///
/// This replaces the bare operator-typed `--trusted-root` as the
/// sync trust anchor: a certificate is cryptographic evidence that
/// validators holding >2/3 of the checkpointed stake attested the
/// root, so the peer serving the snapshot cannot forge it. The
/// checkpoint itself must come from a source the operator already
/// trusts (their own genesis, a network-published committee list,
/// a governance output) — that is the weak-subjectivity assumption.
///
/// ```json
/// {
///   "epoch": 0,
///   "validators": [
///     { "address": "0x<40 hex>", "public_key": "0x<96 hex>", "stake": 1000000 }
///   ]
/// }
/// ```
///
/// `epoch` must equal the epoch the served certificate was signed
/// under: the certificate's aggregate signature binds the epoch, so
/// a checkpoint naming the wrong epoch fails verification rather
/// than indexing the wrong set. For a chain still in its genesis
/// epoch, the genesis file's validator list serves as the epoch-0
/// checkpoint; after a rotation the operator supplies the newer
/// set explicitly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorSetCheckpoint {
    /// The epoch this set was live under — compared to the
    /// certificate's signed epoch at verification time.
    pub epoch: u64,
    /// The validator set: same record shape as genesis validators.
    /// `public_key` is REQUIRED here (unlike genesis, where devnets
    /// may omit it for deterministic derivation) — a checkpoint
    /// without keys can verify nothing.
    pub validators: Vec<GenesisValidator>,
}

impl ValidatorSetCheckpoint {
    /// Parse a checkpoint from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the JSON is invalid or doesn't match the
    /// checkpoint schema.
    pub fn from_json_str(s: &str) -> Result<Self, GenesisError> {
        serde_json::from_str(s).map_err(|e| GenesisError::Parse(e.to_string()))
    }

    /// Parse a checkpoint from a JSON file.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the file cannot be read or parsed.
    pub fn from_json_file(path: &std::path::Path) -> Result<Self, GenesisError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| GenesisError::FileRead(path.display().to_string(), e.to_string()))?;
        Self::from_json_str(&contents)
    }
}

impl Genesis {
    /// Create a new genesis with the given chain ID and defaults.
    #[must_use]
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            consensus: GenesisConsensus::default(),
            bank: GenesisBank::default(),
            staking: GenesisStaking::default(),
            evm: GenesisEvm::default(),
        }
    }

    /// Parse a genesis from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the JSON is invalid or doesn't match the
    /// genesis schema.
    pub fn from_json_str(s: &str) -> Result<Self, GenesisError> {
        serde_json::from_str(s).map_err(|e| GenesisError::Parse(e.to_string()))
    }

    /// Parse a genesis from a JSON file.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the file cannot be read or parsed.
    pub fn from_json_file(path: &std::path::Path) -> Result<Self, GenesisError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| GenesisError::FileRead(path.display().to_string(), e.to_string()))?;
        Self::from_json_str(&contents)
    }

    /// Serialize the genesis to a JSON string (pretty-printed).
    ///
    /// # Errors
    ///
    /// Returns `Err` if serialization fails (shouldn't happen for
    /// well-formed genesis).
    pub fn to_json_string(&self) -> Result<String, GenesisError> {
        serde_json::to_string_pretty(self).map_err(|e| GenesisError::Serialize(e.to_string()))
    }

    /// Write the genesis to a JSON file (pretty-printed).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the file cannot be written or serialization fails.
    pub fn to_json_file(&self, path: &std::path::Path) -> Result<(), GenesisError> {
        let json = self.to_json_string()?;
        std::fs::write(path, json)
            .map_err(|e| GenesisError::FileWrite(path.display().to_string(), e.to_string()))
    }

    /// Generate a default devnet genesis with the given chain ID,
    /// N validators, and pre-funded senders.
    ///
    /// This is the genesis used by the devnet. Validators get
    /// addresses `[0x0a; 20]`, `[0x0b; 20]`, etc. Pre-funded senders
    /// get addresses `[0x00; 20]`, `[0x01; 20]`, etc.
    #[must_use]
    pub fn devnet(chain_id: u64, num_validators: usize, num_prefunded: u8, balance: u64) -> Self {
        let mut genesis = Self::new(chain_id);

        // Pre-fund senders [0x00; 20] through [n-1; 20] in the EVM
        // `alloc` map — the single native-token ledger. `balance` is
        // base units; genesis applies it scaled to wei (10^9 wei per
        // unit) so the same amounts native txs move are visible via
        // `eth_getBalance`.
        // Each address is 20 bytes of the same value: [i; 20].
        for i in 0..num_prefunded {
            let byte_hex = format!("{i:02x}");
            let addr = format!("0x{}", byte_hex.repeat(20));
            genesis.evm.alloc.insert(
                addr,
                GenesisEvmAccount {
                    balance: (u128::from(balance) * 1_000_000_000).to_string(),
                    ..GenesisEvmAccount::default()
                },
            );
        }

        // Create validators [0x0a; 20], [0x0b; 20], etc.
        for i in 0..num_validators {
            let byte = 0x0a + u8::try_from(i).unwrap_or(0xFF);
            let addr = format!(
                "0x{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}{byte:02x}"
            );
            genesis.staking.validators.push(GenesisValidator {
                address: addr,
                public_key: None,
                stake: 1_000_000,
            });
        }

        genesis
    }

    /// Add a pre-funded account balance (base units → EVM `alloc`
    /// in wei).
    ///
    /// `address` must be a hex string with `0x` prefix (20 bytes).
    pub fn add_balance(&mut self, address: &str, balance: u64) {
        self.evm.alloc.insert(
            address.to_string(),
            GenesisEvmAccount {
                balance: (u128::from(balance) * 1_000_000_000).to_string(),
                ..GenesisEvmAccount::default()
            },
        );
    }

    /// Add a validator to the genesis validator set.
    ///
    /// `address` must be a hex string with `0x` prefix (20 bytes).
    pub fn add_validator(&mut self, address: &str, stake: u64) {
        self.staking.validators.push(GenesisValidator {
            address: address.to_string(),
            public_key: None,
            stake,
        });
    }
}

impl GenesisBank {
    /// Get the balance for a hex address, or 0 if not present.
    pub fn balance(&self, address: &str) -> u64 {
        self.balances.get(address).and_then(serde_json::Value::as_u64).unwrap_or(0)
    }

    /// Insert a balance for a hex address.
    pub fn insert(&mut self, address: String, balance: u64) {
        self.balances.insert(address, serde_json::Value::Number(balance.into()));
    }
}

/// Genesis file loading/parsing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisError {
    /// The genesis file could not be read.
    FileRead(String, String),
    /// The genesis file could not be written.
    FileWrite(String, String),
    /// The genesis JSON could not be parsed.
    Parse(String),
    /// The genesis could not be serialized.
    Serialize(String),
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileRead(path, reason) => write!(f, "cannot read genesis file {path}: {reason}"),
            Self::FileWrite(path, reason) => {
                write!(f, "cannot write genesis file {path}: {reason}")
            }
            Self::Parse(reason) => write!(f, "cannot parse genesis: {reason}"),
            Self::Serialize(reason) => write!(f, "cannot serialize genesis: {reason}"),
        }
    }
}

impl std::error::Error for GenesisError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_roundtrips_json() {
        let mut genesis = Genesis::new(42);
        genesis.add_balance("0x0000000000000000000000000000000000000000", 1_000_000);
        genesis.add_validator("0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a", 1_000_000);
        genesis.staking.unbonding_period_blocks = 200;
        genesis.staking.block_reward = 2_000_000_000;

        let json = genesis.to_json_string().unwrap();
        let parsed = Genesis::from_json_str(&json).unwrap();
        assert_eq!(genesis, parsed);
    }

    #[test]
    fn genesis_from_json_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("oxide_genesis_test.json");
        let genesis = Genesis::devnet(1, 4, 32, 1_000_000_000_000);
        genesis.to_json_file(&path).unwrap();
        let loaded = Genesis::from_json_file(&path).unwrap();
        assert_eq!(genesis, loaded);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn devnet_genesis_has_validators_and_balances() {
        let genesis = Genesis::devnet(1, 4, 32, 1_000_000_000_000);
        assert_eq!(genesis.chain_id, 1);
        assert_eq!(genesis.staking.validators.len(), 4);
        assert_eq!(genesis.evm.alloc.len(), 32);
        assert_eq!(genesis.consensus.engine, ConsensusEngineKind::OxideBft);
    }

    #[test]
    fn genesis_balance_lookup() {
        let mut genesis = Genesis::new(1);
        genesis.add_balance("0x0101010101010101010101010101010101010101", 500_000);
        assert_eq!(
            genesis.evm.alloc["0x0101010101010101010101010101010101010101"].balance,
            "500000000000000"
        );
        assert!(!genesis.evm.alloc.contains_key("0x0202020202020202020202020202020202020202"));
    }

    #[test]
    fn genesis_parse_error_on_invalid_json() {
        let result = Genesis::from_json_str("not json");
        assert!(result.is_err());
    }

    #[test]
    fn genesis_default_consensus_is_oxidebft() {
        let genesis = Genesis::new(1);
        assert_eq!(genesis.consensus.engine, ConsensusEngineKind::OxideBft);
    }

    #[test]
    fn genesis_validators_have_stakes() {
        let genesis = Genesis::devnet(1, 3, 0, 0);
        for v in &genesis.staking.validators {
            assert!(v.stake > 0, "validator stake must be positive");
            assert!(v.address.starts_with("0x"), "address must be hex");
        }
    }

    /// The weak-subjectivity checkpoint parses the documented JSON
    /// shape and carries the epoch the served certificate must name.
    #[test]
    fn validator_set_checkpoint_parses() {
        let json = r#"{
            "epoch": 3,
            "validators": [
                {
                    "address": "0x0101010101010101010101010101010101010101",
                    "public_key": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "stake": 1000000
                }
            ]
        }"#;
        let cp = ValidatorSetCheckpoint::from_json_str(json).expect("valid checkpoint");
        assert_eq!(cp.epoch, 3);
        assert_eq!(cp.validators.len(), 1);
        assert_eq!(cp.validators[0].stake, 1_000_000);
        assert!(cp.validators[0].public_key.is_some());
        assert!(ValidatorSetCheckpoint::from_json_str("not json").is_err());
        // A checkpoint with no validators parses but is unusable —
        // the consumer asserts non-empty at ValidatorSet build time.
        let empty = ValidatorSetCheckpoint::from_json_str(r#"{"epoch": 0, "validators": []}"#)
            .expect("empty set still parses");
        assert!(empty.validators.is_empty());
    }
}
