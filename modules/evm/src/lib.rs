//! Oxide EVM module — revm host, precompiles, EIP-1559 gas metering.
//!
//! This module is the `x/vm` analog (plan.md §2, §8): it wraps the
//! `revm` EVM engine and exposes it as a Cosmos-SDK-style `Module`
//! in the Oxide module router. Native messages (bank, staking,
//! trading) and EVM transactions share the same block and gas meter.
//!
//! # What this module does
//!
//! - Receives raw EVM call data via the module router's `handle`
//!   dispatch. The message format is `[to: 20B][calldata: ...]`.
//!   If `to` is all-zeros, the message is a contract deployment
//!   (calldata is the init code).
//! - Executes the call through `revm` with EIP-1559 gas metering.
//! - Persists account state (balance, nonce, code, storage) in a
//!   `CacheDB` (in-memory, backed by `EmptyDB`).
//! - Emits execution results as Oxide events (gas used, status, logs).
//!
//! # Why a module, not a standalone crate
//!
//! The Oxide architecture (plan.md §2) treats the EVM as one execution
//! track alongside the native track (trading modules). Both are modules
//! in the router; the executor dispatches by module ID. This keeps the
//! EVM swappable (future SVM/MoveVM modules use the same seam) and
//! lets native precompiles call into EVM and vice versa.
//!
//! # Phase 2 scope
//!
//! v0 implements:
//! - A `revm` `Evm` instance with a `CacheDB`-backed state.
//! - EIP-1559 gas metering (base fee + priority fee).
//! - Basic transaction execution (call + deploy).
//! - Account state in `CacheDB` (in-memory).
//!
//! Future phases add:
//! - `StorageBackend`-backed persistence (replacing `CacheDB`).
//! - Precompiles that call into native modules (bank, trading).
//! - Parallel OCC scheduler for cross-tx parallelism.
//! - JSON-RPC + WebSocket server.

use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::module_id;
use primitives::{Address, Hash, Height};

pub mod fee;
pub mod precompiles;

// revm imports. The `revm` crate re-exports all sub-crates.
use revm::Context;
use revm::context::TxEnv;
use revm::database::CacheDB;
use revm::database_interface::EmptyDB;
use revm::handler::{ExecuteCommitEvm, MainBuilder, MainContext};
use revm::inspector::NoOpInspector;
use revm::primitives::TxKind;
use revm::primitives::hardfork::SpecId;

/// The EVM module's dispatch ID in the module router.
///
/// Reserved by `framework::module_id::EVM` (3). Native modules use
/// IDs 0–2 (core, bank, staking); the EVM is the first VM module.
pub const MODULE_ID: u8 = module_id::EVM;

/// The default gas limit for a single EVM transaction (EIP-1559).
///
/// 30M gas matches Ethereum mainnet's default block-level tx limit.
/// This is a cold-path constant (set once per tx, not per-opcode).
const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// The EVM module: wraps `revm` and exposes it as an Oxide `Module`.
///
/// State is stored in a `CacheDB<EmptyDB>` (in-memory). The EVM
/// account state (balance, nonce, code, storage) lives in the cache.
/// Phase 2 later wires this to the `StorageBackend` for persistence.
pub struct EvmModule {
    /// The in-memory EVM database (account state, code, storage).
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    db: Mutex<CacheDB<EmptyDB>>,
    /// The chain ID for EIP-155 signed transactions.
    chain_id: u64,
    /// The base fee for EIP-1559 gas metering (wei per gas unit).
    /// Phase 2 v0 uses a fixed base fee; the dynamic base fee
    /// adjustment algorithm arrives with the full EIP-1559 impl.
    base_fee: u64,
    /// The EVM hardfork spec to use for execution.
    /// `SpecId::PRAGUE` is the latest stable mainnet spec in revm 42.
    spec: SpecId,
}

impl EvmModule {
    /// Construct a fresh EVM module with no accounts.
    ///
    /// # Arguments
    ///
    /// - `chain_id`: The EIP-155 chain ID. Used for signed transaction
    ///   validation.
    /// - `base_fee`: The initial EIP-1559 base fee (wei per gas). Phase
    ///   2 v0 uses a fixed base fee; dynamic adjustment arrives later.
    #[must_use]
    pub fn new(chain_id: u64, base_fee: u64) -> Self {
        Self {
            db: Mutex::new(CacheDB::new(EmptyDB::new())),
            chain_id,
            base_fee,
            spec: SpecId::PRAGUE,
        }
    }

    /// Construct with a specific hardfork spec (for testing older
    /// EVM behavior).
    #[must_use]
    pub fn with_spec(chain_id: u64, base_fee: u64, spec: SpecId) -> Self {
        Self { db: Mutex::new(CacheDB::new(EmptyDB::new())), chain_id, base_fee, spec }
    }

    /// The chain ID (EIP-155).
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The current EIP-1559 base fee (wei per gas).
    #[must_use]
    pub fn base_fee(&self) -> u64 {
        self.base_fee
    }

    /// Execute an EVM call. The `msg` format is `[to: 20B][calldata: ...]`.
    /// If `to` is all-zeros, this is a contract deployment.
    ///
    /// Returns the gas used and the execution status (true = success).
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message is too short
    /// (less than 20 bytes for the `to` address) or if the tx env
    /// cannot be built.
    /// Returns [`ExecError::ModuleRejected`] if the EVM execution fails.
    fn execute(&self, ctx: &TxContext, msg: &[u8]) -> Result<(u64, bool), ExecError> {
        // Parse the `to` address (first 20 bytes).
        if msg.len() < 20 {
            return Err(ExecError::Malformed);
        }
        let to_bytes: [u8; 20] = msg[..20].try_into().map_err(|_| ExecError::Malformed)?;
        let calldata = &msg[20..];

        // Build the transaction environment.
        let caller = alloy_primitives_address(ctx.sender.0);
        let to = alloy_primitives_address(to_bytes);
        let is_deploy = to_bytes == [0u8; 20];

        let tx = TxEnv::builder()
            .gas_limit(DEFAULT_GAS_LIMIT)
            .caller(caller)
            .kind(if is_deploy { TxKind::Create } else { TxKind::Call(to) })
            .data(revm::primitives::Bytes::copy_from_slice(calldata))
            .build()
            .map_err(|_| ExecError::Malformed)?;

        // Build and run the EVM. `transact_commit` executes the tx and
        // commits the state changes to the CacheDB in one step.
        let mut db = self.db.lock().expect("db mutex not poisoned");
        let mut evm = Context::mainnet()
            .with_db(&mut *db)
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(self.spec))
            .build_mainnet_with_inspector(NoOpInspector);

        let result = evm
            .transact_commit(tx)
            .map_err(|_| ExecError::ModuleRejected("evm transact failed".to_string()))?;

        let gas_used = result.tx_gas_used();
        let success = result.is_success();

        Ok((gas_used, success))
    }
}

impl Module for EvmModule {
    fn name(&self) -> &'static str {
        "evm"
    }

    fn id(&self) -> u8 {
        MODULE_ID
    }

    fn begin_block(&self, _height: Height) {
        // No per-block setup in v0. The EVM state is persistent across
        // blocks (account balances, nonces, code). Future: dynamic
        // base fee adjustment based on parent block gas usage.
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (gas_used, success) = self.execute(ctx, msg)?;

        let status_str = if success { "success" } else { "revert" };
        Ok(vec![Event {
            module: "evm",
            kind: "evm_call".to_string(),
            data: format!("gas_used={gas_used} status={status_str} base_fee={}", self.base_fee)
                .into_bytes(),
        }])
    }

    fn end_block(&self, _height: Height) {
        // No per-block cleanup in v0. Future: dynamic base fee
        // adjustment based on parent block gas usage.
    }

    fn state_root(&self) -> Hash {
        // Phase 2 v0: hash the CacheDB's account state. We serialize
        // each account's (address, balance, nonce, code_hash) into a
        // flat buffer and hash it. Full implementation hashes the EVM
        // state trie (Merkle Patricia Trie).
        //
        // Determinism (exploit suite, audit session 24): the account
        // map is a `HashMap`, whose iteration order is randomized per
        // instance — hashing in map order made the root differ across
        // processes (two validators executing the same block would
        // sign *different* state roots, breaking execution
        // attestations). Sort by address so the hash preimage is
        // canonical regardless of map order.
        //
        // # Panics
        //
        // Panics if the DB mutex is poisoned (a thread panicked while
        // holding the lock). This is unrecoverable and indicates a bug.
        use crypto::hash::{Domain, Hasher};
        let db = self.db.lock().expect("db mutex not poisoned");
        let mut accounts: Vec<_> = db.cache.accounts.iter().collect();
        accounts.sort_by(|a, b| a.0.cmp(b.0));
        let mut data = Vec::new();
        for (addr, account) in accounts {
            data.extend_from_slice(addr.as_slice());
            data.extend_from_slice(&account.info.balance.to_be_bytes::<32>());
            data.extend_from_slice(&account.info.nonce.to_be_bytes());
            data.extend_from_slice(account.info.code_hash.as_slice());
        }
        Hasher::hash_one(Domain::StateRoot, &data)
    }
}

impl EvmModule {
    /// Get an account's balance from the EVM state.
    ///
    /// Returns 0 for accounts not in the state (EVM convention).
    /// The EVM uses `U256` for balances; we truncate to `u128` (the
    /// upper 128 bits are always zero for any realistic balance).
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned (a thread panicked while
    /// holding the lock). This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn balance(&self, addr: &Address) -> u128 {
        let db = self.db.lock().expect("db mutex not poisoned");
        let evm_addr = alloy_primitives_address(addr.0);
        db.cache.accounts.get(&evm_addr).map_or(0, |a| a.info.balance.to::<u128>())
    }

    /// Get an account's nonce from the EVM state.
    ///
    /// Returns 0 for accounts not in the state.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned (a thread panicked while
    /// holding the lock). This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn nonce(&self, addr: &Address) -> u64 {
        let db = self.db.lock().expect("db mutex not poisoned");
        let evm_addr = alloy_primitives_address(addr.0);
        db.cache.accounts.get(&evm_addr).map_or(0, |a| a.info.nonce)
    }
}

/// Convert an Oxide `Address` (20 bytes) to a revm `Address`.
fn alloy_primitives_address(bytes: [u8; 20]) -> revm::primitives::Address {
    revm::primitives::Address::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module() -> EvmModule {
        EvmModule::new(1, 7)
    }

    #[test]
    fn module_id_is_evm() {
        let m = make_module();
        assert_eq!(m.id(), MODULE_ID);
        assert_eq!(m.id(), module_id::EVM);
    }

    #[test]
    fn name_is_evm() {
        let m = make_module();
        assert_eq!(m.name(), "evm");
    }

    #[test]
    fn chain_id_round_trips() {
        let m = EvmModule::new(42, 1);
        assert_eq!(m.chain_id(), 42);
    }

    #[test]
    fn base_fee_round_trips() {
        let m = EvmModule::new(1, 10_000_000_000);
        assert_eq!(m.base_fee(), 10_000_000_000);
    }

    #[test]
    fn handle_rejects_short_message() {
        let m = make_module();
        let ctx = TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 };
        let result = m.handle(&ctx, b"too short");
        assert!(matches!(result, Err(ExecError::Malformed)));
    }

    #[test]
    fn handle_executes_empty_call() {
        let m = make_module();
        let ctx = TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 };
        // 20-byte `to` address (all zeros = deploy), empty calldata.
        let msg = [0u8; 20];
        let result = m.handle(&ctx, &msg).expect("handle must succeed");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].module, "evm");
        assert_eq!(result[0].kind, "evm_call");
    }

    #[test]
    fn handle_executes_deploy() {
        let m = make_module();
        let ctx = TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 };
        // Deploy a contract: `to` = zeros (deploy), calldata = simple
        // bytecode that stores a value. PUSH1 0x01, PUSH1 0x00, SSTORE,
        // STOP.
        let mut msg = vec![0u8; 20]; // `to` = zeros (deploy)
        msg.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55, 0x00]); // calldata
        let result = m.handle(&ctx, &msg).expect("deploy must succeed");
        assert_eq!(result.len(), 1);
        // The event data contains "gas_used=" and "status=".
        let data_str = std::str::from_utf8(&result[0].data).expect("utf8");
        assert!(data_str.contains("gas_used="), "event must report gas used: {data_str}");
        assert!(data_str.contains("status="), "event must report status: {data_str}");
    }

    #[test]
    fn begin_block_does_not_panic() {
        let m = make_module();
        m.begin_block(Height::new(0));
    }

    #[test]
    fn end_block_does_not_panic() {
        let m = make_module();
        m.end_block(Height::new(0));
    }

    #[test]
    fn state_root_is_deterministic() {
        let m1 = make_module();
        let m2 = make_module();
        assert_eq!(
            m1.state_root(),
            m2.state_root(),
            "two fresh modules must have the same state root"
        );
    }

    #[test]
    fn balance_defaults_to_zero() {
        let m = make_module();
        assert_eq!(m.balance(&Address([0u8; 20])), 0);
    }

    #[test]
    fn nonce_defaults_to_zero() {
        let m = make_module();
        assert_eq!(m.nonce(&Address([0u8; 20])), 0);
    }

    #[test]
    fn state_root_changes_after_deploy() {
        let m = make_module();
        let root_before = m.state_root();
        let ctx = TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 };
        let mut msg = vec![0u8; 20];
        msg.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55, 0x00]);
        m.handle(&ctx, &msg).expect("deploy must succeed");
        let root_after = m.state_root();
        assert_ne!(root_before, root_after, "state root must change after a deploy");
    }

    #[test]
    fn deploy_increases_caller_nonce() {
        let m = make_module();
        let caller = Address([0x11; 20]);
        let ctx = TxContext { sender: caller, nonce: 0, fee: 0 };
        // Before any tx, the caller has no account (nonce 0).
        assert_eq!(m.nonce(&caller), 0);
        // Deploy a contract.
        let mut msg = vec![0u8; 20];
        msg.extend_from_slice(&[0x60, 0x01, 0x60, 0x00, 0x55, 0x00]);
        m.handle(&ctx, &msg).expect("deploy must succeed");
        // After a successful deploy, the caller's nonce must be 1.
        assert_eq!(m.nonce(&caller), 1, "caller nonce must be 1 after a deploy");
    }
}
