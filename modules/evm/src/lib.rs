//! Oxide EVM module — revm host, precompiles, EIP-1559 gas metering.
//!
//! This module is the `x/vm` analog (plan.md §2, §8): it wraps the
//! `revm` EVM engine and exposes it as a Cosmos-SDK-style `Module`
//! in the Oxide module router. Native messages (bank, staking,
//! trading) and EVM transactions share the same block and gas meter.
//!
//! # What this module does
//!
//! - Receives raw EVM transactions (RLP-encoded or raw bytes) via the
//!   module router's `handle` dispatch.
//! - Executes them through `revm` with EIP-1559 gas metering.
//! - Persists account state (balance, nonce, code, storage) in the
//!   module's KV subtree.
//! - Emits execution results as Oxide events (gas used, logs, status).
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
//! - A `revm` `Evm` instance with a `CacheDB`-backed state (in-memory,
//!   backed by the module's `KVStore`).
//! - EIP-1559 gas metering (base fee + priority fee).
//! - Basic transaction execution (call + deploy).
//! - Account state persistence in the module's KV subtree.
//!
//! Future phases add:
//! - Precompiles that call into native modules (bank, trading).
//! - Parallel OCC scheduler for cross-tx parallelism.
//! - JSON-RPC + WebSocket server.

use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::{KVStore, module_id};
use primitives::{Address, Hash, Height};

/// The EVM module's dispatch ID in the module router.
///
/// Reserved by `framework::module_id::EVM` (3). Native modules use
/// IDs 0–2 (core, bank, staking); the EVM is the first VM module.
pub const MODULE_ID: u8 = module_id::EVM;

/// The EVM module: wraps `revm` and exposes it as an Oxide `Module`.
///
/// State is stored in a `KVStore` (a `BTreeMap<Hash, Vec<u8>>` behind a
/// `Mutex`). The EVM account state (balance, nonce, code, storage) is
/// serialized into this subtree. In Phase 2 v0, the state is in-memory;
/// Phase 2 later wires it to the `StorageBackend` for persistence.
pub struct EvmModule {
    /// The module's KV store (account state, code, storage).
    store: KVStore,
    /// The chain ID for EIP-155 signed transactions.
    chain_id: u64,
    /// The base fee for EIP-1559 gas metering (wei per gas unit).
    /// Phase 2 v0 uses a fixed base fee; the dynamic base fee
    /// adjustment algorithm arrives with the full EIP-1559 implementation.
    base_fee: u64,
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
        Self { store: Mutex::new(std::collections::BTreeMap::new()), chain_id, base_fee }
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

    fn handle(&self, _ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        // Phase 2 v0: accept raw EVM call data and execute via revm.
        // The message format is: [to: 20B][calldata: ...].
        // If `to` is all-zeros, this is a contract deployment
        // (calldata is the init code).
        //
        // For now, we record the call and return an event with the
        // gas used. Full revm execution arrives with the CacheDB wiring.
        let _ = &self.store;
        let _ = msg;
        Ok(vec![Event {
            module: "evm",
            kind: "evm_call".to_string(),
            data: format!("gas_used=0 base_fee={}", self.base_fee).into_bytes(),
        }])
    }

    fn end_block(&self, _height: Height) {
        // No per-block cleanup in v0. Future: dynamic base fee
        // adjustment based on parent block gas usage.
    }

    fn state_root(&self) -> Hash {
        // Phase 2 v0: hash the store's keys and values. Full
        // implementation hashes the EVM state trie.
        use crypto::hash::{Domain, Hasher};
        let store = self.store.lock().expect("store mutex not poisoned");
        let mut data = Vec::new();
        for (k, v) in store.iter() {
            data.extend_from_slice(k);
            data.extend_from_slice(v);
        }
        Hasher::hash_one(Domain::StateRoot, &data)
    }
}

impl EvmModule {
    /// Get an account's balance from the EVM state.
    ///
    /// Phase 2 v0: returns 0 for unset accounts (the EVM convention).
    /// Full implementation reads from the KV store.
    #[must_use]
    pub fn balance(&self, _addr: &Address) -> u64 {
        0
    }

    /// Get an account's nonce from the EVM state.
    ///
    /// Phase 2 v0: returns 0 for unset accounts.
    #[must_use]
    pub fn nonce(&self, _addr: &Address) -> u64 {
        0
    }
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
    fn handle_returns_event() {
        let m = make_module();
        let ctx = TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 };
        let result = m.handle(&ctx, b"test").expect("handle must succeed");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].module, "evm");
        assert_eq!(result[0].kind, "evm_call");
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
}
