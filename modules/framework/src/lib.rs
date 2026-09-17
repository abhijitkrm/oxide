//! Oxide module framework — Cosmos-SDK-style module dispatch and routing.
//!
//! The framework provides the shared infrastructure modules use:
//! - The `Module` trait (re-exported from `executor`).
//! - Module dispatch IDs (canonical constants).
//! - A `ModuleRouter` that registers modules and routes messages.
//! - Shared storage prefix conventions.
//!
//! # Phase 1 scope
//!
//! v0 is a minimal router: modules are registered with a dispatch ID,
//! and the router forwards messages. No ABCI-style hooks beyond what
//! the `executor::Module` trait defines. The storage layer is a
//! simple in-memory `BTreeMap` (the real storage backend arrives with
//! the `storage` crate integration).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use executor::{ExecError, Module};
use primitives::{Address, Hash};

/// Canonical module dispatch IDs. These are stable wire constants —
/// changing them is a consensus-breaking change.
pub mod module_id {
    /// The core module: chain parameters, metadata.
    pub const CORE: u8 = 0;
    /// ID 1 was the bank module — removed when the ledger unified
    /// into EVM account balances. The ID stays reserved: reusing it
    /// would silently reinterpret any in-flight v0 envelopes or
    /// historical state keys built for it.
    /// The staking module: delegation, validation, slashing.
    pub const STAKING: u8 = 2;
    /// The EVM module: revm host, precompiles, EIP-1559, and the
    /// native-token ledger (account balances in wei).
    pub const EVM: u8 = 3;
    /// The governance module: parameter changes, market listing.
    pub const GOVERNANCE: u8 = 4;
    /// The exchange module: spot CLOB markets backed by the native
    /// matching engine (`crates/trading`).
    pub const EXCHANGE: u8 = 5;
    /// The perps module: perpetual futures — margin, funding,
    /// liquidations, insurance fund, ADL (plan.md §9.3).
    pub const PERPS: u8 = 6;
    /// The oracle module: median-of-validator-feeds mark price with
    /// EMA smoothing and heartbeat staleness (plan.md §7, §9.3).
    /// The sole authorized writer of perps mark prices at
    /// production wiring.
    pub const ORACLE: u8 = 7;
}

/// Wei per native **base unit** — the fixed conversion at the
/// module/ledger boundary.
///
/// Native modules keep every amount (envelope `fee`, staking
/// delegations, exchange/perps settlement) in `u64` base units —
/// the project's fixed-point convention — while the ledger itself
/// is the EVM account store, which is wei-denominated (`U256`). One
/// base unit is 10⁹ wei (a gwei): fine enough for fee granularity,
/// coarse enough that `u64` spans ~1.8×10¹⁰ tokens of headroom for
/// any single operation. The conversion lives in exactly two places
/// — the [`Balances`] impls — so unit drift is impossible.
pub const WEI_PER_UNIT: u128 = 1_000_000_000;

/// The native-token ledger seam — how modules move value.
///
/// There is exactly one ledger in the system: the EVM account store
/// (the native token is ether-like — balances live on the same
/// 20-byte accounts contracts and EOAs already use). Every module
/// that moves value — staking's bonded pool, exchange settlement,
/// perps margin, the executor's fee charge — goes through this
/// trait rather than a concrete ledger type, so the seam stays
/// replaceable if a second VM with its own account model ever lands.
///
/// The trait deliberately does **not** require `Send`/`Sync`: the
/// in-transaction impl (`JournalBalances`) wraps a `RefCell`-borrowed
/// revm journal and lives only for the duration of one precompile
/// call. Storage sites that share a ledger across threads declare
/// `Arc<dyn Balances + Send + Sync>` themselves — auto-trait removal
/// coerces `&dyn Balances + Send + Sync` down to `&dyn Balances` at
/// call sites.
///
/// All amounts are `u64` **base units** (see [`WEI_PER_UNIT`]).
///
/// Two backends exist:
/// - `EvmModule`'s `Balances` impl — the out-of-transaction path:
///   native-tx `handle` calls, the executor's `charge_fee`, and
///   `end_block` bookkeeping. Mutations write the account cache
///   directly and capture block undo so versioned historical reads
///   stay correct.
/// - `evm::JournalBalances` — the in-transaction path: mutations go
///   through revm's journaled state, so a reverting frame undoes
///   them automatically and a committing frame lands them in the
///   tx's state diff like any EVM balance change.
///
/// Both enforce the same contract: `debit` fails on insufficient
/// funds, `credit` fails on overflow, `transfer` is all-or-nothing,
/// and `mint` creates value (block rewards are inflationary by
/// design — there is no separate issuance module).
pub trait Balances {
    /// The account's balance in base units. Saturates at `u64::MAX`
    /// for the (unreachable in practice) balance above ~1.8×10¹⁰
    /// tokens — callers comparing "has at least X" are unaffected.
    fn balance(&self, addr: &Address) -> u64;
    /// Decrease `addr`'s balance by `amount` base units.
    ///
    /// # Errors
    ///
    /// [`ExecError::ModuleRejected`] if the balance is insufficient.
    fn debit(&self, addr: &Address, amount: u64) -> Result<(), ExecError>;
    /// Increase `addr`'s balance by `amount` base units.
    ///
    /// # Errors
    ///
    /// [`ExecError::ModuleRejected`] if the balance would overflow.
    fn credit(&self, addr: &Address, amount: u64) -> Result<(), ExecError>;
    /// Move `amount` base units `from → to`, all-or-nothing.
    ///
    /// # Errors
    ///
    /// [`ExecError::ModuleRejected`] on insufficient funds or
    /// recipient overflow; on error neither account changes.
    fn transfer(&self, from: &Address, to: &Address, amount: u64) -> Result<(), ExecError>;
    /// Create `amount` base units on `addr` out of thin air —
    /// block-reward issuance. Not a `transfer` from a supply account:
    /// the total supply genuinely grows.
    fn mint(&self, addr: &Address, amount: u64);
}

/// The validator-committee seam — who may perform
/// committee-privileged actions right now.
///
/// Staking implements this; the oracle and perps consume it to gate
/// price feeds and emergency mark/funding overrides without taking a
/// direct dependency on the staking crate. "Active" means in the
/// current validator set *and not jailed*: a jailed validator is by
/// definition suspected of misbehavior and must not keep feeding
/// prices or signing governance actions during its jail period.
pub trait Committee {
    /// `true` if `addr` is an active (non-jailed) validator.
    fn is_active_validator(&self, addr: &Address) -> bool;
    /// Number of currently active validators — the denominator the
    /// oracle uses to size its submission quorum.
    fn active_validator_count(&self) -> usize;
}

/// The mark-price sink seam — where the oracle's aggregated price
/// lands.
///
/// Perps implements this as [`PerpsModule::set_mark_price`], which
/// keeps its own per-update deviation cap and per-block rate limit
/// as a second defensive layer: even if the oracle's median is
/// somehow manipulated past its quorum, the consumer-side circuit
/// breaker still bounds the per-block move.
pub trait MarkSink {
    /// Publish `mark` as the current mark price for `market`.
    ///
    /// # Errors
    ///
    /// [`ExecError::ModuleRejected`] if the consumer rejects the
    /// price (unknown market, deviation cap exceeded, per-block
    /// update budget exhausted).
    fn set_mark_price(&self, market: u8, mark: u64) -> Result<(), ExecError>;
}

/// A minimal in-memory [`Balances`] for tests and tooling.
///
/// This is **not** a chain ledger — it is never registered as a
/// module and does not participate in state roots, undo, or
/// persistence. It exists so module unit tests and sim harnesses can
/// exercise ledger-dependent code paths without standing up a real
/// EVM. On a live node the single ledger is always the EVM account
/// store behind `EvmModule`.
#[derive(Default)]
pub struct MemoryBalances {
    /// `Mutex` because the trait methods take `&self` while callers
    /// hold the impl across threads (`Send + Sync` is satisfied).
    inner: Mutex<BTreeMap<Address, u64>>,
}

impl MemoryBalances {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Balances for MemoryBalances {
    fn balance(&self, addr: &Address) -> u64 {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(addr)
            .copied()
            .unwrap_or(0)
    }

    fn debit(&self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        let mut m = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let bal = m
            .get_mut(addr)
            .ok_or_else(|| ExecError::ModuleRejected(format!("debit: {addr:?} has no account")))?;
        *bal = bal.checked_sub(amount).ok_or_else(|| {
            ExecError::ModuleRejected(format!("debit: {addr:?} balance {bal} < {amount}"))
        })?;
        Ok(())
    }

    fn credit(&self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        let mut m = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let bal = m.entry(*addr).or_insert(0);
        *bal = bal.checked_add(amount).ok_or_else(|| {
            ExecError::ModuleRejected(format!("credit: {addr:?} balance overflows u64"))
        })?;
        Ok(())
    }

    fn transfer(&self, from: &Address, to: &Address, amount: u64) -> Result<(), ExecError> {
        let mut m = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if from == to {
            // Self-transfer: solvency check only — no state change.
            let bal = m.get(from).copied().unwrap_or(0);
            return if bal >= amount {
                Ok(())
            } else {
                Err(ExecError::ModuleRejected(format!(
                    "transfer: {from:?} balance {bal} < {amount}"
                )))
            };
        }
        // Validate both sides before writing either — a transfer is
        // all-or-nothing: a credit overflow must not strand the debit.
        let from_bal = m.get(from).copied().ok_or_else(|| {
            ExecError::ModuleRejected(format!("transfer: {from:?} has no account"))
        })?;
        let new_from = from_bal.checked_sub(amount).ok_or_else(|| {
            ExecError::ModuleRejected(format!("transfer: {from:?} balance {from_bal} < {amount}"))
        })?;
        let to_bal = m.get(to).copied().unwrap_or(0);
        let new_to = to_bal.checked_add(amount).ok_or_else(|| {
            ExecError::ModuleRejected(format!("transfer: {to:?} balance overflows u64"))
        })?;
        m.insert(*from, new_from);
        m.insert(*to, new_to);
        Ok(())
    }

    fn mint(&self, addr: &Address, amount: u64) {
        let mut m = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // `mint` is infallible; saturate on the unreachable u64
        // overflow rather than panic.
        *m.entry(*addr).or_insert(0) = m.get(addr).copied().unwrap_or(0).saturating_add(amount);
    }
}

/// A shared in-memory key-value store for module state.
///
/// Each module owns a subtree keyed by its dispatch ID. The store is
/// behind `Mutex` because `Module::handle` takes `&self` (the executor
/// is single-threaded in the deterministic runtime, but the trait
/// requires `Sync`).
pub type KVStore = Mutex<BTreeMap<Vec<u8>, Vec<u8>>>;

/// A module router: registers modules and provides lookup.
pub struct ModuleRouter {
    modules: BTreeMap<u8, Arc<dyn Module>>,
}

impl ModuleRouter {
    /// Construct an empty router.
    pub fn new() -> Self {
        Self { modules: BTreeMap::new() }
    }

    /// Register a module by its dispatch ID.
    ///
    /// # Panics
    ///
    /// Panics if a module with the same ID is already registered.
    pub fn register(&mut self, module: Arc<dyn Module>) {
        let id = module.id();
        assert!(self.modules.insert(id, module).is_none(), "module {id} already registered");
    }

    /// Look up a module by dispatch ID.
    pub fn get(&self, id: u8) -> Option<&Arc<dyn Module>> {
        self.modules.get(&id)
    }

    /// Iterate all registered modules.
    pub fn modules(&self) -> impl Iterator<Item = &Arc<dyn Module>> {
        self.modules.values()
    }
}

impl Default for ModuleRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute a deterministic state root for a KV subtree by hashing
/// all (key, value) pairs in sorted order.
///
/// # Panics
///
/// Panics if the `KVStore` mutex is poisoned (a thread panicked while
/// holding the lock).
pub fn subtree_root(store: &KVStore) -> Hash {
    use crypto::hash::{Domain, Hasher};
    let mut data = Vec::new();
    let locked = store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    for (k, v) in locked.iter() {
        data.extend_from_slice(k);
        data.extend_from_slice(&(v.len() as u64).to_le_bytes());
        data.extend_from_slice(v);
    }
    Hasher::hash_one(Domain::Block, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use executor::{Event, ExecError};
    use primitives::Height;

    struct DummyModule {
        store: KVStore,
    }

    impl Module for DummyModule {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn id(&self) -> u8 {
            module_id::CORE
        }
        fn begin_block(&self, _h: Height) {}
        fn handle(&self, _ctx: &executor::TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
            self.store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(b"last".to_vec(), msg.to_vec());
            Ok(vec![])
        }
        fn end_block(&self, _h: Height) {}
        fn state_root(&self) -> Hash {
            subtree_root(&self.store)
        }
    }

    #[test]
    fn router_registers_and_looks_up() {
        let mut router = ModuleRouter::new();
        let module = Arc::new(DummyModule { store: Mutex::new(BTreeMap::new()) });
        router.register(module);
        assert!(router.get(module_id::CORE).is_some());
        assert!(router.get(99).is_none());
    }

    #[test]
    fn subtree_root_changes_with_state() {
        let store: KVStore = Mutex::new(BTreeMap::new());
        let root0 = subtree_root(&store);
        store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(b"k".to_vec(), b"v".to_vec());
        let root1 = subtree_root(&store);
        assert_ne!(root0, root1, "state root must change when state changes");
    }
}
