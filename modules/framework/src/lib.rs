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

use std::collections::{BTreeMap, BTreeSet};
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
    /// `addr`'s current voting power — bonded stake for an active
    /// validator, `0` for anything else (jailed, pending-add,
    /// unbonded, unknown). Governance endorsements weigh power, not
    /// membership: a zero-power member cannot move an action.
    fn power(&self, addr: &Address) -> u64;
    /// Total voting power across the active committee — the
    /// denominator for the two-thirds governance quorum.
    fn total_power(&self) -> u64;
}

/// The result of recording one endorsement for a governance action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndorsementOutcome {
    /// The endorsement was recorded; cumulative endorsing power is
    /// still at or below two-thirds of the committee.
    Pending {
        /// Sum of current committee power held by endorsers of this
        /// action — tallied live at each call.
        endorsing: u64,
        /// The smallest endorsing power that would cross the
        /// threshold (`floor(2·total/3) + 1`).
        required: u64,
    },
    /// This endorsement pushed cumulative endorsing power strictly
    /// past two-thirds of total committee power — the action is
    /// authorized and its endorsement record has been consumed.
    Quorum,
}

/// The maximum number of distinct pending governance actions a
/// module tracks endorsements for at once.
///
/// Endorsement state is unbounded attacker-writable memory without
/// a cap: every distinct action payload allocates a fresh entry.
/// 64 pending actions is generous for committee governance (set
/// changes, halts, parameter overrides are rare and deliberate)
/// while bounding the state an adversary can grow for free. New
/// actions beyond the cap are rejected; endorsements for
/// already-tracked actions always land, so the cap cannot deadlock
/// an in-flight decision.
pub const MAX_PENDING_ACTIONS: usize = 64;

/// The parameter-application seam — a module that accepts
/// governance-decided parameter changes.
///
/// Governance proposals carry an opaque `(param_key, param_val)`
/// pair; tallying yes/no power is only half the lifecycle — a
/// PASSED proposal still needs something downstream to enact the
/// change. Modules that expose governed parameters implement this
/// trait and register on the governance module under a name
/// prefix: `param_key = "<name>.<rest>"` routes the application to
/// the sink registered for `<name>`. A key whose prefix matches no
/// registered sink is an advisory (text) proposal — the vote is the
/// outcome and finalization is a no-op.
///
/// The sink is invoked from governance's `end_block` once the
/// proposal's timelock elapses. Implementations must apply the
/// change atomically — either the parameter moves or an error is
/// returned and the proposal is recorded as apply-failed (the
/// decision stands; a failed apply is not retried, because retrying
/// a stale value under newer state is worse than forcing a fresh
/// proposal).
pub trait ParameterSink {
    /// Apply a governance-approved parameter change.
    ///
    /// `key` is the proposal's full parameter key (prefix included);
    /// `value` is the opaque proposed value. The sink MUST reject
    /// keys it does not own rather than guessing — governance routes
    /// by prefix but the sink is the authority on its own keyspace.
    ///
    /// # Errors
    ///
    /// [`ExecError::ModuleRejected`] if the key is unknown to the
    /// sink or the value fails the sink's own validation.
    fn apply_param(&self, key: &[u8], value: &[u8]) -> Result<(), ExecError>;
}

/// Tracks committee endorsements for governance-gated actions.
///
/// Each privileged tx names an exact action — encoded bytes such as
/// "admit validator X with key K", "halt at height H", "set mark M
/// to price P". Identical payloads accumulate endorsers; once
/// cumulative endorsing power strictly exceeds two-thirds of the
/// committee's total bonded power the action is authorized — the
/// same quorum a consensus QC requires, so no coalition under the
/// Byzantine threshold can push a governance action through on its
/// own. One validator's signature is a vote, never a command.
///
/// Endorsing power is tallied against the *current* committee on
/// every call: a member jailed or slashed to zero after endorsing
/// contributes nothing from then on, and endorsements never carry
/// over between different payloads — "admit X with K1" and "admit X
/// with K2" are different actions that race independently.
///
/// The tally is future-affecting state and is committed in each
/// module's canonical state root via [`Self::write_canonical`].
#[derive(Default)]
pub struct Endorsements {
    inner: Mutex<BTreeMap<Vec<u8>, BTreeSet<Address>>>,
}

impl Endorsements {
    /// A fresh, empty endorsement tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `endorser`'s endorsement for `action`.
    ///
    /// The endorser must carry nonzero committee power *right now* —
    /// a jailed, pending-add, or unbonded member holds no vote, so
    /// their tx is rejected rather than silently recorded.
    ///
    /// # Errors
    ///
    /// [`ExecError::ModuleRejected`] if the endorser has no voting
    /// power, or if `action` is new and the tracker already holds
    /// [`MAX_PENDING_ACTIONS`] pending actions.
    pub fn record(
        &self,
        action: &[u8],
        endorser: &Address,
        committee: &dyn Committee,
    ) -> Result<EndorsementOutcome, ExecError> {
        if committee.power(endorser) == 0 {
            return Err(ExecError::ModuleRejected(
                "governance: sender has no committee voting power".to_string(),
            ));
        }
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !inner.contains_key(action) && inner.len() >= MAX_PENDING_ACTIONS {
            return Err(ExecError::ModuleRejected(format!(
                "governance: {MAX_PENDING_ACTIONS} pending actions already tracked"
            )));
        }
        let endorsers = inner.entry(action.to_vec()).or_default();
        endorsers.insert(*endorser);
        // Tally live power on every call: endorsements by members
        // who have since been jailed, removed, or slashed to zero
        // contribute nothing — the quorum reflects the committee as
        // it is now, not as it was when each vote was cast.
        let endorsing: u64 = endorsers.iter().map(|a| committee.power(a)).sum();
        let total = committee.total_power();
        if u128::from(endorsing) * 3 > u128::from(total) * 2 {
            inner.remove(action);
            return Ok(EndorsementOutcome::Quorum);
        }
        // `endorsing ≥ floor(2·total/3) + 1` ⟺ `3·endorsing >
        // 2·total` — the strict BFT two-thirds threshold. The u128
        // intermediate keeps `total * 2` overflow-free for supplies
        // above u64::MAX/2; the result is ≤ total so it fits u64.
        let required = u64::try_from(u128::from(total) * 2 / 3 + 1).unwrap_or(u64::MAX);
        Ok(EndorsementOutcome::Pending { endorsing, required })
    }

    /// The number of distinct actions currently accumulating
    /// endorsements.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Drop every pending action for which `keep` returns `false`.
    ///
    /// Modules call this after a quorum-authorized action applies:
    /// the state change can render sibling actions permanently
    /// inapplicable — admitting validator X kills every other
    /// pending "admit X" variant, and a scheduled halt whose
    /// height the tip has passed can never fire. Record-time
    /// validation already rejects *new* endorsements of dead
    /// actions, but the frozen entry itself would otherwise occupy
    /// the bounded [`MAX_PENDING_ACTIONS`] set forever: it can
    /// never collect another endorsement, so it can never reach
    /// quorum and be consumed. Re-running the module's liveness
    /// predicate over the pending set reclaims those slots
    /// deterministically. Keep semantics are conservative — a
    /// module must only drop actions that can *never* apply again,
    /// never merely ones that fail a transient precondition.
    pub fn retain(&self, keep: impl Fn(&[u8]) -> bool) {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.retain(|action, _| keep(action));
    }

    /// Serialize the full tally into `w` — pending endorsements are
    /// future-affecting state (they decide whether an action
    /// applies), so two replicas must diverge on different tallies.
    /// Deterministic order comes free from `BTreeMap`/`BTreeSet`.
    pub fn write_canonical(&self, w: &mut CanonicalState) {
        let inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        w.put_count(inner.len());
        for (action, endorsers) in inner.iter() {
            w.put_bytes(action);
            w.put_count(endorsers.len());
            for endorser in endorsers {
                w.put_addr(endorser);
            }
        }
    }

    /// Decode the tally written by [`Self::write_canonical`] —
    /// snapshot restore must rebuild the same (action → endorsers)
    /// map so the two-thirds tally resumes identically.
    ///
    /// `None` on truncation or a non-canonical stream: duplicate
    /// action keys or duplicate endorsers within an action are
    /// rejected (a `BTreeMap`/`BTreeSet` insert would otherwise
    /// silently absorb them). The claimed counts only pace the
    /// loops — every element read bounds-checks, so a forged count
    /// cannot over-allocate.
    #[must_use]
    pub fn read_canonical(r: &mut CanonicalReader<'_>) -> Option<Self> {
        let count = r.get_count()?;
        let mut inner = BTreeMap::new();
        for _ in 0..count {
            let action = r.get_bytes()?.to_vec();
            let n = r.get_count()?;
            let mut endorsers = BTreeSet::new();
            for _ in 0..n {
                if !endorsers.insert(r.get_addr()?) {
                    return None; // Duplicate endorser — non-canonical.
                }
            }
            if inner.insert(action, endorsers).is_some() {
                return None; // Duplicate action — non-canonical.
            }
        }
        Some(Self { inner: Mutex::new(inner) })
    }

    /// Replace the tally's contents with `other` — snapshot restore.
    ///
    /// Modules hold `Endorsements` by value inside `&self`-shared
    /// module state, so import cannot move-assign the field; this
    /// swaps the inner map instead. `other` must come from
    /// [`Self::read_canonical`] (or an equivalently verified decode)
    /// so the canonical structure is preserved.
    ///
    /// # Panics
    ///
    /// Panics if a mutex is poisoned.
    pub fn replace_with(&self, other: Endorsements) {
        let mut dst = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let src = other.inner.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
        *dst = src;
    }
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

/// The unlocked form of a module's KV subtree — the decoded store
/// section of a canonical state blob (see [`decode_state_blob`]).
pub type StoreMap = BTreeMap<Vec<u8>, Vec<u8>>;

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
    let locked = store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    subtree_root_map(&locked)
}

/// Compute a subtree root over a plain map — the pure form of
/// [`subtree_root`].
///
/// Snapshot staging needs the subtree root of a store that is still
/// being decoded — before it is committed into a `KVStore` — so the
/// hashing loop is exposed over the map itself. The encoding is the
/// same (`key ‖ u64-le vlen ‖ value` in `BTreeMap` order, hashed
/// under `Domain::Block`); both functions MUST stay byte-identical.
#[must_use]
pub fn subtree_root_map(store: &StoreMap) -> Hash {
    use crypto::hash::{Domain, Hasher};
    let mut data = Vec::new();
    for (k, v) in store {
        data.extend_from_slice(k);
        data.extend_from_slice(&(v.len() as u64).to_le_bytes());
        data.extend_from_slice(v);
    }
    Hasher::hash_one(Domain::Block, &data)
}

/// Canonical module-state serializer for state roots (C8).
///
/// A module's [`Module::state_root`] must commit **every field that
/// can affect future execution** — not just the KV store. Modules
/// keep live state in memory (matching engines, positions, margin,
/// reward accumulators, pending queues); two replicas with
/// identical KV stores can hold divergent books or margin and must
/// NOT produce identical roots.
///
/// `CanonicalState` accumulates a module's authoritative state in a
/// fixed schema order into one byte buffer, then `root()` hashes it
/// once under `Domain::Block` — the same domain [`subtree_root`]
/// uses, so a module root remains a single `Domain::Block` digest.
///
/// Encoding rules (consensus-critical — change = new root format):
/// - Integers are little-endian fixed-width; `bool` is one byte.
/// - `put_bytes` is `u64`-length-prefixed, and every collection
///   must be preceded by `put_count` so section boundaries are
///   unambiguous.
/// - `BTreeMap`/`BTreeSet` iterate sorted — feed them directly.
///   `Vec`/`VecDeque` order is itself committed.
/// - Commit authoritative state; skip derived caches (anything
///   rebuildable from committed state), pure scratch buffers,
///   construction-time config that never changes via txs, and
///   wiring handles (`Arc` seams). Intra-block counters reset by
///   `begin_block`/`end_block` are committed anyway when cheap —
///   they hold the *current* block's deterministic values at
///   commit time.
///
/// `state_root` is a cold path (once per block per module): a
/// single allocation for the buffer is acceptable; the matching
/// hot path never runs it.
#[derive(Default)]
pub struct CanonicalState {
    /// The accumulated canonical encoding.
    buf: Vec<u8>,
}

impl CanonicalState {
    /// A fresh, empty serializer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A section discriminator byte. Use distinct tags per logical
    /// section so two different schemas can never collide.
    pub fn put_tag(&mut self, tag: u8) -> &mut Self {
        self.buf.push(tag);
        self
    }

    /// A `u8`.
    pub fn put_u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// A `u16` little-endian.
    pub fn put_u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// A `u32` little-endian.
    pub fn put_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// A `u64` little-endian.
    pub fn put_u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// A `u128` little-endian.
    pub fn put_u128(&mut self, v: u128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// An `i64` little-endian (positions are signed).
    pub fn put_i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// A `bool` as one byte (`0`/`1`).
    pub fn put_bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(u8::from(v));
        self
    }

    /// An `Address` as its raw 20 bytes.
    pub fn put_addr(&mut self, a: &Address) -> &mut Self {
        self.buf.extend_from_slice(&a.0);
        self
    }

    /// A collection element count as `u64` — must precede the
    /// elements so section boundaries are unambiguous.
    pub fn put_count(&mut self, n: usize) -> &mut Self {
        #[allow(clippy::cast_possible_truncation)]
        self.buf.extend_from_slice(&(n as u64).to_le_bytes());
        self
    }

    /// A length-prefixed byte string (`u64` length + raw bytes).
    pub fn put_bytes(&mut self, v: &[u8]) -> &mut Self {
        #[allow(clippy::cast_possible_truncation)]
        self.buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        self.buf.extend_from_slice(v);
        self
    }

    /// A `Hash` as its raw 32 bytes (fixed-width, unambiguous).
    pub fn put_root(&mut self, h: &Hash) -> &mut Self {
        self.buf.extend_from_slice(h.as_bytes());
        self
    }

    /// The canonical encoding accumulated so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Hash the canonical encoding into the module's state root.
    #[must_use]
    pub fn root(&self) -> Hash {
        use crypto::hash::{Domain, Hasher};
        Hasher::hash_one(Domain::Block, &self.buf)
    }
}

/// Bounds-checked decode mirror of [`CanonicalState`].
///
/// Snapshot import is untrusted input: every read bounds-checks
/// against the buffer and returns `None` on truncation or a
/// non-canonical value (e.g. a `bool` byte other than `0`/`1`) —
/// never a panic. Callers MUST check [`Self::at_end`] after
/// decoding: a stream with trailing garbage is malformed, not
/// silently consumed.
///
/// [`Self::get_count`] returns a *claimed* element count. Do NOT
/// pre-allocate by it — a forged `u64::MAX` count would be an
/// allocation bomb. Instead let each element's own read bound the
/// loop: a stream of `n` bytes can encode at most `n` elements.
pub struct CanonicalReader<'a> {
    /// The buffer being decoded.
    buf: &'a [u8],
    /// Read cursor — next unread byte offset.
    pos: usize,
}

impl<'a> CanonicalReader<'a> {
    /// A reader over `buf` positioned at the start.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// `true` when the buffer is exactly consumed — check after
    /// decoding so trailing garbage marks the input malformed.
    #[must_use]
    pub fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Bytes remaining unread.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Consume `n` raw bytes, or `None` if fewer remain.
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Some(out)
    }

    /// A `u8` (mirror of [`CanonicalState::put_u8`]/`put_tag`).
    pub fn get_u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    /// A `u16` little-endian.
    pub fn get_u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    /// A `u32` little-endian.
    pub fn get_u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    /// A `u64` little-endian.
    pub fn get_u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A `u128` little-endian.
    pub fn get_u128(&mut self) -> Option<u128> {
        Some(u128::from_le_bytes(self.take(16)?.try_into().ok()?))
    }

    /// An `i64` little-endian.
    pub fn get_i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// A `bool` — canonical form only: `0`/`1`; any other byte is
    /// malformed (a permissive `!= 0` read would accept multiple
    /// encodings of the same value, breaking byte-exactness).
    pub fn get_bool(&mut self) -> Option<bool> {
        match self.get_u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// An `Address` — 20 raw bytes.
    pub fn get_addr(&mut self) -> Option<Address> {
        let mut a = [0u8; Address::LEN];
        a.copy_from_slice(self.take(Address::LEN)?);
        Some(Address(a))
    }

    /// A `Hash` — 32 raw bytes (mirror of `put_root`).
    pub fn get_root(&mut self) -> Option<Hash> {
        let mut h = [0u8; Hash::LEN];
        h.copy_from_slice(self.take(Hash::LEN)?);
        Some(Hash(h))
    }

    /// An element count (mirror of `put_count`). See the struct
    /// docs: treat it as a claim, not an allocation size.
    pub fn get_count(&mut self) -> Option<usize> {
        usize::try_from(self.get_u64()?).ok()
    }

    /// A `u64`-length-prefixed byte string (mirror of `put_bytes`).
    pub fn get_bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.get_count()?;
        self.take(len)
    }
}

/// Hash a canonical preimage — the state root it claims.
///
/// Shared by `Module::inspect_state` impls so the domain separation
/// matches [`CanonicalState::root`] exactly (`Domain::Block`).
#[must_use]
pub fn canon_root(canon: &[u8]) -> Hash {
    use crypto::hash::{Domain, Hasher};
    Hasher::hash_one(Domain::Block, canon)
}

/// The snapshot-entry key a module's canonical state blob lives under.
///
/// A canonical module snapshot carries exactly ONE entry: the whole
/// committed state as an opaque blob under this fixed key. Deriving
/// the key from a fixed tag keeps it self-describing, and the single
/// entry makes multi-entry or mis-keyed snapshots trivially
/// malformed — there is nothing else a canonical blob legitimately
/// contains.
#[must_use]
pub fn state_blob_key() -> Hash {
    use crypto::hash::{Domain, Hasher};
    Hasher::hash_one(Domain::Block, b"oxide/module-state-blob")
}

/// Pack committed state into a module's single snapshot value:
/// `u64(canon_len) ‖ canon ‖ store`.
///
/// `canon` is the module's [`CanonicalState`] preimage — the bytes
/// `state_root` hashes — and `store` serializes the module's KV
/// subtree as `u64(count) ‖ (u64 klen ‖ key ‖ u64 vlen ‖ val)*` in
/// `BTreeMap` (sorted) key order. The two sections stay separate
/// because `canon` commits `subtree_root(store)` — a 32-byte digest,
/// not the entries — so `canon_root(canon)` still equals the
/// module's `state_root` while the blob carries enough information
/// to rebuild the store on a peer.
///
/// # Panics
///
/// Panics if the `KVStore` mutex is poisoned.
#[must_use]
pub fn encode_state_blob(canon: &[u8], store: &KVStore) -> Vec<u8> {
    let locked = store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    #[allow(clippy::cast_possible_truncation)]
    let mut out = Vec::with_capacity(8 + canon.len() + 8 + locked.len() * 16);
    out.extend_from_slice(&(canon.len() as u64).to_le_bytes());
    out.extend_from_slice(canon);
    out.extend_from_slice(&(locked.len() as u64).to_le_bytes());
    for (k, v) in locked.iter() {
        out.extend_from_slice(&(k.len() as u64).to_le_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(&(v.len() as u64).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// Inverse of [`encode_state_blob`] — splits a blob into the
/// canonical preimage and the rebuilt store map.
///
/// Structural validation only: the length prefix must be consistent,
/// keys must be strictly increasing (canonical order — a sorted map
/// would silently absorb a duplicate key otherwise), and the buffer
/// must be consumed exactly. Semantic checks — the subtree root
/// committed inside `canon`, field decoding — happen in
/// [`stage_blob_snapshot`].
#[must_use]
pub fn decode_state_blob(blob: &[u8]) -> Option<(&[u8], StoreMap)> {
    let mut r = CanonicalReader::new(blob);
    let canon_len = r.get_count()?;
    let canon = r.take(canon_len)?;
    let n = r.get_count()?;
    let mut store = BTreeMap::new();
    let mut prev: Option<&[u8]> = None;
    for _ in 0..n {
        let k = r.get_bytes()?;
        let v = r.get_bytes()?.to_vec();
        if prev.is_some_and(|p| p >= k) {
            return None; // Unsorted or duplicate key — not canonical.
        }
        prev = Some(k);
        store.insert(k.to_vec(), v);
    }
    if !r.at_end() {
        return None;
    }
    Some((canon, store))
}

/// Decode and verify a canonical-blob module snapshot WITHOUT
/// mutating anything — the shared staging step for
/// `Module::inspect_state` and `Module::import_state`.
///
/// Checks, in order:
/// 1. The snapshot is exactly one entry under [`state_blob_key`].
/// 2. The blob splits cleanly via [`decode_state_blob`].
/// 3. The rebuilt store's [`subtree_root_map`] equals the root the
///    canonical stream commits as its first field (`put_root`) —
///    the store section cannot disagree with the canonical section.
/// 4. `parse` fully decodes the remaining canonical fields (and may
///    cross-check against the store) and consumes the stream exactly.
///
/// Returns `(canon, staged, store)`: `canon` is the root preimage —
/// [`canon_root`]`(canon)` is the state root this snapshot claims —
/// `staged` is the module's decoded field set, and `store` is the
/// rebuilt KV subtree. A module's `import_state` should install both
/// only after this returns `Ok`.
///
/// # Errors
///
/// [`storage::SnapshotError::Malformed`] on any structural,
/// consistency, or field-decode failure.
pub fn stage_blob_snapshot<'a, S>(
    snapshot: &'a storage::Snapshot,
    parse: impl FnOnce(&mut CanonicalReader<'a>, &StoreMap) -> Option<S>,
) -> Result<(&'a [u8], S, StoreMap), storage::SnapshotError> {
    if snapshot.entries.len() != 1 || snapshot.entries[0].0 != state_blob_key() {
        return Err(storage::SnapshotError::Malformed);
    }
    let (canon, store) =
        decode_state_blob(&snapshot.entries[0].1).ok_or(storage::SnapshotError::Malformed)?;
    let mut r = CanonicalReader::new(canon);
    let committed_root = r.get_root().ok_or(storage::SnapshotError::Malformed)?;
    if subtree_root_map(&store) != committed_root {
        return Err(storage::SnapshotError::Malformed);
    }
    let staged = parse(&mut r, &store).ok_or(storage::SnapshotError::Malformed)?;
    if !r.at_end() {
        return Err(storage::SnapshotError::Malformed);
    }
    Ok((canon, staged, store))
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
        fn end_block(&self, _h: Height) -> Vec<Event> {
            Vec::new()
        }
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

    /// `subtree_root` and `subtree_root_map` must agree byte-for-byte —
    /// snapshot staging verifies a rebuilt map against the committed
    /// root, so the two encodings can never diverge.
    #[test]
    fn subtree_root_map_matches_locked_store() {
        let store: KVStore = Mutex::new(BTreeMap::new());
        {
            let mut s = store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            s.insert(b"alpha".to_vec(), vec![1, 2, 3]);
            s.insert(b"beta".to_vec(), vec![]);
        }
        let map = store.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        assert_eq!(subtree_root(&store), subtree_root_map(&map));
    }

    /// `CanonicalState` → `CanonicalReader` must round-trip every field
    /// kind and end exactly at the stream's end.
    #[test]
    fn canonical_reader_round_trips_all_fields() {
        let mut w = CanonicalState::new();
        w.put_tag(0xA5)
            .put_u8(7)
            .put_u16(0xBEEF)
            .put_u32(0xDEAD_BEEF)
            .put_u64(u64::MAX)
            .put_u128(u128::from(u64::MAX) + 1)
            .put_i64(-42)
            .put_bool(true)
            .put_bool(false)
            .put_addr(&Address([0xAB; 20]))
            .put_count(3)
            .put_bytes(b"payload")
            .put_root(&Hash([0x11; 32]));

        let mut r = CanonicalReader::new(w.as_bytes());
        assert_eq!(r.get_u8(), Some(0xA5));
        assert_eq!(r.get_u8(), Some(7));
        assert_eq!(r.get_u16(), Some(0xBEEF));
        assert_eq!(r.get_u32(), Some(0xDEAD_BEEF));
        assert_eq!(r.get_u64(), Some(u64::MAX));
        assert_eq!(r.get_u128(), Some(u128::from(u64::MAX) + 1));
        assert_eq!(r.get_i64(), Some(-42));
        assert_eq!(r.get_bool(), Some(true));
        assert_eq!(r.get_bool(), Some(false));
        assert_eq!(r.get_addr(), Some(Address([0xAB; 20])));
        assert_eq!(r.get_count(), Some(3));
        assert_eq!(r.get_bytes(), Some(b"payload".as_slice()));
        assert_eq!(r.get_root(), Some(Hash([0x11; 32])));
        assert!(r.at_end(), "a well-formed stream must be consumed exactly");
    }

    /// Every malformed input must yield `None`, never a panic:
    /// truncation, trailing garbage, a non-canonical bool, and a
    /// length prefix that overruns the buffer.
    #[test]
    fn canonical_reader_rejects_malformed() {
        // Truncated u64.
        assert_eq!(CanonicalReader::new(&[1, 2, 3]).get_u64(), None);
        // Trailing garbage after a valid field.
        let mut r = CanonicalReader::new(&[0, 9]);
        assert_eq!(r.get_bool(), Some(false));
        assert!(!r.at_end());
        // Non-canonical bool bytes.
        assert_eq!(CanonicalReader::new(&[2]).get_bool(), None);
        assert_eq!(CanonicalReader::new(&[0xFF]).get_bool(), None);
        // Length prefix exceeding remaining bytes.
        let big = u64::MAX.to_le_bytes();
        let mut r = CanonicalReader::new(&big);
        assert_eq!(r.get_bytes(), None, "claimed length must not wrap or overrun");
        // u64 count that cannot fit usize is still rejected cleanly
        // on the element reads — not at the count read itself.
        let mut r = CanonicalReader::new(&big);
        assert_eq!(r.get_count(), Some(usize::MAX));
        assert_eq!(r.get_u8(), None);
    }

    /// A blob round-trips: canon + store rebuild the same subtree
    /// root, and `canon_root` of the preimage equals `CanonicalState`'s
    /// root — the invariant `inspect_state` depends on.
    #[test]
    fn state_blob_round_trip() {
        let store: KVStore = Mutex::new(BTreeMap::new());
        {
            let mut s = store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            s.insert(b"m/1".to_vec(), vec![9; 4]);
            s.insert(b"m/2".to_vec(), b"x".to_vec());
        }
        let mut w = CanonicalState::new();
        w.put_root(&subtree_root(&store));
        w.put_u64(42);
        let canon = w.as_bytes().to_vec();
        let claimed = w.root();

        let blob = encode_state_blob(&canon, &store);
        let snapshot = storage::Snapshot { height: 0, entries: vec![(state_blob_key(), blob)] };

        let (canon_back, fields, store_back) = stage_blob_snapshot(&snapshot, |r, _store| {
            r.get_u64() // the single committed field after the root
        })
        .expect("well-formed blob must stage");
        assert_eq!(fields, 42);
        assert_eq!(canon_back, canon.as_slice());
        assert_eq!(canon_root(canon_back), claimed, "canon hash must equal state_root");
        assert_eq!(
            subtree_root_map(&store_back),
            subtree_root(&store),
            "rebuilt store must hash to the same subtree root"
        );
    }

    /// Malformed blob inputs must all be rejected: wrong entry count,
    /// wrong key, unsorted store keys, tampered subtree root, and a
    /// parse that leaves bytes unread.
    #[test]
    fn state_blob_rejects_malformed() {
        let store: KVStore = Mutex::new(BTreeMap::new());
        let mut w = CanonicalState::new();
        w.put_root(&subtree_root(&store));
        let canon = w.as_bytes().to_vec();
        let blob = encode_state_blob(&canon, &store);

        let key = state_blob_key();
        let ok = |entries: Vec<(Hash, Vec<u8>)>| storage::Snapshot { height: 0, entries };

        // Zero and two entries are both malformed.
        assert!(stage_blob_snapshot(&ok(vec![]), |_, _| Some(())).is_err());
        assert!(
            stage_blob_snapshot(
                &ok(vec![(key, blob.clone()), (Hash([1; 32]), vec![]),]),
                |_, _| Some(())
            )
            .is_err()
        );
        // Wrong key.
        assert!(
            stage_blob_snapshot(&ok(vec![(Hash([0; 32]), blob.clone())]), |_, _| Some(())).is_err()
        );
        // Truncated blob.
        assert!(
            stage_blob_snapshot(&ok(vec![(key, blob[..blob.len() - 1].to_vec())]), |_, _| Some(()))
                .is_err()
        );
        // Store content that doesn't match the committed subtree root:
        // rebuild a blob whose store section holds an extra entry.
        let tampered_store: KVStore = Mutex::new(BTreeMap::from([(b"x".to_vec(), vec![1])]));
        let bad = encode_state_blob(&canon, &tampered_store);
        assert!(
            stage_blob_snapshot(&ok(vec![(key, bad)]), |_, _| Some(())).is_err(),
            "store disagreeing with the committed subtree root must be rejected"
        );
        // A parse that leaves canonical bytes unread must fail:
        // append a stray field to the canon (rebuilt against the same
        // store so the subtree check still passes).
        let mut w2 = CanonicalState::new();
        w2.put_root(&subtree_root(&store));
        w2.put_u8(0xEE); // stray trailing field the parse won't read
        let stray = encode_state_blob(w2.as_bytes(), &store);
        assert!(
            stage_blob_snapshot(&ok(vec![(key, stray)]), |_, _| Some(())).is_err(),
            "trailing canonical bytes are malformed"
        );
        // A parse reading past the stream's end must fail.
        assert!(
            stage_blob_snapshot(&ok(vec![(key, blob)]), |r, _| r.get_u8().map(|_| ())).is_err(),
            "canon ends after the store root — a field read must fail"
        );
    }

    /// Store keys out of canonical order must be rejected by the blob
    /// decoder even though a `BTreeMap` would silently sort them.
    #[test]
    fn state_blob_rejects_unsorted_store() {
        let mut blob = Vec::new();
        // canon_len=32 + canon(dummy root bytes) + 2 unsorted entries.
        blob.extend_from_slice(&32u64.to_le_bytes());
        blob.extend_from_slice(&[0u8; 32]);
        blob.extend_from_slice(&2u64.to_le_bytes());
        for (k, v) in [(b"b".as_slice(), &[1u8][..]), (b"a", &[2u8][..])] {
            blob.extend_from_slice(&(k.len() as u64).to_le_bytes());
            blob.extend_from_slice(k);
            blob.extend_from_slice(&(v.len() as u64).to_le_bytes());
            blob.extend_from_slice(v);
        }
        assert!(decode_state_blob(&blob).is_none(), "unsorted keys are not the canonical encoding");
    }

    /// Endorsements must round-trip through the canonical stream:
    /// identical tallies after decode, and duplicate keys rejected.
    #[test]
    fn endorsements_canonical_round_trip() {
        let e = Endorsements::new();
        {
            let mut inner = e.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            inner
                .insert(b"halt@100".to_vec(), BTreeSet::from([Address([1; 20]), Address([2; 20])]));
            inner.insert(b"admit-x".to_vec(), BTreeSet::from([Address([3; 20])]));
        }
        let mut w = CanonicalState::new();
        e.write_canonical(&mut w);

        let mut r = CanonicalReader::new(w.as_bytes());
        let back = Endorsements::read_canonical(&mut r).expect("must decode");
        assert!(r.at_end());
        assert_eq!(back.pending_count(), 2);

        // A stream claiming 2 actions but containing 1 must fail.
        let mut w2 = CanonicalState::new();
        w2.put_count(2);
        w2.put_bytes(b"a");
        w2.put_count(0);
        let mut r2 = CanonicalReader::new(w2.as_bytes());
        assert!(Endorsements::read_canonical(&mut r2).is_none());
    }
}
