//! Speculative-execution records and the multi-version state layer
//! for the parallel batch path.
//!
//! Split from `lib.rs` around the speculation invariant: each
//! [`SpecTx`] captures everything the canonical-order commit needs
//! to *prove or disprove* the speculation — the exact state values
//! the tx observed ([`ObservedReads`]), the merge payload (the tx's
//! recorded [`EvmState`] diff and `coinbase_delta`), and the flags
//! forcing canonical re-execution.
//!
//! # The multi-version layer
//!
//! [`MvState`] is the Block-STM-flavored shared store all workers
//! speculate against: every tx publishes its writes under its
//! canonical batch index as it finishes, and a reader at index `i`
//! resolves each key to the newest published version with index
//! `< i`, falling back to the pre-block base state. Speculation
//! therefore *sees the canonical write prefix* instead of only
//! same-sender writes — dependent transactions (`A` funds `B`, `B`
//! spends; a swap reading the previous swap's reserves) usually
//! validate on their first execution instead of re-executing.
//!
//! Reads are racy by design — a writer may publish after the
//! reader resolved — so correctness lives in [`SpecTx::observed`]:
//! every value the tx could have seen is recorded, and the
//! canonical-order commit re-validates each observation against
//! the committed state. `MvDb` is the `DatabaseRef` adapter that
//! performs the versioned resolution and recording; `SharedCacheDB`
//! remains as the `Arc`-shared pre-block base it falls back to.
//! [`CoinbaseObs`] isolates the fee-recipient's non-additive
//! interactions, the only coinbase writes that can invalidate a
//! speculation.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use revm::bytecode::Bytecode;
use revm::database::CacheDB;
use revm::database::state::AccountInfo;
use revm::database_interface::{DatabaseRef, EmptyDB};
use revm::primitives::{Address, B256, U256};

use crate::TracedResult;
use executor::ExecError;

/// A shared reference to a `CacheDB<EmptyDB>` for copy-on-write
/// nested caches.
///
/// This wrapper implements [`DatabaseRef`] by delegating to the
/// inner `CacheDB`. Under the multi-version executor it is the
/// immutable **base state**: every worker's `CacheDB<MvDb>` resolves
/// a key first against the version store, then against this shared
/// parent — which by definition holds the pre-block value for every
/// key no earlier tx published.
///
/// # Why not `CacheDB::nest()`?
///
/// `nest()` consumes `self`, so it can only create one nested
/// cache. We need N nested caches (one per worker) sharing the
/// same parent. `SharedCacheDB(Arc<...>)` lets us share the
/// parent across all workers via cheap `Arc` clones.
///
/// # Error type
///
/// The error type is [`Infallible`] — `EmptyDB` never returns
/// errors, and `CacheDB<EmptyDB>` delegates to it on cache miss.
/// The shared parent is read-only, so no errors can arise from
/// concurrent reads.
#[derive(Debug, Clone)]
pub(crate) struct SharedCacheDB(pub(crate) Arc<CacheDB<EmptyDB>>);

impl DatabaseRef for SharedCacheDB {
    type Error = std::convert::Infallible;

    #[inline]
    fn basic_ref(
        &self,
        address: Address,
    ) -> Result<Option<revm::database::state::AccountInfo>, Self::Error> {
        self.0.basic_ref(address)
    }

    #[inline]
    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.0.code_by_hash_ref(code_hash)
    }

    #[inline]
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.0.storage_ref(address, index)
    }

    #[inline]
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.0.block_hash_ref(number)
    }
}

/// The comparison key for an account-info observation or version:
/// `(balance, nonce, code_hash)` — the consensus-visible fields of
/// `AccountInfo`.
///
/// `code` is deliberately absent: bytecode is content-addressed by
/// `code_hash`, so hash equality already proves code equality.
/// `account_id` is a revm-internal journal marker with no consensus
/// meaning.
pub(crate) type InfoKey = (U256, u64, B256);

/// Extract the comparison key from an `AccountInfo`.
pub(crate) fn info_key(info: &AccountInfo) -> InfoKey {
    (info.balance, info.nonce, info.code_hash)
}

/// Every state value a speculative transaction observed, recorded by
/// [`MvDb`] at resolution time.
///
/// Validation in the commit phase compares each entry against the
/// canonical state at the tx's index position: if every observed
/// value equals the canonical value, the speculation ran on identical
/// inputs and its result is valid by revm determinism — no write-set
/// intersection bookkeeping required. This is strictly more precise
/// than the old registry check: a tx that *did* observe an earlier
/// tx's published write (the version it read is the canonical one)
/// validates, where a read/write-set overlap forced re-execution.
#[derive(Debug, Default)]
pub(crate) struct ObservedReads {
    /// Each account's `basic` resolution: `Some(info)` for a present
    /// account, `None` for an observed absence — an absent observation
    /// is still load-bearing (an earlier tx may have created it).
    /// The coinbase is excluded: it is written by every tx's tip and
    /// tracked through [`CoinbaseObs`]/`coinbase_delta` instead.
    pub(crate) accounts: HashMap<Address, Option<InfoKey>>,
    /// Each `(address, slot)` storage resolution. Every `SLOAD` —
    /// including the implicit pre-`SSTORE` load the journal performs —
    /// resolves through `MvDb`, so this is the exact slot read set.
    pub(crate) slots: HashMap<(Address, U256), U256>,
}

/// The multi-version state shared by all speculative workers in a
/// batch — one `BTreeMap` of versions per written key, keyed by the
/// writer's canonical batch index.
///
/// A reader at index `i` resolves `key` via
/// `versions[key].range(..i).next_back()`: the newest write by a
/// canonically-earlier tx. Versions publish once per tx (at the end
/// of its speculative run) under a single lock acquisition, so the
/// map is write-light and read-mostly — an `RwLock`, not a `Mutex`:
/// reads dominate by roughly the read:write ratio of the batch, and
/// a `Mutex` would serialise every worker's every miss onto one
/// queue, throwing away the parallelism the scheme exists to buy.
///
/// Correctness never depends on a version *existing* — a missing or
/// stale version just produces a speculation whose recorded
/// observations fail the canonical-value check and re-execute. The
/// map is an optimistic filter, not a source of truth: the canonical
/// merge in the commit phase is the sole arbiter.
#[derive(Debug, Default)]
pub(crate) struct MvState {
    inner: RwLock<MvMaps>,
}

#[derive(Debug, Default)]
struct MvMaps {
    /// `address -> (writer index -> post-tx account info)`.
    accounts: HashMap<Address, BTreeMap<usize, AccountInfo>>,
    /// `(address, slot) -> (writer index -> post-tx present value)`.
    slots: HashMap<(Address, U256), BTreeMap<usize, U256>>,
    /// Code deployed by earlier txs, content-addressed. Inserted with
    /// the publishing account's info under the same lock acquisition
    /// so a reader that resolves the new `code_hash` always finds the
    /// code.
    code: HashMap<B256, Bytecode>,
}

impl MvState {
    /// The newest account-info version written by a tx with index
    /// `< idx`, or `None` if no earlier tx published one.
    fn account_at(&self, idx: usize, addr: Address) -> Option<AccountInfo> {
        framework::read_state(&self.inner)
            .accounts
            .get(&addr)?
            .range(..idx)
            .next_back()
            .map(|(_, info)| info.clone())
    }

    /// The newest storage version at `(addr, slot)` written by a tx
    /// with index `< idx`, or `None`.
    fn slot_at(&self, idx: usize, key: (Address, U256)) -> Option<U256> {
        framework::read_state(&self.inner)
            .slots
            .get(&key)?
            .range(..idx)
            .next_back()
            .map(|(_, v)| *v)
    }

    /// Code published by an earlier tx, by hash.
    fn code_at(&self, hash: B256) -> Option<Bytecode> {
        framework::read_state(&self.inner).code.get(&hash).cloned()
    }

    /// Publish a finished speculation's writes under its canonical
    /// index.
    ///
    /// Every touched account's post-tx info becomes a version —
    /// including state-neutral touches, whose published info equals
    /// the pre-value (harmless: readers compare values, not
    /// identities). Changed storage publishes its `present_value`;
    /// unchanged entries publish nothing, so same-value `SSTORE`s do
    /// not shadow earlier versions. Deployed code publishes by hash
    /// alongside its account info under the same lock, so the two can
    /// never be observed separately.
    ///
    /// The coinbase is already absent from `state` (stripped at
    /// capture: its delta merges additively), so no tip credit ever
    /// becomes a version — a `BALANCE(coinbase)` observation keeps
    /// resolving to the base value and validates through
    /// `CoinbaseObs` instead.
    pub(crate) fn publish(&self, idx: usize, state: &revm::state::EvmState) {
        let mut inner = framework::write_state(&self.inner);
        for (addr, account) in state {
            if !account.is_touched() {
                continue;
            }
            if let Some(code) = &account.info.code {
                inner.code.entry(account.info.code_hash).or_insert_with(|| code.clone());
            }
            inner.accounts.entry(*addr).or_default().insert(idx, account.info.clone());
            for (slot, entry) in &account.storage {
                if entry.present_value != entry.original_value {
                    inner.slots.entry((*addr, *slot)).or_default().insert(idx, entry.present_value);
                }
            }
        }
    }
}

/// The `DatabaseRef` a speculative worker's `CacheDB` sits on:
/// resolves each read against the multi-version store (newest write
/// by a canonically-earlier tx), falls back to the shared pre-block
/// base, and records the resolved value into [`ObservedReads`].
///
/// # Why recording lives here
///
/// `CacheDB` serves repeat reads from its own cache, so the worker's
/// first read of each key is the only one that reaches this adapter —
/// exactly the pre-tx value the validation phase needs. Reads served
/// from the worker's local cache after its own writes never record,
/// which is correct: a tx cannot be invalidated by its own writes.
///
/// # The coinbase exception
///
/// `basic(coinbase)` resolves straight to the base and records
/// nothing. Every tx credits the coinbase a tip, so its balance can
/// never match a fixed speculative observation — the additive
/// `coinbase_delta` merge and `CoinbaseObs` flags own that lane.
/// Coinbase *storage* reads still record normally: a contract living
/// at the fee-recipient address has ordinary slots whose observation
/// must validate.
pub(crate) struct MvDb<'m> {
    mv: &'m MvState,
    base: SharedCacheDB,
    /// This worker's canonical batch index — the read horizon. Only
    /// versions written by indices `< idx` are visible.
    idx: usize,
    coinbase: Address,
    observed: RefCell<ObservedReads>,
}

impl<'m> MvDb<'m> {
    pub(crate) fn new(mv: &'m MvState, base: SharedCacheDB, idx: usize, coinbase: Address) -> Self {
        Self { mv, base, idx, coinbase, observed: RefCell::new(ObservedReads::default()) }
    }

    /// Take the recorded observations, leaving an empty set. Called
    /// once per tx after execution completes.
    pub(crate) fn take_observed(&mut self) -> ObservedReads {
        std::mem::take(self.observed.get_mut())
    }
}

impl DatabaseRef for MvDb<'_> {
    type Error = std::convert::Infallible;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if address == self.coinbase {
            // Tips make the coinbase balance unobservable-in-advance;
            // the CoinbaseObs machinery validates it separately.
            return self.base.basic_ref(address);
        }
        let value = match self.mv.account_at(self.idx, address) {
            Some(info) => Some(info),
            None => self.base.basic_ref(address)?,
        };
        self.observed.borrow_mut().accounts.insert(address, value.as_ref().map(info_key));
        Ok(value)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Content-addressed: a hit is definitionally the right bytes,
        // so no observation is recorded. A miss means the hash was
        // never published — impossible for a legitimately observed
        // code_hash (publish writes info and code atomically), so a
        // miss resolves to the same empty code the serial path sees.
        match self.mv.code_at(code_hash) {
            Some(code) => Ok(code),
            None => self.base.code_by_hash_ref(code_hash),
        }
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let value = match self.mv.slot_at(self.idx, (address, index)) {
            Some(v) => v,
            None => self.base.storage_ref(address, index)?,
        };
        self.observed.borrow_mut().slots.insert((address, index), value);
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        // Block hashes are block-level constants — never written by a
        // tx in the batch, so no versioning or recording is needed.
        self.base.block_hash_ref(number)
    }
}

/// The speculative outcome of a single transaction, captured for
/// canonical-order validation and merge.
///
/// The parallel executor runs every tx speculatively against the
/// multi-version store, then commits each tx at its canonical index
/// position. A `SpecTx` carries everything needed for both outcomes:
/// the observed state values that prove (or disprove) the
/// speculation, the merge payload (`state`, `coinbase_delta`) for a
/// validated speculation, and the flags that force canonical
/// re-execution.
pub(crate) struct SpecTx {
    /// Original position of the tx in the batch.
    pub(crate) idx: usize,
    /// The tx sender — needed as the re-execution caller and for the
    /// `caller == coinbase` non-additive coinbase check.
    pub(crate) sender: Address,
    /// The speculative execution result and call trace.
    pub(crate) result: TracedResult,
    /// Every state value the tx resolved during execution — the
    /// validity predicate. At commit, each observed value is compared
    /// against the canonical pre-state at this tx's index: all equal
    /// ⇒ the speculation ran on canonical inputs and merges directly.
    /// Any mismatch ⇒ canonical re-execution.
    pub(crate) observed: ObservedReads,
    /// Accounts the tx destroyed or (re)created:
    /// `is_selfdestructed() || is_created_locally()`. Such a write
    /// replaces the account wholesale — including storage semantics
    /// the version map cannot express (e.g. a created-then-destroyed
    /// account's wipe) — so any *access* to a canonically-destructed
    /// account forces re-execution regardless of value equality.
    /// Conservative by design: the rare path stays simple.
    pub(crate) destructive: std::collections::HashSet<Address>,
    /// The merge payload for a validated tx: the transaction's own
    /// `EvmState` — every account the journal loaded, with per-slot
    /// original/present values. The commit phase feeds it through
    /// the same `DatabaseCommit::commit` the serial path uses, so a
    /// validated merge is slot-granular (storage the tx never
    /// touched survives) and create/selfdestruct/zeroing semantics
    /// are identical to sequential execution by construction.
    ///
    /// The coinbase entry is stripped at capture time: its balance
    /// change merges via the additive `coinbase_delta` instead, so
    /// later validators see the canonical running tip total. Fast
    /// paths synthesize equivalent `Account` entries — they only
    /// ever modify `info` (balance, nonce), never storage.
    pub(crate) state: revm::state::EvmState,
    /// The coinbase balance the tx speculated against — always the
    /// pre-block base value under the multi-version scheme (coinbase
    /// versions are never published). Compared against the canonical
    /// running balance at commit when `coinbase.read` is set.
    pub(crate) coinbase_before: U256,
    /// Net coinbase balance change the tx produced. Strictly
    /// additive (tips, plus any transfers to the fee recipient), so
    /// it merges correctly regardless of position.
    pub(crate) coinbase_delta: U256,
    /// How the tx interacted with the block's fee recipient beyond
    /// the strictly additive tip credit — see [`CoinbaseObs`].
    pub(crate) coinbase: CoinbaseObs,
    /// Speculation cannot represent this tx: a mutating native
    /// precompile was suppressed (read-only provider) or a
    /// non-additive coinbase write occurred. The tx must re-execute
    /// against the canonical DB regardless of observed values.
    pub(crate) must_reexec: bool,
    /// `(recipient, value)` when a native fast path executed and its
    /// recipient write is **write-only**: `post = pre + value`, with
    /// the result and gas decided by sender fields and tx bytes alone.
    ///
    /// A stale recipient observation then does not invalidate the
    /// speculation — the commit phase rebases the post-state onto the
    /// canonical balance (`canonical + value`) instead of
    /// re-executing, provided the recipient is still codeless (a
    /// canonical code hash would mean an earlier tx deployed code
    /// and the call semantics changed underfoot). `None` for
    /// revm-executed txs: a contract can `BALANCE`-read the value
    /// into control flow, so no rebase is provable there.
    ///
    /// Same principle as the coinbase lane, one level weaker: the
    /// coinbase delta merges unconditionally (every tx's tip is
    /// protocol-additive), while a transfer recipient rebases only
    /// when its canonical identity still matches the qualification
    /// the fast path checked.
    pub(crate) additive: Option<(Address, U256)>,
}

/// How a speculative transaction interacted with the block's fee
/// recipient beyond the strictly additive tip credit.
///
/// Grouped because the three flags describe one concept — the
/// coinbase is special-cased in conflict detection precisely because
/// every tx writes it, so only *non-additive* interaction can
/// invalidate a speculation.
pub(crate) struct CoinbaseObs {
    /// `BALANCE(coinbase)` executed during speculation — the result
    /// may depend on the canonical running tip total.
    pub(crate) read: bool,
    /// The coinbase account was loaded at all — cheap superset of
    /// `read`, used to gate re-execution once the coinbase has been
    /// non-additively modified (`coinbase_dirty`).
    pub(crate) accessed: bool,
    /// The tx changed the coinbase beyond an additive balance delta
    /// (nonce, storage, creation, or destruction — e.g. sender ==
    /// coinbase, or a contract at the fee-recipient address). Such a
    /// change cannot be merged and dirties the coinbase for every
    /// later accessor.
    pub(crate) nontrivial: bool,
}

impl SpecTx {
    /// A record for a tx that failed before touching state
    /// (`build_tx_env` rejection — intrinsic to the tx bytes, so no
    /// ordering dependency exists).
    pub(crate) fn intrinsic_error(idx: usize, sender: Address, e: ExecError) -> Self {
        Self {
            idx,
            sender,
            result: Err(e),
            observed: ObservedReads::default(),
            destructive: std::collections::HashSet::new(),
            state: revm::state::EvmState::default(),
            coinbase_before: U256::ZERO,
            coinbase_delta: U256::ZERO,
            coinbase: CoinbaseObs { read: false, accessed: false, nontrivial: false },
            must_reexec: false,
            additive: None,
        }
    }
}

/// Accounts a transaction destroyed or (re)created — the conservative
/// re-execution registry.
///
/// `SELFDESTRUCT`/`CREATE` replace an account wholesale in ways the
/// versioned values cannot fully express: a created-then-destroyed
/// account wipes storage without rewriting each slot, so a reader's
/// slot observation can coincide with the canonical value while the
/// *account-level* semantics diverge. Any access (info or slot) to an
/// account in this set therefore forces canonical re-execution —
/// deliberately conservative, matching the pre-multi-version rule.
pub(crate) fn destructive_accounts(
    state: &revm::state::EvmState,
    coinbase: &Address,
) -> std::collections::HashSet<Address> {
    state
        .iter()
        .filter(|(addr, account)| {
            *addr != coinbase && (account.is_selfdestructed() || account.is_created_locally())
        })
        .map(|(addr, _)| *addr)
        .collect()
}

#[cfg(test)]
mod tests {
    //! Unit tests for the multi-version layer — deterministic
    //! mechanism coverage that the end-to-end tests (whose re-execute
    //! counts are scheduling-dependent) cannot pin: the read horizon,
    //! observation recording, the coinbase exclusion, and atomic
    //! code+info publishing.
    use super::*;
    use revm::database::state::AccountInfo;
    use revm::primitives::Bytes;

    /// A fresh shared base with one funded account and one storage
    /// slot — the pre-block state every test worker falls back to.
    fn base_db() -> SharedCacheDB {
        let mut db = CacheDB::new(EmptyDB::new());
        db.insert_account_info(
            Address::from([0x0B; 20]),
            AccountInfo {
                balance: U256::from(7u64),
                nonce: 3,
                code_hash: revm::primitives::KECCAK_EMPTY,
                account_id: None,
                code: None,
            },
        );
        db.insert_account_storage(Address::from([0x0B; 20]), U256::from(5u64), U256::from(50u64))
            .expect("test base storage insert");
        SharedCacheDB(Arc::new(db))
    }

    /// A touched `Account` carrying `info` — the shape `publish`
    /// expects inside an `EvmState`.
    fn touched_account(info: AccountInfo) -> revm::state::Account {
        let mut account = revm::state::Account::default();
        account.info = info;
        account.mark_touch();
        account
    }

    fn bare_info(balance: u64, nonce: u64) -> AccountInfo {
        AccountInfo {
            balance: U256::from(balance),
            nonce,
            code_hash: revm::primitives::KECCAK_EMPTY,
            account_id: None,
            code: None,
        }
    }

    /// A reader at index `i` must see the newest write by a
    /// canonically-earlier tx — and never its own or a later tx's.
    #[test]
    fn mv_versions_resolve_by_read_horizon() {
        let mv = MvState::default();
        let base = base_db();
        let addr = Address::from([0x0A; 20]);

        // Writers at index 1 and 3 publish different infos.
        for (idx, balance) in [(1usize, 100u64), (3, 300)] {
            let mut state = revm::state::EvmState::default();
            state.insert(addr, touched_account(bare_info(balance, 9)));
            mv.publish(idx, &state);
        }

        let at = |idx| {
            MvDb::new(&mv, base.clone(), idx, Address::ZERO)
                .basic_ref(addr)
                .expect("infallible")
                .map(|i| i.balance)
        };
        assert_eq!(at(0), None, "index 0 has no earlier version");
        assert_eq!(at(1), None, "index 1 precedes the first write");
        assert_eq!(at(2), Some(U256::from(100u64)), "index 2 sees idx-1 write");
        assert_eq!(at(3), Some(U256::from(100u64)), "index 3 still sees idx-1");
        assert_eq!(at(4), Some(U256::from(300u64)), "index 4 sees idx-3 write");
        assert_eq!(at(9), Some(U256::from(300u64)), "later indices see the newest");
    }

    /// Every resolution lands in the observation record with the
    /// resolved value — including an observed absence.
    #[test]
    fn mvdb_records_what_it_served() {
        let mv = MvState::default();
        let base = base_db();
        let coinbase = Address::from([0xEE; 20]);
        let written = Address::from([0x0A; 20]);
        let base_only = Address::from([0x0B; 20]);
        let missing = Address::from([0x0C; 20]);

        let mut state = revm::state::EvmState::default();
        state.insert(written, touched_account(bare_info(42, 1)));
        mv.publish(0, &state);

        let mut mdb = MvDb::new(&mv, base, 5, coinbase);
        let versioned = mdb.basic_ref(written).expect("infallible").expect("present");
        assert_eq!(versioned.balance, U256::from(42u64));
        let base_val = mdb.basic_ref(base_only).expect("infallible").expect("present");
        assert_eq!(base_val.balance, U256::from(7u64));
        assert!(mdb.basic_ref(missing).expect("infallible").is_none());
        // A storage read resolves base when no version exists.
        assert_eq!(
            mdb.storage_ref(base_only, U256::from(5u64)).expect("infallible"),
            U256::from(50u64)
        );

        let observed = mdb.take_observed();
        assert_eq!(observed.accounts[&written], Some(info_key(&bare_info(42, 1))));
        assert_eq!(observed.accounts[&base_only], Some(info_key(&bare_info(7, 3))));
        assert_eq!(observed.accounts[&missing], None);
        assert_eq!(observed.slots[&(base_only, U256::from(5u64))], U256::from(50u64));
    }

    /// The coinbase resolves straight to base and records nothing —
    /// the additive-delta merge owns that lane.
    #[test]
    fn coinbase_reads_bypass_recording() {
        let mv = MvState::default();
        let base = base_db();
        let coinbase = Address::from([0x0B; 20]); // exists in base

        // Even a published coinbase version must not be served.
        let mut state = revm::state::EvmState::default();
        state.insert(coinbase, touched_account(bare_info(999, 9)));
        // `publish` is only ever called with coinbase-stripped state,
        // but defensively: a version here would be an upstream bug —
        // MvDb must not serve it regardless. Simulate by inserting
        // directly, bypassing `publish`'s implicit contract.
        framework::write_state(&mv.inner)
            .accounts
            .entry(coinbase)
            .or_default()
            .insert(0, bare_info(999, 9));

        let mut mdb = MvDb::new(&mv, base, 5, coinbase);
        let info = mdb.basic_ref(coinbase).expect("infallible").expect("present");
        assert_eq!(info.balance, U256::from(7u64), "coinbase must resolve to base");
        assert!(
            mdb.take_observed().accounts.is_empty(),
            "coinbase observations are never recorded"
        );
    }

    /// Deployed code publishes atomically with its account info, so a
    /// later tx calling a just-created contract resolves both.
    #[test]
    fn code_publishes_with_its_account() {
        let mv = MvState::default();
        let base = base_db();
        let created = Address::from([0x0D; 20]);
        let code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0x2a]));

        let mut info = bare_info(0, 1);
        info.code_hash = code.hash_slow();
        info.code = Some(code.clone());
        let mut state = revm::state::EvmState::default();
        state.insert(created, touched_account(info));
        mv.publish(0, &state);

        let mdb = MvDb::new(&mv, base, 5, Address::ZERO);
        assert_eq!(mdb.code_by_hash_ref(code.hash_slow()).expect("infallible"), code);
    }

    /// A storage version is visible to later indices only.
    #[test]
    fn slot_versions_resolve_by_read_horizon() {
        let mv = MvState::default();
        let base = base_db();
        let addr = Address::from([0x0A; 20]);
        let slot = U256::from(9u64);

        let mut account = touched_account(bare_info(1, 1));
        account.storage.insert(
            slot,
            revm::state::EvmStorageSlot::new_changed(
                U256::ZERO,
                U256::from(7u64),
                revm::state::TransactionId::new(0).expect("tx id 0 exists"),
            ),
        );
        let mut state = revm::state::EvmState::default();
        state.insert(addr, account);
        mv.publish(2, &state);

        let read = |idx| {
            MvDb::new(&mv, base.clone(), idx, Address::ZERO)
                .storage_ref(addr, slot)
                .expect("infallible")
        };
        assert_eq!(read(2), U256::ZERO, "same-index version is invisible");
        assert_eq!(read(1), U256::ZERO, "earlier index sees base (absent slot)");
        assert_eq!(read(3), U256::from(7u64), "later index sees the write");
    }
}
