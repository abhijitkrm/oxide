//! Versioned state — historical account/storage reads over a bounded
//! undo log.
//!
//! # Why an undo log
//!
//! The authoritative in-memory store (`CacheDB`) holds *latest* state
//! only — durable persistence likewise stores one whole-account value
//! per address (`persist.rs`). Serving `eth_call`/`eth_getBalance`/
//! `eth_getStorageAt`/`eth_getProof` at a *past* height therefore
//! needs a reconstruction mechanism. Two candidate designs:
//!
//! 1. **Height-versioned KV** (Erigon-style MVCC in the backend):
//!    every write is tagged with its block height; reads at `h` seek
//!    the newest entry `≤ h`. Requires the storage engine to retain
//!    all versions — a large, invasive change to the journal layout.
//! 2. **Per-block inverse diff ("undo log")**: at each write site we
//!    record the *pre-write* value of every touched account. State at
//!    height `h` for account `A` is then: the earliest undo entry for
//!    `A` at a height `> h` (which is by definition `A`'s state at the
//!    end of block `h`), or — if no such entry exists — the latest
//!    value (`A` was untouched after `h`).
//!
//! We implement (2): it is purely in-memory, bounded by the same
//! retention window as `history`, and adds zero cost to the durable
//! write path. This matches geth's non-archive behavior window —
//! geth keeps ~128 recent trie states in memory and answers
//! `missing trie node` beyond them; we answer the equivalent
//! "state not available" below the retained floor.
//!
//! # Correctness invariants
//!
//! - `undo[h][A]` holds `A`'s value **before** block `h` executed
//!   (first-write-wins per block: the entry must reflect end-of-block
//!   `h-1`, not mid-block state).
//! - The whole `DbAccount` (info + complete storage map) is captured:
//!   `CacheDB`'s per-account storage map is complete for every cached
//!   account because `load_from_storage` restores the full persisted
//!   slot set, `EmptyDB` never serves slots, and revm `sload`s a slot
//!   before `sstore`ing it — so a map hit/miss is authoritative.
//! - `info.code` is stripped (`None`) in undo entries: bytecode is
//!   immutable per `code_hash` and `cache.contracts` retains every
//!   deployed blob, so `code_by_hash_ref` serves old code forever.
//! - Reads are valid for `h ∈ [floor−1, latest]` where `floor` is the
//!   oldest retained height: any earlier height could miss writes in
//!   `(h, floor)` — the caller must reject those requests.
//!
//! # Cost
//!
//! Memory is `O(Σ touched_accounts_per_block)` over the window —
//! bounded by `history`'s retention. Each `AccountInfo` is ~150 B
//! plus 64 B per storage slot; a 10k-tps block touching ~3 accounts
//! per tx costs ~9 MB/block worst case. Lookups are O(log) per
//! account via the per-address index — no per-read replay.
//!
//! Persisted across restart: `end_block` writes each height's
//! `BlockUndo` under a `0x03` backend key (same batch as the
//! account flush + history record) and `load_from_storage` replays
//! them into this index. Reads below the restored floor still fail
//! closed — the window is only as deep as the retained undo blobs.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use revm::bytecode::Bytecode;
use revm::database::state::AccountInfo;
use revm::database::{CacheDB, DbAccount};
use revm::database_interface::{DatabaseRef, EmptyDB};
use revm::primitives::{Address, B256, U256};

use crate::history::History;

/// The pre-block value of one account, captured before the block's
/// first write to it.
///
/// `info.code` is always `None` — see the module docs; bytecode is
/// resolved by `code_hash` through `cache.contracts`, which retains
/// every deployed blob.
#[derive(Debug, Clone)]
pub struct UndoAccount {
    /// Balance/nonce/`code_hash` as of the end of the previous block.
    pub info: AccountInfo,
    /// The account's complete storage map as of the end of the
    /// previous block (see module docs for the completeness
    /// invariant).
    pub storage: HashMap<U256, U256>,
}

/// Per-block accumulator: the inverse diff for the block currently
/// executing.
///
/// Capture is *first-write-wins* per address — the entry must hold
/// the value as of end-of-block `h-1`; later writes in the same
/// block must not overwrite it.
#[derive(Debug, Default)]
pub struct BlockUndo {
    /// `address → pre-block value`; `None` = the account did not
    /// exist before this block.
    pub accounts: HashMap<Address, Option<UndoAccount>>,
}

impl BlockUndo {
    /// Record `addr`'s pre-write value if it has no entry yet.
    ///
    /// `pre` is the account's value in the `CacheDB` map the write is
    /// about to land in (`None` = not present). Called at every
    /// mutation site *before* the write is applied.
    pub fn capture(&mut self, addr: Address, pre: Option<&DbAccount>) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.accounts.entry(addr) {
            e.insert(pre.map(|a| {
                let mut info = a.info.clone();
                // Code bytes are immutable per `code_hash`; drop the
                // (potentially large) blob — `code_by_hash_ref`
                // resolves it from `cache.contracts`.
                info.code = None;
                UndoAccount { info, storage: a.storage.iter().map(|(k, v)| (*k, *v)).collect() }
            }));
        }
    }
}

/// The bounded undo store: every executed block contributes one
/// [`BlockUndo`], indexed both by height (for pruning) and by
/// account (for O(log) reads).
#[derive(Debug, Default)]
pub struct VersionedState {
    /// `address → (height → pre-block value)`. A lookup for
    /// `(addr, h)` takes the first entry with height `> h`.
    by_account: HashMap<Address, BTreeMap<u64, Option<UndoAccount>>>,
    /// `height → addresses captured`. Drives pruning; every executed
    /// height is present (empty vec for blocks that touched nothing)
    /// so `floor` is the true retained-window lower bound.
    by_height: BTreeMap<u64, Vec<Address>>,
}

impl VersionedState {
    /// Fold a finished block's undo accumulator into the index.
    pub fn push(&mut self, height: u64, undo: BlockUndo) {
        let mut addrs = Vec::with_capacity(undo.accounts.len());
        for (addr, entry) in undo.accounts {
            self.by_account.entry(addr).or_default().insert(height, entry);
            addrs.push(addr);
        }
        self.by_height.insert(height, addrs);
    }

    /// Drop all undo entries for heights `< floor`. Called alongside
    /// `History`'s eviction so the two windows stay aligned.
    ///
    /// Returns the pruned heights — `end_block` deletes the matching
    /// persisted `0x03` blobs so durable storage tracks the window.
    pub fn prune_below(&mut self, floor: u64) -> Vec<u64> {
        let pruned: Vec<(u64, Vec<Address>)> =
            self.by_height.range(..floor).map(|(h, a)| (*h, a.clone())).collect();
        let heights: Vec<u64> = pruned.iter().map(|(h, _)| *h).collect();
        for (height, addrs) in pruned {
            for addr in addrs {
                if let Some(entries) = self.by_account.get_mut(&addr) {
                    entries.remove(&height);
                    if entries.is_empty() {
                        self.by_account.remove(&addr);
                    }
                }
            }
            self.by_height.remove(&height);
        }
        heights
    }

    /// The oldest retained height, or `None` when nothing has been
    /// captured. Reads are valid for `h >= floor - 1` (saturating):
    /// a read at `floor - 1` uses undo entries at `floor..` — the
    /// complete retained range.
    pub fn floor(&self) -> Option<u64> {
        self.by_height.keys().next().copied()
    }

    /// Every address the index knows about — the union with the
    /// latest account map covers accounts deleted since `h` (they
    /// still need trie leaves at `h`).
    pub(crate) fn known_accounts(&self) -> impl Iterator<Item = &Address> {
        self.by_account.keys()
    }

    /// The pre-block value of `addr` for the earliest captured write
    /// strictly above `h` — i.e. `addr`'s state at end of block `h`.
    ///
    /// `None` outer = no captured write above `h`: the account was
    /// untouched in `(h, latest]`, so the *latest* value answers.
    /// `Some(None)` = the account provably did not exist at `h`.
    ///
    /// The nested `Option` is the semantics — allow it.
    #[allow(clippy::option_option)]
    pub(crate) fn entry_at(&self, addr: &Address, h: u64) -> Option<Option<&UndoAccount>> {
        self.by_account
            .get(addr)
            .and_then(|entries| entries.range(h + 1..).next())
            .map(|(_, v)| v.as_ref())
    }
}

/// A read-only view of state as of a past height, backed by the
/// latest `CacheDB` plus the undo index.
///
/// Implements [`DatabaseRef`] so a `CacheDB<StateView>` can host a
/// full revm simulation (`eth_call`, `eth_estimateGas`,
/// `debug_traceCall`, `eth_createAccessList`) at any retained
/// height — identical code path to `latest`, which is simply the
/// case where every undo lookup misses.
///
/// `block_hash_ref` serves `BLOCKHASH` (and `blockHash`-dependent
/// reads) from `History` — the sealed block records carry the
/// Ethereum header hash.
pub struct StateView<'a> {
    /// The latest committed account map.
    db: &'a CacheDB<EmptyDB>,
    /// The undo index.
    undo: &'a VersionedState,
    /// Sealed history for `BLOCKHASH` resolution.
    history: &'a Mutex<History>,
    /// The height this view answers for.
    height: u64,
}

impl<'a> StateView<'a> {
    /// Construct a view at `height` over the given latest-state DB
    /// and undo index.
    pub fn new(
        db: &'a CacheDB<EmptyDB>,
        undo: &'a VersionedState,
        history: &'a Mutex<History>,
        height: u64,
    ) -> Self {
        Self { db, undo, history, height }
    }

    /// The account at the view's height — undo entry if a write
    /// above `h` was captured, else the latest cache value.
    fn account(&self, addr: &Address) -> Option<AccountInfo> {
        match self.undo.entry_at(addr, self.height) {
            Some(entry) => entry.map(|u| u.info.clone()),
            None => self.db.cache.accounts.get(addr).map(|a| a.info.clone()),
        }
    }

    /// `account` for crate-internal callers (the `eth_getProof`
    /// trie build needs info for every account at `h`).
    pub(crate) fn info_at(&self, addr: &Address) -> Option<AccountInfo> {
        self.account(addr)
    }

    /// The account's complete storage map at the view height —
    /// the undo map when a write above `h` was captured, else the
    /// latest map. Cloned: the caller materializes a storage trie.
    ///
    /// `None` when the account is absent at `h`.
    pub(crate) fn storage_map_at(&self, addr: &Address) -> Option<HashMap<U256, U256>> {
        match self.undo.entry_at(addr, self.height) {
            Some(Some(u)) => Some(u.storage.clone()),
            Some(None) => None,
            None => self
                .db
                .cache
                .accounts
                .get(addr)
                .map(|a| a.storage.iter().map(|(k, v)| (*k, *v)).collect()),
        }
    }
}

impl DatabaseRef for StateView<'_> {
    type Error = std::convert::Infallible;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.account(&address))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Bytecode is immutable per hash; the contracts map retains
        // every blob ever deployed, so old code is always servable.
        Ok(self.db.cache.contracts.get(&code_hash).cloned().unwrap_or_default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        match self.undo.entry_at(&address, self.height) {
            Some(Some(u)) => Ok(u.storage.get(&index).copied().unwrap_or_default()),
            // Account provably absent at `h` → every slot is zero.
            Some(None) => Ok(U256::ZERO),
            // Untouched after `h` → latest map is authoritative.
            None => Ok(self
                .db
                .cache
                .accounts
                .get(&address)
                .and_then(|a| a.storage.get(&index))
                .copied()
                .unwrap_or_default()),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let history = framework::lock_state(self.history);
        Ok(history.block(number).map_or(B256::ZERO, |b| b.hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(balance: u64, nonce: u64) -> DbAccount {
        let mut a = DbAccount::default();
        a.info.balance = U256::from(balance);
        a.info.nonce = nonce;
        a.info.code_hash = revm::primitives::KECCAK_EMPTY;
        a
    }

    /// The read semantics of the undo index: an entry at height `b`
    /// answers for reads at `h < b` (it holds end-of-`b-1` state);
    /// reads at `h >= b` fall through to the latest value.
    #[test]
    fn undo_index_serves_pre_write_values() {
        let addr = Address::from([0xAA; 20]);
        let mut db: CacheDB<EmptyDB> = CacheDB::new(EmptyDB::new());
        let history = Mutex::new(History::new(16));
        let mut vs = VersionedState::default();

        // Latest state: balance 200.
        db.cache.accounts.insert(addr, acct(200, 2));

        // Block 10 captured pre-value balance 100 (the write at 10
        // raised it to 200). Block 20 touched nothing.
        let mut undo = BlockUndo::default();
        undo.accounts.insert(addr, {
            let a = acct(100, 1);
            let mut info = a.info.clone();
            info.code = None;
            Some(UndoAccount { info, storage: HashMap::new() })
        });
        vs.push(10, undo);

        // h=9 (pre-block-10): undo answers 100.
        let view = StateView::new(&db, &vs, &history, 9);
        assert_eq!(view.basic_ref(addr).unwrap().unwrap().balance, U256::from(100));
        // h=10 (post-block-10): no entry >10 → latest 200.
        let view = StateView::new(&db, &vs, &history, 10);
        assert_eq!(view.basic_ref(addr).unwrap().unwrap().balance, U256::from(200));
    }

    /// `Some(None)` = the account provably didn't exist at `h`:
    /// `basic_ref` returns `None` and slots read zero.
    #[test]
    fn undo_none_means_nonexistent() {
        let addr = Address::from([0xBB; 20]);
        let mut db: CacheDB<EmptyDB> = CacheDB::new(EmptyDB::new());
        let history = Mutex::new(History::new(16));
        let mut vs = VersionedState::default();
        db.cache.accounts.insert(addr, acct(1, 1));

        let mut undo = BlockUndo::default();
        undo.accounts.insert(addr, None);
        vs.push(5, undo);

        let view = StateView::new(&db, &vs, &history, 4);
        assert!(view.basic_ref(addr).unwrap().is_none());
        assert_eq!(view.storage_ref(addr, U256::from(7)).unwrap(), U256::ZERO);
    }

    /// Pruning below `floor` must drop the per-height index and the
    /// per-account entries, and `floor` must then report the new
    /// minimum.
    #[test]
    fn prune_drops_old_entries() {
        let addr = Address::from([0xCC; 20]);
        let mut vs = VersionedState::default();
        for h in 1..=5u64 {
            let mut undo = BlockUndo::default();
            undo.accounts.insert(addr, None);
            vs.push(h, undo);
        }
        assert_eq!(vs.floor(), Some(1));
        vs.prune_below(4);
        assert_eq!(vs.floor(), Some(4));
        // Entry at height 5 still answers a read at h=4.
        assert!(matches!(vs.entry_at(&addr, 4), Some(None)));
        // h=5+ has no entry above → untouched → latest answers.
        assert!(vs.entry_at(&addr, 5).is_none());
    }

    /// First-write-wins within a block: a second capture must not
    /// overwrite the pre-block value.
    #[test]
    fn capture_is_first_write_wins() {
        let addr = Address::from([0xDD; 20]);
        let mut undo = BlockUndo::default();
        let mut map: revm::primitives::AddressMap<DbAccount> =
            revm::primitives::AddressMap::default();
        map.insert(addr, acct(50, 0));
        undo.capture(addr, map.get(&addr));
        // Later mid-block value must not replace the entry.
        map.insert(addr, acct(60, 1));
        undo.capture(addr, map.get(&addr));
        assert_eq!(undo.accounts[&addr].as_ref().unwrap().info.balance, U256::from(50));
    }
}
