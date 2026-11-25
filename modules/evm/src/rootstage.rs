//! Data carried from the execution stage to the root stage
//! (`docs/root-stage-spec.md`).
//!
//! The execution stage captures everything the state root of block `h`
//! needs as *values* (re-encoded leaves, storage roots, the flush batch,
//! the pending history record), so the next block can mutate the account
//! cache freely while the root stage maintains the Merkle-Patricia
//! structure and seals the block. The root stage applies these strictly in
//! height order on a single thread, so the resulting root is a pure fold
//! over deterministic inputs and equals the synchronous root bit for bit.

use alloy_primitives::B256;
use revm::primitives::Address;

/// One touched account that exists after the block: its trie leaf and,
/// when it has storage, the freshly computed storage root.
#[derive(Debug)]
pub(crate) struct LeafUpsert {
    /// The account address (key of the storage-root cache).
    pub addr: Address,
    /// `keccak256(address)`, the state-trie key.
    pub hashed: B256,
    /// `Some(root)` when the account has non-empty storage (the cache entry to
    /// store); `None` leaves the storage-root cache untouched.
    pub storage_root: Option<B256>,
    /// RLP-encoded `TrieAccount` leaf value.
    pub leaf: Vec<u8>,
}

/// The incremental changes of one block to the state trie leaves.
#[derive(Debug, Default)]
pub(crate) struct PatchDelta {
    /// Accounts to insert or replace.
    pub upserts: Vec<LeafUpsert>,
    /// Accounts to delete (tombstones, EIP-158 empties, selfdestructs).
    pub removals: Vec<(Address, B256)>,
}

impl PatchDelta {
    /// An empty delta sized for `n` touched accounts.
    pub(crate) fn with_capacity(n: usize) -> Self {
        Self { upserts: Vec::with_capacity(n), removals: Vec::new() }
    }

    /// Hashed keys of every account the delta touches (upserts then
    /// removals), the set the sparse walk needs.
    pub(crate) fn touched_keys(&self) -> Vec<B256> {
        self.upserts.iter().map(|u| u.hashed).chain(self.removals.iter().map(|(_, h)| *h)).collect()
    }
}

use crate::EvmModule;
use crate::history::Pending;
use crate::trie::{self, encode_trie_leaf, sparse_walk};
use crate::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
use primitives::Hash;
use revm::database::CacheDB;
use revm::database_interface::EmptyDB;
use revm::primitives::Address as EvmAddress;
use std::sync::Arc;

impl EvmModule {
    /// Re-encode every touched account into leaf/storage-root updates
    /// (the incremental half of the state-root update that reads the
    /// account cache). Pure function of the cache and the touched set,
    /// so it can run on the execution stage while the trie
    /// maintenance (`apply_patch` + `assemble_root`) runs later on the
    /// root stage with the same result.
    pub(crate) fn patch_delta(
        db: &CacheDB<EmptyDB>,
        touched_pairs: &[(EvmAddress, alloy_primitives::B256)],
        tries: &mut crate::storage_trie::LargeStorageTries,
    ) -> PatchDelta {
        let mut delta = PatchDelta::with_capacity(touched_pairs.len());
        for (addr, hashed) in touched_pairs {
            // `NotExisting` tombstones (selfdestruct, or a revm
            // `basic()` miss cached as absent) are NOT part of the
            // state trie — committing them as leaves would put the
            // root ahead of persisted state, which never carries
            // them (flush emits `Delete`). Two nodes that read a
            // missing account on different paths would then
            // compute different roots from identical state.
            if let Some(account) = db
                .cache
                .accounts
                .get(addr)
                .filter(|a| a.account_state != revm::database::AccountState::NotExisting)
                // EIP-158: a touched account that ends up empty
                // (nonce 0, balance 0, no code) is deleted from
                // the state trie — e.g. the coinbase when the
                // tip is zero. Keeping it would put an extra
                // leaf in the root every upstream client drops.
                .filter(|a| !a.info.is_empty())
            {
                let storage_root = if account.storage.is_empty() {
                    None
                } else {
                    // Touched -> its slots may have changed. Large accounts update only the changed
                    // slots (`storage_trie`); small ones recompute in full. Same root either way.
                    Some(tries.storage_root(addr, &account.storage))
                };
                delta.upserts.push(LeafUpsert {
                    addr: *addr,
                    hashed: *hashed,
                    storage_root,
                    leaf: encode_trie_leaf(account, storage_root.unwrap_or(trie::EMPTY_ROOT)),
                });
            } else {
                tries.forget(addr);
                delta.removals.push((*addr, *hashed));
            }
        }
        delta
    }

    /// Apply a [`PatchDelta`](PatchDelta) to the leaf map and
    /// the storage-root cache.
    pub(crate) fn apply_patch_ref(
        leaves: &mut std::collections::BTreeMap<alloy_primitives::B256, Vec<u8>>,
        storage_root_cache: &mut std::collections::HashMap<EvmAddress, alloy_primitives::B256>,
        delta: &PatchDelta,
    ) {
        for up in &delta.upserts {
            if let Some(root) = up.storage_root {
                storage_root_cache.insert(up.addr, root);
            }
            leaves.insert(up.hashed, up.leaf.clone());
        }
        for (addr, hashed) in &delta.removals {
            leaves.remove(hashed);
            storage_root_cache.remove(addr);
        }
    }

    pub(crate) fn apply_patch(
        leaves: &mut std::collections::BTreeMap<alloy_primitives::B256, Vec<u8>>,
        storage_root_cache: &mut std::collections::HashMap<EvmAddress, alloy_primitives::B256>,
        delta: PatchDelta,
    ) {
        for up in delta.upserts {
            // Empty storage keeps no cache entry beyond what an earlier non-empty
            // root left, exactly as the single-pass code behaved.
            if let Some(root) = up.storage_root {
                storage_root_cache.insert(up.addr, root);
            }
            leaves.insert(up.hashed, up.leaf);
        }
        for (addr, hashed) in delta.removals {
            leaves.remove(&hashed);
            storage_root_cache.remove(&addr);
        }
    }

    /// Sparse-walk (or full-feed) the leaf map into the state root and
    /// refresh `retained_branches`. See the long comment inside for the
    /// algorithm; this is the only place the Merkle-Patricia root is
    /// assembled, shared by the synchronous path and the root stage.
    pub(crate) fn assemble_root(
        &self,
        leaves: &std::collections::BTreeMap<alloy_primitives::B256, Vec<u8>>,
        retained: &mut std::collections::HashMap<
            alloy_trie::Nibbles,
            alloy_trie::BranchNodeCompact,
        >,
        touched_keys: &[alloy_primitives::B256],
        full_build: bool,
    ) -> Hash {
        let mut hb = alloy_trie::HashBuilder::default().with_updates(true);

        let is_full_build = full_build;
        let can_sparse = !is_full_build && !retained.is_empty();

        if can_sparse {
            // Sparse incremental walk — O(touched · log n).
            let touched_hashes: std::collections::BTreeSet<alloy_primitives::B256> =
                touched_keys.iter().copied().collect();
            sparse_walk(alloy_trie::Nibbles::default(), retained, leaves, &touched_hashes, &mut hb);
        } else {
            // Full build (or fallback when no retained branches):
            // feed every leaf in sorted hashed-key order.
            for (hashed_key, rlp) in leaves {
                hb.add_leaf(alloy_trie::Nibbles::unpack(hashed_key), rlp);
            }
        }

        let root = hb.root();
        let (_, branch_updates) = hb.split();

        if is_full_build {
            // Full build: replace the entire retained map.
            // `split()` returns `alloy_primitives::map::HashMap`
            // (hashbrown, DefaultHashBuilder); convert to the std
            // HashMap used by `retained_branches`.
            *retained = branch_updates.into_iter().collect();
            let max_len = retained.keys().map(alloy_trie::Nibbles::len).max().unwrap_or(0);
            self.retained_depth.fetch_max(max_len, std::sync::atomic::Ordering::Relaxed);
        } else {
            // Incremental build: remove stale branches on the
            // touched path, then merge the rebuilt branches.
            // A branch is "on the touched path" if its nibble
            // prefix is a prefix of any touched hashed key. We
            // check all 64 prefix lengths per touched key; only
            // prefixes that exist in `retained` are removed.
            let depth = self.retained_depth.load(std::sync::atomic::Ordering::Relaxed);
            for hashed in touched_keys {
                let nibbles = alloy_trie::Nibbles::unpack(hashed);
                for len in 0..=depth.min(nibbles.len().saturating_sub(1)) {
                    retained.remove(&nibbles.slice(..len));
                }
            }
            let mut new_depth = depth;
            for (prefix, node) in branch_updates {
                new_depth = new_depth.max(prefix.len());
                retained.insert(prefix, node);
            }
            self.retained_depth.fetch_max(new_depth, std::sync::atomic::Ordering::Relaxed);
        }

        // Cache the state root for the next call's fast path.
        *framework::lock_state(&self.cached_state_root) = Some(root);

        // Convert the alloy B256 root to Oxide's Hash type.
        Hash(root.0)
    }
}

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};

/// Blocks by which the header's `stateRoot` lags the executed block when
/// the root stage is on (unit: blocks). The header of block `h` carries
/// the state root of block `h - ROOT_HEADER_LAG` (the "delayed state
/// root" design: the EVM block hash, which EIP-2935 writes into state at
/// the start of block `h + 1`, must not depend on a root that is still
/// being computed). Must be >= the executor's `ROOT_LANE_DEPTH` so the
/// root a header needs is already finished or about to be; larger
/// values only lengthen the staleness of `stateRoot` in headers.
pub(crate) const ROOT_HEADER_LAG: u64 = 4;

/// Seal jobs the exec stage may queue ahead of the seal worker (unit: blocks). The seal of
/// block `h` must finish before block `h + 1` ends (its parent hash is written then), so more than
/// one block of slack only hides jitter; it also bounds the captured per-block data held in memory.
const SEAL_QUEUE_DEPTH: usize = 2;

/// How the state root of a deferred block is obtained on the root stage.
#[derive(Debug)]
pub(crate) enum DeferredRoot {
    /// Computed synchronously on the execution stage (the first build
    /// after construction or snapshot import, which must see the whole
    /// cache). The root stage only records it.
    Precomputed(Hash),
    /// Leaf changes for the root stage to fold into the trie.
    Patch(PatchDelta),
}

/// What the root stage needs for block `height`.
#[derive(Debug)]
pub(crate) struct DeferredBlock {
    pub height: u64,
    pub root: DeferredRoot,
}

/// Root-stage bookkeeping owned by the EVM module.
#[derive(Debug, Default)]
pub(crate) struct RootStageState {
    /// When set, `end_block` defers the trie update to
    /// [`EvmModule::finish_root`].
    pub enabled: AtomicBool,
    /// Blocks awaiting `finish_root`, oldest first.
    pub queue: Mutex<VecDeque<DeferredBlock>>,
    /// Finished roots by height (recent window), read by `end_block` for
    /// the lagged header root.
    pub rooted: Mutex<BTreeMap<u64, alloy_primitives::B256>>,
    /// Blocks pushed but not yet finished (queued or in progress).
    pub unfinished: Mutex<usize>,
    /// Signalled whenever `rooted` grows or `unfinished` drops.
    pub progress: Condvar,
    /// Seal jobs for the seal worker thread (`None`: no worker, seal inline).
    pub seal_tx: Mutex<Option<std::sync::mpsc::SyncSender<SealJob>>>,
    /// Seal progress: highest height submitted to / finished by the seal stage.
    pub seal: Mutex<SealProgress>,
    /// Signalled when `seal` advances.
    pub seal_cv: Condvar,
    /// Gas used by the block just ended, recorded on the exec stage for the base-fee update
    /// (`end_block_ctx`), which cannot wait for the seal.
    pub block_gas_used: Mutex<Option<u64>>,
    /// Test hook: microseconds the seal worker sleeps before each seal, to keep a seal in flight
    /// while the next block starts (exercises the lazy parent-hash write deterministically).
    pub seal_delay_us: std::sync::atomic::AtomicU64,
    /// Block whose EIP-2935 parent-hash write is still owed (lazy write; see
    /// `resolve_pending_parent_hash`).
    pub pending_parent: Mutex<Option<u64>>,
}

/// Heights the seal stage has been given and has completed.
#[derive(Debug, Default)]
pub(crate) struct SealProgress {
    /// Highest height whose seal job was submitted.
    pub submitted: Option<u64>,
    /// Highest height sealed (history record, undo index and backend batch done).
    pub sealed: Option<u64>,
    /// The seal worker died; waiters must stop waiting and fail.
    pub dead: bool,
}

/// What the seal stage needs for one block, captured as values on the exec stage.
#[derive(Debug)]
pub(crate) struct SealJob {
    pub height: u64,
    pub timestamp: u64,
    pub coinbase: revm::primitives::Address,
    pub gas_limit: u64,
    pub base_fee: u64,
    pub pending: Pending,
    pub undo: crate::versioned::BlockUndo,
    pub undo_blob: Option<Vec<u8>>,
    /// Account flush batch for the backend, serialised on the exec stage.
    pub flush_ops: Option<Vec<storage::Op>>,
}

impl RootStageState {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Block until every deferred block has been finished. Used before a
    /// full trie build or a snapshot, both of which need the trie to be
    /// quiescent at a known height.
    pub(crate) fn wait_drained(&self) {
        let mut n = framework::lock_state(&self.unfinished);
        while *n > 0 {
            n = self
                .progress
                .wait(n)
                .unwrap_or_else(|_| panic!("state mutex poisoned: a holder panicked mid-mutation"));
        }
    }

    /// Block until the block at `height` is sealed (immediately if no seal job for it exists).
    pub(crate) fn wait_sealed(&self, height: u64) {
        let mut p = framework::lock_state(&self.seal);
        loop {
            if p.sealed.is_some_and(|s| s >= height) || p.submitted.is_none_or(|s| s < height) {
                return;
            }
            assert!(!p.dead, "evm seal worker died while block {height} was unsealed");
            p = self
                .seal_cv
                .wait(p)
                .unwrap_or_else(|_| panic!("state mutex poisoned: a holder panicked mid-mutation"));
        }
    }

    /// Whether block `height` is already sealed, or no seal job for it is outstanding.
    pub(crate) fn sealed_or_idle(&self, height: u64) -> bool {
        let p = framework::lock_state(&self.seal);
        p.sealed.is_some_and(|s| s >= height) || p.submitted.is_none_or(|s| s < height)
    }

    /// Block until the root of `height` is finished and return it.
    pub(crate) fn wait_rooted(&self, height: u64) -> alloy_primitives::B256 {
        let mut map = framework::lock_state(&self.rooted);
        loop {
            if let Some(root) = map.get(&height) {
                return *root;
            }
            map = self
                .progress
                .wait(map)
                .unwrap_or_else(|_| panic!("state mutex poisoned: a holder panicked mid-mutation"));
        }
    }
}

impl EvmModule {
    /// Execution-stage `end_block` in deferred mode. Does everything the
    /// synchronous `end_block` does (sealing, undo, backend flush) except
    /// the trie update: the header carries the root of block
    /// `h - ROOT_HEADER_LAG`, and the block's own root inputs are queued
    /// for the root stage as values. Never touches the trie.
    pub(crate) fn end_block_deferred(&self, height: u64) -> Vec<executor::Event> {
        let rs = &self.root_stage;
        // The parent-hash write owed by `begin_block` must land before this block's state is captured.
        self.resolve_pending_parent_hash();
        let ready = *framework::lock_state(&self.trie_leaves_ready);
        let root = if ready {
            let pairs: Vec<(EvmAddress, alloy_primitives::B256)> =
                framework::lock_state(&self.touched)
                    .iter()
                    .map(|a| (*a, alloy_primitives::keccak256(a)))
                    .collect();
            let db = framework::lock_state(&self.db);
            let mut tries = framework::lock_state(&self.large_storage);
            DeferredRoot::Patch(Self::patch_delta(&db, &pairs, &mut tries))
        } else {
            // First build (or after import): needs the whole cache and a
            // quiescent trie, so it runs here, synchronously.
            rs.wait_drained();
            DeferredRoot::Precomputed(<Self as executor::Module>::state_root(self))
        };

        // Everything the seal needs, captured now (the next block mutates all of it).
        let has_backend = framework::lock_state(&self.backend).is_some();
        let timestamp = *framework::lock_state(&self.block_timestamp);
        let coinbase = *framework::lock_state(&self.coinbase);
        let pending = framework::lock_state(&self.history).take_pending();
        *framework::lock_state(&rs.block_gas_used) = Some(pending.gas_used());
        let undo = std::mem::take(&mut *framework::lock_state(&self.block_undo));
        let undo_blob = has_backend.then(|| crate::persist::serialize_undo(&undo));
        let flush_ops = has_backend.then(|| self.account_flush_ops());
        let job = SealJob {
            height,
            timestamp,
            coinbase,
            gas_limit: self.block_gas_limit(),
            base_fee: self.current_base_fee(),
            pending,
            undo,
            undo_blob,
            flush_ops,
        };
        framework::lock_state(&self.touched).clear();
        framework::lock_state(&rs.seal).submitted = Some(height);
        *framework::lock_state(&rs.unfinished) += 1;
        framework::lock_state(&rs.queue).push_back(DeferredBlock { height, root });
        // Hand the seal to its worker (back-pressure: the channel is bounded), or run it here
        // when no worker is attached (unit tests driving the module directly).
        let worker = framework::lock_state(&rs.seal_tx).clone();
        match worker {
            Some(tx) => assert!(tx.send(job).is_ok(), "evm seal worker thread died"),
            None => self.process_seal_job(job),
        }
        Vec::new()
    }

    /// Seal stage: header roots, history record, undo index and backend batch for one block.
    /// The header carries the root of block `height - ROOT_HEADER_LAG` (zero before that), which
    /// the root stage produces; this waits for it.
    pub(crate) fn process_seal_job(&self, job: SealJob) {
        let rs = &self.root_stage;
        let height = job.height;
        let delay = rs.seal_delay_us.load(Ordering::Relaxed);
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_micros(delay));
        }
        let has_backend = job.flush_ops.is_some();
        let header_root = if height > ROOT_HEADER_LAG {
            rs.wait_rooted(height - ROOT_HEADER_LAG)
        } else {
            alloy_primitives::B256::ZERO
        };
        let (sealed_block, evicted) = {
            let mut history = framework::lock_state(&self.history);
            let roots = crate::history::History::roots_of(&job.pending);
            let evicted = history.seal_taken(
                height,
                job.timestamp,
                job.gas_limit,
                job.base_fee,
                job.coinbase,
                header_root,
                roots,
                job.pending,
            );
            // The clone feeds only the backend batch below; at 28k txs per block it costs
            // ~3 ms, so skip it when no backend is attached.
            (has_backend.then(|| history.block(height).cloned()).flatten(), evicted)
        };
        let pruned_undo = {
            let mut versioned = framework::lock_state(&self.versioned);
            versioned.push(height, job.undo);
            let history = framework::lock_state(&self.history);
            history.blocks_floor().map_or_else(Vec::new, |floor| versioned.prune_below(floor))
        };
        let mut backend_guard = framework::lock_state(&self.backend);
        if let Some(ref mut backend) = *backend_guard {
            let mut ops = job.flush_ops.unwrap_or_default();
            if let Some(b) = sealed_block {
                ops.push(storage::Op::Set {
                    key: crate::persist::block_key(height),
                    value: crate::persist::serialize_block(&b),
                });
            }
            if let Some(blob) = job.undo_blob {
                ops.push(storage::Op::Set { key: crate::persist::undo_key(height), value: blob });
            }
            for h in evicted {
                ops.push(storage::Op::Delete { key: crate::persist::block_key(h) });
            }
            for h in pruned_undo {
                ops.push(storage::Op::Delete { key: crate::persist::undo_key(h) });
            }
            let _ = self.flush_pending(backend.as_mut(), ops);
        }
        drop(backend_guard);
        framework::lock_state(&rs.seal).sealed = Some(height);
        rs.seal_cv.notify_all();
    }

    /// Spawn the seal worker (called through `Module::spawn_workers` by the executor when the
    /// root stage is on). The thread holds only a `Weak`, so it ends when the module is dropped.
    pub(crate) fn spawn_seal_worker(self: &std::sync::Arc<Self>) {
        let rs = &self.root_stage;
        let mut slot = framework::lock_state(&rs.seal_tx);
        if slot.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::sync_channel::<SealJob>(SEAL_QUEUE_DEPTH);
        *slot = Some(tx);
        drop(slot);
        let weak = std::sync::Arc::downgrade(self);
        let spawned = std::thread::Builder::new().name("evm-seal".into()).spawn(move || {
            /// Marks the worker dead on any exit so waiters fail instead of hanging.
            struct Guard(std::sync::Weak<EvmModule>);
            impl Drop for Guard {
                fn drop(&mut self) {
                    if let Some(m) = self.0.upgrade() {
                        framework::lock_state(&m.root_stage.seal).dead = true;
                        m.root_stage.seal_cv.notify_all();
                    }
                }
            }
            let _guard = Guard(weak.clone());
            while let Ok(job) = rx.recv() {
                let Some(module) = weak.upgrade() else { return };
                module.process_seal_job(job);
            }
        });
        assert!(spawned.is_ok(), "spawn evm seal worker");
    }

    /// Write block `h`'s parent hash into the EIP-2935 history-storage contract's ring buffer
    /// (see `begin_block`: the write a geth system call performs before any transaction).
    pub(crate) fn write_parent_hash(&self, h: u64, parent_hash: alloy_primitives::B256) {
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);
        framework::lock_state(&self.block_undo)
            .capture(HISTORY_STORAGE_ADDRESS, db.cache.accounts.get(&HISTORY_STORAGE_ADDRESS));
        let account = db.cache.accounts.entry(HISTORY_STORAGE_ADDRESS).or_insert_with(|| {
            revm::database::DbAccount {
                info: revm::database::state::AccountInfo {
                    balance: revm::primitives::U256::ZERO,
                    nonce: 0,
                    code_hash: revm::primitives::KECCAK_EMPTY,
                    account_id: None,
                    code: Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::new())),
                },
                account_state: revm::database::AccountState::Touched,
                storage: revm::primitives::HashMap::default(),
            }
        });
        let slot = revm::primitives::U256::from((h - 1) % HISTORY_SERVE_WINDOW);
        let value = revm::primitives::U256::from_be_bytes(parent_hash.0);
        // Sparse-storage invariant: a zero write deletes —
        // "slot = 0" and "slot absent" are the same MPT
        // state. A parent hash is a keccak output (never
        // zero in practice), but keep the rule uniform.
        if value.is_zero() {
            account.storage.remove(&slot);
        } else {
            account.storage.insert(slot, value);
        }
        account.account_state = revm::database::AccountState::Touched;
        drop(db_guard);
        framework::lock_state(&self.touched).insert(HISTORY_STORAGE_ADDRESS);
    }

    /// Apply the EIP-2935 parent-hash write that `begin_block` deferred, waiting for the parent's
    /// seal if it is still in flight. No-op when nothing is owed.
    ///
    /// Block `h`'s write needs the hash of block `h - 1`, which covers the receipts and
    /// transactions roots the seal worker is still computing. A block of plain value transfers
    /// cannot read the history contract, so its transactions run first and the write lands before
    /// the end-of-block capture; any other batch calls this before it executes. The final state
    /// is identical to writing at `begin_block`.
    pub(crate) fn resolve_pending_parent_hash(&self) {
        let Some(h) = framework::lock_state(&self.root_stage.pending_parent).take() else {
            return;
        };
        self.root_stage.wait_sealed(h - 1);
        let parent_hash = framework::lock_state(&self.history).block(h - 1).map(|b| b.hash);
        if let Some(parent_hash) = parent_hash {
            self.write_parent_hash(h, parent_hash);
        }
    }

    /// Root-stage half: fold the oldest deferred block into the trie and
    /// publish its root. Equal to what the synchronous `state_root` would
    /// have returned for this height.
    ///
    /// # Panics
    ///
    /// Panics if called with no deferred block queued or for the wrong
    /// height (a stage-ordering bug), or on a poisoned module lock.
    pub(crate) fn finish_root_deferred(&self, height: u64) -> primitives::Hash {
        let rs = &self.root_stage;
        let block = framework::lock_state(&rs.queue)
            .pop_front()
            .unwrap_or_else(|| panic!("evm root stage: finish_root({height}) with an empty queue"));
        assert_eq!(block.height, height, "evm root stage: blocks finished out of order");
        let root = match block.root {
            DeferredRoot::Precomputed(h) => alloy_primitives::B256::from(h.0),
            DeferredRoot::Patch(ref delta) => self.fold_patch(delta),
        };
        {
            let mut rooted = framework::lock_state(&rs.rooted);
            rooted.insert(height, root);
            // Keep a window comfortably wider than the header lag.
            while rooted.len() as u64 > 2 * ROOT_HEADER_LAG + 4 {
                rooted.pop_first();
            }
        }
        // `executed` (the executor watermark) means executed, sealed and rooted: snapshots,
        // RPC and attestations rely on it.
        rs.wait_sealed(height);
        {
            let mut n = framework::lock_state(&rs.unfinished);
            *n = n.saturating_sub(1);
        }
        rs.progress.notify_all();
        primitives::Hash(root.0)
    }

    /// Apply a patch to the trie structures and return the new root.
    fn fold_patch(&self, delta: &PatchDelta) -> alloy_primitives::B256 {
        let mut leaves = framework::lock_state(&self.trie_leaves);
        let mut retained = framework::lock_state(&self.retained_branches);
        let mut cache = framework::lock_state(&self.storage_root_cache);
        if delta.upserts.is_empty()
            && delta.removals.is_empty()
            && let Some(cached) = *framework::lock_state(&self.cached_state_root)
        {
            return cached;
        }
        let keys = delta.touched_keys();
        Self::apply_patch_ref(&mut leaves, &mut cache, delta);
        drop(cache);
        let root = self.assemble_root(&leaves, &mut retained, &keys, false);
        alloy_primitives::B256::from(root.0)
    }
}
