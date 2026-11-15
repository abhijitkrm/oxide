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
use crate::trie::{self, encode_trie_leaf, sparse_walk};
use primitives::Hash;
use revm::database::CacheDB;
use revm::database_interface::EmptyDB;
use revm::primitives::Address as EvmAddress;

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
                    // Touched -> always recompute the storage root
                    // (its slots changed).
                    let storage_iter = account
                        .storage
                        .iter()
                        .filter(|(_, value)| !value.is_zero())
                        .map(|(slot, value)| {
                            (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                        });
                    Some(trie::storage_root(storage_iter))
                };
                delta.upserts.push(LeafUpsert {
                    addr: *addr,
                    hashed: *hashed,
                    storage_root,
                    leaf: encode_trie_leaf(account, storage_root.unwrap_or(trie::EMPTY_ROOT)),
                });
            } else {
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
        let ready = *framework::lock_state(&self.trie_leaves_ready);
        let root = if ready {
            let pairs: Vec<(EvmAddress, alloy_primitives::B256)> =
                framework::lock_state(&self.touched)
                    .iter()
                    .map(|a| (*a, alloy_primitives::keccak256(a)))
                    .collect();
            let db = framework::lock_state(&self.db);
            DeferredRoot::Patch(Self::patch_delta(&db, &pairs))
        } else {
            // First build (or after import): needs the whole cache and a
            // quiescent trie, so it runs here, synchronously.
            rs.wait_drained();
            DeferredRoot::Precomputed(<Self as executor::Module>::state_root(self))
        };

        // Header root: lagged, so the block hash is known right now.
        let header_root = if height > ROOT_HEADER_LAG {
            rs.wait_rooted(height - ROOT_HEADER_LAG)
        } else {
            alloy_primitives::B256::ZERO
        };
        let timestamp = *framework::lock_state(&self.block_timestamp);
        let coinbase = *framework::lock_state(&self.coinbase);
        let (sealed_block, evicted) = {
            let mut history = framework::lock_state(&self.history);
            let pending = history.take_pending();
            let roots = crate::history::History::roots_of(&pending);
            let evicted = history.seal_taken(
                height,
                timestamp,
                self.block_gas_limit(),
                self.current_base_fee(),
                coinbase,
                header_root,
                roots,
                pending,
            );
            (history.block(height).cloned(), evicted)
        };
        let undo = std::mem::take(&mut *framework::lock_state(&self.block_undo));
        let has_backend = framework::lock_state(&self.backend).is_some();
        let undo_blob = has_backend.then(|| crate::persist::serialize_undo(&undo));
        let pruned_undo = {
            let mut versioned = framework::lock_state(&self.versioned);
            versioned.push(height, undo);
            let history = framework::lock_state(&self.history);
            history.blocks_floor().map_or_else(Vec::new, |floor| versioned.prune_below(floor))
        };
        let mut backend_guard = framework::lock_state(&self.backend);
        if let Some(ref mut backend) = *backend_guard {
            let mut ops = self.account_flush_ops();
            if let Some(b) = sealed_block {
                ops.push(storage::Op::Set {
                    key: crate::persist::block_key(height),
                    value: crate::persist::serialize_block(&b),
                });
            }
            if let Some(blob) = undo_blob {
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
        framework::lock_state(&self.touched).clear();
        *framework::lock_state(&rs.unfinished) += 1;
        framework::lock_state(&rs.queue).push_back(DeferredBlock { height, root });
        Vec::new()
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
