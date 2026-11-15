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
        self.upserts
            .iter()
            .map(|u| u.hashed)
            .chain(self.removals.iter().map(|(_, h)| *h))
            .collect()
    }
}

use crate::EvmModule;
use crate::trie::{self, encode_trie_leaf, sparse_walk};
use primitives::Hash;
use revm::database::CacheDB;
use revm::primitives::Address as EvmAddress;
use revm::database_interface::EmptyDB;

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
        storage_root_cache: &mut std::collections::HashMap<
            EvmAddress,
            alloy_primitives::B256,
        >,
        delta: PatchDelta,
    ) {
        for up in delta.upserts {
            match up.storage_root {
                Some(root) => {
                    storage_root_cache.insert(up.addr, root);
                }
                // An account whose storage is empty keeps no cache entry
                // beyond what an earlier non-empty root left, exactly as
                // the single-pass code behaved (it did not touch the
                // cache on this branch).
                None => {}
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
            sparse_walk(
                alloy_trie::Nibbles::default(),
                retained,
                leaves,
                &touched_hashes,
                &mut hb,
            );
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

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};

use crate::history::Pending;

/// How the state root of a deferred block is obtained on the root stage.
#[derive(Debug)]
pub(crate) enum DeferredRoot {
    /// Computed synchronously on the execution stage (the first build
    /// after construction or snapshot import, which must see the whole
    /// cache). The root stage only seals.
    Precomputed(Hash),
    /// Leaf changes for the root stage to fold into the trie.
    Patch(PatchDelta),
}

/// Everything the root stage needs to finish block `height`, captured
/// as values on the execution stage at `end_block`.
#[derive(Debug)]
pub(crate) struct DeferredBlock {
    pub height: u64,
    pub root: DeferredRoot,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee: u64,
    pub coinbase: revm::primitives::Address,
    pub pending: Pending,
    pub undo_blob: Option<Vec<u8>>,
    /// Account flush batch for the backend, serialised on the execution
    /// stage (it reads the live cache); `None` without a backend.
    pub flush_ops: Option<Vec<storage::Op>>,
}

/// Root-stage bookkeeping owned by the EVM module.
#[derive(Debug, Default)]
pub(crate) struct RootStageState {
    /// When set, `end_block` defers the root and sealing to
    /// [`EvmModule::finish_root`].
    pub enabled: AtomicBool,
    /// Blocks awaiting `finish_root`, oldest first.
    pub queue: Mutex<VecDeque<DeferredBlock>>,
    /// Blocks pushed but not yet fully finished (queued or in progress).
    pub unfinished: Mutex<usize>,
    /// Signalled whenever `unfinished` drops.
    pub drained: Condvar,
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
            n = self.drained.wait(n).unwrap_or_else(|_| {
                panic!("state mutex poisoned: a holder panicked mid-mutation")
            });
        }
    }
}

impl EvmModule {
    /// Execution-stage half of `end_block` in deferred mode: capture the
    /// block's root inputs, pending history, undo and flush batch as
    /// values and queue them. Never touches the trie.
    pub(crate) fn end_block_deferred(&self, height: u64) -> Vec<executor::Event> {
        let rs = &self.root_stage;
        let ready = *framework::lock_state(&self.trie_leaves_ready);
        let root = if ready {
            let touched = framework::lock_state(&self.touched);
            let pairs: Vec<(EvmAddress, alloy_primitives::B256)> =
                touched.iter().map(|a| (*a, alloy_primitives::keccak256(a))).collect();
            drop(touched);
            let db = framework::lock_state(&self.db);
            DeferredRoot::Patch(Self::patch_delta(&db, &pairs))
        } else {
            // First build (or after import): needs the whole cache and a
            // quiescent trie, so it runs here, synchronously.
            rs.wait_drained();
            DeferredRoot::Precomputed(<Self as executor::Module>::state_root(self))
        };
        let timestamp = *framework::lock_state(&self.block_timestamp);
        let coinbase = *framework::lock_state(&self.coinbase);
        let pending = framework::lock_state(&self.history).take_pending();
        let undo = std::mem::take(&mut *framework::lock_state(&self.block_undo));
        let has_backend = framework::lock_state(&self.backend).is_some();
        let undo_blob = has_backend.then(|| crate::persist::serialize_undo(&undo));
        framework::lock_state(&self.versioned).push(height, undo);
        let flush_ops = has_backend.then(|| self.account_flush_ops());
        framework::lock_state(&self.touched).clear();
        let block = DeferredBlock {
            height,
            root,
            timestamp,
            gas_limit: self.block_gas_limit(),
            base_fee: self.current_base_fee(),
            coinbase,
            pending,
            undo_blob,
            flush_ops,
        };
        *framework::lock_state(&rs.unfinished) += 1;
        framework::lock_state(&rs.queue).push_back(block);
        Vec::new()
    }

    /// Root-stage half: fold the oldest deferred block into the trie,
    /// seal it and flush its batch. Returns the block's state root, equal
    /// to what the synchronous `end_block` + `state_root` would produce.
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

        // The MPT update and the two header tries are independent.
        let (state_root, roots) = rayon::join(
            || match block.root {
                DeferredRoot::Precomputed(h) => alloy_primitives::B256::from(h.0),
                DeferredRoot::Patch(ref delta) => self.fold_patch(delta),
            },
            || crate::history::History::roots_of(&block.pending),
        );
        let (sealed_block, evicted, pruned_undo) = {
            let mut history = framework::lock_state(&self.history);
            let evicted = history.seal_taken(
                height,
                block.timestamp,
                block.gas_limit,
                block.base_fee,
                block.coinbase,
                state_root,
                roots,
                block.pending,
            );
            let sealed = history.block(height).cloned();
            let pruned = {
                let mut versioned = framework::lock_state(&self.versioned);
                history
                    .blocks_floor()
                    .map_or_else(Vec::new, |floor| versioned.prune_below(floor))
            };
            (sealed, evicted, pruned)
        };
        let mut backend_guard = framework::lock_state(&self.backend);
        if let Some(ref mut backend) = *backend_guard {
            let mut ops = block.flush_ops.unwrap_or_default();
            if let Some(b) = sealed_block {
                ops.push(storage::Op::Set {
                    key: crate::persist::block_key(height),
                    value: crate::persist::serialize_block(&b),
                });
            }
            if let Some(blob) = block.undo_blob {
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
        {
            let mut n = framework::lock_state(&rs.unfinished);
            *n = n.saturating_sub(1);
        }
        rs.drained.notify_all();
        primitives::Hash(state_root.0)
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
