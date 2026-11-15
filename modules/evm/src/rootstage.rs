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
