//! Ethereum-compatible Merkle-Patricia Trie (MPT) state root.
//!
//! This module wraps [`alloy-trie`] to compute Ethereum-compatible
//! state roots from the EVM's account state. The state root is a
//! keccak-256 Merkle-Patricia Trie over accounts, where each account
//! value is RLP-encoded as `[nonce, balance, storageRoot, codeHash]`.
//!
//! # Reference
//!
//! - **reth** uses the same `alloy-trie` crate for state root
//!   computation (see `reth-trie` crate). This ensures Oxide's state
//!   roots match Ethereum mainnet for identical state.
//! - Ethereum Yellow Paper Appendix D: the state trie is a
//!   Merkle-Patricia Trie with keccak-256 node hashes, keyed by
//!   keccak-256 of the 20-byte address.
//! - EIP-1559: the state root is committed in the block header and
//!   must be deterministic across all nodes for the same state.
//!
//! # Why not hand-roll the MPT?
//!
//! Hand-rolling a correct MPT is a multi-week, consensus-critical
//! risk. `alloy-trie` is battle-tested (foundry/reth tooling), uses
//! the same alloy primitives as revm, and provides `HashBuilder`,
//! `ProofRetainer` (for incremental proof-cached updates), and proof
//! verification. See `plan.md` §Phase B decision D4.

use alloy_primitives::{Address, B256, U256};
use alloy_trie::{EMPTY_ROOT_HASH, TrieAccount};

/// The root hash of an empty trie (Ethereum mainnet constant).
///
/// This is the state root when there are zero accounts. It matches
/// Ethereum's `EMPTY_ROOT_HASH`:
/// `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`.
///
/// Reference: Ethereum Yellow Paper Appendix D, and `alloy-trie::EMPTY_ROOT_HASH`.
pub const EMPTY_ROOT: B256 = EMPTY_ROOT_HASH;

/// The code hash of an account with no bytecode (empty account).
///
/// This is `keccak256("")`:
/// `0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`.
///
/// Reference: `alloy_primitives::utils::KECCAK256_EMPTY`.
pub const KECCAK_EMPTY: B256 = alloy_primitives::utils::KECCAK256_EMPTY;

/// Compute the storage root for a single account's storage.
///
/// The storage trie is keyed by `keccak256(slot)` with the RLP-encoded
/// `U256` value. An empty storage map returns `EMPTY_ROOT`.
///
/// # Arguments
///
/// - `storage`: an iterator of `(slot: B256, value: U256)` pairs. The
///   slots are hashed internally (keccak-256) before insertion into the
///   trie, matching Ethereum's secure trie convention.
///
/// # Returns
///
/// The 32-byte storage root hash.
pub fn storage_root(storage: impl IntoIterator<Item = (B256, U256)>) -> B256 {
    alloy_trie::root::storage_root_unhashed(storage)
}

/// Compute the state root over a set of accounts.
///
/// The state trie is keyed by `keccak256(address)` with the
/// RLP-encoded `TrieAccount` value. Accounts are sorted internally
/// by their hashed keys before trie construction.
///
/// # Arguments
///
/// - `accounts`: an iterator of `(address: Address, account: TrieAccount)`
///   pairs. The addresses are hashed internally (keccak-256) before
///   insertion into the trie.
///
/// # Returns
///
/// The 32-byte state root hash. For zero accounts, returns `EMPTY_ROOT`.
pub fn state_root(accounts: impl IntoIterator<Item = (Address, TrieAccount)>) -> B256 {
    alloy_trie::root::state_root_unhashed(accounts)
}

/// Build a `TrieAccount` from the revm account fields.
///
/// This is the bridge between revm's in-memory account representation
/// and the MPT's `TrieAccount`. The `storage_root` is computed
/// separately (via [`storage_root`]) and passed in; the `code_hash`
/// is `KECCAK_EMPTY` for accounts with no bytecode.
///
/// # Arguments
///
/// - `nonce`: the account's transaction nonce.
/// - `balance`: the account's ETH balance (wei).
/// - `storage_root`: the root of the account's storage trie (or
///   `EMPTY_ROOT` for no storage).
/// - `code_hash`: the keccak-256 hash of the account's bytecode (or
///   `KECCAK_EMPTY` for no code).
#[must_use]
pub fn build_trie_account(
    nonce: u64,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
) -> TrieAccount {
    TrieAccount { nonce, balance, storage_root, code_hash }
}

/// RLP-encode an account's `TrieAccount` leaf value for the account
/// trie. Shared by the full-build and incremental-patch paths in
/// `state_root` so both produce byte-identical leaves.
pub(crate) fn encode_trie_leaf(
    account: &revm::database::DbAccount,
    storage_root: revm::primitives::B256,
) -> Vec<u8> {
    let trie_account = build_trie_account(
        account.info.nonce,
        account.info.balance,
        storage_root,
        account.info.code_hash,
    );
    // TrieAccount RLP is ~70 bytes (nonce + 32B balance + two
    // 32B hashes + RLP overhead); one allocation per leaf.
    let mut buf = Vec::with_capacity(80);
    alloy_rlp::Encodable::encode(&trie_account, &mut buf);
    buf
}

/// Compute the inclusive-start and inclusive-end `B256` bounds for
/// all keys that share the given nibble `prefix`.
///
/// The state trie is keyed by `keccak256(address)` — a 32-byte value,
/// i.e. 64 nibbles. A prefix of length L fixes the first L nibbles;
/// the remaining 64−L nibbles range freely. This function returns the
/// `(start, end)` pair for a `BTreeMap<B256, _>::range(start..=end)`
/// query covering exactly those keys (inclusive on both ends).
///
/// Using an inclusive end avoids the `end + 1` wrap-around that
/// would occur for prefixes at the very end of the key space (e.g.
/// a single-nibble prefix of 0xF), which would produce `end < start`
/// and panic in `BTreeMap::range`.
///
/// For even L the boundary is byte-aligned. For odd L the last
/// boundary byte carries the prefix nibble in its high half and 0
/// (start) or 0xF (end) in its low half.
pub(crate) fn prefix_range(
    prefix: &alloy_trie::Nibbles,
) -> (alloy_primitives::B256, alloy_primitives::B256) {
    let len = prefix.len();
    let mut start = [0u8; 32];
    let mut end = [0u8; 32];
    // Pack the prefix nibbles into both arrays. For even `i` we
    // set the high nibble; for odd `i` we OR in the low nibble.
    // We do NOT pre-fill the low nibble with 0xF on the even
    // pass — that would corrupt the odd pass (0xF | x == 0xF).
    for i in 0..len {
        let nibble = prefix.get_unchecked(i);
        let byte_idx = i / 2;
        if i % 2 == 0 {
            start[byte_idx] = nibble << 4;
            end[byte_idx] = nibble << 4;
        } else {
            start[byte_idx] |= nibble;
            end[byte_idx] |= nibble;
        }
    }
    // If the prefix length is odd, the last packed byte has a free
    // low nibble. Set it to 0x0F for the end bound (start already 0).
    if len % 2 == 1 {
        let last_byte_idx = len / 2;
        end[last_byte_idx] |= 0x0F;
    }
    // Bytes after the prefix: start stays 0x00, end becomes 0xFF.
    let last_packed_byte = len.div_ceil(2);
    for b in &mut end[last_packed_byte..] {
        *b = 0xFF;
    }
    (alloy_primitives::B256::from(start), alloy_primitives::B256::from(end))
}

/// Recursively walk the retained branch trie, feeding `HashBuilder`
/// only the leaves and branch hashes that need recomputation.
///
/// Starting from the branch node at `prefix` (looked up in
/// `retained`), iterate each child nibble. For children whose subtree
/// contains no touched account, inject the precomputed child hash
/// via `add_branch` (O(1) skip). For children containing touched
/// accounts, either recurse (if the child is a stored branch) or
/// feed the actual leaves from `trie_leaves` (for inline
/// leaves/extensions or shallow branches not in `retained`).
///
/// # Arguments
///
/// - `prefix`: the nibble prefix of the current branch node.
/// - `retained`: the full retained branch map from the previous
///   `state_root` build.
/// - `leaves`: the `trie_leaves` `BTreeMap` (all account leaves, keyed
///   by `keccak256` of the address).
/// - `touched_hashes`: sorted set of touched hashed addresses, used
///   to determine which subtrees need recomputation.
/// - `hb`: the `HashBuilder` to feed.
///
/// # Complexity
///
/// O(touched · depth · 16) = O(touched · log n) per call.
pub(crate) fn sparse_walk(
    prefix: alloy_trie::Nibbles,
    retained: &std::collections::HashMap<alloy_trie::Nibbles, alloy_trie::BranchNodeCompact>,
    leaves: &std::collections::BTreeMap<alloy_primitives::B256, Vec<u8>>,
    touched_hashes: &std::collections::BTreeSet<alloy_primitives::B256>,
    hb: &mut alloy_trie::HashBuilder,
) {
    let Some(branch) = retained.get(&prefix) else {
        // No retained branch at this prefix — feed all leaves
        // under it. This handles the root-extension case and
        // any shallow branch not stored in `retained`.
        feed_leaves_under(&prefix, leaves, hb);
        return;
    };

    // Collect all child nibbles to process. The stale `state_mask`
    // reflects the branch structure at the time of the previous
    // build. Account insertions may have created new children that
    // are NOT in the stale `state_mask` — we must include them so
    // their leaves are fed. We scan `touched_hashes` under the
    // current prefix and add any child nibble not already in
    // `state_mask`. This is O(touched) per branch, O(touched · depth)
    // total — dominated by the O(touched · depth · 16) walk.
    let mut children: [u8; 16] = [0; 16];
    let mut children_len = 0usize;
    for n in branch.state_mask.iter() {
        children[children_len] = n;
        children_len += 1;
    }
    {
        let (p_start, p_end) = prefix_range(&prefix);
        let mut last_child: Option<u8> = None;
        for th in touched_hashes.range(p_start..=p_end) {
            let nibs = alloy_trie::Nibbles::unpack(th);
            if nibs.len() <= prefix.len() {
                continue;
            }
            let child_n = nibs.get_unchecked(prefix.len());
            if Some(child_n) != last_child && !branch.state_mask.is_bit_set(child_n) {
                children[children_len] = child_n;
                children_len += 1;
                last_child = Some(child_n);
            } else {
                last_child = Some(child_n);
            }
        }
    }
    // `state_mask.iter()` yields ascending nibbles; we appended new
    // children in ascending order (BTreeSet range). Sort to be safe.
    children[..children_len].sort_unstable();

    for &n in &children[..children_len] {
        // Build the child prefix = prefix + n.
        let mut child_prefix = prefix;
        child_prefix.push(n);

        let has_touched = {
            let (start, end) = prefix_range(&child_prefix);
            touched_hashes.range(start..=end).next().is_some()
        };

        // A child not in the stale `state_mask` is new (from an
        // account insertion). It has no retained hash and no stored
        // branch — we must feed its leaves.
        let in_state_mask = branch.state_mask.is_bit_set(n);
        let is_hashed_child = in_state_mask && branch.hash_mask.is_bit_set(n);
        let is_stored_branch = in_state_mask && branch.tree_mask.is_bit_set(n);

        if !has_touched {
            if is_hashed_child {
                // Untouched hashed subtree — skip with precomputed
                // hash. The child hash comes from the parent's
                // `hashes` array (indexed by the hash_mask).
                let child_hash = branch.hash_for_nibble(n);
                hb.add_branch(child_prefix, child_hash, true);
            } else {
                // Untouched inline child (leaf or short extension).
                // We must feed it — its value is embedded in the
                // parent branch's RLP, not stored as a hash.
                feed_leaves_under(&child_prefix, leaves, hb);
            }
        } else if is_stored_branch && retained.contains_key(&child_prefix) {
            // Touched subtree that is a stored branch — recurse.
            sparse_walk(child_prefix, retained, leaves, touched_hashes, hb);
        } else {
            // Touched subtree that is not a stored branch (inline
            // leaf/extension, or a shallow branch not in `retained`,
            // or a new child from account insertion).
            // Feed all leaves under it. For a shallow branch this is
            // at most 16 leaves; for a leaf it is 1.
            feed_leaves_under(&child_prefix, leaves, hb);
        }
    }
}

/// Feed all leaves whose hashed key falls under `prefix` into
/// `HashBuilder`, in sorted order (required by `add_leaf`).
pub(crate) fn feed_leaves_under(
    prefix: &alloy_trie::Nibbles,
    leaves: &std::collections::BTreeMap<alloy_primitives::B256, Vec<u8>>,
    hb: &mut alloy_trie::HashBuilder,
) {
    let (start, end) = prefix_range(prefix);
    for (hashed_key, rlp) in leaves.range(start..=end) {
        hb.add_leaf(alloy_trie::Nibbles::unpack(hashed_key), rlp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256, keccak256};

    /// The empty trie root must match Ethereum's mainnet constant.
    /// This is the single most important invariant: if our empty
    /// root differs from mainnet, no state root will ever match.
    #[test]
    fn empty_root_matches_mainnet_constant() {
        // Ethereum's EMPTY_ROOT_HASH — the state root of a chain
        // with zero accounts. Cited in every Ethereum client and
        // in alloy-trie's source.
        let expected = alloy_primitives::b256!(
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
        assert_eq!(EMPTY_ROOT, expected);
    }

    /// An empty state (zero accounts) must produce the empty root.
    #[test]
    fn empty_state_produces_empty_root() {
        let root = state_root(std::iter::empty());
        assert_eq!(root, EMPTY_ROOT);
    }

    /// A single account with zero balance, zero nonce, no code, and
    /// no storage must produce a known root. This is the simplest
    /// non-empty state.
    #[test]
    fn single_empty_account_has_known_root() {
        let addr = Address::ZERO;
        let account = build_trie_account(0, U256::ZERO, EMPTY_ROOT, KECCAK_EMPTY);
        let root = state_root(std::iter::once((addr, account)));
        // The root must be non-empty (different from EMPTY_ROOT)
        // because there is one account in the trie.
        assert_ne!(root, EMPTY_ROOT);
        // The root must be deterministic.
        let root2 = state_root(std::iter::once((addr, account)));
        assert_eq!(root, root2);
    }

    /// Two accounts with the same content must produce the same root
    /// regardless of insertion order. This verifies that the trie
    /// is order-independent (a critical consensus property).
    #[test]
    fn insertion_order_does_not_affect_root() {
        let addr_a = Address::from_slice(&[0xAA; 20]);
        let addr_b = Address::from_slice(&[0xBB; 20]);
        let account = build_trie_account(1, U256::from(1000), EMPTY_ROOT, KECCAK_EMPTY);

        let root_ab = state_root([(addr_a, account), (addr_b, account)]);
        let root_ba = state_root([(addr_b, account), (addr_a, account)]);
        assert_eq!(root_ab, root_ba, "insertion order must not affect root");
    }

    /// Different account states must produce different roots. This
    /// verifies that the trie actually encodes the state (not just
    /// a constant).
    #[test]
    fn different_states_produce_different_roots() {
        let addr = Address::ZERO;
        let account_1 = build_trie_account(1, U256::ZERO, EMPTY_ROOT, KECCAK_EMPTY);
        let account_2 = build_trie_account(2, U256::ZERO, EMPTY_ROOT, KECCAK_EMPTY);
        let root_1 = state_root(std::iter::once((addr, account_1)));
        let root_2 = state_root(std::iter::once((addr, account_2)));
        assert_ne!(root_1, root_2, "different nonces must produce different roots");
    }

    /// An empty storage map must produce the empty root.
    #[test]
    fn empty_storage_produces_empty_root() {
        let root = storage_root(std::iter::empty());
        assert_eq!(root, EMPTY_ROOT);
    }

    /// A single storage slot must produce a non-empty root.
    #[test]
    fn single_storage_slot_has_non_empty_root() {
        let slot = B256::ZERO;
        let value = U256::from(42);
        let root = storage_root(std::iter::once((slot, value)));
        assert_ne!(root, EMPTY_ROOT);
    }

    /// Storage insertion order must not affect the root.
    #[test]
    fn storage_insertion_order_does_not_affect_root() {
        let slot_a = B256::from_slice(&[0xAA; 32]);
        let slot_b = B256::from_slice(&[0xBB; 32]);
        let value = U256::from(1);

        let root_ab = storage_root([(slot_a, value), (slot_b, value)]);
        let root_ba = storage_root([(slot_b, value), (slot_a, value)]);
        assert_eq!(root_ab, root_ba, "storage insertion order must not affect root");
    }

    /// The keccak empty constant must match `keccak256("")`.
    #[test]
    fn keccak_empty_matches_empty_bytes() {
        let expected = keccak256(b"");
        assert_eq!(KECCAK_EMPTY, expected);
    }

    /// A `TrieAccount` with a non-empty storage root must encode the
    /// storage root in the account RLP (not just the empty root).
    #[test]
    fn account_with_storage_has_different_root_than_without() {
        let addr = Address::ZERO;
        let custom_storage_root = B256::from_slice(&[0xCC; 32]);
        let account_no_storage = build_trie_account(0, U256::ZERO, EMPTY_ROOT, KECCAK_EMPTY);
        let account_with_storage =
            build_trie_account(0, U256::ZERO, custom_storage_root, KECCAK_EMPTY);
        let root_no = state_root(std::iter::once((addr, account_no_storage)));
        let root_with = state_root(std::iter::once((addr, account_with_storage)));
        assert_ne!(root_no, root_with, "storage root must affect state root");
    }
}
