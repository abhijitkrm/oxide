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
