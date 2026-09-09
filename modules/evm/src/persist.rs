//! EVM state persistence — serialization between revm's `CacheDB` and
//! Oxide's `StorageBackend`.
//!
//! # Key scheme
//!
//! Each EVM account (balance, nonce, code, storage) is stored as a
//! single value under a 32-byte key:
//!
//! ```text
//! key = [0x01][address: 20B][0x00: 11B]   (32 bytes total)
//! ```
//!
//! The `0x01` namespace prefix lets `range([0x01])` enumerate all
//! EVM accounts in one scan — used by `load_from_storage` on
//! construction. A single value per account avoids the 32-byte key
//! length limit (address 20B + slot 32B = 52B doesn't fit in 32B).
//!
//! # Value format
//!
//! ```text
//! [balance:  32B big-endian U256]
//! [nonce:     8B big-endian u64]
//! [code_hash: 32B]
//! [code_len:  4B big-endian u32]
//! [code:      code_len bytes]
//! [n_slots:   4B big-endian u32]
//! [slot_0:    32B][value_0: 32B]
//! ...
//! [slot_N:    32B][value_N: 32B]
//! ```
//!
//! All fields are fixed-width big-endian for deterministic
//! serialization (two validators with the same state must produce
//! byte-identical values — consensus requirement).

use primitives::{Address, Hash};

/// Namespace prefix for EVM account keys.
const NS_ACCOUNT: u8 = 0x01;

/// Build the 32-byte storage key for an EVM account.
///
/// Format: `[0x01][address: 20B][0x00: 11B]` = 32 bytes.
pub(crate) fn account_key(addr: &Address) -> Hash {
    let mut key = [0u8; Hash::LEN];
    key[0] = NS_ACCOUNT;
    key[1..21].copy_from_slice(&addr.0);
    // Bytes 21..32 are zero-padded (unused space in the 32-byte key).
    Hash(key)
}

/// The namespace prefix for `range` queries that enumerate all
/// EVM accounts.
pub(crate) fn account_prefix() -> [u8; 1] {
    [NS_ACCOUNT]
}

/// Extract the 20-byte address from a 32-byte account key.
///
/// Returns `None` if the key doesn't have the `0x01` namespace
/// prefix (defensive — should never happen for keys written by
/// `account_key`).
pub(crate) fn key_to_address(key: &Hash) -> Option<Address> {
    if key.0[0] != NS_ACCOUNT {
        return None;
    }
    let mut addr = [0u8; Address::LEN];
    addr.copy_from_slice(&key.0[1..21]);
    Some(Address(addr))
}

/// Serialize an EVM account into a flat byte vector.
///
/// See the module docs for the value format.
pub(crate) fn serialize_account(
    balance: revm::primitives::U256,
    nonce: u64,
    code_hash: revm::primitives::B256,
    code: &[u8],
    storage: &[(revm::primitives::U256, revm::primitives::U256)],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(76 + code.len() + storage.len() * 64);
    out.extend_from_slice(&balance.to_be_bytes::<32>());
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(code_hash.as_slice());
    out.extend_from_slice(&(u32::try_from(code.len()).unwrap_or(u32::MAX)).to_be_bytes());
    out.extend_from_slice(code);
    out.extend_from_slice(&(u32::try_from(storage.len()).unwrap_or(u32::MAX)).to_be_bytes());
    for (slot, value) in storage {
        out.extend_from_slice(&slot.to_be_bytes::<32>());
        out.extend_from_slice(&value.to_be_bytes::<32>());
    }
    out
}

/// Deserialize an EVM account from a byte slice.
///
/// Returns `None` if the data is malformed (too short, truncated
/// code or storage). The caller treats `None` as "skip this entry"
/// during `load_from_storage` — a corrupted entry is a storage bug,
/// not a consensus fault.
pub(crate) struct DeserializedAccount {
    pub balance: revm::primitives::U256,
    pub nonce: u64,
    pub code_hash: revm::primitives::B256,
    pub code: Vec<u8>,
    pub storage: Vec<(revm::primitives::U256, revm::primitives::U256)>,
}

pub(crate) fn deserialize_account(data: &[u8]) -> Option<DeserializedAccount> {
    if data.len() < 76 {
        return None;
    }
    let balance = revm::primitives::U256::from_be_bytes(<[u8; 32]>::try_from(&data[0..32]).ok()?);
    let nonce = u64::from_be_bytes(data[32..40].try_into().ok()?);
    let code_hash = revm::primitives::B256::from_slice(&data[40..72]);
    let code_len = u32::from_be_bytes(data[72..76].try_into().ok()?) as usize;
    if data.len() < 76 + code_len + 4 {
        return None;
    }
    let code = data[76..76 + code_len].to_vec();
    let n_slots_offset = 76 + code_len;
    let n_slots =
        u32::from_be_bytes(data[n_slots_offset..n_slots_offset + 4].try_into().ok()?) as usize;
    let storage_offset = n_slots_offset + 4;
    if data.len() < storage_offset + n_slots * 64 {
        return None;
    }
    let mut storage = Vec::with_capacity(n_slots);
    let mut off = storage_offset;
    for _ in 0..n_slots {
        let slot =
            revm::primitives::U256::from_be_bytes(<[u8; 32]>::try_from(&data[off..off + 32]).ok()?);
        let value = revm::primitives::U256::from_be_bytes(
            <[u8; 32]>::try_from(&data[off + 32..off + 64]).ok()?,
        );
        storage.push((slot, value));
        off += 64;
    }
    Some(DeserializedAccount { balance, nonce, code_hash, code, storage })
}
