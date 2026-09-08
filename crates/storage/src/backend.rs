//! The `StorageBackend` port and its in-memory reference implementation
//! (docs/storage-spec.md §4, plan.md §2.3).
//!
//! ## What this module is
//!
//! The seam every state consumer (executor, modules, RPC) talks to, and
//! the seam future adapters (journal-backed authenticated store in
//! Phase 1; MDBX/RocksDB cold tiers in Phase 2) implement. `Volatile`
//! is the correctness-first `BTreeMap` implementation used by sims, tests,
//! and as the conformance oracle — deliberately boring, because its job
//! is to define *right*, not *fast*.
//!
//! ## Why a trait at all
//!
//! Plug-and-play is a plan.md §2 requirement (the cosmos-evm lesson),
//! but a seam is only real if it is *narrow*: v0 exposes exactly the
//! operations the executor needs today. Snapshots, range streaming, and
//! proofs arrive with the phases that need them (spec §5) — never
//! speculatively, because every speculative method is an API every
//! future adapter must honor forever.
//!
//! ## Invariants
//!
//! - `apply_batch` is atomic per call: the block committer applies one
//!   batch per committed block; a partial application is a
//!   protocol-level bug, not a recoverable state.
//! - `Caps::authenticated` is a *claim the backend must prove* in the
//!   storage-conformance suite (Phase 2) before node wiring lets a
//!   validator run it.

use primitives::Hash;

/// One state operation inside a block batch.
///
/// Keys are 32 bytes (plan.md §8 sizing: `Hash`-sized keys). Values are
/// owned blobs — batch application is a cold-path event (once per
/// block), so the copy is irrelevant next to the IO it amortizes.
///
/// Codec impls arrive with the executor wiring (Phase 1), per spec §5 —
/// not before, per YAGNI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Set `key` to `value` (upsert; creating is the same operation —
    /// the journal represents both identically, per the QMDB model).
    Set {
        /// Target key.
        key: Hash,
        /// New value.
        value: Vec<u8>,
    },
    /// Remove `key` (absent keys are a no-op — deletes in a log-backed
    /// world are tombstones, not errors).
    Delete {
        /// Target key.
        key: Hash,
    },
}

/// What a backend guarantees. The seam between "correct" and "correct
/// and verifiable": validators must run authenticated backends (node
/// wiring enforces this in Phase 1+); `Volatile` is legal for followers,
/// sims, and tests only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Caps {
    /// Backend maintains authenticated state roots and proofs.
    ///
    /// `false` today for `Volatile` by design; the journal-backed store
    /// (Phase 1) flips this and must pass the storage-conformance suite
    /// to be registerable.
    pub authenticated: bool,
}

/// The storage seam (spec §4). Deliberately minimal v0.
///
/// Lifetimes: `get` borrows from `self` so in-RAM backends are zero-copy
/// reads; adapters over remote/disk stores materialize instead — both
/// fit the signature.
pub trait StorageBackend {
    /// What this backend guarantees.
    fn capabilities(&self) -> Caps;

    /// Point read of a key's current value.
    fn get(&self, key: &Hash) -> Option<&[u8]>;

    /// All key-value pairs whose 32-byte key starts with `prefix`
    /// (any length ≤ 32 — module namespaces are short), in key order
    /// (deterministic iteration is a conformance requirement, spec §4).
    /// Materializing is fine: this is a cold-path query API.
    ///
    /// # Errors
    /// None — a prefix longer than 32 bytes simply matches nothing
    /// (keys are exactly 32 bytes); callers get an empty vector.
    fn range(&self, prefix: &[u8]) -> Vec<(Hash, Vec<u8>)>;

    /// Apply one atomic batch (block commit). Order within the batch is
    /// the write order; the last op for a key wins.
    fn apply_batch(&mut self, ops: &[Op]);
}

/// In-memory reference backend: a `BTreeMap` keyed by the full 32-byte
/// key. O(log n) ops, deterministic ordered iteration, no
/// authentication — the oracle other backends are diffed against.
///
/// Prefix `range` exploits `Hash`'s `Ord` (lexicographic over bytes):
/// the prefix's successor bounds the scan, so `range` costs one tree
/// walk, not a full scan.
#[derive(Debug, Default)]
pub struct Volatile {
    map: std::collections::BTreeMap<Hash, Vec<u8>>,
}

impl Volatile {
    /// Empty store.
    pub fn new() -> Self {
        Volatile { map: std::collections::BTreeMap::new() }
    }

    /// Number of live keys (test/sim assertions).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no keys are live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Lexicographic bounds covering exactly the keys that start with
    /// `prefix` (any length ≤ 32; longer prefixes match nothing — see
    /// the trait's `range` doc).
    ///
    /// Returns `(lo, hi)`: keys in `[lo, hi)` start with the prefix.
    /// `lo` is the prefix zero-padded to 32 bytes; `hi` is the prefix
    /// with its last byte incremented (then zero-padded), or `None`
    /// when the prefix is all `0xFF` (the range runs to the end of the
    /// keyspace).
    fn prefix_bounds(prefix: &[u8]) -> (Hash, Option<Hash>) {
        let mut lo = [0u8; Hash::LEN];
        let take = prefix.len().min(Hash::LEN);
        lo[..take].copy_from_slice(&prefix[..take]);
        if prefix.is_empty() {
            // Empty prefix matches every key: [0x00…, end).
            return (Hash(lo), None);
        }
        // Increment the prefix's last byte; all-0xFF carries to None.
        let mut succ = prefix.to_vec();
        let mut carry = true;
        for i in (0..succ.len()).rev() {
            if succ[i] != 0xFF {
                succ[i] += 1;
                carry = false;
                break;
            }
        }
        if carry {
            return (Hash(lo), None);
        }
        let mut hi = [0u8; Hash::LEN];
        hi[..succ.len()].copy_from_slice(&succ);
        (Hash(lo), Some(Hash(hi)))
    }
}

impl StorageBackend for Volatile {
    fn capabilities(&self) -> Caps {
        Caps { authenticated: false }
    }

    fn get(&self, key: &Hash) -> Option<&[u8]> {
        self.map.get(key).map(std::vec::Vec::as_slice)
    }

    fn range(&self, prefix: &[u8]) -> Vec<(Hash, Vec<u8>)> {
        // Prefixes longer than the key width match nothing by
        // definition (keys are exactly 32 bytes).
        if prefix.len() > Hash::LEN {
            return Vec::new();
        }
        // BTreeMap's ordered range: [lo, hi) — everything starting with
        // the prefix, and nothing else; one tree walk, not a scan.
        let (lo, hi) = Self::prefix_bounds(prefix);
        let mut out = Vec::new();
        let iter = hi.map_or_else(|| self.map.range(lo..), |hi| self.map.range(lo..hi));
        for (k, v) in iter {
            out.push((*k, v.clone()));
        }
        out
    }

    fn apply_batch(&mut self, ops: &[Op]) {
        for op in ops {
            match op {
                Op::Set { key, value } => {
                    self.map.insert(*key, value.clone());
                }
                Op::Delete { key } => {
                    self.map.remove(key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Hash {
        // Distinct keys sharing a prefix are the interesting range case.
        let mut k = [0xAA; 32];
        k[0] = b;
        Hash(k)
    }

    /// Set/get/delete round trip, including delete-of-absent (no-op).
    #[test]
    fn test_set_get_delete_round_trip() {
        let mut store = Volatile::new();
        let k = key(1);
        assert_eq!(store.get(&k), None);
        store.apply_batch(&[Op::Set { key: k, value: b"v1".to_vec() }]);
        assert_eq!(store.get(&k), Some(b"v1".as_slice()));
        // Upsert semantics: a second Set overwrites.
        store.apply_batch(&[Op::Set { key: k, value: b"v2".to_vec() }]);
        assert_eq!(store.get(&k), Some(b"v2".as_slice()));
        store.apply_batch(&[Op::Delete { key: k }]);
        assert_eq!(store.get(&k), None);
        // Delete of an absent key is a tombstone no-op, not an error.
        store.apply_batch(&[Op::Delete { key: k }]);
        assert_eq!(store.get(&k), None);
    }

    /// Batch atomicity surface: last-op-wins within a batch, applied in
    /// order — the property block commit relies on.
    #[test]
    fn test_batch_order_last_op_wins() {
        let mut store = Volatile::new();
        let k = key(7);
        store.apply_batch(&[
            Op::Set { key: k, value: b"first".to_vec() },
            Op::Set { key: k, value: b"second".to_vec() },
            Op::Delete { key: key(8) },
        ]);
        assert_eq!(store.get(&k), Some(b"second".as_slice()));
    }

    /// Prefix range: only matching keys, in deterministic order, up to
    /// and including the all-`0xFF` prefix edge case.
    #[test]
    fn test_range_prefix_ordered_and_exact() {
        let mut store = Volatile::new();
        let with_prefix = |last: u8| {
            let mut k = [0x42; 32];
            k[31] = last;
            Hash(k)
        };
        store.apply_batch(&[
            Op::Set { key: with_prefix(1), value: vec![1] },
            Op::Set { key: with_prefix(3), value: vec![3] },
            Op::Set { key: with_prefix(2), value: vec![2] },
            Op::Set { key: key(9), value: vec![9] }, // different first byte
        ]);
        // 1-byte namespace prefix: matches all three 0x42… keys.
        let hits = store.range(&[0x42]);
        assert_eq!(hits.len(), 3, "non-matching keys excluded");
        let lasts: Vec<u8> = hits.iter().map(|(k, _)| k.as_bytes()[31]).collect();
        assert_eq!(lasts, vec![1, 2, 3], "deterministic key order");
        // Empty prefix = the whole store, in key order.
        assert_eq!(store.range(&[]).len(), 4);
        // All-0xFF prefix runs to the end of the keyspace harmlessly.
        assert!(store.range(&[0xFF]).is_empty());
        // Prefixes longer than the key width match nothing.
        assert!(store.range(&[0x42; 33]).is_empty());
    }

    /// Capabilities are honest by construction: Volatile claims no
    /// authentication.
    #[test]
    fn test_volatile_caps_unauthenticated() {
        let store = Volatile::new();
        assert_eq!(store.capabilities(), Caps { authenticated: false });
    }
}
