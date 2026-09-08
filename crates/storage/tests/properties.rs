//! Property tests for the `storage` crate (testing-standards skill,
//! Layer 2). The properties here are the ones the spec calls
//! invariants — a violation is a protocol bug, not a flaky test.

use primitives::Hash;
use proptest::prelude::*;
use storage::backend::{Op, StorageBackend, Volatile};
use storage::journal::{self, JournalConfig, JournalWriter};
use storage::mmr::{self, Mmr};

/// Any strategy over bytes → payload sizes the journal accepts.
fn payload() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..256)
}

/// Unique temp dir per property case (counter keeps parallel cases
/// from colliding; process id keeps runs from colliding).
fn temp_dir(case: u32) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("oxide-storage-prop-{}-{case}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

proptest! {
    /// Spec §2 invariant: replay(append(xs)) == xs, in order, for any
    /// payload sequence — including empty payloads and exact-capacity
    /// edge sizes. The journal is the recovery source of truth; a
    /// round-trip failure means state is unreconstructible.
    #[test]
    fn prop_journal_replay_round_trip(records in proptest::collection::vec(payload(), 0..128)) {
        let dir = temp_dir(0);
        let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
        let mut locs = Vec::new();
        for r in &records {
            locs.push(j.append(r).unwrap());
        }
        j.sync().unwrap();
        let replayed = journal::replay(&dir).unwrap();
        prop_assert!(replayed.truncated_at.is_none());
        prop_assert_eq!(replayed.records.len(), records.len());
        for (i, rec) in replayed.records.iter().enumerate() {
            prop_assert_eq!(rec.payload.as_slice(), records[i].as_slice());
            prop_assert_eq!(rec.location, locs[i]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Spec §2 rule 1, modeled exactly: for ANY cut position in the
    /// flushed file, replay returns precisely the records fully
    /// contained in the prefix, and reports `truncated_at` iff the cut
    /// lands inside the header or inside a record's bytes (a cut at a
    /// record boundary leaves a clean prefix — no torn tail to report).
    /// The expected values are derived from the byte layout here, so
    /// this property is the replay contract, not an approximation.
    #[test]
    fn prop_journal_arbitrary_cut_returns_complete_prefix(
        records in proptest::collection::vec(payload(), 1..64),
        cut in proptest::num::u32::ANY,
    ) {
        let dir = temp_dir(1);
        let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
        for r in &records {
            j.append(r).unwrap();
        }
        j.sync().unwrap();
        let path = dir.join("segment-0.log");
        let full = std::fs::read(&path).unwrap();
        // Any cut in [0, file_len]: u32::ANY % (len+1) covers all of
        // them uniformly (len ≤ 64 × 264B, far below u32 range).
        let cut = (cut as usize) % (full.len() + 1);
        std::fs::write(&path, &full[..cut]).unwrap();

        // Model the expected outcome from the layout:
        // [header 8B][record: 8B framing + payload]…
        let header = 8usize;
        let mut used = header;
        let mut expected_count = 0usize;
        let mut expected_truncated = cut < header; // cut inside header
        for r in &records {
            let record_total = 8 + r.len();
            if cut >= used + record_total {
                expected_count += 1;
                used += record_total;
            } else {
                // Cut ended inside this record's bytes (strictly past
                // its start) → torn tail. Exactly at its start → clean
                // prefix boundary, no torn tail.
                if cut > used {
                    expected_truncated = true;
                }
                break;
            }
        }

        let replayed = journal::replay(&dir).unwrap();
        prop_assert_eq!(
            replayed.truncated_at.is_some(),
            expected_truncated,
            "truncation flag must match the layout model for the cut position"
        );
        prop_assert_eq!(replayed.records.len(), expected_count, "complete-prefix count");
        for (i, rec) in replayed.records.iter().enumerate() {
            prop_assert_eq!(rec.payload.as_slice(), records[i].as_slice());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Spec §3 invariant 1: for any leaf count and any in-range leaf,
    /// the proof verifies against the root for exactly that count.
    #[test]
    fn prop_mmr_every_leaf_proves(
        n in 1u64..256,
        leaf_index in any::<u64>(),
    ) {
        let leaf_index = leaf_index % n; // clamp into range
        let mut m = Mmr::new();
        for i in 0..n {
            m.push(mmr::hash_leaf(&i.to_le_bytes()));
        }
        let root = m.root();
        let proof = m.proof(leaf_index).unwrap();
        prop_assert!(Mmr::verify(&mmr::hash_leaf(&leaf_index.to_le_bytes()), &proof, &root));
        // Structural law (spec §3): n leaves ⇒ 2n − popcount(n) nodes.
        prop_assert_eq!(m.node_count(), usize::try_from(2 * n - u64::from(n.count_ones())).unwrap());
    }

    /// Spec §3 invariant 2: a wrong leaf (any other preimage) must NOT
    /// verify against the same proof and root.
    #[test]
    fn prop_mmr_wrong_leaf_fails(
        n in 1u64..256,
        leaf_index in any::<u64>(),
        wrong in any::<u64>(),
    ) {
        let leaf_index = leaf_index % n;
        let mut m = Mmr::new();
        for i in 0..n {
            m.push(mmr::hash_leaf(&i.to_le_bytes()));
        }
        let root = m.root();
        let proof = m.proof(leaf_index).unwrap();
        let wrong_leaf = mmr::hash_leaf(&wrong.to_le_bytes());
        // Only a genuine collision-equivalent (same hash) could pass —
        // BLAKE3-256 makes that probability negligible for the strategy.
        prop_assert!(
            !Mmr::verify(&wrong_leaf, &proof, &root)
                || wrong_leaf == mmr::hash_leaf(&leaf_index.to_le_bytes())
        );
    }

    /// Spec §3 invariant 3: identical push sequences ⇒ identical roots
    /// (determinism — two validators must compute the same commitment).
    #[test]
    fn prop_mmr_determinism(values in proptest::collection::vec(any::<u64>(), 0..64)) {
        let build = |vals: &[u64]| {
            let mut m = Mmr::new();
            for v in vals {
                m.push(mmr::hash_leaf(&v.to_le_bytes()));
            }
            m.root()
        };
        prop_assert_eq!(build(&values), build(&values));
    }

    /// Spec §4: `Volatile` batch application is last-op-wins per key and
    /// `range` returns exactly the prefix matches in key order — the
    /// oracle semantics every future backend is diffed against.
    #[test]
    fn prop_volatile_batch_and_range(
        ops in proptest::collection::vec(
            (any::<u8>(), any::<bool>(), proptest::collection::vec(any::<u8>(), 0..32)),
            0..64
        ),
    ) {
        let mut store = Volatile::new();
        let batch: Vec<Op> = ops
            .iter()
            .map(|&(tag, is_set, ref value)| {
                let mut key = [0x77u8; 32];
                key[0] = tag;
                if is_set {
                    Op::Set { key: Hash(key), value: value.clone() }
                } else {
                    Op::Delete { key: Hash(key) }
                }
            })
            .collect();
        store.apply_batch(&batch);
        // Model: fold the same ops over a HashMap.
        let mut model = std::collections::BTreeMap::new();
        for op in &batch {
            match op {
                Op::Set { key, value } => { model.insert(*key, value.clone()); }
                Op::Delete { key } => { model.remove(key); }
            }
        }
        // Every model key matches the store (full-width prefix range is
        // an exact-key lookup by construction, so range(&[]) diffs all).
        let all = store.range(&[]);
        prop_assert_eq!(all.len(), model.len());
        for (k, v) in all {
            prop_assert_eq!(model.get(&k), Some(&v));
        }
    }
}
