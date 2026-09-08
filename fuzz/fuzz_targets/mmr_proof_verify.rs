#![no_main]
//! Fuzz target: MMR proof verification over arbitrary (possibly
//! forged) proofs.
//!
//! `Mmr::verify` must never panic on any proof structure — a
//! forged proof simply returns `false`. This target constructs an MMR,
//! then feeds arbitrary bytes as a (possibly forged) proof and
//! asserts `verify` never panics, only returns `true` or `false`.

use primitives::Hash;
use storage::mmr::{Mmr, MmrProof, PathStep};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // Build a small MMR so we have a real root and leaf to test
    // against. The fuzz input is used to construct a *forged* proof:
    // arbitrary path steps and peaks derived from the bytes.
    let mut mmr = Mmr::new();
    for i in 0u8..8 {
        mmr.push(Hash([i; 32]));
    }
    let root = mmr.root();
    let leaf = Hash([0u8; 32]);

    // Construct a forged proof from arbitrary bytes. We don't care
    // about the proof being valid — we care that verify never panics
    // on any structure. Parse bytes into path steps and peaks.
    if data.len() < 16 {
        // Not enough for a leaf_index + leaf_count; still call verify
        // with a degenerate proof.
        let proof = MmrProof {
            leaf_index: 0,
            leaf_count: 0,
            path: Vec::new(),
            peaks: Vec::new(),
        };
        let _ = Mmr::verify(&leaf, &proof, &root);
        return;
    }

    let leaf_index = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0u8; 8]));
    let leaf_count = u64::from_le_bytes(data[8..16].try_into().unwrap_or([0u8; 8]));
    let rest = &data[16..];

    // Parse path steps: each step is 32 bytes (sibling) + 1 byte (side).
    let mut path = Vec::new();
    let mut cursor = rest;
    while cursor.len() >= 33 {
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&cursor[..32]);
        let target_is_left = cursor[32] != 0;
        path.push(PathStep {
            sibling: Hash(sibling),
            target_is_left,
        });
        cursor = &cursor[33..];
    }

    // Remaining bytes are peaks (32 bytes each).
    let mut peaks = Vec::new();
    while cursor.len() >= 32 {
        let mut peak = [0u8; 32];
        peak.copy_from_slice(&cursor[..32]);
        peaks.push(Hash(peak));
        cursor = &cursor[32..];
    }

    let proof = MmrProof {
        leaf_index,
        leaf_count,
        path,
        peaks,
    };

    // Must not panic — only return true or false.
    let _ = Mmr::verify(&leaf, &proof, &root);
});
