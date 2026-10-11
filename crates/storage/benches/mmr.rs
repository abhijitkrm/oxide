//! Oxide blockchain — `storage` crate MMR benchmarks.
//!
//! Gates (source: docs/storage-spec.md §3 — the interpretation is fixed
//! there: root maintenance is *incremental*, so the gate is the
//! amortized per-push cost; dev Mac = relative claims only until the
//! 16-core `x86_64` rig exists):
//!
//! | Bench                     | Gate                        |
//! |---------------------------|-----------------------------|
//! | `mmr/push_amortized`      | p50 < 20 ns (⇒ 1M ops < 20 ms, pre-hashed leaves) |
//! | `mmr/root_after_pushes`   | informational (bagging only) |
//! | `mmr/root_16_peaks`       | informational: fixed 2^16−1-leaf forest, reproducible bagging cost |
//! | `mmr/full_build_1m`       | informational: total wall-clock for 1M leaves incl. leaf hashing — hash-throughput-bound by design (spec §3) |
//!
//! Framing for `push_amortized`: leaves are **pre-hashed outside the
//! timed loop** (the spec's contract — callers hash their payloads once
//! via `hash_leaf`; the MMR's job is structure + internal-node hashing,
//! which is information-theoretically ≤ 1 hash per push).
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Instant;
use storage::Mmr;
use storage::mmr::hash_leaf;

fn bench_mmr(c: &mut Criterion) {
    // Amortized push: cycle a pool of pre-hashed leaves; the loop is
    // pure MMR work (leaf vec push + merge cascade + internal hashing).
    // Pool is a power of two so the cycle wraps with a mask.
    let leaves: Vec<_> = (0..4096u64).map(|i| hash_leaf(&i.to_le_bytes())).collect();
    let mut mmr = Mmr::new();
    let mut next = 0usize;
    c.bench_function("mmr/push_amortized", |b| {
        b.iter(|| {
            mmr.push(black_box(leaves[next]));
            next = (next + 1) & (leaves.len() - 1);
        });
        // Keep the accumulated state observable across samples.
        let _ = black_box(mmr.leaf_count());
    });

    // Root after pushes: bagging cost only (peaks + finalize) — cheap
    // and stable, which is the point of incremental maintenance.
    c.bench_function("mmr/root_after_pushes", |b| {
        b.iter(|| black_box(mmr.root()));
    });

    // Root over a fixed forest shape: 2^16 − 1 leaves = 16 peaks, the
    // worst case for its size. Unlike `root_after_pushes` (whose leaf
    // count depends on how many iterations the push bench ran), this
    // row is reproducible run to run (hft-audit-2 S-10).
    {
        let mut fixed = Mmr::new();
        for i in 0..(1u64 << 16) - 1 {
            fixed.push(leaves[usize::try_from(i & 4095).unwrap()]);
        }
        c.bench_function("mmr/root_16_peaks", |b| {
            b.iter(|| black_box(black_box(&fixed).root()));
        });
    }

    // The hash floor: one internal-node hash (65-byte preimage = two
    // BLAKE3 compression blocks). Every push amortizes to exactly ≤1 of
    // these (n leaves ⇒ n−1 internal nodes), so `push_amortized −
    // hash_node_65b` is the MMR's structure-only overhead — the part
    // this codebase controls. Not gated; it *is* the decomposition the
    // gate depends on (docs/storage-spec.md §3).
    {
        let left = leaves[0];
        let right = leaves[1];
        c.bench_function("mmr/hash_node_65b", |b| {
            b.iter(|| black_box(storage::mmr::hash_node(black_box(&left), black_box(&right))));
        });
    }

    // Informational: full 1M-leaf build, leaf hashing included. This is
    // the number "how long until the root commits a million ops" —
    // dominated by BLAKE3 throughput over ~64 MB of internal-node
    // preimages (spec §3), NOT by MMR structure ops. Not gated; the
    // gated amortized push above isolates the structure cost.
    c.bench_function("mmr/full_build_1m", |b| {
        b.iter_custom(|iters| {
            let mut elapsed = std::time::Duration::ZERO;
            for _ in 0..iters {
                let mut m = Mmr::new();
                let start = Instant::now();
                for i in 0..1_000_000u64 {
                    m.push(hash_leaf(&i.to_le_bytes()));
                }
                let root = m.root();
                elapsed += start.elapsed();
                black_box(root);
            }
            elapsed
        });
    });
}

criterion_group!(benches, bench_mmr);
criterion_main!(benches);
