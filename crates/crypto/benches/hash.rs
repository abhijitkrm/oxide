//! Hashing benchmarks — the domain-separated BLAKE3 floor.
//!
//! This is the "hash floor" for the whole codebase: every hash call
//! (block, vote, QC, MMR node) amortizes to one of these. The gate is
//! informational in Phase 0 (no throughput requirement at the crate
//! level); the storage crate's MMR benches gate the structural
//! overhead on top of this floor.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use crypto::{Domain, Hasher};

fn bench_hash_one(c: &mut Criterion) {
    // 32-byte payload (the common case: hashing a Hash-sized input).
    let payload = [0x42u8; 32];
    c.bench_function("hash_one/32b", |b| {
        b.iter(|| black_box(Hasher::hash_one(Domain::Block, black_box(&payload))));
    });

    // 256-byte payload (a small block header).
    let payload256 = [0x42u8; 256];
    c.bench_function("hash_one/256b", |b| {
        b.iter(|| black_box(Hasher::hash_one(Domain::Block, black_box(&payload256))));
    });
}

fn bench_hash_pair(c: &mut Criterion) {
    // Binary node: domain ‖ left(32) ‖ right(32) — the MMR node shape.
    let left = [0x01u8; 32];
    let right = [0x02u8; 32];
    c.bench_function("hash_pair/32b+32b", |b| {
        b.iter(|| {
            black_box(Hasher::hash_pair(Domain::MmrNode, black_box(&left), black_box(&right)))
        });
    });
}

criterion_group!(benches, bench_hash_one, bench_hash_pair);
criterion_main!(benches);
