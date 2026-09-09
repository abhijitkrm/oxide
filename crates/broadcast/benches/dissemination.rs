//! Oxide blockchain — benchmarks for the `broadcast` crate: the
//! erasure-coded dissemination hot path.
//!
//! `missing_docs` is allowed for this bench crate only.
#![allow(missing_docs)]
//!
//! Gates and baselines (source: `.devin/skills/benchmarks` §3):
//!
//! | Bench              | Gate (p50) | Baseline                       |
//! |--------------------|------------|--------------------------------|
//! | `broadcast_single` | < 5 µs     | chunk + hash + HashMap insert  |
//! | `can_reconstruct`  | < 1 µs     | HashMap lookup + count check   |

use broadcast::ErasureBroadcast;
use criterion::{Criterion, criterion_group, criterion_main};
use ports::BroadcastEngine;
use primitives::Hash;
use std::hint::black_box;
use types::{Proposal, TxBytes};

/// Build a proposal with `n` trivial txs for benching.
fn make_proposal(n: usize) -> Proposal {
    let txs: Vec<TxBytes> = (0..n).map(|_| TxBytes::new(vec![0xAA; 50])).collect();
    Proposal { height: primitives::Height::new(0), txs, attestation: None }
}

fn bench_broadcast(c: &mut Criterion) {
    // 4 validators, f=1 (smallest BFT config).
    let proposal = make_proposal(100);
    c.bench_function("broadcast_single", |b| {
        b.iter_batched(
            || ErasureBroadcast::new(4, 1),
            |mut eb| {
                let _ = eb.broadcast(&proposal);
                black_box(&eb);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_can_reconstruct(c: &mut Criterion) {
    // Benchmark the lookup path with a hash that is not stored
    // (worst case: full scan returns false quickly).
    let dummy = Hash::ZERO;
    let eb = ErasureBroadcast::new(4, 1);
    c.bench_function("can_reconstruct", |b| {
        b.iter(|| {
            let result = eb.can_reconstruct(black_box(&dummy));
            black_box(result);
        });
    });
}

criterion_group!(benches, bench_broadcast, bench_can_reconstruct);
criterion_main!(benches);
