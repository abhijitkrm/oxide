//! Oxide blockchain — benchmarks for the `evm` module's fee crate:
//! the EIP-1559 base-fee adjustment (runs once per block).
//!
//! `missing_docs` is allowed for this bench crate only.
#![allow(missing_docs)]
//!
//! Gates and baselines (source: `.devin/skills/benchmarks` §3):
//!
//! | Bench                       | Gate (p50) | Baseline                       |
//! |-----------------------------|------------|--------------------------------|
//! | `fee_update_single`         | < 50 ns    | u128 mul/div + comparison      |
//! | `fee_update_100_congested`  | < 5 µs     | 100× single update             |
//! | `fee_update_100_alternating`| < 5 µs     | 100× single update             |

use criterion::{Criterion, criterion_group, criterion_main};
use evm::fee::BaseFeeState;
use std::hint::black_box;

fn bench_fee_update_single(c: &mut Criterion) {
    let mut fee = BaseFeeState::new(1_000_000_000, 30_000_000);
    c.bench_function("fee_update_single", |b| {
        b.iter(|| {
            let next = fee.update(black_box(30_000_000));
            black_box(next);
        });
    });
}

fn bench_fee_update_100_congested(c: &mut Criterion) {
    c.bench_function("fee_update_100_congested", |b| {
        b.iter(|| {
            let mut fee = BaseFeeState::new(1_000_000_000, 30_000_000);
            for _ in 0..100 {
                let next = fee.update(30_000_000);
                black_box(next);
            }
        });
    });
}

fn bench_fee_update_100_alternating(c: &mut Criterion) {
    c.bench_function("fee_update_100_alternating", |b| {
        b.iter(|| {
            let mut fee = BaseFeeState::new(1_000_000_000, 30_000_000);
            for i in 0..100u64 {
                let gas = if i % 2 == 0 { 30_000_000 } else { 0 };
                let next = fee.update(gas);
                black_box(next);
            }
        });
    });
}

criterion_group!(
    benches,
    bench_fee_update_single,
    bench_fee_update_100_congested,
    bench_fee_update_100_alternating
);
criterion_main!(benches);
