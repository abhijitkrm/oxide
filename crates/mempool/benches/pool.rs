//! Oxide blockchain — benchmarks for the `mempool` crate: the
//! fee-priority transaction pool hot path.
//!
//! `missing_docs` is allowed for this bench crate only.
#![allow(missing_docs)]
//!
//! Gates and baselines (source: `.devin/skills/benchmarks` §3):
//!
//! | Bench                  | Gate (p50) | Baseline                       |
//! |------------------------|------------|--------------------------------|
//! | `submit_single`        | < 500 ns   | hash + BTreeMap insert         |
//! | `submit_batch_1000`    | < 500 µs   | amortized < 500 ns/tx          |
//! | `select_100_of_10000`  | < 100 µs   | fee-priority sort + nonce chk  |
//! | `contains_check`       | < 50 ns    | HashSet lookup                 |

use criterion::{Criterion, criterion_group, criterion_main};
use mempool::{Mempool, build_tx};
use primitives::Address;
use std::hint::black_box;

/// A fixed sender for bench txs.
fn sender() -> Address {
    Address([0x42; 20])
}

/// Pre-generate `n` txs with increasing nonces and a fee that
/// varies so the fee-priority sort has real work.
fn gen_txs(n: u64) -> Vec<types::TxBytes> {
    (0..n).map(|i| build_tx(sender(), i, 100 + i, &[0xAA; 50])).collect()
}

fn bench_submit_single(c: &mut Criterion) {
    let txs = gen_txs(1);
    c.bench_function("submit_single", |b| {
        let mut i = 0u64;
        b.iter(|| {
            let mut pool = Mempool::new(10_000);
            let _ = pool.submit(txs[0].clone());
            black_box(&pool);
            i += 1;
        });
        black_box(i);
    });
}

fn bench_submit_batch_1000(c: &mut Criterion) {
    let txs = gen_txs(1000);
    c.bench_function("submit_batch_1000", |b| {
        b.iter(|| {
            let mut pool = Mempool::new(10_000);
            for tx in &txs {
                let _ = pool.submit(tx.clone());
            }
            black_box(&pool);
        });
    });
}

fn bench_select_100_of_10000(c: &mut Criterion) {
    let txs = gen_txs(10_000);
    c.bench_function("select_100_of_10000", |b| {
        b.iter_batched(
            || {
                let mut pool = Mempool::new(10_000);
                for tx in &txs {
                    let _ = pool.submit(tx.clone());
                }
                pool
            },
            |mut pool| {
                let selected = pool.select(10_000);
                black_box(selected);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_contains(c: &mut Criterion) {
    let txs = gen_txs(1000);
    let mut pool = Mempool::new(10_000);
    for tx in &txs {
        let _ = pool.submit(tx.clone());
    }
    let hash = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, txs[0].as_bytes());
    c.bench_function("contains_check", |b| {
        b.iter(|| {
            let found = pool.contains(black_box(&hash));
            black_box(found);
        });
    });
}

criterion_group!(
    benches,
    bench_submit_single,
    bench_submit_batch_1000,
    bench_select_100_of_10000,
    bench_contains
);
criterion_main!(benches);
