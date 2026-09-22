//! Nonce-tracker contention benchmark — the multi-market matcher's
//! global replay gate.
//!
//! # What this measures
//!
//! Every admitted request — order or cancel/amend action — consumes
//! one nonce through a single `Mutex<NonceTracker>` shared across all
//! market workers and every dispatching thread (`submit_batch`
//! consumes per order on the caller's thread in batch order;
//! `MarketWorker::submit_action` consumes on the worker). The mutex
//! serializes the whole admission path: N concurrent submitters all
//! convoy on the same lock.
//!
//! This bench isolates that serialization from signature
//! verification and channel dispatch via the `bench_consume_nonce`
//! doc-hidden seam — the measured op is exactly the production gate:
//! one lock acquire + one `check_and_consume` (`HashMap` lookup +
//! insert + dirty counter).
//!
//! - `consume_{n}t`: N threads each consuming forward nonces over a
//!   disjoint 64k-owner range — the uncontended-data shape; every op
//!   still pays the global lock. Throughput is aggregate ops/s, so a
//!   flat line across thread counts *is* the serialization result.
//!
//! # Gate
//!
//! No hard gate — this bench exists to put a number on the audit's
//! "global nonce mutex contention" residual: whether the shared
//! replay gate is a throughput ceiling worth re-architecting (e.g.
//! per-account sharding, which the batch-order consumption rule
//! complicates) or already noise next to Ed25519 admission cost.
//!
//! # Running
//!
//! ```sh
//! cargo bench -p matcher --bench nonce_contention
//! ```
//!
#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use matcher::{AtomicBalanceCache, MultiMarketMatcher};
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};
use trading::MarketConfig;

use primitives::fixed::{Price, Qty};
/// Owners each thread cycles through — wide enough that the tracker's
/// `last_seen` map reaches a production-realistic population (8
/// threads × 64k = 512k entries) instead of a degenerate handful of
/// hot cache lines.
const OWNERS_PER_THREAD: u32 = 1 << 16;

/// Hash-shaped address — the form every production (Ed25519-derived)
/// account takes; distinct index → distinct owner.
fn owner_addr(i: u32) -> primitives::Address {
    let mut a = [0xABu8; 20];
    a[..4].copy_from_slice(&i.to_le_bytes());
    a[4..8].copy_from_slice(&i.rotate_left(13).to_le_bytes());
    primitives::Address(a)
}

/// Run `threads` workers, each consuming `iters` forward nonces
/// spread across its disjoint owner range (owner `base + i % RANGE`,
/// nonce `i / RANGE` — strictly forward per owner, as production
/// admission requires). Returns wall time.
fn run_contended(matcher: &Arc<MultiMarketMatcher>, threads: usize, iters: u64) -> Duration {
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let matcher = Arc::clone(matcher);
            handles.push(s.spawn(move || {
                let base = t as u32 * OWNERS_PER_THREAD;
                for i in 0..iters {
                    let owner = owner_addr(base + (i as u32 % OWNERS_PER_THREAD));
                    let nonce = i / u64::from(OWNERS_PER_THREAD);
                    black_box(matcher.bench_consume_nonce(&owner, nonce));
                }
            }));
        }
        let start = Instant::now();
        for h in handles {
            h.join().expect("worker thread panicked");
        }
        start.elapsed()
    })
}

fn nonce_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("nonce_tracker_contention");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(2));

    for threads in [1usize, 2, 4, 8] {
        group.throughput(Throughput::Elements(threads as u64));
        group.bench_function(format!("consume_{threads}t"), |b| {
            let cfg = MarketConfig {
                market_id: 0,
                tick_size: Price(1_000_000),
                lot_size: Qty(1_000),
                min_price: Price(1_000_000_000),
                max_price: Price(2_000_000_000),
                max_resting: 1 << 10,
            };
            let matcher = Arc::new(MultiMarketMatcher::new(
                vec![cfg],
                Arc::new(AtomicBalanceCache::new(1 << 10)),
            ));
            b.iter_custom(|iters| run_contended(&matcher, threads, iters));
        });
    }
    group.finish();
}

criterion_group!(benches, nonce_contention);
criterion_main!(benches);
