//! Balance-cache contention benchmark — the multi-market matcher's
//! shared-state bottleneck.
//!
//! # What this measures
//!
//! The `MultiMarketMatcher` workers all share one
//! `ShardedBalanceCache`. Every buy order does `check_and_debit`
//! (reserve quote) and every fill does `credit` (pay the seller) —
//! both against accounts that market threads may share. This bench
//! isolates that shared-state cost from matching itself:
//!
//! - `spread_{n}t`: N threads each hammering disjoint canonical
//!   account ranges — measures the *uncontended* op cost (Mutex
//!   acquire vs atomic read-modify-write).
//! - `hot64_{n}t`: N threads all hitting the same 64 canonical
//!   accounts — measures the *contended* case.
//! - `prod_spread_{n}t` / `prod_hot64_{n}t`: the same shapes but on
//!   hash-shaped addresses — the form every production
//!   (Ed25519-derived) account actually takes. These resolve through
//!   the address registry into per-account atomic slots.
//! - `sparse_{n}t`: hash addresses beyond registry capacity —
//!   forced onto the global `Mutex<HashMap>` overflow. This is the
//!   only remaining serialized path, and stands in for what *all*
//!   production traffic paid before the registry tier existed.
//!
//! Each op pair is `check_and_debit(a, 1)` + `credit(a, 1)` — net
//! zero, so balances never drain and the loop runs indefinitely.
//!
//! # Gate
//!
//! No hard gate — this bench exists to *measure* the lock-free
//! rewrite: the acceptance criterion was a throughput improvement
//! at ≥4 threads.
//!
//! ## Measured results (M-series dev Mac, criterion p50)
//!
//! Figures below are per debit+credit pair — lower is better.
//!
//! Mutex-per-shard `HashMap` → per-account `AtomicU64` flat array
//! (historical, canonical addresses):
//!
//! | Bench | Mutex impl | Atomic impl | Speedup |
//! |-------|-----------|-------------|---------|
//! | `spread_1t` | 8.9M ops/s | 158M ops/s | ~18× |
//! | `hot64_1t` | 30M ops/s | 159M ops/s | ~5× |
//! | `spread_4t` | 18.7M ops/s | 465M ops/s | ~25× |
//! | `hot64_4t` | 30.6M ops/s | 124M ops/s | ~4× |
//! | `spread_8t` | 22.2M ops/s | 670M ops/s | ~30× |
//! | `hot64_8t` | 28.4M ops/s | ~89M ops/s | ~3× |
//!
//! Registry tier (`prod_*`, hash-shaped addresses) vs the global
//! `Mutex<HashMap>` overflow (`sparse_*`) — the path all production
//! traffic took before registration existed:
//!
//! | Bench | sparse (mutex) | registered (lock-free) | flat ref | reg vs sparse |
//! |-------|---------------|------------------------|----------|---------------|
//! | `spread_1t` | 53.0 ns | 55.8 ns | 11.0 ns | ~1× |
//! | `spread_4t` | 972.9 ns | 56.4 ns | 11.6 ns | ~17× |
//! | `spread_8t` | 1444 ns | 87.1 ns | 16.1 ns | ~17× |
//! | `hot64_4t` | — | 103.2 ns | 81.2 ns | — |
//! | `hot64_8t` | — | 279.3 ns | 258.4 ns | — |
//!
//! The sparse path serializes globally — it cannot scale past ~20M
//! ops/s aggregate however many threads run. The registered path
//! costs ~45 ns/pair of probe overhead over flat at 1 thread but
//! scales identically (~140M→184M ops/s at 4t→8t), and on the
//! contended `hot64` shape it tracks the flat tier within ~30% —
//! CAS retries on the account words dominate both.
//!
//! `hot64_*` (all threads on the same 64 accounts) is the real-
//! contention case — CAS retries on the same cache lines bound it,
//! not lock convoys.
//!
//! # Running
//!
//! ```sh
//! cargo bench -p matcher --bench balance_contention
//! ```

#![allow(missing_docs)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use matcher::ShardedBalanceCache;
use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Number of accounts in the cache's flat region.
const ACCOUNTS: u32 = 1_000_000;
/// Accounts each thread touches in the contended variant — all
/// threads share the same small set, forcing real conflicts.
const HOT_ACCOUNTS: u32 = 64;

/// Deterministic sequential address: `[u32 index LE][0; 16]` — the
/// canonical form that lives in the flat array.
fn addr_idx(i: u32) -> primitives::Address {
    let mut a = [0u8; 20];
    a[..4].copy_from_slice(&i.to_le_bytes());
    primitives::Address(a)
}

/// Hash-shaped address — the form production accounts take
/// (Ed25519-pubkey-derived). Index bytes from `i`, tail non-zero so
/// the canonical flat-array check rejects it and the address routes
/// through the registry tier (or the sparse overflow once `reg` is
/// exhausted).
fn hash_addr(i: u32) -> primitives::Address {
    let mut a = [0xABu8; 20];
    a[..4].copy_from_slice(&i.to_le_bytes());
    a[4..8].copy_from_slice(&i.rotate_left(13).to_le_bytes());
    primitives::Address(a)
}

/// Run `threads` workers, each doing `iters` debit+credit pairs on
/// accounts chosen by `pick(thread_id, op_index)`, built by
/// `mk_addr`. Returns wall time.
fn run_contended(
    cache: &Arc<ShardedBalanceCache>,
    threads: usize,
    iters: u64,
    mk_addr: impl Fn(u32) -> primitives::Address + Sync,
    pick: impl Fn(usize, u64) -> u32 + Sync,
) -> Duration {
    let mk_addr = &mk_addr;
    let pick = &pick;
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        for t in 0..threads {
            let cache = Arc::clone(cache);
            handles.push(s.spawn(move || {
                for i in 0..iters {
                    let a = mk_addr(pick(t, i));
                    // Debit then refund — net zero, both hot ops hit.
                    black_box(cache.check_and_debit(&a, 1));
                    cache.credit(&a, 1);
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

fn balance_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("balance_cache_contention");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(2));

    for threads in [1usize, 4, 8] {
        // Spread: thread t owns the disjoint range
        // [t*stride, (t+1)*stride) — zero real account conflicts.
        // One criterion "iteration" = one debit+credit pair per
        // thread (2×threads ops); each thread performs `iters` pairs.
        group.throughput(Throughput::Elements(2 * threads as u64));
        group.bench_function(format!("spread_{threads}t"), |b| {
            let cache = Arc::new(ShardedBalanceCache::new(ACCOUNTS as usize));
            for i in 0..ACCOUNTS {
                cache.set(&addr_idx(i), u64::MAX / 4);
            }
            let stride = ACCOUNTS as usize / threads;
            b.iter_custom(|iters| {
                run_contended(&cache, threads, iters, addr_idx, |t, i| {
                    (t * stride + (i as usize % stride)) as u32
                })
            });
        });

        // Hot: all threads hit the same 64 accounts — the worst
        // realistic conflict rate (popular market-makers).
        group.throughput(Throughput::Elements(2 * threads as u64));
        group.bench_function(format!("hot64_{threads}t"), |b| {
            let cache = Arc::new(ShardedBalanceCache::new(ACCOUNTS as usize));
            for i in 0..ACCOUNTS {
                cache.set(&addr_idx(i), u64::MAX / 4);
            }
            b.iter_custom(|iters| {
                run_contended(&cache, threads, iters, addr_idx, |_t, i| {
                    (i % u64::from(HOT_ACCOUNTS)) as u32
                })
            });
        });

        // Production-address spread: hash-shaped accounts on
        // disjoint ranges — the uncontended form of what real
        // traffic costs now (registry read-lock + atomic op).
        group.throughput(Throughput::Elements(2 * threads as u64));
        group.bench_function(format!("prod_spread_{threads}t"), |b| {
            let cache = Arc::new(ShardedBalanceCache::new(ACCOUNTS as usize));
            for i in 0..ACCOUNTS {
                cache.set(&hash_addr(i), u64::MAX / 4);
            }
            let stride = ACCOUNTS as usize / threads;
            b.iter_custom(|iters| {
                run_contended(&cache, threads, iters, hash_addr, |t, i| {
                    (t * stride + (i as usize % stride)) as u32
                })
            });
        });

        // Production-address hot set: same 64 hash accounts across
        // all threads — registered-slot CAS contention.
        group.throughput(Throughput::Elements(2 * threads as u64));
        group.bench_function(format!("prod_hot64_{threads}t"), |b| {
            let cache = Arc::new(ShardedBalanceCache::new(ACCOUNTS as usize));
            for i in 0..HOT_ACCOUNTS {
                cache.set(&hash_addr(i), u64::MAX / 4);
            }
            b.iter_custom(|iters| {
                run_contended(&cache, threads, iters, hash_addr, |_t, i| {
                    (i % u64::from(HOT_ACCOUNTS)) as u32
                })
            });
        });

        // Sparse overflow: registry deliberately exhausted (64-slot
        // cache, 64 pre-registered accounts) so every bench address
        // lands on the global `Mutex<HashMap>` — the serialized path
        // ALL production traffic took before the registry tier.
        group.throughput(Throughput::Elements(2 * threads as u64));
        group.bench_function(format!("sparse_{threads}t"), |b| {
            let cap = HOT_ACCOUNTS as usize;
            let cache = Arc::new(ShardedBalanceCache::new(cap));
            // Fill every reg slot so nothing new can register.
            for i in 0..cap as u32 {
                cache.set(&hash_addr(i), 0);
            }
            // The bench accounts: 64 more hash addresses — all
            // forced to the sparse map.
            for i in cap as u32..(cap as u32 + HOT_ACCOUNTS) {
                cache.set(&hash_addr(i), u64::MAX / 4);
            }
            b.iter_custom(|iters| {
                run_contended(&cache, threads, iters, hash_addr, |_t, i| {
                    (cap + (i as usize % HOT_ACCOUNTS as usize)) as u32
                })
            });
        });
    }
    group.finish();
}

criterion_group!(benches, balance_contention);
criterion_main!(benches);
