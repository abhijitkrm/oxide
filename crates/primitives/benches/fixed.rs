//! Oxide blockchain — benchmarks for the `primitives` crate: fixed-point
//! arithmetic and parsing.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]
//!
//! Gates (source: `.devin/skills/benchmarks` §3 — every gate cites its
//! origin; machine context: dev Mac, relative claims only until the
//! 16-core `x86_64` rig exists):
//!
//! | Bench                    | Gate (p50)      | Baseline / origin                    |
//! |--------------------------|-----------------|--------------------------------------|
//! | `fixed/notional`         | < 10 ns         | a single `u128` multiply — the floor |
//! | `fixed/mul_div_half_up`  | < 150 ns        | `u128` div is software-emulated;    |
//! |                          |                 | margin over `notional` = the divide |
//! | `fixed/qty_checked_ops`  | < 5 ns          | checked `u64` add+sub pair          |
//! | `hash/from_slice`        | < 15 ns         | 32-byte copy + length validation    |
//! | `digest_map/get_hit`     | < 10 ns         | one multiply-mix + one probe; the   |
//! |                          |                 | `SipHash` map it replaced: ~25 ns   |
//!
//! These functions sit on the matching-engine hot path (every fill does
//! a notional and a fee `mul_div`), so their budgets are inputs to the
//! Phase 3 order-op gate (p50 < 200ns, README → Roadmap).

use criterion::{Criterion, criterion_group, criterion_main};
use primitives::Hash;
use primitives::digest_map::DigestMap;
use primitives::fixed::{self, Price, Qty};
use std::hint::black_box;

fn bench_fixed(c: &mut Criterion) {
    // Realistic trading values: 2.5 lots at 1.25 — the same operands the
    // unit tests reason about, so bench and test tell one story.
    let qty = Qty(2_500_000);
    let price = Price(125_000_000);

    c.bench_function("fixed/notional", |b| {
        b.iter(|| black_box(fixed::notional(black_box(qty), black_box(price))));
    });

    // 10 bps fee on a 1M raw notional: the exact shape of every fill's
    // fee calculation (mul then single final rounding divide).
    c.bench_function("fixed/mul_div_half_up", |b| {
        b.iter(|| {
            black_box(fixed::mul_div_half_up(
                black_box(1_000_000),
                black_box(10),
                black_box(10_000),
            ))
        });
    });

    // A fill's quantity bookkeeping: add the remainder, subtract the
    // matched amount — both checked, never wrapping.
    c.bench_function("fixed/qty_checked_ops", |b| {
        b.iter(|| {
            let added =
                black_box(fixed::qty_add(black_box(Qty(1_000_000)), black_box(Qty(500_000))));
            let taken =
                black_box(fixed::qty_sub(black_box(added.unwrap()), black_box(Qty(250_000))));
            black_box(taken)
        });
    });

    // Trust-boundary parsing: every p2p/gateway message starts with
    // length-validated fixed-width reads like this.
    let bytes = [7u8; 32];
    c.bench_function("hash/from_slice", |b| {
        b.iter(|| black_box(Hash::from_slice(black_box(&bytes)).is_ok()));
    });

    // Digest-keyed lookup (hft-audit-2 S-6): the executor's preverify
    // cache shape — a few thousand tx hashes, every probe a hit. Keys
    // are pseudo-random 32-byte digests (splitmix64-filled) so the
    // hasher sees the uniform input it is designed for.
    let keys: Vec<Hash> = (0u64..4096)
        .map(|i| {
            let mut raw = [0u8; 32];
            let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            for chunk in raw.chunks_mut(8) {
                x ^= x >> 31;
                x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
                chunk.copy_from_slice(&x.to_le_bytes());
            }
            Hash(raw)
        })
        .collect();
    let map: DigestMap<u64> = keys.iter().copied().zip(0u64..).collect();
    let mut idx = 0usize;
    c.bench_function("digest_map/get_hit", |b| {
        b.iter(|| {
            idx = (idx + 1) & (keys.len() - 1);
            black_box(map.get(black_box(&keys[idx])))
        });
    });
}

criterion_group!(benches, bench_fixed);
criterion_main!(benches);
