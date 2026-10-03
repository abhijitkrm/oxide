//! SPSC ring vs the displaced `crossbeam_channel::bounded` — the
//! head-to-head for the F-03 fix (benchmarks skill: a replacement
//! must prove the win on identical payloads).
//!
//! What is measured: a single-threaded push+pop round trip of one
//! item — the per-item cost the sequencer pays per order batch, on
//! the exact ring shape production uses (item = `Vec<OrderResponse>`
//! batch handle; here a 48-byte stand-in — one Vec's worth of
//! pointer mass). The crossbeam row runs the SAME protocol
//! (`try_send`/`try_recv`, bounded capacity) so the delta is the
//! MPMC machinery (slot stamping + backoff) the SPSC ring drops.
//!
//! No absolute gate — criterion tracks the pair; the requirement is
//! that `spsc/push_pop` beat `crossbeam/push_pop` decisively. Wake
//! paths are excluded: both are silent here (the matcher's wakeup
//! wiring is covered by the `matcher_throughput` end-to-end numbers).

#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use matcher::ring::{PushError, spsc_ring};
use std::hint::black_box;

/// Payload stand-in: one batch Vec's pointer mass, `Copy` so the
/// measured cost is ring mechanics, not clone/drop churn.
#[derive(Clone, Copy)]
#[allow(dead_code)] // the bytes are payload mass — never read by the harness
struct Batch([u8; 48]);

fn bench_rings(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_push_pop");
    group.bench_function("spsc", |b| {
        let (tx, rx) = spsc_ring::<Batch>(64);
        b.iter(|| {
            tx.push(black_box(Batch([0x5a; 48])))
                .unwrap_or_else(|_| unreachable!("ring never fills at depth 1"));
            black_box(rx.pop());
        });
    });
    group.bench_function("crossbeam", |b| {
        let (tx, rx) = crossbeam_channel::bounded::<Batch>(64);
        b.iter(|| {
            tx.try_send(black_box(Batch([0x5a; 48]))).expect("never full at depth 1");
            let _ = black_box(rx.try_recv());
        });
    });
    group.finish();
}

/// Saturation shape: fill to capacity, then drain — the bursty path
/// where per-slot stamping hurts the MPMC channel most.
fn bench_rings_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_burst_64");
    group.bench_function("spsc", |b| {
        let (tx, rx) = spsc_ring::<Batch>(64);
        b.iter(|| {
            for i in 0..64u8 {
                let mut v = Batch([i; 48]);
                while let Err(PushError::Full(back)) = tx.push(v) {
                    v = back;
                }
            }
            for _ in 0..64 {
                black_box(rx.pop());
            }
        });
    });
    group.bench_function("crossbeam", |b| {
        let (tx, rx) = crossbeam_channel::bounded::<Batch>(64);
        b.iter(|| {
            for i in 0..64u8 {
                let mut v = Batch([i; 48]);
                while let Err(crossbeam_channel::TrySendError::Full(back)) = tx.try_send(v) {
                    v = back;
                }
            }
            for _ in 0..64 {
                let _ = black_box(rx.try_recv());
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_rings, bench_rings_burst);
criterion_main!(benches);
