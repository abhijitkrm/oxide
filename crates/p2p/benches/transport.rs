//! Oxide blockchain — benchmarks for the `p2p` crate: the mesh
//! transport layer (peer-ID parse, transport creation, partition/heal).
//!
//! `missing_docs` is allowed for this bench crate only.
#![allow(missing_docs)]
//!
//! Gates and baselines (source: `.devin/skills/benchmarks` §3):
//!
//! | Bench                | Gate (p50) | Baseline                       |
//! |----------------------|------------|--------------------------------|
//! | `peer_id_parse`      | < 50 ns    | little-endian byte decode      |
//! | `transport_create`   | < 1 µs     | Arc clone + channel setup      |
//! | `partition_heal`     | < 1 µs     | Mutex lock + bool flip         |
//! | `fanout/*`           | head-to-head (no gate): `shared` vs     |
//! |                      | `per_peer_copy` on the real `enqueue`  |

use criterion::{Criterion, criterion_group, criterion_main};
use p2p::MeshNetwork;
use std::hint::black_box;

fn bench_peer_id_parse(c: &mut Criterion) {
    let pid = MeshNetwork::peer_id(42);
    c.bench_function("peer_id_parse", |b| {
        b.iter(|| {
            let idx = MeshNetwork::parse_peer_id(black_box(&pid));
            black_box(idx);
        });
    });
}

fn bench_transport_create(c: &mut Criterion) {
    let mesh = MeshNetwork::new(32);
    c.bench_function("transport_create", |b| {
        b.iter(|| {
            let t = mesh.transport(black_box(0));
            black_box(t);
        });
    });
}

fn bench_partition_heal(c: &mut Criterion) {
    let mesh = MeshNetwork::new(32);
    c.bench_function("partition_heal", |b| {
        b.iter(|| {
            mesh.partition(black_box(0));
            mesh.heal(black_box(0));
        });
    });
}

/// Committee fan-out enqueue: one payload copy per peer (a `send`
/// loop) vs one shared frame (`Transport::broadcast`), on the real
/// `enqueue` path. Sizes span a vote-sized frame to a 1 MiB proposal;
/// peer counts span a small devnet to a 100-validator committee.
fn bench_fanout(c: &mut Criterion) {
    let mut group = c.benchmark_group("fanout");
    for &peers in &[4usize, 100] {
        let table = p2p::tcp::BenchFanout::new(peers);
        for &size in &[256usize, 1 << 20] {
            let payload = vec![0xA5u8; size];
            group.bench_function(format!("per_peer_copy/{peers}p/{size}B"), |b| {
                b.iter(|| table.per_peer_copy(black_box(&payload)));
            });
            group.bench_function(format!("shared/{peers}p/{size}B"), |b| {
                b.iter(|| table.shared(black_box(&payload)));
            });
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_peer_id_parse,
    bench_transport_create,
    bench_partition_heal,
    bench_fanout
);
criterion_main!(benches);
