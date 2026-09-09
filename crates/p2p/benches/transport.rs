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

criterion_group!(benches, bench_peer_id_parse, bench_transport_create, bench_partition_heal);
criterion_main!(benches);
