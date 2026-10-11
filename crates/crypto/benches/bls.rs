//! BLS12-381 benchmarks — `sign`, `verify`, `aggregate`, `aggregate_verify`.
//!
//! These benchmarks measure the cryptographic operations that oxideBFT
//! performs per view: signing a vote, verifying a vote, aggregating
//! quorum signatures, and verifying the aggregate. The `aggregate_verify`
//! gate is the critical one: it's a single pairing check regardless of
//! validator count, which is why BLS QCs scale to thousands of
//! validators.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use crypto::{BlsSecretKey, Domain, aggregate, aggregate_verify, verify};

fn make_keys(n: usize) -> Vec<BlsSecretKey> {
    (0..n)
        .map(|i| {
            let ikm = vec![u8::try_from(i).unwrap_or(u8::MAX).wrapping_add(1); 32];
            BlsSecretKey::from_ikm(&ikm).expect("key gen")
        })
        .collect()
}

fn bench_sign(c: &mut Criterion) {
    let key = make_keys(1).pop().unwrap();
    let msg = [0x42u8; 32];
    c.bench_function("bls/sign", |b| {
        b.iter(|| black_box(key.sign(Domain::Vote, black_box(&msg))));
    });
}

fn bench_verify(c: &mut Criterion) {
    let key = make_keys(1).pop().unwrap();
    let pk = key.public_key();
    let msg = [0x42u8; 32];
    let sig = key.sign(Domain::Vote, &msg);
    c.bench_function("bls/verify", |b| {
        b.iter(|| {
            let _ = verify(black_box(&sig), Domain::Vote, black_box(&msg), black_box(&pk));
        });
    });
}

fn bench_aggregate(c: &mut Criterion) {
    let keys = make_keys(128);
    let msg = [0x42u8; 32];
    let sigs: Vec<_> = keys.iter().map(|k| k.sign(Domain::QuorumCertificate, &msg)).collect();
    c.bench_function("bls/aggregate/128", |b| {
        b.iter(|| black_box(aggregate(black_box(&sigs))));
    });
}

fn bench_aggregate_verify(c: &mut Criterion) {
    for &n in &[4usize, 32, 128] {
        let keys = make_keys(n);
        let pks: Vec<_> = keys.iter().map(BlsSecretKey::public_key).collect();
        let msg = [0x42u8; 32];
        let sigs: Vec<_> = keys.iter().map(|k| k.sign(Domain::QuorumCertificate, &msg)).collect();
        let agg = aggregate(&sigs).expect("aggregate");
        c.bench_function(&format!("bls/aggregate_verify/{n}"), |b| {
            b.iter(|| {
                let _ = aggregate_verify(
                    black_box(&agg),
                    Domain::QuorumCertificate,
                    black_box(&msg),
                    black_box(&pks),
                );
            });
        });
    }
}

/// hft-audit-2 S-9: the same QC verify with keys decompressed once
/// (per epoch, in production) instead of per call — the head-to-head
/// against `bls/aggregate_verify/{n}` above.
fn bench_aggregate_verify_prepared(c: &mut Criterion) {
    for &n in &[4usize, 32, 128] {
        let keys = make_keys(n);
        let prepared: Vec<_> = keys
            .iter()
            .map(|k| crypto::PreparedPublicKey::new(&k.public_key()).expect("valid key"))
            .collect();
        let msg = [0x42u8; 32];
        let sigs: Vec<_> = keys.iter().map(|k| k.sign(Domain::QuorumCertificate, &msg)).collect();
        let agg = aggregate(&sigs).expect("aggregate");
        c.bench_function(&format!("bls/aggregate_verify_prepared/{n}"), |b| {
            b.iter(|| {
                let _ = crypto::aggregate_verify_prepared(
                    black_box(&agg),
                    Domain::QuorumCertificate,
                    black_box(&msg),
                    black_box(&prepared),
                );
            });
        });
    }
}

criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_aggregate,
    bench_aggregate_verify,
    bench_aggregate_verify_prepared
);
criterion_main!(benches);
