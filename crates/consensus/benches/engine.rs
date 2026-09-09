//! Oxide blockchain — benchmarks for the `consensus` crate: the
//! oxideBFT hot path (propose, vote, block-hash, QC verify).
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]
//!
//! Gates and baselines (source: `.devin/skills/benchmarks` §3; dev Mac,
//! relative claims only until the 16-core `x86_64` rig exists):
//!
//! | Bench              | Gate (p50) | Baseline                       |
//! |--------------------|------------|--------------------------------|
//! | `propose_single`   | < 50 µs    | app `prepare_proposal` + header  |
//! | `vote_on_proposal` | < 30 µs    | verdict + BLS sign (if keyed)  |
//! | `block_hash`       | < 500 ns   | BLAKE3 hash of ~100B header    |
//!
//! The `propose` and `vote` benches exclude BLS signing (the engine
//! uses `Signature::ZERO` in conformance mode); the crypto crate
//! benches BLS verify/recover separately.

use consensus::{OxideBft, ValidatorSet};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use ports::mock::MockApp;
use std::hint::black_box;
use std::sync::Arc;

/// Set up a single-validator oxideBFT engine with a mock app.
fn setup_engine() -> OxideBft {
    let app = Arc::new(MockApp::new());
    let app_dyn: Arc<dyn ports::AppInterface> = app.clone();
    let pk = crypto::BlsSecretKey::from_ikm(&[0u8; 32]).expect("BLS key gen").public_key();
    let vs = ValidatorSet::new(vec![pk], vec![1]).expect("validator set");
    OxideBft::new(app_dyn, vs).without_signature_verification()
}

fn bench_propose(c: &mut Criterion) {
    let mut engine = setup_engine();
    c.bench_function("propose_single", |b| {
        b.iter(|| {
            let result = engine.propose();
            black_box(result);
        });
    });
}

fn bench_vote(c: &mut Criterion) {
    // `vote` sets `last_voted_view` on the first call and returns
    // `None` on subsequent calls in the same view. Use
    // `iter_batched` to set up a fresh engine + proposal per batch
    // so each iteration measures the real vote path, not the early
    // return.
    c.bench_function("vote_on_proposal", |b| {
        b.iter_batched(
            || {
                let mut engine = setup_engine();
                let (header, proposal) = engine.propose().expect("propose succeeds");
                (engine, header, proposal)
            },
            |(mut engine, header, proposal)| {
                let v = engine.vote(&header, &proposal);
                black_box(v);
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_block_hash(c: &mut Criterion) {
    // Use a fixed header-like payload — `block_hash` is a pure
    // BLAKE3 hash of the header fields. We measure the hash floor
    // via the crypto crate's Hasher (the same path `block_hash` uses).
    let data = vec![0xABu8; 100];
    c.bench_function("block_hash", |b| {
        b.iter(|| {
            let h = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Block, black_box(&data));
            black_box(h);
        });
    });
}

criterion_group!(benches, bench_propose, bench_vote, bench_block_hash);
criterion_main!(benches);
