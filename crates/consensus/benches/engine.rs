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
//! | Bench                    | Gate (p50) | Baseline                        |
//! |--------------------------|------------|---------------------------------|
//! | `propose_single`         | < 50 µs    | app `prepare_proposal` + header |
//! | `vote_on_proposal`       | < 30 µs    | verdict + BLS sign (if keyed)   |
//! | `block_hash`             | < 500 ns   | BLAKE3 hash of ~100B header     |
//! | `vote_signed_wal`        | < 20 ms    | fsync + sign + proposer verify  |
//! | `form_qc_signed_wal`     | < 25 ms    | 3×collect + agg + self-verify   |
//! | `deliver_qc_signed_wal`  | < 20 ms    | aggregate verify + high_qc fsync|
//!
//! The `propose` and `vote` benches exclude BLS signing (the engine
//! uses `Signature::ZERO` in conformance mode); the crypto crate
//! benches BLS verify/recover separately.
//!
//! The `*_signed_wal` benches are the production-shaped complement:
//! real BLS keys, real signature verification, and a real WAL whose
//! `append` ends in `sync_data` — so they measure the actual durable
//! vote budget a validator pays per view (fsync dominates, BLS
//! second), which the conformance benches structurally cannot.
//! Gates are ~3× the dev-Mac measurement — fsync cost is
//! storage-dependent, so the gate catches order-of-magnitude
//! regressions rather than pinning an absolute hardware budget.
//!
//! Measured on the dev Mac (M-series, NVMe): `vote_signed_wal`
//! 5.7 ms, `form_qc_signed_wal` 6.3 ms, `deliver_qc_signed_wal`
//! 5.7 ms — i.e. the honest per-view vote budget is ~6 ms, not the
//! ~1 µs the conformance bench suggests; the durable WAL write is
//! the dominant term, exactly what the audit asked to be measured.

use consensus::wal::Wal;
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

/// Four real BLS keys — one per validator of the smallest
/// interesting BFT committee (n=4, f=1, quorum=3).
fn production_keys() -> [crypto::BlsSecretKey; 4] {
    [0x10, 0x20, 0x30, 0x40]
        .map(|seed| crypto::BlsSecretKey::from_ikm(&[seed; 32]).expect("BLS key gen"))
}

/// An engine wired the way `oxide-validator` wires it: real BLS
/// secret key, a real WAL (every append ends in `fsync`), and
/// signature verification left at its production default (on for
/// proposals/QCs, off per-vote — the aggregate check covers them).
fn setup_production_engine(
    dir: &tempfile::TempDir,
    keys: &[crypto::BlsSecretKey; 4],
    idx: u16,
) -> OxideBft {
    let app: Arc<dyn ports::AppInterface> = Arc::new(MockApp::new());
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1; keys.len()]).expect("validator set");
    let wal = Wal::open(dir.path().join(format!("wal-{idx}.log"))).expect("wal open");
    OxideBft::with_index(app, vs, idx).with_secret_key(keys[usize::from(idx)].clone()).with_wal(wal)
}

/// The honest voter's per-view cost in production: authenticate the
/// proposal (proposer-signature verify + body-commitment check),
/// record the locks, fsync the WAL entry, then BLS-sign the vote.
/// Gates the C10 durable-order contract — a vote whose locks aren't
/// durable must never leave the process.
fn bench_vote_signed_wal(c: &mut Criterion) {
    c.bench_function("vote_signed_wal", |b| {
        b.iter_batched(
            || {
                let dir = tempfile::tempdir().expect("tempdir");
                let keys = production_keys();
                // Validator 0 leads view 0; the genesis-height
                // propose is unconditional.
                let mut leader = setup_production_engine(&dir, &keys, 0);
                let (header, proposal) = leader.propose().expect("genesis propose");
                let voter = setup_production_engine(&dir, &keys, 1);
                (voter, header, proposal, dir)
            },
            |(mut voter, header, proposal, _dir)| {
                black_box(voter.vote(&header, &proposal));
            },
            BatchSize::SmallInput,
        );
    });
}

/// The leader's per-view collection cost in production: buffer three
/// real signed votes (per-vote verify deferred by design), then
/// `try_form_qc` — aggregate the signatures and self-verify the
/// aggregate before the QC may be emitted — and `deliver_qc`, which
/// re-verifies the aggregate and fsyncs the adopted `high_qc`.
fn bench_qc_signed_wal(c: &mut Criterion) {
    c.bench_function("form_qc_signed_wal", |b| {
        b.iter_batched(
            || {
                let dir = tempfile::tempdir().expect("tempdir");
                let keys = production_keys();
                let mut leader = setup_production_engine(&dir, &keys, 0);
                let (header, proposal) = leader.propose().expect("genesis propose");
                // Three distinct voters reach the 3-of-4 quorum;
                // their vote() calls are setup, not measured.
                let votes: Vec<types::Vote> = (1u16..4)
                    .map(|i| {
                        let mut v = setup_production_engine(&dir, &keys, i);
                        v.vote(&header, &proposal).expect("voter signs")
                    })
                    .collect();
                (leader, votes, dir)
            },
            |(mut leader, votes, _dir)| {
                for (idx, vote) in (1u16..).zip(votes) {
                    leader.collect_vote(idx, vote).expect("collect_vote");
                }
                let qc = leader.try_form_qc().expect("quorum reached");
                leader.deliver_qc(qc).expect("deliver_qc");
            },
            BatchSize::SmallInput,
        );
    });
}

/// The receiver's per-view cost in production: a QC arrives on the
/// wire (from another peer or the leader's broadcast); `deliver_qc`
/// verifies the aggregate signature, adopts the new `high_qc`, and
/// fsyncs it to the WAL before the QC can drive anything further.
fn bench_deliver_qc_signed_wal(c: &mut Criterion) {
    c.bench_function("deliver_qc_signed_wal", |b| {
        b.iter_batched(
            || {
                let dir = tempfile::tempdir().expect("tempdir");
                let keys = production_keys();
                let mut leader = setup_production_engine(&dir, &keys, 0);
                let (header, proposal) = leader.propose().expect("genesis propose");
                for i in 1u16..4 {
                    let mut v = setup_production_engine(&dir, &keys, i);
                    let vote = v.vote(&header, &proposal).expect("voter signs");
                    leader.collect_vote(i, vote).expect("collect_vote");
                }
                let qc = leader.try_form_qc().expect("quorum reached");
                // The QC consumer: any validator identity works —
                // a separate tempdir so its WAL file is its own.
                let rx_dir = tempfile::tempdir().expect("tempdir");
                let receiver = setup_production_engine(&rx_dir, &keys, 3);
                (receiver, qc, dir, rx_dir)
            },
            |(mut receiver, qc, _dir, _rx_dir)| {
                receiver.deliver_qc(qc).expect("deliver_qc");
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_propose,
    bench_vote,
    bench_block_hash,
    bench_vote_signed_wal,
    bench_qc_signed_wal,
    bench_deliver_qc_signed_wal
);
criterion_main!(benches);
