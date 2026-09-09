//! Transaction sender recovery benchmark — the EVM authentication floor.
//!
//! This benchmarks the secp256k1 recovery path that every signed EVM
//! transaction must pass through. It is the "authentication floor" for
//! the EVM module: every `handle` call recovers the sender from the
//! signature before execution, and every `validate` call does the
//! same for mempool admission.
//!
//! ## Acceptance gate
//!
//! The gate is informational in Phase A (no hard throughput requirement
//! at the crate level). The EVM module's block-execution benches will
//! gate on top of this floor. The target is < 100 µs per recovery —
//! well under the 50–100ms block cadence, leaving headroom for
//! execution.
//!
//! ## What this measures
//!
//! `recover_address`: given a 32-byte message hash, a 65-byte
//! recoverable signature, and a recovery ID, recover the sender's
//! 20-byte Ethereum address. This is the exact path used by
//! `SignedTx::recover_sender`.
//!
//! `generate_keypair_for_test`: key generation (for comparison — this
//! is a cold-path operation, not per-tx).

#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use crypto::secp;

fn bench_recover_address(c: &mut Criterion) {
    // Generate a keypair and sign a message.
    let (privkey, _) = secp::generate_keypair_for_test();
    let msg_hash = [0x42u8; 32];
    let sig = secp::sign(&privkey, &msg_hash).expect("sign must succeed");

    c.bench_function("recover_address", |b| {
        b.iter(|| {
            black_box(secp::recover_sender(
                black_box(&msg_hash),
                black_box(&sig.sig),
                black_box(sig.recid.as_u8()),
            ))
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    // Generate a keypair.
    let (privkey, _) = secp::generate_keypair_for_test();
    let msg_hash = [0x42u8; 32];

    c.bench_function("sign", |b| {
        b.iter(|| black_box(secp::sign(black_box(&privkey), black_box(&msg_hash))));
    });
}

fn bench_generate_keypair(c: &mut Criterion) {
    c.bench_function("generate_keypair", |b| {
        b.iter(|| black_box(secp::generate_keypair_for_test()));
    });
}

criterion_group!(benches, bench_recover_address, bench_sign, bench_generate_keypair);
criterion_main!(benches);
