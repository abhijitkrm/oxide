//! Per-item cost budget: what one authenticated unit of work costs per
//! core, and how that scales with threads — the inputs to the
//! "cores needed for target X" arithmetic in `docs/lanes-spec.md` §8.
//!
//! This is a plain `harness = false` program (not criterion) because
//! its job is to print one machine-readable table, not a statistical
//! report. Each row is `stage,threads,items_per_sec,ns_per_item`.
//!
//! Stages measured (all on the authentication path of a lane):
//!
//! - `secp256k1_recover`: EVM sender recovery, the per-tx floor of the
//!   EVM lane (`secp::recover_sender`).
//! - `ed25519_verify_strict`: one native-order signature check.
//! - `ed25519_verify_batch{16,64,256}`: batched verification at the
//!   gateway (`ed25519::verify_batch`); per-item cost falls with batch
//!   size.
//! - `blake3_order_leaf`: hashing one ~120-byte record, the unit cost of
//!   a per-item commitment leaf.
//! - `mac_session_order`: keyed BLAKE3 over a ~60-byte order, the
//!   per-order authentication cost under a gateway session key.
//!
//! Thread scaling uses `std::thread::scope` with one independent
//! working set per thread (no shared mutable state), so the numbers
//! show hardware/library scaling, not lock contention.
//!
//! Usage: `cargo bench -p crypto --bench budget -- [--secs S] [--threads 1,2,4,8]`
//!
//! Gate: informational (feeds the target-to-cores table). The printed
//! `cores_for_target` lines use `TARGET_*` constants below.

#![allow(missing_docs, clippy::cast_precision_loss, clippy::too_many_lines)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use crypto::{Domain, Hasher, ed25519, secp};

/// Items per second the lanes spec targets, per lane. Unit: items/s.
/// Origin: `docs/lanes-spec.md` §1 (10M orders/s, 1M EVM tx/s; 100M is
/// the design headroom target). Changing them only changes the
/// printed core counts.
const TARGETS: [(&str, f64); 3] =
    [("evm_tx_per_s_1M", 1.0e6), ("orders_per_s_10M", 1.0e7), ("orders_per_s_100M", 1.0e8)];

/// Run `work(thread_index)` on `threads` threads for about `secs`,
/// where each call to `work` processes a fixed chunk and returns the
/// item count. Returns aggregate items/s.
fn run_threads<F>(threads: usize, secs: f64, work: F) -> f64
where
    F: Fn(usize) -> u64 + Sync,
{
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    let start = Instant::now();
    let total: u64 = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|t| {
                let work = &work;
                s.spawn(move || {
                    let mut n = 0u64;
                    while Instant::now() < deadline {
                        n += work(t);
                    }
                    n
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or(0)).sum()
    });
    // Elapsed is measured, not the nominal `secs`, so a slow final
    // chunk cannot inflate the rate.
    total as f64 / start.elapsed().as_secs_f64()
}

fn row(stage: &str, threads: usize, rate: f64) {
    println!("{stage},{threads},{rate:.0},{:.1}", 1e9 / rate * threads as f64);
}

fn main() {
    let mut secs = 2.0f64;
    let mut threads: Vec<usize> = vec![1, 2, 4, 8];
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--secs" => {
                secs = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(secs);
                i += 1;
            }
            "--threads" => {
                if let Some(v) = args.get(i + 1) {
                    threads = v.split(',').filter_map(|t| t.parse().ok()).collect();
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    // Working sets: 256 distinct signed messages per scheme so the
    // verifier cannot cache a single result.
    let (sk, _) = secp::generate_keypair_for_test();
    let secp_set: Vec<([u8; 32], secp::RecoverableSignature)> = (0..256u32)
        .map(|n| {
            let mut m = [0u8; 32];
            m[..4].copy_from_slice(&n.to_le_bytes());
            let sig = secp::sign(&sk, &m).expect("sign");
            (m, sig)
        })
        .collect();

    let (esk, epk) = ed25519::generate_keypair_for_test();
    let msgs: Vec<Vec<u8>> =
        (0..256u32).map(|n| [&n.to_le_bytes()[..], &[7u8; 60][..]].concat()).collect();
    let sigs: Vec<_> = msgs.iter().map(|m| ed25519::sign_message(&esk, m)).collect();
    let keys: Vec<_> = (0..256).map(|_| epk).collect();

    let order = [0x5au8; 60];
    let record = [0xa5u8; 120];
    let session_key = [9u8; 32];

    println!("stage,threads,items_per_sec,ns_per_item_per_core");
    let mut single: Vec<(String, f64)> = Vec::new();

    for &t in &threads {
        let r = run_threads(t, secs, |_| {
            for (m, s) in &secp_set {
                black_box(secp::recover_sender(m, &s.sig, s.recid.as_u8()).ok());
            }
            secp_set.len() as u64
        });
        row("secp256k1_recover", t, r);
        if t == 1 {
            single.push(("secp256k1_recover".into(), r));
        }

        let r = run_threads(t, secs, |_| {
            for ((m, s), _) in msgs.iter().zip(&sigs).zip(&keys) {
                black_box(ed25519::verify_message(&epk, m, s).is_ok());
            }
            msgs.len() as u64
        });
        row("ed25519_verify_strict", t, r);
        if t == 1 {
            single.push(("ed25519_verify_strict".into(), r));
        }

        for bs in [16usize, 64, 256] {
            let r = run_threads(t, secs, |_| {
                let mrefs: Vec<&[u8]> = msgs[..bs].iter().map(Vec::as_slice).collect();
                black_box(ed25519::verify_batch(&mrefs, &keys[..bs], &sigs[..bs]).is_ok());
                bs as u64
            });
            let name = format!("ed25519_verify_batch{bs}");
            row(&name, t, r);
            if t == 1 {
                single.push((name, r));
            }
        }

        let r = run_threads(t, secs, |_| {
            for _ in 0..1024 {
                black_box(Hasher::hash_one(Domain::CommittedLeaf, black_box(&record)));
            }
            1024
        });
        row("blake3_order_leaf", t, r);
        if t == 1 {
            single.push(("blake3_order_leaf".into(), r));
        }

        let r = run_threads(t, secs, |_| {
            for _ in 0..1024 {
                let mut h = Hasher::new_keyed(Domain::CommittedLeaf, &session_key);
                h.update(black_box(&order));
                black_box(h.finalize());
            }
            1024
        });
        row("mac_session_order", t, r);
        if t == 1 {
            single.push(("mac_session_order".into(), r));
        }
    }

    println!();
    println!("# cores_for_target: stage, target, cores (single-core rate, perfect scaling)");
    for (stage, rate) in &single {
        for (tname, target) in TARGETS {
            println!("cores_for_target,{stage},{tname},{:.1}", target / rate);
        }
    }
}
