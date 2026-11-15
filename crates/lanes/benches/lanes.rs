//! Lane throughput: orders/s and EVM-style transfers/s versus shard
//! count and seam choice (`docs/lanes-spec.md` §9, "Trading scaling").
//!
//! Part A (trading): every authentication mode x every commitment mode
//! on one shard, then the shard-scaling curve for three representative
//! combinations. Each shard is a thread with its own engine and input;
//! nothing is shared, so the curve shows hardware scaling.
//!
//! Part B (EVM): account-range lanes exchanging cross-lane credits;
//! each round applies transfers in parallel, buckets and delivers
//! credits in parallel, and reports transfers/s.
//!
//! Output is CSV: `part,verifier,commit,shards,items_per_s,ns_per_item_per_shard,extra`.
//!
//! Gate: informational. The point is the curve and the cost of each
//! seam, which feed the target-to-cores table.
//!
//! Usage: `cargo bench -p lanes --bench lanes -- [--secs S] [--shards 1,2,4,8] [--batch N] [--part a|b|ab]`

#![allow(
    missing_docs,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use std::time::{Duration, Instant};

use crypto::ed25519;
use lanes::commit::{CountOnly, FillCommit, Merkle, PerFill, Stream};
use lanes::evm::{AccountRange, EvmLane, Transfer};
use lanes::shard::{ShardLane, synth_bodies};
use lanes::verify::{
    Auth, Batch, BatchCert, Batched, Certified, Item, NoVerify, PerItem, SessionMac, Verifier,
    batch_digest, session_tag,
};

/// Middle of the price band, in ticks.
const MID: u64 = 500_000;
/// Band half-width, ticks. Orders stay within mid ± 3, so the band only
/// needs to contain that.
const BAND: u64 = 100;
/// Resting-order capacity per shard (2^16 x 64 B = 4 MiB pool).
const MAX_RESTING: u32 = 1 << 16;
/// Pre-built batches replayed cyclically per shard. Unit: batches.
const CYCLE: usize = 4;
/// Audit sample for the certified verifier: 1 in N items.
const AUDIT_EVERY: u32 = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Vk {
    None,
    PerItem,
    Batched,
    Certified,
    Mac,
}

impl Vk {
    fn name(self) -> &'static str {
        match self {
            Vk::None => "none",
            Vk::PerItem => "per_item",
            Vk::Batched => "batched",
            Vk::Certified => "certified",
            Vk::Mac => "session_mac",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ck {
    None,
    PerFill,
    Stream,
    Merkle,
}

struct Input {
    batches: Vec<Vec<Item>>,
    certs: Vec<BatchCert>,
}

fn build_input(vk: Vk, shard: usize, batch: usize, key: &[u8; 32]) -> Input {
    let (sk, pk) = ed25519::generate_keypair_for_test();
    let (gsk, gpk) = ed25519::generate_keypair_for_test();
    let mut batches = Vec::new();
    let mut certs = Vec::new();
    let mut counter = 0u64;
    for c in 0..CYCLE {
        let bodies = synth_bodies(batch, (shard * 1000 + c + 1) as u64 * 0x9e37_79b9, MID);
        let items: Vec<Item> = bodies
            .iter()
            .map(|b| {
                let auth = match vk {
                    Vk::None => Auth::Certified,
                    Vk::PerItem | Vk::Batched => {
                        Auth::Sig { key: pk, sig: ed25519::sign_message(&sk, b) }
                    }
                    Vk::Certified => Auth::Sig { key: pk, sig: ed25519::sign_message(&sk, b) },
                    Vk::Mac => {
                        counter += 1;
                        Auth::Mac { session: 0, counter, tag: session_tag(key, 0, counter, b) }
                    }
                };
                Item { body: *b, auth }
            })
            .collect();
        if vk == Vk::Certified {
            let digest = batch_digest(&items);
            certs.push(BatchCert {
                gateway: gpk,
                digest,
                sig: ed25519::sign_message(&gsk, &digest),
            });
        }
        batches.push(items);
    }
    Input { batches, certs }
}

/// Run one shard flat out for `secs`; returns (orders, fills).
fn run_shard<V: Verifier, C: FillCommit>(
    mut lane: ShardLane<V, C>,
    input: &Input,
    secs: f64,
    rewind: &mut dyn FnMut(&mut ShardLane<V, C>),
    start: &std::sync::Barrier,
) -> (u64, u64, f64) {
    // Warm up one cycle so the book and caches reach steady state.
    for (i, b) in input.batches.iter().enumerate() {
        lane.process(&Batch { items: b, cert: input.certs.get(i) });
    }
    rewind(&mut lane);
    start.wait();
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs_f64(secs);
    let (mut orders, mut fills) = (0u64, 0u64);
    'outer: loop {
        for (i, b) in input.batches.iter().enumerate() {
            if Instant::now() >= deadline {
                break 'outer;
            }
            let r = lane.process(&Batch { items: b, cert: input.certs.get(i) });
            orders += u64::from(r.items);
            fills += r.fills;
        }
        rewind(&mut lane);
    }
    (orders, fills, t0.elapsed().as_secs_f64())
}

fn make_lane<V: Verifier, C: FillCommit>(i: usize, v: V, c: C) -> ShardLane<V, C> {
    ShardLane::new(i as u16, 1, MID, BAND, MAX_RESTING, v, c)
}

/// Run `shards` threads of one (verifier, commit) combination.
fn trading(vk: Vk, ck: Ck, shards: usize, secs: f64, batch: usize) {
    let key = [5u8; 32];
    let inputs: Vec<Input> = std::thread::scope(|s| {
        let hs: Vec<_> =
            (0..shards).map(|i| s.spawn(move || build_input(vk, i, batch, &key))).collect();
        hs.into_iter().map(|h| h.join().expect("input thread")).collect()
    });
    let barrier = std::sync::Barrier::new(shards);
    let results: Vec<(u64, u64, f64)> = std::thread::scope(|s| {
        let hs: Vec<_> = inputs
            .iter()
            .enumerate()
            .map(|(i, inp)| {
                let barrier = &barrier;
                s.spawn(move || {
                    // One closure per (verifier, commit) pair keeps the hot
                    // loop monomorphized, with no dyn call per order.
                    macro_rules! go {
                        ($v:expr, $c:expr, $rw:expr) => {
                            run_shard(make_lane(i, $v, $c), inp, secs, &mut $rw, barrier)
                        };
                    }
                    macro_rules! with_commit {
                        ($v:expr, $rw:expr) => {
                            match ck {
                                Ck::None => go!($v, CountOnly::default(), $rw),
                                Ck::PerFill => go!($v, PerFill::default(), $rw),
                                Ck::Stream => go!($v, Stream::default(), $rw),
                                Ck::Merkle => go!($v, Merkle::default(), $rw),
                            }
                        };
                    }
                    match vk {
                        Vk::None => with_commit!(NoVerify, |_l: &mut _| {}),
                        Vk::PerItem => with_commit!(PerItem, |_l: &mut _| {}),
                        Vk::Batched => with_commit!(Batched::default(), |_l: &mut _| {}),
                        Vk::Certified => {
                            let (_, gpk) = (0, inp.certs[0].gateway);
                            with_commit!(Certified::new(vec![gpk], AUDIT_EVERY), |_l: &mut _| {})
                        }
                        Vk::Mac => {
                            let mut m = SessionMac::default();
                            m.open(key);
                            // Counters restart each cycle; lanes expose the
                            // verifier, and rewinding is a bench-only helper.
                            match ck {
                                Ck::None => run_mac(
                                    make_lane(i, m, CountOnly::default()),
                                    inp,
                                    secs,
                                    barrier,
                                ),
                                Ck::PerFill => {
                                    run_mac(make_lane(i, m, PerFill::default()), inp, secs, barrier)
                                }
                                Ck::Stream => {
                                    run_mac(make_lane(i, m, Stream::default()), inp, secs, barrier)
                                }
                                Ck::Merkle => {
                                    run_mac(make_lane(i, m, Merkle::default()), inp, secs, barrier)
                                }
                            }
                        }
                    }
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().expect("shard thread")).collect()
    });
    let orders: u64 = results.iter().map(|r| r.0).sum();
    let fills: u64 = results.iter().map(|r| r.1).sum();
    let wall = results.iter().map(|r| r.2).fold(0.0, f64::max);
    let rate = orders as f64 / wall;
    println!(
        "trading,{},{:?},{shards},{rate:.0},{:.1},fills_per_s={:.0}",
        vk.name(),
        ck,
        1e9 / rate * shards as f64,
        fills as f64 / wall
    );
}

/// The MAC path needs `SessionMac::rewind` on the lane's verifier, which
/// is reachable only through the lane; a tiny wrapper keeps `run_shard`
/// generic.
fn run_mac<C: FillCommit>(
    lane: ShardLane<SessionMac, C>,
    input: &Input,
    secs: f64,
    start: &std::sync::Barrier,
) -> (u64, u64, f64) {
    run_shard(
        lane,
        input,
        secs,
        &mut |l: &mut ShardLane<SessionMac, C>| l.verifier_mut().rewind(),
        start,
    )
}

fn evm(lanes_n: usize, secs: f64, per_round: usize) {
    const PER: u64 = 1 << 14;
    let range = AccountRange { lanes: lanes_n as u16, per_lane: PER };
    let mut lanes: Vec<EvmLane> =
        (0..lanes_n).map(|i| EvmLane::new(i as u16, range, u128::MAX / 4)).collect();
    let total = PER * lanes_n as u64;
    // Same pre-built input every round; funds are effectively unlimited.
    let inputs: Vec<Vec<Transfer>> = (0..lanes_n)
        .map(|l| {
            let mut x = (l as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            (0..per_round)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    Transfer {
                        from: l as u64 * PER + x % PER,
                        to: (x >> 17) % total,
                        amount: x % 1000,
                    }
                })
                .collect()
        })
        .collect();
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs_f64(secs);
    let mut rounds = 0u64;
    let mut credits = 0u64;
    while Instant::now() < deadline {
        // Phase 1: apply and bucket, one thread per lane.
        let matrix: Vec<Vec<Vec<lanes::evm::Credit>>> = std::thread::scope(|s| {
            let hs: Vec<_> = lanes
                .iter_mut()
                .zip(&inputs)
                .map(|(l, t)| {
                    s.spawn(move || {
                        l.apply_transfers(t);
                        l.drain_by_dest()
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().expect("apply thread")).collect()
        });
        credits += matrix.iter().flatten().map(|v| v.len() as u64).sum::<u64>();
        // Phase 2: each destination applies its channels in source order.
        std::thread::scope(|s| {
            for (d, l) in lanes.iter_mut().enumerate() {
                let matrix = &matrix;
                s.spawn(move || {
                    for src in matrix {
                        l.deliver(&src[d]).expect("in-order delivery");
                    }
                });
            }
        });
        rounds += 1;
    }
    let wall = t0.elapsed().as_secs_f64();
    let txs = rounds * (per_round * lanes_n) as u64;
    let rate = txs as f64 / wall;
    println!(
        "evm,-,-,{lanes_n},{rate:.0},{:.1},cross_lane_credits_per_s={:.0}",
        1e9 / rate * lanes_n as f64,
        credits as f64 / wall
    );
}

fn main() {
    let mut secs = 3.0f64;
    let mut shards: Vec<usize> = vec![1, 2, 4, 8];
    let mut batch = 2048usize;
    let mut part = "ab".to_string();
    let a: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < a.len() {
        let v = a.get(i + 1);
        match a[i].as_str() {
            "--secs" => secs = v.and_then(|v| v.parse().ok()).unwrap_or(secs),
            "--shards" => {
                if let Some(v) = v {
                    shards = v.split(',').filter_map(|t| t.parse().ok()).collect();
                }
            }
            "--batch" => batch = v.and_then(|v| v.parse().ok()).unwrap_or(batch),
            "--part" => part = v.cloned().unwrap_or(part),
            _ => {
                i += 1;
                continue;
            }
        }
        i += 2;
    }

    println!("part,verifier,commit,shards,items_per_s,ns_per_item_per_shard,extra");
    if part.contains('a') {
        // Full seam matrix on one shard.
        for vk in [Vk::None, Vk::PerItem, Vk::Batched, Vk::Certified, Vk::Mac] {
            for ck in [Ck::None, Ck::PerFill, Ck::Stream, Ck::Merkle] {
                trading(vk, ck, 1, secs, batch);
            }
        }
        // Scaling curves for: control, the cheap production candidate, the
        // conservative candidate.
        for &n in shards.iter().filter(|&&n| n > 1) {
            trading(Vk::None, Ck::None, n, secs, batch);
            trading(Vk::Mac, Ck::Stream, n, secs, batch);
            trading(Vk::Batched, Ck::Merkle, n, secs, batch);
        }
    }
    if part.contains('b') {
        for &n in &shards {
            evm(n, secs, 50_000);
        }
    }
}
