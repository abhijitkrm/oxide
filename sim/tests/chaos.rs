//! Chaos-simulation tests: real engine-level Byzantine injection.
//!
//! Unlike `swarm.rs` (which records strategies as configuration),
//! these tests run `sim::chaos::run`, which emits real signed
//! equivocating votes, malformed frames, and censorship decisions
//! through the actual `OxideBft` engine + `MeshTransport` path. Every
//! assertion below verifies that the *engines'* defenses — not the
//! harness — rejected the Byzantine input.
//!
//! The final test is the Phase 4 acceptance gate (plan.md §13):
//! 10,000 randomized scenarios with zero safety violations. It is
//! `#[ignore]`d by default — run with:
//!
//! ```sh
//! cargo test -p oxide-sim --test chaos -- --ignored --nocapture
//! ```

use std::collections::{HashMap, HashSet};

use oxide_sim::byzantine::ByzantineStrategy;
use oxide_sim::chaos::{ChaosScenario, PartitionPlan, run};
use oxide_sim::network::DeterministicRng;

fn scenario(strategies: &[(usize, ByzantineStrategy)], rounds: usize) -> ChaosScenario {
    ChaosScenario {
        strategies: strategies.iter().cloned().collect(),
        rounds,
        txs_per_round: 1,
        partition: None,
    }
}

/// Baseline: all-honest 4-validator run finalizes blocks and is safe.
#[test]
fn honest_baseline_finalizes() {
    let report = run(4, &ChaosScenario::honest(8));
    assert!(report.safety_holds(&HashMap::new()), "honest run must be safe");
    assert!(report.liveness_holds(&HashMap::new()), "honest run must be live");
    assert_eq!(report.conflicting_votes, 0);
    assert_eq!(report.malformed_dropped, 0);
}

/// A double-voting follower emits a real vote + a conflicting signed
/// vote. The leader must detect the conflict (`conflicting_votes` > 0
/// proves the forged message was injected AND rejected), and the QC
/// must contain only same-hash votes → safety + liveness hold.
#[test]
fn double_vote_detected_and_safe() {
    let mut strategies = HashMap::new();
    strategies.insert(1, ByzantineStrategy::DoubleVote);
    let report = run(4, &ChaosScenario { strategies: strategies.clone(), ..scenario(&[], 8) });
    assert!(report.safety_holds(&strategies), "double vote must not fork honest nodes");
    assert!(report.liveness_holds(&strategies), "one double-voter must not stall quorum");
    assert!(
        report.conflicting_votes > 0,
        "double vote must actually reach the leader and be rejected (injection proof)"
    );
}

/// An equivocating leader signs two headers for one view and splits
/// the follower set. Neither block can reach quorum — the view goes
/// empty — but safety must hold and honest leaders' later views
/// recover.
#[test]
fn leader_equivocation_split_vote_rejected() {
    let mut strategies = HashMap::new();
    strategies.insert(0, ByzantineStrategy::Equivocate);
    // 8+ rounds so view rotation hits node 0's leader slot at least
    // once (leader = view % n).
    let report = run(4, &ChaosScenario { strategies: strategies.clone(), ..scenario(&[], 12) });
    assert!(report.safety_holds(&strategies));
    assert!(report.liveness_holds(&strategies), "honest leaders must still finalize");
    assert!(report.leader_equivocations > 0, "equivocation must actually be injected");
    assert!(report.conflicting_votes > 0, "split-view votes must conflict at the leader");
}

/// One withholding voter within the BFT bound (n=4, f=1): the
/// remaining 3 honest validators still reach quorum.
#[test]
fn withhold_within_bft_bound_stays_live() {
    let mut strategies = HashMap::new();
    strategies.insert(3, ByzantineStrategy::Withhold);
    let report = run(4, &ChaosScenario { strategies: strategies.clone(), ..scenario(&[], 8) });
    assert!(report.safety_holds(&strategies));
    assert!(
        report.liveness_holds(&strategies),
        "quorum of 3 honest must still finalize with 1 withholding"
    );
}

/// Two withholding voters exceed f=1 for n=4: progress may stall,
/// but safety must never break — no honest node may finalize a
/// conflicting history.
#[test]
fn withhold_beyond_bound_never_unsafe() {
    let mut strategies = HashMap::new();
    strategies.insert(2, ByzantineStrategy::Withhold);
    strategies.insert(3, ByzantineStrategy::Withhold);
    let report = run(4, &ChaosScenario { strategies: strategies.clone(), ..scenario(&[], 8) });
    assert!(report.safety_holds(&strategies), "safety must hold even when liveness stalls");
}

/// A spamming follower floods the leader with malformed frames each
/// round. Decode drops them (`malformed_dropped` > 0 proves delivery),
/// the honest vote still lands, quorum holds.
#[test]
fn spam_flood_dropped_at_decode() {
    let mut strategies = HashMap::new();
    strategies.insert(2, ByzantineStrategy::Spam { rate: 32 });
    let report = run(4, &ChaosScenario { strategies: strategies.clone(), ..scenario(&[], 8) });
    assert!(report.safety_holds(&strategies));
    assert!(report.liveness_holds(&strategies));
    assert!(
        report.malformed_dropped >= 32,
        "spam frames must reach the leader's queue and be dropped: {}",
        report.malformed_dropped
    );
}

/// A censoring node never receives the censored sender's txs (all
/// chaos txs come from `[0;20]`), so its proposals exclude them.
/// Honest leaders still carry them — censorship delays but cannot
/// deny.
#[test]
fn censorship_delays_not_denies() {
    let mut strategies = HashMap::new();
    strategies.insert(1, ByzantineStrategy::Censor { censored: HashSet::from([[0u8; 20]]) });
    let report = run(4, &ChaosScenario { strategies: strategies.clone(), ..scenario(&[], 12) });
    assert!(report.safety_holds(&strategies));
    assert!(report.liveness_holds(&strategies), "txs must land via honest leaders");
}

/// Partition a node mid-run, heal it, and verify the swarm recovers
/// without a safety violation.
#[test]
fn partition_then_heal_recovers() {
    let mut strategies = HashMap::new();
    strategies.insert(3, ByzantineStrategy::Honest); // node 3 honest but partitioned
    let report = run(
        4,
        &ChaosScenario {
            strategies: HashMap::new(),
            rounds: 10,
            txs_per_round: 1,
            partition: Some(PartitionPlan { nodes: vec![3], start: 2, duration: 3 }),
        },
    );
    let _ = strategies;
    assert!(report.safety_holds(&HashMap::new()));
    assert!(report.liveness_holds(&HashMap::new()));
}

/// Determinism gate: two runs of the same scenario produce identical
/// finalized histories and identical injection counters.
#[test]
fn same_scenario_identical_result() {
    let mut strategies = HashMap::new();
    strategies.insert(0, ByzantineStrategy::DoubleVote);
    strategies.insert(2, ByzantineStrategy::Spam { rate: 8 });
    let scenario = ChaosScenario { strategies, rounds: 8, txs_per_round: 1, partition: None };
    let a = run(4, &scenario);
    let b = run(4, &scenario);
    assert_eq!(a.conflicting_votes, b.conflicting_votes);
    assert_eq!(a.malformed_dropped, b.malformed_dropped);
    assert_eq!(a.leader_equivocations, b.leader_equivocations);
    assert_eq!(a.finalized.len(), b.finalized.len());
    for (fa, fb) in a.finalized.iter().zip(b.finalized.iter()) {
        assert_eq!(fa.len(), fb.len());
        for (ba, bb) in fa.iter().zip(fb.iter()) {
            assert_eq!(ba.height, bb.height);
            assert_eq!(ba.txs, bb.txs);
        }
    }
}

/// The Phase 4 acceptance gate (plan.md §13): 10,000 randomized
/// scenarios — random node counts, Byzantine assignments, strategies,
/// round counts, and optional partitions — with **zero safety
/// violations**. Liveness is asserted only where the scenario is
/// within the BFT bound and no permanent impairment applies.
///
/// Run: `cargo test -p oxide-sim --test chaos -- --ignored`
#[test]
#[ignore = "10k-scenario acceptance gate — run explicitly or in nightly CI"]
fn randomized_10k_zero_safety_violations() {
    // Scenarios are independent (each builds a fresh devnet), so the
    // gate parallelizes across cores: single-threaded 10k runs take
    // ~17 min (dominated by per-scenario BLS keygen); fanned out it's
    // ~2-3 min on an 8-core machine. Chunk boundaries are fixed, so
    // the scenario set is identical every run — determinism preserved.
    let threads = std::thread::available_parallelism().map_or(4, Into::into);
    let per_thread = 10_000usize.div_ceil(threads);
    let (violations, liveness_checked, liveness_failures, injected_runs) =
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..threads)
                .map(|t| {
                    scope.spawn(move || {
                        let mut acc = (0usize, 0usize, 0usize, 0usize);
                        let last = ((t + 1) * per_thread).min(10_000);
                        for seed in t * per_thread..last {
                            let r = run_one_scenario(seed as u64);
                            acc.0 += r.0;
                            acc.1 += r.1;
                            acc.2 += r.2;
                            acc.3 += r.3;
                        }
                        acc
                    })
                })
                .collect();
            handles.into_iter().fold((0, 0, 0, 0), |acc, h| {
                let r = h.join().unwrap_or((1, 0, 0, 0));
                (acc.0 + r.0, acc.1 + r.1, acc.2 + r.2, acc.3 + r.3)
            })
        });

    eprintln!(
        "10k gate: {violations} safety violations, \
         {liveness_failures}/{liveness_checked} liveness failures, \
         {injected_runs} runs with confirmed injection"
    );
    assert_eq!(violations, 0, "zero safety violations required");
    assert_eq!(liveness_failures, 0, "within-bound liveness must hold");
    // Injection must actually happen — a gate that never injects
    // Byzantine behavior proves nothing.
    assert!(injected_runs > 1_000, "byzantine injection too rare: {injected_runs}");
}

/// Build and run one randomized scenario for `seed`. Returns
/// `(safety_violations, liveness_checked, liveness_failures,
/// injection_confirmed)` — counts accumulated by the gate.
fn run_one_scenario(seed: u64) -> (usize, usize, usize, usize) {
    // `DeterministicRng` rejects seed 0 (splitmix64 zero-state guard);
    // offset by 1 so seed s covers scenario s.
    let mut rng = DeterministicRng::new(seed + 1);
    let n = if rng.next_u64() % 4 == 0 { 7 } else { 4 };
    let f = (n - 1) / 3;

    // Byzantine count: mostly within bound, ~15% exceed it (safety
    // must still hold — liveness is not required then).
    let max_byz = if rng.next_u64() % 100 < 15 { n } else { f };
    let num_byz =
        usize::try_from(rng.next_u64() % u64::try_from(max_byz + 1).unwrap_or(1)).unwrap_or(0);
    let mut strategies = HashMap::new();
    for _ in 0..num_byz {
        let idx = usize::try_from(rng.next_u64() % u64::try_from(n).unwrap_or(1)).unwrap_or(0);
        let strategy = match rng.next_u64() % 5 {
            0 => ByzantineStrategy::Withhold,
            1 => ByzantineStrategy::DoubleVote,
            2 => ByzantineStrategy::Equivocate,
            3 => ByzantineStrategy::Spam { rate: (rng.next_u64() % 64) as u32 },
            _ => ByzantineStrategy::Censor { censored: HashSet::from([[0u8; 20]]) },
        };
        strategies.insert(idx, strategy);
    }

    let rounds = usize::try_from(6 + rng.next_u64() % 10).unwrap_or(6);
    // ~25% of runs carry a temporary partition.
    let partition = if rng.next_u64() % 4 == 0 {
        let idx = usize::try_from(rng.next_u64() % u64::try_from(n).unwrap_or(1)).unwrap_or(0);
        Some(PartitionPlan {
            nodes: vec![idx],
            start: usize::try_from(rng.next_u64() % 4).unwrap_or(0),
            duration: 1 + usize::try_from(rng.next_u64() % 3).unwrap_or(1),
        })
    } else {
        None
    };

    let has_partition = partition.is_some();
    let scenario =
        ChaosScenario { strategies: strategies.clone(), rounds, txs_per_round: 1, partition };
    let report = run(n, &scenario);

    let mut out = (0usize, 0usize, 0usize, 0usize);
    if !report.safety_holds(&strategies) {
        out.0 += 1;
        eprintln!(
            "SAFETY VIOLATION seed={seed} n={n} byz={:?} finalized={:?}",
            scenario.byzantine_indices(),
            report.finalized.iter().map(Vec::len).collect::<Vec<_>>()
        );
    }
    if report.conflicting_votes > 0
        || report.malformed_dropped > 0
        || report.leader_equivocations > 0
    {
        out.3 += 1;
    }
    // Liveness is required only when within-BFT-bound and no
    // partition applies — partitions heal, so post-heal progress is
    // expected but not asserted; the strict claim is safety.
    if num_byz <= f && !has_partition {
        out.1 += 1;
        if !report.liveness_holds(&strategies) {
            out.2 += 1;
            eprintln!("LIVENESS FAILURE seed={seed} n={n} byz={num_byz}");
        }
    }
    out
}
