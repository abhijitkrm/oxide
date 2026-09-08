//! `oxide-bench` — the orchestrated benchmark runner for Oxide.
//!
//! # What this is
//!
//! A CLI that runs the per-crate criterion benchmarks in a unified
//! harness and reports results. Phase 0 scope: invoke `cargo bench`
//! for each registered crate, summarize pass/fail, and exit non-zero
//! if any bench fails. Phase 1+ adds: latency percentiles (HDR
//! histograms), adapter report cards (§2.4), and dashboard output
//! (plan.md §13, "measure everything").
//!
//! # Why not just `cargo bench --workspace`?
//!
//! `cargo bench --workspace` runs every bench but gives no per-crate
//! summary, no gate enforcement, and no structured output. This
//! harness adds:
//!
//! - A registry of which crates have benches (so a missing bench dir
//!   is not silently skipped).
//! - Per-crate pass/fail with exit code (CI gate).
//! - A summary line per crate ( benches run, pass/fail).
//!
//! # Usage
//!
//! ```sh
//! cargo run -p oxide-bench --           # run all registered benches
//! cargo run -p oxide-bench -- --list    # list registered benches
//! cargo run -p oxide-bench -- primitives # run one crate's benches
//! ```

use std::process::{Command, ExitCode};

/// A crate with criterion benchmarks. The bench harness shells out to
/// `cargo bench -p <crate>` for each entry. The path is informational
/// (for `--list`); the bench invocation uses the package name.
struct BenchTarget {
    /// The cargo package name (as in `cargo bench -p <name>`).
    package: &'static str,
    /// A one-line description of what the crate benches.
    description: &'static str,
}

/// The Phase 0 bench registry. Add crates here as they gain benches.
/// A missing entry here when a crate has benches is a bug — the
/// harness exists to make bench coverage explicit.
const BENCHES: &[BenchTarget] = &[
    BenchTarget {
        package: "primitives",
        description: "Fixed-point arithmetic (mul_div, add, sub)",
    },
    BenchTarget {
        package: "codec",
        description: "Wire codec encode/decode + bincode head-to-head",
    },
    BenchTarget {
        package: "crypto",
        description: "Domain-separated BLAKE3 hashing (hash_one, hash_pair)",
    },
    BenchTarget {
        package: "storage",
        description: "Journal append gate + MMR push/root/proof gates",
    },
];

fn print_list() {
    println!("Registered bench targets:");
    for t in BENCHES {
        println!("  {:<12} {}", t.package, t.description);
    }
}

fn run_one(target: &BenchTarget) -> bool {
    println!("\n=== bench: {} — {} ===", target.package, target.description);
    let result = Command::new("cargo").args(["bench", "-p", target.package]).status();
    match result {
        Ok(status) if status.success() => {
            println!("✓ {} benches passed", target.package);
            true
        }
        Ok(status) => {
            eprintln!("✗ {} benches FAILED (exit {})", target.package, status);
            false
        }
        Err(e) => {
            eprintln!("✗ {} benches: could not run cargo bench: {e}", target.package);
            false
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--list" || a == "-l") {
        print_list();
        return ExitCode::SUCCESS;
    }

    let targets: Vec<&BenchTarget> = if args.is_empty() {
        BENCHES.iter().collect()
    } else {
        let mut found = Vec::new();
        for name in &args {
            if let Some(t) = BENCHES.iter().find(|t| t.package == name.as_str()) {
                found.push(t);
            } else {
                eprintln!("unknown bench target: {name}");
                eprintln!("run `oxide-bench --list` to see registered targets");
                return ExitCode::FAILURE;
            }
        }
        found
    };

    println!("Running {} bench target(s)…", targets.len());
    let mut all_passed = true;
    let mut results: Vec<(&BenchTarget, bool)> = Vec::new();
    for target in &targets {
        let passed = run_one(target);
        if !passed {
            all_passed = false;
        }
        results.push((target, passed));
    }

    println!("\n=== summary ===");
    for (target, passed) in &results {
        let status = if *passed { "PASS" } else { "FAIL" };
        println!("  {:<12} {status}", target.package);
    }

    if all_passed {
        println!("\nAll benches passed.");
        ExitCode::SUCCESS
    } else {
        eprintln!("\nSome benches FAILED.");
        ExitCode::FAILURE
    }
}
