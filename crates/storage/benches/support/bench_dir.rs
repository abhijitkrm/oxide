//! Scratch-directory selection for durability benchmarks
//! (hft-audit-2 §8, "Durability benches run on tmpfs").
//!
//! ## What / why
//!
//! The journal, backend and consensus WAL benches used
//! `std::env::temp_dir()` / `tempfile::tempdir()`, i.e. `/tmp` — which
//! is tmpfs on most Linux hosts and CI images. Every "fsync" row then
//! measured RAM: the ~4 ms real `fdatasync` cost on the audit box was
//! invisible to the suite. This module points those benches at a real
//! filesystem by default and lets the operator choose one explicitly:
//!
//! - `OXIDE_BENCH_DIR=<path>` — use `<path>` (created if missing). Point
//!   it at the validator's data volume to measure production fsync.
//! - otherwise `CARGO_TARGET_TMPDIR` — the scratch dir cargo provides to
//!   bench/integration-test builds, under `target/` (a disk-backed
//!   filesystem on any normal checkout).
//!
//! [`fs_type`] reports which filesystem actually backs the directory so
//! durability rows can carry it in their name (`…/ext4`, `…/tmpfs`) and
//! a tmpfs measurement can never pass for a disk one.
//!
//! Shared by `storage` and `consensus` benches via `#[path]` — one copy
//! of the policy, not two that drift.
//!
//! ## Invariants
//!
//! - [`scratch_dir`] always returns an empty, existing directory unique
//!   to (process, tag).
//! - Nothing here is used outside benches; panics (`expect`) are the
//!   right failure mode for a misconfigured bench run.

// Each including bench uses a subset of these helpers; the rest would
// trip `dead_code` under `-D warnings` in that bench crate only.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Environment variable overriding the bench scratch root.
pub const BENCH_DIR_ENV: &str = "OXIDE_BENCH_DIR";

/// Root directory for durability-bench scratch files: `$OXIDE_BENCH_DIR`
/// if set, else cargo's `CARGO_TARGET_TMPDIR` (under `target/`).
///
/// # Panics
/// If the directory cannot be created — a bench run with an unusable
/// scratch root has nothing meaningful to measure.
pub fn bench_root() -> PathBuf {
    let root = std::env::var_os(BENCH_DIR_ENV)
        .map_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")), PathBuf::from);
    std::fs::create_dir_all(&root).expect("create bench scratch root");
    root
}

/// A fresh, empty directory `<bench_root>/<prefix>-<pid>-<tag>`.
///
/// # Panics
/// If the directory cannot be (re)created.
pub fn scratch_dir(prefix: &str, tag: &str) -> PathBuf {
    let dir = bench_root().join(format!("{prefix}-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create bench scratch dir");
    dir
}

/// Filesystem type backing `path` (`"ext4"`, `"xfs"`, `"tmpfs"`, …):
/// the longest mount point in `/proc/self/mountinfo` that prefixes the
/// canonicalized path. `"unknown"` off Linux or if unreadable.
pub fn fs_type(path: &Path) -> String {
    let Ok(path) = path.canonicalize() else {
        return "unknown".to_owned();
    };
    let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return "unknown".to_owned();
    };
    let mut best: Option<(usize, String)> = None;
    for line in info.lines() {
        // Format: id parent maj:min root MOUNT_POINT opts... - FSTYPE src sopts
        let Some((pre, post)) = line.split_once(" - ") else { continue };
        let Some(mount_point) = pre.split(' ').nth(4) else { continue };
        let Some(fstype) = post.split(' ').next() else { continue };
        // mountinfo escapes spaces as \040; such mount points simply
        // fail to match, falling back to their parent's type.
        if path.starts_with(mount_point)
            && best.as_ref().is_none_or(|(len, _)| mount_point.len() > *len)
        {
            best = Some((mount_point.len(), fstype.to_owned()));
        }
    }
    best.map_or_else(|| "unknown".to_owned(), |(_, t)| t)
}
