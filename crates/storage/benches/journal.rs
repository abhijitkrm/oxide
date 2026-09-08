//! Oxide blockchain — `storage` crate journal benchmarks.
//!
//! Gates (source: docs/storage-spec.md §2, README → Roadmap Phase 0;
//! dev Mac = relative claims only until the 16-core `x86_64` rig exists):
//!
//! | Bench                        | Gate                          |
//! |------------------------------|-------------------------------|
//! | `journal/append_100b`        | p50 ≤ 1000 ns (≥1M appends/s) |
//! | `journal/append_flush_amort` | p50 ≤ 1000 ns per op          |
//!
//! Framing: `append` is the per-op hot path (pure memory: framing +
//! CRC-32 into the group buffer) — production commits once per block
//! batch, so fsync is *never* per-op and is reported separately as an
//! informational (ungated) bench.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;
use storage::{JournalConfig, JournalWriter};

/// Unique temp dir per bench run (journal core is std-only; no tempfile
/// dependency by policy — see production-rust skill §5).
fn temp_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("oxide-journal-bench-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn bench_journal(c: &mut Criterion) {
    // Per-op append: 100-byte payloads (a realistic order/fill record),
    // fresh appends into the group buffer, no IO in the loop. The huge
    // segment cap keeps rotation (a real, IO-performing event) out of
    // the timed region — the amortized bench below measures rotation
    // honestly at production cadence instead.
    {
        let dir = temp_dir("append");
        let mut j = JournalWriter::create(&dir, JournalConfig { max_segment_bytes: 1 << 40 })
            .expect("writer");
        let payload = [0x5Au8; 100];
        let mut n = 0u64;
        c.bench_function("journal/append_100b", |b| {
            b.iter(|| {
                let loc = j.append(black_box(&payload)).expect("append");
                black_box(loc);
                n += 1;
            });
            // Drain the group buffer so memory stays bounded across
            // criterion's samples (outside the timed region semantics
            // are unchanged: flush is batched in production too).
            let _ = j.flush();
        });
        let _ = n;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Amortized append+flush: 1000-record batches, one OS write each —
    // the exact production cadence (group commit), per-op amortized.
    {
        let dir = temp_dir("amort");
        let mut j = JournalWriter::create(&dir, JournalConfig::default()).expect("writer");
        let payload = [0x5Au8; 100];
        c.bench_function("journal/append_flush_amort", |b| {
            b.iter(|| {
                for _ in 0..1000 {
                    black_box(j.append(black_box(&payload)).expect("append"));
                }
                j.flush().expect("flush");
            });
        });
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Informational, NOT gated: the durability point (fdatasync). Its
    // cost is paid once per committed block batch in production, never
    // per op; the number is machine/OS/filesystem-dependent.
    {
        let dir = temp_dir("sync");
        let mut j = JournalWriter::create(&dir, JournalConfig::default()).expect("writer");
        let payload = [0x5Au8; 100];
        c.bench_function("journal/sync_1000_records_info", |b| {
            b.iter(|| {
                for _ in 0..1000 {
                    black_box(j.append(black_box(&payload)).expect("append"));
                }
                j.sync().expect("sync");
            });
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}

criterion_group!(benches, bench_journal);
criterion_main!(benches);
