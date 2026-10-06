#![no_main]
//! Fuzz target: journal replay over arbitrary (possibly corrupt) bytes.
//!
//! The journal must never panic on any byte input — a torn tail or
//! corrupted segment ends that segment's replay at its last valid
//! record, and replay continues into later segments (the writer
//! restarts on a fresh segment after a crash, so post-restart history
//! sits past the tear). The input is split into up to three segment
//! files so that cross-segment continuation is exercised, and the
//! result is checked against invariants, not just for absence of
//! panics.

use storage::journal::replay;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let dir = std::env::temp_dir().join(format!(
        "oxide-fuzz-journal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);

    // First byte picks the segment count (1..=3); the rest is cut at
    // evenly spaced points so each segment gets a share of the input.
    let (segments, body) = match data.split_first() {
        Some((&n, rest)) => (usize::from(n % 3) + 1, rest),
        None => (1, data),
    };
    let chunk = body.len().div_ceil(segments).max(1);
    let mut lens = Vec::new();
    for (seq, part) in body.chunks(chunk).take(segments).enumerate() {
        // Segment files are named `segment-<seq>.log` (SEGMENT_PREFIX
        // in the journal); anything else is ignored.
        let _ = std::fs::write(dir.join(format!("segment-{seq}.log")), part);
        lens.push(part.len() as u64);
    }

    if let Ok(out) = replay(&dir) {
        // Records come back in strictly increasing (segment, offset)
        // order and each lies inside its segment file.
        let mut prev: Option<(u32, u64)> = None;
        for rec in &out.records {
            let key = (rec.location.segment, rec.location.offset);
            assert!(prev.is_none_or(|p| key > p), "records out of order: {prev:?} then {key:?}");
            prev = Some(key);
            let seg_len = lens.get(rec.location.segment as usize).copied().unwrap_or(0);
            // 8-byte magic + record offset + 8-byte frame + payload.
            assert!(
                8 + rec.location.offset + 8 + u64::from(rec.location.len) <= seg_len,
                "record overruns its segment"
            );
            assert_eq!(rec.payload.len(), rec.location.len as usize);
        }
        // A reported tear names a real segment.
        if let Some(t) = out.truncated_at {
            assert!((t.segment as usize) < lens.len(), "tear in a nonexistent segment");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
});
