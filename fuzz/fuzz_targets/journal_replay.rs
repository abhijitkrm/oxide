#![no_main]
//! Fuzz target: journal replay over arbitrary (possibly corrupt) bytes.
//!
//! The journal must never panic on any byte input — a torn tail or
//! corrupted segment returns a replay result that stops at the last
//! valid record, never crashes. This target writes arbitrary bytes as
//! a segment file in a journal directory and replays.

use storage::journal::replay;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // The journal replays a *directory* of segment files. Create a
    // temp dir, write the fuzz input as a segment file, and replay.
    // The journal must handle any byte sequence without panicking —
    // corrupted magic/CRC/lengths are detected and truncate replay.
    let dir = std::env::temp_dir().join(format!(
        "oxide-fuzz-journal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    // Segment files are named `segment-<seq>.log` (SEGMENT_PREFIX in
    // the journal); anything else is ignored by `segment_files` — a
    // bare `0.log` would exercise only the empty-replay path.
    let path = dir.join("segment-0.log");
    let _ = std::fs::write(&path, data);

    // Attempt replay — must not panic regardless of content.
    let _ = replay(&dir);

    // Clean up.
    let _ = std::fs::remove_dir_all(&dir);
});
