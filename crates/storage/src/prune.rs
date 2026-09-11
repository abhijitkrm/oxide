//! State pruning — delete old journal segments to bound disk usage.
//!
//! # What this is
//!
//! A pruning policy that deletes old journal segment files when
//! they are no longer needed for replay or state reconstruction.
//! The journal (§journal) appends records to segment files that
//! rotate at a size threshold. Without pruning, these segments
//! accumulate indefinitely. Pruning deletes segments older than a
//! configurable retention window.
//!
//! # Why this exists
//!
//! A full node stores every block since genesis in the journal.
//! At 50–100ms blocks with ~1 MiB bodies, that's 10–20 MiB/s or
//! ~1 TiB/day. No production node can keep all history on disk.
//! Pruning deletes old segments once the state they contain has
//! been committed to the KV backend and is no longer needed for
//! crash recovery.
//!
//! # Safety contract
//!
//! A segment can be pruned only when:
//! 1. All records in the segment have been applied to the KV
//!    backend (the state is durable in the backend).
//! 2. The segment is older than the retention window (default:
//!    keep the last 1000 segments, or ~256 GiB at default size).
//! 3. No in-progress replay is reading the segment.
//!
//! The pruner does NOT delete the active segment (the one the
//! `JournalWriter` is currently appending to) or any segment
//! newer than the retention window.
//!
//! # Phase scope
//!
//! Phase 3: segment-level pruning with a count-based retention
//! window. No height-indexed pruning, no compaction, no
//! state-snapshot-based pruning. Those arrive in Phase 4+ with
//! the production storage stack.

use std::fs;
use std::path::{Path, PathBuf};

/// The default retention window: keep the last 1000 segments.
///
/// At the default segment size of 256 MiB, this retains ~256 GiB
/// of journal history. The tradeoff: higher retention = more
/// crash-recovery history but more disk usage; lower retention =
/// less disk but less recovery history. A node that needs full
/// history from genesis should set this to `u32::MAX`.
const DEFAULT_RETAIN_SEGMENTS: u32 = 1000;

/// The filename prefix for journal segments.
const SEGMENT_PREFIX: &str = "segment-";

/// The filename suffix for journal segments.
const SEGMENT_SUFFIX: &str = ".log";

/// A pruning policy for journal segments.
///
/// The pruner deletes segment files older than the retention
/// window. It does NOT delete the active segment or any segment
/// within the retention window.
#[derive(Debug, Clone, Copy)]
pub struct PrunePolicy {
    /// The number of recent segments to retain.
    pub retain_segments: u32,
}

impl Default for PrunePolicy {
    fn default() -> Self {
        Self { retain_segments: DEFAULT_RETAIN_SEGMENTS }
    }
}

impl PrunePolicy {
    /// Construct a policy that retains the last `n` segments.
    #[must_use]
    pub fn retain(n: u32) -> Self {
        Self { retain_segments: n }
    }

    /// Construct a policy that retains all segments (no pruning).
    #[must_use]
    pub fn retain_all() -> Self {
        Self { retain_segments: u32::MAX }
    }
}

/// The result of a pruning pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneResult {
    /// The number of segment files deleted.
    pub segments_deleted: u32,
    /// The number of bytes freed (sum of deleted file sizes).
    pub bytes_freed: u64,
}

impl PruneResult {
    /// An empty prune result (nothing deleted).
    #[must_use]
    pub const fn empty() -> Self {
        Self { segments_deleted: 0, bytes_freed: 0 }
    }

    /// Whether any segments were pruned.
    #[must_use]
    pub const fn pruned(&self) -> bool {
        self.segments_deleted > 0
    }
}

/// Prune old journal segments from `dir` according to `policy`.
///
/// Scans the directory for `segment-<seq>.log` files, sorts them
/// by sequence number, and deletes all segments older than the
/// retention window (i.e., all but the last `policy.retain_segments`
/// segments).
///
/// The active segment (the highest-numbered segment) is always
/// retained, regardless of the policy.
///
/// # Errors
///
/// Returns `io::Error` if the directory cannot be read or a
/// segment file cannot be deleted.
///
/// # Panics
///
/// Does not panic. Malformed segment filenames are silently
/// skipped (they don't match the `segment-<seq>.log` pattern).
pub fn prune_segments(dir: &Path, policy: PrunePolicy) -> Result<PruneResult, std::io::Error> {
    let mut segments = list_segments(dir)?;
    if segments.len() <= policy.retain_segments as usize {
        return Ok(PruneResult::empty());
    }
    // Sort by sequence number (ascending).
    segments.sort_by_key(|(seq, _)| *seq);
    // Delete all but the last `retain_segments` segments.
    let retain = policy.retain_segments as usize;
    let to_delete = &segments[..segments.len() - retain];
    let mut deleted = 0u32;
    let mut bytes_freed = 0u64;
    for (_, path) in to_delete {
        let size = match fs::metadata(path) {
            Ok(m) => m.len(),
            Err(_) => 0,
        };
        match fs::remove_file(path) {
            Ok(()) => {
                deleted += 1;
                bytes_freed += size;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already deleted — not an error.
            }
            Err(e) => return Err(e),
        }
    }
    Ok(PruneResult { segments_deleted: deleted, bytes_freed })
}

/// List all journal segment files in `dir`, returning
/// `(sequence_number, path)` pairs.
///
/// Files that don't match the `segment-<seq>.log` pattern are
/// silently skipped.
fn list_segments(dir: &Path) -> Result<Vec<(u32, PathBuf)>, std::io::Error> {
    let mut segments = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(seq) = parse_segment_name(&name) {
            segments.push((seq, entry.path()));
        }
    }
    Ok(segments)
}

/// Parse a segment filename to extract the sequence number.
///
/// Returns `None` if the name doesn't match `segment-<seq>.log`.
fn parse_segment_name(name: &str) -> Option<u32> {
    let rest = name.strip_prefix(SEGMENT_PREFIX)?;
    let num_str = rest.strip_suffix(SEGMENT_SUFFIX)?;
    num_str.parse().ok()
}

/// The total disk usage of all journal segment files in `dir`.
///
/// Returns the sum of file sizes in bytes. Useful for monitoring
/// and for deciding when to prune.
///
/// # Errors
///
/// Returns `io::Error` if the directory cannot be read.
pub fn disk_usage(dir: &Path) -> Result<u64, std::io::Error> {
    let segments = list_segments(dir)?;
    let mut total = 0u64;
    for (_, path) in &segments {
        if let Ok(m) = fs::metadata(path) {
            total += m.len();
        }
    }
    Ok(total)
}

/// The number of journal segment files in `dir`.
///
/// # Errors
///
/// Returns `io::Error` if the directory cannot be read.
pub fn segment_count(dir: &Path) -> Result<usize, std::io::Error> {
    Ok(list_segments(dir)?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a temp dir with `n` segment files of the given size.
    fn make_dir_with_segments(n: u32, size: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for i in 0..n {
            let name = format!("{SEGMENT_PREFIX}{i}{SEGMENT_SUFFIX}");
            let path = dir.path().join(name);
            fs::write(&path, vec![0u8; size]).expect("write segment");
        }
        dir
    }

    #[test]
    fn parse_segment_name_valid() {
        assert_eq!(parse_segment_name("segment-0.log"), Some(0));
        assert_eq!(parse_segment_name("segment-42.log"), Some(42));
        assert_eq!(parse_segment_name("segment-999.log"), Some(999));
    }

    #[test]
    fn parse_segment_name_invalid() {
        assert_eq!(parse_segment_name("segment.log"), None);
        assert_eq!(parse_segment_name("segment-abc.log"), None);
        assert_eq!(parse_segment_name("other-0.log"), None);
        assert_eq!(parse_segment_name("segment-0.txt"), None);
    }

    #[test]
    fn prune_keeps_recent_segments() {
        let dir = make_dir_with_segments(10, 1024);
        let policy = PrunePolicy::retain(3);
        let result = prune_segments(dir.path(), policy).expect("prune");
        assert_eq!(result.segments_deleted, 7);
        assert!(result.pruned());
        // Only 3 segments remain.
        assert_eq!(segment_count(dir.path()).unwrap(), 3);
        // The remaining segments are the 3 highest-numbered.
        let mut remaining = list_segments(dir.path()).unwrap();
        remaining.sort_by_key(|(s, _)| *s);
        let seqs: Vec<u32> = remaining.iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, vec![7, 8, 9]);
    }

    #[test]
    fn prune_nothing_when_under_retention() {
        let dir = make_dir_with_segments(5, 1024);
        let policy = PrunePolicy::retain(10);
        let result = prune_segments(dir.path(), policy).expect("prune");
        assert_eq!(result, PruneResult::empty());
        assert!(!result.pruned());
        assert_eq!(segment_count(dir.path()).unwrap(), 5);
    }

    #[test]
    fn prune_all_but_one() {
        let dir = make_dir_with_segments(10, 1024);
        let policy = PrunePolicy::retain(1);
        let result = prune_segments(dir.path(), policy).expect("prune");
        assert_eq!(result.segments_deleted, 9);
        assert_eq!(segment_count(dir.path()).unwrap(), 1);
        let remaining = list_segments(dir.path()).unwrap();
        assert_eq!(remaining[0].0, 9);
    }

    #[test]
    fn prune_empty_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = PrunePolicy::default();
        let result = prune_segments(dir.path(), policy).expect("prune");
        assert_eq!(result, PruneResult::empty());
    }

    #[test]
    fn prune_retain_all() {
        let dir = make_dir_with_segments(10, 1024);
        let policy = PrunePolicy::retain_all();
        let result = prune_segments(dir.path(), policy).expect("prune");
        assert_eq!(result, PruneResult::empty());
        assert_eq!(segment_count(dir.path()).unwrap(), 10);
    }

    #[test]
    fn disk_usage_reports_total() {
        let dir = make_dir_with_segments(5, 1024);
        let usage = disk_usage(dir.path()).expect("disk_usage");
        assert_eq!(usage, 5 * 1024);
    }

    #[test]
    fn disk_usage_empty_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let usage = disk_usage(dir.path()).expect("disk_usage");
        assert_eq!(usage, 0);
    }

    #[test]
    fn segment_count_correct() {
        let dir = make_dir_with_segments(7, 512);
        assert_eq!(segment_count(dir.path()).unwrap(), 7);
    }

    #[test]
    fn prune_ignores_non_segment_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Create some segment files.
        for i in 0..5 {
            let path = dir.path().join(format!("{SEGMENT_PREFIX}{i}{SEGMENT_SUFFIX}"));
            fs::write(&path, b"data").expect("write");
        }
        // Create a non-segment file.
        fs::write(dir.path().join("other.txt"), b"not a segment").expect("write");
        let policy = PrunePolicy::retain(2);
        let result = prune_segments(dir.path(), policy).expect("prune");
        assert_eq!(result.segments_deleted, 3);
        // The non-segment file is still there.
        assert!(dir.path().join("other.txt").exists());
        assert_eq!(segment_count(dir.path()).unwrap(), 2);
    }

    #[test]
    fn prune_frees_bytes() {
        let dir = make_dir_with_segments(10, 4096);
        let policy = PrunePolicy::retain(3);
        let result = prune_segments(dir.path(), policy).expect("prune");
        assert_eq!(result.segments_deleted, 7);
        assert_eq!(result.bytes_freed, 7 * 4096);
    }
}
