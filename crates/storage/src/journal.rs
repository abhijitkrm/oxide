//! Append-only, CRC-checked journal — the durability primitive
//! (docs/storage-spec.md §2).
//!
//! ## What this module does
//!
//! `JournalWriter` appends length-framed records into an in-memory group
//! buffer; `flush()` hands the buffer to the OS in one write; `sync()`
//! fdatasyncs the active segment. Segments rotate at a size bound so old
//! segments are immutable files the archive tier can move without format
//! conversion. `replay()` walks segments in order, validating every
//! record's CRC, and stops at the first torn or corrupt record — crash
//! recovery is "trust the complete prefix", never guesswork.
//!
//! ## Why group commit
//!
//! One fsync per 50–100ms block *batch* instead of per record: the OS
//! sees one large sequential write (the shape disks are best at), and
//! the consensus critical path never waits on per-op durability. A
//! record is durable exactly when its segment has been flushed and
//! synced — callers sync once per committed batch, per the durability
//! contract in the spec.
//!
//! ## Invariants
//!
//! - std-only core (framing, CRC-32, IO) — no dependencies.
//! - No method panics on malformed on-disk bytes; every failure is a
//!   typed [`JournalError`].
//! - Locations are stable for a record's lifetime: `(segment, offset,
//!   len)` never changes once returned (segments are immutable once
//!   rotated; the active segment only grows).

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Segment file magic + format version: `"OXDJRN01"`. Bumping the
/// version is a migration (replay of old segments must keep working or
/// be explicitly converted), never a silent format change.
const SEGMENT_MAGIC: [u8; 8] = *b"OXDJRN01";

/// Filename prefix for segments; `segment-<seq>.log` (seq 0-based).
const SEGMENT_PREFIX: &str = "segment-";

/// Maximum record payload: 16 MiB.
///
/// Origin: spec §2 rule 1. A bound is required so replay of a corrupted
/// `len` field cannot ask to buffer gigabytes before the CRC check
/// runs; 16 MiB comfortably covers any block-batch artifact we design
/// (largest is a block body chunk) while staying trivially allocatable.
pub const MAX_RECORD_BYTES: u32 = 16 * 1024 * 1024;

/// Everything that can go wrong in the journal, split so callers can
/// tell *operational* failure (io) from *invalid input* (oversize
/// record) — the production-rust skill §3 distinction.
#[derive(Debug)]
pub enum JournalError {
    /// Underlying filesystem failure (permissions, disk full, …).
    Io(io::Error),
    /// A caller tried to append a payload larger than
    /// [`MAX_RECORD_BYTES`] — a caller bug, not an environment fault.
    RecordTooLarge {
        /// Payload size attempted.
        len: usize,
        /// The configured ceiling.
        max: u32,
    },
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            JournalError::Io(ref e) => write!(f, "journal io error: {e}"),
            JournalError::RecordTooLarge { len, max } => {
                write!(f, "record payload {len} bytes exceeds max {max}")
            }
        }
    }
}

impl std::error::Error for JournalError {
    // io::Error is the natural source for the Io arm; RecordTooLarge is
    // purely informational (caller-side bug), so no source.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            JournalError::Io(ref e) => Some(e),
            JournalError::RecordTooLarge { .. } => None,
        }
    }
}

/// Identifies one journal record for its lifetime.
///
/// `offset` is the record's position within its segment (0 = first
/// record after the header), so `(segment, offset)` addresses every
/// byte the journal ever wrote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Location {
    /// Segment sequence number (0-based, from the filename).
    pub segment: u32,
    /// Byte offset of the record's `len` field within the segment.
    pub offset: u64,
    /// Payload byte count.
    pub len: u32,
}

/// Tuning for [`JournalWriter`]; defaults are protocol-shaped, not
/// arbitrary (see field docs).
#[derive(Clone, Copy, Debug)]
pub struct JournalConfig {
    /// Rotate to a new segment when the active one exceeds this many
    /// payload bytes. Default 256 MiB: large enough that rotation is
    /// rare (minutes of full-rate blocks), small enough that a single
    /// segment is a natural archive/cold-tier unit.
    pub max_segment_bytes: usize,
}

impl Default for JournalConfig {
    fn default() -> Self {
        JournalConfig { max_segment_bytes: 256 * 1024 * 1024 }
    }
}

/// Write side of the journal: append, flush, sync, rotate.
///
/// Cold path (open/rotate/sync) may do IO; [`JournalWriter::append`] is
/// pure memory — that asymmetry is the entire point of group commit.
pub struct JournalWriter {
    dir: PathBuf,
    segment: u32,
    file: File,
    /// Group-commit buffer for the active segment (framed records).
    buf: Vec<u8>,
    /// Payload bytes committed to the active segment so far.
    segment_bytes: usize,
    /// Byte offset of the next record within the active segment.
    next_offset: u64,
    config: JournalConfig,
}

impl JournalWriter {
    /// Open (or create) a journal in `dir`, starting a **fresh segment**.
    ///
    /// Recovery flow per the spec: call [`replay`] first (it tolerates
    /// torn tails), then continue writing here — a new segment means a
    /// torn old tail can never be re-appended onto.
    ///
    /// # Errors
    /// [`JournalError::Io`] if the directory cannot be created/read or
    /// the new segment file cannot be written.
    pub fn create(dir: &Path, config: JournalConfig) -> Result<Self, JournalError> {
        std::fs::create_dir_all(dir).map_err(JournalError::Io)?;
        let segment = next_segment_seq(dir)?;
        let (file, buf) = new_segment_file(dir, segment)?;
        Ok(JournalWriter {
            dir: dir.to_path_buf(),
            segment,
            file,
            buf,
            segment_bytes: 0,
            next_offset: 0,
            config,
        })
    }

    /// Append one record; returns its lifetime-stable [`Location`].
    ///
    /// Pure memory (buffer + CRC): the per-op hot path. Rotation is
    /// checked first so a single record never straddles segments.
    ///
    /// # Errors
    /// [`JournalError::RecordTooLarge`] if the payload exceeds
    /// [`MAX_RECORD_BYTES`] (rejected before any bytes are buffered).
    pub fn append(&mut self, payload: &[u8]) -> Result<Location, JournalError> {
        let len = u32::try_from(payload.len()).map_err(|_| JournalError::RecordTooLarge {
            len: payload.len(),
            max: MAX_RECORD_BYTES,
        })?;
        if payload.len() > MAX_RECORD_BYTES as usize {
            return Err(JournalError::RecordTooLarge { len: payload.len(), max: MAX_RECORD_BYTES });
        }
        // Framing: [len u32 LE][crc32 u32 LE][payload].
        let record_bytes = 8 + payload.len();
        if self.segment_bytes + self.buf.len() + record_bytes > self.config.max_segment_bytes
            && self.next_offset > 0
        {
            // Never rotate an empty segment (first oversized record of a
            // fresh segment stays — a hard floor beats an infinite loop
            // of rotations for pathologically large records).
            self.rotate()?;
        }
        let location = Location { segment: self.segment, offset: self.next_offset, len };
        self.buf.extend_from_slice(&len.to_le_bytes());
        let crc = crc32(payload);
        self.buf.extend_from_slice(&crc.to_le_bytes());
        self.buf.extend_from_slice(payload);
        self.next_offset += record_bytes as u64;
        Ok(location)
    }

    /// Hand the group buffer to the OS in one sequential write.
    ///
    /// # Errors
    /// [`JournalError::Io`] on write failure.
    pub fn flush(&mut self) -> Result<(), JournalError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.file.write_all(&self.buf).map_err(JournalError::Io)?;
        self.segment_bytes += self.buf.len();
        self.buf.clear();
        Ok(())
    }

    /// Flush, then `fdatasync` the active segment — the durability
    /// point. Callers invoke this once per committed block batch.
    ///
    /// # Errors
    /// [`JournalError::Io`] on write or sync failure.
    pub fn sync(&mut self) -> Result<(), JournalError> {
        self.flush()?;
        self.file.sync_data().map_err(JournalError::Io)?;
        Ok(())
    }

    /// Finish the active segment and start the next one.
    fn rotate(&mut self) -> Result<(), JournalError> {
        self.flush()?;
        self.segment += 1;
        let (file, buf) = new_segment_file(&self.dir, self.segment)?;
        self.file = file;
        self.buf = buf;
        self.segment_bytes = 0;
        self.next_offset = 0;
        Ok(())
    }

    /// The sequence number of the currently-active segment.
    ///
    /// Callers pin a pruning watermark against this: everything
    /// strictly below it is sealed and deletable; the active
    /// segment is never prunable (it is still being written).
    pub fn active_segment(&self) -> u32 {
        self.segment
    }

    /// Flush, seal, and rotate to a fresh segment — even if the
    /// current one hasn't hit the size bound.
    ///
    /// Used by checkpointing: a checkpoint marker must be the FIRST
    /// record of its segment so that pruning below that segment
    /// leaves the marker as the first record replay sees.
    ///
    /// # Errors
    /// [`JournalError::Io`] on flush or segment-file failure.
    pub fn seal_and_rotate(&mut self) -> Result<(), JournalError> {
        self.rotate()
    }

    /// Delete sealed segment files with `seq < watermark`. Returns
    /// the number of files removed.
    ///
    /// Pruning is a one-way door for replay: records in deleted
    /// segments are gone forever — the caller MUST have a state
    /// checkpoint covering them (see `JournalBackend::checkpoint`)
    /// or accept that `replay` now yields only the suffix. The
    /// active segment is never touched regardless of the watermark.
    ///
    /// # Errors
    /// [`JournalError::Io`] on flush failure (sealed segments are
    /// flushed before any deletion so no buffered bytes are lost)
    /// or on a filesystem error removing a file.
    pub fn prune_below(&mut self, watermark: u32) -> Result<u32, JournalError> {
        // Flush the group buffer first — anything buffered for a
        // sealed-but-unflushed tail must hit disk before we decide
        // what is safe to delete.
        self.flush()?;
        let ceiling = watermark.min(self.segment);
        let mut deleted = 0u32;
        for (seq, path) in segment_files(&self.dir)? {
            if seq < ceiling && seq != self.segment {
                std::fs::remove_file(&path).map_err(JournalError::Io)?;
                deleted += 1;
            }
        }
        Ok(deleted)
    }
}

/// One replayed record with its location.
#[derive(Clone, Debug)]
pub struct ReplayRecord {
    /// Where the record lives.
    pub location: Location,
    /// The payload bytes as written.
    pub payload: Vec<u8>,
}

/// The result of walking a journal directory.
#[derive(Debug, Default)]
pub struct Replay {
    /// Every complete, CRC-valid record, in append order.
    pub records: Vec<ReplayRecord>,
    /// The location where replay stopped, if it stopped early: the
    /// first torn or corrupt record. `None` = the journal is fully
    /// intact. Everything in `records` precedes this point and is
    /// trustworthy per spec §2 rule 1.
    pub truncated_at: Option<Location>,
}

/// Replay a journal directory: segments in sequence order, records in
/// append order, stopping at the first torn or corrupt record anywhere
/// (later segments are then unreachable-by-order and ignored).
///
/// A **missing directory is an empty journal** (`Ok` with no records):
/// replaying before the writer ever ran is the fresh-node bootstrap
/// path, not an error. Malformed *content* is also not an error — it
/// is the documented `truncated_at` path.
///
/// # Errors
/// [`JournalError::Io`] only for true IO failures (a directory that
/// exists but cannot be read, a segment that cannot be opened).
pub fn replay(dir: &Path) -> Result<Replay, JournalError> {
    let mut out = Replay::default();
    let mut segments = segment_files(dir)?;
    segments.sort_unstable();
    for (seq, path) in segments {
        let bytes = std::fs::read(&path).map_err(JournalError::Io)?;
        // Header check: a segment without our magic is not silently
        // accepted — it truncates the replay (same rule as a bad CRC:
        // trust ends where verification ends).
        if bytes.len() < SEGMENT_MAGIC.len() || bytes[..8] != SEGMENT_MAGIC {
            out.truncated_at = Some(Location { segment: seq, offset: 0, len: 0 });
            break;
        }
        // Record addressing starts at 0 (the header is excluded from
        // addressing — spec §2 rule 4), so `pos` counts record bytes
        // only while the cursor skips the header physically.
        let mut pos = 0u64;
        let mut cursor = &bytes[SEGMENT_MAGIC.len()..];
        while !cursor.is_empty() {
            // Framing parse, inline: [len u32][crc u32][payload]. Any
            // short read (torn tail) or out-of-bounds length ends the
            // replay at this position — never a panic, never a guess.
            if cursor.len() < 8 {
                out.truncated_at = Some(Location { segment: seq, offset: pos, len: 0 });
                return Ok(out);
            }
            let len_field = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
            let crc = u32::from_le_bytes([cursor[4], cursor[5], cursor[6], cursor[7]]);
            if len_field > MAX_RECORD_BYTES || cursor.len() < 8 + len_field as usize {
                // Corrupted length or torn payload: identical recovery
                // rule — the complete prefix is trustworthy, the rest is
                // not (spec §2 rule 1).
                out.truncated_at = Some(Location { segment: seq, offset: pos, len: len_field });
                return Ok(out);
            }
            let payload = &cursor[8..8 + len_field as usize];
            if crc32(payload) != crc {
                out.truncated_at = Some(Location { segment: seq, offset: pos, len: len_field });
                return Ok(out);
            }
            out.records.push(ReplayRecord {
                location: Location { segment: seq, offset: pos, len: len_field },
                payload: payload.to_vec(),
            });
            pos += 8 + u64::from(len_field);
            cursor = &cursor[8 + len_field as usize..];
        }
    }
    Ok(out)
}

/// Scan `dir` for segment files; returns `(seq, path)` pairs. A
/// missing directory yields an empty list (fresh-node bootstrap — see
/// [`replay`]'s doc).
fn segment_files(dir: &Path) -> Result<Vec<(u32, PathBuf)>, JournalError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        // NotFound = no journal yet; every other error is real IO.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(JournalError::Io(e)),
    };
    for entry in entries {
        let entry = entry.map_err(JournalError::Io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(seq) = name
            .strip_prefix(SEGMENT_PREFIX)
            .and_then(|s| s.strip_suffix(".log"))
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue; // foreign files in the directory are ignored, not fatal
        };
        out.push((seq, entry.path()));
    }
    Ok(out)
}

/// Highest existing segment seq + 1 (0 for a fresh directory).
fn next_segment_seq(dir: &Path) -> Result<u32, JournalError> {
    Ok(segment_files(dir)?.into_iter().map(|(seq, _)| seq).max().map_or(0, |m| m + 1))
}

/// Create `segment-<seq>.log` with the magic header; returns the file
/// and the (pre-written) group buffer holding the header bytes.
fn new_segment_file(dir: &Path, seq: u32) -> Result<(File, Vec<u8>), JournalError> {
    let path = dir.join(format!("{SEGMENT_PREFIX}{seq}.log"));
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(false)
        .truncate(true)
        .open(&path)
        .map_err(JournalError::Io)?;
    file.write_all(&SEGMENT_MAGIC).map_err(JournalError::Io)?;
    Ok((file, Vec::new()))
}

/// IEEE CRC-32 (reflected, poly `0xEDB88320`, init/xorout `0xFFFF_FFFF`)
/// — the exact variant is part of the on-disk format (spec §2 rule 5).
///
/// Table-based, implemented in-crate to keep the journal core std-only.
pub fn crc32(payload: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in payload {
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ u32::from(byte)) & 0xFF) as usize];
    }
    !crc
}

/// CRC-32 reflected lookup table (generated at compile time — no runtime
/// init, no `OnceLock`, no cost).
const CRC_TABLE: [u32; 256] = build_crc_table();

/// Build the reflected CRC-32 table: `table[i]` is the remainder of
/// the byte `i` followed by 7 zero bits over the generator.
#[allow(clippy::cast_possible_truncation)]
// Justification: `i` is a u32 loop counter bounded by the literal 256,
// and 256 always fits usize on every Rust target — the cast is a width
// formality, not a truncation risk. (`usize::from(u32)` does not
// exist, and `try_from` is not const-compatible here.)
const fn build_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            // Reflected polynomial: LSB-first long division.
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp dir per test (no tempfile dep: journal core stays
    /// std-only; uniqueness via process id + a counter).
    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("oxide-journal-{}-{n}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Round trip: N appends → flush → replay returns exactly them, in
    /// order, with matching locations, and no truncation.
    #[test]
    fn test_replay_round_trip_in_order() {
        let dir = temp_dir("rt");
        let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
        let payloads: Vec<Vec<u8>> = (0..1000u32).map(|i| i.to_le_bytes().to_vec()).collect();
        let mut locs = Vec::new();
        for p in &payloads {
            locs.push(j.append(p).unwrap());
        }
        j.sync().unwrap();
        let replayed = replay(&dir).unwrap();
        assert!(replayed.truncated_at.is_none(), "intact journal must not truncate");
        assert_eq!(replayed.records.len(), 1000);
        for (i, rec) in replayed.records.iter().enumerate() {
            assert_eq!(rec.payload, payloads[i], "order and content preserved");
            assert_eq!(rec.location, locs[i], "locations match what append returned");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Torn tail: truncating the file mid-record makes replay return the
    /// complete prefix and report `truncated_at` — never a panic, never
    /// a partial record.
    #[test]
    fn test_torn_tail_returns_complete_prefix() {
        let dir = temp_dir("torn");
        let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
        for i in 0..100u32 {
            j.append(&i.to_le_bytes()).unwrap();
        }
        j.sync().unwrap();
        // Tear the last record: 8 framing bytes + 4 payload = 12 bytes;
        // drop 5 of them.
        let path = dir.join("segment-0.log");
        let full = std::fs::read(&path).unwrap();
        std::fs::write(&path, &full[..full.len() - 5]).unwrap();
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 99, "complete prefix survives");
        assert!(replayed.truncated_at.is_some(), "torn tail is reported");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Corrupt payload (CRC mismatch) truncates at that record.
    #[test]
    fn test_corrupt_record_stops_replay() {
        let dir = temp_dir("crc");
        let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
        for i in 0..10u32 {
            j.append(&i.to_le_bytes()).unwrap();
        }
        j.sync().unwrap();
        let path = dir.join("segment-0.log");
        let mut bytes = std::fs::read(&path).unwrap();
        // Header (8) + first record (8+4) = byte 20 is inside record 1's
        // payload; flip it.
        bytes[20] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 1, "only the record before the corruption");
        assert!(replayed.truncated_at.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rotation: a small `max_segment_bytes` forces multiple segments;
    /// replay preserves global order across them.
    #[test]
    fn test_rotation_preserves_order_across_segments() {
        let dir = temp_dir("rot");
        let config = JournalConfig { max_segment_bytes: 64 };
        let mut j = JournalWriter::create(&dir, config).unwrap();
        for i in 0..50u32 {
            j.append(&i.to_le_bytes()).unwrap();
        }
        j.sync().unwrap();
        let replayed = replay(&dir).unwrap();
        assert!(replayed.truncated_at.is_none());
        assert_eq!(replayed.records.len(), 50);
        for (i, rec) in replayed.records.iter().enumerate() {
            assert_eq!(rec.payload, u32::try_from(i).unwrap().to_le_bytes());
        }
        assert!(replayed.records.iter().any(|r| r.location.segment > 0), "rotation happened");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Oversized payloads are rejected before any bytes are buffered.
    #[test]
    fn test_oversize_payload_rejected() {
        let dir = temp_dir("big");
        let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
        let huge = vec![0u8; MAX_RECORD_BYTES as usize + 1];
        match j.append(&huge) {
            Err(JournalError::RecordTooLarge { len, max }) => {
                assert_eq!(len, MAX_RECORD_BYTES as usize + 1);
                assert_eq!(max, MAX_RECORD_BYTES);
            }
            other => panic!("expected RecordTooLarge, got {other:?}"),
        }
        // And the rejection left no partial framing behind.
        j.sync().unwrap();
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 0);
        assert!(replayed.truncated_at.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Empty directory replays to an empty, untruncated journal.
    #[test]
    fn test_empty_dir_replays_empty() {
        let dir = temp_dir("empty");
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 0);
        assert!(replayed.truncated_at.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CRC-32 known-answer test: the classic `"123456789"` → `0xCBF43926`
    /// pins the exact variant (reflected IEEE) the format depends on.
    #[test]
    fn test_crc32_known_answer() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
