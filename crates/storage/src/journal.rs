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

/// Sidecar index mapping `segment seq → max block height it
/// contains`. Append-only log of 12-byte records
/// `[seq:u32 LE][max_height:u64 LE]` written at segment rotation —
/// the height-indexed half of pruning (`prune_below_height`) reads
/// it to map "delete history below height H" onto segment files.
///
/// Only segments sealed *through `rotate`* get an entry: a segment
/// left active by a crash has no final height recorded, so the
/// height-pruner conservatively skips it (never deletes unknown
/// state — count-based pruning remains the bound for unindexed
/// segments).
const HEIGHT_INDEX_FILE: &str = "heights.idx";

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

/// Fault-injection points for crash-atomicity tests (audit finding:
/// conformance must establish crash atomicity via fault injection at
/// the write/flush/sync/rotation/checkpoint/reopen boundaries). Each
/// arm names the exact operation a crash interrupts; once it fires,
/// the correct continuation is "drop the writer and reopen" — a dead
/// process does not resume mid-call.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FaultPoint {
    /// `flush`'s `write_all` — the buffered group commit never reaches
    /// the OS. The file keeps only what earlier flushes wrote.
    FlushWrite,
    /// `sync`'s `sync_data` — bytes sit in the page cache, never
    /// durable. (On local filesystems the bytes still reach the file
    /// via `write_all`, so post-reopen they replay — the injected
    /// failure models the API boundary, not lost pages.)
    SyncFsync,
    /// `rotate`'s seal `sync_data` — the sealed segment's tail was
    /// flushed but not synced before the handle moved on.
    RotateSealSync,
    /// `rotate`'s height-index append — the segment is sealed on disk
    /// but `heights.idx` never records it: the crash state a
    /// height-prune must survive (unindexed = "unknown contents,
    /// never delete").
    RotateHeightIndex,
    /// `rotate`'s successor-file create — the sealed segment is on
    /// disk and indexed, but `segment-<n+1>.log` never existed.
    RotateCreate,
    /// `JournalBackend::checkpoint`'s marker `sync` — the marker was
    /// framed into the buffer but never reached the OS, so a crash
    /// must reopen the journal as if no checkpoint happened.
    CheckpointSync,
    /// `snapshot_import`'s journal append — the replacement batch
    /// never reaches the journal, so the import must roll back
    /// rather than swap in-memory state the disk cannot replay.
    ///
    /// Set on `JournalWriter`; the append itself is memory-only, so
    /// the injection point is checked at the top of `append` — it
    /// models "the process died before the record was framed", the
    /// strongest form of an import crash.
    Append,
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
    /// Highest block height appended to the *active* segment via
    /// [`append_at_height`](Self::append_at_height). `None` when the
    /// segment holds no height-tagged records — such segments get
    /// no `heights.idx` entry and are skipped by height pruning.
    current_segment_max: Option<u64>,
    config: JournalConfig,
    /// Armed one-shot fault point — see [`FaultPoint`]. Test builds
    /// only: the field does not exist in production, so the injector
    /// costs nothing and cannot leak into a release binary.
    #[cfg(test)]
    fault: Option<FaultPoint>,
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
            current_segment_max: None,
            config,
            #[cfg(test)]
            fault: None,
        })
    }

    /// Fire the armed fault point exactly once (one-shot: a dead
    /// process does not fail the same boundary twice). Callers treat
    /// the `Err` like any `JournalError::Io` — and the crash-faithful
    /// continuation is to drop the writer and reopen the directory.
    #[cfg(test)]
    pub(crate) fn check_fault(&mut self, point: FaultPoint) -> Result<(), JournalError> {
        if self.fault == Some(point) {
            self.fault = None;
            return Err(JournalError::Io(io::Error::other("injected fault")));
        }
        Ok(())
    }

    /// Arm a one-shot fault at `point` — crash-atomicity test hook.
    /// `pub(crate)` so `AuthenticatedJournal`/`JournalBackend` can
    /// forward it; invisible outside the crate's test build.
    #[cfg(test)]
    pub(crate) fn inject_fault(&mut self, point: FaultPoint) {
        self.fault = Some(point);
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
        #[cfg(test)]
        self.check_fault(FaultPoint::Append)?;
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

    /// [`append`](Self::append) + tag the record with its block
    /// height. The tag only feeds the segment height index (the
    /// `heights.idx` sidecar) — the payload itself is untouched,
    /// so callers that already encode heights inside their records
    /// pay nothing extra.
    ///
    /// Heights need not be contiguous or unique: the index tracks
    /// the *max* height per segment, which is all the height-pruner
    /// needs to know a segment is entirely below a watermark.
    ///
    /// # Errors
    /// Same as [`append`](Self::append).
    pub fn append_at_height(
        &mut self,
        height: u64,
        payload: &[u8],
    ) -> Result<Location, JournalError> {
        // Rotation happens inside `append` — set the max first so a
        // triggering append is indexed under the NEW segment, not
        // the one it just sealed.
        let location = self.append(payload)?;
        self.current_segment_max = Some(self.current_segment_max.map_or(height, |m| m.max(height)));
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
        #[cfg(test)]
        self.check_fault(FaultPoint::FlushWrite)?;
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
        #[cfg(test)]
        self.check_fault(FaultPoint::SyncFsync)?;
        self.file.sync_data().map_err(JournalError::Io)?;
        Ok(())
    }

    /// Finish the active segment and start the next one.
    fn rotate(&mut self) -> Result<(), JournalError> {
        self.flush()?;
        // Sync the segment being sealed BEFORE swapping handles —
        // once `self.file` points at the new segment, a later `sync()`
        // only covers the new file and the sealed segment's tail
        // writes could sit in the page cache indefinitely. "Sealed"
        // must mean durable, or a crash can drop records the caller
        // believes the journal committed.
        #[cfg(test)]
        self.check_fault(FaultPoint::RotateSealSync)?;
        self.file.sync_data().map_err(JournalError::Io)?;
        // Seal the height index FIRST: the entry
        // `[sealed_seq → max_height]` must exist before the new
        // segment file does, or a concurrent height-prune could
        // see the old segment as "sealed but unindexed" (which it
        // conservatively skips anyway — but the entry is cheap:
        // 12 bytes on a path already doing IO).
        if let Some(max_height) = self.current_segment_max.take() {
            #[cfg(test)]
            self.check_fault(FaultPoint::RotateHeightIndex)?;
            append_height_index(&self.dir, self.segment, max_height)?;
        }
        self.segment += 1;
        #[cfg(test)]
        self.check_fault(FaultPoint::RotateCreate)?;
        let (file, buf) = new_segment_file(&self.dir, self.segment)?;
        self.file = file;
        self.buf = buf;
        self.segment_bytes = 0;
        self.next_offset = 0;
        Ok(())
    }

    /// Delete sealed segments whose every record is below
    /// `keep_height` — the height-indexed counterpart of
    /// [`prune_below`](Self::prune_below).
    ///
    /// A segment is deletable only when the `heights.idx` sidecar
    /// records a `max_height < keep_height` for it. Segments with
    /// no index entry — the segment active at a crash, or segments
    /// written without [`append_at_height`] — are *never* deleted
    /// by this call: unknown contents are kept, and count-based
    /// pruning (`prune_below`, `prune::prune_segments`) remains
    /// their bound. The active segment is never touched.
    ///
    /// The same one-way-door contract as `prune_below` applies:
    /// deleted records are unrecoverable — the caller needs a
    /// checkpoint covering `keep_height` or accepts a suffix-only
    /// replay.
    ///
    /// # Errors
    /// [`JournalError::Io`] on flush failure or a filesystem error
    /// removing a file. Returns `Ok(0)` when `heights.idx` does not
    /// exist (no height-tagged appends ever ran).
    pub fn prune_below_height(&mut self, keep_height: u64) -> Result<u32, JournalError> {
        self.flush()?;
        let index = read_height_index(&self.dir)?;
        let mut deleted = 0u32;
        for (seq, path) in segment_files(&self.dir)? {
            if seq == self.segment {
                continue;
            }
            let Some(max_height) = index.get(&seq) else { continue };
            if *max_height < keep_height {
                std::fs::remove_file(&path).map_err(JournalError::Io)?;
                deleted += 1;
            }
        }
        Ok(deleted)
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

/// Append one `[seq:u32 LE][max_height:u64 LE]` record to the
/// `heights.idx` sidecar. Written once per sealed segment, at
/// rotation — the write piggybacks a code path that already
/// touched the filesystem, so the index adds no extra fsync
/// cadence (the next `sync()` covers it; a lost tail entry just
/// leaves the segment unindexed, which pruning skips).
fn append_height_index(dir: &Path, seq: u32, max_height: u64) -> Result<(), JournalError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(HEIGHT_INDEX_FILE))
        .map_err(JournalError::Io)?;
    file.write_all(&seq.to_le_bytes()).map_err(JournalError::Io)?;
    file.write_all(&max_height.to_le_bytes()).map_err(JournalError::Io)
}

/// Read the `heights.idx` sidecar: `segment seq → max recorded
/// height`. Last record wins per seq (the file is append-only; a
/// seq can repeat only if a rotation entry was torn and retried).
///
/// A missing index is an empty map — callers treat unindexed
/// segments as "unknown contents, never delete by height".
/// Trailing partial records (< 12 bytes, torn write) are ignored.
///
/// # Errors
/// [`JournalError::Io`] when the file exists but can't be read.
pub fn read_height_index(dir: &Path) -> Result<std::collections::BTreeMap<u32, u64>, JournalError> {
    let bytes = match std::fs::read(dir.join(HEIGHT_INDEX_FILE)) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(std::collections::BTreeMap::new());
        }
        Err(e) => return Err(JournalError::Io(e)),
    };
    let mut out = std::collections::BTreeMap::new();
    for record in bytes.chunks_exact(12) {
        let seq = u32::from_le_bytes(record[0..4].try_into().unwrap_or([0; 4]));
        let height = u64::from_le_bytes(record[4..12].try_into().unwrap_or([0; 8]));
        out.insert(seq, height);
    }
    Ok(out)
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

    /// Height-indexed pruning: a sealed segment whose max recorded
    /// height falls below the watermark is deleted; the active
    /// segment and unindexed segments are untouched.
    #[test]
    fn test_prune_below_height_deletes_only_indexed_sealed() {
        let dir = temp_dir("hbp");
        // Small segments force rotation so several sealed segments
        // accumulate with distinct height ranges.
        let config = JournalConfig { max_segment_bytes: 64 };
        let mut j = JournalWriter::create(&dir, config).unwrap();
        // ~4-byte payloads + 8-byte framing = 12B/record → a new
        // segment every ~5 records.
        for h in 1..=40u64 {
            j.append_at_height(h, &h.to_le_bytes()).unwrap();
        }
        j.sync().unwrap();
        let index = read_height_index(&dir).unwrap();
        assert!(index.len() > 2, "several segments should be indexed, got {index:?}");

        // Prune below height 20: sealed segments with max < 20 go.
        let deleted = j.prune_below_height(20).unwrap();
        assert!(deleted > 0, "at least one old segment must be pruned");
        // Heights ≥ some boundary survive: replay must still find
        // records for heights ≥ 20 somewhere.
        let replayed = replay(&dir).unwrap();
        let surviving: Vec<u64> = replayed
            .records
            .iter()
            .map(|r| u64::from_le_bytes(r.payload.as_slice().try_into().unwrap()))
            .collect();
        assert!(surviving.contains(&40), "the tip height must survive");
        // Segments straddling the watermark keep all their records
        // (granularity is the segment, not the height) — but every
        // segment *fully* below it is gone, and heights ≥ 20 must
        // still be represented.
        assert!(surviving.iter().any(|h| *h >= 20));
        assert!(deleted >= 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The active segment is never pruned by height, even when its
    /// recorded max is below the watermark.
    #[test]
    fn test_prune_below_height_keeps_active_segment() {
        let dir = temp_dir("hbp-active");
        let config = JournalConfig { max_segment_bytes: 1 << 20 };
        let mut j = JournalWriter::create(&dir, config).unwrap();
        for h in 1..=5u64 {
            j.append_at_height(h, &h.to_le_bytes()).unwrap();
        }
        j.sync().unwrap();
        // One segment only (no rotation); it is active AND unindexed
        // (index entries are written at rotation).
        let deleted = j.prune_below_height(1_000).unwrap();
        assert_eq!(deleted, 0, "the active segment must never be pruned");
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Untagged (`append`) segments carry no heights — the
    /// height-pruner must leave them alone rather than guess.
    #[test]
    fn test_prune_below_height_skips_unindexed_segments() {
        let dir = temp_dir("hbp-unindexed");
        let config = JournalConfig { max_segment_bytes: 64 };
        let mut j = JournalWriter::create(&dir, config).unwrap();
        // Untagged appends → no heights.idx entries at all.
        for i in 0..30u32 {
            j.append(&i.to_le_bytes()).unwrap();
        }
        j.sync().unwrap();
        assert!(read_height_index(&dir).unwrap().is_empty());
        let deleted = j.prune_below_height(1_000).unwrap();
        assert_eq!(deleted, 0, "unindexed segments are never deleted by height");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------
    // Crash atomicity via fault injection.
    //
    // Each test arms a [`FaultPoint`], drops the writer on the error
    // (a dead process does not resume mid-call), reopens, and asserts
    // the disk state equals the prefix the caller had durably acked.
    // ---------------------------------------------------------------

    /// Crash inside `flush`'s `write_all`: the group buffer never
    /// reaches the file, so replay after reopen must expose only the
    /// previously-synced prefix — and the failed `append`/`flush` must
    /// not have claimed durability for anything.
    #[test]
    fn test_crash_at_flush_replays_only_durable_prefix() {
        let dir = temp_dir("fault-flush");
        {
            let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
            j.append(b"durable").unwrap();
            j.sync().unwrap();
            j.append(b"lost").unwrap();
            j.inject_fault(FaultPoint::FlushWrite);
            assert!(j.flush().is_err(), "armed flush must fail");
            // Crash: drop without flushing again.
        }
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 1, "only the synced record survives");
        assert_eq!(replayed.records[0].payload, b"durable");
        assert!(replayed.truncated_at.is_none(), "clean file, no torn tail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Crash at `sync`'s fsync: `write_all` already ran, so the bytes
    /// are in the file — the error lies about durability only. The
    /// caller must see the failure (never a false durable ack), and a
    /// real crash where the pages did land replays the record whole.
    #[test]
    fn test_crash_at_sync_reports_failure_but_bytes_landed() {
        let dir = temp_dir("fault-sync");
        {
            let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
            j.append(b"payload").unwrap();
            j.inject_fault(FaultPoint::SyncFsync);
            assert!(j.sync().is_err(), "armed sync must fail");
        }
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 1);
        assert_eq!(replayed.records[0].payload, b"payload");
        assert!(replayed.truncated_at.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Crash mid-rotation at the sealed segment's fsync: the sealed
    /// file holds its records (flush already ran); the successor
    /// segment and the triggering record never existed. Reopen must
    /// recover the sealed records and continue on a fresh segment.
    #[test]
    fn test_crash_during_rotate_seal_recovers_sealed_segment() {
        let dir = temp_dir("fault-seal");
        let config = JournalConfig { max_segment_bytes: 8 };
        {
            let mut j = JournalWriter::create(&dir, config).unwrap();
            j.append(&[0u8; 16]).unwrap();
            j.inject_fault(FaultPoint::RotateSealSync);
            // This append triggers rotate (16 > 8) and dies at the
            // seal fsync — the triggering payload is never framed.
            assert!(j.append(b"trigger").is_err(), "rotation must fail");
        }
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 1, "sealed segment's record survives");
        assert_eq!(replayed.records[0].payload, &[0u8; 16]);
        // Recovery: reopen and keep writing — a new segment starts, so
        // the sealed file is never touched again.
        let mut j = JournalWriter::create(&dir, config).unwrap();
        j.append(b"after-crash").unwrap();
        j.sync().unwrap();
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 2);
        assert_eq!(replayed.records[1].payload, b"after-crash");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Crash between seal and the height-index write: the sealed
    /// segment is on disk but `heights.idx` has no entry for it. The
    /// crash-faithful invariant is that height pruning treats the
    /// segment as "unknown contents" and keeps it — deleting it would
    /// lose sealed, synced records.
    #[test]
    fn test_crash_before_height_index_keeps_unindexed_segment() {
        let dir = temp_dir("fault-hidx");
        let config = JournalConfig { max_segment_bytes: 8 };
        {
            let mut j = JournalWriter::create(&dir, config).unwrap();
            j.append_at_height(1, b"h1").unwrap();
            j.inject_fault(FaultPoint::RotateHeightIndex);
            // Triggers rotate; dies after seal, before index write.
            assert!(j.append_at_height(2, b"h2").is_err());
        }
        let index = read_height_index(&dir).unwrap();
        assert!(!index.contains_key(&0), "segment 0 must be missing from the index");
        let mut j = JournalWriter::create(&dir, config).unwrap();
        let deleted = j.prune_below_height(1_000).unwrap();
        assert_eq!(deleted, 0, "unindexed sealed segment must be kept");
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 1, "h1 must still replay");
        assert_eq!(replayed.records[0].payload, b"h1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Crash between indexing the sealed segment and creating its
    /// successor: `heights.idx` points at a complete segment and no
    /// `segment-<n+1>.log` exists. Reopen must start a fresh successor
    /// at the right sequence number and keep the sealed history.
    #[test]
    fn test_crash_before_rotate_create_reopens_on_fresh_segment() {
        let dir = temp_dir("fault-create");
        let config = JournalConfig { max_segment_bytes: 8 };
        {
            let mut j = JournalWriter::create(&dir, config).unwrap();
            j.append_at_height(1, b"h1").unwrap();
            j.inject_fault(FaultPoint::RotateCreate);
            assert!(j.append_at_height(2, b"h2").is_err(), "create must fail");
        }
        // The index recorded segment 0 as sealed through height 1.
        let index = read_height_index(&dir).unwrap();
        assert_eq!(index.get(&0), Some(&1));
        assert!(!dir.join("segment-1.log").exists(), "successor was never created");
        // Reopen writes a fresh segment 1 — same name, clean magic.
        let mut j = JournalWriter::create(&dir, config).unwrap();
        j.append_at_height(3, b"h3").unwrap();
        j.sync().unwrap();
        let replayed = replay(&dir).unwrap();
        let payloads: Vec<&[u8]> = replayed.records.iter().map(|r| r.payload.as_slice()).collect();
        assert_eq!(payloads, vec![b"h1".as_slice(), b"h3".as_slice()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `FaultPoint::Append` models death before the record is framed:
    /// nothing enters the buffer, nothing touches the file.
    #[test]
    fn test_crash_before_append_frames_nothing() {
        let dir = temp_dir("fault-append");
        {
            let mut j = JournalWriter::create(&dir, JournalConfig::default()).unwrap();
            j.append(b"kept").unwrap();
            j.sync().unwrap();
            j.inject_fault(FaultPoint::Append);
            assert!(j.append(b"never-framed").is_err());
            j.flush().unwrap(); // even a clean flush writes nothing new
        }
        let replayed = replay(&dir).unwrap();
        assert_eq!(replayed.records.len(), 1);
        assert_eq!(replayed.records[0].payload, b"kept");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
