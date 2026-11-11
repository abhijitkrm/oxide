//! Command journal: journal-before-apply with off-thread group commit.
//!
//! ## What this is
//!
//! An append-only log of the commands a matcher admits, so a crashed
//! matcher can rebuild its books by replaying the log through the
//! (deterministic) engine. The shape follows orderer-rust's design
//! (`docs/DESIGN.md` §4): the engine thread only *encodes* a record
//! into an in-memory chunk — no syscall, no lock on the hot path — and
//! a dedicated I/O thread writes full chunks and makes them durable
//! with one `fsync` per batch (group commit). The caller learns what
//! is durable from [`Journal::durable`] and may hold acknowledgements
//! until [`Journal::wait_durable`] says their sequence number is safe.
//!
//! ## Why not write on the engine thread
//!
//! A single `write()` can stall for tens of milliseconds under
//! page-cache pressure or a concurrent `fsync` (the nonce WAL in this
//! crate measured 4–13 ms per `fsync`). orderer-rust measured durable
//! throughput of 2–5M commands/s with synchronous writes versus 15–24M
//! with this split. A slow disk here costs chunks queued (bounded by
//! [`MAX_CHUNKS_IN_FLIGHT`] — backpressure), never a stalled engine
//! loop.
//!
//! ## Record framing
//!
//! `[len: u32 LE][crc32c(payload): u32 LE][payload: len bytes]`, so a
//! reader can tell a torn tail (short header, short payload, or a
//! checksum that fails on the *last* record) from corruption in the
//! middle of a file. [`ReadMode::Repair`] truncates only a torn final
//! record of the last segment; damage anywhere else is an error, never
//! silently skipped — replaying past a hole would diverge the book.
//!
//! ## Files
//!
//! Segments are `cmd-{NNNNNNNN}.journal` in one directory, rotated at
//! [`SEGMENT_BYTES`]. Sequence numbers count records from 1 across
//! segments in order.
//!
//! This module is self-contained and not yet wired into the market
//! workers (see `docs/devlog.md`): wiring decides *which* commands are
//! journaled and when acks release, which is a service-level design
//! choice made on top of this primitive.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;

/// Bytes of one record header (`len` + `crc`).
pub const HEADER_BYTES: usize = 8;

/// Largest payload a record may carry. Unit: bytes. Origin: a command
/// is at most a few hundred bytes; 1 MiB is generous headroom that
/// still lets the reader reject a garbage `len` (a torn header can
/// decode to any u32) without allocating gigabytes. Raising it widens
/// what a corrupt header can make the reader try to read.
pub const MAX_PAYLOAD_BYTES: usize = 1 << 20;

/// Encode buffer size handed to the I/O thread. Unit: bytes. Origin:
/// orderer-rust's 256 KiB chunk — large enough that one `write` +
/// `fsync` amortizes over thousands of commands, small enough that the
/// durability lag after a quiet moment is one `flush()` away. A larger
/// chunk raises throughput and the loss window of un-flushed records;
/// a smaller one the reverse.
pub const CHUNK_BYTES: usize = 256 * 1024;

/// Chunks that may be queued for the I/O thread before `append` blocks.
/// Unit: chunks (64 × 256 KiB = 16 MiB). Origin: orderer-rust. This is
/// the backpressure bound: a disk that cannot keep up stalls the
/// producer here rather than growing memory without limit.
pub const MAX_CHUNKS_IN_FLIGHT: usize = 64;

/// Rotation threshold per segment file. Unit: bytes (64 MiB).
/// Smaller segments make checkpoint truncation finer-grained and
/// recovery's last-segment repair cheaper; larger ones mean fewer
/// files.
pub const SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// CRC-32C (Castagnoli) lookup table, built at compile time.
const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            // 0x82F6_3B78 is the reflected Castagnoli polynomial.
            c = if c & 1 == 1 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 };
            k += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
};

/// CRC-32C of `data`.
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c = CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// How [`read_dir`] treats a damaged tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMode {
    /// Any damage is an error.
    Strict,
    /// A torn final record of the last segment is truncated away (the
    /// file is rewritten shorter); any other damage is still an error.
    Repair,
}

/// Journal read failure.
#[derive(Debug)]
pub enum JournalError {
    /// Underlying I/O error.
    Io(io::Error),
    /// A record failed its checks somewhere other than a repairable
    /// torn tail.
    Corrupt {
        /// Segment file the damage is in.
        file: PathBuf,
        /// Byte offset of the bad record's header.
        offset: u64,
    },
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Io(e) => write!(f, "journal i/o: {e}"),
            JournalError::Corrupt { file, offset } => {
                write!(f, "journal corrupt: {} at byte {offset}", file.display())
            }
        }
    }
}

impl std::error::Error for JournalError {}

impl From<io::Error> for JournalError {
    fn from(e: io::Error) -> Self {
        JournalError::Io(e)
    }
}

fn segment_path(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("cmd-{n:08}.journal"))
}

/// Segment numbers present in `dir`, ascending.
fn segments(dir: &Path) -> io::Result<Vec<u64>> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir)? {
        let name = e?.file_name();
        let name = name.to_string_lossy();
        if let Some(n) = name
            .strip_prefix("cmd-")
            .and_then(|r| r.strip_suffix(".journal"))
            .and_then(|r| r.parse::<u64>().ok())
        {
            v.push(n);
        }
    }
    v.sort_unstable();
    Ok(v)
}

/// Why a scan stopped before the end of a segment.
struct Bad {
    /// Byte offset of the bad record's header.
    at: usize,
    /// `true` iff the damage is consistent with a torn final append:
    /// the record is cut short, or it is complete with a bad checksum
    /// and ends exactly at end-of-file. Anything with bytes after it
    /// (or an impossible length) is mid-file corruption.
    torn_tail: bool,
}

/// Scan one segment's bytes. Returns the payload ranges of the valid
/// prefix and, if the scan stopped early, where and why.
fn scan(bytes: &[u8]) -> (Vec<(usize, usize)>, Option<Bad>) {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let Some(hdr) = bytes.get(at..at + HEADER_BYTES) else {
            return (out, Some(Bad { at, torn_tail: true })); // header cut short
        };
        let len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let crc = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        if len > MAX_PAYLOAD_BYTES {
            // A torn append is a prefix of well-formed bytes, so a whole
            // header carrying an impossible length is damage, not tearing.
            return (out, Some(Bad { at, torn_tail: false }));
        }
        let start = at + HEADER_BYTES;
        let Some(payload) = bytes.get(start..start + len) else {
            return (out, Some(Bad { at, torn_tail: true })); // payload cut short
        };
        if crc32c(payload) != crc {
            return (out, Some(Bad { at, torn_tail: start + len == bytes.len() }));
        }
        out.push((start, start + len));
        at = start + len;
    }
    (out, None)
}

/// Read every record in `dir`, in order.
///
/// # Errors
/// [`JournalError::Corrupt`] for damage that is not a repairable torn
/// tail (always in `Strict` mode); [`JournalError::Io`] otherwise.
pub fn read_dir(dir: &Path, mode: ReadMode) -> Result<Vec<Vec<u8>>, JournalError> {
    let segs = segments(dir)?;
    let mut out = Vec::new();
    for (i, n) in segs.iter().enumerate() {
        let path = segment_path(dir, *n);
        let mut bytes = Vec::new();
        File::open(&path)?.read_to_end(&mut bytes)?;
        let (ranges, bad) = scan(&bytes);
        out.extend(ranges.iter().map(|&(a, b)| bytes[a..b].to_vec()));
        if let Some(bad) = bad {
            let last = i + 1 == segs.len();
            if mode == ReadMode::Repair && last && bad.torn_tail {
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(bad.at as u64)?;
                f.sync_all()?;
            } else {
                return Err(JournalError::Corrupt { file: path, offset: bad.at as u64 });
            }
        }
    }
    Ok(out)
}

/// What the engine side hands the I/O thread.
enum Msg {
    /// An encoded chunk (whole records) to append.
    Chunk(Vec<u8>, u64),
    /// Stop after draining.
    Shutdown,
}

/// State shared between the engine side and the I/O thread.
struct Shared {
    /// Records handed to the OS and covered by a completed `fsync`.
    durable: AtomicU64,
    /// Set if the I/O thread hit an error; appends then fail.
    failed: AtomicBool,
    /// Wakes [`Journal::wait_durable`] callers.
    gate: Mutex<()>,
    cv: Condvar,
}

/// Single-writer command journal. `append` and `flush` take `&mut self`:
/// one engine thread owns the writer, which is what keeps the hot path
/// lock-free.
pub struct Journal {
    chunk: Vec<u8>,
    /// Records encoded so far (the next record's sequence is `seq + 1`).
    seq: u64,
    /// Sequence covered by the chunk currently being filled.
    tx: SyncSender<Msg>,
    shared: Arc<Shared>,
    io: Option<JoinHandle<()>>,
}

impl Journal {
    /// Open (creating `dir` if needed) and continue after the records
    /// already on disk. Existing damage must be repaired first
    /// ([`read_dir`] with [`ReadMode::Repair`]); a damaged journal is an
    /// error here too, so appends never follow a hole.
    ///
    /// # Errors
    /// I/O failure or a corrupt existing journal.
    pub fn open(dir: &Path) -> Result<Journal, JournalError> {
        fs::create_dir_all(dir)?;
        let existing = read_dir(dir, ReadMode::Strict)?.len() as u64;
        let segs = segments(dir)?;
        let next = segs.last().map_or(0, |n| n + 1);
        let shared = Arc::new(Shared {
            durable: AtomicU64::new(existing),
            failed: AtomicBool::new(false),
            gate: Mutex::new(()),
            cv: Condvar::new(),
        });
        let (tx, rx) = sync_channel::<Msg>(MAX_CHUNKS_IN_FLIGHT);
        let io = {
            let shared = Arc::clone(&shared);
            let dir = dir.to_path_buf();
            std::thread::Builder::new()
                .name("journal-io".into())
                .spawn(move || io_loop(&dir, next, &rx, &shared))
                .map_err(JournalError::Io)?
        };
        Ok(Journal {
            chunk: Vec::with_capacity(CHUNK_BYTES + HEADER_BYTES),
            seq: existing,
            tx,
            shared,
            io: Some(io),
        })
    }

    /// Encode one record and return its sequence number. No syscall; at
    /// a chunk boundary the chunk is queued for the I/O thread (this
    /// blocks only under backpressure).
    ///
    /// # Errors
    /// `InvalidInput` for a payload over [`MAX_PAYLOAD_BYTES`];
    /// `BrokenPipe` if the I/O thread has failed or stopped.
    pub fn append(&mut self, payload: &[u8]) -> io::Result<u64> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "payload too large"));
        }
        if self.shared.failed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "journal i/o failed"));
        }
        // `len <= MAX_PAYLOAD_BYTES (2^20)` always fits u32.
        let len = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload too large"))?;
        self.chunk.extend_from_slice(&len.to_le_bytes());
        self.chunk.extend_from_slice(&crc32c(payload).to_le_bytes());
        self.chunk.extend_from_slice(payload);
        self.seq += 1;
        if self.chunk.len() >= CHUNK_BYTES {
            self.flush()?;
        }
        Ok(self.seq)
    }

    /// Queue the partially filled chunk for the I/O thread now (call at
    /// batch end or after an idle period so low traffic still becomes
    /// durable).
    ///
    /// # Errors
    /// `BrokenPipe` if the I/O thread has stopped.
    pub fn flush(&mut self) -> io::Result<()> {
        if self.chunk.is_empty() {
            return Ok(());
        }
        let chunk =
            std::mem::replace(&mut self.chunk, Vec::with_capacity(CHUNK_BYTES + HEADER_BYTES));
        self.tx
            .send(Msg::Chunk(chunk, self.seq))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "journal i/o stopped"))
    }

    /// Records covered by a completed `fsync`.
    #[must_use]
    pub fn durable(&self) -> u64 {
        self.shared.durable.load(Ordering::Acquire)
    }

    /// Block until record `seq` is durable. Returns `false` if the I/O
    /// thread failed first (the record may never become durable).
    #[must_use]
    pub fn wait_durable(&self, seq: u64) -> bool {
        let mut g = self.shared.gate.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if self.shared.durable.load(Ordering::Acquire) >= seq {
                return true;
            }
            if self.shared.failed.load(Ordering::Acquire) {
                return false;
            }
            g = self.shared.cv.wait(g).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Flush, wait for the final group commit and stop the I/O thread.
    ///
    /// # Errors
    /// `BrokenPipe` if the I/O thread had already failed.
    pub fn close(mut self) -> io::Result<()> {
        self.flush()?;
        let _ = self.tx.send(Msg::Shutdown);
        if let Some(h) = self.io.take() {
            let _ = h.join();
        }
        if self.shared.failed.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "journal i/o failed"));
        }
        Ok(())
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        // Best effort for a journal dropped without `close`.
        if self.io.is_some() {
            let _ = self.flush();
            let _ = self.tx.send(Msg::Shutdown);
            if let Some(h) = self.io.take() {
                let _ = h.join();
            }
        }
    }
}

/// The I/O thread: write each queued chunk, then group-commit — drain
/// everything already queued before the single `fsync`.
fn io_loop(dir: &Path, first_segment: u64, rx: &Receiver<Msg>, shared: &Shared) {
    let mut seg = first_segment;
    let mut file: Option<(File, u64)> = None;
    let mut written_seq = shared.durable.load(Ordering::Acquire);
    let fail = |shared: &Shared| {
        shared.failed.store(true, Ordering::Release);
        let _g = shared.gate.lock().unwrap_or_else(PoisonError::into_inner);
        shared.cv.notify_all();
    };
    let mut stop = false;
    while !stop {
        let Ok(first) = rx.recv() else { break };
        let mut batch = vec![first];
        while let Ok(m) = rx.try_recv() {
            batch.push(m);
        }
        for m in batch {
            match m {
                Msg::Shutdown => stop = true,
                Msg::Chunk(bytes, upto) => {
                    if file.as_ref().is_none_or(|(_, len)| *len >= SEGMENT_BYTES) {
                        if let Some((f, _)) = file.take()
                            && f.sync_data().is_err()
                        {
                            return fail(shared);
                        }
                        match OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(segment_path(dir, seg))
                        {
                            Ok(f) => file = Some((f, 0)),
                            Err(_) => return fail(shared),
                        }
                        seg += 1;
                    }
                    let Some((f, len)) = file.as_mut() else { return fail(shared) };
                    if f.write_all(&bytes).is_err() {
                        return fail(shared);
                    }
                    *len += bytes.len() as u64;
                    written_seq = upto;
                }
            }
        }
        // One fsync covers every chunk written above (group commit).
        if let Some((f, _)) = file.as_ref()
            && f.sync_data().is_err()
        {
            return fail(shared);
        }
        shared.durable.store(written_seq, Ordering::Release);
        let _g = shared.gate.lock().unwrap_or_else(PoisonError::into_inner);
        shared.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oxide-journal-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn crc32c_known_vectors() {
        // RFC 3720 / iSCSI check values.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn round_trip_and_durable_watermark() {
        let dir = tmp("rt");
        let mut j = Journal::open(&dir).unwrap();
        let mut last = 0;
        for i in 0..1000u32 {
            last = j.append(&i.to_le_bytes()).unwrap();
        }
        assert_eq!(last, 1000);
        j.flush().unwrap();
        assert!(j.wait_durable(1000));
        assert_eq!(j.durable(), 1000);
        j.close().unwrap();
        let got = read_dir(&dir, ReadMode::Strict).unwrap();
        assert_eq!(got.len(), 1000);
        assert!(got.iter().enumerate().all(|(i, p)| p == &u32::try_from(i).unwrap().to_le_bytes()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn spans_many_chunks_and_reopens_where_it_left_off() {
        let dir = tmp("chunks");
        let payload = vec![7u8; 4000]; // ~65 records per 256 KiB chunk
        let mut j = Journal::open(&dir).unwrap();
        for _ in 0..500 {
            j.append(&payload).unwrap();
        }
        j.close().unwrap();
        let mut j = Journal::open(&dir).unwrap();
        assert_eq!(j.append(b"after").unwrap(), 501, "sequence continues across reopen");
        j.close().unwrap();
        let got = read_dir(&dir, ReadMode::Strict).unwrap();
        assert_eq!(got.len(), 501);
        assert_eq!(got[500], b"after");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn torn_tail_is_repaired_but_the_prefix_survives() {
        let dir = tmp("torn");
        let mut j = Journal::open(&dir).unwrap();
        for i in 0..10u8 {
            j.append(&[i; 20]).unwrap();
        }
        j.close().unwrap();
        let path = segment_path(&dir, 0);
        let full = fs::read(&path).unwrap();
        // Tear the last record at every possible byte.
        let rec = HEADER_BYTES + 20;
        for cut in 1..rec {
            fs::write(&path, &full[..full.len() - cut]).unwrap();
            assert!(read_dir(&dir, ReadMode::Strict).is_err(), "cut {cut}");
            let got = read_dir(&dir, ReadMode::Repair).unwrap();
            assert_eq!(got.len(), 9, "cut {cut}: last record dropped, prefix kept");
            assert_eq!(fs::read(&path).unwrap().len(), 9 * rec, "file truncated to the prefix");
            assert_eq!(read_dir(&dir, ReadMode::Strict).unwrap().len(), 9);
            fs::write(&path, &full).unwrap();
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn checksum_failure_in_the_last_record_is_a_torn_tail() {
        let dir = tmp("crc-tail");
        let mut j = Journal::open(&dir).unwrap();
        for i in 0..4u8 {
            j.append(&[i; 16]).unwrap();
        }
        j.close().unwrap();
        let path = segment_path(&dir, 0);
        let mut bytes = fs::read(&path).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_dir(&dir, ReadMode::Repair).unwrap().len(), 3);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn damage_in_the_middle_is_never_skipped() {
        let dir = tmp("mid");
        let mut j = Journal::open(&dir).unwrap();
        for i in 0..6u8 {
            j.append(&[i; 16]).unwrap();
        }
        j.close().unwrap();
        let path = segment_path(&dir, 0);
        let mut bytes = fs::read(&path).unwrap();
        bytes[HEADER_BYTES + 3] ^= 0xFF; // inside record 0's payload
        fs::write(&path, &bytes).unwrap();
        // Record 0 is complete with a bad checksum and records follow it:
        // that is a hole, not a torn tail, so even Repair refuses (it
        // would otherwise silently drop five good records).
        assert!(matches!(read_dir(&dir, ReadMode::Strict), Err(JournalError::Corrupt { .. })));
        assert!(matches!(read_dir(&dir, ReadMode::Repair), Err(JournalError::Corrupt { .. })));
        assert!(Journal::open(&dir).is_err(), "never append after a hole");
        assert_eq!(fs::read(&path).unwrap(), bytes, "Repair must not touch mid-file damage");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_oversized_payload() {
        let dir = tmp("big");
        let mut j = Journal::open(&dir).unwrap();
        let err = j.append(&vec![0u8; MAX_PAYLOAD_BYTES + 1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        j.close().unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
