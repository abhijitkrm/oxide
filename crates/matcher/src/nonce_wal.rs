//! Off-thread durability for the consumed-nonce replay gate
//! (hft-audit-2 M-1).
//!
//! # What it does
//!
//! [`NonceDurability`] owns a background writer thread that persists
//! consumed `(owner, nonce)` pairs. The admitting thread (the ring
//! sequencer, or whoever holds the multi-market nonce mutex) hands
//! the writer a small batch of deltas over a channel, which costs a
//! channel send. The writer appends the deltas to a write-ahead log
//! and `fdatasync`s it, group-committing whatever queued up during the
//! previous sync. It folds the log into a full checkpoint
//! ([`NonceStore`]) once the log grows as large as the checkpoint
//! itself.
//!
//! # Why it exists
//!
//! The previous design serialized the WHOLE nonce map, wrote it,
//! `fsync`ed it and renamed it every 64 admissions, on the admitting
//! thread. On the target box an `fsync` costs 4–13 ms, so every 64th
//! order stalled the single-writer sequencer for milliseconds. That
//! capped throughput at roughly 16k orders/s and put a 4+ ms spike
//! at p99.9.
//!
//! # Files
//!
//! - `<path>`: the checkpoint, in the unchanged `OXNC` v1 format,
//!   replaced atomically (tmp + fsync + rename + directory fsync).
//! - `<path>.wal`: append-only fixed-size records,
//!   `owner[20] ‖ nonce u64 LE ‖ crc32(owner ‖ nonce) u32 LE`
//!   (32 bytes each).
//!
//! # Invariants and crash story
//!
//! - **Lower bound only.** Both files record nonces that really were
//!   consumed, and recovery max-merges them. Applying any genuine
//!   record can only raise a watermark to a value that was consumed,
//!   so replaying a record twice or in any order is harmless.
//! - **Torn or corrupt records are skipped, never trusted.** Each
//!   record carries a CRC-32 and records are fixed-size, so a torn
//!   tail or a zero-filled page fails its check and is dropped. That
//!   is the same as losing those admissions in the crash, which is
//!   the window the design accepts. A record that passes its CRC is
//!   applied wherever it sits in the file.
//! - **Recovery starts clean.** `start` writes a fresh checkpoint of
//!   the recovered state and truncates the log before serving, so a
//!   partial record from a crashed run can never misalign records
//!   appended by the next one.
//! - **Compaction order.** The checkpoint is made durable
//!   (rename + directory fsync) BEFORE the log is truncated. A crash
//!   in between leaves log records that the checkpoint already
//!   covers; the max-merge makes them no-ops.
//! - **Crash window.** On a hard crash, the nonces lost are those
//!   still buffered on the admitting thread (fewer than
//!   [`crate::settlement::NONCE_FLUSH_EVERY`]) plus those handed to
//!   the writer but not yet `fdatasync`ed: about one sync interval
//!   (4–13 ms here) of admissions. The old design lost up to 63
//!   admissions and could not admit faster than one checkpoint per
//!   64 orders, so the window is about the same in time, while
//!   throughput is no longer bounded by the disk. A clean drop
//!   (process shutdown) hands off the buffered deltas and joins the
//!   writer, which checkpoints before it exits.
//! - **Admission does not wait for durability,** as before: an order
//!   is acknowledged once its nonce is consumed in memory.

use crate::settlement::{NonceCheckpointError, NonceStore};
use std::collections::HashMap;
use std::io::Write;
use std::sync::mpsc;

/// One log record: owner(20) + nonce(8) + crc32(4).
const RECORD: usize = 32;

/// Smallest log size, in records, that triggers compaction into a
/// checkpoint. The real threshold is `max(this, accounts tracked)`,
/// which keeps the amortized write cost O(1) per delta: a checkpoint
/// of N accounts is written at most once per N appended records. At
/// 65,536 records the log tops out around 2 MiB for small account
/// sets. Raising it means fewer checkpoints and a longer replay at
/// startup; lowering it means more full rewrites.
const COMPACT_MIN_RECORDS: usize = 1 << 16;

/// The log file that sits next to checkpoint `path`: `<path>.wal`.
/// The suffix is appended rather than swapped in, so a checkpoint
/// path that already ends in `.wal` can never collide with its log.
pub(crate) fn wal_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(".wal");
    std::path::PathBuf::from(os)
}

/// CRC-32 (IEEE 802.3, reflected, poly `0xEDB88320`), bitwise.
/// It only runs on the writer thread and at startup, over 28-byte
/// records, so a table-free loop is fast enough and keeps the crate
/// free of a new dependency.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Append one encoded record for `(owner, nonce)` to `out`.
fn encode_record(owner: &primitives::Address, nonce: u64, out: &mut Vec<u8>) {
    let start = out.len();
    out.extend_from_slice(&owner.0);
    out.extend_from_slice(&nonce.to_le_bytes());
    let crc = crc32(&out[start..start + 28]);
    out.extend_from_slice(&crc.to_le_bytes());
}

/// Max-merge `(owner, nonce)` into `map`: a watermark only ever rises.
fn merge(map: &mut HashMap<primitives::Address, u64>, owner: primitives::Address, nonce: u64) {
    map.entry(owner).and_modify(|e| *e = (*e).max(nonce)).or_insert(nonce);
}

/// Decode a log image into `map` (max-merge). Returns how many
/// 32-byte slots failed their CRC plus whether a partial trailing
/// record was present. Both cases are skipped, not trusted (module
/// docs).
fn replay_wal(bytes: &[u8], map: &mut HashMap<primitives::Address, u64>) -> (usize, bool) {
    let mut bad = 0usize;
    let (records, tail) = bytes.as_chunks::<RECORD>();
    for rec in records {
        let mut crc_bytes = [0u8; 4];
        crc_bytes.copy_from_slice(&rec[28..32]);
        if crc32(&rec[..28]) != u32::from_le_bytes(crc_bytes) {
            bad += 1;
            continue;
        }
        let mut owner = [0u8; 20];
        owner.copy_from_slice(&rec[..20]);
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&rec[20..28]);
        merge(map, primitives::Address(owner), u64::from_le_bytes(nonce));
    }
    (bad, !tail.is_empty())
}

/// Rebuild the consumed-nonce state from the checkpoint at `path`
/// plus its log. Cold path (startup).
///
/// # Errors
///
/// A missing checkpoint or log is an empty state (first run). A
/// checkpoint that does not decode, or a log that cannot be read, is
/// an error: the caller fails closed rather than reopening the
/// replay window. Bad log RECORDS are skipped with a warning (module
/// docs).
pub(crate) fn recover(
    path: &std::path::Path,
) -> Result<HashMap<primitives::Address, u64>, NonceCheckpointError> {
    let mut map = HashMap::new();
    for (owner, nonce) in NonceStore::load(path)? {
        merge(&mut map, owner, nonce);
    }
    let wal = wal_path(path);
    let bytes = match std::fs::read(&wal) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(NonceCheckpointError::Io(e)),
    };
    let (bad, torn_tail) = replay_wal(&bytes, &mut map);
    if bad > 0 || torn_tail {
        eprintln!(
            "nonce log {}: skipped {bad} corrupt record(s){} — treated as crash loss",
            wal.display(),
            if torn_tail { " and a torn tail" } else { "" }
        );
    }
    Ok(map)
}

/// A batch of consumed `(owner, nonce)` deltas.
pub(crate) type DeltaBatch = Vec<(primitives::Address, u64)>;

/// Messages from the admitting thread to the writer.
enum Msg {
    /// Deltas to persist.
    Deltas(DeltaBatch),
    /// Reply once everything sent before this message is durable.
    #[cfg(test)]
    Sync(mpsc::Sender<()>),
}

/// Handle to the durability writer. Dropping it hands off nothing by
/// itself (the owning tracker flushes its buffer first). It closes
/// the channel and joins the writer, which drains the queue, writes
/// a final checkpoint and exits.
pub(crate) struct NonceDurability {
    /// Delta channel to the writer; `None` only during `Drop`.
    tx: Option<mpsc::Sender<Msg>>,
    /// Emptied delta buffers coming back from the writer, so the
    /// admitting thread reuses capacity instead of allocating a fresh
    /// `Vec` for every hand-off.
    recycle: mpsc::Receiver<DeltaBatch>,
    /// The writer thread; joined on drop.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl NonceDurability {
    /// Persist `state` (the recovered map) as a fresh checkpoint,
    /// truncate the log, and spawn the writer seeded with `state`.
    /// Cold path (startup).
    ///
    /// # Errors
    ///
    /// Any I/O failure writing the initial checkpoint, opening the
    /// log or spawning the thread. The caller fails closed: an
    /// operator who asked for a durable replay gate must not get a
    /// silently memory-only one.
    pub(crate) fn start(
        path: std::path::PathBuf,
        state: HashMap<primitives::Address, u64>,
    ) -> std::io::Result<Self> {
        let checkpoint = NonceStore { path: path.clone() };
        checkpoint.save(&state)?;
        let wal_file = wal_path(&path);
        let wal = std::fs::OpenOptions::new().create(true).append(true).open(&wal_file)?;
        // The fresh checkpoint already covers every log record.
        wal.set_len(0)?;
        wal.sync_all()?;
        let (tx, rx) = mpsc::channel::<Msg>();
        let (recycle_tx, recycle) = mpsc::channel::<DeltaBatch>();
        let mut writer = Writer {
            checkpoint,
            wal,
            wal_file,
            mirror: state,
            wal_records: 0,
            buf: Vec::new(),
            recycle: recycle_tx,
        };
        // Critical: a dead writer silently turns the durable replay
        // gate into a memory-only one, so a restart would reopen
        // every replay since the death. Aborting under the
        // supervisor and recovering from disk is the coherent
        // outcome.
        let thread =
            primitives::supervision::spawn_supervised("nonce-durability", true, move || {
                writer.run(&rx);
            })?;
        Ok(Self { tx: Some(tx), recycle, thread: Some(thread) })
    }

    /// An empty delta buffer with capacity for `cap` entries: a
    /// recycled one when the writer has returned one, else a new
    /// allocation.
    pub(crate) fn take_buffer(&self, cap: usize) -> DeltaBatch {
        self.recycle.try_recv().unwrap_or_else(|_| Vec::with_capacity(cap))
    }

    /// Hand `batch` to the writer. Never blocks. If the writer is gone
    /// (it can only exit by panicking, which aborts under the
    /// supervision hook) the batch is dropped and the error logged.
    pub(crate) fn submit(&self, batch: DeltaBatch) {
        if let Some(tx) = &self.tx
            && tx.send(Msg::Deltas(batch)).is_err()
        {
            eprintln!("nonce-durability writer is gone; consumed nonces are memory-only");
        }
    }

    /// Block until everything submitted before this call is durable
    /// (in the log, after `fdatasync`). Test-only (see
    /// `NonceTracker::sync_durable`). Returns immediately if the
    /// writer is gone.
    #[cfg(test)]
    pub(crate) fn sync(&self) {
        let Some(tx) = &self.tx else { return };
        let (reply_tx, reply_rx) = mpsc::channel();
        if tx.send(Msg::Sync(reply_tx)).is_ok() {
            let _ = reply_rx.recv();
        }
    }
}

impl Drop for NonceDurability {
    fn drop(&mut self) {
        // Closing the channel lets the writer drain what is queued,
        // write its final checkpoint, and return.
        drop(self.tx.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Writer-thread state.
struct Writer {
    /// The checkpoint file (atomic replace).
    checkpoint: NonceStore,
    /// The append-only log.
    wal: std::fs::File,
    /// The log's path (diagnostics).
    wal_file: std::path::PathBuf,
    /// Full consumed-nonce state, kept by max-merge. It is the source
    /// of every checkpoint, so the admitting thread never has to
    /// serialize its own map.
    mirror: HashMap<primitives::Address, u64>,
    /// Records appended since the last checkpoint.
    wal_records: usize,
    /// Reused encode buffer.
    buf: Vec<u8>,
    /// Returns emptied delta buffers to the admitting thread.
    recycle: mpsc::Sender<DeltaBatch>,
}

impl Writer {
    /// Group-commit loop: block for one message, drain the rest that
    /// are queued, persist them in one append + `fdatasync`, then
    /// answer any `Sync` waiters. Exits when every sender is gone,
    /// after a final checkpoint.
    fn run(&mut self, rx: &mpsc::Receiver<Msg>) {
        let mut batches: Vec<DeltaBatch> = Vec::new();
        let mut waiters: Vec<mpsc::Sender<()>> = Vec::new();
        while let Ok(first) = rx.recv() {
            let mut next = Some(first);
            while let Some(msg) = next {
                match msg {
                    Msg::Deltas(b) => batches.push(b),
                    #[cfg(test)]
                    Msg::Sync(w) => waiters.push(w),
                }
                next = rx.try_recv().ok();
            }
            if !batches.is_empty() {
                self.commit(&batches);
                for mut b in batches.drain(..) {
                    b.clear();
                    // The admitting side may have dropped; then the
                    // buffer just frees here.
                    let _ = self.recycle.send(b);
                }
            }
            for w in waiters.drain(..) {
                let _ = w.send(());
            }
        }
        self.compact();
    }

    /// Append `batches` to the log and make them durable; fold the
    /// log into a checkpoint once it is as large as the state.
    fn commit(&mut self, batches: &[DeltaBatch]) {
        self.buf.clear();
        let mut n = 0usize;
        for batch in batches {
            for &(owner, nonce) in batch {
                encode_record(&owner, nonce, &mut self.buf);
                merge(&mut self.mirror, owner, nonce);
                n += 1;
            }
        }
        let appended = self.wal.write_all(&self.buf).and_then(|()| self.wal.sync_data());
        match appended {
            Ok(()) => {
                self.wal_records += n;
                if self.wal_records >= COMPACT_MIN_RECORDS.max(self.mirror.len()) {
                    self.compact();
                }
            }
            Err(e) => {
                // The mirror already holds these deltas, so a full
                // checkpoint covers them as well as the log would have.
                eprintln!(
                    "nonce log {}: append failed ({e}); checkpointing",
                    self.wal_file.display()
                );
                self.compact();
            }
        }
    }

    /// Write the mirror as a checkpoint, then truncate the log, in
    /// that order (module docs, "Compaction order"). On failure the
    /// log is kept and the replay window is unchanged.
    fn compact(&mut self) {
        if let Err(e) = self.checkpoint.save(&self.mirror) {
            eprintln!(
                "nonce checkpoint {}: write failed ({e}); log retained",
                self.checkpoint.path.display()
            );
            return;
        }
        match self.wal.set_len(0).and_then(|()| self.wal.sync_data()) {
            Ok(()) => self.wal_records = 0,
            Err(e) => eprintln!("nonce log {}: truncate failed ({e})", self.wal_file.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> primitives::Address {
        primitives::Address([b; 20])
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("oxnc-wal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        // The standard CRC-32 check value for ASCII "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn wal_path_appends_a_suffix() {
        assert_eq!(
            wal_path(std::path::Path::new("/x/nonces.oxnc")),
            std::path::PathBuf::from("/x/nonces.oxnc.wal")
        );
        // A checkpoint already named `.wal` never collides with its log.
        assert_ne!(wal_path(std::path::Path::new("a.wal")), std::path::PathBuf::from("a.wal"));
    }

    /// Crash simulation: a log with valid records, a zero-filled
    /// (never-written) slot, a bit-flipped record and a torn tail.
    /// Every valid record must apply, max-merged; every damaged one
    /// must be skipped rather than trusted.
    #[test]
    fn replay_skips_torn_and_corrupt_records_and_max_merges() {
        let mut log = Vec::new();
        encode_record(&addr(1), 5, &mut log);
        encode_record(&addr(2), 9, &mut log);
        log.extend_from_slice(&[0u8; RECORD]); // unwritten page slot
        let flip_at = log.len() + 21;
        encode_record(&addr(3), 77, &mut log);
        log[flip_at] ^= 0x40; // corrupt addr(3)'s nonce
        encode_record(&addr(1), 3, &mut log); // lower: must not regress
        encode_record(&addr(4), 11, &mut log);
        let mut torn = Vec::new();
        encode_record(&addr(5), 1, &mut torn);
        log.extend_from_slice(&torn[..17]); // crash mid-record
        let mut map = HashMap::new();
        let (bad, torn_tail) = replay_wal(&log, &mut map);
        assert_eq!((bad, torn_tail), (2, true));
        assert_eq!(map.get(&addr(1)), Some(&5), "max-merge: a lower record never regresses");
        assert_eq!(map.get(&addr(2)), Some(&9));
        assert_eq!(map.get(&addr(3)), None, "a corrupt record is never trusted");
        assert_eq!(map.get(&addr(4)), Some(&11), "valid records after damage still apply");
        assert_eq!(map.get(&addr(5)), None);
    }

    /// The durability contract: once `sync` returns, a crash (no
    /// clean drop, no final checkpoint) loses nothing that was
    /// submitted. Recovery is read straight off disk while the writer
    /// is still alive, which is what a kill -9 leaves behind.
    #[test]
    fn synced_deltas_survive_a_crash() {
        let dir = temp_dir("crash");
        let path = dir.join("nonces.oxnc");
        let mut seed = HashMap::new();
        seed.insert(addr(9), 100);
        let d = NonceDurability::start(path.clone(), seed).expect("start");
        let mut b = d.take_buffer(4);
        b.extend([(addr(1), 1), (addr(2), 2)]);
        d.submit(b);
        let mut b = d.take_buffer(4);
        b.extend([(addr(1), 7)]);
        d.submit(b);
        d.sync();
        let on_disk = recover(&path).expect("recover");
        assert_eq!(on_disk.get(&addr(1)), Some(&7));
        assert_eq!(on_disk.get(&addr(2)), Some(&2));
        assert_eq!(on_disk.get(&addr(9)), Some(&100), "seed state is checkpointed at start");
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A clean drop compacts: the final state lives in the checkpoint
    /// and the log is empty, so the next start replays nothing.
    #[test]
    fn clean_shutdown_compacts_into_the_checkpoint() {
        let dir = temp_dir("clean");
        let path = dir.join("nonces.oxnc");
        let d = NonceDurability::start(path.clone(), HashMap::new()).expect("start");
        let mut b = d.take_buffer(2);
        b.push((addr(3), 33));
        d.submit(b);
        drop(d);
        assert_eq!(std::fs::metadata(wal_path(&path)).expect("log exists").len(), 0);
        let cp: HashMap<_, _> = NonceStore::load(&path).expect("checkpoint").into_iter().collect();
        assert_eq!(cp.get(&addr(3)), Some(&33));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Restart after a crash: recovery merges checkpoint and log,
    /// and `start` rewrites a clean checkpoint and truncates the log
    /// so a torn tail never misaligns the next run's appends.
    #[test]
    fn restart_after_crash_starts_from_a_clean_log() {
        let dir = temp_dir("restart");
        let path = dir.join("nonces.oxnc");
        let mut cp = HashMap::new();
        cp.insert(addr(1), 10);
        NonceStore { path: path.clone() }.save(&cp).expect("seed checkpoint");
        let mut log = Vec::new();
        encode_record(&addr(1), 12, &mut log);
        encode_record(&addr(2), 4, &mut log);
        log.extend_from_slice(&[0xAB; 9]); // torn tail
        std::fs::write(wal_path(&path), &log).expect("seed log");
        let state = recover(&path).expect("recover");
        assert_eq!(state.get(&addr(1)), Some(&12));
        assert_eq!(state.get(&addr(2)), Some(&4));
        let d = NonceDurability::start(path.clone(), state).expect("start");
        assert_eq!(std::fs::metadata(wal_path(&path)).expect("log").len(), 0);
        drop(d);
        let again = recover(&path).expect("recover again");
        assert_eq!(again.get(&addr(1)), Some(&12));
        assert_eq!(again.get(&addr(2)), Some(&4));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
