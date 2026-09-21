//! Consensus write-ahead log (C9 fix) — restart safety for oxideBFT.
//!
//! ## The problem
//!
//! A validator that crashes and restarts must not violate consensus
//! safety. The two invariants that crash recovery must preserve:
//!
//! 1. **No double-voting.** A restarted validator must not vote in a
//!    view it already voted in (or any earlier view). The
//!    `last_voted_view` field enforces this in-memory; without
//!    persistence, a restart forgets it and can double-vote — a
//!    safety violation that can fork the chain.
//! 2. **No conflicting votes.** A restarted validator must not vote
//!    for a *different* block at a height it already voted. The
//!    `voted_at_height` map enforces this in-memory; without
//!    persistence, a restart forgets it and can notarize a conflicting
//!    block — another safety violation.
//!
//! ## The fix
//!
//! Before sending any vote, the engine appends a `WalEntry` containing
//! `last_voted_view`, `voted_at_height`, `high_qc`, `current_view`,
//! `next_height`, and `epoch` to a durable file. The `Wal::append`
//! call fsyncs before returning, so the entry is on disk before the
//! vote message hits the network. On restart, the engine reads the
//! WAL and restores the highest entry, recovering the safety-critical
//! state.
//!
//! ## Format
//!
//! Each entry is:
//! ```text
//! [u32 LE length] [u32 LE CRC32 of payload] [payload bytes]
//! ```
//!
//! On recovery, the WAL is read sequentially. A truncated or
//! CRC-mismatched tail entry is discarded (the validator crashed
//! mid-write). The last valid entry is the recovered state.
//!
//! ## Rotation
//!
//! The WAL grows monotonically. A future optimization can compact it
//! by writing a snapshot of the current state and truncating the old
//! entries; for now, the entries are small (~200 bytes each) and the
//! file grows at ~1 entry per vote (~10/s), so compaction is not
//! urgent.

use codec::{Decode, DecodeError, Encode, Reader};
use primitives::{Epoch, Hash, Height, View};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Upper bound on one WAL entry's payload.
///
/// Unit: bytes. Origin: a `WalEntry` is the whole consensus safety state
/// (`last_voted_view`, `voted_at_height`, `high_qc`, `current_view`,
/// `next_height`, `epoch`, `last_committed`) — roughly 200 bytes even
/// with a large vote-lock map. 1 MiB is ~5000× headroom. Tradeoff: a
/// corrupt length field beyond this is treated as a torn tail rather
/// than allocated, so a damaged file cannot drive a multi-gigabyte
/// allocation on the recovery path.
const MAX_WAL_ENTRY_BYTES: usize = 1 << 20;

/// The safety-critical consensus state persisted to the WAL.
///
/// This is a snapshot of the engine's safety-critical fields at the
/// moment a vote is cast. On restart, the engine restores these
/// fields from the latest WAL entry before participating in consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalEntry {
    /// The highest view the engine has voted in. Prevents
    /// double-voting after restart (safety invariant #1).
    pub last_voted_view: Option<View>,
    /// Per-height vote lock: height → block hash. Prevents
    /// voting for a conflicting block at a height we already
    /// voted (safety invariant #2).
    pub voted_at_height: BTreeMap<u64, Hash>,
    /// The highest QC the engine has seen. Needed to propose
    /// the correct block after restart and to validate
    /// proposals that extend the chain.
    pub high_qc: Option<types::QuorumCertificate>,
    /// The current view. On restart, the engine resumes from
    /// this view (or catches up via QC delivery).
    pub current_view: View,
    /// The next height at which a block will be proposed.
    /// Needed for the proposer to continue the chain.
    pub next_height: Height,
    /// The current epoch. Needed for validator-set lookup
    /// and vote signing.
    pub epoch: Epoch,
    /// The committed anchor `(block_hash, height)`: the parent a
    /// proposal must extend while `high_qc` is `None` — the
    /// post-rotation boundary case. Safety-critical: a restart that
    /// forgets it falls back to the true-genesis arm and would
    /// accept a forged height-0 chain in a later epoch (or reject
    /// the legitimate continuation and wedge). Written on every
    /// append, and `commit_block` appends when it advances so the
    /// WAL never holds a stale anchor.
    ///
    /// Encoded as an optional trailer (1-byte flag + height + hash)
    /// so entries written by older binaries still decode.
    pub last_committed: Option<(Hash, Height)>,
    /// The committed validator set at this entry's epoch — present
    /// only on entries written by an epoch rotation (or an explicit
    /// set swap); ordinary vote/QC entries leave it `None` so the
    /// per-vote record stays ~200 bytes.
    ///
    /// Durability: the engine's in-memory set is rebuilt from
    /// genesis on every restart; without this field a post-rotation
    /// restart would resurrect the *genesis* committee under the
    /// recovered (later) epoch — a divergent leader schedule and
    /// quorum vs. every peer that stayed up. Recording the set in
    /// the same fsync'd entry that persists the epoch makes the
    /// transition atomic: recovery sees either both halves or the
    /// pre-rotation state, never a mix.
    ///
    /// `recover()` carries the most recent set-bearing entry
    /// forward, so the returned entry always reflects the set that
    /// was committed when the last record was written.
    pub validator_set: Option<crate::validator::ValidatorSet>,
}

impl Encode for WalEntry {
    fn encode(&self, buf: &mut Vec<u8>) {
        // last_voted_view: 1 byte flag + 8 bytes value
        match self.last_voted_view {
            Some(v) => {
                buf.push(1);
                v.encode(buf);
            }
            None => buf.push(0),
        }
        // voted_at_height: varint count + (u64 + Hash) entries
        codec::write::varint(buf, self.voted_at_height.len() as u64);
        for (height, hash) in &self.voted_at_height {
            codec::write::u64(buf, *height);
            hash.encode(buf);
        }
        // high_qc: 1 byte flag + encoded QC
        match &self.high_qc {
            Some(qc) => {
                buf.push(1);
                qc.encode(buf);
            }
            None => buf.push(0),
        }
        // current_view, next_height, epoch
        self.current_view.encode(buf);
        self.next_height.encode(buf);
        self.epoch.encode(buf);
        // last_committed: optional trailer (1-byte flag + height +
        // hash) — appended last so entries written before the field
        // existed still decode (the decoder reads it only if bytes
        // remain).
        match self.last_committed {
            Some((hash, height)) => {
                buf.push(1);
                height.encode(buf);
                hash.encode(buf);
            }
            None => buf.push(0),
        }
        // Optional trailer #2: the committed validator set
        // (1-byte flag + varint count + per-validator
        // [48B key][8B stake][20B address]). Written only on
        // rotation/set-swap entries — absent on old files and on
        // ordinary entries, decoded as `None`.
        match &self.validator_set {
            Some(vs) => {
                buf.push(1);
                codec::write::varint(buf, vs.n() as u64);
                for i in 0..vs.n() {
                    buf.extend_from_slice(vs.public_keys()[i].as_bytes());
                    codec::write::u64(buf, vs.stakes()[i]);
                    buf.extend_from_slice(&vs.validator_addresses()[i].0);
                }
            }
            None => buf.push(0),
        }
    }
}

impl<'a> Decode<'a> for WalEntry {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let last_voted_view =
            if reader.read_u8()? == 1 { Some(View::decode(reader)?) } else { None };
        let count = u32::try_from(reader.read_varint()?)
            .map_err(|_| DecodeError::LengthPrefixTooLarge { claimed: u64::MAX, remaining: 0 })?;
        let mut voted_at_height = BTreeMap::new();
        for _ in 0..count {
            let height = reader.read_u64()?;
            let hash = Hash::decode(reader)?;
            voted_at_height.insert(height, hash);
        }
        let high_qc = if reader.read_u8()? == 1 {
            Some(types::QuorumCertificate::decode(reader)?)
        } else {
            None
        };
        let current_view = View::decode(reader)?;
        let next_height = Height::decode(reader)?;
        let epoch = Epoch::decode(reader)?;
        // Optional trailer: entries written before `last_committed`
        // existed end here — decode them as `None` rather than
        // failing on a short buffer.
        let last_committed = if reader.remaining() > 0 && reader.read_u8()? == 1 {
            let height = Height::decode(reader)?;
            let hash = Hash::decode(reader)?;
            Some((hash, height))
        } else {
            None
        };
        // Optional trailer #2: validator set. Entries written before
        // it existed (and ordinary entries that leave it `None`)
        // end at the flag byte or earlier — decode `None`.
        let validator_set = if reader.remaining() > 0 && reader.read_u8()? == 1 {
            let count = u32::try_from(reader.read_varint()?).map_err(|_| {
                DecodeError::LengthPrefixTooLarge {
                    claimed: u64::MAX,
                    remaining: reader.remaining() as u64,
                }
            })?;
            // Every member encodes 48 key + 8 stake + 20 address
            // bytes — a count beyond what the remaining bytes could
            // hold is malformed, and bounding it here keeps the
            // `with_capacity` below from trusting the wire.
            if u64::from(count) > reader.remaining() as u64 / 76 {
                return Err(DecodeError::LengthPrefixTooLarge {
                    claimed: u64::from(count),
                    remaining: reader.remaining() as u64,
                });
            }
            let mut keys = Vec::with_capacity(count as usize);
            let mut stakes = Vec::with_capacity(count as usize);
            let mut addrs = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let key_bytes = reader.read_fixed::<48>()?;
                keys.push(crypto::bls::PublicKey::from_slice(&key_bytes).map_err(|_| {
                    DecodeError::WrongSliceLength { expected: 48, got: key_bytes.len() }
                })?);
                stakes.push(reader.read_u64()?);
                addrs.push(primitives::Address(reader.read_fixed::<20>()?));
            }
            Some(crate::validator::ValidatorSet::with_addresses(keys, stakes, addrs).map_err(
                |_| DecodeError::LengthPrefixTooLarge {
                    claimed: u64::MAX,
                    remaining: reader.remaining() as u64,
                },
            )?)
        } else {
            None
        };
        Ok(Self {
            last_voted_view,
            voted_at_height,
            high_qc,
            current_view,
            next_height,
            epoch,
            last_committed,
            validator_set,
        })
    }
}

/// Errors that can occur during WAL operations.
#[derive(Debug)]
pub enum WalError {
    /// I/O error (file open, read, write, fsync).
    Io(std::io::Error),
    /// A WAL entry failed to decode (corrupted payload).
    Decode(codec::DecodeError),
    /// The WAL file could not be created or opened.
    Open(std::io::Error),
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "WAL I/O error: {e}"),
            Self::Decode(e) => write!(f, "WAL decode error: {e}"),
            Self::Open(e) => write!(f, "WAL open error: {e}"),
        }
    }
}

impl std::error::Error for WalError {}

impl From<std::io::Error> for WalError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<codec::DecodeError> for WalError {
    fn from(e: codec::DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// CRC32 (IEEE 802.3 polynomial) checksum of a byte slice.
///
/// Used for WAL entry integrity. A CRC32 is sufficient here: the
/// WAL is a local file, not a network protocol — the threat is
/// crash-induced truncation, not an adversary crafting collisions.
/// CRC32 detects all truncation and single-bit errors, and most
/// multi-bit errors, with zero false positives in practice.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// The consensus write-ahead log.
///
/// Append-only file storing `WalEntry` records. Each entry is
/// length-prefixed and CRC32-protected. On restart, call
/// [`Wal::recover`] to read the latest valid entry.
pub struct Wal {
    /// The WAL file path.
    path: PathBuf,
    /// Buffered writer for appending entries. Wrapped in a
    /// `BufWriter` for efficiency (entries are small; without
    /// buffering, each `append` would issue a `write` syscall per
    /// entry).
    writer: BufWriter<File>,
    /// Fault-injection latch for tests: when set, `append` fails
    /// without touching the file. Engine tests use it to exercise
    /// the C10 fail-closed signing path on platforms where no
    /// always-failing device (`/dev/full`) is reachable from the
    /// sandbox.
    poisoned: bool,
}

impl Wal {
    /// Open or create the WAL at `path`. If the file exists,
    /// recovery entries are preserved; new entries are appended.
    ///
    /// A torn or corrupt suffix left by a crash is **truncated** before
    /// the first append — see [`repair_tail`](Self::repair_tail) for why
    /// appending past it would silently strand later records.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Open`] if the file cannot be created
    /// or opened for read+write+create, or [`WalError::Io`] if a torn
    /// tail cannot be repaired.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, WalError> {
        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(WalError::Open)?;
        let mut wal = Self { path, writer: BufWriter::new(file), poisoned: false };
        // Repair before any append can land after the damaged bytes.
        wal.repair_tail()?;
        Ok(wal)
    }

    /// Byte offset just past the last complete, CRC-valid record.
    ///
    /// Scans with the same rules [`recover`](Self::recover) uses (short
    /// read, oversized length, or CRC mismatch ends the scan), so the
    /// returned offset is exactly the boundary between replayable and
    /// unreplayable bytes.
    fn valid_prefix_len(&self) -> Result<u64, WalError> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);
        let mut valid_end = 0u64;
        loop {
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(WalError::Io(e)),
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > MAX_WAL_ENTRY_BYTES {
                break; // corrupt length field — treat as torn tail
            }
            let mut crc_buf = [0u8; 4];
            if reader.read_exact(&mut crc_buf).is_err() {
                break;
            }
            let expected_crc = u32::from_le_bytes(crc_buf);
            let mut payload = vec![0u8; len];
            if reader.read_exact(&mut payload).is_err() {
                break;
            }
            if crc32(&payload) != expected_crc {
                break;
            }
            valid_end += 8 + u64::try_from(len).unwrap_or(u64::MAX);
        }
        Ok(valid_end)
    }

    /// Truncate any torn or corrupt suffix so the file ends at a
    /// replayable record boundary. Returns `true` if bytes were removed.
    ///
    /// Replay stops at the first incomplete or CRC-mismatched record. If
    /// that suffix is left in place, appends land *after* the
    /// unreplayable bytes — and the next restart stops at the same
    /// damaged point, silently discarding every record written since.
    /// The vote those records describe was already fsynced and sent, so
    /// forgetting it is exactly the double-vote hazard this WAL exists
    /// to prevent. Repairing at open time keeps the append position
    /// always at a durable, replayable boundary.
    ///
    /// # Errors
    ///
    /// [`WalError::Io`] if the file cannot be read or truncated.
    pub fn repair_tail(&mut self) -> Result<bool, WalError> {
        let valid_end = self.valid_prefix_len()?;
        let file_len = std::fs::metadata(&self.path).map_err(WalError::Io)?.len();
        if valid_end >= file_len {
            return Ok(false);
        }
        // `set_len` truncates in place; sync so the shortened file is
        // durable before the first append reuses that space.
        let file = OpenOptions::new().write(true).open(&self.path).map_err(WalError::Open)?;
        file.set_len(valid_end).map_err(WalError::Io)?;
        file.sync_all().map_err(WalError::Io)?;
        Ok(true)
    }

    /// Fault-injection hook for tests: after `poison`, every
    /// `append` fails with an I/O error. Permanent for the life of
    /// this `Wal` — matching how a real disk failure presents to
    /// the engine.
    #[doc(hidden)]
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Append a WAL entry and fsync it to disk.
    ///
    /// This must be called BEFORE the engine sends a vote or
    /// advances safety-critical state. The fsync ensures the
    /// entry is durable before the vote hits the network.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Io`] if the write or fsync fails.
    pub fn append(&mut self, entry: &WalEntry) -> Result<(), WalError> {
        // Fault-injection latch (tests only): fail before touching
        // the file, the same outcome an ENOSPC write produces.
        if self.poisoned {
            return Err(WalError::Io(std::io::Error::other("WAL poisoned")));
        }
        // Encode the entry payload.
        let mut payload = Vec::with_capacity(256);
        entry.encode(&mut payload);

        // Write: [u32 LE length] [u32 LE CRC32] [payload]
        // A WAL entry >4 GiB is impossible (the entire consensus
        // state is ~200 bytes), so this conversion never fails in
        // practice. Return an error rather than panicking for
        // robustness.
        let len = u32::try_from(payload.len())
            .map_err(|_| WalError::Io(std::io::Error::other("WAL entry exceeds u32 length")))?;
        let crc = crc32(&payload);
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(&crc.to_le_bytes())?;
        self.writer.write_all(&payload)?;
        self.writer.flush()?;
        // fsync the underlying file (not just the buffer).
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    /// Recover the latest valid WAL entry.
    ///
    /// Reads the WAL sequentially. Each entry is validated by
    /// its CRC32. A truncated or CRC-mismatched tail entry is
    /// discarded (the validator crashed mid-write). Returns
    /// the last valid entry, or `None` if the WAL is empty or
    /// contains no valid entries.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Io`] if the file cannot be read.
    /// Returns [`WalError::Decode`] if a valid-CRC entry fails
    /// to decode (should not happen unless the codec is
    /// inconsistent with the Encode impl).
    pub fn recover(&self) -> Result<Option<WalEntry>, WalError> {
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);
        let mut last_valid: Option<WalEntry> = None;
        let mut last_set: Option<crate::validator::ValidatorSet> = None;

        loop {
            // Read the 4-byte length prefix.
            let mut len_buf = [0u8; 4];
            match reader.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(WalError::Io(e)),
            }
            let len = u32::from_le_bytes(len_buf) as usize;

            // A corrupt length field must not drive a huge allocation.
            // Real entries are ~200 B; anything past the bound is a torn
            // tail, not a record (same rule `valid_prefix_len` applies).
            if len > MAX_WAL_ENTRY_BYTES {
                break;
            }

            // Read the 4-byte CRC32.
            let mut crc_buf = [0u8; 4];
            match reader.read_exact(&mut crc_buf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(WalError::Io(e)),
            }
            let expected_crc = u32::from_le_bytes(crc_buf);

            // Read the payload.
            let mut payload = vec![0u8; len];
            match reader.read_exact(&mut payload) {
                Ok(()) => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(WalError::Io(e)),
            }

            // Validate CRC. If it doesn't match, the entry was
            // truncated mid-write (crash). Discard it and stop.
            if crc32(&payload) != expected_crc {
                break;
            }

            // Decode the entry.
            let mut reader = Reader::new(&payload);
            let entry = WalEntry::decode(&mut reader)?;
            // Track the most recent set-bearing record: only
            // rotation entries carry `validator_set`, so the set
            // that governed the final entry is the last one
            // recorded — possibly many entries back.
            if entry.validator_set.is_some() {
                last_set.clone_from(&entry.validator_set);
            }
            last_valid = Some(entry);
        }

        // Merge the effective committee into the returned entry so
        // the caller restores epoch *and* membership atomically —
        // a tail of plain vote entries after a rotation still
        // resolves to the rotated set.
        if let Some(ref mut entry) = last_valid
            && entry.validator_set.is_none()
        {
            entry.validator_set = last_set;
        }
        Ok(last_valid)
    }

    /// Truncate the WAL to zero entries.
    ///
    /// Called after a snapshot is taken (the snapshot supersedes
    /// the WAL entries). The file is truncated and re-opened for
    /// appending.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Io`] if the truncation fails.
    pub fn truncate(&mut self) -> Result<(), WalError> {
        // Flush and close the current writer.
        self.writer.flush()?;
        // Truncate the file to zero bytes.
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(WalError::Open)?;
        self.writer = BufWriter::new(file);
        Ok(())
    }

    /// Seek to the end of the WAL file (for internal use).
    #[allow(dead_code)]
    fn seek_end(&mut self) -> Result<u64, WalError> {
        self.writer.seek(SeekFrom::End(0)).map_err(WalError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A WAL entry with no `high_qc` (genesis state).
    fn genesis_entry() -> WalEntry {
        WalEntry {
            last_voted_view: None,
            voted_at_height: BTreeMap::new(),
            high_qc: None,
            current_view: View::new(0),
            next_height: Height::new(0),
            epoch: Epoch::new(0),
            last_committed: None,
            validator_set: None,
        }
    }

    /// A WAL entry after voting at view 5, height 3.
    fn voted_entry() -> WalEntry {
        let mut voted_at_height = BTreeMap::new();
        voted_at_height.insert(3, Hash([0xAA; 32]));
        WalEntry {
            last_voted_view: Some(View::new(5)),
            voted_at_height,
            high_qc: None,
            current_view: View::new(6),
            next_height: Height::new(4),
            epoch: Epoch::new(0),
            last_committed: Some((Hash([0xBB; 32]), Height::new(2))),
            validator_set: None,
        }
    }

    /// C9 test: a WAL entry can be encoded and decoded round-trip.
    #[test]
    fn wal_entry_encode_decode_roundtrip() {
        let entry = voted_entry();
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = WalEntry::decode(&mut reader).unwrap();
        assert_eq!(entry, decoded);
    }

    /// C9 test: a WAL can write and recover entries.
    #[test]
    fn wal_write_and_recover() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();

        // Write a genesis entry.
        wal.append(&genesis_entry()).unwrap();
        // Write a voted entry.
        wal.append(&voted_entry()).unwrap();

        // Recover — should get the voted entry.
        let recovered = wal.recover().unwrap();
        assert_eq!(recovered, Some(voted_entry()));
    }

    /// C9 test: recovering an empty WAL returns None.
    #[test]
    fn wal_recover_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap();
        assert!(recovered.is_none());
    }

    /// C9 test: a truncated tail entry (crash mid-write) is
    /// discarded, and the last valid entry is returned.
    #[test]
    fn wal_recover_truncated_tail() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();

        // Write a valid entry.
        wal.append(&genesis_entry()).unwrap();
        // Write a valid entry.
        wal.append(&voted_entry()).unwrap();

        // Append a partial entry (simulate crash mid-write):
        // write the length prefix but not the full payload.
        wal.writer.flush().unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        // Length prefix claiming 1000 bytes, but only 4 written.
        file.write_all(&1000u32.to_le_bytes()).unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap(); // CRC
        file.write_all(&[0u8; 10]).unwrap(); // partial payload
        file.sync_data().unwrap();
        drop(file);

        // Reopen and recover — should get the voted entry (the
        // last valid one), not the truncated tail.
        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap();
        assert_eq!(recovered, Some(voted_entry()));
    }

    /// C9 test: a corrupted entry (CRC mismatch) is discarded.
    #[test]
    fn wal_recover_corrupted_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();

        // Write a valid entry.
        wal.append(&genesis_entry()).unwrap();

        // Append a corrupted entry (wrong CRC).
        wal.writer.flush().unwrap();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        let payload = vec![0xFFu8; 64]; // garbage payload
        let len = u32::try_from(payload.len()).unwrap();
        let wrong_crc = 0xDEAD_BEEFu32; // wrong CRC
        file.write_all(&len.to_le_bytes()).unwrap();
        file.write_all(&wrong_crc.to_le_bytes()).unwrap();
        file.write_all(&payload).unwrap();
        file.sync_data().unwrap();
        drop(file);

        // Reopen and recover — should get the genesis entry (the
        // last valid one), not the corrupted entry.
        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap();
        assert_eq!(recovered, Some(genesis_entry()));
    }

    /// C9 test: WAL truncate clears all entries.
    #[test]
    fn wal_truncate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();

        wal.append(&genesis_entry()).unwrap();
        wal.append(&voted_entry()).unwrap();
        wal.truncate().unwrap();

        let recovered = wal.recover().unwrap();
        assert!(recovered.is_none());
    }

    /// Regression: appending after a torn tail must not strand later
    /// records.
    ///
    /// Previously `open` left the damaged suffix in place, so the append
    /// cursor sat *after* unreplayable bytes. The next restart stopped
    /// at those same bytes and silently discarded every record written
    /// since — including votes that had already been fsynced and sent,
    /// which is precisely the double-vote hazard the WAL exists to
    /// prevent.
    #[test]
    fn wal_repairs_torn_tail_so_later_entries_survive_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");

        // Session 1: one valid entry, then a crash leaves a torn tail.
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&genesis_entry()).unwrap();
            wal.writer.flush().unwrap();
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&1000u32.to_le_bytes()).unwrap(); // claims 1000 B
            file.write_all(&0u32.to_le_bytes()).unwrap(); // CRC
            file.write_all(&[0u8; 10]).unwrap(); // partial payload
            file.sync_data().unwrap();
        }

        // Session 2: restart, recover the valid prefix, then vote.
        {
            let mut wal = Wal::open(&path).unwrap();
            let recovered = wal.recover().unwrap();
            assert_eq!(
                recovered,
                Some(genesis_entry()),
                "the torn tail must not hide the valid entry before it"
            );
            wal.append(&voted_entry()).unwrap();
        }

        // Session 3: the vote fsynced in session 2 must still be there.
        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap();
        assert_eq!(
            recovered,
            Some(voted_entry()),
            "a vote written after a repaired torn tail must survive the next restart"
        );
    }

    /// `repair_tail` is a no-op on an intact file and reports whether it
    /// actually removed anything.
    #[test]
    fn wal_repair_tail_reports_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&genesis_entry()).unwrap();
        }
        // Intact file: nothing to repair.
        let mut wal = Wal::open(&path).unwrap();
        assert!(!wal.repair_tail().unwrap(), "an intact WAL needs no repair");

        // Damaged tail: repaired once, then idempotent.
        {
            wal.writer.flush().unwrap();
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[0xFFu8; 6]).unwrap(); // partial length prefix
            file.sync_data().unwrap();
        }
        assert!(wal.repair_tail().unwrap(), "a torn tail must be removed");
        assert!(!wal.repair_tail().unwrap(), "repair must be idempotent");
        assert_eq!(wal.recover().unwrap(), Some(genesis_entry()));
    }

    /// C9 test: CRC32 produces the expected value for a known input.
    /// The CRC32 of "123456789" (IEEE 802.3) is 0xCBF43926.
    #[test]
    fn crc32_known_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// C9 test: restart safety — after a restart, the engine
    /// recovers `last_voted_view` and `voted_at_height` from the
    /// WAL, preventing double-voting and conflicting votes.
    #[test]
    fn wal_restart_safety() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");

        // Simulate a validator that voted at view 5, height 3.
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&voted_entry()).unwrap();
        }

        // Simulate a restart: reopen the WAL and recover.
        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap().expect("must recover entry");

        // The recovered state must prevent double-voting.
        assert_eq!(recovered.last_voted_view, Some(View::new(5)));
        // The recovered state must prevent conflicting votes.
        assert_eq!(recovered.voted_at_height.get(&3), Some(&Hash([0xAA; 32])));
        // The recovered state must have the correct view and height.
        assert_eq!(recovered.current_view, View::new(6));
        assert_eq!(recovered.next_height, Height::new(4));
    }

    /// Build a two-validator set for set-trailer tests.
    fn test_set() -> crate::validator::ValidatorSet {
        let keys: Vec<crypto::BlsSecretKey> =
            (1u8..=2).map(|i| crypto::BlsSecretKey::from_ikm(&[i; 32]).expect("BLS key")).collect();
        let pks: Vec<crypto::bls::PublicKey> =
            keys.iter().map(crypto::BlsSecretKey::public_key).collect();
        crate::validator::ValidatorSet::with_addresses(
            pks,
            vec![1, 1],
            vec![primitives::Address([0x01; 20]), primitives::Address([0x02; 20])],
        )
        .expect("test validator set")
    }

    /// A set-bearing entry round-trips through the wire — the
    /// rotation record that recovery relies on.
    #[test]
    fn wal_entry_with_validator_set_roundtrips() {
        let mut entry = voted_entry();
        entry.epoch = Epoch::new(1);
        entry.validator_set = Some(test_set());
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = WalEntry::decode(&mut reader).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(decoded.validator_set, Some(test_set()));
    }

    /// Entries written before the set trailer existed must still
    /// decode — the field is an optional tail, not a schema break.
    #[test]
    fn wal_entry_without_set_decodes_legacy() {
        // Encode the pre-set shape by hand: everything through
        // `last_committed`, no set trailer.
        let mut buf = Vec::new();
        buf.push(0u8); // last_voted_view: None
        codec::write::varint(&mut buf, 0); // 0 voted_at_height
        buf.push(0u8); // high_qc: None
        View::new(2).encode(&mut buf);
        Height::new(1).encode(&mut buf);
        Epoch::new(3).encode(&mut buf);
        buf.push(0u8); // last_committed: None — stream ends here
        let mut reader = Reader::new(&buf);
        let decoded = WalEntry::decode(&mut reader).expect("legacy tail decodes");
        assert_eq!(decoded.validator_set, None);
        assert_eq!(decoded.epoch, Epoch::new(3));
    }

    /// The epoch-transition durability contract: a rotation entry
    /// carries the new committee, and recovery must resolve THAT
    /// set even when plain vote entries were appended afterward —
    /// the last record does not hold the set, the last *set-bearing*
    /// record does.
    #[test]
    fn wal_recover_carries_forward_last_validator_set() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let rotated = test_set();

        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&genesis_entry()).unwrap();
            // Rotation entry: epoch 1 with the new committee.
            let mut rotation = voted_entry();
            rotation.epoch = Epoch::new(1);
            rotation.validator_set = Some(rotated.clone());
            wal.append(&rotation).unwrap();
            // Ordinary vote entries after the rotation — no set
            // trailer, epoch 1 (the committee now in force).
            let mut post = voted_entry();
            post.epoch = Epoch::new(1);
            wal.append(&post).unwrap();
        }

        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap().expect("recovers");
        assert_eq!(recovered.epoch, Epoch::new(1), "last entry's own epoch");
        assert_eq!(
            recovered.validator_set,
            Some(rotated),
            "recovery resolves the most recent set-bearing entry"
        );
    }
}
