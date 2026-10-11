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
//! ## Compaction
//!
//! Every `WalEntry` is a *full* snapshot of the engine's
//! safety-critical state, so only the newest entry (plus the most
//! recent set-bearing record, which `recover` merges forward) is
//! replayable state — everything older is dead bytes. When the file
//! grows past [`COMPACT_AFTER_BYTES`], the engine checkpoints: the
//! current state is written as a single set-bearing entry to a
//! temporary file, fsynced, and atomically renamed over the WAL
//! (tmp → fsync → rename → directory fsync, the same atomic-write
//! convention the executor snapshot uses). A crash mid-checkpoint
//! leaves either the old WAL or the new one — both recoverable.
//!
//! Segment chaining was considered and rejected: chained segments
//! exist to preserve deltas, but these entries are snapshots, so a
//! single checkpoint entry carries strictly the same recoverable
//! state as the whole history — extra files would buy complexity,
//! not durability. Compaction bounds the file at
//! `COMPACT_AFTER_BYTES + MAX_WAL_ENTRY_BYTES` and the recovery scan
//! at the same order, so restart time no longer grows with uptime.
//!
//! ## Synchronous durability (the fsync fold)
//!
//! On Linux the WAL file is opened `O_DSYNC`: every `write(2)`
//! completes only when its own data and the metadata needed to
//! retrieve it (the file-size update, covered because appends extend
//! the file) are committed to storage. That folds the fsync into the
//! append's write — one syscall per signature emission instead of
//! `write` + `fdatasync`, which was the dominant per-view cost.
//!
//! Two consequences shape the layout:
//!
//! * **Deferred frames buffer, not write.** `O_DSYNC` syncs only the
//!   data in *that* write call — a deferred frame flushed on its own
//!   would pay a full sync and invert the batching win. So
//!   [`Wal::append_unsynced`] leaves the frame in the `BufWriter`;
//!   the next signature-path [`Wal::append`] flushes it inside the
//!   same `write(2)` as the signature frame, and the one `O_DSYNC`
//!   completion covers both. The deferred contract is unchanged —
//!   loss-tolerant state only — but the loss window now includes
//!   process exit, not just power loss: an unflushed buffer never
//!   reached the kernel.
//! * **Extents are preallocated.** `fallocate(FALLOC_FL_KEEP_SIZE)`
//!   maps [`PREALLOC_CHUNK_BYTES`] ahead of the append position, so
//!   a synced write touches only the file-size update in the journal
//!   — never a block-allocation transaction — and `ENOSPC` surfaces
//!   at allocation time rather than mid-view. `KEEP_SIZE` keeps the
//!   logical length honest: recovery scans real frames only.
//!
//! macOS and other non-Linux targets keep the previous path —
//! `write` + `sync_data` (`F_FULLFSYNC` on Apple, the stronger
//! drive-cache flush `O_DSYNC` does not imply there) — with the same
//! buffered-deferred batching.

use codec::{Decode, DecodeError, Encode, Reader};
use primitives::{Epoch, Hash, Height, View};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// Upper bound on one WAL entry's payload.
///
/// Unit: bytes. Origin: a `WalEntry` carries the consensus safety state
/// (`last_voted_view`, `voted_at_height`, `high_qc`, `current_view`,
/// `next_height`, `epoch`, `last_committed`) — roughly 200 bytes — plus
/// the `pending` tail: up to [`MAX_PERSISTED_PENDING`] uncommitted
/// blocks with their full proposal bodies. Bodies are bounded by the
/// consensus block budget (~1 MiB each), so the entry cap is sized for
/// the tail, not the safety fields. Tradeoff: a corrupt length field
/// beyond this is treated as a torn tail rather than allocated, so a
/// damaged file cannot drive a multi-gigabyte allocation on the
/// recovery path.
const MAX_WAL_ENTRY_BYTES: usize = 16 << 20;

/// Maximum uncommitted chain tail persisted in a [`WalEntry`].
///
/// Unit: blocks. The restart-continuation invariant requires the
/// *contiguous* run of uncommitted blocks above `last_committed` —
/// a gap or a missing body stalls the commit walk (safe, but dead).
/// Healthy operation commits within ~2 heights of the tip, so 8
/// covers deep timeout-driven tails with margin; a tail deeper than
/// the cap means the node fell far behind and needs block sync, not
/// replay (the walk stops at the first missing body either way).
pub(crate) const MAX_PERSISTED_PENDING: usize = 8;

/// Budget for the pending tail's proposal *bodies* in one entry
/// (hft-audit-2 N-3).
///
/// Unit: bytes (an upper bound on the bodies' encoded size). Origin:
/// an entry over [`MAX_WAL_ENTRY_BYTES`] is still written, but
/// recovery treats it as a torn tail and falls back to the previous
/// entry — losing the vote lock it recorded, so a restart could sign
/// a conflicting vote. At the chain's 16 MiB block budget a 2-block
/// tail already crossed the cap. Bodies are persisted lowest height
/// first while they fit in this budget; the rest persist as bare
/// headers, which recovery already handles (the commit walk stops at
/// the first missing body and block sync supplies it — a liveness
/// cost, never a safety one). The 1 MiB of headroom covers the safety
/// fields, headers, `high_qc`, an attached validator set (~100 B per
/// validator) and `recent_signers`.
pub(crate) const MAX_PERSISTED_BODY_BYTES: usize = MAX_WAL_ENTRY_BYTES - (1 << 20);

/// WAL size that triggers a checkpoint compaction.
///
/// Unit: bytes appended since the last checkpoint (or since file
/// open, for a WAL that predates compaction). Origin: recovery reads
/// the whole file once, so this bounds restart scan time — 32 MiB of
/// CRC-framed entries decodes in tens of milliseconds while still
/// being large enough that compaction amortizes to near-zero cost
/// (one extra file write + fsync + rename per 32 MiB of appended
/// state, vs. the per-entry fsync already paid). Tradeoff: halving
/// it halves worst-case restart read time but doubles rewrite churn;
/// raising it delays the checkpoint a busy validator would otherwise
/// take for free.
const COMPACT_AFTER_BYTES: u64 = 32 << 20;

/// Extent preallocation quantum — see "Synchronous durability" above.
///
/// Unit: bytes. `fallocate(FALLOC_FL_KEEP_SIZE)` is issued in chunks
/// of this size so a synced append never triggers a block-allocation
/// journal transaction. Sized a quarter of the compaction bound: a
/// WAL that lives to `COMPACT_AFTER_BYTES` allocates four times ever,
/// while a short-lived test WAL pays at most 8 MiB of reserved space.
/// Linux only — other platforms keep the unsized-append behaviour.
#[cfg(target_os = "linux")]
const PREALLOC_CHUNK_BYTES: u64 = 8 << 20;

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
    /// The latest view this engine signed a timeout for. Safety-
    /// critical under the Jolteon evidence rule: a validator that
    /// signed `timeout(v)` must not also vote in `v` — its TC
    /// entry asserts a fixed `qc_high` that predates any later
    /// vote, and voting after signing would let a TC underreport
    /// the quorum's real locks (arXiv:2106.10362 §3). Without
    /// persistence, a restart forgets the signed view and can
    /// emit both signatures for the same view.
    ///
    /// Encoded as an optional trailer (1-byte flag + 8-byte view)
    /// so entries written by older binaries still decode.
    pub timeout_signed_view: Option<View>,
    /// The uncommitted chain tail: `(header, body)` for every stored
    /// block above `last_committed`, ordered by height. `body` is
    /// `Some` for a `Complete` block and `None` for an `Awaiting`
    /// header — `propose()` stamps heights from the header alone, so
    /// restoring header-only entries preserves the exact pre-crash
    /// resolution capability (the commit walk still waits on the
    /// body, as it did live). Restart-critical: the engine's
    /// `blocks` map is in-memory only, and `propose()` /
    /// `commit_walk` cannot stamp heights or finalize over a QC'd
    /// block whose header/body was lost — without this field a
    /// restart with a pending tip deadlocks (the recovered `high_qc`
    /// resolves to a hash nothing can look up). `voted_at_height`
    /// keeps the same-height locks honest across the re-run.
    ///
    /// Encoded as optional trailer #4 (varint count + per-entry
    /// header + 1-byte body flag + proposal); absent on old files —
    /// decoded `[]`. Capped at [`MAX_PERSISTED_PENDING`] when written.
    pub pending: Vec<(types::BlockHeader, Option<types::Proposal>)>,
    /// The confirmed execution divergence that halted signing, if
    /// any. Safety-critical in the same way the vote locks are: a
    /// restart that forgot the latch would resume signing over state
    /// a verified quorum certificate already proved this node does
    /// not share — the exact silent-divergence failure the latch
    /// exists to close. Terminal: the only clearing path is certified
    /// state repair (which rebuilds the executor, not this record).
    ///
    /// Encoded as optional trailer #5 (1-byte flag + height +
    /// local root + certified root); absent on old files — decoded
    /// `None`.
    pub divergence: Option<types::ExecDivergence>,
    /// The leader-reputation window: the certifying QC's signer
    /// bitmap for each of the most recent committed heights, oldest
    /// → newest. Reputation exclusions are a pure function of this
    /// committed history — restoring it keeps the post-restart
    /// leader schedule identical to the pre-crash one instead of
    /// silently reverting to "nobody excluded" while peers still
    /// skip the dead member.
    ///
    /// Encoded as optional trailer #6 (varint count + per-entry
    /// varint length + bitmap bytes); absent on old files —
    /// decoded `[]`.
    pub recent_signers: Vec<Vec<u8>>,
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
        // Optional trailer #3: the timeout-signed view (1-byte
        // flag + 8-byte view). Absent on old files — decoded `None`.
        match self.timeout_signed_view {
            Some(v) => {
                buf.push(1);
                v.encode(buf);
            }
            None => buf.push(0),
        }
        // Optional trailer #4: the uncommitted tail (varint count +
        // per-entry header + 1-byte body flag + proposal). The count
        // is always present once the writer is this version — older
        // decoders stop before it, newer ones read `0` as an empty
        // tail.
        codec::write::varint(buf, self.pending.len() as u64);
        for (header, body) in &self.pending {
            header.encode(buf);
            match body {
                Some(proposal) => {
                    buf.push(1);
                    proposal.encode(buf);
                }
                None => buf.push(0),
            }
        }
        // Optional trailer #5: the divergence latch (1-byte flag +
        // height + local root + certified root). Absent on old
        // files — decoded `None`.
        match &self.divergence {
            Some(d) => {
                buf.push(1);
                d.height.encode(buf);
                d.local_root.encode(buf);
                d.certified_root.encode(buf);
            }
            None => buf.push(0),
        }
        // Optional trailer #6: the leader-reputation window (varint
        // count + per-entry varint length + bitmap bytes). The count
        // is always present once the writer is this version — older
        // decoders stop before it, newer ones read `0` as empty.
        codec::write::varint(buf, self.recent_signers.len() as u64);
        for bitmap in &self.recent_signers {
            codec::write::varint(buf, bitmap.len() as u64);
            buf.extend_from_slice(bitmap);
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
        // Optional trailer #3: timeout-signed view. Entries written
        // before it existed end at or before the flag byte —
        // decode `None`.
        let timeout_signed_view = if reader.remaining() > 0 && reader.read_u8()? == 1 {
            Some(View::decode(reader)?)
        } else {
            None
        };
        // Optional trailer #4: the uncommitted tail. Entries written
        // before it existed end here — decode `[]`.
        let pending = decode_pending_tail(reader)?;
        // Optional trailer #5: the divergence latch. Entries written
        // before it existed end at or before the flag byte —
        // decode `None`.
        let divergence = if reader.remaining() > 0 && reader.read_u8()? == 1 {
            Some(types::ExecDivergence {
                height: Height::decode(reader)?,
                local_root: Hash::decode(reader)?,
                certified_root: Hash::decode(reader)?,
            })
        } else {
            None
        };
        // Optional trailer #6: the reputation window.
        let recent_signers = decode_signer_window(reader)?;
        Ok(Self {
            last_voted_view,
            voted_at_height,
            high_qc,
            current_view,
            next_height,
            epoch,
            last_committed,
            validator_set,
            timeout_signed_view,
            pending,
            divergence,
            recent_signers,
        })
    }
}

/// Decode optional trailer #4: the uncommitted chain tail.
///
/// Each entry is a header (~150 B fixed fields) + 1-byte body flag +
/// proposal, so a claimed count beyond what the remaining bytes could
/// hold is malformed — the bound runs before the per-entry loop trusts
/// the wire for `with_capacity`. Returns `[]` when the buffer ends
/// before the trailer (entries written by older binaries).
fn decode_pending_tail(
    reader: &mut Reader<'_>,
) -> Result<Vec<(types::BlockHeader, Option<types::Proposal>)>, DecodeError> {
    if reader.remaining() == 0 {
        return Ok(Vec::new());
    }
    let count =
        u32::try_from(reader.read_varint()?).map_err(|_| DecodeError::LengthPrefixTooLarge {
            claimed: u64::MAX,
            remaining: reader.remaining() as u64,
        })?;
    if u64::from(count) > reader.remaining() as u64 / 64 {
        return Err(DecodeError::LengthPrefixTooLarge {
            claimed: u64::from(count),
            remaining: reader.remaining() as u64,
        });
    }
    let mut pending = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let header = types::BlockHeader::decode(reader)?;
        let body =
            if reader.read_u8()? == 1 { Some(types::Proposal::decode(reader)?) } else { None };
        pending.push((header, body));
    }
    Ok(pending)
}

/// Decode optional trailer #6: the leader-reputation window.
///
/// Each entry is a varint length + bitmap bytes, so a claimed count
/// beyond the remaining bytes is malformed — the bound runs before
/// the per-entry loop trusts the wire. Returns `[]` when the buffer
/// ends before the trailer (entries written by older binaries).
fn decode_signer_window(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, DecodeError> {
    if reader.remaining() == 0 {
        return Ok(Vec::new());
    }
    let count =
        u32::try_from(reader.read_varint()?).map_err(|_| DecodeError::LengthPrefixTooLarge {
            claimed: u64::MAX,
            remaining: reader.remaining() as u64,
        })?;
    if u64::from(count) > reader.remaining() as u64 {
        return Err(DecodeError::LengthPrefixTooLarge {
            claimed: u64::from(count),
            remaining: reader.remaining() as u64,
        });
    }
    let mut bitmaps = Vec::with_capacity(count as usize);
    for _ in 0..count {
        bitmaps.push(reader.read_bytes()?.to_vec());
    }
    Ok(bitmaps)
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
    primitives::crc32::checksum(data)
}

/// Encode `entry` into one WAL frame: `[u32 LE length] [u32 LE CRC32]
/// [payload]` — the single framing rule both `append` and
/// `checkpoint` write and `recover`/`valid_prefix_len` read.
///
/// # Errors
///
/// [`WalError::Io`] if the payload exceeds the u32 length prefix —
/// impossible in practice (the cap is [`MAX_WAL_ENTRY_BYTES`]) but
/// reported rather than panicking.
fn frame_entry(entry: &WalEntry) -> Result<Vec<u8>, WalError> {
    let mut payload = Vec::with_capacity(256);
    entry.encode(&mut payload);
    let len = u32::try_from(payload.len())
        .map_err(|_| WalError::Io(std::io::Error::other("WAL entry exceeds u32 length")))?;
    let mut frame = Vec::with_capacity(payload.len() + 8);
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&crc32(&payload).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Atomically replace `path` with `bytes`: write a sibling `.tmp`
/// file, fsync it, `rename` over the destination, then fsync the
/// directory so the rename itself is durable. Same convention as
/// `executor::durability::atomic_write` — duplicated here because
/// `consensus` sits below `executor` in the dependency graph and the
/// helper is fifteen lines.
fn atomic_replace(path: &std::path::Path, bytes: &[u8]) -> Result<(), WalError> {
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp = PathBuf::from(tmp_os);
    {
        let mut file = File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // `rename` replaces atomically on Unix. On Windows it fails if
    // the destination exists — remove then rename, accepting the
    // small non-atomic gap there (a crash in the gap loses the new
    // checkpoint but the caller's retry is the next append).
    if let Err(e) = std::fs::rename(&tmp, path) {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(&tmp, path).map_err(|_| e)?;
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
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
    /// Bytes appended since the last checkpoint (initialized to the
    /// file length at open, so a WAL written by a pre-compaction
    /// binary compacts on its next append rather than growing
    /// forever). When this reaches `compact_after`, the engine
    /// rewrites the file as a single checkpoint entry.
    bytes_since_checkpoint: u64,
    /// Compaction trigger — [`COMPACT_AFTER_BYTES`] in production,
    /// lowered by tests via [`set_compact_threshold`](Self::set_compact_threshold)
    /// to exercise the path without writing megabytes.
    compact_after: u64,
    /// Signature-path fsync counter — see [`sync_count`](Self::sync_count).
    /// Checkpoint fsyncs (`atomic_replace` inside [`checkpoint`]) are
    /// compaction events, not signature emissions, and are not counted.
    syncs: u64,
    /// Logical end of appended data — the file length once every
    /// buffered frame is flushed. Tracked rather than re-stat'd per
    /// append because every write flows through this `BufWriter`;
    /// `repair_tail`, `checkpoint`, and `truncate` re-seed it.
    /// Drives [`ensure_room`](Self::ensure_room).
    appended_end: u64,
    /// End of the `fallocate`'d extent. `appended_end` may pass it
    /// only transiently between appends — [`ensure_room`](
    /// Self::ensure_room) extends before the write lands.
    allocated_end: u64,
    /// `false` once `fallocate` reports `EOPNOTSUPP`/`ENOSYS` (an
    /// exotic filesystem or kernel): preallocation is a hint layer —
    /// `O_DSYNC` still covers durability — so it disables itself
    /// rather than failing appends.
    #[cfg(target_os = "linux")]
    prealloc_ok: bool,
}

/// Open the WAL's data file for read+append — and, on Linux,
/// `O_DSYNC`: the flag makes each `write(2)` complete only when its
/// own data plus the metadata needed to retrieve it are committed
/// to storage, folding the durability fsync into the append write.
/// `O_DSYNC` covers the file-size update that `O_APPEND` needs —
/// unlike `O_SYNC` it does not force unrelated metadata — and the
/// `fallocate`'d extent keeps that update journal-cheap.
///
/// macOS is deliberately excluded: its `O_DSYNC` does not imply
/// `F_FULLFSYNC` (the drive-cache flush `File::sync_data` performs),
/// so Apple builds keep the write+`sync_data` path in
/// [`Wal::sync`](Wal::sync) — identical durability to before.
fn open_wal_file(path: &std::path::Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true).read(true);
    #[cfg(target_os = "linux")]
    opts.custom_flags(libc::O_DSYNC);
    opts.open(path)
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
        let file = open_wal_file(&path).map_err(WalError::Open)?;
        let mut wal = Self {
            path,
            writer: BufWriter::new(file),
            poisoned: false,
            bytes_since_checkpoint: 0,
            compact_after: COMPACT_AFTER_BYTES,
            syncs: 0,
            appended_end: 0,
            allocated_end: 0,
            #[cfg(target_os = "linux")]
            prealloc_ok: true,
        };
        // Repair before any append can land after the damaged bytes,
        // then seed the compaction counter with the repaired length:
        // an old, never-compacted WAL counts its whole history toward
        // the threshold so it compacts on the next append.
        wal.repair_tail()?;
        let len = std::fs::metadata(&wal.path).map_err(WalError::Io)?.len();
        wal.bytes_since_checkpoint = len;
        // The file's real length is both the append position and the
        // floor of the allocated extent (a repaired file may be
        // shorter than what was once allocated — truncation freed
        // the tail). The first append's `ensure_room` extends.
        wal.appended_end = len;
        wal.allocated_end = len;
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

    /// Append a WAL entry and make it durable.
    ///
    /// This must be called BEFORE the engine sends a vote or
    /// advances safety-critical state: the call returns only after
    /// the frame is committed to storage (an `O_DSYNC` write on
    /// Linux, write+`sync_data` elsewhere) — see the module's
    /// "Synchronous durability" section. Every previously buffered
    /// deferred frame rides the same durability point.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Io`] if the write or sync fails.
    pub fn append(&mut self, entry: &WalEntry) -> Result<(), WalError> {
        self.append_unsynced(entry)?;
        self.sync()
    }

    /// Append a WAL entry WITHOUT a durability point of its own.
    ///
    /// The frame stays in the `BufWriter` — it is flushed inside the
    /// *same `write(2)`* as the next signature-path
    /// [`append`](Self::append), so the one `O_DSYNC` completion (or
    /// `sync_data` on non-Linux) covers every buffered frame. That is
    /// the batching contract the engine relies on: state records no
    /// pending signature depends on (QC adoptions, commit markers)
    /// defer here and are made durable by the next signature-gated
    /// append instead of paying their own sync. Flushing each frame
    /// eagerly would still preserve durability — but under `O_DSYNC`
    /// each flush is itself a full sync, which inverts the win.
    ///
    /// A process exit or power loss between this call and the next
    /// [`append`](Self::append) loses the frame — it never left
    /// userspace. Recovery tolerates either presence or absence, so
    /// callers must only defer state that peers can re-deliver (QCs
    /// re-gossip) or that an idempotent downstream re-applies (the
    /// executor's `next_proposal_height` watermark dedupes
    /// re-finalized blocks). A `checkpoint` or `truncate` supersedes
    /// buffered frames — the snapshot they carry is strictly newer.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Io`] if the buffered write or the
    /// extent-preallocation check fails.
    pub fn append_unsynced(&mut self, entry: &WalEntry) -> Result<(), WalError> {
        // Fault-injection latch (tests only): fail before touching
        // the file, the same outcome an ENOSPC write produces.
        if self.poisoned {
            return Err(WalError::Io(std::io::Error::other("WAL poisoned")));
        }
        let frame = frame_entry(entry)?;
        self.ensure_room(frame.len() as u64)?;
        self.writer.write_all(&frame)?;
        self.appended_end = self.appended_end.saturating_add(frame.len() as u64);
        self.bytes_since_checkpoint =
            self.bytes_since_checkpoint.saturating_add(frame.len() as u64);
        Ok(())
    }

    /// Make every buffered frame durable — the durability point the
    /// batching contract counts one-per-signature-emission.
    ///
    /// The `BufWriter` flush issues one `write(2)` for all buffered
    /// frames (or a few, if a frame exceeded the buffer and bypassed
    /// it): under Linux `O_DSYNC` that write IS the sync — data plus
    /// the file-size metadata land committed before it returns, with
    /// no second syscall. On macOS and other non-Linux targets the
    /// explicit `sync_data` retains the previous `F_FULLFSYNC`
    /// strength, which `O_DSYNC` does not imply there.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Io`] if the flush or fsync fails.
    fn sync(&mut self) -> Result<(), WalError> {
        self.writer.flush()?;
        #[cfg(not(target_os = "linux"))]
        self.writer.get_ref().sync_data()?;
        self.syncs = self.syncs.saturating_add(1);
        Ok(())
    }

    /// Extend the `fallocate`'d extent so `appended_end + need`
    /// stays inside mapped space — see "Synchronous durability".
    /// `FALLOC_FL_KEEP_SIZE` keeps the logical length honest, so
    /// recovery never scans reserved-but-unwritten zeros.
    ///
    /// A failure other than `EOPNOTSUPP`/`ENOSYS` (typically
    /// `ENOSPC`) propagates — surfacing a full disk at allocation
    /// time rather than mid-view is the point. Unsupported
    /// filesystems disable the hint and keep writing.
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)] // reviewed syscall wrapper — SAFETY note at the call site
    fn ensure_room(&mut self, need: u64) -> Result<(), WalError> {
        if !self.prealloc_ok || self.appended_end.saturating_add(need) <= self.allocated_end {
            return Ok(());
        }
        while self.appended_end.saturating_add(need) > self.allocated_end {
            // SAFETY: `fallocate` takes a borrowed fd — no ownership
            // or memory-safety contract; `offset`/`len` are plain
            // integers. The fd is valid: `self.writer` owns an open
            // `File` for the life of `self`.
            // The chunk is an 8 MiB constant — `try_from` (not a
            // wrapping cast) keeps the u64→off_t conversion checked.
            let len: libc::off_t =
                i64::try_from(PREALLOC_CHUNK_BYTES).unwrap_or(i64::MAX) as libc::off_t;
            let ret = unsafe {
                libc::fallocate(
                    self.writer.get_ref().as_raw_fd(),
                    libc::FALLOC_FL_KEEP_SIZE,
                    i64::try_from(self.allocated_end).unwrap_or(i64::MAX) as libc::off_t,
                    len,
                )
            };
            if ret == 0 {
                self.allocated_end = self.allocated_end.saturating_add(PREALLOC_CHUNK_BYTES);
                continue;
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EOPNOTSUPP | libc::ENOSYS) => {
                    self.prealloc_ok = false;
                    return Ok(());
                }
                _ => return Err(WalError::Io(err)),
            }
        }
        Ok(())
    }

    /// Non-Linux `ensure_room`: no `fallocate`, nothing to do —
    /// the write+`sync_data` path sizes itself per append. Kept
    /// as a `Result` stub so the call site stays platform-blind.
    #[cfg(not(target_os = "linux"))]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn ensure_room(&mut self, _need: u64) -> Result<(), WalError> {
        Ok(())
    }

    /// Number of durability points this `Wal` has issued.
    ///
    /// Test/bench instrumentation for the fsync-batching contract:
    /// the engine must issue exactly one per signature emission, so
    /// a happy-path view costs a voter one (its vote) and a leader
    /// two (proposal + self-vote). On Linux each is an `O_DSYNC`
    /// write, elsewhere a write+`sync_data` — same contract.
    #[doc(hidden)]
    pub fn sync_count(&self) -> u64 {
        self.syncs
    }

    /// Whether appended bytes since the last checkpoint have reached
    /// the compaction threshold. The engine checks this after each
    /// append; when true it calls [`checkpoint`](Self::checkpoint)
    /// with a full set-bearing snapshot.
    #[must_use]
    pub fn should_compact(&self) -> bool {
        self.bytes_since_checkpoint >= self.compact_after
    }

    /// Test hook: lower the compaction trigger so tests exercise the
    /// checkpoint path with a few entries instead of megabytes.
    #[doc(hidden)]
    pub fn set_compact_threshold(&mut self, bytes: u64) {
        self.compact_after = bytes;
    }

    /// Compact the WAL to a single checkpoint `entry`.
    ///
    /// The caller must pass a *complete* state snapshot with
    /// `validator_set` populated (`OxideBft::wal_entry(true)`): the
    /// checkpoint is the only record `recover` will see afterwards,
    /// so a set-less entry would lose the committed committee a
    /// post-rotation restart depends on.
    ///
    /// Durability: the frame is written to a sibling `.tmp` file and
    /// fsynced before an atomic `rename` over the WAL, followed by a
    /// directory fsync — a crash at any point leaves either the old
    /// WAL or the complete new one, never a torn replacement.
    ///
    /// # Errors
    ///
    /// Returns [`WalError::Io`] if any write, fsync, or rename fails.
    /// The engine treats this exactly like an append failure: the
    /// `wal_failed` latch trips and signing halts.
    pub fn checkpoint(&mut self, entry: &WalEntry) -> Result<(), WalError> {
        if self.poisoned {
            return Err(WalError::Io(std::io::Error::other("WAL poisoned")));
        }
        let frame = frame_entry(entry)?;
        // Buffered deferred frames die with the old writer — the
        // checkpoint snapshot strictly supersedes them, so dropping
        // the buffer loses nothing recoverable.
        atomic_replace(&self.path, &frame)?;
        // Reopen for appending — `rename` swapped the inode under the
        // old writer, which still points at the unlinked file.
        let file = open_wal_file(&self.path).map_err(WalError::Open)?;
        self.writer = BufWriter::new(file);
        self.bytes_since_checkpoint = frame.len() as u64;
        self.appended_end = frame.len() as u64;
        self.allocated_end = frame.len() as u64;
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
        let file = open_wal_file(&self.path).map_err(WalError::Open)?;
        file.set_len(0).map_err(WalError::Io)?;
        self.writer = BufWriter::new(file);
        self.bytes_since_checkpoint = 0;
        self.appended_end = 0;
        self.allocated_end = 0;
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
            timeout_signed_view: None,
            pending: Vec::new(),
            divergence: None,
            recent_signers: Vec::new(),
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
            timeout_signed_view: Some(View::new(5)),
            pending: Vec::new(),
            divergence: None,
            recent_signers: vec![vec![0b0111], vec![0b0111]],
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

    /// A minimal header for tail-persistence tests: only the fields
    /// that distinguish entries matter; the rest are fixed dummies.
    fn test_header(height: u64, prev: Hash) -> types::BlockHeader {
        types::BlockHeader {
            height: Height::new(height),
            view: View::new(height),
            epoch: Epoch::new(0),
            prev_block: prev,
            tx_root: Hash::ZERO,
            high_qc: None,
            timeout_cert: None,
            proposer: Hash::ZERO,
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
            body_hash: Hash::ZERO,
        }
    }

    /// The uncommitted tail must round-trip through the codec — a
    /// restart rebuilds `blocks` from exactly these bytes, so a
    /// codec skew would strand the recovered `high_qc`.
    #[test]
    fn wal_entry_pending_tail_roundtrip() {
        let mut entry = voted_entry();
        let h3 = test_header(3, Hash([0xBB; 32]));
        let h4 = test_header(4, Hash([0xCC; 32]));
        entry.pending = vec![
            (
                h3,
                Some(types::Proposal {
                    height: Height::new(3),
                    txs: vec![types::TxBytes::new(vec![1, 2, 3])],
                    attestation: None,
                }),
            ),
            // An `Awaiting` block persists header-only: `propose()`
            // resolves heights from the header, the body still lands
            // via `supply_body` after restart.
            (h4, None),
        ];
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = WalEntry::decode(&mut reader).unwrap();
        assert_eq!(entry, decoded);
    }

    /// Entries written before the pending tail existed must still
    /// decode — the tail is optional trailer #4, so a buffer that
    /// ends at the timeout-view flag decodes with an empty tail.
    /// This is the rolling-upgrade contract: an old WAL drives a
    /// node through block sync, never a decode failure.
    #[test]
    fn wal_entry_decodes_legacy_layout_without_tail() {
        let mut entry = voted_entry();
        entry.recent_signers.clear();
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        // Trailer #6 (signer window count) sits last, then trailer #5
        // (divergence flag, `0x00` when unset), then `pending` encodes
        // as a trailing varint count; each empty trailer is a single
        // `0x00`. Stripping all three yields exactly the pre-tail
        // byte layout.
        assert_eq!(buf.pop(), Some(0), "empty signer window encodes as one zero byte");
        assert_eq!(buf.pop(), Some(0), "unset divergence encodes as one zero byte");
        assert_eq!(buf.pop(), Some(0), "empty tail encodes as one zero byte");
        let mut reader = Reader::new(&buf);
        let decoded = WalEntry::decode(&mut reader).unwrap();
        assert!(decoded.pending.is_empty());
        assert!(decoded.divergence.is_none());
        assert!(decoded.recent_signers.is_empty());
        assert_eq!(decoded.timeout_signed_view, entry.timeout_signed_view);
        assert_eq!(decoded.last_committed, entry.last_committed);
    }

    /// A forged pending count must not drive allocation — the bound
    /// rejects counts the remaining bytes could never satisfy before
    /// the per-entry loop trusts them.
    #[test]
    fn wal_entry_pending_count_is_bounded() {
        let mut entry = voted_entry();
        entry.recent_signers.clear();
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        // Strip trailer #6's count, trailer #5's flag byte, and the
        // real tail count, then write the forged count followed by a
        // well-formed `None` divergence flag — the failure must come
        // from the pending bound, not a short buffer.
        buf.pop();
        buf.pop();
        buf.pop();
        codec::write::varint(&mut buf, 0xFFFF);
        buf.push(0);
        let mut reader = Reader::new(&buf);
        assert!(WalEntry::decode(&mut reader).is_err());
    }

    /// The divergence latch is durable safety state: it round-trips
    /// through the WAL so a restarted validator stays fail-closed
    /// rather than resuming signatures over diverged state.
    #[test]
    fn wal_entry_divergence_roundtrip() {
        let mut entry = voted_entry();
        entry.divergence = Some(types::ExecDivergence {
            height: Height::new(7),
            local_root: Hash([0x11; 32]),
            certified_root: Hash([0x22; 32]),
        });
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = WalEntry::decode(&mut reader).unwrap();
        assert_eq!(entry, decoded);
    }

    /// Entries written before the divergence trailer existed must
    /// still decode — a buffer that ends at the tail count decodes
    /// with `divergence: None` and an empty signer window (the
    /// rolling-upgrade contract).
    #[test]
    fn wal_entry_decodes_legacy_layout_without_divergence() {
        let mut entry = voted_entry();
        entry.recent_signers.clear();
        let mut buf = Vec::new();
        entry.encode(&mut buf);
        assert_eq!(buf.pop(), Some(0), "empty signer window encodes as one zero byte");
        assert_eq!(buf.pop(), Some(0), "unset divergence encodes as one zero byte");
        let mut reader = Reader::new(&buf);
        let decoded = WalEntry::decode(&mut reader).unwrap();
        assert!(decoded.divergence.is_none());
        assert!(decoded.recent_signers.is_empty());
        assert_eq!(decoded.pending, entry.pending);
    }

    /// Compaction rewrites the WAL as a single set-bearing frame:
    /// the file shrinks to the checkpoint's size, `recover` returns
    /// the checkpoint verbatim (set included — the merge-forward
    /// path has nothing older to merge), and the counter restarts.
    #[test]
    fn wal_checkpoint_compacts_file_and_preserves_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();
        wal.set_compact_threshold(1);

        wal.append(&genesis_entry()).unwrap();
        wal.append(&voted_entry()).unwrap();
        wal.append(&voted_entry()).unwrap();
        assert!(wal.should_compact(), "threshold=1 forces compaction after appends");

        let mut checkpoint = voted_entry();
        checkpoint.epoch = Epoch::new(2);
        checkpoint.validator_set = Some(test_set());
        wal.checkpoint(&checkpoint).unwrap();

        let size = std::fs::metadata(&path).unwrap().len();
        let mut frame = Vec::new();
        checkpoint.encode(&mut frame);
        assert_eq!(
            size,
            u64::try_from(frame.len()).unwrap() + 8,
            "the compacted WAL is exactly one framed entry"
        );
        assert_eq!(wal.recover().unwrap(), Some(checkpoint));
        // Counter restart: one entry's worth of bytes, far below the
        // test threshold's next trigger... at threshold 1 everything
        // triggers, so assert the counter tracks the checkpoint size.
        assert!(wal.should_compact(), "threshold=1 still wants the next compaction");
    }

    /// A checkpointed WAL reopens cleanly, keeps accepting appends,
    /// and recovery still returns the newest record — compaction is
    /// invisible to the format, only to the file size.
    #[test]
    fn wal_checkpoint_survives_reopen_and_appends() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.append(&genesis_entry()).unwrap();
            let mut checkpoint = voted_entry();
            checkpoint.validator_set = Some(test_set());
            wal.checkpoint(&checkpoint).unwrap();
            // Post-checkpoint append lands after the checkpoint and
            // must survive the reopen.
            wal.append(&voted_entry()).unwrap();
        }
        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap().expect("recovers");
        assert_eq!(recovered, {
            let mut expected = voted_entry();
            expected.validator_set = Some(test_set());
            expected
        });
    }

    /// A legacy WAL opened by the compaction-aware binary counts its
    /// existing bytes toward the threshold, so an oversized file from
    /// an older version compacts on the next append instead of
    /// growing forever.
    #[test]
    fn wal_open_seeds_compaction_counter_from_file_len() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        {
            let mut wal = Wal::open(&path).unwrap();
            wal.set_compact_threshold(u64::MAX); // never compact
            wal.append(&genesis_entry()).unwrap();
            wal.append(&voted_entry()).unwrap();
        }
        // Reopen with a tiny threshold: the existing bytes seed the
        // counter and trip compaction immediately.
        let mut wal = Wal::open(&path).unwrap();
        wal.set_compact_threshold(1);
        assert!(wal.should_compact());
    }

    /// `truncate` (the snapshot-supersede path) resets the counter —
    /// a fresh file must not inherit the pre-truncate byte debt.
    #[test]
    fn wal_truncate_resets_compaction_counter() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();
        wal.append(&voted_entry()).unwrap();
        wal.truncate().unwrap();
        wal.set_compact_threshold(u64::MAX);
        assert!(!wal.should_compact());
    }

    /// The deferred-batching contract under the folded fsync:
    /// `append_unsynced` frames buffer in userspace and ride the
    /// *same write* as the next signature-path `append` — one
    /// durability point covers all of them.
    #[test]
    fn wal_deferred_frames_ride_next_append() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();

        wal.append_unsynced(&genesis_entry()).unwrap();
        wal.append_unsynced(&voted_entry()).unwrap();
        // One signature-path append flushes both deferred frames
        // plus its own in a single write — one durability point.
        wal.append(&voted_entry()).unwrap();
        assert_eq!(wal.sync_count(), 1, "three frames, one durability point");

        drop(wal);
        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap().expect("frames must be durable");
        assert_eq!(recovered, voted_entry());
    }

    /// Buffered deferred frames are userspace-only until a
    /// signature-path append flushes them — a `mem::forget`
    /// (no `Drop`, so no flush) simulates the crash loss the
    /// contract documents: only synced state survives.
    #[test]
    fn wal_buffered_deferred_frames_lost_on_crash() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();

        wal.append(&genesis_entry()).unwrap();
        wal.append_unsynced(&voted_entry()).unwrap();
        // Forget skips `BufWriter::drop`'s best-effort flush — the
        // deferred frame never left userspace, matching a kill.
        std::mem::forget(wal);

        let wal = Wal::open(&path).unwrap();
        let recovered = wal.recover().unwrap().expect("synced entry survives");
        assert_eq!(recovered, genesis_entry(), "only the signature-path frame is durable");
    }

    /// On Linux the WAL preallocates extents ahead of the append
    /// position: allocated blocks meet or exceed the file's logical
    /// length while the length itself stays honest — recovery never
    /// scans reserved zeros.
    #[cfg(target_os = "linux")]
    #[test]
    fn wal_preallocates_extents() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("consensus.wal");
        let mut wal = Wal::open(&path).unwrap();

        wal.append(&genesis_entry()).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(
            meta.blocks() * 512 >= PREALLOC_CHUNK_BYTES.min(meta.len()),
            "allocated blocks should cover the file"
        );
        assert!(meta.len() < PREALLOC_CHUNK_BYTES, "KEEP_SIZE keeps the logical length honest");
        // And the reserved tail is never mistaken for frames.
        assert_eq!(wal.recover().unwrap(), Some(genesis_entry()));
    }
}
