//! The matcher's command log: what is journaled, how a checkpoint is
//! stored, and what recovery reports.
//!
//! ## What is journaled — engine operations, not requests
//!
//! The market worker journals the operation that is about to reach the
//! matching engine, AFTER admission: authentication, the nonce gate,
//! the risk check and the balance reservation have already decided
//! "yes". That placement is deliberate:
//!
//! * journal-before-apply holds — the record is appended before
//!   `engine.place_with_cap` / `engine.cancel` runs;
//! * replay needs no clock and no balances — a risk rejection that
//!   depended on the wall-clock rate limiter is never in the log, so
//!   replaying cannot reach a different verdict;
//! * amend and replace, which the worker implements as cancel +
//!   re-place, appear as exactly those two operations.
//!
//! A `Seal` record marks the moment the pending settlement batch was
//! handed to the settler. Replay discards fills up to the last seal
//! (they were already handed off) and keeps the fills after it as the
//! pending batch, so an unsealed batch survives a crash.
//!
//! ## Checkpoints
//!
//! A checkpoint is taken right after a `Seal`, when the pending batch
//! and the marginal-cost accumulator are empty by construction — the
//! state to persist is then just the engine's canonical state plus the
//! `book id → client id` map. Files are written `tmp + fsync + rename +
//! directory fsync` as `checkpoint-{seq:016}.snap` with a trailing
//! CRC-32C; recovery uses the newest valid one and falls back to older
//! ones, then to the empty book. See [`crate::journal`] for segment
//! rotation and truncation.
//!
//! ## What recovery does NOT restore
//!
//! Balances. The shared balance cache is chain-derived and owned by the
//! service; replay therefore never credits or debits it. The report
//! lists the quote reservations the recovered resting buys imply so the
//! service can re-apply them after it reloads balances.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::{OrderType, Side, TimeInForce};

use crate::journal::crc32c;

/// When a request's response may be released relative to the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AckPolicy {
    /// Respond as soon as the batch is applied; the journal is flushed
    /// to its I/O thread at the end of every batch so it becomes
    /// durable within one group commit. A crash can lose the batches
    /// acknowledged since the last completed `fsync` (see
    /// `JournalStats::lag`).
    #[default]
    Queued,
    /// Hold every response until the batch's last record is durable.
    /// No acknowledged order is ever lost; latency becomes one group
    /// commit (milliseconds) instead of microseconds.
    Durable,
}

/// Per-market journal settings.
#[derive(Debug, Clone)]
pub struct JournalConfig {
    /// Root directory; each market journals under `market-{id}/`.
    pub dir: PathBuf,
    /// When responses are released.
    pub ack: AckPolicy,
    /// Take a checkpoint at the next seal once this many records have
    /// been journaled since the last one (0 = never checkpoint).
    pub checkpoint_after_records: u64,
}

impl JournalConfig {
    /// Settings with the default [`AckPolicy::Queued`] and a checkpoint
    /// every 100 000 records.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into(), ack: AckPolicy::default(), checkpoint_after_records: 100_000 }
    }

    /// Directory of one market's journal and checkpoints.
    #[must_use]
    pub fn market_dir(&self, market: u16) -> PathBuf {
        self.dir.join(format!("market-{market}"))
    }
}

/// One journaled engine operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    /// An order reaching `place_with_cap`. `client_id` is the request
    /// nonce the worker binds to the resulting book id.
    Place {
        side: Side,
        order_type: OrderType,
        tif: TimeInForce,
        price: Price,
        qty: Qty,
        owner: Address,
        client_id: u64,
    },
    /// A cancel reaching `engine.cancel`.
    Cancel { order_id: u64 },
    /// The pending settlement batch was handed off.
    Seal,
}

const TAG_PLACE: u8 = 1;
const TAG_CANCEL: u8 = 2;
const TAG_SEAL: u8 = 3;

/// Encoded size of [`Op::Place`]: tag, side, type, tif, price, qty,
/// client id, owner.
const PLACE_LEN: usize = 1 + 1 + 1 + 1 + 8 + 8 + 8 + 20;

fn side_byte(s: Side) -> u8 {
    u8::from(s == Side::Sell)
}

fn otype_byte(t: OrderType) -> u8 {
    match t {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
    }
}

fn tif_byte(t: TimeInForce) -> u8 {
    match t {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    }
}

impl Op {
    /// Append this operation's encoding to `out`.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            Op::Place { side, order_type, tif, price, qty, owner, client_id } => {
                out.push(TAG_PLACE);
                out.push(side_byte(side));
                out.push(otype_byte(order_type));
                out.push(tif_byte(tif));
                out.extend_from_slice(&price.0.to_le_bytes());
                out.extend_from_slice(&qty.0.to_le_bytes());
                out.extend_from_slice(&client_id.to_le_bytes());
                out.extend_from_slice(&owner.0);
            }
            Op::Cancel { order_id } => {
                out.push(TAG_CANCEL);
                out.extend_from_slice(&order_id.to_le_bytes());
            }
            Op::Seal => out.push(TAG_SEAL),
        }
    }

    /// Decode one operation; `None` for anything malformed (a record
    /// that passed its checksum but is not ours is as bad as a torn
    /// one, so recovery treats it as corruption).
    pub(crate) fn decode(b: &[u8]) -> Option<Op> {
        let u64_at = |i: usize| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
        match *b.first()? {
            TAG_PLACE if b.len() == PLACE_LEN => Some(Op::Place {
                side: if b[1] == 0 {
                    Side::Buy
                } else if b[1] == 1 {
                    Side::Sell
                } else {
                    return None;
                },
                order_type: match b[2] {
                    0 => OrderType::Limit,
                    1 => OrderType::Market,
                    2 => OrderType::PostOnly,
                    _ => return None,
                },
                tif: match b[3] {
                    0 => TimeInForce::Gtc,
                    1 => TimeInForce::Ioc,
                    2 => TimeInForce::Fok,
                    _ => return None,
                },
                price: Price(u64_at(4)?),
                qty: Qty(u64_at(12)?),
                client_id: u64_at(20)?,
                owner: Address(b.get(28..48)?.try_into().ok()?),
            }),
            TAG_CANCEL if b.len() == 9 => Some(Op::Cancel { order_id: u64_at(1)? }),
            TAG_SEAL if b.len() == 1 => Some(Op::Seal),
            _ => None,
        }
    }
}

// ── Checkpoints ──────────────────────────────────────────────────────

const CKPT_MAGIC: &[u8; 8] = b"OXMCKPT1";

/// A decoded checkpoint.
pub(crate) struct Checkpoint {
    /// Last journal sequence the snapshot covers.
    pub(crate) seq: u64,
    /// `MatchingEngine::write_canonical_state` bytes.
    pub(crate) engine: Vec<u8>,
    /// `book order id → client id` for every resting order.
    pub(crate) client_ids: Vec<(u64, u64)>,
}

fn checkpoint_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("checkpoint-{seq:016}.snap"))
}

/// Checkpoint sequence numbers in `dir`, newest first.
fn checkpoint_seqs(dir: &Path) -> io::Result<Vec<u64>> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir)? {
        let name = e?.file_name();
        let name = name.to_string_lossy();
        if let Some(n) = name
            .strip_prefix("checkpoint-")
            .and_then(|r| r.strip_suffix(".snap"))
            .and_then(|r| r.parse::<u64>().ok())
        {
            v.push(n);
        }
    }
    v.sort_unstable_by(|a, b| b.cmp(a));
    Ok(v)
}

/// Durably write a checkpoint (tmp + fsync + rename + dir fsync) and
/// remove older ones.
pub(crate) fn write_checkpoint(dir: &Path, c: &Checkpoint) -> io::Result<()> {
    let mut buf = Vec::with_capacity(c.engine.len() + 64 + c.client_ids.len() * 16);
    buf.extend_from_slice(CKPT_MAGIC);
    buf.extend_from_slice(&c.seq.to_le_bytes());
    buf.extend_from_slice(&(c.engine.len() as u64).to_le_bytes());
    buf.extend_from_slice(&c.engine);
    buf.extend_from_slice(&(c.client_ids.len() as u64).to_le_bytes());
    for (id, client) in &c.client_ids {
        buf.extend_from_slice(&id.to_le_bytes());
        buf.extend_from_slice(&client.to_le_bytes());
    }
    let crc = crc32c(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());

    let tmp = dir.join("checkpoint.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(&buf)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, checkpoint_path(dir, c.seq))?;
    File::open(dir)?.sync_all()?;
    for old in checkpoint_seqs(dir)?.into_iter().filter(|s| *s < c.seq) {
        let _ = fs::remove_file(checkpoint_path(dir, old));
    }
    Ok(())
}

fn parse_checkpoint(bytes: &[u8]) -> Option<Checkpoint> {
    let (body, crc) = bytes.split_at(bytes.len().checked_sub(4)?);
    if crc32c(body) != u32::from_le_bytes(crc.try_into().ok()?) || body.get(..8)? != CKPT_MAGIC {
        return None;
    }
    let u64_at = |i: usize| Some(u64::from_le_bytes(body.get(i..i + 8)?.try_into().ok()?));
    let seq = u64_at(8)?;
    let elen = usize::try_from(u64_at(16)?).ok()?;
    let engine = body.get(24..24 + elen)?.to_vec();
    let mut at = 24 + elen;
    let n = usize::try_from(u64_at(at)?).ok()?;
    at += 8;
    // Bound by the bytes actually present — a corrupt count must not
    // drive an allocation.
    if body.len() != at.checked_add(n.checked_mul(16)?)? {
        return None;
    }
    let mut client_ids = Vec::with_capacity(n);
    for i in 0..n {
        client_ids.push((u64_at(at + i * 16)?, u64_at(at + i * 16 + 8)?));
    }
    Some(Checkpoint { seq, engine, client_ids })
}

/// The newest checkpoint that passes its checksum, if any. Corrupt
/// newer files are skipped (a crash during the rename window or bit
/// rot must degrade to an older snapshot plus a longer replay, never
/// to a failed start).
pub(crate) fn latest_checkpoint(dir: &Path) -> io::Result<Option<Checkpoint>> {
    for seq in checkpoint_seqs(dir)? {
        if let Ok(bytes) = fs::read(checkpoint_path(dir, seq))
            && let Some(c) = parse_checkpoint(&bytes)
            && c.seq == seq
        {
            return Ok(Some(c));
        }
    }
    Ok(None)
}

/// Re-debit the quote that recovered resting buys hold from a freshly
/// loaded balance cache, so recovered orders are backed exactly as the
/// live ones were (a later cancel refunds them, a fill pays out of
/// them). The cache must hold balances BEFORE reservations; a cache
/// that already nets them would be debited twice.
///
/// Returns `(market, owner, quote)` for every reservation the cache
/// could not cover (the debit is skipped, never partial); the caller
/// decides how loudly to report it.
pub fn reapply_reservations(
    balances: &crate::AtomicBalanceCache,
    reports: &[RecoveryReport],
) -> Vec<(u16, Address, u64)> {
    let mut failed = Vec::new();
    for r in reports {
        for (owner, quote) in &r.buy_reservations {
            if !balances.check_and_debit(owner, *quote) {
                failed.push((r.market, *owner, *quote));
            }
        }
    }
    failed
}

/// What a market worker found when it started from its journal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Market this report is for.
    pub market: u16,
    /// Sequence of the checkpoint recovery started from (0 = none).
    pub checkpoint_seq: u64,
    /// Operations replayed on top of it.
    pub replayed: u64,
    /// Last journal sequence recovered.
    pub last_seq: u64,
    /// Resting orders after recovery.
    pub resting: u32,
    /// Fills regenerated after the last seal — the pending batch that
    /// will be settled with the next one.
    pub pending_fills: usize,
    /// Quote reserved by recovered resting buys, `(owner, quote units)`
    /// (`⌊price × qty / PRICE_SCALE⌋` each, summed per owner): what the
    /// service must re-apply to a freshly loaded balance cache.
    pub buy_reservations: Vec<(Address, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place() -> Op {
        Op::Place {
            side: Side::Sell,
            order_type: OrderType::PostOnly,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(7_000),
            owner: Address([9; 20]),
            client_id: 42,
        }
    }

    #[test]
    fn ops_round_trip_and_reject_malformed() {
        for op in [place(), Op::Cancel { order_id: 99 }, Op::Seal] {
            let mut b = Vec::new();
            op.encode(&mut b);
            assert_eq!(Op::decode(&b), Some(op));
            // Every strict prefix and a trailing byte are malformed.
            for cut in 0..b.len() {
                assert_eq!(Op::decode(&b[..cut]), None, "{op:?} cut {cut}");
            }
            b.push(0);
            assert_eq!(Op::decode(&b), None);
        }
        let mut b = Vec::new();
        place().encode(&mut b);
        b[1] = 7; // bad side
        assert_eq!(Op::decode(&b), None);
    }

    #[test]
    fn checkpoint_round_trip_prunes_and_falls_back() {
        let dir = std::env::temp_dir().join(format!("oxide-ckpt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mk = |seq| Checkpoint {
            seq,
            engine: vec![1, 2, 3, u8::try_from(seq).unwrap()],
            client_ids: vec![(1, 2), (3, 4)],
        };
        write_checkpoint(&dir, &mk(10)).unwrap();
        write_checkpoint(&dir, &mk(20)).unwrap();
        assert_eq!(checkpoint_seqs(&dir).unwrap(), vec![20], "older checkpoint pruned");
        let c = latest_checkpoint(&dir).unwrap().unwrap();
        assert_eq!((c.seq, c.engine, c.client_ids), (20, vec![1, 2, 3, 20], vec![(1, 2), (3, 4)]));
        // A corrupt newest file falls back to the older one when present.
        write_checkpoint(&dir, &mk(30)).unwrap();
        fs::write(checkpoint_path(&dir, 25), b"garbage").unwrap();
        assert_eq!(latest_checkpoint(&dir).unwrap().unwrap().seq, 30);
        fs::write(checkpoint_path(&dir, 40), b"garbage").unwrap();
        assert_eq!(latest_checkpoint(&dir).unwrap().unwrap().seq, 30, "corrupt 40 skipped");
        fs::remove_dir_all(&dir).unwrap();
    }
}
