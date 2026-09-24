//! Certified block sync — the fetch/serve half of validator
//! catch-up.
//!
//! A validator that misses proposals (partition, restart, slow
//! start) cannot finalize past the gap: `commit_walk` correctly
//! refuses to commit across a missing ancestor, and nothing else
//! puts the ancestor in place. This module is the missing piece.
//! Peers serve *finalized* blocks as [`CertifiedBlock`] records —
//! each carrying the full Jolteon two-chain commit proof — and the
//! receiver verifies the proof itself (`OxideBft::apply_certified_
//! block`), so a malicious or buggy peer can waste bandwidth but
//! cannot poison the chain.
//!
//! ## Wire protocol
//!
//! Two request kinds multiplexed on one tag pair:
//!
//! - `ByHash(hash)` — the requester knows the block's hash (a QC or
//!   a `prev_block` reference named it) but not its height.
//! - `ByRange { from, count }` — the requester needs the contiguous
//!   committed prefix starting at `from`.
//!
//! Responses carry the serving node's retention floor alongside the
//! records: a requester whose needed height is *below* every peer's
//! floor is beyond the block-sync window and must fall back to
//! certified state sync (the `statesync` snapshot path) — the floor
//! field is what makes that detection possible rather than an
//! endless retry loop.
//!
//! ## The serve store
//!
//! Committed records are journaled under `<data_dir>/certified-
//! journal/` (the same CRC-checked, height-indexed
//! [`storage::journal`] the executor's durability layer uses) so a
//! restarted validator can serve the history it finalized *before*
//! the crash — otherwise a fleet where every node restarted once
//! would have nothing to serve. Serving is strictly from this
//! certified store: uncommitted proposals are never answers, because
//! they carry no commit proof a receiver could check.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use codec::{Decode, Encode};
use primitives::Hash;
use storage::journal::{self, JournalConfig, JournalWriter};
use types::CertifiedBlock;

/// `MSG_BLOCK_REQ` request kind: fetch the certified block with this
/// hash (a QC's `block_hash` names a hash, not a height).
pub const REQ_BY_HASH: u8 = 0;
/// `MSG_BLOCK_REQ` request kind: fetch a contiguous certified range.
pub const REQ_BY_RANGE: u8 = 1;

/// Maximum records a single request asks for and a response carries.
///
/// Origin: a page must be large enough that a catch-up makes visible
/// progress per round trip (a partitioned node can be hundreds of
/// heights behind) and small enough that one response frame stays a
/// sane size — 128 records × a few hundred bytes of headers/QC each
/// (plus the block bodies) is a few hundred KiB worst case, well
/// under transport frame limits. Tradeoff: doubling it halves the
/// request count during deep catch-up but doubles the work a single
/// malicious request forces the server to serialize.
pub const SYNC_PAGE_CAP: u32 = 128;

/// Heights the serve store retains below the committed tip.
///
/// Origin: twice the executor checkpoint interval (4096). A peer
/// partitioned for less than a checkpoint interval can always
/// catch up block-by-block; beyond ~2× that window the certified
/// snapshot path (`statesync`) is the designed recovery — replaying
/// thousands of blocks is strictly slower than importing one
/// verified snapshot anyway. Tradeoff: every retained record is
/// ~1 KiB+ of journal disk per height; 8192 bounds the journal at
/// a few MiB of proof data (bodies dominate and are not optional).
pub const SERVE_RETAIN: u64 = 8192;

/// Journal directory inside the node's data dir — a sibling of the
/// executor's `block-journal` and `snapshot.bin`.
const JOURNAL_DIR_NAME: &str = "certified-journal";

/// How many inserts batch before the journal fsyncs. The serve store
/// is availability data, not safety state — a crash that loses the
/// unsynced tail just means this node serves a slightly shorter
/// prefix until it re-commits or re-fetches — so per-record fsyncs
/// would buy nothing correctness needs. 32 bounds the loss window
/// while keeping fsync-per-block bursts (bulk catch-up) cheap.
const SYNC_BATCH: u32 = 32;

/// A fetch request decoded from a `MSG_BLOCK_REQ` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchRequest {
    /// Fetch the certified block with this hash.
    ByHash(Hash),
    /// Fetch up to `count` contiguous certified blocks starting at
    /// `from` (inclusive).
    ByRange {
        /// First height wanted.
        from: u64,
        /// Page size requested — clamped to [`SYNC_PAGE_CAP`].
        count: u32,
    },
}

/// Encode a fetch request: `[kind][payload]`.
pub fn encode_request(req: &FetchRequest) -> Vec<u8> {
    match req {
        FetchRequest::ByHash(hash) => {
            let mut buf = Vec::with_capacity(1 + Hash::LEN);
            buf.push(REQ_BY_HASH);
            buf.extend_from_slice(hash.as_bytes());
            buf
        }
        FetchRequest::ByRange { from, count } => {
            let mut buf = Vec::with_capacity(1 + 8 + 4);
            buf.push(REQ_BY_RANGE);
            buf.extend_from_slice(&from.to_le_bytes());
            buf.extend_from_slice(&count.to_le_bytes());
            buf
        }
    }
}

/// Decode a fetch request body (the `MSG_BLOCK_REQ` tag is already
/// consumed). Returns `None` on any malformed input — a bad request
/// is ignored, never fatal.
pub fn decode_request(bytes: &[u8]) -> Option<FetchRequest> {
    let (&kind, rest) = bytes.split_first()?;
    match kind {
        REQ_BY_HASH => Some(FetchRequest::ByHash(Hash::from_slice(rest.get(..Hash::LEN)?).ok()?)),
        REQ_BY_RANGE => {
            let from = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
            let count = u32::from_le_bytes(rest.get(8..12)?.try_into().ok()?);
            Some(FetchRequest::ByRange { from, count })
        }
        _ => None,
    }
}

/// A decoded fetch response: the server's retention floor, the
/// certified records, and optionally one *notarized* tail block.
///
/// The tail covers the live edge a certified record cannot: a
/// `ByHash` request usually names the block a fresh QC certifies,
/// which is certified but NOT yet committed (its commit needs the
/// *grandchild's* QC). Serving the bare `(header, proposal)` lets
/// the requester authenticate it through `admit_proposal` — the
/// same verification any gossiped proposal gets — so its body lands
/// in the block store and the commit walk can run. Carrying it in
/// the same response keeps the wire at two tags.
pub struct FetchResponse {
    /// Lowest height the server retains (`u64::MAX` when empty) —
    /// the requester's beyond-window signal.
    pub floor: u64,
    /// Certified (committed) records, contiguous when range-served.
    pub records: Vec<CertifiedBlock>,
    /// A notarized-but-uncommitted block resolving a `ByHash` fetch.
    pub tail: Option<(types::BlockHeader, types::Proposal)>,
}

/// Encode a fetch response: `[floor][count]` then `count` records as
/// `[len][CertifiedBlock bytes]`, then `[has_tail][tail?]` where the
/// tail is a bare `header ++ proposal` encoding.
pub fn encode_response(resp: &FetchResponse) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + resp.records.len() * 600);
    buf.extend_from_slice(&resp.floor.to_le_bytes());
    buf.extend_from_slice(&u32::try_from(resp.records.len()).unwrap_or(u32::MAX).to_le_bytes());
    for record in &resp.records {
        let mut rec = Vec::with_capacity(600);
        record.encode(&mut rec);
        buf.extend_from_slice(&u32::try_from(rec.len()).unwrap_or(u32::MAX).to_le_bytes());
        buf.extend_from_slice(&rec);
    }
    if let Some((header, proposal)) = &resp.tail {
        buf.push(1);
        header.encode(&mut buf);
        proposal.encode(&mut buf);
    } else {
        buf.push(0);
    }
    buf
}

/// Decode a fetch response body (tag consumed). `None` on malformed
/// input. The record count is capped at [`SYNC_PAGE_CAP`] — a server
/// cannot inflate the buffer past what the protocol allows it to
/// send. A present tail must decode fully or the whole frame is
/// dropped.
pub fn decode_response(bytes: &[u8]) -> Option<FetchResponse> {
    let floor = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    let count = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
    if count > SYNC_PAGE_CAP {
        return None;
    }
    let mut records = Vec::with_capacity(count.min(16) as usize);
    let mut cursor = &bytes[12..];
    for _ in 0..count {
        let len = u32::from_le_bytes(cursor.get(..4)?.try_into().ok()?) as usize;
        let frame = cursor.get(4..4 + len)?;
        let mut reader = codec::Reader::new(frame);
        records.push(CertifiedBlock::decode(&mut reader).ok()?);
        cursor = &cursor[4 + len..];
    }
    let tail = match *cursor.first()? {
        0 => None,
        1 => {
            let mut reader = codec::Reader::new(&cursor[1..]);
            let header = types::BlockHeader::decode(&mut reader).ok()?;
            let proposal = types::Proposal::decode(&mut reader).ok()?;
            Some((header, proposal))
        }
        _ => return None,
    };
    Some(FetchResponse { floor, records, tail })
}

/// The durable serve store: every certified block this node has
/// finalized, journaled so a restart restores serving capability.
///
/// Writes go to the journal and the in-memory index together; reads
/// are always from the index. The journal is write-only until boot —
/// replay rebuilds the index — so a corrupt record fails replay
/// loudly rather than being served.
pub struct SyncStore {
    /// Certified records by height — the serving index.
    by_height: BTreeMap<u64, CertifiedBlock>,
    /// Block hash → height, for `ByHash` requests.
    by_hash: HashMap<Hash, u64>,
    /// The durable journal, when the node has a data dir.
    journal: Option<JournalWriter>,
    /// Journal dir (kept for replay/prune paths).
    journal_dir: Option<PathBuf>,
    /// Inserts since the last fsync — see [`SYNC_BATCH`].
    unsynced: u32,
}

impl SyncStore {
    /// Open (or create) the serve store rooted at `data_dir`.
    /// `None` runs in-memory only — serving still works but is lost
    /// on restart.
    ///
    /// Replay is deliberately tolerant at the *tail*: the journal's
    /// own recovery already discards a torn trailing record. A
    /// record that decodes but is structurally inconsistent is left
    /// in place — serving integrity is enforced by the *receiver's*
    /// verification, so the store does not re-verify what it
    /// journaled (self-authored, post-verification).
    pub fn open(data_dir: Option<&Path>) -> Self {
        let mut store = Self {
            by_height: BTreeMap::new(),
            by_hash: HashMap::new(),
            journal: None,
            journal_dir: None,
            unsynced: 0,
        };
        let Some(dir) = data_dir else { return store };
        let journal_dir = dir.join(JOURNAL_DIR_NAME);
        store.journal_dir = Some(journal_dir.clone());
        match journal::replay(&journal_dir) {
            Ok(replay) => {
                for rec in replay.records {
                    let mut reader = codec::Reader::new(&rec.payload);
                    match CertifiedBlock::decode(&mut reader) {
                        Ok(cb) => store.index(cb),
                        Err(e) => {
                            // A record that survived CRC but fails
                            // decode was written by an incompatible
                            // binary — drop it rather than serve
                            // bytes a peer cannot verify anyway.
                            eprintln!(
                                "block-sync: dropping undecodable certified record \
                                 during journal replay: {e}"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "block-sync: certified journal replay failed: {e} — serving starts empty"
                );
            }
        }
        // Bound the replayed window the same way live inserts do —
        // a long-lived node's journal must not restore more than it
        // would have served anyway.
        store.enforce_retention();
        match JournalWriter::create(&journal_dir, JournalConfig::default()) {
            Ok(writer) => store.journal = Some(writer),
            Err(e) => {
                eprintln!(
                    "block-sync: cannot open certified journal at {}: {e} — serving is memory-only until restart",
                    journal_dir.display()
                );
            }
        }
        store
    }

    /// Index a verified certified block (no journal write — internal
    /// step of both replay and live insert).
    fn index(&mut self, record: CertifiedBlock) {
        let height = record.header.height.value();
        if self.by_height.contains_key(&height) {
            return;
        }
        let hash = consensus::OxideBft::block_hash(&record.header);
        self.by_hash.insert(hash, height);
        self.by_height.insert(height, record);
    }

    /// Record a newly committed certified block: index it and append
    /// it to the journal (fsync per [`SYNC_BATCH`] batch). A journal
    /// error disables durable serving for the run — the index keeps
    /// working, so a dead disk degrades serving rather than halting
    /// the node.
    pub fn insert(&mut self, record: CertifiedBlock) {
        let height = record.header.height.value();
        if self.by_height.contains_key(&height) {
            return;
        }
        if let Some(writer) = &mut self.journal {
            let mut payload = Vec::with_capacity(600);
            record.encode(&mut payload);
            match writer.append_at_height(height, &payload) {
                Ok(_) => {
                    self.unsynced += 1;
                    if self.unsynced >= SYNC_BATCH {
                        if let Err(e) = writer.sync() {
                            eprintln!(
                                "block-sync: certified journal fsync failed: {e} — serving is memory-only"
                            );
                            self.journal = None;
                        }
                        self.unsynced = 0;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "block-sync: certified journal append failed: {e} — serving is memory-only"
                    );
                    self.journal = None;
                }
            }
        }
        self.index(record);
        self.enforce_retention();
    }

    /// Keep at most [`SERVE_RETAIN`] heights below the tip. In-memory
    /// entries drop first; the journal's sealed segments prune on the
    /// same watermark — a sealed segment whose records all sit below
    /// the floor is deleted, bounding disk use.
    fn enforce_retention(&mut self) {
        let Some(&tip) = self.by_height.keys().next_back() else { return };
        let floor = tip.saturating_sub(SERVE_RETAIN);
        while let Some(&h) = self.by_height.keys().next() {
            if h >= floor {
                break;
            }
            if let Some(rec) = self.by_height.remove(&h) {
                self.by_hash.remove(&consensus::OxideBft::block_hash(&rec.header));
            }
        }
        if let Some(writer) = &mut self.journal
            && let Err(e) = writer.prune_below_height(floor)
        {
            // Prune failure only means disk growth — still correct,
            // still servable; log and continue.
            eprintln!("block-sync: certified journal prune failed: {e}");
        }
    }

    /// The lowest height still servable — the floor field of every
    /// response. `None` when the store is empty.
    pub fn floor(&self) -> Option<u64> {
        self.by_height.keys().next().copied()
    }

    /// The certified record at `height`, if retained.
    pub fn get(&self, height: u64) -> Option<&CertifiedBlock> {
        self.by_height.get(&height)
    }

    /// The certified record with this block hash, if retained.
    pub fn get_by_hash(&self, hash: &Hash) -> Option<&CertifiedBlock> {
        self.by_hash.get(hash).and_then(|h| self.by_height.get(h))
    }

    /// The contiguous certified range starting at `from`, capped at
    /// `count` — stops at the first missing height (a hole can never
    /// be served as if it were contiguous history).
    pub fn range(&self, from: u64, count: u32) -> Vec<CertifiedBlock> {
        let mut out = Vec::new();
        let mut next = from;
        while u32::try_from(out.len()).unwrap_or(u32::MAX) < count.min(SYNC_PAGE_CAP) {
            let Some(rec) = self.by_height.get(&next) else { break };
            out.push(rec.clone());
            next = next.saturating_add(1);
        }
        out
    }

    /// Number of retained records (diagnostics/tests).
    pub fn len(&self) -> usize {
        self.by_height.len()
    }

    /// Whether the store holds nothing (diagnostics/tests).
    pub fn is_empty(&self) -> bool {
        self.by_height.is_empty()
    }

    /// Flush any batched journal appends — called on shutdown and
    /// opportunistically when the loop is idle.
    pub fn flush(&mut self) {
        if let Some(writer) = &mut self.journal {
            if let Err(e) = writer.sync() {
                eprintln!("block-sync: certified journal fsync failed: {e}");
                self.journal = None;
            }
            self.unsynced = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::{Epoch, Height, View};
    use types::{BlockHeader, Proposal, QuorumCertificate, TxBytes, VotePhase};

    /// A structurally valid record — the store indexes whatever it
    /// is given (verification is `apply_certified_block`'s job), so
    /// tests need shape, not signatures. `height`/`view` chain the
    /// record so hash-indexed lookups exercise real linkage.
    fn record(height: u64, view: u64, tag: u8) -> CertifiedBlock {
        let header = BlockHeader {
            height: Height::new(height),
            view: View::new(view),
            epoch: Epoch::new(0),
            prev_block: Hash([tag; 32]),
            tx_root: Hash([tag.wrapping_add(1); 32]),
            high_qc: None,
            timeout_cert: None,
            proposer: Hash([tag.wrapping_add(2); 32]),
            timestamp: 1_000 + height,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash([tag.wrapping_add(3); 32]),
        };
        let child = BlockHeader {
            height: Height::new(height + 1),
            view: View::new(view + 1),
            prev_block: consensus::OxideBft::block_hash(&header),
            high_qc: Some(QuorumCertificate {
                view: View::new(view),
                phase: VotePhase::Prepare,
                block_hash: consensus::OxideBft::block_hash(&header),
                epoch: Epoch::new(0),
                signer_bitmap: vec![0b111],
                aggregate_signature: crypto::AggregateSignature::ZERO,
            }),
            ..header.clone()
        };
        CertifiedBlock {
            header,
            proposal: Proposal {
                height: Height::new(height),
                txs: vec![TxBytes::new(vec![tag])],
                attestation: None,
            },
            qc: QuorumCertificate {
                view: View::new(view + 1),
                phase: VotePhase::Prepare,
                block_hash: consensus::OxideBft::block_hash(&child),
                epoch: Epoch::new(0),
                signer_bitmap: vec![0b111],
                aggregate_signature: crypto::AggregateSignature::ZERO,
            },
            child,
        }
    }

    #[test]
    fn request_codec_round_trips() {
        let req = FetchRequest::ByHash(Hash([7; 32]));
        assert_eq!(decode_request(&encode_request(&req)), Some(req));
        let req = FetchRequest::ByRange { from: 42, count: 16 };
        assert_eq!(decode_request(&encode_request(&req)), Some(req));
        // Malformed inputs are dropped, never fatal.
        assert_eq!(decode_request(&[]), None);
        assert_eq!(decode_request(&[0xEE, 1, 2, 3]), None);
        assert_eq!(decode_request(&[REQ_BY_HASH, 1, 2]), None);
        assert_eq!(decode_request(&[REQ_BY_RANGE, 1, 2, 3]), None);
    }

    #[test]
    fn response_codec_round_trips() {
        let resp =
            FetchResponse { floor: 5, records: vec![record(5, 5, 1), record(6, 6, 2)], tail: None };
        let decoded = decode_response(&encode_response(&resp)).expect("decodes");
        assert_eq!(decoded.floor, 5);
        assert_eq!(decoded.records, resp.records);
        assert!(decoded.tail.is_none());

        // With a notarized tail.
        let tail = (record(9, 9, 3).header, record(9, 9, 3).proposal);
        let resp = FetchResponse { floor: u64::MAX, records: Vec::new(), tail: Some(tail.clone()) };
        let decoded = decode_response(&encode_response(&resp)).expect("decodes with tail");
        assert_eq!(decoded.records.len(), 0);
        assert_eq!(decoded.tail, Some(tail));

        // Over-cap count is refused; truncated frames are dropped.
        let mut bad = encode_response(&FetchResponse {
            floor: 0,
            records: vec![record(0, 0, 9)],
            tail: None,
        });
        bad[8..12].copy_from_slice(&(SYNC_PAGE_CAP + 1).to_le_bytes());
        assert!(decode_response(&bad).is_none());
        let good = encode_response(&FetchResponse {
            floor: 0,
            records: vec![record(0, 0, 9)],
            tail: None,
        });
        assert!(decode_response(&good[..good.len() - 3]).is_none());
    }

    #[test]
    fn store_indexes_by_height_and_hash() {
        let mut store = SyncStore::open(None);
        let r5 = record(5, 5, 10);
        let r6 = record(6, 6, 11);
        store.insert(r5.clone());
        store.insert(r6.clone());
        assert_eq!(store.len(), 2);
        assert_eq!(store.floor(), Some(5));
        assert_eq!(store.get(5), Some(&r5));
        assert_eq!(store.get(7), None);
        let h5 = consensus::OxideBft::block_hash(&r5.header);
        assert_eq!(store.get_by_hash(&h5), Some(&r5));
        assert_eq!(store.get_by_hash(&Hash([0xEE; 32])), None);
        // Range stops at the first hole.
        assert_eq!(store.range(5, 8).len(), 2);
        assert_eq!(store.range(4, 8).len(), 0);
        // Idempotent insert.
        store.insert(r5.clone());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn journal_round_trip_restores_the_index() {
        let dir = std::env::temp_dir().join(format!("oxbs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        {
            let mut store = SyncStore::open(Some(&dir));
            store.insert(record(1, 1, 1));
            store.insert(record(2, 2, 2));
            store.insert(record(3, 3, 3));
            store.flush();
        }
        {
            let store = SyncStore::open(Some(&dir));
            assert_eq!(store.len(), 3, "replayed records must re-index");
            assert_eq!(store.floor(), Some(1));
            let h2 = consensus::OxideBft::block_hash(&record(2, 2, 2).header);
            assert!(store.get_by_hash(&h2).is_some(), "hash index survives replay");
            assert_eq!(store.range(1, 8).len(), 3);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_drops_below_the_window() {
        let mut store = SyncStore::open(None);
        // A small synthetic window: insert SERVE_RETAIN + margin.
        // Rather than 8k inserts, drive the tip forward with sparse
        // records — the floor is tip-relative, not count-relative.
        store.insert(record(0, 0, 1));
        store.insert(record(1, 1, 2));
        // Jump the tip past the retention window: h > SERVE_RETAIN
        // drops every record below tip - SERVE_RETAIN.
        store.insert(record(SERVE_RETAIN + 10, 9, 3));
        assert_eq!(
            store.floor(),
            Some(SERVE_RETAIN + 10),
            "sparse insert: only the tip remains above the floor"
        );
        assert!(store.get(0).is_none());
        assert_eq!(store.len(), 1);
    }
}
