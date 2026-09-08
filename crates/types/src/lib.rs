//! Oxide Application Interface (OAI) data model.
//!
//! These are the types that cross the consensus ⇄ application boundary
//! defined in `docs/oai-spec.md`. They are deliberately *engine-agnostic*:
//! a [`BlockRecord`] is the same whether the block was finalized by
//! `oxideBFT`, the `MockEngine`, or any other engine — followers,
//! indexers, the journal, and RPC consume this shape, never an engine's
//! internal header format (oai-spec.md §1).
//!
//! # Determinism
//!
//! Every type implements [`codec::Encode`] / [`codec::Decode`], so the
//! consensus contract — two validators produce byte-identical encodings
//! of the same value — holds for the whole boundary. Wire forms are
//! pinned by unit tests in this crate and round-tripped by the codec
//! property tests.

use codec::{Decode, DecodeError, Encode, Reader, write};
use crypto::bls::{AggregateSignature, Signature};
use primitives::{Epoch, Hash, Height, View};

/// Read a length/count varint as `usize`. A varint larger than
/// `usize::MAX` (only possible on 32-bit targets) is surfaced as
/// `LengthPrefixTooLarge` — the same framing error the codec uses for
/// overlong byte strings — keeping the trust-boundary vocabulary uniform.
fn read_count(reader: &mut Reader<'_>) -> Result<usize, DecodeError> {
    let claimed = reader.read_varint()?;
    usize::try_from(claimed).map_err(|_| DecodeError::LengthPrefixTooLarge {
        claimed,
        remaining: reader.remaining() as u64,
    })
}

/// Opaque transaction bytes.
///
/// A `newtype` (not a bare `Vec<u8>`) so the type system distinguishes a
/// transaction payload from any other byte string crossing the boundary.
/// Engines treat these as opaque blobs; the application (executor) is
/// the only component that parses them (oai-spec.md §1, "engines order;
/// they never execute").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TxBytes(pub Vec<u8>);

impl TxBytes {
    /// Construct from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for TxBytes {
    fn encode(&self, buf: &mut Vec<u8>) {
        // Length-prefixed byte string: the codec's standard `bytes` form.
        write::bytes(buf, &self.0);
    }
}

impl<'a> Decode<'a> for TxBytes {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(TxBytes(reader.read_bytes()?.to_vec()))
    }
}

/// A proposal's size envelope. Engines respect both bounds when
/// assembling proposals; the application enforces them again in
/// `process_proposal` (defense in depth — a faulty leader could lie).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockBudget {
    /// Maximum total serialized size of the proposal's transactions, in
    /// bytes. Bounds mempool selection and wire framing.
    pub max_bytes: u64,
    /// Maximum cumulative gas the proposal's transactions may consume.
    /// EVM-equivalent execution budgets are denominated in gas (plan.md
    /// §3, "gigagas capacity").
    pub max_gas: u64,
}

impl Encode for BlockBudget {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u64(buf, self.max_bytes);
        write::u64(buf, self.max_gas);
    }
}

impl<'a> Decode<'a> for BlockBudget {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let max_bytes = reader.read_u64()?;
        let max_gas = reader.read_u64()?;
        Ok(Self { max_bytes, max_gas })
    }
}

/// A leader's proposed block: the height it finalizes at, the ordered
/// transactions, and an optional post-execution attestation from the
/// previous block (oai-spec.md §4).
///
/// The attestation is opaque to the engine — it embeds it verbatim and
/// never parses it (oai-spec.md §3, rule 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The height this proposal would finalize.
    pub height: Height,
    /// Ordered transaction bytes. Order is part of consensus output.
    pub txs: Vec<TxBytes>,
    /// Optional attestation bytes carried from the prior block's
    /// execution. `None` at genesis or before the first execution
    /// attestation is available.
    pub attestation: Option<Vec<u8>>,
}

impl Encode for Proposal {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        // Transaction count as a varint, then each tx length-prefixed.
        write::varint(buf, self.txs.len() as u64);
        for tx in &self.txs {
            tx.encode(buf);
        }
        match &self.attestation {
            Some(att) => {
                write::bool(buf, true);
                write::bytes(buf, att);
            }
            None => write::bool(buf, false),
        }
    }
}

impl<'a> Decode<'a> for Proposal {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let height = Height::decode(reader)?;
        let count = read_count(reader)?;
        let mut txs = Vec::with_capacity(count);
        for _ in 0..count {
            txs.push(TxBytes::decode(reader)?);
        }
        let attestation =
            if reader.read_bool()? { Some(reader.read_bytes()?.to_vec()) } else { None };
        Ok(Self { height, txs, attestation })
    }
}

/// An application's verdict on a proposal: accept, or reject with a
/// static reason string. Rejection is a *protocol message* (the proposal
/// is invalid on its face — too large, bad nonce shape, missing fee),
/// never an execution result — engines must accept proposals that
/// would revert on execution (oai-spec.md §3, rule 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The proposal passes static validity.
    Accept,
    /// The proposal fails static validity. `reason` is a short static
    /// string in v0 (no allocation pressure — rejection is the cold
    /// path).
    Reject {
        /// Why the proposal was rejected. Human-readable; not parsed.
        reason: String,
    },
}

impl Encode for Verdict {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Verdict::Accept => write::u8(buf, 0),
            Verdict::Reject { reason } => {
                write::u8(buf, 1);
                write::bytes(buf, reason.as_bytes());
            }
        }
    }
}

impl<'a> Decode<'a> for Verdict {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        match reader.read_u8()? {
            0 => Ok(Verdict::Accept),
            1 => {
                let bytes = reader.read_bytes()?;
                let reason =
                    String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::InvalidUtf8)?;
                Ok(Verdict::Reject { reason })
            }
            other => Err(DecodeError::InvalidBool { got: other }),
        }
    }
}

/// Mempool intake result: accepted, or rejected with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolAck {
    /// The transaction was admitted to the mempool.
    Accepted,
    /// The transaction was rejected (duplicate, too large, low fee).
    Rejected {
        /// Why the transaction was rejected. Human-readable; not parsed.
        reason: String,
    },
}

impl Encode for MempoolAck {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            MempoolAck::Accepted => write::u8(buf, 0),
            MempoolAck::Rejected { reason } => {
                write::u8(buf, 1);
                write::bytes(buf, reason.as_bytes());
            }
        }
    }
}

impl<'a> Decode<'a> for MempoolAck {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        match reader.read_u8()? {
            0 => Ok(MempoolAck::Accepted),
            1 => {
                let bytes = reader.read_bytes()?;
                let reason =
                    String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::InvalidUtf8)?;
                Ok(MempoolAck::Rejected { reason })
            }
            other => Err(DecodeError::InvalidBool { got: other }),
        }
    }
}

/// The engine's whole output: a finalized, reorg-free ordering of
/// transactions at a height. After this is emitted the engine never
/// re-emits this height and never finalizes a different block here
/// (oai-spec.md §3, rule 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedBlock {
    /// The finalized height.
    pub height: Height,
    /// The ordered transactions. This is the complete consensus output;
    /// execution happens downstream.
    pub txs: Vec<TxBytes>,
}

impl Encode for FinalizedBlock {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        write::varint(buf, self.txs.len() as u64);
        for tx in &self.txs {
            tx.encode(buf);
        }
    }
}

impl<'a> Decode<'a> for FinalizedBlock {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let height = Height::decode(reader)?;
        let count = read_count(reader)?;
        let mut txs = Vec::with_capacity(count);
        for _ in 0..count {
            txs.push(TxBytes::decode(reader)?);
        }
        Ok(Self { height, txs })
    }
}

/// The application's reception assertion for a finalized block. Returned
/// from `finalize_block`; asserts reception, *not* execution (execution
/// is async by design — oai-spec.md §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitAck {
    /// The height whose block was received for execution.
    pub height: Height,
}

impl Encode for CommitAck {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
    }
}

impl<'a> Decode<'a> for CommitAck {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Self { height: Height::decode(reader)? })
    }
}

/// Post-execution state commitment, embedded verbatim in the next
/// proposal. Opaque to the engine; the application is the only
/// interpreter (oai-spec.md §3, rule 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateAttestation {
    /// The height whose execution produced this root.
    pub height: Height,
    /// The state root after executing the block at `height`.
    pub root: Hash,
}

impl Encode for StateAttestation {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        self.root.encode(buf);
    }
}

impl<'a> Decode<'a> for StateAttestation {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Self { height: Height::decode(reader)?, root: Hash::decode(reader)? })
    }
}

/// The engine-agnostic canonical ledger entry. This is what followers,
/// indexers, the journal, and RPC consume — *never* an engine's
/// internal header (oai-spec.md §1). Chained by `prev` into a hash
/// chain rooted at genesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRecord {
    /// The height of this block.
    pub height: Height,
    /// Hash of the previous `BlockRecord`. All-zero at genesis.
    pub prev: Hash,
    /// Merkle root of the block's transactions (ordered).
    pub tx_root: Hash,
    /// Optional post-execution attestation carried with this block.
    pub attestation: Option<StateAttestation>,
}

impl Encode for BlockRecord {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        self.prev.encode(buf);
        self.tx_root.encode(buf);
        match &self.attestation {
            Some(att) => {
                write::bool(buf, true);
                att.encode(buf);
            }
            None => write::bool(buf, false),
        }
    }
}

impl<'a> Decode<'a> for BlockRecord {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let height = Height::decode(reader)?;
        let prev = Hash::decode(reader)?;
        let tx_root = Hash::decode(reader)?;
        let attestation =
            if reader.read_bool()? { Some(StateAttestation::decode(reader)?) } else { None };
        Ok(Self { height, prev, tx_root, attestation })
    }
}

// ─── oxideBFT consensus types ──────────────────────────────────────
//
// These are the *engine-internal* message types that oxideBFT validators
// exchange (docs/oxidebft-spec.md §2-4). They do NOT cross the OAI
// boundary — the application never sees a Vote or QC; it only sees the
// finalized ordering via `FinalizedBlock`. They live in `types` (not a
// `consensus` crate) because their wire forms are part of the consensus
// contract (byte-identical encodings across validators) and the codec
// round-trip property must hold for them.
//
// Phase 1 stage 1 (oxideBFT spec §8): types + codec only. The pacemaker,
// vote pipeline, and BLS sign/verify land in stages 2-5.

/// The phase of a `HotStuff` vote within the 2-chain pipeline
/// (docs/oxidebft-spec.md §2).
///
/// - `Prepare` — the leader proposed a block; validators sign a
///   prepare vote once they have the parent's pre-commit QC.
/// - `PreCommit` — a prepare QC formed for this height; validators
///   sign a pre-commit vote (the "lock").
/// - `Commit` — a pre-commit QC formed; validators sign a commit
///   vote. A commit QC is finality.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VotePhase {
    /// Prepare phase (first chain link).
    Prepare = 0,
    /// Pre-commit phase (the lock).
    PreCommit = 1,
    /// Commit phase (finality).
    Commit = 2,
}

impl VotePhase {
    /// Decode from a single byte; rejects unknown discriminants.
    fn from_byte(b: u8) -> Result<Self, DecodeError> {
        match b {
            0 => Ok(Self::Prepare),
            1 => Ok(Self::PreCommit),
            2 => Ok(Self::Commit),
            other => Err(DecodeError::InvalidBool { got: other }),
        }
    }
}

/// A single validator's vote in the 2-chain pipeline
/// (docs/oxidebft-spec.md §3).
///
/// The vote signs `(view, phase, block_hash)` with the validator's BLS
/// secret key. The signature is domain-separated (`crypto::Domain::Vote`)
/// so a prepare vote can never be confused with a pre-commit or commit
/// vote, even if the block hash happens to be identical.
///
/// Wire form (pinned by `vote_wire` test):
/// ```text
/// [view u64 LE][phase u8][block_hash 32B][signature 96B]
/// ```
/// Total: 137 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    /// The view this vote is cast in.
    pub view: View,
    /// The pipeline phase (prepare / pre-commit / commit).
    pub phase: VotePhase,
    /// The block being voted on.
    pub block_hash: Hash,
    /// The validator's BLS signature over `(view, phase, block_hash)`.
    pub signature: Signature,
}

impl Encode for Vote {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.view.encode(buf);
        buf.push(self.phase as u8);
        self.block_hash.encode(buf);
        self.signature.encode(buf);
    }
}

impl<'a> Decode<'a> for Vote {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let view = View::decode(reader)?;
        let phase = VotePhase::from_byte(reader.read_u8()?)?;
        let block_hash = Hash::decode(reader)?;
        let signature = Signature::decode(reader)?;
        Ok(Self { view, phase, block_hash, signature })
    }
}

/// A quorum certificate: the aggregate of ≥2f+1 votes for a single
/// `(view, phase, block_hash)` (docs/oxidebft-spec.md §3).
///
/// The QC carries the aggregate BLS signature (one group element,
/// regardless of validator count) and a bitmap identifying which
/// validators signed. Verification (Phase 1 stage 5) is a single
/// aggregate check against the signers' aggregate public key — this
/// is the throughput lever that keeps the consensus hot path off the
/// floor.
///
/// Wire form (pinned by `quorum_certificate_wire` test):
/// ```text
/// [view u64 LE][phase u8][block_hash 32B][epoch u64 LE]
/// [signer_bitmap_len varint][signer_bitmap bytes]
/// [aggregate_signature 96B]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate {
    /// The view the QC was formed in.
    pub view: View,
    /// The pipeline phase of the votes aggregated.
    pub phase: VotePhase,
    /// The block the QC certifies.
    pub block_hash: Hash,
    /// The epoch the QC belongs to (for validator-set lookup).
    pub epoch: Epoch,
    /// Bitmap of which validators signed (index into the epoch's
    /// validator set). A `1` bit at position *i* means validator *i*
    /// signed. The bitmap's length is the validator set size (rounded
    /// up to the next byte).
    pub signer_bitmap: Vec<u8>,
    /// The aggregate BLS signature over all signers' votes.
    pub aggregate_signature: AggregateSignature,
}

impl Encode for QuorumCertificate {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.view.encode(buf);
        buf.push(self.phase as u8);
        self.block_hash.encode(buf);
        self.epoch.encode(buf);
        write::bytes(buf, &self.signer_bitmap);
        self.aggregate_signature.encode(buf);
    }
}

impl<'a> Decode<'a> for QuorumCertificate {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let view = View::decode(reader)?;
        let phase = VotePhase::from_byte(reader.read_u8()?)?;
        let block_hash = Hash::decode(reader)?;
        let epoch = Epoch::decode(reader)?;
        let signer_bitmap = reader.read_bytes()?.to_vec();
        let aggregate_signature = AggregateSignature::decode(reader)?;
        Ok(Self { view, phase, block_hash, epoch, signer_bitmap, aggregate_signature })
    }
}

/// A timeout certificate: ≥2f+1 validators signed a timeout for view
/// `v`, proving the view should advance (docs/oxidebft-spec.md §4).
///
/// The TC is the "force a view change without the leader" mechanism —
/// tail-fork resistance. The next leader (view *v+1*) embeds the TC in
/// its proposal, proving it is the legitimate successor.
///
/// Wire form (pinned by `timeout_certificate_wire` test):
/// ```text
/// [view u64 LE][epoch u64 LE]
/// [signer_bitmap_len varint][signer_bitmap bytes]
/// [aggregate_signature 96B]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutCertificate {
    /// The view that timed out.
    pub view: View,
    /// The epoch the TC belongs to.
    pub epoch: Epoch,
    /// Bitmap of which validators signed the timeout.
    pub signer_bitmap: Vec<u8>,
    /// Aggregate BLS signature over the timeout messages.
    pub aggregate_signature: AggregateSignature,
}

impl Encode for TimeoutCertificate {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.view.encode(buf);
        self.epoch.encode(buf);
        write::bytes(buf, &self.signer_bitmap);
        self.aggregate_signature.encode(buf);
    }
}

impl<'a> Decode<'a> for TimeoutCertificate {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let view = View::decode(reader)?;
        let epoch = Epoch::decode(reader)?;
        let signer_bitmap = reader.read_bytes()?.to_vec();
        let aggregate_signature = AggregateSignature::decode(reader)?;
        Ok(Self { view, epoch, signer_bitmap, aggregate_signature })
    }
}

/// A consensus block header — the engine-internal header format that
/// oxideBFT validators agree on (docs/oxidebft-spec.md §2, plan.md §4).
///
/// This is distinct from [`BlockRecord`] (the engine-agnostic ledger
/// entry): the `BlockHeader` carries consensus-specific fields (view,
/// epoch, QC, proposer) that the OAI boundary strips away. Followers
/// and indexers consume `BlockRecord`, never `BlockHeader`.
///
/// Wire form (pinned by `block_header_wire` test):
/// ```text
/// [height u64 LE][view u64 LE][epoch u64 LE]
/// [prev_block 32B][tx_root 32B]
/// [has_qc u8][qc ... if present]
/// [has_tc u8][tc ... if present]
/// [proposer 32B][timestamp u64 LE]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// The block's height in the chain.
    pub height: Height,
    /// The view this block was proposed in.
    pub view: View,
    /// The epoch this block belongs to.
    pub epoch: Epoch,
    /// Hash of the previous block (`Hash::ZERO` at genesis).
    pub prev_block: Hash,
    /// Merkle root of the block's transactions.
    pub tx_root: Hash,
    /// The highest QC the leader knew when proposing (embedded in the
    /// proposal to advance the pipeline). `None` for genesis.
    pub high_qc: Option<QuorumCertificate>,
    /// A timeout certificate justifying the view change that led to
    /// this block (if the block starts a new view due to a timeout).
    /// `None` in the happy path (no view change).
    pub timeout_cert: Option<TimeoutCertificate>,
    /// The proposer's public key hash (identifies the leader).
    pub proposer: Hash,
    /// Proposal timestamp in milliseconds since Unix epoch.
    pub timestamp: u64,
}

impl Encode for BlockHeader {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        self.view.encode(buf);
        self.epoch.encode(buf);
        self.prev_block.encode(buf);
        self.tx_root.encode(buf);
        match &self.high_qc {
            Some(qc) => {
                write::bool(buf, true);
                qc.encode(buf);
            }
            None => write::bool(buf, false),
        }
        match &self.timeout_cert {
            Some(tc) => {
                write::bool(buf, true);
                tc.encode(buf);
            }
            None => write::bool(buf, false),
        }
        self.proposer.encode(buf);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
    }
}

impl<'a> Decode<'a> for BlockHeader {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let height = Height::decode(reader)?;
        let view = View::decode(reader)?;
        let epoch = Epoch::decode(reader)?;
        let prev_block = Hash::decode(reader)?;
        let tx_root = Hash::decode(reader)?;
        let high_qc =
            if reader.read_bool()? { Some(QuorumCertificate::decode(reader)?) } else { None };
        let timeout_cert =
            if reader.read_bool()? { Some(TimeoutCertificate::decode(reader)?) } else { None };
        let proposer = Hash::decode(reader)?;
        let timestamp = reader.read_u64()?;
        Ok(Self {
            height,
            view,
            epoch,
            prev_block,
            tx_root,
            high_qc,
            timeout_cert,
            proposer,
            timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Wire-form pinning + round-trip for every OAI type. The codec's
    //! own property tests cover arbitrary-value round-trip; these tests
    //! pin the *exact bytes* so a wire-format change is caught here, not
    //! only by a downstream consensus fork.

    use super::*;
    use codec::{Codec, Reader};
    use primitives::Hash;

    fn roundtrip<T>(value: &T, wire: &[u8])
    where
        T: for<'a> Codec<'a> + PartialEq + std::fmt::Debug + Clone,
    {
        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(buf, wire, "wire form mismatch");
        let mut r = Reader::new(&buf);
        let decoded = T::decode(&mut r).expect("decode");
        assert_eq!(&decoded, value, "round-trip");
        assert!(r.is_empty(), "decode must consume exactly its bytes");
    }

    #[test]
    fn tx_bytes_wire() {
        roundtrip(&TxBytes(vec![0xde, 0xad]), &[2, 0xde, 0xad]);
    }

    #[test]
    fn block_budget_wire() {
        let b = BlockBudget { max_bytes: 1, max_gas: 2 };
        roundtrip(&b, &[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn proposal_wire_no_attestation() {
        // height 5, two txs ([0xaa], [0xbb, 0xcc]), no attestation.
        let p = Proposal {
            height: Height::new(5),
            txs: vec![TxBytes(vec![0xaa]), TxBytes(vec![0xbb, 0xcc])],
            attestation: None,
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&5u64.to_le_bytes()); // height
        expected.push(2); // tx count
        expected.extend_from_slice(&[1, 0xaa]); // tx 0
        expected.extend_from_slice(&[2, 0xbb, 0xcc]); // tx 1
        expected.push(0); // no attestation
        roundtrip(&p, &expected);
    }

    #[test]
    fn verdict_wire() {
        roundtrip(&Verdict::Accept, &[0]);
        let reject = Verdict::Reject { reason: "too large".to_string() };
        roundtrip(&reject, &[1, 9, b't', b'o', b'o', b' ', b'l', b'a', b'r', b'g', b'e']);
    }

    #[test]
    fn mempool_ack_wire() {
        roundtrip(&MempoolAck::Accepted, &[0]);
    }

    #[test]
    fn finalized_block_wire() {
        let fb = FinalizedBlock { height: Height::new(7), txs: vec![TxBytes(vec![0x01])] };
        let mut expected = Vec::new();
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.push(1); // tx count
        expected.extend_from_slice(&[1, 0x01]); // tx
        roundtrip(&fb, &expected);
    }

    #[test]
    fn commit_ack_wire() {
        roundtrip(&CommitAck { height: Height::new(3) }, &3u64.to_le_bytes());
    }

    #[test]
    fn state_attestation_wire() {
        let att = StateAttestation { height: Height::new(9), root: Hash([0x42; 32]) };
        let mut expected = Vec::new();
        expected.extend_from_slice(&9u64.to_le_bytes());
        expected.extend_from_slice(&[0x42; 32]);
        roundtrip(&att, &expected);
    }

    #[test]
    fn block_record_wire_with_attestation() {
        let rec = BlockRecord {
            height: Height::new(1),
            prev: Hash([0; 32]),
            tx_root: Hash([0xff; 32]),
            attestation: Some(StateAttestation { height: Height::new(0), root: Hash([0x11; 32]) }),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&1u64.to_le_bytes()); // height
        expected.extend_from_slice(&[0; 32]); // prev
        expected.extend_from_slice(&[0xff; 32]); // tx_root
        expected.push(1); // attestation present
        expected.extend_from_slice(&0u64.to_le_bytes()); // att height
        expected.extend_from_slice(&[0x11; 32]); // att root
        roundtrip(&rec, &expected);
    }

    #[test]
    fn block_record_wire_no_attestation() {
        let rec = BlockRecord {
            height: Height::new(0),
            prev: Hash([0; 32]),
            tx_root: Hash([0; 32]),
            attestation: None,
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&0u64.to_le_bytes());
        expected.extend_from_slice(&[0; 32]);
        expected.extend_from_slice(&[0; 32]);
        expected.push(0);
        roundtrip(&rec, &expected);
    }

    /// Rejecting non-UTF-8 reason bytes keeps consensus honest: a peer
    /// cannot inject an unparseable reason that round-trips lossily.
    #[test]
    fn verdict_rejects_non_utf8_reason() {
        let bad = [1u8, 2, 0xff, 0xfe];
        let mut r = Reader::new(&bad);
        assert!(Verdict::decode(&mut r).is_err());
    }

    // ─── oxideBFT consensus type wire forms ──────────────────────

    #[test]
    fn vote_wire() {
        let vote = Vote {
            view: View::new(7),
            phase: VotePhase::PreCommit,
            block_hash: Hash([0xAB; 32]),
            signature: Signature([0xCD; 96]),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&7u64.to_le_bytes()); // view
        expected.push(1); // phase = PreCommit
        expected.extend_from_slice(&[0xAB; 32]); // block_hash
        expected.extend_from_slice(&[0xCD; 96]); // signature
        roundtrip(&vote, &expected);
    }

    #[test]
    fn vote_phase_discriminants() {
        // Pin the phase byte to the variant discriminant — part of the
        // wire consensus contract.
        assert_eq!(VotePhase::Prepare as u8, 0);
        assert_eq!(VotePhase::PreCommit as u8, 1);
        assert_eq!(VotePhase::Commit as u8, 2);
    }

    #[test]
    fn vote_rejects_unknown_phase() {
        // A byte that is not 0/1/2 must be rejected, not silently
        // mapped to a default.
        let mut bad = Vec::new();
        bad.extend_from_slice(&0u64.to_le_bytes()); // view
        bad.push(99); // invalid phase
        bad.extend_from_slice(&[0; 32]); // block_hash
        bad.extend_from_slice(&[0; 96]); // signature
        let mut r = Reader::new(&bad);
        assert!(Vote::decode(&mut r).is_err());
    }

    #[test]
    fn quorum_certificate_wire() {
        let qc = QuorumCertificate {
            view: View::new(5),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x11; 32]),
            epoch: Epoch::new(1),
            signer_bitmap: vec![0b0000_0011], // 2 signers
            aggregate_signature: AggregateSignature([0x22; 96]),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&5u64.to_le_bytes()); // view
        expected.push(0); // phase = Prepare
        expected.extend_from_slice(&[0x11; 32]); // block_hash
        expected.extend_from_slice(&1u64.to_le_bytes()); // epoch
        // signer_bitmap: varint length (1) + 1 byte
        expected.push(1);
        expected.push(0b0000_0011);
        expected.extend_from_slice(&[0x22; 96]); // aggregate_signature
        roundtrip(&qc, &expected);
    }

    #[test]
    fn timeout_certificate_wire() {
        let tc = TimeoutCertificate {
            view: View::new(3),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b1111_1111, 0b0000_0001], // 9 signers
            aggregate_signature: AggregateSignature([0x33; 96]),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&3u64.to_le_bytes()); // view
        expected.extend_from_slice(&0u64.to_le_bytes()); // epoch
        // signer_bitmap: varint length (2) + 2 bytes
        expected.push(2);
        expected.push(0b1111_1111);
        expected.push(0b0000_0001);
        expected.extend_from_slice(&[0x33; 96]); // aggregate_signature
        roundtrip(&tc, &expected);
    }

    #[test]
    fn block_header_wire_genesis_no_qc_no_tc() {
        // Genesis block: no parent QC, no timeout cert.
        let header = BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            tx_root: Hash([0xFF; 32]),
            high_qc: None,
            timeout_cert: None,
            proposer: Hash([0x42; 32]),
            timestamp: 1000,
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&0u64.to_le_bytes()); // height
        expected.extend_from_slice(&0u64.to_le_bytes()); // view
        expected.extend_from_slice(&0u64.to_le_bytes()); // epoch
        expected.extend_from_slice(&[0; 32]); // prev_block
        expected.extend_from_slice(&[0xFF; 32]); // tx_root
        expected.push(0); // no high_qc
        expected.push(0); // no timeout_cert
        expected.extend_from_slice(&[0x42; 32]); // proposer
        expected.extend_from_slice(&1000u64.to_le_bytes()); // timestamp
        roundtrip(&header, &expected);
    }

    #[test]
    fn block_header_wire_with_qc() {
        // A non-genesis block carrying a high QC.
        let qc = QuorumCertificate {
            view: View::new(4),
            phase: VotePhase::PreCommit,
            block_hash: Hash([0x55; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: AggregateSignature([0x66; 96]),
        };
        let header = BlockHeader {
            height: Height::new(1),
            view: View::new(5),
            epoch: Epoch::new(0),
            prev_block: Hash([0xAA; 32]),
            tx_root: Hash([0xBB; 32]),
            high_qc: Some(qc),
            timeout_cert: None,
            proposer: Hash([0x42; 32]),
            timestamp: 2000,
        };
        // Encode + round-trip (the QC makes the full wire form long;
        // roundtrip checks both encode-match and decode-match).
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let mut r = Reader::new(&buf);
        let decoded = BlockHeader::decode(&mut r).expect("decode");
        assert_eq!(decoded, header);
        assert!(r.is_empty());
    }

    #[test]
    fn block_header_wire_with_tc() {
        // A block starting a new view due to a timeout.
        let tc = TimeoutCertificate {
            view: View::new(4),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0xFF],
            aggregate_signature: AggregateSignature([0x77; 96]),
        };
        let header = BlockHeader {
            height: Height::new(1),
            view: View::new(5),
            epoch: Epoch::new(0),
            prev_block: Hash([0xAA; 32]),
            tx_root: Hash([0xBB; 32]),
            high_qc: None,
            timeout_cert: Some(tc),
            proposer: Hash([0x42; 32]),
            timestamp: 3000,
        };
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let mut r = Reader::new(&buf);
        let decoded = BlockHeader::decode(&mut r).expect("decode");
        assert_eq!(decoded, header);
        assert!(r.is_empty());
    }
}
