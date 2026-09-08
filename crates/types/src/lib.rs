//! Oxide Application Interface (OAI) data model.
//!
//! These are the types that cross the consensus ⇄ application boundary
//! defined in `docs/oai-spec.md`. They are deliberately *engine-agnostic*:
//! an [`OxideBlockRecord`] is the same whether the block was finalized by
//! `oxideBFT`, the `MockEngine`, or a future `CometBFT` bridge — followers,
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
use primitives::{Hash, Height};

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
pub struct OxideBlockRecord {
    /// The height of this block.
    pub height: Height,
    /// Hash of the previous `OxideBlockRecord`. All-zero at genesis.
    pub prev: Hash,
    /// Merkle root of the block's transactions (ordered).
    pub tx_root: Hash,
    /// Optional post-execution attestation carried with this block.
    pub attestation: Option<StateAttestation>,
}

impl Encode for OxideBlockRecord {
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

impl<'a> Decode<'a> for OxideBlockRecord {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let height = Height::decode(reader)?;
        let prev = Hash::decode(reader)?;
        let tx_root = Hash::decode(reader)?;
        let attestation =
            if reader.read_bool()? { Some(StateAttestation::decode(reader)?) } else { None };
        Ok(Self { height, prev, tx_root, attestation })
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
    fn oxide_block_record_wire_with_attestation() {
        let rec = OxideBlockRecord {
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
    fn oxide_block_record_wire_no_attestation() {
        let rec = OxideBlockRecord {
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
}
