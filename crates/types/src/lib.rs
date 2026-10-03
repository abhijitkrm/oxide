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

pub(crate) mod gf256;
pub mod rs;
pub mod shard;

use codec::{Decode, DecodeError, Encode, Reader, write};
use crypto::bls::{AggregateSignature, Signature, ValidatorIndex};
use primitives::{Address, Epoch, Hash, Height, View};

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

// ── Chain-configured block limits (Ceiling 1) ────────────────────────
//
// Oxide targets 10 gigagas per block (plan.md §3). These constants
// are the single source of truth for the chain-configured block gas
// limit and the matching block byte budget. Before Ceiling 1, the
// consensus engine, the EVM module, and the test helpers each
// hard-coded their own value (1 GG in consensus, 30M in the EVM,
// 1 MiB in tests) — a tx that was legal under one limit was illegal
// under another, and the 10 GG target was unreachable. Unifying
// them here lets a future on-chain governance parameter flip the
// limit in one place.
//
// Units: gas (max_gas) and bytes (max_bytes). Origin: plan.md §3
// (10 GG/block target). Tradeoff: raising max_gas increases the
// worst-case block execution time; raising max_bytes increases the
// wire framing cost and the mempool memory footprint.

/// The chain-configured block gas limit: 10 gigagas per block
/// (plan.md §3 "gigagas capacity"). This is the single source of
/// truth — the consensus engine, the EVM module, and the test
/// helpers all read this constant instead of hard-coding their own.
pub const CHAIN_BLOCK_GAS_LIMIT: u64 = 10_000_000_000;

/// The chain-configured block byte budget: 16 MiB. At ~120 B per
/// min-size tx, 10 GG of 21k-gas transfers is ~476k txs × ~120 B =
/// ~57 MiB — too large for a single block. 16 MiB caps the wire
/// framing cost while still allowing ~140k txs/block, well above
/// the ~47k tx/block Ethereum mainnet throughput. Units: bytes.
pub const CHAIN_BLOCK_MAX_BYTES: u64 = 16 << 20;

/// The default block budget assembled from the chain-configured
/// limits. Engines and tests use this instead of constructing a
/// `BlockBudget` ad hoc.
pub const CHAIN_BLOCK_BUDGET: BlockBudget =
    BlockBudget { max_bytes: CHAIN_BLOCK_MAX_BYTES, max_gas: CHAIN_BLOCK_GAS_LIMIT };

/// Live chain-level execution parameters — the single mutable copy
/// of the block budget and fee floor every enforcement point reads.
///
/// Node assembly seeds one `Arc<ChainParams>` from config and shares
/// it three ways: the consensus engine budgets proposals and stamps
/// `BlockContext.gas_limit` from it, the executor enforces it at
/// admission/proposal-validation/execution, and the governance
/// `chain.*` parameter sink writes it once a timelocked proposal
/// applies. Sharing one set of atomics (rather than letting each
/// consumer keep its own copy) is what keeps a mid-flight
/// parameter change deterministic: every node applies the
/// governance write at the same height in the same `end_block`
/// order, so all enforcement points cross to the new value
/// together. Splitting them would let a mempool admit under the
/// stale limit while consensus packs under the new one — blocks
/// the proposer builds but validators refuse to vote for.
///
/// Mutating the budget below an in-flight proposal's contents is
/// safe (the proposal is rejected at validation and the next view
/// proposes under the new budget) but is still a liveness dip —
/// governance shrinking the limit should expect one timeout round.
#[derive(Debug, Default)]
pub struct ChainParams {
    /// The block gas limit — proposal packing budget, stamped as
    /// `BlockContext.gas_limit` (the EVM module's per-block cap),
    /// and the executor's cumulative-gas bound. Governed via the
    /// `chain.block_gas_limit` parameter key. Units: gas.
    pub max_gas: std::sync::atomic::AtomicU64,
    /// The block byte budget — proposal packing bound on the wire.
    /// Governed via `chain.block_max_bytes`. Units: bytes.
    pub max_bytes: std::sync::atomic::AtomicU64,
    /// The minimum acceptable envelope fee per transaction — the
    /// executor's admission floor for native-module txs (`0` = no
    /// floor). Governed via `chain.min_fee`. Units: base units.
    pub min_fee: std::sync::atomic::AtomicU64,
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
        // Do not pre-allocate `count` from an untrusted varint: a
        // forged count of ~2.9e8 requested a multi-GB allocation
        // before the loop noticed the bytes ran out (fuzz
        // types-decode, audit session 24 — libFuzzer OOM at
        // malloc(2221329816)). Each `TxBytes` occupies at least one
        // wire byte (its length varint), so the remaining input
        // length is a provably safe capacity bound.
        let mut txs = Vec::with_capacity(count.min(reader.remaining()));
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

/// The consensus-derived execution context for a finalized block —
/// the values consensus commits in the block header that execution
/// must consume verbatim rather than reconstruct locally.
///
/// This is the durable protocol model the application boundary
/// carries: every field is committed under the proposer's signature
/// and the committing QC (it travels inside the block header), so
/// all replicas execute the block under identical context. Journal
/// replay decodes the same context from the recorded block, so
/// replayed execution observes the values the live run used.
///
/// A context with `timestamp_ms == 0` is the documented "no
/// consensus timestamp" sentinel — emitted by engines that have no
/// clock (conformance mocks, hand-built test blocks) and produced
/// when decoding journals written before the field existed.
/// Modules must interpret a zero context field as "no data" and
/// keep their configured defaults — never as a real epoch value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockContext {
    /// Block timestamp in milliseconds since the Unix epoch — the
    /// proposer's clock reading committed in the header. `0` means
    /// "no timestamp" (legacy/test block); execution falls back to
    /// its deterministic stand-in for those.
    pub timestamp_ms: u64,
    /// The block's fee beneficiary: the proposer's staking address,
    /// resolved from the committed `header.proposer` identity
    /// against the epoch's validator set — the same address space
    /// the attendance `signers` use. `Address::ZERO` when the
    /// engine cannot attribute a proposer (sequencer, mock).
    pub beneficiary: Address,
    /// The consensus-enforced block gas limit for this height — the
    /// `max_gas` budget the block was produced under. `0` means
    /// "unknown"; modules keep their configured limit. Consensus
    /// is the authority on block capacity: a module-level limit
    /// that disagrees with the budget the engine enforced would let
    /// the mempool accept transactions the block can never hold.
    pub gas_limit: u64,
}

impl Default for BlockContext {
    /// The all-zero "no consensus context" sentinel — every field
    /// reads as "no data", and modules keep their configured
    /// defaults. Produced by hand-built test blocks, clockless
    /// engines, and pre-context journal decode.
    fn default() -> Self {
        Self { timestamp_ms: 0, beneficiary: Address::ZERO, gas_limit: 0 }
    }
}

impl BlockContext {
    /// Milliseconds per second — conversion factor for the EVM's
    /// seconds-granularity `block.timestamp`.
    const MS_PER_SEC: u64 = 1_000;

    /// The timestamp in whole seconds (EVM `block.timestamp`
    /// granularity). Sub-second precision is truncated — matching
    /// Ethereum, whose header timestamps are integer seconds.
    #[must_use]
    pub fn timestamp_secs(&self) -> u64 {
        self.timestamp_ms / Self::MS_PER_SEC
    }
}

/// Milliseconds since the Unix epoch on the system clock — the
/// default proposal clock for engines with no injected time
/// source. A clock reading before the epoch (or past `u64::MAX`
/// ms, i.e. the year ~584 million) saturates to `0`, which callers
/// read as "no timestamp" rather than a panic.
#[must_use]
pub fn system_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The validator-set transition a finalized block's execution
/// produced — the staking module's pending queues, drained by the
/// consensus engine at the epoch boundary.
///
/// Every field is a *delta* against the engine's current
/// `ValidatorSet`, applied in a fixed order — key replacements
/// first, then removals (descending index, so positions don't
/// shift), then additions appended — so every replica that
/// executes the same block derives the same next-epoch set.
///
/// `adds` is a list of `(staking_address, bls_public_key, stake)`
/// tuples for new validators. `removes` is a list of staking
/// addresses to drop.
///
/// The record is the consensus-facing half of the transition:
/// modules record the deltas when the block executes; the engine
/// folds them into a candidate `ValidatorSet`, certifies the swap
/// through the epoch rotation, and persists the resulting set in
/// its WAL so a restart re-derives the same committee.
#[derive(Debug, Clone, Default)]
pub struct EpochChanges {
    /// Consensus-key replacements for existing validators:
    /// `(staking_address, new_bls_public_key)` — a
    /// [`ValidatedPublicKey`](crypto::bls_signer::ValidatedPublicKey)
    /// proving the module ran point + subgroup validation at
    /// admission (previously bare `Vec<u8>` that the engine decoded
    /// with a length-only check at the epoch boundary).
    pub key_changes: Vec<(Address, crypto::bls_signer::ValidatedPublicKey)>,
    /// Validators to add: `(staking_address, bls_public_key, stake)`.
    pub adds: Vec<(Address, crypto::bls_signer::ValidatedPublicKey, u64)>,
    /// Validator staking addresses to remove.
    pub removes: Vec<Address>,
}

impl EpochChanges {
    /// Whether there is no pending transition — the common case on
    /// every block that enacted no staking changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.key_changes.is_empty() && self.adds.is_empty() && self.removes.is_empty()
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
    /// The staking addresses of the validators whose votes formed the
    /// committing QC — the attendance record for this height. Resolved
    /// from the QC's signer bitmap against the engine's validator set,
    /// so it survives consensus-internal index changes.
    ///
    /// Carried *on* the block (and in its encoding) because the journal
    /// replays `finalize_block`: downtime tracking must derive the same
    /// jails on replay, which is only possible if the signer set is
    /// part of the recorded block. Engines that cannot attribute
    /// signers (sequencer mode, mock) leave it empty — the app reads
    /// empty as "no attendance data", never as "everyone absent".
    pub signers: Vec<Address>,
    /// The consensus-derived execution context — timestamp, fee
    /// beneficiary, and the block gas limit the block was produced
    /// under. Carried on the block for the same reason `signers` is:
    /// journal replay must re-execute under the values the live run
    /// committed, which are only available if they are recorded.
    ///
    /// An all-zero context is the legacy/test sentinel — blocks
    /// decoded from journals that predate this field, or produced
    /// by engines with no clock/committee, carry it and modules
    /// keep their configured defaults for those fields.
    pub context: BlockContext,
}

impl Encode for FinalizedBlock {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        write::varint(buf, self.txs.len() as u64);
        for tx in &self.txs {
            tx.encode(buf);
        }
        write::varint(buf, self.signers.len() as u64);
        for signer in &self.signers {
            buf.extend_from_slice(&signer.0);
        }
        // The context is the newest tail: a fixed-shape trio
        // (varint timestamp, `Address::LEN` beneficiary, varint gas
        // limit) appended after signers. Pre-context journals stop
        // at signers — decode reads the absent tail as an all-zero
        // context rather than failing.
        write::varint(buf, self.context.timestamp_ms);
        buf.extend_from_slice(&self.context.beneficiary.0);
        write::varint(buf, self.context.gas_limit);
    }
}

impl<'a> Decode<'a> for FinalizedBlock {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let height = Height::decode(reader)?;
        let count = read_count(reader)?;
        // Same untrusted-varint bound as `Proposal::decode` (fuzz
        // types-decode, audit session 24): cap the pre-allocation at
        // the remaining input — each `TxBytes` needs ≥1 wire byte.
        let mut txs = Vec::with_capacity(count.min(reader.remaining()));
        for _ in 0..count {
            txs.push(TxBytes::decode(reader)?);
        }
        // Tolerant tail: journals written before `signers` existed end
        // here — read as "no attendance data" instead of failing, so
        // pre-change histories stay replayable.
        let mut signers = Vec::new();
        if reader.remaining() > 0 {
            let count = read_count(reader)?;
            // Each signer is exactly `Address::LEN` bytes — the count
            // is capped by remaining input the same way `txs` is.
            signers.reserve(count.min(reader.remaining() / Address::LEN));
            for _ in 0..count {
                signers.push(Address(reader.read_fixed::<{ Address::LEN }>()?));
            }
        }
        // Second tolerant tail: the execution context (timestamp,
        // beneficiary, gas limit) postdates `signers`. Journals
        // written before it existed end at signers — an all-zero
        // context is the "no data" sentinel modules already treat
        // as "keep configured defaults". Once any context byte is
        // present the tail must be complete: a partial context is
        // corruption, not a legacy record, so fields decode
        // strictly (a truncated varint or short beneficiary fails).
        let mut context = BlockContext::default();
        if reader.remaining() > 0 {
            context.timestamp_ms = reader.read_varint()?;
            context.beneficiary = Address(reader.read_fixed::<{ Address::LEN }>()?);
            context.gas_limit = reader.read_varint()?;
        }
        Ok(Self { height, txs, signers, context })
    }
}

/// A finalized block plus the consensus evidence that finalized it —
/// the unit of certified block sync.
///
/// A lagging or restarting validator cannot trust a bare block: the
/// sender could serve any bytes at any height. What it *can* verify
/// is the Jolteon commit chain (arXiv:2106.10362 §3): a block commits
/// when a certified pair `(X, X')` with `X'.view == X.view + 1` and
/// `X'.prev == X` exists at-or-above it — commit-by-descent. Each
/// record carries one *certified link* of that chain plus the body,
/// so a receiver can verify the whole chain of custody locally:
///
/// - `header` — the committed block itself (height, view, epoch,
///   `prev_block` linkage, `tx_root`, proposer signature).
/// - `proposal` — the committed body; the receiver recomputes
///   `tx_root`/`body_commitment` against `header` before executing,
///   so the served bytes are the ones quorum attested.
/// - `child` — the block's certified successor on the committed
///   chain: `child.prev_block == hash(header)` and
///   `child.height == header.height + 1`. Its embedded `high_qc` is
///   the QC *on `header`* — the notarization link. The QC contents
///   are committed by `child`'s hash, so they cannot be swapped
///   without invalidating `qc` below. `child.view` is strictly
///   greater than `header.view` — for the run's tip record it is
///   exactly +1 (the consecutive seal); interior ancestors carry
///   whatever view their real successor landed at, since timeout
///   churn can insert TC'd views between a block and its child.
/// - `qc` — the quorum certificate on `child`: `qc.block_hash ==
///   hash(child)`, `qc.view == child.view`. Verifying its aggregate
///   signature against the epoch's committee proves quorum accepted
///   `child` — and a contiguous run of these links ending in a
///   consecutive seal is what makes the prefix committed, without
///   the receiver trusting the sender at all.
///
/// Attendance is derivable rather than carried: `FinalizedBlock::
/// signers` resolves from `child.high_qc.signer_bitmap` (the QC on
/// `header`), exactly as the live commit path resolves it.
///
/// Only *finalized* blocks are ever served in this form — the proof
/// fields exist precisely because uncommitted proposals carry no such
/// evidence. A node never serves an in-flight proposal as canonical
/// history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedBlock {
    /// The finalized block's header.
    pub header: BlockHeader,
    /// The finalized block's body (`height`, ordered txs, attestation)
    /// — the bytes `header.tx_root` and `header.body_commitment`
    /// commit to.
    pub proposal: Proposal,
    /// The block's certified successor on the committed chain —
    /// carries `header`'s QC in `high_qc`. For the run's tip record
    /// it is the consecutive child that seals the commit.
    pub child: BlockHeader,
    /// The quorum certificate certifying `child`.
    pub qc: QuorumCertificate,
}

impl Encode for CertifiedBlock {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.header.encode(buf);
        self.proposal.encode(buf);
        self.child.encode(buf);
        self.qc.encode(buf);
    }
}

impl<'a> Decode<'a> for CertifiedBlock {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            header: BlockHeader::decode(reader)?,
            proposal: Proposal::decode(reader)?,
            child: BlockHeader::decode(reader)?,
            qc: QuorumCertificate::decode(reader)?,
        })
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

/// Execution certificate: validators holding a strict two-thirds
/// supermajority of voting power (`⌊2·total_stake/3⌋+1`) attest to
/// the state root of a finalized block (docs/oxidebft-spec.md §6).
///
/// This is the consensus-level execution attestation — a quorum
/// certificate proving that a stake-supermajority of validators
/// executed the block at `height` and agree on `state_root`. It is
/// embedded in the *next* block's header as `exec_cert`, so every
/// block carries proof that the previous block's execution was
/// verified by the network.
///
/// This is distinct from [`StateAttestation`] (a single validator's
/// attestation) and from [`QuorumCertificate`] (which certifies a
/// *vote*, not an execution result). The `ExecCertificate` certifies
/// *execution agreement* — divergence detection uses it to prove that
/// all honest validators computed the same state root.
///
/// Wire form:
/// ```text
/// [height u64 LE][state_root 32B][epoch u64 LE]
/// [signer_bitmap_len varint][signer_bitmap bytes]
/// [aggregate_signature 96B]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCertificate {
    /// The height whose execution is certified.
    pub height: Height,
    /// The state root after executing the block at `height`.
    pub state_root: Hash,
    /// The epoch the certificate belongs to.
    pub epoch: Epoch,
    /// Bitmap of which validators signed (same encoding as QC).
    pub signer_bitmap: Vec<u8>,
    /// Aggregate BLS signature over `(height, state_root)`.
    pub aggregate_signature: AggregateSignature,
}

impl Encode for ExecCertificate {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        self.state_root.encode(buf);
        self.epoch.encode(buf);
        write::bytes(buf, &self.signer_bitmap);
        self.aggregate_signature.encode(buf);
    }
}

impl<'a> Decode<'a> for ExecCertificate {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let height = Height::decode(reader)?;
        let state_root = Hash::decode(reader)?;
        let epoch = Epoch::decode(reader)?;
        let signer_bitmap = reader.read_bytes()?.to_vec();
        let aggregate_signature = AggregateSignature::decode(reader)?;
        Ok(Self { height, state_root, epoch, signer_bitmap, aggregate_signature })
    }
}

/// A confirmed execution divergence: a quorum-signed
/// [`ExecCertificate`] attested a state root this validator did not
/// compute at the same height.
///
/// The certificate passed full validation (epoch, bitmap bounds,
/// quorum power, aggregate signature) before the comparison ran, so
/// the mismatch is real evidence — either this validator's execution
/// diverged from the network or a supermajority attested state it
/// never ran. Either way the node must stop signing and be repaired,
/// not quietly drop out of the quorum.
///
/// The type lives in `types` (not `consensus`) so the
/// `ports::ConsensusEngine` seam — which cannot depend on the
/// engine crate — can surface it to node status plumbing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecDivergence {
    /// The height whose state root disagrees.
    pub height: Height,
    /// The root this validator computed locally.
    pub local_root: Hash,
    /// The root the verified certificate attested. This is the
    /// quorum-certified anchor a repair `--state-sync` should pass
    /// as `--trusted-root`.
    pub certified_root: Hash,
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
    /// The voter's most recent execution attestation: the state root
    /// of the newest block it has executed locally. Leaders harvest
    /// matching attestations across votes and aggregate them into an
    /// [`ExecCertificate`] carried by a later block header — the
    /// chain's divergence-detection mechanism (every block carries
    /// quorum proof of what its ancestors computed).
    ///
    /// `None` before the voter has executed anything, or in
    /// conformance mode. The attestation height is embedded in the
    /// value itself, so a stale attestation is never *wrong* — it
    /// simply certifies an older height.
    pub attestation: Option<StateAttestation>,
    /// BLS signature over `(attestation.height, attestation.root,
    /// epoch)` under `Domain::ExecAttest`. Kept separate from
    /// `signature` because the two sign *different* messages: vote
    /// signatures aggregate over `(view, phase, block_hash)` into a
    /// QC, while attestation signatures aggregate over `(height,
    /// state_root)` into an [`ExecCertificate`]. Folding them into
    /// one signature would make QC formation depend on execution
    /// agreement — a validator that diverged (or merely lagged)
    /// could then never be aggregated, turning divergence detection
    /// into a liveness break.
    pub attestation_sig: Option<Signature>,
}

impl Encode for Vote {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.view.encode(buf);
        buf.push(self.phase as u8);
        self.block_hash.encode(buf);
        self.signature.encode(buf);
        match &self.attestation {
            Some(att) => {
                write::bool(buf, true);
                att.encode(buf);
            }
            None => write::bool(buf, false),
        }
        match &self.attestation_sig {
            Some(sig) => {
                write::bool(buf, true);
                sig.encode(buf);
            }
            None => write::bool(buf, false),
        }
    }
}

impl<'a> Decode<'a> for Vote {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let view = View::decode(reader)?;
        let phase = VotePhase::from_byte(reader.read_u8()?)?;
        let block_hash = Hash::decode(reader)?;
        let signature = Signature::decode(reader)?;
        let attestation =
            if reader.read_bool()? { Some(StateAttestation::decode(reader)?) } else { None };
        let attestation_sig =
            if reader.read_bool()? { Some(Signature::decode(reader)?) } else { None };
        Ok(Self { view, phase, block_hash, signature, attestation, attestation_sig })
    }
}

/// Slashable equivocation evidence: two *conflicting* votes observed
/// from the same validator at the same `(view, phase, epoch)` but
/// naming different block hashes.
///
/// Emitted by the consensus engine when its per-view vote history
/// sees a second signed vote that disagrees with the first it
/// recorded for a voter. Both signatures are carried verbatim —
/// the pair is self-authenticating: the staking module re-derives
/// the exact vote signing messages and re-verifies each signature
/// against the offender's current and retired BLS keys, so a
/// malformed or forged pair cannot produce a slash. The record is
/// a Rust-only hand-off (engine → node pump → staking evidence
/// transaction); it has no wire form of its own.
///
/// `first`/`second` are ordered by observation time. The staking
/// module treats the pair symmetrically — order carries no
/// protocol meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoubleSignEvidence {
    /// The equivocating validator's staking address — the account
    /// the slash and jail apply to.
    pub validator: Address,
    /// The view both votes were cast in.
    pub view: View,
    /// The pipeline phase both votes were cast in.
    pub phase: VotePhase,
    /// The epoch both votes belong to — the signing messages the
    /// module reconstructs bind the epoch.
    pub epoch: Epoch,
    /// The block hash of the first observed vote.
    pub first_block_hash: Hash,
    /// The BLS signature on the first observed vote.
    pub first_signature: Signature,
    /// The block hash of the second, conflicting vote.
    pub second_block_hash: Hash,
    /// The BLS signature on the second, conflicting vote.
    pub second_signature: Signature,
}

/// A quorum certificate: the aggregate of votes for a single
/// `(view, phase, block_hash)` whose signers hold a strict
/// two-thirds supermajority of voting power
/// (`⌊2·total_stake/3⌋+1`, docs/oxidebft-spec.md §3).
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

/// One signer's contribution to a [`TimeoutCertificate`]: its timeout
/// signature together with the high-QC evidence it held when it
/// signed (the Jolteon `qc_high` carried in every timeout message,
/// arXiv:2106.10362 §3).
///
/// The signature binds `(view, epoch, has_qc, qc_high.view,
/// qc_high.block_hash)` — the evidence is *inside* the signed
/// payload, not attached alongside it. That binding is load-bearing:
/// a TC is assembled by one replica from timeout messages it
/// collected, and the safety argument needs every signer in the
/// quorum to be accountable for the exact `qc_high` it reported.
/// With the claim inside the signature, the aggregator cannot weaken
/// a locked validator's evidence (it would have to forge the
/// signature), and any quorum-sized signer subset is guaranteed to
/// intersect the locked set — the property the two-chain commit
/// rule leans on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutSigner {
    /// The validator index that produced this timeout signature.
    pub voter: ValidatorIndex,
    /// The signer's high QC at the moment it signed — the highest
    /// certified block it had adopted, which bounds what it can
    /// honestly vote to extend next. `None` only before the first
    /// QC exists (genesis or the post-rotation boundary).
    ///
    /// Carried as the certificate itself rather than a bare
    /// `(view, hash)` claim so the evidence is verifiable in place:
    /// a bogus claim needs a bogus QC, which fails verification —
    /// a byzantine signer can at worst refuse to sign, never poison
    /// the evidence a TC reports.
    pub high_qc: Option<QuorumCertificate>,
    /// BLS signature over the timeout claim — see
    /// [`TimeoutCertificate`] for the payload layout.
    pub signature: Signature,
}

impl Encode for TimeoutSigner {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.voter.to_le_bytes());
        match &self.high_qc {
            Some(qc) => {
                write::bool(buf, true);
                qc.encode(buf);
            }
            None => write::bool(buf, false),
        }
        self.signature.encode(buf);
    }
}

impl<'a> Decode<'a> for TimeoutSigner {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let voter = u16::from_le_bytes(reader.read_fixed::<2>()?);
        let high_qc =
            if reader.read_bool()? { Some(QuorumCertificate::decode(reader)?) } else { None };
        let signature = Signature::decode(reader)?;
        Ok(Self { voter, high_qc, signature })
    }
}

/// A timeout certificate: validators holding a strict two-thirds
/// supermajority of voting power (`⌊2·total_stake/3⌋+1`) signed a
/// timeout for view `v`, proving the view should advance
/// (docs/oxidebft-spec.md §4).
///
/// The TC is the "force a view change without the leader" mechanism —
/// tail-fork resistance. The next leader (view *v+1*) embeds the TC in
/// its proposal, proving it is the legitimate successor.
///
/// Unlike a bare aggregate signature, the TC carries the per-signer
/// [`TimeoutSigner`] records — including each signer's `high_qc`.
/// The Jolteon vote predicate then requires a timeout-entered
/// proposal to extend a QC at least as recent as the maximum
/// evidence view here ([`Self::max_high_qc_view`]): the quorum that
/// locked a certified chain reports it in every later TC, so no
/// post-timeout proposal can legitimately extend around it. This is
/// the condition that makes the consecutive-view two-chain commit
/// safe (the evidence a TC carries is verifiable, so an aggregator
/// can neither fabricate nor downplay it — dropping entries only
/// shrinks the quorum it can claim).
///
/// Wire form (pinned by `timeout_certificate_wire` test):
/// ```text
/// [view u64 LE][epoch u64 LE]
/// [signer_count varint]
/// per signer: [voter u16 LE][has_qc u8][qc ... if present][sig 96B]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutCertificate {
    /// The view that timed out.
    pub view: View,
    /// The epoch the TC belongs to.
    pub epoch: Epoch,
    /// Per-signer timeout records. `signers.len()` ≤ the validator
    /// count and each `voter` must be distinct — checked at
    /// verification, which also enforces the quorum stake threshold.
    pub signers: Vec<TimeoutSigner>,
}

impl TimeoutCertificate {
    /// The maximum `high_qc` view reported by the TC's signers —
    /// the Jolteon evidence bound a timeout-entered proposal must
    /// satisfy (`prop_qc.view >= max`). `View::new(0)` when no
    /// signer reported a QC (fresh-epoch timeouts).
    pub fn max_high_qc_view(&self) -> View {
        self.signers
            .iter()
            .filter_map(|s| s.high_qc.as_ref().map(|qc| qc.view))
            .max()
            .unwrap_or_else(|| View::new(0))
    }
}

impl Encode for TimeoutCertificate {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.view.encode(buf);
        self.epoch.encode(buf);
        write::varint(buf, self.signers.len() as u64);
        for signer in &self.signers {
            signer.encode(buf);
        }
    }
}

impl<'a> Decode<'a> for TimeoutCertificate {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let view = View::decode(reader)?;
        let epoch = Epoch::decode(reader)?;
        let count = read_count(reader)?;
        // Bound the allocation: each signer entry is at least
        // voter(2) + flag(1) + sig(96) = 99 bytes, so a count beyond
        // what the remaining bytes could hold is malformed.
        if u64::try_from(count).unwrap_or(u64::MAX) > reader.remaining() as u64 / 99 {
            return Err(DecodeError::LengthPrefixTooLarge {
                claimed: count as u64,
                remaining: reader.remaining() as u64,
            });
        }
        let mut signers = Vec::with_capacity(count);
        for _ in 0..count {
            signers.push(TimeoutSigner::decode(reader)?);
        }
        Ok(Self { view, epoch, signers })
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
/// [has_proposer_sig u8][proposer_sig 96B if present]
/// [has_exec_cert u8][exec_cert ... if present]
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
    /// The proposer's BLS signature over the block header (excluding
    /// this signature field). Authenticates that the claimed proposer
    /// actually created this proposal — prevents a byzantine node
    /// from fabricating a proposal in another validator's name.
    /// `None` in conformance mode (no real signing).
    pub proposer_signature: Option<Signature>,
    /// Execution certificate for the previous block: validators holding a
    /// strict two-thirds supermajority of voting power attested to the state root of the block at `height - 1`. This
    /// proves the previous block's execution was verified by the
    /// network and enables divergence detection — if two honest
    /// validators disagree on the state root, the `exec_cert` will
    /// not form. `None` at genesis or before the first exec cert.
    pub exec_cert: Option<ExecCertificate>,
    /// Commitment over the dispersed body shards (Merkle-style root
    /// from [`crate::shard::disperse_body`]). Every validator verifies
    /// its own shard's inclusion proof against this root and votes on
    /// the block commitment *before* reconstructing the full body —
    /// the `DispersedSimplex` broadcast pattern: notarize on partial
    /// information, certify (reconstruct + verify) before finalize.
    /// `Hash::ZERO` only for synthetic headers in tests.
    pub body_commitment: Hash,
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
        match &self.proposer_signature {
            Some(sig) => {
                write::bool(buf, true);
                sig.encode(buf);
            }
            None => write::bool(buf, false),
        }
        match &self.exec_cert {
            Some(cert) => {
                write::bool(buf, true);
                cert.encode(buf);
            }
            None => write::bool(buf, false),
        }
        // Appended last so earlier protocol revisions' encodings are a
        // strict prefix — decoders that stop here see the old format.
        self.body_commitment.encode(buf);
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
        let proposer_signature =
            if reader.read_bool()? { Some(Signature::decode(reader)?) } else { None };
        let exec_cert =
            if reader.read_bool()? { Some(ExecCertificate::decode(reader)?) } else { None };
        let body_commitment = Hash::decode(reader)?;
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
            proposer_signature,
            exec_cert,
            body_commitment,
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

    /// Regression (fuzz types-decode, audit session 24):
    /// a crafted `Proposal` claiming a huge tx count (varint
    /// ~2.86e8) must not pre-allocate gigabytes in
    /// `Vec::with_capacity` before the loop notices the bytes ran
    /// out. Found by libFuzzer as `out-of-memory (malloc(2221329816))`.
    ///
    /// The fix caps the pre-allocation at the remaining input
    /// length (each `TxBytes` occupies at least one wire byte), so
    /// a malicious count fails the decode loop cheaply instead of
    /// crashing the node with an out-of-memory abort.
    #[test]
    fn proposal_decode_huge_count_does_not_oom() {
        // height=0 (8 zero bytes) + varint(286_860_940) + nothing.
        // The varint encoding of 286_860_940 is 0xFC 0xFF 0xFF
        // 0x88 ... — we build it via the codec itself so the test
        // stays correct if the varint encoding changes.
        let mut crafted = Vec::new();
        crafted.extend_from_slice(&0u64.to_le_bytes());
        write::varint(&mut crafted, 286_860_940); // ~2.86e8 txs claimed
        // Decode must fail (bytes run out) or return an empty
        // result — never allocate 286M * sizeof(TxBytes) upfront.
        let mut reader = Reader::new(&crafted);
        let result = Proposal::decode(&mut reader);
        // The decode must error: 286M txs cannot fit in 12 bytes.
        assert!(result.is_err(), "huge count must fail decode, got ok");
    }

    /// Same regression for `FinalizedBlock`, whose decoder shares
    /// the vulnerable `Vec::with_capacity(count)` shape.
    #[test]
    fn finalized_block_decode_huge_count_does_not_oom() {
        let mut crafted = Vec::new();
        crafted.extend_from_slice(&0u64.to_le_bytes());
        write::varint(&mut crafted, u64::from(u32::MAX)); // 4e9 txs claimed
        let mut reader = Reader::new(&crafted);
        let result = FinalizedBlock::decode(&mut reader);
        assert!(result.is_err(), "huge count must fail decode, got ok");
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
        let fb = FinalizedBlock {
            height: Height::new(7),
            txs: vec![TxBytes(vec![0x01])],
            signers: Vec::new(),
            context: BlockContext::default(),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.push(1); // tx count
        expected.extend_from_slice(&[1, 0x01]); // tx
        expected.push(0); // signer count
        // Execution context tail: timestamp varint 0, 20-byte zero
        // beneficiary, gas-limit varint 0 — the all-zero sentinel.
        expected.push(0);
        expected.extend_from_slice(&[0u8; Address::LEN]);
        expected.push(0);
        roundtrip(&fb, &expected);
    }

    /// A populated execution context survives the wire: timestamp,
    /// beneficiary, and gas limit all decode to the committed values.
    #[test]
    fn finalized_block_context_roundtrips() {
        let ctx = BlockContext {
            timestamp_ms: 1_700_000_000_123,
            beneficiary: Address([0xAB; 20]),
            gas_limit: 1 << 30,
        };
        let fb = FinalizedBlock {
            height: Height::new(9),
            txs: vec![TxBytes(vec![0x01])],
            signers: vec![Address([0x01; 20])],
            context: ctx,
        };
        let mut buf = Vec::new();
        fb.encode(&mut buf);
        let mut reader = Reader::new(&buf);
        let decoded = FinalizedBlock::decode(&mut reader).expect("decodes");
        assert_eq!(decoded, fb);
        assert_eq!(decoded.context, ctx);
    }

    /// Journals written before the context field existed end at
    /// `signers` — decode must synthesize the all-zero sentinel
    /// rather than fail, keeping pre-change histories replayable.
    #[test]
    fn finalized_block_without_context_decodes_legacy() {
        let mut buf = Vec::new();
        Height::new(4).encode(&mut buf);
        write::varint(&mut buf, 1); // 1 tx
        TxBytes(vec![0xAA]).encode(&mut buf);
        write::varint(&mut buf, 0); // 0 signers — stream ends here
        let mut reader = Reader::new(&buf);
        let decoded = FinalizedBlock::decode(&mut reader).expect("legacy tail decodes");
        assert_eq!(decoded.context, BlockContext::default());
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
            attestation: Some(StateAttestation { height: Height::new(6), root: Hash([0x42; 32]) }),
            attestation_sig: Some(Signature([0xEE; 96])),
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&7u64.to_le_bytes()); // view
        expected.push(1); // phase = PreCommit
        expected.extend_from_slice(&[0xAB; 32]); // block_hash
        expected.extend_from_slice(&[0xCD; 96]); // signature
        expected.push(1); // has attestation
        expected.extend_from_slice(&6u64.to_le_bytes()); // attestation height
        expected.extend_from_slice(&[0x42; 32]); // attestation root
        expected.push(1); // has attestation_sig
        expected.extend_from_slice(&[0xEE; 96]); // attestation sig
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
        let qc = QuorumCertificate {
            view: View::new(1),
            phase: VotePhase::Prepare,
            block_hash: Hash([0x44; 32]),
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0111],
            aggregate_signature: AggregateSignature([0x55; 96]),
        };
        let tc = TimeoutCertificate {
            view: View::new(3),
            epoch: Epoch::new(0),
            signers: vec![
                TimeoutSigner { voter: 0, high_qc: Some(qc), signature: Signature([0x33; 96]) },
                TimeoutSigner { voter: 1, high_qc: None, signature: Signature([0x77; 96]) },
            ],
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&3u64.to_le_bytes()); // view
        expected.extend_from_slice(&0u64.to_le_bytes()); // epoch
        expected.push(2); // signer count varint
        // signer 0: voter u16 + has_qc + qc + sig
        expected.extend_from_slice(&0u16.to_le_bytes());
        expected.push(1); // has_qc
        expected.extend_from_slice(&1u64.to_le_bytes()); // qc.view
        expected.push(0); // qc.phase
        expected.extend_from_slice(&[0x44; 32]); // qc.block_hash
        expected.extend_from_slice(&0u64.to_le_bytes()); // qc.epoch
        expected.push(1); // qc.signer_bitmap varint len
        expected.push(0b0000_0111); // qc.signer_bitmap
        expected.extend_from_slice(&[0x55; 96]); // qc.aggregate_signature
        expected.extend_from_slice(&[0x33; 96]); // signer sig
        // signer 1: voter u16 + no qc + sig
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.push(0); // no high_qc
        expected.extend_from_slice(&[0x77; 96]);
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
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
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
        expected.push(0); // no proposer_signature
        expected.push(0); // no exec_cert
        expected.extend_from_slice(&[0; 32]); // body_commitment
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
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
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
            signers: vec![TimeoutSigner {
                voter: 0,
                high_qc: None,
                signature: Signature([0x77; 96]),
            }],
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
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let mut buf = Vec::new();
        header.encode(&mut buf);
        let mut r = Reader::new(&buf);
        let decoded = BlockHeader::decode(&mut r).expect("decode");
        assert_eq!(decoded, header);
        assert!(r.is_empty());
    }
}
