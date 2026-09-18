//! Oxide plug-and-play seams: the Oxide Application Interface (OAI)
//! traits plus the broadcast and transport ports, a reference
//! [`mock::MockEngine`], and the [`conformance`] suite every engine
//! must pass.
//!
//! # What this crate is
//!
//! The boundary between consensus engines and the application, as
//! specified in `docs/oai-spec.md`. The crate carries five trait seams:
//!
//! - [`AppInterface`] — implemented by the application (executor +
//!   mempool + state).
//! - [`ConsensusEngine`] — implemented by engines (oxideBFT is the
//!   default; [`mock::MockEngine`] is the reference).
//! - [`BroadcastEngine`] — the data-availability port (erasure-coded
//!   broadcast by default; `PlainGossip` for devnets).
//! - [`Transport`] — the peer-to-peer networking port (commonware-p2p
//!   by default; in-process mock for deterministic simulation).
//! - [`StorageBackend`] — re-exported from the `storage` crate (the
//!   storage adapter seam; defined there because storage owns the
//!   conformance suite for backends).
//!
//! # Why traits, not concrete types
//!
//! The chain's identity is engine-agnostic (oai-spec.md §1): followers,
//! indexers, the journal, and RPC consume the [`types::BlockRecord`]
//! ledger, never an engine's internal header. Swapping the engine changes
//! consensus certificates, not the chain's data model. The traits make
//! that swap a compile-time property — a node wires an engine via
//! configuration, and the conformance suite proves the engine honors
//! the contract before it ships.
//!
//! # Phase 0 scope
//!
//! v0 traits are **synchronous** (oai-spec.md §2): the reference path
//! (`MockEngine` + deterministic runtime + conformance) is inherently
//! synchronous, and premature async is an API every adapter must honor
//! forever. Phase 1 revisits the boundary shape with `oxideBFT`'s real
//! loop.

pub mod broadcast;
pub mod conformance;
pub mod mock;
pub mod storage_conformance;
pub mod transport;

pub use broadcast::{BroadcastCaps, BroadcastEngine, BroadcastError};
pub use transport::{InboundMessage, PeerId, Transport, TransportCaps, TransportError};

use primitives::Height;
use types::{
    BlockBudget, CommitAck, FinalizedBlock, MempoolAck, Proposal, StateAttestation, TxBytes,
    Verdict,
};

/// Implemented by the application (executor + mempool + state).
///
/// All methods take `&self`: a real application backs these with
/// interior-mutability structures (channels into async execution lanes,
/// a locked mempool) so the engine can drive it from a single thread
/// without `&mut` access. The reference [`mock::MockApp`] uses `Mutex`
/// for the same property.
pub trait AppInterface: Send + Sync {
    /// Mempool intake. Engines that collect transactions push them here;
    /// engines with their own mempool may no-op (their proposals still
    /// arrive via [`AppInterface::prepare_proposal`]). Idempotence is
    /// per-tx-hash — a duplicate submission is acknowledged but not
    /// double-counted.
    fn ingest_tx(&self, tx: TxBytes) -> MempoolAck;

    /// Batch mempool intake. Default implementation calls
    /// [`ingest_tx`](Self::ingest_tx) per tx. Apps with a locked
    /// mempool can override this to acquire the lock once for the
    /// entire batch, amortizing the per-tx lock overhead.
    fn ingest_tx_batch(&self, txs: Vec<TxBytes>) -> Vec<MempoolAck> {
        txs.into_iter().map(|tx| self.ingest_tx(tx)).collect()
    }

    /// Leader hook: assemble the next proposal within `budget`. The
    /// proposal's height is the app's next chain height (the app is the
    /// ledger's source of truth); the engine and app advance height in
    /// lockstep, one [`AppInterface::prepare_proposal`] per finalized
    /// block.
    fn prepare_proposal(&self, budget: &BlockBudget) -> Proposal;

    /// Whether the app holds *any* queued transactions — including
    /// ones `prepare_proposal` cannot currently select (e.g. nonce-
    /// blocked behind uncommitted earlier rounds).
    ///
    /// Consensus uses this for the leader liveness gate: a leader
    /// whose queue is non-empty has outstanding work even when this
    /// view's selection comes back empty, so it must still produce a
    /// block — possibly empty-content — to keep the chain advancing
    /// until the queued txs become selectable. Returning `false`
    /// while txs remain queued can freeze the chain one view after
    /// an empty block.
    fn has_queued_txs(&self) -> bool;

    /// Replica hook: static validity (sizes, fee/nonce shape,
    /// availability pre-checks). **Never executes.** Rejecting here is a
    /// protocol message, not an application error — a proposal that
    /// would revert on execution must still be accepted (oai-spec.md
    /// §3, rule 4).
    fn process_proposal(&self, proposal: &Proposal) -> Verdict;

    /// Ordering finalized for `height`: hand the block to the execution
    /// lane. Must return immediately (execution is async by design);
    /// the ack asserts reception, not execution.
    fn finalize_block(&self, block: &FinalizedBlock) -> CommitAck;

    /// Post-execution roots for embedding in the next proposal. Opaque
    /// to the engine — it embeds these bytes verbatim and never parses
    /// them (oai-spec.md §3, rule 5).
    fn attest_state(&self, height: Height) -> StateAttestation;

    /// The newest *executed* state root, without blocking. Returns
    /// `root = Hash::ZERO` when nothing has executed yet.
    ///
    /// Consensus attaches this to outgoing votes as the validator's
    /// execution attestation (the input to [`types::ExecCertificate`]
    /// aggregation). It must never wait on in-flight execution — the
    /// vote path cannot afford to stall behind the execution lane,
    /// and a stale attestation is never wrong (its height is carried
    /// inside, so it simply certifies an older block).
    fn attest_latest(&self) -> StateAttestation;
}

/// Implemented by consensus engines (oxideBFT is the default;
/// [`mock::MockEngine`] is the reference).
///
/// An engine's output is a finalized, reorg-free *ordering* of opaque
/// transaction bytes. It never executes (oai-spec.md §1).
pub trait ConsensusEngine: Send {
    /// Feed a transaction into the pipeline. The default path forwards
    /// to [`AppInterface::ingest_tx`]; engines with their own mempool
    /// may handle it directly.
    fn submit_tx(&mut self, tx: TxBytes) -> MempoolAck;

    /// Drive the engine until it has no immediately-executable work.
    /// Deterministic-runtime-friendly: the real engine's I/O is
    /// event-driven in Phase 1; this step function lets conformance
    /// and simulation advance the engine in controlled increments.
    fn run_until_idle(&mut self);

    /// Highest finalized height, if any (engine-attested ordering only).
    fn finalized_height(&self) -> Option<Height>;

    /// The finalized block at `height`, if finalized (oai-spec.md §3,
    /// rule 1: after finalization, this is stable and unique).
    fn finalized_block(&self, height: Height) -> Option<FinalizedBlock>;
}
