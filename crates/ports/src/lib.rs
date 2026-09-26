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

    /// Post-execution root for `height`, or `None` when the block at
    /// `height` has not executed locally. `None` is explicit: a caller
    /// must never mistake "not yet executed" for an attested root —
    /// a `Hash::ZERO` sentinel here once let a forged execution
    /// certificate claiming a zero root "match" a height that had
    /// never run. Opaque to the engine — it embeds these bytes
    /// verbatim and never parses them (oai-spec.md §3, rule 5).
    ///
    /// Implementations with an async execution lane may wait for
    /// in-flight execution; callers that cannot afford to block must
    /// use [`attest_state_bounded`](Self::attest_state_bounded).
    fn attest_state(&self, height: Height) -> Option<StateAttestation>;

    /// [`attest_state`](Self::attest_state) with a ceiling on how
    /// long the call may wait for the execution lane. `None` means
    /// "not executed within `max_wait`" — the consensus vote path
    /// withholds rather than stall the pacemaker behind a lagging
    /// lane (a withheld vote is recoverable on a later delivery; a
    /// stalled consensus thread is not).
    ///
    /// The default delegates to [`attest_state`](Self::attest_state):
    /// synchronous apps never wait anyway. Apps with an async lane
    /// override this with a real timeout.
    fn attest_state_bounded(
        &self,
        height: Height,
        _max_wait: std::time::Duration,
    ) -> Option<StateAttestation> {
        self.attest_state(height)
    }

    /// The newest *executed* state root, without blocking. Returns
    /// `None` when nothing has executed yet.
    ///
    /// Consensus attaches this to outgoing votes as the validator's
    /// execution attestation (the input to [`types::ExecCertificate`]
    /// aggregation). It must never wait on in-flight execution — the
    /// vote path cannot afford to stall behind the execution lane,
    /// and a stale attestation is never wrong (its height is carried
    /// inside, so it simply certifies an older block).
    fn attest_latest(&self) -> Option<StateAttestation>;

    /// `true` while the app's execution debt exceeds its bounded
    /// window — the backpressure signal for an asynchronous
    /// execution lane. A committed block can never be dropped, so
    /// the lane's queue itself cannot be the bound; this flag is.
    ///
    /// The engine responds by withholding votes (throttling new
    /// commits at the source) and deferring commit walks until the
    /// flag clears — consensus stays live for catch-up, timeouts,
    /// and QC adoption, but nothing new is finalized into a lane
    /// that cannot keep up. This is deliberately a *pause*, not a
    /// block: a consensus thread stalled inside `finalize_block`
    /// cannot process timeouts and livelocks the pacemaker, while a
    /// withheld vote recovers on the next delivered proposal once
    /// the lane drains.
    ///
    /// The default returns `false`: synchronous executors apply
    /// the block inside `finalize_block`, so their execution debt
    /// is always zero.
    fn exec_saturated(&self) -> bool {
        false
    }

    /// Drain the validator-set transition pending in the app's
    /// executed state — the staking module's recorded key changes,
    /// validator additions, and removals from finalized blocks.
    ///
    /// This is the consensus-facing half of the epoch protocol: a
    /// `KEY_CHANGE`/`VALIDATOR_ADD`/`VALIDATOR_REMOVE` transaction
    /// lands in the module's pending queue when its block executes;
    /// the engine polls here each epoch-boundary pass and folds the
    /// deltas into the next `ValidatorSet`. Draining is destructive
    /// by design — the engine's rotation (and its WAL record of the
    /// resulting set) is the acknowledgment, so the queues must not
    /// re-report an enacted transition.
    ///
    /// The default returns an empty record for apps with no
    /// validator-set lifecycle (mocks, single-module executors).
    fn take_epoch_changes(&self) -> types::EpochChanges {
        types::EpochChanges::default()
    }

    /// Durability barrier for committed-block records.
    ///
    /// The engine invokes this immediately before any operation that
    /// fsyncs commit-bearing WAL state — signature-gated appends and
    /// compaction checkpoints — so an app whose commit journal
    /// batches fsyncs can flush its pending records *first*:
    /// WAL-durable commit evidence must never outrun the journal
    /// record a restart would need to re-drive the block's
    /// finalization. Implementations without a deferred-durability
    /// journal (mocks, synchronous executors) keep the no-op default.
    fn commit_durability_barrier(&self) {}
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

    /// The confirmed execution divergence that halted this engine's
    /// signing, if any. Engines that verify execution certificates
    /// (oxideBFT) report the mismatch here so node status plumbing —
    /// `/health`, `/metrics` — can surface the halt; engines without
    /// certificate verification (sequencer, mocks) inherit the
    /// default `None`, which means "cannot diverge-observe", not
    /// "healthy".
    ///
    /// Terminal once `Some`: the only safe recovery is certified
    /// state repair, never resumed participation.
    fn divergence(&self) -> Option<types::ExecDivergence> {
        None
    }

    /// The quorum-signed execution certificates this engine holds,
    /// for serving to state-sync clients. A syncing node verifies
    /// each certificate against its own validator-set checkpoint
    /// (weak subjectivity), so an engine only needs to hand over
    /// the certificates it has formed or verified — authenticity
    /// is established client-side, not by trusting the server.
    ///
    /// Engines without execution certificates (sequencer, mocks)
    /// inherit the empty default; their snapshots carry no
    /// quorum-signed anchor and a verifier must refuse them.
    fn exec_certificates(&self) -> Vec<types::ExecCertificate> {
        Vec::new()
    }
}
