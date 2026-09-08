# Oxide Application Interface (OAI) Specification (v1)

Status: Phase 0 scope — the *contract* between consensus engines and the
application, plus the reference `MockEngine` and the conformance-suite
skeleton. The default engine (oxideBFT, `docs/oxidebft-spec.md`) and the
adapter family (sequencer, …) all program against this document. If code
and spec disagree, one of them is wrong — fix it in the same PR.

## 1. What OAI is

The ABCI-analog boundary (the consensus ⇄ app seam in Cosmos-style
chains), adapted to Oxide's two defining architectural facts (plan.md §1):

1. **Engines order; they never execute.** A consensus engine's output
   is a finalized, reorg-free *ordering* of opaque transaction bytes.
   Execution happens downstream in the app's execution lane; the only
   execution-derived data flowing back is the opaque
   [`StateAttestation`] embedded in later proposals.
2. **The chain's identity is engine-agnostic.** Followers, indexers, the
   journal, and RPC consume the app's `BlockRecord` ledger — never
   an engine's internal header format. Swapping the engine changes
   consensus certificates, not the chain's data model.

## 2. The contract (v0 traits, sync)

v0 signatures are **synchronous** on purpose: the reference path
(MockEngine + deterministic runtime + conformance suites) is inherently
synchronous, and premature async is an API every adapter must honor
forever. Phase 1 revisits this with the real oxideBFT loop — options
recorded in §5, decision deferred until there is a second consumer.

```rust
/// Implemented by the application (executor + mempool + state).
pub trait AppInterface: Send + Sync {
    /// Mempool intake: engines that collect transactions push them here;
    /// engines with their own mempool may no-op (their proposals still
    /// arrive via prepare_proposal). Idempotence is per-tx-hash.
    fn ingest_tx(&self, tx: TxBytes) -> MempoolAck;
    /// Leader hook: assemble the next proposal ≤ budget.
    fn prepare_proposal(&self, budget: &BlockBudget) -> Proposal;
    /// Replica hook: static validity (sizes, fees, nonce shape,
    /// availability pre-checks). NEVER executes. Rejecting here is a
    /// protocol message, not an application error.
    fn process_proposal(&self, proposal: &Proposal) -> Verdict;
    /// Ordering finalized for `height`: hand to the execution lane.
    /// Must return immediately (execution is async by design); the ack
    /// asserts reception, not execution.
    fn finalize_block(&self, block: &FinalizedBlock) -> CommitAck;
    /// Post-execution roots for embedding in the next proposal.
    fn attest_state(&self, height: Height) -> StateAttestation;
}

/// Implemented by consensus engines (oxideBFT is the default).
pub trait ConsensusEngine: Send {
    /// Feed a transaction into the pipeline (→ app.ingest_tx for the
    /// default path).
    fn submit_tx(&mut self, tx: TxBytes) -> MempoolAck;
    /// Drive the engine until it has no immediately-executable work
    /// (the deterministic-runtime-friendly step function; the real
    /// engine's I/O is event-driven in Phase 1).
    fn run_until_idle(&mut self);
    /// Highest finalized height, if any (engine-attested ordering only).
    fn finalized_height(&self) -> Option<Height>;
    /// The finalized block at `height` (None if not finalized).
    fn finalized_block(&self, height: Height) -> Option<FinalizedBlock>;
}
```

## 3. Behavioral rules (what makes an engine a valid OAI engine)

These are exactly what the conformance suite asserts
(`consensus-conformance`, plan.md §2.5); every scenario below has a test
against every registered engine:

1. **Finality is final.** After `finalize_block` is emitted for height
   h, the engine never re-emits h and never finalizes a different block
   at h. (No-reorg-after-finalize.)
2. **Heights are a sequence.** Finalized heights are strictly
   increasing from genesis (0) with no gaps — a gap would mean the
   engine skipped ordering a height it committed to.
3. **Determinism under identical inputs.** Two engines fed the same tx
   submission sequence produce byte-identical finalized blocks. (For
   oxideBFT this is network-shape-dependent; the suite runs it under
   the deterministic runtime with a fixed message log.)
4. **Ordering-only.** An engine's accept/reject in `process_proposal`
   must be derivable without executing transactions. (The suite feeds
   proposals that would revert on execution and requires acceptance —
   ordering is unconditional on execution results.)
5. **Attestations are opaque.** Engines embed `StateAttestation` bytes
   verbatim; they never parse or interpret them.

## 4. Data model (`types` crate)

| Type | Meaning |
|---|---|
| `TxBytes` | Opaque transaction bytes (newtype over `Vec<u8>`) |
| `BlockBudget` | `max_bytes`, `max_gas` — proposal size envelope |
| `Proposal` | height, txs, optional attestation bytes |
| `Verdict` | `Accept` or `Reject { reason }` (reason: static string v0) |
| `MempoolAck` | `Accepted` or `Rejected { reason }` |
| `FinalizedBlock` | height + ordered `TxBytes` — the engine's whole output |
| `CommitAck` | height — reception assertion from the app |
| `StateAttestation` | height + root — opaque to the engine |
| `BlockRecord` | the engine-agnostic canonical ledger entry: height, prev record hash, tx-root, optional attestation |

All implement the `codec` traits (deterministic wire forms; the codec's
round-trip properties apply to all of them).

## 5. Open decisions (explicitly deferred to Phase 1)

- **Async boundary shape:** native `async fn` in traits (AFIT) with a
  boxing layer for `dyn`, vs. a channel-based boundary (which also
  suits out-of-process engines). Decided when
  oxideBFT's real loop exists; v0 sync signatures were chosen so the
  decision is not pre-baked.
- **Epoch/validator-set queries:** oxideBFT needs the staking module's
  validator set at epoch boundaries; v0 omits the hook because MockEngine
  has no epochs. Added in Phase 1 with the first consumer.
- **Followers:** a `finalized_stream` subscription API replaces the
  pull-shaped `finalized_block` for live consumers; pull shape is v0
  (sufficient for conformance).
