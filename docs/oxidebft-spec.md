# oxideBFT Specification (v1, draft)

Status: **Draft.** The architecture this document pins is approved
(plan.md §2); the implementation lands in Phase 1 against the OAI
traits (`docs/oai-spec.md`) and must pass the conformance suite
(`ports::conformance`) before it ships. Where this spec and the OAI
spec disagree, the OAI spec wins (oxideBFT is an OAI engine; the
boundary contract is authoritative).

## 1. What oxideBFT is

`oxideBFT` is Oxide's default BFT consensus engine: a pipelined
two-chain HotStuff variant in the Jolteon / DiemBFT / AptosBFT family,
with BLS threshold signature aggregation, an active pacemaker, and
stake-weighted leader rotation. It orders opaque application messages
and emits finalized blocks to the application via the OAI; it never
executes them (oai-spec.md §1).

### Design goals (and the non-goals that follow)

1. **Tail-fork resistance.** A slow or malicious leader cannot stall
   finality: the pacemaker advances views on a timeout, and a
   supermajority of validators can sign a timeout certificate to force
   a view change without waiting for the leader.
2. **Pipelined throughput.** The two-chain structure (prepare →
   pre-commit → commit) is pipelined across heights: while height *h*
   is committing, height *h+1* is pre-committing and *h+2* is preparing.
   The leader's bottleneck is signature aggregation, not serial
   proposal latency.
3. **Decoupled execution.** Consensus output is an ordering; execution
   is an asynchronous downstream lane. The engine embeds the
   application's `StateAttestation` verbatim in later proposals and
   never parses it (oai-spec.md §3 rule 5).
4. **Pluggability.** oxideBFT is the *default* engine, not the *only*
   one. It implements `ports::ConsensusEngine`; the `MockEngine` and
   other alternative engines implement the same trait. The conformance
   suite is the contract.
5. **Determinism.** Given identical inputs (tx submissions + network
   message log), oxideBFT produces byte-identical finalized blocks
   (oai-spec.md §3 rule 3). This is what makes deterministic simulation
   possible.

**Non-goals (Phase 1):** leader reputation / PoS slashing (Phase 2,
needs the staking module), validator-set reconfiguration across
epochs (Phase 1 ships with a fixed validator set; epoch rotation is a
two-phase protocol layered on top), and mempool (the engine uses the
application's mempool via OAI in v1; a dedicated p2p mempool is a
later optimization).

## 2. The two-chain pipeline

oxideBFT chains three votes per block across three consecutive
heights, pipelining the HotStuff phases:

```
height h:    prepare  →  pre-commit  →  commit
height h+1:            prepare  →  pre-commit  →  commit
height h+2:                      prepare  →  pre-commit  →  commit
```

- **Prepare** — the leader proposes a block; validators sign a
  prepare vote once they have the parent's pre-commit certificate (so
  the chain is locked on a prefix).
- **Pre-commit** — once a prepare certificate (QC) forms for height
  *h*, the next leader (height *h+1*) embeds it in the *h+1* proposal;
  validators sign a pre-commit vote for *h*. This is the "lock" —
  honest validators will not prepare a conflicting block at *h*.
- **Commit** — once a pre-commit QC forms for *h*, the *h+2* leader
  embeds it; validators sign a commit vote for *h*. A commit QC for
  *h* is finality: the block at *h* is finalized and emitted via OAI
  `finalize_block`.

Pipelining means the leader at height *h* is simultaneously collecting
the commit vote for *h−2*, the pre-commit for *h−1*, and the prepare
for *h*. The three certificates travel in the proposals of *h*, *h+1*,
*h+2* respectively.

### Vote validity (engine-enforced)

A validator's prepare vote is gated on all of the following — each
rule exists because a concrete attack or wedge was found without it:

- **Current view.** The proposal's view must equal the voter's current
  view; stale views are already decided, premature ones would break
  one-vote-per-view.
- **One vote per view.** `last_voted_view` is monotonic; a second
  proposal in the same view is refused (and two conflicting votes
  for one view are slashing-grade evidence).
- **Height continuity.** The stamped height must be exactly
  `parent.height + 1`, where *parent* is the voter's highQC block
  (or the committed anchor below). Without this a Byzantine leader
  can stamp an arbitrary future height: the forged block is then
  committable at a height the chain never filled — a finalized gap —
  and every voter that signed it becomes per-height-locked at a
  height the honest chain still needs, permanently wedging quorum.
  Heights are therefore *derived*, never free.
- **Committed anchor.** With no highQC, the only voteable proposal
  extends the committed tip — height 0 / zero parent at genesis, or
  `last_committed + 1` across an epoch rotation (rotation resets the
  QC chain but heights continue). A made-up parent hash with a forged
  height is refused.
- **Parent binding.** `prev_block` must equal the voter's highQC
  block, and the embedded justify QC must be at least as recent
  (view ≥ highQC.view) — tail-fork resistance: a proposal that does
  not extend the highest notarized block is bypassed.
- **Structural justify rule.** `prev_block` must equal the embedded
  QC's `block_hash`: a block extends *exactly* the block its
  certificate notarizes. Honest proposals always satisfy this;
  decoupling them is a Byzantine-only construct — the commit rule
  walks justify edges while voters store the prev chain, so a
  crafted `prev ≠ justify` finalizes a block whose real parent was
  never committed (a finalized gap, and a same-height fork against
  validators that committed through the justify chain). The embedded
  QC's aggregate signature is also verified at vote time: it is
  commit evidence — its bitmap becomes the committed parent's
  attendance — so it must be a certificate, not claimed bytes.
- **Per-height lock with TC release.** Once a validator votes at
  height *h* it votes only that block at *h* — until a proposal
  arrives carrying a valid TC for the immediately preceding view.
  The TC is quorum-certified proof that the earlier view ended
  undecided, so re-voting the height cannot produce two commits:
  QC adoption is view-monotonic, and only the *newest* notarization
  can gather the child votes a commit needs. Without the release,
  a single equivocating leader could split the vote and wedge a
  height forever.

### The commit rule (recursive)

Adopting QC(*b*) for a stored block *b* finalizes **the whole
certified ancestor chain beneath it**, not just the single pending
tip: QC(*b*) plus *b*'s embedded QC satisfy two-chain for *b*'s
parent, and since `prev == justify` is enforced at vote time every
stored ancestor is itself certified with a certified child. The
engine walks `prev` links from *b*'s parent back to the finalized
prefix (or an unstored block — storage is prefix-closed, so a gap
means "already finalized") and commits in height order.

A single-link "commit the pending block when a child QC arrives"
rule is *incomplete*: if a QC is adopted before its block is stored,
or a newer QC leapfrogs an undelivered one, the skipped link is never
revisited and the finalized map gains a hole — the `InvNoGap`
counterexample the TLA+ model produced. The recursive rule also makes
the future block-import/catch-up seam safe by construction: imported
ancestors commit with the chain that certifies them.

### Why two-chain, not three-chain or one-chain

- **One-chain (basic HotStuff)** finalizes in one round but requires
  the leader to wait for the previous commit before proposing — no
  pipelining, leader-bound throughput.
- **Three-chain (original HotStuff)** pipelines prepare → pre-commit →
  commit → decide across four heights; the extra phase buys stronger
  chaining but adds a height of latency for no extra safety over the
  two-chain form.
- **Two-chain (Jolteon)** is the minimal pipelined form that preserves
  HotStuff's safety and liveness: a block is committed two heights
  after it is prepared, and the lock (pre-commit) prevents conflicting
  prepares. This is the choice of DiemBFT, AptosBFT, and (in spirit)
  MonadBFT.

## 3. Certificates and signatures

- **Vote.** A validator signs `(height, view, phase, block_hash)` with
  its BLS secret key. The signature is a single BLS signature on a
  domain-separated hash (domain separation is mandatory — see
  production-rust skill §6: every hash input carries a domain tag so
  a prepare vote can never be confused with a pre-commit vote).
- **Quorum certificate (QC).** An aggregate BLS signature over the
  votes for a single `(height, view, phase)`, plus the bitmap of
  signers. Forms when ≥2f+1 of total stake signed (f = maximum
  Byzantine validators). Stake-weighted: a validator with 10% stake
  contributes 10% to the quorum, not 1/N.
- **Aggregate verification.** A QC verifies in one BLS aggregate
  check, not N individual checks — this is the throughput lever.
  Batch verification of many QCs at once is a further optimization
  (Phase 1 benchmarks gate this).

### Why BLS (not Ed25519 or ECDSA)

BLS supports signature aggregation: N validators' votes compress to
one group element, and verification is one pairing check (or one
multi-exponentiation in the pairings-free formulation). Ed25519
QCs are a list of N signatures — N× the wire size and N× the verify
cost. For 20–50 validators the difference is modest; for the
gigagas-per-second target with frequent view changes, aggregate
verification is the design choice that keeps the consensus hot path
off the floor.

## 4. The pacemaker

The pacemaker drives view changes. A *view* is a leader round within
a height; views advance on timeout or on a timeout certificate.

- **Active, not reactive.** The pacemaker broadcasts a `Timeout`
  message when its local timer for the current view expires; it does
  not wait for a leader to self-report failure. This is the
  Jolteon/AptosBFT design: proactive view sync keeps finality moving
  under a faulty leader.
- **Timeout certificate (TC).** Once ≥2f+1 validators sign a timeout
  for view *v*, the next leader (view *v+1*) embeds the TC in its
  proposal (`header.timeout_cert`), proving it is the legitimate
  successor. The embedded TC has a second, load-bearing role: it is
  the evidence that releases per-height vote locks left over from
  the timed-out view, so a split view can be retried at the same
  height. A TC is the "force a view change without the leader"
  mechanism — tail-fork resistance.
- **Continuous.** The pacemaker does not stop on finality; it
  advances views as long as there is work, which (with pipelining)
  is always.

## 5. Leader rotation

- **Stake-weighted round-robin.** Within an epoch, the leader for
  view *v* is `validators[v mod N]`, weighted by stake so a high-stake
  validator leads proportionally more often. The schedule is a
  deterministic function of the epoch's validator set and the view
  number — no VRF, no randomness in the hot path (determinism
  contract, oai-spec.md §3 rule 3).
- **Rotation on view change.** Every view change rotates the leader;
  a stuck leader is bypassed after one timeout, not repeatedly
  retried.
- **Epoch boundaries.** The validator set is fixed within an epoch
  and rotates across epochs (Phase 1 ships fixed-set; epoch rotation
  is a two-phase handoff layered on the existing vote pipeline — old
  set commits the last block of the old epoch, new set takes over at
  the next height).

## 6. The OAI surface

oxideBFT implements `ports::ConsensusEngine`:

- `submit_tx` → forwards to the application's `ingest_tx` (oxideBFT
  v1 uses the app's mempool; a dedicated p2p mempool is a later
  optimization).
- `run_until_idle` → drives the event loop: process incoming votes,
  form QCs, advance views on timeout, emit `finalize_block` when a
  commit QC forms. In Phase 1 this is event-driven (async); the
  conformance suite drives it synchronously via the deterministic
  runtime.
- `finalized_height` / `finalized_block` → the engine's finalized
  output, stable and unique after commit (oai-spec.md §3 rule 1).

The application implements `ports::AppInterface`; oxideBFT calls
`prepare_proposal` when it is leader, `process_proposal` when it is
a replica (static validity only — never execution, oai-spec.md §3
rule 4), `finalize_block` on commit, and `attest_state` to embed
post-execution roots in later proposals.

## 7. Safety and liveness arguments (sketch)

**Safety.** Two honest validators cannot commit different blocks at
the same height: a commit QC requires ≥2f+1 votes, and ≥f+1 of those
voters are honest (f Byzantine ≤ total − 2f−1). An honest validator
signs at most one prepare per (height, view), so two conflicting
commit QCs would require ≥f+1 honest validators to have signed
conflicting prepares — impossible, because the pre-commit lock
prevents a honest validator from preparing a block that conflicts
with its locked block.

**Liveness.** Under partial synchrony (GST after some finite time),
the pacemaker eventually advances views until a honest leader is
chosen; that leader's proposal gathers ≥2f+1 votes within the
network's eventual delay bound, forming a QC and advancing the
pipeline. Tail-fork resistance (TC-forced view change) ensures a
perpetually faulty leader cannot stall finality indefinitely.

## 8. Phase 1 implementation order (staged)

1. **Vote and QC types** in `types` (BLS signature wrapper, QC with
   signer bitmap, timeout certificate) + codec impls.
2. **Pacemaker** as a state machine over views (no networking):
   timeout → TC formation → view advance. Unit + property tests.
3. **Single-leader happy path** (no view changes): prepare →
   pre-commit → commit pipeline, emitting `finalize_block` on
   commit. Conformance suite must pass.
4. **View changes** via TC: faulty leader bypass. Conformance suite
   + deterministic simulation under the `runtime` crate.
5. **BLS aggregation** integration (blst or bls12-381 crate; exact-pin,
   ≥7 days published, GPL-3.0-compatible). Benchmark gate: aggregate
   verify of a 50-validator QC under the single-threaded budget.
6. **Epoch rotation** (two-phase handoff).

Each stage ships behind the conformance suite; no stage closes until
the suite passes.
