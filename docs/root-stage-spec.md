# Root stage: computing the state root off the execution path (spec, draft 15 Nov 2026)

Status: steps 1-4 IMPLEMENTED behind `Executor::with_root_stage(true)` (default off); audit still required before
default-on. Approved by the user 15 Nov ("lagged sharded root: yes", recommendations accepted).
Implements plan W4 of `docs/hft-production-plan.md`.

**Implementation note (supersedes Section 1's "EVM block record's state root is filled by the root stage" and open
question 1).** The EVM block hash covers `stateRoot`, and EIP-2935 (Prague) writes the parent block hash into state at
the start of the next block, so block h+1's execution depends on a hash that would contain root(h): a true data
dependency that forbids overlapping root(h) with execute(h+1). Resolution (the "delayed state root" used by other
deferred-execution EVM chains): with the root stage on, the header of block h carries the state root of block
h - `ROOT_HEADER_LAG` (4; zero before that). The block is sealed, flushed and visible on the exec stage immediately (no
RPC hiding needed); the root stage only folds the trie and publishes root(h) for attestations and for later headers.
Attested roots are unchanged. Consequence: `eth_getBlockByNumber(h).stateRoot` is the root of h-4 in this mode.

**Measured (laptop, `chain_mix`, 8 threads):** EVM transfers, pipeline loop 42.0k tx/s synchronous, 68.9k exec lane,
74.5k with the root stage (execution capacity 1/(plan+dispatch+end_block) up from 80k to 125k tx/s; the loop is now
bound by the serial propose phase, 85k tx/s). CLOB at 100k accounts: end_block 1.89 -> 0.73 us/tx, loop 138k -> 220k
tx/s (+59%), within 1.6x of the 1k-account figure (352k).

## 0. What already exists (corrects an assumption in the plan)

The reference stack's "execution after consensus, lagged app hash" is **already how Oxide is built**:

- Consensus orders blocks and does not execute them. `finalize_block` journals the block and pushes it to the
  **exec lane**, a worker that runs `execute_block` in order (`crates/executor/src/app_iface.rs`).
- Block headers do not carry the executed root. Executed roots travel as `(height, state_root, epoch)` execution
  attestations embedded in *later* proposals and quorum-certified (`docs/oai-spec.md`, `crates/consensus/src/verify.rs`).
  The lag is therefore already variable and bounded by `EXEC_LANE_DEPTH` (`exec_saturated` back-pressures proposals).
- `attest_state(h)` waits until the lane has executed `h` and returns `state_roots[h]`.

So no consensus or header change is needed. The defect is one level down: **inside the lane, executing block h and
computing its root are one serial step.** Measured (laptop, `chain_mix`, `StageReport`):

| Traffic | execute (plan+dispatch) | root work in `end_block` | share of the lane's time |
|---|---|---|---|
| EVM transfers, 1,428/block | ~5.1 us/tx | 4.6-6.6 us/tx | ~48% |
| CLOB orders, 100k accounts | ~1.9 us/tx | 1.9 us/tx (EVM MPT update, ~29k touched accounts/block) | ~50% |
| CLOB orders, 1k accounts | ~1.95 us/tx | 0.02 us/tx | ~1% |

Overlapping the two stages lifts the lane from `1/(E+R)` to `1/max(E,R)`: up to ~2x at 100k accounts and for EVM
blocks, with the root cost then hidden until it becomes the longer stage.

## 1. Design

Two stages inside the lane, connected by a bounded queue:

```
exec stage (thread 1):  execute h  ->  emit RootDelta(h)  ->  execute h+1 ->  ...
root stage (thread 2):                 apply RootDelta(h) -> root(h) -> publish state_roots[h]
```

1. **`RootDelta(h)`** is everything the root of block h needs, captured at the end of `end_block` on the exec
   stage: per module, the list of changed leaves `(key, leaf_bytes | Deleted)` in canonical order (EVM: touched
   accounts as `(keccak(addr), account RLP)` and the touched storage roots; exchange: the folded maps' changed
   entries; the nonce map delta). It is a value, not a reference into live state, so execution of h+1 can mutate
   freely.
2. **Root maintainer** per module owns the commitment structure (EVM: `trie_leaves`, `retained_branches`,
   `storage_root_cache`; exchange: the fold maps). Only the root thread mutates it. It applies deltas strictly in
   height order and returns `root(h)`.
3. **Canonical root** `canonical_state_root(module_roots, nonce_root)` is computed by the root stage once every
   module root for h is ready. The value is **bit-identical** to today's synchronous root (same leaves, same order),
   so attestations, snapshots and replicas on the old code agree during a rolling upgrade.
4. `state_roots[h]` is published by the root stage. `attest_state(h)` waits for the **root stage** watermark instead
   of the exec watermark (`ExecSync` gains `rooted: Option<u64>`).

### Back-pressure and bounds

- Root queue depth `ROOT_LANE_DEPTH` (unit: blocks; proposed 4; tradeoff: deeper hides root jitter but holds more
  deltas in memory and lengthens recovery replay). When full, the exec stage blocks (deterministic: it only changes
  timing, never results).
- The existing exec-lane bound (`EXEC_LANE_DEPTH`) keeps counting *rooted* debt, so proposers see the true lag
  (finalized minus rooted), not the exec watermark.
- `RootDelta` memory is bounded by `ROOT_LANE_DEPTH x touched-per-block x ~150 B`; at 30k touched accounts per block
  and depth 4 that is ~18 MB.

### What must NOT read the commitment structure from the exec stage

Today modules call `state_root()` mid-flow in a few places (EVM `end_block` seals it into the block record,
`eth_getProof`, snapshots). Rules:

- The EVM block record's `state_root` field is filled by the **root stage** when `root(h)` completes (the sealed
  block is persisted by the root stage for height h, in the same atomic batch as before). RPC reading block h before
  it is rooted gets `pending` for that field; `eth_getBlockByNumber` for h waits (bounded) or returns the latest rooted
  block's data per the existing "not yet executed" convention. Decision needed (Section 5).
- Proofs (`eth_getProof`, account/storage proofs) are served at rooted heights only, from the root maintainer's
  structures under a read lock between deltas.

## 2. Determinism and safety argument

- Inputs to the root stage are produced deterministically by execution of h (same on every replica); the root stage
  is a pure fold over them in height order, so every replica computes the same `root(h)` regardless of thread timing.
- Queue order = height order; one consumer; no CAS-by-timing. (This is the rule the reference stack also insists on.)
- Failure containment: a root-stage panic marks the lane dead exactly like an exec-stage panic (`lane_dead`), so
  attesters do not hang and the node halts participation rather than attesting a wrong root.
- Divergence repair (`engine.rs` repair path comparing the local root with a quorum-certified one) is unchanged: it
  reads `attest_state`.

## 3. Interaction with durability, snapshots, restart

- **Journal** (`journal_append` before any effect) is unchanged: blocks are durable before execution.
- **Checkpoints / snapshots** need a consistent (state, root) pair: they are taken at a barrier that drains the root
  queue (`rooted == executed`). Barrier cost is at most `ROOT_LANE_DEPTH` root computations.
- **Restart replay** re-executes from the journal and re-emits deltas; roots are recomputed; the planted
  `state_roots` for replayed heights come from the root stage as it catches up. The halt-height and
  `state_root_at(halt)` path reads the rooted map.
- **Backend flush** (EVM `account_flush_ops`) stays on the exec stage (state, not commitment). History/receipts roots
  that depend only on the block's own txs (`receipts_root`, `transactions_root`) stay where they are (they need no
  trie state); only the state-root field moves.

## 4. Test and acceptance gates

1. **Bit-identity differential:** for generated block streams (EVM transfers, contract calls with storage, CLOB mixes,
   deletions, EIP-158 empties, snapshot import mid-stream), the synchronous root and the root stage's root are equal for
   every height. Run in CI as a property test with a fixed seed set plus the existing sparse-vs-full suite pointed at
   the maintainer.
2. **Mutation check:** break delta ordering or drop a deleted leaf; the differential must fail.
3. **Crash/replay drill:** kill at every pipeline point (exec mid-block, delta queued, root mid-apply); restart; all
   heights re-rooted equal the pre-crash attested roots.
4. **Back-pressure test:** slow root stage by injection; proposals are refused at the configured lag; no unbounded
   memory; no deadlock with the exec-lane condvar.
5. **Performance gate (`chain_mix`, laptop A/B, interleaved, spread reported):** EVM transfer finalize >= 1.5x the
   pre-change figure at 1,428 tx/block; CLOB at 100k accounts within 1.5x of the 1k-account figure (today 1.8x).
   The `stages,` line reports `end_block_us` falling to ~0 and a new `root_us` / `root_wait_us` pair.
6. **Divergence safety:** a deliberately wrong delta on one replica in the sim is detected by quorum attestation
   mismatch and triggers the existing halt/repair path.

## 5. Open questions for review

1. RPC semantics for a block that is executed but not yet rooted: wait (bounded) vs `pending` field vs hide the block.
   Recommendation: hide until rooted (simplest, matches Ethereum clients that expose a block only once fully sealed),
   at the cost of RPC latency of one root computation.
2. `ROOT_LANE_DEPTH` default (4 proposed) and whether it should count against `EXEC_LANE_DEPTH` or add to it.
3. Whether the exchange's folded maps (cheap today) move to the root stage immediately or only the EVM MPT does in
   phase 1. Recommendation: EVM first (the measured cost), exchange once batch settlement lands.
4. Sharded root (account buckets rooted in parallel across cores) as phase 2 after the single root thread is the
   measured bound; requires a consensus-visible commitment change only if the MPT is replaced for native balances, which
   this spec does **not** propose.

## 6. Rollout

| Step | Change | Evidence |
|---|---|---|
| 1 | Module trait: `end_block` additionally returns/stashes a `RootDelta`; EVM maintainer extracted from `state_root()` with the same code | differential test (gate 1) green with the stage still synchronous |
| 2 | Root thread + bounded queue + `rooted` watermark; attestation waits on it | gates 2-4 |
| 3 | EVM block record's state root filled by the root stage | RPC conformance vs reth |
| 4 | Barrier for snapshots/checkpoints; replay drill | gate 3 |
| 5 | Perf gate and devlog; default on after a soak | gate 5 |
| 6 | (optional) parallel/sharded maintainer | measured bound first |

Risk summary: moderate. The commitment value is unchanged, so no protocol or on-disk format change; the risk is
ordering/barrier bugs, covered by the differential, mutation and crash drills before default-on.
