# Multi-core, multi-lane EVM execution (spec, draft 15 Nov 2026)

Status: 3.1 (lanes) and 3.2 (seal worker + lazy EIP-2935) IMPLEMENTED and differential-tested on the laptop (15 Nov);
lanes are OFF by default because they did not pay here, the seal worker is on whenever the root stage is on. Speed claims for
both await the x86 box. Results are in the "Built and measured" section at the end. User decision (15 Nov): raise
the block budget to measured capacity (done: 600M gas, 8 MiB), then multi-core plus multi-lane work. This spec turns the
laptop measurements into a core budget and a build order, and says what only the x86 box can settle.

## 1. Where one transaction's CPU time goes (laptop, signed plain transfers, 600M-gas blocks of 28.5k txs)

| Stage | Cost per tx | Parallel today? | Cores for 1M tx/s |
|---|---|---|---|
| Admission: sender recovery (`ingest_tx`) | 30-34 us | yes, linear to 32 threads (box, earlier run) | ~34 |
| Plan (hash, gates) | 0.11 us | hash pass parallel, gate loop serial | 0.1 |
| Dispatch (decode, execute, receipts) | 1.4 us | decode parallel, execute serial lane | 1.4 |
| End of block: patch, header tries, history seal, undo index | 2.0 us | `rayon::join` of 2 tries only | 2.0 |
| Root stage (trie fold, own thread) | ~1 us | its own thread | 1 |
| **Total** | ~36 us | | **~39 cores** |

Admission is 90% of the CPU. The execution pipeline (plan + dispatch + end_block = 3.57 us) caps one lane at ~280k tx/s;
beyond that it needs lanes, but only when admission has >= ~10 cores to feed it. So the build order is: keep admission
linear, then lane the execution, then the seal.

## 2. What the measurements ruled out

- Block-STM-style speculation for light transactions: ~1 us of work per tx against ~10 us of contention at 8 threads
  (summed busy time 15-19 ms vs 1.5 ms single-threaded for 1,428 txs); sharding the version store and mimalloc did not
  change it. Now routed to the serial lane unless >= 1 in 4 txs touches a contract (`HEAVY_TX_SHARE_DENOM`).
- Greedy data parallelism inside the seal (parallel ordered tries: 46 -> 10 ms in isolation, bit-identical): slower in the
  pipeline on 6P+2E cores because the other stages already occupy them. Needs the box to evaluate; implementation was
  reverted (kept in git history of this branch's devlog entry, not in the tree).

## 3. Design

### 3.1 Execution lanes without a shared structure (sender-partitioned, optimistic, total fallback)

For a batch classified light (plain value transfers; today's `prefer_serial`), partition transactions by
`hash(sender) mod L` into L lanes (L = exec cores). Each lane owns a private `CacheDB` over the immutable block-start
snapshot and runs its senders' transactions in canonical sub-order with the existing `try_native_transfer`. There is no
version store, no publish, no locks. Recipient credits and the coinbase tip are additive, so each lane records them as
deltas; senders are exclusive to a lane, so their final state is taken directly.

Exactness preconditions, checked per batch before any lane result is applied:
1. every tx is a plain transfer to a code-less recipient (checked on the snapshot; light-batch classification already
   excludes calldata and creates);
2. no recipient is also a sender in this batch and no sender or recipient is the coinbase (a ring pattern or a payment to
   a sender in the same block makes a balance depend on cross-lane order);
3. every lane tx succeeds through `try_native_transfer` (no `None`, no failed receipt).
If any precondition fails the lane results are discarded and the whole batch runs on the serial lane from the untouched
snapshot (lanes only wrote private overlays, so abort is free). Merge: apply sender states, then recipient and coinbase
deltas in lane order (commutative), then replay history/undo/receipt recording in canonical order. Expected effect: the
parallel part is the ~0.8 us of per-tx execution; the serial part drops to ~0.6 us of recording and merge.

Gates: (a) differential test, same random batches (distinct senders; ring; self-pay; payments to later senders; failing
txs; contract mixes) through serial lane and lanes, comparing per-tx outcomes, receipts, state root, undo; (b) mutation check
(drop the ring detection: must fail); (c) `chain_mix` dispatch us/tx at 8 and 16 threads on the x86 box, with the explicit
claim to falsify: dispatch scales >= 3x from 1 to 8 lane threads.

### 3.2 Seal lane (header tries, history, undo index) on its own thread

Needs one protocol-neutral change: EIP-2935 writes block h's hash into state at the start of block h+1, and the hash covers
the receipts and transactions roots. Make that write **lazy**: record `pending_parent_hash` at `begin_block`, apply it at
`end_block` (or before the first transaction that can read it: any batch containing calldata, a create, or a call to the
history contract address, which forces `wait(seal(h))` first). Plain-transfer blocks cannot read the slot, so the final
state is identical. Then block h's seal (roots, `seal_taken`, undo index push and prune, backend batch) runs on a seal thread
while block h+1 executes. `versioned.push` (~12 ms per 28k-account block) moves with it; historical reads at heights
>= `sealed_height - 1` must wait for the seal watermark (reads below it are unaffected).
Gates: differential run of a stream with and without the lazy write, including blocks that call the history contract
(must be identical), plus RPC historical-read conformance at the head boundary. Expected: exec lane ~3.57 -> ~1.6 us/tx.

### 3.3 Admission

Already linear in cores. Remaining work is operational: pin verify workers (`intake_threads` = physical cores), keep the
single shared locks (`executed_nonce`, `preverify_cache`) off the per-tx path (they are < 1 us of 30), and benchmark on a
homogeneous-core Linux box; the laptop's mixed P/E cores understate scaling (8 threads give 147k tx/s vs 29k x 6 + E cores).
Bundles (`docs/bundle-auth-spec.md`) are the only way to cut recovery cost per order; EVM transactions are individually
signed by protocol, so 1M EVM tx/s is ~34 recovery cores regardless of executor work.

### 3.4 Core budget by box

| Box | Admission | Exec (lanes) | Seal | Root | Predicted EVM tx/s |
|---|---|---|---|---|---|
| 8 cores | 5 | 1 | 1 | 1 | ~150k (admission-bound) |
| 16 cores | 11 | 2 | 2 | 1 | ~320k |
| 64 cores | 48 | 6 | 5 | 2-3 | ~1.0M+ (needs lanes 3.1 and 3.2) |

## 4. Order of work and what needs the box

1. (laptop) lanes 3.1 with the differential harness; measure on the laptop only for correctness.
2. (laptop) lazy EIP-2935 write + seal thread 3.2 with differential and RPC tests.
3. (8-core x86 box) establish the single-lane baseline and the admission-bound figure; prove the 150k prediction.
4. (16-core box) 3.1 and 3.2 enabled: confirm exec lane scaling and the 320k prediction; find the next bound.
5. (64-core box, only if 4 holds) the 1M run.

## 5. Already done toward this (this branch)

Root stage (state root off the exec lane), gas-capped proposal walk, preverify cache O(block), serial lane for light
batches, one parallel tx-hash pass per block, block budget defaults at measured capacity, per-stage recorder and ratio gates.

## 6. Built and measured (laptop, 15 Nov, 8 threads, 28.5k-tx blocks)

**Lanes (3.1), `modules/evm/src/lanes.rs`, opt-in via `EvmModule::set_exec_lanes`.** Exact: differential tests compare per-tx
events, state root, root vs a full rebuild, sealed block roots, the undo accumulator and the touched set against the serial
lane for fresh-recipient, shared-recipient and (falling back) ring / unaffordable / pay-a-later-sender batches; removing the
sender/recipient disjointness check fails the ring case. Result: **not faster here**. Phase timers: the parallel part is only
2.0 ms per 28.5k-tx block (0.07 us/tx) while the serial merge into the global structures costs 25-30 ms (credit map clones 4.4,
undo and touched sets 8.4, applying new accounts to the main cache 11-14, record preparation 5.8 even when parallel, history
append 2.7). Per tx, the serial lane's ~1 us of bookkeeping into four global structures (account cache, `touched` BTreeSet,
undo map, history) is the floor, not the ~0.3 us of arithmetic the lanes parallelize. Dispatch: 1.52-1.65 us/tx with lanes vs
1.37-1.46 serial. To make lanes pay, those four structures must become per-lane or sharded with a parallel merge (a larger
redesign); on a many-core box the parallel record preparation may already help, hence "opt-in, evaluate on the box".

**Seal worker + lazy EIP-2935 (3.2), `modules/evm/src/rootstage.rs`.** The exec stage now only captures (patch delta, pending
history, undo, gas) and hands the seal (header tries, history record, undo index, backend batch) to an `evm-seal` thread; the
block hash needed by block h+1's parent-hash write is owed and settled at end of block for plain-transfer batches, or before
the first batch that can execute contract code. The base-fee update uses the gas the exec stage recorded (it cannot wait for the
seal). `executed` still means executed, sealed and rooted. Tests: worker vs inline seal over 14 blocks with heavy and light
batches and a 3 ms seal delay that forces the lazy path (roots, sealed block hashes, history slot right after a contract batch);
removing the pre-batch resolve fails the slot check. Result: `end_block` 2.0 -> 0.37 us/tx on the exec lane; transfers loop
196k -> 226k tx/s (sync reference unchanged), 5.4x the 42k at the start of the day. Dispatch rises 1.45 -> 2.1 us/tx because the
seal and root threads now compete for the laptop's six fast cores; the box is needed to see the true overlap.
