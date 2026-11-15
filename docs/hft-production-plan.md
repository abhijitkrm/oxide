# Production-grade, HFT-performant Oxide: plan (15 Nov 2026)

Status: proposal for review. Inputs: our own measurements (devlog, `chain_mix`, rig results) and a study of
Mint-Network/evm-node `box/next` (Go; docs `clob-10m-first-principles`, `clob-deferred-exec-design`,
`clob-engine-hotpath-design`, `box-session-plan-10m`, `practices`, `bench-2026-11-05-report`,
`evm-throughput`; harness `x/clob/keeper/spec_budget_test.go`, `tests/bench/clob/`, `prototype/matchengine`).
I read their docs and harness layout, not their keeper code line by line; claims about their internals below
come from their own write-ups.

## 1. Where each stack really is (scopes differ, so read the labels)

| Quantity | Oxide (Rust) | Mint evm-node (Go) |
|---|---|---|
| Matching engine, one core, no auth/persistence | 20.6M mixed ops/s (48 ns/op) | ~33 ns/item matching, ~0.29 us/item for a whole hot-pair phase (~3.4M/s per market) |
| Executor/chain path per item, signed, real state | CLOB through real `Executor`, laptop: admission 153k tx/s (secp256k1 recovery, 8 threads), finalize 343k tx/s | executor 0.23 us/item (128 traders) to 0.87 (100K traders); whole chain 15.6 us CPU/item on the box (5 Nov) |
| Real node, signatures, persistence, consensus | not measured on a box; matcher TCP 72k/s (ed25519 per order), 2.2M (session MAC) | **1.05-1.1M items/s**, single node, 32-core, 100K+ traders, ed25519 per bundle (5 Nov); laptop 65-95K items/s |
| EVM transfers | real revm 2.5 GG/s parallel (microbench); chain path finalize 76k tx/s after today's fix, was 60k; flat from 8 to 64 threads | ~3.5k tx/s (txpool-bound; their own lever #10) |
| Trader scaling | **unmeasured** beyond small account counts (one cache-capacity cliff already found) | measured and reported: cost/item x5.9 from 128 to 100K traders, x2.9 from 8 to 100 markets, compounding x30 |
| Multi-node | sim + chaos (10k scenarios), no geo testnet | 4-validator runs, lane gossip, availability certs, 2-chain, state-sync drills |

Honest reading. Rust is faster on the raw engine and on EVM execution, as expected. Neither project has shown 10M
items/s end to end: Mint's measured, replicated, signed, persisted number is ~1.1M/s on one 32-core node; "10M" is
their design target with a budget (6.4 us core time per item, <=0.1 us serial). Where Mint is ahead is **method**: every
stage has a cost-per-item number, the axes that break systems (traders, markets, depth, load) are swept, every
performance change is gated by byte-identical differential checks against the reference, and results are kept honest
with invalid-run rules. Our headline numbers are mostly engine or in-process figures; the production-grade gap is the
unmeasured middle (accounts, persistence, signatures, consensus, many validators), not the matcher.

## 2. What the study taught (to adopt, not to copy)

1. **Per-item budget first.** 10M/s on 64 cores = 6.4 us all-in, <=0.1 us serial per item. Every stage gets a row and an
   owner; a stage that touches every item serially is a defect.
2. **Cost must be flat in n, m, d, load.** Their phase-0 matrix (traders {128..100K} x markets {8,32,100}) found the
   real problems (per-touched-account work, per-market passes). We have not run it.
3. **Signatures bound the node, not matching.** 10M sigs/s is 430 cores at 43 us. One signature must cover a bundle
   (64 items = 0.67 us/item, 1024 = 0.04). We already have session MAC and gateway-cert schemes; bundle auth and
   cheapest-reject-first (dedup digest ring: 2.3 us -> 5 ns per resent item) are the missing intake pieces.
4. **Partition by account and by market, deterministically.** Account shards reserve in block order (never lock-free
   CAS: timing-dependent outcomes split validators); one writer per market; fill deltas to the owning account shard.
5. **Execute after consensus, commit a lagged root.** The header commits to the root of height h-k, so the root, the
   persistence and the snapshot leave the critical path; backpressure rule `E(H) >= H-k`, proposals carry no trading
   items when the backlog exceeds D. This is exactly our diagnosed EVM `end_block` ceiling, solved by design.
6. **Resident dense state.** Flat pointer-free arrays, u32 indices, per-height overlay of changed slots, persistence by
   delta, sparse per-token slots for many markets. (Go needs this to dodge GC; Rust gets it cheaper, but the memory
   and cache-miss argument is identical: three random misses at 100 ns is the whole 10M budget of a core.)
7. **Method as policy** (their `practices.md`, worth adopting nearly verbatim): reproduce before fixing, regression test
   that fails on old code, interleaved A/B with spread (inside the spread = no change), invalid-run rules (disk full,
   lagging node, generator can't keep up, unexpected rejections), judge by the **critical path** not total CPU, profile
   every perf change, laptop for correctness and relative A/B only, box for core scaling, network, memory at scale,
   3-hour box cap with a written question list and no coding on rented time.
8. **Shadow mode.** New executors run beside the reference and compare every touched balance, order and next-ID after
   each block, with rollback tests that are mutation-checked. We have differential tests for roots; we need the same
   for the exchange executor path.

## 3. Gaps in our repo, ranked by risk to the goal

| # | Gap | Evidence |
|---|---|---|
| G1 | No end-to-end signed+persisted+replicated number | only in-process and single-component figures |
| G2 | Trader-count and market-count scaling unmeasured | `AtomicBalanceCache::new(n)` capacity cliff found by accident; benches use small account sets |
| G3 | Serial per-block fixed work (EVM state root + seals; CLOB per-tx charge path) | EVM end_block was 8.6 ms of ~14 (now 4.6); plan+dispatch ~4 |
| G4 | Settlement and durability ceilings | one in-flight batch of <=65,536 legs; durable ack not pipelined; deferred chunks not durable |
| G5 | Intake: per-order signature, no bundle auth, no reject-first ordering | 72k/s per-order ed25519; admission 153k/s secp256k1 |
| G6 | EVM propose phase (`Mempool::select_with_gas`) ~80k tx/s; blocks gas-capped ~1.4k transfers | chain_mix propose column |
| G7 | Root commitment is synchronous, unsharded | spec needed before code |
| G8 | Production readiness: external review, geo testnet, multi-host benchmarks, upgrade path, observability SLOs | `production-readiness.md` open gates |
| G9 | Bench integrity: modeled vs real, hard-coded sizes, no regression gates in CI | uniswap_transfer mislabel, evmscale thread bug |

## 4. Workstreams

Each lists the change, the gate that proves it, and the evidence class (laptop = correctness and A/B; box = scaling).

### W0. Measurement spine (first; everything else is judged by it)
- `chain_mix` becomes the scenario driver: traders {128, 10k, 100k, 1M} x markets {8, 32, 100} x mix {transfer, clob,
  mixed} x depth, with warm-up heights, signed txs, real executor. Output is one table: us CPU/item and serial us/item
  per stage (ingest, verify, propose, plan, execute, seal/root, persist), flat-or-not.
- Per-stage recorder in the executor (cheap counters behind a feature, not ad hoc eprintln): ingest, plan, dispatch,
  end_block pieces, state_root, flush. The phase timing I used today becomes permanent.
- Interleaved A/B script (A,B,A,B, spread reported), invalid-run rules enforced by the script (non-zero rejections,
  generator lag, disk), results to `runs.tsv`.
- Gate: every cell of the matrix has a number and an owner; cost-per-item targets written next to the numbers.

### W1. Correctness harness for fast paths
- Reference-vs-fast differential for the exchange/matcher executor: per block compare balances, resting orders,
  next order id, fills, state root. Property tests over generated streams (cancels, amends, STP, partial fills,
  reject-heavy), plus the existing sim for byzantine/ordering faults.
- Rollback/fork tests for any versioned state (mutation-checked: break the undo, test must fail).
- Rule: no perf change merges without a test that fails on the old behavior and a bit-identical root check.

### W2. Intake (target: <=1 us/item incl. verify)
- Bundle authentication (one signature over item digests, N=64..1024) as a lanes scheme; per-order and MAC stay
  selectable (swappable seams are already the architecture).
- Cheapest-reject-first order: frame/size -> per-key rate and fee -> dedup (digest ring of admitted batches, per-tx
  registry) -> signature -> stateful checks. Resend of an admitted batch refused before decode.
- Zero-copy decode straight into the block's item arrays; verify workers pinned per core; retail single-signature lane
  bounded so it cannot starve bundles.
- Gate: intake us/item at 100k traders, 64 cores; invalid/duplicate floods cost <=10 ns/item.

### W3. Execution (target: executor <=0.3 us/item, zero serial per item)
- Resident dense accounts (`tid x token` flat arrays, per-height overlay), account-shard reservation in block order,
  per-market single-writer engines, fill deltas applied per account shard, sparse per-token slots for 40+ markets.
- Replace the generic per-tx path (`charge_and_execute_run`, per-tx fee charge, KV write per op) for exchange traffic
  with batch-level settle (we already have tag 16 committed batches); keep the generic path for fee-paying modules.
- Hot market beyond one core: batch-auction option (opt-in per market) and/or within-market parallel pre-trade
  checks; single-market ceiling reported separately (Mint's: ~3.4M/s on a laptop core).
- Gate: cost/item flat from 128 to 1M traders and 8 to 100 markets (within 1.5x); shadow equality (W1).

### W4. Commitment and persistence (spec in `docs/` first: it changes attestation, state sync, light clients)
- Lagged state root: header at h commits to root of h-k; root, history seal and persistence computed on a worker
  pipelined with h+1; backpressure rule and snapshot-at-executed-height defined in the spec.
- Sharded root: account buckets rehashed only when changed, shard roots combined; EVM MPT root keeps bit-identical
  Ethereum semantics, computed off the critical path (and the 16-way top-nibble parallel hash remains an option).
- NVMe journal, group commit, pipelined durable ack, durable deferred chunks, background snapshots, recovery =
  snapshot + log replay with measured replay speed vs live speed (catch-up margin >=2x).
- Gate: persistence <=0.2 us/item; kill-all and state-sync drills green; identical roots across validators.

### W5. Replication and consensus
- Lane gossip by owners, consensus orders batch digests (proposal size independent of item count), availability
  certificates, 2-chain with timeout certificates evaluated; multi-validator benchmark on separate hosts.
- Gate: 4 validators on 10/25G sustain >=70% of single-node rate, zero state-root divergence, bounded queues under 10x
  bursts, recovery after leader loss.

### W6. EVM path
- Pipeline `end_block` via W4; replace `select_with_gas` O(n) work; revisit `parallel_threshold`; batch dispatch
  granularity (1.3 us/tx is too small to parallelize per tx: group by sender/chunk); keep reth as correctness oracle.
- Gate: EVM finalize scales with cores until the gas-limit-bound block size, not flat from 8 threads; roots identical.
- Reality check: the gas limit caps a block (~1.4k simple transfers per 30M gas), so 1M tx/s needs ~700 blocks/s of that
  size or a higher limit/shorter blocks; the plan must state which (a parameter decision, see section 6).

### W7. Production grade (runs in parallel from the start)
- Security: external review scheduled now (long lead), threat model for intake/DoS/limits, fuzz targets for every wire
  format and the new bundle path, TLA+ model extended for lagged roots, chaos sim extended to the new executor.
- Operations: SLO metrics per stage (us/item, queue depths, lag k, root wait), alert thresholds, runbooks, config and
  defaults inventory, upgrade/migration path for state-format and commitment changes, snapshot/restore drills.
- Release: CI gates beyond fmt/clippy/test: benchmark regression gates with stored baselines and noise bands, reproducible
  builds, `cargo deny`, SBOM, tagged releases with changelog and "In plain words" notes.
- Testnet: 20-50 validator geo-distributed testnet only after W3-W5 gates; soak 7 days with fault injection.

### W8. Rig and box discipline
- Finish the pre-flight (whole-rig container dry run with injected failure, bench audit, expected ranges).
- Box sessions: written question list, laptop dry-run, 3 h cap, no coding, profiles archived; first box 8-16 cores
  x86 (x86 SIMD and real `perf`), later a 2-host session for network and consensus.

## 5. Order and gates

| Phase | Work | Exit gate |
|---|---|---|
| A (now, laptop) | W0 spine, W1 harness, W8 pre-flight, EVM stage recorders, bench audit | full matrix numbers with owners; CI regression gate live |
| B (laptop + 1 small box) | W2 intake, W3 resident accounts + batch settle, W6 quick wins | cost/item flat vs traders/markets; shadow-equal; box confirms core scaling to 16 |
| C | W4 spec -> lagged root + journal; W6 pipelining | root off critical path; recovery and replay-speed drills |
| D (multi-host box) | W5 replication, burst/overload drills, 100k-1M traders | 4 validators, 10G, >=70% of single node, zero divergence |
| E | W7 review, geo testnet, soak | review findings closed; 7-day soak clean |
| F (stretch) | 10M target: bundle auth at 1024, 64-core, multi-market, hot-market batch auction | measured 10M signed, persisted, replicated, or a measured account of the binding stage |

No phase starts before the previous gate passes unless this plan says so (consistent with AGENTS.md).

## 6. Decisions (user, 15 Nov 2026)

1. **Retail share: under 5%** of load may arrive individually signed. Verify budget is sized for 95%+ bundle/MAC/
   gateway traffic; the retail lane is bounded and may not starve bundles.
2. **Lagged sharded root: approved.** Spec first (`docs/`), audit before it ships; header at h commits to root of h-k.
3. **EVM target: move both** block gas limit and block time as needed; the plan must report the throughput for each
   setting (gas limit x block interval grid) so the binding parameter is visible.
4. **Hot markets as opt-in batch auctions: approved** (per-market flag; continuous matching stays the default).
5. **Hardware ladder:** 8-core x86 box until we can prove hardware, not code, is the limit; then 16 cores to scale;
   then the multi-validator set only after single-node limits are at physics limits (memory bandwidth, NVMe, NIC).

## 7. First two weeks of concrete work (no box needed)

1. Land permanent stage recorders in `executor`/`evm` and the CSV format; wire into `chain_mix`.
2. Extend `chain_mix` with traders x markets x depth axes and warm-up; run the matrix on the laptop; commit numbers.
3. Shadow-compare harness for the exchange executor; property tests; CI regression gate on three benches.
4. Write the lagged-root spec (`docs/`), including state sync and light-client effects, for review.
5. Finish the pre-flight; then request the box `user@host`.
