---
name: performance-first
description: HFT-grade performance engineering rules for Oxide — what "hot path" means here, the zero-allocation/zero-syscall/no-locks discipline, fixed-point arithmetic, cache-line hygiene, benchmark gates, and the profiling workflow required before optimizing anything.
---

# Performance-First Engineering (Oxide)

Oxide competes with C++ matching engines (CME/Nasdaq) and Hyperliquid's Rust
node. Performance is a **protocol property**, not a cleanup task. These rules
apply to every commit that touches a hot path.

## What is a hot path?

Anything executed per-order, per-transaction, per-view, or per-block on the
critical commit pipeline:

- matching engine operations (insert/match/cancel) — **per-order**
- codec encode/decode of consensus and tx messages — **per-message**
- journal append + MMR update — **per-block batch (amortized per-op)**
- signature verify/recover (aggregated/batched) — **per-view**
- state reads during execution — **per-tx**

Cold paths (genesis, epoch transitions, RPC queries, snapshot import, config)
are exempt — optimize for *clarity* there.

## The Hot-Path Discipline (rules in force)

1. **Zero allocation.** No `Vec::push` past capacity, no `String`, no
   `format!`, no `Box`, no iterators that box. Data lives in arenas/pools
   preallocated at startup (slab `OrderPool`, journal buffers, codec
   scratch). CI enforces with an allocation-count harness on benched loops.
2. **Zero syscall.** No file IO, no locks that hit futex, no time calls, no
   dynamic dispatch through `dyn` in the loop. `fdatasync` happens once per
   block via group commit, off the consensus critical path.
3. **No locks on hot state.** Single-writer per shard (per market, per
   module subtree). Cross-thread hand-off = bounded SPSC/MPSC rings
   (crossbeam). If you need a lock, you need a different architecture.
4. **Fixed-point only.** Prices/quantities are `u64` scaled integers
   (1e8 / 1e6 — see primitives). Floats in state are forbidden:
   they break cross-validator determinism. Multiply via `u128`, divide
   with round-half-up (`mul_div_half_up` — the one rounding direction
   for the whole codebase, chosen as the fairness rule at the single
   implementation site in primitives), document rounding on every op.
5. **Cache-line hygiene.** Hot structs are `#[repr(C, align(64))]`, fields
   ordered hot→cold with a comment marking the split; no false sharing
   between writer threads; sequential (array) layouts beat pointer-chasing
   (intrusive lists via `u32` indices, flat tick ladders, bitboards with
   `countl_zero`).
6. **Batch everything.** Signatures (BLS aggregate, ed25519 batch), journal
   appends (one CRC'd record per block batch), network (vectored IO),
   market data (frame coalescing). A per-item syscall/flush is a bug.
7. **No `dyn`, no serde, no tracing in the loop.** Static dispatch via
   generics resolved at node wiring; codec is codec (memcpy-shaped);
   logging uses pre-resolved static strings and counters, never formatting
   in the loop.

## The Budget Comment

Every hot-path function documents its measured budget at the top:

```rust
/// Matches an incoming order against resting liquidity.
///
/// Budget (criterion, `bench/matching.rs`, M2 dev machine):
///   p50 ≈ 180ns, p99 ≈ 900ns for 10-level sweep.
/// Gate: p50 < 200ns, p99 < 1µs (README.md → Roadmap, Phase 3 gate).
/// If you make this slower, the block cadence math in
/// docs/oxidebft-spec.md breaks.
```

If no budget is stated, the function is cold-path — say so explicitly
(`/// Cold path: RPC only. Clarity over speed.`).

## Measure, then optimize

1. Reproduce with `cargo bench -p <crate>` (criterion) — never trust
   intuition; the C++ literature does not transfer automatically.
2. Profile before changing anything: `cargo flamegraph --bench <bench>`,
   `dhat` for alloc counting, `cargo asm` for the disassembly of the loop.
3. Optimize the top item only. Re-bench. Commit with before/after numbers
   in the message.
4. Scalar clarity beats clever: SIMD/`unsafe`/huge-pages only when a gate
   is failing and the win is >5% and reproducible on the bench rig.

## Hardware assumptions (validator spec, README.md → "Why Oxide exists")

- Validators: 16–32 modern cores, NVMe, ≥128GB RAM, 100Gbps peering.
- Dev bench rig for gates: 16-core x86_64; local dev machines re-baseline
  relative numbers only.
- NUMA: engine threads pin to the socket owning their arena; the node
  config exposes `numa_node` and fails fast on invalid topology.

## Memory rules

- Arenas are sized from genesis config (e.g., `MAX_RESTING_ORDERS = 2^20`
  per market) — sizing bugs are consensus bugs; document the formula.
- Huge pages (2MiB) for arenas via `mmap(MAP_HUGE_2MB)` where the OS
  allows; graceful fallback to regular pages with a startup warning.
- Free-lists recycle; a leak of slab nodes is detectable (arena
  high-water mark metric exported per market).

## Non-goals

- Do not micro-optimize cold paths (RPC, explorer, config).
- Do not introduce `unsafe` for <5% wins.
- Do not cache-micro-optimize before the algorithmic shape is right
  (O(1) ladder + O(1) intrusive FIFO + O(1) bitboard BBO first).

## Matcher hot-path invariants

- The matching engine's `submit_order` path must not allocate after
  the first call (reusable fill buffer, pre-sized settlement batch).
- Risk checks (rate limit, fat-finger, size cap, resting cap) are
  O(1) and run *before* balance reservation — they must not touch
  the matching engine or balance cache on rejection.
- The condvar-based wakeup pattern replaces busy-loop polling: the
  matcher thread blocks on `condvar.wait_timeout` until signalled
  by the producer or the timeout elapses. No 10ms yield loops.
- Resting-order tracking uses a `HashMap` per account — acceptable
  because it is checked once per order submission, not per fill.
- Market data publishing serializes once and broadcasts the same
  string to all subscribers — no per-subscriber serialization on
  the hot path.

## RPC cold-path invariants

- The RPC server is *not* on the consensus hot path — it may use
  tokio, serde_json, axum, and other standard async dependencies.
- Rate limiting uses a simple fixed-window counter with atomic
  operations — no per-request allocation, no mutex on the hot path.
- Market data subscribers use `tokio::sync::mpsc::unbounded_channel`
  — a slow client misses updates (intentional: market data is lossy
  by design and must not back-pressure the matching engine).
