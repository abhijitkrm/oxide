# Oxide — HFT / Low-Latency Engineering Audit

**Revision audited:** `e98bf2f` (post gate-6 conformance work), working tree clean.
**Validation pass:** `87d63b5` (docs-only delta from the audited revision:
`docs/devlog.md` + this file — all cited code line numbers re-checked
line-by-line and unchanged), 2026-10-04. **Result: 19/19 findings
CONFIRMED, none yet implemented**; verdicts and per-finding evidence in
§7. Two new findings filed (F-20, F-21).
**Date:** 2026-10-04.
**Scope:** hot paths of the matching/trading stack, consensus/validator
loop, executor + EVM execution, p2p transport, storage journal,
primitives/codec, latency instrumentation, and the benchmark/gate
apparatus.
**Method:** source-level review against the `performance-first` and
`benchmarks` skills' rules (zero-alloc / zero-syscall / no-locks /
fixed-point / cache-line hygiene / batch-everything), plus verification
of every quantitative claim against the committed benches and their
documented gates. All citations are `file:line` against the audited
revision.

---

## 1. Executive summary

**Verdict: the foundations are genuinely HFT-shaped; the residual risks
are concentrated in idle/wakeup behavior, one unimplemented hardware
requirement (pinning/NUMA), and a handful of latent hot-path hazards
that are currently unwired.**

The matching engine, order pool, id map, fixed-point layer, wire codec,
and WAL are engineered to the standard this project claims — index-based
intrusive structures on cache-line-aligned slabs, O(1) bitboard best-price
discovery, typed scale-units with one documented rounding direction, and
a WAL that folds fsync into the append syscall with preallocated extents.
These are not accidental; they carry budget comments and head-to-head
benchmarks.

What stands between this codebase and an honest "nano-second system
design" claim is a short list of precise, fixable items:

| # | Severity | Finding | Location |
|---|---|---|---|
| F-01 | **High** | Validator pump sleeps 1 ms at the end of *every* pass (comment claims otherwise) — up to 1 ms added latency per inbound message | `crates/node/src/validator_net.rs:1965` |
| F-02 | **High** | No CPU pinning, no NUMA awareness anywhere — a mandatory rule in the `performance-first` skill is unimplemented | repo-wide (no `numa_node`, no affinity) |
| F-03 | **High** | The "SPSC" ring is `crossbeam_channel` (MPMC), and every push takes a global mutex + `notify_one` | `crates/matcher/src/ring.rs:33,67-71,202-216` |
| F-04 | **High** | Matcher sequencer spins unbounded on a client-drainable response ring (latent; the invariant that prevents it is non-local) | `crates/matcher/src/lib.rs:1126-1139` |
| F-05 | **High** | Market-data publisher would serialize JSON + lock + allocate per subscriber on the sequencer thread (unwired; fix before wiring) | `crates/matcher/src/market_data.rs:212-288` |
| F-06 | **High** | The EVM parallel path re-runs secp256k1 recovery (~30 µs/tx) on every tx — the preverify cache is bypassed by design on the fast path | `modules/evm/src/batch.rs:656-675` |
| F-07 | Medium | Generic OCC scheduler is bench-only; if wired, it spawns OS threads per block, clones all results, and SipHashes already-hashed keys | `crates/executor/src/occ.rs:127,265-272,335-356` |
| F-08 | Medium | Events allocated per tx, stored twice, deep-cloned per block | `crates/executor/src/exec.rs:614-623` |
| F-09 | Medium | Per-swept-level integer division from a redundant price→index round trip the bitboard already resolved | `crates/trading/src/engine.rs:790-807` + `book.rs:328-340` |
| F-10 | Medium | Socket buffer sizing absent — default kernel buffers cap single-stream throughput far below 100 Gbps peering | repo-wide |
| F-11 | Medium | TLS write path ~4 µs/frame under two mutexes (documented, opt-in; budget note) | `crates/p2p/src/tcp.rs:245-253` |
| F-12 | Medium | Enforced throughput floors are 4–5× below claims; the ≥1 GG/s EVM gate has no CI assertion | `crates/devnet/tests/trading_throughput.rs:157-162,230-235` |
| F-13 | Low | Metrics recorder allocates a `String` per record (fine per-block; must never move per-order) | `crates/metrics/src/lib.rs:97-113` |
| F-14 | Low | Per-batch buffer alloc in `write_frames`; `vec![req]` per single order | `crates/p2p/src/tcp.rs:166-183`, `crates/matcher/src/server.rs:165-172` |
| F-15 | Low | Async-side `yield_now` spin loops on tokio workers | `crates/matcher/src/server.rs:106-133` |
| F-16 | Low | FIX/WS parsers allocate per message (acknowledged debt; bench is informational-only) | `crates/matcher/benches/alloc_accounting.rs:9-17` |
| F-17 | Info | Rounding wording: code is half-up everywhere (documented); skill text says "banker's" — reconcile the skill text | `crates/primitives/src/lib.rs:501-542` |
| F-18 | Info | `acquire_ring` starvation under saturation is documented behavior — acceptable, but it is a venue-fairness SLO decision | `crates/matcher/src/lib.rs:1235-1239` |
| F-19 | Info | Settlement exposure window: 100 ms default batch interval between fill and on-chain settlement | `crates/matcher/src/settler.rs:190,338-358` |
| F-20 | Low | Shared `Wakeup` panics on poison where the repo's own poison contract mandates recovery; supervision registers but never restarts | `crates/matcher/src/ring.rs:67-71,81-88` |
| F-21 | Low | `SpscSender::is_connected` is dead code with a tautological predicate — it can never return `false` | `crates/matcher/src/ring.rs:218-223` |

All 21 findings re-verified against source at `87d63b5` — per-finding
verdicts and evidence in §7.

The single highest-value fix is **F-01** (one-line shape change with a
1 ms p99 win on every inbound consensus message). The single most
strategic fix is **F-03** (a purpose-built SPSC ring plus a
lock-free parked-flag wakeup removes the last shared-memory
serialization points from the order path).

---

## 2. Critical-path latency map (as measured/claimed today)

Composed from the committed benches, with the taxes this audit found
called out separately. Machine context: M-series dev machine for all
numbers (the 16-core x86_64 rig does not exist yet — absolute claims
pending).

| Path | Hop | Cost | Source |
|---|---|---|---|
| **Order → ack** | engine `place()` full call (rest+cancel pair gate) | p50 < 400 ns (pair) ⇒ ≥5M ops/s | `crates/trading/benches/matching.rs:12-17` |
| | single-level match, full `place()` | p50 ≈ 470 ns measured; per-match-op ≈ 160–190 ns | `crates/trading/benches/matching.rs:132-140` |
| | resting-fold tax (on-chain exchange only) | +≈160 ns per resting-order mutation | `crates/trading/src/engine.rs:313-317` |
| | Ed25519 verify (batched, multi-scalar) | ≈3× cheaper/order than per-item | `crates/matcher/src/server.rs:68-74` |
| | ring handoff (push + wakeup) | + global mutex lock + notify (**F-03**) | `crates/matcher/src/ring.rs:202-216` |
| **Consensus view** | durable vote append (`vote_signed_wal`) | **≈5.6 ms** (fsync-dominated; O_DSYNC fold) | `crates/consensus/benches/engine.rs:12-40` |
| | propose / form QC / deliver QC (durable) | ≈5.2 ms / 2.4 ms / 1.4 ms | same |
| | inbound message pickup | **up to +1 ms** idle sleep (**F-01**) | `crates/node/src/validator_net.rs:1965` |
| | TLS frame write (when mTLS on) | ≈4 µs vs ≈3.4 µs plaintext | `crates/p2p/benches/tls_contention.rs:1-15` |
| | view timeout budget | base 1,000 ms, max 20,000 ms | `crates/config/src/lib.rs:751-752` |
| **Block execution** | EVM tx (21k-gas transfer), serial | ≈29.3k tx/s | `crates/executor/benches/uniswap_transfer.rs:10-13` |
| | EVM tx, parallel (8-core M1) | ≈118–128k tx/s ≈ 2.5 GG/s | same |
| | secp256k1 recovery per tx | ≈30 µs ("single most expensive per-tx operation") | `crates/executor/src/lib.rs:885-886` |
| | parallel-path recovery re-run | **+≈30 µs/tx inside execution (F-06)** | `modules/evm/src/batch.rs:656-675` |
| **Settlement** | fill → batch seal → submit | 100 ms default window (design) | `crates/matcher/src/settler.rs:190` |

Reading the table: the *engine* is ns-class; the *system* around it is
µs-to-ms-class, dominated by fsync (by design), the pump idle sleep
(F-01), and crypto recovery (F-06). The gap between the two is where
this audit focuses.

---

## 3. Findings

### F-01 — Validator pump sleeps 1 ms at the end of every pass **[High]**

**Location:** `crates/node/src/validator_net.rs:1956-1965` (loop begins
at `:911`; the drain is `while let Some(msg) = transport.recv()` at
`:1002`).

**Evidence.** The main consensus pump ends every iteration with:

```rust
std::thread::sleep(std::time::Duration::from_millis(1));
```

with no guard — it is reached whether or not the pass processed
messages. The in-code comment claims "when messages arrive, `recv()`
returns them immediately and the sleep is never reached" — that is not
what the code does; the sleep runs unconditionally at the end of each
pass. `transport.recv()` is non-blocking (`crates/p2p/src/tcp.rs:2003-2015`
uses `try_recv`), so the sleep is the *only* idle-wait mechanism.

**Impact.** Any message that arrives while the pump is sleeping waits up
to 1 ms (mean +0.5 ms) before intake. On the propose→vote→QC critical
path this lands directly in view latency: a 1 ms tax per inbound hop, at
a cadence (1 s base timeout) where honest per-view work is ~6 ms. It is
also 1,000 wakeups/s/core of pure overhead. At "nano-second system
design" ambitions, this is the largest single avoidable constant in the
node.

**Recommendation.** Replace try_recv+sleep with a real wakeup:

1. Preferred: block on the inbound channel with a timeout
   (`crossbeam_channel::Receiver::recv_timeout` or std mpsc equivalent)
   — the reader threads' `send` wakes the pump in ~µs; the timeout only
   bounds shutdown-check latency.
2. Or reuse the in-repo `Wakeup` pattern (condvar + latch) already used
   by the matcher (`crates/matcher/src/ring.rs:44-89`) and the exec lane
   (`crates/executor/src/lane.rs:64-76`) — the two places that got this
   right.
3. If a spin-then-park hybrid is desired for tail latency, make it a
   config knob (`--idle-spin-us`) with the default remaining
   power-friendly.

Also correct the comment, which currently misdescribes the behavior.

### F-02 — No CPU pinning, no NUMA awareness **[High]**

**Location:** repo-wide. `grep -rn "numa|sched_setaffinity|core_affinity|pin_to_core"`
returns nothing; `Config` has no `numa_node`; threads are spawned via
`std::thread::Builder` with names only
(`crates/primitives/src/lib.rs:1021-1035`).

**Evidence.** The `performance-first` skill states: "NUMA: engine
threads pin to the socket owning their arena; the node config exposes
`numa_node` and fails fast on invalid topology." None of this exists.

**Impact.** On a 16–32 core multi-socket validator:

- the matcher sequencer, exec lane, consensus pump, and p2p readers can
  migrate across sockets mid-flight — every migration is a cold-cache
  and cross-socket-memory event on a hot loop;
- arenas (order pool, balance flat array, journal buffers) are first
  touched by whichever thread constructs them and then read by others —
  cross-socket NUMA traffic on the hottest reads (balance loads, order
  nodes);
- tail latency inherits scheduler jitter that pinning would remove.

**Recommendation.** Linux-first implementation:

1. `Config` gains `numa_node: Option<u32>` (+ per-role overrides later);
   validate at startup against `/sys/devices/system/node/` and fail fast.
2. Pin: matcher sequencer, exec lane, consensus pump, one p2p reader set
   per socket; first-touch arenas from the pinned thread (or
   `numa_alloc_onnode` when `libc` is already in the tree).
3. Non-Linux: log a startup warning ("NUMA pinning unavailable"), keep
   the same config surface.
4. Document the arena-first-touch rule in `OrderPool`/`AtomicBalanceCache`
   doc comments so construction-time pinning stays correct.

### F-03 — The "SPSC" ring is an MPMC channel; every push takes a global mutex **[High]**

**Location:** `crates/matcher/src/ring.rs:33` (`crossbeam_channel::bounded`),
`:44-89` (`Wakeup`), `:202-216` (`push` → `self.wakeup.signal()`).

**Evidence.**

- The ring is `crossbeam_channel::bounded(capacity)` — a lock-free
  *MPMC* queue. Its docs even concede the point: "an MPMC channel with
  a `Clone` handle is only 'SPSC' by convention" (`ring.rs:114-118`).
  The MPMC machinery (per-item stamping/atomics, block indexing)
  costs materially more per handoff than a purpose-built SPSC ring
  (single producer store + consumer load over cache-line-separated
  head/tail indices, cached local indices, no CAS on the fast path).
- `Wakeup::signal()` — called on **every successful push from every
  connection** — locks a global `Mutex<bool>` and calls `notify_one`.
  That is a contended lock plus a possible futex on the order-path
  handoff, and it contradicts the module's own claim of "a single
  atomic store + `notify_one`" (`ring.rs:59-61`).

**Impact.** With the shipped defaults (256 rings, 8192 capacity —
`crates/matcher/src/server.rs:942-945`) the wakeup mutex is the shared
serialization point for all concurrent order batches, and every ring
op pays MPMC overhead. Both are inside the measured matcher throughput
number, so fixing them moves the headline figure, not just theory.

**Recommendation.**

1. Implement a true SPSC ring in `ring.rs` (std-only, ~150 lines):
   `head`/`tail` on separate cache lines, cached indices per side,
   `Acquire`/`Release` ordering, value slots in a power-of-two array.
   Keep `crossbeam_channel` for the control channel only.
2. Replace `Wakeup` with a parked-flag protocol: consumer stores
   `parked = true` (Release) immediately before `cond.wait_timeout`;
   producer does `if parked.swap(false, AcqRel) { lock + notify }` —
   the common (busy consumer) path becomes one relaxed atomic read, no
   lock, no syscall. Re-check the latch after parking to close the
   race (or keep the existing flag *inside* the mutex and only take the
   lock when the atomic says the consumer is parked).
3. Add a loom/proptest test for the ring (single-producer FIFO, no
   lost wakeup under interleavings) — the repo's testing standards
   already require property coverage for concurrency primitives.

### F-04 — Matcher sequencer spins unbounded on a client-drainable resource **[High]**

**Location:** `crates/matcher/src/lib.rs:1126-1139`.

**Evidence.** When pushing a response batch back to a client's ring:

```rust
Err(crate::ring::PushError::Full(returned)) => {
    pending = returned;
    std::hint::spin_loop();
}
```

— an unbounded spin on the single sequencer thread that owns every
market's order book. The only exit is `Disconnected` (socket closed).

**Reachability, precisely:** under the current lease invariant (one
batch pushed per lease, one response popped per lease —
`crates/matcher/src/server.rs:99-140`) a compliant client cannot fill
its response ring, so this path is latent today. But the invariant is
non-local: the sequencer's liveness depends on every current and future
transport honoring "≤1 response per lease". A client that stops reading
while keeping the socket open holds its lease; any future change that
pushes two responses per lease (e.g. streaming partial fills) turns this
spin into a total venue halt for *all* markets — a single-client DoS on
the shared sequencer.

**Recommendation.**

1. Bound the spin (e.g. 100 `spin_loop` iterations, then
   `thread::yield_now`, then a short `park_timeout`); after a bounded
   budget, treat the client as dead: drop the batch and force-release
   the lease — mirroring the market-data slow-consumer policy
   (disconnect, `crates/matcher/src/market_data.rs:270-287`).
2. Add a `debug_assert!` (or counter) pinning the "≤1 response in
   flight per ring" invariant so a violation is loud in tests.
3. Same review for the sequencer's control-channel and any other
   client-controlled wait on this thread.

### F-05 — Market-data publisher is a sequencer-thread hazard waiting to be wired **[High]**

**Location:** `crates/matcher/src/market_data.rs:212-288`.

**Evidence.** The module doc says "the matching server calls
`publish_l1`, `publish_trades`, …" — i.e. publishing is designed to run
on the calling (sequencer) thread. What `broadcast` does there:

- `serde_json::to_string(msg)` — a `String` allocation + formatting per
  update (`:255`);
- `lock_state(&self.subscribers)` — a global mutex over the subscriber
  list (`:256`);
- `json.clone()` per subscriber — one heap allocation per subscriber
  per update (`:278`);
- `retain` walks all subscribers per publish (`:261-284`).

Currently there are **no production call sites** (grep: only
`market_data.rs` tests), so this is latent — the correct time to fix it
is before it is wired, because as designed it would put JSON
serialization, a global lock, and O(subscribers) allocations on the
thread whose job is nanosecond-scale matching.

**Recommendation.**

1. Sequencer side: build a small `Copy` snapshot struct (feed, market,
   prices, qtys, seq) and `try_send` it into a bounded ring — no
   serialization, no lock, no allocation.
2. A dedicated publisher thread drains the ring, serializes once, and
   fans out with `Arc<str>` (or `Bytes`) so subscribers share the
   buffer instead of cloning it.
3. Keep the existing slow-consumer eviction policy (it is correct);
   add an `evicted_subscribers` SLO note to the operator docs.
4. If L2/L3 depth feeds are wired later, the snapshot struct must be
   bounded (fixed depth) or moved by shared ownership — never by
   cloning a `Vec` per subscriber on the publisher's hot loop.

### F-06 — Parallel EVM path re-runs secp256k1 recovery on every tx **[High]**

**Location:** `modules/evm/src/batch.rs:656-675`
(`handle_batch_parallel_preverified`), contrasted with
`modules/evm/src/module_impl.rs:448-453` (serial path: "skips
secp256k1 recovery entirely").

**Evidence.** The parallel path's doc is explicit: "We do NOT trust
`pv.sender` … re-recover the sender from the signature and check it
matches" — the recovery runs inside `par_iter`, per tx, on every
execution. Recovery is "the single most expensive per-tx operation,
~30 µs/tx" (`crates/executor/src/lib.rs:885-886`); the whole preverify
cache (`crates/executor/src/exec.rs:368-398`) exists to amortize it.
At the default `parallel_threshold = 100`
(`crates/config/src/lib.rs:476-478`), every batch of ≥100 txs takes the
path that re-pays it.

**Impact.** ~30 µs of core-time per tx, every block, on the parallel
path — the single most expensive per-tx operation, paid again for work
the node already did at ingestion (the preverify cache exists precisely
to amortize it). The measured parallel throughput (≈118–128k tx/s on
the 8-core dev machine) is the number this tax lives inside.

**Recommendation.** Extend the proof-token pattern the matcher already
proves out (`VerifiedOrder`/`VerifiedAction` —
`crates/matcher/src/protocol.rs`) to the executor's preverify cache:

1. The cache stores a token (tx-hash-keyed, produced only by local
   recovery at ingestion, unforgeable in-process — same discipline as
   `VerifiedOrder::new`).
2. The parallel path consumes the token and skips recovery; uncached
   txs (first-seen from the proposer) take the current re-recovery
   branch.
3. Document the trust boundary precisely: the token proves *this node*
   recovered the sender; it does not trust the proposer.
4. Re-bench `tps_rw` before/after; this should move the parallel
   number materially.

### F-07 — Generic OCC scheduler: bench-only, and wrong-shaped if wired **[Medium]**

**Location:** `crates/executor/src/occ.rs` (`ParallelScheduler`),
used only by `crates/executor/benches/uniswap_transfer.rs` and
`occ.rs` tests (grep confirms no production call sites). Production
executes through the module batch path
(`crates/executor/src/exec.rs:490-527`, `dispatch_run` at `:368-398`);
the EVM module's own sender-grouped parallelism
(`modules/evm/src/batch.rs`) is what the tps_rw numbers measure.

**Issues to fix before wiring:**

- `std::thread::scope` spawns `num_threads` OS threads **per
  `schedule()` call** (per block) plus a `Vec<Mutex<Vec<R>>>`
  (`occ.rs:331-349`). Thread spawn ≈10–50 µs each — at 16 threads
  that is up to ~0.8 ms/block of pure setup, plus per-block allocs.
  Use a persistent worker pool (or rayon) created once.
- The flatten phase clones every result: `out.extend(…iter().cloned())`
  (`occ.rs:351-356`) — a full copy of every `TxExecution`.
- Every write value is cloned into the cumulative set:
  `record_write_key(*k, v.clone())` (`occ.rs:265-272`) — doubles
  write-set memory traffic per tx.
- `HashSet<OccKey>` uses the std default (SipHash) over keys that are
  *already* keccak-derived 32-byte hashes (`occ.rs:127`) — a
  truncated-key identity hasher is ~free here.
- Doc/impl mismatch: header says "using rayon's thread pool"
  (`occ.rs:39-40`); implementation uses `std::thread::scope`.

**Recommendation.** Decide wire-or-delete. If wiring: persistent pool,
`Arc<[u8]>` write values, fast hasher, no result clone, and a budget
comment; then the `uniswap_transfer` numbers become production numbers
and the header's 5–10 GG/s references become claims about *this* path.
If deferring: mark the module clearly as not-on-the-production-path in
its first doc line (today that fact requires grepping).

### F-08 — Event pipeline allocates per tx, stores twice, clones per block **[Medium]**

**Location:** module API returns `Vec<Event>` per tx
(`crates/executor/src/lib.rs:878-880`, `:931-943`); `Event { data: Vec<u8> }`
(`:1303-1312`); outcome recording clones every event:
`block_events.extend(events.iter().cloned())`
(`crates/executor/src/exec.rs:618`), then `self.events.extend(block_events)`
(`:535`).

**Impact.** Per tx: one `Vec<Event>` (result) + one `Vec<u8>` per event
(data) + a full deep copy of each event into the block log — ≥2 heap
allocations per event, twice. At 10k txs/block with a few events each,
this is tens of thousands of allocations per block on the commit path.

**Recommendation.**

1. Move events into the outcome, then extend `block_events` from a
   borrowed pass (`outcomes` + a second iteration), or share via
   `Arc<[Event]>` — eliminates the clone.
2. Consider an events arena (or `SmallVec<[u8; 64]>` for data) at the
   module boundary; the boundary signature is the systemic tax.

### F-09 — Redundant price→index round trip with an integer division per sweep level **[Medium]**

**Location:** `crates/trading/src/engine.rs:790-807` (`sweep` calls
`best_ask_price()`/`best_bid_price()` then `level_head(opp)`);
`crates/trading/src/book.rs:385-387` (price from index),
`:437-439` (`level_head` recomputes the index), `:328-340`
(`level_index` does `offset / tick_size`).

**Evidence.** The bitboard computes the level *index* internally
(`crates/trading/src/bitboard.rs:128-174`) and discards it, mapping to a
raw price; the sweep then maps the price back to an index via an
integer division (~20–26 cycles latency on x86, not pipelined well
against dependent loads) on **every level iteration** of every sweep.

**Impact.** Tens of ns per swept level, on the engine whose whole
single-level budget is 300 ns. The 10-level sweep gate (p50 < 3 µs)
absorbs 10 such divisions.

**Recommendation.** Add index-typed accessors to `BookBackend`
(`best_bid_index`/`best_ask_index`/`level_head_by_index`); keep the
price-form API for callers that need prices (market data, RPC). The
engine's sweep then works purely in index space. Re-run
`match_sweep_10_levels` before/after.

### F-10 — Socket buffer sizing absent **[Medium]**

**Location:** repo-wide — no `set_recv_buffer_size`/`set_send_buffer_size`
anywhere. `TCP_NODELAY` **is** correctly set at all connect/accept
sites (`crates/p2p/src/tcp.rs:1556,1630,1806,1845,2598,2643`).

**Impact.** Default kernel buffers (≈208 KB on Linux) bound a single
TCP stream well below the advertised 100 Gbps peering: at 1 ms RTT the
bandwidth-delay product is ≈12.5 MB per stream, so a single connection
through a default receive buffer tops out around ~1.7 Gbps under loss —
and bursty consensus/broadcast traffic has no headroom, causing drops
or sender-side stalls exactly when the network is loaded.

**Recommendation.** Size from config (e.g. `--tcp-buffer-bytes`,
default 4–8 MB for validator links), log the applied values at startup
(the kernel silently caps to `net.core.rmem_max`), and document the
BDP math next to the constant — per the repo's "every constant carries
unit, origin, tradeoff" rule.

### F-11 — TLS write path: ~4 µs/frame under two mutexes **[Medium, documented]**

**Location:** `crates/p2p/src/tcp.rs:245-253` (`conn` crypto mutex +
`wire` socket mutex, lock-ordered); measured by
`crates/p2p/benches/tls_contention.rs:1-15` ("~4 µs vs ~3.4 µs solo" —
informational, no gate).

**Assessment.** The split-half design (reader never blocks writers;
µs-scale `conn` hold) is the right shape, and the number is honest and
small relative to the current 1 s view cadence. The risk is
compositional: if view cadence ever drops toward 10 ms (or tx gossip
volume grows), ~4 µs/frame plus two mutex acquisitions per frame
becomes a visible share. No action required now.

**Recommendation.** Record the 4 µs figure in the transport budget
comment (it currently lives only in the bench header); revisit with
kernel TLS (`kTLS`) or per-connection crypto threads if cadence
tightens. Keep mTLS opt-in as it is today.

### F-12 — Gate enforcement: conservative floors, unenforced headline claims **[Medium]**

**Location:** enforced assertions in
`crates/devnet/tests/trading_throughput.rs:157-162` (raw engine ≥ 1M
ops/s) and `:230-235` (exchange settlement ≥ 100k ops/s), run nightly
(`.github/workflows/nightly.yml:145-152`). Criterion benches never fail
by themselves; the ≥1 GG/s EVM claim is documented in
`modules/evm/benches/tps_rw.rs:9-13,303-349` but only behavioral
asserts exist (`:594`).

**Impact.** The enforced floors sit far below both the claims and the
measurements: the raw-engine floor (1M ops/s) is ~5× below the engine
gate (5M ops/s, from the 400 ns rest+cancel pair) and ~38× below the
last recorded measurement (38.1M orders/s); the settlement floor
(100k ops/s) is ~24× below the recorded 2.37M orders/s
(`docs/devlog.md:6920-6921`). A regression of up to 4–5× (engine) or
~20× (settlement) passes nightly silently. The EVM GG/s number — the
headline Phase-2 claim — has no mechanical gate at all.

**Recommendation.**

1. Ratchet: assert `measured/2` (or a committed baseline file) per
   gate, labeled by machine class; keep a separate conservative floor
   for shared CI runners and document the de-rating.
2. Add an assertion (or a tracked-baseline comparison) for the tps_rw
   parallel number.
3. Promote the allocation-accounting bench
   (`crates/matcher/benches/alloc_accounting.rs`) from informational to
   gated: assert allocs/op ≤ N for the action path and the matching
   path — the counting-allocator harness already exists.

### F-13 — Metrics recorder: string key + allocation per record **[Low]**

**Location:** `crates/metrics/src/lib.rs:97-113` —
`histograms.entry(op.to_string())` allocates a `String` on **every**
record (even for existing keys), under a global
`Mutex<HashMap<String, Histogram>>`.

**Assessment.** Current call sites are per-block or per-snapshot
(`crates/executor/src/app_iface.rs:365,659,687`,
`crates/node/src/lib.rs:434,472`) — acceptable. The rule to write down
and enforce: this recorder must never be called from per-order or
per-tx paths.

**Recommendation.** `&'static str` keys (or interned handles) +
`get_mut` fast path before `entry`; add a doc line: "never call on a
per-order/per-tx path — the recorder locks and allocates."

### F-14 — Per-batch buffer allocation; `vec![req]` on the single-order path **[Low]**

**Location:** `crates/p2p/src/tcp.rs:166-183` (fresh `Vec` per batched
write), `crates/matcher/src/server.rs:165-172`
(`submit_one_ring` → `vec![req]`).

**Impact.** One heap allocation per batched frame-write and one per
single-order submission — the "fastest path" protocol allocates on
every single-order request.

**Recommendation.** Per-connection reusable scratch buffer for
`write_frames`; pass `&[req]` (a one-element array) or make the ring
item an enum covering 1..N without allocating.

### F-15 — Async-side `yield_now` spin loops **[Low]**

**Location:** `crates/matcher/src/server.rs:106-133` (push-retry and
response-wait loops `tokio::task::yield_now().await`).

**Impact.** Under saturation these loops burn tokio worker CPU and add
scheduler churn for every waiting connection — degrading *all* tasks on
the runtime, not just the waiting one. `acquire_ring` already uses the
right primitive (`Notify`); the ring wait paths should too.

**Recommendation.** Have the ring expose a `Notify`-style "space
available"/"response ready" signal (the SPSC rewrite in F-03 can carry
one), or bound the spin and fall back to `spawn_blocking` with a
blocking wait.

### F-16 — FIX/WS parsers allocate per message **[Low, acknowledged]**

**Location:** self-documented in
`crates/matcher/benches/alloc_accounting.rs:9-17`: `parse_fix_tags`
builds a `HashMap<String, String>` per FIX message; `extract_str` hands
out owned `String`s; response formatters build `String`s.

**Recommendation.** Borrowed parsing over the input frame + a
fixed-size tag array (FIX tags are u16); serialize responses into a
reusable buffer. Then gate the alloc-accounting numbers (F-12).

### F-17 — Rounding-direction wording mismatch **[Info]**

**Location:** code uses **half-up** everywhere, with the direction
documented as a fairness decision (`crates/primitives/src/lib.rs:501-542`
— `qty_from_notional_div_price`, `mul_div_half_up`). The
`performance-first` skill text says "banker's-mode rounding."

**Assessment.** Half-up is deterministic, documented at the single
implementation site, and fair in the stated direction; banker's
rounding is not obviously better here. The *invariant* that matters —
one documented rounding direction for the whole codebase — holds.

**Recommendation.** Reconcile the skill text to the code (half-up) so
the rule and the implementation stop disagreeing.

### F-18 — Ring-lease starvation under saturation is documented policy **[Info]**

**Location:** `crates/matcher/src/lib.rs:1235-1239` ("a busy matcher can
starve an unlucky waiter under sustained saturation. That is the
intended bound").

**Assessment.** "Excess waiters wait rather than corrupt each other" is
a coherent policy at 256 rings (`crates/matcher/src/server.rs:942`).
For venue fairness, the SLO should be explicit: p99 queueing delay
under saturation, and whether a client should instead receive a
typed `ServerBusy` shed response. Add the SLO to the docs; revisit
FIFO ticketing only if measured.

### F-19 — Settlement exposure window: 100 ms batch interval **[Info]**

**Location:** `crates/matcher/src/settler.rs:190,338-358` — default
100 ms seal interval between off-chain fill and on-chain settlement
submission; ~10 s pending-envelope budget at defaults.

**Assessment.** A deliberate design (batch settlement amortizes chain
cost); the interval is configurable. Worth stating plainly in the
trading docs: fill→settlement exposure is ~100 ms + consensus
inclusion, and the settler's queue depth bounds are the venue's
under-settlement risk envelope.

---

## 4. Verified strengths (what not to touch)

These were checked and are genuinely well-engineered; they set the bar
the findings above must be fixed to, not lowered:

1. **Order pool.** 64-byte cache-line-aligned nodes with a compile-time
   size assertion, intrusive `u32` FIFO links, LIFO free-list recycling,
   zero steady-state allocation
   (`crates/trading/src/pool.rs:44-84`).
2. **Bitboard BBO.** Hierarchical tiers, O(1) best-price via
   `trailing_zeros`/`leading_zeros`, two boards (bids/asks)
   (`crates/trading/src/bitboard.rs:1-20,128-174`).
3. **Id map.** Open-addressed, backward-shift deletion (no tombstones),
   sequential-key cache behavior, 50% load cap, never grows
   (`crates/trading/src/idmap.rs:1-26`).
4. **Fixed-point layer.** Typed scale-units (`Price`/`Qty`/`SignedQty`),
   `u128` intermediates, one documented rounding direction, checked
   ops with typed errors (`crates/primitives/src/lib.rs:440-660`).
5. **Wire codec.** Caller-owned encode buffers, borrowed decode,
   memcpy-floor baselines and a bincode head-to-head with an honest
   "parity is a valid result" claim (`crates/codec/benches/wire.rs:12-27`).
6. **WAL.** `O_DSYNC` fold (one syscall per durable append),
   `fallocate(KEEP_SIZE)` preallocation, deferred-frame batching into
   the next synced write, 32 MiB checkpoint compaction, torn-tail
   handling (`crates/consensus/src/wal.rs:61-140`). This is
   textbook-grade.
7. **Consensus engine.** Zero `Mutex`/`RwLock` in `crates/consensus/src`
   (grep-verified); single-threaded state machine; durable-budget
   benches that measure the real fsync cost instead of hiding it
   (`crates/consensus/benches/engine.rs:12-40`).
8. **Matcher protocol.** Batch Ed25519 multi-scalar verification
   (~3× cheaper per order), and proof tokens (`VerifiedOrder` /
   `VerifiedAction`) that make the sequencer's trust boundary explicit
   (`crates/matcher/src/server.rs:58-74`).
9. **Atomic balance cache.** Flat `AtomicU64` array + registration
   table, `Acquire`/`Release` discipline (no `SeqCst` in hot code),
   with the rejected alternatives (sharded mutex, `RwLock`) documented
   by measurement (`crates/matcher/src/balance.rs:181-277`).
10. **Idle-wait precedent.** The exec lane's condvar pattern
    (`crates/executor/src/lane.rs:64-76`) and the matcher `Wakeup`
    are the correct shape F-01 should adopt.
11. **Bench documentation discipline.** Every bench states what is
    measured, the gate, the baseline, and machine context; `black_box`
    and `iter_batched` are used correctly; the counting-allocator bench
    exists (`crates/matcher/benches/alloc_accounting.rs`).
12. **Transport basics.** `TCP_NODELAY` everywhere, vectored writes,
    frame batching, frame-length caps, and the frame-reader
    incremental-state fix (`crates/p2p/src/tcp.rs:135-183,2003-2015`).

---

## 5. Prioritized remediation plan

**Phase A — latency-critical (days):**

1. F-01: replace the pump sleep with a blocking wait/condvar; fix the
   comment. Expect ~1 ms off p99 inbound latency per message.
2. F-04: bound the sequencer's response-push spin + invariant assert.
3. F-05: before wiring market data, move serialization + fan-out off
   the sequencer (ring + dedicated thread).

**Phase B — order-path throughput (1–2 weeks):**

4. F-03: true SPSC ring + parked-flag wakeup; property/loom tests.
5. F-09: index-space sweep API; re-bench the sweep gate.
6. F-06: proof-token preverify consumption on the parallel path;
   re-bench tps_rw.
7. F-02: `numa_node` config + Linux pinning for sequencer/exec
   lane/pump/readers; startup validation.

**Phase C — hygiene and enforcement (ongoing):**

8. F-07 (wire-or-mark OCC), F-08 (event pipeline), F-12 (ratchet the
   gates + promote alloc accounting), F-10 (socket buffers), then the
   Low items (F-13…F-16) as touch-ups in the areas they live in.
9. F-17: reconcile the skill text on rounding.

**Benchmarks required with each fix** (per the `benchmarks` skill):
F-01 (end-to-end view latency, new), F-03 (ring handoff p50/p99,
new microbench + matcher_throughput), F-06 (tps_rw before/after),
F-09 (match_sweep_10_levels before/after), F-04/F-05 (matcher
saturation test with a stalled reader — new).

---

## 6. Method notes and honest limitations

- Every quantitative claim in this document is traceable to a committed
  bench header or source comment; no number was estimated by this audit.
- The 16-core x86_64 gate rig does not exist yet; all absolute numbers
  are M-series dev-machine measurements, as the benches themselves
  state. Re-run Phase A/B benches there before publishing gate claims.
- Not covered in depth: RPC server internals (cold path by policy),
  governance/staking/oracle module internals (cold), TLS handshake
  path (connection-establishment only), devnet/sim harnesses
  (test-only), and the EVM interpreter itself (revm — treated as the
  reference implementation; only Oxide's surrounding wiring was
  audited).
- The audit assumes the production wiring in `bin/oxide-validator` and
  `bin/oxide-matcher`; alternate embedders (tests, sims) may configure
  different ring counts/thresholds than the defaults cited here.

---

## 7. Validation pass (2026-10-04, revision `87d63b5`)

**Method.** Every finding was re-verified against the source tree at
`87d63b5`. The only delta from the audited `e98bf2f` is docs-only
(`docs/devlog.md`, this file), so all original line citations were
expected to hold — each was nevertheless re-checked by reading the
cited code, plus repo-wide greps for the "absence" claims (F-02, F-10).
No finding was accepted on the original audit's authority alone.

**Result: 19/19 CONFIRMED** (four with precision notes in §7.2 that
sharpen the original), **0 refuted, 0 yet implemented. Two new
findings filed** (F-20, F-21, §7.3).

### 7.1 Verdicts

| Finding | Verdict | Key re-checked evidence |
|---|---|---|
| F-01 | **CONFIRMED** | `validator_net.rs:1965` — unconditional `std::thread::sleep(Duration::from_millis(1))` as the last statement of the pump loop (loop head `:911`, drain `while let Some(msg) = transport.recv()` at `:1002`); the preceding comment (`:1956-1964`) is self-contradicting (§7.2.1) |
| F-02 | **CONFIRMED** | repo-wide grep `numa|sched_setaffinity|core_affinity|pin_to_core|set_thread_affinity`: **zero hits in `crates/`** — only README/skills/devlog/hft-audit prose; the devlog itself admits it: "CPU pinning \| Not done \| Requires `core_affinity` crate" (`docs/devlog.md:7746`, `:7826`); threads are named-only `std::thread::Builder` spawns (`primitives/src/lib.rs:1031`) |
| F-03 | **CONFIRMED** | `ring.rs:33` + `:181` — `crossbeam_channel::bounded` (MPMC); the module doc concedes it at `:114-118` ("only 'SPSC' by convention"); `Wakeup::signal` = `Mutex<bool>` lock + `notify_one` (`:67-71`), invoked from `push` on **every** successful push (`:202-209`) while its own doc claims "a single atomic store + `notify_one`" (`:59-61`); the wakeup is shared by **all** order and response rings (`lib.rs:1082,1094-1096` — one `shared_wakeup`), making it the order path's single shared serialization point; defaults 256×8192 confirmed (`server.rs:942-945`) |
| F-04 | **CONFIRMED (latent)** | `lib.rs:1126-1139` — on `Full`, `pending = returned; std::hint::spin_loop();` with no bound; exits only on `Ok`/`Disconnected`. Latent because of the lease invariant (one batch pushed, one response popped, lease dropped at `server.rs:140`) — an invariant enforced nowhere in code, only by convention across every current and future transport |
| F-05 | **CONFIRMED (latent)** | `market_data.rs:254-288` — `serde_json::to_string` (`:255`), global `lock_state(&self.subscribers)` (`:256`), `json.clone()` per matching subscriber (`:278`), full `retain` walk per publish; `publish_l2` takes `Vec<(u64, u64)>` by value (`:232`). Grep `publish_l1|publish_trades|publish_l2|publish_l3` across `crates/`: matches **only** in `market_data.rs` (module doc `:24` + tests `:380-527`) — zero production call sites |
| F-06 | **CONFIRMED** | `batch.rs:656-675` — "We do NOT trust `pv.sender`"; `signed.recover_sender()` per tx inside `par_iter` (`:667`). Cost source: `executor/src/lib.rs:884-886` ("the single most expensive per-tx operation, ~30 µs/tx"). Serial contrast: `module_impl.rs:448-453` ("skips secp256k1 recovery entirely"). Threshold: `config/src/lib.rs:476-478` (`default_parallel_threshold() == 100`); routing at `exec.rs:393-394`. The preverify cache is even *consumed* (`remove`) at `exec.rs:385` — the recovered sender is handed to the parallel path, which then re-derives it anyway. Plus one more per-tx tax found in re-verification (§7.2.3) |
| F-07 | **CONFIRMED** | grep `ParallelScheduler`: only `occ.rs` (impl + tests) and `benches/uniswap_transfer.rs:277` — no production call site. Doc/impl mismatch: `:39-40` "using rayon's thread pool" vs `:309-311`/`:335-349` `std::thread::scope` ("a full rayon-based version arrives with the rayon dependency"). Per-`schedule()` spawns + `Vec<Mutex<Vec<R>>>` (`:331-349`); result clone on flatten (`:354`, `R: Clone` bound at `:315`); write-value clones (`:266`, `:272`); `reads: HashSet<OccKey>` with the default SipHash hasher over keccak-derived 32-byte keys (`:124-129`, `Hash` derived at `:67`) |
| F-08 | **CONFIRMED** | `exec.rs:618` `block_events.extend(events.iter().cloned())` (deep copy of every event); the same events are then stored twice — inside `TxOutcome::Executed { events }` (`:619`) *and* the block log (`:535` `lock_state(&self.events).extend(block_events)`); `Event { data: Vec<u8> }` at `executor/src/lib.rs:1303-1312`. Minor extra: `format!("{e}")` allocates on the error path (`:621`) |
| F-09 | **CONFIRMED** | `engine.rs:790-807` — sweep takes the opponent level as a raw **price** (`:791-794`) then calls `level_head(opp)` per level iteration (`:807`); `book.rs:379-387` — `best_bid_price`/`best_ask_price` convert the bitboard's level **index** to a price (`min_price + idx * tick`), discarding the index; `book.rs:437-439` — `level_head` recomputes `level_index(price_raw)`; `book.rs:334` — `offset / tick_size` integer division per swept level |
| F-10 | **CONFIRMED** | grep `set_recv_buffer|set_send_buffer|RCVBUF|SNDBUF` across `crates/`: **zero**. `set_nodelay(true)` correctly present at `tcp.rs:1556,1630,1806,1845,2598,2643` |
| F-11 | **CONFIRMED** | `tcp.rs:243-254` — `TlsWriteHalf { conn: Arc<Mutex<rustls::Connection>>, wire: Arc<Mutex<TcpStream>> }`, wire-before-conn lock order documented (`:203-211`, `:250-253`); `tls_contention.rs:13` "~4 µs vs ~3.4 µs solo", `:15` "Informational only — no hard gate" |
| F-12 | **CONFIRMED** | enforced asserts: `trading_throughput.rs:157-162` (raw engine ≥ 1M ops/s) and `:230-235` (settlement ≥ 100k ops/s), run nightly (`nightly.yml:145-151`, `THROUGHPUT_TRADES=1_000_000`); `tps_rw.rs` has **no** throughput assertion — its only assert is behavioral (`:594` "probe txs must succeed"). Recorded measurements `devlog.md:6920-6921`: raw engine 38.1M orders/s, settlement 2.37M orders/s → enforced floors sit **38×/24×** below the last measurements. See §7.2.4 |
| F-13 | **CONFIRMED** | `metrics/src/lib.rs:101-113` — `histograms.entry(op.to_string())` allocates a `String` per record (even on the existing-key path) under a global `Mutex<HashMap<String, Histogram>>`. Call sites verified per-block/per-RPC only: `app_iface.rs:365` (prepare_proposal), `:659` (finalize_block), `:687`/`:728` (attest_state), `rpc/endpoints.rs:912` (rpc_send_raw_tx) |
| F-14 | **CONFIRMED** | `tcp.rs:166-183` — fresh `Vec::with_capacity(total)` per batched `write_frames` call; `server.rs:165-172` — `submit_one_ring` → `submit_batch_ring(ring, ring_counter, vec![req])` |
| F-15 | **CONFIRMED** | `server.rs:116` (push-retry) and `:132` (response-wait) — `tokio::task::yield_now().await` loops on tokio workers |
| F-16 | **CONFIRMED** | `alloc_accounting.rs:8-20` — self-documents the per-message `HashMap<String, String>` / owned-`String` allocations and states "Informational only — no gate" |
| F-17 | **CONFIRMED** | `primitives/src/lib.rs:501-542` — "rounding **half-up**" documented on both division ops, ties round upward, "fixed here, once, for the whole codebase"; `performance-first/SKILL.md:41` says "divide with banker's-mode rounding" — the skill text is wrong relative to the code |
| F-18 | **CONFIRMED** | `lib.rs:1235-1239` — verbatim: "a busy matcher can starve an unlucky waiter under sustained saturation. That is the intended bound" |
| F-19 | **CONFIRMED** | `settler.rs:190` ("At the default 100 ms settle interval"); `interval_ms` parameter (`:346-358`); `MAX_PENDING_RETRIES = 60` → ~6 s (`:188-200`); `RESUBMIT_AFTER_TICKS = 100` → ~10 s (`:202-207`) |
| F-20 | **NEW** | filed this pass — §7.3 |
| F-21 | **NEW** | filed this pass — §7.3 |

### 7.2 Precision notes from re-verification

1. **F-01 — the comment disproves itself.** The block at
   `validator_net.rs:1956-1964` correctly states the facts (`recv()`
   is non-blocking `try_recv()`; "A 1ms sleep keeps CPU usage near-zero
   while providing ~1ms message latency") and then draws a false
   conclusion: "when messages arrive, `recv()` returns them immediately
   and the sleep is never reached." The sleep is the loop's last
   statement and is reached after **every** pass, including passes
   that processed messages — so a message arriving mid-pass also waits
   out the remainder of the 1 ms before the *next* intake. The
   comment's own "~1ms message latency" admission is the accurate
   description. Note the loop body itself acknowledges the shape of
   the fix: the matcher sequencer (`lib.rs:1172-1181`) and the exec
   lane (`lane.rs:72-84`) already block on a wakeup/condvar instead.

2. **F-03 — the wakeup is worse than documented, and fully shared.**
   `RingMatcher::new` builds **one** `shared_wakeup`
   (`lib.rs:1082`) and hands it to every order ring *and* every
   response ring (`:1094-1096`) — 512 rings, one `Mutex<bool>`. Every
   successful push on any connection locks it. Under concurrent
   submitters this is a genuine contended lock + potential futex on
   the order handoff, not the "single atomic store" its doc claims
   (`ring.rs:59-61`). This strengthens the F-03 remediation: the
   parked-flag protocol is not just an optimization, it removes a
   cross-connection serialization point.

3. **F-06 — an additional per-tx tax on the same path.** The parallel
   decode phase also heap-copies every payload:
   `batch.rs:673` — `pv.raw.to_vec()` inside the `par_iter` map (the
   serial preverified path borrows the block bytes,
   `exec.rs:381-387`). ~100–200 B memcpy + one allocation per tx,
   dwarfed by the ~30 µs recovery but the same fix window: a
   proof-token design that trusts locally-recovered senders can also
   carry borrowed bytes for already-ingested txs.

4. **F-12 — the tps_rw bench's own documented gate is weaker than the
   headline.** `tps_rw.rs:9-15` documents "Simple transfer TPS:
   > 1,000 tx/s" as its acceptance gate — three orders of magnitude
   below the ≥1 GG/s claim quoted in the README. So the headline
   number is not merely unenforced (the original audit's point); the
   bench that would enforce it carries a gate 1000× looser than the
   claim. A ratchet (§5, item 8) should assert against a committed
   baseline, not against this floor.

### 7.3 New findings

#### F-20 — Shared `Wakeup` panics on poison where the repo's own contract mandates recovery **[Low]**

**Location:** `crates/matcher/src/ring.rs:67-71` (`signal`),
`:81-88` (`wait`) — `.expect("wakeup mutex poisoned")` on the shared
flag mutex.

**Evidence.** The codebase has a *documented* poisoned-mutex contract
(`primitives/src/lib.rs:749-795`): state mutexes panic on poison
("halting is the only safe response" — torn financial/consensus state),
but recovery is explicitly legitimate "with the per-key/per-entry
invariant documented at the type — for structures like the matcher's
sparse balance overflow (each account word is independently meaningful
and every op touches it atomically)." A single `bool` wakeup latch is
the canonical independently-consistent value — the supervision
registry itself recovers poison for exactly this style of reason
(`lib.rs:914-923`). The `Wakeup` uses panic-on-poison instead.

**Impact.** If the flag mutex ever poisons (a panic while a thread
holds it inside `wait`/`signal`), every subsequent `push()` on all 512
rings panics in `signal()` — converting one thread's fault into a
venue-wide panic cascade across every connection handler's tokio task.
The probability is low (the critical sections are a bool store and
condvar ops), which is why this is Low — but the fix is one line and
the repo's own contract already adjudicates it.

**Recommendation.** Use
`lock().unwrap_or_else(std::sync::PoisonError::into_inner)` for the
flag in both `signal` and `wait` (sound per `lib.rs:775-778`), or
remove the question entirely via F-03's parked-atomic protocol.
Related doc debt, same class as F-17: `production-rust` skill §8
mandates "always recovery", while `primitives::sync` mandates
panic-for-state — reconcile the two texts so the next contributor
doesn't have to rediscover which applies. Also worth one clarifying
sentence in the supervision docs: `spawn_supervised`
(`primitives/src/lib.rs:1021-1035`) only registers actors and marks
their death — there is **no in-process respawn**; critical-actor death
surfaces via `/health` (`unhealthy_critical`, `lib.rs:957-966`), and
the exec-lane comment "fail fast so the supervisor restarts"
(`lane.rs:60-63`) means the *operator/process-level* watchdog, not
anything in-process.

#### F-21 — `SpscSender::is_connected` is dead code with a tautological predicate **[Low]**

**Location:** `crates/matcher/src/ring.rs:218-223`.

**Evidence.** The body is
`!self.tx.is_empty() || self.len() < self.capacity`. For any ring with
capacity ≥ 1 this is true in every state: empty → the second disjunct
(`0 < capacity`); non-empty → the first. It can never return `false`,
so it cannot detect the one condition its doc claims ("Returns `true`
if the consumer half is still alive"). Underlying reason:
crossbeam 0.5 exposes no receiver-disconnect probe that doesn't
consume a value — the file itself notes this at `:266-269`. Grep
confirms **zero callers** — the helper is dead.

**Recommendation.** Delete it. If a disconnect probe is genuinely
needed later, implement it honestly: an `Arc<AtomicBool>` (or
`Arc<()>` weak-pair) shared by both halves, cleared by the receiver's
`Drop`, so `is_connected` has a real false case — and add the unit
test the current shape would fail. A liveness predicate that cannot
return `false` is exactly the helper that gets adopted blindly.

### 7.4 Remediation deltas

- No priority changes: F-01 remains the highest-value single fix;
  F-03 the most strategic.
- F-20 joins **Phase C** (hygiene) — one-line poison-recovery on the
  flag, plus the skill-text reconciliation with F-17.
- F-21 is a trivial deletion; fold into any ring.rs touch (it is the
  same file as F-03's rewrite, which will delete or replace it).
- F-06's fix window now also covers the per-tx `pv.raw.to_vec()` copy
  (§7.2.3); its re-bench (tps_rw before/after) should capture both.
- F-12's ratchet should target a committed baseline file, not the
  tps_rw bench's own 1k-tx/s floor (§7.2.4).
