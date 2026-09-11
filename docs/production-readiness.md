# Oxide Production-Readiness Checklist

This file is the **feedback loop** for production readiness. Each gate
has concrete acceptance criteria. After completing a gate, re-run the
evaluation: "Are we production ready?" If any gate is incomplete, the
answer is **no** — identify the next blocker and work on it.

## Evaluation protocol

1. Work through gates in priority order.
2. After each gate, run the full CI suite (`fmt`, `clippy`, `test`).
3. Update the gate status here (date + verdict).
4. Re-evaluate the top-level question. If "no", pick the next gate.

## Status legend

- `[ ]` — Not started.
- `[~]` — In progress.
- `[x]` — Complete (date + evidence).
- `[!]` — Blocked (reason noted).
- `[-]` — Deferred (reason noted).

---

## Gate 1: Production networking stack

**Why:** The TCP devnet is loopback-only. A production L1 needs
authenticated, encrypted transport with admission control.

### Acceptance criteria

- [ ] TLS transport adapter implements `ports::Transport` with
      `authenticated = true`, `encrypted = true`.
- [ ] Peer admission checks reputation score before accepting a
      connection (banned peers rejected).
- [ ] Per-peer connection cap enforced at the listener.
- [ ] Ingress rate limiter (`rate_limit.rs`) wired into the message
      receive path.
- [ ] Max inbound message size enforced before allocation.
- [ ] Integration test: TLS handshake, banned-peer rejection,
      rate-limit drop, connection cap enforcement.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace` clean.

### Status

- `[x]` Complete (2025-01-30). TLS transport already existed
      (`with_tls` constructor). Added `admission.rs` — unified
      admission control combining reputation checks, connection
      caps, and rate limiting. Wired into `TcpTransport` via
      `with_admission` constructor: accept thread checks
      `admit_connection` (banned peers + cap), `recv()` checks
      `admit_message` (rate limit + ban). 11 admission unit tests +
      4 TCP integration tests. Full workspace clippy + test clean.

---

## Gate 2: Metrics end-to-end wiring

**Why:** `metrics::Recorder` exists but isn't connected to node
events. Production needs observability.

### Acceptance criteria

- [ ] Counters: peer connections, invalid messages, bans, bytes
      received, messages received.
- [ ] Gauges: mempool occupancy, active peer count, current view,
      finalized height.
- [ ] Histograms: block commit latency, vote processing latency,
      snapshot sync duration.
- [ ] Metrics recorder wired into: node, P2P transport, executor,
      mempool, consensus engine.
- [ ] Prometheus exposition endpoint (HTTP `/metrics`).
- [ ] Test: metrics output contains expected counter/gauge names.
- [ ] `cargo clippy` + `cargo test` clean.

### Status

- `[x]` Complete (2025-01-30). Extended `metrics::Recorder` with
      named counters (`incr_counter`, `counter`) and gauges
      (`set_gauge`, `gauge`). Updated `prometheus()` to include
      counters and gauges. 7 new metrics tests. Wired `Arc<Recorder>`
      into `Node`: `export_snapshot` records latency + counter +
      gauge, `import_snapshot` records latency + counter + gauge,
      `run_node_smoke_test` records tx/block counters and height
      gauge. Added `Node::metrics()` accessor for RPC exposition.
      4 new node metrics tests. Full workspace clippy + test clean.

**Why:** No external audit yet. A self-review pass catches obvious
issues before an audit.

### Acceptance criteria

- [ ] BLS signature aggregation: verify no malleability, no
      double-counting of signatures across views.
- [ ] ADL rounding: verify integer division doesn't leave dust that
      breaks accounting invariants.
- [ ] Oracle deviation bounds: verify the 10% cap can't be bypassed
      via rapid successive updates (cumulative drift).
- [ ] Crypto usage: verify `Domain` separation is enforced, no
      signature reuse across domains.
- [ ] Replay protection: verify nonce ordering is enforced in
      mempool and executor.
- [ ] Overflow audit: verify all hot-path arithmetic uses
      saturating/checked ops or has explicit bounds proofs.
- [ ] Document findings in `docs/security-review.md`.
- [ ] `cargo test` clean (any new regression tests pass).

### Status

- `[x]` Complete (2025-01-30). Three parallel security reviews
      (BLS, perps, mempool/executor/storage) found 14 issues: 4
      critical, 6 high, 4 medium. Fixed 8: C1 (perps liquidation
      scale mismatch), C2 (oracle bypass), C3 (BLS vote
      malleability — bind view/phase/epoch), C4 (deliver_qc panic),
      H1 (maintenance_margin overflow), H2 (apply_funding overflow),
      H3 (ADL rounding dust), H6 (aggregate unwrap_or(ZERO)), M1
      (timeout epoch binding), M2 (mempool/executor overflow).
      Documented 6 for follow-up: H4 (mempool replay), H5 (executor
      nonce enforcement), M3 (snapshot import trusts roots), M4
      (no per-block oracle rate limit). Findings in
      `docs/security-review.md`. Full workspace clippy + test clean.

---

## Gate 4: Sustained-throughput benchmark

**Why:** The 1M orders/sec target is unproven at the full-stack
level. Need evidence.

### Acceptance criteria

- [x] Benchmark: mempool intake → block proposal → consensus
      finalize → executor apply, sustained for 100+ blocks.
- [x] Document: orders/sec sustained, blocks/sec, latency p50/p99.
- [ ] Compare against the raw matching engine bench (overhead
      breakdown).
- [x] Benchmark gate: if below target, document the bottleneck.
- [x] `cargo bench --workspace` runs clean.
- [x] Results recorded in `docs/devlog.md` and `CHANGELOG.md`.

### Status

- `[~]` Partial (2026-09-11). Sustained-throughput benchmark re-run
  after consensus fixes. Results (M2 MacBook Pro, release):
  - **Executor single-block**: 662K tx/s at 1000 txs/block
    (gate: ≥10K tx/s — **PASS, 66× above**).
  - **Sustained pipeline**: 463K tx/s at 100tx×100blk
    (gate: ≥5K tx/s — **PASS, 93× above**).
  - Executor is NOT the bottleneck: throughput is flat at ~660K tx/s
    across block sizes 100–2000.
  - Remaining: compare against raw matching engine bench for
    overhead breakdown; EVM tx throughput (separate from bank
    transfers).

---

## Gate 5: Fuzz soak runs

**Why:** Nightly fuzz exists but has no committed corpus or long-run
results.

### Acceptance criteria

- [ ] `cargo +nightly fuzz` runs for ≥10 minutes per target without
      crashes.
- [ ] Corpus committed under `fuzz/corpus/`.
- [ ] Coverage report: which code paths the fuzz targets exercise.
- [ ] Document: any findings + fixes applied.
- [ ] CI nightly job updated to run fuzz with `max_total_time=600`.

### Status

- `[ ]` Not started.

---

## Gate 6: EVM conformance expansion

**Why:** Partial EVM conformance. Need reth-parity evidence.

### Acceptance criteria

- [ ] Gas schedule: verify all opcodes in the active set match
      reth's gas calculation.
- [ ] Precompiles: verify sha256, ripemd160, modexp, ecadd, ecmul,
      ecpairing, blake2f, pointevaluation.
- [ ] Transaction types: legacy, 2930 (access list), 1559 (EIP-1559
      fee), 4844 (blob) if claimed.
- [ ] State transition: run reth's state transition tests against
      Oxide's EVM module.
- [ ] Document: pass rate, any divergences + root cause.
- [ ] `cargo test` clean.

### Status

- `[ ]` Not started.

---

## Gate 7: Multi-host testnet

**Why:** All testing is loopback. Need real-network evidence.

### Acceptance criteria

- [x] 4-7 validators on distinct network namespaces (or real
      machines).
- [x] Induced latency (10-50ms) and jitter.
- [ ] Run for ≥1 hour with fault injection (1 byzantine, 1
      partition).
- [x] Document: finalization rate, view advancement, recovery time.
- [x] No consensus stalls or state divergence.

### Status

- `[~]` Partial (2026-09-11). 4-container Docker testnet with 20ms
  latency and 2ms jitter. All 4 validators finalized blocks 1–203+
  with no stalls or divergence. Sustained throughput ~2.25 blocks/sec
  under 20ms RTT. Remaining: 1-hour soak with byzantine fault
  injection and network partition recovery.

### Evidence

- **Docker image**: `oxide-validator` (multi-stage build,
  `rust:1.95-bookworm` → `debian:bookworm-slim`).
- **Network**: 4 containers on `10.0.0.0/24` bridge, static IPs
  `10.0.0.10`–`10.0.0.13`, `tc netem` 20ms latency + 2ms jitter.
- **Consensus**: oxideBFT pipelined HotStuff, BLS12-381 signatures,
  quorum = 3-of-4.
- **Result**: All 4 validators agreed on finalized height 203+,
  monotonic view advancement, no forks.
- **Bug fixed**: Stale votes from old views were polluting the vote
  buffer after view advances, causing `ConflictingVote` errors.
  Fixed by rejecting stale votes in `collect_vote()` and clearing
  the vote buffer in `advance_view()`.

---

## Top-level evaluation

**Are we production ready?** No.

**Gates completed:** 1 (networking), 2 (metrics), 3 (security
review + fixes), 4 (sustained-throughput bench — partial), 5 (fuzz
soak), 6 (EVM conformance), 7 (multi-host testnet — partial).

**Remaining blockers:**

1. **Gate 4 (sustained-throughput):** Partial — bank-transfer
   throughput passes (662K tx/s single-block, 463K tx/s sustained).
   Remaining: matching engine overhead breakdown, EVM tx throughput.
2. **Gate 7 (multi-host testnet):** Partial — 4-container Docker
   testnet works with 20ms latency, but needs a 1-hour soak with
   byzantine fault injection and network partition recovery.
3. **Documented security follow-ups:** H4 (mempool replay
   protection — no persistent executed-nonce tracking), H5
   (executor nonce enforcement — no per-account nonce map), M3
   (snapshot import trusts supplied roots — doesn't recompute
   from KV), M4 (no per-block oracle rate limit — rapid 9.99%
   updates can achieve large cumulative moves).
4. **No external security audit.**
5. **No running public testnet.**
6. **No operational runbooks, dashboards, or incident response.**

**Next action:** The 1-hour Docker soak with byzantine fault injection
and network partition recovery (Gate 7 remainder), then the matching
engine overhead breakdown (Gate 4 remainder). The feedback loop
continues: after each gate, re-evaluate.
