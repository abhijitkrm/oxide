# Oxide system audit — security, performance, throughput, stability

**Date:** post-HFT-audit-implementation pass (`d908ec8`).
**Scope:** the whole tree (~170k LOC, 30 crates) across four dimensions:
security, performance, throughput, stability.
**Method:** full read of the previously-unaudited surfaces (rpc, indexer,
statesync, broadcast, codec, runtime, supervision, storage recovery),
targeted re-review of the security-critical paths (crypto, p2p admission,
consensus evidence, EVM isolation), and cross-checks against
`docs/security-review.md`, `docs/production-readiness.md`,
`docs/evm-parity-gap-analysis.md`, and `hft-audit.md` (F-01…F-26 —
all resolved or explicitly deferred; not re-listed here).

---

## 1. Executive summary

The engineering floor is high. Every layer this audit probed has
mechanisms that most pre-mainnet chains lack until much later:
cost-weighted RPC rate limiting with per-IP in-flight caps, quorum-cert
verified state sync, CRC'd group-commit journaling with torn-tail
recovery, PoP-gated BLS aggregation, actor supervision with
critical-panic abort, 11 fuzz targets, a TLA+ model, and deterministic
chaos sims. The HFT audit's 26 findings are closed.

What remains is not "more hardening of what exists" — it is **four
unwired seams** where the system's economics or egress depend on code
that is not finished yet, plus a measured list of deferred
performance work and two stability campaigns (soak, external review)
that only calendar time can buy.

**The four seams (fix before any value flows):**

| # | Sev | Finding |
|---|---|---|
| S1 | **HIGH** | Consensus equivocation evidence is detected but never reaches staking — no automated slash |
| S2 | **HIGH** | Venue egress is unwired: `withdraw` returns "requires ledger wiring"; no Ed25519↔secp256k1 key linkage |
| S3 | **MED** | The matcher's client-facing FIX/WS listeners are plain TCP — no TLS on the order gateway |
| S4 | **MED** | `debug_trace*` RPC namespace is unconditionally public — operators cannot restrict it |

---

## 2. Security

### What is already strong (verified this pass)

- **Crypto** (`crates/crypto`): `blst` min_pk with mandatory
  proof-of-possession at every aggregation admission point (the
  rogue-key defense); `SecretKey` is `#[zeroize(drop)]`; every
  signature domain is DST-separated (`oxide/vote` ≠ `oxide/timeout` …);
  secp256k1 enforces EIP-2 low-s + `{0,1}` recovery ids at the parse
  boundary (malleability rejected before allocation).
- **P2P** (`crates/p2p`): TLS transport, admission control
  (reputation + bans + connection caps) enforced at the listener, the
  outbound dialer bound by the same cap, per-peer outbound byte
  budgets (bounded worst-case memory), `max_message_bytes` enforced
  below the frame allocation.
- **RPC** (`crates/rpc`): per-source cost-weighted fixed-window
  limiter (batches pay per element, `debug_trace*` pays its weight),
  per-IP in-flight caps, global work-permit semaphore, request
  timeouts, IPv6 sources bucketed per-/64, connection cap including
  idle keep-alives, bounded limiter map (the limiter cannot become
  the DoS).
- **Consensus** (`crates/consensus`): votes sign `(view, phase,
  block_hash, epoch)` (C3 fix); TCs carry quorum evidence integrity;
  per-height vote locks prevent equivocation; WAL-failed signing
  withholds rather than forges; proposals are leader-bound by
  signature.
- **EVM** (`modules/evm`): sender always recovered from the
  signature — the envelope's sender field is never trusted; EIP-155
  replay protection; wall-clock deadlines exist only on read-only
  simulations, never on committed execution (determinism preserved);
  overflow-checks on in the release profile as the arithmetic
  backstop.
- **State sync** (`crates/statesync`): trust anchor is a
  stake-supermajority `ExecCertificate`, chunk hashes verified
  byte-for-byte before import, imported root checked against the
  certified root — fail closed.
- **Storage** (`crates/storage`): CRC-per-record journal, group
  commit, replay stops at the first torn record, height-indexed
  pruning never deletes unindexed segments, fault-injection tests for
  crash atomicity.
- **Supply chain**: `cargo deny` + release-age gate in CI; MSRV job;
  `--locked` everywhere.

### Findings

#### S1 — HIGH: equivocation evidence never reaches staking

`crates/consensus/src/engine.rs` detects and stores quorum-strength
evidence (double-sign fences, equivocation proofs, dead-evidence
refusal). `modules/staking` implements `0x03 Slash` with a
governance-set fraction. **Nothing connects them**: no code path
submits a Slash message when the engine observes equivocation. The
economic deterrent in oxideBFT is therefore theoretical — a byzantine
validator loses reputation, not stake.

**Recommendation:** wire an evidence → transaction pipeline. The
engine already produces provable evidence; the node should wrap it in
a system-signed Slash message into its own mempool at observation
time (with a dedup window per offender/height). Add a multinode test:
a validator double-signs, every honest node's staking module reduces
its stake within N blocks. This is the standard Cosmos
`x/slashing`-evidence pattern and the missing half of the BFT
economics.

#### S2 — HIGH: venue egress unwired (withdraw + key linkage)

Two compounding gaps, both documented in-tree but unresolved:

1. `modules/exchange/src/handlers.rs` — `handle_withdraw_base`
   returns `ExecError::rejected(Internal, "withdraw requires ledger
   wiring")`. Custody can be deposited; it cannot leave. Any venue
   deployment today is a one-way vault.
2. `crates/matcher/src/protocol.rs` — the Ed25519 trading credential
   and the secp256k1 ledger credential share the 20-byte namespace
   but no binding mechanism exists. The doc names the needed design
   (a ledger-key-signed attestation of the trading key) and tracks
   it as a settlement-authorization gap.

**Recommendation:** treat these as one workstream — "venue egress
authorization." Design the linkage attestation (ledger key signs
`Domain::ValidatorAddress`-style statement binding the Ed25519
pubkey), store it at registration, and gate `withdraw` on it. Until
this lands, the honest README status is "deposits only."

#### S3 — MEDIUM: no TLS on the order-entry gateway

The p2p transport has TLS; the matcher's FIX and WebSocket listeners
(`crates/matcher/src/server.rs`) are plain TCP. Order flow is signed
(so spoofing is not the issue), but the gateway is the public-internet
surface where a passive observer learns trading intent, and FIX
clients in production expect TLS at the boundary.

**Recommendation:** `rustls` server-side accept on the FIX/WS
listeners, reusing the p2p crate's TLS config plumbing. The write-path
cost is already priced and documented (F-11: ~4 µs/frame under the
stream lock, mitigated by `write_frames` batching). Alternatively,
document the "TLS-terminating local proxy" deployment shape in
`docs/runbooks.md` and keep the matcher loopback-only — but make that
an explicit, validated startup check (refuse to bind non-loopback
without TLS) rather than a doc note.

#### S4 — MEDIUM: debug namespace cannot be disabled

`debug_traceTransaction` / `debug_traceCall` / `debug_traceBlock*`
are expensive (call-tree recording) and are always registered. The
cost-weighted limiter prices them, but an operator running a
public-facing endpoint has no switch to turn the namespace off
(geth's `--http.api` allowlist equivalent).

**Recommendation:** a `RpcConfig.enabled_namespaces` (or
`enable_debug: bool`, default **off**) threaded through `RpcState`;
unlisted namespaces answer `-32601`. Trivial, closes the
"expensive surface public by default" hole.

#### S5 — LOW: statesync operator pin is optional

The weak-subjectivity `ExecCertificate` is the trust anchor (good
design), and the operator-pinned root is an *optional* extra check.
For production profiles the pin should be required (or a
`--trusted-height/root` pair mandatory on first start), matching what
every major chain's node software does.

#### S6 — LOW: no mempool gossip — document the tradeoff

The mempool is per-validator with no gossip (documented in
`crates/mempool`). Txs reach other validators inside proposal bodies.
This is a DoS-surface *reduction* and a deliberate simplification,
but it concentrates propagation latency on the leader's uplink and
makes the leader's tx-view authoritative. Fine for testnet; for
mainnet, measure proposal propagation at target block sizes (see T1)
and revisit.

---

## 3. Performance

### What is already strong

- True SPSC rings with parked-flag wakeups (~14.7 ns push+pop);
  bitboard FOK pre-scan (~82 ns); index-space book traversal;
  wait-free market-data publish; scratch-buffer discipline on FIX/WS/
  TLS/p2p writes; digest-key hashing without rehash; `Arc<[Event]>`
  sharing; parallel sender recovery (~3× on the preverify path);
  slot-granular OCC parallel execution wired into the production
  dispatch (`exec.rs:400`); incremental state-root caching
  (storage-root cache + trie-leaf cache + retained branch nodes).
- Release profile: `lto = "thin"`, `codegen-units = 1`,
  `overflow-checks = true` (documented, justified).

### Findings

#### P1 — MEDIUM: the measured-vs-possible gap is now compiler-shaped

The remaining §8.3 enablement list (`lto = "full"`,
`target-cpu=native`, PGO) is exactly the class of change that
multiplies *everything* by 5–15% for free. It was deferred from the
HFT pass because it changes the binary contract and deserves its own
bench day. That bench day is the highest-leverage perf work left.

**Recommendation:** one session: build with `lto = "full"` +
`-C target-cpu` detection at the deploy script level (not
hard-coded), run the full gate suite, record deltas per subsystem.
PGO only if the first two show the interpreter/dispatch shapes
dominating.

#### P2 — LOW: io_uring for WAL + sockets

Documented defer. The journal's group commit already amortizes
syscalls; the win is on the p2p reader/writer paths at high peer
counts. Revisit when the testnet measures actual syscall overhead
(`strace -c` under load) rather than speculatively.

#### P3 — LOW: huge pages for the arenas

`performance.numa_node` validates topology; the mmap/THP policy is a
separate decision. Only worth it after the arena access patterns show
TLB misses in perf.

#### P4 — INFO: F-26 resting-commitment fold

2–3 leaf hashes per filled maker, measured-in and gated. The
leaf/qty split is protocol-versioned. Profile under the testnet's
real fill distribution before touching.

#### P5 — LOW: cross-block EVM code caching

`SharedCacheDB` is per-batch. Contract code that is unchanged across
blocks is re-loaded/re-verified per batch. revm's `CacheDB` makes this
cheap-ish, but a persistent code cache keyed by code hash (the reth
shape) removes it entirely. Measure first: if `state_scaling` shows
no code-load component, skip.

---

## 4. Throughput

### What is already strong

- Raw matching 24.5M orders/s; chain-path settlement 400–550k
  orders/s (gated); EVM parallel gate 60k+ tx/s (measured 128k);
  consensus `propose_single` ~102 ns; exec attestations overlap
  execution with voting; erasure-coded DA broadcast.

### Findings

#### T1 — MEDIUM: proposals carry full bodies — measure, then commit to tx-by-hash

With no mempool gossip, every proposal ships the entire block body to
every validator (sharded via the erasure layer, but the leader still
uploads the whole thing). At 50–100 ms cadence the leader's uplink
becomes the throughput ceiling long before execution does.

**Recommendation:** (a) measure: leader egress bytes/s at the target
TPS on the testnet; (b) if it binds, the standard fix is
commitment-based proposals — the proposal carries the body root +
shard proofs, validators fetch missing txs by hash from peers that
announce them. This is a protocol change; design it against
`docs/oxidebft-spec.md` before the public testnet, not after.

#### T2 — MEDIUM: settlement path, not matching, is the venue bottleneck

The engine does 24.5M orders/s; the full settlement path does
~0.5M. The ~50× is module-boundary + custody + event work per order.
`batch_settle` exists in the exchange benches — verify the block path
actually batches settlement (amortize custody lookups and event
appends across the block's fills) rather than settling per fill.

**Recommendation:** profile one 1M-trade block through the module
path; if custody-map lookups and event appends are per-fill, add a
block-scoped settlement batch. This is the next 10× for the venue's
chain-side number.

#### T3 — LOW: pipeline state-root with next-block execution

State-root computation is incremental but still on the critical path
between execute and propose. Overlap it: start the root walk for
block N's touched set while block N+1 executes (the touched-set
discipline already makes this safe). Only worth it if the testnet
shows root computation as a visible % of block time.

---

## 5. Stability

### What is already strong

- Actor supervision: registry, panic hook, critical-actor abort,
  `/health` fail-closed on dead critical actors.
- Exec-lane death RAII (a lane panic marks the lane dead and wakes
  waiters — no half-alive voting).
- Bounded everything: outbound queues, response rings, rate-limiter
  map, per-sender mempool, exec-lane saturation flag.
- Recovery: WAL replay tolerates torn tails; `recover_durable_state`
  + snapshot import; statesync fail-closed.
- Deterministic sims: multinode fault injection (leader kills,
  view-advance, mempool nonce bridging), chaos sim (10k scenarios,
  0 violations), TLA+ model checked in CI.
- The mempool nonce-bridge fix (this pass) removed the last known
  liveness flake; devnet suite green across repeated parallel runs.

### Findings

#### ST1 — HIGH (campaign): 7-day soak at ≥50% load

The Phase 4 gate. Tooling exists (`oxide-loadgen`, `oxide-spammer`,
devnet multinode); what's missing is the *campaign*: a long-running
testnet with artifact collection (memory RSS over time, fd counts,
journal sizes, restart drills). Run it as a background job with
daily restart drills and a weekly report.

#### ST2 — HIGH (campaign): external security review

The open Phase 4 gate. This self-review and the HFT audit are
internal; the gate exists precisely because internal review has
blind spots. The four seams above (S1/S2 especially) are what an
external reviewer would find in week one — close them first to spend
the external budget on what internal review *can't* see.

#### ST3 — MEDIUM: no kill-9-mid-commit restart test

Fault injection covers leader kills between rounds, but not the
nastier case: `SIGKILL` the process *during* `execute_block` (the
`in_flight` state), restart, and assert state-root continuity
against the certified chain. The recovery path exists
(`recover_durable_state` treats in-flight-without-root as partially
applied) but no test exercises it under the real crash timing.

**Recommendation:** a multinode test that kills the process at a
random point during block execution (fault-injected at the journal
boundary — the harness already has `FaultPoint`), restarts, and
asserts the post-restart state root equals the certified root.
This is the single highest-value stability test not yet written.

#### ST4 — LOW: per-stage block latency histograms

Metrics exist for snapshot export/import and block commit, but the
propose→vote→commit→execute stage breakdown is not individually
histogrammed. The testnet soak (ST1) will need it to answer "where
did the 100 ms go." Cheap to add via the existing `metrics` recorder
(cold path).

#### ST5 — LOW: storage-backend conformance under the real workload

MDBX/RocksDB/redb adapters are conformance-tested; the nightly
throughput sims run on the default journal. Run one nightly lane per
backend so a backend-specific regression (compaction stall, WAL
contention) is caught by CI, not by an operator.

---

## 6. Prioritized recommendation list

**Before any value flows (security seams):**
1. S1 — wire equivocation evidence → staking slash (+ multinode test).
2. S2 — venue egress: key-linkage attestation + working withdraw.
3. S4 — RPC namespace allowlist (hours of work, closes a public hole).
4. S3 — TLS on the order gateway or validated loopback-only binding.

**Throughput ceiling work (testnet-blocking):**
5. T1 — measure leader egress at target TPS; design tx-by-hash
   proposals if it binds.
6. T2 — block-scoped settlement batching in the exchange path.
7. P1 — the LTO/target-cpu/PGO bench day.

**Stability campaigns (calendar-shaped — start early):**
8. ST3 — kill-9-mid-commit restart test (write it now).
9. ST1 — the 7-day soak with restart drills.
10. ST2 — external security review, after 1–4 land.

**Deferred-by-design (revisit with data):**
- P2 io_uring, P3 huge pages, P4 F-26 fold split, P5 code cache,
  T3 root/execution overlap, S5 required statesync pin, S6 mempool
  gossip, ST4 stage histograms, ST5 per-backend nightly lanes.

---

## 7. What this audit did not find

Worth stating plainly: no new critical arithmetic, determinism,
or authentication defects. The prior passes (security-review C1–C4,
the TLA+ counterexamples, the HFT audit's 26 findings, the fuzz
corpus) appear to have drained that pond — the remaining surface is
integration seams and campaigns, not bugs in what is built.
