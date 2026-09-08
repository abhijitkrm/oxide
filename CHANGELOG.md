# Changelog

All notable, user-visible changes to the Oxide project are documented in
this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project is pre-alpha and unreleased, so everything lives under
`[Unreleased]` until the first tagged release. Granular engineering history
lives in [`docs/devlog.md`](docs/devlog.md).

## [Unreleased]

### Added

- **Phase 1 stage 2: oxideBFT pacemaker state machine** (2026-09-09)
  - New `consensus` crate with the pacemaker — a pure state machine
    over views (Active ↔ TimedOut) that drives view changes via
    timeout → TC formation → view advance.
  - `ValidatorSet` with stake-weighted round-robin leader election
    (O(log n) binary search over cumulative stakes; deterministic, no
    VRF). Fault tolerance `f = (n-1)/3`, quorum `2f+1`.
  - Exponential backoff on consecutive timeouts (2s base, 30s cap);
    progress resets to base.
  - 19 new tests (10 pacemaker + 9 validator); 97 total.

  **In plain words:** the second piece of oxideBFT is in place — the
  pacemaker that keeps finality moving under a faulty leader. When a
  validator's local timer expires, it broadcasts a timeout; when
  ≥2f+1 validators timeout, a certificate forms and the view advances
  to the next leader. No consensus loop yet (that's stage 3); this is
  the pure state machine, tested in isolation.

- **Phase 1 stage 1: oxideBFT consensus message types** (2026-09-09)
  - `VotePhase` (`Prepare`/`PreCommit`/`Commit`): the 2-chain pipeline
    phase, `repr(u8)` with pinned discriminants.
  - `Vote`: a single validator's signed vote (view, phase, block hash,
    BLS signature).
  - `QuorumCertificate`: ≥2f+1 votes compressed to one aggregate BLS
    signature + a signer bitmap.
  - `TimeoutCertificate`: ≥2f+1 timeout signatures proving a view
    should advance (the tail-fork-resistance mechanism).
  - `BlockHeader`: the engine-internal consensus header (view, epoch,
    QC, TC, proposer) — distinct from the OAI `BlockRecord`.
  - All types implement `codec::Encode`/`Decode` with pinned wire
    forms; 8 new tests in `types` (19 total, up from 11).

  **In plain words:** the first piece of oxideBFT is in place — the
  message types validators exchange (votes, quorum certificates,
  timeout certificates, block headers) with their exact wire formats
  pinned by tests. No consensus logic yet; that's stage 2 (the
  pacemaker). These types settle the consensus contract so every
  validator agrees on what a vote and a QC look like on the wire.

- **Phase 0 completion: crypto crate, ports v1, oxide-bench, fuzz
  targets** (2026-09-09)
  - `crypto` crate: domain-separated BLAKE3 hashing (the `Domain` enum
    makes the domain tag a compile-time-checked API, not a magic byte)
    + BLS12-381 signature type stubs for oxideBFT (types and codec
    settled; sign/verify/aggregate land in Phase 1 via `blst`).
  - `ports` v1 complete: `BroadcastEngine` (data-availability port)
    and `Transport` (p2p port) traits with capability flags. All five
    OAI/adapter traits are now defined.
  - `oxide-bench` harness (`bin/oxide-bench`): unified benchmark
    runner with per-crate pass/fail summary and CI exit code.
  - `fuzz/` directory with four cargo-fuzz targets at trust boundaries:
    codec decode, OAI types decode, journal replay, MMR proof verify.
    Builds with nightly, separate workspace.

  **In plain words:** the last four pieces of the foundation are in
  place. The crypto crate gives every component one consistent hashing
  API with domain separation built in (so a block hash can never be
  confused with a vote hash), plus the BLS signature types oxideBFT
  will use — the types are settled now so Phase 1 just fills in the
  math. The two missing adapter seams (broadcast and transport) are
  defined, so the full plug-and-play surface is ready. The benchmark
  runner and fuzz targets close the testing pyramid's bottom layer.

- **Oxide Application Interface (OAI) — spec, traits, reference engine,
  conformance suite** (2026-09-09)
  - `docs/oai-spec.md` v1: the ABCI-analog boundary, adapted to Oxide's
    "engines order, never execute" and "chain identity is
    engine-agnostic" invariants. v0 traits are synchronous by design;
    the async-vs-channel decision is deferred to Phase 1 with the first
    real consumer.
  - `runtime` crate: a safe, std-only deterministic single-threaded
    executor (FIFO ready queue, FIFO mailboxes, no timers/threads/unsafe)
    — the reproducibility backbone of the deterministic-simulation test
    layer. 4-node echo simulation (simplified Bracha reliable broadcast)
    asserts liveness, determinism (two runs → identical delivery
    sequence), and a pinned delivery order `[3,0,1,2]`.
  - `types` crate: the OAI data model — `TxBytes`, `BlockBudget`,
    `Proposal`, `Verdict`, `MempoolAck`, `FinalizedBlock`, `CommitAck`,
    `StateAttestation`, `BlockRecord` — all with deterministic
    `codec` impls and per-type wire-form pinning tests.
  - `ports` crate: the plug-and-play seams — `ConsensusEngine` and
    `AppInterface` traits, a reference `MockEngine`/`MockApp`, and a
    reusable `conformance::assert_conformance` suite asserting the four
    engine-agnostic rules (liveness, gap-free heights, finality-is-final,
    determinism). An end-to-end OAI test exercises the two rules the
    generic suite can't (ordering-only, attestations opaque).

  **In plain words:** the consensus ⇄ app boundary now has a written
  contract, a working reference implementation, and an automated test
  suite every future consensus engine must pass before it ships. The
  reference engine is deliberately trivial (single-leader, no voting,
  no network) so it can serve as the specification of the contract; the
  real `oxideBFT` will drop in behind the same traits. The deterministic
  runtime means multi-node simulations replay byte-identically every
  run — a prerequisite for bisecting flaky consensus failures.

- **Repository bootstrap** (2026-09-08)
  - Exhaustive open-source README: mission, performance targets vs. state
    of the art (Hyperliquid / Monad / Sei Giga / CME-class engines),
    architecture overview, plug-and-play ports table, workspace layout,
    roadmap with hard phase gates, contributing & security policy,
    acknowledgments.
  - Engineering standards codified as skills in `.devin/skills/`:
    `production-rust` (readability/comment/error/unsafe policy),
    `testing-standards` (five-layer test pyramid), `performance-first`
    (hot-path discipline), `git-conventions` (commit format; project
    policy: no AI attribution trailers unless explicitly requested), and
    `benchmarks` (a feature isn't done until it's benched; gates,
    baselines, plain-English reporting).
  - `AGENTS.md` working guide and `docs/devlog.md` engineering log.
  - CI workflow: fmt + clippy (`-D warnings`) + tests, plus cargo-deny
    supply-chain job with a GPL-3.0-compatible license allowlist.

- **Workspace scaffolding** (2026-09-08)
  - Cargo workspace (edition 2024, resolver 3) with strict shared lints:
    `unsafe_code = deny` (arenas opt back in with SAFETY comments),
    `missing_docs`, clippy pedantic.
  - Release profile tuned for measured perf gates: thin LTO,
    `codegen-units = 1`, `panic = "unwind"` (actor boundaries catch
    panics; consensus never aborts silently).

- **`codec` v0.1.0** (2026-09-08) — deterministic wire codec
  - Hand-rolled binary format (no serde — determinism is a consensus
    requirement): fixed-width little-endian integers, LEB128 varints
    (bounded to 10 bytes), varint-length-prefixed byte strings with
    zero-copy borrowed reads, strict `0x00/0x01` booleans.
  - `Encode`/`Decode`/`Codec` traits; impls for `u8..u128`, `bool`,
    `Vec<u8>`, and the `primitives` vocabulary (`Hash`,
    `Address`, `Height`/`View`/`Epoch`, `TimestampMs`, `Price`, `Qty`).
  - Zero-allocation decode cursor; decoding never panics — corrupted
    input maps to precise, documented `DecodeError` variants that let
    trust boundaries distinguish malicious framing from truncated tails.
  - 5 unit tests pinning exact wire bytes, varint boundary lengths, and
    error paths.

  **In plain words:** every message between computers on the network —
  "here is a block", "here is an order" — must be flattened into bytes,
  and every computer must flatten it *identically*, or they will
  disagree about what was said and split into two chains. The standard
  Rust tools for this (serde) prioritize convenience over that
  guarantee, so this crate implements the flattening by hand: a tiny,
  fully-audited rulebook for turning values into bytes and back. It
  reads data directly out of the network buffer without copying, and
  garbage input is rejected with a precise error instead of a crash —
  important when anyone on the internet can hand you bytes.

- **`primitives` v0.1.0** (2026-09-08) — foundational types
  - `Hash`: 32-byte digest newtype, stable hex `Display`, truncated
    `Debug` that can never be mistaken for a full digest.
  - `Address`: 20-byte EVM-compatible (`H160`) account identity — one
    unified address space for native and EVM users.
  - `Id<Height|View|Epoch>`: strongly-typed consensus counters (space
    names render in logs: `view 7`); manual comparison/hash impls keyed
    on the raw counter.
  - `TimestampMs`: advisory-only header timestamps (state logic uses
    heights for determinism).
  - `fixed` module: deterministic fixed-point trading arithmetic —
    `Price` (scale 1e8), `Qty` (scale 1e6), `notional` in natural
    scale-14 `u128`, round-half-up division, checked add/sub, loud
    `Overflow`/`DivisionByZero` errors. No floats in state, ever.
  - 10 unit tests covering parsing, formats, rounding direction, error
    paths, and boundary arithmetic.

  **In plain words:** before any trading code exists, the chain needs a
  shared dictionary of "what a price is" and "what an account is" that
  every computer on the network reads identically, down to the byte.
  This crate is that dictionary. It also makes money-math exact: a
  computer's usual decimal numbers ("floats") can round differently on
  different machines — which on a shared ledger would mean two
  validators disagreeing about whether you can afford a trade — so all
  values are stored as plain integers with a fixed number of decimal
  places, the way exchanges and banks actually do arithmetic.

### Added

- **`storage` v0.1.0** (2026-09-08) — persistence + authentication layer
  (spec: `docs/storage-spec.md`, written before the code)
  - `journal`: append-only CRC-32'd records in immutable size-bounded
    segments; group commit (one sequential write + one fdatasync per
    block batch — durability is replayed, never per-op); torn-tail and
    corruption recovery trust exactly the complete prefix; a missing
    directory is an empty journal (fresh-node bootstrap).
  - `mmr`: Merkle Mountain Range over pre-hashed leaves with
    incrementally maintained peaks (O(1) amortized push), descent-based
    O(log n) inclusion proofs that verify against the root alone, and
    domain-separated BLAKE3 with the leaf count bound into the root.
  - `backend`: the `StorageBackend` seam (minimal by design — it grows
    only when later phases need it), `Op`/`Caps`, and `Volatile`, the
    in-memory reference implementation and conformance oracle.
  - 16 unit tests + 6 proptest properties, including the
    arbitrary-cut journal-recovery contract modeled from the byte
    layout.
  - Gates (dev Mac): journal append **185ns/op (5.4M/s** vs the ≥1M/s
    gate); append+flush amortized 267ns/op; MMR structure overhead
    **~16ns/op** (< 20ns gate) with the BLAKE3 hash floor (160ns per
    65-byte node hash) and the 1M-leaf full build (248ms) reported as
    hardware/hash-throughput-bound numbers.

  **In plain words:** this is the part of the node that remembers. Every
  committed batch of changes is written once, end-to-end, into an
  append-only file (with checksums on every record), so a crash means
  "replay the file and continue" instead of "hope the database wasn't
  half-writing." On top of the log sits a cryptographic summary (a
  "Merkle Mountain Range") that lets anyone prove a particular record
  was included, using only a tiny proof and the summary hash — that's
  what lets light clients and other chains trust Oxide's state without
  downloading it. The commit path itself costs 185 nanoseconds per
  record — about 5.4 million records per second on one core — and the
  MMR bookkeeping adds only ~16 nanoseconds per record on top of the
  (hardware-bound) cryptographic hashing.

- **Benchmark infrastructure** (2026-09-08)
  - `.devin/skills/benchmarks`: a hot-path feature isn't done until it's
    benched — gate/baseline conventions, head-to-head "prove it was worth
    building" comparisons, mandatory plain-English reporting.
  - Criterion benches for both crates. Results (dev Mac, p50, all gates
    pass): fixed-point notional 0.88ns, fee mul-div 3.0ns, checked
    qty ops 2.2ns, hash parse 0.56ns; codec u64 encode 0.89ns, varint
    encode/decode 5.3/4.1ns, hash roundtrip 3.65ns, ~80B order-message
    roundtrip 10.2ns. Head-to-head on an identical `Vec<u64>`×16
    payload: encode 10.1ns vs bincode 94.1ns (9.3× faster, and ours
    writes into a reused caller buffer); decode 66.5ns vs 93.6ns.

  **In plain words:** before claiming anything is fast, we now measure
  it, the same way every run, with a pass/fail number attached — and
  where we built something ourselves instead of using an existing
  library, we race them side by side. The hand-built message codec
  encodes a small order in about 10 nanoseconds — roughly 100 million
  encodes per second on one core — and beat the standard Rust codec in
  both directions of the race.

- Changelog entries now carry an "In plain words" explanation for every
  user-facing feature (benchmarks skill, §4).

### Changed

- **MMR acceptance gate decomposed** (2026-09-08): the Phase 0 figure
  "MMR root over 1M ops < 20ms" was unachievable as a single-threaded,
  hashing-included number (every push amortizes to exactly one 65-byte
  BLAKE3 hash — information-theoretic for any Merkle structure). Per
  the benchmarks skill it was renegotiated openly, not silently
  weakened: structure-only overhead < 20ns/op (measured ~16ns ✓), hash
  floor and full-build wall-clock reported with their hardware context,
  and merge parallelization staged for Phase 1. Spec + plan updated in
  the same change.

- **Crate naming: dropped the `oxide-` prefix** (2026-09-08):
  `oxide-primitives` → `primitives`, `oxide-codec` → `codec` (renamed
  with history preserved); future crates follow. The workspace already
  scopes the names; the Oxide identity now lives in each file's header
  comment. Unchanged: `oxideBFT` (engine name), the `oxide_*` JSON-RPC
  namespace, and the `bin/oxide-*` commands.

- **License references aligned to GPL-3.0** (2026-09-08): README and
  AGENTS.md now point at the repository's single GPL-3.0 `LICENSE`
  (previously referenced a dual MIT/Apache scheme with files that did
  not exist). Dependency policy updated accordingly: dependencies must
  be GPL-3.0-compatible (MIT, BSD, Apache-2.0, MPL-2.0, GPLv2-or-later,
  AGPL-3.0 are; GPLv2-only, CDDL, proprietary are not).

[Unreleased]: https://github.com/abhijitkrm/oxide/compare/HEAD
