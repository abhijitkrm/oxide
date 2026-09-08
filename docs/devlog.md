# Oxide Devlog

A chronological engineering log. **Every step gets an entry, no matter how
small** — decisions, dead ends, bug hunts, and fixes. This is the
"how we actually got here" record that complements `CHANGELOG.md` (the
what-shipped record) and `docs/` (the why-it-is-designed-this-way record).

Convention: newest entries at the bottom (append-only, like the journal
itself). Each entry is dated and grouped by session. Bug hunts record the
root cause and the fix, never just the symptom.

---

## 2026-09-08 — Session 1: planning, repo bootstrap, toolchain, first crate

### Planning (pre-repo)

- Researched reference systems (reference-only, no forking):
  - **commonware** library + examples (`constantinople`, `alto`):
    threshold-simplex consensus with BLS12-381, buffered signature
    amortization (single multi-verify per quorum, identity blocking),
    erasure-coded broadcast, QMDB (MMR-over-log authenticated DB),
    deterministic runtime for simulation. Alto benchmarks: ~200ms block
    time, ~300ms finality.
  - **Monad**: MonadBFT (pipelined Jolteon + tail-fork resistance,
    speculative 1-view finality), asynchronous execution (consensus
    orders, execution runs a block behind with full block-time budget),
    optimistic parallel EVM, MonadDb.
  - **Hyperliquid**: HyperBFT, HyperCore/HyperEVM dual-engine ("the order
    book must BE the blockchain"), 200k orders/sec (execution-bound per
    their docs), on-chain signed orders, ~0.2s median e2e latency.
  - **Sei Giga**: Autobahn multi-proposer ordering, 5 GG/s devnet, async
    execution with divergence commitments, Block-STM OCC.
  - **Jolteon / DiemBFT v4 / AptosBFT**: 2-chain commit rule, active
    pacemaker, leader fault isolation. **hotstuff_rs**: Rust HotStuff
    library (adapter-wrapper candidate later).
  - **reth + BAL (EIP-7928)**: 10 GG/s pure-execution ceiling with
    parallel scheduling + prewarming. **grevm**: Block-STM-style parallel
    revm at 11.25 GG/s (Uniswap workload). **revmc**: EVM→LLVM JIT.
  - HFT orderbook engineering: flat tick ladders, slab-arena intrusive
    FIFO lists, bitboard best-price discovery (~10–160ns ops in C++/Rust
    references), kernel-bypass latency ladder (socket 18.4µs → io_uring
    4.2µs → XDP 2.1µs → DPDK 850ns).
  - Storage landscape: RocksDB/ParityDB/MDBX/redb/Fjall/NOMT trade-offs
    for blockchain workloads.
- Two rounds of architecture decisions locked with the owner:
  1. Consensus: **Jolteon-family pipelined 2-chain HotStuff** ("oxideBFT")
  2. Build strategy: **hybrid** — commonware p2p/crypto/codec/coding +
     revm/alloy as deps; consensus dialect, executor, matching engine,
     journal, module framework from scratch
  3. Validators: **20–50 high-spec** co-located
  4. EVM: **full equivalence via revm** + optimistic parallel execution
  5. Trading: **spot CLOB + perps** (margin/funding/liquidations/insurance/ADL)
  6. Matching: **continuous price-time** priority, deterministic per block
  7. Orders: **fully on-chain signed** (Hyperliquid model)
  8. Storage: **RAM hot state + authenticated journal + cold-KV adapters**
  9. (owner follow-up) Everything **plug-and-play** behind trait seams
     (consensus/`oxideBFT` default, storage, broadcast, p2p, VM) with
     conformance suites — the cosmos-evm lesson
- Megaplan written and approved; copy lives at `plan.md` **gitignored by
  owner decision** (internal while pre-alpha; public specs go in `docs/`).

### Repo bootstrap

- Created `README.md` (exhaustive open-source style: mission, targets vs
  state of the art, architecture, ports table, layout, roadmap gates,
  contributing, acknowledgments).
- Created `.devin/skills/`: `production-rust` (comment/readability/error
  standards), `testing-standards` (5-layer pyramid), `performance-first`
  (hot-path discipline). Later added `git-conventions` per owner policy:
  **no AI co-author/attribution trailers in commits unless explicitly
  requested**.
- Created `AGENTS.md` (repo working guide) and `.gitignore`.
- `git init -b main`; initial commit `8fc68ae` (docs bootstrap).
- Remote `origin` → `https://github.com/abhijitkrm/oxide.git`; fetched and
  merged the GitHub-side `Initial commit` (`1ae827b`, LICENSE file) with
  `--allow-unrelated-histories` → merge `6392014`.
- License alignment: initially assumed the remote LICENSE was Apache-2.0
  (wrong — misjudged from line count). Owner corrected: it is **GPL-3.0**.
  Updated README + AGENTS.md references accordingly → commit `fe196e7`.
  Dependency policy updated: deps must be GPL-3.0-compatible.

### Toolchain

- Discovered Rust was not installed (no cargo/rustup; PATH checked).
- Owner chose rustup; installed via `sh.rustup.rs` default profile →
  **cargo/rustc 1.98.1** (satisfies edition-2024 requirement, ≥1.85).

### Workspace scaffolding

- Root `Cargo.toml`: resolver 3, members = existing dirs only (see bug a
  below), workspace lints (`unsafe_code = deny` except opted-in arenas,
  `missing_docs`, clippy pedantic), release profile (thin LTO,
  codegen-units 1, `panic = unwind` — consensus must never abort
  silently; panics are caught at actor boundaries).
- `rustfmt.toml`: stable-only options (see bug b below).
- `deny.toml`: GPL-3.0-compatible allowlist (MIT/BSD/Apache-2.0/MPL-2.0/
  Unicode-3.0/Zlib + GPL family), advisory + source bans.
- `.github/workflows/ci.yml`: fmt + clippy (RUSTFLAGS=-D warnings) + test
  on ubuntu, plus cargo-deny supply-chain job.

### `oxide-primitives` (first crate)

- Implemented: `Hash` (32B digest, hex Display/Debug with precision-aware
  truncation), `Address` (20B, EVM `H160`-compatible, unified account
  space), `Id<T>` generic counter over marker spaces (`Height`, `View`,
  `Epoch` — names render in logs), `TimestampMs` (advisory-only: state
  logic branches on heights, never clocks), `fixed` module (`Price`
  scale-1e8, `Qty` scale-1e6, notional in natural scale-14 `u128`,
  round-half-up division everywhere, checked ops, loud
  `Overflow`/`DivisionByZero` errors).
- Design note: comparison/hashing on `Id<T>` are **manual impls** —
  derives would demand `T: PartialOrd` on the marker types, and an `Id`'s
  identity is its raw counter, not its space.
- 10 unit tests, all green; `cargo fmt` + `cargo build` + `cargo test`
  clean.

### Bug hunt log (this session)

a. **Workspace member globs matching nothing break `cargo metadata`.**
   `members = ["crates/*", "modules/*", "bin/*"]` with only `crates/`
   existing made cargo treat `modules/*` as a literal path → "failed to
   read …/modules/*/Cargo.toml". Fix: list only existing globs + a NOTE
   in `Cargo.toml` to re-add `modules/*`/`bin/*` when their first crates
   land.
b. **Nightly-only rustfmt options warn on stable.** `imports_granularity`
   / `group_imports` emitted warnings on every `cargo fmt`. Fix: removed
   from `rustfmt.toml` with a note; to return if/when a nightly fmt CI
   job exists.
c. **Derive bounds on generic newtype.** `#[derive(PartialOrd)]` on
   `Id<T: IdSpace>` generates `T: PartialOrd` bounds the marker types
   don't satisfy → compile errors in tests. Fix: manual
   PartialEq/Eq/PartialOrd/Ord/Hash/Default impls (by-value `self.0`
   semantics; fully-qualified `std::hash::Hash` to avoid colliding with
   our own `Hash` struct).
d. **Off-by-one hand-written test expectation.** `test_display_formats_
   are_exact` failed: the hand-typed 64-hex-char expected string was one
   digit short. Fix: construct expectations mechanically (`"0".repeat()`)
   and document the lesson in the test — the test exists to catch exactly
   this class of bug, so its own expectations must not be hand-countable
   only.
e. **Dead code warning**: unused `Hash::HEX_LEN` const removed (truncation
   math derives from `bytes.len()` in the shared helper).
f. **Lint-group priority ambiguity.** `rust_2018_idioms = "warn"` (a lint
   *group*) alongside individual lints at the same implicit priority →
   clippy warning about precedence. Fix: explicit
   `{ level = "warn", priority = -1 }` for the group.
g. **clippy pedantic hygiene**: `MetaMask` needed backticks in a doc
   comment (`doc_markdown`), and `Id::next` needed `#[must_use]` —
   discarding `next()`'s result is always a caller bug. Both fixed.
h. **Typo'd lint name in workspace lints**: `need_pass_by_value` → the
   lint is `needless_pass_by_value`; the typo surfaced as an
   unknown-lint warning only in some targets. Fixed; clippy now
   warning-free across the workspace.

### `oxide-codec` (second crate, same session)

- Implemented the deterministic wire codec: `Reader` zero-copy cursor
  (`read_slice`/`read_fixed`/`read_u8..u128`/`read_bool`/`read_varint`/
  `read_bytes`), `write` free-function module (LE fixed ints, LEB128
  varints, length-prefixed bytes, strict booleans), `Encode`/`Decode`/
  `Codec` traits, impls for primitives + `Hash`/`Address`/`Id<T>`/
  `TimestampMs`/`Price`/`Qty`/`Vec<u8>`.
- Wire rules table is in the crate docs and pinned by tests
  (`test_wire_format_matches_spec` asserts exact bytes).
- 5 unit tests green (wire forms, varint boundaries, borrowed bytes,
  corruption-never-panics with exact error variants, domain-type forms).

### Bug hunt log (oxide-codec)

i. **Associated consts cannot be const-generic arguments.** The planned
   `read_fixed::<{T::LEN}>` for a blanket `impl<T: Fixed>` is rejected by
   rustc — associated consts are not const-generic arguments. Moved to
   slice-level reads with the `Fixed::LEN` contract checked via
   `debug_assert`.
j. **Blanket foreign-trait impl = future overlap (E0119).** rustc
   rejects `impl<T: Fixed> Encode for T` next to `impl Encode for u8`
   because upstream *could* later add `Fixed for u8`. Replaced with
   explicit per-type impls (`Hash`, `Address`) using their inherent
   `as_bytes`/`from_slice` (which also removed the trait import).
k. **HRTB needed in round-trip helper.** A naive `T: Codec<'a>` helper
   borrows a local buffer under a caller-chosen lifetime → E0597.
   Fixed with `T: for<'b> Codec<'b>` (owned types implement `Codec`
   for every lifetime).
l. **`as usize` cast flagged** (`cast_possible_truncation`): replaced
   with `usize::try_from` + an explicit invariant comment (claimed ≤
   remaining ≤ `usize::MAX`), mapping the impossible failure to the
   semantically-correct error variant.
m. Minor: import paths (`Price`/`Qty` live in `oxide_primitives::fixed`),
   `DoS` backticks, `0xAABB_CCDD_u32` separators, `vec!` → array,
   temp-value-dropped-while-borrowed in a test (bind the Vec first).
   clippy is warning-free after all of the above; an impl-block
   `#[allow(clippy::missing_errors_doc)]` on `Reader` carries a
   justification comment (per-method failure modes are the `DecodeError`
   enum's own exhaustive docs).

### Next up (Phase 0 remainder)

- `oxide-storage` (journal + MMR-over-log + Volatile backend + criterion
  benches; acceptance gates: ≥1M appends/s single-thread, MMR build+root
  over 1M leaves < 20ms) → `oxide-runtime` deterministic executor +
  4-node echo sim → `oxide-types`/`oxide-ports` (OAI traits + MockEngine
  + conformance skeleton) → protocol specs in `docs/` (oxidebft, OAI,
  storage) → fuzz targets (need nightly toolchain via rustup).

---

## 2026-09-08 — Session 2: benchmarks, plain-English docs, crate naming

### Benchmarks infrastructure (per owner request: "prove it was worth building")

- Added `.devin/skills/benchmarks/SKILL.md`: a hot-path feature isn't done
  until it's benched; gates cite their source; baselines strongest-first
  (displaced alternative → hardware floor → previous measurement);
  parity is an acceptable result when the win is determinism/no-alloc/
  zero-deps — say so honestly; numbers reported p50/p99 with machine
  context; plain-English explanation mandatory for user-facing changes.
- Added criterion benches: `primitives/benches/fixed.rs` (4 gates),
  `codec/benches/wire.rs` (7 gates incl. head-to-head vs `bincode` on an
  identical `Vec<u64>` payload — the "worth building" comparison).
- CHANGELOG entries now carry an "In plain words" section (retrofitted
  for primitives + codec); README/AGENTS list the benchmarks skill.

### Crate naming convention (owner decision)

- Crates drop the `oxide-` prefix: `oxide-primitives` → `primitives`,
  `oxide-codec` → `codec` (git mv, history preserved); future crates
  follow (consensus/storage/trading/…). Rationale: the workspace already
  scopes the names; matches the commonware bare-name convention; if ever
  published to crates.io a prefix can be added then. The Oxide identity
  lives in each file's header comment + Cargo.toml header instead.
  Kept as-is: `oxideBFT` (engine name), `oxide_*` JSON-RPC namespace,
  and `bin/oxide-*` commands.

### Bench results (dev Mac — relative claims only; all gates PASS)

| Bench | p50 | Gate |
|---|---|---|
| primitives: notional | 0.88 ns | < 10 ns ✓ |
| primitives: mul_div_half_up | 3.0 ns | < 150 ns ✓ (constant divisor → strength-reduced; noted) |
| primitives: qty_checked_ops | 2.2 ns | < 5 ns ✓ |
| primitives: hash/from_slice | 0.56 ns | < 15 ns ✓ |
| codec: encode u64 (warm buffer) | 0.89 ns | < 5 ns ✓ |
| codec: encode varint u64::MAX | 5.3 ns | < 25 ns ✓ |
| codec: decode varint u64::MAX | 4.1 ns | < 20 ns ✓ |
| codec: hash roundtrip | 3.65 ns | < 20 ns ✓ |
| codec: order-msg roundtrip (~80B) | 10.2 ns | < 80 ns ✓ |
| encode Vec<u64>×16: ours vs bincode | 10.1 vs 94.1 ns | ours 9.3× faster ✓ |
| decode Vec<u64>×16: ours vs bincode | 66.5 vs 93.6 ns | ours 1.4× faster ✓ (parity ≤ 2×) |

Framing stated in the bench file: our encode writes into a caller-owned
reused buffer (bincode's `encode_to_vec` allocates its result by API
design); both decodes allocate the output `Vec`.

### Bug hunt log (session 2)

n. **Bench honesty (three artifacts, found by the gates themselves):**
   (1) encode benches allocated the output buffer inside the timed loop —
   measuring the allocator, not the codec (u64 encode read 19ns; true
   cost 0.89ns); (2) the `Vec<u64>` decode wrapper grew its output Vec
   without capacity → 16 reallocations → 3.5× slower than bincode
   (166ns); fixed with `Vec::with_capacity(wire_len)` → 66ns, faster
   than bincode; (3) `iter_batched` with fresh buffers per batch charges
   first-touch cache misses to the codec (hash roundtrip read 38ns);
   production callers reuse one warm buffer → restructured to
   allocate-once-outside + `clear()`-inside. Lesson recorded: the bench
   must measure the *production shape* of the API, and every failed gate
   got a written explanation before the fix.
o. **`FnMut` escape**: closures returning references to captured buffers
   cannot implement `b.iter`'s `FnMut() -> T`; fix = observe the buffer
   inside the closure (`black_box(&buf);`) instead of returning it —
   same dead-store protection, no escaping borrow.

---

## 2026-09-08 — Session 3: the `storage` crate (journal + MMR + backend seam)

### Spec first

- Wrote `docs/storage-spec.md` v0 before any code (our own rule):
  journal format + recovery rules, MMR construction + domain-separated
  hashing, the minimal `StorageBackend` seam, and explicit out-of-scope
  staging (op linking, snapshots, cold adapters → later phases).

### What was built (`crates/storage`)

- **journal** (std-only core): CRC-32'd, length-framed records in
  size-bounded immutable segments; group commit (`append` is pure
  memory, `flush` is one sequential write, `sync` is one fdatasync per
  block batch); rotation; replay with torn-tail/corruption recovery
  (trust-the-complete-prefix); missing directory = empty journal
  (fresh-node bootstrap semantic, defined in the spec).
- **mmr**: Grin-lineage append-order forest with *incrementally
  maintained* peaks (push never re-derives forest shape); descent-based
  proofs (no left/right index-classification algebra); domain-separated
  BLAKE3 (0x01 node / 0x02 root), root binds leaf_count.
- **backend**: `StorageBackend` trait (deliberately minimal v0), `Op`,
  `Caps`, and `Volatile` (BTreeMap reference backend, byte-slice prefix
  `range` via lexicographic bounds).
- 16 unit tests + 6 proptest properties (Layer 2 of the pyramid now
  real): replay round-trip; **arbitrary-cut recovery** (expected prefix
  + truncation flag modeled from the byte layout — this IS the replay
  contract); every-leaf-proves / wrong-leaf-fails / determinism; batch
  last-op-wins + range semantics vs a model oracle.

### Gates (dev Mac; all relative claims)

| Gate | Result | Verdict |
|---|---|---|
| journal append ≥1M/s (100B) | 185 ns/op (5.4M/s) | **PASS** |
| journal append+flush amortized | 267 ns/op | **PASS** |
| journal sync per 1000-record batch | 3.96 ms | informational (per-batch by design) |
| MMR structure overhead | ~16 ns/op (176 − 160) | **PASS** (renegotiated gate) |
| MMR hash floor (65B node) | 160 ns | reported (hardware-bound) |
| MMR full 1M-leaf build | 248 ms | reported (hash-throughput-bound) |

### Bug hunt log (session 3)

p. **MMR peak-index semantics mismatch.** `peak_positions` (pure) keyed
mountains by their *first* node index while the incremental peak stack
tracks *root* node indexes — proof descent then computed
`left_child = first_node − 2^h` and underflowed. Unify on root indexes
(what descent and bagging actually consume); the exhaustive n≤64 test
caught it immediately.
q. **Hasher call-shape.** Chained `update`×3 hashing of 65-byte
preimages carried per-call state setup and block buffering; replaced
with single-shot hashing of a fixed stack preimage (byte-identical
result). Gain was modest (~10%) — which exposed the real story:
r. **Gate renegotiation (recorded, not silently weakened).** The plan's
"MMR root over 1M ops < 20ms" as a *single-threaded, hashing-included*
figure is unachievable with BLAKE3 on target hardware (1M internal
hashes × 65B = 2 compression blocks each ≈ ≥60ms even at AVX-512
rates; 160ns/call on this dev Mac). The gate is decomposed in the spec
into structure-only (<20ns — passes at ~16ns), the hash floor
(reported), and the full build (reported; parallelization —
independent mountain merges per level — staged for Phase 1 when the
real batch-commit path exists). plan.md's Phase 0 line updated to
match, with the decomposition pointer.
s. **Replay offset addressing counted the 8-byte segment header** while
`append` documents offset 0 = first record; replay now addresses
records from 0 (spec rule 4 honored).
t. **Property bug (the property, not the code):** tearing a fixed
number of bytes off the tail does not guarantee the cut lands *inside*
a record — at a record boundary the file is a clean prefix and
`truncated_at` is correctly `None`. Replaced with the arbitrary-cut
property that derives expected prefix + truncation flag from the byte
layout; the minimal failing input proptest found (`[[],[],[],[0,0]]`,
tear=10) is preserved in this entry as the canonical example.
u. **Misc:** `std::sync::AtomicU32` vs `std::sync::atomic::…` path;
`usize::from(u32)` does not exist (const-fn CRC table keeps a bounded,
justified `as`); `prop_assert_eq!` messages cannot capture variables;
`Vec` moves inside proptest macros → slice comparisons; clippy
autofixes (semicolons, doc backticks, `ilog2`, `?` for let-else).

### Next up (Phase 0 remainder)

- `runtime` (deterministic executor + 4-node echo sim) → `types` +
  `ports` (OAI traits + MockEngine + conformance skeleton) → protocol
  specs (`docs/oxidebft-spec.md`, `docs/oai-spec.md`) → fuzz targets.

## Session 4 — OAI spec, runtime, types, ports (Phase 0 foundation)

Spec-first, then code, then a real bug the conformance suite caught.

a. **`docs/oai-spec.md` v1.** The Oxide Application Interface — the
   ABCI-analog boundary, adapted to Oxide's two defining facts: engines
   order, they never execute; the chain's identity is engine-agnostic
   (followers consume `BlockRecord`, never an engine header). v0
   traits are *synchronous* on purpose — the reference path
   (MockEngine + deterministic runtime + conformance) is inherently
   synchronous, and premature async is an API every adapter must honor
   forever. The async-vs-channel decision is explicitly deferred to
   Phase 1 with the first real consumer (oxideBFT's loop).

b. **`runtime` crate — safe, std-only deterministic executor.** The
   reproducibility backbone of the five-layer test pyramid's top
   (deterministic simulation). `tokio`/OS scheduling is deliberately
   non-deterministic; this crate is the opposite: FIFO ready queue, FIFO
   mailboxes, no timers, no I/O, no threads, no `unsafe` (workspace
   denies it). Wakers built on stable `std::task::Wake` (`Arc<Task>` +
   `Send+Sync` via `Mutex` — the mutexes are never contended, they
   exist only to satisfy `Wake`'s bounds). A wake-dedup `AtomicBool`
   per task is the determinism invariant: without it the same task
   could appear in the ready queue multiple times and poll order would
   depend on how many redundant wakes happened.

   The 4-node echo sim (simplified Bracha reliable broadcast) is the
   Phase 0 acceptance: liveness (all nodes deliver), determinism (two
   runs → identical delivery sequence), and a pinned order
   `[3,0,1,2]` as a regression guard. Writing the sim caught a real
   protocol bug: the initiator (node 0) never receives `Init`, so it
   never echoes, so every node's echo-count tops out at N−1 and nobody
   delivers. Fix: node 0 emits its own `Echo` alongside the `Init`s.
   The `echo_known_order` test exists to guard that invariant — remove
   the self-echo and it fails with node 0 stuck at 3 echoes.

c. **`types` crate — OAI data model.** `TxBytes`, `BlockBudget`,
   `Proposal`, `Verdict`, `MempoolAck`, `FinalizedBlock`, `CommitAck`,
   `StateAttestation`, `BlockRecord` — all with `codec` impls so
   the consensus contract (byte-identical encodings across validators)
   holds for the whole boundary. Wire forms pinned by per-type unit
   tests. Adding string-carrying types (`Verdict::Reject`,
   `MempoolAck::Rejected`) justified a new `codec::DecodeError::InvalidUtf8`
   variant — the codec now carries strings, so the error belongs there
   rather than a misleading `InvalidBool` reuse at the call site.

d. **`ports` crate — the plug-and-play seams.** `ConsensusEngine` +
   `AppInterface` traits (matching the OAI spec), a reference
   `MockEngine`/`MockApp`, and a reusable `conformance::assert_conformance`
   suite asserting the four engine-agnostic rules: liveness, gap-free
   height sequence from genesis, finality-is-final, and determinism
   under identical inputs. Rules 4 (ordering-only) and 5 (attestations
   opaque) are exercised in the e2e test, which needs engine+app
   cooperation a generic factory can't provide.

e. **Bug the conformance suite caught (the point of writing it).**
   `MockApp::prepare_proposal` advanced `next_proposal_height` on every
   call. But the engine calls `prepare_proposal` to *check for pending
   work* and then drops the empty proposal — so the app's counter
   advanced with no block finalized, desyncing it from the engine's
   `next_height`. Result: finalized heights `{0, 2}` with a gap at 1,
   and the gap-free-heights assertion failed. Fix: the counter moves
   *only* in `finalize_block` (the one place a height is committed),
   keeping app and engine in lockstep. This is exactly the class of
   bug the conformance suite exists to catch — and it caught it before
   any real engine was built against the trait.

f. **Misc clippy/fmt:** `cast_possible_truncation` on varint→usize
   counts (added a `read_count` helper mapping overflow to
   `LengthPrefixTooLarge`, keeping the trust-boundary vocabulary
   uniform); `needless_range_loop` on broadcast loops → iterators;
   `missing_panics_doc` on the runtime's `Mutex::lock().unwrap()` (the
   mutexes can't be poisoned in single-threaded use — documented
   honestly in `# Panics` sections); `doc_markdown` backticks around
   `MockEngine`/`oxideBFT`.

### Verification

`cargo fmt --all -- --check` clean; `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean; `cargo test
--workspace` — 56 tests pass (codec 5, primitives 10, runtime 3,
storage 16 + 6 properties, types 11, ports 1 conformance + 4 e2e).

### Next up (Phase 0 remainder)

- `docs/oxidebft-spec.md` v1 draft.
- Fuzz targets at trust boundaries (codec decode, journal replay,
  MMR proof verify, consensus message decode).
- Then Phase 0 gate close.

## Session 4 addendum — oxideBFT spec v1 draft

`docs/oxidebft-spec.md` v1 (draft): pins the approved architecture for
the default consensus engine — pipelined two-chain Jolteon-style
HotStuff, BLS threshold signature aggregation, active pacemaker with
timeout certificates (tail-fork resistance), stake-weighted
round-robin leader rotation, decoupled execution. Records the
two-chain-vs-one/three-chain rationale (Jolteon is the minimal
pipelined form preserving HotStuff safety+liveness), the BLS-vs-Ed25519
choice (aggregate verification keeps the consensus hot path off the
floor), and a six-stage Phase 1 implementation order, each stage
gated by the OAI conformance suite. This is a design document, not
implementation; the implementation lands in Phase 1 against the OAI
traits and must pass `ports::conformance` before it ships.

## Session 4 addendum 2 — naming: generic identifiers, no CometBFT

User direction: code identifiers stay generic — no `Oxide` prefix on
types/traits/functions/crates. `OxideBlockRecord` → `BlockRecord`
(the engine-agnostic canonical ledger entry). The project name
"Oxide" lives in README/docs prose and the repo path, not in code;
code reads the same in any consumer. The single exception is
`oxideBFT`, the consensus engine's proper name (like HotStuff,
Jolteon) — a name, not a prefix, not generalized.

Also: no CometBFT references or usage anywhere. Oxide's engine is
oxideBFT; the boundary is the OAI, not ABCI/CometBFT. All CometBFT
mentions removed from docs/oai-spec.md, docs/oxidebft-spec.md, README,
types, devlog, changelog.

Codified in AGENTS.md (Conventions) and the production-rust skill
(§2 Structure & Naming) so future work honors it without re-deriving
the rule.

Verification: fmt clean, clippy -D warnings clean, 56 tests pass
(unchanged from before — pure rename + reference removal).

## Session 4 addendum 3 — fix cargo-deny CI failures

Three issues surfaced by the cargo-deny-action in CI:

g. **bincode unmaintained (RUSTSEC-2025-0141).** bincode is a dev-only
   benchmark dependency in `codec` (the "prove it was worth building"
   head-to-head comparison, benchmarks skill §4) — it never ships in a
   binary. The advisory states "No safe upgrade is available" (the team
   ceased development permanently). Added to `[advisories] ignore` in
   deny.toml with a documented justification: dev-only, no safe
   upgrade, reviewed. If a maintained alternative with equivalent
   ergonomics emerges (postcard, rkyv) we will switch and drop the
   ignore.

h. **Wildcard dependencies (bans FAILED).** cargo-deny's
   `wildcards = "deny"` flags workspace path deps without an explicit
   version — a bare `{ path = "crates/primitives" }` is a wildcard.
   Fixed by adding `version = "0.1.0"` to every workspace dependency in
   `[workspace.dependencies]`. This also resolved the
   `unresolved-workspace-dependency` bug for storage.

i. **GPL-3.0 deprecated SPDX (licenses parse-error warnings).** The
   SPDX identifier `GPL-3.0` is deprecated; the valid form is
   `GPL-3.0-only` (the repo's LICENSE is plain GPL-3.0, not "or
   later"). Updated `workspace.package.license` and the deny.toml
   allow-list (also fixed `LGPL-3.0` → `LGPL-3.0-only` and
   `AGPL-3.0` → `AGPL-3.0-only`).

Verified locally with `cargo deny check`: advisories ok, bans ok,
licenses ok, sources ok. The remaining `license-not-encountered`
warnings are informational (allowed licenses no current dep uses yet)
— not failures.

## Session 5 — Phase 0 completion: crypto, ports v1, oxide-bench, fuzz

The four remaining Phase 0 deliverables (plan.md §13, line 397):

j. **`crypto` crate.** Domain-separated BLAKE3 hashing (centralizing
   what storage applied inline) + BLS12-381 signature type stubs for
   oxideBFT. The `Domain` enum makes the domain tag a compile-time-
   checked part of the API — every hash call site names its domain
   explicitly, and the tag byte is pinned to the variant discriminant
   (part of the wire consensus contract). The `Hasher` API offers
   single-shot (`hash_one`), pair (`hash_pair`), and streaming
   (`new`/`update`/`finalize`) shapes. BLS types (`PublicKey`,
   `Signature`, `AggregateSignature`, `ValidatorIndex`) are Phase 0
   stubs — the types and codec are settled so oxideBFT Phase 1 fills
   in sign/verify/aggregate via `blst`, not the types. A `Signable`
   trait decouples the signing primitive from consensus types. 14
   tests pin domain separation (different domains never collide, same
   domain + same bytes always match, tag byte = discriminant) and
   BLS wire forms.

k. **`ports` v1 completion.** Added `BroadcastEngine` (DA port:
   erasure-coded broadcast by default, `PlainGossip` for devnets) and
   `Transport` (p2p port: commonware-p2p by default, in-process mock
   for deterministic sim). Both carry capability flags
   (`BroadcastCaps`, `TransportCaps`) checked at wiring time and by
   conformance. v0 synchronous, matching the OAI v0 traits; Phase 1
   revisits with oxideBFT's real I/O loop. The `Transport` send/recv
   shape mirrors `runtime::Mailbox` so the deterministic runtime can
   serve as a zero-code-change mock.

l. **`oxide-bench` harness.** `bin/oxide-bench` — a CLI that runs
   per-crate criterion benches in a unified harness with per-crate
   pass/fail summary and non-zero exit on failure (CI gate). Phase 0
   scope: invoke `cargo bench -p <crate>` for each registered target.
   Phase 1+ adds HDR histograms, adapter report cards, and dashboard
   output. Registered: primitives, codec, crypto, storage.

m. **Fuzz targets.** `fuzz/` with four cargo-fuzz targets at trust
   boundaries: `codec-decode` (every primitive codec decoder, no-panic
   on arbitrary bytes), `types-decode` (every OAI type decoder),
   `journal-replay` (arbitrary bytes as a segment file, replay must
   not panic), `mmr-proof-verify` (forged proofs, verify must not
   panic). `fuzz/` is its own workspace (empty `[workspace]` table)
   so it builds with nightly and its own dependency graph, separate
   from the root workspace. All four compile clean under nightly.

### Verification

`cargo fmt --all -- --check` clean; `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean; `cargo test
--workspace` — 70 tests pass (codec 5, crypto 14, ports 1 conformance
+ 4 e2e, primitives 10, runtime 3, storage 16 + 6 properties, types
11); `cargo deny check` — advisories ok, bans ok, licenses ok, sources
ok; `cargo +nightly check` in fuzz/ — all four targets compile.

### Phase 0 status: complete

All deliverables (plan.md line 397) are done: workspace scaffolding,
primitives, codec, crypto, runtime, ports v1 (all five traits),
storage journal + MMR, oxide-bench harness, CI, plan + oxideBFT spec
+ OAI spec. All acceptance gates (line 398) pass: journal append
≥1M ops/s, MMR structure overhead <20ns/op, 4-node echo sim, mock
engine OAI e2e. Phase 0 is closed.

## Session 6 — Phase 1 stage 1: oxideBFT vote/QC/TC types

Stage 1 of the oxideBFT spec's staged implementation order
(docs/oxidebft-spec.md §8): the consensus message types that oxideBFT
validators exchange, with pinned wire forms.

### What landed

Added to `crates/types`:

- `VotePhase` (`Prepare`/`PreCommit`/`Commit`): the 2-chain pipeline
  phase. `repr(u8)` with discriminants pinned (0/1/2) — part of the
  wire consensus contract. Unknown discriminants are rejected on
  decode, not silently defaulted.
- `Vote { view, phase, block_hash, signature }`: a single validator's
  signed vote. 137-byte wire form. The signature is a BLS12-381
  `crypto::bls::Signature` (96 bytes); the domain separation happens
  in the signer (Phase 1 stage 5), not in the type.
- `QuorumCertificate { view, phase, block_hash, epoch, signer_bitmap,
  aggregate_signature }`: ≥2f+1 votes compressed to one aggregate
  BLS signature + a bitmap. The bitmap's length is the validator set
  size (rounded up to the next byte); a `1` bit at position *i* means
  validator *i* signed.
- `TimeoutCertificate { view, epoch, signer_bitmap,
  aggregate_signature }`: ≥2f+1 timeout signatures proving a view
  should advance. The next leader embeds this in its proposal.
- `BlockHeader { height, view, epoch, prev_block, tx_root, high_qc,
  timeout_cert, proposer, timestamp }`: the engine-internal header.
  Distinct from `BlockRecord` (the OAI ledger entry): `BlockHeader`
  carries consensus-specific fields (view, epoch, QC, TC, proposer)
  that the OAI boundary strips away. Followers consume `BlockRecord`,
  never `BlockHeader`.

### Design decisions

- **Types in `types`, not a `consensus` crate.** The wire forms are
  part of the consensus contract (byte-identical encodings across
  validators), and the codec round-trip property must hold. The
  pacemaker and vote pipeline (stages 2-4) will live in a `consensus`
  crate; the types stay here.
- **`BlockHeader` vs `BlockRecord`.** The OAI spec is explicit:
  engines produce their own headers, the app maintains the canonical
  `BlockRecord` ledger. `BlockHeader` is what oxideBFT agrees on;
  `BlockRecord` is what the journal stores. The conversion happens
  at the OAI boundary (stage 3).
- **BLS types are still stubs.** `Signature` and `AggregateSignature`
  are the Phase 0 `crypto::bls` types — fixed-size byte arrays with
  codec impls. Stage 5 wires in `blst` for sign/verify/aggregate; the
  types don't change.
- **`VotePhase` is `repr(u8)`.** The discriminant is the wire byte;
  `as u8` in encode and `from_byte` in decode. No `Default` — a
  missing phase is a decode error, not a silent `Prepare`.

### Verification

`cargo fmt --all -- --check` clean; `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean; `cargo test
--workspace` — 78 tests pass (types 19, up from 11: 8 new consensus
type wire-form + reject tests); `cargo deny check` — all four checks
ok.

### Next

Stage 2: the pacemaker as a state machine over views (no networking):
timeout → TC formation → view advance. Unit + property tests. This
will be the first code in a new `consensus` crate.

## Session 7 — Phase 1 stage 2: pacemaker state machine

Stage 2 of the oxideBFT spec's staged implementation order
(docs/oxidebft-spec.md §8): the pacemaker as a pure state machine
over views — no networking, no real BLS signing (stage 5 adds that).

### What landed

New `consensus` crate with two modules:

- `validator.rs` — `ValidatorSet` + leader election. Fault tolerance
  (`f = (n-1)/3`), quorum (`2f+1`), and stake-weighted round-robin
  leader election. The leader for view *v* is determined by
  `view % total_stake` mapped through a cumulative-stake binary
  search — O(log n), deterministic, no VRF. For equal stakes this
  reduces to pure round-robin (`view mod n`); for unequal stakes a
  high-stake validator leads proportionally more often. Tested: a
  90%-stake validator leads ~90% of views over 1000 samples.

- `pacemaker.rs` — the pacemaker state machine. Two states
  (`Active`, `TimedOut`), four events:
  - `on_local_timeout()`: timer expired → broadcast Timeout, transition
    to `TimedOut`. Idempotent within a view (no re-broadcast).
  - `on_timeout_signature(validator, sig)`: collect a timeout sig; on
    quorum (≥2f+1), form a TC and advance the view. Duplicate sigs
    are ignored (idempotent via bitmap).
  - `on_timeout_certificate(tc)`: external TC for the current view →
    advance immediately (a peer already collected the quorum). Stale
    TCs (past view/epoch) are ignored.
  - `on_progress()`: valid proposal arrived → reset timer and backoff,
    transition back to `Active`.

  Exponential backoff: consecutive timeouts double the timeout
  duration (capped at 30s). Progress resets to the 2s base.

### Design decisions

- **Pacemaker is a pure state machine.** It does not send messages;
  it emits `PacemakerEvent`s for the consensus loop (stage 3) to act
  on. This keeps the pacemaker testable without networking and lets
  the deterministic runtime drive it synchronously.

- **Signatures collected but not verified (stage 2).** The pacemaker
  counts signatures and checks quorum, but does not verify BLS
  signatures — that's stage 5's job (`blst` integration). The caller
  is responsible for verifying before calling `on_timeout_signature`.
  The TC's aggregate signature is `AggregateSignature::ZERO` (a
  placeholder); stage 5 replaces this with real BLS aggregation.

- **`view % total_stake` for leader election.** The original stride-
  based approach (`view * stride % total_stake`) gave uniform
  distribution regardless of stake — wrong. `view % total_stake`
  cycles through every point in `[0, total_stake)`, so each validator
  gets selected proportionally to its stake. For equal stakes this
  is pure round-robin; for 1:9 stake it gives 10%/90% as expected.

- **Bitmap-based signer tracking.** The pacemaker uses the same
  bitmap format as the QC's `signer_bitmap` — a `Vec<u8>` with one
  bit per validator. This makes TC formation a direct copy of the
  bitmap, no conversion needed.

### Verification

`cargo fmt --all -- --check` clean; `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean; `cargo test
--workspace` — 97 tests pass (consensus 19: 10 pacemaker + 9
validator); `cargo deny check` — all four checks ok.

### Next

Stage 3: the single-leader happy path (no view changes) — prepare →
pre-commit → commit pipeline, emitting `finalize_block` on commit.
This is the first code that actually drives the OAI boundary through
oxideBFT. The conformance suite must pass.

## Session 8 — Phase 1 stage 3: oxideBFT engine, single-leader happy path

Stage 3 of the oxideBFT spec's staged implementation order
(docs/oxidebft-spec.md §8): the engine that drives the OAI boundary
through oxideBFT. The conformance suite passes.

### What landed

New `crates/consensus/src/engine.rs` — the `OxideBft` engine
implementing `ports::ConsensusEngine`:

- **Block proposal:** calls `app.prepare_proposal(budget)` to get a
  `Proposal`, wraps it in a `BlockHeader` (with view, epoch, `high_qc`,
  proposer, `tx_root`), and stores it keyed by block hash.
- **Self-vote:** single-validator mode (quorum = 1); the engine votes
  for its own proposal, forming a `Vote` with a placeholder BLS
  signature (`Signature::ZERO` until stage 5 wires in `blst`).
- **QC formation:** aggregates the self-vote into a
  `QuorumCertificate` with a signer bitmap and placeholder aggregate
  signature.
- **1-chain commit:** commits immediately on QC formation. Safe in
  the single-leader happy path (no view changes, no faults). Stage 4
  upgrades to 2-chain when view changes are introduced.
- **OAI boundary:** drives the full cycle — `prepare_proposal` →
  `process_proposal` → `finalize_block`. `attest_state` is available
  for the next proposal.
- **`run_until_idle`:** drives propose-vote-commit cycles until no
  pending txs (matching the conformance suite's synchronous model).

### Conformance suite modification

The conformance suite was modified to handle pipelined engines:

- **Liveness:** checks all submitted txs appear in some finalized
  block (not one block per tx). Pipelined engines may produce empty
  blocks to advance the pipeline; those are valid finalized blocks.
- **Heights:** contiguous (0..N with no gaps), empty blocks OK.
- **Finality + determinism:** unchanged.

The `MockEngine` still passes the modified suite (one block per tx,
no empty blocks). The `OxideBft` engine passes with the 1-chain rule
(one block per tx, no empty blocks in the happy path).

### Design decisions

- **1-chain for stage 3, 2-chain for stage 4.** The 2-chain rule exists
  to preserve safety under view changes (a block locked by a
  pre-commit QC cannot be forked by a new leader). In the single-
  leader happy path, there are no view changes and no faults, so
  1-chain is safe. Stage 4 upgrades to 2-chain when view changes are
  introduced.

- **Single-validator mode.** The engine self-votes (quorum = 1). This
  is the simplest configuration that exercises the full OAI boundary
  and the oxideBFT types. Multi-validator mode (with networking) is
  stage 4+.

- **Placeholder BLS signatures.** `Signature::ZERO` and
  `AggregateSignature::ZERO` are used in votes and QCs. Stage 5
  replaces these with real `blst` signing and verification. The types
  and codec are settled; only the crypto is stubbed.

- **`proposer_hash` helper.** The proposer is identified by a `Hash`
  derived from the `ValidatorIndex`. Stage 5 replaces this with the
  actual public key hash. The helper avoids an orphan-rule violation
  (can't `impl From<ValidatorIndex> for Hash` in the consensus crate).

### Verification

`cargo fmt --all -- --check` clean; `cargo clippy --workspace
--all-targets --all-features -- -D warnings` clean; `cargo test
--workspace` — 104 tests pass (consensus 26: 19 pacemaker/validator +
7 engine, including `oxidebft_passes_conformance`); `cargo deny
check` — all four checks ok. MockEngine conformance test still passes.

### Next

Stage 4: view changes via TC (faulty leader bypass). This upgrades
the commit rule from 1-chain to 2-chain and wires in the pacemaker for
active view synchronization. The conformance suite + deterministic
simulation must pass.
