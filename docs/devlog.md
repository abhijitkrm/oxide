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
