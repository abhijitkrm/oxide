---
name: testing-standards
description: The Oxide testing mechanism — the five-layer test pyramid (unit, property, conformance, simulation, benchmark+fuzz), where each kind of test lives, how to run it, and the acceptance gates every change must pass before merge.
---

# Testing Standards (Oxide)

Oxide is a financial system: a consensus bug or matching-engine divergence
loses user funds. Testing here is a mechanism, not an afterthought — five
layers, each catching what the previous one cannot.

## The Pyramid

```
            ┌─────────────────┐
            │  fuzz/ (cargo-  │   adversarial input discovery
            │  fuzz targets)  │   (nightly CI, corruption/bit-flips)
            ├─────────────────┤
            │  sim/           │   deterministic swarm simulation:
            │  (10k+ views)   │   partitions, byzantine strategies
            ├─────────────────┤
            │  conformance    │   adapter contracts: consensus &
            │  suites         │   storage seams must hold for EVERY
            ├─────────────────┤   registered engine/backend
            │  property tests │   proptest: invariants over input
            │  (per crate)    │   spaces (codec round-trips, margin
            ├─────────────────┤   invariants, MMR proofs)
            │  unit tests     │   exact behavior, edge cases
            │  (in-module)    │
            └─────────────────┘
```

## Layer 1 — Unit tests

- Live in-module (`#[cfg(test)] mod tests` at the bottom of the file) so
  private helpers are testable and the test sits next to the code it guards.
- Name = the property protected: `test_bitboard_finds_best_bid_after_gap`,
  not `test_book_1`.
- Every error path has at least one test asserting the exact variant.
- **Determinism rule:** no `std::time`, no randomness, no thread-sleep-based
  assertions. If timing matters, inject a `Clock` (oxide-runtime).

## Layer 2 — Property tests (proptest)

- One `proptest!` suite per crate, in `tests/properties.rs`.
- Mandatory properties (already specced — do not skip when touching these):
  - codec: `encode(decode(x)) == x` for every `Codec` type, and decode of
    corrupted bytes never panics (returns `Err`).
  - journal: replay(append(ops)) == ops for arbitrary op sequences, including
    torn final record (crash simulation).
  - MMR: every leaf in [0, n) verifies against root for arbitrary n.
  - matching: parallel/native book ops == sequential model oracle for
    arbitrary order sequences (the anti-divergence property).
  - fixed-point: mul/div round-trip within 1 ulp of scaled rational.
- Regression workflow: **bug → failing property test → fix → green.** A PR
  fixing a bug without a new property/unit test is incomplete.

## Layer 3 — Conformance suites (oxide-ports / oxide-storage)

Any pluggable adapter (`ConsensusEngine`, `StorageBackend`) must pass its
conformance suite before it can be registered in `oxide-node`:

- `consensus-conformance`: no reorg after `finalize_block`; deterministic
  ordering under identical message logs; commit certificates verifiable;
  epoch/validator-set transitions; leader-failure recovery within bounded
  views.
- `storage-conformance`: batch atomicity; crash-replay determinism; iteration
  order stability; snapshot export/import round-trip MMR equality.

Run: `cargo test -p oxide-ports --features conformance` (and the storage
equivalent). CI runs these against **every** registered adapter in a matrix.

## Layer 4 — Deterministic simulation (sim/)

- Uses `oxide-runtime::deterministic` (single-threaded executor, seeded,
  reproducible by `(seed, scenario)` pair — the commonware deterministic-
  runtime pattern).
- Scenarios: kill-leader, partition(1/3), asynchrony bursts, byzantine
  vote/withhold/spam, leader-failure storms.
- Nightly job runs 10k+ views per scenario; consensus safety violations are
  release blockers.
- A failing sim must be reducible to a unit test before the fix is merged.

## Layer 5 — Benchmarks & fuzzing

- Criterion micro-benches per hot-path crate. Every bench documents its
  **acceptance gate** (source: the phase gates in `README.md` → Roadmap).
  CI fails on regression beyond noise (criterion's noise threshold;
  important gates get hard numbers).
- Phase 0 gates (already fixed): journal ≥1M appends/s single-thread;
  MMR build+root over 1M leaves < 20ms.
- `fuzz/` holds cargo-fuzz targets (codec, consensus messages, matching
  engine vs. oracle, journal torn-write replay). Run locally with
  `cargo +nightly fuzz run <target>` — nightly CI job with 10-minute budget.

## Commands (source of truth)

```sh
cargo fmt --check                     # formatting gate
cargo clippy --workspace --all-targets -- -D warnings   # lint gate
cargo test --workspace                # unit + property + conformance
cargo bench --workspace               # criterion + gates
cargo +nightly fuzz run codec -- -max_total_time=600    # fuzz target
```

## Review checklist for tests

1. Does the change have a test that would have caught the bug it fixes?
2. Do new public functions have at least one unit test per outcome
   (Ok and every realistic Err)?
3. Are tests deterministic (no time/random/sleep)?
4. If an adapter changed: conformance suite updated + run?
5. If a hot path changed: bench re-run and gate checked?
