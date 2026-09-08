---
name: production-rust
description: Mandatory production-grade Rust coding standards for the Oxide blockchain — first-principles readability, fully detailed comments, strict error handling, and unsafe policy. Apply to every code change in this repository.
---

# Production Rust Standards (Oxide)

Every line of code in this repository is written for a production financial system.
These standards are **non-negotiable** and apply to all crates in the workspace.

## 1. First-Principles Readability

Code must make sense to a strong engineer reading it for the first time, without
context from the author.

- **Every module starts with a `//!` doc comment** that answers three questions:
  1. What does this module do (one paragraph, concrete)?
  2. Why does it exist (what problem in the architecture does it solve)?
  3. What are its invariants (what must always be true)?
- **Every public item** (struct, trait, fn, enum, const) carries a `///` doc comment
  with at least one full sentence of intent — not a restatement of the name.
  Include `# Errors`, `# Panics`, and `# Safety` sections where applicable.
- **Explain the WHY, not the WHAT.** `// increment i` is noise. `// We advance the
  view *before* dispatching the timeout so a new leader's proposal is never
  compared against a stale QC` is signal.
- **No magic numbers.** Every constant is a named `const` with a comment giving
  its unit, its origin (spec section, benchmark, or protocol rule), and its
  tradeoff. Example:

  ```rust
  /// Target block cadence. Source: plan.md §4 (oxideBFT performance budget).
  /// Halving this doubles WAN round-trip pressure on slow validators; do not
  /// change without re-running the `consensus-cadence` bench.
  pub const TARGET_BLOCK_TIME_MS: u64 = 50;
  ```

- **Spec-first:** non-trivial logic references its spec (`docs/oxidebft-spec.md`
  §section, `docs/oai-spec.md` §section) in the doc comment. If no spec section
  exists yet, write it before writing the code.

## 2. Structure & Naming

- One concept per type; one responsibility per module. If a module exceeds
  ~500 lines, split it.
- Types are nouns (`OrderBook`, `ViewCertificate`); functions are verbs
  (`recover_threshold`, `apply_batch`); predicates read as questions
  (`is_finalized`, `has_quorum`).
- Booleans are never bare parameters (`fn place(self, post_only: bool)` is
  unreadable at call sites) — use an enum (`PostOnly::Yes/No`) or a builder.
- `#[repr(C, align(64))]` and explicit layouts are used on any struct that
  crosses a cache-line boundary on a hot path, with a comment stating which
  fields are hot and why they are grouped.

## 3. Error Handling

- Library crates define a `thiserror` error enum per module. No `String`
  errors, no `Box<dyn Error>` in public APIs.
- `unwrap()`/`expect()` are **forbidden** outside `#[cfg(test)]`, benches, and
  `main` binaries. Use `?`, explicit matches, or `Result` returns.
- Exceptions where `expect` is allowed must carry a proof-of-impossibility
  comment: `// Invariant: pool was sized to MAX_RESTING_ORDERS at genesis
  // (storage-spec.md §3); exhaustion is a protocol bug and must abort loud.`
- Errors that indicate *byzantine behavior* (bad signature, invalid proposal)
  are distinct from *operational* errors (io failure) — separate variants, so
  the caller can penalize peers vs. alert operators.

## 4. Unsafe & Low-Level Policy

- `unsafe` is only permitted in: memory arenas, huge-page allocation, and
  SIMD intrinsics. Every `unsafe` block carries a `// SAFETY:` comment
  enumerating the invariants that make it sound.
- Any `unsafe` code ships with a dedicated test that attempts to violate the
  invariant (overflow, double-free, aliasing) and asserts the guard holds.
- No `unsafe` in consensus-critical logic paths unless it is a measured,
  benchmarked win >5% and flagged in review.

## 5. Dependencies

- Hot-path crates (`oxide-primitives`, `oxide-codec`, `oxide-trading`,
  `oxide-storage` journal core) must remain **dependency-free** (std only) —
  this is a supply-chain and performance guarantee.
- New dependencies anywhere require: (a) a justification comment in the
  crate's README or Cargo.toml, (b) `cargo deny check` passing, (c) published
  ≥7 days, pinned exact version in Cargo.lock committed to the repo.

## 6. Comments on Tests & Benchmarks

- Every test name states the property it protects:
  `test_2chain_commit_rule_finalizes_after_two_views`.
- Every benchmark states the acceptance gate it enforces in its doc comment
  (e.g., "gate: ≥1M journal appends/sec single-thread, plan.md §13 Phase 0").

## 7. Definition of Done (per PR)

1. `cargo fmt --check` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean.
2. Doc comments + spec references present and current.
3. Unit + property tests green; regression test added for any bug fixed
   (failing test first, then fix).
4. Benchmarks re-run if a hot path was touched; no gate regressions.
5. No `unwrap` outside permitted zones; unsafe blocks justified with SAFETY comments.
