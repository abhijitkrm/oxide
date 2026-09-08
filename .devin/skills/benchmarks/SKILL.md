---
name: benchmarks
description: Benchmark guidelines for Oxide — when a feature must be benched before it counts as built, criterion harness conventions, gates and baselines (including "prove it was worth building" comparisons), reporting rules, and how numbers land in the devlog/changelog.
---

# Benchmark Standards (Oxide)

A performance claim without a number is a rumor. On this project,
**a hot-path feature is not "done" until it is benched** — and a
replacement for an off-the-shelf alternative must show a measured reason
it was worth building (faster, cheaper, or deterministic where the
alternative is not).

## 1. When a benchmark is required

| Change | Bench required? |
|---|---|
| Any new crate touching a hot path | Yes — ships in the same commit as the code |
| New hot-path function | Yes — criterion bench + documented budget |
| Replacing a standard library / ecosystem solution | Yes — **head-to-head comparison** against the displaced option on identical payloads ("prove it was worth building") |
| Claim in docs/README/devlog that X is fast | Yes — the claim cites the bench by name |
| Cold-path code (RPC handlers, config, genesis, snapshots) | No — clarity over speed; say so in the doc comment |
| Bug fix that could affect timing | Yes if the function had a budget comment |

## 2. Harness conventions (criterion)

- Benches live in `benches/` per crate, `harness = false`, run via
  `cargo bench -p <crate>` (or `--workspace`).
- Every bench file's doc comment states, per function: **what** is
  measured, the **gate** (pass/fail threshold + its source), and the
  **baseline** it is compared against (memcpy floor, displaced
  alternative, or previous measurement).
- Use `criterion::black_box` on inputs and outputs — the compiler must
  not optimize the work away.
- Measure *warm* steady-state behavior (criterion does this); if
  real-world behavior includes cold paths (first-touch of huge pages),
  bench that separately and label it.
- No allocation inside the timed loop *that the benchmark itself
  introduced* (pre-allocate buffers outside `iter`; `iter_batched`
  with `BatchSize::SmallInput` when setup is unavoidable).
- Keep payloads realistic: sizes from the actual protocol (32-byte
  hashes, ~100–200B messages, 1M-op batches), not powers of ten chosen
  for pretty numbers.

## 3. Gates and baselines

- **Gate** = a number with a source (README roadmap phase gate, a spec
  section, or the function's budget comment). If the gate fails, the
  commit does not land — either fix the code or renegotiate the gate in
  the same PR with justification.
- **Baseline** options, strongest first:
  1. The displaced alternative (e.g., bincode/serde for the codec),
     same payload, same machine.
  2. The hardware floor (e.g., `memcpy` of the same byte count —
     "we are within N× of memcpy").
  3. The previous measurement (regression tracking; criterion reports
     this automatically on re-runs).
- **Parity is a valid result.** If we match the ecosystem option but
  gain determinism/no-alloc/zero-deps, say exactly that in the
  changelog — do not imply a speed win that isn't there.

## 4. Reporting rules

- Numbers are reported as **p50 / p99 with unit and machine context**
  ("M2 dev machine" for relative claims; the 16-core x86_64 rig is the
  source for absolute gate claims — README roadmap).
- Every bench result lands in **three places**: the bench file's doc
  comment (budget), the **devlog** (session entry, with before/after if
  optimizing), and the **changelog** (user-visible "what & why" with the
  plain-English explanation).
- **Plain-English explanation is mandatory** for every user-facing
  feature (changelog entry): one or two sentences a non-engineer could
  follow — what it does, why it matters, what the number means in human
  terms (e.g., "the codec reads a transaction in ~40 nanoseconds — about
  25 million transactions per second on one core").
- Criterion's change-detection output (`target/criterion`) is never
  committed (gitignored); numbers are transcribed with machine context.

## 5. Honesty rules

- Never bench with dependencies/features compiled out that production
  uses; benches build in the workspace release-bench profile.
- If a measurement is noisy (>10% swings between runs), fix the
  measurement (pin cores, larger sample, quieter machine) before
  publishing numbers.
- A failed gate is recorded in the devlog as a failure with the
  follow-up plan — never silently dropped or re-run until lucky.
