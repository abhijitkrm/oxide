# AGENTS.md — working in the Oxide repository

Oxide is a first-principles Rust L1 blockchain with an HFT-grade trading
stack. The full architecture, phase plan, and acceptance gates live in
**`plan.md`** (the internal engineering megaplan — **gitignored, local
only**; keep it updated as work progresses). Public protocol specs live in
`docs/` and precede implementation — if code and spec disagree, fix the
wrong one in the same PR.

## Non-negotiable standards (read before writing code)

Codified as skills in `.devin/skills/`:

1. **`production-rust`** — fully detailed doc comments (the *why* + spec
   refs, no magic numbers), no `unwrap` outside tests, `unsafe` confined to
   arenas/huge-pages with SAFETY comments, hot-path crates stay std-only.
2. **`testing-standards`** — five layers: unit → proptest properties →
   conformance suites (adapters) → deterministic simulation → bench gates +
   fuzz. Bug fix = failing test first, then the fix.
3. **`performance-first`** — hot paths: zero alloc, zero syscall, no locks
   (single-writer + SPSC rings), u64 fixed-point only, cache-line hygiene,
   batch everything, measured budget comment on every hot function.
4. **`git-conventions`** — imperative subjects, *why*-focused bodies,
   scope prefixes — and **never add AI co-author/attribution trailers to
   commits unless the user explicitly asks** (project policy).
5. **`benchmarks`** — a hot-path feature isn't done until it's benched;
   gates + baselines (including head-to-head vs the displaced
   alternative), plain-English reporting of results; every user-facing
   changelog entry carries an "In plain words" section.

## Commands

```sh
cargo build --workspace                                # build everything
cargo test --workspace                                 # unit + property + conformance
cargo fmt --check                                      # formatting gate
cargo clippy --workspace --all-targets -- -D warnings  # lint gate
cargo bench --workspace                                # criterion + acceptance gates
cargo +nightly fuzz run codec -- -max_total_time=600   # fuzz target (nightly)
```

CI (`.github/workflows/ci.yml`) runs fmt + clippy + test + deny on every PR;
nightly adds fuzz and long simulations.

## Structure quick map

- `crates/*` — infrastructure crates (bare names, no `oxide-` prefix:
  the workspace already scopes them; see devlog session 2 for the
  convention); ★ differentiating custom cores:
  `consensus` (oxideBFT), `storage` (journal + MMR),
  `trading` (matching engine), `executor`, `ports` (the
  plug-and-play seams + conformance suites).
- `modules/` — Cosmos-SDK-style module framework (`framework/`) and chain
  modules (`core`, `bank`, `staking`, `evm`, `exchange`, `perps`, `oracle`,
  `governance`).
- `bin/` — node binaries and tooling (`oxide-validator`, `oxide-fullnode`,
  `oxide-spammer`, `oxide-deploy`, `oxide-bench`).
- `sim/`, `fuzz/` — deterministic swarm simulations (`oxide-sim` crate, echo sim now; Phase 4 adds byzantine strategies); cargo-fuzz targets.

## Conventions

- **Log as you go:** every change gets a `docs/devlog.md` entry (no
  matter how small — decisions, dead ends, bug hunts with root cause),
  and `CHANGELOG.md` is updated for anything user-visible. This is part
  of the pre-commit checklist (`.devin/skills/git-conventions`).

- Edition 2024; workspace lint level strict (`clippy::all -D warnings`).
- **Naming: keep code identifiers generic — no `Oxide` prefix on types,
  traits, functions, or crates.** The project name ("Oxide") lives in
  README/docs prose and the repo path; code stays engine- and
  project-neutral so types read the same in any consumer. The one
  exception is `oxideBFT`, the consensus engine's *proper name* (like
  HotStuff, Jolteon) — it is not a prefix and is not generalized.
  **No CometBFT references or usage anywhere** — Oxide's engine is
  oxideBFT; the boundary is the OAI, not ABCI/CometBFT.
- Every constant on a hot path carries a comment: unit, origin (plan.md /
  spec §), and the tradeoff of changing it.
- Benchmarks document the acceptance gate they enforce (source: plan.md §13).
- New dependencies: justify in the PR, must be published ≥7 days, exact-pin,
  `cargo deny check` green. Hot-path crates take **no** dependencies.
- Commits: imperative subject + body explaining *why*.
- License headers: not required; the repository is GPL-3.0 — dependencies
  must be GPL-3.0-compatible (MIT, BSD, Apache-2.0, MPL-2.0, GPLv2-or-later
  and AGPL-3.0 are fine; GPLv2-only, CDDL, and proprietary are not —
  `deny.toml` enforces).

## Current status

Phase 2 complete (EVM + storage). See `plan.md` §13 for the phase
gate that is currently being worked toward. Do not start Phase N+1
work before Phase N's gates pass unless the plan says otherwise.
