# Changelog

All notable, user-visible changes to the Oxide project are documented in
this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project is pre-alpha and unreleased, so everything lives under
`[Unreleased]` until the first tagged release. Granular engineering history
lives in [`docs/devlog.md`](docs/devlog.md).

## [Unreleased]

### Added

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
    policy: no AI attribution trailers unless explicitly requested).
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

- **`oxide-primitives` v0.1.0** (2026-09-08) — foundational types
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

### Changed

- **License references aligned to GPL-3.0** (2026-09-08): README and
  AGENTS.md now point at the repository's single GPL-3.0 `LICENSE`
  (previously referenced a dual MIT/Apache scheme with files that did
  not exist). Dependency policy updated accordingly: dependencies must
  be GPL-3.0-compatible (MIT, BSD, Apache-2.0, MPL-2.0, GPLv2-or-later,
  AGPL-3.0 are; GPLv2-only, CDDL, proprietary are not).

[Unreleased]: https://github.com/abhijitkrm/oxide/compare/HEAD
