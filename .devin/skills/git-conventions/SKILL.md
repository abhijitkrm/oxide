---
name: git-conventions
description: Git conventions for the Oxide repository — commit message format, history hygiene, and the no-attribution rule. Apply whenever creating commits, merges, or any git history in this repository.
---

# Git Conventions (Oxide)

## The no-attribution rule (explicit project policy)

**Never add AI attribution to commits unless the user explicitly asks for it
in the request that produced the commit.** Concretely, do **not** add:

- `Co-Authored-By: Devin <...>` (or any other tool/bot) trailer lines
- `Generated with <tool>` / `Authored by <tool>` lines
- Any boilerplate crediting an assistant in the message body

The user owns this history; commit authorship reflects the humans involved.
If the user explicitly requests attribution in a specific commit, add exactly
what they asked for — nothing more, and only for that commit.

## Commit messages

- **Subject:** imperative mood, ≤ 72 chars, no trailing period
  (`add MMR leaf proof verification`, not `added verification`).
- **Body:** explain *why* the change exists and what tradeoff was made —
  not a diff narration. Reference the spec section or phase gate that
  motivates it (`docs/oxidebft-spec.md §3`, `README.md → Roadmap Phase 0`).
- **Scope prefix** when it aids scanning: `consensus:`, `codec:`,
  `storage:`, `trading:`, `docs:`, `ci:`, `bench:`. A cross-cutting change
  may omit it.
- One logical change per commit. Bench numbers that justify a perf change
  belong in the body (`p50 412ns → 188ns, bench: matching/insert`).

## History hygiene

- Never amend, rebase, or force-push commits that exist on a shared remote
  branch. Fix-ups on an unpushed local branch are fine.
- Never commit secrets, keys, or local node data (`/local`, `/data`, logs
  are gitignored).
- `plan.md` is gitignored by design — never `git add -f` it.
- Do not push unless explicitly asked; do not rewrite remote history ever.

## Pre-commit checklist

1. `cargo fmt --check` clean (or run `cargo fmt` and restage).
2. `cargo clippy --workspace --all-targets -- -D warnings` clean.
3. `cargo test --workspace` green.
4. `docs/devlog.md` has an entry for this change (every step, however
   small — decisions, bug hunts with root cause, fixes) and
   `CHANGELOG.md` updated if anything user-visible shipped.
5. Message follows the format above, with **no attribution trailers**.
6. **Workspace cleanup done** (see below) — nothing generated is left
   running or on disk to eat space.

## Cleanup after each task

Every commit/task ends with a cleanup pass. The rule: *if the task
created it and it isn't source or committed evidence, it goes away.*

- **Scratch files:** remove temp scripts, stray logs, `*.tmp`, core
  dumps, downloaded fixtures, and ad-hoc binaries the task produced.
  `git status` should show only intentional changes.
- **Test/fuzz artifacts:** `fuzz/artifacts/` is gitignored — leave
  crash inputs for triage until the fix lands, then delete them.
  Committed `fuzz/corpus/` stays (it is the regression set); prune
  obviously bloated corpus entries that add no coverage.
- **Docker:** after any testnet run, `docker compose down` and remove
  task-built images (`docker image rm oxide-validator-*`) plus
  `docker system prune -f` for dangling layers if disk is tight.
- **Devnet/node state:** kill any `oxide-*` processes the task started
  (matcher, validator, loadgen); remove `local/`, `data/`, or other
  node dirs the run created (gitignored anyway — don't leave them).
- **Build artifacts:** leave `target/` alone during a work session
  (rebuilds are expensive). Between heavy runs, or when disk pressure
  shows, `cargo clean` is acceptable — `target/criterion` is never
  committed regardless.
- **Gate evidence:** `docs/evidence/` output that a gate requires IS
  committed; everything else generated (coverage html, pprof dumps,
  bench reports) is not.
- **Background work:** no orphaned shell jobs, watch loops, or
  port-bound processes survive the task.
