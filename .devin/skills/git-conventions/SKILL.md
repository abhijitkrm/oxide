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
