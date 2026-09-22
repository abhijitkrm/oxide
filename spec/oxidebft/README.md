# oxideBFT TLA+ model

`OxideBft.tla` is a faithful abstraction of the safety-relevant rules
in `crates/consensus/src/engine.rs` — not generic HotStuff. It models:

- the two-chain commit rule as a **recursive justify-edge walk**
  (`AdoptQC` → `CommitChain`), gated on per-validator block storage
  (`stored`) the way the engine gates on its `blocks` map;
- proposer-**derived** heights (`height = parent.height + 1`,
  `prev = justify`, `prev ∈ stored`) — the fixes TLC drove;
- per-height vote locks with **timeout-certificate release**
  (`TCReleases`) and one-vote-per-view monotonicity;
- view synchronization via TCs and QC catch-up;
- Byzantine proposals/votes/timeouts (arbitrary stamped heights,
  `prev ≠ justify` attempts, equivocation via `MaxVariants`).

Checked invariants (`OxideBft.cfg`): `InvHeightConflict` (no
same-height fork), `InvSingleChain` (all commits on one chain),
`InvNoGap` (committed heights are a contiguous prefix — the invariant
that caught all three counterexamples), `InvOneVotePerView`,
`InvQCUniqueness`, `InvType`.

`OxideBftSmall.cfg` ("hunt") bounds tighter (`IndividualVotes =
FALSE`, `FreeAdvance = FALSE`, `MaxView = 4`, `MaxHeight = 3`) — an
atomic quorum-vote compression reaches deep protocol states fast; a
violation found there is replayed against the full config.

`OxideBftSmoke.cfg` ("smoke") bounds tighter still (`MaxView = 3`,
`MaxHeight = 2`, `MaxVariants = 1`) — the smallest instance that
still exercises two-chain commits, TC lock release, and
equivocation. Even it is not exhaustively checkable in PR time
(the frontier stays in the millions past depth 15); it exists as
the cheapest *exhaustive* target for a local definitive answer.

## Running

Requires Java and `tla2tools.jar` (TLA+ tools release — CI pins
v1.7.4 by sha256):

```sh
java -XX:+UseParallelGC -Xmx6g \
  -cp /path/to/tla2tools.jar tlc2.TLC \
  -config OxideBft.cfg OxideBft.tla

# hunt config (reaches deep states faster):
java -XX:+UseParallelGC -Xmx6g \
  -cp /path/to/tla2tools.jar tlc2.TLC \
  -config OxideBftSmall.cfg OxideBft.tla
```

## CI coverage

`ci.yml` runs a **seeded random simulation** on every PR:
`-simulate num=20000 -depth 40 -seed 424242` over the hunt config —
20k random behaviors × 40 steps, ~16M states checked against all
six invariants in ~1 min on a laptop (~2-3 min on the runner).
Exhaustive checking is not PR-viable: even the smoke bound's state
space stays open past depth 15 with tens of millions of states.

`nightly.yml` runs the deeper pass: 250k behaviors × 60 steps over
the **full** config (`seed 777001`), covering the per-validator
vote granularity and free view movement the hunt config compresses.
A green run means no violation in ~200M sampled states — that is
probabilistic coverage, reported as such; it is not a proof of
exhaustion.

TLC checkpoint artifacts (`states/`, `*_TTrace_*`) are gitignored.
