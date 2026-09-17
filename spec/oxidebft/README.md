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

## Running

Requires Java and `tla2tools.jar` (TLA+ tools release):

```sh
java -XX:+UseParallelGC -Xmx6g \
  -cp /path/to/tla2tools.jar tlc2.TLC \
  -config OxideBft.cfg OxideBft.tla

# hunt config (reaches deep states faster):
java -XX:+UseParallelGC -Xmx6g \
  -cp /path/to/tla2tools.jar tlc2.TLC \
  -config OxideBftSmall.cfg OxideBft.tla
```

TLC checkpoint artifacts (`states/`, `*_TTrace_*`) are gitignored.
