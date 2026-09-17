# Running an archive node (and pruning everywhere else)

How Oxide's retention model fits together, and the operator recipe
for keeping full history without making every node pay for it.

## The two-tier answer

Most nodes should **prune**: block data is unbounded (~1 TiB/day at
target load) and only a tiny slice of it is ever queried again.
But *someone* should keep everything — for explorers, auditors,
dispute forensics, and as the source state-sync peers can't
replace once segments are gone. That someone is an **archive
node**: same software, different retention policy.

The split is config, not code:

```toml
# default (pruning) node
[storage]
journal_retain_segments = 1000   # ~256 GiB of journal at 256 MiB segments
history_retention       = 4096   # heights of state_root/finalized kept in RAM
archive                 = false

# archive node
[storage]
archive = true                   # keep everything; add disk instead of pruning
```

Or via environment: `OXIDE_ARCHIVE=1`, `OXIDE_JOURNAL_RETAIN_SEGMENTS=2000`,
`OXIDE_HISTORY_RETENTION=65536`.

## What gets pruned, and how it's safe

| Layer | Mechanism | Knob |
|---|---|---|
| Journal segments | `JournalWriter::prune_below` (count watermark) and `prune_below_height` (height watermark via the `heights.idx` sidecar — every rotated segment records its max block height) | `journal_retain_segments` |
| Executor memory | `finalized`/`state_roots` BTreeMaps evict the oldest height past the bound | `history_retention` |
| EVM history/undo | Per-height sealed-block + undo namespaces with a retention floor (`with_storage_and_window`) | module-level window |

Safety contract — the same everywhere:

1. **The active segment is never pruned.** Only sealed,
   fsync'd history is deletable.
2. **Unknown contents are never deleted by height.** A segment
   with no `heights.idx` entry (the one active at a crash, or one
   written by untagged appends) is skipped — count-based pruning
   remains its bound.
3. **Pruning is a one-way door.** Deleted records are gone from
   this node forever. Never prune below the height of your newest
   durable checkpoint/snapshot, or the node can no longer replay
   to its own state. Rule of thumb: prune below
   `min(last_snapshot_height, lowest_height_you_serve)`.

## The archive recipe

1. **Run the archive node** with `archive = true` and
   `journal_retain_segments`/`history_retention` maxed. Point
   `storage_path` at the big volume.
2. **Cold-tier the sealed segments** — rotated `segment-*.log`
   files are immutable; rsync/object-store them on a schedule
   (e.g. hourly). The `heights.idx` sidecar travels with them so
   the archive stays height-addressable.
3. **Serve deep queries from the archive node** — explorers and
   `eth_getLogs`-style scans hit it; validators stay pruned.
4. **New nodes bootstrap by state-sync**, not archive replay:
   `oxide-fullnode --state-sync <peer> --trusted-height H
   --trusted-root 0x…` gets a verified snapshot; the archive is
   for history *queries*, not for rebuilding state (snapshots do
   that faster and trust-anchored).
5. **Restore an archive** by replaying the segment files back into
   the journal dir plus the matching `heights.idx`, or by
   state-syncing to a recent height and re-walking forward.

## Sizing intuition

- Default pruning node: ~256 GiB journal + bounded RAM — a
  commodity node.
- Archive node at target load: budget ~1 TiB/day of journal;
  cold-tier moves it off the fast disk on a lag, so the hot volume
  only needs days-to-weeks of runway.
