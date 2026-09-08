# Storage Specification (v0)

Status: Phase 0 scope — the primitives (journal, MMR, backend seam) with
their acceptance gates. The full authenticated-state stack (QMDB-style
op linking, grafting, snapshots, cold-store adapters) is staged in §5 and
lands in later phases. This document precedes implementation
(`crates/storage`); if code and spec disagree, one of them is wrong — fix
it in the same PR.

## 1. Layering (from plan.md §8)

| Layer | Component | Phase |
|---|---|---|
| L1 | `journal` — append-only, CRC'd segment files, group commit | **0 (this doc)** |
| L1 | `mmr` — Merkle Mountain Range over leaf hashes | **0 (this doc)** |
| L2 | `backend` — `StorageBackend` trait + `Volatile` in-memory impl | **0 (this doc)** |
| L2 | authenticated journal (op linking, prev-location chain) | 1 |
| L3 | write-behind → `ColdStore` adapters (MDBX / RocksDB / redb) | 2 |
| L3 | snapshots + state sync, `Any`/`Current` proof variants | 2 |

## 2. Journal (`journal.rs`) — std-only core

**Why append-only:** Oxide commits one block batch per ~50–100ms; an
append-only log with group commit keeps `fdatasync` off the consensus
critical path (one sync per batch, not per op) and makes crash recovery
a replay — the same property that makes every validator's state
reconstructible from genesis (the determinism invariant).

**File format:**

```
segment file:  segment-<seq>.log           (seq: u32, 0-based, ordered)
segment header: magic "OXDJRN01" (8 bytes)         — versioned, greppable
record:        len      u32  LE                  — payload byte count
               crc32    u32  LE                  — IEEE CRC-32 of payload
               payload  [len] bytes
```

**Rules:**
1. A record is *complete* iff `len` ≤ `MAX_RECORD_BYTES` (16 MiB) and its
   payload CRC-32 matches. On replay, the first incomplete/mismatching
   record ends the segment: everything after it is ignored and reported
   as `truncated_at` (torn-write recovery — a crash mid-`flush` leaves a
   partial tail, never a silent corruption).
2. Writers buffer records in memory (`append`) and hand them to the OS on
   `flush()`; `sync()` calls `fdatasync` on the active segment. Durability
   contract: a record is durable iff its segment has been flushed *and*
   synced; callers (the block committer) sync once per block batch.
3. Segment rotation at `max_segment_bytes` (default 256 MiB): flush,
   finish, open `segment-<seq+1>`. Old segments are immutable forever —
   archive/cold-tier moves them later without format conversion.
4. `Location { segment: u32, offset: u64, len: u32 }` identifies a record
   for its lifetime; offsets are absolute within the segment (header
   excluded from addressing; offset 0 = first record).
5. CRC-32 (IEEE, reflected, poly `0xEDB88320`) is implemented in-crate
   (table-based) to keep the journal core std-only — the policy from
   `.devin/skills/production-rust` §5.

**Acceptance gate (Phase 0):** ≥ 1,000,000 buffered `append`s/second
single-thread on the bench rig (p50 per-op ≤ 1000 ns for ~100-byte
payloads). Flush/fsync costs are reported separately — they are per-batch
amortized in production, never per-op.

## 3. MMR (`mmr.rs`)

**Why an MMR:** the authenticated journal commits to *all* ops so far
with one root, appends are O(1) amortized, and inclusion proofs for any
leaf are O(log n) — the shape a block-committed log needs (QMDB pattern,
plan.md §8 L1).

**Construction (canonical, Grin-lineage index math):**
- Nodes live in one `Vec<Hash>` in append order: pushing a leaf appends
  its hash, then while the two rightmost mountains have equal height,
  append `H_node(left ‖ right)`.
- `leaf_count` ⇒ total nodes `= 2n − popcount(n)`; peaks derived from
  the mountain structure of `n`.

**Hashing and domain separation** (BLAKE3-256; the hash choice is
consensus-critical — changing it is a chain migration, not config):

| Input | Preimage |
|---|---|
| leaf | caller-supplied pre-hashed 32 bytes |
| internal node | `0x01 ‖ left(32) ‖ right(32)` |
| root finalize | `0x02 ‖ bagged_peaks(32) ‖ leaf_count(8, LE)` |

Peak bagging folds right-to-left: `acc = H_node(peak_i ‖ acc)` starting
from the rightmost peak. The `leaf_count` binding makes the root
unambiguous about the number of committed leaves (no length-extension
equivalence between different-sized forests).

**Invariants (property-tested for all n ∈ [1, 512] and sampled large n):**
1. Every leaf index in `[0, n)` produces a proof that verifies against
   the root for that exact `n`.
2. Verification fails for: wrong leaf hash, tampered proof nodes,
   wrong index, wrong `leaf_count`.
3. `push` is pure aside from the node vector; roots are stable
   (identical op sequence ⇒ identical root, forever).

**Acceptance gate (Phase 0 — renegotiated 2026-09-08, see devlog session
3, items q/r):** root maintenance is *incremental*, and every `push`
amortizes to **exactly ≤ 1 internal-node hash** (n leaves ⇒ n−1 internal
nodes — information-theoretic for a Merkle structure). The gate is
therefore decomposed:

| Sub-gate | Target | Status (dev Mac, 2026-09-08) |
|---|---|---|
| structure-only overhead (`push_amortized − hash_node_65b`) | < 20 ns/op | **~16 ns ✓** (176 − 160) |
| `hash_node_65b` (65-B preimage = 2 BLAKE3 blocks) | report | ~160 ns — the floor, hardware-bound |
| full 1M-leaf build wall-clock | report; re-baseline on the 16-core rig | 248 ms dev Mac (hash-throughput-bound: ~2M hashes incl. leaves) |

The original single figure ("MMR root over 1M ops < 20 ms") was written
before the hash-floor decomposition existed; as a *single-threaded,
hashing-included* number it is unachievable with BLAKE3 on any of our
target hardware (~2M × 65-B hashes ≈ ≥ 60 ms even at AVX-512 rates).
It survives as the structure-only sub-gate above. Closing the total
build time is a parallelization problem (independent mountain merges
per level; rayon), staged for Phase 1 when the real batch-commit path
exists — not a structure redesign.

## 4. Backend seam (`backend.rs`, `volatile.rs`)

`StorageBackend` is the L2/L3 port from plan.md §2.3. v0 is deliberately
minimal — it grows exactly when later-phase features need it (snapshots,
range streaming, proofs), never speculatively:

```rust
pub trait StorageBackend {
    fn capabilities(&self) -> Caps;                       // Authenticated?
    fn get(&self, key: &Hash) -> Option<&[u8]>;           // RAM read
    fn range(&self, prefix: &[u8]) -> Vec<(Hash, Vec<u8>)>; // cold path
    fn apply_batch(&mut self, ops: &[Op]);                // atomic per block
}
```

`range` takes a byte-slice prefix of any length ≤ 32 (module namespaces
are short); a longer prefix matches nothing by definition — keys are
exactly 32 bytes.

- `Op` is `Set { key, value } | Delete { key }` (32-byte keys per
  plan.md §8 sizing). Codec impls for `Op` arrive with the executor
  wiring (Phase 1) — not before, per YAGNI.
- `Volatile` (BTreeMap-backed) is the reference in-memory backend:
  correct-first, used by sims/tests and as the conformance oracle.
  `Authenticated` backends (journal-backed) arrive in Phase 1 and must
  pass the storage-conformance suite (plan.md §2.5).
- Validators must run `Caps::authenticated` backends (enforced at node
  wiring, Phase 1+); `Volatile` is legal for followers/sims only.

## 5. Explicitly out of scope (v0)

Erasure-coded archive, snapshot export/import, MDBX/RocksDB adapters,
`Any`/`Current` proof variants, op-linking (lexicographic prev-location
chain), grafting, write-behind flusher. Each lands with its own spec
section + conformance tests in the phase that needs it.
