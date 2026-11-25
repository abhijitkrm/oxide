# Compact proposals (spec, draft 25 Nov 2026)

Status: the pure core is implemented and tested (`crates/types/src/compact.rs`: `CompactProposal`, its codec, `reconstruct`). NOT wired into the node yet: no
message tag, no mempool lookup, no fetch path. Phase 3 of the throughput plan; `docs/devlog.md` 25 Nov for the measurements this rests on.

## 1. Problem

A transaction reaches every follower twice: as gossip (`MSG_TX`) when it enters the network, and again inside the leader's `MSG_PROPOSAL`. Block data is therefore the
network's bulk traffic. At the throughput targets that is the binding link: 10M orders/s in bundles is ~27 B/order (delegated ~47 B) = 270-470 MB/s of proposal bytes per
leader egress link, and 1M EVM transfers/s at ~110 B signed = ~110 MB/s. The leader's egress is also serialized through one link per view.

## 2. Design

A compact proposal carries `height`, the transaction **hashes** in block order and the attestation. The signed `BlockHeader` is unchanged.

```
MSG_COMPACT_PROPOSAL (new tag)  [header][compact body: height | varint count | count x 32-byte tx hash | attestation]
MSG_TX_REQ           (new tag)  [block_hash][varint count][count x u32 position]      follower -> leader (or any peer that sent it)
MSG_TX_RESP          (new tag)  [block_hash][varint count][count x (u32 position, tx bytes)]
```

Follower flow on `MSG_COMPACT_PROPOSAL`:
1. Verify the proposer signature as today (header only, in the verify pool). Dedupe `(view, proposer)` as today.
2. `CompactProposal::reconstruct` with a mempool lookup by tx hash. All found: continue as for a full proposal with the rebuilt `Proposal`.
3. Some missing: send `MSG_TX_REQ` for those positions; on `MSG_TX_RESP` fill them and re-run the same check. If the body is still incomplete after one round trip, request the full
   body through the existing certified-block fetch (`MSG_BLOCK_REQ`), exactly as a follower that missed a proposal does today.
4. Integrity: the rebuilt `Proposal` is encoded canonically and BLAKE3-hashed (`Domain::BodyHash`); it must equal the header's signed `body_hash`. A hash that resolves to the wrong bytes
   (poisoned mempool entry, collision, wrong order) changes that hash and is rejected exactly like a bad full body: `a_wrong_transaction_changes_the_body_hash` pins this. Reconstruction adds
   no trust assumption; the leader cannot make followers accept a body other than the one it signed.

The leader chooses per proposal: compact when the body exceeds a threshold (small blocks gain nothing), full otherwise. Both forms are accepted by every follower, so the change is deployable
as a protocol feature flag with a mixed-version window.

### Interaction with the existing paths
- **Dispersed bodies** (`types::shard`, erasure-coded `body_commitment`): unchanged. Compact applies to the direct-proposal path that uses `body_hash`.
- **Execution preverify cache**: the transactions a follower looks up were already admitted and signature-recovered at gossip time, so a compact proposal also makes the follower's
  `preverify` a guaranteed cache hit (the X-2 path) instead of recovering the senders a second time.
- **Mempool**: needs `get_by_hash(&Hash) -> Option<TxBytes>`; today there is only `contains`. Entries proposed-but-uncommitted stay in the pool until commit, so a tx in an earlier in-flight
  block is still found. Eviction pressure can drop a gossiped tx before the block arrives: that is the fetch path, not an error.

## 3. Size

`compact_is_much_smaller_than_full_for_realistic_payloads` (1,000-tx proposals): EVM transfer (110 B) at least 3x smaller, a 64-order bundle (1.8 KB) at least 40x, a 64-order delegated bundle
(3.1 KB) at least 70x. A 10M orders/s block at 20 blocks/s holds ~7,800 bundles of 64: ~14 MB as a full proposal, ~250 KB as a compact one.
Short salted ids (6-8 bytes, BIP-152 style) would cut the list another 4x but need collision handling and a per-block salt; deferred until the 32-byte list is measured as the bottleneck.

## 4. Failure and abuse analysis
- **Withholding leader** (sends a compact proposal for txs nobody has): followers cannot rebuild, fall back to the full-body fetch, which the leader must serve or the view times out: the same
  liveness exposure as a leader that withholds a full proposal.
- **Fetch amplification**: `MSG_TX_REQ` is answered only for blocks the responder holds, capped at the block's own transaction count, charged to the per-peer admission budget (consensus-class
  traffic is exempt from the gossip bucket; the request is small, the reply is bounded by the block).
- **Decode DoS**: the count is bounded by the bytes present (`a_forged_count_is_bounded_by_the_bytes_present`); `CompactProposal` is in the `types-decode` fuzz target (9M inputs, no crash).
- **Cold mempool** (a validator that just joined, or one whose gossip lagged): degrades to today's behavior, one full-body fetch per block, never worse.

## 5. Acceptance gates for the wiring
1. Equivalence: a compact and a full proposal for the same block produce the same `Proposal`, `body_hash` check outcome, votes and state root (differential test over random blocks, including blocks with missing txs).
2. Fault: a follower missing k of n txs recovers through `MSG_TX_REQ` with one round trip; missing more than a threshold falls back to the full body; a poisoned pool entry is rejected.
3. Throughput: on a multi-machine or multi-validator run at a rate where proposal bytes bind (the 1 MiB/s limit no longer hides it), committed tx/s and leader egress bytes with and without compact.
   On loopback with 4 validators bandwidth is not binding, so a win there would show up only as CPU saved by skipping a second recovery; do not expect a throughput headline from the single-box matrix.
4. Mixed version: a committee with compact-enabled and compact-disabled validators keeps committing.
