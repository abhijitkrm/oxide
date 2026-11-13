# Lanes: sharded, swappable execution lanes

Status: draft v1. Implemented in `crates/lanes` (prototype: trading shard
path and EVM lane split). Code and this spec change together.

## 1. Targets and why one global lane cannot reach them

| Lane | Target | Design headroom |
|---|---|---|
| Trading (orders, fills) | 10M orders/s and fills/s | 100M orders/s |
| EVM | 1M tx/s | none promised |

Measured per-core costs (`crypto` bench `budget`, Apple M1, 1 thread):

| Stage | Cost per item | Cores for 1M/s | Cores for 10M/s |
|---|---|---|---|
| secp256k1 recover (EVM sender) | 31 µs | 31 | 309 |
| ed25519 verify, strict | 46 µs | 46 | 457 |
| ed25519 verify, batch of 256 | 16 µs | 16 | 156 |
| BLAKE3 leaf over a 120 B record | 0.15 µs | 0.2 | 1.5 |
| session MAC over a 60 B order | 0.11 µs | 0.1 | 1.1 |

If every validator re-verifies every signature the chain scales with the
slowest validator's core count. The engine itself (14.6M ops/s per core with
the commitment fold on) is not the limit. Three things change:

1. **Authenticate once, near the edge.** A gateway verifies, then vouches with
   a certificate that validators check cheaply (§4).
2. **Shard the work.** Trading shards by market (already single-writer);
   EVM lanes shard by account range (§5, §6).
3. **Commit per batch, not per item.** Consensus orders batch digests; fills
   are committed by one Merkle root per batch, balances are netted per block
   (§7).

## 2. Seams

Every stage is a trait with a default (today's behaviour) and alternatives.
Swapping one must not change the others. Traits live in `crates/lanes`.

| Seam | Trait | Default | Alternatives |
|---|---|---|---|
| Authentication | `Verifier` | `PerItem` (verify each signature) | `Batched` (batch ed25519), `Certified` (check a gateway certificate), `SessionMac` (keyed hash under a session key) |
| Fill commitment | `FillCommit` | `PerFill` (one leaf per fill) | `BatchRoot` (one Merkle root per batch) |
| Routing | `Router` | `ByMarket` (market id to shard) | `ByAccountRange` (EVM) |
| Lane | `Lane` | in-process lane | remote lane (same trait, wire-encoded) |
| Cross-lane | `Outbox` / `Inbox` | in-memory queue | network transport |

Rules for any implementation:

- **Determinism.** Same inputs, same outputs, byte for byte, on every
  validator. No clocks, no randomness, no hash-map iteration order.
- **Conservation.** Total balance across all lanes plus in-flight messages is
  constant except for explicit mint/burn.
- **Fail closed.** An item that fails authentication is dropped before any
  state change; a batch is all-or-nothing at the certificate level.
- **Swap safety.** Two implementations of the same seam must produce the same
  state root when given the same logical input (differential test).

## 3. Lane model

A lane owns a disjoint slice of state and processes an ordered input stream
single-writer. Its output is a `LaneBatch`:

```
LaneBatch { lane: u16, seq: u64, items: u32, input_digest: [u8;32],
            fill_root: [u8;32], state_root: [u8;32], outbox: Vec<Msg> }
```

`seq` is contiguous per lane. The global header commits the ordered list of
`(lane, seq, input_digest, fill_root, state_root)` and the outbox digests. The
chain orders these commitments; the data stays with the lane's replica group
and is fetched on demand (data availability is a replica-group duty).

## 4. Authentication seam

`Verifier::verify_batch(items) -> Vec<bool>` (per-item outcome). Properties:

- `PerItem`: exact, slowest. Baseline and the fallback on any batch failure.
- `Batched`: batch equation; on failure falls back to `PerItem` to find the
  bad item. Not for consensus-critical byte-canonical checks (see
  `crypto::ed25519::verify_batch`).
- `Certified`: items arrive with a `BatchCert { gateway, batch_digest,
  sig }`; validators check one signature per batch plus the digest over the
  items, and a configurable **audit fraction** of items is fully re-verified
  (default 1 in 64, chosen by deterministic hash of the digest so every
  validator audits the same items). A failed audit slashes the gateway
  (out of scope here; the hook is `AuditFailed { gateway, item }`).
- `SessionMac`: the client opens a session with one signature; each order
  carries a keyed-hash tag under the session key. Cost is two orders of
  magnitude below a signature. Trade-off: the gateway can forge orders for
  its own sessions, so session scope (market set, notional cap, expiry) is
  signed by the client at open and enforced by the lane.

### 4.1 Authentication in the matcher service (built)

The matcher service's admission path asks a `matcher::auth::Authenticator`
for its `VerifiedOrder` / `VerifiedAction` proof tokens, so the scheme is a
runtime choice and nothing downstream changes. Selected with
`--auth <kind>` (and `--auth-schemes`, `--evm-threads`, `--gateway-keys`,
`--audit-every`) or `ServerConfig.auth`:

| `--auth` | Credential | Notes |
|---|---|---|
| `ed25519_batch` (default) | ed25519 signature | Historical behaviour, bit-identical (tested). |
| `ed25519` | ed25519 signature | One strict verify per order. |
| `evm` | secp256k1 recoverable signature | Recovered address must equal `owner`: the order trades for the on-chain EOA directly. Parallel with `--evm-threads`. |
| `session_mac` | keyed-hash tag under a session key | Sessions are opened by a request signed by the owner (ed25519 or EVM); scope = market set; revocable; a MAC cannot open sessions. |
| `certified` | gateway signs the batch | Deterministic audit sample, fail closed; uncertified traffic falls to ed25519. |
| `multi` | any of the above per order | `--auth-schemes ed25519,evm,mac,cert` picks the set; others are rejected. |

There is no "accept everything" kind. The wire format is unchanged: each
scheme uses a canonical shape of the existing 32-byte `pubkey` and 64-byte
`signature` fields (EVM: recovery id + `r ‖ s`; MAC: session id + 32-byte
tag), which is also how `multi` routes without a version bump. All schemes
sign or MAC the same signing message and the matcher's existing nonce gate
is the replay protection for all of them.

Measured on the M1 (`matcher:auth`, orders/s on one thread): ed25519
per-item 20k, ed25519 batch 56k, EVM recover 33k (124k on 4 threads), session
MAC 4.8M, gateway certificate with 1-in-64 audit 1.9M.

Not built: a transport frame to open or close a session over TCP/WebSocket/
JSON-RPC (the API and the signed open message exist: `open_session`,
`SessionOpen`), a transport frame carrying a batch certificate, session
expiry, and gateway slashing. Sessions live in memory (a restart drops them
and clients re-open).

## 5. Trading lane

- Shard = market. A `Router` maps market id to shard id; shards are fixed by
  config and changed only at epoch boundaries.
- A shard runs `trading::MatchingEngine::apply_batch` over a verified batch,
  collects fills through `FillSink`, and emits the batch's `fill_root`.
- Per-shard throughput is the engine rate (14.6M ops/s per core with the
  fold on). 100M/s means 64 to 128 shards, each on its own cores, journal
  and NVMe.
- Fills are netted per account per block into balance deltas; settlement
  applies deltas, not fills.

## 6. EVM lane

- Accounts partition by address range into `N` lanes. A transaction runs in
  the lane that owns its sender.
- A transfer or call whose target lives in another lane produces an outbox
  message `Credit { from_lane, idx, to, amount }`. The sender is debited
  immediately in the source lane; the target lane applies the credit when
  it processes the message. `idx` is contiguous per `(source lane,
  destination lane)` channel (a per-source counter would look like gaps to
  a destination that only sees its own channel; found by the prototype's
  property test). A destination applies each channel in `idx` order, at
  most once: a smaller `idx` is a duplicate and ignored, a larger one is a
  gap and stops delivery.
- Conservation invariant: `sum(lane balances) + sum(unapplied credits)` is
  constant. A property test asserts it after every step.
- Out of scope for this prototype: cross-lane contract calls that need a
  synchronous return. The prototype supports value transfers only; calls
  needing atomic multi-lane state are executed in a designated
  "coordinator lane" (future work, spec'd separately).

## 7. Commitments

- `PerFill`: leaf per fill, XOR-folded (today's behaviour). Order-insensitive.
- `Stream`: one streaming BLAKE3 over the encoded fills in match order,
  buffered and hashed in 16 KiB pieces so BLAKE3's multi-chunk SIMD path is
  used (feeding it 73 B at a time was measurably slower: see §10). Order
  sensitive; no per-fill proofs, so a fill is verified by replaying the
  journal.
- `Merkle`: binary tree over per-fill leaves in match order (odd node
  promoted, count bound into the root). Order sensitive; gives per-fill
  inclusion proofs at roughly twice `Stream`'s cost.

They commit to the same fill sequence but are different functions, so a lane
picks one in config and never mixes them. The lane's header carries the one
32-byte root; fills themselves are reproducible from the journal.

### 7.1 Commitments in the settlement path (built, opt-in)

With `--commit-batches` (`ServerConfig.commit_batches`) the settler submits a
**committed batch settle** (exchange tag 16) instead of tag 3. The legs
settle exactly as before (differential-tested: identical balances, fee vault
and leg events), and the chain emits one `batch_commit` event:

`batch_seq ‖ fills_root ‖ raw_fill_count ‖ legs_root ‖ leg_count`

- `legs_root` is computed by the chain over the legs it applied (stream
  commitment, label `oxide-exchange-legs-v1`).
- `fills_root` is the settlement operator's attestation over the raw sealed
  fills the legs were aggregated from (label `oxide-matcher-fills-v1`). The
  chain cannot recompute it, since it never sees the raw fills, but anyone with
  the matcher's journal can replay it and compare. The matcher's order path
  is untouched: the root is computed once per batch on the settler thread
  (~55 ns per fill).
- `batch_seq` is the settler's envelope nonce.

Honest limits: this adds an auditable, chain-recorded commitment; it does
**not** yet remove per-leg work on chain. The module still validates and
applies every leg. Netted-delta settlement (chain applies per-account net
deltas and checks them against `fills_root`, with fraud proofs for the
off-chain stream) is the step that would, and it needs a dispute design that
is not built. Tag 3 stays valid; the default is off because the chain must
understand tag 16.

## 8. Budget formula

For target `T` items/s and measured single-core cost `c` seconds/item,
`cores = T * c / efficiency`, efficiency from the thread-scaling rows of the
budget bench (0.9 is a fair planning number up to the physical core count).
`scripts/rig-bench.sh budget` prints this table per stage.

## 9. Acceptance

| Gate | Pass when |
|---|---|
| Swap safety | `PerFill` and `BatchRoot` give the same fills; `PerItem`, `Batched`, `Certified` accept and reject the same items (differential tests) |
| Conservation | EVM lane property test: no step changes the conserved total |
| Trading scaling | orders/s grows near-linearly with shards up to physical cores on the rig |
| Budget | per-stage costs measured on the rig and the target table filled in |

Not proven by any of the above: a real multi-machine network at these rates.

## 10. Measured (Apple M1, 4 performance + 4 efficiency cores, in-process)

Source: `cargo bench -p lanes --bench lanes`, `-p crypto --bench budget`.
Workload: 60% of orders cross, so about 0.6 fills per order, a deliberately
fill-heavy mix.

Seam cost on one shard (orders/s per core; the engine alone is 8.9M):

| Authentication | none | per-fill commit | stream commit | merkle commit |
|---|---|---|---|---|
| trusted control | 8.9M | 4.8M | 6.8M | 3.4M |
| per-item ed25519 | 21k | 21k | 21k | 21k |
| batched ed25519 (2048) | 77k | 76k | 71k | 74k |
| gateway certificate, audit 1/64 | 1.08M | 0.89M | 1.01M | 0.84M |
| session MAC | 3.9M | 2.8M | 3.3M | 2.1M |

Shard scaling (orders/s, whole machine):

| Shards | trusted, no commit | session MAC + stream | batched ed25519 + merkle |
|---|---|---|---|
| 1 | 8.9M | 3.3M | 74k |
| 2 | 17.7M | 6.5M | 148k |
| 4 | 30.1M | 11.6M | 256k |
| 8 | 34.2M | 12.5M | 312k |

Scaling is near-linear to the four performance cores and flattens when the
efficiency cores join, which is the laptop, not the design; the rig's core
count decides the real curve.

EVM account-range lane (transfers/s): 218M on 1 lane, 138M on 2, 116M on 4,
104M on 8. This measures only the lane mechanism (array balances, credit
bucketing, in-order delivery), not EVM execution: one cross-lane credit costs
about 13 to 35 ns, against about 25 µs to execute a real transaction, so the
split adds well under 0.1% to the work it parallelizes. Throughput falls with
lane count because the cross-lane share rises, (N-1)/N for uniform traffic.

What this does and does not show:

- A 10M orders/s trading lane is reached on this laptop with session-MAC
  authentication and stream commitment (12.5M on 8 shards). With batched
  ed25519 per order it is not (0.3M), which is the reason for the seams.
- It does not include the network, the journal, or consensus. Those are the
  next costs, and none of them is measured at this rate.
- 100M orders/s needs about 8 to 10x this machine's trading throughput:
  consistent with a 64 to 128 shard deployment across several machines, and
  unproven.
