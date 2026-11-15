# Lanes: sharded, swappable execution lanes

Status: v2. Implemented in `crates/lanes` (prototype seams, trading shard and
EVM lane split) and wired into the matcher service (`crates/matcher`: pluggable
authentication, control frames, settlement commitments) and the exchange module
(committed batch settle, bonded operator and disputes). Code and this spec
change together. What is measured is on one laptop only (§10); the many-core,
multi-machine and consensus-in-the-path results are not yet measured.

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

Session and certificate control frames (built):

- **Binary TCP**: header flag `0xFD` (control) with a kind byte: session open
  (188 B body), session close (100 B), certified batch (128 B certificate plus a
  standard batch request). Session responses are 5 bytes
  `[status][session_id]`. Implemented on the multi-market, mutex and ring
  servers (`matcher::control`).
- **JSON-RPC**: `oxide_openSession` / `oxide_closeSession` with
  `{"frame":"<hex>"}`.
- **Expiry**: the expiry is part of the owner's signed open; a session is
  refused at or after it. A default maximum lifetime of 24 h
  (`--max-session-ttl-ms`) also refuses "never expires" opens.
- **Close** needs the *owner's* signature (ed25519 or EVM), not the session
  key: the point is to revoke a session whose key leaked.
- **Gateway faults**: if a trusted gateway signed a batch and an audited order
  fails its own credential check, that is a provable fault (the certificate
  verifies and the digest matches). Faults are counted per gateway, a hook is
  called, and after `--gateway-suspend-after` (default 3) the gateway is
  suspended until an operator reinstates it. Bad certificates from unknown or
  mismatching parties are rejected but not attributed.

Not carried on the WebSocket and FIX transports. Sessions live in memory (a
restart drops them and clients re-open).

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

### 7.2 Bonded operator and disputes (built, opt-in)

The attestation is made enforceable by a bond and a dispute path
(`modules/exchange/src/dispute.rs`; off unless `set_dispute_config` is called,
in which case tag 16 behaves exactly as above):

1. The operator escrows a bond (`TAG_BOND_DEPOSIT` 17, debited from its
   ledger balance). A committed settle needs bond >= `min_bond` and an
   unsuspended operator, and must use a fresh `batch_seq`.
2. Each accepted batch leaves a record (`fills_root`, `legs_root`, counts,
   height) in the module's committed key-value store, so it is in the state
   root and in snapshots (no layout change: the keys are `net/...`, disjoint
   from the `m/{id}` market keys the snapshot decoder checks).
3. For `window_blocks` anyone may submit the raw fills (`TAG_DISPUTE` 18). The
   chain checks they hash to the attested `fills_root`, re-derives the legs
   with the same `aggregate_raw_fills` the settler uses, and compares with the
   legs root it recorded when it applied the batch. A mismatch is proof the
   operator attested fills that do not match what it settled: the whole bond
   is paid to the challenger and the operator is suspended (plain and
   committed settles are both refused) until governance reinstates it
   (`exchange.operator.reinstate`).
4. A dispute that proves nothing (wrong fills, or consistent legs) changes no
   state and costs the challenger the transaction fee. Records past the
   window are pruned at `end_block`.

The raw-fill encoding, stream label and aggregation are defined once in
`exchange::dispute`; the matcher imports them, so the root the settler attests
is the root a dispute recomputes (tested end to end: an honest settler's batch
survives a dispute, a settler that submits different legs than it attested is
slashed).

What this is not: **netted-delta settlement**. Netting the money movement per
account would not remove per-leg work, because every leg still updates the
registered orders' remaining quantity and escrow; the chain would only stop
doing that work if order state moved off chain, which needs a different trust
model and is not built. Also not built: bond withdrawal (the bond stays
locked), a CLI to submit the bond deposit, and a dispute fee/reward market
beyond paying the challenger the bond. The chain still validates and applies
every leg.

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

### 10.1 Real TCP through the matcher service (laptop, same machine as the load generator)

Source: `cargo test -p matcher --release --test e2e_auth_tps -- --ignored
--nocapture`. Multi-market matcher, 4 connections, batch endpoint of 500,
orders pre-authenticated, real matching (50% of orders fill) and the replay
gate; 200,000 orders; one market (so one worker thread).

| `--auth` | Orders/s |
|---|---|
| `ed25519` (one strict verify per order) | 72k |
| `ed25519_batch` (the default) | 184k |
| `evm` (4 recovery threads) | 159k |
| `session_mac` | 2.19M |
| `certified` (audit 1/64) | 2.33M |
| `multi` (schemes enabled, ed25519 traffic) | 175k |

**Correction (2026-11-14):** an earlier version of this table reported session
MAC 1.81M and certified 1.85M. Those runs built the balance cache with
`AtomicBalanceCache::new(8)`, a capacity of 8 accounts, so every account
overflowed to the global-mutex sparse map. The signature-bound rows were
unaffected (they are verification-bound); the cheap-authentication rows were
understated. Operators: `--accounts-cap` must be at least the number of
distinct accounts, or throughput collapses (runbook section 13).

Admission alone on one thread (`cargo bench -p matcher --bench auth`):
ed25519 20k, batch 56k, EVM 33k (124k on 4 threads), session MAC 4.8M,
certified 1.9M orders/s.

Reading: the engine does tens of millions of ops/s per core, so the service's
limit is authentication. With a signature per order it is 72k-184k orders/s;
with a session MAC or a gateway certificate the same one-market server reaches
~2.2M on a laptop that is also running the load generator. The older
single-market mutex-mode service tests (per-order ed25519, synchronous or
pipelined clients) measure 10-18k orders/s.

EVM execution (laptop, one core): 34 us per transaction, of which
secp256k1 recovery is 29.6 us (87%). The 8-core parallel batch does 113k tx/s.
A 1M tx/s EVM target is therefore mostly a question of where signature
recovery happens (ingress verification, certified batches, sharded lanes),
not of the execution engine.

### 10.1a Real-service shard scaling (in process, laptop, session MAC)

Source: `cargo bench -p matcher --bench shards`. The production
`MultiMarketMatcher` (one worker per market), one submitter thread per market
calling `submit_batch`, orders pre-authenticated. Includes the real
admission path, replay gate, balance reservation, risk, per-market worker and
settlement buffer; excludes TCP.

| Markets | Orders/s (journal off) | Per market |
|---|---|---|
| 1 | 1.83M | 1.83M |
| 2 | 3.61M | 1.80M |
| 4 | 6.3-6.9M | 1.6-1.7M |
| 8 | 7.5-7.6M | 0.95M |

Near-linear to 4 markets (8 threads on the 4 performance cores); at 8 markets
the laptop is oversubscribed (16 threads on 4 fast + 4 slow cores), so the
flattening is the machine, not the design. The rig's curve is the real one.

- **Replay gate sharding.** The multi-market replay gate was one mutex taken
  per order. It is now 64 shards keyed by owner (`ShardedNonces`), with
  identical per-owner semantics (differential-tested against a single tracker
  for 1/2/7/64 shards; concurrent and durable tests) and the same on-disk
  format. A/B, three runs each: 8 markets 7.5M orders/s with 64 shards against
  4.6M with one (+64%); 4 markets 6.8M against 6.0M (+12%). My first
  hypothesis (the gate was *the* limit) was wrong; the limit that first showed
  up was the balance-cache capacity artifact above, and the gate became the
  next one once that was fixed.
- **Journal.** `queued` ack is nearly free (4 markets: 5.2M with it, 5.25M
  without). `durable` ack does not scale with submitters on this laptop: about
  95k orders/s per market however many submitters (1, 4 or 16), because the
  worker blocks on one fsync per batch (about 5 ms here) instead of
  group-committing across queued batches. On local NVMe (fsync ~0.1 ms) the
  bound is far higher; on network disks it will bind. Pipelining the ack
  across queued batches is a known improvement, not built.

### 10.1b Separate processes (smoke only on the laptop)

`scripts/rig-bench.sh procs` runs `oxide-matcher` (built with
`--features dev-identities`, started with `--fund-loadgen-keys`) and
`oxide-loadgen --auth <scheme>` as separate processes pinned to disjoint cores,
restarting the matcher per run (the replay gate is per process lifetime).
`oxide-loadgen` now builds, signs and frames every order before its clock
starts, supports `--auth ed25519|evm|session_mac|certified`, and counts
rejections (a run with rejections is flagged). Unpinned laptop smoke, 20k
orders: 1 market ed25519 99k, evm 64k, session MAC 2.1M, certified 1.5M;
2 markets 186k, 122k, 3.5M, 2.4M orders/s. Too small and unpinned to quote
as results; the rig run is the measurement.

### 10.2 Not measured yet (needs the rig)

Many-core scaling of the lanes and of signature recovery (1-64 threads), the
x86 prefetch / exact-division A/B, journal fsync on NVMe, a multi-machine
matcher, and multi-validator consensus with a lane in the path.

On a single dedicated Linux box (about 3 hours): `scripts/rig/setup-linux.sh`
(`TUNE=1` for machine settings), then `scripts/rig-bench.sh single-box`
(env, budget, lanes, e2e at 4-128 cores, scaling, journal, profile, summary;
`QUICK=1` first as a 5-minute smoke test). It writes `summary.md` with the
scaling tables and a cores-needed extrapolation. `scripts/rig/remote.sh
<ssh-target> sync|setup|start|status|fetch|stop` drives a rig over ssh using
your existing ssh config; it stores no credentials. A single box cannot
measure the network, multi-validator consensus, or geo-distribution.
