# Oxide — HFT / Low-Latency Engineering Audit, Pass 2

**Revision audited:** `a5898cc` (main, working tree clean), 2026-10-10.
**Predecessor:** `hft-audit.md` (26 findings F-01…F-26, all marked
resolved at `a809136`). This pass re-verifies those resolutions at HEAD,
then audits the full order / tx / view / block pipeline again with a
nanosecond-and-tail-latency lens, and adds the first measurements taken
on the x86 target machine (the prior audit's numbers were all M-series).
**Target machine:** AMD EPYC 7232P (Zen 2, 8 cores / 16 threads, SMT
sibling of CPU *i* is *i+8*, 4 CCX × 2 cores each sharing an 8 MiB L3
slice, 512 KiB L2 per core, 1 NUMA node), 62 GiB RAM, two Samsung
PM991a-class consumer NVMe (no power-loss protection) in `md` RAID-1
(ext4, **resync in progress during this audit**), Intel 10 GbE
`ixgbe` (16 combined queues, `rx-usecs=1`), kernel 7.0 `PREEMPT_DYNAMIC`,
`schedutil` governor, C-states up to C2 enabled (C2 exit latency
400 µs), THP `madvise`, no reserved huge pages, no `isolcpus`, no
`irqbalance`/`tuned`. ISA: AVX2, BMI2, SHA-NI, PCLMULQDQ, no AVX-512.
**Method:** six parallel source reviews (trading/exchange/perps,
matcher, consensus/node/mempool, executor/EVM/framework,
storage/codec/primitives/crypto, p2p/RPC/config/build), each held to
the `performance-first` rules, followed by line-by-line spot
verification of every High finding by the lead reviewer, a toolchain
install (`1.98.1`, `cc`), a full release build, and a pinned criterion
run of the hot-path benches on this box (§3). All citations are
`file:line` at `a5898cc`. No source files were modified.

---

## 1. Executive summary

**Verdict: the nanosecond cores still hold (engine, ring, codec,
crypto backends), but the system wrapped around them is not yet an HFT
system. Three classes of defect dominate every end-to-end number on
this machine, and none of them is inside the matching engine:**

1. **Synchronous durability on the critical threads.** Four
   fsync-class waits per view today (journal + WAL on vote, journal +
   WAL on proposal; redb commit in `end_block` on the exec lane; the
   matcher's nonce checkpoint on the sequencer). On this box a single
   `fdatasync` is **4 ms p50 / 13 ms p99** (§3). Every one of these
   sits on a thread that is supposed to be ns-class.
2. **Wake-up and scheduling structure.** The consensus pump still ends
   every pass in a 1 ms `recv_timeout` that only the transport can cut
   short (the `progressed` fix from commit 1c9bc93 was lost in the
   merge 7cbcbcd); the matcher sequencer parks immediately with no
   spin phase; every hop is a futex wake across unpinned, oversubscribed
   threads (~50 threads on 8 physical cores for a validator; 128
   market workers + 16 tokio workers for the matcher by default). On
   this machine a futex wake plus C2 exit is 5–400 µs.
3. **Per-item work on the serial threads that was designed to be
   batched.** Gossiped txs are recovered one at a time (~45 µs each)
   on the consensus pump; RPC recovers every sender twice; Ed25519
   batch-verify is invoked with n = 1 per order; the WAL re-writes
   every uncommitted block body on every vote; exchange settlement
   does ~24 heap allocations and 8 hashes per fill.

The prior audit's resolutions mostly hold, with four exceptions that
matter: **F-01 partially regressed** (1 ms idle quantum back), **F-26
regressed in practice** (the production resting leaf allocates 4× per
hash; the gated bench hashes a stack buffer), **F-05 is unwired**
(production emits no market data), and **F-06 is a cliff** (one cache
miss in a run re-recovers the whole run).

### Top findings, ranked by end-to-end impact on this machine

| # | Sev | Finding | Location | Cost today |
|---|---|---|---|---|
| N-1 | **High** | Pump idles ≤1 ms per pass; verify verdicts, own view advance, exec-lane completion and gossip don't wake it; `progressed` flag lost in merge | `crates/node/src/validator_net.rs:2247-2249` | 2–3 ms per view (of ~9–12) |
| N-3 | **High** | WAL entry carries the full bodies of all ≤8 uncommitted blocks on every vote/proposal append, under `O_DSYNC`; at 16 MiB blocks a 2-block tail exceeds `MAX_WAL_ENTRY_BYTES` → recovery sees a torn entry | `crates/consensus/src/engine/persist.rs:180-211`, `wal.rs:117,128` | 2–8× block bytes per vote + ms-class synced write; a correctness hole |
| S-2 | **High** | No async durability anywhere: consensus WAL, executor journal, redb commit are all synchronous on the pump / exec lane | `wal.rs:714,849`, `executor/src/durability.rs:431`, `modules/evm/src/persist.rs:988` | 3–4 × (4 ms p50 / 13 ms p99) per view here |
| N-4 | **High** | Three inline BLS pairings per view on the pump (header `high_qc` re-verify, QC self-verify at form, leader re-verify at deliver); `aggregate_verify/4` measures **1.46 ms** here | `engine/votes.rs:732,1437,1494`, `engine.rs:2363-2402` | ~4.4 ms/view |
| N-2 / X-1 | **High** | Gossiped `MSG_TX` admitted one tx at a time on the pump: serial secp256k1 (**51.8 µs measured here**) + hash + copy | `validator_net.rs:1361`, `executor/src/app_iface.rs:21-52` | ~55 µs/tx; pump saturates at ~18k tx/s |
| T-1 | **High** | `Arc::make_mut` on the live EVM `CacheDB` deep-copies the whole account cache on the first ledger write whenever any RPC/history snapshot is alive | `modules/evm/src/ledger.rs:70` | ms–s tail cliff on the exec lane |
| T-2 | **High** | Perps per-order cost is O(open orders): whole-account clone + double serialize/hash per mutation, ×4 per fill; margin recomputed twice with sorts. Already **6.16 µs measured here with ≤1 open order (doc gate < 3 µs, recorded 723 ns)** | `modules/perps/src/lib.rs:1083-1092,609-629`, `handlers.rs:199-262` | ~0.3–0.5 ms/order for a 1,000-order MM |
| T-3 | **High** | Exchange settlement ~24 allocs + 8 BLAKE3 per fill via a growing `CanonicalState` Vec | `modules/exchange/src/settle.rs:97-163`, `modules/framework/src/lib.rs:870-972` | **2.27 µs/fill measured** on top of a 0.60 µs match |
| T-4 | **High** | Production markets hard-coded `max_resting: 64` | `crates/node/src/lib.rs:862,881` | 65th resting order → `BookFull` |
| M-1 | **High** | Matcher nonce checkpoint: full-map serialize + `fsync` + `rename` every 64 admissions on the sequencer | `crates/matcher/src/settlement.rs:295,337,468` | 15–80 µs/order amortised; ≥4 ms p99.9 |
| M-2 | **High** | Sequencer parks immediately (no spin); 2 futex wakes per order at any sub-saturation load | `crates/matcher/src/lib.rs:1430-1440`, `ring.rs:224-233` | 15–100 µs/order |
| M-5 | **High** | `TCP_NODELAY` never set on accepted order-entry sockets | `crates/matcher/src/server.rs:429,1240` | up to 40 ms for pipelined clients |
| M-3 | **High** | Default `--mode multi` + `--markets 128`: global `Mutex<NonceTracker>` per order, blocking `recv()` inside async handlers, 128 threads | `bin/oxide-matcher/src/main.rs:77,111,380` | ≥2× slower than ring mode |
| P-1 | **High** | RPC recovers the sender twice per submitted tx | `crates/rpc/src/endpoints.rs:889` → `modules/evm/src/batch.rs:185` | ~60 µs CPU/tx, half wasted |
| X-3 / N-9 | **High** | ~50 threads on 8 physical cores: two 16-thread rayon pools, 8 verify workers, 2 threads/peer, tokio; no size knobs, no pinning except pump+lane | `executor/src/lib.rs:1904`, `node/src/verify_pool.rs:97` | scheduler jitter, SMT contention on crypto |
| B-1 | **High** | No `target-cpu`; bitboards compile to `bsf/bsr` not `tzcnt/lzcnt`; `secp256k1-sys` built with no `CFLAGS`; thin LTO; glibc malloc; no PGO | `.cargo/config.toml`, `Cargo.toml:237-253` | 3–15% across every hop |
| S-3 | Med | CRC-32 slice-by-8 (~1.5 GB/s) over whole block bodies under the journal mutex; box has PCLMULQDQ | `crates/primitives/src/lib.rs:858-877` | ~0.5 ms per MiB of block |
| S-1 | High (latent) | The only authenticated backend rehashes the entire state per batch | `crates/storage/src/auth_journal.rs:531,611-622` | O(state) per block if ever enabled |
| G-1 | **High** | Criterion "gates" are doc comments, not assertions, and the durability benches run on tmpfs: `deliver_qc_signed_wal` is 2.8× over its gate, `perps_place_with_margin` 2× over, and the bench-only parallel scheduler is 13–26% **slower** than sequential here — all silently | `crates/consensus/benches/engine.rs`, `modules/perps/benches/perps_settlement.rs`, `crates/executor/benches/uniswap_transfer.rs` | regressions invisible |

Full per-subsystem tables are in §5; the remediation order is in §9.

---

## 2. Prior-audit resolutions — status at HEAD

| Finding | Status | Evidence |
|---|---|---|
| F-01 pump idle sleep | **Partially regressed.** The 1 ms sleep became an unconditional 1 ms `recv_timeout` on the transport channel. Commit 1c9bc93 added a `progressed` flag to skip it after productive passes; merge 7cbcbcd dropped it (`grep -c progressed validator_net.rs` → 0). Internal events don't wake the pump (→ N-1). | `validator_net.rs:2247-2249` |
| F-02 pinning | Holds, narrow. `taskset -pc` via subprocess, once per thread; only pump and exec lane are pinnable; nothing else is sized or pinned; no SMT-sibling check (`consensus_core=1`, `exec_lane_core=9` validates and shares a physical core here). | `primitives/src/lib.rs:1203-1226` |
| F-03 SPSC ring | Holds with residual defects: `severed` (read per push) and `space` (written per pop) share an unpadded line; no cached head/tail so every op is a cross-core line transfer; `Notify::notify_one` on every pop. | `matcher/src/ring.rs:72-86,335-347,473-485` |
| F-04 response parking | Holds. | `matcher/src/lib.rs:1366-1380` |
| F-05 market-data fanout | Holds **and is unwired** — no `publish_*` call site exists in `lib.rs`, `multimarket.rs`, `server.rs`, or `main.rs`. Production emits no market data. | grep |
| F-06 `verified_locally` | Holds as code; **cliff in effect**: `dispatch_run` takes the preverified path only if *all* txs in the run are cached, else re-recovers all of them. Cache is local, fed by the serial per-tx ingest (N-2). | `executor/src/exec.rs` (`all_cached`) |
| F-07 OCC bench-only | Holds. | |
| F-08 `Arc<[Event]>` | Holds; each tx still builds `Vec<Event>` + `format!` + `Arc` conversion (X-5). | |
| F-09 index-space sweep | Holds. One divide remains per `cancel` (acceptable). | `trading/src/engine.rs:796-803`, `book.rs:404-407` |
| F-10 socket buffers | Holds; 4 MiB request equals this box's `rmem_max` cap. Comment says the applied size is read back; it isn't. | `p2p/src/tcp.rs:1086,2565-2576` |
| F-12 gates | Holds; gates still run nightly on shared `ubuntu-latest` runners (§8). | |
| F-13 metrics | Holds. | |
| F-14 single-order path | Holds at the call site; the path still does ~10 allocations (M-7). | `matcher/src/server.rs:224` |
| F-15/F-18/F-20/F-21/F-23 | Hold. | |
| F-16 FIX scratch | Holds for the report; FIX *inbound* still allocates two `String`s + a lossy `Cow` per message and has no framing (a message straddling two `read`s is dropped). | `server.rs:775-786` |
| F-22 bitboard FOK pre-scan | Holds. | `engine.rs:1050-1129` |
| F-24 broadcast buffer | Holds for committee broadcasts; sync pages still copy per peer; `broadcast_committee` allocates a `Vec<&[u8]>` per call. | `validator_net.rs:905-911,2143` |
| F-25 `DigestMap` | Holds for `preverify_cache`; not applied to `TxOutcomeStore`, nonce maps, mempool `by_hash`/`proposed`, pump `seen_*` (X-13, N-8). | |
| F-26 resting fold | **Regressed in practice.** The bench leaf hashes a stack buffer; the production leaf `book_resting_leaf` builds `CanonicalState::new()` = `Vec::new()` and grows it 8→16→32→64 for a 45-byte preimage: 4 reallocations per leaf, 2 leaves per resting mutation. The gated `_folded` rows under-measure the consensus engine. | `modules/exchange/src/lib.rs:570-578`, `modules/framework/src/lib.rs:870-880`, `trading/benches/matching.rs:71-80` |
| 1c9bc93 "stop idling after productive passes" | **Lost in merge** (see F-01). | |
| 71c4b6a withhold votes on exec lag | Holds. | `engine/votes.rs:46-60` |
| bff4725 batch-parallel intake | Holds for RPC/devnet ingest only; gossip bypasses it (N-2). | `app_iface.rs:192-258` |

---

## 3. Measurements on this machine

Measured 2026-10-10 on the box described above, release profile
(`lto=thin`, `codegen-units=1`, `overflow-checks=true`, no
`target-cpu`), criterion `--measurement-time 3`, process pinned with
`taskset -c 3` (physical core 3, SMT sibling 11 idle), governor
`schedutil`, RAID-1 resync running (disk numbers are an upper bound;
re-measure after resync).

### 3.1 OS floors (python probes, `scratchpad/sysprobe.py`)

| Probe | p50 | p99 | Meaning for Oxide |
|---|---|---|---|
| `fdatasync` 4 KiB append, ext4 on md RAID-1 | **4.0 ms** | **12.8 ms** | Every synchronous durability point (S-2, N-3, N-5, M-1) costs this. Both mirrors must flush; consumer NVMe without PLP. |
| `O_DSYNC` 4 KiB append | 4.1 ms | 36.8 ms | The consensus WAL's write primitive. |
| Loopback TCP RTT, 64 B, `TCP_NODELAY` | 25 µs | 68 µs (p99.9 199 µs) | Floor for one network hop + 2 thread wakes with no isolation. |
| Condvar wake after 200 µs idle | 30 µs | 131 µs | Python-inflated, but the shape is the point: an unpinned waiter on a `schedutil`/C2 box wakes in tens of µs with a 100+ µs tail. |
| `cpuidle` C2 exit latency (sysfs) | 400 µs | — | Any pinned thread that parks on an idle core can pay this. |

### 3.2 Criterion results (hot paths)

All rows are criterion p50 (point estimate) on this box, single core.
"Recorded" is the number the bench's own doc comment carries (M-series
dev machine). `/tmp` is **tmpfs** here, and the storage and consensus
benches write to `std::env::temp_dir()` / `tempfile::tempdir()`, so
their "sync" rows measure RAM, not the disk (see §8).

**Engine, ring, codec, primitives — the ns-class cores hold**

| Bench | Measured here | Recorded | Note |
|---|---|---|---|
| `trading/rest_cancel_pair` | 64 ns | <400 ns gate | 2 ops → 31 M ops/s/core |
| `trading/rest_cancel_pair_folded` | 485 ns | "+≈160 ns/leaf" | **fold tax is 421 ns per pair (6.6× the raw pair)**: two leaves × (133 ns BLAKE3 + ~75 ns of `CanonicalState` reallocs) — F-26 regression measured |
| `trading/match_single_level` | 595 ns | 470 ns | |
| `trading/match_sweep_10_levels` | 1.87 µs | <3 µs gate | |
| `trading/mixed_workload` (256 ops) | 18.8 µs → **73 ns/op, 13.6 M ops/s** | ≥1 M gate | |
| `trading/mixed_workload_folded` | 57.4 µs → 224 ns/op, 4.5 M ops/s | — | the on-chain shape is 3× the raw engine |
| `trading/fok_prescan/bitboard` vs `linear` | 67 ns vs 3.0 µs | 82 ns vs 2.6 µs | F-22 holds, 44× |
| `matcher/ring_push_pop/spsc` vs `crossbeam` | 15.5 ns vs 27.1 ns | 12.9 vs 23.2 | single-threaded; cross-core transfer not measured (M-14) |
| `matcher/ring_burst_64/spsc` vs `crossbeam` | 1.11 µs vs 2.19 µs | 0.91 vs 1.90 | |
| `codec/order_msg_roundtrip` | 25.7 ns | <80 ns gate | |
| `codec/vs_bincode encode/decode vec_u64_x16` | 27.7 / 49.3 ns vs 119.5 / 50.7 ns | — | encode 4.3× bincode; decode parity |
| `primitives/fixed/mul_div_half_up` | 6.4 ns | — | 64-bit-fitting inputs only; the `__udivti3` path is never benched (S-8) |
| `crypto/hash_one/32b`, `hash_pair` | 133 ns, 220 ns | — | the per-leaf cost behind T-3 (8 per fill) |

**Crypto — the per-item costs that bound every pipeline here**

| Bench | Measured here | Implication |
|---|---|---|
| `crypto/tx_recover/recover_address` (secp256k1, C, global ctx) | **51.8 µs** | ~19k recoveries/s/core; 8 cores ≈ 150k tx/s ceiling for any path that recovers. Prior estimates (30–43 µs) were optimistic for this part. `secp256k1-sys` is built with no `CFLAGS`/asm (`ECMULT_WINDOW_SIZE=15`); `-march=znver2` (BMI2 `mulx`/ADX) is an untested lever. |
| `evm/breakdown/7_secp_recover_only` / `5_full_handle` | 53.6 µs / 59.5 µs | recovery is **90%** of a transfer's handle cost; everything else is ~6 µs |
| `evm/breakdown/6_steady_state_batch_100` | 6.00 ms → 60 µs/tx | the unbatched `handle` path, recovery-bound |
| `crypto/bls/verify` | 1.41 ms | |
| `crypto/bls/aggregate_verify/4`, `/32`, `/128` | **1.46 ms**, 1.91 ms, 3.43 ms | N-4's three inline pairings per view ≈ **4.4 ms of pump time per view** on this box, not the 2–3 ms estimated |
| `crypto/bls/sign` | 432 µs | ×3 per view on the pump (proposal, vote, attestation) ≈ 1.3 ms |
| `crypto/bls/aggregate/128` | 4.2 ms | QC formation at a 128-validator committee |

**Composed paths — where the µs go**

| Bench | Measured here | Recorded | Note |
|---|---|---|---|
| `exchange/raw_engine_single_fill` | 0.60 µs | — | |
| `exchange/settlement_single_fill` | **2.87 µs** | "~370 ns/fill" | settlement is 2.27 µs on top of the match — T-3 measured; the bench doc is stale (T-8) |
| `exchange/settlement_sweep/10,100,500` | 25 µs / 260 µs / 1.39 ms | — | 358–398k fills/s/core |
| `exchange/batch_settle_1k_distinct_pairs` / `same_pair` | 807 µs / 134 µs | — | 6× cost for distinct pairs = custody-map walks (T-7) |
| `perps/raw_perps_engine_place` | 0.59 µs | — | |
| `perps/perps_place_with_margin` | **6.16 µs** | **723 ns; doc gate p50 < 3 µs** | 8.5× the recorded number and **2× over the documented gate** on an account with ≤1 open order — nothing failed because criterion benches carry no perf assertions (§8). T-2 predicts ~0.4 ms for an MM-shaped account. |
| `perps/perps_deposit` | 748 ns | 274 ns; gate <2 µs | |
| `perps/state_root_vs_accounts/10000` vs `_full_walk` | 1.48 µs vs 121 µs | — | incremental root works |
| `mempool/submit_single` | 436 ns | — | |
| `mempool/select_100_of_10000` | 343 µs → **3.4 µs per selected tx** | — | 16 `proposed` probes + gap covers + clone per tx (N-8, N-6) — 10k-tx proposal ≈ 34 ms of pump time |
| `executor/uniswap_transfer/sequential/2000` | 8.09 ms → 247k tx/s | 29.3k tx/s (Mac) | |
| `executor/uniswap_transfer/parallel_8/500,1000,2000` | 2.53 / 4.72 / 9.14 ms | "2.5 GG/s, beats sequential" | **parallel is 13–26% slower than sequential on this 8-core box** — the bench-only OCC scheduler (F-07) spawns threads per block; the bench's own rule ("parallel must beat sequential") fails here silently |
| `matcher/alloc_accounting` cancel / amend / crossing_fill | 1.00 / 1.00 / 2.08 allocs per op | ceilings 5 | fills still allocate (M-11) |
| `matcher/alloc_accounting/fix_parse_order`, `ws_parse_order` | 2.67 µs, 1.39 µs, 0 allocs | — | |
| `storage/journal/append_100b` | 62 ns | — | |
| `storage/journal/append_flush_amort`, `sync_1000_records_info` | 121 µs, 122 µs | — | **tmpfs** — not a disk measurement; the real `fdatasync` here is 4 ms (§3.1) |

**Consensus engine bench (`--features conformance`; WAL on tmpfs, so no disk cost is included)**

| Bench | Measured here | Recorded (Mac) | Doc gate | Note |
|---|---|---|---|---|
| `propose_single` / `vote_on_proposal` / `block_hash` | 54 ns / 1.39 µs / 213 ns | — | <50 µs / <30 µs | unsigned, no WAL |
| `vote_signed_wal` | **9.3 ms** | 5.6 ms | <20 ms | with the fsync measuring RAM: this is CPU — pairing(s) + sign + pending-body clone/encode/CRC (N-3, N-4) |
| `propose_signed_wal` | 5.8 ms | 5.2 ms | <20 ms | |
| `form_qc_signed_wal` | 9.8 ms | — | <25 ms | 3× collect + aggregate + self-verify |
| `deliver_qc_signed_wal` | **13.8 ms** | — | **<5 ms** | **2.8× over its own documented gate**, silently (no assertion) |

Read together with §3.1: on this box every one of these rows gets a
further +4 ms p50 / +13 ms p99 per synchronous durability point once
the WAL is on the real disk (two per vote, N-5). A view on this
hardware is therefore CPU-bound at ~10 ms *before* disk, and disk-bound
after — which is why §9 puts N-1/N-3/N-4/N-5/S-2 first.

---

## 4. Critical-path latency maps (as the code stands)

### 4.1 Off-chain venue: order → ack (binary TCP, ring mode, n = 1)

| Hop | Thread | Allocs | Syscalls / waits | Cost (est. here) |
|---|---|---|---|---|
| `read_exact(4)` + `read_exact(143)`; no `TCP_NODELAY` on accept | tokio worker (unpinned, 16 workers) | 1 | 2 `recv` | 2–4 µs |
| `batch_with_chain_id(&[req])` → `verify_batch` with n = 1 (slower than `verify_strict`); `Vec<Vec<u8>>` of signing messages | tokio worker | 6–7 | — | **45–60 µs** (dominant) |
| positions/verified/responses Vecs; `acquire_ring` | tokio worker | 3 | — | 0.2 µs |
| ring push → sequencer parked → `mutex + notify_one` | tokio worker | — | **1 futex** | 3–5 µs |
| sequencer wake (scheduler + C-state) | sequencer | — | — | **5–50 µs** |
| `submit_verified`: SipHash nonce/client-id/resting maps; `(clock)()` dyn + `SystemTime::now`; engine ~0.5 µs; `gone_makers` ×2; every 64th order **`fs::write`+`fsync`+`rename`** | sequencer | 2–3 | fsync/64 | 1 µs + (4 ms / 64 ≈ 60 µs amortised) |
| response ring push → remote tokio wake | sequencer | — | **1 futex** | 3–5 µs + scheduler |
| `write_all(13)` | tokio worker | 0 | 1 `send` | 2 µs |

Three thread hops, two futex wakes, ~12 allocations, one amortised
fsync. **Estimated p50 ≈ 80–130 µs, p99 in the hundreds of µs**,
against an engine that does the match in ~0.5 µs. The engine is
<1% of the order's latency.

### 4.2 Consensus: one view, 4 validators on a LAN

```
LEADER(v):  [≤1 ms idle wait N-1] → prepare_proposal (mempool lock N-7; select clones N)
   → process_proposal(N) → tx_root → encode → Reed-Solomon commitment (unwired feature, N-6)
   → journal fdatasync + WAL O_DSYNC with ≤8 pending BODIES (N-3, N-5)   ≈ 2 × 4 ms here
   → BLS sign → clone×2 → broadcast
   → self-vote: process_proposal(N) AGAIN → verify_qc_signature(high_qc) ~1 ms (N-4)
   → journal sync + WAL O_DSYNC (bodies again)                            ≈ 2 × 4 ms here
FOLLOWER:   frame → decode → verify pool (BLS ~1 ms) → [≤1 ms idle] → store → [≤1 ms idle]
   → vote: process_proposal(N) → verify_qc_signature ~1 ms (N-4) → journal + WAL (bodies) → sign
LEADER:     votes → try_form_qc: aggregate + self-verify ~1 ms (N-4) → broadcast
   → deliver_qc: verify AGAIN ~1 ms (N-4) → commit → finalize_block (block.clone×2, N re-hash)
   → advance_view → [≤1 ms idle] → next proposal
```

With this disk, the synchronous WAL/journal writes alone put a view at
**≥ 8–16 ms p50 and 25–50 ms p99** before any CPU work; the three idle
quanta add 2–3 ms; four inline pairings at 1.46 ms each add ~6 ms
(the engine bench measures 9–14 ms per signed step with the disk
removed, §3.2). **Finality (2-chain)
is tens of ms here**, and it is disk- and wake-bound, not CPU-bound.
After N-1/N-3/N-4/N-5/S-2 the same path is ≈ 2–3 ms per view
(one pooled verify + sign + LAN RTT + one small async-durable write).

### 4.3 Block execution (exec lane, per tx, fast-path transfer)

| Step | Serial / parallel | Est. |
|---|---|---|
| BLAKE3 envelope hash + parse + nonce gate (`plan_block_runs`) — hash already computed at ingest | serial | 0.35 µs |
| cache probe ×2 (`contains_key` + `remove`) | serial | 0.05 µs |
| RLP decode + keccak(raw) + `to_vec` | parallel | 0.4 µs |
| secp256k1 recovery — only on cache miss, **but all-or-nothing per run (X-2)** | parallel | 30–40 µs |
| speculation: per-tx `CacheDB` + `Arc` clone + publish under one `RwLock` (X-4, X-6) | parallel | 1.5–3 µs |
| validation + `commit_state` (+ `basic_ref` clones) | serial | 0.5–1 µs |
| receipt, history (`to_vec` again), event `format!`, outcome store, history mutex | serial | 1–1.5 µs |
| exchange/perps fill on top: ledger 3 mutexes × 2–3 ops, ~24 allocs, 8 hashes (T-3, T-5) | serial | +2–3 µs/fill |
| `end_block`: redb `commit()` with `Durability::Immediate` (X-8 / S-2) | serial | **4 ms p50 here** |

Serial floor ≈ 2–3 µs/tx → **~350–500k tx/s exec-lane ceiling**, then
one 4 ms fsync per block.

---

## 5. Findings by subsystem

Severity: **High** = measurable on every operation or a tail cliff;
Med = per-op µs or allocations on a path that claims zero; Low = ns or
hygiene; Info = design note. "Fix" is the concrete change; "Win" is the
estimate on this machine.

### 5.1 Consensus pump, mempool, node assembly (N-*)

| # | Sev | Finding | Evidence | Fix | Win |
|---|---|---|---|---|---|
| N-1 | **High** | Pump blocks ≤1 ms at the end of every pass regardless of pending internal work: a follower needs 2 extra quanta to vote (verdict → pending → vote across passes), the leader 1 quantum before proposing after a view advance. Verify-pool verdicts travel on a separate crossbeam channel and do not wake the pump. | `validator_net.rs:1098-1100,1572-1600,2247-2249`; `verify_pool.rs:329-342` | Restore `progressed`; route verdicts, gossip and lane completion through one wake source (`crossbeam::Select` or a single ring); vote inside `on_admitted_proposal`; run Phase 1 after Phase 5 in the same pass. | −2…3 ms/view; finality −4…6 ms |
| N-2 | **High** | Every gossiped `MSG_TX` is admitted alone on the pump: BLAKE3 + `payload.to_vec()` + `submit_tx` → `ingest_tx` → `preverify_batch(len=1)` (serial secp256k1) + `keccak256` for pending-tx subscribers. The batched `ingest_tx_batch` is reachable only from `submit_txs`, whose only production caller is a signer-failure rollback. | `validator_net.rs:1340-1370`; `consensus/src/engine.rs:2952-2958`; `app_iface.rs:21-151` | Drain all `MSG_TX` frames of a pass into a Vec → `ingest_tx_batch` once (rayon recover); better, a dedicated ingest thread with an SPSC to the pump. | pump 45 µs → ~1 µs per tx; gossip ceiling ×20 |
| N-3 | **High** | WAL entry includes `pending_tail()`: clones of up to 8 uncommitted `Proposal`s re-encoded and CRC'd on every vote/proposal/QC append under `O_DSYNC`. At `CHAIN_BLOCK_MAX_BYTES` (16 MiB) a 2-block tail is 32 MiB > `MAX_WAL_ENTRY_BYTES` (16 MiB): recovery treats the entry as torn. | `engine/persist.rs:180-211`; `wal.rs:117,128,881-895` | Persist bodies once in a body log keyed by block hash (append at admit/propose); WAL entries carry hashes only (~200 B). | vote WAL from ms to ~100–300 µs; closes a recovery hole |
| N-4 | **High** | Three inline pairings per view on the pump: `vote_if_eligible` re-verifies the header's `high_qc` (already pool-verified on delivery); `try_form_qc` self-verifies the aggregate; the leader's `deliver_qc` verifies the QC it just formed. | `engine/votes.rs:732,1437,1494`; `engine.rs:2363-2402` | Memo verified QC digests per epoch; `deliver_qc_preverified` for the leader. | −2…3 ms/view |
| N-5 | Med | Two syncs per vote on the pump: `commit_durability_barrier` → journal `fdatasync` (dirty every view) then the WAL `O_DSYNC` write; the leader pays both twice per view. | `engine/persist.rs:300-312`; `app_iface.rs:772-780`; `durability.rs:431-441`; `journal.rs:374-379` | One fd / one `O_DSYNC` write covering both, or write the commit record after the lane's own sync. | −1 sync/vote (−4 ms p50 here) |
| N-6 | Med | Leader does ~10 body copies and several O(N) passes per block: `select_with_gas` clone, `note_proposed` hash N, `process_proposal` parse + `estimate_gas` N + `note_in_chain` N inserts, body encode, **Reed-Solomon `shard::commitment` over the whole body though dispersed broadcast is not wired**, `blocks.insert(.., clone)`, `pending_proposals.push(clone)`, re-encode for wire, **self-vote re-runs `process_proposal`**; commit: `txs.clone()`, `block.clone()` ×2, `remove_committed` re-hashes N. | `engine.rs:2000-2235`; `engine/votes.rs:79-84,729-734`; `app_iface.rs:358-488,525-560`; `commit.rs:282-297`; `mempool/src/lib.rs:811-826,873-900` | Carry tx hash in `PreparedTx`/`Proposal`; cache the `process_proposal` verdict by body hash; gate `shard::commitment` behind the feature; `Arc<Proposal>` / `Arc<[TxBytes]>`. | 10k-tx block: ~15 ms → ~3 ms pump time |
| N-7 | Med | One `Mutex<Mempool>` shared by RPC ingest (held for an entire `ingest_tx_batch` insert) and the pump (`prepare_proposal`, `note_in_chain`, `remove_committed`). | `app_iface.rs:234-237,265-271,486-487,525-526` | Single-writer mempool thread + SPSC request/response; short term, chunk inserts ≤512 per lock. | removes multi-ms proposal stalls |
| N-8 | Med | SipHash `HashMap<Hash,_>`/`HashSet<Hash>` on 32-byte digests in mempool `by_hash`, 16 `proposed` sets probed per selected tx, pump `seen_txs`/`seen_proposals`; `DigestMap` exists and is unused here. | `mempool/src/lib.rs:103,743`; `validator_net.rs:1032` | `DigestMap`; replace `proposed: VecDeque<HashSet>` with an in-flight count map. | ~0.3 µs/tx |
| N-9 | Med | Thread census on 16 logical CPUs: pump + lane + verify `min(15,8)=8` + rayon intake 16 + rayon global 16 + 2/peer + accept/connect + RPC runtime ≈ 50 threads; none know about the pinned cores. | `verify_pool.rs:96-98`; `executor/src/lib.rs:1904-1907`; `tcp.rs:1672,2662,2837` | `performance.{verify_workers,intake_threads,rayon_threads,pin_list}`; `ThreadPoolBuilder::num_threads(n).start_handler(pin)`. | p99 jitter from ms to tens of µs |
| N-10 | Low | `rpc.record_exec_certificates(engine.exec_certificates())` every pass allocates a `BTreeMap` + Vec clone at 1 kHz idle. | `validator_net.rs:2110-2112`; `engine.rs:1418-1426` | Push on change. | noise |
| N-11 | Low | Per message: `Proposal::decode` allocs per tx, `Box<dyn FnOnce>` per verify job, `peer.to_vec()` ×2 per submit, Vec per outbound frame. | `verify_pool.rs:311-322`; `validator_net.rs:1156,1173` | Scratch reuse; `PeerId = [u8; 20]`. | 5–8 allocs/msg |
| N-12 | Low | `Instant::now()` 6–10× per pass; u128 `as_millis` per pass. | `validator_net.rs:1215-1222,1996-1997` | One `now` per pass. | — |

### 5.2 Executor, EVM, framework ledger (X-*)

| # | Sev | Finding | Evidence | Fix | Win |
|---|---|---|---|---|---|
| X-1 | **High** | Same defect as N-2 seen from the executor: `ingest_tx` is the per-tx path; `ingest_tx_batch` (rayon) is not on the production gossip route; RPC adapter also submits one at a time. | `app_iface.rs:21-52,192`; `node/src/rpc_adapters.rs:32` | As N-2; coalesce RPC submissions per tick. | as N-2 |
| X-2 | **High** | `dispatch_run` uses the preverified path only when `all_cached`; one uncached tx (gossip race, a dropped frame from the 10k-bounded channel) forces secp256k1 recovery of the entire run. | `exec.rs` (`dispatch_run`); `validator_net.rs:584` | Build `PreverifiedTx` per tx with `verified_locally = hit`, always take the preverified path; carry the probe result in `PlannedTx` (avoid double probe). | removes a +30 µs/tx × block-size cliff |
| X-3 | **High** | Two unsized rayon pools (16 + 16) plus everything else on 8 physical cores; `RAYON_NUM_THREADS` only affects the global pool. secp256k1/BLS gain nothing from SMT siblings. | `executor/src/lib.rs:1904`; `modules/evm/src/batch.rs:110,175,261,606,684,793` | One pool, size = physical cores − pinned (5–6 here), `install` EVM batches into it, pin pool threads. | 10–20% block exec; deterministic latency |
| X-4 | Med-High | Single `RwLock` on the multi-version store; every worker miss `read_state`, every tx `write_state` + `AccountInfo` clone; `ObservedReads`/`MvMaps` are SipHash `std::HashMap`. | `modules/evm/src/parallel.rs` | Shard by `addr[0] & 63`; `alloy_primitives::map::HashMap` (foldhash); preallocate `ObservedReads`. | 20–40% of Phase 4 on contended blocks |
| X-5 | Med | ~8 allocs + 2 raw-byte copies + `format!` + history mutex per tx on commit. | `batch.rs` (`handle_batch_preverified`), `history.rs:338-353`, `exec.rs` (`record_group_outcomes`) | `Arc<[u8]>` raw once; `History::record_batch`; binary events; `DigestMap` outcomes. | 10–15% of serial commit |
| X-6 | Med | Per-tx `CacheDB<MvDb>` + `Arc` clone + `SharedCacheDB`; `publish` clones `AccountInfo` incl. `Bytecode`; `destructive_accounts` `HashSet` per tx. | `batch.rs` (`execute_parallel_decoded`) | Thread-local worker `CacheDB` with `clear()`; `Option`/small-vec; publish key + code hash only. | 5–10% Phase 4 |
| X-7 | Med | `FinalizedBlock` deep-cloned twice on the consensus thread in `finalize_block`; `TxBytes = Vec<u8>`. | `app_iface.rs:540,556`; `types/src/lib.rs:46,439` | `Arc<[TxBytes]>` / `Arc<FinalizedBlock>`. | ~1–2 ms per 10k-tx block |
| X-8 | Med | redb `txn.commit()` with default `Durability::Immediate` inside `end_block` on the exec lane, plus the lane's own journal sync: two fsyncs per block serialized before the next block. | `modules/evm/src/module_impl.rs:502-530`; `persist.rs:988`; `lane.rs` | `Durability::Eventual` (the executor journal already supersedes it for crash recovery, per `durability.rs` module doc) + explicit `sync()` batched with the journal's point. | −4 ms p50 per block here |
| X-9 | Med | Serial per-tx BLAKE3 envelope hash in `plan_block_runs`, then keccak of the same bytes in the EVM phase; hash was computed at ingest. | `exec.rs` (`plan_block_runs`) | Carry the hash in the block / hash in parallel. | ~2.5 ms per 10k block |
| X-10 | Med | Native ledger `set_balance` = 3 mutex acquisitions + `BlockUndo::capture` (clones `AccountInfo`, collects storage map) + `BTreeSet<Address>` insert per side; an exchange transfer is 6 locks + 2 clones per fill leg. | `modules/evm/src/ledger.rs:68-96,139-166`; `versioned.rs:107-118` | Batch API `apply(&[Delta])` taking the lock once per settlement, or a block-scoped `&mut` ledger handle for native modules. | 50–70% of native settlement ledger cost |
| X-11 | Low-Med | Phase 5 validates via `basic_ref` (lookup + `AccountInfo` clone), `commit_state` re-hashes keys, `zero_slot_writers` Vec per tx. | `batch.rs` (`canonical_info_key`, `commit_state`) | Tombstone-aware by-ref compare. | 5% commit |
| X-12 | Low | Per EVM build: `NativePrecompiles::new` clones the warm `AddressSet`; `build_reader` takes two mutexes + two `Arc` clones; `Context::mainnet()` per tx. | `build.rs:19-23,184-228`; `precompiles.rs:803-808` | Cache at `set_native_modules`. | 0.3–0.5 µs per contract tx |
| X-13 | Low | SipHash maps on hot executor keys: `ExecutedNonces.map`, `BlockNonces.delta`, `TxOutcomeStore.outcomes` (keyed by `Hash`), `touched` sets. | `executor/src/lib.rs:28,649,684,1465` | `DigestMap`/foldhash; sorted Vec at block end. | 2–5% |
| X-14 | Info | `contract_mix` bench shows the parallel path **14% slower than serial** on a realistic mix; `parallel_threshold` is count-only (default 32). | `modules/evm/benches/contract_mix.rs` | Contention-aware fallback (re-exec ratio over last N blocks). | avoids a regression on contract-heavy blocks |

### 5.3 Trading engine, exchange, perps (T-*)

| # | Sev | Finding | Evidence | Fix | Win |
|---|---|---|---|---|---|
| T-1 | **High** | `ledger.credit/debit` → `Arc::make_mut` on `Mutex<Arc<CacheDB>>`. When any snapshot clone is alive (RPC `eth_call`/history reads, snapshot export, the parallel batch) the first write **deep-copies the entire account cache** (all accounts, storage maps, contracts, logs). The code's own comment acknowledges it. | `modules/evm/src/ledger.rs:70-73`; clones at `read.rs:404,461`, `history.rs:891-1033`, `module_impl.rs:853`, `batch.rs:764` | Uniquely owned live cache (`Mutex<CacheDB>`); readers get an immutable per-block snapshot published at `end_block` (copy-on-publish, off the lane) or an MVCC view over `VersionedState`. | removes a ms–s tail cliff on every on-chain fill |
| T-2 | **High** | Perps: `with_account_mut` clones the whole `AccountState` (two BTreeMaps) and re-serializes + hashes the whole account twice per `insert`, called ~4× per fill; admission runs `cover_booked` O(N) and `open_order_im_with` twice (BTreeMap build + sort). Bench covers accounts with ≤1 open order. | `modules/perps/src/lib.rs:1083-1092,609-629,529-590`; `handlers.rs:199-241,261-262`; `accounting.rs:41-96` | In-place `CommittedMap::update`; two-level account leaf (header ⊕ Σ order leaves); maintained open-order IM scalar per (account, market). | ~0.4 ms → ~5 µs per MM order |
| T-3 | **High** | Exchange settlement ~24 heap allocations + 8 BLAKE3 per fill: `base_holds` (2 leaves), `base_balances` (2), `fee_vault` (2), engine `fold_replace` (2), each through a growing `CanonicalState` Vec (2–4 mallocs); `fill_event` Vec, `Vec<Event>` per tx, `Vec→Arc<[Event]>` copy. Module doc claims zero-alloc. | `settle.rs:97-163`; `exchange/src/lib.rs:533-578`; `framework/src/lib.rs:718-731,870-972`; `codec.rs:123-133`; `executor/src/exec.rs:633` | `CanonicalState` with inline `[u8; 96]` + len (std-only), or hash fixed-shape leaves straight into the hasher; inline `Event.data` (fills ≤ 73 B). | ~0.6–0.9 µs/fill; 24 → 0–1 allocs |
| T-4 | **High** | Production spot and perps markets are listed with `max_resting: 64` and no config surface. | `crates/node/src/lib.rs:856-884` | Markets in `NodeConfig`/genesis, default ≥ 2^16, arenas prefaulted. | makes "orders/s chain-wide" meaningful |
| T-5 | Med | Three mutexes (`db`, `block_undo`, `touched`) + `capture` per ledger op; 2–3 ops per order. | `ledger.rs:71-100,105-135` | Fold `block_undo`/`touched` under the `db` guard; skip storage clone for EOAs. | 0.6–1.2 µs/order |
| T-6 | Med | `ReduceOnlyCap::cap` runs for every maker on every perps sweep (3 BTreeMap lookups + `spent` entry alloc) with no fast path when the market has no reduce-only orders. | `perps/src/lib.rs:756-791` | Maintain a reduce-only count; skip when zero; inline `spent`. | ~2 µs per 10-level sweep |
| T-7 | Med | `CommittedMap<(Address,u8),Qty>` BTreeMaps for custody: 2 `get` + 2 `insert` (each insert = get + 2 hashes + insert) ≈ 8 tree walks per fill. | `settle.rs:97-157` | Flat open-addressed map (the batch path's `ConsumedMap` shape). | 0.4–0.8 µs/fill at scale |
| T-8 | Med | Bench docs describe a settlement path that no longer exists ("one `ledger.transfer()`, two BTreeMap lookups, ~370 ns"); gates measure 2 accounts / 1 market / hot everything; `rest_cancel_pair_folded` benches a stack leaf, not `book_resting_leaf`. | `exchange/benches/settlement.rs:12-52,495-515`; `perps_settlement.rs:557-572`; `trading/benches/matching.rs:71-80` | Bench the real leaf fn; add MM-shaped accounts, cold-cache, concurrent-snapshot rows, p99. | gates stop passing on the wrong shape |
| T-9 | Med | `Bitboard { tiers: Vec<Vec<u64>> }`: double indirection + two bounds checks per tier per op. | `bitboard.rs:43-47,83-174` | Flat `Vec<u64>` with const tier offsets, or inline `[u64; 1+64+4096]`. | 3–6 ns per book op (~5% of engine op) |
| T-10 | Med | No huge pages / prefault for arenas. At plan scale (2^20 resting) a market is ~100 MiB (64 MiB pool + 32 MiB IdMap + 4 MiB levels) vs an 8 MiB L2-DTLB reach and an 8 MiB L3 slice. THP is `madvise` and nothing `madvise`s. | `pool.rs:113-119`; `idmap.rs:87-102`; `book.rs:369-377` | Today, zero-code: `GLIBC_TUNABLES=glibc.malloc.hugetlb=1` + pre-touch; properly: `mmap` + `MADV_HUGEPAGE` arenas, one market writer per CCX. | 2–4 TLB misses (~100 ns) per fill at scale |
| T-11 | Low | `format!` on per-order reject paths (attacker-controllable). | `handlers.rs:42,257`; `ledger.rs:53-58` | Static strs. | 100–300 ns + alloc per reject |
| T-12 | Low | `PerpsModule::handle` locks `inner`, drops, re-locks; market looked up twice. | `module_impl.rs:45-51`; `handlers.rs:146,253` | One guard. | ~40 ns |
| T-13 | Low | `OrderPool::index` `usize::try_from(slot).unwrap_or(0)` aliases slot 0 on a bogus index. | `pool.rs:179-200` | `debug_assert` + unchecked-by-construction index type. | correctness smell |
| T-14 | Low | `margin_check_trade_parties` dedups with `Vec::contains` (O(fills²)). | `handlers.rs:329-336` | Sort/dedup or bitmap. | quadratic on deep sweeps |
| T-15 | Info | `fold_replace` hashes the maker leaf twice per partial fill (F-26 ACKNOWLEDGED). | `engine.rs:871-875,979-983` | Qty-free leaf, protocol-versioned. | 2 hashes/partial fill |
| T-16 | Info | Per-market working set at the dense cap ≈ 100 MiB ≫ 8 MiB CCX L3; cross-CCX hits cost +30 ns on this part. | `book.rs:350-377` | Pin each market's single writer to a core; keep its arena on that CCX. | — |

### 5.4 Off-chain matcher venue (M-*)

| # | Sev | Finding | Evidence | Fix | Win |
|---|---|---|---|---|---|
| M-1 | **High** | `NonceTracker::check_and_consume` → `flush` every `NONCE_FLUSH_EVERY = 64` admissions: serializes the entire nonce map, `fs::write`, `sync_all`, `rename` — on the sequencer (ring mode) or inside the global nonce mutex every transport thread takes (multi mode). `--nonce-state` is the runbook's production setting. | `settlement.rs:295,337,451-468` | Delta WAL: `(owner, nonce)` on an SPSC to a durability thread; fsync there on a cadence; full checkpoint at `seal_batch`. | lifts a ~20–60k orders/s ceiling; kills a 4+ ms p99.9 spike |
| M-2 | **High** | No spin-before-park: the sequencer parks on the first empty pass; every order at sub-saturation pays `mutex + notify_one` (producer) + futex wake (consumer) + scheduler/C-state exit; the response path repeats it toward tokio (remote wake). | `lib.rs:1430-1440`; `ring.rs:224-233`; `server.rs:160-166` | Spin 100–300 µs polling all rings before `wait_for_work`; `--sequencer-idle=spin|park`; brief spin on the response consumer before `Notify`. | p50 −20…60 µs, p99 −100+ µs |
| M-3 | **High** | Default `--mode multi`: per batch a fresh `std::sync::mpsc::channel`, a global `Mutex<NonceTracker>` per order (with M-1 inside), worker blocks on `recv()`, and the tokio worker **blocks on `response_rx.recv()` inside an async handler**. | `main.rs:111`; `multimarket.rs:190-199,215-230`; `server.rs:1282-1286` | Make `ring` the default; multi mode gets per-market SPSC rings + sharded nonces; never `recv()` on an executor thread. | ≥2× at ≥8 connections |
| M-4 | **High** | Oversubscription/no isolation: `--markets 128` → 128 worker threads + 16 tokio workers (`new_multi_thread()` default, no affinity) + blocking pool + 10 ms settlement pump + settler; sequencer core not excluded. | `main.rs:77,380`; `server.rs:1105` | `worker_threads = cores − reserved`; `on_thread_start` → pin to the non-sequencer set; markets ≤ 6 on this box; isolate sequencer core + its SMT sibling. | removes ms-class preemption tails |
| M-5 | **High** | `TCP_NODELAY` never set on accepted order-entry sockets. | `server.rs:429,1240` (grep `set_nodelay`: none) | `set_nodelay(true)` at accept; consider `SO_BUSY_POLL`. | removes a 40 ms Nagle × delayed-ACK worst case |
| M-6 | Med | Ed25519 `verify_batch` with n = 1 per single order (slower than `verify_strict`; 6–7 allocs incl. `Vec<Vec<u8>>` of 61-byte signing messages). ~45 µs/verify ≈ 22k/s/core → **~250k orders/s per-item on 8 cores regardless of the engine**; the 3× batch win needs cross-connection batching, which the single-order path never does. `curve25519-dalek` SIMD backend is runtime-dispatched (fine). | `server.rs:81`; `protocol.rs:400-445`; `Cargo.toml:146` | n = 1 → `verify_strict` with a stack `[u8; 61]`; coalesce ≥16 orders across connections per `verify_batch`; session-key auth (verify once per session, then HMAC + sequence). | 250k → 700k+ orders/s on this box |
| M-7 | Med | `Vec<VerifiedOrder>` allocated on tokio, freed on the sequencer, and the reverse for responses: cross-thread malloc defeats tcache. | `server.rs:74-76,108`; `lib.rs:1395` | Inline `[VerifiedOrder; 4]` + len, or a per-ring slab returned via the response ring. | ~0.3 µs/order; allocator stops scaling-limiting |
| M-8 | Med | Ring: unpadded `severed`/`space`; no cached head/tail; `Notify::notify_one` every pop. | `ring.rs:72-86,335-347,473-485` | Pad; rigtorp-style cached indices; waiter flag before `notify_one`. | 2–3× on the hand-off hop |
| M-9 | Med | Cancels via `spawn_blocking` + `std::sync::mpsc`; the sequencer services the control channel only after draining all 256 rings → cancel waits behind every queued order. Cancel:order is ≥5:1 in HFT. | `server.rs:280-289`; `lib.rs:1403-1425` | `enum RingItem { Orders, Action }` in the order ring under the same lease. | cancel p99 = order p99 |
| M-10 | Med | Production addresses are BLAKE3-derived so `is_flat` is always false: every balance op hits `sparse: HashMap<[u8;20],u64>` (SipHash, growth rehash on the hot thread); the `balance_cache` bench measures the flat path production never takes. | `balance.rs:8-14,81-120` | Open-addressed `RegTable`-style table, pre-sized. | ~0.15 µs/order; no rehash stalls |
| M-11 | Med | `LegCostAcc` BTreeMap keyed by a 70-byte `LegId`; `gone_makers` 2 Vecs + O(n²) dedupe; 2–3 SipHash ops per order for client-id maps. `alloc_accounting` ceiling of 5/op accepts this. | `settlement.rs:88-110,168-190,195-230` | Client ids by order slot; per-order local leg accumulation; scratch Vecs on the server. | zero-alloc fill path; ~0.4 µs/filled order |
| M-12 | Med | `seal_batch` `mem::take` → `Vec::new()` regrows to 10k through ~14 reallocs; multi mode seals 128 workers serially. | `lib.rs:764-768`; `multimarket.rs:238-250` | Pre-sized spare Vec swap; non-blocking fan-out. | removes 100 ms-aligned jitter |
| M-13 | Med | Settler runs synchronous executor calls and file writes on a tokio worker. | `settler.rs:501-540,653-680` | Dedicated thread. | removes a periodic executor stall |
| M-14 | Med | Bench realism: `ring.rs` bench is single-threaded push+pop (never the cross-core transfer); `matcher_throughput` is signature-bound; no e2e loopback p50/p99/p99.9; no idle-wake row; no nonce-flush row. | `benches/ring.rs:12-30`; `matcher_throughput.rs:60-100`; `alloc_accounting.rs` | Pinned 2-thread ring bench (same-CCX vs cross-CCX); e2e HDR via `oxide-loadgen`; idle→first-ack row. | M-1/M-2 become visible to CI |
| M-15 | Low | `(self.clock)()` `Arc<dyn Fn>` + `SystemTime::now` per order even with rate limiting disabled; FIX inbound allocs + O(tags × fields) rescans + no framing; `run_server_ring` builds a throw-away `DenseBook` 1<<16. | `lib.rs:398-399`; `risk.rs:174-205`; `server.rs:775-786,1163-1173` | Skip clock when rate limit is 0; single-pass FIX parse with `8=…10=xxx\x01` framing. | small |
| M-16 | Info | Market data is unwired; when wired, `publish_l2` takes owned Vecs, full-depth snapshots, JSON only; settlement window 100 ms. | `market_data.rs`; `server.rs:1077` | Incremental binary L2 deltas into the SPSC; JSON only at fanout. | — |

### 5.5 Storage, codec, primitives, crypto (S-*)

| # | Sev | Finding | Evidence | Fix | Win |
|---|---|---|---|---|---|
| S-1 | **High** (latent) | `JournalBackend::apply_batch` → `recompute_state_root` concatenates every `(key,len,value)` of the whole `BTreeMap` into a fresh Vec and BLAKE3s it per batch; clones every old value and every new value, and `encode_batch_record` copies the batch again. Not wired (node uses `RedbBackend`), but it is the only `Caps::authenticated` backend. | `auth_journal.rs:518-531,611-640`; `node/src/lib.rs:779` | Incremental root (sparse Merkle over touched keys), `Arc<[u8]>`/borrowed `Op` values. | O(state) → O(touched) per block |
| S-2 | **High** | No asynchronous durability primitive anywhere: consensus WAL `O_DSYNC` on the pump; executor journal `write_all` + `sync_data` under the journal mutex; redb `Durability::Immediate` commit on the exec lane. 4 ms p50 / 13 ms p99 each on this box. | `wal.rs:714,849-852`; `durability.rs:431-433`; `journal.rs:354-361`; `modules/evm/src/persist.rs:988`; `redb-4.2.0 transactions.rs:954` | `JournalWriter::sync_async()` → one pinned I/O thread, completion via an `AtomicU64` durable-offset watermark / SPSC; `RedbBackend::open_with(Durability::Eventual)`; `io_uring` `IORING_OP_FSYNC` later. | fsyncs/view 4 → 1, off the critical threads |
| S-3 | Med | CRC-32 slice-by-8 (~1.5–2 GB/s) over whole block bodies per journal record and per WAL entry, inside the journal mutex. The box has PCLMULQDQ (15–25 GB/s folding). | `primitives/src/lib.rs:858-877`; `journal.rs:300`; `wal.rs:610` | In-tree `_mm_clmulepi64_si128` folding behind `is_x86_feature_detected!` with `#[allow(unsafe_code)]` + SAFETY (same pattern as `fallocate`); KAT `0xCBF43926`. | ~0.5 ms per MiB of block |
| S-4 | Med | `StorageBackend::get` returns `Option<Vec<u8>>` (spec says `Option<&[u8]>`); `RedbBackend::get` opens a read txn per call. Only boot/recovery reads today. | `backend.rs:90`; `redb_backend.rs:112-117` | `Cow`/visitor API; one read txn per block. | 1–2 µs + alloc per future read-through miss |
| S-5 | Med | `codec` has zero `#[inline]`; `primitives` 2; `crypto` 0. Thin LTO's import heuristic skips the looping `read_varint`/`read_bytes` first. | `grep -c '#\[inline' crates/codec/src` → 0 | `#[inline]` on all `Reader`/`write` methods and primitive `Encode`/`Decode` impls; verify with `cargo asm`. | 20–50 ns per decoded message |
| S-6 | Low | `DigestHasher` does 5 multiply steps, not the documented 1: `#[derive(Hash)]` on `Hash([u8;32])` writes a length prefix + 4 chunks. | `primitives/src/lib.rs:40,1339-1349` | Hand-written `impl Hash for Hash { s.write(&self.0) }`; take `u64::from_le_bytes(bytes[..8])`. | ~2 ns × several lookups/tx |
| S-7 | Low | `pin_current_thread` shells out to `taskset` (hard-fails if absent); `online_cpus()` counts logical CPUs; no SMT-sibling check. | `primitives/src/lib.rs:1203-1244` | Read `thread_siblings_list`; `perf_pin_errors` rejects two pinned actors on one physical core and warns when a sibling isn't isolated. | prevents a silent 2× slowdown |
| S-8 | Low | `mul_div_half_up` is unused on the fill path (good). If used for fees: `product / div` + `product % div` = two `__udivti3` calls (40–80 ns). | `primitives/src/lib.rs:512-548` | Single div-rem; reciprocal-multiply specialisations for `PRICE_SCALE`/`QTY_SCALE`/bps. | 40 → 5 ns per fee calc |
| S-9 | Info | Crypto backends are right (`secp256k1` C with global context ~22–30 µs; `blst` ADX; `blake3` AVX2; `ed25519-dalek` SIMD, all runtime-dispatched). Residuals: `recover_sender` does `to_standard().serialize_compact()` just to read `s`; `crypto::secp::keccak256` is software `sha3` while `alloy-primitives` already links `keccak-asm` (3 EVM tx-hash sites hit the slow one, ~250 vs 150 ns); `aggregate_verify` deserialises every pubkey per call (1–2 µs each → 100–200 µs per 100-validator QC); `Hasher::hash_one` does `new()+update(1 B)+update()` (extra block copy for ≤63 B inputs). | `secp.rs:205-258,404-406`; `tx.rs:310,791,823`; `bls_signer.rs:366-385`; `hash.rs` | Read `s` from `sig[32..64]`; switch to `alloy_primitives::keccak256`; cache deserialised `blst` pubkeys per epoch; single-shot stack preimage for short inputs (the `mmr::hash_node` pattern). | 1%/tx; 100–200 µs/QC; 10–20% on short hashes |
| S-10 | Info | MMR push alloc-free; `root()` allocs a peaks Vec per block; `JournalWriter::append` is pure memory; `new_segment_file` lacks the WAL's `fallocate` so the first sync into each new segment pays block allocation. | `mmr.rs:268-293`; `journal.rs:278-313` | `fallocate(KEEP_SIZE)` + `posix_fadvise(DONTNEED)` after seal; stack peaks array. | avoids a periodic first-sync spike |

### 5.6 Transport, RPC ingress, config, build (P-*, B-*)

| # | Sev | Finding | Evidence | Fix | Win |
|---|---|---|---|---|---|
| P-1 | **High** | `eth_sendRawTransaction` recovers the sender in the endpoint, then `ingest_tx` → `preverify_one` recovers it again. | `rpc/src/endpoints.rs:889`; `modules/evm/src/batch.rs:180-186` | `TxSubmitter::submit_tx` accepts a `PreverifiedTx` with `verified_locally = true`; `Executor::ingest_preverified`. | +~45% RPC ingest per core |
| P-2 | **High** | RPC runtime is `new_current_thread` + default `spawn_blocking` pool (≤512 threads) floating across all CPUs incl. the pump's; every submit is a cross-thread hop. | `validator_net.rs:829`; `rpc/src/server.rs:659` | `new_multi_thread().worker_threads(2)` pinned to housekeeping cores; run submit inline (~40 µs CPU). | −30…80 µs submit p50 |
| P-3 | Med | No batch ingest for JSON-RPC arrays: `handle_value` processes elements one by one → N × `ingest_tx` → N × mempool lock. `ingest_tx_batch` is used only by the devnet injector. | `rpc/src/lib.rs:1406-1430`; `app_iface.rs:192` | Collect `eth_sendRawTransaction` elements of an array and route through `ingest_tx_batch`. | 3–6× RPC batch ingest |
| P-4 | Med | Three copies of the tx bytes per submit; `TxBytes = Vec<u8>`. | `rpc_adapters.rs:64,78` | `TxBytes(Arc<[u8]>)`. | ~100 ns + allocator pressure |
| P-5 | Low | `serde_json::Value` DOM per request; WS pending-tx fanout serializes per subscriber under the `active` mutex (F-05's fix never ported here). | `server.rs:630`; `lib.rs:461-494,808` | Serialize once, `Arc<str>`. | RPC node only |
| P-6 | Med | Transport is thread-per-peer × 2 with std blocking I/O: per inbound frame `read` → `vec![0u8; len]` → `PeerId` (`Vec<u8>`) clone → `mpsc::send` (futex) → pump `recv` taking `Mutex<Receiver>` per message. ~110 threads at 50 validators. | `tcp.rs:2392,2477,2510,2578,2220`; `ports/src/transport.rs:33` | One epoll/`mio` reactor thread feeding the pump through an SPSC ring; `PeerId = [u8; 20]`; frame slab. Pin reactor on the pump's SMT sibling (shared L1/L2 hand-off). | −10…25 µs p50 / −50 µs p99 per hop; O(1) threads |
| P-7 | Med | No `TCP_QUICKACK`, `SO_BUSY_POLL`, `SO_PRIORITY`/`IP_TOS` on peer sockets (only `NODELAY` + buffers). | `tcp.rs:2565-2576` | Re-arm `QUICKACK` after each read; `SO_BUSY_POLL=50` once pinned. | −20…40 µs vote→QC p99 |
| P-8 | Low | Writer loop allocates `Vec<Frame>::with_capacity(8)` per drain; `broadcast` holds the `streams` mutex across N futex wakes. | `tcp.rs:2601,2196-2200` | Scratch reuse; reactor design removes the fan-out loop. | small at 4 peers |
| B-1 | **High** | `.cargo/config.toml` sets only `incremental=false`: baseline x86-64 ISA. Bitboard `trailing_zeros`/`leading_zeros` compile to `bsf`/`bsr` + zero-check branches instead of `tzcnt`/`lzcnt`; no BMI2 `mulx` for u128 paths. (Hashing/crypto crates runtime-dispatch and are unaffected.) | `trading/src/bitboard.rs:9,123` | `[target.x86_64-unknown-linux-gnu] rustflags = ["-C","target-cpu=znver2"]` for this box (or `x86-64-v3` as the deployable floor). | 3–10% on engine/codec |
| B-2 | Med | `lto = "thin"`; no PGO/BOLT; glibc malloc with ~50–150 threads (arena locking + trim show up as tail latency). | `Cargo.toml:237-253` | `lto = "fat"` (3–8%); `mimalloc` as `#[global_allocator]` in the bins only (hot-path crates stay std-only); PGO on `oxide-validator`/`oxide-matcher` with the devnet load scripts as training (5–15%). | 10–25% combined |
| B-3 | Low | `overflow-checks = true` in release costs 2–8% on integer-dense loops. The justification (money arithmetic must not wrap) is sound for `trading`/`exchange`/`perps`. | `Cargo.toml:245-251` | Keep globally; bench `[profile.release.package.{codec,primitives,storage}] overflow-checks=false` and flip only on a measured >3% win, as the comment already demands. | 0–5% on codec/CRC |
| B-4 | Low | `Dockerfile` uses `rust:1.95-bookworm` while the pin is `1.98.1`. | `Dockerfile` | Align. | reproducibility |
| C-1 | Med | All `[performance]` pins default `None`; verify pool `available_parallelism−1` clamped to 8 (so 8 here); rayon 16 + 16; no `verify_workers`/`intake_threads`/`rpc_worker_threads`/`transport_core`/`realtime_priority` knobs. | `config/src/lib.rs:641-690`; `verify_pool.rs:97`; `executor/src/lib.rs:1904` | Add the knobs; defaults derived from physical-core count minus pinned set. | prerequisite for §7 |

---

## 6. What dominates on *this* machine (ranked)

1. **Disk durability on the critical threads.** 4 ms p50 / 13 ms p99 per
   fsync, 3–4 of them per view on the pump and lane (N-3, N-5, X-8,
   S-2), plus M-1 on the sequencer. Nothing else in this document is
   within an order of magnitude of this until it's moved off-thread.
2. **Wake-up structure.** 1 ms idle quanta (N-1), park-immediately
   (M-2), futex per message per hop (P-6, M-2), C2 exit 400 µs,
   `schedutil`. Tens to hundreds of µs per hop, ms tails.
3. **Serial crypto on the pump / tokio worker.** Per-tx secp256k1 on
   the pump (N-2), double recovery on RPC (P-1), per-order Ed25519
   with n = 1 (M-6), three inline BLS pairings per view (N-4). Measured here:
   secp256k1 recovery 51.8 µs, one BLS aggregate verify 1.46 ms. With 8
   real cores, per-item Ed25519 caps the venue at ~250k orders/s and
   per-tx recovery caps any recovering path at ~150k tx/s, no matter
   what the engine does.
4. **Oversubscription.** ~50 validator threads / ~150 matcher threads
   on 8 physical cores with no pool sizing and almost no pinning (N-9,
   X-3, M-4, C-1).
5. **Allocation and hashing on paths that claim zero.** ~24 allocs per
   fill (T-3), ~10 per order on the venue (M-7, M-11), ~8 per tx on
   commit (X-5), 5–8 per consensus message (N-11, P-6); SipHash on
   32-byte digests in six places (N-8, X-13, M-10).
6. **Structural tail cliffs.** `Arc::make_mut` state copy (T-1), perps
   O(N) per order (T-2), `all_cached` run cliff (X-2), the WAL body
   tail at the block budget (N-3), `max_resting: 64` (T-4), Nagle on
   the venue (M-5).

---

## 7. Configuring this machine

CPU *i* and *i+8* are SMT siblings; CCX groups are {0,1,8,9},
{2,3,10,11}, {4,5,12,13}, {6,7,14,15}, each with its own 8 MiB L3.

### 7.1 Core map (validator)

| Role | CPUs | Rationale |
|---|---|---|
| Housekeeping: OS, `ixgbe` IRQs, RPC tokio, logging, journal I/O thread | 0, 1, 8, 9 | one CCX absorbs all interrupts and background work |
| Consensus pump | 2 (leave 10 **idle**) | own physical core; no sibling stealing L1/L2 |
| Exec lane | 3 (leave 11 idle) | same CCX as the pump → shared L3 for the block hand-off |
| p2p reactor (after P-6) | 10 | pump's sibling: frame hand-off stays in shared L1/L2 |
| Verify pool (4 workers, not 8) | 4, 5, 12, 13 | pairing is ALU-bound, SMT acceptable |
| Rayon (one pool, 4 threads) | 6, 7, 14, 15 | off the pump's CCX |

Matcher co-hosted on the same box would need its own CCX; prefer a
separate host. Matcher-only box: sequencer on 2 (10 idle), tokio
workers on 4–7/12–15 with `worker_threads = 6`, markets ≤ 6.

### 7.2 Kernel / NIC

```
# cmdline
isolcpus=managed_irq,domain,2-7,10-15 nohz_full=2-7,10-15 rcu_nocbs=2-7,10-15
processor.max_cstate=1          # C2 exit latency is 400 µs on this box
transparent_hugepage=madvise    # keep; arenas madvise(MADV_HUGEPAGE) explicitly
# runtime
cpupower frequency-set -g performance                 # schedutil → performance
for c in /sys/devices/system/cpu/cpu*/cpuidle/state2/disable; do echo 1 > $c; done
sysctl -w kernel.timer_migration=0 vm.swappiness=1 vm.nr_hugepages=2048
sysctl -w net.core.rmem_max=33554432 net.core.wmem_max=33554432
sysctl -w net.ipv4.tcp_autocorking=0 net.ipv4.tcp_slow_start_after_idle=0
sysctl -w net.core.busy_poll=50 net.core.busy_read=50
ethtool -C enp65s0f0 adaptive-rx off rx-usecs 0 tx-usecs 0
ethtool -L enp65s0f0 combined 4          # 4 queues, IRQs pinned to 0,1,8,9
systemctl disable --now irqbalance
# until T-10 lands:
export GLIBC_TUNABLES=glibc.malloc.hugetlb=1
```

Storage: the consensus WAL and executor journal belong on a device
with power-loss protection; on this box the md RAID-1 of consumer NVMe
makes every durability point ≥4 ms. Until S-2 lands, consider a
dedicated enterprise NVMe (or a small PLP-backed partition) for
`wal/` and `journal/`, and keep redb at `Durability::Eventual`.

### 7.3 Node config

```toml
[performance]
consensus_core = 2
exec_lane_core = 3
numa_node = 0
# knobs that do not exist yet (C-1): verify_workers = 4, intake_threads = 4,
# rayon_threads = 4, rpc_worker_threads = 2, transport_core = 10, realtime_priority = false
[network]
tcp_buffer_bytes = 4194304     # LAN; raise with rmem_max for WAN peers
```

Matcher: `--mode ring --markets <n≤6> --pin-sequencer 2` and, once
added, `--worker-threads 6 --sequencer-idle spin`.

### 7.4 Build

```toml
# .cargo/config.toml
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "target-cpu=znver2"]     # or x86-64-v3 for a deployable floor
# Cargo.toml
[profile.release]
lto = "fat"
```
plus `mimalloc` in `bin/*` and a PGO run against the devnet load
scripts. Measure each against the gate suite separately (the prior
audit deferred these for exactly that reason).

---

## 8. Benchmark and gate gaps

What the gates cannot see today, and therefore what regressed
unnoticed (F-01, F-26):

- **No tail latency anywhere.** Criterion reports mean/p50; no p99,
  p99.9 or max in any bench; `oxide-loadgen` prints an average; the only
  HDR histogram in the tree measures the RPC handler. The two numbers an
  HFT venue is judged on — order→ack and submit→commit p99/p99.9 — are
  not measured.
- **Wrong shapes.** Exchange/perps gates use 2 accounts, ≤1 open order,
  hot caches, no concurrent snapshot (T-1 can never show); the resting
  fold is benched on a stack leaf, not the production fn (F-26); the
  consensus engine bench is single-validator, `MockApp`, empty blocks
  (N-3/N-4/N-5 can never show); `sustained_throughput` uses
  `SequencerEngine` (no voting, WAL or network); `tps_rw` measures the
  recovery path, not the production preverified path; `ring.rs` is
  single-threaded (never the cross-core transfer it exists for);
  `matcher_throughput` is signature-bound; `balance_cache` measures the
  flat path production addresses never take; `fixed/mul_div_half_up`
  never exercises the 128-bit division path.
- **Gates are comments.** No criterion bench asserts a time; the
  "Gate" columns are documentation. Measured violations today:
  `deliver_qc_signed_wal` 13.8 ms vs "< 5 ms", `perps_place_with_margin`
  6.16 µs vs "< 3 µs", `uniswap_transfer/parallel_8` slower than
  `sequential` vs "parallel must beat sequential". The devnet
  `trading_throughput` tests are the only enforced floors.
- **Durability benches run on tmpfs.** `storage/journal` uses
  `std::env::temp_dir()` and `consensus/engine` uses
  `tempfile::tempdir()`; `/tmp` is tmpfs on this box (and on most Linux
  CI images), so every "fsync" row measures RAM. The 4 ms real cost
  (§3.1) is invisible to the suite. Add a `OXIDE_BENCH_DIR` override
  defaulting to `target/` and print the filesystem type in the row name.
- **Alloc gates only on the matcher**, and its fill ceiling is 5/op
  (should be 0); none for exchange/perps/executor commit.
- **Noisy runner.** Nightly benches run on shared `ubuntu-latest` with
  a baseline `rust-cache` may or may not restore; a 20% regression is
  inside the noise. The de-rated floors (5M ops/s engine, 400k ops/s
  settlement, 60k tx/s `tps_rw`) catch only catastrophes.
- **Stale docs.** Bench headers cite `ledger.transfer()`/"two BTreeMap
  lookups"/"re-serializes the entire book" — none exist now — and all
  recorded numbers are M-series.

Add, in this order: (1) this box as a self-hosted bench runner with
`--save-baseline main` + `critcmp` failing on >5% p50 / >10% p99;
(2) `oxide-loadgen --hist` (hdrhistogram is already in-tree) and an
e2e submit→commit probe in `e2e-local.sh`; (3) a pinned two-thread
ring bench (same-CCX vs cross-CCX) and an idle→first-ack row;
(4) a 4-validator in-process view-loop bench with a real WAL and N-tx
bodies plus a pump pass-time histogram split by phase; (5) MM-shaped
(100/1k/10k open orders), cold-cache (2^18 levels) and
concurrent-snapshot rows for exchange/perps with alloc assertions;
(6) `aggregate_verify` with cached keys, CRC-32 GB/s, redb `Eventual`
commit, and `fsync p99` rows gated per machine.

---

## 9. Remediation plan

Ordered by (end-to-end win on this machine) ÷ (risk × effort). Each
step is independently shippable with a failing bench/test first.

**Phase A — days, no protocol change, removes the ms-class items**
1. N-1: restore `progressed`, unify wake sources, vote/propose in-pass. (−2…3 ms/view)
2. S-2 + X-8 + N-5: pinned durability thread with a durable-offset watermark; redb `Eventual`; one sync per vote. (fsyncs/view 4 → 1, all off the pump/lane: −8…12 ms p50 per view here)
3. N-4: QC verify memo. (−2…3 ms/view)
4. N-2 / X-1 / P-1 / P-3: batch gossip and RPC ingest through `ingest_tx_batch`; single recovery per tx. (pump 45 → 1 µs/tx; +45% RPC ingest)
5. M-5, M-2, M-3: `set_nodelay`, spin-then-park, `ring` as default. (venue p50 −20…60 µs; kills 40 ms tail)
6. M-1: nonce delta WAL on a durability thread. (removes the sequencer fsync)
7. T-4: markets in config, `max_resting ≥ 2^16`.
8. C-1 + §7: pool-size and pin-list knobs; apply the core map; kernel tuning script in `scripts/`.

**Phase B — a week or two, allocation and hashing diet**
9. T-3 + F-26: inline-buffer `CanonicalState`; bench the real leaf. (24 → 0–1 allocs/fill)
10. T-1: snapshot-on-publish instead of `Arc::make_mut`. (removes the state-copy cliff)
11. T-2: in-place `CommittedMap::update`, two-level perps account leaf, cached IM. (0.4 ms → 5 µs per MM order)
12. X-2 (per-tx `verified_locally`), X-4 (sharded MV store + foldhash), X-5/X-6/X-7 (commit-path allocs, `Arc` block), X-10/T-5 (batched ledger).
13. N-3: body log; 200 B WAL entries. (also fixes the recovery hole)
14. N-6 + X-9: carry tx hashes; cache the `process_proposal` verdict; gate the RS commitment; `Arc<Proposal>`.
15. M-6, M-7, M-8, M-9, M-10, M-11: `verify_strict` for n = 1 + cross-connection batching; inline payloads; ring padding + cached indices; cancels in the order ring; open-addressed balances; slot-indexed client ids.
16. N-8, X-13, S-6: `DigestMap` everywhere a 32-byte digest is a key; fixed `Hash` impl.
17. S-3, S-5, S-9: PCLMUL CRC; `#[inline]` across codec; asm keccak; cached BLS pubkeys; single-shot short hashes.

**Phase C — measured build and platform changes**
18. B-1/B-2: `target-cpu`, fat LTO, `mimalloc` in bins, PGO — one bench day each against the gate suite.
19. P-6/P-7: epoll reactor + SPSC to the pump, `PeerId=[u8;20]`, `QUICKACK`/`busy_poll`.
20. T-10/T-9: huge-page arenas with prefault; flat bitboard.
21. S-1: incremental state root before anyone enables the authenticated backend.
22. §8 bench programme, starting with the self-hosted runner and the two e2e histograms.

Expected end state on this machine after A+B: venue order→ack p50
≈ 15–25 µs (Ed25519-bound) with p99 < 100 µs on isolated cores;
4-validator LAN finality ≈ 5–6 ms (one pooled pairing + sign + RTT +
async durability) instead of tens of ms; exec lane ≥ 500k tx/s before
state root; gossip ingest no longer bounded by the pump.

---

## 10. Honest limitations

- Criterion numbers in §3.2 were taken under `schedutil` with C-states
  enabled and no `target-cpu`; the OS probes in §3.1 ran during an md
  RAID-1 resync (upper bounds). The benches' own "sync" rows ran on
  tmpfs and contain no disk cost at all. Re-run after resync with the §7
  tuning applied to establish the real baseline.
- Per-finding "Win" figures are estimates from code shape and Zen 2 cost
  models (BLAKE3 short input ≈ 100–150 ns, malloc/free ≈ 20–40 ns,
  BTreeMap walk ≈ 30–100 ns, futex wake ≈ 5–15 µs, `aggregate_verify/4`
  ≈ 1 ms). The structural findings (T-1, T-2, N-3, X-2, M-1, S-2) do
  not depend on those models to be real.
- No end-to-end p99 was measured because the tree has no instrument
  for it (§8); building that instrument is the first item of the bench
  programme, not a prerequisite for Phase A.
- `plan.md` is not present in this checkout, so gate text was taken
  from the benches' own doc comments and `hft-audit.md`.
