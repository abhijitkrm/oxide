# Oxide

**A first-principles, hyper-optimized Rust L1 blockchain with a native HFT-grade trading stack.**

Oxide is a gigagas-capable, EVM-equivalent Layer 1 designed from first principles for
one purpose: **on-chain trading at centralized-exchange performance** — a fully
on-chain CLOB + perps venue where the order book *is* the blockchain, secured by
**oxideBFT** (a pipelined 2-chain HotStuff), with every subsystem engineered to
HFT standards (zero-allocation hot paths, sub-microsecond matching, ~50–100ms
blocks, sub-250ms full finality).

> **Status: pre-alpha / Phases 0–3 complete, Phase 4 (hardening &
> testnet) in progress.** Oxide is under active development. Nothing
> here is production-ready yet, APIs will change without notice, and
> no releases have been cut. Protocol specs are landing in `docs/` as
> each phase progresses; the roadmap table below tracks the current
> phase. **Do not run with real funds.**

---

## Why Oxide exists

The best-performing on-chain trading venue today (Hyperliquid) handles ~200k
orders/sec with ~200ms median end-to-end latency, and its own docs state the
bottleneck is execution, not consensus. Traditional exchanges (CME, Nasdaq)
match orders in tens of nanoseconds but are trusted third parties. Oxide's
thesis is that you do not have to choose:

| Property | Oxide target | State of the art |
|---|---|---|
| Consensus | oxideBFT — pipelined 2-chain HotStuff (Jolteon/DiemBFT/MonadBFT lineage), tail-fork resistant | MonadBFT 600ms finality; HyperBFT (Hyperliquid) |
| Block cadence | 50–100ms | Hyperliquid ~70ms; Monad 300ms |
| Full finality | 2 views ≈ 150–250ms (optimistic 1-view ≈ 75–125ms) | Hyperliquid median e2e ~200ms |
| EVM throughput | 1–5 gigagas/s sustained (16–32 core validators) — **~2.5 GG/s measured in a single-node microbenchmark on an 8-core M1** (real revm, parallel executor, signed 21k-gas transfers — not a sustained network measurement; hot-contract workloads serialise at account granularity today); the 12.96 figure quoted earlier was a scheduler simulation | Sei Giga 5 GG/s (devnet); reth+BAL experiments 10 GG/s ceiling |
| EVM compatibility | Full equivalence via revm: JSON-RPC, EIP-1559, MetaMask/Foundry/Blockscout | cosmos-evm `x/vm` (Go) |
| Matching engine | ≥5M ops/s single-core (engine-only), ≥1M orders/s chain-wide, p50 < 200ns per order op | C++ engines ~10–160ns; Hyperliquid 200k orders/s chain-wide |
| Order flow | Fully on-chain signed orders (no operator trust, no private order flow) | Hyperliquid model |

Oxide is **not a fork** of any existing chain. Reference systems (commonware,
Monad, Hyperliquid, Sei Giga, reth, Sovereign SDK, cosmos-evm) are studied for
ideas; differentiating cores (consensus dialect, executor, matching engine,
authenticated storage journal, module framework) are designed and written from
first principles. See [Acknowledgments](#acknowledgments).

---

## Architecture at a glance

```
Users / HFT ──gRPC/WS──▶ Gateway (sig verify, risk pre-check, rate limits)
                              │  SPSC rings
                              ▼
                        Mempool (fee-priority, nonce mgmt)
                              │
   P2P mesh (swappable)       ▼
  ◀────────────▶  CONSENSUS LANE  ── 50–100ms cadence
                     ConsensusEngine  [PORT: default = oxideBFT]
                     (orders transactions only — never executes)
                     BroadcastEngine [PORT: default = erasure-coded + f+1 PoA]
                              │  finalized ordering (OAI)
                              ▼
                    EXECUTION LANE (runs 1 block behind)
                    ┌──────────────────┬───────────────────────┐
                    │ NATIVE TRACK      │ EVM TRACK              │
                    │ module router:    │ revm host + optimistic │
                    │ core / staking /  │ parallel execution     │
                    │ exchange / perps /│ (Block-STM-style OCC)  │
                    │ oracle / gov      │ native precompiles →   │
                    └────────┬─────────┴───────────┬────────────┘
                             ▼   unified state      ▼   trading core
              RAM hot state (huge pages, NUMA-pinned)
              + StorageBackend [PORT: default = authenticated journal
                (MMR-over-log, group commit)]
              + async write-behind → ColdStore [PORT: MDBX/RocksDB/redb]
              + signed post-execution state attestations
                fed back into consensus headers
                              │
                              ▼
              RPC: JSON-RPC (eth_* + oxide_*), WebSocket streams
                   (L1/L2/L3 market data, fills, logs)
```

Three architectural ideas define Oxide (full detail in `docs/`):

1. **The order book must BE the blockchain** (Hyperliquid's insight). The
   matching engine is a native module with its own in-memory, HFT-grade core —
   not a smart contract fighting for shared blockspace.
2. **Consensus orders; execution follows** (Monad's insight). oxideBFT
   finalizes *transaction ordering* only; execution runs one block behind in
   a separate lane with the full block-time budget, and validators sign
   post-execution state roots (execution certificates) that flow back into
   consensus headers.
3. **Nothing is hard-wired** (the cosmos-evm lesson). Consensus engine,
   storage backend, data dissemination, p2p transport, and VM modules are all
   swappable adapters behind stable, type-safe trait seams — with conformance
   suites and performance report cards so "pluggable" never means "slow".

---

## Plug-and-play by design (ports & adapters)

Oxide ships opinionated, performance-validated defaults *and* the ability to
swap them — the Rust-native answer to Cosmos's ABCI composability:

| Port | Default | Swap examples |
|---|---|---|
| `ConsensusEngine` | **oxideBFT** (2-chain HotStuff) | `MockEngine` (sims/tests), `SequencerEngine` (dev mode) — shipped; hotstuff_rs wrapper — planned |
| `AppInterface` (OAI) | oxide app: mempool + executor + state | the boundary every engine programs against (`docs/oai-spec.md`) |
| `StorageBackend` | authenticated journal (MMR-over-log) | `Volatile` (in-memory), `RedbBackend` (pure Rust), `RocksDbBackend` (LSM), `MdbxBackend` (B-tree) — all shipped, conformance-tested, benchmarked |
| `ColdStore` | MDBX (won the Phase 0 bench-off) | RocksDB, redb |
| `BroadcastEngine` | erasure-coded + f+1 availability votes | `PlainGossip` (tiny devnets), external DA (planned) |
| `Transport` | hand-rolled TCP + TLS (signed-greeting peer auth, admission control) | libp2p/QUIC adapter (planned) |
| `VmModule` | `evm` (revm) | SVM/MoveVM modules (post-testnet) |
| `BookBackend` (internal) | dense flat tick ladder | sparse B-tree (wide-range markets) |

Adapters are feature-gated, compiled in at build time (no runtime plugin
loading — a supply-chain guarantee), wired via TOML config in the node
binary, and must pass their conformance suite plus a ≤5%-of-default
performance report card in CI. Hot paths are monomorphized — the seam never
sits on a per-order code path.

---

## Workspace layout

```
oxide/
├── docs/                      # protocol specs (oxideBFT, OAI, storage)
├── crates/
│   ├── primitives/      # Hash, Address, Height/View/Epoch, fixed-point
│   ├── codec/           # deterministic wire codec (no serde on hot paths)
│   ├── crypto/          # BLS12-381 threshold, ed25519, batch verify, hashers
│   ├── runtime/         # runtime abstraction: tokio (prod) + deterministic (sim)
│   ├── ports/           # ★ the seams: ConsensusEngine, AppInterface (OAI), …
│   │                          #   + MockEngine + conformance suites
│   ├── consensus/       # ★ oxideBFT engine + mock/sequencer engines + epochs
│   ├── broadcast/       # erasure-coded dissemination + backfill
│   ├── p2p/             # Transport impl: TCP + TLS, admission control
│   ├── mempool/         # fee-priority pool, nonce queues, dedup
│   ├── storage/         # ★ journal + MMR-over-log + StorageBackend adapters
│   ├── executor/        # block executor: module router + parallel EVM scheduler
│   ├── trading/         # ★ matching engine, risk engine (HFT-grade)
│   ├── matcher/         # ★ order-entry gateway: SPSC rings, FIX/WS/TCP/JSON-RPC
│   ├── rpc/             # JSON-RPC + WebSocket (eth_* + web3_* + txpool_* + debug_*)
│   ├── indexer/         # finalized-block index for explorer queries
│   ├── statesync/       # certificate-verified snapshot bootstrap
│   ├── metrics/ devnet/ config/ types/
│   ├── node/            # node assembly: config-driven wiring of all ports
├── modules/                   # Cosmos-SDK-style module framework + modules
│   ├── framework/  core/  staking/
│   ├── evm/        # revm host + native precompiles; its account
│   │               # store is also the chain's single native-token ledger
│   └── exchange/  perps/  oracle/  governance/
├── bin/                       # oxide-validator, oxide-fullnode, oxide-matcher,
│                              # oxide-devnet, oxide-loadgen, oxide-spammer,
│                              # oxide-deploy, oxide-bench
├── sim/                       # deterministic swarm simulations (chaos injection)
├── fuzz/                      # cargo-fuzz targets
└── .devin/skills/             # coding/testing/performance standards (see below)
```

★ = differentiating custom cores written from scratch.

---

## Engineering standards ( enforced via skills )

This repository codifies its engineering process in `.devin/skills/`:

- **`production-rust`** — first-principles readability, fully detailed
  doc comments (the *why*, spec references, no magic numbers), strict error
  handling (no `unwrap` outside tests), confined-and-justified `unsafe`,
  dependency-free hot-path crates.
- **`testing-standards`** — the five-layer test pyramid: unit → property
  (proptest) → conformance (adapter suites) → deterministic simulation →
  benchmark gates + fuzzing. Bug fixes require a failing test first.
- **`performance-first`** — the hot-path discipline: zero allocation, zero
  syscall, no locks (single-writer + rings), fixed-point only, cache-line
  hygiene, batch everything, measured budgets on every hot function,
  profile-before-optimize.
- **`benchmarks`** — a hot-path feature isn't done until it's benched:
  criterion conventions, gates and baselines (including head-to-head
  "prove it was worth building" comparisons), and mandatory
  plain-English reporting of results.
- **`git-conventions`** — commit format and history hygiene; project
  policy: no AI attribution trailers unless explicitly requested.

Read them before contributing. They are short, and they are the contract.

---

## Getting started

### Prerequisites

- **Rust** 1.91+ (edition 2024) — <https://rustup.rs>
- Linux is the production target; macOS works for development.
  (Some perf features — huge pages, io_uring tweaks, NUMA pinning — are
  Linux-only and degrade gracefully elsewhere.)

### Build & test

```sh
# everything
cargo build --workspace
cargo test --workspace

# quality gates (what CI runs)
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check            # supply-chain policy (after deps land)

# benchmarks (acceptance gates live in the bench files)
cargo bench --workspace

# local devnet (Phase 1 deliverable)
cargo run --bin oxide-deploy -- generate --validators 4 local
```

### Repository conventions

- Protocol specs in `docs/` are the public source of truth and precede
  implementation: `docs/oxidebft-spec.md`, `docs/oai-spec.md`,
  `docs/storage-spec.md`. If code and spec disagree, one of them is wrong —
  fix whichever, in the same PR. (The team's full internal engineering
  megaplan is kept out of the public repo during pre-alpha.)
- Every crate's hot-path functions document a performance budget with its
  benchmark reference (see the `performance-first` skill).

---

## Roadmap

| Phase | Scope | Hard acceptance gates | Status |
|---|---|---|---|
| **0 — Foundation** | workspace, primitives, codec, runtime, ports/OAI, storage journal + MMR | journal ≥1M appends/s single-thread; MMR over 1M leaves <20ms; deterministic 4-node echo sim; mock engine drives app via OAI | ✅ Complete |
| **1 — Consensus + chain skeleton** | oxideBFT, broadcast, mempool, executor v0, core/bank/staking, devnet tooling | 50–100ms blocks; 200k tx/s sim (n=32); devnet runs on SequencerEngine via config swap with **zero app-code changes**; bit-exact journal replay | ✅ Complete |
| **2 — EVM + storage** | revm module, parallel OCC scheduler, JSON-RPC, adapters, snapshots | ≥1 GG/s on 16-core rig; MetaMask/Foundry/Blockscout green; storage conformance for every adapter | ✅ Complete |
| **3 — Trading core** | matching engine, risk, spot + perps, oracle, market data | ≥5M ops/s single-core; ≥1M orders/s chain-wide sim; p50 <200ns order ops; perps property tests (no negative equity, ADL correctness) | ✅ Complete |
| **4 — Hardening & testnet** | fuzz, chaos sims, TLA+ model, external review, 20–50 validator testnet | 7-day soak ≥50% load; zero safety violations in 10k randomized sims | 🚧 In progress |

Post-testnet: mainnet + tokenomics, slashing, encrypted mempool, BAL access
lists, revmc JIT, DPDK/AF_XDP gateway lane, bridges, SVM/MoveVM modules.

---

## What's built so far

Phases 0–3 are complete; Phase 4 (hardening & testnet) is in progress. Here's what's in the repo today:

### Phase 0 — Foundation ✅

- **Workspace**: 20+ crates, edition 2024, strict clippy (`-D warnings`),
  `cargo deny` supply-chain policy.
- **Primitives**: `Hash` (BLAKE3, 32B), `Address` (20B), `Height`/`View`/`Epoch`,
  fixed-point arithmetic (`u64` scaled integers, `u128` intermediates).
- **Codec**: deterministic wire codec (no serde on hot paths), 5ns encode/decode.
- **Crypto**: domain-separated BLAKE3, ed25519, BLS12-381 threshold signatures.
- **Ports/OAI**: `ConsensusEngine`, `AppInterface`, `StorageBackend`,
  `BroadcastEngine`, `Transport`, `VmModule` — all swappable, conformance-tested.
- **Storage journal**: append-only CRC'd journal (group commit), Merkle Mountain
  Range over leaf hashes. Benchmarked: journal ≥1M appends/s, MMR root over 1M
  leaves <20ms.

### Phase 1 — Consensus + chain skeleton ✅

- **oxideBFT**: original pipelined 2-chain HotStuff consensus engine.
- **MockEngine + SequencerEngine**: for deterministic sims and devnet.
- **Broadcast**: erasure-coded dissemination + `PlainGossip` for tiny devnets.
- **Mempool**: fee-priority pool, nonce queues, dedup.
- **Executor**: sequential block executor with module router.
- **Modules**: `core`, `staking` (Cosmos-SDK-style framework); the EVM
  account store doubles as the native-token ledger — there is no bank
  module.
- **Devnet tooling**: `oxide-deploy` (genesis generation), `oxide-validator`,
  `oxide-fullnode`, `oxide-spammer`.
- **Deterministic replay**: bit-exact journal replay verified.

### Phase 2 — EVM + storage ✅

- **EVM module** (`modules/evm`): full `revm` execution (`CacheDB`,
  `transact_commit`, `SpecId::PRAGUE`).
- **Dynamic EIP-1559 base fee**: standard Ethereum fee market algorithm
  (elasticity multiplier = 8, u128 arithmetic, overflow-safe).
- **EVM precompiles**: native module bridge — `BANK_TRANSFER`, `BANK_BALANCE`,
  `STAKING_DELEGATE` at addresses `0x0B_01`/`0x0B_02`/`0x0C_01`.
- **Parallel OCC scheduler**: Block-STM-style speculative parallel execution
  with read/write set tracking and conflict re-execution.
- **4 StorageBackend adapters**: `Volatile` (in-memory), `redb` (pure Rust),
  `RocksDB` (LSM), `MDBX` (B-tree) — all feature-gated, conformance-tested.
- **Storage conformance suite**: shared suite verifying `get`, `range`,
  `apply_batch`, snapshot export/import for every adapter.
- **JSON-RPC server**: 10 Ethereum-compatible endpoints
  (`eth_chainId`, `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionCount`,
  `eth_gasPrice`, `eth_sendRawTransaction`, `net_version`, `web3_clientVersion`,
  `eth_subscribe`, `eth_unsubscribe`).
- **WebSocket subscriptions**: `newHeads` and `logs` subscription types.
- **MetaMask/Foundry/Blockscout integration tests**: 18 tests simulating the
  exact JSON-RPC calls these tools make.
- **Snapshot export/import**: round-trip lossless state export/import.
- **Divergence detection**: execution certificate mismatch reporting.
- **Indexer/explorer v0**: in-memory block/tx index.
- **EVM throughput**: ≥1 GG/s gate met on *real revm execution*
  (~2.5 GG/s parallel on signed 21k-gas transfers; ~0.62 GG/s
  sequential). The parallel figure is transfer-shaped: conflict
  detection is account-granular, so hot contracts (tokens, AMMs)
  serialise — treat ~0.62 GG/s as the honest contract-workload
  number until slot-level MVCC lands. The 4.83/12.96 GG/s Uniswap
  rows below are a scheduler simulation with a synthetic gas
  model — they measure the OCC scheduler, not revm.

### Audit-driven hardening (post-Phase 2)

A full codebase audit against the production-testnet release bar
identified critical consensus-safety findings, HIGH-severity
security issues, and four execution-path ceilings for the 10 GG/block
target. Remediation is in progress:

**Critical fixes (C1–C10):** all landed.
- C1: consensus height overflow (`u64::MAX` wrap) — saturating arithmetic
- C2: future-view vote acceptance — view-range filtering
- C3: unsigned proposals — leader signature verification
- C4: mutual TLS bound to validator keys — client-cert check against the peer-id map + signed-greeting `PeerAuth`
- C5: precompile no-ops — executor-side settlement
- C6: Reed-Solomon reconstruct panic on unequal shards — checked lengths
- C7: matcher ignores protocol nonce — replay protection
- C8: fills before bank settlement — settlement ordering
- C9: consensus WAL — durable vote/lock journal with torn-tail repair (`crates/consensus/src/wal.rs`)
- C10: `executed_nonce` in-memory only — persisted to storage backend

**Execution-path ceilings (10 GG/block):** all landed.
- Ceiling 1: unified block gas limit at 10 GG ✅
- Ceiling 2: parallel executor with slot-granular conflict tracking ✅
- Ceiling 3: sparse retained-trie for O(touched·log N) state root ✅
- Ceiling 4: O(n) receipts root + free-gas stuffing gates ✅

**HIGH-severity fixes:** landed (RPC cost-weighted rate limiting,
per-vote BLS verify, EIP-2718 receipts, perps funding clamp, trading
money-math clamps, RLP trailing bytes, signature malleability,
bounded channels, admission control, mempool nonce anchoring,
certificate-verified snapshots).

**HFT audit (F-01…F-26):** resolved — see `hft-audit.md` (SPSC ring
rewrite, bitboard FOK pre-scan, wait-free market-data publish, scratch
discipline on every write path, CPU pinning, ratcheted throughput
gates) and `docs/system-audit.md` for the follow-up system audit.

### Phase 3 — Trading core ✅

- **Matching engine** (`crates/trading`): multi-market parallel
  matcher (one worker per market), shared `ShardedBalanceCache`
  (64 shards), 4 protocols (TCP, JSON-RPC, FIX, WebSocket).
  24.5M orders/s raw engine; true-SPSC ring transport (~14.7 ns
  push+pop); bitboard FOK pre-scan (~82 ns).
- **Exchange module** (`modules/exchange`): spot CLOB with
  limit/market orders, settlement via the EVM account ledger;
  chain-path settlement 400–550k orders/s (gated).
- **Perps module** (`modules/perps`): perpetuals with margin,
  funding, liquidations, insurance fund, ADL.
- **Oracle module** (`modules/oracle`): median-of-feeds mark price,
  EMA smoothing, quorum gating, staleness tracking.
- **EVM load test**: 100K EVM txs at 6,410 tx/s (4 validators),
  throughput stable as state grows (sparse state root).
- **Trading load test**: 2M trading txs at 72,556 tx/s (4 validators).

### Phase 4 — Hardening & testnet (in progress)

- **Fuzz campaign**: 11 targets (`codec_decode`, `consensus_msg`,
  `evm_execute`, `evm_parallel_differential`, `exchange_settlement`,
  `journal_replay`, `mmr_proof_verify`, `sync_decode`,
  `trading_engine`, `trading_order_validate`, `types_decode`) with
  committed corpus, 10-min nightly budget each.
- **Chaos sim**: 10k randomized scenarios, zero safety violations.
- **TLA+ model** of oxideBFT: 3 counterexamples found and fixed;
  TLC seeded simulation in CI, deep config nightly.
- **Deterministic multinode fault injection**: leader kills, view
  advances, mempool nonce-bridge liveness (green across repeated
  parallel runs).
- **Open gates**: 7-day soak at ≥50% load, external security review,
  20–50 validator public testnet. Current audit state:
  `docs/system-audit.md`.

### Benchmark results (8-core Apple M1)

| Benchmark | Result | Gate |
|---|---|---|
| Journal append | ≥1M appends/s | ≥1M/s ✅ |
| MMR root (1M leaves) | <20ms | <20ms ✅ |
| Storage `apply_batch` (1k keys) | Volatile 13.5M elem/s, RocksDB 4M, MDBX 2.9M, redb 197K | runs + reports ✅ |
| Storage `get` (1 key) | Volatile 32.7M elem/s, MDBX 3M, RocksDB 2.1M, redb 825K | runs + reports ✅ |
| Uniswap-transfer scheduler sim (sequential) | 4.83 GG-equivalent/s — synthetic `NS_PER_GAS` work loop, **not** revm execution | scheduler baseline |
| Uniswap-transfer scheduler sim (parallel, 8 threads) | 12.96 GG-equivalent/s (2.7x speedup) | scheduler scaling ✅ |
| revm execution, real signed transfers (sequential `handle`) | ~29.3k tx/s ≈ **0.62 GG/s** | real EVM number |
| revm execution, real signed transfers (parallel, 10k-tx batch) | ~118k tx/s ≈ **2.5 GG/s** | ≥1 GG/s ✅ |
| State root incremental (100k accts, 10 touched) | 110 µs | <10ms ✅ |
| State root incremental (100k accts, 100 touched) | 1.0 ms | <10ms ✅ |
| State root incremental (1M accts, 100 touched) | 1.27 ms | <10ms ✅ |
| Matching engine (1 market, ring) | 24.5M orders/s raw; ~14.7 ns SPSC push+pop | ≥5M ops/s ✅ |
| Matching engine (128 markets, multi) | 11.68M orders/s | ≥1M orders/s ✅ |
| FOK pre-scan (sparse 1k-level book, bitboard) | ~82 ns (linear oracle: 2.61 µs) | ~32× vs linear ✅ |
| Exchange settlement (chain path) | 538k orders/s (1M-trade gate run) | ≥400k ops/s ✅ |
| EVM load test (4 validators, 100k txs) | 6,410 tx/s | — |
| Trading load test (4 validators, 2M txs) | 72,556 tx/s | — |

**2,048 tests pass.** `cargo fmt --check`, `cargo clippy -D warnings`,
`cargo deny check` all clean.

---

## Contributing

- Read the specs in `docs/`, the roadmap above, and the three skills in
  `.devin/skills/` first.
- PRs must pass: `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test --workspace`, and re-run benchmarks when touching hot paths.
- Bug fixes ship with a regression test (failing-first).
- New adapters must pass their conformance suite and add a perf report card.
- Commit style: imperative subject line + body explaining *why* (see
  `git log` once history begins).

## Security

Oxide is pre-alpha: do not run it with real funds. Once testnet launches,
vulnerability disclosure will follow the responsible-disclosure policy in
`SECURITY.md` (created at that phase). Pre-audit, everything is
best-effort.

## License

Licensed under the **GNU General Public License v3.0**. See [`LICENSE`](LICENSE).

## Acknowledgments

Oxide stands on the shoulders of — and intentionally does **not** copy —
these systems, whose public designs informed ours:

- **commonware** (p2p/crypto/codec/coding primitives, buffered-signature
  amortization, threshold-simplex, QMDB, deterministic runtime pattern) —
  studied as a design reference; the shipped transport/codec are
  first-principles implementations
- **Monad** (MonadBFT: pipelined Jolteon + tail-fork resistance; async
  execution; optimistic parallel EVM)
- **Hyperliquid** (HyperBFT; HyperCore/HyperEVM dual-engine; on-chain signed
  orders; "the order book must be the blockchain")
- **Jolteon / DiemBFT v4 / AptosBFT** (2-chain commit, active pacemaker)
- **Sei Giga** (multi-proposer ordering, async execution with divergence
  commitments, Block-STM OCC)
- **reth / revm / grevm / Block-STM** (parallel EVM execution, BAL/EIP-7928
  access lists)
- **cosmos-evm / evmOS** (EVM-as-module with native precompiles; swappable
  consensus via ABCI)
- **Sovereign SDK** (Rust module-system patterns)
- The HFT orderbook engineering community (flat tick ladders, intrusive
  pools, bitboards) whose published designs proved ~10–160ns matching ops
  are achievable
