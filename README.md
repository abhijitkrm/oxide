# Oxide

**A first-principles, hyper-optimized Rust L1 blockchain with a native HFT-grade trading stack.**

Oxide is a gigagas-capable, EVM-equivalent Layer 1 designed from first principles for
one purpose: **on-chain trading at centralized-exchange performance** — a fully
on-chain CLOB + perps venue where the order book *is* the blockchain, secured by
**oxideBFT** (a pipelined 2-chain HotStuff), with every subsystem engineered to
HFT standards (zero-allocation hot paths, sub-microsecond matching, ~50–100ms
blocks, sub-250ms full finality).

> **Status: pre-alpha / Phase 0.** Oxide is under active initial development.
> Nothing here is production-ready yet, APIs will change without notice, and no
> releases have been cut. Protocol specs are landing in `docs/` as each phase
> progresses; the roadmap table below tracks the current phase. **Do not run
> with real funds.**

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
| EVM throughput | 1–5 gigagas/s sustained (16–32 core validators) | Sei Giga 5 GG/s (devnet); reth+BAL experiments 10 GG/s ceiling |
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
                    │ core / bank /     │ parallel execution     │
                    │ staking /         │ (Block-STM-style OCC)  │
                    │ exchange / perps /│ native precompiles →   │
                    │ oracle / gov      │ trading core           │
                    └────────┬─────────┴───────────┬────────────┘
                             ▼   unified state      ▼
              RAM hot state (huge pages, NUMA-pinned)
              + StorageBackend [PORT: default = authenticated journal
                (MMR-over-log, group commit, io_uring)]
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
| `StorageBackend` | authenticated journal (MMR-over-log) | `Volatile` (in-memory), `Mdbx` / `RocksDb` / `Redb` (plain, followers) |
| `ColdStore` | MDBX (pending Phase 0 bench-off) | RocksDB, redb |
| `BroadcastEngine` | erasure-coded + f+1 availability votes | `PlainGossip` (tiny devnets), external DA (planned) |
| `Transport` | commonware-p2p (authenticated) | libp2p/QUIC adapter (planned) |
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
│   ├── p2p/             # Transport impl over commonware-p2p
│   ├── mempool/         # fee-priority pool, nonce queues, dedup
│   ├── storage/         # ★ journal + MMR-over-log + StorageBackend adapters
│   ├── state/           # in-memory authenticated state overlay
│   ├── executor/        # block executor: module router + parallel EVM scheduler
│   ├── trading/         # ★ matching engine, risk engine (HFT-grade)
│   ├── rpc/             # JSON-RPC + WebSocket (eth_* + oxide_*)
│   ├── node/            # node assembly: config-driven wiring of all ports
│   └── types/           # shared chain types (Tx, Header, QC, BlockRecord…)
├── modules/                   # Cosmos-SDK-style module framework + modules
│   ├── framework/  core/  bank/  staking/
│   ├── evm/        # revm host + native precompiles (the "x/vm" analog)
│   └── exchange/  perps/  oracle/  governance/
├── bin/                       # oxide-validator, oxide-fullnode, oxide-spammer,
│                              # oxide-deploy, oxide-bench
├── sim/                       # deterministic swarm simulations
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

- **Rust** 1.85+ (edition 2024) — <https://rustup.rs>
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

| Phase | Scope | Hard acceptance gates |
|---|---|---|
| **0 — Foundation** (now) | workspace, primitives, codec, runtime, ports/OAI, storage journal + MMR | journal ≥1M appends/s single-thread; MMR over 1M leaves <20ms; deterministic 4-node echo sim; mock engine drives app via OAI |
| **1 — Consensus + chain skeleton** | oxideBFT, broadcast, mempool, executor v0, core/bank/staking, devnet tooling | 50–100ms blocks; 200k tx/s sim (n=32); devnet runs on SequencerEngine via config swap with **zero app-code changes**; bit-exact journal replay |
| **2 — EVM + storage** | revm module, parallel OCC scheduler, JSON-RPC, adapters, snapshots | ≥1 GG/s on 16-core rig; MetaMask/Foundry/Blockscout green; storage conformance for every adapter |
| **3 — Trading core** | matching engine, risk, spot + perps, oracle, market data | ≥5M ops/s single-core; ≥1M orders/s chain-wide sim; p50 <200ns order ops; perps property tests (no negative equity, ADL correctness) |
| **4 — Hardening & testnet** | fuzz, chaos sims, TLA+ model, external review, 20–50 validator testnet | 7-day soak ≥50% load; zero safety violations in 10k randomized sims |

Post-testnet: mainnet + tokenomics, slashing, encrypted mempool, BAL access
lists, revmc JIT, DPDK/AF_XDP gateway lane, bridges, SVM/MoveVM modules.

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
  used as *libraries* where non-differentiating
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
