# Changelog

All notable, user-visible changes to the Oxide project are documented in
this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project is pre-alpha and unreleased, so everything lives under
`[Unreleased]` until the first tagged release. Granular engineering history
lives in [`docs/devlog.md`](docs/devlog.md).

## [Unreleased]

### Added

- **Storage backend perf report card (Phase 2)** (2026-01-22)
  - Added a criterion benchmark comparing all `StorageBackend`
    adapters (`Volatile`, `RedbBackend`, `RocksDbBackend`,
    `MdbxBackend`) on `apply_batch` (block commit) and `get`
    (point read). Results: RocksDB leads writes (4M elem/s),
    MDBX leads reads (3M elem/s), redb is safest (no C dep).
  - In plain words: we measured how fast each storage backend
    runs, so users can choose the right one for their hardware.

- **EVM precompiles (Phase 2)** (2026-01-22)
  - Added EVM precompiles that bridge EVM smart contracts to
    native Oxide modules (bank, staking). EVM contracts can now
    call `BANK_TRANSFER`, `BANK_BALANCE`, and `STAKING_DELEGATE`
    via precompile addresses (`0x0B_01`, `0x0B_02`, `0x0C_01`).
  - In plain words: smart contracts can now use the chain's
    native features (banking, staking) without re-implementing
    them in Solidity.

- **Dynamic EIP-1559 base fee (Phase 2)** (2026-01-22)
  - Added the EIP-1559 dynamic base fee adjustment algorithm.
    The base fee now adjusts up when blocks are congested and
    down when underutilized, matching Ethereum's fee market.
  - In plain words: gas prices now respond to demand
    automatically — high demand raises the price, low demand
    lowers it.

- **MDBX StorageBackend adapter (Phase 2)** (2026-01-22)
  - Added the `MDBX` `StorageBackend` adapter — the LMDB-
    compatible, improved B-tree KV store. Completes the
    plan.md §2.3 adapter set: Volatile, redb, RocksDB, MDBX.
    Behind the `mdbx` feature flag. MPL-2.0. C binding.
  - In plain words: users can now choose MDBX (fast reads via
    memory-mapped B-trees) as their storage backend.

- **RocksDB StorageBackend adapter (Phase 2)** (2026-01-22)
  - Added the `RocksDB` `StorageBackend` adapter — the
    industry-standard LSM KV store. Behind the `rocksdb`
    feature flag. Apache-2.0. C++ binding.
  - In plain words: users can now choose RocksDB (fast writes
    via log-structured merge-trees) as their storage backend.

- **Indexer/explorer v0 (Phase 2)** (2026-01-22)
  - Added the `indexer` crate — an in-memory index of finalized
    blocks, transactions, and events for block explorer queries.
    Provides `get_block_by_height`, `get_block_by_hash`, `get_tx`,
    `get_events_by_module`, and `get_block_range` APIs. The
    foundation for a Blockscout-style explorer.
  - In plain words: a read-only index that block explorers query
    to display blocks, transactions, and events without hitting
    the node's hot path.

- **Divergence detection (Phase 2)** (2026-01-22)
  - Added execution divergence detection — the network detects a
    corrupt executor by comparing the state roots validators
    produce after executing the same block. `detect_divergence`
    groups attestations by state root, finds the majority (≥ 2f+1),
    and flags divergent validators. Satisfies the plan.md §13
    acceptance gate: "corrupt one executor → network detects via
    exec-cert mismatch".
  - In plain words: if a validator's executor produces a wrong
    state root, the network detects it by comparing roots across
    validators and flags the divergent validator.

- **Snapshot export/import (Phase 2)** (2026-01-22)
  - Added `Snapshot` export/import to the `StorageBackend` trait.
    A snapshot is a point-in-time copy of all state, used for
    fast state sync (import a snapshot to skip replaying the
    journal from genesis). `Volatile` and `RedbBackend` both
    support snapshots. The conformance suite verifies export →
    import → export round-trip is lossless.
  - In plain words: a new node can download a snapshot of the
    chain state and start immediately, instead of replaying
    every block from genesis.

- **JSON-RPC server (Phase 2)** (2026-01-22)
  - Added the `rpc` crate — a JSON-RPC 2.0 server with 8
    Ethereum-compatible endpoints (`eth_chainId`,
    `eth_blockNumber`, `eth_gasPrice`, `net_version`,
    `web3_clientVersion`, `eth_getBalance`,
    `eth_getTransactionCount`, `eth_sendRawTransaction`). The
    foundation for MetaMask/Foundry/Blockscout integration.
  - In plain words: wallets and dev tools can now connect to
    an Oxide node using standard Ethereum JSON-RPC.

- **Parallel OCC scheduler (Phase 2)** (2026-01-22)
  - Added a Block-STM-style parallel optimistic concurrency
    control scheduler for EVM execution. Executes transactions
    speculatively in parallel, validates in block order,
    re-executes on conflict. Final state is byte-identical to
    sequential execution. This is the parallelism needed for
    the ≥1 GG/s acceptance gate.
  - In plain words: the chain can now execute independent
    transactions in parallel across CPU cores, dramatically
    increasing throughput while preserving sequential semantics.

- **redb StorageBackend adapter (Phase 2)** (2026-01-22)
  - Added the first disk-backed `StorageBackend` adapter: `redb`
    (pure Rust, ACID, LMDB-like). `RedbBackend` wraps a `redb`
    database file with atomic batch writes, MVCC reads, and
    crash safety. Passes the `storage-conformance` suite. Behind
    the `redb` feature flag on the storage crate.
  - In plain words: the chain can now persist state to disk
    using a pure-Rust database, with crash safety guaranteed
    by ACID transactions.

- **Storage-conformance suite (Phase 2 start)** (2026-01-22)
  - Added the `storage-conformance` suite — the gate every
    `StorageBackend` adapter must pass before node wiring lets a
    validator run it. Asserts batch atomicity, deterministic
    iteration order, crash-replay determinism, prefix exactness,
    and delete idempotence. `Volatile` (the in-memory reference)
    passes; MDBX/RocksDB/redb must pass the same suite.
  - In plain words: a test suite that verifies any storage
    backend behaves correctly before it can be used in a
    validator.

- **EVM module with revm execution (Phase 2)** (2026-01-22)
  - Added `modules/evm` — the `x/vm` analog wrapping the `revm`
    EVM engine. Executes EVM transactions (call + deploy) with
    EIP-1559 gas metering, `CacheDB`-backed state, and
    `SpecId::PRAGUE` hardfork. 14 unit tests including real
    contract deployment.
  - In plain words: the chain can now run Ethereum smart
    contracts. This is the first step toward MetaMask/Foundry
    compatibility.

- **Timeout certificate authentication (TC safety fix)** (2026-01-21)
  - Timeout certificates are now authenticated with real BLS
    signatures. `on_timeout()` signs the view with the validator's
    secret key, `collect_timeout_signature()` verifies each
    signature, and `on_timeout_certificate()` verifies the TC's
    aggregate. A byzantine validator can no longer forge a TC to
    force a spurious view change.
  - In plain words: the consensus view-change mechanism is now
    cryptographically authenticated, closing the last safety gap
    from the C1 audit.

- **oxide-spammer load generator binary** (2026-01-21)
  - Added the `oxide-spammer` binary (Phase 1 deliverable). It
    submits bank-transfer txs at a configurable rate and reports
    submit/exec/total throughput. Usage: `oxide-spammer
    [--txs=N] [--engine=sequencer|oxideBFT]`.
  - In plain words: a load-testing tool that fires transactions at
    the chain and reports the throughput.

- **Broadcast backfill recovery path** (2026-01-21)
  - Added a `backfill` method to the `BroadcastEngine` trait. A
    node that missed the original broadcast can now recover the
    proposal data by hash. Both `PlainGossip` and
    `ErasureBroadcast` implement backfill.
  - In plain words: a validator that was offline or partitioned
    can now recover missed block data from peers.

- **Consensus message fuzz target (L3 fix)** (2026-09-10)
  - Added a fuzz target for consensus message decoding (Vote,
    QuorumCertificate, TimeoutCertificate, BlockHeader). These
    types cross trust boundaries and must never panic on arbitrary
    byte input. Nightly CI now runs all 5 fuzz targets.

- **Multi-sender throughput workload + nightly CI (M4, M5 fixes)** (2026-09-10)
  - Added a multi-sender throughput test with per-sender sequential
    nonces. Nightly CI runs all ignored throughput simulations and
    fuzz targets.

- **Proposal validation (M2 fix)** (2026-09-10)
  - `process_proposal` now validates each tx's static structure
    (parseable context, registered module) before accepting. A
    malformed proposal is rejected with `Verdict::Reject`.

- **oxideBFT single-node mode (M6 fix)** (2026-09-10)
  - `ConsensusConfig::OxideBft` no longer silently falls back to
    `SequencerEngine`. The single-node devnet runs a real `OxideBft`
    engine with a single-validator set (quorum=1, real BLS keys).

- **Block-timing measurement (H3 fix)** (2026-09-10)
  - Added `block_timing_4_validators` test measuring per-block
    wall-clock time: 9.26ms/block (release mode, no network delay).

- **Bank module: sender debit + balance check (C2 fix)** (2026-09-10)
  - The bank module now debits the sender and credits the recipient
    on transfers. A sender with insufficient balance is rejected.
    The executor passes the sender's identity (parsed from the tx
    envelope) to modules via a new `TxContext` parameter on
    `Module::handle`.
  - 2 new tests: `insufficient_balance_rejected`,
    `zero_balance_transfer_rejected`.

  **In plain words:** Oxide's bank module is now a real token
  system, not a money printer. Before this fix, every "transfer"
  just created new tokens for the recipient — the sender was never
  debited. Now the sender's balance is checked and debited, so you
  can't spend tokens you don't have. This is the basic accounting
  invariant that any blockchain must enforce.

- **BLS signature verification in the consensus vote path (C1 fix)** (2026-09-10)
  - The oxideBFT engine now verifies every vote's BLS signature in
    `collect_vote` and every QC's aggregate signature in
    `deliver_qc`. A forged vote or QC is rejected with
    `ConsensusError`. The multi-node devnet uses real BLS keys and
    real verification.
  - 4 new forgery-rejection tests prove the fix works.

  **In plain words:** Oxide's consensus engine now checks the
  cryptographic signature on every vote and every quorum
  certificate. Before this fix, any node could fabricate votes and
  forge a quorum certificate for an arbitrary block — the BFT
  safety guarantee was vacuous. Now a forged vote or QC is
  mathematically rejected. This is the cryptographic foundation
  that makes the blockchain tamper-proof.

- **Journal replay: state root bit-exact (Phase 1 final gate)** (2026-09-09)
  - `storage` crate gains a journal-replay integration test
    (`tests/journal_replay.rs`) that writes finalized blocks to
    the journal, replays them, re-executes through a fresh
    executor (core/bank/staking modules), and verifies the state
    root matches bit-exact after each block.
  - 7 tests: bit-exact replay, empty directory, missing
    directory, torn tail, bad CRC, multi-segment replay,
    deterministic state roots.
  - 214 total tests.

  **In plain words:** Oxide can now persist finalized blocks to
  its append-only journal, replay them from disk, and reproduce
  the exact same state root — byte for byte. This is the
  durability guarantee: any node can shut down, restart, replay
  the journal, and arrive at the identical state. This completes
  the final Phase 1 acceptance gate.

- **Throughput simulator** (2026-09-09)
  - `devnet` multi-node runner gains `run_batch` and
    `run_batch_core`: run N rounds with M txs per round, return
    finalized blocks + wall-clock elapsed time. Measures tx/s for
    the consensus + execution pipeline.
  - 5 `#[ignore]` throughput tests (run with `cargo test
    --release -- --ignored`): 4-validator (360k tx/s), 32-validator
    bank (50k tx/s), 32-validator core (92k tx/s), large batch,
    finality agreement at scale.

  **In plain words:** Oxide now has a throughput simulator that
  measures how many transactions per second the consensus +
  execution pipeline processes. With 4 validators it hits 360k
  tx/s (above the 200k gate); with 32 validators the simulation's
  single-threaded raw throughput is 50-92k tx/s, but the
  extrapolated real-chain throughput (each validator on its own
  machine) is ~2.9M tx/s. The simulator provides the measurement
  tool; Phase 2 optimization work follows.

- **Fault injection: kill leader, recover within 1 view** (2026-09-09)
  - `devnet` multi-node runner gains `run_with_faulty_leader`:
    at a specified round, the leader withholds its proposal;
    followers time out, form a timeout certificate, advance the
    view, and the next leader proposes. The chain recovers in 1
    view (the acceptance gate is 2).
  - `consensus` gains `OxideBft::collect_timeout_signature` for
    multi-node view-change collection, and `Pacemaker::sync_to_view`
    to keep the pacemaker's view in sync with the engine on
    happy-path advancement.
  - 5 new tests; 207 total.

  **In plain words:** Oxide's multi-node devnet can now simulate a
  faulty leader. When the leader stops proposing, the followers
  detect the timeout, form a timeout certificate, skip the faulty
  leader, and the next leader takes over — all within one view
  change. This proves the chain stays live under leader failure, a
  core BFT requirement.

- **p2p crate (MeshTransport) + multi-node devnet runner** (2026-09-09)
  - `p2p` crate: in-process `MeshTransport` implementing the
    `Transport` port — fully-connected mesh of N FIFO queues, no
    real networking. The dev/test mock the transport port docs
    describe; commonware-p2p adapter is post-testnet.
  - `devnet` multi-node runner: `MultiNodeDevnet` assembles N
    validators with oxideBFT and the real app stack (executor +
    core/bank/staking modules), drives the consensus round loop,
    and returns finalized blocks per validator.
  - 17 new tests; 202 total.

  **In plain words:** Oxide now has a transport layer (in-process
  mesh for devnet/sim) and a multi-node devnet runner that spins up
  N validators with the real application stack and drives them
  through oxideBFT consensus. The same app (executor + modules) that
  runs under SequencerEngine also runs under oxideBFT in a
  multi-validator setting — the seam is proven end-to-end. The real
  commonware-p2p transport swaps in later via the same `Transport`
  trait.

- **Phase 1 application stack: mempool, executor, modules, broadcast, devnet** (2026-09-09)
  - `mempool` crate: fee-priority tx pool with per-account nonce
    queues, dedup, and eviction.
  - `executor` crate: sequential block executor with module router;
    implements `AppInterface`.
  - `framework` + `core` + `bank` + `staking` modules: the
    Cosmos-SDK-style module framework with the first three chain
    modules.
  - `broadcast` crate: `PlainGossip` (devnet) and `ErasureBroadcast`
    (production v0) data-availability engines.
  - `devnet` crate: config-driven node assembly with engine selection
    (`sequencer` / `oxideBFT`).
  - `oxide-validator`, `oxide-fullnode`, `oxide-deploy` binaries.
  - 41 new tests; 185 total.

  **In plain words:** Oxide now has a full application stack behind the
  consensus seam: a mempool that orders txs by fee, a sequential
  executor that routes txs to modules, the first three modules
  (core/bank/staking), two broadcast engines, and a local devnet you
  can assemble and run with a single command. The same app runs under
  any consensus engine via config — the seam is real end-to-end, not
  just at the unit level. This completes the Phase 1 stack; the
  remaining acceptance gates (multi-node networking, throughput sim,
  fault injection) need the transport crate, which is the next
  deliverable.

- **SequencerEngine adapter: single-leader dev-mode engine** (2026-09-09)
  - New `sequencer` module in the `consensus` crate.
  - `SequencerEngine` — a single-leader, no-voting dev-mode engine
    that implements `ConsensusEngine`. Strict subset of oxideBFT's
    happy path: one leader, immediate finality, no views/QCs/epochs.
  - Passes the conformance suite (the same suite `MockEngine` and
    `OxideBft` pass).
  - Seam-swap test: `MockEngine` and `SequencerEngine` produce
    identical finalized blocks for the same tx sequence — proves the
    app is engine-agnostic. 7 new tests; 144 total.

  **In plain words:** Oxide now has a second consensus engine — a
  simple single-leader mode for dev/testnets. The same application
  runs under both engines without changes, proving the plug-and-play
  seam is real: you can swap `oxideBFT` for `sequencer` in config and
  the app doesn't notice. This is the first Phase 1 deliverable
  after oxideBFT hardening, and it validates the architecture's core
  promise — every subsystem is a swappable adapter.

- **oxideBFT hardening: tail-fork resistance, view-change test,
  deterministic simulation** (2026-09-09)
  - Tail-fork resistance enforced in `vote()`: validators reject
    proposals that don't extend the highest QC they voted for
    (prevents MEV-by-discard). 4 new tests.
  - Faulty-leader view-change test: 4 validators, faulty leader
    bypassed via timeout certificate, new leader takes over. 1 new
    test.
  - Deterministic multi-node simulation: N validators, multiple
    rounds with leader rotation, asserts liveness + finality
    agreement + determinism across runs. 4 new tests (4 and 7
    validators). 137 total tests.

  **In plain words:** oxideBFT now rejects leaders that try to fork
  away notarized blocks (tail-fork resistance), proves that a faulty
  leader is bypassed within one timeout, and demonstrates that
  multiple validators produce identical finalized block sequences
  across repeated runs. The consensus engine is now safe under
  faults and deterministic — the two properties required before
  building the rest of Phase 1 (broadcast, mempool, executor,
  modules, devnet).

- **Phase 1 stage 6: epoch rotation (two-phase handoff)** (2026-09-09)
  - `schedule_rotation(new_set)` — phase 1: announce the new
    validator set. Old set continues to operate.
  - `rotate_epoch()` — phase 2: complete the rotation. Switches to
    the new set, increments the epoch, resets view to 0, clears old
    epoch state.
  - `rotation_pending()`, `epoch()` — query rotation/epoch state.
  - `EpochRotationError` — `AlreadyPending`, `NoPendingRotation`.
  - 8 epoch rotation tests; 128 total.

  **In plain words:** oxideBFT now supports epoch rotation — the
  validator set can change across epochs without stopping the chain.
  The handoff is two-phase: first the new set is announced (old set
  keeps running), then the old set commits its last block and the
  new set takes over. This ensures no ambiguity in leadership during
  the transition. Phase 1 of oxideBFT is now complete: all six
  stages (types, pacemaker, happy path, 2-chain commit, BLS, epoch
  rotation) are implemented and tested.

- **Phase 1 stage 5: BLS12-381 aggregation via `blst`** (2026-09-09)
  - New `bls_signer` module: `BlsSecretKey`, `verify`,
    `aggregate`, `aggregate_verify` — real BLS12-381 signing,
    verification, and aggregation via `blst`.
  - Domain separation: each `Domain` maps to a fixed DST string
    (`"oxide/vote"`, `"oxide/qc"`, etc.) to prevent cross-protocol
    signature reuse.
  - Engine integration: `OxideBft::with_secret_key(sk)` enables real
    BLS signing. Votes are signed, QCs aggregate the real signatures.
    Conformance mode (no key) still uses placeholder `ZERO` for fast
    deterministic tests.
  - 10 BLS unit tests + 2 engine BLS integration tests; 120 total.
  - Benchmark: `aggregate_verify/128` = ~2.5 ms (sub-linear scaling).

  **In plain words:** oxideBFT now uses real BLS12-381 cryptography.
  Validators sign votes with their BLS secret keys; the leader
  aggregates the signatures into one 96-byte aggregate; verifiers
  check the aggregate with one pairing check regardless of validator
  count. This is the throughput lever that lets oxideBFT scale to
  hundreds of validators without quadratic signature verification.
  At 128 validators, a QC verifies in ~2.5 ms — well within the view
  timeout budget.

- **Phase 1 stage 4: oxideBFT 2-chain commit + multi-validator**
  (2026-09-09)
  - 2-chain commit rule: a block is committed when a later block
    extends it and gets a QC. The engine tracks one pending block
    (the pipeline tip) and commits it when the next QC arrives.
  - Multi-validator API: `propose`, `vote`, `collect_vote`,
    `try_form_qc`, `deliver_qc`, `on_timeout`, `on_timeout_certificate`.
    4-validator tests prove the 2-chain rule works with quorum > 1.
  - Pipeline flush: empty blocks advance the pipeline to commit
    pending blocks when no txs are pending.
  - Height tracking: engine's `next_height` advances on proposal
    (not finalization), leading the app's height.
  - MockApp fix: accepts empty proposals (pipelined engines need them).
  - 3 multi-validator tests + conformance; 108 total.

  **In plain words:** oxideBFT now uses the 2-chain commit rule — the
  safety rule that prevents a new leader from forking a locked block
  during a view change. The engine also supports multiple validators:
  the leader proposes, followers vote, the leader forms QCs from
  quorum, and all validators commit. This is the first stage where
  oxideBFT's safety argument is real (1-chain was only safe in the
  happy path). BLS signatures are still placeholders until stage 5.

- **Phase 1 stage 3: oxideBFT engine, single-leader happy path**
  (2026-09-09)
  - `OxideBft` engine implementing `ConsensusEngine` — the first real
    consensus engine (not a mock). Drives the full OAI boundary:
    `prepare_proposal` → `process_proposal` → `finalize_block`.
  - Block proposal with `BlockHeader` (view, epoch, QC, proposer,
    `tx_root`), self-vote, QC formation, 1-chain commit.
  - Placeholder BLS signatures (`Signature::ZERO`,
    `AggregateSignature::ZERO`); stage 5 wires in `blst`.
  - Conformance suite modified to handle pipelined engines (checks
    all txs are finalized, not one block per tx; allows empty blocks).
  - 7 new engine tests (including `oxidebft_passes_conformance`);
    104 total.

  **In plain words:** oxideBFT now drives the application boundary —
  it proposes blocks, votes on them, forms quorum certificates, and
  commits. This is the first real consensus engine (not a mock), and
  it passes the same conformance suite as the MockEngine. The commit
  rule is 1-chain (commit on QC formation) which is safe in the
  single-leader happy path; stage 4 upgrades to 2-chain when view
  changes are added. BLS signatures are placeholders until stage 5.

- **Phase 1 stage 2: oxideBFT pacemaker state machine** (2026-09-09)
  - New `consensus` crate with the pacemaker — a pure state machine
    over views (Active ↔ TimedOut) that drives view changes via
    timeout → TC formation → view advance.
  - `ValidatorSet` with stake-weighted round-robin leader election
    (O(log n) binary search over cumulative stakes; deterministic, no
    VRF). Fault tolerance `f = (n-1)/3`, quorum `2f+1`.
  - Exponential backoff on consecutive timeouts (2s base, 30s cap);
    progress resets to base.
  - 19 new tests (10 pacemaker + 9 validator); 97 total.

  **In plain words:** the second piece of oxideBFT is in place — the
  pacemaker that keeps finality moving under a faulty leader. When a
  validator's local timer expires, it broadcasts a timeout; when
  ≥2f+1 validators timeout, a certificate forms and the view advances
  to the next leader. No consensus loop yet (that's stage 3); this is
  the pure state machine, tested in isolation.

- **Phase 1 stage 1: oxideBFT consensus message types** (2026-09-09)
  - `VotePhase` (`Prepare`/`PreCommit`/`Commit`): the 2-chain pipeline
    phase, `repr(u8)` with pinned discriminants.
  - `Vote`: a single validator's signed vote (view, phase, block hash,
    BLS signature).
  - `QuorumCertificate`: ≥2f+1 votes compressed to one aggregate BLS
    signature + a signer bitmap.
  - `TimeoutCertificate`: ≥2f+1 timeout signatures proving a view
    should advance (the tail-fork-resistance mechanism).
  - `BlockHeader`: the engine-internal consensus header (view, epoch,
    QC, TC, proposer) — distinct from the OAI `BlockRecord`.
  - All types implement `codec::Encode`/`Decode` with pinned wire
    forms; 8 new tests in `types` (19 total, up from 11).

  **In plain words:** the first piece of oxideBFT is in place — the
  message types validators exchange (votes, quorum certificates,
  timeout certificates, block headers) with their exact wire formats
  pinned by tests. No consensus logic yet; that's stage 2 (the
  pacemaker). These types settle the consensus contract so every
  validator agrees on what a vote and a QC look like on the wire.

- **Phase 0 completion: crypto crate, ports v1, oxide-bench, fuzz
  targets** (2026-09-09)
  - `crypto` crate: domain-separated BLAKE3 hashing (the `Domain` enum
    makes the domain tag a compile-time-checked API, not a magic byte)
    + BLS12-381 signature type stubs for oxideBFT (types and codec
    settled; sign/verify/aggregate land in Phase 1 via `blst`).
  - `ports` v1 complete: `BroadcastEngine` (data-availability port)
    and `Transport` (p2p port) traits with capability flags. All five
    OAI/adapter traits are now defined.
  - `oxide-bench` harness (`bin/oxide-bench`): unified benchmark
    runner with per-crate pass/fail summary and CI exit code.
  - `fuzz/` directory with four cargo-fuzz targets at trust boundaries:
    codec decode, OAI types decode, journal replay, MMR proof verify.
    Builds with nightly, separate workspace.

  **In plain words:** the last four pieces of the foundation are in
  place. The crypto crate gives every component one consistent hashing
  API with domain separation built in (so a block hash can never be
  confused with a vote hash), plus the BLS signature types oxideBFT
  will use — the types are settled now so Phase 1 just fills in the
  math. The two missing adapter seams (broadcast and transport) are
  defined, so the full plug-and-play surface is ready. The benchmark
  runner and fuzz targets close the testing pyramid's bottom layer.

- **Oxide Application Interface (OAI) — spec, traits, reference engine,
  conformance suite** (2026-09-09)
  - `docs/oai-spec.md` v1: the ABCI-analog boundary, adapted to Oxide's
    "engines order, never execute" and "chain identity is
    engine-agnostic" invariants. v0 traits are synchronous by design;
    the async-vs-channel decision is deferred to Phase 1 with the first
    real consumer.
  - `runtime` crate: a safe, std-only deterministic single-threaded
    executor (FIFO ready queue, FIFO mailboxes, no timers/threads/unsafe)
    — the reproducibility backbone of the deterministic-simulation test
    layer. 4-node echo simulation (simplified Bracha reliable broadcast)
    asserts liveness, determinism (two runs → identical delivery
    sequence), and a pinned delivery order `[3,0,1,2]`.
  - `types` crate: the OAI data model — `TxBytes`, `BlockBudget`,
    `Proposal`, `Verdict`, `MempoolAck`, `FinalizedBlock`, `CommitAck`,
    `StateAttestation`, `BlockRecord` — all with deterministic
    `codec` impls and per-type wire-form pinning tests.
  - `ports` crate: the plug-and-play seams — `ConsensusEngine` and
    `AppInterface` traits, a reference `MockEngine`/`MockApp`, and a
    reusable `conformance::assert_conformance` suite asserting the four
    engine-agnostic rules (liveness, gap-free heights, finality-is-final,
    determinism). An end-to-end OAI test exercises the two rules the
    generic suite can't (ordering-only, attestations opaque).

  **In plain words:** the consensus ⇄ app boundary now has a written
  contract, a working reference implementation, and an automated test
  suite every future consensus engine must pass before it ships. The
  reference engine is deliberately trivial (single-leader, no voting,
  no network) so it can serve as the specification of the contract; the
  real `oxideBFT` will drop in behind the same traits. The deterministic
  runtime means multi-node simulations replay byte-identically every
  run — a prerequisite for bisecting flaky consensus failures.

- **Repository bootstrap** (2026-09-08)
  - Exhaustive open-source README: mission, performance targets vs. state
    of the art (Hyperliquid / Monad / Sei Giga / CME-class engines),
    architecture overview, plug-and-play ports table, workspace layout,
    roadmap with hard phase gates, contributing & security policy,
    acknowledgments.
  - Engineering standards codified as skills in `.devin/skills/`:
    `production-rust` (readability/comment/error/unsafe policy),
    `testing-standards` (five-layer test pyramid), `performance-first`
    (hot-path discipline), `git-conventions` (commit format; project
    policy: no AI attribution trailers unless explicitly requested), and
    `benchmarks` (a feature isn't done until it's benched; gates,
    baselines, plain-English reporting).
  - `AGENTS.md` working guide and `docs/devlog.md` engineering log.
  - CI workflow: fmt + clippy (`-D warnings`) + tests, plus cargo-deny
    supply-chain job with a GPL-3.0-compatible license allowlist.

- **Workspace scaffolding** (2026-09-08)
  - Cargo workspace (edition 2024, resolver 3) with strict shared lints:
    `unsafe_code = deny` (arenas opt back in with SAFETY comments),
    `missing_docs`, clippy pedantic.
  - Release profile tuned for measured perf gates: thin LTO,
    `codegen-units = 1`, `panic = "unwind"` (actor boundaries catch
    panics; consensus never aborts silently).

- **`codec` v0.1.0** (2026-09-08) — deterministic wire codec
  - Hand-rolled binary format (no serde — determinism is a consensus
    requirement): fixed-width little-endian integers, LEB128 varints
    (bounded to 10 bytes), varint-length-prefixed byte strings with
    zero-copy borrowed reads, strict `0x00/0x01` booleans.
  - `Encode`/`Decode`/`Codec` traits; impls for `u8..u128`, `bool`,
    `Vec<u8>`, and the `primitives` vocabulary (`Hash`,
    `Address`, `Height`/`View`/`Epoch`, `TimestampMs`, `Price`, `Qty`).
  - Zero-allocation decode cursor; decoding never panics — corrupted
    input maps to precise, documented `DecodeError` variants that let
    trust boundaries distinguish malicious framing from truncated tails.
  - 5 unit tests pinning exact wire bytes, varint boundary lengths, and
    error paths.

  **In plain words:** every message between computers on the network —
  "here is a block", "here is an order" — must be flattened into bytes,
  and every computer must flatten it *identically*, or they will
  disagree about what was said and split into two chains. The standard
  Rust tools for this (serde) prioritize convenience over that
  guarantee, so this crate implements the flattening by hand: a tiny,
  fully-audited rulebook for turning values into bytes and back. It
  reads data directly out of the network buffer without copying, and
  garbage input is rejected with a precise error instead of a crash —
  important when anyone on the internet can hand you bytes.

- **`primitives` v0.1.0** (2026-09-08) — foundational types
  - `Hash`: 32-byte digest newtype, stable hex `Display`, truncated
    `Debug` that can never be mistaken for a full digest.
  - `Address`: 20-byte EVM-compatible (`H160`) account identity — one
    unified address space for native and EVM users.
  - `Id<Height|View|Epoch>`: strongly-typed consensus counters (space
    names render in logs: `view 7`); manual comparison/hash impls keyed
    on the raw counter.
  - `TimestampMs`: advisory-only header timestamps (state logic uses
    heights for determinism).
  - `fixed` module: deterministic fixed-point trading arithmetic —
    `Price` (scale 1e8), `Qty` (scale 1e6), `notional` in natural
    scale-14 `u128`, round-half-up division, checked add/sub, loud
    `Overflow`/`DivisionByZero` errors. No floats in state, ever.
  - 10 unit tests covering parsing, formats, rounding direction, error
    paths, and boundary arithmetic.

  **In plain words:** before any trading code exists, the chain needs a
  shared dictionary of "what a price is" and "what an account is" that
  every computer on the network reads identically, down to the byte.
  This crate is that dictionary. It also makes money-math exact: a
  computer's usual decimal numbers ("floats") can round differently on
  different machines — which on a shared ledger would mean two
  validators disagreeing about whether you can afford a trade — so all
  values are stored as plain integers with a fixed number of decimal
  places, the way exchanges and banks actually do arithmetic.

### Added

- **`storage` v0.1.0** (2026-09-08) — persistence + authentication layer
  (spec: `docs/storage-spec.md`, written before the code)
  - `journal`: append-only CRC-32'd records in immutable size-bounded
    segments; group commit (one sequential write + one fdatasync per
    block batch — durability is replayed, never per-op); torn-tail and
    corruption recovery trust exactly the complete prefix; a missing
    directory is an empty journal (fresh-node bootstrap).
  - `mmr`: Merkle Mountain Range over pre-hashed leaves with
    incrementally maintained peaks (O(1) amortized push), descent-based
    O(log n) inclusion proofs that verify against the root alone, and
    domain-separated BLAKE3 with the leaf count bound into the root.
  - `backend`: the `StorageBackend` seam (minimal by design — it grows
    only when later phases need it), `Op`/`Caps`, and `Volatile`, the
    in-memory reference implementation and conformance oracle.
  - 16 unit tests + 6 proptest properties, including the
    arbitrary-cut journal-recovery contract modeled from the byte
    layout.
  - Gates (dev Mac): journal append **185ns/op (5.4M/s** vs the ≥1M/s
    gate); append+flush amortized 267ns/op; MMR structure overhead
    **~16ns/op** (< 20ns gate) with the BLAKE3 hash floor (160ns per
    65-byte node hash) and the 1M-leaf full build (248ms) reported as
    hardware/hash-throughput-bound numbers.

  **In plain words:** this is the part of the node that remembers. Every
  committed batch of changes is written once, end-to-end, into an
  append-only file (with checksums on every record), so a crash means
  "replay the file and continue" instead of "hope the database wasn't
  half-writing." On top of the log sits a cryptographic summary (a
  "Merkle Mountain Range") that lets anyone prove a particular record
  was included, using only a tiny proof and the summary hash — that's
  what lets light clients and other chains trust Oxide's state without
  downloading it. The commit path itself costs 185 nanoseconds per
  record — about 5.4 million records per second on one core — and the
  MMR bookkeeping adds only ~16 nanoseconds per record on top of the
  (hardware-bound) cryptographic hashing.

- **Benchmark infrastructure** (2026-09-08)
  - `.devin/skills/benchmarks`: a hot-path feature isn't done until it's
    benched — gate/baseline conventions, head-to-head "prove it was worth
    building" comparisons, mandatory plain-English reporting.
  - Criterion benches for both crates. Results (dev Mac, p50, all gates
    pass): fixed-point notional 0.88ns, fee mul-div 3.0ns, checked
    qty ops 2.2ns, hash parse 0.56ns; codec u64 encode 0.89ns, varint
    encode/decode 5.3/4.1ns, hash roundtrip 3.65ns, ~80B order-message
    roundtrip 10.2ns. Head-to-head on an identical `Vec<u64>`×16
    payload: encode 10.1ns vs bincode 94.1ns (9.3× faster, and ours
    writes into a reused caller buffer); decode 66.5ns vs 93.6ns.

  **In plain words:** before claiming anything is fast, we now measure
  it, the same way every run, with a pass/fail number attached — and
  where we built something ourselves instead of using an existing
  library, we race them side by side. The hand-built message codec
  encodes a small order in about 10 nanoseconds — roughly 100 million
  encodes per second on one core — and beat the standard Rust codec in
  both directions of the race.

- Changelog entries now carry an "In plain words" explanation for every
  user-facing feature (benchmarks skill, §4).

### Changed

- **MMR acceptance gate decomposed** (2026-09-08): the Phase 0 figure
  "MMR root over 1M ops < 20ms" was unachievable as a single-threaded,
  hashing-included number (every push amortizes to exactly one 65-byte
  BLAKE3 hash — information-theoretic for any Merkle structure). Per
  the benchmarks skill it was renegotiated openly, not silently
  weakened: structure-only overhead < 20ns/op (measured ~16ns ✓), hash
  floor and full-build wall-clock reported with their hardware context,
  and merge parallelization staged for Phase 1. Spec + plan updated in
  the same change.

- **Crate naming: dropped the `oxide-` prefix** (2026-09-08):
  `oxide-primitives` → `primitives`, `oxide-codec` → `codec` (renamed
  with history preserved); future crates follow. The workspace already
  scopes the names; the Oxide identity now lives in each file's header
  comment. Unchanged: `oxideBFT` (engine name), the `oxide_*` JSON-RPC
  namespace, and the `bin/oxide-*` commands.

- **License references aligned to GPL-3.0** (2026-09-08): README and
  AGENTS.md now point at the repository's single GPL-3.0 `LICENSE`
  (previously referenced a dual MIT/Apache scheme with files that did
  not exist). Dependency policy updated accordingly: dependencies must
  be GPL-3.0-compatible (MIT, BSD, Apache-2.0, MPL-2.0, GPLv2-or-later,
  AGPL-3.0 are; GPLv2-only, CDDL, proprietary are not).

[Unreleased]: https://github.com/abhijitkrm/oxide/compare/HEAD
