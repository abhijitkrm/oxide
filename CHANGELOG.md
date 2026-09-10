# Changelog

All notable, user-visible changes to the Oxide project are documented in
this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project is pre-alpha and unreleased, so everything lives under
`[Unreleased]` until the first tagged release. Granular engineering history
lives in [`docs/devlog.md`](docs/devlog.md).

## [Unreleased]

### Added

- **Layered configuration system (TOML + env vars + CLI flags)** (2026-01-25)
  - New `config` crate provides a layered config system matching the
    geth/reth model: TOML file as base, env var overrides, CLI flag
    overrides (highest priority). No more recompiling to change a
    timeout or mempool size.
  - **In plain words:** you can now run `oxide-validator --config
    config/devnet.toml` instead of recompiling with different
    hardcoded constants. Env vars (`OXIDE_NETWORK_LISTEN_ADDR`,
    `OXIDE_CONSENSUS_BASE_TIMEOUT_MS`, etc.) override the TOML file,
    and CLI flags (`--engine oxideBFT`) override everything. This
    enables Docker/K8s deployments without mounting config files.
  - Example config files: `config/devnet.toml`, `config/testnet.toml`,
    `config/mainnet.toml`.
  - All previously hardcoded `const` values are now configurable:
    TCP timeouts (5s/30s), max message size (16 MiB), pacemaker
    timeouts (2s/30s), parallel threshold (100), genesis balance,
    base port, mempool size.
  - New `with_config` constructors on `TcpTransport`, `Executor`,
    `Pacemaker`, and `TcpMultiNodeDevnet`. Original constructors
    delegate with defaults.
  - `oxide-validator` and `oxide-fullnode` binaries load config from
    `--config path.toml`, apply env vars, then `--engine` CLI flag.
  - 9 new tests: 7 config crate tests, 1 TCP transport config test,
    1 devnet `from_config` test.

- **Preverified sender pipeline + TCP transport + multi-node devnet** (2026-01-25)
  - The preverified sender path is now wired through the full pipeline:
    `ingest_tx` pre-recovers senders at mempool ingestion time, caches
    them, and `execute_block` uses `handle_batch_preverified` (or
    `handle_batch_parallel_preverified` for batches ≥ 100 txs) to skip
    secp256k1 recovery on the execution hot path.
  - **In plain words:** when you submit an EVM transaction, the
    sender's signature is recovered once at submission time and cached.
    When the block is executed, the cached sender is reused — no
    signature recovery happens during execution. This brings the 14x
    speedup from the pre-verified work into the actual pipeline. For
    large blocks (≥ 100 txs), the executor uses the parallel
    speculative path (rayon) for even higher throughput.
  - Real TCP transport (`p2p::tcp::TcpTransport`) replaces the
    in-process mesh for multi-node devnet operation. Length-prefixed
    framing, thread-per-peer I/O, and a background accept thread.
  - TCP-based multi-node devnet runner (`devnet::tcp_multinode`)
    validates that oxideBFT consensus works over real TCP connections.
  - New `Module` trait methods: `preverify_batch`,
    `handle_batch_preverified`, `handle_batch_parallel_preverified`.
  - New `PreverifiedTx` struct in the executor crate (module-agnostic).
  - 10 new tests: 6 TCP transport tests, 4 TCP multi-node devnet tests.

- **EVM pipeline wired to executor and mempool** (2026-01-25)
  - The EVM module is now connected to the executor/mempool/consensus
    pipeline. Signed EVM transactions can be submitted through the
    mempool, proposed in a block, finalized by consensus, and executed
    by the EVM module — producing a state root end-to-end.
  - **In plain words:** the blockchain pipeline now works end-to-end
    for EVM transactions. You can submit a signed Ethereum transaction,
    and it flows through the mempool → block proposal → consensus
    finalization → EVM execution → state root. Previously the pieces
    existed but were never connected.
  - New `handle_batch` method on the `Module` trait lets modules with
    batch-optimized paths (like EVM's parallel sender recovery) amortize
    per-tx overhead across the whole block.
  - New `wrap_evm_tx_envelope` helper wraps RLP-encoded signed EVM
    transactions in the mempool's v0 envelope format.
  - 3 integration tests prove the pipeline works: executor pipeline,
    SequencerEngine pipeline, and state root differs from empty block.

- **Pre-verified sender recovery** (2026-01-25)
  - New `PreverifiedTx` struct and `preverify_batch` helper allow the
    mempool to pre-recover transaction senders once at ingestion time.
    Block execution then skips secp256k1 recovery entirely via
    `handle_batch_preverified` and `handle_batch_parallel_preverified`.
  - **In plain words:** signature verification (the slowest step in
    transaction processing) now happens once when a transaction enters
    the mempool, not again when it's executed in a block. This makes
    block execution ~14x faster for simple transfers — from ~70k tx/s
    to ~2M tx/s on an 8-core machine.
  - Security: the caller must ensure senders are correctly recovered.
    A byzantine block proposer providing wrong senders causes state
    divergence, detectable by state root comparison. For the Phase 0
    devnet (single validator), trusting the proposer is safe.
    Verification sampling for production is future work.
  - State roots are identical between pre-verified and recovery paths
    (verified by `preverified_matches_recovery_state_root` and
    `preverified_parallel_matches_recovery_parallel_state_root` tests).
  - New benchmarks: `preverified_vs_recovery` and
    `preverified_parallel_vs_recovery` — head-to-head comparisons
    showing ~14x and ~12x speedup respectively for 10k simple transfers.

- **Native fast path for simple ETH transfers** (2026-01-25)
  - Simple ETH transfers (empty calldata, EOA recipient) now bypass
    revm entirely — balance and nonce updates are executed directly
    on the `CacheDB` without EVM interpreter overhead.
  - **In plain words:** sending ETH to a regular wallet address is
    now ~4x faster because the EVM virtual machine is skipped —
    just a direct balance update, like a database write.
  - Qualification: `to` is a Call (not Create), empty calldata, no
    access list, recipient has no code, sufficient balance and gas.
    Non-qualifying txs (contract calls, creations, calldata) fall
    through to revm with identical semantics.
  - Integrated into `handle_batch`, `handle_batch_parallel`, and
    conflict re-execution paths.
  - State roots are identical between native and revm paths
    (verified by `native_transfer_matches_revm_state_root` and
    `native_transfer_multi_tx_matches_revm` tests).
  - New benchmark: `native_vs_revm` — head-to-head comparison of
    native vs revm for 1k and 10k simple transfers.
  - Bug fix: `code_hash` normalization (`B256::ZERO` →
    `KECCAK_EMPTY`) to match revm's account normalization behavior.

- **Speculative parallel EVM execution** (2026-01-25)
  - **`EvmModule::handle_batch_parallel`**: new batch execution
    path that parallelizes EVM execution across sender groups.
    Transactions from different senders execute in parallel on
    copy-on-write nested caches (`SharedCacheDB`); same-sender
    txs execute sequentially (nonce dependency). Conflict
    detection via actual touched-account sets from nested cache
    state (not heuristic). Conflicting groups are re-executed
    sequentially against the main DB. Coinbase tips are handled
    additively to avoid false conflicts. Single-sender batches
    fall back to `handle_batch` to avoid overhead.
  - **Optimizations**: `transact_commit` with direct `DbAccount`
    merge (no per-tx `EvmState` clone), pre-loading of hot
    accounts (sender, coinbase, recipient) into nested cache,
    EVM context reuse within each group (parallel + conflict
    re-execution paths).
  - **9 correctness tests**: serial/speculative state-root
    equality for conflict-free, conflict, multi-nonce,
    single-sender, empty, invalid-tx, and determinism cases.
  - **3 benchmarks**: `batch_parallel_multi_sender` (conflict-free
    100-sender workload), `batch_parallel_conflict` (same-recipient
    conflict workload), comparison against existing `batch_parallel`
    serial baseline.
  - **In plain words**: the EVM can now execute transactions from
    different senders in parallel, with automatic fallback to
    sequential execution when transactions conflict. Uses
    copy-on-write nested caches (`SharedCacheDB`) so each worker
    only pays O(touched) instead of O(state). EVM context is
    reused within each group, and hot accounts are pre-loaded.
    Measured at 128k TPS for 100-sender conflict-free workloads
    (parity with single-sender serial) and 114k TPS for
    conflict-heavy workloads (13% slower than serial).

- **Phase B: Ethereum-compatible MPT state root** (2026-01-24)
  - **B1 — Trie integration**: added `modules/evm/src/trie.rs`
    wrapping `alloy-trie` (0.9.5). Provides `state_root()`,
    `storage_root()`, `build_trie_account()`, and the
    `EMPTY_ROOT` / `KECCAK_EMPTY` constants. The state trie is
    keyed by `keccak256(address)` with RLP-encoded
    `TrieAccount { nonce, balance, storage_root, code_hash }`
    values. 10 new trie unit tests.
  - **B2 — Replace module state root**: `EvmModule::state_root()`
    now computes the Ethereum-compatible MPT root over all
    CacheDB accounts, including per-account storage tries. This
    replaces the Phase 2 sorted-account BLAKE3 hash. The new root
    matches Ethereum mainnet and reth for identical state. New
    test: `empty_state_root_matches_ethereum_constant` verifies
    the empty state produces `0x56e81f17...`.
  - **Dependencies**: `alloy-trie = "0.9.5"` (ethereum feature),
    `alloy-primitives = "1.0"` — both MIT/Apache-2.0, same alloy
    ecosystem as revm.
  - **Benchmark**: `modules/evm/benches/trie_root.rs` — full MPT
    rebuild baseline: 1k accounts = 620 µs, 10k = 6.3 ms, 100k =
    65 ms. Shows the O(N) scaling that motivates B3 (incremental
    updates via ProofRetainer, deferred).
  - **In plain words**: the EVM module's state root is now a
    proper Ethereum Merkle-Patricia Trie root, computed with
    keccak-256 — the same algorithm Ethereum mainnet and reth use.
    For identical account state, Oxide now produces the same
    state root as Ethereum. The empty state produces Ethereum's
    well-known empty root constant `0x56e81f17...`. The full
    rebuild is correct but O(N) in the number of accounts;
    incremental updates (B3) will make it O(touched) in a follow-up.

- **Phase G: native module authenticity — Ed25519 signatures** (2026-01-25)
  - Added `crates/crypto/src/ed25519.rs` with Ed25519 key
    generation, signing, and verification via `ed25519-dalek`
    3.0.0 (BSD-3-Clause). Provides `Ed25519PublicKey`,
    `Ed25519SecretKey`, `Ed25519Signature`, `sign_message`,
    `verify_message`, `derive_public`, and `Ed25519Error`.
  - 8 new unit tests (sign/verify roundtrip, wrong message, wrong
    key, deterministic, empty message, large message, different
    keypairs, derive public). 42 crypto tests total.
  - **In plain words**: native (non-EVM) modules can now use
    Ed25519 signatures for transaction authentication. Ed25519
    is faster, has no malleability, and has smaller keys than
    secp256k1 ECDSA. This is the signature scheme for bank,
    staking, and trading modules.

- **Phase F: EVM conformance tests** (2026-01-25)
  - Added `modules/evm/tests/conformance.rs` with 9 hand-crafted
    conformance tests verifying Ethereum properties: empty state
    root, simple transfer, nonce progression, stale nonce
    rejection, contract creation, state root determinism, wrong
    chain ID rejection, multiple transfer accounting, empty block
    preservation.
  - **In plain words**: the EVM now has a conformance test suite
    that verifies it matches Ethereum's specification for core
    properties. Full BlockchainTests integration is deferred.

- **Phase E: RPC completeness — 35+ Ethereum JSON-RPC methods** (2026-01-25)
  - Expanded the JSON-RPC server from 10 to 35+ Ethereum-compatible
    methods for Foundry/MetaMask/Blockscout integration. New
    methods: `net_listening`, `net_peerCount`, `web3_sha3`,
    `eth_getCode`, `eth_getStorageAt`, `eth_getBlockByNumber`,
    `eth_getBlockByHash`, `eth_getBlockTransactionCountBy*`,
    `eth_getTransactionBy*`, `eth_getTransactionReceipt`,
    `eth_sendRawTransaction`, `eth_call`, `eth_estimateGas`,
    `eth_maxPriorityFeePerGas`, `eth_getBlockReceipts`,
    `eth_getLogs`, `eth_feeHistory`, `eth_mining`, `eth_syncing`,
    `eth_protocolVersion`, `eth_accounts`, `eth_coinbase`,
    `eth_hashrate`.
  - `web3_sha3` and `eth_sendRawTransaction` are fully
    functional (keccak-256 hash computation). Other methods
    return stubs until the RPC server is wired to the EVM
    module's CacheDB.
  - Dependencies: `hex = "0.4"`, `sha3` (workspace).
  - 13 new tests (38 RPC tests total, all pass).
  - **In plain words**: the RPC server now speaks enough of the
    Ethereum JSON-RPC protocol that MetaMask, Foundry, and
    Blockscout can connect. Most queries return placeholder
    values until the server is wired to live state.

- **Phase D: incremental state flush — touched-account tracking** (2026-01-25)
  - `EvmModule` now tracks accounts touched during each block
    (caller, `to` address, created address, coinbase) and
    flushes only those accounts to storage at block end. This
    changes `flush_to_storage` from O(N) to O(touched) where N
    is the total number of accounts.
  - Load test (10k txs) improved from 34.58s to 32.19s. The
    improvement is modest because the bottleneck is now the
    O(N) state root rebuild (Phase B), not the flush.
  - **In plain words**: the EVM no longer rewrites every
    account to storage after every block. Only accounts that
    were actually modified in the block are flushed. This is a
    major scalability improvement for chains with many accounts.

- **EVM TPS and read/write benchmarks** (2026-01-25)
  - Added `modules/evm/benches/tps_rw.rs` measuring EVM
    execution throughput and read/write operation costs.
  - Added `modules/evm/benches/breakdown.rs` isolating each
    step of the tx execution path.
  - Results (single-threaded, no networking):
    - Simple transfer: ~28,800 tx/s (34.7 µs/tx)
    - 10-tx batch: ~29,500 tx/s (339.5 µs/batch)
    - Contract deploy: ~28,800 tx/s (34.7 µs/deploy)
    - Full block cycle (1000 txs): ~28,200 tx/s (35.5 ms/block)
    - Balance read: 11.2 ns
    - Nonce read: 9.7 ns
    - State root (100 accounts): 5.1 µs
    - End block flush (100 txs): 1.07 µs
  - **In plain words**: the EVM execution layer sustains
    ~28,000–29,500 transactions per second single-threaded.
    Read operations are effectively free (~10 ns). The
    bottleneck for large blocks is the O(N) state root rebuild
    (35.5 ms for 1000 accounts). Incremental root updates (B3)
    will bring this down to O(touched).

- **EVM batch parallel execution — 4.5x TPS improvement** (2026-01-25)
  - Added `EvmModule::handle_batch()` — a high-throughput batch
    execution path that recovers all secp256k1 senders in
    parallel using `rayon`, then executes sequentially with
    EVM context reuse and batch touched-account tracking.
  - Profiling revealed secp256k1 ECDSA recovery is 88% of
    per-tx cost (29.6 µs out of 33.6 µs). Parallelizing across
    8 cores turns that into 88%/8 ≈ 11%, yielding a 4.5x
    speedup.
  - Results (10000-tx batch, 8 cores):
    - Serial: ~28,200 tx/s (35.5 µs/tx)
    - Parallel: **~128,000 tx/s** (7.8 µs/tx)
    - Speedup: **4.5x**
  - The 7.8 µs/tx is at the theoretical minimum (3.7 µs
    recovery/8 cores + 4 µs sequential execution = 7.7 µs).
  - Dependency: `rayon = "1.12"` (MIT/Apache-2.0).
  - 2 new unit tests (batch execution, invalid tx skipping).
  - **In plain words**: by recovering transaction signatures in
    parallel across CPU cores, the EVM now sustains ~128,000
    transactions per second on an 8-core machine — a 4.5x
    improvement over the serial path. This is the execution-
    layer ceiling; the full node stack (networking, consensus,
    mempool) will determine the real-world throughput.

- **Phase A: EVM transaction authenticity, mempool admission, gas economics** (2026-01-24)
  - **A1 — secp256k1 + Keccak in the crypto crate**: added
    `recover_sender`, `sign`, `generate_keypair_for_test`, and
    `keccak256` to `crates/crypto/src/secp.rs`. The EVM module now
    recovers the sender from the signature — the outer executor
    envelope is no longer trusted for EVM caller identity. 34 new
    crypto unit tests.
  - **A2 — signed Ethereum transaction types**: `modules/evm/src/tx.rs`
    now defines `TxLegacy`, `TxEip2930`, `TxEip1559`, and a
    `SignedTx` RLP envelope with `recover_sender()`, `chain_id()`,
    `nonce()`, `gas_limit()`, `to()`, `value()`, `data()`,
    `max_fee_per_gas()`, and `max_priority_fee_per_gas()` accessors.
    Legacy, EIP-2930, and EIP-1559 transactions are all supported.
  - **A3 — signed-only EVM execution**: `EvmModule::handle` now
    decodes a signed transaction, recovers the sender, enforces the
    chain ID, and executes via `transact_commit`. The envelope sender
    is deliberately ignored. All unit, integration, replay,
    persistence, exploit, load, and standalone tests migrated to
    deterministic signed transactions.
  - **A4 — mempool admission through `Module::validate`**: added a
    `validate` hook to the executor's `Module` trait. `ingest_tx`
    now parses the envelope, resolves the module, invokes
    `module.validate`, and rejects invalid transactions before they
    enter the mempool. EVM validation checks RLP decodability,
    signature recovery, chain ID, nonce ordering, gas limit, and
    balance affordability — without mutating state. 8 new
    validation tests.
  - **A5 — gas economics**: `build_tx_env` now wires `gas_price` and
    `gas_priority_fee` from the signed transaction into revm. revm's
    internal gas accounting charges the sender, burns the base-fee
    component, and tips the coinbase.
  - **A6 — block context + coinbase**: `EvmModule` now holds
    `coinbase`, `block_height`, `block_timestamp`, and
    `block_gas_limit`. `begin_block` sets the height and timestamp;
    `execute` wires them into revm's `BlockEnv` via
    `modify_block_chained`. `set_coinbase()` / `coinbase()` accessors
    expose the fee recipient.
  - **Benchmark**: `crates/crypto/benches/tx_recover.rs` — secp256k1
    ECDSA recovery at 35 µs (acceptance gate: < 100 µs; 3x headroom).
    At 35 µs/recovery, a single thread authenticates ~28k txs/s.
  - **In plain words**: the EVM module now executes only
    cryptographically signed transactions. The sender is recovered
    from the secp256k1 signature — the outer envelope is no longer
    trusted. Invalid transactions are rejected at mempool admission
    (not just at execution). EIP-1559 gas economics (charge, burn,
    tip) and block context (coinbase, base fee, block number,
    timestamp) are wired into revm. A single thread can authenticate
    ~28k transactions per second.

- **EVM standalone-chain validation + reth reference** (2026-01-23)
  - Wired the EVM module to `StorageBackend` for durable state
    persistence: `EvmModule::with_storage()` loads state on
    construction and flushes after each block. State survives
    restarts and produces identical roots on replay.
  - Added 8 new EVM tests: 5 multi-block integrity tests (100-block
    state root evolution, nonce progression, gas accounting,
    persistence round-trip, restart survival), 2 replay integrity
    tests (deterministic roots, storage-backed replay matches
    in-memory), and 1 standalone EVM-only chain test (50 finalized
    blocks via `Executor` with no native modules).
  - Added 1 ignored load test: 10,000 EVM transactions across 100
    blocks (3,949 txs/s on M1 debug build).
  - Established **reth** as the canonical EVM reference for Oxide
    (analogous to cosmos-evm using geth). Added
    `.devin/skills/evm-reference/SKILL.md`, updated `plan.md` §16,
    `AGENTS.md`, and EVM module docs.
  - In plain words: the EVM can now run as a standalone blockchain
    without any native modules. State persists across restarts,
    replays produce identical roots, and the system sustains ~4k
    txs/s under load. reth is now our reference for verifying EVM
    correctness.

- **Audit gap fixes: sim crate, binary tests, benchmarks, CI** (2026-01-22)
  - Resolved all 4 structural gaps from the session-24 audit: created
    the `sim/` workspace crate, added 9 smoke tests across 5 binaries,
    added criterion benchmarks for 5 previously-unbenched crates
    (consensus, mempool, broadcast, p2p, evm-fee), and wired
    feature-gated conformance tests + the new fuzz target into CI.
  - In plain words: the audit found our test coverage had blind spots
    — 5 binaries with zero tests, 5 hot-path crates with no benchmarks,
    storage adapter tests that silently skipped in CI, and a `sim/`
    directory the docs promised but didn't exist. All four are fixed.

- **Security audit + EVM exploit suite (session 24)** (2026-01-22)
  - Self-audit across all quality layers plus 17 adversarial EVM
    exploit tests. **Three real bugs found and fixed**: (1) MMR proof
    verification panicked on forged leaf counts ≥ 2^63 (remote DoS);
    (2) crafted `Proposal`/`FinalizedBlock` messages pre-allocated
    gigabytes before failing decode (remote OOM); (3) EVM state
    roots were nondeterministic — two validators executing the same
    block would sign different roots (consensus-breaking). All
    fixed with regression tests; fuzz targets re-verified clean.
  - In plain words: we tried to break our own chain like an attacker
    would, and found three ways to do it — one crash bug, one
    memory-hog bug, and one bug that would have made validators
    disagree about account balances. All three are fixed and locked
    with tests so they can't come back.

- **Uniswap-transfer throughput benchmark (Phase 2 complete)** (2026-01-22)
  - Added a criterion benchmark measuring sustained EVM execution
    throughput on a realistic Uniswap tx mix (60% ERC20 transfers,
    20% ETH transfers, 15% Uniswap swaps, 5% addLiquidity). Runs
    on 8-core Apple M1: sequential 4.83 GG/s, parallel 12.96 GG/s.
    The 1 GG/s gate is exceeded by 13x on the parallel scheduler.
  - In plain words: we proved the chain can process ~13 billion
    units of gas per second on an 8-core machine — 13x faster than
    the target. A real Uniswap block would process ~217k
    transactions per second at this rate.

- **MetaMask/Foundry/Blockscout integration tests (Phase 2)** (2026-01-22)
  - Added 18 integration tests that simulate the exact JSON-RPC
    calls MetaMask, Foundry, and Blockscout make when connecting
    to an Oxide node. Verifies hex formatting, decimal strings,
    error codes, and response structure.
  - In plain words: we verified that the three most popular
    Ethereum tools can connect to an Oxide node and get the
    responses they expect.

- **WebSocket subscriptions (Phase 2)** (2026-01-22)
  - Added `eth_subscribe` and `eth_unsubscribe` to the RPC
    server, with `newHeads` and `logs` subscription types.
    Enables real-time block and log notifications for wallets
    and explorers.
  - In plain words: wallets and explorers can now get live
    updates when new blocks are produced, instead of polling.

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

- **TCP transport hardening: graceful shutdown, TLS, peer discovery, multi-process devnet** (2026-09-09)
  - **Graceful shutdown:** `TcpTransport::shutdown()` now sets a shared
    shutdown flag, clears all active streams, and signals the accept and
    reader threads to exit. `send()` returns `ChannelClosed` after
    shutdown; `recv()` drains buffered messages then returns `None`.
  - **In plain words:** you can now cleanly shut down a node without
    leaking threads or leaving connections half-open. This is required
    for process lifecycle management in the multi-process devnet.
  - **TLS authentication and encryption:** the `p2p` crate now supports
    TLS via a `tls` feature flag, using `rustls` and `rcgen`. When
    configured, all peer connections are encrypted and authenticated
    via X.509 certificates. `TransportCaps` reports `authenticated` and
    `encrypted` as `true` only when TLS is active. Self-signed
    certificate generation is provided for devnet/testnet use;
    production deployments load certificates from files.
  - **In plain words:** devnet and testnet traffic is now encrypted and
    authenticated by default. Production nodes can load their own
    certificates. Plain TCP (no TLS) remains the default for
    backward compatibility.
  - **Peer discovery:** new `p2p::discovery` module implements a
    gossip-based peer discovery protocol. Nodes exchange peer lists
    on connection, then connect to newly discovered peers. A new
    `TcpTransport::add_peer()` method supports dynamic peer addition
    at runtime. This replaces the requirement to statically configure
    every peer.
  - **In plain words:** adding a new node to the devnet no longer
    requires updating every node's config — the new node only needs
    to know one bootstrap peer.
  - **Multi-process TCP devnet:** new `devnet::multiprocess` module
    spawns N `oxide-validator` processes, each running a single
    validator node over TCP. The `oxide-validator` binary gains a
    `--devnet-node <i>` mode for this purpose. This tests process
    isolation, real OS networking, and independent startup/shutdown.
  - **In plain words:** the devnet can now run as separate processes,
    closer to a real deployment. A crash in one node doesn't take
    down the others.
  - **Storage benchmark fix:** the storage benchmark no longer fails
    strict clippy when no storage backend features are enabled.

- **Blockchain infrastructure completion: state sync, chaos sim, governance, peer reputation** (2026-09-09)
  - **State sync protocol:** new `p2p::sync` module implements a
    chunked snapshot sync protocol. New nodes can download a state
    snapshot from existing peers instead of replaying the entire
    journal from genesis. Includes `SnapshotServer` (serves
    chunks), `SnapshotClient` (downloads and assembles), state
    root verification, and 1 MiB chunking.
  - **In plain words:** a new node joining the network can now sync
    in minutes instead of hours/days. This is the last major piece
    for full node operability.
  - **Chaos sim suite:** new `oxide-sim` crate modules: `network.rs`
    (delay/loss/partition models with deterministic PRNG),
    `byzantine.rs` (6 byzantine strategies + BFT bound tracking),
    `swarm.rs` (swarm harness with 8 predefined scenarios). 35 new
    tests.
  - **In plain words:** we can now simulate network partitions,
    byzantine validators, message loss, and latency in a
    deterministic, reproducible way. Same seed = same result.
  - **Governance module:** new `modules/governance` — the
    Cosmos-SDK-style `x/gov` analog. Token holders can propose
    parameter changes and vote yes/no. Simple majority passes at
    `end_block`. 13 new tests.
  - **In plain words:** the chain can now update its own parameters
    (timeouts, fees, limits) through on-chain governance, without
    a hard fork.
  - **Peer reputation and banning:** new `p2p::reputation` module.
    Tracks per-peer reputation scores. Peers that send invalid
    messages, timeout, or disconnect lose reputation. Below -50,
    a peer is banned for 5 minutes. 23 new tests.
  - **In plain words:** bad peers are now automatically banned.
    A byzantine node can't reconnect indefinitely to flood the
    network with garbage.
  - **Fuzz bug fix:** the `sync-decode` fuzz target found an OOM
    bug in `ChunkResponse::decode` — an untrusted `entry_count`
    caused a 206 GB allocation. Fixed by capping entry count,
    key length, and value length. 14M fuzz executions after fix,
    no crashes.
  - **In plain words:** the fuzzer found a memory exhaustion
    vulnerability in the new sync protocol within seconds. It's
    now fixed — untrusted wire data can't cause OOM.
  - **Test count:** 587+ tests pass (was 374). 91 new tests across
    p2p (+43), oxide-sim (+35), and governance (+13).
