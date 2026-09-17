# Changelog

All notable, user-visible changes to the Oxide project are documented in
this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project is pre-alpha and unreleased, so everything lives under
`[Unreleased]` until the first tagged release. Granular engineering history
lives in [`docs/devlog.md`](docs/devlog.md).

## [Unreleased]

### Added

- **Unified ledger: the EVM account store is now the single
  native-token ledger** (`modules/framework`, `modules/evm`,
  `modules/staking`, `modules/exchange`, `modules/perps`,
  `crates/node`, `crates/devnet`, `bin/*`, `crates/config`)
  - The `bank` module is gone. One account store — the same
    `revm`-backed accounts EVM transactions debit and credit —
    now backs envelope fees, staking bonds and unbonding payouts,
    exchange fill settlement, perps margin and liquidation flows,
    and the insurance fund. `eth_getBalance`, plain transfers, and
    every native money movement finally see the same numbers.
  - Native modules settle through a new `framework::Balances`
    trait instead of a concrete module: production wiring passes
    `Arc<dyn Balances + Send + Sync>` fulfilled by `EvmModule`;
    tests can substitute `framework::MemoryBalances`. Balances are
    `u64` base units; `framework::WEI_PER_UNIT` (10⁹) defines the
    wei conversion.
  - In-transaction native calls (the `0x0C_*` staking precompiles)
    move funds through **revm's own journal** via
    `JournalBalances` — a reverted EVM frame restores the bond
    transfer automatically, and the frame-scoped native journal
    undoes only the staking record (no double refund).
  - `EvmModule` implements `Module::charge_fee`, so the executor's
    fee module is the ledger itself; zero-fee envelopes skip the
    account touch exactly as before.
  - The `0x0B01`/`0x0B02` bank precompiles are retired —
    `eth_getBalance` and normal transfers already do their job;
    regression tests pin the addresses to clean reverts. Module ID
    1 is reserved and will not be reused.
  - Genesis compatibility: a legacy `bank.balances` map is still
    accepted and folded into `evm.alloc` (base units → wei), so
    existing genesis files migrate without losing funds;
    `evm.alloc` is the canonical allocation format going forward.
  - Measured, not just assumed: exchange settlement on the new
    ledger benches **744 ns/fill (~20% faster** than the old bank
    path — the account-cache write beats the deleted
    `BTreeMap<Vec<u8>, Vec<u8>>`), perps deposit **181 ns (−43%)**,
    margin-gated order placement **375 ns**, liquidation check
    **24 ns** — all well under their gates.
  - **In plain words:** there used to be two separate banks that
    didn't talk to each other — one for regular Ethereum-style
    transactions and one for everything else, so the same account
    could show two different balances depending on where you
    looked. Now there is exactly one ledger: the balance MetaMask
    shows is the same balance your staking bond, exchange fills,
    and perps margin actually use — and it turned out to be
    faster, too.
- **Validator rewards and fee distribution** (`modules/staking`,
  `modules/evm`, `crates/node`, `crates/devnet`, `bin/*`)
  - Transaction fees are now *collected*, not burned: the executor
    charges each envelope fee into staking's `FEE_POOL` address
    (wired via `EvmModule::with_fee_recipient`). Nodes that prefer
    Ethereum-style fee burning simply don't set a recipient.
  - At every block's end the pool is swept into `REWARD_POOL`
    together with fixed per-block issuance, and the total is
    distributed to validators proportional to bonded stake through
    a reward-per-token accumulator — the same accounting model
    Cosmos `x/distribution` uses, so work stays O(validators) per
    block and O(1) per delegation change.
  - Delegators earn too: each delegation accrues its pro-rata
    share lazily and `claim_reward` pays the claimer's own pending
    balance out of `REWARD_POOL` — validators claim their
    self-bonded share, delegators claim across every delegation
    they hold. Rewards already earned stay claimable after
    undelegating or being slashed.
  - **In plain words:** staking finally pays. Fees people pay to
    send transactions plus a fixed block reward flow into a pool
    each block and are split between validators and the people who
    delegated to them, proportional to stake. Anyone who staked —
    not just validator operators — can withdraw exactly what their
    position earned, whenever they want.
- **Slashing, evidence, and jailing** (`modules/staking`,
  `crates/types`, `crates/consensus`, `crates/executor`,
  `bin/oxide-validator`)
  - Double-sign evidence: anyone can submit a proof that a
    validator signed two conflicting blocks at the same view —
    `[validator][view][phase][epoch]` plus two block hashes and
    their BLS signatures. The chain verifies both signatures
    against the validator's registered consensus key; a valid
    proof slashes 10% of their stake and jails them out of the
    validator set. Forged or replayed proofs are rejected.
  - Jailing and unjailing: jailed validators stop signing and stop
    earning rewards until they unjail (after ~10 minutes). Their
    stake is not confiscated beyond the evidence slash.
  - Downtime tracking: each block now records which validators
    signed it (`FinalizedBlock.signers`), and a validator who
    misses more than half of the last 100 blocks is jailed
    automatically — without slashing, since going offline is a
    liveness fault, not malice.
  - Governance fix: the raw slash message now requires a validator
    sender — previously any account could slash anyone, an open
    confiscation hole.
  - **In plain words:** validators can now actually be punished.
    If a validator double-signs (the provable kind of cheating),
    anyone can submit the proof — two of their own signatures —
    and the chain takes 10% of their stake and kicks them out.
    If a validator just goes quiet and stops signing blocks, they
    get temporarily removed too, but without losing stake. And a
    scary hole is closed: before this, literally any account could
    have sent a "slash" message and zeroed out a validator's
    stake.

- **Coordinated upgrades: halt heights and schema migrations**
  (`crates/executor`, `modules/staking`, `modules/evm`)
  - Halt scheduling: a validator can submit a `SCHEDULE_HALT`
    transaction naming a future block height. Once the chain
    passes that height, every replica stops applying
    transactions and keeps committing empty blocks — the
    deterministic "freeze state, stay live" posture operators
    need to swap binaries for an upgrade.
  - Schema versions: modules declare a `state_version`, and a
    `migrate(from)` hook upgrades imported or reloaded state
    written by an older schema. Snapshots now record the format
    version plus every module's version; a snapshot from a newer
    binary is refused outright, and a failed migration fails the
    whole import rather than booting half-upgraded state.
  - Old snapshots still load — a pre-versioning snapshot decodes
    as format v1 and imports normally.
  - The EVM's durable backend stamps the schema version it was
    written at (`0x04` meta namespace) and runs the same
    migration on restart, so a binary upgrade protects both
    state-synced nodes and plain reboots.
  - **In plain words:** upgrades used to mean "stop the chain,
    hope everyone restarts on the same software at the same
    time". Now a validator schedules a height, every node
    freezes state there automatically while staying online,
    and the new binary knows exactly how old the data it's
    loading is — upgrading it cleanly or refusing loudly
    instead of corrupting state.

- **State-sync bootstrap for fullnodes** (`crates/statesync`,
  `crates/rpc`, `bin/oxide-fullnode`, `bin/oxide-validator`)
  - New `/snapshot/manifest` and `/snapshot/chunk/{i}` endpoints
    on the validator RPC: a small manifest (height, state root,
    format version, per-chunk BLAKE3 hashes) plus the snapshot
    served in 4 MiB hash-verified chunks.
  - `oxide-fullnode --state-sync <peer> --trusted-height H
    --trusted-root 0x...` downloads a recent snapshot instead of
    replaying the journal from genesis. Both trusted values are
    required: the manifest is checked before downloading and the
    imported state root must recompute to the trusted root, so a
    peer serving wrong state is detected twice.
  - **In plain words:** joining the network used to mean
    re-executing every block since genesis — fine at week one,
    impossible at year three. Now a new node downloads a recent
    snapshot in verified pieces from any validator, checks it
    against a root the operator already trusts, and starts
    serving from that height.

- **Height-indexed pruning and archive mode** (`crates/storage`,
  `crates/config`, `crates/executor`, `docs/archive-recipe.md`)
  - The journal now records each sealed segment's max block
    height in a `heights.idx` sidecar, so history can be pruned
    by *height* ("delete everything below H"), not just by
    segment count. Segments with unknown contents are never
    deleted.
  - New `[storage]` config: `journal_retain_segments`,
    `history_retention` (the executor's in-memory
    finalized-block window), and `archive = true` for
    keep-everything nodes.
  - `docs/archive-recipe.md` documents the two-tier deployment:
    pruned validators + one archive node for explorers/audits,
    with state-sync for new joins instead of full replay.
  - **In plain words:** disk usage was going to grow forever —
    at target speed, a node writes a terabyte of history a day.
    Now operators choose: prune by count or by block height for
    normal nodes, or flip one flag and keep everything on an
    archive node that serves explorers and auditors. New nodes
    still bootstrap by verified snapshot rather than replaying
    the archive.

- **Oracle module: median-of-feeds mark price** (`modules/oracle`,
  `modules/perps`, `modules/staking`, `modules/framework`,
  `crates/node`)
  - Validators submit per-market price observations; at end of
    each block the oracle requires a strict majority of eligible
    feeders, takes the median, smooths it through an EMA, and
    pushes the result into perps. A single bad feed can no longer
    move the mark.
  - **Security fix:** the perps `set_mark`/`apply_funding`
    transaction paths were previously unauthenticated — any
    account could move the mark within the deviation cap. They are
    now gated to active (non-jailed) validators as an emergency
    override, and closed entirely when no committee is wired.
  - External price feeds can be whitelisted via committee-gated
    register/unregister messages; staleness tracking flags marks
    that stop being updated.
  - The governance module (previously built but unwired) is now
    registered in `Node::assemble`.
  - `oxide-spammer --orders` adds an order-load mode for the
    matching path (~144K orders/s through mempool→block→match→
    settle on a dev machine).
  - **In plain words:** the price that decides when traders get
    liquidated used to be set by a single message anyone could
    send (rate-limited, but still one actor). Now a majority of
    validators must agree on the price, outliers are discarded by
    taking the median, updates are smoothed, and the old manual
    path is locked to validators as an emergency fallback.

- **Lock-free balance cache + nonce-overflow hardening**
  (`crates/matcher`, `crates/mempool`, `crates/executor`,
  `crates/storage`)
  - `ShardedBalanceCache` (now `AtomicBalanceCache`) replaces
    per-shard `Mutex<HashMap>` locks with a flat array of
    per-account atomics: measured 3-30x higher throughput under
    contention (up to ~670M ops/s at 8 threads spread; ~89M ops/s
    even with all threads on the same 64 accounts). The sparse
    fallback keeps arbitrary 20-byte addresses collision-free.
  - **Security fix:** a transaction carrying nonce `u64::MAX` could
    execute and wrap the sender's next-expected nonce to 0,
    reopening the account's entire history to replay. `u64::MAX` is
    now a reserved nonce — rejected at admission, skipped at
    execution, rejected at proposal.
  - Arithmetic-overflow sweep across mempool, executor, journal,
    and MMR: checked nonce/height/count arithmetic on all paths
    reachable by untrusted input.
  - **In plain words:** two safety wins and one big speed win —
    a crafted nonce can no longer rewind an account's replay
    protection, and the off-chain matcher's shared balance book
    now scales with cores instead of fighting over 64 locks.

- **Batch-settlement throughput proven ≥1M orders/s on-chain**
  (`modules/exchange`, `crates/devnet`)
  - Two new `settlement` benches measure the `batch_settle` path —
    pre-matched fills from the off-chain matcher, validated and
    settled without re-matching: ~3.9M fills/s worst-case (every
    fill a distinct buyer/seller pair, one ledger transfer each)
    and ~110M fills/s when a batch aggregates to one pair.
  - New `settle_tps` devnet test drives `batch_settle` txs through
    the full 4-validator oxideBFT/TCP pipeline and verifies exact
    balance conservation plus state-root agreement. Measured:
    **~1.85M fills/s (~3.7M orders/s)** at the 65,536-fill wire
    maximum; ~1.35–1.41M fills/s at 16,384 fills/tx.
  - `ExchangeModule::with_settlement_operator` builder and a
    `TcpMultiNodeDevnet::with_exchange_settlement_and_base_port`
    constructor wire the operator through the devnet.
  - **In plain words:** the "1 million orders per second" design —
    match off-chain, settle in bulk on-chain — is now proven
    end-to-end: the chain settles ~3.7 million orders' worth of
    fills per second with every validator agreeing on identical
    state, and the bottleneck is now network payload size, not the
    ledger.

- **EIP-712-signed native module transactions** (`crates/crypto`,
  `crates/executor`, `crates/mempool`, `crates/rpc`, `modules/evm`,
  `crates/node`, `bin/oxide-validator`, `bin/oxide-fullnode`)
  - Native transactions can now carry a secp256k1 EIP-712 signature.
    The signed envelope sets `0x80` on the module-ID byte and places
    `r‖s‖v` (65 bytes) between the module ID and the payload, so the
    module payload stays "the rest of the bytes" and every module
    decoder is unchanged.
  - The signature covers `Tx(address sender,uint64 nonce,uint64 fee,uint8
    moduleId,bytes payload)` over the EIP-712 domain `name="Oxide"`,
    `version="1"`, `chainId=<configured>` — the chain ID makes
    cross-chain replay impossible, and sender/recovered-signer
    equality binds the declared `sender` field.
  - Wallets sign via `eth_signTypedData_v4` (MetaMask/Ledger) — the
    same key controls the EVM account and the native bank/staking/
    exchange identity. `mempool::build_signed_tx` and
    `crypto::eip712::{sign_tx, verify_tx_sender}` are the
    signing-side helpers.
  - Verification runs at mempool admission, batch admission, and
    block execution; `process_proposal` statically rejects an
    envelope signature on a self-authenticating module. The
    preverify cache makes verified-at-ingest txs skip re-recovery
    during execution.
  - `oxide_sendRawTransaction` submits a hex-encoded signed native
    envelope and returns the BLAKE3 transaction hash.
  - Operators: `oxide-validator --require-signed-txs` rejects
    unsigned native transactions outright (production posture); the
    default `Allow` policy keeps devnets and tests working during
    the migration. Chain ID flows from the RPC config.
  - **In plain words:** before this change a native transaction's
    "who sent this" field was just a claim — anyone could submit a
    transfer spending your bank balance, because only EVM
    transactions carried real signatures. Now native transactions
    can be signed with the same Ethereum key MetaMask already
    holds, forged senders are rejected at every boundary, and
    validators can require signatures so no unauthenticated spend
    ever executes.

- **EVM-RPC surface closeout** (`modules/evm`, `crates/rpc`)
  - `eth_call`, `eth_estimateGas`, and `debug_traceCall` now accept
    geth's state-override argument — per-account
    `balance`/`nonce`/`code`/`state`/`stateDiff` applied through a
    read-only `OverrideView` for the duration of one simulation and
    never persisted. `debug_traceCall` reads `stateOverrides` from
    its config object, matching geth's `TraceCallConfig`.
  - `eth_gasPrice` and `eth_maxPriorityFeePerGas` quote the history
    oracle instead of constants: the p60 of the three lowest
    effective tips sampled from each of the last 20 sealed blocks
    (geth `GasPriceOracle` policy), capped at 500 gwei with a 1 gwei
    default on a young chain.
  - `eth_pendingTransactions` returns the pool's pending
    (executable) transactions as geth-shaped tx objects —
    `blockHash`/`blockNumber`/`transactionIndex` null — excluding
    queued nonce-gap entries.
  - The pollable-filter registry is now count-bounded at 1,024 live
    entries (`filter-cap`), and HTTP dispatch carries a 30 s
    wall-clock timeout (`http-timeout`): past the deadline the
    client receives HTTP 408 plus a JSON-RPC error. WebSocket frame
    writes are bounded at 30 s so a stalled consumer cannot hold a
    connection slot forever.
  - **In plain words:** tooling can now simulate transactions "as
    if" an account had different code/balances/storage — the trick
    every dapp debugger relies on — gas-price queries return real
    market quotes instead of stubs, `eth_pendingTransactions` shows
    what the mempool will execute next, and two more standard
    resource ceilings close out the abuse-surface checklist.

- **EIP-2935 history-storage contract** (`modules/evm`)
  - The canonical Prague history contract is preinstalled at
    `0x0000F90827F1C53a10cb7A02335B175320002935` (bytecode identical
    to `alloy_eips::eip2935`), and `begin_block` records the parent
    block's hash at slot `(h−1) % 8191` — the same observable state
    geth's system call produces, captured into the block's undo so
    historical reads stay correct. The preinstall and the write are
    both Prague-gated: a chain configured for an earlier fork
    carries neither.
  - **In plain words:** contracts can now read block hashes older
    than the BLOCKHASH opcode's 256-block limit — up to 8,191 blocks
    back — the same way they do on post-Prague Ethereum.

- **Historical state reads + `eth_getProof` (EIP-1186)**
  (`modules/evm`, `crates/rpc`)
  - A versioned state window now records first-write-wins
    per-block undo entries, so `eth_getBalance`,
    `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`,
    `eth_call`, `eth_estimateGas`, `debug_traceCall`, and
    `eth_createAccessList` all answer at any retained height —
    block tags, hex numbers, and EIP-1898 `{blockHash}`/
    `{blockNumber}` objects. Heights above the tip return
    `header not found`; heights below the window return geth's
    `missing trie node` error.
  - `eth_getProof` returns the account's Merkle-Patricia proof
    plus one storage proof per requested key at the requested
    height — including proofs of non-inclusion — matching geth's
    JSON shape (`accountProof`, `balance`, `codeHash`, `nonce`,
    `storageHash`, `storageProof[]`).
  - **In plain words:** block explorers, indexers, bridges, and
    light-client tooling can now query balances/storage *as of a
    past block* and fetch real Merkle proofs — the archive-read
    surface geth-compatible tooling expects.

- **EVM history + undo persistence across restart**
  (`modules/evm`, `crates/storage`)
  - Sealed `ExecutedBlock` records (headers, transactions,
    receipts, logs, call traces) and the versioned undo window now
    flush to the storage backend in the same atomic per-block
    batch as account state, under dedicated namespaces. A restart
    restores history, rebuilds the tx-hash/block-hash indexes,
    and resumes sealing with correct parent linkage; pruning
    keeps the in-memory and on-disk windows identical.
  - **In plain words:** a node that restarts no longer forgets
    every transaction and receipt it ever served — `eth_getBlock*`,
    `eth_getTransaction*`, `eth_getLogs`, traces, and historical
    reads all survive a crash or upgrade.

- **`eth_createAccessList` + EIP-7702 SetCode transactions**
  (`modules/evm`, `crates/rpc`)
  - `eth_createAccessList` returns the accessed
    addresses/storage keys and `gasUsed` with geth's
    accessListTracer semantics: sender/recipient/coinbase/
    precompiles are excluded at address level, but their touched
    storage keys still appear.
  - Type-4 (`0x04`) transactions decode, sign, recover, and
    execute: `TxEip7702` + `TxAuthorization` RLP, secp256k1
    recovery, revm `authorization_list` wiring, and a Prague spec
    gate. RPC responses expose `type:"0x4"` and the
    `authorizationList` array.
  - **In plain words:** dapps that gas-optimize via
    `eth_createAccessList` work, and EOAs can delegate to contract
    code (smart-account UX) exactly as on post-Prague Ethereum.

- **RPC resource limits (second tranche)** (`modules/evm`,
  `crates/rpc`)
  - Simulation calls (`eth_call`, `debug_traceCall`,
    `eth_estimateGas`, `eth_createAccessList`) enforce a
    wall-clock EVM timeout via a `DeadlineInspector` that halts
    the interpreter mid-execution — an infinite-loop contract can
    no longer pin a worker forever.
  - JSON-RPC batch arrays are accepted and capped at 1,024
    requests per batch (geth's default); the HTTP listener drops
    accepts beyond a maximum-open-connections bound.
  - **In plain words:** three more standard guardrails — no
    request can burn unbounded CPU, no single connection can
    smuggle an unbounded workload in one POST, and a flood of
    sockets can't exhaust the node.

- **`debug_trace*` namespace — callTracer over revm inspector
  composition** (`modules/evm`, `crates/rpc`)
  - `debug_traceTransaction`, `debug_traceCall`,
    `debug_traceBlockByNumber`, and `debug_traceBlockByHash` return
    geth-shaped callTracer output: per-frame `type`/`from`/`to`/
    `input`/`output`/`value`/`gas`/`gasUsed`/`calls`/`error`/
    `revertReason`, including nested calls and creates.
  - Traces are recorded *during* execution by a `CallRecorder`
    inspector composed with the native-journal inspector, and
    retained in `evm::history` — the honest approach while the
    state store serves latest-only state (no silent re-execution
    against wrong state). Coverage is bounded by the 8192-block
    history window.
  - `debug_traceCall` returns the trace for reverted executions
    (error inside the root frame), matching geth; unsupported
    tracers are rejected explicitly.
  - **In plain words:** `debug_traceTransaction` works — explorers
    and indexers get the same call-tree JSON geth produces, for any
    transaction still inside the node's retained history window.

- **`txpool_*` namespace** (`crates/rpc`, `crates/mempool`,
  `crates/executor`, `bin/oxide-validator`)
  - `txpool_status` (pending/queued hex counts),
    `txpool_content`/`txpool_contentFrom` (sender → nonce → full
    transaction objects), and `txpool_inspect` (geth summary
    strings) expose the mempool's per-sender nonce queues.
    Pending = contiguous executable nonces, queued = behind a gap.
  - The RPC crate talks to a `TxpoolProvider` trait; the validator
    wires the executor-backed implementation — the RPC/mempool seam
    stays replaceable.
  - **In plain words:** wallets and operators can now inspect
    exactly which transactions are about to execute and which are
    stuck behind nonce gaps — the same view geth exposes.

- **Pollable filter APIs + `newPendingTransactions` (P1.5)**
  (`crates/rpc`, `bin/oxide-validator`)
  - `eth_newFilter`/`eth_getFilterChanges`/`eth_getFilterLogs`
    (log filters reuse `eth_getLogs` semantics),
    `eth_newBlockFilter` (block-hash deltas),
    `eth_newPendingTransactionFilter` (mempool-arrival tx hashes),
    and `eth_uninstallFilter`. Filters live 300s between polls
    (geth's TTL); expired filters return `filter not found`.
  - `eth_subscribe` supports `newPendingTransactions`: canonical
    EVM tx hashes push on local submit *and* on gossip-accepted
    peer transactions (1024-hash bounded ring, dedup by hash).
  - **In plain words:** standard wallet tooling that polls
    `eth_getFilterChanges` (MetaMask, ethers, web3.js) now works
    unchanged, and pending transactions stream to subscribers —
    the last pieces needed for explorer and bot backends.

- **RPC resource limits (first tranche)** (`crates/rpc`)
  - `eth_call` and `debug_traceCall` clamp requested gas to the
    chain block gas limit (the `gas-cap` role); `eth_getLogs` and
    all filter log paths cap results at 10,000 entries;
    `eth_feeHistory` caps `blockCount` at 1,024.
  - **In plain words:** a single expensive RPC request can no
    longer consume unbounded node resources — the same guardrails
    geth ships with.

- **WebSocket transport + `eth_subscribe` (P1)** (`crates/rpc`,
  `bin/oxide-validator`)
  - `GET /` with `Upgrade: websocket` now upgrades to a JSON-RPC
    WebSocket on the same port as HTTP — the geth convention
    (`ws://host:8545`). All `eth_*`/`web3_*`/`net_*` methods work
    over WS identically to HTTP.
  - `eth_subscribe` over WS creates real subscriptions: `newHeads`
    pushes the block header on every finalized block, `logs` pushes
    each log matching an `eth_getLogs`-shaped `address`/`topics`
    filter. `eth_unsubscribe` cancels (`true`/`false`, geth
    semantics). Subscriptions are reaped when their connection
    closes.
  - Over HTTP, `eth_subscribe` now returns the geth-parity error
    `-32000 "notifications not supported"` instead of minting an ID
    that could never deliver.
  - The single-node consensus driver gained a block observer that
    keeps `eth_blockNumber` live and drives the notification fan-out
    (previously the RPC height stayed frozen at its startup seed).
  - **In plain words:** wallets, explorers, and dapp backends can now
    subscribe to the chain live over `ws://` — new blocks and
    filtered contract events push to subscribers the moment they
    finalize, instead of polling `eth_getBlockByNumber` in a loop.

- **Bank-backed staking + real `0x0C_*` precompile side effects (P1)**
  (`modules/staking`, `modules/evm`)
  - `delegate` now debits the delegator into a bonded-pool account and
    records per-`(delegator, validator)` delegations; `undelegate`
    requires owning the delegation and queues an unbonding entry that
    pays out at `completion_height`; `slash` burns pro-rata across
    real delegations; `claim_reward` is validator-only and mints at
    claim. Previously stake inflated for free and anyone could unbond
    or burn anyone's rewards — wiring a precompile to that would have
    been the cosmos-evm exploit class.
  - `0x0C_01` (delegate) and `0x0C_02` (undelegate) EVM precompiles
    now perform the real staking operation for `msg.sender` through
    the same invariant-checked path as native messages.
  - **In plain words:** contracts can now stake and unstake from
    Solidity/EVM — and if a contract call reverts, the stake change
    reverts with it, exactly like a state write.

- **EVM native journal — frame-scoped undo for precompile side
  effects** (`modules/evm/src/native_journal.rs`)
  - Mutating native precompiles journal each mutation with an undo
    closure tagged by call depth; a reverted frame replays its undos,
    a successful frame merges them into the parent — geth StateDB
    journal semantics applied to non-EVM state.
  - **In plain words:** an EVM call that fails can never leave a
    half-applied staking change behind.

- **Genesis preinstalls** (`modules/evm/src/preinstalls.rs`)
  - CREATE2 deploy proxy (EIP-7997), EIP-2470 singleton factory,
    Multicall3, Permit2, and the Safe proxy factory are installed at
    their canonical mainnet addresses at genesis.
  - **In plain words:** Foundry/Hardhat/Safe contracts deploy to the
    same addresses as on Ethereum, and contracts that assume
    Multicall3/Permit2 just work.

- **Mempool same-nonce replacement** (`crates/mempool`)
  - Resubmitting a transaction for a sender+nonce already in the pool
    requires a ≥10% fee bump (geth legacypool rule); the old entry is
    removed from every index. Lower- or equal-fee resubmissions are
    rejected, and replacement works even when the pool is full.
  - **In plain words:** "speed up" works — bump the fee and the new
    transaction replaces the old one instead of silently corrupting
    the pool.


### Added

- **EVM execution history + real `eth_*` RPC surface (P0 parity)**
  (`modules/evm/src/history.rs`, `crates/rpc`, `bin/oxide-validator`)
  - `History` retains a bounded window (8192 blocks) of executed
    blocks: real block hash (Prague-style header), transaction and
    receipt trie roots, block bloom, receipts, logs with block-wide
    indices, gas totals, and per-hash/height indexes.
  - `eth_getBlockByNumber`/`ByHash`, `eth_getTransactionByHash`,
    `eth_getTransactionByBlockNumberAndIndex`, block transaction
    counts, `eth_getTransactionReceipt`, `eth_getBlockReceipts`,
    `eth_getLogs` (range + address + topics + `blockHash`), and
    `eth_feeHistory` now serve real executed data instead of stubs.
  - `eth_call` executes a real read-only call against current EVM
    state; reverts surface as JSON-RPC code 3 with revert data.
    `eth_estimateGas` runs a bounded binary search and propagates
    reverts/halts instead of returning a constant.
  - Genesis supports an Ethereum-style `evm.alloc` section
    (balance/nonce/code/storage) applied in single-node and devnet
    assembly.
  - `eth_sendRawTransaction` now gossips the wrapped transaction to
    peers (deduplicated, no rebroadcast loops) so submissions to a
    non-leader node still reach the mempool.
  - Multi-node devnet mode now registers an `EvmModule` — `eth_*`
    endpoints were previously unbacked there.
  - **In plain words:** MetaMask, Foundry, and other Ethereum tooling
    can now query blocks, transactions, receipts, and logs, simulate
    calls, and estimate gas against Oxide the same way they do
    against Ethereum — and transactions submitted to any validator
    reach the whole network.


- **Mutual TLS bound to validator/peer identities (C4)**
  (`crates/p2p/src/tls.rs`, `crates/p2p/src/tcp.rs`)
  - The p2p transport now requires mutual TLS: the server verifies
    the client's certificate, and the client presents its
    certificate. The verified certificate's DER is bound to a
    configured peer ID via a `peer_id_map`.
  - `accept_tls_connection` extracts the authenticated peer ID
    from the verified certificate and verifies it matches the
    self-claimed first-frame peer ID. Unknown or untrusted
    certificates are rejected.
  - Added `TlsConfig::with_cert_pem()` for pre-generated
    certificates (production file-based config and test sharing).
  - **In plain words:** A peer can no longer impersonate a
    validator by claiming its peer ID. The TLS handshake
    cryptographically verifies the peer's identity, and the
    first-frame peer ID must match the certificate.

- **Consensus write-ahead log for restart safety (C9)**
  (`crates/consensus/src/wal.rs`, `crates/consensus/src/engine.rs`)
  - Added a `Wal` that persists safety-critical consensus state
    (`last_voted_view`, `voted_at_height`, `high_qc`,
    `current_view`, `next_height`, `epoch`) to a durable file
    before the engine sends any vote or QC.
  - On restart, `OxideBft::recover_from_wal()` restores the
    state, preventing double-voting and conflicting votes after
    a crash.

- **State snapshot export/import via CLI and RPC**
  (`bin/oxide-validator/src/main.rs`, `crates/rpc/src/server.rs`)
  - `oxide-validator --export-snapshot <path>` writes the
    codec-encoded `ExecutorSnapshot` to a file and exits.
  - `oxide-validator --import-snapshot <path>` restores state from
    a snapshot file before starting consensus.
  - `GET /snapshot` on the RPC endpoint returns the snapshot as
    hex (for download/transfer to a new node).
  - `rpc::SnapshotProvider` trait lets the RPC layer export state
    without a direct dependency on the executor.
  - **In plain words:** A validator can now save its entire state
    to a file (backup), transfer it to a new node (migration), or
    restore it after data loss (disaster recovery) — without
    replaying from genesis.

- **Validator BLS key rotation via `--submit-key-change`**
  (`modules/staking/src/lib.rs`, `bin/oxide-validator/src/main.rs`)
  - New `KEY_CHANGE` (0x05) staking message type: `[type][validator:20B][new_key:48B]`.
  - `staking::msg::key_change(validator, key)` constructs the message.
  - `handle_key_change` validates sender == validator, validator
    has stake, key is 48 bytes. Stores in `pending_key_changes`.
  - `staking.take_key_changes()` drains pending changes.
  - `oxide-validator --submit-key-change <hex>` submits the tx.
  - **In plain words:** A validator can rotate its BLS consensus
    key (e.g., after a suspected key compromise) by submitting a
    transaction — no restart or re-registration needed.

- **Key-change → epoch rotation wiring**
  (`crates/consensus/src/validator.rs`, `crates/consensus/src/engine.rs`,
  `crates/executor/src/lib.rs`, `crates/devnet/src/tcp_multinode.rs`)
  - `ValidatorSet` now carries `validator_addresses: Vec<Address>` —
    each validator's staking identity, parallel to their consensus
    key. The address survives key rotation.
  - `validator_address(pk)` derives the staking address from a BLS
    key: `hash(ValidatorAddress ‖ pk)[..20]` — the standard pattern
    (Ethereum derives addresses from public keys).
  - `ValidatorSet::index_of(address)` maps a staking address to its
    validator index. `ValidatorSet::apply_key_change(index, key)`
    returns an updated set preserving the address.
  - `Module::take_key_changes()` is a new trait method (default
    empty); `StakingModule` overrides it to drain pending changes.
    `Executor::take_pending_key_changes()` collects them across all
    modules.
  - `OxideBft::apply_key_changes(changes)` builds an updated
    `ValidatorSet` and calls `schedule_rotation` — the two-phase
    handoff completes at the epoch boundary via `complete_rotation`.
  - `TcpMultiNodeDevnet::rotate_epoch_with_key_changes()` bridges
    the full flow: drain → apply → schedule → rotate.
  - **In plain words:** When a validator submits a `KEY_CHANGE`
    transaction, the new key is stored pending. At epoch boundary,
    the consensus engine reads the pending changes, swaps in the
    new BLS keys, and rotates — the validator's identity (staking
    address) stays the same, only the signing key changes.

- **Full commit history in devnet via `commit_listener`**
  (`crates/consensus/src/engine.rs`, `crates/devnet/src/tcp_multinode.rs`)
  - `OxideBft::set_commit_listener` registers a callback that fires
    on each committed block — before the `finalized` map prunes
    entries at `MAX_RETAINED_FINALIZED` (4096).
  - `TcpMultiNodeDevnet` wires the listener to collect all commits
    into `committed_blocks` vectors for the integrity check.
  - **In plain words:** Long-running tests (>4096 blocks) now
    correctly verify that all validators committed the same blocks —
    previously only the last 4096 were visible due to pruning.
  - Entries are CRC32-protected and length-prefixed; truncated
    or corrupted tail entries are discarded on recovery.
  - **In plain words:** A validator that crashes and restarts
    can no longer double-vote or vote for a conflicting block.
    The WAL ensures the safety-critical state is durable before
    the vote hits the network.

- **O(n) receipts root for the EVM module**
  (`modules/evm/src/receipts.rs`)
  - Replaced the O(n²) `position()` lookup in `receipts_root` with an
    O(n) indexed iteration. The encoder now receives the receipt and
    its index directly, eliminating the per-receipt scan.
  - **In plain words:** Computing the receipts root for a block with
    millions of transactions no longer takes quadratic time. Each
    receipt is processed exactly once instead of scanning the entire
    receipt list to find each one's position.

- **Authenticated replay-protection nonces in snapshots**
  (`crates/executor/src/lib.rs`)
  - Added `nonce_root` to `ExecutorSnapshot` that binds
    `executed_nonces` into the authenticated `state_root`. A crafted
    snapshot can no longer zero or corrupt replay-protection nonces
    without detection.

- **Production deployment wiring for `--devnet-node`**
  (`bin/oxide-validator/src/main.rs`, `crates/config/src/genesis.rs`,
  `modules/staking/src/lib.rs`)
  - `run_devnet_node` now uses the same production infrastructure as
    `run_single_node`: `--config` TOML, `--genesis-file`, BLS key
    file, TLS/mTLS, WAL persistence, RPC server, and graceful
    shutdown — plus multi-node TCP networking.
  - New flags: `--genesis-file`, `--bls-key-file`, `--tls-dir`,
    `--wal-file`, `--rpc-listen`. The `--config` flag now applies to
    devnet mode too.
  - `GenesisValidator` gains `public_key: Option<String>` — a hex-
    encoded 48-byte BLS public key. `oxide-validator genesis`
    generates keys and fills it in; production deployments provide
    their own.
  - `StakingModule::genesis_register_validator(addr, stake)` registers
    validators at genesis without requiring a delegate transaction.
  - SIGINT/SIGTERM triggers graceful shutdown: the consensus loop
    breaks cleanly, transport flushes, WAL closes.
  - `eth_blockNumber`, `/health`, `/metrics`, and `/snapshot` are now
    available on every devnet node.
  - **In plain words:** A validator can now be deployed on a real
    machine with proper keys, TLS-encrypted peer connections, WAL
    persistence for crash recovery, and monitoring endpoints — the
    same infrastructure a production node uses.
  - **In plain words:** When a new node syncs state from a snapshot,
    the replay-protection nonce map is now cryptographically
    authenticated. A malicious peer cannot tamper with nonces to
    enable replay attacks.

- **`conformance` feature for the consensus crate**
  (`crates/consensus/Cargo.toml`, `crates/consensus/src/engine.rs`)
  - Added a `conformance` feature that gates the
    `without_signature_verification` method. The method can no longer
    be called from production builds without explicitly enabling the
    feature.
  - **In plain words:** The BLS signature verification bypass, used
    only by conformance tests and benchmarks with fake keys, is now
    locked behind a feature flag. It cannot accidentally ship in a
    production validator.

- **TLS certificate generation (`oxide-validator tls-gen`)**
  (`bin/oxide-validator/src/main.rs`)
  - New `tls-gen` subcommand generates self-signed certificates +
    private keys for a multi-node testnet, then writes per-node
    `--tls-dir` directories (`tls/node-{i}/`) with `cert.pem`,
    `key.pem`, and `peer-{j}.pem` for every peer.
  - Each node runs with `--tls-dir tls/node-{i}` — mTLS is enforced
    by the existing `TlsConfig::from_files` + `with_tls` path (C4).
  - **In plain words:** A testnet operator can generate all TLS
    certificates with one command instead of manually creating
    self-signed certs for each validator. For production, use a
    proper CA (`step ca`, Vault PKI, cert-manager).

- **Governance validator set changes (`VALIDATOR_ADD`/`VALIDATOR_REMOVE`)**
  (`modules/staking/src/lib.rs`, `crates/consensus/src/engine.rs`,
  `crates/consensus/src/validator.rs`, `crates/executor/src/lib.rs`)
  - `VALIDATOR_ADD` (0x06): `[type][address:20B][bls_key:48B][stake:8B]`
    — registers a new validator in `validators` and
    `pending_validator_adds`. Joins consensus at the next epoch.
  - `VALIDATOR_REMOVE` (0x07): `[type][address:20B]` — adds the
    validator to `pending_validator_removes`. Removed from consensus
    at the next epoch.
  - Only a current validator can submit — the validator set admits
    and evicts its own members (governance-by-committee).
  - `ValidatorSet::add_validator(pk, stake, address)` and
    `remove_validator(index)` return new sets with recomputed
    quorum thresholds and leader-election weights.
  - `OxideBft::apply_validator_changes` applies removes first
    (descending index to avoid shifting), then adds, then
    `schedule_rotation`.
  - **In plain words:** A validator set can now grow or shrink at
    epoch boundaries via transactions — no restart or genesis
    regeneration needed. A new validator submits `VALIDATOR_ADD`
    (proposed by an existing validator), waits for the epoch
    rotation, then joins consensus.

- **Automatic state persistence (`--data-dir`)**
  (`bin/oxide-validator/src/main.rs`)
  - `--data-dir <dir>` enables auto-snapshot persistence: on startup,
    imports `<dir>/snapshot.bin` if it exists; on shutdown
    (SIGINT/SIGTERM), exports the current state to
    `<dir>/snapshot.bin`.
  - SIGTERM is now handled via `tokio::signal::unix::signal` —
    `pkill -TERM` or `docker stop` triggers graceful shutdown +
    snapshot export.
  - **In plain words:** A validator that restarts (crash, upgrade,
    machine reboot) resumes with its full chain state — no manual
    snapshot export/import needed.

- **Validator set discovery (`GET /validator-set`)**
  (`crates/rpc/src/lib.rs`, `crates/rpc/src/server.rs`,
  `bin/oxide-validator/src/main.rs`)
  - New RPC endpoint returns the current validator set as JSON:
    `[{address, public_key, stake}, ...]`.
  - `ValidatorSetProvider` trait decouples the RPC from `consensus` —
    the validator binary wraps `Arc<RwLock<ValidatorSet>>` and
    updates it after each epoch rotation.
  - **In plain words:** A new validator joining mid-epoch queries
    `GET /validator-set` on an existing validator to discover the
    current set + peer addresses — no genesis file needed.

### Fixed

- **Signature malleability: reject recovery IDs 2 and 3**
  (`crates/crypto/src/secp.rs`)
  - `RecoveryId::try_from_u8` now rejects values 2 and 3 (only 0 and
    1 are valid for Ethereum signatures). Previously, 2/3 were
    accepted, enabling signature malleability and DoS vectors.
  - **In plain words:** Only recovery IDs 0 and 1 are now accepted in
    transaction signatures. Values 2 and 3 correspond to
    provably-unused keys and never appear in real Ethereum signatures.

- **Unbounded outbound p2p channel**
  (`crates/p2p/src/tcp.rs`, `crates/ports/src/transport.rs`)
  - Replaced the unbounded `mpsc::channel()` with a bounded
    `mpsc::sync_channel(10_000)`. `send()` now returns
    `TransportError::ChannelFull` when the outbound queue is full,
    applying backpressure instead of growing without bound.
  - **In plain words:** A slow peer can no longer cause the node to
    run out of memory by buffering unlimited outbound messages. When
    the queue is full, the sender is told to back off.

- **Admission control connection leak**
  (`crates/p2p/src/tcp.rs`)
  - `release_connection` is now called when connections break and on
    shutdown. Previously, the connection counter leaked, eventually
    reaching the cap and rejecting all new connections.
  - **In plain words:** The node no longer slowly loses the ability
    to accept new peer connections over time. Disconnected peers
    properly free their connection slots.

- **BatchSettler cache/chain divergence**
  (`crates/matcher/src/server.rs`)
  - The pending settlement envelope is no longer dropped after max
    retries. Dropping would leave the off-chain cache applied
    without on-chain settlement. The envelope stays pending so the
    operator can intervene.
  - **In plain words:** When a settlement transaction repeatedly
    fails to submit, the system no longer silently drops it and
    diverges from the chain. The pending settlement is kept for
    operator intervention.

- **TCP batch decoder OOM**
  (`crates/matcher/src/server.rs`)
  - The batch `count` field is now bound-checked against
    `MAX_BATCH_SIZE` before allocating the buffer. A byzantine peer
    sending `u32::MAX` could previously trigger a multi-GB allocation.
  - **In plain words:** A malicious peer can no longer crash the
    matching engine by sending a huge batch count in a single
    request.

- **`without_signature_verification` release-build backdoor**
  (`crates/consensus/src/engine.rs`)
  - The method is now gated behind `#[cfg(any(test, feature =
    "conformance"))]`. Previously, it was callable from release
    builds, allowing a production validator to disable BLS
    verification.
  - **In plain words:** The signature verification bypass can no
    longer be called from a production build. It is only available
    in tests and when the `conformance` feature is explicitly enabled.

- **Sparse incremental state-root computation for the EVM module**
  (`modules/evm/src/lib.rs`, `modules/evm/benches/trie_root.rs`)
  - Replaced the O(N) `HashBuilder` trie-assembly pass with a
    sparse retained-trie walk that skips untouched subtrees via
    `add_branch`. After the first full build, branch node metadata
    (`BranchNodeCompact`) is retained from `HashBuilder::split()`.
    Subsequent calls walk only the path from touched leaves to the
    root, injecting precomputed hashes for untouched subtrees.
  - Complexity reduced from O(total_accounts) to
    O(touched · log(total_accounts)) per block.
  - **In plain words:** When a block changes 100 accounts out of
    1 million, the state root is now computed by walking only the
    100 changed paths through the trie tree, not by re-hashing all
    1 million accounts. This makes state-root computation ~1000x
    faster at scale and eliminates the throughput degradation that
    occurred as the account set grew.
  - Benchmark gate: 1M accounts / 100 touched < 10ms → **1.27 ms**
    (7.9x margin).
  - EVM load test: 100K txs at 6,410 tx/s with 4 validators,
    throughput now *increases* over time instead of degrading.

- **Real Reed-Solomon erasure broadcast with proof of availability**
  (`crates/broadcast/src/gf256.rs`, `crates/broadcast/src/rs.rs`,
  `crates/broadcast/src/lib.rs`)
  - Replaced the placeholder replication-based `ErasureBroadcast`
    with a real Reed-Solomon erasure coding implementation over
    GF(256) using the AES irreducible polynomial.
  - Dependency-free: GF(256) arithmetic with precomputed log/exp
    tables, Vandermonde matrix in systematic form, Gaussian
    elimination for reconstruction.
  - k = 2f+1 data shards, m = f parity shards (n = 3f+1 total).
    Any k shards suffice for reconstruction — tolerates f
    byzantine/missing validators.
  - Proof of availability: Merkle root of shard hashes (BLAKE3)
    computed per broadcast, deterministic across nodes.
  - **In plain words:** Block data is now erasure-coded across
    validators. A node can reconstruct the full block from any
    two-thirds of the shards, even if f validators are offline or
    malicious. Each broadcast carries a cryptographic proof that
    the shards belong to the announced block.

- **Snapshot sync for fast node startup**
  (`crates/executor/src/lib.rs`, `crates/node/src/lib.rs`)
  - `ExecutorSnapshot` captures chain height, aggregate state
    root, and per-module state roots. Deterministic: two
    executors with the same state produce byte-identical
    snapshots.
  - `Node::assemble_from_snapshot()` assembles a node from config
    and restores from a snapshot in one call — the node is ready
    for consensus immediately.
  - Snapshot import validates internal consistency (state root
    matches module roots, module count matches) and is atomic
    (no partial state on failure).
  - **In plain words:** A new node can now start from a snapshot
    instead of replaying the entire chain from genesis. The
    snapshot is verified before installation — a corrupted or
    tampered snapshot is rejected without affecting local state.

- **Exact-pinned production dependencies**
  (`Cargo.toml`, `deny.toml`)
  - All workspace dependencies are now exact-pinned (`=X.Y.Z`)
    to prevent silent transitive upgrades.
  - `cargo deny check` passes all four gates: advisories, bans,
    licenses, sources.

- **Authenticated leader proposals with execution certificates**
  (`crates/types/src/lib.rs`, `crates/consensus/src/engine.rs`)
  - `BlockHeader` now carries an optional proposer BLS signature and
    an optional `ExecCertificate` — a quorum attestation of the
    execution result (state root) of a previous block.
  - The consensus engine detects state divergence: when a proposal
    carries an `exec_cert`, the engine compares the certified state
    root to its locally computed state root and refuses to vote if
    they differ. This prevents extending a divergent chain.
  - **In plain words:** validators now cryptographically prove they
    agree on the result of executing each block. If a validator's
    local computation differs from the network's consensus, it stops
    voting rather than silently extending a wrong chain.

- **`JournalBackend` — authenticated storage backend**
  (`crates/storage/src/auth_journal.rs`)
  - `AuthenticatedJournal` now implements the `StorageBackend` trait,
    combining an in-memory `BTreeMap` for fast reads with the
    journal+MMR for durability and authentication.
  - Every `apply_batch` appends a serialized record to the journal
    and pushes to the MMR. The state root (BLAKE3 hash of all
    key-value pairs) and the MMR log root are both available.
  - `capabilities()` returns `authenticated: true`.
  - **In plain words:** the storage layer now has a backend that
    proves state hasn't been tampered with — every change is
    permanently recorded in an authenticated log that any node can
    verify from genesis.

- **Deterministic swarm simulation with `ScenarioRunner::run()`**
  (`sim/src/swarm.rs`)
  - The `ScenarioRunner` now executes simulations: creates a
    multi-node devnet, applies network partitions, runs consensus
    rounds, and checks safety (no forks) and liveness (blocks
    finalize).
  - New `partition_one_7` scenario: 7 nodes, one partitioned — the
    remaining 6 must still finalize (BFT liveness).
  - **In plain words:** the simulation harness can now actually run
    consensus scenarios with network partitions and verify that the
    blockchain stays safe and live under adverse conditions.

- **Byzantine fault injection harness for TCP multi-node devnet**
  (`crates/devnet/src/byzantine.rs`)
  - A test harness that wraps `TcpMultiNodeDevnet` and injects
    Byzantine behavior into specific validators over the real TCP
    transport.
  - Supported behaviors: invalid votes, forged signatures,
    equivocation, malformed/truncated messages, unknown message
    tags, and non-responsive (no-vote) validators.
  - `verify_honest_convergence()` checks that all honest
    validators agree on finalized height and state root after
    Byzantine injection.
  - 9 tests: assembly, index validation, 6 injection scenarios,
    and 2 convergence tests (4 validators with f=1, 7 validators
    with f=2).
  - **In plain words:** the testnet can now simulate faulty
    validators that send bad votes, forge signatures, equivocate,
    or go silent — and verify that the honest validators still
    reach consensus and agree on the chain state.

- **Full KV snapshot sync with disk-backed EVM persistence**
  (`crates/node/src/lib.rs`, `crates/executor/src/lib.rs`,
  `modules/evm/src/lib.rs`)
  - `ExecutorSnapshot` now carries per-module state payloads via
    `module_state: Vec<Vec<u8>>`, enabling complete state transfer
    (not just metadata).
  - The `Module` trait has `export_state`/`import_state` default
    methods; EVM implements them to serialize account/code/storage
    state.
  - `NodeConfig.storage_path: Option<PathBuf>` configures a
    disk-backed redb storage backend. When set, EVM state persists
    across restarts.
  - `full_kv_snapshot_sync_restores_evm_state` test: exports EVM
    state from a source node, imports it into a fresh destination
    node, and verifies the EVM state root matches.
  - **In plain words:** a node can now export its full state
    (including EVM accounts, code, and storage) and transfer it to
    a new node. A node configured with a disk path persists EVM
    state to disk and restores it on restart.

- **Per-peer ingress rate limiting for DoS protection**
  (`crates/p2p/src/rate_limit.rs`)
  - A token-bucket rate limiter that throttles inbound messages on
    a per-peer basis. Each peer gets a bounded token budget;
    messages consume tokens proportional to their size.
  - Integer-only arithmetic, no allocations on the hot path, lazy
    idle eviction to bound memory.
  - 8 tests covering admission, overflow, refill, multi-peer
    tracking, idle eviction, reset, remove, and capacity cap.
  - **In plain words:** each peer gets a bandwidth budget. If a
    peer floods the node with messages, its budget runs out and
    subsequent messages are dropped until the budget refills.

- **State pruning for the append-only journal**
  (`crates/storage/src/prune.rs`)
  - Segment-level pruning that deletes old journal segment files
    when they exceed a configurable retention window (default:
    keep last 1000 segments, ~256 GiB).
  - Always retains the active segment and all segments within the
    retention window. Reports bytes freed and segments deleted.
  - `disk_usage()` and `segment_count()` utilities for monitoring.
  - 12 tests covering parsing, retention, edge cases, and byte
    accounting.
  - **In plain words:** old block history files are automatically
    deleted when they exceed the retention window, keeping disk
    usage bounded without losing recent history.

- **Full auto-deleveraging (ADL) implementation**
  (`modules/perps/src/lib.rs`)
  - Replaced the placeholder ADL event with a full ranking and
    execution algorithm. When the insurance fund is depleted, ADL
    deleverages profitable counterparties to cover the shortfall.
  - Ranks by PnL descending, size descending, address ascending for
    determinism. Integer-only arithmetic.
  - Emits `adl_executed` events per counterparty and
    `adl_shortfall_remaining` if unrecoverable.
  - 3 stress tests: triggers on fund depletion, ranks by profit,
    deterministic.
  - **In plain words:** when the insurance fund runs out, the system
    automatically reduces the positions of the most profitable traders
    to cover the losses, in a deterministic order.

- **Oracle robustness for mark prices**
  (`modules/perps/src/lib.rs`)
  - Added a 10% maximum mark price change per update to prevent a
    malicious or buggy oracle from causing cascading liquidations.
  - `set_mark_price` rejects updates deviating more than 10% from
    the current mark. `set_mark_price_unchecked` bypasses for
    testing/genesis.
  - 7 tests covering accepted/rejected changes, boundary, and
    deviation calculation.
  - **In plain words:** the oracle can't move the price by more than
    10% in a single update, protecting against manipulation and bugs.

### Benchmark Results (M2 MacBook Pro, release profile)

- **Matching engine: 56.27M orders/s** (raw engine, single-thread).
  The mixed trading workload (resting + matching + cancel) runs at
  18.1K ops/s per market.
- **EVM transfers: ~17K tx/s single-threaded, ~100K tx/s parallel**
  (8-core Rayon, 10K-tx batches with pre-recovered signatures).
  Native module execution is 4.5× faster than revm (126K vs 28K tx/s).
- **Consensus: 316K votes/s** (BLS verification is the bottleneck at
  3.16µs/vote; block proposal is 62ns).
- **Executor: 360K native tx/s** (block pipeline, 100-1000 tx
  batches). Execute-only path hits 654K tx/s.
- **Perps: 1.32M place-with-margin/s**, liquidation checks at
  6.19M/s.
- **Exchange settlement: 800K fills/s** (2.05M fills/s raw engine).

### Added (previous)

- **Multi-market parallel matcher — one worker thread per market,
  shared sharded balances, all four protocols routed by market ID**
  (`crates/matcher/src/lib.rs`, `crates/matcher/src/balance.rs`,
  `crates/matcher/src/server.rs`, `bin/oxide-matcher/src/main.rs`,
  `bin/oxide-loadgen/src/main.rs`)
  - **`ShardedBalanceCache`**: N shards (default 64), each a
    `Mutex<HashMap>`. Address → shard via hash. Two-account
    operations acquire both shards in canonical order (lower index
    first) to avoid deadlock. `check_and_debit` is atomic under one
    shard lock — a buyer cannot overdraw by racing two markets
    simultaneously. Concurrency test: 8 threads × 1000 transfers, no
    overdraw.
  - **`MultiMarketMatcher`**: one `MatchingEngine` per market, one
    worker thread per market, shared sharded balances. Work and
    control commands (seal/stats) share one `mpsc` channel per
    market — a single `recv()` handles both, avoiding the
    missed-wakeup deadlock that the two-channel design caused.
    Implements `BatchSealer` so `BatchSettler` works with it.
  - **`run_server_multi`**: all four protocols (binary TCP,
    JSON-RPC, FIX, WebSocket) have multi-market variants. Orders
    routed by `OrderRequest.market`. Fast path: all orders in a
    batch for the same market → one channel send. Slow path: mixed
    markets → split by market, re-sort by original index.
  - **Runtime mode flag**: `oxide-matcher --mode multi|ring|mutex`.
    `multi` (default) = multi-market parallel, N worker threads.
    `ring` = single-market ring matcher (existing path). `mutex` =
    single-market mutex matcher (existing path). `--markets N`
    (default 128) and `--shards N` (default 64) control multi mode.
  - **Load generator**: `oxide-loadgen --markets N` (default 1).
    `generate_orders_grouped` groups orders by market per batch so
    each TCP batch hits the multi-market fast path.
  - **Tests**: 6 new multi-market e2e tests (basic match per market,
    no cross-market matching, mixed batch slow path, balance
    conservation, 128-market stress, rejection isolation) + 2 new
    unit tests (two-market independent matching, atomic balance
    check across markets) + 6 new sharded balance tests (fund,
    credit/debit, overdraw rejection, same-shard transfer,
    cross-shard transfer, concurrent transfers no overdraw).
  - **Benchmark (100M orders, 1000 accounts, 16 conns, batch=1000,
    release, macOS):** multi mode 11.68M orders/s (128 markets),
    ring mode 15.15M (1 market), mutex mode 17.87M (1 market). The
    multi path is slower per-core than single-market paths due to
    cross-thread channel overhead and 128 workers oversubscribing
    8 cores, but it scales with market count — the single-market
    paths cannot scale beyond one book.

  **In plain words:** The matching server can now run 128 markets
  in parallel, each on its own worker thread with its own order
  book, sharing a sharded balance cache that prevents any account
  from overdraw across markets. All four order-entry protocols
  (binary TCP, JSON-RPC, FIX, WebSocket) route orders to the
  correct market by market ID. The server has three runtime modes:
  `multi` (parallel, 128 markets, 11.7M orders/s), `ring`
  (deterministic single-market, 15.1M), and `mutex` (fastest
  single-market, 17.9M). The multi-market path is the production
  architecture for exchanges with many instruments — it scales
  with core count, while the single-market paths are capped at one
  book. The balance cache uses per-shard mutexes (a known hot-path
  lock that the next iteration will replace with lock-free atomics).

- **Ring matcher is now the production order path — one order book,
  all four protocols**
  (`crates/matcher/src/lib.rs`, `crates/matcher/src/server.rs`,
  `bin/oxide-matcher/src/main.rs`)
  - **Control channel**: `RingMatcher` now services `Seal`/`Stats`
    commands from the batch settler and monitoring — the owner
    thread reaches THE one book without a second server.
  - **`BatchSealer` trait**: `BatchSettler` works with either
    `SharedMatcher` (mutex seal) or `RingMatcher` (control-channel
    seal) — both seal from the single book.
  - **All four protocols routed through the rings**:
    `run_binary_tcp_server_ring`, `run_jsonrpc_tcp_server_ring`,
    `run_fix_server_ring`, `run_websocket_server_ring`. One shared
    ring counter gives every connection a unique ring pair across
    ALL protocols — responses never interleave.
  - **`run_server_ring`**: new production entry point. The funded
    `MatchingServer` is moved to the ring owner thread — it IS the
    one book. `oxide-matcher` binary now uses this path.
  - **Verified**: unit test proves seal returns the fills produced
    via the ring; live server shows JSON-RPC sell → buy fills and
    FIX NewOrderSingle → ExecutionReport against the same book.
  - **Benchmark (100M orders, 16 conns, batch=1000):** ring path
    11.80M orders/s vs mutex path 15.74M. The ring trades raw batch
    throughput (single-owner serial matching) for determinism, zero
    contention, and provably-one-book. Mutex path remains available
    via `run_server`.

  **In plain words:** The matching server now runs on the lock-free
  ring architecture in production — one thread owns the single
  order book, and all four order-entry protocols (binary TCP,
  JSON-RPC, FIX, WebSocket) submit through lock-free rings to that
  one book. The batch settler reaches the same book through a
  control channel. Throughput is 11.8M orders/s (the mutex path was
  faster at 15.7M because it matches on multiple cores in parallel,
  but it has lock contention; the ring is deterministic and never
  contends). Every path — every protocol — shares exactly one
  order book.

- **Ring matcher wired into TCP server + verified remaining optimizations**
  (`crates/matcher/src/ring.rs`, `crates/matcher/src/lib.rs`,
  `crates/matcher/src/server.rs`)
  - **SPSC ring matcher** now routes orders through lock-free
    per-connection rings (no mutex on the order path). Each ring item
    is a whole batch — one mpsc send per batch, not per order.
    `run_binary_tcp_server_ring` exposes the ring path; the mutex
    path remains for compatibility.
  - **Verified already implemented**: Block-STM parallel EVM execution
    (sender-grouped, COW CacheDB snapshots, 4-16x with conflicts),
    native EVM precompiles (bank/exchange/perps), batch BLS
    verification (one pairing for N-validator QCs), direct bank
    settlement (no intermediate dispatch).
  - **Deferred with reasons**: io_uring (Linux-only), CPU pinning
    (no portable std API), huge pages (Linux-only), prefetch
    (single-level-dominant workloads), flat EVM state arrays (large
    refactor), optimistic settlement (fraud-proof framework needed),
    memory-mapped state (Phase 4).
  - **Final benchmark (100M orders, 16 conns, batch=1000):**
    **15.74M orders/s** — 2.02x over the original 7.80M orders/s.
    Ring path: 7.67M orders/s (mutex batch path still wins for
    single-connection batch throughput; ring wins on latency).

  **In plain words:** The remaining optimizations are now done:
  Block-STM, native precompiles, and batch BLS verification were
  already in the codebase — this session verified them and wired the
  lock-free SPSC ring matcher into the TCP server. The final
  benchmark sustains 15.7M orders/s on a 100M-order run through real
  TCP connections, 2x faster than the original 7.8M. The remaining
  roadmap items (io_uring, CPU pinning, huge pages, optimistic
  settlement) are deferred because they're platform-specific or
  security-critical.

- **Hyper-optimizations: 2x throughput improvement** (flat array,
  fill aggregation, async execution, lock-free mempool)
  (`crates/matcher/src/balance.rs`, `crates/matcher/src/server.rs`,
  `crates/executor/src/lib.rs`, `crates/node/src/lib.rs`)
  - **Flat array balance cache**: replaced `HashMap<Address, u64>`
    with `Vec<u64>` indexed by account index. O(1) direct indexed
    access — no hash, no probe. 45% faster on the binary benchmark
    (16.98M vs 11.65M orders/s).
  - **Aggregate fills by account pair**: `BatchSettler` now groups
    fills by (buyer, seller), computes net amount, submits one
    `BatchFillEntry` per unique pair. 2-5x fewer settlement entries.
  - **Async execution lane**: enabled `executor.enable_async_execution()`
    in `Node::assemble`. Overlaps execution of block h-1 with
    consensus for block h.
  - **Lock-free mempool intake**: added MPSC ring to `Executor`.
    `ingest_tx` validates + pushes to ring without locking the
    mempool; `prepare_proposal` drains under a single lock.
  - **SPSC ring buffer**: added `ring.rs` with `SpscSender`/
    `SpscReceiver` and `RingMatcher` — lock-free alternative to
    `SharedMatcher` using per-connection SPSC rings.
  - **Combined result**: 16.1M orders/s on 100M-order run (2.07x
    faster than previous 7.8M), 16.98M orders/s on 1M-order run
    (46% faster than previous 11.65M).

  **In plain words:** Oxide's matching server now sustains 16.1M
  orders/s through real TCP connections — a 2x improvement from the
  previous 7.8M. The key changes: balances are stored in a flat
  array (not a hash map), fills are aggregated by trading pair (not
  per-fill), consensus execution overlaps with voting, and the
  mempool uses a lock-free ring for transaction intake. These are
  the same optimizations that power Hyperliquid and CME's matching
  engines.

- **Standalone matching server + load generator binaries** (real
  binary TPS benchmark)
  (`bin/oxide-matcher/`, `bin/oxide-loadgen/`)
  - Two new binaries that run as separate processes over real TCP:
    - **`oxide-matcher`**: assembles a full single-node Oxide devnet
      (executor + bank + exchange + perps + EVM modules), funds
      accounts, wires the batch settler to the executor's mempool, and
      starts all four protocol servers (binary TCP, JSON-RPC, FIX,
      WebSocket). Drives consensus in a background thread.
    - **`oxide-loadgen`**: connects to the matching server via binary
      TCP and submits orders at scale. Three modes: `sync` (baseline),
      `pipe` (pipelined), `batch` (M connections × batch requests).
  - **Binary benchmark results** (separate processes, real TCP, full
    devnet running):
    - 100k orders sync: 43,925 orders/s (22.77 µs/order)
    - 1M orders pipelined (pipe=500): 395,074 orders/s (2.53 µs/order)
    - 1M orders batch (8 conns, batch=500): 11,645,991 orders/s
    - 10M orders batch (8 conns, batch=500): 5,469,929 orders/s
    - **100M orders batch (16 conns, batch=1000): 7,802,348 orders/s**
      (12.82s, 0.128 µs/order)

  **In plain words:** Oxide now has standalone binaries for the
  matching server and load generator. Running them as separate
  processes over real TCP, the matching server sustains 7.8M orders/s
  on a 100M-order run with a full Oxide devnet (executor + bank +
  exchange + perps + EVM) running underneath. The batch endpoint packs
  1000 orders into a single TCP message, processes them under one
  mutex lock, and returns a single batch response — eliminating
  per-order lock contention and syscall overhead.

- **Pipelining + connection pooling + batch endpoint** (135x TCP speedup)
  (`crates/matcher/src/protocol.rs`, `crates/matcher/src/server.rs`,
  `crates/matcher/tests/e2e_optimized.rs`)
  - Three optimizations to close the gap between synchronous TCP
    throughput (70k orders/s) and the in-process ceiling (6M orders/s):
    - **Batch protocol extension**: new binary TCP message type that
      packs N orders into a single request (`[magic][version][0xFF][count][entries]`).
      The server processes all orders under a single mutex lock,
      eliminating per-order lock contention. 95x speedup.
    - **Pipelining**: client sends N requests in a burst, then reads N
      responses. Amortizes TCP round-trip latency. 5.6x speedup.
    - **Connection pooling**: M connections, each sending batch
      requests. Scales horizontally. Combined with batch: 135x speedup.
  - **Benchmark results** (1M orders, 1k accounts, real TCP):
    - Synchronous: 70,062 orders/s (baseline)
    - Pipelining (pipe=500): 390,928 orders/s (5.6x)
    - Batch (batch=500): 6,674,960 orders/s (95x)
    - **Combined (8 conns, batch=500): 9,485,240 orders/s (135x)**
  - The combined throughput (9.5M orders/s) is 450x faster than the
    consensus pipeline (21k tx/s) and exceeds the in-process ceiling
    (6M orders/s) because batch processing reduces per-order overhead.

  **In plain words:** Oxide's matching server now sustains 9.5M
  orders/s through real TCP connections using batch requests and
  connection pooling — 135x faster than the synchronous baseline and
  450x faster than the consensus pipeline. The batch endpoint packs
  500 orders into a single TCP message, processes them under one
  mutex lock, and returns a single batch response. This is the
  HFT-grade order entry layer: clients send batched orders, the
  matcher processes them off-chain, and fills are settled on-chain
  in periodic batches.

- **All-protocol TPS benchmark** (`crates/matcher/tests/e2e_all_protocols.rs`,
  `crates/matcher/src/server.rs`)
  - Benchmarked all four order-entry protocols with 1M orders each
    through real TCP connections:
    - **Binary TCP: 69,589 orders/s** (fastest — pure binary, no parsing)
    - **FIX 4.4: 52,450 orders/s** (SOH-delimited text, institutional)
    - **JSON-RPC: 44,319 orders/s** (JSON over TCP, HTTP-compatible)
    - **WebSocket: 36,014 orders/s** (JSON + WS framing, browser)
  - Added **WebSocket server endpoint** (`run_websocket_server`) using
    `tokio-tungstenite`. Accepts WS connections, receives JSON order
    messages, returns JSON responses. Browser-compatible.
  - Binary TCP is ~2x faster than WebSocket because it avoids JSON
    parsing and WS framing overhead. All protocols are bottlenecked
    by TCP round-trip latency, not matching speed (6M orders/s
    in-process ceiling).

  **In plain words:** All four order-entry protocols are now
  benchmarked end-to-end through real TCP connections. Binary TCP
  leads at 69.6k orders/s, followed by FIX at 52.5k, JSON-RPC at
  44.3k, and WebSocket at 36.0k. The protocol choice matters: Binary
  TCP is ~2x faster than WebSocket. For HFT clients, use Binary TCP;
  for browsers, WebSocket; for institutional desks, FIX; for HTTP
  integrations, JSON-RPC.

- **Batch settlement + server endpoints + e2e TCP benchmark**
  (`crates/matcher/src/server.rs`, `modules/exchange/src/lib.rs`,
  `crates/matcher/tests/e2e_tcp.rs`)
  - **Batch settlement:** added `TAG_BATCH_SETTLE` (tag 3) to the
    exchange module. Applies pre-matched fills from the off-chain
    matching server without re-matching. Each fill debits the buyer
    and credits the seller via the bank module. Emits `batch_fill`
    events. This is the bridge between off-chain matching and on-chain
    settlement.
  - **BatchSettler:** periodically seals the fill buffer, encodes
    fills as a `TAG_BATCH_SETTLE` message, wraps in an Oxide tx
    envelope, and submits to consensus via `TxSubmitter`. Runs on a
    dedicated tokio task (default 100ms interval).
  - **Server endpoints:** four protocol servers that accept client
    connections:
    - Binary TCP (43-byte requests, 13-byte responses; fastest path).
    - JSON-RPC over TCP (line-delimited JSON; `oxide_placeOrder`).
    - FIX 4.4 (`NewOrderSingle` MsgType=D → `ExecutionReport` MsgType=8).
    - Multi-protocol launcher (`run_server` runs all + batch settler).
  - **E2e TCP benchmark:** 10M orders through real TCP connections
    with 10k accounts. **66,828 orders/s** end-to-end (client → TCP →
    match → settle), 5M fills, 1497 settlement txs, 0 rejections.
    Smoke test: 100k orders at 64,886 orders/s.

  **In plain words:** Oxide's matching server now accepts real client
  connections via binary TCP, JSON-RPC, and FIX, matches orders
  off-chain, and batches fills for on-chain settlement through
  consensus. End-to-end TCP throughput is 66.8k orders/s — limited by
  synchronous TCP round-trip latency, not matching speed (6M orders/s
  in-process). The batch settler bridges off-chain matching to on-chain
  settlement: every 100ms, sealed fills are submitted as a single
  settlement transaction that validators verify without re-matching.

- **Off-chain matching server** (`crates/matcher`) (new crate)
  - A high-performance matching server that runs the trading engine
    directly, accepts orders via four protocols, enforces pre-trade
    balance checks on every order, and batches fills for on-chain
    settlement. This is the HFT-grade order entry layer (plan.md §9.5).
  - **Four order entry protocols:**
    - Binary TCP (43-byte request, 13-byte response; pure binary,
      no JSON; the fastest path).
    - WebSocket (JSON over WebSocket; browser-compatible).
    - JSON-RPC (`oxide_placeOrder` method; HTTP-compatible with
      existing RPC server).
    - FIX 4.4 (`NewOrderSingle` MsgType=D; institutional trading
      desk protocol; integer arithmetic for price/qty parsing).
  - **Balance check (anti-spam gate):** every buy order is balance-
    checked before matching. Insufficient balance → rejected with
    `RejectReason::InsufficientBalance`. Balance is debited
    immediately (reserved) and credited back on partial fills.
  - **Balance cache:** flat `HashMap<[u8; 20], u64>` — O(1) lookup,
    zero allocation (fixed 20-byte keys). ~10x faster than the
    bank's `BTreeMap<Vec<u8>, Vec<u8>>` for the hot path. Handles
    1M+ accounts.
  - **1B-order benchmark:** 1,000,000,000 orders through 1,000,000
    active accounts with balance checks on every buy order.
    **6,043,301 orders/s** sustained, 500M fills, 0 rejections,
    balance conservation verified. Elapsed: 165.47s.
  - **Protocol codec benchmarks:** binary encode at 648M req/s,
    decode at 444M req/s. The codec is ~100x faster than the
    matching path — the bottleneck is the matching engine + settlement,
    not the wire format.

  **In plain words:** Oxide now has an off-chain matching server
  that accepts orders via binary TCP, WebSocket, JSON-RPC, and FIX,
  balance-checks every order to prevent spam, and sustains 6M
  orders/s with 1M active accounts. This is ~285x faster than the
  consensus-backed path (21k tx/s) because it skips TCP round-trips,
  BLS signatures, and mempool admission — the matching server is
  the HFT-grade order entry layer that batches fills for on-chain
  settlement.

- **Trading TPS tests** (`crates/devnet/tests/trading_tps.rs`,
  `crates/devnet/tests/trading_throughput.rs`)
  - Two new integration tests measuring trading throughput at scale:
    - **Path A — consensus-backed trading TPS** (`trading_tps.rs`):
      exchange order matching + bank settlement through the full
      oxideBFT consensus pipeline (4 validators, real TCP loopback,
      BLS signatures, QC formation, pipelined execution). Verifies
      all validators finalize the same blocks, agree on tx contents,
      agree on exchange resting count, and agree on the state root.
      Default: 200k txs at 36.3k tx/s. Configurable up to 1M fills
      (2M txs) at 21.1k tx/s via `TRADING_ROUNDS=2000`.
    - **Path B — single-node 100M-trade throughput**
      (`trading_throughput.rs`): raw matching engine and exchange
      settlement path (no consensus, no networking). 100M trades
      through the raw `MatchingEngine::place()` at 19.05M fills/s
      (5.25s); 100M trades through `ExchangeModule::handle()` (full
      matching + bank settlement + events) at 1.19M fills/s (84.3s).
      Verifies all 100M makers matched (resting count = 0) and all
      200M events emitted.
  - Extended `TcpMultiNodeDevnet` with `with_exchange_and_base_port`
    to register the `ExchangeModule` (backed by each validator's
    `BankModule`) on every validator. Scaled the pipelined loop
    deadline with the workload (60s base + 5s per 100 rounds) so
    large trading tests complete without timing out.

  **In plain words:** The trading machine now has measured throughput
  numbers at scale — 100M trades through the raw engine in 5 seconds,
  100M trades through the full settlement path in 84 seconds, and
  1M trades through the full 4-validator consensus pipeline in 95
  seconds. All integrity checks pass: no dropped txs, no crossed
  books, all validators agree on state.

- **Trading-stack settlement benchmarks** (`modules/exchange/benches/settlement.rs`,
  `modules/perps/benches/perps_settlement.rs`)
  - Criterion benches measuring the full `Module::handle()` path for
    the exchange and perps modules — the production settlement path
    that was previously unbenched (only the raw matching engine had
    gates). Each bench includes a head-to-head against the raw
    `MatchingEngine::place()` to quantify settlement overhead.
  - Exchange: `settlement_single_fill` (829 ns p50, ~1.2M
    orders/s/core, gate < 2 µs ✅), `settlement_sweep_10_levels`
    (3.08 µs p50, ~325k sweeps/s/core, gate < 10 µs ✅),
    `raw_engine_single_fill` baseline (459 ns). Settlement overhead
    ~370 ns/fill — dominated by the bank's `BTreeMap<Vec<u8>, Vec<u8>>`
    lookups and `Vec` key allocations.
  - Perps: `perps_place_with_margin` (723 ns p50, ~1.38M orders/s/core,
    gate < 3 µs ✅), `perps_deposit` (274 ns p50, ~3.65M deposits/s/core,
    gate < 2 µs ✅), `perps_liquidation_check` (150 ns p50, ~6.7M
    checks/s/core, gate < 5 µs ✅), `raw_perps_engine_place` baseline
    (406 ns). Perps overhead ~316 ns/fill — less than exchange because
    perps does not call `bank.transfer` per fill, only on explicit
    margin deposits/withdrawals.
  - All gates pass. Method: module + bank created once outside the
    bench (`handle` takes `&self` via internal Mutex); setup only
    rests a maker; the measured section places a taker. This avoids
    the `iter_batched` by-value drop-in-measured-section regression
    documented in the trading crate bench.

  **In plain words:** The full trading settlement path — matching
  plus bank transfer plus event emission for spot, and matching
  plus position update plus margin check for perps — is now
  benchmarked and gated. The settlement path sustains ~1.2M
  orders/s/core for spot and ~1.38M for perps, with the bank's
  BTreeMap identified as the next optimization target.

- **Perpetual futures module (`modules/perps`)** (new module)
  - Cross and isolated margin per account/market, with signed
    position sizes (long/short) and volume-weighted average entry
    prices.
  - Mark price setter (deterministic, stands in for the deferred
    oracle module) driving unrealized PnL and liquidation.
  - Funding settlement (basis-point rate, longs pay shorts on
    positive rate).
  - Liquidation: equity vs. maintenance margin check, position
    closure, penalty credited to the insurance fund.
  - Insurance fund and ADL structure.
  - Wired to the shared `BankModule` for margin deposits and
    withdrawals (same cross-module settlement pattern as the
    exchange module).
  - 17 unit tests covering market listing, deposits, position
    opens via matching, long/short PnL, funding, liquidation,
    insurance fund, and message dispatch.

  **In plain words:** Oxide now has a native perpetual futures
  module with margin, funding, and liquidation — the second leg of
  the trading stack after the spot exchange.

- **Read-only EVM precompiles for native market state**
  (`modules/evm/src/precompiles.rs`)
  - Five new precompile addresses bridging EVM contracts to native
    exchange and perps state: exchange best bid (`0x05_01`),
    exchange best ask (`0x05_02`), perps position (`0x06_01`),
    perps mark price (`0x06_02`), perps insurance fund
    (`0x06_03`).
  - `NativePrecompiles` provider wraps `EthPrecompiles` and
    implements revm's `PrecompileProvider` trait, so all EVM
    execution paths (single-tx, batch, parallel) use the custom
    precompile set.
  - `EvmModule::set_native_modules` wires the exchange and perps
    module handles into the EVM. The node assembly wires them
    during `Node::assemble`.
  - 10 new precompile tests (23 total).

  **In plain words:** EVM smart contracts can now read native
  exchange and perps market state (best bid/ask, positions, mark
  prices, insurance fund) via fixed precompile addresses — no
  Solidity reimplementation needed.

- **Trading fuzz targets** (`fuzz/fuzz_targets/`)
  - `trading-engine`: feeds arbitrary order sequences to the
    matching engine, asserts no panics, verifies the no-crossed-book
    invariant.
  - `trading-order-validate`: feeds arbitrary order fields to the
    validator, asserts no panics.

  **In plain words:** The matching engine and order validator are
  now fuzz-tested for crash resistance and invariant preservation.

- **Deterministic trading simulation** (`sim/tests/trading.rs`)
  - `deterministic_trading_scenario`: a fixed sequence of exchange
    orders, perps deposits, position opens, funding, liquidation,
    and insurance fund inspection — all deterministic, reproducible
    run-to-run.
  - `exchange_l1_invariant`: verifies the exchange L1 data is
    consistent (no crossed book) after a sequence of orders.

  **In plain words:** The trading stack now has a deterministic
  simulation that exercises exchange matching, perps margin, funding,
  and liquidation end-to-end — the foundation for reproducible
  trading bug hunting.

- **Native HFT matching engine (`crates/trading`)** (new crate)
  - A first-principles, std-only matching engine library built for
    HFT-grade throughput: slab-arena order pool with `u32` indices
    and free-list recycling (zero allocation after warm-up),
    intrusive doubly-linked FIFO queues for strict price-time
    priority, open-addressed order-ID locator, hierarchical bitboard
    for O(1) best-bid/ask discovery, and a dense tick-indexed ladder
    behind a `BookBackend` seam (sparse backend pluggable later).
  - Full order semantics: limit, market, GTC, IOC, FOK, post-only,
    reduce-only, and STP (cancel-oldest/newest/both). Deterministic
    fill ordering for consensus replay.
  - Fixed-point `Price`/`Qty` throughout — no floats in consensus
    state.
  - 48 unit tests + 1 property test (proptest) comparing the engine
    against an independent BTreeMap/VecDeque sequential-model oracle.
  - Criterion benchmarks on an M-series dev Mac (relative baseline):
    insert/cancel 12.8 ns/op (gate < 200 ns), derived per-match-op
    ~160 ns (gate < 300 ns), mixed workload ~22.5M ops/s/core (gate
    ≥1M ops/s/core). All Phase 3 gates pass.
  - **In plain words:** the core matching engine that will power
    Oxide's spot and perpetuals exchanges is built, tested, and
    benchmarked. It handles order placement, cancellation, and
    matching at ~78M simple operations per second per core — far
    exceeding the 5M ops/s gate — with strict price-time priority
    and deterministic replay. This is the foundation; the exchange
    module and EVM precompiles come next.

- **Spot CLOB exchange module (`modules/exchange`)** (new module)
  - The on-chain home of the native matching engine: wraps one
    `MatchingEngine` per market behind the `Module` trait, with a
    compact wire format for place/cancel/list-market messages. The
    tx sender becomes the order owner; cancel is owner-authorized.
  - Emits fill events (price, qty, maker/taker owners) and outcome
    events (resting/filled/canceled/killed/rejected) for the
    executor's event log. Reuses one fill buffer across all calls
    in a block — zero allocation after the first call.
  - Registered in the node with a default spot market (tick 0.01,
    lot 0.001, [$10, $20]).
  - 13 unit tests covering market listing, order placement, fills,
    cancel authorization, rejection paths, and L1 market data.
  - **In plain words:** the exchange module connects the HFT
    matching engine to the blockchain. Users can place and cancel
    orders via transactions; the module produces deterministic fill
    events that all validators agree on. Settlement (moving
    balances) arrives with the cross-module coordinator.

- **Empty-code-call fast path for EVM execution** (performance)
  - Calls to accounts with no runtime bytecode now bypass the revm
    interpreter entirely — no call-frame setup, no journal, no
    bytecode analysis. The fast path handles gas calculation
    (including EIP-7623 floor gas), balance transfers, nonce
    increments, and coinbase tips natively.
  - Wired into all three execution paths: sequential, parallel
    (speculative), and conflict re-execution. All paths produce
    identical state roots.
  - Differential tests verify gas and state-root equivalence with
    revm for both single-tx and multi-tx scenarios.
  - **In plain words:** transactions that call an address with no
    contract code (a common case in the current workload mix) now
    skip the EVM interpreter, reducing per-transaction overhead.
    This is not a JIT compiler — it is a shortcut for the degenerate
    case where there is no code to execute. True JIT compilation is
    not available in revm 42.

### Performance

- **Mempool selection walked the whole pool every block**
  (`crates/mempool/src/lib.rs`)
  - `select` scanned the entire fee bucket plus a per-block
    `retain` over all buckets — O(pool) per proposal. At a
    2M-entry pool the 2000-round trading test finalized ~0.4
    blocks/s. Selection is now a sender-fair max-heap of
    (head-tx fee density, sender) walked along each sender's
    contiguous nonce chain: O(senders + selected·log senders).
    `by_fee` survives only for pool-full eviction, lazily pruned.
  - **In plain words:** proposing a block no longer re-reads
    every pending transaction — the sustained 2M-tx trading run
    now finalizes at 8.7 blocks/s (8,684 tx/s).

- **Incremental EVM state root** (`modules/evm/src/lib.rs`)
  - `state_root` no longer re-hashes every address, re-encodes
    every account, and re-sorts all leaves per call. A
    `BTreeMap<keccak(addr) → RLP leaf>` is patched for touched
    accounts only; it rebuilds once after construction or
    snapshot import.
  - 100k accounts / 10 touched: 45.1 ms vs ~72 ms full rebuild
    (~37%). The residual O(n) is `HashBuilder`'s intrinsic leaf
    hashing — a sparse retained trie is the O(touched·log n)
    follow-up.
  - **In plain words:** each block re-derives the state root for
    only the accounts that changed, not the whole state.

- **Every event and vote signature heap-allocated for no reason**
  (`crates/executor/src/lib.rs`, `crates/consensus/src/engine.rs`,
  all modules)
  - `Event.kind` is now `&'static str` — all ~35 event sites
    emitted static literals into a `String`, allocating once per
    event (fill, funding, liquidation) for nothing.
  - `vote_signing_message` is a `[u8; 49]` stack array instead of
    a per-vote `Vec`.
  - **In plain words:** the two most frequent allocations on the
    trading and consensus hot paths are gone entirely.

- **Perps cloned whole maps and positions on liquidation/funding
  paths** (`modules/perps/src/lib.rs`)
  - `margin_check` no longer clones configs, marks, and the whole
    account per post-trade call — shared borrows of disjoint
    fields suffice.
  - `liquidation_check` splits into a read-only solvency phase and
    a destructured mutation phase that closes positions in the
    same pass it totals losses (was two passes + three clones).
  - `auto_deleverage` reads `inner.marks` directly (its old
    signature forced a marks clone) and collects scalar candidate
    tuples instead of `Position` clones.
  - `apply_funding` collects `(addr, amount)` instead of a
    `Position` clone per holder.
  - **In plain words:** liquidation and funding — the paths that
    fire exactly when the market is busiest — no longer copy the
    entire account book before doing math.

- **P2P writer flushed and syscalled per queued frame**
  (`crates/p2p/src/tcp.rs`)
  - `PeerStream::write_frames` batches a drained outbound queue:
    `TcpStream` builds one contiguous frame buffer (one
    `write_all` + one `flush` per drain); `SharedStream` (TLS)
    takes the lock once and flushes once, also closing a
    mid-batch interleave window.
  - The writer loop drains up to 64 queued messages per batch —
    consensus bursts (votes → QCs) now cost one syscall + one
    flush instead of N of each.
  - **In plain words:** vote and QC bursts go out in a single
    socket write instead of a syscall per message.

- **Consensus and executor history maps grew without bound**
  (`crates/consensus/src/engine.rs`, `crates/executor/src/lib.rs`)
  - `OxideBft::blocks` now drops stale proposals at-or-below the
    committed height — a byzantine leader can no longer flood the
    block store for a memory DoS.
  - `OxideBft::finalized`, `Executor::finalized`, and
    `Executor::state_roots` are capped at the newest 4096 heights;
    full history stays in the journal.
  - **In plain words:** validators no longer leak memory every
    block, and a hostile proposer can't bloat node RAM.

- **Journal history grew forever with no integrity-safe pruning**
  (`crates/storage/src/journal.rs`, `auth_journal.rs`, `mmr.rs`)
  - `JournalBackend::checkpoint()` writes a marker committing the
    state root and MMR checkpoint `(leaf_count, peaks)`;
    `prune_below` deletes sealed segments under the marker
    (never the active one).
  - `open_with_snapshot` rebuilds base state from the caller's
    snapshot, verifies it against the marker's committed root,
    and resumes the MMR — the resumed log root is identical to
    the unpruned root, so pruned and archive nodes agree.
  - Every failure is loud: `CheckpointWithoutSnapshot`,
    `SnapshotMismatch`, `MalformedCheckpoint`,
    `IntegrityMismatch`.
  - **In plain words:** a node can finally discard old journal
    history without corrupting its state or silently diverging
    from the rest of the chain.

- **Mempool `select` cloned every chosen transaction and let one
  sender monopolize a block** (`crates/mempool/src/lib.rs`)
  - Selection now moves `TxBytes` out of `by_hash` in order
    (zero clones), and index cleanup is a single
    `BTreeMap::retain` pass per bucket.
  - New `max_per_sender` cap (default 1000,
    `with_max_per_sender`) bounds any account's block share —
    a top-fee spammer can no longer starve other senders.
  - **In plain words:** block proposals no longer copy every
    transaction, and a single whale can't fill an entire block.

- **EVM batch path cloned every transaction's bytes up to three
  times** (`crates/executor/src/lib.rs`, `modules/evm/src/lib.rs`)
  - `PreverifiedTx` now borrows `raw: &[u8]` instead of owning a
    `Vec<u8>`; the preverify cache stores only the recovered sender
    and re-borrows the payload from block bytes at execution time;
    batch entry points take `impl AsRef<[u8]>` so no per-tx clone
    happens at any layer.
  - **In plain words:** the block-execution hot path no longer
    allocates or copies transaction bytes — ~30k fewer `Vec<u8>`
    allocations per 10k-tx block.

### Fixed

- **Devnet TPS harness crashed or starved under sustained load**
  (`crates/devnet/src/tcp_multinode.rs`,
  `crates/devnet/src/evm_workload.rs`)
  - `TCP send … UnknownPeer` panic: the transport removes a dropped
    peer's writer channel and reconnects after ~500ms, so `send`
    fails transiently during the gap. Vote sends now retry next
    tick; QC sends skip failed peers.
  - The EVM workload declared `gas_limit = 30M` (the whole block)
    per tx, so proposal gas accounting admitted exactly one tx per
    block. Per-type declared limits (25k/100k/100k/50k) and a
    devnet block cap matching the 1-gigagas consensus budget fix
    it — `evm_load` now finalizes all txs with identical state
    roots across validators.
  - Pipeline deadline scales as 60s + 250ms/round; the old formula
    made the 2000-round trading test impossible to finish.
  - **In plain words:** the multi-validator load tests now survive
    transient disconnects and run their full transaction count.

- **EVM parallel execution dropped nonces on conflict re-execution**
  (`modules/evm/src/lib.rs`)
  - The tx-granular conflict re-execution path kept speculative
    results for non-conflicting txs but never applied their state
    changes (nonce increments, balance deductions) to the main DB.
    When a later tx in the same sender group was re-executed, the
    main DB had a stale nonce, causing `NonceTooHigh` failures.
  - In the devnet workload (100 senders, 10 txs each, mixed tx
    types), this caused 441 out of 1000 transactions to fail.
  - Replaced tx-granular re-execution with full-group re-execution:
    when any tx in a group conflicts, the entire group is
    re-executed sequentially against the main DB, preserving nonce
    continuity.
  - Added regression test `handle_batch_parallel_conflict_nonce_continuity`.
  - **In plain words:** EVM load tests at scale now pass with all
    transactions succeeding and correct state roots across validators.

- **Real-time progress reporting in pipelined tx runner**
  (`crates/devnet/src/tcp_multinode.rs`)
  - The pipelined tx runner (used by trading TPS and EVM load
    tests) previously ran silently for minutes on large workloads.
    Now prints finalized txs / total, block count, throughput, and
    elapsed time every 5% of blocks or every 5 seconds.
  - **In plain words:** long-running load tests now show live
    progress instead of a multi-minute silence.

- **Matcher balance cache aliased colliding addresses and minted
  money on insolvent transfers** (`crates/matcher/src/balance.rs`)
  - `BalanceCache` keyed the flat array by the first 4 address
    bytes only — two different addresses sharing those bytes
    silently read and wrote each other's balance. Only canonical
    sequential addresses (`[u32 index LE][0; 16]`) live in the flat
    array now; everything else goes to the full-20-byte sparse map.
  - `iter()` silently excluded every sparse balance.
  - `ShardedBalanceCache::transfer` saturated the debit to zero
    but credited the full amount — an insolvent sender paid the
    recipient out of thin air. It now returns `false` and moves
    nothing when the sender can't cover the amount.
  - **In plain words:** accounts can no longer share balances by
    accident, and insolvent transfers fail instead of creating
    money.

- **Failed settlement submissions lost matched trades and wedged
  the settlement lane** (`crates/matcher/src/server.rs`)
  - `BatchSettler::settle_now` drained the fill buffer and burned
    a nonce before submitting — a failed `submit_tx` dropped real
    fills, and the nonce gap made every later settlement get
    nonce-skipped forever.
  - Failed envelopes are now retried verbatim (the executor still
    expects that nonce), sealing pauses while a batch is pending
    (fills accumulate, nothing lost), the nonce advances only on
    success, and a permanently-dead envelope is dropped loudly
    after 60 retries with its nonce reused by the next batch.
  - **In plain words:** a transient mempool rejection can no
    longer erase matched trades or permanently stall settlement.

- **Journal restart dropped integrity checks and snapshot imports
  lost their data** (`crates/storage/src/auth_journal.rs`)
  - `JournalBackend::open` never verified the journal against a
    trusted root and discarded the reconstructed MMR — post-restart
    `log_root()` reflected an empty log and new appends forked off
    history. `open` now takes `expected_root: Option<Hash>` (the
    caller's last `log_root()`), keeps the rebuilt MMR, and fails
    fatally with `OpenError::IntegrityMismatch` on disagreement
    (which also catches truncated tails).
  - `snapshot_import` journaled only a state root with zero ops —
    the imported entries vanished on restart. The record now
    carries the full replacement (delete-all + set-all) and append
    failures propagate instead of being silently ignored.
  - **In plain words:** reopening a node now proves the journal is
    exactly the history it shut down with, and state snapshots
    actually survive a restart.

- **Most transaction types executed for free**
  (`crates/executor/src/lib.rs`, `crates/node/src/lib.rs`,
  `crates/devnet/`, `bin/oxide-validator/`)
  - The fee charge was dispatched to `module.charge_fee` on the
    *target* module — a no-op default meant only bank txs ever
    paid; exchange, perps, core, and EVM txs ran free, and the
    sender-controlled `ctx.fee` could be 0 anyway.
  - The executor now charges every non-self-funded tx through a
    designated fee collector (`set_fee_module`, wired to the bank
    at node/devnet/validator assembly), plus a `min_fee` floor
    (`NodeConfig.min_fee`) on the sender-declared fee.
  - `Module::pays_own_fee()` exempts self-funded modules: the EVM
    charges gas inside execution (bounded by base fee), so the
    envelope fee would double-charge users.
  - Fees are kept if execution later fails (the fee pays for
    attempted work); a skipped tx doesn't advance its nonce and
    can be resubmitted with adequate fee.
  - **In plain words:** every transaction now pays its declared
    fee through the bank — no more free execution on non-bank
    modules, and a configurable floor stops zero-fee spam.

- **Block gas limit was effectively unenforced**
  (`modules/evm/src/lib.rs`, `crates/executor/src/lib.rs`)
  - `EvmModule` used the default `estimate_gas` (`1000 + msg.len()`),
    so a transaction declaring `gas_limit = 30_000_000` counted as
    ~150 gas — an over-limit block passed proposal validation.
    `estimate_gas` now returns the declared RLP `gas_limit`;
    undecodable payloads count as `u64::MAX` (fail-safe).
  - `prepare_proposal` selected transactions by bytes only and
    ignored `BlockBudget.max_gas` — a proposer could build blocks
    every validator rejects (a wasted round + griefing vector).
    Selection now caps total gas at
    `min(budget.max_gas, block_gas_limit)`, skips oversized txs, and
    skips un-executable txs that would poison the whole proposal.
  - Regression tests: gas-capped proposal builds + validates;
    declared-limit estimation with fail-safe malformed handling.
  - **In plain words:** block gas limits now mean what they say —
    proposals can't exceed them and individual transactions are
    charged their real declared gas.

- **EVM execution under-tracked modified accounts**
  (`modules/evm/src/lib.rs`)
  - The sequential execution paths marked only `caller`, `to`,
    `created`, and `coinbase` as touched. Accounts changed by
    internal calls, `SELFDESTRUCT` beneficiaries, and `SSTORE`
    writes to third accounts were updated in memory but never
    flushed to durable storage nor re-hashed by the incremental
    state root — persistent state could silently diverge.
  - Fix: `evm.transact()` now returns the complete `EvmState` and
    its key set (the exact modified accounts) is recorded before
    committing — applied to single-tx, batch, and parallel
    re-execution paths.
  - `touched` is now a `BTreeSet` — the flush op order is part of
    the journaled state transition, so a `HashSet`'s nondeterministic
    order would have produced divergent journal histories across
    validators.
  - `balance()` saturated instead of panicking on balances above
    `u128::MAX` (reachable via crafted snapshot import).
  - Regression tests: `SELFDESTRUCT` beneficiary tracked + paid;
    `U256::MAX` balance reads as `u128::MAX`.
  - **In plain words:** every account an EVM transaction changes is
    now correctly persisted and hashed, and every validator writes
    state changes in the same order.

- **Consensus allowed voting for conflicting blocks at the same
  height** (`crates/consensus/src/engine.rs`)
  - After voting for block A at view v and timing out, a validator
    would vote for a different block B at the same height in view
    v+1 — the tail-fork check passes on equal parent-QC view and the
    per-view check passes on the new view. Both blocks could form
    QCs and commit divergent state (a committed-chain fork).
  - Fix: `voted_at_height` records the block hash voted at each
    height; a different hash at an already-voted height is refused.
    Locks are pruned on commit so the map stays bounded by in-flight
    heights.
  - Regression test: same-height conflicting proposal refused while
    next-height voting still succeeds.
  - **In plain words:** validators can no longer accidentally help
    notarize two competing versions of the same block — closing a
    path that could split the finalized chain.

- **Perps margin accounting could destroy or create value**
  (`modules/perps/src/lib.rs`)
  - `withdraw` debited margin before crediting the bank — a failed
    bank credit destroyed the user's margin. Now the bank credit is
    attempted first while the margin lock is held.
  - `deposit` debited the bank then `saturating_add`ed margin — a
    deposit overflowing `u64` took bank funds while crediting less.
    Now the margin add is `checked_add` validated before the debit.
  - `apply_funding` debited insolvent payers with `saturating_sub`
    but credited receivers the full computed amount — minting margin
    every funding round. Now two-pass collect-then-distribute:
    receivers share the actually-collected pool pro-rata (exactly
    zero-sum); rounding dust accrues to the insurance fund and a
    `funding_shortfall` event marks under-collection.
  - `handle_place` had no initial-margin gate — positions could be
    opened with zero margin. Orders that increase exposure now
    require `equity >= existing IM + notional / max_leverage`.
  - **In plain words:** deposits, withdrawals, and funding payments
    can no longer silently lose or invent money, and leveraged
    positions now require backing margin.

- **Market buys bypassed the pre-trade balance check**
  (`modules/exchange/src/lib.rs`, `crates/trading/src/`)
  - The balance check was guarded by `order_type != Market`, so an
    unfunded taker could submit a market buy that swept resting
    makers and left every fill unsettled — orders consumed with no
    payment.
  - Fix: new `BookBackend::sweep_cost` walks the opposite side
    best-first accumulating `price × qty` (u128), giving the
    exchange the real cost of a market sweep. All buy orders are now
    checked: limit buys keep the worst-case `price × qty` bound,
    market buys check the actual sweep cost. Over-`u64` amounts
    reject rather than saturating to `u64::MAX`.
  - Regression tests: unfunded market buy rejected (book untouched),
    funded market buy settles the exact sweep cost, partially-
    affordable sweep rejected entirely.
  - **In plain words:** you can no longer place a market buy order
    with an empty wallet and consume other people's resting orders
    for free.

- **Batch settlement was unauthenticated and trusted operator-supplied
  amounts** (`modules/exchange/src/lib.rs`, `crates/matcher/src/`)
  - `handle_batch_settle` ignored `ctx.sender` entirely — any account
    could submit forged fills and drain arbitrary bank balances via
    `bank.transfer`. The wire format also carried a claimed
    `quote_amount` that was never verified against `price × qty`.
  - Fix: batch settle now requires `ctx.sender` to equal the
    genesis-configured `settlement_operator` (fail-closed while
    unset — `NodeConfig.settlement_operator` configures it). Every
    leg is validated against the market's config (listed market,
    positive lot-aligned qty, on-tick price inside the band,
    distinct buyer/seller), the settlement amount is recomputed
    on-chain as `price * qty / PRICE_SCALE` with checked
    `u128`/`u64` math, and legs are aggregated per (buyer, seller)
    pair for one atomic transfer each. Invalid or insolvent legs
    are skipped with `fill_rejected` / `settlement_failed` events.
  - Wire format changed: fill entries are now
    `[market:2][price:8][qty:8][buyer:20][seller:20]` = 58 bytes
    (no claimed amount, market included for config validation).
    The matcher aggregates same-price legs per pair with checked
    qty accumulation.
  - Regression tests: unauthorized sender rejection, disabled
    without operator, six classes of invalid legs, chain-computed
    pair aggregation, credit-overflow rollback.
  - **In plain words:** only the configured matching service can
    settle trades on-chain, and the chain — not the matcher —
    decides how much money moves for each trade. Previously anyone
    could submit a "settlement" transaction that transferred funds
    out of any account.

- **Storage backend benchmark had broken closure syntax** (pre-existing,
  exposed by enabling the `redb` feature)
  - The `crates/storage/benches/backend.rs` file had mangled closure
    syntax in the `#[cfg(feature = "redb")]` and `#[cfg(feature =
    "mdbx")]` sections: `&b, batch | {` instead of `&batch, |b, batch| {`.
  - The `criterion_group!`/`criterion_main!` macros were inside a
    `mod bench` module, so `criterion_main!` couldn't generate the
    crate-level `main` function.
  - Fix: restructured the bench file to move all bench functions to
    crate level, fixed all three backend sections (redb, rocksdb,
    mdbx) in both `bench_apply_batch` and `bench_get`.
  - **In plain words:** the storage benchmark now compiles and runs
    correctly when the `redb` feature is enabled.

- **Pipelined devnet flush round left followers lagging** (P0 correctness)
  - `run_pipelined` and `run_pipelined_txs` checked only the leader's
    `finalized_height()` to decide when to stop the flush round. The
    2-chain commit rule commits block N when block N+1's QC is
    delivered; the leader self-delivers QCs, so it commits faster
    than followers (who receive QCs via TCP). The flush loop exited
    before followers received the last QC, leaving them with zero
    state roots while the leader had non-zero roots.
  - Additionally, `finalized_height().map_or(0, ...)` treated "no
    blocks committed" (`None`) the same as "block 0 committed"
    (`Some(0)`), causing the flush loop to exit immediately when no
    blocks were committed at all (e.g., with `rounds=1`).
  - Fix: check the **minimum** finalized height across ALL validators,
    and use `u64::MAX` as the sentinel for `None` so the loop doesn't
    conflate "no blocks" with "block 0 committed".
  - **In plain words:** all validators in the devnet now finalize the
    same blocks and produce the same state roots. Previously, the
    last block's QC was only delivered to the leader, leaving
    followers with stale state.

- **Preverification cache key mismatch in executor** (P0 correctness)
  - `ingest_tx` cached preverified senders under the full-tx hash, but
    `execute_block` looked them up under the module-payload hash. The
    cache almost always missed, and secp256k1 recovery was repeated at
    execution time. Both paths now use the full-tx hash.
  - **In plain words:** transactions that were pre-verified at
    submission time are now actually reused during block execution,
    eliminating a redundant ~30 µs signature recovery per transaction.

- **Mempool fee-density ordering** (P0 correctness)
  - `FeeDensity` derived `Ord` structurally over `(fee, size)`, sorting
    by absolute fee instead of fee-per-byte. Selection now uses
    cross-multiplication in `u128` to compare exact fee/size ratios.
  - **In plain words:** the mempool now selects transactions by
    fee-per-byte (value density), not by absolute fee — a 100-fee
    36-byte transaction correctly outranks a 200-fee 100-byte one.

- **Consensus certificate validation hardening** (P0 security)
  - `collect_vote` now rejects conflicting votes for different
    `(view, block_hash)` at the same view.
  - `deliver_qc` and `on_timeout_certificate` enforce quorum threshold
    regardless of whether BLS verification is enabled.
  - `deliver_qc` rejects stale QCs (view ≤ current `high_qc` view) to
    prevent replay attacks.
  - **In plain words:** a byzantine validator can no longer mix
    conflicting votes into one QC, forge a QC with fewer than quorum
    signers, or replay an old QC to regress the engine's state.

- **EVM parallel execution read-write conflict detection** (P0 correctness)
  - The parallel executor detected conflicts between speculative
    groups using only the write/touched set, missing read-after-write
    hazards. A later group could read an account written by an earlier
    group, observe stale snapshot state, and commit a divergent result.
    Conflict detection now uses the full access set (every account read
    or written by a group), not only modified accounts.
  - **In plain words:** parallel block execution now produces
    identical state to serial execution even when one transaction
    reads an account that another transaction in the same block
    modifies — a correctness bug that could silently corrupt state
    has been fixed.

- **RPC `eth_sendRawTransaction` now submits to the mempool** (P0 correctness)
  - The RPC handler computed and returned the transaction hash but
    never submitted the transaction to the mempool — submitted
    transactions were silently dropped. The handler now decodes the
    raw RLP, recovers the sender, wraps the transaction in the Oxide
    envelope, and pushes it into the mempool via a `TxSubmitter`
    trait. The validator binary wires the executor into the RPC
    server so submitted transactions enter the mempool and are
    eligible for block proposals.
  - **In plain words:** sending a raw transaction via JSON-RPC
    (MetaMask, Foundry, cast) now actually puts the transaction into
    the mempool. Previously the server returned a hash but the
    transaction was never seen by the executor.

### Changed

- **Split `devnet` into `node` (production) + `devnet` (test harness)** (architecture)
  - The `devnet` crate had a dual identity: it was both the production
    node assembly path (called by `oxide-validator`, `oxide-fullnode`,
    `oxide-deploy`) and the test harness (multi-node runners, workload
    generators, load tests). Production binaries depended on test-only
    code, and the "devnet" name was misleading for a load-bearing
    production path.
  - New `crates/node` crate contains the production node assembly:
    `Node`, `NodeConfig`, `ConsensusConfig`, `Node::assemble`,
    `run_node_smoke_test`. No test-harness code.
  - `crates/devnet` is now the test harness only: `multinode`,
    `tcp_multinode`, `multiprocess`, `evm_workload`, and the load
    tests. It depends on `node` (one-way: `devnet -> node`, never the
    reverse).
  - `oxide-validator`, `oxide-fullnode`, and `oxide-deploy` now depend
    on `node` instead of `devnet`. `oxide-spammer` depends on both
    (`node` for assembly, `devnet` for `evm_workload`).
  - Backward-compat: `devnet` re-exports `node::{Node, NodeConfig,
    ConsensusConfig, run_node_smoke_test}` and provides a deprecated
    `DevnetNode` type alias + `run_devnet_smoke_test` wrapper so
    existing imports keep working.
  - **In plain words:** the production node binary no longer pulls in
    TCP test networking, subprocess orchestration, or workload
    generators. The node assembly path is now a first-class
    production crate (`node`) with a clear name, and `devnet` is
    explicitly the test/devnet harness.
  - **Release-build throughput** (macOS, TCP loopback, single machine):
    - Bank transfers: 4 validators / 10k txs → **6,732 tx/s**
    - EVM (transfers + deploys + calls): 4 validators / 10k txs →
      **2,970 tx/s** (parallel speculative execution already on)
    - These are lower bounds; Linux + kernel-bypass + larger blocks
      would push EVM throughput to 10k+ tx/s.
  - **Block-size sweep results** (release, 4 validators, TCP loopback):
    - Bank transfers scale linearly: 100→1000 txs/block gives
      **11k→71k tx/s** (6.3×). Executor ceiling is ~460k tx/s —
      consensus overhead is the only bottleneck.
    - EVM plateaus at ~8k tx/s (1000 txs/block). The revm interpreter
      is the bottleneck at large EVM block sizes, not consensus.
    - New `crates/devnet/tests/block_sweep.rs` and
      `crates/node/benches/sustained_throughput.rs`.
  - **Block-size tuning + mempool fix** (release, 4 validators):
    - Bank transfers: 3,021 → **29,822 tx/s** (9.9×) at 500 txs/block.
    - EVM: 2,970 → **6,271 tx/s** (2.1×) at 500 txs/block, 10k txs.
    - Fixed mempool nonce-chain bug: `select()` now follows contiguous
      nonces within a single pass, preventing tx loss at large block
      sizes (was silently dropping 3–6% of txs).
    - Added read-only group fast path in EVM parallel executor: groups
      that only write sender+coinbase skip conflict detection.
    - Lowered `DEFAULT_PARALLEL_THRESHOLD` from 100 to 32.
    - `NodeConfig` now exposes `parallel_threshold` for tuning.
    - **In plain words:** bigger blocks + a mempool bug fix gave us
      ~10× more bank-transfer throughput and ~2× more EVM throughput
      with no architecture changes. The executor was never the
      bottleneck — consensus overhead was.

- **Mempool batch removal** (P1 performance)
  - `select()` now removes selected transactions in a single batch
    pass instead of calling `remove()` per tx. Selecting N txs from
    one fee bucket is O(N) instead of O(N²).
  - **In plain words:** building a block from a mempool with many
    same-fee transactions is no longer quadratically slow.

### Added

- **EVM transaction workload generator and multi-validator load test suite** (Phase 2)
  - New `crates/devnet/src/evm_workload.rs` generates a realistic mix
    of signed EVM transactions: 50% transfers, 20% contract
    deployments, 20% contract calls (storage writes), 10% contract
    reads. Uses deterministic secp256k1 keypairs and tracks per-sender
    expected nonces for integrity verification.
  - New `crates/devnet/tests/evm_load.rs` with 4 test variants:
    `evm_load_default` (4 validators, 1000 txs), `evm_load_10k` (4
    validators, 10k txs), `evm_load_7_validators` (7 validators),
    `evm_load_single_validator` (1 validator). All `#[ignore]`d (bind
    TCP ports; run with `--ignored --nocapture`). Configurable via
    `EVM_LOAD_VALIDATORS` and `EVM_LOAD_TXS` env vars.
  - 7-layer integrity verification: block agreement across validators,
    all-tx-finalized, tx-content agreement, executor state-root
    agreement, nonce continuity, balance conservation, EVM state-root
    agreement.
  - `TcpMultiNodeDevnet` and `DevnetNode` now register an EVM module
    and expose `fund_evm_account` for funding secp256k1-derived
    addresses. `TcpMultiNodeDevnet` exposes `evm_module(i)` for direct
    state inspection (balance, nonce, state root).
  - `oxide-spammer` binary gains `--evm` flag for EVM-mode load
    testing with the same workload generator.
  - **In plain words:** the blockchain now has a production-grade EVM
    load test that submits thousands of signed EVM transactions
    (transfers, deploys, contract calls) across multiple validators
    and verifies that all validators agree on state, nonces, and
    balances. The spammer binary can also generate EVM load for
    external testing.

- **Production benchmark and metrics infrastructure** (Phase 2)
  - **TPS floor assertions**: devnet TPS tests now assert a minimum
    throughput (500 tx/s for 4-validator default, 1000 tx/s for
    10k and single-validator, 300 tx/s for 7-validator). The nightly
    CI job can now fail on throughput regression. Override with
    `TPS_MIN_FLOOR=0`.
  - **Block pipeline benchmark**: new `block_pipeline` bench in the
    executor crate measures the full `prepare_proposal →
    process_proposal → finalize_block → attest_state` pipeline for
    10/100/1000-tx blocks. Gate: < 50ms for a 1000-tx block.
  - **Parallel-vs-serial differential bench**: new
    `read_write_conflict_parallel_vs_serial` group in the EVM
    tps_rw bench proves the read-write conflict detection overhead
    doesn't regress throughput. Gate: parallel within 20% of serial.
  - **`metrics` crate**: HDR histogram latency recording with
    Prometheus text exposition. Thread-safe `Recorder` with
    p50/p90/p99/p999 percentiles. Wired into the executor
    (`prepare_proposal`, `finalize_block`, `attest_state`) and
    RPC (`eth_sendRawTransaction`). The validator binary shares
    one recorder across both.
  - **In plain words:** the node now has production-grade
    performance gates and observability — TPS tests fail CI on
    regression, the block pipeline has a latency budget, and
    every hot-path operation records p99 latencies that can be
    scraped by Prometheus.

- **`TxSubmitter` trait and `SignedTx::decode_raw`** (Phase 2)
  - `rpc::TxSubmitter` is a narrow `Send + Sync` trait the RPC server
    uses to push wrapped transaction envelopes into the mempool. The
    validator binary provides an `ExecutorTxSubmitter` adapter that
    delegates to `Executor::ingest_tx`.
  - `evm::tx::SignedTx::decode_raw` decodes a raw RLP byte slice into
    a `SignedTx`, rejecting trailing bytes (prevents a class of tx
    malleability where appended junk is silently ignored).
  - **In plain words:** the RPC layer can now accept and decode raw
    Ethereum transactions from wallet clients and feed them into the
    node's mempool.

- **Batch mempool submit API** (Phase E #11)
  - `Mempool::submit_batch` accepts a `Vec<TxBytes>` and returns per-tx
    results, pre-allocating the result Vec.
  - `AppInterface::ingest_tx_batch` trait method with a default
    implementation that calls `ingest_tx` per tx. The executor overrides
    this to acquire the mempool lock once for the entire batch.
  - **In plain words:** high-throughput clients can now submit thousands
    of transactions in a single call instead of one at a time, reducing
    per-tx lock overhead.

- **Opt-in async execution lane** (Phase D #10)
  - `Executor::enable_async_execution()` defers block execution to
    overlap with consensus. The pending block is executed lazily when
    `attest_state` is called or when the next `finalize_block` flushes it.
  - **In plain words:** the consensus engine can propose and vote on the
    next block while the previous block is still executing, hiding
    execution latency behind consensus latency. Disabled by default.

### Changed

- **Per-peer writer channels in p2p transport** (Phase C #7)
  - Replaced the global stream mutex with per-peer send channels. Each
    peer has a dedicated writer thread. `send()` only locks the map to
    look up the channel sender — no I/O under the lock.
  - **In plain words:** a slow peer no longer blocks sends to other
    peers. Previously, one slow peer could stall all outbound network
    traffic.

- **Vectored I/O for TCP writes** (Phase C #8)
  - `write_frame` now uses `write_vectored` to combine the 4-byte length
    prefix and payload into a single syscall, halving write syscalls per
    frame. TLS path unchanged.
  - **In plain words:** fewer kernel syscalls per network write.

- **Zero-copy payload handling in executor** (Phase E #5)
  - `execute_block` no longer constructs a `preverified` Vec for tx
    groups that will use the fallback path. Payload clones are eliminated
    when cached senders are available.
  - **In plain words:** less memory allocation during block execution.

- **Fixed-size OCC keys** (Phase E #14)
  - OCC read/write set keys changed from `Vec<u8>` to `OccKey` (`[u8; 32]`),
    eliminating per-key heap allocation on the parallel execution path.
  - **In plain words:** parallel EVM execution is faster because keys
    are stored inline in hash maps instead of on the heap.

### Performance

- Parallel executor (`uniswap_transfer` benchmark): **16–18% faster**
  - `parallel_8/500`: 2.13 ms → 1.79 ms (-15.9%)
  - `parallel_8/1000`: 4.16 ms → 3.54 ms (-15.9%)
  - `parallel_8/2000`: 8.44 ms → 6.89 ms (-18.3%)
  - Sequential path: ~2% improvement (within noise on some sizes).
  - Measured with criterion, 100 samples, on the same machine.

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

- **Pipelined TCP TPS harness** (devnet)
  - `run_pipelined` replaces the sequential `run_batch` driver in the
    networked TPS tests. It overlaps vote collection, QC formation, and
    QC delivery across views via a tick-based event loop that drains all
    TCP transports concurrently, forms QCs as soon as quorum is reached,
    and advances views independently per engine.
  - Added 1-byte message type tags (`MSG_VOTE` / `MSG_QC`) to
    disambiguate votes from QCs on the TCP inbound channel (the `Vote`
    decoder otherwise succeeds on QC bytes by reading the epoch+bitmap
    as the 96-byte BLS signature).
  - Gated `propose()` on `high_qc` availability for view > 0 (tail-fork
    resistance, oxidebft-spec.md §4).
  - Disabled Nagle's algorithm (`TCP_NODELAY`) on all TCP connections
    (accept + both connect paths, plain + TLS).
  - **In plain words:** the networked TPS benchmark no longer serializes
    a pipelined protocol. The 10,000-tx test improved ~2.6× (7,883 →
    20,714 tx/s) and the four-validator case now finalizes all blocks
    instead of hanging. Measured TPS still *falls* with more validators
    because each round needs more TCP round-trips, but the decline is
    now a real network/protocol cost, not a driver artifact.

### Added (2026-09-10)

- **Matcher risk engine — rate limits, order size caps, fat-finger
  price bands, and resting-order caps** (`crates/matcher/src/risk.rs`)
  - Four pre-match risk controls run *before* balance reservation:
    per-account rate limiting (sliding window, 100/sec default),
    order quantity cap, fat-finger price deviation band (basis points
    from mid-market reference), and per-account resting-order cap.
  - Four new `RejectReason` variants (8–11): `RateLimited`,
    `OrderTooLarge`, `FatFinger`, `TooManyResting`. All four protocol
    adapters (TCP, WS, JSON-RPC, FIX) map them to stable wire values.
    Existing discriminants 0–7 are unchanged.
  - Resting-order accounting is updated on every path: placement,
    cancel, amend, replace, and canceled remainder after partial fill.
  - **In plain words:** the matcher now rejects orders that are too
    large, too far from market price, or exceed per-account limits
    *before* they touch the order book or lock balances. This prevents
    fat-finger crashes and limits the damage from a misbehaving or
    compromised client.

- **WebSocket market data publisher — L1, L2, and Trades feeds**
  (`crates/matcher/src/market_data.rs`)
  - Subscribers subscribe to specific feeds (L1 top-of-book, L2 full
    depth, Trades) and markets. The publisher serializes once and
    broadcasts the same JSON string to all matching subscribers.
  - Slow clients miss updates (intentional — market data is lossy by
    design and must not back-pressure the matching engine).
  - **In plain words:** market data clients can now subscribe to
    real-time top-of-book, full depth, and trade feeds over
    WebSocket, the standard format used by every major exchange.

- **Autonomous consensus driver**
  (`bin/oxide-validator/src/driver.rs`)
  - A tokio-based driver that continuously drives the consensus
    engine in a background task at a configurable block interval
    (100ms default = 10 blocks/sec). Reports block height, tx count,
    and block count atomically for the `/metrics` endpoint.
  - The validator now runs consensus autonomously instead of
    one-shot at startup.
  - **In plain words:** the validator node now continuously produces
    blocks as transactions arrive, instead of finalizing one
    smoke-test block and idling. This is the minimal autonomous loop
    needed for a real node.

- **RPC rate limiting** (`crates/rpc/src/lib.rs`)
  - Simple fixed-window rate limiter on the RPC server, configurable
    via `set_rate_limit(max_per_second)`. Returns JSON-RPC error
    -32005 when exceeded. Uses atomic operations — no mutex on the
    request path.
  - **In plain words:** the RPC endpoint now has a configurable
    request rate limit, preventing a single client from overwhelming
    the node with RPC calls.

### Changed (2026-09-10)

- **Mutex poisoning recovery across the workspace**: all production
  `.lock().unwrap()` calls replaced with
  `.lock().unwrap_or_else(std::sync::PoisonError::into_inner)`.
  A poisoned mutex (caused by a thread panic) no longer cascades the
  panic to unrelated threads. The operator should still restart the
  process, but the process does not die immediately.

- **Clippy workspace clean**: all `clippy::redundant_closure_for_method_calls`
  and other clippy errors fixed across the workspace.
  `cargo clippy --workspace --all-targets -- -D warnings` is now clean.

- **Skills updated**: `production-rust` skill now documents mutex
  poisoning recovery (§8), protocol stability rules (§9), and risk &
  rate limiting invariants (§10). `performance-first` skill now
  documents matcher hot-path and RPC cold-path invariants.

### Added (2026-09-11)

- **Docker multi-host testnet — 4-container oxideBFT consensus with
  induced latency** (`Dockerfile`, `docker-compose.yml`,
  `scripts/inject-latency.sh`, `bin/oxide-validator/src/main.rs`,
  `crates/consensus/src/engine.rs`)
  - 4 validator containers on a shared Docker bridge network
    (`10.0.0.0/24`), each with a static IP and `tc netem` applied
    for 20ms latency + 2ms jitter.
  - Distributed consensus loop in the validator binary: proposes,
    broadcasts proposals, votes, drains inbound transport, forms
    QCs, broadcasts QCs, advances views, and reports finalized
    heights — all over TCP between separate processes.
  - All 4 validators finalized blocks 1–203+ with no stalls or
    divergence. Sustained throughput ~2.25 blocks/sec under 20ms RTT.
  - **In plain words:** the blockchain now runs across 4 separate
    Docker containers that talk to each other over a network with
    realistic latency. They agree on blocks, form quorum
    certificates, and finalize blocks together — proving the
    consensus engine works in a real distributed setting, not just
    in a single process.

### Fixed (2026-09-11)

- **Stale vote pollution in oxideBFT consensus**: `collect_vote()`
  accepted votes for any view, and `advance_view()` didn't clear
  the vote buffer. Late-arriving votes from old views polluted the
  new view's quorum accounting, causing `ConflictingVote` errors
  and stalling consensus at view=5. Fixed by rejecting stale votes
  (`vote.view < current_view`) in `collect_vote()` and clearing
  the vote buffer in `advance_view()`.

### Benchmark Results (2026-09-11, M2 MacBook Pro, release)

- **Executor single-block throughput**: 662K tx/s at 1000 txs/block
  (gate: ≥10K tx/s — PASS, 66× above).
- **Sustained pipeline throughput**: 463K tx/s at 100tx×100blk
  (gate: ≥5K tx/s — PASS, 93× above).
- Executor is NOT the bottleneck: throughput is flat at ~660K tx/s
  across block sizes 100–2000.
- **In plain words:** the blockchain's transaction processor can
  handle 660,000 simple transfers per second in a single block, and
  sustains 463,000 per second across 100 consecutive blocks. Both
  numbers are far above the targets, confirming the executor is not
  the performance bottleneck.

### Fixed (2026-09-11)

- **H4: Mempool replay protection** (`crates/executor/src/lib.rs`):
  Added per-account `executed_nonce` map to the executor. `ingest_tx`
  rejects any tx whose nonce has already been executed. The map is
  preserved across restarts via snapshot export/import.
  - **In plain words:** a transaction that has already been
    executed cannot be re-submitted and re-executed. This prevents
    replay attacks where a tx removed from the mempool after block
    selection is re-submitted.

- **H5: Executor nonce ordering enforcement**
  (`crates/executor/src/lib.rs`):
  `process_proposal` now enforces per-sender nonce contiguity (no
  gaps, no reorderings). `execute_block` enforces cross-block nonce
  continuity — txs with stale nonces are skipped.
  - **In plain words:** a byzantine proposer cannot reorder
    same-account transactions or insert gaps to bypass nonce
    protection. Each sender's transactions must be in strict
    nonce order.

- **M3: Snapshot import verifies module roots from KV**
  (`crates/executor/src/lib.rs`):
  After importing KV state, each module's state root is recomputed
  from the imported data and verified against the snapshot's claimed
  root. Mismatches are rejected.
  - **In plain words:** a crafted snapshot with arbitrary key-value
    data that doesn't match its claimed state roots is now rejected.
    Previously, the snapshot was trusted without verification.

- **M4: Per-block oracle rate limit** (`modules/perps/src/lib.rs`):
  Added `MAX_ORACLE_UPDATES_PER_BLOCK` (1) — each market can have at
  most 1 mark price update per block. The `TAG_SET_MARK` handle path
  now routes through `set_mark_price` which enforces both the
  per-update deviation check and the per-block rate limit.
  - **In plain words:** an oracle cannot make many small (just under
    10%) price updates in a single block to achieve a large
    cumulative price move. Each market gets only 1 oracle update per
    block, forcing large price moves to happen across multiple
    blocks and giving the system time to react.

### Added (2026-09-11)

- **Operational runbooks** (`docs/runbooks.md`):
  Added operational procedures for running an Oxide validator or
  full node in production: startup, shutdown, backup and snapshot
  export, restore from snapshot, incident response (node stalled,
  consensus halt, state divergence), monitoring and health checks,
  key rotation, and software upgrade with rollback.
  - **In plain words:** operators now have documented procedures
    for running and maintaining an Oxide node, including what to do
    when things go wrong.

### Added (2026-09-11)

- **Gate 4: Overhead breakdown** (`docs/production-readiness.md`):
  Completed the sustained-throughput gate by comparing the executor
  pipeline against the raw matching engine and EVM execution layer.
  - **In plain words:** we now have a complete picture of where
    throughput is spent. The matching engine runs at 20.6M ops/s
    single-core, the executor pipeline processes bank transfers at
    662K tx/s, and EVM transfers run at 28.7K tx/s single-threaded.
    The matching engine is not the bottleneck — the executor
    pipeline's tx dispatch overhead is. For EVM, revm execution
    itself is the bottleneck, not the Oxide pipeline.

### Fixed (2026-09-12)

- **Consensus liveness after validator restart and partition**
  (`crates/consensus/src/engine.rs`, `crates/consensus/src/pacemaker.rs`,
  `crates/p2p/src/tcp.rs`, `bin/oxide-validator/src/main.rs`)
  - Fixed a liveness stall where a restarted validator (at view 0)
    could not catch up to the cluster (at view ~8600), causing the
    entire cluster to stall after the byzantine restart phase.
  - Fixed timeout signature framing: MSG_TIMEOUT now carries the
    signed view and epoch so the receiver verifies against the
    sender's view, not the receiver's local view.
  - Added `OxideBft::sync_to_view()`: a monotonic view catch-up
    method that advances the engine to a higher view, syncs the
    pacemaker, and clears stale vote state.
  - The MSG_TIMEOUT handler now syncs forward to a higher-view
    timeout signature before collecting it, letting lagging
    validators converge to the highest view in the cluster.
  - `deliver_qc` now synchronizes the current view when receiving
    a valid higher-view QC.
  - `on_timeout_certificate` now accepts higher-view TCs (not just
    the exact current view).
  - TCP transport now reconnects after partition-induced connection
    loss (outbound connector retries after reader exit).
  - **In plain words:** if a validator crashes and restarts, or the
    network partitions and heals, the cluster now recovers in ~10
    seconds instead of stalling forever. The 1-hour Gate 7 soak
    (5285 blocks, both fault phases, no state divergence) passes.

### Added (2026-09-12)

- **Gate 7: 1-hour Docker soak passes** (`docs/evidence/gate7-soak/`)
  - Duration: 3603 s (60 min). 5285 blocks finalized.
  - Finalization rate: 1.4668 blocks/sec.
  - Byzantine fault (validator-3 stop/restart): recovery in 10 s.
  - Network partition (validator-2 isolated 90 s): recovery in 10 s.
  - Final heights: [5329, 5329, 5329, 5329] — no state divergence.
  - **In plain words:** the four-validator Docker testnet now
    survives both a crash and a network partition within the same
    hour-long run, with all validators converging and no forks.

- **Regression tests for view catch-up** (`crates/consensus/src/engine.rs`)
  - `sync_to_view_advances_lagging_validator`
  - `sync_to_view_rejects_lower_or_equal_view`
  - `sync_to_view_clears_stale_votes`
  - `deliver_qc_advances_lagging_validator_view`
  - `on_timeout_certificate_advances_lagging_validator`
  - `on_timeout_certificate_rejects_past_view`
  - **In plain words:** we now have tests proving a lagging
    validator catches up via higher-view QCs, TCs, and timeout
    signatures, and that stale (lower-view) messages can never
    regress the view.

### Fixed (2026-09-13)

- **Followers never synced block heights from received proposals**
  (`crates/consensus/src/engine.rs`, `bin/oxide-validator/src/main.rs`)
  - The validator binary's consensus loop synced `next_height` to its
    own value — a no-op. Followers never advanced `next_height` from
    received proposals. When a follower became the leader after a
    view change, it proposed at a stale height (often height 0),
    conflicting with already-finalized blocks and corrupting chain
    state.
  - Added `OxideBft::observe_block_height(height)` to the consensus
    engine, called from `vote()` and the validator loop's
    `MSG_PROPOSAL` handler. It advances `next_height` to `height + 1`
    whenever a higher height is observed.
  - Regression tests: `vote_syncs_next_height_from_proposal`,
    `observe_block_height_only_advances_forward`,
    `new_leader_proposes_at_correct_height_after_view_change`.
  - **In plain words:** validators now learn the chain's block
    height from proposals they receive. A validator that takes over
    as leader after a view change proposes at the correct height
    instead of re-proposing an already-finalized height.

- **View-change paths did not clear timeout signatures**
  (`crates/consensus/src/engine.rs`)
  - `on_timeout_certificate`, `sync_to_view`, `deliver_qc` catch-up,
    `advance_view`, and `collect_timeout_signature` cleared votes
    but not `timeout_signatures`. Stale timeout signatures from the
    old view leaked into the new view's TC aggregation, producing an
    aggregate that failed verification and stalled view changes.
    `on_timeout_certificate` was the worst: it cleared neither votes
    nor timeout signatures, so stale votes caused ConflictingVote
    errors that prevented the new leader from forming a QC.
  - Added `clear_per_view_state()` helper that clears votes,
    vote_count, and timeout_signatures. Called from every view-change
    path.
  - Regression tests: `on_timeout_certificate_clears_per_view_state`,
    `sync_to_view_clears_timeout_signatures`,
    `deliver_qc_catchup_clears_timeout_signatures`,
    `advance_view_clears_timeout_signatures`.
  - **In plain words:** when the consensus engine switches to a new
    view, it now clears all per-view state (votes and timeout
    signatures). This prevents stale data from the old view from
    blocking the new view.

- **MMR used raw hash prefixes colliding with consensus domains**
  (`crates/storage/src/mmr.rs`, `crates/crypto/src/hash.rs`)
  - The MMR used raw prefixes `0x01` (internal node) and `0x02` (root),
    colliding with `Domain::Transaction = 1` and `Domain::Vote = 2`.
    `hash_leaf` had no domain tag at all. The crypto crate already
    defined `Domain::MmrNode = 5` and `Domain::MmrLeaf = 6` but the
    MMR never used them.
  - Added `Domain::MmrRoot = 8` and updated `hash_node`, `bag_root`,
    and `hash_leaf` to use the canonical `Domain` enum via the
    `Hasher` API.
  - Regression test: `mmr_domains_do_not_collide_with_consensus_domains`.
  - **In plain words:** MMR hashes are now in their own domain-
    separated hash space, so they can never collide with transaction,
    vote, or block hashes — even if the underlying bytes are identical.

- **Trading core had production panic paths**
  (`crates/trading/src/engine.rs`, `crates/trading/src/book.rs`,
  `crates/trading/src/idmap.rs`, `crates/trading/src/pool.rs`)
  - `remove_maker` used `.expect()`, `cancel` used unchecked
    `resting -= 1`, `level_index` used `.expect()`/`assert!`,
    `IdMap::insert` used `assert!` for duplicate keys, and
    `OrderPool::index/index_mut` used `.expect()`/`assert!`. A
    crafted input or internal invariant violation could crash the
    validator.
  - Replaced all production panics with graceful error returns or
    `debug_assert` (debug-only checks that don't fire in release).
  - Regression tests: `cancel_nonexistent_order_returns_error_not_panic`,
    `remove_maker_does_not_panic_on_invariant_violation`,
    `duplicate_insert_returns_error_not_panic`.
  - **In plain words:** the matching engine no longer crashes on
    invariant violations or edge-case inputs. Errors are returned
    instead of panicking, so a bad order or internal bug rejects the
    transaction rather than killing the validator.

- **Executor did not enforce fees or block gas limits**
  (`crates/executor/src/lib.rs`, `modules/bank/src/lib.rs`)
  - The executor parsed `fee` and `gas` from the tx envelope but
    never charged fees or enforced gas limits. `BlockBudget.max_gas`
    existed but was only used in tests. This permitted free,
    unbounded execution — a spam vector on a public testnet.
  - Added `charge_fee()` and `estimate_gas()` methods to the
    `Module` trait. The bank module overrides `charge_fee()` to
    debit the sender's balance. Added `block_gas_limit` to the
    Executor (default: 30M gas). `process_proposal` rejects blocks
    exceeding the limit; `execute_block` skips txs exceeding the
    cumulative limit and charges fees before execution.
  - Also fixed `bank::mint()` which used `.expect("balance overflow")`
    — replaced with `saturating_add()`.
  - Regression tests: `process_proposal_rejects_block_exceeding_gas_limit`,
    `process_proposal_accepts_block_within_gas_limit`,
    `execute_block_skips_txs_exceeding_gas_limit`,
    `charge_fee_debits_sender_balance`,
    `charge_fee_rejects_insufficient_balance`,
    `charge_fee_zero_is_noop`.
  - **In plain words:** every transaction now pays its declared fee
    before it can execute, and the total computation in a block is
    bounded by a gas limit. A sender with insufficient balance for
    the fee has their transaction skipped. A byzantine proposer
    cannot include unbounded computation in a single block.

- **FOK pre-scan did not exclude self-trades under STP**
  (`crates/trading/src/engine.rs`, `crates/trading/src/book.rs`)
  - The FOK pre-scan used `fillable_qty` which summed all orders
    including the taker's own. When STP was active, the sweep would
    skip or cancel the taker's own orders, so the actual fillable
    quantity was less. A FOK that should have been killed was
    instead accepted and then canceled mid-sweep — violating the
    FOK all-or-nothing guarantee.
  - Added `fillable_qty_excluding_owner` to the `BookBackend` trait.
    The FOK pre-scan now uses it when STP is active.
  - Regression tests: `fok_pre_scan_excludes_self_trades_under_stp`,
    `fok_pre_scan_counts_all_orders_without_stp`.
  - **In plain words:** a fill-or-kill order now correctly accounts
    for self-trade prevention when checking if enough liquidity
    exists. If the only available liquidity is the trader's own
    resting orders, the FOK is killed immediately rather than
    executing partially and then being canceled.

- **P2P transport did not forcibly close connections on shutdown**
  (`crates/p2p/src/tcp.rs`)
  - `shutdown()` only cleared the `streams` map (dropping writer
    senders). Reader threads kept blocking on `read` for up to 30s
    before noticing the shutdown. This delayed clean process exit.
  - Added a `shutdown_streams` map storing `TcpStream` clones. On
    `shutdown()`, `shutdown(Shutdown::Both)` is called on each
    stream, causing reader threads to exit immediately.
  - Also fixed duplicate-connection handling: when both peers connect
    simultaneously, the old connection is NOT shut down (that would
    kill the peer's new inbound connection). The old writer sender
    is dropped, and the old reader thread exits naturally.
  - Regression tests: `tcp_shutdown_closes_connections_promptly`,
    `tcp_duplicate_connections_survive`.
  - **In plain words:** when a validator shuts down, all network
    connections are closed immediately instead of lingering for up
    to 30 seconds. Simultaneous connections between two peers no
    longer kill each other.

- **Executor and perps had unnecessary per-transaction allocations**
  (`crates/executor/src/lib.rs`, `modules/perps/src/lib.rs`)
  - The executor allocated a `Vec<u8>` per transaction for the
    module payload, then cloned it again for uncached txs. The perps
    module cloned every `FillEvent` to release a borrow.
  - Executor: store `&[u8]` references into the original tx bytes
    instead of `Vec<u8>` allocations. Perps: use `std::mem::take` to
    move fills out of the scratch buffer in O(1) instead of cloning.
  - **In plain words:** the execution hot path now avoids a memory
    allocation per transaction, reducing GC pressure and improving
    throughput. The perps module avoids cloning fill events, which
    reduces per-trade overhead.

- **Batch mempool intake missing nonce replay check**
  (`crates/executor/src/lib.rs`)
  - `ingest_tx_batch` (the batch intake path) did not enforce the
    executed-nonce replay check that `ingest_tx` (the single-tx path)
    enforced. A tx with a stale nonce could be accepted via the batch
    path — a replay attack vector.
  - Added the same executed-nonce replay check to `ingest_tx_batch`.
  - Regression test: `h4_ingest_batch_rejects_stale_nonce_after_execution`.
  - **In plain words:** a transaction that has already been executed
    can no longer be re-submitted via the batch intake path. Previously,
    only the single-tx path checked for replays, leaving the batch
    path as a bypass.

- **Exchange batch settlement was not atomic**
  (`modules/exchange/src/lib.rs`)
  - `handle_batch_settle` used separate `debit` + `credit` calls. If
    the credit failed (e.g., overflow), the debit was not rolled
    back — funds were lost.
  - Replaced with a single `bank.transfer` call, which is atomic:
    both debit and credit are checked before either is committed.
  - Regression test: `batch_settle_rolls_back_on_credit_overflow`.
  - **In plain words:** when the exchange settles a batch of trades,
    a failed credit no longer leaves the buyer debited without the
    seller being credited. The settlement is now all-or-nothing.

- **Trading enums lacked stable layout representation**
  (`crates/trading/src/order.rs`)
  - The `Side`, `OrderType`, `TimeInForce`, and `StpMode` enums
    relied on the default Rust representation, which is not
    guaranteed to be 1 byte.
  - Added `#[repr(u8)]` to all four enums, guaranteeing a 1-byte
    representation for stable slab node layout and cache density.
  - **In plain words:** the matching engine's order data structures
    now have a guaranteed compact layout, improving cache
    performance and preventing future layout regressions.

- **BLS aggregate verification had unnecessary reallocations**
  (`crates/crypto/src/bls_signer.rs`)
  - `aggregate_verify` allocated two Vecs per QC verification without
    pre-sizing, causing multiple reallocations as the Vecs grew.
  - Pre-sized both Vecs to `pks.len()` using `Vec::with_capacity`,
    eliminating reallocations.
  - **In plain words:** quorum certificate verification is faster
    because the public key buffer no longer reallocates as it grows.
    This reduces per-QC overhead for the consensus engine.

- **Journal backend ignored append errors and used unverified replay**
  (`crates/storage/src/auth_journal.rs`)
  - `apply_batch` silently discarded journal append errors (`let _ = ...`).
    If the append failed (e.g., disk full), the in-memory state was updated
    but the journal was not — on restart, the state would diverge.
  - `open` used the unverified `replay` function, which did not reconstruct
    the MMR root — a corrupted or tampered journal would not be detected.
  - `apply_batch` now rolls back the in-memory state if the append fails.
    `open` now uses `replay_verified` to reconstruct the MMR root.
  - Regression tests: `journal_backend_open_uses_verified_replay`,
    `journal_backend_apply_batch_rolls_back_on_append_failure`.
  - **In plain words:** if the disk fills up while writing a block, the
    node's in-memory state is rolled back to match what was actually
    persisted. On restart, the journal is verified to detect corruption.

- **Mempool and perps had production panic paths**
  (`crates/mempool/src/lib.rs`, `modules/perps/src/lib.rs`)
  - The mempool's `evict_lowest_fee` used `expect` on internal state
    that could be corrupted by a bug, crashing the node. The perps
    module's `apply_funding` used `unwrap()` on a position lookup
    that could fail if the position was removed mid-loop.
  - Replaced with `let Some(...) else` guards that return/skip
    gracefully instead of panicking.
  - **In plain words:** a corrupted internal state in the mempool
    or a removed position in the perps funding loop no longer
    crashes the node. The operations are skipped gracefully.

- **Validator loop had 10ms message latency from sleep polling**
  (`crates/p2p/src/tcp.rs`, `bin/oxide-validator/src/main.rs`)
  - The transport's `recv` used `try_recv()` (non-blocking), forcing
    the validator loop to sleep 10ms between polls. Messages arriving
    during the sleep waited up to 10ms before processing.
  - Changed `recv` to use `recv_timeout(10ms)`, which returns
    immediately when a message arrives. Removed the 10ms sleep from
    the validator loop.
  - **In plain words:** consensus messages are now processed as soon
    as they arrive, instead of waiting up to 10ms for the next poll.
    This reduces consensus round-trip latency by up to 10ms per
    message.

- **Benchmark gates were not enforced with assertions or CI**
  (`crates/devnet/tests/trading_throughput.rs`, `.github/workflows/nightly.yml`)
  - The benchmark gates were documented in bench file doc comments but not
    enforced. The nightly CI ran throughput simulations but did not run
    criterion benchmarks or enforce the throughput gates.
  - Added throughput gate assertions to `trading_throughput.rs`: raw matching
    engine ≥ 1M orders/s, exchange settlement ≥ 100k orders/s. Added a
    benchmark job to nightly CI that runs criterion benchmarks and the
    throughput gate tests.
  - **In plain words:** a performance regression will now fail CI instead of
    landing unnoticed. The gates are conservative (1M raw, 100k exchange)
    to avoid noise on CI runners; the dev machine measures 37M raw and 2M
    exchange — 37× and 21× headroom respectively.

### Fixed (2026-09-14)

- **Trading TPS test stalled after ~270 blocks due to TCP QC drops and
  10ms recv timeout tax**
  (`crates/devnet/src/tcp_multinode.rs`, `crates/p2p/src/tcp.rs`)
  - The 2M-tx trading TPS test (`trading_tps_1m`) deadlocked after
    ~270 blocks. Two root causes: (1) `form_qc_phase` broadcast QCs
    via TCP and ignored send errors — a transient `UnknownPeer`
    (peer mid-reconnect) permanently dropped the QC, stalling the
    recipient's view advancement; (2) `Transport::recv` used
    `recv_timeout(10ms)`, costing 40ms/tick (4 transports × 10ms)
    when channels were empty, throttling throughput from ~75 blk/s
    to ~1.5 blk/s once the intake filled.
  - Fix: (1) `form_qc_phase` now delivers every formed QC directly to
    all engines in-process (in addition to best-effort TCP).
    `deliver_qc` is idempotent for stale QCs, so duplicate delivery
    is a no-op. (2) `Transport::recv` now uses non-blocking
    `try_recv()` — the tight pipelined loop picks up messages on
    the next tick (microseconds later), eliminating the 10ms tax.
  - **In plain words:** the 2M-tx trading test now passes in 27s at
    74,293 tx/s (was: stalled at 495K txs). The 200K test improved
    from 16,968 tx/s to 74,902 tx/s. All validators agree on
    finalized height, tx count, resting count, and state root.

### Fixed (2026-09-13)

- **Multi-validator trading TPS test stalled due to tx_idx accumulation
  bug in devnet harness** (`crates/devnet/src/tcp_multinode.rs`)
  - The 7-validator and 10-validator trading TPS tests stalled at ~98% CPU
    with no progress. Root cause: `run_pipelined_txs` used
    `tx_idx = submit_round_txs(...)` instead of `tx_idx += ...`. The
    helper returns the *count* of txs submitted (0..txs_per_round), not
    the absolute index. Using `=` reset `tx_idx` to the count instead of
    advancing it, causing every round after the first to re-submit the
    same stale txs. Those duplicates were rejected by the replay check
    (nonce already executed), filling the intake with rejected txs and
    deadlocking the pipeline.
  - Fix: changed `=` to `+=` in both submission loops, and made
    `SUBMIT_AHEAD` dynamic (`max(n, 4)`) so every upcoming leader has
    txs in its intake before the pipeline reaches its view.
  - **In plain words:** the 7-validator and 10-validator trading TPS
    tests now pass. 7 validators: 17,369 tx/s. 10 validators: 31,949
    tx/s. All validators agree on finalized height, tx count, resting
    count, and state root.

### Changed (2026-09-13)

- **Docker testnet blocktime improved to 65ms average (15.4 blocks/s)**
  (`bin/oxide-validator/src/main.rs`, `crates/p2p/src/tcp.rs`)
  - The Docker testnet previously had "painfully slow" blocktime. The
    transport's `recv()` was changed from `recv_timeout(10ms)` to
    non-blocking `try_recv()` with a 1ms sleep in the consensus loop,
    reducing idle-loop latency from 10ms to ~1ms. The 4-validator
    Docker testnet now produces blocks at 65ms average (min 25ms,
    max 251ms), a major improvement from the previous slow blocktime.
  - **In plain words:** Docker testnet blocks are now produced ~15
    times per second instead of the previous slow rate, giving much
    faster response times for transactions.
