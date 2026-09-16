# EVM parity gap analysis — Oxide vs. cosmos-evm

Comparison target: `github.com/cosmos/evm` (evmOS successor), latest release
v0.7.2. cosmos-evm embeds go-ethereum (Cosmos fork ~v1.17) behind a
`vm.StateDB` adapter over the Cosmos SDK KVStore — no Merkle Patricia Trie.
Oxide embeds revm at SpecId::PRAGUE with a flat account/storage model and a
sparse retained trie for state roots.

This document inventories release-grade functionality cosmos-evm ships and
maps each item to Oxide's current state: **implemented**, **partial/stub**,
**missing**, or **out of scope** (deliberately not planned — e.g. IBC).
Rows are updated as items ship — the "Gap" column records what remains.

## Legend

- ✅ implemented and functional
- 🟡 partial — code exists but is stubbed, unwired, or semantically incomplete
- ❌ missing entirely
- ➖ out of scope for Oxide's architecture

---

## 1. Ethereum JSON-RPC surface

cosmos-evm namespaces: `eth`, `web3`, `net`, `txpool`, `debug`, `personal`
(miner/admin stubs). Oxide implements `eth` + `web3` + `net` over HTTP and
WebSocket (`GET /` upgrade, same port — the geth convention).

| Method / capability | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| `web3_clientVersion`, `web3_sha3` | ✅ | ✅ | — |
| `net_version`, `net_listening`, `net_peerCount` | ✅ | ✅ | `net_peerCount` returns stub; needs live peer count |
| `eth_chainId`, `eth_blockNumber`, `eth_accounts`, `eth_syncing`, `eth_mining`, `eth_coinbase`, `eth_hashrate`, `eth_protocolVersion` | ✅ | ✅ | — |
| `eth_getBalance` | ✅ incl. block tags | 🟡 | executes against **latest state only** — `parse_block_tag` maps every tag to height 0 |
| `eth_getTransactionCount` | ✅ incl. `pending` | 🟡 | latest state only; `pending` should overlay mempool nonces |
| `eth_getCode` | ✅ incl. block tags | 🟡 | latest state only |
| `eth_getStorageAt` | ✅ incl. block tags | 🟡 | latest state only |
| `eth_getBlockByNumber` | ✅ full header+txs | 🟡 | synthetic block, no real tx list / receipts root |
| `eth_getBlockByHash` | ✅ | ❌ | returns `null` — no block store wired |
| `eth_getHeaderByNumber/Hash` | ✅ | ❌ | not implemented |
| `eth_getBlockTransactionCountBy*` | ✅ | ❌ | returns 0 — no block store |
| `eth_getTransactionByHash` | ✅ | ❌ | returns `null` — no tx index |
| `eth_getTransactionByBlock*AndIndex` | ✅ | ❌ | returns `null` |
| `eth_getTransactionReceipt` | ✅ | ❌ | returns `null` — receipts built for events then dropped, never stored |
| `eth_getBlockReceipts` | ✅ (cosmos ext) | ❌ | returns `null` |
| `eth_getLogs` | ✅ bloom-prefiltered scan, `block-range-cap` 10k | ✅ | bloom-prefiltered scan over sealed history (`blockHash`/range/address/topics); result count capped at 10,000 (`MAX_LOG_RESULTS`) |
| `eth_newFilter` / `eth_getFilterChanges` / `eth_getFilterLogs` / `eth_newBlockFilter` / `eth_newPendingTransactionFilter` / `eth_uninstallFilter` | ✅ | ✅ | filter registry with 300s TTL (geth's timeout): log filters share `eth_getLogs` semantics + `MAX_LOG_RESULTS` cap, block filters serve hashes, pending filters serve mempool-arrival tx hashes by sequence cursor; expired filters return `filter not found` |
| `eth_sendRawTransaction` | ✅ | ✅ | decodes, submits to local mempool, **and gossips the raw tx to peers** with dedup (100k-hash FIFO) |
| `eth_call` | ✅ EVM simulation, `gas-cap`, `evm-timeout` | ✅ | real `call_read` revm simulation (nonce/base-fee/gas-limit checks off, balance on — geth `DoCall`); `gas` clamped to `CHAIN_BLOCK_GAS_LIMIT` (our gas-cap); wall-clock `evm-timeout` via `DeadlineInspector`; historical heights via the versioned window; `stateOverride` (param 2) via read-only `OverrideView` — balance/nonce/code/state/stateDiff per geth, never persisted |
| `eth_estimateGas` | ✅ binary search + state overrides | ✅ | binary search over `call_read` with revert/halt propagation, historical heights, and `stateOverride` (param 2) applied through a read-only `OverrideView` — never persisted |
| `eth_createAccessList` | ✅ | ✅ | touched-set accounting with geth accessListTracer semantics — sender/recipient/coinbase/precompiles excluded at address level, their touched storage keys still included |
| `eth_gasPrice` | ✅ | ✅ | history oracle quote: latest sealed base fee + sampled tip (geth `SuggestGasPrice` = `suggestTip + head.BaseFee`); configured base fee is the no-EVM fallback |
| `eth_maxPriorityFeePerGas` | ✅ | ✅ | geth GPO parity: p60 of the 3 lowest effective tips in each of the last 20 blocks, capped at 500 gwei, 1 gwei default when no samples |
| `eth_feeHistory` | ✅ | 🟡 | real base fees + reward percentiles over the retained window; `blockCount` capped at 1,024 (`MAX_FEE_HISTORY_BLOCKS`) |
| `eth_getProof` | ✅ (height > 2) | ✅ | EIP-1186 account + storage proofs at any retained height — trie rebuilt at the versioned view via `HashBuilder` + `ProofRetainer`; non-inclusion proofs supported; tests verify nodes against the sealed state root |
| `eth_sign` / `eth_signTypedData` | ✅/partial | ❌ | keyring-backed — deliberately omit (nodes should not custody user keys) |
| `eth_sendTransaction` / `eth_pendingTransactions` | ❌/partial | ❌/✅ | `sendTransaction` is a node-custody API — omit; `eth_pendingTransactions` ships over the `TxpoolProvider` seam — flat array of pending (executable) pool entries as geth-shaped tx objects, queued entries excluded |
| `eth_subscribe` / `eth_unsubscribe` | ✅ WS: `newHeads`, `logs`, `newPendingTransactions` | ✅ | **WS transport shipped** (axum `ws` on `GET /`, geth same-port convention): `newHeads` + filtered `logs` push on finalization; `newPendingTransactions` pushes canonical EVM tx hashes for locally submitted + gossip-accepted txs (1024-hash bounded ring, dedup by hash) |
| `txpool_content` / `txpool_contentFrom` / `txpool_inspect` / `txpool_status` | ✅ | ✅ | all four shipped over a `TxpoolProvider` seam (executor → mempool nonce-gap queues); `contentFrom` filters by sender |
| `debug_traceTransaction` / `debug_traceBlock*` / `debug_traceCall` | ✅ re-execution via EVM | ✅ | callTracer shipped via revm inspector composition (`NativeJournalInspector` + `CallRecorder` tuple); traces captured **at execution time** and retained in `evm::history` — no historical-state re-execution (state store is latest-only), so tracing is bounded by the 8192-block history window; `debug_traceCall`/`traceBlockByNumber`/`traceBlockByHash` included; unsupported tracers rejected explicitly |
| `debug_*` runtime profiling endpoints | ✅ | ❌ | Go-specific; equivalent Rust profiling hooks not needed |
| `personal_*` (keyring) | ✅ partial | ❌ | out of scope — node-custodied keys are a security liability |
| JSON-RPC resource limits | `gas-cap` 25M, `evm-timeout`, `filter-cap` 200, `feehistory-cap` 100, `batch-request-limit`, `max-open-connections`, `http-timeout` 30s | 🟡 | per-client rate limiting + `gas-cap` (`eth_call`/`debug_traceCall` clamp to `CHAIN_BLOCK_GAS_LIMIT`), `evm-timeout` (`DeadlineInspector` wall-clock halt on sim paths), log-cap (`MAX_LOG_RESULTS` = 10k on `eth_getLogs` + filter polls), `feehistory-cap` (`MAX_FEE_HISTORY_BLOCKS` = 1,024), filter TTL (300s), `batch-request-limit` (`MAX_BATCH_REQUESTS` = 1,024), `max-open-connections` (listener-level accept bound), `filter-cap` (`MAX_FILTERS` = 1,024 live registrations, expired reaped first), `http-timeout` (30 s `spawn_blocking` dispatch bound → HTTP 408 + JSON-RPC error; WS writes bounded by `WS_WRITE_TIMEOUT` = 30 s) |
| WS endpoint `:8546` | ✅ | ✅ | WS rides the same port as HTTP (`ws://host:8545/`, geth convention) rather than a separate `:8546` listener |

**Summary (updated):** the advertised `eth_*` surface now serves real data —
blocks/txs/receipts/logs come from `evm::history` (8192-block retained
window, **durable across restart**), `eth_call`/`eth_estimateGas` run real
revm simulations (gas-cap + wall-clock timeout, historical heights,
`stateOverride`), `eth_subscribe` pushes `newHeads`/`logs`/`newPendingTransactions`
over WebSocket, pollable filter APIs track logs/blocks/pending txs under a
count cap + TTL, `txpool_*` exposes the mempool's nonce-gap queues and
`eth_pendingTransactions` flattens the pending set, `debug_trace*` serves
callTracer output captured at execution time (with `stateOverrides` in the
`debug_traceCall` config), `eth_createAccessList` matches geth's tracer
semantics, `eth_getProof` produces EIP-1186 account/storage proofs at any
retained height over the versioned state window, and the gas oracle quotes
`eth_gasPrice`/`eth_maxPriorityFeePerGas` from sampled inclusion tips. The
deliberate omissions stand: `eth_sendTransaction`/`personal_*` key custody,
EIP-4844 blobs (no blob lane). The generic `indexer` crate (451 lines)
remains unwired — EVM history superseded it for the `eth_*` surface.

## 2. EVM execution semantics

| Feature | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| Interpreter | geth `core/vm` (Cosmos fork 1.17) | revm, `SpecId::PRAGUE` | parity in fork level |
| Legacy tx type 0 | ✅ | ✅ | — |
| EIP-2930 access-list tx (type 1) | ✅ | ✅ | — |
| EIP-1559 dynamic-fee tx (type 2) | ✅ | ✅ | — |
| EIP-4844 blob tx (type 3) | ✅ parsed | ❌ rejected `Malformed` | acceptable to reject — no blob lane in consensus; document it |
| EIP-7702 SetCodeTx (type 4) | ✅ (v0.5+) | ✅ | `TxEip7702` + `TxAuthorization` decode/sign/recover, revm `authorization_list` wiring, Prague spec gate; `authorizationList` emitted in RPC tx JSON |
| EIP-155 chain-ID replay protection | ✅ | ✅ | — |
| `allow_unprotected_txs` policy | rejects pre-EIP-155 by default | 🟡 | verify unprotected legacy txs are rejected at `validate` |
| secp256k1 sender recovery | ✅ | ✅ | — |
| Intrinsic gas / calldata gas / access-list warm costs | geth | revm | conformance suite needed to prove parity |
| Gas refund semantics | ✅ | ✅ via revm | — |
| `BLOCKHASH` last-256-blocks | ✅ (+EIP-2935 history contract) | ✅ | `block_hash_ref` serves sealed hashes (revm's opcode handler enforces the N−256 window); EIP-2935 history contract preinstalled at `0x0000F90827F1C53a10cb7A02335B175320002935` with `begin_block` writing `parent_hash` to slot `(h−1) % 8191` — state-equivalent to geth's system call, undo-captured and Prague-gated |
| Base fee | EIP-1559 via `x/feemarket`, **distributed to validators** | EIP-1559 `BaseFeeState`, **burned** (revm default) | design choice — burning is Ethereum-L1-faithful; distribution is Cosmos-faithful. Decide + document |
| `evm_denom` / native-token-as-gas | ✅ | ✅ | native balance == EVM balance (single account space — simpler than dual-model) |
| Preinstalls (Create2 `0x4e59…`, Multicall3 `0xcA11…`, Permit2 `0x0000…D473`, Safe singleton `0x914d…`, EIP-2935 history `0x0000F908…`) | ✅ at genesis | ✅ | Create2 factory, Multicall3, Permit2, Safe proxy+singleton, and the EIP-2935 history contract installed at canonical addresses (bytecode verified against `alloy_eips::eip2935` constants); fork-gated entries (`requires_spec`) skip on pre-Prague specs |
| Genesis `alloc` (accounts/code/storage) | ✅ | ✅ | `evm.alloc` section wired in both single-node and devnet assembly (balance/nonce/code/storage) |
| `access_control` — permissioned create/call whitelists | ✅ | ❌ | optional; needed only for permissioned-deployment chains |
| `extra_eips` / custom opcode hooks | ✅ | ❌ | out of scope — revm fork schedule is fixed at compile time |
| Historical state queries (`history_serve_window`, default 8192) | ✅ | ✅ | versioned reads via first-write-wins per-block undo (`versioned.rs`) over the same 8192-block window; `StateView` overlay serves balance/nonce/code/storage/`eth_call` at `h ∈ [floor−1, latest]` |

## 3. Precompiles

cosmos-evm static registry (`0x…0100`–`0x…0807`) + dynamic ERC20/WERC20:

| Precompile | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| Standard geth set (ecrecover, sha256, ripemd160, identity, modexp, ecadd, ecmul, ecpairing, blake2f, kzg) | ✅ | ✅ via revm | — |
| P256 `0x…0100` | ✅ | ❌ | add if requested — cheap |
| Bech32 `0x…0400` | ✅ | ➖ | no bech32 in Oxide addressing |
| Staking `0x…0800` (delegate/redelegate/undelegate/queries) | ✅ **state-mutating** | 🟡 | `0x0C01` delegate + `0x0C02` undelegate **wired with real side effects** — caller-scoped, bank-backed, same native invariants, revert-safe via frame-scoped native journal; redelegate + queries still missing |
| Distribution `0x…0801` | ✅ | ❌ | no rewards/distribution module yet |
| ICS20 `0x…0802` | ✅ | ➖ | no IBC |
| Vesting `0x…0803` | ✅ | ➖ | no vesting module |
| Bank `0x…0804` | ✅ | 🟡 | `0x0B01` transfer (mutating) + `0x0B02` balance — close parity |
| Gov `0x…0805` | ✅ | ❌ | governance module exists, no precompile |
| Slashing `0x…0806` | ✅ | ❌ | no slashing module |
| ICS02 `0x…0807` | ✅ | ➖ | no IBC |
| ERC20 dynamic precompiles (STRv2: denom ↔ ERC20 facade over bank state) | ✅ | ❌ | no bank-denom→ERC20 view; needed for wallet UX of issued assets |
| WERC20 wrapped-native | ✅ | ❌ | same |
| Exchange/perps read precompiles | ➖ n/a | ✅ `0x05_*`/`0x06_*` best bid/ask, position, mark, insurance | Oxide-only, no cosmos-evm equivalent |
| IBC callbacks (`x/ibc/callbacks`) | ✅ | ➖ | no IBC |

**Security lesson from cosmos-evm (Aug 2026 advisories):** a staking
precompile + vesting path let `SubBalance` underflow in StateDB and mint
unlimited tokens — exploited in production (~2.99B minted on one chain),
fixed in v0.6.2/v0.7.2. When Oxide wires precompile→module state mutation,
the precompile path must run the **same balance/invariant checks as the
native message path** — no unchecked debits.

## 4. Transaction lifecycle / mempool

| Capability | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| Mempool model | geth `legacypool` port — nonce-gap queue, replacement-by-tip, insert-time validation | per-sender nonce queues + fee-ordered select + **same-nonce replacement with geth's ≥10% bump** | close — still missing: insert-time validation against account balance/nonce floor, and a separate `queued` pool for gapped nonces |
| Tx gossip | CometBFT mempool gossip | ✅ | raw-tx gossip to peers on `eth_sendRawTransaction` (dedup, no rebroadcast of inbound) |
| Pending-tx visibility | `PendingTxListener` feeds `newPendingTransactions` + `"pending"` block tag | 🟡 | `newPendingTransactions` WS push + pending-tx filter + `txpool_*` inspect all ship; `"pending"` block tag overlay still missing |
| Priority ordering | tip-based (`min(tip_cap, fee_cap − base_fee)`) | fee-density ordering at select time | adequate for now; per-tip-cap ordering matters once EIP-1559 tips exist |
| `max_gas_wanted` per-tx cap | ✅ | 🟡 | `BlockBudget` exists; per-tx cap not enforced at RPC ingress |

## 5. State, history, and indexing

| Capability | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| Canonical block store | CometBFT blockstore + `BlockResults` | ✅ | `evm::history` retains the last 8192 sealed EVM blocks (hash/height/tx indexed) **and persists across restart** — records flush to the storage backend in the same atomic per-block batch as account state |
| Tx index | `KVIndexer` (hash→(h,i), (h,i)→tx) | ✅ | `tx_hash → (height, index)` in `evm::history` for the retained window |
| Receipt/log persistence | per-block logs+bloom in store; receipts via indexer | ✅ | receipts + logs + blooms retained per block in `evm::history`; `eth_getLogs`/`eth_getBlockReceipts` serve them |
| Historical state | `history_serve_window` 8192; EIP-2935 for BLOCKHASH | ✅ | versioned undo window (default 8192) serves balance/nonce/code/storage/`eth_call`/proofs at retained heights — persisted across restart alongside history |
| State sync / snapshots | SDK snapshot-interval + keep-recent | 🟡 | snapshot export/import + `/snapshot` endpoint exist; no interval/retention policy, no state-sync bootstrap protocol |
| Pruning | SDK strategies (default/nothing/everything/custom) | ❌ | no pruning policy for journal/history |
| Archive-node recipe | documented config combo | ❌ | needs the stores above first |

## 6. Cosmos-SDK application parity

Oxide was never intended to be SDK-wire-compatible, but cosmos-evm's module
surface is the reference for "complete L1 functionality":

| Module | cosmos-evm | Oxide | Status |
|---|---|---|---|
| `x/auth` accounts + ante (sig verify, nonce, fee deduct) | ✅ | 🟡 | secp256k1 recovery in EVM path; native modules have no unified ante/nonce layer — executor tracks `executed_nonces` per module |
| `x/bank` | ✅ | ✅ | balances, transfer, supply |
| `x/staking` | ✅ | ✅ | delegate, undelegate, validator add/remove, key rotation |
| `x/distribution` (staking rewards) | ✅ | ❌ | **missing** — validators earn only burned-fee remainder? Fee destination needs a design decision |
| `x/slashing` + evidence | ✅ | ❌ | **missing** — no downtime/double-sign slashing; oxideBFT has BLS QC evidence to slash on |
| `x/gov` | ✅ | 🟡 | module exists — verify proposal lifecycle/vote/tally/deposit params |
| `x/feemarket` | ✅ | ✅ | `BaseFeeState` EIP-1559 |
| `x/erc20` STRv2 | ✅ | ❌ | see §3 |
| `x/precisebank` (18-decimal wrap) | ✅ | ➖ | Oxide native denom is already atto-scaled |
| `x/vesting` | ✅ | ❌ | optional |
| `x/ibc/callbacks` | ✅ | ➖ | no IBC |
| `x/upgrade` (chain halt/software upgrade) | ✅ | ❌ | **missing** — no coordinated upgrade mechanism; only rolling restarts |
| Module migrations / version maps | ✅ | ❌ | no migration framework |
| Genesis validate / import / export per module | ✅ | 🟡 | EVM `alloc` missing; other modules partial |

## 7. Wallet / tooling compatibility

| Item | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| MetaMask | ✅ | 🟡 | connects, but `eth_call`/receipts/logs stubs break real use |
| Foundry/Hardhat/Remix | ✅ | 🟡 | deploy needs `eth_estimateGas` + receipts; verify needs `eth_getCode` at tags |
| ethers.js/viem/web3.js | ✅ | 🟡 | same blockers |
| Blockscout/explorers | ✅ | ❌ | needs full block/tx/receipt/log APIs |
| HD keys `m/44'/60'` | ✅ | ✅ | secp256k1, coin-type-60 compatible keys work |
| Ledger via Ethereum app | ✅ | ❌ | optional |
| EIP-712 typed-data signing of native msgs | ✅ | ✅ | `Tx(address sender,uint64 nonce,uint64 fee,uint8 moduleId,bytes payload)` over `Oxide`-v1 domain; `eth_signTypedData_v4` signs bank/staking/exchange txs |
| Dual bech32+hex addressing | ✅ | ➖ | single 20-byte space — simpler; document `0x` as canonical |

## 8. Operations

| Item | cosmos-evm | Oxide |
|---|---|---|
| Prometheus + OTel spans | ✅ | 🟡 `/metrics` exists, no tracing spans |
| `evmd testnet init-files` multi-node generator | ✅ | 🟡 `tls-gen` + `genesis` CLI; no all-in-one init-files |
| Docker compose / k8s manifests | ✅ example | 🟡 `oxide-deploy` + docs; no published image |
| Public peer discovery | bootstrap peers | 🟡 gossip discovery exists (`p2p/discovery.rs`); validators correctly use static+mTLS |
| State sync bootstrap | ✅ | ❌ `/snapshot` exists; no fetch-and-verify protocol |

---

## Prioritized roadmap

### P0 — required before claiming "EVM compatible" to external devs

1. **Canonical block/tx/receipt/log store** — persist per-block: header,
   txs, receipts (status, gas, logs, bloom), tx hash→(h,i) index.
   Wire `indexer` (or a new `evm-history` store) into `run_consensus_loop`
   + RPC. Unblocks: `eth_getBlockByHash`, `eth_getTransactionByHash`,
   `eth_getTransactionReceipt`, `eth_getBlockReceipts`, tx-count and
   by-index lookups, `eth_getLogs`, real `eth_feeHistory`.
   *Files: new store in `modules/evm/src/history.rs` or `crates/indexer`
   extension; `crates/rpc/src/lib.rs` handlers.*

2. **Read-only call path** — `EvmModule::call_read(from, to, data, value,
   gas, [block])` executing revm against a cloned/readonly DB with no
   signature requirement. Unblocks `eth_call`, `eth_estimateGas`
   (binary search), `eth_createAccessList`, `debug_traceCall`.
   *Files: `modules/evm/src/lib.rs` (new method beside `execute_signed`),
   `crates/rpc/src/lib.rs`.*

3. **Correct block tags** — `latest`/`earliest`/`safe`/`finalized` → real
   heights (instant finality: safe==finalized==latest); `pending` → latest
   + mempool overlay where feasible.
   *File: `crates/rpc/src/lib.rs` `parse_block_tag`.*

4. **Tx gossip** — broadcast submitted txs to peers (or at minimum to the
   current/next leaders). Without it, `eth_sendRawTransaction` to a
   non-leader node is broken in multi-validator deployments.
   *Files: `crates/p2p` (tx message type), `bin/oxide-validator` (submitter
   that gossips), `crates/mempool` (dedupe).*

### P1 — production-grade EVM service

5. ~~**Mempool ordering**~~ — **shipped**: per-sender nonce queues,
   fee-ordered select, and same-nonce replacement enforcing geth's
   ≥10% bump (`ReplacementUnderpriced` below the threshold).
6. ~~**WebSocket transport**~~ — **shipped**: axum `ws` upgrade on
   `GET /` (same port as HTTP, geth convention), per-connection
   subscription registry, `publish_new_block` fans out on finalization,
   `newPendingTransactions` pushes canonical EVM tx hashes for locally
   submitted + gossip-accepted txs.
7. ~~**Filter APIs**~~ — **shipped**: `eth_newFilter` (log filters reuse
   `eth_getLogs` semantics), `eth_newBlockFilter`, `eth_newPendingTransactionFilter`,
   `eth_getFilterChanges` (cursor semantics), `eth_getFilterLogs`,
   `eth_uninstallFilter`; 300s TTL with `filter not found` on expiry.
8. ~~**Staking precompile side effects**~~ — **shipped**: `0x0C01`/`0x0C02`
   run the same bank-backed native cores as `MsgDelegate`/`MsgUndelegate`
   (the exploit-safe path — see §3 note), rolled back on EVM-frame revert
   by the native journal. Remaining: redelegate, queries, gov precompile.
9. ~~**Preinstalls**~~ — **shipped**: Create2 factory, Multicall3, Permit2,
   Safe proxy+singleton, and the EIP-2935 history contract (Prague-gated)
   at canonical addresses (bytecode verified against
   `alloy_eips::eip2935`/mainnet `eth_getCode`); `evm.alloc` in
   `GenesisConfig`. The contract's ring buffer is populated by a
   `begin_block` parent-hash write — state-equivalent to geth's system
   call.
10. ~~**RPC resource limits**~~ — **shipped**: `gas-cap` (`eth_call` +
    `debug_traceCall` clamp to `CHAIN_BLOCK_GAS_LIMIT`), `evm-timeout`
    (`DeadlineInspector` halts the sim interpreter on a wall-clock
    deadline; consensus path unaffected), log-cap (`MAX_LOG_RESULTS` =
    10k on `eth_getLogs` + all filter log paths), `feehistory-cap`
    (`MAX_FEE_HISTORY_BLOCKS` = 1,024), filter TTL (300s),
    `filter-cap` (`MAX_FILTERS` = 1,024 live entries),
    `batch-request-limit` (`MAX_BATCH_REQUESTS` = 1,024 per JSON array),
    `max-open-connections` (listener-level accept bound), `http-timeout`
    (30 s dispatch bound → HTTP 408; WS writes bounded at 30 s).

### P2 — conformance and completeness

11. ~~**Historical state queries**~~ — **shipped**: first-write-wins
    per-block undo (`versioned.rs`) indexed per-account over the
    `history_serve_window` (default 8192); `StateView` overlay serves
    balance/nonce/code/storage and full `eth_call`/`estimateGas`/
    `traceCall`/`createAccessList` simulations at `h ∈ [floor−1, latest]`;
    too-new → `header not found`, pruned → `missing trie node` (geth's
    strings). Persisted across restart with history.
12. ~~**`eth_getProof`**~~ — **shipped**: EIP-1186 account + storage
    proofs at any retained height; the account/storage tries are rebuilt
    at the versioned view while `ProofRetainer` keeps the path nodes;
    non-inclusion proofs included; parity tests verify nodes against the
    sealed state root.
13. ~~**`debug_trace*` namespace**~~ — **shipped**: callTracer via revm
    inspector composition (`(NativeJournalInspector, CallRecorder)`
    tuple); `debug_traceTransaction`/`traceCall`/`traceBlockByNumber`/
    `traceBlockByHash`; traces recorded at execution time into
    `evm::history` (bounded by its window — no historical-state
    re-execution while state is latest-only); unsupported tracers error
    explicitly.
14. ~~**`txpool_*` namespace**~~ — **shipped**: `txpool_status`/
    `content`/`contentFrom`/`inspect` over a `TxpoolProvider` trait so
    the RPC crate stays executor-agnostic (validator wires the impl);
    pending/queued split follows the mempool's nonce-gap queues.
15. ~~**EIP-7702 SetCodeTx**~~ — **shipped**: `TxEip7702` +
    `TxAuthorization` RLP decode/encode/recover (type `0x04`, `0x05`
    authorization domain), revm `authorization_list` wiring, Prague spec
    gate, `authorizationList` in RPC tx JSON; delegated-EOA execution
    verified end-to-end.
16. ~~**EIP-712 signing for native module txs**~~ — **shipped**: signed
    native envelope (`module_id | 0x80` flag + `r‖s‖v` between module ID
    and payload), `Tx(address sender,uint64 nonce,uint64 fee,uint8
    moduleId,bytes payload)` struct over the `Oxide`-v1 EIP-712 domain (chain-ID-bound,
    cross-chain replay-proof); `crypto::eip712` sign/verify helpers with
    spec-vector KATs; executor verifies at ingest/batch/execute and
    `process_proposal` statically rejects the flag on self-authenticating
    modules; `Module::authenticates_sender` (EVM = true, its RLP sig is
    authoritative); `UnsignedTxPolicy` (`Allow` compat default, validator
    `--require-signed-txs` rejects unsigned); `mempool::build_signed_tx`
    helper; `oxide_sendRawTransaction` RPC submits hex envelopes and
    returns the BLAKE3 tx hash. This also closed the pre-existing hole
    where native senders were merely *declared*, not proven.
17. **ERC20 facade over bank denoms** — dynamic precompile per denom
    (STRv2-lite, no IBC).

### P3 — chain completeness (non-EVM)

18. **Distribution** — fee/reward distribution to validators+delegators;
    decide base-fee burn-vs-distribute policy (documented difference
    from cosmos-evm either way).
19. **Slashing + evidence** — double-sign/downtime slashing from QC
    evidence.
20. **Upgrade mechanism + module migrations** — coordinated halts, version
    maps.
21. **State sync protocol** — verified bootstrap from `/snapshot`.
22. **Pruning policies.**

### Conformance gates

- Differential test harness: run the same tx sequences through revm
  (Oxide path) and a geth/reth reference; compare state roots, receipts,
  gas.
- JSON-RPC conformance suite: replay ethereum/execution-apis test
  vectors + a Hardhat/ethers smoke matrix in CI.
- Fuzz: `eth_sendRawTransaction` decoder, `eth_call` params, filter args.

### Deliberately out of scope

- IBC (`x/ibc/*`, ICS20/ICS02 precompiles, callbacks, relayer APIs)
- `personal_*` keyring custody APIs, `eth_sendTransaction`,
  `eth_sign*` node-side signing
- `miner_*`, `engine_*`, `clique`, `les`, `trace_*` (openethereum-style)
- Cosmos wire/gRPC compatibility, bech32, CometBFT RPC
- `extra_eips` runtime opcode mutation, `access_control` permissioned EVM
  (revisit only if a permissioned deployment is ever required)
