# EVM parity gap analysis — Oxide vs. cosmos-evm

Comparison target: `github.com/cosmos/evm` (evmOS successor), latest release
v0.7.2. cosmos-evm embeds go-ethereum (Cosmos fork ~v1.17) behind a
`vm.StateDB` adapter over the Cosmos SDK KVStore — no Merkle Patricia Trie.
Oxide embeds revm at SpecId::PRAGUE with a flat account/storage model and a
sparse retained trie for state roots.

This document inventories release-grade functionality cosmos-evm ships and
maps each item to Oxide's current state: **implemented**, **partial/stub**,
**missing**, or **out of scope** (deliberately not planned — e.g. IBC).

## Legend

- ✅ implemented and functional
- 🟡 partial — code exists but is stubbed, unwired, or semantically incomplete
- ❌ missing entirely
- ➖ out of scope for Oxide's architecture

---

## 1. Ethereum JSON-RPC surface

cosmos-evm namespaces: `eth`, `web3`, `net`, `txpool`, `debug`, `personal`
(miner/admin stubs). Oxide implements `eth` + `web3` + `net` over HTTP only.

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
| `eth_getLogs` | ✅ bloom-prefiltered scan, `block-range-cap` 10k | ❌ | returns `[]` — no log index over receipts |
| `eth_newFilter` / `eth_getFilterChanges` / `eth_getFilterLogs` / `eth_newBlockFilter` / `eth_newPendingTransactionFilter` / `eth_uninstallFilter` | ✅ | ❌ | no filter registry at all |
| `eth_sendRawTransaction` | ✅ | 🟡 | decodes + submits to **local mempool only** — no tx gossip to peers (see §4) |
| `eth_call` | ✅ EVM simulation, `gas-cap`, `evm-timeout` | ❌ | returns `"0x"` — `execute_signed` requires signature recovery; **no read-only call path exists in the EVM module** |
| `eth_estimateGas` | ✅ binary search + state overrides | ❌ | returns `0x5208` unconditionally |
| `eth_createAccessList` | ✅ | ❌ | not implemented |
| `eth_gasPrice` | ✅ | 🟡 | returns configured base fee, not a market quote |
| `eth_maxPriorityFeePerGas` | ✅ | 🟡 | stub `0x3b9aca00` (1 gwei) — should reflect recent block tips |
| `eth_feeHistory` | ✅ | 🟡 | minimal synthetic response, no real base-fee/reward history |
| `eth_getProof` | ✅ (height > 2) | ❌ | needs Merkle proof generation over the state trie (`trie.rs` computes roots; no proof path) |
| `eth_sign` / `eth_signTypedData` | ✅/partial | ❌ | keyring-backed — deliberately omit (nodes should not custody user keys) |
| `eth_sendTransaction` / `eth_pendingTransactions` | ❌/partial | ❌ | `sendTransaction` is a node-custody API — omit; `pendingTransactions` needs the txpool index |
| `eth_subscribe` / `eth_unsubscribe` | ✅ WS: `newHeads`, `logs`, `newPendingTransactions` | ❌ | subscription manager exists but **no WebSocket transport** (no `tokio-tungstenite` dep); subs never deliver |
| `txpool_content` / `txpool_contentFrom` / `txpool_inspect` / `txpool_status` | ✅ | ❌ | no txpool namespace — mempool has no nonce-gap queue to expose |
| `debug_traceTransaction` / `debug_traceBlock*` / `debug_traceCall` | ✅ re-execution via EVM | ❌ | needs revm inspector hooks — feasible, not built |
| `debug_*` runtime profiling endpoints | ✅ | ❌ | Go-specific; equivalent Rust profiling hooks not needed |
| `personal_*` (keyring) | ✅ partial | ❌ | out of scope — node-custodied keys are a security liability |
| JSON-RPC resource limits | `gas-cap` 25M, `evm-timeout`, `filter-cap` 200, `feehistory-cap` 100, `batch-request-limit`, `max-open-connections`, `http-timeout` 30s | 🟡 | only per-client rate limiting exists |
| WS endpoint `:8546` | ✅ | ❌ | no WS listener |

**Summary:** ~17 of ~35 advertised `eth_*` methods return correct data today;
the rest are stubs returning `null`/`[]`/fixed values. The single biggest
structural gap is that **finalized blocks, transactions, receipts, and logs
are not retained anywhere** — the `indexer` crate exists (451 lines, indexes
`FinalizedBlock` events + tx hashes) but is not wired to the validator or
RPC and does not capture EVM receipts/logs/blooms.

## 2. EVM execution semantics

| Feature | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| Interpreter | geth `core/vm` (Cosmos fork 1.17) | revm, `SpecId::PRAGUE` | parity in fork level |
| Legacy tx type 0 | ✅ | ✅ | — |
| EIP-2930 access-list tx (type 1) | ✅ | ✅ | — |
| EIP-1559 dynamic-fee tx (type 2) | ✅ | ✅ | — |
| EIP-4844 blob tx (type 3) | ✅ parsed | ❌ rejected `Malformed` | acceptable to reject — no blob lane in consensus; document it |
| EIP-7702 SetCodeTx (type 4) | ✅ (v0.5+) | ❌ | not parsed; revm supports authorization lists — wire if Prague-complete is claimed |
| EIP-155 chain-ID replay protection | ✅ | ✅ | — |
| `allow_unprotected_txs` policy | rejects pre-EIP-155 by default | 🟡 | verify unprotected legacy txs are rejected at `validate` |
| secp256k1 sender recovery | ✅ | ✅ | — |
| Intrinsic gas / calldata gas / access-list warm costs | geth | revm | conformance suite needed to prove parity |
| Gas refund semantics | ✅ | ✅ via revm | — |
| `BLOCKHASH` last-256-blocks | ✅ (+EIP-2935 history contract) | 🟡 | `block_hash_ref` exists — verify it serves real hashes for N−1..N−256 and zero beyond |
| Base fee | EIP-1559 via `x/feemarket`, **distributed to validators** | EIP-1559 `BaseFeeState`, **burned** (revm default) | design choice — burning is Ethereum-L1-faithful; distribution is Cosmos-faithful. Decide + document |
| `evm_denom` / native-token-as-gas | ✅ | ✅ | native balance == EVM balance (single account space — simpler than dual-model) |
| Preinstalls (Create2 `0x4e59…`, Multicall3 `0xcA11…`, Permit2 `0x0000…D473`, Safe singleton `0x914d…`, EIP-2935 history `0x0000F908…`) | ✅ at genesis | ❌ | **high value, low cost** — Foundry/Hardhat/DeFi tooling assumes these exist at canonical addresses |
| Genesis `alloc` (accounts/code/storage) | ✅ | 🟡 | genesis covers validators + bank balances; EVM `alloc` not exposed in `GenesisConfig` |
| `access_control` — permissioned create/call whitelists | ✅ | ❌ | optional; needed only for permissioned-deployment chains |
| `extra_eips` / custom opcode hooks | ✅ | ❌ | out of scope — revm fork schedule is fixed at compile time |
| Historical state queries (`history_serve_window`, default 8192) | ✅ | ❌ | **architectural gap** — state DB is mutable, no versioned reads; needs snapshot-per-window or versioned store |

## 3. Precompiles

cosmos-evm static registry (`0x…0100`–`0x…0807`) + dynamic ERC20/WERC20:

| Precompile | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| Standard geth set (ecrecover, sha256, ripemd160, identity, modexp, ecadd, ecmul, ecpairing, blake2f, kzg) | ✅ | ✅ via revm | — |
| P256 `0x…0100` | ✅ | ❌ | add if requested — cheap |
| Bech32 `0x…0400` | ✅ | ➖ | no bech32 in Oxide addressing |
| Staking `0x…0800` (delegate/redelegate/undelegate/queries) | ✅ **state-mutating** | 🟡 | `0x0C01` delegate **explicitly reverts — side effect not wired** (`precompiles.rs` test asserts revert) |
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
| Mempool model | geth `legacypool` port — nonce-gap queue, replacement-by-tip, insert-time validation | FIFO `VecDeque` + size cap | **critical** — no nonce ordering, no replacement, no `pending`/`queued` split |
| Tx gossip | CometBFT mempool gossip | ❌ | **critical** — `eth_sendRawTransaction` lands in the local node's mempool only; if that node isn't the current leader the tx waits for its leader turn |
| Pending-tx visibility | `PendingTxListener` feeds `newPendingTransactions` + `"pending"` block tag | ❌ | no pending overlay |
| Priority ordering | tip-based (`min(tip_cap, fee_cap − base_fee)`) | insertion order | needed for fair fee market + trading-stack ordering guarantees |
| `max_gas_wanted` per-tx cap | ✅ | 🟡 | `BlockBudget` exists; per-tx cap not enforced at RPC ingress |

## 5. State, history, and indexing

| Capability | cosmos-evm | Oxide | Gap |
|---|---|---|---|
| Canonical block store | CometBFT blockstore + `BlockResults` | ❌ | `FinalizedBlock`s stream to listeners; `MAX_RETAINED_FINALIZED` in devnet is a test fixture, not a store |
| Tx index | `KVIndexer` (hash→(h,i), (h,i)→tx) | ❌ | `indexer` crate not wired; doesn't index EVM receipts anyway |
| Receipt/log persistence | per-block logs+bloom in store; receipts via indexer | ❌ | receipts dropped after event emission |
| Historical state | `history_serve_window` 8192; EIP-2935 for BLOCKHASH | ❌ | no versioned state reads |
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
| EIP-712 typed-data signing of native msgs | ✅ | ❌ | needed if MetaMask should sign staking/exchange txs |
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

5. **Mempool ordering** — nonce-gap queue + tip ordering + replacement
   (port of legacypool semantics, sized for the trading stack's needs).
6. **WebSocket transport** — `newHeads`, `logs`, `newPendingTransactions`
   on `:8546` (`tokio-tungstenite`); the `SubscriptionManager` is already
   in place.
7. **Filter APIs** — `eth_newFilter`/`eth_getFilterChanges`/`eth_newBlockFilter`
   over the log index from (1).
8. **Staking precompile side effects** — wire `0x0C01` delegate through the
   native staking path with full invariant checks (see §3 security note);
   add gov precompile.
9. **Preinstalls** — deploy Create2 factory, Multicall3, Permit2, Safe
   singleton at canonical addresses in genesis; add EVM `alloc` to
   `GenesisConfig`.
10. **RPC resource limits** — `gas-cap`, `evm-timeout`, `filter-cap`,
    `feehistory-cap`, `batch-request-limit`, `max-open-connections`.

### P2 — conformance and completeness

11. **Historical state queries** — versioned reads over a serve window
    (cosmos-evm's `history_serve_window`≈8192 is a sane default); enables
    `eth_call`/`eth_getBalance`/`eth_getStorageAt` at past heights and
    `eth_getProof`.
12. **`eth_getProof`** — Merkle proofs over the state trie.
13. **`debug_trace*` namespace** — revm inspector hooks.
14. **`txpool_*` namespace** — after mempool (5).
15. **EIP-7702 SetCodeTx** — parse type-4 + authorization lists (revm
    supports; wire decode + spec gate).
16. **EIP-712 signing for native module txs** — MetaMask-signable staking/
    exchange messages.
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
