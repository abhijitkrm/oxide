# EVM Reference: reth

## Purpose

reth (https://github.com/paradigmxyz/reth) is the canonical EVM
reference implementation for Oxide — analogous to how cosmos-evm
uses geth as its reference. This skill defines when and how to
consult reth when implementing or verifying Oxide's EVM module.

## When to consult reth

- **State persistence**: How reth wires revm's `CacheDB` to durable
  storage (MDBX-backed). Compare our `StorageBackend` flush/load
  pattern against reth's `StateProvider` / `DatabaseProvider` design.
- **Block execution pipeline**: How reth executes a block (begin →
  txs → end → state root). Verify our `execute_block` matches the
  same ordering and gas accounting.
- **Replay integrity**: How reth replays blocks from chain history
  and verifies state root equality. Our replay tests should match
  reth's guarantees.
- **Gas accounting**: EIP-1559 base fee adjustment, cumulative gas
  per block, gas refund logic. Compare against reth's
  `revm::primitives` usage.
- **Nonce progression**: How reth tracks account nonces across
  blocks. Verify our `CacheDB` nonce handling matches.
- **JSON-RPC parity**: reth's `eth_*` RPC method implementations are
  the reference for our `crates/rpc` server. When in doubt about
  response format or edge cases, check reth's RPC handlers.
- **Test suites**: reth's integration tests and hive test results
  are the gold standard for EVM correctness. When we find a
  discrepancy, write a regression test that would also fail in reth.

## How to use reth (reference-only, no forking)

1. **Study the design**: Read reth's source for the subsystem in
   question. Understand the architecture, not just the code.
2. **Compare behavior**: Write a test in Oxide that exercises the
   same scenario. If our behavior differs from reth's, investigate
   whether it's a bug or a deliberate design choice.
3. **Document the reference**: In the devlog or code comments, cite
   the reth file/function that informed the design decision.
4. **No copying**: Oxide is original code. reth is a reference for
   understanding EVM behavior, not a source of code to copy. The
   `revm` crate (which both Oxide and reth use) is the shared
   execution engine.

## Key reth subsystems to reference

| Subsystem | reth path | Oxide equivalent |
|-----------|-----------|------------------|
| Block execution | `crates/evm/` | `modules/evm/src/lib.rs` |
| State persistence | `crates/storage/` | `modules/evm/src/persist.rs` |
| JSON-RPC | `crates/rpc/rpc-api/` | `crates/rpc/src/lib.rs` |
| Transaction pool | `crates/transaction-pool/` | `crates/mempool/src/lib.rs` |
| Consensus (post-merge) | `crates/consensus/` | `crates/consensus/src/engine.rs` |
| P2P networking | `crates/net/` | `crates/p2p/src/lib.rs` |

## Relationship to revm

Both Oxide and reth use the `revm` crate as the EVM execution engine.
This means the core EVM semantics (opcode behavior, gas costs, state
transitions) are identical — they come from the same library. What
differs is the **host** around revm: how state is stored, how blocks
are sequenced, how transactions are routed, and how the JSON-RPC API
is exposed. reth is the reference for these host-level decisions.
