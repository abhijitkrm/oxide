//! Oxide EVM module — revm host, precompiles, EIP-1559 gas metering.
//!
//! This module is the `x/vm` analog (plan.md §2, §8): it wraps the
//! `revm` EVM engine and exposes it as a Cosmos-SDK-style `Module`
//! in the Oxide module router. Native messages (staking,
//! trading) and EVM transactions share the same block and gas meter.
//!
//! # Reference implementation
//!
//! **reth** (<https://github.com/paradigmxyz/reth>) is the canonical
//! EVM reference for Oxide — analogous to how cosmos-evm uses geth.
//! When verifying EVM correctness (state persistence, replay
//! integrity, gas accounting, nonce progression, JSON-RPC parity),
//! we consult reth's execution pipeline and test suites. See
//! `plan.md` §16 for the full reference framework.
//!//!
//! # What this module does
//!
//! - Receives raw signed EVM transactions via the module router's
//!   `handle` dispatch. The message is an RLP-encoded signed
//!   transaction (Legacy, EIP-2930, or EIP-1559 per EIP-2718).
//! - Recovers the sender from the transaction's secp256k1 signature —
//!   **never** trusts the outer envelope's sender field. This is the
//!   core security boundary (Phase A).
//! - Enforces EIP-155 chain ID replay protection.
//! - Executes the transaction through `revm` with EIP-1559 gas metering.
//! - Persists account state (balance, nonce, code, storage) in a
//!   `CacheDB` (in-memory, backed by `EmptyDB`).
//! - Emits execution results as Oxide events (gas used, status, logs).
//!
//! # Why a module, not a standalone crate
//!
//! The Oxide architecture (plan.md §2) treats the EVM as one execution
//! track alongside the native track (trading modules). Both are modules
//! in the router; the executor dispatches by module ID. This keeps the
//! EVM swappable (future SVM/MoveVM modules use the same seam) and
//! lets native precompiles call into EVM and vice versa.
//!
//! # Phase 2 scope
//!
//! v0 implements:
//! - A `revm` `Evm` instance with a `CacheDB`-backed state.
//! - EIP-1559 gas metering (base fee + priority fee).
//! - Signed transaction execution (Legacy, EIP-2930, EIP-1559) with
//!   secp256k1 sender recovery (Phase A).
//! - EIP-155 chain ID replay protection.
//! - Account state in `CacheDB` (in-memory).
//! - Optional `StorageBackend` persistence (flush after each block,
//!   load on construction — added session 26).
//!
//! Future phases add:
//! - Gas debiting, base-fee burn, and priority-fee tips (Phase A5).
//! - Block context and coinbase/fee-recipient wiring (Phase A6).
//! - Precompiles that call into native modules (staking, trading).
//! - Parallel OCC scheduler for cross-tx parallelism.
//! - JSON-RPC + WebSocket server.

use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::{Balances, module_id};
use primitives::{Address, Hash, Height};
// Ceiling 1: the chain-configured block gas limit is the single
// source of truth for the EVM's block gas limit too.
use parallel::{CoinbaseObs, GroupExecResult, SharedCacheDB, SpecTx};
use trie::{encode_trie_leaf, sparse_walk};
use types::CHAIN_BLOCK_GAS_LIMIT;
// rayon: parallel secp256k1 sender recovery in `handle_batch`.
// 88% of per-tx cost is ECDSA recovery; parallelizing across cores
// turns that into 88%/N_cores.
use rayon::prelude::*;

mod batch;
mod build;
pub mod coinbase_read;
pub mod deadline;
mod fastpath;
pub mod fee;
pub mod history;
pub mod ledger;
mod module_impl;
pub mod native_journal;
pub mod overrides;
mod parallel;
mod persist;
pub mod precompiles;
pub mod preinstalls;
mod read;
pub mod receipts;
pub mod spec;
pub mod trace;
pub mod trie;
pub mod tx;
pub mod versioned;

// revm imports. The `revm` crate re-exports all sub-crates.
use revm::Context;
use revm::context::TxEnv;
use revm::context::result::{ExecutionResult, Output, SuccessReason};
use revm::context_interface::result::ResultGas;
use revm::database::CacheDB;
use revm::database_interface::{DatabaseCommit, DatabaseRef, EmptyDB};
use revm::handler::{ExecuteCommitEvm, MainContext};
use revm::inspector::InspectEvm;
use revm::primitives::TxKind;
use revm::primitives::hardfork::SpecId;
use std::sync::Arc;

/// The EVM module's dispatch ID in the module router.
///
/// Reserved by `framework::module_id::EVM` (3). Native modules use
/// IDs 0–2 (core, reserved, staking); the EVM is the first VM module.
pub const MODULE_ID: u8 = module_id::EVM;

/// One traced execution: the execution result paired with the
/// call-trace root recorded beside it (`None` when recording was
/// off or the tx never entered the interpreter).
///
/// Aliased because the parallel batch path threads `(position,
/// result)` pairs through several helper signatures — the
/// fully-spelled type obscured the plumbing.
pub(crate) type TracedResult =
    Result<(revm::context::result::ExecutionResult, Option<trace::CallFrame>), ExecError>;

/// Wrap an RLP-encoded signed EVM transaction in the Oxide v0 tx
/// envelope format for mempool submission.
///
/// The v0 envelope is:
/// `[sender:20B][nonce:8B LE][fee:8B LE][module_id:1B][payload]`
///
/// For EVM, the `payload` is the raw RLP-encoded signed transaction.
/// The `sender`, `nonce`, and `fee` fields are used by the mempool
/// for fee-priority selection and nonce ordering. The EVM module
/// ignores them during execution — it recovers the sender from the
/// secp256k1 signature in the RLP payload.
///
/// # Arguments
///
/// - `sender`: the recovered sender address (20 bytes).
/// - `nonce`: the transaction's nonce (for mempool nonce ordering).
/// - `fee`: the transaction's fee (for mempool fee-priority ranking).
/// - `rlp_signed_tx`: the RLP-encoded signed EVM transaction bytes.
///
/// # Returns
///
/// The v0 envelope bytes, ready for `Executor::ingest_tx`.
pub fn wrap_evm_tx_envelope(
    sender: &primitives::Address,
    nonce: u64,
    fee: u64,
    rlp_signed_tx: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20 + 8 + 8 + 1 + rlp_signed_tx.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(MODULE_ID);
    bytes.extend_from_slice(rlp_signed_tx);
    bytes
}

/// Inverse of [`wrap_evm_tx_envelope`]: return the raw signed-EVM
/// RLP bytes carried by a v0 envelope.
///
/// Returns `None` when the envelope is too short to hold the
/// header or routes to a different module — non-EVM envelopes pass
/// through the same mempool/gossip path and must not be mistaken
/// for EVM payloads (e.g. by the pending-tx feed).
#[must_use]
pub fn unwrap_evm_tx_envelope(envelope: &[u8]) -> Option<&[u8]> {
    /// Envelope header: `[sender:20][nonce:8][fee:8][module:1]`.
    const HEADER_LEN: usize = 20 + 8 + 8 + 1;
    if envelope.len() <= HEADER_LEN || envelope[HEADER_LEN - 1] != MODULE_ID {
        return None;
    }
    Some(&envelope[HEADER_LEN..])
}

/// The base intrinsic gas cost for any EVM transaction (EIP-2028).
///
/// `21_000` gas is the cost of a simple value transfer (no calldata, no
/// contract creation). This is a conservative lower bound for the
/// intrinsic gas check in `validate`; the full calldata-aware check
/// arrives with the gas economics phase (A5).
const INTRINSIC_GAS_BASE: u64 = 21_000;

/// The block time in seconds. Used to derive a deterministic timestamp
/// from the block height when the real timestamp is not yet wired from
/// the block header. Ethereum mainnet uses ~12s; we use 15s as a
/// conservative estimate.
const BLOCK_TIME_SECS: u64 = 15;

/// The default gas limit for a single EVM transaction (EIP-1559).
///
/// 30M gas matches Ethereum mainnet's default block-level tx limit.
/// This is a cold-path constant (set once per tx, not per-opcode).
/// Used by test helpers when constructing signed transactions.
#[cfg(test)]
const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// Intrinsic gas cost for a simple ETH transfer (no calldata).
/// This is the EVM base transaction cost: 21,000 gas units per
/// EIP-2028. Used by the native fast path to bypass revm for
/// simple transfers.
const TX_GAS_TRANSFER: u64 = 21_000;

/// A transaction with a pre-recovered sender.
///
/// The mempool recovers the sender once at ingestion time (via
/// [`SignedTx::recover_sender`](tx::SignedTx::recover_sender)). The
/// execution layer trusts this pre-recovered sender and skips
/// secp256k1 recovery entirely, saving ~30 µs/tx — the dominant
/// cost in batch execution.
///
/// # Security
///
/// The caller MUST ensure `sender` is correctly recovered from
/// `raw`. A byzantine block proposer providing wrong senders will
/// cause state divergence, detectable by state root comparison
/// across validators. For the Phase 0 devnet (single validator),
/// trusting the proposer is safe. For production, pair this with
/// verification sampling (future work).
///
/// # Construction
///
/// Use [`EvmModule::preverify_batch`] to construct a batch of
/// `PreverifiedTx` from raw RLP-encoded transactions. Then pass
/// the result to [`EvmModule::handle_batch_preverified`] or
/// [`EvmModule::handle_batch_parallel_preverified`].
#[derive(Debug, Clone)]
pub struct PreverifiedTx<'a> {
    /// RLP-encoded signed transaction bytes (Legacy, EIP-2930, or
    /// EIP-1559 per EIP-2718), borrowed from the caller's buffer —
    /// the batch hot path must not clone per-tx.
    pub raw: &'a [u8],
    /// The sender recovered from the transaction's secp256k1
    /// signature by the mempool. The execution layer trusts this
    /// address without re-verifying.
    pub sender: revm::primitives::Address,
}

/// An `eth_call` / `eth_estimateGas` request — the read-only
/// counterpart of a signed transaction.
///
/// Field names mirror the JSON-RPC call object. `from` defaults to
/// the zero address (geth's behaviour for unsigned calls), `gas` to
/// the block gas limit, and every fee field to zero. Either
/// `gas_price` (plain) or the EIP-1559 pair
/// (`max_fee_per_gas`, `max_priority_fee_per_gas`) may be set; the
/// EIP-1559 pair wins when both are present.
#[derive(Debug, Clone, Default)]
pub struct CallRequest {
    /// Caller address; `None` → `0x0000…0000`.
    pub from: Option<Address>,
    /// Callee; `None` simulates a contract creation.
    pub to: Option<Address>,
    /// Gas limit; `None` → block gas limit. Values above the block
    /// gas limit are capped at it (a tx that needs more than a
    /// block's worth can never execute anyway).
    pub gas: Option<u64>,
    /// Plain `gasPrice` (legacy-style fee field).
    pub gas_price: Option<u128>,
    /// EIP-1559 `maxFeePerGas`.
    pub max_fee_per_gas: Option<u128>,
    /// EIP-1559 `maxPriorityFeePerGas`.
    pub max_priority_fee_per_gas: Option<u128>,
    /// Wei value to transfer.
    pub value: revm::primitives::U256,
    /// Calldata or initcode.
    pub data: Vec<u8>,
    /// Optional nonce override — rarely set for calls (nonce checks
    /// are disabled in the sim env anyway).
    pub nonce: Option<u64>,
    /// Optional EIP-2930 access list.
    pub access_list: tx::AccessList,
}

/// A successful read-only call's output (`eth_call` result).
#[derive(Debug, Clone)]
pub struct CallOutcome {
    /// The EVM return data.
    pub output: Vec<u8>,
    /// Gas consumed by the call.
    pub gas_used: u64,
}

/// Why a read-only call failed — maps onto Ethereum's `eth_call`
/// error surface (code 3 + revert data for reverts).
#[derive(Debug)]
pub enum CallError {
    /// The call executed REVERT. `output` is the revert data —
    /// including ABI `Error(string)` payloads clients decode.
    Revert {
        /// Revert return data.
        output: Vec<u8>,
        /// Gas consumed up to the revert.
        gas_used: u64,
    },
    /// The call halted without a revert (out-of-gas, stack overflow,
    /// invalid opcode…). `reason` is the revm halt kind.
    Halt {
        /// Debug name of the halt reason.
        reason: String,
        /// Gas consumed before the halt.
        gas_used: u64,
    },
    /// Validation failed before execution (insufficient funds for
    /// `gas*price + value`, malformed env).
    Rejected(ExecError),
}

/// Why a state read at a requested height cannot be served — maps
/// onto geth's `header not found` / `missing trie node` errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    /// The requested height is beyond the latest sealed block.
    TooNew {
        /// Requested height.
        requested: u64,
        /// Latest sealed height.
        latest: u64,
    },
    /// The requested height is below the retained undo window — the
    /// pre-values needed to reconstruct it were pruned.
    Pruned {
        /// Requested height.
        requested: u64,
        /// Oldest height still servable.
        floor: u64,
    },
}

impl StateError {
    /// The height the caller asked for.
    #[must_use]
    pub fn requested(&self) -> u64 {
        match *self {
            Self::TooNew { requested, .. } | Self::Pruned { requested, .. } => requested,
        }
    }
}

/// An `eth_getProof` (EIP-1186) response: the account fields plus
/// the Merkle-Patricia proof path as RLP-encoded nodes, and one
/// proof per requested storage key.
#[derive(Debug, Clone)]
pub struct AccountProof {
    /// The queried address.
    pub address: revm::primitives::Address,
    /// Account balance at the queried height (0 for absent accounts).
    pub balance: revm::primitives::U256,
    /// Account `code_hash` (`KECCAK_EMPTY` for EOAs / absent).
    pub code_hash: revm::primitives::B256,
    /// Account nonce at the queried height.
    pub nonce: u64,
    /// The account's storage-root at the queried height.
    pub storage_hash: revm::primitives::B256,
    /// RLP-encoded trie nodes from the state root to the account
    /// leaf (or the divergence point for an absent account).
    pub account_proof: Vec<revm::primitives::Bytes>,
    /// One entry per requested storage key.
    pub storage_proofs: Vec<StorageProof>,
}

/// One storage-slot entry in an [`AccountProof`].
#[derive(Debug, Clone)]
pub struct StorageProof {
    /// The requested slot (unhashed — geth echoes the query key).
    pub key: revm::primitives::B256,
    /// The slot's value at the queried height.
    pub value: revm::primitives::U256,
    /// RLP-encoded storage-trie nodes from `storageHash` to the leaf.
    pub proof: Vec<revm::primitives::Bytes>,
}

/// One element of a decoded batch: the signed transaction, its
/// recovered sender, the canonical `keccak256(raw)` hash, and the raw
/// signed RLP (retained for the `transactionsRoot` trie at seal).
type DecodedTx =
    Result<(tx::SignedTx, revm::primitives::Address, alloy_primitives::B256, Vec<u8>), ExecError>;

/// Default wall-clock bound for one read-only simulation — geth's
/// `--rpc.evmtimeout` default. Bounds the worst case a single
/// `eth_call`-family request can hold the state lock; the block gas
/// limit alone does not (30M gas of pure looping is seconds of CPU).
/// Units: seconds. Tradeoff: shorter rejects legitimate heavy
/// simulations; longer weakens the `DoS` bound. Consensus execution is
/// unaffected — the deadline inspector is sim-only.
const DEFAULT_SIM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// EIP-2935 ring-buffer size: the history-storage contract serves
/// block hashes for the last 8191 blocks (one slot per block,
/// `slot = block_number % HISTORY_SERVE_WINDOW`). The value is
/// fixed by the EIP and hardcoded in the contract bytecode — it is
/// not a tunable.
const HISTORY_SERVE_WINDOW: u64 = 8_191;

/// EIP-2935 canonical deployment address — identical on every
/// Prague+ EVM chain (tooling and clients hardcode it). Matches
/// `alloy_eips::eip2935::HISTORY_STORAGE_ADDRESS`; the constant is
/// inlined here to avoid a dep taken for two constants.
const HISTORY_STORAGE_ADDRESS: revm::primitives::Address =
    revm::primitives::address!("0000f90827f1c53a10cb7a02335b175320002935");

/// The EVM module: wraps `revm` and exposes it as an Oxide `Module`.
///
/// State is stored in a `CacheDB<EmptyDB>` (in-memory) during
/// execution. When a `StorageBackend` is attached via
/// [`EvmModule::with_storage`], the cache is flushed to durable
/// storage after each block (`end_block`) and loaded on construction.
/// This makes the EVM state persistent across restarts and shareable
/// between nodes — the foundation for standalone-chain operation.
pub struct EvmModule {
    /// The in-memory EVM database (account state, code, storage).
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    ///
    /// Wrapped in `Arc` so the parallel execution path can take an
    /// O(1) snapshot via `Arc::clone` instead of an `O(total_state)`
    /// deep clone. Mutable access uses `Arc::make_mut`, which is
    /// free when the refcount is 1 (no outstanding snapshots) and
    /// only clones when a snapshot is actually held.
    ///
    /// `pub(crate)` so `ledger.rs` (the `Balances` impl) can mutate
    /// balances through the same undo/touched bookkeeping.
    pub(crate) db: Mutex<Arc<CacheDB<EmptyDB>>>,
    /// The chain ID for EIP-155 signed transactions.
    chain_id: u64,
    /// The live EIP-1559 base-fee state — the fee the current
    /// block's transactions are charged, plus the `max_gas` the
    /// congestion target derives from. Seeded from the configured
    /// `base_fee` constructor argument and
    /// [`CHAIN_BLOCK_GAS_LIMIT`]; `end_block_ctx` advances it once
    /// per finalized block from that block's measured gas usage
    /// (the EIP-1559 update rule). Behind a `Mutex` because
    /// `Module::handle` takes `&self` — it is locked once per
    /// transaction build, matching `block_timestamp`/`coinbase`.
    fee_state: Mutex<fee::BaseFeeState>,
    /// The constructor's seed base fee — retained so
    /// `import_state` can reset `fee_state` to genesis conditions
    /// before `load_from_storage` rehydrates it from the restored
    /// block history. Without this a snapshot import onto a backend
    /// that had flushed *ahead* of the checkpoint would keep the
    /// stale tip's fee curve — sealed-block `baseFee` fields would
    /// diverge from every peer's replay, corrupting block hashes.
    initial_base_fee: u64,
    /// The EVM hardfork spec to use for execution.
    /// `SpecId::PRAGUE` is the latest stable mainnet spec in revm 42.
    spec: SpecId,
    /// Optional durable storage backend. When `Some`, the EVM state
    /// (accounts, code, storage) is flushed here after each block
    /// and loaded on construction. When `None`, the module is
    /// purely in-memory (useful for tests and single-block sims).
    backend: Mutex<Option<Box<dyn storage::StorageBackend + Send>>>,
    /// Storage ops that have been built but not yet durably applied
    /// to `backend`. `end_block` appends each block's flush batch
    /// here and attempts one `apply_batch` over the whole buffer:
    /// on `Ok` the buffer clears; on `Err` the ops stay queued and
    /// the next block's flush retries them. Without this, a failed
    /// batch silently dropped that block's account updates AND its
    /// sealed-history/undo records — the backend's rollback meant
    /// nothing was written, so retrying is the only way the data
    /// survives.
    pending_flush: Mutex<Vec<storage::Op>>,
    /// The last storage-layer failure observed by `end_block` or a
    /// maintenance flush — the module's health signal. `Some` while
    /// persistence is failing (every block retries the pending
    /// buffer); cleared by the first successful `apply_batch`. Node
    /// wiring should treat `Some` as "commit durability degraded":
    /// keep executing (the in-memory state is correct) but do not
    /// trust restart recovery until it clears.
    storage_error: Mutex<Option<storage::ApplyError>>,
    /// The coinbase / fee recipient for the current block.
    /// The priority fee (tip) is paid to this address by revm's
    /// internal gas accounting. Set via `begin_block`.
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    coinbase: Mutex<revm::primitives::Address>,
    /// The current block height. Set in `begin_block`, read in
    /// `execute` to populate the EVM block environment.
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    block_height: Mutex<u64>,
    /// The current block timestamp (seconds since Unix epoch).
    /// Set in `begin_block`, read in `execute`.
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    block_timestamp: Mutex<u64>,
    /// The block gas limit for the current block — revm's
    /// `block.gas_limit`, the `validate` admission bound, and the
    /// denominator of the EIP-1559 fee target. `begin_block_ctx`
    /// overwrites it with the consensus-enforced limit whenever the
    /// context carries one; the configured
    /// [`CHAIN_BLOCK_GAS_LIMIT`] is the fallback for context-less
    /// blocks. `AtomicU64` (not a plain `u64`) because `validate`
    /// reads it from RPC threads while the executor writes it at
    /// block start.
    block_gas_limit: std::sync::atomic::AtomicU64,
    /// Phase D: accounts touched in the current block. Tracked
    /// during `execute` so `end_block` can flush only the changed
    /// accounts (incremental flush) instead of the full state.
    /// Cleared at the start of each `begin_block` (after
    /// `state_root` has consumed the set for incremental updates).
    /// Behind a `Mutex` because `Module::handle` takes `&self`.
    ///
    /// `BTreeSet` (sorted): `flush_to_storage` iterates this set to
    /// build the backend op batch, and op order is part of the
    /// journaled state transition. A `HashSet` would produce a
    /// different op order on every validator — identical logical
    /// state, divergent journal/MMR histories.
    ///
    /// `pub(crate)` for `ledger.rs` (`Balances` impl).
    pub(crate) touched: Mutex<std::collections::BTreeSet<revm::primitives::Address>>,
    /// Wall-clock bound applied to read-only simulations
    /// (`eth_call`/`eth_estimateGas`/`eth_createAccessList`/
    /// `debug_traceCall`) — the geth `--rpc.evmtimeout` equivalent.
    /// Enforced inside the interpreter by [`deadline::DeadlineInspector`];
    /// never applied to committed execution (a wall clock cannot be
    /// a consensus input).
    sim_timeout: std::time::Duration,
    /// Envelope-fee destination for `charge_fee`: `Some` → fees are
    /// *collected* at this address (staking's `FEE_POOL` in
    /// production wiring, swept into rewards at `end_block`);
    /// `None` → fees burn (Ethereum base-fee semantics). Set at
    /// construction via [`Self::with_fee_recipient`] — a fixed
    /// chain parameter, not per-block state.
    fee_recipient: Option<primitives::Address>,
    /// Per-account storage root cache. Updated incrementally in
    /// `state_root` — only touched accounts have their storage
    /// roots recomputed; the rest are reused from the cache.
    ///
    /// This turns the per-block state root computation from
    /// `O(total_state)` to `O(touched + log(total_accounts))` for the
    /// storage root portion. The state trie itself is still rebuilt
    /// from scratch (alloy-trie's `HashBuilder` is `O(n)` but very
    /// fast — the dominant cost was per-account storage root
    /// computation, not the trie assembly).
    storage_root_cache:
        Mutex<std::collections::HashMap<revm::primitives::Address, alloy_primitives::B256>>,
    /// Cached state root from the last `state_root` call. If no
    /// Phase B: incremental account-trie leaf cache — hashed
    /// address (`keccak256` of the 20-byte EVM address) →
    /// RLP-encoded `TrieAccount`. `state_root` patches this map
    /// for `touched` accounts only instead of re-hashing every
    /// address, re-encoding every account, and re-sorting every
    /// call. The `BTreeMap` keeps leaves in sorted hashed-key
    /// order — the exact order `HashBuilder::add_leaf` requires.
    trie_leaves: Mutex<std::collections::BTreeMap<revm::primitives::B256, Vec<u8>>>,
    /// Whether `trie_leaves` reflects the full account set. False
    /// at construction and after `import_state` (state was
    /// replaced wholesale); the next `state_root` rebuilds the
    /// map in one pass — the same cost as the old non-incremental
    /// path — then flips this true.
    trie_leaves_ready: Mutex<bool>,
    /// Ceiling 3: retained branch node metadata from the previous
    /// `state_root` build. Keyed by the nibble prefix of the branch
    /// node. Each entry stores the `BranchNodeCompact` (state/tree/hash
    /// masks + child hashes) returned by `HashBuilder::split()`.
    ///
    /// Used to skip non-touched subtrees: instead of feeding every
    /// leaf into `HashBuilder`, we call `add_branch` with the
    /// retained child hash for subtrees that contain no touched
    /// accounts. Only the branch nodes on the path from touched
    /// leaves to the root are rebuilt. This turns trie assembly
    /// from `O(total_accounts)` to `O(touched · log(total_accounts))`.
    ///
    /// A branch's own hash (needed for `add_branch`) is obtained
    /// from its parent's `BranchNodeCompact::hash_for_nibble`, or
    /// from `root_hash` for the root branch (prefix = empty).
    ///
    /// The map is cleared on full rebuild (when `trie_leaves_ready`
    /// is false) and after `import_state`. It is repopulated after
    /// each `state_root` call via `HashBuilder::split()`: the full
    /// build replaces the map entirely; the incremental build merges
    /// the rebuilt branches (removing stale entries on the touched
    /// path first, then inserting the new `BranchNodeCompact`s).
    retained_branches:
        Mutex<std::collections::HashMap<alloy_trie::Nibbles, alloy_trie::BranchNodeCompact>>,
    /// accounts were touched since the last computation, the cached
    /// root is returned directly (O(1) fast path).
    cached_state_root: Mutex<Option<alloy_primitives::B256>>,
    /// Optional exchange module handle for read-only EVM precompiles
    /// (plan.md §10). When `Some`, EVM contracts can call precompile
    /// addresses to read exchange L1 data (best bid/ask).
    exchange: Mutex<Option<Arc<exchange::ExchangeModule>>>,
    /// Optional perps module handle for read-only EVM precompiles.
    /// When `Some`, EVM contracts can read perps positions, mark
    /// prices, and insurance fund balance.
    perps: Mutex<Option<Arc<perps::PerpsModule>>>,
    /// Optional staking module handle for the `0x0C_*` mutating
    /// precompiles (delegate/undelegate). Mutations apply through the
    /// module's own invariant-checked path and are journaled per
    /// frame via [`native_journal`] — a reverted call undoes them.
    staking: Mutex<Option<Arc<staking::StakingModule>>>,
    /// Executed-block history for Ethereum JSON-RPC queries
    /// (`eth_getTransactionByHash`, `eth_getTransactionReceipt`,
    /// `eth_getLogs`, `eth_feeHistory`, …). Every executed tx records
    /// its metadata + receipt here; `end_block` seals the block.
    ///
    /// Consensus-side block metadata (hash, parent hash, proposer,
    /// wall-clock timestamp) is *not* known to the module — it lives
    /// in the RPC layer's `BlockIndex`, joined on height.
    history: Mutex<history::History>,
    /// The current block's inverse-diff accumulator — every mutation
    /// site records the pre-write value of each account it touches
    /// (first-write-wins). Folded into `versioned` at `end_block`.
    /// See `versioned.rs` for the reconstruction semantics.
    ///
    /// `pub(crate)` for `ledger.rs` (`Balances` impl).
    pub(crate) block_undo: Mutex<versioned::BlockUndo>,
    /// The bounded historical-state window: per-block undo entries
    /// indexed by account and height, pruned with `history`'s
    /// retention. Backs all `eth_*` reads at past heights.
    versioned: Mutex<versioned::VersionedState>,
}

impl EvmModule {
    /// Construct a fresh EVM module with no accounts.
    ///
    /// # Arguments
    ///
    /// - `chain_id`: The EIP-155 chain ID. Used for signed transaction
    ///   validation.
    /// - `base_fee`: The initial EIP-1559 base fee (wei per gas). Phase
    ///   2 v0 uses a fixed base fee; dynamic adjustment arrives later.
    #[must_use]
    pub fn new(chain_id: u64, base_fee: u64) -> Self {
        Self::with_history_window(chain_id, base_fee, history::DEFAULT_HISTORY_BLOCKS)
    }

    /// Construct with a specific history retention window — also the
    /// undo-log window for historical state reads. Tests use small
    /// windows to exercise pruning; production keeps
    /// [`history::DEFAULT_HISTORY_BLOCKS`].
    #[must_use]
    pub fn with_history_window(chain_id: u64, base_fee: u64, window_blocks: usize) -> Self {
        Self {
            db: Mutex::new(Arc::new(CacheDB::new(EmptyDB::new()))),
            chain_id,
            fee_state: Mutex::new(fee::BaseFeeState::new(base_fee, CHAIN_BLOCK_GAS_LIMIT)),
            initial_base_fee: base_fee,
            spec: SpecId::PRAGUE,
            backend: Mutex::new(None),
            pending_flush: Mutex::new(Vec::new()),
            storage_error: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: std::sync::atomic::AtomicU64::new(CHAIN_BLOCK_GAS_LIMIT),
            sim_timeout: DEFAULT_SIM_TIMEOUT,
            fee_recipient: None,
            touched: Mutex::new(std::collections::BTreeSet::new()),
            storage_root_cache: Mutex::new(std::collections::HashMap::new()),
            trie_leaves: Mutex::new(std::collections::BTreeMap::new()),
            retained_branches: Mutex::new(std::collections::HashMap::new()),
            trie_leaves_ready: Mutex::new(false),
            cached_state_root: Mutex::new(None),
            exchange: Mutex::new(None),
            perps: Mutex::new(None),
            staking: Mutex::new(None),
            history: Mutex::new(history::History::new(window_blocks)),
            block_undo: Mutex::new(versioned::BlockUndo::default()),
            versioned: Mutex::new(versioned::VersionedState::default()),
        }
    }

    /// Construct with a specific hardfork spec (for testing older
    /// EVM behavior).
    #[must_use]
    pub fn with_spec(chain_id: u64, base_fee: u64, spec: SpecId) -> Self {
        Self {
            db: Mutex::new(Arc::new(CacheDB::new(EmptyDB::new()))),
            chain_id,
            fee_state: Mutex::new(fee::BaseFeeState::new(base_fee, CHAIN_BLOCK_GAS_LIMIT)),
            initial_base_fee: base_fee,
            spec,
            backend: Mutex::new(None),
            pending_flush: Mutex::new(Vec::new()),
            storage_error: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: std::sync::atomic::AtomicU64::new(CHAIN_BLOCK_GAS_LIMIT),
            sim_timeout: DEFAULT_SIM_TIMEOUT,
            fee_recipient: None,
            touched: Mutex::new(std::collections::BTreeSet::new()),
            storage_root_cache: Mutex::new(std::collections::HashMap::new()),
            trie_leaves: Mutex::new(std::collections::BTreeMap::new()),
            retained_branches: Mutex::new(std::collections::HashMap::new()),
            trie_leaves_ready: Mutex::new(false),
            cached_state_root: Mutex::new(None),
            exchange: Mutex::new(None),
            perps: Mutex::new(None),
            staking: Mutex::new(None),
            history: Mutex::new(history::History::new(history::DEFAULT_HISTORY_BLOCKS)),
            block_undo: Mutex::new(versioned::BlockUndo::default()),
            versioned: Mutex::new(versioned::VersionedState::default()),
        }
    }

    /// Construct with a durable `StorageBackend`. Initial EVM state
    /// (accounts, code, storage) is loaded from the backend into the
    /// in-memory `CacheDB`. After each block, `end_block` flushes the
    /// updated state back to the backend.
    ///
    /// This is the standalone-chain constructor: state persists
    /// across restarts and can be shared between nodes.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned during `load_from_storage`.
    /// This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn with_storage(
        chain_id: u64,
        base_fee: u64,
        backend: Box<dyn storage::StorageBackend + Send>,
    ) -> Self {
        Self::with_storage_and_window(chain_id, base_fee, backend, history::DEFAULT_HISTORY_BLOCKS)
    }

    /// `with_storage` with a configurable history/undo retention
    /// window — tests use small windows to exercise restore-time
    /// pruning; production uses [`history::DEFAULT_HISTORY_BLOCKS`].
    #[must_use]
    pub fn with_storage_and_window(
        chain_id: u64,
        base_fee: u64,
        backend: Box<dyn storage::StorageBackend + Send>,
        window_blocks: usize,
    ) -> Self {
        let module = Self {
            db: Mutex::new(Arc::new(CacheDB::new(EmptyDB::new()))),
            chain_id,
            fee_state: Mutex::new(fee::BaseFeeState::new(base_fee, CHAIN_BLOCK_GAS_LIMIT)),
            initial_base_fee: base_fee,
            spec: SpecId::PRAGUE,
            backend: Mutex::new(None),
            pending_flush: Mutex::new(Vec::new()),
            storage_error: Mutex::new(None),
            coinbase: Mutex::new(revm::primitives::Address::ZERO),
            block_height: Mutex::new(0),
            block_timestamp: Mutex::new(0),
            block_gas_limit: std::sync::atomic::AtomicU64::new(CHAIN_BLOCK_GAS_LIMIT),
            sim_timeout: DEFAULT_SIM_TIMEOUT,
            fee_recipient: None,
            touched: Mutex::new(std::collections::BTreeSet::new()),
            storage_root_cache: Mutex::new(std::collections::HashMap::new()),
            trie_leaves: Mutex::new(std::collections::BTreeMap::new()),
            retained_branches: Mutex::new(std::collections::HashMap::new()),
            trie_leaves_ready: Mutex::new(false),
            cached_state_root: Mutex::new(None),
            exchange: Mutex::new(None),
            perps: Mutex::new(None),
            staking: Mutex::new(None),
            history: Mutex::new(history::History::new(window_blocks)),
            block_undo: Mutex::new(versioned::BlockUndo::default()),
            versioned: Mutex::new(versioned::VersionedState::default()),
        };
        // Load initial state from the backend into the CacheDB, then
        // install the backend for future flushes.
        let mut backend = backend;
        module.load_from_storage(backend.as_mut());
        *framework::lock_state(&module.backend) = Some(backend);
        module
    }

    /// The chain ID (EIP-155).
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The last storage-layer failure, if any — the module's
    /// persistence-health signal.
    ///
    /// `Some` means at least one `apply_batch`/`sync` has failed and
    /// the pending buffer still holds ops not yet written (every
    /// `end_block` retries them). `None` means everything built so
    /// far is durable. Node wiring should treat `Some` as "restart
    /// recovery is degraded": in-memory state keeps serving
    /// correctly, but a crash before the next successful flush loses
    /// the buffered blocks' writes.
    #[must_use]
    pub fn storage_error(&self) -> Option<storage::ApplyError> {
        framework::lock_state(&self.storage_error).clone()
    }

    /// Wire native exchange and perps modules for read-only EVM
    /// precompiles (plan.md §10). EVM contracts can call precompile
    /// addresses to read exchange L1 data and perps state.
    ///
    /// # Panics
    ///
    /// Panics if the internal exchange or perps mutexes are
    /// poisoned (indicates a panic in another thread holding the
    /// lock — unrecoverable).
    pub fn set_native_modules(
        &self,
        exchange: Option<Arc<exchange::ExchangeModule>>,
        perps: Option<Arc<perps::PerpsModule>>,
    ) {
        *framework::lock_state(&self.exchange) = exchange;
        *framework::lock_state(&self.perps) = perps;
    }

    /// Wire the staking module for the `0x0C_*` mutating
    /// precompiles. Mutations go through `delegate_for`/
    /// `undelegate_for` — the same invariant-checked path as native
    /// staking messages — and are journaled for frame-scoped revert
    /// (see [`native_journal`]).
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn set_staking(&self, staking: Arc<staking::StakingModule>) {
        *framework::lock_state(&self.staking) = Some(staking);
    }

    /// Set the envelope-fee recipient: every `charge_fee` transfers
    /// `sender → recipient` instead of burning. Production wiring
    /// passes `staking::FEE_POOL`, whose balance `end_block` sweeps
    /// into validator/delegator rewards — the distribution half of
    /// the fee policy. `None` (the default) keeps Ethereum-style
    /// fee burning.
    #[must_use]
    pub fn with_fee_recipient(mut self, recipient: primitives::Address) -> Self {
        self.fee_recipient = Some(recipient);
        self
    }

    /// The current EIP-1559 base fee (wei per gas).
    #[must_use]
    pub fn base_fee(&self) -> u64 {
        self.current_base_fee()
    }

    /// The live base fee read from the evolving [`fee::BaseFeeState`]
    /// — the value `block.basefee`, admission checks, and receipt
    /// accounting all observe for the current block. The lock is
    /// acquired once per call and never held across work; the update
    /// itself happens once per block in `end_block_ctx`.
    fn current_base_fee(&self) -> u64 {
        framework::lock_state(&self.fee_state).base_fee()
    }

    /// The EVM block gas limit the module enforces — the cap
    /// `eth_call`/`eth_estimateGas`/`debug_traceCall` clamp against.
    /// Reflects the consensus-enforced limit for the in-progress
    /// block once `begin_block_ctx` has applied the context.
    #[must_use]
    pub fn block_gas_limit(&self) -> u64 {
        self.block_gas_limit.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Override the read-only simulation wall-clock bound (the
    /// geth `--rpc.evmtimeout` equivalent). Applied per simulation;
    /// `eth_estimateGas` shares one deadline across its binary search
    /// so the bound covers the whole request.
    ///
    /// Never applied to committed execution — a wall clock cannot be
    /// a consensus input.
    pub fn set_sim_timeout(&mut self, timeout: std::time::Duration) {
        self.sim_timeout = timeout;
    }

    /// Set the coinbase / fee recipient for the current block.
    ///
    /// The priority fee (tip) from each transaction is paid to this
    /// address by revm's internal gas accounting. This is the
    /// validator's reward for including transactions.
    ///
    /// # Panics
    ///
    /// Panics if the coinbase mutex is poisoned.
    pub fn set_coinbase(&self, coinbase: revm::primitives::Address) {
        *framework::lock_state(&self.coinbase) = coinbase;
    }

    /// Get the coinbase / fee recipient for the current block.
    ///
    /// # Panics
    ///
    /// Panics if the coinbase mutex is poisoned.
    #[must_use]
    pub fn coinbase(&self) -> revm::primitives::Address {
        *framework::lock_state(&self.coinbase)
    }
}

impl EvmModule {
    /// Lock and return the executed-block history for RPC queries.
    ///
    /// The guard is held only for the duration of the read — readers
    /// must clone what they need and drop the guard promptly so the
    /// block-execution thread is never starved.
    ///
    /// # Panics
    ///
    /// Panics if the history mutex is poisoned.
    pub fn history(&self) -> std::sync::MutexGuard<'_, history::History> {
        framework::lock_state(&self.history)
    }

    /// The height the module is currently executing (or last
    /// executed) — the "latest" EVM height for RPC block-tag
    /// resolution.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn current_height(&self) -> u64 {
        *framework::lock_state(&self.block_height)
    }

    /// The latest sealed block's base fee — geth's `head.BaseFee`,
    /// the base component of `eth_gasPrice`. Falls back to the
    /// configured initial base fee before the first block seals.
    ///
    /// # Panics
    ///
    /// Panics if the history mutex is poisoned.
    #[must_use]
    pub fn latest_base_fee(&self) -> u64 {
        let history = self.history();
        history
            .latest()
            .and_then(|h| history.block(h))
            .map_or(self.current_base_fee(), |b| b.base_fee)
    }

    /// The oracle-suggested priority fee — `eth_maxPriorityFeePerGas`.
    /// Delegates to [`history::History::suggest_gas_tip`].
    ///
    /// # Panics
    ///
    /// Panics if the history mutex is poisoned.
    #[must_use]
    pub fn suggest_gas_tip(&self) -> u128 {
        self.history().suggest_gas_tip()
    }

    /// Extract the `StorageBackend` for testing. The backend is
    /// removed from the module (set to `None`), so subsequent
    /// `end_block` calls will not flush. The returned backend can
    /// be passed to `EvmModule::with_storage` to create a new
    /// module with the same persisted state.
    ///
    /// # Panics
    ///
    /// Panics if the backend mutex is poisoned or no backend is
    /// attached (the module was constructed with `new`, not
    /// `with_storage`).
    #[doc(hidden)]
    pub fn backend_for_test(&self) -> Box<dyn storage::StorageBackend + Send> {
        let mut guard = framework::lock_state(&self.backend);
        guard.take().expect("backend_for_test: no storage backend attached")
    }

    /// Fund an account with the given balance (test-only helper).
    ///
    /// This directly inserts the balance into the CacheDB, bypassing
    /// execution. It's used by `validate` tests to set up accounts
    /// with sufficient balance to pass the admission gate.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    #[doc(hidden)]
    pub fn fund_account_for_test(&self, addr: &Address, balance: u128) {
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);
        let evm_addr = alloy_primitives_address(addr.0);
        let empty_code = revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::new());
        let code_hash = empty_code.hash_slow();
        let account =
            db.cache.accounts.entry(evm_addr).or_insert_with(|| revm::database::DbAccount {
                info: revm::database::state::AccountInfo {
                    balance: revm::primitives::U256::ZERO,
                    nonce: 0,
                    // keccak256("") — the canonical empty-code hash
                    // Ethereum stores in the account leaf.
                    code_hash,
                    account_id: None,
                    code: Some(empty_code),
                },
                account_state: revm::database::AccountState::None,
                storage: revm::primitives::HashMap::default(),
            });
        account.info.balance = revm::primitives::U256::from(balance);
        // Funding is a state write — mark the account touched so the
        // next `end_block` flush persists it. Without the mark the
        // balance is committed to `state_root` but never reaches the
        // backend: a restart (or a snapshot built from flushed state)
        // would lose the account. `Node::assemble` uses this path for
        // genesis faucet funding, so the hole is not test-only.
        drop(db_guard);
        framework::lock_state(&self.touched).insert(evm_addr);
    }

    /// Insert an account with full state — the genesis `alloc` path.
    ///
    /// Unlike [`fund_account_for_test`](Self::fund_account_for_test)
    /// this sets nonce, code, and storage too, so `genesis.json`
    /// `alloc` entries can declare contracts and preinstalls. Called
    /// once at node assembly, before the first `begin_block` — it is
    /// not part of block execution and must never be called
    /// mid-chain (it would rewrite live state).
    ///
    /// The account is marked `touched` so the first `state_root`
    /// computation includes it in the trie.
    ///
    /// # Panics
    ///
    /// Panics if a mutex is poisoned.
    pub fn genesis_insert_account(
        &self,
        addr: &Address,
        balance: u128,
        nonce: u64,
        code: Vec<u8>,
        storage: Vec<(revm::primitives::U256, revm::primitives::U256)>,
    ) {
        let evm_addr = alloy_primitives_address(addr.0);
        let bytecode = revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::from(code));
        let code_hash = bytecode.hash_slow();
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);
        let account =
            db.cache.accounts.entry(evm_addr).or_insert_with(|| revm::database::DbAccount {
                info: revm::database::state::AccountInfo {
                    balance: revm::primitives::U256::ZERO,
                    nonce: 0,
                    code_hash: revm::primitives::B256::ZERO,
                    account_id: None,
                    code: None,
                },
                account_state: revm::database::AccountState::None,
                storage: revm::primitives::HashMap::default(),
            });
        account.info.balance = revm::primitives::U256::from(balance);
        account.info.nonce = nonce;
        account.info.code = Some(bytecode);
        account.info.code_hash = code_hash;
        for (slot, value) in storage {
            // Sparse-storage invariant: zero means absent — a
            // `genesis.json` alloc entry with an explicit 0 must not
            // create a slot the MPT cannot encode.
            if !value.is_zero() {
                account.storage.insert(slot, value);
            }
        }
        drop(db_guard);
        framework::lock_state(&self.touched).insert(evm_addr);
    }

    /// Install the canonical preinstalled contracts (CREATE2 factory,
    /// singleton factories, Multicall3, Permit2) at their well-known
    /// addresses.
    ///
    /// Must be called at genesis assembly, before the first
    /// `begin_block` — each entry is inserted via
    /// [`genesis_insert_account`](Self::genesis_insert_account) with
    /// nonce 1 (matching the keyless deployments on other chains, so
    /// `CREATE`-derived addresses stay reproducible) and zero balance.
    /// Idempotent by construction: re-inserting overwrites with the
    /// same values. A user-supplied `genesis.json` `alloc` entry at a
    /// preinstall address wins only if applied *after* this call —
    /// callers apply alloc afterwards so genesis can intentionally
    /// override (e.g. a dev chain seeding a different factory).
    ///
    /// # Panics
    ///
    /// Panics if a mutex is poisoned or the compile-time preinstall
    /// table is malformed.
    pub fn install_preinstalls(&self) {
        for p in preinstalls::PREINSTALLS {
            // Fork-gated contracts (EIP-2935's history contract is
            // Prague+) must not exist on an earlier-spec chain —
            // installing them would diverge the genesis state root
            // from the real fork's.
            if !p.requires_spec.is_none_or(|req| self.spec.is_enabled_in(req)) {
                continue;
            }
            self.genesis_insert_account(
                &preinstalls::preinstall_address(p),
                0,
                p.nonce,
                preinstalls::preinstall_code(p),
                Vec::new(),
            );
        }
    }

    /// Commit `state` into the authoritative `CacheDB`, then restore
    /// Ethereum's sparse-storage invariant: a slot whose present
    /// value is zero is *absent*. revm's `DatabaseCommit::commit`
    /// writes the zero into `DbAccount.storage` — harmless to revm
    /// itself (SLOAD still observes 0) but poison to every
    /// committed-state consumer: the MPT encodes only nonzero leaves,
    /// so a surviving zero entry would skew `state_root`, land in the
    /// backend flush and snapshots, and contradict `eth_getProof`'s
    /// trie view. The post-commit sweep is restricted to accounts
    /// that actually wrote a zero this commit — O(tx writes), never
    /// O(account storage).
    ///
    /// Must NOT be applied to speculative/group overlays
    /// (`CacheDB<SharedCacheDB>`): there a committed zero entry is
    /// load-bearing — it shadows the parent's stale value for later
    /// same-sender transactions. Only the canonical cache, whose
    /// inner db returns zero on every miss, may drop zero entries.
    fn commit_state(db: &mut CacheDB<EmptyDB>, state: revm::state::EvmState) {
        let zeroed = Self::zero_slot_writers(&state);
        db.commit(state);
        Self::prune_zero_slots(db, &zeroed);
    }

    /// Collect the accounts in `state` that write a zero-valued
    /// storage slot. Must run *before* `DatabaseCommit::commit`
    /// consumes the diff — afterwards the distinction between "set
    /// to zero" and "already absent" is gone from the journal view.
    /// See [`commit_state`](Self::commit_state).
    fn zero_slot_writers(state: &revm::state::EvmState) -> Vec<revm::primitives::Address> {
        state
            .iter()
            .filter(|(_, account)| {
                account.is_touched()
                    && account.storage.values().any(|slot| slot.present_value.is_zero())
            })
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Delete zero-valued entries a commit just installed in `db`
    /// for `addrs` — the sweep half of [`commit_state`](Self::commit_state),
    /// split out for call sites whose db lives inside a built `Evm`
    /// (`evm.commit` hides the concrete commit call).
    fn prune_zero_slots(db: &mut CacheDB<EmptyDB>, addrs: &[revm::primitives::Address]) {
        for addr in addrs {
            if let Some(account) = db.cache.accounts.get_mut(addr) {
                account.storage.retain(|_, value| !value.is_zero());
            }
        }
    }

    /// Mark an account as touched for the current block — the
    /// incremental `state_root` then re-encodes its leaf. Test/bench
    /// hook: real execution populates `touched` from
    /// `EvmState::keys()` automatically; benches need a way to mark
    /// accounts without executing txs.
    ///
    /// # Panics
    ///
    /// Panics if the touched mutex is poisoned.
    #[doc(hidden)]
    pub fn mark_touched_for_test(&self, addr: &Address) {
        framework::lock_state(&self.touched).insert(alloy_primitives_address(addr.0));
    }

    /// Reset the leaf cache so the next `state_root` call performs
    /// a full rebuild instead of an incremental sparse walk. Test
    /// hook: used to compute the "ground truth" root and verify
    /// that the sparse incremental path produces the same result.
    ///
    /// # Panics
    ///
    /// Panics if any mutex is poisoned.
    #[doc(hidden)]
    pub fn reset_leaf_cache_for_test(&self) {
        *framework::lock_state(&self.trie_leaves_ready) = false;
        framework::lock_state(&self.trie_leaves).clear();
        framework::lock_state(&self.retained_branches).clear();
        *framework::lock_state(&self.cached_state_root) = None;
    }
}

/// Convert an Oxide `Address` (20 bytes) to a revm `Address`.
pub(crate) fn alloy_primitives_address(bytes: [u8; 20]) -> revm::primitives::Address {
    revm::primitives::Address::from(bytes)
}

#[cfg(test)]
mod tests;
