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
use trie::{encode_trie_leaf, sparse_walk};
use types::CHAIN_BLOCK_GAS_LIMIT;
// rayon: parallel secp256k1 sender recovery in `handle_batch`.
// 88% of per-tx cost is ECDSA recovery; parallelizing across cores
// turns that into 88%/N_cores.
use rayon::prelude::*;

pub mod coinbase_read;
pub mod deadline;
pub mod fee;
pub mod history;
pub mod ledger;
pub mod native_journal;
pub mod overrides;
mod persist;
pub mod precompiles;
pub mod preinstalls;
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
use revm::database_interface::{DatabaseRef, EmptyDB};
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
type TracedResult =
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

    /// Build a `NativeMarketReader` from the wired exchange and
    /// perps modules. Returns an empty reader if no modules are
    /// wired (all precompile reads return empty/zero).
    fn build_reader(&self) -> precompiles::native::NativeMarketReader {
        let exchange = framework::lock_state(&self.exchange).clone();
        let perps = framework::lock_state(&self.perps).clone();
        precompiles::native::NativeMarketReader::new(exchange, perps)
    }

    /// Build a revm `Evm` with `NativePrecompiles` wired in. This
    /// replaces `build_mainnet_with_inspector` so that EVM contracts
    /// can call Oxide native precompile addresses.
    ///
    /// Generic over the database type to support both the
    /// single-tx path (`CacheDB<EmptyDB>`) and the batch paths
    /// (`CacheDB<SharedCacheDB>`).
    ///
    /// # Panics
    ///
    /// This function does not panic.
    /// Consensus-path EVM builder — strict validation (all checks on).
    #[allow(clippy::type_complexity)]
    fn build_evm<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        (native_journal::NativeJournalInspector, trace::CallRecorder),
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        self.build_evm_with_mode(db, coinbase, block_number, block_timestamp, false, false)
    }

    /// Speculative EVM builder for the parallel executor: identical
    /// to [`build_evm`](Self::build_evm) but with two speculative-only
    /// guards — read-only native precompiles (a speculative frame can
    /// never write shared native state outside its own `CacheDB`
    /// clone; suppressed mutations surface via
    /// `blocked_native_mutation`)
    /// and a [`CoinbaseReadDetector`](coinbase_read) flagging
    /// `BALANCE(coinbase)` observations so the commit phase can
    /// validate them against the canonical running tip total.
    #[allow(clippy::type_complexity)]
    fn build_spec_evm<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        (
            native_journal::NativeJournalInspector,
            (trace::CallRecorder, coinbase_read::CoinbaseReadDetector),
        ),
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        let (ctx, instruction, precompiles, journal) =
            self.evm_parts(db, coinbase, block_number, block_timestamp, false, true);
        revm::context::Evm::new_with_inspector(
            ctx,
            (
                native_journal::NativeJournalInspector::new(journal),
                (trace::CallRecorder::new(), coinbase_read::CoinbaseReadDetector::new(coinbase)),
            ),
            instruction,
            precompiles,
        )
    }

    /// Assemble the pieces both EVM builders share: the context
    /// (with the sim flag applied to `CfgEnv`), the instruction set,
    /// the native precompiles wired to the undo journal, and the
    /// journal handle itself (the inspector needs the same `Rc`).
    ///
    /// Splitting assembly this way keeps the consensus-path builder
    /// and the simulation builder identical except for the inspector
    /// — the sim path adds the wall-clock deadline, which must never
    /// exist on a committed path.
    ///
    /// `spec_ro` (speculative read-only) makes mutating native
    /// precompiles revert — used by the parallel executor so a
    /// speculative frame can never write shared native state outside
    /// its own `CacheDB` clone. The suppressed mutation is flagged in
    /// the native journal (`blocked_mutation`) so the tx is known to
    /// need canonical re-execution.
    #[allow(clippy::type_complexity)]
    fn evm_parts<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
        sim: bool,
        spec_ro: bool,
    ) -> (
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        std::rc::Rc<std::cell::RefCell<native_journal::NativeJournal>>,
    )
    where
        DB: revm::database_interface::Database,
    {
        let reader = self.build_reader();
        let ctx = Context::mainnet()
            .with_db(db)
            .modify_cfg_chained(|cfg| {
                cfg.set_spec_and_mainnet_gas_params(self.spec);
                if sim {
                    // Read-only call env (`eth_call`/`eth_estimateGas`),
                    // matching geth's `DoCall`/reth's call env:
                    // - nonce: callers rarely set it.
                    // - base fee: callers may omit gasPrice.
                    // - block gas limit: calls may exceed the block
                    //   limit (bounded by our own cap instead).
                    // - priority-fee check: call objects often set
                    //   only `gasPrice`, never a tip cap.
                    // - EIP-3607: calls from accounts *with code* are
                    //   legitimate for eth_call (simulating a contract
                    //   as sender), unlike txs.
                    // Balance and fee checks stay enabled — geth
                    // rejects calls the sender cannot afford
                    // (`gas*price + value`), and so do we.
                    cfg.disable_nonce_check = true;
                    cfg.disable_base_fee = true;
                    cfg.disable_block_gas_limit = true;
                    cfg.disable_priority_fee_check = true;
                    cfg.disable_eip3607 = true;
                }
            })
            .modify_block_chained(|block| {
                block.number = revm::primitives::U256::from(block_number);
                block.beneficiary = coinbase;
                block.timestamp = revm::primitives::U256::from(block_timestamp);
                block.gas_limit = self.block_gas_limit();
                block.basefee = self.current_base_fee();
            });
        let instruction = revm::handler::instructions::EthInstructions::<
            revm::interpreter::interpreter::EthInterpreter,
            _,
        >::new_mainnet_with_spec(self.spec);
        // Frame-scoped undo journal for native mutations (staking
        // delegate/undelegate): the precompile records an undo op per
        // mutation, the inspector replays them on frame revert — the
        // geth `StateDB` journal semantics for non-EVM state.
        let journal =
            std::rc::Rc::new(std::cell::RefCell::new(native_journal::NativeJournal::new()));
        let mut precompiles =
            precompiles::NativePrecompiles::new(self.spec, reader, journal.clone());
        if let Some(staking) = framework::lock_state(&self.staking).clone() {
            precompiles = precompiles.with_staking(staking);
        }
        if sim || spec_ro {
            precompiles = precompiles.read_only();
        }
        (ctx, instruction, precompiles, journal)
    }

    /// Simulation-path EVM builder — same machine as
    /// [`build_evm`](Self::build_evm) plus a
    /// [`deadline::DeadlineInspector`] enforcing the wall-clock
    /// simulation bound. Used only by read-only calls; committed
    /// execution must never carry a wall clock (determinism).
    #[allow(clippy::type_complexity)]
    fn build_sim_evm<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
        deadline: std::time::Instant,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        (
            (native_journal::NativeJournalInspector, trace::CallRecorder),
            deadline::DeadlineInspector,
        ),
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        let (ctx, instruction, precompiles, journal) =
            self.evm_parts(db, coinbase, block_number, block_timestamp, true, false);
        revm::context::Evm::new_with_inspector(
            ctx,
            (
                (native_journal::NativeJournalInspector::new(journal), trace::CallRecorder::new()),
                deadline::DeadlineInspector::new(deadline),
            ),
            instruction,
            precompiles,
        )
    }

    #[allow(clippy::type_complexity)]
    fn build_evm_with_mode<'db, DB>(
        &self,
        db: &'db mut DB,
        coinbase: revm::primitives::Address,
        block_number: u64,
        block_timestamp: u64,
        sim: bool,
        spec_ro: bool,
    ) -> revm::context::Evm<
        revm::context::Context<
            revm::context::BlockEnv,
            TxEnv,
            revm::context::CfgEnv,
            &'db mut DB,
            revm::context::Journal<&'db mut DB>,
            (),
        >,
        (native_journal::NativeJournalInspector, trace::CallRecorder),
        revm::handler::instructions::EthInstructions<
            revm::interpreter::interpreter::EthInterpreter,
            revm::context::Context<
                revm::context::BlockEnv,
                TxEnv,
                revm::context::CfgEnv,
                &'db mut DB,
                revm::context::Journal<&'db mut DB>,
                (),
            >,
        >,
        precompiles::NativePrecompiles,
        revm::handler::EthFrame<revm::interpreter::interpreter::EthInterpreter>,
    >
    where
        DB: revm::database_interface::Database,
    {
        let (ctx, instruction, precompiles, journal) =
            self.evm_parts(db, coinbase, block_number, block_timestamp, sim, spec_ro);
        revm::context::Evm::new_with_inspector(
            ctx,
            (
                native_journal::NativeJournalInspector::new(journal),
                // Call-tree recorder: feeds `debug_trace*` — see
                // trace.rs for why traces are captured at execution
                // time rather than re-executed on demand.
                trace::CallRecorder::new(),
            ),
            instruction,
            precompiles,
        )
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

    /// Execute a signed EVM transaction. The `msg` is a raw RLP-encoded
    /// signed transaction (Legacy, EIP-2930, or EIP-1559 per EIP-2718).
    ///
    /// The sender is recovered from the signature inside the transaction —
    /// **never** trusted from the outer envelope (`ctx.sender`). This is
    /// the core security boundary: authentication is enforced at
    /// execution, not admission.
    ///
    /// Returns the revm `ExecutionResult` containing gas used, status,
    /// logs, output, and (for CREATE) the created address.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the message cannot be parsed
    /// as a valid signed transaction (RLP decode failure, invalid
    /// signature, wrong chain ID).
    /// Returns [`ExecError::ModuleRejected`] if the EVM execution fails.
    /// Execute a already-decoded signed transaction (Perf: single
    /// RLP decode). Used by `handle()` to avoid decoding the same
    /// RLP twice — `handle()` decodes once to get the tx type for
    /// the receipt, then calls this method.
    ///
    /// Returns the execution result and the recovered sender — the
    /// caller needs both to record the transaction into the
    /// executed-block history.
    fn execute_signed(
        &self,
        signed: &tx::SignedTx,
    ) -> Result<
        (
            revm::context::result::ExecutionResult,
            revm::primitives::Address,
            Option<trace::CallFrame>,
        ),
        ExecError,
    > {
        // Enforce chain ID (EIP-155 replay protection).
        if signed.chain_id() != self.chain_id {
            return Err(ExecError::Malformed);
        }

        // Recover the sender from the signature. This is the
        // authentication step — the EVM never trusts `ctx.sender`.
        let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
        let caller = alloy_primitives_address(sender.0);

        // Build the transaction environment from the signed tx fields.
        let tx = Self::build_tx_env(signed, caller, self.spec)?;

        // Build and run the EVM. `transact_commit` executes the tx and
        // commits the state changes to the CacheDB in one step.
        //
        // A5/A6: wire the block environment (base fee, coinbase, block
        // number, timestamp, gas limit) into revm. revm's internal gas
        // accounting then:
        //   1. Charges `gas_used * gas_price` from the sender.
        //   2. Burns `gas_used * base_fee` (removes from supply).
        //   3. Tips `gas_used * (gas_price - base_fee)` to the coinbase.
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);
        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);
        let mut evm = self.build_evm(db, coinbase, block_number, block_timestamp);

        // `transact` (not `transact_commit`) so we get the complete
        // `EvmState` — the exact set of accounts the tx modified.
        // The previous top-level-only tracking (caller + to +
        // created + coinbase) missed accounts changed by internal
        // calls, SELFDESTRUCT beneficiaries, and SSTORE writes to
        // third accounts — those accounts were updated in the
        // CacheDB but never flushed or reflected in the incremental
        // state root, diverging durable state from in-memory state.
        // `inspect_tx` is `transact` plus inspector hooks — the
        // native journal inspector replays precompile side-effect
        // undos when a frame reverts. Result/state semantics are
        // identical.
        let result_and_state = evm
            .inspect_tx(tx)
            .map_err(|e| ExecError::ModuleRejected(format!("evm transact failed: {e:?}")))?;
        evm.precompiles.clear_native_journal();
        // Drain the call-tree recorder before the Evm is dropped —
        // the trace lands in `history` beside this tx's receipt for
        // `debug_trace*` lookups.
        let call_trace = evm.inspector.1.take_root();

        // Phase D: track touched accounts for incremental flush.
        // `state` contains EVERY account revm modified (including
        // internal-call targets and selfdestruct beneficiaries);
        // `commit` then applies it to the CacheDB — identical
        // semantics to `transact_commit` but with the state
        // available for tracking first.
        {
            let mut touched = framework::lock_state(&self.touched);
            touched.extend(result_and_state.state.keys().copied());
        }
        // Capture every account the commit is about to overwrite —
        // the undo entry must hold the pre-block value, so it reads
        // the map before `commit` lands.
        {
            let mut undo = framework::lock_state(&self.block_undo);
            for addr in result_and_state.state.keys() {
                undo.capture(*addr, evm.ctx.journaled_state.database.cache.accounts.get(addr));
            }
        }
        evm.commit(result_and_state.state);

        Ok((result_and_state.result, caller, call_trace))
    }

    /// Capture the fast-path write set into the block's undo
    /// accumulator.
    ///
    /// `try_native_transfer`/`try_empty_code_call` mutate exactly
    /// {caller, recipient, coinbase} — the same accounts the call
    /// sites already record as touched. Called *before* the fast-path
    /// attempt so the undo entry holds the pre-block value; if the
    /// fast path declines and revm runs instead, the entries remain
    /// correct (first-write-wins).
    fn undo_capture_fast_path<DB: DatabaseRef>(
        undo: &mut versioned::BlockUndo,
        db: &CacheDB<DB>,
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        coinbase: revm::primitives::Address,
    ) {
        undo.capture(caller, db.cache.accounts.get(&caller));
        if let tx::TxKind::Call(addr) = signed.to() {
            undo.capture(
                revm::primitives::Address::from(addr.0),
                db.cache.accounts.get(&revm::primitives::Address::from(addr.0)),
            );
        }
        undo.capture(coinbase, db.cache.accounts.get(&coinbase));
    }

    /// Try to execute a simple ETH transfer natively, bypassing revm.
    ///
    /// This is the **native fast path**: for simple value transfers
    /// (empty calldata, recipient is an EOA, no access list), the full
    /// EVM is unnecessary. A native balance+nonce update is ~10-50x
    /// faster than revm's stack-machine execution.
    ///
    /// # When the native path applies
    ///
    /// All of the following must be true:
    /// 1. `to` is `TxKind::Call` (not `Create`).
    /// 2. `data` is empty (no calldata).
    /// 3. Access list is empty (EIP-2930/1559).
    /// 4. Recipient has no code (`code_hash == KECCAK_EMPTY` or
    ///    account doesn't exist).
    /// 5. `gas_limit >= 21000` (intrinsic gas for a simple transfer).
    /// 6. Sender nonce matches the tx nonce.
    /// 7. Sender has sufficient balance for `value + gas_limit *
    ///    effective_gas_price`.
    /// 8. `effective_gas_price >= base_fee`.
    /// 9. `value`, `gas_price` fit in `u128` (Ethereum amounts always
    ///    do, but we check for safety).
    ///
    /// If any check fails, returns `None` and the caller falls through
    /// to revm, which handles the error identically.
    ///
    /// # Gas semantics
    ///
    /// For a simple transfer: `gas_used = 21000` (intrinsic gas, no
    /// execution). The effective gas price is computed per EIP-1559:
    /// - Legacy/EIP-2930: `effective = gas_price`
    /// - EIP-1559: `effective = min(max_fee, base_fee + priority_fee)`
    ///
    /// The coinbase receives `gas_used * (effective - base_fee)` (the
    /// tip). The base fee portion (`gas_used * base_fee`) is burned
    /// (removed from supply).
    ///
    /// # State changes (identical to revm)
    ///
    /// - `sender.balance -= value + gas_used * effective_gas_price`
    /// - `sender.nonce += 1`
    /// - `recipient.balance += value`
    /// - `coinbase.balance += gas_used * (effective_gas_price - base_fee)`
    ///
    /// # Arguments
    ///
    /// - `signed`: the signed transaction.
    /// - `caller`: the recovered sender address.
    /// - `db`: the cache database (reads via `DatabaseRef`, writes
    ///   via direct `cache.accounts` mutation).
    /// - `coinbase`: the block's coinbase address (tip recipient).
    /// - `base_fee`: the block's base fee (wei per gas unit).
    ///
    /// # Returns
    ///
    /// `Some(ExecutionResult)` if the native path was taken.
    /// `None` if the tx doesn't qualify (caller should use revm).
    ///
    /// # Panics
    ///
    /// Panics if the database mutex is poisoned (internal to
    /// `load_account`).
    /// Whether `recipient` is executed as a precompile rather than as an
    /// ordinary account.
    ///
    /// Precompiles have no account code, so the fast paths' "no code ⇒
    /// plain transfer" rule would otherwise treat them as EOAs and skip
    /// their execution entirely — returning empty output and charging
    /// calldata gas instead of the precompile's own gas and result. That
    /// is a consensus-visible divergence: `sha256` (0x02) called with
    /// empty input must return the 32-byte digest of empty input, and a
    /// call to `identity` must echo its calldata, whereas the shortcut
    /// would report success with no output at all.
    ///
    /// Both sets are checked: Ethereum's (fork-dependent, taken from
    /// revm so a future EIP precompile is covered automatically) and
    /// Oxide's native precompiles, which live in their own address space
    /// (`0x0000…OOXX`) and are unknown to revm.
    fn recipient_is_precompile(recipient: &revm::primitives::Address, spec: SpecId) -> bool {
        use revm::precompile::{PrecompileSpecId, Precompiles};
        if Precompiles::new(PrecompileSpecId::from(spec)).contains(recipient) {
            return true;
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(recipient.as_slice());
        crate::precompiles::is_precompile(&Address(bytes))
    }

    fn try_native_transfer<DB: DatabaseRef>(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        db: &mut CacheDB<DB>,
        coinbase: revm::primitives::Address,
        base_fee: u64,
        spec: SpecId,
    ) -> Option<ExecutionResult> {
        // ── Qualification checks ──────────────────────────────

        // 1. Must be a Call (not Create).
        let recipient = match signed.to() {
            tx::TxKind::Create => return None,
            tx::TxKind::Call(addr) => addr,
        };

        // 2. A precompile executes even though it has no account code,
        //    so it must never take the plain-transfer shortcut.
        if Self::recipient_is_precompile(&recipient, spec) {
            return None;
        }

        // 2. Empty calldata.
        if !signed.data().is_empty() {
            return None;
        }

        // 3. Empty access list and no EIP-7702 authorizations. A
        //    type-4 tx carries delegation tuples that must execute —
        //    a fast path that skips revm would silently drop them.
        if !signed.access_list().is_empty() || !signed.authorization_list().is_empty() {
            return None;
        }

        // 4. Recipient has no code (is an EOA).
        //    Check the cache directly — avoids the `AccountInfo`
        //    clone from `basic_ref`. If the account is not in the
        //    cache, it doesn't exist yet (no code, is an EOA).
        //    `B256::ZERO` is a sentinel used by test setup; treat
        //    it the same as `KECCAK_EMPTY` (no code).
        let recipient_has_code = match db.cache.accounts.get(&recipient) {
            Some(account) => {
                account.info.code_hash != revm::primitives::KECCAK_EMPTY
                    && account.info.code_hash != revm::primitives::B256::ZERO
            }
            None => false, // Account doesn't exist — no code.
        };
        if recipient_has_code {
            return None; // Recipient is a contract — needs EVM.
        }

        // 5. Gas limit >= intrinsic gas (21000 for a simple transfer).
        let gas_limit = signed.gas_limit();
        if gas_limit < TX_GAS_TRANSFER {
            return None; // Let revm handle the error.
        }

        // 9. Value and gas price must fit in u128.
        let value_u128: u128 = match signed.value().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let max_fee: u128 = match signed.max_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let priority_fee: u128 = match signed.max_priority_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };

        // Compute effective gas price per EIP-1559.
        let effective_gas_price = std::cmp::min(max_fee, u128::from(base_fee) + priority_fee);

        // 8. Effective gas price >= base fee.
        if effective_gas_price < u128::from(base_fee) {
            return None; // Let revm handle the error.
        }

        // ── Read + validate sender ─────────────────────────────
        //
        // We load the sender account, check nonce and balance, then
        // modify in place. The `load_account` call returns a `&mut
        // DbAccount` that borrows `db`; we scope it so the borrow is
        // released before we load other accounts.
        {
            let sender_account = db.load_account(caller).ok()?;

            // 6. Nonce must match.
            if sender_account.info.nonce != signed.nonce() {
                return None;
            }

            // 7. Sufficient balance for value + gas reserve.
            //    The EVM deducts `gas_limit * effective_gas_price`
            //    upfront as a gas reserve, then refunds the unused
            //    portion. The sender must have enough for both the
            //    reserve and the value transfer.
            let gas_reserve = u128::from(gas_limit) * effective_gas_price;
            let total_needed = value_u128 + gas_reserve;
            if sender_account.info.balance < revm::primitives::U256::from(total_needed) {
                return None;
            }

            // ── All checks passed — execute natively ───────────
            //
            // Net gas cost = gas_used * effective_gas_price
            // (gas_limit - gas_used is refunded).
            let gas_cost = u128::from(TX_GAS_TRANSFER) * effective_gas_price;
            sender_account.info.balance -= revm::primitives::U256::from(value_u128 + gas_cost);
            sender_account.info.nonce += 1;
            // Normalize code_hash: revm sets KECCAK_EMPTY for EOAs
            // during execution. Test setup (fund_account_for_test)
            // may use B256::ZERO as a sentinel; revm fixes it, so we
            // must too to produce identical state roots.
            if sender_account.info.code_hash == revm::primitives::B256::ZERO {
                sender_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            sender_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Update recipient ───────────────────────────────────
        {
            let recipient_account = db.load_account(recipient).ok()?;
            recipient_account.info.balance += signed.value();
            if recipient_account.info.code_hash == revm::primitives::B256::ZERO {
                recipient_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            recipient_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Update coinbase (tip only, base fee is burned) ─────
        let tip = effective_gas_price - u128::from(base_fee);
        if tip > 0 {
            let coinbase_tip = u128::from(TX_GAS_TRANSFER) * tip;
            let coinbase_account = db.load_account(coinbase).ok()?;
            coinbase_account.info.balance += revm::primitives::U256::from(coinbase_tip);
            if coinbase_account.info.code_hash == revm::primitives::B256::ZERO {
                coinbase_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            coinbase_account.account_state = revm::database::AccountState::Touched;
        }

        // ── Build ExecutionResult ──────────────────────────────
        //
        // Identical to what revm produces for a successful simple
        // transfer: Success with gas_used=21000, no logs, no output.
        // EIP-7623 floor gas for empty calldata = 21000 + 0 = 21000,
        // same as standard gas. Setting floor_gas correctly prevents
        // free-gas stuffing: a tx with empty calldata pays at least
        // 21000 gas (the floor), not less.
        let result = ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::default()
                .with_total_gas_spent(TX_GAS_TRANSFER)
                .with_refunded(0)
                .with_floor_gas(TX_GAS_TRANSFER),
            logs: Vec::new(),
            output: Output::Call(revm::primitives::Bytes::new()),
        };

        Some(result)
    }

    /// Native fast path for calls to contracts with **no runtime code**.
    ///
    /// When a transaction sends calldata to an address that has no
    /// deployed code (an EOA or a contract whose constructor didn't
    /// return runtime bytecode), revm still creates a full call frame,
    /// loads the empty code, and immediately returns. This costs
    /// ~60–80 µs per tx in revm overhead (frame setup, gas accounting,
    /// state journal). This fast path performs the same state changes
    /// (nonce bump, gas deduction, coinbase tip) in ~200 ns — a
    /// ~300× speedup for this tx class.
    ///
    /// # Qualification
    ///
    /// The tx must:
    /// 1. Be a `Call` (not `Create`).
    /// 2. Have **non-empty** calldata (empty calldata is handled by
    ///    `try_native_transfer`).
    /// 3. Have an empty access list.
    /// 4. Target a recipient with no code (`KECCAK_EMPTY` or `B256::ZERO`).
    /// 5. Have `gas_limit >= 21000 + calldata_gas`.
    /// 6. Have a matching nonce and sufficient balance.
    ///
    /// # Gas model
    ///
    /// `gas_used = max(21000 + calldata_gas, 21000 + calldata_tokens × 10)`
    /// 4 per zero byte and 16 per non-zero byte (EIP-2028). This
    /// matches revm's intrinsic gas calculation for a transaction
    /// that executes no opcodes. The cold-access surcharge
    /// (EIP-2929, 2600 gas) is **not** charged because the
    /// `try_native_transfer` fast path (which produces matching
    /// state roots) also doesn't charge it — revm's 21000 base
    /// includes the recipient access cost for top-level transactions.
    ///
    /// Budget: ~200 ns per tx (vs ~60–80 µs through revm).
    fn try_empty_code_call<DB: DatabaseRef>(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        db: &mut CacheDB<DB>,
        coinbase: revm::primitives::Address,
        base_fee: u64,
        spec: SpecId,
    ) -> Option<ExecutionResult> {
        // 1. Must be a Call (not Create).
        let recipient = match signed.to() {
            tx::TxKind::Create => return None,
            tx::TxKind::Call(addr) => addr,
        };

        // 1b. A precompile has no account code but is not an EOA — its
        //     execution is the whole point of the call, so it must fall
        //     through to revm rather than being answered as an empty
        //     call with no output.
        if Self::recipient_is_precompile(&recipient, spec) {
            return None;
        }

        // 2. Must have non-empty calldata (empty → try_native_transfer).
        let data = signed.data();
        if data.is_empty() {
            return None;
        }

        // 3. Empty access list and no EIP-7702 authorizations (see
        //    `try_native_transfer` — a fast path would drop the
        //    delegation tuples).
        if !signed.access_list().is_empty() || !signed.authorization_list().is_empty() {
            return None;
        }

        // 4. Recipient has no code. Unlike `try_native_transfer`,
        //    we **must** load the account from the database (not just
        //    check the local cache) because the recipient might have
        //    code in the parent DB that hasn't been loaded into the
        //    local cache yet. For simple transfers this doesn't matter
        //    (code is irrelevant for balance updates), but for calls
        //    with calldata, skipping execution against real code would
        //    produce wrong state roots.
        //
        //    `load_account` checks the local cache first, then falls
        //    through to the parent on miss. It also caches the account
        //    for later use (the recipient touch below). The borrow is
        //    scoped so we can access `db` again for the sender.
        let recipient_has_code = {
            let recipient_account = db.load_account(recipient).ok()?;
            recipient_account.info.code_hash != revm::primitives::KECCAK_EMPTY
                && recipient_account.info.code_hash != revm::primitives::B256::ZERO
        };
        if recipient_has_code {
            return None;
        }

        // 5. Gas limit >= intrinsic gas.
        //    EIP-2028: 4 gas per zero byte, 16 per non-zero byte.
        //    EIP-7623 (Prague): floor gas = 21000 + calldata_tokens × 10,
        //    where calldata_tokens = zero_bytes×1 + non_zero_bytes×4.
        //    The actual gas used is max(standard_gas, floor_gas).
        //    For empty calldata, floor_gas == standard_gas == 21000,
        //    so `try_native_transfer` is unaffected. For non-empty
        //    calldata, floor_gas is usually higher.
        let zero_bytes = data.iter().fold(0u64, |acc, &b| acc + u64::from(b == 0));
        let non_zero_bytes = data.len() as u64 - zero_bytes;
        let calldata_gas = zero_bytes * 4 + non_zero_bytes * 16;
        let calldata_tokens = zero_bytes + non_zero_bytes * 4;
        let floor_gas = TX_GAS_TRANSFER + calldata_tokens * 10;
        let standard_gas = TX_GAS_TRANSFER + calldata_gas;
        let gas_used = std::cmp::max(standard_gas, floor_gas);
        let gas_limit = signed.gas_limit();
        if gas_limit < gas_used {
            return None;
        }

        // 6. Value and gas price must fit in u128.
        let value_u128: u128 = match signed.value().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let max_fee: u128 = match signed.max_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };
        let priority_fee: u128 = match signed.max_priority_fee_per_gas().try_into() {
            Ok(v) => v,
            Err(_) => return None,
        };

        // 7. Effective gas price >= base fee (EIP-1559).
        let effective_gas_price = std::cmp::min(max_fee, u128::from(base_fee) + priority_fee);
        if effective_gas_price < u128::from(base_fee) {
            return None;
        }

        // ── All checks passed — execute natively ───────────────
        //
        // Same state changes as `try_native_transfer` but with
        // `gas_used = 21000 + calldata_gas` instead of 21000.

        // 8. Nonce must match + sufficient balance.
        {
            let sender_account = db.load_account(caller).ok()?;
            if sender_account.info.nonce != signed.nonce() {
                return None;
            }
            let gas_reserve = u128::from(gas_limit) * effective_gas_price;
            let total_needed = value_u128 + gas_reserve;
            if sender_account.info.balance < revm::primitives::U256::from(total_needed) {
                return None;
            }

            // Deduct gas cost + value, increment nonce.
            let gas_cost = u128::from(gas_used) * effective_gas_price;
            sender_account.info.balance -= revm::primitives::U256::from(value_u128 + gas_cost);
            sender_account.info.nonce += 1;
            if sender_account.info.code_hash == revm::primitives::B256::ZERO {
                sender_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            sender_account.account_state = revm::database::AccountState::Touched;
        }

        // Update recipient. revm touches the callee account for all
        // calls (even zero-value, even to empty-code accounts) because
        // the CALL frame loads the account. We must match this.
        {
            let recipient_account = db.load_account(recipient).ok()?;
            if value_u128 > 0 {
                recipient_account.info.balance += signed.value();
            }
            if recipient_account.info.code_hash == revm::primitives::B256::ZERO {
                recipient_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            recipient_account.account_state = revm::database::AccountState::Touched;
        }

        // Update coinbase (tip only, base fee is burned).
        let tip = effective_gas_price - u128::from(base_fee);
        if tip > 0 {
            let coinbase_tip = u128::from(gas_used) * tip;
            let coinbase_account = db.load_account(coinbase).ok()?;
            coinbase_account.info.balance += revm::primitives::U256::from(coinbase_tip);
            if coinbase_account.info.code_hash == revm::primitives::B256::ZERO {
                coinbase_account.info.code_hash = revm::primitives::KECCAK_EMPTY;
            }
            coinbase_account.account_state = revm::database::AccountState::Touched;
        }

        // Build ExecutionResult — identical to what revm produces for
        // a successful call to empty code: Success with no logs, no
        // output, gas_used = max(21000 + calldata_gas, floor_gas).
        // EIP-7623 floor gas prevents free-gas stuffing: a tx with
        // cheap calldata still pays at least the floor gas.
        let result = ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas: ResultGas::default()
                .with_total_gas_spent(gas_used)
                .with_refunded(0)
                .with_floor_gas(floor_gas),
            logs: Vec::new(),
            output: Output::Call(revm::primitives::Bytes::new()),
        };

        Some(result)
    }

    /// Synthesize the geth-callTracer-equivalent root frame for a
    /// transaction that executed on a native fast path (no revm
    /// frame machinery ran, so the `CallRecorder` saw nothing).
    ///
    /// The fast paths only ever produce `Success` — every check that
    /// could fail falls through to revm — so `error` is always
    /// `None` and `output` is empty. `gas`/`gasUsed` use the tx-level
    /// values (the frame gas equals the tx gas for a single-frame
    /// call, and geth's callTracer reports the same).
    fn fast_path_frame(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        result: &ExecutionResult,
    ) -> trace::CallFrame {
        let to = match signed.to() {
            tx::TxKind::Call(addr) => Some(revm::primitives::Address::from(addr.0)),
            tx::TxKind::Create => None,
        };
        trace::CallFrame {
            kind: "CALL",
            from: caller,
            to,
            value: signed.value(),
            gas_limit: signed.gas_limit(),
            gas_used: result.tx_gas_used(),
            input: signed.data().clone(),
            output: revm::primitives::Bytes::new(),
            error: None,
            revert_reason: None,
            calls: Vec::new(),
        }
    }

    /// Build the [`SpecTx`] record for a transaction that ran on a
    /// native fast path (`try_native_transfer` or
    /// `try_empty_code_call`).
    ///
    /// The fast paths touch exactly three accounts — caller (nonce +
    /// balance), recipient (balance), and the coinbase (tip). The
    /// coinbase is tracked through `coinbase_delta` instead of the
    /// write set because every transaction writes it and the change
    /// is strictly additive. When the caller *is* the coinbase the
    /// nonce bump lands on the fee-recipient account — a
    /// non-additive change the delta cannot represent — so the tx is
    /// flagged `coinbase_nontrivial` and re-executes canonically.
    ///
    /// `coinbase_before` is the coinbase balance the group cache
    /// showed just before this tx ran — what any `BALANCE(coinbase)`
    /// would have observed (fast paths never execute opcodes, so
    /// `coinbase.read` only matters for the caller == coinbase case,
    /// which is already `must_reexec`).
    #[allow(clippy::too_many_arguments)]
    fn spec_fast_path<DB: DatabaseRef>(
        db: &CacheDB<DB>,
        idx: usize,
        caller: revm::primitives::Address,
        signed: &tx::SignedTx,
        coinbase: revm::primitives::Address,
        coinbase_before: revm::primitives::U256,
        result: ExecutionResult,
    ) -> SpecTx {
        let recipient = match signed.to() {
            tx::TxKind::Call(addr) => revm::primitives::Address::from(addr.0),
            // Both fast paths reject Create before reaching here.
            tx::TxKind::Create => revm::primitives::Address::ZERO,
        };
        let caller_is_coinbase = caller == coinbase;

        let mut reads: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::with_capacity(2);
        reads.insert(caller);
        reads.insert(recipient);

        let mut writes: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::with_capacity(2);
        let mut write_accounts = Vec::with_capacity(2);
        for addr in [caller, recipient] {
            if addr == coinbase || !writes.insert(addr) {
                continue;
            }
            if let Some(dba) = db.cache.accounts.get(&addr) {
                write_accounts.push((addr, dba.clone()));
            }
        }

        let coinbase_after =
            db.cache.accounts.get(&coinbase).map_or(coinbase_before, |a| a.info.balance);
        let frame = Self::fast_path_frame(signed, caller, &result);
        SpecTx {
            idx,
            sender: caller,
            result: Ok((result, Some(frame))),
            reads,
            writes,
            write_accounts,
            new_contracts: Vec::new(),
            coinbase_before,
            coinbase_delta: coinbase_after - coinbase_before,
            coinbase: CoinbaseObs {
                // The caller's balance-sufficiency check reads the
                // coinbase balance when caller == coinbase.
                read: caller_is_coinbase,
                accessed: caller_is_coinbase || recipient == coinbase,
                nontrivial: caller_is_coinbase,
            },
            must_reexec: caller_is_coinbase,
        }
    }

    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] if the `TxEnv` cannot be
    /// constructed from the signed tx fields.
    fn build_tx_env(
        signed: &tx::SignedTx,
        caller: revm::primitives::Address,
        spec: SpecId,
    ) -> Result<TxEnv, ExecError> {
        // EIP-7702 gate: type-4 transactions are only valid from the
        // Prague hardfork onward (EIP-7702 shipped in Prague). On
        // Ethereum, submitting a type-4 tx pre-Prague is a validity
        // failure, not a decode failure — mirror that here so the
        // rejection is deterministic at every entry point that
        // builds a TxEnv.
        if signed.tx_type() == 4 && !spec.is_enabled_in(SpecId::PRAGUE) {
            return Err(ExecError::Malformed);
        }
        let to = match signed.to() {
            tx::TxKind::Create => TxKind::Create,
            tx::TxKind::Call(addr) => TxKind::Call(revm::primitives::Address::from(addr.0)),
        };
        // A5: wire gas pricing from the signed tx into the TxEnv.
        // - Legacy/EIP-2930: `gas_price` is the exact fee per gas.
        // - EIP-1559: `max_fee_per_gas` is the cap; `max_priority_fee_per_gas`
        //   is the tip. revm uses these with the block's base fee to
        //   compute the effective gas price.
        // Fuzz fix: U256::to::<u128>() panics if the value doesn't fit
        // in u128. Use try_into and reject oversized values.
        let gas_price =
            u128::try_from(signed.max_fee_per_gas()).map_err(|_| ExecError::Malformed)?;
        let priority_fee =
            u128::try_from(signed.max_priority_fee_per_gas()).map_err(|_| ExecError::Malformed)?;
        // EIP-2930/1559 access list — wire it through so revm warms
        // the listed (address, slot) pairs. Dropping it would charge
        // cold-access gas for warm slots and diverge state roots from
        // Ethereum semantics.
        let access_list: revm::context_interface::transaction::AccessList = signed
            .access_list()
            .iter()
            .map(|item| revm::context_interface::transaction::AccessListItem {
                address: item.address,
                storage_keys: item.storage_keys.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        // EIP-7702 authorization list — convert each decoded tuple to
        // revm's `SignedAuthorization`. revm recovers each authority,
        // applies the delegation designator, and charges the
        // PER_EMPTY_ACCOUNT_COST intrinsic gas per authorization.
        let authorization_list: Vec<
            revm::context_interface::either::Either<
                revm::context_interface::transaction::SignedAuthorization,
                revm::context_interface::transaction::RecoveredAuthorization,
            >,
        > = signed
            .authorization_list()
            .iter()
            .map(|auth| {
                revm::context_interface::either::Either::Left(
                    revm::context_interface::transaction::SignedAuthorization::new_unchecked(
                        revm::context_interface::transaction::Authorization {
                            chain_id: auth.chain_id,
                            address: auth.address,
                            nonce: auth.nonce,
                        },
                        auth.sig.recid.as_u8(),
                        auth.sig.r,
                        auth.sig.s,
                    ),
                )
            })
            .collect();
        let tx = TxEnv::builder()
            .gas_limit(signed.gas_limit())
            .caller(caller)
            .kind(to)
            .data(signed.data().clone())
            .nonce(signed.nonce())
            .value(signed.value())
            .gas_price(gas_price)
            .gas_priority_fee(Some(priority_fee))
            .access_list(access_list)
            .tx_type(Some(signed.tx_type()))
            .authorization_list(authorization_list)
            .build()
            .map_err(|_| ExecError::Malformed)?;
        Ok(tx)
    }

    /// Execute a batch of signed EVM transactions with **parallel
    /// sender recovery**.
    ///
    /// This is the high-throughput execution path. Profiling shows
    /// secp256k1 ECDSA recovery is 88% of per-tx cost (29.6 µs out
    /// of 33.6 µs). By recovering all senders in parallel across
    /// cores using `rayon`, then executing sequentially (the `CacheDB`
    /// requires single-writer access), we turn the 88% into
    /// `88%/N_cores`.
    ///
    /// On an 8-core machine, the expected per-tx cost drops from
    /// ~33.6 µs to ~4 µs (execution) + 29.6/8 µs (recovery) ≈ 7.7 µs,
    /// yielding ~130,000 tx/s.
    ///
    /// For even higher throughput, use [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// which skips sender recovery entirely (the caller pre-recovers
    /// senders at mempool ingestion time).
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is recovered from the signature).
    /// - `msgs`: a slice of raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction. Each result is
    /// either a vector of events (success) or an `ExecError` (failure).
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch — subsequent transactions
    /// are still executed.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`, `block_timestamp`, or
    /// touched mutex is poisoned (a previous thread panicked while
    /// holding the lock).
    pub fn handle_batch(
        &self,
        ctx: &TxContext,
        msgs: &[impl AsRef<[u8]> + Sync],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 1: decode + recover all senders in parallel.
        // Each tx is independently decoded and its sender recovered.
        // Failures are recorded and skipped during execution.
        //
        // secp256k1 recovery (~30 µs/tx) is the dominant cost. Rayon
        // parallelizes it across cores, reducing effective per-tx
        // cost to ~30µs/N_cores. For pre-recovered senders (mempool
        // already verified), use `handle_batch_preverified` to skip
        // this entirely.
        let decoded: Vec<DecodedTx> = msgs
            .par_iter()
            .map(|raw| {
                let signed =
                    tx::SignedTx::decode_raw(raw.as_ref()).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                // Canonical Ethereum tx hash — keccak256 of the raw
                // signed RLP. Computed here (parallel, off the DB
                // lock) so history recording needs no re-hash. The
                // raw bytes ride along for the `transactionsRoot`
                // trie at seal time.
                let tx_hash = alloy_primitives::keccak256(raw.as_ref());
                Ok((signed, caller, tx_hash, raw.as_ref().to_vec()))
            })
            .collect();

        self.execute_decoded(ctx, decoded)
    }

    /// Pre-recover senders from a batch of raw transactions.
    ///
    /// The mempool calls this at ingestion time to recover the sender
    /// for each transaction **once**. The resulting [`PreverifiedTx`]
    /// pairs are then passed to [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// or [`handle_batch_parallel_preverified`](Self::handle_batch_parallel_preverified),
    /// which skip secp256k1 recovery entirely during block execution.
    ///
    /// This is the key to eliminating the ~30 µs/tx signature recovery
    /// cost from the block execution critical path. Recovery happens
    /// once at mempool admission (off the consensus critical path);
    /// execution reuses the pre-recovered sender.
    ///
    /// # Arguments
    ///
    /// - `msgs`: raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of `PreverifiedTx` (for valid txs) or `ExecError` (for
    /// malformed txs, wrong chain ID, or invalid signatures). The
    /// vector is in the same order as the input.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] for each transaction that
    /// cannot be decoded, has the wrong chain ID, or has an invalid
    /// signature.
    ///
    /// # Panics
    ///
    /// This function does not panic.
    pub fn preverify_batch<'a, T: AsRef<[u8]> + Sync + 'a>(
        &self,
        msgs: &'a [T],
    ) -> Vec<Result<PreverifiedTx<'a>, ExecError>> {
        msgs.par_iter()
            .map(|raw| {
                let signed =
                    tx::SignedTx::decode_raw(raw.as_ref()).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                Ok(PreverifiedTx { raw: raw.as_ref(), sender: caller })
            })
            .collect()
    }

    /// Execute a batch of transactions with **pre-verified senders**.
    ///
    /// This is the highest-throughput serial execution path. The
    /// caller (mempool/block builder) has already recovered the sender
    /// for each tx via [`preverify_batch`](Self::preverify_batch).
    /// This method re-recovers the sender from the signature and
    /// checks it matches the pre-recovered value — only RLP decoding
    /// (~79 ns/tx), chain ID validation, and sender re-verification
    /// remain in Phase 1.
    ///
    /// # Performance
    ///
    /// Re-recovery adds ~30 µs/tx (single-threaded) or ~3.7 µs/tx
    /// (8-core parallelized) back to the critical path. This is the
    /// cost of not trusting the proposer. For 10k simple transfers,
    /// batch time is ~80 ms (recovery + native execution) — the same
    /// as the non-preverified path. The preverified path still wins
    /// because it avoids redundant recovery at mempool ingestion.
    ///
    /// # Security
    ///
    /// The sender is re-recovered from the signature inside this
    /// method and checked against `pv.sender`. A byzantine block
    /// proposer supplying wrong senders will be detected here —
    /// mismatched senders are rejected with `ExecError::Malformed`
    /// before any state transition occurs. This closes the trust
    /// gap: the proposer cannot forge a sender.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is re-recovered from the signature).
    /// - `txs`: a slice of [`PreverifiedTx`] (raw bytes + pre-recovered
    ///   sender, used as a hint and verified).
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch. A sender mismatch
    /// (pre-recovered vs signature-recovered) returns `Malformed`.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    pub fn handle_batch_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 1: decode and re-recover the sender. RLP decode is
        // ~79 ns/tx; secp256k1 recovery is ~30 µs/tx. We re-recover
        // the sender and check it matches the pre-recovered value.
        // A byzantine proposer cannot forge a sender — any mismatch
        // is rejected before state transition.
        let decoded: Vec<DecodedTx> = txs
            .par_iter()
            .map(|pv| {
                let signed = tx::SignedTx::decode_raw(pv.raw).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                // Re-recover the sender from the signature. This is
                // the security gate: we do NOT trust `pv.sender`.
                let recovered = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let recovered_addr = alloy_primitives_address(recovered.0);
                // Check the pre-recovered sender matches the
                // signature-recovered sender. A mismatch means the
                // proposer supplied a wrong sender — reject it.
                if recovered_addr != pv.sender {
                    return Err(ExecError::Malformed);
                }
                let tx_hash = alloy_primitives::keccak256(pv.raw);
                Ok((signed, recovered_addr, tx_hash, pv.raw.to_vec()))
            })
            .collect();

        self.execute_decoded(ctx, decoded)
    }

    /// Shared execution loop for decoded transactions.
    ///
    /// Both [`handle_batch`](Self::handle_batch) and
    /// [`handle_batch_preverified`](Self::handle_batch_preverified)
    /// produce a `decoded` vector of `(SignedTx, caller)` pairs (or
    /// errors). This method executes them sequentially under a single
    /// DB lock, trying the native fast path first and falling through
    /// to revm for non-native txs.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    // One long linear loop: fast path, empty-code path, then revm — the
    // sequencing is the point, so splitting it would obscure the order.
    #[allow(clippy::too_many_lines)]
    fn execute_decoded(
        &self,
        ctx: &TxContext,
        decoded: Vec<DecodedTx>,
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Phase 2: execute all txs sequentially under a single lock.
        // The CacheDB is a single-writer structure — parallel execution
        // would require partitioning the state, which is future work.
        //
        // For each tx, try the **native fast path** first (simple ETH
        // transfers bypass revm entirely). Only fall through to revm
        // for contract calls, creations, and txs with calldata.
        //
        // For all-native batches (simple transfers to EOAs), the EVM
        // context is never constructed — zero revm overhead. For mixed
        // batches, the EVM context is built per non-native tx inside a
        // scoped block; the ~100 ns rebuild cost is negligible vs the
        // ~3.7 µs EVM execution cost.
        let mut results = Vec::with_capacity(decoded.len());

        // Acquire the DB lock once for the entire batch.
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);
        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);

        // Accumulate touched accounts in a local set to avoid
        // locking the mutex per tx. Merge once at the end.
        let mut local_touched: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();
        // Per-block inverse-diff accumulator — merged into
        // `self.block_undo` once at the end (same pattern as
        // `local_touched`).
        let mut local_undo = versioned::BlockUndo::default();

        for item in decoded {
            let (signed, caller, tx_hash, raw) = match item {
                Ok(v) => v,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };

            // Try the native fast path first. For simple ETH
            // transfers (empty calldata, EOA recipient), this
            // bypasses revm entirely — just balance + nonce
            // updates. The native path accesses the CacheDB
            // directly, so no EVM context is needed.
            //
            // Capture the fast-path write set ({caller, recipient,
            // coinbase}) unconditionally — if the path declines and
            // the tx falls through to revm, the entries still hold
            // the correct pre-block values and the later capture is
            // a no-op (first-write-wins).
            Self::undo_capture_fast_path(&mut local_undo, db, &signed, caller, coinbase);
            if let Some(result) = Self::try_native_transfer(
                &signed,
                caller,
                &mut *db,
                coinbase,
                self.current_base_fee(),
                self.spec,
            ) {
                local_touched.insert(caller);
                if let tx::TxKind::Call(addr) = signed.to() {
                    local_touched.insert(revm::primitives::Address::from(addr.0));
                }
                local_touched.insert(coinbase);
                // Fast paths bypass revm's frame machinery, so no
                // `CallRecorder` ran — but geth's callTracer still
                // reports a root CALL frame for a plain transfer.
                // Synthesize the equivalent frame so every sealed tx
                // has a trace.
                let frame = Self::fast_path_frame(&signed, caller, &result);
                results.push(self.exec_result_to_events(
                    Ok(result),
                    Some((history::stored_tx(&signed, caller, tx_hash, 0), raw, Some(frame))),
                ));
                continue;
            }

            // Try the empty-code call fast path. For calls to
            // contracts with no runtime code (EOA or constructor-only
            // deployment), this bypasses revm's call-frame setup.
            if let Some(result) = Self::try_empty_code_call(
                &signed,
                caller,
                &mut *db,
                coinbase,
                self.current_base_fee(),
                self.spec,
            ) {
                local_touched.insert(caller);
                if let tx::TxKind::Call(addr) = signed.to() {
                    local_touched.insert(revm::primitives::Address::from(addr.0));
                }
                local_touched.insert(coinbase);
                let frame = Self::fast_path_frame(&signed, caller, &result);
                results.push(self.exec_result_to_events(
                    Ok(result),
                    Some((history::stored_tx(&signed, caller, tx_hash, 0), raw, Some(frame))),
                ));
                continue;
            }

            // Fall through to revm for non-native txs (contract
            // calls, creations, txs with calldata, etc.). Build
            // the EVM context in a scoped block — the `&mut *db`
            // borrow is released when the block exits, allowing
            // the next tx to use the native path if it qualifies.
            let tx = match Self::build_tx_env(&signed, caller, self.spec) {
                Ok(t) => t,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };

            let result = {
                let mut evm = self.build_evm(&mut *db, coinbase, block_number, block_timestamp);
                // `transact` (not `transact_commit`) gives the
                // complete `EvmState`: every account the tx
                // modified, including internal-call targets and
                // selfdestruct beneficiaries — not just the
                // top-level caller/to/created/coinbase set that
                // under-tracked durable state.
                let result_and_state = match evm.inspect_tx(tx) {
                    Ok(rs) => rs,
                    Err(e) => {
                        evm.precompiles.clear_native_journal();
                        results.push(Err(ExecError::ModuleRejected(format!(
                            "evm transact failed: {e:?}"
                        ))));
                        continue;
                    }
                };
                evm.precompiles.clear_native_journal();
                let call_trace = evm.inspector.1.take_root();
                // Track the exact modified-account set locally
                // (no lock per tx), then commit.
                local_touched.extend(result_and_state.state.keys().copied());
                for addr in result_and_state.state.keys() {
                    local_undo
                        .capture(*addr, evm.ctx.journaled_state.database.cache.accounts.get(addr));
                }
                evm.commit(result_and_state.state);
                (result_and_state.result, call_trace)
            };

            let (result, call_trace) = result;
            results.push(self.exec_result_to_events(
                Ok(result),
                Some((history::stored_tx(&signed, caller, tx_hash, 0), raw, call_trace)),
            ));
        }

        // Merge local touched set into the global one (single lock).
        {
            let mut touched = framework::lock_state(&self.touched);
            touched.extend(local_touched);
        }
        {
            let mut undo = framework::lock_state(&self.block_undo);
            for (addr, entry) in local_undo.accounts {
                undo.accounts.entry(addr).or_insert(entry);
            }
        }

        // Silence unused-ctx warning — ctx is part of the Module
        // interface but EVM recovers the sender from the signature.
        let _ = ctx;

        results
    }

    /// Execute a batch of signed EVM transactions with **parallel
    /// speculative execution**.
    ///
    /// This is the highest-throughput execution path. It extends
    /// [`handle_batch`](Self::handle_batch) by parallelizing not only
    /// signature recovery but also EVM execution itself, using
    /// per-sender-group state snapshots.
    ///
    /// # Algorithm
    ///
    /// 1. **Parallel decode + recovery**: All senders are recovered in
    ///    parallel (same as `handle_batch`).
    /// 2. **Sender grouping**: Transactions are grouped by sender.
    ///    Within a group, transactions execute sequentially (nonce
    ///    dependency). Across groups, transactions are independent
    ///    (different senders).
    /// 3. **Parallel execution**: Each group executes on its own
    ///    copy-on-write `CacheDB` over a shared snapshot. Groups
    ///    execute in parallel via `rayon`. Each transaction uses
    ///    `transact` (non-commit) to obtain the `EvmState` diff —
    ///    its exact read and write sets — then commits it to the
    ///    group's local clone so the next transaction in the group
    ///    sees the updated state. Speculative EVMs run with
    ///    read-only native precompiles (a suppressed native
    ///    mutation flags the tx for re-execution) and a
    ///    `BALANCE(coinbase)` detector.
    /// 4. **Canonical-order commit**: Transactions are committed in
    ///    original batch order — *not* group order — so an
    ///    interleaving like `A0, B0, A1` can never commit as
    ///    `A0, A1, B0`. At each tx's position, its speculative
    ///    read/write sets are validated against the writes of all
    ///    canonically-earlier txs from other senders: a tx whose
    ///    speculation saw only same-sender writes and untouched
    ///    accounts merges directly; anything else re-executes
    ///    against the main DB, which by then holds exactly the
    ///    canonical pre-state. Once a tx re-executes, its
    ///    same-sender successors re-execute too (they speculated
    ///    on its speculative outcome).
    /// 5. **Coinbase handling**: The coinbase (fee recipient) is
    ///    written by every transaction via tips, so it is tracked
    ///    outside the read/write sets: each tx's net coinbase
    ///    delta merges additively in canonical order, keeping the
    ///    running balance canonical. A tx that observed the
    ///    coinbase balance (`BALANCE`) re-executes unless the
    ///    balance it saw matches the canonical total; a tx that
    ///    changed the coinbase non-additively (nonce/storage)
    ///    always re-executes.
    ///
    /// # When to use this vs `handle_batch`
    ///
    /// Use `handle_batch_parallel` when the batch contains
    /// transactions from **multiple senders** (the common case in a
    /// real blockchain). When all transactions share a single sender,
    /// this method degrades to sequential execution (one group) plus
    /// the overhead of cloning the DB — `handle_batch` is faster in
    /// that case.
    ///
    /// # Limitations
    ///
    /// - Conflict detection is account-granular: two txs touching
    ///   different storage slots of the same account are treated as
    ///   conflicting. Per-storage-slot tracking is future work.
    /// - Re-execution cascades within a sender: one invalid
    ///   speculative tx re-executes all its same-sender successors
    ///   (their speculation depended on its outcome).
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM — the sender
    ///   is recovered from the signature).
    /// - `msgs`: a slice of raw RLP-encoded signed transactions.
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction. Each result is
    /// either a vector of events (success) or an `ExecError` (failure).
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch — subsequent transactions
    /// are still executed.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned (a previous
    /// thread panicked while holding the lock).
    #[allow(clippy::too_many_lines)]
    pub fn handle_batch_parallel(
        &self,
        ctx: &TxContext,
        msgs: &[impl AsRef<[u8]> + Sync],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Fast path: empty batch.
        if msgs.is_empty() {
            return Vec::new();
        }

        // Phase 1: decode + recover all senders in parallel.
        // Same as handle_batch — rayon parallelizes the 88%-of-cost
        // secp256k1 recovery across cores.
        //
        // For pre-recovered senders (mempool already verified), use
        // `handle_batch_parallel_preverified` to skip this entirely.
        let decoded: Vec<DecodedTx> = msgs
            .par_iter()
            .map(|raw| {
                let signed =
                    tx::SignedTx::decode_raw(raw.as_ref()).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let caller = alloy_primitives_address(sender.0);
                let tx_hash = alloy_primitives::keccak256(raw.as_ref());
                Ok((signed, caller, tx_hash, raw.as_ref().to_vec()))
            })
            .collect();

        self.execute_parallel_decoded(ctx, decoded)
    }

    /// Execute a batch of transactions with **pre-verified senders**
    /// and **parallel speculative execution**.
    ///
    /// This combines the two highest-throughput optimizations:
    /// 1. **Pre-verified senders** — re-recovers the sender from the
    ///    signature and checks it matches the pre-recovered value
    ///    (the caller pre-recovered senders at mempool ingestion time;
    ///    we verify rather than trust).
    /// 2. **Parallel speculative execution** — transactions from
    ///    different senders execute in parallel on per-group state
    ///    snapshots, with conflict detection and sequential fallback.
    ///
    /// This is the fastest execution path in the EVM module. Use it
    /// when the mempool has already verified senders and the batch
    /// contains transactions from multiple senders.
    ///
    /// # Security
    ///
    /// Same security model as
    /// [`handle_batch_preverified`](Self::handle_batch_preverified):
    /// the sender is re-recovered from the signature and checked
    /// against the pre-recovered value. A byzantine proposer
    /// supplying wrong senders is rejected. See that method's
    /// documentation for the full security discussion.
    ///
    /// # Arguments
    ///
    /// - `ctx`: the transaction context (unused for EVM).
    /// - `txs`: a slice of [`PreverifiedTx`] (raw bytes + pre-recovered
    ///   sender).
    ///
    /// # Returns
    ///
    /// A vector of results, one per input transaction.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    #[allow(clippy::too_many_lines)]
    pub fn handle_batch_parallel_preverified(
        &self,
        ctx: &TxContext,
        txs: &[PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Fast path: empty batch.
        if txs.is_empty() {
            return Vec::new();
        }

        // Phase 1: decode and re-recover the sender. We do NOT
        // trust `pv.sender` — a byzantine proposer could forge it.
        let decoded: Vec<DecodedTx> = txs
            .par_iter()
            .map(|pv| {
                let signed = tx::SignedTx::decode_raw(pv.raw).map_err(|_| ExecError::Malformed)?;
                if signed.chain_id() != self.chain_id {
                    return Err(ExecError::Malformed);
                }
                // Re-recover the sender from the signature and
                // check it matches the pre-recovered value.
                let recovered = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
                let recovered_addr = alloy_primitives_address(recovered.0);
                if recovered_addr != pv.sender {
                    return Err(ExecError::Malformed);
                }
                let tx_hash = alloy_primitives::keccak256(pv.raw);
                Ok((signed, recovered_addr, tx_hash, pv.raw.to_vec()))
            })
            .collect();

        self.execute_parallel_decoded(ctx, decoded)
    }

    /// Shared parallel execution loop for decoded transactions.
    ///
    /// Both [`handle_batch_parallel`](Self::handle_batch_parallel) and
    /// [`handle_batch_parallel_preverified`](Self::handle_batch_parallel_preverified)
    /// produce a `decoded` vector. This method implements the
    /// parallel speculative execution algorithm: sender grouping,
    /// parallel execution on per-group snapshots, conflict detection,
    /// and sequential fallback for conflicting groups.
    ///
    /// # Panics
    ///
    /// Panics if the `DB`, `coinbase`, `block_height`,
    /// `block_timestamp`, or touched mutex is poisoned.
    #[allow(clippy::too_many_lines)]
    fn execute_parallel_decoded(
        &self,
        ctx: &TxContext,
        decoded: Vec<DecodedTx>,
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        use std::collections::hash_map::Entry;
        // Phase 2: group txs by sender, preserving original order
        // within each group. Txs from the same sender must execute
        // sequentially (nonce dependency). Txs from different senders
        // can execute in parallel.
        //
        // We use an insertion-ordered map so that groups are naturally
        // ordered by first appearance (canonical order).
        let mut groups: std::collections::HashMap<
            revm::primitives::Address,
            Vec<(usize, tx::SignedTx)>,
        > = std::collections::HashMap::new();
        let mut group_order: Vec<revm::primitives::Address> = Vec::new();
        let mut errors: Vec<Option<ExecError>> = vec![None; decoded.len()];
        let n_txs = decoded.len();
        // History metadata for each decoded tx, indexed by original
        // position. Built at grouping time (before `signed` moves into
        // its group) so the result-assembly phase can record receipts
        // without re-decoding. `None` for pre-execution failures. The
        // raw RLP rides along for the `transactionsRoot` trie.
        let mut metas: Vec<Option<(history::StoredTx, Vec<u8>)>> = Vec::with_capacity(n_txs);
        metas.resize_with(n_txs, || None);

        for (idx, item) in decoded.into_iter().enumerate() {
            match item {
                Ok((signed, caller, tx_hash, raw)) => {
                    metas[idx] = Some((history::stored_tx(&signed, caller, tx_hash, 0), raw));
                    match groups.entry(caller) {
                        Entry::Occupied(_) => {
                            groups.get_mut(&caller).expect("group exists").push((idx, signed));
                        }
                        Entry::Vacant(v) => {
                            group_order.push(caller);
                            v.insert(Vec::from([(idx, signed)]));
                        }
                    }
                }
                Err(e) => {
                    errors[idx] = Some(e);
                }
            }
        }

        // Note: single-group batches (all txs from one sender) are
        // handled correctly by the parallel path — the group executes
        // sequentially on its own clone. The clone cost (O(n_accounts))
        // is acceptable; a future optimization can skip the clone for
        // single-group batches by calling `execute_decoded` directly.

        // Phase 3: snapshot the main DB into an `Arc` for
        // copy-on-write sharing. Each group gets a
        // `CacheDB::new(SharedCacheDB(arc_clone))` — a fresh, empty
        // local cache backed by the shared parent via
        // `DatabaseRef`. Reads fall through to the parent on cache
        // miss; writes stay local. Per-group cost is O(1) init +
        // O(touched) memory, vs O(state) for a full clone.
        //
        // The snapshot is an O(1) `Arc::clone` — no deep clone of
        // the CacheDB. Each parallel group gets a fresh empty
        // `CacheDB<SharedCacheDB>` backed by the shared snapshot via
        // `DatabaseRef`. Reads fall through to the parent on cache
        // miss; writes stay local.
        let snapshot = framework::lock_state(&self.db).clone();
        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);

        // Phase 4: execute each group in parallel on its own COW
        // nested cache. Within a group txs run sequentially (nonce
        // dependency); across groups they speculate independently.
        // Every tx produces a `SpecTx` recording its exact per-tx
        // read/write sets, coinbase observation, and native-mutation
        // flags — the commit phase (Phase 5) validates each tx in
        // canonical index order, so speculation order cannot leak
        // into the committed result.
        //
        // Speculative EVMs run with read-only native precompiles:
        // a mutating staking call reverts instead of touching the
        // shared `StakingModule`, and the suppressed mutation sets
        // `native_blocked` so the tx re-executes canonically.
        let parent_coinbase = snapshot
            .cache
            .accounts
            .get(&coinbase)
            .map_or(revm::primitives::U256::ZERO, |a| a.info.balance);
        let group_results: Vec<GroupExecResult> = group_order
            .par_iter()
            .map(|sender| {
                let txs = groups.get(sender).expect("group exists");
                // COW nested cache: empty local cache, reads from
                // the shared parent on miss.
                let mut db: CacheDB<SharedCacheDB> = CacheDB::new(SharedCacheDB(snapshot.clone()));

                // Pre-load hot accounts into the nested cache before
                // execution. This avoids `DatabaseRef` trait dispatch
                // on the first access to each account. The accounts
                // touched by (almost) every tx in a group:
                //
                // 1. **Sender** — nonce bump + balance deduction on
                //    every tx.
                // 2. **Coinbase** — receives tips on every tx.
                // 3. **All unique recipients** — pre-loading every
                //    recipient in the group avoids a cache miss on
                //    the first call to each contract. For workloads
                //    with many calls to the same contract (CLOB,
                //    storage patterns), this eliminates repeated
                //    `DatabaseRef` dispatch.
                let _ = db.load_account(*sender);
                let _ = db.load_account(coinbase);
                // Collect unique recipient addresses from all txs in
                // the group. Uses a small HashSet to deduplicate —
                // typical groups have 1–5 unique recipients.
                let mut recipients: std::collections::HashSet<revm::primitives::Address> =
                    std::collections::HashSet::new();
                for (_, signed) in txs {
                    if let tx::TxKind::Call(addr) = signed.to() {
                        recipients.insert(revm::primitives::Address::from(addr.0));
                    }
                }
                for addr in &recipients {
                    let _ = db.load_account(*addr);
                }

                let mut spec_txs: Vec<SpecTx> = Vec::with_capacity(txs.len());

                for (idx, signed) in txs {
                    let caller = *sender;
                    let idx = *idx;

                    // The coinbase state this tx speculates against:
                    // pre-block balance plus own-group tips so far.
                    // `nonce_before` detects non-additive coinbase
                    // writes (only possible when the sender *is* the
                    // coinbase — tips never bump a nonce).
                    let coinbase_before = db
                        .cache
                        .accounts
                        .get(&coinbase)
                        .map_or(parent_coinbase, |a| a.info.balance);
                    let coinbase_nonce_before =
                        db.cache.accounts.get(&coinbase).map_or(0, |a| a.info.nonce);

                    // Try the native transfer fast path first. For
                    // simple ETH transfers (empty calldata, EOA
                    // recipient), this bypasses revm entirely.
                    if let Some(result) = Self::try_native_transfer(
                        signed,
                        caller,
                        &mut db,
                        coinbase,
                        self.current_base_fee(),
                        self.spec,
                    ) {
                        spec_txs.push(Self::spec_fast_path(
                            &db,
                            idx,
                            caller,
                            signed,
                            coinbase,
                            coinbase_before,
                            result,
                        ));
                        continue;
                    }

                    // Try the empty-code call fast path. For calls
                    // to contracts with no runtime code (EOA or
                    // constructor-only deployment), this bypasses
                    // revm's call-frame setup and gas accounting.
                    if let Some(result) = Self::try_empty_code_call(
                        signed,
                        caller,
                        &mut db,
                        coinbase,
                        self.current_base_fee(),
                        self.spec,
                    ) {
                        spec_txs.push(Self::spec_fast_path(
                            &db,
                            idx,
                            caller,
                            signed,
                            coinbase,
                            coinbase_before,
                            result,
                        ));
                        continue;
                    }

                    // Fall through to revm.
                    let tx_env = match Self::build_tx_env(signed, caller, self.spec) {
                        Ok(t) => t,
                        Err(e) => {
                            // Build failures are tx-intrinsic (malformed
                            // fields) — no state was read, so the result
                            // cannot depend on ordering.
                            spec_txs.push(SpecTx::intrinsic_error(idx, caller, e));
                            continue;
                        }
                    };

                    // Snapshot contract-code keys before the tx so the
                    // per-tx `new_contracts` diff is exact (CREATE is
                    // the only way code enters the cache).
                    let contracts_before: std::collections::HashSet<revm::primitives::B256> =
                        db.cache.contracts.keys().copied().collect();

                    // Speculative run: read-only native precompiles
                    // + coinbase-read detection. `transact` (not
                    // `transact_commit`) returns the per-tx `EvmState`
                    // — the exact set of accounts the tx loaded
                    // (reads) and modified (writes). The state diff is
                    // committed into the group cache before the EVM is
                    // dropped so `db` is free for the write-set scan.
                    let (result, native_blocked, coinbase_read, call_trace, loaded) = {
                        let mut evm =
                            self.build_spec_evm(&mut db, coinbase, block_number, block_timestamp);
                        let rs = evm.inspect_tx(tx_env);
                        let blocked = evm.precompiles.blocked_native_mutation();
                        evm.precompiles.clear_native_journal();
                        let cb_read = evm.inspector.1.1.observed();
                        let call_trace = evm.inspector.1.0.take_root();
                        match rs {
                            Ok(rs) => {
                                // `rs.state` holds every account the
                                // journal loaded — the exact read set.
                                let accessed_coinbase = rs.state.contains_key(&coinbase);
                                // A non-additive coinbase change cannot
                                // be merged via the balance delta:
                                // nonce bumps (sender == coinbase, or a
                                // CREATE/CREATE2 deployed at the fee
                                // recipient), storage writes into a
                                // contract living at that address, or
                                // destruction — `SELFDESTRUCT` or an
                                // EIP-161 empty-touch delete, which
                                // leaves balance, nonce, and storage
                                // map untouched in the journal entry
                                // but must still drop the account.
                                let coinbase_nontrivial =
                                    rs.state.get(&coinbase).is_some_and(|a| {
                                        a.is_touched()
                                            && (a.is_selfdestructed()
                                                || a.is_created_locally()
                                                || !a.storage.is_empty()
                                                || a.info.nonce != coinbase_nonce_before)
                                    });
                                let mut addrs: std::collections::HashSet<
                                    revm::primitives::Address,
                                > = std::collections::HashSet::with_capacity(rs.state.len());
                                for addr in rs.state.keys() {
                                    addrs.insert(*addr);
                                }
                                evm.commit(rs.state);
                                (
                                    Ok(rs.result),
                                    blocked,
                                    cb_read,
                                    call_trace,
                                    Some((addrs, accessed_coinbase, coinbase_nontrivial)),
                                )
                            }
                            Err(e) => (Err(e), blocked, cb_read, call_trace, None),
                        }
                    };

                    match result {
                        Ok(exec_result) => {
                            let (loaded_addrs, accessed_coinbase, coinbase_nontrivial) =
                                loaded.expect("Ok carries the loaded state");

                            // The coinbase delta captures the tx's
                            // net balance effect on the fee recipient
                            // (tips, plus transfers/selfdestructs to
                            // it — all strictly additive).
                            let coinbase_after = db
                                .cache
                                .accounts
                                .get(&coinbase)
                                .map_or(parent_coinbase, |a| a.info.balance);

                            // `loaded_addrs` holds every account the
                            // journal touched — the exact read set.
                            // Writes are the subset the commit marked
                            // modified (`account_state != None`),
                            // matching sequential `commit_account`
                            // semantics.
                            let mut reads: std::collections::HashSet<revm::primitives::Address> =
                                std::collections::HashSet::with_capacity(loaded_addrs.len());
                            for addr in &loaded_addrs {
                                if *addr != coinbase {
                                    reads.insert(*addr);
                                }
                            }

                            let mut writes: std::collections::HashSet<revm::primitives::Address> =
                                std::collections::HashSet::new();
                            let mut write_accounts: Vec<(
                                revm::primitives::Address,
                                revm::database::DbAccount,
                            )> = Vec::new();
                            for addr in &reads {
                                if let Some(dba) = db.cache.accounts.get(addr)
                                    && dba.account_state != revm::database::AccountState::None
                                {
                                    writes.insert(*addr);
                                    write_accounts.push((*addr, dba.clone()));
                                }
                            }

                            let new_contracts: Vec<(
                                revm::primitives::B256,
                                revm::bytecode::Bytecode,
                            )> = db
                                .cache
                                .contracts
                                .iter()
                                .filter(|(hash, _)| !contracts_before.contains(*hash))
                                .map(|(hash, code)| (*hash, code.clone()))
                                .collect();

                            spec_txs.push(SpecTx {
                                idx,
                                sender: caller,
                                result: Ok((exec_result, call_trace)),
                                reads,
                                writes,
                                write_accounts,
                                new_contracts,
                                coinbase_before,
                                coinbase_delta: coinbase_after - coinbase_before,
                                coinbase: CoinbaseObs {
                                    read: coinbase_read,
                                    accessed: accessed_coinbase,
                                    nontrivial: coinbase_nontrivial,
                                },
                                must_reexec: native_blocked || coinbase_nontrivial,
                            });
                        }
                        Err(e) => {
                            // revm validation failure — the only state
                            // consulted is the sender's account (nonce,
                            // balance, gas affordability), so the
                            // sender alone forms the read set.
                            let mut reads = std::collections::HashSet::new();
                            reads.insert(caller);
                            spec_txs.push(SpecTx {
                                idx,
                                sender: caller,
                                result: Err(ExecError::ModuleRejected(format!(
                                    "evm transact failed: {e:?}"
                                ))),
                                reads,
                                writes: std::collections::HashSet::new(),
                                write_accounts: Vec::new(),
                                new_contracts: Vec::new(),
                                coinbase_before,
                                coinbase_delta: revm::primitives::U256::ZERO,
                                coinbase: CoinbaseObs {
                                    read: false,
                                    accessed: false,
                                    nontrivial: false,
                                },
                                must_reexec: native_blocked,
                            });
                        }
                    }
                }

                GroupExecResult { spec_txs }
            })
            .collect();

        // Release the shared snapshot before Phase 5's
        // `Arc::make_mut` on the main DB: while `snapshot` (or any
        // per-group `SharedCacheDB` clone of it — those die with
        // their closures) is alive, the outer Arc's refcount is >1
        // and `make_mut` deep-clones the entire CacheDB — O(total
        // state) on every parallel batch. The snapshot's last use
        // is inside the parallel closures, so dropping it here is
        // free and restores the in-place mutation the Arc wrapping
        // was designed for.
        drop(snapshot);

        // Phase 5: commit in canonical transaction order.
        //
        // Speculation ran per-sender groups — for `A0, B0, A1` the
        // speculative execution order was effectively `A0, A1, B0`.
        // Merging in group order would let `A1` commit a result
        // computed without `B0`'s writes. Instead every tx is
        // validated at its canonical index position: it keeps its
        // speculative result iff no canonically-earlier tx from a
        // *different* sender wrote anything it read or wrote —
        // otherwise it is re-executed against the main DB, which at
        // that point holds exactly the canonical pre-state.
        //
        // `writers` maps each written account to its first writer's
        // sender plus a "multiple senders" flag; a tx conflicts when
        // any account in `reads ∪ writes` was written by a different
        // sender. Same-sender writes are excluded because the group's
        // sequential speculation already observed them — but only up
        // to the first re-execution: once a tx re-executes, its
        // same-group successors speculated on its speculative
        // outcome, so they re-execute too (`broken`).
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);

        // Flatten speculative records and signed txs into index
        // order — the commit loop below walks positions 0..n_txs.
        let mut flat: Vec<Option<SpecTx>> = Vec::with_capacity(n_txs);
        flat.resize_with(n_txs, || None);
        for gr in group_results {
            for st in gr.spec_txs {
                let idx = st.idx;
                flat[idx] = Some(st);
            }
        }
        let mut signed_by_idx: Vec<Option<&tx::SignedTx>> = Vec::with_capacity(n_txs);
        signed_by_idx.resize_with(n_txs, || None);
        for txs in groups.values() {
            for (idx, signed) in txs {
                signed_by_idx[*idx] = Some(signed);
            }
        }

        let mut writers: std::collections::HashMap<
            revm::primitives::Address,
            (revm::primitives::Address, bool),
        > = std::collections::HashMap::new();
        let mut broken: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();
        // Set once any tx changed the coinbase beyond an additive
        // balance delta (nonce/storage — e.g. sender == coinbase, or
        // a contract deployed at the fee recipient). Later txs that
        // accessed the coinbase at all can no longer trust their
        // speculative view of it.
        let mut coinbase_dirty = false;
        let mut all_touched: std::collections::HashSet<revm::primitives::Address> =
            std::collections::HashSet::new();
        // Inverse-diff accumulator for the parallel path — captures
        // only writes that land in the *main* DB (conflict
        // re-execution and non-conflict merges), never the
        // speculative scratch caches.
        let mut committed_undo = versioned::BlockUndo::default();
        // The committed result for each tx position — speculative or
        // re-executed, whichever the validation chose.
        let mut final_results: Vec<Option<TracedResult>> = Vec::with_capacity(n_txs);
        final_results.resize_with(n_txs, || None);

        for i in 0..n_txs {
            let Some(st) = flat[i].take() else {
                continue;
            };

            // Canonical coinbase balance before tx i — the main DB
            // receives merged deltas and re-executed tips in index
            // order, so this equals the sequential value.
            let canonical_coinbase = db
                .cache
                .accounts
                .get(&coinbase)
                .map_or(revm::primitives::U256::ZERO, |a| a.info.balance);

            let account_conflict =
                st.reads.iter().chain(st.writes.iter()).any(|addr| match writers.get(addr) {
                    Some(&(writer, multi)) => writer != st.sender || multi,
                    None => false,
                });
            // The speculative coinbase observation is only valid if
            // the balance it saw equals the canonical running total.
            let stale_coinbase = (st.coinbase.read && st.coinbase_before != canonical_coinbase)
                || (coinbase_dirty && st.coinbase.accessed);

            if st.must_reexec || broken.contains(&st.sender) || account_conflict || stale_coinbase {
                // Re-execute this tx against the canonical DB.
                broken.insert(st.sender);
                coinbase_dirty |= st.coinbase.nontrivial;
                let caller = st.sender;
                let signed = signed_by_idx[i].expect("speculative tx has signed bytes");
                let cb_nonce_pre = db.cache.accounts.get(&coinbase).map_or(0, |a| a.info.nonce);

                // Try native fast path first.
                Self::undo_capture_fast_path(&mut committed_undo, db, signed, caller, coinbase);
                if let Some(result) = Self::try_native_transfer(
                    signed,
                    caller,
                    &mut *db,
                    coinbase,
                    self.current_base_fee(),
                    self.spec,
                ) {
                    coinbase_dirty |= caller == coinbase;
                    all_touched.insert(caller);
                    all_touched.insert(coinbase);
                    for addr in [caller] {
                        match writers.entry(addr) {
                            Entry::Occupied(mut o) => {
                                if o.get().0 != caller {
                                    o.get_mut().1 = true;
                                }
                            }
                            Entry::Vacant(v) => {
                                v.insert((caller, false));
                            }
                        }
                    }
                    if let tx::TxKind::Call(addr) = signed.to() {
                        let rcp = revm::primitives::Address::from(addr.0);
                        all_touched.insert(rcp);
                        match writers.entry(rcp) {
                            Entry::Occupied(mut o) => {
                                if o.get().0 != caller {
                                    o.get_mut().1 = true;
                                }
                            }
                            Entry::Vacant(v) => {
                                v.insert((caller, false));
                            }
                        }
                    }
                    let frame = Self::fast_path_frame(signed, caller, &result);
                    final_results[i] = Some(Ok((result, Some(frame))));
                    continue;
                }

                // Try empty-code call fast path — must use the
                // same fast paths as the speculative execution to
                // ensure identical state roots.
                if let Some(result) = Self::try_empty_code_call(
                    signed,
                    caller,
                    &mut *db,
                    coinbase,
                    self.current_base_fee(),
                    self.spec,
                ) {
                    coinbase_dirty |= caller == coinbase;
                    all_touched.insert(caller);
                    all_touched.insert(coinbase);
                    match writers.entry(caller) {
                        Entry::Occupied(mut o) => {
                            if o.get().0 != caller {
                                o.get_mut().1 = true;
                            }
                        }
                        Entry::Vacant(v) => {
                            v.insert((caller, false));
                        }
                    }
                    if let tx::TxKind::Call(addr) = signed.to() {
                        let rcp = revm::primitives::Address::from(addr.0);
                        all_touched.insert(rcp);
                        match writers.entry(rcp) {
                            Entry::Occupied(mut o) => {
                                if o.get().0 != caller {
                                    o.get_mut().1 = true;
                                }
                            }
                            Entry::Vacant(v) => {
                                v.insert((caller, false));
                            }
                        }
                    }
                    let frame = Self::fast_path_frame(signed, caller, &result);
                    final_results[i] = Some(Ok((result, Some(frame))));
                    continue;
                }

                // Fall through to revm — the committed-path EVM
                // (mutating native precompiles enabled: this is the
                // canonical execution).
                let tx_env = match Self::build_tx_env(signed, caller, self.spec) {
                    Ok(t) => t,
                    Err(e) => {
                        final_results[i] = Some(Err(e));
                        continue;
                    }
                };
                {
                    let mut evm = self.build_evm(&mut *db, coinbase, block_number, block_timestamp);
                    match evm.inspect_tx(tx_env) {
                        Ok(rs) => {
                            let r = rs.result;
                            if let Some(cb) = rs.state.get(&coinbase) {
                                // Same non-additive predicate as the
                                // speculative scan: nonce, storage,
                                // creation, or destruction — anything a
                                // balance-delta merge cannot represent.
                                coinbase_dirty |= cb.is_touched()
                                    && (cb.is_selfdestructed()
                                        || cb.is_created_locally()
                                        || !cb.storage.is_empty()
                                        || cb.info.nonce != cb_nonce_pre);
                            }
                            let state_keys: Vec<revm::primitives::Address> =
                                rs.state.keys().copied().collect();
                            for addr in &state_keys {
                                all_touched.insert(*addr);
                                committed_undo.capture(
                                    *addr,
                                    evm.ctx.journaled_state.database.cache.accounts.get(addr),
                                );
                            }
                            evm.precompiles.clear_native_journal();
                            let call_trace = evm.inspector.1.take_root();
                            evm.commit(rs.state);
                            // Mark the tx's actual write set — accounts
                            // the commit marked modified — as written
                            // by this sender.
                            for addr in &state_keys {
                                if *addr == coinbase {
                                    continue;
                                }
                                if db.cache.accounts.get(addr).is_some_and(|a| {
                                    a.account_state != revm::database::AccountState::None
                                }) {
                                    match writers.entry(*addr) {
                                        Entry::Occupied(mut o) => {
                                            if o.get().0 != caller {
                                                o.get_mut().1 = true;
                                            }
                                        }
                                        Entry::Vacant(v) => {
                                            v.insert((caller, false));
                                        }
                                    }
                                }
                            }
                            final_results[i] = Some(Ok((r, call_trace)));
                        }
                        Err(e) => {
                            final_results[i] = Some(Err(ExecError::ModuleRejected(format!(
                                "evm transact failed: {e:?}"
                            ))));
                        }
                    }
                }
                continue;
            }

            // Speculation validated: merge the tx's write set into
            // the main DB and keep its speculative result.
            for (addr, account) in &st.write_accounts {
                committed_undo.capture(*addr, db.cache.accounts.get(addr));
                db.cache.accounts.insert(*addr, account.clone());
            }
            for (hash, bytecode) in &st.new_contracts {
                db.cache.contracts.entry(*hash).or_insert_with(|| bytecode.clone());
            }
            // Apply the coinbase delta now — keeping the running
            // balance canonical for every later validation check.
            if st.coinbase_delta != revm::primitives::U256::ZERO {
                committed_undo.capture(coinbase, db.cache.accounts.get(&coinbase));
                let coinbase_account = db.cache.accounts.entry(coinbase).or_insert_with(|| {
                    revm::database::DbAccount {
                        info: revm::database::state::AccountInfo {
                            balance: revm::primitives::U256::ZERO,
                            nonce: 0,
                            // `KECCAK_EMPTY` matches what revm's
                            // `insert_contract` sets for an empty-code
                            // account. Using `B256::ZERO` here would
                            // produce a different state root from the
                            // serial path.
                            code_hash: revm::primitives::KECCAK_EMPTY,
                            account_id: None,
                            code: Some(revm::bytecode::Bytecode::new_raw(
                                revm::primitives::Bytes::new(),
                            )),
                        },
                        // `Touched` matches what revm's `commit_account`
                        // sets for a modified account.
                        account_state: revm::database::AccountState::Touched,
                        storage: revm::primitives::HashMap::default(),
                    }
                });
                coinbase_account.info.balance += st.coinbase_delta;
                coinbase_account.account_state = revm::database::AccountState::Touched;
                all_touched.insert(coinbase);
            }
            for w in &st.writes {
                match writers.entry(*w) {
                    Entry::Occupied(mut o) => {
                        if o.get().0 != st.sender {
                            o.get_mut().1 = true;
                        }
                    }
                    Entry::Vacant(v) => {
                        v.insert((st.sender, false));
                    }
                }
                all_touched.insert(*w);
            }
            final_results[i] = Some(st.result);
        }

        // Merge touched accounts into the module-level set.
        {
            let mut touched = framework::lock_state(&self.touched);
            touched.extend(all_touched);
        }
        {
            let mut undo = framework::lock_state(&self.block_undo);
            for (addr, entry) in committed_undo.accounts {
                undo.accounts.entry(addr).or_insert(entry);
            }
        }

        // Phase 6: assemble results in original order. `final_results`
        // already carries whichever execution won — the validated
        // speculative result or the canonical re-execution.
        let mut results: Vec<Result<Vec<Event>, ExecError>> = Vec::with_capacity(n_txs);
        for (i, err) in errors.iter().enumerate() {
            if let Some(e) = err {
                results.push(Err(e.clone()));
                continue;
            }
            // Split `(result, trace)` out of the Ok payload and merge
            // the trace into `metas[i]` — `exec_result_to_events`
            // takes the 3-tuple so the trace lands in history beside
            // the receipt.
            match final_results[i].take() {
                Some(r) => {
                    let (res, call_trace) = match r {
                        Ok((res, t)) => (Ok(res), t),
                        Err(e) => (Err(e), None),
                    };
                    let meta = metas[i].take().map(|(s, raw)| (s, raw, call_trace));
                    results.push(self.exec_result_to_events(res, meta));
                }
                None => {
                    results.push(Err(ExecError::ModuleRejected(
                        "parallel execution: missing result".to_string(),
                    )));
                }
            }
        }

        // Silence unused-ctx warning — ctx is part of the Module
        // interface but EVM recovers the sender from the signature.
        let _ = ctx;

        results
    }

    /// Convert a revm `ExecutionResult` to a vector of Oxide events,
    /// recording the transaction into the executed-block history.
    ///
    /// Shared between `handle_batch` and `handle_batch_parallel` to
    /// ensure identical event formatting.
    ///
    /// `meta` is `Some((StoredTx, raw_rlp))` for transactions that
    /// executed (success, revert, or halt — all are sealed in the
    /// block) and `None` for transactions rejected before execution
    /// (decode / chain-id / signature-recovery failures). Only
    /// executed txs appear in `eth_getTransactionReceipt` /
    /// `eth_getLogs`. The raw RLP accompanies the record for the
    /// `transactionsRoot` trie at seal time.
    fn exec_result_to_events(
        &self,
        result: Result<revm::context::result::ExecutionResult, ExecError>,
        meta: Option<(history::StoredTx, Vec<u8>, Option<trace::CallFrame>)>,
    ) -> Result<Vec<Event>, ExecError> {
        match result {
            Ok(r) => {
                let tx_type = meta.as_ref().map_or(0, |m| m.0.tx_type);
                let receipt = receipts::Receipt::from_execution_result(&r, tx_type);
                if let Some((stored, raw, call_trace)) = meta {
                    framework::lock_state(&self.history).record(
                        stored,
                        receipt.clone(),
                        &raw,
                        call_trace,
                    );
                }
                let status_str = if receipt.status { "success" } else { "revert" };
                let contract_info =
                    receipt.contract_address.map(|a| format!(" contract={a}")).unwrap_or_default();
                let log_count = receipt.logs.len();
                Ok(vec![Event {
                    module: "evm",
                    kind: "evm_call",
                    data: format!(
                        "gas_used={} status={} base_fee={} logs={}{}",
                        receipt.gas_used,
                        status_str,
                        self.current_base_fee(),
                        log_count,
                        contract_info
                    )
                    .into_bytes(),
                }])
            }
            Err(e) => Err(e),
        }
    }
}

/// A shared reference to a `CacheDB<EmptyDB>` for copy-on-write
/// nested caches.
///
/// This wrapper implements [`DatabaseRef`] by delegating to the
/// inner `CacheDB`. It is the key to efficient parallel speculative
/// execution: each worker gets a
/// `CacheDB::new(SharedCacheDB(arc_clone))`, which starts with an
/// empty local cache and reads from the shared parent on cache miss.
/// Per-worker initialization cost is O(1) instead of O(state), and
/// per-worker memory is O(touched) instead of O(state).
///
/// # Why not `CacheDB::nest()`?
///
/// `nest()` consumes `self`, so it can only create one nested
/// cache. We need N nested caches (one per sender group) sharing
/// the same parent. `SharedCacheDB(Arc<...>)` lets us share the
/// parent across all workers via cheap `Arc` clones.
///
/// # Error type
///
/// The error type is [`Infallible`] — `EmptyDB` never returns
/// errors, and `CacheDB<EmptyDB>` delegates to it on cache miss.
/// The shared parent is read-only, so no errors can arise from
/// concurrent reads.
#[derive(Debug, Clone)]
struct SharedCacheDB(Arc<CacheDB<EmptyDB>>);

impl DatabaseRef for SharedCacheDB {
    type Error = std::convert::Infallible;

    #[inline]
    fn basic_ref(
        &self,
        address: revm::primitives::Address,
    ) -> Result<Option<revm::database::state::AccountInfo>, Self::Error> {
        self.0.basic_ref(address)
    }

    #[inline]
    fn code_by_hash_ref(
        &self,
        code_hash: revm::primitives::B256,
    ) -> Result<revm::bytecode::Bytecode, Self::Error> {
        self.0.code_by_hash_ref(code_hash)
    }

    #[inline]
    fn storage_ref(
        &self,
        address: revm::primitives::Address,
        index: revm::primitives::U256,
    ) -> Result<revm::primitives::U256, Self::Error> {
        self.0.storage_ref(address, index)
    }

    #[inline]
    fn block_hash_ref(&self, number: u64) -> Result<revm::primitives::B256, Self::Error> {
        self.0.block_hash_ref(number)
    }
}

/// The speculative outcome of a single transaction, captured for
/// canonical-order validation and merge.
///
/// The parallel executor speculates per-sender groups, then commits
/// each tx at its canonical index position. A `SpecTx` carries
/// everything needed for both paths: the read/write sets that prove
/// (or disprove) the speculation, the merge payload
/// (`write_accounts`, `new_contracts`, `coinbase_delta`) for the
/// fast path, and the flags that force canonical re-execution.
struct SpecTx {
    /// Original position of the tx in the batch.
    idx: usize,
    /// The tx sender (its group's key) — used to exclude same-sender
    /// predecessor writes, which sequential in-group speculation
    /// already observed.
    sender: revm::primitives::Address,
    /// The speculative execution result and call trace.
    result: TracedResult,
    /// Accounts the tx loaded during execution (read or wrote),
    /// excluding the coinbase — tracked separately because every tx
    /// writes it via tips. For the revm path this is `rs.state`'s
    /// keys; for fast paths `{caller, recipient}`.
    reads: std::collections::HashSet<revm::primitives::Address>,
    /// Accounts the tx modified, excluding the coinbase.
    writes: std::collections::HashSet<revm::primitives::Address>,
    /// Post-execution snapshots of `writes` — the merge payload for
    /// a validated tx.
    write_accounts: Vec<(revm::primitives::Address, revm::database::DbAccount)>,
    /// Code entries the tx deployed (CREATE is the only source).
    new_contracts: Vec<(revm::primitives::B256, revm::bytecode::Bytecode)>,
    /// The coinbase balance the tx speculated against — pre-block
    /// balance plus own-group tips. Compared against the canonical
    /// running balance at commit when `coinbase.read` is set.
    coinbase_before: revm::primitives::U256,
    /// Net coinbase balance change the tx produced. Strictly
    /// additive (tips, plus any transfers to the fee recipient), so
    /// it merges correctly regardless of position.
    coinbase_delta: revm::primitives::U256,
    /// How the tx interacted with the block's fee recipient beyond
    /// the strictly additive tip credit — see [`CoinbaseObs`].
    coinbase: CoinbaseObs,
    /// Speculation cannot represent this tx: a mutating native
    /// precompile was suppressed (read-only provider) or a
    /// non-additive coinbase write occurred. The tx must re-execute
    /// against the canonical DB regardless of conflict sets.
    must_reexec: bool,
}

/// How a speculative transaction interacted with the block's fee
/// recipient beyond the strictly additive tip credit.
///
/// Grouped because the three flags describe one concept — the
/// coinbase is special-cased in conflict detection precisely because
/// every tx writes it, so only *non-additive* interaction can
/// invalidate a speculation.
struct CoinbaseObs {
    /// `BALANCE(coinbase)` executed during speculation — the result
    /// may depend on the canonical running tip total.
    read: bool,
    /// The coinbase account was loaded at all — cheap superset of
    /// `read`, used to gate re-execution once the coinbase has been
    /// non-additively modified (`coinbase_dirty`).
    accessed: bool,
    /// The tx changed the coinbase beyond an additive balance delta
    /// (nonce, storage, creation, or destruction — e.g. sender ==
    /// coinbase, or a contract at the fee-recipient address). Such a
    /// change cannot be merged and dirties the coinbase for every
    /// later accessor.
    nontrivial: bool,
}

impl SpecTx {
    /// A record for a tx that failed before touching state
    /// (`build_tx_env` rejection — intrinsic to the tx bytes, so no
    /// ordering dependency exists).
    fn intrinsic_error(idx: usize, sender: revm::primitives::Address, e: ExecError) -> Self {
        Self {
            idx,
            sender,
            result: Err(e),
            reads: std::collections::HashSet::new(),
            writes: std::collections::HashSet::new(),
            write_accounts: Vec::new(),
            new_contracts: Vec::new(),
            coinbase_before: revm::primitives::U256::ZERO,
            coinbase_delta: revm::primitives::U256::ZERO,
            coinbase: CoinbaseObs { read: false, accessed: false, nontrivial: false },
            must_reexec: false,
        }
    }
}

/// The result of executing a single sender group in parallel:
/// one [`SpecTx`] per transaction, in group (nonce) order.
struct GroupExecResult {
    /// Per-tx speculative records, in the order the txs ran
    /// (ascending nonce within the sender).
    spec_txs: Vec<SpecTx>,
}

impl Module for EvmModule {
    fn name(&self) -> &'static str {
        "evm"
    }

    fn id(&self) -> u8 {
        MODULE_ID
    }

    fn begin_block(&self, height: Height) {
        // A6: set the block context for EVM execution. The block number
        // and timestamp are wired into revm's BlockEnv in `execute`.
        //
        // Height-derived timestamp (`h * BLOCK_TIME_SECS`): the
        // deterministic stand-in used when no consensus context is
        // available — direct `begin_block` callers (module-level
        // tests, clockless engines, pre-context journal replay).
        // The production path drives `begin_block_ctx`, which runs
        // this same logic and then overlays the header-committed
        // timestamp, so real blocks always carry consensus time.
        let h = height.value();
        *framework::lock_state(&self.block_height) = h;
        *framework::lock_state(&self.block_timestamp) = h.saturating_mul(BLOCK_TIME_SECS);

        // `touched` is deliberately NOT cleared here: marks made
        // before the first block (genesis `alloc`, preinstalls,
        // assembly-time funding) must survive into block 1's
        // `end_block` flush or genesis state would be committed to
        // the state root yet never persisted — a restart would serve
        // a different account set than the committed root covers.
        // `end_block` clears the set after flushing, so `touched`
        // still means exactly "accounts written since the last
        // durable commit" and stays block-bounded.

        // Start a fresh undo accumulator — any residue here means a
        // previous block never sealed, which is a bug, but dropping
        // it is safer than mixing two blocks' pre-values.
        framework::lock_state(&self.block_undo).accounts.clear();

        // EIP-2935: record the parent block's hash in the
        // history-storage contract's ring buffer. Geth performs this
        // as a gasless system call (caller `SYSTEM_ADDRESS`) at the
        // start of block processing — before any transaction — that
        // stores `parent_hash` at slot `(h-1) % HISTORY_SERVE_WINDOW`.
        // A direct storage write is state-equivalent (the system call
        // produces no transaction, receipt, or log) and is captured
        // into this block's undo like any other write, so historical
        // reads at `h-1` still observe the pre-write slot. Prague
        // gate: a pre-Prague spec must not mutate this storage or the
        // state root diverges from the real fork.
        if h > 0 && self.spec.is_enabled_in(SpecId::PRAGUE) {
            let parent_hash = framework::lock_state(&self.history).block(h - 1).map(|b| b.hash);
            if let Some(parent_hash) = parent_hash {
                let mut db_guard = framework::lock_state(&self.db);
                let db = Arc::make_mut(&mut *db_guard);
                framework::lock_state(&self.block_undo).capture(
                    HISTORY_STORAGE_ADDRESS,
                    db.cache.accounts.get(&HISTORY_STORAGE_ADDRESS),
                );
                let account =
                    db.cache.accounts.entry(HISTORY_STORAGE_ADDRESS).or_insert_with(|| {
                        revm::database::DbAccount {
                            info: revm::database::state::AccountInfo {
                                balance: revm::primitives::U256::ZERO,
                                nonce: 0,
                                code_hash: revm::primitives::KECCAK_EMPTY,
                                account_id: None,
                                code: Some(revm::bytecode::Bytecode::new_raw(
                                    revm::primitives::Bytes::new(),
                                )),
                            },
                            account_state: revm::database::AccountState::Touched,
                            storage: revm::primitives::HashMap::default(),
                        }
                    });
                account.storage.insert(
                    revm::primitives::U256::from((h - 1) % HISTORY_SERVE_WINDOW),
                    revm::primitives::U256::from_be_bytes(parent_hash.0),
                );
                account.account_state = revm::database::AccountState::Touched;
                drop(db_guard);
                framework::lock_state(&self.touched).insert(HISTORY_STORAGE_ADDRESS);
            }
        }
    }

    /// Apply the consensus-committed execution context on top of the
    /// legacy begin: the block timestamp, the fee beneficiary, and
    /// the block gas limit all come from the `FinalizedBlock`'s
    /// recorded context rather than local derivation. Every field
    /// keeps the legacy behavior when the context carries the zero
    /// sentinel — `0` means "no consensus value", never a real
    /// timestamp/beneficiary/limit.
    ///
    /// The full `begin_block` runs first so height bookkeeping, the
    /// undo reset, and the EIP-2935 parent-hash write stay identical
    /// on both paths; the context then overlays the three fields it
    /// actually governs.
    fn begin_block_ctx(&self, height: Height, ctx: &types::BlockContext) {
        self.begin_block(height);
        if ctx.timestamp_ms != 0 {
            // The header stamps milliseconds; `block.timestamp` is
            // seconds-granularity (Ethereum semantics) — truncate.
            *framework::lock_state(&self.block_timestamp) = ctx.timestamp_secs();
        }
        if ctx.beneficiary != primitives::Address::ZERO {
            // The proposer's staking address is the fee recipient:
            // priority-fee tips land with the validator that built
            // the block, matching every other module's identity
            // space (the attendance `signers` use the same set).
            *framework::lock_state(&self.coinbase) =
                revm::primitives::Address::from(ctx.beneficiary.0);
        }
        if ctx.gas_limit != 0 {
            // Consensus is the authority on block capacity: the
            // budget the block was produced under becomes the limit
            // revm enforces and the EIP-1559 target derives from.
            self.block_gas_limit.store(ctx.gas_limit, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Seal the block, then advance the EIP-1559 base fee for the
    /// next block from this block's measured gas usage.
    ///
    /// Ordering matters: `end_block` seals the history record with
    /// the fee this block was *executed under* (Ethereum semantics —
    /// `block.baseFee` describes the block itself), so the update
    /// runs strictly after sealing. `gas_used` comes back from the
    /// sealed record — the same number `eth_getBlock` reports — so
    /// the fee transition and the observable block always agree.
    ///
    /// A zero `ctx.gas_limit` keeps the running `max_gas`; a nonzero
    /// one re-targets the fee curve to the consensus-enforced limit
    /// (a governance block-budget change moves the fee with it).
    fn end_block_ctx(&self, height: Height, ctx: &types::BlockContext) -> Vec<Event> {
        self.end_block(height);
        let gas_used = {
            let history = framework::lock_state(&self.history);
            history.block(height.value()).map(|b| b.gas_used)
        };
        // The sealed block is written by `end_block` immediately
        // before this — `None` would mean sealing never ran, in
        // which case there is no measured usage to update from and
        // the fee must stay put rather than drift toward the floor.
        if let Some(gas_used) = gas_used {
            let mut fee_state = framework::lock_state(&self.fee_state);
            if ctx.gas_limit != 0 && ctx.gas_limit != fee_state.max_gas() {
                fee_state.set_max_gas(ctx.gas_limit);
            }
            fee_state.update(gas_used);
        }
        Vec::new()
    }

    /// A4: validate a signed EVM transaction for mempool admission.
    ///
    /// This is the admission gate. It runs on every submitted tx
    /// *before* the tx enters the mempool. It checks:
    ///
    /// 1. **RLP decode** — the message must be a valid RLP-encoded
    ///    signed transaction (Legacy, EIP-2930, or EIP-1559).
    /// 2. **Chain ID** — must match the module's chain ID (EIP-155
    ///    replay protection).
    /// 3. **Signature** — the secp256k1 signature must recover to a
    ///    valid sender address.
    /// 4. **Nonce** — the tx nonce must be ≥ the sender's current
    ///    account nonce (rejects stale txs; allows future nonces for
    ///    mempool queueing).
    /// 5. **Gas limit** — must be positive and within block limits.
    /// 6. **Intrinsic gas** — the gas limit must cover the tx's
    ///    intrinsic cost (21k base + calldata + access list).
    /// 7. **Balance** — the sender must have enough balance to cover
    ///    the gas cost (`gas_limit * max_fee_per_gas`) plus the
    ///    transferred value.
    ///
    /// This method is pure: it reads module state but does not mutate
    /// it. A tx that passes `validate` may still fail in `handle`
    /// (e.g. out-of-gas, revert). But a tx that fails `validate`
    /// never reaches `handle`.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::Malformed`] for RLP decode failures,
    /// wrong chain ID, or signature recovery failure. Returns
    /// [`ExecError::ModuleRejected`] for nonce, gas, or balance
    /// violations.
    fn validate(&self, _ctx: &TxContext, msg: &[u8]) -> Result<(), ExecError> {
        // 1. RLP decode — `decode_raw` enforces complete input
        // consumption: the trust boundary is exactly as strict as
        // the RPC parse, so a trailing-junk encoding that RPC
        // rejects can't enter through the mempool/executor path.
        let signed = tx::SignedTx::decode_raw(msg).map_err(|_| ExecError::Malformed)?;

        // 2. Chain ID (EIP-155 replay protection).
        if signed.chain_id() != self.chain_id {
            return Err(ExecError::Malformed);
        }

        // 3. Signature recovery.
        let sender = signed.recover_sender().map_err(|_| ExecError::Malformed)?;
        let sender_addr = Address(sender.0);

        // 4. Nonce: tx nonce must be ≥ current account nonce.
        //    This rejects stale (already-used) nonces. Future nonces
        //    are allowed for mempool queueing.
        let current_nonce = self.nonce(&sender_addr);
        if signed.nonce() < current_nonce {
            return Err(ExecError::ModuleRejected(format!(
                "nonce {nonce} < current {current_nonce}",
                nonce = signed.nonce()
            )));
        }

        // 5. Gas limit: must be positive.
        let gas_limit = signed.gas_limit();
        if gas_limit == 0 {
            return Err(ExecError::ModuleRejected("gas_limit is zero".to_string()));
        }

        // HIGH fix: gas_limit must fit within the block gas limit.
        // A tx with gas_limit > block_gas_limit can never be included
        // and should be rejected at admission to save mempool space.
        if gas_limit > self.block_gas_limit() {
            return Err(ExecError::ModuleRejected(format!(
                "gas_limit {gas_limit} > block_gas_limit {}",
                self.block_gas_limit()
            )));
        }

        // 6. Intrinsic gas: gas_limit must cover the intrinsic cost.
        //    The intrinsic cost is 21_000 (base) + calldata cost
        //    (16/byte for non-zero, 4/byte for zero) + access list
        //    cost. We use a conservative lower bound of 21_000 here;
        //    the full calldata-aware check arrives with the gas
        //    economics phase (A5).
        if gas_limit < INTRINSIC_GAS_BASE {
            return Err(ExecError::ModuleRejected(format!(
                "gas_limit {gas_limit} < intrinsic {INTRINSIC_GAS_BASE}"
            )));
        }

        // HIGH fix: EIP-1559 fee gates.
        //   a. max_fee >= base_fee: a tx with max_fee < base_fee
        //      can never be included (revm rejects it during
        //      execution). Reject at admission to save resources.
        //   b. priority_fee <= max_fee: EIP-1559 requires
        //      max_priority_fee_per_gas <= max_fee_per_gas. A tx
        //      with priority_fee > max_fee is invalid.
        let max_fee = u128::try_from(signed.max_fee_per_gas())
            .map_err(|_| ExecError::ModuleRejected("max_fee overflow u128".to_string()))?;
        let priority_fee = u128::try_from(signed.max_priority_fee_per_gas())
            .map_err(|_| ExecError::ModuleRejected("priority_fee overflow u128".to_string()))?;
        if max_fee < u128::from(self.current_base_fee()) {
            return Err(ExecError::ModuleRejected(format!(
                "max_fee {max_fee} < base_fee {}",
                self.current_base_fee()
            )));
        }
        if priority_fee > max_fee {
            return Err(ExecError::ModuleRejected(format!(
                "priority_fee {priority_fee} > max_fee {max_fee}"
            )));
        }

        // 7. Balance: sender must cover gas_cost + value.
        //    gas_cost = gas_limit * max_fee_per_gas (the worst-case
        //    fee the sender could pay). For legacy txs, gas_price is
        //    the max fee. For EIP-1559, max_fee_per_gas is the cap.
        let balance = self.balance(&sender_addr);
        let value = u128::try_from(signed.value())
            .map_err(|_| ExecError::ModuleRejected("value overflow u128".to_string()))?;
        // gas_cost = gas_limit * max_fee, checked for overflow.
        let gas_cost = u128::from(gas_limit)
            .checked_mul(max_fee)
            .ok_or_else(|| ExecError::ModuleRejected("gas cost overflow".to_string()))?;
        let total_needed = gas_cost
            .checked_add(value)
            .ok_or_else(|| ExecError::ModuleRejected("gas_cost + value overflow".to_string()))?;
        if balance < total_needed {
            return Err(ExecError::ModuleRejected(format!(
                "insufficient balance: have {balance}, need {total_needed}"
            )));
        }

        Ok(())
    }

    /// The EVM is self-funded: revm charges `gas_used × effective
    /// gas price` from the sender's account inside execution,
    /// bounded below by the block base fee (`GasPriceLessThanBasefee`
    /// rejects under-priced txs). Charging the envelope fee on top
    /// would double-charge every EVM user.
    fn pays_own_fee(&self) -> bool {
        true
    }

    /// The durable schema version this binary writes (`0x04` meta
    /// namespace). Bump when the on-disk account/history/undo
    /// encoding or cache layout changes in a way that needs a
    /// migration step; leave `migrate` to fill it in.
    fn state_version(&self) -> u32 {
        1
    }

    /// Charge the envelope fee from the sender's EVM balance. When
    /// the node configured a `fee_recipient` (the staking module's
    /// `FEE_POOL` in production wiring) the fee is *collected* —
    /// transferred to the pool for `end_block` distribution to
    /// validators and delegators. Without a recipient the fee is
    /// **burned** (debited, credited to nobody), matching
    /// Ethereum's base-fee semantics — the operator's policy choice.
    ///
    /// `ctx.fee` is in `u64` base units; the `Balances` impl
    /// converts to wei at [`WEI_PER_UNIT`](framework::WEI_PER_UNIT).
    /// Zero-fee txs skip the ledger touch entirely (fresh senders
    /// with `fee = 0` succeed without an account record — same
    /// admission behavior the old bank fee module had).
    fn charge_fee(&self, ctx: &TxContext) -> Result<(), ExecError> {
        if ctx.fee == 0 {
            return Ok(());
        }
        if let Some(recipient) = self.fee_recipient {
            self.transfer(&ctx.sender, &recipient, ctx.fee)
        } else {
            self.debit(&ctx.sender, ctx.fee)
        }
    }

    /// The EVM is self-authenticating: the sender is recovered from
    /// the secp256k1 signature inside the RLP transaction, so the
    /// envelope's declared `sender` is a mempool-ordering hint only.
    /// An envelope signature (`SIGNED_FLAG`) on an EVM tx is rejected
    /// as malformed — it would shift the payload offset and add a
    /// redundant recovery on top of the RLP's own verification.
    fn authenticates_sender(&self) -> bool {
        true
    }

    /// Gas estimate = the tx's declared `gas_limit`, decoded from
    /// the RLP payload. The default `1000 + len` proxy would let a
    /// tx with a 30M gas limit count as ~150 gas and blow through
    /// the block limit at execution time — the block gas limit must
    /// be enforced against *declared* limits (EIP-1559 semantics:
    /// `sum(tx.gas_limit) <= block.gas_limit`).
    ///
    /// An undecodable tx counts as `u64::MAX`: it cannot carry a
    /// valid gas limit, so any proposal containing it exceeds the
    /// limit and is rejected at `process_proposal` — the safe
    /// direction.
    fn estimate_gas(&self, msg: &[u8]) -> u64 {
        // `decode_raw` (exact-consumption): a tx with trailing junk
        // is undecodable here too, so its proposal is rejected at
        // `process_proposal` — the same treatment the RPC path gives.
        match tx::SignedTx::decode_raw(msg) {
            Ok(signed) => signed.gas_limit(),
            Err(_) => u64::MAX,
        }
    }

    fn handle(&self, _ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        // Perf: single RLP decode. Decode once to get both the tx
        // type (for the receipt) and the signed tx (for execution).
        // The old code decoded twice — once in handle() for the tx
        // type, once in execute() for execution. The decode is
        // ~1 µs, so this saves ~1 µs per tx on the cold path.
        let signed = tx::SignedTx::decode_raw(msg).map_err(|_| ExecError::Malformed)?;
        let tx_type = signed.tx_type();
        // The canonical Ethereum tx hash is keccak256 of the raw
        // RLP — the same value `eth_sendRawTransaction` returns.
        let tx_hash = alloy_primitives::keccak256(msg);
        let (result, caller, call_trace) = self.execute_signed(&signed)?;

        // Phase C: build a receipt from the execution result.
        // The receipt captures status, gas used, logs, bloom, and
        // (for CREATE) the created address. This is the data that
        // `eth_getTransactionReceipt` returns and that goes into the
        // block's receipts trie.
        let receipt = receipts::Receipt::from_execution_result(&result, tx_type);

        // Record into the executed-block history for RPC queries
        // (`eth_getTransactionByHash`, `eth_getTransactionReceipt`,
        // `eth_getLogs`). `record` assigns the tx_index from the
        // pending-block position; `msg` (the raw signed RLP) is kept
        // until `seal_block` computes `transactionsRoot`.
        framework::lock_state(&self.history).record(
            history::stored_tx(&signed, caller, tx_hash, 0),
            receipt.clone(),
            msg,
            call_trace,
        );

        let status_str = if receipt.status { "success" } else { "revert" };
        let contract_info =
            receipt.contract_address.map(|a| format!(" contract={a}")).unwrap_or_default();
        let log_count = receipt.logs.len();

        Ok(vec![Event {
            module: "evm",
            kind: "evm_call",
            data: format!(
                "gas_used={} status={} base_fee={} logs={}{}",
                receipt.gas_used,
                status_str,
                self.current_base_fee(),
                log_count,
                contract_info
            )
            .into_bytes(),
        }])
    }

    /// Batch execution: delegate to the inherent `handle_batch` which
    /// recovers senders in parallel via rayon and uses the native fast
    /// path for simple transfers.
    ///
    /// The `ctx` (sender, nonce, fee) from the tx envelope is ignored
    /// — the EVM recovers the sender from the secp256k1 signature in
    /// the RLP-encoded payload. The envelope's sender/nonce/fee fields
    /// exist only for the mempool's v0 format compatibility.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch(&self, msgs: &[(TxContext, &[u8])]) -> Vec<Result<Vec<Event>, ExecError>> {
        // Borrow the raw RLP bytes from each (ctx, payload) pair —
        // no per-tx clone. The payload IS the RLP-encoded signed
        // transaction.
        let raw_txs: Vec<&[u8]> = msgs.iter().map(|(_, payload)| *payload).collect();
        let ctx = TxContext { sender: primitives::Address([0u8; 20]), nonce: 0, fee: 0 };
        // Call the inherent `handle_batch` (2 args: ctx, msgs) — Rust
        // resolves to the inherent method, not the trait method (1 arg)
        // because the signatures differ.
        self.handle_batch(&ctx, &raw_txs)
    }

    /// Pre-recover senders from RLP-encoded signed EVM transactions.
    ///
    /// Delegates to the inherent `preverify_batch` which uses rayon
    /// to parallelize secp256k1 recovery across cores. The
    /// pre-recovered senders are cached by the executor and reused
    /// at block execution time to skip recovery entirely.
    ///
    /// # Errors
    ///
    /// Returns `Err(ExecError::Malformed)` for each transaction
    /// that cannot be RLP-decoded, has a wrong chain ID, or whose
    /// signature is invalid.
    fn preverify_batch<'a>(
        &self,
        msgs: &'a [&'a [u8]],
    ) -> Vec<Result<executor::PreverifiedTx<'a>, ExecError>> {
        // Delegate to the inherent `preverify_batch` (which returns
        // `evm::PreverifiedTx` borrowing from `msgs`) and convert to
        // the executor's `PreverifiedTx` (which uses a generic
        // `[u8; 20]` sender). The borrow propagates — zero clones.
        let results = EvmModule::preverify_batch(self, msgs);
        results
            .into_iter()
            .map(|r| {
                r.map(|pv| executor::PreverifiedTx { raw: pv.raw, sender: pv.sender.into_array() })
            })
            .collect()
    }

    /// Execute a batch of pre-verified EVM transactions (serial).
    ///
    /// Delegates to the inherent `handle_batch_preverified` which
    /// skips secp256k1 recovery entirely — only RLP decoding and
    /// chain ID validation remain. This is the highest-throughput
    /// serial execution path.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch_preverified(
        &self,
        ctxs: &[TxContext],
        txs: &[executor::PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // The per-tx envelope contexts are unused — the EVM recovers
        // each sender from the transaction's own secp256k1 signature
        // and verifies it against `pv.sender`. A zero ctx (same
        // convention as `handle_batch` above) makes the ignoring
        // explicit rather than passing an arbitrary tx's context.
        let ctx = TxContext { sender: primitives::Address([0u8; 20]), nonce: 0, fee: 0 };
        let _ = ctxs;
        // Convert the executor's `PreverifiedTx` (generic [u8; 20]
        // sender) to the EVM's `PreverifiedTx` (revm Address sender).
        // The raw bytes stay borrowed — no per-tx clone.
        let evm_txs: Vec<PreverifiedTx<'_>> = txs
            .iter()
            .map(|pv| PreverifiedTx {
                raw: pv.raw,
                sender: revm::primitives::Address::from(pv.sender),
            })
            .collect();
        // Call the inherent `handle_batch_preverified` (3 args).
        EvmModule::handle_batch_preverified(self, &ctx, &evm_txs)
    }

    /// Execute a batch of pre-verified EVM transactions in parallel.
    ///
    /// Delegates to the inherent `handle_batch_parallel_preverified`
    /// which groups transactions by sender and executes each group on
    /// a separate rayon thread. Results are merged in original block
    /// order.
    ///
    /// # Errors
    ///
    /// Individual transactions may fail independently. A failed
    /// transaction does not abort the batch.
    fn handle_batch_parallel_preverified(
        &self,
        ctxs: &[TxContext],
        txs: &[executor::PreverifiedTx<'_>],
    ) -> Vec<Result<Vec<Event>, ExecError>> {
        // Same convention as `handle_batch_preverified`: envelope
        // contexts are unused — senders come from the signatures.
        let ctx = TxContext { sender: primitives::Address([0u8; 20]), nonce: 0, fee: 0 };
        let _ = ctxs;
        // Convert the executor's `PreverifiedTx` to the EVM's.
        // The raw bytes stay borrowed — no per-tx clone.
        let evm_txs: Vec<PreverifiedTx<'_>> = txs
            .iter()
            .map(|pv| PreverifiedTx {
                raw: pv.raw,
                sender: revm::primitives::Address::from(pv.sender),
            })
            .collect();
        // Call the inherent `handle_batch_parallel_preverified` (3 args).
        EvmModule::handle_batch_parallel_preverified(self, &ctx, &evm_txs)
    }

    fn end_block(&self, height: Height) -> Vec<Event> {
        // Seal the executed-block history for RPC queries. Every
        // block seals an entry — including blocks with zero EVM txs —
        // so `eth_getBlockByNumber` can distinguish "empty block" from
        // "unknown block".
        //
        // `state_root` is computed incrementally (O(touched · log n)
        // via the sparse retained-trie walk). The executor calls
        // `state_root` again right after `end_block` for the block
        // attestation; clearing `touched` after computing lets that
        // second call hit the O(1) cached fast path
        // (`leaves_ready && touched.is_empty()`), so sealing adds no
        // extra trie work per block.
        let root = self.state_root();
        let timestamp = *framework::lock_state(&self.block_timestamp);
        let coinbase = *framework::lock_state(&self.coinbase);
        let (sealed_block, evicted) = {
            let mut history = framework::lock_state(&self.history);
            let evicted = history.seal_block(
                height.value(),
                timestamp,
                self.block_gas_limit(),
                self.current_base_fee(),
                coinbase,
                alloy_primitives::B256::from(root.0),
            );
            // Clone the sealed record for persistence — the clone is
            // once per block (cold path) and keeps the backend write
            // off the history lock's critical section.
            let sealed = history.block(height.value()).cloned();
            (sealed, evicted)
        };

        // Fold the block's captured pre-values into the versioned
        // index, then prune it to the same retention window as
        // `history` so the two stay aligned. Reads at heights below
        // the floor fail closed ("state not available") — see
        // `versioned.rs`.
        let undo = std::mem::take(&mut *framework::lock_state(&self.block_undo));
        // Serialize the undo blob only when a backend will consume
        // it — pointless work otherwise (per-block, cold path, but
        // free is better).
        let has_backend = framework::lock_state(&self.backend).is_some();
        let undo_blob = has_backend.then(|| persist::serialize_undo(&undo));
        let pruned_undo = {
            let mut versioned = framework::lock_state(&self.versioned);
            versioned.push(height.value(), undo);
            let history = framework::lock_state(&self.history);
            history.blocks_floor().map_or_else(Vec::new, |floor| versioned.prune_below(floor))
        };

        // If a StorageBackend is attached, flush accounts + the
        // sealed block record + the undo blob in ONE `apply_batch`.
        // Atomicity matters: a crash between the account flush and
        // the history write would otherwise leave durable state at
        // height N with durable history at N-1 — on restart the node
        // would then serve state-N answers labelled as height N-1.
        let mut backend_guard = framework::lock_state(&self.backend);
        if let Some(ref mut backend) = *backend_guard {
            let mut ops = self.account_flush_ops();
            if let Some(block) = sealed_block {
                ops.push(storage::Op::Set {
                    key: persist::block_key(height.value()),
                    value: persist::serialize_block(&block),
                });
            }
            if let Some(blob) = undo_blob {
                ops.push(storage::Op::Set { key: persist::undo_key(height.value()), value: blob });
            }
            // `evicted` (history window) and `pruned_undo` (undo
            // window) cover the same heights — the two indexes are
            // kept aligned — but they namespace different keys.
            for h in evicted {
                ops.push(storage::Op::Delete { key: persist::block_key(h) });
            }
            for h in pruned_undo {
                ops.push(storage::Op::Delete { key: persist::undo_key(h) });
            }
            // `end_block` cannot return an error (the `Module` trait
            // is infallible), so the flush goes through the pending
            // buffer: a failed batch keeps its ops queued for the
            // next block's retry instead of silently dropping the
            // block's state + history writes. The failure is latched
            // into `storage_error` for node health checks.
            let _ = self.flush_pending(backend.as_mut(), ops);
        }
        drop(backend_guard);

        framework::lock_state(&self.touched).clear();
        Vec::new()
    }

    #[allow(clippy::too_many_lines)]
    fn state_root(&self) -> Hash {
        // Phase B: compute the Ethereum-compatible Merkle-Patricia
        // Trie state root over all accounts in the CacheDB.
        //
        // The state trie is keyed by keccak256(address) with the
        // RLP-encoded `TrieAccount { nonce, balance, storage_root,
        // code_hash }` as the value. Each account's `storage_root`
        // is computed from its individual storage trie (keyed by
        // keccak256(slot)).
        //
        // # Incremental storage root cache
        //
        // The dominant cost of `state_root` is per-account storage
        // root computation (O(storage_size) per account). We cache
        // each account's storage root and only recompute it for
        // accounts in the `touched` set. This turns the per-block
        // cost from O(total_storage) to O(touched_storage +
        // total_accounts) — the trie assembly is still O(n) but
        // the storage root computation (the expensive part) is
        // incremental.
        //
        // # Panics
        //
        // Panics if the DB mutex is poisoned (a thread panicked while
        // holding the lock). This is unrecoverable and indicates a bug.
        let touched = framework::lock_state(&self.touched);
        let mut leaves = framework::lock_state(&self.trie_leaves);
        let mut leaves_ready = framework::lock_state(&self.trie_leaves_ready);
        let mut retained = framework::lock_state(&self.retained_branches);

        // Fast path: if the leaf map is built and nothing was
        // touched since the last computation, return the cached
        // root. This makes consecutive `state_root` calls with no
        // intervening execution O(1).
        if *leaves_ready
            && touched.is_empty()
            && let Some(cached) = *framework::lock_state(&self.cached_state_root)
        {
            return Hash(cached.0);
        }

        let db = framework::lock_state(&self.db);
        let mut storage_root_cache = framework::lock_state(&self.storage_root_cache);

        if *leaves_ready {
            // Incremental patch — only `touched` accounts are
            // re-encoded. `touched` is the complete modified set
            // (populated from `EvmState::keys()` post-commit), so
            // every changed account is patched; accounts absent
            // from the cache were removed from state.
            for addr in touched.iter() {
                let hashed = alloy_primitives::keccak256(addr);
                // `NotExisting` tombstones (selfdestruct, or a revm
                // `basic()` miss cached as absent) are NOT part of the
                // state trie — committing them as leaves would put the
                // root ahead of persisted state, which never carries
                // them (flush emits `Delete`). Two nodes that read a
                // missing account on different paths would then
                // compute different roots from identical state.
                if let Some(account) = db
                    .cache
                    .accounts
                    .get(addr)
                    .filter(|a| a.account_state != revm::database::AccountState::NotExisting)
                {
                    let storage_root = if account.storage.is_empty() {
                        trie::EMPTY_ROOT
                    } else {
                        // Touched → always recompute the
                        // storage root (its slots changed).
                        let storage_iter = account.storage.iter().map(|(slot, value)| {
                            (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                        });
                        let root = trie::storage_root(storage_iter);
                        storage_root_cache.insert(*addr, root);
                        root
                    };
                    leaves.insert(hashed, encode_trie_leaf(account, storage_root));
                } else {
                    leaves.remove(&hashed);
                    storage_root_cache.remove(addr);
                }
            }
        } else {
            // Full build — first call after construction or
            // `import_state`. Hashes and encodes every account once
            // (same cost as the old path); subsequent calls patch
            // only `touched` accounts. `NotExisting` tombstones are
            // skipped — they are not part of the committed trie (see
            // the incremental path above).
            for (addr, account) in &db.cache.accounts {
                if account.account_state == revm::database::AccountState::NotExisting {
                    continue;
                }
                let storage_root = if account.storage.is_empty() {
                    trie::EMPTY_ROOT
                } else if touched.contains(addr) {
                    // Recompute for touched accounts.
                    let storage_iter = account.storage.iter().map(|(slot, value)| {
                        (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                    });
                    let root = trie::storage_root(storage_iter);
                    storage_root_cache.insert(*addr, root);
                    root
                } else {
                    // Reuse cached storage root for untouched accounts.
                    storage_root_cache.get(addr).copied().unwrap_or_else(|| {
                        let storage_iter = account.storage.iter().map(|(slot, value)| {
                            (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                        });
                        let root = trie::storage_root(storage_iter);
                        storage_root_cache.insert(*addr, root);
                        root
                    })
                };
                leaves.insert(
                    alloy_primitives::keccak256(addr),
                    encode_trie_leaf(account, storage_root),
                );
            }
            *leaves_ready = true;
            // Clear retained branches on full rebuild — the trie
            // structure changed entirely.
            retained.clear();
        }

        // Ceiling 3: Sparse retained trie for O(touched · log n)
        // state root computation.
        //
        // The state root computation has three costs:
        // 1. Per-account storage root computation — O(storage_size)
        //    per account. Already incremental: only touched accounts
        //    recompute their storage roots (via `storage_root_cache`).
        // 2. Per-account leaf encoding — O(1) per account. Already
        //    incremental: only touched accounts are re-encoded in
        //    the `trie_leaves` BTreeMap.
        // 3. HashBuilder trie assembly — was O(n) over all leaves.
        //    Now O(touched · log n) via the sparse walk below.
        //
        // # Sparse walk algorithm
        //
        // After the first full build, `retained_branches` holds every
        // branch node's `BranchNodeCompact` (masks + child hashes),
        // keyed by nibble prefix. On subsequent calls, instead of
        // feeding all N leaves into `HashBuilder`, we walk the
        // retained branch tree depth-first:
        //
        // - For each branch node at prefix P, iterate its children
        //   (the set bits in `state_mask`).
        // - For a child at P+n that contains NO touched account:
        //   call `add_branch(P+n, child_hash, true)` — the entire
        //   subtree is skipped (O(1)).
        // - For a child that DOES contain touched accounts:
        //   - If the child is a stored branch (in `tree_mask` and
        //     present in `retained_branches`), recurse.
        //   - Otherwise (inline leaf/extension, or a shallow branch
        //     not in `retained_branches`), feed all leaves under
        //     that child prefix from `trie_leaves` (at most 16 for
        //     a shallow branch; O(1) for a leaf).
        //
        // The total work is O(touched · depth · 16) = O(touched ·
        // log n): at each of the ~log n levels, we visit at most 16
        // children per touched path, and each untouched child is
        // skipped in O(1) via `add_branch`.
        //
        // After the build, `HashBuilder::split()` returns the
        // rebuilt branch nodes. For the full build, these replace
        // `retained_branches` entirely. For the incremental build,
        // we first remove stale entries on the touched path (prefixes
        // of touched hashed keys that were in `retained_branches`),
        // then merge the new `BranchNodeCompact`s — this correctly
        // handles account insertions (new branches) and deletions
        // (branches that become leaves/extensions and are no longer
        // in the `split()` output).
        //
        // # `with_updates(true)` overhead
        //
        // Enabling update tracking adds a constant factor to each
        // branch node construction. For the full build this is a
        // one-time O(n) cost. For the incremental build the overhead
        // is O(touched · log n) — negligible compared to the savings.
        //
        // # Edge cases
        //
        // - Empty state (zero accounts): `retained_branches` is
        //   empty; the full-build path feeds zero leaves and returns
        //   `EMPTY_ROOT`.
        // - Single account: no branch nodes, `retained_branches` is
        //   empty; the sparse walk falls back to feeding all leaves
        //   (O(1)).
        // - Root is an extension (rare with keccak256 keys):
        //   `retained_branches[empty]` doesn't exist; we fall back to
        //   feeding all leaves for that call, and `split()` repopulates
        //   `retained_branches` for the next call.
        let mut hb = alloy_trie::HashBuilder::default().with_updates(true);

        let is_full_build = !*leaves_ready;
        let can_sparse = !is_full_build && !retained.is_empty();

        if can_sparse {
            // Sparse incremental walk — O(touched · log n).
            let touched_hashes: std::collections::BTreeSet<alloy_primitives::B256> =
                touched.iter().map(alloy_primitives::keccak256).collect();
            sparse_walk(
                alloy_trie::Nibbles::default(),
                &retained,
                &leaves,
                &touched_hashes,
                &mut hb,
            );
        } else {
            // Full build (or fallback when no retained branches):
            // feed every leaf in sorted hashed-key order.
            for (hashed_key, rlp) in leaves.iter() {
                hb.add_leaf(alloy_trie::Nibbles::unpack(hashed_key), rlp);
            }
        }

        let root = hb.root();
        let (_, branch_updates) = hb.split();

        if is_full_build {
            // Full build: replace the entire retained map.
            // `split()` returns `alloy_primitives::map::HashMap`
            // (hashbrown, DefaultHashBuilder); convert to the std
            // HashMap used by `retained_branches`.
            *retained = branch_updates.into_iter().collect();
        } else {
            // Incremental build: remove stale branches on the
            // touched path, then merge the rebuilt branches.
            // A branch is "on the touched path" if its nibble
            // prefix is a prefix of any touched hashed key. We
            // check all 64 prefix lengths per touched key; only
            // prefixes that exist in `retained` are removed.
            for addr in touched.iter() {
                let hashed = alloy_primitives::keccak256(addr);
                let nibbles = alloy_trie::Nibbles::unpack(hashed);
                for len in 0..nibbles.len() {
                    let prefix = nibbles.slice(..len);
                    retained.remove(&prefix);
                }
            }
            for (prefix, node) in branch_updates {
                retained.insert(prefix, node);
            }
        }

        // Cache the state root for the next call's fast path.
        *framework::lock_state(&self.cached_state_root) = Some(root);

        // Convert the alloy B256 root to Oxide's Hash type.
        Hash(root.0)
    }

    /// Export the EVM's committed state for snapshot sync.
    ///
    /// Returns `Some(snapshot)` if a `StorageBackend` is attached,
    /// `None` otherwise.
    ///
    /// The committed `state_root` covers the whole `CacheDB` account
    /// set — which can run ahead of the backend (genesis-funded and
    /// preinstalled accounts, for example, sit in the cache until the
    /// first `end_block` flush). A snapshot built from the backend
    /// alone would then be unable to reproduce the claimed root
    /// (audit 3.2). So the `0x01` account entries are serialized from
    /// the authoritative cache via the same
    /// [`Self::serialize_committed_account`] the flush uses, while the
    /// `0x02`/`0x03`/`0x04` namespaces (sealed history, undo window,
    /// schema meta — RPC data, not committed to the trie) are copied
    /// from the backend verbatim.
    fn export_state(&self) -> Option<storage::Snapshot> {
        let backend = framework::lock_state(&self.backend);
        let mut snap = backend.as_ref()?.snapshot_export();
        // Drop the backend's account entries — the cache is
        // authoritative for committed state and may hold accounts
        // the backend has not seen yet.
        snap.entries.retain(|(k, _)| k.0[0] != persist::NS_ACCOUNT);
        let db = framework::lock_state(&self.db);
        snap.entries.reserve(db.cache.accounts.len());
        for evm_addr in db.cache.accounts.keys() {
            if let Some(value) = Self::serialize_committed_account(evm_addr, &db) {
                let key = persist::account_key(&Address(evm_addr.0.into()));
                snap.entries.push((key, value));
            }
        }
        drop(db);
        drop(backend);
        // The cache merge broke the backend's ascending key order —
        // `Snapshot` requires strictly sorted entries (verified by
        // `snapshot_import` and `parse_snapshot_entries`).
        snap.entries.sort_unstable_by_key(|e| e.0);
        Some(snap)
    }

    /// Verify a staged snapshot without mutating: strictly parse
    /// every entry by namespace, rebuild the account set in a
    /// scratch map, and recompute the Ethereum MPT root the same way
    /// `state_root`'s full-build path does. The returned root is
    /// checked against the snapshot's claimed module root — bytes
    /// that don't reproduce it never reach the backend (audit 3.2).
    ///
    /// The `0x02`/`0x03`/`0x04` namespaces (sealed blocks, undo
    /// blobs, schema meta) are RPC-window data — not committed to
    /// the account trie — but they are still schema-validated so a
    /// malformed record can't be installed silently.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let accounts = Self::parse_snapshot_entries(snapshot)?;
        // Rebuild the state trie from the staged accounts — the
        // same keying (keccak256(addr)) and leaf RLP as the live
        // `state_root` full-build path.
        let iter = accounts.iter().map(|(addr, acct)| {
            let storage_root = if acct.storage.is_empty() {
                trie::EMPTY_ROOT
            } else {
                trie::storage_root(acct.storage.iter().map(|(slot, value)| {
                    (alloy_primitives::B256::from_slice(&slot.to_be_bytes::<32>()), *value)
                }))
            };
            (
                alloy_primitives_address(addr.0),
                trie::build_trie_account(acct.nonce, acct.balance, storage_root, acct.code_hash),
            )
        });
        Ok(Hash(trie::state_root(iter).0))
    }

    /// Import a key-value snapshot, restoring the EVM's state.
    ///
    /// The snapshot is strictly re-validated before the backend is
    /// touched — `import_state` must never trust a prior inspection
    /// to have happened.
    ///
    /// Flushes the current in-memory state to the backend first, then
    /// replaces the backend's state with the snapshot, then reloads
    /// the in-memory cache from the backend.
    ///
    /// Returns `Ok(())` on success, or an error if the backend is
    /// not attached or the import fails.
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        // Strict structural validation before any mutation — the
        // executor's verify-then-mutate contract depends on
        // `inspect_state`, but `import_state` must not blindly trust
        // it ran (same pattern as the blob modules' re-staging).
        Self::parse_snapshot_entries(snapshot)?;
        // Flush the current state to the backend first (so we don't
        // lose any pending changes — though in practice, import
        // happens before consensus starts, so there are no pending
        // changes).
        {
            let mut backend = framework::lock_state(&self.backend);
            if let Some(ref mut b) = *backend {
                self.flush_to_storage(b.as_mut())
                    .map_err(|_| storage::SnapshotError::BackendError)?;
                b.snapshot_import(snapshot.clone())?;
            } else {
                return Err(storage::SnapshotError::BackendError);
            }
        }
        // Reload the in-memory cache from the backend.
        let mut backend = framework::lock_state(&self.backend);
        if let Some(ref mut b) = *backend {
            self.load_from_storage(b.as_mut());
        }
        // The account set was wholesale replaced — the incremental
        // leaf map, retained branches, root cache, and any pending
        // `touched` marks all describe pre-import state. Reset them:
        // the next `state_root` rebuilds from scratch and the next
        // `end_block` flush must not re-emit ops for accounts the
        // snapshot already installed.
        *framework::lock_state(&self.trie_leaves_ready) = false;
        framework::lock_state(&self.trie_leaves).clear();
        framework::lock_state(&self.retained_branches).clear();
        *framework::lock_state(&self.cached_state_root) = None;
        framework::lock_state(&self.touched).clear();
        Ok(())
    }
}

impl EvmModule {
    /// Strictly parse a snapshot's entries, returning the staged
    /// account set keyed by address.
    ///
    /// Enforces, before any state is touched:
    ///
    /// - `Snapshot.entries` sorted ascending with no duplicate keys
    ///   (the `Snapshot` contract — verified, not assumed).
    /// - `0x01` account keys in canonical form
    ///   (`[0x01][addr:20][0x00:11]` — the zero padding matters: a
    ///   key with non-zero tail bytes would alias the same address
    ///   under a second encoding) and values that satisfy
    ///   [`persist::deserialize_account_strict`].
    /// - `0x02` block records / `0x03` undo blobs: canonical key
    ///   padding and a fully-parsing value (RPC-window data — not
    ///   committed to the trie, but malformed records must not be
    ///   installed).
    /// - `0x04`: exactly the schema-version slot with a 4-byte value.
    /// - Any other namespace byte is rejected outright.
    fn parse_snapshot_entries(
        snapshot: &storage::Snapshot,
    ) -> Result<
        std::collections::BTreeMap<Address, persist::DeserializedAccount>,
        storage::SnapshotError,
    > {
        if snapshot.entries.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(storage::SnapshotError::Malformed);
        }
        let mut accounts = std::collections::BTreeMap::new();
        for (key, value) in &snapshot.entries {
            match key.0[0] {
                persist::NS_ACCOUNT => {
                    if key.0[21..].iter().any(|b| *b != 0) {
                        return Err(storage::SnapshotError::Malformed);
                    }
                    let addr =
                        persist::key_to_address(key).ok_or(storage::SnapshotError::Malformed)?;
                    let acct = persist::deserialize_account_strict(value)
                        .ok_or(storage::SnapshotError::Malformed)?;
                    if accounts.insert(addr, acct).is_some() {
                        return Err(storage::SnapshotError::Malformed);
                    }
                }
                persist::NS_BLOCK => {
                    if key.0[9..].iter().any(|b| *b != 0)
                        || persist::key_to_height(key).is_none()
                        || persist::deserialize_block(value).is_none()
                    {
                        return Err(storage::SnapshotError::Malformed);
                    }
                }
                persist::NS_UNDO => {
                    if key.0[9..].iter().any(|b| *b != 0)
                        || persist::key_to_height(key).is_none()
                        || persist::deserialize_undo(value).is_none()
                    {
                        return Err(storage::SnapshotError::Malformed);
                    }
                }
                persist::NS_META => {
                    if *key != persist::state_version_key() || value.len() != 4 {
                        return Err(storage::SnapshotError::Malformed);
                    }
                }
                _ => return Err(storage::SnapshotError::Malformed),
            }
        }
        Ok(accounts)
    }

    /// Get an account's balance from the EVM state.
    ///
    /// Returns 0 for accounts not in the state (EVM convention).
    /// The EVM uses `U256` for balances; we truncate to `u128` (the
    /// upper 128 bits are always zero for any realistic balance).
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned (a thread panicked while
    /// holding the lock). This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn balance(&self, addr: &Address) -> u128 {
        let db = framework::lock_state(&self.db);
        let evm_addr = alloy_primitives_address(addr.0);
        // `to::<u128>` panics on balances above u128::MAX — reachable
        // via crafted state (e.g. snapshot import). Saturate instead:
        // a balance that large cannot be spent anyway, and this is a
        // query accessor, not a consensus path.
        db.cache
            .accounts
            .get(&evm_addr)
            .map_or(0, |a| u128::try_from(a.info.balance).unwrap_or(u128::MAX))
    }

    /// Get an account's nonce from the EVM state.
    ///
    /// Returns 0 for accounts not in the state.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned (a thread panicked while
    /// holding the lock). This is unrecoverable and indicates a bug.
    #[must_use]
    pub fn nonce(&self, addr: &Address) -> u64 {
        let db = framework::lock_state(&self.db);
        let evm_addr = alloy_primitives_address(addr.0);
        db.cache.accounts.get(&evm_addr).map_or(0, |a| a.info.nonce)
    }

    /// Get the deployed bytecode of an account (`eth_getCode`).
    ///
    /// Returns an empty vec for EOAs, missing accounts, and
    /// not-yet-loaded code entries. Code lives in two places in the
    /// `CacheDB`: inline on the account (`info.code`) for freshly
    /// deployed/loaded accounts, and in the `contracts` map keyed by
    /// `code_hash` for accounts loaded from durable storage.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    #[must_use]
    pub fn code(&self, addr: &Address) -> Vec<u8> {
        let db = framework::lock_state(&self.db);
        let evm_addr = alloy_primitives_address(addr.0);
        let Some(account) = db.cache.accounts.get(&evm_addr) else {
            return Vec::new();
        };
        if let Some(code) = &account.info.code {
            return code.original_bytes().to_vec();
        }
        db.cache
            .contracts
            .get(&account.info.code_hash)
            .map(|c| c.original_bytes().to_vec())
            .unwrap_or_default()
    }

    /// Read one 32-byte storage slot (`eth_getStorageAt`).
    ///
    /// Returns `U256::ZERO` for missing accounts and untouched slots
    /// (EVM sparse-storage convention).
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    #[must_use]
    pub fn storage_at(
        &self,
        addr: &Address,
        slot: &revm::primitives::U256,
    ) -> revm::primitives::U256 {
        let db = framework::lock_state(&self.db);
        let evm_addr = alloy_primitives_address(addr.0);
        db.cache
            .accounts
            .get(&evm_addr)
            .and_then(|a| a.storage.get(slot))
            .copied()
            .unwrap_or_default()
    }

    /// Execute a read-only contract call against the current state
    /// (`eth_call`).
    ///
    /// Runs the full revm pipeline — including native read-only
    /// precompiles — with the simulation `CfgEnv` (nonce/base-fee/
    /// block-gas-limit/priority-fee/EIP-3607 checks disabled; balance
    /// and fee checks kept, matching geth's `DoCall`). The returned
    /// `EvmState` is **not** committed, so state cannot change.
    ///
    /// `transact` does not write the `CacheDB` — writes only flow
    /// through `commit`, which this path never calls — so holding the
    /// DB lock for the call's duration is safe and side-effect-free.
    ///
    /// `req.gas` defaults to the block gas limit; a supplied value is
    /// capped at it (a tx that needs more than a block's worth can
    /// never execute anyway).
    ///
    /// # Errors
    ///
    /// - [`CallError::Revert`] — the call hit REVERT; `output` carries
    ///   the revert data (including ABI `Error(string)` payloads).
    /// - [`CallError::Halt`] — out-of-gas, stack overflow, etc.
    /// - [`CallError::Rejected`] — validation failed before execution
    ///   (e.g. insufficient funds for `gas*price + value`).
    pub fn call_read(&self, req: &CallRequest) -> Result<CallOutcome, CallError> {
        self.call_read_impl(req, None, &overrides::StateOverrides::new())
    }

    /// `eth_call` with geth's `stateOverride` argument — `at`
    /// selects the height (`None` = latest, `Some(h)` = historical
    /// overlay), `ovr` the per-account replacements.
    ///
    /// # Errors
    ///
    /// Same [`CallError`] variants as `call_read`, plus
    /// [`CallError::Rejected`] when `h` is outside the window.
    pub fn call_read_with_overrides(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<CallOutcome, CallError> {
        let at = match at {
            Some(h) => self.resolve_at(h).map_err(Self::state_as_call_err)?,
            None => None,
        };
        self.call_read_impl(req, at, ovr)
    }

    /// Shared body of `call_read`/`call_read_at` — `at` is the
    /// `simulate` height selector (`None` = latest).
    fn call_read_impl(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<CallOutcome, CallError> {
        let (rs, _trace, timed_out) = self.simulate(
            req,
            req.gas.unwrap_or(self.block_gas_limit()),
            self.sim_deadline(),
            at,
            ovr,
        )?;
        let gas_used = rs.result.tx_gas_used();
        let result = rs.result;
        if timed_out {
            return Err(CallError::Halt { reason: "execution timed out".to_string(), gas_used });
        }
        match result {
            revm::context::result::ExecutionResult::Success { output, .. } => {
                Ok(CallOutcome { output: output.into_data().to_vec(), gas_used })
            }
            revm::context::result::ExecutionResult::Revert { output, .. } => {
                Err(CallError::Revert { output: output.to_vec(), gas_used })
            }
            revm::context::result::ExecutionResult::Halt { reason, .. } => {
                Err(CallError::Halt { reason: format!("{reason:?}"), gas_used })
            }
        }
    }

    /// Estimate the minimum gas a call needs to succeed
    /// (`eth_estimateGas`).
    ///
    /// Named `estimate_call_gas` to avoid colliding with the `Module`
    /// trait's `estimate_gas(&self, msg)` block-budget hook.
    ///
    /// Bounded binary search over [`call_read`](Self::call_read):
    /// first try the ceiling (`req.gas` capped at the block gas
    /// limit); if it fails there, no gas limit can succeed — the
    /// error propagates verbatim (geth does the same: "gas required
    /// exceeds allowance or always failing transaction" surfaces the
    /// revert reason). Otherwise binary-search `[0, cap)` for the
    /// smallest succeeding limit — at most ~34 iterations for a 10 GG
    /// cap.
    ///
    /// # Errors
    ///
    /// Same [`CallError`] variants as `call_read`.
    pub fn estimate_call_gas(&self, req: &CallRequest) -> Result<u64, CallError> {
        self.estimate_call_gas_impl(req, None, &overrides::StateOverrides::new())
    }

    /// `eth_estimateGas` at height `h` — historical form; same
    /// binary-search semantics over the undo-log overlay.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window; otherwise the same variants as `estimate_call_gas`.
    pub fn estimate_call_gas_at(&self, req: &CallRequest, h: u64) -> Result<u64, CallError> {
        let at = self.resolve_at(h).map_err(Self::state_as_call_err)?;
        self.estimate_call_gas_impl(req, at, &overrides::StateOverrides::new())
    }

    /// `eth_estimateGas` with geth's `stateOverride` argument.
    ///
    /// # Errors
    ///
    /// Same variants as `estimate_call_gas`/`call_read_with_overrides`.
    pub fn estimate_call_gas_with_overrides(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<u64, CallError> {
        let at = match at {
            Some(h) => self.resolve_at(h).map_err(Self::state_as_call_err)?,
            None => None,
        };
        self.estimate_call_gas_impl(req, at, ovr)
    }

    /// Shared body — `at` selects the state view (`None` = latest).
    fn estimate_call_gas_impl(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<u64, CallError> {
        let cap = req.gas.unwrap_or(self.block_gas_limit()).min(self.block_gas_limit());
        // One deadline bounds the whole request: geth's evmtimeout
        // covers `eth_estimateGas` end-to-end, not each probe. Sharing
        // the instant across binary-search iterations means a
        // timed-out estimate fails instead of silently converging on
        // a wrong bound.
        let deadline = self.sim_deadline();
        // If it cannot succeed at the cap, it can never succeed —
        // surface the failure (revert data included) immediately.
        // `simulate` returns `Ok` for Revert/Halt too (they are valid
        // execution outcomes), so check the variant, not just Ok/Err.
        let (rs, _trace, timed_out) = self.simulate(req, cap, deadline, at, ovr)?;
        if timed_out {
            return Err(CallError::Halt {
                reason: "execution timed out".to_string(),
                gas_used: rs.result.tx_gas_used(),
            });
        }
        match rs.result {
            revm::context::result::ExecutionResult::Success { .. } => {}
            revm::context::result::ExecutionResult::Revert { output, gas, .. } => {
                return Err(CallError::Revert {
                    output: output.to_vec(),
                    gas_used: gas.tx_gas_used(),
                });
            }
            revm::context::result::ExecutionResult::Halt { reason, gas, .. } => {
                return Err(CallError::Halt {
                    reason: format!("{reason:?}"),
                    gas_used: gas.tx_gas_used(),
                });
            }
        }
        let mut lo = 0u64;
        let mut hi = cap;
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            match self.simulate(req, mid, deadline, at, ovr) {
                Ok((rs, _, timed_out)) => {
                    if timed_out {
                        return Err(CallError::Halt {
                            reason: "execution timed out".to_string(),
                            gas_used: rs.result.tx_gas_used(),
                        });
                    }
                    if matches!(rs.result, revm::context::result::ExecutionResult::Success { .. }) {
                        hi = mid;
                    } else {
                        lo = mid;
                    }
                }
                Err(_) => lo = mid,
            }
        }
        Ok(hi)
    }

    /// Run one simulated execution at `gas_limit`. Shared by
    /// `call_read`, `estimate_call_gas`, `call_read_traced`, and
    /// `create_access_list`. Returns the full `ResultAndState` (the
    /// touched `EvmState` is the accessed-account/slot set that
    /// `eth_createAccessList` answers from) plus the recorded call
    /// tree (only the trace consumer uses it — dropping it costs
    /// nothing) and whether the wall-clock deadline fired
    /// (`timed_out` — the caller maps it to a timeout error).
    ///
    /// `at_height` selects the state view: `None` runs against the
    /// live `CacheDB` (latest); `Some(h)` runs against a
    /// [`versioned::StateView`] at `h` — the undo-log overlay — with
    /// the block env taken from `h`'s sealed history record
    /// (timestamp/coinbase/base fee), matching geth, which evaluates
    /// `eth_call` under the target block's env.
    ///
    /// `ovr` carries geth's `stateOverride` table — applied through
    /// [`overrides::OverrideView`], a read-only `DatabaseRef`
    /// wrapper, so fake state can never leak into the authoritative
    /// cache. On the latest path with non-empty overrides the sim
    /// runs on a `SharedCacheDB`-nested scratch (same trick the
    /// parallel executor uses) precisely so the live `CacheDB` is
    /// never borrowed mutably while fake entries exist.
    fn simulate(
        &self,
        req: &CallRequest,
        gas_limit: u64,
        deadline: std::time::Instant,
        at_height: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<(revm::context::result::ResultAndState, Option<trace::CallFrame>, bool), CallError>
    {
        let caller =
            req.from.map_or(revm::primitives::Address::ZERO, |a| alloy_primitives_address(a.0));
        let kind = match req.to {
            Some(addr) => TxKind::Call(alloy_primitives_address(addr.0)),
            None => TxKind::Create,
        };
        // Fee fields: a plain `gasPrice` maps to both caps (geth
        // treats it as max_fee for calls); explicit EIP-1559 fields
        // take precedence.
        let max_fee = req.max_fee_per_gas.or(req.gas_price).unwrap_or(0);
        let priority_fee = req.max_priority_fee_per_gas.or(req.gas_price).unwrap_or(0);
        let access_list: revm::context_interface::transaction::AccessList = req
            .access_list
            .iter()
            .map(|item| revm::context_interface::transaction::AccessListItem {
                address: item.address,
                storage_keys: item.storage_keys.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        let tx_env = TxEnv::builder()
            .caller(caller)
            .gas_limit(gas_limit)
            .kind(kind)
            .data(req.data.clone().into())
            .value(req.value)
            .gas_price(max_fee)
            .gas_priority_fee(Some(priority_fee))
            .nonce(req.nonce.unwrap_or(0))
            .access_list(access_list)
            .build()
            .map_err(|_| CallError::Rejected(ExecError::Malformed))?;

        let mut db_guard = framework::lock_state(&self.db);
        let coinbase = *framework::lock_state(&self.coinbase);
        let block_number = *framework::lock_state(&self.block_height);
        let block_timestamp = *framework::lock_state(&self.block_timestamp);

        match at_height {
            None if ovr.is_empty() => {
                let db = Arc::make_mut(&mut *db_guard);
                let mut evm =
                    self.build_sim_evm(&mut *db, coinbase, block_number, block_timestamp, deadline);
                // No `commit`: simulation state dies with the
                // EvmState. The call trace rides out alongside the
                // result for `debug_traceCall` —
                // `call_read`/`estimate_call_gas` ignore it.
                let result = evm
                    .inspect_tx(tx_env)
                    .map_err(|e| CallError::Rejected(ExecError::ModuleRejected(format!("{e:?}"))));
                // Inspector is ((NativeJournalInspector,
                // CallRecorder), DeadlineInspector): trace at `.0.1`,
                // timeout flag at `.1`.
                let timed_out = evm.inspector.1.timed_out();
                let call_trace = evm.inspector.0.1.take_root();
                evm.precompiles.clear_native_journal();
                result.map(|rs| (rs, call_trace, timed_out))
            }
            None => {
                // Overrides on latest state: run on a nested
                // scratch cache — fake entries must never land in
                // the authoritative `CacheDB`.
                let base = SharedCacheDB(Arc::clone(&db_guard));
                let mut cache = CacheDB::new(overrides::OverrideView::new(base, ovr));
                let mut evm = self.build_sim_evm(
                    &mut cache,
                    coinbase,
                    block_number,
                    block_timestamp,
                    deadline,
                );
                let result = evm
                    .inspect_tx(tx_env)
                    .map_err(|e| CallError::Rejected(ExecError::ModuleRejected(format!("{e:?}"))));
                let timed_out = evm.inspector.1.timed_out();
                let call_trace = evm.inspector.0.1.take_root();
                evm.precompiles.clear_native_journal();
                result.map(|rs| (rs, call_trace, timed_out))
            }
            Some(h) => {
                // Historical simulation: serve reads through the
                // undo-log overlay and take the block env from the
                // sealed record at `h` (the env a tx in that block
                // actually ran under).
                let env = {
                    let history = framework::lock_state(&self.history);
                    history.block(h).map(|b| (b.timestamp, b.coinbase, b.number))
                };
                let Some((ts, cb, num)) = env else {
                    return Err(CallError::Rejected(ExecError::ModuleRejected(format!(
                        "state for block {h} unavailable"
                    ))));
                };
                let versioned = framework::lock_state(&self.versioned);
                let view = versioned::StateView::new(&db_guard, &versioned, &self.history, h);
                let mut cache = CacheDB::new(overrides::OverrideView::new(view, ovr));
                let mut evm = self.build_sim_evm(&mut cache, cb, num, ts, deadline);
                let result = evm
                    .inspect_tx(tx_env)
                    .map_err(|e| CallError::Rejected(ExecError::ModuleRejected(format!("{e:?}"))));
                let timed_out = evm.inspector.1.timed_out();
                let call_trace = evm.inspector.0.1.take_root();
                evm.precompiles.clear_native_journal();
                result.map(|rs| (rs, call_trace, timed_out))
            }
        }
    }

    /// The wall-clock deadline applied to the next simulation —
    /// `Instant::now() + sim_timeout`.
    fn sim_deadline(&self) -> std::time::Instant {
        std::time::Instant::now() + self.sim_timeout
    }

    /// `debug_traceCall` — run a simulated call and return the
    /// recorded call tree (geth `callTracer` shape).
    ///
    /// Same semantics as [`call_read`](Self::call_read) — latest
    /// state, no commit — plus the root [`trace::CallFrame`].
    ///
    /// Unlike `call_read`, a reverted or halted call is **not** an
    /// error: geth's `debug_traceCall` returns the trace with the
    /// frame's `error` field set — the revert *is* the answer the
    /// caller asked for. Only pre-execution rejection (malformed
    /// env, unpayable) is an `Err`. The `u64` is the total gas used
    /// for the root-frame `gasUsed` patch.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when the call cannot be simulated at
    /// all.
    pub fn call_read_traced(
        &self,
        req: &CallRequest,
    ) -> Result<(u64, Option<trace::CallFrame>), CallError> {
        self.call_read_traced_impl(req, None, &overrides::StateOverrides::new())
    }

    /// `debug_traceCall` at height `h` — historical form.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window; otherwise the same variants as `call_read_traced`.
    pub fn call_read_traced_at(
        &self,
        req: &CallRequest,
        h: u64,
    ) -> Result<(u64, Option<trace::CallFrame>), CallError> {
        let at = self.resolve_at(h).map_err(Self::state_as_call_err)?;
        self.call_read_traced_impl(req, at, &overrides::StateOverrides::new())
    }

    /// `debug_traceCall` with geth's `stateOverride` argument.
    ///
    /// # Errors
    ///
    /// Same variants as `call_read_traced`.
    pub fn call_read_traced_with_overrides(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<(u64, Option<trace::CallFrame>), CallError> {
        let at = match at {
            Some(h) => self.resolve_at(h).map_err(Self::state_as_call_err)?,
            None => None,
        };
        self.call_read_traced_impl(req, at, ovr)
    }

    /// Shared body — `at` selects the state view (`None` = latest).
    fn call_read_traced_impl(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<(u64, Option<trace::CallFrame>), CallError> {
        let (rs, call_trace, timed_out) = self.simulate(
            req,
            req.gas.unwrap_or(self.block_gas_limit()),
            self.sim_deadline(),
            at,
            ovr,
        )?;
        if timed_out {
            return Err(CallError::Halt {
                reason: "execution timed out".to_string(),
                gas_used: rs.result.tx_gas_used(),
            });
        }
        Ok((rs.result.tx_gas_used(), call_trace))
    }

    /// `eth_createAccessList` — generate the EIP-2930 access list a
    /// call would touch, plus the gas it used.
    ///
    /// The touched set is the journal's final `EvmState`: every
    /// account loaded (read *or* written — journal loads land in
    /// `state` either way) and every slot `sload`/`sstore` touched.
    /// Matching geth's `accessListTracer`, the caller, the call
    /// target, and all protocol-warmed precompiles (Ethereum's
    /// active set plus the native `0x0B_*`–`0x0E_*` range) are
    /// excluded — they come warm for free, so listing them buys
    /// nothing. Entries the caller supplied in `req.access_list`
    /// are kept verbatim and merged with the generated ones (geth
    /// preserves the provided list as the base).
    ///
    /// `gas_used` is the simulated execution's gas — i.e. measured
    /// *with* the caller-provided access list applied (empty if none
    /// was supplied), matching geth, which does not re-run the call
    /// with the generated list.
    ///
    /// # Errors
    ///
    /// Same [`CallError`] variants as `call_read` — a reverting call
    /// is an error here (geth fails `eth_createAccessList` on
    /// revert rather than returning a list).
    pub fn create_access_list(
        &self,
        req: &CallRequest,
    ) -> Result<(tx::AccessList, u64), CallError> {
        self.create_access_list_impl(req, None, &overrides::StateOverrides::new())
    }

    /// `eth_createAccessList` at height `h` — historical form.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window; otherwise the same variants as `create_access_list`.
    pub fn create_access_list_at(
        &self,
        req: &CallRequest,
        h: u64,
    ) -> Result<(tx::AccessList, u64), CallError> {
        let at = self.resolve_at(h).map_err(Self::state_as_call_err)?;
        self.create_access_list_impl(req, at, &overrides::StateOverrides::new())
    }

    /// Shared body — `at` selects the state view (`None` = latest).
    fn create_access_list_impl(
        &self,
        req: &CallRequest,
        at: Option<u64>,
        ovr: &overrides::StateOverrides,
    ) -> Result<(tx::AccessList, u64), CallError> {
        let (rs, _trace, timed_out) = self.simulate(
            req,
            req.gas.unwrap_or(self.block_gas_limit()),
            self.sim_deadline(),
            at,
            ovr,
        )?;
        let gas_used = rs.result.tx_gas_used();
        if timed_out {
            return Err(CallError::Halt { reason: "execution timed out".to_string(), gas_used });
        }
        match rs.result {
            revm::context::result::ExecutionResult::Success { .. } => {}
            revm::context::result::ExecutionResult::Revert { output, .. } => {
                return Err(CallError::Revert { output: output.to_vec(), gas_used });
            }
            revm::context::result::ExecutionResult::Halt { reason, .. } => {
                return Err(CallError::Halt { reason: format!("{reason:?}"), gas_used });
            }
        }

        // Map the journal's touched-account set onto geth's
        // opcode-level `accessListTracer` semantics
        // (`eth/tracers/logger/access_list_tracer.go`):
        //
        // - `excl` gates *address-level* entries only: {caller, `to`,
        //   precompiles}. `addSlot` ignores `excl`, so `to`'s storage
        //   keys still appear — hence `to` is excluded below only when
        //   it touched no slots.
        // - Coinbase is not in geth's `excl` but also never appears —
        //   tip crediting is not an opcode touch — so it is excluded
        //   here unconditionally.
        // - Every other journal account corresponds to an opcode-level
        //   access (EXT*/BALANCE/CALL-family targets, SLOAD/SSTORE
        //   storage owners, SELFDESTRUCT beneficiaries) and is emitted
        //   with its touched slot set — including entries with no
        //   slots, which geth also emits.
        let caller =
            req.from.map_or(revm::primitives::Address::ZERO, |a| alloy_primitives_address(a.0));
        let to = req.to.map(|a| alloy_primitives_address(a.0));
        let coinbase = *framework::lock_state(&self.coinbase);
        let mut excluded = precompiles::NativePrecompiles::warm_addresses_for(self.spec);
        excluded.insert(caller);
        excluded.insert(coinbase);
        // geth's `excl` set for *address-level* entries — the same
        // plus `to` — also filters the caller-provided acl
        // (`NewAccessListTracer` skips them when seeding `list`).
        let mut addr_excl = excluded.clone();
        if let Some(t) = to {
            addr_excl.insert(t);
        }

        // Base map = caller-provided entries (excl-filtered, as geth
        // seeds), then merge in every accessed slot per touched
        // account.
        let mut merged: std::collections::BTreeMap<
            revm::primitives::Address,
            std::collections::BTreeSet<revm::primitives::B256>,
        > = std::collections::BTreeMap::new();
        for item in &req.access_list {
            if addr_excl.contains(&item.address) {
                continue;
            }
            merged.entry(item.address).or_default().extend(item.storage_keys.iter().copied());
        }
        for (addr, account) in &rs.state {
            if excluded.contains(addr) {
                continue;
            }
            let is_to = Some(*addr) == to;
            if is_to && account.storage.is_empty() {
                // `to` is address-excluded in geth — it only appears
                // when the call actually touched its storage.
                continue;
            }
            // Journal storage keys are `U256` slot indices; the wire
            // format wants `B256`.
            merged
                .entry(*addr)
                .or_default()
                .extend(account.storage.keys().map(|k| revm::primitives::B256::from(*k)));
        }
        let list = merged
            .into_iter()
            .map(|(address, keys)| tx::AccessListItem {
                address,
                storage_keys: keys.into_iter().collect(),
            })
            .collect();
        Ok((list, gas_used))
    }

    // ── Historical state reads (undo-log window) ────────────────

    /// Validate `h` against the servable window.
    ///
    /// - `h > latest` → [`StateError::TooNew`] ("header not found").
    /// - `h == latest` → always servable (live `CacheDB`).
    /// - `h < latest` → servable iff the undo log covers `(h, latest]`,
    ///   i.e. `h >= floor - 1` where `floor` is the oldest retained
    ///   height; otherwise [`StateError::Pruned`] ("missing trie
    ///   node", geth's non-archive behavior).
    fn check_state_height(&self, h: u64) -> Result<u64, StateError> {
        let latest =
            framework::lock_state(&self.history).latest().unwrap_or_else(|| self.current_height());
        if h > latest {
            return Err(StateError::TooNew { requested: h, latest });
        }
        if h == latest {
            return Ok(h);
        }
        let versioned = framework::lock_state(&self.versioned);
        // `floor - 1` is the oldest servable height; an empty index
        // means nothing is retained — only `latest` answers.
        let min = versioned.floor().map_or(latest, |f| f.saturating_sub(1));
        if h < min {
            return Err(StateError::Pruned { requested: h, floor: min });
        }
        Ok(h)
    }

    /// Map a requested height onto the `simulate` `at_height` arg:
    /// `None` for `latest` (the live-db fast path), `Some(h)` for a
    /// historical overlay.
    fn resolve_at(&self, h: u64) -> Result<Option<u64>, StateError> {
        let h = self.check_state_height(h)?;
        let latest =
            framework::lock_state(&self.history).latest().unwrap_or_else(|| self.current_height());
        Ok(if h == latest { None } else { Some(h) })
    }

    /// [`StateError`] → [`CallError`] for the simulation entry
    /// points (which surface height errors through `Rejected`).
    fn state_as_call_err(e: StateError) -> CallError {
        CallError::Rejected(ExecError::ModuleRejected(format!(
            "state for block {} unavailable: {e:?}",
            e.requested()
        )))
    }

    /// A [`versioned::StateView`] at `h` over the live db and undo
    /// index. Callers hold both guards for the view's lifetime.
    fn state_view<'a>(
        db: &'a CacheDB<EmptyDB>,
        versioned: &'a versioned::VersionedState,
        history: &'a Mutex<history::History>,
        h: u64,
    ) -> versioned::StateView<'a> {
        versioned::StateView::new(db, versioned, history, h)
    }

    /// `eth_getBalance` at height `h`.
    ///
    /// # Errors
    ///
    /// [`StateError`] when `h` is outside the retained window.
    pub fn balance_at(&self, addr: &Address, h: u64) -> Result<u128, StateError> {
        self.check_state_height(h)?;
        let db = framework::lock_state(&self.db);
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&db, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);
        Ok(view
            .basic_ref(evm_addr)
            .unwrap_or_default()
            .map_or(0, |a| u128::try_from(a.balance).unwrap_or(u128::MAX)))
    }

    /// `eth_getTransactionCount` at height `h`.
    ///
    /// # Errors
    ///
    /// [`StateError`] when `h` is outside the retained window.
    pub fn nonce_at(&self, addr: &Address, h: u64) -> Result<u64, StateError> {
        self.check_state_height(h)?;
        let db = framework::lock_state(&self.db);
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&db, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);
        Ok(view.basic_ref(evm_addr).unwrap_or_default().map_or(0, |a| a.nonce))
    }

    /// `eth_getCode` at height `h`. Old bytecode is always servable —
    /// `cache.contracts` retains every deployed blob keyed by hash.
    ///
    /// # Errors
    ///
    /// [`StateError`] when `h` is outside the retained window.
    pub fn code_at(&self, addr: &Address, h: u64) -> Result<Vec<u8>, StateError> {
        self.check_state_height(h)?;
        let db = framework::lock_state(&self.db);
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&db, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);
        let Some(info) = view.basic_ref(evm_addr).unwrap_or_default() else {
            return Ok(Vec::new());
        };
        if let Some(code) = &info.code {
            return Ok(code.original_bytes().to_vec());
        }
        Ok(view.code_by_hash_ref(info.code_hash).unwrap_or_default().original_bytes().to_vec())
    }

    /// `eth_getStorageAt` at height `h`.
    ///
    /// # Errors
    ///
    /// [`StateError`] when `h` is outside the retained window.
    pub fn storage_at_height(
        &self,
        addr: &Address,
        slot: &revm::primitives::U256,
        h: u64,
    ) -> Result<revm::primitives::U256, StateError> {
        self.check_state_height(h)?;
        let db = framework::lock_state(&self.db);
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&db, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);
        Ok(view.storage_ref(evm_addr, *slot).unwrap_or_default())
    }

    /// `eth_call` at height `h` — the historical form of
    /// [`call_read`](Self::call_read). The simulation runs over a
    /// `CacheDB<StateView>`: identical code path to `latest`, with
    /// reads served by the undo overlay and the block env taken from
    /// `h`'s sealed record.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window or the block record is missing; otherwise the same
    /// [`CallError`] variants as `call_read`.
    pub fn call_read_at(&self, req: &CallRequest, h: u64) -> Result<CallOutcome, CallError> {
        let at = self.resolve_at(h).map_err(Self::state_as_call_err)?;
        self.call_read_impl(req, at, &overrides::StateOverrides::new())
    }

    /// `eth_getProof` (EIP-1186): the account's Merkle-Patricia proof
    /// plus one proof per requested storage key, all at height `h`.
    ///
    /// The state trie is not persisted — the proof is produced by
    /// rebuilding the trie from the state at `h` while a
    /// [`alloy_trie::proof::ProofRetainer`] keeps the nodes on the
    /// target path. This is `O(accounts + touched_since_h)` per call —
    /// expensive, but bounded, and proofs are a cold-path archive
    /// query (bridges/light clients hit `latest` almost always).
    ///
    /// Absent accounts/slots return proofs of non-inclusion (geth
    /// parity), not errors.
    ///
    /// # Errors
    ///
    /// [`CallError::Rejected`] when `h` is outside the retained
    /// window.
    #[allow(clippy::too_many_lines)]
    pub fn account_proof(
        &self,
        addr: &Address,
        slots: &[revm::primitives::B256],
        h: u64,
    ) -> Result<AccountProof, CallError> {
        let h = self.check_state_height(h).map_err(|e| {
            CallError::Rejected(ExecError::ModuleRejected(format!(
                "state for block {} unavailable: {e:?}",
                e.requested()
            )))
        })?;
        let db = framework::lock_state(&self.db);
        let versioned = framework::lock_state(&self.versioned);
        let view = Self::state_view(&db, &versioned, &self.history, h);
        let evm_addr = alloy_primitives_address(addr.0);

        // ── Account-trie proof ──────────────────────────────────
        // Materialize every account at `h`: latest map ∪ undo-known
        // addresses (the union covers accounts deleted since `h`).
        // Each entry contributes `keccak(addr) → rlp(TrieAccount)`.
        let mut leaves: std::collections::BTreeMap<revm::primitives::B256, Vec<u8>> =
            std::collections::BTreeMap::new();
        let addrs: std::collections::BTreeSet<revm::primitives::Address> =
            db.cache.accounts.keys().copied().chain(versioned.known_accounts().copied()).collect();
        let mut storage_root_cache = framework::lock_state(&self.storage_root_cache);
        for a in addrs {
            let Some(info) = view.info_at(&a) else { continue };
            // Storage root at `h`: the undo map when the account was
            // rewritten above `h`, else the latest map. The cached
            // root is only reused on the untouched path.
            let storage_map = view.storage_map_at(&a).unwrap_or_default();
            let sroot = if storage_map.is_empty() {
                trie::EMPTY_ROOT
            } else if versioned.entry_at(&a, h).is_none() {
                // Untouched since `h` — the cached root is valid.
                if let Some(r) = storage_root_cache.get(&a) {
                    *r
                } else {
                    let r = trie::storage_root(
                        storage_map.iter().map(|(k, v)| (revm::primitives::B256::from(*k), *v)),
                    );
                    storage_root_cache.insert(a, r);
                    r
                }
            } else {
                trie::storage_root(
                    storage_map.iter().map(|(k, v)| (revm::primitives::B256::from(*k), *v)),
                )
            };
            let trie_account =
                trie::build_trie_account(info.nonce, info.balance, sroot, info.code_hash);
            let mut leaf = Vec::with_capacity(80);
            alloy_rlp::Encodable::encode(&trie_account, &mut leaf);
            leaves.insert(alloy_primitives::keccak256(a), leaf);
        }
        drop(storage_root_cache);

        let target = alloy_trie::Nibbles::unpack(alloy_primitives::keccak256(evm_addr));
        let retainer = alloy_trie::proof::ProofRetainer::new(vec![target]);
        let mut hb = alloy_trie::hash_builder::HashBuilder::default().with_proof_retainer(retainer);
        for (hashed, leaf) in &leaves {
            hb.add_leaf(alloy_trie::Nibbles::unpack(*hashed), leaf);
        }
        hb.root();
        let account_proof: Vec<revm::primitives::Bytes> = hb
            .take_proof_nodes()
            .matching_nodes_sorted(&target)
            .into_iter()
            .map(|(_, node)| node)
            .collect();

        // ── Account fields at `h` ───────────────────────────────
        let info = view.info_at(&evm_addr);
        let storage_map = view.storage_map_at(&evm_addr).unwrap_or_default();
        let storage_hash = if storage_map.is_empty() {
            trie::EMPTY_ROOT
        } else {
            trie::storage_root(
                storage_map.iter().map(|(k, v)| (revm::primitives::B256::from(*k), *v)),
            )
        };

        // ── Storage proofs ──────────────────────────────────────
        // One storage trie serves all requested keys — build it
        // once with every requested slot as a retainer target.
        let mut storage_proofs = Vec::with_capacity(slots.len());
        if !slots.is_empty() {
            let targets: Vec<alloy_trie::Nibbles> = slots
                .iter()
                .map(|s| alloy_trie::Nibbles::unpack(alloy_primitives::keccak256(*s)))
                .collect();
            let retainer = alloy_trie::proof::ProofRetainer::new(targets.clone());
            let mut shb =
                alloy_trie::hash_builder::HashBuilder::default().with_proof_retainer(retainer);
            // Storage leaves: hashed_slot → rlp(value) — zero slots
            // are never stored (EVM sparse-storage convention).
            let mut sleaves: std::collections::BTreeMap<revm::primitives::B256, Vec<u8>> =
                std::collections::BTreeMap::new();
            for (slot, value) in &storage_map {
                if value.is_zero() {
                    continue;
                }
                let mut leaf = Vec::with_capacity(40);
                alloy_rlp::Encodable::encode(&alloy_primitives::U256::from(*value), &mut leaf);
                sleaves
                    .insert(alloy_primitives::keccak256(revm::primitives::B256::from(*slot)), leaf);
            }
            for (hashed, leaf) in &sleaves {
                shb.add_leaf(alloy_trie::Nibbles::unpack(*hashed), leaf);
            }
            shb.root();
            let nodes = shb.take_proof_nodes();
            for (slot, target) in slots.iter().zip(targets.iter()) {
                let proof: Vec<revm::primitives::Bytes> =
                    nodes.matching_nodes_sorted(target).into_iter().map(|(_, n)| n).collect();
                let slot_u256 = revm::primitives::U256::from_be_bytes(slot.0);
                storage_proofs.push(StorageProof {
                    key: *slot,
                    value: storage_map.get(&slot_u256).copied().unwrap_or_default(),
                    proof,
                });
            }
        }

        Ok(AccountProof {
            address: evm_addr,
            balance: info.as_ref().map_or(revm::primitives::U256::ZERO, |i| i.balance),
            code_hash: info.as_ref().map_or(revm::primitives::KECCAK_EMPTY, |i| i.code_hash),
            nonce: info.as_ref().map_or(0, |i| i.nonce),
            storage_hash,
            account_proof,
            storage_proofs,
        })
    }

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
            account.storage.insert(slot, value);
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

    /// Flush the current `CacheDB` state to the `StorageBackend`.
    ///
    /// Phase D: incremental flush. Only accounts touched in the
    /// current block are flushed. This is O(touched) instead of
    /// O(N) — a major improvement for large states where each
    /// block modifies only a few accounts.
    ///
    /// If no accounts were touched (e.g., empty block), this is a
    /// no-op.
    ///
    /// # Self-destructed accounts
    ///
    /// Accounts that became `NotExisting` (self-destructed) or were
    /// removed from the cache emit a `Delete` op so the storage
    /// backend removes the stale entry. Without this, a
    /// self-destructed account would reappear on reload.
    ///
    /// # Deterministic serialization
    ///
    /// Storage slots are sorted by slot key before serialization so
    /// the persisted blob is byte-identical across all validators
    /// with the same logical state. Without this, `HashMap`
    /// iteration order would make the raw `StorageBackend` value
    /// non-deterministic.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    fn flush_to_storage(
        &self,
        backend: &mut (dyn storage::StorageBackend + Send),
    ) -> Result<(), storage::ApplyError> {
        let ops = self.account_flush_ops();
        self.flush_pending(backend, ops)
    }

    /// Attempt `apply_batch` over `pending_flush + extra` as ONE
    /// batch — a failed earlier flush retries inside the next one,
    /// so no account update, sealed-block record, or undo blob is
    /// ever dropped on a transient storage failure.
    ///
    /// On `Ok`: the buffer clears, the error latch resets, and the
    /// batch is synced (the per-block durability point — `Ok` from
    /// `apply_batch` is "written", `sync` is "durable"). On `Err`:
    /// the ops stay in `pending_flush` and the error is latched into
    /// `storage_error` — the in-memory state remains correct, but
    /// callers can observe degraded persistence via
    /// [`Self::storage_error`].
    fn flush_pending(
        &self,
        backend: &mut (dyn storage::StorageBackend + Send),
        extra: Vec<storage::Op>,
    ) -> Result<(), storage::ApplyError> {
        let mut pending = framework::lock_state(&self.pending_flush);
        pending.extend(extra);
        if pending.is_empty() {
            return Ok(());
        }
        match backend.apply_batch(&pending) {
            Ok(()) => {
                pending.clear();
                drop(pending);
                // Per-block durability point: `apply_batch` is
                // "written", `sync` is "durable". A sync failure is
                // latched but not buffered — the ops ARE written, and
                // the next successful sync covers them (same file).
                if let Err(e) = backend.sync() {
                    *framework::lock_state(&self.storage_error) = Some(e.clone());
                    return Err(e);
                }
                *framework::lock_state(&self.storage_error) = None;
                Ok(())
            }
            Err(e) => {
                drop(pending);
                *framework::lock_state(&self.storage_error) = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Build the account write ops for the block's `touched` set —
    /// the pure form of [`flush_to_storage`], split out so
    /// `end_block` can commit accounts, the sealed history record,
    /// and the undo blob in one `apply_batch` (a crash must never
    /// leave state ahead of history, or a restarted node would serve
    /// newer state under an older height label).
    fn account_flush_ops(&self) -> Vec<storage::Op> {
        let db = framework::lock_state(&self.db);
        let touched = framework::lock_state(&self.touched);

        let mut ops = Vec::with_capacity(touched.len());
        for evm_addr in touched.iter() {
            let oxide_addr = Address(evm_addr.0.into());
            let key = persist::account_key(&oxide_addr);

            // Handle self-destructed / removed accounts: emit a
            // Delete op so the stale entry is removed from storage.
            // Without this, a self-destructed account reappears on
            // reload because the old persisted value is still there.
            // `serialize_committed_account` returns `None` for both
            // cases (missing entry or `NotExisting` tombstone) —
            // exactly the accounts absent from committed state.
            match Self::serialize_committed_account(evm_addr, &db) {
                Some(value) => ops.push(storage::Op::Set { key, value }),
                None => ops.push(storage::Op::Delete { key }),
            }
        }
        // The schema version rides every flush batch: one extra op
        // per block keeps the `0x04` meta slot in lockstep with the
        // binary that last wrote state — a downgraded binary's
        // `state_version` would rewrite it honestly instead of
        // inheriting a newer label it can't interpret.
        ops.push(storage::Op::Set {
            key: persist::state_version_key(),
            value: self.state_version().to_le_bytes().to_vec(),
        });
        ops
    }

    /// Serialize one committed cache account into its canonical
    /// value blob — the single encoding shared by the incremental
    /// flush ([`Self::account_flush_ops`]) and the snapshot export
    /// ([`Module::export_state`]). Keeping both on one serializer is
    /// the audit-3.2 invariant: the bytes that reach durable storage
    /// and the bytes a snapshot carries can never drift apart.
    ///
    /// Returns `None` when the address is absent from committed
    /// state — no cache entry, or an `AccountState::NotExisting`
    /// tombstone (self-destructed this block, or a `basic()` miss
    /// revm cached). Tombstones are not part of the state trie, so
    /// they must never serialize as live accounts.
    ///
    /// The blob layout is `persist::serialize_account`'s: balance,
    /// nonce, `code_hash`, code bytes, then storage slots sorted
    /// ascending by slot key. `DbAccount.storage` is a `U256Map`
    /// (hash map) — sorting makes the blob deterministic across
    /// validators with the same logical state.
    fn serialize_committed_account(
        evm_addr: &revm::primitives::Address,
        db: &CacheDB<EmptyDB>,
    ) -> Option<Vec<u8>> {
        let account = db.cache.accounts.get(evm_addr)?;
        if account.account_state == revm::database::AccountState::NotExisting {
            return None;
        }
        let code_bytes: Vec<u8> = if account.info.code_hash == revm::primitives::KECCAK_EMPTY {
            Vec::new()
        } else {
            // `original_byte_slice`, not `bytes_slice`: once revm has
            // analyzed a contract (first execution) `bytes_slice`
            // returns the padded buffer, whose keccak no longer
            // matches the committed `code_hash` — persisting it
            // would reinstall divergent bytecode on restart
            // (`extcodesize`/`extcodecopy` observe the padding).
            match &account.info.code {
                Some(bc) => bc.original_byte_slice().to_vec(),
                // A balance/nonce-touched contract may never have
                // loaded bytecode into `info.code` (e.g. a contract
                // coinbase receiving fees — `basic()` doesn't
                // populate `code`). Fall back to the contracts map:
                // writing `code_len=0` under a real `code_hash`
                // would silently strip the contract's code on
                // reload/snapshot.
                None => db
                    .cache
                    .contracts
                    .get(&account.info.code_hash)
                    .map_or_else(Vec::new, |bc| bc.original_byte_slice().to_vec()),
            }
        };
        let mut storage_slots: Vec<(revm::primitives::U256, revm::primitives::U256)> =
            account.storage.iter().map(|(slot, val)| (*slot, *val)).collect();
        storage_slots.sort_by_key(|a| a.0);
        Some(persist::serialize_account(
            account.info.balance,
            account.info.nonce,
            account.info.code_hash,
            &code_bytes,
            &storage_slots,
        ))
    }

    /// Load EVM state from the `StorageBackend` into the `CacheDB`.
    ///
    /// Reads all account entries (namespace prefix `0x01`) and
    /// populates the cache with balances, nonces, code, and storage.
    /// Called from `with_storage` on construction.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    fn load_from_storage(&self, backend: &mut (dyn storage::StorageBackend + Send)) {
        let entries = backend.range(&persist::account_prefix());
        // Only the *account* section is skipped on an empty range —
        // block history, the undo window, stale-record cleanup, and
        // the schema-version check still run: a backend can hold
        // sealed blocks (empty blocks write no accounts) or only a
        // version marker, and skipping their restore would silently
        // drop durable state that exists.
        if !entries.is_empty() {
            let mut db_guard = framework::lock_state(&self.db);
            let db = Arc::make_mut(&mut *db_guard);
            for (key, value) in &entries {
                let Some(oxide_addr) = persist::key_to_address(key) else { continue };
                let Some(account) = persist::deserialize_account(value) else {
                    continue;
                };
                let evm_addr = alloy_primitives_address(oxide_addr.0);

                // Insert account info into the cache.
                let info = revm::database::state::AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                    account_id: None,
                    // revm's `Bytecode::default()` contains a STOP opcode,
                    // which makes `is_empty()` return false and triggers
                    // EIP-3607 `RejectCallerWithCode`. Use `new_raw` with
                    // empty bytes to create a truly empty bytecode.
                    code: if account.code.is_empty() {
                        Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::new()))
                    } else {
                        Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::from_iter(
                            account.code.iter().copied(),
                        )))
                    },
                };
                db.cache.accounts.insert(
                    evm_addr,
                    revm::database::DbAccount {
                        info,
                        // `None` = account exists in cache but EVM hasn't
                        // interacted with it in this block. This is correct
                        // for loaded state — revm will read storage from
                        // the `DbAccount.storage` field. `StorageCleared`
                        // would incorrectly zero out the storage.
                        account_state: revm::database::AccountState::None,
                        storage: account.storage.into_iter().collect(),
                    },
                );
                // HIGH fix: also populate `cache.contracts` (the code
                // hash → Bytecode map). revm looks up contract code by
                // hash via `cache.contracts`, not via the account's
                // `info.code` field. Without this, after a storage
                // reload, the EVM can't find contract code by hash —
                // calling a reloaded contract would behave as if it
                // has no code (a silent no-op call).
                if !account.code.is_empty() {
                    db.cache.contracts.insert(
                        account.code_hash,
                        revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::from_iter(
                            account.code.iter().copied(),
                        )),
                    );
                }
            }
            drop(db_guard);
        }

        // Restore the sealed-block history (`0x02` records) and the
        // undo window (`0x03` blobs) so historical state reads, log
        // queries, receipts, and `debug_trace*` survive restart.
        // Both scans come back height-ascending (the key layout is
        // height-major); `restore_block`/`push` rebuild the in-memory
        // indexes as they insert.
        let mut stale: Vec<Hash> = Vec::new();
        let floor = {
            let mut history = framework::lock_state(&self.history);
            for (_key, value) in backend.range(&persist::block_prefix()) {
                let Some(block) = persist::deserialize_block(&value) else {
                    continue; // Malformed record — a storage bug, skip it.
                };
                for evicted in history.restore_block(block) {
                    // Restored-then-evicted records are stale on disk
                    // (the configured window shrank since the records
                    // were written). Delete them below.
                    stale.push(persist::block_key(evicted));
                }
            }
            history.blocks_floor()
        };

        // Rehydrate the EIP-1559 fee state from the newest sealed
        // block. `end_block_ctx` evolves the fee as
        // `BaseFeeState::new(block.base_fee, block.gas_limit)
        //   .update(block.gas_used)`
        // — replaying that transition on the last sealed record
        // reproduces the exact in-memory state a crash dropped, so
        // the next block charges the same base fee it would have
        // without the restart. A fresh backend (no sealed blocks)
        // keeps the constructor seed, matching a cold start.
        {
            let history = framework::lock_state(&self.history);
            if let Some(last) = history.latest().and_then(|h| history.block(h)) {
                let mut fee_state = fee::BaseFeeState::new(last.base_fee, last.gas_limit);
                fee_state.update(last.gas_used);
                *framework::lock_state(&self.fee_state) = fee_state;
            }
        }

        {
            let mut versioned = framework::lock_state(&self.versioned);
            for (key, value) in backend.range(&persist::undo_prefix()) {
                let Some(height) = persist::key_to_height(&key) else { continue };
                if floor.is_some_and(|f| height < f) {
                    stale.push(key); // Below the restored window.
                    continue;
                }
                let Some(undo) = persist::deserialize_undo(&value) else { continue };
                versioned.push(height, undo);
            }
        }

        // One cleanup batch for stale records discovered during
        // restore (over-capacity or below-floor entries). Routed
        // through the pending buffer: a failure latches into
        // `storage_error` and retries inside the next block's flush
        // — the records are housekeeping, so a delayed cleanup is
        // harmless, but a silently dropped write is not.
        if !stale.is_empty() {
            let ops: Vec<storage::Op> =
                stale.into_iter().map(|key| storage::Op::Delete { key }).collect();
            let _ = self.flush_pending(backend, ops);
        }

        // Schema version check: the backend records the layout
        // version it was last written at (`0x04` meta namespace,
        // absent = v1 pre-versioning). Older than this binary's
        // declared `state_version` → run `migrate` on the freshly
        // loaded state and persist the new version. A failed
        // migration leaves the stored version untouched — the next
        // restart retries it.
        let stored_version = backend
            .get(&persist::state_version_key())
            .and_then(|v| <[u8; 4]>::try_from(v.as_slice()).ok().map(u32::from_le_bytes))
            .unwrap_or(1);
        if stored_version < self.state_version()
            && let Ok(new_version) = self.migrate(stored_version)
        {
            // Schema-version write through the pending buffer — a
            // failure latches and retries rather than leaving the
            // recorded version silently behind the migrated state.
            let _ = self.flush_pending(
                backend,
                vec![storage::Op::Set {
                    key: persist::state_version_key(),
                    value: new_version.to_le_bytes().to_vec(),
                }],
            );
        }
    }
}

/// Convert an Oxide `Address` (20 bytes) to a revm `Address`.
pub(crate) fn alloy_primitives_address(bytes: [u8; 20]) -> revm::primitives::Address {
    revm::primitives::Address::from(bytes)
}

#[cfg(test)]
mod tests;
