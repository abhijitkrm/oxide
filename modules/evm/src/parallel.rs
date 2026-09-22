//! Speculative-execution records for the parallel batch path.
//!
//! Split from `lib.rs` around the speculation invariant: each
//! [`SpecTx`] captures everything the canonical-order commit needs
//! to *prove or disprove* the speculation — read/write sets, the
//! merge payload (`write_accounts`, `new_contracts`,
//! `coinbase_delta`), and the flags forcing canonical re-execution.
//! [`SharedCacheDB`] is the read-only parent all worker groups
//! share (N nested caches over one `Arc`, because `CacheDB::nest`
//! consumes `self`); [`CoinbaseObs`] isolates the fee-recipient's
//! non-additive interactions, the only coinbase writes that can
//! invalidate a speculation.

use std::sync::Arc;

use revm::database::CacheDB;
use revm::database_interface::{DatabaseRef, EmptyDB};

use crate::TracedResult;
use executor::ExecError;

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
pub(crate) struct SharedCacheDB(pub(crate) Arc<CacheDB<EmptyDB>>);

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
pub(crate) struct SpecTx {
    /// Original position of the tx in the batch.
    pub(crate) idx: usize,
    /// The tx sender (its group's key) — used to exclude same-sender
    /// predecessor writes, which sequential in-group speculation
    /// already observed.
    pub(crate) sender: revm::primitives::Address,
    /// The speculative execution result and call trace.
    pub(crate) result: TracedResult,
    /// Accounts the tx loaded during execution (read or wrote),
    /// excluding the coinbase — tracked separately because every tx
    /// writes it via tips. For the revm path this is `rs.state`'s
    /// keys; for fast paths `{caller, recipient}`.
    pub(crate) reads: std::collections::HashSet<revm::primitives::Address>,
    /// Accounts the tx modified, excluding the coinbase.
    pub(crate) writes: std::collections::HashSet<revm::primitives::Address>,
    /// Post-execution snapshots of `writes` — the merge payload for
    /// a validated tx.
    pub(crate) write_accounts: Vec<(revm::primitives::Address, revm::database::DbAccount)>,
    /// Code entries the tx deployed (CREATE is the only source).
    pub(crate) new_contracts: Vec<(revm::primitives::B256, revm::bytecode::Bytecode)>,
    /// The coinbase balance the tx speculated against — pre-block
    /// balance plus own-group tips. Compared against the canonical
    /// running balance at commit when `coinbase.read` is set.
    pub(crate) coinbase_before: revm::primitives::U256,
    /// Net coinbase balance change the tx produced. Strictly
    /// additive (tips, plus any transfers to the fee recipient), so
    /// it merges correctly regardless of position.
    pub(crate) coinbase_delta: revm::primitives::U256,
    /// How the tx interacted with the block's fee recipient beyond
    /// the strictly additive tip credit — see [`CoinbaseObs`].
    pub(crate) coinbase: CoinbaseObs,
    /// Speculation cannot represent this tx: a mutating native
    /// precompile was suppressed (read-only provider) or a
    /// non-additive coinbase write occurred. The tx must re-execute
    /// against the canonical DB regardless of conflict sets.
    pub(crate) must_reexec: bool,
}

/// How a speculative transaction interacted with the block's fee
/// recipient beyond the strictly additive tip credit.
///
/// Grouped because the three flags describe one concept — the
/// coinbase is special-cased in conflict detection precisely because
/// every tx writes it, so only *non-additive* interaction can
/// invalidate a speculation.
pub(crate) struct CoinbaseObs {
    /// `BALANCE(coinbase)` executed during speculation — the result
    /// may depend on the canonical running tip total.
    pub(crate) read: bool,
    /// The coinbase account was loaded at all — cheap superset of
    /// `read`, used to gate re-execution once the coinbase has been
    /// non-additively modified (`coinbase_dirty`).
    pub(crate) accessed: bool,
    /// The tx changed the coinbase beyond an additive balance delta
    /// (nonce, storage, creation, or destruction — e.g. sender ==
    /// coinbase, or a contract at the fee-recipient address). Such a
    /// change cannot be merged and dirties the coinbase for every
    /// later accessor.
    pub(crate) nontrivial: bool,
}

impl SpecTx {
    /// A record for a tx that failed before touching state
    /// (`build_tx_env` rejection — intrinsic to the tx bytes, so no
    /// ordering dependency exists).
    pub(crate) fn intrinsic_error(
        idx: usize,
        sender: revm::primitives::Address,
        e: ExecError,
    ) -> Self {
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
pub(crate) struct GroupExecResult {
    /// Per-tx speculative records, in the order the txs ran
    /// (ascending nonce within the sender).
    pub(crate) spec_txs: Vec<SpecTx>,
}
