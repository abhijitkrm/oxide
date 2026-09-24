//! Speculative-execution records for the parallel batch path.
//!
//! Split from `lib.rs` around the speculation invariant: each
//! [`SpecTx`] captures everything the canonical-order commit needs
//! to *prove or disprove* the speculation — read/write sets, the
//! merge payload (the tx's recorded [`EvmState`] diff and
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
/// (or disprove) the speculation, the merge payload (`state`,
/// `coinbase_delta`) for a validated speculation, and the flags that
/// force canonical re-execution.
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
    ///
    /// Loading an account means its *info* (balance, nonce, `code_hash`)
    /// was observable — revm gives no finer signal, so an account
    /// loaded only as a storage slot's host still counts here. That
    /// is the conservative direction: it can only produce a spurious
    /// re-execution, never a missed conflict.
    pub(crate) reads: std::collections::HashSet<revm::primitives::Address>,
    /// Every storage slot the tx accessed — `SLOAD` targets *and*
    /// `SSTORE` targets (a write is also an access: the tx observed
    /// the slot's pre-write value). revm's journal inserts every
    /// accessed slot into `account.storage`, so this is exact, not
    /// an over-approximation.
    pub(crate) slot_reads:
        std::collections::HashSet<(revm::primitives::Address, revm::primitives::U256)>,
    /// Accounts whose `info` (balance, nonce, or code hash) actually
    /// changed — a strict subset of `is_touched()`. Storage-only
    /// writes (e.g. a token contract's `balances` mapping) do NOT
    /// land here: they are tracked per-slot in `slot_writes` instead,
    /// which is what lets two txs to the same hot contract proceed
    /// in parallel. Excludes destructive writes (those live in
    /// `destructive`).
    pub(crate) info_writes: std::collections::HashSet<revm::primitives::Address>,
    /// Storage slots whose `present_value` differs from
    /// `original_value` — the exact write footprint. A same-value
    /// `SSTORE` (x → x) is state-neutral and deliberately absent.
    pub(crate) slot_writes:
        std::collections::HashSet<(revm::primitives::Address, revm::primitives::U256)>,
    /// Accounts the tx destroyed or (re)created:
    /// `is_selfdestructed() || is_created_locally()`. Such a write
    /// replaces the account wholesale — storage included — so it
    /// conflicts with *any* access to the address, info or slot.
    /// Kept separate from `info_writes` because its conflict radius
    /// is wider.
    pub(crate) destructive: std::collections::HashSet<revm::primitives::Address>,
    /// The merge payload for a validated tx: the transaction's own
    /// `EvmState` — every account the journal loaded, with per-slot
    /// original/present values. The commit phase feeds it through
    /// the same `DatabaseCommit::commit` the serial path uses, so a
    /// validated merge is slot-granular (storage the tx never
    /// touched survives) and create/selfdestruct/zeroing semantics
    /// are identical to sequential execution by construction.
    ///
    /// The coinbase entry is stripped at capture time: its balance
    /// change merges via the additive `coinbase_delta` instead, so
    /// later validators see the canonical running tip total. Fast
    /// paths synthesize equivalent `Account` entries — they only
    /// ever modify `info` (balance, nonce), never storage.
    pub(crate) state: revm::state::EvmState,
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
            slot_reads: std::collections::HashSet::new(),
            info_writes: std::collections::HashSet::new(),
            slot_writes: std::collections::HashSet::new(),
            destructive: std::collections::HashSet::new(),
            state: revm::state::EvmState::default(),
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

/// The slot-granular decomposition of an [`revm::state::EvmState`]
/// diff — the write classes the canonical-order validator tracks
/// separately so that independent slot writes on one account do not
/// force re-execution.
pub(crate) struct WriteSplit {
    /// Every accessed slot (reads and writes — a write implies the
    /// tx observed the slot's pre-write value).
    pub(crate) slot_access:
        std::collections::HashSet<(revm::primitives::Address, revm::primitives::U256)>,
    /// Accounts whose `info` changed, excluding destructive writes.
    pub(crate) info_writes: std::collections::HashSet<revm::primitives::Address>,
    /// Slots where `present_value != original_value`.
    pub(crate) slot_writes:
        std::collections::HashSet<(revm::primitives::Address, revm::primitives::U256)>,
    /// `is_selfdestructed() || is_created_locally()` accounts.
    pub(crate) destructive: std::collections::HashSet<revm::primitives::Address>,
}

/// Split an `EvmState` diff into slot-granular write sets.
///
/// `state` is the journal's post-transaction account map — the exact
/// set of accounts the tx loaded, each with its accessed storage
/// slots (`EvmStorageSlot` records `original_value`/`present_value`,
/// so a pure `SLOAD` shows `present == original` and an `SSTORE`
/// shows the delta).
///
/// `coinbase` is skipped: the fee recipient is tracked through
/// [`CoinbaseObs`]/`coinbase_delta` instead, because every tx writes
/// it and its tip merge is additive.
///
/// `pre_info` resolves the account's pre-transaction `AccountInfo`
/// (group cache for speculation, canonical cache for re-execution).
/// It decides whether an `is_touched` account's write is info-level:
/// a touched account whose balance, nonce, and `code_hash` equal the
/// pre-values — and which is not destructive — changed nothing a
/// parallel tx could have observed, so it registers *no* write at
/// all (a bare EIP-158-style touch is state-neutral for conflict
/// purposes: reads observe identical values whether the empty
/// account survives or is swept).
///
/// # Why this is sound
///
/// A conflict exists iff tx *i* could have observed a value that a
/// canonically-earlier tx *j* changed. revm never mutates `info`
/// without touching the account and never mutates storage without
/// journaling the slot, so:
///
/// - info writes conflict with *info* accesses only — a balance or
///   nonce change cannot move a storage slot, and a slot write
///   cannot change `info`;
/// - slot writes conflict only with accesses to the same
///   `(address, slot)`;
/// - destructive writes conflict with every access to the address —
///   `SELFDESTRUCT`/`CREATE` invalidate the account wholesale.
pub(crate) fn classify_state<'p>(
    state: &revm::state::EvmState,
    coinbase: &revm::primitives::Address,
    pre_info: impl Fn(&revm::primitives::Address) -> Option<&'p revm::database::state::AccountInfo>,
) -> WriteSplit {
    let mut split = WriteSplit {
        slot_access: std::collections::HashSet::new(),
        info_writes: std::collections::HashSet::new(),
        slot_writes: std::collections::HashSet::new(),
        destructive: std::collections::HashSet::new(),
    };
    for (addr, account) in state {
        if addr == coinbase {
            continue;
        }
        for (slot, entry) in &account.storage {
            split.slot_access.insert((*addr, *slot));
            if entry.present_value != entry.original_value {
                split.slot_writes.insert((*addr, *slot));
            }
        }
        if account.is_selfdestructed() || account.is_created_locally() {
            split.destructive.insert(*addr);
            continue;
        }
        if !account.is_touched() {
            continue;
        }
        let changed = match pre_info(addr) {
            Some(pre) => {
                pre.balance != account.info.balance
                    || pre.nonce != account.info.nonce
                    || pre.code_hash != account.info.code_hash
            }
            // Previously-absent account: only counts as an info write
            // if it materialized with visible content. A still-empty
            // touch is state-neutral.
            None => {
                account.info.balance != revm::primitives::U256::ZERO
                    || account.info.nonce != 0
                    || (account.info.code_hash != revm::primitives::KECCAK_EMPTY
                        && account.info.code_hash != revm::primitives::B256::ZERO)
            }
        };
        if changed {
            split.info_writes.insert(*addr);
        }
    }
    split
}
