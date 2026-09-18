//! Native side-effect journal — geth `StateDB`-journal semantics for
//! native-module mutations performed by precompiles.
//!
//! # The problem
//!
//! Oxide native precompiles (e.g. the staking delegate precompile
//! `0x0C_01`) mutate state that lives *outside* the EVM journal — the
//! staking module's delegation ledger. revm checkpoints and reverts
//! only EVM state (accounts/storage — which now includes the balance
//! ledger, since the EVM account store is the single token ledger).
//! Without a
//! parallel undo mechanism, a contract could:
//!
//! 1. `CALL` the delegate precompile (succeeds — stake bonded), then
//! 2. `REVERT` in the same frame (or an ancestor frame reverts),
//!
//! and the stake mutation would survive a call the EVM reports as
//! reverted — the same exploit class as the cosmos-evm precompile
//! incident. Ethereum's own answer is that precompiles mutate the same
//! journaled `StateDB`; our equivalent is this frame-scoped undo log.
//!
//! # The design
//!
//! Execution keeps a per-transaction [`NativeJournal`] shared (via
//! `Rc<RefCell>`) between the [`NativePrecompiles`](crate::precompiles)
//! provider and a [`NativeJournalInspector`]:
//!
//! - `frame_start` increments `depth`; the precompile tags each
//!   mutation it applies with the current depth and pushes a matching
//!   undo closure.
//! - `frame_end` observes the frame's outcome:
//!   - **failure** → pop and run every undo tagged `>= depth`, in
//!     reverse order of application (stack discipline);
//!   - **success** → retag the frame's ops to `depth - 1`, merging
//!     them into the parent's revert scope — exactly how revm's
//!     `checkpoint_commit` merges a frame's journal into its parent.
//!
//! After the root frame ends, ops retagged to depth 0 are committed
//! (the transaction succeeded); on a root failure every op has been
//! undone. The log is drained after each transaction regardless.
//!
//! The inspector runs through revm's `inspect_*` path, which is
//! `transact` with frame/step hooks — validation, gas, and post
//! execution are identical.

use std::cell::RefCell;
use std::rc::Rc;

use revm::context_interface::ContextTr;
use revm::handler::FrameResult;
use revm::inspector::Inspector;
use revm::interpreter::FrameInput;
use revm::interpreter::interpreter::EthInterpreter;

/// A reversible native-state mutation applied by a precompile.
///
/// The closure restores the exact prior state (e.g.
/// `StakingModule::undo_delegate`). Returning `()` keeps the type
/// object-safe; undo failures are module-rejected internally and
/// indicate a journal bug, never user error.
pub type UndoFn = Box<dyn FnOnce()>;

/// Per-transaction log of native mutations tagged by call depth.
///
/// `depth` is the inspector-maintained current frame depth (1 = the
/// transaction's root call/create frame). `ops` is append-only during
/// a frame and drained tail-first on frame failure — mirroring the
/// revm journal's checkpoint semantics.
///
/// Single-threaded by construction: each transaction builds a fresh
/// `Rc<RefCell<NativeJournal>>` inside its own `Evm`; the parallel
/// executor gives each worker its own EVM, so no `Rc` crosses threads.
pub struct NativeJournal {
    /// Current frame depth — `frame_start` +1 / `frame_end` −1.
    depth: usize,
    /// `(depth_at_application, undo)` pairs.
    ops: Vec<(usize, UndoFn)>,
    /// Set when a read-only precompile provider suppressed a mutation
    /// a committed path would have applied (the mutating staking
    /// precompiles revert under `call.read_only`). The parallel
    /// executor reads this after each speculative transaction: a
    /// suppressed mutation means the speculative result is *not* the
    /// committed-path result, so the tx is flagged for canonical
    /// re-execution rather than merged.
    blocked_mutation: bool,
}

impl Default for NativeJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeJournal {
    /// An empty journal for a new transaction.
    #[must_use]
    pub fn new() -> Self {
        Self { depth: 0, ops: Vec::new(), blocked_mutation: false }
    }

    /// Mark that a read-only provider suppressed a native mutation
    /// (called by the mutating precompiles' shared guard). See the
    /// field docs for why the parallel executor depends on it.
    pub fn mark_blocked_mutation(&mut self) {
        self.blocked_mutation = true;
    }

    /// Whether a read-only provider suppressed a mutation during this
    /// transaction.
    #[must_use]
    pub fn blocked_mutation(&self) -> bool {
        self.blocked_mutation
    }

    /// The depth subsequent mutations are tagged with — the frame the
    /// precompile is executing inside.
    #[must_use]
    pub fn current_depth(&self) -> usize {
        self.depth
    }

    /// Record a mutation applied at the current depth.
    pub fn record(&mut self, undo: UndoFn) {
        self.ops.push((self.depth, undo));
    }

    /// Frame `d` ended: on failure undo its ops (and any child ops not
    /// yet merged below `d`); on success merge its ops into `d - 1`.
    fn frame_closed(&mut self, depth: usize, success: bool) {
        if success {
            let parent = depth.saturating_sub(1);
            for (tag, _) in &mut self.ops {
                if *tag == depth {
                    *tag = parent;
                }
            }
            return;
        }
        // Undo newest-first: undos replay in reverse application
        // order, matching journal checkpoint revert.
        while let Some((tag, _)) = self.ops.last() {
            if *tag < depth {
                break;
            }
            let (_, undo) = self.ops.pop().expect("nonempty");
            undo();
        }
    }

    /// Drop all bookkeeping — called after each transaction. Applied
    /// ops are either committed (depth-0 survivors) or already undone.
    /// The blocked flag is reset here too — it is read after the tx
    /// ends, before the next one starts.
    pub fn clear(&mut self) {
        self.ops.clear();
        self.depth = 0;
        self.blocked_mutation = false;
    }
}

/// Inspector implementing frame-scoped undo for native mutations.
///
/// Attached to every execution-path EVM; when no mutating precompile
/// runs, its only cost is two counter updates per frame (the step
/// hooks are empty and inline away).
pub struct NativeJournalInspector {
    /// The transaction's shared undo log (shared with
    /// `NativePrecompiles`).
    journal: Rc<RefCell<NativeJournal>>,
}

impl NativeJournalInspector {
    /// Attach to `journal` — the same `Rc` handed to the precompile
    /// provider.
    #[must_use]
    pub fn new(journal: Rc<RefCell<NativeJournal>>) -> Self {
        Self { journal }
    }
}

impl<CTX> Inspector<CTX, EthInterpreter> for NativeJournalInspector
where
    CTX: ContextTr,
{
    #[inline]
    fn frame_start(
        &mut self,
        _context: &mut CTX,
        frame_input: &mut FrameInput,
    ) -> Option<FrameResult> {
        let _ = frame_input;
        self.journal.borrow_mut().depth += 1;
        None
    }

    #[inline]
    fn frame_end(
        &mut self,
        _context: &mut CTX,
        frame_input: &FrameInput,
        frame_result: &mut FrameResult,
    ) {
        let _ = frame_input;
        let mut journal = self.journal.borrow_mut();
        let depth = journal.depth;
        let success = match frame_result {
            FrameResult::Call(o) => o.result.result.is_ok(),
            FrameResult::Create(o) => o.result.result.is_ok(),
        };
        journal.frame_closed(depth, success);
        journal.depth = depth.saturating_sub(1);
    }
}
