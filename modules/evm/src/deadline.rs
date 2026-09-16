//! Wall-clock execution deadline for read-only simulations.
//!
//! geth's `--rpc.evmtimeout` (default 5s) bounds how long
//! `eth_call`/`eth_estimateGas`/`eth_createAccessList`/
//! `debug_traceCall` may run: a hostile or pathological contract can
//! burn the entire gas cap in loops, and without a wall-clock bound
//! every such request holds the state lock for its full gas budget.
//!
//! geth implements this with a cancel flag the interpreter checks
//! between instructions. The revm equivalent is an `Inspector::step`
//! hook that calls [`Interpreter::halt`] once the deadline passes —
//! the interpreter unwinds exactly like geth's `evm.Cancel()` path.
//!
//! # Why a deadline check every N steps
//!
//! `Instant::now()` is a vdso clock read (~20 ns). Checking it on
//! every opcode would add ~20 ns/step — meaningful on a 30M-gas
//! simulation. Checking every [`CHECK_INTERVAL`] steps amortizes the
//! read to ~0.02 ns/step while bounding the overshoot: at ~50
//! gas/step average, 1024 steps is well under a millisecond of
//! overrun on a 5-second deadline — noise.
//!
//! # Determinism
//!
//! This inspector is composed **only** on the read-only simulation
//! path (`simulate` → `eth_call`/`eth_estimateGas`/`eth_createAccessList`/
//! `debug_traceCall`). Committed consensus execution never carries a
//! wall clock — halting on time there would be nondeterministic.

use std::time::Instant;

use revm::context_interface::ContextTr;
use revm::inspector::Inspector;
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::{InstructionResult, Interpreter};

/// Steps between wall-clock checks inside the interpreter loop.
///
/// 1024 opcodes at typical per-step cost (~3–20 gas each, ~10–100 ns
/// each) is ≪1 ms of granularity — far finer than the 5 s deadline it
/// guards — while amortizing the clock read to ~0.02 ns/step.
const CHECK_INTERVAL: u32 = 1024;

/// An [`Inspector`] that halts the interpreter once a wall-clock
/// deadline passes.
///
/// On expiry it calls `interpreter.halt(InstructionResult::OutOfGas)`
/// and sets [`timed_out`](Self::timed_out) so the caller can
/// distinguish the deadline from a genuine out-of-gas. `OutOfGas` is
/// the honest halt class here: geth consumes the full gas allowance
/// on a deadline abort (nothing is refunded), and the remaining
/// variants are either internal-only (`FatalExternalError` panics in
/// post-execution) or lie about *what* failed (stack underflow,
/// invalid jump, …). Callers check [`timed_out`](Self::timed_out)
/// before mapping the halt to the user-facing "execution timed out".
pub struct DeadlineInspector {
    /// The wall-clock instant after which execution is aborted.
    deadline: Instant,
    /// Opcodes seen since the last clock read — bounds the deadline
    /// overshoot to `CHECK_INTERVAL` steps (see module docs).
    steps_since_check: u32,
    /// Whether the deadline fired. Read by `simulate` after
    /// `inspect_tx` returns so the timeout surfaces as its own
    /// error rather than a generic halt.
    timed_out: bool,
}

impl DeadlineInspector {
    /// Create an inspector that halts at `deadline`.
    #[must_use]
    pub const fn new(deadline: Instant) -> Self {
        Self { deadline, steps_since_check: 0, timed_out: false }
    }

    /// Whether the deadline fired (i.e. the resulting halt is a
    /// timeout, not an execution error).
    #[must_use]
    pub const fn timed_out(&self) -> bool {
        self.timed_out
    }
}

impl<CTX> Inspector<CTX, EthInterpreter> for DeadlineInspector
where
    CTX: ContextTr,
{
    #[inline]
    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        self.steps_since_check = self.steps_since_check.wrapping_add(1);
        if self.steps_since_check >= CHECK_INTERVAL {
            self.steps_since_check = 0;
            if Instant::now() >= self.deadline {
                self.timed_out = true;
                interp.halt(InstructionResult::OutOfGas);
            }
        }
    }
}
