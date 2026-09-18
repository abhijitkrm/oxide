//! Coinbase-balance observation detection for speculative execution.
//!
//! # The problem
//!
//! Every transaction in a block credits the block's coinbase
//! (fee recipient) with its priority-fee tip. In canonical
//! sequential execution, the coinbase balance a transaction can
//! observe — via the `BALANCE` opcode — equals the pre-block balance
//! plus the tips of *all* preceding transactions, regardless of
//! sender. The parallel executor speculates per-sender groups on
//! copy-on-write snapshots, so a speculative transaction instead
//! sees the pre-block balance plus only the tips of earlier
//! transactions *in its own group*.
//!
//! Ordinary account conflicts are detected by read/write-set
//! intersection, but the coinbase is different: *every* transaction
//! writes it (tips), so tracking it as a normal write would
//! serialize the entire batch. Because tips are additive the writes
//! commute — the only true hazard is a transaction that *reads* the
//! coinbase balance, and the only opcode that exposes another
//! account's balance is `BALANCE` (`0x31`).
//!
//! # The design
//!
//! This inspector watches speculative execution for `BALANCE` whose
//! operand is the coinbase address. When it fires, the transaction
//! is flagged: at commit time its speculative result is only valid
//! if the coinbase balance it observed equals the canonical running
//! balance (pre-block plus every preceding transaction's tip). If
//! they differ the transaction is re-executed against the canonical
//! state — the same fallback any other conflict takes.
//!
//! The inspector is attached only to speculative EVMs
//! (`build_spec_evm`); committed and simulation paths never pay the
//! per-step hook. `CALL`-family transfers *to* the coinbase do not
//! need flagging: they only add balance, and the added value is
//! already captured by the per-transaction tip delta. `SELFDESTRUCT`
//! *to* the coinbase is additive for the same reason — but a contract
//! living *at* the coinbase address selfdestructing is not, and that
//! case is covered by the executor's `coinbase_nontrivial` flag.

use revm::context_interface::ContextTr;
use revm::inspector::Inspector;
use revm::interpreter::Interpreter;
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::interpreter_types::Jumps;
use revm::primitives::{Address, B256};

/// The `BALANCE` opcode (`0x31`): pops an address, pushes that
/// account's balance — the sole instruction that can observe the
/// coinbase's running tip total.
///
/// `EXTCODESIZE`/`EXTCODEHASH`/`EXTCODECOPY` on the coinbase are
/// deliberately not watched here: a mid-block code change at the fee
/// recipient (CREATE2 deployment, or `SELFDESTRUCT` of a contract
/// living there) is a non-additive account write the executor already
/// flags via `coinbase_nontrivial`/`coinbase_dirty`, which re-executes
/// every later tx that touched the account at all.
const OP_BALANCE: u8 = 0x31;

/// Records whether an executing transaction read the coinbase
/// account's balance via `BALANCE`.
///
/// The `step` hook runs before every instruction: on `BALANCE` it
/// compares the stack-top address operand against the coinbase —
/// a handful of nanoseconds against the ~10–100 ns an interpreter
/// step already costs, paid only on the speculative path.
pub struct CoinbaseReadDetector {
    /// The block's fee recipient.
    coinbase: Address,
    /// Set the first time `BALANCE(coinbase)` executes; latches —
    /// once observed, the tx stays flagged for the whole run.
    observed: bool,
}

impl CoinbaseReadDetector {
    /// Watch for `BALANCE` reads of `coinbase`.
    #[must_use]
    pub const fn new(coinbase: Address) -> Self {
        Self { coinbase, observed: false }
    }

    /// Whether the transaction observed the coinbase balance.
    /// Read after `inspect_tx` returns, before the next run.
    #[must_use]
    pub const fn observed(&self) -> bool {
        self.observed
    }
}

impl<CTX> Inspector<CTX, EthInterpreter> for CoinbaseReadDetector
where
    CTX: ContextTr,
{
    #[inline]
    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, _context: &mut CTX) {
        if self.observed || interp.bytecode.opcode() != OP_BALANCE {
            return;
        }
        // `BALANCE`'s operand is the stack top; an empty stack faults
        // inside the instruction itself, so a failed peek is not an
        // observation.
        if let Ok(word) = interp.stack.peek(0) {
            let addr = Address::from_word(B256::from(word));
            if addr == self.coinbase {
                self.observed = true;
            }
        }
    }
}
