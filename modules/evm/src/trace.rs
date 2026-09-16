//! Call-frame recording for the `debug_trace*` namespace.
//!
//! # The problem
//!
//! `debug_traceTransaction` needs the tx's pre-state to re-execute —
//! and Oxide keeps no archive trie (the `CacheDB` holds latest state
//! only, and there is no height-versioned store). A non-archive geth
//! node answers the same situation with `missing trie node`.
//!
//! Instead of archive state, Oxide records the call tree *at
//! execution time*: every committed transaction already runs through
//! the `inspect_*` path (the native-side-effect journal needs frame
//! hooks — see `native_journal.rs`), so a second inspector composed
//! in a tuple captures each frame's inputs and outcome while it is
//! still in scope. `debug_traceTransaction` then becomes a history
//! lookup — deterministic by construction (the trace *is* what
//! executed, not a re-execution that could diverge), bounded by the
//! same 8192-block retention window the rest of history obeys.
//!
//! # Output shape
//!
//! [`CallFrame`] mirrors geth's `callTracer` result: `type`, `from`,
//! `to`, `value`, `gas`, `gasUsed`, `input`, `output`/`error` (plus
//! `revertReason` when the revert data is an ABI `Error(string)`),
//! and the nested `calls` array. The recorded `gas`/`gasUsed` are
//! *frame-scoped* (post-intrinsic deduction); the RPC layer patches
//! the root frame with the tx-level values from the stored receipt,
//! matching geth's callTracer output.
//!
//! # Cost
//!
//! The `call`/`create` hooks push one [`CallFrame`] per frame and
//! clone the frame's input/output bytes; `step`/`step_end` are
//! empty and inline away. On the committed path this is one small
//! allocation per call frame — the same order as the native journal's
//! per-frame counter updates plus the bytes clones. There is no
//! per-opcode work: a simple transfer records a single root frame.

use revm::context_interface::ContextTr;
use revm::inspector::Inspector;
use revm::interpreter::interpreter::EthInterpreter;
use revm::interpreter::{CallOutcome, CallScheme, CreateOutcome, CreateScheme};
use revm::primitives::{Address, Bytes, U256};

/// One frame of a call tree — geth `callTracer` output shape.
///
/// Populated by [`CallRecorder`]: `kind`/`from`/`to`/`value`/`input`/
/// `gas_limit` at `call`/`create` (frame entry), `gas_used`/`output`/
/// `error` at `call_end`/`create_end` (frame exit). Children nest in
/// `calls` in execution order.
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// geth callTracer `type`: `"CALL"`, `"CALLCODE"`,
    /// `"DELEGATECALL"`, `"STATICCALL"`, `"CREATE"`, or `"CREATE2"`.
    pub kind: &'static str,
    /// The frame's caller (tx sender for the root).
    pub from: Address,
    /// The callee. For CREATE/CREATE2 this is the deployed address,
    /// known only at `create_end` — `None` until then.
    pub to: Option<Address>,
    /// Wei carried into the frame (`apparent` value for
    /// DELEGATECALL — what `CALLVALUE` would read, matching geth).
    pub value: U256,
    /// Gas allocated to the frame (post-63/64-rule).
    pub gas_limit: u64,
    /// Gas the frame actually spent (filled at frame end).
    pub gas_used: u64,
    /// Calldata (calls) or init code (creates).
    pub input: Bytes,
    /// Returned bytes on success; revert/halt payload otherwise.
    pub output: Bytes,
    /// Failure description (`"execution reverted"`, `"OutOfGas"`, …)
    /// — `None` on success. Decoded ABI `Error(string)` reason goes
    /// to [`CallFrame::revert_reason`].
    pub error: Option<String>,
    /// Decoded ABI `Error(string)` payload when the frame reverted
    /// with one — geth's `revertReason` field.
    pub revert_reason: Option<String>,
    /// Child frames in execution order.
    pub calls: Vec<CallFrame>,
}

/// Per-transaction call-tree recorder.
///
/// The inspector sees every frame — including the transaction's
/// root call/create — because `frame_start` dispatches to
/// `call`/`create` for the root `FrameInput` too. `call` pushes an
/// in-flight frame onto `stack`; `call_end` pops it, fills the
/// outcome, and reattaches it to the parent — or to `root` when the
/// stack is empty.
///
/// Reentrancy and halts need no special handling: revm runs
/// `call_end`/`create_end` for every frame it opened, including
/// frames unwound by an ancestor's failure, so the stack stays
/// balanced.
#[derive(Debug, Default)]
pub struct CallRecorder {
    /// In-flight frames, innermost last.
    stack: Vec<CallFrame>,
    /// The completed root frame once the outermost `call_end` fires.
    root: Option<CallFrame>,
}

impl CallRecorder {
    /// Fresh recorder — one per transaction (built inside the EVM).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take the completed root frame, leaving the recorder empty for
    /// the next transaction. `None` means no frame ran (pre-execution
    /// rejection — the tx never reached a call/create frame).
    pub fn take_root(&mut self) -> Option<CallFrame> {
        self.stack.clear();
        self.root.take()
    }

    /// Push a just-opened frame.
    fn enter(&mut self, frame: CallFrame) {
        self.stack.push(frame);
    }

    /// Close the innermost frame and attach it to its parent (or to
    /// `root` at depth zero).
    fn exit(&mut self, frame: CallFrame) {
        if let Some(parent) = self.stack.last_mut() {
            parent.calls.push(frame);
        } else {
            self.root = Some(frame);
        }
    }
}

/// Map a [`CallScheme`] to the geth callTracer `type` string.
const fn call_kind(scheme: CallScheme) -> &'static str {
    match scheme {
        CallScheme::Call => "CALL",
        CallScheme::CallCode => "CALLCODE",
        CallScheme::DelegateCall => "DELEGATECALL",
        CallScheme::StaticCall => "STATICCALL",
    }
}

/// Map a [`CreateScheme`] to the geth callTracer `type` string.
const fn create_kind(scheme: &CreateScheme) -> &'static str {
    match scheme {
        CreateScheme::Create => "CREATE",
        CreateScheme::Create2 { .. } => "CREATE2",
        // `Custom` is the chain-defined create scheme — no geth
        // callTracer string exists; report the opcode name honestly.
        CreateScheme::Custom { .. } => "CUSTOMCREATE",
    }
}

/// Decode an ABI `Error(string)` revert payload — selector
/// `0x08c379a0` followed by a `(string)` ABI encoding — into the
/// reason string geth reports as `revertReason`.
fn decode_revert_reason(output: &[u8]) -> Option<String> {
    const ERROR_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];
    if output.len() < 4 + 32 + 32 || output[..4] != ERROR_SELECTOR {
        return None;
    }
    // ABI string: [selector][offset:32][len:32][data…]. The offset
    // is always 0x20 for a single-argument error; skip it.
    let len_bytes: [u8; 4] = output[4 + 32 + 28..4 + 32 + 32].try_into().ok()?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let start = 4 + 32 + 32;
    if output.len() < start + len {
        return None;
    }
    String::from_utf8(output[start..start + len].to_vec()).ok()
}

/// Fill a frame's outcome fields from the interpreter result —
/// shared by `call_end` and `create_end`.
fn apply_outcome(
    frame: &mut CallFrame,
    result: revm::interpreter::InstructionResult,
    output: &Bytes,
    gas_used: u64,
) {
    frame.gas_used = gas_used;
    if result.is_ok() {
        frame.output = output.clone();
    } else if result.is_revert() {
        frame.error = Some("execution reverted".to_string());
        frame.output = output.clone();
        frame.revert_reason = decode_revert_reason(output);
    } else {
        // Halts (OOG, stack overflow, invalid opcode, …) carry no
        // return data geth would surface — `output` stays empty and
        // `error` names the halt.
        frame.error = Some(format!("{result:?}"));
    }
}

impl<CTX> Inspector<CTX, EthInterpreter> for CallRecorder
where
    CTX: ContextTr,
{
    #[inline]
    fn call(
        &mut self,
        context: &mut CTX,
        inputs: &mut revm::interpreter::CallInputs,
    ) -> Option<CallOutcome> {
        // `input.as_bytes` resolves SharedBuffer inputs against the
        // context's shared memory — the same bytes the callee will
        // execute.
        let input = inputs.input.as_bytes(context).to_vec().into();
        self.enter(CallFrame {
            kind: call_kind(inputs.scheme),
            from: inputs.caller,
            // `target_address` is the storage-owning callee; for
            // DELEGATECALL the code lives at `bytecode_address` while
            // the state target is the contract being delegated into —
            // geth's callTracer reports `target_address` as `to`.
            to: Some(inputs.target_address),
            value: inputs.value.get(),
            gas_limit: inputs.gas_limit,
            gas_used: 0,
            input,
            output: Bytes::new(),
            error: None,
            revert_reason: None,
            calls: Vec::new(),
        });
        // `None` = observe only; overriding the frame's outcome is
        // what geth's `txExecEnv`-style interception would do, and a
        // tracer must never change execution.
        None
    }

    #[inline]
    fn call_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &revm::interpreter::CallInputs,
        outcome: &mut CallOutcome,
    ) {
        let Some(mut frame) = self.stack.pop() else {
            // Unbalanced end hook — should be impossible (revm pairs
            // every open with a close); drop rather than corrupt the
            // tree.
            return;
        };
        apply_outcome(
            &mut frame,
            outcome.result.result,
            &outcome.result.output,
            outcome.result.gas.total_gas_spent(),
        );
        self.exit(frame);
    }

    #[inline]
    fn create(
        &mut self,
        _context: &mut CTX,
        inputs: &mut revm::interpreter::CreateInputs,
    ) -> Option<CreateOutcome> {
        self.enter(CallFrame {
            kind: create_kind(&inputs.scheme()),
            from: inputs.caller(),
            to: None,
            value: inputs.value(),
            gas_limit: inputs.gas_limit(),
            gas_used: 0,
            input: inputs.init_code().clone(),
            output: Bytes::new(),
            error: None,
            revert_reason: None,
            calls: Vec::new(),
        });
        None
    }

    #[inline]
    fn create_end(
        &mut self,
        _context: &mut CTX,
        _inputs: &revm::interpreter::CreateInputs,
        outcome: &mut CreateOutcome,
    ) {
        let Some(mut frame) = self.stack.pop() else { return };
        frame.to = outcome.address;
        apply_outcome(
            &mut frame,
            outcome.result.result,
            &outcome.result.output,
            outcome.result.gas.total_gas_spent(),
        );
        self.exit(frame);
    }
}
