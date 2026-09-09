#![no_main]
//! Fuzz target: EVM module execution on arbitrary messages.
//!
//! `EvmModule::handle` must never panic on any input — malformed
//! messages return `ExecError::Malformed`, hostile contract
//! deployments burn bounded gas and revert, and the state root
//! stays computable. This target (audit session 24) feeds arbitrary
//! bytes as `Module::handle` messages and drives several blocks,
//! asserting only "no panic" — every error outcome is legal.
//!
//! Found by the audit: the MMR overflow (`peak_positions`) and the
//! types OOM (`Vec::with_capacity` on untrusted counts) were both
//! discovered by fuzzing adjacent surfaces; this target covers the
//! last untested trust boundary — user transactions into the EVM.

use evm::EvmModule;
use executor::{Module, TxContext};
use primitives::Address;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let evm = EvmModule::new(1, 7_000_000_000);

    // The fuzzer controls the whole message: the 20-byte `to`
    // prefix selects call vs. deploy (all-zero ⇒ CREATE), and the
    // remainder is calldata / init code.
    let mut sender = [0u8; 20];
    if data.len() >= 20 {
        // Derive a sender from the input so different inputs create
        // different accounts (exercising multi-account state).
        sender[..20].copy_from_slice(&data[..20]);
    }
    let ctx = TxContext { sender: Address(sender), nonce: 0, fee: 1_000_000_000 };

    // Feed the raw bytes as one message.
    let _ = evm.handle(&ctx, data);

    // Feed it again (nonce 1): re-execution of the same payload
    // must also be safe.
    let ctx1 = TxContext { sender: Address(sender), nonce: 1, fee: 1_000_000_000 };
    let _ = evm.handle(&ctx1, data);

    // Split the input: first half as a deploy, second half as a call.
    if data.len() >= 40 {
        let (deploy, call) = data.split_at(data.len() / 2);
        let ctx2 = TxContext { sender: Address(sender), nonce: 2, fee: 1_000_000_000 };
        let _ = evm.handle(&ctx2, deploy);
        let ctx3 = TxContext { sender: Address(sender), nonce: 3, fee: 1_000_000_000 };
        let _ = evm.handle(&ctx3, call);
    }

    // The state root must be computable after any input sequence
    // (a panic here would poison every downstream consumer).
    let _ = evm.state_root();
});
