#![no_main]
//! Fuzz target: OAI types decoding.
//!
//! Every OAI type must never panic on arbitrary byte input —
//! malformed data returns `DecodeError`. This target feeds arbitrary
//! bytes to each OAI type's decoder and asserts no panic. Covers the
//! consensus ⇄ application boundary types (Proposal, Verdict,
//! FinalizedBlock, etc.) that cross trust boundaries.

use codec::{Decode, Reader};
use types::{
    BlockBudget, BlockRecord, CommitAck, FinalizedBlock, MempoolAck, Proposal, StateAttestation,
    TxBytes, Verdict,
};

fn fuzz_decode<T: for<'a> Decode<'a>>(data: &[u8]) {
    let mut reader = Reader::new(data);
    let _ = T::decode(&mut reader);
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    fuzz_decode::<TxBytes>(data);
    fuzz_decode::<BlockBudget>(data);
    fuzz_decode::<Proposal>(data);
    fuzz_decode::<Verdict>(data);
    fuzz_decode::<MempoolAck>(data);
    fuzz_decode::<FinalizedBlock>(data);
    fuzz_decode::<CommitAck>(data);
    fuzz_decode::<StateAttestation>(data);
    fuzz_decode::<BlockRecord>(data);
});
