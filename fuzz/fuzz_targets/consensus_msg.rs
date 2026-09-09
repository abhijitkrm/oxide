#![no_main]
//! Fuzz target: consensus message decoding.
//!
//! Consensus messages (Vote, QuorumCertificate, TimeoutCertificate,
//! BlockHeader) cross trust boundaries — they arrive from the
//! network and must never panic on arbitrary byte input. A
//! malformed message returns `DecodeError`, never crashes. This
//! target feeds arbitrary bytes to each consensus message decoder
//! and asserts no panic.
//!
//! Covers the L3 audit finding: consensus message decoders must
//! handle malformed input without panicking.

use codec::{Decode, Reader};
use types::{BlockHeader, QuorumCertificate, TimeoutCertificate, Vote};

fn fuzz_decode<T: for<'a> Decode<'a>>(data: &[u8]) {
    let mut reader = Reader::new(data);
    // The result is intentionally discarded — we only care that
    // decoding never panics on arbitrary input. A `DecodeError` is
    // the correct response to malformed bytes.
    let _ = T::decode(&mut reader);
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    fuzz_decode::<Vote>(data);
    fuzz_decode::<QuorumCertificate>(data);
    fuzz_decode::<TimeoutCertificate>(data);
    fuzz_decode::<BlockHeader>(data);
});
