#![no_main]
//! Fuzz target: the accept-side P2P handshake over arbitrary bytes.
//!
//! These parsers (greeting decode, proof decode, frame length caps)
//! run before a peer has proven anything, so they must survive any
//! input: never panic, never allocate past the handshake frame cap,
//! and never admit a peer whose proof does not verify. The seam's
//! auth rejects every proof, so admission here is always a bug.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    assert!(!p2p::tcp::fuzz_acceptor_handshake(data), "unverified peer admitted");
});
