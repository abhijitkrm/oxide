//! Fuzz target: state sync protocol decode.
//!
//! Fuzzes the `p2p::sync` decode paths: `SyncRequest::decode`,
//! `SyncResponse::decode`, and `ChunkResponse::decode`. These are
//! the wire-format entry points for the state sync protocol — any
//! input must either decode successfully or return an error, never
//! panic.

#![no_main]

use libfuzzer_sys::{Corpus, fuzz_target};

fuzz_target!(|data: &[u8]| -> Corpus {
    // Try decoding as a SyncRequest.
    let _ = p2p::sync::SyncRequest::decode(data);

    // Try decoding as a SyncResponse.
    let _ = p2p::sync::SyncResponse::decode(data);

    // Try decoding as a ChunkResponse.
    let _ = p2p::sync::ChunkResponse::decode(data);

    Corpus::Keep
});
