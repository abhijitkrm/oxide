#![no_main]
//! Fuzz target: codec decoding.
//!
//! The codec must never panic on any byte input — corrupted data
//! returns `DecodeError`, never crashes. This target feeds arbitrary
//! bytes to every primitive codec decoder and asserts no panic. The
//! property is also tested with proptest in the codec crate, but fuzz
//! explores the input space far more broadly.

use codec::{Decode, Reader};
use primitives::{Address, Hash, Height};

fn fuzz_decode<T: for<'a> Decode<'a>>(data: &[u8]) {
    let mut reader = Reader::new(data);
    // The result is intentionally discarded — we only care that
    // decoding never panics on arbitrary input. A `DecodeError` is the
    // correct response to malformed bytes.
    let _ = T::decode(&mut reader);
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    fuzz_decode::<u8>(data);
    fuzz_decode::<u16>(data);
    fuzz_decode::<u32>(data);
    fuzz_decode::<u64>(data);
    fuzz_decode::<u128>(data);
    fuzz_decode::<bool>(data);
    fuzz_decode::<Hash>(data);
    fuzz_decode::<Address>(data);
    fuzz_decode::<Height>(data);
});
