//! Oxide blockchain — benchmarks for the `codec` crate: the wire layer
//! every consensus and order message passes through, twice (encode +
//! decode) per hop.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! internal tooling, not published API.
#![allow(missing_docs)]
//!
//! Gates and baselines (source: `.devin/skills/benchmarks` §3; dev Mac,
//! relative claims only until the 16-core `x86_64` rig exists):
//!
//! | Bench                          | Gate (p50) | Baseline                       |
//! |--------------------------------|------------|--------------------------------|
//! | `codec/encode/u64_fixed`       | < 5 ns     | 8-byte memcpy floor            |
//! | `codec/encode/varint_u64_max`  | < 25 ns    | 10-iteration LEB128 loop       |
//! | `codec/decode/varint_u64_max`  | < 20 ns    | same loop, read side           |
//! | `codec/hash_roundtrip`         | < 20 ns    | 32-byte copy floor ×2          |
//! | `codec/order_msg_roundtrip`    | < 80 ns    | ~80B realistic message         |
//! | `vs_bincode/encode/vec_u64_x16`| parity ≤ 2×| head-to-head, same payload     |
//! | `vs_bincode/decode/vec_u64_x16`| parity ≤ 2×| head-to-head, same payload     |
//!
//! The head-to-head against `bincode` is the "prove it was worth
//! building" comparison the benchmarks skill requires: parity is an
//! acceptable result *because* the codec's real wins are determinism
//! by construction, zero-copy borrowed reads, no-alloc encode into a
//! caller-owned buffer, and a dependency tree of exactly one internal
//! crate — none of which bincode offers simultaneously.

use codec::{Decode, Encode, Reader, write};
use criterion::{Criterion, criterion_group, criterion_main};
use primitives::fixed::{Price, Qty};
use primitives::{Address, Hash};
use std::hint::black_box;

/// A realistic order-shaped message (~80B on the wire) — field sizes are
/// what the exchange module will actually send, not round numbers.
struct OrderMsg {
    id: Hash,
    account: Address,
    price: Price,
    qty: Qty,
    nonce: u64,
}

impl Encode for OrderMsg {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.id.encode(buf);
        self.account.encode(buf);
        self.price.encode(buf);
        self.qty.encode(buf);
        self.nonce.encode(buf);
    }
}

impl<'a> Decode<'a> for OrderMsg {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, codec::DecodeError> {
        Ok(OrderMsg {
            id: Hash::decode(reader)?,
            account: Address::decode(reader)?,
            price: Price::decode(reader)?,
            qty: Qty::decode(reader)?,
            nonce: u64::decode(reader)?,
        })
    }
}

/// Wire-encoded wrapper for `Vec<u64>` — the like-for-like payload for
/// the bincode comparison (a length + 16 fixed u64s).
struct WireVecU64(Vec<u64>);

impl Encode for WireVecU64 {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::varint(buf, self.0.len() as u64);
        for v in &self.0 {
            write::u64(buf, *v);
        }
    }
}

impl<'a> Decode<'a> for WireVecU64 {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, codec::DecodeError> {
        let len = reader.read_varint()?;
        // Pre-allocate exactly the wire-declared length: incremental Vec
        // growth costs a reallocation per power of two, which the first
        // bench run measured at 3.5× bincode (devlog session 2, bug n) —
        // capacity closes the gap. try_from: len ≤ remaining input, so
        // this cannot overflow; unwrap_or(0) keeps it lint-clean.
        let mut out = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        for _ in 0..len {
            out.push(reader.read_u64()?);
        }
        Ok(WireVecU64(out))
    }
}

fn bench_wire(c: &mut Criterion) {
    // Framing rule for all encode benches: production callers reuse one
    // caller-owned warm buffer per message stream — the codec's API is
    // write-into-buffer by design. Buffers are therefore allocated once
    // outside timing and `clear()`ed inside it (the honest cost of
    // reuse); neither fresh allocations nor first-touch cache misses are
    // part of the codec's budget (devlog session 2, bug n).
    let mut u64_buf = Vec::with_capacity(8);
    c.bench_function("codec/encode/u64_fixed", |b| {
        b.iter(|| {
            u64_buf.clear();
            write::u64(&mut u64_buf, black_box(u64::MAX));
            black_box(&u64_buf);
        });
    });

    let mut varint_enc_buf = Vec::with_capacity(10);
    c.bench_function("codec/encode/varint_u64_max", |b| {
        b.iter(|| {
            varint_enc_buf.clear();
            write::varint(&mut varint_enc_buf, black_box(u64::MAX));
            black_box(&varint_enc_buf);
        });
    });

    // Worst-case varint decode: all 10 bytes present, full shift chain.
    let mut varint_buf = Vec::with_capacity(10);
    write::varint(&mut varint_buf, u64::MAX);
    c.bench_function("codec/decode/varint_u64_max", |b| {
        b.iter(|| {
            let mut r = Reader::new(black_box(&varint_buf));
            black_box(r.read_varint().unwrap())
        });
    });

    let hash = Hash([0xab; 32]);
    // Production shape: one caller-owned buffer, reused every message;
    // `clear()` (the cost of reuse) is inside the timing, allocation
    // never is. This is the number the budget comment refers to.
    let mut hash_buf = Vec::with_capacity(32);
    c.bench_function("codec/hash_roundtrip", |b| {
        b.iter(|| {
            hash_buf.clear();
            black_box(&hash).encode(&mut hash_buf);
            let mut r = Reader::new(&hash_buf);
            black_box(Hash::decode(&mut r).unwrap())
        });
    });

    let order = OrderMsg {
        id: Hash([0x11; 32]),
        account: Address([0x22; 20]),
        price: Price(125_000_000),
        qty: Qty(2_500_000),
        nonce: 7,
    };
    // Same production shape as hash_roundtrip: reused warm buffer.
    let mut order_buf = Vec::with_capacity(80);
    c.bench_function("codec/order_msg_roundtrip", |b| {
        b.iter(|| {
            order_buf.clear();
            black_box(&order).encode(&mut order_buf);
            let mut r = Reader::new(&order_buf);
            black_box(OrderMsg::decode(&mut r).unwrap())
        });
    });

    // Head-to-head: identical Vec<u64> payload through our codec and
    // through bincode (the standard Rust binary codec). Framing note,
    // stated honestly: our encode writes into a caller-owned buffer
    // (no allocation beyond that buffer), bincode's encode_to_vec
    // allocates its result Vec; both decodes allocate the output Vec.
    // Knuth's multiplicative constant gives the payload non-trivial bit
    // patterns; u64 range from the start so no casts appear anywhere.
    let payload: Vec<u64> = (0..16u64).map(|i| i * 2_654_435_761).collect();

    // Ours: reused warm buffer, payload cloned once outside timing —
    // the timed routine is purely clear + encode.
    let vec_msg = WireVecU64(payload.clone());
    let mut vec_buf = Vec::with_capacity(16 * 8 + 1);
    c.bench_function("vs_bincode/encode/vec_u64_x16", |b| {
        b.iter(|| {
            vec_buf.clear();
            vec_msg.encode(&mut vec_buf);
            black_box(&vec_buf);
        });
    });
    c.bench_function("vs_bincode/encode_bincode/vec_u64_x16", |b| {
        b.iter(|| {
            black_box(
                bincode::encode_to_vec(black_box(&payload), bincode::config::standard()).unwrap(),
            )
        });
    });
    let mut our_buf = Vec::with_capacity(16 * 8 + 1);
    WireVecU64(payload.clone()).encode(&mut our_buf);
    let bincode_buf = bincode::encode_to_vec(&payload, bincode::config::standard()).unwrap();
    c.bench_function("vs_bincode/decode/vec_u64_x16", |b| {
        b.iter(|| {
            let mut r = Reader::new(black_box(&our_buf));
            black_box(WireVecU64::decode(&mut r).unwrap())
        });
    });
    c.bench_function("vs_bincode/decode_bincode/vec_u64_x16", |b| {
        b.iter(|| {
            black_box(bincode::decode_from_slice::<Vec<u64>, _>(
                black_box(&bincode_buf),
                bincode::config::standard(),
            ))
            .unwrap()
        });
    });
}

criterion_group!(benches, bench_wire);
criterion_main!(benches);
