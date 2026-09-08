//! Deterministic wire codec for every message in the Oxide blockchain.
//!
//! ## What this crate is
//!
//! A small, hand-rolled binary format plus [`Encode`]/[`Decode`] traits:
//! fixed-width **little-endian** integers, **LEB128** varints,
//! varint-length-prefixed byte strings, and strict booleans — layered on
//! [`Reader`] (a zero-copy cursor) and plain `Vec<u8>` writing.
//!
//! ## Why hand-rolled (why not serde/protobuf)
//!
//! 1. **Determinism is consensus.** Two validators must produce
//!    byte-identical encodings of the same value or they compute
//!    different state roots and fork. serde's default behaviors (map
//!    iteration order, `skip_serializing_if`, feature flags) are
//!    reproducible *per build*, not *per ecosystem* — an unacceptable
//!    ambiguity class for chain data.
//! 2. **Hot-path budget.** No trait objects, no reflection, no alloc on
//!    decode of borrowed data (the `performance-first` skill, §"No `dyn`,
//!    no serde"). Encoding is a sequence of `extend_from_slice`s.
//! 3. **Auditability.** The entire wire language fits in one file; every
//!    rule is testable without generated code.
//!
//! ## Wire rules (the whole format)
//!
//! | Construct        | Encoding                                             |
//! |------------------|------------------------------------------------------|
//! | `u8/u16/u32/u64/u128` | fixed-width, little-endian                    |
//! | varint (`u64`)   | LEB128: 7 bits/byte, high bit = "more"; ≤ 10 bytes  |
//! | bytes            | varint length prefix + raw bytes (borrowed on read) |
//! | fixed arrays     | raw bytes, no prefix (length is in the type)        |
//! | `bool`           | exactly `0x00` or `0x01` (anything else → error)    |
//!
//! ## Invariants
//!
//! - `decode(encode(x)) == x` for every [`Codec`] type (property-tested).
//! - Decoding **never panics** on any byte input; corrupted data returns
//!   [`DecodeError`] (fuzz-tested).
//! - No floats on the wire (see `primitives` for the rationale).

use primitives::fixed::{Price, Qty};
use primitives::{Address, Hash, Id, IdSpace, TimestampMs};
use std::fmt;

/// Every way decoding structured data from bytes can fail.
///
/// Variants are split so trust boundaries (gateway, p2p ingress) can
/// distinguish *malicious framing* from a *truncated tail* (the latter is
/// expected during journal crash recovery; the former is a peer to
/// penalize — see `production-rust` skill §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended before a complete value was read.
    UnexpectedEof {
        /// How many more bytes the value needed.
        needed: usize,
        /// Bytes actually remaining.
        remaining: usize,
    },
    /// A varint exceeded 10 bytes or its final byte carried set bits
    /// beyond `u64`'s range — not a length issue, a *malformed* varint.
    InvalidVarint,
    /// A length prefix pointed past the end of the input.
    LengthPrefixTooLarge {
        /// Length the prefix claimed.
        claimed: u64,
        /// Bytes actually remaining after the prefix.
        remaining: u64,
    },
    /// A boolean byte was neither `0x00` nor `0x01`.
    InvalidBool {
        /// The offending byte.
        got: u8,
    },
    /// A fixed-width type received the wrong number of bytes
    /// (re-exported shape from `primitives`).
    WrongSliceLength {
        /// Length the type requires.
        expected: usize,
        /// Length the input actually had.
        got: usize,
    },
    /// A byte string that must be valid UTF-8 (e.g. an OAI rejection
    /// reason) contained invalid UTF-8. Surfaced at trust boundaries as a
    /// peer-to-penalize framing error, not a truncation.
    InvalidUtf8,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DecodeError::UnexpectedEof { needed, remaining } => {
                write!(f, "unexpected end of input: needed {needed} more bytes, {remaining} remain")
            }
            DecodeError::InvalidVarint => {
                write!(f, "malformed varint (overlong or out-of-range final byte)")
            }
            DecodeError::LengthPrefixTooLarge { claimed, remaining } => {
                write!(f, "length prefix {claimed} exceeds remaining input {remaining}")
            }
            DecodeError::InvalidBool { got } => {
                write!(f, "boolean byte must be 0x00 or 0x01, got {got:#04x}")
            }
            DecodeError::WrongSliceLength { expected, got } => {
                write!(f, "slice length {got} != required {expected}")
            }
            DecodeError::InvalidUtf8 => {
                write!(f, "byte string contained invalid UTF-8")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Zero-copy decoding cursor over a borrowed buffer.
///
/// Positions only move forward; every read either returns a complete
/// value or leaves a precise [`DecodeError`]. No allocation happens in
/// any [`Reader`] method — borrowed data is returned as subslices.
pub struct Reader<'a> {
    /// Not-yet-consumed bytes.
    buf: &'a [u8],
}

// `missing_errors_doc` is silenced for this impl block deliberately:
// every method returns `DecodeError` only, and the enum's own docs are
// the exhaustive, canonical description of each failure mode (the
// per-method docs say *which* variant). Repeating a `# Errors` section
// ten times would duplicate the enum docs verbatim — a comment
// maintenance hazard, not documentation.
#[allow(clippy::missing_errors_doc)]
impl<'a> Reader<'a> {
    /// Begin reading `buf` from its start.
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// True once every input byte has been consumed. Protocols call this
    /// after a full message to reject trailing garbage (a common
    /// framing-slash tactic).
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Take exactly `n` bytes, erroring precisely if fewer remain.
    ///
    /// Public because types sized at runtime (e.g. via [`Fixed::LEN`])
    /// need slice-level access; array-sized callers prefer
    /// [`Reader::read_fixed`].
    pub fn read_slice(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            // needed/remaining rather than a bare EOF: callers at trust
            // boundaries log how short the peer's message was.
            return Err(DecodeError::UnexpectedEof { needed: n, remaining: self.buf.len() });
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// Read one byte.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_slice(1)?[0])
    }

    /// Read a little-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.read_slice(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a little-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.read_slice(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.read_slice(8)?;
        Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// Read a little-endian `u128`.
    pub fn read_u128(&mut self) -> Result<u128, DecodeError> {
        let b = self.read_slice(16)?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(b);
        Ok(u128::from_le_bytes(arr))
    }

    /// Read a strict boolean (`0x00` = false, `0x01` = true).
    ///
    /// Strictness is deliberate: any other byte is attacker-chosen
    /// ambiguity about which validators saw which truth value.
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(DecodeError::InvalidBool { got: other }),
        }
    }

    /// Read a LEB128 varint (`u64`).
    ///
    /// Rejects varints longer than 10 bytes or with out-of-range bits in
    /// the final byte, so a peer can't spend 100 bytes making us "decode"
    /// a 64-bit number (a cheap `DoS`) — see `InvalidVarint`.
    pub fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        // 10 bytes × 7 bits = 70 bits ≥ 64; the loop bounds are part of
        // the wire contract, not an implementation detail.
        for byte_index in 0..10 {
            let byte = self.read_u8()?;
            let payload = u64::from(byte & 0x7f);
            if byte_index == 9 {
                // Final allowed byte: only bit 63 may be set, and the
                // continuation flag must be clear.
                if byte & 0xfe != 0 {
                    return Err(DecodeError::InvalidVarint);
                }
                return Ok(value | payload << shift);
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        // Unreachable: the byte_index == 9 branch always returns.
        Err(DecodeError::InvalidVarint)
    }

    /// Read a length-prefixed byte string, returning a **borrowed**
    /// subslice (zero-copy; valid for the lifetime of the input).
    pub fn read_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let claimed = self.read_varint()?;
        let remaining = self.buf.len() as u64;
        if claimed > remaining {
            return Err(DecodeError::LengthPrefixTooLarge { claimed, remaining });
        }
        // claimed ≤ remaining ≤ usize::MAX by the check above, so this
        // conversion cannot lose information; the map_err exists to make
        // that invariant explicit to the compiler (and to a reviewer)
        // rather than relying on an `as` cast.
        let n = usize::try_from(claimed)
            .map_err(|_| DecodeError::LengthPrefixTooLarge { claimed, remaining })?;
        self.read_slice(n)
    }

    /// Read exactly `N` bytes into a fixed array (no prefix; the length
    /// lives in the type).
    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let b = self.read_slice(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(b);
        Ok(arr)
    }
}

/// Write-side helpers: deterministic encodings into a growing `Vec<u8>`.
///
/// Free functions (not a trait) so composite `Encode` impls read as a
/// literal script of the wire format — the encoding *is* the spec.
pub mod write {
    /// Append a `u8`.
    pub fn u8(buf: &mut Vec<u8>, v: u8) {
        buf.push(v);
    }

    /// Append a little-endian `u16`.
    pub fn u16(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `u32`.
    pub fn u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    pub fn u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a little-endian `u128`.
    pub fn u128(buf: &mut Vec<u8>, v: u128) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Append a strict boolean (`0x00`/`0x01`).
    pub fn bool(buf: &mut Vec<u8>, v: bool) {
        buf.push(u8::from(v));
    }

    /// Append a LEB128 varint (`u64`): 7 bits per byte, high bit set
    /// while more bytes follow. At most 10 bytes — the read side
    /// enforces the bound.
    pub fn varint(buf: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                buf.push(byte);
                break;
            }
            buf.push(byte | 0x80);
        }
    }

    /// Append a length-prefixed byte string (varint length + raw bytes).
    pub fn bytes(buf: &mut Vec<u8>, v: &[u8]) {
        varint(buf, v.len() as u64);
        buf.extend_from_slice(v);
    }

    /// Append a fixed array verbatim (no prefix).
    pub fn fixed<const N: usize>(buf: &mut Vec<u8>, v: &[u8; N]) {
        buf.extend_from_slice(v);
    }
}

/// A type that can serialize itself deterministically into `buf`.
pub trait Encode {
    /// Append the wire form of `self` to `buf`.
    fn encode(&self, buf: &mut Vec<u8>);
}

/// A type that can deserialize itself from a [`Reader`].
///
/// Generic over the input lifetime so borrows (e.g. [`Reader::read_bytes`])
/// flow through; owned types simply ignore the parameter.
pub trait Decode<'a>: Sized {
    /// Read one value, advancing `reader` past exactly its wire bytes.
    ///
    /// # Errors
    /// Any [`DecodeError`] describing the first malformed byte sequence
    /// encountered; the reader position after an error is unspecified
    /// (callers treat the whole message as invalid, never partially
    /// decoded — there is no "resync" in a length-framed protocol).
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError>;
}

/// Shorthand for the round-trip contract: encodable and decodable.
pub trait Codec<'a>: Encode + Decode<'a> {}
impl<'a, T> Codec<'a> for T where T: Encode + Decode<'a> {}

// ---------------------------------------------------------------------------
// Primitive impls
// ---------------------------------------------------------------------------

impl Encode for u8 {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u8(buf, *self);
    }
}

impl<'a> Decode<'a> for u8 {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        reader.read_u8()
    }
}

impl Encode for u16 {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u16(buf, *self);
    }
}

impl<'a> Decode<'a> for u16 {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        reader.read_u16()
    }
}

impl Encode for u32 {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u32(buf, *self);
    }
}

impl<'a> Decode<'a> for u32 {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        reader.read_u32()
    }
}

impl Encode for u64 {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u64(buf, *self);
    }
}

impl<'a> Decode<'a> for u64 {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        reader.read_u64()
    }
}

impl Encode for u128 {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u128(buf, *self);
    }
}

impl<'a> Decode<'a> for u128 {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        reader.read_u128()
    }
}

impl Encode for bool {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::bool(buf, *self);
    }
}

impl<'a> Decode<'a> for bool {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        reader.read_bool()
    }
}

/// Owned byte strings: varint length + raw bytes. Allocating on decode
/// is acceptable here — byte-string *values* are cold-path payloads
/// (transaction bodies are borrowed at the framing layer instead).
impl Encode for Vec<u8> {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::bytes(buf, self);
    }
}

impl<'a> Decode<'a> for Vec<u8> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(reader.read_bytes()?.to_vec())
    }
}

// Fixed-width domain types serialize verbatim — the length lives in the
// type, so no prefix. These impls are deliberately *concrete* (Hash,
// Address) rather than a blanket `impl<T: Fixed>`: rustc rejects the
// blanket form next to `impl Encode for u8`, because the upstream crate
// could someday add `Fixed` for `u8` (E0119 "future overlap"). Two
// explicit impls per type are the price of a stable coherence story.

impl Encode for Hash {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl<'a> Decode<'a> for Hash {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let bytes = reader.read_slice(Hash::LEN)?;
        // from_slice re-checks the length; the mapping keeps error types
        // in this crate's vocabulary at trust boundaries.
        Hash::from_slice(bytes)
            .map_err(|e| DecodeError::WrongSliceLength { expected: e.expected, got: e.got })
    }
}

impl Encode for Address {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
    }
}

impl<'a> Decode<'a> for Address {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let bytes = reader.read_slice(Address::LEN)?;
        Address::from_slice(bytes)
            .map_err(|e| DecodeError::WrongSliceLength { expected: e.expected, got: e.got })
    }
}

/// Consensus counters travel as fixed `u64`s (they're compared and
/// merkleized constantly; the 4–9 byte varint saving isn't worth the
/// decode branching on the consensus hot path).
impl<T: IdSpace> Encode for Id<T> {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u64(buf, self.0);
    }
}

impl<'a, T: IdSpace> Decode<'a> for Id<T> {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Id::new(reader.read_u64()?))
    }
}

impl Encode for TimestampMs {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u64(buf, self.0);
    }
}

impl<'a> Decode<'a> for TimestampMs {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(TimestampMs(reader.read_u64()?))
    }
}

/// Fixed-point values travel as raw `u64`s: their scales are part of
/// the *type*, so the wire never carries them (and can never disagree
/// with them).
impl Encode for Price {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u64(buf, self.0);
    }
}

impl<'a> Decode<'a> for Price {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Price(reader.read_u64()?))
    }
}

impl Encode for Qty {
    fn encode(&self, buf: &mut Vec<u8>) {
        write::u64(buf, self.0);
    }
}

impl<'a> Decode<'a> for Qty {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Qty(reader.read_u64()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::{Address, Epoch, Hash, Height, View};

    /// Deterministic encoding: same value → identical bytes, twice.
    ///
    /// The `for<'b>` bound (HRTB) ties decode's borrow to the *local*
    /// buffer: owned types implement `Codec` for every lifetime, so this
    /// both type-checks and asserts the owned round-trip contract.
    fn assert_roundtrip<T>(value: &T, wire: &[u8])
    where
        T: for<'b> Codec<'b> + PartialEq + std::fmt::Debug + Clone,
    {
        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(buf, wire, "encoding must match the documented wire form");
        // Encode a second time: byte-identical (the consensus contract).
        let mut again = Vec::new();
        value.encode(&mut again);
        assert_eq!(buf, again);
        let mut r = Reader::new(&buf);
        let decoded = T::decode(&mut r).expect("round-trip decode");
        assert_eq!(&decoded, value, "decode(encode(x)) == x");
        assert!(r.is_empty(), "decode must consume exactly its own bytes");
    }

    /// The wire table in the crate docs is load-bearing: each construct
    /// matches its documented bytes exactly.
    #[test]
    fn test_wire_format_matches_spec() {
        assert_roundtrip(&0x01u8, &[0x01]);
        assert_roundtrip(&0x0203u16, &[0x03, 0x02]);
        assert_roundtrip(&0xAABB_CCDD_u32, &[0xDD, 0xCC, 0xBB, 0xAA]);
        assert_roundtrip(&5u64, &[5, 0, 0, 0, 0, 0, 0, 0]);
        assert_roundtrip(&true, &[0x01]);
        assert_roundtrip(&false, &[0x00]);
        let h = Hash([9u8; 32]);
        assert_roundtrip(&h, &[9u8; 32]);
        let a = Address([7u8; 20]);
        assert_roundtrip(&a, &[7u8; 20]);
        assert_roundtrip(&Height::new(300), &300u64.to_le_bytes());
    }

    /// Varints: boundary lengths and every continuation shape.
    #[test]
    fn test_varint_boundaries() {
        let cases: &[(u64, Vec<u8>)] = &[
            (0, vec![0x00]),
            (0x7f, vec![0x7f]),       // single-byte max
            (0x80, vec![0x80, 0x01]), // spills to two
            (0xff, vec![0xff, 0x01]),
            (u64::MAX, [0xff; 9].iter().copied().chain([0x01]).collect()),
        ];
        for (value, wire) in cases {
            let mut buf = Vec::new();
            write::varint(&mut buf, *value);
            assert_eq!(&buf, wire, "varint({value}) wire form");
            let mut r = Reader::new(&buf);
            assert_eq!(r.read_varint().unwrap(), *value);
        }
    }

    /// Length-prefixed bytes: zero-copy borrow, empty string, exact tail.
    #[test]
    fn test_bytes_prefix_borrow() {
        let mut buf = Vec::new();
        write::bytes(&mut buf, b"oxide");
        assert_eq!(buf, vec![5, b'o', b'x', b'i', b'd', b'e']);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_bytes().unwrap(), b"oxide");
        // Empty string: prefix 0, no payload.
        let mut e = Vec::new();
        write::bytes(&mut e, b"");
        assert_eq!(e, vec![0]);
    }

    /// Corruption never panics and always yields a precise error.
    #[test]
    fn test_corruption_is_loud_not_panicking() {
        // Truncated fixed-width read.
        let mut r = Reader::new(&[1, 2, 3]);
        match r.read_u32() {
            Err(DecodeError::UnexpectedEof { needed: 4, remaining: 3 }) => {}
            other => panic!("expected precise EOF, got {other:?}"),
        }
        // Invalid boolean byte.
        let mut r = Reader::new(&[0x02]);
        assert_eq!(r.read_bool(), Err(DecodeError::InvalidBool { got: 0x02 }));
        // Overlong varint: 10 continuation bytes then more.
        let mut r = Reader::new(&[0xff; 11]);
        assert_eq!(r.read_varint(), Err(DecodeError::InvalidVarint));
        // Out-of-range final byte (bit 64+ set). Bound first: the Vec
        // must outlive the Reader that borrows it.
        let overlong = [0xff; 9].iter().copied().chain([0x02]).collect::<Vec<u8>>();
        let mut r = Reader::new(&overlong);
        assert_eq!(r.read_varint(), Err(DecodeError::InvalidVarint));
        // Length prefix pointing past the end.
        let mut r = Reader::new(&[10, b'x']);
        match r.read_bytes() {
            Err(DecodeError::LengthPrefixTooLarge { claimed: 10, remaining: 1 }) => {}
            other => panic!("expected length-prefix error, got {other:?}"),
        }
    }

    /// Id / fixed-point / timestamp wire forms are their raw u64s.
    #[test]
    fn test_domain_types_wire_form() {
        assert_roundtrip(&View::new(1), &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_roundtrip(&Epoch::new(1), &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_roundtrip(&TimestampMs(1_000), &1_000u64.to_le_bytes());
        assert_roundtrip(&Price(123), &123u64.to_le_bytes());
        assert_roundtrip(&Qty(456), &456u64.to_le_bytes());
    }
}
