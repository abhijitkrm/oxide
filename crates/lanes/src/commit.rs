//! The fill-commitment seam (`docs/lanes-spec.md` §7).
//!
//! A [`FillCommit`] is a [`FillSink`] the engine writes fills into; at
//! the end of a batch [`FillCommit::finish`] yields one 32-byte
//! commitment and the fill count, then resets for the next batch.
//!
//! | Commit | Work per fill | Proofs per fill |
//! |---|---|---|
//! | [`PerFill`] | one leaf hash (~150 ns) + XOR | no |
//! | [`Stream`] | bytes appended to one streaming hash (~10–20 ns) | no (replay from the journal) |
//! | [`Merkle`] | one leaf hash + one node hash amortized | yes |
//!
//! They commit to the same fill sequence but are different functions: a
//! chain picks one per lane and never mixes them within a lane.

use crypto::{Domain, Hasher};
use trading::{FillEvent, FillSink, Side};

/// Encoded length of one fill: price 8 + qty 8 + maker id 8 + taker id 8
/// + maker owner 20 + taker owner 20 + side 1.
pub const FILL_LEN: usize = 73;

/// Canonical byte encoding of a fill (little-endian, fixed layout).
#[must_use]
pub fn encode_fill(f: &FillEvent) -> [u8; FILL_LEN] {
    let mut b = [0u8; FILL_LEN];
    b[0..8].copy_from_slice(&f.price.0.to_le_bytes());
    b[8..16].copy_from_slice(&f.qty.0.to_le_bytes());
    b[16..24].copy_from_slice(&f.maker_order_id.0.to_le_bytes());
    b[24..32].copy_from_slice(&f.taker_order_id.0.to_le_bytes());
    b[32..52].copy_from_slice(&f.maker_owner.0);
    b[52..72].copy_from_slice(&f.taker_owner.0);
    b[72] = u8::from(f.taker_side == Side::Sell);
    b
}

/// The commitment seam: a fill sink that produces one commitment per batch.
pub trait FillCommit: FillSink {
    /// Short stable name for reports.
    fn name(&self) -> &'static str;
    /// Commitment over the fills since the last call, and their count.
    /// Resets the accumulator.
    fn finish(&mut self) -> ([u8; 32], u64);
}

/// One leaf per fill, XOR-folded (order-insensitive; the existing
/// resting-fold style). Baseline.
#[derive(Default)]
pub struct PerFill {
    acc: [u8; 32],
    n: u64,
}

impl FillSink for PerFill {
    #[inline]
    fn fill(&mut self, f: FillEvent) {
        let leaf = Hasher::hash_one(Domain::CommittedLeaf, &encode_fill(&f)).0;
        for (a, l) in self.acc.iter_mut().zip(leaf) {
            *a ^= l;
        }
        self.n += 1;
    }
}

impl FillCommit for PerFill {
    fn name(&self) -> &'static str {
        "per_fill"
    }
    fn finish(&mut self) -> ([u8; 32], u64) {
        let out = (self.acc, self.n);
        *self = Self::default();
        out
    }
}

/// One streaming hash over the encoded fills in match order
/// (order-sensitive). Cheapest; no per-fill proofs.
///
/// Fills are buffered and hashed in [`STREAM_FLUSH_BYTES`] pieces:
/// feeding BLAKE3 73 bytes at a time pays per-call block handling on
/// every fill, while a large `update` lets it hash many 1 KiB chunks
/// at once with SIMD (measured in `benches/lanes.rs`).
pub struct Stream {
    h: Hasher,
    buf: Vec<u8>,
    n: u64,
}

/// Bytes buffered before one `update` call. Unit: bytes. 16 KiB is
/// sixteen BLAKE3 chunks, enough for the multi-chunk SIMD path; larger
/// only grows the buffer past L1 with no gain.
pub const STREAM_FLUSH_BYTES: usize = 16 * 1024;

impl Default for Stream {
    fn default() -> Self {
        Self {
            h: Hasher::new(Domain::MmrLeaf),
            buf: Vec::with_capacity(STREAM_FLUSH_BYTES + FILL_LEN),
            n: 0,
        }
    }
}

impl FillSink for Stream {
    #[inline]
    fn fill(&mut self, f: FillEvent) {
        self.buf.extend_from_slice(&encode_fill(&f));
        if self.buf.len() >= STREAM_FLUSH_BYTES {
            self.h.update(&self.buf);
            self.buf.clear();
        }
        self.n += 1;
    }
}

impl FillCommit for Stream {
    fn name(&self) -> &'static str {
        "stream"
    }
    fn finish(&mut self) -> ([u8; 32], u64) {
        let mut h = std::mem::replace(&mut self.h, Hasher::new(Domain::MmrLeaf));
        h.update(&self.buf);
        h.update(&self.n.to_le_bytes());
        self.buf.clear();
        let out = (h.finalize().0, self.n);
        self.n = 0;
        out
    }
}

/// Binary Merkle tree over per-fill leaves in match order. An odd node
/// is promoted unchanged; the count is bound into the final root so the
/// shape is unambiguous.
#[derive(Default)]
pub struct Merkle {
    leaves: Vec<[u8; 32]>,
}

/// Root of `leaves` (consumes the buffer contents), bound to `n`.
#[must_use]
pub fn merkle_root(leaves: &mut Vec<[u8; 32]>) -> [u8; 32] {
    let n = leaves.len() as u64;
    while leaves.len() > 1 {
        let mut w = 0;
        let mut r = 0;
        while r + 1 < leaves.len() {
            leaves[w] = Hasher::hash_pair(Domain::MmrNode, &leaves[r], &leaves[r + 1]).0;
            w += 1;
            r += 2;
        }
        if r < leaves.len() {
            leaves[w] = leaves[r];
            w += 1;
        }
        leaves.truncate(w);
    }
    let top = leaves.first().copied().unwrap_or([0u8; 32]);
    Hasher::hash_pair(Domain::MmrRoot, &top, &n.to_le_bytes()).0
}

impl FillSink for Merkle {
    #[inline]
    fn fill(&mut self, f: FillEvent) {
        self.leaves.push(Hasher::hash_one(Domain::MmrLeaf, &encode_fill(&f)).0);
    }
}

impl FillCommit for Merkle {
    fn name(&self) -> &'static str {
        "merkle"
    }
    fn finish(&mut self) -> ([u8; 32], u64) {
        let n = self.leaves.len() as u64;
        let root = merkle_root(&mut self.leaves);
        self.leaves.clear();
        (root, n)
    }
}

/// Discards fills (count only): the no-commitment control.
#[derive(Default)]
pub struct CountOnly(u64);

impl FillSink for CountOnly {
    #[inline]
    fn fill(&mut self, _f: FillEvent) {
        self.0 += 1;
    }
}

impl FillCommit for CountOnly {
    fn name(&self) -> &'static str {
        "none"
    }
    fn finish(&mut self) -> ([u8; 32], u64) {
        let n = self.0;
        self.0 = 0;
        ([0u8; 32], n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::Address;
    use primitives::fixed::{Price, Qty};
    use trading::OrderId;

    fn fill(i: u64) -> FillEvent {
        FillEvent {
            price: Price(1000 + i),
            qty: Qty(i + 1),
            maker_order_id: OrderId(i),
            maker_owner: Address([1; 20]),
            taker_order_id: OrderId(i + 100),
            taker_owner: Address([2; 20]),
            taker_side: if i.is_multiple_of(2) { Side::Buy } else { Side::Sell },
        }
    }

    fn run<C: FillCommit>(c: &mut C, n: u64) -> ([u8; 32], u64) {
        for i in 0..n {
            c.fill(fill(i));
        }
        c.finish()
    }

    #[test]
    fn all_count_the_same_fills_and_reset_between_batches() {
        for n in [0u64, 1, 2, 3, 7, 64] {
            let a = run(&mut PerFill::default(), n);
            let b = run(&mut Stream::default(), n);
            let c = run(&mut Merkle::default(), n);
            let d = run(&mut CountOnly::default(), n);
            assert_eq!(a.1, n);
            assert_eq!((b.1, c.1, d.1), (n, n, n));
        }
        let mut m = Merkle::default();
        let first = run(&mut m, 5);
        let second = run(&mut m, 5);
        assert_eq!(first, second, "finish must fully reset");
    }

    /// Naive recursive reference with the same promote-odd rule.
    fn rec(l: &[[u8; 32]]) -> [u8; 32] {
        if l.len() == 1 {
            return l[0];
        }
        let mut next = Vec::new();
        for c in l.chunks(2) {
            next.push(if c.len() == 2 {
                Hasher::hash_pair(Domain::MmrNode, &c[0], &c[1]).0
            } else {
                c[0]
            });
        }
        rec(&next)
    }

    #[test]
    fn merkle_matches_a_naive_recomputation() {
        for n in [1usize, 2, 3, 5, 8, 13] {
            let leaves: Vec<[u8; 32]> = (0..n as u64)
                .map(|i| Hasher::hash_one(Domain::MmrLeaf, &encode_fill(&fill(i))).0)
                .collect();
            let want =
                Hasher::hash_pair(Domain::MmrRoot, &rec(&leaves), &(n as u64).to_le_bytes()).0;
            let got = run(&mut Merkle::default(), n as u64).0;
            assert_eq!(got, want, "n={n}");
        }
    }

    /// The buffering must be invisible: the digest equals one hash over
    /// the whole encoded stream, however many flushes happened.
    #[test]
    fn stream_equals_one_shot_hash_across_flush_boundaries() {
        for n in [0u64, 1, 5, 224, 225, 226, 1000] {
            let mut all = Vec::new();
            for i in 0..n {
                all.extend_from_slice(&encode_fill(&fill(i)));
            }
            let mut h = Hasher::new(Domain::MmrLeaf);
            h.update(&all);
            h.update(&n.to_le_bytes());
            let got = run(&mut Stream::default(), n);
            assert_eq!(got, (h.finalize().0, n), "n={n}");
        }
    }

    #[test]
    fn commitments_bind_content_and_order() {
        for make in [
            (|| Box::new(Stream::default()) as Box<dyn FillCommit>) as fn() -> Box<dyn FillCommit>,
            || Box::new(Merkle::default()),
            || Box::new(PerFill::default()),
        ] {
            let mut a = make();
            let mut b = make();
            let mut c = make();
            for i in 0..4 {
                a.fill(fill(i));
                b.fill(fill(i));
            }
            for i in [0, 1, 2, 9] {
                c.fill(fill(i));
            }
            let (ra, rb, rc) = (a.finish().0, b.finish().0, c.finish().0);
            assert_eq!(ra, rb, "deterministic");
            assert_ne!(ra, rc, "content change must change the root");
        }
        // Order-sensitive commitments detect a swap; per-fill XOR does not (documented).
        for make in [
            (|| Box::new(Stream::default()) as Box<dyn FillCommit>) as fn() -> Box<dyn FillCommit>,
            || Box::new(Merkle::default()),
        ] {
            let mut a = make();
            let mut b = make();
            a.fill(fill(0));
            a.fill(fill(1));
            b.fill(fill(1));
            b.fill(fill(0));
            assert_ne!(a.finish().0, b.finish().0);
        }
    }
}
