//! Per-batch commitment over the fills the matcher sealed.
//!
//! When a settlement batch is sealed, [`fills_root`] folds the raw
//! fills, in seal order, into one 32-byte root with the same streaming
//! construction the lanes use (`lanes::commit::ByteStream`). The
//! settler can attach that root to the on-chain batch (committed batch
//! settle) as the operator's attestation over the raw fill stream.
//!
//! The root is a pure function of the sealed fills, which are a pure
//! function of the journaled command stream, so anyone holding the
//! matcher's journal can replay it and recompute the root to audit the
//! operator; no extra state is kept or persisted for it.
//!
//! Cost: about 55 ns per fill (`lanes` bench: stream commit), paid
//! once per batch on the settler thread, never on the order path.

use lanes::commit::ByteStream;

use crate::SettledFill;

/// Stream label of the raw-fill commitment (keeps it distinct from the
/// chain's legs commitment and the lanes' fill stream).
pub const FILLS_STREAM_LABEL: &[u8] = b"oxide-matcher-fills-v1";

/// Encoded length of one sealed fill: market 2 + price 8 + qty 8 +
/// buyer 20 + buyer id 8 + seller 20 + seller id 8 + quote amount 8.
pub const SETTLED_FILL_LEN: usize = 2 + 8 + 8 + 20 + 8 + 20 + 8 + 8;

/// Canonical byte encoding of a sealed fill (little-endian, fixed
/// layout; every field the settlement acts on).
#[must_use]
pub fn encode_settled_fill(f: &SettledFill) -> [u8; SETTLED_FILL_LEN] {
    let mut b = [0u8; SETTLED_FILL_LEN];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        b[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(&f.market.to_le_bytes());
    put(&f.price.0.to_le_bytes());
    put(&f.qty.0.to_le_bytes());
    put(&f.buyer.0);
    put(&f.buyer_id.to_le_bytes());
    put(&f.seller.0);
    put(&f.seller_id.to_le_bytes());
    put(&f.quote_amount.to_le_bytes());
    debug_assert_eq!(at, SETTLED_FILL_LEN, "fill layout drifted from its length");
    b
}

/// Commitment over `fills` in order, and their count (saturating at
/// `u32::MAX`; a batch that large is rejected on chain anyway).
#[must_use]
pub fn fills_root(fills: &[SettledFill]) -> ([u8; 32], u32) {
    let mut s = ByteStream::new(FILLS_STREAM_LABEL);
    for f in fills {
        s.push(&encode_settled_fill(f));
    }
    let (root, n) = s.finish();
    (root, u32::try_from(n).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::Address;
    use primitives::fixed::{Price, Qty};

    fn fill(i: u64) -> SettledFill {
        SettledFill {
            market: (i % 3) as u16,
            price: Price(1_000_000_000 + i),
            qty: Qty(1_000 + i),
            buyer: Address([1; 20]),
            buyer_id: i,
            seller: Address([2; 20]),
            seller_id: i + 7,
            quote_amount: 10 * i,
        }
    }

    #[test]
    fn root_is_deterministic_ordered_and_binds_every_field() {
        let a: Vec<_> = (0..10).map(fill).collect();
        assert_eq!(fills_root(&a), fills_root(&a));
        assert_eq!(fills_root(&a).1, 10);
        let mut swapped = a.clone();
        swapped.swap(2, 3);
        assert_ne!(fills_root(&a).0, fills_root(&swapped).0, "order matters");
        assert_ne!(fills_root(&a).0, fills_root(&a[..9]).0, "count matters");
        // Each field change moves the root.
        let base = fills_root(&a).0;
        let mutations: [fn(&mut SettledFill); 8] = [
            |f| f.market ^= 1,
            |f| f.price = Price(f.price.0 + 1),
            |f| f.qty = Qty(f.qty.0 + 1),
            |f| f.buyer.0[0] ^= 1,
            |f| f.buyer_id += 1,
            |f| f.seller.0[0] ^= 1,
            |f| f.seller_id += 1,
            |f| f.quote_amount += 1,
        ];
        for (k, m) in mutations.iter().enumerate() {
            let mut b = a.clone();
            m(&mut b[4]);
            assert_ne!(fills_root(&b).0, base, "field {k} must be committed");
        }
    }

    #[test]
    fn empty_batch_has_a_defined_root() {
        let (root, n) = fills_root(&[]);
        assert_eq!(n, 0);
        assert_ne!(root, [0u8; 32]);
    }
}
