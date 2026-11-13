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
//! The encoding, label and aggregation live in `exchange::dispute`; the
//! chain's dispute path recomputes exactly this root.
//!
//! Cost: about 55 ns per fill (`lanes` bench: stream commit), paid
//! once per batch on the settler thread, never on the order path.

use exchange::dispute::{FILLS_STREAM_LABEL, RawFill};
use lanes::commit::ByteStream;

use crate::SettledFill;

/// A sealed fill as the chain's dispute path sees it. The encoding,
/// the stream label and the aggregation are defined once, in
/// `exchange::dispute`, so the root the settler attests and the root a
/// dispute recomputes cannot drift apart.
#[must_use]
pub fn to_raw(f: &SettledFill) -> RawFill {
    RawFill {
        market: f.market,
        price: f.price,
        qty: f.qty,
        buy: exchange::OrderKey { owner: f.buyer, client_id: f.buyer_id },
        sell: exchange::OrderKey { owner: f.seller, client_id: f.seller_id },
        quote_amount: f.quote_amount,
    }
}

/// Commitment over `fills` in order, and their count (saturating at
/// `u32::MAX`; a batch that large is rejected on chain anyway).
/// Streams the encoding directly (no intermediate `Vec`); equals
/// `exchange::dispute::raw_fills_root` over the same fills (tested).
#[must_use]
pub fn fills_root(fills: &[SettledFill]) -> ([u8; 32], u32) {
    let mut s = ByteStream::new(FILLS_STREAM_LABEL);
    for f in fills {
        s.push(&to_raw(f).encode());
    }
    let (root, n) = s.finish();
    (root, u32::try_from(n).unwrap_or(u32::MAX))
}

/// The dispute message (`TAG_DISPUTE`) an auditor submits for
/// `batch_seq`, built from the raw fills it replayed from the
/// matcher's journal.
#[must_use]
pub fn dispute_payload(batch_seq: u64, fills: &[SettledFill]) -> Vec<u8> {
    let raw: Vec<RawFill> = fills.iter().map(to_raw).collect();
    exchange::msg::dispute(batch_seq, &raw)
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
    fn matches_the_chains_definition_of_the_root() {
        let a: Vec<_> = (0..25).map(fill).collect();
        let raw: Vec<_> = a.iter().map(to_raw).collect();
        assert_eq!(fills_root(&a), exchange::dispute::raw_fills_root(&raw));
    }

    #[test]
    fn empty_batch_has_a_defined_root() {
        let (root, n) = fills_root(&[]);
        assert_eq!(n, 0);
        assert_ne!(root, [0u8; 32]);
    }
}
