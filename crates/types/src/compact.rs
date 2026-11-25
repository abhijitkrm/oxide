//! Compact proposals: a block body as transaction *hashes*, rebuilt from the follower's own mempool.
//!
//! Every transaction reaches a follower twice today: once as gossip (`MSG_TX`) when it enters the
//! network, and again inside the leader's proposal. A compact proposal replaces the second copy with a
//! 32-byte hash per transaction. The follower looks each hash up in its mempool, rebuilds the exact
//! [`Proposal`], and the existing integrity binding does the rest: `BlockHeader::body_hash` is a
//! BLAKE3 hash over the canonical encoding of the full [`Proposal`] and is signed in the header, so a
//! rebuilt body that differs in any byte (a wrong transaction, a wrong order) fails the same check a
//! full proposal does. Reconstruction therefore adds no trust assumption: a hash that resolves to the
//! wrong bytes is indistinguishable from a missing transaction and is handled the same way (fetch the
//! full body).
//!
//! This module is the pure core: the wire type, its allocation-safe codec, and [`CompactProposal::reconstruct`].
//! The mempool lookup, the missing-transaction fetch and the pump wiring live in the node
//! (`docs/compact-proposals-spec.md`).

use codec::{Decode, DecodeError, Encode, Reader, write};
use primitives::{Hash, Height};

use crate::{Proposal, TxBytes};

/// Bytes of one transaction id on the wire (unit: bytes). The full 32-byte hash: short salted ids
/// (BIP-152 style, 6-8 bytes) would cut the list another 4x but add collision handling; see the spec
/// for why that is deferred.
pub const TX_ID_LEN: usize = 32;

/// A proposal body with transactions referenced by hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactProposal {
    /// The height this proposal would finalize (same field as [`Proposal::height`]).
    pub height: Height,
    /// Transaction hashes in block order. Order is part of consensus output.
    pub tx_hashes: Vec<Hash>,
    /// The prior block's execution attestation, carried verbatim (same field as [`Proposal`]).
    pub attestation: Option<Vec<u8>>,
}

/// Outcome of rebuilding a [`Proposal`] from a [`CompactProposal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconstruction {
    /// Every transaction was found; the full proposal, ready for the `body_hash` check.
    Complete(Proposal),
    /// These positions (indices into `tx_hashes`, ascending) were not found. The caller fetches the
    /// missing transactions, or falls back to the full body.
    Missing(Vec<usize>),
}

impl CompactProposal {
    /// The compact form of `proposal`, given the hash of each of its transactions (same order).
    ///
    /// # Panics
    ///
    /// Panics if `hashes.len() != proposal.txs.len()`: a caller bug (the leader hashes the txs it
    /// selected), never wire input.
    #[must_use]
    pub fn from_proposal(proposal: &Proposal, hashes: &[Hash]) -> Self {
        assert_eq!(hashes.len(), proposal.txs.len(), "one hash per transaction");
        Self {
            height: proposal.height,
            tx_hashes: hashes.to_vec(),
            attestation: proposal.attestation.clone(),
        }
    }

    /// Rebuild the full proposal, resolving each hash with `lookup` (the follower's mempool). Never
    /// trusts a result: the caller must still check `header.body_hash` over the returned proposal.
    #[must_use]
    pub fn reconstruct(&self, mut lookup: impl FnMut(&Hash) -> Option<TxBytes>) -> Reconstruction {
        let mut txs = Vec::with_capacity(self.tx_hashes.len());
        let mut missing = Vec::new();
        for (i, h) in self.tx_hashes.iter().enumerate() {
            match lookup(h) {
                Some(tx) => txs.push(tx),
                None => missing.push(i),
            }
        }
        if missing.is_empty() {
            Reconstruction::Complete(Proposal {
                height: self.height,
                txs,
                attestation: self.attestation.clone(),
            })
        } else {
            Reconstruction::Missing(missing)
        }
    }
}

impl Encode for CompactProposal {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.height.encode(buf);
        write::varint(buf, self.tx_hashes.len() as u64);
        for h in &self.tx_hashes {
            h.encode(buf);
        }
        match &self.attestation {
            Some(att) => {
                write::bool(buf, true);
                write::bytes(buf, att);
            }
            None => write::bool(buf, false),
        }
    }
}

impl<'a> Decode<'a> for CompactProposal {
    fn decode(reader: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let height = Height::decode(reader)?;
        let claimed = reader.read_varint()?;
        // A forged count must not size an allocation: each hash occupies TX_ID_LEN wire bytes, so the
        // bytes actually left bound the capacity (the same defence `Proposal::decode` uses).
        let count = usize::try_from(claimed).map_err(|_| DecodeError::LengthPrefixTooLarge {
            claimed,
            remaining: reader.remaining() as u64,
        })?;
        let mut tx_hashes = Vec::with_capacity(count.min(reader.remaining() / TX_ID_LEN));
        for _ in 0..count {
            tx_hashes.push(Hash::decode(reader)?);
        }
        let attestation =
            if reader.read_bool()? { Some(reader.read_bytes()?.to_vec()) } else { None };
        Ok(Self { height, tx_hashes, attestation })
    }
}

#[cfg(test)]
// Short names (`p` proposal, `h` hashes, `c` compact) keep the test bodies readable.
#[allow(clippy::many_single_char_names)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn tx(i: u32, len: usize) -> TxBytes {
        let mut v = vec![(i % 251) as u8; len];
        v[..4].copy_from_slice(&i.to_le_bytes());
        TxBytes(v)
    }

    fn id(t: &TxBytes) -> Hash {
        crypto::hash::Hasher::hash_one(crypto::hash::Domain::BodyHash, &t.0)
    }

    fn proposal(n: u32, len: usize, att: Option<Vec<u8>>) -> (Proposal, Vec<Hash>) {
        let txs: Vec<TxBytes> = (0..n).map(|i| tx(i, len)).collect();
        let hashes = txs.iter().map(id).collect();
        (Proposal { height: Height::new(9), txs, attestation: att }, hashes)
    }

    fn pool(p: &Proposal) -> HashMap<Hash, TxBytes> {
        p.txs.iter().map(|t| (id(t), t.clone())).collect()
    }

    fn roundtrip<T: Encode + for<'a> Decode<'a> + PartialEq + std::fmt::Debug>(v: &T) {
        let mut buf = Vec::new();
        v.encode(&mut buf);
        let mut r = Reader::new(&buf);
        assert_eq!(&T::decode(&mut r).expect("decode"), v);
        assert_eq!(r.remaining(), 0, "no trailing bytes");
    }

    /// The codec round-trips, with and without an attestation and with an empty list.
    #[test]
    fn compact_proposal_round_trips() {
        for (n, att) in [(0, None), (1, None), (50, Some(vec![7u8; 33]))] {
            let (p, h) = proposal(n, 120, att);
            roundtrip(&CompactProposal::from_proposal(&p, &h));
        }
    }

    /// With every transaction in the pool the rebuilt proposal equals the original byte for byte, so
    /// the signed `body_hash` over its canonical encoding matches.
    #[test]
    fn reconstruct_rebuilds_the_exact_proposal() {
        let (p, h) = proposal(40, 150, Some(vec![1, 2, 3]));
        let pool = pool(&p);
        let c = CompactProposal::from_proposal(&p, &h);
        let Reconstruction::Complete(rebuilt) = c.reconstruct(|x| pool.get(x).cloned()) else {
            panic!("all transactions are in the pool");
        };
        assert_eq!(rebuilt, p);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        p.encode(&mut a);
        rebuilt.encode(&mut b);
        assert_eq!(
            crypto::hash::Hasher::hash_one(crypto::hash::Domain::BodyHash, &a),
            crypto::hash::Hasher::hash_one(crypto::hash::Domain::BodyHash, &b),
            "the body_hash binding sees identical bytes"
        );
    }

    /// Order is part of consensus output: the rebuilt order is the compact list's order, not the
    /// pool's.
    #[test]
    fn reconstruct_keeps_block_order_not_pool_order() {
        let (p, h) = proposal(30, 90, None);
        let mut shuffled: Vec<(Hash, TxBytes)> = pool(&p).into_iter().collect();
        shuffled.reverse();
        let lookup: HashMap<Hash, TxBytes> = shuffled.into_iter().collect();
        let c = CompactProposal::from_proposal(&p, &h);
        assert_eq!(c.reconstruct(|x| lookup.get(x).cloned()), Reconstruction::Complete(p));
    }

    /// Missing transactions are reported by position, ascending, and nothing partial is returned.
    #[test]
    fn reconstruct_reports_every_missing_position() {
        let (p, h) = proposal(20, 100, None);
        let mut pool = pool(&p);
        for i in [3usize, 4, 17] {
            pool.remove(&h[i]);
        }
        let c = CompactProposal::from_proposal(&p, &h);
        assert_eq!(
            c.reconstruct(|x| pool.get(x).cloned()),
            Reconstruction::Missing(vec![3, 4, 17])
        );
    }

    /// A hash that resolves to the WRONG bytes (a poisoned or colliding pool entry) rebuilds a body whose
    /// `body_hash` differs: the existing check rejects it, so reconstruction needs no extra trust.
    #[test]
    fn a_wrong_transaction_changes_the_body_hash() {
        let (p, h) = proposal(10, 100, None);
        let mut pool = pool(&p);
        pool.insert(h[5], tx(9_999, 100)); // the hash now resolves to different bytes
        let c = CompactProposal::from_proposal(&p, &h);
        let Reconstruction::Complete(rebuilt) = c.reconstruct(|x| pool.get(x).cloned()) else {
            panic!("the lookup returned something for every hash");
        };
        assert_ne!(rebuilt, p);
        let hash_of = |q: &Proposal| {
            let mut b = Vec::new();
            q.encode(&mut b);
            crypto::hash::Hasher::hash_one(crypto::hash::Domain::BodyHash, &b)
        };
        assert_ne!(hash_of(&rebuilt), hash_of(&p));
    }

    /// A forged count must not allocate by the claimed size or read past the buffer (the failure class
    /// the `Proposal` decoder was fuzzed for).
    #[test]
    fn a_forged_count_is_bounded_by_the_bytes_present() {
        let mut buf = Vec::new();
        Height::new(1).encode(&mut buf);
        write::varint(&mut buf, 2_000_000_000); // claims 2e9 hashes
        buf.extend_from_slice(&[0u8; 64]); // two hashes' worth of bytes
        let mut r = Reader::new(&buf);
        assert!(CompactProposal::decode(&mut r).is_err(), "must fail, not allocate 64 GB");
        let mut r = Reader::new(&[]);
        assert!(CompactProposal::decode(&mut r).is_err());
    }

    /// The point of the exercise, as numbers: compact versus full wire size for the three payload shapes
    /// of the throughput targets (EVM transfer ~110 B signed, order bundle of 64 at ~27 B per order,
    /// delegated bundle of 64 at ~47 B per order).
    #[test]
    fn compact_is_much_smaller_than_full_for_realistic_payloads() {
        let size = |e: &dyn Fn(&mut Vec<u8>)| {
            let mut b = Vec::new();
            e(&mut b);
            b.len()
        };
        for (what, tx_len, min_ratio) in [
            ("evm transfer", 110usize, 3.0),
            ("bundle of 64", 1_800, 40.0),
            ("dbundle of 64", 3_100, 70.0),
        ] {
            let (p, h) = proposal(1_000, tx_len, None);
            let full = size(&|b| p.encode(b));
            let compact = size(&|b| CompactProposal::from_proposal(&p, &h).encode(b));
            #[allow(clippy::cast_precision_loss)]
            let ratio = full as f64 / compact as f64;
            assert!(
                ratio >= min_ratio,
                "{what}: full {full} B vs compact {compact} B = {ratio:.1}x"
            );
        }
    }
}
