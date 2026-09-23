//! BLS-backed [`p2p::tcp::PeerAuth`] — binds a transport connection's
//! peer ID to the consensus key registered for it.
//!
//! The peer ID is the validator's index into the live
//! [`consensus::ValidatorSet`] (the `vec![i]` convention every
//! launcher uses). `verify` resolves `peer_id` → `set.validator(i)`
//! at call time against a shared `RwLock`, so a committee rotation
//! the pump publishes is immediately the key the handshake checks —
//! no transport restart, no stale map.
//!
//! Signatures run under [`crypto::hash::Domain::PeerHandshake`]: a
//! handshake proof can never be reinterpreted as a vote, attestation,
//! or proof-of-possession over the same bytes, and vice versa.

use std::sync::{Arc, RwLock};

use consensus::ValidatorSet;
use crypto::bls::Signature;
use crypto::{BlsSecretKey, Domain};
use p2p::tcp::{AUTH_NONCE_LEN, PeerAuth};
use ports::transport::PeerId;

/// `PeerAuth` over a live validator set.
///
/// `secret` is this node's consensus key (it signs its half of every
/// greeting). `validators` is shared with the pump that swaps in the
/// rotated committee at each epoch boundary — the same
/// `Arc<RwLock<ValidatorSet>>` feeding `GET /validator-set`.
///
/// # Peer-ID ↔ key binding
///
/// `verify`/`sign` treat `peer_id`'s little-endian bytes as the
/// validator index (`parse_index`). If a rotation *reorders* the
/// committee the index mapping follows the new set's ordering — the
/// same coupling the validator-set-change routing work tracks
/// separately; peer IDs must stay stable across rotations for this
/// binding to remain meaningful.
pub struct BlsPeerAuth {
    /// This node's consensus secret key — never printed (the manual
    /// `Debug` impl shows only the committee size).
    secret: BlsSecretKey,
    /// Live committee, index → BLS public key.
    validators: Arc<RwLock<ValidatorSet>>,
}

impl std::fmt::Debug for BlsPeerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format `secret` — debug output must not carry key
        // material. The committee size is enough to identify the
        // configuration.
        let n = self.validators.read().map_or(0, |s| s.n());
        f.debug_struct("BlsPeerAuth").field("committee_size", &n).finish_non_exhaustive()
    }
}

impl BlsPeerAuth {
    /// Create an authenticator over `validators` (shared, mutable at
    /// epoch boundaries) signing with `secret`.
    #[must_use]
    pub fn new(secret: BlsSecretKey, validators: Arc<RwLock<ValidatorSet>>) -> Self {
        Self { secret, validators }
    }

    /// Decode a peer ID into a validator-set index — little-endian,
    /// at most 8 bytes. Anything longer can never be an index and
    /// fails closed.
    fn parse_index(peer_id: &PeerId) -> Option<crypto::bls::ValidatorIndex> {
        if peer_id.is_empty() || peer_id.len() > 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf[..peer_id.len()].copy_from_slice(peer_id);
        crypto::bls::ValidatorIndex::try_from(u64::from_le_bytes(buf)).ok()
    }
}

impl PeerAuth for BlsPeerAuth {
    fn challenge(&self) -> [u8; AUTH_NONCE_LEN] {
        crypto::random_nonce()
    }

    fn sign(&self, transcript: &[u8]) -> Option<Vec<u8>> {
        Some(self.secret.sign(Domain::PeerHandshake, transcript).as_bytes().to_vec())
    }

    fn verify(&self, peer: &PeerId, transcript: &[u8], signature: &[u8]) -> bool {
        let Some(index) = Self::parse_index(peer) else { return false };
        let Ok(sig) = Signature::from_slice(signature) else { return false };
        let pk = {
            let Ok(set) = self.validators.read() else { return false };
            let Ok(pk) = set.validator(index) else { return false };
            *pk
        };
        crypto::verify(&sig, Domain::PeerHandshake, transcript, &pk).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three-member committee over the deterministic devnet keys:
    /// validator `i` ↔ `bls_key(i+1)` ↔ peer ID `vec![i]` — the same
    /// convention `tcp_multinode` and `oxide-devnet` use.
    fn committee() -> (Vec<BlsSecretKey>, Arc<RwLock<ValidatorSet>>) {
        let secrets: Vec<BlsSecretKey> = (1u8..=3).map(crate::cli::bls_key).collect();
        let pks: Vec<crypto::PublicKey> = secrets.iter().map(BlsSecretKey::public_key).collect();
        let set = ValidatorSet::new(pks, vec![1, 1, 1]).expect("committee");
        (secrets, Arc::new(RwLock::new(set)))
    }

    #[test]
    fn handshake_proof_verifies_and_rejects_spoofers() {
        let (secrets, set) = committee();
        let auth = BlsPeerAuth::new(secrets[0].clone(), Arc::clone(&set));
        // A proof signed by validator 1's key verifies under peer
        // ID 1, and fails under every other claim.
        let transcript = b"test transcript";
        let proof =
            BlsPeerAuth::new(secrets[1].clone(), Arc::clone(&set)).sign(transcript).expect("sign");
        assert!(auth.verify(&vec![1u8], transcript, &proof));
        assert!(!auth.verify(&vec![0u8], transcript, &proof), "wrong index");
        assert!(!auth.verify(&vec![9u8], transcript, &proof), "out-of-range index");
        assert!(!auth.verify(&vec![1u8], b"other", &proof), "wrong transcript");
        let mut bad = proof.clone();
        bad[0] ^= 0xFF;
        assert!(!auth.verify(&vec![1u8], transcript, &bad), "tampered signature");
        // Malformed inputs fail closed, never panic.
        assert!(!auth.verify(&Vec::new(), transcript, &proof), "empty peer id");
        assert!(
            !auth.verify(&vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9], transcript, &proof),
            "over-length peer id"
        );
        assert!(!auth.verify(&vec![1u8], transcript, &[0u8; 12]), "short signature");
    }

    #[test]
    fn challenge_nonces_are_unique() {
        let (secrets, set) = committee();
        let auth = BlsPeerAuth::new(secrets[0].clone(), set);
        assert_ne!(auth.challenge(), auth.challenge());
    }
}
