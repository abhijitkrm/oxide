//! BLS-backed [`p2p::tcp::PeerAuth`] — binds a transport connection's
//! peer ID to the consensus key registered for it.
//!
//! The peer ID is the validator's **staking address** (20 bytes,
//! [`ValidatorSet::validator_addresses`]), not its committee index:
//! indices shift when a member is removed, while the address is the
//! stable staking identity — it survives index reshuffles *and* BLS
//! key rotation (`apply_key_change` preserves the address). `verify`
//! resolves `peer_id` → `index_of(addr)` → `validator(index)` at
//! call time against a shared `RwLock`, so a committee rotation the
//! pump publishes is immediately the key the handshake checks — no
//! transport restart, no stale map.
//!
//! During a scheduled rotation's schedule→activation window the
//! pending set is published too: an incoming member's handshake
//! proves its key against `current ∪ pending`, so it is connected
//! and receiving consensus traffic *before* its first duty — a
//! member admitted only at activation would miss its opening views.
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
use primitives::Address;

/// `PeerAuth` over a live validator set.
///
/// `secret` is this node's consensus key (it signs its half of every
/// greeting). `validators` is shared with the pump that swaps in the
/// rotated committee at each epoch boundary — the same
/// `Arc<RwLock<ValidatorSet>>` feeding `GET /validator-set`.
/// `pending` is the scheduled next-epoch set while a rotation waits
/// for its certified activation height — `None` the rest of the time.
///
/// # Peer-ID ↔ key binding
///
/// `verify`/`sign` treat `peer_id` as the validator's 20-byte
/// staking address (`parse_address`). Resolution runs against the
/// live set first, then the pending set — an address admitted only
/// through the pending set is a next-epoch member connecting early.
/// Address-keyed identity is what survives the committee changes a
/// positional index cannot: removal reshuffles indices, key rotation
/// replaces keys, and neither moves the address.
pub struct BlsPeerAuth {
    /// This node's consensus secret key — never printed (the manual
    /// `Debug` impl shows only the committee size).
    secret: BlsSecretKey,
    /// Live committee, index → BLS public key (+ staking addresses).
    validators: Arc<RwLock<ValidatorSet>>,
    /// Scheduled next-epoch committee during the activation window.
    pending: Arc<RwLock<Option<ValidatorSet>>>,
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
    /// epoch boundaries) signing with `secret`. `pending` carries the
    /// scheduled next-epoch set during the activation window.
    #[must_use]
    pub fn new(
        secret: BlsSecretKey,
        validators: Arc<RwLock<ValidatorSet>>,
        pending: Arc<RwLock<Option<ValidatorSet>>>,
    ) -> Self {
        Self { secret, validators, pending }
    }

    /// Decode a peer ID into a staking address — exactly 20 bytes.
    /// Anything else can never be a member identity and fails closed.
    fn parse_address(peer_id: &PeerId) -> Option<Address> {
        let bytes: [u8; 20] = peer_id.as_slice().try_into().ok()?;
        Some(Address(bytes))
    }

    /// Resolve `addr` to its consensus public key in `set` — the
    /// key a proof for this address must verify under.
    fn key_for(set: &ValidatorSet, addr: &Address) -> Option<crypto::PublicKey> {
        let idx = set.index_of(addr)?;
        set.validator(idx).ok().copied()
    }

    /// The key a peer claiming `peer_id` must prove: its address in
    /// the live set, else in the scheduled next-epoch set (the
    /// pre-activation admission window), else it is not a member.
    fn expected_key(&self, addr: &Address) -> Option<crypto::PublicKey> {
        if let Ok(set) = self.validators.read()
            && let Some(pk) = Self::key_for(&set, addr)
        {
            return Some(pk);
        }
        if let Ok(pending) = self.pending.read()
            && let Some(set) = pending.as_ref()
        {
            return Self::key_for(set, addr);
        }
        None
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
        let Some(addr) = Self::parse_address(peer) else { return false };
        let Ok(sig) = Signature::from_slice(signature) else { return false };
        let Some(pk) = self.expected_key(&addr) else { return false };
        crypto::verify(&sig, Domain::PeerHandshake, transcript, &pk).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three-member committee over the deterministic devnet keys:
    /// validator `i` ↔ `bls_key(i+1)` ↔ staking address
    /// `test_identity_address(i)` — the same convention
    /// `tcp_multinode` and `oxide-devnet` use.
    fn committee() -> (Vec<BlsSecretKey>, Arc<RwLock<ValidatorSet>>) {
        let secrets: Vec<BlsSecretKey> = (1u8..=3).map(crate::cli::bls_key).collect();
        let pks: Vec<crypto::PublicKey> = secrets.iter().map(BlsSecretKey::public_key).collect();
        let addresses: Vec<Address> =
            (0u8..3).map(|i| crypto::secp::test_identity_address(i).unwrap()).collect();
        let set = ValidatorSet::with_addresses(pks, vec![1, 1, 1], addresses).expect("committee");
        (secrets, Arc::new(RwLock::new(set)))
    }

    /// The 20-byte peer ID for committee member `i` of `committee()`.
    fn peer_id(set: &Arc<RwLock<ValidatorSet>>, i: usize) -> PeerId {
        set.read().expect("set").validator_addresses()[i].0.to_vec()
    }

    #[test]
    fn handshake_proof_verifies_and_rejects_spoofers() {
        let (secrets, set) = committee();
        let pending = Arc::new(RwLock::new(None));
        let auth = BlsPeerAuth::new(secrets[0].clone(), Arc::clone(&set), Arc::clone(&pending));
        // A proof signed by validator 1's key verifies under its
        // address peer ID, and fails under every other claim.
        let transcript = b"test transcript";
        let proof = BlsPeerAuth::new(secrets[1].clone(), Arc::clone(&set), Arc::clone(&pending))
            .sign(transcript)
            .expect("sign");
        let id1 = peer_id(&set, 1);
        assert!(auth.verify(&id1, transcript, &proof));
        assert!(!auth.verify(&peer_id(&set, 0), transcript, &proof), "wrong member");
        assert!(!auth.verify(&id1, b"other", &proof), "wrong transcript");
        let mut bad = proof.clone();
        bad[0] ^= 0xFF;
        assert!(!auth.verify(&id1, transcript, &bad), "tampered signature");
        // Malformed inputs fail closed, never panic.
        assert!(!auth.verify(&Vec::new(), transcript, &proof), "empty peer id");
        assert!(
            !auth.verify(&vec![1u8], transcript, &proof),
            "index-style peer id is not an address"
        );
        assert!(!auth.verify(&vec![0xAB; 21], transcript, &proof), "over-length peer id");
        assert!(!auth.verify(&id1, transcript, &[0u8; 12]), "short signature");
        // An address not in the committee is not a member.
        assert!(
            !auth.verify(&Address([0x77; 20]).0.to_vec(), transcript, &proof),
            "foreign address"
        );
    }

    /// A scheduled rotation's incoming member is admitted during the
    /// activation window: its address is absent from the live set but
    /// present in the pending set — the same verification path, one
    /// fallback away.
    #[test]
    fn pending_member_admitted_before_activation() {
        let (secrets, set) = committee();
        // The pending set drops member 0 and adds a fourth validator.
        let new_secret = crate::cli::bls_key(9);
        let new_addr = crypto::secp::test_identity_address(9).expect("identity");
        let cur = set.read().expect("set").clone();
        let mut keys = cur.public_keys().to_vec();
        let mut stakes = cur.stakes().to_vec();
        let mut addrs = cur.validator_addresses().to_vec();
        keys.remove(0);
        stakes.remove(0);
        addrs.remove(0);
        keys.push(new_secret.public_key());
        stakes.push(1);
        addrs.push(new_addr);
        let next = ValidatorSet::with_addresses(keys, stakes, addrs).expect("pending committee");
        let pending = Arc::new(RwLock::new(Some(next)));
        let auth = BlsPeerAuth::new(secrets[0].clone(), Arc::clone(&set), Arc::clone(&pending));

        let transcript = b"join handshake";
        let proof = BlsPeerAuth::new(new_secret.clone(), Arc::clone(&set), Arc::clone(&pending))
            .sign(transcript)
            .expect("sign");
        assert!(
            auth.verify(&new_addr.0.to_vec(), transcript, &proof),
            "pending member must authenticate during the window"
        );
        // The removed member is still in the LIVE set — removal takes
        // effect at activation, not at schedule, so its proof keeps
        // verifying during the window (correct: it still carries
        // quorum until then).
        let evicted_addr = peer_id(&set, 0);
        let evicted_proof =
            BlsPeerAuth::new(secrets[0].clone(), Arc::clone(&set), Arc::clone(&pending))
                .sign(transcript)
                .expect("sign");
        assert!(
            auth.verify(&evicted_addr, transcript, &evicted_proof),
            "a member being removed stays connected until activation"
        );

        // Post-activation the auth map follows the rotated set: the
        // evicted member's proof dies, the new member's verifies.
        let rotated = pending.read().expect("pending").clone().expect("scheduled set");
        *set.write().expect("set") = rotated;
        *pending.write().expect("pending") = None;
        assert!(
            !auth.verify(&evicted_addr, transcript, &evicted_proof),
            "post-activation the evicted member is refused"
        );
        assert!(
            auth.verify(&new_addr.0.to_vec(), transcript, &proof),
            "post-activation the new member verifies under the live set"
        );
    }
}
