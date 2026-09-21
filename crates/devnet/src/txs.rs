//! Signed-envelope construction for devnet workloads.
//!
//! The executor's default `UnsignedTxPolicy::Reject` means every
//! native-module tx a devnet harness emits must carry a real
//! EIP-712 envelope signature — `ctx.sender` is only accepted when
//! the signature recovers to it. Devnet identities are therefore
//! **key-derived**, never byte patterns: index `i` maps to a fixed
//! secp256k1 secret, and its address is what funding, validator
//! registration, and `sender`-gated module ops (e.g. staking
//! `key_change`) all agree on.
//!
//! Determinism is load-bearing: the same index must produce the
//! same key on every validator and every process, or replicated
//! state diverges.

use crypto::secp;
use primitives::Address;
use types::TxBytes;

/// The chain id every devnet executor signs for — matches the
/// `Executor`/`EvmModule` default of 1 used by the devnet assembly.
pub const CHAIN_ID: u64 = 1;

/// The deterministic secp256k1 secret for devnet identity `index` —
/// `crypto::secp::test_identity_key`, re-exported here so every
/// harness and binary shares one index space (the single-node devnet
/// genesis funds/registers identity 0 through the same derivation).
#[must_use]
pub fn identity_key(index: u8) -> [u8; 32] {
    secp::test_identity_key(index)
}

/// The address of devnet identity `index` — the account a signed
/// envelope from `identity_key(index)` authenticates as.
///
/// # Panics
///
/// Never in practice — `identity_key` only produces valid secp256k1
/// secrets; panics only if the secp256k1 backend rejects one.
#[must_use]
pub fn identity_addr(index: u8) -> Address {
    secp::test_identity_address(index).expect("index-derived secrets are valid secp256k1 keys")
}

/// Build a signed v1 tx envelope for identity `index`:
/// `[sender][nonce][fee][module_id|0x80][sig:65][payload]`.
///
/// This mirrors `mempool::build_signed_tx` without depending on the
/// mempool crate — the layout lives in `executor`'s envelope codec
/// (`SIGNED_FLAG` in the module-id byte).
///
/// # Panics
///
/// Never in practice — `identity_key` only produces valid secp256k1
/// secrets; panics only if the secp256k1 backend rejects one or
/// fails to sign.
#[must_use]
pub fn signed_tx(index: u8, nonce: u64, fee: u64, module_id: u8, payload: &[u8]) -> TxBytes {
    let key = identity_key(index);
    let sender = secp::signable_pubkey_address(&key).expect("valid key");
    let sig = crypto::eip712::sign_tx(&key, CHAIN_ID, &sender, nonce, fee, module_id, payload)
        .expect("valid key must sign");
    let mut bytes = Vec::with_capacity(36 + 1 + 65 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id | 0x80);
    bytes.extend_from_slice(&sig.sig);
    bytes.push(sig.recid.as_u8());
    bytes.extend_from_slice(payload);
    TxBytes::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every identity index yields a distinct, valid address, and a
    /// `signed_tx` envelope declares that address as its sender.
    #[test]
    fn identities_are_distinct_and_match_envelope_sender() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..32u8 {
            let addr = identity_addr(i);
            assert!(seen.insert(addr), "identity {i} must be unique");
            let tx = signed_tx(i, 7, 100, framework::module_id::STAKING, b"x");
            assert_eq!(&tx.0[..20], &addr.0, "envelope sender must be identity {i}");
            // Signed flag set, 65-byte signature before the payload.
            assert_eq!(tx.0[36] & 0x80, 0x80);
        }
    }

    /// The signature embedded in a `signed_tx` envelope verifies
    /// under the executor's EIP-712 check and recovers the declared
    /// sender — the property `check_envelope_auth` enforces under
    /// the default `Reject` policy (executor-side reject/allow
    /// coverage lives in `executor`'s own tests).
    #[test]
    fn signed_envelope_recovers_declared_sender() {
        let nonce = 42u64;
        let fee = 100u64;
        let module_id = framework::module_id::STAKING;
        let payload = staking::msg::delegate(identity_addr(0), 1);
        let tx = signed_tx(0, nonce, fee, module_id, &payload);
        let bytes = &tx.0;

        let sender = Address(<[u8; 20]>::try_from(&bytes[..20]).unwrap());
        let sig = crypto::secp::RecoverableSignature::from_bytes(&bytes[37..101], bytes[101])
            .expect("well-formed signature");
        let recovered = crypto::eip712::verify_tx_sender(
            CHAIN_ID,
            &sender,
            nonce,
            fee,
            module_id,
            &bytes[102..],
            &sig,
        )
        .expect("signature must verify");
        assert_eq!(recovered, identity_addr(0), "signer must be identity 0");
        assert_eq!(recovered, sender, "signer must equal declared sender");
    }
}
