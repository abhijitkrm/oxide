//! Pluggable order and action authentication.
//!
//! Every admission path asks an [`Authenticator`] to turn requests into
//! the [`VerifiedOrder`] / [`VerifiedAction`] proof tokens the rest of
//! the matcher requires. The scheme is an operator decision, not a
//! protocol constant; the default ([`Ed25519Batch`]) is the historical
//! behaviour, bit for bit, and the others trade trust, cost and client
//! effort differently (see `docs/lanes-spec.md` §4):
//!
//! | Authenticator | Credential | Per-order cost (M1) | Trust added |
//! |---|---|---|---|
//! | [`Ed25519Batch`] (default) | ed25519 signature | ~16 µs batched | none |
//! | [`Ed25519PerItem`] | ed25519 signature | ~46 µs | none |
//! | [`EvmRecover`] | secp256k1 recoverable signature | ~31 µs | none |
//! | [`SessionMac`] | keyed-hash tag under a session key | ~0.1 µs | the matcher holds the session key |
//! | [`Certified`] | gateway signs the whole batch | ~1/`audit_every` of a signature | the gateway, audited |
//! | [`Multi`] | any of the above, per order | per scheme | per scheme |
//!
//! # Credential encoding (no wire change)
//!
//! The wire carries a 32-byte `pubkey` and a 64-byte `signature` per
//! request. Each scheme uses a distinct, canonical shape of those bytes,
//! so [`Multi`] can tell them apart without a version bump:
//!
//! | Scheme | `pubkey` | `signature` |
//! |---|---|---|
//! | ed25519 | the 32-byte key | the signature |
//! | EVM | byte 0 = recovery id (0/1), bytes 1..32 zero | `r ‖ s` |
//! | session MAC | bytes 0..4 = session id (LE), bytes 4..32 zero | bytes 0..32 = tag, bytes 32..64 zero |
//!
//! Classification is a routing hint, never a security boundary: every
//! scheme fails closed, so a credential shaped for one scheme but forged
//! passes nowhere. (An ed25519 key that happens to look like another
//! shape would be misrouted and rejected, never accepted.)
//!
//! All schemes sign or MAC the same signing message the ed25519 path
//! always used (domain, chain id, every order field, nonce, owner), so
//! replay protection stays the matcher's existing strictly-increasing
//! nonce gate: the MAC session needs no counter of its own.
//!
//! # Owner binding
//!
//! The order's `owner` must be the authenticated identity: the ed25519
//! key's derived address, the EVM-recovered address, or the session's
//! owner. The EVM address is the chain's own account address, so an
//! EVM-authenticated order trades for the on-chain EOA directly.

use std::sync::{Arc, RwLock};

use crypto::secp;
use crypto::{Domain, Hasher};
use primitives::Address;

use crate::protocol::{
    ActionRequest, OrderRequest, VerifiedAction, VerifiedOrder,
    signing_message_action_with_chain_id, signing_message_array,
};

/// Smallest batch an EVM recovery splits across threads. Unit: orders.
/// Same trade-off as `lanes::verify::EVM_PARALLEL_MIN`: below this the
/// thread start-up (~20 µs) costs more than it saves.
pub const EVM_PARALLEL_MIN: usize = 64;

/// Most sessions one authenticator will hold. Unit: sessions. Bounds the
/// memory an authenticated-but-hostile client can pin by opening
/// sessions (each is ~100 bytes, so 1M is ~100 MB at worst). Raising it
/// only raises that ceiling.
pub const MAX_SESSIONS: usize = 1 << 20;

/// The seam: how requests become proof tokens.
///
/// Implementations are shared across transport threads, so they take
/// `&self` and are `Send + Sync`.
pub trait Authenticator: Send + Sync {
    /// Short stable name for logs and metrics.
    fn name(&self) -> &'static str;

    /// Authenticate order requests; one aligned result per request.
    fn orders(&self, reqs: &[OrderRequest], chain_id: u64) -> Vec<Option<VerifiedOrder>>;

    /// Authenticate an action (cancel / amend / replace).
    fn action(&self, req: ActionRequest, chain_id: u64) -> Option<VerifiedAction>;

    /// Authenticate a batch the gateway has certified. The default
    /// refuses everything: only [`Certified`] (and [`Multi`] with that
    /// scheme enabled) accepts certificates.
    fn certified_orders(
        &self,
        reqs: &[OrderRequest],
        _cert: &BatchCertificate,
        _chain_id: u64,
    ) -> Vec<Option<VerifiedOrder>> {
        vec![None; reqs.len()]
    }

    /// Open a session from a signed request. The default refuses.
    ///
    /// # Errors
    ///
    /// [`SessionError`] if the scheme has no sessions, the open fails
    /// authentication, or the table is full.
    fn open_session(&self, _open: &SessionOpen, _chain_id: u64) -> Result<u32, SessionError> {
        Err(SessionError::Unsupported)
    }

    /// Revoke a session. Returns whether it existed. The default has
    /// no sessions.
    fn close_session(&self, _id: u32) -> bool {
        false
    }
}

/// Why a session could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// This authenticator has no sessions.
    Unsupported,
    /// The open request's own signature did not verify, or its signer
    /// is not the claimed owner.
    BadAuthorization,
    /// The session table is full ([`MAX_SESSIONS`]).
    Full,
}

// ── credential shapes ───────────────────────────────────────────────

/// Which scheme a credential is shaped for (a routing hint; see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// ed25519 signature.
    Ed25519,
    /// EVM secp256k1 recoverable signature.
    Evm,
    /// Session MAC.
    SessionMac,
}

fn all_zero(b: &[u8]) -> bool {
    b.iter().all(|x| *x == 0)
}

/// Classify a credential by its canonical shape.
#[must_use]
pub fn classify(pubkey: &[u8; 32], signature: &[u8; 64]) -> Scheme {
    if all_zero(&signature[32..]) && all_zero(&pubkey[4..]) {
        Scheme::SessionMac
    } else if pubkey[0] <= 1 && all_zero(&pubkey[1..]) {
        Scheme::Evm
    } else {
        Scheme::Ed25519
    }
}

fn ed25519_ok(pubkey: &[u8; 32], sig: &[u8; 64], owner: &Address, msg: &[u8]) -> bool {
    let Ok(pk) = crypto::ed25519::Ed25519PublicKey::from_bytes(pubkey) else {
        return false;
    };
    if crypto::ed25519::owner_address(&pk) != *owner {
        return false;
    }
    let Ok(s) = crypto::ed25519::Ed25519Signature::from_slice(sig) else {
        return false;
    };
    crypto::ed25519::verify_message(&pk, msg, &s).is_ok()
}

fn evm_ok(pubkey: &[u8; 32], sig: &[u8; 64], owner: &Address, msg: &[u8]) -> bool {
    if pubkey[0] > 1 || !all_zero(&pubkey[1..]) {
        return false;
    }
    let hash = secp::keccak256(msg);
    secp::recover_sender(&hash, sig, pubkey[0]).is_ok_and(|a| a == *owner)
}

/// Constant-time equality of two tags (no early exit on the first
/// differing byte).
fn tag_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn mac_tag(key: &[u8; 32], session: u32, msg: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(Domain::Transaction, key);
    h.update(&session.to_le_bytes());
    h.update(msg);
    h.finalize().0
}

// ── client helpers (also used by tests and the load generators) ────

/// Sign an order with an EVM (secp256k1) key: sets `owner` to the
/// key's address, `pubkey[0]` to the recovery id, and `signature` to
/// `r ‖ s`.
///
/// # Panics
///
/// Panics if `secret` is not a valid secp256k1 secret key.
pub fn sign_order_evm(req: &mut OrderRequest, secret: &[u8; 32], chain_id: u64) {
    req.owner = secp::signable_pubkey_address(secret).expect("valid secp256k1 secret");
    req.pubkey = [0u8; 32];
    let hash = secp::keccak256(&signing_message_array(req, chain_id));
    let sig = secp::sign(secret, &hash).expect("sign");
    req.pubkey[0] = sig.recid.as_u8();
    req.signature = sig.sig;
}

/// MAC an order under a session: `owner` must already be the session's
/// owner; sets `pubkey` (session id) and `signature` (tag).
pub fn sign_order_session(req: &mut OrderRequest, session: u32, key: &[u8; 32], chain_id: u64) {
    req.pubkey = [0u8; 32];
    req.pubkey[..4].copy_from_slice(&session.to_le_bytes());
    let tag = mac_tag(key, session, &signing_message_array(req, chain_id));
    req.signature = [0u8; 64];
    req.signature[..32].copy_from_slice(&tag);
}

/// EVM-sign an action (see [`sign_order_evm`]).
///
/// # Panics
///
/// Panics if `secret` is not a valid secp256k1 secret key.
pub fn sign_action_evm(req: &mut ActionRequest, secret: &[u8; 32], chain_id: u64) {
    req.owner = secp::signable_pubkey_address(secret).expect("valid secp256k1 secret");
    req.pubkey = [0u8; 32];
    let hash = secp::keccak256(&signing_message_action_with_chain_id(req, chain_id));
    let sig = secp::sign(secret, &hash).expect("sign");
    req.pubkey[0] = sig.recid.as_u8();
    req.signature = sig.sig;
}

/// MAC an action under a session (see [`sign_order_session`]).
pub fn sign_action_session(req: &mut ActionRequest, session: u32, key: &[u8; 32], chain_id: u64) {
    req.pubkey = [0u8; 32];
    req.pubkey[..4].copy_from_slice(&session.to_le_bytes());
    let tag = mac_tag(key, session, &signing_message_action_with_chain_id(req, chain_id));
    req.signature = [0u8; 64];
    req.signature[..32].copy_from_slice(&tag);
}

// ── default: ed25519 ────────────────────────────────────────────────

/// ed25519 with the batch equation across each batch (the historical
/// admission behaviour; identical results to
/// `VerifiedOrder::batch_with_chain_id`).
#[derive(Default)]
pub struct Ed25519Batch;

impl Authenticator for Ed25519Batch {
    fn name(&self) -> &'static str {
        "ed25519_batch"
    }
    fn orders(&self, reqs: &[OrderRequest], chain_id: u64) -> Vec<Option<VerifiedOrder>> {
        VerifiedOrder::batch_with_chain_id(reqs, chain_id)
    }
    fn action(&self, req: ActionRequest, chain_id: u64) -> Option<VerifiedAction> {
        VerifiedAction::with_chain_id(req, chain_id)
    }
}

/// ed25519, one strict verification per order (no batch equation).
#[derive(Default)]
pub struct Ed25519PerItem;

impl Authenticator for Ed25519PerItem {
    fn name(&self) -> &'static str {
        "ed25519"
    }
    fn orders(&self, reqs: &[OrderRequest], chain_id: u64) -> Vec<Option<VerifiedOrder>> {
        reqs.iter().map(|r| VerifiedOrder::with_chain_id(*r, chain_id)).collect()
    }
    fn action(&self, req: ActionRequest, chain_id: u64) -> Option<VerifiedAction> {
        VerifiedAction::with_chain_id(req, chain_id)
    }
}

// ── EVM ─────────────────────────────────────────────────────────────

/// EVM-style secp256k1 recovery: the recovered address must equal the
/// order's `owner`.
///
/// `threads > 1` splits batches of [`EVM_PARALLEL_MIN`] or more across
/// scoped threads.
pub struct EvmRecover {
    /// Worker threads (at least 1).
    pub threads: usize,
}

impl Default for EvmRecover {
    fn default() -> Self {
        Self { threads: 1 }
    }
}

fn evm_order(r: &OrderRequest, chain_id: u64) -> Option<VerifiedOrder> {
    evm_ok(&r.pubkey, &r.signature, &r.owner, &signing_message_array(r, chain_id))
        .then(|| VerifiedOrder::authenticated(*r))
}

impl Authenticator for EvmRecover {
    fn name(&self) -> &'static str {
        "evm_recover"
    }
    fn orders(&self, reqs: &[OrderRequest], chain_id: u64) -> Vec<Option<VerifiedOrder>> {
        let t = self.threads.max(1);
        if t == 1 || reqs.len() < EVM_PARALLEL_MIN {
            return reqs.iter().map(|r| evm_order(r, chain_id)).collect();
        }
        let mut out: Vec<Option<VerifiedOrder>> = vec![None; reqs.len()];
        let chunk = reqs.len().div_ceil(t);
        std::thread::scope(|s| {
            for (o, rs) in out.chunks_mut(chunk).zip(reqs.chunks(chunk)) {
                s.spawn(move || {
                    for (slot, r) in o.iter_mut().zip(rs) {
                        *slot = evm_order(r, chain_id);
                    }
                });
            }
        });
        out
    }
    fn action(&self, req: ActionRequest, chain_id: u64) -> Option<VerifiedAction> {
        evm_ok(
            &req.pubkey,
            &req.signature,
            &req.owner,
            &signing_message_action_with_chain_id(&req, chain_id),
        )
        .then(|| VerifiedAction::authenticated(req))
    }
}

// ── sessions ────────────────────────────────────────────────────────

/// The markets a session may trade: a 256-bit set over market ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketScope([u64; 4]);

impl MarketScope {
    /// Every market.
    #[must_use]
    pub const fn all() -> Self {
        Self([u64::MAX; 4])
    }

    /// Exactly the listed markets.
    #[must_use]
    pub fn only(markets: &[u8]) -> Self {
        let mut w = [0u64; 4];
        for m in markets {
            w[usize::from(*m / 64)] |= 1u64 << (m % 64);
        }
        Self(w)
    }

    /// Whether `market` is in scope.
    #[must_use]
    pub fn contains(&self, market: u8) -> bool {
        self.0[usize::from(market / 64)] >> (market % 64) & 1 == 1
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|w| *w == 0)
    }

    fn bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, w) in self.0.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        b
    }
}

/// Signing domain for session opens: keeps an open's signature from
/// being replayed as an order or action.
pub const SESSION_OPEN_DOMAIN: &[u8] = b"oxide-session-open-v1";

/// A request to open a session, authorized by the owner's own key.
#[derive(Clone, Copy, Debug)]
pub struct SessionOpen {
    /// The account the session trades for.
    pub owner: Address,
    /// The shared secret MAC key.
    pub session_key: [u8; 32],
    /// Markets the session may trade.
    pub scope: MarketScope,
    /// Credential `pubkey` field (ed25519 key, or EVM recovery id).
    pub pubkey: [u8; 32],
    /// Credential `signature` field over [`SessionOpen::message`].
    pub signature: [u8; 64],
}

impl SessionOpen {
    /// The bytes the owner signs.
    #[must_use]
    pub fn message(owner: &Address, key: &[u8; 32], scope: &MarketScope, chain_id: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(SESSION_OPEN_DOMAIN.len() + 8 + 20 + 32 + 32);
        m.extend_from_slice(SESSION_OPEN_DOMAIN);
        m.extend_from_slice(&chain_id.to_le_bytes());
        m.extend_from_slice(&owner.0);
        m.extend_from_slice(key);
        m.extend_from_slice(&scope.bytes());
        m
    }

    /// Open request authorized by an ed25519 key.
    #[must_use]
    pub fn sign_ed25519(
        secret: &crypto::ed25519::Ed25519SecretKey,
        key: [u8; 32],
        scope: MarketScope,
        chain_id: u64,
    ) -> Self {
        let pk = secret.verifying_key();
        let owner = crypto::ed25519::owner_address(&pk);
        let sig =
            crypto::ed25519::sign_message(secret, &Self::message(&owner, &key, &scope, chain_id));
        Self { owner, session_key: key, scope, pubkey: pk.to_bytes(), signature: sig.to_bytes() }
    }

    /// Open request authorized by an EVM key.
    ///
    /// # Panics
    ///
    /// Panics if `secret` is not a valid secp256k1 secret key.
    #[must_use]
    pub fn sign_evm(secret: &[u8; 32], key: [u8; 32], scope: MarketScope, chain_id: u64) -> Self {
        let owner = secp::signable_pubkey_address(secret).expect("valid secp256k1 secret");
        let hash = secp::keccak256(&Self::message(&owner, &key, &scope, chain_id));
        let sig = secp::sign(secret, &hash).expect("sign");
        let mut pubkey = [0u8; 32];
        pubkey[0] = sig.recid.as_u8();
        Self { owner, session_key: key, scope, pubkey, signature: sig.sig }
    }

    fn authorized(&self, chain_id: u64) -> bool {
        let msg = Self::message(&self.owner, &self.session_key, &self.scope, chain_id);
        match classify(&self.pubkey, &self.signature) {
            Scheme::Evm => evm_ok(&self.pubkey, &self.signature, &self.owner, &msg),
            // A MAC cannot open a session: that would let any session
            // mint more sessions (and widen its own scope).
            Scheme::SessionMac => false,
            Scheme::Ed25519 => ed25519_ok(&self.pubkey, &self.signature, &self.owner, &msg),
        }
    }
}

struct Session {
    key: [u8; 32],
    owner: Address,
    scope: MarketScope,
}

/// Session-MAC authentication over a table of open sessions.
///
/// Replay protection is the matcher's own nonce gate (the nonce is part
/// of the MAC'd message), so the table is read-only on the hot path:
/// one shared read lock per batch.
#[derive(Default)]
pub struct SessionMac {
    slots: RwLock<Vec<Option<Session>>>,
}

impl SessionMac {
    fn lock_read(&self) -> std::sync::RwLockReadGuard<'_, Vec<Option<Session>>> {
        // A poisoned table is a halted authenticator, not a permissive
        // one: recover the guard (the data is plain old data) so
        // already-open sessions keep working, never grant new access.
        self.slots.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn check(
        table: &[Option<Session>],
        pubkey: &[u8; 32],
        signature: &[u8; 64],
        owner: &Address,
        market: Option<u8>,
        msg: &[u8],
    ) -> bool {
        if !all_zero(&pubkey[4..]) || !all_zero(&signature[32..]) {
            return false;
        }
        let mut id = [0u8; 4];
        id.copy_from_slice(&pubkey[..4]);
        let id = u32::from_le_bytes(id);
        let Some(Some(s)) = table.get(id as usize) else { return false };
        if s.owner != *owner {
            return false;
        }
        if let Some(m) = market {
            if !s.scope.contains(m) {
                return false;
            }
        } else if s.scope.is_empty() {
            return false;
        }
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&signature[..32]);
        tag_eq(&mac_tag(&s.key, id, msg), &tag)
    }
}

impl Authenticator for SessionMac {
    fn name(&self) -> &'static str {
        "session_mac"
    }
    fn orders(&self, reqs: &[OrderRequest], chain_id: u64) -> Vec<Option<VerifiedOrder>> {
        let table = self.lock_read();
        reqs.iter()
            .map(|r| {
                Self::check(
                    &table,
                    &r.pubkey,
                    &r.signature,
                    &r.owner,
                    Some(r.market),
                    &signing_message_array(r, chain_id),
                )
                .then(|| VerifiedOrder::authenticated(*r))
            })
            .collect()
    }
    fn action(&self, req: ActionRequest, chain_id: u64) -> Option<VerifiedAction> {
        let table = self.lock_read();
        Self::check(
            &table,
            &req.pubkey,
            &req.signature,
            &req.owner,
            None,
            &signing_message_action_with_chain_id(&req, chain_id),
        )
        .then(|| VerifiedAction::authenticated(req))
    }
    fn open_session(&self, open: &SessionOpen, chain_id: u64) -> Result<u32, SessionError> {
        if !open.authorized(chain_id) {
            return Err(SessionError::BadAuthorization);
        }
        let mut slots = self.slots.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots.len() >= MAX_SESSIONS {
            return Err(SessionError::Full);
        }
        slots.push(Some(Session { key: open.session_key, owner: open.owner, scope: open.scope }));
        u32::try_from(slots.len() - 1).map_err(|_| SessionError::Full)
    }
    fn close_session(&self, id: u32) -> bool {
        let mut slots = self.slots.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        slots.get_mut(id as usize).and_then(Option::take).is_some()
    }
}

// ── gateway certificates ────────────────────────────────────────────

/// Signing domain for batch certificates.
pub const CERT_DOMAIN: &[u8] = b"oxide-batch-cert-v1";

/// A gateway's signed statement that it authenticated a batch.
#[derive(Clone, Copy, Debug)]
pub struct BatchCertificate {
    /// Gateway ed25519 public key.
    pub gateway: [u8; 32],
    /// Digest over the batch's signing messages, in order.
    pub digest: [u8; 32],
    /// Gateway signature over `CERT_DOMAIN ‖ digest`.
    pub signature: [u8; 64],
}

/// Digest over a batch's signing messages in order (covers every order
/// field; chain-bound through the messages).
#[must_use]
pub fn orders_digest(reqs: &[OrderRequest], chain_id: u64) -> [u8; 32] {
    let mut h = Hasher::new(Domain::Transaction);
    h.update(&(reqs.len() as u64).to_le_bytes());
    for r in reqs {
        h.update(&signing_message_array(r, chain_id));
    }
    h.finalize().0
}

/// Certify a batch as a gateway.
#[must_use]
pub fn certify(
    gateway: &crypto::ed25519::Ed25519SecretKey,
    reqs: &[OrderRequest],
    chain_id: u64,
) -> BatchCertificate {
    let digest = orders_digest(reqs, chain_id);
    let mut msg = CERT_DOMAIN.to_vec();
    msg.extend_from_slice(&digest);
    BatchCertificate {
        gateway: gateway.verifying_key().to_bytes(),
        digest,
        signature: crypto::ed25519::sign_message(gateway, &msg).to_bytes(),
    }
}

/// Gateway-certified batches with a deterministic audit sample.
///
/// A batch is accepted when a trusted gateway's signature over its
/// digest verifies and the digest matches the orders; additionally a
/// 1-in-`audit_every` sample (offset from the digest, so it is the same
/// on every node) has its own credential fully verified by `inner`. Any
/// failure rejects the whole batch (fail closed) and is counted.
///
/// Orders submitted without a certificate go to `inner` unchanged.
pub struct Certified {
    trusted: Vec<[u8; 32]>,
    audit_every: usize,
    inner: Box<dyn Authenticator>,
    audit_failures: std::sync::atomic::AtomicU64,
}

impl Certified {
    /// `audit_every` of 0 audits every order. `inner` verifies the
    /// audited orders and any uncertified traffic.
    #[must_use]
    pub fn new(trusted: Vec<[u8; 32]>, audit_every: u32, inner: Box<dyn Authenticator>) -> Self {
        Self {
            trusted,
            audit_every: (audit_every as usize).max(1),
            inner,
            audit_failures: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Batches rejected for a bad certificate, digest or audit.
    #[must_use]
    pub fn audit_failures(&self) -> u64 {
        self.audit_failures.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn cert_ok(&self, reqs: &[OrderRequest], cert: &BatchCertificate, chain_id: u64) -> bool {
        if !self.trusted.contains(&cert.gateway) || cert.digest != orders_digest(reqs, chain_id) {
            return false;
        }
        let Ok(pk) = crypto::ed25519::Ed25519PublicKey::from_bytes(&cert.gateway) else {
            return false;
        };
        let Ok(sig) = crypto::ed25519::Ed25519Signature::from_slice(&cert.signature) else {
            return false;
        };
        let mut msg = CERT_DOMAIN.to_vec();
        msg.extend_from_slice(&cert.digest);
        if crypto::ed25519::verify_message(&pk, &msg, &sig).is_err() {
            return false;
        }
        let off = usize::from(cert.digest[0]) % self.audit_every;
        let audited: Vec<OrderRequest> = reqs
            .iter()
            .enumerate()
            .filter(|(i, _)| (i + off).is_multiple_of(self.audit_every))
            .map(|(_, r)| *r)
            .collect();
        audited.is_empty() || self.inner.orders(&audited, chain_id).iter().all(Option::is_some)
    }
}

impl Authenticator for Certified {
    fn name(&self) -> &'static str {
        "certified"
    }
    fn orders(&self, reqs: &[OrderRequest], chain_id: u64) -> Vec<Option<VerifiedOrder>> {
        self.inner.orders(reqs, chain_id)
    }
    fn action(&self, req: ActionRequest, chain_id: u64) -> Option<VerifiedAction> {
        self.inner.action(req, chain_id)
    }
    fn certified_orders(
        &self,
        reqs: &[OrderRequest],
        cert: &BatchCertificate,
        chain_id: u64,
    ) -> Vec<Option<VerifiedOrder>> {
        if self.cert_ok(reqs, cert, chain_id) {
            reqs.iter().map(|r| Some(VerifiedOrder::authenticated(*r))).collect()
        } else {
            self.audit_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            vec![None; reqs.len()]
        }
    }
    fn open_session(&self, open: &SessionOpen, chain_id: u64) -> Result<u32, SessionError> {
        self.inner.open_session(open, chain_id)
    }
    fn close_session(&self, id: u32) -> bool {
        self.inner.close_session(id)
    }
}

// ── several schemes in one matcher ──────────────────────────────────

/// Which schemes a [`Multi`] accepts; anything off is rejected.
// One independent on/off switch per scheme is the whole point of the
// type; a bitset or enum set would only hide the same four flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schemes {
    /// ed25519 signatures.
    pub ed25519: bool,
    /// EVM recoverable signatures.
    pub evm: bool,
    /// Session MACs.
    pub session_mac: bool,
    /// Gateway certificates.
    pub certified: bool,
}

impl Schemes {
    /// Everything on.
    #[must_use]
    pub const fn all() -> Self {
        Self { ed25519: true, evm: true, session_mac: true, certified: true }
    }

    /// Parse `ed25519,evm,mac,cert` (or `all`).
    ///
    /// # Errors
    ///
    /// The unrecognized token.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut s = Self { ed25519: false, evm: false, session_mac: false, certified: false };
        for tok in list.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match tok {
                "all" => s = Self::all(),
                "ed25519" => s.ed25519 = true,
                "evm" => s.evm = true,
                "mac" | "session_mac" => s.session_mac = true,
                "cert" | "certified" => s.certified = true,
                other => return Err(other.to_string()),
            }
        }
        Ok(s)
    }
}

/// Several schemes at once: each order goes to the scheme its
/// credential is shaped for, ed25519 orders share one batch equation,
/// EVM orders recover in parallel, and disabled schemes are rejected.
pub struct Multi {
    schemes: Schemes,
    batch: Ed25519Batch,
    evm: EvmRecover,
    mac: SessionMac,
    cert: Option<Certified>,
}

impl Multi {
    /// Build over `schemes`. `cert` supplies the gateway-certificate
    /// scheme when enabled and configured.
    #[must_use]
    pub fn new(schemes: Schemes, evm_threads: usize, cert: Option<Certified>) -> Self {
        Self {
            schemes,
            batch: Ed25519Batch,
            evm: EvmRecover { threads: evm_threads },
            mac: SessionMac::default(),
            cert,
        }
    }

    fn scheme_on(&self, s: Scheme) -> bool {
        match s {
            Scheme::Ed25519 => self.schemes.ed25519,
            Scheme::Evm => self.schemes.evm,
            Scheme::SessionMac => self.schemes.session_mac,
        }
    }
}

impl Authenticator for Multi {
    fn name(&self) -> &'static str {
        "multi"
    }
    fn orders(&self, reqs: &[OrderRequest], chain_id: u64) -> Vec<Option<VerifiedOrder>> {
        let mut out: Vec<Option<VerifiedOrder>> = vec![None; reqs.len()];
        // Group by shape, verify each group with its scheme, scatter back.
        let mut groups: [Vec<usize>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for (i, r) in reqs.iter().enumerate() {
            let s = classify(&r.pubkey, &r.signature);
            if self.scheme_on(s) {
                groups[s as usize].push(i);
            }
        }
        for (gi, idxs) in groups.iter().enumerate() {
            if idxs.is_empty() {
                continue;
            }
            let sub: Vec<OrderRequest> = idxs.iter().map(|i| reqs[*i]).collect();
            let verified = match gi {
                0 => self.batch.orders(&sub, chain_id),
                1 => self.evm.orders(&sub, chain_id),
                _ => self.mac.orders(&sub, chain_id),
            };
            for (i, r) in idxs.iter().zip(verified) {
                out[*i] = r;
            }
        }
        out
    }
    fn action(&self, req: ActionRequest, chain_id: u64) -> Option<VerifiedAction> {
        let s = classify(&req.pubkey, &req.signature);
        if !self.scheme_on(s) {
            return None;
        }
        match s {
            Scheme::Ed25519 => self.batch.action(req, chain_id),
            Scheme::Evm => self.evm.action(req, chain_id),
            Scheme::SessionMac => self.mac.action(req, chain_id),
        }
    }
    fn certified_orders(
        &self,
        reqs: &[OrderRequest],
        cert: &BatchCertificate,
        chain_id: u64,
    ) -> Vec<Option<VerifiedOrder>> {
        match (&self.cert, self.schemes.certified) {
            (Some(c), true) => c.certified_orders(reqs, cert, chain_id),
            _ => vec![None; reqs.len()],
        }
    }
    fn open_session(&self, open: &SessionOpen, chain_id: u64) -> Result<u32, SessionError> {
        if self.schemes.session_mac {
            self.mac.open_session(open, chain_id)
        } else {
            Err(SessionError::Unsupported)
        }
    }
    fn close_session(&self, id: u32) -> bool {
        self.mac.close_session(id)
    }
}

// ── configuration ───────────────────────────────────────────────────

/// Which authenticator to run. There is deliberately no "accept
/// everything" kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    /// [`Ed25519Batch`] (the default; historical behaviour).
    Ed25519Batch,
    /// [`Ed25519PerItem`].
    Ed25519,
    /// [`EvmRecover`].
    Evm,
    /// [`SessionMac`].
    SessionMac,
    /// [`Certified`] over ed25519 for audits and uncertified traffic.
    Certified,
    /// [`Multi`] over [`Schemes`].
    Multi,
}

impl AuthKind {
    /// Parse a config name.
    ///
    /// # Errors
    ///
    /// The unrecognized name.
    pub fn parse(name: &str) -> Result<Self, String> {
        Ok(match name {
            "ed25519_batch" | "batched" => Self::Ed25519Batch,
            "ed25519" | "per_item" => Self::Ed25519,
            "evm" | "evm_recover" => Self::Evm,
            "session_mac" | "mac" => Self::SessionMac,
            "certified" | "cert" => Self::Certified,
            "multi" => Self::Multi,
            other => return Err(other.to_string()),
        })
    }
}

/// Runtime authenticator selection.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Which authenticator.
    pub kind: AuthKind,
    /// Schemes for `Multi`.
    pub schemes: Schemes,
    /// Threads for EVM recovery (1 = serial).
    pub evm_threads: usize,
    /// Gateways trusted for certificates (`Certified`, or `Multi` with `cert`).
    pub trusted_gateways: Vec<[u8; 32]>,
    /// Certificate audit sample, 1 in N orders.
    pub audit_every: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            kind: AuthKind::Ed25519Batch,
            schemes: Schemes::all(),
            evm_threads: 1,
            trusted_gateways: Vec::new(),
            audit_every: 64,
        }
    }
}

impl AuthConfig {
    /// Build the configured authenticator.
    #[must_use]
    pub fn build(&self) -> Arc<dyn Authenticator> {
        let cert = || {
            Certified::new(self.trusted_gateways.clone(), self.audit_every, Box::new(Ed25519Batch))
        };
        match self.kind {
            AuthKind::Ed25519Batch => Arc::new(Ed25519Batch),
            AuthKind::Ed25519 => Arc::new(Ed25519PerItem),
            AuthKind::Evm => Arc::new(EvmRecover { threads: self.evm_threads }),
            AuthKind::SessionMac => Arc::new(SessionMac::default()),
            AuthKind::Certified => Arc::new(cert()),
            AuthKind::Multi => Arc::new(Multi::new(
                self.schemes,
                self.evm_threads,
                self.schemes.certified.then(cert),
            )),
        }
    }
}

/// The default authenticator: [`Ed25519Batch`].
#[must_use]
pub fn default_authenticator() -> Arc<dyn Authenticator> {
    Arc::new(Ed25519Batch)
}
