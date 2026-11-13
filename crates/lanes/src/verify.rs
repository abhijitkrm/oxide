//! The authentication seam (`docs/lanes-spec.md` §4).
//!
//! A [`Verifier`] turns a [`Batch`] of authenticated items into a
//! per-item accept/reject vector. Implementations differ in what they
//! prove per item and what that costs:
//!
//! | Verifier | Per-item cost (M1, 1 core) | Trust added |
//! |---|---|---|
//! | [`PerItem`] | ~46 µs | none |
//! | [`Batched`] | ~16 µs | none (falls back to per-item on failure) |
//! | [`Certified`] | ~1/`audit_every` of per-item + 1 sig per batch | the gateway, audited |
//! | [`SessionMac`] | ~0.11 µs | the session holder, bounded by session scope |
//!
//! All implementations fail closed: an item that cannot be proven
//! authentic is `false` and the lane must not touch state for it.

use crypto::ed25519::{self, Ed25519PublicKey, Ed25519Signature};
use crypto::{Domain, Hasher};

/// Order body length in bytes: side, type, tif, stp (4) + price (8) +
/// qty (8) + owner (20). See [`encode_body`].
pub const BODY_LEN: usize = 40;

/// How an item proves it was authorized.
// `Sig` carries a decoded verifying key (large) next to the small `Mac`
// variant. Boxing would add a heap allocation per item on the hot path;
// the size cost is accepted and bounded by the batch size.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy)]
pub enum Auth {
    /// The account's own signature over the body.
    Sig {
        /// Account key.
        key: Ed25519PublicKey,
        /// Signature over the body.
        sig: Ed25519Signature,
    },
    /// A keyed-hash tag under a session key (see [`session_tag`]).
    Mac {
        /// Session identifier (index into the verifier's session table).
        session: u32,
        /// Strictly increasing per-session counter (replay guard).
        counter: u64,
        /// The tag.
        tag: [u8; 32],
    },
    /// No per-item proof: covered by the batch certificate.
    Certified,
}

/// One authenticated order.
#[derive(Clone, Copy)]
pub struct Item {
    /// Order body (see [`encode_body`]).
    pub body: [u8; BODY_LEN],
    /// Proof of authorization.
    pub auth: Auth,
}

/// A gateway's signed statement that it verified a batch.
#[derive(Clone, Copy)]
pub struct BatchCert {
    /// Gateway key (must be in the verifier's trusted set).
    pub gateway: Ed25519PublicKey,
    /// Digest over the batch's bodies ([`batch_digest`]).
    pub digest: [u8; 32],
    /// Gateway signature over `digest`.
    pub sig: Ed25519Signature,
}

/// A batch as presented to a verifier.
pub struct Batch<'a> {
    /// The items, in order.
    pub items: &'a [Item],
    /// Gateway certificate, when the batch came through one.
    pub cert: Option<&'a BatchCert>,
}

/// The authentication seam.
pub trait Verifier {
    /// Short stable name for reports.
    fn name(&self) -> &'static str;
    /// Verify `batch`; on return `ok` has exactly one entry per item.
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>);
}

/// Digest over a batch's bodies in order, domain-separated. Covers
/// bodies only, not the per-item proofs, so a gateway can re-wrap the
/// same orders with different auth without changing the digest.
#[must_use]
pub fn batch_digest(items: &[Item]) -> [u8; 32] {
    let mut h = Hasher::new(Domain::Transaction);
    h.update(&(items.len() as u64).to_le_bytes());
    for it in items {
        h.update(&it.body);
    }
    h.finalize().0
}

/// The session tag: keyed hash of `session ‖ counter ‖ body`.
#[must_use]
pub fn session_tag(key: &[u8; 32], session: u32, counter: u64, body: &[u8; BODY_LEN]) -> [u8; 32] {
    let mut h = Hasher::new_keyed(Domain::Transaction, key);
    h.update(&session.to_le_bytes());
    h.update(&counter.to_le_bytes());
    h.update(body);
    h.finalize().0
}

/// Trusted-input control: accepts everything. Used only to measure the
/// cost of the lane without authentication.
#[derive(Default)]
pub struct NoVerify;

impl Verifier for NoVerify {
    fn name(&self) -> &'static str {
        "none"
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        ok.clear();
        ok.resize(batch.items.len(), true);
    }
}

fn verify_one(it: &Item) -> bool {
    match &it.auth {
        Auth::Sig { key, sig } => ed25519::verify_message(key, &it.body, sig).is_ok(),
        _ => false,
    }
}

/// Exact, slowest: one strict verification per item. The baseline and
/// the fallback everything else must agree with.
#[derive(Default)]
pub struct PerItem;

impl Verifier for PerItem {
    fn name(&self) -> &'static str {
        "per_item"
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        ok.clear();
        ok.extend(batch.items.iter().map(verify_one));
    }
}

/// Batch-equation verification with a per-item fallback.
///
/// Batch verification is all-or-nothing; on failure the items are
/// re-checked one by one to find the bad ones, so the accept set is the
/// same as [`PerItem`] for well-formed signatures (differential-tested).
/// Items that are not [`Auth::Sig`] are rejected.
#[derive(Default)]
pub struct Batched {
    keys: Vec<Ed25519PublicKey>,
    sigs: Vec<Ed25519Signature>,
}

impl Verifier for Batched {
    fn name(&self) -> &'static str {
        "batched"
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        self.keys.clear();
        self.sigs.clear();
        let mut msgs: Vec<&[u8]> = Vec::with_capacity(batch.items.len());
        let mut all_sig = true;
        for it in batch.items {
            if let Auth::Sig { key, sig } = &it.auth {
                self.keys.push(*key);
                self.sigs.push(*sig);
                msgs.push(&it.body);
            } else {
                all_sig = false;
            }
        }
        if all_sig && ed25519::verify_batch(&msgs, &self.keys, &self.sigs).is_ok() {
            ok.clear();
            ok.resize(batch.items.len(), true);
        } else {
            PerItem.verify(batch, ok);
        }
    }
}

/// Gateway-certified batches with deterministic auditing.
///
/// Checks one gateway signature per batch plus the digest, and fully
/// re-verifies a deterministic 1-in-`audit_every` sample of items. The
/// sample offset comes from the digest, so every validator audits the
/// same items. Any failed audit, bad certificate or digest mismatch
/// rejects the *whole batch* (fail closed) and bumps
/// [`Certified::audit_failures`].
pub struct Certified {
    trusted: Vec<Ed25519PublicKey>,
    audit_every: u32,
    /// Number of batches rejected for a bad certificate or failed audit.
    pub audit_failures: u64,
}

impl Certified {
    /// `audit_every` of 0 is treated as 1 (audit everything).
    #[must_use]
    pub fn new(trusted: Vec<Ed25519PublicKey>, audit_every: u32) -> Self {
        Self { trusted, audit_every: audit_every.max(1), audit_failures: 0 }
    }

    fn check(&self, batch: &Batch<'_>) -> bool {
        let Some(c) = batch.cert else { return false };
        if !self.trusted.contains(&c.gateway) {
            return false;
        }
        if c.digest != batch_digest(batch.items) {
            return false;
        }
        if ed25519::verify_message(&c.gateway, &c.digest, &c.sig).is_err() {
            return false;
        }
        let n = self.audit_every as usize;
        let off = usize::from(c.digest[0]) % n;
        batch.items.iter().enumerate().all(|(i, it)| match it.auth {
            Auth::Sig { .. } if (i + off).is_multiple_of(n) => verify_one(it),
            _ => true,
        })
    }
}

impl Verifier for Certified {
    fn name(&self) -> &'static str {
        "certified"
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        let pass = self.check(batch);
        if !pass {
            self.audit_failures += 1;
        }
        ok.clear();
        ok.resize(batch.items.len(), pass);
    }
}

/// An open session: the key and the last counter accepted.
#[derive(Clone, Copy)]
pub struct Session {
    /// Session key shared by the client and the verifying lane.
    pub key: [u8; 32],
    /// Last accepted counter (next must be strictly greater).
    pub last: u64,
}

/// Keyed-hash session authentication.
///
/// The session table is filled by an out-of-band, signature-checked
/// session open (not modeled here). Each item must carry a tag that
/// matches and a counter greater than the last accepted one, so replays
/// and reorders fail. Sessions are per-lane; scope enforcement (market
/// set, notional cap, expiry) belongs to the lane and is signed at open.
#[derive(Default)]
pub struct SessionMac {
    sessions: Vec<Session>,
}

impl SessionMac {
    /// Open a session and return its id.
    pub fn open(&mut self, key: [u8; 32]) -> u32 {
        self.sessions.push(Session { key, last: 0 });
        (self.sessions.len() - 1) as u32
    }
}

impl SessionMac {
    /// Reset every session's counter to 0. For benches that replay a
    /// pre-built batch cycle; a real lane never rewinds.
    pub fn rewind(&mut self) {
        for s in &mut self.sessions {
            s.last = 0;
        }
    }
}

impl Verifier for SessionMac {
    fn name(&self) -> &'static str {
        "session_mac"
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        ok.clear();
        for it in batch.items {
            let good = match it.auth {
                Auth::Mac { session, counter, tag } => {
                    match self.sessions.get_mut(session as usize) {
                        Some(s)
                            if counter > s.last
                                && session_tag(&s.key, session, counter, &it.body) == tag =>
                        {
                            s.last = counter;
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            };
            ok.push(good);
        }
    }
}
