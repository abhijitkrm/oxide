//! The authentication seam (`docs/lanes-spec.md` §4).
//!
//! A [`Verifier`] turns a [`Batch`] of authenticated items into a
//! per-item accept/reject vector. Implementations differ in what they
//! prove per item and what that costs:
//!
//! | Verifier | Per-item cost (M1, 1 core) | Trust added |
//! |---|---|---|
//! | [`EvmRecover`] | ~31 µs (parallel across `threads`) | none |
//! | [`PerItem`] | ~46 µs | none |
//! | [`Batched`] | ~16 µs | none (falls back to per-item on failure) |
//! | [`Certified`] | ~1/`audit_every` of per-item + 1 sig per batch | the gateway, audited |
//! | [`SessionMac`] | ~0.11 µs | the session holder, bounded by session scope |
//!
//! [`Multi`] accepts several schemes in one lane, dispatching per item by
//! its [`Auth`] variant, and [`VerifierConfig`] builds any of them at run
//! time, so an operator chooses the scheme (or the set) and the default
//! (`Multi` with every scheme on) only picks the fastest scheme each client
//! is willing to use. [`OwnerBound`] adds "the authenticated identity must
//! be the order's `owner`" to any verifier.
//!
//! All implementations fail closed: an item that cannot be proven
//! authentic is `false` and the lane must not touch state for it.

use crypto::ed25519::{self, Ed25519PublicKey, Ed25519Signature};
use crypto::secp::{self, RecoverableSignature};
use crypto::{Domain, Hasher};
use primitives::Address;

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
    /// An EVM-style recoverable secp256k1 signature over
    /// `keccak256(body)`; the signer is the recovered address, which
    /// must equal `sender`.
    Evm {
        /// Claimed sender address.
        sender: Address,
        /// Recoverable signature over `keccak256(body)`.
        sig: RecoverableSignature,
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
    /// Open a session under `key` and return its id, for verifiers that
    /// support sessions; `None` otherwise. In a real deployment the open
    /// is itself authorized by a signature the caller has checked.
    fn open_session(&mut self, _key: [u8; 32]) -> Option<u32> {
        None
    }
}

impl Verifier for Box<dyn Verifier> {
    fn name(&self) -> &'static str {
        (**self).name()
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        (**self).verify(batch, ok);
    }
    fn open_session(&mut self, key: [u8; 32]) -> Option<u32> {
        (**self).open_session(key)
    }
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

fn verify_evm(sender: &Address, sig: &RecoverableSignature, body: &[u8; BODY_LEN]) -> bool {
    let hash = secp::keccak256(body);
    secp::recover_sender(&hash, &sig.sig, sig.recid.as_u8()).is_ok_and(|a| a == *sender)
}

fn verify_one(it: &Item) -> bool {
    match &it.auth {
        Auth::Sig { key, sig } => ed25519::verify_message(key, &it.body, sig).is_ok(),
        Auth::Evm { sender, sig } => verify_evm(sender, sig, &it.body),
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
        for it in batch.items {
            if let Auth::Sig { key, sig } = &it.auth {
                self.keys.push(*key);
                self.sigs.push(*sig);
                msgs.push(&it.body);
            }
        }
        // One batch equation over the ed25519 items; everything else is
        // checked individually. If the batch equation fails, fall back to
        // per-item for all so each bad item is found.
        let batch_ok =
            msgs.is_empty() || ed25519::verify_batch(&msgs, &self.keys, &self.sigs).is_ok();
        ok.clear();
        ok.extend(batch.items.iter().map(|it| match it.auth {
            Auth::Sig { .. } if batch_ok => true,
            _ => verify_one(it),
        }));
    }
}

/// EVM-style sender recovery (secp256k1) over `keccak256(body)`, the
/// authentication the EVM lane uses per transaction.
///
/// `threads > 1` splits large batches across scoped threads (no pool, no
/// shared state): recovery is ~31 µs per item and embarrassingly
/// parallel, so this is the lever for the EVM lane's "50 cores" of
/// signature work. Below [`EVM_PARALLEL_MIN`] items a batch runs serial
/// because thread start-up costs more than it saves.
pub struct EvmRecover {
    /// Worker threads (at least 1).
    pub threads: usize,
}

/// Smallest batch that is split across threads. Unit: items. At ~31 µs per
/// recovery a thread's start-up (~20 µs) is paid back after a handful of
/// items per thread; 64 keeps small batches serial and deterministic in
/// cost. Changing it only moves the serial/parallel crossover.
pub const EVM_PARALLEL_MIN: usize = 64;

impl Default for EvmRecover {
    fn default() -> Self {
        Self { threads: 1 }
    }
}

impl Verifier for EvmRecover {
    fn name(&self) -> &'static str {
        "evm_recover"
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        let n = batch.items.len();
        ok.clear();
        ok.resize(n, false);
        let check = |it: &Item| match &it.auth {
            Auth::Evm { sender, sig } => verify_evm(sender, sig, &it.body),
            _ => false,
        };
        let t = self.threads.max(1);
        if t == 1 || n < EVM_PARALLEL_MIN {
            for (o, it) in ok.iter_mut().zip(batch.items) {
                *o = check(it);
            }
            return;
        }
        let chunk = n.div_ceil(t);
        std::thread::scope(|s| {
            for (os, its) in ok.chunks_mut(chunk).zip(batch.items.chunks(chunk)) {
                s.spawn(move || {
                    for (o, it) in os.iter_mut().zip(its) {
                        *o = check(it);
                    }
                });
            }
        });
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
    fn open_session(&mut self, key: [u8; 32]) -> Option<u32> {
        Some(self.open(key))
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

/// The identity an item proves for itself, when the scheme carries one:
/// the ed25519 key's owner address or the EVM sender. Session-MAC and
/// certified items prove identity through the session scope or the
/// gateway instead, so they return `None`.
fn self_identity(it: &Item) -> Option<Address> {
    match &it.auth {
        Auth::Sig { key, .. } => Some(ed25519::owner_address(key)),
        Auth::Evm { sender, .. } => Some(*sender),
        _ => None,
    }
}

/// The order's claimed owner (bytes 20..40 of the body).
fn body_owner(body: &[u8; BODY_LEN]) -> Address {
    let mut o = [0u8; Address::LEN];
    o.copy_from_slice(&body[20..40]);
    Address(o)
}

/// Decorator: in addition to the inner verifier's check, a signature
/// scheme's authenticated identity must equal the order's `owner`.
///
/// Without this an account could sign an order *for someone else's
/// owner address*. Items whose scheme proves identity another way
/// (session scope, gateway certificate) are not affected: binding them
/// is the session's / gateway's job.
pub struct OwnerBound<V: Verifier> {
    /// The wrapped verifier.
    pub inner: V,
}

impl<V: Verifier> Verifier for OwnerBound<V> {
    fn name(&self) -> &'static str {
        self.inner.name()
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        self.inner.verify(batch, ok);
        for (o, it) in ok.iter_mut().zip(batch.items) {
            if *o && self_identity(it).is_some_and(|id| id != body_owner(&it.body)) {
                *o = false;
            }
        }
    }
    fn open_session(&mut self, key: [u8; 32]) -> Option<u32> {
        self.inner.open_session(key)
    }
}

/// Which schemes a [`Multi`] verifier accepts. Anything off is rejected
/// (fail closed), so an operator can run a lane that takes only, say,
/// session MACs and gateway certificates.
// One independent on/off switch per scheme is the whole point of the
// type; a bitset or enum set would only hide the same four flags.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schemes {
    /// Native ed25519 signatures (single or batched).
    pub ed25519: bool,
    /// EVM secp256k1 recoverable signatures.
    pub evm: bool,
    /// Session MAC.
    pub session_mac: bool,
    /// Gateway-certified batches.
    pub certified: bool,
}

impl Schemes {
    /// Every scheme enabled.
    #[must_use]
    pub const fn all() -> Self {
        Self { ed25519: true, evm: true, session_mac: true, certified: true }
    }

    /// Parse a comma-separated list of `ed25519`, `evm`, `mac`, `cert`
    /// (or `all`).
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

/// Accepts several schemes in one lane, dispatching each item by its
/// [`Auth`] variant.
///
/// Within a batch: ed25519 items go through one batch equation (with a
/// per-item fallback), EVM items through [`EvmRecover`] (parallel when
/// `threads > 1`), session items through the session table in original
/// order (counters are order-sensitive), and a batch that carries a gateway
/// certificate goes through [`Certified`] as a whole when that scheme is
/// enabled. Items of a disabled scheme are rejected.
pub struct Multi {
    schemes: Schemes,
    batched: Batched,
    evm: EvmRecover,
    mac: SessionMac,
    cert: Certified,
    bind_owner: bool,
    scratch: Vec<Item>,
    sub_ok: Vec<bool>,
}

impl Multi {
    /// Build with the given schemes.
    #[must_use]
    pub fn new(cfg: &VerifierConfig) -> Self {
        Self {
            schemes: cfg.schemes,
            batched: Batched::default(),
            evm: EvmRecover { threads: cfg.evm_threads },
            mac: SessionMac::default(),
            cert: Certified::new(cfg.trusted_gateways.clone(), cfg.audit_every),
            bind_owner: cfg.bind_owner,
            scratch: Vec::new(),
            sub_ok: Vec::new(),
        }
    }

    /// Verify the items selected by `pick` with `v`, writing results back
    /// into `ok` at their original positions.
    fn subset(&mut self, items: &[Item], ok: &mut [bool], pick: fn(&Auth) -> bool, which: u8) {
        self.scratch.clear();
        self.scratch.extend(items.iter().filter(|it| pick(&it.auth)).copied());
        if self.scratch.is_empty() {
            return;
        }
        let sub = Batch { items: &self.scratch, cert: None };
        match which {
            0 => self.batched.verify(&sub, &mut self.sub_ok),
            1 => self.evm.verify(&sub, &mut self.sub_ok),
            _ => self.mac.verify(&sub, &mut self.sub_ok),
        }
        let mut k = 0;
        for (o, it) in ok.iter_mut().zip(items) {
            if pick(&it.auth) {
                *o = self.sub_ok[k];
                k += 1;
            }
        }
    }
}

impl Verifier for Multi {
    fn name(&self) -> &'static str {
        "multi"
    }
    fn open_session(&mut self, key: [u8; 32]) -> Option<u32> {
        self.schemes.session_mac.then(|| self.mac.open(key))
    }
    fn verify(&mut self, batch: &Batch<'_>, ok: &mut Vec<bool>) {
        if batch.cert.is_some() && self.schemes.certified {
            self.cert.verify(batch, ok);
        } else {
            ok.clear();
            ok.resize(batch.items.len(), false);
            if self.schemes.ed25519 {
                self.subset(batch.items, ok, |a| matches!(a, Auth::Sig { .. }), 0);
            }
            if self.schemes.evm {
                self.subset(batch.items, ok, |a| matches!(a, Auth::Evm { .. }), 1);
            }
            if self.schemes.session_mac {
                self.subset(batch.items, ok, |a| matches!(a, Auth::Mac { .. }), 2);
            }
        }
        if self.bind_owner {
            for (o, it) in ok.iter_mut().zip(batch.items) {
                if *o && self_identity(it).is_some_and(|id| id != body_owner(&it.body)) {
                    *o = false;
                }
            }
        }
    }
}

/// Which verifier to run. There is deliberately no "accept everything"
/// kind: [`NoVerify`] is a bench control and cannot be configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifierKind {
    /// [`PerItem`] ed25519.
    PerItem,
    /// [`Batched`] ed25519.
    Batched,
    /// [`EvmRecover`].
    Evm,
    /// [`Certified`].
    Certified,
    /// [`SessionMac`].
    SessionMac,
    /// [`Multi`] over [`Schemes`].
    Multi,
}

impl VerifierKind {
    /// Parse a config name.
    ///
    /// # Errors
    ///
    /// The unrecognized name.
    pub fn parse(name: &str) -> Result<Self, String> {
        Ok(match name {
            "per_item" | "ed25519" => Self::PerItem,
            "batched" | "ed25519_batch" => Self::Batched,
            "evm" | "evm_recover" => Self::Evm,
            "certified" | "cert" => Self::Certified,
            "session_mac" | "mac" => Self::SessionMac,
            "multi" => Self::Multi,
            other => return Err(other.to_string()),
        })
    }
}

/// Runtime verifier selection.
///
/// The default is `Multi` with every scheme enabled: each client uses
/// whichever scheme it prefers and the lane accepts it, so the fast
/// schemes are used when clients opt in and nothing is forced. An
/// operator who wants one scheme only sets `kind` (or `schemes` under
/// `Multi`).
#[derive(Clone)]
pub struct VerifierConfig {
    /// Which verifier to build.
    pub kind: VerifierKind,
    /// Schemes accepted when `kind` is `Multi`.
    pub schemes: Schemes,
    /// Threads for EVM recovery. Unit: threads. 1 = serial.
    pub evm_threads: usize,
    /// Gateways whose certificates are accepted (`Certified`/`Multi`).
    pub trusted_gateways: Vec<Ed25519PublicKey>,
    /// Certificate audit sample, 1 in N items. Unit: items. Higher is
    /// cheaper and less safe; 64 is the spec default.
    pub audit_every: u32,
    /// Require a signature scheme's identity to equal the order owner.
    pub bind_owner: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            kind: VerifierKind::Multi,
            schemes: Schemes::all(),
            evm_threads: 1,
            trusted_gateways: Vec::new(),
            audit_every: 64,
            bind_owner: true,
        }
    }
}

impl VerifierConfig {
    /// Build the configured verifier. Owner binding wraps every kind
    /// except `Multi`, which applies it internally.
    #[must_use]
    pub fn build(&self) -> Box<dyn Verifier> {
        fn wrap<V: Verifier + 'static>(v: V, bind: bool) -> Box<dyn Verifier> {
            if bind { Box::new(OwnerBound { inner: v }) } else { Box::new(v) }
        }
        let b = self.bind_owner;
        match self.kind {
            VerifierKind::PerItem => wrap(PerItem, b),
            VerifierKind::Batched => wrap(Batched::default(), b),
            VerifierKind::Evm => wrap(EvmRecover { threads: self.evm_threads }, b),
            VerifierKind::Certified => {
                wrap(Certified::new(self.trusted_gateways.clone(), self.audit_every), b)
            }
            VerifierKind::SessionMac => wrap(SessionMac::default(), b),
            VerifierKind::Multi => Box::new(Multi::new(self)),
        }
    }
}
