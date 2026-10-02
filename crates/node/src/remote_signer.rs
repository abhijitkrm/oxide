//! A privval-style remote consensus signer: the BLS secret lives in
//! a signer daemon, and the validator process holds only a
//! [`RemoteSigner`] client behind `Arc<dyn ConsensusSigner>`.
//!
//! # Why
//!
//! `docs/audit002.md` C4's last piece: the consensus key is what
//! equivocation-slashable signatures are made of, and a validator
//! that keeps it in its own address space loses the key the moment
//! the process is compromised. The privval model (a small signing
//! daemon on a trusted link) moves the secret off the hot host and,
//! critically, gives the *signer* the durable high-watermark — a
//! crashed-and-failed-over validator pair cannot equivocate because
//! the shared signer refuses the second signature at a repeated
//! `(epoch, mark, phase)` coordinate.
//!
//! # Wire protocol
//!
//! TCP, little-endian integers. Every connection opens with an
//! authentication handshake, then exchanges MAC'd frames:
//!
//! ```text
//! auth     := tag 3 (AuthHello) | client_nonce:32B | client_proof:32B
//!   client_proof = MAC(link_key, "client" ‖ client_nonce)
//! authresp := status:u8 | len:u32 | payload           (unMAC'd —
//!   the daemon_proof inside it authenticates this frame)
//!   status 4 (AuthOk): payload = daemon_nonce:32B | daemon_proof:32B
//!     daemon_proof = MAC(link_key, "daemon" ‖ client_nonce ‖ daemon_nonce)
//!   status 3 (Error):  payload = utf8 reason — auth failed, close.
//! session keys (both ends derive, never transmitted):
//!   c2s = MAC(link_key, "c2s" ‖ client_nonce ‖ daemon_nonce)
//!   s2c = MAC(link_key, "s2c" ‖ client_nonce ‖ daemon_nonce)
//!
//! request  := req_mac:32B | len:u32 | body
//!   body   := tag:u8 | payload
//!   req_mac = MAC(c2s, seq:u64 ‖ len ‖ body)
//!   tag 1 (SignRequest):   domain:u8 | epoch:u64 | mark:u64 |
//!                          phase:u8 | msg_len:u32 | msg
//!   tag 2 (PubKeyRequest): (empty)
//! response := resp_mac:32B | status:u8 | payload_len:u32 | payload
//!   resp_mac = MAC(s2c, seq:u64 ‖ status ‖ payload_len ‖ payload)
//!   status 0 (Signed):   payload = 96-byte BLS signature
//!   status 1 (Refused):  payload = utf8 reason (fence rejection —
//!                        the coordinate regressed or conflicts)
//!   status 2 (PubKey):   payload = 48-byte public key
//!   status 3 (Error):    payload = utf8 diagnostic
//! ```
//!
//! `seq` starts at 0 per connection and increments per request;
//! responses carry the request's `seq`. A MAC failure drops the
//! connection — there is no soft error for an inauthentic frame.
//!
//! `SignRequest` carries the [`crypto::SignContext`] because the
//! signable bytes cannot supply it: a proposal's payload is an
//! opaque 32-byte hash, and even the structured domains would make
//! the daemon re-derive consensus layout knowledge it has no
//! business owning. The coordinate is advisory to verify — the
//! fence never trusts it against a *different* message anyway —
//! the property it protects is honest-process equivocation
//! (restart/failover), not a malicious client (a hostile validator
//! host can always request whatever signatures it wants; the fence
//! exists so two *honest* processes cannot equivocate through a
//! shared signer).
//!
//! # Fencing
//!
//! The fenced domains are the consensus-coordinate ones:
//! [`Domain::Vote`], [`Domain::Timeout`], [`Domain::Proposal`], and
//! [`Domain::ExecAttest`]. Each keeps one durable record —
//! `(epoch, mark, phase)` + the BLAKE3 hash of the signed message:
//!
//! - coordinate < record → **refused** (regression: a stale process
//!   asking for a signature the engine already moved past).
//! - coordinate == record, different message → **refused**
//!   (equivocation: two distinct signables at one coordinate).
//! - coordinate == record, same message → **allowed** (idempotent
//!   re-sign — BLS is deterministic; this is what makes a retried
//!   request after a dropped connection safe).
//! - coordinate > record → **allowed**, record updated first.
//!
//! The record is persisted to disk *before* the signature leaves
//! the daemon — the same rule the engine's WAL applies: no
//! signature may outlive the durability of the anti-equivocation
//! state that produced it. A persist failure answers `Error`
//! without signing.
//!
//! Unfenced domains (handshake proofs, `PoP`, everything else) sign
//! unconditionally — a handshake transcript is a fresh random nonce
//! with no progress coordinate and no equivocation concept.
//!
//! # Link security
//!
//! The link carries only signatures and already-public bytes — the
//! consensus secret never crosses it — so the transport need not
//! hide payloads; it must prevent a third party from *issuing*
//! requests or *forging* responses. Before authentication, anyone
//! who could reach the port had two attacks: burn the fence
//! (requests at coordinates ahead of the engine stall the real
//! validator behind a regression refusal) and, worse, use the
//! daemon as a signing oracle on unfenced domains — a
//! `PeerHandshake` signature is a validator-identity forgery.
//!
//! Authentication is a pre-shared **link key**: 32 bytes of
//! symmetric entropy both ends load from a file
//! (`--link-key-file` on the daemon, `--signer-link-key-file` on
//! the validator — the same file). The handshake proves key
//! possession both ways (client proves first, daemon answers with
//! its own proof over both nonces), then per-session MAC keys are
//! derived per direction — a captured session's MACs are useless
//! for a later connection, and knowing the link key alone never
//! reveals which frames a *different* session MAC'd. The key is
//! mandatory: the daemon's first read must be `AuthHello`, so a
//! pre-auth connection can only waste one handshake-timeout
//! thread, never reach the fence.
//!
//! Deliberately not TLS: the privval convention is a small,
//! physically trusted link, and a shared MAC key is the entire
//! trust decision — there is no CA, no certificate lifecycle, and
//! no peer set to manage. The daemon serves each connection on its
//! own thread so the documented failover pair (two validators, one
//! fenced daemon) can hold simultaneous sessions; the fence mutex
//! already serializes check→persist→sign across threads.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crypto::hash::Domain;
use crypto::{BlsSecretKey, ConsensusSigner, SignContext, Signature, SignerError};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Protocol tag: a signing request (`SignRequest`).
const TAG_SIGN_REQUEST: u8 = 1;
/// Protocol tag: a public-key request (`PubKeyRequest`).
const TAG_PUBKEY_REQUEST: u8 = 2;
/// Protocol tag: the authentication hello — the only frame allowed
/// before a session is established.
const TAG_AUTH_HELLO: u8 = 3;

/// Response status: request signed; payload is the 96-byte sig.
const STATUS_SIGNED: u8 = 0;
/// Response status: the fence refused the request; payload is a
/// utf8 reason. A refusal is a *safety* answer — the daemon is
/// healthy, it is declining to equivocate.
const STATUS_REFUSED: u8 = 1;
/// Response status: public-key answer; payload is the 48-byte key.
const STATUS_PUBKEY: u8 = 2;
/// Response status: daemon-side failure; payload is a utf8
/// diagnostic (malformed request, persist failure, failed auth).
const STATUS_ERROR: u8 = 3;
/// Response status: handshake accepted; payload is
/// `daemon_nonce ‖ daemon_proof` (see module docs).
const STATUS_AUTH_OK: u8 = 4;

/// Upper bound on a request's `msg` field: the largest legitimate
/// signable is the 57-byte timeout message — anything bigger is a
/// malformed/hostile frame, and the bound keeps a garbage length
/// from driving a daemon-side allocation. Origin: wire format
/// `types::` messages; tradeoff: a future domain whose signable
/// exceeds this must raise the constant in lockstep on both sides.
const MAX_MSG_BYTES: u32 = 4096;
/// Upper bound on a request *body* (`tag ‖ payload`): tag + the
/// `SignRequest` header (1 domain + 8 epoch + 8 mark + 1 phase +
/// 4 `msg_len`) + the message itself.
const MAX_REQUEST_BODY: u32 = 1 + 18 + 4 + MAX_MSG_BYTES;
/// Upper bound on a response payload (error strings are the only
/// variable-size payload; 4 KiB is far past any diagnostic).
const MAX_RESPONSE_BYTES: u32 = 4096;

/// Bound on the daemon's handshake read: a TCP peer that connects
/// and sends nothing must not hold a serve thread forever. 10 s is
/// far past any sane client (the hello is the first bytes sent on
/// connect) while keeping the pre-auth thread pool bounded.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The MAC / KDF: keyed BLAKE3 under [`Domain::SignerLink`], so
/// link material can never alias a signature preimage. `label`
/// gives the role separation (`client`, `daemon`, `c2s`, `s2s`);
/// `parts` is the frame material in wire order.
fn mac(key: &[u8; 32], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = crypto::Hasher::new_keyed(Domain::SignerLink, key);
    h.update(label);
    for p in parts {
        h.update(p);
    }
    h.finalize().as_bytes().try_into().expect("BLAKE3 is 32 bytes")
}

/// Constant-time 32-byte equality — MAC checks must not leak how
/// many leading bytes matched via early-exit timing.
fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The per-session MAC keys derived from the link key + both
/// nonces. `c2s` authenticates client→daemon frames, `s2c` the
/// reverse; separating the directions means a reflected frame
/// never verifies in the wrong direction. `ZeroizeOnDrop`: the
/// keys are as sensitive as the link key — a live session MAC key
/// forges frames for its direction.
#[derive(ZeroizeOnDrop)]
struct Session {
    c2s: [u8; 32],
    s2c: [u8; 32],
}

impl Session {
    /// Derive the directional keys — both ends run the same
    /// derivation over the exchanged nonces.
    fn derive(link_key: &[u8; 32], client_nonce: &[u8; 32], daemon_nonce: &[u8; 32]) -> Self {
        Self {
            c2s: mac(link_key, b"c2s", &[client_nonce, daemon_nonce]),
            s2c: mac(link_key, b"s2c", &[client_nonce, daemon_nonce]),
        }
    }

    /// MAC one request frame (`len ‖ body`, body = `tag ‖ payload`)
    /// at `seq`. The length sits inside the MAC so a tampered
    /// length prefix fails verification, not just framing.
    fn request_mac(&self, seq: u64, body: &[u8]) -> [u8; 32] {
        mac(&self.c2s, b"", &[&seq.to_le_bytes(), &body_len(body), body])
    }

    /// MAC one response frame at `seq`: the preimage is
    /// `seq ‖ status ‖ payload_len ‖ payload` — the same bytes the
    /// receiver will parse, so a MITM bit-flip anywhere fails.
    fn response_mac(&self, seq: u64, status: u8, payload: &[u8]) -> [u8; 32] {
        mac(&self.s2c, b"", &[&seq.to_le_bytes(), &[status], &body_len(payload), payload])
    }
}

/// The wire `u32` length prefix of a body — callers bound the size
/// before framing, so the cast cannot wrap.
fn body_len(body: &[u8]) -> [u8; 4] {
    u32::try_from(body.len()).expect("bounded frame bodies").to_le_bytes()
}

/// Fence-state file magic + version — `OXSG\x01`. The file is the
/// daemon's only durable state: the high-watermark records that
/// survive a signer restart.
const FENCE_MAGIC: &[u8; 5] = b"OXSG\x01";

/// On-disk fence record length: `domain:u8 | epoch:u64 | mark:u64 |
/// phase:u8 | msg_hash:32B` — 50 bytes.
const REC_LEN: usize = 1 + 8 + 8 + 1 + 32;

/// The domains the fence applies to — the ones whose signature
/// carries consensus progress. Everything else signs
/// unconditionally (see module docs).
fn fenced(domain: Domain) -> bool {
    matches!(domain, Domain::Vote | Domain::Timeout | Domain::Proposal | Domain::ExecAttest)
}

/// A daemon-side fence record for one domain: the highest signed
/// coordinate plus the hash of the message signed there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FenceRecord {
    epoch: u64,
    mark: u64,
    phase: u8,
    msg_hash: [u8; 32],
}

/// The durable high-watermark fence: one [`FenceRecord`] per fenced
/// domain, persisted to `path` on every signing.
///
/// The file format is `OXSG\x01 | count:u32 | records*` where each
/// record is `domain:u8 | epoch:u64 | mark:u64 | phase:u8 |
/// msg_hash:32B` — 50 bytes. Writes go through a tmp file + rename
/// + directory fsync so a crash mid-write can only lose the
///   *newest* record (the rename is atomic), never corrupt the file.
struct FenceState {
    path: PathBuf,
    records: BTreeMap<u8, FenceRecord>,
}

impl FenceState {
    /// Load the fence file, or start empty when none exists.
    ///
    /// An existing but malformed file is an error, not a fresh
    /// start: a corrupt fence means we cannot prove what was
    /// already signed, and silently resetting it could permit an
    /// equivocation the file was written to prevent.
    fn load(path: &Path) -> Result<Self, SignerError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self { path: path.to_path_buf(), records: BTreeMap::new() });
            }
            Err(e) => {
                return Err(SignerError::Unavailable(format!(
                    "cannot read signer state {}: {e}",
                    path.display()
                )));
            }
        };
        if bytes.len() < FENCE_MAGIC.len() + 4 || &bytes[..FENCE_MAGIC.len()] != FENCE_MAGIC {
            return Err(SignerError::Unavailable(format!(
                "signer state {} is corrupt (bad magic) — refusing to sign with an \
                 unknown high-watermark",
                path.display()
            )));
        }
        let count = u32::from_le_bytes(
            bytes[FENCE_MAGIC.len()..FENCE_MAGIC.len() + 4].try_into().expect("4-byte count"),
        ) as usize;
        if bytes.len() != FENCE_MAGIC.len() + 4 + count * REC_LEN {
            return Err(SignerError::Unavailable(format!(
                "signer state {} is corrupt (length mismatch) — refusing to sign",
                path.display()
            )));
        }
        let mut records = BTreeMap::new();
        let mut off = FENCE_MAGIC.len() + 4;
        for _ in 0..count {
            let domain = bytes[off];
            let epoch = u64::from_le_bytes(bytes[off + 1..off + 9].try_into().expect("8"));
            let mark = u64::from_le_bytes(bytes[off + 9..off + 17].try_into().expect("8"));
            let phase = bytes[off + 17];
            let mut msg_hash = [0u8; 32];
            msg_hash.copy_from_slice(&bytes[off + 18..off + 50]);
            records.insert(domain, FenceRecord { epoch, mark, phase, msg_hash });
            off += REC_LEN;
        }
        Ok(Self { path: path.to_path_buf(), records })
    }

    /// Serialize + atomically persist the fence. Fails closed: the
    /// caller must not release a signature whose fence update did
    /// not reach disk.
    fn persist(&self) -> Result<(), SignerError> {
        let mut buf = Vec::with_capacity(FENCE_MAGIC.len() + 4 + self.records.len() * 50);
        buf.extend_from_slice(FENCE_MAGIC);
        let count = u32::try_from(self.records.len()).map_err(|_| {
            SignerError::Unavailable("signer state exceeds the u32 record-count bound".into())
        })?;
        buf.extend_from_slice(&count.to_le_bytes());
        for (domain, r) in &self.records {
            buf.push(*domain);
            buf.extend_from_slice(&r.epoch.to_le_bytes());
            buf.extend_from_slice(&r.mark.to_le_bytes());
            buf.push(r.phase);
            buf.extend_from_slice(&r.msg_hash);
        }
        let tmp = self.path.with_extension("tmp");
        let write_res = (|| -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)?;
            // Fsync the directory so the rename itself is durable —
            // a file fsync alone does not commit the directory entry.
            if let Some(dir) = self.path.parent() {
                std::fs::File::open(dir)?.sync_all()?;
            }
            Ok(())
        })();
        write_res.map_err(|e| {
            SignerError::Unavailable(format!(
                "cannot persist signer state {}: {e}",
                self.path.display()
            ))
        })
    }

    /// The fence decision for `(domain, ctx, msg_hash)`.
    ///
    /// `Err` is a refusal string — the daemon reports it as
    /// `Refused`, not as a transport failure.
    fn check(&self, domain: Domain, ctx: SignContext, msg_hash: &[u8; 32]) -> Result<(), String> {
        if !fenced(domain) {
            return Ok(());
        }
        let Some(rec) = self.records.get(&(domain as u8)) else { return Ok(()) };
        let requested = (ctx.epoch, ctx.mark, ctx.phase);
        let held = (rec.epoch, rec.mark, rec.phase);
        if requested < held {
            return Err(format!(
                "fence: {domain:?} request at {requested:?} regresses below \
                 the signed high-watermark {held:?}"
            ));
        }
        if requested == held && *msg_hash != rec.msg_hash {
            return Err(format!(
                "fence: {domain:?} request at {requested:?} conflicts with the \
                 already-signed message — refusing to equivocate"
            ));
        }
        Ok(())
    }

    /// Record a signature about to be released. Must be called —
    /// and must succeed — before the signature leaves the daemon.
    fn record(
        &mut self,
        domain: Domain,
        ctx: SignContext,
        msg_hash: [u8; 32],
    ) -> Result<(), SignerError> {
        if fenced(domain) {
            self.records.insert(
                domain as u8,
                FenceRecord { epoch: ctx.epoch, mark: ctx.mark, phase: ctx.phase, msg_hash },
            );
            self.persist()?;
        }
        Ok(())
    }
}

/// The daemon: holds the secret key, the durable fence, and the
/// link key, serving signing requests over a TCP listener.
///
/// One `SignerDaemon` is one consensus identity — a failover pair of
/// validators points at the same daemon and the fence is what makes
/// their signatures non-equivocating.
pub struct SignerDaemon {
    key: BlsSecretKey,
    // The shared link secret authenticates every client handshake —
    // zeroized on drop like the signing key itself.
    link_key: Zeroizing<[u8; 32]>,
    state: Mutex<FenceState>,
}

impl SignerDaemon {
    /// Load the secret key and the fence file. The keys come in
    /// already decoded — the binary owns keystore/hex parsing; the
    /// daemon owns only what it needs to sign and authenticate.
    /// `link_key` is the 32-byte shared secret every legitimate
    /// client proves in the handshake — see the module docs for the
    /// protocol.
    ///
    /// # Errors
    /// [`SignerError::Unavailable`] when the fence file exists but is
    /// unreadable or corrupt — signing without a trustworthy
    /// high-watermark could equivocate.
    pub fn new(
        key: BlsSecretKey,
        state_path: PathBuf,
        link_key: [u8; 32],
    ) -> Result<Self, SignerError> {
        Ok(Self {
            key,
            link_key: Zeroizing::new(link_key),
            state: Mutex::new(FenceState::load(&state_path)?),
        })
    }

    /// The daemon's public key — what `PubKeyRequest` answers.
    #[must_use]
    pub fn public_key(&self) -> crypto::PublicKey {
        self.key.public_key()
    }

    /// Serve requests until `shutdown` is set. Each accepted
    /// connection gets its own thread: the documented failover
    /// topology is *two* validators holding simultaneous
    /// persistent sessions, and a serial accept loop would starve
    /// the second peer behind the first's connection for its whole
    /// lifetime. Signing stays correct under threads because every
    /// request runs check→persist→sign under the fence mutex —
    /// the fence is only correct if that sequence is atomic.
    ///
    /// # Panics
    /// Panics if `listener.accept()` fails — a daemon that cannot
    /// accept is not a degraded signer, it is a dead one.
    pub fn serve(self: &Arc<Self>, listener: TcpListener, shutdown: &AtomicBool) {
        // The accept loop must observe the flag, so put the socket
        // in nonblocking mode and poll — a blocking accept would
        // outlive the shutdown request until a peer connects.
        listener.set_nonblocking(true).expect("nonblocking listener");
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Detached: a connection thread lives until its
                    // peer hangs up or misbehaves; the process owns
                    // the set and exiting reaps them. Threads are
                    // cheap — only link-key holders get past the
                    // handshake anyway.
                    let this = Arc::clone(self);
                    std::thread::spawn(move || this.serve_conn(stream));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("signer daemon accept failed: {e}"),
            }
        }
    }

    /// Run the mutual-authentication handshake on a fresh
    /// connection. `Some(Session)` means the peer proved the link
    /// key and both sides derived the session MAC keys; `None`
    /// means auth failed or the peer went away — the connection is
    /// dropped either way (a failed-auth peer gets an `Error`
    /// frame first so a misconfigured client learns why).
    fn handshake(&self, stream: &mut TcpStream) -> Option<Session> {
        // The pre-auth read is the only place an anonymous peer can
        // stall this thread — bound it, then clear the deadline so
        // an authenticated session may idle between requests.
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).ok()?;
        let mut hello = [0u8; 1 + 32 + 32];
        stream.read_exact(&mut hello).ok()?;
        if hello[0] != TAG_AUTH_HELLO {
            let _ = write_response(stream, STATUS_ERROR, b"expected auth hello");
            return None;
        }
        let client_nonce: &[u8; 32] = hello[1..33].try_into().expect("32-byte nonce");
        let client_proof: &[u8; 32] = hello[33..65].try_into().expect("32-byte proof");
        let expected = mac(&self.link_key, b"client", &[client_nonce]);
        if !ct_eq32(client_proof, &expected) {
            let _ = write_response(stream, STATUS_ERROR, b"unauthenticated");
            return None;
        }
        let daemon_nonce = crypto::random_nonce();
        let daemon_proof = mac(&self.link_key, b"daemon", &[client_nonce, &daemon_nonce]);
        let mut payload = Vec::with_capacity(64);
        payload.extend_from_slice(&daemon_nonce);
        payload.extend_from_slice(&daemon_proof);
        write_response(stream, STATUS_AUTH_OK, &payload).ok()?;
        // Authenticated: no deadline — a validator idles between
        // requests by design (persistent session, sign per block).
        stream.set_read_timeout(None).ok()?;
        Some(Session::derive(&self.link_key, client_nonce, &daemon_nonce))
    }

    /// Handle one authenticated connection until the peer hangs up
    /// or a frame fails verification — a bad MAC is never a soft
    /// error, the connection is dropped.
    fn serve_conn(&self, mut stream: TcpStream) {
        // Accepted sockets inherit the listener's nonblocking flag
        // on some platforms (BSD/macOS); the connection protocol is
        // strictly blocking read/write, so force it back here —
        // on Linux this is a no-op.
        if stream.set_nonblocking(false).is_err() {
            return;
        }
        let Some(sess) = self.handshake(&mut stream) else { return };
        let mut seq = 0u64;
        loop {
            // Frame: mac:32 ‖ len:u32 ‖ body (body = tag ‖ payload).
            let mut hdr = [0u8; 32 + 4];
            if stream.read_exact(&mut hdr).is_err() {
                return;
            }
            let len = u32::from_le_bytes(hdr[32..36].try_into().expect("4"));
            if len == 0 || len > MAX_REQUEST_BODY {
                let _ = Self::send_response(&mut stream, &sess, seq, STATUS_ERROR, b"bad length");
                return;
            }
            let mut body = vec![0u8; len as usize];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            let expected = sess.request_mac(seq, &body);
            if !ct_eq32(hdr[..32].try_into().expect("32"), &expected) {
                return;
            }
            let (status, payload) = match body[0] {
                TAG_PUBKEY_REQUEST => (STATUS_PUBKEY, self.key.public_key().as_bytes().to_vec()),
                TAG_SIGN_REQUEST => match self.handle_sign_request(&body) {
                    Ok(pair) => pair,
                    Err(resp) => {
                        // Persist failure: report and drop — a
                        // daemon that cannot fence must not keep
                        // answering on this connection.
                        let _ = Self::send_response(&mut stream, &sess, seq, STATUS_ERROR, &resp);
                        return;
                    }
                },
                _ => (STATUS_ERROR, b"unknown request tag".to_vec()),
            };
            if Self::send_response(&mut stream, &sess, seq, status, &payload).is_err() {
                return;
            }
            seq += 1;
        }
    }

    /// Encode + MAC + write one response frame at `seq`.
    fn send_response(
        stream: &mut TcpStream,
        sess: &Session,
        seq: u64,
        status: u8,
        payload: &[u8],
    ) -> std::io::Result<()> {
        if payload.len() > MAX_RESPONSE_BYTES as usize {
            // Impossible today (largest payload is a 96-byte
            // signature); fail closed rather than frame past the
            // client's bound.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "response payload exceeds bound",
            ));
        }
        let mut out = Vec::with_capacity(32 + 5 + payload.len());
        out.extend_from_slice(&sess.response_mac(seq, status, payload));
        out.push(status);
        out.extend_from_slice(&body_len(payload));
        out.extend_from_slice(payload);
        stream.write_all(&out)
    }

    /// Handle one `SignRequest` body (`domain ‖ epoch ‖ mark ‖
    /// phase ‖ msg_len ‖ msg` after the tag byte). On success the
    /// pair is `(status, payload)` for the caller to MAC and send;
    /// on persist failure the `Err` carries the diagnostic — the
    /// caller reports it and drops the connection, because a
    /// daemon that cannot fence is not a safe signer.
    fn handle_sign_request(&self, body: &[u8]) -> Result<(u8, Vec<u8>), Vec<u8>> {
        // body[0] is the tag, consumed by the dispatcher.
        let hdr_len = 1 + 1 + 8 + 8 + 1 + 4;
        let Some(hdr) = body.get(1..hdr_len) else {
            return Ok((STATUS_ERROR, b"truncated sign request".to_vec()));
        };
        let Some(domain) = domain_from_u8(hdr[0]) else {
            return Ok((STATUS_ERROR, b"unknown domain".to_vec()));
        };
        let epoch = u64::from_le_bytes(hdr[1..9].try_into().expect("8"));
        let mark = u64::from_le_bytes(hdr[9..17].try_into().expect("8"));
        let phase = hdr[17];
        let msg_len = u32::from_le_bytes(hdr[18..22].try_into().expect("4")) as usize;
        let Some(msg) = body.get(hdr_len..hdr_len + msg_len) else {
            return Ok((STATUS_ERROR, b"truncated message".to_vec()));
        };
        if msg.len() != msg_len || body.len() != hdr_len + msg_len {
            return Ok((STATUS_ERROR, b"message length mismatch".to_vec()));
        }
        if msg_len > MAX_MSG_BYTES as usize {
            return Ok((STATUS_ERROR, b"message exceeds bound".to_vec()));
        }
        let ctx = SignContext { epoch, mark, phase };
        let msg_hash: [u8; 32] = crypto::Hasher::hash_one(Domain::Block, msg)
            .as_bytes()
            .try_into()
            .expect("BLAKE3 output is 32 bytes");
        self.sign_fenced(domain, msg, ctx, msg_hash).map_err(String::into_bytes)
    }

    /// Fence → persist → sign. The whole sequence runs under the
    /// state mutex so a second connection cannot slip a request
    /// between another's check and record. Returns the
    /// `(status, payload)` pair to answer; `Err(reason)` only on a
    /// persist failure — the caller reports it then drops the
    /// connection, because answering while the fence cannot reach
    /// disk would keep signing state the next restart cannot see.
    fn sign_fenced(
        &self,
        domain: Domain,
        msg: &[u8],
        ctx: SignContext,
        msg_hash: [u8; 32],
    ) -> Result<(u8, Vec<u8>), String> {
        // Poison recovery is safe *and* stricter here: a panic mid-
        // `record` can only leave the in-memory fence AHEAD of the
        // persisted one (records are insert-only), so the recovered
        // guard enforces a superset of what disk guarantees — the
        // fail-closed direction. Cascading the panic would wedge the
        // validator's signing for no safety gain.
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(reason) = state.check(domain, ctx, &msg_hash) {
            return Ok((STATUS_REFUSED, reason.into_bytes()));
        }
        // Persist BEFORE the signature exists — a crash between
        // "signed" and "fenced" would let a restarted daemon sign a
        // conflicting message at the same coordinate.
        state.record(domain, ctx, msg_hash).map_err(|e| e.to_string())?;
        let sig = self.key.sign(domain, msg);
        Ok((STATUS_SIGNED, sig.as_bytes().to_vec()))
    }
}

/// Map a wire byte to a [`Domain`] — the enum is `repr(u8)` with
/// stable discriminants; unknown bytes fail closed. Deliberately
/// absent: [`Domain::SignerLink`] — the link's MAC domain is not a
/// signing domain, so byte 20 answers `unknown domain` like any
/// other out-of-range value.
fn domain_from_u8(b: u8) -> Option<Domain> {
    Some(match b {
        0 => Domain::Block,
        1 => Domain::Transaction,
        2 => Domain::Vote,
        3 => Domain::QuorumCertificate,
        4 => Domain::Timeout,
        5 => Domain::MmrNode,
        6 => Domain::MmrLeaf,
        7 => Domain::StateRoot,
        8 => Domain::MmrRoot,
        9 => Domain::Proposal,
        10 => Domain::ValidatorAddress,
        11 => Domain::StateSyncChunk,
        12 => Domain::BodyShardLeaf,
        13 => Domain::BodyShardNode,
        14 => Domain::ExecAttest,
        15 => Domain::BlsPop,
        16 => Domain::Ed25519Owner,
        17 => Domain::ExecutedNonceLeaf,
        18 => Domain::CommittedLeaf,
        19 => Domain::PeerHandshake,
        _ => return None,
    })
}

/// Write one *unauthenticated* response frame — only the handshake
/// uses this; session responses are MAC'd via
/// [`SignerDaemon::send_response`].
fn write_response(stream: &mut TcpStream, status: u8, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "response payload exceeds u32")
    })?;
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(status);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    stream.write_all(&out)
}

/// An authenticated link session: the socket plus the derived MAC
/// keys and the next request sequence number. Re-dialing produces
/// a fresh session (fresh nonces → fresh keys, `seq` restarts at
/// 0 — the daemon tracks the sequence per connection).
struct Conn {
    stream: TcpStream,
    sess: Session,
    seq: u64,
}

/// The client half: a `ConsensusSigner` backed by a [`SignerDaemon`]
/// over TCP. The validator binary installs it as the engine's
/// signer — and as the handshake auth's signer — so the consensus
/// secret never exists in the validator process at all.
///
/// The connection is persistent and reconnect-once on failure: a
/// dropped socket mid-request is retried once, which the daemon's
/// idempotent fence makes sound (same coordinate + same message is
/// always re-signable). Every re-dial re-runs the handshake —
/// session keys are per-connection, so a retry cannot reuse a
/// dead session's MACs.
pub struct RemoteSigner {
    addr: String,
    // The client credential — a copy of the daemon's link secret.
    // Zeroized with the struct so a retired signer doesn't leave it
    // in freed memory.
    link_key: Zeroizing<[u8; 32]>,
    conn: Mutex<Option<Conn>>,
    public_key: crypto::PublicKey,
    io_timeout: Duration,
}

impl RemoteSigner {
    /// Connect to the daemon at `addr`, authenticate with
    /// `link_key`, and fetch its public key.
    ///
    /// `link_key` is the same 32-byte shared secret the daemon was
    /// started with — the validator loads it from
    /// `--signer-link-key-file`; possession alone is the client
    /// credential (see the module docs for the handshake).
    ///
    /// `io_timeout` bounds every socket read/write — the engine's
    /// signing path is synchronous, so a hung daemon must fail the
    /// request, not freeze the consensus loop.
    ///
    /// Connect retries briefly before giving up: boot ordering
    /// between the validator and its signer daemon is a deployment
    /// detail, and a one-shot `connect` would make the validator's
    /// startup depend on the daemon binding first. ~5 s of
    /// 100 ms-spaced retries covers a daemon that is still loading
    /// its key; a truly absent daemon still fails the boot.
    ///
    /// # Errors
    /// [`SignerError::Unavailable`] when the daemon cannot be
    /// reached, refuses the link key, or does not answer the
    /// public-key request.
    pub fn connect(
        addr: &str,
        io_timeout: Duration,
        link_key: [u8; 32],
    ) -> Result<Self, SignerError> {
        let mut last_err = None;
        for _ in 0..50 {
            match Self::dial(addr, io_timeout, &link_key) {
                Ok(conn) => {
                    let mut rs = Self {
                        addr: addr.to_string(),
                        link_key: Zeroizing::new(link_key),
                        conn: Mutex::new(Some(conn)),
                        public_key: crypto::PublicKey([0u8; 48]),
                        io_timeout,
                    };
                    rs.public_key = rs.request_pubkey()?;
                    return Ok(rs);
                }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| SignerError::Unavailable(format!("cannot reach signer at {addr}"))))
    }

    /// TCP connect + authentication handshake. Returns the live
    /// session; a refused hello (wrong key, pre-auth garbage) is a
    /// connect failure — retrying cannot fix a bad credential.
    fn dial(addr: &str, io_timeout: Duration, link_key: &[u8; 32]) -> Result<Conn, SignerError> {
        let sock: std::net::SocketAddr = addr.parse().map_err(|e| {
            SignerError::Unavailable(format!("invalid signer address {addr:?}: {e}"))
        })?;
        let mut stream = TcpStream::connect_timeout(&sock, io_timeout)
            .map_err(|e| SignerError::Unavailable(format!("cannot reach signer at {addr}: {e}")))?;
        stream
            .set_read_timeout(Some(io_timeout))
            .map_err(|e| SignerError::Unavailable(format!("cannot set read timeout: {e}")))?;
        stream
            .set_write_timeout(Some(io_timeout))
            .map_err(|e| SignerError::Unavailable(format!("cannot set write timeout: {e}")))?;
        let sess = Self::handshake(&mut stream, link_key)?;
        Ok(Conn { stream, sess, seq: 0 })
    }

    /// Prove the link key to the daemon and verify the daemon's
    /// counter-proof. The hello is the first bytes on the wire —
    /// `client ‖ nonce` proves possession without revealing the
    /// key, and the daemon's proof binds both nonces so a replayed
    /// `AuthOk` can never authenticate a different session.
    fn handshake(stream: &mut TcpStream, link_key: &[u8; 32]) -> Result<Session, SignerError> {
        let client_nonce = crypto::random_nonce();
        let client_proof = mac(link_key, b"client", &[&client_nonce]);
        let mut hello = Vec::with_capacity(65);
        hello.push(TAG_AUTH_HELLO);
        hello.extend_from_slice(&client_nonce);
        hello.extend_from_slice(&client_proof);
        stream
            .write_all(&hello)
            .map_err(|e| SignerError::Unavailable(format!("signer handshake write: {e}")))?;
        let mut hdr = [0u8; 5];
        stream
            .read_exact(&mut hdr)
            .map_err(|e| SignerError::Unavailable(format!("signer handshake read: {e}")))?;
        let len = u32::from_le_bytes(hdr[1..5].try_into().expect("4")) as usize;
        if len > MAX_RESPONSE_BYTES as usize {
            return Err(SignerError::Unavailable("signer handshake response exceeds bound".into()));
        }
        let mut payload = vec![0u8; len];
        stream
            .read_exact(&mut payload)
            .map_err(|e| SignerError::Unavailable(format!("signer handshake read: {e}")))?;
        if hdr[0] != STATUS_AUTH_OK || payload.len() != 64 {
            return Err(SignerError::Unavailable(format!(
                "signer refused authentication: {}",
                String::from_utf8_lossy(&payload)
            )));
        }
        let daemon_nonce: &[u8; 32] = payload[..32].try_into().expect("32-byte nonce");
        let daemon_proof: &[u8; 32] = payload[32..64].try_into().expect("32-byte proof");
        let expected = mac(link_key, b"daemon", &[&client_nonce, daemon_nonce]);
        if !ct_eq32(daemon_proof, &expected) {
            return Err(SignerError::Unavailable(
                "signer failed mutual authentication (wrong link key?)".to_string(),
            ));
        }
        Ok(Session::derive(link_key, &client_nonce, daemon_nonce))
    }

    /// One MAC'd request; reconnects (re-handshakes) and retries
    /// once when the connection died — the daemon's fence makes the
    /// retry idempotent. Returns `[status, payload..]` for the
    /// caller's status dispatch.
    fn request(&self, body: &[u8]) -> Result<Vec<u8>, SignerError> {
        for attempt in 0..2 {
            let mut guard = self
                .conn
                .lock()
                .map_err(|_| SignerError::Unavailable("signer connection lock poisoned".into()))?;
            if guard.is_none() {
                *guard = Some(Self::dial(&self.addr, self.io_timeout, &self.link_key)?);
            }
            let conn = guard.as_mut().expect("dial fills the slot");
            let result = Self::roundtrip(conn, body);
            match result {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    // The connection is presumed dead — drop it so
                    // the next attempt redials (and re-handshakes).
                    // On the second attempt the error is final.
                    *guard = None;
                    if attempt == 1 {
                        return Err(SignerError::Unavailable(format!(
                            "signer at {} failed after reconnect: {e}",
                            self.addr
                        )));
                    }
                }
            }
        }
        unreachable!("the loop returns on attempt 1")
    }

    /// Write `mac ‖ len ‖ body`, read `mac ‖ status ‖ len ‖
    /// payload`, verify the response MAC at the same `seq` — any
    /// MITM-tampered byte fails verification and the caller drops
    /// the connection as dead.
    fn roundtrip(conn: &mut Conn, body: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut frame = Vec::with_capacity(32 + 4 + body.len());
        frame.extend_from_slice(&conn.sess.request_mac(conn.seq, body));
        frame.extend_from_slice(&body_len(body));
        frame.extend_from_slice(body);
        conn.stream.write_all(&frame)?;
        let mut hdr = [0u8; 32 + 5];
        conn.stream.read_exact(&mut hdr)?;
        let status = hdr[32];
        let len = u32::from_le_bytes(hdr[33..37].try_into().expect("4")) as usize;
        if len > MAX_RESPONSE_BYTES as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "signer response exceeds bound",
            ));
        }
        let mut payload = vec![0u8; len];
        conn.stream.read_exact(&mut payload)?;
        let expected = conn.sess.response_mac(conn.seq, status, &payload);
        if !ct_eq32(hdr[..32].try_into().expect("32"), &expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "signer response failed MAC verification",
            ));
        }
        conn.seq += 1;
        let mut resp = Vec::with_capacity(1 + payload.len());
        resp.push(status);
        resp.extend_from_slice(&payload);
        Ok(resp)
    }

    fn request_pubkey(&self) -> Result<crypto::PublicKey, SignerError> {
        let resp = self.request(&[TAG_PUBKEY_REQUEST])?;
        if resp[0] != STATUS_PUBKEY || resp.len() != 1 + 48 {
            return Err(SignerError::Unavailable(format!(
                "unexpected pubkey response (status {}, {} bytes)",
                resp[0],
                resp.len() - 1
            )));
        }
        crypto::PublicKey::from_slice(&resp[1..])
            .map_err(|_| SignerError::Unavailable("signer returned a malformed public key".into()))
    }
}

impl ConsensusSigner for RemoteSigner {
    fn public_key(&self) -> crypto::PublicKey {
        self.public_key
    }

    fn sign(&self, domain: Domain, msg: &[u8], ctx: SignContext) -> Result<Signature, SignerError> {
        let msg_len = u32::try_from(msg.len()).map_err(|_| {
            SignerError::Unavailable("signable exceeds the u32 length prefix".into())
        })?;
        let mut frame = Vec::with_capacity(22 + msg.len());
        frame.push(TAG_SIGN_REQUEST);
        frame.push(domain as u8);
        frame.extend_from_slice(&ctx.epoch.to_le_bytes());
        frame.extend_from_slice(&ctx.mark.to_le_bytes());
        frame.push(ctx.phase);
        frame.extend_from_slice(&msg_len.to_le_bytes());
        frame.extend_from_slice(msg);
        let resp = self.request(&frame)?;
        let (status, payload) = (resp[0], &resp[1..]);
        match status {
            STATUS_SIGNED => Signature::from_slice(payload).map_err(|_| {
                SignerError::Unavailable("signer returned a malformed signature".into())
            }),
            STATUS_REFUSED => Err(SignerError::Unavailable(format!(
                "signer fence refused: {}",
                String::from_utf8_lossy(payload)
            ))),
            _ => Err(SignerError::Unavailable(format!(
                "signer error: {}",
                String::from_utf8_lossy(payload)
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> BlsSecretKey {
        BlsSecretKey::from_ikm(&[7u8; 32]).expect("key")
    }

    fn ctx(epoch: u64, mark: u64) -> SignContext {
        SignContext { epoch, mark, phase: 0 }
    }

    fn hash(msg: &[u8]) -> [u8; 32] {
        crypto::Hasher::hash_one(Domain::Block, msg)
            .as_bytes()
            .try_into()
            .expect("BLAKE3 output is 32 bytes")
    }

    #[test]
    fn fence_allows_progress_and_identical_resign() {
        let dir = std::env::temp_dir().join(format!("oxsg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("fence.state");
        let mut state = FenceState { path: path.clone(), records: BTreeMap::new() };
        // First request at a coordinate: allowed, recorded.
        state.check(Domain::Vote, ctx(0, 5), &hash(b"a")).expect("first sign");
        state.record(Domain::Vote, ctx(0, 5), hash(b"a")).expect("record");
        // Identical re-sign: allowed (retry-safe).
        state.check(Domain::Vote, ctx(0, 5), &hash(b"a")).expect("idempotent");
        // Forward progress: allowed.
        state.check(Domain::Vote, ctx(0, 6), &hash(b"b")).expect("progress");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fence_refuses_conflict_and_regression() {
        let dir = std::env::temp_dir().join(format!("oxsg2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("fence.state");
        let mut state = FenceState { path: path.clone(), records: BTreeMap::new() };
        state.check(Domain::Vote, ctx(0, 5), &hash(b"a")).expect("ok");
        state.record(Domain::Vote, ctx(0, 5), hash(b"a")).expect("record");
        // Same coordinate, different message: equivocation refused.
        assert!(state.check(Domain::Vote, ctx(0, 5), &hash(b"b")).is_err());
        // Regression: refused.
        assert!(state.check(Domain::Vote, ctx(0, 4), &hash(b"c")).is_err());
        // A different domain at the same coordinate is independent.
        state.check(Domain::Timeout, ctx(0, 5), &hash(b"b")).expect("other domain");
        // Phase distinguishes sub-steps at one mark.
        state.check(Domain::Vote, ctx(0, 5), &hash(b"a")).expect("same");
        let mut p1 = ctx(0, 5);
        p1.phase = 1;
        state.check(Domain::Vote, p1, &hash(b"phase1")).expect("next phase");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fence_persists_across_reopen() {
        let dir = std::env::temp_dir().join(format!("oxsg3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("fence.state");
        let mut state = FenceState { path: path.clone(), records: BTreeMap::new() };
        state.record(Domain::Vote, ctx(3, 9), hash(b"x")).expect("persist");
        drop(state);
        let state = FenceState::load(&path).expect("reload");
        // After reload the record is still authoritative.
        assert!(state.check(Domain::Vote, ctx(3, 9), &hash(b"y")).is_err());
        state.check(Domain::Vote, ctx(3, 10), &hash(b"z")).expect("forward");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Spin up a daemon on an ephemeral loopback port and return
    /// its address. The serve flag never flips in tests — the
    /// thread dies with the test process.
    fn spawn_daemon(link_key: [u8; 32], state_path: PathBuf) -> String {
        let daemon = Arc::new(SignerDaemon::new(key(), state_path, link_key).expect("daemon"));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let _daemon_thread = std::thread::spawn(move || {
            let flag = AtomicBool::new(false);
            daemon.serve(listener, &flag);
        });
        addr
    }

    #[test]
    fn remote_signer_roundtrip_over_tcp() {
        let dir = std::env::temp_dir().join(format!("oxsg4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let link_key = [9u8; 32];
        let addr = spawn_daemon(link_key, dir.join("s.state"));
        let signer =
            RemoteSigner::connect(&addr, Duration::from_secs(5), link_key).expect("connect");
        assert_eq!(signer.public_key(), key().public_key());
        let sig = signer.sign(Domain::Vote, b"vote-bytes", ctx(0, 1)).expect("remote sign");
        assert!(
            crypto::verify(&sig, Domain::Vote, b"vote-bytes", &key().public_key()).is_ok(),
            "the remote signature verifies under the daemon's key"
        );
        // A conflicting request at the same coordinate is refused.
        let err = signer.sign(Domain::Vote, b"other-bytes", ctx(0, 1));
        assert!(err.is_err(), "equivocation must be refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_link_key_is_refused_at_handshake() {
        let dir = std::env::temp_dir().join(format!("oxsg5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let addr = spawn_daemon([1u8; 32], dir.join("s.state"));
        // A client holding a different link key must fail the
        // handshake — it can never reach the fence or the key.
        let err = RemoteSigner::connect(&addr, Duration::from_secs(5), [2u8; 32]);
        assert!(err.is_err(), "a wrong link key must not authenticate");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pre_auth_garbage_is_rejected() {
        let dir = std::env::temp_dir().join(format!("oxsg6-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let addr = spawn_daemon([1u8; 32], dir.join("s.state"));
        // A raw SignRequest with no handshake — the daemon must
        // answer an error frame and close, never reaching the fence.
        let mut stream = TcpStream::connect(&addr).expect("connect");
        // A full 65-byte "hello" whose tag is not AuthHello — the
        // daemon reads the fixed-size hello first, so a non-auth
        // tag is what must trigger the refusal.
        stream.write_all(&[TAG_SIGN_REQUEST; 65]).expect("write garbage");
        let mut hdr = [0u8; 5];
        stream.read_exact(&mut hdr).expect("error frame");
        assert_eq!(hdr[0], STATUS_ERROR, "pre-auth frames get an Error + close");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forged_frame_mac_drops_the_connection() {
        let dir = std::env::temp_dir().join(format!("oxsg7-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let link_key = [3u8; 32];
        let addr = spawn_daemon(link_key, dir.join("s.state"));
        let signer =
            RemoteSigner::connect(&addr, Duration::from_secs(5), link_key).expect("connect");
        // Hand-craft a frame with a MAC over the wrong key: the
        // daemon must drop the connection rather than answer.
        let mut conn = RemoteSigner::dial(&addr, Duration::from_secs(5), &link_key).expect("dial");
        let body = [TAG_PUBKEY_REQUEST];
        let bad_mac = mac(&[0xFFu8; 32], b"", &[&0u64.to_le_bytes(), &body_len(&body), &body]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&bad_mac);
        frame.extend_from_slice(&body_len(&body));
        frame.extend_from_slice(&body);
        conn.stream.write_all(&frame).expect("write forged frame");
        conn.stream.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
        let mut byte = [0u8; 1];
        // The forged MAC must drop the connection — the daemon
        // never sends a response, so the read hits EOF or timeout.
        assert!(
            conn.stream.read_exact(&mut byte).is_err(),
            "a forged MAC must end the session, not get an answer"
        );
        // And the honest session still works — the daemon dropped
        // only the forged connection.
        let sig = signer.sign(Domain::Vote, b"ok", ctx(0, 1));
        assert!(sig.is_ok(), "the honest session must survive a forged peer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_connections_share_the_fence() {
        let dir = std::env::temp_dir().join(format!("oxsg8-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let link_key = [5u8; 32];
        let addr = spawn_daemon(link_key, dir.join("s.state"));
        // Two simultaneous clients — the failover-pair topology.
        // Both must be served concurrently (thread-per-connection)
        // and the fence must still refuse a conflicting pair.
        let a = RemoteSigner::connect(&addr, Duration::from_secs(5), link_key).expect("client a");
        let b = RemoteSigner::connect(&addr, Duration::from_secs(5), link_key).expect("client b");
        a.sign(Domain::Vote, b"msg", ctx(0, 7)).expect("a signs");
        // Same coordinate, different message via the OTHER
        // connection: the fence refuses across sessions.
        let err = b.sign(Domain::Vote, b"different", ctx(0, 7));
        assert!(err.is_err(), "the fence must arbitrate across connections");
        // Identical re-sign through b is the safe idempotent case.
        b.sign(Domain::Vote, b"msg", ctx(0, 7)).expect("idempotent re-sign");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
