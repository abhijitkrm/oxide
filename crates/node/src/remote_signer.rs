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
//! One request/response per frame over TCP. All integers
//! little-endian.
//!
//! ```text
//! request  := tag:u8 | payload
//!   tag 1 (SignRequest):   domain:u8 | epoch:u64 | mark:u64 |
//!                          phase:u8 | msg_len:u32 | msg
//!   tag 2 (PubKeyRequest): (empty)
//! response := status:u8 | payload_len:u32 | payload
//!   status 0 (Signed):   payload = 96-byte BLS signature
//!   status 1 (Refused):  payload = utf8 reason (fence rejection —
//!                        the coordinate regressed or conflicts)
//!   status 2 (PubKey):   payload = 48-byte public key
//!   status 3 (Error):    payload = utf8 diagnostic
//! ```
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
//! secret never crosses it, so the transport need not hide
//! payloads; it must prevent a third party from *issuing* requests
//! (a MITM can burn the fence and stall the validator). Run the
//! daemon on loopback or a private interface; there is deliberately
//! no TLS here — the privval convention is a physically trusted
//! link, and an untrusted link needs a deployment decision (mTLS,
//! `WireGuard`) the daemon should not bake in silently.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crypto::hash::Domain;
use crypto::{BlsSecretKey, ConsensusSigner, SignContext, Signature, SignerError};

/// Protocol tag: a signing request (`SignRequest`).
const TAG_SIGN_REQUEST: u8 = 1;
/// Protocol tag: a public-key request (`PubKeyRequest`).
const TAG_PUBKEY_REQUEST: u8 = 2;

/// Response status: request signed; payload is the 96-byte sig.
const STATUS_SIGNED: u8 = 0;
/// Response status: the fence refused the request; payload is a
/// utf8 reason. A refusal is a *safety* answer — the daemon is
/// healthy, it is declining to equivocate.
const STATUS_REFUSED: u8 = 1;
/// Response status: public-key answer; payload is the 48-byte key.
const STATUS_PUBKEY: u8 = 2;
/// Response status: daemon-side failure; payload is a utf8
/// diagnostic (malformed request, persist failure).
const STATUS_ERROR: u8 = 3;

/// Upper bound on a request's `msg` field: the largest legitimate
/// signable is the 57-byte timeout message — anything bigger is a
/// malformed/hostile frame, and the bound keeps a garbage length
/// from driving a daemon-side allocation. Origin: wire format
/// `types::` messages; tradeoff: a future domain whose signable
/// exceeds this must raise the constant in lockstep on both sides.
const MAX_MSG_BYTES: u32 = 4096;
/// Upper bound on a response payload (error strings are the only
/// variable-size payload; 4 KiB is far past any diagnostic).
const MAX_RESPONSE_BYTES: u32 = 4096;

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

/// The daemon: holds the secret key and the durable fence, serves
/// signing requests over a TCP listener.
///
/// One `SignerDaemon` is one consensus identity — a failover pair of
/// validators points at the same daemon and the fence is what makes
/// their signatures non-equivocating.
pub struct SignerDaemon {
    key: BlsSecretKey,
    state: Mutex<FenceState>,
}

impl SignerDaemon {
    /// Load the secret key and the fence file. The key comes in
    /// already decoded — the binary owns keystore/hex parsing; the
    /// daemon owns only what it needs to sign.
    ///
    /// # Errors
    /// [`SignerError::Unavailable`] when the fence file exists but is
    /// unreadable or corrupt — signing without a trustworthy
    /// high-watermark could equivocate.
    pub fn new(key: BlsSecretKey, state_path: PathBuf) -> Result<Self, SignerError> {
        Ok(Self { key, state: Mutex::new(FenceState::load(&state_path)?) })
    }

    /// The daemon's public key — what `PubKeyRequest` answers.
    #[must_use]
    pub fn public_key(&self) -> crypto::PublicKey {
        self.key.public_key()
    }

    /// Serve requests until `shutdown` is set. Accepts serially;
    /// every request is handled under the fence mutex, so
    /// concurrent connections cannot interleave a check/record
    /// pair — the fence is only correct if check→persist→sign is
    /// atomic.
    ///
    /// # Panics
    /// Panics if `listener.accept()` fails — a daemon that cannot
    /// accept is not a degraded signer, it is a dead one.
    pub fn serve(&self, listener: TcpListener, shutdown: &AtomicBool) {
        // The accept loop must observe the flag, so put the socket
        // in nonblocking mode and poll — a blocking accept would
        // outlive the shutdown request until a peer connects.
        listener.set_nonblocking(true).expect("nonblocking listener");
        while !shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => self.serve_conn(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("signer daemon accept failed: {e}"),
            }
        }
    }

    /// Handle one connection until the peer hangs up or a frame
    /// fails to parse.
    fn serve_conn(&self, mut stream: TcpStream) {
        loop {
            let mut tag = [0u8; 1];
            if stream.read_exact(&mut tag).is_err() {
                return;
            }
            match tag[0] {
                TAG_PUBKEY_REQUEST => {
                    let pk = self.key.public_key();
                    if write_response(&mut stream, STATUS_PUBKEY, pk.as_bytes()).is_err() {
                        return;
                    }
                }
                TAG_SIGN_REQUEST => {
                    let Some(resp) = self.handle_sign_request(&mut stream) else { return };
                    if stream.write_all(&resp).is_err() {
                        return;
                    }
                }
                _ => {
                    // Unknown tag — answer Error so a mismatched
                    // client learns it rather than hanging.
                    let _ = write_response(&mut stream, STATUS_ERROR, b"unknown request tag");
                }
            }
        }
    }

    /// Read one `SignRequest` body, fence it, sign it, and return
    /// the encoded response frame. `None` means the connection's
    /// frame was malformed mid-read — drop the connection.
    fn handle_sign_request(&self, stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut hdr = [0u8; 1 + 8 + 8 + 1 + 4];
        stream.read_exact(&mut hdr).ok()?;
        let domain = domain_from_u8(hdr[0])?;
        let epoch = u64::from_le_bytes(hdr[1..9].try_into().expect("8"));
        let mark = u64::from_le_bytes(hdr[9..17].try_into().expect("8"));
        let phase = hdr[17];
        let msg_len = u32::from_le_bytes(hdr[18..22].try_into().expect("4"));
        if msg_len > MAX_MSG_BYTES {
            return encode_response(STATUS_ERROR, b"message exceeds bound").ok();
        }
        let mut msg = vec![0u8; msg_len as usize];
        stream.read_exact(&mut msg).ok()?;
        let ctx = SignContext { epoch, mark, phase };
        let msg_hash: [u8; 32] = crypto::Hasher::hash_one(Domain::Block, &msg)
            .as_bytes()
            .try_into()
            .expect("BLAKE3 output is 32 bytes");
        self.sign_fenced(domain, &msg, ctx, msg_hash)
    }

    /// Fence → persist → sign → respond. The whole sequence runs
    /// under the state mutex so a second connection cannot slip a
    /// request between another's check and record. `None` drops the
    /// connection — the only encode failure is an impossible
    /// payload size, and refusing is safer than framing a lie.
    fn sign_fenced(
        &self,
        domain: Domain,
        msg: &[u8],
        ctx: SignContext,
        msg_hash: [u8; 32],
    ) -> Option<Vec<u8>> {
        let mut state = self.state.lock().expect("fence mutex");
        if let Err(reason) = state.check(domain, ctx, &msg_hash) {
            return encode_response(STATUS_REFUSED, reason.as_bytes()).ok();
        }
        // Persist BEFORE the signature exists — a crash between
        // "signed" and "fenced" would let a restarted daemon sign a
        // conflicting message at the same coordinate.
        if let Err(e) = state.record(domain, ctx, msg_hash) {
            return encode_response(STATUS_ERROR, e.to_string().as_bytes()).ok();
        }
        let sig = self.key.sign(domain, msg);
        encode_response(STATUS_SIGNED, sig.as_bytes()).ok()
    }
}

/// Map a wire byte to a [`Domain`] — the enum is `repr(u8)` with
/// stable discriminants; unknown bytes fail closed (`None` drops
/// the connection).
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

/// Frame-encode a response: `[status][len:u32][payload]`.
fn encode_response(status: u8, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "response payload exceeds u32")
    })?;
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(status);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Write one response frame; `Err` means the connection is dead.
fn write_response(stream: &mut TcpStream, status: u8, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(&encode_response(status, payload)?)
}

/// The client half: a `ConsensusSigner` backed by a [`SignerDaemon`]
/// over TCP. The validator binary installs it as the engine's
/// signer — and as the handshake auth's signer — so the consensus
/// secret never exists in the validator process at all.
///
/// The connection is persistent and reconnect-once on failure: a
/// dropped socket mid-request is retried once, which the daemon's
/// idempotent fence makes sound (same coordinate + same message is
/// always re-signable).
pub struct RemoteSigner {
    addr: String,
    conn: Mutex<Option<TcpStream>>,
    public_key: crypto::PublicKey,
    io_timeout: Duration,
}

impl RemoteSigner {
    /// Connect to the daemon at `addr` and fetch its public key.
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
    /// reached or does not answer the public-key handshake.
    pub fn connect(addr: &str, io_timeout: Duration) -> Result<Self, SignerError> {
        let mut last_err = None;
        for _ in 0..50 {
            match Self::dial(addr, io_timeout) {
                Ok(stream) => {
                    let mut rs = Self {
                        addr: addr.to_string(),
                        conn: Mutex::new(Some(stream)),
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

    fn dial(addr: &str, io_timeout: Duration) -> Result<TcpStream, SignerError> {
        let sock: std::net::SocketAddr = addr.parse().map_err(|e| {
            SignerError::Unavailable(format!("invalid signer address {addr:?}: {e}"))
        })?;
        let stream = TcpStream::connect_timeout(&sock, io_timeout)
            .map_err(|e| SignerError::Unavailable(format!("cannot reach signer at {addr}: {e}")))?;
        stream
            .set_read_timeout(Some(io_timeout))
            .map_err(|e| SignerError::Unavailable(format!("cannot set read timeout: {e}")))?;
        stream
            .set_write_timeout(Some(io_timeout))
            .map_err(|e| SignerError::Unavailable(format!("cannot set write timeout: {e}")))?;
        Ok(stream)
    }

    /// One framed request; reconnects and retries once when the
    /// connection died (the daemon's fence makes the retry
    /// idempotent).
    fn request(&self, frame: &[u8]) -> Result<Vec<u8>, SignerError> {
        for attempt in 0..2 {
            let mut guard = self
                .conn
                .lock()
                .map_err(|_| SignerError::Unavailable("signer connection lock poisoned".into()))?;
            if guard.is_none() {
                *guard = Some(Self::dial(&self.addr, self.io_timeout)?);
            }
            let stream = guard.as_mut().expect("dial fills the slot");
            let result = stream.write_all(frame).and_then(|()| {
                let mut hdr = [0u8; 5];
                stream.read_exact(&mut hdr)?;
                let len = u32::from_le_bytes(hdr[1..5].try_into().expect("4"));
                if len > MAX_RESPONSE_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "signer response exceeds bound",
                    ));
                }
                let mut payload = vec![0u8; len as usize];
                stream.read_exact(&mut payload)?;
                Ok((hdr[0], payload))
            });
            match result {
                Ok((status, payload)) => return Ok([vec![status], payload].concat()),
                Err(e) => {
                    // The connection is presumed dead — drop it so
                    // the next attempt redials. On the second
                    // attempt the error is final.
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

    #[test]
    fn remote_signer_roundtrip_over_tcp() {
        let dir = std::env::temp_dir().join(format!("oxsg4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let daemon = SignerDaemon::new(key(), dir.join("s.state")).expect("daemon");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        // The serve loop runs forever on its thread (the flag never
        // flips in the test); the thread dies with the test process.
        let _daemon_thread = std::thread::spawn(move || {
            let flag = AtomicBool::new(false);
            daemon.serve(listener, &flag);
        });
        let signer = RemoteSigner::connect(&addr, Duration::from_secs(5)).expect("connect");
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
}
