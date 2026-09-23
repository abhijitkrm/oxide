//! Oxide statesync — bootstrap a node from a snapshot instead of
//! replaying the journal from genesis.
//!
//! A fresh fullnode can't catch up to a long-lived chain by replay:
//! history is unbounded and the sender already paid the execution
//! cost. State sync downloads a recent executor snapshot instead:
//!
//! 1. `GET /snapshot/manifest` — a small [`Manifest`] describing the
//!    snapshot: chain height, claimed state root, chunk size, and a
//!    BLAKE3 hash per fixed-size chunk.
//! 2. `GET /snapshot/cert/{height}` — the quorum-signed
//!    [`types::ExecCertificate`] attesting the manifest's
//!    `(height, state_root)`. The client verifies it against its
//!    own validator-set checkpoint (weak subjectivity): a
//!    stake-supermajority signature the serving peer cannot forge.
//!    This certificate — not an operator-typed root — is the trust
//!    anchor; the operator pin remains as an optional extra check.
//! 3. `GET /snapshot/chunk/{i}` — each chunk of the codec-encoded
//!    [`executor::ExecutorSnapshot`] blob, hex-encoded. The client
//!    verifies `H(StateSyncChunk ‖ chunk)` against
//!    `manifest.chunk_hashes[i]` before accepting it — a tampered or
//!    torn chunk is rejected byte-for-byte, not discovered as a bad
//!    root after import.
//! 4. Assemble, decode, `import_snapshot`, then verify the imported
//!    state root equals the certified root — fail closed otherwise.
//!
//! The client is deliberately `std`-only (blocking `TcpStream`):
//! bootstrap runs once at startup before the async runtime is
//! needed, and the crate stays dependency-free enough for any
//! binary to link.

use primitives::Hash;

/// Wire chunk size: 4 MiB.
///
/// Unit: bytes. Origin: tuned for LAN/west-coast-datacenter syncs —
/// large enough that per-request overhead is noise (<0.1% for a
/// 1 GiB snapshot ≈ 256 requests), small enough that a single
/// corrupted chunk re-fetch is cheap and a `/snapshot/chunk`
/// handler never has to build a giant response. Tradeoff: halving
/// it doubles request count; doubling it quadruples the worst-case
/// single-chunk re-download.
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Description of one snapshot instance, served by
/// `GET /snapshot/manifest` as codec-encoded hex.
///
/// The manifest is what the operator cross-checks (`height` +
/// `state_root` from a trusted source); everything else follows
/// from it deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Finalized height the snapshot was exported at.
    pub height: u64,
    /// The snapshot's claimed aggregate state root — the value the
    /// operator must already trust (from a block header, an
    /// explorer, or their own node) before accepting the download.
    pub state_root: Hash,
    /// `ExecutorSnapshot` format version (`SNAPSHOT_FORMAT_VERSION`)
    /// — lets a client refuse a snapshot its importer can't read
    /// before downloading a byte.
    pub format_version: u32,
    /// Fixed chunk size in bytes (the final chunk may be shorter).
    pub chunk_size: u32,
    /// Total encoded blob length in bytes.
    pub total_len: u64,
    /// `H(StateSyncChunk ‖ chunk_i)` for each chunk, in order.
    /// `chunk_count` is implied by `chunk_hashes.len()`.
    pub chunk_hashes: Vec<Hash>,
}

impl Manifest {
    /// Number of chunks needed to cover `total_len`.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunk_hashes.len()
    }
}

impl codec::Encode for Manifest {
    fn encode(&self, buf: &mut Vec<u8>) {
        codec::write::u64(buf, self.height);
        self.state_root.encode(buf);
        codec::write::u32(buf, self.format_version);
        codec::write::u32(buf, self.chunk_size);
        codec::write::u64(buf, self.total_len);
        codec::write::u32(buf, u32::try_from(self.chunk_hashes.len()).unwrap_or(u32::MAX));
        for h in &self.chunk_hashes {
            h.encode(buf);
        }
    }
}

impl<'a> codec::Decode<'a> for Manifest {
    fn decode(reader: &mut codec::Reader<'a>) -> Result<Self, codec::DecodeError> {
        let height = reader.read_u64()?;
        let state_root = Hash::decode(reader)?;
        let format_version = reader.read_u32()?;
        let chunk_size = reader.read_u32()?;
        let total_len = reader.read_u64()?;
        let count = reader.read_u32()? as usize;
        // Bound the allocation: a hostile manifest could claim a
        // huge count and OOM the reader. `ceil(total_len /
        // chunk_size)` is the only legal count — validate before
        // reserving. A chunk_size of 0 would divide-by-zero.
        if chunk_size == 0 {
            return Err(codec::DecodeError::InvalidVarint);
        }
        let expected = total_len.div_ceil(u64::from(chunk_size));
        if u64::try_from(count).unwrap_or(u64::MAX) != expected {
            return Err(codec::DecodeError::LengthPrefixTooLarge {
                claimed: u64::try_from(count).unwrap_or(u64::MAX),
                remaining: expected,
            });
        }
        // The self-consistency check above bounds `count` only by
        // the *claimed* `total_len` — a manifest can legally claim
        // u32::MAX chunks (~137 GiB of hashes) in a tiny message.
        // Every hash occupies exactly 32 bytes on the wire, so a
        // count exceeding `remaining / 32` is definitively malformed;
        // reject before the reserve trusts the claim.
        let max_count = reader.remaining() / Hash::LEN;
        if count > max_count {
            return Err(codec::DecodeError::LengthPrefixTooLarge {
                claimed: u64::try_from(count).unwrap_or(u64::MAX),
                remaining: u64::try_from(max_count).unwrap_or(u64::MAX),
            });
        }
        let mut chunk_hashes = Vec::with_capacity(count);
        for _ in 0..count {
            chunk_hashes.push(Hash::decode(reader)?);
        }
        Ok(Self { height, state_root, format_version, chunk_size, total_len, chunk_hashes })
    }
}

/// Errors a state sync can hit — each variant maps to one step of
/// the protocol so the operator sees *where* trust broke down.
#[derive(Debug)]
pub enum SyncError {
    /// The HTTP fetch failed (connect, status, or framing).
    Transport(String),
    /// A manifest or chunk body did not decode.
    Decode(String),
    /// `chunk_hashes[i]` did not match the served chunk — the peer
    /// is serving torn or tampered data.
    ChunkHashMismatch { index: usize },
    /// The reassembled blob's length differs from the manifest's
    /// `total_len` (impossible if all chunks verified — indicates
    /// a manifest/blob disagreement on the server side).
    LengthMismatch { expected: u64, actual: u64 },
    /// The manifest's height or root does not match the operator's
    /// trusted values — abort before downloading.
    Untrusted,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::ChunkHashMismatch { index } => write!(f, "chunk {index} hash mismatch"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "blob length {actual} != manifest total_len {expected}")
            }
            Self::Untrusted => write!(f, "manifest does not match trusted height/root"),
        }
    }
}

impl std::error::Error for SyncError {}

/// Split an encoded snapshot blob into `chunk_size` pieces and
/// build its manifest. Deterministic: the same blob + size yields
/// the same chunk boundaries and hashes on every node.
#[must_use]
pub fn chunk_blob(
    height: u64,
    state_root: Hash,
    format_version: u32,
    blob: &[u8],
    chunk_size: usize,
) -> (Manifest, Vec<Vec<u8>>) {
    let chunk_size = chunk_size.max(1);
    let chunks: Vec<Vec<u8>> = blob.chunks(chunk_size).map(<[u8]>::to_vec).collect();
    let chunk_hashes = chunks
        .iter()
        .map(|c| crypto::hash::Hasher::hash_one(crypto::hash::Domain::StateSyncChunk, c))
        .collect();
    let manifest = Manifest {
        height,
        state_root,
        format_version,
        chunk_size: u32::try_from(chunk_size).unwrap_or(u32::MAX),
        total_len: blob.len() as u64,
        chunk_hashes,
    };
    (manifest, chunks)
}

/// Check `H(StateSyncChunk ‖ chunk)` against the manifest. A
/// mismatch means the peer served different bytes than the manifest
/// describes — never assemble around it.
#[must_use]
pub fn verify_chunk(manifest: &Manifest, index: usize, chunk: &[u8]) -> bool {
    manifest.chunk_hashes.get(index).is_some_and(|expected| {
        *expected == crypto::hash::Hasher::hash_one(crypto::hash::Domain::StateSyncChunk, chunk)
    })
}

/// Concatenate verified chunks into the original blob. Callers
/// must run [`verify_chunk`] on every chunk first — this function
/// checks only the final length as a belt-and-suspenders guard.
///
/// # Errors
///
/// [`SyncError::LengthMismatch`] if the assembled length differs
/// from `manifest.total_len`.
pub fn assemble(manifest: &Manifest, chunks: &[Vec<u8>]) -> Result<Vec<u8>, SyncError> {
    let mut blob = Vec::with_capacity(manifest.total_len as usize);
    for c in chunks {
        blob.extend_from_slice(c);
    }
    if blob.len() as u64 != manifest.total_len {
        return Err(SyncError::LengthMismatch {
            expected: manifest.total_len,
            actual: blob.len() as u64,
        });
    }
    Ok(blob)
}

/// Verify a manifest against the operator's trusted anchor: the
/// (height, state_root) pair obtained from a trusted source —
/// a finalized block header the node already holds, an explorer,
/// or out-of-band ops channel. This is the *only* trust decision
/// in the protocol: a peer can lie about everything else, but if
/// these two values match what the operator already trusts and
/// the post-import root recomputes to the same value, the state
/// is correct regardless.
///
/// # Errors
///
/// [`SyncError::Untrusted`] on any mismatch.
pub fn check_trusted(
    manifest: &Manifest,
    trusted_height: u64,
    trusted_root: &Hash,
) -> Result<(), SyncError> {
    if manifest.height != trusted_height || &manifest.state_root != trusted_root {
        return Err(SyncError::Untrusted);
    }
    Ok(())
}

/// One blocking HTTP GET for a hex body. Returns the decoded
/// bytes. Only `200` responses with a `0x` hex body are accepted —
/// the endpoints this client talks to (`/snapshot/manifest`,
/// `/snapshot/chunk/{i}`) always answer that shape.
///
/// `std`-only by design: bootstrap is a startup-time, sequential
/// download — no async runtime needed.
///
/// # Errors
///
/// [`SyncError::Transport`] on connect/IO/non-200,
/// [`SyncError::Decode`] on malformed hex.
pub fn fetch_hex(addr: &str, path: &str) -> Result<Vec<u8>, SyncError> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let mut stream = TcpStream::connect(addr)
        .map_err(|e| SyncError::Transport(format!("connect {addr}: {e}")))?;
    // A bootstrap peer that stalls mid-body shouldn't hang the node
    // forever — 30s per request is generous for LAN/wan syncs and
    // bounds the worst case.
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| SyncError::Transport(format!("set_read_timeout: {e}")))?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: {addr}\r\n\r\n")
        .map_err(|e| SyncError::Transport(format!("write: {e}")))?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| SyncError::Transport(format!("read: {e}")))?;

    // Split headers/body at the first CRLFCRLF; the status line is
    // the first line of the head.
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| SyncError::Transport("no header/body separator".to_string()))?;
    let head = std::str::from_utf8(&raw[..sep])
        .map_err(|_| SyncError::Transport("non-utf8 headers".to_string()))?;
    let status_ok = head.lines().next().is_some_and(|line| line.contains(" 200"));
    if !status_ok {
        return Err(SyncError::Transport(format!(
            "non-200: {}",
            head.lines().next().unwrap_or("")
        )));
    }
    let body = std::str::from_utf8(&raw[sep + 4..])
        .map_err(|_| SyncError::Decode("non-utf8 body".to_string()))?;
    hex_decode(body.trim()).map_err(|e| SyncError::Decode(format!("hex: {e}")))
}

/// Fetch `GET /snapshot/manifest` — the first step of every sync.
/// The returned manifest pins the snapshot height, claimed state
/// root, and per-chunk hashes; the caller decides how to anchor it
/// (operator pin, quorum-signed certificate) before downloading.
///
/// # Errors
///
/// [`SyncError::Transport`] on HTTP failure, [`SyncError::Decode`]
/// on a malformed manifest.
pub fn fetch_manifest(addr: &str) -> Result<Manifest, SyncError> {
    let manifest_bytes = fetch_hex(addr, "/snapshot/manifest")?;
    let mut reader = codec::Reader::new(&manifest_bytes);
    <Manifest as codec::Decode>::decode(&mut reader)
        .map_err(|e| SyncError::Decode(format!("manifest: {e}")))
}

/// Fetch `GET /snapshot/cert/{height}` — the quorum-signed
/// [`types::ExecCertificate`] attesting `(height, state_root)`.
///
/// The endpoint 404s until the serving validator's engine has
/// formed the certificate for that height, so callers poll: pin a
/// manifest first, then retry this until it succeeds or the
/// deadline passes. The certificate is verified client-side
/// against a validator-set checkpoint — this function returns
/// raw bytes + decode only; trusting the peer ends here.
///
/// # Errors
///
/// [`SyncError::Transport`] on HTTP failure (including the 404
/// poll response), [`SyncError::Decode`] on a malformed cert.
pub fn fetch_exec_certificate(
    addr: &str,
    height: u64,
) -> Result<types::ExecCertificate, SyncError> {
    let bytes = fetch_hex(addr, &format!("/snapshot/cert/{height}"))?;
    let mut reader = codec::Reader::new(&bytes);
    <types::ExecCertificate as codec::Decode>::decode(&mut reader)
        .map_err(|e| SyncError::Decode(format!("exec cert: {e}")))
}

/// Download and hash-verify every chunk of `manifest`, returning
/// the assembled snapshot blob — the caller decodes the
/// [`executor::ExecutorSnapshot`] and imports it.
///
/// # Errors
///
/// Propagates [`SyncError`] per chunk; `ChunkHashMismatch` means
/// the peer served bytes the manifest does not describe.
pub fn fetch_blob(addr: &str, manifest: &Manifest) -> Result<Vec<u8>, SyncError> {
    let mut chunks = Vec::with_capacity(manifest.chunk_count());
    for i in 0..manifest.chunk_count() {
        let chunk = fetch_hex(addr, &format!("/snapshot/chunk/{i}"))?;
        if !verify_chunk(manifest, i, &chunk) {
            return Err(SyncError::ChunkHashMismatch { index: i });
        }
        chunks.push(chunk);
    }
    assemble(manifest, &chunks)
}

/// Run the full download against a peer's snapshot endpoints.
/// Returns the assembled, chunk-verified blob — the caller decodes
/// the [`executor::ExecutorSnapshot`] and imports it.
///
/// `trusted_height`/`trusted_root` anchor the manifest before any
/// chunk is fetched; `max_version` lets the caller reject a format
/// its importer predates. Note this composed helper anchors on the
/// operator pin only — the certificate-verified path
/// (`fetch_manifest` → `fetch_exec_certificate` → `fetch_blob`) is
/// the one that removes operator-typed trust.
///
/// # Errors
///
/// Propagates [`SyncError`] from each stage; `Untrusted` or a
/// `format_version` newer than `max_version` abort before any
/// chunk download.
pub fn fetch_snapshot(
    addr: &str,
    trusted_height: u64,
    trusted_root: &Hash,
    max_version: u32,
) -> Result<Vec<u8>, SyncError> {
    let manifest = fetch_manifest(addr)?;
    check_trusted(&manifest, trusted_height, trusted_root)?;
    if manifest.format_version > max_version {
        return Err(SyncError::Decode(format!(
            "snapshot format {} newer than supported {max_version}",
            manifest.format_version
        )));
    }
    fetch_blob(addr, &manifest)
}

/// Decode a `0x`-prefixed (or bare) hex string. Local copy so the
/// crate stays std-only — the body is a hex string, nothing more.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode as _;

    fn blob(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn chunk_verify_assemble_round_trip() {
        let data = blob(10_000);
        let (manifest, chunks) = chunk_blob(7, Hash([9; 32]), 2, &data, 1024);
        assert_eq!(manifest.height, 7);
        assert_eq!(manifest.chunk_count(), chunks.len());
        assert_eq!(manifest.total_len, 10_000);
        for (i, c) in chunks.iter().enumerate() {
            assert!(verify_chunk(&manifest, i, c), "chunk {i} must verify");
        }
        assert_eq!(assemble(&manifest, &chunks).unwrap(), data);
    }

    #[test]
    fn tampered_chunk_rejected() {
        let data = blob(3000);
        let (manifest, mut chunks) = chunk_blob(1, Hash::ZERO, 2, &data, 1024);
        chunks[1][0] ^= 0xff;
        assert!(!verify_chunk(&manifest, 1, &chunks[1]));
    }

    #[test]
    fn manifest_codec_round_trip() {
        let data = blob(1500);
        let (manifest, _) = chunk_blob(42, Hash([3; 32]), 2, &data, 512);
        let mut buf = Vec::new();
        codec::Encode::encode(&manifest, &mut buf);
        let mut reader = codec::Reader::new(&buf);
        let decoded = <Manifest as codec::Decode>::decode(&mut reader).unwrap();
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn manifest_decode_rejects_inconsistent_count() {
        // Forge a manifest whose count field disagrees with
        // total_len/chunk_size — must not allocate on the claim.
        let mut buf = Vec::new();
        codec::write::u64(&mut buf, 1);
        Hash::ZERO.encode(&mut buf);
        codec::write::u32(&mut buf, 2);
        codec::write::u32(&mut buf, 100); // chunk_size
        codec::write::u64(&mut buf, 1000); // total_len → expected 10 chunks
        codec::write::u32(&mut buf, 50); // forged count
        let mut reader = codec::Reader::new(&buf);
        assert!(<Manifest as codec::Decode>::decode(&mut reader).is_err());
    }

    #[test]
    fn empty_blob_yields_zero_chunks() {
        let (manifest, chunks) = chunk_blob(0, Hash::ZERO, 2, &[], 1024);
        assert!(chunks.is_empty());
        assert_eq!(manifest.chunk_count(), 0);
        assert_eq!(assemble(&manifest, &chunks).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn check_trusted_enforces_height_and_root() {
        let (manifest, _) = chunk_blob(9, Hash([7; 32]), 2, &blob(10), 4);
        assert!(check_trusted(&manifest, 9, &Hash([7; 32])).is_ok());
        assert!(matches!(check_trusted(&manifest, 8, &Hash([7; 32])), Err(SyncError::Untrusted)));
        assert!(matches!(check_trusted(&manifest, 9, &Hash([6; 32])), Err(SyncError::Untrusted)));
    }
}
