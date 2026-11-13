//! Control frames on the binary TCP protocol: session open, session
//! close and certified batches.
//!
//! A control frame reuses the 4-byte request header,
//! `[magic:2][version:1][flag:1]`, with the flag [`CONTROL_FLAG`]
//! (`0xFD`), followed by one kind byte and a fixed-size body:
//!
//! | Kind | Body | Response |
//! |---|---|---|
//! | [`KIND_SESSION_OPEN`] | `SessionOpen` ([`crate::auth::SESSION_OPEN_LEN`] bytes) | 5 bytes |
//! | [`KIND_SESSION_CLOSE`] | `SessionClose` ([`crate::auth::SESSION_CLOSE_LEN`] bytes) | 5 bytes |
//! | [`KIND_CERT_BATCH`] | `BatchCertificate` (128 bytes) ‖ a standard batch request | a standard batch response |
//!
//! The 5-byte response is `[status:1][session_id:4 LE]` (the id is
//! meaningful only for a successful open). Status values are
//! [`Status`]. Every frame is authenticated by its own signature; the
//! flag only routes it. Not carried on the WebSocket and FIX transports.

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::auth::{
    Authenticator, BatchCertificate, CERT_LEN, SESSION_CLOSE_LEN, SESSION_OPEN_LEN, SessionClose,
    SessionError, SessionOpen,
};
use crate::protocol::{BATCH_ENTRY_SIZE, MAGIC, MAX_BATCH_SIZE, OrderRequest, VERSION};

/// Header flag byte marking a control frame (`0xFF` = batch, `0xFE` =
/// action).
pub const CONTROL_FLAG: u8 = 0xFD;
/// Kind: open a session.
pub const KIND_SESSION_OPEN: u8 = 1;
/// Kind: close a session.
pub const KIND_SESSION_CLOSE: u8 = 2;
/// Kind: a gateway-certified batch.
pub const KIND_CERT_BATCH: u8 = 3;
/// Length of the session-control response.
pub const SESSION_RESPONSE_LEN: usize = 5;

/// Outcome codes in a session-control response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Done.
    Ok = 0,
    /// This matcher's authentication scheme has no sessions.
    Unsupported = 1,
    /// The request was not authorized by the session's owner.
    BadAuthorization = 2,
    /// The session table is full.
    Full = 3,
    /// The expiry is missing, past, or beyond the maximum lifetime.
    BadExpiry = 4,
    /// No such session.
    NotFound = 5,
    /// The frame could not be parsed.
    Malformed = 6,
}

impl Status {
    /// Decode a response status byte.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Ok,
            1 => Self::Unsupported,
            2 => Self::BadAuthorization,
            3 => Self::Full,
            4 => Self::BadExpiry,
            5 => Self::NotFound,
            6 => Self::Malformed,
            _ => return None,
        })
    }
}

impl From<SessionError> for Status {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::Unsupported => Self::Unsupported,
            SessionError::BadAuthorization => Self::BadAuthorization,
            SessionError::Full => Self::Full,
            SessionError::BadExpiry => Self::BadExpiry,
            SessionError::NotFound => Self::NotFound,
        }
    }
}

fn header(kind: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(5);
    b.extend_from_slice(&MAGIC.to_le_bytes());
    b.push(VERSION);
    b.push(CONTROL_FLAG);
    b.push(kind);
    b
}

/// Client: encode a session-open frame.
#[must_use]
pub fn encode_session_open(open: &SessionOpen) -> Vec<u8> {
    let mut b = header(KIND_SESSION_OPEN);
    b.extend_from_slice(&open.to_bytes());
    b
}

/// Client: encode a session-close frame.
#[must_use]
pub fn encode_session_close(close: &SessionClose) -> Vec<u8> {
    let mut b = header(KIND_SESSION_CLOSE);
    b.extend_from_slice(&close.to_bytes());
    b
}

/// Client: encode a certified-batch frame.
///
/// # Panics
///
/// Panics if `orders` is empty (as `encode_batch_request`).
#[must_use]
pub fn encode_cert_batch(cert: &BatchCertificate, orders: &[OrderRequest]) -> Vec<u8> {
    let mut b = header(KIND_CERT_BATCH);
    b.extend_from_slice(&cert.to_bytes());
    b.extend_from_slice(&crate::protocol::encode_batch_request(orders));
    b
}

/// Client: decode a session-control response into `(status, session id)`.
#[must_use]
pub fn decode_session_response(b: &[u8; SESSION_RESPONSE_LEN]) -> Option<(Status, u32)> {
    let status = Status::from_u8(b[0])?;
    Some((status, u32::from_le_bytes([b[1], b[2], b[3], b[4]])))
}

/// The connection failed or sent an unusable length: drop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLost;

/// A parsed control frame body (the 4-byte header is already consumed).
pub enum Frame {
    /// Open a session.
    Open(SessionOpen),
    /// Close a session.
    Close(SessionClose),
    /// A certified batch.
    CertBatch(BatchCertificate, Vec<OrderRequest>),
    /// Well-formed header, unusable body (unknown kind, bad batch).
    Malformed,
}

/// Read the rest of a control frame from `r` (kind byte and body).
///
/// # Errors
///
/// [`ConnectionLost`] on an I/O error or EOF: the caller should drop the
/// connection. A frame that reads fully but does not parse is
/// `Ok(Frame::Malformed)`, so the caller can answer and continue.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame, ConnectionLost> {
    let mut kind = [0u8; 1];
    r.read_exact(&mut kind).await.map_err(|_| ConnectionLost)?;
    match kind[0] {
        KIND_SESSION_OPEN => {
            let mut b = [0u8; SESSION_OPEN_LEN];
            r.read_exact(&mut b).await.map_err(|_| ConnectionLost)?;
            Ok(Frame::Open(SessionOpen::from_bytes(&b)))
        }
        KIND_SESSION_CLOSE => {
            let mut b = [0u8; SESSION_CLOSE_LEN];
            r.read_exact(&mut b).await.map_err(|_| ConnectionLost)?;
            Ok(Frame::Close(SessionClose::from_bytes(&b)))
        }
        KIND_CERT_BATCH => {
            let mut cert = [0u8; CERT_LEN];
            r.read_exact(&mut cert).await.map_err(|_| ConnectionLost)?;
            let mut head = [0u8; 8];
            r.read_exact(&mut head).await.map_err(|_| ConnectionLost)?;
            let count = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as usize;
            // Bound the count BEFORE allocating (a peer can send u32::MAX).
            if count > MAX_BATCH_SIZE {
                return Err(ConnectionLost);
            }
            let mut entries = vec![0u8; count * BATCH_ENTRY_SIZE];
            r.read_exact(&mut entries).await.map_err(|_| ConnectionLost)?;
            let mut full = Vec::with_capacity(8 + entries.len());
            full.extend_from_slice(&head);
            full.extend_from_slice(&entries);
            Ok(crate::protocol::decode_batch_request(&full).map_or(Frame::Malformed, |orders| {
                Frame::CertBatch(BatchCertificate::from_bytes(&cert), orders)
            }))
        }
        _ => Ok(Frame::Malformed),
    }
}

/// Apply a session frame with `auth` and build the 5-byte response.
/// Returns `None` for frames that are not session frames.
#[must_use]
pub fn apply_session_frame(
    auth: &dyn Authenticator,
    chain_id: u64,
    frame: &Frame,
) -> Option<[u8; SESSION_RESPONSE_LEN]> {
    let (status, id) = match frame {
        Frame::Open(open) => match auth.open_session(open, chain_id) {
            Ok(id) => (Status::Ok, id),
            Err(e) => (e.into(), 0),
        },
        Frame::Close(close) => match auth.close_session_authorized(close, chain_id) {
            Ok(()) => (Status::Ok, close.session_id),
            Err(e) => (e.into(), 0),
        },
        Frame::Malformed => (Status::Malformed, 0),
        Frame::CertBatch(..) => return None,
    };
    let mut out = [0u8; SESSION_RESPONSE_LEN];
    out[0] = status as u8;
    out[1..5].copy_from_slice(&id.to_le_bytes());
    Some(out)
}

/// JSON-RPC method: open a session. Params: `{"frame":"<hex>"}` where
/// the frame is [`SessionOpen::to_bytes`] in hex.
pub const METHOD_OPEN_SESSION: &str = "oxide_openSession";
/// JSON-RPC method: close a session. Params: `{"frame":"<hex>"}` where
/// the frame is [`SessionClose::to_bytes`] in hex.
pub const METHOD_CLOSE_SESSION: &str = "oxide_closeSession";

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            let hi = crate::protocol::hex_nibble(*s.as_bytes().get(i)?)?;
            let lo = crate::protocol::hex_nibble(*s.as_bytes().get(i + 1)?)?;
            Some((hi << 4) | lo)
        })
        .collect()
}

/// Handle a JSON-RPC session method. Returns the full response line
/// (newline-terminated), or `None` if `method` is not a session method.
#[must_use]
pub fn jsonrpc_session(
    auth: &dyn Authenticator,
    chain_id: u64,
    method: &str,
    params: &serde_json::Value,
    id: &serde_json::Value,
) -> Option<String> {
    if method != METHOD_OPEN_SESSION && method != METHOD_CLOSE_SESSION {
        return None;
    }
    let bytes = params.get("frame").and_then(|v| v.as_str()).and_then(unhex);
    let frame = match (method == METHOD_OPEN_SESSION, bytes) {
        (true, Some(b)) => <[u8; SESSION_OPEN_LEN]>::try_from(b)
            .ok()
            .map_or(Frame::Malformed, |a| Frame::Open(SessionOpen::from_bytes(&a))),
        (false, Some(b)) => <[u8; SESSION_CLOSE_LEN]>::try_from(b)
            .ok()
            .map_or(Frame::Malformed, |a| Frame::Close(SessionClose::from_bytes(&a))),
        (_, None) => Frame::Malformed,
    };
    let resp = apply_session_frame(auth, chain_id, &frame)?;
    let status = Status::from_u8(resp[0]).unwrap_or(Status::Malformed);
    let session_id = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]);
    let result = if status == Status::Ok {
        serde_json::json!({"jsonrpc": "2.0", "result": {"status": "ok", "session_id": session_id}, "id": id})
    } else {
        serde_json::json!({"jsonrpc": "2.0", "error": {"code": -32000, "message": format!("{status:?}")}, "id": id})
    };
    Some(format!("{result}\n"))
}
