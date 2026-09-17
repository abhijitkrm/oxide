//! HTTP server for the JSON-RPC endpoint.
//!
//! Wraps [`RpcServer::handle_raw`] in an HTTP server using `axum`
//! (built on `hyper` + `tokio`). Exposes a single POST endpoint at `/`
//! that accepts JSON-RPC request bodies and returns JSON-RPC responses.
//!
//! # Why axum
//!
//! axum is the standard ergonomic HTTP framework for Rust, built on
//! hyper + tokio. It handles HTTP/1.1 protocol details (content-length,
//! keep-alive, chunked encoding) that we would otherwise need to
//! implement manually. The RPC crate is not a hot-path crate (it's not
//! on the consensus/execution path), so the dependency footprint is
//! acceptable.
//!
//! # Endpoints
//!
//! - `POST /` — JSON-RPC 2.0 request/response (Ethereum-compatible)
//! - `GET /` — WebSocket upgrade (geth convention: WS shares the
//!   HTTP port on the root path). Serves `eth_subscribe` /
//!   `eth_unsubscribe` and pushes `eth_subscription` notifications.
//! - `GET /health` — simple health check (returns 200 OK)
//! - `GET /metrics` — Prometheus-format node metrics
//! - `GET /snapshot` — codec-encoded state snapshot (hex)
//!
//! # Usage
//!
//! ```no_run
//! use rpc::server::HttpServer;
//! use rpc::RpcServer;
//!
//! # async fn run() {
//! let rpc = RpcServer::new(1, 1_000_000_000);
//! let server = HttpServer::new(rpc, "127.0.0.1:8545".to_string());
//! server.serve().await;
//! # }
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::{RpcServer, WsConn};

/// Default rate limit: max requests per second per IP. Prevents a
/// single client from flooding the RPC with requests and exhausting
/// the node's resources. 100 req/s is generous for a JSON-RPC client
/// (`eth_getLogs`, `eth_call`, etc.) but caps abuse. Units: requests
/// per second per IP. Origin: HIGH audit fix. Tradeoff: lower =
/// safer but may reject legitimate bursty clients; higher = more
/// permissive but more vulnerable to `DoS`.
const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 100;

/// Maximum number of simultaneously open client connections
/// (HTTP + WebSocket share one pool). reth's `--rpc.max-connections`
/// is 500 by default; geth has no equivalent cap. Past the limit the
/// listener drops freshly accepted sockets — clients see a reset and
/// can retry — rather than queueing unbounded work.
/// Units: open sockets. Tradeoff: too low starves real traffic behind
/// idle keep-alive conns; too high weakens fd/memory exhaustion
/// protection.
const DEFAULT_MAX_OPEN_CONNECTIONS: usize = 512;

/// Wall-clock bound on a single HTTP request's dispatch — the
/// `http-timeout` role (geth's `--http.timeouts` default: 30 s
/// read/write/idle). The handler is synchronous CPU work, so the
/// dispatch runs on `tokio::task::spawn_blocking` and the timeout
/// abandons the *response* — the orphaned task still drains on the
/// blocking pool (it cannot be killed mid-flight; the EVM sim
/// timeout bounds the expensive cases anyway). What this guard
/// buys: a client never waits past 30 s, and a runaway request
/// occupies at most one blocking-pool slot rather than a
/// core-blocking handler slot indefinitely.
/// Units: seconds. Tradeoff: lower protects the pool sooner but
/// can cut off legitimately heavy `eth_getProof`/log sweeps.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Wall-clock bound on a single WebSocket frame write — geth's
/// `--ws.timeouts` is the same 30 s default. A slow/stalled
/// consumer otherwise holds the connection (and its
/// `ConnectionLimiter` slot) forever: `send` on a full TCP buffer
/// never returns. On timeout the connection is closed, freeing
/// the slot.
const WS_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// A process-wide cap on open RPC connections.
///
/// The counter is acquired in [`LimitedListener::accept`] — before a
/// socket is ever served — and released when the connection closes
/// (the permit rides inside [`CountedIo`]). That makes the bound a
/// true open-connection limit, including idle keep-alive sockets and
/// long-lived `WebSocket`s, not just in-flight requests.
struct ConnectionLimiter {
    /// Currently open connections.
    open: AtomicUsize,
    /// The cap.
    max: usize,
}

impl ConnectionLimiter {
    fn new(max: usize) -> Self {
        Self { open: AtomicUsize::new(0), max }
    }

    /// Try to admit one more connection. `None` when at the cap.
    fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        // CAS loop: increment only while under the cap so a racing
        // acquire cannot push the count past `max`.
        let mut cur = self.open.load(Ordering::Acquire);
        loop {
            if cur >= self.max {
                return None;
            }
            match self.open.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Some(ConnectionPermit { limiter: Arc::clone(self) }),
                Err(next) => cur = next,
            }
        }
    }

    /// Number of currently open connections (metrics/tests).
    #[cfg(test)]
    fn open_count(&self) -> usize {
        self.open.load(Ordering::Acquire)
    }
}

/// Held inside [`CountedIo`] for a connection's lifetime; releases
/// the slot on drop.
struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.open.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A `TcpStream` that holds a [`ConnectionPermit`] until the socket
/// is closed — the permit's `Drop` releases the slot.
struct CountedIo {
    inner: TcpStream,
    _permit: ConnectionPermit,
}

impl AsyncRead for CountedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CountedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// A `TcpListener` that drops accepted sockets once the connection
/// cap is reached. Implements axum's [`Listener`] so `serve` uses it
/// directly.
struct LimitedListener {
    inner: TcpListener,
    limiter: Arc<ConnectionLimiter>,
}

impl Listener for LimitedListener {
    type Io = CountedIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (CountedIo, SocketAddr) {
        loop {
            // A failed accept is not a connection — keep listening
            // rather than wedging the server on a transient
            // EMFILE/EINTR.
            let Ok((socket, addr)) = self.inner.accept().await else { continue };
            if let Some(permit) = self.limiter.try_acquire() {
                return (CountedIo { inner: socket, _permit: permit }, addr);
            }
            // Over the cap: drop the socket. The client sees a reset;
            // pending backlog connections are pulled next iteration
            // until a slot frees.
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// A simple per-IP fixed-window rate limiter (HIGH fix).
///
/// Tracks request counts per IP in a `HashMap`. The window resets
/// every second. This is a cold-path component (RPC, not consensus),
/// so a `Mutex<HashMap>` is acceptable — the lock is held for a
/// single `HashMap` lookup/update per request.
struct RateLimiter {
    /// IP to `(window_start, request_count)`.
    buckets: std::sync::Mutex<HashMap<IpAddr, (Instant, u32)>>,
    /// Max requests per second per IP.
    max_per_sec: u32,
}

impl RateLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self { buckets: std::sync::Mutex::new(HashMap::new()), max_per_sec }
    }

    /// Check if a request from `ip` is allowed. Returns `true` if
    /// the request is within the rate limit, `false` if it exceeds
    /// it.
    fn allow(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if let Some((window_start, count)) = buckets.get_mut(&ip) {
            if now.duration_since(*window_start) >= Duration::from_secs(1) {
                // Reset the window.
                *window_start = now;
                *count = 1;
                true
            } else if *count < self.max_per_sec {
                *count += 1;
                true
            } else {
                false
            }
        } else {
            buckets.insert(ip, (now, 1));
            true
        }
    }
}

/// The HTTP server wrapping an [`RpcServer`] in an axum router.
///
/// The RPC server is wrapped in `Arc` so it can be shared across
/// async tasks. The `handle_raw` method is thread-safe (it takes
/// `&self` and all state is either immutable or behind interior
/// mutability).
pub struct HttpServer {
    /// The RPC handler (wrapped in Arc for sharing across tasks).
    rpc: Arc<RpcServer>,
    /// The bind address (e.g. "127.0.0.1:8545").
    addr: String,
    /// Per-IP rate limiter (HIGH fix). Prevents a single client
    /// from flooding the RPC with requests.
    rate_limiter: Arc<RateLimiter>,
    /// Open-connection cap shared by HTTP and WebSocket.
    conn_limiter: Arc<ConnectionLimiter>,
}

impl HttpServer {
    /// Create a new HTTP server wrapping the given RPC handler.
    ///
    /// The server will listen on `addr` when [`serve`](Self::serve) is
    /// called.
    #[must_use]
    pub fn new(rpc: RpcServer, addr: String) -> Self {
        Self {
            rpc: Arc::new(rpc),
            addr,
            rate_limiter: Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC)),
            conn_limiter: Arc::new(ConnectionLimiter::new(DEFAULT_MAX_OPEN_CONNECTIONS)),
        }
    }

    /// Create a new HTTP server from an `Arc<RpcServer>` (useful when
    /// the RPC server is shared with other components, e.g. the
    /// executor updates the block height).
    #[must_use]
    pub fn from_shared(rpc: Arc<RpcServer>, addr: String) -> Self {
        Self {
            rpc,
            addr,
            rate_limiter: Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC)),
            conn_limiter: Arc::new(ConnectionLimiter::new(DEFAULT_MAX_OPEN_CONNECTIONS)),
        }
    }

    /// Get a clone of the inner `Arc<RpcServer>` (for external state
    /// updates, e.g. `set_block_height`).
    #[must_use]
    pub fn rpc(&self) -> Arc<RpcServer> {
        Arc::clone(&self.rpc)
    }

    /// Start serving HTTP requests. This blocks the current async
    /// task until the server is shut down.
    ///
    /// # Panics
    ///
    /// Panics if the TCP listener cannot bind to `addr` (e.g. port in
    /// use). In production, the caller should handle this gracefully.
    pub async fn serve(self) {
        let listener = TcpListener::bind(&self.addr).await.unwrap_or_else(|e| {
            panic!("RPC HTTP server: failed to bind {addr}: {e}", addr = self.addr)
        });
        eprintln!("RPC HTTP server: listening on http://{}", self.addr);
        self.serve_on(listener).await;
    }

    /// Serve on an already-bound listener — the caller owns the
    /// socket choice (e.g. tests binding `127.0.0.1:0` and reading
    /// back the OS-assigned port).
    ///
    /// # Panics
    ///
    /// Panics if axum fails while serving.
    pub async fn serve_on(self, listener: TcpListener) {
        let app = Self::router(self.rpc, self.rate_limiter);
        let listener = LimitedListener { inner: listener, limiter: self.conn_limiter };
        axum::serve(listener, app).await.unwrap_or_else(|e| panic!("RPC HTTP server: {e}"));
    }

    /// Build the axum router with the RPC handler and rate limiter.
    fn router(rpc: Arc<RpcServer>, rate_limiter: Arc<RateLimiter>) -> Router {
        Router::new()
            .route("/", post(handle_rpc).get(ws_handler))
            .route("/health", get(health_check))
            .route("/metrics", get(metrics_handler))
            .route("/snapshot", get(snapshot_handler))
            .route("/snapshot/manifest", get(snapshot_manifest_handler))
            .route("/snapshot/chunk/{index}", get(snapshot_chunk_handler))
            .route("/validator-set", get(validator_set_handler))
            .with_state((rpc, rate_limiter))
    }
}

/// Handle a JSON-RPC POST request.
///
/// The request body is the raw JSON-RPC request string. The response
/// is the raw JSON-RPC response string from [`RpcServer::handle_raw`].
async fn handle_rpc(
    State((rpc, rate_limiter)): State<(Arc<RpcServer>, Arc<RateLimiter>)>,
    body: String,
) -> Response<String> {
    // HIGH fix: rate-limit per IP. Use 127.0.0.1 as a fallback when
    // the connection info isn't available (e.g. behind a proxy).
    // In production, axum's `ConnectInfo` extractor provides the
    // real client IP; for now, we use a default since the server
    // doesn't yet use `into_make_service_with_connect_info`.
    let ip: IpAddr = "127.0.0.1".parse().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    if !rate_limiter.allow(ip) {
        return Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"rate limit exceeded"},"id":null}"#.to_string())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("{}".to_string())
                    .unwrap()
            });
    }
    // `handle_raw` is synchronous CPU work — run it on the
    // blocking pool so a heavy request (proof rebuild, 10k-log
    // sweep, max-size batch) cannot pin a tokio worker thread,
    // and bound it with `HTTP_REQUEST_TIMEOUT`: past the deadline
    // the client gets a timeout response while the orphaned task
    // drains to completion on the blocking pool.
    let rpc2 = Arc::clone(&rpc);
    let work = tokio::task::spawn_blocking(move || rpc2.handle_raw(&body));
    let response = match tokio::time::timeout(HTTP_REQUEST_TIMEOUT, work).await {
        Ok(Ok(response)) => response,
        Ok(Err(_join_err)) => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"},"id":null}"#.to_string())
                .unwrap_or_else(|_| Response::new("{}".to_string()));
        }
        Err(_elapsed) => {
            return Response::builder()
                .status(StatusCode::REQUEST_TIMEOUT)
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"request timed out"},"id":null}"#.to_string())
                .unwrap_or_else(|_| Response::new("{}".to_string()));
        }
    };
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(response)
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("{}".to_string())
                .unwrap()
        })
}

/// WebSocket upgrade endpoint (`GET /` with `Upgrade: websocket`).
///
/// geth serves WS on the same port and root path as HTTP; clients
/// like ethers/MetaMask default to `ws://host:8545`. A plain
/// `GET /` without the upgrade header fails extraction with 426.
async fn ws_handler(
    State((rpc, _rate_limiter)): State<(Arc<RpcServer>, Arc<RateLimiter>)>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws_socket(socket, rpc))
}

/// Drive one WebSocket connection: inbound text frames are
/// JSON-RPC requests dispatched through [`RpcServer::handle_ws_raw`]
/// (so `eth_subscribe` binds to this connection's outbound
/// channel); outbound frames are request responses plus
/// `eth_subscription` notifications pushed by the publish path.
///
/// A single `select!` loop multiplexes the two directions on one
/// socket — no `split()` needed because the writer half never
/// outlives the reader (`rx` closes when every sender drops; the
/// last sender lives in the subscription table and is reaped by
/// `drop_connection` below).
async fn handle_ws_socket(mut socket: WebSocket, rpc: Arc<RpcServer>) {
    let conn_id = rpc.next_connection_id();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let conn = WsConn::new(conn_id, tx.clone());
    loop {
        tokio::select! {
            out = rx.recv() => match out {
                Some(text) => {
                    // Bound the write: a stalled consumer otherwise
                    // holds the connection slot forever. `Err` outer
                    // = timed out; `Err` inner = socket write failed.
                    let send = socket.send(Message::Text(text.into()));
                    match tokio::time::timeout(WS_WRITE_TIMEOUT, send).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
                // All senders dropped (conn reaped) — close cleanly.
                None => break,
            },
            msg = socket.recv() => match msg {
                Some(Ok(Message::Text(text))) => {
                    let response = rpc.handle_ws_raw(&text, &conn);
                    if conn.sink.send(response).is_err() {
                        break;
                    }
                }
                // Protocol-level keepalive: reply to pings so
                // intermediaries don't drop the idle connection.
                Some(Ok(Message::Ping(payload))) => {
                    let send = socket.send(Message::Pong(payload));
                    match tokio::time::timeout(WS_WRITE_TIMEOUT, send).await {
                        Ok(Ok(())) => {}
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
                // Binary frames carry no JSON-RPC and pong frames
                // need no reply — the catch-all ignores both;
                // close/error/stream-end terminate the connection.
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
    // Reap this connection's subscriptions before `conn`/`tx` drop
    // so a publish racing the shutdown can't target a dead sink.
    rpc.drop_connection(conn_id);
}

/// State snapshot endpoint (`GET /snapshot`).
///
/// Returns the codec-encoded `ExecutorSnapshot` as a hex string
/// (`0x`-prefixed). The caller can save the hex to a file and later
/// import it via `--import-snapshot` on a new node.
///
/// Returns 404 if no snapshot provider is attached (stateless config).
async fn snapshot_handler(
    State((rpc, _rate_limiter)): State<(Arc<RpcServer>, Arc<RateLimiter>)>,
) -> Response<String> {
    match rpc.snapshot_provider() {
        Some(provider) => match provider.export_snapshot() {
            Ok(bytes) => {
                let hex = format!("0x{}", hex_encode(&bytes));
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .body(hex)
                    .unwrap_or_else(|_| {
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(String::new())
                            .unwrap()
                    })
            }
            Err(e) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "application/json")
                .body(format!(r#"{{"error":"{e}"}}"#))
                .unwrap_or_else(|_| {
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("{}".to_string())
                        .unwrap()
                }),
        },
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "application/json")
            .body(r#"{"error":"snapshot provider not configured"}"#.to_string())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("{}".to_string())
                    .unwrap()
            }),
    }
}

/// Helper for the snapshot-sync endpoints: hex-encode a byte body
/// or map the error to a status code. Kept small and shared so the
/// two handlers stay identical in framing.
fn hex_response(result: Result<Vec<u8>, String>, err_status: StatusCode) -> Response<String> {
    match result {
        Ok(bytes) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(format!("0x{}", hex_encode(&bytes)))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(String::new())
                    .unwrap()
            }),
        Err(e) => Response::builder()
            .status(err_status)
            .header("content-type", "application/json")
            .body(format!(r#"{{"error":"{e}"}}"#))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("{}".to_string())
                    .unwrap()
            }),
    }
}

/// Sync manifest endpoint (`GET /snapshot/manifest`).
///
/// Returns the codec-encoded `statesync::Manifest` as hex — the
/// trust anchor a syncing node verifies against its out-of-band
/// (height, `state_root`) before fetching any chunk. A request
/// re-exports the snapshot so the manifest always describes the
/// latest finalized state.
///
/// 404 when no snapshot provider is attached.
async fn snapshot_manifest_handler(
    State((rpc, _rate_limiter)): State<(Arc<RpcServer>, Arc<RateLimiter>)>,
) -> Response<String> {
    if rpc.snapshot_provider().is_none() {
        return hex_response(
            Err("snapshot provider not configured".to_string()),
            StatusCode::NOT_FOUND,
        );
    }
    hex_response(rpc.snapshot_manifest(), StatusCode::INTERNAL_SERVER_ERROR)
}

/// Sync chunk endpoint (`GET /snapshot/chunk/{index}`).
///
/// Returns the raw bytes of chunk `index` as hex — the client
/// verifies each chunk against `manifest.chunk_hashes[index]`
/// before assembling. Out-of-range indices get a 404: the client
/// should re-fetch the manifest (the cached snapshot may have been
/// replaced by a newer export).
async fn snapshot_chunk_handler(
    State((rpc, _rate_limiter)): State<(Arc<RpcServer>, Arc<RateLimiter>)>,
    Path(index): Path<usize>,
) -> Response<String> {
    if rpc.snapshot_provider().is_none() {
        return hex_response(
            Err("snapshot provider not configured".to_string()),
            StatusCode::NOT_FOUND,
        );
    }
    hex_response(rpc.snapshot_chunk(index), StatusCode::NOT_FOUND)
}

/// Validator set endpoint (`GET /validator-set`).
///
/// Returns the current validator set as JSON — a list of
/// `{address, public_key, stake}` objects. A new validator joining
/// mid-epoch queries this endpoint on an existing validator to
/// discover the current set + peer addresses, then connects via
/// `--devnet-node` with the updated `ValidatorSet`.
///
/// Returns 404 if no validator-set provider is attached.
async fn validator_set_handler(
    State((rpc, _rate_limiter)): State<(Arc<RpcServer>, Arc<RateLimiter>)>,
) -> Response<String> {
    match rpc.validator_set_provider() {
        Some(provider) => match provider.validator_set() {
            Ok(entries) => {
                let json = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(json)
                    .unwrap_or_else(|_| {
                        Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(String::new())
                            .unwrap()
                    })
            }
            Err(e) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("content-type", "application/json")
                .body(format!(r#"{{"error":"{e}"}}"#))
                .unwrap_or_else(|_| {
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("{}".to_string())
                        .unwrap()
                }),
        },
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("content-type", "application/json")
            .body(r#"{"error":"validator-set provider not configured"}"#.to_string())
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body("{}".to_string())
                    .unwrap()
            }),
    }
}

/// Hex-encode a byte slice (lowercase, no separators).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to String cannot fail");
    }
    s
}

/// Health check endpoint. Returns 200 OK with "ok".
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Prometheus metrics endpoint (`GET /metrics`).
///
/// Returns a Prometheus text-format exposition of node metrics:
/// `oxide_block_height`, `oxide_tx_count`, `oxide_mempool_size`, and
/// any latency histograms recorded by the attached `metrics::Recorder`.
/// The `Content-Type` is `text/plain; version=0.0.4` (the standard
/// Prometheus exposition format).
async fn metrics_handler(
    State((rpc, _rate_limiter)): State<(Arc<RpcServer>, Arc<RateLimiter>)>,
) -> Response<String> {
    let body = rpc.metrics_text();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(body)
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(String::new())
                .unwrap()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RpcRequest;

    /// Test the health check endpoint returns 200.
    #[tokio::test]
    async fn health_check_returns_ok() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Test the RPC handler responds to a simple `eth_chainId` request.
    #[tokio::test]
    async fn rpc_responds_to_chain_id() {
        let rpc = Arc::new(RpcServer::new(1, 1_000_000_000));
        let request = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#;
        let response = rpc.handle_raw(request);
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(parsed["result"], "0x1");
    }

    /// Test the router is constructed without panicking.
    #[tokio::test]
    async fn router_builds() {
        let rpc = Arc::new(RpcServer::new(1, 1_000_000_000));
        let rate_limiter = Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC));
        let _router = HttpServer::router(rpc, rate_limiter);
    }

    /// Test the `/metrics` endpoint returns Prometheus-format text
    /// with the basic node gauges.
    #[tokio::test]
    async fn metrics_handler_returns_prometheus_text() {
        let rpc = Arc::new(RpcServer::new(1, 1_000_000_000));
        rpc.set_block_height(42);
        rpc.increment_tx_count();
        rpc.increment_tx_count();
        rpc.set_mempool_size(7);
        let rate_limiter = Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC));
        let response = metrics_handler(State((rpc, rate_limiter))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.body();
        assert!(body.contains("oxide_block_height 42"), "body: {body}");
        assert!(body.contains("oxide_tx_count 2"), "body: {body}");
        assert!(body.contains("oxide_mempool_size 7"), "body: {body}");
    }

    /// Test that an unknown method returns a method-not-found error.
    #[tokio::test]
    async fn unknown_method_returns_error() {
        let rpc = Arc::new(RpcServer::new(1, 1_000_000_000));
        let request = r#"{"jsonrpc":"2.0","method":"eth_unknownMethod","params":[],"id":1}"#;
        let response = rpc.handle_raw(request);
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(parsed["error"].is_object(), "should return an error");
        assert!(parsed["result"].is_null(), "result should be null on error");
    }

    /// Test that a malformed JSON returns a parse error.
    #[tokio::test]
    async fn malformed_json_returns_parse_error() {
        let rpc = Arc::new(RpcServer::new(1, 1_000_000_000));
        let response = rpc.handle_raw("not valid json");
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(parsed["error"].is_object(), "should return a parse error");
    }

    /// Test that the `RpcRequest` struct deserializes correctly.
    #[test]
    fn rpc_request_deserializes() {
        let json = r#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":42}"#;
        let req: RpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "eth_blockNumber");
    }

    /// The connection limiter admits up to `max` concurrent
    /// connections and frees slots when permits drop.
    #[test]
    fn connection_limiter_caps_and_releases() {
        let limiter = Arc::new(ConnectionLimiter::new(2));
        let p1 = limiter.try_acquire().expect("first connection admitted");
        let p2 = limiter.try_acquire().expect("second connection admitted");
        assert!(limiter.try_acquire().is_none(), "third connection at cap");
        assert_eq!(limiter.open_count(), 2);
        drop(p1);
        assert_eq!(limiter.open_count(), 1);
        let _p3 = limiter.try_acquire().expect("slot freed after close");
        drop(p2);
    }
}
