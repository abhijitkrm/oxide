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
use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::serve::{Listener, ListenerExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

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

/// Maximum RPC dispatches allowed on the blocking pool at once —
/// the bound that keeps expensive work (`eth_call` sweeps, log
/// scans, snapshot exports) from saturating every runtime blocking
/// slot and starving the rest of the node. Requests past the cap
/// are refused fast (HTTP 429 / a WS error frame) rather than
/// queued unboundedly. Units: in-flight blocking tasks. Origin:
/// the audit requires *bounded* expensive-work concurrency —
/// `spawn_blocking` tasks cannot be cancelled, so a client's
/// abandoned request still occupies a slot until it finishes;
/// this semaphore makes that occupancy finite. Tradeoff: lower
/// protects the node harder but rejects heavy-but-legitimate
/// bursts; 64 is deep enough for real dashboards while still
/// ~8× under tokio's default 512-thread pool ceiling.
const RPC_BLOCKING_PERMITS: usize = 64;

/// Maximum distinct source IPs tracked by the rate limiter —
/// now that buckets key on *real* connection IPs, an attacker
/// rotating source addresses could otherwise grow the map
/// without bound (the limiter itself becoming the memory-DoS
/// vector). On overflow the limiter first evicts expired windows;
/// a still-full map refuses the request (fail closed — the
/// attacked node rejects rather than allocates). Units: map
/// entries. Tradeoff: 65,536 ≈ 64K IPs ≈ a few MB worst case —
/// generous for real client diversity, bounded for memory.
const MAX_RATE_BUCKETS: usize = 65_536;

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
        let mut buckets = primitives::sync::lock_state(&self.buckets);
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
            // Bound the map: real per-IP keys mean an attacker
            // rotating source addresses could otherwise allocate
            // without limit. Sweep expired windows first; a map
            // still at cap refuses rather than grows.
            if buckets.len() >= MAX_RATE_BUCKETS {
                buckets.retain(|_, (window_start, _)| {
                    now.duration_since(*window_start) < Duration::from_secs(1)
                });
                if buckets.len() >= MAX_RATE_BUCKETS {
                    return false;
                }
            }
            buckets.insert(ip, (now, 1));
            true
        }
    }
}

/// State shared by every handler: the RPC dispatcher, the per-IP
/// rate limiter, and the semaphore bounding concurrent expensive
/// dispatches. One `Arc` keeps handler extraction cheap and lets
/// the WebSocket path share the same budgets as HTTP.
#[derive(Clone)]
struct RpcState {
    /// The JSON-RPC dispatcher.
    rpc: Arc<RpcServer>,
    /// Per-IP fixed-window limiter — transport-independent: one
    /// client cannot get more budget by switching to WebSocket.
    rate_limiter: Arc<RateLimiter>,
    /// Bound on concurrent `spawn_blocking` dispatches — covers
    /// HTTP handlers, WS frames, and snapshot exports.
    work_permits: Arc<Semaphore>,
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

    /// Override the per-IP request budget (requests/second). The
    /// default [`DEFAULT_RATE_LIMIT_PER_SEC`] suits private
    /// endpoints; operators exposing the RPC publicly lower it,
    /// and tests use small values so limit behavior is exercised
    /// without hundred-request floods.
    #[must_use]
    pub fn with_rate_limit(mut self, max_per_sec: u32) -> Self {
        self.rate_limiter = Arc::new(RateLimiter::new(max_per_sec));
        self
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
        // `tap_io` wraps the listener so axum's generic `Connected`
        // impl can surface the accepted `SocketAddr` to handlers —
        // the tap itself is a no-op; only the type plumbing matters.
        let listener =
            LimitedListener { inner: listener, limiter: self.conn_limiter }.tap_io(|_io| {});
        // `into_make_service_with_connect_info` attaches the real
        // peer `SocketAddr` to every request — `ConnectInfo` then
        // hands handlers the client's actual IP so the rate
        // limiter buckets per source instead of sharing one
        // loopback bucket across all clients.
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap_or_else(|e| panic!("RPC HTTP server: {e}"));
    }

    /// Build the axum router with the RPC handler and rate limiter.
    fn router(rpc: Arc<RpcServer>, rate_limiter: Arc<RateLimiter>) -> Router {
        let state = RpcState {
            rpc,
            rate_limiter,
            work_permits: Arc::new(Semaphore::new(RPC_BLOCKING_PERMITS)),
        };
        Router::new()
            .route("/", post(handle_rpc).get(ws_handler))
            .route("/health", get(health_check))
            .route("/metrics", get(metrics_handler))
            .route("/snapshot", get(snapshot_handler))
            .route("/snapshot/manifest", get(snapshot_manifest_handler))
            .route("/snapshot/chunk/{index}", get(snapshot_chunk_handler))
            .route("/validator-set", get(validator_set_handler))
            .with_state(state)
    }
}

/// Build the standard 429 rate-limit JSON-RPC response — shared by
/// the HTTP handler and the GET endpoints so every transport
/// reports budget exhaustion identically.
fn rate_limited_response() -> Response<String> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"rate limit exceeded"},"id":null}"#.to_string())
        .unwrap_or_else(|_| Response::new("{}".to_string()))
}

/// Build the standard 429 response for an exhausted
/// blocking-work budget — the node is refusing NEW expensive
/// dispatches, not rate-limiting a client. Same shape so clients
/// retry the same way.
fn busy_response() -> Response<String> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("content-type", "application/json")
        .body(r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"server busy — too many in-flight requests"},"id":null}"#.to_string())
        .unwrap_or_else(|_| Response::new("{}".to_string()))
}

/// Handle a JSON-RPC POST request.
///
/// The request body is the raw JSON-RPC request string. The response
/// is the raw JSON-RPC response string from [`RpcServer::handle_raw`].
async fn handle_rpc(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
    body: String,
) -> Response<String> {
    // Rate-limit per REAL connection IP — `ConnectInfo` is the
    // peer address axum accepted, so one client can no longer
    // consume the quota other clients share.
    if !state.rate_limiter.allow(addr.ip()) {
        return rate_limited_response();
    }
    // Bound concurrent expensive dispatches: `spawn_blocking`
    // tasks cannot be cancelled once running (a timed-out request
    // still occupies its slot), so an unbounded spawn rate would
    // let a flood pin the whole blocking pool. Refusing fast here
    // keeps the occupancy provably finite.
    let Ok(permit) = state.work_permits.clone().try_acquire_owned() else {
        return busy_response();
    };
    // `handle_raw` is synchronous CPU work — run it on the
    // blocking pool so a heavy request (proof rebuild, 10k-log
    // sweep, max-size batch) cannot pin a tokio worker thread,
    // and bound it with `HTTP_REQUEST_TIMEOUT`: past the deadline
    // the client gets a timeout response while the orphaned task
    // drains to completion on the blocking pool.
    let rpc2 = Arc::clone(&state.rpc);
    let work = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        rpc2.handle_raw(&body)
    });
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_ws_socket(socket, state, addr.ip()))
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
async fn handle_ws_socket(mut socket: WebSocket, state: RpcState, ip: IpAddr) {
    let conn_id = state.rpc.next_connection_id();
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
                    // Transport-independent budget: a WS frame
                    // costs the same per-IP quota as an HTTP POST,
                    // so switching transports buys a client nothing.
                    if !state.rate_limiter.allow(ip) {
                        if conn.sink.send(
                            r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"rate limit exceeded"},"id":null}"#.to_string()
                        ).is_err() {
                            break;
                        }
                        continue;
                    }
                    // Same bounded-work rule as HTTP: synchronous
                    // dispatch never runs on the async task, and
                    // the semaphore caps total in-flight work.
                    let Ok(permit) = state.work_permits.clone().try_acquire_owned() else {
                        if conn.sink.send(
                            r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"server busy — too many in-flight requests"},"id":null}"#.to_string()
                        ).is_err() {
                            break;
                        }
                        continue;
                    };
                    let rpc2 = Arc::clone(&state.rpc);
                    let conn2 = conn.clone();
                    // A panicked dispatch is a dead connection:
                    // subscriptions may be half-bound.
                    let Ok(response) = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        rpc2.handle_ws_raw(&text, &conn2)
                    }).await else { break };
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
    state.rpc.drop_connection(conn_id);
}

/// State snapshot endpoint (`GET /snapshot`).
///
/// Returns the codec-encoded `ExecutorSnapshot` as a hex string
/// (`0x`-prefixed). The caller can save the hex to a file and later
/// import it via `--import-snapshot` on a new node.
///
/// Returns 404 if no snapshot provider is attached (stateless config).
async fn snapshot_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
) -> Response<String> {
    // A full export serializes the entire state — it costs quota
    // AND a blocking-pool slot like any other expensive request.
    if !state.rate_limiter.allow(addr.ip()) {
        return rate_limited_response();
    }
    let Ok(permit) = state.work_permits.clone().try_acquire_owned() else {
        return busy_response();
    };
    match state.rpc.snapshot_provider().cloned() {
        Some(provider) => match tokio::task::spawn_blocking(move || {
            let _permit = permit;
            provider.export_snapshot()
        })
        .await
        .unwrap_or_else(|_| Err("snapshot export failed".to_string()))
        {
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
) -> Response<String> {
    if !state.rate_limiter.allow(addr.ip()) {
        return rate_limited_response();
    }
    if state.rpc.snapshot_provider().is_none() {
        return hex_response(
            Err("snapshot provider not configured".to_string()),
            StatusCode::NOT_FOUND,
        );
    }
    // The manifest re-exports the snapshot — same bounded
    // blocking-pool rule as every expensive dispatch.
    let Ok(permit) = state.work_permits.clone().try_acquire_owned() else {
        return busy_response();
    };
    let rpc2 = Arc::clone(&state.rpc);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        rpc2.snapshot_manifest()
    })
    .await
    .unwrap_or_else(|_| Err("manifest export failed".to_string()));
    hex_response(result, StatusCode::INTERNAL_SERVER_ERROR)
}

/// Sync chunk endpoint (`GET /snapshot/chunk/{index}`).
///
/// Returns the raw bytes of chunk `index` as hex — the client
/// verifies each chunk against `manifest.chunk_hashes[index]`
/// before assembling. Out-of-range indices get a 404: the client
/// should re-fetch the manifest (the cached snapshot may have been
/// replaced by a newer export).
async fn snapshot_chunk_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
    Path(index): Path<usize>,
) -> Response<String> {
    if !state.rate_limiter.allow(addr.ip()) {
        return rate_limited_response();
    }
    if state.rpc.snapshot_provider().is_none() {
        return hex_response(
            Err("snapshot provider not configured".to_string()),
            StatusCode::NOT_FOUND,
        );
    }
    // Chunk reads hit the cached export — cheap-ish but still
    // behind the same quotas so a chunk-flood loop can't bypass
    // the budget through a cheaper endpoint.
    let Ok(permit) = state.work_permits.clone().try_acquire_owned() else {
        return busy_response();
    };
    let rpc2 = Arc::clone(&state.rpc);
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        rpc2.snapshot_chunk(index)
    })
    .await
    .unwrap_or_else(|_| Err("chunk read failed".to_string()));
    hex_response(result, StatusCode::NOT_FOUND)
}

/// Validator set endpoint (`GET /validator-set`).
///
/// Returns the current validator set as JSON — a list of
/// `{address, public_key, stake}` objects. A new validator joining
/// mid-epoch queries this endpoint on an existing validator to
/// discover the current set + peer addresses, then connects via
/// `oxide-devnet` with the updated `ValidatorSet`.
///
/// Returns 404 if no validator-set provider is attached.
async fn validator_set_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
) -> Response<String> {
    if !state.rate_limiter.allow(addr.ip()) {
        return rate_limited_response();
    }
    match state.rpc.validator_set_provider() {
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

/// Health check endpoint. Returns 200 OK with "ok" while the node
/// is signing-safe; 503 once the consensus engine has latched a
/// verified execution divergence — the validator has stopped
/// signing and needs certified state repair, so load balancers and
/// watchdogs must see it as down, not merely degraded.
///
/// The body carries the quorum-certified `(height, root)` — the
/// exact `--trusted-height`/`--trusted-root` pair the repair
/// `--state-sync` requires, so the response doubles as the sync
/// trigger material.
async fn health_check(State(state): State<RpcState>) -> impl IntoResponse {
    match state.rpc.exec_divergence() {
        Some(d) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "execution divergence at height {}: local root 0x{}, certified root 0x{}; \
                 signing halted — repair via --state-sync with --trusted-height {} \
                 --trusted-root 0x{}",
                d.height.value(),
                hex_encode(d.local_root.as_bytes()),
                hex_encode(d.certified_root.as_bytes()),
                d.height.value(),
                hex_encode(d.certified_root.as_bytes()),
            ),
        ),
        None => (StatusCode::OK, "ok".to_string()),
    }
}

/// Prometheus metrics endpoint (`GET /metrics`).
///
/// Returns a Prometheus text-format exposition of node metrics:
/// `oxide_block_height`, `oxide_tx_count`, `oxide_mempool_size`, and
/// any latency histograms recorded by the attached `metrics::Recorder`.
/// The `Content-Type` is `text/plain; version=0.0.4` (the standard
/// Prometheus exposition format).
async fn metrics_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
) -> Response<String> {
    if !state.rate_limiter.allow(addr.ip()) {
        return rate_limited_response();
    }
    let body = state.rpc.metrics_text();
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
        let state = RpcState {
            rpc: Arc::new(RpcServer::new(1, 1_000_000_000)),
            rate_limiter: Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC)),
            work_permits: Arc::new(Semaphore::new(RPC_BLOCKING_PERMITS)),
        };
        let response = health_check(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// A confirmed execution divergence must flip `/health` to 503
    /// and carry the certified repair anchor — a silently degraded
    /// validator is exactly the failure mode this endpoint exists
    /// to expose.
    #[tokio::test]
    async fn health_check_reports_divergence() {
        let rpc = Arc::new(RpcServer::new(1, 1_000_000_000));
        rpc.set_exec_divergence(types::ExecDivergence {
            height: primitives::Height::new(42),
            local_root: primitives::Hash([0xAA; 32]),
            certified_root: primitives::Hash([0xBB; 32]),
        });
        let state = RpcState {
            rpc,
            rate_limiter: Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC)),
            work_permits: Arc::new(Semaphore::new(RPC_BLOCKING_PERMITS)),
        };
        let response = health_check(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("42"), "body must name the diverged height: {text}");
        assert!(
            text.contains(&"bb".repeat(32)),
            "body must carry the certified root for --trusted-root: {text}"
        );
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
        let state = RpcState {
            rpc,
            rate_limiter: Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC)),
            work_permits: Arc::new(Semaphore::new(RPC_BLOCKING_PERMITS)),
        };
        let addr: SocketAddr = "127.0.0.1:8545".parse().unwrap();
        let response = metrics_handler(ConnectInfo(addr), State(state)).await;
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

    /// Build test state with explicit limits.
    fn test_state(max_per_sec: u32, permits: usize) -> RpcState {
        RpcState {
            rpc: Arc::new(RpcServer::new(1, 1_000_000_000)),
            rate_limiter: Arc::new(RateLimiter::new(max_per_sec)),
            work_permits: Arc::new(Semaphore::new(permits)),
        }
    }

    /// Each source IP gets its own rate-limit bucket: one client
    /// exhausting its quota must not consume anyone else's — the
    /// old loopback fallback shared a single bucket across all
    /// clients, so one flooder starved the entire RPC.
    #[tokio::test]
    async fn rate_limit_applies_per_real_ip() {
        let state = test_state(2, 8);
        let a: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:40000".parse().unwrap();
        let body = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#.to_string();

        // IP A exhausts its 2-request window.
        assert_eq!(
            handle_rpc(ConnectInfo(a), State(state.clone()), body.clone()).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            handle_rpc(ConnectInfo(a), State(state.clone()), body.clone()).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            handle_rpc(ConnectInfo(a), State(state.clone()), body.clone()).await.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "IP A must hit its own bucket's limit"
        );

        // IP B is unaffected — per-source accounting, not shared.
        assert_eq!(
            handle_rpc(ConnectInfo(b), State(state), body).await.status(),
            StatusCode::OK,
            "a different IP must get an independent bucket"
        );
    }

    /// An exhausted blocking-work budget refuses new dispatches
    /// fast instead of queueing unboundedly — zero permits means
    /// every request is rejected immediately.
    #[tokio::test]
    async fn exhausted_work_budget_refuses_fast() {
        let state = test_state(1_000_000, 0);
        let a: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let body = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#.to_string();
        let response = handle_rpc(ConnectInfo(a), State(state), body).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// A fresh IP always wins its first request even when the
    /// limiter map is under pressure — and the per-IP window still
    /// governs it afterwards.
    #[tokio::test]
    async fn rate_limiter_independent_windows() {
        let limiter = RateLimiter::new(1);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(limiter.allow(ip1));
        assert!(!limiter.allow(ip1), "second in-window request denied");
        assert!(limiter.allow(ip2), "a new IP gets its own window");
        assert!(!limiter.allow(ip2));
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
