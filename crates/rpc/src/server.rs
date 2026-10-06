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

/// Maximum distinct source buckets tracked by the rate limiter —
/// now that buckets key on *real* connection IPs (IPv6 /64s), an
/// attacker rotating source addresses could otherwise grow the map
/// without bound (the limiter itself becoming the memory-DoS
/// vector). On overflow the limiter first evicts expired windows,
/// then the least-recently-seen bucket — an attacker can evict
/// *idle* clients but cannot lock out active ones. Units: map
/// entries. Tradeoff: 65,536 ≈ 64K buckets ≈ a few MB worst case —
/// generous for real client diversity, bounded for memory.
const MAX_RATE_BUCKETS: usize = 65_536;

/// Maximum in-flight dispatches one client may hold at once.
///
/// The global `RPC_BLOCKING_PERMITS` semaphore bounds total
/// expensive work; without a per-source cap a single client can
/// pin every permit and starve all others (the "one IP pins the
/// pool" half of the coupling finding). Units: in-flight blocking
/// tasks per source bucket. Tradeoff: 8 leaves headroom for a
/// legitimate dashboard's concurrent widgets while capping one
/// client at 1/8 of the global pool.
const RPC_MAX_INFLIGHT_PER_IP: usize = 8;

/// Rate-limit bucket key: IPv4 addresses count individually; IPv6
/// sources share their /64 prefix — the LAN segment an attacker
/// can rotate within trivially (SLAAC/DHCPv6 give a host 2^64
/// addresses), so per-address buckets there are both useless as
/// limits and a map-growth vector.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum BucketKey {
    /// A full IPv4 address.
    V4(std::net::Ipv4Addr),
    /// The first 64 bits of an IPv6 address (the /64 prefix).
    V6(u64),
}

impl From<IpAddr> for BucketKey {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                Self::V6(u64::from_be_bytes(octets[..8].try_into().unwrap_or([0; 8])))
            }
        }
    }
}

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

/// Per-request accounting state for one rate-limit bucket.
struct Bucket {
    /// Start of the current 1-second window.
    window_start: Instant,
    /// Cost units spent in the current window — requests are
    /// weighted ([`RpcServer::cost_of`]) so a 100-element batch or a
    /// `debug_trace*` call spends proportionally more budget than a
    /// cheap read.
    spent: u32,
    /// Last touch — the LRU eviction key when the map is full.
    last_seen: Instant,
}

/// A per-source fixed-window cost limiter (HIGH fix).
///
/// Tracks *cost-weighted* spend per source bucket in a `HashMap`
/// keyed by [`BucketKey`] (IPv4 address or IPv6 /64). The window
/// resets every second. This is a cold-path component (RPC, not
/// consensus), so a `Mutex<HashMap>` is acceptable — the lock is
/// held for a single `HashMap` lookup/update per request.
struct RateLimiter {
    /// Source bucket to its accounting state.
    buckets: std::sync::Mutex<HashMap<BucketKey, Bucket>>,
    /// Max cost units per second per source.
    max_per_sec: u32,
    /// Map bound — [`MAX_RATE_BUCKETS`] in production; tests lower
    /// it to exercise eviction without filling 64K entries.
    max_buckets: usize,
}

impl RateLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            buckets: std::sync::Mutex::new(HashMap::new()),
            max_per_sec,
            max_buckets: MAX_RATE_BUCKETS,
        }
    }

    /// Check if a request costing `cost` units from `ip` is allowed.
    /// Cost weighting is what makes batches and heavy methods
    /// honest: a 1000-element batch spends 1000+ units, not one.
    fn allow_cost(&self, ip: IpAddr, cost: u32) -> bool {
        let mut buckets = primitives::sync::lock_state(&self.buckets);
        let now = Instant::now();
        let key = BucketKey::from(ip);
        if let Some(bucket) = buckets.get_mut(&key) {
            bucket.last_seen = now;
            if now.duration_since(bucket.window_start) >= Duration::from_secs(1) {
                // Reset the window.
                bucket.window_start = now;
                bucket.spent = 0;
            }
            if bucket.spent.saturating_add(cost) <= self.max_per_sec {
                bucket.spent = bucket.spent.saturating_add(cost);
                return true;
            }
            return false;
        }
        // Bound the map: real per-source keys mean an attacker
        // rotating source addresses could otherwise allocate
        // without limit. Sweep expired windows first; a map still
        // at cap evicts the least-recently-seen bucket — an
        // attacker can displace idle clients but cannot refuse
        // service to active ones (the old fail-closed refusal let a
        // full table lock out every new client).
        if buckets.len() >= self.max_buckets {
            buckets.retain(|_, b| now.duration_since(b.window_start) < Duration::from_secs(1));
            if buckets.len() >= self.max_buckets
                && let Some(oldest) =
                    buckets.iter().min_by_key(|(_, b)| b.last_seen).map(|(k, _)| *k)
            {
                buckets.remove(&oldest);
            }
        }
        if cost > self.max_per_sec {
            // A single request costlier than the whole window can
            // never be served — refuse it without spending a bucket.
            return false;
        }
        buckets.insert(key, Bucket { window_start: now, spent: cost, last_seen: now });
        true
    }

    /// Single-unit admission — the common case for non-dispatch
    /// endpoints (health, manifest, cert) that cost one unit each.
    fn allow(&self, ip: IpAddr) -> bool {
        self.allow_cost(ip, 1)
    }
}

/// Per-source cap on in-flight dispatches: the per-IP half of the
/// global `work_permits` bound so one client cannot pin the whole
/// blocking pool. Counters live behind `Arc` so an evicted bucket's
/// in-flight entries still decrement correctly — the slot guard
/// outlives its map entry.
struct IpInflight {
    /// Source bucket to its live in-flight counter.
    counters: std::sync::Mutex<HashMap<BucketKey, Arc<AtomicUsize>>>,
}

/// RAII guard decrementing the source's in-flight count on drop —
/// the permit rides through `spawn_blocking` so the slot is held
/// for the dispatch's real lifetime, not the handler's.
struct IpSlot {
    /// The per-source counter this slot holds.
    counter: Arc<AtomicUsize>,
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

impl IpInflight {
    fn new() -> Self {
        Self { counters: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Try to take one in-flight slot for `ip`. `None` when the
    /// source already holds [`RPC_MAX_INFLIGHT_PER_IP`] slots.
    fn try_acquire(&self, ip: IpAddr) -> Option<IpSlot> {
        let key = BucketKey::from(ip);
        let mut counters = primitives::sync::lock_state(&self.counters);
        // Bound the counter map like the rate table: when a new
        // source would overflow it, evict entries whose count is
        // zero — idle buckets only, since a live entry's guard
        // decrements its own `Arc` even after eviction.
        if !counters.contains_key(&key) && counters.len() >= MAX_RATE_BUCKETS {
            counters.retain(|_, c| c.load(Ordering::Acquire) > 0);
            if counters.len() >= MAX_RATE_BUCKETS {
                return None;
            }
        }
        let counter = counters.entry(key).or_insert_with(|| Arc::new(AtomicUsize::new(0)));
        let mut cur = counter.load(Ordering::Acquire);
        loop {
            if cur >= RPC_MAX_INFLIGHT_PER_IP {
                return None;
            }
            match counter.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(IpSlot { counter: Arc::clone(counter) }),
                Err(next) => cur = next,
            }
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
    /// Per-source bound on in-flight dispatches — the global
    /// semaphore's companion so one client can't pin every permit.
    inflight: Arc<IpInflight>,
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
            inflight: Arc::new(IpInflight::new()),
        };
        Router::new()
            .route("/", post(handle_rpc).get(ws_handler))
            .route("/health", get(health_check))
            .route("/metrics", get(metrics_handler))
            .route("/snapshot", get(snapshot_handler))
            .route("/snapshot/manifest", get(snapshot_manifest_handler))
            .route("/snapshot/chunk/{index}", get(snapshot_chunk_handler))
            .route("/snapshot/cert/{height}", get(snapshot_cert_handler))
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
    // Parse once up front: the request's *cost* (batch size +
    // per-method weight) is what the rate limiter must charge —
    // a 1,000-element batch spending one unit was the cheap-CPU
    // bypass. A body that doesn't parse costs one unit and falls
    // through to `handle_raw`, which answers the parse error.
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
    let cost = parsed.as_ref().map_or(1, |v| state.rpc.cost_of(v));
    // Rate-limit per REAL connection source bucket — `ConnectInfo`
    // is the peer address axum accepted (IPv6 sources share their
    // /64), so one client can no longer consume the quota other
    // clients share or bypass the budget with batching.
    if !state.rate_limiter.allow_cost(addr.ip(), cost) {
        return rate_limited_response();
    }
    // Per-source in-flight cap: without it a single client can
    // pin every global permit and starve everyone else.
    let Some(ip_slot) = state.inflight.try_acquire(addr.ip()) else {
        return busy_response();
    };
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
        let _ip_slot = ip_slot;
        match &parsed {
            Ok(body) => rpc2.handle_parsed(body),
            Err(_) => rpc2.handle_raw(&body),
        }
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
                    // costs the same per-source quota as an HTTP
                    // POST — weighted by batch size and method, so
                    // switching transports or batching buys a
                    // client nothing.
                    let parsed: Result<serde_json::Value, _> =
                        serde_json::from_str(&text);
                    let cost =
                        parsed.as_ref().map_or(1, |v| state.rpc.cost_of(v));
                    if !state.rate_limiter.allow_cost(ip, cost) {
                        if conn.sink.send(
                            r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"rate limit exceeded"},"id":null}"#.to_string()
                        ).is_err() {
                            break;
                        }
                        continue;
                    }
                    // Per-source in-flight cap, same as HTTP.
                    let Some(ip_slot) = state.inflight.try_acquire(ip) else {
                        if conn.sink.send(
                            r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"server busy — too many in-flight requests"},"id":null}"#.to_string()
                        ).is_err() {
                            break;
                        }
                        continue;
                    };
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
                        let _ip_slot = ip_slot;
                        match &parsed {
                            Ok(body) => rpc2.handle_ws_parsed(body, &conn2),
                            Err(_) => rpc2.handle_ws_raw(&text, &conn2),
                        }
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
    // A full export serializes the entire state — it costs weighted
    // quota AND a blocking-pool slot like any other expensive
    // request. Weight 10 (same class as `eth_call`/log sweeps):
    // an export is O(state size), not O(request).
    if !state.rate_limiter.allow_cost(addr.ip(), 10) {
        return rate_limited_response();
    }
    let Some(ip_slot) = state.inflight.try_acquire(addr.ip()) else {
        return busy_response();
    };
    let Ok(permit) = state.work_permits.clone().try_acquire_owned() else {
        return busy_response();
    };
    match state.rpc.snapshot_provider() {
        Some(_) => match tokio::task::spawn_blocking({
            let rpc = Arc::clone(&state.rpc);
            move || {
                let _permit = permit;
                let _ip_slot = ip_slot;
                // Per-height cache: repeated `/snapshot` requests at
                // an unchanged height cost a copy, not an export.
                rpc.snapshot_blob()
            }
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

/// Execution-certificate endpoint (`GET /snapshot/cert/{height}`).
///
/// Returns the codec-encoded `types::ExecCertificate` for `height`
/// as hex — the quorum-signed `(height, state_root, epoch)` a
/// state-sync client verifies against its own validator-set
/// checkpoint before trusting a snapshot. 404 while the cert is
/// unformed or has aged out of the mirror: a syncing client pins
/// its manifest first, then polls this path until the certificate
/// for that height arrives (a live chain certifies a committed
/// height within a few views).
async fn snapshot_cert_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RpcState>,
    Path(height): Path<u64>,
) -> Response<String> {
    if !state.rate_limiter.allow(addr.ip()) {
        return rate_limited_response();
    }
    hex_response(
        state
            .rpc
            .exec_certificate(height)
            .ok_or_else(|| format!("no execution certificate for height {height}")),
        StatusCode::NOT_FOUND,
    )
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
    if let Some(d) = state.rpc.exec_divergence() {
        return (
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
        );
    }
    // Actor liveness: a dead critical actor (exec lane, accept loop,
    // consensus driver) means the node is silently degraded — the
    // process runs but does not function. 503 so watchdogs and
    // load balancers see it as down.
    let dead = primitives::supervision::unhealthy_critical();
    if !dead.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("dead critical actors: {}", dead.join(", ")),
        );
    }
    (StatusCode::OK, "ok".to_string())
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
    use crate::{EXEC_CERT_MIRROR_CAP, RpcRequest};

    /// Serializes tests that read the process-global supervision
    /// registry — a dead critical actor registered by one test would
    /// otherwise flip a concurrent `/health` assertion to 503.
    /// `tokio::sync::Mutex` because the guard is held across `.await`
    /// (the endpoint call is async).
    static HEALTH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn health_state() -> RpcState {
        RpcState {
            rpc: Arc::new(RpcServer::new(1, 1_000_000_000)),
            rate_limiter: Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC)),
            work_permits: Arc::new(Semaphore::new(RPC_BLOCKING_PERMITS)),
            inflight: Arc::new(IpInflight::new()),
        }
    }

    /// Test the health check endpoint returns 200.
    #[tokio::test]
    async fn health_check_returns_ok() {
        let _guard = HEALTH_LOCK.lock().await;
        let response = health_check(State(health_state())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// `GET /snapshot/cert/{height}` serves the mirrored
    /// certificate as codec-hex; an unformed/unknown height 404s so
    /// a syncing client can poll until it appears.
    #[tokio::test]
    async fn snapshot_cert_serves_recorded_certificate() {
        let state = test_state(1_000_000, 8);
        let addr: SocketAddr = "10.0.0.9:40000".parse().unwrap();
        let cert = types::ExecCertificate {
            height: primitives::Height::new(7),
            state_root: primitives::Hash([0xAB; 32]),
            epoch: primitives::Epoch::new(0),
            signer_bitmap: vec![0b0000_1111],
            aggregate_signature: crypto::AggregateSignature::ZERO,
        };
        state.rpc.record_exec_certificates(vec![cert.clone()]);

        let response =
            snapshot_cert_handler(ConnectInfo(addr), State(state.clone()), Path(7)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.body();
        let hex = body.trim().strip_prefix("0x").expect("hex response body");
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        let mut reader = codec::Reader::new(&bytes);
        let decoded =
            <types::ExecCertificate as codec::Decode>::decode(&mut reader).expect("decodes");
        assert_eq!(decoded, cert, "served bytes must round-trip to the mirrored cert");

        let missing = snapshot_cert_handler(ConnectInfo(addr), State(state), Path(8)).await;
        assert_eq!(
            missing.status(),
            StatusCode::NOT_FOUND,
            "a height with no formed cert must 404 so clients keep polling"
        );
    }

    /// The cert mirror is bounded: once it exceeds the cap the
    /// oldest heights are evicted (a sync client pinned a recent
    /// height, so ancient certs are dead weight), and re-recording
    /// the same height is an idempotent no-op.
    #[test]
    fn exec_cert_mirror_is_bounded_and_idempotent() {
        let rpc = RpcServer::new(1, 1_000_000_000);
        let cert = |h: u64| types::ExecCertificate {
            height: primitives::Height::new(h),
            state_root: primitives::Hash([u8::try_from(h).unwrap_or(0); 32]),
            epoch: primitives::Epoch::new(0),
            signer_bitmap: vec![0b1],
            aggregate_signature: crypto::AggregateSignature::ZERO,
        };
        rpc.record_exec_certificates((0..EXEC_CERT_MIRROR_CAP as u64 + 16).map(cert));
        assert!(
            rpc.exec_certificate(0).is_none(),
            "oldest height must be evicted once the cap overflows"
        );
        assert!(
            rpc.exec_certificate(EXEC_CERT_MIRROR_CAP as u64 + 15).is_some(),
            "newest height must be retained"
        );
        // Re-recording a held cert replaces it with identical bytes.
        let first = cert(5000);
        rpc.record_exec_certificates(vec![first.clone()]);
        assert_eq!(rpc.exec_certificate(5000), {
            let mut buf = Vec::new();
            codec::Encode::encode(&first, &mut buf);
            Some(buf)
        });
    }

    /// A dead critical actor must flip `/health` to 503 and name it —
    /// a node with a dead exec lane or accept loop looks alive on the
    /// wire but does not function. Re-registering revives the entry
    /// so the healthy 200 still holds afterwards (registry is
    /// process-global; the lock above keeps parallel tests out of the
    /// dead window).
    #[tokio::test]
    async fn health_check_reports_dead_critical_actor() {
        let _guard = HEALTH_LOCK.lock().await;
        primitives::supervision::register("hc-critical-test", true);
        primitives::supervision::mark_exited("hc-critical-test");
        let response = health_check(State(health_state())).await.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("hc-critical-test"), "body must name the dead actor: {text}");

        // Revive — the actor's re-registration is what a real respawn
        // would do, and it restores the healthy 200.
        primitives::supervision::register("hc-critical-test", true);
        let response = health_check(State(health_state())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// A confirmed execution divergence must flip `/health` to 503
    /// and carry the certified repair anchor — a silently degraded
    /// validator is exactly the failure mode this endpoint exists
    /// to expose.
    #[tokio::test]
    async fn health_check_reports_divergence() {
        let _guard = HEALTH_LOCK.lock().await;
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
            inflight: Arc::new(IpInflight::new()),
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
            inflight: Arc::new(IpInflight::new()),
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
            inflight: Arc::new(IpInflight::new()),
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

    /// Batches cost per element now: a 3-element batch spends 3
    /// units, so a budget of 2 refuses it — the "one thousand
    /// elements, one hit" bypass is closed.
    #[tokio::test]
    async fn batch_requests_charge_per_element() {
        let state = test_state(2, 8);
        let a: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let batch = r#"[
            {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
            {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2},
            {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":3}
        ]"#
        .to_string();
        let response = handle_rpc(ConnectInfo(a), State(state.clone()), batch).await;
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a 3-element batch must spend 3 units against a budget of 2"
        );
        // A 2-element batch fits the same budget.
        let pair = r#"[
            {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
            {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2}
        ]"#
        .to_string();
        let response = handle_rpc(ConnectInfo(a), State(state), pair).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Heavy methods weigh more: `eth_call` spends 10 units, so a
    /// budget of 5 refuses a single call even though it is one
    /// request — cost weighting, not request counting.
    #[tokio::test]
    async fn heavy_methods_charge_weighted_cost() {
        let state = test_state(5, 8);
        let a: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let call = r#"{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000000000","data":"0x"},"latest"],"id":1}"#
            .to_string();
        let response = handle_rpc(ConnectInfo(a), State(state), call).await;
        assert_eq!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "eth_call (weight 10) must exceed a budget of 5"
        );
    }

    /// IPv6 sources share a /64 bucket: two addresses in the same
    /// prefix spend one budget (SLAAC rotation buys nothing), while
    /// a different /64 is independent.
    #[test]
    fn rate_limiter_buckets_ipv6_by_64() {
        let limiter = RateLimiter::new(1);
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::9999".parse().unwrap();
        let other_prefix: IpAddr = "2001:db8:ffff::1".parse().unwrap();
        assert!(limiter.allow(a));
        assert!(!limiter.allow(b), "same /64 shares the bucket");
        assert!(limiter.allow(other_prefix), "a different /64 is independent");
    }

    /// A full table evicts the least-recently-seen bucket instead
    /// of refusing every new client — the attacked node degrades
    /// idle entries, never locks out.
    #[test]
    fn rate_limiter_evicts_lru_when_full() {
        let mut limiter = RateLimiter::new(1);
        limiter.max_buckets = 3;
        let stale: IpAddr = "10.0.0.9".parse().unwrap();
        let active_a: IpAddr = "10.0.0.1".parse().unwrap();
        let active_b: IpAddr = "10.0.0.2".parse().unwrap();
        let newcomer: IpAddr = "10.0.0.3".parse().unwrap();
        assert!(limiter.allow(stale));
        assert!(limiter.allow(active_a));
        assert!(limiter.allow(active_b));
        // Make `stale` the LRU entry by backdating its last_seen.
        {
            let mut buckets = primitives::sync::lock_state(&limiter.buckets);
            let b = buckets.get_mut(&BucketKey::from(stale)).unwrap();
            b.last_seen =
                Instant::now().checked_sub(Duration::from_secs(1)).unwrap_or_else(Instant::now);
        }
        // All windows are still live (spent budget intact), so the
        // expired sweep frees nothing — LRU eviction must pick
        // `stale`, and the newcomer's own budget then applies.
        assert!(limiter.allow(newcomer), "a full table evicts LRU, not the newcomer");
        assert!(!limiter.allow(newcomer), "the newcomer's budget still applies");
        {
            let buckets = primitives::sync::lock_state(&limiter.buckets);
            assert!(
                !buckets.contains_key(&BucketKey::from(stale)),
                "the least-recently-seen bucket was evicted"
            );
            assert!(buckets.contains_key(&BucketKey::from(active_a)));
            assert!(buckets.contains_key(&BucketKey::from(active_b)));
        }
    }

    /// One source may hold at most `RPC_MAX_INFLIGHT_PER_IP`
    /// in-flight dispatches; slots release on drop and other
    /// sources are unaffected.
    #[test]
    fn ip_inflight_caps_per_source() {
        let inflight = IpInflight::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let slots: Vec<IpSlot> =
            (0..RPC_MAX_INFLIGHT_PER_IP).map(|_| inflight.try_acquire(a).unwrap()).collect();
        assert!(
            inflight.try_acquire(a).is_none(),
            "the per-IP cap must refuse past {RPC_MAX_INFLIGHT_PER_IP}"
        );
        assert!(inflight.try_acquire(b).is_some(), "another source is unaffected");
        drop(slots);
        assert!(inflight.try_acquire(a).is_some(), "dropped slots release");
    }
}
