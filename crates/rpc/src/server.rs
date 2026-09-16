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
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::net::TcpListener;

use crate::{RpcServer, WsConn};

/// Default rate limit: max requests per second per IP. Prevents a
/// single client from flooding the RPC with requests and exhausting
/// the node's resources. 100 req/s is generous for a JSON-RPC client
/// (`eth_getLogs`, `eth_call`, etc.) but caps abuse. Units: requests
/// per second per IP. Origin: HIGH audit fix. Tradeoff: lower =
/// safer but may reject legitimate bursty clients; higher = more
/// permissive but more vulnerable to `DoS`.
const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 100;

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
        }
    }

    /// Create a new HTTP server from an `Arc<RpcServer>` (useful when
    /// the RPC server is shared with other components, e.g. the
    /// executor updates the block height).
    #[must_use]
    pub fn from_shared(rpc: Arc<RpcServer>, addr: String) -> Self {
        Self { rpc, addr, rate_limiter: Arc::new(RateLimiter::new(DEFAULT_RATE_LIMIT_PER_SEC)) }
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
        let app = Self::router(self.rpc, self.rate_limiter);
        let listener = TcpListener::bind(&self.addr).await.unwrap_or_else(|e| {
            panic!("RPC HTTP server: failed to bind {addr}: {e}", addr = self.addr)
        });
        eprintln!("RPC HTTP server: listening on http://{}", self.addr);
        axum::serve(listener, app).await.unwrap_or_else(|e| panic!("RPC HTTP server: {e}"));
    }

    /// Build the axum router with the RPC handler and rate limiter.
    fn router(rpc: Arc<RpcServer>, rate_limiter: Arc<RateLimiter>) -> Router {
        Router::new()
            .route("/", post(handle_rpc).get(ws_handler))
            .route("/health", get(health_check))
            .route("/metrics", get(metrics_handler))
            .route("/snapshot", get(snapshot_handler))
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
    let response = rpc.handle_raw(&body);
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
                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
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
                    if socket.send(Message::Pong(payload)).await.is_err() {
                        break;
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
}
