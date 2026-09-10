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
//! - `GET /health` — simple health check (returns 200 OK)
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

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use tokio::net::TcpListener;

use crate::RpcServer;

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
}

impl HttpServer {
    /// Create a new HTTP server wrapping the given RPC handler.
    ///
    /// The server will listen on `addr` when [`serve`](Self::serve) is
    /// called.
    #[must_use]
    pub fn new(rpc: RpcServer, addr: String) -> Self {
        Self { rpc: Arc::new(rpc), addr }
    }

    /// Create a new HTTP server from an `Arc<RpcServer>` (useful when
    /// the RPC server is shared with other components, e.g. the
    /// executor updates the block height).
    #[must_use]
    pub fn from_shared(rpc: Arc<RpcServer>, addr: String) -> Self {
        Self { rpc, addr }
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
        let app = Self::router(self.rpc);
        let listener = TcpListener::bind(&self.addr).await.unwrap_or_else(|e| {
            panic!("RPC HTTP server: failed to bind {addr}: {e}", addr = self.addr)
        });
        eprintln!("RPC HTTP server: listening on http://{}", self.addr);
        axum::serve(listener, app).await.unwrap_or_else(|e| panic!("RPC HTTP server: {e}"));
    }

    /// Build the axum router with the RPC handler.
    fn router(rpc: Arc<RpcServer>) -> Router {
        Router::new()
            .route("/", post(handle_rpc))
            .route("/health", get(health_check))
            .with_state(rpc)
    }
}

/// Handle a JSON-RPC POST request.
///
/// The request body is the raw JSON-RPC request string. The response
/// is the raw JSON-RPC response string from [`RpcServer::handle_raw`].
async fn handle_rpc(State(rpc): State<Arc<RpcServer>>, body: String) -> Response<String> {
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

/// Health check endpoint. Returns 200 OK with "ok".
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
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
        let _router = HttpServer::router(rpc);
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
