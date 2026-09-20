//! Network server endpoints for the off-chain matching server.
//!
//! Provides four order-entry protocols:
//! - **Binary TCP** — the fastest path (43-byte requests, 13-byte responses).
//! - **WebSocket** — JSON over WebSocket (browser-compatible).
//! - **JSON-RPC** — HTTP-compatible (`oxide_placeOrder` method).
//! - **FIX 4.4** — institutional trading desk protocol.
//!
//! All protocols feed orders to a shared `MatchingServer` via
//! `SharedMatcher`. The matching server runs on a dedicated thread;
//! protocol handlers send orders through the shared matcher and
//! return responses to clients.
//!
//! # Batch settlement
//!
//! The `BatchSettler` periodically seals the fill buffer and submits
//! a batch settlement transaction to consensus via the `TxSubmitter`
//! trait. This is the bridge between off-chain matching and on-chain
//! settlement.

use crate::protocol::{
    OrderRequest, OrderResponse, RejectReason, decode_action_request, decode_request,
    encode_response, is_action_request,
};
use crate::{MatchingServer, SharedMatcher};
use exchange::BatchFillEntry;
use futures_util::{SinkExt, StreamExt};
use primitives::fixed::{Price, Qty};
use std::sync::Arc;
use std::time::Duration;
use trading::MarketConfig;
use types::TxBytes;

/// Submit a batch of orders through the ring matcher's SPSC rings
/// (no mutex). Assigns this connection a ring index round-robin,
/// pushes the WHOLE batch as one item, and pops the batch response.
///
/// This is the lock-free submission path shared by all protocol
/// servers. Each connection must use its OWN ring index for the
/// duration of the request (the matcher thread replies to the same
/// ring the request came in on).
///
/// # Errors
///
/// Returns a vector of `EngineError` rejections (one per order) if
/// the matcher worker thread has died and the ring is disconnected.
/// This is a terminal condition — the caller should close the
/// connection.
async fn submit_batch_ring(
    ring: &crate::RingMatcher,
    ring_counter: &std::sync::atomic::AtomicUsize,
    orders: Vec<OrderRequest>,
) -> Vec<OrderResponse> {
    // Authenticate on THIS transport thread: Ed25519 verification
    // parallelizes across connections, and the ring only accepts
    // `VerifiedOrder` proof tokens (unforgeable outside
    // `VerifiedOrder::new`), so the matcher thread can never execute
    // an unauthenticated order. `positions[i]` is the original batch
    // index of verified order i; failed entries keep an aligned
    // `BadSignature` response and never touch the ring.
    let mut positions: Vec<usize> = Vec::with_capacity(orders.len());
    let mut verified: Vec<crate::protocol::VerifiedOrder> = Vec::with_capacity(orders.len());
    let mut responses: Vec<Option<OrderResponse>> = Vec::with_capacity(orders.len());
    // Verify against the ring's configured chain ID — the embedded
    // server re-checks nothing for `VerifiedOrder`, so the transport
    // MUST use the same domain or valid orders die here as
    // `BadSignature`.
    let chain_id = ring.chain_id();
    for (i, req) in orders.into_iter().enumerate() {
        match crate::protocol::VerifiedOrder::with_chain_id(req, chain_id) {
            Some(vo) => {
                positions.push(i);
                verified.push(vo);
                responses.push(None);
            }
            None => {
                responses.push(Some(OrderResponse::rejected(
                    crate::protocol::RejectReason::BadSignature,
                )));
            }
        }
    }
    if !verified.is_empty() {
        let ring_idx =
            ring_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % ring.num_rings();
        let order_sender = ring.order_sender(ring_idx).clone();
        let response_receiver = ring.response_receiver(ring_idx).clone();
        let mut pending = verified;
        let sent = loop {
            match order_sender.push(pending) {
                Ok(()) => break true,
                Err(crate::ring::PushError::Disconnected(_)) => {
                    // Worker thread died — verified slots fall through
                    // to EngineError below.
                    break false;
                }
                Err(crate::ring::PushError::Full(returned)) => {
                    pending = returned;
                    tokio::task::yield_now().await;
                }
            }
        };
        if sent {
            let worker_responses = loop {
                if let Some(r) = response_receiver.pop() {
                    break r;
                }
                tokio::task::yield_now().await;
            };
            for (pos, resp) in positions.into_iter().zip(worker_responses) {
                responses[pos] = Some(resp);
            }
        }
    }
    // Every slot is Some: verified entries got worker responses,
    // unverified got BadSignature, dead-worker entries get
    // EngineError — all at their original batch positions.
    responses
        .into_iter()
        .map(|r| {
            r.unwrap_or_else(|| OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
        })
        .collect()
}

/// The chain ID the target matcher verifies signatures against —
/// ring mode reads it off the `RingMatcher`, mutex mode off the
/// `SharedMatcher`. Early transport verifies MUST use the same
/// domain as the mandatory in-server re-verify.
fn transport_chain_id(
    matcher: &SharedMatcher,
    ring_matcher: Option<&Arc<crate::RingMatcher>>,
) -> u64 {
    ring_matcher.map_or_else(|| matcher.chain_id(), |rm| rm.chain_id())
}

/// Submit a single order through the ring matcher (batch of one).
async fn submit_one_ring(
    ring: &crate::RingMatcher,
    ring_counter: &std::sync::atomic::AtomicUsize,
    req: OrderRequest,
) -> OrderResponse {
    let mut responses = submit_batch_ring(ring, ring_counter, vec![req]).await;
    responses.pop().unwrap_or(OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
}

/// Submit an order action (cancel/amend/replace) through the ring
/// matcher's control channel. Actions are less frequent than new
/// orders, so the control-channel path (serviced between ring polls)
/// is the right seam — it reaches THE SAME order book the rings
/// write to, with no second book.
fn submit_action_ring(
    ring: &crate::RingMatcher,
    req: crate::protocol::ActionRequest,
) -> OrderResponse {
    // The control channel is synchronous (std::sync::mpsc); the
    // matcher thread services it between ring polls. We send and
    // recv — the recv blocks the tokio task, but actions are rare
    // (cancel/amend/replace), so this is acceptable. For a hot-path
    // action stream, a dedicated ring would be added.
    //
    // The wire `ActionRequest` crosses the channel intact — the
    // matching server authenticates it (signature + owner binding +
    // nonce) inside `submit_action` before dispatching.
    ring.submit_action(req)
}

// ── TxSubmitter trait ────────────────────────────────────────────────

/// A handle that submits transactions to the consensus mempool.
/// Mirrors `rpc::TxSubmitter` but lives in the matcher crate to
/// avoid a circular dependency.
pub trait TxSubmitter: Send + Sync {
    /// Submit a wrapped Oxide transaction envelope to the mempool.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` if the mempool rejects the transaction.
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String>;
}

// ── BatchSettler ─────────────────────────────────────────────────────

/// The batch settler: periodically seals the fill buffer and submits
/// a batch settlement transaction to consensus.
///
/// Runs on a dedicated tokio task. Every `interval` milliseconds,
/// it seals the current batch from the matching server, encodes it
/// as a `TAG_BATCH_SETTLE` message, wraps it in an Oxide transaction
/// envelope, and submits it via `TxSubmitter`.
pub struct BatchSettler {
    /// The batch sealer — either the mutex path (`SharedMatcher`) or
    /// the ring owner thread (`RingMatcher`). Both seal from THE ONE
    /// order book.
    sealer: Arc<dyn crate::BatchSealer>,
    submitter: Arc<dyn TxSubmitter>,
    interval: Duration,
    /// The sender address for settlement txs (the matcher operator).
    sender: primitives::Address,
    /// Next settlement nonce — advanced ONLY on a successful submit,
    /// never at encode time. A failed submission keeps its nonce so
    /// the retried envelope (and the next batch) stay contiguous
    /// with the executor's `executed_nonce` counter; a burned nonce
    /// would gap the sequence and nonce-skip every later settlement
    /// from this sender forever.
    nonce: std::sync::atomic::AtomicU64,
    /// The encoded envelope whose last submit failed, awaiting
    /// retry. Sealing pauses while a batch is pending — fills keep
    /// accumulating in the sealer's buffer (nothing is lost), and
    /// the same envelope is resubmitted verbatim because the
    /// executor still expects exactly that nonce next.
    pending: std::sync::Mutex<Option<PendingBatch>>,
}

/// A settlement envelope whose submission is being retried.
struct PendingBatch {
    /// The full encoded tx envelope (nonce baked in).
    envelope: Vec<u8>,
    /// Aggregated pair count (returned when the retry lands).
    pair_count: usize,
    /// Failed submission attempts so far.
    attempts: u32,
}

/// Maximum retries before a pending batch is dropped: 60.
///
/// At the default 100 ms settle interval this is ~6 seconds of
/// retry — long enough to ride out a transient mempool-full or a
/// consensus reconnect, short enough that a permanently-rejected
/// envelope doesn't wedge the settlement lane forever. After this
/// many retries, the settler logs a critical alert but does NOT
/// drop the pending envelope — dropping would cause cache/chain
/// divergence (the off-chain cache already reflects the fills from
/// `seal_batch`, but the on-chain settlement never landed). Instead,
/// the envelope stays pending so the operator can intervene and the
/// settlement can eventually land when the chain recovers.
const MAX_PENDING_RETRIES: u32 = 60;

impl BatchSettler {
    /// Create a new batch settler.
    ///
    /// # Arguments
    /// - `sealer`: the batch sealer (`SharedMatcher` or `RingMatcher` —
    ///   both seal from the single order book).
    /// - `submitter`: the consensus tx submitter.
    /// - `interval_ms`: how often to seal and submit batches.
    /// - `sender`: the matcher operator's address (for tx envelope).
    /// - `start_nonce`: the initial nonce for settlement txs.
    #[must_use]
    pub fn new(
        sealer: Arc<dyn crate::BatchSealer>,
        submitter: Arc<dyn TxSubmitter>,
        interval_ms: u64,
        sender: primitives::Address,
        start_nonce: u64,
    ) -> Self {
        Self {
            sealer,
            submitter,
            interval: Duration::from_millis(interval_ms),
            sender,
            nonce: std::sync::atomic::AtomicU64::new(start_nonce),
            pending: std::sync::Mutex::new(None),
        }
    }

    /// Seal the current batch and submit it to consensus. Returns
    /// the number of fills settled.
    ///
    /// Aggregates fills by (buyer, seller) pair before encoding —
    /// multiple fills between the same pair are combined into one
    /// net transfer. This reduces the number of ledger operations from
    /// `fill_count` to `unique_pair_count` (typically 2-5x fewer).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the settlement tx is rejected by the mempool.
    ///
    /// # Panics
    ///
    /// Panics if the underlying sealer's mutex/control channel is
    /// poisoned or disconnected.
    pub fn settle_now(&self) -> Result<usize, String> {
        // Retry a pending envelope before sealing anything new.
        // Previously a failed submit dropped the sealed fills AND
        // burned the nonce — the next batch carried nonce N+1 while
        // the executor still expected N, so every later settlement
        // was nonce-skipped forever. Now the same envelope is
        // resubmitted verbatim and the nonce advances only on
        // success.
        {
            let mut pending =
                self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(p) = pending.as_mut() {
                return match self.submitter.submit_tx(TxBytes::new(p.envelope.clone())) {
                    Ok(()) => {
                        self.nonce.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let settled = p.pair_count;
                        *pending = None;
                        Ok(settled)
                    }
                    Err(e) => {
                        p.attempts += 1;
                        if p.attempts >= MAX_PENDING_RETRIES {
                            // HIGH fix: do NOT drop the pending
                            // envelope. The fills were already removed
                            // from the order book by `seal_batch` and
                            // the off-chain cache reflects the trades.
                            // Dropping the envelope would leave the
                            // cache applied without on-chain settlement,
                            // causing cache/chain divergence. Instead,
                            // log a critical alert and keep the
                            // envelope pending so the operator can
                            // intervene and the settlement can land
                            // when the chain recovers.
                            eprintln!(
                                "batch settler: CRITICAL — batch of {} pairs failed {} submissions, keeping pending: {e}",
                                p.pair_count, p.attempts
                            );
                        }
                        Err(e)
                    }
                };
            }
        }

        // Seal the batch from the single order book.
        let fills = self.sealer.seal_batch();

        if fills.is_empty() {
            return Ok(0);
        }

        // Aggregate fills by (market, price, buyer, seller): legs at
        // the same price between the same pair merge into one entry.
        // The wire carries no claimed settlement amount — the chain
        // recomputes `price * qty / PRICE_SCALE` per leg — so
        // aggregation must not sum the off-chain `quote_amount`
        // (floor-division dust would make the sums diverge).
        //
        // BTreeMap keeps the encoded entry order deterministic and
        // reproducible for a given fill sequence.
        let mut aggregated: std::collections::BTreeMap<
            (u16, Price, primitives::Address, primitives::Address),
            Qty,
        > = std::collections::BTreeMap::new();
        for f in &fills {
            let key = (f.market, f.price, f.buyer, f.seller);
            match aggregated.get_mut(&key) {
                Some(q) => {
                    // A qty sum above u64::MAX is unreachable in
                    // practice (would require ~1.8e13 lots traded in
                    // one batch); fail loudly rather than saturate.
                    *q = Qty(q
                        .0
                        .checked_add(f.qty.0)
                        .ok_or_else(|| "fill qty aggregation overflow".to_string())?);
                }
                None => {
                    aggregated.insert(key, f.qty);
                }
            }
        }
        let entries: Vec<BatchFillEntry> = aggregated
            .into_iter()
            .map(|((market, price, buyer, seller), qty)| BatchFillEntry {
                market,
                price,
                qty,
                buyer,
                seller,
            })
            .collect();
        let pair_count = entries.len();

        // Encode as a batch-settle message.
        let module_payload = exchange::msg::batch_settle(&entries);

        // Wrap in an Oxide transaction envelope. The nonce is READ
        // here, not consumed — it advances only when the submit
        // succeeds, so a failed submission leaves the sequence
        // contiguous for the retry (and for the next batch if this
        // envelope is eventually dropped).
        let nonce = self.nonce.load(std::sync::atomic::Ordering::Relaxed);
        let fee = 100u64;
        let mut envelope = Vec::with_capacity(36 + module_payload.len());
        envelope.extend_from_slice(&self.sender.0);
        envelope.extend_from_slice(&nonce.to_le_bytes());
        envelope.extend_from_slice(&fee.to_le_bytes());
        envelope.push(framework::module_id::EXCHANGE);
        envelope.extend_from_slice(&module_payload);

        // Submit to consensus. On failure the envelope is kept for
        // retry — the fills are NOT lost (they were drained from the
        // sealer but live on in `pending`).
        match self.submitter.submit_tx(TxBytes::new(envelope.clone())) {
            Ok(()) => {
                self.nonce.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(pair_count)
            }
            Err(e) => {
                *self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(PendingBatch { envelope, pair_count, attempts: 1 });
                Err(e)
            }
        }
    }

    /// Run the batch settler loop. Seals and submits batches every
    /// `interval` until the matcher is dropped or the task is
    /// cancelled.
    pub async fn run(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.settle_now() {
                eprintln!("batch settler: submission failed: {e}");
            }
        }
    }
}

// ── Binary TCP server ────────────────────────────────────────────────

/// Run a binary TCP order-entry server on the given port.
///
/// Accepts connections, reads 43-byte binary order requests, feeds
/// them to the shared matcher, and writes 13-byte responses. Each
/// connection is handled on its own tokio task. Also supports batch
/// requests (multiple orders in a single message) via the batch flag.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
///
/// # Panics
///
/// Panics if the inner matching server mutex is poisoned during
/// batch order processing.
pub async fn run_binary_tcp_server(matcher: Arc<SharedMatcher>, port: u16) -> std::io::Result<()> {
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run_binary_tcp_server_impl(matcher, port, None, ring_counter).await
}

/// Run a binary TCP order-entry server on the given port, using the
/// lock-free SPSC ring matcher instead of the mutex.
///
/// The `ring_matcher` is wrapped in `Arc<Mutex<Option<_>>>` so it can
/// be shared with the batch settler (which needs `seal_batch` via the
/// mutex path). Each connection is assigned a ring index; orders go
/// through the SPSC ring (no locks) and responses come back through
/// the per-connection response ring.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
///
/// # Panics
///
/// Panics if the inner matching server mutex is poisoned during
/// batch order processing.
pub async fn run_binary_tcp_server_ring(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Arc<crate::RingMatcher>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    run_binary_tcp_server_impl(matcher, port, Some(ring_matcher), ring_counter).await
}

/// Shared implementation for both TCP server variants. When
/// `ring_matcher` is `Some`, orders are routed through the SPSC
/// rings; otherwise they go through the mutex path.
async fn run_binary_tcp_server_impl(
    matcher: Arc<SharedMatcher>,
    port: u16,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("binary TCP server listening on 127.0.0.1:{port}");

    loop {
        let (socket, _addr) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        let ring_matcher = ring_matcher.clone();
        let ring_counter = Arc::clone(&ring_counter);
        tokio::spawn(handle_connection(socket, matcher, ring_matcher, ring_counter));
    }
}

/// Handle a single TCP connection: read requests (single or batch),
/// submit to the matching server (mutex or SPSC ring path), and
/// write responses. Runs until the client disconnects.
#[allow(clippy::too_many_lines)]
async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    matcher: Arc<SharedMatcher>,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Read the first 4 bytes to check if it's a batch or single request.
    let mut header = [0u8; 4];
    loop {
        if socket.read_exact(&mut header).await.is_err() {
            break;
        }
        // Check for batch flag (byte 3 = 0xFF).
        if header[3] == crate::protocol::BATCH_FLAG {
            // Batch request: read the rest of the header (count:4)
            // and then count × 40-byte entries.
            let mut count_buf = [0u8; 4];
            if socket.read_exact(&mut count_buf).await.is_err() {
                break;
            }
            let count = u32::from_le_bytes(count_buf) as usize;
            // HIGH fix: bound-check `count` BEFORE allocating. A
            // byzantine peer can send `u32::MAX` as the count, which
            // would cause a multi-GB allocation (OOM). The MAX_BATCH_SIZE
            // check in the protocol decoder runs after allocation;
            // we must check here first.
            if count > crate::protocol::MAX_BATCH_SIZE {
                break; // reject oversized batch
            }
            let entries_len = count * crate::protocol::BATCH_ENTRY_SIZE;
            let mut entries = vec![0u8; entries_len];
            if socket.read_exact(&mut entries).await.is_err() {
                break;
            }
            // Reconstruct the full batch message for decoding.
            let mut full_msg = Vec::with_capacity(8 + entries_len);
            full_msg.extend_from_slice(&header);
            full_msg.extend_from_slice(&count_buf);
            full_msg.extend_from_slice(&entries);
            // Decode the batch.
            let Some(orders) = crate::protocol::decode_batch_request(&full_msg) else {
                let resp = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&resp)).await;
                continue;
            };
            // Submit the whole batch. The ring path authenticates
            // each order on this thread and pushes only
            // `VerifiedOrder` proofs; the mutex path authenticates
            // inside `submit_order`. Both produce one response per
            // request — failed authentication yields an aligned
            // `BadSignature` in place, never a dropped or reordered
            // response.
            let responses: Vec<OrderResponse> = if let Some(rm) = &ring_matcher {
                submit_batch_ring(rm, &ring_counter, orders).await
            } else {
                match matcher.inner.lock() {
                    Ok(mut server) => orders.iter().map(|req| server.submit_order(req)).collect(),
                    Err(_) => orders
                        .iter()
                        .map(|_| {
                            OrderResponse::rejected(crate::protocol::RejectReason::EngineError)
                        })
                        .collect(),
                }
            };
            // Encode and send the batch response.
            let batch_resp = crate::protocol::encode_batch_response(&responses);
            if socket.write_all(&batch_resp).await.is_err() {
                break;
            }
        } else if is_action_request(&header) {
            // Action request (cancel/amend/replace): the market byte
            // is ACTION_FLAG (0xFE). Read the remaining
            // ACTION_REQUEST_SIZE - 4 bytes and decode.
            let mut rest = [0u8; crate::protocol::ACTION_REQUEST_SIZE - 4];
            if socket.read_exact(&mut rest).await.is_err() {
                break;
            }
            let mut full = Vec::with_capacity(crate::protocol::ACTION_REQUEST_SIZE);
            full.extend_from_slice(&header);
            full.extend_from_slice(&rest);
            let Some(action_req) = decode_action_request(&full) else {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            };
            // Signature verification before processing — with the
            // SAME chain ID the matcher will re-verify against.
            let action_chain_id =
                ring_matcher.as_ref().map_or_else(|| matcher.chain_id(), |rm| rm.chain_id());
            if !crate::protocol::verify_action_with_chain_id(&action_req, action_chain_id) {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::BadSignature);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            }
            // The wire `ActionRequest` is submitted intact — the
            // matching server re-authenticates it (signature + owner
            // binding + nonce) as the mandatory boundary before
            // dispatching. The verify above is only an early reject.
            let action_resp = if let Some(rm) = &ring_matcher {
                submit_action_ring(rm, action_req)
            } else {
                matcher.submit_action(&action_req)
            };
            if socket.write_all(&encode_response(&action_resp)).await.is_err() {
                break;
            }
        } else {
            // Single request: read the remaining 39 bytes
            // (we already have the first 4).
            let mut rest = [0u8; crate::protocol::REQUEST_SIZE - 4];
            if socket.read_exact(&mut rest).await.is_err() {
                break;
            }
            let mut full = Vec::with_capacity(crate::protocol::REQUEST_SIZE);
            full.extend_from_slice(&header);
            full.extend_from_slice(&rest);
            // Decode the order.
            let Some(req) = decode_request(&full) else {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            };
            // Submit to the matching server — through the
            // SPSC ring if available, otherwise the mutex.
            let order_resp = if let Some(rm) = &ring_matcher {
                submit_one_ring(rm, &ring_counter, req).await
            } else {
                matcher.submit(&req)
            };
            // Write the response.
            if socket.write_all(&encode_response(&order_resp)).await.is_err() {
                break;
            }
        }
    }
}

// ── JSON-RPC over TCP server (simplified, no HTTP) ───────────────────

/// Run a JSON-RPC order-entry server on the given port (TCP, line-
/// delimited JSON). This is a simplified version that doesn't require
/// axum/hyper — each line is a JSON-RPC request, each response is a
/// JSON line.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
/// Run a JSON-RPC order-entry server on the given port (TCP, line-
/// delimited JSON) — mutex path.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_jsonrpc_tcp_server(matcher: Arc<SharedMatcher>, port: u16) -> std::io::Result<()> {
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run_jsonrpc_tcp_server_impl(matcher, None, ring_counter, port).await
}

/// Run a JSON-RPC order-entry server on the given port, routing
/// orders through the lock-free SPSC ring matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_jsonrpc_tcp_server_ring(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Arc<crate::RingMatcher>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    run_jsonrpc_tcp_server_impl(matcher, Some(ring_matcher), ring_counter, port).await
}

/// Shared implementation for the JSON-RPC server. When
/// `ring_matcher` is `Some`, orders route through the SPSC rings.
async fn run_jsonrpc_tcp_server_impl(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("JSON-RPC server listening on 127.0.0.1:{port}");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        let ring_matcher = ring_matcher.clone();
        let ring_counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = socket.split();
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // Parse the JSON-RPC request.
                let req: serde_json::Value = if let Ok(v) = serde_json::from_str(&line) {
                    v
                } else {
                    let _ = writer
                        .write_all(
                            br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}
"#,
                        )
                        .await;
                    continue;
                };
                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let params = req.get("params").cloned().unwrap_or(serde_json::Value::Null);

                if method == crate::jsonrpc::MANAGE_ORDER {
                    // Order action (cancel/amend/replace).
                    let Some(action_req) = crate::jsonrpc::parse_jsonrpc_action(&params) else {
                        let _ = writer
                            .write_all(
                                br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":null}
"#,
                            )
                            .await;
                        continue;
                    };
                    let action_chain_id = transport_chain_id(&matcher, ring_matcher.as_ref());
                    if !crate::protocol::verify_action_with_chain_id(&action_req, action_chain_id) {
                        let _ = writer
                            .write_all(
                                br#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"bad signature"},"id":null}
"#,
                            )
                            .await;
                        continue;
                    }
                    // Submit the wire `ActionRequest` intact — the
                    // core re-authenticates before dispatch.
                    let resp = if let Some(rm) = &ring_matcher {
                        submit_action_ring(rm, action_req)
                    } else {
                        matcher.submit_action(&action_req)
                    };
                    let result = crate::jsonrpc::format_jsonrpc_response(&resp);
                    let response = serde_json::json!({
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": id,
                    });
                    let mut response_line = serde_json::to_string(&response).unwrap_or_default();
                    response_line.push('\n');
                    let _ = writer.write_all(response_line.as_bytes()).await;
                    continue;
                }

                if method != "oxide_placeOrder" {
                    let _ = writer
                        .write_all(
                            br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":null}
"#,
                        )
                        .await;
                    continue;
                }
                // Parse the order.
                let Some(order_req) = crate::jsonrpc::parse_jsonrpc_order(&params) else {
                    let _ = writer
                        .write_all(
                            br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":null}
"#,
                        )
                        .await;
                    continue;
                };
                // Submit to the matching server — through the SPSC
                // ring if available, otherwise the mutex.
                let resp = if let Some(rm) = &ring_matcher {
                    submit_one_ring(rm, &ring_counter, order_req).await
                } else {
                    matcher.submit(&order_req)
                };
                // Format the response.
                let result = crate::jsonrpc::format_jsonrpc_response(&resp);
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": result,
                    "id": id,
                });
                let mut response_line = serde_json::to_string(&response).unwrap_or_default();
                response_line.push('\n');
                let _ = writer.write_all(response_line.as_bytes()).await;
            }
        });
    }
}

// ── FIX server (simplified) ──────────────────────────────────────────

/// Run a FIX order-entry server on the given port. Accepts FIX
/// `NewOrderSingle` (MsgType=D) messages, feeds them to the shared
/// matcher, and returns `ExecutionReport` (MsgType=8) responses.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
/// Run a FIX order-entry server on the given port (mutex path).
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_fix_server(matcher: Arc<SharedMatcher>, port: u16) -> std::io::Result<()> {
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run_fix_server_impl(matcher, None, ring_counter, port).await
}

/// Run a FIX order-entry server on the given port, routing orders
/// through the lock-free SPSC ring matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_fix_server_ring(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Arc<crate::RingMatcher>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    run_fix_server_impl(matcher, Some(ring_matcher), ring_counter, port).await
}

/// Shared implementation for the FIX server.
async fn run_fix_server_impl(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("FIX server listening on 127.0.0.1:{port}");

    loop {
        let (mut socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        let ring_matcher = ring_matcher.clone();
        let ring_counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break, // EOF or error.
                    Ok(n) => n,
                };
                // FIX messages are SOH-delimited. Find complete
                // messages and process them.
                let data = &buf[..n];
                // Split on SOH (0x01) to find the message boundary.
                // A complete FIX message ends with a SOH after the
                // last tag. We look for the CheckSum tag (10=) as
                // the message terminator.
                let text = String::from_utf8_lossy(data);
                // Find the ClOrdID for the response.
                let cl_ord_id = text
                    .split('\x01')
                    .find_map(|f| f.strip_prefix("11=").map(str::to_string))
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                // Determine the FIX MsgType (tag 35) to dispatch.
                let msg_type = text
                    .split('\x01')
                    .find_map(|f| f.strip_prefix("35=").map(str::to_string))
                    .unwrap_or_default();

                if msg_type == crate::fix::MSG_TYPE_CANCEL
                    || msg_type == crate::fix::MSG_TYPE_CANCEL_REPLACE
                {
                    // Order cancel (F) or cancel-replace (G).
                    let action_req = if msg_type == crate::fix::MSG_TYPE_CANCEL {
                        crate::fix::parse_fix_cancel(&text)
                    } else {
                        crate::fix::parse_fix_cancel_replace(&text)
                    };
                    let Some(action_req) = action_req else {
                        // Malformed action — answer with a rejected
                        // ExecutionReport instead of dropping the
                        // message: a client blocking on a response
                        // per message must never be wedged by a
                        // parse failure.
                        let resp = OrderResponse::rejected(RejectReason::Malformed);
                        let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                        let _ = socket.write_all(report.as_bytes()).await;
                        continue;
                    };
                    let action_chain_id = transport_chain_id(&matcher, ring_matcher.as_ref());
                    if !crate::protocol::verify_action_with_chain_id(&action_req, action_chain_id) {
                        let resp = OrderResponse::rejected(RejectReason::BadSignature);
                        let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                        let _ = socket.write_all(report.as_bytes()).await;
                        continue;
                    }
                    // Submit the wire `ActionRequest` intact — the
                    // core re-authenticates before dispatch.
                    let resp = if let Some(rm) = &ring_matcher {
                        submit_action_ring(rm, action_req)
                    } else {
                        matcher.submit_action(&action_req)
                    };
                    let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                    let _ = socket.write_all(report.as_bytes()).await;
                    continue;
                }

                // Default: parse as NewOrderSingle (D).
                let Some(req) = crate::fix::parse_fix_order(&text) else {
                    // Malformed order — answer with a rejected
                    // ExecutionReport instead of dropping the
                    // message: a client blocking on a response per
                    // message must never be wedged by a parse
                    // failure.
                    let resp = OrderResponse::rejected(RejectReason::Malformed);
                    let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                    let _ = socket.write_all(report.as_bytes()).await;
                    continue;
                };
                // Submit to the matching server — through the SPSC
                // ring if available, otherwise the mutex.
                let resp = if let Some(rm) = &ring_matcher {
                    submit_one_ring(rm, &ring_counter, req).await
                } else {
                    matcher.submit(&req)
                };
                // Format the FIX ExecutionReport.
                let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                let _ = socket.write_all(report.as_bytes()).await;
            }
        });
    }
}

// ── WebSocket server ─────────────────────────────────────────────────

/// Run a WebSocket order-entry server on the given port. Accepts
/// WebSocket connections, receives JSON order messages, feeds them
/// to the shared matcher, and sends JSON responses back.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
/// Run a WebSocket order-entry server on the given port (mutex path).
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_websocket_server(matcher: Arc<SharedMatcher>, port: u16) -> std::io::Result<()> {
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    run_websocket_server_impl(matcher, None, ring_counter, port).await
}

/// Run a WebSocket order-entry server on the given port, routing
/// orders through the lock-free SPSC ring matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_websocket_server_ring(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Arc<crate::RingMatcher>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    run_websocket_server_impl(matcher, Some(ring_matcher), ring_counter, port).await
}

/// Shared implementation for the WebSocket server.
async fn run_websocket_server_impl(
    matcher: Arc<SharedMatcher>,
    ring_matcher: Option<Arc<crate::RingMatcher>>,
    ring_counter: Arc<std::sync::atomic::AtomicUsize>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("WebSocket server listening on 127.0.0.1:{port}");

    loop {
        let (socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        let ring_matcher = ring_matcher.clone();
        let ring_counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            use tokio_tungstenite::tungstenite::Message;
            let ws_stream = match tokio_tungstenite::accept_async(socket).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("WebSocket handshake failed: {e}");
                    return;
                }
            };
            let (mut ws_sender, mut ws_receiver) = ws_stream.split();

            while let Some(msg_result) = ws_receiver.next().await {
                let Ok(msg) = msg_result else { break };
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                    Message::Close(_) => break,
                    _ => continue,
                };

                // Check if this is an action request (has "action" field)
                // or a new order request.
                if text.contains("\"action\"") {
                    // Parse as an order action (cancel/amend/replace).
                    let Some(action_req) = crate::ws::parse_ws_action(&text) else {
                        let _ = ws_sender
                            .send(Message::Text(r#"{"error":"invalid action"}"#.into()))
                            .await;
                        continue;
                    };
                    let action_chain_id = transport_chain_id(&matcher, ring_matcher.as_ref());
                    if !crate::protocol::verify_action_with_chain_id(&action_req, action_chain_id) {
                        let resp = OrderResponse::rejected(RejectReason::BadSignature);
                        let response = crate::ws::format_ws_response(&resp, 0);
                        let _ = ws_sender.send(Message::Text(response.into())).await;
                        continue;
                    }
                    // Submit the wire `ActionRequest` intact — the
                    // core re-authenticates before dispatch.
                    let resp = if let Some(rm) = &ring_matcher {
                        submit_action_ring(rm, action_req)
                    } else {
                        matcher.submit_action(&action_req)
                    };
                    let response = crate::ws::format_ws_response(&resp, 0);
                    if ws_sender.send(Message::Text(response.into())).await.is_err() {
                        break;
                    }
                    continue;
                }

                // Parse the WebSocket order.
                let Some(req) = crate::ws::parse_ws_order(&text) else {
                    let _ =
                        ws_sender.send(Message::Text(r#"{"error":"invalid order"}"#.into())).await;
                    continue;
                };
                // Submit to the matching server — through the SPSC
                // ring if available, otherwise the mutex.
                let resp = if let Some(rm) = &ring_matcher {
                    submit_one_ring(rm, &ring_counter, req).await
                } else {
                    matcher.submit(&req)
                };
                // Format the WebSocket response.
                let response = crate::ws::format_ws_response(&resp, 0);
                if ws_sender.send(Message::Text(response.into())).await.is_err() {
                    break;
                }
            }
        });
    }
}

// ── Multi-protocol server ────────────────────────────────────────────

/// Configuration for the multi-protocol matching server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Port for the binary TCP server.
    pub binary_tcp_port: u16,
    /// Port for the JSON-RPC server.
    pub jsonrpc_port: u16,
    /// Port for the FIX server.
    pub fix_port: u16,
    /// Port for the WebSocket server.
    pub websocket_port: u16,
    /// Batch settlement interval in milliseconds.
    pub batch_interval_ms: u64,
    /// The chain ID order/action signatures are verified against.
    /// Used only where this module constructs the matcher itself
    /// (`run_server_multi`) — otherwise the chain ID lives on the
    /// matcher object the caller built (`MatchingServer::set_chain_id`).
    /// Defaults to the devnet [`crate::protocol::CHAIN_ID`]; set it
    /// to the deployment's real chain ID.
    pub chain_id: u64,
    /// Durable checkpoint file for consumed nonces — bounds the
    /// restart replay window to the flush interval instead of
    /// "any captured request replays once after every restart".
    /// Same scope note as `chain_id`: used where this module builds
    /// the matcher (`run_server_multi`); `None` = memory-only gate.
    pub nonce_state_path: Option<std::path::PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            binary_tcp_port: 36000,
            jsonrpc_port: 36001,
            fix_port: 36002,
            websocket_port: 36003,
            batch_interval_ms: 100,
            chain_id: crate::protocol::CHAIN_ID,
            nonce_state_path: None,
        }
    }
}

/// Default number of ring pairs for the ring-backed server.
const DEFAULT_RING_COUNT: usize = 256;

/// Default ring capacity (items per ring; each item is one batch).
const DEFAULT_RING_CAPACITY: usize = 8192;

/// Run all protocol servers concurrently (mutex path). This is the
/// compatibility entry point — for new deployments use
/// [`run_server_ring`], which routes ALL protocols through the
/// lock-free SPSC rings while sharing THE SAME single order book.
///
/// # Arguments
/// - `matcher`: the shared matching server.
/// - `submitter`: the consensus tx submitter (for batch settlement).
/// - `config`: server configuration (ports, batch interval).
/// - `sender`: the matcher operator's address (for settlement txs).
pub async fn run_server(
    matcher: Arc<SharedMatcher>,
    submitter: Arc<dyn TxSubmitter>,
    config: ServerConfig,
    sender: primitives::Address,
) {
    // Start the batch settler. `Arc<SharedMatcher>` coerces to
    // `Arc<dyn BatchSealer>` (the mutex-seal implementation).
    let sealer: Arc<dyn crate::BatchSealer> = Arc::clone(&matcher) as Arc<dyn crate::BatchSealer>;
    let settler = Arc::new(BatchSettler::new(
        sealer,
        Arc::clone(&submitter),
        config.batch_interval_ms,
        sender,
        0,
    ));
    let settler_clone = Arc::clone(&settler);
    tokio::spawn(async move {
        settler_clone.run().await;
    });

    // Start the protocol servers.
    let tcp_matcher = Arc::clone(&matcher);
    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = run_binary_tcp_server(tcp_matcher, config.binary_tcp_port).await {
            eprintln!("binary TCP server error: {e}");
        }
    });

    let jsonrpc_matcher = Arc::clone(&matcher);
    let jsonrpc_handle = tokio::spawn(async move {
        if let Err(e) = run_jsonrpc_tcp_server(jsonrpc_matcher, config.jsonrpc_port).await {
            eprintln!("JSON-RPC server error: {e}");
        }
    });

    let fix_matcher = Arc::clone(&matcher);
    let fix_handle = tokio::spawn(async move {
        if let Err(e) = run_fix_server(fix_matcher, config.fix_port).await {
            eprintln!("FIX server error: {e}");
        }
    });

    let ws_matcher = Arc::clone(&matcher);
    let ws_handle = tokio::spawn(async move {
        if let Err(e) = run_websocket_server(ws_matcher, config.websocket_port).await {
            eprintln!("WebSocket server error: {e}");
        }
    });

    // Wait for all servers (they run forever).
    let _ = tokio::join!(tcp_handle, jsonrpc_handle, fix_handle, ws_handle);
}

/// Run all protocol servers concurrently with the lock-free SPSC
/// ring matcher as the production order path. This is the
/// recommended entry point.
///
/// # One order book
///
/// The `server` passed in is moved to the ring matcher's owner
/// thread — it is THE single order book. ALL protocols (binary TCP,
/// JSON-RPC, FIX, WebSocket) submit through the rings to this one
/// book, and the batch settler seals from the same book via the
/// control channel. There is never a second book.
///
/// # Arguments
/// - `server`: the funded matching server (moved to the owner thread).
/// - `submitter`: the consensus tx submitter (for batch settlement).
/// - `config`: server configuration (ports, batch interval).
/// - `sender`: the matcher operator's address (for settlement txs).
pub async fn run_server_ring(
    server: MatchingServer,
    submitter: Arc<dyn TxSubmitter>,
    config: ServerConfig,
    sender: primitives::Address,
) {
    // The ring matcher owns the server (and thus the one book).
    let ring = Arc::new(crate::RingMatcher::new(server, DEFAULT_RING_COUNT, DEFAULT_RING_CAPACITY));
    // Shared ring-index counter: every connection across ALL
    // protocols gets a unique ring pair, so responses never
    // interleave between connections.
    let ring_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Batch settler seals from the same book via the control channel.
    let sealer: Arc<dyn crate::BatchSealer> = Arc::clone(&ring) as Arc<dyn crate::BatchSealer>;
    let settler = Arc::new(BatchSettler::new(
        sealer,
        Arc::clone(&submitter),
        config.batch_interval_ms,
        sender,
        0,
    ));
    let settler_clone = Arc::clone(&settler);
    tokio::spawn(async move {
        settler_clone.run().await;
    });

    // Start the protocol servers, all routed through the rings.
    // The dummy SharedMatcher is the mutex-path fallback — it is
    // never touched when the ring is present, but the API requires
    // it. All actual order flow goes through the ring to THE one book.
    let dummy = Arc::new(SharedMatcher::new(MatchingServer::new(
        trading::MarketConfig {
            market_id: 0,
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
            max_resting: 1 << 16,
        },
        1,
    )));

    let tcp_handle = {
        let matcher = Arc::clone(&dummy);
        let ring = Arc::clone(&ring);
        let counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            if let Err(e) =
                run_binary_tcp_server_ring(matcher, ring, counter, config.binary_tcp_port).await
            {
                eprintln!("binary TCP server error: {e}");
            }
        })
    };

    let jsonrpc_handle = {
        let matcher = Arc::clone(&dummy);
        let ring = Arc::clone(&ring);
        let counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            if let Err(e) =
                run_jsonrpc_tcp_server_ring(matcher, ring, counter, config.jsonrpc_port).await
            {
                eprintln!("JSON-RPC server error: {e}");
            }
        })
    };

    let fix_handle = {
        let matcher = Arc::clone(&dummy);
        let ring = Arc::clone(&ring);
        let counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            if let Err(e) = run_fix_server_ring(matcher, ring, counter, config.fix_port).await {
                eprintln!("FIX server error: {e}");
            }
        })
    };

    let ws_handle = {
        let matcher = Arc::clone(&dummy);
        let ring = Arc::clone(&ring);
        let counter = Arc::clone(&ring_counter);
        tokio::spawn(async move {
            if let Err(e) =
                run_websocket_server_ring(matcher, ring, counter, config.websocket_port).await
            {
                eprintln!("WebSocket server error: {e}");
            }
        })
    };

    // Wait for all servers (they run forever).
    let _ = tokio::join!(tcp_handle, jsonrpc_handle, fix_handle, ws_handle);
}

// ── Multi-market parallel server ─────────────────────────────────────

/// Submit a batch of orders through the multi-market parallel matcher.
/// Splits the batch by market, sends each sub-batch to the correct
/// market worker, and collects responses. Preserves the original
/// order by tagging each response with its index.
fn submit_batch_multi(
    matcher: &crate::MultiMarketMatcher,
    orders: Vec<OrderRequest>,
) -> Vec<OrderResponse> {
    if orders.is_empty() {
        return Vec::new();
    }
    // `submit_batch` authenticates every request on this thread,
    // routes each verified order by its own `market` field (single-
    // and mixed-market batches both), and merges responses at their
    // original positions — no transport-side grouping needed.
    matcher.submit_batch(orders)
}

/// Submit a single order through the multi-market parallel matcher.
fn submit_one_multi(matcher: &crate::MultiMarketMatcher, req: OrderRequest) -> OrderResponse {
    matcher.submit_one(req)
}

/// Run a binary TCP server backed by the multi-market parallel
/// matcher. Each connection reads orders and routes them to the
/// correct market worker.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_binary_tcp_server_multi(
    matcher: Arc<crate::MultiMarketMatcher>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("binary TCP (multi-market) server listening on 127.0.0.1:{port}");
    loop {
        let (socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        tokio::spawn(handle_connection_multi(socket, matcher));
    }
}

/// Handle a single TCP connection on the multi-market path.
async fn handle_connection_multi(
    mut socket: tokio::net::TcpStream,
    matcher: Arc<crate::MultiMarketMatcher>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut header = [0u8; 4];
    loop {
        if socket.read_exact(&mut header).await.is_err() {
            break;
        }
        if header[3] == crate::protocol::BATCH_FLAG {
            let mut count_buf = [0u8; 4];
            if socket.read_exact(&mut count_buf).await.is_err() {
                break;
            }
            let count = u32::from_le_bytes(count_buf) as usize;
            // HIGH fix: bound-check `count` BEFORE allocating (OOM
            // prevention — same as the async path above).
            if count > crate::protocol::MAX_BATCH_SIZE {
                break; // reject oversized batch
            }
            let entries_len = count * crate::protocol::BATCH_ENTRY_SIZE;
            let mut entries = vec![0u8; entries_len];
            if socket.read_exact(&mut entries).await.is_err() {
                break;
            }
            let mut full_msg = Vec::with_capacity(8 + entries_len);
            full_msg.extend_from_slice(&header);
            full_msg.extend_from_slice(&count_buf);
            full_msg.extend_from_slice(&entries);
            let Some(orders) = crate::protocol::decode_batch_request(&full_msg) else {
                let resp = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&resp)).await;
                continue;
            };
            let responses = submit_batch_multi(&matcher, orders);
            let batch_resp = crate::protocol::encode_batch_response(&responses);
            if socket.write_all(&batch_resp).await.is_err() {
                break;
            }
        } else if is_action_request(&header) {
            // Action request (cancel/amend/replace).
            let mut rest = [0u8; crate::protocol::ACTION_REQUEST_SIZE - 4];
            if socket.read_exact(&mut rest).await.is_err() {
                break;
            }
            let mut full = Vec::with_capacity(crate::protocol::ACTION_REQUEST_SIZE);
            full.extend_from_slice(&header);
            full.extend_from_slice(&rest);
            let Some(action_req) = decode_action_request(&full) else {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            };
            if !crate::protocol::verify_action_with_chain_id(&action_req, matcher.chain_id()) {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::BadSignature);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            }
            // The wire `ActionRequest` is routed intact — the market
            // worker authenticates it before dispatching.
            let action_resp = matcher.submit_action(&action_req);
            if socket.write_all(&encode_response(&action_resp)).await.is_err() {
                break;
            }
        } else {
            let mut rest = [0u8; crate::protocol::REQUEST_SIZE - 4];
            if socket.read_exact(&mut rest).await.is_err() {
                break;
            }
            let mut full = Vec::with_capacity(crate::protocol::REQUEST_SIZE);
            full.extend_from_slice(&header);
            full.extend_from_slice(&rest);
            let Some(req) = decode_request(&full) else {
                let rej = OrderResponse::rejected(crate::protocol::RejectReason::Malformed);
                let _ = socket.write_all(&encode_response(&rej)).await;
                continue;
            };
            let order_resp = submit_one_multi(&matcher, req);
            if socket.write_all(&encode_response(&order_resp)).await.is_err() {
                break;
            }
        }
    }
}

/// Run a JSON-RPC server backed by the multi-market parallel matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_jsonrpc_tcp_server_multi(
    matcher: Arc<crate::MultiMarketMatcher>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("JSON-RPC (multi-market) server listening on 127.0.0.1:{port}");
    loop {
        let (mut socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (reader, mut writer) = socket.split();
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let req: serde_json::Value = if let Ok(v) = serde_json::from_str(&line) {
                    v
                } else {
                    let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null}
"#).await;
                    continue;
                };
                let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
                let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
                let params = req.get("params").cloned().unwrap_or(serde_json::Value::Null);

                if method == crate::jsonrpc::MANAGE_ORDER {
                    let Some(action_req) = crate::jsonrpc::parse_jsonrpc_action(&params) else {
                        let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":null}
"#).await;
                        continue;
                    };
                    if !crate::protocol::verify_action_with_chain_id(
                        &action_req,
                        matcher.chain_id(),
                    ) {
                        let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"bad signature"},"id":null}
"#).await;
                        continue;
                    }
                    // The wire `ActionRequest` is routed intact — the
                    // market worker authenticates it before dispatch.
                    let resp = matcher.submit_action(&action_req);
                    let result = crate::jsonrpc::format_jsonrpc_response(&resp);
                    let response =
                        serde_json::json!({ "jsonrpc": "2.0", "result": result, "id": id });
                    let mut response_line = serde_json::to_string(&response).unwrap_or_default();
                    response_line.push('\n');
                    let _ = writer.write_all(response_line.as_bytes()).await;
                    continue;
                }

                if method != "oxide_placeOrder" {
                    let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":null}
"#).await;
                    continue;
                }
                let Some(order_req) = crate::jsonrpc::parse_jsonrpc_order(&params) else {
                    let _ = writer.write_all(br#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":null}
"#).await;
                    continue;
                };
                let resp = submit_one_multi(&matcher, order_req);
                let result = crate::jsonrpc::format_jsonrpc_response(&resp);
                let response = serde_json::json!({ "jsonrpc": "2.0", "result": result, "id": id });
                let mut response_line = serde_json::to_string(&response).unwrap_or_default();
                response_line.push('\n');
                let _ = writer.write_all(response_line.as_bytes()).await;
            }
        });
    }
}

/// Run a FIX server backed by the multi-market parallel matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_fix_server_multi(
    matcher: Arc<crate::MultiMarketMatcher>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("FIX (multi-market) server listening on 127.0.0.1:{port}");
    loop {
        let (mut socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let text = String::from_utf8_lossy(&buf[..n]);
                let cl_ord_id = text
                    .split('\x01')
                    .find_map(|f| f.strip_prefix("11=").map(str::to_string))
                    .unwrap_or_else(|| "UNKNOWN".to_string());
                let msg_type = text
                    .split('\x01')
                    .find_map(|f| f.strip_prefix("35=").map(str::to_string))
                    .unwrap_or_default();
                if msg_type == crate::fix::MSG_TYPE_CANCEL
                    || msg_type == crate::fix::MSG_TYPE_CANCEL_REPLACE
                {
                    let action_req = if msg_type == crate::fix::MSG_TYPE_CANCEL {
                        crate::fix::parse_fix_cancel(&text)
                    } else {
                        crate::fix::parse_fix_cancel_replace(&text)
                    };
                    let Some(action_req) = action_req else {
                        // Malformed action — answer with a rejected
                        // ExecutionReport instead of dropping the
                        // message: a client blocking on a response
                        // per message must never be wedged by a
                        // parse failure.
                        let resp = OrderResponse::rejected(RejectReason::Malformed);
                        let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                        let _ = socket.write_all(report.as_bytes()).await;
                        continue;
                    };
                    if !crate::protocol::verify_action_with_chain_id(
                        &action_req,
                        matcher.chain_id(),
                    ) {
                        let resp = OrderResponse::rejected(RejectReason::BadSignature);
                        let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                        let _ = socket.write_all(report.as_bytes()).await;
                        continue;
                    }
                    // The wire `ActionRequest` is routed intact — the
                    // market worker authenticates it before dispatch.
                    let resp = matcher.submit_action(&action_req);
                    let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                    let _ = socket.write_all(report.as_bytes()).await;
                    continue;
                }
                let Some(req) = crate::fix::parse_fix_order(&text) else {
                    // Malformed order — answer with a rejected
                    // ExecutionReport instead of dropping the
                    // message: a client blocking on a response per
                    // message must never be wedged by a parse
                    // failure.
                    let resp = OrderResponse::rejected(RejectReason::Malformed);
                    let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                    let _ = socket.write_all(report.as_bytes()).await;
                    continue;
                };
                let resp = submit_one_multi(&matcher, req);
                let report = crate::fix::format_fix_execution_report(&resp, &cl_ord_id);
                let _ = socket.write_all(report.as_bytes()).await;
            }
        });
    }
}

/// Run a WebSocket server backed by the multi-market parallel matcher.
///
/// # Errors
///
/// Returns `Err` if the TCP listener fails to bind.
pub async fn run_websocket_server_multi(
    matcher: Arc<crate::MultiMarketMatcher>,
    port: u16,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("WebSocket (multi-market) server listening on 127.0.0.1:{port}");
    loop {
        let (socket, _) = listener.accept().await?;
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            use tokio_tungstenite::tungstenite::Message;
            let ws_stream = match tokio_tungstenite::accept_async(socket).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("WebSocket handshake failed: {e}");
                    return;
                }
            };
            let (mut ws_sender, mut ws_receiver) = ws_stream.split();
            while let Some(msg_result) = ws_receiver.next().await {
                let Ok(msg) = msg_result else { break };
                let text = match msg {
                    Message::Text(t) => t.to_string(),
                    Message::Binary(b) => String::from_utf8_lossy(&b).to_string(),
                    Message::Close(_) => break,
                    _ => continue,
                };
                let Some(req) = crate::ws::parse_ws_order(&text) else {
                    let _ =
                        ws_sender.send(Message::Text(r#"{"error":"invalid order"}"#.into())).await;
                    continue;
                };
                let resp = submit_one_multi(&matcher, req);
                let response = crate::ws::format_ws_response(&resp, 0);
                if ws_sender.send(Message::Text(response.into())).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Run all protocol servers concurrently with the multi-market
/// parallel matcher. This is the production entry point for
/// high-throughput multi-market deployments: one worker thread per
/// market, shared sharded balances, all four protocols routed by
/// `OrderRequest.market`.
///
/// # Arguments
/// - `configs`: one `MarketConfig` per market.
/// - `balances`: the shared sharded balance cache (fund accounts
///   before calling this).
/// - `submitter`: the consensus tx submitter (for batch settlement).
/// - `config`: server configuration (ports, batch interval).
/// - `sender`: the matcher operator's address (for settlement txs).
pub async fn run_server_multi(
    configs: Vec<MarketConfig>,
    balances: Arc<crate::ShardedBalanceCache>,
    submitter: Arc<dyn TxSubmitter>,
    config: ServerConfig,
    sender: primitives::Address,
) {
    let matcher = Arc::new(crate::MultiMarketMatcher::with_options(
        configs,
        balances,
        Arc::new(crate::wall_clock_ms),
        config.chain_id,
        config.nonce_state_path.clone(),
    ));

    // Batch settler seals from ALL markets via the control channel.
    let sealer: Arc<dyn crate::BatchSealer> = Arc::clone(&matcher) as Arc<dyn crate::BatchSealer>;
    let settler = Arc::new(BatchSettler::new(
        sealer,
        Arc::clone(&submitter),
        config.batch_interval_ms,
        sender,
        0,
    ));
    let settler_clone = Arc::clone(&settler);
    tokio::spawn(async move {
        settler_clone.run().await;
    });

    let tcp_handle = {
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            if let Err(e) = run_binary_tcp_server_multi(matcher, config.binary_tcp_port).await {
                eprintln!("binary TCP server error: {e}");
            }
        })
    };
    let jsonrpc_handle = {
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            if let Err(e) = run_jsonrpc_tcp_server_multi(matcher, config.jsonrpc_port).await {
                eprintln!("JSON-RPC server error: {e}");
            }
        })
    };
    let fix_handle = {
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            if let Err(e) = run_fix_server_multi(matcher, config.fix_port).await {
                eprintln!("FIX server error: {e}");
            }
        })
    };
    let ws_handle = {
        let matcher = Arc::clone(&matcher);
        tokio::spawn(async move {
            if let Err(e) = run_websocket_server_multi(matcher, config.websocket_port).await {
                eprintln!("WebSocket server error: {e}");
            }
        })
    };
    let _ = tokio::join!(tcp_handle, jsonrpc_handle, fix_handle, ws_handle);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchingServer, OrderRequest};
    use primitives::fixed::{Price, Qty};
    use trading::{MarketConfig, OrderType, Side, TimeInForce};

    fn cfg() -> MarketConfig {
        MarketConfig {
            market_id: 0,
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
            max_resting: 1 << 16,
        }
    }

    fn addr(byte: u8) -> primitives::Address {
        primitives::Address([byte; 20])
    }

    /// A deterministic test account: `seed` derives the Ed25519
    /// signing key; the account address is the key's derived owner.
    fn test_account(seed: u8) -> (crypto::ed25519::Ed25519SecretKey, primitives::Address) {
        let secret = crypto::ed25519::Ed25519SecretKey::from_bytes(&[seed; 32]);
        let owner = crypto::ed25519::owner_address(&secret.verifying_key());
        (secret, owner)
    }

    /// Build a signed order for `secret`'s account — every request
    /// reaching `submit_order` must now authenticate.
    fn signed_req(
        secret: &crypto::ed25519::Ed25519SecretKey,
        side: Side,
        nonce: u64,
    ) -> OrderRequest {
        let mut req = OrderRequest {
            market: 0,
            side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            nonce,
            owner: addr(0),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        crate::protocol::sign_order(&mut req, secret);
        req
    }

    /// A mock tx submitter that records submissions.
    struct MockSubmitter {
        submissions: std::sync::Mutex<Vec<TxBytes>>,
    }

    impl MockSubmitter {
        fn new() -> Self {
            Self { submissions: std::sync::Mutex::new(Vec::new()) }
        }

        fn count(&self) -> usize {
            self.submissions.lock().unwrap().len()
        }
    }

    impl TxSubmitter for MockSubmitter {
        fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
            self.submissions.lock().unwrap().push(tx);
            Ok(())
        }
    }

    #[test]
    fn batch_settler_seals_and_submits() {
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&seller, 1_000_000_000_000);
        server.fund_account(&buyer, 1_000_000_000_000);

        // Rest a maker sell, then a taker buy — should match.
        server.submit_order(&signed_req(&seller_sk, Side::Sell, 0));
        server.submit_order(&signed_req(&buyer_sk, Side::Buy, 0));

        // There should be 1 fill in the batch.
        assert_eq!(server.pending_settlements(), 1);

        // Create the shared matcher and settler.
        let shared = Arc::new(SharedMatcher::new(server));
        let counter = Arc::new(MockSubmitter::new());
        let submitter: Arc<dyn TxSubmitter> = Arc::clone(&counter) as Arc<dyn TxSubmitter>;
        let batch_sealer: Arc<dyn crate::BatchSealer> =
            Arc::clone(&shared) as Arc<dyn crate::BatchSealer>;
        let settler = BatchSettler::new(batch_sealer, Arc::clone(&submitter), 100, addr(0), 0);

        // Settle now.
        let settled = settler.settle_now().expect("settle");
        assert_eq!(settled, 1, "should settle 1 fill");
        assert_eq!(counter.count(), 1, "should submit 1 tx");
        assert_eq!(shared.stats().pending_settlements, 0, "batch should be empty after settle");
    }

    #[test]
    fn batch_settler_empty_batch_is_noop() {
        let server = MatchingServer::new(cfg(), 100);
        let shared = Arc::new(SharedMatcher::new(server));
        let submitter: Arc<dyn TxSubmitter> = Arc::new(MockSubmitter::new());
        let settler = BatchSettler::new(shared, submitter, 100, addr(0), 0);

        let settled = settler.settle_now().expect("settle");
        assert_eq!(settled, 0, "empty batch should settle 0");
    }

    /// A submitter that fails the first `fail_count` submissions,
    /// then accepts — and records every attempt.
    struct FlakySubmitter {
        fail_remaining: std::sync::Mutex<u32>,
        submissions: std::sync::Mutex<Vec<TxBytes>>,
    }

    impl TxSubmitter for FlakySubmitter {
        fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
            self.submissions.lock().unwrap().push(tx);
            let mut remaining = self.fail_remaining.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                return Err("mempool full".to_string());
            }
            Ok(())
        }
    }

    /// Regression test: a failed `submit_tx` must NOT lose the
    /// sealed fills or burn the nonce. Before the fix the batch was
    /// drained and the nonce already incremented, so the retry
    /// carried nonce N+1 while the executor still expected N —
    /// every subsequent settlement was nonce-skipped forever.
    #[test]
    fn batch_settler_retries_failed_batch_same_envelope() {
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&seller, 1_000_000_000_000);
        server.fund_account(&buyer, 1_000_000_000_000);
        server.submit_order(&signed_req(&seller_sk, Side::Sell, 0));
        server.submit_order(&signed_req(&buyer_sk, Side::Buy, 0));
        assert_eq!(server.pending_settlements(), 1);

        let shared = Arc::new(SharedMatcher::new(server));
        let flaky = Arc::new(FlakySubmitter {
            fail_remaining: std::sync::Mutex::new(1),
            submissions: std::sync::Mutex::new(Vec::new()),
        });
        let settler = BatchSettler::new(
            Arc::clone(&shared) as Arc<dyn crate::BatchSealer>,
            Arc::clone(&flaky) as Arc<dyn TxSubmitter>,
            100,
            addr(0),
            0,
        );

        // First submission fails — the fills must be kept in
        // `pending`, not dropped.
        assert!(settler.settle_now().is_err());
        assert_eq!(flaky.submissions.lock().unwrap().len(), 1);

        // The retry resubmits the SAME envelope (same nonce — the
        // executor still expects it) and succeeds.
        let settled = settler.settle_now().expect("retry must succeed");
        assert_eq!(settled, 1);
        let subs = flaky.submissions.lock().unwrap();
        assert_eq!(subs.len(), 2, "one original + one retry");
        assert_eq!(
            subs[0].as_bytes(),
            subs[1].as_bytes(),
            "the retry must resubmit the identical envelope (nonce baked in)"
        );
        drop(subs);

        // The next batch gets the NEXT nonce — the sequence stayed
        // contiguous because the failed submit never consumed one.
        server_refill(&shared);
        let settled = settler.settle_now().expect("second batch");
        assert_eq!(settled, 1);
        let subs = flaky.submissions.lock().unwrap();
        assert_eq!(subs.len(), 3);
        assert_ne!(subs[1].as_bytes(), subs[2].as_bytes(), "the next batch carries the next nonce");
    }

    /// Submit another matched pair so `seal_batch` returns a fill.
    /// Each account's second order uses nonce 1 (nonce 0 was the
    /// first fill's pair).
    fn server_refill(shared: &SharedMatcher) {
        let (seller_sk, _) = test_account(9);
        let (buyer_sk, _) = test_account(1);
        shared.submit(&signed_req(&seller_sk, Side::Sell, 1));
        shared.submit(&signed_req(&buyer_sk, Side::Buy, 1));
    }

    /// Regression test: a permanently-rejected envelope must NOT be
    /// dropped after `MAX_PENDING_RETRIES`. Dropping would cause
    /// cache/chain divergence (the off-chain cache already reflects
    /// the fills from `seal_batch`, but the on-chain settlement never
    /// landed). Instead, the envelope stays pending so the operator
    /// can intervene and the settlement can land when the chain
    /// recovers. The nonce is NOT advanced (the tx never executed).
    #[test]
    fn batch_settler_keeps_pending_after_max_retries() {
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&seller, 1_000_000_000_000);
        server.fund_account(&buyer, 1_000_000_000_000);
        server.submit_order(&signed_req(&seller_sk, Side::Sell, 0));
        server.submit_order(&signed_req(&buyer_sk, Side::Buy, 0));

        let shared = Arc::new(SharedMatcher::new(server));
        // Fail forever — the batch is retried but NOT dropped.
        let flaky = Arc::new(FlakySubmitter {
            fail_remaining: std::sync::Mutex::new(u32::MAX),
            submissions: std::sync::Mutex::new(Vec::new()),
        });
        let settler = BatchSettler::new(
            Arc::clone(&shared) as Arc<dyn crate::BatchSealer>,
            Arc::clone(&flaky) as Arc<dyn TxSubmitter>,
            100,
            addr(0),
            0,
        );

        // 1 initial failure + (MAX-1) retries — all fail, but the
        // pending envelope is NOT dropped.
        for _ in 0..MAX_PENDING_RETRIES {
            assert!(settler.settle_now().is_err());
        }
        // One more call: pending is still there, so the SAME envelope
        // is retried (not a new batch). The nonce is NOT advanced.
        assert!(settler.settle_now().is_err());
        let subs = flaky.submissions.lock().unwrap();
        // All submissions carry the same nonce (the same envelope
        // is retried, never dropped).
        let first_nonce = &subs[0].as_bytes()[20..28];
        let last_nonce = &subs[subs.len() - 1].as_bytes()[20..28];
        assert_eq!(first_nonce, last_nonce, "nonce must not advance while pending");
    }
}
