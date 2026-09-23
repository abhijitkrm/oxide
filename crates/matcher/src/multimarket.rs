//! Multi-market orchestration: one `MarketWorker` thread per
//! market behind a [`MultiMarketMatcher`], sharing one
//! [`crate::AtomicBalanceCache`].
//!
//! Split from `lib.rs` around the concurrency invariant: every
//! worker owns its `MatchingServer` (single-threaded matching per
//! market); markets communicate ONLY through the shared balance
//! cache and the per-worker `mpsc` control channels. `Work` /
//! `Action` / `Seal` / `Stats` messages multiplex on one channel so
//! a control command never queues behind order flow.

use std::collections::HashMap;
use std::sync::Arc;

use primitives::fixed::{Price, Qty};
use trading::{
    DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderOutcome, OrderType, Side,
    StpMode, TimeInForce,
};

use crate::protocol::{
    self, ActionRequest, OrderAction, OrderRequest, OrderResponse, RejectReason,
};
use crate::risk::{RiskDecision, RiskEngine};
use crate::settlement::{
    LegCostAcc, LegId, NonceTracker, PRICE_SCALE, SettledFill, buy_reservation_refund,
    evict_gone_client_ids, fill_parties, gone_makers,
};
use crate::{AtomicBalanceCache, BatchSealer, MatcherStats, wall_clock_ms};

// ── MultiMarketMatcher ───────────────────────────────────────────────

/// A message sent to a market worker — either a batch of orders to
/// process or a control command (seal/stats). Merging these into one
/// channel avoids the worker blocking on `work_rx.recv()` while a
/// control command waits on a separate channel.
pub(crate) enum MarketMessage {
    /// A batch of orders to match and settle.
    Work(MarketWork),
    /// An order action (cancel/amend/replace) to process.
    Action(ActionWork),
    /// Seal this worker's settlement batch and return it.
    Seal(std::sync::mpsc::Sender<Vec<SettledFill>>),
    /// Snapshot this worker's stats.
    Stats(std::sync::mpsc::Sender<WorkerStats>),
}

/// A work item sent from a protocol handler to a market worker
/// thread. The worker processes the orders, sends the responses back
/// via `response_tx`, and accumulates fills for batch settlement.
///
/// Orders arrive PRE-AUTHENTICATED: `MultiMarketMatcher::submit_batch`
/// verifies each request on the calling (transport) thread and packs
/// the survivors as [`protocol::VerifiedOrder`] — proof tokens that
/// can only be built by passing `verify_order`. The worker therefore
/// never executes an unauthenticated order AND never pays a second
/// signature verification (signature checks parallelize across the
/// submitting threads).
pub(crate) struct MarketWork {
    /// The authenticated orders (all for this market).
    pub(crate) orders: Vec<protocol::VerifiedOrder>,
    /// One-shot channel for the worker to return the responses.
    pub(crate) response_tx: std::sync::mpsc::Sender<Vec<OrderResponse>>,
}

/// An action work item: a single order action (cancel/amend/replace)
/// routed to the correct market worker. Carries a
/// [`protocol::VerifiedAction`] proof — authentication happens at the
/// boundary (submitting thread), the same proof-token boundary as
/// orders' [`protocol::VerifiedOrder`], so the worker never pays a
/// second signature verification.
pub(crate) struct ActionWork {
    /// The authenticated action to process.
    pub(crate) action: protocol::VerifiedAction,
    /// One-shot channel for the worker to return the response.
    pub(crate) response_tx: std::sync::mpsc::Sender<OrderResponse>,
}

/// Per-worker stats (one market).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WorkerStats {
    pub(crate) orders_processed: u64,
    pub(crate) fills_produced: u64,
    pub(crate) balance_rejections: u64,
    pub(crate) engine_rejections: u64,
    pub(crate) risk_rejections: u64,
    pub(crate) auth_rejections: u64,
    pub(crate) resting_count: u32,
    pub(crate) pending_settlements: usize,
}

/// A multi-market parallel matcher: one worker thread per market,
/// each owning its own `MatchingEngine`, all sharing a single
/// `AtomicBalanceCache` (aliased `ShardedBalanceCache`).
///
/// # Architecture
///
/// ```text
///   Protocol handlers (TCP, WS, JSON-RPC, FIX)
///         │
///         ▼
///   ┌─────────────────────────────────────────────┐
///   │  Per-market order channels (MPSC)            │
///   │  market 0 → worker 0  (owns Engine 0)        │
///   │  market 1 → worker 1  (owns Engine 1)        │
///   │  ...                                         │
///   │  market N → worker N  (owns Engine N)        │
///   └─────────────────────────────────────────────┘
///         │                        │
///         ▼                        ▼
///   ┌──────────────┐    ┌──────────────────────┐
///   │ Each worker: │    │ AtomicBalanceCache   │
///   │ 1 Engine     │───►│ (64 shards, Mutex    │
///   │ 1 fill buf   │    │  per shard)           │
///   │ 1 settle buf │    └──────────────────────┘
///   └──────────────┘
/// ```
///
/// # Parallelism
///
/// Each market worker is an independent thread. Markets are
/// independent (no shared order book state), so N markets run on N
/// cores with zero contention on the matching hot path. The only
/// shared state is the balance cache, which is sharded by account
/// hash — contention only occurs when two markets trade the same
/// account simultaneously, and even then it's one shard lock.
///
/// # Determinism
///
/// Within each market, the worker processes orders in FIFO order
/// (MPSC channel preserves order). Across markets, execution order is
/// non-deterministic (threads run independently), but that's correct
/// — different markets are independent state machines. The one
/// cross-market invariant — per-account nonce ordering — IS
/// deterministic: `submit_batch` consumes nonces in batch order on
/// the calling thread before dispatch (see the `nonces` field).
///
/// # Settlement
///
/// Each worker accumulates fills in its own `settlement_batch` vec
/// (no shared lock on the fill path). The batch settler sends a
/// `Seal` command to every worker, collects all batches, and
/// concatenates them. This is lock-free on the hot path.
pub struct MultiMarketMatcher {
    /// One sender per market: protocol handlers push `MarketMessage`
    /// items here (either `Work` or `Seal`/`Stats` control commands).
    /// `mpsc::Sender` is cloneable, so multiple connections can feed
    /// the same market.
    pub(crate) market_senders: Vec<std::sync::mpsc::Sender<MarketMessage>>,
    /// Worker thread handles (kept for shutdown).
    pub(crate) _threads: Vec<std::thread::JoinHandle<()>>,
    /// Number of markets.
    pub(crate) num_markets: usize,
    /// Shared per-account replay gate — the SAME tracker the workers
    /// hold. `submit_batch` consumes nonces HERE (in batch order, on
    /// the calling thread) rather than in the workers: a batch mixing
    /// markets for one account would otherwise have its nonces
    /// consumed by different workers in parallel, making admission
    /// order — and therefore `StaleNonce` vs accept — nondeterministic
    /// within a single call. Consuming at dispatch defines the batch's
    /// submission order as the admission order. (Races ACROSS
    /// concurrent `submit_batch` calls remain, which is correct —
    /// concurrent submissions have no defined order.)
    pub(crate) nonces: Arc<std::sync::Mutex<NonceTracker>>,
    /// The chain ID order signatures are verified against — shared
    /// with every worker so transport-side and worker-side
    /// authentication can never disagree.
    pub(crate) chain_id: u64,
}

impl MultiMarketMatcher {
    /// Create a multi-market parallel matcher with the given market
    /// configs. Spawns one worker thread per market.
    ///
    /// # Arguments
    /// - `configs`: one `MarketConfig` per market (`market_id` = index).
    /// - `balances`: the shared sharded balance cache (fund accounts
    ///   before calling this).
    ///
    /// # Panics
    ///
    /// Panics if `configs` is empty or if any engine/book fails to
    /// create from the given config.
    #[must_use]
    pub fn new(configs: Vec<MarketConfig>, balances: Arc<AtomicBalanceCache>) -> Self {
        Self::with_options(configs, balances, Arc::new(wall_clock_ms), protocol::CHAIN_ID, None)
    }

    /// Create a multi-market matcher with a custom millisecond time
    /// source — production deployments can supply a monotonic clock;
    /// tests inject a deterministic one so rate-limit windows are
    /// controllable.
    ///
    /// # Panics
    ///
    /// Panics if `configs` is empty or if any engine/book fails to
    /// create from the given config.
    #[must_use]
    pub fn with_clock(
        configs: Vec<MarketConfig>,
        balances: Arc<AtomicBalanceCache>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self::with_options(configs, balances, clock, protocol::CHAIN_ID, None)
    }

    /// Create a multi-market matcher with a custom clock and chain
    /// ID. `chain_id` is the signature-verification domain — set it
    /// to the deployment's real chain ID or foreign-chain signatures
    /// replay here (the devnet default is [`protocol::CHAIN_ID`]).
    /// `nonce_store_path` attaches the durable replay-gate checkpoint
    /// (see [`MatchingServer::set_nonce_store`]) — the SHARED tracker
    /// it guards covers all workers/markets.
    ///
    /// # Panics
    ///
    /// Panics if `configs` is empty, if any engine/book fails to
    /// create from the given config, or if `nonce_store_path` exists
    /// but is corrupt.
    #[must_use]
    pub fn with_options(
        configs: Vec<MarketConfig>,
        balances: Arc<AtomicBalanceCache>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        chain_id: u64,
        nonce_store_path: Option<std::path::PathBuf>,
    ) -> Self {
        assert!(!configs.is_empty(), "must have at least one market");
        let num_markets = configs.len();
        let mut market_senders = Vec::with_capacity(num_markets);
        let mut threads = Vec::with_capacity(num_markets);
        // The nonce tracker is SHARED across workers: nonces are
        // per-account, not per-market, so a replayed nonce must be
        // rejected no matter which market it lands on. A short Mutex
        // is acceptable — the check runs once per admission and the
        // work already crosses an MPSC hop.
        let nonces = Arc::new(std::sync::Mutex::new(NonceTracker::new()));
        if let Some(path) = nonce_store_path {
            nonces
                .lock()
                .expect("nonce tracker mutex poisoned during construction")
                .attach_store(path);
        }

        for cfg in configs {
            let (tx, rx) = std::sync::mpsc::channel::<MarketMessage>();
            let balances = Arc::clone(&balances);
            let nonces = Arc::clone(&nonces);
            let clock = Arc::clone(&clock);
            // Supervised per-market worker — non-critical: a dead
            // worker strands one market's book, not the process.
            let actor = format!("market-worker-{}", cfg.market_id);
            let thread = primitives::supervision::spawn_supervised(&actor, false, move || {
                MarketWorker::run(cfg, balances, nonces, clock, rx);
            })
            .expect("spawn market worker thread");
            market_senders.push(tx);
            threads.push(thread);
        }

        Self { market_senders, _threads: threads, num_markets, nonces, chain_id }
    }

    /// The chain ID order signatures are verified against —
    /// transports read this so transport-side and worker-side
    /// authentication always agree.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Submit a batch of orders. Orders may span markets — each order
    /// is routed to the worker for its own `market` field. Returns
    /// the responses in the same order as the requests.
    ///
    /// Authentication runs HERE — on the calling (transport) thread —
    /// so signature verification parallelizes across submitters.
    /// Each request becomes a [`protocol::VerifiedOrder`] proof token
    /// (unforgeable outside `verify_order`); failed entries get an
    /// aligned `BadSignature` response at their original position and
    /// never reach the worker.
    ///
    /// Routing is by EACH order's market, not the batch head's:
    /// routing every order to `orders[0].market` would silently match
    /// mixed-market batches on the wrong book (the engine does not
    /// re-check the market field — the worker's engine IS the market).
    ///
    /// # Panics
    ///
    /// Panics if `orders` is empty, if any order's `market` is out of
    /// range, or if a market worker thread has died mid-batch.
    pub fn submit_batch(&self, orders: Vec<OrderRequest>) -> Vec<OrderResponse> {
        assert!(!orders.is_empty(), "batch must not be empty");
        // Authenticate + replay-check every order on this thread, IN
        // BATCH ORDER. `positions[i]` records the original index of
        // admitted order i so its response lands in the right slot.
        //
        // The nonce is consumed HERE — before dispatch — because the
        // workers run in parallel: if two same-account orders went to
        // different markets and each worker consumed its nonce on
        // arrival, whichever worker ran first would set the watermark
        // and the other order's result (StaleNonce vs accept) would
        // be nondeterministic within a single call. Consuming in
        // batch order makes the batch's submission order the
        // admission order. Order matters within the sequence:
        // signature verification runs BEFORE the nonce is consumed —
        // a forged request must never burn the victim's next nonce.
        let mut positions: Vec<usize> = Vec::with_capacity(orders.len());
        let mut responses: Vec<Option<OrderResponse>> = Vec::with_capacity(orders.len());
        // Batch authentication: one multi-scalar multiplication across
        // all parse-valid signatures (~3× cheaper per order than
        // per-item `verify_strict`). The nonce check still runs
        // per-item afterwards, in batch order — verification ordering
        // relative to nonce consumption is unchanged (every signature
        // is proven before any nonce is consumed).
        let authenticated = protocol::VerifiedOrder::batch_with_chain_id(&orders, self.chain_id);
        let mut verified: Vec<protocol::VerifiedOrder> = Vec::with_capacity(orders.len());
        for (i, item) in authenticated.into_iter().enumerate() {
            match item {
                Some(vo) => {
                    // The nonce tracker is the replay gate: a panic
                    // mid-`check_and_consume` can leave `last_seen`
                    // and `dirty` torn. Panic on poison (loud halt)
                    // rather than reject — a poisoned gate must not
                    // keep looking alive while refusing orders.
                    let ok = primitives::sync::lock_state(&self.nonces)
                        .check_and_consume(&vo.request().owner, vo.request().nonce);
                    if ok {
                        positions.push(i);
                        verified.push(vo);
                        responses.push(None);
                    } else {
                        responses.push(Some(OrderResponse::rejected(RejectReason::StaleNonce)));
                    }
                }
                None => {
                    responses.push(Some(OrderResponse::rejected(RejectReason::BadSignature)));
                }
            }
        }
        if verified.is_empty() {
            return responses
                .into_iter()
                .map(|r| r.unwrap_or_else(|| OrderResponse::rejected(RejectReason::EngineError)))
                .collect();
        }

        let first_market = usize::from(verified[0].request().market);
        if verified.iter().all(|v| usize::from(v.request().market) == first_market) {
            // Fast path: single market — one send, one recv, no
            // per-market grouping allocation.
            assert!(
                first_market < self.num_markets,
                "market {first_market} out of range (have {} markets)",
                self.num_markets
            );
            let (response_tx, response_rx) = std::sync::mpsc::channel();
            if self.market_senders[first_market]
                .send(MarketMessage::Work(MarketWork { orders: verified, response_tx }))
                .is_err()
            {
                return vec![OrderResponse::rejected(RejectReason::EngineError); 1];
            }
            let worker_responses = response_rx
                .recv()
                .unwrap_or_else(|_| vec![OrderResponse::rejected(RejectReason::EngineError); 1]);
            for (pos, resp) in positions.into_iter().zip(worker_responses) {
                responses[pos] = Some(resp);
            }
        } else {
            // Slow path: mixed markets — split verified orders by
            // market, dispatch every group BEFORE blocking on any
            // response channel so the workers run in parallel, then
            // merge each worker's responses by original batch index.
            // `by_market[m]` holds (orig_pos, order) pairs. Indexed by
            // market rather than a HashMap: `num_markets` is bounded
            // (u8) and the mixed path is already the rare path.
            let mut by_market: Vec<Vec<(usize, protocol::VerifiedOrder)>> =
                (0..self.num_markets).map(|_| Vec::new()).collect();
            for (pos, vo) in positions.iter().copied().zip(verified) {
                let m = usize::from(vo.request().market);
                assert!(
                    m < self.num_markets,
                    "market {m} out of range (have {} markets)",
                    self.num_markets
                );
                by_market[m].push((pos, vo));
            }
            let mut receivers = Vec::new();
            for (m, group) in by_market.into_iter().enumerate() {
                if group.is_empty() {
                    continue;
                }
                let (idxs, group_orders): (Vec<usize>, Vec<protocol::VerifiedOrder>) =
                    group.into_iter().unzip();
                let (response_tx, response_rx) = std::sync::mpsc::channel();
                if self.market_senders[m]
                    .send(MarketMessage::Work(MarketWork { orders: group_orders, response_tx }))
                    .is_err()
                {
                    for pos in idxs {
                        responses[pos] = Some(OrderResponse::rejected(RejectReason::EngineError));
                    }
                    continue;
                }
                receivers.push((idxs, response_rx));
            }
            for (idxs, rx) in receivers {
                let n = idxs.len();
                let worker_responses = rx.recv().unwrap_or_else(|_| {
                    vec![OrderResponse::rejected(RejectReason::EngineError); n]
                });
                for (pos, resp) in idxs.into_iter().zip(worker_responses) {
                    responses[pos] = Some(resp);
                }
            }
        }
        // Every slot is Some: verified entries got worker responses,
        // unverified got BadSignature at submit time.
        responses
            .into_iter()
            .map(|r| r.unwrap_or_else(|| OrderResponse::rejected(RejectReason::EngineError)))
            .collect()
    }

    /// Submit a single order. Routes to the correct market worker.
    ///
    /// Returns an `EngineError` rejection if the market worker thread
    /// has died.
    pub fn submit_one(&self, order: OrderRequest) -> OrderResponse {
        let mut responses = self.submit_batch(vec![order]);
        responses.pop().unwrap_or_else(|| OrderResponse::rejected(RejectReason::EngineError))
    }

    /// Submit an order action (cancel/amend/replace). Authenticates the
    /// wire `ActionRequest` HERE (calling thread) and ships the
    /// [`protocol::VerifiedAction`] proof to the worker — the same
    /// proof-token boundary as orders' `VerifiedOrder`, so the market
    /// worker never pays a second signature verification and can never
    /// admit a forged action. Routes to market 0 (the v0 action
    /// protocol is single-market; the wire format carries no market
    /// field).
    ///
    /// Returns an `EngineError` rejection if the market worker thread
    /// has died.
    pub fn submit_action(&self, action: &ActionRequest) -> OrderResponse {
        let Some(verified) = protocol::VerifiedAction::with_chain_id(*action, self.chain_id) else {
            return OrderResponse::rejected(RejectReason::BadSignature);
        };
        self.submit_verified_action(verified)
    }

    /// Submit a pre-authenticated action — the caller constructed the
    /// [`protocol::VerifiedAction`] token itself (a transport that
    /// already verified the signature), so no verification happens
    /// again anywhere.
    ///
    /// Returns an `EngineError` rejection if the market worker thread
    /// has died.
    pub fn submit_verified_action(&self, action: protocol::VerifiedAction) -> OrderResponse {
        // v0: all actions route to market 0 — the wire `ActionRequest`
        // has no market field (multi-market routing is future work).
        let market = 0;
        if market >= self.num_markets {
            return OrderResponse::rejected(RejectReason::EngineError);
        }
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        if self.market_senders[market]
            .send(MarketMessage::Action(ActionWork { action, response_tx }))
            .is_err()
        {
            return OrderResponse::rejected(RejectReason::EngineError);
        }
        response_rx.recv().unwrap_or_else(|_| OrderResponse::rejected(RejectReason::EngineError))
    }

    /// `#[doc(hidden)]` — bench seam, not an admission path. Runs the
    /// exact production replay gate (shared `Mutex<NonceTracker>`
    /// acquire + `check_and_consume`) so the contention bench
    /// measures the lock every `submit_batch` order and every worker
    /// `submit_action` takes, without confounding it with signature
    /// verification or channel dispatch. Callers must not rely on the
    /// return value for admission decisions — this consumes the
    /// nonce exactly as production does.
    #[doc(hidden)]
    pub fn bench_consume_nonce(&self, owner: &primitives::Address, nonce: u64) -> bool {
        primitives::sync::lock_state(&self.nonces).check_and_consume(owner, nonce)
    }

    /// Seal the settlement batch across ALL markets. Sends a `Seal`
    /// message to every worker, collects all fills, and concatenates
    /// them. This is the `BatchSealer` implementation for the
    /// multi-market path.
    ///
    /// Returns fills only from live workers; dead workers contribute
    /// nothing.
    ///
    /// Also checkpoints the shared consumed-nonce state — the same
    /// settler-cadence durability point the single-market path uses.
    pub fn seal_batch(&self) -> Vec<SettledFill> {
        // Same panic-on-poison rule as admission: sealing fills while
        // skipping the durability checkpoint would keep the settler
        // running on a torn replay gate with a silently widening
        // restart-replay window.
        primitives::sync::lock_state(&self.nonces).flush();
        let mut all_fills = Vec::new();
        for tx in &self.market_senders {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            if tx.send(MarketMessage::Seal(reply_tx)).is_err() {
                continue;
            }
            if let Ok(fills) = reply_rx.recv() {
                all_fills.extend(fills);
            }
        }
        all_fills
    }

    /// Snapshot aggregate stats across ALL markets.
    ///
    /// Returns partial stats from live workers; dead workers
    /// contribute zeros.
    pub fn stats(&self) -> MatcherStats {
        let mut total = MatcherStats::default();
        for tx in &self.market_senders {
            let (reply_tx, reply_rx) = std::sync::mpsc::channel();
            if tx.send(MarketMessage::Stats(reply_tx)).is_err() {
                continue;
            }
            if let Ok(s) = reply_rx.recv() {
                total.orders_processed += s.orders_processed;
                total.fills_produced += s.fills_produced;
                total.balance_rejections += s.balance_rejections;
                total.engine_rejections += s.engine_rejections;
                total.risk_rejections += s.risk_rejections;
                total.auth_rejections += s.auth_rejections;
                total.resting_count += s.resting_count;
                total.pending_settlements += s.pending_settlements;
            }
        }
        total
    }

    /// Number of markets.
    #[must_use]
    pub fn num_markets(&self) -> usize {
        self.num_markets
    }
}

impl BatchSealer for MultiMarketMatcher {
    /// Seal across all markets: collect fills from every worker.
    ///
    /// # Panics
    ///
    /// Panics if any worker thread has died.
    fn seal_batch(&self) -> Vec<SettledFill> {
        MultiMarketMatcher::seal_batch(self)
    }
}

/// A single market worker thread — owns one `MatchingEngine` and
/// processes orders from its MPSC channel. Settlement fills are
/// accumulated locally (no shared lock); the batch settler collects
/// them via the control channel.
///
/// The worker enforces the SAME admission boundary as
/// `MatchingServer`: orders arrive pre-authenticated as
/// [`protocol::VerifiedOrder`] (signature + owner binding already
/// checked on the submitting thread), then the worker runs the
/// remaining steps — replay-check → risk → reserve → match — using
/// the SHARED nonce tracker (nonces are per-account across all
/// markets) and a per-market risk engine. Actions arrive as wire
/// `ActionRequest`s and are authenticated inside `submit_action`.
pub(crate) struct MarketWorker {
    /// The matching engine for this market (single-writer).
    pub(crate) engine: MatchingEngine,
    /// Shared sharded balance cache (cross-market).
    pub(crate) balances: Arc<AtomicBalanceCache>,
    /// Shared per-account replay gate — one sequence per owner
    /// across ALL markets (see `NonceTracker`).
    pub(crate) nonces: Arc<std::sync::Mutex<NonceTracker>>,
    /// Per-market risk engine (rate limits, fat-finger, size caps).
    /// Per-market rather than shared: an account's rate/resting
    /// budget is scoped to this market's book.
    pub(crate) risk: RiskEngine,
    /// Reusable fill buffer — zero alloc after the first order.
    pub(crate) fills: Vec<FillEvent>,
    /// The pending settlement batch (local to this worker).
    pub(crate) settlement_batch: Vec<SettledFill>,
    /// Worker-local marginal leg-cost accumulator — same
    /// telescoping semantics as [`MatchingServer::cost_acc`],
    /// reset when `Seal` drains the batch.
    pub(crate) cost_acc: LegCostAcc,
    /// Total orders processed by this worker.
    pub(crate) orders_processed: u64,
    /// Total fills produced by this worker.
    pub(crate) fills_produced: u64,
    /// Total orders rejected by balance check.
    pub(crate) balance_rejections: u64,
    /// Total orders rejected by the engine.
    pub(crate) engine_rejections: u64,
    /// Total orders rejected by the risk engine.
    pub(crate) risk_rejections: u64,
    /// Total requests rejected by authentication.
    pub(crate) auth_rejections: u64,
    /// Millisecond time source for the rate limiter — same injection
    /// point as `MatchingServer`; threaded from the matcher that
    /// spawned this worker.
    pub(crate) clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Scratch for non-fill book removals the sweep reports.
    pub(crate) removed: Vec<trading::MakerRemoval>,
    /// Book order id → the client order id (request nonce) of the
    /// owner who placed it — the same bookkeeping
    /// [`MatchingServer`] keeps so fills carry the on-chain
    /// `(owner, client_id)` authorization key.
    order_client_ids: HashMap<u64, u64>,
}

impl MarketWorker {
    /// The worker loop: receive messages (work or control), process
    /// them. Blocks on the single channel — no polling, no missed
    /// control commands.
    pub(crate) fn run(
        cfg: MarketConfig,
        balances: Arc<AtomicBalanceCache>,
        nonces: Arc<std::sync::Mutex<NonceTracker>>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        rx: std::sync::mpsc::Receiver<MarketMessage>,
    ) {
        let vcfg = cfg.validated().expect("market config must be valid");
        let engine = MatchingEngine::new(vcfg, DenseBook::new(vcfg).expect("book creation"))
            .expect("engine creation");
        let mut worker = MarketWorker {
            engine,
            balances,
            nonces,
            risk: RiskEngine::with_defaults(),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(10_000),
            cost_acc: LegCostAcc::default(),
            clock,
            removed: Vec::with_capacity(64),
            order_client_ids: HashMap::with_capacity(65_536),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
            auth_rejections: 0,
        };

        loop {
            match rx.recv() {
                Ok(MarketMessage::Work(work)) => {
                    let responses = worker.process_batch(&work.orders);
                    let _ = work.response_tx.send(responses);
                }
                Ok(MarketMessage::Action(action_work)) => {
                    let resp = worker.submit_verified_action(action_work.action);
                    let _ = action_work.response_tx.send(resp);
                }
                Ok(MarketMessage::Seal(reply)) => {
                    // Same boundary as `MatchingServer::seal_batch`:
                    // legs re-form per batch, so the marginal-cost
                    // accumulator resets with the drain.
                    worker.cost_acc.legs.clear();
                    let batch = std::mem::take(&mut worker.settlement_batch);
                    let _ = reply.send(batch);
                }
                Ok(MarketMessage::Stats(reply)) => {
                    let stats = WorkerStats {
                        orders_processed: worker.orders_processed,
                        fills_produced: worker.fills_produced,
                        balance_rejections: worker.balance_rejections,
                        engine_rejections: worker.engine_rejections,
                        risk_rejections: worker.risk_rejections,
                        auth_rejections: worker.auth_rejections,
                        resting_count: worker.engine.resting_count(),
                        pending_settlements: worker.settlement_batch.len(),
                    };
                    let _ = reply.send(stats);
                }
                Err(_) => break, // All senders dropped — shutdown.
            }
        }
    }

    /// Process a batch of authenticated orders for this market.
    /// Returns responses in the same order as the requests.
    pub(crate) fn process_batch(
        &mut self,
        orders: &[protocol::VerifiedOrder],
    ) -> Vec<OrderResponse> {
        let mut responses = Vec::with_capacity(orders.len());
        for req in orders {
            responses.push(self.submit_verified(req));
        }
        responses
    }

    /// Check the shared nonce for `owner`/`nonce` — returns `false`
    /// on replay. One lock acquisition per admission.
    pub(crate) fn check_nonce(&self, owner: &primitives::Address, nonce: u64) -> bool {
        // Panic-on-poison, matching `submit_batch`: a torn replay
        // gate halts loudly rather than looking alive-but-refusing.
        primitives::sync::lock_state(&self.nonces).check_and_consume(owner, nonce)
    }

    /// Submit one authenticated, nonce-consumed order: risk →
    /// reserve → match → settle. The replay check already ran on the
    /// dispatching thread inside `MultiMarketMatcher::submit_batch`
    /// (in batch order — see that function's comment for why the
    /// consume cannot happen here: parallel workers would make
    /// cross-market admission order nondeterministic). `VerifiedOrder`
    /// can only arrive via `MarketWork`, which `submit_batch` builds
    /// exclusively — the worker boundary cannot be reached without
    /// passing authentication AND nonce consumption.
    pub(crate) fn submit_verified(&mut self, req: &protocol::VerifiedOrder) -> OrderResponse {
        self.orders_processed += 1;
        self.execute_order(req.request())
    }

    /// Execute an authenticated, nonce-consumed order: risk →
    /// reserve → match → settle. Private — also used by the internal
    /// amend/replace resubmits (authenticated by their enclosing
    /// signed action).
    pub(crate) fn execute_order(&mut self, req: &OrderRequest) -> OrderResponse {
        // ── Risk-engine checks ───────────────────────────────────
        // Per-market risk engine: rate limit, size cap, price band,
        // resting cap. Mirrors `MatchingServer::execute_order` —
        // including the real-time source: the limiter measures
        // elapsed milliseconds, not the order counter.
        let mid = match (self.engine.best_bid(), self.engine.best_ask()) {
            (Some((bid, _)), Some((ask, _))) => u64::midpoint(bid.0, ask.0),
            _ => 0,
        };
        let now_ms = (self.clock)();
        if let RiskDecision::Reject(reason) =
            self.risk.check(&req.owner, now_ms, req.price.0, req.qty.0, mid)
        {
            self.risk_rejections += 1;
            return OrderResponse::rejected(reason);
        }

        // ── Reservation (buy orders only) ───────────────────────
        // Same accounting as `MatchingServer::execute_order`: limit
        // buys reserve `price × qty`, market buys reserve the
        // ask-ladder sweep bound (`sweep_cost`). Atomic
        // check-and-debit under the shard lock — no TOCTOU race
        // even if another market trades this account.
        let mut reservation = 0u64;
        if req.side == Side::Buy {
            let notional = match req.order_type {
                OrderType::Market => self.engine.sweep_cost(Side::Buy, req.qty.0, None),
                _ => u128::from(req.price.0) * u128::from(req.qty.0),
            };
            let quote_needed = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            if !self.balances.check_and_debit(&req.owner, quote_needed) {
                self.balance_rejections += 1;
                return OrderResponse::rejected(RejectReason::InsufficientBalance);
            }
            reservation = quote_needed;
        }

        // ── Build the order ─────────────────────────────────────
        let order = NewOrder {
            side: req.side,
            order_type: req.order_type,
            tif: req.tif,
            price: req.price,
            qty: req.qty,
            owner: req.owner,
            stp: StpMode::None,
        };

        // ── Match ───────────────────────────────────────────────
        // `ObserveRemovals` reports non-fill removals for the
        // resting-count bookkeeping below — same as the
        // single-market server.
        self.fills.clear();
        self.removed.clear();
        let Ok(outcome) = self.engine.place_with_cap(
            order,
            &mut self.fills,
            &mut trading::ObserveRemovals { removed: &mut self.removed },
        ) else {
            self.engine_rejections += 1;
            // Engine-level error: nothing matched, nothing rests —
            // the whole reservation comes back.
            if reservation > 0 {
                self.balances.credit(&req.owner, reservation);
            }
            return OrderResponse::rejected(RejectReason::EngineError);
        };

        // ── Settle fills ─────────────────────────────────────────
        // Credit the seller each fill's MARGINAL leg cost (cross-
        // shard if needed) — the delta in the merged leg's floored
        // total, telescoping to exactly the chain's
        // `floor(price × Σqty / SCALE)` (see `LegCostAcc`). The
        // buyer's payment comes out of the reservation debited at
        // admission — released piecewise below via
        // `buy_reservation_refund`.
        let mut taker_fill_cost: u64 = 0;
        for f in &self.fills {
            self.fills_produced += 1;
            // Client-id resolution mirrors
            // `MatchingServer::execute_order` (see `fill_parties`).
            let (buyer, seller, buyer_id, seller_id) =
                fill_parties(f, req.nonce, &self.order_client_ids);
            let market = self.engine.config().market_id;
            let quote_amount = self
                .cost_acc
                .add(LegId::new(market, f.price.0, buyer, buyer_id, seller, seller_id), f.qty.0);
            self.balances.credit(&seller, quote_amount);
            taker_fill_cost = taker_fill_cost.saturating_add(quote_amount);
            // Accumulate for batch settlement.
            self.settlement_batch.push(SettledFill {
                market,
                price: f.price,
                qty: f.qty,
                buyer,
                buyer_id,
                seller,
                seller_id,
                quote_amount,
            });
        }

        // ── Release resting slots for makers that left the book ──
        // Same accounting as `MatchingServer::execute_order` — see
        // `gone_makers` for the rules.
        for owner in gone_makers(&self.engine, &self.removed, &self.fills) {
            self.risk.dec_resting(&owner);
        }
        evict_gone_client_ids(&self.engine, &self.fills, &self.removed, &mut self.order_client_ids);

        // ── Release the reservation (buys) ──────────────────────
        // Fills pay their actual price (improvement refunded), a
        // surviving resting remainder keeps `price × resting_qty`
        // held (exactly what cancel refunds — once), dead
        // remainders come back in full.
        if reservation > 0 {
            let refund =
                buy_reservation_refund(reservation, req.price.0, &outcome, taker_fill_cost);
            if refund > 0 {
                self.balances.credit(&req.owner, refund);
            }
        }

        // ── Build response ──────────────────────────────────────
        let fills_count = u32::try_from(self.fills.len()).unwrap_or(u32::MAX);
        match outcome {
            OrderOutcome::Filled => OrderResponse::filled(fills_count),
            OrderOutcome::Resting { order_id, .. } => {
                // Track the new resting order for the resting-cap
                // risk check.
                self.risk.inc_resting(&req.owner);
                // Bind the book id to the request nonce (see
                // `MatchingServer::execute_order`).
                self.order_client_ids.insert(order_id.0, req.nonce);
                OrderResponse::resting(order_id, fills_count)
            }
            OrderOutcome::CanceledRemainder { .. } => {
                // IOC/FOK entry or STP self-touch: the remainder is
                // DEAD, not resting — no resting counter, and the
                // response must not claim a live order id.
                OrderResponse::filled(fills_count)
            }
            OrderOutcome::Killed => OrderResponse::rejected(RejectReason::Killed),
            OrderOutcome::Rejected(_) => {
                self.engine_rejections += 1;
                OrderResponse::rejected(RejectReason::EngineRejected)
            }
        }
    }

    /// Submit a pre-authenticated action — see
    /// [`MatchingServer::submit_verified_action`]. The token proves
    /// signature + owner binding; the shared nonce check still runs
    /// here so a captured action is consumed exactly once.
    pub(crate) fn submit_verified_action(
        &mut self,
        req: protocol::VerifiedAction,
    ) -> OrderResponse {
        self.orders_processed += 1;
        let req = req.request();
        if !self.check_nonce(&req.owner, req.nonce) {
            return OrderResponse::rejected(RejectReason::StaleNonce);
        }
        let action = protocol::action_request_to_order_action(req);
        self.execute_action(&action)
    }

    /// Dispatch an authenticated, nonce-consumed action. Private —
    /// reachable only via `submit_action`.
    pub(crate) fn execute_action(&mut self, action: &OrderAction) -> OrderResponse {
        match action {
            OrderAction::Cancel { order_id, owner } => self.cancel_order(*order_id, *owner),
            OrderAction::Amend { order_id, owner, new_price, new_qty } => {
                self.amend_order(*order_id, *owner, *new_price, *new_qty)
            }
            OrderAction::Replace { order_id, owner, new_order } => {
                self.replace_order(*order_id, *owner, new_order)
            }
        }
    }

    /// Cancel a resting order (multi-market path).
    pub(crate) fn cancel_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
    ) -> OrderResponse {
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        self.risk.dec_resting(&canceled.owner);
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        OrderResponse::filled(0)
    }

    /// Amend a resting order (multi-market path).
    pub(crate) fn amend_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
        new_price: Price,
        new_qty: Qty,
    ) -> OrderResponse {
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        self.risk.dec_resting(&canceled.owner);
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        let req = OrderRequest {
            market: 0,
            side: canceled.side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: new_price,
            qty: new_qty,
            nonce: 0,
            owner: canceled.owner,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        // Internal resubmit — authenticated by the enclosing action.
        self.execute_order(&req)
    }

    /// Replace a resting order (multi-market path).
    pub(crate) fn replace_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
        new_order: &OrderRequest,
    ) -> OrderResponse {
        match self.engine.order_owner(trading::OrderId(order_id)) {
            Some(real_owner) if real_owner == owner => {}
            _ => {
                self.engine_rejections += 1;
                return OrderResponse::rejected(RejectReason::OrderNotFound);
            }
        }
        let Ok(canceled) = self.engine.cancel(trading::OrderId(order_id)) else {
            self.engine_rejections += 1;
            return OrderResponse::rejected(RejectReason::OrderNotFound);
        };
        self.risk.dec_resting(&canceled.owner);
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        // Internal resubmit — authenticated by the enclosing action.
        self.execute_order(new_order)
    }
}
