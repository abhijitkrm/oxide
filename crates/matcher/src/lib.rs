//! Off-chain matching server — the HFT-grade order entry layer.
//!
//! This crate implements the off-chain matching architecture
//! (plan.md §9.5): a high-performance matching server that runs the
//! [`trading::MatchingEngine`] directly, accepts orders via four
//! protocols (binary TCP, WebSocket, JSON-RPC, FIX), enforces
//! pre-trade balance checks on every order, and batches fills for
//! on-chain settlement.
//!
//! # Architecture
//!
//! ```text
//!                       ┌─────────────────────────────┐
//!   Binary TCP ──────►  │                             │
//!   WebSocket ──────►  │   Protocol Adapters          │
//!   JSON-RPC ───────►  │   (decode → OrderRequest)     │
//!   FIX ────────────►  │                             │
//!                       └──────────┬──────────────────┘
//!                                  │
//!                                  ▼
//!                       ┌─────────────────────────────┐
//!                       │   Balance Cache              │
//!                       │   (HashMap<Address, u64>)    │
//!                       │   Pre-check: reject buys     │
//!                       │   with insufficient quote    │
//!                       └──────────┬──────────────────┘
//!                                  │
//!                                  ▼
//!                       ┌─────────────────────────────┐
//!                       │   MatchingEngine             │
//!                       │   (19M fills/s raw)           │
//!                       └──────────┬──────────────────┘
//!                                  │
//!                                  ▼
//!                       ┌─────────────────────────────┐
//!                       │   Fill Buffer                 │
//!                       │   → Update balance cache      │
//!                       │   → Batch for settlement       │
//!                       └─────────────────────────────┘
//! ```
//!
//! # Balance checks (anti-spam)
//!
//! Every order is balance-checked before matching:
//! - **Buy orders:** the buyer's available quote balance must cover
//!   `price * qty / PRICE_SCALE` (the notional in scale-6 quote).
//!   If insufficient, the order is rejected with `Reject::InsufficientBalance`.
//! - **Sell orders:** v0 does not track base-asset balances (the
//!   exchange module's v0 behaviour). Sell orders are accepted
//!   without a pre-check; settlement credits the seller on fill.
//!
//! The balance cache is a flat `HashMap<[u8; 20], u64>` — O(1)
//! lookup, no allocation (fixed 20-byte keys, not `Vec<u8>`). This
//! is ~10x faster than a generic `BTreeMap<Vec<u8>, Vec<u8>>` for
//! the hot path.
//!
//! # Settlement
//!
//! Fills are accumulated in a batch buffer. Every `batch_interval`
//! (default 100ms), the batch is sealed and submitted as a single
//! settlement transaction to consensus. Validators verify the
//! batch (check balances, fill consistency) but do not re-match.

#![allow(clippy::module_name_repetitions)]

pub mod balance;
pub mod fix;
pub mod jsonrpc;
pub mod market_data;
pub mod protocol;
pub mod ring;
pub mod risk;
pub mod server;
pub mod ws;

pub use balance::{AtomicBalanceCache, BalanceCache, DEFAULT_SHARD_COUNT, ShardedBalanceCache};
pub use protocol::{
    ActionRequest, ActionType, OrderAction, OrderRequest, OrderResponse, RejectReason,
};
pub use ring::{SpscReceiver, SpscSender, Wakeup, spsc_ring, spsc_ring_with_wakeup};
pub use risk::{RiskConfig, RiskDecision, RiskEngine};

use primitives::fixed::{Price, Qty};
use std::collections::HashMap;
use std::sync::Arc;
use trading::{
    DenseBook, FillEvent, MarketConfig, MatchingEngine, NewOrder, OrderOutcome, OrderType, Side,
    StpMode, TimeInForce,
};

/// The price scale divisor: notional = price * qty / `PRICE_SCALE`.
/// Matches `modules/exchange/src/lib.rs`.
const PRICE_SCALE: u128 = 100_000_000;

/// Settlement arithmetic for a buy order's reservation (C6).
///
/// `reservation` was debited at admission: `limit_price × qty` for
/// limit buys, the ask-ladder sweep bound for market buys — always
/// the WORST CASE the taker could owe. This returns how much of it
/// comes back:
///
/// - Fills cost their ACTUAL execution price (`fill.price`), not the
///   limit — the difference is taker price improvement, refunded
///   here. Each fill's quote is truncated at `/PRICE_SCALE` exactly
///   the way the seller credits are computed, so buyer-out equals
///   seller-in to the unit (no rounding drift).
/// - A `Resting` outcome keeps `limit_price × resting_qty` held —
///   precisely the amount `cancel_order` refunds later, exactly once.
///   The resting remainder IS the reservation; the book is the
///   reservation ledger.
/// - Every other terminal outcome (`Filled`, `Killed`,
///   `CanceledRemainder`, `Rejected`, engine `Err`) holds nothing —
///   an IOC/FOK remainder is dead, not resting, so its reservation
///   comes back in full.
///
/// `saturating_sub` guards the refund against arithmetic drift: a
/// refund can never exceed what was actually debited.
fn buy_reservation_refund(
    reservation: u64,
    limit_price: u64,
    outcome: &OrderOutcome,
    fills: &[FillEvent],
) -> u64 {
    let fill_cost: u64 = fills
        .iter()
        .map(|f| {
            u64::try_from(u128::from(f.price.0) * u128::from(f.qty.0) / PRICE_SCALE)
                .unwrap_or(u64::MAX)
        })
        .sum();
    let held = match outcome {
        OrderOutcome::Resting { resting_qty, .. } => {
            u64::try_from(u128::from(limit_price) * u128::from(resting_qty.0) / PRICE_SCALE)
                .unwrap_or(u64::MAX)
        }
        _ => 0,
    };
    reservation.saturating_sub(fill_cost.saturating_add(held))
}

/// Owners whose resting orders left the book during a sweep —
/// deduplicated so each releases its resting-count slot exactly
/// once. Two sources:
///
/// - Reported removals with nothing left (`remaining == 0`): STP
///   and cap removals. A removal with `remaining > 0` is only a
///   decrement — the order still rests and keeps its slot.
/// - Fill-exhausted makers: a fill event reports the trade but
///   nothing says "the order ended", so a maker absent from the
///   engine's id map after the sweep is gone. Without this, every
///   fully filled maker leaked its slot and active traders hit the
///   per-account resting cap on phantom counts.
///
/// A maker can appear in both sources (a capped fill followed by a
/// cap removal of the dead remainder) — the order-id dedup makes
/// the release exactly-once.
fn gone_makers(
    engine: &MatchingEngine,
    removed: &[trading::MakerRemoval],
    fills: &[FillEvent],
) -> Vec<primitives::Address> {
    let mut gone: Vec<(u64, primitives::Address)> = Vec::with_capacity(removed.len() + fills.len());
    for r in removed {
        if r.remaining == 0 {
            gone.push((r.order_id.0, r.owner));
        }
    }
    for f in fills {
        let exhausted = engine.order_owner(f.maker_order_id).is_none();
        if exhausted && !gone.iter().any(|(id, _)| *id == f.maker_order_id.0) {
            gone.push((f.maker_order_id.0, f.maker_owner));
        }
    }
    gone.into_iter().map(|(_, owner)| owner).collect()
}

/// Resolve a book fill's settlement attribution into the
/// `(buyer, seller, buyer_id, seller_id)` tuple a `SettledFill`
/// carries. The taker's client id is its request nonce (the same
/// value the owner registers the order under on-chain); the maker's
/// comes from the resting-order map. A missing maker entry yields
/// 0 — the on-chain leg will fail its order lookup rather than
/// settle against a guessed order.
fn fill_parties(
    f: &FillEvent,
    taker_nonce: u64,
    order_client_ids: &HashMap<u64, u64>,
) -> (primitives::Address, primitives::Address, u64, u64) {
    let maker_id = order_client_ids.get(&f.maker_order_id.0).copied().unwrap_or(0);
    if f.taker_side == Side::Buy {
        (f.taker_owner, f.maker_owner, taker_nonce, maker_id)
    } else {
        (f.maker_owner, f.taker_owner, maker_id, taker_nonce)
    }
}

/// Drop the client-id bindings of every order the last match left
/// out of the book — makers exhausted by fills (no `order_owner`
/// left) and non-fill removals the sweep reported with zero
/// remaining. Cancels evict directly at their own site. Shared by
/// `MatchingServer` and `MarketWorker`.
fn evict_gone_client_ids(
    engine: &MatchingEngine,
    fills: &[FillEvent],
    removed: &[trading::MakerRemoval],
    order_client_ids: &mut HashMap<u64, u64>,
) {
    for f in fills {
        if engine.order_owner(f.maker_order_id).is_none() {
            order_client_ids.remove(&f.maker_order_id.0);
        }
    }
    for r in removed {
        if r.remaining == 0 {
            order_client_ids.remove(&r.order_id.0);
        }
    }
}

/// A matched fill with settlement attribution.
#[derive(Debug, Clone, Copy)]
pub struct SettledFill {
    /// Market the fill executed on — included in the on-chain
    /// batch-settle leg so the chain can validate against the
    /// market's config.
    pub market: u16,
    /// Execution price (scale-8).
    pub price: Price,
    /// Traded quantity (scale-6).
    pub qty: Qty,
    /// Buyer address.
    pub buyer: primitives::Address,
    /// The buyer's client order id — the per-account request nonce
    /// of their order request, which is also the `client_id` they
    /// registered the order under on-chain. The batch-settle leg
    /// names `(buyer, buyer_id)` so the chain can resolve the
    /// registered order this fill consumes.
    pub buyer_id: u64,
    /// Seller address.
    pub seller: primitives::Address,
    /// The seller's client order id (same convention as
    /// `buyer_id`).
    pub seller_id: u64,
    /// Quote amount debited from buyer / credited to seller (scale-6)
    /// in the off-chain cache — recorded for reconciliation; the
    /// on-chain batch settles a recomputed amount, not this value.
    pub quote_amount: u64,
}

/// Per-owner nonce tracker — the replay gate at the admission
/// boundary.
///
/// Each admitted order/action carries a nonce strictly greater than
/// the last seen for its owner; anything at-or-below is a replay and
/// is rejected with `StaleNonce`. The nonce is consumed BEFORE any
/// later check fails (same semantics as Ethereum account nonces: a
/// transaction consumes its nonce even if it reverts), so a captured
/// request can never be replayed, including a rejected one.
///
/// `MatchingServer` owns one directly (single writer); the
/// multi-market workers share one `Arc<Mutex<NonceTracker>>` because
/// nonces are per-ACCOUNT, not per-market — an owner trading on
/// market A must not be able to replay the same nonce on market B.
struct NonceTracker {
    /// owner → last consumed nonce.
    last_seen: HashMap<primitives::Address, u64>,
    /// Optional durable checkpoint. Without it, every restart resets
    /// the replay gate to empty — ANY captured signed request is
    /// then replayable once (the first request from an owner is
    /// always accepted). With a store attached, the replay window
    /// shrinks to the entries consumed since the last flush.
    store: Option<NonceStore>,
    /// Mutations since the last successful flush.
    dirty: u32,
}

/// Consumed-nonce mutations between durable checkpoints. Chosen to
/// bound crash loss to ~64 admissions while keeping writes rare —
/// `seal_batch` (the settler cadence) also flushes, so a graceful
/// run checkpoints far more often than this bound.
const NONCE_FLUSH_EVERY: u32 = 64;

impl NonceTracker {
    /// Create an empty tracker.
    fn new() -> Self {
        Self { last_seen: HashMap::new(), store: None, dirty: 0 }
    }

    /// Attach a durable checkpoint file, loading any previously
    /// persisted nonces. Must be called before serving traffic —
    /// entries already consumed are NOT loaded again.
    ///
    /// # Errors / panics
    ///
    /// Panics if the file exists but does not decode — a corrupt
    /// replay DB must fail closed (refuse to start) rather than
    /// silently reopen the replay window for every account.
    fn attach_store(&mut self, path: std::path::PathBuf) {
        let loaded = NonceStore::load(&path)
            .unwrap_or_else(|e| panic!("nonce store at {} is corrupt: {e}", path.display()));
        // Max-merge, never overwrite downward: a checkpoint is a
        // LOWER bound of consumed nonces. Regressing a watermark
        // would let already-consumed requests replay.
        for (owner, nonce) in loaded {
            self.last_seen.entry(owner).and_modify(|e| *e = (*e).max(nonce)).or_insert(nonce);
        }
        self.store = Some(NonceStore { path });
        self.dirty = 0;
    }

    /// Returns `true` and consumes `nonce` iff it is strictly
    /// greater than the last seen for `owner`; `false` on replay
    /// (the map is not modified). The first request from a new
    /// owner is always accepted.
    fn check_and_consume(&mut self, owner: &primitives::Address, nonce: u64) -> bool {
        if let Some(&last) = self.last_seen.get(owner) {
            if nonce <= last {
                return false;
            }
        }
        self.last_seen.insert(*owner, nonce);
        self.dirty += 1;
        if self.dirty >= NONCE_FLUSH_EVERY {
            self.flush();
        }
        true
    }

    /// Persist consumed nonces if a store is attached. Best-effort:
    /// a failed write is ignored (the in-memory gate keeps working;
    /// only the restart boundary widens).
    fn flush(&mut self) {
        let Some(store) = &self.store else { return };
        if store.save(&self.last_seen).is_ok() {
            self.dirty = 0;
        }
    }
}

/// A file-backed checkpoint of consumed nonces — bounds the
/// restart replay window to the flush interval instead of forever.
///
/// Format (little-endian, strict):
/// `[magic "OXNC"][version u32=1][count u32][entry × count]` where
/// `entry = owner[20] ‖ nonce u64` (28 bytes). Writes go to a temp
/// file then `rename` for atomicity — a crash mid-write can never
/// leave a torn checkpoint.
struct NonceStore {
    /// Checkpoint file path (`<path>.tmp` is the write scratch).
    path: std::path::PathBuf,
}

impl NonceStore {
    /// Checkpoint format magic + version for strict decode.
    const MAGIC: &'static [u8; 4] = b"OXNC";
    /// Current format version.
    const VERSION: u32 = 1;
    /// Hard bound on stored accounts — a larger count means the file
    /// is corrupt or hostile; the decode allocates nothing up front.
    const MAX_ENTRIES: usize = 8_000_000;
    /// Header size: magic(4) + version(4) + count(4).
    const HEADER: usize = 12;
    /// Entry size: owner(20) + nonce(8).
    const ENTRY: usize = 28;

    /// Read the checkpoint. Missing file = empty state (first run).
    /// Returns `Err` on ANY structural violation — the caller fails
    /// closed rather than resetting the replay gate.
    fn load(path: &std::path::Path) -> Result<Vec<(primitives::Address, u64)>, String> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("read failed: {e}")),
        };
        if bytes.len() < Self::HEADER {
            return Err(format!("truncated header ({} bytes)", bytes.len()));
        }
        if &bytes[0..4] != Self::MAGIC {
            return Err("bad magic".to_string());
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or_default());
        if version != Self::VERSION {
            return Err(format!("unsupported version {version}"));
        }
        let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or_default()) as usize;
        if count > Self::MAX_ENTRIES {
            return Err(format!("count {count} exceeds bound"));
        }
        if bytes.len() != Self::HEADER + count * Self::ENTRY {
            return Err(format!("size mismatch: {} bytes for {count} entries", bytes.len()));
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let off = Self::HEADER + i * Self::ENTRY;
            let mut owner = [0u8; 20];
            owner.copy_from_slice(&bytes[off..off + 20]);
            let nonce =
                u64::from_le_bytes(bytes[off + 20..off + 28].try_into().unwrap_or_default());
            out.push((primitives::Address(owner), nonce));
        }
        Ok(out)
    }

    /// Serialize and atomically replace the checkpoint.
    fn save(&self, last_seen: &HashMap<primitives::Address, u64>) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(12 + last_seen.len() * 28);
        buf.extend_from_slice(Self::MAGIC);
        buf.extend_from_slice(&Self::VERSION.to_le_bytes());
        buf.extend_from_slice(&u32::try_from(last_seen.len()).unwrap_or(u32::MAX).to_le_bytes());
        for (owner, nonce) in last_seen {
            buf.extend_from_slice(&owner.0);
            buf.extend_from_slice(&nonce.to_le_bytes());
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &buf)?;
        // Fsync the temp file before the rename so the checkpoint is
        // durable, not just renamed.
        if let Ok(f) = std::fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        std::fs::rename(&tmp, &self.path)
    }
}

/// The core matching server — owns the matching engine, balance
/// cache, and fill buffer. Single-threaded by design (the matching
/// engine takes `&mut self`); protocol adapters feed orders via a
/// channel or call `submit_order` directly.
///
/// # The admission boundary
///
/// `submit_order` / `submit_verified` / `submit_action` are THE
/// mandatory admission points — every wire path (TCP single/batch,
/// JSON-RPC, FIX, WS, ring, multi-market) and every direct caller
/// funnels through them. The sequence is always:
/// `authenticate → replay-check → risk → reserve → match`. There is
/// no public path that skips authentication: [`protocol::VerifiedOrder`]
/// is constructible only by passing [`protocol::verify_order`], and
/// internal resubmits (amend/replace) use the private
/// `execute_order` — safe only because the enclosing signed action
/// was already authenticated.
pub struct MatchingServer {
    /// The matching engine (one market in v0).
    engine: MatchingEngine,
    /// The balance cache — fast `HashMap`, 1M+ accounts.
    balances: BalanceCache,
    /// Pre-trade risk engine (rate limits, fat-finger, size caps).
    risk: RiskEngine,
    /// Reusable fill buffer — zero alloc after the first order.
    fills: Vec<FillEvent>,
    /// Total orders processed.
    orders_processed: u64,
    /// Total fills produced.
    fills_produced: u64,
    /// Total orders rejected by balance check.
    balance_rejections: u64,
    /// Total orders rejected by engine.
    engine_rejections: u64,
    /// Total orders rejected by the risk engine.
    risk_rejections: u64,
    /// Total requests rejected by authentication (bad signature or
    /// owner not derived from the request's public key).
    auth_rejections: u64,
    /// The pending settlement batch.
    settlement_batch: Vec<SettledFill>,
    /// Per-owner replay gate (see [`NonceTracker`]).
    nonces: NonceTracker,
    /// Book order id → the client order id (request nonce) of the
    /// owner who placed it — kept for every resting order so a fill
    /// can carry the `(owner, client_id)` key the on-chain
    /// registered-order authorization model settles against.
    /// Entries are inserted when an order rests and evicted when it
    /// leaves the book (filled, cancelled, or removed).
    order_client_ids: HashMap<u64, u64>,
    /// Millisecond time source for the rate limiter — the limiter's
    /// sliding window only has meaning against real elapsed time.
    /// Injectable so tests control the window deterministically and
    /// deployments can swap in a monotonic clock.
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// The chain ID order/action signatures are verified against —
    /// configured per deployment so a signature produced for one
    /// chain can never replay on another. Defaults to the devnet
    /// [`protocol::CHAIN_ID`].
    chain_id: u64,
    /// Scratch for non-fill book removals the sweep reports —
    /// reused across orders like `fills` (zero alloc steady-state).
    removed: Vec<trading::MakerRemoval>,
}

/// Wall-clock milliseconds since the Unix epoch — the production
/// time source for risk controls. `map_or(0, …)` only if the system
/// clock predates the epoch (already handled as "no elapsed time").
fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl MatchingServer {
    /// Create a new matching server with the given market config and
    /// initial balance cache capacity.
    ///
    /// # Panics
    ///
    /// Panics if the matching engine or order book cannot be created
    /// from the given config (e.g. invalid tick/lot sizes).
    pub fn new(cfg: MarketConfig, balance_capacity: usize) -> Self {
        let engine = MatchingEngine::new(cfg, DenseBook::new(cfg).expect("book creation"))
            .expect("engine creation");
        Self {
            engine,
            balances: BalanceCache::with_capacity(balance_capacity),
            risk: RiskEngine::with_defaults(),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(10_000),
            nonces: NonceTracker::new(),
            order_client_ids: HashMap::with_capacity(65_536),
            clock: Arc::new(wall_clock_ms),
            chain_id: protocol::CHAIN_ID,
            removed: Vec::with_capacity(64),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
            auth_rejections: 0,
        }
    }

    /// Create a new matching server with a custom risk-engine
    /// configuration. Use this when you need non-default rate
    /// limits, size caps, or price bands.
    ///
    /// # Panics
    ///
    /// Panics if the matching engine or order book cannot be created
    /// from the given config.
    pub fn with_risk_config(
        cfg: MarketConfig,
        balance_capacity: usize,
        risk_config: RiskConfig,
    ) -> Self {
        let engine = MatchingEngine::new(cfg, DenseBook::new(cfg).expect("book creation"))
            .expect("engine creation");
        Self {
            engine,
            balances: BalanceCache::with_capacity(balance_capacity),
            risk: RiskEngine::new(risk_config),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(10_000),
            nonces: NonceTracker::new(),
            order_client_ids: HashMap::with_capacity(65_536),
            clock: Arc::new(wall_clock_ms),
            chain_id: protocol::CHAIN_ID,
            removed: Vec::with_capacity(64),
            orders_processed: 0,
            fills_produced: 0,
            balance_rejections: 0,
            engine_rejections: 0,
            risk_rejections: 0,
            auth_rejections: 0,
        }
    }

    /// Swap in a different millisecond time source for the rate
    /// limiter — tests inject a controllable clock; deployments can
    /// supply a monotonic source.
    pub fn set_clock(&mut self, clock: Arc<dyn Fn() -> u64 + Send + Sync>) {
        self.clock = clock;
    }

    /// The chain ID order and action signatures are verified
    /// against.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Configure the chain ID signatures verify against. Call this
    /// before serving traffic — signatures made under a different
    /// chain ID verify as forgeries (rejected `BadSignature`), which
    /// is exactly the cross-chain replay boundary.
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.chain_id = chain_id;
    }

    /// Attach a durable checkpoint file for consumed nonces. Without
    /// it the replay gate is memory-only: every restart forgets all
    /// consumed nonces, so ANY captured signed request becomes
    /// replayable once. With a store attached, the replay window
    /// shrinks to the entries consumed since the last checkpoint —
    /// flushed every [`NONCE_FLUSH_EVERY`] admissions and on every
    /// [`Self::seal_batch`]. Call before serving traffic.
    ///
    /// # Panics
    ///
    /// Panics if the file exists but is corrupt — a replay DB that
    /// can't be verified must fail closed, not silently reset.
    pub fn set_nonce_store(&mut self, path: std::path::PathBuf) {
        self.nonces.attach_store(path);
    }

    /// Fund an account with the given quote balance. Called during
    /// setup or when the balance cache is synced from the ledger.
    pub fn fund_account(&mut self, addr: &primitives::Address, amount: u64) {
        self.balances.set(addr, amount);
    }

    /// Get an account's available balance.
    pub fn balance(&self, addr: &primitives::Address) -> u64 {
        self.balances.get(addr)
    }

    /// Submit an order for matching — THE admission boundary for new
    /// orders.
    ///
    /// The pipeline is `authenticate → replay-check → risk → reserve
    /// → match → settle`:
    /// 1. Authentication ([`protocol::verify_order`]): the Ed25519
    ///    signature must verify AND the claimed `owner` must equal
    ///    the address derived from the request's public key.
    /// 2. Replay check: the nonce must be strictly greater than the
    ///    owner's last consumed nonce.
    /// 3. Risk-engine checks (rate limit, size cap, price band,
    ///    resting cap).
    /// 4. Balance reservation (buy orders only).
    /// 5. Matching via `MatchingEngine::place`.
    /// 6. Settlement (update balance cache, accumulate fills).
    ///
    /// Every wire path funnels through here or through
    /// [`Self::submit_verified`] (which only accepts a
    /// [`protocol::VerifiedOrder`] — constructible solely by passing
    /// the same authentication). There is no public path that skips
    /// authentication.
    ///
    /// Returns the order response (filled, resting, or rejected).
    pub fn submit_order(&mut self, req: &OrderRequest) -> OrderResponse {
        if let Some(verified) = protocol::VerifiedOrder::with_chain_id(*req, self.chain_id) {
            self.submit_verified(&verified)
        } else {
            self.auth_rejections += 1;
            OrderResponse::rejected(RejectReason::BadSignature)
        }
    }

    /// Submit an already-authenticated order — the entry point for
    /// ring channels and internal call sites that hold a
    /// [`protocol::VerifiedOrder`] (which can only be constructed by
    /// passing [`protocol::verify_order`], so this path cannot be
    /// reached with a forged order).
    ///
    /// The transport threads authenticate in parallel; this function
    /// performs the remaining boundary steps (replay-check → risk →
    /// reserve → match → settle) on the single matcher thread.
    pub fn submit_verified(&mut self, req: &protocol::VerifiedOrder) -> OrderResponse {
        self.orders_processed += 1;
        let req = req.request();

        // Replay check: each order must carry a nonce strictly
        // greater than the last seen for this owner. A replayed
        // order (same or lower nonce) is rejected with `StaleNonce`
        // before any balance reservation or engine state change.
        // This prevents a captured signed order from being
        // resubmitted. The nonce is consumed even if a later check
        // rejects — a spent nonce can never be replayed (same
        // semantics as Ethereum account nonces).
        if !self.nonces.check_and_consume(&req.owner, req.nonce) {
            return OrderResponse::rejected(RejectReason::StaleNonce);
        }

        self.execute_order(req)
    }

    /// Execute an authenticated, nonce-consumed order: risk →
    /// reserve → match → settle. Private — called by
    /// `submit_verified` and by the internal amend/replace resubmits
    /// (which are authenticated by their enclosing signed action and
    /// must NOT consume a second nonce).
    fn execute_order(&mut self, req: &OrderRequest) -> OrderResponse {
        // ── Risk-engine checks ───────────────────────────────────
        // Run before the balance check so we reject spam and
        // fat-finger orders without reserving any balance. The
        // timestamp comes from the injected clock — the rate
        // limiter's sliding window measures ELAPSED time; feeding it
        // the order counter would make an account's allowance depend
        // on how fast the whole venue trades, not on real seconds.
        // The mid-price comes from the engine's best bid/ask.
        let mid = match (self.engine.best_bid(), self.engine.best_ask()) {
            (Some((bid, _)), Some((ask, _))) => u64::midpoint(bid.0, ask.0),
            _ => 0, // no mid available — skip price-band check
        };
        let now_ms = (self.clock)();
        let decision = self.risk.check(&req.owner, now_ms, req.price.0, req.qty.0, mid);
        if let RiskDecision::Reject(reason) = decision {
            self.risk_rejections += 1;
            return OrderResponse::rejected(reason);
        }

        // ── Reservation (buy orders only) ───────────────────────
        // Every buy debits its WORST-CASE quote cost up front:
        // limit buys reserve `price × qty` (fills can only cost
        // less — price improvement is refunded at settlement), and
        // market buys reserve the ask-ladder sweep bound from
        // `sweep_cost` (a market order pays whatever the book
        // charges — skipping this reservation let unfunded takers
        // drain makers, C6). The reservation is released piecewise
        // at settlement via `buy_reservation_refund`: fills pay
        // their actual price, a surviving resting remainder keeps
        // `price × resting_qty` held (exactly what cancel refunds
        // later — once), and dead remainders come back in full.
        let mut reservation = 0u64;
        if req.side == Side::Buy {
            let notional = match req.order_type {
                OrderType::Market => self.engine.sweep_cost(Side::Buy, req.qty.0, None),
                _ => u128::from(req.price.0) * u128::from(req.qty.0),
            };
            let quote_needed = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            let available = self.balances.get(&req.owner);
            if available < quote_needed {
                self.balance_rejections += 1;
                return OrderResponse::rejected(RejectReason::InsufficientBalance);
            }
            self.balances.debit(&req.owner, quote_needed);
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
        // `ObserveRemovals` never restricts a fill — it reports the
        // non-fill removals the resting-count bookkeeping below must
        // consume, so a maker deleted without a fill still releases
        // its resting slot.
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
        // For each fill: credit the seller. The buyer's side of the
        // payment comes out of the reservation debited at admission
        // (buy orders) — see `buy_reservation_refund` below. Sell
        // takers simply receive quote; their fills' buyers are
        // resting makers whose own reservations paid at rest.
        for f in &self.fills {
            self.fills_produced += 1;
            let notional = u128::from(f.price.0) * u128::from(f.qty.0);
            let quote_amount = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            // The taker's client id is this request's nonce; the
            // maker's resolves through the resting-order map (see
            // `fill_parties` for the fallback rules).
            let (buyer, seller, buyer_id, seller_id) =
                fill_parties(f, req.nonce, &self.order_client_ids);
            // Credit the seller.
            self.balances.credit(&seller, quote_amount);
            // Accumulate for batch settlement.
            self.settlement_batch.push(SettledFill {
                market: self.engine.config().market_id,
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
        // Fills and reported removals both retire resting orders;
        // `gone_makers` attributes each departure to its owner,
        // exactly once (see the helper for the accounting rules).
        for owner in gone_makers(&self.engine, &self.removed, &self.fills) {
            self.risk.dec_resting(&owner);
        }
        evict_gone_client_ids(&self.engine, &self.fills, &self.removed, &mut self.order_client_ids);

        // ── Release the reservation (buys) ──────────────────────
        // Everything not consumed by fills (at their actual price)
        // or held for a surviving resting remainder comes back —
        // exactly once. A resting buy keeps `price × resting_qty`
        // locked, which is what `cancel_order` refunds.
        if reservation > 0 {
            let refund = buy_reservation_refund(reservation, req.price.0, &outcome, &self.fills);
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
                // Bind the book id to the request nonce — fills
                // against this maker resolve `(owner, client_id)`
                // through this entry.
                self.order_client_ids.insert(order_id.0, req.nonce);
                OrderResponse::resting(order_id, fills_count)
            }
            OrderOutcome::Killed => {
                // FOK killed — full reservation already refunded.
                OrderResponse::rejected(RejectReason::Killed)
            }
            OrderOutcome::CanceledRemainder { .. } => {
                // IOC/FOK entry or an STP self-touch: the remainder
                // is DEAD, not resting — no resting counter, and the
                // response must not claim a live order id. Report it
                // as a terminal fill result (partial fills are
                // visible in `fills_count`).
                OrderResponse::filled(fills_count)
            }
            OrderOutcome::Rejected(_) => {
                self.engine_rejections += 1;
                OrderResponse::rejected(RejectReason::EngineRejected)
            }
        }
    }

    /// Submit an order action (cancel, amend, or replace) for
    /// processing. This is the entry point for all order-management
    /// operations beyond new-order submission.
    ///
    /// # Cancel
    ///
    /// Cancels a resting order by id. The `owner` must match the
    /// resting order's owner (authorization). On success, returns
    /// `filled(0)`. On failure (order not found or owner mismatch),
    /// returns `rejected(OrderNotFound)`. For buy orders, the
    /// reserved balance is refunded.
    ///
    /// # Amend
    ///
    /// Cancels the resting order and re-submits with the new price
    /// and/or quantity. The side is preserved from the original order;
    /// the re-submission uses Limit/GTC (resting orders are always
    /// GTC). If the cancel succeeds but the re-submit fails (e.g.
    /// insufficient balance at the new price), the original order is
    /// already canceled — this is the documented cancel-then-resubmit
    /// semantics. Returns the re-submission's response.
    ///
    /// # Replace
    ///
    /// Cancels the resting order and submits a brand-new order
    /// atomically. If the cancel fails, the new order is not
    /// submitted. Returns the new order's response (or the cancel
    /// rejection).
    ///
    /// # The admission boundary (C5)
    ///
    /// `submit_action` is THE entry point for cancel/amend/replace —
    /// it takes the wire [`ActionRequest`] directly so authentication
    /// can never be skipped: `verify_action` (signature + owner
    /// binding) runs first, then the per-owner nonce check, then
    /// dispatch. The signed action's nonce is consumed here, which
    /// fixes the previous gap where a captured action could be
    /// replayed forever.
    pub fn submit_action(&mut self, req: &ActionRequest) -> OrderResponse {
        self.orders_processed += 1;
        // Authentication gate — identical policy to `submit_order`,
        // including the configured chain ID.
        if !protocol::verify_action_with_chain_id(req, self.chain_id) {
            self.auth_rejections += 1;
            return OrderResponse::rejected(RejectReason::BadSignature);
        }
        // Replay check on the signed action's nonce — this is the
        // nonce the "cancel/amend drops the signed action nonce"
        // finding referred to: it is now consumed here, before any
        // book mutation.
        if !self.nonces.check_and_consume(&req.owner, req.nonce) {
            return OrderResponse::rejected(RejectReason::StaleNonce);
        }
        let action = protocol::action_request_to_order_action(req);
        self.execute_action(&action)
    }

    /// Dispatch an authenticated, nonce-consumed action to the
    /// matching engine. Private — reachable only via
    /// `submit_action`.
    fn execute_action(&mut self, action: &OrderAction) -> OrderResponse {
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

    /// Cancel a resting order by id, checking ownership and refunding
    /// any reserved balance for buy orders.
    fn cancel_order(&mut self, order_id: u64, owner: primitives::Address) -> OrderResponse {
        // Authorization: verify the order exists and the requester
        // owns it. This must happen BEFORE the cancel so an
        // unauthorized requester cannot remove another account's
        // order.
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
        // Decrement the resting-order counter for this account.
        self.risk.dec_resting(&canceled.owner);
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
        // Refund the reserved balance for buy orders. The canceled
        // order's `qty` is the remaining (unfilled) quantity; the
        // reserved notional was `price * qty / PRICE_SCALE`.
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        OrderResponse::filled(0)
    }

    /// Amend a resting order: cancel + re-submit with new price/qty.
    fn amend_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
        new_price: Price,
        new_qty: Qty,
    ) -> OrderResponse {
        // Authorization + cancel.
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
        // Decrement resting count for the canceled order.
        self.risk.dec_resting(&canceled.owner);
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
        // Refund the reserved balance for buy orders (the cancel side).
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        // Re-submit with the new price/qty, preserving the original
        // side. Resting orders are always GTC; use Limit/GTC for the
        // re-submission (a PostOnly order that would cross is rejected
        // by the engine, which is acceptable amend behavior).
        //
        // This is an INTERNAL resubmit: the enclosing signed action
        // was already authenticated and its nonce already consumed
        // by `submit_action`, so `execute_order` (which skips
        // authentication and the nonce check) is the correct entry —
        // not `submit_order`, which would (correctly) reject this
        // unsigned synthetic request.
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
        self.execute_order(&req)
    }

    /// Replace a resting order: cancel + submit a new order atomically.
    fn replace_order(
        &mut self,
        order_id: u64,
        owner: primitives::Address,
        new_order: &OrderRequest,
    ) -> OrderResponse {
        // Authorization + cancel. If the cancel fails, the new order
        // is NOT submitted (atomic semantics).
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
        // Decrement resting count for the canceled order.
        self.risk.dec_resting(&canceled.owner);
        // The order left the book — drop its client-id binding so a
        // stale id can never be attributed to a later order.
        self.order_client_ids.remove(&order_id);
        // Refund the reserved balance for buy orders.
        if canceled.side == Side::Buy {
            let notional = u128::from(canceled.price.0) * u128::from(canceled.qty.0);
            let refund = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            self.balances.credit(&canceled.owner, refund);
        }
        // Submit the new order via the internal path: the enclosing
        // signed action was already authenticated and its nonce
        // consumed — the replacement must not re-verify (its
        // signature is the ACTION signature, not an order signature)
        // nor consume a second nonce.
        self.execute_order(new_order)
    }

    /// Seal the current settlement batch and return it. The caller
    /// submits this batch to consensus for on-chain finalization.
    ///
    /// Also checkpoints consumed nonces — the settler's seal cadence
    /// is a natural, off-hot-path durability point for the replay
    /// gate.
    pub fn seal_batch(&mut self) -> Vec<SettledFill> {
        self.nonces.flush();
        std::mem::take(&mut self.settlement_batch)
    }

    /// Total orders processed since creation.
    pub fn orders_processed(&self) -> u64 {
        self.orders_processed
    }

    /// Total fills produced since creation.
    pub fn fills_produced(&self) -> u64 {
        self.fills_produced
    }

    /// Total orders rejected by the balance check.
    pub fn balance_rejections(&self) -> u64 {
        self.balance_rejections
    }

    /// Total orders rejected by the engine.
    pub fn engine_rejections(&self) -> u64 {
        self.engine_rejections
    }

    /// Total orders rejected by the risk engine (rate limit,
    /// fat-finger, size cap, resting cap).
    pub fn risk_rejections(&self) -> u64 {
        self.risk_rejections
    }

    /// Total requests rejected by authentication — bad signature or
    /// an `owner` not derived from the request's public key.
    pub fn auth_rejections(&self) -> u64 {
        self.auth_rejections
    }

    /// Number of resting orders in the book.
    pub fn resting_count(&self) -> u32 {
        self.engine.resting_count()
    }

    /// Number of pending fills in the settlement batch.
    pub fn pending_settlements(&self) -> usize {
        self.settlement_batch.len()
    }

    /// Get a snapshot of the server's stats.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn stats(&self) -> MatcherStats {
        MatcherStats {
            orders_processed: self.orders_processed,
            fills_produced: self.fills_produced,
            balance_rejections: self.balance_rejections,
            engine_rejections: self.engine_rejections,
            risk_rejections: self.risk_rejections,
            auth_rejections: self.auth_rejections,
            resting_count: self.engine.resting_count(),
            pending_settlements: self.settlement_batch.len(),
        }
    }
}

/// A shared, thread-safe matching server wrapper for protocol
/// adapters. The protocol handlers (TCP, WS, JSON-RPC, FIX) all
/// feed orders through a single channel to the matching server,
/// which runs on a dedicated thread.
///
/// # Performance
///
/// `SharedMatcher` uses `Mutex<MatchingServer>` — every order
/// acquires a lock. For the batch endpoint (500+ orders per lock),
/// this amortizes well. For per-order paths, use `RingMatcher`
/// instead — it eliminates the lock entirely via SPSC rings.
pub struct SharedMatcher {
    /// The inner matching server, behind a mutex. Public so the
    /// batch settler can access `seal_batch()`.
    pub inner: Arc<std::sync::Mutex<MatchingServer>>,
}

impl SharedMatcher {
    /// Create a shared matcher wrapping the given server.
    pub fn new(server: MatchingServer) -> Self {
        Self { inner: Arc::new(std::sync::Mutex::new(server)) }
    }

    /// Submit an order (called by protocol adapters). Authentication
    /// runs inside `MatchingServer::submit_order` — this path can
    /// never admit a forged order.
    ///
    /// Returns an `EngineError` rejection if the internal mutex is
    /// poisoned (a thread panicked while holding the lock). A poisoned
    /// mutex means the matching server is in an inconsistent state —
    /// the operator should restart the process.
    pub fn submit(&self, req: &OrderRequest) -> OrderResponse {
        match self.inner.lock() {
            Ok(mut guard) => guard.submit_order(req),
            Err(_) => OrderResponse::rejected(crate::protocol::RejectReason::EngineError),
        }
    }

    /// Submit an order action (cancel/amend/replace) (called by
    /// protocol adapters). Takes the wire `ActionRequest` so
    /// authentication runs inside the server — this path can never
    /// admit a forged action.
    ///
    /// Returns an `EngineError` rejection if the internal mutex is
    /// poisoned.
    pub fn submit_action(&self, req: &ActionRequest) -> OrderResponse {
        match self.inner.lock() {
            Ok(mut guard) => guard.submit_action(req),
            Err(_) => OrderResponse::rejected(crate::protocol::RejectReason::EngineError),
        }
    }

    /// The chain ID the inner server verifies signatures against —
    /// transports use it for their early (pre-dispatch) signature
    /// check so early-reject and the mandatory in-server re-verify
    /// can never disagree. Falls back to the devnet default if the
    /// mutex is poisoned.
    pub fn chain_id(&self) -> u64 {
        match self.inner.lock() {
            Ok(guard) => guard.chain_id(),
            Err(_) => crate::protocol::CHAIN_ID,
        }
    }

    /// Get a snapshot of the server's stats.
    ///
    /// Returns zeroed stats if the internal mutex is poisoned.
    pub fn stats(&self) -> MatcherStats {
        match self.inner.lock() {
            Ok(s) => MatcherStats {
                orders_processed: s.orders_processed(),
                fills_produced: s.fills_produced(),
                balance_rejections: s.balance_rejections(),
                engine_rejections: s.engine_rejections(),
                risk_rejections: s.risk_rejections(),
                auth_rejections: s.auth_rejections(),
                resting_count: s.resting_count(),
                pending_settlements: s.pending_settlements(),
            },
            Err(_) => MatcherStats::default(),
        }
    }
}

/// The seam between the batch settler and whatever owns the matching
/// server. `SharedMatcher` implements this via the mutex;
/// `RingMatcher` implements it via a control-channel command to its
/// owner thread. Either way, `seal_batch` pulls fills from THE ONE
/// order book — there is never more than one book.
pub trait BatchSealer: Send + Sync {
    /// Seal the current settlement batch. Returns the fills accrued
    /// since the last seal (empty if none).
    fn seal_batch(&self) -> Vec<SettledFill>;
}

impl BatchSealer for SharedMatcher {
    /// Seal via the mutex: lock the server, take the batch.
    ///
    /// Returns an empty vec if the inner mutex is poisoned.
    fn seal_batch(&self) -> Vec<SettledFill> {
        match self.inner.lock() {
            Ok(mut guard) => guard.seal_batch(),
            Err(_) => Vec::new(),
        }
    }
}

/// A control command sent from the protocol layer to the matcher
/// thread (via the control channel). The matcher thread services
/// these between ring polls — they never contend with order rings.
enum ControlCommand {
    /// Seal the current settlement batch and send it back via the
    /// oneshot channel. Used by the batch settler.
    Seal(std::sync::mpsc::Sender<Vec<SettledFill>>),
    /// Snapshot matcher stats and send them back via the oneshot
    /// channel. Used by monitoring.
    Stats(std::sync::mpsc::Sender<MatcherStats>),
    /// Process an order action (cancel/amend/replace) and send the
    /// response back via the oneshot channel. The wire
    /// `ActionRequest` travels to the matcher thread so
    /// authentication runs inside `MatchingServer::submit_action` —
    /// the control path can never admit a forged action.
    Action(ActionRequest, std::sync::mpsc::Sender<OrderResponse>),
}

/// A lock-free matching server using SPSC rings (LMAX Disruptor
/// pattern). Replaces `SharedMatcher`'s mutex with per-connection
/// lock-free rings — zero contention on the order submission hot path.
///
/// # Architecture
///
/// ```text
/// Conn 0 ──→ [ring 0] ──→ Matcher Thread (owns MatchingServer)
/// Conn 1 ──→ [ring 1] ──→      (reads all rings round-robin)
/// Conn 2 ──→ [ring 2] ──→      (no locks, ever)
///   ...         ...
/// Conn N ──→ [ring N] ──→
///                 ↓
///           [control channel] ← batch settler / monitoring
/// ```
///
/// Each connection pushes WHOLE BATCHES to its own `SpscRing`. The
/// matcher thread pops from all rings in round-robin order, processes
/// them via `MatchingServer::submit_order`, and pushes batch
/// responses to the per-connection response ring.
///
/// # One order book, always
///
/// The matcher thread is the SOLE owner of the `MatchingServer` —
/// there is exactly one book. The batch settler reaches the same
/// book through the control channel (`seal_batch`), never through a
/// second server instance.
///
/// # Why this is faster than Mutex
///
/// - `Mutex::lock` = atomic CAS + cache line invalidation (~20-50ns
///   when contended, ~10ns uncontended).
/// - `SpscRing::push` = one atomic store + one array write (~5ns).
/// - The matcher thread never blocks on a lock — it spins on rings.
/// - For batch requests, the matcher processes all orders in a ring
///   before moving to the next — natural batching.
pub struct RingMatcher {
    /// The order rings (one per in-flight exchange — an exclusive
    /// [`RingLease`] serializes who the connection-side producer is).
    /// Producer = lease-holding request handler,
    /// consumer = matcher thread. Each item is a WHOLE BATCH of
    /// orders (`Vec<VerifiedOrder>`) — one mpsc send per batch, not
    /// per order. This keeps the per-order overhead near zero.
    ///
    /// The ring carries `VerifiedOrder` (proof-of-authentication),
    /// not raw requests: the producer's transport thread runs the
    /// expensive signature check in parallel with other connections,
    /// while the matcher thread trusts the type — a forged order
    /// can never be placed on the ring because `VerifiedOrder` is
    /// constructible only by passing `verify_order`.
    order_rings: Vec<ring::SpscSender<Vec<protocol::VerifiedOrder>>>,
    /// The response rings (one per in-flight exchange). Producer =
    /// matcher, consumer = the lease-holding request handler. Each
    /// item is a WHOLE BATCH of responses.
    response_rings: Vec<ring::SpscReceiver<Vec<OrderResponse>>>,
    /// One exclusive-occupancy flag per ring pair. A request handler
    /// must hold the lease for the WHOLE submit→response exchange:
    /// without it, two connections landing on the same ring index
    /// interleave order batches and — worse — race on the shared
    /// response ring, so a response batch addressed to request A can
    /// be consumed by request B. `true` = a lease holder owns the
    /// ring; acquisition is a `false→true` CAS.
    ring_leases: Vec<std::sync::atomic::AtomicBool>,
    /// Wakes one lease waiter when a ring is released. Async (`Notify`)
    /// because waiters run on tokio tasks — a condvar would block an
    /// executor thread.
    lease_notify: tokio::sync::Notify,
    /// Control channel sender (protocol side). The matcher thread
    /// polls the receiver between ring polls and services seal/stats
    /// commands without touching the order rings.
    control_tx: std::sync::mpsc::Sender<ControlCommand>,
    /// The chain ID the embedded server verifies signatures
    /// against — copied at construction (the server moves to the
    /// matcher thread, so this can never diverge). Transport threads
    /// verify `VerifiedOrder` proofs with the same value.
    chain_id: u64,
    /// The matcher thread handle — its `is_finished` flag is the
    /// worker-liveness oracle for lease holders awaiting a response.
    worker_thread: std::thread::JoinHandle<()>,
}

impl RingMatcher {
    /// Create a ring-based matcher with `num_rings` ring pairs.
    /// Spawns a dedicated matcher thread that owns the
    /// `MatchingServer` and polls all rings.
    ///
    /// # Arguments
    /// - `server`: the matching server (moved to the matcher thread).
    /// - `num_rings`: number of ring pairs — the bound on
    ///   CONCURRENT submit→response exchanges (each holds an
    ///   exclusive [`RingLease`]); excess requesters wait for a
    ///   free ring rather than share one.
    /// - `ring_capacity`: capacity of each ring (power of 2).
    ///
    /// # Panics
    ///
    /// Panics if `num_rings` is 0.
    #[must_use]
    pub fn new(server: MatchingServer, num_rings: usize, ring_capacity: usize) -> Self {
        assert!(num_rings > 0, "must have at least one ring");
        // Shared wakeup signal for all rings. A push on any ring
        // signals this, waking the consumer thread from its idle
        // `wait_for_work` block. This replaces the previous
        // `std::thread::yield_now()` busy-spin that burned a full
        // CPU core at 100% when the matcher was idle.
        let shared_wakeup = Arc::new(ring::Wakeup::new());
        // Create ring pairs: (order_tx, order_rx) and (resp_tx, resp_rx).
        let mut order_senders: Vec<ring::SpscSender<Vec<protocol::VerifiedOrder>>> =
            Vec::with_capacity(num_rings);
        let mut order_receivers: Vec<ring::SpscReceiver<Vec<protocol::VerifiedOrder>>> =
            Vec::with_capacity(num_rings);
        let mut response_senders: Vec<ring::SpscSender<Vec<OrderResponse>>> =
            Vec::with_capacity(num_rings);
        let mut response_receivers: Vec<ring::SpscReceiver<Vec<OrderResponse>>> =
            Vec::with_capacity(num_rings);
        for _ in 0..num_rings {
            let (o_tx, o_rx) =
                ring::spsc_ring_with_wakeup(ring_capacity, Arc::clone(&shared_wakeup));
            let (r_tx, r_rx) =
                ring::spsc_ring_with_wakeup(ring_capacity, Arc::clone(&shared_wakeup));
            order_senders.push(o_tx);
            order_receivers.push(o_rx);
            response_senders.push(r_tx);
            response_receivers.push(r_rx);
        }

        let mut server = server;
        let chain_id = server.chain_id();
        let (control_tx, control_rx) = std::sync::mpsc::channel::<ControlCommand>();
        let thread = std::thread::spawn(move || {
            loop {
                let mut did_work = false;
                // Round-robin poll all rings.
                for (i, order_rx) in order_receivers.iter().enumerate() {
                    while let Some(batch) = order_rx.pop() {
                        // Process the WHOLE batch: submit every order
                        // back-to-back (no interleaving from other
                        // rings — the batch is atomic).
                        let responses: Vec<OrderResponse> =
                            batch.iter().map(|req| server.submit_verified(req)).collect();
                        // Push the batch response to this connection's
                        // ring. If the ring is full, spin until the
                        // client drains it. If the client disconnected
                        // (connection dropped), drop the responses —
                        // there is nowhere to send them.
                        let mut pending = responses;
                        loop {
                            match response_senders[i].push(pending) {
                                Ok(()) => break,
                                Err(crate::ring::PushError::Disconnected(_)) => {
                                    // Client gone; discard responses.
                                    break;
                                }
                                Err(crate::ring::PushError::Full(returned)) => {
                                    pending = returned;
                                    std::hint::spin_loop();
                                }
                            }
                        }
                        did_work = true;
                    }
                }
                // Service control commands (seal/stats) between ring
                // polls. These come from the batch settler and
                // monitoring — never from the order hot path.
                while let Ok(cmd) = control_rx.try_recv() {
                    match cmd {
                        ControlCommand::Seal(reply) => {
                            let batch = server.seal_batch();
                            let _ = reply.send(batch);
                        }
                        ControlCommand::Stats(reply) => {
                            let stats = MatcherStats {
                                orders_processed: server.orders_processed(),
                                fills_produced: server.fills_produced(),
                                balance_rejections: server.balance_rejections(),
                                engine_rejections: server.engine_rejections(),
                                risk_rejections: server.risk_rejections(),
                                auth_rejections: server.auth_rejections(),
                                resting_count: server.resting_count(),
                                pending_settlements: server.pending_settlements(),
                            };
                            let _ = reply.send(stats);
                        }
                        ControlCommand::Action(action, reply) => {
                            let resp = server.submit_action(&action);
                            let _ = reply.send(resp);
                        }
                    }
                    did_work = true;
                }
                if !did_work {
                    // No work on any ring — block on the shared wakeup
                    // signal until a producer pushes or the 1 ms
                    // timeout elapses. The timeout ensures the control
                    // channel (seal/stats) is still serviced
                    // regularly. This replaces the previous
                    // `std::thread::yield_now()` busy-spin that burned
                    // a full CPU core at 100% when idle.
                    order_receivers[0].wait_for_work(std::time::Duration::from_millis(1));
                }
            }
        });

        Self {
            order_rings: order_senders,
            response_rings: response_receivers,
            ring_leases: (0..num_rings)
                .map(|_| std::sync::atomic::AtomicBool::new(false))
                .collect(),
            lease_notify: tokio::sync::Notify::new(),
            control_tx,
            chain_id,
            worker_thread: thread,
        }
    }

    /// Try to take the exclusive lease on one ring pair without
    /// waiting. `hint` biases the starting index so concurrent
    /// acquirers spread across rings instead of pile-driving ring 0.
    ///
    /// Returns `None` when every ring is leased — the caller decides
    /// whether to wait ([`acquire_ring`]) or shed load.
    #[must_use]
    pub fn try_acquire_ring(&self, hint: usize) -> Option<RingLease<'_>> {
        let n = self.order_rings.len();
        let start = hint % n;
        for offset in 0..n {
            let idx = (start + offset) % n;
            if self.ring_leases[idx]
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::Acquire,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
            {
                return Some(RingLease { matcher: self, ring_idx: idx });
            }
        }
        None
    }

    /// Take the exclusive lease on one ring pair, waiting until a
    /// ring frees. The lease MUST cover the whole submit→response
    /// exchange: it is the only thing that keeps two request
    /// handlers from sharing one ring and consuming each other's
    /// responses.
    ///
    /// `hint` is the caller's round-robin counter value — used as the
    /// scan start so load spreads across rings.
    ///
    /// Fairness: waiters re-scan all rings on wake in hint order, so
    /// a busy matcher can starve an unlucky waiter under sustained
    /// saturation. That is the intended bound — `num_rings`
    /// concurrent exchanges is the system's throughput limit, and
    /// excess requests wait rather than corrupt each other.
    pub async fn acquire_ring(&self, hint: usize) -> RingLease<'_> {
        let mut hint = hint;
        loop {
            if let Some(lease) = self.try_acquire_ring(hint) {
                return lease;
            }
            // Register interest BEFORE re-checking: a release landing
            // between the failed scan and `await` would otherwise be
            // missed and the waiter could sleep with a free ring.
            let notified = self.lease_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(lease) = self.try_acquire_ring(hint) {
                return lease;
            }
            notified.await;
            // Drift the scan start so a herd of waiters doesn't all
            // pile onto the same ring after each release.
            hint = hint.wrapping_add(1);
        }
    }

    /// The chain ID signatures are verified against — transports
    /// read this to produce `VerifiedOrder` proofs the embedded
    /// server will accept.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Seal the settlement batch via a control-channel command to the
    /// matcher thread. This reads from THE SAME order book the
    /// protocols write to — there is exactly one book.
    ///
    /// Returns an empty vec if the control channel is disconnected
    /// (matcher thread died) or the reply fails.
    pub fn seal_batch(&self) -> Vec<SettledFill> {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self.control_tx.send(ControlCommand::Seal(reply_tx)).is_err() {
            return Vec::new();
        }
        reply_rx.recv().unwrap_or_default()
    }

    /// Snapshot matcher stats via a control-channel command.
    ///
    /// Returns zeroed stats if the control channel is disconnected
    /// (matcher thread died) or the reply fails.
    pub fn stats(&self) -> MatcherStats {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self.control_tx.send(ControlCommand::Stats(reply_tx)).is_err() {
            return MatcherStats::default();
        }
        reply_rx.recv().unwrap_or_default()
    }

    /// Submit an order action (cancel/amend/replace) via a
    /// control-channel command to the matcher thread. Takes the wire
    /// `ActionRequest` so authentication runs inside the server's
    /// `submit_action` — this reaches THE SAME order book the rings
    /// write to, and can never admit a forged action.
    ///
    /// Returns an `EngineError` rejection if the control channel is
    /// disconnected (matcher thread died) or the reply fails.
    pub fn submit_action(&self, action: ActionRequest) -> OrderResponse {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self.control_tx.send(ControlCommand::Action(action, reply_tx)).is_err() {
            return OrderResponse::rejected(crate::protocol::RejectReason::EngineError);
        }
        reply_rx
            .recv()
            .unwrap_or_else(|_| OrderResponse::rejected(crate::protocol::RejectReason::EngineError))
    }

    /// Get a connection's order sender (producer side of the order
    /// ring). The caller pushes WHOLE BATCHES of authenticated orders
    /// (`Vec<VerifiedOrder>`) to this ring — one push per batch, not
    /// per order. Only `VerifiedOrder`s can enter the ring, so the
    /// matcher thread never sees an unauthenticated order.
    ///
    /// CALLERS MUST HOLD the [`RingLease`] for `ring_idx` — pushing
    /// without it interleaves batches from concurrent requesters and
    /// breaks the response pairing the lease exists to guarantee.
    pub fn order_sender(&self, ring_idx: usize) -> &ring::SpscSender<Vec<protocol::VerifiedOrder>> {
        &self.order_rings[ring_idx]
    }

    /// Get a connection's response receiver (consumer side of the
    /// response ring). The caller pops WHOLE BATCHES
    /// (`Vec<OrderResponse>`) from this ring.
    ///
    /// CALLERS MUST HOLD the [`RingLease`] for `ring_idx` — the
    /// receiver is not `Clone`, but shared `&` access still lets two
    /// requesters race `pop`, and whichever loses gets the other's
    /// response batch (wrong order IDs to the wrong client).
    pub fn response_receiver(&self, ring_idx: usize) -> &ring::SpscReceiver<Vec<OrderResponse>> {
        &self.response_rings[ring_idx]
    }

    /// Number of ring pairs — the bound on concurrent in-flight
    /// exchanges (one exclusive lease each).
    pub fn num_rings(&self) -> usize {
        self.order_rings.len()
    }

    /// Whether the matcher worker thread is still running.
    ///
    /// A lease holder awaiting a response checks this to escape the
    /// wait: if the thread died mid-batch, its response senders are
    /// dropped and no response can ever arrive — the caller must
    /// bail rather than spin (and hold the ring) forever. crossbeam
    /// 0.5 has no receiver-side disconnect probe, so the
    /// `JoinHandle` is the liveness oracle.
    #[must_use]
    pub fn worker_is_alive(&self) -> bool {
        !self.worker_thread.is_finished()
    }
}

/// Exclusive ownership of one ring pair for a single
/// submit→response exchange.
///
/// Obtained from [`RingMatcher::acquire_ring`] or
/// [`RingMatcher::try_acquire_ring`]. While the guard lives, no other
/// requester can lease the same ring — the matcher thread's response
/// batch can only be popped by this holder. Release on `Drop`
/// (frees the ring and wakes one waiter), so the lease covers
/// exactly the lexical scope of the exchange — including early
/// returns and disconnect paths.
///
/// The guard borrows the `RingMatcher`; it cannot outlive the
/// matcher or move to another thread's exchange.
pub struct RingLease<'a> {
    /// The matcher that owns the leased ring (for release + notify).
    matcher: &'a RingMatcher,
    /// The leased ring pair index — pass to
    /// [`RingMatcher::order_sender`]/[`RingMatcher::response_receiver`].
    ring_idx: usize,
}

impl RingLease<'_> {
    /// The leased ring index.
    #[must_use]
    pub fn ring_idx(&self) -> usize {
        self.ring_idx
    }
}

impl Drop for RingLease<'_> {
    fn drop(&mut self) {
        // Release BEFORE notify so a woken waiter can never observe
        // the flag still held. Ordering pairs with acquire's CAS.
        self.matcher.ring_leases[self.ring_idx].store(false, std::sync::atomic::Ordering::Release);
        self.matcher.lease_notify.notify_one();
    }
}

impl BatchSealer for RingMatcher {
    /// Seal via the control channel: the matcher thread (sole owner
    /// of the book) takes the batch and replies over the oneshot.
    ///
    /// # Panics
    ///
    /// Panics if the control channel is disconnected (matcher thread
    /// died) or the reply channel fails.
    fn seal_batch(&self) -> Vec<SettledFill> {
        RingMatcher::seal_batch(self)
    }
}

/// A snapshot of matcher statistics (for monitoring/reporting).
#[derive(Debug, Clone, Copy, Default)]
#[allow(missing_docs)]
pub struct MatcherStats {
    pub orders_processed: u64,
    pub fills_produced: u64,
    pub balance_rejections: u64,
    /// Requests rejected by authentication (bad signature or owner
    /// not derived from the request's public key).
    pub auth_rejections: u64,
    pub engine_rejections: u64,
    /// Orders rejected by the risk engine (rate limit, fat-finger,
    /// size cap, resting cap).
    pub risk_rejections: u64,
    pub resting_count: u32,
    pub pending_settlements: usize,
}

// ── MultiMarketMatcher ───────────────────────────────────────────────

/// A message sent to a market worker — either a batch of orders to
/// process or a control command (seal/stats). Merging these into one
/// channel avoids the worker blocking on `work_rx.recv()` while a
/// control command waits on a separate channel.
enum MarketMessage {
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
struct MarketWork {
    /// The authenticated orders (all for this market).
    orders: Vec<protocol::VerifiedOrder>,
    /// One-shot channel for the worker to return the responses.
    response_tx: std::sync::mpsc::Sender<Vec<OrderResponse>>,
}

/// An action work item: a single order action (cancel/amend/replace)
/// routed to the correct market worker. Carries the wire
/// `ActionRequest` so the worker authenticates it inside
/// `MarketWorker::submit_action` — the same boundary as orders.
struct ActionWork {
    /// The wire action request to process.
    action: ActionRequest,
    /// One-shot channel for the worker to return the response.
    response_tx: std::sync::mpsc::Sender<OrderResponse>,
}

/// Per-worker stats (one market).
#[derive(Debug, Clone, Copy, Default)]
struct WorkerStats {
    orders_processed: u64,
    fills_produced: u64,
    balance_rejections: u64,
    engine_rejections: u64,
    risk_rejections: u64,
    auth_rejections: u64,
    resting_count: u32,
    pending_settlements: usize,
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
    market_senders: Vec<std::sync::mpsc::Sender<MarketMessage>>,
    /// Worker thread handles (kept for shutdown).
    _threads: Vec<std::thread::JoinHandle<()>>,
    /// Number of markets.
    num_markets: usize,
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
    nonces: Arc<std::sync::Mutex<NonceTracker>>,
    /// The chain ID order signatures are verified against — shared
    /// with every worker so transport-side and worker-side
    /// authentication can never disagree.
    chain_id: u64,
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
            let thread = std::thread::spawn(move || {
                MarketWorker::run(cfg, balances, nonces, clock, chain_id, rx);
            });
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
        let mut verified: Vec<protocol::VerifiedOrder> = Vec::with_capacity(orders.len());
        let mut responses: Vec<Option<OrderResponse>> = Vec::with_capacity(orders.len());
        for (i, req) in orders.into_iter().enumerate() {
            match protocol::VerifiedOrder::with_chain_id(req, self.chain_id) {
                Some(vo) => {
                    let ok = match self.nonces.lock() {
                        Ok(mut tracker) => {
                            tracker.check_and_consume(&vo.request().owner, vo.request().nonce)
                        }
                        // A poisoned nonce mutex means a worker panicked
                        // mid-check — fail closed rather than admit a
                        // possible replay.
                        Err(_) => false,
                    };
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

    /// Submit an order action (cancel/amend/replace). Takes the wire
    /// `ActionRequest` so the worker authenticates it inside
    /// `MarketWorker::submit_action` — the same mandatory boundary as
    /// order admission. Routes to market 0 (the v0 action protocol
    /// is single-market; the wire format carries no market field).
    ///
    /// Returns an `EngineError` rejection if the market worker thread
    /// has died.
    pub fn submit_action(&self, action: &ActionRequest) -> OrderResponse {
        // v0: all actions route to market 0 — the wire `ActionRequest`
        // has no market field (multi-market routing is future work).
        let market = 0;
        if market >= self.num_markets {
            return OrderResponse::rejected(RejectReason::EngineError);
        }
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        if self.market_senders[market]
            .send(MarketMessage::Action(ActionWork { action: *action, response_tx }))
            .is_err()
        {
            return OrderResponse::rejected(RejectReason::EngineError);
        }
        response_rx.recv().unwrap_or_else(|_| OrderResponse::rejected(RejectReason::EngineError))
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
        if let Ok(mut tracker) = self.nonces.lock() {
            tracker.flush();
        }
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
struct MarketWorker {
    /// The matching engine for this market (single-writer).
    engine: MatchingEngine,
    /// Shared sharded balance cache (cross-market).
    balances: Arc<AtomicBalanceCache>,
    /// Shared per-account replay gate — one sequence per owner
    /// across ALL markets (see `NonceTracker`).
    nonces: Arc<std::sync::Mutex<NonceTracker>>,
    /// Per-market risk engine (rate limits, fat-finger, size caps).
    /// Per-market rather than shared: an account's rate/resting
    /// budget is scoped to this market's book.
    risk: RiskEngine,
    /// Reusable fill buffer — zero alloc after the first order.
    fills: Vec<FillEvent>,
    /// The pending settlement batch (local to this worker).
    settlement_batch: Vec<SettledFill>,
    /// Total orders processed by this worker.
    orders_processed: u64,
    /// Total fills produced by this worker.
    fills_produced: u64,
    /// Total orders rejected by balance check.
    balance_rejections: u64,
    /// Total orders rejected by the engine.
    engine_rejections: u64,
    /// Total orders rejected by the risk engine.
    risk_rejections: u64,
    /// Total requests rejected by authentication.
    auth_rejections: u64,
    /// Millisecond time source for the rate limiter — same injection
    /// point as `MatchingServer`; threaded from the matcher that
    /// spawned this worker.
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// The chain ID action signatures are verified against —
    /// identical to the dispatching matcher's so a verified order
    /// can never be rejected downstream (and vice versa).
    chain_id: u64,
    /// Scratch for non-fill book removals the sweep reports.
    removed: Vec<trading::MakerRemoval>,
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
    fn run(
        cfg: MarketConfig,
        balances: Arc<AtomicBalanceCache>,
        nonces: Arc<std::sync::Mutex<NonceTracker>>,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        chain_id: u64,
        rx: std::sync::mpsc::Receiver<MarketMessage>,
    ) {
        let engine = MatchingEngine::new(cfg, DenseBook::new(cfg).expect("book creation"))
            .expect("engine creation");
        let mut worker = MarketWorker {
            engine,
            balances,
            nonces,
            risk: RiskEngine::with_defaults(),
            fills: Vec::with_capacity(64),
            settlement_batch: Vec::with_capacity(10_000),
            clock,
            chain_id,
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
                    let resp = worker.submit_action(&action_work.action);
                    let _ = action_work.response_tx.send(resp);
                }
                Ok(MarketMessage::Seal(reply)) => {
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
    fn process_batch(&mut self, orders: &[protocol::VerifiedOrder]) -> Vec<OrderResponse> {
        let mut responses = Vec::with_capacity(orders.len());
        for req in orders {
            responses.push(self.submit_verified(req));
        }
        responses
    }

    /// Check the shared nonce for `owner`/`nonce` — returns `false`
    /// on replay. One lock acquisition per admission.
    fn check_nonce(&self, owner: &primitives::Address, nonce: u64) -> bool {
        match self.nonces.lock() {
            Ok(mut tracker) => tracker.check_and_consume(owner, nonce),
            // A poisoned nonce mutex means a worker panicked
            // mid-check — the tracker may be inconsistent. Fail
            // closed: reject rather than admit a possible replay.
            Err(_) => false,
        }
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
    fn submit_verified(&mut self, req: &protocol::VerifiedOrder) -> OrderResponse {
        self.orders_processed += 1;
        self.execute_order(req.request())
    }

    /// Execute an authenticated, nonce-consumed order: risk →
    /// reserve → match → settle. Private — also used by the internal
    /// amend/replace resubmits (authenticated by their enclosing
    /// signed action).
    fn execute_order(&mut self, req: &OrderRequest) -> OrderResponse {
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
        // Credit the seller for each fill (cross-shard if needed).
        // The buyer's payment comes out of the reservation debited
        // at admission — released piecewise below via
        // `buy_reservation_refund`.
        for f in &self.fills {
            self.fills_produced += 1;
            let notional = u128::from(f.price.0) * u128::from(f.qty.0);
            let quote_amount = u64::try_from(notional / PRICE_SCALE).unwrap_or(u64::MAX);
            // Client-id resolution mirrors
            // `MatchingServer::execute_order` (see `fill_parties`).
            let (buyer, seller, buyer_id, seller_id) =
                fill_parties(f, req.nonce, &self.order_client_ids);
            self.balances.credit(&seller, quote_amount);
            // Accumulate for batch settlement.
            self.settlement_batch.push(SettledFill {
                market: self.engine.config().market_id,
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
            let refund = buy_reservation_refund(reservation, req.price.0, &outcome, &self.fills);
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

    /// Submit an order action (cancel/amend/replace). Takes the wire
    /// `ActionRequest` — the SAME mandatory boundary as
    /// `MatchingServer::submit_action`: `verify_action` (signature +
    /// owner binding) → shared nonce check → dispatch.
    fn submit_action(&mut self, req: &ActionRequest) -> OrderResponse {
        self.orders_processed += 1;
        if !protocol::verify_action_with_chain_id(req, self.chain_id) {
            self.auth_rejections += 1;
            return OrderResponse::rejected(RejectReason::BadSignature);
        }
        if !self.check_nonce(&req.owner, req.nonce) {
            return OrderResponse::rejected(RejectReason::StaleNonce);
        }
        let action = protocol::action_request_to_order_action(req);
        self.execute_action(&action)
    }

    /// Dispatch an authenticated, nonce-consumed action. Private —
    /// reachable only via `submit_action`.
    fn execute_action(&mut self, action: &OrderAction) -> OrderResponse {
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
    fn cancel_order(&mut self, order_id: u64, owner: primitives::Address) -> OrderResponse {
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
    fn amend_order(
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
    fn replace_order(
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

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::fixed::{Price, Qty};
    use trading::TimeInForce;

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

    /// Build a signed order for `secret`'s account.
    fn signed_req(
        secret: &crypto::ed25519::Ed25519SecretKey,
        market: u8,
        side: Side,
        nonce: u64,
        price: u64,
        qty: u64,
    ) -> OrderRequest {
        let mut req = OrderRequest {
            market,
            side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(price),
            qty: Qty(qty),
            nonce,
            owner: addr(0),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        crate::protocol::sign_order(&mut req, secret);
        req
    }

    /// Build a signed action for `secret`'s account.
    fn signed_action(
        secret: &crypto::ed25519::Ed25519SecretKey,
        action_type: ActionType,
        order_id: u64,
        nonce: u64,
    ) -> ActionRequest {
        let mut req = ActionRequest {
            action_type,
            order_id,
            new_price: Price(0),
            new_qty: Qty(0),
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            nonce,
            owner: addr(0),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        crate::protocol::sign_action(&mut req, secret);
        req
    }

    // ── C5 regression tests: the mandatory admission boundary ──────

    /// Regression (C5): `submit_order` used to execute orders with
    /// no signature verification at all — the binary-TCP single
    /// order path, JSON-RPC, FIX, and WS all submitted unverified
    /// requests. An unsigned (zero-signature) order must be rejected
    /// with `BadSignature` before any nonce/balance/book state
    /// changes.
    #[test]
    fn unsigned_order_rejected_with_bad_signature() {
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&addr(1), 1_000_000_000);

        let req = OrderRequest {
            market: 0,
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            owner: addr(1),
            nonce: 0,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let resp = server.submit_order(&req);
        assert!(resp.rejected, "unsigned order must be rejected");
        assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
        assert_eq!(server.resting_count(), 0, "no order may reach the book");
    }

    /// Regression (C5): a validly-signed order whose `owner` is NOT
    /// derived from the signing key must be rejected — the signature
    /// alone does not prove the key controls the claimed account.
    #[test]
    fn signed_order_with_foreign_owner_rejected() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (secret, _) = test_account(1);
        server.fund_account(&addr(0x77), 1_000_000_000); // the victim

        // Attacker signs a real order but claims the victim's owner.
        let mut req = signed_req(&secret, 0, Side::Buy, 1, 1_500_000_000, 1_000);
        req.owner = addr(0x77);
        // Re-sign so the signature covers the claimed owner verbatim —
        // this is the attack the owner-binding check exists to stop.
        let msg = crate::protocol::signing_message(&req);
        req.signature = crypto::ed25519::sign_message(&secret, &msg).to_bytes();

        let resp = server.submit_order(&req);
        assert!(resp.rejected);
        assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
        assert_eq!(server.balance(&addr(0x77)), 1_000_000_000, "victim balance untouched");
    }

    /// A properly signed order (owner derived from the key) passes
    /// the boundary and matches.
    #[test]
    fn signed_order_accepted_and_matched() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, _seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&buyer, 1_000_000_000);

        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&taker);
        assert!(!resp.rejected, "authentic order must be admitted");
        assert_eq!(resp.fills_count, 1);
        assert_eq!(server.balance(&buyer), 1_000_000_000 - 15_000);
    }

    /// Regression (C5): actions (cancel/amend/replace) were admitted
    /// without any nonce check — a captured signed action replayed
    /// forever. The same action nonce must be rejected as stale.
    #[test]
    fn replayed_action_nonce_rejected() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        server.fund_account(&seller, 0);

        // Rest a sell order so there is something to cancel.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&maker);
        assert!(!resp.rejected);
        let order_id = resp.order_id;
        assert_eq!(server.resting_count(), 1);

        // Cancel with nonce 1 — accepted.
        let cancel = signed_action(&seller_sk, ActionType::Cancel, order_id, 1);
        let resp = server.submit_action(&cancel);
        assert!(!resp.rejected, "first cancel must be admitted");

        // Rest a second order; replay the same cancel request
        // (same nonce) — must be rejected as stale, and the second
        // order must NOT be canceled.
        let maker2 = signed_req(&seller_sk, 0, Side::Sell, 2, 1_500_000_000, 1_000);
        let resp2 = server.submit_order(&maker2);
        assert!(!resp2.rejected);

        let replay = signed_action(&seller_sk, ActionType::Cancel, resp2.order_id, 1);
        let replay_resp = server.submit_action(&replay);
        assert!(replay_resp.rejected, "replayed action nonce must be rejected");
        assert_eq!(replay_resp.reject_reason, Some(RejectReason::StaleNonce));
        assert_eq!(server.resting_count(), 1, "second order must still be resting");
    }

    /// Regression (C5): an action with a bad signature must be
    /// rejected at the boundary — today `submit_action` took an
    /// `OrderAction` (already stripped of signature) so forged
    /// cancels could reach the engine directly.
    #[test]
    fn unsigned_action_rejected_with_bad_signature() {
        let mut server = MatchingServer::new(cfg(), 100);
        let req = ActionRequest {
            action_type: ActionType::Cancel,
            order_id: 1,
            new_price: Price(0),
            new_qty: Qty(0),
            side: Side::Buy,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            nonce: 0,
            owner: addr(1),
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let resp = server.submit_action(&req);
        assert!(resp.rejected);
        assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));
    }

    #[test]
    fn buy_order_rejected_with_insufficient_balance() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&buyer, 1_000); // Not enough for 5 lots at $15.

        let req = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 5_000);

        let resp = server.submit_order(&req);
        assert!(resp.rejected, "should reject insufficient balance");
        assert_eq!(resp.reject_reason, Some(RejectReason::InsufficientBalance));
        assert_eq!(server.balance(&buyer), 1_000, "balance unchanged");
    }

    #[test]
    fn buy_order_accepted_with_sufficient_balance() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 1_000_000_000);

        // Rest a maker sell.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);

        // Taker buy — should match the maker.
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&taker);
        assert!(!resp.rejected, "should accept sufficient balance");
        assert_eq!(resp.fills_count, 1, "should have one fill");
        // Notional = 1_500_000_000 * 1_000 / 100_000_000 = 15_000.
        assert_eq!(server.balance(&buyer), 1_000_000_000 - 15_000);
        assert_eq!(server.balance(&seller), 1_000_000_000 + 15_000);
    }

    /// Regression test (C7): a replayed order (same nonce from the
    /// same owner) must be rejected with `StaleNonce`. Before the
    /// fix, the matcher ignored the protocol nonce field — signed
    /// orders could be replayed indefinitely.
    #[test]
    fn replayed_order_rejected_with_stale_nonce() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&buyer, 1_000_000_000);

        let req = signed_req(&buyer_sk, 0, Side::Buy, 42, 1_500_000_000, 1_000);

        // First submission: accepted (nonce 42 is new).
        let resp = server.submit_order(&req);
        assert!(!resp.rejected, "first order with new nonce must be accepted");

        // Replay: same nonce, same owner — must be rejected.
        let replay = server.submit_order(&req);
        assert!(replay.rejected, "replayed order must be rejected");
        assert_eq!(
            replay.reject_reason,
            Some(RejectReason::StaleNonce),
            "replay must be rejected with StaleNonce"
        );

        // Higher nonce: accepted.
        let req2 = signed_req(&buyer_sk, 0, Side::Buy, 43, 1_500_000_000, 1_000);
        let resp2 = server.submit_order(&req2);
        assert!(!resp2.rejected, "order with higher nonce must be accepted");
    }

    #[test]
    fn spam_orders_rejected_without_balance() {
        let risk_cfg = RiskConfig {
            max_orders_per_second: 0,
            max_order_qty: 0,
            max_price_deviation_bps: 0,
            max_resting_per_account: 0,
        };
        let mut server = MatchingServer::with_risk_config(cfg(), 100, risk_cfg);
        let (buyer_sk, _buyer) = test_account(1);

        // Submit 1000 signed buy orders with zero balance — all
        // should be rejected at the balance check (they pass
        // authentication and the nonce gate, then fail reservation).
        for i in 0..1000u64 {
            let req = signed_req(&buyer_sk, 0, Side::Buy, i, 1_500_000_000, 1_000);
            let resp = server.submit_order(&req);
            assert!(resp.rejected, "spam order should be rejected");
        }
        assert_eq!(server.balance_rejections(), 1000);
        assert_eq!(server.orders_processed(), 1000);
        assert_eq!(server.fills_produced(), 0, "no fills from rejected orders");
    }

    #[test]
    fn ring_matcher_seals_from_the_one_book() {
        // The ring matcher's owner thread holds THE book. Submit
        // orders through the ring, then seal via the control channel
        // — the seal must return the SAME fills the protocols
        // produced (one book, never two).
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let mut server = MatchingServer::new(cfg(), 100);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 1_000_000_000);
        let ring = RingMatcher::new(server, 4, 1024);

        // Push a maker sell + taker buy as one batch through ring 0.
        // The ring only accepts `VerifiedOrder` proofs — transport
        // threads authenticate, the matcher thread never sees a raw
        // unauthenticated request. Distinct request nonces (5 and 7)
        // let the fill assertions prove the (owner, client_id)
        // plumbing: a fill's buyer_id/seller_id must carry the
        // request nonces the owners registered on-chain.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 5, 1_500_000_000, 1_000);
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 7, 1_500_000_000, 1_000);
        let verified: Vec<crate::protocol::VerifiedOrder> = [maker, taker]
            .into_iter()
            .map(|req| crate::protocol::VerifiedOrder::new(req).expect("signed orders must verify"))
            .collect();
        // Hold the ring lease for the exchange — the same contract
        // the production submit path follows.
        let lease = ring.try_acquire_ring(0).expect("a free ring must lease");
        let sender = ring.order_sender(lease.ring_idx());
        let receiver = ring.response_receiver(lease.ring_idx());
        let mut batch = verified;
        while let Err(crate::ring::PushError::Full(returned)) = sender.push(batch) {
            batch = returned;
            std::hint::spin_loop();
        }
        let responses = loop {
            if let Some(r) = receiver.pop() {
                break r;
            }
            std::hint::spin_loop();
        };
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[1].fills_count, 1, "taker should fill against maker");

        // Seal through the control channel — must return the fill.
        let fills = ring.seal_batch();
        assert_eq!(fills.len(), 1, "seal returns the fill produced via the ring");
        assert_eq!(fills[0].qty, Qty(1_000));
        assert_eq!(fills[0].buyer, buyer);
        assert_eq!(fills[0].seller, seller);
        // The fill carries each side's request nonce as its client
        // id — the (owner, client_id) key the on-chain batch leg
        // resolves to a registered order.
        assert_eq!(fills[0].buyer_id, 7);
        assert_eq!(fills[0].seller_id, 5);

        // Stats via the control channel.
        let stats = ring.stats();
        assert_eq!(stats.orders_processed, 2);
        assert_eq!(stats.fills_produced, 1);
    }

    /// The ring lease grants exclusive use of a ring pair: a second
    /// acquisition on the same ring must fail while the lease lives,
    /// and succeed after the holder drops it. This is what stops two
    /// requesters sharing a response ring.
    #[test]
    fn ring_lease_grants_exclusive_ownership() {
        let server = MatchingServer::new(cfg(), 100);
        let ring = RingMatcher::new(server, 2, 64);

        let lease = ring.try_acquire_ring(0).expect("a free ring leases");
        let held_idx = lease.ring_idx();

        // With 2 rings the other index is still free — the lease
        // excludes per-ring, not globally.
        let other = ring.try_acquire_ring(held_idx).expect("the other ring is free");
        assert_ne!(other.ring_idx(), held_idx);
        drop(other);

        // Every ring now free except the held one: scanning from the
        // held index must skip it and find the other.
        let other2 = ring.try_acquire_ring(held_idx).expect("scan finds the free ring");
        assert_ne!(other2.ring_idx(), held_idx);
        drop(other2);

        // Drop the held lease — its ring becomes leasable again.
        drop(lease);
        let reacquired = ring.try_acquire_ring(held_idx);
        assert_eq!(reacquired.map(|l| l.ring_idx()), Some(held_idx));
    }

    /// With a single ring, a held lease leaves NO free ring —
    /// `try_acquire_ring` must report exhaustion rather than share.
    #[test]
    fn ring_lease_exhaustion_waits() {
        let server = MatchingServer::new(cfg(), 100);
        let ring = RingMatcher::new(server, 1, 64);
        let lease = ring.try_acquire_ring(0).expect("first lease");
        assert!(ring.try_acquire_ring(0).is_none(), "held ring cannot re-lease");
        drop(lease);
        assert!(ring.try_acquire_ring(0).is_some(), "drop frees the ring");
    }

    // ── MultiMarketMatcher tests ────────────────────────────────

    fn cfg_for(market_id: u8) -> MarketConfig {
        MarketConfig {
            market_id: u16::from(market_id),
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
            max_resting: 1 << 16,
        }
    }

    #[test]
    fn multi_market_two_markets_match_independently() {
        // Two markets, each with its own book. The same seller and
        // buyer trade on both — balances are shared (sharded), books
        // are independent. Nonces are also shared (per-ACCOUNT, not
        // per-market): each account's nonces must increase across
        // markets.
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000);
        balances.set(&buyer, 1_000_000_000);
        let configs = vec![cfg_for(0), cfg_for(1)];
        let matcher = MultiMarketMatcher::new(configs, balances);

        // Market 0: rest a maker sell, then a taker buy fills it.
        let maker0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let taker0 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let responses = matcher.submit_batch(vec![maker0, taker0]);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[1].fills_count, 1, "market 0 taker should fill");

        // Market 1: same pair, independent book — should also fill.
        // Nonces continue per account (seller 1, buyer 1).
        let maker1 = signed_req(&seller_sk, 1, Side::Sell, 1, 1_600_000_000, 1_000);
        let taker1 = signed_req(&buyer_sk, 1, Side::Buy, 1, 1_600_000_000, 1_000);
        let responses = matcher.submit_batch(vec![maker1, taker1]);
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[1].fills_count, 1, "market 1 taker should fill");

        // Seal: should have 2 fills (one per market).
        let fills = matcher.seal_batch();
        assert_eq!(fills.len(), 2, "seal collects from both markets");

        // Aggregate stats: 4 orders, 2 fills.
        let stats = matcher.stats();
        assert_eq!(stats.orders_processed, 4);
        assert_eq!(stats.fills_produced, 2);
    }

    #[test]
    fn multi_market_balance_check_is_atomic_across_markets() {
        // The buyer has exactly 15_000 quote (enough for ONE fill at
        // $15 × 1000 qty). Two markets try to debit simultaneously —
        // only one should succeed.
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000); // Seller (funded).
        balances.set(&buyer, 15_000); // Buyer: exactly one fill's worth.
        let configs = vec![cfg_for(0), cfg_for(1)];
        let matcher = MultiMarketMatcher::new(configs, balances);

        // Rest maker sells on both markets (seller nonces 0, 1 —
        // shared per-account nonce tracker across markets).
        let maker0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let maker1 = signed_req(&seller_sk, 1, Side::Sell, 1, 1_500_000_000, 1_000);
        matcher.submit_batch(vec![maker0]);
        matcher.submit_batch(vec![maker1]);

        // Submit taker buys on both markets (same buyer, same
        // balance; buyer nonces 0, 1).
        let taker0 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let taker1 = signed_req(&buyer_sk, 1, Side::Buy, 1, 1_500_000_000, 1_000);
        let resp0 = matcher.submit_one(taker0);
        let resp1 = matcher.submit_one(taker1);

        // Exactly one should fill, the other should be rejected
        // (insufficient balance). The check_and_debit is atomic
        // under the shard lock.
        let fills0 = resp0.fills_count;
        let fills1 = resp1.fills_count;
        assert!(
            (fills0 == 1 && resp1.rejected) || (fills1 == 1 && resp0.rejected),
            "exactly one market should fill, the other reject; got fills0={fills0} rejected0={} fills1={fills1} rejected1={}",
            resp0.rejected,
            resp1.rejected
        );
    }

    /// Regression (C5): a batch with a bad-signature order between
    /// two valid orders must produce aligned responses —
    /// `[good, bad, good]` → `[result0, BadSignature, result1]`.
    /// The pre-fix transport filtered valid requests and prepended
    /// rejections, yielding `[BadSignature, result0, result1]` and
    /// misattributing every response after the bad entry.
    #[test]
    fn multi_market_batch_preserves_positions_with_bad_signature() {
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000);
        balances.set(&buyer, 1_000_000_000);
        let configs = vec![cfg_for(0), cfg_for(1)];
        let matcher = MultiMarketMatcher::new(configs, balances);

        let good0 = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        // A forged order: zero signature/pubkey — fails verify_order
        // outright regardless of the claimed owner.
        let bad = OrderRequest {
            market: 0,
            side: Side::Sell,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price(1_500_000_000),
            qty: Qty(1_000),
            nonce: 0,
            owner: seller,
            pubkey: [0u8; 32],
            signature: [0u8; 64],
        };
        let good1 = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);

        // The interleaved case: [good sell, forged, good buy].
        let responses = matcher.submit_batch(vec![good0, bad, good1]);
        assert_eq!(responses.len(), 3);
        assert!(!responses[0].rejected, "index 0 (good sell) must rest");
        assert!(responses[1].rejected, "index 1 (forged) must be rejected");
        assert_eq!(
            responses[1].reject_reason,
            Some(RejectReason::BadSignature),
            "the middle slot gets BadSignature at its own position"
        );
        assert_eq!(
            responses[2].fills_count, 1,
            "index 2 (good buy) fills against the resting sell"
        );
    }

    // ── C6 regression tests: reservation accounting ─────────────

    /// Regression (C6): a resting buy's reservation must STAY debited
    /// while the order rests. The old code refunded `price * unfilled`
    /// immediately — including the resting quantity — then `cancel`
    /// refunded it again, minting balance out of nothing (buy at
    /// `15_000`, cancel, end with `15_000` MORE than started).
    #[test]
    fn resting_buy_reservation_released_exactly_once() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&buyer, 100_000);

        // GTC limit buy, nothing to match against — rests.
        let req = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&req);
        assert!(!resp.rejected, "buy should rest");

        // Reservation = 1.5e9 * 1_000 / 1e8 = 15_000. The balance
        // must show the reservation is STILL held — if this shows
        // 100_000, the cancel below will refund a second time.
        let after_rest = server.balances.get(&buyer);
        assert_eq!(
            after_rest,
            100_000 - 15_000,
            "resting reservation must remain debited (got {after_rest})"
        );

        // Cancel via a signed action (nonce 1).
        let cancel = signed_action(&buyer_sk, ActionType::Cancel, resp.order_id, 1);
        let resp2 = server.submit_action(&cancel);
        assert!(!resp2.rejected, "cancel should succeed");

        // Conservation: started with 100_000, traded nothing —
        // must end with exactly 100_000. The double-refund bug
        // leaves 115_000.
        assert_eq!(
            server.balances.get(&buyer),
            100_000,
            "cancel must refund the reservation exactly once"
        );
    }

    /// Regression (C6): price improvement must be refunded. A taker
    /// limit buy debited at its LIMIT price but filled at a BETTER
    /// maker price keeps the difference today — the reservation
    /// silently overcharges the taker.
    #[test]
    fn price_improvement_is_refunded_to_taker() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 100_000);

        // Maker rests a sell at 1.5e9.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);

        // Taker buys with a 1.6e9 limit — fills at the maker's 1.5e9.
        // Reservation debits 16_000; actual cost 15_000.
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_600_000_000, 1_000);
        let resp = server.submit_order(&taker);
        assert_eq!(resp.fills_count, 1, "taker should fill at maker price");

        // The 1_000 improvement must come back.
        assert_eq!(
            server.balances.get(&buyer),
            100_000 - 15_000,
            "taker pays the fill price, not the limit price"
        );
        assert_eq!(
            server.balances.get(&seller),
            1_000_000_000 + 15_000,
            "seller receives the fill price"
        );
    }

    /// Regression (C6): market buys were never reserved — the
    /// `!= Market` guard skipped the debit while fills still
    /// credited sellers, minting quote on every market sweep.
    /// An unfunded market buy must reject BEFORE touching the book;
    /// a funded one must pay the actual sweep cost.
    #[test]
    fn market_buy_reserves_sweep_cost_and_settles() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (poor_sk, poor) = test_account(2);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&poor, 0);
        server.fund_account(&buyer, 100_000);

        // Maker rests a sell at 1.5e9.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);

        // Unfunded market buy: must reject WITHOUT consuming the
        // resting order.
        let mut poor_req = signed_req(&poor_sk, 0, Side::Buy, 0, 0, 1_000);
        poor_req.order_type = OrderType::Market;
        poor_req.tif = TimeInForce::Ioc; // Market requires Ioc.
        poor_req.price = Price(0);
        // Re-sign after mutation (signature covers price/type).
        crate::protocol::sign_order(&mut poor_req, &poor_sk);
        let resp = server.submit_order(&poor_req);
        assert!(resp.rejected, "unfunded market buy must reject");
        assert_eq!(resp.reject_reason, Some(RejectReason::InsufficientBalance));
        assert_eq!(server.resting_count(), 1, "the resting maker must survive a rejected sweep");

        // Funded market buy: pays the actual sweep cost (15_000).
        let mut mkt = signed_req(&buyer_sk, 0, Side::Buy, 0, 0, 1_000);
        mkt.order_type = OrderType::Market;
        mkt.tif = TimeInForce::Ioc;
        mkt.price = Price(0);
        crate::protocol::sign_order(&mut mkt, &buyer_sk);
        let resp = server.submit_order(&mkt);
        assert_eq!(resp.fills_count, 1, "market buy should sweep the ask");
        assert_eq!(
            server.balances.get(&buyer),
            100_000 - 15_000,
            "market taker pays the real fill cost"
        );
        assert_eq!(server.balances.get(&seller), 1_000_000_000 + 15_000);
    }

    /// Regression (C6): an IOC/FOK remainder is DEAD — it must not be
    /// counted or reported as resting. `CanceledRemainder` was
    /// mapped to `OrderResponse::resting` + `inc_resting`, inflating
    /// the resting cap and telling the client a dead order is live.
    #[test]
    fn ioc_remainder_does_not_rest() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 100_000);

        // Maker sells 1_000 (one lot); taker IOC buys 2_000 — fills
        // 1_000, the remaining 1_000 must die, not rest.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);

        let mut ioc = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 2_000);
        ioc.tif = TimeInForce::Ioc;
        crate::protocol::sign_order(&mut ioc, &buyer_sk);
        let resp = server.submit_order(&ioc);
        assert!(!resp.rejected);
        assert_eq!(resp.fills_count, 1, "IOC fills the 1_000 available");

        // The book must be empty and the resting counter at zero —
        // the remainder was canceled by IOC semantics.
        assert_eq!(server.resting_count(), 0, "IOC remainder must not rest");

        // Reservation: debited 30_000, paid 15_000, remainder dead
        // → 15_000 refunded (nothing stays reserved).
        assert_eq!(
            server.balances.get(&buyer),
            100_000 - 15_000,
            "dead remainder's reservation is fully refunded"
        );
    }

    /// Regression (C6): a partially-filled buy that then rests holds
    /// reservation ONLY for the resting remainder — and cancel
    /// refunds exactly that, once.
    #[test]
    fn partial_fill_buy_holds_only_remainder_reservation() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 100_000);

        // Maker sells 1_000; taker GTC buys 2_000 — fills 1_000,
        // rests 1_000.
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        server.submit_order(&maker);
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 2_000);
        let resp = server.submit_order(&taker);
        assert_eq!(resp.fills_count, 1);

        // Paid 1_000×15 = 15_000; still holds 1_000×15 = 15_000 reserved.
        assert_eq!(
            server.balances.get(&buyer),
            100_000 - 15_000 - 15_000,
            "paid fills + held remainder reservation"
        );

        // Cancel the remainder: 15_000 comes back exactly once.
        let cancel = signed_action(&buyer_sk, ActionType::Cancel, resp.order_id, 1);
        server.submit_action(&cancel);
        assert_eq!(server.balances.get(&buyer), 100_000 - 15_000);
    }

    /// Regression (C5): `submit_batch` must route each verified order
    /// by ITS OWN `market` field — not `orders[0].market`. The pre-fix
    /// code sent the whole batch to the head order's worker, silently
    /// matching mixed-market batches on the wrong book. Distinct
    /// price bands make misrouting observable: market 1's price is
    /// out of band on market 0's engine, so a misrouted order would
    /// be rejected instead of filling.
    #[test]
    fn multi_market_batch_routes_by_each_orders_market() {
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000);
        balances.set(&buyer, 1_000_000_000);
        // Market 0 band: [1e9, 2e9]. Market 1 band: [3e9, 4e9] — no
        // overlap, so a market-1 order landing on market 0's engine
        // is rejected by price-band validation.
        let mut cfg0 = cfg_for(0);
        cfg0.min_price = 1_000_000_000;
        cfg0.max_price = 2_000_000_000;
        let mut cfg1 = cfg_for(1);
        cfg1.min_price = 3_000_000_000;
        cfg1.max_price = 4_000_000_000;
        let matcher = MultiMarketMatcher::new(vec![cfg0, cfg1], balances);

        // One mixed batch: market-1 orders INTERLEAVED after the
        // market-0 head. If routed by orders[0].market, both market-1
        // orders hit the [1e9,2e9] engine and are rejected.
        let orders = vec![
            signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000),
            signed_req(&seller_sk, 1, Side::Sell, 1, 3_500_000_000, 1_000),
            signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000),
            signed_req(&buyer_sk, 1, Side::Buy, 1, 3_500_000_000, 1_000),
        ];
        let responses = matcher.submit_batch(orders);
        assert_eq!(responses.len(), 4);
        assert!(
            !responses[0].rejected,
            "market-0 maker rests, got {:?}",
            responses[0].reject_reason
        );
        assert!(
            !responses[1].rejected,
            "market-1 maker must reach market 1's engine (its 3.5e9 \
             price is out of band on market 0 — a misroute would reject)"
        );
        assert_eq!(
            responses[2].fills_count, 1,
            "market-0 taker fills (rejected={} reason={:?})",
            responses[2].rejected, responses[2].reject_reason
        );
        assert_eq!(
            responses[3].fills_count, 1,
            "market-1 taker fills (rejected={} reason={:?})",
            responses[3].rejected, responses[3].reject_reason
        );

        let fills = matcher.seal_batch();
        assert_eq!(fills.len(), 2, "one fill per market");
    }

    // ── Risk-control accounting: time source + resting counts ────

    /// A test clock the caller advances explicitly — the rate
    /// limiter must measure THESE milliseconds, never the server's
    /// order counter.
    fn test_clock() -> (Arc<std::sync::atomic::AtomicU64>, Arc<dyn Fn() -> u64 + Send + Sync>) {
        let now = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reader = Arc::clone(&now);
        let clock: Arc<dyn Fn() -> u64 + Send + Sync> =
            Arc::new(move || reader.load(std::sync::atomic::Ordering::Relaxed));
        (now, clock)
    }

    /// Regression: `execute_order` fed `orders_processed` — a
    /// GLOBAL counter — to the rate limiter as its millisecond
    /// timestamp. Every order submitted anywhere advanced every
    /// account's "time", so unrelated traffic could slide a
    /// rate-limited trader's window open while zero real time had
    /// passed, and real elapsed time had no effect on the limit.
    #[test]
    fn rate_limiter_uses_clock_not_order_counter() {
        let mut server = MatchingServer::with_risk_config(
            cfg(),
            100,
            RiskConfig {
                max_orders_per_second: 2,
                max_order_qty: 0,
                max_price_deviation_bps: 0,
                max_resting_per_account: 0,
            },
        );
        let (now, clock) = test_clock();
        server.set_clock(clock);

        let (trader_sk, trader) = test_account(3);
        let (other_sk, other) = test_account(4);
        server.fund_account(&trader, 1_000_000_000_000);
        server.fund_account(&other, 1_000_000_000_000);

        // Two orders at t=0 pass; the third is rate-limited.
        for nonce in 0..2 {
            let req = signed_req(&trader_sk, 0, Side::Buy, nonce, 1_500_000_000, 1_000);
            assert!(!server.submit_order(&req).rejected);
        }
        let req = signed_req(&trader_sk, 0, Side::Buy, 2, 1_500_000_000, 1_000);
        let resp = server.submit_order(&req);
        assert_eq!(resp.reject_reason, Some(RejectReason::RateLimited));

        // 1_500 orders from ANOTHER account. With the counter fed
        // as milliseconds this pushed "now" ~1.5s forward and slid
        // the trader's window open — even though the clock has not
        // moved at all. (Each flood order is itself rejected after
        // the second one, but `orders_processed` counted them all.)
        for nonce in 0..1_500 {
            let req = signed_req(&other_sk, 0, Side::Sell, nonce, 1_500_000_000, 1_000);
            server.submit_order(&req);
        }
        let req = signed_req(&trader_sk, 0, Side::Buy, 3, 1_500_000_000, 1_000);
        let resp = server.submit_order(&req);
        assert_eq!(
            resp.reject_reason,
            Some(RejectReason::RateLimited),
            "other accounts' order flow must not slide the window"
        );

        // Real elapsed time does slide it: +1001ms exceeds the
        // one-second window and the next order passes.
        now.store(1_001, std::sync::atomic::Ordering::Relaxed);
        let req = signed_req(&trader_sk, 0, Side::Buy, 4, 1_500_000_000, 1_000);
        assert!(!server.submit_order(&req).rejected, "order after the window slid must be allowed");
    }

    /// Regression: a maker filled to zero left the book but kept
    /// its resting-order slot — active market makers accumulated
    /// phantom counts until the per-account cap rejected them.
    #[test]
    fn filled_maker_releases_resting_count() {
        let mut server = MatchingServer::with_risk_config(
            cfg(),
            100,
            RiskConfig {
                max_orders_per_second: 0,
                max_order_qty: 0,
                max_price_deviation_bps: 0,
                max_resting_per_account: 1,
            },
        );
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 1_000_000_000_000);

        // Maker rests — its slot is taken (a second resting order
        // would exceed the cap of 1).
        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        assert!(!server.submit_order(&maker).rejected);
        assert_eq!(server.risk.resting_count(&seller), 1);
        let blocked = signed_req(&seller_sk, 0, Side::Sell, 1, 1_500_000_000, 1_000);
        assert_eq!(server.submit_order(&blocked).reject_reason, Some(RejectReason::TooManyResting));

        // A taker fills the maker completely — the slot frees and
        // the account can rest again.
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        assert_eq!(server.submit_order(&taker).fills_count, 1);
        assert_eq!(
            server.risk.resting_count(&seller),
            0,
            "a fully filled maker must release its resting slot"
        );
        let again = signed_req(&seller_sk, 0, Side::Sell, 2, 1_500_000_000, 1_000);
        assert!(!server.submit_order(&again).rejected);
    }

    /// A partially filled maker still rests — it must keep its
    /// slot. Only orders that leave the book release one.
    #[test]
    fn partially_filled_maker_keeps_resting_count() {
        let mut server = MatchingServer::new(cfg(), 100);
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        server.fund_account(&seller, 1_000_000_000);
        server.fund_account(&buyer, 1_000_000_000_000);

        let maker = signed_req(&seller_sk, 0, Side::Sell, 0, 1_500_000_000, 2_000);
        assert!(!server.submit_order(&maker).rejected);
        assert_eq!(server.risk.resting_count(&seller), 1);

        // Fill half — the other half still rests at 1.5e9.
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000);
        assert_eq!(server.submit_order(&taker).fills_count, 1);
        assert_eq!(
            server.risk.resting_count(&seller),
            1,
            "a surviving maker remainder keeps its slot"
        );
    }

    /// The worker path shares the accounting: a maker filled away
    /// on a `MultiMarketMatcher` must be able to rest again. The
    /// maker floods the book to the default 1000-order cap; a
    /// single sweep fills them all; the next order must not see
    /// `TooManyResting`. The injected clock advances 1001ms between
    /// bursts so the 100/sec limiter never engages — this also
    /// exercises `MultiMarketMatcher::with_clock`.
    #[test]
    fn worker_releases_filled_maker_resting_count() {
        let (seller_sk, seller) = test_account(9);
        let (buyer_sk, buyer) = test_account(1);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&seller, 1_000_000_000);
        balances.set(&buyer, u64::MAX / 2);
        let (now, clock) = test_clock();
        let matcher = MultiMarketMatcher::with_clock(vec![cfg_for(0)], balances, clock);

        // 1_000 resting sells = the default per-account cap. Ten
        // batches of 100 with a full window slide between them stay
        // under the 100/sec rate limit.
        let mut nonce = 0u64;
        for _ in 0..10 {
            let batch: Vec<OrderRequest> = (0..100)
                .map(|_| {
                    let req = signed_req(&seller_sk, 0, Side::Sell, nonce, 1_500_000_000, 1_000);
                    nonce += 1;
                    req
                })
                .collect();
            for resp in matcher.submit_batch(batch) {
                assert!(!resp.rejected, "maker order rejected: {:?}", resp.reject_reason);
            }
            now.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed);
        }
        // The cap is real: one more resting order is rejected.
        now.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed);
        let extra = signed_req(&seller_sk, 0, Side::Sell, nonce, 1_500_000_000, 1_000);
        nonce += 1;
        let resp = matcher.submit_batch(vec![extra]);
        assert_eq!(resp[0].reject_reason, Some(RejectReason::TooManyResting));

        // One taker sweeps all 1_000 makers (1_000 × 1_000 qty).
        now.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed);
        let taker = signed_req(&buyer_sk, 0, Side::Buy, 0, 1_500_000_000, 1_000_000);
        let resp = matcher.submit_batch(vec![taker]);
        assert_eq!(resp[0].fills_count, 1_000);

        // Every slot released: the maker rests again instead of
        // hitting the phantom cap.
        now.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed);
        let again = signed_req(&seller_sk, 0, Side::Sell, nonce, 1_500_000_000, 1_000);
        let resp = matcher.submit_batch(vec![again]);
        assert!(
            !resp[0].rejected,
            "maker must rest again after the sweep freed its slots, got {:?}",
            resp[0].reject_reason
        );
    }

    /// Regression: the chain ID is the signature domain — an order
    /// signed for chain A must not replay on chain B. The server
    /// verifies against its CONFIGURED chain ID, not a hardcoded
    /// constant.
    #[test]
    fn order_signed_for_other_chain_rejected() {
        let mut server = MatchingServer::new(cfg(), 100);
        server.set_chain_id(42);
        let (trader_sk, trader) = test_account(5);
        server.fund_account(&trader, 1_000_000_000);

        // Signed under the devnet default (1): verifies as a forgery
        // on chain 42 — exactly the cross-chain replay boundary.
        let req = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let resp = server.submit_order(&req);
        assert_eq!(resp.reject_reason, Some(RejectReason::BadSignature));

        // The same request re-signed for chain 42 verifies and rests.
        // (The BadSignature rejection never consumed the nonce.)
        let mut req2 = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        crate::protocol::sign_order_with_chain_id(&mut req2, &trader_sk, 42);
        let resp2 = server.submit_order(&req2);
        assert!(
            !resp2.rejected,
            "order signed for the server's chain must verify, got {:?}",
            resp2.reject_reason
        );
    }

    /// The worker path shares the domain: a `MultiMarketMatcher`
    /// configured for chain 42 must reject devnet-signed orders and
    /// accept chain-42 signatures.
    #[test]
    fn worker_verifies_configured_chain_id() {
        let (trader_sk, trader) = test_account(5);
        let balances = Arc::new(AtomicBalanceCache::new(8));
        balances.set(&trader, 1_000_000_000);
        let matcher = MultiMarketMatcher::with_options(
            vec![cfg_for(0)],
            balances,
            Arc::new(wall_clock_ms),
            42,
            None,
        );

        let bad = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let resp = matcher.submit_batch(vec![bad]);
        assert_eq!(resp[0].reject_reason, Some(RejectReason::BadSignature));

        let mut good = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        crate::protocol::sign_order_with_chain_id(&mut good, &trader_sk, 42);
        let resp = matcher.submit_batch(vec![good]);
        assert!(
            !resp[0].rejected,
            "chain-42 order must verify on the chain-42 worker, got {:?}",
            resp[0].reject_reason
        );
    }

    /// Regression: without a durable checkpoint, every restart
    /// forgot all consumed nonces — a captured signed order became
    /// replayable once per restart, forever. `set_nonce_store`
    /// bounds the window to the checkpoint interval.
    #[test]
    fn nonce_store_survives_restart() {
        let dir = std::env::temp_dir().join(format!("oxnc-test-{}", std::process::id()));
        let path = dir.join("nonces.oxnc");
        std::fs::create_dir_all(&dir).unwrap_or_default();
        let (trader_sk, trader) = test_account(6);
        {
            let mut server = MatchingServer::new(cfg(), 100);
            server.set_nonce_store(path.clone());
            server.fund_account(&trader, 1_000_000_000);
            let req = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
            assert!(!server.submit_order(&req).rejected);
            // Checkpoint via the seal-cadence flush (the 64-mutation
            // amortized flush has not been reached).
            server.seal_batch();
        }

        // "Restart": a fresh server over the same checkpoint must
        // still reject the replayed nonce — before the store, this
        // was accepted because the gate restarted empty.
        let mut server2 = MatchingServer::new(cfg(), 100);
        server2.set_nonce_store(path.clone());
        server2.fund_account(&trader, 1_000_000_000);
        let replay = signed_req(&trader_sk, 0, Side::Sell, 0, 1_500_000_000, 1_000);
        let resp = server2.submit_order(&replay);
        assert_eq!(
            resp.reject_reason,
            Some(RejectReason::StaleNonce),
            "consumed nonce must stay consumed across restart"
        );
        // And a genuinely new nonce still works.
        let fresh = signed_req(&trader_sk, 0, Side::Sell, 1, 1_500_000_000, 1_000);
        assert!(!server2.submit_order(&fresh).rejected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt checkpoint must fail closed at startup — the
    /// alternative (silently resetting the gate) reopens the replay
    /// window for every captured signature.
    #[test]
    fn corrupt_nonce_store_fails_closed() {
        let dir = std::env::temp_dir().join(format!("oxnc-bad-{}", std::process::id()));
        let path = dir.join("bad.oxnc");
        std::fs::create_dir_all(&dir).unwrap_or_default();
        std::fs::write(&path, b"definitely-not-a-checkpoint").unwrap_or_default();
        let result = std::panic::catch_unwind(|| {
            let mut tracker = NonceTracker::new();
            tracker.attach_store(path.clone());
        });
        assert!(result.is_err(), "corrupt nonce store must panic, not reset the gate");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
