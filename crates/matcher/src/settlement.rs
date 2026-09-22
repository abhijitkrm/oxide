//! Settlement accounting and nonce durability for the matcher.
//!
//! Split from `lib.rs` around one invariant: **the fill the engine
//! emits must settle to the same quote the chain computes**, and a
//! consumed nonce must stay consumed across a restart.
//!
//! - [`LegId`]/[`LegCostAcc`] accumulate marginal per-leg settlement
//!   cost so the merged on-chain leg (`floor(price x qty / PRICE_SCALE)`)
//!   is bit-identical to the off-chain reservation cache.
//! - [`SettledFill`] is the per-fill record the settler aggregates.
//! - [`NonceTracker`]/[`NonceStore`] are the replay gate: consumed
//!   (owner, nonce) pairs checkpoint to disk every
//!   [`NONCE_FLUSH_EVERY`] admissions, bounding the restart replay
//!   window to the flush interval.

use primitives::fixed::{Price, Qty};
use std::collections::HashMap;
use trading::{FillEvent, MatchingEngine, OrderOutcome, Side};

/// The price scale divisor: notional = price * qty / `PRICE_SCALE`.
/// Matches `modules/exchange/src/lib.rs`.
pub(crate) const PRICE_SCALE: u128 = 100_000_000;

/// The leg identity a fill merges into — identical to the key
/// `aggregate_fills` groups batch legs by
/// (`market, price, buy order key, sell order key`, with the order
/// keys flattened to `(owner, client_id)`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LegId {
    /// Market the fill traded on.
    pub(crate) market: u16,
    /// Execution price (scale-8).
    pub(crate) price: u64,
    /// Buy order owner.
    pub(crate) buyer: [u8; 20],
    /// Buy order's client id.
    pub(crate) buyer_id: u64,
    /// Sell order owner.
    pub(crate) seller: [u8; 20],
    /// Sell order's client id.
    pub(crate) seller_id: u64,
}

impl LegId {
    /// Build the leg key for a fill — the same identity
    /// `aggregate_fills` merges batch legs by.
    pub(crate) fn new(
        market: u16,
        price: u64,
        buyer: primitives::Address,
        buyer_id: u64,
        seller: primitives::Address,
        seller_id: u64,
    ) -> Self {
        Self { market, price, buyer: buyer.0, buyer_id, seller: seller.0, seller_id }
    }
}

/// Marginal per-leg settlement-cost accumulator — one entry per
/// pending settlement leg, keyed EXACTLY the way
/// `aggregate_fills` merges fills into batch legs
/// (see [`LegId`]).
///
/// Why marginal: the chain computes a leg's quote as
/// `floor(price × Σqty / PRICE_SCALE)` — one truncation over the
/// merged quantity. Per-fill truncation (`Σ floor(price × qty_i)`)
/// under-counts by up to `merges−1` dust units, so the off-chain
/// cache diverged from the on-chain settlement whenever the engine
/// emitted multiple fills for the same pair at the same price.
///
/// The fix: each fill contributes only the DELTA in the leg's
/// floored total — `floor(price × (acc+q)/S) − floor(price × acc/S)`.
/// The marginals telescope: after fills `q1..qn` at price `p` the
/// accumulated total IS `floor(p × Σq / S)` — bit-identical to the
/// leg the chain will settle. When a leg has exactly one fill (the
/// common case) the marginal equals the old per-fill floor, so
/// unmerged accounting is unchanged.
///
/// Scope: entries accumulate across orders until `seal_batch`
/// drains the pending fills — the same boundary the settler
/// aggregates at — then reset. A fractional residue below one
/// unit is never a payment on either side (the chain's floor drops
/// it identically); nothing is lost on reset.
#[derive(Default)]
pub(crate) struct LegCostAcc {
    /// `LegId` → (accumulated qty, `floor(price × qty / PRICE_SCALE)`
    /// so far).
    pub(crate) legs: std::collections::BTreeMap<LegId, (u64, u64)>,
}

impl LegCostAcc {
    /// Accumulate `qty` into `leg` and return the marginal floored
    /// quote — the amount to credit the seller / charge the buyer
    /// for THIS fill so the running total equals the chain's
    /// merged-leg floor.
    pub(crate) fn add(&mut self, leg: LegId, qty: u64) -> u64 {
        let (acc_qty, acc_floor) = self.legs.entry(leg).or_insert((0, 0));
        // `saturating_add` mirrors the cache's never-panic rule; the
        // overflow the batch-side `checked_add` rejects needs
        // ~1.8e13 lots in one leg — unreachable, and a rejected
        // batch makes the cache's view moot anyway.
        let new_qty = acc_qty.saturating_add(qty);
        let new_floor = u64::try_from(u128::from(leg.price) * u128::from(new_qty) / PRICE_SCALE)
            .unwrap_or(u64::MAX);
        let marginal = new_floor.saturating_sub(*acc_floor);
        *acc_qty = new_qty;
        *acc_floor = new_floor;
        marginal
    }
}

/// Settlement arithmetic for a buy order's reservation (C6).
///
/// `reservation` was debited at admission: `limit_price × qty` for
/// limit buys, the ask-ladder sweep bound for market buys — always
/// the WORST CASE the taker could owe. This returns how much of it
/// comes back:
///
/// - `fill_cost` is the telescoped leg cost — the sum of marginal
///   floor deltas from [`LegCostAcc`], bit-identical to the
///   `floor(price × Σqty / PRICE_SCALE)` the chain settles per
///   merged leg. Fills cost their ACTUAL execution price, not the
///   limit — the difference is taker price improvement, refunded
///   here.
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
pub(crate) fn buy_reservation_refund(
    reservation: u64,
    limit_price: u64,
    outcome: &OrderOutcome,
    fill_cost: u64,
) -> u64 {
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
pub(crate) fn gone_makers(
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
pub(crate) fn fill_parties(
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
pub(crate) fn evict_gone_client_ids(
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
    /// The marginal leg-cost delta this fill contributed (scale-6)
    /// — credited to the seller / charged to the buyer's
    /// reservation in the off-chain cache. Marginals telescope:
    /// summed over the fills that merge into one chain leg they
    /// equal `floor(price × Σqty / PRICE_SCALE)` exactly — the same
    /// value the chain recomputes and settles.
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
pub(crate) struct NonceTracker {
    /// owner → last consumed nonce.
    pub(crate) last_seen: HashMap<primitives::Address, u64>,
    /// Optional durable checkpoint. Without it, every restart resets
    /// the replay gate to empty — ANY captured signed request is
    /// then replayable once (the first request from an owner is
    /// always accepted). With a store attached, the replay window
    /// shrinks to the entries consumed since the last flush.
    pub(crate) store: Option<NonceStore>,
    /// Mutations since the last successful flush.
    pub(crate) dirty: u32,
}

/// Consumed-nonce mutations between durable checkpoints. Chosen to
/// bound crash loss to ~64 admissions while keeping writes rare —
/// `seal_batch` (the settler cadence) also flushes, so a graceful
/// run checkpoints far more often than this bound.
pub(crate) const NONCE_FLUSH_EVERY: u32 = 64;

impl NonceTracker {
    /// Create an empty tracker.
    pub(crate) fn new() -> Self {
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
    pub(crate) fn attach_store(&mut self, path: std::path::PathBuf) {
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
    pub(crate) fn check_and_consume(&mut self, owner: &primitives::Address, nonce: u64) -> bool {
        if let Some(&last) = self.last_seen.get(owner)
            && nonce <= last
        {
            return false;
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
    pub(crate) fn flush(&mut self) {
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
pub(crate) struct NonceStore {
    /// Checkpoint file path (`<path>.tmp` is the write scratch).
    pub(crate) path: std::path::PathBuf,
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
    pub(crate) fn load(path: &std::path::Path) -> Result<Vec<(primitives::Address, u64)>, String> {
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
    pub(crate) fn save(
        &self,
        last_seen: &HashMap<primitives::Address, u64>,
    ) -> std::io::Result<()> {
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
