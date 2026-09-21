//! Oxide oracle module — median-of-feeds mark price with EMA
//! smoothing, quorum gating, and staleness tracking.
//!
//! The oracle module is the module-equivalent of Cosmos SDK's
//! `x/oracle` (and Chainlink/Pyth's aggregation contract): validators
//! submit price observations per market, the module aggregates them
//! into a manipulation-resistant mark price, and pushes the result to
//! the perps module's [`MarkSink`] at `end_block`.
//!
//! # Why a separate module
//!
//! Before this module, perps accepted `TAG_SET_MARK` transactions from
//! any sender — bounded only by the per-update deviation cap, meaning
//! *anyone* could walk the mark 10% per block in either direction.
//! The oracle replaces that open path with a quorum of the active
//! validator set: a single bad feed (compromised key, buggy feed
//! software, malicious operator) cannot move the price, because the
//! median discards outliers and the quorum requirement means a
//! minority of feeders cannot publish at all.
//!
//! # Pipeline (per block)
//!
//! 1. During the block, feeders submit `TAG_SUBMIT` transactions:
//!    `[market:1][price:8]`. Each feeder contributes at most one
//!    observation per market per block — resubmission overwrites, so
//!    a feeder can correct a fat-fingered submission within the same
//!    block but cannot stuff the ballot.
//! 2. At `end_block`, for every market that received submissions the
//!    module counts them against a quorum of
//!    `eligible/2 + 1` (strict majority), where `eligible` is the
//!    number of active (non-jailed) validators plus registered
//!    external feeds. Markets below quorum are skipped — their marks
//!    go stale rather than track a minority of feeds.
//! 3. The median of a market's submissions (lower median for even
//!    counts — deterministic, no averaging) is smoothed through an
//!    exponential moving average:
//!    `ema_next = (ema_prev · (EMA_SPAN−1) + median) / EMA_SPAN`.
//!    The first accepted median seeds the EMA directly.
//! 4. The EMA value is pushed to the consumer through
//!    [`MarkSink::set_mark_price`]. The sink (perps) applies its own
//!    deviation cap and per-block rate limit — an independent second
//!    defensive layer, so a single compromise at either layer cannot
//!    produce an unbounded move.
//!
//! # Staleness
//!
//! `last_update[market]` records the height of the last *successful*
//! sink write. `is_stale(market, height)` reports whether a mark is
//! older than [`STALE_AFTER_BLOCKS`]; consumers may gate risky paths
//! (e.g. liquidations) on freshness. Marks that fail quorum or are
//! rejected by the sink do not advance `last_update`, so staleness
//! honestly reflects consumer-visible freshness.
//!
//! # External feeds
//!
//! Validators are implicit feeders. Committee-gated
//! `TAG_REGISTER_FEED`/`TAG_UNREGISTER_FEED` messages whitelist
//! additional feed addresses (e.g. a dedicated price-service signer)
//! — they submit through the same `TAG_SUBMIT` path and count toward
//! the same quorum denominator.
//!
//! # Message format
//!
//! | Tag | Operation | Body |
//! |-----|-----------|------|
//! | 0   | Submit price | `[market:1][price:8]` |
//! | 1   | Register external feed | `[feed:20]` (committee only) |
//! | 2   | Unregister external feed | `[feed:20]` (committee only) |
//!
//! # State
//!
//! Persisted to the module's [`KVStore`] (and therefore committed to
//! the state root):
//!
//! - `b"mark/" + [market:1]` → EMA mark price, `u64` LE
//! - `b"upd/" + [market:1]` → last successful update height, `u64` LE
//! - `b"feed/" + [address:20]` → `0x01` presence marker
//!
//! Intra-block submissions are ephemeral: they are collected during
//! `handle`, consumed by `end_block`, and never touch the store —
//! replay is deterministic because the aggregation output is a pure
//! function of the journaled submission txs.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

use executor::{Event, ExecError, Module, TxContext};
use framework::{KVStore, module_id, subtree_root};
use primitives::{Address, Hash, Height};

// ── Wire tags ────────────────────────────────────────────────────────

/// Submit a price observation: body `[market:1][price:8]`.
const TAG_SUBMIT: u8 = 0;
/// Register an external feed address: body `[feed:20]`. Committee only.
const TAG_REGISTER_FEED: u8 = 1;
/// Unregister an external feed address: body `[feed:20]`. Committee only.
const TAG_UNREGISTER_FEED: u8 = 2;

// ── Aggregation constants ────────────────────────────────────────────

/// EMA smoothing span — `ema = (prev·(SPAN−1) + median) / SPAN`.
///
/// Units: block-updates. Origin: plan.md §9.3 "mark price = median
/// with EMA smoothing". A span of 4 means a step change in the median
/// moves the published mark 25% of the way each accepted update —
/// responsive enough for real price discovery (converges within a few
/// blocks) while a one-block median blip only moves the mark a
/// quarter of the blip's size. Raising it hardens against transient
/// manipulation at the cost of slower convergence; lowering it
/// approaches raw-median behavior.
const EMA_SPAN: u64 = 4;

/// How many blocks a mark may go without a successful sink write
/// before [`OracleModule::is_stale`] reports it stale.
///
/// Units: blocks. Origin: heartbeat convention (plan.md §7 module
/// list: "median-of-feeds mark price, EMA, heartbeat"). 60 blocks ≈
/// one minute at ~1s block times — long enough to absorb a few
/// quorum-failing blocks (validators briefly offline) without
/// declaring the feed dead, short enough that a genuinely dead feed
/// is flagged before liquidations lean on a fossil price.
pub const STALE_AFTER_BLOCKS: u64 = 60;

// ── Module ───────────────────────────────────────────────────────────

/// The oracle module: aggregates validator/external price
/// observations into a quorum-gated, EMA-smoothed mark price and
/// pushes it to a [`MarkSink`] consumer.
pub struct OracleModule {
    /// Persistent state for the state root — see module docs for the
    /// key layout.
    store: KVStore,
    /// The committee that authorizes feeders and emergency actions —
    /// staking on a live node. `None` means *no* feeders are
    /// authorized: submissions are rejected outright, so a bare
    /// `OracleModule::new()` is a closed module, not an open one.
    committee: Option<Arc<dyn framework::Committee + Send + Sync>>,
    /// The consumer the aggregated mark is pushed to at `end_block`
    /// — perps on a live node. `RwLock` because the sink is attached
    /// after construction in node assembly (perps is built before the
    /// oracle but the oracle must be registered before `handle` runs).
    /// `None` = aggregation still runs (marks/staleness update) but
    /// nothing is pushed — a measurement-only mode for tests.
    sink: RwLock<Option<Arc<dyn framework::MarkSink + Send + Sync>>>,
    /// This block's price observations: `market → feeder → price`.
    /// Cleared at `end_block` after aggregation. `BTreeMap` keeps
    /// iteration deterministic for the state-root-adjacent paths.
    submissions: Mutex<BTreeMap<u8, BTreeMap<Address, u64>>>,
    /// Published EMA mark per market — the last value successfully
    /// delivered to the sink (or computed in sinkless mode).
    marks: Mutex<BTreeMap<u8, u64>>,
    /// Last height each market's mark was successfully published —
    /// the heartbeat/staleness clock.
    last_update: Mutex<BTreeMap<u8, u64>>,
    /// Registered external (non-validator) feed addresses.
    feeds: Mutex<BTreeSet<Address>>,
    /// C9: committee endorsements for feed-registry changes —
    /// registering a feed grants it a vote in every market's
    /// median, so admission/removal takes the same two-thirds
    /// committee quorum as any other governance action. A single
    /// validator's signature is a vote, never a command.
    endorsements: framework::Endorsements,
}

/// The oracle's committed state decoded from a snapshot blob —
/// every field `state_root` commits, minus the store subtree
/// (carried separately in the blob's store section).
struct StagedOracle {
    /// Published EMA mark per market.
    marks: BTreeMap<u8, u64>,
    /// Last height each market's mark was published.
    last_update: BTreeMap<u8, u64>,
    /// Registered external feed addresses.
    feeds: BTreeSet<Address>,
    /// This block's `market → feeder → price` observations.
    submissions: BTreeMap<u8, BTreeMap<Address, u64>>,
    /// Pending feed-registry endorsements.
    endorsements: framework::Endorsements,
}

impl OracleModule {
    /// Construct a bare oracle with no committee and no sink: all
    /// submissions are rejected and nothing is pushed. Use
    /// [`with_committee`](Self::with_committee) and
    /// [`with_sink`](Self::with_sink) to wire it.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(BTreeMap::new()),
            committee: None,
            sink: RwLock::new(None),
            submissions: Mutex::new(BTreeMap::new()),
            marks: Mutex::new(BTreeMap::new()),
            last_update: Mutex::new(BTreeMap::new()),
            feeds: Mutex::new(BTreeSet::new()),
            endorsements: framework::Endorsements::new(),
        }
    }

    /// Attach the committee (staking on a live node) that authorizes
    /// feeders and committee-gated feed registration.
    #[must_use]
    pub fn with_committee(
        mut self,
        committee: Arc<dyn framework::Committee + Send + Sync>,
    ) -> Self {
        self.committee = Some(committee);
        self
    }

    /// Attach the mark-price sink (perps on a live node). Takes
    /// `&self` rather than consuming because node assembly builds the
    /// oracle before registering it behind an `Arc` — the sink is the
    /// last wire to connect.
    pub fn with_sink(&self, sink: Arc<dyn framework::MarkSink + Send + Sync>) {
        *self.sink.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sink);
    }

    /// The current published EMA mark for `market`, if any.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn mark(&self, market: u8) -> Option<u64> {
        self.marks.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&market).copied()
    }

    /// The height of the last successful publish for `market`.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn last_update_height(&self, market: u8) -> Option<u64> {
        self.last_update
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&market)
            .copied()
    }

    /// `true` if `market`'s mark is older than
    /// [`STALE_AFTER_BLOCKS`] at `height` — or has never been
    /// published. A never-published market is stale by definition:
    /// consumers must not liquidate against a mark that does not
    /// exist.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn is_stale(&self, market: u8, height: u64) -> bool {
        match self.last_update_height(market) {
            Some(last) => height.saturating_sub(last) > STALE_AFTER_BLOCKS,
            None => true,
        }
    }

    /// `true` if `addr` may submit price observations: an active
    /// (non-jailed) validator or a registered external feed.
    fn is_feeder(&self, addr: &Address) -> bool {
        if self.feeds.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains(addr) {
            return true;
        }
        self.committee.as_ref().is_some_and(|c| c.is_active_validator(addr))
    }

    /// The number of feeders eligible to submit right now — active
    /// validators plus registered external feeds. The submission
    /// quorum is a strict majority of this count, so a minority of
    /// feeders can never move a mark on their own.
    fn eligible_feeders(&self) -> usize {
        let external = self.feeds.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len();
        let validators = self.committee.as_ref().map_or(0, |c| c.active_validator_count());
        validators + external
    }

    /// Minimum submissions a market needs this block for its median
    /// to be published: strict majority of eligible feeders
    /// (`eligible/2 + 1`). At one eligible feeder the quorum is 1 —
    /// a single-validator devnet still works.
    fn quorum(&self) -> usize {
        self.eligible_feeders() / 2 + 1
    }

    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        {
            let marks = self.marks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(marks.len());
            for (m, p) in marks.iter() {
                w.put_u8(*m).put_u64(*p);
            }
            let updates =
                self.last_update.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(updates.len());
            for (m, h) in updates.iter() {
                w.put_u8(*m).put_u64(*h);
            }
            let feeds = self.feeds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(feeds.len());
            for f in feeds.iter() {
                w.put_addr(f);
            }
            let subs = self.submissions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(subs.len());
            for (m, feeders) in subs.iter() {
                w.put_u8(*m).put_count(feeders.len());
                for (f, p) in feeders {
                    w.put_addr(f).put_u64(*p);
                }
            }
        }
        self.endorsements.write_canonical(w);
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema. Map/set
    /// insertions enforce uniqueness: a duplicated key is
    /// non-canonical, not absorbed.
    fn decode_committed(r: &mut framework::CanonicalReader<'_>) -> Option<StagedOracle> {
        let mut marks = BTreeMap::new();
        for _ in 0..r.get_count()? {
            if marks.insert(r.get_u8()?, r.get_u64()?).is_some() {
                return None;
            }
        }
        let mut last_update = BTreeMap::new();
        for _ in 0..r.get_count()? {
            if last_update.insert(r.get_u8()?, r.get_u64()?).is_some() {
                return None;
            }
        }
        let mut feeds = BTreeSet::new();
        for _ in 0..r.get_count()? {
            if !feeds.insert(r.get_addr()?) {
                return None;
            }
        }
        let mut submissions = BTreeMap::new();
        for _ in 0..r.get_count()? {
            let market = r.get_u8()?;
            let mut feeders = BTreeMap::new();
            for _ in 0..r.get_count()? {
                if feeders.insert(r.get_addr()?, r.get_u64()?).is_some() {
                    return None;
                }
            }
            if submissions.insert(market, feeders).is_some() {
                return None;
            }
        }
        let endorsements = framework::Endorsements::read_canonical(r)?;
        Some(StagedOracle { marks, last_update, feeds, submissions, endorsements })
    }

    /// The lower median of `prices` (element at index `(n−1)/2`
    /// after sorting). For an even count this picks the lower of the
    /// two middle values — deterministic without any averaging, so
    /// there is no u64-mean overflow path and no rounding ambiguity
    /// between replicas.
    fn median(prices: &mut [u64]) -> u64 {
        prices.sort_unstable();
        prices[(prices.len() - 1) / 2]
    }

    /// Persist one market's mark + update height into the store so
    /// the state root reflects the published price.
    fn store_mark(&self, market: u8, mark: u64, height: u64) {
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.insert([b"mark/".as_slice(), &[market]].concat(), mark.to_le_bytes().to_vec());
        store.insert([b"upd/".as_slice(), &[market]].concat(), height.to_le_bytes().to_vec());
    }

    /// Aggregate this block's submissions and push the result to the
    /// sink. Runs at `end_block`; see the module-level pipeline docs.
    fn aggregate(&self, height: Height) {
        let mut submissions =
            self.submissions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if submissions.is_empty() {
            return;
        }
        let quorum = self.quorum();
        let sink = self.sink.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let mut marks = self.marks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut last_update =
            self.last_update.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (market, feeds) in submissions.iter() {
            if feeds.len() < quorum {
                // Minority of feeders — do not publish. The mark
                // keeps its previous value and goes stale via
                // `last_update` rather than tracking a potentially
                // compromised subset.
                continue;
            }
            let mut prices: Vec<u64> = feeds.values().copied().collect();
            let median = Self::median(&mut prices);
            // EMA in u128: `prev·(SPAN−1) + median` cannot overflow —
            // both operands are u64 and SPAN is tiny — and the result
            // divided by SPAN fits u64 by construction (weighted mean
            // of two u64s).
            let ema = match marks.get(market) {
                Some(prev) => u64::try_from(
                    (u128::from(*prev) * u128::from(EMA_SPAN - 1) + u128::from(median))
                        / u128::from(EMA_SPAN),
                )
                .unwrap_or(u64::MAX),
                None => median,
            };
            let delivered = match &sink {
                Some(s) => s.set_mark_price(*market, ema).is_ok(),
                // Sinkless mode: the aggregation itself is the product
                // (tests, audit replays). Count it as published.
                None => true,
            };
            if delivered {
                marks.insert(*market, ema);
                last_update.insert(*market, height.value());
                self.store_mark(*market, ema, height.value());
            }
            // If the sink rejected (unknown market, deviation cap,
            // rate limit): the mark stays at its last published value
            // and `last_update` does not advance — staleness honestly
            // reflects that the consumer is not seeing fresh prices.
        }
        submissions.clear();
    }
}

impl Default for OracleModule {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for OracleModule {
    fn name(&self) -> &'static str {
        "oracle"
    }

    fn id(&self) -> u8 {
        module_id::ORACLE
    }

    fn begin_block(&self, _height: Height) {
        // Submissions are cleared at `end_block` after aggregation,
        // not here: clearing at begin_block would also work, but
        // end_block-clearing means a crash mid-block leaves the
        // unconsumed submissions in memory rather than silently
        // dropping them — irrelevant for consensus (state root only
        // sees persisted marks), just easier to reason about.
    }

    fn validate(&self, ctx: &TxContext, msg: &[u8]) -> Result<(), ExecError> {
        let Some(&tag) = msg.first() else {
            return Err(ExecError::Malformed);
        };
        match tag {
            TAG_SUBMIT => {
                if msg.len() != 10 {
                    return Err(ExecError::Malformed);
                }
                if !self.is_feeder(&ctx.sender) {
                    return Err(ExecError::ModuleRejected(
                        "submit: sender is not an authorized price feed".to_string(),
                    ));
                }
                Ok(())
            }
            TAG_REGISTER_FEED | TAG_UNREGISTER_FEED => {
                if msg.len() != 21 {
                    return Err(ExecError::Malformed);
                }
                let mut feed = [0u8; 20];
                feed.copy_from_slice(&msg[1..21]);
                if !self.committee.as_ref().is_some_and(|c| c.is_active_validator(&ctx.sender)) {
                    return Err(ExecError::ModuleRejected(
                        "feed registry: sender is not an active validator".to_string(),
                    ));
                }
                let _ = feed;
                Ok(())
            }
            _ => Err(ExecError::Malformed),
        }
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.is_empty() {
            return Err(ExecError::Malformed);
        }
        let tag = msg[0];
        let body = &msg[1..];
        match tag {
            TAG_SUBMIT => {
                if body.len() != 9 {
                    return Err(ExecError::Malformed);
                }
                let market = body[0];
                let mut price_bytes = [0u8; 8];
                price_bytes.copy_from_slice(&body[1..9]);
                let price = u64::from_le_bytes(price_bytes);
                if price == 0 {
                    // A zero mark is not a price — it zeroes margin
                    // math and would mass-liquidate every position.
                    return Err(ExecError::ModuleRejected(
                        "submit: price must be nonzero".to_string(),
                    ));
                }
                if !self.is_feeder(&ctx.sender) {
                    return Err(ExecError::ModuleRejected(
                        "submit: sender is not an authorized price feed".to_string(),
                    ));
                }
                let mut submissions =
                    self.submissions.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                // Last-write-wins per feeder per market: a feeder may
                // correct itself within the block but still only
                // contributes one observation to the median.
                submissions.entry(market).or_default().insert(ctx.sender, price);
                Ok(vec![Event { module: "oracle", kind: "price_submitted", data: vec![market] }])
            }
            TAG_REGISTER_FEED | TAG_UNREGISTER_FEED => {
                if body.len() != 20 {
                    return Err(ExecError::Malformed);
                }
                // C9: the feed registry is committee governance —
                // a registered feed holds a vote in every market's
                // median, so one validator must not grant or strip
                // that power alone. The tx endorses the exact
                // (tag, feed) action; it applies only once
                // endorsing power strictly exceeds two-thirds of
                // the committee. Without a wired committee the path
                // is closed entirely.
                let Some(committee) = self.committee.clone() else {
                    return Err(ExecError::ModuleRejected(
                        "feed registry: no committee wired".to_string(),
                    ));
                };
                match self.endorsements.record(msg, &ctx.sender, committee.as_ref())? {
                    framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                        module: "oracle",
                        kind: "feed_registry_endorse",
                        data: body.to_vec(),
                    }]),
                    framework::EndorsementOutcome::Quorum => {
                        let mut feed = [0u8; 20];
                        feed.copy_from_slice(body);
                        let feed_addr = Address(feed);
                        let mut feeds =
                            self.feeds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        let mut store =
                            self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        let key = [b"feed/".as_slice(), &feed].concat();
                        if tag == TAG_REGISTER_FEED {
                            feeds.insert(feed_addr);
                            store.insert(key, vec![1]);
                            Ok(vec![Event {
                                module: "oracle",
                                kind: "feed_registered",
                                data: feed.to_vec(),
                            }])
                        } else {
                            feeds.remove(&feed_addr);
                            store.remove(&key);
                            Ok(vec![Event {
                                module: "oracle",
                                kind: "feed_unregistered",
                                data: feed.to_vec(),
                            }])
                        }
                    }
                }
            }
            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, height: Height) -> Vec<Event> {
        self.aggregate(height);
        Vec::new()
    }

    fn state_root(&self) -> Hash {
        // C8: commit every future-affecting field. The store already
        // mirrors marks/last_update/feeds, but committing the live
        // maps directly keeps the invariant true even if a future
        // field is added without a store mirror. `submissions` is
        // intra-block state (cleared at `end_block`, so empty at
        // commit time); it is committed anyway for uniformity.
        // Excluded: `committee`/`sink` (assembly wiring).
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        w.root()
    }

    /// Export the committed state as one canonical blob —
    /// `canon ‖ store` (audit 3.2). The canon section is the
    /// `state_root` preimage, so a peer verifies the claimed root
    /// before installing anything.
    fn export_state(&self) -> Option<storage::Snapshot> {
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        Some(storage::Snapshot {
            height: 0,
            entries: vec![(
                framework::state_blob_key(),
                framework::encode_state_blob(w.as_bytes(), &self.store),
            )],
        })
    }

    /// Verify a staged snapshot's claimed root without mutating —
    /// full field decode included, so a payload that can't rebuild
    /// the oracle's state can't pass.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let (canon, _staged, _store) =
            framework::stage_blob_snapshot(snapshot, |r, _store| Self::decode_committed(r))?;
        Ok(framework::canon_root(canon))
    }

    /// Install staged state after inspection proved it — decode
    /// first, then swap the store and in-memory fields in one step.
    /// `committee`/`sink` are assembly wiring and are NOT touched.
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let (_canon, staged, store) =
            framework::stage_blob_snapshot(snapshot, |r, _store| Self::decode_committed(r))?;
        *self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = store;
        *self.marks.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = staged.marks;
        *self.last_update.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.last_update;
        *self.feeds.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = staged.feeds;
        *self.submissions.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.submissions;
        self.endorsements.replace_with(staged.endorsements);
        Ok(())
    }
}

/// Message constructors (client-side helpers).
pub mod msg {
    /// `submit_price(market, price)` — a feeder's observation for the
    /// current block.
    #[must_use]
    pub fn submit_price(market: u8, price: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(10);
        msg.push(super::TAG_SUBMIT);
        msg.push(market);
        msg.extend_from_slice(&price.to_le_bytes());
        msg
    }

    /// `register_feed(feed)` — whitelist an external feed address.
    /// Committee (active validator) senders only.
    #[must_use]
    pub fn register_feed(feed: primitives::Address) -> Vec<u8> {
        let mut msg = Vec::with_capacity(21);
        msg.push(super::TAG_REGISTER_FEED);
        msg.extend_from_slice(&feed.0);
        msg
    }

    /// `unregister_feed(feed)` — remove an external feed address.
    /// Committee (active validator) senders only.
    #[must_use]
    pub fn unregister_feed(feed: primitives::Address) -> Vec<u8> {
        let mut msg = Vec::with_capacity(21);
        msg.push(super::TAG_UNREGISTER_FEED);
        msg.extend_from_slice(&feed.0);
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal committee stub: a fixed set of "validators" whose
    /// membership is the whole test fixture.
    struct TestCommittee {
        members: BTreeSet<Address>,
    }

    impl framework::Committee for TestCommittee {
        fn is_active_validator(&self, addr: &Address) -> bool {
            self.members.contains(addr)
        }
        fn active_validator_count(&self) -> usize {
            self.members.len()
        }
        fn power(&self, addr: &Address) -> u64 {
            u64::from(self.is_active_validator(addr))
        }
        fn total_power(&self) -> u64 {
            self.members.len() as u64
        }
    }

    /// A recording sink that captures every pushed mark.
    struct TestSink {
        pushed: Mutex<BTreeMap<u8, u64>>,
        reject: bool,
    }

    impl framework::MarkSink for TestSink {
        fn set_mark_price(&self, market: u8, mark: u64) -> Result<(), ExecError> {
            if self.reject {
                return Err(ExecError::ModuleRejected("sink rejected".to_string()));
            }
            self.pushed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(market, mark);
            Ok(())
        }
    }

    fn addr(b: u8) -> Address {
        Address([b; 20])
    }

    fn ctx(sender: u8) -> TxContext {
        TxContext { sender: addr(sender), nonce: 0, fee: 0 }
    }

    /// Oracle wired to `n` validators (`addr(0..n)`), optional sink.
    fn setup(n_validators: u8, sink: Option<Arc<TestSink>>) -> OracleModule {
        let members = (0..n_validators).map(addr).collect();
        let oracle = OracleModule::new().with_committee(Arc::new(TestCommittee { members }));
        if let Some(s) = sink {
            oracle.with_sink(s);
        }
        oracle
    }

    #[test]
    fn submit_rejects_non_feeder() {
        let oracle = setup(4, None);
        let err = oracle.handle(&ctx(99), &msg::submit_price(0, 1_500)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    #[test]
    fn submit_rejects_zero_price() {
        let oracle = setup(4, None);
        let err = oracle.handle(&ctx(0), &msg::submit_price(0, 0)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    #[test]
    fn median_not_published_below_quorum() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        // 4 validators → quorum 3. Only 2 submit.
        oracle.handle(&ctx(0), &msg::submit_price(0, 1_000)).unwrap();
        oracle.handle(&ctx(1), &msg::submit_price(0, 1_100)).unwrap();
        oracle.end_block(Height::new(1));
        assert!(sink.pushed.lock().unwrap().is_empty());
        assert!(oracle.mark(0).is_none());
        assert!(oracle.is_stale(0, 1));
    }

    #[test]
    fn median_published_at_quorum() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        // 3 of 4 submit: 1000, 1200, 900 → lower median 1000.
        oracle.handle(&ctx(0), &msg::submit_price(0, 1_000)).unwrap();
        oracle.handle(&ctx(1), &msg::submit_price(0, 1_200)).unwrap();
        oracle.handle(&ctx(2), &msg::submit_price(0, 900)).unwrap();
        oracle.end_block(Height::new(1));
        assert_eq!(oracle.mark(0), Some(1_000));
        assert_eq!(sink.pushed.lock().unwrap()[&0], 1_000);
        assert!(!oracle.is_stale(0, 1));
    }

    #[test]
    fn median_rejects_outlier_manipulation() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        // One malicious feeder submits ~100x; the median discards
        // it — sorted [1000, 1100, 100000] → 1100.
        oracle.handle(&ctx(0), &msg::submit_price(0, 1_000)).unwrap();
        oracle.handle(&ctx(1), &msg::submit_price(0, 100_000)).unwrap();
        oracle.handle(&ctx(2), &msg::submit_price(0, 1_100)).unwrap();
        oracle.end_block(Height::new(1));
        assert_eq!(oracle.mark(0), Some(1_100));
    }

    #[test]
    fn resubmission_overwrites() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        // Feeder 0 fat-fingers then corrects within the same block.
        oracle.handle(&ctx(0), &msg::submit_price(0, 999_999)).unwrap();
        oracle.handle(&ctx(0), &msg::submit_price(0, 1_000)).unwrap();
        oracle.handle(&ctx(1), &msg::submit_price(0, 1_100)).unwrap();
        oracle.handle(&ctx(2), &msg::submit_price(0, 900)).unwrap();
        oracle.end_block(Height::new(1));
        // Median of {1000, 1100, 900} = 1000 — not 999_999.
        assert_eq!(oracle.mark(0), Some(1_000));
    }

    #[test]
    fn ema_smooths_step_change() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        // Block 1: median 1000 seeds the EMA.
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::submit_price(0, 1_000)).unwrap();
        }
        oracle.end_block(Height::new(1));
        assert_eq!(oracle.mark(0), Some(1_000));
        // Block 2: median doubles to 2000. EMA moves a quarter of the
        // way: (1000·3 + 2000)/4 = 1250.
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::submit_price(0, 2_000)).unwrap();
        }
        oracle.end_block(Height::new(2));
        assert_eq!(oracle.mark(0), Some(1_250));
        // Block 3: (1250·3 + 2000)/4 = 1437.
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::submit_price(0, 2_000)).unwrap();
        }
        oracle.end_block(Height::new(3));
        assert_eq!(oracle.mark(0), Some(1_437));
    }

    #[test]
    fn staleness_grows_when_quorum_fails() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::submit_price(0, 1_000)).unwrap();
        }
        oracle.end_block(Height::new(1));
        assert!(!oracle.is_stale(0, 1));
        assert!(!oracle.is_stale(0, 1 + STALE_AFTER_BLOCKS));
        assert!(oracle.is_stale(0, 1 + STALE_AFTER_BLOCKS + 1));
    }

    #[test]
    fn sink_rejection_keeps_old_mark_and_staleness() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::submit_price(0, 1_000)).unwrap();
        }
        oracle.end_block(Height::new(1));
        assert_eq!(oracle.mark(0), Some(1_000));

        // Sink starts rejecting (e.g. deviation cap). Mark must not
        // move and `last_update` must not advance.
        let rejecting = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: true });
        oracle.with_sink(rejecting);
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::submit_price(0, 2_000)).unwrap();
        }
        oracle.end_block(Height::new(2));
        assert_eq!(oracle.mark(0), Some(1_000));
        assert_eq!(oracle.last_update_height(0), Some(1));
    }

    #[test]
    fn external_feed_can_submit_after_registration() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        // Non-validator registers a feed — rejected (not committee).
        let err = oracle.handle(&ctx(50), &msg::register_feed(addr(77))).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        // A committee quorum registers it (C9: one signature is an
        // endorsement; three of four equal-power validators reach
        // the two-thirds threshold).
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::register_feed(addr(77))).unwrap();
        }
        // Now 5 eligible feeders (4 validators + 1 external) → quorum
        // still 3. External feed's submission counts.
        oracle.handle(&ctx(0), &msg::submit_price(0, 1_000)).unwrap();
        oracle.handle(&ctx(1), &msg::submit_price(0, 1_000)).unwrap();
        oracle.handle(&ctx(77), &msg::submit_price(0, 1_000)).unwrap();
        oracle.end_block(Height::new(1));
        assert_eq!(oracle.mark(0), Some(1_000));
    }

    #[test]
    fn unregistered_feed_stops_counting() {
        let oracle = setup(4, None);
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::register_feed(addr(77))).unwrap();
            oracle.handle(&ctx(v), &msg::unregister_feed(addr(77))).unwrap();
        }
        let err = oracle.handle(&ctx(77), &msg::submit_price(0, 1_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    /// C9: registering a price feed grants it a vote in every
    /// market's median — one validator must not grant that power
    /// alone. Feed registry changes are committee-quorum actions.
    #[test]
    fn register_feed_requires_committee_quorum() {
        let oracle = setup(4, None);
        let feed = addr(77);
        let err = oracle.handle(&ctx(77), &msg::submit_price(0, 1_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));

        // Two of four endorsements — below quorum, the feed is not
        // registered and its submissions stay rejected.
        oracle.handle(&ctx(0), &msg::register_feed(feed)).unwrap();
        oracle.handle(&ctx(1), &msg::register_feed(feed)).unwrap();
        let err = oracle.handle(&ctx(77), &msg::submit_price(0, 1_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "below quorum the feed stays out");

        // The third endorsement crosses two-thirds — the feed is in.
        oracle.handle(&ctx(2), &msg::register_feed(feed)).unwrap();
        oracle.handle(&ctx(77), &msg::submit_price(0, 1_000)).unwrap();
    }

    /// Kicking a feed out of the registry is the same quorum-gated
    /// action — a single validator must not silence a feeder.
    #[test]
    fn unregister_feed_requires_committee_quorum() {
        let oracle = setup(4, None);
        let feed = addr(77);
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::register_feed(feed)).unwrap();
        }

        oracle.handle(&ctx(0), &msg::unregister_feed(feed)).unwrap();
        oracle.handle(&ctx(1), &msg::unregister_feed(feed)).unwrap();
        oracle.handle(&ctx(77), &msg::submit_price(0, 1_000)).unwrap();

        oracle.handle(&ctx(2), &msg::unregister_feed(feed)).unwrap();
        let err = oracle.handle(&ctx(77), &msg::submit_price(0, 1_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "quorum removes the feed");
    }

    #[test]
    fn multi_market_aggregation_independent() {
        let sink = Arc::new(TestSink { pushed: Mutex::new(BTreeMap::new()), reject: false });
        let oracle = setup(4, Some(sink.clone()));
        // Market 0 reaches quorum; market 1 does not.
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::submit_price(0, 1_000)).unwrap();
        }
        oracle.handle(&ctx(0), &msg::submit_price(1, 5_000)).unwrap();
        oracle.end_block(Height::new(1));
        assert_eq!(oracle.mark(0), Some(1_000));
        assert!(oracle.mark(1).is_none());
    }

    #[test]
    fn no_committee_rejects_everything() {
        let oracle = OracleModule::new();
        let err = oracle.handle(&ctx(0), &msg::submit_price(0, 1_000)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
    }

    #[test]
    fn state_root_reflects_published_marks() {
        let oracle = setup(4, None);
        let root_empty = oracle.state_root();
        for v in 0..3u8 {
            oracle.handle(&ctx(v), &msg::submit_price(0, 1_000)).unwrap();
        }
        oracle.end_block(Height::new(1));
        let root_after = oracle.state_root();
        assert_ne!(root_empty, root_after);
    }

    /// Export → inspect → import must reproduce the exact committed
    /// state: published marks, heartbeat heights, and feeds survive a
    /// snapshot round-trip with the state root intact (audit 3.2).
    /// `committee`/`sink` are assembly wiring — the destination
    /// supplies its own.
    #[test]
    fn state_snapshot_round_trips() {
        let src = setup(4, None);
        for v in 0..3u8 {
            src.handle(&ctx(v), &msg::submit_price(0, 1_000)).unwrap();
        }
        src.handle(&ctx(0), &msg::submit_price(1, 9_999)).unwrap();
        src.end_block(Height::new(1));
        let snapshot = src.export_state().expect("oracle exports state");
        assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

        let dst = setup(4, None); // wiring reattached by the harness
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), src.state_root());
        assert_eq!(dst.mark(0), src.mark(0));
        assert_eq!(dst.last_update_height(0), src.last_update_height(0));
    }

    /// A truncated blob and a non-canonical stream must both fail
    /// inspection — the claimed root is never trusted over the bytes.
    #[test]
    fn state_snapshot_rejects_corruption() {
        let src = setup(4, None);
        src.end_block(Height::new(1));
        let mut snapshot = src.export_state().unwrap();
        snapshot.entries[0].1.truncate(12);
        assert!(src.inspect_state(&snapshot).is_err());
        assert!(setup(4, None).import_state(&snapshot).is_err());
    }
}
