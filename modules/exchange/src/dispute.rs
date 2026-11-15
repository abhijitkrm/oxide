//! Bonded settlement operator and the dispute path over the committed
//! batch settle (tag 16).
//!
//! The operator of a committed batch settle attests a `fills_root` over
//! the raw off-chain fills the legs were aggregated from. The chain
//! cannot see raw fills, so on its own the attestation is just a claim.
//! This module makes it enforceable:
//!
//! 1. **Bond.** The operator escrows a bond (`TAG_BOND_DEPOSIT`, funds
//!    debited from the operator's ledger balance and held by the module).
//!    While disputes are enabled, a committed batch settle is accepted
//!    only if the bond is at least `min_bond` and the operator is not
//!    suspended.
//! 2. **Record.** Each accepted committed batch leaves a record
//!    `(fills_root, legs_root, raw_count, leg_count, height)` under its
//!    `batch_seq`, in the module's committed key-value store, so it is
//!    part of the state root and of snapshots.
//! 3. **Dispute.** Within `window_blocks` anyone may submit the raw
//!    fills for a `batch_seq` (`TAG_DISPUTE`). The chain recomputes the
//!    root over them and, if it equals the attested `fills_root` (so
//!    these are the attested fills), recomputes the legs they aggregate
//!    to. If that legs root differs from the one the operator actually
//!    applied, the operator provably attested fills that do not match
//!    what it settled: the bond is paid to the challenger and the
//!    operator is suspended (every settle, plain or committed, is
//!    refused) until governance reinstates it
//!    (`exchange.operator.reinstate`).
//!
//! A dispute that fails (the fills do not hash to the attested root, or
//! they do aggregate to the applied legs) changes no state and costs the
//! challenger the transaction fee. Records older than the window are
//! pruned at `end_block`, bounding the state this adds.
//!
//! Everything here is off unless [`crate::ExchangeModule::set_dispute_config`]
//! is called, in which case tag 16 behaves exactly as before (no state
//! written, no bond required).

use std::collections::BTreeMap;

use executor::{Event, ExecError, RejectCategory, TxContext};
use primitives::Address;
use primitives::fixed::{Price, Qty};

use crate::{BatchFillEntry, ExchangeModule, FILL_ENTRY_LEN, OrderKey};

/// Encoded length of a [`RawFill`]: market 2 + price 8 + qty 8 + buy
/// owner 20 + buy id 8 + sell owner 20 + sell id 8 + quote amount 8.
pub const RAW_FILL_LEN: usize = 2 + 8 + 8 + 20 + 8 + 20 + 8 + 8;

/// Stream label of the operator's raw-fill commitment.
pub const FILLS_STREAM_LABEL: &[u8] = b"oxide-matcher-fills-v1";

/// Most raw fills one dispute may carry. Unit: fills. Bounds the work a
/// dispute transaction can force (hashing plus aggregation) and the
/// transaction size (82 B each, ~5 MiB at the cap). Raising it only
/// raises that bound; batches larger than this cannot be disputed.
pub const MAX_DISPUTE_FILLS: usize = 65_536;

/// Store key of the operator's bond (u64 LE). The `net/` prefix keeps
/// these keys disjoint from the 2-byte `m/{id}` market-config keys the
/// snapshot decoder cross-checks.
const BOND_KEY: &[u8] = b"net/bond";
/// Store key of the suspension flag (present = suspended).
const SUSPENDED_KEY: &[u8] = b"net/susp";
/// Store key prefix of batch records: `net/p/` ‖ `batch_seq` (8 bytes BE,
/// so keys sort by sequence).
const RECORD_PREFIX: &[u8] = b"net/p/";
/// Encoded length of a batch record.
const RECORD_LEN: usize = 32 + 32 + 4 + 4 + 8;

/// Governed-parameter key that lifts a suspension.
pub const REINSTATE_PARAM: &[u8] = b"exchange.operator.reinstate";

/// Dispute configuration. `None` on the module (the default) disables
/// the bond and dispute machinery entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisputeConfig {
    /// Smallest bond (ledger base units) the operator must hold for a
    /// committed batch settle to be accepted.
    pub min_bond: u64,
    /// Blocks a batch record stays disputable. Unit: blocks. Longer
    /// gives auditors more time and grows retained state; shorter does
    /// the opposite.
    pub window_blocks: u64,
}

/// One raw fill as the operator attests it: the fields settlement acts
/// on. The commitment covers every field, including `quote_amount`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawFill {
    /// Market.
    pub market: u16,
    /// Execution price (scale-8).
    pub price: Price,
    /// Quantity (scale-6).
    pub qty: Qty,
    /// Buy order consumed.
    pub buy: OrderKey,
    /// Sell order consumed.
    pub sell: OrderKey,
    /// Marginal quote delta (scale-6), as the matcher's cache booked it.
    pub quote_amount: u64,
}

impl RawFill {
    /// Canonical little-endian encoding.
    #[must_use]
    pub fn encode(&self) -> [u8; RAW_FILL_LEN] {
        let mut b = [0u8; RAW_FILL_LEN];
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            b[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(&self.market.to_le_bytes());
        put(&self.price.0.to_le_bytes());
        put(&self.qty.0.to_le_bytes());
        put(&self.buy.owner.0);
        put(&self.buy.client_id.to_le_bytes());
        put(&self.sell.owner.0);
        put(&self.sell.client_id.to_le_bytes());
        put(&self.quote_amount.to_le_bytes());
        debug_assert_eq!(at, RAW_FILL_LEN, "raw fill layout drifted from its length");
        b
    }

    /// Decode [`Self::encode`].
    #[must_use]
    pub fn decode(b: &[u8; RAW_FILL_LEN]) -> Self {
        let u64_at = |o: usize| {
            let mut x = [0u8; 8];
            x.copy_from_slice(&b[o..o + 8]);
            u64::from_le_bytes(x)
        };
        let addr_at = |o: usize| {
            let mut x = [0u8; 20];
            x.copy_from_slice(&b[o..o + 20]);
            Address(x)
        };
        Self {
            market: u16::from_le_bytes([b[0], b[1]]),
            price: Price(u64_at(2)),
            qty: Qty(u64_at(10)),
            buy: OrderKey { owner: addr_at(18), client_id: u64_at(38) },
            sell: OrderKey { owner: addr_at(46), client_id: u64_at(66) },
            quote_amount: u64_at(74),
        }
    }
}

/// The quantity sum of merged legs overflowed `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateOverflow;

/// Aggregate raw fills into settlement legs: fills at the same price
/// between the same registered order pair merge into one leg (each key
/// authorizes only its own remaining quantity). `BTreeMap` order makes
/// the leg order a pure function of the fill set. This is the single
/// definition shared by the settler (to build legs) and by the dispute
/// path (to re-derive them), so the two can never drift.
///
/// # Errors
///
/// [`AggregateOverflow`] if a merged quantity exceeds `u64::MAX`.
pub fn aggregate_raw_fills(fills: &[RawFill]) -> Result<Vec<BatchFillEntry>, AggregateOverflow> {
    let mut agg: BTreeMap<(u16, Price, OrderKey, OrderKey), Qty> = BTreeMap::new();
    for f in fills {
        let key = (f.market, f.price, f.buy, f.sell);
        match agg.get_mut(&key) {
            Some(q) => *q = Qty(q.0.checked_add(f.qty.0).ok_or(AggregateOverflow)?),
            None => {
                agg.insert(key, f.qty);
            }
        }
    }
    Ok(agg
        .into_iter()
        .map(|((market, price, buy, sell), qty)| BatchFillEntry { market, price, qty, buy, sell })
        .collect())
}

/// Wire bytes of one leg, as in a batch-settle message.
#[must_use]
pub fn leg_bytes(l: &BatchFillEntry) -> [u8; FILL_ENTRY_LEN] {
    let mut b = [0u8; FILL_ENTRY_LEN];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        b[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(&l.market.to_le_bytes());
    put(&l.price.0.to_le_bytes());
    put(&l.qty.0.to_le_bytes());
    put(&l.buy.owner.0);
    put(&l.buy.client_id.to_le_bytes());
    put(&l.sell.owner.0);
    put(&l.sell.client_id.to_le_bytes());
    b
}

/// Root over raw fills: the operator's attestation.
#[must_use]
pub fn raw_fills_root(fills: &[RawFill]) -> ([u8; 32], u32) {
    let mut s = lanes::commit::ByteStream::new(FILLS_STREAM_LABEL);
    for f in fills {
        s.push(&f.encode());
    }
    let (root, n) = s.finish();
    (root, u32::try_from(n).unwrap_or(u32::MAX))
}

/// Root over legs: what the chain computes over what it applied.
#[must_use]
pub fn legs_root(legs: &[BatchFillEntry]) -> ([u8; 32], u32) {
    let mut s = lanes::commit::ByteStream::new(crate::LEGS_STREAM_LABEL);
    for l in legs {
        s.push(&leg_bytes(l));
    }
    let (root, n) = s.finish();
    (root, u32::try_from(n).unwrap_or(u32::MAX))
}

fn record_key(seq: u64) -> Vec<u8> {
    let mut k = RECORD_PREFIX.to_vec();
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// A decoded batch record.
struct Record {
    fills_root: [u8; 32],
    legs_root: [u8; 32],
    raw_count: u32,
    height: u64,
}

fn encode_record(r: &Record, leg_count: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(RECORD_LEN);
    v.extend_from_slice(&r.fills_root);
    v.extend_from_slice(&r.legs_root);
    v.extend_from_slice(&r.raw_count.to_le_bytes());
    v.extend_from_slice(&leg_count.to_le_bytes());
    v.extend_from_slice(&r.height.to_le_bytes());
    v
}

fn decode_record(v: &[u8]) -> Option<Record> {
    if v.len() != RECORD_LEN {
        return None;
    }
    let mut fills_root = [0u8; 32];
    fills_root.copy_from_slice(&v[0..32]);
    let mut legs_root = [0u8; 32];
    legs_root.copy_from_slice(&v[32..64]);
    Some(Record {
        fills_root,
        legs_root,
        raw_count: u32::from_le_bytes(v[64..68].try_into().ok()?),
        height: u64::from_le_bytes(v[72..80].try_into().ok()?),
    })
}

impl ExchangeModule {
    /// Enable the bond and dispute machinery (see the module docs). Must
    /// be called before the module is shared, like
    /// [`Self::set_settlement_operator`].
    pub fn set_dispute_config(&mut self, cfg: DisputeConfig) {
        self.dispute = Some(cfg);
    }

    /// The operator's current bond, in ledger base units.
    #[must_use]
    pub fn operator_bond(&self) -> u64 {
        let store = framework::lock_state(&self.store);
        store
            .get(&BOND_KEY.to_vec())
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map_or(0, u64::from_le_bytes)
    }

    /// Whether the operator has been slashed and not reinstated.
    #[must_use]
    pub fn operator_suspended(&self) -> bool {
        framework::lock_state(&self.store).get(&SUSPENDED_KEY.to_vec()).is_some()
    }

    /// Whether a disputable record exists for `batch_seq`.
    #[must_use]
    pub fn has_batch_record(&self, batch_seq: u64) -> bool {
        framework::lock_state(&self.store).get(&record_key(batch_seq)).is_some()
    }

    fn set_bond(&self, amount: u64) {
        framework::lock_state(&self.store).insert(BOND_KEY.to_vec(), amount.to_le_bytes().to_vec());
    }

    /// Refuse a settle from a suspended operator (no-op while disputes
    /// are disabled).
    pub(crate) fn require_operator_active(&self) -> Result<(), ExecError> {
        if self.dispute.is_some() && self.operator_suspended() {
            return Err(ExecError::rejected(
                RejectCategory::Unauthorized,
                "settlement operator suspended after a proven dispute",
            ));
        }
        Ok(())
    }

    /// Gate a committed batch settle before it applies: bond, duplicate
    /// sequence. No-op while disputes are disabled.
    pub(crate) fn pre_committed_settle(&self, batch_seq: u64) -> Result<(), ExecError> {
        let Some(cfg) = self.dispute else { return Ok(()) };
        self.require_operator_active()?;
        if self.operator_bond() < cfg.min_bond {
            return Err(ExecError::rejected(
                RejectCategory::InsufficientFunds,
                "operator bond below the required minimum",
            ));
        }
        if self.has_batch_record(batch_seq) {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "batch sequence already recorded",
            ));
        }
        Ok(())
    }

    /// Record a settled committed batch. No-op while disputes are disabled.
    pub(crate) fn record_committed_settle(
        &self,
        batch_seq: u64,
        fills_root: [u8; 32],
        raw_count: u32,
        legs_root: [u8; 32],
        leg_count: u32,
    ) {
        if self.dispute.is_none() {
            return;
        }
        let rec = Record {
            fills_root,
            legs_root,
            raw_count,
            height: self.height.load(std::sync::atomic::Ordering::Relaxed),
        };
        framework::lock_state(&self.store)
            .insert(record_key(batch_seq), encode_record(&rec, leg_count));
    }

    /// `TAG_BOND_DEPOSIT`: the operator escrows `amount` more bond.
    pub(crate) fn handle_bond_deposit(
        &self,
        ctx: &TxContext,
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        if self.dispute.is_none() || self.settlement_operator != Some(ctx.sender) {
            return Err(ExecError::rejected(
                RejectCategory::Unauthorized,
                "bond deposits are for the settlement operator while disputes are enabled",
            ));
        }
        let amount =
            u64::from_le_bytes(<[u8; 8]>::try_from(body).map_err(|_| ExecError::Malformed)?);
        if amount == 0 {
            return Err(ExecError::rejected(RejectCategory::InvalidInput, "zero bond"));
        }
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::rejected(RejectCategory::Internal, "bond deposit requires ledger wiring")
        })?;
        let new_bond = self
            .operator_bond()
            .checked_add(amount)
            .ok_or_else(|| ExecError::rejected(RejectCategory::InvalidInput, "bond overflow"))?;
        // Debit first: a failed debit leaves the recorded bond untouched.
        ledger.debit(&ctx.sender, amount)?;
        self.set_bond(new_bond);
        Ok(vec![Event {
            module: "exchange",
            kind: "bond_deposited",
            data: [amount.to_le_bytes(), new_bond.to_le_bytes()].concat(),
        }])
    }

    /// `TAG_DISPUTE`: prove a recorded batch's attestation false.
    pub(crate) fn handle_dispute(
        &self,
        ctx: &TxContext,
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let Some(_cfg) = self.dispute else {
            return Err(ExecError::rejected(RejectCategory::Precondition, "disputes are disabled"));
        };
        let seq = u64::from_le_bytes(
            body.get(0..8)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        );
        let count = usize::try_from(u32::from_le_bytes(
            body.get(8..12)
                .ok_or(ExecError::Malformed)?
                .try_into()
                .map_err(|_| ExecError::Malformed)?,
        ))
        .map_err(|_| ExecError::Malformed)?;
        if count > MAX_DISPUTE_FILLS || body.len() != 12 + count * RAW_FILL_LEN {
            return Err(ExecError::Malformed);
        }
        let rec_bytes = framework::lock_state(&self.store).get(&record_key(seq)).cloned();
        let rec = rec_bytes.as_deref().and_then(decode_record).ok_or_else(|| {
            ExecError::rejected(RejectCategory::NotFound, "no disputable record for that batch")
        })?;
        if count != rec.raw_count as usize {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                "raw fill count does not match the attested count",
            ));
        }
        let (raw, _) = body[12..].as_chunks::<RAW_FILL_LEN>();
        let fills: Vec<RawFill> = raw.iter().map(RawFill::decode).collect();

        // These must be THE attested fills.
        let (fills_root, _) = raw_fills_root(&fills);
        if fills_root != rec.fills_root {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                "supplied fills do not hash to the attested root",
            ));
        }
        // What those fills aggregate to, versus what was applied.
        let legs = aggregate_raw_fills(&fills).map_err(|_| ExecError::Malformed)?;
        let (recomputed, _) = legs_root(&legs);
        if recomputed == rec.legs_root {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "attestation is consistent with the applied legs",
            ));
        }

        // Proven: the operator attested fills that do not match what it
        // settled. Slash the whole bond to the challenger and suspend.
        let bond = self.operator_bond();
        if bond > 0 {
            let ledger = self.ledger.as_ref().ok_or_else(|| {
                ExecError::rejected(RejectCategory::Internal, "slash requires ledger wiring")
            })?;
            ledger.credit(&ctx.sender, bond)?;
        }
        {
            let mut store = framework::lock_state(&self.store);
            store.insert(BOND_KEY.to_vec(), 0u64.to_le_bytes().to_vec());
            store.insert(SUSPENDED_KEY.to_vec(), vec![1]);
            store.remove(&record_key(seq));
        }
        let mut data = Vec::with_capacity(8 + 20 + 8 + 32 * 3);
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(&ctx.sender.0);
        data.extend_from_slice(&bond.to_le_bytes());
        data.extend_from_slice(&rec.fills_root);
        data.extend_from_slice(&rec.legs_root);
        data.extend_from_slice(&recomputed);
        Ok(vec![Event { module: "exchange", kind: "operator_slashed", data }])
    }

    /// Governed reinstatement of a suspended operator.
    pub(crate) fn reinstate_operator(&self) {
        framework::lock_state(&self.store).remove(&SUSPENDED_KEY.to_vec());
    }

    /// Drop records past their window (called from `end_block`).
    pub(crate) fn prune_records(&self, height: u64) {
        let Some(cfg) = self.dispute else { return };
        let mut store = framework::lock_state(&self.store);
        let stale: Vec<Vec<u8>> = store
            .inner()
            .range(RECORD_PREFIX.to_vec()..)
            .take_while(|(k, _)| k.starts_with(RECORD_PREFIX))
            .filter(|(_, v)| {
                decode_record(v).is_none_or(|r| r.height.saturating_add(cfg.window_blocks) < height)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            store.remove(&k);
        }
    }
}
