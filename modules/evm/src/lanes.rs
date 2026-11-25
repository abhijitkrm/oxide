//! Sender-partitioned execution lanes for light batches (`docs/multi-lane-evm-spec.md` §3.1).
//!
//! A batch of plain value transfers is split by sender into `L` lanes. Each lane
//! runs its senders' transactions, in canonical sub-order, with the same native
//! transfer function the serial lane uses, against a **private** overlay of the
//! immutable block-start snapshot: no version store, no publish, no shared lock.
//! Recipient credits and the coinbase tip are additive and therefore merge as
//! deltas; senders are exclusive to one lane, so their final state is taken
//! as is.
//!
//! The scheme is exact only while no balance depends on a cross-lane credit, so
//! it checks its preconditions first and returns the batch untouched (the caller
//! runs the serial lane) when any fails:
//!
//! 1. every transaction decoded, and is a plain value transfer (a call with empty
//!    calldata, no access list, no authorisations);
//! 2. no recipient is also a sender of this batch, and neither a sender nor a
//!    recipient is the coinbase;
//! 3. every transaction succeeds through the native transfer function (a `None`
//!    would send it to revm, which the lanes do not run).
//!
//! Lanes write only their private overlays, so abandoning them after the fact is
//! free; the main state is mutated once, at the end, after every check passed.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rayon::prelude::*;
use revm::database::CacheDB;
use revm::primitives::{Address as EvmAddress, U256};

use super::{DecodedTx, Event, EvmModule, ExecError, history, tx, versioned};
use crate::parallel::SharedCacheDB;
use crate::receipts;

/// Smallest batch (unit: txs) worth partitioning into lanes. Below it the
/// per-batch setup (snapshot clone, partition, merge) outweighs the parallel
/// part of ~0.8 us per tx.
pub(crate) const LANE_MIN_TXS: usize = 512;

/// Most lanes a batch is split into (unit: lanes). Origin: one lane per rayon thread is the point of
/// the design (more lanes than cores only add merge work), and the old cap of 8 left 56 of 64 cores
/// idle for EVM batches on a big machine; 64 covers the 64-96 core targets in `plan.md` Phase 2. The
/// cap bounds the per-lane overlay memory (each lane holds its own account overlay) and the merge
/// pass, which is linear in the number of lanes. Tradeoff of raising it further: more merge work and
/// memory for cores that a batch of a few thousand txs cannot keep busy anyway (`LANE_MIN_TXS`).
const MAX_LANES: usize = 64;

/// Number of lanes for a pool of `threads` rayon threads: one per thread, at least 1, at most
/// [`MAX_LANES`]. Pure so the rule is testable without a big machine.
pub(crate) fn lane_count_for(threads: usize) -> usize {
    threads.clamp(1, MAX_LANES)
}

/// The lane (0..`lanes_n`) a sender's transactions run in. Stable within a batch, which is all that
/// is required (lanes only have to keep one sender's txs together and in order). Mixes the whole
/// address: the previous hash read three bytes, so structured addresses (benchmark accounts that
/// differ in a few low bytes, vanity prefixes) collapsed onto a handful of lanes, which does not
/// matter with 8 lanes and wastes most of 64. Folding all 20 bytes through an avalanche finalizer
/// spreads any structured set evenly.
pub(crate) fn lane_of_address(addr: &EvmAddress, lanes_n: usize) -> usize {
    let b = addr.as_slice();
    let lo = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let hi = u64::from_le_bytes([b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]]);
    let mid = u64::from(u32::from_le_bytes([b[8], b[9], b[10], b[11]]));
    // Fold the three parts together, then a full avalanche finalizer (splitmix64): a bare multiply only
    // carries information upward, so a counter in the middle bytes never reached the bits read below.
    let mut z = lo ^ hi.rotate_left(29) ^ mid.rotate_left(47);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    usize::try_from(z >> 32).unwrap_or(0) % lanes_n.max(1)
}

/// A transaction's finished history record, receipt and event, built off the serial path.
struct PreparedRecord {
    stored: history::StoredTx,
    receipt: receipts::Receipt,
    raw: Vec<u8>,
    frame: crate::trace::CallFrame,
    event: Event,
}

/// A sender's final state in a lane: `(address, balance, nonce, code_hash)`.
type SenderState = (EvmAddress, U256, u64, alloy_primitives::B256);

/// A non-sender account a lane loaded: `(address, account, credit delta over the snapshot)`.
type Credit = (EvmAddress, revm::database::DbAccount, U256);

/// One lane's output, built entirely on the lane's thread.
struct LaneOut {
    /// Per-tx results by canonical index.
    results: Vec<(usize, revm::context::result::ExecutionResult)>,
    /// Final states of this lane's senders (exclusive to the lane).
    senders: Vec<SenderState>,
    /// Every other account the lane loaded: `(address, account, credit delta over the snapshot)`.
    credits: Vec<Credit>,
    /// Pre-block values of the accounts the lane touched, first write wins.
    undo: HashMap<EvmAddress, Option<versioned::UndoAccount>>,
    /// Accounts the lane touched (senders and recipients).
    touched: std::collections::BTreeSet<EvmAddress>,
}

impl EvmModule {
    /// Run one lane: its senders' transactions in canonical sub-order on a private overlay of
    /// `snapshot`, then its undo/touched capture and account classification. `None` aborts the
    /// whole lane scheme (the caller falls back to the serial lane).
    fn run_lane(
        idxs: &[usize],
        decoded: &[DecodedTx],
        snapshot: &Arc<CacheDB<revm::database_interface::EmptyDB>>,
        coinbase: EvmAddress,
        base_fee: u64,
        spec: revm::primitives::hardfork::SpecId,
        senders: &HashSet<EvmAddress>,
    ) -> Option<LaneOut> {
        let mut db = CacheDB::new(SharedCacheDB(Arc::clone(snapshot)));
        let mut results = Vec::with_capacity(idxs.len());
        let mut lane_undo = versioned::BlockUndo::default();
        let mut touched = std::collections::BTreeSet::new();
        for &i in idxs {
            let Ok((signed, caller, ..)) = &decoded[i] else { return None };
            let r = Self::try_native_transfer(signed, *caller, &mut db, coinbase, base_fee, spec)?;
            // Only a success is a plain transfer receipt; anything else belongs to revm.
            if !matches!(r, revm::context::result::ExecutionResult::Success { .. }) {
                return None;
            }
            results.push((i, r));
            // Pre-block values come from the snapshot (the lane's overlay already holds
            // post-transaction state); `capture` keeps the first.
            lane_undo.capture(*caller, snapshot.cache.accounts.get(caller));
            touched.insert(*caller);
            if let tx::TxKind::Call(to) = signed.to() {
                let to = EvmAddress::from(to.0);
                lane_undo.capture(to, snapshot.cache.accounts.get(&to));
                touched.insert(to);
            }
        }
        let mut sender_states = Vec::new();
        let mut credits = Vec::new();
        for (addr, acct) in db.cache.accounts {
            if senders.contains(&addr) {
                sender_states.push((addr, acct.info.balance, acct.info.nonce, acct.info.code_hash));
                continue;
            }
            let base = snapshot.cache.accounts.get(&addr).map_or(U256::ZERO, |a| a.info.balance);
            // Credits only ever add; a smaller balance would mean the lane debited a non-sender,
            // which the preconditions rule out.
            let delta = acct.info.balance.checked_sub(base)?;
            credits.push((addr, acct, delta));
        }
        Some(LaneOut {
            results,
            senders: sender_states,
            credits,
            undo: lane_undo.accounts,
            touched,
        })
    }

    /// Whether `d` is a plain value transfer by shape (the preconditions that need
    /// no state): a call with empty calldata, access list and authorisations.
    fn is_plain_transfer(signed: &tx::SignedTx) -> bool {
        matches!(signed.to(), tx::TxKind::Call(_))
            && signed.data().is_empty()
            && signed.access_list().is_empty()
            && signed.authorization_list().is_empty()
    }

    /// Execute `decoded` on sender-partitioned lanes, or hand it back untouched
    /// (`Err(decoded)`) when the batch does not qualify; the caller then runs the
    /// serial lane. See the module docs for the exactness argument.
    ///
    /// # Panics
    ///
    /// Panics if a module mutex is poisoned.
    // One linear check-then-apply sequence (preconditions, lanes, merge preparation, apply,
    // record): the order is the exactness argument, so splitting it would scatter it.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_lanes(
        &self,
        decoded: Vec<DecodedTx>,
    ) -> Result<Vec<Result<Vec<Event>, ExecError>>, Vec<DecodedTx>> {
        if decoded.len() < LANE_MIN_TXS {
            return Err(decoded);
        }
        let coinbase = *framework::lock_state(&self.coinbase);

        // Precondition 1 and 2 (shape and cross-lane independence): the sender set first (a few
        // thousand distinct keys), then every recipient is checked against it in parallel.
        let mut senders: HashSet<EvmAddress> = HashSet::new();
        for item in &decoded {
            let Ok((signed, caller, ..)) = item else { return Err(decoded) };
            if !Self::is_plain_transfer(signed) || *caller == coinbase {
                return Err(decoded);
            }
            if !senders.contains(caller) {
                senders.insert(*caller);
            }
        }
        let crosses = decoded.par_iter().any(|item| match item {
            Ok((signed, ..)) => match signed.to() {
                tx::TxKind::Call(to) => {
                    let to = EvmAddress::from(to.0);
                    to == coinbase || senders.contains(&to)
                }
                tx::TxKind::Create => true,
            },
            Err(_) => true,
        });
        if crosses {
            return Err(decoded);
        }

        // Partition by sender. The hash only has to be stable within the batch.
        let lanes_n = lane_count_for(rayon::current_num_threads());
        let lane_of = |a: &EvmAddress| -> usize { lane_of_address(a, lanes_n) };
        let mut lanes: Vec<Vec<usize>> = vec![Vec::new(); lanes_n];
        for (i, item) in decoded.iter().enumerate() {
            if let Ok((_, caller, ..)) = item {
                lanes[lane_of(caller)].push(i);
            }
        }

        let snapshot: Arc<CacheDB<revm::database_interface::EmptyDB>> =
            framework::lock_state(&self.db).clone();
        let base_fee = self.current_base_fee();
        let spec = self.spec;

        // Run the lanes (read-only on the shared snapshot, private overlays). Everything that does
        // not need the main state is built here, in parallel: the lane's results, its undo capture
        // and touched set (from the snapshot, first write wins as in the serial lane), and its final
        // account states split into exclusive sender states and additive credits.
        let outs: Option<Vec<LaneOut>> = lanes
            .par_iter()
            .map(|idxs| {
                Self::run_lane(idxs, &decoded, &snapshot, coinbase, base_fee, spec, &senders)
            })
            .collect();
        let Some(outs) = outs else { return Err(decoded) };

        // Per-tx results by canonical index (moved, not cloned).
        let mut results_by_idx: Vec<Option<revm::context::result::ExecutionResult>> =
            (0..decoded.len()).map(|_| None).collect();
        let mut total_accounts = 0usize;
        let mut undo_guard = framework::lock_state(&self.block_undo);
        let mut touched_guard = framework::lock_state(&self.touched);
        let mut lane_states: Vec<(Vec<SenderState>, Vec<Credit>)> = Vec::with_capacity(outs.len());
        for out in outs {
            for (i, r) in out.results {
                results_by_idx[i] = Some(r);
            }
            // Cross-lane first-write-wins: lanes captured from the same snapshot, so any entry for
            // an address is the same value; keep the first.
            undo_guard.accounts.reserve(out.undo.len());
            for (addr, entry) in out.undo {
                undo_guard.accounts.entry(addr).or_insert(entry);
            }
            // `BTreeSet::append` merges two sorted sets linearly, far cheaper than 28k inserts.
            let mut t = out.touched;
            touched_guard.append(&mut t);
            total_accounts += out.senders.len() + out.credits.len();
            lane_states.push((out.senders, out.credits));
        }
        // The coinbase receives every tip: capture/touch it once.
        undo_guard.capture(coinbase, snapshot.cache.accounts.get(&coinbase));
        touched_guard.insert(coinbase);
        drop((undo_guard, touched_guard));

        // Everything checked: release the snapshot so the main state is uniquely owned, then apply
        // in one pass. Credits are additive, so applying lane after lane equals the sum of deltas.
        drop(snapshot);
        {
            let mut guard = framework::lock_state(&self.db);
            let db = Arc::make_mut(&mut *guard);
            db.cache.accounts.reserve(total_accounts);
            for (senders_state, credits) in lane_states {
                for (addr, balance, nonce, code_hash) in senders_state {
                    let acct = db
                        .cache
                        .accounts
                        .entry(addr)
                        .or_insert_with(revm::database::DbAccount::new_not_existing);
                    acct.info.balance = balance;
                    acct.info.nonce = nonce;
                    acct.info.code_hash = if code_hash == revm::primitives::B256::ZERO {
                        revm::primitives::KECCAK_EMPTY
                    } else {
                        code_hash
                    };
                    acct.account_state = revm::database::AccountState::Touched;
                }
                for (addr, lane_acct, delta) in credits {
                    let touched = lane_acct.account_state == revm::database::AccountState::Touched;
                    match db.cache.accounts.entry(addr) {
                        std::collections::hash_map::Entry::Occupied(mut e) => {
                            // An existing entry keeps its storage and code; only the fields the
                            // serial lane would change are updated. An unmodified account (not
                            // Touched) is left as is.
                            if touched {
                                let acct = e.get_mut();
                                acct.info.balance = acct.info.balance.saturating_add(delta);
                                if acct.info.code_hash == revm::primitives::B256::ZERO {
                                    acct.info.code_hash = revm::primitives::KECCAK_EMPTY;
                                }
                                acct.account_state = revm::database::AccountState::Touched;
                            }
                        }
                        std::collections::hash_map::Entry::Vacant(e) => {
                            // Absent from the main state: the serial lane would have created it
                            // through `load_account` and modified it; the lane's copy is that
                            // entry (its balance is already base 0 + this lane's credits).
                            e.insert(lane_acct);
                        }
                    }
                }
            }
        }
        // Record in canonical order exactly as the serial lane does. Building each tx's
        // record, receipt and event is pure, so it runs in parallel; only the append to the
        // history (one lock, canonical order) is serial.
        let base_fee_now = self.current_base_fee();
        let prepared: Vec<Result<PreparedRecord, ExecError>> = decoded
            .into_par_iter()
            .zip(results_by_idx.into_par_iter())
            .map(|(item, result)| {
                let (signed, caller, tx_hash, raw) = item?;
                let result = result.ok_or(ExecError::Malformed)?;
                let frame = Self::fast_path_frame(&signed, caller, &result);
                let stored = history::stored_tx(&signed, caller, tx_hash, 0);
                let receipt = receipts::Receipt::from_execution_result(&result, stored.tx_type);
                let event = Self::evm_call_event(&receipt, base_fee_now);
                Ok(PreparedRecord { stored, receipt, raw, frame, event })
            })
            .collect();
        let mut records = Vec::with_capacity(prepared.len());
        let mut out = Vec::with_capacity(prepared.len());
        for p in prepared {
            match p {
                Ok(p) => {
                    out.push(Ok(vec![p.event]));
                    records.push((p.stored, p.receipt, p.raw, Some(p.frame)));
                }
                Err(e) => out.push(Err(e)),
            }
        }
        framework::lock_state(&self.history).record_many(records);
        self.lane_batches.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(out)
    }
}
