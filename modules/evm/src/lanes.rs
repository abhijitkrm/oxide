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

/// Most lanes a batch is split into (unit: lanes). More lanes than cores only add
/// merge work; the cap also bounds the per-lane overlay memory.
const MAX_LANES: usize = 8;

/// A transaction's finished history record, receipt and event, built off the serial path.
struct PreparedRecord {
    stored: history::StoredTx,
    receipt: receipts::Receipt,
    raw: Vec<u8>,
    frame: crate::trace::CallFrame,
    event: Event,
}

/// One lane's output: per-tx results by canonical index, plus the lane's overlay.
struct LaneOut {
    results: Vec<(usize, revm::context::result::ExecutionResult)>,
    db: CacheDB<SharedCacheDB>,
}

impl EvmModule {
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

        // Precondition 1 and 2 (shape and cross-lane independence).
        let mut senders: HashSet<EvmAddress> = HashSet::new();
        let mut recipients: HashSet<EvmAddress> = HashSet::new();
        for item in &decoded {
            let Ok((signed, caller, ..)) = item else { return Err(decoded) };
            if !Self::is_plain_transfer(signed) || *caller == coinbase {
                return Err(decoded);
            }
            senders.insert(*caller);
            if let tx::TxKind::Call(to) = signed.to() {
                recipients.insert(EvmAddress::from(to.0));
            }
        }
        if recipients.contains(&coinbase) || !recipients.is_disjoint(&senders) {
            return Err(decoded);
        }

        // Partition by sender. The hash only has to be stable within the batch.
        let lanes_n = rayon::current_num_threads().clamp(1, MAX_LANES);
        let lane_of = |a: &EvmAddress| -> usize {
            let b = a.as_slice();
            (usize::from(b[0]) ^ (usize::from(b[7]) << 3) ^ (usize::from(b[19]) << 5)) % lanes_n
        };
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

        // Run the lanes (read-only on the shared snapshot, private overlays).
        let outs: Option<Vec<LaneOut>> = lanes
            .par_iter()
            .map(|idxs| {
                let mut db = CacheDB::new(SharedCacheDB(Arc::clone(&snapshot)));
                let mut results = Vec::with_capacity(idxs.len());
                for &i in idxs {
                    let Ok((signed, caller, ..)) = &decoded[i] else { return None };
                    let r = Self::try_native_transfer(
                        signed, *caller, &mut db, coinbase, base_fee, spec,
                    )?;
                    // Only a success is a plain transfer receipt; anything else
                    // belongs to revm.
                    if !matches!(r, revm::context::result::ExecutionResult::Success { .. }) {
                        return None;
                    }
                    results.push((i, r));
                }
                Some(LaneOut { results, db })
            })
            .collect();
        let Some(outs) = outs else { return Err(decoded) };

        // Merge preparation, still without touching the main state: sender states
        // (exclusive), summed credit deltas for everything else.
        let base_balance = |a: &EvmAddress| -> U256 {
            snapshot.cache.accounts.get(a).map_or(U256::ZERO, |acc| acc.info.balance)
        };
        let mut sender_final: Vec<(EvmAddress, U256, u64, alloy_primitives::B256)> = Vec::new();
        let mut credit: HashMap<EvmAddress, (revm::database::DbAccount, U256)> = HashMap::new();
        for out in &outs {
            for (addr, acct) in &out.db.cache.accounts {
                if senders.contains(addr) {
                    sender_final.push((
                        *addr,
                        acct.info.balance,
                        acct.info.nonce,
                        acct.info.code_hash,
                    ));
                    continue;
                }
                let base = base_balance(addr);
                // Credits only ever add; a smaller balance would mean the lane
                // debited a non-sender, which the preconditions rule out.
                let Some(delta) = acct.info.balance.checked_sub(base) else {
                    return Err(decoded);
                };
                let entry = credit.entry(*addr).or_insert_with(|| (acct.clone(), U256::ZERO));
                entry.1 = entry.1.saturating_add(delta);
                // Prefer a template that was actually modified (Touched).
                if acct.account_state == revm::database::AccountState::Touched {
                    entry.0.account_state = revm::database::AccountState::Touched;
                    entry.0.info.code_hash = acct.info.code_hash;
                }
            }
        }

        // Per-tx results by canonical index, and the pre-block undo (from the
        // snapshot, first write wins as in the serial lane).
        let mut results_by_idx: Vec<Option<revm::context::result::ExecutionResult>> =
            vec![None; decoded.len()];
        for out in &outs {
            for (i, r) in &out.results {
                results_by_idx[*i] = Some(r.clone());
            }
        }
        let mut local_undo = versioned::BlockUndo::default();
        let mut local_touched: HashSet<EvmAddress> = HashSet::new();
        for item in &decoded {
            let Ok((signed, caller, ..)) = item else { return Err(decoded) };
            local_undo.capture(*caller, snapshot.cache.accounts.get(caller));
            if let tx::TxKind::Call(to) = signed.to() {
                let to = EvmAddress::from(to.0);
                local_undo.capture(to, snapshot.cache.accounts.get(&to));
                local_touched.insert(to);
            }
            local_touched.insert(*caller);
        }
        local_undo.capture(coinbase, snapshot.cache.accounts.get(&coinbase));
        local_touched.insert(coinbase);

        // Everything checked: release the lane overlays and the snapshot so the main
        // state is uniquely owned, then apply.
        drop(outs);
        drop(snapshot);
        {
            let mut guard = framework::lock_state(&self.db);
            let db = Arc::make_mut(&mut *guard);
            for (addr, balance, nonce, code_hash) in sender_final {
                let slot = db.cache.accounts.entry(addr);
                let acct = slot.or_insert_with(revm::database::DbAccount::new_not_existing);
                acct.info.balance = balance;
                acct.info.nonce = nonce;
                acct.info.code_hash = if code_hash == revm::primitives::B256::ZERO {
                    revm::primitives::KECCAK_EMPTY
                } else {
                    code_hash
                };
                acct.account_state = revm::database::AccountState::Touched;
            }
            for (addr, (template, delta)) in credit {
                match db.cache.accounts.entry(addr) {
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        // An existing main-state entry keeps its storage and code; only
                        // the fields the serial lane would change are updated. An
                        // unmodified account (zero delta, not Touched) is left as is.
                        if template.account_state == revm::database::AccountState::Touched {
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
                        // entry, with the balance replaced by the merged total.
                        let mut acct = template;
                        acct.info.balance = delta;
                        e.insert(acct);
                    }
                }
            }
        }
        {
            let mut touched = framework::lock_state(&self.touched);
            touched.extend(local_touched);
        }
        {
            let mut undo = framework::lock_state(&self.block_undo);
            for (addr, entry) in local_undo.accounts {
                undo.accounts.entry(addr).or_insert(entry);
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
