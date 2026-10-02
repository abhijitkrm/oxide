//! `framework::Module` and `ParameterSink` adapters for the
//! exchange module.
//!
//! Split from `lib.rs` around the adapter invariant: the
//! consensus-facing lifecycle and the governance parameter sink
//! are the only surfaces the chain drives — one file makes the
//! ordering auditable end-to-end.

use super::{
    Address, Event, ExchangeModule, ExecError, Hash, Height, Module, RejectCategory,
    TAG_BATCH_SETTLE, TAG_CANCEL, TAG_CANCEL_REGISTERED, TAG_DEPOSIT_BASE, TAG_LIST_MARKET,
    TAG_PLACE, TAG_REGISTER_ORDER, TAG_WITHDRAW_BASE, TxContext, base_balances_leaf,
    base_holds_leaf, decode, fee_vault_leaf, module_id, registered_leaf, store_leaf,
};

impl Module for ExchangeModule {
    fn name(&self) -> &'static str {
        "exchange"
    }

    fn id(&self) -> u8 {
        module_id::EXCHANGE
    }

    fn begin_block(&self, _height: Height) {}

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.is_empty() {
            return Err(ExecError::Malformed);
        }
        let tag = msg[0];
        let body = &msg[1..];

        let mut inner = framework::lock_state(&self.inner);

        match tag {
            TAG_PLACE => self.handle_place(ctx, body, &mut inner),

            TAG_CANCEL => self.handle_cancel(ctx, body, &mut inner),

            TAG_LIST_MARKET => {
                let cfg = Self::parse_list_market(body).ok_or(ExecError::Malformed)?;
                // Reject an invalid config before recording an
                // endorsement — pending actions are a bounded set, so
                // a proposal that can never apply must not occupy a
                // slot. This also bounds the allocation `list_market`
                // performs at quorum: `validate` caps `max_resting`
                // at `MAX_RESTING_LIMIT`.
                cfg.validate().map_err(|e| {
                    ExecError::rejected(RejectCategory::Internal, format!("list_market: {e}"))
                })?;
                drop(inner);
                // Committee-quorum gate: a listing eagerly allocates
                // the market's order-pool and id-map arenas, so an
                // unauthenticated listing is a memory-exhaustion
                // primitive. Each tx endorses the exact tagged
                // message; the market lists only once endorsing power
                // strictly exceeds two-thirds of the committee.
                let Some(committee) = self.committee.clone() else {
                    return Err(ExecError::rejected(
                        RejectCategory::Unauthorized,
                        "list_market: no committee wired",
                    ));
                };
                match self.endorsements.record(msg, &ctx.sender, committee.as_ref())? {
                    framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                        module: "exchange",
                        kind: "list_market_endorse",
                        data: body.to_vec(),
                    }]),
                    framework::EndorsementOutcome::Quorum => match self.list_market(cfg) {
                        Ok(id) => Ok(vec![Event {
                            module: "exchange",
                            kind: "market_listed",
                            data: vec![id],
                        }]),
                        // Quorum reached but the listing no longer
                        // applies (e.g. all slots filled while the
                        // proposal accumulated votes).
                        Err(_) => Ok(vec![Event {
                            module: "exchange",
                            kind: "list_market_stale",
                            data: body.to_vec(),
                        }]),
                    },
                }
            }

            TAG_BATCH_SETTLE => self.handle_batch_settle(ctx, body, &mut inner),

            TAG_REGISTER_ORDER => self.handle_register(ctx, body, &mut inner),

            TAG_CANCEL_REGISTERED => self.handle_cancel_registered(ctx, body, &mut inner),

            TAG_DEPOSIT_BASE => self.handle_deposit_base(ctx, body, &mut inner),

            TAG_WITHDRAW_BASE => self.handle_withdraw_base(ctx, body, &mut inner),

            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, _height: Height) -> Vec<Event> {
        Vec::new()
    }

    fn state_root(&self) -> Hash {
        // C8: commit EVERY field that can affect future execution.
        // The KV store (market configs) is only part of it — the
        // live order books decide future fills, cancels, and
        // settlement, so identical roots across validators must
        // prove identical books. Section order is fixed and
        // consensus-critical.
        //
        // Trader-scale maps contribute their maintained fold root
        // (7.4): a block's root work no longer re-serializes every
        // registration and custody record — only the market engines
        // still walk their books (the resting-order fold lives
        // inside the matcher's mutation path, a separate residual).
        //
        // Excluded: `fills` (per-call scratch), `ledger` /
        // `settlement_operator` (assembly wiring, not tx-mutated
        // state).
        let store = framework::lock_state(&self.store);
        let inner = framework::lock_state(&self.inner);
        let view = decode::RootView {
            store_fold: store.root(),
            markets: &inner.markets,
            endorsements: &self.endorsements,
            registered_fold: inner.registered.root(),
            base_balances_fold: inner.base_balances.root(),
            base_holds_fold: inner.base_holds.root(),
            fee_vault_fold: inner.fee_vault.root(),
        };
        let mut w = framework::CanonicalState::new();
        decode::write_root_preimage(&view, &mut w);
        w.root()
    }

    /// Export the committed state as one canonical blob —
    /// `canon ‖ store`. The canon section is the `state_root`
    /// preimage, so a peer can verify the claimed root before
    /// installing anything (audit 3.2).
    fn export_state(&self) -> Option<storage::Snapshot> {
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        Some(storage::Snapshot {
            height: 0,
            entries: vec![(
                framework::state_blob_key(),
                framework::encode_state_blob(
                    w.as_bytes(),
                    framework::lock_state(&self.store).inner(),
                ),
            )],
        })
    }

    /// Verify a staged snapshot's claimed root without mutating:
    /// decode the blob, check the store section hashes to the
    /// committed subtree root, fully decode the fields, then
    /// recompute the incremental root over the staged state —
    /// folded maps fold over the staged `BTreeMap`s (`fold_map`),
    /// serialized sections serialize the staged fields, so the
    /// result equals the `state_root` this state would produce
    /// once installed.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let slots = framework::lock_state(&self.inner).markets.len();
        let (_canon, (markets, endorsements, registered, balances, holds, fees), store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        let view = decode::RootView {
            store_fold: framework::CommittedStore::fold_map(&store, store_leaf),
            markets: &markets,
            endorsements: &endorsements,
            registered_fold: framework::CommittedMap::fold_map(&registered, registered_leaf),
            base_balances_fold: framework::CommittedMap::fold_map(&balances, base_balances_leaf),
            base_holds_fold: framework::CommittedMap::fold_map(&holds, base_holds_leaf),
            fee_vault_fold: framework::CommittedMap::fold_map(&fees, fee_vault_leaf),
        };
        let mut w = framework::CanonicalState::new();
        decode::write_root_preimage(&view, &mut w);
        Ok(w.root())
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then the fields swap in
    /// atomically (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let slots = framework::lock_state(&self.inner).markets.len();
        let (_canon, (markets, endorsements, registered, balances, holds, fees), store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        *framework::lock_state(&self.store) =
            framework::CommittedStore::from_map(store, store_leaf);
        let mut inner = framework::lock_state(&self.inner);
        inner.markets = markets;
        inner.registered = framework::CommittedMap::from_map(registered, registered_leaf);
        inner.base_balances = framework::CommittedMap::from_map(balances, base_balances_leaf);
        inner.base_holds = framework::CommittedMap::from_map(holds, base_holds_leaf);
        inner.fee_vault = framework::CommittedMap::from_map(fees, fee_vault_leaf);
        // `fills` is per-call scratch — clear it so a buffer left
        // mid-transaction cannot leak across the import boundary.
        inner.fills.clear();
        drop(inner);
        // Restore the pending-endorsement tally so an in-flight
        // listing resumes accumulating exactly where the snapshot
        // left it — the tally is committed state, not local cache.
        self.endorsements.replace_with(endorsements);
        Ok(())
    }
}

/// Governance-enacted parameter application — the module's half of
/// the deposit → quorum → veto → timelock → apply lifecycle. The
/// exchange registers under the `"exchange"` prefix and owns exactly
/// one key:
///
/// `exchange.fee_vault.withdraw` — value `[market:1B][dest:20B]
/// [amount:8B LE]` (29 bytes): pays `amount` of the market's accrued
/// fee vault out of module custody directly to `dest`'s ledger
/// balance. The vault is a sink by design — the ONLY exit is this
/// governance-gated path, so fee spending carries a deposited,
/// quorum-decided, timelocked mandate rather than any single key.
///
/// Rejects foreign keys (the sink owns its keyspace, not governance's
/// routing guesses), malformed values, zero amounts, and a vault that
/// does not cover the amount — an `Err` lands the proposal in
/// `ApplyFailed`, terminal, never retried.
impl framework::ParameterSink for ExchangeModule {
    fn apply_param(&self, key: &[u8], value: &[u8]) -> Result<(), ExecError> {
        if key != b"exchange.fee_vault.withdraw" {
            return Err(ExecError::rejected(
                RejectCategory::NotFound,
                "exchange: unknown governed parameter",
            ));
        }
        if value.len() != 29 {
            return Err(ExecError::Malformed);
        }
        let market = value[0];
        let Ok(dest_bytes) = <[u8; 20]>::try_from(&value[1..21]) else {
            return Err(ExecError::Malformed);
        };
        let Ok(amount_bytes) = <[u8; 8]>::try_from(&value[21..29]) else {
            return Err(ExecError::Malformed);
        };
        let dest = Address(dest_bytes);
        let amount = u64::from_le_bytes(amount_bytes);
        if amount == 0 {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                "fee_vault.withdraw: zero amount",
            ));
        }
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::rejected(RejectCategory::Internal, "fee_vault.withdraw: no ledger wired")
        })?;
        let mut inner = framework::lock_state(&self.inner);
        let vault = inner.fee_vault.get(&market).copied().unwrap_or(0);
        if vault < amount {
            return Err(ExecError::rejected(
                RejectCategory::InsufficientFunds,
                "fee_vault.withdraw: insufficient vault balance",
            ));
        }
        // Credit before decrementing custody — same ordering as
        // `handle_withdraw_base`: a credit failure leaves the vault
        // untouched (the proposal then records ApplyFailed rather
        // than silently losing the funds).
        ledger.credit(&dest, amount).map_err(|_| {
            ExecError::rejected(RejectCategory::Internal, "fee_vault.withdraw: credit failed")
        })?;
        // `vault >= amount` was just proven — saturating is the same
        // value and cannot panic under release `overflow-checks`.
        inner.fee_vault.insert(market, vault.saturating_sub(amount));
        Ok(())
    }
}
