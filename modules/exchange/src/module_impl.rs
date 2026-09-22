//! `framework::Module` and `ParameterSink` adapters for the
//! exchange module.
//!
//! Split from `lib.rs` around the adapter invariant: the
//! consensus-facing lifecycle and the governance parameter sink
//! are the only surfaces the chain drives — one file makes the
//! ordering auditable end-to-end.

use super::{
    Address, Event, ExchangeModule, ExecError, Hash, Height, Module, TAG_BATCH_SETTLE, TAG_CANCEL,
    TAG_CANCEL_REGISTERED, TAG_DEPOSIT_BASE, TAG_LIST_MARKET, TAG_PLACE, TAG_REGISTER_ORDER,
    TAG_WITHDRAW_BASE, TxContext, module_id,
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
                cfg.validate()
                    .map_err(|e| ExecError::ModuleRejected(format!("list_market: {e}")))?;
                drop(inner);
                // Committee-quorum gate: a listing eagerly allocates
                // the market's order-pool and id-map arenas, so an
                // unauthenticated listing is a memory-exhaustion
                // primitive. Each tx endorses the exact tagged
                // message; the market lists only once endorsing power
                // strictly exceeds two-thirds of the committee.
                let Some(committee) = self.committee.clone() else {
                    return Err(ExecError::ModuleRejected(
                        "list_market: no committee wired".to_string(),
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
        // Excluded: `fills` (per-call scratch), `ledger` /
        // `settlement_operator` (assembly wiring, not tx-mutated
        // state).
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
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
                framework::encode_state_blob(w.as_bytes(), &self.store),
            )],
        })
    }

    /// Verify a staged snapshot's claimed root without mutating:
    /// decode the blob, check the store section hashes to the
    /// committed subtree root, fully decode the fields, then hash
    /// the canonical preimage.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let slots = framework::lock_state(&self.inner).markets.len();
        let (canon, _decoded, _store) = framework::stage_blob_snapshot(snapshot, |r, store| {
            Self::decode_committed(r, store, slots)
        })?;
        Ok(framework::canon_root(canon))
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then the fields swap in
    /// atomically (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let slots = framework::lock_state(&self.inner).markets.len();
        let (_canon, (markets, endorsements, registered, balances, holds, fees), store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s, slots))?;
        *framework::lock_state(&self.store) = store;
        let mut inner = framework::lock_state(&self.inner);
        inner.markets = markets;
        inner.registered = registered;
        inner.base_balances = balances;
        inner.base_holds = holds;
        inner.fee_vault = fees;
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
            return Err(ExecError::ModuleRejected(
                "exchange: unknown governed parameter".to_string(),
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
            return Err(ExecError::ModuleRejected("fee_vault.withdraw: zero amount".to_string()));
        }
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::ModuleRejected("fee_vault.withdraw: no ledger wired".to_string())
        })?;
        let mut inner = framework::lock_state(&self.inner);
        let vault = inner.fee_vault.get(&market).copied().unwrap_or(0);
        if vault < amount {
            return Err(ExecError::ModuleRejected(
                "fee_vault.withdraw: insufficient vault balance".to_string(),
            ));
        }
        // Credit before decrementing custody — same ordering as
        // `handle_withdraw_base`: a credit failure leaves the vault
        // untouched (the proposal then records ApplyFailed rather
        // than silently losing the funds).
        ledger.credit(&dest, amount).map_err(|_| {
            ExecError::ModuleRejected("fee_vault.withdraw: credit failed".to_string())
        })?;
        // `vault >= amount` was just proven — cannot underflow.
        *inner.fee_vault.get_mut(&market).ok_or(ExecError::Malformed)? -= amount;
        Ok(())
    }
}
