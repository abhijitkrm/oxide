//! Delegations and delegated bundles (`docs/delegated-bundle-spec.md`): cheap authentication on
//! the chain path. An owner delegates to an agent once (one signature); the agent then signs ONE
//! transaction carrying many owners' orders, each item authorized by a table lookup instead of a
//! signature recovery.
//!
//! Delegations live in the exchange's committed key-value store, so they are folded into the
//! state root and exported in snapshots with no state-format change.

use std::collections::BTreeMap;

use executor::{Event, ExecError, RejectCategory, TxContext};
use primitives::Address;

use super::{
    ExchangeModule, Inner, MAX_BUNDLE_BYTES, MAX_BUNDLE_ITEMS, PRICE_SCALE, TAG_CANCEL, TAG_PLACE,
};

/// Store key prefix of a delegation: `"dlg/" || owner || agent`.
pub(crate) const DELEGATION_PREFIX: &[u8; 4] = b"dlg/";

/// Length of a delegation key in bytes (prefix + owner + agent).
pub(crate) const DELEGATION_KEY_LEN: usize = 4 + 20 + 20;

/// Flag: the agent may place orders for the owner.
pub(crate) const FLAG_PLACE: u8 = 1;
/// Flag: the agent may cancel orders for the owner.
pub(crate) const FLAG_CANCEL: u8 = 2;
/// All flags this version understands; a delegation with other bits is refused.
const FLAGS_KNOWN: u8 = FLAG_PLACE | FLAG_CANCEL;

/// Body length of a delegate message: `[agent:20][flags:1][expiry:8][max_item_notional:8]`.
pub(crate) const DELEGATE_BODY_LEN: usize = 20 + 1 + 8 + 8;
/// Body length of a revoke message: `[agent:20]`.
pub(crate) const REVOKE_BODY_LEN: usize = 20;
/// Encoded delegation value length: `flags || expiry || max_item_notional`.
const DELEGATION_VALUE_LEN: usize = 1 + 8 + 8;

/// A decoded delegation: what an agent may do for an owner, and until when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Delegation {
    /// `FLAG_PLACE | FLAG_CANCEL` bits.
    pub(crate) flags: u8,
    /// Valid while `height < expiry`.
    pub(crate) expiry: u64,
    /// Largest `price x qty / PRICE_SCALE` of one placed order (0 = unlimited).
    pub(crate) max_item_notional: u64,
}

/// The store key of `(owner, agent)`'s delegation.
pub(crate) fn delegation_key(owner: &Address, agent: &Address) -> [u8; DELEGATION_KEY_LEN] {
    let mut k = [0u8; DELEGATION_KEY_LEN];
    k[..4].copy_from_slice(DELEGATION_PREFIX);
    k[4..24].copy_from_slice(&owner.0);
    k[24..].copy_from_slice(&agent.0);
    k
}

fn encode_delegation(d: &Delegation) -> Vec<u8> {
    let mut v = Vec::with_capacity(DELEGATION_VALUE_LEN);
    v.push(d.flags);
    v.extend_from_slice(&d.expiry.to_le_bytes());
    v.extend_from_slice(&d.max_item_notional.to_le_bytes());
    v
}

fn decode_delegation(v: &[u8]) -> Option<Delegation> {
    if v.len() != DELEGATION_VALUE_LEN {
        return None;
    }
    Some(Delegation {
        flags: v[0],
        expiry: u64::from_le_bytes(v[1..9].try_into().ok()?),
        max_item_notional: u64::from_le_bytes(v[9..17].try_into().ok()?),
    })
}

fn unauthorized(detail: &str) -> ExecError {
    ExecError::rejected(RejectCategory::Unauthorized, detail.to_string())
}

/// Authorize one delegated-bundle item: may `agent` run an item of kind `tag` (a place body is
/// `rest`) for `owner` at `height`? Pure over the committed store map, so the serial path and the
/// lanes share it. An owner equal to the agent needs no delegation.
pub(crate) fn authorize_item(
    store: &BTreeMap<Vec<u8>, Vec<u8>>,
    height: u64,
    agent: &Address,
    owner: &Address,
    tag: u8,
    rest: &[u8],
) -> Result<(), ExecError> {
    if owner == agent {
        return Ok(());
    }
    let key = delegation_key(owner, agent);
    let d = store
        .get(&key[..])
        .and_then(|v| decode_delegation(v))
        .ok_or_else(|| unauthorized("dbundle: no delegation"))?;
    if height >= d.expiry {
        return Err(unauthorized("dbundle: delegation expired"));
    }
    let needed = if tag == TAG_PLACE { FLAG_PLACE } else { FLAG_CANCEL };
    if d.flags & needed == 0 {
        return Err(unauthorized("dbundle: delegation does not allow this action"));
    }
    if tag == TAG_PLACE
        && d.max_item_notional > 0
        && let Some((_, order, _)) = ExchangeModule::parse_place(rest)
    {
        let notional = u128::from(order.price.0) * u128::from(order.qty.0) / PRICE_SCALE;
        if notional > u128::from(d.max_item_notional) {
            return Err(unauthorized("dbundle: order exceeds the delegated notional"));
        }
    }
    Ok(())
}

impl ExchangeModule {
    /// Validate a delegated bundle's framing and return each item's `(owner, start, end)` span in
    /// `body` (item message only; nothing is executed). Shared by the serial path and the lane
    /// planner so both agree on what is well formed. Only place and cancel items are allowed.
    pub(crate) fn dbundle_spans(body: &[u8]) -> Result<Vec<(Address, usize, usize)>, ExecError> {
        if body.len() > MAX_BUNDLE_BYTES || body.len() < 2 {
            return Err(ExecError::Malformed);
        }
        let count = usize::from(u16::from_le_bytes([body[0], body[1]]));
        if count == 0 || count > MAX_BUNDLE_ITEMS {
            return Err(ExecError::Malformed);
        }
        let mut spans = Vec::with_capacity(count);
        let mut at = 2usize;
        for _ in 0..count {
            let owner_end = at.checked_add(20).ok_or(ExecError::Malformed)?;
            let owner = Address(
                body.get(at..owner_end)
                    .ok_or(ExecError::Malformed)?
                    .try_into()
                    .map_err(|_| ExecError::Malformed)?,
            );
            let len_end = owner_end.checked_add(2).ok_or(ExecError::Malformed)?;
            let len = usize::from(u16::from_le_bytes([
                *body.get(owner_end).ok_or(ExecError::Malformed)?,
                *body.get(owner_end + 1).ok_or(ExecError::Malformed)?,
            ]));
            let end = len_end.checked_add(len).ok_or(ExecError::Malformed)?;
            let item = body.get(len_end..end).ok_or(ExecError::Malformed)?;
            match item.first() {
                Some(&(TAG_PLACE | TAG_CANCEL)) => {}
                _ => return Err(ExecError::Malformed),
            }
            spans.push((owner, len_end, end));
            at = end;
        }
        if at != body.len() {
            return Err(ExecError::Malformed);
        }
        Ok(spans)
    }

    /// The per-item loop of a delegated bundle, with authorization and execution supplied by the
    /// caller (the serial path runs against the live maps, a lane against its overlay). A rejected
    /// item does not abort the bundle; it is reported like a rejected bundle item.
    pub(crate) fn dbundle_core(
        body: &[u8],
        mut exec_item: impl FnMut(&Address, u8, &[u8]) -> Result<Vec<Event>, ExecError>,
    ) -> Result<Vec<Event>, ExecError> {
        let spans = Self::dbundle_spans(body)?;
        let mut events = Vec::new();
        for (i, (owner, start, end)) in spans.into_iter().enumerate() {
            let item = &body[start..end];
            match exec_item(&owner, item[0], &item[1..]) {
                Ok(evs) => events.extend(evs),
                Err(e) => events.push(Self::item_rejected_event(i, &e)),
            }
        }
        Ok(events)
    }

    /// Serial-path handler for a delegated bundle: the envelope sender is the agent.
    pub(crate) fn handle_dbundle(
        &self,
        ctx: &TxContext,
        body: &[u8],
        inner: &mut Inner,
    ) -> Result<Vec<Event>, ExecError> {
        let height = self.height.load(std::sync::atomic::Ordering::Relaxed);
        let store = framework::lock_state(&self.store);
        let agent = ctx.sender;
        Self::dbundle_core(body, |owner, tag, rest| {
            authorize_item(store.inner(), height, &agent, owner, tag, rest)?;
            let octx = TxContext { sender: *owner, ..*ctx };
            match tag {
                TAG_PLACE => self.handle_place(&octx, rest, inner),
                _ => self.handle_cancel(&octx, rest, inner),
            }
        })
    }

    /// Record (or replace) the sender's delegation to an agent.
    pub(crate) fn handle_delegate(
        &self,
        ctx: &TxContext,
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != DELEGATE_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let agent = Address(body[..20].try_into().map_err(|_| ExecError::Malformed)?);
        let flags = body[20];
        let expiry = u64::from_le_bytes(body[21..29].try_into().map_err(|_| ExecError::Malformed)?);
        let max_item_notional =
            u64::from_le_bytes(body[29..37].try_into().map_err(|_| ExecError::Malformed)?);
        if agent == ctx.sender {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                "delegate: an account cannot delegate to itself",
            ));
        }
        if flags == 0 || flags & !FLAGS_KNOWN != 0 {
            return Err(ExecError::rejected(RejectCategory::InvalidInput, "delegate: bad flags"));
        }
        let d = Delegation { flags, expiry, max_item_notional };
        framework::lock_state(&self.store)
            .insert(delegation_key(&ctx.sender, &agent).to_vec(), encode_delegation(&d));
        Ok(vec![Event { module: "exchange", kind: "delegated", data: body.to_vec() }])
    }

    /// Remove the sender's delegation to an agent (absent: a no-op event).
    pub(crate) fn handle_revoke_delegate(
        &self,
        ctx: &TxContext,
        body: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        if body.len() != REVOKE_BODY_LEN {
            return Err(ExecError::Malformed);
        }
        let agent = Address(body[..20].try_into().map_err(|_| ExecError::Malformed)?);
        framework::lock_state(&self.store).remove(&delegation_key(&ctx.sender, &agent).to_vec());
        Ok(vec![Event { module: "exchange", kind: "delegation_revoked", data: body.to_vec() }])
    }
}
