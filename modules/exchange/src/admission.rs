//! Admission rules for zero-fee orders.
//!
//! Orders (place, cancel, amend, bundles and delegated bundles) cost no fee: the exchange tells the
//! executor their fee floor is 0 (`Module::min_fee_for`). Free must not mean unbounded, so a message
//! only enters the pool if its sender can fund what it asks for:
//!
//! - a limit buy needs the payer's native balance to cover its worst-case reservation;
//! - a market buy needs a non-zero balance (its true cost depends on the live book);
//! - a sell needs base custody for its quantity (best effort: custody sits behind the exchange's main
//!   lock, which execution holds for whole lane runs, so the check is skipped when the lock is busy);
//! - a delegated bundle needs every item authorized (best effort on the same terms).
//!
//! This is an admission filter only. Execution stays authoritative: escrow is taken at execution and a
//! failing order moves nothing, so a stale or skipped check can waste block space but never funds.

use executor::{ExecError, RejectCategory, TxContext};
use primitives::Address;
use trading::{OrderType, Side};

use super::{
    ExchangeModule, PRICE_SCALE, TAG_AMEND, TAG_BUNDLE, TAG_CANCEL, TAG_DBUNDLE, TAG_PLACE,
    delegation::authorize_item,
};

/// What the items of one message ask for, per payer.
#[derive(Default)]
struct Needs {
    /// Worst-case quote reservation of limit buys.
    buys: Vec<(Address, u128)>,
    /// Payers with a market buy (non-zero balance required).
    market_buyers: Vec<Address>,
    /// Base quantity of sells per `(payer, market)`.
    sells: Vec<((Address, u8), u128)>,
}

fn add<K: PartialEq + Copy>(v: &mut Vec<(K, u128)>, key: K, amount: u128) {
    match v.iter_mut().find(|(k, _)| *k == key) {
        Some((_, a)) => *a += amount,
        None => v.push((key, amount)),
    }
}

fn insufficient(detail: &str) -> ExecError {
    ExecError::rejected(RejectCategory::InsufficientFunds, detail.to_string())
}

/// Record what one item (`tag` + body `rest`) needs from `payer`; place bodies must parse.
fn collect(payer: Address, tag: u8, rest: &[u8], needs: &mut Needs) -> Result<(), ExecError> {
    match tag {
        TAG_PLACE => {
            let (market, order, _) =
                ExchangeModule::parse_place(rest).ok_or(ExecError::Malformed)?;
            match order.side {
                Side::Buy if order.order_type == OrderType::Market => {
                    if !needs.market_buyers.contains(&payer) {
                        needs.market_buyers.push(payer);
                    }
                }
                Side::Buy => {
                    let q = u128::from(order.price.0) * u128::from(order.qty.0) / PRICE_SCALE;
                    add(&mut needs.buys, payer, q);
                }
                Side::Sell => add(&mut needs.sells, (payer, market), u128::from(order.qty.0)),
            }
            Ok(())
        }
        // Cancels release funds and amends net them: nothing to prove up front.
        TAG_CANCEL | TAG_AMEND => Ok(()),
        _ => Err(ExecError::Malformed),
    }
}

impl ExchangeModule {
    /// The fee floor of an order message: 0 (free by design). Everything else follows the chain floor.
    pub(crate) fn order_fee_floor(payload: &[u8]) -> Option<u64> {
        match payload.first() {
            Some(&(TAG_PLACE | TAG_CANCEL | TAG_AMEND | TAG_BUNDLE | TAG_DBUNDLE)) => Some(0),
            _ => None,
        }
    }

    /// Admission check for an order message; see the module docs. `Ok` for every other message kind.
    pub(crate) fn admit_order(&self, ctx: &TxContext, msg: &[u8]) -> Result<(), ExecError> {
        let Some(ledger) = self.ledger.as_ref() else {
            return Ok(());
        };
        let Some((&tag, body)) = msg.split_first() else {
            return Err(ExecError::Malformed);
        };
        let mut needs = Needs::default();
        let mut delegated: Vec<(Address, u8, &[u8])> = Vec::new();
        match tag {
            TAG_PLACE | TAG_AMEND | TAG_CANCEL => collect(ctx.sender, tag, body, &mut needs)?,
            TAG_BUNDLE => {
                for (a, b) in Self::bundle_spans(body)? {
                    collect(ctx.sender, body[a], &body[a + 1..b], &mut needs)?;
                }
            }
            TAG_DBUNDLE => {
                for (owner, a, b) in Self::dbundle_spans(body)? {
                    collect(owner, body[a], &body[a + 1..b], &mut needs)?;
                    delegated.push((owner, body[a], &body[a + 1..b]));
                }
            }
            _ => return Ok(()),
        }
        for (payer, need) in &needs.buys {
            if u128::from(framework::Balances::balance(&**ledger, payer)) < *need {
                return Err(insufficient("insufficient balance for order"));
            }
        }
        for payer in &needs.market_buyers {
            if framework::Balances::balance(&**ledger, payer) == 0 {
                return Err(insufficient("no balance for market buy"));
            }
        }
        if !needs.sells.is_empty()
            && let Ok(inner) = self.inner.try_lock()
        {
            for ((payer, market), qty) in &needs.sells {
                let have = inner.base_balances.get(&(*payer, *market)).map_or(0, |q| q.0);
                if u128::from(have) < *qty {
                    return Err(insufficient("insufficient base custody for sell order"));
                }
            }
        }
        if !delegated.is_empty()
            && let Ok(store) = self.store.try_lock()
        {
            let height = self.height.load(std::sync::atomic::Ordering::Relaxed);
            for (owner, t, rest) in delegated {
                authorize_item(store.inner(), height, &ctx.sender, &owner, t, rest)?;
            }
        }
        Ok(())
    }
}
