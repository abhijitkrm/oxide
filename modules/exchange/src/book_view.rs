//! The custody and ledger surface a book-path order touches, as a trait.
//!
//! `place`, `cancel` and settlement move four kinds of state: the native ledger (quote
//! debits and credits), free base custody, resting-sell base holds and the per-market fee
//! vault. Reaching them only through [`BookView`] lets the same code run in two places
//! with identical results: serially against the live committed maps ([`SerialBook`], the
//! consensus path), and inside an execution lane against a private overlay
//! (`lanes::LaneBook`, `docs/multi-market-lanes-spec.md`). One body, two backends: the
//! lane path cannot drift from the serial path by construction, and the differential
//! tests compare the two end to end.

use std::sync::Arc;

use executor::ExecError;
use primitives::Address;
use primitives::fixed::Qty;

/// Ledger and custody operations of a book-path order. Getters return `None` for an
/// absent key, because "present with value zero" and "absent" differ in the committed
/// fold; setters always write, exactly like the map inserts they replace.
pub(crate) trait BookView {
    /// Decrease `addr`'s native balance; fails on insufficient funds.
    fn debit(&mut self, addr: &Address, amount: u64) -> Result<(), ExecError>;
    /// Increase `addr`'s native balance.
    fn credit(&mut self, addr: &Address, amount: u64) -> Result<(), ExecError>;
    /// Free base custody of `(owner, market)`.
    fn bal(&self, key: &(Address, u8)) -> Option<Qty>;
    /// Overwrite free base custody of `(owner, market)`.
    fn set_bal(&mut self, key: (Address, u8), value: Qty);
    /// Base locked by `(owner, market)`'s resting sells.
    fn hold(&self, key: &(Address, u8)) -> Option<Qty>;
    /// Overwrite base held by `(owner, market)`'s resting sells.
    fn set_hold(&mut self, key: (Address, u8), value: Qty);
    /// Accrued protocol fees of `market`.
    fn vault(&self, market: u8) -> Option<u64>;
    /// Overwrite accrued protocol fees of `market`.
    fn set_vault(&mut self, market: u8, value: u64);
}

/// The consensus path: the live ledger and the module's committed maps.
pub(crate) struct SerialBook<'a> {
    /// The native ledger; `None` is the matching-only test mode (never called: callers
    /// gate every ledger operation on the ledger being wired).
    pub(crate) ledger: Option<&'a Arc<dyn framework::Balances + Send + Sync>>,
    /// Free base custody.
    pub(crate) base_balances: &'a mut framework::CommittedMap<(Address, u8), Qty>,
    /// Resting-sell base holds.
    pub(crate) base_holds: &'a mut framework::CommittedMap<(Address, u8), Qty>,
    /// Per-market fee sink.
    pub(crate) fee_vault: &'a mut framework::CommittedMap<u8, u64>,
}

impl BookView for SerialBook<'_> {
    fn debit(&mut self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        self.ledger.map_or(Ok(()), |l| l.debit(addr, amount))
    }
    fn credit(&mut self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        self.ledger.map_or(Ok(()), |l| l.credit(addr, amount))
    }
    fn bal(&self, key: &(Address, u8)) -> Option<Qty> {
        self.base_balances.get(key).copied()
    }
    fn set_bal(&mut self, key: (Address, u8), value: Qty) {
        self.base_balances.insert(key, value);
    }
    fn hold(&self, key: &(Address, u8)) -> Option<Qty> {
        self.base_holds.get(key).copied()
    }
    fn set_hold(&mut self, key: (Address, u8), value: Qty) {
        self.base_holds.insert(key, value);
    }
    fn vault(&self, market: u8) -> Option<u64> {
        self.fee_vault.get(&market).copied()
    }
    fn set_vault(&mut self, market: u8, value: u64) {
        self.fee_vault.insert(market, value);
    }
}
