//! Oxide bank module — token transfers, balances, supply tracking.
//!
//! The bank module is the simplest application module: it tracks
//! account balances and processes transfer messages. It's the
//! module-equivalent of Cosmos SDK's `x/bank`.
//!
//! # Message format
//!
//! A bank transfer message is: `[to: 20B][amount: 8B LE]`.
//! The sender is parsed from the tx envelope (the mempool's
//! `[sender: 20B]` prefix).
//!
//! # State
//!
//! Balances are stored in the module's KV subtree, keyed by address:
//! `[address: 20B] -> [balance: 8B LE]`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::{KVStore, module_id, subtree_root};
use primitives::{Address, Hash, Height};

/// The bank module: token transfers and balances.
pub struct BankModule {
    store: KVStore,
}

impl BankModule {
    /// Construct a fresh bank module with no balances.
    pub fn new() -> Self {
        Self { store: Mutex::new(BTreeMap::new()) }
    }

    /// Get an account's balance.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned.
    pub fn balance(&self, addr: &Address) -> u64 {
        let store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        store
            .get(&addr.0[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])))
    }

    /// Mint tokens to an account (for genesis / staking rewards).
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned or the balance overflows.
    pub fn mint(&self, addr: &Address, amount: u64) {
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let bal = store
            .get(&addr.0[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])));
        let new_bal = bal.checked_add(amount).expect("balance overflow");
        store.insert(addr.0.to_vec(), new_bal.to_le_bytes().to_vec());
    }

    /// Debit `amount` from `addr`. Called by other modules (exchange,
    /// perps) during cross-module settlement.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] if the balance is
    /// insufficient or overflows (should not happen with a checked
    /// debit, but guards against corrupted state).
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned.
    pub fn debit(&self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let bal = store
            .get(&addr.0[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])));
        let new_bal = bal
            .checked_sub(amount)
            .ok_or_else(|| ExecError::ModuleRejected("insufficient balance".to_string()))?;
        store.insert(addr.0.to_vec(), new_bal.to_le_bytes().to_vec());
        Ok(())
    }

    /// Credit `amount` to `addr`. Called by other modules (exchange,
    /// perps) during cross-module settlement.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] on balance overflow.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned.
    pub fn credit(&self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let bal = store
            .get(&addr.0[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])));
        let new_bal = bal
            .checked_add(amount)
            .ok_or_else(|| ExecError::ModuleRejected("balance overflow".to_string()))?;
        store.insert(addr.0.to_vec(), new_bal.to_le_bytes().to_vec());
        Ok(())
    }

    /// Atomic transfer: debit `from`, credit `to`. Called by other
    /// modules during settlement. If the debit succeeds but the credit
    /// fails (overflow), the debit is rolled back.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::ModuleRejected`] if the sender has
    /// insufficient balance or the recipient balance overflows.
    ///
    /// # Panics
    ///
    /// Panics if the store mutex is poisoned.
    pub fn transfer(&self, from: &Address, to: &Address, amount: u64) -> Result<(), ExecError> {
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let from_bal = store
            .get(&from.0[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])));
        let new_from_bal = from_bal
            .checked_sub(amount)
            .ok_or_else(|| ExecError::ModuleRejected("insufficient balance".to_string()))?;
        let to_bal = store
            .get(&to.0[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])));
        let new_to_bal = to_bal
            .checked_add(amount)
            .ok_or_else(|| ExecError::ModuleRejected("recipient balance overflow".to_string()))?;
        // Both checks passed — commit.
        store.insert(from.0.to_vec(), new_from_bal.to_le_bytes().to_vec());
        store.insert(to.0.to_vec(), new_to_bal.to_le_bytes().to_vec());
        Ok(())
    }

    /// Parse a transfer message: `[to: 20B][amount: 8B LE]`.
    fn parse_transfer(msg: &[u8]) -> Option<(Address, u64)> {
        if msg.len() < 28 {
            return None;
        }
        let to = Address::from_slice(&msg[..20]).ok()?;
        let amount = u64::from_le_bytes(msg[20..28].try_into().ok()?);
        Some((to, amount))
    }

    /// Key for a balance entry.
    fn balance_key(addr: &Address) -> Vec<u8> {
        addr.0.to_vec()
    }
}

impl Default for BankModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Bank message types.
pub mod msg {
    /// A transfer message: `[to: 20B][amount: 8B LE]`.
    pub fn transfer(to: primitives::Address, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(28);
        msg.extend_from_slice(&to.0);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }
}

impl Module for BankModule {
    fn name(&self) -> &'static str {
        "bank"
    }
    fn id(&self) -> u8 {
        module_id::BANK
    }

    fn begin_block(&self, _height: Height) {}

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (to, amount) = Self::parse_transfer(msg).ok_or(ExecError::Malformed)?;

        // C2 fix: debit the sender, credit the recipient. Before
        // this fix, `handle` had no sender context and could only
        // mint to the recipient — the bank was a money printer.
        // Now we debit the sender first and reject if insufficient.
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        // Debit sender.
        let sender_key = Self::balance_key(&ctx.sender);
        let sender_bal = store
            .get(&sender_key[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])));
        let new_sender_bal = sender_bal
            .checked_sub(amount)
            .ok_or(ExecError::ModuleRejected("insufficient balance".to_string()))?;
        store.insert(sender_key, new_sender_bal.to_le_bytes().to_vec());

        // Credit recipient.
        let to_key = Self::balance_key(&to);
        let to_bal = store
            .get(&to_key[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])));
        let new_to_bal = to_bal
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("recipient balance overflow".to_string()))?;
        store.insert(to_key, new_to_bal.to_le_bytes().to_vec());

        Ok(vec![Event { module: "bank", kind: "transfer".to_string(), data: msg.to_vec() }])
    }

    fn end_block(&self, _height: Height) {}

    fn state_root(&self) -> Hash {
        subtree_root(&self.store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn ctx(sender_byte: u8) -> TxContext {
        TxContext { sender: addr(sender_byte), nonce: 0, fee: 0 }
    }

    #[test]
    fn transfer_debits_sender_credits_recipient() {
        let bank = BankModule::new();
        let from = addr(1);
        let to = addr(2);
        bank.mint(&from, 1000);
        let msg = msg::transfer(to, 100);
        bank.handle(&ctx(1), &msg).unwrap();
        assert_eq!(bank.balance(&from), 900);
        assert_eq!(bank.balance(&to), 100);
    }

    #[test]
    fn multiple_transfers_accumulate() {
        let bank = BankModule::new();
        let from = addr(1);
        let to = addr(3);
        bank.mint(&from, 1000);
        bank.handle(&ctx(1), &msg::transfer(to, 50)).unwrap();
        bank.handle(&ctx(1), &msg::transfer(to, 30)).unwrap();
        assert_eq!(bank.balance(&from), 920);
        assert_eq!(bank.balance(&to), 80);
    }

    #[test]
    fn insufficient_balance_rejected() {
        let bank = BankModule::new();
        let from = addr(1);
        let to = addr(2);
        bank.mint(&from, 50);
        let msg = msg::transfer(to, 100);
        let err = bank.handle(&ctx(1), &msg).unwrap_err();
        assert_eq!(err, ExecError::ModuleRejected("insufficient balance".to_string()));
        // Sender balance unchanged.
        assert_eq!(bank.balance(&from), 50);
        // Recipient got nothing.
        assert_eq!(bank.balance(&to), 0);
    }

    #[test]
    fn malformed_message_rejected() {
        let bank = BankModule::new();
        assert_eq!(bank.handle(&ctx(1), &[1, 2, 3]), Err(ExecError::Malformed));
    }

    #[test]
    fn mint_sets_balance() {
        let bank = BankModule::new();
        let a = addr(1);
        bank.mint(&a, 1000);
        assert_eq!(bank.balance(&a), 1000);
    }

    #[test]
    fn state_root_changes_after_transfer() {
        let bank = BankModule::new();
        bank.mint(&addr(1), 1000);
        let root0 = bank.state_root();
        bank.handle(&ctx(1), &msg::transfer(addr(2), 100)).unwrap();
        let root1 = bank.state_root();
        assert_ne!(root0, root1);
    }

    #[test]
    fn zero_balance_transfer_rejected() {
        // A sender with no balance cannot transfer.
        let bank = BankModule::new();
        let to = addr(2);
        let err = bank.handle(&ctx(1), &msg::transfer(to, 1)).unwrap_err();
        assert_eq!(err, ExecError::ModuleRejected("insufficient balance".to_string()));
    }

    #[test]
    fn debit_reduces_balance() {
        let bank = BankModule::new();
        let a = addr(1);
        bank.mint(&a, 1000);
        bank.debit(&a, 300).unwrap();
        assert_eq!(bank.balance(&a), 700);
    }

    #[test]
    fn debit_insufficient_rejected() {
        let bank = BankModule::new();
        let a = addr(1);
        bank.mint(&a, 50);
        let err = bank.debit(&a, 100).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        assert_eq!(bank.balance(&a), 50);
    }

    #[test]
    fn credit_increases_balance() {
        let bank = BankModule::new();
        let a = addr(1);
        bank.credit(&a, 500).unwrap();
        assert_eq!(bank.balance(&a), 500);
    }

    #[test]
    fn transfer_moves_balance_atomically() {
        let bank = BankModule::new();
        let from = addr(1);
        let to = addr(2);
        bank.mint(&from, 1000);
        bank.transfer(&from, &to, 400).unwrap();
        assert_eq!(bank.balance(&from), 600);
        assert_eq!(bank.balance(&to), 400);
    }

    #[test]
    fn transfer_insufficient_rejected() {
        let bank = BankModule::new();
        let from = addr(1);
        let to = addr(2);
        bank.mint(&from, 50);
        let err = bank.transfer(&from, &to, 100).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));
        // Neither balance changed.
        assert_eq!(bank.balance(&from), 50);
        assert_eq!(bank.balance(&to), 0);
    }
}
