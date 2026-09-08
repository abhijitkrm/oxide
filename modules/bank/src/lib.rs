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

use executor::{Event, ExecError, Module};
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
        let store = self.store.lock().unwrap();
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
        let mut store = self.store.lock().unwrap();
        let bal = store
            .get(&addr.0[..])
            .map_or(0, |v| u64::from_le_bytes(v.as_slice().try_into().unwrap_or([0u8; 8])));
        let new_bal = bal.checked_add(amount).expect("balance overflow");
        store.insert(addr.0.to_vec(), new_bal.to_le_bytes().to_vec());
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

    fn handle(&self, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (to, amount) = Self::parse_transfer(msg).ok_or(ExecError::Malformed)?;

        // In v0, the sender is not yet passed to `handle` (the executor
        // doesn't extract it from the tx envelope). For now, we accept
        // the transfer as a "mint to recipient" — the real sender
        // extraction arrives when the executor passes the tx context.
        // This is a known limitation documented in the devlog.
        let mut store = self.store.lock().unwrap();
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

    #[test]
    fn transfer_increments_recipient_balance() {
        let bank = BankModule::new();
        let to = addr(2);
        let msg = msg::transfer(to, 100);
        bank.handle(&msg).unwrap();
        assert_eq!(bank.balance(&to), 100);
    }

    #[test]
    fn multiple_transfers_accumulate() {
        let bank = BankModule::new();
        let to = addr(3);
        bank.handle(&msg::transfer(to, 50)).unwrap();
        bank.handle(&msg::transfer(to, 30)).unwrap();
        assert_eq!(bank.balance(&to), 80);
    }

    #[test]
    fn malformed_message_rejected() {
        let bank = BankModule::new();
        assert_eq!(bank.handle(&[1, 2, 3]), Err(ExecError::Malformed));
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
        let root0 = bank.state_root();
        bank.handle(&msg::transfer(addr(1), 100)).unwrap();
        let root1 = bank.state_root();
        assert_ne!(root0, root1);
    }
}
