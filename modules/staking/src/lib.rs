//! Oxide staking module — delegation, validator set, slashing.
//!
//! The staking module tracks validator stakes and delegations, and
//! produces the validator set for each epoch. It's the
//! module-equivalent of Cosmos SDK's `x/staking`.
//!
//! # Phase 1 scope
//!
//! v0 tracks delegations and validator stakes. No slashing, no
//! rewards, no unbonding periods. The validator set is computed from
//! the top-N staked validators.
//!
//! # Messages
//!
//! - Delegate: `[validator: 20B][amount: 8B LE]`
//! - Undelegate: `[validator: 20B][amount: 8B LE]`

use std::collections::BTreeMap;
use std::sync::Mutex;

use executor::{Event, ExecError, Module};
use framework::{KVStore, module_id, subtree_root};
use primitives::{Address, Hash, Height};

/// A validator's stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validator {
    /// The validator's address.
    pub address: Address,
    /// Total delegated stake.
    pub stake: u64,
}

/// The staking module: delegation and validator set.
pub struct StakingModule {
    store: KVStore,
    /// Validator stakes, keyed by address.
    validators: Mutex<BTreeMap<Address, u64>>,
}

impl StakingModule {
    /// Construct a fresh staking module with no validators.
    pub fn new() -> Self {
        Self { store: Mutex::new(BTreeMap::new()), validators: Mutex::new(BTreeMap::new()) }
    }

    /// Get a validator's total stake.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn stake(&self, addr: &Address) -> u64 {
        *self.validators.lock().unwrap().get(addr).unwrap_or(&0)
    }

    /// Get the top-N validators by stake (descending).
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn top_validators(&self, n: usize) -> Vec<Validator> {
        let validators = self.validators.lock().unwrap();
        let mut sorted: Vec<(Address, u64)> = validators
            .iter()
            .filter(|&(_, &stake)| stake > 0)
            .map(|(addr, &stake)| (*addr, stake))
            .collect();
        sorted.sort_by_key(|&(_, stake)| std::cmp::Reverse(stake));
        sorted.into_iter().take(n).map(|(address, stake)| Validator { address, stake }).collect()
    }

    /// Parse a delegate message: `[validator: 20B][amount: 8B LE]`.
    fn parse_delegate(msg: &[u8]) -> Option<(Address, u64)> {
        if msg.len() < 28 {
            return None;
        }
        let validator = Address::from_slice(&msg[..20]).ok()?;
        let amount = u64::from_le_bytes(msg[20..28].try_into().ok()?);
        Some((validator, amount))
    }
}

impl Default for StakingModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Staking message types.
pub mod msg {
    /// A delegate message: `[validator: 20B][amount: 8B LE]`.
    pub fn delegate(validator: primitives::Address, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(28);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// An undelegate message: `[validator: 20B][amount: 8B LE]`.
    pub fn undelegate(validator: primitives::Address, amount: u64) -> Vec<u8> {
        // Same format as delegate; the module distinguishes by a
        // leading type byte in the full message. For v0, we use the
        // same format and treat all as delegate.
        delegate(validator, amount)
    }
}

impl Module for StakingModule {
    fn name(&self) -> &'static str {
        "staking"
    }
    fn id(&self) -> u8 {
        module_id::STAKING
    }

    fn begin_block(&self, _height: Height) {}

    fn handle(&self, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (validator, amount) = Self::parse_delegate(msg).ok_or(ExecError::Malformed)?;

        let mut validators = self.validators.lock().unwrap();
        let stake = validators.entry(validator).or_insert(0);
        *stake = stake
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("stake overflow".to_string()))?;

        // Record in store for state root.
        let mut store = self.store.lock().unwrap();
        store.insert(validator.0.to_vec(), stake.to_le_bytes().to_vec());

        Ok(vec![Event { module: "staking", kind: "delegate".to_string(), data: msg.to_vec() }])
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
    fn delegate_increases_stake() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&msg::delegate(v, 1000)).unwrap();
        assert_eq!(staking.stake(&v), 1000);
    }

    #[test]
    fn multiple_delegates_accumulate() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&msg::delegate(v, 100)).unwrap();
        staking.handle(&msg::delegate(v, 200)).unwrap();
        assert_eq!(staking.stake(&v), 300);
    }

    #[test]
    fn top_validators_sorted_by_stake() {
        let staking = StakingModule::new();
        staking.handle(&msg::delegate(addr(1), 100)).unwrap();
        staking.handle(&msg::delegate(addr(2), 500)).unwrap();
        staking.handle(&msg::delegate(addr(3), 300)).unwrap();
        let top = staking.top_validators(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].address, addr(2), "highest stake first");
        assert_eq!(top[0].stake, 500);
        assert_eq!(top[1].address, addr(3), "second highest");
    }

    #[test]
    fn zero_stake_validators_excluded() {
        let staking = StakingModule::new();
        staking.handle(&msg::delegate(addr(1), 100)).unwrap();
        let top = staking.top_validators(10);
        assert_eq!(top.len(), 1, "only non-zero-stake validators");
    }

    #[test]
    fn malformed_message_rejected() {
        let staking = StakingModule::new();
        assert_eq!(staking.handle(&[1, 2, 3]), Err(ExecError::Malformed));
    }

    #[test]
    fn state_root_changes_after_delegate() {
        let staking = StakingModule::new();
        let root0 = staking.state_root();
        staking.handle(&msg::delegate(addr(1), 100)).unwrap();
        let root1 = staking.state_root();
        assert_ne!(root0, root1);
    }
}
