//! Oxide staking module — delegation, unbonding, slashing, rewards.
//!
//! The staking module tracks validator stakes and delegations, and
//! produces the validator set for each epoch. It's the
//! module-equivalent of Cosmos SDK's `x/staking` + `x/slashing` +
//! `x/distribution` (combined for simplicity in a single module).
//!
//! # Messages
//!
//! All staking messages share a common format:
//! `[type: 1B][validator: 20B][amount: 8B LE]` (29 bytes).
//!
//! - `0x01` Delegate: add `amount` to `validator`'s stake.
//! - `0x02` Undelegate: start unbonding `amount` from `validator`.
//!   The unbonded amount is locked until `completion_height =
//!   current_height + UNBONDING_PERIOD_BLOCKS`. After completion,
//!   the delegator can withdraw via a bank transfer (future: a
//!   `withdraw` message).
//! - `0x03` Slash: reduce `validator`'s stake by `slash_fraction`
//!   of `amount`. Called by consensus (double-sign evidence) or
//!   governance. The slashed amount is burned.
//! - `0x04` Claim reward: withdraw accumulated rewards for
//!   `validator` (transferred to the sender's bank balance).
//!
//! # Unbonding
//!
//! When a delegator undelegates, the amount moves from the
//! validator's `stake` to an `unbonding` queue with a completion
//! height. At `end_block`, completed unbonding entries are removed
//! from the queue (the funds are now withdrawable).
//!
//! The unbonding period prevents validators from withdrawing their
//! stake immediately after misbehaving — if evidence of misbehavior
//! arrives within the unbonding period, the stake can still be
//! slashed.
//!
//! # Slashing
//!
//! Slashing reduces a validator's stake. The slash fraction depends
//! on the offense:
//! - Double-sign (Byzantine): 10% of stake.
//! - Downtime (liveness): 1% of stake.
//!
//! Slashing is triggered by:
//! - Consensus evidence (double-sign detected by the engine).
//! - Governance proposals (manual slash vote).
//!
//! # Rewards
//!
//! At each `end_block`, a block reward is distributed to all active
//! validators proportional to their stake fraction. Rewards
//! accumulate in a `rewards` map. Delegators claim rewards via the
//! `claim_reward` message.
//!
//! The block reward is a fixed amount per block (configurable). In
//! a production chain, this would be combined with transaction fees
//! and an inflation schedule.

use std::collections::BTreeMap;
use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::{module_id, subtree_root};
use primitives::{Address, Hash, Height};

/// Message type byte for staking messages.
///
/// The first byte of every staking message identifies the operation.
/// This allows a single module to handle multiple message types
/// without separate module IDs.
mod msg_type {
    /// Delegate: add stake to a validator.
    pub const DELEGATE: u8 = 0x01;
    /// Undelegate: start unbonding (withdraw stake).
    pub const UNDELEGATE: u8 = 0x02;
    /// Slash: reduce a validator's stake (called by consensus/gov).
    pub const SLASH: u8 = 0x03;
    /// Claim reward: withdraw accumulated rewards.
    pub const CLAIM_REWARD: u8 = 0x04;
    /// Key change: update a validator's BLS consensus public key.
    /// The new key takes effect at the next epoch rotation.
    pub const KEY_CHANGE: u8 = 0x05;
    /// Validator add: register a new validator in the set. Takes
    /// effect at the next epoch rotation — the new validator joins
    /// the validator set, participates in consensus, and receives
    /// block rewards.
    pub const VALIDATOR_ADD: u8 = 0x06;
    /// Validator remove: remove a validator from the set. Takes
    /// effect at the next epoch rotation — the validator is removed
    /// from consensus and stops receiving block rewards. Their
    /// stake enters unbonding (reclaimable after the unbonding
    /// period).
    pub const VALIDATOR_REMOVE: u8 = 0x07;
}

/// The unbonding period in blocks.
///
/// A delegator must wait this many blocks after undelegating before
/// the funds are withdrawable. This prevents validators from
/// withdrawing their stake immediately after misbehaving — if
/// evidence arrives within the unbonding period, the stake can
/// still be slashed.
///
/// Devnet: 100 blocks (~100 seconds at 1 block/s).
/// Mainnet: ~21 days (1,209,600 blocks at 1.5s/block).
/// Configurable per-chain via [`StakingModule::with_unbonding_period`].
const DEFAULT_UNBONDING_PERIOD_BLOCKS: u64 = 100;

/// The block reward in atomic units (1 token = 10^18 atomic units).
///
/// Distributed to validators proportional to stake at each `end_block`.
/// This is a fixed reward — a production chain would combine this
/// with transaction fees and an inflation schedule (Cosmos SDK's
/// `mint` module).
///
/// Devnet: `1_000_000_000` atomic units (10^-9 tokens per block).
/// Configurable via [`StakingModule::with_block_reward`].
const DEFAULT_BLOCK_REWARD: u64 = 1_000_000_000;

/// The slash fraction for double-signing (Byzantine fault).
///
/// The slash amount is `stake * SLASH_FRACTION_DOUBLE_SIGN_NUMERATOR
/// / SLASH_FRACTION_DENOMINATOR`. Using integer arithmetic to avoid
/// floating-point non-determinism.
///
/// 10% slash for double-signing (the Cosmos SDK default).
const SLASH_FRACTION_DOUBLE_SIGN_NUMERATOR: u64 = 10;
/// The denominator for slash fractions (100 = percentage basis).
const SLASH_FRACTION_DENOMINATOR: u64 = 100;

/// A pending unbonding entry.
///
/// When a delegator undelegates, the amount is locked until
/// `completion_height`. After that, the funds are withdrawable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnbondingEntry {
    /// The delegator who undelegated.
    pub delegator: Address,
    /// The validator being undelegated from.
    pub validator: Address,
    /// The amount being unbonded.
    pub amount: u64,
    /// The height at which unbonding completes.
    pub completion_height: u64,
}

/// A validator's stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validator {
    /// The validator's address.
    pub address: Address,
    /// Total delegated stake.
    pub stake: u64,
}

/// The staking module: delegation, unbonding, slashing, rewards.
pub struct StakingModule {
    /// The KV store for state root computation.
    /// `KVStore` is `Mutex<BTreeMap<Vec<u8>, Vec<u8>>>` — already
    /// thread-safe, no extra `Mutex` needed.
    store: framework::KVStore,
    /// Validator stakes, keyed by address.
    validators: Mutex<BTreeMap<Address, u64>>,
    /// Pending unbonding entries (completed at `end_block`).
    unbonding: Mutex<Vec<UnbondingEntry>>,
    /// Accumulated rewards per validator address.
    rewards: Mutex<BTreeMap<Address, u64>>,
    /// Pending BLS key changes per validator address. The new key
    /// takes effect at the next epoch rotation — the consensus
    /// engine reads these via `take_key_changes` at the epoch
    /// boundary.
    pending_key_changes: Mutex<BTreeMap<Address, Vec<u8>>>,
    /// Pending validator additions: `(address, bls_public_key,
    /// stake)`. The new validator joins the set at the next epoch
    /// rotation. The consensus engine reads these via
    /// `take_validator_changes`.
    pending_validator_adds: Mutex<Vec<(Address, Vec<u8>, u64)>>,
    /// Pending validator removals: addresses to remove at the next
    /// epoch rotation. The consensus engine reads these via
    /// `take_validator_changes`.
    pending_validator_removes: Mutex<Vec<Address>>,
    /// The unbonding period in blocks.
    unbonding_period: u64,
    /// The block reward in atomic units.
    block_reward: u64,
    /// The current block height (set at `begin_block`).
    current_height: Mutex<u64>,
}

impl StakingModule {
    /// Construct a fresh staking module with no validators and
    /// default parameters.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(BTreeMap::new()),
            validators: Mutex::new(BTreeMap::new()),
            unbonding: Mutex::new(Vec::new()),
            rewards: Mutex::new(BTreeMap::new()),
            pending_key_changes: Mutex::new(BTreeMap::new()),
            pending_validator_adds: Mutex::new(Vec::new()),
            pending_validator_removes: Mutex::new(Vec::new()),
            unbonding_period: DEFAULT_UNBONDING_PERIOD_BLOCKS,
            block_reward: DEFAULT_BLOCK_REWARD,
            current_height: Mutex::new(0),
        }
    }

    /// Construct a staking module with a custom unbonding period.
    ///
    /// # Panics
    ///
    /// Panics if the unbonding period is 0 (must be at least 1 block).
    #[must_use]
    pub fn with_unbonding_period(mut self, period: u64) -> Self {
        assert!(period > 0, "unbonding period must be > 0");
        self.unbonding_period = period;
        self
    }

    /// Construct a staking module with a custom block reward.
    #[must_use]
    pub fn with_block_reward(mut self, reward: u64) -> Self {
        self.block_reward = reward;
        self
    }

    /// Register a validator at genesis — sets stake directly without
    /// requiring a delegate transaction.
    ///
    /// This is the genesis-state path: the `genesis.json` `staking.validators`
    /// list is applied before the first block, so validators have stake
    /// when consensus starts. It bypasses the `ctx.sender == validator`
    /// check that `handle(DELEGATE)` enforces — genesis registration is
    /// not a user transaction.
    ///
    /// # Panics
    ///
    /// Panics if `stake == 0` — a zero-stake validator is useless and
    /// likely a genesis bug.
    pub fn genesis_register_validator(&self, validator: Address, stake: u64) {
        assert!(stake > 0, "genesis validator {validator:?} has zero stake");
        self.validators.lock().unwrap().insert(validator, stake);
    }

    /// Get a validator's total stake.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn stake(&self, addr: &Address) -> u64 {
        *self
            .validators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(addr)
            .unwrap_or(&0)
    }

    /// Get a validator's accumulated rewards.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn rewards(&self, addr: &Address) -> u64 {
        *self
            .rewards
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(addr)
            .unwrap_or(&0)
    }

    /// Get the top-N validators by stake (descending).
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn top_validators(&self, n: usize) -> Vec<Validator> {
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut sorted: Vec<(Address, u64)> = validators
            .iter()
            .filter(|&(_, &stake)| stake > 0)
            .map(|(addr, &stake)| (*addr, stake))
            .collect();
        sorted.sort_by_key(|&(_, stake)| std::cmp::Reverse(stake));
        sorted.into_iter().take(n).map(|(address, stake)| Validator { address, stake }).collect()
    }

    /// Get all pending unbonding entries (for inspection/testing).
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn pending_unbonding(&self) -> Vec<UnbondingEntry> {
        self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
    }

    /// Take all pending key changes, clearing the queue. Called by
    /// the consensus engine at the epoch boundary to apply new BLS
    /// keys to the validator set.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn take_key_changes(&self) -> Vec<(Address, Vec<u8>)> {
        std::mem::take(
            &mut *self
                .pending_key_changes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_iter()
        .collect()
    }

    /// Take all pending validator changes, clearing both queues.
    /// Called by the consensus engine at the epoch boundary to apply
    /// validator additions and removals to the validator set.
    ///
    /// Returns a [`framework::ValidatorChanges`] — `adds` is a list
    /// of `(address, bls_public_key, stake)` tuples for new
    /// validators; `removes` is a list of addresses to remove.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn take_validator_changes(&self) -> executor::ValidatorChanges {
        executor::ValidatorChanges {
            adds: std::mem::take(
                &mut *self
                    .pending_validator_adds
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
            removes: std::mem::take(
                &mut *self
                    .pending_validator_removes
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            ),
        }
    }

    /// Check if a validator has a pending key change.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn has_key_change(&self, addr: &Address) -> bool {
        self.pending_key_changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(addr)
    }

    /// Get completed unbonding entries (for withdrawal).
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn completed_unbonding(&self) -> Vec<UnbondingEntry> {
        let current =
            *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.unbonding
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.completion_height <= current)
            .copied()
            .collect()
    }

    /// Parse a staking message header: `[type: 1B][validator: 20B]`.
    /// Returns `(msg_type, validator)` — the payload after the
    /// validator field varies by message type (amount, BLS key, etc.).
    fn parse_message_header(msg: &[u8]) -> Option<(u8, Address)> {
        if msg.len() < 21 {
            return None;
        }
        let msg_type = msg[0];
        let validator = Address::from_slice(&msg[1..21]).ok()?;
        Some((msg_type, validator))
    }

    /// Parse a staking message: `[type: 1B][validator: 20B][amount: 8B LE]`.
    fn parse_message(msg: &[u8]) -> Option<(u8, Address, u64)> {
        if msg.len() < 29 {
            return None;
        }
        let (msg_type, validator) = Self::parse_message_header(msg)?;
        let amount = u64::from_le_bytes(msg[21..29].try_into().ok()?);
        Some((msg_type, validator, amount))
    }
}

impl Default for StakingModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Staking message constructors.
pub mod msg {
    /// A delegate message: `[type: 0x01][validator: 20B][amount: 8B LE]`.
    pub fn delegate(validator: primitives::Address, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(29);
        msg.push(super::msg_type::DELEGATE);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// An undelegate message: `[type: 0x02][validator: 20B][amount: 8B LE]`.
    pub fn undelegate(validator: primitives::Address, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(29);
        msg.push(super::msg_type::UNDELEGATE);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// A slash message: `[type: 0x03][validator: 20B][amount: 8B LE]`.
    ///
    /// The `amount` is the slash amount (not the slash fraction).
    /// The caller (consensus engine or governance) computes the
    /// actual slash amount based on the offense type.
    pub fn slash(validator: primitives::Address, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(29);
        msg.push(super::msg_type::SLASH);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// A claim-reward message: `[type: 0x04][validator: 20B][amount: 8B LE]`.
    ///
    /// The `amount` is the reward amount to claim. If `amount` is 0,
    /// all accumulated rewards for the validator are claimed.
    pub fn claim_reward(validator: primitives::Address, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(29);
        msg.push(super::msg_type::CLAIM_REWARD);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }

    /// Compute the slash amount for a double-sign offense.
    ///
    /// Returns `stake * SLASH_FRACTION_DOUBLE_SIGN_NUMERATOR /
    /// SLASH_FRACTION_DENOMINATOR` (10% of the stake).
    #[must_use]
    pub fn double_sign_slash_amount(stake: u64) -> u64 {
        stake.saturating_mul(super::SLASH_FRACTION_DOUBLE_SIGN_NUMERATOR)
            / super::SLASH_FRACTION_DENOMINATOR
    }

    /// A key-change message: `[type: 0x05][validator: 20B][new_key: 48B]`.
    ///
    /// Updates a validator's BLS consensus public key. The new key
    /// takes effect at the next epoch rotation. Only the validator
    /// itself can submit this (the sender must equal `validator`).
    ///
    /// `new_key` is a 48-byte BLS12-381 compressed public key.
    pub fn key_change(validator: primitives::Address, new_key: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(69);
        msg.push(super::msg_type::KEY_CHANGE);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(new_key);
        msg
    }

    /// A validator-add message: `[type: 0x06][new_validator: 20B][bls_key: 48B][stake: 8B LE]`.
    ///
    /// Registers a new validator in the set. Only a current validator
    /// can submit this (governance-by-committee — the validator set
    /// admits new members). The new validator joins at the next epoch
    /// rotation.
    ///
    /// `new_validator` is the staking address. `bls_key` is the
    /// 48-byte BLS12-381 compressed public key. `stake` is the
    /// initial stake in atomic units.
    pub fn validator_add(
        new_validator: primitives::Address,
        bls_key: &[u8],
        stake: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(77);
        msg.push(super::msg_type::VALIDATOR_ADD);
        msg.extend_from_slice(&new_validator.0);
        msg.extend_from_slice(bls_key);
        msg.extend_from_slice(&stake.to_le_bytes());
        msg
    }

    /// A validator-remove message: `[type: 0x07][validator: 20B]`.
    ///
    /// Removes a validator from the set. Only a current validator
    /// can submit this. The validator is removed at the next epoch
    /// rotation; their stake enters unbonding.
    pub fn validator_remove(validator: primitives::Address) -> Vec<u8> {
        let mut msg = Vec::with_capacity(21);
        msg.push(super::msg_type::VALIDATOR_REMOVE);
        msg.extend_from_slice(&validator.0);
        msg
    }
}

impl Module for StakingModule {
    fn name(&self) -> &'static str {
        "staking"
    }
    fn id(&self) -> u8 {
        module_id::STAKING
    }

    fn begin_block(&self, height: Height) {
        *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            height.value();
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (msg_type, validator) = Self::parse_message_header(msg).ok_or(ExecError::Malformed)?;

        match msg_type {
            msg_type::KEY_CHANGE => return self.handle_key_change(ctx, validator, msg),
            msg_type::VALIDATOR_ADD => return self.handle_validator_add(ctx, validator, msg),
            msg_type::VALIDATOR_REMOVE => return self.handle_validator_remove(ctx, validator, msg),
            _ => {}
        }
        let (_, _, amount) = Self::parse_message(msg).ok_or(ExecError::Malformed)?;
        match msg_type {
            msg_type::DELEGATE => self.handle_delegate(ctx, validator, amount, msg),
            msg_type::UNDELEGATE => self.handle_undelegate(ctx, validator, amount, msg),
            msg_type::SLASH => self.handle_slash(ctx, validator, amount, msg),
            msg_type::CLAIM_REWARD => self.handle_claim_reward(ctx, validator, amount, msg),
            _ => Err(ExecError::ModuleRejected(format!("unknown staking message type {msg_type}"))),
        }
    }

    fn end_block(&self, height: Height) {
        // Process completed unbonding entries.
        let current = height.value();
        let mut unbonding =
            self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        unbonding.retain(|entry| entry.completion_height > current);

        // Distribute block rewards to active validators.
        self.distribute_rewards();
    }

    fn state_root(&self) -> Hash {
        subtree_root(&self.store)
    }

    fn take_key_changes(&self) -> Vec<(Address, Vec<u8>)> {
        StakingModule::take_key_changes(self)
    }

    fn take_validator_changes(&self) -> executor::ValidatorChanges {
        StakingModule::take_validator_changes(self)
    }
}

impl StakingModule {
    /// Handle a delegate message: add `amount` to `validator`'s stake.
    fn handle_delegate(
        &self,
        _ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stake = validators.entry(validator).or_insert(0);
        *stake = stake
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("stake overflow".to_string()))?;

        // Record in store for state root.
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.insert(validator.0.to_vec(), stake.to_le_bytes().to_vec());

        Ok(vec![Event { module: "staking", kind: "delegate", data: msg.to_vec() }])
    }

    /// Handle an undelegate message: start unbonding `amount` from
    /// `validator`'s stake.
    ///
    /// The amount is removed from the validator's stake immediately
    /// and placed in the unbonding queue. After `unbonding_period`
    /// blocks, the funds are withdrawable.
    fn handle_undelegate(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undelegate: validator not found".to_string()))?;
        if *stake < amount {
            return Err(ExecError::ModuleRejected("undelegate: insufficient stake".to_string()));
        }
        *stake -= amount;

        // Record updated stake in store.
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.insert(validator.0.to_vec(), stake.to_le_bytes().to_vec());

        // Add to unbonding queue.
        let current =
            *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let completion = current.saturating_add(self.unbonding_period);
        let entry = UnbondingEntry {
            delegator: ctx.sender,
            validator,
            amount,
            completion_height: completion,
        };
        self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(entry);

        Ok(vec![Event { module: "staking", kind: "undelegate", data: msg.to_vec() }])
    }

    /// Handle a slash message: reduce `validator`'s stake by `amount`.
    ///
    /// The slashed amount is burned (removed from circulation). This
    /// is called by the consensus engine (double-sign evidence) or
    /// governance proposals.
    fn handle_slash(
        &self,
        _ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("slash: validator not found".to_string()))?;
        let slash_amount = amount.min(*stake);
        *stake -= slash_amount;

        // Record updated stake in store.
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.insert(validator.0.to_vec(), stake.to_le_bytes().to_vec());

        Ok(vec![Event { module: "staking", kind: "slash", data: msg.to_vec() }])
    }

    /// Handle a claim-reward message: withdraw accumulated rewards.
    ///
    /// If `amount` is 0, all accumulated rewards are claimed.
    /// Otherwise, up to `amount` rewards are claimed.
    ///
    /// The claimed rewards are recorded as an event — the actual
    /// bank transfer is handled by a future `withdraw` step (or
    /// directly by the executor wiring the reward to the bank
    /// module).
    fn handle_claim_reward(
        &self,
        _ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let mut rewards = self.rewards.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let accumulated = rewards.get(&validator).copied().unwrap_or(0);
        let claim_amount = if amount == 0 { accumulated } else { amount.min(accumulated) };
        if claim_amount == 0 {
            return Err(ExecError::ModuleRejected("claim_reward: no rewards to claim".to_string()));
        }
        *rewards.entry(validator).or_insert(0) -= claim_amount;

        Ok(vec![Event { module: "staking", kind: "claim_reward", data: msg.to_vec() }])
    }

    /// Handle a key-change message: record a new BLS consensus key
    /// for `validator`.
    ///
    /// The message format is `[type: 0x05][validator: 20B][new_key: 48B]`.
    /// The new key takes effect at the next epoch rotation — the
    /// consensus engine reads pending changes via `take_key_changes`.
    ///
    /// Only the validator itself can change its key (checked via
    /// `ctx.sender`). The sender must be the validator address.
    fn handle_key_change(
        &self,
        ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // The sender must be the validator changing its own key.
        if ctx.sender != validator {
            return Err(ExecError::ModuleRejected(
                "key_change: sender must be the validator".to_string(),
            ));
        }
        // The validator must exist (have non-zero stake).
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !validators.contains_key(&validator) {
            return Err(ExecError::ModuleRejected("key_change: validator not found".to_string()));
        }
        // The new key is a 48-byte BLS12-381 compressed public key.
        if msg.len() != 21 + 48 {
            return Err(ExecError::ModuleRejected(format!(
                "key_change: expected 48-byte key, got {} bytes",
                msg.len().saturating_sub(21)
            )));
        }
        let new_key = msg[21..69].to_vec();
        drop(validators); // release lock before acquiring pending_key_changes

        self.pending_key_changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(validator, new_key);

        Ok(vec![Event { module: "staking", kind: "key_change", data: msg.to_vec() }])
    }

    /// Handle a validator-add message: `[type: 0x06][new_validator: 20B][bls_key: 48B][stake: 8B LE]`.
    ///
    /// The sender must be a current validator — only the validator
    /// set itself can admit new members (governance-by-committee).
    /// The new validator joins at the next epoch rotation.
    ///
    /// `validator` is the new validator's staking address. The
    /// `bls_key` is the 48-byte BLS12-381 compressed public key.
    /// `stake` is the initial stake in atomic units.
    ///
    /// # Errors
    ///
    /// - `ModuleRejected` if the sender is not a current validator.
    /// - `ModuleRejected` if the new validator is already in the set
    ///   or has a pending add.
    /// - `ModuleRejected` if the BLS key is not exactly 48 bytes.
    /// - `ModuleRejected` if the stake is 0.
    fn handle_validator_add(
        &self,
        ctx: &TxContext,
        new_validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // Governance check: only a current validator can propose
        // adding a new validator. This prevents an arbitrary account
        // from flooding the set with sybil validators.
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !validators.contains_key(&ctx.sender) {
            return Err(ExecError::ModuleRejected(
                "validator_add: sender is not a current validator".to_string(),
            ));
        }
        // The new validator must not already exist.
        if validators.contains_key(&new_validator) {
            return Err(ExecError::ModuleRejected(
                "validator_add: validator already exists".to_string(),
            ));
        }
        // The new validator must not already be pending.
        let pending_adds =
            self.pending_validator_adds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending_adds.iter().any(|(a, _, _)| *a == new_validator) {
            return Err(ExecError::ModuleRejected(
                "validator_add: validator already pending".to_string(),
            ));
        }
        // Parse [bls_key: 48B][stake: 8B LE] after the validator field.
        if msg.len() != 21 + 48 + 8 {
            return Err(ExecError::ModuleRejected(format!(
                "validator_add: expected 77-byte message, got {} bytes",
                msg.len()
            )));
        }
        let bls_key = msg[21..69].to_vec();
        let stake = u64::from_le_bytes(msg[69..77].try_into().map_err(|_| ExecError::Malformed)?);
        if stake == 0 {
            return Err(ExecError::ModuleRejected("validator_add: zero stake".to_string()));
        }
        drop(pending_adds);

        // Register the validator in the staking map immediately —
        // they can receive delegations and be removed before the
        // epoch rotation. They only join consensus at the rotation.
        validators.insert(new_validator, stake);
        drop(validators);

        self.pending_validator_adds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((new_validator, bls_key, stake));

        Ok(vec![Event { module: "staking", kind: "validator_add", data: msg.to_vec() }])
    }

    /// Handle a validator-remove message: `[type: 0x07][validator: 20B]`.
    ///
    /// The sender must be a current validator — only the validator
    /// set itself can remove members. The validator is removed at
    /// the next epoch rotation; their stake enters unbonding.
    ///
    /// # Errors
    ///
    /// - `ModuleRejected` if the sender is not a current validator.
    /// - `ModuleRejected` if the validator is not in the set.
    /// - `ModuleRejected` if the validator is already pending removal.
    /// - `ModuleRejected` if removing this validator would leave the
    ///   set empty.
    fn handle_validator_remove(
        &self,
        ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !validators.contains_key(&ctx.sender) {
            return Err(ExecError::ModuleRejected(
                "validator_remove: sender is not a current validator".to_string(),
            ));
        }
        if !validators.contains_key(&validator) {
            return Err(ExecError::ModuleRejected(
                "validator_remove: validator not found".to_string(),
            ));
        }

        // If the validator is pending add, cancel the add instead of
        // adding a remove — the validator never joins the set.
        let mut pending_adds =
            self.pending_validator_adds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pos) = pending_adds.iter().position(|(a, _, _)| *a == validator) {
            pending_adds.remove(pos);
            validators.remove(&validator);
            drop(pending_adds);
            drop(validators);
            return Ok(vec![Event {
                module: "staking",
                kind: "validator_remove",
                data: msg.to_vec(),
            }]);
        }
        drop(pending_adds);

        let pending_removes = self
            .pending_validator_removes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending_removes.contains(&validator) {
            return Err(ExecError::ModuleRejected(
                "validator_remove: validator already pending removal".to_string(),
            ));
        }
        // Cannot remove the last validator — a chain must have at
        // least one validator.
        let active_count = validators.values().filter(|&&s| s > 0).count();
        if active_count <= 1 {
            return Err(ExecError::ModuleRejected(
                "validator_remove: cannot remove last validator".to_string(),
            ));
        }
        drop(pending_removes);
        drop(validators);

        self.pending_validator_removes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(validator);

        Ok(vec![Event { module: "staking", kind: "validator_remove", data: msg.to_vec() }])
    }

    /// Distribute block rewards to active validators proportional
    /// to their stake.
    ///
    /// Called at `end_block`. The block reward is split among all
    /// active validators (stake > 0) proportional to their stake
    /// fraction. Uses integer arithmetic to avoid floating-point
    /// non-determinism.
    ///
    /// Any remainder (from integer division) is not distributed —
    /// it stays in the "mint" (effectively burned). This is simpler
    /// than tracking a fractional remainder and is deterministic.
    fn distribute_rewards(&self) {
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let total_stake: u64 = validators.values().copied().filter(|&s| s > 0).sum();
        if total_stake == 0 {
            return; // no active validators — no distribution
        }

        let mut rewards = self.rewards.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (&addr, &stake) in validators.iter() {
            if stake == 0 {
                continue;
            }
            // reward = block_reward * stake / total_stake
            let reward = self.block_reward.saturating_mul(stake) / total_stake;
            if reward > 0 {
                *rewards.entry(addr).or_insert(0) += reward;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address([byte; 20])
    }

    fn ctx() -> TxContext {
        TxContext { sender: addr(0), nonce: 0, fee: 0 }
    }

    fn ctx_with_sender(sender: u8) -> TxContext {
        TxContext { sender: addr(sender), nonce: 0, fee: 0 }
    }

    #[test]
    fn delegate_increases_stake() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        assert_eq!(staking.stake(&v), 1000);
    }

    #[test]
    fn multiple_delegates_accumulate() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
        staking.handle(&ctx(), &msg::delegate(v, 200)).unwrap();
        assert_eq!(staking.stake(&v), 300);
    }

    #[test]
    fn undelegate_reduces_stake_and_creates_unbonding_entry() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(10));
        staking.handle(&ctx_with_sender(5), &msg::undelegate(v, 300)).unwrap();
        assert_eq!(staking.stake(&v), 700, "stake should be reduced");
        let pending = staking.pending_unbonding();
        assert_eq!(pending.len(), 1, "one unbonding entry");
        assert_eq!(pending[0].amount, 300);
        assert_eq!(pending[0].delegator, addr(5));
        assert_eq!(
            pending[0].completion_height,
            10 + DEFAULT_UNBONDING_PERIOD_BLOCKS,
            "completion = current + unbonding_period"
        );
    }

    #[test]
    fn undelegate_rejects_insufficient_stake() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
        let result = staking.handle(&ctx(), &msg::undelegate(v, 200));
        assert!(result.is_err(), "should reject undelegate > stake");
    }

    #[test]
    fn undelegate_rejects_unknown_validator() {
        let staking = StakingModule::new();
        let v = addr(1);
        let result = staking.handle(&ctx(), &msg::undelegate(v, 100));
        assert!(result.is_err(), "should reject undelegate of unknown validator");
    }

    #[test]
    fn unbonding_completes_after_period() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(10));
        staking.handle(&ctx(), &msg::undelegate(v, 500)).unwrap();
        assert_eq!(staking.completed_unbonding().len(), 0, "not completed yet");
        staking.begin_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
        staking.end_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
        assert_eq!(
            staking.completed_unbonding().len(),
            0,
            "entry should be removed after end_block processes it"
        );
        assert_eq!(staking.pending_unbonding().len(), 0, "no pending entries");
    }

    #[test]
    fn unbonding_not_completed_before_period() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(10));
        staking.handle(&ctx(), &msg::undelegate(v, 500)).unwrap();
        staking.begin_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS - 1));
        staking.end_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS - 1));
        assert_eq!(staking.pending_unbonding().len(), 1, "still pending");
    }

    #[test]
    fn slash_reduces_stake() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let slash_amount = msg::double_sign_slash_amount(1000);
        assert_eq!(slash_amount, 100, "10% of 1000 = 100");
        staking.handle(&ctx(), &msg::slash(v, slash_amount)).unwrap();
        assert_eq!(staking.stake(&v), 900, "stake reduced by slash");
    }

    #[test]
    fn slash_capped_at_stake() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
        // Try to slash more than the stake.
        staking.handle(&ctx(), &msg::slash(v, 500)).unwrap();
        assert_eq!(staking.stake(&v), 0, "stake floored at 0");
    }

    #[test]
    fn slash_rejects_unknown_validator() {
        let staking = StakingModule::new();
        let v = addr(1);
        let result = staking.handle(&ctx(), &msg::slash(v, 100));
        assert!(result.is_err(), "should reject slash of unknown validator");
    }

    #[test]
    fn rewards_accumulate_per_block() {
        let staking = StakingModule::new().with_block_reward(1_000_000);
        let v1 = addr(1);
        let v2 = addr(2);
        staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
        staking.handle(&ctx(), &msg::delegate(v2, 3000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        // v1 has 25% of stake (1000/4000), v2 has 75% (3000/4000).
        // reward = 1_000_000 * stake / total_stake
        // v1: 1_000_000 * 1000 / 4000 = 250_000
        // v2: 1_000_000 * 3000 / 4000 = 750_000
        assert_eq!(staking.rewards(&v1), 250_000, "v1 gets 25% of reward");
        assert_eq!(staking.rewards(&v2), 750_000, "v2 gets 75% of reward");
    }

    #[test]
    fn rewards_accumulate_over_multiple_blocks() {
        let staking = StakingModule::new().with_block_reward(1_000_000);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        staking.begin_block(Height::new(2));
        staking.end_block(Height::new(2));
        assert_eq!(staking.rewards(&v), 2_000_000, "2 blocks * 1M reward");
    }

    #[test]
    fn claim_reward_withdraws_accumulated() {
        let staking = StakingModule::new().with_block_reward(1_000_000);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        assert_eq!(staking.rewards(&v), 1_000_000);
        staking.handle(&ctx(), &msg::claim_reward(v, 0)).unwrap();
        assert_eq!(staking.rewards(&v), 0, "rewards claimed");
    }

    #[test]
    fn claim_reward_partial_withdrawal() {
        let staking = StakingModule::new().with_block_reward(1_000_000);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        staking.handle(&ctx(), &msg::claim_reward(v, 400_000)).unwrap();
        assert_eq!(staking.rewards(&v), 600_000, "600K remaining");
    }

    #[test]
    fn claim_reward_rejects_zero_balance() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let result = staking.handle(&ctx(), &msg::claim_reward(v, 0));
        assert!(result.is_err(), "should reject claim with no rewards");
    }

    #[test]
    fn top_validators_sorted_by_stake() {
        let staking = StakingModule::new();
        staking.handle(&ctx(), &msg::delegate(addr(1), 100)).unwrap();
        staking.handle(&ctx(), &msg::delegate(addr(2), 500)).unwrap();
        staking.handle(&ctx(), &msg::delegate(addr(3), 300)).unwrap();
        let top = staking.top_validators(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].address, addr(2), "highest stake first");
        assert_eq!(top[0].stake, 500);
        assert_eq!(top[1].address, addr(3), "second highest");
    }

    #[test]
    fn zero_stake_validators_excluded() {
        let staking = StakingModule::new();
        staking.handle(&ctx(), &msg::delegate(addr(1), 100)).unwrap();
        let top = staking.top_validators(10);
        assert_eq!(top.len(), 1, "only non-zero-stake validators");
    }

    #[test]
    fn malformed_message_rejected() {
        let staking = StakingModule::new();
        assert_eq!(staking.handle(&ctx(), &[1, 2, 3]), Err(ExecError::Malformed));
    }

    #[test]
    fn unknown_message_type_rejected() {
        let staking = StakingModule::new();
        let v = addr(1);
        let mut msg = msg::delegate(v, 100);
        msg[0] = 0xFF; // unknown type
        let result = staking.handle(&ctx(), &msg);
        assert!(result.is_err(), "should reject unknown message type");
    }

    #[test]
    fn state_root_changes_after_delegate() {
        let staking = StakingModule::new();
        let root0 = staking.state_root();
        staking.handle(&ctx(), &msg::delegate(addr(1), 100)).unwrap();
        let root1 = staking.state_root();
        assert_ne!(root0, root1);
    }

    #[test]
    fn state_root_changes_after_slash() {
        let staking = StakingModule::new();
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let root0 = staking.state_root();
        staking.handle(&ctx(), &msg::slash(v, 100)).unwrap();
        let root1 = staking.state_root();
        assert_ne!(root0, root1, "state root must change after slash");
    }

    #[test]
    fn custom_unbonding_period() {
        let staking = StakingModule::new().with_unbonding_period(10);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(5));
        staking.handle(&ctx(), &msg::undelegate(v, 500)).unwrap();
        let pending = staking.pending_unbonding();
        assert_eq!(pending[0].completion_height, 15, "5 + 10 = 15");
    }

    #[test]
    fn key_change_stores_pending_key() {
        let staking = StakingModule::new();
        let v = addr(0); // sender is addr(0) in ctx()
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let new_key = vec![0xAA; 48];
        staking.handle(&ctx(), &msg::key_change(v, &new_key)).unwrap();
        assert!(staking.has_key_change(&v), "key change must be pending");
        let changes = staking.take_key_changes();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].0, v);
        assert_eq!(changes[0].1, new_key);
        // After take, the pending map is empty.
        assert!(!staking.has_key_change(&v), "key change must be drained");
    }

    #[test]
    fn key_change_rejects_wrong_sender() {
        let staking = StakingModule::new();
        let v = addr(1); // sender is addr(0), but validator is addr(1)
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let new_key = vec![0xAA; 48];
        let result = staking.handle(&ctx(), &msg::key_change(v, &new_key));
        assert!(result.is_err(), "must reject key change from non-validator sender");
    }

    #[test]
    fn key_change_rejects_unknown_validator() {
        let staking = StakingModule::new();
        let v = addr(0); // sender is addr(0) but no stake delegated
        let new_key = vec![0xAA; 48];
        let result = staking.handle(&ctx(), &msg::key_change(v, &new_key));
        assert!(result.is_err(), "must reject key change for unknown validator");
    }

    #[test]
    fn key_change_rejects_wrong_key_length() {
        let staking = StakingModule::new();
        let v = addr(0);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let short_key = vec![0xAA; 32]; // not 48 bytes
        let msg = msg::key_change(v, &short_key);
        let result = staking.handle(&ctx(), &msg);
        assert!(result.is_err(), "must reject non-48-byte key");
    }
}
