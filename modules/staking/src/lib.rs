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

/// The bonded-pool module account.
///
/// Delegated funds are held at this address in the bank module: a
/// `delegate` moves `delegator → BONDED_POOL`, and completed unbonding
/// moves `BONDED_POOL → delegator` back. The pool balance therefore
/// always equals total live delegations + in-flight unbonding — the
/// same accounting identity Cosmos keeps between `x/bank` and the
/// bonded-tokens pool.
///
/// The address is a fixed 20-byte tag — no private key exists, so
/// only the staking module's own calls can move funds out.
pub const BONDED_POOL: Address = Address(*b"oxide/staking/pool!!");

/// The staking module: delegation, unbonding, slashing, rewards.
pub struct StakingModule {
    /// The KV store for state root computation.
    /// `KVStore` is `Mutex<BTreeMap<Vec<u8>, Vec<u8>>>` — already
    /// thread-safe, no extra `Mutex` needed.
    store: framework::KVStore,
    /// Validator stakes, keyed by address.
    validators: Mutex<BTreeMap<Address, u64>>,
    /// Live delegations: `(delegator, validator) → bonded amount`.
    ///
    /// This is the record that makes delegation real: `delegate`
    /// debits the delegator's bank balance into [`BONDED_POOL`] and
    /// credits this map; `undelegate` requires the delegator's own
    /// delegation to cover the amount. Without it, `delegate` was
    /// unbacked stake inflation (any tx could grow any validator's
    /// stake for free) and `undelegate` let any account unbond any
    /// validator's stake.
    delegations: Mutex<BTreeMap<(Address, Address), u64>>,
    /// The bank module handle for bond/unbond settlement. `None` in
    /// bare unit tests only — `delegate`/`unbond_immediate` fail
    /// closed when unset (an unbacked delegation is a consensus
    /// accounting hole; see `docs/evm-parity-gap-analysis.md` for why
    /// precompile→module paths must reuse the native invariants).
    bank: Mutex<Option<std::sync::Arc<bank::BankModule>>>,
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
            delegations: Mutex::new(BTreeMap::new()),
            bank: Mutex::new(None),
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

    /// Register a validator with zero stake — the "can receive
    /// delegations" state used by tests and devnet assembly.
    ///
    /// A registered-but-empty validator participates in no weight
    /// accounting until a real `delegate` bonds funds. This exists
    /// because [`handle_delegate`] requires the validator to be
    /// registered — delegation can no longer fabricate consensus
    /// stake for unknown addresses.
    ///
    /// `#[doc(hidden)]` — assembly/test seam, not a message path.
    ///
    /// # Panics
    ///
    /// Panics if a mutex is poisoned.
    #[doc(hidden)]
    pub fn register_validator(&self, validator: Address) {
        self.validators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(validator)
            .or_insert(0);
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

    /// Undo a delegation immediately — the EVM-precompile revert path.
    ///
    /// [`handle_delegate`](Self::handle_delegate) bonds funds via the
    /// normal message path. When the enclosing EVM frame later reverts,
    /// the EVM journal calls this to restore the exact pre-call state:
    /// delegation and stake reduced, funds returned pool → delegator
    /// without entering the unbonding queue.
    ///
    /// `#[doc(hidden)]` — only the EVM module's native-side-effect
    /// journal may call this; it is not a user-facing message path.
    ///
    /// # Panics
    ///
    /// Panics if a mutex is poisoned.
    #[doc(hidden)]
    pub fn unbond_immediate(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), ExecError> {
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let delegation = delegations
            .get_mut(&(delegator, validator))
            .ok_or(ExecError::ModuleRejected("undo: delegation missing".to_string()))?;
        if *delegation < amount {
            return Err(ExecError::ModuleRejected("undo: delegation underflow".to_string()));
        }
        *delegation -= amount;
        let new_delegation = *delegation;
        if new_delegation == 0 {
            delegations.remove(&(delegator, validator));
        }
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undo: validator missing".to_string()))?;
        *stake -= amount;
        self.store_delegation_state(validator, delegator, *stake, new_delegation);
        drop(delegations);
        drop(validators);
        // Refund the bond — same funds the delegate moved in.
        self.require_bank()?.transfer(&BONDED_POOL, &delegator, amount)
    }

    /// Undo an undelegation — the EVM-precompile revert path.
    ///
    /// Restores the delegation and stake and removes the unbonding
    /// entry the failed frame created. No bank movement: undelegate
    /// never moved funds (the payout happens at completion).
    ///
    /// `#[doc(hidden)]` — only the EVM module's native-side-effect
    /// journal may call this.
    ///
    /// # Panics
    ///
    /// Panics if a mutex is poisoned.
    #[doc(hidden)]
    pub fn cancel_unbond(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), ExecError> {
        // Remove the most recent matching unbonding entry (the one the
        // reverted frame appended — same (delegator, validator,
        // amount) triple).
        {
            let mut unbonding =
                self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let pos = unbonding
                .iter()
                .rposition(|e| {
                    e.delegator == delegator && e.validator == validator && e.amount == amount
                })
                .ok_or(ExecError::ModuleRejected("undo: unbonding entry missing".to_string()))?;
            unbonding.remove(pos);
        }
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undo: validator missing".to_string()))?;
        *stake = stake
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("undo: stake overflow".to_string()))?;
        let delegation = delegations.entry((delegator, validator)).or_insert(0);
        *delegation = delegation
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("undo: delegation overflow".to_string()))?;
        self.store_delegation_state(validator, delegator, *stake, *delegation);
        Ok(())
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
        // Process completed unbonding entries: pay each delegator out
        // of the bonded pool. Before this, unbonded funds vanished
        // (entries were dropped with no payout — the bonded pool kept
        // tokens nobody could reclaim).
        let current = height.value();
        let bank = self.bank.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let mut unbonding =
            self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        unbonding.retain(|entry| {
            if entry.completion_height > current {
                return true;
            }
            if let Some(bank) = &bank {
                // Pool → delegator. The pool always holds the funds
                // (delegations + in-flight unbonding sum to the pool
                // balance), so this cannot fail; if it does, keep the
                // entry so the delegator can still be paid later.
                if bank.transfer(&BONDED_POOL, &entry.delegator, entry.amount).is_err() {
                    return true;
                }
            }
            false
        });
        drop(unbonding);

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
    /// Wire the bank module used for bond/unbond settlement.
    ///
    /// Must be called at assembly (before any block executes). Once
    /// set, `delegate` debits the delegator into [`BONDED_POOL`] and
    /// completed unbonding credits the delegator back — the precompile
    /// path (`0x0C01`) goes through the same `handle` entry point, so
    /// EVM callers get identical accounting.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn set_bank(&self, bank: std::sync::Arc<bank::BankModule>) {
        *self.bank.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bank);
    }

    /// The delegator's bonded amount with a validator.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn delegation(&self, delegator: &Address, validator: &Address) -> u64 {
        self.delegations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(*delegator, *validator))
            .copied()
            .unwrap_or(0)
    }

    /// Record a stake + delegation mutation in the KV store so
    /// `state_root` covers it. Lock order: callers must already hold
    /// (or not need) `validators`/`delegations`; this only takes
    /// `store`.
    fn store_delegation_state(
        &self,
        validator: Address,
        delegator: Address,
        stake: u64,
        delegation: u64,
    ) {
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        store.insert(validator.0.to_vec(), stake.to_le_bytes().to_vec());
        let mut key = Vec::with_capacity(4 + 40);
        key.extend_from_slice(b"del/");
        key.extend_from_slice(&delegator.0);
        key.extend_from_slice(&validator.0);
        store.insert(key, delegation.to_le_bytes().to_vec());
    }

    /// Take the bank handle, failing closed when unwired.
    ///
    /// An unbacked delegation is an accounting hole — never run the
    /// debit path without a bank.
    fn require_bank(&self) -> Result<std::sync::Arc<bank::BankModule>, ExecError> {
        self.bank.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone().ok_or_else(
            || {
                ExecError::ModuleRejected(
                    "staking: bank module not wired (cannot settle delegation)".to_string(),
                )
            },
        )
    }

    /// Handle a delegate message: move `amount` from the sender's bank
    /// balance into the bonded pool and record the delegation.
    ///
    /// Invariants enforced (shared by the native and EVM-precompile
    /// paths — both call `handle`):
    /// - The validator must be registered (`genesis_register_validator`
    ///   or `VALIDATOR_ADD`); delegation to an unknown validator is
    ///   rejected rather than silently fabricating consensus stake.
    /// - The sender's bank balance must cover `amount` — the bank's
    ///   `transfer` enforces this, so the EVM precompile cannot inflate
    ///   stake for free.
    fn handle_delegate(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        self.delegate_for(ctx.sender, validator, amount)?;
        Ok(vec![Event { module: "staking", kind: "delegate", data: msg.to_vec() }])
    }

    /// Bond `amount` of `delegator`'s bank balance to `validator`.
    ///
    /// This is the shared core of [`handle_delegate`] and the EVM
    /// staking precompile: identical invariant enforcement regardless
    /// of which path the request arrives on. The delegator is debited
    /// through the bank into [`BONDED_POOL`]; the validator must be
    /// registered.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if the validator is unregistered,
    /// the bank is unwired, the transfer fails, or stake/delegation
    /// arithmetic overflows.
    pub fn delegate_for(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), ExecError> {
        let bank = self.require_bank()?;
        {
            let validators =
                self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !validators.contains_key(&validator) {
                return Err(ExecError::ModuleRejected(
                    "delegate: validator not registered".to_string(),
                ));
            }
        }
        // Debit first: if the transfer fails nothing is recorded.
        bank.transfer(&delegator, &BONDED_POOL, amount)?;

        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("delegate: validator vanished".to_string()))?;
        *stake = stake
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("stake overflow".to_string()))?;
        let delegation = delegations.entry((delegator, validator)).or_insert(0);
        *delegation = delegation
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("delegation overflow".to_string()))?;
        self.store_delegation_state(validator, delegator, *stake, *delegation);
        Ok(())
    }

    /// Reverse a [`delegate_for`] — used by the EVM journal when the
    /// calling frame reverts. Subtracts stake/delegation and refunds
    /// the delegator from the bonded pool.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if the delegation is smaller than
    /// `amount` (the undo would make accounting inconsistent — this
    /// indicates a journal bug, not user error).
    pub fn undo_delegate(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), ExecError> {
        let bank = self.require_bank()?;
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let delegation = delegations
            .get_mut(&(delegator, validator))
            .ok_or(ExecError::ModuleRejected("undo_delegate: no delegation".to_string()))?;
        if *delegation < amount {
            return Err(ExecError::ModuleRejected(
                "undo_delegate: delegation smaller than undo amount".to_string(),
            ));
        }
        *delegation -= amount;
        let new_delegation = *delegation;
        if new_delegation == 0 {
            delegations.remove(&(delegator, validator));
        }
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undo_delegate: validator gone".to_string()))?;
        *stake -= amount;
        self.store_delegation_state(validator, delegator, *stake, new_delegation);
        drop(delegations);
        drop(validators);
        // Refund after ledger state is consistent — a failed refund
        // leaves the pool over-funded rather than stake inflated.
        bank.transfer(&BONDED_POOL, &delegator, amount)
    }

    /// Start unbonding `amount` of `delegator`'s own delegation to
    /// `validator` — shared core of [`handle_undelegate`] and the EVM
    /// staking precompile.
    ///
    /// Stake drops immediately; the amount enters the unbonding queue
    /// and is paid from the bonded pool at `completion_height`.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if `delegator` has no delegation to
    /// `validator` or it is smaller than `amount`.
    pub fn undelegate_for(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<u64, ExecError> {
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let delegation = delegations.get_mut(&(delegator, validator)).ok_or_else(|| {
            ExecError::ModuleRejected(
                "undelegate: no delegation from this sender to this validator".to_string(),
            )
        })?;
        if *delegation < amount {
            return Err(ExecError::ModuleRejected(
                "undelegate: insufficient delegation".to_string(),
            ));
        }
        *delegation -= amount;
        let new_delegation = *delegation;
        if new_delegation == 0 {
            delegations.remove(&(delegator, validator));
        }
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undelegate: validator not found".to_string()))?;
        *stake -= amount; // delegation ≤ stake by construction
        self.store_delegation_state(validator, delegator, *stake, new_delegation);
        drop(delegations);
        drop(validators);

        let current =
            *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let completion = current.saturating_add(self.unbonding_period);
        self.unbonding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(UnbondingEntry { delegator, validator, amount, completion_height: completion });
        Ok(completion)
    }

    /// Reverse an [`undelegate_for`] — EVM journal rollback. Removes
    /// the most recent matching unbonding entry and restores the
    /// delegation and stake.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if no matching unbonding entry
    /// exists (journal bug).
    pub fn undo_undelegate(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
    ) -> Result<(), ExecError> {
        {
            let mut unbonding =
                self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            // Remove the *last* matching entry — journal undos run in
            // reverse order of mutation within the frame.
            let pos = unbonding
                .iter()
                .rposition(|e| {
                    e.delegator == delegator && e.validator == validator && e.amount == amount
                })
                .ok_or(ExecError::ModuleRejected(
                    "undo_undelegate: no matching unbonding entry".to_string(),
                ))?;
            unbonding.remove(pos);
        }
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undo_undelegate: validator gone".to_string()))?;
        *stake = stake
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("stake overflow on undo".to_string()))?;
        let delegation = delegations.entry((delegator, validator)).or_insert(0);
        *delegation = delegation
            .checked_add(amount)
            .ok_or(ExecError::ModuleRejected("delegation overflow on undo".to_string()))?;
        self.store_delegation_state(validator, delegator, *stake, *delegation);
        Ok(())
    }

    /// Handle an undelegate message: start unbonding `amount` of the
    /// **sender's own** delegation to `validator`.
    ///
    /// The delegation is removed immediately (stake drops now) and the
    /// amount enters the unbonding queue; at `completion_height` the
    /// bank pays it out of the bonded pool to the delegator.
    fn handle_undelegate(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        self.undelegate_for(ctx.sender, validator, amount)?;
        Ok(vec![Event { module: "staking", kind: "undelegate", data: msg.to_vec() }])
    }

    /// Handle a slash message: reduce `validator`'s stake by `amount`,
    /// burning the same proportion from every delegation to it.
    ///
    /// Slashing must hit the delegations, not just the aggregate —
    /// otherwise the bonded pool still owes the full pre-slash amount
    /// (a slash would effectively refund itself on unbond). Each
    /// delegation loses `floor(amount · delegation / stake)`; the
    /// rounding remainder is distributed 1 unit per delegation in
    /// deterministic `(delegator, validator)` order so all replicas
    /// slash identically.
    fn handle_slash(
        &self,
        _ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("slash: validator not found".to_string()))?;
        let slash_amount = amount.min(*stake);
        let stake_before = *stake;
        *stake -= slash_amount;
        let new_stake = *stake;

        let mut burned_from_pool = 0u64;
        if slash_amount > 0 && stake_before > 0 {
            // floor-share each delegation, then hand out the remainder
            // one unit at a time in BTreeMap (sorted) order.
            let mut affected: Vec<(Address, u64)> = delegations
                .range(..)
                .filter(|((_, v), _)| *v == validator)
                .map(|((d, _), a)| (*d, *a))
                .collect();
            let mut applied = 0u64;
            let mut dust_keys = Vec::with_capacity(affected.len());
            for (d, a) in &mut affected {
                let share = u128::from(slash_amount) * u128::from(*a) / u128::from(stake_before);
                let share = u64::try_from(share).unwrap_or(u64::MAX).min(*a);
                *a -= share;
                applied = applied.saturating_add(share);
                if *a > 0 {
                    dust_keys.push(*d);
                }
            }
            // Leftover from flooring: at most `affected.len()` units.
            let mut rem = slash_amount.saturating_sub(applied);
            for d in &dust_keys {
                if rem == 0 {
                    break;
                }
                if let Some((_, a)) = affected.iter_mut().find(|(dd, _)| dd == d) {
                    *a -= 1;
                    rem -= 1;
                    applied += 1;
                }
            }
            for (d, a) in affected {
                if a == 0 {
                    delegations.remove(&(d, validator));
                } else {
                    delegations.insert((d, validator), a);
                }
                self.store_delegation_state(validator, d, new_stake, a);
            }
            burned_from_pool = applied;
        }
        drop(delegations);
        drop(validators);

        // Burn only the amount removed from pool-backed delegations —
        // unattributed stake (genesis self-stake) was never in the
        // pool, so burning it would overdraw.
        if burned_from_pool > 0 {
            if let Some(bank) =
                self.bank.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
            {
                // Burn = send to the zero address (no key holder).
                let _ = bank.transfer(&BONDED_POOL, &Address::ZERO, burned_from_pool);
            }
        }

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
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // Only the validator may withdraw their own rewards — the
        // rewards ledger is a claimable balance, not a public pool.
        // (Matches the key_change authorization model.)
        if ctx.sender != validator {
            return Err(ExecError::ModuleRejected(
                "claim_reward: only the validator can claim its rewards".to_string(),
            ));
        }
        let bank = self.bank.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let bank = bank
            .ok_or_else(|| ExecError::ModuleRejected("claim_reward: bank not wired".to_string()))?;

        let claim_amount = {
            let mut rewards =
                self.rewards.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let accumulated = rewards.get(&validator).copied().unwrap_or(0);
            let claim_amount = if amount == 0 { accumulated } else { amount.min(accumulated) };
            if claim_amount == 0 {
                return Err(ExecError::ModuleRejected(
                    "claim_reward: no rewards to claim".to_string(),
                ));
            }
            *rewards.entry(validator).or_insert(0) -= claim_amount;
            claim_amount
        };

        // Rewards are new issuance authorized by the block-reward
        // schedule — mint lazily at claim time so the bonded pool is
        // never touched by reward payouts.
        bank.mint(&validator, claim_amount);

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

    /// A staking module with a bank wired and each address `0..=9`
    /// funded with 1M units, plus every listed validator registered
    /// (zero stake — delegations build it up).
    fn setup(validators: &[u8]) -> StakingModule {
        let staking = StakingModule::new();
        let bank = std::sync::Arc::new(bank::BankModule::new());
        for s in 0u8..=9 {
            bank.mint(&addr(s), 1_000_000);
        }
        staking.set_bank(bank);
        for v in validators {
            staking.register_validator(addr(*v));
        }
        staking
    }

    /// The bank behind a setup — needed by tests asserting pool
    /// movement. (`setup` keeps the handle internally; tests that
    /// need bank assertions build it directly.)
    fn setup_with_bank(validators: &[u8]) -> (StakingModule, std::sync::Arc<bank::BankModule>) {
        let staking = StakingModule::new();
        let bank = std::sync::Arc::new(bank::BankModule::new());
        for s in 0u8..=9 {
            bank.mint(&addr(s), 1_000_000);
        }
        staking.set_bank(bank.clone());
        for v in validators {
            staking.register_validator(addr(*v));
        }
        (staking, bank)
    }

    fn ctx() -> TxContext {
        TxContext { sender: addr(0), nonce: 0, fee: 0 }
    }

    fn ctx_with_sender(sender: u8) -> TxContext {
        TxContext { sender: addr(sender), nonce: 0, fee: 0 }
    }

    #[test]
    fn delegate_increases_stake() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        assert_eq!(staking.stake(&v), 1000);
    }

    #[test]
    fn multiple_delegates_accumulate() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
        staking.handle(&ctx(), &msg::delegate(v, 200)).unwrap();
        assert_eq!(staking.stake(&v), 300);
    }

    #[test]
    fn undelegate_reduces_stake_and_creates_unbonding_entry() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(10));
        staking.handle(&ctx(), &msg::undelegate(v, 300)).unwrap();
        assert_eq!(staking.stake(&v), 700, "stake should be reduced");
        let pending = staking.pending_unbonding();
        assert_eq!(pending.len(), 1, "one unbonding entry");
        assert_eq!(pending[0].amount, 300);
        assert_eq!(pending[0].delegator, addr(0));
        assert_eq!(
            pending[0].completion_height,
            10 + DEFAULT_UNBONDING_PERIOD_BLOCKS,
            "completion = current + unbonding_period"
        );
    }

    #[test]
    fn undelegate_rejects_insufficient_stake() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
        let result = staking.handle(&ctx(), &msg::undelegate(v, 200));
        assert!(result.is_err(), "should reject undelegate > stake");
    }

    #[test]
    fn undelegate_rejects_non_delegator() {
        // Security regression: previously any sender could unbond any
        // validator's stake — the delegation is owned by sender 0, so
        // sender 5's undelegate must be rejected.
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let result = staking.handle(&ctx_with_sender(5), &msg::undelegate(v, 300));
        assert!(result.is_err(), "non-delegator must not unbond someone else's stake");
        assert_eq!(staking.stake(&v), 1000, "stake unchanged after rejected undelegate");
    }

    #[test]
    fn delegate_moves_funds_to_bonded_pool() {
        let (staking, bank) = setup_with_bank(&[1]);
        let v = addr(1);
        let before = bank.balance(&addr(0));
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        assert_eq!(bank.balance(&addr(0)), before - 1000, "delegator debited");
        assert_eq!(bank.balance(&BONDED_POOL), 1000, "bonded pool credited");
        assert_eq!(staking.delegation(&addr(0), &v), 1000);
    }

    #[test]
    fn delegate_rejects_insufficient_balance() {
        let (staking, bank) = setup_with_bank(&[1]);
        let v = addr(1);
        let result = staking.handle(&ctx(), &msg::delegate(v, 2_000_000));
        assert!(result.is_err(), "delegate exceeding balance must fail");
        assert_eq!(staking.stake(&v), 0, "no stake created on failure");
        assert_eq!(bank.balance(&BONDED_POOL), 0, "pool untouched on failure");
    }

    #[test]
    fn unbonding_refunds_delegator_via_bank() {
        let (staking, bank) = setup_with_bank(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let after_delegate = bank.balance(&addr(0));
        staking.begin_block(Height::new(10));
        staking.handle(&ctx(), &msg::undelegate(v, 400)).unwrap();
        // Still in the pool while unbonding.
        assert_eq!(bank.balance(&BONDED_POOL), 1000);
        assert_eq!(bank.balance(&addr(0)), after_delegate, "not refunded yet");
        staking.begin_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
        staking.end_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
        assert_eq!(
            bank.balance(&addr(0)),
            after_delegate + 400,
            "unbonded funds returned to the delegator"
        );
        assert_eq!(bank.balance(&BONDED_POOL), 600, "pool keeps the bonded remainder");
    }

    #[test]
    fn slash_burns_only_bonded_funds() {
        let (staking, bank) = setup_with_bank(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.handle(&ctx(), &msg::slash(v, 100)).unwrap();
        assert_eq!(staking.stake(&v), 900);
        assert_eq!(staking.delegation(&addr(0), &v), 900, "delegation reduced proportionally");
        assert_eq!(bank.balance(&BONDED_POOL), 900, "slashed amount burned from pool");
    }

    #[test]
    fn undelegate_rejects_unknown_validator() {
        let staking = setup(&[1]);
        let v = addr(1);
        let result = staking.handle(&ctx(), &msg::undelegate(v, 100));
        assert!(result.is_err(), "should reject undelegate of unknown validator");
    }

    #[test]
    fn unbonding_completes_after_period() {
        let staking = setup(&[1]);
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
        let staking = setup(&[1]);
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
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let slash_amount = msg::double_sign_slash_amount(1000);
        assert_eq!(slash_amount, 100, "10% of 1000 = 100");
        staking.handle(&ctx(), &msg::slash(v, slash_amount)).unwrap();
        assert_eq!(staking.stake(&v), 900, "stake reduced by slash");
    }

    #[test]
    fn slash_capped_at_stake() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
        // Try to slash more than the stake.
        staking.handle(&ctx(), &msg::slash(v, 500)).unwrap();
        assert_eq!(staking.stake(&v), 0, "stake floored at 0");
    }

    #[test]
    fn slash_rejects_unknown_validator() {
        let staking = setup(&[]);
        let v = addr(1);
        let result = staking.handle(&ctx(), &msg::slash(v, 100));
        assert!(result.is_err(), "should reject slash of unknown validator");
    }

    #[test]
    fn rewards_accumulate_per_block() {
        let staking = setup(&[1, 2]).with_block_reward(1_000_000);
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
        let staking = setup(&[1]).with_block_reward(1_000_000);
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
        let staking = setup(&[0]).with_block_reward(1_000_000);
        let v = addr(0); // sender addr(0) is the validator — claims its own rewards
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        assert_eq!(staking.rewards(&v), 1_000_000);
        staking.handle(&ctx(), &msg::claim_reward(v, 0)).unwrap();
        assert_eq!(staking.rewards(&v), 0, "rewards claimed");
    }

    #[test]
    fn claim_reward_partial_withdrawal() {
        let staking = setup(&[0]).with_block_reward(1_000_000);
        let v = addr(0);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        staking.handle(&ctx(), &msg::claim_reward(v, 400_000)).unwrap();
        assert_eq!(staking.rewards(&v), 600_000, "600K remaining");
    }

    #[test]
    fn claim_reward_rejects_zero_balance() {
        let staking = setup(&[0]);
        let v = addr(0);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let result = staking.handle(&ctx(), &msg::claim_reward(v, 0));
        assert!(result.is_err(), "should reject claim with no rewards");
    }

    #[test]
    fn top_validators_sorted_by_stake() {
        let staking = setup(&[1, 2, 3]);
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
        let staking = setup(&[1]);
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
        let staking = setup(&[1]);
        let v = addr(1);
        let mut msg = msg::delegate(v, 100);
        msg[0] = 0xFF; // unknown type
        let result = staking.handle(&ctx(), &msg);
        assert!(result.is_err(), "should reject unknown message type");
    }

    #[test]
    fn state_root_changes_after_delegate() {
        let staking = setup(&[1]);
        let root0 = staking.state_root();
        staking.handle(&ctx(), &msg::delegate(addr(1), 100)).unwrap();
        let root1 = staking.state_root();
        assert_ne!(root0, root1);
    }

    #[test]
    fn state_root_changes_after_slash() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let root0 = staking.state_root();
        staking.handle(&ctx(), &msg::slash(v, 100)).unwrap();
        let root1 = staking.state_root();
        assert_ne!(root0, root1, "state root must change after slash");
    }

    #[test]
    fn custom_unbonding_period() {
        let staking = setup(&[1]).with_unbonding_period(10);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(5));
        staking.handle(&ctx(), &msg::undelegate(v, 500)).unwrap();
        let pending = staking.pending_unbonding();
        assert_eq!(pending[0].completion_height, 15, "5 + 10 = 15");
    }

    #[test]
    fn key_change_stores_pending_key() {
        let staking = setup(&[0]);
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
        let staking = setup(&[1]);
        let v = addr(1); // sender is addr(0), but validator is addr(1)
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let new_key = vec![0xAA; 48];
        let result = staking.handle(&ctx(), &msg::key_change(v, &new_key));
        assert!(result.is_err(), "must reject key change from non-validator sender");
    }

    #[test]
    fn key_change_rejects_unknown_validator() {
        let staking = setup(&[]);
        let v = addr(0); // sender is addr(0) but no stake delegated
        let new_key = vec![0xAA; 48];
        let result = staking.handle(&ctx(), &msg::key_change(v, &new_key));
        assert!(result.is_err(), "must reject key change for unknown validator");
    }

    #[test]
    fn key_change_rejects_wrong_key_length() {
        let staking = setup(&[0]);
        let v = addr(0);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let short_key = vec![0xAA; 32]; // not 48 bytes
        let msg = msg::key_change(v, &short_key);
        let result = staking.handle(&ctx(), &msg);
        assert!(result.is_err(), "must reject non-48-byte key");
    }
}
