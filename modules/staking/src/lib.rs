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
//!   the delegator is paid from the bonded pool at
//!   `end_block` (completed automatically).
//! - `0x03` Slash: reduce `validator`'s stake by `slash_fraction`
//!   of `amount`. Called by consensus (double-sign evidence) or
//!   governance. The slashed amount is burned.
//! - `0x04` Claim reward: withdraw accumulated rewards for
//!   `validator` (minted to the sender's account balance).
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
//! At each `end_block`, the block reward — swept envelope fees
//! (collected in [`FEE_POOL`]) plus fixed issuance — is distributed
//! to all active validators proportional to their stake, credited
//! to a *reward-per-token* accumulator per validator. Delegators
//! and the validator's self-share both earn pro-rata through lazy
//! accrual: positions settle into `pending_rewards` when they
//! mutate or when the owner claims via `claim_reward`. Claims pay
//! out of [`REWARD_POOL`], which `end_block` funds with the swept
//! fees plus an issuance mint.
//!
//! Validators pending removal stop earning. Rounding remainders
//! stay in the reward pool as unclaimable dust — a deterministic
//! rounding burn.

use std::collections::BTreeMap;
use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::{Balances, module_id, subtree_root};
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
    /// Validator add: endorse admitting a new validator. The
    /// admission applies only once cumulative endorsing power
    /// strictly exceeds two-thirds of the committee (C9), registers
    /// the candidate with zero stake, and seats it at the next
    /// epoch rotation only if collateral has been bonded via
    /// `delegate` — declared stake was never real collateral.
    pub const VALIDATOR_ADD: u8 = 0x06;
    /// Validator remove: endorse removing a validator from the
    /// set. Applies at committee quorum; the validator is removed
    /// from consensus at the next epoch rotation and stops
    /// receiving block rewards. Their stake enters unbonding
    /// (reclaimable after the unbonding period).
    pub const VALIDATOR_REMOVE: u8 = 0x07;
    /// Evidence: submit cryptographic proof of a consensus fault
    /// (double-sign). Permissionless — the proof itself
    /// authenticates the report; no committee check applies.
    /// On a valid proof the offender is slashed and jailed.
    pub const EVIDENCE: u8 = 0x08;
    /// Unjail: a jailed validator rejoins the set after the jail
    /// period. Sender must be the validator itself.
    pub const UNJAIL: u8 = 0x09;
    /// Schedule halt: endorse setting (or clearing) the
    /// coordinated halt height. Applies at committee quorum —
    /// a lone validator must never hold the freeze trigger.
    /// Height 0 clears the schedule.
    pub const SCHEDULE_HALT: u8 = 0x0A;
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
/// Minimum jail time in blocks before `unjail` is accepted.
///
/// Unit: blocks. At the ~1 s/view block cadence this is ~10 min —
/// the Cosmos `x/slashing` `DowntimeJailDuration` order of
/// magnitude. It exists so a jailed validator cannot slash-evade by
/// unjailing in the very next block; the epoch rotation that drops
/// them from consensus must happen first.
const MIN_JAIL_BLOCKS: u64 = 600;

/// Byte length of a double-sign evidence payload after the
/// `[type][validator]` header:
/// `[view:8B][phase:1B][epoch:8B][hash_a:32B][sig_a:96B][hash_b:32B][sig_b:96B]`.
///
/// The layout mirrors `vote_signing_message` in
/// `crates/consensus/src/engine.rs` (49 bytes per vote:
/// view LE + phase + `block_hash` + epoch LE) so the reporter only
/// has to forward what the wire carried.
const EVIDENCE_PAYLOAD_LEN: usize = 8 + 1 + 8 + 32 + 96 + 32 + 96;

/// How many retired consensus keys are kept per validator for
/// evidence verification. Double-sign evidence must arrive while
/// the offender's stake is still slashable (the unbonding window);
/// key rotations are endorsement-driven, not on a fixed block
/// schedule, so the bound is a COUNT of displaced keys rather than
/// an epoch span. `8` covers a validator rotating eight times
/// inside one unbonding window — far beyond honest churn — while
/// keeping attacker-driven growth bounded per validator.
const EVIDENCE_KEY_HISTORY: usize = 8;

/// Sliding window (blocks) over which downtime is measured.
///
/// Unit: blocks. Mirrors Cosmos `SignedBlocksWindow` (= 100
/// default) — big enough that a few missed blocks never jail, small
/// enough that a dead validator is evicted in ~2 minutes at ~1 s
/// blocks. Each tracked validator keeps at most this many outcome
/// bits, so memory stays O(validators × 100).
const DOWNTIME_WINDOW: usize = 100;

/// Minimum blocks a validator must sign within `DOWNTIME_WINDOW`
/// to avoid jailing (50% — Cosmos `MinSignedPerWindow` = 0.5).
/// Evaluated only once the window is full: a validator cannot be
/// jailed before they have been live for `DOWNTIME_WINDOW` blocks,
/// so fresh joins get a full grace period.
const DOWNTIME_MIN_SIGNED: usize = 50;

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
/// Delegated funds are held at this address in the EVM account
/// ledger: a `delegate` moves `delegator → BONDED_POOL`, and completed
/// unbonding moves `BONDED_POOL → delegator` back. The pool balance
/// therefore always equals total live delegations + in-flight
/// unbonding — the same accounting identity Cosmos keeps between its
/// ledger and the bonded-tokens pool, except here the "account"
/// is a real EVM address whose balance is part of the state root.
///
/// The address is a fixed 20-byte tag — no private key exists, so
/// only the staking module's own calls can move funds out.
pub const BONDED_POOL: Address = Address(*b"oxide/staking/pool!!");

/// The fee-collection module account.
///
/// The EVM ledger's `charge_fee` transfers each envelope fee
/// `sender → FEE_POOL` when the node wires it as the fee recipient
/// (`EvmModule::with_fee_recipient`). At `end_block` the pool's
/// balance is swept into [`REWARD_POOL`] and distributed
/// pro-rata to validators and their delegators. No private key
/// exists for the address.
pub const FEE_POOL: Address = Address(*b"oxide/staking/fee!!!");

/// The claim-funding module account.
///
/// `end_block` funds it with the swept [`FEE_POOL`] balance plus the
/// issuance `block_reward` mint; `claim_reward` pays out of it. Its
/// balance therefore always equals total accrued-but-unclaimed
/// rewards plus integer-division dust (rounding remainders are
/// unclaimable — they accumulate deterministically, a rounding burn).
pub const REWARD_POOL: Address = Address(*b"oxide/staking/rwd!!!");

/// Fixed-point scale for the reward-per-token accumulator.
///
/// `reward_per_token[v]` is a cumulative `u128` of reward units per
/// bonded stake unit, scaled by 1e18 so integer division keeps
/// sub-unit precision across many small blocks — the same scheme
/// Synthetix's `StakingRewards` uses, chosen because it makes
/// per-block distribution O(validators) and each delegation
/// mutation O(1) instead of O(total delegators) per block.
const RPT_SCALE: u128 = 1_000_000_000_000_000_000;

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
    /// debits the delegator's balance into [`BONDED_POOL`] and
    /// credits this map; `undelegate` requires the delegator's own
    /// delegation to cover the amount. Without it, `delegate` was
    /// unbacked stake inflation (any tx could grow any validator's
    /// stake for free) and `undelegate` let any account unbond any
    /// validator's stake.
    delegations: Mutex<BTreeMap<(Address, Address), u64>>,
    /// The balance ledger used for bond/unbond settlement — the
    /// EVM account store behind `framework::Balances`. `None` in
    /// bare unit tests only — `delegate`/`unbond_immediate` fail
    /// closed when unset (an unbacked delegation is a consensus
    /// accounting hole; see `docs/evm-parity-gap-analysis.md` for why
    /// precompile→module paths must reuse the native invariants).
    ///
    /// Note: the EVM *precompile* path does not go through this
    /// handle — inside a revm frame the bond moves through
    /// [`JournalBalances`] so revm's checkpoint machinery owns the
    /// revert. This field serves native `handle_delegate` txs,
    /// `end_block` unbond payouts, reward mints, and slash burns.
    ledger: Mutex<Option<std::sync::Arc<dyn Balances + Send + Sync>>>,
    /// Pending unbonding entries (completed at `end_block`).
    unbonding: Mutex<Vec<UnbondingEntry>>,
    /// Settled-but-unclaimed rewards per account (validators and
    /// delegators alike). Lazy accrual lives in
    /// `reward_per_token`/`reward_debt`; this map is only topped up
    /// when a position settles (delegation mutation or claim).
    pending_rewards: Mutex<BTreeMap<Address, u64>>,
    /// Cumulative reward units per bonded stake unit per validator,
    /// scaled by [`RPT_SCALE`] — the "reward-per-token" accumulator.
    /// `end_block` grows it by `block_reward_v × SCALE / stake_v`.
    reward_per_token: Mutex<BTreeMap<Address, u128>>,
    /// The `reward_per_token` value at which each delegation last
    /// settled — `(delegator, validator) → debt`. Pending reward =
    /// `delegation × (rpt − debt) / SCALE`.
    reward_debt: Mutex<BTreeMap<(Address, Address), u128>>,
    /// The `reward_per_token` value at which each validator's
    /// *self-share* last settled. A validator's reward splits two
    /// ways: delegations accrue through `reward_debt`, and the
    /// non-delegated remainder (`stake − delegated_total`, e.g.
    /// genesis self-stake) accrues to the validator itself through
    /// this map.
    self_debt: Mutex<BTreeMap<Address, u128>>,
    /// Delegator → validators index: which validators each account
    /// delegates to, so `claim_reward` can settle all of a sender's
    /// positions without scanning the full delegation map.
    delegator_index: Mutex<BTreeMap<Address, std::collections::BTreeSet<Address>>>,
    /// Sum of live delegations per validator — `stake −
    /// delegated_total` is the validator's self-share that accrues
    /// through `self_debt`.
    delegated_total: Mutex<BTreeMap<Address, u64>>,
    /// Pending BLS key changes per validator address. The new key
    /// takes effect at the next epoch rotation — the consensus
    /// engine reads these via `take_key_changes` at the epoch
    /// boundary.
    pending_key_changes: Mutex<BTreeMap<Address, Vec<u8>>>,
    /// Pending validator additions: `(address, bls_public_key)`.
    /// The new validator joins the set at the next epoch rotation —
    /// and only if it has *bonded* stake by then (delegations to the
    /// registered candidate): admission authorizes membership, the
    /// ledger debit proves collateral. The consensus engine reads
    /// these via `take_validator_changes`.
    pending_validator_adds: Mutex<Vec<(Address, Vec<u8>)>>,
    /// Pending validator removals: addresses to remove at the next
    /// epoch rotation. The consensus engine reads these via
    /// `take_validator_changes`.
    pending_validator_removes: Mutex<Vec<Address>>,
    /// Committee endorsements for governance-gated actions —
    /// validator adds/removes, slashes, and scheduled halts. Each
    /// gated tx records the sender's endorsement of the exact
    /// action payload; the action applies only when cumulative
    /// endorsing power strictly exceeds two-thirds of the
    /// committee's total bonded power (C9: one validator's
    /// signature is a vote, never a command).
    endorsements: framework::Endorsements,
    /// The *current* BLS consensus key per validator — 48-byte
    /// BLS12-381 compressed public key. Unlike
    /// `pending_key_changes` (drained each rotation), this map
    /// persists so `handle_evidence` can verify vote signatures
    /// against the key the validator is known by. Set at
    /// `VALIDATOR_ADD` / `genesis_set_bls_key`, updated when
    /// `take_key_changes` applies a rotation, never deleted — a
    /// stale key is harmless (evidence requires the validator to
    /// still exist) and re-adds overwrite it.
    bls_keys: Mutex<BTreeMap<Address, Vec<u8>>>,
    /// Recently displaced consensus keys per validator, oldest
    /// first, capped at [`EVIDENCE_KEY_HISTORY`]. A rotation or
    /// re-admission moves the previous key here: the key can no
    /// longer sign new votes but `handle_evidence` must still
    /// verify proofs for votes signed BEFORE the rotation —
    /// otherwise a validator could rotate away from an offense
    /// (the v1 bound: evidence died the moment keys changed).
    /// Committed state: two replicas disagreeing on the retired
    /// set disagree on whether a proof verifies.
    retired_bls_keys: Mutex<BTreeMap<Address, Vec<Vec<u8>>>>,
    /// Jailed validators: address → height jailed. Jailed
    /// validators are emitted as `removes` at the next epoch
    /// rotation (out of consensus), stop earning rewards, and keep
    /// their (already-slashed) stake — jailing is exclusion, not
    /// confiscation. `unjail` re-admits them after
    /// [`MIN_JAIL_BLOCKS`].
    jailed: Mutex<BTreeMap<Address, u64>>,
    /// Validators jailed since the last `take_validator_changes`
    /// drain — emitted as `removes` so the engine drops them from
    /// consensus at the next rotation.
    pending_jails: Mutex<Vec<Address>>,
    /// Validators unjailed since the last drain — emitted as `adds`
    /// (with their `bls_keys` entry and current stake) so the
    /// engine re-admits them at the next rotation.
    pending_unjails: Mutex<Vec<Address>>,
    /// The coordinated halt height scheduled by governance
    /// (`SCHEDULE_HALT`): the chain freezes state for heights
    /// above it. Read by the executor via
    /// `Module::scheduled_halt_height`. `None` = no halt. Lives in
    /// module state (set by a tx), so every replica schedules the
    /// same halt deterministically.
    scheduled_halt: Mutex<Option<u64>>,
    /// Canonical offense identities already applied — the hash of
    /// `(validator, view, phase, epoch)`, NOT of the evidence
    /// payload. Penalties are per OFFENSE: once a validator is
    /// slashed for equivocating at a consensus position, any
    /// further proof of that same position — the pair swapped, or
    /// a different conflicting pair entirely — is a replay, not a
    /// new offense. (The v1 key hashed the raw ordered pair, so
    /// resubmitting the same offense with the votes swapped
    /// minted a fresh identity and slashed twice.)
    seen_evidence: Mutex<std::collections::BTreeSet<Hash>>,
    /// Per-validator attendance ring: `true` = signed the block's
    /// committing QC, `false` = absent. Fed by
    /// `record_block_attendance` (called inside `execute_block`,
    /// so journal replay rebuilds identical windows). Each entry
    /// is capped at [`DOWNTIME_WINDOW`] outcomes.
    attendance: Mutex<BTreeMap<Address, std::collections::VecDeque<bool>>>,
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
            ledger: Mutex::new(None),
            unbonding: Mutex::new(Vec::new()),
            pending_rewards: Mutex::new(BTreeMap::new()),
            reward_per_token: Mutex::new(BTreeMap::new()),
            reward_debt: Mutex::new(BTreeMap::new()),
            self_debt: Mutex::new(BTreeMap::new()),
            delegator_index: Mutex::new(BTreeMap::new()),
            delegated_total: Mutex::new(BTreeMap::new()),
            pending_key_changes: Mutex::new(BTreeMap::new()),
            pending_validator_adds: Mutex::new(Vec::new()),
            pending_validator_removes: Mutex::new(Vec::new()),
            endorsements: framework::Endorsements::new(),
            bls_keys: Mutex::new(BTreeMap::new()),
            retired_bls_keys: Mutex::new(BTreeMap::new()),
            jailed: Mutex::new(BTreeMap::new()),
            pending_jails: Mutex::new(Vec::new()),
            pending_unjails: Mutex::new(Vec::new()),
            scheduled_halt: Mutex::new(None),
            seen_evidence: Mutex::new(std::collections::BTreeSet::new()),
            attendance: Mutex::new(BTreeMap::new()),
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

    /// Register a genesis validator's BLS consensus key — the
    /// evidence-verification counterpart of
    /// `genesis_register_validator`. Genesis JSON carries
    /// `validators[].public_key` optionally; single-node devnets
    /// skip it (mock consensus never produces real signatures, so
    /// no verifiable evidence can exist anyway).
    ///
    /// # Panics
    ///
    /// Panics if `key` is not 48 bytes or the mutex is poisoned.
    pub fn genesis_set_bls_key(&self, validator: Address, key: &[u8]) {
        assert_eq!(key.len(), crypto::bls::PublicKey::LEN, "BLS key must be 48 bytes");
        self.bls_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(validator, key.to_vec());
    }

    /// Whether `addr` is currently jailed (excluded from consensus
    /// and rewards until unjailed). Exposed for tests and the
    /// validator-status RPC surface.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn is_jailed(&self, addr: &Address) -> bool {
        self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains_key(addr)
    }

    /// `true` if `addr` is in the current validator set, not
    /// jailed, and not a quorum-admitted candidate still waiting
    /// for the epoch rotation — i.e. eligible to perform
    /// committee-privileged actions (oracle price feeds,
    /// governance endorsements) right now.
    ///
    /// Jailed validators keep their stake (so `is_jailed` alone is
    /// not the check) but are excluded from committee duties until
    /// they unjail: a jailed validator is by definition suspected
    /// of misbehavior, and letting it keep feeding prices or voting
    /// on slashes would let the fault continue during the jail
    /// period. Pending candidates are registered so delegations can
    /// bond to them, but committee membership begins at the
    /// rotation that seats them.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn is_active_validator(&self, addr: &Address) -> bool {
        let in_set = self
            .validators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(addr);
        if !in_set || self.is_jailed(addr) {
            return false;
        }
        !self
            .pending_validator_adds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|(a, _)| a == addr)
    }

    /// `true` if `addr` is registered as a validator — an active
    /// committee member *or* a quorum-admitted candidate awaiting
    /// the epoch rotation (candidates are registered so
    /// delegations can bond collateral to them).
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn is_registered(&self, addr: &Address) -> bool {
        self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains_key(addr)
    }

    /// `addr`'s current voting power: bonded stake if the address
    /// is an active committee member, `0` otherwise. Governance
    /// endorsements weigh power, not membership — a jailed,
    /// pending, or unbonded member holds no vote.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn power(&self, addr: &Address) -> u64 {
        if !self.is_active_validator(addr) {
            return 0;
        }
        self.validators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(addr)
            .copied()
            .unwrap_or(0)
    }

    /// Total voting power across the active committee — the
    /// denominator for the two-thirds governance quorum. Jailed
    /// and pending-add members are excluded (their stake exists but
    /// holds no vote).
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn total_power(&self) -> u64 {
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let jailed = self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending =
            self.pending_validator_adds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        validators
            .iter()
            .filter(|(a, _)| !jailed.contains_key(*a) && !pending.iter().any(|(p, _)| p == *a))
            .map(|(_, s)| *s)
            .sum()
    }

    /// Number of validators eligible for committee duties right now
    /// (in set, not jailed, not pending activation). Used by the
    /// oracle to size its submission quorum.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    #[must_use]
    pub fn active_validator_count(&self) -> usize {
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let jailed = self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending =
            self.pending_validator_adds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        validators
            .keys()
            .filter(|v| !jailed.contains_key(*v) && !pending.iter().any(|(p, _)| p == *v))
            .count()
    }
}

impl framework::Committee for StakingModule {
    fn is_active_validator(&self, addr: &Address) -> bool {
        Self::is_active_validator(self, addr)
    }

    fn active_validator_count(&self) -> usize {
        Self::active_validator_count(self)
    }

    fn power(&self, addr: &Address) -> u64 {
        Self::power(self, addr)
    }

    fn total_power(&self) -> u64 {
        Self::total_power(self)
    }
}

impl StakingModule {
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

    /// The account's claimable rewards *as if it settled now* —
    /// stored `pending_rewards` plus lazy accrual on every position
    /// it holds (delegations + validator self-share). Read-only:
    /// the same arithmetic `settle_all` performs, without writing.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn claimable(&self, addr: &Address) -> u64 {
        let rpts = self.reward_per_token.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let debts = self.reward_debt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut total = *self
            .pending_rewards
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(addr)
            .unwrap_or(&0);
        let delegator_vs = self
            .delegator_index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(addr)
            .cloned()
            .unwrap_or_default();
        let delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for v in &delegator_vs {
            let amount = delegations.get(&(*addr, *v)).copied().unwrap_or(0);
            let rpt = rpts.get(v).copied().unwrap_or(0);
            let debt = debts.get(&(*addr, *v)).copied().unwrap_or(0);
            if rpt > debt && amount > 0 {
                let accrued = u128::from(amount).saturating_mul(rpt - debt) / RPT_SCALE;
                total = total.saturating_add(u64::try_from(accrued).unwrap_or(u64::MAX));
            }
        }
        drop(delegations);
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(&stake) = validators.get(addr) {
            let delegated = self
                .delegated_total
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(addr)
                .copied()
                .unwrap_or(0);
            let self_share = Self::self_share_of(stake, delegated);
            let rpt = rpts.get(addr).copied().unwrap_or(0);
            let debt = self
                .self_debt
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(addr)
                .copied()
                .unwrap_or(0);
            if rpt > debt && self_share > 0 {
                let accrued = u128::from(self_share).saturating_mul(rpt - debt) / RPT_SCALE;
                total = total.saturating_add(u64::try_from(accrued).unwrap_or(u64::MAX));
            }
        }
        total
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
    /// Draining means the rotation *applied* — the new key is now
    /// the validator's current consensus key, so `bls_keys` is
    /// updated here (not at `handle_key_change`, which is only the
    /// pending stage). The displaced key moves to
    /// `retired_bls_keys`: it cannot sign new votes but evidence
    /// for votes signed before the rotation still verifies — an
    /// offender cannot rotate away from a pending proof.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn take_key_changes(&self) -> Vec<(Address, Vec<u8>)> {
        let changes: Vec<(Address, Vec<u8>)> = std::mem::take(
            &mut *self
                .pending_key_changes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_iter()
        .collect();
        let mut bls_keys = self.bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (addr, key) in &changes {
            if let Some(old) = bls_keys.insert(*addr, key.clone()) {
                if old != *key {
                    self.retire_key(*addr, old);
                }
            }
        }
        changes
    }

    /// Move `old_key` into `validator`'s retired-key history —
    /// bounded at [`EVIDENCE_KEY_HISTORY`] entries, oldest dropped
    /// first. Every site that displaces or removes a live
    /// `bls_keys` entry routes through here: the key can no longer
    /// sign new votes but evidence for votes it already signed
    /// must still verify — the uniform rule keeps re-admission,
    /// rotation, and lapse paths from silently dropping the one
    /// key a pending proof needs.
    fn retire_key(&self, validator: Address, old_key: Vec<u8>) {
        let mut retired =
            self.retired_bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let keys = retired.entry(validator).or_default();
        keys.push(old_key);
        if keys.len() > EVIDENCE_KEY_HISTORY {
            // The oldest retirements fall off — evidence that old
            // is almost certainly outside the slashable window
            // anyway.
            keys.remove(0);
        }
    }

    /// Take all pending validator changes, clearing all queues.
    /// Called by the consensus engine at the epoch boundary to apply
    /// validator additions and removals to the validator set.
    ///
    /// Returns a [`framework::ValidatorChanges`] — `adds` is a list
    /// of `(address, bls_public_key, stake)` tuples for new
    /// validators; `removes` is a list of addresses to remove.
    ///
    /// Jails fold into `removes` (a jailed validator leaves
    /// consensus at the rotation) and unjails fold into `adds`
    /// (re-admitted with their `bls_keys` entry and current stake).
    /// A validator that is somehow both pending-remove and jailed
    /// appears in `removes` once — the merge goes through a set.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn take_validator_changes(&self) -> executor::ValidatorChanges {
        let removes: std::collections::BTreeSet<Address> = std::mem::take(
            &mut *self
                .pending_validator_removes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_iter()
        .chain(std::mem::take(
            &mut *self.pending_jails.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        ))
        .collect();
        let pending_adds = std::mem::take(
            &mut *self
                .pending_validator_adds
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut adds = Vec::with_capacity(pending_adds.len());
        {
            let mut validators =
                self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut bls_keys =
                self.bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for (addr, key) in pending_adds {
                let bonded = validators.get(&addr).copied().unwrap_or(0);
                if bonded == 0 {
                    // Admission authorized membership, not stake —
                    // a candidate that reaches the rotation with no
                    // bonded collateral never proved it has skin in
                    // the game. The admission lapses: unwind the
                    // registration so a fresh endorsement round can
                    // admit them once funded. (Keeping the pending
                    // add would let an unfunded address hold a queue
                    // slot forever.)
                    validators.remove(&addr);
                    // Retire, not drop — a lapsed admission's key
                    // never signed votes, but if the address was a
                    // previously-active validator this entry is its
                    // last live key and old evidence still needs it.
                    if let Some(old) = bls_keys.remove(&addr) {
                        self.retire_key(addr, old);
                    }
                    continue;
                }
                adds.push((addr, key, bonded));
            }
        }
        let unjails = std::mem::take(
            &mut *self.pending_unjails.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if !unjails.is_empty() {
            let bls_keys = self.bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let validators =
                self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for addr in unjails {
                // `handle_unjail` already required both — a missing
                // entry here means the validator was removed between
                // unjail and rotation; skip rather than re-add a
                // phantom.
                if let (Some(key), Some(stake)) = (bls_keys.get(&addr), validators.get(&addr)) {
                    adds.push((addr, key.clone(), *stake));
                }
            }
        }
        executor::ValidatorChanges { adds, removes: removes.into_iter().collect() }
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
    ///
    /// The tx is a committee *endorsement* of the exact
    /// `(validator, amount)` action — it applies only once
    /// endorsing power strictly exceeds two-thirds (C9). The
    /// permissionless alternative is [`msg::evidence`], which
    /// authenticates itself with the proof it carries.
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

    /// A key-change message: `[type: 0x05][validator: 20B][new_key: 48B][pop: 96B]`.
    ///
    /// Updates a validator's BLS consensus public key. The new key
    /// takes effect at the next epoch rotation. Only the validator
    /// itself can submit this (the sender must equal `validator`).
    ///
    /// `new_key` is a 48-byte BLS12-381 compressed public key. `pop`
    /// is the 96-byte proof-of-possession for that key
    /// (`BlsSecretKey::pop_prove`) — required because QC verification
    /// uses `fast_aggregate_verify`, which is unsafe unless every
    /// admitted key proves possession (rogue-key attack).
    pub fn key_change(validator: primitives::Address, new_key: &[u8], pop: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(165);
        msg.push(super::msg_type::KEY_CHANGE);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(new_key);
        msg.extend_from_slice(pop);
        msg
    }

    /// A validator-add endorsement:
    /// `[type: 0x06][new_validator: 20B][bls_key: 48B][pop: 96B]`.
    ///
    /// Records the sender's endorsement of admitting `new_validator`
    /// with consensus key `bls_key`. The admission applies only once
    /// cumulative endorsing power strictly exceeds two-thirds of the
    /// committee (C9) — one validator's tx is a vote, not a command.
    /// The admitted candidate joins at the next epoch rotation, and
    /// only if real balance has been bonded to it via `delegate`:
    /// the message carries no stake field because declared stake was
    /// never collateral.
    ///
    /// `new_validator` is the staking address. `bls_key` is the
    /// 48-byte BLS12-381 compressed public key. `pop` is the 96-byte
    /// proof-of-possession for `bls_key` (`BlsSecretKey::pop_prove`),
    /// required so `fast_aggregate_verify` QC checks are safe from
    /// rogue-key forgery.
    pub fn validator_add(
        new_validator: primitives::Address,
        bls_key: &[u8],
        pop: &[u8],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(165);
        msg.push(super::msg_type::VALIDATOR_ADD);
        msg.extend_from_slice(&new_validator.0);
        msg.extend_from_slice(bls_key);
        msg.extend_from_slice(pop);
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

    /// A double-sign evidence message:
    /// `[type: 0x08][validator: 20B][view: 8B LE][phase: 1B]`
    /// `[epoch: 8B LE][hash_a: 32B][sig_a: 96B][hash_b: 32B][sig_b: 96B]`.
    ///
    /// `view`/`phase`/`epoch` must be identical for both votes —
    /// they are the shared context the offender equivocated within;
    /// the two `block_hash`/`signature` pairs are the conflicting
    /// votes themselves. Anyone may submit: the signatures are the
    /// authentication.
    #[allow(clippy::too_many_arguments)]
    pub fn evidence(
        validator: primitives::Address,
        view: u64,
        phase: u8,
        epoch: u64,
        hash_a: &[u8],
        sig_a: &[u8],
        hash_b: &[u8],
        sig_b: &[u8],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(21 + super::EVIDENCE_PAYLOAD_LEN);
        msg.push(super::msg_type::EVIDENCE);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(&view.to_le_bytes());
        msg.push(phase);
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(hash_a);
        msg.extend_from_slice(sig_a);
        msg.extend_from_slice(hash_b);
        msg.extend_from_slice(sig_b);
        msg
    }

    /// An unjail message: `[type: 0x09][validator: 20B]`.
    ///
    /// Re-admits a jailed validator at the next epoch rotation.
    /// Only the validator itself can submit this, after
    /// `MIN_JAIL_BLOCKS` have passed since jailing.
    pub fn unjail(validator: primitives::Address) -> Vec<u8> {
        let mut msg = Vec::with_capacity(21);
        msg.push(super::msg_type::UNJAIL);
        msg.extend_from_slice(&validator.0);
        msg
    }

    /// A schedule-halt message: `[type: 0x0A][validator: 20B][halt_height: 8B LE]`.
    ///
    /// Sets the coordinated halt height — the chain freezes state
    /// for heights above it so operators can snapshot and swap
    /// binaries. `halt_height` must be in the future; `0` clears
    /// the schedule.
    ///
    /// The tx is a committee *endorsement* of the exact
    /// `(SCHEDULE_HALT, halt_height)` action — a lone validator
    /// must never hold the freeze trigger, so the schedule applies
    /// only once endorsing power strictly exceeds two-thirds (C9).
    /// The `validator` field is part of the wire format but not
    /// the action identity — the height alone decides what the
    /// vote means.
    pub fn schedule_halt(validator: primitives::Address, halt_height: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(29);
        msg.push(super::msg_type::SCHEDULE_HALT);
        msg.extend_from_slice(&validator.0);
        msg.extend_from_slice(&halt_height.to_le_bytes());
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
            // Evidence and unjail carry no `[amount: 8B]` field —
            // they must not reach `parse_message` below.
            msg_type::EVIDENCE => return self.handle_evidence(ctx, validator, msg),
            msg_type::UNJAIL => return self.handle_unjail(ctx, validator, msg),
            // Schedule-halt's second field is a height, not an
            // amount — same parse, different meaning.
            msg_type::SCHEDULE_HALT => {
                let (_, _, halt_height) = Self::parse_message(msg).ok_or(ExecError::Malformed)?;
                return self.handle_schedule_halt(ctx, validator, halt_height, msg);
            }
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

    fn end_block(&self, height: Height) -> Vec<Event> {
        // Process completed unbonding entries: pay each delegator out
        // of the bonded pool. Before this, unbonded funds vanished
        // (entries were dropped with no payout — the bonded pool kept
        // tokens nobody could reclaim).
        let current = height.value();
        let ledger = self.ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let mut unbonding =
            self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        unbonding.retain(|entry| {
            if entry.completion_height > current {
                return true;
            }
            if let Some(ledger) = &ledger {
                // Pool → delegator. The pool always holds the funds
                // (delegations + in-flight unbonding sum to the pool
                // balance), so this cannot fail; if it does, keep the
                // entry so the delegator can still be paid later.
                if ledger.transfer(&BONDED_POOL, &entry.delegator, entry.amount).is_err() {
                    return true;
                }
            }
            false
        });
        drop(unbonding);

        // Fund the reward pool and distribute this block's reward:
        // swept envelope fees (real, pre-collected) + fixed issuance
        // (minted). With no ledger wired there is nothing to
        // distribute — reward accounting requires the pool.
        if let Some(ledger) = &ledger {
            let total_reward = self.collect_block_reward(ledger.as_ref());
            self.distribute_rewards(total_reward);
        }
        Vec::new()
    }

    /// Record QC signers for `height` and jail validators whose
    /// attendance window has filled without meeting
    /// [`DOWNTIME_MIN_SIGNED`].
    ///
    /// Called inside `execute_block` — journal replay re-runs it
    /// with the journaled `signers`, so downtime jails derive
    /// identically on every replica.
    ///
    /// Downtime jails without slashing: absence is a liveness
    /// fault, not provable malice — the evidence path handles the
    /// confiscatory case. (v1 policy; a small downtime slash can be
    /// added once slash parameters are governance-controlled.)
    fn record_block_attendance(&self, height: Height, signers: &[Address]) {
        // Empty = "no attendance data" (sequencer/mock engines) —
        // never "everyone absent".
        if signers.is_empty() {
            return;
        }
        let signer_set: std::collections::BTreeSet<Address> = signers.iter().copied().collect();
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending_removes = self
            .pending_validator_removes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let jailed = self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut attendance =
            self.attendance.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let mut newly_jailed = Vec::new();
        for (addr, stake) in validators.iter() {
            // Only live members accrue attendance: no stake → not in
            // consensus; jailed/departing → already excluded.
            if *stake == 0 || jailed.contains_key(addr) || pending_removes.contains(addr) {
                continue;
            }
            let window = attendance.entry(*addr).or_default();
            window.push_back(signer_set.contains(addr));
            if window.len() > DOWNTIME_WINDOW {
                window.pop_front();
            }
            // Evaluate only a full window — a validator cannot be
            // jailed before being live for `DOWNTIME_WINDOW` blocks
            // (fresh-join grace period, same as Cosmos).
            if window.len() == DOWNTIME_WINDOW
                && window.iter().filter(|signed| **signed).count() < DOWNTIME_MIN_SIGNED
            {
                newly_jailed.push(*addr);
            }
        }
        // Release every read guard before re-locking `jailed` for
        // the write below — the first guard lives until scope end
        // (std `Mutex` is non-reentrant), so holding it here would
        // self-deadlock the first validator jailing.
        drop(attendance);
        drop(validators);
        drop(pending_removes);
        drop(jailed);

        if !newly_jailed.is_empty() {
            let mut jailed = self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut pending_jails =
                self.pending_jails.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for addr in newly_jailed {
                jailed.insert(addr, height.value());
                pending_jails.push(addr);
            }
        }
    }

    /// The governance-scheduled halt height, if any. Set by
    /// `SCHEDULE_HALT` (a tx, so every replica schedules the same
    /// halt deterministically — including on journal replay).
    fn scheduled_halt_height(&self) -> Option<u64> {
        *self.scheduled_halt.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn state_root(&self) -> Hash {
        // C8: commit EVERY field that can affect future execution.
        // The KV store mirrors only stake/delegation pairs — the
        // unbonding queue, reward accumulators, pending validator
        // changes, jails, attendance rings, and the scheduled halt
        // all decide future consensus set membership and payouts,
        // so identical roots across validators must prove identical
        // staking state. Field order is fixed and consensus-
        // critical (struct-declaration order).
        //
        // Excluded: `ledger` (assembly wiring), `unbonding_period` /
        // `block_reward` (construction config, never tx-mutated).
        // Locks are taken one at a time and released before the
        // next — no lock-order interaction with handlers.
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
    /// committed subtree root, fully decode every field with all
    /// internal invariants enforced, then hash the canonical
    /// preimage.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let (canon, _staged, _store) =
            framework::stage_blob_snapshot(snapshot, |r, store| Self::decode_committed(r, store))?;
        Ok(framework::canon_root(canon))
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then every field swaps in
    /// (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let (_canon, staged, store) =
            framework::stage_blob_snapshot(snapshot, |r, s| Self::decode_committed(r, s))?;
        *self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = store;
        *self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.validators;
        *self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.delegations;
        *self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.unbonding;
        *self.pending_rewards.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.pending_rewards;
        *self.reward_per_token.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.reward_per_token;
        *self.reward_debt.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.reward_debt;
        *self.self_debt.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.self_debt;
        *self.delegator_index.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.delegator_index;
        *self.delegated_total.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.delegated_total;
        *self.pending_key_changes.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.pending_key_changes;
        *self.pending_validator_adds.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.pending_validator_adds;
        *self.pending_validator_removes.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.pending_validator_removes;
        *self.bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = staged.bls_keys;
        *self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = staged.jailed;
        *self.pending_jails.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.pending_jails;
        *self.pending_unjails.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.pending_unjails;
        *self.scheduled_halt.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.scheduled_halt;
        *self.seen_evidence.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.seen_evidence;
        *self.retired_bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.retired_bls_keys;
        *self.attendance.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.attendance;
        *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            staged.current_height;
        self.endorsements.replace_with(staged.endorsements);
        Ok(())
    }

    fn take_key_changes(&self) -> Vec<(Address, Vec<u8>)> {
        StakingModule::take_key_changes(self)
    }

    fn take_validator_changes(&self) -> executor::ValidatorChanges {
        StakingModule::take_validator_changes(self)
    }
}

/// Staged staking state — the decoded form of a snapshot blob's
/// canonical section, produced by [`StakingModule::decode_committed`]
/// and installed by `import_state` only after the executor has
/// verified the blob's claimed root.
///
/// The `ledger` handle is not part of it — assembly wiring reattached
/// by the node harness, not chain state.
#[derive(Default)]
struct StagedStaking {
    /// Validator stake: address → total bonded.
    validators: BTreeMap<Address, u64>,
    /// `(delegator, validator) → bonded amount`.
    delegations: BTreeMap<(Address, Address), u64>,
    /// FIFO unbonding queue.
    unbonding: Vec<UnbondingEntry>,
    /// Claimable rewards per delegator.
    pending_rewards: BTreeMap<Address, u64>,
    /// Lazy-accrual accumulator per validator.
    reward_per_token: BTreeMap<Address, u128>,
    /// Reward debt per `(delegator, validator)`.
    reward_debt: BTreeMap<(Address, Address), u128>,
    /// Self-share reward debt per validator.
    self_debt: BTreeMap<Address, u128>,
    /// Delegator → set of validators mirrored from `delegations`.
    delegator_index: BTreeMap<Address, std::collections::BTreeSet<Address>>,
    /// Total delegated into each validator.
    delegated_total: BTreeMap<Address, u64>,
    /// Pending consensus-key rotations.
    pending_key_changes: BTreeMap<Address, Vec<u8>>,
    /// Endorsed validator admissions awaiting the epoch rotation.
    pending_validator_adds: Vec<(Address, Vec<u8>)>,
    /// Endorsed removals awaiting the epoch rotation.
    pending_validator_removes: Vec<Address>,
    /// Pending governance endorsements (C9).
    endorsements: framework::Endorsements,
    /// Live BLS consensus keys.
    bls_keys: BTreeMap<Address, Vec<u8>>,
    /// Retired BLS consensus keys per validator (bounded history —
    /// [`EVIDENCE_KEY_HISTORY`]). Empty in pre-upgrade blobs.
    retired_bls_keys: BTreeMap<Address, Vec<Vec<u8>>>,
    /// Jailed validators: address → height jailed.
    jailed: BTreeMap<Address, u64>,
    /// Jail events awaiting the next validator-set broadcast.
    pending_jails: Vec<Address>,
    /// Unjail events awaiting the next validator-set broadcast.
    pending_unjails: Vec<Address>,
    /// Governance-scheduled halt height.
    scheduled_halt: Option<u64>,
    /// Evidence hashes already acted on (replay guard).
    seen_evidence: std::collections::BTreeSet<Hash>,
    /// Per-validator attendance rings for downtime tracking.
    attendance: BTreeMap<Address, std::collections::VecDeque<bool>>,
    /// Last processed block height.
    current_height: u64,
}

impl StakingModule {
    /// Wire the balance ledger used for bond/unbond settlement.
    ///
    /// Must be called at assembly (before any block executes). On a
    /// live node this is the [`EvmModule`]-backed `Balances` impl —
    /// delegation debits land in the same account store EVM contracts
    /// read, so a delegator's `eth_getBalance` already reflects the
    /// bonded amount. `delegate` debits the delegator into
    /// [`BONDED_POOL`] and completed unbonding credits the delegator
    /// back.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn set_ledger(&self, ledger: std::sync::Arc<dyn Balances + Send + Sync>) {
        *self.ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ledger);
    }

    /// Commit `validators`, `delegations`, and the `unbonding` queue
    /// to the canonical state encoding (C8). These decide consensus
    /// voting power and future unbond payouts.
    fn commit_stake_state(&self, w: &mut framework::CanonicalState) {
        {
            let validators =
                self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(validators.len());
            for (a, s) in validators.iter() {
                w.put_addr(a).put_u64(*s);
            }
        }
        {
            let delegations =
                self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(delegations.len());
            for ((d, v), amt) in delegations.iter() {
                w.put_addr(d).put_addr(v).put_u64(*amt);
            }
        }
        {
            let unbonding =
                self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(unbonding.len());
            for e in unbonding.iter() {
                w.put_addr(&e.delegator)
                    .put_addr(&e.validator)
                    .put_u64(e.amount)
                    .put_u64(e.completion_height);
            }
        }
    }

    /// Commit the reward accrual state (C8): `pending_rewards`,
    /// `reward_per_token`, `reward_debt`, `self_debt`,
    /// `delegator_index`, and `delegated_total` — the lazy-accrual
    /// bookkeeping that decides future payouts. `delegator_index`
    /// is technically derivable from `delegations`, but it is
    /// maintained as replicated state and committed alongside: a
    /// drift bug would produce divergent claims and SHOULD diverge
    /// the root.
    fn commit_reward_state(&self, w: &mut framework::CanonicalState) {
        {
            let pending =
                self.pending_rewards.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(pending.len());
            for (a, r) in pending.iter() {
                w.put_addr(a).put_u64(*r);
            }
        }
        {
            let rpt =
                self.reward_per_token.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(rpt.len());
            for (a, r) in rpt.iter() {
                w.put_addr(a).put_u128(*r);
            }
            let debt = self.reward_debt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(debt.len());
            for ((d, v), r) in debt.iter() {
                w.put_addr(d).put_addr(v).put_u128(*r);
            }
            let self_debt =
                self.self_debt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(self_debt.len());
            for (a, r) in self_debt.iter() {
                w.put_addr(a).put_u128(*r);
            }
            let index =
                self.delegator_index.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(index.len());
            for (d, validators) in index.iter() {
                w.put_addr(d).put_count(validators.len());
                for v in validators {
                    w.put_addr(v);
                }
            }
            let totals =
                self.delegated_total.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(totals.len());
            for (a, t) in totals.iter() {
                w.put_addr(a).put_u64(*t);
            }
        }
    }

    /// Commit the validator-set transition state (C8): pending key
    /// changes, pending adds/removes, live BLS keys, jails, and the
    /// pending jail/unjail queues — everything the next epoch
    /// rotation will act on.
    fn commit_set_state(&self, w: &mut framework::CanonicalState) {
        let pending_keys =
            self.pending_key_changes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        w.put_count(pending_keys.len());
        for (a, k) in pending_keys.iter() {
            w.put_addr(a).put_bytes(k);
        }
        let adds =
            self.pending_validator_adds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        w.put_count(adds.len());
        for (a, k) in adds.iter() {
            w.put_addr(a).put_bytes(k);
        }
        let removes = self
            .pending_validator_removes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        w.put_count(removes.len());
        for a in removes.iter() {
            w.put_addr(a);
        }
        let keys = self.bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        w.put_count(keys.len());
        for (a, k) in keys.iter() {
            w.put_addr(a).put_bytes(k);
        }
        let jailed = self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        w.put_count(jailed.len());
        for (a, h) in jailed.iter() {
            w.put_addr(a).put_u64(*h);
        }
        let pending_jails =
            self.pending_jails.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        w.put_count(pending_jails.len());
        for a in pending_jails.iter() {
            w.put_addr(a);
        }
        let pending_unjails =
            self.pending_unjails.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        w.put_count(pending_unjails.len());
        for a in pending_unjails.iter() {
            w.put_addr(a);
        }
        // C9: pending governance endorsements — an action that has
        // accumulated votes but not yet reached quorum is
        // future-affecting state: two replicas must diverge if one
        // has recorded an endorsement the other has not.
        self.endorsements.write_canonical(w);
    }

    /// Commit consensus-adjacent state (C8): the scheduled halt,
    /// seen-evidence replay set, per-validator attendance rings,
    /// and the current height marker.
    fn commit_consensus_state(&self, w: &mut framework::CanonicalState) {
        match *self.scheduled_halt.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
            Some(h) => {
                w.put_u8(1).put_u64(h);
            }
            None => {
                w.put_u8(0);
            }
        }
        {
            let seen = self.seen_evidence.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(seen.len());
            for h in seen.iter() {
                w.put_root(h);
            }
            let attendance =
                self.attendance.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(attendance.len());
            for (a, ring) in attendance.iter() {
                w.put_addr(a).put_count(ring.len());
                for present in ring {
                    w.put_bool(*present);
                }
            }
        }
        w.put_u64(*self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        // ── Trailing section (v2): retired consensus keys ──
        // Evidence verification consults the retired set for
        // proofs spanning a key rotation — committed because two
        // replicas disagreeing on it disagree on whether a proof
        // verifies. Appended last so pre-upgrade blobs decode
        // with the empty-history default.
        {
            let retired =
                self.retired_bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            w.put_count(retired.len());
            for (a, keys) in retired.iter() {
                w.put_addr(a).put_count(keys.len());
                for k in keys {
                    w.put_bytes(k);
                }
            }
        }
    }

    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        self.commit_stake_state(w);
        self.commit_reward_state(w);
        self.commit_set_state(w);
        self.commit_consensus_state(w);
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema. Field
    /// order mirrors `commit_stake_state` → `commit_consensus_state`
    /// exactly.
    ///
    /// Beyond structural validity this enforces the *internal*
    /// invariants every live code path maintains (store mirror,
    /// index/total mirrors, pending-action membership). Those matter
    /// because the root check alone only proves the blob hashes to
    /// the claimed root — a crafted blob with a matching claimed root
    /// could otherwise install state no honest execution could
    /// produce.
    fn decode_committed(
        r: &mut framework::CanonicalReader<'_>,
        store: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Option<StagedStaking> {
        let mut staged = StagedStaking::default();
        Self::decode_stake_state(r, &mut staged)?;
        Self::decode_reward_state(r, &mut staged)?;
        Self::decode_set_state(r, &mut staged)?;
        Self::decode_consensus_state(r, &mut staged)?;
        Self::check_replica_mirrors(&staged)?;
        Self::check_store_binding(&staged, store)?;
        Some(staged)
    }

    /// Decode `validators`, `delegations`, and the `unbonding` queue —
    /// the mirror of [`Self::commit_stake_state`].
    fn decode_stake_state(
        r: &mut framework::CanonicalReader<'_>,
        out: &mut StagedStaking,
    ) -> Option<()> {
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            let stake = r.get_u64()?;
            if out.validators.insert(a, stake).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let d = r.get_addr()?;
            let v = r.get_addr()?;
            let amt = r.get_u64()?;
            // A delegation can only target a registered validator —
            // `delegate` requires membership and validator removal
            // drains every delegation into the unbonding queue.
            if !out.validators.contains_key(&v) {
                return None;
            }
            if out.delegations.insert((d, v), amt).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        // Order-preserving: the queue is FIFO by completion height;
        // `n.min(remaining/56)` bounds the allocation to what the
        // bytes could actually encode (each entry costs 56 bytes).
        out.unbonding.reserve(n.min(r.remaining() / 56));
        for _ in 0..n {
            out.unbonding.push(UnbondingEntry {
                delegator: r.get_addr()?,
                validator: r.get_addr()?,
                amount: r.get_u64()?,
                completion_height: r.get_u64()?,
            });
        }
        Some(())
    }

    /// Decode the reward-accrual bookkeeping — the mirror of
    /// [`Self::commit_reward_state`].
    fn decode_reward_state(
        r: &mut framework::CanonicalReader<'_>,
        out: &mut StagedStaking,
    ) -> Option<()> {
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            if out.pending_rewards.insert(a, r.get_u64()?).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            if out.reward_per_token.insert(a, r.get_u128()?).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let d = r.get_addr()?;
            let v = r.get_addr()?;
            if out.reward_debt.insert((d, v), r.get_u128()?).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            if out.self_debt.insert(a, r.get_u128()?).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let d = r.get_addr()?;
            let vn = r.get_count()?;
            let mut set = std::collections::BTreeSet::new();
            for _ in 0..vn {
                if !set.insert(r.get_addr()?) {
                    return None;
                }
            }
            if out.delegator_index.insert(d, set).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            if out.delegated_total.insert(a, r.get_u64()?).is_some() {
                return None;
            }
        }
        Some(())
    }

    /// Decode the validator-set transition state — the mirror of
    /// [`Self::commit_set_state`]. Membership in `out.validators` is
    /// enforced where the live paths require it.
    fn decode_set_state(
        r: &mut framework::CanonicalReader<'_>,
        out: &mut StagedStaking,
    ) -> Option<()> {
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            // `handle_key_change` requires the validator to exist.
            if !out.validators.contains_key(&a) {
                return None;
            }
            if out.pending_key_changes.insert(a, r.get_bytes()?.to_vec()).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        out.pending_validator_adds.reserve(n.min(r.remaining() / 20));
        for _ in 0..n {
            let a = r.get_addr()?;
            let key = r.get_bytes()?.to_vec();
            // `validate_add_action` seats the candidate in
            // `validators` (0 stake) and records its key in
            // `bls_keys` at quorum time — both must hold.
            if !out.validators.contains_key(&a) {
                return None;
            }
            out.pending_validator_adds.push((a, key));
        }
        let n = r.get_count()?;
        out.pending_validator_removes.reserve(n.min(r.remaining() / 20));
        for _ in 0..n {
            let a = r.get_addr()?;
            // Removal is only ever queued for a live member.
            if !out.validators.contains_key(&a) {
                return None;
            }
            out.pending_validator_removes.push(a);
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            let key = r.get_bytes()?.to_vec();
            // Consensus keys are fixed-size BLS12-381 compressed
            // public keys — every writer enforces 48 bytes.
            if key.len() != crypto::bls::PublicKey::LEN {
                return None;
            }
            if out.bls_keys.insert(a, key).is_some() {
                return None;
            }
        }
        for (a, key) in &out.pending_validator_adds {
            match out.bls_keys.get(a) {
                Some(k) if *k == *key => {}
                _ => return None,
            }
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            if out.jailed.insert(a, r.get_u64()?).is_some() {
                return None;
            }
        }
        let n = r.get_count()?;
        out.pending_jails.reserve(n.min(r.remaining() / 20));
        for _ in 0..n {
            out.pending_jails.push(r.get_addr()?);
        }
        let n = r.get_count()?;
        out.pending_unjails.reserve(n.min(r.remaining() / 20));
        for _ in 0..n {
            out.pending_unjails.push(r.get_addr()?);
        }
        out.endorsements = framework::Endorsements::read_canonical(r)?;
        Some(())
    }

    /// Decode consensus-adjacent state — the mirror of
    /// [`Self::commit_consensus_state`].
    fn decode_consensus_state(
        r: &mut framework::CanonicalReader<'_>,
        out: &mut StagedStaking,
    ) -> Option<()> {
        out.scheduled_halt = match r.get_u8()? {
            0 => None,
            1 => Some(r.get_u64()?),
            _ => return None,
        };
        let n = r.get_count()?;
        for _ in 0..n {
            if !out.seen_evidence.insert(r.get_root()?) {
                return None;
            }
        }
        let n = r.get_count()?;
        for _ in 0..n {
            let a = r.get_addr()?;
            let ring_len = r.get_count()?;
            let mut ring = std::collections::VecDeque::with_capacity(ring_len.min(r.remaining()));
            for _ in 0..ring_len {
                ring.push_back(r.get_bool()?);
            }
            if out.attendance.insert(a, ring).is_some() {
                return None;
            }
        }
        out.current_height = r.get_u64()?;
        // ── Trailing section (v2), tolerant of pre-upgrade blobs ──
        // Absent = the blob predates key-history retention: the
        // retired set decodes empty and evidence verifies only
        // against the live key — exactly the pre-upgrade bound.
        if r.remaining() != 0 {
            let n = r.get_count()?;
            for _ in 0..n {
                let a = r.get_addr()?;
                let kn = r.get_count()?;
                // Live code only writes non-empty lists bounded at
                // EVIDENCE_KEY_HISTORY — anything else is crafted.
                if kn == 0 || kn > EVIDENCE_KEY_HISTORY {
                    return None;
                }
                let mut keys = Vec::with_capacity(kn);
                for _ in 0..kn {
                    let k = r.get_bytes()?.to_vec();
                    if k.len() != crypto::bls::PublicKey::LEN {
                        return None;
                    }
                    keys.push(k);
                }
                if out.retired_bls_keys.insert(a, keys).is_some() {
                    return None;
                }
            }
        }
        Some(())
    }

    /// Enforce the replicated-state mirrors: `delegator_index` and
    /// `delegated_total` are maintained alongside `delegations` and
    /// must agree exactly — drift corrupts reward/delegation walks.
    fn check_replica_mirrors(staged: &StagedStaking) -> Option<()> {
        for (d, v) in staged.delegations.keys() {
            match staged.delegator_index.get(d) {
                Some(set) if set.contains(v) => {}
                _ => return None,
            }
        }
        for (d, set) in &staged.delegator_index {
            for v in set {
                if !staged.delegations.contains_key(&(*d, *v)) {
                    return None;
                }
            }
        }
        // `delegated_total[v]` is the sum of all delegations into
        // `v` — maintained on every delegate/undelegate/slash and
        // never re-derived, so it must match exactly.
        let mut totals = BTreeMap::<Address, u128>::new();
        for ((_, v), amt) in &staged.delegations {
            *totals.entry(*v).or_default() += u128::from(*amt);
        }
        for (v, expected) in &totals {
            if staged.delegated_total.get(v).copied().unwrap_or(0)
                != u64::try_from(*expected).ok()?
            {
                return None;
            }
        }
        for (v, total) in &staged.delegated_total {
            // Entries are removed with the validator; a total for an
            // unregistered address is dead state.
            if !staged.validators.contains_key(v) {
                return None;
            }
            if u128::from(*total) != *totals.get(v).unwrap_or(&0) {
                return None;
            }
        }
        Some(())
    }

    /// Enforce the KV-store mirror. The binding is intentionally
    /// asymmetric: `genesis_register_validator` never mirrors a
    /// validator's stake into the store, so a bare 20-byte store key
    /// must resolve to a live validator with the same stake, but a
    /// validator WITHOUT a store entry is legitimate (genesis-only,
    /// never delegated). `del/` entries are mirrored in both
    /// directions because every delegation mutation goes through
    /// `store_delegation_state`.
    fn check_store_binding(
        staged: &StagedStaking,
        store: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Option<()> {
        for ((d, v), amt) in &staged.delegations {
            let mut key = Vec::with_capacity(4 + 40);
            key.extend_from_slice(b"del/");
            key.extend_from_slice(&d.0);
            key.extend_from_slice(&v.0);
            match store.get(&key) {
                Some(val) if *val == amt.to_le_bytes() => {}
                _ => return None,
            }
        }
        for (key, val) in store {
            if let Some(rest) = key.strip_prefix(b"del/") {
                if rest.len() != 40 {
                    return None;
                }
                let d = Address(rest[..20].try_into().ok()?);
                let v = Address(rest[20..].try_into().ok()?);
                match staged.delegations.get(&(d, v)) {
                    Some(amt) if *val == amt.to_le_bytes() => {}
                    _ => return None,
                }
            } else {
                if key.len() != Address::LEN {
                    return None;
                }
                let v = Address(key.as_slice().try_into().ok()?);
                match staged.validators.get(&v) {
                    Some(stake) if *val == stake.to_le_bytes() => {}
                    _ => return None,
                }
            }
        }
        Some(())
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

    /// Take the ledger handle, failing closed when unwired.
    ///
    /// An unbacked delegation is an accounting hole — never run the
    /// debit path without a ledger.
    fn require_ledger(&self) -> Result<std::sync::Arc<dyn Balances + Send + Sync>, ExecError> {
        self.ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone().ok_or_else(
            || {
                ExecError::ModuleRejected(
                    "staking: balance ledger not wired (cannot settle delegation)".to_string(),
                )
            },
        )
    }

    /// Handle a delegate message: move `amount` from the sender's
    /// balance into the bonded pool and record the delegation.
    ///
    /// Invariants enforced (shared by the native and EVM-precompile
    /// paths — both call `handle`):
    /// - The validator must be registered (`genesis_register_validator`
    ///   or `VALIDATOR_ADD`); delegation to an unknown validator is
    ///   rejected rather than silently fabricating consensus stake.
    /// - The sender's balance must cover `amount` — the ledger's
    ///   `transfer` enforces this, so the EVM precompile cannot inflate
    ///   stake for free.
    fn handle_delegate(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let ledger = self.require_ledger()?;
        self.delegate_for(ctx.sender, validator, amount, ledger.as_ref())?;
        Ok(vec![Event { module: "staking", kind: "delegate", data: msg.to_vec() }])
    }

    /// Bond `amount` of `delegator`'s balance to `validator` through
    /// `ledger`.
    ///
    /// This is the shared core of [`handle_delegate`] and the EVM
    /// staking precompile: identical invariant enforcement regardless
    /// of which path the request arrives on. The delegator is debited
    /// into [`BONDED_POOL`]; the validator must be registered.
    ///
    /// The `ledger` is a parameter, not `self.ledger`, because the
    /// two call sites need *different* revert scopes: a native
    /// `delegate` tx settles against the block-undo'd account cache
    /// (the `EvmModule` impl), while the EVM precompile must move the
    /// bond through revm's journal so a reverting frame restores both
    /// balances — refunding in `undo_delegate` would then double-pay
    /// the pool.
    ///
    /// # Errors
    ///
    /// `ExecError::ModuleRejected` if the validator is unregistered,
    /// the transfer fails (insufficient balance), or stake/delegation
    /// arithmetic overflows.
    pub fn delegate_for(
        &self,
        delegator: Address,
        validator: Address,
        amount: u64,
        ledger: &dyn Balances,
    ) -> Result<(), ExecError> {
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
        ledger.transfer(&delegator, &BONDED_POOL, amount)?;

        let mut validators =
            self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        // Reward accounting must settle on the *pre-mutation*
        // position: the delegation earns rewards accrued while it
        // existed, and the validator's self-share shrinks as
        // `delegated_total` grows.
        let current_delegation = delegations.get(&(delegator, validator)).copied().unwrap_or(0);
        self.settle_delegation(delegator, validator, current_delegation);
        {
            let mut totals =
                self.delegated_total.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let stake_now = validators.get(&validator).copied().unwrap_or(0);
            let self_share =
                Self::self_share_of(stake_now, totals.get(&validator).copied().unwrap_or(0));
            self.settle_self_share(validator, self_share);
            *totals.entry(validator).or_insert(0) += amount;
        }
        self.delegator_index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(delegator)
            .or_default()
            .insert(validator);
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

    /// Reverse a [`delegate_for`]'s *record* — used by the EVM
    /// native journal when the calling frame reverts.
    ///
    /// Subtracts stake/delegation only. The bonded funds need no
    /// refund here: the precompile moved them through revm's journal,
    /// so `checkpoint_revert` already restored both balances before
    /// this undo runs. Refunding again would double-pay the pool.
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
            self.delegator_index
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_mut(&delegator)
                .map(|set| set.remove(&validator));
        }
        if let Some(t) = self
            .delegated_total
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&validator)
        {
            *t = t.saturating_sub(amount);
        }
        let stake = validators
            .get_mut(&validator)
            .ok_or(ExecError::ModuleRejected("undo_delegate: validator gone".to_string()))?;
        *stake -= amount;
        self.store_delegation_state(validator, delegator, *stake, new_delegation);
        Ok(())
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
        // Settle on the pre-mutation amounts: the full delegation
        // earned rewards up to now; the validator's self-share grows
        // as `delegated_total` shrinks.
        let old_delegation = *delegation;
        self.settle_delegation(delegator, validator, old_delegation);
        {
            let mut totals =
                self.delegated_total.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let stake_now = validators.get(&validator).copied().unwrap_or(0);
            let self_share =
                Self::self_share_of(stake_now, totals.get(&validator).copied().unwrap_or(0));
            self.settle_self_share(validator, self_share);
            if let Some(t) = totals.get_mut(&validator) {
                *t = t.saturating_sub(amount);
            }
        }
        *delegation -= amount;
        let new_delegation = *delegation;
        if new_delegation == 0 {
            delegations.remove(&(delegator, validator));
            self.delegator_index
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_mut(&delegator)
                .map(|set| set.remove(&validator));
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
        *self
            .delegated_total
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(validator)
            .or_insert(0) += amount;
        self.delegator_index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(delegator)
            .or_default()
            .insert(validator);
        self.store_delegation_state(validator, delegator, *stake, *delegation);
        Ok(())
    }

    /// Handle an undelegate message: start unbonding `amount` of the
    /// **sender's own** delegation to `validator`.
    ///
    /// The delegation is removed immediately (stake drops now) and the
    /// amount enters the unbonding queue; at `completion_height`
    /// `end_block` pays it out of the bonded pool to the delegator.
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

    /// Handle a slash message: reduce `validator`'s stake by `amount`.
    ///
    /// Arbitrary-amount slashing is a governance action — the tx
    /// endorses the exact `(validator, amount)` action, which
    /// applies only once endorsing power strictly exceeds
    /// two-thirds of the committee (C9: a single signer's command
    /// is not committee authorization). The permissionless path is
    /// [`msg_type::EVIDENCE`], which authenticates itself with the
    /// proof it carries.
    fn handle_slash(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // The action must name a live validator before it can
        // collect endorsements — slashing an unknown address is
        // never meaningful.
        if !self
            .validators
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&validator)
        {
            return Err(ExecError::ModuleRejected("slash: validator not found".to_string()));
        }
        match self.endorsements.record(msg, &ctx.sender, self)? {
            framework::EndorsementOutcome::Pending { .. } => {
                Ok(vec![Event { module: "staking", kind: "slash_endorse", data: msg.to_vec() }])
            }
            framework::EndorsementOutcome::Quorum => {
                let events = self.apply_slash(validator, amount, msg)?;
                // A slash that zeroed the target's stake can kill
                // pending removes whose "last powered member" guard
                // now fails — reclaim dead endorsement slots.
                self.sweep_dead_actions();
                Ok(events)
            }
        }
    }

    /// Reduce `validator`'s stake by `amount`, burning the same
    /// proportion from every delegation to it.
    ///
    /// Slashing must hit the delegations, not just the aggregate —
    /// otherwise the bonded pool still owes the full pre-slash amount
    /// (a slash would effectively refund itself on unbond). Each
    /// delegation loses `floor(amount · delegation / stake)`; the
    /// rounding remainder is distributed 1 unit per delegation in
    /// deterministic `(delegator, validator)` order so all replicas
    /// slash identically.
    ///
    /// Shared by `handle_slash` (committee governance) and
    /// `handle_evidence` (permissionless, proof-authenticated).
    fn apply_slash(
        &self,
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

        // Reward accounting settles on the pre-slash positions: every
        // delegation earned its accrued share while it existed, and
        // the self-share settles before it shrinks. (Slash must not
        // confiscate already-earned rewards.)
        {
            let totals =
                self.delegated_total.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let self_share =
                Self::self_share_of(stake_before, totals.get(&validator).copied().unwrap_or(0));
            drop(totals);
            self.settle_self_share(validator, self_share);
            for ((d, v), a) in delegations.range(..).filter(|((_, v), _)| *v == validator) {
                self.settle_delegation(*d, *v, *a);
            }
        }

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
                    self.delegator_index
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get_mut(&d)
                        .map(|set| set.remove(&validator));
                } else {
                    delegations.insert((d, validator), a);
                }
                self.store_delegation_state(validator, d, new_stake, a);
            }
            if let Some(t) = self
                .delegated_total
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_mut(&validator)
            {
                *t = t.saturating_sub(applied);
            }
            burned_from_pool = applied;
        }
        drop(delegations);
        drop(validators);

        // Burn only the amount removed from pool-backed delegations —
        // unattributed stake (genesis self-stake) was never in the
        // pool, so burning it would overdraw.
        if burned_from_pool > 0 {
            if let Some(ledger) =
                self.ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
            {
                // Burn = debit the pool with no credit — supply
                // shrinks (Ethereum burn semantics; cleaner than
                // accumulating at the zero address).
                let _ = ledger.debit(&BONDED_POOL, burned_from_pool);
            }
        }

        Ok(vec![Event { module: "staking", kind: "slash", data: msg.to_vec() }])
    }

    /// Handle a double-sign evidence message:
    /// `[type: 0x08][validator: 20B][view: 8B][phase: 1B][epoch: 8B]`
    /// `[hash_a: 32B][sig_a: 96B][hash_b: 32B][sig_b: 96B]`.
    ///
    /// Permissionless — anyone may submit; the two BLS signatures
    /// are the authentication. Each is verified against ANY key the
    /// validator holds in `bls_keys` ∪ `retired_bls_keys` over the
    /// exact `vote_signing_message` layout the engine signs
    /// (`view LE | phase | block_hash | epoch LE`, `Domain::Vote`):
    /// a forged or misattributed proof fails verification and the
    /// reporter loses only their envelope fee. Retired-key coverage
    /// means a proof stays valid across a rotation — an offender
    /// cannot rotate away from evidence of its own offense.
    ///
    /// The replay guard keys on the CANONICAL OFFENSE —
    /// `(validator, view, phase, epoch)` — so penalties are per
    /// offense, not per payload: the same equivocation resubmitted
    /// with the votes swapped, or proven by a different conflicting
    /// pair at the same position, is a replay, not a second slash.
    ///
    /// On a valid proof: the offender is slashed
    /// [`double_sign_slash_amount`](msg::double_sign_slash_amount)
    /// (10%) and jailed — emitted as a `removes` entry at the next
    /// epoch rotation via `take_validator_changes`.
    fn handle_evidence(
        &self,
        _ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        if msg.len() != 21 + EVIDENCE_PAYLOAD_LEN {
            return Err(ExecError::ModuleRejected(format!(
                "evidence: expected {}-byte message, got {} bytes",
                21 + EVIDENCE_PAYLOAD_LEN,
                msg.len()
            )));
        }
        let view = u64::from_le_bytes(msg[21..29].try_into().map_err(|_| ExecError::Malformed)?);
        let phase = msg[29];
        let epoch = u64::from_le_bytes(msg[30..38].try_into().map_err(|_| ExecError::Malformed)?);
        let hash_a = &msg[38..70];
        let hash_b = &msg[166..198];
        // Equivocation is two votes for *different* blocks at the
        // same (view, phase, epoch). Identical hashes are just one
        // vote presented twice — no fault.
        if hash_a == hash_b {
            return Err(ExecError::ModuleRejected(
                "evidence: identical block hashes — no equivocation".to_string(),
            ));
        }
        let sig_a =
            crypto::bls::Signature::from_slice(&msg[70..166]).map_err(|_| ExecError::Malformed)?;
        let sig_b =
            crypto::bls::Signature::from_slice(&msg[198..294]).map_err(|_| ExecError::Malformed)?;

        // Candidate verification keys: the validator's CURRENT
        // consensus key plus its bounded retired history — evidence
        // can span a key rotation (the offense predates it), so
        // every key the validator has held inside the evidence
        // window is tried. A signature that verifies under ANY of
        // the validator's own keys is a real signature by that
        // validator — BLS unforgeability makes a foreign key's
        // signature impossible to fake.
        let mut candidates: Vec<Vec<u8>> = Vec::new();
        {
            let bls_keys = self.bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(k) = bls_keys.get(&validator) {
                candidates.push(k.clone());
            }
        }
        {
            let retired =
                self.retired_bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(keys) = retired.get(&validator) {
                candidates.extend(keys.iter().cloned());
            }
        }
        if candidates.is_empty() {
            return Err(ExecError::ModuleRejected(
                "evidence: no consensus key on record for validator".to_string(),
            ));
        }

        // Replay guard keyed by the CANONICAL OFFENSE IDENTITY —
        // `(validator, view, phase, epoch)` — not the raw payload.
        // Penalties are per offense: the same equivocation proven
        // by the swapped pair, or by a different conflicting pair
        // at the same position, is one offense and one penalty.
        // The v1 key hashed the ordered payload bytes, so a
        // resubmission with the votes swapped produced a fresh
        // identity and slashed a second time.
        let mut offense = Vec::with_capacity(37);
        offense.extend_from_slice(&validator.0);
        offense.extend_from_slice(&view.to_le_bytes());
        offense.push(phase);
        offense.extend_from_slice(&epoch.to_le_bytes());
        let offense_id = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Vote, &offense);
        {
            let seen = self.seen_evidence.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if seen.contains(&offense_id) {
                return Err(ExecError::ModuleRejected("evidence: already applied".to_string()));
            }
        }

        // Rebuild the exact 49-byte signing messages and verify
        // both signatures — a valid proof is two verifying
        // signatures over different block hashes. Each signature
        // is checked against every candidate independently: the
        // votes were cast at the same view, but a rotation mid-way
        // could in principle split them across keys, and the
        // offense is the validator signing conflicting votes
        // regardless of which of its keys signed which.
        let mut vote_msg_a = [0u8; 49];
        vote_msg_a[..8].copy_from_slice(&view.to_le_bytes());
        vote_msg_a[8] = phase;
        vote_msg_a[9..41].copy_from_slice(hash_a);
        vote_msg_a[41..49].copy_from_slice(&epoch.to_le_bytes());
        let mut vote_msg_b = [0u8; 49];
        vote_msg_b[..8].copy_from_slice(&view.to_le_bytes());
        vote_msg_b[8] = phase;
        vote_msg_b[9..41].copy_from_slice(hash_b);
        vote_msg_b[41..49].copy_from_slice(&epoch.to_le_bytes());
        let verifies = |sig: &crypto::bls::Signature, vote_msg: &[u8; 49]| {
            candidates.iter().any(|key| {
                crypto::bls::PublicKey::from_slice(key).is_ok_and(|pk| {
                    crypto::bls_signer::verify(sig, crypto::hash::Domain::Vote, vote_msg, &pk)
                        .is_ok()
                })
            })
        };
        if !verifies(&sig_a, &vote_msg_a) || !verifies(&sig_b, &vote_msg_b) {
            return Err(ExecError::ModuleRejected(
                "evidence: signature verification failed".to_string(),
            ));
        }

        // Proof verified — slash and jail. `apply_slash` resolves
        // "validator not found" with the same rejection it already
        // produces.
        let slash_amount = msg::double_sign_slash_amount(self.stake(&validator));
        let mut events = self.apply_slash(validator, slash_amount, msg)?;

        let height = *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let already_jailed = self
            .jailed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(validator, height)
            .is_some();
        if !already_jailed {
            self.pending_jails
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(validator);
        }
        self.seen_evidence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(offense_id);

        events.push(Event { module: "staking", kind: "evidence", data: msg.to_vec() });
        Ok(events)
    }

    /// Handle an unjail message: `[type: 0x09][validator: 20B]`.
    ///
    /// Re-admits a jailed validator to the set at the next epoch
    /// rotation. Sender must be the validator itself (same
    /// authorization model as `key_change`), the jail must have
    /// lasted at least [`MIN_JAIL_BLOCKS`], and the validator must
    /// still have stake and a consensus key on record — the engine
    /// cannot re-admit a keyless validator.
    fn handle_unjail(
        &self,
        ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        if ctx.sender != validator {
            return Err(ExecError::ModuleRejected(
                "unjail: only the validator can unjail itself".to_string(),
            ));
        }
        let jailed_at = self
            .jailed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&validator)
            .copied()
            .ok_or(ExecError::ModuleRejected("unjail: validator is not jailed".to_string()))?;
        let height = *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if height.saturating_sub(jailed_at) < MIN_JAIL_BLOCKS {
            return Err(ExecError::ModuleRejected(format!(
                "unjail: {MIN_JAIL_BLOCKS}-block jail period not elapsed"
            )));
        }
        if self.stake(&validator) == 0 {
            return Err(ExecError::ModuleRejected("unjail: validator has no stake".to_string()));
        }
        if !self
            .bls_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&validator)
        {
            return Err(ExecError::ModuleRejected(
                "unjail: no consensus key on record".to_string(),
            ));
        }

        self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&validator);
        self.pending_unjails
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(validator);

        Ok(vec![Event { module: "staking", kind: "unjail", data: msg.to_vec() }])
    }

    /// Handle a schedule-halt message:
    /// `[type: 0x0A][validator: 20B][halt_height: 8B LE]`.
    ///
    /// Committee-quorum endorsement — coordinating an upgrade halt
    /// is a validator-set decision no single member may take. The
    /// endorsed action is `(SCHEDULE_HALT, halt_height)`: the
    /// `validator` field is only the message header's uniform
    /// address slot (the real sender is `ctx.sender`), so it does
    /// not participate in the action's identity.
    /// `halt_height` must be in the future (a past/present halt
    /// freezes immediately, which governance cannot intend
    /// mid-block); `0` clears the schedule.
    fn handle_schedule_halt(
        &self,
        ctx: &TxContext,
        _validator: Address,
        halt_height: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        let current =
            *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if halt_height != 0 && halt_height <= current {
            return Err(ExecError::ModuleRejected(format!(
                "schedule_halt: height {halt_height} is not in the future (current {current})"
            )));
        }
        // Action identity = the type tag + the target height. A
        // stale-height action can still reach quorum after the tip
        // passes it, so the future check is re-evaluated at apply
        // time below.
        let mut action = Vec::with_capacity(9);
        action.push(msg_type::SCHEDULE_HALT);
        action.extend_from_slice(&halt_height.to_le_bytes());
        match self.endorsements.record(&action, &ctx.sender, self)? {
            framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                module: "staking",
                kind: "schedule_halt_endorse",
                data: msg.to_vec(),
            }]),
            framework::EndorsementOutcome::Quorum => {
                let now =
                    *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let events = if halt_height != 0 && halt_height <= now {
                    vec![Event {
                        module: "staking",
                        kind: "schedule_halt_stale",
                        data: msg.to_vec(),
                    }]
                } else {
                    *self
                        .scheduled_halt
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        if halt_height == 0 { None } else { Some(halt_height) };
                    vec![Event { module: "staking", kind: "schedule_halt", data: msg.to_vec() }]
                };
                // Applying (or passing) a halt height kills pending
                // halt entries for heights the tip has passed.
                self.sweep_dead_actions();
                Ok(events)
            }
        }
    }

    /// Handle a claim-reward message: withdraw accumulated rewards.
    ///
    /// If `amount` is 0, all accumulated rewards are claimed.
    /// Otherwise, up to `amount` rewards are claimed.
    ///
    /// The claimed amount is paid out of [`REWARD_POOL`] — the pool
    /// `end_block` funds with swept fees + issuance — so a claim is
    /// a transfer, never new minting at claim time. Validators claim
    /// their self-share; delegators claim their share of every
    /// delegation they hold.
    fn handle_claim_reward(
        &self,
        ctx: &TxContext,
        validator: Address,
        amount: u64,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // An account claims only its own rewards — the pending
        // ledger is a claimable balance, not a public pool. (Matches
        // the key_change authorization model.) The `validator` field
        // is the *claimer* — delegators pass their own address.
        if ctx.sender != validator {
            return Err(ExecError::ModuleRejected(
                "claim_reward: only the account can claim its rewards".to_string(),
            ));
        }
        let ledger = self.require_ledger().map_err(|_| {
            ExecError::ModuleRejected("claim_reward: balance ledger not wired".to_string())
        })?;

        // Lazy accrual: settle every position the claimer holds so
        // `pending_rewards` reflects rewards through the last
        // `end_block` — delegations via `reward_debt`, self-share
        // via `self_debt`.
        self.settle_all(validator);

        let claim_amount = {
            let mut pending =
                self.pending_rewards.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let accumulated = pending.get(&validator).copied().unwrap_or(0);
            let claim_amount = if amount == 0 { accumulated } else { amount.min(accumulated) };
            if claim_amount == 0 {
                return Err(ExecError::ModuleRejected(
                    "claim_reward: no rewards to claim".to_string(),
                ));
            }
            *pending.entry(validator).or_insert(0) -= claim_amount;
            claim_amount
        };

        // Pay from the reward pool: pending_rewards only grows by
        // what `end_block` funded into the pool, so the transfer
        // cannot overdraw. Failure leaves `pending` decremented —
        // acceptable because the pool-conservation invariant makes
        // it unreachable; a poisoned ledger would have failed the
        // block earlier.
        ledger
            .transfer(&REWARD_POOL, &validator, claim_amount)
            .map_err(|_| ExecError::ModuleRejected("claim_reward: pool underfunded".to_string()))?;

        Ok(vec![Event { module: "staking", kind: "claim_reward", data: msg.to_vec() }])
    }

    /// Handle a key-change message: record a new BLS consensus key
    /// for `validator`.
    ///
    /// The message format is
    /// `[type: 0x05][validator: 20B][new_key: 48B][pop: 96B]`.
    /// The new key takes effect at the next epoch rotation — the
    /// consensus engine reads pending changes via `take_key_changes`.
    ///
    /// Only the validator itself can change its key (checked via
    /// `ctx.sender`). The sender must be the validator address.
    ///
    /// `pop` is a proof-of-possession for `new_key` — mandatory
    /// because QC verification uses `fast_aggregate_verify`, which is
    /// forgeable unless every signer key proves possession at
    /// admission (rogue-key attack). A key that cannot produce a `PoP`
    /// cannot enter the validator set.
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
        // The new key is a 48-byte BLS12-381 compressed public key,
        // followed by its 96-byte proof-of-possession.
        if msg.len() != 21 + 48 + 96 {
            return Err(ExecError::ModuleRejected(format!(
                "key_change: expected 144-byte key+pop, got {} bytes",
                msg.len().saturating_sub(21)
            )));
        }
        let new_key = msg[21..69].to_vec();
        Self::verify_key_pop(&new_key, &msg[69..165], "key_change")?;
        // A consensus key identifies exactly one staking address —
        // rotating to a key another member already holds would
        // collide identities at the rotation's duplicate check
        // (same gate `validator_add` applies at admission).
        if self
            .bls_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|(a, k)| *a != validator && *k == new_key)
        {
            return Err(ExecError::ModuleRejected(
                "key_change: consensus key already in use".to_string(),
            ));
        }
        drop(validators); // release lock before acquiring pending_key_changes

        self.pending_key_changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(validator, new_key);

        Ok(vec![Event { module: "staking", kind: "key_change", data: msg.to_vec() }])
    }

    /// Verify a BLS proof-of-possession for a consensus key being
    /// admitted (`validator_add` or `key_change`).
    ///
    /// `PoP` admission is the precondition that makes
    /// `fast_aggregate_verify` safe for same-message QC aggregation:
    /// a rogue key — a public key crafted as a linear combination of
    /// honest keys so an attacker's lone signature verifies as a
    /// quorum aggregate — cannot produce `Sign(sk_rogue, pk)` because
    /// its discrete log is unknowable. Requiring the `PoP` here means
    /// every key that reaches `ValidatorSet` is a real key the
    /// presenter controls, not an algebraic forgery.
    ///
    /// # Errors
    /// `ExecError::ModuleRejected` if `key` is not a 48-byte
    /// compressed public key, `pop` is not a 96-byte signature, or
    /// the `PoP` fails verification.
    fn verify_key_pop(key: &[u8], pop: &[u8], op: &str) -> Result<(), ExecError> {
        let pk = crypto::bls::PublicKey::from_slice(key)
            .map_err(|_| ExecError::ModuleRejected(format!("{op}: malformed BLS public key")))?;
        let pop_sig = crypto::bls::Signature::from_slice(pop)
            .map_err(|_| ExecError::ModuleRejected(format!("{op}: malformed PoP signature")))?;
        crypto::bls_signer::pop_verify(&pk, &pop_sig).map_err(|_| {
            ExecError::ModuleRejected(format!("{op}: proof-of-possession verification failed"))
        })
    }

    /// Handle a validator-add message:
    /// `[type: 0x06][new_validator: 20B][bls_key: 48B][pop: 96B]`.
    ///
    /// The message is a committee *endorsement* of the exact
    /// `(new_validator, bls_key)` action: the sender must carry
    /// committee voting power, and the admission applies only once
    /// cumulative endorsing power strictly exceeds two-thirds of
    /// the committee — the same quorum a consensus QC requires
    /// (C9: consensus on inclusion is not governance
    /// authorization).
    ///
    /// Admission registers the candidate with **zero** stake — it
    /// declares membership, not collateral. Delegations bond real
    /// balance to the candidate, and the rotation seats it only if
    /// bonded stake exists at the epoch boundary; the activation
    /// stake is whatever the ledger proves, never anything the add
    /// message claimed.
    ///
    /// # Errors
    ///
    /// - `ModuleRejected` if the sender has no committee voting
    ///   power (not a member, jailed, pending, or unbonded).
    /// - `ModuleRejected` if the candidate is already registered,
    ///   already pending, or its BLS key is already in use.
    /// - `ModuleRejected` if the message is malformed or the `PoP`
    ///   does not verify.
    fn handle_validator_add(
        &self,
        ctx: &TxContext,
        new_validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        // Parse [bls_key: 48B][pop: 96B] after the validator field.
        // The PoP is verified BEFORE an endorsement is recorded —
        // endorsements only accumulate for actions that could
        // apply, and a consensus key that cannot prove possession
        // must never reach the ValidatorSet (rogue-key
        // aggregate-forgery defense).
        if msg.len() != 21 + 48 + 96 {
            return Err(ExecError::ModuleRejected(format!(
                "validator_add: expected 165-byte message, got {} bytes",
                msg.len()
            )));
        }
        let bls_key = msg[21..69].to_vec();
        Self::verify_key_pop(&bls_key, &msg[69..165], "validator_add")?;

        // Validate the action before recording: the candidate must
        // not already be registered or pending, and its consensus
        // key must not duplicate another member's (a BLS key
        // identifies exactly one staking address — the same
        // duplicate-identity check `ValidatorSet` enforces at
        // rotation, applied early so doomed actions never collect
        // endorsements).
        self.validate_add_action(&new_validator, &bls_key)?;

        // The endorsement binds the action payload — type +
        // address + key (the PoP is a proof, not part of the
        // action's identity: two different proofs for the same key
        // endorse the same action).
        match self.endorsements.record(&msg[..69], &ctx.sender, self)? {
            framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                module: "staking",
                kind: "validator_add_endorse",
                data: msg.to_vec(),
            }]),
            framework::EndorsementOutcome::Quorum => {
                // Re-validate at apply time — the set may have
                // changed since the first endorsement (a different
                // action may have registered the address or key).
                let events = if self.validate_add_action(&new_validator, &bls_key).is_err() {
                    vec![Event {
                        module: "staking",
                        kind: "validator_add_stale",
                        data: msg.to_vec(),
                    }]
                } else {
                    self.validators
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(new_validator, 0);
                    // Record the consensus key immediately — evidence
                    // submitted before the rotation still needs it
                    // for verification. A re-admission overwrites
                    // the previous live key — retire it rather
                    // than dropping the one a pending proof needs.
                    let displaced = self
                        .bls_keys
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(new_validator, bls_key.clone());
                    if let Some(old) = displaced {
                        if old != bls_key {
                            self.retire_key(new_validator, old);
                        }
                    }
                    self.pending_validator_adds
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((new_validator, bls_key));
                    vec![Event { module: "staking", kind: "validator_add", data: msg.to_vec() }]
                };
                // Registering the candidate killed every other
                // pending "admit this address" variant — reclaim
                // their endorsement slots before they leak.
                self.sweep_dead_actions();
                Ok(events)
            }
        }
    }

    /// Check that `(candidate, key)` may be admitted: not already
    /// registered, not already pending, and the key not in use by
    /// another address. Runs both before an endorsement is
    /// recorded and again when the action reaches quorum — the
    /// committee may have changed in between.
    fn validate_add_action(&self, candidate: &Address, key: &[u8]) -> Result<(), ExecError> {
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if validators.contains_key(candidate) {
            return Err(ExecError::ModuleRejected(
                "validator_add: validator already exists".to_string(),
            ));
        }
        let pending_adds =
            self.pending_validator_adds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending_adds.iter().any(|(a, _)| a == candidate) {
            return Err(ExecError::ModuleRejected(
                "validator_add: validator already pending".to_string(),
            ));
        }
        let bls_keys = self.bls_keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if bls_keys.iter().any(|(a, k)| a != candidate && k == key) {
            return Err(ExecError::ModuleRejected(
                "validator_add: consensus key already in use".to_string(),
            ));
        }
        Ok(())
    }

    /// Handle a validator-remove message: `[type: 0x07][validator: 20B]`.
    ///
    /// Committee-quorum endorsement, same model as
    /// `validator_add`: the remove applies only once endorsing
    /// power strictly exceeds two-thirds. Removing a
    /// quorum-admitted candidate that has not seated yet cancels
    /// its admission outright; removing an active member queues it
    /// for the next epoch rotation, where its stake enters
    /// unbonding.
    ///
    /// # Errors
    ///
    /// - `ModuleRejected` if the sender has no committee voting
    ///   power.
    /// - `ModuleRejected` if the validator is not registered or is
    ///   already pending removal.
    /// - `ModuleRejected` if removing this validator would leave
    ///   the set without powered members.
    fn handle_validator_remove(
        &self,
        ctx: &TxContext,
        validator: Address,
        msg: &[u8],
    ) -> Result<Vec<Event>, ExecError> {
        self.validate_remove_action(&validator)?;

        match self.endorsements.record(msg, &ctx.sender, self)? {
            framework::EndorsementOutcome::Pending { .. } => Ok(vec![Event {
                module: "staking",
                kind: "validator_remove_endorse",
                data: msg.to_vec(),
            }]),
            framework::EndorsementOutcome::Quorum => {
                let events = if self.validate_remove_action(&validator).is_err() {
                    vec![Event {
                        module: "staking",
                        kind: "validator_remove_stale",
                        data: msg.to_vec(),
                    }]
                } else {
                    self.apply_validator_remove(&validator);
                    vec![Event { module: "staking", kind: "validator_remove", data: msg.to_vec() }]
                };
                // Removing the target killed pending actions aimed
                // at it (e.g. a queued slash or remove variant) —
                // reclaim their endorsement slots.
                self.sweep_dead_actions();
                Ok(events)
            }
        }
    }

    /// Check that `validator` may be removed right now — run before
    /// an endorsement is recorded and again at quorum.
    fn validate_remove_action(&self, validator: &Address) -> Result<(), ExecError> {
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !validators.contains_key(validator) {
            return Err(ExecError::ModuleRejected(
                "validator_remove: validator not found".to_string(),
            ));
        }
        let pending_removes = self
            .pending_validator_removes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending_removes.contains(validator) {
            return Err(ExecError::ModuleRejected(
                "validator_remove: validator already pending removal".to_string(),
            ));
        }
        // A pending-add candidate is removable — the remove cancels
        // the admission — so the "last validator" guard only applies
        // to powered members. Count powered members not already
        // queued for removal: removing the last one would leave the
        // chain with no committee.
        let jailed = self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let staying_powered = validators
            .iter()
            .filter(|(a, s)| **s > 0 && !pending_removes.contains(*a) && !jailed.contains_key(*a))
            .count();
        if staying_powered <= 1
            && self
                .pending_validator_adds
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .all(|(a, _)| a != validator)
        {
            return Err(ExecError::ModuleRejected(
                "validator_remove: cannot remove last powered validator".to_string(),
            ));
        }
        Ok(())
    }

    /// Apply a quorum-authorized removal: cancel a pending
    /// admission outright, or queue an active member for the next
    /// epoch rotation.
    fn apply_validator_remove(&self, validator: &Address) {
        let mut pending_adds =
            self.pending_validator_adds.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pos) = pending_adds.iter().position(|(a, _)| a == validator) {
            pending_adds.remove(pos);
            drop(pending_adds);
            self.cancel_pending_add(validator);
            return;
        }
        drop(pending_adds);
        self.pending_validator_removes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(*validator);
    }

    /// Unwind a pending-add candidate that never seated: drop the
    /// registration and key, and move every delegation into
    /// unbonding so delegators recover their collateral after the
    /// period — the bonded pool pays out at `end_block` exactly as
    /// for a normal undelegation. Bonded admission (C9) lets real
    /// collateral accumulate while a candidate waits to seat, so
    /// cancelling is NOT the no-op it was when adds carried only a
    /// declared amount. Reward settlement is unnecessary: a pending
    /// candidate never entered the consensus set, so it accrued
    /// nothing.
    fn cancel_pending_add(&self, validator: &Address) {
        let current =
            *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let completion = current.saturating_add(self.unbonding_period);
        let mut delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let affected: Vec<(Address, u64)> = delegations
            .iter()
            .filter(|((_, v), _)| v == validator)
            .map(|((d, _), amount)| (*d, *amount))
            .collect();
        {
            let mut unbonding =
                self.unbonding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut delegator_index =
                self.delegator_index.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            for (delegator, amount) in &affected {
                delegations.remove(&(*delegator, *validator));
                if let Some(set) = delegator_index.get_mut(delegator) {
                    set.remove(validator);
                }
                unbonding.push(UnbondingEntry {
                    delegator: *delegator,
                    validator: *validator,
                    amount: *amount,
                    completion_height: completion,
                });
            }
        }
        self.delegated_total
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(validator);
        self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(validator);
        // Retire rather than drop: the cancelled candidate's key
        // never went live, but a previous incarnation's key may be
        // what this entry held — the uniform retire rule applies.
        let removed_key = self
            .bls_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(validator);
        if let Some(old) = removed_key {
            self.retire_key(*validator, old);
        }
        // Clear the store mirror so queries cannot report a phantom
        // stake or delegation for the cancelled candidate.
        {
            let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            store.remove(&validator.0.to_vec());
            for (delegator, _) in &affected {
                let mut key = Vec::with_capacity(4 + 40);
                key.extend_from_slice(b"del/");
                key.extend_from_slice(&delegator.0);
                key.extend_from_slice(&validator.0);
                store.remove(&key);
            }
        }
    }

    /// Drop pending endorsements for actions that can never apply.
    ///
    /// Called after every quorum — the authorized state change can
    /// kill sibling actions: admitting validator X makes every
    /// other pending "admit X" variant permanently invalid, and a
    /// scheduled halt whose height the tip passes can never fire.
    /// Record-time validation already rejects *new* endorsements
    /// of dead actions, but the frozen entry would otherwise occupy
    /// the bounded [`framework::MAX_PENDING_ACTIONS`] set forever:
    /// unable to collect another endorsement, it can never reach
    /// quorum and be consumed. Governance txs are rare, so the
    /// O(pending) sweep is cheap insurance against cap exhaustion.
    fn sweep_dead_actions(&self) {
        self.endorsements.retain(|action| self.is_action_live(action));
    }

    /// `true` while `action` could still apply — the same checks the
    /// handlers run before recording an endorsement, reused so the
    /// sweep drops exactly the actions the record path would reject
    /// forever.
    fn is_action_live(&self, action: &[u8]) -> bool {
        match action.first() {
            // [type][validator: 20B][bls_key: 48B] — dead once the
            // address is registered/pending or the key is taken.
            Some(&msg_type::VALIDATOR_ADD) => {
                if action.len() != 1 + 20 + 48 {
                    return false;
                }
                let Ok(addr) = <[u8; 20]>::try_from(&action[1..21]) else { return false };
                self.validate_add_action(&Address(addr), &action[21..69]).is_ok()
            }
            // [type][validator: 20B] — dead once the target is
            // unremovable (gone, already queued, or last powered
            // member). "Last member" is transient — a later add
            // could re-enable removal — but dropping a dead entry
            // only forces re-endorsement, never a wrong apply.
            Some(&msg_type::VALIDATOR_REMOVE) => {
                if action.len() != 1 + 20 {
                    return false;
                }
                let Ok(addr) = <[u8; 20]>::try_from(&action[1..21]) else { return false };
                self.validate_remove_action(&Address(addr)).is_ok()
            }
            // [type][validator: 20B][amount: 8B] — dead once the
            // target is no longer registered.
            Some(&msg_type::SLASH) => {
                if action.len() != 1 + 20 + 8 {
                    return false;
                }
                let Ok(addr) = <[u8; 20]>::try_from(&action[1..21]) else { return false };
                self.validators
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains_key(&Address(addr))
            }
            // [type][height: 8B] — dead once the tip passes the
            // target height (height 0 = "cancel halt" never dies).
            Some(&msg_type::SCHEDULE_HALT) => {
                if action.len() != 1 + 8 {
                    return false;
                }
                let Ok(bits) = <[u8; 8]>::try_from(&action[1..9]) else { return false };
                let halt = u64::from_le_bytes(bits);
                let current =
                    *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                halt == 0 || halt > current
            }
            // Unknown payloads are kept — conservatively assume a
            // future action type rather than silently dropping
            // state a replica expects to reach quorum.
            _ => true,
        }
    }

    /// The validator's self-share: bonded stake not attributable to
    /// any delegation record (genesis self-stake, validator-add
    /// stake). Accrues rewards to the validator through `self_debt`.
    ///
    /// Callers must hold `validators` and `delegated_total` (or pass
    /// the values in) — lock order is `validators → delegated_total
    /// → reward_per_token → reward_debt/self_debt → pending_rewards`.
    fn self_share_of(stake: u64, delegated_total: u64) -> u64 {
        stake.saturating_sub(delegated_total)
    }

    /// Settle one delegation position: move accrued rewards into
    /// `pending_rewards[delegator]` and stamp the debt at the
    /// current `reward_per_token`. Must run BEFORE the delegation
    /// amount changes — the accrual is a function of the position
    /// that existed while rewards were distributed.
    ///
    /// Lock order: callers may hold `validators`/`delegations`;
    /// this only takes `reward_per_token`, `reward_debt`,
    /// `pending_rewards` — always in that order.
    fn settle_delegation(&self, delegator: Address, validator: Address, delegation: u64) {
        let rpt = *self
            .reward_per_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&validator)
            .unwrap_or(&0);
        let mut debts = self.reward_debt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let debt = debts.entry((delegator, validator)).or_insert(0);
        if rpt > *debt && delegation > 0 {
            let accrued = u128::from(delegation).saturating_mul(rpt - *debt) / RPT_SCALE;
            if accrued > 0 {
                let mut pending =
                    self.pending_rewards.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let current = pending.get(&delegator).copied().unwrap_or(0);
                pending.insert(
                    delegator,
                    current.saturating_add(u64::try_from(accrued).unwrap_or(u64::MAX)),
                );
            }
        }
        *debt = rpt;
    }

    /// Settle a validator's self-share position into
    /// `pending_rewards[validator]`. Same settle-before-mutate rule
    /// as [`Self::settle_delegation`].
    fn settle_self_share(&self, validator: Address, self_share: u64) {
        let rpt = *self
            .reward_per_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&validator)
            .unwrap_or(&0);
        let mut debts = self.self_debt.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let debt = debts.entry(validator).or_insert(0);
        if rpt > *debt && self_share > 0 {
            let accrued = u128::from(self_share).saturating_mul(rpt - *debt) / RPT_SCALE;
            if accrued > 0 {
                let mut pending =
                    self.pending_rewards.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let current = pending.get(&validator).copied().unwrap_or(0);
                pending.insert(
                    validator,
                    current.saturating_add(u64::try_from(accrued).unwrap_or(u64::MAX)),
                );
            }
        }
        *debt = rpt;
    }

    /// Settle every position an account holds — all delegations in
    /// `delegator_index[account]` plus the self-share if the account
    /// is a registered validator. Called by `claim_reward`.
    fn settle_all(&self, account: Address) {
        let delegator_vs: Vec<Address> = self
            .delegator_index
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&account)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        let delegations =
            self.delegations.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for v in delegator_vs {
            let amount = delegations.get(&(account, v)).copied().unwrap_or(0);
            self.settle_delegation(account, v, amount);
        }
        drop(delegations);
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(&stake) = validators.get(&account) {
            let delegated =
                self.delegated_total.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let self_share =
                Self::self_share_of(stake, delegated.get(&account).copied().unwrap_or(0));
            self.settle_self_share(account, self_share);
        }
    }

    /// Sweep collected fees into [`REWARD_POOL`] and mint the block
    /// issuance, returning the total reward for this block.
    ///
    /// The fee component is a *transfer* (real, pre-collected funds
    /// in [`FEE_POOL`]); the issuance component is a *mint* (new
    /// supply authorized by the reward schedule). Both land in the
    /// reward pool so claims are always pool-funded — a claim can
    /// never overdraw because `pending_rewards` only grows by the
    /// same total distributed here (minus rounding dust, which is
    /// unclaimable).
    fn collect_block_reward(&self, ledger: &dyn Balances) -> u64 {
        let fee_collected = ledger.balance(&FEE_POOL);
        if fee_collected > 0 {
            // The pool can only hold what was deposited — the
            // transfer cannot fail; treat failure as zero collected
            // (defensive: a partially-wired ledger must not halt the
            // block).
            let _ = ledger.transfer(&FEE_POOL, &REWARD_POOL, fee_collected);
        }
        if self.block_reward > 0 {
            ledger.mint(&REWARD_POOL, self.block_reward);
        }
        fee_collected.saturating_add(self.block_reward)
    }

    /// Distribute `total_reward` to active validators proportional
    /// to their stake, growing each validator's
    /// `reward_per_token` accumulator.
    ///
    /// Called at `end_block` with the swept fees + issuance. The
    /// accumulator divides the reward across *all* bonded stake of
    /// the validator — delegations earn through `reward_debt`, the
    /// self-share earns through `self_debt` — so delegators and the
    /// validator's own bond share pro-rata with no commission
    /// parameter (v1 policy; a commission field can be added to the
    /// validator record later without changing the accounting).
    ///
    /// Validators pending removal stop earning — the removal
    /// decision is the point at which they "stop receiving block
    /// rewards" (module docs).
    ///
    /// Integer-division remainders are not distributed — they stay
    /// in [`REWARD_POOL`] as unclaimable dust (deterministic
    /// rounding burn).
    fn distribute_rewards(&self, total_reward: u64) {
        if total_reward == 0 {
            return;
        }
        let validators = self.validators.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending_removes = self
            .pending_validator_removes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Jailed validators stop earning too — jailing is exclusion
        // from consensus and rewards, not just consensus.
        let jailed = self.jailed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let is_eligible =
            |a: &Address, s: u64| s > 0 && !pending_removes.contains(a) && !jailed.contains_key(a);
        let eligible: u64 =
            validators.iter().filter(|(a, s)| is_eligible(a, **s)).map(|(_, s)| *s).sum();
        if eligible == 0 {
            return;
        }
        let mut rpt =
            self.reward_per_token.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for (addr, stake) in validators.iter() {
            if !is_eligible(addr, *stake) {
                continue;
            }
            let reward = total_reward.saturating_mul(*stake) / eligible;
            if reward > 0 {
                *rpt.entry(*addr).or_insert(0) +=
                    u128::from(reward).saturating_mul(RPT_SCALE).saturating_div(u128::from(*stake));
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

    /// A staking module with a `MemoryBalances` ledger wired and each
    /// address `0..=9` funded with 1M base units, plus every listed
    /// validator registered (zero stake — delegations build it up).
    fn setup(validators: &[u8]) -> StakingModule {
        setup_with_ledger(validators).0
    }

    /// The ledger behind a setup — needed by tests asserting pool
    /// movement. The ledger is `MemoryBalances`: a unit-test double
    /// over the same `Balances` seam the real EVM-backed impl serves.
    fn setup_with_ledger(
        validators: &[u8],
    ) -> (StakingModule, std::sync::Arc<framework::MemoryBalances>) {
        let staking = StakingModule::new();
        let ledger = std::sync::Arc::new(framework::MemoryBalances::new());
        for s in 0u8..=9 {
            ledger.mint(&addr(s), 1_000_000);
        }
        staking.set_ledger(ledger.clone());
        for v in validators {
            staking.register_validator(addr(*v));
        }
        (staking, ledger)
    }

    fn ctx() -> TxContext {
        TxContext { sender: addr(0), nonce: 0, fee: 0 }
    }

    fn ctx_with_sender(sender: u8) -> TxContext {
        TxContext { sender: addr(sender), nonce: 0, fee: 0 }
    }

    /// A committee with real voting power: each listed validator is
    /// registered and self-bonds `power` base units. Governance
    /// actions are weighed by bonded stake, so a registered but
    /// unbonded "validator" carries no authority — committee-gated
    /// tests must use this fixture, not bare `setup`.
    fn setup_powered(validators: &[u8], power: u64) -> StakingModule {
        let staking = setup(validators);
        for v in validators {
            let a = addr(*v);
            staking
                .handle(&ctx_with_sender(*v), &msg::delegate(a, power))
                .expect("self-bond for committee power");
        }
        staking
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
        let (staking, ledger) = setup_with_ledger(&[1]);
        let v = addr(1);
        let before = ledger.balance(&addr(0));
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        assert_eq!(ledger.balance(&addr(0)), before - 1000, "delegator debited");
        assert_eq!(ledger.balance(&BONDED_POOL), 1000, "bonded pool credited");
        assert_eq!(staking.delegation(&addr(0), &v), 1000);
    }

    #[test]
    fn delegate_rejects_insufficient_balance() {
        let (staking, ledger) = setup_with_ledger(&[1]);
        let v = addr(1);
        let result = staking.handle(&ctx(), &msg::delegate(v, 2_000_000));
        assert!(result.is_err(), "delegate exceeding balance must fail");
        assert_eq!(staking.stake(&v), 0, "no stake created on failure");
        assert_eq!(ledger.balance(&BONDED_POOL), 0, "pool untouched on failure");
    }

    #[test]
    fn unbonding_refunds_delegator_via_ledger() {
        let (staking, ledger) = setup_with_ledger(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let after_delegate = ledger.balance(&addr(0));
        staking.begin_block(Height::new(10));
        staking.handle(&ctx(), &msg::undelegate(v, 400)).unwrap();
        // Still in the pool while unbonding.
        assert_eq!(ledger.balance(&BONDED_POOL), 1000);
        assert_eq!(ledger.balance(&addr(0)), after_delegate, "not refunded yet");
        staking.begin_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
        staking.end_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
        assert_eq!(
            ledger.balance(&addr(0)),
            after_delegate + 400,
            "unbonded funds returned to the delegator"
        );
        assert_eq!(ledger.balance(&BONDED_POOL), 600, "pool keeps the bonded remainder");
    }

    #[test]
    fn slash_burns_only_bonded_funds() {
        let (staking, ledger) = setup_with_ledger(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.handle(&ctx_with_sender(1), &msg::slash(v, 100)).unwrap();
        assert_eq!(staking.stake(&v), 900);
        assert_eq!(staking.delegation(&addr(0), &v), 900, "delegation reduced proportionally");
        assert_eq!(ledger.balance(&BONDED_POOL), 900, "slashed amount burned from pool");
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
        staking.handle(&ctx_with_sender(1), &msg::slash(v, slash_amount)).unwrap();
        assert_eq!(staking.stake(&v), 900, "stake reduced by slash");
    }

    #[test]
    fn slash_capped_at_stake() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
        // Try to slash more than the stake.
        staking.handle(&ctx_with_sender(1), &msg::slash(v, 500)).unwrap();
        assert_eq!(staking.stake(&v), 0, "stake floored at 0");
    }

    #[test]
    fn slash_rejects_unknown_validator() {
        let staking = setup(&[2]);
        let v = addr(1);
        let result = staking.handle(&ctx_with_sender(2), &msg::slash(v, 100));
        assert!(result.is_err(), "should reject slash of unknown validator");
    }

    #[test]
    fn slash_rejects_non_committee_sender() {
        // The permissionless slash path must not exist — evidence
        // carries its own proof; raw slash is governance.
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let result = staking.handle(&ctx(), &msg::slash(v, 100));
        assert!(result.is_err(), "non-validator sender must not slash");
        assert_eq!(staking.stake(&v), 1000, "stake untouched");
    }

    // ── Evidence (double-sign) + jail ────────────────────────────

    /// A real BLS secret key for deterministic tests — same
    /// `from_ikm` path consensus tests use.
    fn bls_key(byte: u8) -> crypto::BlsSecretKey {
        let ikm = vec![byte; 32];
        crypto::BlsSecretKey::from_ikm(&ikm).expect("key gen")
    }

    /// Build a valid double-sign evidence message for `key`'s
    /// validator: two votes over `(view, phase, epoch)` for two
    /// different block hashes, both really signed.
    fn signed_evidence(
        validator: Address,
        key: &crypto::BlsSecretKey,
        view: u64,
        epoch: u64,
    ) -> Vec<u8> {
        let hash_a = [0xAAu8; 32];
        let hash_b = [0xBBu8; 32];
        let vote_msg = |hash: &[u8; 32]| {
            let mut m = [0u8; 49];
            m[..8].copy_from_slice(&view.to_le_bytes());
            m[8] = 0; // phase — matches the engine's current_phase_byte
            m[9..41].copy_from_slice(hash);
            m[41..49].copy_from_slice(&epoch.to_le_bytes());
            m
        };
        let sig_a = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_a));
        let sig_b = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_b));
        msg::evidence(
            validator,
            view,
            0,
            epoch,
            &hash_a,
            sig_a.as_bytes(),
            &hash_b,
            sig_b.as_bytes(),
        )
    }

    #[test]
    fn evidence_slashes_and_jails_on_valid_proof() {
        let (staking, ledger) = setup_with_ledger(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        staking.genesis_set_bls_key(v, key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        let evidence = signed_evidence(v, &key, 7, 0);
        staking.handle(&ctx(), &evidence).unwrap();

        assert_eq!(staking.stake(&v), 900, "10% double-sign slash applied");
        assert_eq!(ledger.balance(&BONDED_POOL), 900, "slashed funds burned");
        assert!(staking.is_jailed(&v), "offender jailed");
        // The jail reaches consensus at the next rotation.
        let changes = staking.take_validator_changes();
        assert!(changes.removes.contains(&v), "jailed validator emitted as remove");
    }

    #[test]
    fn evidence_rejects_identical_hashes() {
        let staking = setup(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        staking.genesis_set_bls_key(v, key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        // Same block hash twice is one vote, not equivocation.
        let hash = [0xAAu8; 32];
        let mut vote_msg = [0u8; 49];
        vote_msg[..8].copy_from_slice(&7u64.to_le_bytes());
        vote_msg[9..41].copy_from_slice(&hash);
        let sig = key.sign(crypto::hash::Domain::Vote, &vote_msg);
        let evidence = msg::evidence(v, 7, 0, 0, &hash, sig.as_bytes(), &hash, sig.as_bytes());
        assert!(staking.handle(&ctx(), &evidence).is_err());
        assert_eq!(staking.stake(&v), 1000);
    }

    #[test]
    fn evidence_rejects_forged_signature() {
        let staking = setup(&[1]);
        let v = addr(1);
        // Register key 1, but sign the "evidence" with key 2 —
        // verification must fail against the registered key.
        let registered = bls_key(1);
        let forger = bls_key(2);
        staking.genesis_set_bls_key(v, registered.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        let evidence = signed_evidence(v, &forger, 7, 0);
        assert!(staking.handle(&ctx(), &evidence).is_err(), "forged proof must reject");
        assert_eq!(staking.stake(&v), 1000, "no slash on forged evidence");
        assert!(!staking.is_jailed(&v));
    }

    #[test]
    fn evidence_rejects_replay() {
        let staking = setup(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        staking.genesis_set_bls_key(v, key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        let evidence = signed_evidence(v, &key, 7, 0);
        staking.handle(&ctx(), &evidence).unwrap();
        let result = staking.handle(&ctx(), &evidence);
        assert!(result.is_err(), "same proof must not slash twice");
        assert_eq!(staking.stake(&v), 900, "still exactly one slash");
    }

    #[test]
    fn evidence_rejects_validator_without_key() {
        let staking = setup(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        // No genesis_set_bls_key — the validator exists in staking
        // but has no consensus key on record to verify against.
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let evidence = signed_evidence(v, &key, 7, 0);
        assert!(staking.handle(&ctx(), &evidence).is_err());
    }

    #[test]
    fn jailed_validator_stops_earning_rewards() {
        let staking = setup(&[1, 2]).with_block_reward(1_000);
        let (v1, v2) = (addr(1), addr(2));
        let key = bls_key(1);
        staking.genesis_set_bls_key(v1, key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
        staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();

        staking.handle(&ctx(), &signed_evidence(v1, &key, 7, 0)).unwrap();
        // v1 jailed with 900 stake; v2 free with 1000 — v2 must take
        // the whole block reward.
        staking.end_block(Height::new(1));
        assert_eq!(staking.claimable(&addr(0)), 1_000, "all rewards to v2's delegator");
    }

    #[test]
    fn unjail_readmits_after_period() {
        let staking = setup(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        staking.genesis_set_bls_key(v, key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.handle(&ctx(), &signed_evidence(v, &key, 7, 0)).unwrap();

        // Too early — jail period not elapsed.
        staking.begin_block(Height::new(100));
        assert!(staking.handle(&ctx_with_sender(1), &msg::unjail(v)).is_err());

        // After MIN_JAIL_BLOCKS the unjail is accepted and the
        // validator is re-admitted via the changes drain.
        staking.begin_block(Height::new(100 + MIN_JAIL_BLOCKS));
        staking.handle(&ctx_with_sender(1), &msg::unjail(v)).unwrap();
        assert!(!staking.is_jailed(&v));
        let changes = staking.take_validator_changes();
        assert_eq!(changes.adds.len(), 1, "unjailed validator re-admitted");
        assert_eq!(changes.adds[0].0, v);
        assert_eq!(changes.adds[0].1, key.public_key().as_bytes(), "re-adds with current key");
        assert_eq!(changes.adds[0].2, 900, "re-adds with post-slash stake");
    }

    #[test]
    fn unjail_rejects_non_jailed_and_other_sender() {
        let staking = setup(&[1]);
        let v = addr(1);
        // Not jailed at all.
        assert!(staking.handle(&ctx_with_sender(1), &msg::unjail(v)).is_err());
    }

    // ── Downtime tracking (record_block_attendance) ──────────────

    #[test]
    fn downtime_jails_after_full_window_of_absence() {
        let staking = setup(&[1, 2]);
        let (v1, v2) = (addr(1), addr(2));
        staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
        staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();

        // v1 never signs; v2 signs every block.
        for h in 1..=DOWNTIME_WINDOW as u64 {
            staking.record_block_attendance(Height::new(h), &[v2]);
        }
        assert!(staking.is_jailed(&v1), "absent for the full window → jailed");
        assert!(!staking.is_jailed(&v2), "perfect attendance stays free");
        assert_eq!(staking.stake(&v1), 1000, "downtime jail does not slash");
        let changes = staking.take_validator_changes();
        assert!(changes.removes.contains(&v1), "auto-jail emitted as remove");
    }

    #[test]
    fn downtime_grace_period_before_window_fills() {
        let staking = setup(&[1, 2]);
        let (v1, v2) = (addr(1), addr(2));
        staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
        staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();

        // 99 absent blocks — one short of a full window: no jail yet
        // (fresh-join grace, same as Cosmos SignedBlocksWindow).
        for h in 1..DOWNTIME_WINDOW as u64 {
            staking.record_block_attendance(Height::new(h), &[v2]);
        }
        assert!(!staking.is_jailed(&v1), "cannot jail before the window fills");
    }

    #[test]
    fn downtime_partial_absence_does_not_jail() {
        let staking = setup(&[1, 2]);
        let (v1, v2) = (addr(1), addr(2));
        staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
        staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();

        // v1 signs exactly half the window (≥ DOWNTIME_MIN_SIGNED).
        for h in 1..=DOWNTIME_WINDOW as u64 {
            let signers = if h % 2 == 0 { vec![v1, v2] } else { vec![v2] };
            staking.record_block_attendance(Height::new(h), &signers);
        }
        assert!(!staking.is_jailed(&v1), "50% attendance stays free");
    }

    #[test]
    fn attendance_empty_signers_is_noop() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        // Sequencer/mock engines report no attendance — an empty
        // signer list must never read as "everyone absent".
        for h in 1..=DOWNTIME_WINDOW as u64 {
            staking.record_block_attendance(Height::new(h), &[]);
        }
        assert!(!staking.is_jailed(&v));
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
        // addr(0) is the only delegator: 25% accrues through v1's
        // reward-per-token and 75% through v2's — the delegator
        // claimable total is the full block reward.
        assert_eq!(staking.claimable(&addr(0)), 1_000_000, "delegator earns all positions");
        // The validators hold no self-share — their entire stake is
        // addr(0)'s delegation, so they accrue nothing directly.
        assert_eq!(staking.claimable(&v1), 0, "validator self-share is zero");
        assert_eq!(staking.claimable(&v2), 0, "validator self-share is zero");
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
        assert_eq!(staking.claimable(&addr(0)), 2_000_000, "2 blocks * 1M reward");
    }

    #[test]
    fn rewards_split_between_delegator_and_self_share() {
        // Validator v1 has 4000 genesis self-stake (no delegation
        // record); delegator d bonds 4000 to it. The 1M block
        // reward splits pro-rata: half to the validator's
        // self-share, half to the delegator.
        let staking = setup(&[]).with_block_reward(1_000_000);
        staking.genesis_register_validator(addr(1), 4_000);
        let d = addr(0);
        staking.handle(&ctx_with_sender(0), &msg::delegate(addr(1), 4_000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        assert_eq!(staking.claimable(&d), 500_000, "delegator gets half");
        assert_eq!(staking.claimable(&addr(1)), 500_000, "self-share gets half");
    }

    #[test]
    fn rewards_do_not_accrue_retroactively_to_new_delegator() {
        // A delegation made after rewards accrued starts at the
        // current reward-per-token — it cannot claim past rewards.
        let staking = setup(&[1]).with_block_reward(1_000_000);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        // addr(2) delegates at block 2 — it must not share block 1's
        // reward.
        staking.handle(&ctx_with_sender(2), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(2));
        staking.end_block(Height::new(2));
        assert_eq!(staking.claimable(&addr(0)), 1_500_000, "early delegator: b1 full + b2 half");
        assert_eq!(staking.claimable(&addr(2)), 500_000, "late delegator: b2 half only");
    }

    #[test]
    fn fees_collected_in_fee_pool_distribute_to_delegators() {
        // The fee sweep is the "distribution" half of #18: whatever
        // landed in FEE_POOL during the block is added to the
        // issuance and distributed pro-rata.
        let (staking, ledger) = setup_with_ledger(&[1]);
        let staking = staking.with_block_reward(0);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        // Simulate the executor's charge_fee path: 3 txs x 700 fee
        // collected into FEE_POOL.
        ledger.mint(&FEE_POOL, 2_100);
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        assert_eq!(ledger.balance(&FEE_POOL), 0, "fee pool swept");
        assert_eq!(ledger.balance(&REWARD_POOL), 2_100);
        assert_eq!(staking.claimable(&addr(0)), 2_100, "fees distributed pro-rata");
    }

    #[test]
    fn claim_pays_delegator_from_reward_pool() {
        // Conservation: a claim transfers real funds out of
        // REWARD_POOL — no minting at claim time.
        let (staking, ledger) = setup_with_ledger(&[1]);
        let staking = staking.with_block_reward(1_000);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let delegator_before = ledger.balance(&addr(0));
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        let pool_funded = ledger.balance(&REWARD_POOL);
        staking.handle(&ctx(), &msg::claim_reward(addr(0), 0)).unwrap();
        assert_eq!(
            ledger.balance(&addr(0)),
            delegator_before + 1_000,
            "claim pays real funds to the delegator"
        );
        assert_eq!(
            ledger.balance(&REWARD_POOL),
            pool_funded - 1_000,
            "pool decremented by exactly the claim"
        );
    }

    #[test]
    fn claim_reward_withdraws_accumulated() {
        let staking = setup(&[0]).with_block_reward(1_000_000);
        let v = addr(0); // sender addr(0) is the validator — claims its own rewards
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        assert_eq!(staking.claimable(&v), 1_000_000);
        staking.handle(&ctx(), &msg::claim_reward(v, 0)).unwrap();
        assert_eq!(staking.claimable(&v), 0, "rewards claimed");
    }

    #[test]
    fn claim_reward_partial_withdrawal() {
        let staking = setup(&[0]).with_block_reward(1_000_000);
        let v = addr(0);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(1));
        staking.end_block(Height::new(1));
        staking.handle(&ctx(), &msg::claim_reward(v, 400_000)).unwrap();
        assert_eq!(staking.claimable(&v), 600_000, "600K remaining");
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
        staking.handle(&ctx_with_sender(1), &msg::slash(v, 100)).unwrap();
        let root1 = staking.state_root();
        assert_ne!(root0, root1, "state root must change after slash");
    }

    // ── C8 canonical state-root completeness ─────────────────────
    //
    // Most staking state (unbonding queues, reward accumulators,
    // pending validator changes, jails, attendance rings, the
    // scheduled halt) lives in memory, not the KV store. The state
    // root must commit all of it — identical roots across
    // validators must prove identical staking state.

    #[test]
    fn state_root_changes_after_attendance() {
        let staking = setup(&[1, 2]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let root0 = staking.state_root();
        // v2 signed, v1 absent — the attendance ring is consensus
        // state: it decides future downtime jailing.
        staking.record_block_attendance(Height::new(1), &[addr(2)]);
        let root1 = staking.state_root();
        assert_ne!(root0, root1, "attendance must be committed");
    }

    #[test]
    fn state_root_changes_after_schedule_halt() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        staking.begin_block(Height::new(5));
        let root0 = staking.state_root();
        staking.handle(&ctx_with_sender(1), &msg::schedule_halt(v, 100)).unwrap();
        let root1 = staking.state_root();
        assert_ne!(root0, root1, "the scheduled halt must be committed");
    }

    #[test]
    fn state_root_changes_after_key_change() {
        let staking = setup(&[0]);
        let v = addr(0);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let root0 = staking.state_root();
        let new_sk = bls_key(0xAA);
        let new_key = new_sk.public_key().as_bytes().to_vec();
        let pop = new_sk.pop_prove();
        staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes())).unwrap();
        let root1 = staking.state_root();
        assert_ne!(root0, root1, "pending key changes must be committed");
    }

    #[test]
    fn state_root_changes_after_rewards_accrue() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let root0 = staking.state_root();
        // end_block accrues `reward_per_token` — an in-memory
        // accumulator that decides future payouts.
        staking.end_block(Height::new(1));
        let root1 = staking.state_root();
        assert_ne!(root0, root1, "reward accrual must be committed");
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
        let new_sk = bls_key(0xAA);
        let new_key = new_sk.public_key().as_bytes().to_vec();
        let pop = new_sk.pop_prove();
        staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes())).unwrap();
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
        let new_sk = bls_key(0xAA);
        let new_key = new_sk.public_key().as_bytes().to_vec();
        let pop = new_sk.pop_prove();
        let result = staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes()));
        assert!(result.is_err(), "must reject key change from non-validator sender");
    }

    #[test]
    fn key_change_rejects_unknown_validator() {
        let staking = setup(&[]);
        let v = addr(0); // sender is addr(0) but no stake delegated
        let new_sk = bls_key(0xAA);
        let new_key = new_sk.public_key().as_bytes().to_vec();
        let pop = new_sk.pop_prove();
        let result = staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes()));
        assert!(result.is_err(), "must reject key change for unknown validator");
    }

    #[test]
    fn key_change_rejects_wrong_key_length() {
        let staking = setup(&[0]);
        let v = addr(0);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let short_key = vec![0xAA; 32]; // not 48 bytes
        let pop = bls_key(0xBB).pop_prove();
        let msg = msg::key_change(v, &short_key, pop.as_bytes());
        let result = staking.handle(&ctx(), &msg);
        assert!(result.is_err(), "must reject non-48-byte key");
    }

    /// C3: a consensus key must prove possession at admission.
    /// Without `PoP`, `fast_aggregate_verify` QC checks admit a rogue
    /// key — a public key crafted from honest keys so a lone attacker
    /// signature verifies as a quorum aggregate.
    #[test]
    fn key_change_rejects_invalid_pop() {
        let staking = setup(&[0]);
        let v = addr(0);
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let new_sk = bls_key(0xAA);
        let new_key = new_sk.public_key().as_bytes().to_vec();
        // A different key's PoP is not a PoP for `new_key`.
        let wrong_pop = bls_key(0xBB).pop_prove();
        let result = staking.handle(&ctx(), &msg::key_change(v, &new_key, wrong_pop.as_bytes()));
        assert!(result.is_err(), "PoP for a different key must be rejected");
        // Garbage bytes are not a PoP either.
        let garbage = vec![0xCC; 96];
        let result = staking.handle(&ctx(), &msg::key_change(v, &new_key, &garbage));
        assert!(result.is_err(), "garbage PoP must be rejected");
        // The real PoP admits the change.
        let pop = new_sk.pop_prove();
        staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes())).unwrap();
        assert!(staking.has_key_change(&v), "valid PoP must admit the key change");
    }

    // ── Validator add / remove (committee-gated set changes) ────

    /// A committee quorum can admit a new validator whose key
    /// carries a valid proof-of-possession — the add lands in the
    /// pending set changes for the next epoch rotation. Activation
    /// requires bonded collateral, so the test delegates to the
    /// admitted candidate before draining the rotation.
    #[test]
    fn validator_add_with_valid_pop_succeeds() {
        let staking = setup_powered(&[1], 100);
        let new_addr = addr(9);
        let new_sk = bls_key(0xAA);
        let pop = new_sk.pop_prove();
        staking
            .handle(
                &ctx_with_sender(1),
                &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        // The candidate bonds 500 (any delegator can bond to a
        // registered candidate — the ledger debit is the collateral).
        staking.handle(&ctx_with_sender(0), &msg::delegate(new_addr, 500)).unwrap();
        let changes = staking.take_validator_changes();
        assert_eq!(changes.adds.len(), 1, "one pending add");
        assert_eq!(changes.adds[0].0, new_addr);
        assert_eq!(changes.adds[0].1, new_sk.public_key().as_bytes().to_vec());
        assert_eq!(changes.adds[0].2, 500);
    }

    /// `PoP` is mandatory at admission: a `validator_add` carrying a
    /// `PoP` for a different key — or garbage bytes — must be rejected.
    /// Without this gate a rogue key (a public key algebraically
    /// derived from honest keys) could enter the set and forge
    /// `fast_aggregate_verify` quorum checks.
    #[test]
    fn validator_add_rejects_invalid_pop() {
        let staking = setup_powered(&[1], 100);
        let new_addr = addr(9);
        let new_sk = bls_key(0xAA);
        // PoP for a different key.
        let wrong_pop = bls_key(0xBB).pop_prove();
        let result = staking.handle(
            &ctx_with_sender(1),
            &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), wrong_pop.as_bytes()),
        );
        assert!(result.is_err(), "PoP for a different key must be rejected");
        // Garbage bytes.
        let result = staking.handle(
            &ctx_with_sender(1),
            &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), &[0xCC; 96]),
        );
        assert!(result.is_err(), "garbage PoP must be rejected");
        // Nothing registered or pending.
        assert!(!staking.is_registered(&new_addr));
        assert!(staking.take_validator_changes().adds.is_empty());
    }

    /// Only a powered committee member can endorse set membership —
    /// an arbitrary account must not sybil the committee.
    #[test]
    fn validator_add_rejects_non_committee_sender() {
        let staking = setup_powered(&[1], 100);
        let new_sk = bls_key(0xAA);
        let pop = new_sk.pop_prove();
        let result = staking.handle(
            &ctx_with_sender(8), // addr(8) is funded but not a validator
            &msg::validator_add(addr(9), new_sk.public_key().as_bytes(), pop.as_bytes()),
        );
        assert!(result.is_err(), "non-validator sender must be rejected");
    }

    /// The staking address is the validator's identity — an existing
    /// member (or a quorum-admitted pending candidate) cannot be
    /// re-added under a new key.
    #[test]
    fn validator_add_rejects_duplicate_address() {
        let staking = setup_powered(&[1], 100);
        let sk = bls_key(0xAA);
        let pop = sk.pop_prove();
        // addr(1) is already a validator.
        let result = staking.handle(
            &ctx_with_sender(1),
            &msg::validator_add(addr(1), sk.public_key().as_bytes(), pop.as_bytes()),
        );
        assert!(result.is_err(), "existing validator address must be rejected");
        // A quorum-admitted candidate cannot be re-added either.
        let new_addr = addr(9);
        staking
            .handle(
                &ctx_with_sender(1),
                &msg::validator_add(new_addr, sk.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        let other_sk = bls_key(0xBB);
        let other_pop = other_sk.pop_prove();
        let result = staking.handle(
            &ctx_with_sender(1),
            &msg::validator_add(new_addr, other_sk.public_key().as_bytes(), other_pop.as_bytes()),
        );
        assert!(result.is_err(), "registered candidate address must be rejected");
    }

    /// A malformed BLS public key (48 bytes that do not encode a
    /// valid compressed BLS12-381 point) must be rejected at
    /// admission: `pop_verify` fails to uncompress it, so the add
    /// never lands.
    #[test]
    fn validator_add_rejects_malformed_key() {
        let staking = setup_powered(&[1], 100);
        // 48 bytes that do not encode a valid BLS12-381 G1 point.
        let bogus_key = vec![0xFF; 48];
        let pop = bls_key(0xAA).pop_prove();
        let result = staking
            .handle(&ctx_with_sender(1), &msg::validator_add(addr(9), &bogus_key, pop.as_bytes()));
        assert!(result.is_err(), "malformed public key must be rejected");
    }

    // ── Coordinated halt scheduling (SCHEDULE_HALT) ─────────────

    #[test]
    fn schedule_halt_committee_only_and_future_only() {
        let staking = setup_powered(&[1], 100);
        staking.begin_block(Height::new(10));

        // Non-validator sender is refused.
        assert!(staking.handle(&ctx_with_sender(9), &msg::schedule_halt(addr(9), 100)).is_err());
        // A past/current height is refused (already executed —
        // scheduling behind the tip can never trigger cleanly).
        assert!(staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 10)).is_err());
        assert!(staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 5)).is_err());
        assert_eq!(staking.scheduled_halt_height(), None);

        // A powered validator schedules a future halt (a
        // single-validator committee is its own quorum).
        staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 100)).unwrap();
        assert_eq!(staking.scheduled_halt_height(), Some(100));
    }

    #[test]
    fn schedule_halt_reschedule_and_cancel() {
        let staking = setup_powered(&[1], 100);
        staking.begin_block(Height::new(10));

        staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 100)).unwrap();
        assert_eq!(staking.scheduled_halt_height(), Some(100));

        // Re-schedule moves the halt (still future).
        staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 200)).unwrap();
        assert_eq!(staking.scheduled_halt_height(), Some(200));

        // Height 0 cancels the schedule.
        staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 0)).unwrap();
        assert_eq!(staking.scheduled_halt_height(), None);
    }

    // ── C9: committee-quorum governance ──────────────────────────
    //
    // Privileged actions are *endorsements*: each gated tx records
    // the sender's endorsement of the exact action payload and the
    // action applies only once cumulative endorser power strictly
    // exceeds two-thirds of the committee's total bonded power —
    // the same quorum a consensus QC requires. One validator's
    // signature is a vote, never a command.

    /// One validator must not admit a peer on its own signature:
    /// two endorsements out of four equal-power validators are
    /// still below quorum; the third crosses it.
    #[test]
    fn validator_add_requires_committee_quorum() {
        let staking = setup_powered(&[1, 2, 3, 4], 100);
        let new_addr = addr(9);
        let new_sk = bls_key(0xAA);
        let pop = new_sk.pop_prove();
        let add = msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes());

        staking.handle(&ctx_with_sender(1), &add).unwrap();
        assert!(!staking.is_registered(&new_addr), "one endorsement must not admit");
        staking.handle(&ctx_with_sender(2), &add).unwrap();
        assert!(!staking.is_registered(&new_addr), "two of four is below quorum");

        staking.handle(&ctx_with_sender(3), &add).unwrap();
        assert!(staking.is_registered(&new_addr), "quorum admits the candidate");
    }

    /// Admission itself bonds nothing — the audit's original hole
    /// let the add message *declare* stake with no collateral behind
    /// it. The endorsed registration carries zero stake; the
    /// candidate activates at the rotation only if real balance was
    /// bonded to it (by itself or any delegator), and the activation
    /// stake is the bonded amount, not anything the add claimed.
    #[test]
    fn validator_add_activation_requires_bonded_stake() {
        // Unbonded candidate: the quorum-approved admission lapses
        // at the epoch boundary and the registration unwinds.
        let staking = setup_powered(&[1], 100);
        let new_addr = addr(9);
        let new_sk = bls_key(0xAA);
        let pop = new_sk.pop_prove();
        staking
            .handle(
                &ctx_with_sender(1),
                &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        assert!(staking.is_registered(&new_addr));
        assert_eq!(staking.stake(&new_addr), 0, "admission itself bonds nothing");
        let changes = staking.take_validator_changes();
        assert!(changes.adds.is_empty(), "unbonded candidate must not activate");
        assert!(!staking.is_registered(&new_addr), "lapsed admission unwinds");

        // Bonded candidate: activates with the bonded collateral —
        // delegation by any account counts, the ledger debit is the
        // collateral proof.
        let staking = setup_powered(&[1], 100);
        let pop = new_sk.pop_prove();
        staking
            .handle(
                &ctx_with_sender(1),
                &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        staking.handle(&ctx_with_sender(0), &msg::delegate(new_addr, 500)).unwrap();
        let changes = staking.take_validator_changes();
        assert_eq!(changes.adds.len(), 1);
        assert_eq!(changes.adds[0].0, new_addr);
        assert_eq!(changes.adds[0].2, 500, "activation stake is the bonded collateral");
    }

    /// A lone validator must not evict a peer: removal is the same
    /// quorum-gated endorsement as admission.
    #[test]
    fn validator_remove_requires_committee_quorum() {
        let staking = setup_powered(&[1, 2, 3, 4], 100);
        let rm = msg::validator_remove(addr(4));

        staking.handle(&ctx_with_sender(1), &rm).unwrap();
        staking.handle(&ctx_with_sender(2), &rm).unwrap();
        assert!(
            staking.take_validator_changes().removes.is_empty(),
            "two endorsements must not remove"
        );

        staking.handle(&ctx_with_sender(3), &rm).unwrap();
        let changes = staking.take_validator_changes();
        assert_eq!(changes.removes, vec![addr(4)], "quorum removes");
    }

    /// Confiscating a validator's stake is a governance action —
    /// one signer must not slash. (The permissionless path is
    /// `EVIDENCE`, which authenticates itself with the proof.)
    #[test]
    fn slash_requires_committee_quorum() {
        let staking = setup_powered(&[1, 2, 3, 4], 100);
        let slash = msg::slash(addr(4), 10);

        staking.handle(&ctx_with_sender(1), &slash).unwrap();
        staking.handle(&ctx_with_sender(2), &slash).unwrap();
        assert_eq!(staking.stake(&addr(4)), 100, "below quorum, no slash");

        staking.handle(&ctx_with_sender(3), &slash).unwrap();
        assert_eq!(staking.stake(&addr(4)), 90, "quorum slashes");
    }

    /// Scheduling a coordinated halt freezes the chain — a single
    /// validator must never hold that trigger alone.
    #[test]
    fn schedule_halt_requires_committee_quorum() {
        let staking = setup_powered(&[1, 2, 3, 4], 100);
        staking.begin_block(Height::new(10));
        let halt = msg::schedule_halt(addr(1), 100);

        staking.handle(&ctx_with_sender(1), &halt).unwrap();
        staking.handle(&ctx_with_sender(2), &halt).unwrap();
        assert_eq!(staking.scheduled_halt_height(), None, "below quorum, no halt");

        staking.handle(&ctx_with_sender(3), &halt).unwrap();
        assert_eq!(staking.scheduled_halt_height(), Some(100), "quorum schedules");
    }

    /// A registered-but-unbonded validator has zero voting power —
    /// its endorsement is not even recorded. Registration is not
    /// authority; bonded stake is.
    #[test]
    fn powerless_validator_cannot_endorse() {
        let staking = setup(&[1]);
        let new_sk = bls_key(0xAA);
        let pop = new_sk.pop_prove();
        let result = staking.handle(
            &ctx_with_sender(1),
            &msg::validator_add(addr(9), new_sk.public_key().as_bytes(), pop.as_bytes()),
        );
        assert!(result.is_err(), "a powerless member holds no governance vote");
        assert!(!staking.is_registered(&addr(9)));
    }

    /// A jailed validator is by definition suspected of misbehavior
    /// — it must not keep voting on set changes during its jail
    /// period even though its stake is still bonded.
    #[test]
    fn jailed_validator_cannot_endorse() {
        let staking = setup_powered(&[1, 2, 3, 4], 100);
        staking.jailed.lock().unwrap().insert(addr(4), 1);
        let result = staking.handle(&ctx_with_sender(4), &msg::validator_remove(addr(3)));
        assert!(result.is_err(), "jailed validators hold no committee vote");
    }

    /// A quorum-admitted candidate is registered for delegation but
    /// is not committee until the rotation seats it — it must not
    /// endorse actions in the gap.
    #[test]
    fn pending_candidate_cannot_endorse() {
        let staking = setup_powered(&[1], 100);
        let new_addr = addr(9);
        let new_sk = bls_key(0xAA);
        let pop = new_sk.pop_prove();
        staking
            .handle(
                &ctx_with_sender(1),
                &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        staking.handle(&ctx_with_sender(0), &msg::delegate(new_addr, 100)).unwrap();
        let result = staking.handle(&ctx_with_sender(9), &msg::validator_remove(addr(1)));
        assert!(result.is_err(), "a pending candidate is not yet committee");
    }

    /// Endorsements bind to the exact action payload: "admit X with
    /// key K1" and "admit X with key K2" are different actions and
    /// accumulate separately. Whichever reaches quorum first wins;
    /// the loser's later quorum is consumed as stale — it must not
    /// rotate the already-admitted validator's key.
    #[test]
    fn endorsements_are_per_action() {
        let staking = setup_powered(&[1, 2, 3, 4], 100);
        let new_addr = addr(9);
        let (sk1, sk2) = (bls_key(0xAA), bls_key(0xBB));
        let add1 =
            msg::validator_add(new_addr, sk1.public_key().as_bytes(), sk1.pop_prove().as_bytes());
        let add2 =
            msg::validator_add(new_addr, sk2.public_key().as_bytes(), sk2.pop_prove().as_bytes());

        // Two endorsements on each action — neither quorums.
        for sender in [1u8, 2] {
            staking.handle(&ctx_with_sender(sender), &add1).unwrap();
            staking.handle(&ctx_with_sender(sender), &add2).unwrap();
        }
        assert!(!staking.is_registered(&new_addr), "split endorsements reach no quorum");
        assert_eq!(staking.endorsements.pending_count(), 2, "both variants accumulate");

        // K1 wins the race to quorum — and registering new_addr
        // killed the K2 variant, which can never apply now: its
        // frozen entry is swept out of the bounded pending set.
        staking.handle(&ctx_with_sender(3), &add1).unwrap();
        assert!(staking.is_registered(&new_addr));
        assert_eq!(
            staking.endorsements.pending_count(),
            0,
            "losing variant must be swept, not leaked",
        );
        staking.handle(&ctx_with_sender(0), &msg::delegate(new_addr, 50)).unwrap();

        // A late endorsement for K2 is rejected outright — the
        // address is registered, so the action is permanently dead.
        let err = staking.handle(&ctx_with_sender(4), &add2).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)));

        let changes = staking.take_validator_changes();
        assert_eq!(changes.adds.len(), 1);
        assert_eq!(changes.adds[0].1, sk1.public_key().as_bytes().to_vec(), "K1 won admission");
    }

    /// Removing a quorum-admitted candidate before it seats cancels
    /// the pending add outright — it never occupied consensus, so
    /// there is nothing to unbond and nothing reaches the rotation.
    #[test]
    fn validator_remove_cancels_pending_add_at_quorum() {
        let staking = setup_powered(&[1, 2], 100);
        let new_addr = addr(9);
        let new_sk = bls_key(0xAA);
        let pop = new_sk.pop_prove();
        let add = msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes());
        staking.handle(&ctx_with_sender(1), &add).unwrap();
        staking.handle(&ctx_with_sender(2), &add).unwrap();
        assert!(staking.is_registered(&new_addr));

        let rm = msg::validator_remove(new_addr);
        staking.handle(&ctx_with_sender(1), &rm).unwrap();
        staking.handle(&ctx_with_sender(2), &rm).unwrap();
        assert!(!staking.is_registered(&new_addr), "quorum remove cancels the admission");
        let changes = staking.take_validator_changes();
        assert!(changes.adds.is_empty() && changes.removes.is_empty());
    }

    /// The endorsement map is bounded state: beyond
    /// `MAX_PENDING_ACTIONS` distinct pending actions new ones are
    /// refused, while already-tracked actions still accept
    /// endorsements (a cap must not deadlock governance).
    #[test]
    fn endorsement_cap_rejects_new_actions() {
        let staking = setup_powered(&[1, 2], 100);
        staking.begin_block(Height::new(1));
        // One endorsement per distinct halt height — with power 100
        // of 200 a single endorsement never quorums, so each stays
        // pending and fills the tracker.
        for h in 2..(2 + framework::MAX_PENDING_ACTIONS as u64) {
            staking
                .handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), h))
                .expect("tracked actions accepted up to the cap");
        }
        let result = staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 10_000));
        assert!(result.is_err(), "the cap rejects new actions");

        // An already-tracked action still takes endorsements — the
        // second validator completes its quorum and it applies.
        staking.handle(&ctx_with_sender(2), &msg::schedule_halt(addr(1), 2)).unwrap();
        assert_eq!(staking.scheduled_halt_height(), Some(2));
    }

    /// C8 for C9: pending endorsements are future-affecting state —
    /// two replicas must diverge if one has recorded an endorsement
    /// the other has not, so the tally is committed in the root.
    #[test]
    fn state_root_changes_after_endorsement() {
        let staking = setup_powered(&[1, 2], 100);
        let root0 = staking.state_root();
        staking.handle(&ctx_with_sender(1), &msg::validator_remove(addr(2))).unwrap();
        assert_ne!(staking.state_root(), root0, "a pending endorsement is committed state");
    }

    /// Snapshot round-trip: validators, delegations, an unbonding
    /// entry, and the reward/set bookkeeping must export, verify,
    /// and re-import byte-identically — the imported module's root
    /// must equal the source's (audit 3.2).
    #[test]
    fn state_snapshot_round_trips() {
        let src = setup(&[1, 2]);
        src.handle(&ctx_with_sender(1), &msg::delegate(addr(1), 100)).unwrap();
        src.handle(&ctx_with_sender(3), &msg::delegate(addr(2), 250)).unwrap();
        // An unbonding entry exercises the FIFO queue section.
        src.handle(&ctx_with_sender(3), &msg::undelegate(addr(2), 50)).unwrap();
        src.begin_block(Height::new(10));
        src.end_block(Height::new(10));

        let snapshot = src.export_state().expect("staking exports state");
        assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

        let dst = StakingModule::new();
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), src.state_root());
        assert_eq!(dst.delegation(&addr(1), &addr(1)), 100);
        assert_eq!(dst.delegation(&addr(3), &addr(2)), 200);
    }

    /// A truncated blob must fail inspection and import — the
    /// claimed root is never trusted over the bytes.
    #[test]
    fn state_snapshot_rejects_corruption() {
        let src = setup(&[1]);
        src.handle(&ctx_with_sender(1), &msg::delegate(addr(1), 100)).unwrap();
        let mut snapshot = src.export_state().unwrap();
        snapshot.entries[0].1.truncate(12);
        assert!(src.inspect_state(&snapshot).is_err());
        assert!(StakingModule::new().import_state(&snapshot).is_err());
    }

    /// The replay key is the canonical OFFENSE identity —
    /// `(validator, view, phase, epoch)` — so resubmitting the
    /// same equivocation with the two votes swapped hits the same
    /// key. The v1 key hashed the ordered pair and double-slashed.
    #[test]
    fn evidence_swapped_pair_is_same_offense() {
        let staking = setup(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        staking.genesis_set_bls_key(v, key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        let evidence = signed_evidence(v, &key, 7, 0);
        staking.handle(&ctx(), &evidence).unwrap();
        assert_eq!(staking.stake(&v), 900);

        // Rebuild the same proof with (hash_a, sig_a) and
        // (hash_b, sig_b) swapped — byte-distinct message, same
        // offense.
        let view = 7u64;
        let epoch = 0u64;
        let hash_a = [0xAAu8; 32];
        let hash_b = [0xBBu8; 32];
        let vote_msg = |hash: &[u8; 32]| {
            let mut m = [0u8; 49];
            m[..8].copy_from_slice(&view.to_le_bytes());
            m[9..41].copy_from_slice(hash);
            m[41..49].copy_from_slice(&epoch.to_le_bytes());
            m
        };
        let sig_a = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_a));
        let sig_b = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_b));
        let swapped =
            msg::evidence(v, view, 0, epoch, &hash_b, sig_b.as_bytes(), &hash_a, sig_a.as_bytes());
        let result = staking.handle(&ctx(), &swapped);
        assert!(result.is_err(), "swapped pair must not re-slash");
        assert_eq!(staking.stake(&v), 900, "still exactly one slash");
    }

    /// Penalties are per OFFENSE: a different conflicting pair at
    /// the same (view, phase, epoch) — e.g. the validator triple-
    /// signed the view — is still one offense, one penalty.
    #[test]
    fn evidence_different_pair_same_offense() {
        let staking = setup(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        staking.genesis_set_bls_key(v, key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        staking.handle(&ctx(), &signed_evidence(v, &key, 7, 0)).unwrap();
        assert_eq!(staking.stake(&v), 900);

        // Same triple, different second hash — still the same
        // offense position.
        let hash_a = [0xAAu8; 32];
        let hash_c = [0xCCu8; 32];
        let vote_msg = |hash: &[u8; 32]| {
            let mut m = [0u8; 49];
            m[..8].copy_from_slice(&7u64.to_le_bytes());
            m[9..41].copy_from_slice(hash);
            m[41..49].copy_from_slice(&0u64.to_le_bytes());
            m
        };
        let sig_a = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_a));
        let sig_c = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_c));
        let second =
            msg::evidence(v, 7, 0, 0, &hash_a, sig_a.as_bytes(), &hash_c, sig_c.as_bytes());
        assert!(staking.handle(&ctx(), &second).is_err(), "same offense — no second slash");
        assert_eq!(staking.stake(&v), 900);
    }

    /// A DIFFERENT consensus position is a different offense —
    /// equivocating again at another view must slash again.
    #[test]
    fn evidence_distinct_view_is_distinct_offense() {
        let staking = setup(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        staking.genesis_set_bls_key(v, key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        staking.handle(&ctx(), &signed_evidence(v, &key, 7, 0)).unwrap();
        staking.handle(&ctx(), &signed_evidence(v, &key, 8, 0)).unwrap();
        // Two offenses, two 10% slashes: 1000 → 900 → 810.
        assert_eq!(staking.stake(&v), 810, "each distinct offense slashes");
    }

    /// Evidence for votes signed with a rotated-out key must still
    /// verify — the retired-key history covers the evidence
    /// window. v1 used only the live key, so a validator could
    /// rotate away from a pending proof.
    #[test]
    fn evidence_verifies_with_retired_key() {
        let staking = setup(&[1]);
        let v = addr(1);
        let old_key = bls_key(1);
        let new_key = bls_key(2);
        staking.genesis_set_bls_key(v, old_key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        // The offense predates the rotation: signed under K1.
        let evidence = signed_evidence(v, &old_key, 7, 0);
        // Rotate K1 → K2.
        let pop = new_key.pop_prove();
        staking
            .handle(
                &ctx_with_sender(1),
                &msg::key_change(v, new_key.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        let changes = staking.take_key_changes();
        assert_eq!(changes.len(), 1, "rotation applied");

        // Evidence signed with the retired key still verifies —
        // and slashes.
        staking.handle(&ctx(), &evidence).unwrap();
        assert_eq!(staking.stake(&v), 900, "rotated-out key evidence still slashes");
        assert!(staking.is_jailed(&v));
    }

    /// Each signature may verify under a different validator-owned
    /// key — a mid-view rotation could split them. The offense is
    /// the validator signing conflicting votes either way.
    #[test]
    fn evidence_verifies_mixed_keys() {
        let staking = setup(&[1]);
        let v = addr(1);
        let old_key = bls_key(1);
        let new_key = bls_key(2);
        staking.genesis_set_bls_key(v, old_key.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let pop = new_key.pop_prove();
        staking
            .handle(
                &ctx_with_sender(1),
                &msg::key_change(v, new_key.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        staking.take_key_changes();

        // Vote A signed under retired K1, vote B under current K2.
        let hash_a = [0xAAu8; 32];
        let hash_b = [0xBBu8; 32];
        let vote_msg = |hash: &[u8; 32]| {
            let mut m = [0u8; 49];
            m[..8].copy_from_slice(&7u64.to_le_bytes());
            m[9..41].copy_from_slice(hash);
            m[41..49].copy_from_slice(&0u64.to_le_bytes());
            m
        };
        let sig_a = old_key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_a));
        let sig_b = new_key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_b));
        let evidence =
            msg::evidence(v, 7, 0, 0, &hash_a, sig_a.as_bytes(), &hash_b, sig_b.as_bytes());
        staking.handle(&ctx(), &evidence).unwrap();
        assert_eq!(staking.stake(&v), 900);
    }

    /// A key no validator ever held still cannot verify — the
    /// retired set is validator-scoped, not a global forgery pool.
    #[test]
    fn evidence_rejects_unrelated_retired_key() {
        let staking = setup(&[1, 2]);
        let (v1, v2) = (addr(1), addr(2));
        let k1 = bls_key(1);
        let k2 = bls_key(2);
        staking.genesis_set_bls_key(v1, k1.public_key().as_bytes());
        staking.genesis_set_bls_key(v2, k2.public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
        staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();
        // Rotate v2's key — v1's evidence signed with v2's OLD key
        // must still fail: the key was never v1's.
        let k2_new = bls_key(3);
        let pop = k2_new.pop_prove();
        staking
            .handle(
                &ctx_with_sender(2),
                &msg::key_change(v2, k2_new.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        staking.take_key_changes();
        let forged = signed_evidence(v1, &k2, 7, 0);
        assert!(
            staking.handle(&ctx(), &forged).is_err(),
            "another validator's key must not verify"
        );
        assert_eq!(staking.stake(&v1), 1000);
    }

    /// The retired history is bounded — rotations beyond
    /// `EVIDENCE_KEY_HISTORY` evict the oldest entries.
    #[test]
    fn retired_key_history_is_bounded() {
        let staking = setup(&[1]);
        let v = addr(1);
        staking.genesis_set_bls_key(v, bls_key(0).public_key().as_bytes());
        staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        // Nine rotations: keys 1..=9 displace 0..=8 → retired
        // holds at most EVIDENCE_KEY_HISTORY (8).
        for i in 1u8..=9 {
            let k = bls_key(i);
            let pop = k.pop_prove();
            staking
                .handle(
                    &ctx_with_sender(1),
                    &msg::key_change(v, k.public_key().as_bytes(), pop.as_bytes()),
                )
                .unwrap();
            staking.take_key_changes();
        }
        let retired = staking.retired_bls_keys.lock().unwrap();
        let keys = retired.get(&v).expect("history exists");
        assert_eq!(keys.len(), EVIDENCE_KEY_HISTORY, "history capped");
        // The oldest (key 0) was evicted; the newest (key 8) kept.
        assert_eq!(keys.last().unwrap().as_slice(), bls_key(8).public_key().as_bytes());
    }

    /// Retired keys are committed state — they must survive a
    /// snapshot round-trip so every replica verifies the same
    /// post-rotation evidence.
    #[test]
    fn snapshot_roundtrips_retired_keys() {
        let src = setup(&[1]);
        let v = addr(1);
        let old_key = bls_key(1);
        let new_key = bls_key(2);
        src.genesis_set_bls_key(v, old_key.public_key().as_bytes());
        src.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
        let pop = new_key.pop_prove();
        src.handle(
            &ctx_with_sender(1),
            &msg::key_change(v, new_key.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
        src.take_key_changes();
        let evidence = signed_evidence(v, &old_key, 7, 0);

        let snapshot = src.export_state().unwrap();
        assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());
        let dst = StakingModule::new();
        dst.set_ledger(std::sync::Arc::new(framework::MemoryBalances::new()));
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), src.state_root());
        // The imported replica verifies retired-key evidence too.
        dst.handle(&ctx(), &evidence).unwrap();
        assert_eq!(dst.stake(&v), 900);
    }

    /// Pre-upgrade blobs carry no retired-keys section: they decode
    /// with an empty history — evidence verifies against the live
    /// key, the exact pre-upgrade bound.
    #[test]
    fn pre_upgrade_blob_decodes_without_key_history() {
        let src = setup(&[1]);
        let v = addr(1);
        let key = bls_key(1);
        src.genesis_set_bls_key(v, key.public_key().as_bytes());
        src.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

        // Strip the trailing retired-keys section from the canon:
        // with an empty history the section is a single
        // `put_count(0)` — 8 zero bytes at the canon tail.
        let mut snapshot = src.export_state().unwrap();
        let blob = &mut snapshot.entries[0].1;
        let canon_len = usize::try_from(u64::from_le_bytes(blob[..8].try_into().unwrap())).unwrap();
        let section_len = 8usize; // put_count(0)
        blob[..8].copy_from_slice(&(canon_len as u64 - section_len as u64).to_le_bytes());
        blob.drain(8 + canon_len - section_len..8 + canon_len);
        let v1_snapshot = snapshot.clone();

        let dst = StakingModule::new();
        dst.set_ledger(std::sync::Arc::new(framework::MemoryBalances::new()));
        dst.inspect_state(&v1_snapshot).unwrap();
        dst.import_state(&v1_snapshot).unwrap();
        // Empty retired history — but live-key evidence works.
        assert!(dst.retired_bls_keys.lock().unwrap().is_empty());
        let evidence = signed_evidence(v, &key, 7, 0);
        dst.handle(&ctx(), &evidence).unwrap();
        assert_eq!(dst.stake(&v), 900);
    }
}
