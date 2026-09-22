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
mod decode;

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
        framework::lock_state(&self.validators).entry(validator).or_insert(0);
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
        framework::lock_state(&self.validators).insert(validator, stake);
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
        // Genesis has no PoP to check — the group-element validation
        // is the only thing keeping a typo'd key from wedging the
        // validator's votes for the chain's whole life.
        let pk = crypto::bls::PublicKey::from_slice(key).expect("length checked above");
        assert!(
            crypto::bls_signer::validate_point(&pk).is_ok(),
            "genesis BLS key for {validator:?} is not a valid group element"
        );
        framework::lock_state(&self.bls_keys).insert(validator, key.to_vec());
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
        framework::lock_state(&self.jailed).contains_key(addr)
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
        let in_set = framework::lock_state(&self.validators).contains_key(addr);
        if !in_set || self.is_jailed(addr) {
            return false;
        }
        !framework::lock_state(&self.pending_validator_adds).iter().any(|(a, _)| a == addr)
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
        framework::lock_state(&self.validators).contains_key(addr)
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
        framework::lock_state(&self.validators).get(addr).copied().unwrap_or(0)
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
        let validators = framework::lock_state(&self.validators);
        let jailed = framework::lock_state(&self.jailed);
        let pending = framework::lock_state(&self.pending_validator_adds);
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
        let validators = framework::lock_state(&self.validators);
        let jailed = framework::lock_state(&self.jailed);
        let pending = framework::lock_state(&self.pending_validator_adds);
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
        *framework::lock_state(&self.validators).get(addr).unwrap_or(&0)
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
        let rpts = framework::lock_state(&self.reward_per_token);
        let debts = framework::lock_state(&self.reward_debt);
        let mut total = *framework::lock_state(&self.pending_rewards).get(addr).unwrap_or(&0);
        let delegator_vs =
            framework::lock_state(&self.delegator_index).get(addr).cloned().unwrap_or_default();
        let delegations = framework::lock_state(&self.delegations);
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
        let validators = framework::lock_state(&self.validators);
        if let Some(&stake) = validators.get(addr) {
            let delegated =
                framework::lock_state(&self.delegated_total).get(addr).copied().unwrap_or(0);
            let self_share = Self::self_share_of(stake, delegated);
            let rpt = rpts.get(addr).copied().unwrap_or(0);
            let debt = framework::lock_state(&self.self_debt).get(addr).copied().unwrap_or(0);
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
        let validators = framework::lock_state(&self.validators);
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
        framework::lock_state(&self.unbonding).clone()
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
        let changes: Vec<(Address, Vec<u8>)> =
            std::mem::take(&mut *framework::lock_state(&self.pending_key_changes))
                .into_iter()
                .collect();
        let mut bls_keys = framework::lock_state(&self.bls_keys);
        for (addr, key) in &changes {
            if let Some(old) = bls_keys.insert(*addr, key.clone())
                && old != *key
            {
                self.retire_key(*addr, old);
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
        let mut retired = framework::lock_state(&self.retired_bls_keys);
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
        let removes: std::collections::BTreeSet<Address> =
            std::mem::take(&mut *framework::lock_state(&self.pending_validator_removes))
                .into_iter()
                .chain(std::mem::take(&mut *framework::lock_state(&self.pending_jails)))
                .collect();
        let pending_adds =
            std::mem::take(&mut *framework::lock_state(&self.pending_validator_adds));
        let mut adds = Vec::with_capacity(pending_adds.len());
        {
            let mut validators = framework::lock_state(&self.validators);
            let mut bls_keys = framework::lock_state(&self.bls_keys);
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
        let unjails = std::mem::take(&mut *framework::lock_state(&self.pending_unjails));
        if !unjails.is_empty() {
            let bls_keys = framework::lock_state(&self.bls_keys);
            let validators = framework::lock_state(&self.validators);
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
        framework::lock_state(&self.pending_key_changes).contains_key(addr)
    }

    /// Get completed unbonding entries (for withdrawal).
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn completed_unbonding(&self) -> Vec<UnbondingEntry> {
        let current = *framework::lock_state(&self.current_height);
        framework::lock_state(&self.unbonding)
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
        *framework::lock_state(&self.current_height) = height.value();
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
        let ledger = framework::lock_state(&self.ledger).clone();
        let mut unbonding = framework::lock_state(&self.unbonding);
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
        let validators = framework::lock_state(&self.validators);
        let pending_removes = framework::lock_state(&self.pending_validator_removes);
        let jailed = framework::lock_state(&self.jailed);
        let mut attendance = framework::lock_state(&self.attendance);

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
            let mut jailed = framework::lock_state(&self.jailed);
            let mut pending_jails = framework::lock_state(&self.pending_jails);
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
        *framework::lock_state(&self.scheduled_halt)
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
        let (canon, _staged, _store) = framework::stage_blob_snapshot(snapshot, |r, store| {
            decode::decode_committed(r, store)
        })?;
        Ok(framework::canon_root(canon))
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then every field swaps in
    /// (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let (_canon, staged, store) =
            framework::stage_blob_snapshot(snapshot, |r, s| decode::decode_committed(r, s))?;
        *framework::lock_state(&self.store) = store;
        *framework::lock_state(&self.validators) = staged.validators;
        *framework::lock_state(&self.delegations) = staged.delegations;
        *framework::lock_state(&self.unbonding) = staged.unbonding;
        *framework::lock_state(&self.pending_rewards) = staged.pending_rewards;
        *framework::lock_state(&self.reward_per_token) = staged.reward_per_token;
        *framework::lock_state(&self.reward_debt) = staged.reward_debt;
        *framework::lock_state(&self.self_debt) = staged.self_debt;
        *framework::lock_state(&self.delegator_index) = staged.delegator_index;
        *framework::lock_state(&self.delegated_total) = staged.delegated_total;
        *framework::lock_state(&self.pending_key_changes) = staged.pending_key_changes;
        *framework::lock_state(&self.pending_validator_adds) = staged.pending_validator_adds;
        *framework::lock_state(&self.pending_validator_removes) = staged.pending_validator_removes;
        *framework::lock_state(&self.bls_keys) = staged.bls_keys;
        *framework::lock_state(&self.jailed) = staged.jailed;
        *framework::lock_state(&self.pending_jails) = staged.pending_jails;
        *framework::lock_state(&self.pending_unjails) = staged.pending_unjails;
        *framework::lock_state(&self.scheduled_halt) = staged.scheduled_halt;
        *framework::lock_state(&self.seen_evidence) = staged.seen_evidence;
        *framework::lock_state(&self.retired_bls_keys) = staged.retired_bls_keys;
        *framework::lock_state(&self.attendance) = staged.attendance;
        *framework::lock_state(&self.current_height) = staged.current_height;
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
        *framework::lock_state(&self.ledger) = Some(ledger);
    }

    /// Commit `validators`, `delegations`, and the `unbonding` queue
    /// to the canonical state encoding (C8). These decide consensus
    /// voting power and future unbond payouts.
    fn commit_stake_state(&self, w: &mut framework::CanonicalState) {
        {
            let validators = framework::lock_state(&self.validators);
            w.put_count(validators.len());
            for (a, s) in validators.iter() {
                w.put_addr(a).put_u64(*s);
            }
        }
        {
            let delegations = framework::lock_state(&self.delegations);
            w.put_count(delegations.len());
            for ((d, v), amt) in delegations.iter() {
                w.put_addr(d).put_addr(v).put_u64(*amt);
            }
        }
        {
            let unbonding = framework::lock_state(&self.unbonding);
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
            let pending = framework::lock_state(&self.pending_rewards);
            w.put_count(pending.len());
            for (a, r) in pending.iter() {
                w.put_addr(a).put_u64(*r);
            }
        }
        {
            let rpt = framework::lock_state(&self.reward_per_token);
            w.put_count(rpt.len());
            for (a, r) in rpt.iter() {
                w.put_addr(a).put_u128(*r);
            }
            let debt = framework::lock_state(&self.reward_debt);
            w.put_count(debt.len());
            for ((d, v), r) in debt.iter() {
                w.put_addr(d).put_addr(v).put_u128(*r);
            }
            let self_debt = framework::lock_state(&self.self_debt);
            w.put_count(self_debt.len());
            for (a, r) in self_debt.iter() {
                w.put_addr(a).put_u128(*r);
            }
            let index = framework::lock_state(&self.delegator_index);
            w.put_count(index.len());
            for (d, validators) in index.iter() {
                w.put_addr(d).put_count(validators.len());
                for v in validators {
                    w.put_addr(v);
                }
            }
            let totals = framework::lock_state(&self.delegated_total);
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
        let pending_keys = framework::lock_state(&self.pending_key_changes);
        w.put_count(pending_keys.len());
        for (a, k) in pending_keys.iter() {
            w.put_addr(a).put_bytes(k);
        }
        let adds = framework::lock_state(&self.pending_validator_adds);
        w.put_count(adds.len());
        for (a, k) in adds.iter() {
            w.put_addr(a).put_bytes(k);
        }
        let removes = framework::lock_state(&self.pending_validator_removes);
        w.put_count(removes.len());
        for a in removes.iter() {
            w.put_addr(a);
        }
        let keys = framework::lock_state(&self.bls_keys);
        w.put_count(keys.len());
        for (a, k) in keys.iter() {
            w.put_addr(a).put_bytes(k);
        }
        let jailed = framework::lock_state(&self.jailed);
        w.put_count(jailed.len());
        for (a, h) in jailed.iter() {
            w.put_addr(a).put_u64(*h);
        }
        let pending_jails = framework::lock_state(&self.pending_jails);
        w.put_count(pending_jails.len());
        for a in pending_jails.iter() {
            w.put_addr(a);
        }
        let pending_unjails = framework::lock_state(&self.pending_unjails);
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
        match *framework::lock_state(&self.scheduled_halt) {
            Some(h) => {
                w.put_u8(1).put_u64(h);
            }
            None => {
                w.put_u8(0);
            }
        }
        {
            let seen = framework::lock_state(&self.seen_evidence);
            w.put_count(seen.len());
            for h in seen.iter() {
                w.put_root(h);
            }
            let attendance = framework::lock_state(&self.attendance);
            w.put_count(attendance.len());
            for (a, ring) in attendance.iter() {
                w.put_addr(a).put_count(ring.len());
                for present in ring {
                    w.put_bool(*present);
                }
            }
        }
        w.put_u64(*framework::lock_state(&self.current_height));
        // ── Trailing section (v2): retired consensus keys ──
        // Evidence verification consults the retired set for
        // proofs spanning a key rotation — committed because two
        // replicas disagreeing on it disagree on whether a proof
        // verifies. Appended last so pre-upgrade blobs decode
        // with the empty-history default.
        {
            let retired = framework::lock_state(&self.retired_bls_keys);
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

    /// The delegator's bonded amount with a validator.
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn delegation(&self, delegator: &Address, validator: &Address) -> u64 {
        framework::lock_state(&self.delegations)
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
        let mut store = framework::lock_state(&self.store);
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
        framework::lock_state(&self.ledger).clone().ok_or_else(|| {
            ExecError::ModuleRejected(
                "staking: balance ledger not wired (cannot settle delegation)".to_string(),
            )
        })
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
            let validators = framework::lock_state(&self.validators);
            if !validators.contains_key(&validator) {
                return Err(ExecError::ModuleRejected(
                    "delegate: validator not registered".to_string(),
                ));
            }
        }
        // Debit first: if the transfer fails nothing is recorded.
        ledger.transfer(&delegator, &BONDED_POOL, amount)?;

        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
        // Reward accounting must settle on the *pre-mutation*
        // position: the delegation earns rewards accrued while it
        // existed, and the validator's self-share shrinks as
        // `delegated_total` grows.
        let current_delegation = delegations.get(&(delegator, validator)).copied().unwrap_or(0);
        self.settle_delegation(delegator, validator, current_delegation);
        {
            let mut totals = framework::lock_state(&self.delegated_total);
            let stake_now = validators.get(&validator).copied().unwrap_or(0);
            let self_share =
                Self::self_share_of(stake_now, totals.get(&validator).copied().unwrap_or(0));
            self.settle_self_share(validator, self_share);
            *totals.entry(validator).or_insert(0) += amount;
        }
        framework::lock_state(&self.delegator_index)
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
        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
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
            framework::lock_state(&self.delegator_index)
                .get_mut(&delegator)
                .map(|set| set.remove(&validator));
        }
        if let Some(t) = framework::lock_state(&self.delegated_total).get_mut(&validator) {
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
        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
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
            let mut totals = framework::lock_state(&self.delegated_total);
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
            framework::lock_state(&self.delegator_index)
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

        let current = *framework::lock_state(&self.current_height);
        let completion = current.saturating_add(self.unbonding_period);
        framework::lock_state(&self.unbonding).push(UnbondingEntry {
            delegator,
            validator,
            amount,
            completion_height: completion,
        });
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
            let mut unbonding = framework::lock_state(&self.unbonding);
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
        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
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
        *framework::lock_state(&self.delegated_total).entry(validator).or_insert(0) += amount;
        framework::lock_state(&self.delegator_index)
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
        if !framework::lock_state(&self.validators).contains_key(&validator) {
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
        let mut validators = framework::lock_state(&self.validators);
        let mut delegations = framework::lock_state(&self.delegations);
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
            let totals = framework::lock_state(&self.delegated_total);
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
                    framework::lock_state(&self.delegator_index)
                        .get_mut(&d)
                        .map(|set| set.remove(&validator));
                } else {
                    delegations.insert((d, validator), a);
                }
                self.store_delegation_state(validator, d, new_stake, a);
            }
            if let Some(t) = framework::lock_state(&self.delegated_total).get_mut(&validator) {
                *t = t.saturating_sub(applied);
            }
            burned_from_pool = applied;
        }
        drop(delegations);
        drop(validators);

        // Burn only the amount removed from pool-backed delegations —
        // unattributed stake (genesis self-stake) was never in the
        // pool, so burning it would overdraw.
        if burned_from_pool > 0
            && let Some(ledger) = framework::lock_state(&self.ledger).clone()
        {
            // Burn = debit the pool with no credit — supply
            // shrinks (Ethereum burn semantics; cleaner than
            // accumulating at the zero address).
            let _ = ledger.debit(&BONDED_POOL, burned_from_pool);
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
            let bls_keys = framework::lock_state(&self.bls_keys);
            if let Some(k) = bls_keys.get(&validator) {
                candidates.push(k.clone());
            }
        }
        {
            let retired = framework::lock_state(&self.retired_bls_keys);
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
            let seen = framework::lock_state(&self.seen_evidence);
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

        let height = *framework::lock_state(&self.current_height);
        let already_jailed =
            framework::lock_state(&self.jailed).insert(validator, height).is_some();
        if !already_jailed {
            framework::lock_state(&self.pending_jails).push(validator);
        }
        framework::lock_state(&self.seen_evidence).insert(offense_id);

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
        let jailed_at = framework::lock_state(&self.jailed)
            .get(&validator)
            .copied()
            .ok_or(ExecError::ModuleRejected("unjail: validator is not jailed".to_string()))?;
        let height = *framework::lock_state(&self.current_height);
        if height.saturating_sub(jailed_at) < MIN_JAIL_BLOCKS {
            return Err(ExecError::ModuleRejected(format!(
                "unjail: {MIN_JAIL_BLOCKS}-block jail period not elapsed"
            )));
        }
        if self.stake(&validator) == 0 {
            return Err(ExecError::ModuleRejected("unjail: validator has no stake".to_string()));
        }
        if !framework::lock_state(&self.bls_keys).contains_key(&validator) {
            return Err(ExecError::ModuleRejected(
                "unjail: no consensus key on record".to_string(),
            ));
        }

        framework::lock_state(&self.jailed).remove(&validator);
        framework::lock_state(&self.pending_unjails).push(validator);

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
        let current = *framework::lock_state(&self.current_height);
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
                let now = *framework::lock_state(&self.current_height);
                let events = if halt_height != 0 && halt_height <= now {
                    vec![Event {
                        module: "staking",
                        kind: "schedule_halt_stale",
                        data: msg.to_vec(),
                    }]
                } else {
                    *framework::lock_state(&self.scheduled_halt) =
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
            let mut pending = framework::lock_state(&self.pending_rewards);
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
        let validators = framework::lock_state(&self.validators);
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
        if framework::lock_state(&self.bls_keys)
            .iter()
            .any(|(a, k)| *a != validator && *k == new_key)
        {
            return Err(ExecError::ModuleRejected(
                "key_change: consensus key already in use".to_string(),
            ));
        }
        drop(validators); // release lock before acquiring pending_key_changes

        framework::lock_state(&self.pending_key_changes).insert(validator, new_key);

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
                    framework::lock_state(&self.validators).insert(new_validator, 0);
                    // Record the consensus key immediately — evidence
                    // submitted before the rotation still needs it
                    // for verification. A re-admission overwrites
                    // the previous live key — retire it rather
                    // than dropping the one a pending proof needs.
                    let displaced = framework::lock_state(&self.bls_keys)
                        .insert(new_validator, bls_key.clone());
                    if let Some(old) = displaced
                        && old != bls_key
                    {
                        self.retire_key(new_validator, old);
                    }
                    framework::lock_state(&self.pending_validator_adds)
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
        let validators = framework::lock_state(&self.validators);
        if validators.contains_key(candidate) {
            return Err(ExecError::ModuleRejected(
                "validator_add: validator already exists".to_string(),
            ));
        }
        let pending_adds = framework::lock_state(&self.pending_validator_adds);
        if pending_adds.iter().any(|(a, _)| a == candidate) {
            return Err(ExecError::ModuleRejected(
                "validator_add: validator already pending".to_string(),
            ));
        }
        let bls_keys = framework::lock_state(&self.bls_keys);
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
        let validators = framework::lock_state(&self.validators);
        if !validators.contains_key(validator) {
            return Err(ExecError::ModuleRejected(
                "validator_remove: validator not found".to_string(),
            ));
        }
        let pending_removes = framework::lock_state(&self.pending_validator_removes);
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
        let jailed = framework::lock_state(&self.jailed);
        let staying_powered = validators
            .iter()
            .filter(|(a, s)| **s > 0 && !pending_removes.contains(*a) && !jailed.contains_key(*a))
            .count();
        if staying_powered <= 1
            && framework::lock_state(&self.pending_validator_adds)
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
        let mut pending_adds = framework::lock_state(&self.pending_validator_adds);
        if let Some(pos) = pending_adds.iter().position(|(a, _)| a == validator) {
            pending_adds.remove(pos);
            drop(pending_adds);
            self.cancel_pending_add(validator);
            return;
        }
        drop(pending_adds);
        framework::lock_state(&self.pending_validator_removes).push(*validator);
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
        let current = *framework::lock_state(&self.current_height);
        let completion = current.saturating_add(self.unbonding_period);
        let mut delegations = framework::lock_state(&self.delegations);
        let affected: Vec<(Address, u64)> = delegations
            .iter()
            .filter(|((_, v), _)| v == validator)
            .map(|((d, _), amount)| (*d, *amount))
            .collect();
        {
            let mut unbonding = framework::lock_state(&self.unbonding);
            let mut delegator_index = framework::lock_state(&self.delegator_index);
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
        framework::lock_state(&self.delegated_total).remove(validator);
        framework::lock_state(&self.validators).remove(validator);
        // Retire rather than drop: the cancelled candidate's key
        // never went live, but a previous incarnation's key may be
        // what this entry held — the uniform retire rule applies.
        let removed_key = framework::lock_state(&self.bls_keys).remove(validator);
        if let Some(old) = removed_key {
            self.retire_key(*validator, old);
        }
        // Clear the store mirror so queries cannot report a phantom
        // stake or delegation for the cancelled candidate.
        {
            let mut store = framework::lock_state(&self.store);
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
                framework::lock_state(&self.validators).contains_key(&Address(addr))
            }
            // [type][height: 8B] — dead once the tip passes the
            // target height (height 0 = "cancel halt" never dies).
            Some(&msg_type::SCHEDULE_HALT) => {
                if action.len() != 1 + 8 {
                    return false;
                }
                let Ok(bits) = <[u8; 8]>::try_from(&action[1..9]) else { return false };
                let halt = u64::from_le_bytes(bits);
                let current = *framework::lock_state(&self.current_height);
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
        let rpt = *framework::lock_state(&self.reward_per_token).get(&validator).unwrap_or(&0);
        let mut debts = framework::lock_state(&self.reward_debt);
        let debt = debts.entry((delegator, validator)).or_insert(0);
        if rpt > *debt && delegation > 0 {
            let accrued = u128::from(delegation).saturating_mul(rpt - *debt) / RPT_SCALE;
            if accrued > 0 {
                let mut pending = framework::lock_state(&self.pending_rewards);
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
        let rpt = *framework::lock_state(&self.reward_per_token).get(&validator).unwrap_or(&0);
        let mut debts = framework::lock_state(&self.self_debt);
        let debt = debts.entry(validator).or_insert(0);
        if rpt > *debt && self_share > 0 {
            let accrued = u128::from(self_share).saturating_mul(rpt - *debt) / RPT_SCALE;
            if accrued > 0 {
                let mut pending = framework::lock_state(&self.pending_rewards);
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
        let delegator_vs: Vec<Address> = framework::lock_state(&self.delegator_index)
            .get(&account)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();
        let delegations = framework::lock_state(&self.delegations);
        for v in delegator_vs {
            let amount = delegations.get(&(account, v)).copied().unwrap_or(0);
            self.settle_delegation(account, v, amount);
        }
        drop(delegations);
        let validators = framework::lock_state(&self.validators);
        if let Some(&stake) = validators.get(&account) {
            let delegated = framework::lock_state(&self.delegated_total);
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
        let validators = framework::lock_state(&self.validators);
        let pending_removes = framework::lock_state(&self.pending_validator_removes);
        // Jailed validators stop earning too — jailing is exclusion
        // from consensus and rewards, not just consensus.
        let jailed = framework::lock_state(&self.jailed);
        let is_eligible =
            |a: &Address, s: u64| s > 0 && !pending_removes.contains(a) && !jailed.contains_key(a);
        let eligible: u64 =
            validators.iter().filter(|(a, s)| is_eligible(a, **s)).map(|(_, s)| *s).sum();
        if eligible == 0 {
            return;
        }
        let mut rpt = framework::lock_state(&self.reward_per_token);
        for (addr, stake) in validators.iter() {
            if !is_eligible(addr, *stake) {
                continue;
            }
            // Money math in u128, not u64 saturation: at realistic
            // token scale `total_reward * stake` overflows u64
            // (1e10 units × 1e10 stake = 1e20 > u64::MAX), and
            // saturating there under-pays a large validator to
            // `u64::MAX / eligible` — a silent obligation change,
            // exactly what saturation-as-error-handling hides. The
            // u128 product cannot overflow (two u64s), and since
            // `stake <= eligible` the quotient is ≤ `total_reward`,
            // so the narrowing is provably lossless.
            let reward =
                u64::try_from(u128::from(total_reward) * u128::from(*stake) / u128::from(eligible))
                    .unwrap_or(u64::MAX);
            if reward > 0 {
                *rpt.entry(*addr).or_insert(0) +=
                    u128::from(reward).saturating_mul(RPT_SCALE).saturating_div(u128::from(*stake));
            }
        }
    }
}

#[cfg(test)]
mod tests;
