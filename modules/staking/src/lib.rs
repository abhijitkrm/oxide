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
use framework::{Balances, module_id};
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
    /// The KV store for state root computation, with its
    /// set-commitment root maintained incrementally (7.4): every
    /// `insert`/`remove` folds the record's leaf hash in O(1) instead
    /// of `subtree_root` re-walking every entry per block.
    store: Mutex<framework::CommittedStore>,
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
    delegations: Mutex<framework::CommittedMap<(Address, Address), u64>>,
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
    pending_rewards: Mutex<framework::CommittedMap<Address, u64>>,
    /// Cumulative reward units per bonded stake unit per validator,
    /// scaled by [`RPT_SCALE`] — the "reward-per-token" accumulator.
    /// `end_block` grows it by `block_reward_v × SCALE / stake_v`.
    reward_per_token: Mutex<BTreeMap<Address, u128>>,
    /// The `reward_per_token` value at which each delegation last
    /// settled — `(delegator, validator) → debt`. Pending reward =
    /// `delegation × (rpt − debt) / SCALE`.
    reward_debt: Mutex<framework::CommittedMap<(Address, Address), u128>>,
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
    delegator_index: Mutex<framework::CommittedMap<Address, std::collections::BTreeSet<Address>>>,
    /// Sum of live delegations per validator — `stake −
    /// delegated_total` is the validator's self-share that accrues
    /// through `self_debt`.
    delegated_total: Mutex<framework::CommittedMap<Address, u64>>,
    /// Pending BLS key changes per validator address. The new key
    /// takes effect at the next epoch rotation — the consensus
    /// engine reads these via `take_key_changes` at the epoch
    /// boundary. Stored as `ValidatedPublicKey`: admission already
    /// proved point + subgroup validity, so the token that crosses
    /// to the engine is that proof.
    pending_key_changes: Mutex<BTreeMap<Address, crypto::bls_signer::ValidatedPublicKey>>,
    /// Pending validator additions: `(address, bls_public_key)`.
    /// The new validator joins the set at the next epoch rotation —
    /// and only if it has *bonded* stake by then (delegations to the
    /// registered candidate): admission authorizes membership, the
    /// ledger debit proves collateral. The consensus engine reads
    /// these via `take_validator_changes`.
    pending_validator_adds: Mutex<Vec<(Address, crypto::bls_signer::ValidatedPublicKey)>>,
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
    /// The *current* BLS consensus key per validator — held as
    /// `ValidatedPublicKey`, the proof that every stored key passed
    /// point + subgroup validation at admission (`PoP` paths) or
    /// decode (snapshot/genesis). Unlike `pending_key_changes`
    /// (drained each rotation), this map persists so
    /// `handle_evidence` can verify vote signatures against the key
    /// the validator is known by. Set at `VALIDATOR_ADD` /
    /// `genesis_set_bls_key`, updated when `take_key_changes`
    /// applies a rotation, never deleted — a stale key is harmless
    /// (evidence requires the validator to still exist) and
    /// re-adds overwrite it.
    bls_keys: Mutex<BTreeMap<Address, crypto::bls_signer::ValidatedPublicKey>>,
    /// Recently displaced consensus keys per validator, oldest
    /// first, capped at [`EVIDENCE_KEY_HISTORY`]. A rotation or
    /// re-admission moves the previous key here: the key can no
    /// longer sign new votes but `handle_evidence` must still
    /// verify proofs for votes signed BEFORE the rotation —
    /// otherwise a validator could rotate away from an offense
    /// (the v1 bound: evidence died the moment keys changed).
    /// Committed state: two replicas disagreeing on the retired
    /// set disagree on whether a proof verifies.
    retired_bls_keys: Mutex<BTreeMap<Address, Vec<crypto::bls_signer::ValidatedPublicKey>>>,
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

/// Per-map salts inside [`Domain::CommittedLeaf`](crypto::hash::Domain)
/// preimages — the separation that keeps a (key, value) encoding from
/// aliasing across committed maps. Module-local constants; distinct
/// numbers are the only requirement, and they are append-only (a new
/// committed map takes the next value; an existing tag never changes —
/// the leaf hash is part of the state-root preimage).
const MAP_TAG_STORE: u64 = 1;
const MAP_TAG_DELEGATIONS: u64 = 2;
const MAP_TAG_REWARD_DEBT: u64 = 3;
const MAP_TAG_DELEGATOR_INDEX: u64 = 4;
const MAP_TAG_DELEGATED_TOTAL: u64 = 5;
const MAP_TAG_PENDING_REWARDS: u64 = 6;

/// The committed KV-subtree leaf: `key ‖ u64-le vlen ‖ value` — the
/// same record shape `subtree_root_map` folds sequentially, so the
/// fold commits the same information under an incremental
/// construction.
// The `fn(&K, &V) -> Hash` signature is fixed by `CommittedMap`'s
// leaf slot — borrowing `Vec<u8>`/`u64` is the uniform shape, not a
// style choice.
#[allow(clippy::ptr_arg)]
fn store_leaf(k: &Vec<u8>, v: &Vec<u8>) -> Hash {
    framework::committed_store_leaf(MAP_TAG_STORE, k, v)
}

/// `(delegator ‖ validator ‖ amount_le)` — the same field order
/// `commit_stake_state` writes into the canonical stream.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn delegations_leaf(k: &(Address, Address), v: &u64) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(&k.0).put_addr(&k.1).put_u64(*v);
    framework::committed_leaf(MAP_TAG_DELEGATIONS, w.as_bytes())
}

/// `(delegator ‖ validator ‖ u128 debt_le)` — mirrors
/// `commit_reward_state`'s `reward_debt` record.
fn reward_debt_leaf(k: &(Address, Address), v: &u128) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(&k.0).put_addr(&k.1).put_u128(*v);
    framework::committed_leaf(MAP_TAG_REWARD_DEBT, w.as_bytes())
}

/// `(delegator ‖ count ‖ sorted validator addrs)` — mirrors the
/// `delegator_index` record: the value is the whole validator set,
/// so a membership change re-encodes that one set (bounded by a
/// delegator's validator count, not the map's).
fn delegator_index_leaf(k: &Address, v: &std::collections::BTreeSet<Address>) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(k).put_count(v.len());
    for validator in v {
        w.put_addr(validator);
    }
    framework::committed_leaf(MAP_TAG_DELEGATOR_INDEX, w.as_bytes())
}

/// `(validator ‖ total_le)` — mirrors `delegated_total`'s record.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn delegated_total_leaf(k: &Address, v: &u64) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(k).put_u64(*v);
    framework::committed_leaf(MAP_TAG_DELEGATED_TOTAL, w.as_bytes())
}

/// `(account ‖ reward_le)` — mirrors `pending_rewards`' record.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn pending_rewards_leaf(k: &Address, v: &u64) -> Hash {
    let mut w = framework::CanonicalState::new();
    w.put_addr(k).put_u64(*v);
    framework::committed_leaf(MAP_TAG_PENDING_REWARDS, w.as_bytes())
}

mod commit;
mod delegation;
mod rewards;
mod slashing;
mod validators;

impl StakingModule {
    /// Construct a fresh staking module with no validators and
    /// default parameters.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(framework::CommittedStore::new(store_leaf)),
            validators: Mutex::new(BTreeMap::new()),
            delegations: Mutex::new(framework::CommittedMap::new(delegations_leaf)),
            ledger: Mutex::new(None),
            unbonding: Mutex::new(Vec::new()),
            pending_rewards: Mutex::new(framework::CommittedMap::new(pending_rewards_leaf)),
            reward_per_token: Mutex::new(BTreeMap::new()),
            reward_debt: Mutex::new(framework::CommittedMap::new(reward_debt_leaf)),
            self_debt: Mutex::new(BTreeMap::new()),
            delegator_index: Mutex::new(framework::CommittedMap::new(delegator_index_leaf)),
            delegated_total: Mutex::new(framework::CommittedMap::new(delegated_total_leaf)),
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
    /// Panics if `key` is not a valid compressed BLS12-381 key or
    /// the mutex is poisoned.
    pub fn genesis_set_bls_key(&self, validator: Address, key: &[u8]) {
        // Genesis has no PoP to check — the point validation inside
        // the token constructor is the only thing keeping a typo'd
        // key from wedging the validator's votes for the chain's
        // whole life.
        let pk = crypto::bls_signer::ValidatedPublicKey::from_bytes(key)
            .expect("genesis BLS key must decode to a valid group element");
        framework::lock_state(&self.bls_keys).insert(validator, pk);
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
    pub fn take_key_changes(&self) -> Vec<(Address, crypto::bls_signer::ValidatedPublicKey)> {
        let changes: Vec<(Address, crypto::bls_signer::ValidatedPublicKey)> =
            std::mem::take(&mut *framework::lock_state(&self.pending_key_changes))
                .into_iter()
                .collect();
        let mut bls_keys = framework::lock_state(&self.bls_keys);
        for (addr, key) in &changes {
            if let Some(old) = bls_keys.insert(*addr, *key)
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
    fn retire_key(&self, validator: Address, old_key: crypto::bls_signer::ValidatedPublicKey) {
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
                    adds.push((addr, *key, *stake));
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
        // C8: commit EVERY field that can affect future execution —
        // via the incremental root preimage (7.4): delegator-scale
        // maps contribute their maintained fold root, so a block
        // costs O(validator-scale state) rather than re-serializing
        // every delegation record ever written. The serialized
        // sections are byte-identical to `write_committed`'s, and
        // `write_root_preimage` is its schema pair — a field added
        // there must land here too.
        //
        // Excluded: `ledger` (assembly wiring), `unbonding_period` /
        // `block_reward` (construction config, never tx-mutated).
        // Guards are all taken before the view is built — consistent
        // lock order with handlers (each field locked once).
        let store = framework::lock_state(&self.store);
        let validators = framework::lock_state(&self.validators);
        let delegations = framework::lock_state(&self.delegations);
        let unbonding = framework::lock_state(&self.unbonding);
        let pending_rewards = framework::lock_state(&self.pending_rewards);
        let reward_per_token = framework::lock_state(&self.reward_per_token);
        let reward_debt = framework::lock_state(&self.reward_debt);
        let self_debt = framework::lock_state(&self.self_debt);
        let delegator_index = framework::lock_state(&self.delegator_index);
        let delegated_total = framework::lock_state(&self.delegated_total);
        let pending_key_changes = framework::lock_state(&self.pending_key_changes);
        let pending_validator_adds = framework::lock_state(&self.pending_validator_adds);
        let pending_validator_removes = framework::lock_state(&self.pending_validator_removes);
        let bls_keys = framework::lock_state(&self.bls_keys);
        let retired_bls_keys = framework::lock_state(&self.retired_bls_keys);
        let jailed = framework::lock_state(&self.jailed);
        let pending_jails = framework::lock_state(&self.pending_jails);
        let pending_unjails = framework::lock_state(&self.pending_unjails);
        let scheduled_halt = framework::lock_state(&self.scheduled_halt);
        let seen_evidence = framework::lock_state(&self.seen_evidence);
        let attendance = framework::lock_state(&self.attendance);
        let current_height = framework::lock_state(&self.current_height);
        let view = commit::RootView {
            store_fold: store.root(),
            validators: &validators,
            delegations_fold: delegations.root(),
            unbonding: &unbonding,
            pending_rewards_fold: pending_rewards.root(),
            reward_per_token: &reward_per_token,
            reward_debt_fold: reward_debt.root(),
            self_debt: &self_debt,
            delegator_index_fold: delegator_index.root(),
            delegated_total_fold: delegated_total.root(),
            pending_key_changes: &pending_key_changes,
            pending_validator_adds: &pending_validator_adds,
            pending_validator_removes: &pending_validator_removes,
            endorsements: &self.endorsements,
            bls_keys: &bls_keys,
            retired_bls_keys: &retired_bls_keys,
            jailed: &jailed,
            pending_jails: &pending_jails,
            pending_unjails: &pending_unjails,
            scheduled_halt: *scheduled_halt,
            seen_evidence: &seen_evidence,
            attendance: &attendance,
            current_height: *current_height,
        };
        let mut w = framework::CanonicalState::new();
        commit::write_root_preimage(&view, &mut w);
        w.root()
    }

    /// Export the committed state as one canonical blob —
    /// `canon ‖ store`. The canon section is the snapshot's install
    /// payload (the `write_committed` bytes); a peer verifies the
    /// claimed root by decoding it and recomputing the incremental
    /// root over the staged state (`inspect_state`).
    fn export_state(&self) -> Option<storage::Snapshot> {
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        Some(storage::Snapshot {
            height: 0,
            entries: vec![(
                framework::state_blob_key(),
                framework::encode_state_blob(
                    w.as_bytes(),
                    framework::lock_state(&self.store).inner(),
                ),
            )],
        })
    }

    /// Verify a staged snapshot's claimed root without mutating:
    /// decode the blob, check the store section hashes to the
    /// committed subtree root, fully decode every field with all
    /// internal invariants enforced, then recompute the incremental
    /// root over the staged state — folded maps fold over the staged
    /// `BTreeMap`s (`fold_map`), serialized sections serialize the
    /// staged fields, so the result equals the `state_root` this
    /// state would produce once installed.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let (_canon, staged, store) = framework::stage_blob_snapshot(snapshot, |r, store| {
            decode::decode_committed(r, store)
        })?;
        let view = commit::RootView {
            store_fold: framework::CommittedStore::fold_map(&store, store_leaf),
            validators: &staged.validators,
            delegations_fold: framework::CommittedMap::fold_map(
                &staged.delegations,
                delegations_leaf,
            ),
            unbonding: &staged.unbonding,
            pending_rewards_fold: framework::CommittedMap::fold_map(
                &staged.pending_rewards,
                pending_rewards_leaf,
            ),
            reward_per_token: &staged.reward_per_token,
            reward_debt_fold: framework::CommittedMap::fold_map(
                &staged.reward_debt,
                reward_debt_leaf,
            ),
            self_debt: &staged.self_debt,
            delegator_index_fold: framework::CommittedMap::fold_map(
                &staged.delegator_index,
                delegator_index_leaf,
            ),
            delegated_total_fold: framework::CommittedMap::fold_map(
                &staged.delegated_total,
                delegated_total_leaf,
            ),
            pending_key_changes: &staged.pending_key_changes,
            pending_validator_adds: &staged.pending_validator_adds,
            pending_validator_removes: &staged.pending_validator_removes,
            endorsements: &staged.endorsements,
            bls_keys: &staged.bls_keys,
            retired_bls_keys: &staged.retired_bls_keys,
            jailed: &staged.jailed,
            pending_jails: &staged.pending_jails,
            pending_unjails: &staged.pending_unjails,
            scheduled_halt: staged.scheduled_halt,
            seen_evidence: &staged.seen_evidence,
            attendance: &staged.attendance,
            current_height: staged.current_height,
        };
        let mut w = framework::CanonicalState::new();
        commit::write_root_preimage(&view, &mut w);
        Ok(w.root())
    }

    /// Install staged state after `inspect_state` has proven it —
    /// the same staged decode runs again, then every field swaps in
    /// (decode first, mutate second).
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let (_canon, staged, store) =
            framework::stage_blob_snapshot(snapshot, |r, s| decode::decode_committed(r, s))?;
        *framework::lock_state(&self.store) =
            framework::CommittedStore::from_map(store, store_leaf);
        *framework::lock_state(&self.validators) = staged.validators;
        *framework::lock_state(&self.delegations) =
            framework::CommittedMap::from_map(staged.delegations, delegations_leaf);
        *framework::lock_state(&self.unbonding) = staged.unbonding;
        *framework::lock_state(&self.pending_rewards) =
            framework::CommittedMap::from_map(staged.pending_rewards, pending_rewards_leaf);
        *framework::lock_state(&self.reward_per_token) = staged.reward_per_token;
        *framework::lock_state(&self.reward_debt) =
            framework::CommittedMap::from_map(staged.reward_debt, reward_debt_leaf);
        *framework::lock_state(&self.self_debt) = staged.self_debt;
        *framework::lock_state(&self.delegator_index) =
            framework::CommittedMap::from_map(staged.delegator_index, delegator_index_leaf);
        *framework::lock_state(&self.delegated_total) =
            framework::CommittedMap::from_map(staged.delegated_total, delegated_total_leaf);
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

    fn take_key_changes(&self) -> Vec<(Address, crypto::bls_signer::ValidatedPublicKey)> {
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
}

#[cfg(test)]
mod tests;
