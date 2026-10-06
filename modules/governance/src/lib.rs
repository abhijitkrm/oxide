//! Oxide governance module — on-chain parameter changes and market
//! listing.
//!
//! The governance module is the module-equivalent of Cosmos SDK's
//! `x/gov`. It allows token holders to propose and vote on parameter
//! changes for other modules.
//!
//! # Lifecycle
//!
//! A proposal moves through an explicit machine — every transition
//! is decided by committed state, so two nodes replaying the same
//! block always agree on where a proposal stands:
//!
//! ```text
//! Propose ──▶ DepositPeriod ──(deposit ≥ MIN_DEPOSIT)──▶ Voting
//!                  │                                       │
//!            deadline passes                             deadline:
//!            underfunded                       quorum? veto? majority?
//!                  │                                       │
//!                  ▼                    ┌──── FailedQuorum (deposits burned)
//!               Expired                 ├──── Vetoed       (deposits burned)
//!              (deposits burned)        ├──── Rejected     (deposits refunded)
//!                                       └──── Passed ──(timelock)──▶ Applied / ApplyFailed
//!                                                              (deposits refunded at decision)
//! ```
//!
//! - **Deposit escrow.** A fresh proposal collects deposits via
//!   `TAG_DEPOSIT`; each is moved `depositor → GOVERNANCE_ESCROW`
//!   through the wired [`Balances`] ledger and recorded
//!   per-depositor so it can be returned. Crossing `min_deposit`
//!   opens voting (`end_height` is set then, not at submission).
//!   A proposal still underfunded at `deposit_deadline` expires and
//!   its deposits are burned — the deposit is an anti-spam bond,
//!   refunded only when the proposal actually reached a decision.
//! - **Quorum.** At `end_height` the tally only decides if turnout
//!   meets `quorum_bps` of the committee's *current* total power;
//!   otherwise `FailedQuorum` (deposits burned — a proposal nobody
//!   showed up for must not refund free spam).
//! - **Veto.** `no ≥ veto_bps × total_power` vetoes regardless of
//!   the majority — a blocking minority of bonded power kills a
//!   hostile change outright (deposits burned).
//! - **Timelock + apply.** Passed proposals wait `timelock` blocks,
//!   then `param_key` is routed by its `"<name>."` prefix to a
//!   registered [`ParameterSink`](framework::ParameterSink); the
//!   sink applies or rejects (`ApplyFailed` is terminal — a stale
//!   value is never retried under newer state). A key with no
//!   registered prefix is advisory: the vote is the outcome and the
//!   proposal closes `Applied` with a `proposal_noop` event.
//! - **Fail closed.** No ledger wired → deposits (and therefore
//!   voting) are impossible; no committee → no vote counts and
//!   quorum can never be met. `min_deposit = 0` is an explicit
//!   configuration, not a silent fallback.
//!
//! Voting power is bonded stake via the wired `Committee` (staking):
//! a vote's weight is the voter's power at cast, zero-power senders
//! cannot vote, and a second vote replaces the first with the tally
//! corrected.
//!
//! # Messages
//!
//! - `Propose`: `[TAG_PROPOSE][param_key_len: 2B BE][param_key][param_val_len: 2B BE][param_val]`
//! - `Vote`: `[TAG_VOTE][proposal_id: 8B LE][vote: 1B (0=no, 1=yes)]`
//! - `Deposit`: `[TAG_DEPOSIT][proposal_id: 8B LE][amount: 8B LE]`
//!
//! # State
//!
//! - Proposals: `[proposal_id: 8B LE] -> [encoded proposal]`
//! - Votes: `[proposal_id: 8B LE][voter: 20B] -> [vote: 1B][power: 8B LE]`
//! - Next proposal ID: `next_proposal_id -> [8B LE]`

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use executor::{Event, ExecError, Module, RejectCategory, TxContext};
use framework::{Balances, Committee, KVStore, ParameterSink, module_id, subtree_root};
use primitives::{Address, Hash, Height};

/// Wire tag: governance proposal submission.
const TAG_PROPOSE: u8 = 1;
/// Wire tag: a vote on an open proposal.
const TAG_VOTE: u8 = 2;
/// Wire tag: a deposit toward a proposal's funding threshold.
const TAG_DEPOSIT: u8 = 3;

/// Module-owned escrow account holding proposal deposits while a
/// proposal is live. Deposits sit here from `TAG_DEPOSIT` until the
/// decision point, then refund to the depositors (Rejected/Passed)
/// or burn — debited out without a credit — on `Expired`,
/// `FailedQuorum`, and `Vetoed`. `0x60`-repeating is a
/// never-generated address (no key can sign for it), same pattern
/// as perps' `CLEARING_ACCOUNT`.
const GOVERNANCE_ESCROW: Address = Address([0x60; 20]);

/// Minimum escrowed deposit before a proposal opens for voting, in
/// ledger base units. A real chain must set this high enough that
/// spamming the proposal queue costs money — the value is a
/// deliberate placeholder pending tokenomics (the devnet's
/// `MemoryBalances`/EVM-wei denominations make any absolute number
/// an approximation). `with_min_deposit(0)` disables the deposit
/// gate entirely for tests and deployments that gate proposals
/// out-of-band.
const MIN_DEPOSIT: u64 = 1_000_000;

/// How long a proposal may sit collecting deposits before it
/// expires unfunded, in blocks: `deposit_deadline = submit_height +
/// DEPOSIT_PERIOD_BLOCKS`. Bounded so unfundable proposals clean
/// themselves out of committed state instead of lingering forever.
const DEPOSIT_PERIOD_BLOCKS: u64 = 500;

/// Minimum turnout for a tally to decide anything: `yes + no` must
/// reach `QUORUM_BPS / 10_000` of the committee's total power at
/// finalize. 3340 bps = 33.4% — the Cosmos default; below it a
/// handful of voters could steer parameters while the chain sleeps.
const QUORUM_BPS: u64 = 3_340;

/// Veto threshold: `no` power reaching `VETO_BPS / 10_000` of total
/// committee power vetoes the proposal regardless of the yes/no
/// split. 3340 bps = a blocking third — the same fraction that can
/// halt consensus, so a coalition too small to stop the chain can
/// still stop a parameter change it considers hostile.
const VETO_BPS: u64 = 3_340;

/// Blocks between a proposal passing and its parameter applying:
/// `apply_height = finalize_height + TIMELOCK_BLOCKS`. The delay is
/// the review window — validators and fullnodes see the decision in
/// the block log (`proposal_finalized`) before the value takes
/// effect and can emergency-halt a clearly-hostile change. 100
/// blocks is a deliberate v1 value (~30 s at 300 ms blocks — enough
/// to prove the window exists, not a substitute for operational
/// review).
const TIMELOCK_BLOCKS: u64 = 100;

/// Maximum distinct depositors per proposal. Every depositor is a
/// committed record refunded individually at decision time —
/// unbounded, a spammer could fill the canon with one-wei records
/// and make the refund pass the most expensive part of
/// `end_block`. 128 depositors is far above any honest funding
/// crowd while keeping both bounded; an existing depositor topping
/// up never counts against it.
const MAX_DEPOSITORS_PER_PROPOSAL: usize = 128;

/// How long a proposal accepts votes, in blocks: `end_height =
/// submit_height + VOTING_PERIOD_BLOCKS`, and `end_block` finalizes
/// it once the height reaches `end_height`. `1_000` blocks is a
/// deliberate v1 value — long enough for devnet tests to exercise
/// the open/finalized lifecycle (~5 min at 300 ms blocks) without a
/// wall-clock scheduler; the parameter-governance path this module
/// enables is the right place to make it configurable later.
const VOTING_PERIOD_BLOCKS: u64 = 1_000;

/// Maximum simultaneously-open proposals. Unbounded proposal
/// creation is attacker-writable state growth for the price of a
/// tx fee; `1_024` open proposals is far above any honest governance
/// cadence while keeping the pending set bounded.
const MAX_OPEN_PROPOSALS: usize = 1_024;

/// Where a proposal sits in its lifecycle — see the module-level
/// diagram. The discriminants are a stable wire encoding (the
/// canonical snapshot writes them as one byte); do not reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    /// Collecting deposits toward `min_deposit`; votes rejected.
    DepositPeriod = 0,
    /// Funded and accepting votes until `end_height`.
    Voting = 1,
    /// Quorum + majority met at `end_height`; applies once
    /// `height ≥ apply_height`.
    Passed = 2,
    /// Quorum met but `yes ≤ no` — terminal; deposits refunded.
    Rejected = 3,
    /// Turnout below quorum at `end_height` — terminal; deposits
    /// burned.
    FailedQuorum = 4,
    /// `no` reached the veto threshold — terminal; deposits burned.
    Vetoed = 5,
    /// Deposit deadline passed underfunded — terminal; deposits
    /// burned.
    Expired = 6,
    /// Timelock elapsed and the parameter applied (or the key was
    /// advisory with no registered sink) — terminal.
    Applied = 7,
    /// Timelock elapsed but the sink rejected the value — terminal;
    /// the governance decision stands, the parameter does not move,
    /// and the proposal is never retried.
    ApplyFailed = 8,
}

impl ProposalStatus {
    /// The tally has been decided — the proposal can no longer
    /// collect deposits or votes. `Passed` counts: its outcome is
    /// fixed even though the apply step is still pending.
    fn is_decided(self) -> bool {
        !matches!(self, Self::DepositPeriod | Self::Voting)
    }

    /// The proposal has fully resolved — nothing further happens to
    /// it. Differs from [`Self::is_decided`] only for `Passed`,
    /// which still owes an apply attempt at `apply_height`.
    fn is_terminal(self) -> bool {
        self.is_decided() && self != Self::Passed
    }

    /// The vote concluded in favor. `ApplyFailed` counts — the
    /// electorate approved; execution is what failed.
    fn did_pass(self) -> bool {
        matches!(self, Self::Passed | Self::Applied | Self::ApplyFailed)
    }

    /// Decode the one-byte canonical form.
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::DepositPeriod),
            1 => Some(Self::Voting),
            2 => Some(Self::Passed),
            3 => Some(Self::Rejected),
            4 => Some(Self::FailedQuorum),
            5 => Some(Self::Vetoed),
            6 => Some(Self::Expired),
            7 => Some(Self::Applied),
            8 => Some(Self::ApplyFailed),
            _ => None,
        }
    }
}

/// A governance proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// The proposal's unique ID.
    pub id: u64,
    /// The proposer's address.
    pub proposer: Address,
    /// The parameter key (e.g., `consensus.base_timeout_ms`).
    pub param_key: Vec<u8>,
    /// The proposed parameter value.
    pub param_val: Vec<u8>,
    /// Yes votes — total VOTING POWER cast yes (bonded stake of the
    /// voters at cast time), not a voter count.
    pub yes_votes: u64,
    /// No votes — voting power cast no.
    pub no_votes: u64,
    /// Lifecycle position — authoritative state the `finalized` and
    /// `passed` flags mirror (they stay as fields for the v1 codec
    /// section; every transition keeps all three consistent).
    pub status: ProposalStatus,
    /// Total deposit escrowed on this proposal so far, in ledger
    /// base units — the sum of the per-depositor records.
    pub deposit: u64,
    /// Funding deadline while in `DepositPeriod`: the proposal
    /// expires at `end_block` once `height ≥ deposit_deadline`.
    /// `0` once voting has opened (no longer meaningful).
    pub deposit_deadline: u64,
    /// The height at which voting closes: votes are accepted for
    /// `height < end_height` only, and `end_block` decides the
    /// proposal once the chain reaches `end_height`. Set when
    /// voting opens (at submission for `min_deposit = 0`, at the
    /// deposit that crosses the threshold otherwise); `0` while in
    /// `DepositPeriod`.
    pub end_height: u64,
    /// The height at which a passed proposal applies — the
    /// finalize height plus `timelock`. `0` unless `status ==
    /// Passed`.
    pub apply_height: u64,
    /// Whether the tally has been decided (`status.is_decided()`).
    /// Kept in sync on every transition; the v1 codec section
    /// writes this flag, so decode can verify the two never
    /// disagree.
    pub finalized: bool,
    /// Whether the proposal's vote concluded in favor
    /// (`status.did_pass()`).
    pub passed: bool,
}

/// A vote on a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vote {
    /// Vote no.
    No = 0,
    /// Vote yes.
    Yes = 1,
}

impl Vote {
    /// Parse a vote from a byte.
    ///
    /// # Errors
    ///
    /// Returns `None` if the byte is not 0 or 1.
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::No),
            1 => Some(Self::Yes),
            _ => None,
        }
    }
}

/// Per-depositor escrow records, keyed by proposal — the refund
/// manifest settled at decision time.
type DepositRecords = BTreeMap<u64, Vec<(Address, u64)>>;

/// The governable lifecycle tunables — the `governance.*`
/// parameter keyspace, held behind atomics so the module's own
/// parameter sink can apply timelocked changes through `&self`
/// (self-governance: the module is its own sink's state).
///
/// Every field is an independent `AtomicU64` — no cross-field
/// invariant exists beyond each key's own validation, so `Relaxed`
/// ordering is correct: the apply's determinism comes from
/// `end_block` ordering on every replica, not memory order.
#[derive(Debug)]
pub struct GovernanceParams {
    /// Voting window in blocks — [`VOTING_PERIOD_BLOCKS`] default.
    /// Governed via `governance.voting_period`; `0` rejected (a
    /// proposal that closes instantly can never reach quorum
    /// legitimately).
    pub voting_period: std::sync::atomic::AtomicU64,
    /// Funding threshold for opening voting — [`MIN_DEPOSIT`]
    /// default; `0` opens voting at submission (a legitimate
    /// configuration). Governed via `governance.min_deposit`.
    pub min_deposit: std::sync::atomic::AtomicU64,
    /// Funding window before an underfunded proposal expires —
    /// [`DEPOSIT_PERIOD_BLOCKS`] default. Governed via
    /// `governance.deposit_period`; `0` rejected (unfunded
    /// proposals would expire in their submit block).
    pub deposit_period: std::sync::atomic::AtomicU64,
    /// Turnout threshold in basis points of total committee power —
    /// [`QUORUM_BPS`] default. Governed via `governance.quorum_bps`;
    /// values above `10_000` (more than all voting power) rejected.
    pub quorum_bps: std::sync::atomic::AtomicU64,
    /// Veto threshold in basis points of total committee power —
    /// [`VETO_BPS`] default. Governed via `governance.veto_bps`;
    /// same `> 10_000` bound.
    pub veto_bps: std::sync::atomic::AtomicU64,
    /// Delay between a proposal passing and its parameter applying —
    /// [`TIMELOCK_BLOCKS`] default; `0` applies at the decision
    /// height (legitimate). Governed via `governance.timelock`.
    pub timelock: std::sync::atomic::AtomicU64,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            voting_period: std::sync::atomic::AtomicU64::new(VOTING_PERIOD_BLOCKS),
            min_deposit: std::sync::atomic::AtomicU64::new(MIN_DEPOSIT),
            deposit_period: std::sync::atomic::AtomicU64::new(DEPOSIT_PERIOD_BLOCKS),
            quorum_bps: std::sync::atomic::AtomicU64::new(QUORUM_BPS),
            veto_bps: std::sync::atomic::AtomicU64::new(VETO_BPS),
            timelock: std::sync::atomic::AtomicU64::new(TIMELOCK_BLOCKS),
        }
    }
}

/// The `governance.*` keyspace — self-governance: the module
/// registers this handle as its own `governance` sink, so its
/// lifecycle knobs are tuned through the same deposited, voted,
/// timelocked path every other module's parameters take. Values
/// are bare `u64` LE payloads (8 bytes); each key validates its
/// own domain (see field docs — zero windows and `>10_000` bps are
/// rejected into `ApplyFailed`, never clamped).
impl ParameterSink for GovernanceParams {
    fn apply_param(&self, key: &[u8], value: &[u8]) -> Result<(), ExecError> {
        let (target, nonzero, capped) = match key {
            b"governance.voting_period" => (&self.voting_period, true, false),
            b"governance.min_deposit" => (&self.min_deposit, false, false),
            b"governance.deposit_period" => (&self.deposit_period, true, false),
            b"governance.quorum_bps" => (&self.quorum_bps, false, true),
            b"governance.veto_bps" => (&self.veto_bps, false, true),
            b"governance.timelock" => (&self.timelock, false, false),
            _ => {
                return Err(ExecError::rejected(
                    RejectCategory::NotFound,
                    "governance: unknown governed parameter",
                ));
            }
        };
        let Ok(v) = <[u8; 8]>::try_from(value) else {
            return Err(ExecError::Malformed);
        };
        let v = u64::from_le_bytes(v);
        if nonzero && v == 0 {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                format!("{}: window must be > 0", String::from_utf8_lossy(key)),
            ));
        }
        if capped && v > 10_000 {
            return Err(ExecError::rejected(
                RejectCategory::InvalidInput,
                format!("{}: bps must be <= 10_000", String::from_utf8_lossy(key)),
            ));
        }
        target.store(v, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// The governance module: on-chain parameter changes.
pub struct GovernanceModule {
    store: KVStore,
    /// Proposals, keyed by ID.
    proposals: Mutex<BTreeMap<u64, Proposal>>,
    /// Per-proposal deposit records — `proposal_id → [(depositor,
    /// amount)]`. Committed state (deposits decide what gets
    /// refunded or burned); each entry is removed at decision time
    /// once its refund/burn settles, so live entries only ever
    /// exist for `DepositPeriod`/`Voting` proposals.
    deposits: Mutex<DepositRecords>,
    /// The next proposal ID.
    next_id: Mutex<u64>,
    /// Voting-power source — the validator committee (staking
    /// supplies bonded-stake power). `None` = no power source:
    /// votes are rejected fail-closed (a call-counted tally is the
    /// bug this module must never silently fall back to), and a
    /// zero total power means quorum can never be met.
    committee: Option<Arc<dyn Committee + Send + Sync>>,
    /// The balance ledger deposits escrow into — the EVM account
    /// store in production. `None` = deposits cannot be taken, so
    /// proposals can never reach voting (fail-closed, same as the
    /// committee seam).
    ledger: Option<Arc<dyn Balances + Send + Sync>>,
    /// Parameter sinks by routing prefix — `"<name>."` in
    /// `param_key` selects the sink. A key with no registered
    /// prefix is advisory and applies as a no-op.
    sinks: BTreeMap<&'static str, Arc<dyn ParameterSink + Send + Sync>>,
    /// The governable lifecycle tunables — voting window, deposit
    /// floor/window, quorum and veto thresholds, timelock — shared
    /// with this module's own `governance.*` parameter sink
    /// (self-governance: the `Arc` the sink mutates is the same one
    /// the module reads). Atomics only need cross-thread
    /// visibility: the apply lands in `end_block` at the same
    /// height on every replica, so `Relaxed` suffices.
    params: Arc<GovernanceParams>,
    /// The height of the block currently executing, captured at
    /// `begin_block` — drives vote-window and finalization checks.
    /// `0` outside block execution (unit tests driving `handle`
    /// directly), which makes a just-submitted proposal voteable
    /// for `voting_period` blocks from height 0.
    current_height: Mutex<u64>,
}

impl GovernanceModule {
    /// Construct a fresh governance module.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(BTreeMap::new()),
            proposals: Mutex::new(BTreeMap::new()),
            deposits: Mutex::new(BTreeMap::new()),
            next_id: Mutex::new(0),
            committee: None,
            ledger: None,
            sinks: BTreeMap::new(),
            params: Arc::new(GovernanceParams::default()),
            current_height: Mutex::new(0),
        }
    }

    /// Wire the voting-power source (the staking committee).
    #[must_use]
    pub fn with_committee(mut self, committee: Arc<dyn Committee + Send + Sync>) -> Self {
        self.committee = Some(committee);
        self
    }

    /// Wire the balance ledger deposits escrow through — without it
    /// no proposal can fund, so none can reach a vote.
    #[must_use]
    pub fn with_ledger(mut self, ledger: Arc<dyn Balances + Send + Sync>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Register a parameter sink under `name`: proposals whose
    /// `param_key` begins `"<name>."` apply through it after the
    /// timelock. A duplicate `name` replaces the earlier sink —
    /// registration order can never decide which module answers.
    #[must_use]
    pub fn with_sink(
        mut self,
        name: &'static str,
        sink: Arc<dyn ParameterSink + Send + Sync>,
    ) -> Self {
        self.sinks.insert(name, sink);
        self
    }

    /// The shared lifecycle-parameters handle — the `Arc` node
    /// assembly registers as the `governance.*` parameter sink so
    /// the module governs its own knobs.
    pub fn params(&self) -> Arc<GovernanceParams> {
        Arc::clone(&self.params)
    }

    /// Override the funding threshold — `0` opens voting at
    /// submission (an explicit no-deposit configuration, used by
    /// tests and deployments that gate proposals out-of-band).
    #[must_use]
    pub fn with_min_deposit(self, amount: u64) -> Self {
        self.params.min_deposit.store(amount, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Override the funding window — tests exercise expiry without
    /// driving hundreds of blocks.
    #[must_use]
    pub fn with_deposit_period(self, blocks: u64) -> Self {
        self.params.deposit_period.store(blocks, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Override the quorum threshold (basis points of total power).
    #[must_use]
    pub fn with_quorum_bps(self, bps: u64) -> Self {
        self.params.quorum_bps.store(bps, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Override the veto threshold (basis points of total power).
    #[must_use]
    pub fn with_veto_bps(self, bps: u64) -> Self {
        self.params.veto_bps.store(bps, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Override the apply timelock — `0` applies in the same
    /// `end_block` the decision lands.
    #[must_use]
    pub fn with_timelock(self, blocks: u64) -> Self {
        self.params.timelock.store(blocks, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Override the voting window — tests exercise the lifecycle
    /// without driving a thousand blocks.
    #[must_use]
    pub fn with_voting_period(self, blocks: u64) -> Self {
        self.params.voting_period.store(blocks, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Get a proposal by ID.
    ///
    /// # Panics
    ///
    /// Panics if the proposals mutex is poisoned.
    #[must_use]
    pub fn proposal(&self, id: u64) -> Option<Proposal> {
        framework::lock_state(&self.proposals).get(&id).cloned()
    }

    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        w.put_u64(*framework::lock_state(&self.next_id));
        let proposals = framework::lock_state(&self.proposals);
        w.put_count(proposals.len());
        for (id, p) in proposals.iter() {
            w.put_u64(*id);
            w.put_addr(&p.proposer);
            w.put_bytes(&p.param_key);
            w.put_bytes(&p.param_val);
            w.put_u64(p.yes_votes);
            w.put_u64(p.no_votes);
            w.put_bool(p.finalized);
            w.put_bool(p.passed);
        }
        // ── Trailing section (v2): per-proposal voting deadline ──
        // Appended after the proposal map so pre-upgrade blobs
        // decode with the default below: the deadline is consensus
        // state (two nodes disagreeing on when a proposal closes
        // disagree on its outcome).
        w.put_count(proposals.len());
        for (id, p) in proposals.iter() {
            w.put_u64(*id);
            w.put_u64(p.end_height);
        }
        // ── Trailing section (v3): lifecycle + deposits ──
        // Status, escrowed total, funding deadline, and apply height
        // are all future-affecting (they gate votes, refunds, burns,
        // and the apply step) — consensus state, committed. The
        // per-depositor records follow; without them a restored
        // node could not tell a refunded proposal from a burned
        // one or return deposits to the right accounts.
        w.put_count(proposals.len());
        for (id, p) in proposals.iter() {
            w.put_u64(*id);
            w.put_u8(p.status as u8);
            w.put_u64(p.deposit);
            w.put_u64(p.deposit_deadline);
            w.put_u64(p.apply_height);
        }
        let deposits = framework::lock_state(&self.deposits);
        w.put_count(deposits.len());
        for (id, records) in deposits.iter() {
            w.put_u64(*id);
            w.put_count(records.len());
            for (addr, amount) in records {
                w.put_addr(addr);
                w.put_u64(*amount);
            }
        }
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema.
    ///
    /// Beyond shape, the decode enforces the module's live
    /// invariants a snapshot can't fake: map keys are unique (the
    /// stream's `id` IS the key), `id < next_id` (ids are issued
    /// sequentially), `passed` implies `finalized` and a strict
    /// majority, and when the v3 lifecycle section is present the
    /// status must be consistent with both flags — `finalized ⇔
    /// status.is_decided()`, `passed ⇔ status.did_pass()`. Deposit
    /// records must name live proposals, carry unique depositors,
    /// and sum to the proposal's escrowed total.
    fn decode_committed(
        r: &mut framework::CanonicalReader<'_>,
    ) -> Option<(u64, BTreeMap<u64, Proposal>, DepositRecords)> {
        let next_id = r.get_u64()?;
        let n = r.get_count()?;
        let mut proposals = BTreeMap::new();
        for _ in 0..n {
            let id = r.get_u64()?;
            let proposer = r.get_addr()?;
            let param_key = r.get_bytes()?.to_vec();
            let param_val = r.get_bytes()?.to_vec();
            let yes_votes = r.get_u64()?;
            let no_votes = r.get_u64()?;
            let finalized = r.get_bool()?;
            let passed = r.get_bool()?;
            // `passed` always required a majority under every
            // lifecycle version — veto/quorum-fail only ever turn a
            // would-be pass into a non-passed close, never the
            // reverse.
            if id >= next_id || (passed && !(finalized && yes_votes > no_votes)) {
                return None;
            }
            if proposals
                .insert(
                    id,
                    Proposal {
                        id,
                        proposer,
                        param_key,
                        param_val,
                        yes_votes,
                        no_votes,
                        // Filled from the v3 section below; absent →
                        // derived from the flags: unfinalized
                        // proposals were immediately voteable under
                        // v1 (Voting), a finalized+passed proposal
                        // was advisory — nothing downstream consumed
                        // it — so it decodes straight to `Applied`
                        // rather than risk a retroactive enactment
                        // under rules the vote predated.
                        status: if finalized {
                            if passed { ProposalStatus::Applied } else { ProposalStatus::Rejected }
                        } else {
                            ProposalStatus::Voting
                        },
                        deposit: 0,
                        deposit_deadline: 0,
                        // Filled from the trailing section below;
                        // absent in pre-upgrade blobs → 0 (finalize
                        // at the next end_block — the same immediate
                        // close the pre-lifecycle module had).
                        end_height: 0,
                        apply_height: 0,
                        finalized,
                        passed,
                    },
                )
                .is_some()
            {
                return None; // Duplicate proposal id — non-canonical.
            }
        }
        // ── Trailing section (v2), tolerant of pre-upgrade blobs ──
        // `remaining() == 0` means the blob predates voting
        // deadlines: every proposal keeps the default 0 deadline —
        // finalized proposals are already closed and unfinalized
        // ones close at the next end_block (the old behavior).
        if r.remaining() != 0 {
            let n = r.get_count()?;
            for _ in 0..n {
                let id = r.get_u64()?;
                let end_height = r.get_u64()?;
                let Some(p) = proposals.get_mut(&id) else {
                    return None; // deadline for an unknown proposal is dead state
                };
                p.end_height = end_height;
            }
        }
        // ── Trailing section (v3), tolerant of pre-upgrade blobs ──
        // Absent → every proposal keeps the status derived above;
        // v1 knew no quorum/veto semantics, so the flags alone are
        // the authoritative record for those blobs.
        let deposits = if r.remaining() != 0 {
            Self::decode_lifecycle_section(r, &mut proposals)?
        } else {
            BTreeMap::new()
        };
        Some((next_id, proposals, deposits))
    }

    /// Decode the v3 lifecycle trailing section: per-proposal
    /// `[id][status][deposit][deposit_deadline][apply_height]`
    /// followed by the depositor record map. Every entry must name
    /// a live proposal, the status must agree with the v1 flags it
    /// mirrors, depositor lists must be non-empty and unique, and
    /// each list must sum to its proposal's escrowed total — a blob
    /// violating any of these lies about who gets refunded.
    fn decode_lifecycle_section(
        r: &mut framework::CanonicalReader<'_>,
        proposals: &mut BTreeMap<u64, Proposal>,
    ) -> Option<DepositRecords> {
        let n = r.get_count()?;
        for _ in 0..n {
            let id = r.get_u64()?;
            let status = ProposalStatus::from_byte(r.get_u8()?)?;
            let deposit = r.get_u64()?;
            let deposit_deadline = r.get_u64()?;
            let apply_height = r.get_u64()?;
            let Some(p) = proposals.get_mut(&id) else {
                return None; // lifecycle for an unknown proposal is dead state
            };
            // The flags and the status are two encodings of the
            // same decision — a blob where they disagree is
            // corrupt, not merely unusual.
            if p.finalized != status.is_decided() || p.passed != status.did_pass() {
                return None;
            }
            p.status = status;
            p.deposit = deposit;
            p.deposit_deadline = deposit_deadline;
            p.apply_height = apply_height;
        }
        let mut deposits = BTreeMap::new();
        let n = r.get_count()?;
        for _ in 0..n {
            let id = r.get_u64()?;
            let n_records = r.get_count()?;
            if n_records == 0 {
                return None; // empty records are never written — non-canonical
            }
            let Some(p) = proposals.get(&id) else {
                return None; // deposits for an unknown proposal are dead state
            };
            let mut records = Vec::with_capacity(n_records);
            let mut sum = 0u64;
            for _ in 0..n_records {
                let addr = r.get_addr()?;
                let amount = r.get_u64()?;
                if records.iter().any(|(a, _)| *a == addr) {
                    return None; // one record per depositor — a double pays twice
                }
                sum = sum.checked_add(amount)?;
                records.push((addr, amount));
            }
            // The escrowed total and its records are the same
            // fact — disagreement means the blob lies about who
            // gets refunded.
            if sum != p.deposit {
                return None;
            }
            deposits.insert(id, records);
        }
        Some(deposits)
    }

    /// Get the number of proposals.
    ///
    /// # Panics
    ///
    /// Panics if the proposals mutex is poisoned.
    #[must_use]
    pub fn num_proposals(&self) -> usize {
        framework::lock_state(&self.proposals).len()
    }

    /// Parse a propose message.
    fn parse_propose(msg: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if msg.len() < 4 {
            return None;
        }
        let key_len = u16::from_be_bytes([msg[0], msg[1]]) as usize;
        if msg.len() < 2 + key_len + 2 {
            return None;
        }
        let key = msg[2..2 + key_len].to_vec();
        let val_len_off = 2 + key_len;
        let val_len = u16::from_be_bytes([msg[val_len_off], msg[val_len_off + 1]]) as usize;
        if msg.len() < val_len_off + 2 + val_len {
            return None;
        }
        let val = msg[val_len_off + 2..val_len_off + 2 + val_len].to_vec();
        Some((key, val))
    }

    /// Parse a vote message.
    fn parse_vote(msg: &[u8]) -> Option<(u64, Vote)> {
        if msg.len() < 9 {
            return None;
        }
        let id =
            u64::from_le_bytes([msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7]]);
        let vote = Vote::from_byte(msg[8])?;
        Some((id, vote))
    }

    /// Move a proposal into a new status, keeping the `finalized` /
    /// `passed` mirror flags consistent — the v1 codec section and
    /// every status check read them interchangeably.
    fn set_status(proposal: &mut Proposal, status: ProposalStatus) {
        proposal.status = status;
        proposal.finalized = status.is_decided();
        proposal.passed = status.did_pass();
    }

    /// The decision rule at `end_height`, evaluated against the
    /// committee's CURRENT total power (same live snapshot the vote
    /// weights were drawn from):
    ///
    /// 1. `turnout × 10_000 < quorum_bps × total_power` →
    ///    `FailedQuorum` — a tally nobody showed up for cannot move
    ///    parameters, and its deposits burn rather than refund free
    ///    spam.
    /// 2. `no × 10_000 ≥ veto_bps × total_power` → `Vetoed` — a
    ///    blocking third kills the change even when `yes > no`.
    /// 3. `yes > no` → `Passed` (timelock starts).
    /// 4. Otherwise → `Rejected`.
    fn decide(
        proposal: &Proposal,
        total_power: u64,
        quorum_bps: u64,
        veto_bps: u64,
    ) -> ProposalStatus {
        let turnout = u128::from(proposal.yes_votes) + u128::from(proposal.no_votes);
        let total = u128::from(total_power);
        if turnout * 10_000 < u128::from(quorum_bps) * total {
            return ProposalStatus::FailedQuorum;
        }
        if u128::from(proposal.no_votes) * 10_000 >= u128::from(veto_bps) * total {
            return ProposalStatus::Vetoed;
        }
        if proposal.yes_votes > proposal.no_votes {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        }
    }

    /// Route a passed proposal's parameter to its sink: the
    /// `"<name>."` prefix of `param_key` selects the registered
    /// sink; the sink applies or rejects the value. No registered
    /// prefix → advisory proposal: the vote is the outcome and the
    /// apply is a no-op (recorded as `Applied`, not a failure — a
    /// text proposal did everything it was asked to do).
    fn apply(
        proposal: &Proposal,
        sinks: &BTreeMap<&'static str, Arc<dyn ParameterSink + Send + Sync>>,
    ) -> (ProposalStatus, &'static str) {
        let dot = proposal.param_key.iter().position(|b| *b == b'.');
        let sink = dot.and_then(|i| {
            std::str::from_utf8(&proposal.param_key[..i]).ok().and_then(|name| sinks.get(name))
        });
        match sink.map(|s| s.apply_param(&proposal.param_key, &proposal.param_val)) {
            None => (ProposalStatus::Applied, "proposal_noop"),
            Some(Ok(())) => (ProposalStatus::Applied, "proposal_applied"),
            Some(Err(_)) => (ProposalStatus::ApplyFailed, "proposal_apply_failed"),
        }
    }

    /// Settle a proposal's escrowed deposits: `refund` transfers
    /// each record back to its depositor, `burn` debits the escrow
    /// without a credit (supply shrinks — the anti-spam bond). Either
    /// way the records are consumed so a re-driven `end_block` can
    /// never settle the same deposit twice. A failed transfer leaves
    /// that record's funds in escrow — reachable, never lost, but
    /// no longer owed by this proposal.
    fn settle_deposits(&self, id: u64, refund: bool) {
        let records = framework::lock_state(&self.deposits).remove(&id).unwrap_or_default();
        if records.is_empty() {
            return;
        }
        let Some(ledger) = self.ledger.as_ref() else {
            // No ledger ⇒ no deposit ever succeeded ⇒ no records —
            // but a hand-imported snapshot could disagree; leaving
            // the funds in escrow is the conservative outcome.
            return;
        };
        if refund {
            for (depositor, amount) in records {
                let _ = ledger.transfer(&GOVERNANCE_ESCROW, &depositor, amount);
            }
        } else {
            let total = records.iter().fold(0u64, |acc, (_, a)| acc.saturating_add(*a));
            let _ = ledger.debit(&GOVERNANCE_ESCROW, total);
        }
    }

    /// A proposal submission: `[param_key_len][key][param_val_len][val]`.
    /// With `min_deposit > 0` the proposal opens in `DepositPeriod`
    /// — it cannot take a vote until deposits reach the threshold
    /// (a submission the network never funded is noise, not a
    /// ballot). `min_deposit = 0` is an explicit configuration that
    /// opens voting immediately. Unresolved proposals are capped —
    /// creation is attacker-writable state growth otherwise.
    fn handle_propose(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (key, val) = Self::parse_propose(&msg[1..]).ok_or(ExecError::Malformed)?;
        let height = *framework::lock_state(&self.current_height);
        let mut proposals = framework::lock_state(&self.proposals);
        let open = proposals.values().filter(|p| !p.status.is_terminal()).count();
        if open >= MAX_OPEN_PROPOSALS {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "too many open proposals",
            ));
        }
        let id = {
            let mut next = framework::lock_state(&self.next_id);
            let id = *next;
            *next += 1;
            id
        };
        let funded = self.params.min_deposit.load(std::sync::atomic::Ordering::Relaxed) == 0;
        proposals.insert(
            id,
            Proposal {
                id,
                proposer: ctx.sender,
                param_key: key,
                param_val: val,
                yes_votes: 0,
                no_votes: 0,
                status: if funded { ProposalStatus::Voting } else { ProposalStatus::DepositPeriod },
                deposit: 0,
                deposit_deadline: if funded {
                    0
                } else {
                    height.saturating_add(
                        self.params.deposit_period.load(std::sync::atomic::Ordering::Relaxed),
                    )
                },
                end_height: if funded {
                    height.saturating_add(
                        self.params.voting_period.load(std::sync::atomic::Ordering::Relaxed),
                    )
                } else {
                    0
                },
                apply_height: 0,
                finalized: false,
                passed: false,
            },
        );
        drop(proposals);
        framework::lock_state(&self.store).insert(id.to_le_bytes().to_vec(), msg.to_vec());
        Ok(vec![Event { module: "governance", kind: "propose", data: msg.to_vec() }])
    }

    /// A deposit toward a proposal's funding threshold:
    /// `[proposal_id: 8B LE][amount: 8B LE]`. Moves `amount` from the
    /// sender into `GOVERNANCE_ESCROW` and records it per-depositor
    /// for the eventual refund-or-burn. Only `DepositPeriod`
    /// proposals collect — deposits on a live vote would let the
    /// sponsor keep topping up an already-decided deadline, and
    /// deposits on a closed proposal are pure donation to escrow.
    /// The deposit that crosses `min_deposit` opens voting with
    /// `end_height = height + voting_period`.
    fn handle_deposit(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.len() != 17 {
            return Err(ExecError::Malformed);
        }
        let Ok(id_bytes) = <[u8; 8]>::try_from(&msg[1..9]) else {
            return Err(ExecError::Malformed);
        };
        let Ok(amount_bytes) = <[u8; 8]>::try_from(&msg[9..17]) else {
            return Err(ExecError::Malformed);
        };
        let id = u64::from_le_bytes(id_bytes);
        let amount = u64::from_le_bytes(amount_bytes);
        if amount == 0 {
            // A zero-cost record is pure state growth — the refund
            // loop still walks it at decision time.
            return Err(ExecError::rejected(RejectCategory::InvalidInput, "zero deposit"));
        }
        let ledger = self.ledger.as_ref().ok_or_else(|| {
            ExecError::rejected(RejectCategory::Internal, "deposits: no ledger wired")
        })?;
        let height = *framework::lock_state(&self.current_height);
        let mut proposals = framework::lock_state(&self.proposals);
        let proposal = proposals
            .get_mut(&id)
            .ok_or(ExecError::rejected(RejectCategory::NotFound, "unknown proposal"))?;
        if proposal.status != ProposalStatus::DepositPeriod {
            return Err(ExecError::rejected(
                RejectCategory::Precondition,
                "proposal not collecting deposits",
            ));
        }
        if height >= proposal.deposit_deadline {
            return Err(ExecError::rejected(RejectCategory::Precondition, "deposit period ended"));
        }
        {
            let mut deposits = framework::lock_state(&self.deposits);
            let records = deposits.entry(id).or_default();
            let known_idx = records.iter().position(|(a, _)| *a == ctx.sender);
            if known_idx.is_none() && records.len() >= MAX_DEPOSITORS_PER_PROPOSAL {
                return Err(ExecError::rejected(
                    RejectCategory::Precondition,
                    "too many depositors",
                ));
            }
            // Move the funds first — if the debit fails nothing has
            // been recorded and the proposal's tally is untouched.
            ledger.transfer(&ctx.sender, &GOVERNANCE_ESCROW, amount)?;
            // Deposits escrow real balance — cumulative deposits are
            // bounded by the u64 money supply, so the saturating adds
            // cannot fire in a consistent ledger. The bound is kept
            // anyway: a clamped tally is "fully funded," and the
            // escrow already holds every recorded unit.
            match known_idx {
                Some(i) => records[i].1 = records[i].1.saturating_add(amount),
                None => records.push((ctx.sender, amount)),
            }
            proposal.deposit = proposal.deposit.saturating_add(amount);
        }
        let mut events = vec![Event {
            module: "governance",
            kind: "deposit",
            // `[id:8B][depositor:20B][amount:8B]` — the refund/burn
            // is auditable from the block log.
            data: [&id.to_le_bytes()[..], &ctx.sender.0[..], &amount.to_le_bytes()[..]].concat(),
        }];
        if proposal.deposit >= self.params.min_deposit.load(std::sync::atomic::Ordering::Relaxed) {
            proposal.status = ProposalStatus::Voting;
            proposal.end_height = height.saturating_add(
                self.params.voting_period.load(std::sync::atomic::Ordering::Relaxed),
            );
            proposal.deposit_deadline = 0;
            events.push(Event {
                module: "governance",
                kind: "proposal_voting",
                data: id.to_le_bytes().to_vec(),
            });
        }
        Ok(events)
    }

    /// A vote on an open proposal: `[proposal_id: 8B LE][vote: 1B]`.
    /// Weight = the voter's bonded-stake power AT CAST via the wired
    /// committee — a zero-power sender cannot vote (a call-counted
    /// tally is the bug this fixes; there is no unweighted
    /// fallback). A second vote REPLACES the first: the stored
    /// `(choice, power)` record is what lets the tally be corrected
    /// instead of double-counted — the overwrite-without-correction
    /// the audit flagged.
    fn handle_vote(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (id, vote) = Self::parse_vote(&msg[1..]).ok_or(ExecError::Malformed)?;
        let committee = self.committee.as_ref().ok_or_else(|| {
            ExecError::rejected(RejectCategory::Unauthorized, "vote: no committee wired")
        })?;
        let power = committee.power(&ctx.sender);
        if power == 0 {
            return Err(ExecError::rejected(
                RejectCategory::Unauthorized,
                "voter has no voting power",
            ));
        }
        let height = *framework::lock_state(&self.current_height);
        let mut proposals = framework::lock_state(&self.proposals);
        let proposal = proposals
            .get_mut(&id)
            .ok_or(ExecError::rejected(RejectCategory::NotFound, "unknown proposal"))?;
        match proposal.status {
            ProposalStatus::Voting => {}
            ProposalStatus::DepositPeriod => {
                // Unfunded proposals cannot collect votes — a ballot
                // cast before funding would lock in a tally the
                // proposal may never earn the right to hold.
                return Err(ExecError::rejected(
                    RejectCategory::Precondition,
                    "proposal not in voting period",
                ));
            }
            _ => {
                return Err(ExecError::rejected(
                    RejectCategory::Precondition,
                    "proposal already finalized",
                ));
            }
        }
        if height >= proposal.end_height {
            return Err(ExecError::rejected(RejectCategory::Precondition, "voting period ended"));
        }

        // Prior vote record: `[vote:1B][power:8B]` (9B); a 1-byte
        // record is pre-upgrade state — approximate its power by
        // the voter's current power (the best available for a vote
        // cast under call-counted semantics).
        let vote_key = [id.to_le_bytes().as_slice(), ctx.sender.0.as_slice()].concat();
        let prior = {
            let store = framework::lock_state(&self.store);
            match store.get(&vote_key).map(Vec::as_slice) {
                None => None,
                Some([b]) => Vote::from_byte(*b).map(|v| (v, power)),
                Some(rec) if rec.len() == 9 => {
                    let v = Vote::from_byte(rec[0]).ok_or(ExecError::Malformed)?;
                    let Ok(p) = <[u8; 8]>::try_from(&rec[1..9]) else {
                        return Err(ExecError::Malformed);
                    };
                    Some((v, u64::from_le_bytes(p)))
                }
                Some(_) => return Err(ExecError::Malformed), // corrupt record
            }
        };
        // Correct the tally: remove the prior contribution before
        // adding the new one — a same-choice revote nets to just a
        // power refresh, a flip moves the whole weight.
        if let Some((prior_vote, prior_power)) = prior {
            match prior_vote {
                Vote::Yes => proposal.yes_votes = proposal.yes_votes.saturating_sub(prior_power),
                Vote::No => proposal.no_votes = proposal.no_votes.saturating_sub(prior_power),
            }
        }
        match vote {
            Vote::Yes => proposal.yes_votes = proposal.yes_votes.saturating_add(power),
            Vote::No => proposal.no_votes = proposal.no_votes.saturating_add(power),
        }
        drop(proposals);
        let mut rec = Vec::with_capacity(9);
        rec.push(vote as u8);
        rec.extend_from_slice(&power.to_le_bytes());
        framework::lock_state(&self.store).insert(vote_key, rec);
        Ok(vec![Event { module: "governance", kind: "vote", data: msg.to_vec() }])
    }
}

impl Default for GovernanceModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Governance message types.
pub mod msg {
    /// A propose message: `[tag][param_key_len: 2B BE][param_key][param_val_len: 2B BE][param_val]`.
    pub fn propose(param_key: &[u8], param_val: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(5 + param_key.len() + param_val.len());
        msg.push(super::TAG_PROPOSE);
        msg.extend_from_slice(&(u16::try_from(param_key.len()).unwrap_or(u16::MAX)).to_be_bytes());
        msg.extend_from_slice(param_key);
        msg.extend_from_slice(&(u16::try_from(param_val.len()).unwrap_or(u16::MAX)).to_be_bytes());
        msg.extend_from_slice(param_val);
        msg
    }

    /// A vote message: `[tag][proposal_id: 8B LE][vote: 1B (0=no, 1=yes)]`.
    pub fn vote(proposal_id: u64, vote: super::Vote) -> Vec<u8> {
        let mut msg = Vec::with_capacity(10);
        msg.push(super::TAG_VOTE);
        msg.extend_from_slice(&proposal_id.to_le_bytes());
        msg.push(vote as u8);
        msg
    }

    /// A deposit message: `[tag][proposal_id: 8B LE][amount: 8B LE]`.
    pub fn deposit(proposal_id: u64, amount: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(17);
        msg.push(super::TAG_DEPOSIT);
        msg.extend_from_slice(&proposal_id.to_le_bytes());
        msg.extend_from_slice(&amount.to_le_bytes());
        msg
    }
}

impl Module for GovernanceModule {
    fn name(&self) -> &'static str {
        "governance"
    }
    fn id(&self) -> u8 {
        module_id::GOVERNANCE
    }

    fn begin_block(&self, height: Height) {
        // The executing height drives vote-window and finalization
        // checks for every tx this block.
        *framework::lock_state(&self.current_height) = height.value();
    }

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        if msg.is_empty() {
            return Err(ExecError::Malformed);
        }
        // Explicit tag dispatch — the previous length heuristic
        // (9-byte body = vote) collided with any 9-byte proposal
        // payload, an unambiguous-encoding bug.
        match msg[0] {
            TAG_VOTE => self.handle_vote(ctx, msg),
            TAG_PROPOSE => self.handle_propose(ctx, msg),
            TAG_DEPOSIT => self.handle_deposit(ctx, msg),
            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, height: Height) -> Vec<Event> {
        // One pass, three transitions — each gated on committed
        // deadlines so every node lands on the same states:
        //   DepositPeriod & height ≥ deposit_deadline → Expired
        //     (deposits burn — an unfundable proposal was spam).
        //   Voting & height ≥ end_height → decide() against the
        //     committee's current total power: FailedQuorum and
        //     Vetoed burn, Rejected and Passed refund.
        //   Passed & height ≥ apply_height → route param_key to its
        //     sink → Applied / ApplyFailed (terminal either way).
        let height = height.value();
        let total_power = self.committee.as_ref().map_or(0, |c| c.total_power());
        let mut proposals = framework::lock_state(&self.proposals);
        let mut events = Vec::new();
        for proposal in proposals.values_mut() {
            let id = proposal.id;
            match proposal.status {
                ProposalStatus::DepositPeriod if height >= proposal.deposit_deadline => {
                    Self::set_status(proposal, ProposalStatus::Expired);
                    self.settle_deposits(id, false);
                    events.push(Event {
                        module: "governance",
                        kind: "proposal_expired",
                        data: id.to_le_bytes().to_vec(),
                    });
                }
                ProposalStatus::Voting if height >= proposal.end_height => {
                    let status = Self::decide(
                        proposal,
                        total_power,
                        self.params.quorum_bps.load(std::sync::atomic::Ordering::Relaxed),
                        self.params.veto_bps.load(std::sync::atomic::Ordering::Relaxed),
                    );
                    Self::set_status(proposal, status);
                    // Refund/burn at the decision — the escrowed bond
                    // is released the moment the tally is known; it
                    // is not collateral for the apply step.
                    let refund =
                        matches!(status, ProposalStatus::Passed | ProposalStatus::Rejected);
                    self.settle_deposits(id, refund);
                    if status == ProposalStatus::Passed {
                        proposal.apply_height = height.saturating_add(
                            self.params.timelock.load(std::sync::atomic::Ordering::Relaxed),
                        );
                    }
                    // `[id:8B LE][passed:1B][status:1B]` — the
                    // block-log record of the outcome. The status
                    // byte distinguishes rejected / vetoed /
                    // quorum-failed closes that the bare `passed`
                    // flag cannot.
                    let mut data = Vec::with_capacity(10);
                    data.extend_from_slice(&id.to_le_bytes());
                    data.push(u8::from(proposal.passed));
                    data.push(status as u8);
                    events.push(Event { module: "governance", kind: "proposal_finalized", data });
                }
                ProposalStatus::Passed if height >= proposal.apply_height => {
                    let (status, kind) = Self::apply(proposal, &self.sinks);
                    Self::set_status(proposal, status);
                    events.push(Event {
                        module: "governance",
                        kind,
                        data: id.to_le_bytes().to_vec(),
                    });
                }
                _ => {}
            }
        }
        events
    }

    fn state_root(&self) -> Hash {
        // C8: commit every future-affecting field — the store only
        // mirrors proposal bytes and per-voter records; the tallies,
        // `finalized`/`passed` flags, and `next_id` live in memory
        // and decide which param changes apply.
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        w.root()
    }

    /// Export the committed state as one canonical blob —
    /// `canon ‖ store` (audit 3.2). The canon section is the
    /// `state_root` preimage, so a peer verifies the claimed root
    /// before installing anything.
    fn export_state(&self) -> Option<storage::Snapshot> {
        let mut w = framework::CanonicalState::new();
        self.write_committed(&mut w);
        Some(storage::Snapshot {
            height: 0,
            entries: vec![(
                framework::state_blob_key(),
                framework::encode_state_blob(w.as_bytes(), &framework::lock_state(&self.store)),
            )],
        })
    }

    /// Verify a staged snapshot's claimed root without mutating:
    /// blob decode → store-subtree-root consistency → full field
    /// decode (with proposal invariants) → hash the canonical
    /// preimage.
    fn inspect_state(&self, snapshot: &storage::Snapshot) -> Result<Hash, storage::SnapshotError> {
        let (canon, _staged, _store) =
            framework::stage_blob_snapshot(snapshot, |r, _store| Self::decode_committed(r))?;
        Ok(framework::canon_root(canon))
    }

    /// Install staged state after inspection proved it — decode
    /// first, then swap the store and in-memory fields in one step.
    fn import_state(&self, snapshot: &storage::Snapshot) -> Result<(), storage::SnapshotError> {
        let (_canon, (next_id, proposals, deposits), store) =
            framework::stage_blob_snapshot(snapshot, |r, _store| Self::decode_committed(r))?;
        *framework::lock_state(&self.store) = store;
        *framework::lock_state(&self.proposals) = proposals;
        *framework::lock_state(&self.deposits) = deposits;
        *framework::lock_state(&self.next_id) = next_id;
        // Block-transient — the next `begin_block` refreshes it.
        *framework::lock_state(&self.current_height) = 0;
        Ok(())
    }
}
#[cfg(test)]
mod tests;
