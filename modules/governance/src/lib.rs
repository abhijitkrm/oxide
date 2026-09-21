//! Oxide governance module — on-chain parameter changes and market
//! listing.
//!
//! The governance module is the module-equivalent of Cosmos SDK's
//! `x/gov`. It allows token holders to propose and vote on parameter
//! changes for other modules.
//!
//! # Phase 4 scope
//!
//! v0 is a minimal governance module: proposals are submitted with
//! a parameter key/value pair, voters vote yes/no, and a simple
//! majority of cast VOTING POWER passes the proposal. Voting power
//! is bonded stake via the wired `Committee` (staking): a vote's
//! weight is the voter's power at cast, zero-power senders cannot
//! vote, and a second vote replaces the first with the tally
//! corrected. Proposals accept votes for `voting_period` blocks and
//! finalize at their deadline in `end_block` — no timelock, no
//! veto, no proposal deposits. The `passed` flag is advisory: the
//! parameter-application lifecycle is still incomplete, so nothing
//! downstream consumes it yet.
//!
//! # Messages
//!
//! - `Propose`: `[TAG_PROPOSE][param_key_len: 2B BE][param_key][param_val_len: 2B BE][param_val]`
//! - `Vote`: `[TAG_VOTE][proposal_id: 8B LE][vote: 1B (0=no, 1=yes)]`
//!
//! # State
//!
//! - Proposals: `[proposal_id: 8B LE] -> [encoded proposal]`
//! - Votes: `[proposal_id: 8B LE][voter: 20B] -> [vote: 1B][power: 8B LE]`
//! - Next proposal ID: `next_proposal_id -> [8B LE]`

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use executor::{Event, ExecError, Module, TxContext};
use framework::{Committee, KVStore, module_id, subtree_root};
use primitives::{Address, Hash, Height};

/// Wire tag: governance proposal submission.
const TAG_PROPOSE: u8 = 1;
/// Wire tag: a vote on an open proposal.
const TAG_VOTE: u8 = 2;

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
    /// The height at which voting closes: votes are accepted for
    /// `height < end_height` only, and `end_block` finalizes the
    /// proposal once the chain reaches `end_height`.
    pub end_height: u64,
    /// Whether the proposal has been finalized.
    pub finalized: bool,
    /// Whether the proposal passed.
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

/// The governance module: on-chain parameter changes.
pub struct GovernanceModule {
    store: KVStore,
    /// Proposals, keyed by ID.
    proposals: Mutex<BTreeMap<u64, Proposal>>,
    /// The next proposal ID.
    next_id: Mutex<u64>,
    /// Voting-power source — the validator committee (staking
    /// supplies bonded-stake power). `None` = no power source:
    /// votes are rejected fail-closed (a call-counted tally is the
    /// bug this module must never silently fall back to).
    committee: Option<Arc<dyn Committee + Send + Sync>>,
    /// Voting window in blocks — [`VOTING_PERIOD_BLOCKS`] default;
    /// overridable for tests/devnets.
    voting_period: u64,
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
            next_id: Mutex::new(0),
            committee: None,
            voting_period: VOTING_PERIOD_BLOCKS,
            current_height: Mutex::new(0),
        }
    }

    /// Wire the voting-power source (the staking committee).
    #[must_use]
    pub fn with_committee(mut self, committee: Arc<dyn Committee + Send + Sync>) -> Self {
        self.committee = Some(committee);
        self
    }

    /// Override the voting window — tests exercise the lifecycle
    /// without driving a thousand blocks.
    #[must_use]
    pub fn with_voting_period(mut self, blocks: u64) -> Self {
        self.voting_period = blocks;
        self
    }

    /// Get a proposal by ID.
    ///
    /// # Panics
    ///
    /// Panics if the proposals mutex is poisoned.
    #[must_use]
    pub fn proposal(&self, id: u64) -> Option<Proposal> {
        self.proposals.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&id).cloned()
    }

    /// Write the module's committed state into `w` — shared by
    /// `state_root` and `export_state` so the snapshot blob's
    /// canonical section is provably the same bytes `state_root`
    /// hashes.
    fn write_committed(&self, w: &mut framework::CanonicalState) {
        w.put_root(&subtree_root(&self.store));
        w.put_u64(*self.next_id.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        let proposals = self.proposals.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
    }

    /// Decode the canonical fields following the leading store root —
    /// shared by `inspect_state` and `import_state` so verification
    /// and installation can never disagree about the schema.
    ///
    /// Beyond shape, the decode enforces the module's live
    /// invariants a snapshot can't fake: map keys are unique (the
    /// stream's `id` IS the key), `id < next_id` (ids are issued
    /// sequentially), `passed` implies `finalized`, a finalized
    /// proposal's `passed` must equal `yes_votes > no_votes` — the
    /// tally is computed once at finalize and votes cannot change
    /// afterwards.
    fn decode_committed(
        r: &mut framework::CanonicalReader<'_>,
    ) -> Option<(u64, BTreeMap<u64, Proposal>)> {
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
            if id >= next_id || (passed && !finalized) {
                return None;
            }
            if finalized && passed != (yes_votes > no_votes) {
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
                        // Filled from the trailing section below;
                        // absent in pre-upgrade blobs → 0 (finalize
                        // at the next end_block — the same immediate
                        // close the pre-lifecycle module had).
                        end_height: 0,
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
        Some((next_id, proposals))
    }

    /// Get the number of proposals.
    ///
    /// # Panics
    ///
    /// Panics if the proposals mutex is poisoned.
    #[must_use]
    pub fn num_proposals(&self) -> usize {
        self.proposals.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
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

    /// Finalize a proposal: count votes and decide.
    fn finalize_proposal(proposal: &mut Proposal) {
        if proposal.finalized {
            return;
        }
        proposal.finalized = true;
        proposal.passed = proposal.yes_votes > proposal.no_votes;
    }

    /// A proposal submission: `[param_key_len][key][param_val_len][val]`.
    /// The proposal opens at the current height and accepts votes
    /// until `current_height + voting_period`; `end_block` finalizes
    /// it at the deadline. Open proposals are capped — creation is
    /// attacker-writable state growth otherwise.
    fn handle_propose(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        let (key, val) = Self::parse_propose(&msg[1..]).ok_or(ExecError::Malformed)?;
        let height = *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut proposals =
            self.proposals.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let open = proposals.values().filter(|p| !p.finalized).count();
        if open >= MAX_OPEN_PROPOSALS {
            return Err(ExecError::ModuleRejected("too many open proposals".to_string()));
        }
        let id = {
            let mut next = self.next_id.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let id = *next;
            *next += 1;
            id
        };
        proposals.insert(
            id,
            Proposal {
                id,
                proposer: ctx.sender,
                param_key: key,
                param_val: val,
                yes_votes: 0,
                no_votes: 0,
                end_height: height.saturating_add(self.voting_period),
                finalized: false,
                passed: false,
            },
        );
        drop(proposals);
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id.to_le_bytes().to_vec(), msg.to_vec());
        Ok(vec![Event { module: "governance", kind: "propose", data: msg.to_vec() }])
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
        let committee = self
            .committee
            .as_ref()
            .ok_or_else(|| ExecError::ModuleRejected("vote: no committee wired".to_string()))?;
        let power = committee.power(&ctx.sender);
        if power == 0 {
            return Err(ExecError::ModuleRejected("voter has no voting power".to_string()));
        }
        let height = *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut proposals =
            self.proposals.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let proposal = proposals
            .get_mut(&id)
            .ok_or(ExecError::ModuleRejected("unknown proposal".to_string()))?;
        if proposal.finalized {
            return Err(ExecError::ModuleRejected("proposal already finalized".to_string()));
        }
        if height >= proposal.end_height {
            return Err(ExecError::ModuleRejected("voting period ended".to_string()));
        }

        // Prior vote record: `[vote:1B][power:8B]` (9B); a 1-byte
        // record is pre-upgrade state — approximate its power by
        // the voter's current power (the best available for a vote
        // cast under call-counted semantics).
        let vote_key = [id.to_le_bytes().as_slice(), ctx.sender.0.as_slice()].concat();
        let prior = {
            let store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
        self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(vote_key, rec);
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
        *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            height.value();
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
            _ => Err(ExecError::Malformed),
        }
    }

    fn end_block(&self, height: Height) -> Vec<Event> {
        // Finalize only proposals whose voting period has closed —
        // finalizing every proposal every block (the old behavior)
        // made the voting period meaningless: a proposal closed
        // the same block it opened.
        let mut proposals =
            self.proposals.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut events = Vec::new();
        for proposal in proposals.values_mut() {
            if proposal.finalized || height.value() < proposal.end_height {
                continue;
            }
            Self::finalize_proposal(proposal);
            // `[id:8B LE][passed:1B]` — the block-log record of the
            // outcome (auditable, unlike the silent flag flip).
            let mut data = Vec::with_capacity(9);
            data.extend_from_slice(&proposal.id.to_le_bytes());
            data.push(u8::from(proposal.passed));
            events.push(Event { module: "governance", kind: "proposal_finalized", data });
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
                framework::encode_state_blob(w.as_bytes(), &self.store),
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
        let (_canon, (next_id, proposals), store) =
            framework::stage_blob_snapshot(snapshot, |r, _store| Self::decode_committed(r))?;
        *self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = store;
        *self.proposals.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = proposals;
        *self.next_id.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = next_id;
        // Block-transient — the next `begin_block` refreshes it.
        *self.current_height.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = 0;
        Ok(())
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

    /// Test voting power: `byte × 10` — distinct weights per voter
    /// so tallies prove stake-weighting (addr(2)=20, addr(3)=30,
    /// addr(4)=40, addr(5)=50; addr(0) is powerless).
    struct TestCommittee;

    impl Committee for TestCommittee {
        fn is_active_validator(&self, a: &Address) -> bool {
            a.0[0] != 0
        }
        fn active_validator_count(&self) -> usize {
            5
        }
        fn power(&self, a: &Address) -> u64 {
            u64::from(a.0[0]) * 10
        }
        fn total_power(&self) -> u64 {
            150
        }
    }

    /// A module with voting power wired and a 5-block voting window
    /// (tests exercise the deadline without driving `1_000` blocks).
    fn wired_gov() -> GovernanceModule {
        GovernanceModule::new().with_committee(Arc::new(TestCommittee)).with_voting_period(5)
    }

    #[test]
    fn propose_creates_proposal() {
        let gov = GovernanceModule::new();
        let msg = msg::propose(b"consensus.base_timeout_ms", b"1000");
        gov.handle(&ctx(1), &msg).unwrap();
        assert_eq!(gov.num_proposals(), 1);
        let proposal = gov.proposal(0).unwrap();
        assert_eq!(proposal.param_key, b"consensus.base_timeout_ms");
        assert_eq!(proposal.param_val, b"1000");
        assert_eq!(proposal.proposer, addr(1));
    }

    #[test]
    fn multiple_proposals_get_unique_ids() {
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key1", b"val1")).unwrap();
        gov.handle(&ctx(1), &msg::propose(b"key2", b"val2")).unwrap();
        assert_eq!(gov.num_proposals(), 2);
        assert_eq!(gov.proposal(0).unwrap().param_key, b"key1");
        assert_eq!(gov.proposal(1).unwrap().param_key, b"key2");
    }

    #[test]
    fn vote_yes_increments_yes_votes() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        let proposal = gov.proposal(0).unwrap();
        // Stake-weighted: addr(2) casts 20 power, not 1 vote.
        assert_eq!(proposal.yes_votes, 20);
        assert_eq!(proposal.no_votes, 0);
    }

    #[test]
    fn vote_no_increments_no_votes() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::No)).unwrap();
        let proposal = gov.proposal(0).unwrap();
        assert_eq!(proposal.yes_votes, 0);
        assert_eq!(proposal.no_votes, 20);
    }

    #[test]
    fn vote_on_unknown_proposal_rejected() {
        let gov = wired_gov();
        let err = gov.handle(&ctx(1), &msg::vote(99, Vote::Yes)).unwrap_err();
        assert_eq!(err, ExecError::ModuleRejected("unknown proposal".to_string()));
    }

    #[test]
    fn end_block_finalizes_proposals() {
        let gov = wired_gov(); // voting_period = 5
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        // Before end_block, not finalized.
        let proposal = gov.proposal(0).unwrap();
        assert!(!proposal.finalized);
        // A mid-window end_block must NOT finalize — the old code
        // closed every proposal every block, making the voting
        // period meaningless.
        gov.end_block(Height::new(4));
        assert!(!gov.proposal(0).unwrap().finalized, "still inside the window");
        // At the deadline it finalizes.
        gov.end_block(Height::new(5));
        let proposal = gov.proposal(0).unwrap();
        assert!(proposal.finalized);
        assert!(proposal.passed); // 20 power yes > 0
    }

    #[test]
    fn proposal_with_more_no_votes_fails() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::No)).unwrap();
        gov.handle(&ctx(3), &msg::vote(0, Vote::No)).unwrap();
        gov.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
        gov.end_block(Height::new(5));
        let proposal = gov.proposal(0).unwrap();
        assert!(proposal.finalized);
        assert!(!proposal.passed); // 20+30 no power < ... wait: 20+30=50 > 40
        // 50 no-power vs 40 yes-power — the WEIGHTED outcome fails.
        // (Under call-counting this was 2-vs-1 too; the weights
        // prove the tally is power, not heads.)
    }

    #[test]
    fn tie_vote_fails() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        gov.handle(&ctx(3), &msg::vote(0, Vote::Yes)).unwrap();
        gov.handle(&ctx(5), &msg::vote(0, Vote::No)).unwrap();
        gov.end_block(Height::new(5));
        let proposal = gov.proposal(0).unwrap();
        assert!(proposal.finalized);
        // 20+30 yes-power == 50 no-power — not strictly >, fails.
        assert!(!proposal.passed);
    }

    #[test]
    fn malformed_propose_rejected() {
        let gov = GovernanceModule::new();
        // Too short.
        assert_eq!(gov.handle(&ctx(1), &[1, 2]), Err(ExecError::Malformed));
        // Key length exceeds message.
        let msg = vec![0xFF, 0xFF, 0x00]; // key_len = 65535 but only 1 byte
        assert_eq!(gov.handle(&ctx(1), &msg), Err(ExecError::Malformed));
    }

    #[test]
    fn malformed_vote_rejected() {
        let gov = GovernanceModule::new();
        // Too short.
        assert_eq!(gov.handle(&ctx(1), &[1, 2, 3]), Err(ExecError::Malformed));
        // Invalid vote byte.
        let msg = vec![0u8; 8];
        let mut msg = msg;
        msg.push(2); // not 0 or 1
        assert_eq!(gov.handle(&ctx(1), &msg), Err(ExecError::Malformed));
    }

    #[test]
    fn state_root_changes_after_finalize() {
        // C8: `finalized`/`passed` live only in the in-memory
        // proposals map — they decide whether a proposal's param
        // change applies, so they are future-affecting state and
        // must move the root even though they never touch the store.
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        let root0 = gov.state_root();
        gov.end_block(Height::new(5));
        let root1 = gov.state_root();
        assert_ne!(root0, root1, "finalizing a proposal must change the state root");
    }

    #[test]
    fn state_root_changes_after_proposal() {
        let gov = GovernanceModule::new();
        let root0 = gov.state_root();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        let root1 = gov.state_root();
        assert_ne!(root0, root1);
    }

    #[test]
    fn state_root_changes_after_vote() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        let root0 = gov.state_root();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        let root1 = gov.state_root();
        assert_ne!(root0, root1);
    }

    #[test]
    fn vote_from_same_sender_different_proposals() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key1", b"val1")).unwrap();
        gov.handle(&ctx(1), &msg::propose(b"key2", b"val2")).unwrap();
        // Same sender can vote on both — each ballot is independent.
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        gov.handle(&ctx(2), &msg::vote(1, Vote::No)).unwrap();
        let p0 = gov.proposal(0).unwrap();
        let p1 = gov.proposal(1).unwrap();
        assert_eq!(p0.yes_votes, 20);
        assert_eq!(p1.no_votes, 20);
    }

    /// Export → inspect → import must reproduce the exact committed
    /// state: proposals, tallies, and `next_id` survive a snapshot
    /// round-trip with the state root intact (audit 3.2).
    #[test]
    fn state_snapshot_round_trips() {
        let src = wired_gov();
        src.handle(&ctx(1), &msg::propose(b"k1", b"v1")).unwrap();
        // Proposal 1 submits two blocks later → deadline 7 vs 5.
        src.begin_block(Height::new(2));
        src.handle(&ctx(1), &msg::propose(b"k2", b"v2")).unwrap();
        src.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        // Proposal 0 at its deadline (5) finalizes; proposal 1 is
        // still mid-window — the round-trip must carry BOTH
        // deadlines.
        src.end_block(Height::new(5));
        let snapshot = src.export_state().expect("governance exports state");
        assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

        let dst = wired_gov();
        dst.import_state(&snapshot).unwrap();
        assert_eq!(dst.state_root(), src.state_root());
        assert_eq!(dst.num_proposals(), 2);
        assert!(dst.proposal(0).unwrap().finalized);
        // The v2 trailing section: proposal 1's deadline survived —
        // it must not close before height 7 on the imported module.
        assert_eq!(dst.proposal(1).unwrap().end_height, 7);
        assert!(!dst.proposal(1).unwrap().finalized);
        dst.end_block(Height::new(7));
        assert!(dst.proposal(1).unwrap().finalized, "deadline survived import");
    }

    /// Corrupt canonical bytes and a violated proposal invariant
    /// must both fail inspection — never import.
    #[test]
    fn state_snapshot_rejects_corruption() {
        let src = GovernanceModule::new();
        src.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
        let mut snapshot = src.export_state().unwrap();
        snapshot.entries[0].1.truncate(20);
        assert!(src.inspect_state(&snapshot).is_err());
        assert!(GovernanceModule::new().import_state(&snapshot).is_err());
    }

    /// Without a committee there is no power source — votes fail
    /// closed rather than falling back to call-counting.
    #[test]
    fn vote_rejected_without_committee() {
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        let err = gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "expected rejection, got {err:?}");
        assert_eq!(gov.proposal(0).unwrap().yes_votes, 0);
    }

    /// A sender with zero bonded-stake power cannot vote — an
    /// unbonded key must not move a stake-weighted tally.
    #[test]
    fn zero_power_voter_rejected() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        // addr(0) is not on the committee → power 0.
        let err = gov.handle(&ctx(0), &msg::vote(0, Vote::Yes)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "expected rejection, got {err:?}");
        assert_eq!(gov.proposal(0).unwrap().yes_votes, 0);
    }

    /// The bug this guards: a second vote must REPLACE the first,
    /// not stack on top of it. Same choice → the tally sees the
    /// voter's power exactly once.
    #[test]
    fn revote_same_choice_not_double_counted() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        let p = gov.proposal(0).unwrap();
        // Call-counting (the old bug) would report 40; the stored
        // record lets the tally correct back to 20.
        assert_eq!(p.yes_votes, 20);
        assert_eq!(p.no_votes, 0);
    }

    /// Flipping a vote moves the voter's WHOLE weight between
    /// tallies — not one head from each side.
    #[test]
    fn revote_flips_weight() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::No)).unwrap();
        let p = gov.proposal(0).unwrap();
        assert_eq!(p.yes_votes, 0);
        assert_eq!(p.no_votes, 20);
        // And back again — the correction is symmetric.
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        let p = gov.proposal(0).unwrap();
        assert_eq!(p.yes_votes, 20);
        assert_eq!(p.no_votes, 0);
    }

    /// The voting window is a hard deadline — a vote cast at or
    /// after `end_height` must not count, even before `end_block`
    /// has run.
    #[test]
    fn vote_after_deadline_rejected() {
        let gov = wired_gov(); // window = 5 → proposals end at height 5
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.begin_block(Height::new(5));
        let err = gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "expected rejection, got {err:?}");
        assert_eq!(gov.proposal(0).unwrap().yes_votes, 0);
    }

    /// A finalized proposal is immutable — no late votes.
    #[test]
    fn vote_on_finalized_rejected() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.end_block(Height::new(5));
        let err = gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap_err();
        assert!(matches!(err, ExecError::ModuleRejected(_)), "expected rejection, got {err:?}");
    }

    /// `end_block` reports each closing proposal — the outcome is
    /// auditable block-log data, not a silent flag flip.
    #[test]
    fn end_block_emits_finalized_event() {
        let gov = wired_gov();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(5), &msg::vote(0, Vote::Yes)).unwrap();
        let events = gov.end_block(Height::new(5));
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.module, "governance");
        assert_eq!(e.kind, "proposal_finalized");
        // `[id:8B LE][passed:1B]` — id 0, passed (50 power yes).
        assert_eq!(&e.data[..8], &0u64.to_le_bytes());
        assert_eq!(e.data[8], 1);
        // A mid-window end_block emits nothing.
        let other = wired_gov();
        other.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
        assert!(other.end_block(Height::new(4)).is_empty());
    }

    /// Explicit tags: a 9-byte proposal payload is no longer
    /// misread as a vote — the old length heuristic hijacked any
    /// proposal whose message was exactly 9 bytes.
    #[test]
    fn nine_byte_proposal_not_hijacked() {
        let gov = wired_gov();
        // key(2)+val(2) → tagged message is exactly 9 bytes.
        let m = msg::propose(b"ab", b"cd");
        assert_eq!(m.len(), 9);
        gov.handle(&ctx(1), &m).unwrap();
        assert_eq!(gov.num_proposals(), 1, "must decode as a proposal, not a vote");
        // Unknown tag is still malformed.
        assert!(matches!(gov.handle(&ctx(1), &[0xFF, 0x00]), Err(ExecError::Malformed)));
        // Valid tag + truncated body is malformed.
        assert!(matches!(gov.handle(&ctx(1), &[TAG_VOTE, 0x01]), Err(ExecError::Malformed)));
        assert!(matches!(gov.handle(&ctx(1), &[TAG_PROPOSE, 0x01]), Err(ExecError::Malformed)));
    }

    /// Pre-upgrade blobs carry no deadline section: every proposal
    /// decodes with `end_height = 0` — already-closed ones stay
    /// closed and still-open ones finalize at the next `end_block`
    /// (the same immediate close the old module had).
    #[test]
    fn pre_upgrade_blob_decodes_and_finalizes() {
        // Hand-build the v1 canonical stream: root ‖ next_id ‖
        // proposals — with NO trailing deadline section — plus the
        // store mirror entry the live module writes per proposal.
        let propose_msg = msg::propose(b"k1", b"v1");
        let mut store_map: framework::StoreMap = std::collections::BTreeMap::new();
        store_map.insert(0u64.to_le_bytes().to_vec(), propose_msg.clone());
        let mut w = framework::CanonicalState::new();
        w.put_root(&framework::subtree_root_map(&store_map));
        w.put_u64(1); // next_id
        w.put_count(1);
        w.put_u64(0); // proposal id
        w.put_addr(&addr(1));
        w.put_bytes(b"k1");
        w.put_bytes(b"v1");
        w.put_u64(3); // yes_votes — v1 counted CALLS, so small ints
        w.put_u64(0); // no_votes
        w.put_bool(false); // finalized
        w.put_bool(false); // passed
        let blob = framework::encode_state_blob(w.as_bytes(), &Mutex::new(store_map));
        let snapshot =
            storage::Snapshot { height: 0, entries: vec![(framework::state_blob_key(), blob)] };

        let gov = wired_gov();
        gov.import_state(&snapshot).unwrap();
        let p = gov.proposal(0).unwrap();
        assert!(!p.finalized);
        assert_eq!(p.end_height, 0, "absent section → legacy zero deadline");
        // The zero deadline makes the proposal due immediately —
        // same close-on-first-end_block behavior as the v1 module.
        gov.end_block(Height::new(1));
        let p = gov.proposal(0).unwrap();
        assert!(p.finalized);
        assert!(p.passed); // 3 yes > 0 no
    }
}
