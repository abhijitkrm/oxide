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
//! majority of staked tokens passes the proposal. No timelock, no
//! veto, no proposal deposits. This is the minimum needed for
//! on-chain parameter changes.
//!
//! # Messages
//!
//! - `Propose`: `[param_key_len: 2B BE][param_key][param_val_len: 2B BE][param_val]`
//! - `Vote`: `[proposal_id: 8B LE][vote: 1B (0=no, 1=yes)]`
//!
//! # State
//!
//! - Proposals: `[proposal_id: 8B LE] -> [encoded proposal]`
//! - Votes: `[proposal_id: 8B LE][voter: 20B] -> [vote: 1B]`
//! - Next proposal ID: `next_proposal_id -> [8B LE]`

use std::collections::BTreeMap;
use std::sync::Mutex;

use executor::{Event, ExecError, Module, TxContext};
use framework::{KVStore, module_id, subtree_root};
use primitives::{Address, Hash, Height};

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
    /// Yes votes (count of voters, not stake-weighted in v0).
    pub yes_votes: u64,
    /// No votes.
    pub no_votes: u64,
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
}

impl GovernanceModule {
    /// Construct a fresh governance module.
    pub fn new() -> Self {
        Self {
            store: Mutex::new(BTreeMap::new()),
            proposals: Mutex::new(BTreeMap::new()),
            next_id: Mutex::new(0),
        }
    }

    /// Get a proposal by ID.
    ///
    /// # Panics
    ///
    /// Panics if the proposals mutex is poisoned.
    #[must_use]
    pub fn proposal(&self, id: u64) -> Option<Proposal> {
        self.proposals.lock().unwrap().get(&id).cloned()
    }

    /// Get the number of proposals.
    ///
    /// # Panics
    ///
    /// Panics if the proposals mutex is poisoned.
    #[must_use]
    pub fn num_proposals(&self) -> usize {
        self.proposals.lock().unwrap().len()
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
}

impl Default for GovernanceModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Governance message types.
pub mod msg {
    /// A propose message: `[param_key_len: 2B BE][param_key][param_val_len: 2B BE][param_val]`.
    pub fn propose(param_key: &[u8], param_val: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(4 + param_key.len() + param_val.len());
        msg.extend_from_slice(&(u16::try_from(param_key.len()).unwrap_or(u16::MAX)).to_be_bytes());
        msg.extend_from_slice(param_key);
        msg.extend_from_slice(&(u16::try_from(param_val.len()).unwrap_or(u16::MAX)).to_be_bytes());
        msg.extend_from_slice(param_val);
        msg
    }

    /// A vote message: `[proposal_id: 8B LE][vote: 1B (0=no, 1=yes)]`.
    pub fn vote(proposal_id: u64, vote: super::Vote) -> Vec<u8> {
        let mut msg = Vec::with_capacity(9);
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

    fn begin_block(&self, _height: Height) {}

    fn handle(&self, ctx: &TxContext, msg: &[u8]) -> Result<Vec<Event>, ExecError> {
        // Try to parse as a propose message first (key_len prefix).
        // If the first two bytes form a valid key length, it's a propose.
        // Otherwise, try to parse as a vote (8-byte ID + 1-byte vote).
        if msg.len() >= 9 {
            // Heuristic: if msg[8] is 0 or 1, it could be a vote.
            // But a propose message could also have msg[8] == 0 or 1.
            // We use the message length to disambiguate:
            // - Vote: exactly 9 bytes.
            // - Propose: variable length (>= 4 bytes).
            if msg.len() == 9 {
                // Vote.
                let (id, vote) = Self::parse_vote(msg).ok_or(ExecError::Malformed)?;
                let mut proposals = self.proposals.lock().unwrap();
                let proposal = proposals
                    .get_mut(&id)
                    .ok_or(ExecError::ModuleRejected("unknown proposal".to_string()))?;
                match vote {
                    Vote::Yes => proposal.yes_votes += 1,
                    Vote::No => proposal.no_votes += 1,
                }
                // Store the vote in the KV store.
                let mut store = self.store.lock().unwrap();
                let vote_key = [id.to_le_bytes().as_slice(), ctx.sender.0.as_slice()].concat();
                store.insert(vote_key, vec![vote as u8]);
                return Ok(vec![Event {
                    module: "governance",
                    kind: "vote".to_string(),
                    data: msg.to_vec(),
                }]);
            }
        }

        // Try to parse as a propose message.
        let (key, val) = Self::parse_propose(msg).ok_or(ExecError::Malformed)?;
        let mut next_id = self.next_id.lock().unwrap();
        let id = *next_id;
        *next_id += 1;
        let proposal = Proposal {
            id,
            proposer: ctx.sender,
            param_key: key.clone(),
            param_val: val.clone(),
            yes_votes: 0,
            no_votes: 0,
            finalized: false,
            passed: false,
        };
        let mut proposals = self.proposals.lock().unwrap();
        proposals.insert(id, proposal);
        let mut store = self.store.lock().unwrap();
        store.insert(id.to_le_bytes().to_vec(), msg.to_vec());
        Ok(vec![Event { module: "governance", kind: "propose".to_string(), data: msg.to_vec() }])
    }

    fn end_block(&self, _height: Height) {
        // Finalize all proposals at the end of each block.
        let mut proposals = self.proposals.lock().unwrap();
        for proposal in proposals.values_mut() {
            Self::finalize_proposal(proposal);
        }
    }

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
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        let proposal = gov.proposal(0).unwrap();
        assert_eq!(proposal.yes_votes, 1);
        assert_eq!(proposal.no_votes, 0);
    }

    #[test]
    fn vote_no_increments_no_votes() {
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::No)).unwrap();
        let proposal = gov.proposal(0).unwrap();
        assert_eq!(proposal.yes_votes, 0);
        assert_eq!(proposal.no_votes, 1);
    }

    #[test]
    fn vote_on_unknown_proposal_rejected() {
        let gov = GovernanceModule::new();
        let err = gov.handle(&ctx(1), &msg::vote(99, Vote::Yes)).unwrap_err();
        assert_eq!(err, ExecError::ModuleRejected("unknown proposal".to_string()));
    }

    #[test]
    fn end_block_finalizes_proposals() {
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        // Before end_block, not finalized.
        let proposal = gov.proposal(0).unwrap();
        assert!(!proposal.finalized);
        // End block finalizes.
        gov.end_block(Height::new(1));
        let proposal = gov.proposal(0).unwrap();
        assert!(proposal.finalized);
        assert!(proposal.passed); // 1 yes > 0 no
    }

    #[test]
    fn proposal_with_more_no_votes_fails() {
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::No)).unwrap();
        gov.handle(&ctx(3), &msg::vote(0, Vote::No)).unwrap();
        gov.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
        gov.end_block(Height::new(1));
        let proposal = gov.proposal(0).unwrap();
        assert!(proposal.finalized);
        assert!(!proposal.passed); // 1 yes < 2 no
    }

    #[test]
    fn tie_vote_fails() {
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        gov.handle(&ctx(3), &msg::vote(0, Vote::No)).unwrap();
        gov.end_block(Height::new(1));
        let proposal = gov.proposal(0).unwrap();
        assert!(proposal.finalized);
        assert!(!proposal.passed); // 1 yes == 1 no, not > so fails
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
    fn state_root_changes_after_proposal() {
        let gov = GovernanceModule::new();
        let root0 = gov.state_root();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        let root1 = gov.state_root();
        assert_ne!(root0, root1);
    }

    #[test]
    fn state_root_changes_after_vote() {
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
        let root0 = gov.state_root();
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        let root1 = gov.state_root();
        assert_ne!(root0, root1);
    }

    #[test]
    fn vote_from_same_sender_different_proposals() {
        let gov = GovernanceModule::new();
        gov.handle(&ctx(1), &msg::propose(b"key1", b"val1")).unwrap();
        gov.handle(&ctx(1), &msg::propose(b"key2", b"val2")).unwrap();
        // Same sender can vote on both.
        gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
        gov.handle(&ctx(2), &msg::vote(1, Vote::No)).unwrap();
        let p0 = gov.proposal(0).unwrap();
        let p1 = gov.proposal(1).unwrap();
        assert_eq!(p0.yes_votes, 1);
        assert_eq!(p1.no_votes, 1);
    }
}
