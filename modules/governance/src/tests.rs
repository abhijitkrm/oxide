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
/// `min_deposit = 0` opens voting at submission and `timelock =
/// 0` resolves the apply step at the next `end_block` — the
/// deposit/quorum paths have their own dedicated tests.
fn wired_gov() -> GovernanceModule {
    GovernanceModule::new()
        .with_committee(Arc::new(TestCommittee))
        .with_voting_period(5)
        .with_min_deposit(0)
        .with_timelock(0)
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
    assert_eq!(err, ExecError::rejected(RejectCategory::NotFound, "unknown proposal"));
}

#[test]
fn end_block_finalizes_proposals() {
    let gov = wired_gov(); // voting_period = 5
    gov.handle(&ctx(1), &msg::propose(b"key", b"val")).unwrap();
    // Quorum needs turnout ≥ 33.4% of 150 power → addr(2)+addr(4)
    // contribute 60 ≥ 50.1.
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
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
    assert!(proposal.passed); // 60 power yes > 0, turnout met quorum
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
    // 50 + 20 = 70 power turnout — above the 50.1 quorum.
    gov.handle(&ctx(5), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    let events = gov.end_block(Height::new(5));
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.module, "governance");
    assert_eq!(e.kind, "proposal_finalized");
    // `[id:8B LE][passed:1B][status:1B]` — id 0, passed, and the
    // status byte records the Passed lifecycle position.
    assert_eq!(&e.data[..8], &0u64.to_le_bytes());
    assert_eq!(e.data[8], 1);
    assert_eq!(e.data[9], ProposalStatus::Passed as u8);
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
    // 60 yes-power — enough to meet the 50.1 quorum the
    // post-upgrade decision applies at finalize.
    w.put_u64(60); // yes_votes — v1 counted CALLS, so small ints
    w.put_u64(0); // no_votes
    w.put_bool(false); // finalized
    w.put_bool(false); // passed
    let blob = framework::encode_state_blob(w.as_bytes(), &store_map);
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
    assert!(p.passed); // 60 yes > 0 no and meets quorum
}

// ── Parameter-application lifecycle ─────────────────────────
// Deposit escrow → quorum → veto → timelock → sink apply: the
// phases the module doc's state machine names, each pinned by
// its own regression test.

/// A parameter sink that records what it was asked to apply —
/// the lifecycle's value is what it delivers downstream, so the
/// tests assert on delivered `(key, value)` pairs, not just
/// module-internal flags.
struct TestSink {
    applied: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    fail: bool,
}

impl ParameterSink for TestSink {
    fn apply_param(&self, key: &[u8], value: &[u8]) -> Result<(), ExecError> {
        if self.fail {
            return Err(ExecError::rejected(RejectCategory::Other, "sink rejected value"));
        }
        framework::lock_state(&self.applied).push((key.to_vec(), value.to_vec()));
        Ok(())
    }
}

/// Governance wired for the full lifecycle: a funded ledger
/// (depositors 1..=10 hold `10_000_000` each), committee power,
/// and short deadlines — deposit window 3, voting window 5,
/// min deposit `1_000`, timelock 2.
fn funded_gov() -> (GovernanceModule, Arc<framework::MemoryBalances>) {
    let ledger = Arc::new(framework::MemoryBalances::new());
    for b in 1..=10u8 {
        ledger.mint(&addr(b), 10_000_000);
    }
    let gov = GovernanceModule::new()
        .with_committee(Arc::new(TestCommittee))
        .with_ledger(ledger.clone())
        .with_voting_period(5)
        .with_deposit_period(3)
        .with_min_deposit(1_000)
        .with_timelock(2);
    (gov, ledger)
}

/// A proposal opens in `DepositPeriod` — it cannot take votes
/// until deposits cross the threshold, and the crossing deposit
/// is what starts the voting window.
#[test]
fn deposits_open_voting_at_threshold() {
    let (gov, ledger) = funded_gov();
    gov.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
    let p = gov.proposal(0).unwrap();
    assert_eq!(p.status, ProposalStatus::DepositPeriod);
    assert_eq!(p.deposit_deadline, 3);
    // Ballots are rejected until the proposal is funded.
    let err = gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "expected rejection, got {err:?}");
    // A partial deposit moves funds into escrow but does not
    // open voting.
    gov.handle(&ctx(2), &msg::deposit(0, 600)).unwrap();
    assert_eq!(ledger.balance(&addr(2)), 10_000_000 - 600);
    assert_eq!(ledger.balance(&GOVERNANCE_ESCROW), 600);
    assert_eq!(gov.proposal(0).unwrap().status, ProposalStatus::DepositPeriod);
    // A second depositor crosses the threshold → Voting, and the
    // window opens from THIS height.
    let events = gov.handle(&ctx(3), &msg::deposit(0, 500)).unwrap();
    assert_eq!(gov.proposal(0).unwrap().status, ProposalStatus::Voting);
    assert_eq!(gov.proposal(0).unwrap().end_height, 5);
    assert_eq!(gov.proposal(0).unwrap().deposit, 1_100);
    assert!(events.iter().any(|e| e.kind == "proposal_voting"));
    assert!(gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).is_ok());
    // No further deposits once voting is open.
    assert!(gov.handle(&ctx(4), &msg::deposit(0, 10)).is_err());
}

/// An underfunded proposal expires at its deposit deadline and
/// its deposits burn — the anti-spam bond is real.
#[test]
fn underfunded_proposal_expires_and_burns() {
    let (gov, ledger) = funded_gov();
    gov.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 600)).unwrap();
    // Past the deadline a deposit is refused...
    gov.begin_block(Height::new(3));
    assert!(gov.handle(&ctx(3), &msg::deposit(0, 500)).is_err());
    // ...and the block's end_block expires the proposal: the
    // escrowed 600 is debited with no credit — supply shrinks,
    // the depositor is NOT refunded.
    let events = gov.end_block(Height::new(3));
    assert!(events.iter().any(|e| e.kind == "proposal_expired"));
    let p = gov.proposal(0).unwrap();
    assert_eq!(p.status, ProposalStatus::Expired);
    assert!(p.finalized);
    assert!(!p.passed);
    assert_eq!(ledger.balance(&GOVERNANCE_ESCROW), 0, "expired deposits burn");
    assert_eq!(ledger.balance(&addr(2)), 10_000_000 - 600, "no refund on expiry");
}

/// A rejected proposal refunds every depositor to the unit —
/// escrow conservation is per-depositor, not pooled.
#[test]
fn rejected_proposal_refunds_depositors() {
    let (gov, ledger) = funded_gov();
    gov.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 600)).unwrap();
    gov.handle(&ctx(3), &msg::deposit(0, 500)).unwrap();
    // Quorum met (60 turnout ≥ 50.1) and no wins 40 > 20 —
    // but 40 no-power stays under the 50.1 veto threshold, so
    // this is a plain rejection, not a veto.
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(4), &msg::vote(0, Vote::No)).unwrap();
    gov.end_block(Height::new(5));
    let p = gov.proposal(0).unwrap();
    assert_eq!(p.status, ProposalStatus::Rejected);
    assert_eq!(ledger.balance(&addr(2)), 10_000_000, "refunded whole");
    assert_eq!(ledger.balance(&addr(3)), 10_000_000, "refunded whole");
    assert_eq!(ledger.balance(&GOVERNANCE_ESCROW), 0, "escrow fully drained");
}

/// Turnout below quorum fails the proposal even when yes leads —
/// and burns the deposits: a proposal nobody showed up for must
/// not be free.
#[test]
fn low_turnout_fails_quorum_and_burns() {
    let (gov, ledger) = funded_gov();
    gov.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 1_000)).unwrap();
    // 20 power yes — under the 50.1 quorum of 150 total.
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    let events = gov.end_block(Height::new(5));
    let p = gov.proposal(0).unwrap();
    assert_eq!(p.status, ProposalStatus::FailedQuorum);
    assert!(!p.passed);
    let fin = events.iter().find(|e| e.kind == "proposal_finalized").unwrap();
    assert_eq!(fin.data[9], ProposalStatus::FailedQuorum as u8);
    assert_eq!(ledger.balance(&GOVERNANCE_ESCROW), 0, "quorum-fail deposits burn");
    assert_eq!(ledger.balance(&addr(2)), 10_000_000 - 1_000);
}

/// A blocking third of total power voting no vetoes regardless
/// of the majority — the "yes won but it doesn't matter" case.
#[test]
fn veto_overrides_majority_and_burns() {
    let (gov, ledger) = funded_gov();
    gov.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 1_000)).unwrap();
    // 90 yes vs 60 no — a majority for yes, but 60 no-power ≥
    // 33.4% of 150 → vetoed anyway.
    gov.handle(&ctx(9), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(6), &msg::vote(0, Vote::No)).unwrap();
    gov.end_block(Height::new(5));
    let p = gov.proposal(0).unwrap();
    assert_eq!(p.status, ProposalStatus::Vetoed);
    assert!(p.finalized);
    assert!(!p.passed, "veto overrides the yes majority");
    assert_eq!(ledger.balance(&GOVERNANCE_ESCROW), 0, "vetoed deposits burn");
}

/// A passed proposal does not apply at the decision — it waits
/// out the timelock, then the sink receives the exact key/value.
#[test]
fn passed_proposal_applies_after_timelock() {
    let (gov, ledger) = funded_gov();
    let sink = Arc::new(TestSink { applied: Mutex::new(Vec::new()), fail: false });
    let gov = gov.with_sink("test", sink.clone());
    gov.handle(&ctx(1), &msg::propose(b"test.param", b"42")).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 1_000)).unwrap();
    gov.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    // Decision at the deadline: Passed with apply_height = 5+2;
    // the deposit already refunded — escrow is not apply collateral.
    let events = gov.end_block(Height::new(5));
    let p = gov.proposal(0).unwrap();
    assert_eq!(p.status, ProposalStatus::Passed);
    assert_eq!(p.apply_height, 7);
    assert!(p.passed && p.finalized);
    assert!(events.iter().any(|e| e.kind == "proposal_finalized"));
    assert_eq!(ledger.balance(&addr(2)), 10_000_000, "refunded at decision");
    assert!(framework::lock_state(&sink.applied).is_empty(), "timelock has not elapsed");
    // Inside the timelock the proposal waits.
    assert!(gov.end_block(Height::new(6)).is_empty());
    assert_eq!(gov.proposal(0).unwrap().status, ProposalStatus::Passed);
    // At apply_height the sink gets the proposal's exact bytes.
    let events = gov.end_block(Height::new(7));
    assert_eq!(gov.proposal(0).unwrap().status, ProposalStatus::Applied);
    assert!(events.iter().any(|e| e.kind == "proposal_applied"));
    let applied = framework::lock_state(&sink.applied);
    assert_eq!(applied.as_slice(), &[(b"test.param".to_vec(), b"42".to_vec())]);
}

/// A passed proposal whose key has no registered sink is
/// advisory: it resolves `Applied` with a `proposal_noop` event —
/// the vote was the outcome, nothing downstream to enact.
#[test]
fn unregistered_key_applies_as_noop() {
    let (gov, _ledger) = funded_gov(); // no sinks registered
    gov.handle(&ctx(1), &msg::propose(b"text.proposal", b"hello")).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 1_000)).unwrap();
    gov.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    gov.end_block(Height::new(5));
    let events = gov.end_block(Height::new(7));
    assert_eq!(gov.proposal(0).unwrap().status, ProposalStatus::Applied);
    assert!(events.iter().any(|e| e.kind == "proposal_noop"));
}

/// A sink rejection marks the proposal `ApplyFailed` — terminal,
/// never retried: replaying a stale value under newer state is
/// worse than forcing a fresh proposal.
#[test]
fn sink_rejection_is_terminal_apply_failed() {
    let (gov, _ledger) = funded_gov();
    let sink = Arc::new(TestSink { applied: Mutex::new(Vec::new()), fail: true });
    let gov = gov.with_sink("test", sink.clone());
    gov.handle(&ctx(1), &msg::propose(b"test.param", b"bad")).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 1_000)).unwrap();
    gov.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    gov.end_block(Height::new(5));
    let events = gov.end_block(Height::new(7));
    let p = gov.proposal(0).unwrap();
    assert_eq!(p.status, ProposalStatus::ApplyFailed);
    assert!(p.passed, "the electorate approved — execution failed");
    assert!(events.iter().any(|e| e.kind == "proposal_apply_failed"));
    // No retry: the next end_block touches nothing.
    assert!(gov.end_block(Height::new(8)).is_empty());
    assert_eq!(framework::lock_state(&sink.applied).len(), 0);
}

/// Fail-closed deposit path: no ledger wired → deposits cannot
/// be taken → proposals expire unfunded instead of silently
/// opening a vote.
#[test]
fn deposits_fail_closed_without_ledger() {
    let gov = GovernanceModule::new()
        .with_committee(Arc::new(TestCommittee))
        .with_voting_period(5)
        .with_deposit_period(3)
        .with_min_deposit(1_000);
    gov.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
    let err = gov.handle(&ctx(2), &msg::deposit(0, 1_000)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "expected rejection, got {err:?}");
    gov.end_block(Height::new(3));
    assert_eq!(gov.proposal(0).unwrap().status, ProposalStatus::Expired);
}

/// Depositor bookkeeping is per-address: a repeat depositor
/// tops up under one record, and the crowd is capped so the
/// refund loop and canonical size stay bounded.
#[test]
fn deposit_records_merge_and_cap() {
    let (gov, ledger) = funded_gov();
    gov.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
    // Same sender twice → one record, summed.
    gov.handle(&ctx(2), &msg::deposit(0, 100)).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 100)).unwrap();
    assert_eq!(gov.proposal(0).unwrap().deposit, 200);
    // Fill the depositor cap with funded throwaway addresses —
    // addr(2) holds one record, so 127 more reach the cap of 128.
    for i in 20u8..147 {
        let a = addr(i);
        ledger.mint(&a, 1);
        gov.handle(&TxContext { sender: a, nonce: 0, fee: 0 }, &msg::deposit(0, 1)).unwrap();
    }
    // Cap reached — the next distinct depositor is refused.
    assert_eq!(gov.proposal(0).unwrap().deposit, 200 + 127);
    let a = addr(200);
    ledger.mint(&a, 1);
    let err =
        gov.handle(&TxContext { sender: a, nonce: 0, fee: 0 }, &msg::deposit(0, 1)).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)), "cap must reject, got {err:?}");
}

/// Zero-amount deposits and malformed bodies are rejected — a
/// zero-cost record is pure committed-state growth.
#[test]
fn deposit_validation_rejected() {
    let (gov, _ledger) = funded_gov();
    gov.handle(&ctx(1), &msg::propose(b"k", b"v")).unwrap();
    assert!(gov.handle(&ctx(2), &msg::deposit(0, 0)).is_err());
    assert!(matches!(gov.handle(&ctx(2), &[TAG_DEPOSIT, 1, 2]), Err(ExecError::Malformed)));
    assert!(gov.handle(&ctx(2), &msg::deposit(99, 1)).is_err(), "unknown proposal");
    // Insufficient funds — the transfer fails before any record.
    assert!(gov.handle(&ctx(2), &msg::deposit(0, 99_000_000)).is_err());
    assert_eq!(gov.proposal(0).unwrap().deposit, 0);
}

/// The v3 lifecycle section must round-trip: statuses, escrow
/// totals, deadlines, apply heights, and per-depositor records —
/// then the imported module continues settling refunds and
/// applies from where the exporter left off.
#[test]
fn state_snapshot_round_trips_lifecycle() {
    let (src, ledger) = funded_gov();
    let sink = Arc::new(TestSink { applied: Mutex::new(Vec::new()), fail: false });
    let src = src.with_sink("test", sink.clone());
    // p2 first: funded at height 0 → voting closes at 5.
    src.handle(&ctx(1), &msg::propose(b"test.p2", b"7")).unwrap();
    src.handle(&ctx(5), &msg::deposit(0, 1_000)).unwrap();
    src.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
    src.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    // Decided at the deadline: Passed, apply_height = 5+2, the
    // deposit already refunded to addr(5).
    src.end_block(Height::new(5));
    assert_eq!(src.proposal(0).unwrap().status, ProposalStatus::Passed);
    // At height 6: p1 opens a deposit period (deadline 9) with a
    // partial deposit; p2-later (id 2) funds fully → Voting with
    // end_height 11 and a quorum-meeting tally.
    src.begin_block(Height::new(6));
    src.handle(&ctx(1), &msg::propose(b"k1", b"v1")).unwrap();
    src.handle(&ctx(2), &msg::deposit(1, 400)).unwrap();
    src.handle(&ctx(1), &msg::propose(b"test.p3", b"9")).unwrap();
    src.handle(&ctx(3), &msg::deposit(2, 1_000)).unwrap();
    src.handle(&ctx(4), &msg::vote(2, Vote::Yes)).unwrap();
    src.handle(&ctx(2), &msg::vote(2, Vote::Yes)).unwrap();

    let snapshot = src.export_state().expect("governance exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());
    // The imported module settles against the SAME ledger the
    // deposits escrowed into — governance state and the ledger
    // are separate modules' subtrees.
    let dst = GovernanceModule::new()
        .with_committee(Arc::new(TestCommittee))
        .with_ledger(ledger.clone())
        .with_voting_period(5)
        .with_deposit_period(3)
        .with_min_deposit(1_000)
        .with_timelock(2)
        .with_sink("test", sink.clone());
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    assert_eq!(dst.proposal(0).unwrap().status, ProposalStatus::Passed);
    assert_eq!(dst.proposal(0).unwrap().apply_height, 7);
    assert_eq!(dst.proposal(1).unwrap().status, ProposalStatus::DepositPeriod);
    assert_eq!(dst.proposal(1).unwrap().deposit, 400);
    assert_eq!(dst.proposal(1).unwrap().deposit_deadline, 9);
    assert_eq!(dst.proposal(2).unwrap().status, ProposalStatus::Voting);
    assert_eq!(dst.proposal(2).unwrap().end_height, 11);
    // Lifecycle continues post-restore: p0 applies at its
    // timelock, p1 expires unfunded at deadline 9 (the escrowed
    // 400 burns), p2's vote closes at 11 → Passed → applies at 13.
    let events = dst.end_block(Height::new(7));
    assert_eq!(dst.proposal(0).unwrap().status, ProposalStatus::Applied);
    assert!(events.iter().any(|e| e.kind == "proposal_applied"));
    dst.end_block(Height::new(9));
    assert_eq!(dst.proposal(1).unwrap().status, ProposalStatus::Expired);
    assert_eq!(
        ledger.balance(&GOVERNANCE_ESCROW),
        1_000,
        "p1's 400 burned; p2's 1_000 still escrowed"
    );
    dst.end_block(Height::new(11));
    assert_eq!(dst.proposal(2).unwrap().status, ProposalStatus::Passed);
    assert_eq!(ledger.balance(&addr(3)), 10_000_000, "imported deposit record refunded");
    dst.end_block(Height::new(13));
    assert_eq!(dst.proposal(2).unwrap().status, ProposalStatus::Applied);
    // Both applied proposals delivered their exact key/value.
    let applied = framework::lock_state(&sink.applied);
    assert_eq!(
        applied.as_slice(),
        &[(b"test.p2".to_vec(), b"7".to_vec()), (b"test.p3".to_vec(), b"9".to_vec())]
    );
}

// ── `governance.*` self-parameter sink ─────────────────────
// The module's own lifecycle knobs take the same deposited,
// voted, timelocked path as every other module's — the tests
// prove the sink writes the atomics the lifecycle reads.

/// `GovernanceParams` applies each `governance.*` key to its
/// atomic — and rejects what its own keyspace does not cover.
#[test]
fn governance_params_apply_each_key_and_validate() {
    use std::sync::atomic::Ordering::Relaxed;
    let params = GovernanceParams::default();
    let ok = |key: &[u8], v: u64| {
        ParameterSink::apply_param(&params, key, &v.to_le_bytes()).expect("apply should succeed");
    };
    ok(b"governance.voting_period", 7);
    ok(b"governance.min_deposit", 0); // 0 = vote at submission, legitimate
    ok(b"governance.deposit_period", 9);
    ok(b"governance.quorum_bps", 5_000);
    ok(b"governance.veto_bps", 10_000);
    ok(b"governance.timelock", 0);
    assert_eq!(params.voting_period.load(Relaxed), 7);
    assert_eq!(params.min_deposit.load(Relaxed), 0);
    assert_eq!(params.deposit_period.load(Relaxed), 9);
    assert_eq!(params.quorum_bps.load(Relaxed), 5_000);
    assert_eq!(params.veto_bps.load(Relaxed), 10_000);
    assert_eq!(params.timelock.load(Relaxed), 0);

    // Zero windows are nonsense — a proposal that closes in its
    // own block can never legitimately reach quorum.
    assert!(
        ParameterSink::apply_param(&params, b"governance.voting_period", &0u64.to_le_bytes())
            .is_err()
    );
    assert!(
        ParameterSink::apply_param(&params, b"governance.deposit_period", &0u64.to_le_bytes())
            .is_err()
    );
    // Bps above 10_000 is a threshold no tally can ever reach.
    assert!(
        ParameterSink::apply_param(&params, b"governance.quorum_bps", &10_001u64.to_le_bytes())
            .is_err()
    );
    // Foreign key + malformed payload.
    assert!(
        ParameterSink::apply_param(&params, b"staking.block_reward", &1u64.to_le_bytes()).is_err()
    );
    assert!(ParameterSink::apply_param(&params, b"governance.timelock", &[1, 2]).is_err());
}

/// The module registered as its own `governance` sink: a passed
/// `governance.min_deposit` proposal moves the live atomic the
/// deposit gate reads — proven end-to-end through propose →
/// deposit → vote → decide → timelock → apply.
#[test]
fn self_sink_applies_governance_params_end_to_end() {
    let (gov, _ledger) = funded_gov();
    let params = gov.params();
    let gov = gov.with_sink("governance", params.clone());
    let new_deposit = 5_000u64;
    gov.handle(&ctx(1), &msg::propose(b"governance.min_deposit", &new_deposit.to_le_bytes()))
        .unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 1_000)).unwrap();
    gov.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    gov.end_block(Height::new(5)); // decision: Passed, apply_height = 7
    assert_eq!(
        params.min_deposit.load(std::sync::atomic::Ordering::Relaxed),
        1_000,
        "the configured value holds until the timelock elapses"
    );
    gov.end_block(Height::new(7)); // apply
    assert_eq!(gov.proposal(0).unwrap().status, ProposalStatus::Applied);
    assert_eq!(
        params.min_deposit.load(std::sync::atomic::Ordering::Relaxed),
        5_000,
        "the applied proposal moved the live deposit floor"
    );
}

/// A self-governance proposal the sink rejects (a zero voting
/// window) lands `ApplyFailed` — terminal, the same outcome a
/// foreign module's invalid apply records.
#[test]
fn self_sink_rejection_is_terminal_apply_failed() {
    let (gov, _ledger) = funded_gov();
    let params = gov.params();
    let gov = gov.with_sink("governance", params.clone());
    gov.handle(&ctx(1), &msg::propose(b"governance.voting_period", &0u64.to_le_bytes())).unwrap();
    gov.handle(&ctx(2), &msg::deposit(0, 1_000)).unwrap();
    gov.handle(&ctx(4), &msg::vote(0, Vote::Yes)).unwrap();
    gov.handle(&ctx(2), &msg::vote(0, Vote::Yes)).unwrap();
    gov.end_block(Height::new(5));
    gov.end_block(Height::new(7));
    assert_eq!(gov.proposal(0).unwrap().status, ProposalStatus::ApplyFailed);
    assert_eq!(
        params.voting_period.load(std::sync::atomic::Ordering::Relaxed),
        5,
        "the rejected apply left the configured window untouched"
    );
}
