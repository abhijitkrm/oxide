//! Unit tests — extracted from `engine.rs` so the production
//! code reads top-to-bottom without the test bulk (split-giant-
//! modules pass: every entry point's enforcement stays visible).

//! Conformance + unit tests for the oxideBFT engine.
//!
//! The conformance suite proves the engine honors the OAI contract
//! (liveness, sequence, finality, determinism). Unit tests check
//! the internal state (block hash, `tx_root`, view advancement).

use super::*;
use crate::verify::VerifiedQc;
use ports::conformance;
use ports::mock::MockApp;
use types::{ExecCertificate, ExecDivergence};

fn pk(byte: u8) -> crypto::bls::PublicKey {
    crypto::bls::PublicKey([byte; crypto::bls::PublicKey::LEN])
}

fn single_validator_set() -> ValidatorSet {
    ValidatorSet::new(vec![pk(1)], vec![1]).expect("1 validator")
}

fn make_engine() -> OxideBft {
    let app = Arc::new(MockApp::new());
    // Fixed clock: the conformance determinism gate compares
    // finalized blocks byte-for-byte across two runs, and the
    // committed header timestamp now lands in the execution
    // context — a wall clock would make identical runs differ.
    OxideBft::new(app, single_validator_set())
        .without_signature_verification()
        .with_clock(|| 1_700_000_000_000)
}

#[test]
fn oxidebft_passes_conformance() {
    conformance::assert_conformance(make_engine);
}

#[test]
fn engine_starts_at_genesis() {
    let engine = make_engine();
    assert_eq!(engine.finalized_height(), None);
    assert_eq!(engine.next_height, Height::new(0));
    assert_eq!(engine.current_view(), View::new(0));
}

#[test]
fn one_tx_produces_one_committed_block() {
    let mut engine = make_engine();
    engine.submit_tx(TxBytes::new(vec![1, 2, 3]));
    engine.run_until_idle();
    // The tx is in a committed block (the 2-chain flush ensures this).
    assert!(engine.finalized_height().is_some());
    // Find the block containing our tx.
    let mut found = false;
    let h = engine.finalized_height().unwrap().value();
    for i in 0..=h {
        if let Some(block) = engine.finalized_block(Height::new(i))
            && block.txs.iter().any(|t| t.as_bytes() == [1, 2, 3])
        {
            found = true;
            break;
        }
    }
    assert!(found, "tx must appear in a committed block");
}

/// Idle mode: with no pending work, `propose()` stays silent but
/// `propose_heartbeat()` still emits a valid empty block — the
/// leader's liveness proof that keeps followers' view timers from
/// churning through timeout certificates when the mempool is empty.
#[test]
fn heartbeat_proposes_empty_block_when_idle() {
    let mut engine = make_engine();
    // Move past genesis so the idle gate applies.
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    assert!(engine.finalized_height().is_some());

    // Idle: the work gate keeps a quiet leader silent.
    assert!(engine.propose().is_none(), "idle leader must stay silent");
    // …but the heartbeat path still produces a normal, votable
    // proposal — usually empty, extending the committed tip.
    let (header, proposal) = engine.propose_heartbeat().expect("heartbeat must propose when idle");
    assert!(proposal.txs.is_empty(), "idle heartbeat carries no txs");
    assert!(engine.vote(&header, &proposal).is_some(), "heartbeat proposal must be votable");
}

#[test]
fn multiple_txs_all_committed() {
    let mut engine = make_engine();
    for i in 0..5u8 {
        engine.submit_tx(TxBytes::new(vec![i]));
        engine.run_until_idle();
    }
    // All 5 txs must be in committed blocks.
    let mut found_txs = 0;
    let h = engine.finalized_height().unwrap().value();
    for i in 0..=h {
        if let Some(block) = engine.finalized_block(Height::new(i)) {
            found_txs += block.txs.len();
        }
    }
    assert_eq!(found_txs, 5, "all 5 txs must be committed");
}

#[test]
fn view_advances_per_block() {
    let mut engine = make_engine();
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    // After proposing + flushing, the view should have advanced.
    assert!(engine.current_view().value() > 0);
}

#[test]
fn high_qc_advances() {
    let mut engine = make_engine();
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    assert!(engine.high_qc.is_some(), "high_qc should be set after first block");
}

#[test]
fn no_work_when_idle() {
    let mut engine = make_engine();
    // With no txs, the engine proposes genesis but it stays
    // pending (2-chain needs a second block to commit). A second
    // run is a no-op (no new work).
    engine.run_until_idle();
    // Genesis is pending but not committed (no second block to
    // form the 2-chain). This is correct 2-chain behavior.
    // A second run is a true no-op.
    let height_before = engine.finalized_height();
    engine.run_until_idle();
    assert_eq!(engine.finalized_height(), height_before);
}

#[test]
fn is_leader_for_view_zero() {
    let engine = make_engine();
    // Validator 0 is the leader for view 0 (round-robin, equal stakes).
    assert!(engine.is_leader());
}

// ---- Multi-validator tests ----
//
// These tests exercise the engine's multi-validator API
// (propose/vote/collect_vote/try_form_qc/deliver_qc) with a
// 4-validator set, proving the 2-chain commit rule works with
// quorum > 1.

fn four_validator_set() -> ValidatorSet {
    ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![1, 1, 1, 1]).expect("4 validators")
}

fn make_multi_engine(idx: ValidatorIndex) -> OxideBft {
    let app = Arc::new(MockApp::new());
    OxideBft::with_index(app, four_validator_set(), idx).without_signature_verification()
}

/// Drive one happy-path round with 4 validators:
/// 1. Leader proposes.
/// 2. All 4 validators vote.
/// 3. Leader collects votes and forms a QC.
/// 4. All validators receive the QC (2-chain commit check).
/// 5. Advance the view.
///
/// Returns the QC so the caller can chain rounds.
fn drive_round(
    leader: &mut OxideBft,
    followers: &mut [&mut OxideBft],
    tx: Option<TxBytes>,
) -> QuorumCertificate {
    // Submit tx to leader's app (if any).
    if let Some(t) = tx {
        leader.submit_tx(t);
    }

    // 1. Leader proposes.
    let (header, proposal) = leader.propose().expect("leader should propose");

    // 2. Leader self-votes through `vote()` — the single signing
    // authority (C10): locks + WAL update precede the signature,
    // same as for followers.
    let leader_idx = leader.validator_index;
    if let Some(leader_vote) = leader.vote(&header, &proposal) {
        leader.collect_vote(leader_idx, leader_vote).expect("conformance: no verification");
    }

    // 3. Followers vote.
    for (i, follower) in followers.iter_mut().enumerate() {
        if let Some(vote) = follower.vote(&header, &proposal) {
            // Voter index is i+1 (leader is 0, followers are 1..n).
            let voter_idx = u16::try_from(i + 1).expect("validator index fits u16");
            leader.collect_vote(voter_idx, vote).expect("conformance: no verification");
        }
    }

    // 4. Leader forms a QC.
    let qc = leader.try_form_qc().expect("quorum should be reached");

    // 5. All validators receive the QC.
    leader.deliver_qc(qc.clone()).expect("conformance: no verification");
    for follower in followers.iter_mut() {
        follower.deliver_qc(qc.clone()).expect("conformance: no verification");
    }

    // 6. Advance the view on all validators.
    leader.advance_view();
    for follower in followers.iter_mut() {
        follower.advance_view();
    }

    qc
}

/// Drive one round over the dispersed-broadcast path
/// (DispersedSimplex): followers vote on the *header only* —
/// the shard-commitment vote — while the body is still
/// propagating; the QC forms and delivers before any follower
/// holds the body. `supply_body` then certifies the body and
/// triggers the deferred commit walk.
///
/// Returns `(header, proposal, qc)` — callers inspect the QC
/// and choose whether/when to supply bodies.
fn drive_round_sharded(
    leader: &mut OxideBft,
    followers: &mut [&mut OxideBft],
    tx: Option<TxBytes>,
    supply_bodies: bool,
) -> (BlockHeader, Proposal, QuorumCertificate) {
    if let Some(t) = tx {
        leader.submit_tx(t);
    }
    let (header, proposal) = leader.propose().expect("leader should propose");
    let block_hash = OxideBft::block_hash(&header);
    // Leader self-vote through `vote()` — the single signing
    // authority (C10): locks + WAL update precede the signature.
    // It produced the body, so the complete path applies.
    let leader_idx = leader.validator_index;
    if let Some(leader_vote) = leader.vote(&header, &proposal) {
        leader.collect_vote(leader_idx, leader_vote).expect("conformance: no verification");
    }
    // Followers notarize the commitment — body not required.
    for (i, follower) in followers.iter_mut().enumerate() {
        if let Some(vote) = follower.vote_header(&header) {
            let voter_idx = u16::try_from(i + 1).expect("validator index fits u16");
            leader.collect_vote(voter_idx, vote).expect("conformance: no verification");
        }
    }
    let qc = leader.try_form_qc().expect("quorum should be reached");
    leader.deliver_qc(qc.clone()).expect("conformance: no verification");
    for follower in followers.iter_mut() {
        follower.deliver_qc(qc.clone()).expect("conformance: no verification");
    }
    // The body lands *after* the QC — the dispersed order.
    if supply_bodies {
        for follower in followers.iter_mut() {
            follower.supply_body(block_hash, &proposal).expect("certified body must be accepted");
        }
    }
    leader.advance_view();
    for follower in followers.iter_mut() {
        follower.advance_view();
    }
    (header, proposal, qc)
}

/// A follower must vote on a block's commitment without ever
/// having seen its body — notarization attests availability of
/// the *commitment*, execution waits for certification.
#[test]
fn vote_header_notarizes_without_body() {
    let mut leader = make_multi_engine(0);
    let mut follower = make_multi_engine(1);
    leader.submit_tx(TxBytes::new(vec![9]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    assert!(follower.vote_header(&header).is_some(), "commitment vote must not need the body");
    // One vote per view — a second header-vote in the same view
    // is a no-op, same as the full path.
    assert!(follower.vote_header(&header).is_none());
}

/// The certify gate: a QC'd block whose body is still `Awaiting`
/// must defer the commit walk, and `supply_body` must trigger
/// the deferred walk — finalization only after the body is
/// verified and complete.
#[test]
fn commit_defers_until_body_certified() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];

    // Round 1: block h0 — followers never receive its body.
    let (h0, p0, _qc0) =
        drive_round_sharded(&mut leader, &mut followers, Some(TxBytes::new(vec![42])), false);
    // Round 2: block h1 — QC(h1) is what would commit h0.
    drive_round_sharded(&mut leader, &mut followers, None, false);

    // On every follower, h0 is notarized but NOT committed: its
    // body is still Awaiting, so the commit walk broke on it.
    for (name, e) in [("f1", &f1), ("f2", &f2), ("f3", &f3)] {
        assert!(
            e.finalized_block(Height::new(0)).is_none(),
            "{name}: uncommitted body must defer finalization"
        );
    }

    // The body arrives — certification completes it and the
    // deferred walk fires: h0 commits under the already-stored
    // QC(h1) (2-chain rule satisfied since h1's header is known).
    let h0_hash = OxideBft::block_hash(&h0);
    for (i, e) in [&mut f1, &mut f2, &mut f3].iter_mut().enumerate() {
        e.supply_body(h0_hash, &p0)
            .unwrap_or_else(|e| panic!("f{}: certified body accepted: {e:?}", i + 1));
        let block = e.finalized_block(Height::new(0));
        assert!(block.is_some(), "f{}: certified body must unblock commit", i + 1);
        assert_eq!(block.map(|b| b.txs.len()), Some(1));
    }
}

/// `supply_body` must reject a body whose canonical encoding
/// does not hash to the header's signed `body_commitment` —
/// equivocating bodies can never be certified, and the stored
/// `Awaiting` slot must not be poisoned (the genuine body is
/// still accepted afterwards).
#[test]
fn supply_body_rejects_commitment_mismatch() {
    let mut leader = make_multi_engine(0);
    let mut follower = make_multi_engine(1);
    leader.submit_tx(TxBytes::new(vec![7]));
    let (header, proposal) = leader.propose().expect("leader proposes");
    let hash = OxideBft::block_hash(&header);
    assert!(follower.vote_header(&header).is_some());

    let mut wrong = proposal.clone();
    wrong.txs = vec![TxBytes::new(vec![8])];
    assert!(matches!(follower.supply_body(hash, &wrong), Err(ConsensusError::BodyRejected { .. })));
    // Genuine body still accepted — the failed supply did not
    // poison the slot. Duplicate supply is idempotent.
    follower.supply_body(hash, &proposal).expect("genuine body accepted");
    follower.supply_body(hash, &proposal).expect("duplicate supply is a no-op");
}

/// A notarized header keeps the block eligible for all
/// header-level rules while its body propagates: with bodies
/// supplied every round, the dispersed path commits identically
/// to the full-proposal path.
#[test]
fn sharded_round_trip_commits_identically() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];

    drive_round_sharded(&mut leader, &mut followers, Some(TxBytes::new(vec![42])), true);
    drive_round_sharded(&mut leader, &mut followers, None, true);

    for (name, e) in [("leader", &leader), ("f1", &f1), ("f2", &f2), ("f3", &f3)] {
        let block = e.finalized_block(Height::new(0)).expect("block 0 committed");
        assert_eq!(block.txs.len(), 1, "{name}: block 0 should have 1 tx");
        assert_eq!(block.txs[0].as_bytes(), [42], "{name}: block 0 tx mismatch");
    }
}

#[test]
fn multi_validator_two_chain_commits() {
    // 4 validators, 1 leader (index 0), 3 followers.
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];

    // Round 1: propose block0 with a tx.
    drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![42])));
    // After round 1: block0 is pending (has a QC but no 2-chain yet).

    // Round 2: propose block1 (empty) to flush the pipeline.
    drive_round(&mut leader, &mut followers, None);
    // After round 2: block0 should be committed (2-chain: block0
    // → block1 extends block0 → QC over block1).

    // Check block0 is committed on all validators.
    for (name, engine) in [("leader", &leader), ("f1", &f1), ("f2", &f2), ("f3", &f3)] {
        let block = engine.finalized_block(Height::new(0)).expect("block 0 committed");
        assert_eq!(block.txs.len(), 1, "{name}: block 0 should have 1 tx");
        assert_eq!(block.txs[0].as_bytes(), [42], "{name}: block 0 tx mismatch");
    }
}

/// Execution-lane saturation must pause finalization without
/// freezing consensus: a saturated follower withholds its vote
/// (throttling new commits at the source), refuses new body
/// admission, and defers commit walks — while QC adoption stays
/// live so catch-up never stalls. Once the lane drains, the next
/// delivered QC re-runs the deferred walk and the backlog commits
/// in order. The regression this guards: the old bounded channel
/// made `finalize_block` block the consensus thread inside the
/// commit path, so a backed-up execution lane froze timeouts and
/// catch-up along with commits.
#[test]
fn exec_saturation_defers_commits_without_stalling() {
    let mut leader = make_multi_engine(0);
    let f1_app = Arc::new(MockApp::new());
    let mut f1 = OxideBft::with_index(f1_app.clone(), four_validator_set(), 1)
        .without_signature_verification();
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);

    // Round 1 (healthy): h0@v0 earns its QC on every replica — f1
    // stores the body.
    drive_round(&mut leader, &mut [&mut f1, &mut f2, &mut f3], Some(TxBytes::new(vec![1])));
    assert!(f1_app.attest_latest().is_none(), "2-chain: h0 cannot commit on its own QC");

    // Saturate f1's execution lane.
    f1_app.set_exec_saturated(true);

    // Round 2 by hand to inspect the withheld vote: h1@v1 carries
    // QC(h0) — its commit walk would finalize h0.
    leader.submit_tx(TxBytes::new(vec![2]));
    let (h1, p1) = leader.propose().expect("leader proposes");
    let lv = leader.vote(&h1, &p1).expect("leader self-votes");
    leader.collect_vote(0, lv).expect("collect leader vote");
    assert!(f1.vote(&h1, &p1).is_none(), "a saturated executor must withhold the vote");
    assert!(
        !f1.blocks.contains_key(&OxideBft::block_hash(&h1)),
        "saturated admission must not store unexecutable bodies"
    );
    for (i, f) in [&mut f2, &mut f3].iter_mut().enumerate() {
        let v = f.vote(&h1, &p1).expect("healthy followers still vote");
        leader.collect_vote(u16::try_from(i + 2).unwrap(), v).expect("collect");
    }
    let qc1 = leader.try_form_qc().expect("3 of 4 still reach quorum");
    leader.deliver_qc(qc1.clone()).expect("deliver");
    f2.deliver_qc(qc1.clone()).expect("deliver");
    f3.deliver_qc(qc1.clone()).expect("deliver");

    // QC adoption is unaffected — catch-up stays live under
    // saturation — but nothing finalizes.
    f1.deliver_qc(qc1.clone()).expect("QC adoption stays live under saturation");
    assert_eq!(
        f1.high_qc.as_ref().map(VerifiedQc::block_hash),
        Some(OxideBft::block_hash(&h1)),
        "the saturated follower must still adopt the QC"
    );
    assert!(f1_app.attest_latest().is_none(), "no commit may finalize while the lane is saturated");
    for e in [&mut leader, &mut f1, &mut f2, &mut f3] {
        e.advance_view();
    }

    // The lane drains. h1's body re-delivers (the block-sync seam):
    // admission and voting resume.
    f1_app.set_exec_saturated(false);
    assert!(f1.admit_proposal(&h1, &p1), "drained lane must re-admit the body");

    // Round 3: f1 votes on h2 (its body is now stored), then
    // saturates again before the QC lands — QC(h2)'s walk would
    // commit h0+h1 through the consecutive pair, so a deferral here
    // isolates the commit gate from the admission gate.
    leader.submit_tx(TxBytes::new(vec![3]));
    let (h2, p2) = leader.propose().expect("leader proposes");
    let lv = leader.vote(&h2, &p2).expect("leader self-votes");
    leader.collect_vote(0, lv).expect("collect leader vote");
    let f1v = f1.vote(&h2, &p2).expect("voting resumes once drained");
    leader.collect_vote(1, f1v).expect("collect");
    for (i, f) in [&mut f2, &mut f3].iter_mut().enumerate() {
        let v = f.vote(&h2, &p2).expect("vote");
        leader.collect_vote(u16::try_from(i + 2).unwrap(), v).expect("collect");
    }
    let qc2 = leader.try_form_qc().expect("quorum");
    leader.deliver_qc(qc2.clone()).expect("deliver");
    f2.deliver_qc(qc2.clone()).expect("deliver");
    f3.deliver_qc(qc2.clone()).expect("deliver");
    f1_app.set_exec_saturated(true);
    f1.deliver_qc(qc2).expect("adopt QC while saturated");
    assert!(
        f1_app.attest_latest().is_none(),
        "the commit walk itself must defer under saturation — the bodies are stored"
    );
    for e in [&mut leader, &mut f1, &mut f2, &mut f3] {
        e.advance_view();
    }

    // Drain for good: the very next delivered QC re-runs the walk
    // and commits the deferred backlog in order.
    f1_app.set_exec_saturated(false);
    drive_round(&mut leader, &mut [&mut f1, &mut f2, &mut f3], None);
    assert_eq!(
        f1_app.attest_latest().map(|a| a.height),
        Some(Height::new(2)),
        "the deferred backlog must commit in one walk once the lane drains"
    );
}

/// Leader reputation: a validator absent from every committed QC in
/// the reputation window loses its schedule turns — `effective_leader`
/// walks the cycle past it — so a crashed member stops costing a view
/// timeout per rotation. The window holds only committed-QC signer
/// bitmaps: deterministic for every replica that finalized the same
/// prefix.
#[test]
fn absent_validator_loses_leader_turns() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    // Validator 3 is in the set but never signs — a crashed member.
    // Every QC's bitmap is 0b0111.

    // Reputation window = 2 * cycle_len = 8 committed heights (n = 4,
    // equal stake → one rotation is 4 views). Each round commits the
    // block two views back, so 10 rounds fill the window. A tx per
    // round keeps `propose` producing (the idle gate stays silent
    // when there is no work).
    for i in 0..10u8 {
        drive_round(&mut leader, &mut [&mut f1, &mut f2], Some(TxBytes::new(vec![i])));
    }
    assert_eq!(leader.recent_signers.len(), 8, "the window must cap at two schedule rotations");

    let excluded = leader.excluded_leaders();
    assert!(excluded[3], "a validator that signed nothing must be excluded");
    assert!(!excluded[..3].iter().any(|e| *e), "participating validators must stay eligible");

    // Raw schedule: view % 4 — validator 3 owns views 3, 7, 11….
    // Excluded, its slots fall to the next eligible member (0).
    for v in [3u64, 7, 11, 15] {
        assert_eq!(
            leader.effective_leader(View::new(v)),
            0,
            "v{v}: an excluded validator's slot must pass to the next eligible member"
        );
    }
    // Untouched views keep their raw leader.
    for v in [0u64, 1, 2, 4, 5, 6] {
        assert_eq!(
            leader.effective_leader(View::new(v)),
            u16::try_from(v % 4).unwrap(),
            "v{v}: a healthy member's slot is unchanged"
        );
    }

    // And the replacement actually leads: at the next skipped view
    // (11 ≡ raw slot 3) the effective leader's engine is the
    // proposer, its stamped hash is accepted by a follower's
    // authentication, and the proposal votes.
    leader.current_view = View::new(11);
    f1.current_view = View::new(11);
    assert!(leader.is_leader(), "the replacement member must know it leads");
    let (header, proposal) = leader.propose().expect("replacement leader proposes");
    assert_eq!(header.proposer, proposer_hash(0));
    assert!(
        f1.vote(&header, &proposal).is_some(),
        "followers must accept the replacement leader's proposal"
    );
}

/// The exclusion bound must hold even under inputs a real chain
/// can't produce: a window where only a below-quorum subset signed
/// must not exclude so many members that no quorum remains.
#[test]
fn reputation_exclusion_never_strands_quorum() {
    let mut engine = make_multi_engine(0);
    // Window full, signed only by validators 0 and 1 — fabricated:
    // a real QC needs quorum (3 of 4), so this can't arise from
    // commits, but the guard must hold regardless.
    let window = 2 * engine.validator_set.leader_cycle_len();
    for _ in 0..window {
        engine.recent_signers.push_back(vec![0b0011]);
    }
    let excluded = engine.excluded_leaders();
    // Excluding index 2 leaves eligible stake 3 — exactly quorum —
    // so it goes. Excluding index 3 next would drop to 2 < 3:
    // the bound stops there.
    assert!(excluded[2]);
    assert!(!excluded[3], "exclusion must stop before the eligible set drops below quorum");
}

/// Reputation must survive restart: the window is committed state
/// carried in the WAL, so a recovered engine computes the same
/// exclusions its peers do — not a divergent schedule while the
/// window "refills".
#[test]
fn reputation_window_survives_restart() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");

    {
        let app = Arc::new(MockApp::new());
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine =
            OxideBft::new(app, four_validator_set()).without_signature_verification().with_wal(wal);
        // One full rotation of committed bitmaps missing validator 3.
        for _ in 0..4 {
            engine.recent_signers.push_back(vec![0b0111]);
        }
        engine.append_wal().expect("WAL append must succeed");
        assert!(engine.excluded_leaders()[3]);
    }

    {
        let app = Arc::new(MockApp::new());
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine =
            OxideBft::new(app, four_validator_set()).without_signature_verification().with_wal(wal);
        engine.recover_from_wal().expect("recover from WAL");
        assert_eq!(
            engine.recent_signers.len(),
            4,
            "the committed-participation window must be restored"
        );
        assert!(engine.excluded_leaders()[3], "post-restart exclusions must match pre-crash");
    }
}

/// The pacemaker's adaptive floor is fed by the engine's injected
/// clock: each single-step `advance_view` samples the completed
/// view's duration into the EWMA. Sustained slow rounds raise the
/// timeout floor above the configured base; fast rounds decay it
/// back — the base is the floor in both directions.
#[test]
fn adaptive_timeout_tracks_view_durations() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let clock = Arc::new(AtomicU64::new(1_700_000_000_000));
    let c = Arc::clone(&clock);
    let mut engine = make_engine().with_clock(move || c.load(Ordering::Relaxed));
    let base = engine.pacemaker.timeout_duration_ms();

    // The first advance only starts the mark — there is no prior
    // sample to measure against.
    engine.advance_view();
    assert_eq!(engine.pacemaker.timeout_duration_ms(), base);

    // Second advance with a 1s elapsed view: the EWMA seeds at
    // 1000 and the floor lifts to 4× — 4000 > the 2s base.
    clock.fetch_add(1_000, Ordering::Relaxed);
    engine.advance_view();
    assert_eq!(engine.pacemaker.timeout_duration_ms(), 4_000);

    // Sustained 1s rounds hold the floor at 4s.
    for _ in 0..6 {
        clock.fetch_add(1_000, Ordering::Relaxed);
        engine.advance_view();
    }
    assert_eq!(engine.pacemaker.timeout_duration_ms(), 4_000);

    // Fast rounds decay the EWMA until the floor returns to base.
    for _ in 0..32 {
        clock.fetch_add(100, Ordering::Relaxed);
        engine.advance_view();
    }
    assert_eq!(engine.pacemaker.timeout_duration_ms(), base);
}

/// A view that timed out before completing must NOT feed the
/// round-time EWMA — its duration is dead-leader-plus-timeout, not
/// a round-trip, and feeding it back would let a crashed leader
/// inflate the timeout floor it was excluded for. The next *clean*
/// view still samples normally.
#[test]
fn timeout_views_do_not_feed_round_ema() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let clock = Arc::new(AtomicU64::new(1_700_000_000_000));
    let c = Arc::clone(&clock);
    let mut engine = make_engine().with_clock(move || c.load(Ordering::Relaxed));
    let base = engine.pacemaker.timeout_duration_ms();

    engine.advance_view(); // start the mark
    // A 60s stall, a local timeout, then a late-QC advance: the
    // dead-leader wait must not enter the EWMA.
    clock.fetch_add(60_000, Ordering::Relaxed);
    let _ = engine.on_timeout();
    engine.advance_view();
    assert_eq!(
        engine.pacemaker.timeout_duration_ms(),
        base,
        "a view completed after timing out must not feed the EWMA"
    );
    // The next view is clean — its 1s duration samples normally
    // and lifts the floor to 4s.
    clock.fetch_add(1_000, Ordering::Relaxed);
    engine.advance_view();
    assert_eq!(engine.pacemaker.timeout_duration_ms(), 4_000);
}

/// Regression test (safety): a validator that voted for block A
/// at height h must refuse a *different* block B at the same
/// height, even in a later view. Without the per-height lock,
/// the post-timeout flow — vote A at view v, time out, new
/// leader proposes conflicting B at height h extending the same
/// parent QC — passes the tail-fork check (equal QC view) and
/// the validator notarizes two conflicting blocks at one
/// height: both can form QCs and commit divergent state.
#[test]
fn vote_lock_rejects_conflicting_block_at_same_height() {
    let mut leader = make_multi_engine(0);
    let mut follower = make_multi_engine(1);

    // Leader proposes block A at height 0, view 0.
    let (header_a, prop_a) = leader.propose().expect("leader should propose");
    assert!(follower.vote(&header_a, &prop_a).is_some(), "first vote at height 0 must succeed");

    // Conflicting block B: same height, same parent QC, later
    // view — different contents → different block hash.
    let mut header_b = header_a.clone();
    header_b.view = View::new(header_a.view.value() + 1);
    header_b.tx_root = Hash([0xAB; 32]);
    let prop_b = prop_a.clone();
    // HIGH fix: vote() requires header.view == current_view.
    follower.current_view = header_b.view;
    assert!(
        follower.vote(&header_b, &prop_b).is_none(),
        "a conflicting block at an already-voted height must be refused"
    );

    // A block at the NEXT height is unaffected — normal
    // progression continues. Voting for a non-genesis block
    // requires a highQC (the tail-fork rule needs `prev ==
    // high_qc.block`), so give the follower QC(A) — its block
    // header is already stored from the first vote.
    let qc_a = QuorumCertificate {
        view: header_a.view,
        phase: VotePhase::Prepare,
        block_hash: OxideBft::block_hash(&header_a),
        epoch: Epoch::new(0),
        // A QC's bitmap must carry quorum signers — the count is
        // a structural property enforced even without signature
        // verification (conformance mode): a fabricated
        // single-signer "QC" is not a certificate.
        signer_bitmap: vec![0x07],
        aggregate_signature: AggregateSignature::ZERO,
    };
    let mut header_c = header_a.clone();
    header_c.view = View::new(header_a.view.value() + 1);
    header_c.height = Height::new(header_a.height.value() + 1);
    header_c.prev_block = OxideBft::block_hash(&header_a);
    // The child must justify with QC(A) — a proposal without a
    // high_qc is refused while the voter holds one.
    header_c.high_qc = Some(qc_a.clone());
    follower.high_qc = Some(VerifiedQc::from_trusted(qc_a));
    // current_view already set to header_c.view above.
    assert!(
        follower.vote(&header_c, &prop_a).is_some(),
        "voting at the next height must still succeed"
    );
}

#[test]
fn multi_validator_multiple_rounds() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];

    // Drive 5 rounds with txs.
    for i in 0..5u8 {
        drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![i])));
    }
    // Drive one more empty round to flush the last pending block.
    drive_round(&mut leader, &mut followers, None);

    // All 5 txs should be committed across the validators.
    let mut total_txs = 0;
    let h = leader.finalized_height().expect("some blocks finalized").value();
    for i in 0..=h {
        if let Some(block) = leader.finalized_block(Height::new(i)) {
            total_txs += block.txs.len();
        }
    }
    assert_eq!(total_txs, 5, "all 5 txs must be committed");
}

#[test]
fn multi_validator_finalized_heights_match() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];

    for i in 0..3u8 {
        drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![i])));
    }
    drive_round(&mut leader, &mut followers, None);

    // All validators should have the same finalized height.
    let leader_h = leader.finalized_height();
    assert_eq!(f1.finalized_height(), leader_h, "f1 height mismatch");
    assert_eq!(f2.finalized_height(), leader_h, "f2 height mismatch");
    assert_eq!(f3.finalized_height(), leader_h, "f3 height mismatch");
}

/// Regression test (safety + liveness): a Byzantine leader can
/// stamp an arbitrary `height` on a proposal — `vote()` never
/// checked that the stamped height is `parent.height + 1`. A
/// forged block is then committable at a height the honest chain
/// has not reached: `finalized.insert(forged_h, d)` creates a
/// finalized *gap*, and the voters who signed d's child are now
/// per-height-locked at the height the honest chain still needs —
/// the next honest proposal at that height can never reach quorum
/// again. The chain wedges permanently and finalized histories
/// diverge.
///
/// Scenario: commit b0@0 and b1@1 honestly; at view 3 the
/// Byzantine leader proposes d with height forged to 5 (prev =
/// the real highQC block, so tail-fork checks pass — nobody holds
/// a height-5 lock); QC(d) forms; the honest view-4 leader adopts
/// QC(d) as its highQC and proposes a child; QC(child) commits d
/// at forged height 5 while only heights 0..=2 exist.
///
/// The fix makes stamped heights chain coordinates: a voter
/// accepts a proposal only if `header.height ==
/// parent.height + 1` (genesis excepted), and the proposer
/// derives its stamp the same way.
#[test]
fn forged_height_block_cannot_commit_or_wedge_chain() {
    let mut e0 = make_multi_engine(0);
    let mut e1 = make_multi_engine(1);
    let mut e2 = make_multi_engine(2);
    let mut e3 = make_multi_engine(3);

    // Views 0..=2: honest rounds — leaders rotate e0, e1, e2.
    // After view 1 every engine has committed b0@0; after view 2,
    // b1@1 (and pending = b2). drive_round's follower→voter-index
    // mapping (i+1) mislabels indices for non-zero leaders but
    // still collects quorum — conformance mode ignores identity.
    drive_round(&mut e0, &mut [&mut e1, &mut e2, &mut e3], Some(TxBytes::new(vec![0xA0])));
    drive_round(&mut e1, &mut [&mut e0, &mut e2, &mut e3], Some(TxBytes::new(vec![0xB0])));
    drive_round(&mut e2, &mut [&mut e0, &mut e1, &mut e3], Some(TxBytes::new(vec![0xC0])));

    // View 3 — Byzantine leader e3: take its honest proposal and
    // forge the stamped height to 5 (skipping 3 and 4). Parent
    // and justify pointers stay the real highQC — every existing
    // vote check passes; only the height is a lie.
    let (mut d_header, d_proposal) = e3.propose().expect("byz leader proposes");
    assert_eq!(d_header.height, Height::new(3), "honest stamp would be 3");
    d_header.height = Height::new(5); // the attack: a height the chain hasn't reached
    let d_hash = OxideBft::block_hash(&d_header);
    e3.blocks.insert(d_hash, (d_header.clone(), BlockBody::Complete(d_proposal.clone())));

    // e0 and e1 vote for d: nobody holds a height-5 lock, the
    // parent is the real highQC, and the view matches.
    let d_vote0 = e0.vote(&d_header, &d_proposal);
    let d_vote1 = e1.vote(&d_header, &d_proposal);
    assert!(d_vote0.is_none(), "forged-height proposal must be rejected");
    assert!(d_vote1.is_none(), "forged-height proposal must be rejected");
    e3.collect_vote(
        3,
        Vote {
            view: d_header.view,
            phase: VotePhase::Prepare,
            block_hash: d_hash,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        },
    )
    .expect("conformance mode");
    assert!(e3.try_form_qc().is_none(), "a forged-height block must never reach quorum");

    // The honest chain is unaffected: no forged commit, no
    // finalized gap, and the next honest round still works. Move
    // to view 4 (leader e0) — view 3's buffer on e3 still holds
    // the forged self-vote; advancing clears per-view state.
    assert!(e0.finalized_block(Height::new(5)).is_none(), "no forged commit");
    assert!(e0.finalized_height().map_or(0, Height::value) <= 2, "no height gap");
    e0.advance_view();
    e1.advance_view();
    e2.advance_view();
    e3.advance_view();
    drive_round(&mut e0, &mut [&mut e1, &mut e2, &mut e3], Some(TxBytes::new(vec![0xD0])));
    // View 4's block extends QC(b2)@2 across the dead view — a
    // nonconsecutive link, so b2 can't commit through it. The
    // next consecutive pair (view 5 → view 4) commits the whole
    // stored prefix transitively: liveness via ancestor commit.
    drive_round(&mut e1, &mut [&mut e0, &mut e2, &mut e3], Some(TxBytes::new(vec![0xE0])));
    assert!(
        e0.finalized_block(Height::new(2)).is_some(),
        "honest chain still finalizes (b2 lands at height 2)"
    );
}

/// Regression test (liveness, complements the forged-height fix):
/// once stamped heights are bound to `parent.height + 1`, a
/// same-height equivocation that produces no QC leaves honest
/// voters per-height-locked — the only recovery is re-voting the
/// height after the view provably timed out. The proposal's
/// embedded TC is that proof (spec §view-changes: the new leader
/// is the TC's legitimate successor). Without the release, one
/// Byzantine leader could wedge a height forever.
#[test]
fn same_height_lock_releases_on_timeout_certificate() {
    let mut e0 = make_multi_engine(0);
    let mut e1 = make_multi_engine(1);
    let mut e2 = make_multi_engine(2);
    let mut e3 = make_multi_engine(3);

    // View 0: leader e0 equivocates — block A goes to e1, a
    // conflicting block A' (same height, same view, different
    // tx_root) goes to e2 and e3. Votes split 2-2; no QC forms.
    e0.submit_tx(TxBytes::new(vec![0xA0]));
    let (ha, pa) = e0.propose().expect("leader proposes A");
    let mut ha2 = ha.clone();
    ha2.tx_root = Hash([0xAB; 32]);
    let pa2 = Proposal { height: ha2.height, ..pa.clone() };
    let hash_a = OxideBft::block_hash(&ha);
    let hash_a2 = OxideBft::block_hash(&ha2);
    assert_ne!(hash_a, hash_a2, "equivocated blocks must differ");

    e0.collect_vote(
        0,
        Vote {
            view: ha.view,
            phase: VotePhase::Prepare,
            block_hash: hash_a,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        },
    )
    .expect("conformance mode");
    assert!(e1.vote(&ha, &pa).is_some(), "e1 votes A");
    assert!(e2.vote(&ha2, &pa2).is_some(), "e2 votes A'");
    assert!(e3.vote(&ha2, &pa2).is_some(), "e3 votes A'");
    assert!(e0.try_form_qc().is_none(), "2 votes < quorum 3");

    // All four validators time out view 0 and collect each
    // other's signatures — every engine forms TC(0) and advances
    // to view 1 with `last_tc` set.
    timeout_round(&mut [&mut e0, &mut e1, &mut e2, &mut e3]);
    assert_eq!(e1.current_view(), View::new(1), "TC(0) advances to view 1");

    // View 1: new leader e1 re-proposes at height 0 (its highQC
    // is still genesis — no block was ever notarized). The
    // proposal embeds TC(0).
    e1.submit_tx(TxBytes::new(vec![0xB0]));
    let (hb, pb) = e1.propose().expect("new leader re-proposes the height");
    assert_eq!(hb.height, Height::new(0), "the failed height is retried");
    assert_eq!(hb.prev_block, Hash::ZERO, "genesis anchor parent");
    assert_eq!(
        hb.timeout_cert.as_ref().map(|tc| tc.view),
        Some(View::new(0)),
        "proposal embeds TC(0) as successor evidence"
    );

    // Locked voters release: e0 voted A, e2/e3 voted A' — all
    // accept B because TC(0) proves the split view ended
    // undecided.
    assert!(e0.vote(&hb, &pb).is_some(), "A-voter releases on TC evidence");
    assert!(e2.vote(&hb, &pb).is_some(), "A'-voter releases on TC evidence");
    assert!(e3.vote(&hb, &pb).is_some(), "A'-voter releases on TC evidence");
}

/// Regression test (safety): a Byzantine leader can decouple a
/// proposal's `prev_block` from the block its embedded QC
/// certifies (`justify`). The tail-fork rule binds `prev` to the
/// voter's own highQC block, while the two-chain commit rule in
/// `deliver_qc` walks *justify* edges — the QC'd block commits
/// its embedded QC's target. A proposal with `prev = our highQC
/// block` but `justify = a different, newer-view notarized block`
/// passes every pre-fix check: it is stored, gathers votes,
/// becomes `pending`, and commits via its child — while the
/// voter's real parent chain is never committed. Result: a gap
/// in `finalized`, and a same-height conflict against validators
/// that committed through the justify chain.
///
/// The fix is the structural `HotStuff` rule: a block extends
/// exactly the block its embedded QC certifies —
/// `header.prev_block == header.high_qc.block_hash`. Honest
/// proposers always satisfy this (`propose()` sets both from the
/// same highQC); only a crafted proposal can violate it.
///
/// Scenario: all validators hold highQC = QC(a), pending = a.
/// `b@1` is honestly proposed and notarized at view 1, but QC(b)
/// is delivered to nobody — e0/e2/e3 keep highQC = QC(a) and a
/// per-height-1 lock on b. View 1 then times out (TC(1) exists:
/// honest voters can both vote and later timeout-sign a view).
/// The Byzantine view-2 leader crafts `d` with prev = a (the
/// stale voters' highQC block), justify = QC(b) (a real QC for
/// a DIFFERENT block), and TC(1) (which legitimately releases
/// the h1 locks). Pre-fix all three vote for d — QC(d) forms,
/// adoption sets pending = d without committing a, and a child's
/// QC would commit d@1: a finalized gap on e0/e2/e3 and a
/// height-1 fork against e1, which commits b through QC(d)'s
/// justify edge. Post-fix every vote must be rejected.
#[test]
#[allow(clippy::too_many_lines)]
fn prev_justify_divergence_cannot_fork_commits() {
    let mut e0 = make_multi_engine(0);
    let mut e1 = make_multi_engine(1);
    let mut e2 = make_multi_engine(2);
    let mut e3 = make_multi_engine(3);

    // View 0: e0 proposes a@0, everyone votes, QC(a) delivered to
    // all four — pending = a, highQC = QC(a).
    e0.submit_tx(TxBytes::new(vec![0xA0]));
    let (ha, pa) = e0.propose().expect("e0 proposes a@0");
    let hash_a = OxideBft::block_hash(&ha);
    e0.collect_vote(
        0,
        Vote {
            view: ha.view,
            phase: VotePhase::Prepare,
            block_hash: hash_a,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        },
    )
    .expect("conformance mode");
    for (idx, e) in [&mut e1, &mut e2, &mut e3].iter_mut().enumerate() {
        let v = e.vote(&ha, &pa).expect("honest vote for a");
        e0.collect_vote(u16::try_from(idx + 1).unwrap_or(0), v).expect("collect");
    }
    let qc_a = e0.try_form_qc().expect("QC(a)");
    for e in [&mut e0, &mut e1, &mut e2, &mut e3] {
        e.deliver_qc(qc_a.clone()).expect("deliver QC(a)");
        e.advance_view();
    }

    // View 1: e1 honestly proposes b@1 (prev = a, justify =
    // QC(a)). All four vote so QC(b) is real — but it is
    // delivered to NOBODY: e0/e2/e3 keep highQC = QC(a),
    // pending = a, and a height-1 lock on b.
    e1.submit_tx(TxBytes::new(vec![0xB0]));
    let (hb, pb) = e1.propose().expect("e1 proposes b@1");
    let hash_b = OxideBft::block_hash(&hb);
    assert_eq!(hb.prev_block, hash_a, "honest b extends a");
    e1.collect_vote(
        1,
        Vote {
            view: hb.view,
            phase: VotePhase::Prepare,
            block_hash: hash_b,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        },
    )
    .expect("conformance mode");
    for (voter_idx, e) in [(0u16, &mut e0), (2, &mut e2), (3, &mut e3)] {
        let v = e.vote(&hb, &pb).expect("honest vote for b");
        e1.collect_vote(voter_idx, v).expect("collect");
    }
    let qc_b = e1.try_form_qc().expect("QC(b) is real");

    // View 1 times out everywhere: TC(1) forms and advances all
    // engines to view 2 — the release evidence the crafted
    // proposal will carry.
    let tc1 = timeout_round(&mut [&mut e0, &mut e1, &mut e2, &mut e3]);
    assert_eq!(e0.current_view(), View::new(2), "TC(1) advances to view 2");

    // View 2 — Byzantine leader e2 crafts `d`: prev = a (the
    // stale voters' highQC block), justify = QC(b), height = 1,
    // and TC(1) as the lock-release evidence. Every pre-fix
    // check passes for e0/e2/e3: prev == their highQC block,
    // justify.view > theirs, height = parent + 1, and the TC
    // releases their b-lock at height 1.
    let d_header = BlockHeader {
        view: View::new(2),
        height: Height::new(1),
        prev_block: hash_a,          // the stale voters' highQC block
        high_qc: Some(qc_b.clone()), // justify: a DIFFERENT, newer notarized block
        timeout_cert: Some(tc1),
        ..hb.clone()
    };
    // d carries its own payload so a commit is distinguishable
    // from b's.
    let d_proposal = Proposal {
        height: d_header.height,
        txs: vec![TxBytes::new(vec![0xD0])],
        attestation: None,
    };
    let hash_d = OxideBft::block_hash(&d_header);
    assert_ne!(hash_d, hash_b, "crafted block is distinct from b");

    assert!(
        e0.vote(&d_header, &d_proposal).is_none(),
        "prev=a / justify=b divergence must be rejected"
    );
    assert!(
        e2.vote(&d_header, &d_proposal).is_none(),
        "TC-released lock does not rescue a divergent justify"
    );
    assert!(
        e3.vote(&d_header, &d_proposal).is_none(),
        "prev=a / justify=b divergence must be rejected"
    );

    // The honest chain is unaffected: deliver QC(b) (commits a —
    // the (a@0, b@1) link is consecutive), advance, and resume the
    // pipeline. The first resumed block (view 3) extends QC(b)@1
    // across the timed-out gap — a *nonconsecutive* link, so b
    // cannot commit through it; b commits transitively when the
    // next consecutive pair (view 4 → view 3) lands above it.
    for e in [&mut e0, &mut e1, &mut e2, &mut e3] {
        e.deliver_qc(qc_b.clone()).expect("deliver QC(b)");
        e.advance_view();
    }
    drive_round(&mut e3, &mut [&mut e0, &mut e1, &mut e2], Some(TxBytes::new(vec![0xC0])));
    drive_round(&mut e0, &mut [&mut e1, &mut e2, &mut e3], Some(TxBytes::new(vec![0xE0])));

    // b@1 — not d — commits, and the committed prefix is
    // contiguous from genesis.
    let b1 = e1.finalized_block(Height::new(1)).expect("b@1 committed");
    assert_eq!(b1.txs[0].as_bytes(), [0xB0], "height 1 must contain b, not d");
    let h = e1.finalized_height().map_or(0, Height::value);
    for height in 0..=h {
        assert!(e1.finalized_block(Height::new(height)).is_some(), "height {height} committed");
    }
}

/// Commit-rule completeness (third TLC finding): adopting a QC
/// must commit the *entire* certified ancestor chain, not just
/// the single `pending` link. With the single-link rule, a
/// validator whose stored blocks outpace its pending pointer —
/// the state a block-import/catch-up seam produces — skips the
/// intermediate commits forever: adopting QC(b3) with pending
/// b0 committed nothing, and the chain finalized b3 later with
/// heights 1..2 missing (`InvNoGap` counterexample shape).
///
/// The scenario is not reachable through `vote()` today —
/// storage is prefix-closed (a vote requires the parent stored)
/// so pending can never actually lag the stored chain — but the
/// commit rule must be correct against the storage states the
/// planned import seam will create, so the test seeds `blocks`
/// directly.
#[test]
fn leapfrog_qc_commits_full_ancestor_chain() {
    let mut e0 = make_multi_engine(0);
    e0.current_view = View::new(10);

    let qc = |view: u64, block_hash: Hash| QuorumCertificate {
        view: View::new(view),
        phase: VotePhase::Prepare,
        block_hash,
        epoch: Epoch::new(0),
        // 3-of-4 signers: meets quorum under conformance mode.
        signer_bitmap: vec![0x07],
        aggregate_signature: AggregateSignature::ZERO,
    };
    let store = |e: &mut OxideBft,
                 height: u64,
                 view: u64,
                 prev_block: Hash,
                 high_qc: Option<QuorumCertificate>,
                 tag: u8| {
        let header = BlockHeader {
            height: Height::new(height),
            view: View::new(view),
            epoch: Epoch::new(0),
            prev_block,
            tx_root: Hash([tag; 32]),
            high_qc,
            timeout_cert: None,
            proposer: Hash([tag; 32]),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: None,
            body_commitment: Hash::ZERO,
        };
        let proposal = Proposal {
            height: header.height,
            txs: vec![TxBytes::new(vec![tag])],
            attestation: None,
        };
        let hash = OxideBft::block_hash(&header);
        e.blocks.insert(hash, (header, BlockBody::Complete(proposal.clone())));
        (hash, proposal)
    };

    let (h0, _) = store(&mut e0, 0, 0, Hash::ZERO, None, 0xB0);
    let (h1, _) = store(&mut e0, 1, 1, h0, Some(qc(0, h0)), 0xB1);
    let (h2, _) = store(&mut e0, 2, 2, h1, Some(qc(1, h1)), 0xB2);
    let (h3, _) = store(&mut e0, 3, 3, h2, Some(qc(2, h2)), 0xB3);

    // QC(b3) arrives (e.g. via catch-up): commits b2, and the
    // recursive walk must finalize b0 and b1 beneath it —
    // oldest first.
    e0.deliver_qc(qc(3, h3)).expect("leapfrog QC accepted");

    for (height, tag) in [(0u64, 0xB0u8), (1, 0xB1), (2, 0xB2)] {
        let block = e0
            .finalized_block(Height::new(height))
            .unwrap_or_else(|| panic!("height {height} must be committed"));
        assert_eq!(block.txs[0].as_bytes(), [tag], "height {height} content");
    }
    assert!(
        e0.finalized_block(Height::new(3)).is_none(),
        "b3 is notarized, not committed — commits need its child QC"
    );
}

/// Companion (integrity): the embedded QC's aggregate signature
/// is commit evidence — its bitmap becomes the committed
/// parent's attendance record in `commit_block`. A proposal
/// carrying a structurally consistent but *unverifiable* QC must
/// be rejected at vote time, not deferred to commit.
#[test]
fn proposal_with_forged_embedded_qc_is_rejected() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
    let mut voter = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());

    // Real QC(a) for a genesis block: voter adopts it so the
    // proposal's embedded QC is a newer-view claim.
    let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone());
    leader.submit_tx(TxBytes::new(vec![0xA0]));
    let (ha, pa) = leader.propose().expect("leader proposes a");
    let hash_a = OxideBft::block_hash(&ha);
    // Sign a real quorum of votes for a.
    let mut sigs = Vec::new();
    for (i, k) in keys.iter().enumerate() {
        let mut msg = Vec::with_capacity(49);
        msg.extend_from_slice(&ha.view.value().to_le_bytes());
        msg.push(VotePhase::Prepare as u8);
        msg.extend_from_slice(hash_a.as_bytes());
        msg.extend_from_slice(&leader.epoch.value().to_le_bytes());
        sigs.push((i, k.sign(crypto::hash::Domain::Vote, &msg)));
    }
    for (i, sig) in sigs.iter().take(3) {
        leader
            .collect_vote(
                u16::try_from(*i).unwrap_or(0),
                Vote {
                    view: ha.view,
                    phase: VotePhase::Prepare,
                    block_hash: hash_a,
                    signature: *sig,
                    attestation: None,
                    attestation_sig: None,
                },
            )
            .expect("real votes");
    }
    let qc_a = leader.try_form_qc().expect("real QC(a)");
    // The voter must have `a` stored (the height-continuity check
    // needs the parent header), so it votes for a first, then
    // adopts QC(a).
    assert!(voter.vote(&ha, &pa).is_some(), "voter stores a via its vote");
    voter.deliver_qc(qc_a.clone()).expect("adopt real QC(a)");
    voter.advance_view();

    // Craft a child proposal whose embedded QC has a valid
    // structure (certifies a, the real parent) but a garbage
    // aggregate signature. Pre-fix: the embedded QC was never
    // verified, so the vote passed. Post-fix: reject.
    let mut forged_qc = qc_a.clone();
    forged_qc.aggregate_signature = AggregateSignature::ZERO;
    let mut header_c = ha.clone();
    header_c.view = View::new(1);
    header_c.height = Height::new(1);
    header_c.prev_block = hash_a;
    header_c.high_qc = Some(forged_qc);
    // Re-sign the crafted header as the view-1 leader so the
    // proposer check passes and only the embedded QC is bad.
    let leader_idx = vs.leader(header_c.view);
    header_c.proposer = proposer_hash(leader_idx);
    let signing_hash = OxideBft::proposal_signing_hash(&header_c);
    header_c.proposer_signature = Some(
        keys[usize::from(leader_idx)].sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()),
    );
    voter.current_view = header_c.view;
    assert!(
        voter.vote(&header_c, &pa).is_none(),
        "a proposal carrying an unverifiable embedded QC must be rejected"
    );
}

/// Complement: without the TC the lock still holds — a retried
/// proposal at a locked height with different content is refused.
#[test]
fn same_height_lock_holds_without_timeout_certificate() {
    let mut e0 = make_multi_engine(0);
    let mut e1 = make_multi_engine(1);

    e0.submit_tx(TxBytes::new(vec![0xA0]));
    let (ha, pa) = e0.propose().expect("leader proposes A");
    assert!(e1.vote(&ha, &pa).is_some(), "e1 votes A at height 0");

    // Advance the view WITHOUT a TC (models the QC/happy-path
    // advance the driver performs) and craft a conflicting
    // same-height block — no TC is attached, so the lock holds.
    e1.advance_view();
    let mut hb = ha.clone();
    hb.view = View::new(1);
    hb.tx_root = Hash([0xAB; 32]);
    assert!(
        e1.vote(&hb, &pa).is_none(),
        "same-height conflict without TC evidence must be refused"
    );
}

// ---- BLS integration tests (stage 5) ----
//
// These tests use real BLS signing (via blst) to prove the engine
// produces valid signatures and aggregate signatures.

fn bls_key(byte: u8) -> crypto::BlsSecretKey {
    let ikm = vec![byte; 32];
    crypto::BlsSecretKey::from_ikm(&ikm).expect("key gen")
}

/// Mint the admission-proof token for a real key — the shape
/// `EpochChanges`/`apply_*` now require: only a point + subgroup
/// member can cross the module → engine seam.
fn vpk(sk: &crypto::BlsSecretKey) -> crypto::bls_signer::ValidatedPublicKey {
    crypto::bls_signer::ValidatedPublicKey::new(sk.public_key()).expect("real key validates")
}

/// Sign a timeout claim exactly as `collect_timeout_signature`
/// verifies it: `(view, epoch, qc_high)` under `Domain::Timeout`.
fn sign_timeout_claim(
    sk: &crypto::BlsSecretKey,
    view: View,
    epoch: Epoch,
    high_qc: Option<&QuorumCertificate>,
) -> Signature {
    let msg = crate::verify::timeout_signing_message(view, epoch, high_qc);
    sk.sign(crypto::hash::Domain::Timeout, &msg)
}

/// Build a real TC for `view`/`epoch` from `(voter, key, qc_high)`
/// entries — each record signed over its own evidence claim (the
/// Jolteon per-signer shape).
fn make_tc(
    view: u64,
    epoch: u64,
    entries: &[(ValidatorIndex, &crypto::BlsSecretKey, Option<QuorumCertificate>)],
) -> TimeoutCertificate {
    TimeoutCertificate {
        view: View::new(view),
        epoch: Epoch::new(epoch),
        signers: entries
            .iter()
            .map(|(voter, sk, qc)| types::TimeoutSigner {
                voter: *voter,
                high_qc: qc.clone(),
                signature: sign_timeout_claim(sk, View::new(view), Epoch::new(epoch), qc.as_ref()),
            })
            .collect(),
    }
}

/// Conformance-mode TC: real signer indices, placeholder
/// signatures, no evidence — for engines running with
/// `verify_signatures = false`.
fn conformance_tc(view: u64, epoch: u64, voters: &[u16]) -> TimeoutCertificate {
    TimeoutCertificate {
        view: View::new(view),
        epoch: Epoch::new(epoch),
        signers: voters
            .iter()
            .map(|&voter| types::TimeoutSigner { voter, high_qc: None, signature: Signature::ZERO })
            .collect(),
    }
}

/// Drive a full timeout round over conformance-mode engines: every
/// engine signs its timeout (with its real `high_qc` claim), then
/// every engine collects every signature. Returns the TC they all
/// form. Mirrors what the wire pump does in the devnet binary.
fn timeout_round(engines: &mut [&mut OxideBft]) -> TimeoutCertificate {
    let records: Vec<(ValidatorIndex, Signature, Option<QuorumCertificate>)> = engines
        .iter_mut()
        .map(|e| {
            let sig = e.on_timeout().expect("timeout signature");
            (e.validator_index(), sig, e.high_qc().cloned())
        })
        .collect();
    let mut formed = None;
    for engine in engines.iter_mut() {
        for (voter, sig, qc) in &records {
            if let Ok(Some(tc)) = engine.collect_timeout_signature(*voter, *sig, qc.clone()) {
                formed = Some(tc);
            }
        }
    }
    formed.expect("a full timeout round must form a TC")
}

#[test]
fn bls_signed_vote_verifies() {
    // Single validator with a real BLS key. The validator set
    // must contain the real PK derived from the secret key so
    // that deliver_qc's signature verification passes.
    let key = bls_key(1);
    let pk = key.public_key();
    let app = Arc::new(MockApp::new());
    let vs = ValidatorSet::new(vec![pk], vec![1]).expect("1 validator with real PK");
    let mut engine = OxideBft::new(app, vs).with_secret_key(key);
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();

    // The engine should have formed a QC with a real aggregate
    // signature (not ZERO).
    let qc = engine.high_qc.as_ref().map(VerifiedQc::qc).expect("high_qc");
    assert_ne!(
        qc.aggregate_signature,
        AggregateSignature::ZERO,
        "QC must have a real aggregate signature"
    );

    // Verify the aggregate signature against the validator's PK.
    // C3 fix: the signed message now binds (view, phase,
    // block_hash, epoch).
    let block_hash = qc.block_hash;
    let mut msg = Vec::with_capacity(49);
    msg.extend_from_slice(&qc.view.value().to_le_bytes());
    msg.push(qc.phase as u8);
    msg.extend_from_slice(block_hash.as_bytes());
    msg.extend_from_slice(&qc.epoch.value().to_le_bytes());
    let result =
        crypto::aggregate_verify(&qc.aggregate_signature, crypto::hash::Domain::Vote, &msg, &[pk]);
    assert!(result.is_ok(), "QC aggregate signature must verify");
}

/// The `ConsensusSigner` seam: an engine built on a trait-object
/// signer produces verifiable signatures, a failing signer
/// withholds them (no proposal, no vote), and recovery needs no
/// restart — a transient outage is a liveness event, not a latch.
#[test]
fn remote_signer_seam_signs_and_fails_closed() {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A stand-in for a remote-signer client: delegates to a real
    /// key but can be toggled to report the endpoint down.
    struct StubSigner {
        key: crypto::BlsSecretKey,
        up: AtomicBool,
    }
    impl crypto::ConsensusSigner for StubSigner {
        fn public_key(&self) -> crypto::bls::PublicKey {
            self.key.public_key()
        }
        fn sign(
            &self,
            domain: crypto::Domain,
            msg: &[u8],
            _ctx: crypto::SignContext,
        ) -> Result<crypto::Signature, crypto::SignerError> {
            if self.up.load(Ordering::Relaxed) {
                Ok(self.key.sign(domain, msg))
            } else {
                Err(crypto::SignerError::Unavailable("endpoint down".into()))
            }
        }
    }

    let key = bls_key(1);
    let pk = key.public_key();
    let signer = Arc::new(StubSigner { key, up: AtomicBool::new(true) });
    let vs = ValidatorSet::new(vec![pk], vec![1]).expect("1 validator with real PK");
    let mut engine = OxideBft::new(Arc::new(MockApp::new()), vs)
        .with_signer(signer.clone() as Arc<dyn crypto::ConsensusSigner>);

    // Signer up: the engine signs and a real QC forms.
    engine.submit_tx(TxBytes::new(vec![7]));
    let (header, _) = engine.propose().expect("propose with live signer");
    assert!(header.proposer_signature.is_some(), "proposal must carry the signature");
    engine.run_until_idle();
    let qc = engine.high_qc.as_ref().map(VerifiedQc::qc).expect("high_qc");
    assert_ne!(qc.aggregate_signature, AggregateSignature::ZERO);

    // Signer down: proposal withheld entirely (an unsigned proposal
    // would fail authentication everywhere), and no vote/attest
    // signature leaks — fail-closed silence, not a latch.
    signer.up.store(false, Ordering::Relaxed);
    engine.submit_tx(TxBytes::new(vec![8]));
    assert!(engine.propose().is_none(), "a downed signer must withhold the proposal");

    // Signer back: signing resumes without a restart.
    signer.up.store(true, Ordering::Relaxed);
    assert!(engine.propose().is_some(), "a recovered signer must resume signing");
}

#[test]
fn bls_multi_validator_qc_verifies() {
    // 4 validators with real BLS keys.
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let stakes = vec![1u64; 4];
    let vs = ValidatorSet::new(pks.clone(), stakes).expect("4 validators");

    let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone());
    let mut followers: Vec<OxideBft> = (1..4u8)
        .map(|i| {
            OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), u16::from(i))
                .with_secret_key(keys[i as usize].clone())
        })
        .collect();

    // Submit a tx and drive one round.
    leader.submit_tx(TxBytes::new(vec![42]));
    let (header, proposal) = leader.propose().expect("propose");
    let block_hash = OxideBft::block_hash(&header);

    // Leader self-votes. C3 fix: sign with (view, phase,
    // block_hash, epoch) message.
    let mut vote_msg = Vec::with_capacity(49);
    vote_msg.extend_from_slice(&header.view.value().to_le_bytes());
    vote_msg.push(VotePhase::Prepare as u8);
    vote_msg.extend_from_slice(block_hash.as_bytes());
    vote_msg.extend_from_slice(&leader.epoch.value().to_le_bytes());
    let leader_sig = keys[0].sign(crypto::hash::Domain::Vote, &vote_msg);
    leader
        .collect_vote(
            0,
            Vote {
                view: header.view,
                phase: VotePhase::Prepare,
                block_hash,
                signature: leader_sig,
                attestation: None,
                attestation_sig: None,
            },
        )
        .expect("valid self-vote must verify");

    // Followers vote.
    for (i, follower) in followers.iter_mut().enumerate() {
        if let Some(vote) = follower.vote(&header, &proposal) {
            leader
                .collect_vote(u16::try_from(i + 1).expect("validator index fits u16"), vote)
                .expect("valid follower vote must verify");
        }
    }

    // Form QC.
    let qc = leader.try_form_qc().expect("quorum");
    assert_ne!(
        qc.aggregate_signature,
        AggregateSignature::ZERO,
        "QC must have a real aggregate signature"
    );

    // Verify the aggregate signature against all 4 public keys.
    // C3 fix: verify against (view, phase, block_hash, epoch).
    let mut verify_msg = Vec::with_capacity(49);
    verify_msg.extend_from_slice(&qc.view.value().to_le_bytes());
    verify_msg.push(qc.phase as u8);
    verify_msg.extend_from_slice(block_hash.as_bytes());
    verify_msg.extend_from_slice(&qc.epoch.value().to_le_bytes());
    let result = crypto::aggregate_verify(
        &qc.aggregate_signature,
        crypto::hash::Domain::Vote,
        &verify_msg,
        &pks,
    );
    assert!(result.is_ok(), "QC aggregate signature must verify against all 4 keys");
}

// ---- C1 fix: signature verification tests ----
//
// These tests prove the production vote path rejects forged
// votes and QCs (the C1 audit finding). A forged vote has a
// signature that does not verify against the claimed voter's
// public key. A forged QC has an aggregate signature that does
// not verify against the signer bitmap's public keys.

/// Regression test (C3): `vote()` must reject a proposal whose
/// `proposer` field does not match the expected leader for the
/// view. Without this check, any validator could fabricate a
/// proposal in any view.
#[test]
fn vote_rejects_proposal_from_wrong_proposer() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());

    // Leader for view 0 is index 0 (round-robin/stake-weighted).
    // Construct a header claiming proposer = validator 2 (wrong).
    let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
    let mut header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: Hash::ZERO,
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(2), // wrong proposer
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    // Even with a valid signature from key 2, the proposer field
    // doesn't match the expected leader (0), so vote() rejects.
    let sk2 = bls_key(3);
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(sk2.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
    assert!(
        follower.vote(&header, &proposal).is_none(),
        "proposal from wrong proposer must be rejected"
    );
}

/// Regression test (C3): `vote()` must reject a proposal with a
/// missing or invalid proposer signature. The signature proves
/// the claimed leader actually created the proposal.
#[test]
fn vote_rejects_proposal_with_missing_signature() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());

    let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
    // Correct proposer (leader 0 for view 0) but no signature.
    let header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: Hash::ZERO,
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None, // missing
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    assert!(
        follower.vote(&header, &proposal).is_none(),
        "proposal with missing proposer signature must be rejected"
    );
}

/// Regression test (C3): `vote()` must reject a proposal with a
/// forged proposer signature (signed by a different key).
#[test]
fn vote_rejects_proposal_with_forged_signature() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());

    let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
    // Correct proposer (leader 0 for view 0) but signed by key 3.
    let mut header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: Hash::ZERO,
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let forged_sk = bls_key(3);
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(forged_sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
    assert!(
        follower.vote(&header, &proposal).is_none(),
        "proposal with forged proposer signature must be rejected"
    );
}

/// Regression test: a rejected proposal is memoised — re-delivering
/// it must not re-run the proposer-signature verify, and its body
/// must never enter the block store.
///
/// The pump retries `vote()` for pending entries every iteration;
/// without a negative memo each retry re-paid the full
/// authentication, which is exactly the exhaustion vector a junk-
/// proposal flood exploits. The verdict is a pure function of the
/// header bytes, so `rejected_headers` short-circuits repeats.
#[test]
fn vote_memoises_rejected_proposal() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());

    let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
    // Correct leader claim for view 0 but signed by the wrong key —
    // it passes the cheap intake checks and fails at the BLS verify.
    let mut header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: Hash::ZERO,
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let forged_sk = bls_key(3);
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(forged_sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));

    let hash = OxideBft::block_hash(&header);
    assert!(follower.vote(&header, &proposal).is_none());
    assert!(follower.rejected_headers.contains(&hash), "a failed authentication must be memoised");
    assert!(
        !follower.blocks.contains_key(&hash),
        "a rejected proposal's body must never be stored"
    );
    // Re-delivery: same verdict, and — with the memo — no repeat
    // verify. The memo also covers a mutated body presented under
    // the same header hash: still the same rejected identity.
    let mut junk_body = proposal.clone();
    junk_body.txs.push(TxBytes::new(vec![0xFF]));
    assert!(follower.vote(&header, &junk_body).is_none());
    assert!(follower.rejected_headers.contains(&hash));
}

/// The positive side of the memo: once a proposal's body is stored
/// `Complete`, a re-delivery skips re-authentication entirely —
/// including the body-commitment check. A second, equivocating body
/// under the same header therefore cannot fail the check (it is
/// never checked) and cannot replace the verified body.
#[test]
fn vote_redelivery_uses_stored_body() {
    let mut leader = make_multi_engine(0);
    let mut follower = make_multi_engine(1);

    leader.submit_tx(TxBytes::new(vec![0xA0]));
    let (header, proposal) = leader.propose().expect("leader proposes");
    let hash = OxideBft::block_hash(&header);
    assert!(follower.vote(&header, &proposal).is_some(), "first vote lands");
    assert!(
        matches!(follower.blocks.get(&hash), Some((_, BlockBody::Complete(_)))),
        "authenticated body stored"
    );

    // Equivocation attempt: same header, different body bytes. The
    // memoised path must skip the commitment re-check (so the hash
    // must NOT enter rejected_headers) and must not overwrite the
    // stored body.
    let mut equivocated = proposal.clone();
    equivocated.txs.push(TxBytes::new(vec![0xEE]));
    assert!(follower.vote(&header, &equivocated).is_none());
    assert!(
        !follower.rejected_headers.contains(&hash),
        "memoised re-delivery must not re-run the commitment check"
    );
    assert!(
        matches!(
            follower.blocks.get(&hash),
            Some((_, BlockBody::Complete(stored))) if stored.txs.len() == 1
        ),
        "the originally verified body must remain stored"
    );
}

/// The censorship fix: an authentic header whose first delivered
/// body fails the commitment check must park as `Awaiting` — not be
/// memoised as rejected. A corrupting relay cannot sign the header
/// itself, so a bad body indicts the *delivery*, not the header;
/// rejecting the header permanently would let one bad body censor
/// the genuine proposal behind it.
#[test]
fn admit_proposal_bad_body_does_not_poison_header() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone());
    let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());

    leader.submit_tx(TxBytes::new(vec![0xA0]));
    let (header, proposal) = leader.propose().expect("leader proposes");
    let hash = OxideBft::block_hash(&header);

    // A relay swaps in a corrupt body: the header is authentic, the
    // body is not what the commitment covers.
    let mut bad_body = proposal.clone();
    bad_body.txs.push(TxBytes::new(vec![0xEE]));
    assert!(
        !follower.admit_proposal(&header, &bad_body),
        "a body that fails the commitment check must not complete"
    );
    assert!(
        matches!(follower.blocks.get(&hash), Some((_, BlockBody::Awaiting))),
        "the authentic header must be parked Awaiting, not rejected"
    );
    assert!(
        !follower.rejected_headers.contains(&hash),
        "a bad body must not poison the header's verdict"
    );
    assert!(follower.proposal_known(&hash));

    // The genuine body arrives on a second delivery — it completes
    // the parked header without re-paying authentication.
    assert!(
        follower.admit_proposal(&header, &proposal),
        "the genuine body must still complete the proposal"
    );
    assert!(matches!(follower.blocks.get(&hash), Some((_, BlockBody::Complete(_)))));
}

/// The driver-side dedupe contract: `proposal_known` is the
/// authenticated check — true for a stored proposal, false for a
/// forged one that only claimed the leader slot. Drivers must queue
/// retries only for the former, or a forged first delivery parks
/// the `(view, proposer)` slot and censors the genuine proposal.
#[test]
fn proposal_known_distinguishes_authentic_from_forged() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone());
    let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());

    // Forged: right leader claim, wrong signing key.
    let mut forged = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: Hash::ZERO,
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let signing_hash = OxideBft::proposal_signing_hash(&forged);
    forged.proposer_signature =
        Some(bls_key(3).sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
    let forged_hash = OxideBft::block_hash(&forged);
    let junk = Proposal { height: Height::new(0), txs: vec![], attestation: None };
    assert!(!follower.admit_proposal(&forged, &junk));
    assert!(!follower.proposal_known(&forged_hash), "a forged proposal must never report known");

    // Authentic: the real leader's proposal.
    leader.submit_tx(TxBytes::new(vec![0xA0]));
    let (header, proposal) = leader.propose().expect("leader proposes");
    let hash = OxideBft::block_hash(&header);
    assert!(follower.admit_proposal(&header, &proposal));
    assert!(follower.proposal_known(&hash));
}

/// The intake gate: `proposal_admissible` accepts only in-window,
/// scheduled-leader proposals — the two cheap checks a driver must
/// run before queueing anything for `vote()`.
#[test]
fn proposal_admissible_gates_window_and_leader() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut voter = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());
    voter.current_view = View::new(50);

    let mk = |view: u64, proposer: ValidatorIndex| BlockHeader {
        height: Height::new(view),
        view: View::new(view),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: Hash::ZERO,
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(proposer),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };

    // In-window edges: [50−10, 50+32] = [40, 82] with the correct
    // scheduled leader for each view.
    for v in [40, 50, 82] {
        assert!(
            voter.proposal_admissible(&mk(v, vs.leader(View::new(v)))),
            "view {v} by its scheduled leader must be admissible"
        );
    }
    // Just outside the window on both sides.
    assert!(!voter.proposal_admissible(&mk(39, vs.leader(View::new(39)))));
    assert!(!voter.proposal_admissible(&mk(83, vs.leader(View::new(83)))));
    // Right view, wrong claimant — the free rejection that keeps
    // non-leader junk off the verify path.
    let wrong = u16::try_from((usize::from(vs.leader(View::new(50))) + 1) % 4).unwrap_or(0);
    assert!(!voter.proposal_admissible(&mk(50, wrong)));
    // Far-future view even with its correct leader.
    assert!(!voter.proposal_admissible(&mk(10_000, vs.leader(View::new(10_000)))));
}

/// `vote_header` shares the memoisation contract: rejected headers
/// short-circuit and stored entries skip re-authentication.
#[test]
fn vote_header_memoises_rejected_proposal() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut follower = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 1)
        .with_secret_key(keys[1].clone());

    let mut header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: Hash::ZERO,
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(bls_key(3).sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));

    let hash = OxideBft::block_hash(&header);
    assert!(follower.vote_header(&header).is_none());
    assert!(follower.rejected_headers.contains(&hash));
    assert!(!follower.blocks.contains_key(&hash));
    // Repeat delivery — memoised, still refused.
    assert!(follower.vote_header(&header).is_none());
}

/// A single forged vote must not stall the view.
///
/// `collect_vote` stores the first vote per validator *without*
/// verifying it (per-vote BLS verification is opt-in for cost
/// reasons), so a Byzantine validator can slip a bad signature into
/// the leader's buffer. Before this fix the resulting aggregate
/// failed verification at every receiver, so the view stalled until
/// its timeout — and because the bad vote stayed buffered, it
/// poisoned every retry: one participant, one permanently stalled
/// view. The leader must now detect its own bad aggregate,
/// quarantine the invalid contribution, and still form a QC from
/// the honest quorum.
#[test]
fn forged_vote_is_quarantined_and_quorum_still_forms() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    leader.submit_tx(TxBytes::new(vec![42]));
    let (header, _proposal) = leader.propose().expect("propose");
    let block_hash = OxideBft::block_hash(&header);

    let mut msg = Vec::with_capacity(49);
    msg.extend_from_slice(&header.view.value().to_le_bytes());
    msg.push(VotePhase::Prepare as u8);
    msg.extend_from_slice(block_hash.as_bytes());
    msg.extend_from_slice(&leader.epoch.value().to_le_bytes());

    // Three honest votes — quorum at n=4 is 3.
    for voter in [0u16, 2, 3] {
        let vote = Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: keys[usize::from(voter)].sign(crypto::hash::Domain::Vote, &msg),
            attestation: None,
            attestation_sig: None,
        };
        leader.collect_vote(voter, vote).expect("honest vote accepted");
    }

    // Validator 1 equivocates by signing with validator 3's key:
    // well-formed bytes, wrong signer for the claimed slot.
    let forged = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: keys[3].sign(crypto::hash::Domain::Vote, &msg),
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, forged).expect("the default path stores without per-vote verification");

    // Nominal quorum is reached, but one contribution is forged.
    let qc = leader.try_form_qc().expect("the honest quorum must still form a QC after quarantine");

    // The QC must describe exactly the three honest signers.
    assert_eq!(qc.signer_bitmap, vec![0b0000_1101], "voter 1 must be quarantined");

    let honest_pks: Vec<crypto::bls::PublicKey> =
        [0usize, 2, 3].iter().map(|i| keys[*i].public_key()).collect();
    crypto::aggregate_verify(
        &qc.aggregate_signature,
        crypto::hash::Domain::Vote,
        &msg,
        &honest_pks,
    )
    .expect("the emitted QC must verify against exactly its signers");
}

/// If quarantine leaves less than a quorum, no QC may be emitted.
/// Broadcasting a certificate no peer can verify is worse than
/// stalling, and the honest votes must stay buffered for the retry.
#[test]
fn quarantine_below_quorum_emits_no_qc() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    leader.submit_tx(TxBytes::new(vec![42]));
    let (header, _proposal) = leader.propose().expect("propose");
    let block_hash = OxideBft::block_hash(&header);

    let mut msg = Vec::with_capacity(49);
    msg.extend_from_slice(&header.view.value().to_le_bytes());
    msg.push(VotePhase::Prepare as u8);
    msg.extend_from_slice(block_hash.as_bytes());
    msg.extend_from_slice(&leader.epoch.value().to_le_bytes());

    // Two honest votes plus one forged: nominally 3, honestly 2.
    for voter in [0u16, 2] {
        let vote = Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: keys[usize::from(voter)].sign(crypto::hash::Domain::Vote, &msg),
            attestation: None,
            attestation_sig: None,
        };
        leader.collect_vote(voter, vote).expect("honest vote accepted");
    }
    leader
        .collect_vote(
            1,
            Vote {
                view: header.view,
                phase: VotePhase::Prepare,
                block_hash,
                signature: keys[3].sign(crypto::hash::Domain::Vote, &msg),
                attestation: None,
                attestation_sig: None,
            },
        )
        .expect("default path stores without per-vote verification");

    assert!(leader.try_form_qc().is_none(), "must not emit a QC it cannot prove");
    assert_eq!(leader.vote_count(), 2, "honest votes must be preserved for the retry");
}

#[test]
fn collect_vote_rejects_forged_signature() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone())
        .with_per_vote_verification();

    // Submit a tx and propose.
    leader.submit_tx(TxBytes::new(vec![42]));
    let (header, _proposal) = leader.propose().expect("propose");
    let block_hash = OxideBft::block_hash(&header);

    // Forge a vote: sign with key[2] but claim it's from validator 1.
    // The signature will verify against key[2]'s PK, not key[1]'s PK.
    // C3 fix: use the full (view, phase, block_hash, epoch) message.
    let mut vote_msg = Vec::with_capacity(49);
    vote_msg.extend_from_slice(&header.view.value().to_le_bytes());
    vote_msg.push(VotePhase::Prepare as u8);
    vote_msg.extend_from_slice(block_hash.as_bytes());
    vote_msg.extend_from_slice(&leader.epoch.value().to_le_bytes());
    let forged_sig = keys[2].sign(crypto::hash::Domain::Vote, &vote_msg);
    let forged_vote = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: forged_sig,
        attestation: None,
        attestation_sig: None,
    };

    // collect_vote must reject the forged vote.
    let err = leader.collect_vote(1, forged_vote).expect_err("forged vote must be rejected");
    assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 1 });
}

#[test]
fn collect_vote_rejects_out_of_bounds_voter() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    let block_hash = Hash::ZERO;
    let vote = Vote {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };

    // Voter index 99 is out of bounds (n=4).
    let err = leader.collect_vote(99, vote).expect_err("out-of-bounds voter must be rejected");
    assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 99 });
}

/// C9 fix: `save_state` / `restore_state` round-trip must preserve
/// the engine's safety-critical state.
#[test]
fn save_restore_state_round_trip() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone());

    // Advance the engine: submit, propose, vote.
    leader.submit_tx(TxBytes::new(vec![42]));
    let (header, _proposal) = leader.propose().expect("propose");
    let block_hash = OxideBft::block_hash(&header);

    // Simulate a vote at height 0 for this block.
    leader.voted_at_height.insert(0, block_hash);

    // The committed anchor must also round-trip: it is safety
    // state (the no-highQC vote arm's parent check).
    leader.last_committed = Some((block_hash, header.height));

    // Save the state.
    let state_bytes = leader.save_state();
    assert!(!state_bytes.is_empty(), "save_state must produce non-empty bytes");

    // Create a fresh engine and restore the state.
    let mut restored =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    restored.restore_state(&state_bytes).expect("restore_state must succeed");

    // Verify the state was restored.
    assert_eq!(restored.current_view, leader.current_view, "current_view must match");
    assert_eq!(restored.last_voted_view, leader.last_voted_view, "last_voted_view must match");
    assert_eq!(restored.next_height, leader.next_height, "next_height must match");
    assert_eq!(restored.epoch, leader.epoch, "epoch must match");
    assert_eq!(restored.high_qc, leader.high_qc, "high_qc must match");
    assert_eq!(restored.voted_at_height, leader.voted_at_height, "voted_at_height must match");
    assert_eq!(restored.last_committed, leader.last_committed, "last_committed must match");
}

/// C9 fix: `restore_state` must reject malformed buffers.
#[test]
fn restore_state_rejects_malformed_buffer() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    // Too short (less than 33 bytes).
    let short = vec![0u8; 10];
    let err = leader.restore_state(&short).expect_err("short buffer must be rejected");
    assert_eq!(err, ConsensusError::InvalidState);

    // Empty buffer.
    let empty: Vec<u8> = vec![];
    let err = leader.restore_state(&empty).expect_err("empty buffer must be rejected");
    assert_eq!(err, ConsensusError::InvalidState);
}

#[test]
fn deliver_qc_rejects_forged_aggregate() {
    // 4 validators with real BLS keys. A QC with a forged aggregate
    // signature (all zeros) must be rejected by deliver_qc.
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut engine =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    // Forge a QC: all-zero aggregate signature, but the signer
    // bitmap claims all 4 validators signed.
    let forged_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash::ZERO,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111], // all 4 validators
        aggregate_signature: AggregateSignature::ZERO, // forged
    };

    let err = engine.deliver_qc(forged_qc).expect_err("forged QC must be rejected");
    assert_eq!(err, ConsensusError::InvalidQcSignature);
}

#[test]
fn collect_vote_accepts_valid_signature() {
    // 4 validators with real BLS keys. A valid vote (signed by
    // the claimed voter's key) must be accepted.
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut leader =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    leader.submit_tx(TxBytes::new(vec![42]));
    let (header, _proposal) = leader.propose().expect("propose");
    let block_hash = OxideBft::block_hash(&header);

    // Validator 1 signs its own vote with its own key.
    // C3 fix: sign with (view, phase, block_hash, epoch) message.
    let mut vote_msg = Vec::with_capacity(49);
    vote_msg.extend_from_slice(&header.view.value().to_le_bytes());
    vote_msg.push(VotePhase::Prepare as u8);
    vote_msg.extend_from_slice(block_hash.as_bytes());
    vote_msg.extend_from_slice(&leader.epoch.value().to_le_bytes());
    let valid_sig = keys[1].sign(crypto::hash::Domain::Vote, &vote_msg);
    let valid_vote = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: valid_sig,
        attestation: None,
        attestation_sig: None,
    };

    leader.collect_vote(1, valid_vote).expect("valid vote must be accepted");
}

#[test]
fn on_timeout_certificate_rejects_forged_tc() {
    // 4 validators with real BLS keys. A TC with a forged aggregate
    // signature (all zeros) must be rejected by on_timeout_certificate.
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut engine =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    // Forge a TC: all four signer records carry all-zero
    // signatures — nothing verifiable behind them.
    let forged_tc = TimeoutCertificate {
        view: View::new(0),
        epoch: Epoch::new(0),
        signers: (0u16..4)
            .map(|voter| types::TimeoutSigner {
                voter,
                high_qc: None,
                signature: Signature::ZERO, // forged
            })
            .collect(),
    };

    let err = engine.on_timeout_certificate(&forged_tc).expect_err("forged TC must be rejected");
    assert_eq!(err, ConsensusError::InvalidTcSignature);
}

#[test]
fn collect_timeout_signature_rejects_forged_signature() {
    // 4 validators with real BLS keys. A forged timeout signature
    // (signed by the wrong key) must be rejected.
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut engine =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    // Validator 1 times out and signs the view.
    let _ = engine.on_timeout();

    // Forge a timeout signature: sign with validator 2's key but
    // claim it's from validator 1. The claim carries no evidence
    // (a view-0 timeout before any QC exists).
    let forged_sig = sign_timeout_claim(&keys[2], engine.current_view(), engine.epoch(), None);
    let err = engine
        .collect_timeout_signature(1, forged_sig, None)
        .expect_err("forged timeout signature must be rejected");
    assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 1 });
}

#[test]
fn collect_timeout_signature_accepts_valid_signature() {
    // 4 validators with real BLS keys. A valid timeout signature
    // (signed by the claimed voter's key) must be accepted.
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut engine =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    // Validator 1 signs the timeout for view 0 — no evidence yet
    // (no QC exists at view 0).
    let valid_sig = sign_timeout_claim(&keys[1], engine.current_view(), engine.epoch(), None);
    let result = engine.collect_timeout_signature(1, valid_sig, None);
    assert!(result.is_ok(), "valid timeout signature must be accepted");
}

// ---- Jolteon timeout-evidence tests ----
//
// The safety fix's three signatures: the timeout signature binds
// the signer's `qc_high`; a TC carries each signer's claim
// verbatim; and a validator that signed `timeout(v)` cannot vote
// in `v` (vote-then-timeout stays legal — the timeout then
// reports the lock the vote created).

/// Vote after timeout-signing is refused: the TC entry the
/// signature produced claims the `qc_high` held at signing time —
/// a later vote would create a lock the evidence doesn't report.
#[test]
fn vote_after_timeout_is_rejected() {
    let mut e0 = make_multi_engine(0);
    let mut e1 = make_multi_engine(1);

    // Time out view 0 first, then try to vote in view 0.
    let _sig = e0.on_timeout().expect("timeout signature");

    e1.submit_tx(TxBytes::new(vec![0x42]));
    let (h, p) = e1.propose().expect("leader proposes");
    // e0 already signed timeout(0): a view-0 vote would mean its
    // TC entry underreports what it actually did.
    assert!(e0.vote(&h, &p).is_none(), "a view we timed out on is unvotable — evidence integrity");
}

/// Vote then timeout stays legal, and the timeout signature binds
/// the voter's `qc_high` — the lock its vote produced.
#[test]
fn timeout_after_vote_reports_high_qc() {
    let (keys, vs) = bls_validator_set();
    let mut e0 = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone());

    // Drive one real round so a genuine QC exists to report:
    // propose, collect three signed votes, adopt the QC.
    e0.submit_tx(TxBytes::new(vec![0x11]));
    let (h, p) = e0.propose().expect("propose");
    let hash = OxideBft::block_hash(&h);
    let self_vote = e0.vote(&h, &p).expect("self vote");
    e0.collect_vote(0, self_vote).expect("collect");
    for i in 1u16..3 {
        let msg = e0.vote_signing_message(h.view, 0, &hash);
        let v = Vote {
            view: h.view,
            phase: VotePhase::Prepare,
            block_hash: hash,
            signature: keys[usize::from(i)].sign(crypto::hash::Domain::Vote, &msg),
            attestation: None,
            attestation_sig: None,
        };
        e0.collect_vote(i, v).expect("collect peer vote");
    }
    let qc = e0.try_form_qc().expect("quorum of real votes forms a QC");
    e0.deliver_qc(qc).expect("adopt the QC");
    e0.advance_view();

    // The timeout signature must cover (view, epoch, high_qc):
    // verify it end-to-end against the adopted high QC.
    let sig = e0.on_timeout().expect("timeout signature");
    let claimed = e0.high_qc().cloned();
    assert!(claimed.is_some(), "a QC was adopted — evidence exists");
    e0.verify_timeout_signature_for(0, e0.current_view(), e0.epoch(), claimed.as_ref(), &sig)
        .expect("timeout sig verifies over its qc_high claim");

    // And fails if a relay swaps the evidence claim for a different
    // (even absent) one — the claim is inside the signed message.
    assert!(
        e0.verify_timeout_signature_for(0, e0.current_view(), e0.epoch(), None, &sig).is_err(),
        "evidence swap must break the signature"
    );
}

/// A TC whose per-signer evidence was tampered with — claim
/// swapped for a different QC after signing — fails verification:
/// the signature is over the original claim.
#[test]
fn tc_with_swapped_evidence_is_rejected() {
    let (keys, vs) = bls_validator_set();
    let mut engine =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());
    // Drive the engine to view 5 so a TC(4) advances it.
    for _ in 0..5 {
        engine.advance_view();
    }

    let claimed_qc = QuorumCertificate {
        view: View::new(2),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x11; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0111],
        aggregate_signature: AggregateSignature::ZERO,
    };
    let mut tc = make_tc(
        4,
        0,
        &[
            (0, &keys[0], Some(claimed_qc.clone())),
            (1, &keys[1], Some(claimed_qc.clone())),
            (2, &keys[2], Some(claimed_qc)),
        ],
    );
    // Tamper: strip entry 0's evidence — the signature still
    // covers the original claim, so the TC fails verification.
    // (A swap to a *forged* QC dies earlier, at the QC check —
    // stripping isolates the evidence-binding property itself.)
    tc.signers[0].high_qc = None;
    let err = engine.on_timeout_certificate(&tc).expect_err("evidence-swapped TC must be rejected");
    assert_eq!(err, ConsensusError::InvalidTcSignature);
}

/// A TC entry whose `qc_high` is itself forged — a signed claim
/// about a certificate that doesn't verify — is rejected at
/// collection time, so it can never poison a TC's evidence set.
#[test]
fn timeout_sig_binding_forged_qc_is_rejected() {
    let (keys, vs) = bls_validator_set();
    let mut engine =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    let forged_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x77; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0111],
        aggregate_signature: AggregateSignature::ZERO, // forged
    };
    // Validator 1 signs a timeout claim carrying the forged QC —
    // its own signature is genuine; the evidence is not.
    let sig = sign_timeout_claim(&keys[1], engine.current_view(), engine.epoch(), Some(&forged_qc));
    let err = engine
        .collect_timeout_signature(1, sig, Some(forged_qc))
        .expect_err("a bound-but-forged QC claim must be rejected");
    assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 1 });
}

/// A forged timeout signature must not pass with mismatched
/// evidence: the signature binds the *exact* claim, so collecting
/// the same signature under a different `qc_high` fails.
#[test]
fn timeout_sig_rejects_evidence_substitution() {
    let (keys, vs) = bls_validator_set();
    let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone());

    // Validator 1 signs a timeout claiming `None` evidence.
    let sig = sign_timeout_claim(&keys[1], engine.current_view(), engine.epoch(), None);
    // A relay attaches a real-looking QC claim — the signature no
    // longer covers it.
    let sub_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x55; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0111],
        aggregate_signature: AggregateSignature::ZERO,
    };
    let err = engine
        .collect_timeout_signature(1, sig, Some(sub_qc))
        .expect_err("evidence substitution must break the signature");
    assert_eq!(err, ConsensusError::InvalidVoteSignature { voter: 1 });
}

// ---- Epoch rotation tests (stage 6) ----
//
// These tests exercise the two-phase epoch handoff: schedule a
// new validator set, then complete the rotation.

fn second_validator_set() -> ValidatorSet {
    ValidatorSet::new(vec![pk(5), pk(6)], vec![1, 1]).expect("2 validators")
}

/// A different single-validator set — used by the rotation
/// continuation test. A lone engine inside a multi-validator set
/// legitimately cannot reach quorum (`n − f` signers), so driving
/// post-rotation consensus requires a set it can quorum in alone.
fn replacement_single_validator_set() -> ValidatorSet {
    ValidatorSet::new(vec![pk(9)], vec![1]).expect("1 validator")
}

#[test]
fn schedule_rotation_sets_pending() {
    let mut engine = make_engine();
    assert!(!engine.rotation_pending());
    engine.schedule_rotation(second_validator_set()).expect("schedule");
    assert!(engine.rotation_pending());
}

#[test]
fn schedule_rotation_rejects_double_schedule() {
    let mut engine = make_engine();
    engine.schedule_rotation(second_validator_set()).expect("first");
    let err = engine.schedule_rotation(second_validator_set());
    assert!(err.is_err(), "double schedule must fail");
}

#[test]
fn rotate_epoch_completes_rotation() {
    let mut engine = make_engine();
    engine.schedule_rotation(second_validator_set()).expect("schedule");
    assert!(engine.rotation_pending());
    engine.rotate_epoch().expect("rotate");
    assert!(!engine.rotation_pending());
    assert_eq!(engine.epoch(), Epoch::new(1));
    assert_eq!(engine.current_view(), View::new(0));
}

#[test]
fn rotate_epoch_without_pending_fails() {
    let mut engine = make_engine();
    let err = engine.rotate_epoch();
    assert!(err.is_err(), "rotation without pending must fail");
}

#[test]
fn rotate_epoch_resets_view_and_votes() {
    let mut engine = make_engine();
    // Advance the view and collect some state.
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    let view_before = engine.current_view();
    assert!(view_before.value() > 0, "view should have advanced");

    // Schedule and complete rotation.
    engine.schedule_rotation(second_validator_set()).expect("schedule");
    engine.rotate_epoch().expect("rotate");

    // View resets to 0, last_voted_view resets to None.
    assert_eq!(engine.current_view(), View::new(0));
    assert_eq!(engine.last_voted_view, None);
}

#[test]
fn rotate_epoch_changes_validator_set() {
    let mut engine = make_engine();
    let original_n = engine.validator_set.n();
    engine.schedule_rotation(second_validator_set()).expect("schedule");
    engine.rotate_epoch().expect("rotate");
    // The new set has 2 validators, the old had 1.
    assert_ne!(engine.validator_set.n(), original_n);
    assert_eq!(engine.validator_set.n(), 2);
}

#[test]
fn pacemaker_timeouts_reach_the_running_engine() {
    // `with_pacemaker_timeouts` must override the compiled
    // defaults — the parsed `consensus.base_timeout_ms` /
    // `max_timeout_ms` values flow through this knob.
    let engine = make_engine().with_pacemaker_timeouts(5_000, 60_000);
    assert_eq!(
        engine.pacemaker_timeout_ms(),
        5_000,
        "the current view timeout must equal the configured base"
    );
}

#[test]
fn pacemaker_timeouts_survive_epoch_rotation() {
    // Rotation rebuilds the pacemaker — a rebuild from
    // `Pacemaker::new` would silently revert configured timeouts
    // to defaults. The engine must carry them across the rebuild.
    let mut engine = make_engine().with_pacemaker_timeouts(5_000, 60_000);
    engine.schedule_rotation(second_validator_set()).expect("schedule");
    engine.rotate_epoch().expect("rotate");
    assert_eq!(
        engine.pacemaker_timeout_ms(),
        5_000,
        "configured timeouts must survive the rotation rebuild, \
         not revert to the 2000ms default"
    );
}

#[test]
fn block_budget_is_configurable() {
    let budget = types::BlockBudget { max_bytes: 1 << 20, max_gas: 1_000_000_000 };
    let engine = make_engine().with_block_budget(budget);
    assert_eq!(engine.block_budget(), budget);
    // Default remains the chain-configured budget.
    assert_eq!(make_engine().block_budget(), types::CHAIN_BLOCK_BUDGET);
}

/// The body commitment must follow the LIVE committee's
/// erasure layout: after a rotation that changes the stake
/// distribution, the next proposal's `body_commitment`
/// recomputes with the new set's `k` — not the construction
/// set's. A stale `k` would make honest replicas (deriving the
/// same new `k`) fail to reproduce the signed root.
#[test]
fn body_commitment_uses_rotated_committee_layout() {
    let mut engine = make_engine();
    // Single-validator committee: no Byzantine possible —
    // k = 1, one plain chunk.
    assert_eq!(engine.erasure_k(), 1);
    // Rotate into a 4-validator committee with skewed stakes:
    // the Byzantine budget admits the two small validators,
    // so k = 2 — different layout, different root.
    let rotated =
        ValidatorSet::new(vec![pk(5), pk(6), pk(7), pk(8)], vec![3, 3, 1, 1]).expect("rotated set");
    engine.schedule_rotation(rotated.clone()).expect("schedule");
    engine.rotate_epoch().expect("rotate");
    assert_eq!(engine.erasure_k(), 2);
    engine.submit_tx(TxBytes::new(vec![1, 2, 3]));
    let (header, proposal) = engine.propose().expect("propose after rotation");
    let mut buf = Vec::new();
    proposal.encode(&mut buf);
    assert_eq!(
        header.body_commitment,
        types::shard::commitment(&buf, rotated.n(), engine.erasure_k()),
        "the signed root must follow the rotated committee's layout"
    );
    assert_ne!(
        header.body_commitment,
        types::shard::commitment(&buf, rotated.n(), rotated.n()),
        "and must differ from the plain n-of-n layout a stale derivation would produce"
    );
}

/// The proposal clock lands in the signed header: a leader
/// stamps `with_clock`'s value — the value the whole cluster
/// will execute under — not a height-derived stand-in.
#[test]
fn propose_stamps_injected_clock() {
    let mut leader = make_multi_engine(0).with_clock(|| 1_700_000_000_123);
    let (header, _proposal) = leader.propose().expect("leader proposes");
    assert_eq!(header.timestamp, 1_700_000_000_123);
}

/// The committed block carries the consensus execution context
/// on every replica: the header's signed timestamp, the
/// proposer's staking address resolved from `header.proposer`
/// against the validator set, and the block budget's gas limit.
/// Because all three derive from committed material, leader and
/// followers observe identical contexts.
#[test]
fn committed_block_carries_execution_context() {
    const TS: u64 = 1_700_000_000_123;
    let mut leader = make_multi_engine(0).with_clock(|| TS);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];
    drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![1])));
    // The QC for h1 is what commits h0 (2-chain rule).
    drive_round(&mut leader, &mut followers, None);

    let expected_beneficiary = four_validator_set().validator_addresses()[0];
    for (name, e) in [("leader", &leader), ("f1", &f1), ("f2", &f2), ("f3", &f3)] {
        let block = e
            .finalized_block(Height::new(0))
            .unwrap_or_else(|| panic!("{name}: h0 must be committed"));
        assert_eq!(block.context.timestamp_ms, TS, "{name}: committed timestamp");
        assert_eq!(
            block.context.beneficiary, expected_beneficiary,
            "{name}: beneficiary is the proposer's staking address"
        );
        assert_eq!(
            block.context.gas_limit,
            types::CHAIN_BLOCK_BUDGET.max_gas,
            "{name}: gas limit is the enforced block budget"
        );
    }
}

/// `vote()` rejects a proposal whose committed timestamp goes
/// backwards relative to its parent — the one objective clock
/// rule consensus enforces. An equal timestamp (same millisecond
/// tick) remains legal.
#[test]
fn vote_rejects_backwards_timestamp() {
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
    let mut leader = make_multi_engine(0).with_clock({
        let c = Arc::clone(&clock);
        move || c.load(std::sync::atomic::Ordering::Relaxed)
    });
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];
    // Round 1: h0 is proposed (ts=1000), voted, and QC'd — the
    // followers store its header in `blocks`, which is what
    // `parent_timestamp` consults for the round-2 child.
    drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![1])));

    // Round 2 with a backwards clock: the child of the
    // ts=1000 parent stamps 500 — an objective violation.
    clock.store(500, std::sync::atomic::Ordering::Relaxed);
    let (header, proposal) = leader.propose().expect("round-2 proposal");
    assert_eq!(header.timestamp, 500);
    assert!(
        f1.vote(&header, &proposal).is_none(),
        "a timestamp earlier than the parent's must be rejected"
    );

    // An equal stamp (same millisecond as the parent) is legal.
    clock.store(1_000, std::sync::atomic::Ordering::Relaxed);
    let (header2, proposal2) = leader.propose().expect("re-proposal");
    assert_eq!(header2.timestamp, 1_000);
    assert!(
        f2.vote(&header2, &proposal2).is_some(),
        "a timestamp equal to the parent's must be accepted"
    );
}

#[test]
fn engine_continues_after_rotation() {
    let mut engine = make_engine();
    // Commit a block in epoch 0.
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();

    // Rotate to a new epoch — a single-validator set, because a
    // lone engine inside a multi-validator set cannot reach the
    // `n − f` quorum alone (a self-signed single-signer "QC" is
    // not a certificate). Under the previous `2f + 1` formula a
    // 2-validator set had quorum 1 and this engine could commit
    // unilaterally — exactly the unsafe threshold this fix removes.
    engine.schedule_rotation(replacement_single_validator_set()).expect("schedule");
    engine.rotate_epoch().expect("rotate");
    assert_eq!(engine.epoch(), Epoch::new(1));

    // The engine should still be able to propose and commit in
    // the new epoch. Note: the validator_index (0) is still valid
    // in the new 2-validator set.
    engine.submit_tx(TxBytes::new(vec![2]));
    engine.run_until_idle();

    // The new tx should be committed.
    let h = engine.finalized_height().expect("finalized").value();
    let mut found = false;
    for i in 0..=h {
        if let Some(block) = engine.finalized_block(Height::new(i))
            && block.txs.iter().any(|t| t.as_bytes() == [2])
        {
            found = true;
            break;
        }
    }
    assert!(found, "tx submitted after rotation must be committed");
}

#[test]
fn epoch_in_blocks_increments_after_rotation() {
    let mut engine = make_engine();
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();

    // Before rotation, blocks are in epoch 0.
    assert_eq!(engine.epoch(), Epoch::new(0));

    // Rotate.
    engine.schedule_rotation(second_validator_set()).expect("schedule");
    engine.rotate_epoch().expect("rotate");

    // After rotation, new blocks are in epoch 1.
    engine.submit_tx(TxBytes::new(vec![2]));
    engine.run_until_idle();
    assert_eq!(engine.epoch(), Epoch::new(1));
}

// ---- Tail-fork resistance tests ----
//
// docs/oxidebft-spec.md §4: validators reject proposals that don't
// extend the highest QC they voted for. This prevents a faulty
// leader from discarding a notarized block (MEV-by-discard).

#[test]
fn tail_fork_rejects_proposal_without_high_qc() {
    // After the engine has a high_qc, a proposal with no high_qc
    // (a fork) must be rejected.
    let mut engine = make_engine();
    // Drive one round to establish a high_qc.
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    assert!(engine.high_qc.is_some(), "high_qc should be set");

    // Craft a proposal with no high_qc (a fork).
    let proposal =
        Proposal { height: Height::new(99), txs: vec![TxBytes::new(vec![2])], attestation: None };
    let header = BlockHeader {
        height: Height::new(99),
        view: View::new(99),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: OxideBft::tx_root(&proposal.txs),
        high_qc: None, // fork: no high_qc
        timeout_cert: None,
        proposer: Hash::ZERO,
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let vote = engine.vote(&header, &proposal);
    assert!(vote.is_none(), "fork proposal without high_qc must be rejected");
}

#[test]
fn tail_fork_rejects_proposal_with_wrong_high_qc() {
    // After the engine has a high_qc, a proposal with a different
    // high_qc (extending a different chain) must be rejected.
    let mut engine = make_engine();
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    let our_high_qc = engine.high_qc.clone().map(|v| v.qc().clone()).expect("high_qc set");

    // Craft a fake QC over a different block.
    let fake_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash::ZERO, // different block
        epoch: Epoch::new(0),
        signer_bitmap: vec![0x01],
        aggregate_signature: AggregateSignature::ZERO,
    };

    let proposal =
        Proposal { height: Height::new(99), txs: vec![TxBytes::new(vec![2])], attestation: None };
    let header = BlockHeader {
        height: Height::new(99),
        view: View::new(99),
        epoch: Epoch::new(0),
        prev_block: fake_qc.block_hash,
        tx_root: OxideBft::tx_root(&proposal.txs),
        high_qc: Some(fake_qc),
        timeout_cert: None,
        proposer: Hash::ZERO,
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let vote = engine.vote(&header, &proposal);
    assert!(
        vote.is_none(),
        "fork proposal with wrong high_qc must be rejected (our high_qc block: {:?})",
        our_high_qc.block_hash
    );
}

#[test]
fn tail_fork_accepts_proposal_extending_high_qc() {
    // After the engine has a high_qc, a proposal that extends it
    // (same high_qc) must be accepted.
    let mut engine = make_engine();
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    let our_high_qc = engine.high_qc.clone().map(|v| v.qc().clone()).expect("high_qc set");

    // The stamped height must be the parent's height + 1 —
    // vote() now enforces height continuity, so derive it from
    // the stored parent header.
    let stamped_height = engine
        .blocks
        .get(&our_high_qc.block_hash)
        .map(|(h, _)| h.height.saturating_next())
        .expect("high_qc block must be in the block map");

    let proposal =
        Proposal { height: stamped_height, txs: vec![TxBytes::new(vec![2])], attestation: None };
    // HIGH fix: vote() now requires header.view == current_view.
    // Set current_view to match the test proposal's view.
    engine.current_view = View::new(99);
    let header = BlockHeader {
        height: stamped_height,
        view: View::new(99),
        epoch: Epoch::new(0),
        prev_block: our_high_qc.block_hash,
        tx_root: OxideBft::tx_root(&proposal.txs),
        high_qc: Some(our_high_qc),
        timeout_cert: None,
        proposer: Hash::ZERO,
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let vote = engine.vote(&header, &proposal);
    assert!(vote.is_some(), "proposal extending high_qc must be accepted");
}

#[test]
fn tail_fork_accepts_proposal_with_newer_high_qc() {
    // Regression test for tail-fork *resistance* (extends-highest-QC
    // rule, docs/oxidebft-spec.md §4). After the engine has a
    // high_qc, a proposal carrying a *newer* QC (higher view, e.g.
    // from a view-change leader that saw a QC we missed) must be
    // accepted — not rejected for failing strict equality with our
    // high_qc. The old strict-`block_hash`-equality check rejected
    // these valid proposals from a newer fork; the view-ordering
    // check (`prop_qc.view >= our_high_qc.view`) accepts them.
    let mut engine = make_engine();
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    let our_high_qc = engine.high_qc.clone().map(|v| v.qc().clone()).expect("high_qc set");

    // Craft a QC one view newer than ours, over a different block
    // (simulating a view-change leader that built on a fresher QC).
    let newer_qc = QuorumCertificate {
        view: View::new(our_high_qc.view.value() + 1),
        phase: VotePhase::Prepare,
        block_hash: Hash([0xab; 32]), // different block — strict equality would reject
        epoch: Epoch::new(0),
        signer_bitmap: vec![0x01],
        aggregate_signature: AggregateSignature::ZERO,
    };

    // HIGH fix: vote() now requires header.view == current_view
    // and prev_block == high_qc.block_hash. Set current_view to
    // match, and update high_qc so prev_block matches. The voter
    // must also have the parent block stored — height continuity
    // (`header.height == parent.height + 1`) is verified against
    // the stored header — so insert the block the newer QC
    // points at, stamped at the chain tip's height.
    let parent_height = engine.next_height;
    let parent_proposal =
        Proposal { height: parent_height, txs: vec![TxBytes::new(vec![9])], attestation: None };
    let parent_header = BlockHeader {
        height: parent_height,
        view: View::new(our_high_qc.view.value() + 1),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: OxideBft::tx_root(&parent_proposal.txs),
        high_qc: None,
        timeout_cert: None,
        proposer: Hash::ZERO,
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    engine
        .blocks
        .insert(newer_qc.block_hash, (parent_header, BlockBody::Complete(parent_proposal)));

    let stamped_height = parent_height.saturating_next();
    let proposal_view = View::new(our_high_qc.view.value() + 2);
    engine.current_view = proposal_view;
    engine.high_qc = Some(VerifiedQc::from_trusted(newer_qc.clone()));
    let proposal =
        Proposal { height: stamped_height, txs: vec![TxBytes::new(vec![2])], attestation: None };
    let header = BlockHeader {
        height: stamped_height,
        view: proposal_view,
        epoch: Epoch::new(0),
        prev_block: newer_qc.block_hash,
        tx_root: OxideBft::tx_root(&proposal.txs),
        high_qc: Some(newer_qc),
        timeout_cert: None,
        proposer: Hash::ZERO,
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let vote = engine.vote(&header, &proposal);
    assert!(
        vote.is_some(),
        "proposal with a newer high_qc (view > ours) must be accepted (extends-highest-QC rule)"
    );
}

#[test]
fn tail_fork_rejects_proposal_with_older_high_qc() {
    // Complement to the above: a proposal carrying an *older* QC
    // (lower view than our high_qc) is a stale fork and must still
    // be rejected. This guards against regressing the safety side
    // of the extends-highest-QC rule.
    let mut engine = make_engine();
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    let our_high_qc = engine.high_qc.clone().map(|v| v.qc().clone()).expect("high_qc set");
    // Only meaningful once we've advanced past view 0.
    assert!(our_high_qc.view.value() > 0, "high_qc should be past view 0 after a round");

    let older_qc = QuorumCertificate {
        view: View::new(our_high_qc.view.value() - 1),
        phase: VotePhase::Prepare,
        block_hash: Hash([0xcd; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0x01],
        aggregate_signature: AggregateSignature::ZERO,
    };

    let proposal =
        Proposal { height: Height::new(99), txs: vec![TxBytes::new(vec![2])], attestation: None };
    let header = BlockHeader {
        height: Height::new(99),
        view: View::new(99),
        epoch: Epoch::new(0),
        prev_block: older_qc.block_hash,
        tx_root: OxideBft::tx_root(&proposal.txs),
        high_qc: Some(older_qc),
        timeout_cert: None,
        proposer: Hash::ZERO,
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let vote = engine.vote(&header, &proposal);
    assert!(
        vote.is_none(),
        "proposal with an older high_qc (view < ours) must be rejected (stale fork)"
    );
}

#[test]
fn tail_fork_accepts_genesis_proposal() {
    // At genesis (no high_qc), any proposal is accepted.
    let mut engine = make_engine();
    let proposal =
        Proposal { height: Height::new(0), txs: vec![TxBytes::new(vec![1])], attestation: None };
    let header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: OxideBft::tx_root(&proposal.txs),
        high_qc: None,
        timeout_cert: None,
        proposer: Hash::ZERO,
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: Hash::ZERO,
    };
    let vote = engine.vote(&header, &proposal);
    assert!(vote.is_some(), "genesis proposal must be accepted");
}

#[test]
fn divergence_detection_rejects_mismatched_exec_cert() {
    // When a proposal carries an exec_cert whose state_root
    // differs from the locally computed state root, the engine
    // must refuse to vote (divergence detected).
    //
    // We use an engine with signature verification enabled (the
    // divergence check is gated on verify_signatures). C3 fix:
    // the validator set must use the real public key derived
    // from the BLS secret key so proposer-signature verification
    // passes (the fake `pk(1)` key doesn't match `bls_key(1)`).
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    // The MockApp's attest_state for height 0 returns
    // Hash([0x00; 32]) (height 0 → byte 0). We craft an
    // exec_cert with a *different* state_root to trigger
    // divergence.
    let mock_root = Hash([0x00; 32]);
    let divergent_root = Hash([0xDE; 32]); // != mock_root

    // A real, correctly-signed cert over the *wrong* root —
    // the reject must come from the root comparison, not from
    // signature verification (a fabricated cert would fail
    // verify_exec_cert earlier and for a different reason).
    let att_msg = engine.attestation_signing_message(Height::new(0), &divergent_root);
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let exec_cert = ExecCertificate {
        height: Height::new(0),
        state_root: divergent_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
    };

    // `genesis_proposal_with_cert` signs the header AND carries the
    // real body commitment — `vote` binds body↔commitment before the
    // cert check, so a zero commitment would withhold the vote for
    // the wrong reason and never reach the divergence comparison.
    let (header, proposal) = genesis_proposal_with_cert(&sk, exec_cert);
    let vote = engine.vote(&header, &proposal);
    assert!(
        vote.is_none(),
        "proposal with divergent exec_cert must be rejected (state divergence)"
    );
    // The verified mismatch must latch: signing halts and the
    // divergence detail is exposed for health/metrics plumbing.
    let d = engine.divergence().expect("verified root mismatch must latch divergence");
    assert_eq!(d.height, Height::new(0));
    assert_eq!(d.local_root, mock_root);
    assert_eq!(d.certified_root, divergent_root);
    assert!(!engine.signing_healthy(), "diverged engine must report signing-unhealthy");

    // Sanity: the divergent root is indeed different from the
    // mock root.
    assert_ne!(divergent_root, mock_root, "test setup: roots must differ");
}

#[test]
fn divergence_latch_halts_every_signing_path() {
    // Withholding the divergent vote alone is not enough: a
    // validator whose executed state is proven wrong must go
    // fully silent — timeouts, attestations, and proposals all
    // extend a chain this node does not share.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    let divergent_root = Hash([0xDE; 32]);
    let att_msg = engine.attestation_signing_message(Height::new(0), &divergent_root);
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let cert = ExecCertificate {
        height: Height::new(0),
        state_root: divergent_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
    };
    let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
    assert!(engine.vote(&header, &proposal).is_none(), "setup: divergent vote withheld");
    assert!(engine.divergence().is_some(), "setup: latch must be set");

    // Timeouts and attestations are signatures too — both refuse.
    assert!(engine.on_timeout().is_none(), "diverged engine must not sign timeouts");
    let (att, sig) = engine.vote_attestation();
    assert!(att.is_none() && sig.is_none(), "diverged engine must not attest");

    // Proposals carry a signature — refuse even with a committed
    // anchor that would otherwise make propose() produce a block
    // (mirrors `propose_never_embeds_stale_epoch_cert`'s setup).
    engine.last_committed = Some((Hash([9; 32]), Height::new(1)));
    assert!(engine.propose().is_none(), "diverged engine must not propose");

    // A second divergent delivery does not move the recorded
    // anchor: the earliest verified mismatch is the repair point.
    let second_root = Hash([0x77; 32]);
    let att_msg2 = engine.attestation_signing_message(Height::new(0), &second_root);
    let att_sig2 = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg2);
    let cert2 = ExecCertificate {
        height: Height::new(0),
        state_root: second_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig2]).expect("aggregate"),
    };
    let (header2, proposal2) = genesis_proposal_with_cert(&sk, cert2);
    assert!(engine.vote(&header2, &proposal2).is_none());
    assert_eq!(
        engine.divergence().expect("latch persists").certified_root,
        divergent_root,
        "the first verified mismatch is the recorded repair anchor"
    );
}

#[test]
fn divergence_latch_survives_restart_via_wal() {
    // The latch is safety state, not status detail: a validator
    // that crashes after diverging must not wake up signing over
    // the same diverged state — that would be the silent-fade
    // failure with extra steps. The latch therefore rides the WAL
    // like the vote locks do.
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");
    let divergent_root = Hash([0xDE; 32]);

    {
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone()).with_wal(wal);

        let att_msg = engine.attestation_signing_message(Height::new(0), &divergent_root);
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let cert = ExecCertificate {
            height: Height::new(0),
            state_root: divergent_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        };
        let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
        assert!(engine.vote(&header, &proposal).is_none());
        assert!(engine.divergence().is_some(), "setup: latch must be set");
        // Engine drops here — the crash.
    }

    {
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone()).with_wal(wal);
        engine.recover_from_wal().expect("recover from WAL");

        let d = engine.divergence().expect("the divergence latch must survive restart via the WAL");
        assert_eq!(d.certified_root, divergent_root);
        assert!(!engine.signing_healthy());
        assert!(
            engine.on_timeout().is_none(),
            "a restarted diverged engine must still refuse to sign"
        );
    }
}

#[test]
fn mark_repaired_requires_a_certified_anchor_at_or_above_divergence() {
    // The latch clears only when local state attests to a
    // quorum-certified root at a height >= the diverged height.
    // Matching an earlier root never proves the diverged height
    // was rebuilt — a repair that stops below the anchor is not
    // a repair.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app.clone(), vs).with_secret_key(sk.clone());

    // Latch the divergence at height 1 directly — the same state
    // the verified-mismatch path in `vote` produces, without
    // needing a two-block chain to reach it.
    engine.divergence = Some(ExecDivergence {
        height: Height::new(1),
        local_root: Hash([0x01; 32]),
        certified_root: Hash([0xDE; 32]),
    });

    // No certified anchor yet — repair is impossible.
    assert_eq!(engine.mark_repaired(), crate::RepairOutcome::NoAnchor);
    assert!(engine.divergence().is_some());

    // Execute through height 0 so `attest_latest` reports a tip —
    // the anchor filter (h >= diverged height) is what rejects the
    // below-anchor cert, not a missing attestation.
    app.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![],
        signers: vec![],
    });

    // A cert BELOW the diverged height cannot clear the latch even
    // though its root matches local state.
    let below_root = Hash([0x00; 32]); // mock root at height 0
    let att_msg0 = engine.attestation_signing_message(Height::new(0), &below_root);
    let att_sig0 = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg0);
    let below_cert = ExecCertificate {
        height: Height::new(0),
        state_root: below_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig0]).expect("aggregate"),
    };
    assert!(engine.admit_exec_cert(&below_cert), "valid cert must be admitted");
    assert_eq!(engine.mark_repaired(), crate::RepairOutcome::NoAnchor);
    assert!(
        engine.divergence().is_some(),
        "an anchor below the diverged height must not clear the latch"
    );
}

#[test]
fn mark_repaired_clears_when_local_root_matches_certified_anchor() {
    // The repair flow: node diverges, rebuilds state from a
    // certified snapshot, re-executes to a height a quorum cert
    // attests, and the engine observes the roots now agree.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app.clone(), vs).with_secret_key(sk.clone());

    // Diverge at height 0.
    let divergent_root = Hash([0xDE; 32]);
    let att_msg = engine.attestation_signing_message(Height::new(0), &divergent_root);
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let cert = ExecCertificate {
        height: Height::new(0),
        state_root: divergent_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
    };
    let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
    assert!(engine.vote(&header, &proposal).is_none(), "setup: divergent vote withheld");
    assert!(!engine.signing_healthy(), "setup: signing halted");

    // Simulate the repair: the rebuilt chain re-executes through
    // height 2, whose mock root Hash([2;32]) is what quorum
    // attested (the repair peer's cert).
    app.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![],
        signers: vec![],
    });
    app.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: vec![],
        signers: vec![],
    });
    app.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(2),
        txs: vec![],
        signers: vec![],
    });
    let repaired_root = Hash([2; 32]); // mock_state_root(2)
    let att_msg2 = engine.attestation_signing_message(Height::new(2), &repaired_root);
    let att_sig2 = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg2);
    let anchor_cert = ExecCertificate {
        height: Height::new(2),
        state_root: repaired_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig2]).expect("aggregate"),
    };
    // The fetched cert arrives through the same verification the
    // proposal path applies — admit_exec_cert is the serving-
    // endpoint intake.
    assert!(engine.admit_exec_cert(&anchor_cert), "verified anchor cert must be admitted");

    assert_eq!(
        engine.mark_repaired(),
        crate::RepairOutcome::Repaired(Height::new(2)),
        "a certified anchor above the diverged height with a matching local root must clear"
    );
    assert!(engine.divergence().is_none(), "latch cleared");
    assert!(engine.signing_healthy(), "signing resumes after repair");

    // Idempotent: a second call has nothing to repair.
    assert_eq!(engine.mark_repaired(), crate::RepairOutcome::NotLatched);
}

#[test]
fn admit_exec_cert_rejects_invalid_certificates() {
    // The repair intake must not poison `verified_exec_certs` with
    // a fabricated cert: same verification as the proposal path —
    // a bad aggregate signature is refused and not cached.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let sk2 = bls_key(2);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    // Signed by a key outside the committee: bitmap seat 0 resolves
    // to `sk`, so `sk2`'s signature can never verify.
    let msg = engine.attestation_signing_message(Height::new(0), &Hash([0x00; 32]));
    let bad_sig = sk2.sign(crypto::hash::Domain::ExecAttest, &msg);
    let forged = ExecCertificate {
        height: Height::new(0),
        state_root: Hash([0x00; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[bad_sig]).expect("aggregate"),
    };
    assert!(!engine.admit_exec_cert(&forged), "a forged cert must not be admitted");

    // Wrong epoch: the signed message binds epoch 99, the engine is
    // at epoch 0 — verification fails on the epoch mismatch.
    let msg99 = engine.attestation_signing_message(Height::new(0), &Hash([0x00; 32]));
    let sig99 = sk.sign(crypto::hash::Domain::ExecAttest, &msg99);
    let foreign = ExecCertificate {
        height: Height::new(0),
        state_root: Hash([0x00; 32]),
        epoch: Epoch::new(99),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[sig99]).expect("aggregate"),
    };
    assert!(!engine.admit_exec_cert(&foreign), "a foreign-epoch cert must not be admitted");
}

#[test]
fn mark_repaired_persists_clear_through_wal() {
    // The cleared latch must be durable like the latch itself: a
    // crash after repair must not wake up halted on state the
    // operator already rebuilt.
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");
    let divergent_root = Hash([0xDE; 32]);
    let repaired_root = Hash([1; 32]); // mock_state_root(1)

    {
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app.clone(), vs).with_secret_key(sk.clone()).with_wal(wal);

        let att_msg = engine.attestation_signing_message(Height::new(0), &divergent_root);
        let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let cert = ExecCertificate {
            height: Height::new(0),
            state_root: divergent_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        };
        let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
        assert!(engine.vote(&header, &proposal).is_none());
        assert!(engine.divergence().is_some(), "setup: latch set");

        // Repair: execute to height 1 and admit the anchor cert.
        app.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![],
            signers: vec![],
        });
        app.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(1),
            txs: vec![],
            signers: vec![],
        });
        let att_msg1 = engine.attestation_signing_message(Height::new(1), &repaired_root);
        let att_sig1 = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg1);
        let anchor = ExecCertificate {
            height: Height::new(1),
            state_root: repaired_root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig1]).expect("aggregate"),
        };
        assert!(engine.admit_exec_cert(&anchor));
        assert_eq!(engine.mark_repaired(), crate::RepairOutcome::Repaired(Height::new(1)));
        // Engine drops — the crash.
    }

    {
        let app = Arc::new(MockApp::new());
        let sk = bls_key(1);
        let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone()).with_wal(wal);
        engine.recover_from_wal().expect("recover from WAL");
        assert!(
            engine.divergence().is_none(),
            "the cleared latch must survive restart — the WAL entry after repair carries divergence=None"
        );
    }
}

#[test]
fn divergence_detection_accepts_matching_exec_cert() {
    // When a proposal carries an exec_cert whose state_root
    // *matches* the locally computed state root, the engine
    // proceeds normally (no divergence).
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    // MockApp returns Hash([0x00; 32]) for height 0.
    let matching_root = Hash([0x00; 32]);

    let att_msg = engine.attestation_signing_message(Height::new(0), &matching_root);
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let exec_cert = ExecCertificate {
        height: Height::new(0),
        state_root: matching_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
    };

    let proposal =
        Proposal { height: Height::new(0), txs: vec![TxBytes::new(vec![1])], attestation: None };
    // C3: sign the header so the proposer-auth check passes.
    // The signed header must also carry the real body
    // commitment — `vote` verifies the binding in production
    // mode (this engine verifies signatures).
    let mut body = Vec::new();
    proposal.encode(&mut body);
    let mut header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: OxideBft::tx_root(&proposal.txs),
        body_commitment: types::shard::commitment(&body, 1, 1),
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: Some(exec_cert),
    };
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
    let vote = engine.vote(&header, &proposal);
    assert!(vote.is_some(), "proposal with matching exec_cert must be accepted");
    assert!(
        engine.divergence().is_none() && engine.signing_healthy(),
        "a matching cert must not trip the divergence latch"
    );
}

// ---- Exec-cert validation hardening ----
//
// Audit: a matching `state_root` used to skip *all* certificate
// validation — signature, signer bitmap, quorum, and epoch — so a
// leader could embed a fabricated cert and have it committed as
// unproven "proof" of execution agreement. Attestations were also
// cached by `(height, root)` without the epoch they sign, and an
// unexecuted height reported `Hash::ZERO`, matching a forged cert
// that claimed a zero root. These tests pin the hardened
// behavior: full validation once per cert identity, epoch-bound
// certificates, and an explicit "not executed" signal.

/// Build a correctly-signed single-validator proposal at genesis
/// carrying `cert` as its `exec_cert`. Mirrors the header shape
/// `divergence_detection_accepts_matching_exec_cert` proves is
/// accepted when the cert is valid.
fn genesis_proposal_with_cert(
    sk: &crypto::BlsSecretKey,
    cert: ExecCertificate,
) -> (BlockHeader, Proposal) {
    let proposal =
        Proposal { height: Height::new(0), txs: vec![TxBytes::new(vec![1])], attestation: None };
    let mut body = Vec::new();
    proposal.encode(&mut body);
    let mut header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: OxideBft::tx_root(&proposal.txs),
        body_commitment: types::shard::commitment(&body, 1, 1),
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: Some(cert),
    };
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
    (header, proposal)
}

#[test]
fn forged_exec_cert_with_matching_root_rejected() {
    // The cert's root matches local execution, but its aggregate
    // signature is over a different message — a fabrication. The
    // old code voted anyway (root match bypassed verification);
    // a forged cert must withhold the vote regardless of the
    // root it carries.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    let matching_root = Hash([0x00; 32]); // mock_state_root(0)
    let wrong_msg = engine.attestation_signing_message(Height::new(0), &Hash([0xAA; 32]));
    let forged_sig = sk.sign(crypto::hash::Domain::ExecAttest, &wrong_msg);
    let cert = ExecCertificate {
        height: Height::new(0),
        state_root: matching_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[forged_sig]).expect("aggregate"),
    };
    let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
    let vote = engine.vote(&header, &proposal);
    assert!(
        vote.is_none(),
        "a forged exec_cert must withhold the vote even when its root matches local state"
    );
    // Rejection by authentication is not divergence: the latch must
    // NOT trip — a forged cert carries zero evidence about this
    // node's execution correctness.
    assert!(
        engine.divergence().is_none() && engine.signing_healthy(),
        "an unverifiable cert must not halt signing"
    );
}

#[test]
fn exec_cert_with_wrong_epoch_rejected() {
    // Attestations sign `(height, root, epoch)` and the bitmap
    // indexes the *current* validator set — a cert claiming any
    // other epoch is unverifiable even when its signature
    // happens to match this epoch's message.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    let matching_root = Hash([0x00; 32]);
    let att_msg = engine.attestation_signing_message(Height::new(0), &matching_root);
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let cert = ExecCertificate {
        height: Height::new(0),
        state_root: matching_root,
        // One epoch ahead of the engine — same signature bytes,
        // wrong claimed epoch.
        epoch: Epoch::new(1),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
    };
    assert!(
        engine.verify_exec_cert(&cert).is_err(),
        "a cert whose epoch differs from the engine's must fail verification"
    );
    let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
    assert!(
        engine.vote(&header, &proposal).is_none(),
        "a proposal embedding a stale-epoch cert must be refused"
    );
}

#[test]
fn propose_never_embeds_stale_epoch_cert() {
    // `propose()` selects the newest embeddable cert; a cert from
    // another epoch can never be verified by voters, so the
    // leader must not embed it — doing so would withhold every
    // honest vote and waste the view.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    // A cert for height 0 stamped with a foreign epoch, and a
    // committed anchor at height 1 so the leader proposes
    // height 2 (the embed bound is `cert.height <= h - 2`).
    let att_msg = engine.attestation_signing_message(Height::new(0), &Hash([0x00; 32]));
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    engine.exec_certs.insert(
        0,
        ExecCertificate {
            height: Height::new(0),
            state_root: Hash([0x00; 32]),
            epoch: Epoch::new(99),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
        },
    );
    engine.last_committed = Some((Hash([9; 32]), Height::new(1)));

    let (header, _proposal) = engine.propose().expect("genesis chain must propose");
    assert_eq!(header.height, Height::new(2));
    assert!(header.exec_cert.is_none(), "a stale-epoch cert must never be embedded in a proposal");
}

#[test]
fn attestation_cache_binds_epoch() {
    // The attestation signature cache must key on the epoch the
    // signature commits to. Reusing a signature minted in epoch N
    // under epoch N+1 attaches an attestation that fails every
    // verify — the cached sig must not survive an epoch change.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app.clone(), vs).with_secret_key(sk.clone());

    // Give the app an executed tip with a non-zero root (height 1;
    // height 0's mock root is Hash::ZERO, the never-attested
    // sentinel).
    app.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: vec![],
        signers: vec![],
    });
    app.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: vec![],
        signers: vec![],
    });

    let (att0, sig0) = engine.vote_attestation();
    assert!(att0.is_some() && sig0.is_some(), "executed tip must produce an attestation");
    // Same epoch: the deterministic BLS signature is cached —
    // byte-identical on repeat.
    let (_, sig0_again) = engine.vote_attestation();
    assert_eq!(sig0, sig0_again, "same-epoch attestation must reuse the cached signature");

    // Simulate the epoch boundary: the same `(height, root)` now
    // signs a different message, so the cached signature is
    // invalid and must be re-minted.
    engine.epoch = Epoch::new(1);
    let (att1, sig1) = engine.vote_attestation();
    assert_eq!(att0, att1, "the attested tip is unchanged across the boundary");
    assert_ne!(sig0, sig1, "an epoch change must invalidate the cached attestation signature");
}

/// An app whose execution lane never runs: `attest_state`
/// returns `None` for every height — the explicit "not
/// executed" signal a `Hash::ZERO` sentinel used to hide.
/// Exercises the vote path's cannot-confirm branch, which
/// `MockApp`'s fabricating `attest_state` cannot reach.
struct NeverExecutedApp;

impl AppInterface for NeverExecutedApp {
    fn ingest_tx(&self, _tx: TxBytes) -> MempoolAck {
        MempoolAck::Accepted
    }
    fn prepare_proposal(&self, _budget: &types::BlockBudget) -> Proposal {
        Proposal { height: Height::new(0), txs: Vec::new(), attestation: None }
    }
    fn has_queued_txs(&self) -> bool {
        false
    }
    fn process_proposal(&self, _proposal: &Proposal) -> Verdict {
        Verdict::Accept
    }
    fn finalize_block(&self, block: &FinalizedBlock) -> types::CommitAck {
        types::CommitAck { height: block.height }
    }
    fn attest_state(&self, _height: Height) -> Option<StateAttestation> {
        None
    }
    fn attest_latest(&self) -> Option<StateAttestation> {
        None
    }
}

#[test]
fn exec_cert_for_unexecuted_height_withheld() {
    // A *validly signed* cert claiming a state root for a height
    // the app never executed must still withhold the vote: there
    // is no local execution to confirm it against. Before
    // `attest_state` returned `Option`, the `Hash::ZERO` sentinel
    // made a cert claiming a zero root "match" an unexecuted
    // height and the vote went through.
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(Arc::new(NeverExecutedApp), vs).with_secret_key(sk.clone());

    // Claim a ZERO root at height 0 — the exact value the old
    // sentinel produced for unexecuted heights. The cert itself
    // verifies (real signature, in-bounds bitmap, right epoch);
    // only local confirmation is missing.
    let att_msg = engine.attestation_signing_message(Height::new(0), &Hash::ZERO);
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let cert = ExecCertificate {
        height: Height::new(0),
        state_root: Hash::ZERO,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
    };
    let (header, proposal) = genesis_proposal_with_cert(&sk, cert);
    assert!(
        engine.vote(&header, &proposal).is_none(),
        "a cert for a height with no local execution must withhold the vote"
    );
}

#[test]
fn verified_exec_cert_is_cached_per_identity() {
    // A cert that passes full validation is cached under its
    // complete identity; a *different* cert at the same height
    // must re-validate (and fail, here) rather than inheriting
    // the cached verdict.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    let matching_root = Hash([0x00; 32]);
    let att_msg = engine.attestation_signing_message(Height::new(0), &matching_root);
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let cert = ExecCertificate {
        height: Height::new(0),
        state_root: matching_root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
    };
    let (header, proposal) = genesis_proposal_with_cert(&sk, cert.clone());
    assert!(engine.vote(&header, &proposal).is_some(), "a valid cert must be accepted");
    assert_eq!(
        engine.verified_exec_certs.get(&0),
        Some(&cert),
        "the verified cert must be cached under its complete identity"
    );

    // A forged cert at the SAME height: the cached entry must
    // not launder it — it re-validates and fails.
    let wrong_msg = engine.attestation_signing_message(Height::new(0), &Hash([0xBB; 32]));
    let forged_sig = sk.sign(crypto::hash::Domain::ExecAttest, &wrong_msg);
    let forged = ExecCertificate {
        aggregate_signature: crypto::aggregate(&[forged_sig]).expect("aggregate"),
        ..cert
    };
    let (header, proposal) = genesis_proposal_with_cert(&sk, forged);
    assert!(
        engine.vote(&header, &proposal).is_none(),
        "a forged cert must re-validate even when a valid cert is cached at its height"
    );
}

#[test]
fn confirm_exec_cert_compares_local_root_and_latches_divergence() {
    // The consume-path check followers run instead of voting: a
    // verified cert whose attested root local state did not
    // compute is confirmed divergence and must latch — bare
    // `admit_exec_cert` (verify-only) would have let a diverged
    // replica mirror wrong state forever.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    let mk_cert = |height: u64, root: Hash| {
        let msg =
            crate::verify::attestation_signing_message(Epoch::new(0), Height::new(height), &root);
        let sig = sk.sign(crypto::hash::Domain::ExecAttest, &msg);
        ExecCertificate {
            height: Height::new(height),
            state_root: root,
            epoch: Epoch::new(0),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[sig]).expect("aggregate"),
        }
    };

    // MockApp attests `mock_state_root(5) == Hash([5;32])` — a cert
    // attesting exactly that root confirms cleanly and latches
    // nothing.
    let good = mk_cert(5, Hash([5u8; 32]));
    assert!(engine.confirm_exec_cert(&good), "matching local root must confirm");
    assert!(engine.divergence().is_none(), "no divergence on agreement");

    // A fully verified cert attesting a root local state did not
    // compute at height 6 (MockApp computes `Hash([6;32])`) is
    // confirmed divergence — the latch must record the anchor a
    // certified repair would trust.
    let bad = mk_cert(6, Hash([0xee; 32]));
    assert!(!engine.confirm_exec_cert(&bad), "a mismatched verified root must not confirm");
    let d = *engine.divergence().expect("divergence must latch on confirmed mismatch");
    assert_eq!(d.height, Height::new(6));
    assert_eq!(d.certified_root, Hash([0xee; 32]));
    assert_eq!(d.local_root, Hash([6u8; 32]), "the latch records what WE computed");

    // First write wins: a second divergent cert must not overwrite
    // the earliest repair anchor.
    let later = mk_cert(7, Hash([0xcc; 32]));
    assert!(!engine.confirm_exec_cert(&later));
    assert_eq!(
        engine.divergence().expect("still latched").height,
        Height::new(6),
        "the earliest divergence is the repair anchor"
    );
}

#[test]
fn confirm_exec_cert_rejects_unverifiable_certs_without_latching() {
    // A forged cert (signature over a different message) fails
    // verification — `false`, but NOT a latched divergence: an
    // unproven claim is not evidence of execution disagreement.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    let msg = engine.attestation_signing_message(Height::new(3), &Hash([3u8; 32]));
    let sig = sk.sign(crypto::hash::Domain::ExecAttest, &msg);
    let forged = ExecCertificate {
        height: Height::new(3),
        // Attests a root the signature does not cover.
        state_root: Hash([0xaa; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[sig]).expect("aggregate"),
    };
    assert!(!engine.confirm_exec_cert(&forged), "an unverifiable cert must not confirm");
    assert!(engine.divergence().is_none(), "a forged cert is not divergence evidence");
}

#[test]
fn rotation_clears_exec_cert_state() {
    // Certs, pooled attestations, and cached verifications are
    // bound to the signing epoch's validator set — none may
    // outlive the epoch they were formed in.
    let app = Arc::new(MockApp::new());
    let sk = bls_key(1);
    let vs = ValidatorSet::new(vec![sk.public_key()], vec![1]).expect("1 validator");
    let mut engine = OxideBft::new(app, vs).with_secret_key(sk.clone());

    let att_msg = engine.attestation_signing_message(Height::new(0), &Hash([7; 32]));
    let att_sig = sk.sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let cert = ExecCertificate {
        height: Height::new(0),
        state_root: Hash([7; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[att_sig]).expect("aggregate"),
    };
    engine
        .exec_attest_pool
        .entry(0)
        .or_default()
        .entry(Hash([7; 32]))
        .or_default()
        .push((0u16, Signature::ZERO));
    engine.exec_certs.insert(0, cert.clone());
    engine.verified_exec_certs.insert(0, cert);

    engine.schedule_rotation(second_validator_set()).expect("schedule");
    engine.rotate_epoch().expect("rotate");
    assert!(engine.exec_attest_pool.is_empty(), "stale attestations must not survive rotation");
    assert!(engine.exec_certs.is_empty(), "stale certs must not survive rotation");
    assert!(
        engine.verified_exec_certs.is_empty(),
        "cached verifications must not survive rotation"
    );
}

// ---- Execution attestation / exec-cert aggregation tests ----
//
// Votes carry `StateAttestation`s (BLS-signed under
// `Domain::ExecAttest`); leaders aggregate quorum-identical
// attestations into `ExecCertificate`s embedded in later
// proposals — the chain's divergence-detection substrate.

/// Build a signed-mode 4-validator committee: engines with real
/// keys and signature verification on (production path).
fn signed_committee() -> (Vec<OxideBft>, Vec<crypto::BlsSecretKey>) {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
    let engines = (0..4u16)
        .map(|i| {
            OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), i)
                .with_secret_key(keys[usize::from(i)].clone())
        })
        .collect();
    (engines, keys)
}

#[test]
fn vote_carries_execution_attestation() {
    // After the app has executed a block, the engine's vote must
    // carry an attestation for that height+root — the raw input
    // leaders aggregate into exec certs.
    let (mut engines, _keys) = signed_committee();
    let engine = &mut engines[1];
    // Height 1, not 0: the mock's height-derived root for height 0
    // is `Hash::ZERO` — the same value `attest_latest` uses as the
    // "nothing executed" sentinel — so an attestation for height 0
    // could never be observed. Height 1 attests cleanly.
    engine.app.finalize_block(&FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: vec![],
        signers: vec![],
    });

    // A genesis-style proposal (height 0, no highQC needed).
    let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
    let mut body = Vec::new();
    proposal.encode(&mut body);
    let mut header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: OxideBft::tx_root(&proposal.txs),
        body_commitment: types::shard::commitment(&body, 4, 3),
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
    };
    // Sign with the real leader key so proposer auth passes.
    let sk = bls_key(1);
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));

    let vote = engine.vote(&header, &proposal).expect("vote must be produced");
    let att = vote.attestation.expect("vote must carry an attestation");
    assert_eq!(att.height, Height::new(1), "attestation covers executed height");
    assert_eq!(
        att.root,
        engine.app.attest_state(Height::new(1)).expect("executed").root,
        "attestation root matches local execution"
    );
    // The attestation signature must verify under ExecAttest.
    let msg = engine.attestation_signing_message(att.height, &att.root);
    let pk = &bls_key(2).public_key();
    crypto::verify(
        &vote.attestation_sig.expect("attestation must be signed"),
        crypto::hash::Domain::ExecAttest,
        &msg,
        pk,
    )
    .expect("attestation signature must verify");
}

#[test]
fn exec_cert_forms_from_quorum_attestations() {
    // Three (of four) identical, correctly-signed attestations
    // for the same (height, root) must aggregate into an
    // ExecCertificate on the collecting leader.
    let (mut engines, keys) = signed_committee();
    let leader = &mut engines[0];
    let height = Height::new(7);
    let root = Hash([0x77; 32]);
    // The votes must name a block the leader actually stored —
    // the phantom-block guard drops first-votes for unknown
    // hashes — so the leader proposes for real.
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    for i in 1u16..=3 {
        let att = StateAttestation { height, root };
        let msg = leader.attestation_signing_message(height, &root);
        let att_sig = keys[usize::from(i)].sign(crypto::hash::Domain::ExecAttest, &msg);
        let vote_msg = leader.vote_signing_message(View::new(0), 0, &block_hash);
        let vote_sig = keys[usize::from(i)].sign(crypto::hash::Domain::Vote, &vote_msg);
        leader
            .collect_vote(
                i,
                Vote {
                    view: View::new(0),
                    phase: VotePhase::Prepare,
                    block_hash,
                    signature: vote_sig,
                    attestation: Some(att),
                    attestation_sig: Some(att_sig),
                },
            )
            .expect("vote accepted");
    }

    let cert = leader.exec_certs.get(&7).expect("exec cert must form at quorum");
    assert_eq!(cert.state_root, root);
    assert_eq!(cert.height, height);
    // The cert must verify: aggregate sig + bitmap ≥ quorum.
    leader.verify_exec_cert(cert).expect("formed cert must verify");
}

/// The state-sync trust anchor: a certificate served over the wire
/// must verify against the *client's* checkpointed validator set —
/// epoch equality, bitmap bounds, quorum power, and the aggregate
/// signature over `(height, root, epoch)` — so a peer cannot
/// fabricate the anchor, and a checkpoint naming the wrong epoch
/// or committee fails closed rather than indexing the wrong set.
#[test]
fn exec_certificate_verifies_against_client_checkpoint() {
    let (mut engines, keys) = signed_committee();
    let leader = &mut engines[0];
    let height = Height::new(7);
    let root = Hash([0x77; 32]);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);
    for i in 1u16..=3 {
        let att = StateAttestation { height, root };
        let msg = leader.attestation_signing_message(height, &root);
        let att_sig = keys[usize::from(i)].sign(crypto::hash::Domain::ExecAttest, &msg);
        let vote_msg = leader.vote_signing_message(View::new(0), 0, &block_hash);
        let vote_sig = keys[usize::from(i)].sign(crypto::hash::Domain::Vote, &vote_msg);
        leader
            .collect_vote(
                i,
                Vote {
                    view: View::new(0),
                    phase: VotePhase::Prepare,
                    block_hash,
                    signature: vote_sig,
                    attestation: Some(att),
                    attestation_sig: Some(att_sig),
                },
            )
            .expect("vote accepted");
    }
    let cert = leader
        .exec_certificates()
        .into_iter()
        .find(|c| c.height == height)
        .expect("served cert for the attested height");

    // Happy path: the checkpointed set is the committee that signed.
    let vset = leader.validator_set().clone();
    crate::verify_exec_cert(&vset, leader.epoch(), &cert).expect("valid cert verifies");

    // A checkpoint naming the wrong epoch: the signed message binds
    // the epoch, so the same committee at epoch+1 cannot validate
    // this cert — the mismatch fails before signature verification.
    assert!(matches!(
        crate::verify_exec_cert(&vset, Epoch::new(leader.epoch().value() + 1), &cert),
        Err(ConsensusError::CertEpochMismatch { .. })
    ));

    // A sub-quorum bitmap: one validator's stake cannot certify,
    // however valid its signature would be alone.
    let mut thin = cert.clone();
    thin.signer_bitmap = vec![0b0000_0010]; // validator index 1 only
    assert!(matches!(
        crate::verify_exec_cert(&vset, leader.epoch(), &thin),
        Err(ConsensusError::InsufficientQuorum { .. })
    ));

    // A bitmap naming validators past the end of the checkpointed
    // set — a malicious index can never resolve to real keys.
    let mut wide = cert.clone();
    wide.signer_bitmap = vec![0xFF];
    assert!(matches!(
        crate::verify_exec_cert(&vset, leader.epoch(), &wide),
        Err(ConsensusError::SignerOutOfBounds)
    ));

    // A tampered root: the aggregate was over the honest root, so
    // claiming a different one fails signature verification.
    let mut forged = cert.clone();
    forged.state_root = Hash([0x99; 32]);
    assert!(matches!(
        crate::verify_exec_cert(&vset, leader.epoch(), &forged),
        Err(ConsensusError::InvalidQcSignature)
    ));

    // A checkpoint built from *different* keys (the attacker's
    // committee): the real signers' aggregate does not verify under
    // foreign public keys.
    let foreign_keys: Vec<crypto::BlsSecretKey> = (0xA0..=0xA3u8).map(bls_key).collect();
    let foreign_vset = ValidatorSet::new(
        foreign_keys.iter().map(crypto::BlsSecretKey::public_key).collect(),
        vec![1u64; 4],
    )
    .expect("foreign set");
    assert!(matches!(
        crate::verify_exec_cert(&foreign_vset, leader.epoch(), &cert),
        Err(ConsensusError::InvalidQcSignature)
    ));
}

#[test]
fn forged_attestation_signature_is_dropped_not_fatal() {
    // An attestation signed by the wrong key must be ignored —
    // but the vote carrying it still counts for the QC (an
    // attestation is a best-effort signal, not a vote defect).
    let (mut engines, keys) = signed_committee();
    let leader = &mut engines[0];
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    // Attestation for (7, root) signed by validator 0's key but
    // claimed as validator 1's — fails verification.
    let root = Hash([0x77; 32]);
    let msg = leader.attestation_signing_message(Height::new(7), &root);
    let bad_sig = keys[0].sign(crypto::hash::Domain::ExecAttest, &msg);
    let vote_msg = leader.vote_signing_message(View::new(0), 0, &block_hash);
    let vote_sig = keys[1].sign(crypto::hash::Domain::Vote, &vote_msg);
    leader
        .collect_vote(
            1,
            Vote {
                view: View::new(0),
                phase: VotePhase::Prepare,
                block_hash,
                signature: vote_sig,
                attestation: Some(StateAttestation { height: Height::new(7), root }),
                attestation_sig: Some(bad_sig),
            },
        )
        .expect("vote itself must still be accepted");
    assert!(leader.exec_attest_pool.is_empty(), "forged attestation must be dropped");
    assert_eq!(leader.vote_count, 1, "the vote still counts toward the QC");
}

#[test]
fn forged_exec_cert_is_rejected_on_root_mismatch() {
    // A proposal carrying a cert whose aggregate signature does
    // not verify AND whose root the voter never computed must be
    // refused — the leader can withhold a vote this way but never
    // redirect it. (A forged cert claiming the root we DID compute
    // is harmless: the vote outcome is unchanged, so the signature
    // is not even checked — the aggregate verify only runs on the
    // mismatch path.)
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];

    // Cert over a root the engine never produced (local attest is
    // Hash::ZERO at every unexecuted height), with an aggregate
    // built from a Vote-domain signature — fails verify_exec_cert.
    let root = Hash([0xab; 32]);
    let msg = engine.attestation_signing_message(Height::new(0), &root);
    let wrong_domain_sig = keys[0].sign(crypto::hash::Domain::Vote, &msg);
    let exec_cert = ExecCertificate {
        height: Height::new(0),
        state_root: root,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[wrong_domain_sig]).expect("aggregate"),
    };

    let proposal = Proposal { height: Height::new(0), txs: vec![], attestation: None };
    let mut body = Vec::new();
    proposal.encode(&mut body);
    let mut header = BlockHeader {
        height: Height::new(0),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: Hash::ZERO,
        tx_root: OxideBft::tx_root(&proposal.txs),
        body_commitment: types::shard::commitment(&body, 4, 3),
        high_qc: None,
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: Some(exec_cert),
    };
    let sk = bls_key(1);
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
    assert!(
        engine.vote(&header, &proposal).is_none(),
        "proposal with a forged exec cert must be rejected"
    );
}

#[test]
fn propose_embeds_exec_cert_only_for_proven_heights() {
    // The embed rule: block h may carry a cert only for heights
    // <= h-2 — voters have only executed through h-2 at vote
    // time (2-chain lag), so a newer cert would freeze quorum.
    let (mut engines, _keys) = signed_committee();
    let leader = &mut engines[0];
    leader.submit_tx(TxBytes::new(vec![1]));

    // Seed a cert at height 3 and one at height 4 (not yet
    // provable when proposing height 5).
    for h in [3u64, 4] {
        leader.exec_certs.insert(
            h,
            ExecCertificate {
                height: Height::new(h),
                state_root: Hash([0x55; 32]),
                epoch: Epoch::new(0),
                signer_bitmap: vec![0xFF],
                aggregate_signature: AggregateSignature::ZERO,
            },
        );
    }
    // Committed tip = 4 → next proposal is height 5; embeddable
    // certs are those <= 3.
    leader.last_committed = Some((Hash([0x01; 32]), Height::new(4)));
    let (header, _proposal) = leader.propose().expect("must propose");
    assert_eq!(header.height, Height::new(5));
    let cert = header.exec_cert.expect("cert(3) must be embedded");
    assert_eq!(cert.height, Height::new(3), "the *newest embeddable* cert wins");
}

#[test]
fn exec_cert_flows_through_signed_pipeline() {
    // End-to-end: 4 signed engines drive rounds; attestations
    // ride every vote, certs form, and later proposals embed
    // them — with finality unaffected.
    let (mut engines, keys) = signed_committee();
    let mut saw_cert = false;
    for round in 0..8usize {
        let leader_idx = round % 4;
        // Keep the mempool non-empty: `propose()` returns None
        // when no work is outstanding (liveness gate), which
        // would stall the driver.
        engines[leader_idx].submit_tx(TxBytes::new(vec![u8::try_from(round).unwrap_or(u8::MAX)]));
        let mut followers: Vec<&mut OxideBft> = Vec::new();
        // Split borrow: leader at leader_idx, followers elsewhere.
        let (before, rest) = engines.split_at_mut(leader_idx);
        let (leader, after) = rest.split_at_mut(1);
        followers.extend(before.iter_mut());
        followers.extend(after.iter_mut());
        let (header, proposal) = leader[0].propose().expect("propose");
        if header.exec_cert.is_some() {
            saw_cert = true;
        }
        let block_hash = OxideBft::block_hash(&header);
        let leader_vi = leader[0].validator_index;
        let msg = leader[0].vote_signing_message(header.view, 0, &block_hash);
        let sig = keys[usize::from(leader_vi)].sign(crypto::hash::Domain::Vote, &msg);
        let (attestation, attestation_sig) = leader[0].vote_attestation();
        leader[0]
            .collect_vote(
                leader_vi,
                Vote {
                    view: header.view,
                    phase: VotePhase::Prepare,
                    block_hash,
                    signature: sig,
                    attestation,
                    attestation_sig,
                },
            )
            .expect("self vote");
        for f in &mut followers {
            if let Some(vote) = f.vote(&header, &proposal) {
                leader[0].collect_vote(f.validator_index, vote).expect("vote");
            }
        }
        let qc = leader[0].try_form_qc().expect("qc");
        leader[0].deliver_qc(qc.clone()).expect("deliver");
        for f in &mut followers {
            f.deliver_qc(qc.clone()).expect("deliver");
            f.advance_view();
        }
        leader[0].advance_view();
    }
    assert!(saw_cert, "exec certs must flow through proposals once quorum attests");
}

/// Regression test for the embedded-justify hole: a proposal's
/// `high_qc` used to be checked only for a *verifying* aggregate
/// signature — never for quorum. A QC with one real signer's vote
/// verifies as a valid aggregate yet certifies nothing: a
/// Byzantine leader could embed a self-signed "QC" and have
/// honest validators notarize a chain whose parent never reached
/// consensus. The signer count must be enforced unconditionally.
#[test]
fn subquorum_embedded_qc_is_rejected() {
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];

    // Anchor the chain at (H, 0): the vote path accepts a
    // proposal whose `prev_block`/`height` continue the committed
    // tip when no highQC is known locally.
    let parent_hash = Hash([0x42; 32]);
    engine.last_committed = Some((parent_hash, Height::new(0)));

    // A structurally valid QC for the parent — but with only
    // validator 0's signature (1 < quorum 3). The aggregate is a
    // real BLS signature and verifies fine: the signature is not
    // the problem, the missing quorum is.
    let vote_msg = engine.vote_signing_message(View::new(0), 0, &parent_hash);
    let one_sig = keys[0].sign(crypto::hash::Domain::Vote, &vote_msg);
    let thin_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: parent_hash,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: crypto::aggregate(&[one_sig]).expect("aggregate"),
    };
    // Sanity: the signature itself is sound — only the count fails.
    assert!(
        engine.verify_qc_signature(&thin_qc).is_err(),
        "sub-quorum QC must fail complete certificate validation"
    );

    let proposal = Proposal { height: Height::new(1), txs: vec![], attestation: None };
    let mut body = Vec::new();
    proposal.encode(&mut body);
    let mut header = BlockHeader {
        height: Height::new(1),
        view: View::new(0),
        epoch: Epoch::new(0),
        prev_block: parent_hash,
        tx_root: OxideBft::tx_root(&proposal.txs),
        body_commitment: types::shard::commitment(&body, 4, 3),
        high_qc: Some(thin_qc),
        timeout_cert: None,
        proposer: proposer_hash(0),
        timestamp: 0,
        proposer_signature: None,
        exec_cert: None,
    };
    let sk = bls_key(1);
    let signing_hash = OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(sk.sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));

    assert!(
        engine.vote(&header, &proposal).is_none(),
        "a proposal whose embedded QC lacks quorum must not be voted"
    );
}

// ---- View-change tests (multi-validator) ----
//
// docs/oxidebft-spec.md §4: a faulty leader is bypassed after one
// timeout. Validators collect timeout signatures, form a TC, and
// advance the view. The new leader takes over.

#[test]
fn faulty_leader_bypassed_via_timeout() {
    // 4 validators. The leader (index 0) for view 0 is faulty
    // (withholds proposals). The 3 followers time out, collect
    // timeout signatures, form a TC, and advance to view 1.
    // The leader for view 1 (index 1) is honest and proposes.
    let mut v0 = make_multi_engine(0);
    let mut v1 = make_multi_engine(1);
    let mut v2 = make_multi_engine(2);
    let mut v3 = make_multi_engine(3);

    // All followers time out for view 0 — each emits its real
    // timeout signature over (view, epoch, qc_high = None).
    let sig1 = v1.on_timeout().expect("v1 timeout sig");
    let sig2 = v2.on_timeout().expect("v2 timeout sig");
    let sig3 = v3.on_timeout().expect("v3 timeout sig");

    // The signatures are gossiped: v1 collects from itself, v2,
    // v3 — the engine path stores each signer's evidence record,
    // so the TC it emits carries real per-signer claims.
    let tc = [(1u16, sig1), (2, sig2), (3, sig3)]
        .iter()
        .find_map(|&(voter, sig)| v1.collect_timeout_signature(voter, sig, None).ok().flatten())
        .expect("v1 should form a TC at quorum");
    assert_eq!(tc.view, View::new(0), "TC is for view 0");
    assert_eq!(tc.signers.len(), 3, "TC carries each signer's record");

    // All other validators receive the TC and advance the view.
    let _ = v2.on_timeout_certificate(&tc);
    let _ = v3.on_timeout_certificate(&tc);
    let _ = v0.on_timeout_certificate(&tc);

    // All validators should now be at view 1.
    assert_eq!(v1.current_view(), View::new(1), "v1 should be at view 1");
    assert_eq!(v2.current_view(), View::new(1), "v2 should be at view 1");
    assert_eq!(v3.current_view(), View::new(1), "v3 should be at view 1");
    assert_eq!(v0.current_view(), View::new(1), "v0 should be at view 1");

    // The leader for view 1 is validator 1 (round-robin).
    assert!(v1.is_leader(), "v1 should be leader for view 1");
}

/// Regression test (liveness): when the view-0 leader is absent
/// *from boot* the fleet must not livelock. Headers always carried
/// `timeout_cert`, but the networked pump gated proposals on
/// `high_qc.is_some()` — which no proposal can ever produce, so
/// with the first leader dead every later leader stayed silent
/// forever and the chain never committed block 0.
/// `view_justified()` admits the TC path; this test proves a
/// TC-justified proposal is also *votable*: it extends the genesis
/// anchor and its embedded TC clears the evidence gate.
#[test]
fn tc_justified_proposal_breaks_boot_livelock() {
    let mut v1 = make_multi_engine(1);
    let mut v2 = make_multi_engine(2);
    let mut v3 = make_multi_engine(3);
    // Validator 0 (the view-0 leader) exists only as an address —
    // it never boots, never proposes, never signs a timeout.

    // View 0: the three live validators time out and form a TC —
    // quorum does not need the absent leader's signature.
    let sig1 = v1.on_timeout().expect("v1 timeout sig");
    let sig2 = v2.on_timeout().expect("v2 timeout sig");
    let sig3 = v3.on_timeout().expect("v3 timeout sig");
    let tc = [(1u16, sig1), (2, sig2), (3, sig3)]
        .iter()
        .find_map(|&(voter, sig)| v1.collect_timeout_signature(voter, sig, None).ok().flatten())
        .expect("3-of-4 forms a TC");
    let _ = v2.on_timeout_certificate(&tc);
    let _ = v3.on_timeout_certificate(&tc);

    // View 1, still no QC anywhere — but the TC justifies it.
    assert!(v1.is_leader(), "v1 leads view 1");
    assert!(v1.high_qc().is_none(), "no QC could have formed yet");
    assert!(v1.view_justified(), "TC(0) must justify proposing at view 1");

    // The proposal extends the genesis anchor and embeds the TC as
    // its succession proof.
    let (header, proposal) = v1.propose_heartbeat().expect("TC-justified proposal");
    assert_eq!(header.height, Height::new(0), "extends the committed anchor");
    assert_eq!(header.prev_block, Hash::ZERO);
    assert!(header.high_qc.is_none(), "no QC exists to embed");
    assert_eq!(
        header.timeout_cert.as_ref().map(|t| t.view),
        Some(View::new(0)),
        "the entry TC must be embedded for voters' evidence check"
    );

    // All three live validators vote — the proposal clears every
    // gate (anchor rule, evidence floor, view match).
    let leader_idx = v1.validator_index();
    let self_vote = v1.vote(&header, &proposal).expect("leader self-votes");
    v1.collect_vote(leader_idx, self_vote).expect("self vote");
    for (idx, follower) in [(2u16, &mut v2), (3, &mut v3)] {
        let vote = follower.vote(&header, &proposal).expect("followers vote");
        v1.collect_vote(idx, vote).expect("collect follower vote");
    }

    // The QC forms and the block commits — the livelock is broken.
    let qc = v1.try_form_qc().expect("quorum of three forms a QC");
    assert_eq!(qc.view, View::new(1));
}

// ---- Deterministic multi-node simulation ----
//
// A synchronous deterministic simulation of N validators running
// oxideBFT. This is layer 4 of the testing pyramid (testing-
// standards skill §4): deterministic simulation. The simulation
// drives multiple engines in a fixed round-robin order, routes
// messages deterministically, and asserts:
// - Liveness: all submitted txs appear in finalized blocks.
// - Finality: all validators agree on the same finalized blocks.
// - Determinism: two runs with the same inputs produce identical
//   finalized block sequences.

/// A deterministic multi-node simulation. Creates N validators,
/// drives `rounds` happy-path rounds with txs, and returns the
/// finalized blocks from each validator.
#[allow(clippy::too_many_lines)] // test helper: the .expect() calls for C1 verification added 4 lines
fn run_simulation(n: usize, txs_per_round: usize, rounds: usize) -> Vec<Vec<FinalizedBlock>> {
    let pks: Vec<crypto::bls::PublicKey> = (1..=u8::try_from(n).unwrap()).map(pk).collect();
    let stakes = vec![1u64; n];
    let vs = ValidatorSet::new(pks, stakes).expect("validator set");

    let mut engines: Vec<OxideBft> = (0..n)
        .map(|i| {
            OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), u16::try_from(i).unwrap())
                .without_signature_verification()
        })
        .collect();

    for round in 0..rounds {
        // The leader for this view is engines[0]'s leader.
        let leader_idx = usize::from(vs.leader(engines[0].current_view()));
        let tx = TxBytes::new(vec![
            u8::try_from(round).unwrap() + 1,
            u8::try_from(txs_per_round).unwrap(),
        ]);
        // Submit tx only to the leader's app. In a real system,
        // txs are gossiped, but each validator's mempool dedups
        // by tx hash. Here, each engine has its own MockApp, so
        // submitting to all would cause duplicate txs in blocks
        // (each leader would pull all pending txs from its
        // mempool). Submitting only to the leader matches the
        // real-world flow: the leader proposes, followers vote.
        engines[leader_idx].submit_tx(tx);

        // Leader proposes.
        let (header, proposal) = engines[leader_idx]
            .propose()
            .unwrap_or_else(|| panic!("leader {leader_idx} should propose in round {round}"));
        let block_hash = OxideBft::block_hash(&header);

        // Leader self-votes.
        let leader_vote = Vote {
            view: header.view,
            phase: VotePhase::Prepare,
            block_hash,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        engines[leader_idx]
            .collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote)
            .expect("conformance: no verification");

        // All followers vote (deterministic order: 0, 1, 2, ...).
        // Collect votes first to avoid double mutable borrow.
        let mut follower_votes = Vec::new();
        for (i, engine) in engines.iter_mut().enumerate() {
            if i == leader_idx {
                continue;
            }
            if let Some(vote) = engine.vote(&header, &proposal) {
                follower_votes.push((u16::try_from(i).unwrap(), vote));
            }
        }
        for (voter, vote) in follower_votes {
            engines[leader_idx].collect_vote(voter, vote).expect("conformance: no verification");
        }

        // Leader forms QC.
        let qc = engines[leader_idx]
            .try_form_qc()
            .unwrap_or_else(|| panic!("quorum should be reached in round {round}"));

        // All validators receive the QC (deterministic order).
        for engine in &mut engines {
            engine.deliver_qc(qc.clone()).expect("conformance: no verification");
        }

        // All validators advance the view (deterministic order).
        for engine in &mut engines {
            engine.advance_view();
        }

        // Sync next_height across all engines. In a real system,
        // the height is a chain property (all validators see the
        // same blocks via broadcast). Here, each engine has its
        // own next_height counter, so we sync them to the max
        // after each round.
        let max_height = engines.iter().map(|e| e.next_height.value()).max().unwrap_or(0);
        for engine in &mut engines {
            if engine.next_height.value() < max_height {
                engine.next_height = Height::new(max_height);
            }
        }
    }

    // Drive one more empty round to flush the pipeline.
    let leader_idx = usize::from(vs.leader(engines[0].current_view()));
    let (header, proposal) =
        engines[leader_idx].propose().expect("leader should propose flush round");
    let block_hash = OxideBft::block_hash(&header);
    let leader_vote = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    engines[leader_idx]
        .collect_vote(u16::try_from(leader_idx).unwrap(), leader_vote)
        .expect("conformance: no verification");
    let mut follower_votes = Vec::new();
    for (i, engine) in engines.iter_mut().enumerate() {
        if i == leader_idx {
            continue;
        }
        if let Some(vote) = engine.vote(&header, &proposal) {
            follower_votes.push((u16::try_from(i).unwrap(), vote));
        }
    }
    for (voter, vote) in follower_votes {
        engines[leader_idx].collect_vote(voter, vote).expect("conformance: no verification");
    }
    let qc = engines[leader_idx].try_form_qc().expect("flush quorum");
    for engine in &mut engines {
        engine.deliver_qc(qc.clone()).expect("conformance: no verification");
    }
    for engine in &mut engines {
        engine.advance_view();
    }

    // Collect finalized blocks from each validator.
    engines
        .iter()
        .map(|e| {
            let h = e.finalized_height().map_or(0, primitives::Id::value);
            (0..=h).filter_map(|i| e.finalized_block(Height::new(i))).collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn sim_4_validators_liveness() {
    // 4 validators, 5 rounds with txs. All txs must be finalized.
    let results = run_simulation(4, 1, 5);
    // All validators should have the same number of finalized blocks.
    let n_blocks = results[0].len();
    assert!(n_blocks > 0, "should have finalized blocks");
    for (i, blocks) in results.iter().enumerate() {
        assert_eq!(
            blocks.len(),
            n_blocks,
            "validator {i} has {n_blocks} blocks expected, got {}",
            blocks.len()
        );
    }
    // All txs should be present.
    let total_txs: usize = results[0].iter().map(|b| b.txs.len()).sum();
    assert_eq!(total_txs, 5, "all 5 txs must be finalized");
}

#[test]
fn sim_4_validators_finality_agreement() {
    // All validators must agree on the same finalized blocks.
    let results = run_simulation(4, 1, 5);
    let reference = &results[0];
    for (i, blocks) in results.iter().enumerate().skip(1) {
        assert_eq!(blocks.len(), reference.len(), "validator {i} disagrees on block count");
        for (j, (a, b)) in reference.iter().zip(blocks.iter()).enumerate() {
            assert_eq!(a.height, b.height, "validator {i} disagrees on height at block {j}");
            assert_eq!(a.txs, b.txs, "validator {i} disagrees on txs at block {j}");
        }
    }
}

#[test]
fn sim_deterministic_across_runs() {
    // Two runs with identical inputs must produce identical outputs.
    let run1 = run_simulation(4, 1, 5);
    let run2 = run_simulation(4, 1, 5);
    assert_eq!(run1.len(), run2.len(), "different validator count across runs");
    for (i, (a, b)) in run1.iter().zip(run2.iter()).enumerate() {
        assert_eq!(a.len(), b.len(), "validator {i}: different block count");
        for (j, (ba, bb)) in a.iter().zip(b.iter()).enumerate() {
            assert_eq!(ba.height, bb.height, "validator {i} block {j}: height mismatch");
            assert_eq!(ba.txs, bb.txs, "validator {i} block {j}: txs mismatch");
        }
    }
}

#[test]
fn sim_7_validators_liveness() {
    // 7 validators (f=2, quorum=5). 3 rounds with txs.
    let results = run_simulation(7, 1, 3);
    let n_blocks = results[0].len();
    assert!(n_blocks > 0, "should have finalized blocks");
    let total_txs: usize = results[0].iter().map(|b| b.txs.len()).sum();
    assert_eq!(total_txs, 3, "all 3 txs must be finalized");
}

// ---- Certificate validation hardening tests ----
//
// These tests prove the engine rejects byzantine attacks that
// the prior validation missed: conflicting votes, insufficient
// quorum, and stale QCs.

#[test]
fn collect_vote_rejects_conflicting_vote_for_different_block() {
    // 4 validators, conformance mode (no BLS). The leader collects
    // a vote for its real proposal, then receives a vote for a
    // different hash at the same view. The conflicting vote must
    // be rejected.
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    // First vote: for the proposed block.
    let vote_a = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, vote_a).expect("first vote accepted");

    // Second vote: for block hash B (different block, same view).
    let vote_b = Vote {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash([0xBB; 32]),
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    let err = leader.collect_vote(2, vote_b).expect_err("conflicting vote must be rejected");
    assert!(
        matches!(err, ConsensusError::ConflictingVote { voter, .. } if voter == 2),
        "expected ConflictingVote from voter 2, got {err:?}"
    );
}

#[test]
fn collect_vote_rejects_conflicting_vote_for_different_view() {
    // 4 validators, conformance mode. The leader collects a vote
    // for view 0, then receives a vote for view 1 (different view).
    // C2 fix: future-view votes are silently dropped (not
    // ConflictingVote errors) to prevent buffer poisoning — a
    // single future-view vote must not become the "first vote"
    // and block all real current-view votes.
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    let vote_v0 = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, vote_v0).expect("first vote accepted");

    let vote_v1 = Vote {
        view: View::new(1),
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    // C2: future-view vote is silently dropped, not an error.
    leader.collect_vote(2, vote_v1).expect("future-view vote silently dropped (C2)");
    // The vote buffer must not contain the future-view vote.
    assert!(leader.votes[2].is_none(), "future-view vote must not be stored");
}

/// Regression test (C2): a single future-view vote must not
/// poison the vote buffer. Before the fix, the future-view vote
/// became the "first vote" and all real current-view votes then
/// failed the `ConflictingVote` check, stalling the view until
/// timeout — a permanent liveness `DoS` with one message per view.
#[test]
fn collect_vote_future_view_does_not_block_current_view_votes() {
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    // Byzantine voter sends a vote for view 1 (future).
    let future_vote = Vote {
        view: View::new(1),
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, future_vote).expect("future-view vote silently dropped");

    // Real votes for view 0 (current) must still be accepted.
    let real_vote = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(2, real_vote).expect("current-view vote accepted after future-view drop");
    assert!(leader.votes[2].is_some(), "current-view vote must be stored");
}

/// System-audit S1: a validator that signs two different blocks at
/// the same `(view, phase)` has equivocated — the engine must
/// preserve BOTH signed votes as `DoubleSignEvidence` instead of
/// silently dropping the second as an idempotent duplicate. The
/// evidence record is what the node pump turns into a staking
/// `evidence` transaction; losing it here made the slash
/// impossible.
#[test]
fn collect_vote_emits_evidence_on_same_voter_conflict() {
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_a = OxideBft::block_hash(&header);

    let sig_a = Signature([0xAA; 96]);
    let sig_b = Signature([0xBB; 96]);
    let vote_a = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash: block_a,
        signature: sig_a,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, vote_a).expect("first vote collects");
    assert!(leader.take_evidence().is_empty(), "no evidence from one vote");

    // Same voter, same view + phase, DIFFERENT block — the
    // equivocation. It returns Ok (the relaying peer is not the
    // offender) and never enters the collection bucket.
    let vote_b = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash: Hash([0xCC; 32]),
        signature: sig_b,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, vote_b).expect("conflicting vote drops without error");

    let evidence = leader.take_evidence();
    assert_eq!(evidence.len(), 1, "exactly one evidence record emitted");
    let ev = &evidence[0];
    assert_eq!(ev.validator, leader.validator_set().validator_addresses()[1]);
    assert_eq!(ev.view, header.view);
    assert_eq!(ev.phase, VotePhase::Prepare);
    assert_eq!(ev.epoch, leader.epoch);
    assert_eq!((ev.first_block_hash, ev.first_signature), (block_a, sig_a));
    assert_eq!(
        (ev.second_block_hash, ev.second_signature),
        (Hash([0xCC; 32]), sig_b),
        "the second, conflicting signed vote must be preserved verbatim"
    );
    // The queue drains fully — a second take returns empty.
    assert!(leader.take_evidence().is_empty());
    // The conflicting vote never displaced the recorded one in the
    // collection slot.
    assert_eq!(leader.votes[1].as_ref().map(|v| v.block_hash), Some(block_a));
}

/// A re-delivered copy of the recorded vote is idempotent, not
/// equivocation — same `(view, phase, block_hash)` produces no
/// evidence.
#[test]
fn collect_vote_duplicate_same_block_emits_no_evidence() {
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    let vote = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, vote.clone()).expect("first collects");
    leader.collect_vote(1, vote).expect("duplicate is idempotent");
    assert!(leader.take_evidence().is_empty(), "identical re-delivery is not an offense");
}

/// Equivocation straddling a QC formation must still be caught:
/// the collection buffer clears when the QC forms, so a detector
/// that only reads the live slot would miss a conflicting vote
/// delivered late. `vote_history` spans the whole view.
#[test]
fn collect_vote_catches_equivocation_after_qc_clear() {
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_a = OxideBft::block_hash(&header);

    // Voter 1 votes for block A; enough same-block votes collect
    // to form the QC (buffer clears on formation).
    let vote = |sig: Signature| Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash: block_a,
        signature: sig,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, vote(Signature([0x01; 96]))).expect("v1 collects");
    leader.collect_vote(2, vote(Signature([0x02; 96]))).expect("v2 collects");
    leader.collect_vote(3, vote(Signature([0x03; 96]))).expect("v3 collects");
    assert!(leader.try_form_qc().is_some() || leader.vote_count() >= 3);
    // The conflicting vote arrives only AFTER the buffer cleared —
    // history still holds voter 1's first vote.
    let conflicting = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash: Hash([0xDD; 32]),
        signature: Signature([0xEE; 96]),
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, conflicting).expect("late conflict drops without error");
    let evidence = leader.take_evidence();
    assert_eq!(evidence.len(), 1, "post-clear equivocation must still emit evidence");
    assert_eq!(evidence[0].validator, leader.validator_set().validator_addresses()[1]);
}

/// Two votes in different *phases* are different signing contexts —
/// voting at `Prepare` and again at `PreCommit` is the protocol, not
/// an offense. History is keyed per `(validator, phase)` position.
#[test]
fn collect_vote_different_phase_is_not_equivocation() {
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    for phase in [VotePhase::Prepare, VotePhase::PreCommit, VotePhase::Commit] {
        let vote = Vote {
            view: header.view,
            phase,
            block_hash,
            signature: Signature::ZERO,
            attestation: None,
            attestation_sig: None,
        };
        leader.collect_vote(1, vote).expect("per-phase vote collects");
    }
    assert!(leader.take_evidence().is_empty(), "phase progression is not an offense");
}

/// The pending-evidence queue is bounded — a byzantine spam of
/// distinct offenses must not grow memory without limit. Overflow
/// drops the newest record and counts the drop.
#[test]
fn evidence_queue_is_bounded() {
    let mut leader = make_multi_engine(0);
    // Fill the queue directly — simulating a backlog of distinct
    // offenses the pump has not drained.
    for i in 0..MAX_PENDING_EVIDENCE {
        leader.evidence_out.push_back(types::DoubleSignEvidence {
            validator: Address::ZERO,
            view: View::new(0),
            phase: VotePhase::Prepare,
            epoch: Epoch::new(0),
            first_block_hash: Hash([u8::try_from(i % 256).unwrap_or(0); 32]),
            first_signature: Signature::ZERO,
            second_block_hash: Hash([0xFF; 32]),
            second_signature: Signature::ZERO,
        });
    }
    assert_eq!(leader.evidence_stats(), (MAX_PENDING_EVIDENCE, 0));

    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let vote_a = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash: OxideBft::block_hash(&header),
        signature: Signature([0x01; 96]),
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, vote_a).expect("first collects");
    let vote_b = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash: Hash([0xAB; 32]),
        signature: Signature([0x02; 96]),
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(1, vote_b).expect("conflict drops without error");
    assert_eq!(
        leader.evidence_stats(),
        (MAX_PENDING_EVIDENCE, 1),
        "overflow drops the newest record and counts the drop"
    );
}

/// A vote naming a block the collector never stored must not
/// become the quorum's reference. The first buffered vote fixes
/// the `(view, block_hash)` every later vote is compared
/// against — so a byzantine voter racing a phantom-hash vote in
/// before the leader's self-vote used to poison the whole view:
/// every honest vote failed `ConflictingVote` and the round
/// stalled until timeout. The phantom vote is now dropped, the
/// voter's slot stays free, and the honest QC still forms.
#[test]
fn phantom_block_vote_does_not_block_honest_quorum() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    // Byzantine voter 2's vote for a never-proposed block lands
    // FIRST — before the leader's own vote is collected.
    let phantom = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash: Hash([0xEE; 32]),
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    leader.collect_vote(2, phantom).expect("phantom vote is dropped, not an error");
    assert!(leader.votes[2].is_none(), "phantom vote must not be stored");
    assert_eq!(leader.vote_count, 0, "phantom vote must not anchor the quorum");

    // The honest path is unaffected: the self-vote establishes
    // the real reference and voter 2's honest vote still counts —
    // its slot was never consumed.
    let leader_idx = leader.validator_index;
    if let Some(v) = leader.vote(&header, &proposal) {
        leader.collect_vote(leader_idx, v).expect("self-vote accepted");
    }
    if let Some(v) = f1.vote(&header, &proposal) {
        leader.collect_vote(1, v).expect("honest vote accepted");
    }
    if let Some(v) = f2.vote(&header, &proposal) {
        leader.collect_vote(2, v).expect("honest vote from the phantom voter still counts");
    }
    let qc = leader.try_form_qc().expect("quorum forms despite the phantom vote");
    assert_eq!(qc.block_hash, block_hash, "QC certifies the real proposal");
}

#[test]
fn deliver_qc_rejects_insufficient_quorum() {
    // 4 validators (quorum = 3). A QC with only 2 signers has a
    // valid aggregate signature (in conformance mode) but does
    // not meet quorum — it must be rejected.
    let mut engine = make_multi_engine(0);

    // QC with 2 signers (below quorum of 3).
    let insufficient_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash::ZERO,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0011], // 2 signers
        aggregate_signature: AggregateSignature::ZERO,
    };

    let err = engine
        .deliver_qc(insufficient_qc)
        .expect_err("QC with insufficient quorum must be rejected");
    assert!(
        matches!(err, ConsensusError::InsufficientQuorum { voting_power, required } if voting_power == 2 && required == 3),
        "expected InsufficientQuorum (2 < 3), got {err:?}"
    );
}

/// Stake-weighted quorum (spec §3): a committee with stakes
/// [100, 1, 1, 1] has `quorum_stake = 69` of `T = 103`. The three
/// low-stake validators outnumber the honest quorum by *count*
/// (3 ≥ 3) but hold only 3 stake — a count-based check would
/// accept a certificate that commits nothing. The dominant
/// validator alone carries enough power to form a QC.
#[test]
fn deliver_qc_enforces_stake_weighted_quorum() {
    let weighted_set = ValidatorSet::new(vec![pk(1), pk(2), pk(3), pk(4)], vec![100, 1, 1, 1])
        .expect("4 validators, 100:1:1:1 stake");
    let app = Arc::new(MockApp::new());
    let mut engine = OxideBft::with_index(app, weighted_set, 0).without_signature_verification();
    assert_eq!(engine.validator_set().quorum_stake(), 69);

    // QC signed by the three 1-stake validators: count says 3/4
    // signers (≥ count-quorum 3), power says 3/103 (< 69). This
    // certificate must be rejected — the exact failure mode the
    // count-based quorum admitted.
    let small_signers_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash::ZERO,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1110],
        aggregate_signature: AggregateSignature::ZERO,
    };
    let err =
        engine.deliver_qc(small_signers_qc).expect_err("low-stake signers must not form a quorum");
    assert!(
        matches!(err, ConsensusError::InsufficientQuorum { voting_power, required } if voting_power == 3 && required == 69),
        "expected InsufficientQuorum (3 < 69), got {err:?}"
    );

    // The 100-stake validator alone exceeds the power quorum —
    // fewer signers, more weight.
    let dominant_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash::ZERO,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_0001],
        aggregate_signature: AggregateSignature::ZERO,
    };
    engine.deliver_qc(dominant_qc).expect("dominant-stake signer alone must form a quorum");
}

#[test]
fn deliver_qc_rejects_stale_qc() {
    // 4 validators, conformance mode. The engine receives a QC
    // for view 1, then receives a QC for view 0 (stale). The
    // stale QC must be rejected.
    let mut engine = make_multi_engine(0);

    // First QC: view 1 (accepted, sets high_qc).
    let qc_v1 = QuorumCertificate {
        view: View::new(1),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x11; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111], // 4 signers (≥ quorum)
        aggregate_signature: AggregateSignature::ZERO,
    };
    engine.deliver_qc(qc_v1).expect("first QC accepted");

    // Second QC: view 0 (stale — below high_qc's view 1).
    let stale_qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x00; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: AggregateSignature::ZERO,
    };
    let err = engine.deliver_qc(stale_qc).expect_err("stale QC must be rejected");
    assert!(
        matches!(err, ConsensusError::StaleQc { qc_view, high_qc_view } if qc_view == View::new(0) && high_qc_view == View::new(1)),
        "expected StaleQc (view 0 ≤ high_qc view 1), got {err:?}"
    );
}

#[test]
fn deliver_qc_rejects_qc_with_same_view_as_high_qc() {
    // A QC with the same view as the current high_qc is also
    // stale (not strictly greater). This prevents replaying the
    // same QC.
    let mut engine = make_multi_engine(0);

    let qc = QuorumCertificate {
        view: View::new(1),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x11; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: AggregateSignature::ZERO,
    };
    engine.deliver_qc(qc.clone()).expect("first QC accepted");

    // Same view, different block — stale.
    let same_view_qc = QuorumCertificate {
        view: View::new(1),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x22; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: AggregateSignature::ZERO,
    };
    let err = engine.deliver_qc(same_view_qc).expect_err("same-view QC must be rejected");
    assert!(matches!(err, ConsensusError::StaleQc { .. }), "expected StaleQc, got {err:?}");
}

#[test]
fn on_timeout_certificate_rejects_insufficient_quorum() {
    // 4 validators (quorum = 3). A TC with only 2 signers must
    // be rejected even if the aggregate signature verifies (in
    // conformance mode it always does).
    let mut engine = make_multi_engine(0);

    let insufficient_tc = conformance_tc(0, 0, &[0, 1]); // 2 signers < quorum 3

    let err = engine
        .on_timeout_certificate(&insufficient_tc)
        .expect_err("TC with insufficient quorum must be rejected");
    assert!(
        matches!(err, ConsensusError::InsufficientQuorum { voting_power, required } if voting_power == 2 && required == 3),
        "expected InsufficientQuorum (2 < 3), got {err:?}"
    );
}

/// Regression test: a validator that restarts at view 0 must
/// catch up when it receives a higher-view QC from peers. Before
/// the fix, `deliver_qc` only updated `high_qc` without advancing
/// `current_view`, so a restarted validator stayed stuck at view 0
/// forever and could never participate in consensus again.
#[test]
fn deliver_qc_advances_lagging_validator_view() {
    // Run 5 rounds to advance the view.
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    for i in 0..5u8 {
        drive_round(&mut leader, &mut [&mut f1, &mut f2, &mut f3], Some(TxBytes::new(vec![i])));
    }
    // All validators should have advanced beyond view 0.
    let peer_view = leader.current_view().value();
    assert!(peer_view > 0, "peers should have advanced beyond view 0");

    // Simulate a restart: create a fresh engine for validator 3
    // at view 0 (as if the process restarted from scratch).
    let mut restarted = make_multi_engine(3);
    assert_eq!(restarted.current_view().value(), 0);

    // The restarted validator receives a QC from a peer for the
    // peers' current high QC view.
    let qc = leader.high_qc().expect("high_qc should be set").clone();
    let qc_view = qc.view.value();
    assert!(qc_view > 0, "QC should be for a view > 0");

    // Deliver the QC to the restarted validator. Before the fix,
    // this would update `high_qc` but NOT advance `current_view`,
    // leaving the validator stuck at view 0.
    restarted.deliver_qc(qc).expect("QC must verify");

    // After the fix, the restarted validator's view should advance
    // to qc.view + 1, allowing it to participate in consensus.
    assert_eq!(
        restarted.current_view().value(),
        qc_view + 1,
        "restarted validator must catch up to qc.view + 1"
    );
}

/// Regression test: a validator that restarts at view 0 must
/// catch up when it receives a higher-view TC from peers. Before
/// the fix, the pacemaker rejected any TC whose view differed
/// from the current view, so a restarted validator could never
/// advance its view via TCs.
#[test]
fn on_timeout_certificate_advances_lagging_validator() {
    // Run 5 rounds to advance the view.
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    for i in 0..5u8 {
        drive_round(&mut leader, &mut [&mut f1, &mut f2, &mut f3], Some(TxBytes::new(vec![i])));
    }
    let peer_view = leader.current_view().value();
    assert!(peer_view > 0, "peers should have advanced beyond view 0");

    // Simulate a restart: create a fresh engine for validator 3
    // at view 0.
    let mut restarted = make_multi_engine(3);
    assert_eq!(restarted.current_view().value(), 0);

    // Construct a TC for the peers' current view with quorum.
    let tc = conformance_tc(peer_view, 0, &[0, 1, 2]); // 3 signers (quorum)

    // Deliver the TC to the restarted validator. Before the fix,
    // the pacemaker would reject this TC because tc.view != current_view.
    restarted.on_timeout_certificate(&tc).expect("TC must be accepted");

    // After the fix, the restarted validator's view should advance
    // to tc.view + 1.
    assert_eq!(
        restarted.current_view().value(),
        peer_view + 1,
        "restarted validator must catch up to tc.view + 1"
    );
}

/// Hidden-QC interleave: a QC formed in view v is withheld from a
/// validator while it times out and a TC(v) pushes it to v+1.
/// When the QC finally arrives its view is *behind* the current
/// view but ahead of `high_qc` — it must still be honored:
/// `high_qc` adopts it and the commit walk finalizes the chain it
/// certifies. Timing out of a view must never make its QC
/// unreachable — the timeout only says "quorum was not observed
/// in time", not "the block can never commit".
#[test]
fn hidden_qc_arriving_after_tc_still_commits_its_chain() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);

    // Round 0: QC(0) delivered to everyone — f3's high_qc.
    drive_round(&mut leader, &mut [&mut f1, &mut f2, &mut f3], Some(TxBytes::new(vec![0])));

    // Round 1: the leader proposes h1 and QC(1) forms — but f3
    // never receives it (the hidden QC). f3 still votes, so it
    // stores h1 for the eventual commit walk.
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header1, proposal1) = leader.propose().expect("leader proposes h1");
    let leader_idx = leader.validator_index;
    if let Some(v) = leader.vote(&header1, &proposal1) {
        leader.collect_vote(leader_idx, v).expect("self-vote");
    }
    for (i, f) in [&mut f1, &mut f2, &mut f3].iter_mut().enumerate() {
        if let Some(v) = f.vote(&header1, &proposal1) {
            let idx = u16::try_from(i + 1).expect("validator index fits u16");
            leader.collect_vote(idx, v).expect("follower vote");
        }
    }
    let qc1 = leader.try_form_qc().expect("QC(1) forms");
    for e in [&mut leader, &mut f1, &mut f2] {
        e.deliver_qc(qc1.clone()).expect("deliver");
        e.advance_view();
    }

    // f3 times out of view 1: a quorum-signed TC(1) advances it
    // to view 2 while its high_qc is still QC(0).
    let tc1 = conformance_tc(1, 0, &[0, 1, 2]); // 3 signers (quorum)
    f3.on_timeout_certificate(&tc1).expect("TC(1) accepted");
    assert_eq!(f3.current_view().value(), 2, "TC advances f3 past the hidden QC's view");
    assert!(f3.finalized_block(Height::new(0)).is_none(), "h0 is not committed at f3 yet");

    // The hidden QC(1) finally arrives: qc.view(1) < current_view
    // (2) but > high_qc(0). It must be accepted — high_qc adopts
    // it and the commit walk finalizes h0 (2-chain: QC(1)
    // certifies h1, whose embedded justify certifies h0).
    f3.deliver_qc(qc1.clone()).expect("hidden QC must be accepted");
    assert_eq!(f3.current_view().value(), 2, "the view must not regress behind the TC");
    assert_eq!(f3.high_qc().map(|q| q.view.value()), Some(1), "high_qc adopts the revealed QC");
    assert!(
        f3.finalized_block(Height::new(0)).is_some(),
        "the hidden QC's chain commits on arrival"
    );
}

// ---- Bounded view catch-up (DiemBFT v4 timeout evidence) ----
//
// A remote timeout signature may not pull a node to an arbitrary
// view: the claimed view is honored only when certificate
// evidence (QC or TC for the preceding view) moves us there.
// `deliver_timeout_evidence` feeds attached certificates through
// the verified ingestion paths; the wire handler then collects
// the signature only when `sig_view == current_view`.

/// A TC for the preceding view carried as timeout evidence
/// advances a lagging validator — the certificate, not the
/// signature, does the moving.
#[test]
fn timeout_evidence_tc_advances_view() {
    let mut engine = make_multi_engine(0);
    assert_eq!(engine.current_view().value(), 0);
    let tc = conformance_tc(4, 0, &[0, 1, 2]);
    engine.deliver_timeout_evidence(None, Some(tc));
    assert_eq!(engine.current_view().value(), 5, "TC(4) evidence moves the validator to view 5");
    // And the TC is recorded as the view's successor evidence.
    assert_eq!(
        engine.last_tc.as_ref().map(|t| t.view().value()),
        Some(4),
        "the carried TC becomes last_tc — the next proposal embeds it"
    );
}

/// A QC carried as timeout evidence both advances the view AND
/// updates `high_qc` — the timeout message doubles as high-QC
/// propagation, as in `DiemBFT`.
#[test]
fn timeout_evidence_qc_advances_view_and_high_qc() {
    let mut engine = make_multi_engine(0);
    let qc = QuorumCertificate {
        view: View::new(7),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x77; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: AggregateSignature::ZERO,
    };
    engine.deliver_timeout_evidence(Some(qc), None);
    assert_eq!(engine.current_view().value(), 8, "QC(7) evidence moves to view 8");
    assert_eq!(engine.high_qc().map(|q| q.view.value()), Some(7), "the carried QC updates high_qc");
}

/// Evidence that cannot verify must move nothing — a forged QC
/// (zero aggregate) is rejected by `deliver_qc`, so the claimed
/// jump collapses to nothing.
#[test]
fn timeout_evidence_forged_qc_moves_nothing() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
    let mut engine =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).with_secret_key(keys[0].clone());

    let forged_qc = QuorumCertificate {
        view: View::new(49),
        phase: VotePhase::Prepare,
        block_hash: Hash([0xAA; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: AggregateSignature::ZERO, // forged
    };
    engine.deliver_timeout_evidence(Some(forged_qc), None);
    assert_eq!(
        engine.current_view().value(),
        0,
        "a forged QC justifies nothing — the view stays put"
    );
}

/// A validly-signed TC from a different epoch is ignored — the
/// explicit epoch check keeps foreign-epoch evidence out even
/// when the validator sets happen to share keys.
#[test]
fn timeout_evidence_ignores_foreign_epoch() {
    let mut engine = make_multi_engine(0);
    let foreign_tc = conformance_tc(4, 9, &[0, 1, 2]); // not our epoch
    engine.deliver_timeout_evidence(None, Some(foreign_tc));
    assert_eq!(engine.current_view().value(), 0, "foreign-epoch evidence must be ignored");
}

/// The sender side: `timeout_evidence` reports the certificate
/// that justifies our current view. Entered via QC → the high QC
/// alone justifies (no TC attached). Entered via TC → the last
/// TC rides alongside the (older) high QC.
#[test]
fn timeout_evidence_reports_justifying_certificates() {
    let mut engine = make_multi_engine(0);
    // Enter view 6 via QC(5).
    let qc = QuorumCertificate {
        view: View::new(5),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x55; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: AggregateSignature::ZERO,
    };
    engine.deliver_qc(qc).expect("QC accepted");
    assert_eq!(engine.current_view().value(), 6);
    let (qc_ev, tc_ev) = engine.timeout_evidence();
    assert_eq!(qc_ev.map(|q| q.view.value()), Some(5));
    assert!(tc_ev.is_none(), "QC(view−1) alone justifies the view");

    // Then enter view 10 via TC(9) — high_qc stays at 5, so the
    // TC is the justifying evidence.
    let tc = conformance_tc(9, 0, &[0, 1, 2]);
    engine.on_timeout_certificate(&tc).expect("TC accepted");
    assert_eq!(engine.current_view().value(), 10);
    let (qc_ev, tc_ev) = engine.timeout_evidence();
    assert_eq!(
        qc_ev.map(|q| q.view.value()),
        Some(5),
        "high_qc still propagates (it feeds the receiver's own high_qc)"
    );
    assert_eq!(
        tc_ev.map(|t| t.view.value()),
        Some(9),
        "TC(view−1) is the justifying evidence here"
    );
}

/// Regression test: a TC for a past view must NOT regress the
/// engine's view. This ensures the catch-up logic doesn't
/// allow view regression (safety violation).
#[test]
fn on_timeout_certificate_rejects_past_view() {
    let mut engine = make_multi_engine(0);
    // Advance to view 5.
    for _ in 0..5 {
        engine.advance_view();
    }
    assert_eq!(engine.current_view().value(), 5);

    // TC for view 3 (past view) — must be rejected.
    let past_tc = conformance_tc(3, 0, &[0, 1, 2]);
    // The engine accepts the TC (quorum + signature pass) but
    // the pacemaker ignores it (past view) — the view must not
    // change.
    engine.on_timeout_certificate(&past_tc).expect("TC with valid quorum should not error");

    // View must not regress.
    assert_eq!(engine.current_view().value(), 5);
}

/// Regression test: `sync_to_view` must advance a lagging
/// validator forward to a higher view. This is the catch-up path
/// used when a validator receives a timeout signature for a
/// higher view (e.g., after a restart or partition). Without
/// this, validators at adjacent views can never converge
/// because they reject each other's timeout signatures.
#[test]
fn sync_to_view_advances_lagging_validator() {
    let mut engine = make_multi_engine(0);
    assert_eq!(engine.current_view().value(), 0);

    // Sync forward to view 10.
    let advanced = engine.sync_to_view(View::new(10));
    assert!(advanced, "sync_to_view should return true for a higher view");
    assert_eq!(engine.current_view().value(), 10, "view should be 10");
}

/// Regression test: `sync_to_view` must NOT regress the view.
/// A lower or equal view is a no-op (returns false).
#[test]
fn sync_to_view_rejects_lower_or_equal_view() {
    let mut engine = make_multi_engine(0);
    // Advance to view 5.
    for _ in 0..5 {
        engine.advance_view();
    }
    assert_eq!(engine.current_view().value(), 5);

    // Lower view — no-op.
    let advanced = engine.sync_to_view(View::new(3));
    assert!(!advanced, "sync_to_view should return false for a lower view");
    assert_eq!(engine.current_view().value(), 5, "view must not regress");

    // Equal view — no-op.
    let advanced = engine.sync_to_view(View::new(5));
    assert!(!advanced, "sync_to_view should return false for an equal view");
    assert_eq!(engine.current_view().value(), 5, "view must not change");
}

/// Regression test: `sync_to_view` must clear stale vote state
/// so that late-arriving votes from the old view don't pollute
/// the new view's quorum accounting.
#[test]
fn sync_to_view_clears_stale_votes() {
    let mut engine = make_multi_engine(0);
    engine.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = engine.propose().expect("engine proposes");
    let block_hash = OxideBft::block_hash(&header);

    // Manually collect a vote to populate vote state.
    let vote = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    engine.collect_vote(1, vote).expect("conformance: no verification");
    assert!(engine.vote_count > 0, "engine should have collected a vote");

    // Sync forward to a higher view.
    let advanced = engine.sync_to_view(View::new(100));
    assert!(advanced, "sync should advance");

    // Vote state must be cleared.
    assert_eq!(engine.vote_count, 0, "vote_count must be cleared after sync");
    assert!(engine.votes.iter().all(Option::is_none), "votes must be cleared after sync");
}

/// Regression test: a follower that votes on proposals must
/// advance its `next_height` via `observe_block_height` (called
/// from `vote`). Without this, a follower that becomes the leader
/// after a view change would propose at a stale height,
/// re-executing an already-finalized height with different
/// transactions and corrupting chain state.
#[test]
fn vote_syncs_next_height_from_proposal() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];

    // Drive 3 rounds. The leader proposes at heights 0, 1, 2.
    for i in 0..3u8 {
        drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![i])));
    }

    // Followers should have advanced their next_height past 0
    // because they voted on proposals at heights 0, 1, 2.
    // After 3 rounds, next_height should be at least 3 (the
    // leader proposed at heights 0, 1, 2, so next_height = 3).
    for (name, follower) in [("f1", &f1), ("f2", &f2), ("f3", &f3)] {
        assert!(
            follower.next_height.value() >= 3,
            "{name}: next_height should be >= 3 after 3 rounds, got {}",
            follower.next_height.value()
        );
    }
}

/// Regression test: `observe_block_height` must be idempotent
/// and only advance forward. A stale height must not regress
/// `next_height`.
#[test]
fn observe_block_height_only_advances_forward() {
    let mut engine = make_multi_engine(0);
    assert_eq!(engine.next_height.value(), 0);

    // Observe height 5 — should advance to 6.
    engine.observe_block_height(Height::new(5));
    assert_eq!(engine.next_height.value(), 6);

    // Observe height 3 (stale) — should be a no-op.
    engine.observe_block_height(Height::new(3));
    assert_eq!(engine.next_height.value(), 6);

    // Observe height 6 (equal) — should advance to 7.
    engine.observe_block_height(Height::new(6));
    assert_eq!(engine.next_height.value(), 7);
}

/// Regression test (C1): `observe_block_height` with
/// `height = u64::MAX` must saturate `next_height` at `MAX`
/// rather than wrapping to 0. Before the fix, the unchecked
/// `value() + 1` wrapped `next_height` to 0, which would make
/// the validator re-propose height 0 — conflicting with the
/// finalized genesis block and corrupting chain state.
#[test]
fn observe_block_height_saturates_at_max_not_wraps_to_zero() {
    let mut engine = make_multi_engine(0);
    assert_eq!(engine.next_height.value(), 0);

    // A byzantine proposal with height = u64::MAX.
    engine.observe_block_height(Height::MAX);
    assert_eq!(
        engine.next_height.value(),
        u64::MAX,
        "next_height must saturate at u64::MAX, not wrap to 0"
    );
}

/// Regression test (C1): `Id::checked_next` and `saturating_next`
/// must not wrap at `u64::MAX`. This guards the primitive that all
/// consensus `+1` paths now use.
#[test]
fn id_checked_and_saturating_next_do_not_wrap() {
    assert!(Height::MAX.checked_next().is_none());
    assert_eq!(Height::MAX.saturating_next(), Height::MAX);
    assert_eq!(Height::new(5).checked_next(), Some(Height::new(6)));
    assert_eq!(Height::new(5).saturating_next(), Height::new(6));
}

/// Regression test: a follower that becomes the leader after a
/// view change must propose at the correct height (not height 0).
/// Before the fix, followers never advanced `next_height` from
/// received proposals, so a new leader proposed at height 0,
/// conflicting with the already-finalized block at height 0.
#[test]
fn new_leader_proposes_at_correct_height_after_view_change() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];

    // Drive 3 rounds with leader 0 (heights 0, 1, 2).
    for i in 0..3u8 {
        drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![i])));
    }

    // All validators should have finalized blocks up to height 1
    // (2-chain: 3 rounds → 2 committed blocks).
    let finalized_h = leader.finalized_height().map_or(0, primitives::Id::value);
    assert!(finalized_h >= 1, "should have finalized at least height 1");

    // Now simulate a view change: advance views so that f1
    // becomes the leader. With 4 validators and round-robin,
    // view 4 % 4 = 0 (leader 0), view 5 % 4 = 1 (leader 1).
    // Advance to view 5 so f1 is the leader.
    for engine in [&mut leader, &mut f1, &mut f2, &mut f3] {
        while engine.current_view().value() < 5 {
            engine.advance_view();
        }
    }
    assert!(f1.is_leader(), "f1 should be leader for view 5");

    // f1 should propose at a height > finalized_h, not height 0.
    f1.submit_tx(TxBytes::new(vec![42]));
    let (header, _proposal) = f1.propose().expect("f1 should propose as new leader");
    assert!(
        header.height.value() > finalized_h,
        "new leader must propose at height > {finalized_h} (finalized), got {}",
        header.height.value()
    );
}

/// Regression test: `on_timeout_certificate` must clear votes
/// and timeout signatures when the view advances. Before the
/// fix, `on_timeout_certificate` advanced the view but left
/// stale votes in the buffer, causing `ConflictingVote` errors
/// when the new view's real votes arrived.
#[test]
fn on_timeout_certificate_clears_per_view_state() {
    let mut engine = make_multi_engine(0);
    engine.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = engine.propose().expect("engine proposes");
    let block_hash = OxideBft::block_hash(&header);

    // Populate vote and timeout signature state for view 0.
    let vote = Vote {
        view: header.view,
        phase: VotePhase::Prepare,
        block_hash,
        signature: Signature::ZERO,
        attestation: None,
        attestation_sig: None,
    };
    engine.collect_vote(1, vote).expect("conformance: no verification");
    engine.timeout_signatures[2] =
        Some(types::TimeoutSigner { voter: 2, high_qc: None, signature: Signature::ZERO });
    assert!(engine.vote_count > 0, "should have collected a vote");
    assert!(
        engine.timeout_signatures.iter().any(Option::is_some),
        "should have a timeout signature"
    );

    // Process a TC for view 0 with quorum (advances to view 1).
    let tc = conformance_tc(0, 0, &[0, 1, 2]); // 3 signers (quorum)
    engine.on_timeout_certificate(&tc).expect("TC must be accepted");

    // After the view advance, all per-view state must be cleared.
    assert_eq!(engine.vote_count, 0, "vote_count must be cleared after TC");
    assert!(engine.votes.iter().all(Option::is_none), "votes must be cleared after TC");
    assert!(
        engine.timeout_signatures.iter().all(Option::is_none),
        "timeout_signatures must be cleared after TC"
    );
}

/// Regression test: `sync_to_view` must clear timeout
/// signatures, not just votes. Before the fix, stale timeout
/// signatures from the old view leaked into the new view's TC
/// aggregation, producing an aggregate that failed verification.
#[test]
fn sync_to_view_clears_timeout_signatures() {
    let mut engine = make_multi_engine(0);

    // Populate timeout signature state for view 0.
    engine.timeout_signatures[1] =
        Some(types::TimeoutSigner { voter: 1, high_qc: None, signature: Signature::ZERO });
    engine.timeout_signatures[2] =
        Some(types::TimeoutSigner { voter: 2, high_qc: None, signature: Signature::ZERO });
    assert!(
        engine.timeout_signatures.iter().any(Option::is_some),
        "should have timeout signatures"
    );

    // Sync forward to view 10.
    let advanced = engine.sync_to_view(View::new(10));
    assert!(advanced, "sync should advance");

    // Timeout signatures must be cleared.
    assert!(
        engine.timeout_signatures.iter().all(Option::is_none),
        "timeout_signatures must be cleared after sync_to_view"
    );
}

/// Regression test: `deliver_qc` catch-up (when the QC's view
/// is higher than the local view) must clear timeout signatures,
/// not just votes. Before the fix, stale timeout signatures
/// from the old view leaked into the new view's TC aggregation.
#[test]
fn deliver_qc_catchup_clears_timeout_signatures() {
    let mut engine = make_multi_engine(0);

    // Populate timeout signature state for view 0.
    engine.timeout_signatures[1] =
        Some(types::TimeoutSigner { voter: 1, high_qc: None, signature: Signature::ZERO });
    assert!(
        engine.timeout_signatures.iter().any(Option::is_some),
        "should have a timeout signature"
    );

    // Deliver a QC for a higher view (triggers catch-up).
    let qc = QuorumCertificate {
        view: View::new(5),
        phase: VotePhase::Prepare,
        block_hash: Hash([0x11; 32]),
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111], // 4 signers (quorum)
        aggregate_signature: AggregateSignature::ZERO,
    };
    engine.deliver_qc(qc).expect("QC must be accepted");

    // After the catch-up, timeout signatures must be cleared.
    assert!(
        engine.timeout_signatures.iter().all(Option::is_none),
        "timeout_signatures must be cleared after deliver_qc catch-up"
    );
}

/// Regression test: `advance_view` must clear timeout
/// signatures, not just votes.
#[test]
fn advance_view_clears_timeout_signatures() {
    let mut engine = make_multi_engine(0);

    // Populate timeout signature state.
    engine.timeout_signatures[1] =
        Some(types::TimeoutSigner { voter: 1, high_qc: None, signature: Signature::ZERO });
    assert!(
        engine.timeout_signatures.iter().any(Option::is_some),
        "should have a timeout signature"
    );

    engine.advance_view();

    assert!(
        engine.timeout_signatures.iter().all(Option::is_none),
        "timeout_signatures must be cleared after advance_view"
    );
}

/// C9 test: a restarted engine recovers `last_voted_view` and
/// `voted_at_height` from the WAL, preventing double-voting
/// and conflicting votes after a crash.
#[test]
fn c9_wal_restart_recovery() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");

    // Phase 1: create an engine with a WAL, vote on a proposal,
    // and verify the WAL was written.
    {
        let app = Arc::new(MockApp::new());
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_wal(wal);

        // Manually set safety-critical state to simulate a vote.
        engine.last_voted_view = Some(View::new(5));
        engine.voted_at_height.insert(3, Hash([0xAA; 32]));
        engine.current_view = View::new(6);
        engine.next_height = Height::new(4);
        engine.last_committed = Some((Hash([0xBB; 32]), Height::new(2)));
        engine.append_wal().expect("tempdir WAL append must succeed");
    }

    // Phase 2: simulate a restart — create a new engine with
    // the same WAL and recover.
    {
        let app = Arc::new(MockApp::new());
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_wal(wal);

        engine.recover_from_wal().expect("recover from WAL");

        // The recovered state must prevent double-voting.
        assert_eq!(engine.last_voted_view, Some(View::new(5)));
        // The recovered state must prevent conflicting votes.
        assert_eq!(
            engine.voted_at_height.get(&3),
            Some(&Hash([0xAA; 32])),
            "voted_at_height must be recovered from WAL"
        );
        // The recovered state must have the correct view and height.
        assert_eq!(engine.current_view, View::new(6));
        assert_eq!(engine.next_height, Height::new(4));
        // The committed anchor must survive restart — it gates
        // the no-highQC vote arm after epoch rotation.
        assert_eq!(
            engine.last_committed,
            Some((Hash([0xBB; 32]), Height::new(2))),
            "last_committed must be recovered from WAL"
        );
    }
}

/// WAL compaction: with the threshold forced to a single byte,
/// every append triggers a checkpoint — the file must stay at one
/// frame no matter how many votes/commits ran, and a restart must
/// still recover the full safety state including the validator set
/// (the checkpoint entry is written `include_set: true`).
#[test]
fn wal_auto_compaction_bounds_file_and_preserves_recovery() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");

    {
        let app = Arc::new(MockApp::new());
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_wal(wal);
        engine.wal.as_mut().expect("wal attached").set_compact_threshold(1);

        // Real traffic appends per vote/QC/commit — under threshold=1
        // each one compacts, exercising the checkpoint path hard.
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();

        // Safety state for the restart assertions below.
        engine.last_voted_view = Some(View::new(50));
        engine.voted_at_height.insert(9, Hash([0x77; 32]));
        engine.append_wal().expect("append must succeed");
    }

    // The compacted file holds exactly one framed entry — kilobytes,
    // not the unbounded growth the audit flagged. Generous bound so
    // the test doesn't couple to the encoded size of a pending tail.
    let size = std::fs::metadata(&wal_path).expect("stat wal").len();
    assert!(size < 64 * 1024, "compacted WAL must be one entry, got {size} bytes");

    {
        let app = Arc::new(MockApp::new());
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_wal(wal);
        engine.recover_from_wal().expect("recover from WAL");

        assert_eq!(engine.last_voted_view, Some(View::new(50)));
        assert_eq!(engine.voted_at_height.get(&9), Some(&Hash([0x77; 32])));
        assert_eq!(
            engine.validator_set,
            single_validator_set(),
            "the set-bearing checkpoint restores committee membership"
        );
    }
}

/// Fsync batching: the WAL pays one `sync_data` per *signature
/// emission*, not per state mutation. QC adoptions and commit
/// markers flush their frames but defer the fsync onto the next
/// signature-path append, so a happy-path view costs a voter one
/// fsync (its vote) and a leader two (proposal + self-vote) —
/// not one per adopted QC, committed block, and vote. The
/// regression this guards: a refactor that re-syncs deferred
/// records would silently triple the durable-write budget.
#[test]
fn wal_fsyncs_once_per_signature_emission() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let syncs = |e: &OxideBft| e.wal.as_ref().expect("wal attached").sync_count();

    // Real BLS keys + real WALs: conformance engines sign nothing,
    // so `propose` would skip its pre-signature fsync and the
    // leader count would read 1 instead of 2.
    let keys: Vec<crypto::BlsSecretKey> = (1u8..=4).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1; 4]).expect("4 validators");
    let mut engines: Vec<OxideBft> = (0u16..4)
        .map(|i| {
            let wal = Wal::open(dir.path().join(format!("wal-{i}.log"))).expect("open WAL");
            OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), i)
                .with_secret_key(keys[usize::from(i)].clone())
                .with_wal(wal)
        })
        .collect();

    // Three full views: view 1's QC commits view 0's block (the
    // deferred commit marker) and view 2's commits view 1's, so
    // every append class — proposal, vote, adoption, commit —
    // runs inside the counted window.
    for view in 0..3u64 {
        let leader_pos = usize::from(engines[0].validator_set.leader(View::new(view)));
        let pre: Vec<u64> = engines.iter().map(syncs).collect();

        let leader = &mut engines[leader_pos];
        leader.submit_tx(TxBytes::new(vec![u8::try_from(view).expect("view fits u8") + 1]));
        let (header, proposal) = leader.propose().expect("view's leader proposes");
        assert_eq!(
            syncs(leader) - pre[leader_pos],
            1,
            "proposal signature pays exactly one fsync (view {view})"
        );
        let lidx = leader.validator_index;
        let self_vote = leader.vote(&header, &proposal).expect("leader self-votes");
        leader.collect_vote(lidx, self_vote).expect("collect self-vote");
        assert_eq!(
            syncs(leader) - pre[leader_pos],
            2,
            "leader pays one fsync per signature: proposal + self-vote (view {view})"
        );

        // Followers vote — one fsync each. Votes are gathered first
        // so the leader borrow doesn't overlap the iteration.
        let mut votes: Vec<(usize, types::Vote)> = Vec::new();
        for (i, engine) in engines.iter_mut().enumerate() {
            if i == leader_pos {
                continue;
            }
            let Some(vote) = engine.vote(&header, &proposal) else { continue };
            assert_eq!(
                syncs(engine) - pre[i],
                1,
                "follower {i} pays one fsync per view (view {view})"
            );
            votes.push((i, vote));
        }
        let leader = &mut engines[leader_pos];
        for (i, ballot) in votes {
            let voter_idx = u16::try_from(i).expect("validator index fits u16");
            leader.collect_vote(voter_idx, ballot).expect("collect follower vote");
        }

        let qc = leader.try_form_qc().expect("quorum reached");
        // QC adoption + the commit it triggers are deferred records:
        // frames flush to the file but no fsync fires — they ride
        // the next view's signature-path appends.
        for (i, engine) in engines.iter_mut().enumerate() {
            engine.deliver_qc(qc.clone()).expect("adopt QC");
            assert_eq!(
                syncs(engine) - pre[i],
                if i == leader_pos { 2 } else { 1 },
                "QC adoption and commit must not fsync (engine {i}, view {view})"
            );
            engine.advance_view();
        }
    }
}

/// Deferred WAL frames become durable at the next signature's fsync:
/// adopt a QC (no fsync), then emit a timeout signature (one fsync)
/// — a restart must recover BOTH the adopted `high_qc` and the
/// timeout bar, proving the deferred frame rode the signature's
/// `sync_data` rather than paying its own.
#[test]
fn deferred_wal_frames_ride_next_signature_fsync() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    // A real QC from a conformance cluster (no WALs needed there).
    let mut aux: Vec<OxideBft> = (0u16..4).map(make_multi_engine).collect();
    let (l, rest) = aux.split_first_mut().expect("nonempty");
    let mut f: Vec<&mut OxideBft> = rest.iter_mut().collect();
    let qc = drive_round(l, &mut f, Some(TxBytes::new(vec![1])));

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("voter.wal");
    {
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut voter = make_multi_engine(1).with_wal(wal);
        voter.deliver_qc(qc.clone()).expect("adopt QC");
        assert_eq!(
            voter.wal.as_ref().expect("wal attached").sync_count(),
            0,
            "QC adoption must not fsync — the frame waits for the next signature"
        );
        // The timeout signature is a signature emission: its append
        // fsyncs, covering the deferred adoption frame behind it.
        voter.on_timeout().expect("timeout signature emitted");
        assert_eq!(
            voter.wal.as_ref().expect("wal attached").sync_count(),
            1,
            "timeout emission pays the view's only fsync"
        );
    }

    // Restart: both records must be durable — the adoption only
    // survived because the timeout's fsync covered it.
    let wal = Wal::open(&wal_path).expect("reopen WAL");
    let mut voter = make_multi_engine(1).with_wal(wal);
    voter.recover_from_wal().expect("recover from WAL");
    assert_eq!(
        voter.high_qc.as_ref().map(crate::verify::VerifiedQc::qc),
        Some(&qc),
        "deferred adoption must be durable after the signature's fsync"
    );
    // Catch-up requires qc.view > current_view (strict); adopting a
    // view-0 QC while at view 0 leaves the view at 0.
    assert_eq!(voter.timeout_signed_view, Some(View::new(0)));
}

/// Restart continuity: the WAL must restore the uncommitted chain
/// tail, not just safety metadata. `blocks` is in-memory only, and
/// the recovered `high_qc` anchors into it — `propose()` stamps
/// `parent.height + 1` from the stored header, `commit_walk`
/// finalizes `Complete` bodies it can reach. Without the tail a
/// restart deadlocks at its committed tip: the QC resolves to a
/// hash nothing holds and every proposal attempt returns None.
#[test]
fn wal_restart_restores_pending_tail_and_resumes_finality() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");

    let committed_before;
    let pending_hash;
    let pending_height;
    // Phase 1: run a chain with a WAL so the tail is persisted.
    {
        let app = Arc::new(MockApp::new());
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_wal(wal);
        engine.submit_tx(TxBytes::new(vec![1]));
        engine.run_until_idle();
        committed_before = engine.finalized_height().expect("blocks committed").value();
        // The newest QC'd block is still pending (the 2-chain rule
        // commits through its children) — it must be the entry the
        // restart has to resolve.
        pending_hash = engine.high_qc.as_ref().expect("high_qc set").qc().block_hash;
        pending_height = engine
            .blocks
            .get(&pending_hash)
            .map(|(header, _)| header.height)
            .expect("high_qc block stored")
            .value();
        assert!(pending_height > committed_before, "tip must be uncommitted");
    }

    // Phase 2: restart on the same WAL — the recovered engine must
    // resolve the QC'd tip and resume finalizing over the tail.
    {
        let app = Arc::new(MockApp::new());
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut engine = OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_wal(wal);
        engine.recover_from_wal().expect("recover from WAL");

        let (header, _) =
            engine.blocks.get(&pending_hash).expect("restored tail must contain the high_qc block");
        assert_eq!(header.height.value(), pending_height);

        // New work forces proposals; the flush commits through the
        // restored blocks — if the tail were lost, `propose()` would
        // return None forever and this stays at the pre-crash tip.
        engine.submit_tx(TxBytes::new(vec![2]));
        engine.run_until_idle();
        let after = engine.finalized_height().expect("finality resumed").value();
        assert!(
            after >= pending_height,
            "the pre-crash pending tip must finalize post-restart: {after} < {pending_height}"
        );
        assert!(
            engine.finalized_block(Height::new(pending_height)).is_some(),
            "commit walk must reach the restored block"
        );
    }
}

/// The dispersed-broadcast shape: a block voted header-only is
/// stored `Awaiting`, and the tail must restore it as `Awaiting`
/// (not `Complete`, not missing) so `supply_body` can still
/// certify it after restart — the same capability it had live.
#[test]
fn wal_restart_restores_awaiting_header() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");
    let mut leader = make_multi_engine(0);
    let header;
    let proposal;
    let block_hash;
    {
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut follower = make_multi_engine(1).with_wal(wal);
        // Quorum is 3 of 4 — the WAL'd follower votes alongside two
        // plain followers. `supply_bodies: false` leaves the stored
        // entry Awaiting at the moment the WAL captures it.
        let mut f2 = make_multi_engine(2);
        let mut f3 = make_multi_engine(3);
        let (h, p, _qc) = drive_round_sharded(
            &mut leader,
            &mut [&mut follower, &mut f2, &mut f3],
            Some(TxBytes::new(vec![5])),
            false,
        );
        header = h;
        proposal = p;
        block_hash = OxideBft::block_hash(&header);
        assert!(
            matches!(follower.blocks.get(&block_hash).map(|(_, b)| b), Some(BlockBody::Awaiting)),
            "pre-crash entry must be Awaiting for this test to mean anything"
        );
    }
    {
        let wal = Wal::open(&wal_path).expect("open WAL");
        let mut follower = make_multi_engine(1).with_wal(wal);
        follower.recover_from_wal().expect("recover from WAL");
        assert!(
            matches!(follower.blocks.get(&block_hash).map(|(_, b)| b), Some(BlockBody::Awaiting)),
            "restart must restore the header as Awaiting — dropping it strands the QC'd tip"
        );
        follower.supply_body(block_hash, &proposal).expect("certified body must be accepted");
        assert!(
            matches!(
                follower.blocks.get(&block_hash).map(|(_, b)| b),
                Some(BlockBody::Complete(_))
            ),
            "supply_body must upgrade the restored header exactly as live"
        );
    }
}

/// C9 test: an engine without a WAL does not crash when
/// `append_wal` or `recover_from_wal` is called.
#[test]
fn c9_no_wal_no_crash() {
    let mut engine = make_engine();

    // append_wal with no WAL should be a no-op.
    engine.append_wal().expect("no-WAL append is a no-op Ok");

    // recover_from_wal with no WAL should return Ok(()).
    engine.recover_from_wal().expect("recover with no WAL should be Ok");
}

// ---- C10: durable signing fails closed ----

/// C10 test: a WAL append failure must withhold the vote — a
/// signature emitted while its anti-equivocation state is not
/// durable can equivocate after a restart. `Wal::poison` makes
/// every append fail without touching the file — the same
/// outcome an ENOSPC write produces.
#[test]
fn c10_wal_failure_disables_vote_signing() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    // Follower engine (index 1) with a WAL that fails on append.
    let dir = tempdir().expect("tempdir");
    let mut wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
    wal.poison();
    let mut follower = make_multi_engine(1).with_wal(wal);

    // A valid proposal from leader 0 at view 0.
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, proposal) = leader.propose().expect("leader proposes");

    // The vote must be withheld: the vote-lock update cannot be
    // made durable, so no signature may leave.
    assert!(
        follower.vote(&header, &proposal).is_none(),
        "vote must be withheld when the WAL append fails"
    );
    assert!(follower.wal_failed, "WAL failure must latch");
    assert!(!follower.signing_healthy(), "signing_healthy must report the latched failure");
}

/// C10 test: the WAL-failure latch is sticky — a validator with
/// a failed WAL must go silent for every signature kind until
/// the operator restarts it on healthy storage.
#[test]
fn c10_wal_failure_latches_all_signing() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let mut wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
    wal.poison();
    let mut follower = make_multi_engine(1).with_wal(wal);
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, proposal) = leader.propose().expect("leader proposes");

    // First vote attempt fails and latches.
    assert!(follower.vote(&header, &proposal).is_none());
    assert!(follower.wal_failed);

    // Timeout signatures must also be refused.
    assert!(
        follower.on_timeout().is_none(),
        "timeout signature must be withheld while the WAL is failed"
    );
    // A second vote attempt must still refuse even though the
    // locks are already updated in memory.
    assert!(follower.vote(&header, &proposal).is_none());
}

/// C10 test: an attestation signature is still a signature — a
/// WAL-failed validator must not emit one either.
#[test]
fn c10_wal_failure_disables_attestation() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    // Two committed rounds so `attest_latest` reports a nonzero
    // executed root (the height-0 mock root is `Hash::ZERO`).
    let dir = tempdir().expect("tempdir");
    let wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
    let mut engine = OxideBft::new(Arc::new(MockApp::new()), single_validator_set())
        .without_signature_verification()
        .with_wal(wal);
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    engine.submit_tx(TxBytes::new(vec![2]));
    engine.run_until_idle();
    assert!(engine.vote_attestation().0.is_some(), "committed blocks give a non-empty attestation");

    // Poison the WAL: the next step's vote append fails and
    // latches — the self-vote must be withheld, nothing new
    // can finalize, and attestations go silent too.
    engine.wal.as_mut().expect("wal attached").poison();
    engine.submit_tx(TxBytes::new(vec![3]));
    engine.run_until_idle();
    assert!(engine.wal_failed, "failed append must latch wal_failed");

    assert_eq!(
        engine.vote_attestation(),
        (None, None),
        "attestation signatures must be withheld while the WAL is failed"
    );
}

/// C10 test: `step()` (single-validator mode) must refuse to
/// cast its self-vote when the WAL append fails — previously it
/// signed first, updated the locks after, and never appended at
/// all, so a crash left restart state unaware the vote was cast.
#[test]
fn c10_step_refuses_when_wal_fails() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let mut wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
    wal.poison();
    let mut engine = OxideBft::new(Arc::new(MockApp::new()), single_validator_set())
        .without_signature_verification()
        .with_wal(wal);
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();

    assert!(engine.wal_failed, "failed append must latch wal_failed");
    assert!(
        engine.finalized_height().is_none(),
        "a WAL-failed engine must not vote, so nothing can finalize"
    );
}

/// C10 test: `step()`'s self-vote is durable — a restart
/// recovering the WAL must see exactly the lock state the
/// engine holds (committed-height pruning included).
#[test]
fn c10_step_persists_locks_before_signing() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");
    let wal = Wal::open(&wal_path).expect("open WAL");
    let mut engine = OxideBft::new(Arc::new(MockApp::new()), single_validator_set())
        .without_signature_verification()
        .with_wal(wal);
    engine.submit_tx(TxBytes::new(vec![1]));
    engine.run_until_idle();
    assert!(engine.last_voted_view.is_some(), "run_until_idle must have voted at least once");

    // The WAL's latest entry must cover the engine's live
    // safety state — every lock the engine relies on is durable.
    // (The WAL may hold MORE locks than the live map: commit
    // appends run before `voted_at_height` pruning, so the
    // durable set is the safe, strictly-conservative superset.)
    let entry = Wal::open(&wal_path)
        .expect("reopen WAL")
        .recover()
        .expect("recover")
        .expect("WAL must contain at least one entry");
    assert_eq!(entry.last_voted_view, engine.last_voted_view);
    assert!(
        engine.voted_at_height.iter().all(|(h, b)| entry.voted_at_height.get(h) == Some(b)),
        "every live vote lock must be durable in the WAL"
    );
}

/// C10 test: the leader's self-vote must go through `vote()` —
/// the single signing authority — which updates the vote locks
/// and appends the WAL before the signature exists. Harnesses
/// that hand-built a `Vote` and called `collect_vote` skipped
/// both.
#[test]
fn c10_leader_self_vote_via_vote_is_durable() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal_path = dir.path().join("consensus.wal");
    let wal = Wal::open(&wal_path).expect("open WAL");
    let mut leader = make_multi_engine(0).with_wal(wal);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);

    // The engine's own proposal passes every eligibility rule —
    // vote() is the canonical path for leader and follower alike.
    let vote = leader.vote(&header, &proposal);
    assert!(vote.is_some(), "leader self-vote through vote() must succeed");

    // The lock must be recorded in memory AND durable in the WAL.
    assert_eq!(
        leader.voted_at_height.get(&header.height.value()),
        Some(&block_hash),
        "leader vote must take the per-height lock"
    );
    let entry = Wal::open(&wal_path)
        .expect("reopen WAL")
        .recover()
        .expect("recover")
        .expect("WAL entry must exist");
    assert_eq!(
        entry.voted_at_height.get(&header.height.value()),
        Some(&block_hash),
        "leader vote lock must be durable before the vote ships"
    );
}

/// C10 test: a healthy WAL keeps signing enabled — the
/// fail-closed gate must not break the normal path.
#[test]
fn c10_healthy_wal_signs() {
    use crate::wal::Wal;
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir");
    let wal = Wal::open(dir.path().join("consensus.wal")).expect("open WAL");
    let mut follower = make_multi_engine(1).with_wal(wal);
    let mut leader = make_multi_engine(0);
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, proposal) = leader.propose().expect("leader proposes");

    assert!(follower.vote(&header, &proposal).is_some());
    assert!(follower.signing_healthy());
    assert!(follower.on_timeout().is_some());
}

// ---- Validator key rotation (staking KEY_CHANGE) ----

/// `apply_key_changes` reads pending key changes, builds an
/// updated `ValidatorSet`, and schedules a rotation. After
/// `rotate_epoch`, the new key is active.
#[test]
fn key_change_rotates_validator_key() {
    // 4 validators with derived addresses (production convention:
    // address = validator_address(pk)).
    let pks: Vec<crypto::bls::PublicKey> = (1..=4u8).map(pk).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .without_signature_verification();

    // The staking address of validator 0 is derived from pk(1).
    let addr = vs.validator_addresses()[0];

    // Submit a key change: validator 0 rotates to a fresh real key.
    let new_key = bls_key(9).public_key();
    let changes = vec![(addr, vpk(&bls_key(9)))];
    let applied = engine.apply_key_changes(&changes).expect("apply key changes");
    assert_eq!(applied, 1, "one key change applied");

    // The rotation is pending.
    assert!(engine.rotation_pending(), "rotation should be pending");

    // Complete the rotation — the new key takes effect.
    engine.rotate_epoch().expect("complete rotation");

    // The new set has the updated key for validator 0.
    let new_set = engine.validator_set();
    assert_eq!(
        new_set.validator(0).expect("validator 0").as_bytes(),
        new_key.as_bytes(),
        "validator 0's key must be rotated",
    );

    // The staking address is preserved (identity survives key rotation).
    assert_eq!(new_set.validator_addresses()[0], addr);
}

/// `apply_key_changes` with an unknown address skips it (no-op).
#[test]
fn key_change_unknown_address_skipped() {
    let pks: Vec<crypto::bls::PublicKey> = (1..=4u8).map(pk).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    let mut engine =
        OxideBft::with_index(Arc::new(MockApp::new()), vs, 0).without_signature_verification();

    // An address not in the validator set — no index_of match.
    let unknown = primitives::Address([0xAA; 20]);
    let changes = vec![(unknown, vpk(&bls_key(0x0B)))];
    let applied = engine.apply_key_changes(&changes).expect("apply key changes");
    assert_eq!(applied, 0, "unknown address produces no change");
    assert!(!engine.rotation_pending(), "no rotation scheduled");
}

/// Malformed key bytes are unrepresentable past the seam —
/// `ValidatedPublicKey::from_bytes` is the only way to mint the
/// token `apply_key_changes` accepts, and it rejects both wrong
/// length and non-point encodings. This replaces the old
/// length-check error the engine returned at the boundary.
#[test]
fn validated_key_rejects_malformed_bytes() {
    // Wrong length.
    assert!(
        crypto::bls_signer::ValidatedPublicKey::from_bytes(&[0xBB; 47]).is_err(),
        "47 bytes cannot be a compressed BLS key"
    );
    // Right length, not a curve point.
    assert!(
        crypto::bls_signer::ValidatedPublicKey::from_bytes(&[0xBB; 48]).is_err(),
        "48 arbitrary bytes must not decode to a subgroup member"
    );
    // A real key mints fine.
    assert_eq!(vpk(&bls_key(1)).as_bytes(), bls_key(1).public_key().as_bytes());
}

/// `ValidatorSet::index_of` finds the right index for a derived
/// address, and `apply_key_change` preserves the address.
#[test]
fn validator_set_index_of_and_apply_key_change() {
    let pks: Vec<crypto::bls::PublicKey> = (1..=4u8).map(pk).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");

    // Derived addresses: index_of finds each validator.
    for i in 0..4u16 {
        let addr = vs.validator_addresses()[usize::from(i)];
        assert_eq!(vs.index_of(&addr), Some(i));
    }

    // Unknown address returns None.
    let unknown = primitives::Address([0xAA; 20]);
    assert_eq!(vs.index_of(&unknown), None);

    // apply_key_change replaces the key, preserves the address.
    let new_key = crypto::bls::PublicKey([0xFF; 48]);
    let updated = vs.apply_key_change(0, new_key).expect("apply key change");
    assert_eq!(updated.validator(0).expect("v0").as_bytes(), new_key.as_bytes());
    assert_eq!(updated.validator_addresses()[0], vs.validator_addresses()[0]);
}

/// A BLS-keyed validator set for index re-seat tests — keys that
/// correspond to real secret keys, so `index_of_key` can find
/// them after membership moves.
fn bls_validator_set() -> (Vec<crypto::BlsSecretKey>, ValidatorSet) {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
    (keys, vs)
}

/// The production epoch bridge: staged adds drain through the
/// app seam and complete a rotation in one drive.
#[test]
fn drive_epoch_changes_rotates_committee() {
    let app = Arc::new(MockApp::new());
    let mut engine =
        OxideBft::new(app.clone(), single_validator_set()).without_signature_verification();
    let (new_keys, _) = bls_validator_set();
    app.queue_epoch_changes(types::EpochChanges {
        key_changes: Vec::new(),
        adds: vec![(primitives::Address([0x09; 20]), vpk(&new_keys[0]), 1)],
        removes: Vec::new(),
    });
    assert_eq!(engine.drive_epoch_changes().expect("drive"), 1);
    // The transition is staged, not yet active: activation waits for
    // the certified activation height. `rotate_epoch` force-completes
    // — the test/sim path a production node reaches via the delay.
    assert!(engine.rotation_pending());
    engine.rotate_epoch().expect("activate");
    assert_eq!(engine.epoch(), Epoch::new(1));
    assert_eq!(engine.validator_set().n(), 2);
    // A second drain sees nothing — the queues were consumed.
    assert_eq!(engine.drive_epoch_changes().expect("drive"), 0);
}

/// Key replacement + removal + addition fold into ONE rotation —
/// the combined path the two separate apply methods could not
/// express (the second schedule would hit `AlreadyPending`).
#[test]
fn drive_epoch_changes_combines_key_add_remove() {
    let app = Arc::new(MockApp::new());
    let (_, vs) = bls_validator_set();
    let mut engine =
        OxideBft::with_index(app.clone(), vs.clone(), 1).without_signature_verification();
    let old_addr = vs.validator_addresses()[0];
    let rotate_key_addr = vs.validator_addresses()[1];
    let fresh = bls_key(9);
    app.queue_epoch_changes(types::EpochChanges {
        key_changes: vec![(rotate_key_addr, vpk(&fresh))],
        adds: vec![(primitives::Address([0x0A; 20]), vpk(&bls_key(10)), 1)],
        removes: vec![old_addr],
    });
    let applied = engine.drive_epoch_changes().expect("drive");
    assert_eq!(applied, 3, "key change + remove + add");
    engine.rotate_epoch().expect("activate");
    assert_eq!(engine.epoch(), Epoch::new(1));
    let new_set = engine.validator_set();
    // Original members 0 removed; 1..3 remain, plus the append.
    assert_eq!(new_set.n(), 4);
    assert_eq!(new_set.index_of(&old_addr), None, "removed member gone");
    assert_eq!(new_set.index_of_key(&fresh.public_key()), Some(0), "key replaced at index 0");
}

/// The restart-mid-transition case: module queues persist the
/// deltas, so a node that rotated then crashed before draining
/// would re-offer the same transition post-recovery. Re-applying
/// must recognize the already-enacted set and NOT bump the
/// epoch a second time — a spurious extra epoch diverges us
/// from every peer that stayed up.
#[test]
fn drive_epoch_changes_dedups_replayed_transition() {
    let app = Arc::new(MockApp::new());
    let mut engine =
        OxideBft::new(app.clone(), single_validator_set()).without_signature_verification();
    let change = types::EpochChanges {
        key_changes: Vec::new(),
        adds: vec![(primitives::Address([0x09; 20]), vpk(&bls_key(9)), 1)],
        removes: Vec::new(),
    };
    app.queue_epoch_changes(change.clone());
    assert_eq!(engine.drive_epoch_changes().expect("drive"), 1);
    engine.rotate_epoch().expect("activate");
    assert_eq!(engine.epoch(), Epoch::new(1));
    // Replay: the same deltas re-pend after a restart — the
    // candidate equals the current set, so it is a no-op, not
    // a second transition.
    app.queue_epoch_changes(change);
    assert_eq!(engine.drive_epoch_changes().expect("re-drive"), 0);
    assert_eq!(engine.epoch(), Epoch::new(1), "no duplicate epoch bump");
}

/// Local index remapping: removing a lower-index member shifts
/// our slot; the engine must re-seat `validator_index` by
/// matching our BLS key, or we'd sign under the wrong identity.
#[test]
fn rotation_reseats_validator_index() {
    let (keys, vs) = bls_validator_set();
    let app = Arc::new(MockApp::new());
    // We are validator index 3 (key 4).
    let mut engine = OxideBft::with_index(app.clone(), vs.clone(), 3)
        .without_signature_verification()
        .with_secret_key(keys[3].clone());
    let removed_addr = vs.validator_addresses()[0];
    app.queue_epoch_changes(types::EpochChanges {
        key_changes: Vec::new(),
        adds: Vec::new(),
        removes: vec![removed_addr],
    });
    engine.drive_epoch_changes().expect("drive");
    engine.rotate_epoch().expect("activate");
    // Validator 0 removed → our key now sits at index 2.
    assert_eq!(engine.validator_index(), 2);
    assert_eq!(engine.validator_set().index_of_key(&keys[3].public_key()), Some(2));
}

/// The production drain must not activate membership at the commit
/// that staged it: the transition schedules at a certified future
/// height, stays pending until that height finalizes, and completes
/// there deterministically — the window in which the network layer
/// admits incoming members' peer connections.
#[test]
fn drive_epoch_changes_defers_activation_until_certified_height() {
    let app = Arc::new(MockApp::new());
    let mut engine =
        OxideBft::new(app.clone(), single_validator_set()).without_signature_verification();
    app.queue_epoch_changes(types::EpochChanges {
        key_changes: Vec::new(),
        adds: vec![(primitives::Address([0x09; 20]), vpk(&bls_key(9)), 1)],
        removes: Vec::new(),
    });
    // Nothing committed yet: activation is height 0 + DELAY.
    assert_eq!(engine.drive_epoch_changes().expect("drive"), 1);
    assert!(engine.rotation_pending(), "transition must be staged, not applied");
    assert_eq!(engine.epoch(), Epoch::new(0), "no epoch bump before activation");
    assert_eq!(engine.rotation_activation_height(), Some(crate::engine::ROTATION_ACTIVATION_DELAY),);
    assert_eq!(
        engine.next_validator_set().expect("pending set").n(),
        2,
        "the incoming committee is observable during the window"
    );

    // A second delta queued mid-window is NOT drained — draining
    // would either lose the record or collide with the pending
    // schedule; it waits for the next transition instead.
    app.queue_epoch_changes(types::EpochChanges {
        key_changes: Vec::new(),
        adds: vec![(primitives::Address([0x0B; 20]), vpk(&bls_key(10)), 1)],
        removes: Vec::new(),
    });
    engine.last_committed = Some((Hash([0x11; 32]), Height::new(1)));
    assert_eq!(
        engine.drive_epoch_changes().expect("drive below activation"),
        0,
        "below the activation height the pending set holds"
    );
    assert!(engine.rotation_pending());
    assert_eq!(engine.validator_set().n(), 1, "still the old committee");

    // Reaching the activation height completes the rotation.
    engine.last_committed = Some((Hash([0x22; 32]), Height::new(2)));
    assert_eq!(engine.drive_epoch_changes().expect("drive at activation"), 0);
    assert_eq!(engine.epoch(), Epoch::new(1));
    assert_eq!(engine.validator_set().n(), 2);
    assert!(!engine.rotation_pending());

    // The queued delta drains into the NEXT transition — it
    // survived the window instead of being dropped.
    assert_eq!(engine.drive_epoch_changes().expect("drive next"), 1);
    assert_eq!(engine.next_validator_set().expect("second pending set").n(), 3);
    engine.rotate_epoch().expect("activate second");
    assert_eq!(engine.epoch(), Epoch::new(2));
    assert_eq!(engine.validator_set().n(), 3);
}

/// A node holding the right committee but a stale epoch (joiner
/// configured with the current committee mid-epoch, or a restart
/// whose WAL predates the last rotation) adopts the epoch a
/// verified QC certifies: the aggregate signature binding
/// `(view, phase, block, epoch)` is the handoff proof.
#[test]
fn deliver_qc_adopts_certified_epoch() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
    // We are key 2 but believe index 0 — adoption must re-seat by key.
    let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[2].clone());
    assert_eq!(engine.epoch(), Epoch::new(0));

    // The committee mints a QC at view 5 of epoch 1 — the first
    // epoch-1 view the joiner can see.
    let block_hash = Hash([0xAB; 32]);
    let msg = crate::verify::vote_signing_message(
        Epoch::new(1),
        View::new(5),
        VotePhase::Prepare as u8,
        &block_hash,
    );
    let sigs: Vec<crypto::Signature> =
        keys.iter().map(|k| k.sign(crypto::hash::Domain::Vote, &msg)).collect();
    let qc = QuorumCertificate {
        view: View::new(5),
        phase: VotePhase::Prepare,
        block_hash,
        epoch: Epoch::new(1),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: crypto::aggregate(&sigs).expect("aggregate"),
    };
    engine.deliver_qc(qc).expect("certified epoch must adopt");

    assert_eq!(engine.epoch(), Epoch::new(1), "epoch adopted from the certified QC");
    assert_eq!(engine.current_view(), View::new(6), "view catch-up runs after adoption");
    assert_eq!(engine.validator_index(), 2, "index re-seated by key on adoption");
    assert_eq!(
        engine.pacemaker.current_epoch(),
        Epoch::new(1),
        "pacemaker rebuilt under the adopted epoch — timeouts attest it"
    );
}

/// The adoption path is fail-closed: a QC claiming a higher epoch
/// whose signers are NOT our committee fails verification under the
/// claimed epoch and is rejected — a node that genuinely missed a
/// rotation cannot invent membership by accepting it.
#[test]
fn deliver_qc_rejects_future_epoch_from_foreign_committee() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
    let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), vs, 0);

    // A FOREIGN committee (keys 9..12) signs an epoch-1 QC — the
    // bitmap resolves to OUR keys, so the aggregate must fail.
    let foreign: Vec<crypto::BlsSecretKey> = (9..=12u8).map(bls_key).collect();
    let block_hash = Hash([0xCD; 32]);
    let msg = crate::verify::vote_signing_message(
        Epoch::new(1),
        View::new(3),
        VotePhase::Prepare as u8,
        &block_hash,
    );
    let sigs: Vec<crypto::Signature> =
        foreign.iter().map(|k| k.sign(crypto::hash::Domain::Vote, &msg)).collect();
    let qc = QuorumCertificate {
        view: View::new(3),
        phase: VotePhase::Prepare,
        block_hash,
        epoch: Epoch::new(1),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: crypto::aggregate(&sigs).expect("aggregate"),
    };
    assert!(engine.deliver_qc(qc).is_err(), "foreign-committee QC must not verify");
    assert_eq!(engine.epoch(), Epoch::new(0), "no adoption on a failed verify");
    assert!(engine.high_qc().is_none());
}

/// Backward epochs are never adopted: a QC from an old epoch is
/// dead evidence — its bitmap indexes a committee we no longer
/// hold — so it is refused before any state touches it, and the
/// epoch counter can never roll back.
#[test]
fn deliver_qc_rejects_backward_epoch() {
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
    let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 0)
        .with_secret_key(keys[0].clone());
    engine.schedule_rotation(vs).expect("schedule same set");
    engine.rotate_epoch().expect("rotate to epoch 1");
    assert_eq!(engine.epoch(), Epoch::new(1));

    // A QC validly signed under epoch 0 arrives late.
    let block_hash = Hash([0xEF; 32]);
    let msg = crate::verify::vote_signing_message(
        Epoch::new(0),
        View::new(7),
        VotePhase::Prepare as u8,
        &block_hash,
    );
    let sigs: Vec<crypto::Signature> =
        keys.iter().map(|k| k.sign(crypto::hash::Domain::Vote, &msg)).collect();
    let qc = QuorumCertificate {
        view: View::new(7),
        phase: VotePhase::Prepare,
        block_hash,
        epoch: Epoch::new(0),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: crypto::aggregate(&sigs).expect("aggregate"),
    };
    assert!(
        matches!(
            engine.deliver_qc(qc),
            Err(ConsensusError::PastEpochQc { qc_epoch, epoch })
            if qc_epoch == Epoch::new(0) && epoch == Epoch::new(1)
        ),
        "a QC signed under a past epoch is refused as dead evidence"
    );
    assert_eq!(engine.epoch(), Epoch::new(1));
}

/// The mid-window restart case: a node that was down across the
/// activation boundary holds the OLD committee live and the NEW
/// committee staged (re-derived from the committed transition on
/// recovery). A QC signed by the staged committee at the new epoch
/// is certified proof that committee operated — the engine installs
/// the staged set and adopts the epoch it proved, recovering
/// membership it could never have verified under the stale set.
#[test]
fn deliver_qc_adopts_pending_committee_and_epoch() {
    let old_keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let old_pks: Vec<crypto::bls::PublicKey> =
        old_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let old_vs = ValidatorSet::new(old_pks, vec![1u64; 4]).expect("old committee");

    // The staged committee swaps member 0 for key 9 (a remove+add
    // the old set certified before this node went down).
    let new_keys: Vec<crypto::BlsSecretKey> = vec![bls_key(9), bls_key(2), bls_key(3), bls_key(4)];
    let new_pks: Vec<crypto::bls::PublicKey> =
        new_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let new_vs = ValidatorSet::new(new_pks, vec![1u64; 4]).expect("new committee");

    // We are key 2 in the old committee — still a member of the new
    // one at the same position. The engine holds old-set + staged
    // new set at epoch 0.
    let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), old_vs.clone(), 1)
        .with_secret_key(old_keys[1].clone());
    engine.schedule_rotation(new_vs.clone()).expect("stage the certified transition");
    assert!(engine.rotation_pending());

    // A quorum of the NEW committee signs a QC at epoch 1 — key 9's
    // signature cannot verify under the old committee (bitmap bit 0
    // resolves to old key 1), so only the pending-set path admits it.
    let block_hash = Hash([0x5A; 32]);
    let msg = crate::verify::vote_signing_message(
        Epoch::new(1),
        View::new(0),
        VotePhase::Prepare as u8,
        &block_hash,
    );
    let sigs: Vec<crypto::Signature> =
        new_keys.iter().map(|k| k.sign(crypto::hash::Domain::Vote, &msg)).collect();
    let qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash,
        epoch: Epoch::new(1),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: crypto::aggregate(&sigs).expect("aggregate"),
    };
    engine.deliver_qc(qc).expect("pending-committee QC must adopt");

    assert_eq!(engine.epoch(), Epoch::new(1), "epoch adopted from the staged set's QC");
    assert_eq!(engine.validator_set(), &new_vs, "the staged committee becomes the live committee");
    assert!(!engine.rotation_pending(), "adoption consumed the pending rotation");
    assert_eq!(engine.validator_index(), 1, "index re-seated under the new committee");
    assert_eq!(engine.pacemaker.current_epoch(), Epoch::new(1));
}

/// The pending-set path stays fail-closed: a staged rotation plus a
/// QC signed by keys in NEITHER committee cannot adopt — the bitmap
/// resolves to real members whose signatures were never produced.
#[test]
fn deliver_qc_rejects_pending_committee_mismatch() {
    let old_keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let old_pks: Vec<crypto::bls::PublicKey> =
        old_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let old_vs = ValidatorSet::new(old_pks, vec![1u64; 4]).expect("old committee");
    let new_keys: Vec<crypto::BlsSecretKey> = (5..=8u8).map(bls_key).collect();
    let new_pks: Vec<crypto::bls::PublicKey> =
        new_keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let new_vs = ValidatorSet::new(new_pks, vec![1u64; 4]).expect("new committee");

    let mut engine = OxideBft::with_index(Arc::new(MockApp::new()), old_vs, 0);
    engine.schedule_rotation(new_vs).expect("stage transition");

    // A THIRD committee (keys 20..24) signs — matches neither the
    // live nor the staged set, so both verifications fail.
    let foreign: Vec<crypto::BlsSecretKey> = (20..=23u8).map(bls_key).collect();
    let block_hash = Hash([0x6B; 32]);
    let msg = crate::verify::vote_signing_message(
        Epoch::new(1),
        View::new(0),
        VotePhase::Prepare as u8,
        &block_hash,
    );
    let sigs: Vec<crypto::Signature> =
        foreign.iter().map(|k| k.sign(crypto::hash::Domain::Vote, &msg)).collect();
    let qc = QuorumCertificate {
        view: View::new(0),
        phase: VotePhase::Prepare,
        block_hash,
        epoch: Epoch::new(1),
        signer_bitmap: vec![0b0000_1111],
        aggregate_signature: crypto::aggregate(&sigs).expect("aggregate"),
    };
    assert!(engine.deliver_qc(qc).is_err(), "foreign QC must not adopt via pending set");
    assert_eq!(engine.epoch(), Epoch::new(0));
    assert!(engine.rotation_pending(), "the staged rotation survives the rejection");
}

/// Recovery is a full lifecycle restore: the rotated committee,
/// the epoch, AND the pacemaker's epoch/membership all come
/// back — not just the view. A restart that rebuilt only the
/// view would stamp timeouts under the wrong epoch and reject
/// the cluster's TCs.
#[test]
fn recover_from_wal_restores_rotated_set_and_pacemaker() {
    use tempfile::tempdir;
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("consensus.wal");

    let (_, rotated_vs) = bls_validator_set();
    // Engine commits a rotation, which appends a set-bearing
    // WAL entry.
    {
        let app = Arc::new(MockApp::new());
        let mut engine = OxideBft::new(app, single_validator_set())
            .without_signature_verification()
            .with_wal(crate::wal::Wal::open(&path).expect("wal"));
        engine.schedule_rotation(rotated_vs.clone()).expect("schedule");
        engine.rotate_epoch().expect("rotate");
        assert_eq!(engine.epoch(), Epoch::new(1));
    }

    // Restart: a fresh engine built with the GENESIS set
    // recovers from the same WAL — it must come back with the
    // rotated committee, epoch, and a pacemaker rebuilt for
    // both (leader schedule + timeout epoch correctness).
    let app = Arc::new(MockApp::new());
    let mut engine = OxideBft::new(app, single_validator_set())
        .without_signature_verification()
        .with_wal(crate::wal::Wal::open(&path).expect("wal"));
    engine.recover_from_wal().expect("recover");
    assert_eq!(engine.epoch(), Epoch::new(1), "epoch recovered");
    assert_eq!(engine.validator_set(), &rotated_vs, "committee recovered");
    assert_eq!(
        engine.pacemaker.current_epoch(),
        Epoch::new(1),
        "pacemaker rebuilt with the recovered epoch — timeouts attest the right epoch"
    );
    assert_eq!(
        engine.pacemaker.validator_set().n(),
        rotated_vs.n(),
        "pacemaker rebuilt with the recovered committee — quorum math matches peers"
    );
}

/// Recovery re-seats `validator_index` through the key match:
/// a restart whose committee moved under it must not sign under
/// the stale construction index.
#[test]
fn recover_from_wal_reseats_index_by_key() {
    use tempfile::tempdir;
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("consensus.wal");

    let (keys, vs) = bls_validator_set();
    // Rotate: drop validator 0 — key 4 moves from index 3 to 2.
    {
        let app = Arc::new(MockApp::new());
        let mut engine = OxideBft::with_index(app, vs.clone(), 3)
            .without_signature_verification()
            .with_secret_key(keys[3].clone())
            .with_wal(crate::wal::Wal::open(&path).expect("wal"));
        engine.apply_validator_changes(&[], &[vs.validator_addresses()[0]]).expect("apply remove");
        engine.rotate_epoch().expect("rotate");
    }

    // Restart with the ORIGINAL set at the ORIGINAL index — the
    // WAL carries the rotated committee; recovery must both
    // restore it and re-seat us at index 2.
    let app = Arc::new(MockApp::new());
    let mut engine = OxideBft::with_index(app, vs, 3)
        .without_signature_verification()
        .with_secret_key(keys[3].clone())
        .with_wal(crate::wal::Wal::open(&path).expect("wal"));
    engine.recover_from_wal().expect("recover");
    assert_eq!(engine.validator_set().n(), 3);
    assert_eq!(engine.validator_index(), 2, "re-seated by BLS key match");
}

// ---- Hidden-QC / timeout-release fork REGRESSION ----
//
/// Regression test for the hidden-QC fork: a withheld QC plus a
/// bare TC release used to let honest validators finalize
/// conflicting blocks at the same height. The Jolteon evidence
/// rule closes it: timeout signatures bind the signer's `qc_high`,
/// a TC carries every signer's claim, and a TC-entered proposal
/// must carry a QC at least as recent as the TC's max evidence.
/// Two-chain commit additionally requires consecutive views, so a
/// hidden QC can no longer complete a committing pair across a
/// timeout gap.
///
/// Same schedule as the original counterexample — n=4, quorum=3,
/// validator 3 byzantine; equal stakes give round-robin leaders
/// (leader(v) = v % 4):
///
///   v0 (leader 0): P @ h0. Votes {0,1,2} -> QC(P). All adopt.
///   v1 (leader 1): X @ h1 (prev=P). Votes {0,1,3} -> QC(X).
///       The QC is WITHHELD. All honest time out view 1 — their
///       evidence is QC(P) (votes don't touch the adopted high QC),
///       so TC(1)'s floor is view 0.
///   v2 (leader 2): X' @ h1 (prev=P, TC(1)) — the sibling is still
///       legal: nothing is committed yet, so the floor only
///       requires extending P. Votes {0,2,3} -> QC(X').
///   Selective adoption: QC(X) -> {e0,e1}; QC(X') -> {e2}.
///   TC(2): evidence {X@1, X@1, X'@2} — max is X'@2.
///   v3 (leader 3, byz): c @ h2 (prev=X, justify=QC(X)@1) —
///       REJECTED: the floor is X'@2 and the hidden branch is
///       under it. The legit c' (prev=X', justify=QC(X')@2) is
///       voted — TC evidence adoption moves e0/e1 onto the X'
///       branch automatically.
///   QC(c')@3 is the consecutive pair over X'@2 -> commits X'
///   (and its prefix P) at h1. X can never commit: a consecutive
///   pair over X@1 would need a view-2 child extending X, and
///   view 2 already produced X'.
#[allow(clippy::similar_names, clippy::too_many_lines)]
#[test]
fn hidden_qc_timeout_release_cannot_fork() {
    let (keys, vs) = bls_validator_set();
    // Equal stakes => round-robin leader schedule 0,1,2,3.
    for (v, want) in [(0u64, 0u16), (1, 1), (2, 2), (3, 3), (4, 0)] {
        assert_eq!(vs.leader(View::new(v)), want, "round-robin leader at v{v}");
    }
    let mk = |i: u16| {
        OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), i)
            .with_secret_key(keys[i as usize].clone())
    };
    let (mut e0, mut e1, mut e2) = (mk(0), mk(1), mk(2));
    let byz = &keys[3];

    // A vote signed by the byz key for an arbitrary block.
    let byz_vote = |engine: &OxideBft, view: View, hash: Hash| -> Vote {
        let msg = engine.vote_signing_message(view, 0, &hash);
        Vote {
            view,
            phase: VotePhase::Prepare,
            block_hash: hash,
            signature: byz.sign(crypto::hash::Domain::Vote, &msg),
            attestation: None,
            attestation_sig: None,
        }
    };

    // ---- v0: P at height 0; everyone adopts QC(P) ----
    e0.submit_tx(TxBytes::new(vec![0xA0]));
    let (h_par, p_par) = e0.propose().expect("leader 0 proposes P");
    let hash_par = OxideBft::block_hash(&h_par);
    for (i, v) in [e0.vote(&h_par, &p_par), e1.vote(&h_par, &p_par), e2.vote(&h_par, &p_par)]
        .into_iter()
        .enumerate()
        .filter_map(|(i, v)| v.map(|v| (i, v)))
    {
        e0.collect_vote(u16::try_from(i).expect("idx"), v).expect("collect P vote");
    }
    let qc_par = e0.try_form_qc().expect("QC(P)@0");
    for e in [&mut e0, &mut e1, &mut e2] {
        e.deliver_qc(qc_par.clone()).expect("adopt QC(P)");
        // Same-view adoption does not bump the view (catch-up is
        // strict-greater); the driver advances after the round.
        e.advance_view();
    }

    // ---- v1: X at height 1 — the hidden QC ----
    e1.submit_tx(TxBytes::new(vec![0xB0]));
    let (h_hid, p_hid) = e1.propose().expect("leader 1 proposes X");
    let hash_hid = OxideBft::block_hash(&h_hid);
    let vx1 = e1.vote(&h_hid, &p_hid).expect("e1 votes X");
    let vx0 = e0.vote(&h_hid, &p_hid).expect("e0 votes X");
    // e1 collects {self, e0, byz} and forms the QC — but the QC is
    // never broadcast: it stays hidden from the honest network.
    e1.collect_vote(1, vx1).expect("collect");
    e1.collect_vote(0, vx0).expect("collect");
    e1.collect_vote(3, byz_vote(&e1, View::new(1), hash_hid)).expect("byz vote X");
    let qc_hid = e1.try_form_qc().expect("QC(X)@1 — exists but is withheld");

    // ---- TC(1): all honest time out view 1 ----
    // Each timeout signature binds the signer's adopted high QC —
    // all three still hold QC(P)@0 (a vote doesn't move it), so
    // TC(1)'s evidence floor is view 0.
    let t0_1 = (e0.on_timeout().expect("e0 timeout(1)"), e0.high_qc().cloned());
    let t1_1 = (e1.on_timeout().expect("e1 timeout(1)"), e1.high_qc().cloned());
    let t2_1 = (e2.on_timeout().expect("e2 timeout(1)"), e2.high_qc().cloned());
    e2.collect_timeout_signature(2, t2_1.0, t2_1.1.clone()).expect("collect t2");
    e2.collect_timeout_signature(0, t0_1.0, t0_1.1.clone()).expect("collect t0");
    let tc1 = e2
        .collect_timeout_signature(1, t1_1.0, t1_1.1.clone())
        .expect("collect t1")
        .expect("TC(1) forms — e2 advances to v2");
    assert_eq!(
        tc1.signers.iter().filter_map(|s| s.high_qc.as_ref()).map(|q| q.view.value()).max(),
        Some(0),
        "TC(1) evidence floor is QC(P)@0 — the hidden QC(X) was never adopted"
    );
    e0.on_timeout_certificate(&tc1).expect("e0 -> v2");
    e1.on_timeout_certificate(&tc1).expect("e1 -> v2");

    // ---- v2: X' at height 1 — the sibling is still legal ----
    // Nothing is committed yet, so the floor only requires
    // extending P — the conflicting QC can still form.
    e2.submit_tx(TxBytes::new(vec![0xC0]));
    let (h_sib, p_sib) = e2.propose().expect("leader 2 proposes X'");
    let hash_sib = OxideBft::block_hash(&h_sib);
    assert_eq!(h_sib.prev_block, hash_par, "X' extends P — same parent as X");
    assert_eq!(h_sib.height, h_hid.height, "X' conflicts with X at height 1");
    let vx2p = e2.vote(&h_sib, &p_sib).expect("e2 votes X'");
    e2.collect_vote(2, vx2p).expect("collect");
    e2.collect_vote(0, e0.vote(&h_sib, &p_sib).expect("e0 votes X' (lock released)"))
        .expect("collect");
    e2.collect_vote(3, byz_vote(&e2, View::new(2), hash_sib)).expect("byz vote X'");
    let qc_sib = e2.try_form_qc().expect("QC(X')@2 — conflicting QC at h1");

    // ---- Selective adoption: QC(X) -> {e0,e1}; QC(X') -> {e2} ----
    e0.deliver_qc(qc_hid.clone()).expect("e0 adopts X@1");
    e1.deliver_qc(qc_hid.clone()).expect("e1 adopts X@1");
    e2.deliver_qc(qc_sib.clone()).expect("e2 adopts X'@2");

    // ---- TC(2): evidence carries the split — {X@1, X@1, X'@2} ----
    let t0_2 = (e0.on_timeout().expect("e0 timeout(2)"), e0.high_qc().cloned());
    let t1_2 = (e1.on_timeout().expect("e1 timeout(2)"), e1.high_qc().cloned());
    let t2_2 = (e2.on_timeout().expect("e2 timeout(2)"), e2.high_qc().cloned());
    assert_eq!(t0_2.1.as_ref().map(|q| q.view.value()), Some(1), "e0 evidence: QC(X)@1");
    assert_eq!(t2_2.1.as_ref().map(|q| q.view.value()), Some(2), "e2 evidence: QC(X')@2");
    e1.collect_timeout_signature(1, t1_2.0, t1_2.1.clone()).expect("collect");
    e1.collect_timeout_signature(0, t0_2.0, t0_2.1.clone()).expect("collect");
    let tc2 = e1
        .collect_timeout_signature(2, t2_2.0, t2_2.1.clone())
        .expect("collect")
        .expect("TC(2) forms — e1 advances to v3");
    assert_eq!(
        tc2.signers.iter().filter_map(|s| s.high_qc.as_ref()).map(|q| q.view.value()).max(),
        Some(2),
        "TC(2) evidence floor is X'@2 — the hidden branch is below it"
    );
    // Forming the TC also adopts its max evidence: e1's high QC
    // moves to X'@2 — the branch hop is now *driven by the
    // certificate*, not by selective gossip.
    assert_eq!(
        e1.high_qc().map(|q| q.view.value()),
        Some(2),
        "TC evidence adoption moved e1 onto the X' branch"
    );
    e0.on_timeout_certificate(&tc2).expect("e0 -> v3");
    e2.on_timeout_certificate(&tc2).expect("e2 -> v3");

    // ---- v3: the hidden-branch proposal is REJECTED ----
    // byz (leader 3) proposes c @ h2 extending X (justify=QC(X)@1)
    // — below TC(2)'s evidence floor of view 2.
    let prop_c =
        Proposal { height: Height::new(2), txs: vec![TxBytes::new(vec![0xD0])], attestation: None };
    let mut body_bytes = Vec::new();
    prop_c.encode(&mut body_bytes);
    let k = types::shard::erasure_params(&[1, 1, 1, 1], vs.quorum_stake()).0;
    let mut h_child1 = BlockHeader {
        height: Height::new(2),
        view: View::new(3),
        epoch: Epoch::new(0),
        prev_block: hash_hid,
        tx_root: OxideBft::tx_root(&prop_c.txs),
        high_qc: Some(qc_hid.clone()),
        timeout_cert: Some(tc2.clone()),
        proposer: proposer_hash(3),
        timestamp: h_hid.timestamp.saturating_add(1),
        proposer_signature: None,
        exec_cert: None,
        body_commitment: types::shard::commitment(&body_bytes, 4, k),
    };
    h_child1.proposer_signature = Some(byz.sign(
        crypto::hash::Domain::Proposal,
        OxideBft::proposal_signing_hash(&h_child1).as_bytes(),
    ));
    // Under the old rules e0 and e1 voted c (c.prev matched their
    // hidden-branch high QC) — the flip that built the fork. Now
    // every honest engine rejects it at the evidence floor, so
    // QC(c) can never form.
    assert!(e0.vote(&h_child1, &prop_c).is_none(), "floor rejects hidden-branch c at e0");
    assert!(e1.vote(&h_child1, &prop_c).is_none(), "floor rejects hidden-branch c at e1");
    assert!(e2.vote(&h_child1, &prop_c).is_none(), "floor rejects hidden-branch c at e2");

    // ---- v3 (legit): c' extends X' — the evidence-max branch ----
    // The byz leader equivocates a second proposal, this one on the
    // chain the TC evidence locks in.
    let prop_cp =
        Proposal { height: Height::new(2), txs: vec![TxBytes::new(vec![0xE0])], attestation: None };
    let mut body_bytes = Vec::new();
    prop_cp.encode(&mut body_bytes);
    let mut h_child2 = BlockHeader {
        height: Height::new(2),
        view: View::new(3),
        epoch: Epoch::new(0),
        prev_block: hash_sib,
        tx_root: OxideBft::tx_root(&prop_cp.txs),
        high_qc: Some(qc_sib.clone()),
        timeout_cert: Some(tc2.clone()),
        proposer: proposer_hash(3),
        timestamp: h_sib.timestamp.saturating_add(1),
        proposer_signature: None,
        exec_cert: None,
        body_commitment: types::shard::commitment(&body_bytes, 4, k),
    };
    h_child2.proposer_signature = Some(byz.sign(
        crypto::hash::Domain::Proposal,
        OxideBft::proposal_signing_hash(&h_child2).as_bytes(),
    ));
    let hash_child2 = OxideBft::block_hash(&h_child2);
    // e1 adopted QC(X') from TC(2) evidence but never received
    // X' itself — catch-up gossip: `vote` stores an authenticated
    // block even when the vote is stale-view rejected, which is
    // exactly the "adopted a QC for a block we haven't seen"
    // case evidence adoption creates.
    let _ = e1.vote(&h_sib, &p_sib);
    // e0's high QC is X'@2 (adopted via TC(2) evidence), so
    // c'.prev binds correctly and the floor passes. e1 votes too —
    // TC evidence adoption put it on the same branch — so it
    // stores c' and can run the commit walk when the QC lands.
    let vcp0 = e0.vote(&h_child2, &prop_cp).expect("e0 votes c' — extends the evidence max");
    e0.collect_vote(0, vcp0).expect("collect");
    let vcp1 = e1.vote(&h_child2, &prop_cp).expect("e1 votes c' — same adopted branch");
    e0.collect_vote(1, vcp1).expect("collect");
    let vcp2 = e2.vote(&h_child2, &prop_cp).expect("e2 votes c' — built on its own branch");
    e0.collect_vote(2, vcp2).expect("collect");
    e0.collect_vote(3, byz_vote(&e0, View::new(3), hash_child2)).expect("byz vote c'");
    let qc_child2 = e0.try_form_qc().expect("QC(c')@3 — the consecutive pair over X'@2");

    // ---- Commit: the consecutive pair commits X' AND its prefix ----
    // QC(c')@3 certifies c'; c' embeds QC(X')@2 — consecutive
    // views 2->3 — so X' commits at h1, finalizing its whole
    // prefix (P at h0) even though X'@2 -> P@0 is itself
    // nonconsecutive.
    for e in [&mut e0, &mut e1, &mut e2] {
        e.deliver_qc(qc_child2.clone()).expect("adopt QC(c')@3");
    }
    for (i, e) in [&e0, &e1, &e2].iter().enumerate() {
        let f1 = e.finalized_block(Height::new(1)).expect("height 1 committed");
        assert_eq!(
            f1.txs[0].as_bytes(),
            [0xC0],
            "engine {i} committed X' — the evidence-max branch, never the hidden X"
        );
        let f0 = e.finalized_block(Height::new(0)).expect("height 0 committed as X' prefix");
        assert_eq!(f0.txs[0].as_bytes(), [0xA0], "engine {i} committed P at h0");
    }
}

// ---- Certified block sync (H5) ----
//
// A partitioned or restarted validator catches up on *proofs*, not
// trust: every committed block ships a `CertifiedBlock` — header,
// body, certifying child, QC on the child — and the receiver runs
// the full Jolteon pair check itself (`apply_certified_block`).
// These tests prove the emission path produces verifiable records
// and the intake path accepts exactly the well-formed ones.

/// Drive `rounds` on a 4-engine conformance fleet with leader 0 and
/// harvest every `CertifiedBlock` the leader emits. Each `drive_round`
/// commits the previous round's block (2-chain lag), so `rounds`
/// yields `rounds - 1` records.
fn harvest_certified(rounds: usize) -> Vec<types::CertifiedBlock> {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];
    let mut out = Vec::new();
    for r in 0..rounds {
        drive_round(
            &mut leader,
            &mut followers,
            Some(TxBytes::new(vec![u8::try_from(r).unwrap_or(0)])),
        );
        out.extend(leader.take_certified());
    }
    out
}

/// The commit path must emit one `CertifiedBlock` per committed
/// height, each carrying a well-formed Jolteon pair: child extends
/// the block one view later, `qc` certifies the child, and the
/// child's embedded `high_qc` certifies the block.
#[test]
fn commit_emits_certified_block_with_valid_proof() {
    let records = harvest_certified(3);
    assert_eq!(records.len(), 2, "3 rounds commit 2 blocks");
    for (i, rec) in records.iter().enumerate() {
        let block_hash = OxideBft::block_hash(&rec.header);
        let child_hash = OxideBft::block_hash(&rec.child);
        assert_eq!(rec.header.height, Height::new(i as u64), "record {i} height");
        assert_eq!(rec.child.prev_block, block_hash, "record {i}: child must extend the block");
        assert_eq!(
            rec.child.view,
            rec.header.view.saturating_next(),
            "record {i}: pair must be consecutive views"
        );
        assert_eq!(rec.qc.block_hash, child_hash, "record {i}: qc must certify the child");
        assert_eq!(rec.qc.view, rec.child.view, "record {i}: qc view must match the child's");
        let notary = rec.child.high_qc.as_ref().expect("record {i}: child must carry high_qc");
        assert_eq!(notary.block_hash, block_hash, "record {i}: high_qc must certify the block");
        assert_eq!(notary.view, rec.header.view, "record {i}: notary view must match");
    }
    // The queue is per-commit: a fresh fleet's first round emits
    // nothing (the 2-chain rule needs a certified pair), the second
    // emits exactly the first block's record.
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];
    drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![1])));
    assert!(leader.take_certified().is_empty(), "nothing commits after one round");
    drive_round(&mut leader, &mut followers, None);
    assert_eq!(leader.take_certified().len(), 1, "second round commits the first block");
}

/// A node that never saw the proposals finalizes the exact committed
/// prefix by applying certified records — the sync path must produce
/// identical `FinalizedBlock`s (txs, signers, context) as the live
/// commit path.
#[test]
fn apply_certified_block_commits_the_verified_prefix() {
    let records = harvest_certified(3);
    let mut syncer = make_multi_engine(3);
    for rec in &records {
        assert!(
            syncer.apply_certified_block(rec).expect("valid record must apply"),
            "height {} must commit",
            rec.header.height.value()
        );
    }
    for (i, rec) in records.iter().enumerate() {
        let committed =
            syncer.finalized_block(rec.header.height).expect("synced height must be finalized");
        assert_eq!(committed.txs, rec.proposal.txs, "height {i}: body must be the certified one");
    }
    let (_, tip) = syncer.committed_anchor().expect("anchor set after sync");
    assert_eq!(tip, records.last().expect("records").header.height);
    // Idempotent: redelivery of an already-committed record is a
    // no-op, not an error — retries under loss are normal.
    assert!(
        !syncer.apply_certified_block(&records[0]).expect("duplicate apply"),
        "re-delivered record must be idempotent"
    );
    assert!(!syncer.apply_certified_block(records.last().expect("records")).expect("dup tip"));
}

/// After syncing the committed prefix, the node must rejoin the live
/// protocol: a proposal extending the synced tip is votable once the
/// certified-but-uncommitted tip block lands (the notarized tail of
/// a `ByHash` response). One fleet drives the whole scenario so the
/// timestamps — and therefore the block hashes — chain correctly.
#[test]
fn synced_node_votes_past_the_synced_anchor() {
    let mut leader = make_multi_engine(0);
    let mut f1 = make_multi_engine(1);
    let mut f2 = make_multi_engine(2);
    let mut f3 = make_multi_engine(3);
    let mut followers = [&mut f1, &mut f2, &mut f3];
    let mut records = Vec::new();
    for r in 0..3u8 {
        drive_round(&mut leader, &mut followers, Some(TxBytes::new(vec![r])));
        records.extend(leader.take_certified());
    }
    assert_eq!(records.len(), 2, "3 rounds commit heights 0 and 1");
    // The certified-but-uncommitted tip is the newest record's child;
    // its body still sits in the leader's block store — exactly what
    // a `ByHash` response tail carries over the wire.
    let tip_header = records.last().expect("records").child.clone();
    let tip_hash = OxideBft::block_hash(&tip_header);
    let tip_body = leader
        .get_proposal(&tip_hash)
        .map(|(_, p)| p)
        .expect("the certified tip must still be stored");
    // The continuation the network produces next: extends the tip.
    let (next_header, next_proposal) = leader.propose().expect("leader proposes next");
    assert_eq!(next_header.prev_block, tip_hash, "must extend the certified tip");

    // The syncer: apply the committed prefix, then adopt the QC that
    // certifies the tip — adoption advances `current_view` to the
    // view the continuation proposal lands in.
    let mut syncer = make_multi_engine(3);
    for rec in &records {
        assert!(syncer.apply_certified_block(rec).expect("apply"));
    }
    syncer.deliver_qc(records.last().expect("records").qc.clone()).expect("adopt tip QC");
    assert_eq!(
        next_header.view,
        syncer.current_view(),
        "QC adoption must land the syncer in the proposal's view"
    );
    // Without the tail block stored, the proposal's parent is
    // unresolvable: it extends the certified tip, not the committed
    // anchor — no vote.
    assert!(
        syncer.vote(&next_header, &next_proposal).is_none(),
        "proposal over an unknown parent must not be votable"
    );
    // The tail fetch delivers the tip block; admit_proposal
    // authenticates and stores it, and the continuation is votable.
    assert!(syncer.admit_proposal(&tip_header, &tip_body));
    assert!(
        syncer.vote(&next_header, &next_proposal).is_some(),
        "with the notarized tail stored, the continuation is votable"
    );
}

/// The reject matrix: every structural mutation of a valid record
/// must fail with the specific `SyncReject` reason — a catch-all
/// accept would let a crafted record slip a forged body or a broken
/// proof past verification.
///
/// Hash bindings cascade: mutating `header` changes `hash(header)`,
/// which `child.prev_block` and `child.high_qc.block_hash` must keep
/// naming or an *earlier* check fires instead of the one under test.
/// The mutators below re-point the downstream bindings where needed
/// so each case isolates exactly one fault (conformance mode makes
/// this possible — QCs carry real bitmaps but unsigned aggregates).
/// Re-point the bindings a mutated `header` breaks so the fault
/// under test is the first to fire.
fn repoint_header(r: &mut types::CertifiedBlock) {
    let bh = OxideBft::block_hash(&r.header);
    r.child.prev_block = bh;
    if let Some(q) = &mut r.child.high_qc {
        q.block_hash = bh;
    }
    r.qc.block_hash = OxideBft::block_hash(&r.child);
}

/// Same for a mutated `child`: only the outer QC re-points —
/// the notary binding stays whatever the mutation left.
fn repoint_child(r: &mut types::CertifiedBlock) {
    r.qc.block_hash = OxideBft::block_hash(&r.child);
    r.qc.view = r.child.view;
}

type RejectCase = (&'static str, Box<dyn Fn(&mut types::CertifiedBlock)>, SyncReject);

fn reject_cases() -> Vec<RejectCase> {
    vec![
        (
            "NotNext",
            Box::new(|r: &mut types::CertifiedBlock| {
                r.header.height = r.header.height.saturating_next();
                r.proposal.height = r.header.height;
            }),
            SyncReject::NotNext,
        ),
        (
            "AnchorMismatch",
            Box::new(|r: &mut types::CertifiedBlock| {
                r.header.prev_block = Hash([0xEE; 32]);
            }),
            SyncReject::AnchorMismatch,
        ),
        (
            "BrokenPair",
            Box::new(|r: &mut types::CertifiedBlock| {
                r.child.prev_block = Hash([0xEE; 32]);
            }),
            SyncReject::BrokenPair,
        ),
        (
            "NonConsecutiveViews",
            Box::new(|r: &mut types::CertifiedBlock| {
                // View regression: a child at-or-below its parent's
                // view is impossible in any honest chain. (Forward
                // gaps — `child.view > header.view + 1` — are LEGAL
                // interior links under commit-by-descent and stage
                // rather than reject; `..._stages_interior_links`
                // covers them.)
                r.child.view = r.header.view;
            }),
            SyncReject::NonConsecutiveViews,
        ),
        (
            "MalformedCertificate",
            Box::new(|r: &mut types::CertifiedBlock| {
                r.qc.block_hash = Hash([0xEE; 32]);
            }),
            SyncReject::MalformedCertificate,
        ),
        (
            "ChildHeightSkips",
            Box::new(|r: &mut types::CertifiedBlock| {
                // The certifying child must be the direct successor —
                // a height jump means the pair skips a link.
                r.child.height = r.child.height.saturating_next();
            }),
            SyncReject::MalformedCertificate,
        ),
        (
            "MissingNotarization",
            Box::new(|r: &mut types::CertifiedBlock| {
                r.child.high_qc = None;
                repoint_child(r);
            }),
            SyncReject::BrokenNotarization,
        ),
        (
            "WrongNotaryTarget",
            Box::new(|r: &mut types::CertifiedBlock| {
                if let Some(qc) = &mut r.child.high_qc {
                    qc.block_hash = Hash([0xEE; 32]);
                }
                repoint_child(r);
            }),
            SyncReject::BrokenNotarization,
        ),
        (
            "BodyTxMismatch",
            Box::new(|r: &mut types::CertifiedBlock| {
                r.proposal.txs.push(TxBytes::new(vec![0xFF]));
            }),
            SyncReject::BodyMismatch,
        ),
        (
            "BodyRootMismatch",
            Box::new(|r: &mut types::CertifiedBlock| {
                r.header.tx_root = Hash([0xEE; 32]);
                repoint_header(r);
            }),
            SyncReject::BodyMismatch,
        ),
        (
            "BodyCommitmentMismatch",
            Box::new(|r: &mut types::CertifiedBlock| {
                r.header.body_commitment = Hash([0xEE; 32]);
                repoint_header(r);
            }),
            SyncReject::BodyMismatch,
        ),
    ]
}

#[test]
fn apply_certified_block_reject_matrix() {
    let records = harvest_certified(3);
    let valid = records[1].clone(); // height 1 — needs record[0] applied first
    for (name, mutate, want) in reject_cases() {
        let mut syncer = make_multi_engine(3);
        syncer.apply_certified_block(&records[0]).expect("prefix applies");
        let mut bad = valid.clone();
        mutate(&mut bad);
        match syncer.apply_certified_block(&bad) {
            Err(ConsensusError::SyncRejected { reason, .. }) => {
                assert_eq!(reason, want, "{name}: wrong reject reason");
            }
            other => panic!("{name}: expected SyncRejected({want:?}), got {other:?}"),
        }
        // The rejected record must not have committed the height.
        assert!(
            syncer.finalized_block(valid.header.height).is_none(),
            "{name}: rejected record must not finalize"
        );
    }
    // Sanity: the unmutated record still applies on the same prefix.
    let mut syncer = make_multi_engine(3);
    syncer.apply_certified_block(&records[0]).expect("prefix applies");
    assert!(syncer.apply_certified_block(&valid).expect("valid applies"));
}

/// Commit-by-descent on the sync path: an interior record whose
/// certifying child is NOT view-consecutive (a timeout-certificate
/// gap intervened) is still a valid certified link — it stages, and
/// commits when the run's tail seal lands. A strict per-record
/// adjacency requirement (the original check) rejected every
/// churned history and made partition-recovery unsyncable.
#[test]
fn apply_certified_block_stages_interior_links_until_the_seal() {
    let records = harvest_certified(4); // heights 0, 1, 2
    assert_eq!(records.len(), 3, "4 rounds commit 3 blocks");
    // Simulate churn on the interior record: h0's certifier (h1)
    // landed two views later — `child.view = header.view + 2`. The
    // pair is still well-formed: the QC certifies the child at the
    // child's real view (conformance mode doesn't cryptographically
    // bind the view, matching how the reject matrix re-points it).
    let mut interior = records[0].clone();
    interior.child.view = interior.header.view.saturating_next().saturating_next();
    interior.qc.view = interior.child.view;
    interior.qc.block_hash = OxideBft::block_hash(&interior.child);

    let mut syncer = make_multi_engine(3);
    // Interior link: verified, staged — but no seal exists yet, so
    // NOTHING may commit. Marking it committed here would be the
    // unsafe half of the old behavior (a notarized block can still
    // be orphaned by a later TC unlock).
    assert!(
        !syncer.apply_certified_block(&interior).expect("valid link applies"),
        "unsealed interior record must stage, not commit"
    );
    assert!(syncer.finalized_block(Height::new(0)).is_none(), "staged record must not finalize");
    assert_eq!(syncer.sync_frontier(), 1, "staging advances the verified frontier");
    // Idempotent while staged: redelivery is a no-op.
    assert!(!syncer.apply_certified_block(&interior).expect("dup"));

    // The tail seal lands: records[1] carries its own consecutive
    // pair — descent commits the whole staged prefix through it.
    assert!(
        syncer.apply_certified_block(&records[1]).expect("seal applies"),
        "the seal commits the run"
    );
    assert!(
        syncer.finalized_block(Height::new(0)).is_some(),
        "descent commits the interior ancestor"
    );
    assert!(syncer.finalized_block(Height::new(1)).is_some(), "the sealed record commits itself");

    // A run whose tail never seals commits nothing even when every
    // record is a valid link — the unsafe case the seal rule guards.
    let mut stalled = make_multi_engine(3);
    let mut unsealed_tail = records[1].clone();
    unsealed_tail.child.view = unsealed_tail.header.view.saturating_next().saturating_next();
    unsealed_tail.qc.view = unsealed_tail.child.view;
    unsealed_tail.qc.block_hash = OxideBft::block_hash(&unsealed_tail.child);
    assert!(!stalled.apply_certified_block(&interior).expect("link"));
    assert!(!stalled.apply_certified_block(&unsealed_tail).expect("link"));
    assert!(
        stalled.finalized_block(Height::new(0)).is_none()
            && stalled.finalized_block(Height::new(1)).is_none(),
        "an unsealed run must commit nothing"
    );
    assert_eq!(stalled.sync_frontier(), 2, "the staged run still extends the frontier");
}

/// A record signed under a different epoch cannot be checked against
/// this committee — `SyncEpoch` (the state-sync signal), not a
/// structural rejection.
#[test]
fn apply_certified_block_rejects_foreign_epoch() {
    let records = harvest_certified(3);
    let mut syncer = make_multi_engine(3);
    let mut bad = records[0].clone();
    bad.header.epoch = Epoch::new(9);
    match syncer.apply_certified_block(&bad) {
        Err(ConsensusError::SyncEpoch { .. }) => {}
        other => panic!("expected SyncEpoch, got {other:?}"),
    }
}

/// The crypto arms: under real BLS verification a valid record's
/// proposer signature and both QC aggregates must verify, and a
/// forged proposer signature or sub-quorum bitmap must fail.
#[test]
fn apply_certified_block_verifies_real_crypto() {
    // Real-key fleet: drive two rounds so height 0 commits.
    let keys: Vec<crypto::BlsSecretKey> = (1..=4u8).map(bls_key).collect();
    let pks: Vec<crypto::bls::PublicKey> =
        keys.iter().map(crypto::BlsSecretKey::public_key).collect();
    let vs = ValidatorSet::new(pks, vec![1u64; 4]).expect("4 validators");
    let mut engines: Vec<OxideBft> = (0..4u16)
        .map(|i| {
            OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), i)
                .with_secret_key(keys[usize::from(i)].clone())
        })
        .collect();

    let mut records = Vec::new();
    for round in 0..3u8 {
        // The engine whose seat is the reputation-effective leader
        // proposes — `header.proposer` stamps that seat and the
        // signature must verify under *its* key, so only the real
        // leader can produce a record the syncer accepts. The tx
        // keeps the conveyor busy (an empty pipeline idles out).
        let leader_idx = (0..4).position(|i| engines[i].is_leader()).expect("a leader exists");
        engines[leader_idx].submit_tx(TxBytes::new(vec![round]));
        let (h, p) = engines[leader_idx].propose().expect("leader proposes");
        let votes: Vec<(u16, types::Vote)> = engines
            .iter_mut()
            .enumerate()
            .filter_map(|(i, e)| e.vote(&h, &p).map(|v| (u16::try_from(i).expect("idx"), v)))
            .collect();
        for (idx, v) in votes {
            engines[leader_idx].collect_vote(idx, v).expect("vote collects");
        }
        let qc = engines[leader_idx].try_form_qc().expect("quorum");
        for e in &mut engines {
            e.deliver_qc(qc.clone()).expect("deliver qc");
        }
        for e in &mut engines {
            e.advance_view();
        }
        records.extend(engines[0].take_certified());
    }
    assert!(!records.is_empty(), "real-key fleet must commit");

    // A fresh real-verifying engine (a committee member that missed
    // every round) applies the records.
    let mut syncer = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 3)
        .with_secret_key(keys[3].clone());
    for rec in &records {
        assert!(syncer.apply_certified_block(rec).expect("real record must verify"));
    }

    // Forged proposer signature: sign the header with the WRONG key.
    // The signature is part of `hash(header)`, so the downstream
    // bindings must be re-pointed for the sig check to be the first
    // failure reached.
    let mut bad = records[0].clone();
    let wrong = bls_key(7);
    bad.header.proposer_signature = Some(wrong.sign(
        crypto::hash::Domain::Proposal,
        OxideBft::proposal_signing_hash(&bad.header).as_bytes(),
    ));
    let bh = OxideBft::block_hash(&bad.header);
    bad.child.prev_block = bh;
    if let Some(q) = &mut bad.child.high_qc {
        q.block_hash = bh;
    }
    bad.qc.block_hash = OxideBft::block_hash(&bad.child);
    let mut syncer2 = OxideBft::with_index(Arc::new(MockApp::new()), vs.clone(), 3)
        .with_secret_key(keys[3].clone());
    match syncer2.apply_certified_block(&bad) {
        Err(ConsensusError::SyncRejected { reason: SyncReject::BadProposerSignature, .. }) => {}
        other => panic!("expected BadProposerSignature, got {other:?}"),
    }

    // Sub-quorum outer QC: trim the bitmap to a single signer — the
    // aggregate still verifies structurally but quorum fails first.
    let mut bad2 = records[0].clone();
    bad2.qc.signer_bitmap = vec![1];
    match syncer2.apply_certified_block(&bad2) {
        Err(ConsensusError::InsufficientQuorum { .. } | ConsensusError::SyncRejected { .. }) => {}
        other => panic!("sub-quorum qc must fail, got {other:?}"),
    }
}

/// The engine's proposal budget follows the shared
/// `types::ChainParams` atomics once the governance-wired handle
/// is installed — the path a `chain.block_*` apply travels to
/// reach proposal packing and the stamped `BlockContext.gas_limit`
/// at the height it lands.
#[test]
fn chain_params_drive_live_block_budget() {
    use std::sync::atomic::Ordering::Relaxed;
    let params = Arc::new(types::ChainParams {
        max_gas: std::sync::atomic::AtomicU64::new(10_000_000_000),
        max_bytes: std::sync::atomic::AtomicU64::new(16 << 20),
        min_fee: std::sync::atomic::AtomicU64::new(0),
    });
    let engine = make_engine().with_chain_params(params.clone());
    assert_eq!(engine.block_budget().max_gas, 10_000_000_000);
    params.max_gas.store(5_000, Relaxed);
    params.max_bytes.store(1 << 20, Relaxed);
    assert_eq!(engine.block_budget().max_gas, 5_000);
    assert_eq!(engine.block_budget().max_bytes, 1 << 20);
    // Without the handle the configured budget is static.
    let bare = make_engine();
    assert_eq!(bare.block_budget(), types::CHAIN_BLOCK_BUDGET);
}

// ── Pooled-verification apply entries ─────────────────────────
//
// The node's signature pool verifies wire crypto off the
// consensus thread; the `*_preverified` entries apply the
// verdict. These tests pin the safety contract: a verdict
// replaces ONLY the pairing — every state-dependent check
// (epoch, view monotonicity, leader schedule, quorum structure)
// re-runs against live state, so a verdict that was true at
// intake but stale or contradictory at apply time can never
// move consensus.

/// Build a real quorum-signed QC for `block_hash` under the
/// `signed_committee` keys — the same artifact `try_form_qc`
/// emits, constructed directly so tests don't drive a round.
fn signed_qc(
    keys: &[crypto::BlsSecretKey],
    view: u64,
    epoch: u64,
    block_hash: Hash,
    signers: &[u16],
) -> QuorumCertificate {
    let msg = crate::verify::vote_signing_message(
        Epoch::new(epoch),
        View::new(view),
        VotePhase::Prepare as u8,
        &block_hash,
    );
    let sigs: Vec<Signature> = signers
        .iter()
        .map(|&i| keys[usize::from(i)].sign(crypto::hash::Domain::Vote, &msg))
        .collect();
    let width = signers.iter().max().map_or(0usize, |m| usize::from(*m) / 8 + 1);
    let mut bitmap = vec![0u8; width];
    for &i in signers {
        bitmap[usize::from(i) / 8] |= 1 << (i % 8);
    }
    QuorumCertificate {
        view: View::new(view),
        phase: VotePhase::Prepare,
        block_hash,
        epoch: Epoch::new(epoch),
        signer_bitmap: bitmap,
        aggregate_signature: crypto::aggregate(&sigs).expect("aggregate"),
    }
}

/// The intake-resolve step produces material a worker's pure
/// check proves — `proposal_verify_context`,
/// `qc_verify_context`, `timeout_verify_context`, and
/// `tc_verify_context` each mirror the crypto half of their
/// inline counterparts exactly.
#[test]
fn verify_context_material_runs_the_same_crypto_workers_would() {
    let (mut engines, keys) = signed_committee();
    // Proposal: a real signed header resolves material, and the
    // worker-side verify over it passes.
    let (header, _proposal) = engines[0].propose().expect("leader proposes");
    let follower = &mut engines[1];
    let material = follower.proposal_verify_context(&header).expect("resolves");
    assert!(
        crypto::verify(
            header.proposer_signature.as_ref().expect("signed"),
            crypto::hash::Domain::Proposal,
            material.signing_hash.as_bytes(),
            &material.leader_pk,
        )
        .is_ok(),
        "material proves the real signature"
    );
    // A header claiming a different proposer resolves nothing —
    // the context can never prove a forged claim.
    let mut forged = header.clone();
    forged.proposer = proposer_hash(3);
    assert!(follower.proposal_verify_context(&forged).is_none());

    // QC: a real quorum QC resolves live-committee material that
    // the worker's exact check (`qc_material_verifies`) proves.
    let qc = signed_qc(&keys, 0, 0, Hash([3; 32]), &[0, 1, 2]);
    let materials = follower.qc_verify_context(&qc).expect("resolves");
    assert_eq!(materials.len(), 1, "same-epoch QC resolves the live set only");
    assert!(!materials[0].pending_set);
    assert!(crate::verify::qc_material_verifies(&materials[0], &qc));

    // Timeout: the resolved (key, message) pair verifies a real
    // timeout signature over the same claim.
    let (pk, msg) = follower
        .timeout_verify_context(1, View::new(0), Epoch::new(0), Some(&qc))
        .expect("resolves");
    assert_eq!(pk, keys[1].public_key());
    let sig = sign_timeout_claim(&keys[1], View::new(0), Epoch::new(0), Some(&qc));
    assert!(crypto::verify(&sig, crypto::hash::Domain::Timeout, &msg, &pk).is_ok());

    // TC: per-record material plus one deduplicated material per
    // distinct carried QC — every piece verifies.
    let tc = make_tc(
        0,
        0,
        &[(0, &keys[0], Some(qc.clone())), (1, &keys[1], Some(qc.clone())), (2, &keys[2], None)],
    );
    let tm = follower.tc_verify_context(&tc).expect("resolves");
    assert_eq!(tm.records.len(), 3);
    assert_eq!(tm.qcs.len(), 1, "identical carried QCs deduplicate");
    for (pk, msg, sig) in &tm.records {
        assert!(crypto::verify(sig, crypto::hash::Domain::Timeout, msg, pk).is_ok());
    }
    for (qc, m) in &tm.qcs {
        assert!(crate::verify::qc_material_verifies(m, qc));
    }
}

/// `admit_preverified` stores a proposal only when both verdicts
/// pass — and a false verdict memoizes the rejection exactly as
/// the inline path does.
#[test]
fn admit_preverified_verdicts_gate_proposal_storage() {
    let (mut engines, _keys) = signed_committee();
    // engines[0] leads view 0 — a real signed header + matching
    // shard commitment.
    let (header, proposal) = engines[0].propose().expect("propose");
    let hash = OxideBft::block_hash(&header);

    // The truthful verdict admits and stores the body.
    let f0 = &mut engines[1];
    assert!(f0.admit_preverified(&header, &proposal, true, true));
    assert!(
        matches!(f0.blocks.get(&hash), Some((_, BlockBody::Complete(_)))),
        "verified body stores Complete"
    );

    // sig_ok = false: the verdict is the crypto word — a failing
    // verdict rejects the real signature too (fail closed), and
    // the rejection memoizes.
    let f1 = &mut engines[2];
    assert!(!f1.admit_preverified(&header, &proposal, false, true));
    assert!(
        !f1.admit_preverified(&header, &proposal, true, true),
        "a later 'verified' verdict cannot un-reject a memoized rejection"
    );

    // commit_ok = false: the signature parks the header Awaiting
    // but the mismatched body never stores Complete.
    let f2 = &mut engines[3];
    assert!(!f2.admit_preverified(&header, &proposal, true, false));
    assert!(
        matches!(f2.blocks.get(&hash), Some((_, BlockBody::Awaiting))),
        "bad body leaves the header parked, never Complete"
    );
}

/// A verdict can never admit a proposal the live schedule
/// rejects: the effective-leader check re-runs at apply, so a
/// 'verified' verdict attached to a non-leader's claim — or one
/// computed under a rotated committee — fails closed.
#[test]
fn admit_preverified_reruns_leader_check_on_live_state() {
    let (mut engines, _keys) = signed_committee();
    let (header, proposal) = engines[0].propose().expect("propose");
    let follower = &mut engines[1];
    // Claim a proposer that isn't the effective leader for view 0.
    let mut forged = header.clone();
    forged.proposer = proposer_hash(3);
    assert!(!follower.admit_preverified(&forged, &proposal, true, true));
    // And a header stripped of its signature field can't ride a
    // 'verified' verdict either.
    let mut unsigned = header.clone();
    unsigned.proposer_signature = None;
    assert!(!follower.admit_preverified(&unsigned, &proposal, true, true));
}

/// `deliver_qc_preverified` applies a `Current` verdict on a real
/// QC — and fails closed on `Invalid` or on a contradictory
/// `Pending` (the staged committee cannot sign its own epoch).
#[test]
fn deliver_qc_preverified_gates_on_verdict() {
    use crate::verify::QcVerdict;
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];
    let qc = signed_qc(&keys, 0, 0, Hash([7; 32]), &[0, 1, 2]);

    assert!(
        matches!(
            engine.deliver_qc_preverified(qc.clone(), QcVerdict::Invalid),
            Err(ConsensusError::InvalidQcSignature)
        ),
        "a failing verdict rejects the real aggregate too"
    );
    assert!(
        matches!(
            engine.deliver_qc_preverified(qc.clone(), QcVerdict::Pending),
            Err(ConsensusError::InvalidQcSignature)
        ),
        "Pending on a same-epoch QC is contradictory"
    );
    engine
        .deliver_qc_preverified(qc.clone(), QcVerdict::Current)
        .expect("the truthful verdict admits");
    assert_eq!(engine.high_qc().map(|q| q.view), Some(View::new(0)));
}

/// Stale verdict: the pool proved a QC that was ahead at intake,
/// but `high_qc` moved past it before the verdict applied. The
/// admission gates re-run on live state — the QC dies as stale.
#[test]
fn deliver_qc_preverified_stale_verdict_dies_at_live_gates() {
    use crate::verify::QcVerdict;
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];
    let hash = Hash([9; 32]);
    let qc_v1 = signed_qc(&keys, 1, 0, hash, &[0, 1, 2]);
    let qc_v2 = signed_qc(&keys, 2, 0, hash, &[0, 1, 2]);
    engine.deliver_qc_preverified(qc_v2, QcVerdict::Current).expect("v2 admitted");
    assert!(
        matches!(
            engine.deliver_qc_preverified(qc_v1, QcVerdict::Current),
            Err(ConsensusError::StaleQc { .. })
        ),
        "a verdict that was valid at intake is stale at apply"
    );
}

/// `collect_timeout_signature_preverified` collects on a truthful
/// `Current` claim verdict and fails closed on `Pending`,
/// `Invalid`, or a claim the live view/epoch can't support.
#[test]
fn collect_timeout_signature_preverified_enforces_claim_verdicts() {
    use crate::verify::QcVerdict;
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];
    let qc = signed_qc(&keys, 0, 0, Hash([5; 32]), &[0, 1, 2]);

    // Truthful verdict on a real claim collects (no TC yet).
    let sig0 = sign_timeout_claim(&keys[0], View::new(0), Epoch::new(0), Some(&qc));
    assert!(matches!(
        engine.collect_timeout_signature_preverified(
            0,
            sig0,
            Some((qc.clone(), QcVerdict::Current))
        ),
        Ok(None)
    ));

    // `Pending` on a same-epoch claim is contradictory.
    let sig1 = sign_timeout_claim(&keys[1], View::new(0), Epoch::new(0), Some(&qc));
    assert!(matches!(
        engine.collect_timeout_signature_preverified(
            1,
            sig1,
            Some((qc.clone(), QcVerdict::Pending))
        ),
        Err(ConsensusError::InvalidVoteSignature { .. })
    ));

    // `Invalid` — the pool proved the claimed QC forged.
    let sig2 = sign_timeout_claim(&keys[2], View::new(0), Epoch::new(0), Some(&qc));
    assert!(matches!(
        engine.collect_timeout_signature_preverified(
            2,
            sig2,
            Some((qc.clone(), QcVerdict::Invalid))
        ),
        Err(ConsensusError::InvalidVoteSignature { .. })
    ));

    // A claim the live state can't support: the QC's view is
    // beyond ours — dies at the re-run live gate even with a
    // `Current` verdict.
    let future_qc = signed_qc(&keys, 7, 0, Hash([5; 32]), &[0, 1, 2]);
    let sig3 = sign_timeout_claim(&keys[3], View::new(0), Epoch::new(0), Some(&future_qc));
    assert!(matches!(
        engine.collect_timeout_signature_preverified(
            3,
            sig3,
            Some((future_qc, QcVerdict::Current))
        ),
        Err(ConsensusError::InvalidVoteSignature { .. })
    ));
}

/// `on_timeout_certificate_preverified` applies a truthful
/// verdict and advances the view — a false verdict never moves
/// state even when the certificate would verify inline.
#[test]
fn on_timeout_certificate_preverified_gates_on_verdict() {
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];
    let tc = make_tc(0, 0, &[(0, &keys[0], None), (1, &keys[1], None), (2, &keys[2], None)]);
    assert!(
        matches!(
            engine.on_timeout_certificate_preverified(&tc, false),
            Err(ConsensusError::InvalidTcSignature)
        ),
        "a false verdict never applies"
    );
    engine
        .on_timeout_certificate_preverified(&tc, true)
        .expect("the truthful verdict advances the view");
    assert_eq!(engine.current_view(), View::new(1));
}

/// A `verified = true` verdict only covers the crypto: the
/// structural half — quorum power, distinct in-bounds voters,
/// epoch match — re-runs against the live set at apply. A forged
/// 'true' verdict cannot conjure quorum or cross an epoch.
#[test]
fn on_timeout_certificate_preverified_reruns_structure_on_live_state() {
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];

    // Sub-quorum: 2 of 4 equal-stake signers (quorum is 3).
    let thin_tc = make_tc(0, 0, &[(0, &keys[0], None), (1, &keys[1], None)]);
    assert!(
        matches!(
            engine.on_timeout_certificate_preverified(&thin_tc, true),
            Err(ConsensusError::InsufficientQuorum { .. })
        ),
        "a 'verified' verdict cannot conjure quorum"
    );

    // Duplicate voter: malformed regardless of verdict.
    let dup_tc = TimeoutCertificate {
        view: View::new(0),
        epoch: Epoch::new(0),
        signers: [0u16, 0, 1, 2]
            .iter()
            .map(|&v| types::TimeoutSigner {
                voter: v,
                high_qc: None,
                signature: sign_timeout_claim(
                    &keys[usize::from(v)],
                    View::new(0),
                    Epoch::new(0),
                    None,
                ),
            })
            .collect(),
    };
    assert!(matches!(
        engine.on_timeout_certificate_preverified(&dup_tc, true),
        Err(ConsensusError::InvalidTcSignature)
    ));

    // Wrong epoch: a verdict resolved pre-rotation can never move
    // the view under a different epoch.
    let wrong_epoch =
        make_tc(0, 9, &[(0, &keys[0], None), (1, &keys[1], None), (2, &keys[2], None)]);
    assert!(matches!(
        engine.on_timeout_certificate_preverified(&wrong_epoch, true),
        Err(ConsensusError::InvalidTcSignature)
    ));

    // Out-of-bounds voter: the structural pass reports the
    // roster violation even when the verdict claims verified.
    let oob_tc = TimeoutCertificate {
        view: View::new(0),
        epoch: Epoch::new(0),
        signers: vec![
            types::TimeoutSigner {
                voter: 0,
                high_qc: None,
                signature: sign_timeout_claim(&keys[0], View::new(0), Epoch::new(0), None),
            },
            types::TimeoutSigner {
                voter: 1,
                high_qc: None,
                signature: sign_timeout_claim(&keys[1], View::new(0), Epoch::new(0), None),
            },
            types::TimeoutSigner { voter: 99, high_qc: None, signature: Signature::ZERO },
        ],
    };
    assert!(matches!(
        engine.on_timeout_certificate_preverified(&oob_tc, true),
        Err(ConsensusError::SignerOutOfBounds)
    ));
}

/// `collect_vote_pooled` collects the vote immediately and returns
/// the attestation's verify material — the verdict inserts through
/// `apply_attest_verdict` and still forms the cert at quorum,
/// exactly as the inline harvest did.
#[test]
fn collect_vote_pooled_defers_attestation_and_forms_cert() {
    let (mut engines, keys) = signed_committee();
    let leader = &mut engines[0];
    // The votes must name a block the leader stored — the
    // phantom-block guard drops first-votes for unknown hashes.
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);
    let height = Height::new(7);
    let root = Hash([0x77; 32]);

    for i in 1u16..=3 {
        let att = StateAttestation { height, root };
        let att_msg = leader.attestation_signing_message(height, &root);
        let att_sig = keys[usize::from(i)].sign(crypto::hash::Domain::ExecAttest, &att_msg);
        let vote_msg = leader.vote_signing_message(View::new(0), 0, &block_hash);
        let vote_sig = keys[usize::from(i)].sign(crypto::hash::Domain::Vote, &vote_msg);
        let (res, task) = leader.collect_vote_pooled(
            i,
            Vote {
                view: View::new(0),
                phase: VotePhase::Prepare,
                block_hash,
                signature: vote_sig,
                attestation: Some(att),
                attestation_sig: Some(att_sig),
            },
        );
        res.expect("vote collects before its attestation verifies");
        let task = task.expect("harvest-eligible attestation emits material");
        assert_eq!(task.voter, i);
        // The worker-side check the pool runs — the verdict
        // applies only when it passes.
        let verified =
            crypto::verify(&task.signature, crypto::hash::Domain::ExecAttest, &task.msg, &task.pk)
                .is_ok();
        assert!(verified, "real attestation signature must verify");
        leader.apply_attest_verdict(task.voter, task.attestation, task.signature, verified);
    }
    let cert = leader.exec_certs.get(&7).expect("cert forms from pooled verdicts");
    assert_eq!(cert.state_root, root);

    // Stale verdict: a late attestation for a height whose cert
    // already formed inserts nothing — the live gate re-runs.
    let late = StateAttestation { height, root: Hash([0x99; 32]) };
    leader.apply_attest_verdict(0, late, Signature::ZERO, true);
    assert!(
        leader.exec_attest_pool.get(&7).is_none_or(|roots| !roots.contains_key(&late.root)),
        "a stale verdict can never write into the attestation pool"
    );
}

/// A failing attestation verdict drops the attestation — the vote
/// itself already collected and still counts toward quorum.
#[test]
fn attest_verdict_failure_drops_attestation_not_vote() {
    let (mut engines, keys) = signed_committee();
    let leader = &mut engines[0];
    leader.submit_tx(TxBytes::new(vec![1]));
    let (header, _proposal) = leader.propose().expect("leader proposes");
    let block_hash = OxideBft::block_hash(&header);
    let att = StateAttestation { height: Height::new(3), root: Hash([1; 32]) };
    let att_msg = leader.attestation_signing_message(att.height, &att.root);
    let att_sig = keys[1].sign(crypto::hash::Domain::ExecAttest, &att_msg);
    let vote_msg = leader.vote_signing_message(View::new(0), 0, &block_hash);
    let vote_sig = keys[1].sign(crypto::hash::Domain::Vote, &vote_msg);
    let (res, task) = leader.collect_vote_pooled(
        1,
        Vote {
            view: View::new(0),
            phase: VotePhase::Prepare,
            block_hash,
            signature: vote_sig,
            attestation: Some(att),
            attestation_sig: Some(att_sig),
        },
    );
    res.expect("vote collects");
    let task = task.expect("attestation emits material");
    // A false verdict — e.g. the pool found a bad signature —
    // inserts nothing while the vote stands.
    leader.apply_attest_verdict(task.voter, task.attestation, task.signature, false);
    assert!(!leader.exec_attest_pool.contains_key(&3), "a failing verdict never writes the pool");
    assert_eq!(leader.vote_count, 1, "the vote still collected");
}

/// Intake routing: `*_verify_context` returns `None` for cases the
/// cheap inline path already handles — a stale QC, a foreign-epoch
/// TC, a memoized-rejected header, or a stored-complete proposal
/// must never burn a pool job.
#[test]
fn verify_contexts_route_cheap_cases_inline() {
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];

    // Stale QC: high_qc at v2 makes v1's context refuse.
    let qc_v1 = signed_qc(&keys, 1, 0, Hash([9; 32]), &[0, 1, 2]);
    let qc_v2 = signed_qc(&keys, 2, 0, Hash([9; 32]), &[0, 1, 2]);
    engine.deliver_qc(qc_v2).expect("v2 delivers");
    assert!(engine.qc_verify_context(&qc_v1).is_none(), "a stale QC resolves no job");
    // And the inline path rejects it before any crypto.
    assert!(matches!(engine.deliver_qc(qc_v1), Err(ConsensusError::StaleQc { .. })));

    // Foreign-epoch TC: the context resolves nothing and the
    // inline gate rejects it.
    let foreign_tc =
        make_tc(0, 9, &[(0, &keys[0], None), (1, &keys[1], None), (2, &keys[2], None)]);
    assert!(engine.tc_verify_context(&foreign_tc).is_none(), "a foreign-epoch TC resolves no job");
    assert!(matches!(
        engine.on_timeout_certificate(&foreign_tc),
        Err(ConsensusError::InvalidTcSignature)
    ));

    // Rejected headers resolve nothing — `admit_proposal` already
    // memoized the verdict.
    let (header, proposal) = engines[0].propose().expect("propose");
    let engine = &mut engines[1];
    let mut forged = header.clone();
    forged.proposer = proposer_hash(3);
    assert!(!engine.admit_proposal(&forged, &proposal), "forged claim rejects");
    assert!(
        engine.proposal_verify_context(&forged).is_none(),
        "a memoized rejection resolves no job"
    );

    // Stored-complete proposals resolve nothing — the inline memo
    // admits them without re-verifying.
    assert!(engine.admit_proposal(&header, &proposal), "the real proposal admits");
    assert!(
        engine.proposal_verify_context(&header).is_none(),
        "a stored-complete proposal resolves no job"
    );
}

/// A timeout's carried QC is lock evidence, not a delivery — the
/// admission gate that rejects a stale QC for `deliver_qc` must
/// not suppress its verification material. Regression for a live
/// stall: an honest timeout carrying its already-adopted `high_qc`
/// resolved no material under the admission-gated context, folded
/// to `Invalid`, and was rejected — TCs could never form.
#[test]
fn qc_evidence_verify_context_resolves_stale_carried_qc() {
    use crate::verify::QcVerdict;
    let (mut engines, keys) = signed_committee();
    let engine = &mut engines[1];

    // Adopt a QC — it is now stale for admission (its view is at
    // or below our high_qc).
    let qc = signed_qc(&keys, 1, 0, Hash([9; 32]), &[0, 1, 2]);
    engine.deliver_qc(qc.clone()).expect("deliver");
    assert!(engine.qc_verify_context(&qc).is_none(), "the carried QC is stale for admission");

    // The evidence context still resolves verifiable material
    // under the live committee — exactly the crypto half the
    // inline path runs.
    let materials = engine.qc_evidence_verify_context(&qc).expect("resolves material");
    assert_eq!(materials.len(), 1, "live-committee candidate only");
    assert!(
        materials.iter().all(|m| crate::verify::qc_material_verifies(m, &qc)),
        "the real QC verifies"
    );

    // The full pooled path collects the honest timeout: verdict
    // `Current`, live screens pass, signature collects.
    let sig = sign_timeout_claim(&keys[0], engine.current_view(), Epoch::new(0), Some(&qc));
    assert!(matches!(
        engine.collect_timeout_signature_preverified(0, sig, Some((qc, QcVerdict::Current))),
        Ok(None)
    ));
}
