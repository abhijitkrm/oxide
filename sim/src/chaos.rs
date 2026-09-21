//! Engine-level Byzantine chaos driver for deterministic simulation.
//!
//! # What this is
//!
//! [`crate::swarm`] models Byzantine behavior at the *configuration*
//! layer — strategies are tracked but the underlying
//! [`devnet::multinode::MultiNodeDevnet`] runs honest rounds. This
//! module closes that gap: it drives each consensus round through the
//! real `OxideBft` API (`propose`, `vote`, `collect_vote`,
//! `try_form_qc`, `deliver_qc`) while applying the per-node
//! [`ByzantineStrategy`] as real deviations in the message flow:
//!
//! - **`Withhold`** — the node genuinely sends no vote; the leader
//!   must reach quorum without it (or the view advances empty).
//! - **`DoubleVote` / `Equivocate` (voter)** — the node emits its
//!   honest vote plus a second, *validly signed* vote for a different
//!   block hash in the same view, crafted with the node's real BLS
//!   secret key. The leader's `collect_vote` must detect the conflict
//!   (`ConsensusError::ConflictingVote`) and refuse to fold both into
//!   a QC.
//! - **`Equivocate` (leader)** — the leader signs two different
//!   headers for the same view (re-signed via
//!   [`OxideBft::proposal_signing_hash`]) and shows different halves
//!   of the follower set different blocks. Honest followers each vote
//!   once; the split vote must not form a QC for either block.
//! - **`Spam`** — the node floods the leader's inbound queue with
//!   malformed frames; decode must drop them without stalling the
//!   round (the honest vote still counts).
//! - **`Censor`** — censorship is modelled at ingress: censored
//!   transactions are never submitted to a censoring node's mempool,
//!   so a censoring leader proposes without them; honest leaders
//!   still have them and include them when rotation reaches them.
//!
//! # Why real signatures
//!
//! Every forged/conflicting message is signed with the Byzantine
//! node's actual BLS key. This is deliberate: signature verification
//! cannot be the defense (the signatures are valid) — the QC
//! consistency rule (all votes in a view must agree on one block
//! hash) is what has to catch it. That is the same property the
//! production network relies on, so the simulation exercises the
//! real code path instead of a stub.
//!
//! # Determinism
//!
//! The driver iterates followers in index order, drains queues
//! completely each round, and uses no randomness inside a run — a
//! scenario is fully determined by its inputs. Randomized scenario
//! *generation* (for the 10k gate) lives in `tests/chaos.rs` and uses
//! [`crate::network::DeterministicRng`].

use std::collections::{HashMap, HashSet};

use codec::{Decode, Encode};
use consensus::{ConsensusError, OxideBft};
use crypto::hash::Domain;
use devnet::multinode::MultiNodeDevnet;
use ports::{ConsensusEngine, Transport};
use primitives::Hash;
use types::{FinalizedBlock, TxBytes, Vote, VotePhase};

use crate::byzantine::ByzantineStrategy;

/// Cap on spam messages per round per node. `Spam { rate }` is a
/// user-supplied knob; unbounded rates would make the 10k randomized
/// gate quadratic in wall-clock for no extra coverage — the decode
/// path is exercised identically at 1 or 1e6 malformed frames.
const MAX_SPAM_PER_ROUND: u32 = 64;

/// Outcome of a chaos scenario run: what the engines observed and
/// decided, plus counters proving the Byzantine messages were
/// actually injected (a run with `votes_rejected == 0` under
/// `DoubleVote` would mean the injection never happened).
#[derive(Debug, Default)]
pub struct ChaosReport {
    /// Finalized blocks per node index (as observed by that node's
    /// own engine).
    pub finalized: Vec<Vec<FinalizedBlock>>,
    /// Votes rejected by leaders for structural/signature reasons
    /// (stale view, bad signature, unknown voter).
    pub votes_rejected: usize,
    /// Votes rejected specifically for conflicting with the first
    /// vote seen in the view — the equivocation detector firing.
    pub conflicting_votes: usize,
    /// Inbound frames dropped because they failed wire decode
    /// (spam payloads).
    pub malformed_dropped: usize,
    /// Number of rounds in which a leader equivocated (produced two
    /// signed headers for one view).
    pub leader_equivocations: usize,
    /// Rounds actually executed (always `rounds` unless noted).
    pub rounds_run: usize,
}

impl ChaosReport {
    /// Safety gate: honest nodes must never finalize conflicting
    /// histories. A lagging honest node may have *gaps* (heights it
    /// never saw — e.g. while partitioned), so this compares per-height
    /// content: for every height present in two honest nodes'
    /// finalized sets, the tx payload must be identical. Same height +
    /// different txs = a fork = violation.
    ///
    /// It also asserts each honest node's committed heights form a
    /// contiguous prefix from 0 — the property both TLA+ findings
    /// violated (forged heights, prev/justify decoupling). The engine
    /// retains up to 4096 finalized entries, far above scenario
    /// lengths, so pruning never masquerades as a gap here.
    #[must_use]
    pub fn safety_holds(&self, strategies: &HashMap<usize, ByzantineStrategy>) -> bool {
        let mut reference: Option<std::collections::BTreeMap<u64, &FinalizedBlock>> = None;
        for (i, blocks) in self.finalized.iter().enumerate() {
            if strategies.contains_key(&i) {
                continue;
            }
            let mine: std::collections::BTreeMap<u64, &FinalizedBlock> =
                blocks.iter().map(|b| (b.height.value(), b)).collect();
            // Contiguous prefix: every height below the node's
            // committed tip must be present.
            if let Some((&max_h, _)) = mine.iter().next_back() {
                if mine.len() as u64 != max_h + 1 {
                    return false;
                }
            }
            if let Some(reference) = &reference {
                for (h, block) in &mine {
                    if let Some(ref_block) = reference.get(h) {
                        if ref_block.txs != block.txs {
                            return false;
                        }
                    }
                }
            } else {
                reference = Some(mine);
            }
        }
        true
    }

    /// Liveness gate: at least one honest node finalized at least one
    /// block. Only meaningful when the scenario is within the BFT
    /// bound (byz ≤ f) and no permanent partition is in effect.
    #[must_use]
    pub fn liveness_holds(&self, strategies: &HashMap<usize, ByzantineStrategy>) -> bool {
        self.finalized
            .iter()
            .enumerate()
            .any(|(i, blocks)| !strategies.contains_key(&i) && !blocks.is_empty())
    }

    /// Count of finalized blocks across all honest nodes (used by
    /// the 10k gate to verify progress, not just safety).
    #[must_use]
    pub fn honest_finalized_total(&self, strategies: &HashMap<usize, ByzantineStrategy>) -> usize {
        self.finalized
            .iter()
            .enumerate()
            .filter(|(i, _)| !strategies.contains_key(i))
            .map(|(_, b)| b.len())
            .sum()
    }
}

/// A deterministic chaos scenario: which nodes deviate and how, plus
/// optional partition timing.
#[derive(Debug, Clone)]
pub struct ChaosScenario {
    /// Per-node strategies; absent = honest.
    pub strategies: HashMap<usize, ByzantineStrategy>,
    /// Consensus rounds to run.
    pub rounds: usize,
    /// Transactions offered per round (1 is typical — chaos testing
    /// stresses consensus, not throughput).
    pub txs_per_round: usize,
    /// Nodes partitioned for `partition_rounds` rounds starting at
    /// `partition_start`, then healed. Tests recovery-after-heal.
    pub partition: Option<PartitionPlan>,
}

/// A temporary partition: `nodes` are silenced for
/// `[start, start+duration)` rounds, then healed.
#[derive(Debug, Clone)]
pub struct PartitionPlan {
    /// Partitioned node indices.
    pub nodes: Vec<usize>,
    /// First round under partition.
    pub start: usize,
    /// Duration in rounds before healing.
    pub duration: usize,
}

impl ChaosScenario {
    /// All-honest baseline: `rounds` rounds, 1 tx per round.
    #[must_use]
    pub fn honest(rounds: usize) -> Self {
        Self { strategies: HashMap::new(), rounds, txs_per_round: 1, partition: None }
    }

    /// Node indices carrying a Byzantine strategy.
    #[must_use]
    pub fn byzantine_indices(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.strategies.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

/// Run a chaos scenario against a fresh `n`-validator devnet over the
/// in-process mesh transport. Returns the observed outcome for the
/// caller to check `safety_holds` / `liveness_holds`.
///
/// # Panics
///
/// Panics on harness-internal inconsistencies only (e.g. transport
/// errors, which are bugs in the sim — the mesh cannot fail).
/// Byzantine engine behavior surfaces as rejections in the report,
/// never as panics.
#[must_use]
pub fn run(n: usize, scenario: &ChaosScenario) -> ChaosReport {
    assert!(n > 0, "chaos scenario needs at least one validator");
    // Mempool sized generously: txs are submitted to every honest
    // node's mempool (gossip model) each round; censored leaders
    // never get them. rounds × txs_per_round × small is far below.
    let mut devnet = MultiNodeDevnet::new(n, 1 << 16);
    devnet.enable_mesh();

    let mut report = ChaosReport::default();
    for round in 0..scenario.rounds {
        // Partition timing: apply at `start`, heal after `duration`.
        if let Some(plan) = &scenario.partition {
            if round == plan.start {
                for &idx in &plan.nodes {
                    devnet.partition(idx);
                }
            }
            if round == plan.start.saturating_add(plan.duration) {
                for &idx in &plan.nodes {
                    devnet.heal(idx);
                }
            }
        }
        run_chaos_round(&mut devnet, scenario, round, &mut report);
        report.rounds_run += 1;
    }

    // Flush: one extra empty round lets the two-chain pipeline commit
    // the last pending block (same role as the devnet flush round).
    run_chaos_round(&mut devnet, scenario, usize::MAX, &mut report);

    report.finalized = devnet
        .engines()
        .iter()
        .map(|e| {
            let h = e.finalized_height().map_or(0, primitives::Id::value);
            (0..=h).filter_map(|i| e.finalized_block(primitives::Height::new(i))).collect()
        })
        .collect();
    report
}

/// One round of the chaos loop: submit → propose → vote → collect →
/// QC → deliver, with per-node strategy deviations injected at the
/// engine/transport boundary.
#[allow(clippy::too_many_lines)] // round pipeline is a single sequential flow; splitting it obscures the message order
fn run_chaos_round(
    devnet: &mut MultiNodeDevnet,
    scenario: &ChaosScenario,
    round: usize,
    report: &mut ChaosReport,
) {
    let n = devnet.n();
    let leader_idx = usize::from(devnet.validator_set().leader(devnet.engines()[0].current_view()));
    let leader_strat = scenario.strategies.get(&leader_idx);

    // Gossip submission: every node whose strategy would relay the tx
    // gets it in its mempool. A `Censor` node refuses txs from its
    // censored sender set — they never reach its mempool, so when it
    // leads, its proposals exclude them. Honest leaders still carry
    // them (the censorship-delayed-but-not-denied property).
    for i in 0..n {
        let censors_here = match scenario.strategies.get(&i) {
            Some(ByzantineStrategy::Censor { censored }) => Some(censored),
            _ => None,
        };
        for t in 0..scenario.txs_per_round {
            let tx = make_tx(round, t);
            if let Some(set) = censors_here {
                if tx_is_censored(&tx, set) {
                    continue;
                }
            }
            devnet.engines_mut()[i].submit_tx(tx);
        }
    }

    // A withholding leader emits no proposal: followers observe the
    // silence and the view advances empty via the real timeout path
    // (timeout signatures -> TC -> view change).
    if matches!(leader_strat, Some(ByzantineStrategy::Withhold)) {
        timeout_all(devnet);
        return;
    }

    let Some((header, proposal)) = devnet.engines_mut()[leader_idx].propose() else {
        timeout_all(devnet);
        return;
    };
    let hash_a = OxideBft::block_hash(&header);

    // Equivocating leader: sign a second header for the same view
    // with a different tx_root, using the leader's real key. The
    // forged signature is valid — followers' `vote()` verifies it
    // against the claimed proposer and accepts.
    let alt: Option<(types::BlockHeader, Hash)> =
        if matches!(leader_strat, Some(ByzantineStrategy::Equivocate)) {
            let mut h2 = header.clone();
            h2.tx_root = Hash([0xAB; 32]);
            let sh = OxideBft::proposal_signing_hash(&h2);
            h2.proposer_signature =
                Some(devnet.secret_key(leader_idx).sign(Domain::Proposal, sh.as_bytes()));
            report.leader_equivocations += 1;
            let h2_hash = OxideBft::block_hash(&h2);
            Some((h2, h2_hash))
        } else {
            None
        };

    // Leader self-votes for its real proposal through the engine's
    // single signing path (C10): `vote()` records the locks and
    // appends the WAL before the signature exists — the same path
    // honest followers use.
    if let Some(leader_vote) = devnet.engines_mut()[leader_idx].vote(&header, &proposal) {
        devnet.engines_mut()[leader_idx]
            .collect_vote(u16::try_from(leader_idx).unwrap_or(0), leader_vote)
            .expect("leader self-vote must verify");
    }

    // Followers vote. Under leader equivocation, the first half of
    // the follower set sees header A and the second half sees B —
    // modelling equivocating proposal delivery.
    let split_at = n.div_ceil(2);
    for i in 0..n {
        if i == leader_idx {
            continue;
        }
        let (seen_header, seen_hash) = match &alt {
            Some((h2, h2_hash)) if i >= split_at => (h2, *h2_hash),
            _ => (&header, hash_a),
        };
        match scenario.strategies.get(&i) {
            Some(ByzantineStrategy::Withhold) => {}
            Some(ByzantineStrategy::Spam { rate }) => {
                // Flood the leader's queue with malformed frames, then
                // vote honestly — a spammer is still a voter.
                let mut transport = devnet.transport(i);
                for s in 0..(*rate).min(MAX_SPAM_PER_ROUND) {
                    let junk = [0xFF, 0xDE, 0xAD, u8::try_from(s & 0xFF).unwrap_or(0)];
                    transport
                        .send(&p2p::MeshNetwork::peer_id(leader_idx), &junk)
                        .expect("mesh send");
                }
                send_vote(devnet, i, leader_idx, seen_header, &proposal);
            }
            Some(ByzantineStrategy::DoubleVote | ByzantineStrategy::Equivocate) => {
                // Forged conflicting vote FIRST, then the honest one.
                // `collect_vote` dedups by voter index — a second vote
                // from the same voter is a silent no-op — so sending
                // the forgery first is what exercises the conflict
                // check (it disagrees with the leader's self-vote for
                // `hash_a`). The signature is valid: signed with the
                // node's real key over (view, phase, conflict_hash,
                // epoch) — the QC consistency rule, not signature
                // verification, is the defense under test.
                let conflict = alt.as_ref().map_or(Hash([0xEE; 32]), |(_, h2_hash)| {
                    if seen_hash == *h2_hash { hash_a } else { *h2_hash }
                });
                let eng = &devnet.engines()[i];
                let msg =
                    eng.vote_signing_message(seen_header.view, VotePhase::Prepare as u8, &conflict);
                let sig = devnet.secret_key(i).sign(Domain::Vote, &msg);
                let forged = Vote {
                    view: seen_header.view,
                    phase: VotePhase::Prepare,
                    block_hash: conflict,
                    signature: sig,
                    attestation: None,
                    attestation_sig: None,
                };
                let mut buf = Vec::with_capacity(64);
                forged.encode(&mut buf);
                devnet
                    .transport(i)
                    .send(&p2p::MeshNetwork::peer_id(leader_idx), &buf)
                    .expect("mesh send");
                send_vote(devnet, i, leader_idx, seen_header, &proposal);
            }
            _ => send_vote(devnet, i, leader_idx, seen_header, &proposal),
        }
    }

    // Leader drains its queue tolerantly: malformed bytes are dropped
    // (spam), decode-able votes go to `collect_vote`, which may reject
    // them (conflict/stale/forged) — all counted, none panic.
    let mut leader_transport = devnet.transport(leader_idx);
    while let Some(msg) = leader_transport.recv() {
        let mut reader = codec::Reader::new(&msg.bytes);
        match Vote::decode(&mut reader) {
            Ok(vote) => {
                let voter =
                    u16::try_from(p2p::MeshNetwork::parse_peer_id(&msg.from).unwrap_or(usize::MAX))
                        .unwrap_or(u16::MAX);
                match devnet.engines_mut()[leader_idx].collect_vote(voter, vote) {
                    Ok(()) => {}
                    Err(ConsensusError::ConflictingVote { .. }) => {
                        report.conflicting_votes += 1;
                    }
                    Err(_) => report.votes_rejected += 1,
                }
            }
            Err(_) => report.malformed_dropped += 1,
        }
    }

    let Some(qc) = devnet.engines_mut()[leader_idx].try_form_qc() else {
        // Split vote / withheld votes: no quorum this view — the
        // timeout path forms a TC so the next leader carries
        // successor evidence (and locked voters can re-vote).
        timeout_all(devnet);
        return;
    };

    // QC broadcast — a spamming leader sends garbage instead, which
    // followers drop at decode.
    let mut qc_buf = Vec::new();
    qc.encode(&mut qc_buf);
    let leader_spams = matches!(leader_strat, Some(ByzantineStrategy::Spam { .. }));
    for i in 0..n {
        if i == leader_idx {
            continue;
        }
        let payload: &[u8] = if leader_spams { &[0xBA, 0xAD, 0xF0, 0x0D] } else { &qc_buf };
        devnet
            .transport(leader_idx)
            .send(&p2p::MeshNetwork::peer_id(i), payload)
            .expect("mesh send");
    }
    // Transport handles are grabbed before the mutable engine borrow:
    // `MeshTransport` is a handle into the shared mesh, so collecting
    // them upfront avoids interleaved borrows of `devnet`.
    let mut transports: Vec<p2p::MeshTransport> = (0..n).map(|i| devnet.transport(i)).collect();
    for (i, engine) in devnet.engines_mut().iter_mut().enumerate() {
        if i == leader_idx {
            if engine.deliver_qc(qc.clone()).is_err() {
                report.votes_rejected += 1;
            }
            continue;
        }
        while let Some(msg) = transports[i].recv() {
            let mut reader = codec::Reader::new(&msg.bytes);
            match types::QuorumCertificate::decode(&mut reader) {
                Ok(received) => {
                    if engine.deliver_qc(received).is_err() {
                        report.votes_rejected += 1;
                    }
                }
                Err(_) => report.malformed_dropped += 1,
            }
        }
    }
    advance_all(devnet);
}

/// Follower `i` computes its real engine vote on `header`/`proposal`
/// and sends it to `leader_idx` through the mesh.
fn send_vote(
    devnet: &mut MultiNodeDevnet,
    i: usize,
    leader_idx: usize,
    header: &types::BlockHeader,
    proposal: &types::Proposal,
) {
    if let Some(vote) = devnet.engines_mut()[i].vote(header, proposal) {
        let mut buf = Vec::with_capacity(64);
        vote.encode(&mut buf);
        devnet.transport(i).send(&p2p::MeshNetwork::peer_id(leader_idx), &buf).expect("mesh send");
    }
}

/// Advance every engine's view and re-sync heights — the harness's
/// model of a completed view (with or without a QC).
/// Happy-path advance: every engine moves to the next view after a
/// QC (no timeout evidence — the view succeeded).
fn advance_all(devnet: &mut MultiNodeDevnet) {
    for engine in devnet.engines_mut() {
        engine.advance_view();
    }
    let max_height = devnet.engines().iter().map(OxideBft::next_height_value).max().unwrap_or(0);
    for engine in devnet.engines_mut() {
        engine.sync_next_height(max_height);
    }
}

/// Timeout-path advance: every engine emits its real timeout
/// signature, all engines collect a quorum of them into a TC, and
/// each records the TC as the view-change evidence (engines set
/// `last_tc` inside `collect_timeout_signature`). The next proposal
/// then embeds the TC (legitimate-successor rule), which is what
/// lets voters release same-height vote locks left over from the
/// timed-out view — without TC evidence, a split view wedges
/// forever.
fn timeout_all(devnet: &mut MultiNodeDevnet) {
    let n = devnet.engines().len();
    let sigs: Vec<crypto::bls::Signature> = (0..n)
        .map(|i| devnet.engines_mut()[i].on_timeout().unwrap_or(crypto::bls::Signature::ZERO))
        .collect();
    for collector in 0..n {
        for (signer, sig) in sigs.iter().enumerate() {
            let _ = devnet.engines_mut()[collector]
                .collect_timeout_signature(u16::try_from(signer).unwrap_or(0), *sig);
        }
    }
    let max_height = devnet.engines().iter().map(OxideBft::next_height_value).max().unwrap_or(0);
    for engine in devnet.engines_mut() {
        engine.sync_next_height(max_height);
    }
}

/// Whether `tx`'s sender is in the censor set. Sender is bytes 0..20
/// of the envelope (module-tx layout: sender | nonce | fee | module).
fn tx_is_censored(tx: &TxBytes, censored: &HashSet<[u8; 20]>) -> bool {
    let bytes = &tx.0;
    if bytes.len() < 20 {
        return false;
    }
    let mut sender = [0u8; 20];
    sender.copy_from_slice(&bytes[..20]);
    censored.contains(&sender)
}

/// A deterministic signed staking-delegate tx: devnet identity 0
/// (genesis-funded — `devnet::txs::identity_addr(0)`), nonce derived
/// from `(round, t)`, 1 unit delegated to validator 0.
fn make_tx(round: usize, t: usize) -> TxBytes {
    let nonce = u64::try_from(round.saturating_mul(1000).saturating_add(t)).unwrap_or(u64::MAX - 1);
    let fee = 100u64;
    let payload = staking::msg::delegate(devnet::txs::identity_addr(0), 1);
    devnet::txs::signed_tx(0, nonce, fee, framework::module_id::STAKING, &payload)
}
