//! Junk-proposal flood resilience — a Byzantine committee member
//! cannot stall honest validators' consensus thread.
//!
//! Six real `oxide-devnet` processes run as validators 0..5 of a
//! seven-member committee (f=2, quorum=5). The seventh member never
//! starts a node — instead this test drives a bare `TcpTransport`
//! authenticated with member 6's real BLS key, so every junk frame
//! arrives through the *legitimate* signed greeting: the flood is
//! authenticated-Byzantine, the worst case the intake gate must
//! survive. Member 6's absent leader turns cost one view timeout
//! each — a pre-existing liveness cost of a phantom member, present
//! with or without the flood.
//!
//! Three junk classes are sent:
//!
//! 1. **Wrong-proposer** headers — dropped by the cheap intake gate
//!    before any signature work.
//! 2. **Leader-claimed, badly-signed** headers across many views —
//!    each survives the gate, pays exactly one BLS verify inside
//!    `vote()`, and is memoised so redelivery is free.
//! 3. **Mass repeats** of one junk header — the pump dedupes by
//!    `(view, proposer)`, so hundreds of copies cost one verify.
//!
//! The assertion is the audit's acceptance gate: under the flood,
//! honest commit progress must not stall — every live node keeps
//! advancing its finalized height.
//!
//! # Running
//!
//! ```sh
//! cargo build -p oxide-devnet && \
//!   cargo test -p devnet --test proposal_flood -- --ignored --nocapture
//! ```

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use codec::Encode;
use ports::transport::Transport;

/// Wire tag for `MSG_PROPOSAL` — duplicated from the devnet binary's
/// pump contract (`bin/oxide-devnet/src/main.rs`); the frame is
/// `[tag][header.encode][proposal.encode]` decoded sequentially.
const MSG_PROPOSAL: u8 = 0x00;

/// Committee size: nodes 0..6 run real binaries; member 6 is the
/// phantom this test impersonates over its own authenticated socket.
/// Seven members → f=2, quorum=5: the six live nodes form a
/// super-majority even with the phantom Byzantine-or-absent.
const NUM_NODES: usize = 7;
/// Nodes actually spawned (0..LIVE); the rest are the attacker's
/// phantom slots.
const LIVE_NODES: usize = 6;

/// Locate the `oxide-devnet` binary next to the test executable
/// (`target/debug/deps/<test>` → `target/debug/oxide-devnet`).
fn devnet_binary() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let deps = exe.parent().expect("deps dir");
    for cand in [deps.join("oxide-devnet"), deps.join("../oxide-devnet")] {
        if cand.exists() {
            return cand;
        }
    }
    panic!("oxide-devnet binary not found — run `cargo build -p oxide-devnet` first");
}

/// Spawn one devnet node; returns the child plus a shared counter
/// tracking the highest finalized height it has printed.
fn spawn_node(index: usize, base_port: u16, rpc_port: u16) -> (Child, Arc<AtomicU64>) {
    let mut child = Command::new(devnet_binary())
        .arg("--node")
        .arg(index.to_string())
        .arg("--num-nodes")
        .arg(NUM_NODES.to_string())
        .arg("--base-port")
        .arg(base_port.to_string())
        .arg("--rpc-listen")
        .arg(format!("127.0.0.1:{rpc_port}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Node diagnostics (view timeouts, divergence) flow to the
        // test's stderr — visible under `--nocapture`.
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn node {index}: {e}"));
    let height = Arc::new(AtomicU64::new(0));
    let height_writer = Arc::clone(&height);
    let stdout = child.stdout.take().expect("stdout piped");
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Some(pos) = line.find("finalized height = ") {
                let rest = &line[pos + "finalized height = ".len()..];
                if let Ok(h) = rest.trim().parse::<u64>() {
                    height_writer.fetch_max(h, Ordering::Relaxed);
                }
            }
        }
    });
    (child, height)
}

/// Build the same validator set the `--num-nodes` deterministic
/// fallback derives inside the binary: `bls_key(i + 1)` public keys,
/// unit stakes, key-derived test addresses.
fn devnet_committee() -> consensus::ValidatorSet {
    let pks: Vec<crypto::bls::PublicKey> = (1..=NUM_NODES)
        .map(|i| node::cli::bls_key(u8::try_from(i).unwrap_or(0)).public_key())
        .collect();
    let addresses: Vec<primitives::Address> = (0..NUM_NODES)
        .map(|i| {
            crypto::secp::test_identity_address(u8::try_from(i).unwrap_or(0))
                .expect("devnet identity is a valid key")
        })
        .collect();
    consensus::ValidatorSet::with_addresses(pks, vec![1u64; NUM_NODES], addresses)
        .expect("committee")
}

/// A junk proposal frame for `view`. With `claim_leader` the header
/// claims the scheduled leader's proposer hash (signed by a
/// non-committee key — passes the cheap gate, fails the BLS verify);
/// without it the claim is garbage and the gate drops it for free.
/// `salt` perturbs the timestamp so every frame hashes distinctly —
/// a flood of *distinct* admissible junk is the audit's worst case:
/// without the per-sender budget each frame pays a BLS verify.
fn junk_proposal_frame(
    set: &consensus::ValidatorSet,
    view: u64,
    claim_leader: bool,
    salt: u64,
) -> Vec<u8> {
    let proposer = if claim_leader {
        consensus::proposer_hash(set.leader(primitives::View::new(view)))
    } else {
        primitives::Hash([0xEE; 32])
    };
    let mut header = types::BlockHeader {
        height: primitives::Height::new(view),
        view: primitives::View::new(view),
        epoch: primitives::Epoch::new(0),
        prev_block: primitives::Hash::ZERO,
        tx_root: primitives::Hash::ZERO,
        high_qc: None,
        timeout_cert: None,
        proposer,
        timestamp: salt,
        proposer_signature: None,
        exec_cert: None,
        body_commitment: primitives::Hash::ZERO,
    };
    // Signed by key 9 — not a committee member. Well-formed, real
    // signing-hash coverage: the rejection lands inside BLS
    // verification, the most expensive check on the path.
    let signing_hash = consensus::OxideBft::proposal_signing_hash(&header);
    header.proposer_signature =
        Some(node::cli::bls_key(9).sign(crypto::hash::Domain::Proposal, signing_hash.as_bytes()));
    let proposal =
        types::Proposal { height: primitives::Height::new(view), txs: vec![], attestation: None };
    let mut frame = Vec::with_capacity(512);
    frame.push(MSG_PROPOSAL);
    header.encode(&mut frame);
    proposal.encode(&mut frame);
    frame
}

/// The audit's acceptance gate: under an authenticated junk-proposal
/// flood, honest commit progress must not stall.
#[test]
#[ignore = "process-level e2e — spawns real binaries; run explicitly"]
fn junk_proposal_flood_keeps_committing() {
    let base_port: u16 = 24_700;
    let set = devnet_committee();

    // Six honest nodes; committee member 6 is the attacker phantom.
    let mut children = Vec::new();
    let mut heights = Vec::new();
    for i in 0..LIVE_NODES {
        let (child, h) = spawn_node(i, base_port, 31_000 + u16::try_from(i).unwrap_or(0));
        children.push(child);
        heights.push(h);
    }
    let _guard = scopeguard(children);
    std::thread::sleep(Duration::from_secs(4));

    // The attacker's authenticated transport: peer id = member 6's
    // staking address, signed with member 6's real BLS key. It
    // passes the signed greeting — the test measures the
    // *consensus* intake path, not the handshake.
    let attacker_auth: Arc<dyn p2p::tcp::PeerAuth> = Arc::new(node::peer_auth::BlsPeerAuth::new(
        node::cli::bls_key(7),
        Arc::new(std::sync::RwLock::new(set.clone())),
        Arc::new(std::sync::RwLock::new(None)),
    ));
    // Peer ids are staking addresses — member `i` is
    // `test_identity_address(i)`, matching the binary's derivation.
    let member_id = |i: usize| -> Vec<u8> {
        crypto::secp::test_identity_address(u8::try_from(i).unwrap_or(0))
            .expect("devnet identity")
            .0
            .to_vec()
    };
    let peers: Vec<(Vec<u8>, String)> = (0..LIVE_NODES)
        .map(|i| (member_id(i), format!("127.0.0.1:{}", base_port + u16::try_from(i).unwrap_or(0))))
        .collect();
    let mut transport = p2p::tcp::TcpTransport::with_config(
        "127.0.0.1:0",
        member_id(6),
        peers,
        p2p::tcp::TcpTransportConfig { peer_auth: Some(attacker_auth), ..Default::default() },
    );

    // Wait for the signed handshake to install the member-6 slots.
    let first = member_id(0);
    let probe = junk_proposal_frame(&set, 1, true, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while transport.send(&first, &probe).is_err() {
        assert!(Instant::now() < deadline, "authenticated dial never installed");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Baseline right before the flood starts.
    let baseline: Vec<u64> = heights.iter().map(|h| h.load(Ordering::Relaxed)).collect();

    // ── The flood ────────────────────────────────────────────────
    // The audit gate is 10^4 junk proposals per second. Frames are
    // *distinct* (salted timestamps) so every admissible one would
    // cost a BLS verify without the per-sender budget — this is the
    // worst case, not the repeat-flood the dedupe trivially kills.
    //  (a) leader-claimed junk on in-window-ish views — admissible,
    //      rate-limited at the verify step;
    //  (b) far-future leader claims — dropped at the window check;
    //  (c) wrong-proposer junk — dropped at the free compare;
    //  (d) the identical repeat every round — the dedupe case.
    let flood_start = Instant::now();
    let mut frames_sent: u64 = 0;
    for round in 0..2_000u64 {
        let view = round % 80;
        for peer in 0..LIVE_NODES {
            let pid = member_id(peer);
            let _ = transport.send(&pid, &junk_proposal_frame(&set, view, true, round));
            let _ = transport.send(&pid, &junk_proposal_frame(&set, 500 + view, true, round));
            let _ = transport.send(&pid, &junk_proposal_frame(&set, view, false, round));
            frames_sent += 3;
        }
        let _ = transport.send(&first, &probe);
        frames_sent += 1;
        // Give the honest loop air between bursts — the point is
        // sustained pressure, not one socket-buffer cliff.
        if round % 25 == 24 {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let flood_elapsed = flood_start.elapsed();
    eprintln!(
        "flood sent {frames_sent} frames in {flood_elapsed:.1?} (~{} fps)",
        frames_sent / flood_elapsed.as_secs().max(1)
    );

    // Honest progress during and after the flood: every node must
    // advance at least 2 further heights within a generous deadline
    // (idle heartbeat cadence is ~1 Hz minus the phantom leader's
    // timeout views; the gate leaves the pump free for real work).
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let advanced =
            heights.iter().zip(&baseline).all(|(h, b)| h.load(Ordering::Relaxed) >= b + 2);
        if advanced {
            break;
        }
        assert!(Instant::now() < deadline, "flood stalled finalization: {heights:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!(
        "flood complete — finalized heights now {:?} (baseline {baseline:?})",
        heights.iter().map(|h| h.load(Ordering::Relaxed)).collect::<Vec<_>>()
    );
}

/// Kill-on-drop guard for the spawned node processes.
struct ScopeGuard(Vec<Child>);
fn scopeguard(children: Vec<Child>) -> ScopeGuard {
    ScopeGuard(children)
}
impl Drop for ScopeGuard {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
