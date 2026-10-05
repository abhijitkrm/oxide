//! `follower` — the certified-block consumer: a **non-signing**
//! replica that mirrors committed chain state from validator peers.
//!
//! # What this is
//!
//! A full node that never participates in consensus: no seat, no
//! signer, no votes, no proposals. It dials the committee's
//! authenticated transport like a member (proving an
//! operator-registered *observer* key — see
//! [`crate::peer_auth::BlsPeerAuth::with_observers`]), pulls
//! [`types::CertifiedBlock`] records through the same
//! `MSG_BLOCK_REQ`/`MSG_BLOCK_RESP` protocol validators use for
//! catch-up, and finalizes each one through
//! [`consensus::OxideBft::apply_certified_block`] — the single
//! verification authority, so a follower's trust in a record is
//! exactly a validator's: certified pair, body binding, proposer
//! signature, both QC aggregates against the live committee.
//!
//! Because it runs the real engine in consume-only mode, the
//! follower also gets the safety machinery for free: the
//! divergence latch (`confirm_exec_cert` on every certified
//! record's embedded attestation certificate — verification plus
//! the local-root comparison the vote path applies), WAL
//! persistence of the committed tip, epoch rotations via
//! `drive_epoch_changes`, and certified-snapshot repair
//! (`--repair-peer`).
//!
//! # What it deliberately does not do
//!
//! - **Sign.** The engine is built without `.with_signer()`; no
//!   code path in this module calls `propose`/`vote`/`timeout`. A
//!   follower that somehow emitted a signature would be a bug in
//!   this file, not a capability of the engine.
//! - **Gossip consensus messages.** Proposals and QCs it receives
//!   are used purely as tip signals (an authenticated leader
//!   proposal at height `h` proves committed history below it
//!   exists — fetch it). It never re-broadcasts them.
//! - **Serve unverified state.** Every read the RPC layer answers
//!   came from a block whose Jolteon commit proof verified against
//!   the checkpointed committee. `MSG_BLOCK_REQ` IS served, though —
//!   verified records re-serve to other followers for free.
//!
//! # Trust model (weak subjectivity)
//!
//! `FollowerSpec::validator_set` + `epoch` are the operator's
//! trusted checkpoint — the same anchor `--state-sync` uses. All
//! cryptographic verification chains from it: a peer can lie about
//! heights, floors, or record bytes, but cannot forge the quorum
//! signatures `apply_certified_block` checks. A record under a
//! different epoch is rejected (`SyncEpoch`) — crossing a rotation
//! boundary requires either in-window `drive_epoch_changes`
//! convergence (the follower executes the same rotation blocks, so
//! it stages the same next set) or a fresh checkpoint.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use codec::Decode;
use ports::ConsensusEngine;
use ports::transport::Transport;
use types::TxBytes;

use crate::validator_net::{
    GOSSIP_SEEN_CAP, GenesisAlloc, MSG_BLOCK_REQ, MSG_BLOCK_RESP, MSG_PROPOSAL, MSG_QC, MSG_TX,
    SYNC_PENDING_CAP, SYNC_REQ_RETRY, TlsSpec, attempt_state_repair, build_transport,
    drain_sync_buffer, start_rpc,
};

/// Poll interval for the follower's tip reconciliation (unit:
/// wall-clock). Validators only fetch when a proposal reveals a
/// gap — a follower has no such guarantee: gossip may be silent
/// (idle chain, missed frames), and a restarted follower cannot
/// know the tip moved while it was down. An unconditional
/// `ByRange` request every `SYNC_REQ_RETRY` is the liveness floor;
/// proposal gossip refines it to sub-view latency when traffic
/// flows. Reuses `SYNC_REQ_RETRY` — the response-cost and
/// request-rate tradeoffs are identical to the validator's.
const FOLLOWER_FETCH_INTERVAL: Duration = SYNC_REQ_RETRY;

/// Everything [`run`] needs, already resolved — the same boundary
/// style as [`crate::validator_net::ValidatorNetSpec`]: binaries own
/// flag parsing, the spec carries runtime facts.
pub struct FollowerSpec {
    /// Log prefix on every line this node prints — `oxide-fullnode`.
    pub log_tag: String,
    /// The committee this follower trusts — the weak-subjectivity
    /// checkpoint (`--trusted-validators` or the genesis set). All
    /// record verification resolves signatures against it.
    pub validator_set: consensus::ValidatorSet,
    /// The epoch the checkpoint names. `apply_certified_block`
    /// rejects records signed under any other committee, so the
    /// engine must start at the checkpoint's epoch — not always 0.
    pub epoch: primitives::Epoch,
    /// This follower's peer id: the 20-byte observer identity the
    /// validators' `--observer-peer` allowlist names. Unlike a
    /// validator's id it is NOT committee-derived — the operator
    /// picks it (or the binary derives it from the observer key).
    pub own_id: Vec<u8>,
    /// The observer's handshake signer — proves possession of the
    /// registered key over the `Domain::PeerHandshake` transcript.
    /// This key has no consensus role and signs nothing else.
    pub signer: Arc<dyn crypto::ConsensusSigner>,
    /// The resolved node config — executor graph, genesis, chain
    /// id, block budget, pacemaker timeouts.
    pub node_config: crate::NodeConfig,
    /// Consensus WAL path — persists the committed tip (and the
    /// divergence latch) across restarts so sync resumes at the
    /// frontier instead of genesis.
    pub wal_path: Option<PathBuf>,
    /// TCP listen address. Peers never dial a follower (it is not
    /// in their peer lists) but the transport requires a bound
    /// socket — `127.0.0.1:0` is a valid default.
    pub listen_addr: String,
    /// Validator endpoints to follow: `(peer_id, host:port)` where
    /// `peer_id` is the member's staking-address bytes — the same
    /// format `ValidatorNetSpec::peers` carries. Must be non-empty:
    /// a follower with no upstream mirrors nothing.
    pub peers: Vec<(Vec<u8>, String)>,
    /// mTLS material; `None` runs plaintext TCP (devnet posture —
    /// production fleets run `with_tls_and_admission` and the
    /// follower's cert must be in each validator's trusted set).
    pub tls: Option<TlsSpec>,
    /// `[network]` transport tunables — timeouts, frame bound.
    pub network: config::NetworkConfig,
    /// Genesis `evm.alloc` application hook, run only on a fresh
    /// start — same rule as validators: a restart must not rewind
    /// balances the chain moved.
    pub genesis_alloc: Option<GenesisAlloc>,
    /// Data directory for executor durability (block journal +
    /// checkpoint), the certified-record journal (`SyncStore`), and
    /// the shutdown snapshot export. `None` = in-memory only.
    pub data_dir: Option<PathBuf>,
    /// Resolved RPC listen address (`None` = no RPC server).
    pub rpc_listen: Option<String>,
    /// `[rpc]` config — chain id, base fee, debug API.
    pub rpc_config: config::RpcConfig,
    /// Peer RPC endpoints (`host:port`) for certified state repair
    /// after an execution-divergence halt — same semantics as
    /// [`crate::validator_net::ValidatorNetSpec::repair_peers`]. For
    /// a follower, convergence is the *whole product*: repairing a
    /// diverged mirror automatically is worth more, not less, than
    /// on a validator. Empty disables auto-repair.
    pub repair_peers: Vec<String>,
    /// Shutdown flag — the binary installs signal handling.
    pub shutdown: Arc<AtomicBool>,
}

/// Run a certified-block follower until `spec.shutdown` is set.
///
/// Assembles the executor + a signer-less engine, joins the
/// authenticated transport as an observer, then reconciles
/// committed history forever: poll `ByRange` at the verified
/// frontier, apply every record through `apply_certified_block`,
/// buffer and drain out-of-order pages, mirror finalized height and
/// divergence into RPC, follow epoch rotations, and repair
/// divergence via certified snapshots when `repair_peers` is set.
/// On shutdown, flushes the certified journal and exports
/// `<data_dir>/snapshot.bin`.
///
/// # Panics
///
/// Panics on unrecoverable startup failures — empty peer list,
/// transport bind, WAL open/recovery — and on snapshot export
/// failure during shutdown.
#[allow(clippy::too_many_lines)]
pub fn run(spec: FollowerSpec) {
    let FollowerSpec {
        log_tag,
        validator_set,
        epoch,
        own_id,
        signer,
        node_config,
        wal_path,
        listen_addr,
        peers,
        tls,
        network,
        genesis_alloc,
        data_dir,
        rpc_listen,
        rpc_config,
        repair_peers,
        shutdown,
    } = spec;

    assert!(
        !peers.is_empty(),
        "{log_tag}: follower needs at least one --consensus-peer — \
         a mirror with no upstream follows nothing"
    );
    assert_eq!(own_id.len(), 20, "{log_tag}: follower peer id must be a 20-byte address");

    println!(
        "{log_tag}: follower mode — {} upstream peers, committee {} @ epoch {}, \
         never signing",
        peers.len(),
        validator_set.n(),
        epoch.value()
    );

    // ── Assembly ──────────────────────────────────────────
    // The shared production path: same executor graph, same module
    // wiring, same durable recovery as `assemble_devnet_node` — the
    // only differences are engine construction (no signer, seat 0
    // is inert) and the membership gate (a follower is deliberately
    // not a member).
    let crate::AssembledExecutor {
        app,
        evm_module,
        staking_module: _,
        exchange_module: _,
        recovery,
        chain_params,
    } = crate::assemble_executor(&node_config);
    let app_dyn: Arc<dyn ports::AppInterface> = app.clone();

    let mut engine = consensus::OxideBft::with_index(app_dyn, validator_set.clone(), 0)
        .with_epoch(epoch)
        // Configured timeouts/budget — identical wiring to
        // `assemble_devnet_node` so a `[consensus]` TOML change
        // reaches followers too.
        .with_pacemaker_timeouts(node_config.base_timeout_ms, node_config.max_timeout_ms)
        .with_block_budget(node_config.block_budget)
        // Mandatory on a consume-only engine too: the commit path
        // stamps `BlockContext.gas_limit` from the live budget, and
        // a governed `chain.block_gas_limit` apply must land here at
        // the same height it lands on validators — a follower
        // stamping the static config past that height would diverge.
        .with_chain_params(chain_params);
    // No `.with_signer()` — this engine must never produce a
    // signature. Every signing path (`propose`, `vote`, timeout)
    // is unreachable from this pump by construction.

    let wal_path = wal_path.or_else(|| node_config.wal_path.clone());
    if let Some(ref wal_path) = wal_path {
        if let Some(parent) = wal_path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("{log_tag}: cannot create WAL dir: {e}"));
        }
        let wal = consensus::wal::Wal::open(wal_path)
            .unwrap_or_else(|e| panic!("{log_tag}: cannot open consensus WAL: {e}"));
        engine = engine.with_wal(wal);
        engine
            .recover_from_wal()
            .unwrap_or_else(|e| panic!("{log_tag}: consensus WAL recovery failed: {e}"));
        println!("{log_tag}: WAL loaded from {}", wal_path.display());
    }

    // `evm.alloc` is genesis state — fresh start only, same rule as
    // validators: a restart must not rewind balances the chain moved.
    let fresh_start =
        recovery.as_ref().is_none_or(|r| r.snapshot_height.is_none() && r.blocks_replayed == 0);
    if fresh_start && let Some(apply) = genesis_alloc {
        apply(&evm_module);
    }

    // The devnet auto-persistence convention: `<data_dir>/snapshot.bin`
    // resumes full chain state before any fetch. Reuses the shared
    // helpers — a corrupt snapshot fails loudly rather than booting
    // from genesis.
    if let Some(ref dir) = data_dir
        && let Ok(Some(height)) = crate::devnet::import_snapshot_if_present(&app, dir)
    {
        println!("{log_tag}: imported snapshot at height {height} from {}", dir.display());
    }

    // Shared validator sets: the follower's OUTBOUND handshakes
    // verify the dialled member's proof against this live committee
    // — a rotation the engine converges through `drive_epoch_changes`
    // must be published here or the next re-handshake fails.
    let shared_validator_set = Arc::new(RwLock::new(validator_set.clone()));
    let shared_next_validator_set = Arc::new(RwLock::new(Option::<consensus::ValidatorSet>::None));

    // Transport: same production composition as validators — TLS
    // when configured, admission control always, `BlsPeerAuth`
    // proving our observer key. `observers` stays empty: nobody
    // dials a follower.
    let mut transport = build_transport(
        &listen_addr,
        &log_tag,
        own_id,
        peers.clone(),
        tls,
        &network,
        signer,
        shared_validator_set.clone(),
        shared_next_validator_set.clone(),
        Vec::new(),
    );

    // RPC: identical surface to a validator — reads answer from
    // certified-mirrored state, and `eth_sendRawTransaction` gossips
    // into the fleet through the MSG_TX channel below, so a client
    // can submit to the follower like any node.
    let (gossip_tx, gossip_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(10_000);
    let rpc_handle = start_rpc(
        &rpc_config,
        rpc_listen,
        &app,
        &log_tag,
        shared_validator_set.clone(),
        &evm_module,
        gossip_tx,
    );

    // Certified serve store: journals committed records so this
    // follower re-serves history to OTHER followers across restarts
    // — the fetch mesh does not require every follower to pin a
    // validator.
    let mut sync_store = crate::block_sync::SyncStore::open(data_dir.as_deref());

    let mut sync_pending: BTreeMap<u64, types::CertifiedBlock> = BTreeMap::new();
    let mut sync_last_req: Option<Instant> = None;
    let mut sync_peer_cursor: usize = 0;
    let mut sync_below_floor_logged = false;
    let mut seen_txs: HashSet<primitives::Hash> = HashSet::with_capacity(4096);
    let mut seen_txs_fifo: VecDeque<primitives::Hash> = VecDeque::new();
    let mut last_epoch = engine.epoch().value();
    let mut last_reported_height: u64 = engine.finalized_height().map_or(0, primitives::Id::value);
    let mut repair_next_attempt: Option<Instant> = None;
    let mut repair_peer_cursor: usize = 0;
    let mut repair_unconfigured_logged = false;
    let mut divergence_logged = false;
    let mut all_peers_down_next_log: Option<Instant> = None;

    println!("{log_tag}: follower running — committed tip {last_reported_height}");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            println!("{log_tag}: shutdown signal received, stopping");
            break;
        }

        // ── Phase 1: drain the transport ─────────────────
        while let Some(msg) = transport.recv() {
            if msg.bytes.is_empty() {
                continue;
            }
            let mut reader = codec::Reader::new(&msg.bytes[1..]);
            match msg.bytes[0] {
                MSG_BLOCK_REQ => {
                    // Serve certified history to whoever asked —
                    // another follower bootstrapping, or a restarted
                    // validator. Verified records only; the tail
                    // (certified-but-uncommitted tip) belongs to
                    // validators that store proposals, so `tail`
                    // stays `None` here.
                    if let Some(req) = crate::block_sync::decode_request(&msg.bytes[1..]) {
                        let mut resp = crate::block_sync::FetchResponse {
                            floor: sync_store.floor().unwrap_or(u64::MAX),
                            records: Vec::new(),
                            tail: None,
                        };
                        match req {
                            crate::block_sync::FetchRequest::ByHash(hash) => {
                                if let Some(record) = sync_store.get_by_hash(&hash) {
                                    resp.records.push(record.clone());
                                }
                            }
                            crate::block_sync::FetchRequest::ByRange { from, count } => {
                                resp.records = sync_store.range(from, count);
                            }
                        }
                        let mut buf = Vec::with_capacity(16 + resp.records.len() * 600);
                        buf.push(MSG_BLOCK_RESP);
                        buf.extend_from_slice(&crate::block_sync::encode_response(&resp));
                        let _ = transport.send(&msg.from, &buf);
                    }
                }
                MSG_BLOCK_RESP => {
                    if let Some(resp) = crate::block_sync::decode_response(&msg.bytes[1..]) {
                        let need = engine.committed_anchor().map_or(0, |(_, h)| h.value() + 1);
                        if resp.floor != u64::MAX && resp.floor > need && !sync_below_floor_logged {
                            eprintln!(
                                "{log_tag}: sync gap starts at height {need} but peer's \
                                 certified store floor is {} — below the retention window; \
                                 certified state sync (--state-sync) is the recovery path",
                                resp.floor
                            );
                            sync_below_floor_logged = true;
                        }
                        for record in resp.records {
                            let h = record.header.height.value();
                            let next = engine.sync_frontier();
                            if h < next {
                                continue;
                            }
                            if h == next {
                                match engine.apply_certified_block(&record) {
                                    Ok(_) => {
                                        // Confirm the embedded exec
                                        // cert — attests `h - 1`,
                                        // which the apply just
                                        // committed/sealed. The
                                        // shared drain feeds certs
                                        // for buffered records it
                                        // commits, so both paths
                                        // run the divergence check.
                                        if let Some(ref cert) = record.header.exec_cert {
                                            engine.confirm_exec_cert(cert);
                                        }
                                        drain_sync_buffer(&mut engine, &mut sync_pending, &log_tag);
                                    }
                                    Err(consensus::ConsensusError::SyncDeferred { .. }) => {
                                        sync_pending.insert(h, record);
                                    }
                                    Err(e @ consensus::ConsensusError::SyncEpoch { .. }) => {
                                        if !sync_below_floor_logged {
                                            eprintln!(
                                                "{log_tag}: certified block {h} crosses an \
                                                 epoch boundary this follower cannot verify \
                                                 ({e}) — a fresh validator-set checkpoint is \
                                                 the recovery path"
                                            );
                                            sync_below_floor_logged = true;
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("{log_tag}: certified block {h} rejected: {e}");
                                    }
                                }
                            } else if sync_pending.len() < SYNC_PENDING_CAP {
                                sync_pending.insert(h, record);
                            }
                        }
                    }
                }
                MSG_PROPOSAL => {
                    // Tip signal only: a verified leader proposal at
                    // height h proves committed history below h
                    // exists — aim the fetcher. `admit_proposal`
                    // authenticates the leader signature first, so a
                    // forged frame cannot drive fetches. The proposal
                    // itself is never used for anything else — the
                    // follower does not vote.
                    if let (Ok(header), Ok(proposal)) = (
                        types::BlockHeader::decode(&mut reader),
                        types::Proposal::decode(&mut reader),
                    ) && engine.proposal_admissible(&header)
                        && engine.admit_proposal(&header, &proposal)
                    {
                        let need = engine.sync_frontier();
                        if header.height.value() > need
                            && sync_last_req.is_none_or(|t| t.elapsed() >= SYNC_REQ_RETRY)
                        {
                            send_range_request(&mut transport, &msg.from, need);
                            sync_last_req = Some(Instant::now());
                        }
                    }
                }
                MSG_QC => {
                    // A fresh QC is the cheapest possible tip signal —
                    // it means something just certified. The
                    // unconditional poll would catch it anyway; this
                    // just tightens latency by one cadence. Decode is
                    // intentionally skipped: an invalid QC triggers a
                    // harmless fetch, which is cheaper than paying
                    // BLS-verify costs on gossip we never use.
                    if sync_last_req.is_none_or(|t| t.elapsed() >= SYNC_REQ_RETRY / 2) {
                        send_range_request(&mut transport, &msg.from, engine.sync_frontier());
                        sync_last_req = Some(Instant::now());
                    }
                }
                MSG_TX => {
                    // Mempool mirror: ingest gossiped txs so the
                    // follower's RPC reflects pending state. Same
                    // dedupe window as validators; never re-broadcast.
                    let payload = &msg.bytes[1..];
                    let tx_hash =
                        crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, payload);
                    if seen_txs.insert(tx_hash) {
                        seen_txs_fifo.push_back(tx_hash);
                        if seen_txs_fifo.len() > GOSSIP_SEEN_CAP
                            && let Some(old) = seen_txs_fifo.pop_front()
                        {
                            seen_txs.remove(&old);
                        }
                        let _ = engine.submit_tx(TxBytes::new(payload.to_vec()));
                    }
                }
                _ => {}
            }
        }

        // ── Phase 2: committed-height report + RPC mirror ─
        // `set_block_height` runs unconditionally: a follower that
        // resumed from durable state owes RPC clients its recovered
        // tip immediately — reporting 0 until the next commit would
        // misrepresent the mirror as unsynced.
        if let Some(h) = engine.finalized_height() {
            let h_val = h.value();
            if h_val > last_reported_height {
                println!("{log_tag}: finalized height = {h_val}");
                last_reported_height = h_val;
                if let Some(rpc) = rpc_handle.as_deref() {
                    rpc.publish_new_block(h_val);
                }
            }
            if let Some(rpc) = rpc_handle.as_deref() {
                rpc.set_block_height(h_val);
            }
        }

        // ── Phase 3: divergence latch + certified repair ─
        if let (Some(rpc), Some(d)) = (rpc_handle.as_deref(), engine.divergence()) {
            rpc.set_exec_divergence(*d);
        }
        if engine.divergence().is_some() && !divergence_logged {
            eprintln!(
                "{log_tag}: execution divergence latched — mirrored state is \
                 untrusted until a certified repair clears it"
            );
            divergence_logged = true;
        }
        if let Some(divergence) = engine.divergence().copied()
            && repair_next_attempt.is_none_or(|t| Instant::now() >= t)
        {
            match engine.mark_repaired() {
                consensus::RepairOutcome::Repaired(h) => {
                    println!("{log_tag}: divergence cleared at height {}", h.value());
                    if let Some(rpc) = rpc_handle.as_deref() {
                        rpc.clear_exec_divergence();
                    }
                }
                consensus::RepairOutcome::NotLatched => {}
                consensus::RepairOutcome::NoAnchor => {
                    if repair_peers.is_empty() {
                        if !repair_unconfigured_logged {
                            eprintln!(
                                "{log_tag}: divergence latched and no --repair-peer configured — \
                                 mirror stays halted; manual certified-state repair applies"
                            );
                            repair_unconfigured_logged = true;
                        }
                    } else {
                        attempt_state_repair(
                            &repair_peers,
                            &mut repair_peer_cursor,
                            divergence,
                            &mut engine,
                            &app,
                            &log_tag,
                        );
                        if let consensus::RepairOutcome::Repaired(h) = engine.mark_repaired() {
                            println!(
                                "{log_tag}: divergence cleared at height {} after certified \
                                 state repair",
                                h.value()
                            );
                            if let Some(rpc) = rpc_handle.as_deref() {
                                rpc.clear_exec_divergence();
                            }
                        }
                    }
                    repair_next_attempt =
                        Some(Instant::now() + crate::validator_net::REPAIR_RETRY_INTERVAL);
                }
            }
        }

        // Mirror execution certificates into RPC — the follower
        // answers `/snapshot/cert/{h}` for downstream state-sync
        // clients exactly like a validator does.
        if let Some(rpc) = rpc_handle.as_deref() {
            rpc.record_exec_certificates(engine.exec_certificates());
        }

        // ── Phase 4: journal committed records ────────────
        for record in engine.take_certified() {
            sync_store.insert(record);
        }

        // ── Phase 5: the fetch ─────────────────────────────
        // Unconditional ByRange at the verified frontier — the
        // follower's liveness floor. Proposal/QC gossip refines the
        // trigger above; this guarantees convergence even when
        // gossip is silent or frames were lost. Round-robin across
        // configured peers so no single validator bears the load.
        if sync_last_req.is_none_or(|t| t.elapsed() >= FOLLOWER_FETCH_INTERVAL) {
            let frontier = engine.sync_frontier();
            let mut sent = false;
            for _ in 0..peers.len() {
                let peer_id = &peers[sync_peer_cursor % peers.len()].0;
                sync_peer_cursor = sync_peer_cursor.wrapping_add(1);
                if send_range_request(&mut transport, peer_id, frontier) {
                    sent = true;
                    break;
                }
            }
            if sent {
                sync_last_req = Some(Instant::now());
            } else if all_peers_down_next_log.is_none_or(|t| Instant::now() >= t) {
                // Every configured upstream failed `send` — the
                // handshake has not completed on ANY connection
                // (or all are down). Without this line a follower
                // that cannot reach the committee sits silent while
                // mirroring nothing; once connected, fetches land
                // and this stays quiet. Rate-bounded to the fetch
                // cadence.
                eprintln!(
                    "{log_tag}: no upstream peer reachable — \
                     certified fetch from height {frontier} cannot be sent; \
                     retrying every {FOLLOWER_FETCH_INTERVAL:?}"
                );
                all_peers_down_next_log = Some(Instant::now() + FOLLOWER_FETCH_INTERVAL);
            }
        }

        // ── Phase 6: epoch lifecycle ──────────────────────
        // The follower executes the same finalized blocks, so it
        // stages the same rotation deltas and activates at the same
        // certified boundary. Publishing the rotated set keeps its
        // own handshake verifier able to re-authenticate members
        // after a reconnect.
        match engine.drive_epoch_changes() {
            Ok(0) => {}
            Ok(applied) => {
                eprintln!(
                    "{log_tag}: epoch rotation scheduled ({applied} validator-set change(s)) \
                     — activates at committed height {:?}",
                    engine.rotation_activation_height()
                );
            }
            Err(e) => {
                eprintln!("{log_tag}: epoch transition rejected: {e}");
            }
        }
        if engine.epoch().value() != last_epoch {
            last_epoch = engine.epoch().value();
            if let Ok(mut shared) = shared_validator_set.write() {
                *shared = engine.validator_set().clone();
            }
        }
        if let Ok(mut pending) = shared_next_validator_set.write() {
            let staged = engine.next_validator_set().cloned();
            if *pending != staged {
                *pending = staged;
            }
        }

        // ── Phase 7: RPC-submitted txs → gossip ───────────
        // A client that submits to the follower expects the tx to
        // reach the fleet — fan it out to every upstream peer.
        while let Ok(raw) = gossip_rx.try_recv() {
            let mut buf = Vec::with_capacity(raw.len() + 1);
            buf.push(MSG_TX);
            buf.extend_from_slice(&raw);
            for (peer_id, _) in &peers {
                let _ = transport.send(peer_id, &buf);
            }
        }

        std::thread::sleep(Duration::from_millis(1));
    }

    sync_store.flush();
    if let Some(ref dir) = data_dir {
        let height =
            crate::devnet::export_snapshot(&app, dir).unwrap_or_else(|e| panic!("{log_tag}: {e}"));
        println!(
            "{log_tag}: exported snapshot to {} (height {height})",
            dir.join("snapshot.bin").display(),
        );
    }
    println!("{log_tag}: shutdown complete");
}

/// Send one `ByRange` fetch request. Returns `true` when the send
/// landed — the caller uses it for throttle bookkeeping (a failed
/// send to an unconnected peer must not consume the cadence).
fn send_range_request(transport: &mut p2p::tcp::TcpTransport, peer_id: &[u8], from: u64) -> bool {
    let mut buf = Vec::with_capacity(16);
    buf.push(MSG_BLOCK_REQ);
    buf.extend_from_slice(&crate::block_sync::encode_request(
        &crate::block_sync::FetchRequest::ByRange { from, count: crate::block_sync::SYNC_PAGE_CAP },
    ));
    transport.send(peer_id, &buf).is_ok()
}

#[cfg(test)]
mod tests {
    //! In-process fleet tests: real `validator_net` validators plus a
    //! `follower` on loopback TCP — the same wire path production
    //! runs, minus TLS (covered by the p2p suite's gate test).
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    /// One POST to a JSON-RPC endpoint returning a hex `result`
    /// (`eth_blockNumber`, `eth_getBlockTransactionCountByNumber`) —
    /// the honest external probe: what a real client would read.
    fn rpc_hex(addr: &str, body: &str) -> Option<u64> {
        let mut stream = TcpStream::connect(addr).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        write!(
            stream,
            "POST / HTTP/1.0\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).ok()?;
        let text = String::from_utf8_lossy(&raw);
        // `"result":"0x..."` — hex value or null.
        let marker = text.find("\"result\":")? + "\"result\":".len();
        let rest = &text[marker..];
        let start = rest.find('"')? + 1;
        let end = start + rest[start..].find('"')?;
        u64::from_str_radix(rest[start..end].trim_start_matches("0x"), 16).ok()
    }

    /// `eth_blockNumber` probe.
    fn rpc_block_number(addr: &str) -> Option<u64> {
        rpc_hex(addr, r#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#)
    }

    /// `eth_getBlockTransactionCountByNumber` probe — how many
    /// transactions the committed block at `height` carried.
    fn rpc_block_tx_count(addr: &str, height: u64) -> Option<u64> {
        rpc_hex(
            addr,
            &format!(
                r#"{{"jsonrpc":"2.0","method":"eth_getBlockTransactionCountByNumber","params":["0x{height:x}"],"id":1}}"#
            ),
        )
    }

    /// `eth_getBalance` probe on the sink account — u128 result.
    fn rpc_balance(addr: &str, account: &str) -> Option<u128> {
        let mut stream = TcpStream::connect(addr).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        let body = format!(
            r#"{{"jsonrpc":"2.0","method":"eth_getBalance","params":["{account}","latest"],"id":1}}"#
        );
        write!(
            stream,
            "POST / HTTP/1.0\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .ok()?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).ok()?;
        let text = String::from_utf8_lossy(&raw);
        let marker = text.find("\"result\":")? + "\"result\":".len();
        let rest = &text[marker..];
        let start = rest.find('"')? + 1;
        let end = start + rest[start..].find('"')?;
        u128::from_str_radix(rest[start..end].trim_start_matches("0x"), 16).ok()
    }

    /// The devnet committee convention: validator `i` ↔ `bls_key(i+1)`
    /// ↔ `test_identity_address(i)` — identical to `peer_auth` tests
    /// and `oxide-devnet`.
    fn devnet_committee(n: usize) -> (Vec<crypto::BlsSecretKey>, consensus::ValidatorSet) {
        let secrets: Vec<crypto::BlsSecretKey> =
            (1u8..=u8::try_from(n).unwrap()).map(crate::cli::bls_key).collect();
        let pks: Vec<crypto::PublicKey> =
            secrets.iter().map(crypto::BlsSecretKey::public_key).collect();
        let addresses: Vec<primitives::Address> = (0u8..u8::try_from(n).unwrap())
            .map(|i| crypto::secp::test_identity_address(i).unwrap())
            .collect();
        let set = consensus::ValidatorSet::with_addresses(pks, vec![1; n], addresses).unwrap();
        (secrets, set)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_validator(
        seat: usize,
        secrets: &[crypto::BlsSecretKey],
        committee: &consensus::ValidatorSet,
        base_port: u16,
        observer: (primitives::Address, crypto::PublicKey),
        shutdown: Arc<AtomicBool>,
        tx_inject: Option<crate::validator_net::TxInject>,
        fund: Option<primitives::Address>,
    ) {
        let n = committee.n();
        let peers: Vec<(Vec<u8>, String)> = (0..n)
            .filter(|i| *i != seat)
            .map(|i| {
                (
                    committee.validator_addresses()[i].0.to_vec(),
                    format!("127.0.0.1:{}", base_port + u16::try_from(i).unwrap()),
                )
            })
            .collect();
        let spec = crate::validator_net::ValidatorNetSpec {
            log_tag: format!("val[{seat}]"),
            seat,
            validator_set: committee.clone(),
            signer: Arc::new(secrets[seat].clone()),
            node_config: crate::NodeConfig::default(),
            wal_path: None,
            listen_addr: format!("127.0.0.1:{}", base_port + u16::try_from(seat).unwrap()),
            peers,
            tls: None,
            network: config::NetworkConfig::default(),
            genesis_alloc: fund.map(|addr| {
                Box::new(move |m: &evm::EvmModule| {
                    m.fund_account_for_test(&addr, u128::MAX);
                }) as crate::validator_net::GenesisAlloc
            }),
            data_dir: None,
            rpc_listen: None,
            rpc_config: config::RpcConfig::default(),
            smoke_tx: None,
            shutdown,
            repair_peers: Vec::new(),
            observer_peers: vec![observer],
            tx_inject,
        };
        std::thread::spawn(move || crate::validator_net::run(spec));
    }

    /// Three validators produce blocks; a follower joins as an
    /// observer, syncs the certified history, and keeps mirroring —
    /// the live-consume contract end to end: handshake auth, fetch,
    /// per-record verification, execution, RPC mirror.
    #[test]
    fn follower_mirrors_committed_history() {
        let (secrets, set) = devnet_committee(3);
        let shutdown = Arc::new(AtomicBool::new(false));
        let base = 26400u16;
        let rpc_port = 26410u16;

        let observer_key = crate::cli::bls_key(99);
        let observer_addr = crypto::bls::validator_address(&observer_key.public_key());
        for seat in 0..3 {
            spawn_validator(
                seat,
                &secrets,
                &set,
                base,
                (observer_addr, observer_key.public_key()),
                shutdown.clone(),
                None,
                None,
            );
        }

        // The follower dials all three members. `own_id` is the
        // key-derived address the validators' observer allowlist
        // names — exactly what the binary derives.
        let follower_peers: Vec<(Vec<u8>, String)> = (0..3)
            .map(|i| {
                (
                    set.validator_addresses()[i].0.to_vec(),
                    format!("127.0.0.1:{}", base + u16::try_from(i).unwrap()),
                )
            })
            .collect();
        let follower_shutdown = shutdown.clone();
        std::thread::spawn(move || {
            run(FollowerSpec {
                log_tag: "follower".to_string(),
                validator_set: set,
                epoch: primitives::Epoch::new(0),
                own_id: observer_addr.0.to_vec(),
                signer: Arc::new(observer_key),
                node_config: crate::NodeConfig::default(),
                wal_path: None,
                listen_addr: "127.0.0.1:26404".to_string(),
                peers: follower_peers,
                tls: None,
                network: config::NetworkConfig::default(),
                genesis_alloc: None,
                data_dir: None,
                rpc_listen: Some(format!("127.0.0.1:{rpc_port}")),
                rpc_config: config::RpcConfig::default(),
                repair_peers: Vec::new(),
                shutdown: follower_shutdown,
            });
        });

        // The fleet needs a few views to reach height ≥ 3: 2s base
        // timeout, ~1 view/2s worst case plus startup handshake.
        // 40s is generous for loopback.
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        let mut reached = 0u64;
        while std::time::Instant::now() < deadline {
            if let Some(h) = rpc_block_number(&format!("127.0.0.1:{rpc_port}"))
                && h > reached
            {
                reached = h;
            }
            if reached >= 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        shutdown.store(true, Ordering::Relaxed);
        assert!(
            reached >= 3,
            "follower mirrored only height {reached} within the deadline — \
             handshake, fetch, or apply path is broken"
        );
    }

    /// The `TxInject` path end to end: a validator with a configured
    /// injector emits signed staking txs on a fixed schedule, they
    /// enter its mempool, gossip to peers, land in proposals, and
    /// commit — observed through the follower's mirrored
    /// `eth_getBlockTransactionCountByNumber`, the same surface a
    /// load harness reads.
    #[test]
    fn validator_tx_inject_commits_signed_txs() {
        let (secrets, set) = devnet_committee(3);
        let shutdown = Arc::new(AtomicBool::new(false));
        let base = 26500u16;
        let rpc_port = 26510u16;

        // Seat 0 injects signed EVM transfers: sender identity 0 is
        // the devnet-funded account; 50 offered tx/s — well above
        // the ~1.5 blk/s finalization cadence, so blocks must batch.
        let sender = crypto::secp::test_identity_address(0).expect("devnet identity");
        let key = crypto::secp::test_identity_key(0);
        let inject = crate::validator_net::TxInject::evm_transfers(50.0, key, sender, 1);

        let observer_key = crate::cli::bls_key(97);
        let observer_addr = crypto::bls::validator_address(&observer_key.public_key());
        let mut inject = Some(inject);
        for seat in 0..3 {
            spawn_validator(
                seat,
                &secrets,
                &set,
                base,
                (observer_addr, observer_key.public_key()),
                shutdown.clone(),
                if seat == 0 { inject.take() } else { None },
                // EVERY validator funds `sender`: execution must be
                // identical fleet-wide — a funded-only-on-one-node
                // account would execute on that node and skip on the
                // rest (the divergence-latch case). The
                // `dev-identities`-gated default funding doesn't
                // cover this crate's own test build, so the spec
                // funds the account explicitly — mirroring the
                // uniform `evm.alloc` the real harness provisions.
                Some(sender),
            );
        }

        let follower_peers: Vec<(Vec<u8>, String)> = (0..3)
            .map(|i| {
                (
                    set.validator_addresses()[i].0.to_vec(),
                    format!("127.0.0.1:{}", base + u16::try_from(i).unwrap()),
                )
            })
            .collect();
        let follower_shutdown = shutdown.clone();
        std::thread::spawn(move || {
            run(FollowerSpec {
                log_tag: "follower".to_string(),
                validator_set: set,
                epoch: primitives::Epoch::new(0),
                own_id: observer_addr.0.to_vec(),
                signer: Arc::new(observer_key),
                node_config: crate::NodeConfig::default(),
                wal_path: None,
                listen_addr: "127.0.0.1:26504".to_string(),
                peers: follower_peers,
                tls: None,
                network: config::NetworkConfig::default(),
                // The follower must fund the injector's sender too —
                // it re-executes every committed tx, so an unfunded
                // account diverges its EVM state from the fleet
                // (the production path gets this from `evm.alloc`
                // in the shared genesis file).
                genesis_alloc: Some(Box::new(move |m: &evm::EvmModule| {
                    m.fund_account_for_test(&sender, u128::MAX);
                }) as crate::validator_net::GenesisAlloc),
                data_dir: None,
                rpc_listen: Some(format!("127.0.0.1:{rpc_port}")),
                rpc_config: config::RpcConfig::default(),
                repair_peers: Vec::new(),
                shutdown: follower_shutdown,
            });
        });

        // Wait for the mirror to reach height ≥ 4, then require at
        // least one committed block carrying injected txs — a block
        // count alone can't distinguish empty heartbeat commits
        // from real load.
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        let mut reached = 0u64;
        while std::time::Instant::now() < deadline {
            if let Some(h) = rpc_block_number(&format!("127.0.0.1:{rpc_port}"))
                && h > reached
            {
                reached = h;
            }
            if reached >= 4 {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(reached >= 4, "follower mirrored only height {reached}");

        let mut committed_txs = 0u64;
        for h in 1..=reached {
            committed_txs += rpc_block_tx_count(&format!("127.0.0.1:{rpc_port}"), h).unwrap_or(0);
        }
        // The transfers carry 1 wei each — a nonzero sink balance is
        // the state-level proof the committed txs actually executed
        // on the follower (not merely that history was recorded).
        let sink_balance = rpc_balance(
            &format!("127.0.0.1:{rpc_port}"),
            "0x7777777777777777777777777777777777777777",
        )
        .unwrap_or(0);
        shutdown.store(true, Ordering::Relaxed);
        assert!(
            committed_txs > 0,
            "no committed block carried injected txs over {reached} mirrored heights — \
             the injector path (submit + gossip + proposal) is broken"
        );
        assert!(
            sink_balance > 0,
            "committed txs never landed in the follower's EVM state (sink balance 0 \
             after {committed_txs} counted txs) — execution diverged from the fleet"
        );
    }

    /// A restarted follower resumes at its durable frontier instead
    /// of re-walking the chain: `data_dir` gives the executor
    /// journal + `snapshot.bin` export, the WAL restores
    /// `last_committed`, and the sync store replays its journal —
    /// the post-restart `eth_blockNumber` reads ≥ the pre-shutdown
    /// tip immediately, not after a full re-fetch.
    #[test]
    fn follower_restart_resumes_from_durable_state() {
        let (secrets, set) = devnet_committee(3);
        let shutdown = Arc::new(AtomicBool::new(false));
        let base = 26420u16;
        let rpc_port1 = 26430u16;
        let rpc_port2 = 26431u16;

        let observer_key = crate::cli::bls_key(98);
        let observer_addr = crypto::bls::validator_address(&observer_key.public_key());
        for seat in 0..3 {
            spawn_validator(
                seat,
                &secrets,
                &set,
                base,
                (observer_addr, observer_key.public_key()),
                shutdown.clone(),
                None,
                None,
            );
        }

        let data_dir = std::env::temp_dir().join(format!(
            "oxide-follower-test-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let follower_peers: Vec<(Vec<u8>, String)> = (0..3)
            .map(|i| {
                (
                    set.validator_addresses()[i].0.to_vec(),
                    format!("127.0.0.1:{}", base + u16::try_from(i).unwrap()),
                )
            })
            .collect();

        let mk_spec = |shutdown: Arc<AtomicBool>, rpc_port: u16| {
            let wal = Some(data_dir.join("consensus.wal"));
            FollowerSpec {
                log_tag: "follower".to_string(),
                validator_set: set.clone(),
                epoch: primitives::Epoch::new(0),
                own_id: observer_addr.0.to_vec(),
                signer: Arc::new(observer_key.clone()),
                node_config: crate::NodeConfig::default(),
                wal_path: wal,
                // Ephemeral transport bind — nothing dials a
                // follower, and an OS-assigned port cannot collide
                // with the previous run's lingering listener.
                listen_addr: "127.0.0.1:0".to_string(),
                peers: follower_peers.clone(),
                tls: None,
                network: config::NetworkConfig::default(),
                genesis_alloc: None,
                data_dir: Some(data_dir.clone()),
                // A fresh RPC port per run: the previous run's HTTP
                // server outlives `run()` (supervised thread) — a
                // distinct port makes the probe unambiguous.
                rpc_listen: Some(format!("127.0.0.1:{rpc_port}")),
                rpc_config: config::RpcConfig::default(),
                repair_peers: Vec::new(),
                shutdown,
            }
        };

        // First run: reach height ≥ 3, then graceful shutdown — the
        // snapshot export + WAL append land on disk.
        let run_shutdown = Arc::new(AtomicBool::new(false));
        let spec1 = mk_spec(run_shutdown.clone(), rpc_port1);
        let join = std::thread::spawn(move || run(spec1));
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        let mut first_tip = 0u64;
        while std::time::Instant::now() < deadline {
            if let Some(h) = rpc_block_number(&format!("127.0.0.1:{rpc_port1}"))
                && h > first_tip
            {
                first_tip = h;
            }
            if first_tip >= 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(first_tip >= 3, "follower never reached height 3 (got {first_tip})");
        run_shutdown.store(true, Ordering::Relaxed);
        join.join().expect("first follower run must not panic");

        // Second run: SAME data dir + WAL. A resume imports the
        // exported snapshot immediately — `eth_blockNumber` reads ≥
        // the first tip right away; a from-scratch restart would
        // read 0 and re-walk for seconds. The tight window
        // distinguishes the two.
        let rerun_shutdown = shutdown.clone();
        let spec2 = mk_spec(rerun_shutdown.clone(), rpc_port2);
        let join2 = std::thread::spawn(move || run(spec2));
        let deadline2 = std::time::Instant::now() + Duration::from_secs(20);
        let mut resumed: Option<u64> = None;
        while std::time::Instant::now() < deadline2 {
            // Probe ONLY run 2's server — run 1's outlives `run()`
            // and would serve a stale (but passable) height, making
            // this assertion vacuous.
            if let Some(h) = rpc_block_number(&format!("127.0.0.1:{rpc_port2}"))
                && h >= first_tip
            {
                resumed = Some(h);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        shutdown.store(true, Ordering::Relaxed);
        join2.join().expect("second follower run must not panic");
        let _ = std::fs::remove_dir_all(&data_dir);
        assert!(
            resumed.is_some(),
            "restarted follower did not resume at ≥{first_tip} within the window — \
             durable-state recovery is broken"
        );
    }
}
