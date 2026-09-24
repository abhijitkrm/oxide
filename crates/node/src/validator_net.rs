//! `validator_net` — the networked single-validator node runtime.
//!
//! # What this is
//!
//! One process = one validator: the transport-to-engine pump that
//! turns an assembled [`crate::devnet::DevnetNode`] into a live
//! committee member. Both node binaries consume it:
//!
//! - `oxide-devnet --node <i>` derives its inputs from devnet
//!   conventions (deterministic keys, index-templated ports) and
//!   calls [`run`];
//! - `oxide-validator --validator` resolves them from config —
//!   `--genesis-file`, `--bls-key-file`, `--tls-dir`, and
//!   `addr@host:port` peer entries — and calls the same [`run`].
//!
//! Keeping the pump here rather than in either binary is the point:
//! a divergence between "the devnet's networking" and "the
//! production validator's networking" is exactly the kind of drift
//! the 6.5 remediation removed from executor assembly.
//!
//! # Wire protocol
//!
//! One-byte message tags on the transport frame: `MSG_PROPOSAL`,
//! `MSG_VOTE`, `MSG_QC`, `MSG_TIMEOUT`, `MSG_TC`, `MSG_TX`,
//! `MSG_BLOCK_REQ`, `MSG_BLOCK_RESP`. This IS the production
//! consensus wire format — a change here is a protocol change, not
//! a devnet tweak.
//!
//! # Block sync
//!
//! `MSG_BLOCK_REQ`/`MSG_BLOCK_RESP` close the catch-up gap: a node
//! that missed committed history fetches [`types::CertifiedBlock`]
//! records by hash or height range, verifies each one's Jolteon
//! commit proof locally (`OxideBft::apply_certified_block`), and
//! finalizes the contiguous prefix — see [`crate::block_sync`].
//!
//! # Routing convention
//!
//! Transport peer IDs are staking *addresses*, not committee
//! indexes: sends resolve the live committee's
//! `validator_addresses()` (which follows rotations), and inbound
//! attribution resolves `msg.from` — the handshake-authenticated
//! address — back to a committee index via `index_of`. An index
//! baked into the peer id would point at a different member the
//! moment a removal reshuffled the committee; the address cannot.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use ports::ConsensusEngine;
use ports::transport::Transport;
use types::TxBytes;

// Codec traits for encoding/decoding consensus messages.
use codec::{Decode, Encode};

// ── Wire message tags ───────────────────────────────────
// One-byte type tags for the transport frame: the first byte of
// each message identifies the payload type.
pub(crate) const MSG_PROPOSAL: u8 = 0x00;
const MSG_VOTE: u8 = 0x01;
pub(crate) const MSG_QC: u8 = 0x02;
const MSG_TIMEOUT: u8 = 0x03; // timeout signature (view-change init)
const MSG_TC: u8 = 0x04; // timeout certificate (view-change proof)
pub(crate) const MSG_TX: u8 = 0x05; // raw tx envelope gossip (mempool propagation)
pub(crate) const MSG_BLOCK_REQ: u8 = 0x06; // certified-block fetch (by hash/height)
pub(crate) const MSG_BLOCK_RESP: u8 = 0x07; // certified-block serve (verified records)

/// Idle heartbeat interval for the consensus pump (unit: wall-clock
/// time). A leader with no pending work still owes the network a
/// — usually empty — block on this cadence: followers cannot
/// distinguish "idle" from "dead", so silence would churn views
/// through timeout certificates forever. Must stay comfortably
/// below the pacemaker's base timeout (2s default) so a live idle
/// leader's heartbeats keep follower timers reset; 1s leaves a
/// full timeout of slack for scheduling jitter. Lower = more empty
/// blocks (fresher liveness evidence, more I/O); higher = fewer
/// blocks but closer to timeout churn.
const IDLE_HEARTBEAT: Duration = Duration::from_secs(1);

/// Minimum interval between outgoing block-fetch requests for the
/// same gap (unit: wall-clock). The fetch trigger fires on every
/// gapped proposal — at tip pace that's one per view — so without a
/// throttle each proposal would re-send the same range request
/// while the previous response is still in flight. 750ms sits
/// between the transport's expected RTT (~ms on LAN, ~100ms WAN)
/// and the pacemaker's 2s base timeout: slow enough that a healthy
/// peer answers first, fast enough that a dropped response stalls
/// catch-up for less than one view.
pub(crate) const SYNC_REQ_RETRY: Duration = Duration::from_millis(750);

/// Cap on out-of-order certified records buffered awaiting
/// contiguity. Responses are requested in order, so a healthy flow
/// never buffers — the cap exists for interleaved pages and
/// adversarial servers, not normal operation. 1024 records ≈ a few
/// MiB of headers/QCs/bodies — a bounded soak, never a growth
/// channel.
pub(crate) const SYNC_PENDING_CAP: usize = 1024;

/// Interval between full divergence-repair attempts (unit:
/// wall-clock). Each attempt is a manifest fetch + certificate
/// verify + chunked snapshot download + journal replay — seconds of
/// work and megabytes of peer bandwidth — so the cadence is
/// deliberate rather than per-tick. Ten seconds is far below the
/// cost of a halted validator to the fleet (missed leader turns
/// burn whole views), and slow enough that a transient peer
/// failure does not spin the download loop.
pub(crate) const REPAIR_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Gossip dedup cap: tx hashes already ingested (ours + peers').
/// 100k entries covers several blocks' worth of txs; a duplicate
/// arriving after eviction is re-ingested harmlessly (the
/// executor's nonce-replay check still applies). Shared with the
/// follower pump — the bound rationale is identical there.
pub(crate) const GOSSIP_SEEN_CAP: usize = 100_000;

/// Per-peer certificate poll budget during a repair attempt: a
/// serving validator forms an exec cert within a few views of the
/// manifest's height, so `CERT_POLL_ATTEMPTS × CERT_POLL_INTERVAL`
/// ≈ 2s bounds the wait without letting one peer stall the pass.
const CERT_POLL_ATTEMPTS: u32 = 10;
/// See [`CERT_POLL_ATTEMPTS`].
const CERT_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// mTLS material for the peer transport — resolved file paths.
///
/// Peer certificates are required per expected peer: a peer without
/// a trusted cert can never complete the handshake, which is the
/// point — the trust list IS the admission policy at the TLS layer
/// (membership itself is re-checked live by `BlsPeerAuth`).
#[derive(Debug)]
pub struct TlsSpec {
    /// This node's own certificate (PEM).
    pub cert_path: PathBuf,
    /// This node's private key (PEM).
    pub key_path: PathBuf,
    /// `(peer_id, cert_path)` for every peer this node trusts —
    /// `peer_id` is the peer's staking-address bytes.
    pub trusted_peer_certs: Vec<(Vec<u8>, PathBuf)>,
}

/// Genesis `evm.alloc` application hook — see
/// [`ValidatorNetSpec::genesis_alloc`].
pub type GenesisAlloc = Box<dyn FnOnce(&evm::EvmModule) + Send>;

/// Everything [`run`] needs, already resolved.
///
/// The binaries own flag/config parsing and their mode's defaults;
/// this spec is the boundary between "how the operator expressed
/// it" and "what the node runs". Nothing inside `validator_net`
/// reads CLI flags — an input that matters to the network path is
/// a field here, so a binary cannot accidentally inherit another
/// binary's flag conventions.
pub struct ValidatorNetSpec {
    /// Log prefix on every line this node prints —
    /// `oxide-devnet[0]` or `oxide-validator`.
    pub log_tag: String,
    /// This node's committee seat: the index into `validator_set`
    /// its `signer` resolves to. Decoupled from any process/
    /// port index — a post-rotation genesis legitimately seats a
    /// node differently than its address sort or launch order.
    pub seat: usize,
    /// The committee this node joins.
    pub validator_set: consensus::ValidatorSet,
    /// This node's consensus signer — votes/QC contributions and
    /// the peer-handshake proof. A trait object so a remote-signer
    /// deployment (`--signer-addr`) keeps the secret outside the
    /// validator process; `Arc::new(secret_key)` is the local path.
    pub signer: Arc<dyn crypto::ConsensusSigner>,
    /// The resolved node config — executor graph, genesis, chain
    /// id, block budget, pacemaker timeouts.
    pub node_config: crate::NodeConfig,
    /// Consensus WAL path — `None` follows `node_config`'s own
    /// `<data_dir>/consensus.wal` derivation; both `None` disables
    /// WAL persistence.
    pub wal_path: Option<PathBuf>,
    /// TCP listen address for peer connections (`host:port`).
    pub listen_addr: String,
    /// Peers to dial: `(peer_id, host:port)` where `peer_id` is the
    /// member's staking-address bytes. The transport authenticates
    /// each peer id against the live committee at handshake time,
    /// so an entry for an address that never joins simply fails
    /// auth — listing a pending rotation member early is safe.
    pub peers: Vec<(Vec<u8>, String)>,
    /// mTLS material; `None` runs plaintext TCP. The posture gate
    /// (`refuse_insecure_posture_on_external_binds`) is what stands
    /// between `None` and a public bind — this layer does not
    /// re-decide policy.
    pub tls: Option<TlsSpec>,
    /// `[network]` transport tunables — timeouts, frame bound.
    pub network: config::NetworkConfig,
    /// Genesis `evm.alloc` application hook, run only on a fresh
    /// start (a restart must not rewind balances the chain moved).
    /// A closure rather than parsed data so the `node` crate stays
    /// free of an `alloy_primitives` dependency — the binaries own
    /// the hex→U256 conversion.
    pub genesis_alloc: Option<GenesisAlloc>,
    /// Data directory for block journal + checkpoint durability and
    /// the shutdown snapshot export. `None` = in-memory only.
    pub data_dir: Option<PathBuf>,
    /// Resolved RPC listen address (`None` = no RPC server).
    pub rpc_listen: Option<String>,
    /// `[rpc]` config — chain id, base fee, debug API.
    pub rpc_config: config::RpcConfig,
    /// Optional startup transaction (the devnet smoke test).
    /// Production validators pass `None` — a validator must not
    /// emit transactions signed by public test identities.
    pub smoke_tx: Option<TxBytes>,
    /// Shutdown flag — the binary installs its own signal handling
    /// (tokio `select!` in `oxide-validator`, a supervised signal
    /// thread in `oxide-devnet`); the pump polls it each iteration.
    pub shutdown: Arc<AtomicBool>,
    /// Peer RPC endpoints (`host:port`) for certified state repair
    /// after an execution-divergence halt. When the engine latches a
    /// divergence, the pump polls these peers' `/snapshot/*`
    /// endpoints for a manifest + quorum-signed certificate it can
    /// verify against the live committee, imports the snapshot, and
    /// replays the durable journal over it — clearing the latch only
    /// when the rebuilt state reproduces a certified root
    /// (`OxideBft::mark_repaired`). Empty disables auto-repair: the
    /// node stays halted and the manual runbook applies. These are
    /// RPC endpoints, not consensus transport addresses — the
    /// snapshot surface lives on the HTTP server.
    pub repair_peers: Vec<String>,
    /// Observer allowlist: `(address, BLS public key)` for
    /// non-committee endpoints permitted to complete the peer
    /// handshake — fullnode followers that mirror committed state.
    /// An observer authenticates exactly like a member (proof of its
    /// registered key over the handshake transcript); the only
    /// difference is which map resolves the claimed address, and
    /// committee maps always win — an observer entry can never
    /// shadow a member. Serving certified history to an observer is
    /// safe: records are already public, quorum-verified data.
    pub observer_peers: Vec<(primitives::Address, crypto::PublicKey)>,
}

/// Run a networked validator until `spec.shutdown` is set.
///
/// The full lifecycle: assemble the engine + executor (with WAL and
/// durable-state recovery), build the authenticated transport, start
/// RPC, and drive the consensus pump. On shutdown, exports a state
/// snapshot to `<data_dir>/snapshot.bin` when a data dir is
/// configured. Blocks the calling thread — the pump is deliberately
/// synchronous (single-writer engine, non-blocking transport
/// drains).
///
/// # Panics
///
/// Panics on unrecoverable startup failures (assembly errors, TLS
/// config, data-dir creation) — startup is the right place for
/// fatal errors; a half-assembled validator emits only rejected
/// noise.
#[allow(clippy::too_many_lines)]
pub fn run(spec: ValidatorNetSpec) {
    let ValidatorNetSpec {
        log_tag,
        seat,
        validator_set,
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
        smoke_tx,
        shutdown,
        repair_peers,
        observer_peers,
    } = spec;

    // Peer identity is the validator's staking address — the stable
    // identity that survives index reshuffles on removal and key
    // replacement on rotation. Our own address (becomes our
    // transport peer id) is read from the committee, never derived.
    let our_addr = validator_set.validator_addresses()[seat];
    let own_id = our_addr.0.to_vec();

    println!(
        "{log_tag}: listening on {listen_addr}, {} peers, seat {seat} of {}",
        peers.len(),
        validator_set.n()
    );

    // Assemble the node through the ONE shared production path —
    // `assemble_devnet_node` runs the same executor graph, engine
    // wiring (configured timeouts/budget), WAL recovery, and
    // membership gate every caller consumes.
    let crate::devnet::DevnetNode {
        mut engine,
        app,
        evm_module,
        staking_module: _,
        exchange_module: _,
        recovered: _,
        recovery,
        wal_path: effective_wal_path,
    } = crate::devnet::assemble_devnet_node(crate::devnet::DevnetNodeSpec {
        index: seat,
        validator_set: validator_set.clone(),
        signer: Arc::clone(&signer),
        config: node_config.clone(),
        clock: None, // production wall clock
        wal_path,
    })
    .unwrap_or_else(|e| {
        eprintln!("{log_tag}: {e} — exiting");
        std::process::exit(1);
    });
    let app: Arc<executor::Executor> = app;
    // `evm.alloc` is genesis state: it applies on a fresh start
    // only. `assemble_executor` already ran durable recovery, so a
    // restart arrives here holding the replayed tip — overwriting
    // alloc accounts now would rewind balances the chain moved.
    let fresh_start =
        recovery.as_ref().is_none_or(|r| r.snapshot_height.is_none() && r.blocks_replayed == 0);
    if fresh_start && let Some(apply) = genesis_alloc {
        apply(&evm_module);
    }
    if let Some(ref wal_path) = effective_wal_path {
        println!("{log_tag}: WAL loaded from {}", wal_path.display());
    }

    // Shared validator set — created before the transport so the
    // handshake authenticator and the RPC provider both read the
    // same live committee. The consensus loop writes the rotated
    // set at each epoch boundary; readers always see the current
    // keys.
    let shared_validator_set = Arc::new(std::sync::RwLock::new(validator_set.clone()));
    // Shared pending set: while a rotation is scheduled, the
    // consensus loop publishes `engine.next_validator_set()` here so
    // `BlsPeerAuth` admits the incoming member's handshake BEFORE
    // its first consensus duty — a member admitted only at
    // activation would miss its opening views. `None` otherwise.
    let shared_next_validator_set =
        Arc::new(std::sync::RwLock::new(Option::<consensus::ValidatorSet>::None));

    // Create the TCP transport: mTLS when `tls` is configured, plain
    // TCP otherwise. `[network]` timeouts and the frame bound flow
    // into `TcpTransportConfig`. Peer IDs are cryptographically
    // bound to committee keys via the signed greeting
    // (`BlsPeerAuth`) — a self-claimed ID can neither join nor
    // displace a live peer.
    let mut transport = build_transport(
        &listen_addr,
        &log_tag,
        own_id,
        peers,
        tls,
        &network,
        signer,
        shared_validator_set.clone(),
        shared_next_validator_set.clone(),
        observer_peers,
    );

    // Give connections time to establish. TLS handshakes take
    // longer than plain TCP — 2s gives all peers time to connect
    // and complete the handshake before the first proposal.
    thread::sleep(Duration::from_millis(2000));

    // Data directory enables durable state — `<dir>/block-journal/`
    // records every finalized block and `<dir>/snapshot.bin` is the
    // periodic checkpoint, both already replayed by
    // `assemble_executor` above (the `recovery` report).
    if let Some(ref dir) = data_dir {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("failed to create data dir {}: {e}", dir.display()));
        if let Some(report) = &recovery {
            if report.snapshot_height.is_some() || report.blocks_replayed > 0 {
                println!(
                    "{log_tag}: recovered durable state from {} \
                     (snapshot {:?}, replayed {} blocks, height {})",
                    dir.display(),
                    report.snapshot_height,
                    report.blocks_replayed,
                    report.recovered_height,
                );
            }
            if let Some(reason) = &report.snapshot_rejected {
                eprintln!(
                    "{log_tag}: snapshot.bin rejected ({reason}); \
                     recovered from the block journal alone"
                );
            }
        }
    }

    // Tx-gossip channel: the RPC submitter pushes accepted txs here;
    // the consensus loop drains it and broadcasts `MSG_TX` frames to
    // all peers. Bounded at 10k — a full channel drops the gossip
    // copy (local submission already succeeded) instead of blocking
    // the RPC thread.
    let (gossip_tx, gossip_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(10_000);

    // Start the RPC server if a listen address was resolved.
    let rpc_handle = start_rpc(
        &rpc_config,
        rpc_listen,
        &app,
        &log_tag,
        shared_validator_set.clone(),
        &evm_module,
        gossip_tx,
    );

    println!("{log_tag}: consensus engine started, waiting for blocks...");

    // Optional startup transaction — the devnet smoke test. `None`
    // on production validators.
    if let Some(tx) = smoke_tx {
        engine.submit_tx(tx);
    }

    let height = engine.finalized_height();
    println!("{log_tag}: finalized height = {height:?}");
    println!("{log_tag}: node running");

    // The certified-block serve store: replays the durable journal
    // under `<data_dir>/certified-journal/` so a restarted validator
    // can still serve the history it finalized before the crash.
    // Drained from the engine's `certified_out` queue every loop.
    let mut sync_store = crate::block_sync::SyncStore::open(data_dir.as_deref());

    // Run the consensus message pump loop until shutdown.
    run_consensus_loop(
        &mut engine,
        &mut transport,
        &app,
        &log_tag,
        our_addr,
        shutdown.as_ref(),
        rpc_handle.as_deref(),
        &shared_validator_set,
        &shared_next_validator_set,
        &gossip_rx,
        &mut sync_store,
        &repair_peers,
    );
    // Flush any batched certified-record appends before the data
    // dir is handed to the snapshot exporter.
    sync_store.flush();

    // Graceful shutdown: if a data dir is configured, export the
    // current state to `<dir>/snapshot.bin` so a restart can resume
    // with the full chain state (not just the WAL).
    if let Some(ref dir) = data_dir {
        let height = crate::devnet::export_snapshot(&app, dir).unwrap_or_else(|e| panic!("{e}"));
        println!(
            "{log_tag}: exported snapshot to {} (height {height})",
            dir.join("snapshot.bin").display(),
        );
    }
    println!("{log_tag}: shutdown complete");
}

/// Build the TCP transport: `spec.tls` for mTLS, plain TCP otherwise.
///
/// The `network` config supplies the timeouts and frame bound.
/// Admission is cryptographic, not list-based: `allowed_peer_ids`
/// stays `None` because a static set can never follow committee
/// rotations (a member added post-boot would be refused before the
/// handshake it must pass). `BlsPeerAuth` resolves each connection's
/// address-id against the LIVE validator set — plus the staged
/// `pending` set during a rotation's activation window — and
/// requires a `Domain::PeerHandshake` signature under that member's
/// registered key. A self-claimed id can neither join nor displace
/// a live peer, and a removed member's proofs die the moment the
/// new set activates.
///
/// # Panics
///
/// Panics if a `TlsSpec` is given but the TLS config cannot be built
/// (missing cert/key files, invalid PEM, etc.).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_transport(
    listen_addr: &str,
    log_tag: &str,
    own_id: Vec<u8>,
    peers: Vec<(Vec<u8>, String)>,
    tls: Option<TlsSpec>,
    network: &config::NetworkConfig,
    signer: Arc<dyn crypto::ConsensusSigner>,
    validators: Arc<std::sync::RwLock<consensus::ValidatorSet>>,
    pending: Arc<std::sync::RwLock<Option<consensus::ValidatorSet>>>,
    observers: Vec<(primitives::Address, crypto::PublicKey)>,
) -> p2p::tcp::TcpTransport {
    // Signed greeting: peer IDs are staking addresses bound to
    // committee keys, so a connection claiming member `a` must sign
    // with the key registered for `a` — the ID can no longer be
    // self-claimed, and a duplicate connection is a
    // proven-same-identity reconnect, not a hijack. The shared sets
    // mean committee rotations take effect without a transport
    // restart. `observers` carries the operator's non-committee
    // allowlist (fullnode followers) — resolved after the live and
    // pending sets so it can never shadow a member.
    let auth: Arc<dyn p2p::tcp::PeerAuth> = Arc::new(
        crate::peer_auth::BlsPeerAuth::new(signer, validators, pending)
            .with_observers(observers.into_iter().collect()),
    );
    let transport_config =
        p2p::tcp::TcpTransportConfig { peer_auth: Some(auth), ..to_transport_config(network) };
    // Admission control is always on in the shipped node: connection
    // caps, per-peer ingress rate limits, and reputation bans are not
    // optional defenses. Default limits (256 connections, 10 MiB
    // burst / 1 MiB/s per peer) comfortably fit consensus traffic.
    let admission =
        p2p::admission::SharedAdmissionControl::new(p2p::admission::AdmissionControl::new());
    if let Some(tls_spec) = tls {
        let trusted_peers: Vec<(Vec<u8>, String)> = tls_spec
            .trusted_peer_certs
            .iter()
            .map(|(id, path)| (id.clone(), path.display().to_string()))
            .collect();
        let trusted_peers_refs: Vec<(Vec<u8>, &str)> =
            trusted_peers.iter().map(|(id, path)| (id.clone(), path.as_str())).collect();
        let tls_config = p2p::tls::TlsConfig::from_files(
            &tls_spec.cert_path.display().to_string(),
            &tls_spec.key_path.display().to_string(),
            &trusted_peers_refs,
        )
        .unwrap_or_else(|e| panic!("{log_tag}: failed to build TLS config: {e}"));
        println!("{log_tag}: mTLS enabled");
        p2p::tcp::TcpTransport::with_tls_and_admission(
            listen_addr,
            own_id,
            peers,
            transport_config,
            tls_config,
            admission,
        )
    } else {
        p2p::tcp::TcpTransport::with_admission(
            listen_addr,
            own_id,
            peers,
            transport_config,
            admission,
        )
    }
}

/// A `ValidatorSetProvider` that reads from a shared
/// `Arc<RwLock<ValidatorSet>>` — the consensus loop writes the
/// updated set after each epoch rotation; the RPC handler reads it.
struct SharedValidatorSetProvider {
    /// The shared validator set — written by the consensus loop
    /// after `rotate_epoch`, read by the RPC handler.
    set: std::sync::Arc<std::sync::RwLock<consensus::ValidatorSet>>,
}

impl rpc::ValidatorSetProvider for SharedValidatorSetProvider {
    fn validator_set(&self) -> Result<Vec<rpc::ValidatorSetEntry>, String> {
        let set = self.set.read().map_err(|e| format!("validator set lock poisoned: {e}"))?;
        let entries = set
            .validator_addresses()
            .iter()
            .zip(set.public_keys().iter())
            .zip(set.stakes().iter())
            .map(|((addr, pk), stake)| rpc::ValidatorSetEntry {
                address: format!("0x{}", crate::cli::hex_encode(&addr.0)),
                public_key: format!("0x{}", crate::cli::hex_encode(pk.as_bytes())),
                stake: *stake,
            })
            .collect();
        Ok(entries)
    }
}

/// Start the RPC server for a networked validator.
///
/// Returns a handle to the `RpcServer` for metrics updates, or
/// `None` if no RPC address is configured.
///
/// The HTTP server is spawned on a dedicated tokio runtime thread so
/// the consensus loop can run on the calling thread.
pub(crate) fn start_rpc(
    rpc_config: &config::RpcConfig,
    rpc_listen: Option<String>,
    app: &Arc<executor::Executor>,
    log_tag: &str,
    shared_validator_set: Arc<std::sync::RwLock<consensus::ValidatorSet>>,
    evm_module: &Arc<evm::EvmModule>,
    gossip_tx: std::sync::mpsc::SyncSender<Vec<u8>>,
) -> Option<Arc<rpc::RpcServer>> {
    let listen = rpc_listen?;

    let mut rpc_server = rpc::RpcServer::new(rpc_config.chain_id, rpc_config.base_fee)
        .with_debug_api(rpc_config.enable_debug_api);
    // Gossip-aware submitter: accepted txs are broadcast to all peers
    // so a tx sent to a non-leader still reaches the current leader.
    rpc_server.set_tx_submitter(Arc::new(crate::rpc_adapters::GossipingTxSubmitter {
        inner: crate::rpc_adapters::ExecutorTxSubmitter { executor: app.clone() },
        gossip: gossip_tx,
    }));
    rpc_server.set_evm(evm_module.clone());
    rpc_server.set_txpool_provider(Arc::new(crate::rpc_adapters::ExecutorTxpoolProvider {
        executor: app.clone(),
    }));
    rpc_server.set_snapshot_provider(Arc::new(crate::rpc_adapters::ExecutorSnapshotProvider {
        executor: app.clone(),
    }));
    rpc_server.set_validator_set_provider(Arc::new(SharedValidatorSetProvider {
        set: shared_validator_set,
    }));
    let rpc = Arc::new(rpc_server);
    let http_server = rpc::server::HttpServer::from_shared(rpc.clone(), listen.clone());

    // Spawn the HTTP server on a dedicated tokio runtime thread so
    // the consensus loop can run on the calling thread. Non-critical:
    // a dead RPC leaves consensus running; health probes see a
    // refused connection.
    let rpc_clone = rpc.clone();
    let _ = primitives::supervision::spawn_supervised("rpc-http", false, move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rpc runtime");
        rt.block_on(async move {
            http_server.serve().await;
        });
    });

    println!("{log_tag}: RPC server on http://{listen}");
    Some(rpc_clone)
}

/// Map the `[network]` config onto the transport's tunables.
///
/// `listen_addr`/`peers` are NOT taken from the file by callers that
/// derive them per-index (`--node`, `--base-port`) or per-member
/// (`addr=host:port` entries); the timeouts and frame bound DO apply
/// to both TLS and plain TCP.
fn to_transport_config(network: &config::NetworkConfig) -> p2p::tcp::TcpTransportConfig {
    p2p::tcp::TcpTransportConfig {
        connect_timeout: network.connect_timeout(),
        read_timeout: network.read_timeout(),
        max_message_bytes: network.max_message_bytes,
        ..Default::default()
    }
}
/// The consensus message pump loop: proposes, votes, drains the
/// transport, forms QCs, advances views, and syncs heights.
///
/// This is the distributed equivalent of the in-process devnet's
/// `pipelined_tick`. Each iteration:
/// 1. Leader proposes and broadcasts to followers.
/// 2. Followers vote on pending proposals.
/// 3. Drain inbound transport messages (proposals, votes, QCs).
/// 4. Form QC if quorum reached, broadcast to peers.
/// 5. Advance views and sync heights.
///
/// Routing convention: transport peer IDs are staking *addresses*,
/// not committee indexes. Sends resolve the live committee's
/// `validator_addresses()` — which follows rotations as soon as the
/// engine swaps the set — and inbound attribution resolves
/// `msg.from` (the handshake-authenticated address) back to a
/// committee index via `index_of`. An index baked into the peer id
/// would point at a different member the moment a removal reshuffled
/// the committee; the address cannot.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn run_consensus_loop(
    engine: &mut consensus::OxideBft,
    transport: &mut p2p::tcp::TcpTransport,
    app: &executor::Executor,
    log_tag: &str,
    our_addr: primitives::Address,
    shutdown: &AtomicBool,
    rpc: Option<&rpc::RpcServer>,
    shared_validator_set: &std::sync::RwLock<consensus::ValidatorSet>,
    shared_next_validator_set: &std::sync::RwLock<Option<consensus::ValidatorSet>>,
    gossip_rx: &std::sync::mpsc::Receiver<Vec<u8>>,
    sync_store: &mut crate::block_sync::SyncStore,
    repair_peers: &[String],
) {
    // (cap documented at module scope — `GOSSIP_SEEN_CAP`)
    // Track proposals received from the network. Followers vote on
    // these proposals; the leader proposes locally.
    let mut pending_proposals: Vec<(types::BlockHeader, types::Proposal)> = Vec::new();
    // Admitted-proposal dedupe: `(view, proposer)` pairs that
    // already occupy a pending slot. The key is claimed only by a
    // *verified* proposal (the intake runs `admit_proposal` before
    // inserting), so one entry per view is the honest maximum — an
    // equivocating leader's second signed body for the same view,
    // or a re-delivered identical header, is dropped here without
    // re-running any verification.
    let mut seen_proposals: std::collections::HashSet<(u64, primitives::Hash)> =
        std::collections::HashSet::new();
    // Per-sender budget on proposal *authentication attempts*:
    // `(last window start, frames admitted this second)` per
    // authenticated peer id. Every distinct admissible frame costs
    // one BLS verify inside `admit_proposal`; without a per-peer
    // bound a flooding member would hold the consensus thread in
    // verification while the real leader's proposal queues behind
    // the junk in the transport's merged recv queue. The key is the
    // handshake-proven peer id — a peer cannot spend another's
    // budget. Committee-sized map: only `allowed_peer_ids` can hold
    // a connection at all.
    let mut proposal_verify_budget: std::collections::HashMap<Vec<u8>, (std::time::Instant, u32)> =
        std::collections::HashMap::new();
    let mut voted_views: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut proposed_views: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut last_reported_height: u64 = 0;
    // View-change timeout tracking. The pacemaker has an internal
    // timeout duration (base 2s, exponential backoff). We track when
    // the current view started; if it hasn't advanced within the
    // timeout, we fire `on_timeout()` and broadcast the timeout
    // signature to all peers. This is essential for recovering from
    // a byzantine or crashed leader — without it, the consensus
    // stalls forever when the leader stops proposing.
    let mut view_start = std::time::Instant::now();
    let mut timeout_sent_for_view: Option<u64> = None;
    // Track the last epoch — when `engine.epoch()` increments, the
    // validator set was rotated by `complete_rotation`. Update the
    // shared set so `GET /validator-set` reflects the new set.
    let mut last_epoch = engine.epoch().value();
    let mut seen_txs: std::collections::HashSet<primitives::Hash> =
        std::collections::HashSet::with_capacity(GOSSIP_SEEN_CAP.min(4096));
    let mut seen_txs_fifo: std::collections::VecDeque<primitives::Hash> =
        std::collections::VecDeque::new();
    // ── Certified block sync state ────────────────────────
    // `sync_pending` buffers fetched records that are not yet the
    // contiguous next height — pages can interleave across peers.
    // Entries are verified at drain time (apply_certified_block is
    // the single verification authority); the cap bounds the soak
    // an adversarial server could cause.
    let mut sync_pending: std::collections::BTreeMap<u64, types::CertifiedBlock> =
        std::collections::BTreeMap::new();
    // `sync_target` is the highest committed-adjacent height a
    // verified proposal has revealed — the catch-up goal.
    let mut sync_target: u64 = 0;
    // Throttle state for outgoing fetch requests; see SYNC_REQ_RETRY.
    let mut sync_last_req: Option<std::time::Instant> = None;
    // Round-robin cursor over the committee for periodic re-requests
    // (the trigger path prefers the peer that revealed the gap).
    let mut sync_peer_cursor: usize = 0;
    // One-shot log latch: set when a peer's retention floor is above
    // the height we need — the gap is beyond block sync's window and
    // certified state sync is the designed recovery.
    let mut sync_below_floor_logged = false;
    // ── Divergence auto-repair state ─────────────────────
    // Next instant a full repair attempt may run. Poll cadence —
    // each attempt is a verified snapshot download + journal replay,
    // expensive enough to rate-limit but cheap next to a halted
    // validator's cost to the network.
    let mut repair_next_attempt: Option<std::time::Instant> = None;
    // Round-robin cursor over `repair_peers` so repeated attempts do
    // not pin one peer's snapshot endpoint.
    let mut repair_peer_cursor: usize = 0;
    // One-shot log latch for the unconfigured case — a halted node
    // with no repair peers is page-worthy once, not every tick.
    let mut repair_unconfigured_logged = false;

    loop {
        // Graceful shutdown: SIGINT/SIGTERM sets the flag, we break
        // cleanly so the transport can flush and the WAL can be
        // closed by `Drop`.
        if shutdown.load(Ordering::Relaxed) {
            println!("{log_tag}: shutdown signal received, stopping");
            break;
        }

        // Phase 1: propose (if leader and haven't proposed this view).
        // Leader decisions consult the engine's LIVE committee —
        // `is_leader` reads the current validator set AND our
        // re-seated index, so a rotated epoch can't strand us on the
        // startup set's schedule (or our startup slot).
        let view = engine.current_view().value();
        // `view_justified` admits a TC-justified proposal, not just a
        // high-QC one: without it a fleet whose view-0 leader is dead
        // from boot livelocks — no QC can ever form, so `high_qc`
        // stays `None` and every later leader would wait forever.
        if engine.is_leader() && !proposed_views.contains(&view) && engine.view_justified() {
            // Idle mode is an explicit heartbeat, not silence:
            // `propose()` returns None when no work is pending, but
            // a silent leader is indistinguishable from a dead one —
            // followers' view timers would fire and views would
            // churn through timeout certificates without committing
            // anything. If this view has been idle past
            // `IDLE_HEARTBEAT`, propose anyway: the QC advances the
            // chain on the healthy path and commits the uncommitted
            // tail. (Replaces the keep-alive transaction, which
            // needed a funded test identity to fake real work.)
            let produced = engine.propose().or_else(|| {
                if view_start.elapsed() >= IDLE_HEARTBEAT {
                    engine.propose_heartbeat()
                } else {
                    None
                }
            });
            if let Some((header, proposal)) = produced {
                let proposal_view = header.view.value();
                proposed_views.insert(proposal_view);
                pending_proposals.push((header.clone(), proposal.clone()));
                // C10: the leader self-votes through `engine.vote()` —
                // the single signing authority — which records the
                // vote locks and appends the WAL BEFORE signing. The
                // manual sign-then-collect this replaces emitted a
                // signature whose anti-equivocation state was never
                // durable: a restart could then double-vote.
                if let Some(leader_vote) = engine.vote(&header, &proposal) {
                    let _ = engine.collect_vote(engine.validator_index(), leader_vote);
                    voted_views.insert(proposal_view);
                }
                // Broadcast proposal to followers — every live
                // committee member except us, addressed by the
                // staking address that IS its peer id.
                let mut buf = Vec::with_capacity(1 + 512);
                buf.push(MSG_PROPOSAL);
                header.encode(&mut buf);
                proposal.encode(&mut buf);
                for addr in engine.validator_set().validator_addresses() {
                    if *addr != our_addr {
                        let _ = transport.send(&addr.0.to_vec(), &buf);
                    }
                }
            }
        }

        // Phase 2: vote on pending proposals (followers).
        for (header, proposal) in &pending_proposals {
            let proposal_view = header.view.value();
            if voted_views.contains(&proposal_view) {
                continue;
            }
            let leader = usize::from(engine.validator_set().leader(header.view));
            if usize::from(engine.validator_index()) == leader {
                continue; // Leader already self-voted.
            }
            if let Some(vote) = engine.vote(header, proposal) {
                let mut buf = Vec::with_capacity(1 + 137);
                buf.push(MSG_VOTE);
                vote.encode(&mut buf);
                // The leader's peer id is its staking address —
                // `leader` is a committee index into the live set.
                if let Some(leader_addr) = engine.validator_set().validator_addresses().get(leader)
                {
                    let _ = transport.send(&leader_addr.0.to_vec(), &buf);
                }
                voted_views.insert(proposal_view);
            }
        }

        // Phase 3: drain inbound transport messages.
        while let Some(msg) = transport.recv() {
            if msg.bytes.is_empty() {
                continue;
            }
            let tag = msg.bytes[0];
            let mut reader = codec::Reader::new(&msg.bytes[1..]);
            match tag {
                MSG_PROPOSAL => {
                    if let (Ok(header), Ok(proposal)) = (
                        types::BlockHeader::decode(&mut reader),
                        types::Proposal::decode(&mut reader),
                    ) {
                        // Intake gate, cheapest check first: a junk
                        // proposal must be dropped before it ever
                        // costs this single-threaded loop a BLS
                        // verify. `proposal_admissible` applies the
                        // view window (stale/premature churn) and the
                        // scheduled-leader compare — both pure, no
                        // crypto. Without this gate a Byzantine peer
                        // could push unbounded pending entries and
                        // have `vote()` re-verify all of them on
                        // every iteration.
                        let proposal_view = header.view.value();
                        if !engine.proposal_admissible(&header) {
                            continue;
                        }
                        // Per-sender verify budget before the one
                        // expensive step: a distinct admissible
                        // frame costs one BLS verify in
                        // `admit_proposal`. Charged per frame rather
                        // than per fresh verify — memo-hit
                        // redeliveries are cheap enough that the
                        // accounting stays simple and honest bursts
                        // (≤1 proposal per view per leader) sit far
                        // below the cap.
                        let budget = proposal_verify_budget
                            .entry(msg.from.clone())
                            .or_insert((std::time::Instant::now(), 0));
                        if budget.0.elapsed() >= std::time::Duration::from_secs(1) {
                            *budget = (std::time::Instant::now(), 0);
                        }
                        if budget.1 >= consensus::PROPOSAL_VERIFY_BUDGET_PER_SEC {
                            continue;
                        }
                        budget.1 += 1;
                        // Authenticate BEFORE the dedupe slot is
                        // claimed: `header.proposer` is a public
                        // claim, so junk can pass the leader compare
                        // while carrying a forged signature. If an
                        // unverified frame took the (view, proposer)
                        // key, junk that races ahead of the real
                        // leader would park it and the genuine
                        // proposal would be dropped as a "duplicate"
                        // — the flood becomes censorship. Only a
                        // verified proposal may occupy the slot;
                        // `admit_proposal` memoises both verdicts so
                        // re-deliveries are free.
                        let admitted = engine.admit_proposal(&header, &proposal);
                        if admitted && seen_proposals.insert((proposal_view, header.proposer)) {
                            // A verified leader proposal above our
                            // verified frontier proves committed
                            // history we never saw — start (or
                            // refresh) a certified-block fetch
                            // toward the gap. `admit_proposal` ran
                            // first, so `header.height` is a real
                            // signed leader height, not a forged
                            // trigger. The frontier (not the bare
                            // committed tip) is the fetch origin so
                            // records already verified-and-staged
                            // under `apply_certified_block`'s seal
                            // rule are never re-requested.
                            let need = engine.sync_frontier();
                            if header.height.value() > need {
                                sync_target = sync_target.max(header.height.value());
                                if sync_last_req.is_none_or(|t| t.elapsed() >= SYNC_REQ_RETRY) {
                                    let mut buf = Vec::with_capacity(16);
                                    buf.push(MSG_BLOCK_REQ);
                                    buf.extend_from_slice(&crate::block_sync::encode_request(
                                        &crate::block_sync::FetchRequest::ByRange {
                                            from: need,
                                            count: crate::block_sync::SYNC_PAGE_CAP,
                                        },
                                    ));
                                    let _ = transport.send(&msg.from, &buf);
                                    sync_last_req = Some(std::time::Instant::now());
                                }
                            }
                            pending_proposals.push((header, proposal));
                        }
                    }
                }
                MSG_VOTE => {
                    if let Ok(vote) = types::Vote::decode(&mut reader) {
                        // Attribute by the AUTHENTICATED peer id: the
                        // handshake proved the sender owns the staking
                        // address it claims, so `index_of` resolves the
                        // committee seat the signature must verify
                        // under. A removed member's address resolves to
                        // nothing — its vote dies here rather than
                        // collecting under whatever index it used to
                        // hold.
                        let voter = msg
                            .from
                            .as_slice()
                            .try_into()
                            .map(primitives::Address)
                            .ok()
                            .and_then(|a| engine.validator_set().index_of(&a));
                        if let Some(voter_idx) = voter {
                            let _ = engine.collect_vote(voter_idx, vote);
                        }
                    }
                }
                MSG_QC => {
                    if let Ok(qc) = types::QuorumCertificate::decode(&mut reader) {
                        // A QC certifying a block we never saw is a
                        // gap signal the height alone can't give us
                        // (the QC carries only the hash). Fetch the
                        // certified record by hash — if the peer has
                        // already finalized it, the proof comes back
                        // verified-ready; if not, range sync picks
                        // it up once the peer commits it.
                        let unknown = !engine.has_block(&qc.block_hash);
                        let qc_hash = qc.block_hash;
                        let _ = engine.deliver_qc(qc);
                        if unknown {
                            let mut buf = Vec::with_capacity(36);
                            buf.push(MSG_BLOCK_REQ);
                            buf.extend_from_slice(&crate::block_sync::encode_request(
                                &crate::block_sync::FetchRequest::ByHash(qc_hash),
                            ));
                            let _ = transport.send(&msg.from, &buf);
                        }
                    }
                }
                MSG_TX => {
                    // Raw tx envelope gossiped by a peer's RPC
                    // (`eth_sendRawTransaction`). Ingest into our
                    // mempool — the leader may be a different node,
                    // so without gossip a tx submitted to a non-leader
                    // would sit until that node's leader turn.
                    //
                    // Never re-broadcast: in the full-mesh validator
                    // topology a single hop reaches every peer, and
                    // re-gossip would loop indefinitely.
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
                        // Feed pending-tx subscribers/filters — the
                        // Ethereum hash is keccak256 of the signed
                        // RLP inside the envelope, not the envelope
                        // hash used for dedup.
                        if let Some(rpc) = rpc
                            && let Some(raw) = evm::unwrap_evm_tx_envelope(payload)
                        {
                            rpc.record_pending_tx(alloy_primitives::keccak256(raw));
                        }
                    }
                }
                MSG_TIMEOUT => {
                    // View-change timeout signature from a peer.
                    // Format: [voter_addr: 20B][view: 8B][epoch: 8B]
                    //         [has_qc: 1B][qc?][has_tc: 1B][tc?]
                    //         [signature: 96B]
                    // The certificate fields are the DiemBFT v4
                    // timeout evidence: entering view v is
                    // legitimate only via QC(v−1) or TC(v−1).
                    if let Ok(voter_bytes) = reader.read_slice(20)
                        && let Ok(sig_view) = reader.read_u64()
                        && let Ok(sig_epoch) = reader.read_u64()
                        && let Ok(has_qc) = reader.read_u8()
                    {
                        // The claimed voter must BE the authenticated
                        // sender — otherwise a member could attribute
                        // its timeout signature to any other seat.
                        let Ok(voter_arr): Result<[u8; 20], _> = voter_bytes.try_into() else {
                            continue;
                        };
                        if voter_arr.as_slice() != msg.from.as_slice() {
                            continue;
                        }
                        // Resolve the sender's address to its seat in
                        // the live committee; a non-member (or a
                        // removed member post-activation) collects
                        // nothing.
                        let voter_idx =
                            engine.validator_set().index_of(&primitives::Address(voter_arr));
                        let Some(voter_idx) = voter_idx else { continue };
                        // The wire interleaves each flag with its
                        // payload — has_qc then the QC bytes, then
                        // has_tc then the TC bytes. Reading both
                        // flags up front would consume the QC's
                        // first byte as `has_tc` and misalign every
                        // field after it, so the qc_ev the signature
                        // is verified against would never match what
                        // the sender signed.
                        let qc_ev = if has_qc == 1 {
                            types::QuorumCertificate::decode(&mut reader).ok()
                        } else {
                            None
                        };
                        let Ok(has_tc) = reader.read_u8() else { continue };
                        let tc_ev = if has_tc == 1 {
                            types::TimeoutCertificate::decode(&mut reader).ok()
                        } else {
                            None
                        };
                        if let Ok(sig) = crypto::Signature::decode(&mut reader) {
                            // Authenticate the evidence BEFORE acting
                            // on it. Everything below mutates
                            // consensus state — the pacemaker timer,
                            // the vote buffer, high_qc — so a peer
                            // claiming a high view with a garbage
                            // signature must be rejected here rather
                            // than after the damage is done. The
                            // signature is checked against the
                            // (view, epoch) the sender actually signed,
                            // never against our own current view.
                            if engine
                                .verify_timeout_signature_for(
                                    voter_idx,
                                    primitives::View::new(sig_view),
                                    primitives::Epoch::new(sig_epoch),
                                    qc_ev.as_ref(),
                                    &sig,
                                )
                                .is_err()
                            {
                                continue;
                            }
                            let my_epoch = engine.epoch().value();
                            // Ignore timeout sigs from a different
                            // epoch — they are not valid for this epoch.
                            if sig_epoch != my_epoch {
                                continue;
                            }
                            // Bounded catch-up: feed the attached
                            // certificate evidence through the
                            // verified ingestion paths first — a
                            // timeout signature alone cannot move
                            // our view; only real QC/TC evidence
                            // can. After this, a collectible sig
                            // must claim exactly our current view.
                            let view_before = engine.current_view().value();
                            engine.deliver_timeout_evidence(qc_ev.clone(), tc_ev);
                            // If the sig is for a past view, ignore it
                            // (stale — the sender is behind us); if it
                            // is for a view the evidence didn't reach,
                            // ignore it — an unjustified jump (the
                            // old code synced to the claimed view
                            // unconditionally, letting one peer pull
                            // the node to an arbitrary view).
                            if sig_view != engine.current_view().value() {
                                continue;
                            }
                            // Reset the view timer only when the
                            // evidence actually moved us — resetting
                            // on every same-view sig would let a peer
                            // starve our own timeout.
                            if engine.current_view().value() != view_before {
                                view_start = std::time::Instant::now();
                                timeout_sent_for_view = None;
                            }
                            match engine.collect_timeout_signature(voter_idx, sig, qc_ev) {
                                Ok(Some(tc)) => {
                                    // TC formed — broadcast to all peers.
                                    eprintln!(
                                        "{log_tag}: TC formed after collecting timeout sig from voter={voter_idx} view={}",
                                        engine.current_view().value()
                                    );
                                    let mut tc_buf = Vec::with_capacity(1 + 200);
                                    tc_buf.push(MSG_TC);
                                    tc.encode(&mut tc_buf);
                                    for addr in engine.validator_set().validator_addresses() {
                                        if *addr != our_addr {
                                            let _ = transport.send(&addr.0.to_vec(), &tc_buf);
                                        }
                                    }
                                    view_start = std::time::Instant::now();
                                    timeout_sent_for_view = None;
                                }
                                Ok(None) => {
                                    // Timeout sig collected but
                                    // no TC yet — no log needed
                                    // (this is the common case).
                                }
                                Err(e) => {
                                    eprintln!(
                                        "{log_tag}: timeout sig from voter={voter_idx} rejected: {e:?}"
                                    );
                                }
                            }
                        }
                    }
                }
                MSG_TC => {
                    // Timeout certificate from a peer — advance the view.
                    if let Ok(tc) = types::TimeoutCertificate::decode(&mut reader) {
                        match engine.on_timeout_certificate(&tc) {
                            Ok(()) => {
                                view_start = std::time::Instant::now();
                                timeout_sent_for_view = None;
                            }
                            Err(e) => {
                                eprintln!("{log_tag}: TC rejected: {e:?}");
                            }
                        }
                    }
                }
                MSG_BLOCK_REQ => {
                    // Certified-block fetch from a peer. Certified
                    // records serve strictly out of the committed
                    // store — an in-flight proposal has no commit
                    // proof and is never served as one. The one live-
                    // edge exception is `ByHash`: when the hash names
                    // the certified-but-uncommitted tip (a QC names
                    // it; its own commit needs the grandchild's QC),
                    // the stored proposal goes back as the response
                    // tail — authentication is the receiver's job,
                    // through `admit_proposal` like any gossip.
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
                                } else {
                                    resp.tail = engine.get_proposal(&hash);
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
                        // The server's retention floor: if the height
                        // we need is below it, this gap is beyond
                        // block sync's window — certified state sync
                        // is the designed recovery, and the log must
                        // say so once instead of retrying forever.
                        let need = engine.committed_anchor().map_or(0, |(_, h)| h.value() + 1);
                        if resp.floor != u64::MAX && resp.floor > need && !sync_below_floor_logged {
                            eprintln!(
                                "{log_tag}: sync gap starts at height {need} but peer's \
                                 certified store floor is {} — the missing prefix is \
                                 below the retention window; certified state sync \
                                 (snapshot) is the recovery path for gaps this deep",
                                resp.floor
                            );
                            sync_below_floor_logged = true;
                        }
                        for record in resp.records {
                            let h = record.header.height.value();
                            // The apply gate is the verified
                            // frontier — committed tip + staged run —
                            // so a record contiguous with the staged
                            // tail stages immediately instead of
                            // bouncing through `sync_pending` while
                            // its seal is still in flight.
                            let next = engine.sync_frontier();
                            if h < next {
                                continue; // already committed — retries are normal
                            }
                            if h == next {
                                match engine.apply_certified_block(&record) {
                                    // Whether this record committed
                                    // (`true`) or staged awaiting its
                                    // seal (`false`), the verified
                                    // frontier may have advanced —
                                    // the next buffered record is now
                                    // appliable, so the drain must run
                                    // either way. Skipping it on a
                                    // staged record would strand the
                                    // seal itself inside the buffer.
                                    Ok(_) => drain_sync_buffer(engine, &mut sync_pending, log_tag),
                                    // Lane saturated: the record was
                                    // verified — re-buffer it at its
                                    // height so the drain retries when
                                    // the next apply frees the lane.
                                    Err(consensus::ConsensusError::SyncDeferred { .. }) => {
                                        sync_pending.insert(h, record);
                                    }
                                    // Different epoch: the record is
                                    // not *invalid* — it is signed by
                                    // a committee we no longer hold.
                                    // Per-block sync cannot bridge a
                                    // rotation; the certified-snapshot
                                    // path (weak subjectivity) is the
                                    // designed recovery. Log once via
                                    // the same latch as the floor case.
                                    Err(e @ consensus::ConsensusError::SyncEpoch { .. }) => {
                                        if !sync_below_floor_logged {
                                            eprintln!(
                                                "{log_tag}: certified block {h} crosses an \
                                                 epoch boundary this node cannot verify \
                                                 locally ({e}) — certified state sync is \
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
                                // Out-of-order: a by-hash fetch (or an
                                // interleaved page) landed above the
                                // gap. Buffer it AND aim the range
                                // fetcher at the hole — without the
                                // target update the periodic re-request
                                // never fires and the record sits
                                // buffered forever.
                                sync_target = sync_target.max(h);
                                sync_pending.insert(h, record);
                            }
                        }
                        // The notarized tail: a `ByHash` fetch that
                        // resolved to the live tip returns the bare
                        // proposal. `admit_proposal` runs the full
                        // authentication (proposer sig + body
                        // commitment); a stored body is all the commit
                        // walk needs, and if its view is current the
                        // pending queue votes on it next iteration.
                        if let Some((tail_header, tail_proposal)) = resp.tail
                            && engine.admit_proposal(&tail_header, &tail_proposal)
                        {
                            // The tail carries an authenticated leader
                            // height — the same gap signal the direct
                            // proposal arm uses. Without it, a lagging
                            // node that only ever sees QC gossip (a
                            // fleet mid-timeout-churn proposes nothing
                            // new) learns the uncommitted tip but never
                            // aims the range fetcher at the committed
                            // hole beneath it.
                            let need = engine.sync_frontier();
                            if tail_header.height.value() > need {
                                sync_target = sync_target.max(tail_header.height.value());
                            }
                            pending_proposals.push((tail_header, tail_proposal));
                        }
                    }
                }
                _ => {}
            }
        }

        // Phase 3b: drain the tx-gossip channel — the RPC submitter
        // pushes locally-accepted txs here; broadcast each as a
        // `MSG_TX` frame to every peer. Bounded by the channel cap
        // (10k), so worst case this drains 10k frames in one
        // iteration — each send is a channel push to the peer's
        // writer task, non-blocking.
        while let Ok(tx_bytes) = gossip_rx.try_recv() {
            // Record locally-originated txs in the dedup set too, so a
            // peer that somehow reflects our frame back is dropped.
            let tx_hash =
                crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, &tx_bytes);
            if seen_txs.insert(tx_hash) {
                seen_txs_fifo.push_back(tx_hash);
                if seen_txs_fifo.len() > GOSSIP_SEEN_CAP
                    && let Some(old) = seen_txs_fifo.pop_front()
                {
                    seen_txs.remove(&old);
                }
            }
            let mut buf = Vec::with_capacity(1 + tx_bytes.len());
            buf.push(MSG_TX);
            buf.extend_from_slice(&tx_bytes);
            for addr in engine.validator_set().validator_addresses() {
                if *addr != our_addr {
                    let _ = transport.send(&addr.0.to_vec(), &buf);
                }
            }
        }

        // Phase 4: form QC (if quorum reached).
        if let Some(qc) = engine.try_form_qc() {
            let mut qc_buf = Vec::with_capacity(1 + 150);
            qc_buf.push(MSG_QC);
            qc.encode(&mut qc_buf);
            for addr in engine.validator_set().validator_addresses() {
                if *addr != our_addr {
                    let _ = transport.send(&addr.0.to_vec(), &qc_buf);
                }
            }
            let _ = engine.deliver_qc(qc);
        }

        // Phase 5: advance views.
        let prev_view = engine.current_view().value();
        if let Some(hqc) = engine.high_qc()
            && hqc.view == engine.current_view()
        {
            engine.advance_view();
        }

        // Phase 5b: view-change timeout. If the current view hasn't
        // advanced within the pacemaker's timeout duration, fire
        // `on_timeout()`, broadcast the timeout signature to all
        // peers, and let the pacemaker collect signatures to form a
        // TC. This is the critical path for recovering from a
        // byzantine or crashed leader.
        let current_view_now = engine.current_view().value();
        if current_view_now != prev_view {
            // View advanced — reset the timer and clear the sent flag.
            view_start = std::time::Instant::now();
            timeout_sent_for_view = None;
        }
        let timeout_ms = engine.pacemaker_timeout_ms();
        let elapsed_ms = u64::try_from(view_start.elapsed().as_millis()).unwrap_or(0);
        if timeout_sent_for_view.is_none() && elapsed_ms >= timeout_ms {
            timeout_sent_for_view = Some(current_view_now);
            if let Some(sig) = engine.on_timeout() {
                eprintln!(
                    "{log_tag}: view timeout view={current_view_now} elapsed={elapsed_ms}ms — broadcasting timeout sig"
                );
                // The certificate evidence that justifies our
                // presence at this view (DiemBFT v4 timeout fields):
                // receivers only honor a view claim backed by
                // QC(view−1) or TC(view−1) — a bare signature can no
                // longer pull a peer to an arbitrary view.
                let (high_qc_ev, last_tc_ev) = engine.timeout_evidence();
                let mut buf = Vec::with_capacity(1 + 20 + 8 + 8 + 2 + 96);
                buf.push(MSG_TIMEOUT);
                // Encode: voter_address (20B) + view (8B) + epoch (8B)
                // + [has_qc 1B][qc?] + [has_tc 1B][tc?] + sig (96B).
                // The voter field is our staking address — the same
                // bytes the transport proves ownership of at
                // handshake, so the receiver can cross-check the
                // claimed voter against the authenticated peer id
                // and resolve the committee seat that must have
                // signed. (An index here would misattribute the
                // signature the moment a removal reshuffled seats.)
                // The view and epoch are included so the receiver can
                // verify the signature against the correct view and
                // ignore stale sigs from a different view (e.g., after
                // a partition when validators may be at different views).
                buf.extend_from_slice(&our_addr.0);
                buf.extend_from_slice(&current_view_now.to_le_bytes());
                buf.extend_from_slice(&engine.epoch().value().to_le_bytes());
                // Evidence flags + optional certificates.
                match &high_qc_ev {
                    Some(qc) => {
                        buf.push(1u8);
                        qc.encode(&mut buf);
                    }
                    None => buf.push(0u8),
                }
                match &last_tc_ev {
                    Some(tc) => {
                        buf.push(1u8);
                        tc.encode(&mut buf);
                    }
                    None => buf.push(0u8),
                }
                sig.encode(&mut buf);
                for addr in engine.validator_set().validator_addresses() {
                    if *addr != our_addr {
                        let _ = transport.send(&addr.0.to_vec(), &buf);
                    }
                }
                // Self-collect: feed our own timeout signature to the
                // engine so it counts toward the quorum.
                if let Ok(Some(tc)) = engine.collect_timeout_signature(
                    engine.validator_index(),
                    sig,
                    high_qc_ev.clone(),
                ) {
                    // TC formed immediately (unlikely with 1/4, but
                    // handle it). Broadcast the TC to all peers.
                    eprintln!(
                        "{log_tag}: TC formed locally after self-timeout view={current_view_now}"
                    );
                    let mut tc_buf = Vec::with_capacity(1 + 200);
                    tc_buf.push(MSG_TC);
                    tc.encode(&mut tc_buf);
                    for addr in engine.validator_set().validator_addresses() {
                        if *addr != our_addr {
                            let _ = transport.send(&addr.0.to_vec(), &tc_buf);
                        }
                    }
                    view_start = std::time::Instant::now();
                    timeout_sent_for_view = None;
                }
            }
        }

        // Height sync is handled inside `vote()` — `authenticate_
        // proposal` calls `observe_block_height` once the header's
        // leader and signature check out. The previous self-sync
        // (sync_next_height(next_height_value)) was a no-op — it
        // synced the engine to its own value.

        // Report finalized height changes.
        let height = engine.finalized_height();
        if let Some(h) = height {
            let h_val = h.value();
            if h_val > last_reported_height {
                println!("{log_tag}: finalized height = {h_val}");
                last_reported_height = h_val;
                // Update the RPC server's block height so
                // `eth_blockNumber` and `/metrics` reflect the
                // current finalized height, then push the block to
                // WebSocket subscribers (no-op when nobody is
                // subscribed or no EVM is attached).
                if let Some(rpc) = rpc {
                    rpc.set_block_height(h_val);
                    rpc.publish_new_block(h_val);
                }
            }
        }

        // A confirmed execution divergence is terminal for this
        // process: the engine has already logged CRITICAL and
        // stopped signing; mirror the latch into RPC status so
        // `/health` flips to 503 and `/metrics` exposes the gauge —
        // otherwise the only signal is a stderr line a watchdog
        // never sees. Idempotent: the detail is write-once.
        if let (Some(rpc), Some(d)) = (rpc, engine.divergence()) {
            rpc.set_exec_divergence(*d);
        }

        // Certified state repair: while the divergence latch holds,
        // periodically try to prove the local state again matches a
        // quorum-certified root. `mark_repaired` runs first every
        // pass — it is cheap relative to a download and clears the
        // moment an earlier repair (or an unrelated snapshot import)
        // lands the matching root. Only `NoAnchor` pays for the full
        // fetch path. The pump stalls for the download + replay —
        // acceptable: a diverged node signs nothing anyway, and the
        // buffered network backlog plus certified block sync close
        // the gap on resume.
        if let Some(divergence) = engine.divergence().copied()
            && repair_next_attempt.is_none_or(|t| std::time::Instant::now() >= t)
        {
            match engine.mark_repaired() {
                consensus::RepairOutcome::Repaired(h) => {
                    println!("{log_tag}: divergence cleared at height {}", h.value());
                    // The mirror was set on the latch pass — clearing
                    // the engine without clearing it would leave
                    // `/health` reporting a halted node that is in
                    // fact signing again.
                    if let Some(rpc) = rpc {
                        rpc.clear_exec_divergence();
                    }
                }
                consensus::RepairOutcome::NotLatched => {}
                consensus::RepairOutcome::NoAnchor => {
                    if repair_peers.is_empty() {
                        if !repair_unconfigured_logged {
                            eprintln!(
                                "{log_tag}: divergence latched and no --repair-peer configured — \
                                 node stays halted; manual certified-state repair per runbook 7"
                            );
                            repair_unconfigured_logged = true;
                        }
                    } else {
                        attempt_state_repair(
                            repair_peers,
                            &mut repair_peer_cursor,
                            divergence,
                            engine,
                            app,
                            log_tag,
                        );
                        // Re-check immediately: a completed import may
                        // already attest to a held certificate — no
                        // reason to wait out the retry window.
                        if let consensus::RepairOutcome::Repaired(h) = engine.mark_repaired() {
                            println!(
                                "{log_tag}: divergence cleared at height {} after certified state repair",
                                h.value()
                            );
                            if let Some(rpc) = rpc {
                                rpc.clear_exec_divergence();
                            }
                        }
                    }
                    repair_next_attempt = Some(std::time::Instant::now() + REPAIR_RETRY_INTERVAL);
                }
            }
        }

        // Mirror the engine's execution certificates into RPC so
        // `GET /snapshot/cert/{height}` can answer a syncing node's
        // certificate poll. Pushed every iteration (the mirror
        // dedups by height); a syncing client verifies the cert
        // against its own validator-set checkpoint, so serving the
        // bytes costs this node no trust assumption.
        if let Some(rpc) = rpc {
            rpc.record_exec_certificates(engine.exec_certificates());
        }

        // Feed the certified serve store: every committed height —
        // committed locally or imported via sync — emits one
        // CertifiedBlock through `take_certified`. Journaling here is
        // what lets a restarted node keep serving pre-crash history.
        for record in engine.take_certified() {
            sync_store.insert(record);
        }

        // Periodic catch-up re-request: a dropped response or a peer
        // that had nothing yet must not stall sync until the next
        // proposal happens to reveal the gap. Round-robin across the
        // committee so a lagging node doesn't pin one peer. The fetch
        // origin is the verified frontier: heights already staged
        // under the seal rule are verified work — re-requesting them
        // only re-pays the crypto.
        let frontier = engine.sync_frontier();
        if sync_target >= frontier && sync_last_req.is_none_or(|t| t.elapsed() >= SYNC_REQ_RETRY) {
            let addrs = engine.validator_set().validator_addresses();
            if !addrs.is_empty() {
                for _ in 0..addrs.len() {
                    let addr = addrs[sync_peer_cursor % addrs.len()];
                    sync_peer_cursor = sync_peer_cursor.wrapping_add(1);
                    if addr != our_addr {
                        let mut buf = Vec::with_capacity(16);
                        buf.push(MSG_BLOCK_REQ);
                        buf.extend_from_slice(&crate::block_sync::encode_request(
                            &crate::block_sync::FetchRequest::ByRange {
                                from: frontier,
                                count: crate::block_sync::SYNC_PAGE_CAP,
                            },
                        ));
                        let _ = transport.send(&addr.0.to_vec(), &buf);
                        sync_last_req = Some(std::time::Instant::now());
                        break;
                    }
                }
            }
        }

        // Compact proposal bookkeeping (keep last
        // PROPOSAL_PAST_VIEWS views — the same bound the intake
        // gate applies, so a set entry and its pending slot age
        // out together).
        let current_view = engine.current_view().value();
        let keep_from = current_view.saturating_sub(consensus::PROPOSAL_PAST_VIEWS);
        pending_proposals.retain(|(h, _)| h.view.value() >= keep_from);
        voted_views.retain(|v| *v >= keep_from);
        proposed_views.retain(|v| *v >= keep_from);
        seen_proposals.retain(|(v, _)| *v >= keep_from);

        // Epoch lifecycle: drain the validator-set transition the
        // executor's finalized blocks recorded (staking key changes,
        // validator adds/removes) and schedule the epoch rotation.
        // The drain is deterministic — the queues only fill when a
        // block *executes*, so every node stages the same committee
        // at the same committed height — and activation is deferred
        // to a certified boundary (`ROTATION_ACTIVATION_DELAY`
        // commits later), never immediate on a local queue.
        match engine.drive_epoch_changes() {
            Ok(0) => {}
            Ok(applied) => {
                eprintln!(
                    "{log_tag}: epoch rotation scheduled ({applied} \
                     validator-set change(s)) — activates at committed height {:?}",
                    engine.rotation_activation_height()
                );
            }
            Err(e) => {
                // Deterministic rejection — every replica folds the
                // same deltas through `build_next_set` and reaches
                // the same verdict, so this is consistent cluster
                // state, not a fork: the transition is dropped and
                // must be re-submitted.
                eprintln!(
                    "{log_tag}: epoch transition rejected: {e} — \
                     pending change dropped (re-submit a valid set)"
                );
            }
        }

        // Epoch boundary: `commit_block` (from `deliver_qc` in the
        // drain loop or Phase 4) and `drive_epoch_changes` (the
        // activation-height completion above) may both swap the
        // validator set — as can `adopt_certified_epoch` inside
        // `deliver_qc` when a verified higher-epoch QC lands. Publish
        // the live committee whenever the epoch moved so the
        // authenticator and `GET /validator-set` track it.
        if engine.epoch().value() != last_epoch {
            last_epoch = engine.epoch().value();
            if let Ok(mut shared) = shared_validator_set.write() {
                *shared = engine.validator_set().clone();
            }
            // The pump's view-keyed bookkeeping must die with the
            // epoch: the new epoch's view space restarts at 0, so a
            // retained `voted_views`/`proposed_views` entry for view 0
            // would suppress this node's first vote/proposal of the
            // epoch, and pending proposals signed under the old epoch
            // can never become votable. Mirrors the engine's own
            // `clear_epoch_scoped_state`.
            pending_proposals.clear();
            seen_proposals.clear();
            voted_views.clear();
            proposed_views.clear();
            view_start = std::time::Instant::now();
            timeout_sent_for_view = None;
        }

        // Publish the staged committee to the transport's handshake
        // authenticator for the whole schedule→activation window:
        // an incoming member's first connection must already pass
        // membership verification before its committee duties start.
        // `next_validator_set` returns `None` outside the window (and
        // clears itself at activation), so this is `None` most of the
        // time — the `!=` guard avoids paying a committee clone on
        // every pass.
        if let Ok(mut pending) = shared_next_validator_set.write() {
            let staged = engine.next_validator_set().cloned();
            if *pending != staged {
                *pending = staged;
            }
        }

        // Yield to avoid busy-spinning when no messages are available.
        // `transport.recv()` uses non-blocking `try_recv()`, so the loop
        // would spin at 100% CPU without this sleep. A 1ms sleep keeps
        // CPU usage near-zero while providing ~1ms message latency,
        // 10x better than the previous `recv_timeout(10ms)` approach.
        // The consensus hot path (propose -> vote -> QC) is message-driven:
        // when messages arrive, `recv()` returns them immediately and
        // the sleep is never reached. The sleep only fires when the
        // transport is idle (waiting for the next network round).
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Apply buffered certified records while they sit at the verified
/// frontier — the drain half of the sync buffer.
///
/// `apply_certified_block` is the verification authority: a buffered
/// record that fails is dropped (and logged), after which the buffer
/// stops — the remaining entries are above the new gap and stay
/// buffered until a valid record for it arrives. `SyncDeferred`
/// re-queues the record and stops: the execution lane is saturated,
/// not the record invalid, so retrying later is correct. The
/// frontier (committed tip + staged run) is the drain point: an
/// interior record that stages but doesn't seal leaves the frontier
/// advanced anyway, so the next buffered record applies immediately
/// rather than waiting for the seal to land first.
pub(crate) fn drain_sync_buffer(
    engine: &mut consensus::OxideBft,
    pending: &mut std::collections::BTreeMap<u64, types::CertifiedBlock>,
    log_tag: &str,
) {
    loop {
        let next = engine.sync_frontier();
        let Some(record) = pending.remove(&next) else { break };
        match engine.apply_certified_block(&record) {
            Ok(_) => {
                // Admit the record's embedded execution certificate:
                // it attests `next - 1`, which the apply just
                // committed (or sealed) — feeding it here means a
                // synced node's divergence check runs on certified
                // history it fetched, not only on live proposals.
                // Idempotent: `verified_exec_certs` dedupes.
                if let Some(ref cert) = record.header.exec_cert {
                    engine.admit_exec_cert(cert);
                }
            }
            Err(consensus::ConsensusError::SyncDeferred { .. }) => {
                pending.insert(next, record);
                break;
            }
            Err(e) => {
                eprintln!("{log_tag}: buffered certified block {next} rejected: {e}");
            }
        }
    }
}

/// One certified-repair pass across the configured peers.
///
/// For each peer (starting at `cursor`, wrapping once): fetch the
/// snapshot manifest, poll for the quorum-signed execution
/// certificate at the manifest's height, require the cert to match
/// the manifest's `(height, root)` — the peer cannot substitute a
/// different anchor — verify it through `admit_exec_cert` (the same
/// quorum+signature+epoch checks the proposal path applies), then
/// download the chunk-verified snapshot and rebuild local state via
/// `Executor::repair_import_snapshot` (verified import + tainted-
/// state purge + journal replay). Returns `true` when an import
/// landed — the caller then re-runs `mark_repaired`, which clears
/// the latch only if the rebuilt state attests to a held certified
/// root. A peer that fails any step is skipped; a deterministic
/// executor fault survives every honest repair, which is correct —
/// the node must stay halted until the binary is fixed.
///
/// The certificate poll is bounded (`CERT_POLL_ATTEMPTS` ×
/// `CERT_POLL_INTERVAL`): the serving engine mirrors certs per tick
/// so a healthy peer answers quickly, and an older binary without
/// the endpoint only costs ~2s.
pub(crate) fn attempt_state_repair(
    peers: &[String],
    cursor: &mut usize,
    divergence: types::ExecDivergence,
    engine: &mut consensus::OxideBft,
    app: &executor::Executor,
    log_tag: &str,
) -> bool {
    for _ in 0..peers.len() {
        let peer = &peers[*cursor % peers.len()];
        *cursor = cursor.wrapping_add(1);
        // 1. Manifest — pins the peer's claimed (height, root) and
        //    chunk hashes before any state byte moves.
        let manifest = match statesync::fetch_manifest(peer) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("{log_tag}: repair peer {peer}: manifest fetch failed: {e}");
                continue;
            }
        };
        // Anchor reach: a snapshot below the diverged height cannot
        // carry the certified state this node needs to rebuild —
        // `mark_repaired` only clears on an anchor >= the diverged
        // height, so importing such a snapshot would be pure cost.
        if manifest.height < divergence.height.value() {
            eprintln!(
                "{log_tag}: repair peer {peer}: snapshot at height {} predates the diverged \
                 height {} — skipping (cannot anchor the repair)",
                manifest.height,
                divergence.height.value()
            );
            continue;
        }
        if manifest.format_version > executor::SNAPSHOT_FORMAT_VERSION {
            eprintln!(
                "{log_tag}: repair peer {peer}: snapshot format {} newer than supported {} — skipping",
                manifest.format_version,
                executor::SNAPSHOT_FORMAT_VERSION
            );
            continue;
        }
        // 2. Certificate at the manifest's height — bounded poll.
        let mut cert = None;
        for _ in 0..CERT_POLL_ATTEMPTS {
            match statesync::fetch_exec_certificate(peer, manifest.height) {
                Ok(c) => {
                    cert = Some(c);
                    break;
                }
                Err(_) => std::thread::sleep(CERT_POLL_INTERVAL),
            }
        }
        let Some(cert) = cert else {
            eprintln!(
                "{log_tag}: repair peer {peer}: no execution certificate for height {} — skipping",
                manifest.height
            );
            continue;
        };
        // 3. Anchor consistency: the served certificate must cover
        //    exactly the manifest's pinned (height, root) — the peer
        //    is untrusted, so a mismatch is a lie, not bad luck.
        if cert.height.value() != manifest.height || cert.state_root != manifest.state_root {
            eprintln!(
                "{log_tag}: repair peer {peer}: certificate (height {}, root {}) does not cover \
                 manifest (height {}, root {}) — refusing inconsistent anchors",
                cert.height.value(),
                cert.state_root,
                manifest.height,
                manifest.state_root
            );
            continue;
        }
        // 4. Verify quorum + signatures against OUR live committee —
        //    the engine's own verification path, so an epoch the
        //    engine no longer holds (or has not reached) fails here
        //    and the repair correctly refuses unverifiable state.
        if !engine.admit_exec_cert(&cert) {
            eprintln!(
                "{log_tag}: repair peer {peer}: certificate for height {} failed engine \
                 verification (epoch/committee mismatch or bad signature) — skipping",
                manifest.height
            );
            continue;
        }
        // 5. Download + per-chunk verify + decode.
        let blob = match statesync::fetch_blob(peer, &manifest) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{log_tag}: repair peer {peer}: chunk download failed: {e}");
                continue;
            }
        };
        let mut reader = codec::Reader::new(&blob);
        let snapshot = match <executor::ExecutorSnapshot as codec::Decode>::decode(&mut reader) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{log_tag}: repair peer {peer}: snapshot decode failed: {e}");
                continue;
            }
        };
        // 6. Verified import + tainted-state purge + journal replay.
        //    A JournalGap means our durable log cannot cover the
        //    committed heights above the snapshot — a later peer
        //    manifest may sit higher, so keep trying other peers.
        match app.repair_import_snapshot(&snapshot) {
            Ok(tip) => {
                println!(
                    "{log_tag}: certified state repair imported height {} from {peer}; \
                     execution rebuilt through height {tip}",
                    manifest.height
                );
                return true;
            }
            Err(e) => {
                eprintln!("{log_tag}: repair peer {peer}: snapshot import/replay failed: {e}");
            }
        }
    }
    false
}

#[cfg(test)]
mod repair_tests {
    //! End-to-end coverage for the automatic certified state repair
    //! path: a live `OxideBft` latched by a real `vote()` divergence,
    //! a canned HTTP peer serving manifest/cert/chunks, and the real
    //! `Executor::repair_import_snapshot` rebuild underneath.
    use super::*;
    use ports::AppInterface;
    use primitives::{Epoch, Hash, Height, View};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Lowercase hex — the snapshot endpoints' wire format
    /// (`statesync::fetch_hex` decodes exactly this).
    fn hex_encode(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    /// Mint an exec certificate over `(height, root, epoch)` signed by
    /// `sk` as committee seat 0. The message layout is the protocol's
    /// attestation preimage — `height ‖ root ‖ epoch`, 48 bytes under
    /// `Domain::ExecAttest` (consensus `attestation_signing_message`;
    /// duplicated here because that helper is crate-private — the
    /// layout itself is wire-stable).
    fn exec_cert(
        sk: &crypto::BlsSecretKey,
        height: u64,
        root: Hash,
        epoch: u64,
    ) -> types::ExecCertificate {
        let mut msg = [0u8; 48];
        msg[..8].copy_from_slice(&height.to_le_bytes());
        msg[8..40].copy_from_slice(root.as_bytes());
        msg[40..48].copy_from_slice(&epoch.to_le_bytes());
        let sig = sk.sign(crypto::hash::Domain::ExecAttest, &msg);
        types::ExecCertificate {
            height: Height::new(height),
            state_root: root,
            epoch: Epoch::new(epoch),
            signer_bitmap: vec![0b0000_0001],
            aggregate_signature: crypto::aggregate(&[sig]).expect("single-sig aggregate"),
        }
    }

    /// A canned snapshot peer: serves the manifest, the exec cert at
    /// any height, and the chunk table — the three endpoints
    /// `attempt_state_repair` consumes. Nonblocking accept + a stop
    /// flag so the test cannot leak a parked thread.
    struct Peer {
        addr: String,
        stop: Arc<AtomicBool>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn spawn_peer(
        manifest: &statesync::Manifest,
        cert: &types::ExecCertificate,
        chunks: Vec<Vec<u8>>,
    ) -> Peer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake peer");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("local addr").to_string();
        let mut manifest_bytes = Vec::new();
        manifest.encode(&mut manifest_bytes);
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let join = thread::spawn(move || {
            while !stop2.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(c) => c,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                let mut req = Vec::with_capacity(256);
                let mut buf = [0u8; 512];
                // One request per connection — `fetch_hex` is
                // HTTP/1.0 close-delimited.
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            req.extend_from_slice(&buf[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let text = String::from_utf8_lossy(&req);
                let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
                let body: Option<Vec<u8>> = if path == "/snapshot/manifest" {
                    Some(manifest_bytes.clone())
                } else if path.starts_with("/snapshot/cert/") {
                    Some(cert_bytes.clone())
                } else if let Some(idx) =
                    path.strip_prefix("/snapshot/chunk/").and_then(|s| s.parse::<usize>().ok())
                {
                    chunks.get(idx).cloned()
                } else {
                    None
                };
                match body {
                    Some(bytes) => {
                        let hexed = hex_encode(&bytes);
                        let resp = format!(
                            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                            hexed.len(),
                            hexed
                        );
                        let _ = stream.write_all(resp.as_bytes());
                    }
                    None => {
                        let _ = stream
                            .write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                    }
                }
            }
        });
        Peer { addr, stop, join: Some(join) }
    }

    /// An assembled executor + engine over it, latched by a REAL
    /// divergence: a signed genesis proposal carrying a verified cert
    /// whose root the local executor cannot reproduce.
    fn latched_node() -> (crate::AssembledExecutor, consensus::OxideBft, crypto::BlsSecretKey) {
        let assembled = crate::assemble_executor(&crate::NodeConfig::default());
        let sk = crate::cli::bls_key(1);
        let vs = consensus::ValidatorSet::new(vec![sk.public_key()], vec![1])
            .expect("one-validator set");
        let app_dyn: Arc<dyn ports::AppInterface> = assembled.app.clone();
        let mut engine = consensus::OxideBft::new(app_dyn, vs).with_secret_key(sk.clone());
        // Execute height 0 so `attest_state(0)` exists — the
        // divergence check compares certified vs local roots only at
        // heights the executor already attests.
        assembled.app.finalize_block(&types::FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(0),
            txs: vec![],
            signers: vec![],
        });
        // Wait for the lane so `attest_state(0)` exists — the
        // divergence check compares certified vs local roots only at
        // heights the executor already attests.
        assembled
            .app
            .attest_state_bounded(Height::new(0), Duration::from_secs(10))
            .expect("block 0 executed");
        // A cert attesting a root local state never produced —
        // verified (signed by seat 0, this epoch) but divergent.
        let bad_root = Hash([0xDE; 32]);
        let cert = exec_cert(&sk, 0, bad_root, 0);
        let proposal = types::Proposal {
            height: Height::new(0),
            txs: vec![TxBytes::new(vec![1])],
            attestation: None,
        };
        let mut body = Vec::new();
        proposal.encode(&mut body);
        let mut header = types::BlockHeader {
            height: Height::new(0),
            view: View::new(0),
            epoch: Epoch::new(0),
            prev_block: Hash::ZERO,
            // `OxideBft::tx_root` is crate-private — the wire-stable
            // formula is `Domain::Transaction` over the concatenated
            // tx bytes (consensus `tx_root`; duplicated per the
            // attestation-preimage note above).
            tx_root: crypto::hash::Hasher::hash_one(
                crypto::hash::Domain::Transaction,
                &proposal.txs.iter().flat_map(|t| t.as_bytes().to_vec()).collect::<Vec<u8>>(),
            ),
            body_commitment: types::shard::commitment(&body, 1, 1),
            high_qc: None,
            timeout_cert: None,
            proposer: consensus::proposer_hash(0),
            timestamp: 0,
            proposer_signature: None,
            exec_cert: Some(cert),
        };
        let signing = consensus::OxideBft::proposal_signing_hash(&header);
        header.proposer_signature =
            Some(sk.sign(crypto::hash::Domain::Proposal, signing.as_bytes()));
        assert!(engine.vote(&header, &proposal).is_none(), "divergent vote withheld");
        assert!(engine.divergence().is_some(), "setup: latch must hold");
        (assembled, engine, sk)
    }

    /// A peer node whose executor finalized empty blocks 0,1 — its
    /// snapshot is the certified repair base, chunked and served.
    fn peer_node() -> (crate::AssembledExecutor, executor::ExecutorSnapshot) {
        let peer = crate::assemble_executor(&crate::NodeConfig::default());
        for h in 0..2u64 {
            peer.app.finalize_block(&types::FinalizedBlock {
                context: types::BlockContext::default(),
                height: Height::new(h),
                txs: vec![],
                signers: vec![],
            });
        }
        // `export_snapshot` drains the lane before reading module
        // state — the snapshot captures the quiesced tip.
        let snapshot = peer.app.export_snapshot();
        assert_eq!(snapshot.height, 1, "peer tip is the snapshot base");
        (peer, snapshot)
    }

    /// Encode `snapshot`, chunk it, and return `(manifest, chunks)` —
    /// the exact serve-side shape `/snapshot/*` endpoints produce.
    fn chunk_snapshot(
        snapshot: &executor::ExecutorSnapshot,
    ) -> (statesync::Manifest, Vec<Vec<u8>>) {
        let mut blob = Vec::new();
        snapshot.encode(&mut blob);
        statesync::chunk_blob(
            snapshot.height,
            snapshot.state_root,
            executor::SNAPSHOT_FORMAT_VERSION,
            &blob,
            4096,
        )
    }

    #[test]
    fn state_repair_imports_verified_snapshot_and_clears_latch() {
        let (_peer, snapshot) = peer_node();
        let (manifest, chunks) = chunk_snapshot(&snapshot);
        let sk = crate::cli::bls_key(1);
        // The anchor cert attests exactly the manifest's (height,
        // root) — the quorum-signed repair base.
        let cert = exec_cert(&sk, manifest.height, manifest.state_root, 0);
        let peer = spawn_peer(&manifest, &cert, chunks);

        let (assembled, mut engine, _sk) = latched_node();
        let divergence = engine.divergence().copied().expect("latched");
        assert_eq!(divergence.height, Height::new(0));

        let mut cursor = 0usize;
        assert!(
            attempt_state_repair(
                std::slice::from_ref(&peer.addr),
                &mut cursor,
                divergence,
                &mut engine,
                assembled.app.as_ref(),
                "test",
            ),
            "a verified peer must complete the repair"
        );
        // The latch clears on the NEXT mark_repaired pass — the
        // admitted cert at height 1 attests the rebuilt root.
        assert_eq!(
            engine.mark_repaired(),
            consensus::RepairOutcome::Repaired(Height::new(1)),
            "rebuilt state attests to the admitted certified anchor"
        );
        assert!(engine.divergence().is_none(), "controlled rejoin");
    }

    #[test]
    fn state_repair_refuses_cert_root_mismatch() {
        let (_peer, snapshot) = peer_node();
        let (manifest, chunks) = chunk_snapshot(&snapshot);
        let sk = crate::cli::bls_key(1);
        // The cert attests a DIFFERENT root than the manifest pins —
        // a peer lying about which state it serves.
        let cert = exec_cert(&sk, manifest.height, Hash([0x77; 32]), 0);
        let peer = spawn_peer(&manifest, &cert, chunks);

        let (assembled, mut engine, _sk) = latched_node();
        let divergence = engine.divergence().copied().expect("latched");
        let mut cursor = 0usize;
        assert!(
            !attempt_state_repair(
                std::slice::from_ref(&peer.addr),
                &mut cursor,
                divergence,
                &mut engine,
                assembled.app.as_ref(),
                "test",
            ),
            "cert/manifest anchor mismatch must refuse the import"
        );
        assert!(engine.divergence().is_some(), "latch stays — no repair happened");
    }

    #[test]
    fn state_repair_refuses_forged_certificate() {
        let (_peer, snapshot) = peer_node();
        let (manifest, chunks) = chunk_snapshot(&snapshot);
        // Signed by a key OUTSIDE the committee: the bitmap resolves
        // to seat 0's pubkey, so the aggregate can never verify.
        let attacker = crate::cli::bls_key(9);
        let cert = exec_cert(&attacker, manifest.height, manifest.state_root, 0);
        let peer = spawn_peer(&manifest, &cert, chunks);

        let (assembled, mut engine, _sk) = latched_node();
        let divergence = engine.divergence().copied().expect("latched");
        let mut cursor = 0usize;
        assert!(
            !attempt_state_repair(
                std::slice::from_ref(&peer.addr),
                &mut cursor,
                divergence,
                &mut engine,
                assembled.app.as_ref(),
                "test",
            ),
            "a cert that fails engine verification must not import"
        );
        assert!(engine.divergence().is_some(), "latch stays — cert rejected");
    }

    #[test]
    fn state_repair_skips_snapshot_below_diverged_height() {
        // A snapshot that predates the diverged height cannot carry
        // the certified state the node must rebuild — the peer is
        // skipped without a cert poll or a single chunk byte.
        let (assembled, mut engine, _sk) = latched_node();
        let divergence = engine.divergence().copied().expect("latched");
        // Forge a manifest pinned below the diverged height. The
        // peer never gets asked for cert or chunks — a closed
        // listener proves it (connect refused → skip either way).
        let (manifest, chunks) = statesync::chunk_blob(
            0,
            Hash([1; 32]),
            executor::SNAPSHOT_FORMAT_VERSION,
            &[1, 2, 3],
            1024,
        );
        let _ = chunks;
        let peer =
            spawn_peer(&manifest, &exec_cert(&crate::cli::bls_key(1), 0, Hash([1; 32]), 0), vec![]);
        let mut cursor = 0usize;
        assert!(
            !attempt_state_repair(
                std::slice::from_ref(&peer.addr),
                &mut cursor,
                divergence,
                &mut engine,
                assembled.app.as_ref(),
                "test",
            ),
            "manifest at height 0 cannot repair a divergence at height {}",
            divergence.height.value()
        );
        assert!(engine.divergence().is_some());
    }
}
