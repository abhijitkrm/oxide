//! oxide-fullnode — the full node binary.
//!
//! Two modes, one trust model:
//!
//! - **Follower mode** (`--consensus-peer`): a non-signing replica
//!   that joins the authenticated peer transport as an *observer*,
//!   pulls certified blocks through the same block-sync protocol
//!   validators use for catch-up, verifies each record's Jolteon
//!   commit proof against the checkpointed committee, executes it,
//!   and serves RPC. It never votes, proposes, or signs — the
//!   engine runs without a signer by construction.
//! - **Bootstrap-only** (no peers): `--state-sync` + `--verify-only`
//!   fetches a snapshot whose `(height, state_root)` is anchored by
//!   a quorum-signed execution certificate, imports it, and exits.
//!   Without `--verify-only` or peers the process exits non-zero —
//!   a node that cannot follow the chain is not "ready".
//!
//! Usage:
//!
//! ```sh
//! oxide-fullnode --config config/devnet.toml \
//!   --genesis-file genesis.json \
//!   --consensus-peer <validator_addr_hex>=127.0.0.1:9000 \
//!   --observer-key-file observer.key \
//!   --data-dir /var/lib/oxide --rpc-listen 127.0.0.1:8545
//! ```
//!
//! The checkpoint is a weak-subjectivity anchor: `{"epoch": E,
//! "validators": [{"address", "public_key", "stake"}]}` naming the
//! committee the operator trusts. With `--genesis-file`, the genesis
//! validator set serves as the epoch-0 checkpoint when every entry
//! carries `public_key`. `--trusted-height`/`--trusted-root` remain
//! as an optional pin pair for bootstrap mode. Each validator must
//! allowlist the follower's identity via
//! `--observer-peer <observer_id>=<observer_bls_pubkey>` — the
//! follower proves possession of its key in the peer handshake;
//! its claimed id alone is worthless.

use std::env;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use node::{Node, NodeConfig};

/// How long to poll `/snapshot/cert/{height}` for the certificate
/// covering the pinned manifest (unit: attempts × interval).
///
/// A committed height's cert forms once the next round of votes
/// aggregates the attestations — one or two views on a live chain
/// (~2-4s at the default 2s view timeout). 120 × 500ms = 60s of
/// budget tolerates loaded or slow-validator chains; a peer that
/// still cannot produce the cert after that is either dead or
/// serving state no quorum attested — refuse either way.
const CERT_POLL_ATTEMPTS: u32 = 120;
/// Interval between certificate polls. Sub-view so a cert that
/// forms mid-poll is picked up promptly; generous enough that the
/// retry loop is cheap for the server.
const CERT_POLL_INTERVAL: Duration = Duration::from_millis(500);

fn main() {
    // Supervision before anything can spawn: a panic on a critical
    // actor's thread aborts the process so the supervisor restarts a
    // coherent node instead of running half-alive.
    primitives::supervision::install_panic_hook();

    println!("oxide-fullnode: starting");

    let (cfg, config) = load_config();
    println!(
        "oxide-fullnode: engine = {}, mempool = {}",
        config.consensus.as_str(),
        config.max_mempool_entries
    );

    // Follower mode: `--consensus-peer <addr_hex>=<host:port>` names
    // at least one validator transport endpoint. With it the binary
    // runs `node::follower` — a non-signing replica that consumes
    // certified blocks and mirrors state. Without it, the only
    // honest function remains the one-shot certified bootstrap.
    let consensus_peers = resolve_consensus_peers();
    if !consensus_peers.is_empty() {
        run_follower(&cfg, &config, consensus_peers);
        return;
    }

    let mut node = Node::assemble(&config);
    bootstrap_state_sync(&mut node);

    println!("oxide-fullnode: assembled stack (executor + core/staking/evm modules)");

    // `--verify-only` makes the bootstrap-and-verify contract
    // explicit: exit 0 after a certified snapshot import. Without
    // it — and with no `--consensus-peer` — exiting 0 would claim a
    // "ready" node that cannot follow the chain.
    if std::env::args().any(|a| a == "--verify-only") {
        println!("oxide-fullnode: verify-only complete");
        return;
    }
    eprintln!(
        "oxide-fullnode: no --consensus-peer configured — the node cannot \
         follow the chain. Pass --consensus-peer <addr_hex>=<host:port> for \
         follower mode, or --verify-only for the bootstrap-and-verify flow."
    );
    std::process::exit(1);
}

/// Follower mode: consume certified blocks from validator peers and
/// mirror committed state. The trust anchor is the same
/// weak-subjectivity checkpoint `--state-sync` uses
/// (`--trusted-validators` or `--genesis-file`) — every applied
/// record's quorum signatures verify against it.
///
/// Flags:
/// - `--consensus-peer <addr_hex>=<host:port>` (repeatable,
///   required): validator transport endpoints. `addr_hex` is the
///   member's 20-byte staking address — the peer id its handshake
///   claims.
/// - `--observer-key-file <path>` (required): this follower's BLS
///   key for the handshake proof. The operator allowlists it on
///   each validator via `--observer-peer <id>=<pubkey>`.
/// - `--observer-id <addr_hex>` (optional): the claimed peer id —
///   defaults to `validator_address(observer_pubkey)`, printed at
///   startup so the operator can allowlist it.
/// - `--listen <host:port>` (optional): transport bind; peers never
///   dial a follower, so `127.0.0.1:0` suffices.
/// - `--state-sync <host:port>` (optional): fetch a certified
///   snapshot to `<data_dir>/snapshot.bin` first, then follow.
/// - `--repair-peer <host:port>` (repeatable, optional): snapshot
///   endpoints for certified state repair after a divergence halt.
/// - `--tls-dir`, `--data-dir`, `--wal-file`, `--rpc-listen`: same
///   meaning as on `oxide-validator`.
fn run_follower(cfg: &config::Config, config: &NodeConfig, peers: Vec<(Vec<u8>, String)>) {
    let (epoch, validator_set) = load_sync_checkpoint();

    // Observer identity: the handshake proof key + the claimed peer
    // id. The key is mandatory — an unauthenticated follower cannot
    // join a production transport (`BlsPeerAuth` rejects it).
    let key_path = parse_cli_flag("--observer-key-file").unwrap_or_else(|| {
        eprintln!(
            "oxide-fullnode: --consensus-peer requires --observer-key-file \
             (this node's BLS key for the peer-handshake proof)"
        );
        std::process::exit(1);
    });
    let key_bytes = node::cli::load_secret_key_file(&key_path, node::cli::SecretKind::Bls)
        .unwrap_or_else(|e| panic!("invalid observer key file {key_path}: {e}"));
    let observer_key = crypto::BlsSecretKey::from_bytes(&key_bytes[..])
        .unwrap_or_else(|e| panic!("invalid BLS secret key in {key_path}: {e:?}"));
    let signer: std::sync::Arc<dyn crypto::ConsensusSigner> =
        std::sync::Arc::new(observer_key.clone());
    let own_id: Vec<u8> = match parse_cli_flag("--observer-id") {
        Some(hex) => {
            let bytes =
                hex_decode(&hex).unwrap_or_else(|e| panic!("invalid --observer-id '{hex}': {e}"));
            assert_eq!(bytes.len(), 20, "--observer-id must be a 20-byte address");
            bytes
        }
        None => crypto::bls::validator_address(&observer_key.public_key()).0.to_vec(),
    };
    println!(
        "oxide-fullnode: observer id {} — allowlist it on validators with \
         --observer-peer {}=<pubkey>",
        node::cli::hex_encode(&own_id),
        node::cli::hex_encode(&own_id)
    );

    // Graceful shutdown: same supervised signal thread as the
    // validator — SIGINT/SIGTERM flips the flag the pump polls.
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let _ = primitives::supervision::spawn_supervised("signal-handler", false, move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("signal runtime");
        rt.block_on(async {
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("sigterm handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = sigterm.recv() => {},
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.expect("ctrl_c handler");
            }
            shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    });

    // Optional certified-snapshot bootstrap: fetch, verify against
    // the same checkpoint, and write to `<data_dir>/snapshot.bin` —
    // `follower::run`'s `import_snapshot_if_present` picks it up on
    // assembly. Writing the file (rather than importing into a
    // throwaway executor) keeps the bootstrap artifact durable: a
    // restart skips the download entirely.
    if let Some(addr) = parse_cli_flag("--state-sync") {
        let Some(ref dir) = config.durability_dir else {
            eprintln!(
                "oxide-fullnode: --state-sync in follower mode requires --data-dir \
                 (the snapshot must persist for assembly to import it)"
            );
            std::process::exit(1);
        };
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("cannot create data dir {}: {e}", dir.display()));
        fetch_certified_snapshot_to_file(&addr, epoch, &validator_set, dir);
    }

    let genesis_file = parse_cli_flag("--genesis-file").map(|p| {
        config::genesis::Genesis::from_json_file(&PathBuf::from(&p))
            .unwrap_or_else(|e| panic!("failed to load genesis file {p}: {e}"))
    });
    let genesis_alloc: Option<node::validator_net::GenesisAlloc> = genesis_file.map(|g| {
        Box::new(move |m: &evm::EvmModule| apply_evm_alloc(m, &g))
            as node::validator_net::GenesisAlloc
    });

    let rpc_listen = parse_cli_flag("--rpc-listen")
        .or_else(|| cfg.rpc.as_ref().map(|r| r.listen_addr.clone()).filter(|l| !l.is_empty()));

    node::follower::run(node::follower::FollowerSpec {
        log_tag: "oxide-fullnode".to_string(),
        validator_set,
        epoch: primitives::Epoch::new(epoch),
        own_id,
        signer,
        node_config: config.clone(),
        wal_path: parse_cli_flag("--wal-file").map(PathBuf::from),
        listen_addr: parse_cli_flag("--listen").unwrap_or_else(|| "127.0.0.1:0".to_string()),
        peers: peers.clone(),
        tls: resolve_tls_spec(&peers),
        network: cfg.network.clone(),
        genesis_alloc,
        // The resolved data dir (`--data-dir` / `[storage]
        // data_dir` → `durability_dir`) — block journal, certified
        // journal, WAL, and the snapshot.bin import/export all hang
        // off the same root.
        data_dir: config.durability_dir.clone(),
        rpc_listen,
        rpc_config: cfg.rpc.clone().unwrap_or_default(),
        repair_peers: parse_cli_flags("--repair-peer"),
        shutdown,
    });
}

/// Parse `--consensus-peer <addr_hex>=<host:port>` entries — same
/// format `oxide-validator`'s `--peer` uses: the member's 20-byte
/// staking address as peer id, its transport endpoint as host:port.
fn resolve_consensus_peers() -> Vec<(Vec<u8>, String)> {
    let mut peers: Vec<(Vec<u8>, String)> = Vec::new();
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for entry in parse_cli_flags("--consensus-peer") {
        let Some((addr_hex, hostport)) = entry.split_once('=') else {
            eprintln!(
                "oxide-fullnode: invalid --consensus-peer '{entry}' — \
                 expected <addr_hex>=<host:port>"
            );
            std::process::exit(1);
        };
        let addr_bytes = hex_decode(addr_hex)
            .unwrap_or_else(|e| panic!("invalid consensus-peer address '{addr_hex}': {e}"));
        assert_eq!(addr_bytes.len(), 20, "--consensus-peer address must be 20 bytes");
        if seen.insert(addr_bytes.clone()) {
            peers.push((addr_bytes, hostport.to_string()));
        }
    }
    peers
}

/// `--tls-dir` resolves into the shared [`node::validator_net::TlsSpec`]:
/// `cert.pem`/`key.pem` for this node, `peer-<addr-hex>.pem` per
/// upstream member — the same layout the validator binary uses.
fn resolve_tls_spec(peers: &[(Vec<u8>, String)]) -> Option<node::validator_net::TlsSpec> {
    parse_cli_flag("--tls-dir").map(|tls_dir| {
        let trusted_peer_certs = peers
            .iter()
            .map(|(id, _)| {
                (
                    id.clone(),
                    PathBuf::from(format!("{tls_dir}/peer-{}.pem", node::cli::hex_encode(id))),
                )
            })
            .collect();
        node::validator_net::TlsSpec {
            cert_path: PathBuf::from(format!("{tls_dir}/cert.pem")),
            key_path: PathBuf::from(format!("{tls_dir}/key.pem")),
            trusted_peer_certs,
        }
    })
}

/// Fetch a chunk-verified certified snapshot from `addr` and write
/// it to `<data_dir>/snapshot.bin` — the file
/// `import_snapshot_if_present` imports during follower assembly.
/// Runs the full anchor chain: manifest → polled certificate →
/// quorum verification against the checkpoint → chunk download.
///
/// # Panics
///
/// Panics on any verification or transport failure — bootstrapping
/// an unverified snapshot is the exact failure this binary refuses.
fn fetch_certified_snapshot_to_file(
    addr: &str,
    epoch: u64,
    vset: &consensus::ValidatorSet,
    data_dir: &std::path::Path,
) {
    let manifest = statesync::fetch_manifest(addr)
        .unwrap_or_else(|e| panic!("state sync from {addr}: manifest fetch failed: {e}"));
    assert!(
        manifest.format_version <= executor::SNAPSHOT_FORMAT_VERSION,
        "state sync from {addr}: snapshot format {} newer than supported {}",
        manifest.format_version,
        executor::SNAPSHOT_FORMAT_VERSION
    );
    let cert = poll_exec_certificate(addr, manifest.height);
    consensus::verify_exec_cert(vset, primitives::Epoch::new(epoch), &cert)
        .unwrap_or_else(|e| panic!("state sync from {addr}: certificate verification failed: {e}"));
    assert_eq!(
        cert.height.value(),
        manifest.height,
        "certificate covers height {} but the manifest is pinned to {}",
        cert.height.value(),
        manifest.height
    );
    assert_eq!(
        cert.state_root, manifest.state_root,
        "certified state root does not match the manifest's claimed root"
    );
    let blob = statesync::fetch_blob(addr, &manifest)
        .unwrap_or_else(|e| panic!("state sync from {addr}: chunk download failed: {e}"));
    let path = data_dir.join("snapshot.bin");
    // Atomic write — a crash mid-write must not leave a torn
    // snapshot the restart would try to decode.
    let tmp = data_dir.join("snapshot.bin.tmp");
    std::fs::write(&tmp, &blob).unwrap_or_else(|e| panic!("cannot write {}: {e}", tmp.display()));
    std::fs::rename(&tmp, &path).unwrap_or_else(|e| panic!("cannot rename {}: {e}", tmp.display()));
    println!(
        "oxide-fullnode: fetched certified snapshot — height {}, {} bytes → {}",
        manifest.height,
        blob.len(),
        path.display()
    );
}

/// `--state-sync <host:port>` bootstrap: fetch a chunked snapshot
/// from a peer's `/snapshot/*` endpoints, anchor it in a
/// quorum-signed execution certificate, and import it.
///
/// Trust model (weak subjectivity): the operator supplies a
/// validator-set checkpoint — `--trusted-validators <path>` or the
/// `--genesis-file` validator set — naming the committee live at
/// the certificate's epoch. The peer then must produce an
/// `ExecCertificate` for the snapshot height whose aggregate BLS
/// signature verifies against >2/3 of that checkpointed stake.
/// A peer can lie about everything else — manifest, chunks, even
/// the certificate bytes it serves — but cannot forge quorum.
///
/// `--trusted-height`/`--trusted-root` are now an *optional pin
/// pair*: when given, the manifest (and therefore the certificate)
/// must match them; when absent, the latest certified height is
/// accepted. Verification order:
///
/// 1. `GET /snapshot/manifest` — pins `(height, state_root)` and
///    the chunk hashes before any state byte moves.
/// 2. `GET /snapshot/cert/{height}` — polled until the serving
///    validator's engine has formed the certificate for that exact
///    height (a live chain certifies within a few views).
/// 3. `verify_exec_cert` — epoch match, bitmap bounds, quorum
///    stake, and the aggregate signature over `(height, root,
///    epoch)`; then `cert == manifest` on both values.
/// 4. Chunks verified per-hash, assembled, decoded, imported.
/// 5. The imported root must recompute to the certified root —
///    fail closed.
fn bootstrap_state_sync(node: &mut Node) {
    let Some(addr) = parse_cli_flag("--state-sync") else {
        return;
    };
    let (epoch, vset) = load_sync_checkpoint();
    let pins = parse_trusted_pins();

    // 1. Manifest: the peer's claimed (height, root) plus per-chunk
    //    hashes. The manifest fetch also populates the server's
    //    snapshot cache, so the chunks fetched below describe THIS
    //    manifest unless another client's manifest call interleaves
    //    (detected by chunk-hash mismatch — restart the sync).
    let manifest = statesync::fetch_manifest(&addr)
        .unwrap_or_else(|e| panic!("state sync from {addr}: manifest fetch failed: {e}"));
    if let Some((trusted_height, trusted_root)) = pins {
        statesync::check_trusted(&manifest, trusted_height, &trusted_root).unwrap_or_else(|_| {
            panic!(
                "state sync from {addr}: manifest (height {}, root {}) does not match pinned \
                 --trusted-height/--trusted-root {trusted_height}:{trusted_root}",
                manifest.height, manifest.state_root
            )
        });
    }
    assert!(
        manifest.format_version <= executor::SNAPSHOT_FORMAT_VERSION,
        "state sync from {addr}: snapshot format {} newer than supported {}",
        manifest.format_version,
        executor::SNAPSHOT_FORMAT_VERSION
    );

    // 2. Certificate: poll until the cert for the pinned height is
    //    served. Transport errors retry (404 while the engine's cert
    //    forms, or a restarting peer); the deadline bounds the wait.
    let cert = poll_exec_certificate(&addr, manifest.height);

    // 3. Verify against the checkpointed set: epoch match (the
    //    signed message binds it), bitmap bounds, >2/3 stake quorum,
    //    aggregate BLS signature. Any failure is permanent — retrying
    //    cannot make an invalid cert valid, so fail fast.
    consensus::verify_exec_cert(&vset, primitives::Epoch::new(epoch), &cert).unwrap_or_else(|e| {
        panic!(
            "state sync from {addr}: execution certificate for height {} failed \
             verification against the checkpointed validator set (epoch {epoch}): {e}",
            manifest.height
        )
    });
    assert_eq!(
        cert.height.value(),
        manifest.height,
        "served certificate covers height {} but the manifest is pinned to {}",
        cert.height.value(),
        manifest.height
    );
    assert_eq!(
        cert.state_root, manifest.state_root,
        "certified state root does not match the manifest's claimed root — \
         the peer is serving inconsistent anchors"
    );
    println!(
        "oxide-fullnode: certificate verified — height {}, root {}, epoch {} \
         attested by a quorum of the checkpointed set",
        cert.height.value(),
        cert.state_root,
        cert.epoch.value()
    );

    // 4. Chunks: each verified against the manifest's hash list
    //    before assembly — a torn or tampered chunk is rejected
    //    byte-for-byte.
    let blob = statesync::fetch_blob(&addr, &manifest)
        .unwrap_or_else(|e| panic!("state sync from {addr}: chunk download failed: {e}"));
    let mut reader = codec::Reader::new(&blob);
    let snapshot = <executor::ExecutorSnapshot as codec::Decode>::decode(&mut reader)
        .unwrap_or_else(|e| panic!("snapshot decode failed: {e}"));
    node.import_snapshot(&snapshot).unwrap_or_else(|e| panic!("snapshot import failed: {e}"));

    // 5. Post-import anchor: the imported root at the certified
    //    height must recompute to what the quorum attested — catches
    //    a snapshot whose KV payload decoded and imported but does
    //    not recompute.
    let imported_root = node.app_handle().state_root_at(manifest.height);
    assert_eq!(
        imported_root, manifest.state_root,
        "imported state root does not match the certified root — refusing to run"
    );
    println!(
        "oxide-fullnode: state synced to height {} ({} chunks, {} bytes)",
        manifest.height,
        blob.len().div_ceil(statesync::DEFAULT_CHUNK_SIZE),
        blob.len()
    );
}

/// Poll `GET /snapshot/cert/{height}` until the certificate arrives
/// or the poll budget is exhausted. Every `Err` is retried — the
/// endpoint 404s (transport error) while the serving engine's cert
/// is still forming — so the deadline is the only bound.
///
/// # Panics
///
/// Panics after `CERT_POLL_ATTEMPTS` failures: a peer that cannot
/// produce a quorum-signed cert for a committed height is not a
/// valid sync source (halted chain, non-validator peer, or an
/// older binary without the endpoint).
fn poll_exec_certificate(addr: &str, height: u64) -> types::ExecCertificate {
    let deadline = Instant::now() + CERT_POLL_ATTEMPTS * CERT_POLL_INTERVAL;
    let mut attempts = 0u32;
    loop {
        match statesync::fetch_exec_certificate(addr, height) {
            Ok(cert) => return cert,
            Err(e) => {
                attempts += 1;
                assert!(
                    Instant::now() < deadline && attempts < CERT_POLL_ATTEMPTS,
                    "state sync from {addr}: no execution certificate for height \
                     {height} after {attempts} attempts — refusing to trust an \
                     unattested snapshot (last error: {e})"
                );
                std::thread::sleep(CERT_POLL_INTERVAL);
            }
        }
    }
}

/// Resolve the weak-subjectivity checkpoint into `(epoch,
/// ValidatorSet)`. `--trusted-validators <path>` wins; otherwise the
/// `--genesis-file` validator set is the epoch-0 checkpoint.
///
/// # Panics
///
/// Panics when neither source yields a usable set, or when a
/// checkpoint validator lacks `public_key`/has bad hex — syncing
/// without a verifiable committee is exactly the trust hole this
/// flag exists to close.
fn load_sync_checkpoint() -> (u64, consensus::ValidatorSet) {
    if let Some(path) = parse_cli_flag("--trusted-validators") {
        let checkpoint =
            config::genesis::ValidatorSetCheckpoint::from_json_file(&PathBuf::from(&path))
                .unwrap_or_else(|e| panic!("failed to load validator checkpoint {path}: {e}"));
        let vset = checkpoint_to_validator_set(&checkpoint.validators, &path);
        return (checkpoint.epoch, vset);
    }
    if let Some(path) = parse_cli_flag("--genesis-file") {
        let genesis = config::genesis::Genesis::from_json_file(&PathBuf::from(&path))
            .unwrap_or_else(|e| panic!("failed to load genesis file {path}: {e}"));
        let vset = checkpoint_to_validator_set(&genesis.staking.validators, &path);
        // The genesis set is definitionally the epoch-0 committee.
        return (0, vset);
    }
    panic!(
        "--state-sync requires a validator-set checkpoint: pass --trusted-validators <path> \
         (a JSON {{\"epoch\", \"validators\"}} file) or --genesis-file whose validators carry \
         public_key — refusing to sync state no quorum attested"
    );
}

/// Build a `consensus::ValidatorSet` from checkpoint/genesis
/// validator records. `public_key` and `stake` drive certificate
/// verification (the bitmap indexes set order, so the file's
/// validator order must match committee order); `address` is the
/// member's registered staking identity — required here so the
/// follower's `BlsPeerAuth` can resolve a dialled member's claimed
/// peer id (a staking address, NOT `validator_address(pk)`-derived
/// on devnets that seat secp test identities).
///
/// # Panics
///
/// Panics on a missing/malformed `public_key` or `address`, or on
/// an empty set.
fn checkpoint_to_validator_set(
    validators: &[config::genesis::GenesisValidator],
    source: &str,
) -> consensus::ValidatorSet {
    assert!(
        !validators.is_empty(),
        "validator-set checkpoint {source} lists no validators — nothing can form a quorum"
    );
    let pks: Vec<crypto::bls::PublicKey> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let hex = v.public_key.as_ref().unwrap_or_else(|| {
                panic!(
                    "checkpoint {source} validator {i} missing public_key — \
                     the certificate cannot be verified without it"
                )
            });
            let bytes = hex_decode(hex)
                .unwrap_or_else(|e| panic!("checkpoint {source} validator {i} bad key hex: {e}"));
            crypto::bls::PublicKey::from_slice(&bytes).unwrap_or_else(|_| {
                panic!("checkpoint {source} validator {i} is not a valid BLS public key")
            })
        })
        .collect();
    let stakes: Vec<u64> = validators.iter().map(|v| v.stake).collect();
    let addresses: Vec<primitives::Address> = validators
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let bytes = hex_decode(&v.address).unwrap_or_else(|e| {
                panic!("checkpoint {source} validator {i} bad address hex: {e}")
            });
            primitives::Address(<[u8; 20]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
                panic!("checkpoint {source} validator {i} address must be 20 bytes")
            }))
        })
        .collect();
    consensus::ValidatorSet::with_addresses(pks, stakes, addresses)
        .unwrap_or_else(|e| panic!("checkpoint {source} is not a valid validator set: {e}"))
}

/// Parse the optional `--trusted-height` + `--trusted-root` pin
/// pair. Both or neither: a lone pin would leave one axis of the
/// operator's intent unchecked.
///
/// # Panics
///
/// Panics on a lone flag or malformed values.
fn parse_trusted_pins() -> Option<(u64, primitives::Hash)> {
    let height_str = parse_cli_flag("--trusted-height");
    let root_str = parse_cli_flag("--trusted-root");
    match (height_str, root_str) {
        (None, None) => None,
        (Some(h), Some(r)) => {
            let height: u64 = h.parse().unwrap_or_else(|_| panic!("invalid --trusted-height {h}"));
            let root_hex = r.strip_prefix("0x").unwrap_or(&r);
            let root_bytes =
                hex_decode(root_hex).unwrap_or_else(|e| panic!("invalid --trusted-root: {e}"));
            let root = primitives::Hash(
                <[u8; 32]>::try_from(root_bytes.as_slice())
                    .unwrap_or_else(|_| panic!("--trusted-root must be 32 bytes")),
            );
            Some((height, root))
        }
        _ => panic!(
            "--trusted-height and --trusted-root are a pair — pass both or neither \
             (the certificate alone anchors the sync either way)"
        ),
    }
}

/// Decode a hex string — bare or `0x`-prefixed (checkpoint files
/// reuse the genesis/`/validator-set` convention of `0x` prefixes).
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Load the node configuration from CLI flags, env vars, and TOML file.
///
/// Priority: CLI > env vars > TOML > defaults.
///
/// Returns `(config::Config, NodeConfig)`: the raw layered config
/// carries `network`/`rpc`/`data_dir` (transport + RPC topology),
/// the converted `NodeConfig` is what assembly consumes.
fn load_config() -> (config::Config, NodeConfig) {
    let mut config = config::Config::default();

    // 1. Load from TOML file if --config is given.
    let config_path = parse_cli_flag("--config");
    if let Some(path) = config_path.clone() {
        let path = PathBuf::from(path);
        match config::Config::from_toml_file(&path) {
            Ok(loaded) => config = loaded,
            Err(e) => {
                eprintln!("oxide-fullnode: failed to load config from {}: {e}", path.display());
                std::process::exit(1);
            }
        }
    }

    // 2. Env vars are applied automatically by `from_toml_file`. For
    //    the default config (no --config), apply env vars manually.
    if config_path.is_none() {
        config.apply_env_vars();
    }

    // 3. CLI flags override everything.
    if let Some(engine_str) = parse_cli_flag("--engine") {
        if let Some(engine) = config::ConsensusEngineKind::parse(&engine_str) {
            config.consensus.engine = engine;
        } else {
            eprintln!(
                "oxide-fullnode: unknown --engine value {engine_str:?} \
                      (expected \"sequencer\" or \"oxidebft\")"
            );
            std::process::exit(1);
        }
    }

    // `--genesis-file`: same chain-state source the validator uses —
    // the shared conversion applies its validators and native
    // balances at assembly.
    let genesis_file = parse_cli_flag("--genesis-file").map(|p| {
        config::genesis::Genesis::from_json_file(&PathBuf::from(&p))
            .unwrap_or_else(|e| panic!("failed to load genesis file {p}: {e}"))
    });

    // `--data-dir` wins over `[storage] data_dir`.
    let data_dir =
        parse_cli_flag("--data-dir").map(PathBuf::from).or_else(|| config.storage.data_dir.clone());

    // The RPC config carries the chain ID and base fee — the
    // executor, the EVM module, and the RPC layer all read the same
    // source so advertised and enforced parameters cannot diverge.
    let rpc_config = config.rpc.clone().unwrap_or_default();

    // Genesis chain id must match the RPC chain id.
    if let Some(g) = &genesis_file
        && g.chain_id != rpc_config.chain_id
    {
        eprintln!(
            "oxide-fullnode: genesis chain_id {} != rpc.chain_id {} — \
                 refusing to run a node whose signatures advertise a different chain",
            g.chain_id, rpc_config.chain_id
        );
        std::process::exit(1);
    }

    let genesis = Some(match &genesis_file {
        Some(g) => {
            node::genesis_spec_from_file(g).unwrap_or_else(|e| panic!("invalid genesis file: {e}"))
        }
        None => node::genesis_spec_devnet(&config.genesis),
    });
    let overrides = node::AssemblyOverrides {
        allow_unsigned_txs: env::args().any(|a| a == "--unsafe-allow-unsigned-txs"),
        data_dir,
        wal_path: parse_cli_flag("--wal-file").map(PathBuf::from),
        genesis,
    };
    // The shared conversion — the same mapping the validator binary
    // uses, so both binaries run identical effective config.
    let node_config =
        node::node_config_from(&config, &rpc_config, &overrides, node::NodeMode::Single)
            .unwrap_or_else(|e| panic!("invalid configuration: {e}"));

    // Validate BEFORE building anything: unsupported settings fail,
    // overridden ones warn — never silently do nothing.
    let (warnings, errors) =
        node::validate_effective_config(&config, &node_config, node::NodeMode::Single);
    for w in &warnings {
        eprintln!("oxide-fullnode: config warning: {w}");
    }
    if !errors.is_empty() {
        for e in &errors {
            eprintln!("oxide-fullnode: config error: {e}");
        }
        std::process::exit(1);
    }

    // Emit the effective configuration — the values actually running.
    println!("oxide-fullnode: effective node config: {node_config:?}");
    (config, node_config)
}

/// Parse a `--flag value` pair from CLI args.
fn parse_cli_flag(flag: &str) -> Option<String> {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == flag {
            return args.next();
        }
    }
    None
}

/// Collect every `--flag value` pair — repeatable flags like
/// `--consensus-peer` and `--repair-peer`.
fn parse_cli_flags(flag: &str) -> Vec<String> {
    let mut args = env::args().skip(1);
    let mut values = Vec::new();
    while let Some(arg) = args.next() {
        if arg == flag
            && let Some(value) = args.next()
        {
            values.push(value);
        }
    }
    values
}

/// Apply a genesis file's `evm.alloc` map to the assembled EVM
/// module: balances, nonces, code, and storage for pre-funded
/// accounts and preinstalled contracts (Ethereum `genesis.json`
/// convention). Mirrors `oxide-validator`'s copy — kept in the
/// binary because the `node` crate deliberately stays free of the
/// `alloy_primitives` dependency.
///
/// # Panics
///
/// Panics on malformed hex — genesis errors are fatal at startup.
fn apply_evm_alloc(evm_module: &evm::EvmModule, genesis: &config::genesis::Genesis) {
    for (addr_hex, account) in &genesis.evm.alloc {
        let addr_bytes = hex_decode(addr_hex)
            .unwrap_or_else(|e| panic!("genesis evm.alloc invalid address: {e}"));
        let addr: [u8; 20] = addr_bytes
            .try_into()
            .unwrap_or_else(|_| panic!("genesis evm.alloc address must be 20 bytes"));
        let balance = if let Some(hex) = account.balance.strip_prefix("0x") {
            u128::from_str_radix(hex, 16)
        } else {
            account.balance.parse::<u128>()
        }
        .unwrap_or_else(|e| panic!("genesis evm.alloc invalid balance: {e}"));
        let code = account
            .code
            .as_deref()
            .map(|c| hex_decode(c).unwrap_or_else(|e| panic!("evm.alloc code: {e}")))
            .unwrap_or_default();
        let storage = account
            .storage
            .iter()
            .map(|(slot, value)| {
                let slot = alloy_primitives::U256::from_str_radix(
                    slot.strip_prefix("0x").unwrap_or(slot),
                    16,
                )
                .unwrap_or_else(|e| panic!("evm.alloc slot: {e}"));
                let value = alloy_primitives::U256::from_str_radix(
                    value.strip_prefix("0x").unwrap_or(value),
                    16,
                )
                .unwrap_or_else(|e| panic!("evm.alloc storage value: {e}"));
                (slot, value)
            })
            .collect();
        evm_module.genesis_insert_account(
            &primitives::Address(addr),
            balance,
            account.nonce,
            code,
            storage,
        );
    }
}
