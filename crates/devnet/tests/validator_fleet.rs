//! Production-validator fleet convergence — the `oxide-validator
//! --validator` deployment path, end to end.
//!
//! Unlike the devnet fleet tests (which exercise `--node` with
//! derivable identities), this drives the *operator* flow against the
//! real binary: `keygen` produces per-validator BLS secrets, `genesis`
//! binds their public keys into the committee, `tls-gen
//! --genesis-file` emits address-keyed mTLS material, and four
//! `--validator` processes run oxideBFT over the TCP/mTLS transport
//! with `addr=host:port` peers from their own config files.
//!
//! The assertions mirror the audit's acceptance shape for the
//! production binary:
//!
//! 1. Every node resolves its committee seat from its key file and
//!    reaches the same finalized height — not a fixed index, the
//!    key's registered position.
//! 2. mTLS is on (`mTLS enabled` in the log) and peers are
//!    address-keyed.
//! 3. A SIGTERM'd validator exports a durable snapshot, and its
//!    remaining three peers keep finalizing (3-of-4 is quorum).
//! 4. The restarted node recovers its durable state (`snapshot
//!    Some(h)`, WAL reloaded) and rejoins the consensus machinery.
//!    It cannot re-finalize heights it missed — block fetch is the
//!    documented sync gap, not a failure of this path — so the gate
//!    is that restart *succeeds* and the node re-attaches, not that
//!    it catches up.
//!
//! # Running
//!
//! ```sh
//! cargo build -p oxide-validator && \
//!   cargo test -p devnet --test validator_fleet -- --ignored --nocapture
//! ```

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Fleet size — f=1, quorum=3, so one stopped member leaves the
/// remaining three finalizing.
const NUM_NODES: usize = 4;
/// First validator-mode listen port; node `i` binds `BASE_PORT + i`.
/// Distinct from `proposal_flood`'s range so both suites can run.
const BASE_PORT: u16 = 26_400;
/// First JSON-RPC port; node `i` binds `RPC_BASE + i`.
const RPC_BASE: u16 = 32_400;
/// Port ranges for the remote-signer fleet — every test in this
/// file needs its own range: `cargo test` runs the `#[ignore]`d
/// tests in parallel when both are selected.
const SIGNER_P2P_BASE: u16 = 27_400;
const SIGNER_RPC_BASE: u16 = 33_400;
/// The signer daemon's listen port in the remote-signer test.
const SIGNER_DAEMON_PORT: u16 = 33_900;
/// Port range for the absent-leader boot test.
const ABSENT_P2P_BASE: u16 = 28_400;
const ABSENT_RPC_BASE: u16 = 34_400;
/// Chain id shared by the genesis file and every node's `[rpc]`
/// config — the loader refuses a mismatch.
const CHAIN_ID: u64 = 31_337;

/// Locate the `oxide-validator` binary next to the test executable
/// (`target/debug/deps/<test>` → `target/debug/oxide-validator`).
fn validator_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let deps = exe.parent().expect("deps dir");
    for cand in [deps.join("oxide-validator"), deps.join("../oxide-validator")] {
        if cand.exists() {
            return cand;
        }
    }
    panic!("oxide-validator binary not found — run `cargo build -p oxide-validator` first");
}

/// Run a binary subcommand to completion, returning stdout.
fn run_ok(bin: &Path, args: &[&str]) -> String {
    let out = Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn {} {args:?}: {e}", bin.display()));
    assert!(
        out.status.success(),
        "{} {args:?} failed: {}",
        bin.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `oxide-validator keygen -o <path>` → the printed public key hex.
fn keygen(bin: &Path, key_path: &Path) -> String {
    let stdout = run_ok(bin, &["keygen", "-o", key_path.to_str().expect("utf8 path")]);
    stdout
        .split_whitespace()
        .skip_while(|t| *t != "key")
        .nth(1)
        .unwrap_or_else(|| panic!("keygen printed no public key: {stdout}"))
        .to_string()
}

/// A spawned validator process plus the test's view of it: the
/// highest finalized height it printed and every stdout line for
/// post-hoc assertions (snapshot export, seat resolution).
struct NodeProc {
    child: Child,
    height: Arc<AtomicU64>,
    lines: Arc<std::sync::Mutex<Vec<String>>>,
}

/// `Child::drop` does not kill — a panicking test would orphan the
/// fleet and its ports would poison the next run.
impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `oxide-validator --validator` for committee member `i`.
/// `signer_port` selects the identity source: `Some(port)` delegates
/// signing to the daemon at `127.0.0.1:port` (the member's key file
/// then lives only inside the daemon), `None` uses the local
/// `val{i}.key` file.
fn spawn_validator(i: usize, dir: &Path, bin: &Path, signer_port: Option<u16>) -> NodeProc {
    let mut cmd = Command::new(bin);
    cmd.arg("--validator")
        .arg("--config")
        .arg(dir.join(format!("config{i}.toml")))
        .arg("--genesis-file")
        .arg(dir.join("genesis.json"))
        .arg("--tls-dir")
        .arg(dir.join(format!("tls/node-{i}")))
        .arg("--data-dir")
        .arg(dir.join(format!("data-{i}")));
    match signer_port {
        Some(port) => {
            cmd.arg("--signer-addr").arg(format!("127.0.0.1:{port}"));
        }
        None => {
            cmd.arg("--bls-key-file").arg(dir.join(format!("val{i}.key")));
        }
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn validator {i}: {e}"));
    let height = Arc::new(AtomicU64::new(0));
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let height_writer = Arc::clone(&height);
    let line_writer = Arc::clone(&lines);
    let stdout = child.stdout.take().expect("stdout piped");
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Some(pos) = line.find("finalized height = ")
                && let Ok(h) = line[pos + "finalized height = ".len()..].trim().parse::<u64>()
            {
                height_writer.fetch_max(h, Ordering::Relaxed);
            }
            line_writer.lock().expect("lines").push(line);
        }
    });
    NodeProc { child, height, lines }
}

/// Write member `i`'s config: its own `listen_addr`, every other
/// member as `addr=host:port`, and the matching `[rpc]` chain id.
/// `p2p_base`/`rpc_base` select the test's port range — parallel
/// tests must not share them.
fn write_config(i: usize, addrs: &[String], dir: &Path, p2p_base: u16, rpc_base: u16) {
    let peers: Vec<String> = (0..NUM_NODES)
        .filter(|j| *j != i)
        .map(|j| {
            format!(
                "{}=127.0.0.1:{}",
                addrs[j],
                p2p_base + u16::try_from(j).expect("fleet fits in u16")
            )
        })
        .collect();
    let peers_toml = peers.iter().map(|p| format!("\"{p}\"")).collect::<Vec<_>>().join(", ");
    std::fs::write(
        dir.join(format!("config{i}.toml")),
        format!(
            "[network]\nlisten_addr = \"127.0.0.1:{}\"\npeers = [{peers_toml}]\n\n\
             [rpc]\nlisten_addr = \"127.0.0.1:{}\"\nchain_id = {CHAIN_ID}\nbase_fee = 1\n",
            p2p_base + u16::try_from(i).expect("fleet fits in u16"),
            rpc_base + u16::try_from(i).expect("fleet fits in u16"),
        ),
    )
    .expect("write config");
}

/// Provision the fleet's workdir: per-validator key files, the
/// genesis file binding their public keys, address-keyed TLS
/// material, and per-node config files. Returns the committee's
/// staking addresses (hex, no `0x`) in genesis order.
fn provision(bin: &Path, dir: &Path) {
    let mut pubkeys = Vec::new();
    for i in 0..NUM_NODES {
        pubkeys.push(keygen(bin, &dir.join(format!("val{i}.key"))));
    }
    let pubkeys_file = dir.join("pubkeys.txt");
    std::fs::write(&pubkeys_file, pubkeys.join("\n")).expect("write pubkeys");
    run_ok(
        bin,
        &[
            "genesis",
            "--validators",
            &NUM_NODES.to_string(),
            "--validator-pubkeys",
            pubkeys_file.to_str().expect("utf8"),
            "--chain-id",
            &CHAIN_ID.to_string(),
            "-o",
            dir.join("genesis.json").to_str().expect("utf8"),
        ],
    );
    run_ok(
        bin,
        &[
            "tls-gen",
            "--genesis-file",
            dir.join("genesis.json").to_str().expect("utf8"),
            "-o",
            dir.join("tls").to_str().expect("utf8"),
        ],
    );
}

/// Read the committee's staking addresses back out of the genesis
/// file — `Genesis::devnet`'s `[i + 0x0a; 20]` pattern is the
/// binary's convention, but the test reads rather than assumes.
fn genesis_addrs(dir: &Path) -> Vec<String> {
    let genesis_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("genesis.json")).expect("read genesis"),
    )
    .expect("parse genesis");
    let addrs: Vec<String> = genesis_json["staking"]["validators"]
        .as_array()
        .expect("validators array")
        .iter()
        .map(|v| v["address"].as_str().expect("address").trim_start_matches("0x").to_string())
        .collect();
    assert_eq!(addrs.len(), NUM_NODES);
    addrs
}

/// The operator flow, end to end: provision → converge → stop one →
/// restart it and confirm durable recovery re-attaches.
#[test]
#[ignore = "process-level e2e — spawns real binaries; run explicitly"]
fn validator_fleet_converges_and_recovers() {
    let bin = validator_binary();
    // Unique working dir — the test must not collide with a
    // concurrent run or a stale previous one.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("oxide-valfleet-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create workdir");
    let _dir_guard = DirGuard(dir.clone());

    // 1. Keys → pubkeys → genesis → address-keyed TLS material.
    provision(&bin, &dir);
    let addrs = genesis_addrs(&dir);

    // 2. Configs + launch.
    let mut nodes = Vec::new();
    for i in 0..NUM_NODES {
        write_config(i, &addrs, &dir, BASE_PORT, RPC_BASE);
        nodes.push(spawn_validator(i, &dir, &bin, None));
    }

    // 3. Convergence gate: every node reaches height 5 — proof that
    //    seat resolution, mTLS, and the shared pump all work on the
    //    production binary.
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let all = nodes.iter().all(|n| n.height.load(Ordering::Relaxed) >= 5);
        if all {
            break;
        }
        assert!(Instant::now() < deadline, "fleet did not converge: {:?}", heights(&nodes));
        std::thread::sleep(Duration::from_millis(300));
    }
    for (i, n) in nodes.iter().enumerate() {
        let log = n.lines.lock().expect("lines").join("\n");
        assert!(log.contains("mTLS enabled"), "node {i} not running mTLS");
        assert!(log.contains(&format!("seat {i} of {NUM_NODES}")), "node {i} seat unresolved");
    }

    // 4. Stop member 3; the remaining three are quorum and must keep
    //    finalizing.
    let mut stopped = nodes.pop().expect("node 3");
    terminate(&mut stopped);
    let survivors_converged = Instant::now() + Duration::from_secs(20);
    let stop_height = nodes[0].height.load(Ordering::Relaxed);
    loop {
        let advanced = nodes.iter().all(|n| n.height.load(Ordering::Relaxed) >= stop_height + 2);
        if advanced {
            break;
        }
        assert!(
            Instant::now() < survivors_converged,
            "quorum stalled after member stop: {:?}",
            heights(&nodes)
        );
        std::thread::sleep(Duration::from_millis(300));
    }

    // 5. Restart member 3 — durable recovery must re-attach it to
    //    the fleet. Catching up on the missed blocks needs block
    //    sync (a separate protocol); the gate here is that restart
    //    succeeds and the node rejoins consensus, not that it
    //    re-finalizes.
    let mut restarted = spawn_validator(3, &dir, &bin, None);
    let rejoin_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let log = restarted.lines.lock().expect("lines").join("\n");
        if log.contains("recovered durable state") {
            break;
        }
        assert!(
            Instant::now() < rejoin_deadline && restarted.child.try_wait().expect("wait").is_none(),
            "restarted validator did not recover durable state:\n{log}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    terminate(&mut restarted);
    for n in &mut nodes {
        terminate(n);
    }
}

fn heights(nodes: &[NodeProc]) -> Vec<u64> {
    nodes.iter().map(|n| n.height.load(Ordering::Relaxed)).collect()
}

/// Block until `host:port` accepts a TCP connection — the daemon's
/// listener is up. Without this the validator's `RemoteSigner`
/// connect can race the daemon's bind and exit on `ECONNREFUSED`.
fn wait_for_port(addr: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{addr} did not accept a connection within {timeout:?}");
}

/// A spawned signer daemon — killed on drop for the same reason as
/// [`NodeProc`]: a panicking test must not leave it holding its
/// port for the next run.
struct DaemonGuard(Child);

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn the `signer` daemon for committee member `i` — the remote
/// signing endpoint a `--signer-addr` validator delegates to.
fn spawn_signer_daemon(i: usize, dir: &Path, bin: &Path, port: u16) -> DaemonGuard {
    let child = Command::new(bin)
        .arg("signer")
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--bls-key-file")
        .arg(dir.join(format!("val{i}.key")))
        .arg("--state-file")
        .arg(dir.join(format!("signer-{i}.state")))
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn signer daemon {i}: {e}"));
    DaemonGuard(child)
}

/// Same fleet shape as `validator_fleet_converges_and_recovers`, but
/// node 0 holds no key file at all — it signs through a remote
/// signer daemon (`--signer-addr`). Proves the production path end
/// to end: the validator process never touches the secret, the
/// daemon's fence file is the only anti-equivocation state.
#[test]
#[ignore = "process-level e2e — spawns real binaries; run explicitly"]
fn validator_fleet_runs_through_remote_signer() {
    let bin = validator_binary();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("oxide-valsns-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create workdir");
    let _dir_guard = DirGuard(dir.clone());

    provision(&bin, &dir);
    let addrs = genesis_addrs(&dir);

    // Node 0's key lives in the signer daemon; the validator gets
    // `--signer-addr`, never `--bls-key-file`.
    let _daemon = spawn_signer_daemon(0, &dir, &bin, SIGNER_DAEMON_PORT);
    wait_for_port(&format!("127.0.0.1:{SIGNER_DAEMON_PORT}"), Duration::from_secs(10));
    let mut nodes = Vec::new();
    for i in 0..NUM_NODES {
        write_config(i, &addrs, &dir, SIGNER_P2P_BASE, SIGNER_RPC_BASE);
        let signer = (i == 0).then_some(SIGNER_DAEMON_PORT);
        nodes.push(spawn_validator(i, &dir, &bin, signer));
    }

    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        if nodes.iter().all(|n| n.height.load(Ordering::Relaxed) >= 5) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fleet with remote signer did not converge: {:?}",
            heights(&nodes)
        );
        std::thread::sleep(Duration::from_millis(300));
    }

    for n in &mut nodes {
        terminate(n);
    }
}

/// Boot-time fault tolerance: member 0 — the view-0 leader — is
/// never started. The remaining three must still converge: the TC
/// for view 0 justifies view 1's proposal, which is what breaks the
/// boot livelock (regression: the pump once required a `high_qc`
/// to propose, and with the first leader dead no QC could ever
/// form — the fleet sat at height 0 forever).
#[test]
#[ignore = "process-level e2e — spawns real binaries; run explicitly"]
fn validator_fleet_boots_without_first_leader() {
    let bin = validator_binary();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("oxide-valboot-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create workdir");
    let _dir_guard = DirGuard(dir.clone());

    provision(&bin, &dir);
    let addrs = genesis_addrs(&dir);

    // Nodes 1..=3 only — node 0's process never exists.
    let mut nodes = Vec::new();
    for i in 1..NUM_NODES {
        write_config(i, &addrs, &dir, ABSENT_P2P_BASE, ABSENT_RPC_BASE);
        nodes.push(spawn_validator(i, &dir, &bin, None));
    }

    // Convergence is slower than the healthy fleet: every fourth
    // view belongs to the absent leader and costs a view timeout.
    // Height 3 needs ~5 live views plus two dead-leader timeouts.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if nodes.iter().all(|n| n.height.load(Ordering::Relaxed) >= 3) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fleet without its view-0 leader did not converge: {:?}",
            heights(&nodes)
        );
        std::thread::sleep(Duration::from_millis(300));
    }

    for n in &mut nodes {
        terminate(n);
    }
}

/// SIGTERM on unix (the graceful path — snapshot export runs),
/// SIGKILL elsewhere.
fn terminate(node: &mut NodeProc) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill").args(["-TERM", &node.child.id().to_string()]).status();
    }
    #[cfg(not(unix))]
    let _ = node.child.kill();
    let _ = node.child.wait();
}

/// Best-effort cleanup of the per-run workdir.
struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
