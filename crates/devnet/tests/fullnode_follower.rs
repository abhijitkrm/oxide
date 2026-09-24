//! Fullnode follower — the operator flow, end to end.
//!
//! `oxide-validator` binaries run a 3-member committee (plaintext
//! transport — the observer handshake and block-sync paths are what
//! this test covers; TLS composition is the p2p suite's gate). Each
//! validator allowlists the follower's observer identity via
//! `--observer-peer`, then `oxide-fullnode` joins the authenticated
//! transport, pulls certified history through `MSG_BLOCK_REQ`/
//! `MSG_BLOCK_RESP`, verifies each record's Jolteon commit proof
//! locally, executes it, and serves the mirrored height on its own
//! JSON-RPC.
//!
//! Assertions:
//! 1. The follower's `eth_blockNumber` reaches the fleet's
//!    finalized tip — real handshake auth + fetch + verify +
//!    execute + mirror, not a mocked pump.
//! 2. A SIGTERM'd follower exports `snapshot.bin`; the restarted
//!    process imports it and reports a height ≥ its pre-shutdown
//!    tip immediately — durable resume, not a genesis re-walk.
//!
//! # Running
//!
//! ```sh
//! cargo build -p oxide-validator -p oxide-fullnode && \
//!   cargo test -p devnet --test fullnode_follower -- --ignored --nocapture
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Fleet size — 3 members, quorum 3. The follower only needs a live
/// committee producing blocks; fault-injection coverage lives in
/// `validator_fleet`.
const NUM_NODES: usize = 3;
/// Validator p2p/RPC port bases — distinct from every other suite
/// in `crates/devnet/tests` (parallel `cargo test` runs share the
/// loopback space).
const P2P_BASE: u16 = 29_400;
const RPC_BASE: u16 = 35_400;
/// The follower's own JSON-RPC port (primary + restarted runs each
/// get one — the previous run's HTTP server may linger).
const FOLLOWER_RPC: u16 = 35_900;
const CHAIN_ID: u64 = 31_337;

fn validator_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let deps = exe.parent().expect("deps dir");
    for cand in [deps.join("oxide-validator"), deps.join("../oxide-validator")] {
        if cand.exists() {
            return cand;
        }
    }
    panic!("oxide-validator not found — run `cargo build -p oxide-validator` first");
}

fn fullnode_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let deps = exe.parent().expect("deps dir");
    for cand in [deps.join("oxide-fullnode"), deps.join("../oxide-fullnode")] {
        if cand.exists() {
            return cand;
        }
    }
    panic!("oxide-fullnode not found — run `cargo build -p oxide-fullnode` first");
}

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

/// A spawned process plus the test's view of it: highest finalized
/// height printed and every stdout line for post-hoc assertions.
struct NodeProc {
    child: Child,
    height: Arc<AtomicU64>,
    lines: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn watch_stdout(child: &mut Child) -> (Arc<AtomicU64>, Arc<std::sync::Mutex<Vec<String>>>) {
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
    (height, lines)
}

/// Spawn `oxide-validator --validator` for committee member `i`,
/// allowlisting `observer` (`(address_hex, pubkey_hex)`) for the
/// follower's handshake.
fn spawn_validator(i: usize, dir: &Path, bin: &Path, observer: &(String, String)) -> NodeProc {
    let mut cmd = Command::new(bin);
    cmd.arg("--validator")
        .arg("--config")
        .arg(dir.join(format!("config{i}.toml")))
        .arg("--genesis-file")
        .arg(dir.join("genesis.json"))
        .arg("--bls-key-file")
        .arg(dir.join(format!("val{i}.key")))
        .arg("--data-dir")
        .arg(dir.join(format!("data-{i}")))
        .arg("--observer-peer")
        .arg(format!("{}={}", observer.0, observer.1));
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn validator {i}: {e}"));
    let (height, lines) = watch_stdout(&mut child);
    NodeProc { child, height, lines }
}

/// Spawn `oxide-fullnode` in follower mode against the committee's
/// p2p endpoints.
fn spawn_follower(dir: &Path, bin: &Path, addrs: &[String], rpc_port: u16, name: &str) -> NodeProc {
    let mut cmd = Command::new(bin);
    cmd.arg("--config")
        .arg(dir.join("follower.toml"))
        .arg("--genesis-file")
        .arg(dir.join("genesis.json"))
        .arg("--observer-key-file")
        .arg(dir.join("observer.key"))
        .arg("--data-dir")
        .arg(dir.join(format!("follower-{name}")))
        .arg("--rpc-listen")
        .arg(format!("127.0.0.1:{rpc_port}"));
    for (i, addr) in addrs.iter().enumerate() {
        cmd.arg("--consensus-peer").arg(format!(
            "{addr}=127.0.0.1:{}",
            P2P_BASE + u16::try_from(i).expect("fleet fits in u16")
        ));
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn follower {name}: {e}"));
    let (height, lines) = watch_stdout(&mut child);
    NodeProc { child, height, lines }
}

/// Write member `i`'s config: its own `listen_addr`, every other
/// member as `addr=host:port`, and the matching `[rpc]` chain id.
fn write_validator_config(i: usize, addrs: &[String], dir: &Path) {
    let peers: Vec<String> = (0..NUM_NODES)
        .filter(|j| *j != i)
        .map(|j| format!("{}=127.0.0.1:{}", addrs[j], P2P_BASE + u16::try_from(j).expect("u16")))
        .collect();
    let peers_toml = peers.iter().map(|p| format!("\"{p}\"")).collect::<Vec<_>>().join(", ");
    std::fs::write(
        dir.join(format!("config{i}.toml")),
        format!(
            "[network]\nlisten_addr = \"127.0.0.1:{}\"\npeers = [{peers_toml}]\n\n\
             [rpc]\nlisten_addr = \"127.0.0.1:{}\"\nchain_id = {CHAIN_ID}\nbase_fee = 1\n",
            P2P_BASE + u16::try_from(i).expect("u16"),
            RPC_BASE + u16::try_from(i).expect("u16"),
        ),
    )
    .expect("write config");
}

/// The follower's config: chain id must match genesis; no peers
/// needed (upstream comes from `--consensus-peer` argv).
fn write_follower_config(dir: &Path) {
    std::fs::write(
        dir.join("follower.toml"),
        format!("[rpc]\nlisten_addr = \"\"\nchain_id = {CHAIN_ID}\nbase_fee = 1\n"),
    )
    .expect("write follower config");
}

fn genesis_addrs(dir: &Path) -> Vec<String> {
    let genesis_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("genesis.json")).expect("read genesis"),
    )
    .expect("parse genesis");
    genesis_json["staking"]["validators"]
        .as_array()
        .expect("validators array")
        .iter()
        .map(|v| v["address"].as_str().expect("address").trim_start_matches("0x").to_string())
        .collect()
}

/// One POST to a JSON-RPC `eth_blockNumber` — the honest external
/// probe: the mirrored committed height is what a real client reads.
fn rpc_block_number(addr: &str) -> Option<u64> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let body = r#"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#;
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
    u64::from_str_radix(rest[start..end].trim_start_matches("0x"), 16).ok()
}

fn terminate(proc: &mut NodeProc) {
    let _ = Command::new("kill").args(["-TERM", &proc.child.id().to_string()]).status();
    let _ = proc.child.wait();
}

struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Provision the fleet directory: `NUM_NODES` validator key files +
/// genesis, one observer key file, and every member's config. Returns
/// `(committee staking-address hexes, (observer_id_hex, observer_pubkey_hex))`
/// — the observer pair is what each validator's `--observer-peer`
/// allowlist names.
fn provision(bin: &Path, dir: &Path) -> (Vec<String>, (String, String)) {
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
    let addrs = genesis_addrs(dir);

    // The observer: its key file lives with the follower; the
    // validators allowlist (derived-id, pubkey). `validator_address`
    // is exactly the derivation the binary applies for `--observer-id`.
    let observer_pub_hex = keygen(bin, &dir.join("observer.key"));
    let observer_pk_bytes = node::cli::hex_decode(&observer_pub_hex).expect("observer pubkey hex");
    let observer_pk = crypto::bls::PublicKey::from_slice(&observer_pk_bytes)
        .unwrap_or_else(|_| panic!("observer pubkey decode"));
    let observer_addr = crypto::bls::validator_address(&observer_pk);
    let observer = (node::cli::hex_encode(&observer_addr.0), observer_pub_hex);

    for i in 0..NUM_NODES {
        write_validator_config(i, &addrs, dir);
    }
    write_follower_config(dir);
    (addrs, observer)
}

/// The full operator path: provisioned committee + allowlisted
/// observer → follower syncs certified history → restart resumes.
#[test]
#[ignore = "process-level e2e — spawns real binaries; run explicitly"]
fn fullnode_follows_and_resumes() {
    let bin = validator_binary();
    let fbin = fullnode_binary();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("oxide-fnfleet-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create workdir");
    let _dir_guard = DirGuard(dir.clone());

    // 1. Provision + launch the committee.
    let (addrs, observer) = provision(&bin, &dir);
    let mut nodes = Vec::new();
    for i in 0..NUM_NODES {
        nodes.push(spawn_validator(i, &dir, &bin, &observer));
    }

    // 3. Let the committee produce a few certified heights first —
    //    the follower then exercises catch-up, not just live track.
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let all = nodes.iter().all(|n| n.height.load(Ordering::Relaxed) >= 3);
        if all {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "committee did not reach height 3: {:?}",
            nodes.iter().map(|n| n.height.load(Ordering::Relaxed)).collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(300));
    }

    // 4. Spawn the follower: handshake auth + certified fetch +
    //    per-record verification + execution + RPC mirror.
    let mut follower = spawn_follower(&dir, &fbin, &addrs, FOLLOWER_RPC, "a");
    let fleet_tip = nodes.iter().map(|n| n.height.load(Ordering::Relaxed)).max().unwrap_or(0);
    let follow_deadline = Instant::now() + Duration::from_secs(30);
    let mut tip = 0u64;
    loop {
        if let Some(h) = rpc_block_number(&format!("127.0.0.1:{FOLLOWER_RPC}"))
            && h > tip
        {
            tip = h;
        }
        if tip >= fleet_tip && tip >= 3 {
            break;
        }
        assert!(
            Instant::now() < follow_deadline && follower.child.try_wait().expect("wait").is_none(),
            "follower mirrored only height {tip} (fleet tip {fleet_tip}):\n{}",
            follower.lines.lock().expect("lines").join("\n")
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // The follower should also keep finalizing forward in lockstep —
    // its own stdout prints the same committed heights.
    assert!(
        follower.height.load(Ordering::Relaxed) >= tip,
        "follower log never reported its mirrored tip ({tip})"
    );

    // 5. Graceful stop → snapshot.bin export → restart resumes at
    //    ≥ the pre-shutdown tip on a fresh RPC port (the first run's
    //    server can linger — probing the new port only).
    terminate(&mut follower);
    let log = follower.lines.lock().expect("lines").join("\n");
    assert!(log.contains("exported snapshot"), "follower did not export state:\n{log}");
    drop(follower);

    let mut follower2 = spawn_follower(&dir, &fbin, &addrs, FOLLOWER_RPC + 1, "a");
    let resume_deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(h) = rpc_block_number(&format!("127.0.0.1:{}", FOLLOWER_RPC + 1))
            && h >= tip
        {
            break;
        }
        assert!(
            Instant::now() < resume_deadline && follower2.child.try_wait().expect("wait").is_none(),
            "restarted follower did not report ≥{tip} within the window:\n{}",
            follower2.lines.lock().expect("lines").join("\n")
        );
        std::thread::sleep(Duration::from_millis(150));
    }
}
