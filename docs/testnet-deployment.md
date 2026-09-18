# Oxide Public Testnet Deployment Guide

This guide covers deploying a multi-machine Oxide testnet on public
infrastructure — real network latency, firewall rules, TLS
certificates, and persistent state. It is the last step before
external security audit and production readiness.

**Audience:** infrastructure engineers deploying 4–32 validators
across 2+ machines with public IPs.

**Prerequisites:**
- `oxide-validator` binary built for the target architecture
  (`cargo build --release -p oxide-validator`)
- Rust toolchain for building from source, or a pre-built binary
- SSH access to each machine
- Basic familiarity with TCP networking and TLS certificates

---

## Table of contents

1. [Architecture overview](#1-architecture-overview)
2. [Infrastructure requirements](#2-infrastructure-requirements)
3. [Key generation](#3-key-generation)
4. [Configuration files](#4-configuration-files)
5. [Deployment: bare binary](#5-deployment-bare-binary)
6. [Deployment: Docker](#6-deployment-docker)
7. [Firewall and security groups](#7-firewall-and-security-groups)
8. [Monitoring](#8-monitoring)
9. [Operational procedures](#9-operational-procedures)
10. [Validation checklist](#10-validation-checklist)
11. [Troubleshooting](#11-troubleshooting)
12. [What's NOT covered](#12-whats-not-covered)

---

## 1. Architecture overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Validator 0 │────▶│ Validator 1 │────▶│ Validator 2 │────▶│ Validator 3 │
│  (leader)   │◀────│             │◀────│             │◀────│             │
│             │     │             │     │             │     │             │
│ TCP :22000  │     │ TCP :22001  │     │ TCP :22002  │     │ TCP :22003  │
│ RPC :8545   │     │ RPC :8546   │     │ RPC :8547   │     │ RPC :8548   │
│ WAL :/data  │     │ WAL :/data  │     │ WAL :/data  │     │ WAL :/data  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       └───────────────────┴───────────────────┴───────────────────┘
                           Full mesh TCP (mTLS)
                           Machine A          Machine B
                           (or 4 machines)
```

Each validator runs one `oxide-validator` process with:

- **Consensus TCP port** — peer-to-peer BFT messages (votes, QCs,
  proposals). This is the only port that MUST be reachable by all
  other validators.
- **RPC HTTP port** — JSON-RPC, `/health`, `/metrics`, `/snapshot`.
  Expose to operators only (or bind to localhost + SSH tunnel).
- **WAL directory** — write-ahead log for restart safety. Survives
  crashes; must be on persistent storage.
- **mTLS** — all peer connections are mutually authenticated via
  X.509 certificates bound to peer IDs.

The current `--devnet-node` mode works for a testnet but has
limitations documented below. The recommended production path uses
`--config` with a per-node TOML file.

---

## 2. Infrastructure requirements

### Minimum (4 validators, 1 per machine)

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Machines | 4 VMs (or 2 VMs × 2 validators) | 4 dedicated VMs |
| CPU | 2 vCPU | 4+ vCPU |
| RAM | 4 GB | 8+ GB |
| Disk | 20 GB SSD | 100+ GB NVMe (journal grows) |
| Network | 1 Gbps, <50ms inter-node RTT | <10ms inter-node RTT |
| OS | Linux (glibc ≥2.36) or macOS | Debian 12 / Ubuntu 22.04+ |
| NTP | chrony or systemd-timesyncd | chrony with 2+ sources |

### Network requirements

- Each validator needs a **public IP** (or a private IP reachable
  by all other validators — a VPN/tailscale mesh works).
- TCP port `22000 + node_index` must be open inbound and outbound
  between all validators.
- The RPC port (`8545 + node_index`) can be bound to `127.0.0.1`
  and accessed via SSH tunnel for security.
- **Clock sync is mandatory.** `oxideBFT` view timeouts are 2s;
  >500ms clock drift causes spurious timeouts. Verify with
  `chronyc tracking` or `timedatectl`.

### Scaling

- **4 validators:** `f = 1` Byzantine fault tolerance. Minimum for
  meaningful BFT testing.
- **7 validators:** `f = 2`. Recommended for a public testnet.
- **10+ validators:** `f ≥ 3`. Approaching production scale.

For `n` validators, quorum is `⌈2n/3⌉`. With `n = 3f + 1`, that's
`2f + 1` out of `3f + 1` — one validator can be offline/byzantine.

---

## 3. Key generation

Each validator needs **two kinds of keys**:

| Key type | Purpose | Format |
|----------|---------|--------|
| BLS12-381 secret key | Sign consensus votes and proposals | 32 bytes |
| TLS certificate | mTLS peer authentication | X.509 PEM |

### 3.1 BLS keys

The current `--devnet-node` mode derives BLS keys deterministically
from the node index (`bls_key(i)` where `i` is the index). This is
**not secure for public use** — anyone who knows the index can
derive the key.

For a public testnet, generate random keys:

```sh
# On each validator machine:
openssl rand -hex 32 > /etc/oxide/bls-key.hex
```

Or use the validator binary (once `--generate-key` is wired):

```sh
oxide-validator --generate-key --output /etc/oxide/bls-key.json
```

The genesis file records each validator's **public key** (48 bytes,
compressed BLS12-381) and **staking address** (20 bytes, derived
from the public key via `validator_address(pk)`).

### 3.2 TLS certificates (mTLS — C4)

For a public testnet, each validator needs a certificate signed by
a shared CA (or a set of self-signed certs distributed to all peers).

**Option A: Shared CA (recommended for testnet)**

```sh
# 1. Create a testnet CA (once, on a secure machine).
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
    -out ca.crt -subj "/CN=oxide-testnet-ca"

# 2. For each validator, generate a key + CSR + sign.
for i in 0 1 2 3; do
    openssl genrsa -out "validator-${i}.key" 2048
    openssl req -new -key "validator-${i}.key" \
        -out "validator-${i}.csr" -subj "/CN=validator-${i}"
    openssl x509 -req -in "validator-${i}.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "validator-${i}.crt" -days 365 -sha256
done

# 3. Distribute: each validator gets ca.crt + its own .key + .crt.
```

**Option B: Self-signed via `tls-gen` (testnet)**

`oxide-validator tls-gen` generates self-signed certificates for all
validators and writes per-node `--tls-dir` directories:

```sh
oxide-validator tls-gen --num-nodes 4 --output-dir tls/
# Generates: tls/node-{i}/cert.pem, key.pem, peer-{j}.pem

# Each validator runs with:
oxide-validator --devnet-node 0 --tls-dir tls/node-0 ...
```

Each node's `peer-{j}.pem` files are the other validators' `cert.pem`
files — the `peer_id_map` binds cert DER → peer ID. For a testnet
on a single operator's machines, this is sufficient. For a public
testnet with multiple operators, use Option A (shared CA) — each
operator generates their own key, submits a CSR to the shared CA,
and receives a signed cert + the CA's certificate.

**Recommendation:** `tls-gen` for a single-operator testnet;
shared CA for multi-operator.

### 3.3 Staking addresses

Each validator's staking address is derived from its BLS public key:

```
Address = hash(ValidatorAddress ‖ bls_public_key)[..20]
```

The `ValidatorSet` records these addresses via `with_addresses()`.
For the genesis file, compute them:

```rust
// On the deployment coordinator machine:
let addr = validator_address(&public_key);
// addr is a 20-byte Address — format as 0x + 40 hex chars
```

---

## 4. Configuration files

### 4.1 Genesis file (`genesis.json`)

One shared genesis file for all validators. It defines the initial
validator set, pre-funded accounts, and consensus parameters.

```json
{
  "chain_id": 42,
  "consensus": {
    "engine": "oxidebft",
    "base_timeout_ms": 2000,
    "max_timeout_ms": 30000
  },
  // Legacy alias: "bank.balances" is still accepted and folded
  // into the EVM account store (base units -> wei). New genesis
  // files should use "evm.alloc" directly.
  "evm": {
    "alloc": {
      "0x0000000000000000000000000000000000000000": {
        "balance": "1000000000000000000000000000000"
      },
      "0x0101010101010101010101010101010101010101": {
        "balance": "1000000000000000000000000000000"
      }
    }
  },
  "staking": {
    "validators": [
      {
        "address": "0x<validator_address(pk_0)>",
        "stake": 1000000
      },
      {
        "address": "0x<validator_address(pk_1)>",
        "stake": 1000000
      },
      {
        "address": "0x<validator_address(pk_2)>",
        "stake": 1000000
      },
      {
        "address": "0x<validator_address(pk_3)>",
        "stake": 1000000
      }
    ],
    "unbonding_period_blocks": 100,
    "block_reward": 1000000000
  }
}
```

Replace `<validator_address(pk_i)>` with the computed staking
address for each validator's BLS public key.

### 4.2 Per-node config (`oxide-node-<i>.toml`)

Each validator gets its own TOML config with its specific listen
address, peer list, and (eventually) key paths.

```toml
# oxide-node-0.toml — validator 0 on machine A
[network]
# Listen on all interfaces — public testnet.
listen_addr = "0.0.0.0:22000"
# Peers: all other validators. Use public IPs or DNS names.
peers = [
    "validator-1.example.com:22001",
    "validator-2.example.com:22002",
    "validator-3.example.com:22003",
]
# Longer timeouts for WAN — 5s is too short for 50ms+ RTT.
connect_timeout_secs = 10
read_timeout_secs = 60
max_message_bytes = 16777216

[consensus]
engine = "oxidebft"
# Longer base timeout for WAN — 2s is too tight for >20ms RTT.
# Rule of thumb: base_timeout > 2 × worst-case RTT + jitter.
base_timeout_ms = 5000
max_timeout_ms = 60000
max_block_bytes = 1048576
max_block_gas = 1000000000

[executor]
max_mempool_entries = 10000
parallel_threshold = 100

[genesis]
genesis_balance = 1000000000000
num_prefunded_senders = 32
num_validators = 4
base_port = 22000
```

**Key changes for public testnet vs. local devnet:**

| Setting | Local devnet | Public testnet | Why |
|---------|-------------|----------------|-----|
| `listen_addr` | `127.0.0.1` | `0.0.0.0` | Must accept external connections |
| `connect_timeout_secs` | 5 | 10 | WAN latency |
| `read_timeout_secs` | 30 | 60 | WAN jitter |
| `base_timeout_ms` | 2000 | 5000 | >2× worst-case RTT |
| `max_timeout_ms` | 30000 | 60000 | Allow more backoff |
| `peers` | `127.0.0.1:*` | public IPs/DNS | Reachable addresses |

### 4.3 `ValidatorSet` construction

The `ValidatorSet` is constructed from the BLS public keys and
staking addresses. For `--devnet-node` mode, these are derived
deterministically. For a proper testnet, they come from the genesis
file + pre-generated keys.

**Current `--devnet-node` approach (works for testing):**

```sh
oxide-validator --devnet-node 0 --num-nodes 4 \
    --base-port 22000 --bind-host 0.0.0.0 \
    --peer-host validator-{i}.example.com
```

This derives BLS keys from the node index (deterministic) and
uses `Address([i; 20])` for staking addresses. Peers are computed
as `validator-{i}.example.com:2200{i}`.

**Limitations of `--devnet-node` for public testnet:**

- BLS keys are deterministic (insecure for public use)
- No TLS (plain TCP — anyone can read/inject consensus messages)
- No WAL persistence (restart loses consensus state)
- No RPC endpoint configured
- Peer addresses are auto-computed (no manual override)

**Recommended path:** Use `--config` with a per-node TOML that
specifies the BLS key path, TLS cert paths, and peer list. This
requires the binary to support loading keys/certs from files —
partially implemented (`TlsConfig::from_files` exists in the p2p
crate but is not wired into the validator binary yet).

---

## 5. Deployment: bare binary

### 5.1 Build the binary

```sh
# On the deployment machine (or cross-compile):
cargo build --release -p oxide-validator

# The binary is at:
target/release/oxide-validator
```

### 5.2 Distribute

```sh
# Copy to each validator machine:
for i in 0 1 2 3; do
    scp target/release/oxide-validator \
        validator-${i}.example.com:/usr/local/bin/
done
```

### 5.3 Start each validator

**Using `--devnet-node` (quick testnet):**

```sh
# On validator-0 (machine A):
nohup oxide-validator --devnet-node 0 --num-nodes 4 \
    --base-port 22000 --bind-host 0.0.0.0 \
    --peer-host-template "validator-{i}.example.com" \
    > /var/log/oxide/validator.log 2>&1 &

# On validator-1 (machine B):
nohup oxide-validator --devnet-node 1 --num-nodes 4 \
    --base-port 22000 --bind-host 0.0.0.0 \
    --peer-host-template "validator-{i}.example.com" \
    > /var/log/oxide/validator.log 2>&1 &

# ... same for validators 2 and 3
```

The `--peer-host-template` flag uses `{i}` as a placeholder for the
peer index: `"validator-{i}.example.com"` produces peers
`validator-0.example.com:22000`, `validator-1.example.com:22001`,
etc. If all validators share the same hostname prefix, this works.
For heterogeneous addresses (different hostnames or IPs), use
`--config` with an explicit `peers` list instead.

**Using `--config` (recommended):**

```sh
nohup oxide-validator --config /etc/oxide/oxide-node-0.toml \
    > /var/log/oxide/validator.log 2>&1 &
```

### 5.4 systemd unit (recommended for production)

```ini
# /etc/systemd/system/oxide-validator.service
[Unit]
Description=Oxide Validator Node
After=network.target

[Service]
Type=simple
User=oxide
ExecStart=/usr/local/bin/oxide-validator --config /etc/oxide/oxide.toml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/oxide
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
systemctl enable oxide-validator
systemctl start oxide-validator
journalctl -u oxide-validator -f
```

---

## 6. Deployment: Docker

The `Dockerfile` builds a release binary inside a container. For a
multi-machine testnet, each machine runs one container.

### 6.1 Build and push

```sh
docker build -t oxide-validator:latest .

# Tag for a registry:
docker tag oxide-validator:latest registry.example.com/oxide-validator:latest
docker push registry.example.com/oxide-validator:latest
```

### 6.2 docker-compose per machine

```yaml
# docker-compose.yml on validator-0
version: "3.8"
services:
  validator:
    image: registry.example.com/oxide-validator:latest
    command: ["--devnet-node", "0", "--num-nodes", "4",
              "--base-port", "22000", "--bind-host", "0.0.0.0",
              "--peer-host-template", "validator-{i}.example.com"]
    ports:
      - "22000:22000"
      - "8545:8545"
    volumes:
      - oxide-data:/var/lib/oxide
    restart: unless-stopped
    networks:
      - oxide

volumes:
  oxide-data:

networks:
  oxide:
    driver: bridge
```

### 6.3 Kubernetes (for larger testnets)

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: oxide-validator
spec:
  serviceName: oxide-validator
  replicas: 4
  selector:
    matchLabels:
      app: oxide-validator
  template:
    metadata:
      labels:
        app: oxide-validator
    spec:
      containers:
      - name: validator
        image: registry.example.com/oxide-validator:latest
        args: ["--devnet-node", "$(POD_INDEX)", "--num-nodes", "4",
               "--base-port", "22000", "--bind-host", "0.0.0.0",
               "--peer-host-template", "oxide-validator-{i}.oxide.svc.cluster.local"]
        env:
        - name: POD_INDEX
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        ports:
        - containerPort: 22000
          name: consensus
        - containerPort: 8545
          name: rpc
        volumeMounts:
        - name: data
          mountPath: /var/lib/oxide
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi
```

---

## 7. Firewall and security groups

### Inbound rules (each validator)

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 22000 + i | TCP | Other validators' IPs | Consensus messages |
| 8545 + i | TCP | Operator IPs only (or localhost) | RPC/monitoring |

**AWS security group example:**

```hcl
resource "aws_security_group" "oxide_validator" {
  ingress {
    from_port   = 22000
    to_port     = 22003
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # VPC CIDR or peer IPs
  }
  ingress {
    from_port   = 8545
    to_port     = 8548
    protocol    = "tcp"
    cidr_blocks = ["YOUR_IP/32"]  # Operator only
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

### Outbound rules

- All outbound TCP allowed (validators connect to each other).
- DNS resolution if using hostnames for peers.

### iptables (bare metal)

```sh
# Allow consensus port from specific peer IPs:
iptables -A INPUT -p tcp --dport 22000 -s <peer-ip-1> -j ACCEPT
iptables -A INPUT -p tcp --dport 22000 -s <peer-ip-2> -j ACCEPT
iptables -A INPUT -p tcp --dport 22000 -s <peer-ip-3> -j ACCEPT
iptables -A INPUT -p tcp --dport 22000 -j DROP  # Drop all other inbound

# RPC on localhost only:
iptables -A INPUT -p tcp --dport 8545 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 8545 -j DROP
```

---

## 8. Monitoring

### 8.1 Health check

```sh
# SSH tunnel to the RPC port:
ssh -L 8545:localhost:8545 validator-0.example.com

# Check health:
curl -s http://localhost:8545/health
# Expected: {"status":"healthy","height":N,"peers":M}
```

### 8.2 Metrics (Prometheus)

```sh
curl -s http://localhost:8545/metrics | grep oxide_
```

Key metrics to watch:

| Metric | Healthy | Alert |
|--------|---------|-------|
| `oxide_finalized_height` | Increasing | Flat >60s |
| `oxide_current_view` | Advancing | Flat >30s |
| `oxide_peer_count` | ≥ quorum | <2 |
| `oxide_mempool_size` | 0–max | At max |
| `oxide_block_time_ms` | 200–2000 | >5000 |

### 8.3 Prometheus scrape config

```yaml
scrape_configs:
  - job_name: oxide-validators
    static_configs:
      - targets:
        - validator-0.example.com:8545
        - validator-1.example.com:8546
        - validator-2.example.com:8547
        - validator-3.example.com:8548
    metrics_path: /metrics
    scrape_interval: 15s
```

### 8.4 JSON-RPC (for tooling)

```sh
curl -s http://localhost:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
# Expected: {"jsonrpc":"2.0","result":"0x<hex_height>","id":1}
```

---

## 9. Operational procedures

### 9.1 Graceful shutdown

```sh
kill -TERM $(pidof oxide-validator)
# Or: systemctl stop oxide-validator
```

### 9.2 Restart with WAL recovery (C9)

```sh
# The WAL is in the working directory by default.
# On restart, the engine calls recover_from_wal() automatically.
systemctl restart oxide-validator
# Verify: the log should show recovered state (last_voted_view, high_qc)
```

### 9.3 Snapshot backup (runbook 3)

```sh
curl -s http://localhost:8545/snapshot > /backups/snapshot-$(date +%Y%m%d).hex
# Or via CLI:
oxide-validator --export-snapshot /backups/snapshot-$(date +%Y%m%d).bin
```

### 9.4 Snapshot restore (runbook 4)

```sh
oxide-validator --import-snapshot /backups/snapshot-20260914.bin
```

### 9.5 Key rotation (runbook 9)

```sh
# 1. Generate a new 32-byte BLS secret key (on a secure machine).
# 2. Submit the key-change tx from the running validator — the flag
#    takes the new SECRET key (hex); the node derives the public key
#    and the mandatory proof-of-possession itself:
oxide-validator --submit-key-change <new_bls_secret_key_hex>
# 3. Wait for the block to finalize.
# 4. Stop the validator, update the key file, restart.
```

### 9.6 Rolling upgrade (runbook 10)

```sh
# Upgrade one validator at a time — maintain quorum.
for i in 0 1 2 3; do
    ssh validator-${i} "systemctl stop oxide-validator"
    scp new-oxide-validator validator-${i}:/usr/local/bin/oxide-validator
    ssh validator-${i} "systemctl start oxide-validator"
    # Verify health before proceeding to next.
    sleep 10
    curl -s http://validator-${i}:8545/health
done
```

---

## 10. Validation checklist

After deploying, verify each item:

- [ ] **All validators online:** `curl http://validator-{i}:8545/health` returns `healthy` for all `i`
- [ ] **Peers connected:** `oxide_peer_count` ≥ 3 (for 4 validators)
- [ ] **Blocks finalizing:** `oxide_finalized_height` increasing on all validators
- [ ] **Same height:** All validators report the same `eth_blockNumber` (±1 block)
- [ ] **Same state root:** `oxide_state_root` matches across all validators
- [ ] **Block time:** `oxide_block_time_ms` < 2000ms sustained
- [ ] **mTLS:** TLS handshake succeeds; untrusted certs rejected
- [ ] **WAL recovery:** Kill + restart a validator — catches up without double-voting
- [ ] **Quorum resilience:** Stop 1 validator — remaining 3 continue finalizing
- [ ] **RPC:** `eth_blockNumber` returns the current height
- [ ] **Snapshot:** `/snapshot` returns a non-empty hex payload
- [ ] **Key rotation:** `--submit-key-change` finalizes and the new key is active after epoch rotation

---

## 11. Troubleshooting

### "No blocks being finalized"

- Check `oxide_peer_count` — are enough peers connected?
- Check `oxide_current_view` — is it advancing (view timeouts firing)?
- Check logs for `InsufficientQuorum` — are 3+ validators online?
- Check logs for `proposal rejected` — is the leader's proposal being voted on?

### "Connection refused" between validators

- Verify firewall rules allow inbound TCP on the consensus port.
- Verify the peer list in the config matches the actual addresses.
- Test connectivity: `nc -zv validator-1.example.com 22001`

### "TLS handshake failed"

- Verify all validators trust the same CA (or have each other's certs).
- Check cert expiry: `openssl x509 -in cert.pem -noout -dates`
- Check the `peer_id_map` — the cert DER must map to the expected peer ID.

### "View timeout storm" (repeated timeouts)

- Check clock sync: `chronyc tracking` — offset should be <100ms.
- Check RTT between validators: `ping validator-1` — if >500ms,
  increase `base_timeout_ms`.
- Check for a byzantine leader sending invalid proposals.

### "State root mismatch"

- Run the divergence check (runbook 7).
- The majority (3+) agree — the minority is divergent.
- Restore the divergent node from a snapshot.

---

## 12. What's covered vs. remaining blockers

The following production features are **now implemented** and covered
by this guide:

- **BLS key loading** — `--bls-key-file` loads a 32-byte BLS secret
  key (hex or raw). `oxide-validator genesis` fills `public_key` in
  `genesis.json`; production operators provide their own keys.
- **TLS cert loading** — `--tls-dir` loads `cert.pem`, `key.pem`,
  and `peer-{i}.pem` files. `oxide-validator tls-gen` generates
  self-signed certs for testnet; production uses a proper CA.
- **Genesis file loading** — `--genesis-file` loads `genesis.json`
  with validator addresses, public keys, stakes, and account balances
  (`evm.alloc`; a legacy `bank.balances` map is still accepted and
  folded into the same EVM accounts, base units -> wei).
- **WAL persistence** — `--wal-file` persists consensus safety state
  (last voted view, high QC, voted heights). Recovered on restart.
- **Snapshot persistence** — `--data-dir` auto-exports on shutdown
  and auto-imports on startup. `--export-snapshot`/`--import-snapshot`
  for manual control.
- **Validator set changes** — `VALIDATOR_ADD` (0x06) and
  `VALIDATOR_REMOVE` (0x07) staking messages for epoch-boundary
  validator set changes. `GET /validator-set` returns the current
  set for mid-epoch joins.
- **Graceful shutdown** — SIGINT/SIGTERM triggers clean shutdown
  with snapshot export.

### Remaining blockers for a public testnet

- **External security audit** — all 14 internal findings (4 critical,
  6 high, 4 medium) are fixed, but an external audit is required
  before production.
- **Rate limiting / DDoS protection** — the p2p layer has admission
  control but no IP-based rate limiting for public endpoints. The
  RPC has a per-IP rate limiter (`--max-rps`).
- **Write-through persistent storage** — `--data-dir` provides
  snapshot persistence, but the `KVStore` is still in-memory
  (write-through to disk on every commit is a future optimization).
- **Full-node peer discovery** — validators use a static peer list
  (correct for a known validator set). Full nodes joining the
  network need bootstrap nodes or a rendezvous protocol — a separate
  concern for `oxide-fullnode`.
