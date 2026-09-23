# Oxide Operational Runbooks

This document covers the operational procedures for running an Oxide
validator or full node in production. Each runbook is self-contained:
what it does, when to use it, prerequisites, steps, and verification.

## Table of contents

1. [Startup](#1-startup)
2. [Shutdown](#2-shutdown)
3. [Backup and snapshot export](#3-backup-and-snapshot-export)
4. [Restore from snapshot](#4-restore-from-snapshot)
5. [Incident response: node stalled](#5-incident-response-node-stalled)
6. [Incident response: consensus halt](#6-incident-response-consensus-halt)
7. [Incident response: state divergence](#7-incident-response-state-divergence)
8. [Monitoring and health checks](#8-monitoring-and-health-checks)
9. [Key rotation](#9-key-rotation)
10. [Software upgrade](#10-software-upgrade)

---

## 1. Startup

### When to use

Starting a new validator or full node, or restarting after a
planned shutdown or crash.

### Prerequisites

- The `oxide-validator` (validator) or `oxide-fullnode` (full node)
  binary is built and available.
- The node's configuration file (`oxide.toml`) is in place with the
  correct peer list, bind address, and BLS key path.
- The BLS key file exists and is readable by the process.
- The data directory is writable and has sufficient disk space
  (minimum 10 GB for the journal; 100+ GB for a long-running node).
- The system clock is synchronized (NTP or chrony). Clock drift
  >500 ms can cause view timeout issues.

### Steps

```sh
# 1. Verify the binary version.
oxide-validator --version

# 2. Verify the configuration.
oxide-validator --config /path/to/oxide.toml --dry-run

# 3. Start the node in the background.
oxide-validator --config /path/to/oxide.toml &

# 4. Watch the startup log for "consensus engine started".
tail -f /var/log/oxide/validator.log
```

### Verification

- The log shows `consensus engine started, waiting for blocks...`.
- The log shows `listening on <bind_host>:<port>, N peers`.
- Within 30 seconds, the log shows `finalized height = 1` (or the
  first block after the node's starting height).
- The Prometheus metrics endpoint (`http://localhost:9000/metrics`)
  returns `oxide_finalized_height` > 0.

### Troubleshooting

- **No peers connected:** Check the peer list in the config. Verify
  firewall rules allow inbound TCP on the bind port and outbound TCP
  to all peer addresses.
- **InsufficientQuorum errors:** Check that 3 of 4 validators are
  online and reachable. A single validator cannot finalize blocks.
- **State root mismatch on startup:** The node's local state is
  corrupted. Restore from a snapshot (runbook 4).

---

## 2. Shutdown

### When to use

Planned maintenance, software upgrade, or decommissioning.

### Steps

```sh
# 1. Send SIGTERM to the process (graceful shutdown).
kill -TERM $(pidof oxide-validator)

# 2. Wait for the process to exit (up to 30 seconds).
#    The node flushes pending blocks and closes peer connections.

# 3. Verify the process has exited.
ps aux | grep oxide-validator
```

### Verification

- The log shows `shutting down...` and `goodbye`.
- The process is no longer running.
- The data directory's lock file (if any) is removed.

### Notes

- Do not use `kill -9` (SIGKILL) unless the process is hung. SIGKILL
  skips the graceful shutdown and may leave the journal in an
  inconsistent state. The journal is recoverable (it's append-only),
  but the node will need to replay from the last checkpoint.
- If the node is a validator, shutting it down reduces the network's
  fault tolerance. With 4 validators, shutting down 1 leaves 3
  (still above the 3-of-4 quorum threshold). Shutting down 2 or more
  halts consensus.

---

## 3. Backup and snapshot export

### When to use

- Regular backups (daily or before upgrades).
- Before any maintenance that risks data loss.
- To provide a snapshot for a new node joining the network.

### Steps

```sh
# 1. Export a snapshot via the RPC endpoint.
#    This produces a JSON file with the chain height, state root,
#    per-module roots, and full KV state.
curl -s http://localhost:9000/snapshot > snapshot.json

# 2. Verify the snapshot is non-empty and has the expected height.
jq '.height' snapshot.json
jq '.state_root' snapshot.json
jq '.module_roots | length' snapshot.json

# 3. Copy the snapshot to a backup location.
cp snapshot.json /backups/oxide-snapshot-$(date +%Y%m%d).json

# 4. Optionally, back up the raw data directory.
tar czf /backups/oxide-data-$(date +%Y%m%d).tar.gz /var/lib/oxide/
```

### Verification

- The snapshot file is non-empty and valid JSON.
- The height matches the node's current finalized height.
- The state root matches the node's `attest_state` output.

### Notes

- The snapshot includes the `executed_nonces` map (H4/H5 fix), so
  replay protection survives restore.
- The snapshot is deterministic: two nodes with the same state
  produce byte-identical snapshots.

---

## 4. Restore from snapshot

### When to use

- A new node joining the network (fast sync without replaying
  genesis).
- A corrupted node recovering from a known-good snapshot.
- After a state divergence incident (runbook 7).

### Prerequisites

- A valid snapshot file from a trusted source.
- The node binary is built and the configuration is in place.
- The data directory is empty (or will be overwritten).

### Steps

```sh
# 1. Stop the node if it's running (runbook 2).

# 2. Clear the data directory (if restoring a corrupted node).
rm -rf /var/lib/oxide/*

# 3. Start the node with the --import-snapshot flag.
oxide-validator --config /path/to/oxide.toml \
  --import-snapshot /path/to/snapshot.json

# 4. Watch the log for the import to complete.
tail -f /var/log/oxide/validator.log
```

### Verification

- The log shows `snapshot imported: height=N, root=0x...`.
- The node's finalized height matches the snapshot's height.
- The node begins syncing new blocks from the snapshot's height + 1.
- The `executed_nonces` map is restored (replay protection is active).

### Notes

- The snapshot's module roots are recomputed from the imported KV
  data and verified against the snapshot's claimed roots (M3 fix).
  If they don't match, the import is rejected.
- The snapshot must be from a trusted source. The import verifies
  internal consistency (state root matches module roots, module
  roots match KV data) but does not verify the snapshot against the
  chain's consensus (that requires syncing from genesis or trusting
  a checkpoint).

---

## 5. Incident response: node stalled

### Symptoms

- The node's finalized height has not advanced for >60 seconds.
- The log shows repeated `view timeout` messages.
- The Prometheus metrics show `oxide_finalized_height` flatlined.

### Diagnosis

```sh
# 1. Check if the node is still running.
ps aux | grep oxide-validator

# 2. Check peer connectivity.
curl -s http://localhost:9000/peers | jq .

# 3. Check the consensus state.
curl -s http://localhost:9000/consensus | jq .

# 4. Check the log for errors.
tail -100 /var/log/oxide/validator.log | grep -i error
```

### Resolution

- **If the node is not running:** Restart it (runbook 1).
- **If peers are disconnected:** Check network connectivity, firewall
  rules, and peer health. If >1 validator is down, the network
  cannot finalize (needs 3-of-4).
- **If the node is running but not finalizing:** Check for state
  divergence (runbook 7). If no divergence, restart the node.
- **If the log shows `InsufficientQuorum`:** Not enough validators
  are online. Wait for the missing validators to come back, or
  contact the validator operators.

---

## 6. Incident response: consensus halt

### Symptoms

- All nodes' finalized heights have stopped advancing.
- No new blocks are being proposed or finalized.
- The network is live (peers are connected) but no progress.

### Diagnosis

```sh
# 1. Check if 3+ validators are online.
for host in validator-0 validator-1 validator-2 validator-3; do
  echo "$host: $(curl -s http://$host:9000/health 2>/dev/null || echo 'unreachable')"
done

# 2. Check each validator's current view and height.
for host in validator-0 validator-1 validator-2 validator-3; do
  echo "$host: $(curl -s http://$host:9000/consensus 2>/dev/null | jq -c '{view, height}' || echo 'unreachable')"
done

# 3. Check for conflicting proposals or QC errors in the logs.
for host in validator-0 validator-1 validator-2 validator-3; do
  echo "=== $host ==="
  ssh $host "tail -100 /var/log/oxide/validator.log | grep -i 'error\|reject\|conflict'"
done
```

### Resolution

- **If 2+ validators are down:** The network cannot finalize (needs
  3-of-4). Wait for the missing validators to come back. If a
  validator is permanently lost, initiate a key rotation (runbook 9)
  to replace it.
- **If all validators are up but not finalizing:** Check for state
  divergence (runbook 7). If all nodes agree on state, check for
  network partitions (use `tc` or `ping` to verify connectivity).
- **If a byzantine validator is sending conflicting proposals:**
  The consensus engine should reject them (H5 fix: nonce ordering,
  C3 fix: BLS vote malleability). If the issue persists, identify
  the byzantine validator from the logs and remove it from the
  validator set (runbook 9).

---

## 7. Incident response: state divergence

### Symptoms

- The diverged validator's `/health` endpoint returns
  **503 Service Unavailable** with a body naming the diverged
  height, the local root, and the quorum-certified root.
- `oxide_exec_diverged` is `1` on the node's `/metrics` endpoint,
  and `oxide_exec_divergence_height` reports the height.
- The log shows
  `oxideBFT: CRITICAL — execution divergence at height N: local root
  ... != quorum-certified root ...; signing halted`.
- The validator stops signing entirely — no votes, timeouts,
  attestations, or proposals — so the network's finalized-height
  rate may drop if it was needed for quorum.

This state is terminal for the node: a verified execution
certificate proves a stake supermajority attested a state root this
node did not compute. The latch is persisted in the consensus WAL,
so restarting without repair does NOT clear it — the node comes
back up still refusing to sign. The only clearing path is certified
state repair (which rebuilds executor state, not the safety latch).

### Diagnosis

```sh
# 1. Pull the divergence detail — the certified root in the body is
#    the repair anchor (do NOT substitute an unverified root).
curl -s http://diverged-host:9000/health
# "execution divergence at height 1234: local root 0xaaaa...,
#  certified root 0xbbbb...; signing halted — repair via
#  --state-sync with --trusted-height 1234 --trusted-root 0xbbbb..."

# 2. Confirm the metric latch.
curl -s http://diverged-host:9000/metrics | grep oxide_exec_diverged
# oxide_exec_diverged 1

# 3. Identify the divergent node(s). The majority (quorum) agrees on
#    the certified root — the node reporting the mismatch is the one
#    to repair. If MULTIPLE nodes report divergence at the same
#    height, stop all of them and escalate: that is a potential
#    consensus-level execution bug, not a single-node fault.
```

### Resolution

1. **Stop the diverged node** (runbook 2).
2. **Repair via certified state sync** from a peer that agrees with
   the certified root, using the anchor from the `/health` body:

   ```sh
   oxide-validator --config /path/to/oxide.toml \
     --state-sync <healthy-peer-rpc-host:port> \
     --trusted-height <height-from-health-body> \
     --trusted-root 0x<certified-root-from-health-body>
   ```

   The certified root is quorum-signed — it is the correct trusted
   anchor even when the local root "looks" more plausible. Never
   pass the local root.
3. **Restart the node** (runbook 1) and verify `/health` returns 200
   and `oxide_exec_diverged` is 0.
4. **Investigate the cause before wiping evidence:** preserve the
   data directory (journal + snapshot) — the divergence may
   indicate a nondeterministic-execution bug that must be root-caused
   before the node rejoins.

### Prevention

- The executor's nonce enforcement prevents most divergence caused
  by replay or nonce reordering.
- The snapshot import verification prevents importing corrupted
  state.
- The divergence check runs on every verified execution certificate
  embedded in a proposal; a confirmed mismatch latches the engine
  and halts all signing automatically — there is no silent path.

---

## 8. Monitoring and health checks

### Key metrics

| Metric | Endpoint | Healthy | Alert |
|--------|----------|---------|-------|
| Finalized height | `oxide_finalized_height` | Increasing | Flat for >60s |
| Current view | `oxide_current_view` | Advancing | Flat for >30s |
| Peer count | `oxide_peer_count` | 3+ (for validators) | <2 |
| Mempool size | `oxide_mempool_size` | 0–max | At max |
| Block time | `oxide_block_time_ms` | 400–600 ms | >2000 ms |
| State root | `oxide_state_root` | Matches majority | Mismatch |
| Execution divergence | `oxide_exec_diverged` | 0 | 1 — page immediately (runbook 7) |
| Divergence height | `oxide_exec_divergence_height` | absent | present — repair anchor |

### Health check

```sh
curl -s http://localhost:9000/health
# Healthy: 200 OK, "ok"
# Diverged: 503 with the diverged height and certified root
#           (see runbook 7)
```

### Prometheus

The node exposes Prometheus metrics at `http://localhost:9000/metrics`.
Key dashboards:

- **Consensus:** finalized height, current view, block time, view
  timeouts, QC formation time.
- **Mempool:** size, intake rate, selection rate, eviction count.
- **Executor:** block execution time, state root, event count.
- **P2P:** peer count, bytes sent/received, connection errors.

### Alerting rules (recommended)

- `oxide_finalized_height` flat for >60 seconds → page.
- `oxide_peer_count` < 2 → page.
- `oxide_block_time_ms` > 2000 → warn.
- State root mismatch across validators → page.

---

## 9. Key rotation

### When to use

- A validator key is compromised.
- A validator operator is replaced.
- Regular key rotation (recommended annually).

### Steps

1. **Generate a new 32-byte BLS secret key** and keep it safe:
   ```sh
   openssl rand -hex 32 > /path/to/new-key.hex   # 64 hex chars
   ```

2. **Submit a key-change transaction** from the current validator.
   The flag takes the new **secret** key (hex): the transaction must
   attach a proof-of-possession (`Sign(sk, pk)` under the `BlsPop`
   domain), which only the secret key can produce — the node derives
   the public key and PoP automatically:
   ```sh
   oxide-validator --config /path/to/oxide.toml \
     --submit-key-change "0x$(cat /path/to/new-key.hex)"
   ```

3. **Wait for the key-change transaction to be finalized.** The
   network must finalize the block containing the key change before
   the new key is active.

4. **Stop the validator** (runbook 2).

5. **Update the configuration** to point to the new key file
   (`--bls-key-file` accepts the same hex/raw 32-byte format).

6. **Restart the validator** (runbook 1).

### Verification

- The validator's log shows the new BLS public key.
- The validator participates in consensus with the new key.
- The old key is no longer used for signing.

### Notes

- Key rotation requires the validator to be online to submit the
  key-change transaction. If the validator is down, the key change
  must be submitted by a different validator or via governance.
- The old key should be securely destroyed after rotation.

---

## 10. Software upgrade

### When to use

- Deploying a new version of the Oxide software.
- Applying a security patch.
- Upgrading consensus parameters.

### Steps

1. **Review the changelog** for breaking changes.
2. **Test the new version** on a local testnet first.
3. **Export a snapshot** from each validator (runbook 3).
4. **Coordinate the upgrade window** with all validator operators.
5. **For each validator, one at a time:**
   a. Stop the validator (runbook 2).
   b. Replace the binary.
   c. Start the validator (runbook 1).
   d. Verify the validator is healthy and finalizing blocks.
6. **After all validators are upgraded**, verify the network is
   finalizing at the expected rate.

### Rollback

If the upgrade causes issues:

1. Stop the upgraded validator (runbook 2).
2. Replace the binary with the previous version.
3. Restore from the snapshot taken before the upgrade (runbook 4).
4. Restart the validator (runbook 1).

### Notes

- Oxide uses a rolling upgrade strategy: upgrade one validator at a
  time, verifying each before proceeding. This maintains 3-of-4
  quorum throughout the upgrade.
- If the upgrade includes a consensus protocol change, all
  validators must upgrade within the same block window. Check the
  changelog for coordination requirements.
- If a rollback is needed, restoring from a snapshot ensures the
  node's state is consistent with the pre-upgrade chain.
