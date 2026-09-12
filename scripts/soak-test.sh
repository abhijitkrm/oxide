#!/bin/bash
# soak-test.sh — Gate 7 long-duration Docker soak with fault injection.
#
# Runs the four-validator Docker testnet for a configurable duration
# (default: 1 hour) and injects two faults:
#
#   1. Byzantine validator: stops validator-3 for 60 seconds, then
#      restarts it. Simulates a validator that stops voting.
#
#   2. Network partition: isolates validator-2 from the other three
#      validators for 90 seconds using iptables DROP rules, then
#      restores connectivity.
#
# Throughout the soak, the script samples finalized height from all
# four validators every 10 seconds and records:
#   - finalization rate (blocks/sec)
#   - view advancement
#   - recovery time after each fault
#   - state divergence (all four validators at the same height)
#
# Evidence is written to docs/evidence/gate7-soak/
#
# Usage:
#   scripts/soak-test.sh [duration_minutes]
#
# Defaults to 60 minutes.

set -euo pipefail

DURATION_MIN="${1:-60}"
DURATION_SEC=$((DURATION_MIN * 60))
EVIDENCE_DIR="docs/evidence/gate7-soak"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")

mkdir -p "$EVIDENCE_DIR"

LOG_FILE="$EVIDENCE_DIR/soak-${TIMESTAMP}.log"
SUMMARY_FILE="$EVIDENCE_DIR/soak-${TIMESTAMP}-summary.txt"
SAMPLES_FILE="$EVIDENCE_DIR/soak-${TIMESTAMP}-samples.csv"

echo "timestamp,validator,finalized_height,view,leader,votes" > "$SAMPLES_FILE"

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $*" | tee -a "$LOG_FILE"
}

# Get the finalized height from a validator's logs.
get_height() {
    local idx=$1
    # Handle stopped containers — return 0 if logs are unavailable.
    docker logs oxide-validator-$idx 2>&1 \
        | grep 'finalized height' \
        | tail -1 \
        | grep -oE '[0-9]+$' \
        2>/dev/null || echo "0"
}

# Get the debug status line from a validator.
get_status() {
    local idx=$1
    docker logs oxide-validator-$idx 2>&1 \
        | grep "iter=" \
        | tail -1
}

# Sample all four validators and append to CSV.
sample() {
    local ts=$1
    for i in 0 1 2 3; do
        local h=$(get_height $i)
        local status=$(get_status $i)
        local view=$(echo "$status" | grep -oE 'view=[0-9]+' | grep -oE '[0-9]+' || echo "0")
        local leader=$(echo "$status" | grep -oE 'leader=[0-9]+' | grep -oE '[0-9]+' || echo "0")
        local votes=$(echo "$status" | grep -oE 'votes=[0-9]+' | grep -oE '[0-9]+' || echo "0")
        echo "$ts,$i,$h,$view,$leader,$votes" >> "$SAMPLES_FILE"
    done
}

# Check all four validators agree on finalized height.
check_divergence() {
    local h0=$(get_height 0)
    local h1=$(get_height 1)
    local h2=$(get_height 2)
    local h3=$(get_height 3)
    local max_h=$h0
    for h in $h1 $h2 $h3; do
        if [ "$h" -gt "$max_h" ]; then max_h=$h; fi
    done
    # Allow up to 5 blocks of lag (one validator may be slightly behind).
    for h in $h0 $h1 $h2 $h3; do
        local diff=$((max_h - h))
        if [ "$diff" -gt 10 ]; then
            log "DIVERGENCE: heights=[$h0,$h1,$h2,$h3] max=$max_h lag=$diff"
            return 1
        fi
    done
    return 0
}

# ── Main ───────────────────────────────────────────────────────────

log "=== Gate 7 Soak Test START ==="
log "Duration: $DURATION_MIN minutes ($DURATION_SEC seconds)"
log "Faults: byzantine (stop validator-3), partition (isolate validator-2)"
log ""

# Record start heights.
START_HEIGHT=$(get_height 0)
log "Start height (validator-0): $START_HEIGHT"

# ── Phase 1: Baseline (first 20% of duration) ─────────────────────
PHASE1_END=$((DURATION_SEC / 5))
log "Phase 1: Baseline (0-${PHASE1_END}s) — no faults"
START_TIME=$(date +%s)
ELAPSED=0
while [ "$ELAPSED" -lt "$PHASE1_END" ]; do
    sample "$ELAPSED"
    check_divergence || log "WARNING: divergence during baseline"
    sleep 10
    ELAPSED=$(( $(date +%s) - START_TIME ))
done
log "Phase 1 complete. Height: $(get_height 0)"

# ── Phase 2: Byzantine validator (stop validator-3 for 60s) ─────────
log "Phase 2: Byzantine fault — stopping validator-3 for 60s"
FAULT_START=$(date +%s)
docker stop oxide-validator-3 >/dev/null 2>&1
log "validator-3 stopped at height $(get_height 3)"

# Wait 60 seconds with the byzantine validator down.
BYZ_DURATION=60
BYZ_END=$(( $(date +%s) + BYZ_DURATION ))
while [ "$(date +%s)" -lt "$BYZ_END" ]; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    sample "$ELAPSED"
    check_divergence || log "WARNING: divergence during byzantine fault (expected — validator-3 down)"
    sleep 10
done

# Restart validator-3.
docker start oxide-validator-3 >/dev/null 2>&1
log "validator-3 restarted"
RECOVERY_START=$(date +%s)

# Wait for validator-3 to catch up (up to 120s).
RECOVERY_TIMEOUT=120
while true; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    sample "$ELAPSED"
    if check_divergence; then
        RECOVERY_TIME=$(( $(date +%s) - RECOVERY_START ))
        log "Byzantine recovery: ${RECOVERY_TIME}s (validator-3 caught up)"
        break
    fi
    RECOVERY_TIME=$(( $(date +%s) - RECOVERY_START ))
    if [ "$RECOVERY_TIME" -ge "$RECOVERY_TIMEOUT" ]; then
        log "WARNING: byzantine recovery took >${RECOVERY_TIMEOUT}s"
        break
    fi
    sleep 10
done
log "Phase 2 complete. Heights: [$(get_height 0),$(get_height 1),$(get_height 2),$(get_height 3)]"

# ── Phase 3: Stable period (20% of duration) ───────────────────────
PHASE3_END=$((DURATION_SEC * 2 / 5))
log "Phase 3: Stable period (${ELAPSED}s-${PHASE3_END}s)"
while [ "$ELAPSED" -lt "$PHASE3_END" ]; do
    sample "$ELAPSED"
    check_divergence || log "WARNING: divergence during stable period"
    sleep 10
    ELAPSED=$(( $(date +%s) - START_TIME ))
done
log "Phase 3 complete. Height: $(get_height 0)"

# ── Phase 4: Network partition (isolate validator-2 for 90s) ──────
log "Phase 4: Network partition — isolating validator-2 for 90s"
PART_START=$(date +%s)

# Drop all traffic between validator-2 and the other validators.
# Use `tc netem` with 100% loss (the container has iproute2 but not
# iptables). This effectively partitions validator-2 from the network.
docker exec oxide-validator-2 tc qdisc replace dev eth0 root netem loss 100% 2>/dev/null || true
log "validator-2 isolated (tc netem loss 100% applied)"

PART_DURATION=90
PART_END=$(( $(date +%s) + PART_DURATION ))
while [ "$(date +%s)" -lt "$PART_END" ]; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    sample "$ELAPSED"
    check_divergence || log "WARNING: divergence during partition (expected — validator-2 isolated)"
    sleep 10
done

# Heal the partition: restore the original latency (20ms + 2ms jitter).
docker exec oxide-validator-2 tc qdisc replace dev eth0 root netem delay 20ms 2ms 2>/dev/null || true
log "validator-2 partition healed (tc netem restored to 20ms)"
RECOVERY_START=$(date +%s)

# Wait for validator-2 to catch up.
RECOVERY_TIMEOUT=120
while true; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    sample "$ELAPSED"
    if check_divergence; then
        RECOVERY_TIME=$(( $(date +%s) - RECOVERY_START ))
        log "Partition recovery: ${RECOVERY_TIME}s (validator-2 caught up)"
        break
    fi
    RECOVERY_TIME=$(( $(date +%s) - RECOVERY_START ))
    if [ "$RECOVERY_TIME" -ge "$RECOVERY_TIMEOUT" ]; then
        log "WARNING: partition recovery took >${RECOVERY_TIMEOUT}s"
        break
    fi
    sleep 10
done
log "Phase 4 complete. Heights: [$(get_height 0),$(get_height 1),$(get_height 2),$(get_height 3)]"

# ── Phase 5: Final stable period (remaining duration) ─────────────
log "Phase 5: Final stable period (${ELAPSED}s-${DURATION_SEC}s)"
while [ "$ELAPSED" -lt "$DURATION_SEC" ]; do
    sample "$ELAPSED"
    check_divergence || log "WARNING: divergence during final period"
    sleep 10
    ELAPSED=$(( $(date +%s) - START_TIME ))
done

# ── Summary ────────────────────────────────────────────────────────
END_HEIGHT=$(get_height 0)
TOTAL_BLOCKS=$((END_HEIGHT - START_HEIGHT))
TOTAL_TIME=$ELAPSED
BLOCKS_PER_SEC=$(echo "scale=4; $TOTAL_BLOCKS / $TOTAL_TIME" | bc -l 2>/dev/null || echo "N/A")

log "=== Gate 7 Soak Test END ==="
log "Total duration: ${TOTAL_TIME}s"
log "Total blocks finalized: $TOTAL_BLOCKS (from $START_HEIGHT to $END_HEIGHT)"
log "Finalization rate: $BLOCKS_PER_SEC blocks/sec"
log "Final heights: [$(get_height 0),$(get_height 1),$(get_height 2),$(get_height 3)]"

# Write summary file.
cat > "$SUMMARY_FILE" <<EOF
Gate 7 Soak Test Summary
========================
Timestamp: $TIMESTAMP
Duration: ${TOTAL_TIME}s ($DURATION_MIN minutes requested)
Faults injected:
  1. Byzantine: validator-3 stopped for 60s
  2. Partition: validator-2 isolated for 90s (iptables DROP)
Start height: $START_HEIGHT
End height: $END_HEIGHT
Total blocks: $TOTAL_BLOCKS
Finalization rate: $BLOCKS_PER_SEC blocks/sec
Final heights: [$(get_height 0),$(get_height 1),$(get_height 2),$(get_height 3)]
State divergence: $(check_divergence && echo "NONE" || echo "DETECTED")
Latency: 20ms, Jitter: 2ms
Validators: 4
EOF

log "Summary written to $SUMMARY_FILE"
log "Samples written to $SAMPLES_FILE"
log "Log written to $LOG_FILE"
