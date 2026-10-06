#!/usr/bin/env bash
# e2e-local.sh — process-level end-to-end check of the real validator
# loop (`oxide-devnet` → `node::validator_net`), runnable on a laptop
# (no Docker, no iptables; works on macOS and Linux).
#
# Phases, each with a pass/fail verdict:
#   1. liveness:  N validators finalize and agree on height
#   2. rejoin:    the last validator is killed, its data dir WIPED,
#                 and restarted; it must catch up to the fleet's
#                 height within REJOIN_DEADLINE seconds
#                 (docs/devlog.md: "wiped-node rejoin path")
#   3. agreement: all validators end within MAX_LAG blocks
#   4. inclusion: injected transactions are actually committed (a
#                 chain of empty heartbeat blocks also advances height,
#                 so height alone does not prove tx flow)
#
# Usage: scripts/e2e-local.sh [num_nodes] [tx_inject_rate]
# Env:   E2E_BASE_PORT (default 24000), E2E_RPC_PORT (default 25000),
#        REJOIN_DEADLINE (default 120), MAX_LAG (default 3)
set -euo pipefail

N="${1:-4}"
RATE="${2:-200}"
BASE_PORT="${E2E_BASE_PORT:-24000}"
RPC_PORT="${E2E_RPC_PORT:-25000}"
REJOIN_DEADLINE="${REJOIN_DEADLINE:-120}"
MAX_LAG="${MAX_LAG:-3}"
BIN="target/release/oxide-devnet"
WORK="$(mktemp -d -t oxide-e2e.XXXXXX)"
PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    if [ "${KEEP_E2E_DIR:-0}" = "1" ]; then echo "logs kept in $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

log() { echo "[e2e $(date +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; KEEP_E2E_DIR=1; exit 1; }

height() {
    local out
    out=$(curl -s -m 2 -X POST -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
        "127.0.0.1:$((RPC_PORT + $1))" 2>/dev/null | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p')
    echo $(( ${out:-0} ))
}

start_node() {
    local i=$1 tag=$2
    "$BIN" --node "$i" --num-nodes "$N" --base-port "$BASE_PORT" \
        --data-dir "$WORK/n$i" --rpc-listen "127.0.0.1:$((RPC_PORT + i))" \
        --genesis-file "$WORK/genesis.json" \
        --tx-inject-rate "$RATE" > "$WORK/n$i.$tag.log" 2>&1 &
    PIDS[$i]=$!
}

# Total transactions in blocks [from, to] on validator $1.
tx_count() {
    local i=$1 from=$2 to=$3 total=0 b n
    for b in $(seq "$from" "$to"); do
        n=$(curl -s -m 2 -X POST -H 'content-type: application/json' \
            --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"$(printf '0x%x' "$b")\",false]}" \
            "127.0.0.1:$((RPC_PORT + i))" 2>/dev/null \
            | python3 -c 'import json,sys; r=json.load(sys.stdin).get("result") or {}; print(len(r.get("transactions",[])))' 2>/dev/null || echo 0)
        total=$((total + ${n:-0}))
    done
    echo "$total"
}

heights() { local s=""; for i in $(seq 0 $((N - 1))); do s="$s $(height "$i")"; done; echo "$s"; }
max_height() { local m=0 h; for i in $(seq 0 $((N - 2))); do h=$(height "$i"); [ "$h" -gt "$m" ] && m=$h; done; echo "$m"; }

[ -x "$BIN" ] || { log "building oxide-devnet (release)"; cargo build -q --release -p oxide-devnet; }

# Genesis that funds every node's injector identity — without it the
# default devnet genesis leaves the injectors unfunded and every
# injected tx is rejected at admission (blocks stay empty).
"$BIN" genesis --num-nodes "$N" -o "$WORK/genesis.json" > /dev/null

log "phase 1: starting $N validators (inject $RATE tx/s)"
for i in $(seq 0 $((N - 1))); do start_node "$i" boot; done
sleep 20
H1=$(heights); log "heights:$H1"
for h in $H1; do [ "$h" -gt 0 ] || fail "a validator has not finalized anything:$H1"; done

log "phase 2: kill + wipe validator $((N - 1)), restart"
LAST=$((N - 1))
kill "${PIDS[$LAST]}"; wait "${PIDS[$LAST]}" 2>/dev/null || true
rm -rf "$WORK/n$LAST"
sleep 5
start_node "$LAST" rejoin
START=$(date +%s)
while :; do
    sleep 5
    TARGET=$(max_height); MINE=$(height "$LAST")
    ELAPSED=$(( $(date +%s) - START ))
    log "t+${ELAPSED}s fleet=$TARGET rejoined=$MINE"
    [ "$MINE" -gt 0 ] && [ $((TARGET - MINE)) -le "$MAX_LAG" ] && break
    [ "$ELAPSED" -ge "$REJOIN_DEADLINE" ] && fail "wiped validator did not rejoin within ${REJOIN_DEADLINE}s"
done
log "rejoined in ${ELAPSED}s"

log "phase 3: agreement"
sleep 10
H3=$(heights); log "heights:$H3"
MAX=0; MIN=999999999
for h in $H3; do [ "$h" -gt "$MAX" ] && MAX=$h; [ "$h" -lt "$MIN" ] && MIN=$h; done
[ $((MAX - MIN)) -le "$MAX_LAG" ] || fail "validators disagree by $((MAX - MIN)) blocks:$H3"
log "phase 4: inclusion"
TIP=$(height 0); FROM=$(( TIP > 20 ? TIP - 20 : 1 ))
TXS=$(tx_count 0 "$FROM" "$TIP")
log "transactions in blocks $FROM..$TIP: $TXS"
[ "$TXS" -gt 0 ] || fail "no injected transaction was committed in blocks $FROM..$TIP"
log "PASS (liveness, wiped-node rejoin in ${ELAPSED}s, agreement within $((MAX - MIN)), $TXS txs in last $((TIP - FROM + 1)) blocks)"
