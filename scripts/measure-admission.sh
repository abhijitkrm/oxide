#!/usr/bin/env bash
# measure-admission.sh — fleet CPU cost per committed transaction.
#
# Starts N `oxide-devnet` validators (funded injectors, RATE tx/s
# each), warms up, then over WINDOW seconds records the validators'
# total CPU time and the transactions committed. Prints CPU-ms per
# committed tx and committed tx/s — the numbers the tx-gossip
# targeting change (gossip_targets) is judged on: every validator
# that admits a tx pays its signature recovery, so fewer admissions
# per tx should show up as less fleet CPU per committed tx.
#
# Usage: scripts/measure-admission.sh <oxide-devnet binary> [N] [RATE] [WINDOW]
set -euo pipefail
BIN="$1"; N="${2:-7}"; RATE="${3:-500}"; WINDOW="${4:-60}"
BASE_PORT="${E2E_BASE_PORT:-26000}"; RPC_PORT="${E2E_RPC_PORT:-27000}"
WORK="$(mktemp -d -t oxide-admit.XXXXXX)"; PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

rpc() { curl -s -m 2 -X POST -H 'content-type: application/json' --data "$2" "127.0.0.1:$((RPC_PORT + $1))"; }
height() { local v; v=$(rpc 0 '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p'); echo $(( ${v:-0} )); }
nonce_sum() { # executed txs = summed nonces of every funded account
    # (all load is injected transfers, so the sum counts exactly the
    # committed-and-executed txs; N+32 calls, well under the RPC
    # rate limit that a per-block scan trips)
    python3 - "$WORK/genesis.json" "$RPC_PORT" <<'PY'
import json, sys, urllib.request
alloc = json.load(open(sys.argv[1]))["evm"]["alloc"]
port = int(sys.argv[2]); total = 0
for addr in alloc:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount", "params": [addr, "latest"]}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}", body, {"content-type": "application/json"})
    total += int(json.load(urllib.request.urlopen(req, timeout=5)).get("result", "0x0"), 16)
print(total)
PY
}
cpu_ms() { # summed user+sys CPU of all validators, in ms
    local total=0 t
    for p in "${PIDS[@]}"; do
        t=$(ps -o time= -p "$p" | tr -d ' ')   # [[dd-]hh:]mm:ss.cc
        total=$(python3 -c "
t='$t'.replace('-',':'); parts=[float(x) for x in t.split(':')]
s=0
for x in parts: s=s*60+x
print(int($total+s*1000))")
    done
    echo "$total"
}

"$BIN" genesis --num-nodes "$N" -o "$WORK/genesis.json" > /dev/null
for i in $(seq 0 $((N - 1))); do
    "$BIN" --node "$i" --num-nodes "$N" --base-port "$BASE_PORT" --data-dir "$WORK/n$i" \
        --rpc-listen "127.0.0.1:$((RPC_PORT + i))" --genesis-file "$WORK/genesis.json" \
        --tx-inject-rate "$RATE" > "$WORK/n$i.log" 2>&1 &
    PIDS+=($!)
done
sleep 20
H0=$(height); N0=$(nonce_sum); C0=$(cpu_ms)
sleep "$WINDOW"
H1=$(height); N1=$(nonce_sum); C1=$(cpu_ms)
TX=$((N1 - N0))
python3 -c "
cpu=$C1-$C0; tx=$TX; w=$WINDOW
print(f'blocks={$H1-$H0} committed_txs={tx} tx/s={tx/w:.0f} fleet_cpu_s={cpu/1000:.1f} cpu_ms_per_tx={cpu/max(tx,1):.3f}')"
