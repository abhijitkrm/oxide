#!/bin/bash
# measure-tls-throughput.sh — committed-throughput measurement for
# the TLS+WAL multi-host testnet (docker-compose.tls.yml).
#
# Samples one validator's JSON-RPC over a window and reports:
#   - blocks/s           (eth_blockNumber delta)
#   - executed tx/s      (eth_getBalance of the injector sink —
#                         every injected transfer is exactly 1 wei,
#                         so the balance delta IS the executed-tx
#                         count; EVM history only records executed
#                         txs, making this the honest metric, not
#                         committed bytes)
#   - avg tx/block
#   - fleet convergence  (eth_blockNumber on all four published
#                         RPC ports must agree within the commit lag)
#
# Usage: ./scripts/measure-tls-throughput.sh [window_seconds] [port]
#   window_seconds — sample window (default 30)
#   port           — host port of the sampled validator's RPC
#                    (default 8545 = validator-0)
#   FLEET_PORTS    — env var, space-separated RPC ports for the
#                    convergence check (default "8545 8546 8547 8548";
#                    the local loopback fleet uses "8500 8501 8502")
#
# Requires python3 on the host (JSON-RPC over the published ports).

set -e

WINDOW="${1:-30}"
PORT="${2:-8545}"
FLEET_PORTS="${FLEET_PORTS:-8545 8546 8547 8548}"
SINK="0x7777777777777777777777777777777777777777"

python3 - "$WINDOW" "$PORT" "$SINK" "$FLEET_PORTS" <<'PYEOF'
import json, sys, time, urllib.request

window = float(sys.argv[1])
port = sys.argv[2]
sink = sys.argv[3]
fleet_ports = sys.argv[4].split()

def rpc(method, params, p=port, timeout=8):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{p}", data=body,
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=timeout).read()).get("result")

def height(p=port):
    r = rpc("eth_blockNumber", [], p)
    return int(r, 16) if r else None

def bal():
    r = rpc("eth_getBalance", [sink, "latest"])
    return int(r, 16) if r else 0

h0, s0, t0 = height(), bal(), time.time()
if h0 is None:
    print("RPC not answering on port", port, "— is the fleet up?", file=sys.stderr)
    sys.exit(1)
time.sleep(window)
h1, s1, t1 = height(), bal(), time.time()

dt = t1 - t0
blocks = h1 - h0
txs = s1 - s0
print(f"window: {dt:.1f}s  heights {h0}..{h1}")
print(f"blocks: {blocks}  ({blocks/dt:.2f} blk/s)")
print(f"executed txs: {txs}  ({txs/dt:.1f} tx/s)")
print(f"avg tx/block: {txs/max(blocks, 1):.1f}")

print("fleet heights:", end=" ")
for p in fleet_ports:
    try:
        print(height(p), end=" ")
    except Exception as e:
        print(f"ERR({type(e).__name__})", end=" ")
print()
PYEOF
