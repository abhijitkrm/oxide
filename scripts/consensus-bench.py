#!/usr/bin/env python3
"""Consensus-in-the-loop throughput bench: N real validators on one box, each pinned to its own CPUs.

Launches N `oxide-devnet` processes (real oxideBFT over loopback TCP, tx gossip, WAL, JSON-RPC, the
production module graph) under `taskset`, each injecting pre-signed EVM transfers from its own funded
identity, waits for liveness, then samples committed blocks and transactions over a window through
the JSON-RPC of validator 0 and reads each process's CPU use from /proc.

Layout: `--validators N --cores C` gives validator k the physical cores [k*C, k*C+C); `--smt` also
gives it their SMT siblings (CPU i and i + NCORES share a core), i.e. "threads as cores".

Usage (from the repo root, release binary built):
    scripts/consensus-bench.py --validators 4 --cores 3 --rate 20000 --duration 20
    scripts/consensus-bench.py --validators 3 --cores 4 --smt --rate 30000 --presign 600000

Output: one human summary and one `RESULT {...}` JSON line.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

NCORES = 12  # physical cores on the reference box (Ryzen 9 7900); siblings are CPU + NCORES


def rpc(port, method, params=None, timeout=3.0):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}", body, {"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read()).get("result")
    except Exception:
        return None


def height(port):
    v = rpc(port, "eth_blockNumber")
    return int(v, 16) if v else None


SINK = "0x" + "77" * 20  # every injected transfer pays 1 wei to this address


def executed_txs(port):
    """Exact count of executed injected transfers: the sink's balance in wei (1 wei each). One RPC
    call per sample (per-block count calls trip the RPC's per-IP rate limit at 100+ blocks/s)."""
    v = rpc(port, "eth_getBalance", [SINK, "latest"])
    return int(v, 16) if v else None


def cpu_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().rsplit(")", 1)[1].split()
    return int(parts[11]) + int(parts[12])  # utime + stime, clock ticks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validators", type=int, default=4)
    ap.add_argument("--cores", type=int, default=3, help="physical cores per validator")
    ap.add_argument("--smt", action="store_true", help="also use the SMT siblings of those cores")
    ap.add_argument("--rate", type=float, default=10000, help="offered tx/s per validator")
    ap.add_argument("--presign", type=int, default=400000, help="envelopes signed up front per validator")
    ap.add_argument("--duration", type=float, default=20, help="measurement window, seconds")
    ap.add_argument("--warmup", type=float, default=8, help="seconds to run before measuring")
    ap.add_argument("--base-port", type=int, default=26000)
    ap.add_argument("--rpc-port", type=int, default=27000)
    ap.add_argument("--bin", default="target/release/oxide-devnet")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    n = a.validators
    if n * a.cores > NCORES:
        sys.exit(f"{n} validators x {a.cores} cores exceeds the {NCORES} physical cores")

    work = tempfile.mkdtemp(prefix="oxide-cbench.")
    genesis = os.path.join(work, "genesis.json")
    subprocess.run([a.bin, "genesis", "--num-nodes", str(n), "-o", genesis], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs, cpusets = [], []
    try:
        for i in range(n):
            cores = list(range(i * a.cores, (i + 1) * a.cores))
            cpus = cores + ([c + NCORES for c in cores] if a.smt else [])
            cpusets.append(cpus)
            threads = len(cpus)
            env = dict(os.environ, RAYON_NUM_THREADS=str(threads), RUST_LOG="warn")
            cmd = ["taskset", "-c", ",".join(map(str, cpus)), a.bin, "--node", str(i), "--num-nodes", str(n),
                   "--base-port", str(a.base_port), "--data-dir", os.path.join(work, f"n{i}"),
                   "--rpc-listen", f"127.0.0.1:{a.rpc_port + i}", "--genesis-file", genesis,
                   "--tx-inject-rate", str(a.rate), "--tx-inject-presign", str(a.presign)]
            log = open(os.path.join(work, f"n{i}.log"), "wb")
            procs.append(subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT))
        # Liveness: validator 0 finalizes some blocks (presigning delays the start; allow a while).
        t0 = time.time()
        while time.time() - t0 < 180:
            h = height(a.rpc_port)
            if h is not None and h >= 3:
                break
            if any(p.poll() is not None for p in procs):
                sys.exit("a validator exited early; logs in " + work)
            time.sleep(1)
        else:
            sys.exit("no liveness within 180 s; logs in " + work)
        time.sleep(a.warmup)

        port = a.rpc_port
        h_start, tx_start = height(port), executed_txs(port)
        ticks0 = [cpu_ticks(p.pid) for p in procs]
        t_start = time.time()
        last_h, last_tx, t_last = h_start, tx_start, t_start
        end = t_start + a.duration
        while time.time() < end:
            h, c = height(port), executed_txs(port)
            if h is not None and c is not None:
                last_h, last_tx, t_last = h, c, time.time()
            time.sleep(0.5)
        t_end, h_end = t_last, last_h
        total_txs = (last_tx or 0) - (tx_start or 0)
        per_block = []
        ticks1 = [cpu_ticks(p.pid) for p in procs]
        elapsed = t_end - t_start
        hz = os.sysconf("SC_CLK_TCK")
        cpu_pct = []
        for k in range(n):
            used = (ticks1[k] - ticks0[k]) / hz / elapsed
            cpu_pct.append(round(100 * used / len(cpusets[k]), 1))
        heights = [height(a.rpc_port + i) for i in range(n)]
        dead = [i for i, p in enumerate(procs) if p.poll() is not None]
        blocks = (h_end or 0) - (h_start or 0)
        res = {
            "validators": n, "cores_each": a.cores, "smt": a.smt, "cpus_each": len(cpusets[0]),
            "offered_per_validator": a.rate, "offered_total": a.rate * n,
            "blocks": blocks, "blocks_per_s": round(blocks / elapsed, 2),
            "avg_block_ms": round(1000 * elapsed / blocks, 1) if blocks else None,
            "txs": total_txs, "tx_per_s": round(total_txs / elapsed),
            "avg_tx_per_block": round(total_txs / blocks, 1) if blocks else None,
            "cpu_pct_of_pinned": cpu_pct, "end_heights": heights,
            "exited": dead,
            "max_height_lag": (max(heights) - min(heights)) if all(x is not None for x in heights) else None,
        }
        print(f"{n} validators x {len(cpusets[0])} CPUs ({'cores+SMT' if a.smt else 'cores'}), offered "
              f"{a.rate:.0f}/validator ({a.rate * n:.0f} total)")
        print(f"  committed {res['tx_per_s']} tx/s, {res['blocks_per_s']} blocks/s "
              f"(~{res['avg_block_ms']} ms/block, avg {res['avg_tx_per_block']} tx/block)")
        print(f"  CPU of pinned set: {cpu_pct}%  end heights {heights}")
        print("RESULT " + json.dumps(res))
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        if a.keep:
            print("logs kept in", work)
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
