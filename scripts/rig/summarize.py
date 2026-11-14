#!/usr/bin/env python3
"""Assemble summary.md from a rig-bench results directory.

Reads whatever is present (budget.csv, auth.csv, lanes.csv, e2e_auth.txt,
env.txt) and prints markdown: per-stage scaling with efficiency, the
trading-lane scaling table, real-TCP orders/s by scheme and core count, and a
cores-needed extrapolation for the 1M EVM tx/s, 10M and 100M orders/s targets.
Missing files are skipped, never fatal.

Usage: summarize.py <results dir>
"""
import csv
import os
import re
import sys

TARGETS = [("1M EVM tx/s", 1e6, "evm"), ("10M orders/s", 1e7, "orders"), ("100M orders/s", 1e8, "orders")]


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def rows(path):
    t = read(path)
    if not t:
        return []
    return [r for r in csv.reader(l for l in t.splitlines() if l and not l.startswith(("$", "#", "stage", "scheme", "part", "cores_for", "(")))]


def table(head, body):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in body]
    return "\n".join(out)


def human(x):
    x = float(x)
    for unit, d in (("M", 1e6), ("k", 1e3)):
        if x >= d:
            return f"{x / d:.2f}{unit}"
    return f"{x:.0f}"


def main(d):
    out = ["# Rig summary", ""]
    env = read(os.path.join(d, "env.txt")) or ""
    for key in ("model name", "Model name", "CPU(s)", "Thread(s) per core", "governor", "SMT", "journal disk"):
        m = re.search(rf"^{re.escape(key)}.*$", env, re.M)
        if m:
            out.append(f"- {m.group(0).strip()}")
    out.append("")

    # ---- per-stage scaling (budget.csv)
    b = rows(os.path.join(d, "budget.csv"))
    stages = {}
    for r in b:
        if len(r) >= 3:
            try:
                stages.setdefault(r[0], {})[int(r[1])] = float(r[2])
            except ValueError:
                pass
    best = {}
    if stages:
        out.append("## Per-stage cost and thread scaling (`crypto:budget`)\n")
        threads = sorted({t for s in stages.values() for t in s})
        body = []
        for st, byt in stages.items():
            one = byt.get(1) or byt[min(byt)]
            cells = [f"{human(byt[t])} ({byt[t] / (one * t):.0%})" if t in byt else "-" for t in threads]
            body.append([st, f"{1e9 / one:.0f} ns"] + cells)
            tmax = max(byt)
            best[st] = (one, byt[tmax] / (one * tmax), tmax)
        out.append(table(["stage", "1-thread cost"] + [f"{t}t items/s (efficiency)" for t in threads], body))
        out.append("")

    # ---- admission (auth.csv)
    a = rows(os.path.join(d, "auth.csv"))
    if a:
        out.append("## Matcher admission by scheme (`matcher:auth`)\n")
        out.append(table(["scheme", "threads", "orders/s"], [[r[0], r[1], human(r[2])] for r in a if len(r) >= 3]))
        out.append("")

    # ---- lanes
    l = rows(os.path.join(d, "lanes.csv"))
    trading = [r for r in l if r and r[0] == "trading"]
    lane_best = {}
    if trading:
        out.append("## Trading lane (`lanes:lanes`)\n")
        out.append(table(["verifier", "commit", "shards", "orders/s"], [[r[1], r[2], r[3], human(r[4])] for r in trading]))
        out.append("")
        for r in trading:
            if r[1] == "session_mac" and r[2] == "Stream":
                lane_best[int(r[3])] = float(r[4])
    evm = [r for r in l if r and r[0] == "evm"]
    if evm:
        out.append("EVM lane mechanism only (not EVM execution): " + ", ".join(f"{r[3]} lanes {human(r[4])}/s" for r in evm) + "\n")

    # ---- chain path by transaction type (chainmix)
    cm = read(os.path.join(d, "chain_mix.csv"))
    if cm:
        out.append("## Signed transactions through the real executor (`executor:chain_mix`)\n")
        out.append("Admission recovers every signature (parallel over the ingest threads); execution is "
                   "single-writer per block. `executed=all` means every tx was admitted, proposed, finalized, "
                   "and every CLOB sender's nonce advanced exactly.\n")
        body = []
        for line in cm.splitlines():
            r = line.split(",")
            if len(r) == 9 and r[1].isdigit():
                body.append([r[0], r[1], r[2], human(r[3]), human(r[4]), human(r[5]), human(r[6]), r[7], r[8]])
        if body:
            out.append(table(["mix", "ingest threads", "txs", "admission tx/s", "propose tx/s", "execution tx/s", "end-to-end tx/s", "executed", "resting"], body))
            out.append("")

    # ---- parallel EVM scaling (evmscale)
    def crit_rows(path):
        t = read(path)
        if not t:
            return {}
        cores, last, res = None, None, {}
        for line in t.splitlines():
            m = re.match(r"# cores=(\d+)", line)
            if m:
                cores = int(m.group(1))
                continue
            m = re.match(r"^(\S+/\S+)\s*(time:.*)?$", line.strip())
            if m and not line.startswith(("Benchmarking", "Warning")):
                last = m.group(1)
            t2 = re.search(r"time:\s+\[\S+ \S+ (\S+) (\S+)", line)
            if t2 and last and cores:
                v = float(t2.group(1)) * {"ns": 1e-9, "µs": 1e-6, "us": 1e-6, "ms": 1e-3, "s": 1.0}[t2.group(2)]
                res.setdefault(last, {})[cores] = v
        return res
    for title, fn in (("Parallel scheduler, MODELED workload (synthetic spin loop per tx, Uniswap-style gas mix of 59,850 gas/tx; NOT real EVM execution, no signature recovery)", "scaling_evm_parallel.txt"),
                      ("REAL EVM execution (revm, signed 21k-gas transfers, rayon sender recovery + execution), `modules/evm`", "scaling_evm_batch.txt")):
        res = crit_rows(os.path.join(d, fn))
        if not res:
            continue
        out.append(f"## {title}\n")
        cs = sorted({c for v in res.values() for c in v})
        body = []
        for name, v in sorted(res.items()):
            m = re.search(r"/(\d+)(?:_|$)", name)
            n = int(m.group(1)) if m else 0
            cells = []
            for c in cs:
                if c in v and n:
                    cells.append(human(n / v[c]) + " tx/s")
                elif c in v:
                    cells.append(f"{v[c]*1e3:.1f} ms")
                else:
                    cells.append("-")
            body.append([name] + cells)
        out.append(table(["bench"] + [f"{c} cores" for c in cs], body))
        out.append("")

    # ---- real-service shard scaling
    sh = [r for r in rows(os.path.join(d, "shards.csv")) if len(r) >= 9 and r[0].isdigit()]
    shard_best = {}
    if sh:
        out.append("## Real matcher shard scaling (`matcher:shards`, session MAC)\n")
        body = []
        for r in sh:
            body.append([r[0], r[1], r[2], human(r[6]), human(r[7]), r[8]])
            if r[2] == "queued" and r[1] == "1":
                shard_best[int(r[0])] = float(r[6])
        out.append(table(["markets", "submitters/market", "journal", "orders/s", "per market", "rejects"], body))
        out.append("")

    # ---- separate-process, pinned
    pt = read(os.path.join(d, "procs.txt"))
    if pt:
        out.append("## Real binaries, separate pinned processes (`oxide-matcher` vs `oxide-loadgen`)\n")
        data, cur, rej = {}, None, {}
        for line in pt.splitlines():
            m = re.match(r"# server cores=(\d+) .* scheme=(\w+)", line)
            if m:
                cur = (int(m.group(1)), m.group(2))
            m = re.search(r"throughput:\s+(\d+) orders/s", line)
            if m and cur:
                data[cur] = int(m.group(1))
            m = re.search(r"rejected:\s+(\d+)", line)
            if m and cur:
                rej[cur] = int(m.group(1))
        schemes = sorted({k[1] for k in data})
        cs = sorted({k[0] for k in data})
        body = []
        for sc in schemes:
            body.append([sc] + [(human(data[(c, sc)]) + (" (rejects!)" if rej.get((c, sc)) else "")) if (c, sc) in data else "-" for c in cs])
        out.append(table(["scheme"] + [f"{c} server cores" for c in cs], body))
        out.append("")

    # ---- e2e
    e = read(os.path.join(d, "e2e_auth.txt"))
    if e:
        out.append("## Real loopback TCP through the matcher (shared box)\n")
        cores, data = None, {}
        for line in e.splitlines():
            m = re.match(r"# cores=(\d+)", line)
            if m:
                cores = int(m.group(1))
            m = re.match(r"\s+(\w+)\s+(\d+) orders/s", line)
            if m:
                data.setdefault(m.group(1), {})[cores or 0] = int(m.group(2))
        cs = sorted({c for v in data.values() for c in v})
        out.append(table(["scheme"] + [f"{c} cores" for c in cs], [[s] + [human(v[c]) if c in v else "-" for c in cs] for s, v in data.items()]))
        out.append("")

    # ---- extrapolation
    out.append("## Cores needed for the targets (single-core cost / measured efficiency)\n")
    ext = []
    if "secp256k1_recover" in best:
        one, eff, tmax = best["secp256k1_recover"]
        r = max(one * eff, 1)
        ext.append(["1M EVM tx/s, signature recovery only", f"{1e6 / r:.0f}", f"{one:.0f}/s per core at {eff:.0%} efficiency to {tmax} threads"])
    if "mac_session_order" in best:
        one, eff, tmax = best["mac_session_order"]
        for name, t in (("10M orders/s", 1e7), ("100M orders/s", 1e8)):
            ext.append([f"{name}, session-MAC authentication only", f"{t / (one * eff):.1f}", f"{one:.0f}/s per core at {eff:.0%}"])
    if "ed25519_verify_batch256" in best:
        one, eff, tmax = best["ed25519_verify_batch256"]
        for name, t in (("10M orders/s", 1e7), ("100M orders/s", 1e8)):
            ext.append([f"{name}, batched ed25519 authentication only", f"{t / (one * eff):.0f}", f"{one:.0f}/s per core at {eff:.0%}"])
    if shard_best:
        n = max(shard_best)
        per = shard_best[n] / n
        for name, t in (("10M orders/s", 1e7), ("100M orders/s", 1e8)):
            ext.append([f"{name}, real matcher with a queued journal", f"{t / per:.0f} markets", f"{human(per)}/s per market at {n} markets (worker + submitter threads)"])
    if lane_best:
        n = max(lane_best)
        per_shard = lane_best[n] / n
        for name, t in (("10M orders/s", 1e7), ("100M orders/s", 1e8)):
            ext.append([f"{name}, whole trading lane (session MAC + stream commit)", f"{t / per_shard:.0f} shards", f"{human(per_shard)}/s per shard at {n} shards"])
    if ext:
        out.append(table(["target", "cores needed", "basis"], ext))
        out.append("\nExtrapolation assumes the measured efficiency holds; it excludes network, consensus, "
                   "journal fsync and execution cost, none of which one box measures.")
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
