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
