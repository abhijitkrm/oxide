#!/usr/bin/env python3
"""Per-process resource time series for long runs (soak, devnet, load tests).

    sampler.py OUT.csv [--interval 5] [--match PATTERN ...] [--pid PID ...]

Every INTERVAL seconds, for each process whose command line contains a
PATTERN (or whose pid was given), appends one CSV row:

    t_s, pid, name, cpu_pct, rss_kb, vsz_kb, threads, fds, vol_ctx, invol_ctx,
    minor_faults, major_faults

`cpu_pct` is the process's CPU use over the last interval (100 = one core).
Linux reads /proc; macOS falls back to `ps` (no fd/ctx/fault columns: left
empty). Stops on SIGTERM/SIGINT, then prints a per-process summary with the
RSS growth slope (KiB/hour, least squares over the second half of the run, to
skip warm-up) and flags a slope above 1% of mean RSS per hour as a LEAK
SUSPECT. Standard library only.
"""
import argparse, csv, os, signal, subprocess, sys, time

CLK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
LINUX = os.path.isdir("/proc/self")
stop = False


def _sig(*_):
    global stop
    stop = True


def find_pids(patterns, pids):
    out = set(pids)
    if patterns:
        me = os.getpid()
        for line in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout.splitlines():
            pid_s, _, cmd = line.strip().partition(" ")
            if pid_s.isdigit() and int(pid_s) != me and any(p in cmd for p in patterns) and "sampler.py" not in cmd:
                out.add(int(pid_s))
    return sorted(out)


def read_linux(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            raw = f.read()
        rest = raw[raw.rindex(")") + 2:].split()
        name = raw[raw.index("(") + 1: raw.rindex(")")]
        utime, stime = int(rest[11]), int(rest[12])
        minflt, majflt = int(rest[7]), int(rest[9])
        threads = int(rest[17])
        vsz = int(rest[20]) // 1024
        rss = int(rest[21]) * (os.sysconf("SC_PAGE_SIZE") // 1024)
        vol = invol = ""
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("voluntary_ctxt_switches"):
                    vol = int(line.split()[1])
                elif line.startswith("nonvoluntary_ctxt_switches"):
                    invol = int(line.split()[1])
        try:
            fds = len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            fds = ""
        return dict(name=name, cpu_ticks=utime + stime, rss=rss, vsz=vsz, threads=threads,
                    fds=fds, vol=vol, invol=invol, minflt=minflt, majflt=majflt)
    except (OSError, ValueError, IndexError):
        return None


def read_ps(pid):
    r = subprocess.run(["ps", "-o", "rss=,vsz=,time=,comm=", "-p", str(pid)], capture_output=True, text=True)
    parts = r.stdout.split(None, 3)
    if len(parts) < 4:
        return None
    t = parts[2].replace("-", ":").split(":")
    secs = 0.0
    for x in t:
        secs = secs * 60 + float(x)
    return dict(name=os.path.basename(parts[3].strip()), cpu_ticks=secs * CLK, rss=int(parts[0]),
                vsz=int(parts[1]), threads="", fds="", vol="", invol="", minflt="", majflt="")


def summarize(path):
    by = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            by.setdefault((row["pid"], row["name"]), []).append((float(row["t_s"]), float(row["rss_kb"]), float(row["cpu_pct"])))
    print("\n== sampler summary ==")
    for (pid, name), rows in by.items():
        half = rows[len(rows) // 2:] if len(rows) >= 6 else rows
        n = len(half)
        xs = [r[0] for r in half]; ys = [r[1] for r in half]
        mx, my = sum(xs) / n, sum(ys) / n
        den = sum((x - mx) ** 2 for x in xs) or 1.0
        slope_h = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den * 3600
        flag = "  LEAK SUSPECT" if my and slope_h > 0.01 * my and len(rows) >= 12 else ""
        print(f"pid {pid:>7} {name:<18} samples={len(rows):>5} rss_max={max(r[1] for r in rows)/1024:.0f}MiB "
              f"rss_mean={my/1024:.0f}MiB slope={slope_h:.0f}KiB/h cpu_mean={sum(r[2] for r in rows)/len(rows):.0f}%{flag}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--match", action="append", default=[])
    ap.add_argument("--pid", action="append", type=int, default=[])
    a = ap.parse_args()
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    reader = read_linux if LINUX else read_ps
    prev, t0 = {}, time.time()
    with open(a.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow("t_s pid name cpu_pct rss_kb vsz_kb threads fds vol_ctx invol_ctx minor_faults major_faults".split())
        while not stop:
            now = time.time()
            for pid in find_pids(a.match, a.pid):
                s = reader(pid)
                if not s:
                    continue
                last = prev.get(pid)
                cpu = ""
                if last:
                    dt = now - last[0]
                    cpu = f"{(s['cpu_ticks'] - last[1]) / CLK / dt * 100:.1f}" if dt > 0 else ""
                prev[pid] = (now, s["cpu_ticks"])
                w.writerow([f"{now - t0:.1f}", pid, s["name"], cpu or 0, s["rss"], s["vsz"], s["threads"], s["fds"],
                            s["vol"], s["invol"], s["minflt"], s["majflt"]])
            f.flush()
            slept = 0.0
            while slept < a.interval and not stop:
                time.sleep(0.2)
                slept += 0.2
    summarize(a.out)


if __name__ == "__main__":
    main()
