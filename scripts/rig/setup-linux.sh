#!/usr/bin/env bash
# setup-linux.sh — prepare a fresh Debian/Ubuntu rig for scripts/rig-bench.sh.
#
# Installs the toolchain prerequisites and the profiling tools, and (with
# TUNE=1) applies the machine settings the benchmarks assume. Idempotent.
# Needs root (or sudo). Prints, at the end, anything it could not do.
#
#   scripts/rig/setup-linux.sh            # install only
#   TUNE=1 scripts/rig/setup-linux.sh     # also: performance governor, perf access, SMT report
set -euo pipefail
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
TODO=()

export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -y
# One missing package aborts a whole `apt-get install`, so install in tiers:
# the build prerequisites must succeed; each profiling tool is best-effort.
$SUDO apt-get install -y build-essential pkg-config libssl-dev clang cmake git curl rsync \
    python3 python3-pip util-linux numactl procps
for pkg in sysstat strace fio htop blktrace heaptrack; do
    $SUDO apt-get install -y "$pkg" >/dev/null 2>&1 || TODO+=("package $pkg not installed (that profiling step will be skipped)")
done
# perf: the package name depends on the distro and kernel flavour.
if ! perf --version >/dev/null 2>&1; then
    for pkg in "linux-tools-$(uname -r)" linux-tools-generic linux-tools-common linux-perf; do
        $SUDO apt-get install -y "$pkg" >/dev/null 2>&1 && perf --version >/dev/null 2>&1 && break
    done
    perf --version >/dev/null 2>&1 || TODO+=("perf not available for this kernel (flamegraphs / counters will be skipped)")
fi
# bcc off-CPU tooling (Ubuntu: bpfcc-tools; Debian: bpfcc-tools too).
$SUDO apt-get install -y bpfcc-tools >/dev/null 2>&1 || TODO+=("bpfcc-tools not installed (offcputime skipped)")

# SKIP_RUST=1 / SKIP_INFERNO=1: for testing the package steps alone.
if [ "${SKIP_RUST:-0}" != 1 ] && ! command -v cargo >/dev/null 2>&1; then
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
# shellcheck disable=SC1090
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
[ "${SKIP_INFERNO:-0}" = 1 ] || command -v inferno-flamegraph >/dev/null 2>&1 || cargo install inferno --locked || TODO+=("inferno (flamegraphs) not installed")

if [ "${TUNE:-0}" = 1 ]; then
    # perf needs kernel symbols and unrestricted counters.
    $SUDO sysctl -w kernel.perf_event_paranoid=-1 kernel.kptr_restrict=0 >/dev/null || TODO+=("could not relax perf sysctls")
    # Fixed frequency: performance governor where the box allows it (often absent in VMs).
    if command -v cpupower >/dev/null 2>&1; then $SUDO cpupower frequency-set -g performance >/dev/null || true; fi
    for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [ -w "$g" ] && echo performance | $SUDO tee "$g" >/dev/null || true
    done
fi

echo
echo "== machine"
lscpu | grep -E "Model name|^CPU\(s\)|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|L2|L3|NUMA node\(s\)" || true
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
SMT="$(cat /sys/devices/system/cpu/smt/active 2>/dev/null || echo n/a)"
echo "SMT active: $SMT"
if [ "$SMT" = 1 ]; then
    TODO+=("SMT is on: for per-core numbers run  echo off | sudo tee /sys/devices/system/cpu/smt/control  (or record it; the summary will carry it)")
fi
echo "perf: $(perf --version 2>/dev/null || echo missing)"
echo "free disk (journal target): $(df -h "${JOURNAL_DIR:-$HOME}" | tail -1)"
echo "toolchain: $(rustc --version 2>/dev/null || echo missing)"
if [ "${#TODO[@]}" -gt 0 ]; then
    echo; echo "== needs attention"; printf ' - %s\n' "${TODO[@]}"
fi
