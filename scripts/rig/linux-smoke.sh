#!/usr/bin/env bash
# linux-smoke.sh — run the Linux-only parts of the rig in a container BEFORE
# renting a box, so script and build bugs cost minutes here, not paid hours.
#
# What it can check: the Linux build and tests (including CPU-pinning code),
# rig-bench.sh in QUICK mode (taskset, the /proc sampler, iostat, strace,
# setup-linux.sh's apt steps). What it cannot: `perf` counters (a container has
# no kernel PMU access), real NVMe, x86 behaviour when the host is arm64
# (use PLATFORM=linux/amd64 for an emulated x86 build/test of the correctness
# paths, slow and not for timing).
#
#   scripts/rig/linux-smoke.sh tests     # cargo test of the rig-relevant crates on Linux
#   scripts/rig/linux-smoke.sh rig       # QUICK rig-bench.sh with a small section set
#   scripts/rig/linux-smoke.sh x86       # emulated x86-64: prefetch feature, trading, crypto (asm keccak) and lanes tests
#   scripts/rig/linux-smoke.sh shell     # interactive shell in the same environment
#
# Environment: IMAGE (default rust:1.98.1-bookworm, the Dockerfile's builder),
# JOBS (default 2: a Docker Desktop VM is small), PLATFORM (default native).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${IMAGE:-rust:1.98.1-bookworm}"
JOBS="${JOBS:-2}"
PLATFORM_ARG=()
[ -n "${PLATFORM:-}" ] && PLATFORM_ARG=(--platform "$PLATFORM")
MODE="${1:-tests}"
VOL_SUFFIX="${PLATFORM:+-$(echo "$PLATFORM" | tr '/' '-')}"

inner() { # the command run inside the container
    case "$MODE" in
    tests)
        echo 'cargo test -j'"$JOBS"' -p lanes -p matcher -p exchange -p crypto -p trading -p primitives 2>&1 | grep -E "^(test result|error|warning: unused|failures:|---- )|FAILED|panicked" | sort | uniq -c | sort -rn | head -40' ;;
    rig)
        echo 'apt-get install -y --no-install-recommends sysstat strace util-linux python3 procps >/dev/null 2>&1 || true;
              cd /work && QUICK=1 CARGO_BUILD_JOBS='"$JOBS"' OUT=/out/rig SECTIONS="env budget lanes e2e journal summary" scripts/rig-bench.sh 2>&1 | tail -60' ;;
    x86)
        echo 'uname -m; cargo check -j'"$JOBS"' -p trading --features prefetch 2>&1 | tail -3;
              cargo test -j'"$JOBS"' -p trading --features prefetch --lib 2>&1 | grep -E "^test result|FAILED|panicked|^error" | head;
              cargo test -j'"$JOBS"' -p crypto -p lanes --lib 2>&1 | grep -E "^test result|FAILED|panicked|^error" | head' ;;
    shell) echo 'bash' ;;
    *) echo "unknown mode $MODE" >&2; exit 2 ;;
    esac
}

TTY=(); [ "$MODE" = shell ] && TTY=(-it)
docker run --rm ${TTY[@]+"${TTY[@]}"} ${PLATFORM_ARG[@]+"${PLATFORM_ARG[@]}"} \
    -v "$ROOT":/work-src:ro \
    -v "oxide-cargo$VOL_SUFFIX":/usr/local/cargo/registry \
    -v "oxide-target$VOL_SUFFIX":/target \
    -v "oxide-out$VOL_SUFFIX":/out \
    -e CARGO_TARGET_DIR=/target -e CARGO_INCREMENTAL=0 \
    "$IMAGE" bash -c '
set -e
# Source is mounted read-only; work on a copy so the build never touches the host tree.
mkdir -p /work && rsync -a --delete --exclude target --exclude .git --exclude rig-results /work-src/ /work/ 2>/dev/null \
    || { apt-get update -qq >/dev/null && apt-get install -y -qq rsync >/dev/null && rsync -a --delete --exclude target --exclude .git --exclude rig-results /work-src/ /work/; }
git -c safe.directory='*' -C /work-src rev-parse --short HEAD > /work/.rig-sha 2>/dev/null || true
cd /work
'"$(inner)"
