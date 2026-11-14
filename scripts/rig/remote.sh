#!/usr/bin/env bash
# remote.sh — drive a rig over ssh: sync the tree, set it up, start a run
# detached, watch progress, fetch results. Nothing here stores credentials;
# it uses whatever ssh config/agent you already have.
#
#   scripts/rig/remote.sh <ssh-target> sync [ref]      # box: git fetch + checkout from GitHub (no rsync)
#   scripts/rig/remote.sh <ssh-target> setup           # install deps (TUNE=1 to apply machine tuning)
#   scripts/rig/remote.sh <ssh-target> start [args]    # start rig-bench.sh detached (default: single-box)
#   scripts/rig/remote.sh <ssh-target> status          # last lines of the log + which sections finished
#   scripts/rig/remote.sh <ssh-target> fetch [dir]     # copy rig-results back over ssh+tar (default ./rig-results-remote)
#   scripts/rig/remote.sh <ssh-target> stop            # kill the run
#
# Code reaches the box through GitHub only: push the branch first, then `sync`
# (default ref: rig/single-box, override with REF= or the argument). The repo is
# public, so the box needs no credentials.
set -euo pipefail
T="${1:?ssh target, e.g. user@host}"; CMD="${2:?command}"; shift 2
DIR='$HOME/oxide'
case "$CMD" in
  sync)
    REF_="${1:-${REF:-rig/single-box}}"
    ssh "$T" "set -e; [ -d oxide/.git ] || git clone --quiet --depth 50 --branch $REF_ https://github.com/abhijitkrm/oxide.git oxide; \
        cd oxide && git fetch --quiet --depth 50 origin $REF_ && git checkout -q -f FETCH_HEAD && git log --oneline | head -1" ;;
  setup)
    ssh "$T" "cd $DIR && TUNE=${TUNE:-0} scripts/rig/setup-linux.sh" ;;
  start)
    ARGS="${*:-single-box}"
    ssh "$T" "cd $DIR && . \$HOME/.cargo/env 2>/dev/null; rm -f \$HOME/rig.pid; \
        nohup env QUICK=${QUICK:-0} scripts/rig-bench.sh $ARGS > \$HOME/rig.log 2>&1 & echo \$! > \$HOME/rig.pid; \
        echo started pid \$(cat \$HOME/rig.pid)" ;;
  status)
    ssh "$T" 'echo "running: $(pgrep -f rig-bench.sh >/dev/null && echo yes || echo no)"; \
        grep -E "^== " $HOME/rig.log | tail -15; echo ---; tail -8 $HOME/rig.log' ;;
  fetch)
    OUT="${1:-./rig-results-remote}"; mkdir -p "$OUT"
    ssh "$T" 'tar -C "$HOME/oxide/rig-results" -cf - .' | tar -C "$OUT" -xf - ;;
  stop)
    ssh "$T" 'pkill -f rig-bench.sh || true; pkill -f "target/release" || true' ;;
  *) echo "unknown command: $CMD" >&2; exit 2 ;;
esac
