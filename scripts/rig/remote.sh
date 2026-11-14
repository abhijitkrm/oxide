#!/usr/bin/env bash
# remote.sh — drive a rig over ssh: sync the tree, set it up, start a run
# detached, watch progress, fetch results. Nothing here stores credentials;
# it uses whatever ssh config/agent you already have.
#
#   scripts/rig/remote.sh <ssh-target> sync            # rsync this tree to ~/oxide (no target/, .git/)
#   scripts/rig/remote.sh <ssh-target> setup           # install deps (TUNE=1 to apply machine tuning)
#   scripts/rig/remote.sh <ssh-target> start [args]    # start rig-bench.sh detached (default: single-box)
#   scripts/rig/remote.sh <ssh-target> status          # last lines of the log + which sections finished
#   scripts/rig/remote.sh <ssh-target> fetch [dir]     # copy rig-results back (default ./rig-results-remote)
#   scripts/rig/remote.sh <ssh-target> stop            # kill the run
set -euo pipefail
T="${1:?ssh target, e.g. user@host}"; CMD="${2:?command}"; shift 2
DIR='$HOME/oxide'
case "$CMD" in
  sync)
    # Record the commit (the tree goes over without .git); the dirty count too.
    TOP="$(cd "$(dirname "$0")/../.." && pwd)"
    git -C "$TOP" rev-parse --short HEAD > "$TOP/.rig-sha" 2>/dev/null || true
    rsync -az --delete --exclude target --exclude .git --exclude rig-results --exclude 'rig-results-remote' \
        "$TOP/" "$T:oxide/"
    rm -f "$TOP/.rig-sha" ;;
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
    rsync -az "$T:oxide/rig-results/" "$OUT/" ;;
  stop)
    ssh "$T" 'pkill -f rig-bench.sh || true; pkill -f "target/release" || true' ;;
  *) echo "unknown command: $CMD" >&2; exit 2 ;;
esac
