#!/usr/bin/env bash
# rig-bench.sh — one-command benchmark session for a dedicated rig.
#
# Runs the A/B and scaling measurements listed in docs/devlog.md
# ("Rig plan") with pinning, repetitions and an environment capture, and
# writes everything under $OUT (default: ./rig-results/<host>-<sha>-<time>).
#
# Usage:
#   scripts/rig-bench.sh [sections...]
#   SECTIONS="env corpus journal"  scripts/rig-bench.sh
#   SECTIONS="profile" PROFILE_SECS=20 scripts/rig-bench.sh   # needs perf (+ optional tools below)
#
# Sections (default: env corpus fold journal scaling):
#   env      machine + toolchain capture (always runs first)
#   corpus   trading engine vs matcher-rust on W1..W5, fold on/off, native
#            amend, batch/prefetch, digests, leaf-hash cost, perf counters
#   fold     FOLD_LOG_CAP and block-size sweeps (fold on)
#   journal  ack policy overhead (off/queued/durable), CHUNK_BYTES sweep,
#            crash-test loop, recovery time vs journal size
#   budget   per-item cost of each authentication/commit stage per core and its
#            thread scaling (secp256k1 recover, ed25519 strict/batch, BLAKE3 leaf,
#            session MAC) and the cores needed for 1M EVM tx/s, 10M and 100M
#            orders/s (crates/crypto/benches/budget.rs; docs/lanes-spec.md §8), plus
#            the matcher's per-scheme admission cost (crates/matcher/benches/auth.rs)
#   lanes    sharded trading lane + EVM lane prototypes: orders/s vs shard count
#            and verifier mode (crates/lanes/benches/lanes.rs)
#   shards   the REAL multi-market matcher (one worker per market) driven by one
#            submitter per market, session-MAC auth, journal off/queued/durable,
#            markets 1..NPROC/2 (crates/matcher/benches/shards.rs): the service's
#            shard-scaling curve including the journal on the disk under test
#   procs    the real binaries as SEPARATE pinned processes: oxide-matcher on cores
#            0..S-1 and oxide-loadgen on a disjoint core set, per auth scheme
#            (ed25519, evm, session_mac, certified) at S = 1,2,4,.. up to half the
#            cores; the loadgen builds and signs everything before its clock starts,
#            so the curve is the server's (crates/matcher/benches/shards.rs is the
#            in-process counterpart; e2e is the single-process one)
#   e2e      real loopback TCP through the matcher service for every auth scheme
#            (crates/matcher/tests/e2e_auth_tps.rs), repeated at 4/8/16/32/64 cores
#            via taskset so the curve shows how the whole service scales
#   summary  assemble summary.md (scaling tables, cores-needed-for-target
#            extrapolation) from the files above (scripts/rig/summarize.py)
#   scaling  parallel-EVM, multi-market matcher, ring, hashing benches
#   profile  CPU flamegraphs + top-function tables (perf record, frame pointers),
#            peak RSS/page-faults/ctx-switches per run (/usr/bin/time), heap
#            profiles (heaptrack), off-CPU and lock time (perf sched/lock, bcc),
#            I/O (iostat, strace -c, blktrace) for every bench in the workspace
#            plus the journal worker
#   devnet   multi-validator local devnet (scripts/measure-admission.sh) with a
#            per-process CPU/RSS/threads/FDs/ctx-switch/fault time series and an
#            in-situ perf record of the live validators
#   soak     scripts/soak-test.sh (long; never in the default set) with the same
#            per-process sampler and `docker stats` series; flags RSS leak slopes
#
# One-box preset (about 3 hours; everything that needs only one machine):
#   scripts/rig-bench.sh single-box          # = env budget lanes e2e scaling journal profile summary
#   QUICK=1 scripts/rig-bench.sh single-box  # 5-minute smoke test of the script first
#
# Short-box preset (about 30 min, the measurements that decide the design):
#   SECTIONS="env budget lanes" THREADS="1 2 4 8 16 32" scripts/rig-bench.sh
#
# Environment:
#   THREADS         thread counts for budget/lanes scaling (default: 1 2 4 8 up to nproc)
#   PROFILE_SECS    seconds each profiled bench runs under perf (default: 15)
#   PROFILE_SPECS   space-separated pkg:bench list to profile (default: every bench)
#   OUT             results directory
#   CORES           CPU list to pin single-thread runs to (default: 2)
#   REPS            repetitions per corpus run (default: 7)
#   MATCHER_RUST    path to a matcher-rust checkout (default: ~/matcher-rust or
#                   ~/Documents/matcher-rust); corpus section needs it for
#                   vectorgen and the head-to-head
#   JOURNAL_DIR     directory ON THE DISK UNDER TEST for journal runs (default:
#                   $OUT/journal-scratch — put this on your NVMe mount)
#   QUICK=1         tiny sizes, 1 rep: a smoke test of the script itself
#
# Before a real run: performance governor, fixed frequency, SMT off (or
# recorded), isolated cores (`isolcpus`), nothing else running. The script
# records what it can see but cannot fix it for you.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# The tree may have been rsync'd without .git (scripts/rig/remote.sh, the Linux
# container smoke test): fall back to the hash the sync recorded.
SHA="$(git rev-parse --short HEAD 2>/dev/null || cat "$ROOT/.rig-sha" 2>/dev/null || echo nogit)"
HOST="$(hostname -s)"
OUT="${OUT:-$ROOT/rig-results/$HOST-$SHA-$(date +%Y%m%d-%H%M%S)}"
CORES="${CORES:-2}"
REPS="${REPS:-7}"
QUICK="${QUICK:-0}"
JOURNAL_DIR="${JOURNAL_DIR:-$OUT/journal-scratch}"
mkdir -p "$OUT" "$JOURNAL_DIR"
if [ "$QUICK" = 1 ]; then REPS=1; fi

MATCHER_RUST="${MATCHER_RUST:-}"
for d in "$HOME/matcher-rust" "$HOME/Documents/matcher-rust"; do
    [ -z "$MATCHER_RUST" ] && [ -d "$d" ] && MATCHER_RUST="$d"
done

# Pin a command to $CORES when taskset exists (Linux); run bare otherwise.
pin() { if command -v taskset >/dev/null 2>&1; then taskset -c "$CORES" "$@"; else "$@"; fi; }
log() { printf '\n== %s\n' "$*" | tee -a "$OUT/session.log"; }
run() { # run <outfile> <cmd...> — tee stdout+stderr
    local f="$OUT/$1"; shift
    echo "\$ $*" | tee -a "$OUT/session.log" >>"$f"
    "$@" 2>&1 | tee -a "$f" >>"$OUT/session.log"
}
# Build a bench once and print its executable path (cargo prints it on stderr).
bench_bin() { # bench_bin <package> <bench> [extra cargo args...]
    local pkg="$1" b="$2"; shift 2
    cargo bench -p "$pkg" --bench "$b" "$@" --no-run 2>&1 |
        sed -n 's/.*Executable .*(\(.*\))/\1/p' | tail -1
}

if [ "${1:-}" = "single-box" ] && [ -z "${SECTIONS:-}" ]; then
    SECTIONS="env budget lanes shards procs e2e scaling journal profile summary"
else
    SECTIONS="${SECTIONS:-${*:-env corpus fold journal scaling profile}}"
fi
want() { case " $SECTIONS " in *" $1 "*) return 0 ;; esac; return 1; }


have() { command -v "$1" >/dev/null 2>&1; }
# Copy the source tree (no build output, no VCS) to $1: a scratch tree for the
# sweeps that patch a constant and rebuild. A plain copy, not `git worktree`, so
# it works on trees that were rsync'd without .git.
copy_tree() {
    mkdir -p "$1"
    tar -C "$ROOT" --exclude=./target --exclude=./rig-results --exclude=./.git -cf - . | tar -C "$1" -xf -
}
SAMPLER="$ROOT/scripts/rig/sampler.py"
# sampler_start <name> <match>... ; sampler_stop — per-process time series
SAMPLER_PID=""
sampler_start() {
    local name="$1"; shift
    local args=(); for m in "$@"; do args+=(--match "$m"); done
    python3 "$SAMPLER" "$OUT/proc_$name.csv" --interval "${SAMPLE_SECS:-5}" "${args[@]}" \
        >"$OUT/proc_$name.summary.txt" 2>&1 &
    SAMPLER_PID=$!
}
sampler_stop() {
    [ -n "$SAMPLER_PID" ] && { kill "$SAMPLER_PID" 2>/dev/null || true; wait "$SAMPLER_PID" 2>/dev/null || true; }
    SAMPLER_PID=""
}
# iostat_start <name> ; iostat_stop — block-device utilisation, queue depth, await
IOSTAT_PID=""
iostat_start() {
    if have iostat; then iostat -x -t 1 >"$OUT/iostat_$1.txt" 2>&1 & IOSTAT_PID=$!; fi
}
iostat_stop() { [ -n "$IOSTAT_PID" ] && { kill "$IOSTAT_PID" 2>/dev/null || true; wait "$IOSTAT_PID" 2>/dev/null || true; }; IOSTAT_PID=""; }

# ── env ─────────────────────────────────────────────────────────────
{
    echo "git: $(git rev-parse HEAD 2>/dev/null || cat "$ROOT/.rig-sha" 2>/dev/null || echo unknown) $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') dirty files"
    echo "rustc: $(rustc --version)  cargo: $(cargo --version)"
    uname -a
    if [ -r /proc/cpuinfo ]; then
        lscpu 2>/dev/null | sed -n '1,30p'
        echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
        echo "SMT: $(cat /sys/devices/system/cpu/smt/active 2>/dev/null || echo n/a)"
        echo "turbo/no_turbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)"
        echo "isolated: $(cat /sys/devices/system/cpu/isolated 2>/dev/null || echo none)"
        free -h | head -2
    else
        sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize 2>/dev/null || true
    fi
    echo "journal disk: $(df -h "$JOURNAL_DIR" | tail -1)"
    mount | grep -F "$(df "$JOURNAL_DIR" | tail -1 | awk '{print $1}')" || true
    echo "pin cores: $CORES  reps: $REPS  matcher-rust: ${MATCHER_RUST:-none}"
    echo "profiling tools:"
    for t in perf heaptrack heaptrack_print inferno-collapse-perf inferno-flamegraph flamegraph.pl \
             stackcollapse-perf.pl iostat strace blktrace fio pidstat offcputime-bpfcc docker; do
        if have "$t"; then echo "  [x] $t"; else echo "  [ ] $t (missing)"; fi
    done
    echo "  hint (Debian/Ubuntu): apt install linux-tools-common linux-tools-generic heaptrack sysstat strace blktrace fio bpfcc-tools;"
    echo "                        cargo install inferno   # flamegraphs from perf script"
} | tee "$OUT/env.txt"

# ── corpus ──────────────────────────────────────────────────────────
if want corpus; then
    log "corpus: building"
    CORPUS="$OUT/corpus"; mkdir -p "$CORPUS"
    CBIN="$(bench_bin trading corpus)"
    CBIN_PF="$(bench_bin trading corpus --features prefetch)"
    [ -x "$CBIN" ] || { echo "could not build the corpus bench" >&2; exit 1; }
    if [ -n "$MATCHER_RUST" ]; then
        (cd "$MATCHER_RUST" && cargo build --release --bin matcher_bench \
            --manifest-path Cargo.toml && cargo build --release \
            --manifest-path tools/vectorgen/Cargo.toml) >/dev/null 2>&1
        VG="$MATCHER_RUST/tools/vectorgen/target/release/vectorgen"
        MB="$MATCHER_RUST/target/release/matcher_bench"
    fi
    if [ "$QUICK" = 1 ]; then N=50000; SIZES="1000 20000"; else N=1000000; SIZES="1000 100000 600000"; fi
    if [ -n "${VG:-}" ]; then
        log "corpus: generating"
        "$VG" --workload w1 --n "$N" --out "$CORPUS/w1" 2>/dev/null
        "$VG" --workload w2 --n $((N/5)) --setup-n 100000 --out "$CORPUS/w2" 2>/dev/null
        "$VG" --workload w3 --n $((N/2)) --setup-n 100000 --out "$CORPUS/w3" 2>/dev/null
        "$VG" --workload w4 --n "$N" --setup-n 100000 --out "$CORPUS/w4" 2>/dev/null
        for s in $SIZES; do
            "$VG" --workload w5 --n "$N" --setup-n "$s" --out "$CORPUS/w5_$s" 2>/dev/null
        done
    else
        echo "matcher-rust not found: set MATCHER_RUST to generate corpora" >&2; exit 1
    fi
    WORKLOADS="w1 w2 w3 w4"; for s in $SIZES; do WORKLOADS="$WORKLOADS w5_$s"; done

    log "corpus: Oxide, fold off/on x replace cancel/native"
    for w in $WORKLOADS; do
        for fold in "" "--fold"; do
            for rep in cancel native; do
                run corpus_oxide.txt pin "$CBIN" "$CORPUS/$w" $fold --replace "$rep" --reps "$REPS"
            done
        done
    done
    log "corpus: matcher-rust head-to-head (throughput mode)"
    for w in $WORKLOADS; do run corpus_matcher.txt pin "$MB" "$CORPUS/$w" --mode throughput --reps "$REPS"; done

    log "corpus: batch path, default vs real prefetch"
    for w in $(for s in $SIZES; do echo "w5_$s"; done); do
        run corpus_batch.txt pin "$CBIN" "$CORPUS/$w" --replace native --batch --reps "$REPS"
        [ -x "$CBIN_PF" ] && run corpus_batch_prefetch.txt pin "$CBIN_PF" "$CORPUS/$w" --replace native --batch --reps "$REPS"
    done

    log "corpus: digests vs matcher-rust (correctness gate)"
    MD="$OUT/matcher-digest"; mkdir -p "$MD/src"
    cp scripts/rig/matcher_digest.rs "$MD/src/main.rs"
    printf '[package]\nname = "matcher-digest"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nmatcher = { path = "%s" }\n' \
        "$MATCHER_RUST" >"$MD/Cargo.toml"
    (cd "$MD" && CARGO_TARGET_DIR="$MD/target" cargo build --release >/dev/null 2>&1)
    dig_fail=0
    for w in $WORKLOADS; do
        o="$("$CBIN" "$CORPUS/$w" --replace native --digest)"
        m="$("$MD/target/release/matcher-digest" "$CORPUS/$w")"
        if [ "$o" = "$m" ]; then r=MATCH; else r=MISMATCH; dig_fail=1; fi
        printf '%-10s %s\n  oxide:   %s\n  matcher: %s\n' "$w" "$r" "$o" "$m" | tee -a "$OUT/digests.txt"
    done
    [ "$dig_fail" = 0 ] && echo "ALL DIGESTS MATCH" | tee -a "$OUT/digests.txt" \
        || echo "DIGEST MISMATCH — stop and investigate before trusting any number" | tee -a "$OUT/digests.txt"

    log "corpus: leaf hash cost"
    run leaf.txt pin "$CBIN" --leaf
    run leaf.txt pin "$CBIN" --leaf
    if command -v perf >/dev/null 2>&1; then
        log "corpus: perf counters on the deepest book"
        deep="w5_$(echo $SIZES | awk '{print $NF}')"
        run perf_oxide.txt perf stat -e cycles,instructions,cache-misses,dTLB-load-misses,branch-misses \
            taskset -c "$CORES" "$CBIN" "$CORPUS/$deep" --replace native
        run perf_matcher.txt perf stat -e cycles,instructions,cache-misses,dTLB-load-misses,branch-misses \
            taskset -c "$CORES" "$MB" "$CORPUS/$deep" --mode throughput
    else
        echo "perf not installed: skipping hardware counters (install linux-tools)" | tee -a "$OUT/session.log"
    fi
fi

# ── fold sweeps (need rebuilds with a patched constant: work in a worktree) ──
sweep_const() { # sweep_const <file> <regex-for-line> <name> <values...>
    local file="$1" pat="$2" name="$3"; shift 3
    local wt="$OUT/worktree-$name"
    copy_tree "$wt"
    for v in "$@"; do
        sed -E "s/$pat/\\1$v\\2/" "$ROOT/$file" >"$wt/$file"
        local bin; bin="$(cd "$wt" && bench_bin_in "$name")"
        echo "$name=$v" >>"$OUT/${name}_sweep.txt"
        for w in $SWEEP_WORKLOADS; do
            pin "$bin" "$CORPUS/$w" --fold --reps "$REPS" 2>&1 | tee -a "$OUT/${name}_sweep.txt" >>"$OUT/session.log"
        done
    done
    rm -rf "$wt"
}
bench_bin_in() { CARGO_TARGET_DIR="$OUT/target-$1" cargo bench -p trading --bench corpus --no-run 2>&1 |
    sed -n 's/.*Executable .*(\(.*\))/\1/p' | tail -1; }

if want fold; then
    CORPUS="${CORPUS:-$OUT/corpus}"
    [ -d "$CORPUS" ] || { echo "fold section needs the corpus section's data (run corpus first)" >&2; exit 1; }
    CBIN="${CBIN:-$(bench_bin trading corpus)}"
    SWEEP_WORKLOADS="w1 w4"
    log "fold: block-size sweep (resting_fold read + settle every N ops)"
    for b in 256 1024 4096 16384; do
        for w in $SWEEP_WORKLOADS; do
            echo "block=$b" >>"$OUT/fold_block.txt"
            pin "$CBIN" "$CORPUS/$w" --fold --block "$b" --reps "$REPS" 2>&1 | tee -a "$OUT/fold_block.txt" >>"$OUT/session.log"
        done
    done
    log "fold: FOLD_LOG_CAP sweep (rebuilds)"
    sweep_const crates/trading/src/engine.rs '(pub const FOLD_LOG_CAP: usize = )[0-9_]+(;)' fold_cap 1024 4096 16384 65536
fi

# ── journal ─────────────────────────────────────────────────────────
if want journal; then
    log "journal: ack policy overhead (off/queued/durable) on $JOURNAL_DIR"
    export TMPDIR="$JOURNAL_DIR"
    iostat_start journal; sampler_start journal "matcher-"
    for i in 1 2 3; do
        run journal_ack.txt cargo test -p matcher --release --lib journal_overhead -- --ignored --nocapture
    done
    sampler_stop; iostat_stop
    log "journal: crash-test loop (SIGKILL under Durable)"
    ITER=$([ "$QUICK" = 1 ] && echo 5 || echo 200)
    fails=0
    for i in $(seq 1 "$ITER"); do
        cargo test -p matcher --release --lib acknowledged_orders_survive_sigkill >/dev/null 2>&1 || fails=$((fails+1))
    done
    echo "crash loop: $ITER iterations, $fails failures" | tee "$OUT/journal_crash.txt"
    log "journal: restart time vs journal size (with / without checkpoints)"
    for n in $([ "$QUICK" = 1 ] && echo "20000" || echo "200000 1000000 5000000"); do
        OXIDE_RECOVERY_N=$n run journal_recovery.txt cargo test -p matcher --release --lib \
            journal_recovery_time -- --ignored --nocapture
    done
    log "journal: CHUNK_BYTES sweep (rebuilds)"
    JW="$OUT/worktree-chunk"
    copy_tree "$JW"
    for kb in 64 256 1024; do
        sed -E "s/(pub const CHUNK_BYTES: usize = )[^;]+(;)/\\1$kb * 1024\\2/" \
            crates/matcher/src/journal.rs >"$JW/crates/matcher/src/journal.rs"
        echo "CHUNK_BYTES=${kb}KiB" >>"$OUT/journal_chunk.txt"
        (cd "$JW" && CARGO_TARGET_DIR="$OUT/target-chunk" cargo test -p matcher --release --lib \
            journal_overhead -- --ignored --nocapture 2>&1) | tee -a "$OUT/journal_chunk.txt" >>"$OUT/session.log"
    done
    rm -rf "$JW"
    log "journal: raw fsync cost on this disk"
    if command -v fio >/dev/null 2>&1; then
        run fsync_fio.txt fio --name=fsync --directory="$JOURNAL_DIR" --rw=write --bs=64k --size=256m \
            --fdatasync=1 --ioengine=sync --runtime=20 --time_based
    else
        echo "fio not installed: skipping raw fsync probe (see fsync_avg_us in the server log instead)" | tee -a "$OUT/session.log"
    fi
fi

# ── budget ──────────────────────────────────────────────────────────
if want budget; then
    log "budget: per-stage cost per core and thread scaling"
    NPROC="$( (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null) || echo 4)"
    if [ -z "${THREADS:-}" ]; then
        THREADS=""; t=1
        while [ "$t" -le "$NPROC" ]; do THREADS="$THREADS $t"; t=$((t * 2)); done
        if [ "$((t / 2))" -ne "$NPROC" ]; then THREADS="$THREADS $NPROC"; fi
    fi
    TLIST="$(echo $THREADS | tr ' ' ',')"
    SECS=2; [ "$QUICK" = 1 ] && SECS=0.3
    run budget.csv cargo bench -p crypto --bench budget -- --secs "$SECS" --threads "$TLIST"
    # Admission cost per authentication scheme through the matcher's own
    # authenticators (ed25519 per-item/batch, EVM recover, session MAC,
    # gateway certificate, mixed).
    run auth.csv cargo bench -p matcher --bench auth -- --secs "$SECS" --threads "$TLIST"
fi

# ── lanes ───────────────────────────────────────────────────────────
if want lanes; then
    log "lanes: seam matrix on 1 shard, shard scaling, EVM lane scaling"
    NPROC="${NPROC:-$( (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null) || echo 4)}"
    if [ -z "${THREADS:-}" ]; then
        THREADS=""; t=1
        while [ "$t" -le "$NPROC" ]; do THREADS="$THREADS $t"; t=$((t * 2)); done
        if [ "$((t / 2))" -ne "$NPROC" ]; then THREADS="$THREADS $NPROC"; fi
    fi
    SECS=3; [ "$QUICK" = 1 ] && SECS=0.3
    run lanes.csv cargo bench -p lanes --bench lanes -- --secs "$SECS" \
        --shards "$(echo $THREADS | tr ' ' ',')"
fi

# ── shards ──────────────────────────────────────────────────────────
# Each market costs a worker thread plus a submitter thread, so the market
# steps stop at half the cores.
if want shards; then
    NCPU=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)
    MK=""; m=1
    while [ "$m" -le "$((NCPU / 2))" ] || [ -z "$MK" ]; do MK="$MK,$m"; m=$((m * 2)); done
    MK="${MK#,}"
    SORD=200000; SSUB="1,8"; [ "$QUICK" = 1 ] && { SORD=20000; MK="1,2"; SSUB="1"; }
    log "shards: real matcher scaling, markets $MK, journal on $JOURNAL_DIR"
    mkdir -p "$JOURNAL_DIR/shards"
    run shards.csv cargo bench -p matcher --bench shards -- --markets "$MK" \
        --journal off,queued,durable --sub "$SSUB" --orders "$SORD" --dir "$JOURNAL_DIR/shards"
fi

# ── procs ───────────────────────────────────────────────────────────
# Real binaries, separate processes, disjoint core sets. Matcher state (the
# replay gate) is per process lifetime, so the matcher restarts for every
# (cores, scheme) run: nonces from the previous run would be rejected.
if want procs; then
    NCPU=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)
    log "procs: oxide-matcher + oxide-loadgen as pinned separate processes"
    cargo build --release -p oxide-matcher --features dev-identities -p oxide-loadgen 2>&1 | tail -2 | tee -a "$OUT/session.log"
    MBIN="$ROOT/target/release/oxide-matcher"; LBIN="$ROOT/target/release/oxide-loadgen"
    GW="$("$LBIN" --print-gateway-key)"
    # oxide-matcher refuses to start without a settlement key (there is no default).
    # A throwaway random one is fine here: nothing this bench settles has value.
    SKEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
    PPORT=39000
    SLOW=200000; FAST=2000000
    STEPS="1 2 4 8 16 32 64"
    [ "$QUICK" = 1 ] && { SLOW=20000; FAST=20000; STEPS="1 2"; }
    for S in $STEPS; do
        [ "$S" -gt "$((NCPU / 2))" ] && [ "$S" -gt 1 ] && break
        C="${CLIENT_CORES:-$S}"; [ "$((S + C))" -gt "$NCPU" ] && C=$((NCPU - S)); [ "$C" -lt 1 ] && C=1
        SRV_SET="0-$((S - 1))"; CLI_SET="$S-$((S + C - 1))"
        if ! command -v taskset >/dev/null 2>&1; then SRV_SET=""; CLI_SET=""; fi
        for scheme in ed25519 evm session_mac certified; do
            N=$SLOW; case "$scheme" in session_mac|certified) N=$FAST ;; esac
            ACCTS=$((C * 2 * 64))
            MLOG="$OUT/procs_matcher_${S}_${scheme}.log"
            if [ -n "$SRV_SET" ]; then PIN_S="taskset -c $SRV_SET"; PIN_C="taskset -c $CLI_SET"; else PIN_S=""; PIN_C=""; fi
            # shellcheck disable=SC2086
            $PIN_S "$MBIN" --mode multi --markets "$S" --accounts "$ACCTS" --accounts-cap 262144 \
                --tcp-port "$PPORT" --jsonrpc-port $((PPORT + 1)) --fix-port $((PPORT + 2)) --ws-port $((PPORT + 3)) \
                --auth multi --gateway-keys "$GW" --audit-every 64 --fund-loadgen-keys \
                --settlement-key "$SKEY" >"$MLOG" 2>&1 &
            MPID=$!
            for _ in $(seq 1 100); do (echo >/dev/tcp/127.0.0.1/$PPORT) 2>/dev/null && break; sleep 0.2; done
            echo "# server cores=$S ($SRV_SET) client cores=$C ($CLI_SET) scheme=$scheme orders=$N" >>"$OUT/procs.txt"
            # shellcheck disable=SC2086
            $PIN_C "$LBIN" --port "$PPORT" --orders "$N" --accounts "$ACCTS" --connections $((C * 2)) \
                --batch 500 --markets "$S" --auth "$scheme" 2>&1 | tee -a "$OUT/procs.txt" >>"$OUT/session.log" || true
            kill "$MPID" 2>/dev/null || true; wait "$MPID" 2>/dev/null || true
            sleep 1
        done
    done
fi

# ── e2e ─────────────────────────────────────────────────────────────
# Real loopback TCP through the matcher for every authentication scheme.
# The test process (server + load generator together) is confined to the
# first N cores with taskset, so each step shows how the whole service
# scales; on a one-box rig the load generator shares those cores, which
# understates the server (note it when quoting).
if want e2e; then
    NCPU=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)
    log "e2e: real TCP per auth scheme, core steps up to $NCPU"
    TBIN="$(cargo test -p matcher --release --test e2e_auth_tps --no-run 2>&1 |
        sed -n 's/.*Executable .*(\(.*\))/\1/p' | tail -1)"
    ORDERS=200000; [ "$QUICK" = 1 ] && ORDERS=20000
    for c in 4 8 16 32 64 128; do
        [ "$c" -gt "$NCPU" ] && break
        echo "# cores=$c" >>"$OUT/e2e_auth.txt"
        if command -v taskset >/dev/null 2>&1; then
            AUTH_ORDERS=$ORDERS run e2e_auth.txt taskset -c "0-$((c-1))" "$TBIN" --ignored --nocapture
        else
            AUTH_ORDERS=$ORDERS run e2e_auth.txt "$TBIN" --ignored --nocapture
            break
        fi
    done
fi

# ── scaling ─────────────────────────────────────────────────────────
if want scaling; then
    NCPU=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)
    # Criterion's defaults (100 samples, 5 s each) make this section an hour on a
    # big box; these keep the medians usable. Override with CRIT_ARGS.
    CRIT="${CRIT_ARGS:---warm-up-time 1 --measurement-time 2 --sample-size 20}"
    SCORES="1 2 4 8 16 32 64 128"
    [ "$QUICK" = 1 ] && { CRIT="--warm-up-time 1 --measurement-time 1 --sample-size 10"; SCORES="1 2"; }
    log "scaling: parallel EVM vs cores ($NCPU online)"
    EBIN="$(bench_bin executor uniswap_transfer)"
    for c in $SCORES; do
        [ "$c" -gt "$NCPU" ] && break
        if command -v taskset >/dev/null 2>&1; then
            # shellcheck disable=SC2086
            run scaling_evm.txt taskset -c "0-$((c-1))" "$EBIN" --bench $CRIT
        else
            # shellcheck disable=SC2086
            RAYON_NUM_THREADS=$c run scaling_evm.txt "$EBIN" --bench $CRIT
        fi
        echo "(cores=$c above)" >>"$OUT/scaling_evm.txt"
    done
    log "scaling: matcher benches (multi-market, balance contention, nonce, ring, allocs)"
    for b in matcher_throughput balance_contention nonce_contention ring alloc_accounting; do
        # shellcheck disable=SC2086
        run "scaling_matcher_$b.txt" cargo bench -p matcher --bench "$b" -- $CRIT
    done
    log "scaling: hashing / signature benches (leaf hash, BLS, tx recovery)"
    # shellcheck disable=SC2086
    for b in hash bls tx_recover; do run "scaling_crypto_$b.txt" cargo bench -p crypto --bench "$b" -- $CRIT; done
    # shellcheck disable=SC2086
    run scaling_pipeline.txt cargo bench -p executor --bench block_pipeline -- $CRIT
fi

# ── profile ─────────────────────────────────────────────────────────
if want profile; then
    PROF="$OUT/prof"; mkdir -p "$PROF"
    PSECS="${PROFILE_SECS:-15}"
    log "profile: building the workspace benches with frame pointers (own target dir)"
    pb() { RUSTFLAGS="${RUSTFLAGS:-} -C force-frame-pointers=yes" CARGO_TARGET_DIR="$OUT/target-prof" bench_bin "$@"; }

    # flame_svg <perf.data> <out.svg>: inferno, else FlameGraph scripts, else none
    flame_svg() {
        if have inferno-collapse-perf && have inferno-flamegraph; then
            perf script -i "$1" 2>/dev/null | inferno-collapse-perf | inferno-flamegraph >"$2" 2>/dev/null
        elif have stackcollapse-perf.pl && have flamegraph.pl; then
            perf script -i "$1" 2>/dev/null | stackcollapse-perf.pl | flamegraph.pl >"$2" 2>/dev/null
        fi
    }
    # profile_one <name> <cmd...>
    profile_one() {
        local name="$1"; shift
        log "profile: $name"
        # (1) totals: wall, user/sys CPU, MAX RSS, page faults, context switches
        if [ "$(uname)" = Linux ] && [ -x /usr/bin/time ]; then
            /usr/bin/time -v -o "$PROF/$name.time.txt" "$@" >"$PROF/$name.out.txt" 2>&1 || true
        elif [ -x /usr/bin/time ]; then
            /usr/bin/time -l -o "$PROF/$name.time.txt" "$@" >"$PROF/$name.out.txt" 2>&1 || true
        fi
        # (2) CPU: sampled call graphs -> top functions + flamegraph
        if have perf; then
            perf record -F 999 -g -o "$PROF/$name.perf.data" -- "$@" >/dev/null 2>&1 || true
            if [ -s "$PROF/$name.perf.data" ]; then
                perf report --stdio --no-children --percent-limit 0.5 -i "$PROF/$name.perf.data" \
                    >"$PROF/$name.top.txt" 2>/dev/null || true
                flame_svg "$PROF/$name.perf.data" "$PROF/$name.svg"
            fi
        fi
        # (3) heap: who allocates, how much, peak vs steady state
        if have heaptrack; then
            heaptrack -o "$PROF/$name.heaptrack" "$@" >/dev/null 2>&1 || true
            local hf; hf="$(ls -t "$PROF/$name.heaptrack"* 2>/dev/null | head -1)"
            [ -n "$hf" ] && have heaptrack_print && heaptrack_print -n 25 "$hf" >"$PROF/$name.heap.txt" 2>/dev/null || true
        fi
    }

    # the workload binaries: every bench that exists, built with symbols
    PROFILE_SPECS="${PROFILE_SPECS:-trading:matching matcher:matcher_throughput matcher:balance_contention \
        matcher:nonce_contention matcher:ring executor:block_pipeline executor:uniswap_transfer consensus:engine \
        mempool:pool storage:backend storage:journal storage:mmr p2p:transport broadcast:dissemination codec:wire \
        node:sustained_throughput exchange:settlement evm:breakdown evm:contract_mix crypto:hash crypto:bls \
        crypto:tx_recover}"
    for spec in $PROFILE_SPECS; do
        pkg="${spec%%:*}"; b="${spec##*:}"
        bin="$(pb "$pkg" "$b" 2>/dev/null || true)"
        if [ -x "$bin" ]; then
            # criterion benches take --profile-time (no analysis); others ignore extra args
            profile_one "$pkg-$b" "$bin" --bench --profile-time "$PSECS"
        else
            echo "skip $pkg:$b (no such bench / did not build)" | tee -a "$OUT/session.log"
        fi
    done

    # the matching engine on the corpus, fold on/off, shallow and deep
    CORPUS="${CORPUS:-$OUT/corpus}"
    if [ -d "$CORPUS" ]; then
        PCB="$(pb trading corpus 2>/dev/null || true)"
        deep="$(ls "$CORPUS"/w5_*.run.cmd.jsonl 2>/dev/null | sed 's/.run.cmd.jsonl//' | sort -t_ -k2 -n | tail -1)"
        for fold in "" "--fold"; do
            tag="${fold:+fold}"; tag="${tag:-nofold}"
            [ -x "$PCB" ] && [ -n "$deep" ] && profile_one "corpus-w5deep-$tag" "$PCB" "$deep" $fold --replace native --reps 3
            [ -x "$PCB" ] && [ -f "$CORPUS/w4.run.cmd.jsonl" ] && profile_one "corpus-w4-$tag" "$PCB" "$CORPUS/w4" $fold --replace native --reps 3
        done
    else
        echo "no corpus data: run the corpus section first to profile the engine on W4/W5" | tee -a "$OUT/session.log"
    fi

    # the journal worker (writer thread + I/O thread), with disk + syscall views
    JT="$(RUSTFLAGS="${RUSTFLAGS:-} -C force-frame-pointers=yes" CARGO_TARGET_DIR="$OUT/target-prof" \
        cargo test -p matcher --release --lib --no-run 2>&1 | sed -n 's/.*Executable .*(\(.*\))/\1/p' | tail -1)"
    if [ -x "$JT" ]; then
        export TMPDIR="$JOURNAL_DIR"
        iostat_start profile
        profile_one journal-worker "$JT" journal_overhead --ignored --nocapture
        iostat_stop
        if have strace; then   # fsync/write counts and time, per thread
            strace -c -f -e trace=fsync,fdatasync,write,pwrite64 -o "$PROF/journal-strace.txt" \
                "$JT" journal_overhead --ignored --nocapture >/dev/null 2>&1 || true
        fi
        if have blktrace && [ "$(id -u)" = 0 ]; then
            dev="$(df "$JOURNAL_DIR" | tail -1 | awk '{print $1}')"
            (blktrace -d "$dev" -w 20 -o - | blkparse -i - >"$PROF/journal-blktrace.txt" 2>/dev/null) &
            sleep 1; "$JT" journal_overhead --ignored --nocapture >/dev/null 2>&1 || true; wait
        else
            echo "blktrace skipped (needs the tool and root)" | tee -a "$OUT/session.log"
        fi
    fi

    # off-CPU time and lock contention on the contended paths
    for spec in matcher:balance_contention matcher:matcher_throughput; do
        pkg="${spec%%:*}"; b="${spec##*:}"; bin="$(pb "$pkg" "$b" 2>/dev/null || true)"
        [ -x "$bin" ] || continue
        if have perf; then
            perf sched record -o "$PROF/sched-$b.data" -- "$bin" --bench --profile-time "$PSECS" >/dev/null 2>&1 || true
            perf sched latency -i "$PROF/sched-$b.data" 2>/dev/null | head -40 >"$PROF/sched-$b.latency.txt" || true
            perf lock record -o "$PROF/lock-$b.data" -- "$bin" --bench --profile-time "$PSECS" >/dev/null 2>&1 || true
            perf lock report -i "$PROF/lock-$b.data" 2>/dev/null | head -40 >"$PROF/lock-$b.txt" || true
        fi
        if have offcputime-bpfcc && [ "$(id -u)" = 0 ]; then
            ("$bin" --bench --profile-time "$PSECS" >/dev/null 2>&1 &) ; sleep 2
            offcputime-bpfcc -f -p "$(pgrep -n -f "$b")" "$PSECS" >"$PROF/offcpu-$b.folded" 2>/dev/null || true
            have flamegraph.pl && flamegraph.pl --color=io <"$PROF/offcpu-$b.folded" >"$PROF/offcpu-$b.svg" || true
        fi
    done
    log "profile: done -> $PROF  (*.top.txt, *.svg, *.time.txt, *.heap.txt, sched-*, lock-*, journal-*)"
fi

# ── devnet / soak (opt-in) ──────────────────────────────────────────
if want devnet; then
    log "devnet: fleet CPU per committed tx at 4/7/16 validators, with per-process series + in-situ profile"
    cargo build --release -p oxide-devnet >/dev/null 2>&1
    for n in 4 7 16; do
        sampler_start "devnet$n" oxide-devnet
        # run the load in the background; attach perf/heaptrack once warmed up (measure-admission warms 20 s)
        (run devnet_admission.txt scripts/measure-admission.sh target/release/oxide-devnet "$n" 500 60) &
        LOAD=$!
        sleep 28
        pids="$(pgrep -d, -f 'oxide-devnet.*--node' || true)"
        if [ -n "$pids" ] && have perf; then
            mkdir -p "$OUT/prof"
            perf record -F 199 -g -p "$pids" -o "$OUT/prof/devnet$n.perf.data" -- sleep 30 >/dev/null 2>&1 || true
            perf report --stdio --no-children --percent-limit 0.5 -i "$OUT/prof/devnet$n.perf.data" \
                >"$OUT/prof/devnet$n.top.txt" 2>/dev/null || true
        fi
        if [ -n "$pids" ] && have heaptrack && [ "$n" = 4 ]; then
            heaptrack --pid "$(echo "$pids" | cut -d, -f1)" -o "$OUT/prof/devnet-heap" >/dev/null 2>&1 &
            HT=$!; sleep 20; kill "$HT" 2>/dev/null || true
        fi
        wait "$LOAD" || true
        sampler_stop
    done
    echo "latency injection: see scripts/inject-latency.sh (tc netem) — run it, then re-run this section" \
        | tee -a "$OUT/session.log"
fi
if want soak; then
    log "soak: scripts/soak-test.sh (long-running) with per-process + container series"
    sampler_start soak oxide-validator oxide-devnet oxide-matcher
    if have docker; then
        ( while true; do
              docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}' \
                  | sed "s/^/$(date +%s),/" >>"$OUT/soak_docker_stats.csv" 2>/dev/null
              sleep 10
          done ) &
        DSTAT=$!
    fi
    run soak.txt scripts/soak-test.sh
    [ -n "${DSTAT:-}" ] && kill "$DSTAT" 2>/dev/null || true
    sampler_stop
    echo "RSS leak slopes: see proc_soak.summary.txt (LEAK SUSPECT = growth > 1%/h of mean RSS)" | tee -a "$OUT/session.log"
fi

# ── summary ─────────────────────────────────────────────────────────
if want summary; then
    log "summary: assembling summary.md"
    python3 "$ROOT/scripts/rig/summarize.py" "$OUT" | tee "$OUT/summary.md" >/dev/null || true
    echo "see $OUT/summary.md" | tee -a "$OUT/session.log"
fi

log "done: results in $OUT"
echo "Send back: $OUT (env.txt, digests.txt, corpus_*, journal_*, scaling_*, prof/, proc_*.csv + summaries, iostat_*, soak_docker_stats.csv)"
