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
#
# Sections (default: env corpus fold journal scaling):
#   env      machine + toolchain capture (always runs first)
#   corpus   trading engine vs matcher-rust on W1..W5, fold on/off, native
#            amend, batch/prefetch, digests, leaf-hash cost, perf counters
#   fold     FOLD_LOG_CAP and block-size sweeps (fold on)
#   journal  ack policy overhead (off/queued/durable), CHUNK_BYTES sweep,
#            crash-test loop, recovery time vs journal size
#   scaling  parallel-EVM, multi-market matcher, ring, hashing benches
#   devnet   multi-validator local devnet (scripts/measure-admission.sh)
#   soak     scripts/soak-test.sh (long; never in the default set)
#
# Environment:
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
SHA="$(git rev-parse --short HEAD)"
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

SECTIONS="${SECTIONS:-${*:-env corpus fold journal scaling}}"
want() { case " $SECTIONS " in *" $1 "*) return 0 ;; esac; return 1; }

# ── env ─────────────────────────────────────────────────────────────
{
    echo "git: $(git rev-parse HEAD) $(git status --porcelain | wc -l | tr -d ' ') dirty files"
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
    git worktree add --detach "$wt" HEAD >/dev/null 2>&1 || true
    for v in "$@"; do
        sed -E "s/$pat/\\1$v\\2/" "$ROOT/$file" >"$wt/$file"
        local bin; bin="$(cd "$wt" && bench_bin_in "$name")"
        echo "$name=$v" >>"$OUT/${name}_sweep.txt"
        for w in $SWEEP_WORKLOADS; do
            pin "$bin" "$CORPUS/$w" --fold --reps "$REPS" 2>&1 | tee -a "$OUT/${name}_sweep.txt" >>"$OUT/session.log"
        done
    done
    git worktree remove --force "$wt" >/dev/null 2>&1 || true
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
    for i in 1 2 3; do
        run journal_ack.txt cargo test -p matcher --release --lib journal_overhead -- --ignored --nocapture
    done
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
    git worktree add --detach "$JW" HEAD >/dev/null 2>&1 || true
    for kb in 64 256 1024; do
        sed -E "s/(pub const CHUNK_BYTES: usize = )[^;]+(;)/\\1$kb * 1024\\2/" \
            crates/matcher/src/journal.rs >"$JW/crates/matcher/src/journal.rs"
        echo "CHUNK_BYTES=${kb}KiB" >>"$OUT/journal_chunk.txt"
        (cd "$JW" && CARGO_TARGET_DIR="$OUT/target-chunk" cargo test -p matcher --release --lib \
            journal_overhead -- --ignored --nocapture 2>&1) | tee -a "$OUT/journal_chunk.txt" >>"$OUT/session.log"
    done
    git worktree remove --force "$JW" >/dev/null 2>&1 || true
    log "journal: raw fsync cost on this disk"
    if command -v fio >/dev/null 2>&1; then
        run fsync_fio.txt fio --name=fsync --directory="$JOURNAL_DIR" --rw=write --bs=64k --size=256m \
            --fdatasync=1 --ioengine=sync --runtime=20 --time_based
    else
        echo "fio not installed: skipping raw fsync probe (see fsync_avg_us in the server log instead)" | tee -a "$OUT/session.log"
    fi
fi

# ── scaling ─────────────────────────────────────────────────────────
if want scaling; then
    NCPU=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)
    log "scaling: parallel EVM vs cores ($NCPU online)"
    EBIN="$(bench_bin executor uniswap_transfer)"
    for c in 1 2 4 8 16 32; do
        [ "$c" -gt "$NCPU" ] && break
        if command -v taskset >/dev/null 2>&1; then
            run scaling_evm.txt taskset -c "0-$((c-1))" "$EBIN" --bench
        else
            RAYON_NUM_THREADS=$c run scaling_evm.txt "$EBIN" --bench
        fi
        echo "(cores=$c above)" >>"$OUT/scaling_evm.txt"
    done
    log "scaling: matcher benches (multi-market, balance contention, nonce, ring, allocs)"
    for b in matcher_throughput balance_contention nonce_contention ring alloc_accounting; do
        run "scaling_matcher_$b.txt" cargo bench -p matcher --bench "$b"
    done
    log "scaling: hashing / signature benches (leaf hash, BLS, tx recovery)"
    for b in hash bls tx_recover; do run "scaling_crypto_$b.txt" cargo bench -p crypto --bench "$b"; done
    run scaling_pipeline.txt cargo bench -p executor --bench block_pipeline
fi

# ── devnet / soak (opt-in) ──────────────────────────────────────────
if want devnet; then
    log "devnet: fleet CPU per committed tx at 4/7/16 validators"
    cargo build --release -p oxide-devnet >/dev/null 2>&1
    for n in 4 7 16; do
        run devnet_admission.txt scripts/measure-admission.sh target/release/oxide-devnet "$n" 500 60
    done
    echo "latency injection: see scripts/inject-latency.sh (tc netem) — run it, then re-run this section" \
        | tee -a "$OUT/session.log"
fi
if want soak; then
    log "soak: scripts/soak-test.sh (long-running)"
    run soak.txt scripts/soak-test.sh
fi

log "done: results in $OUT"
echo "Send back: $OUT (env.txt, corpus_*.txt, perf_*.txt, journal_*.txt, scaling_*.txt, digests.txt)"
