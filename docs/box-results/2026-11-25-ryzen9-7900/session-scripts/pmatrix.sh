#!/usr/bin/env bash
# Profile session on the box: CPU profiles (perf, frame pointers), peak RSS, mimalloc stats, stall syscalls.
. $HOME/.cargo/env; cd /root/oxide
BIN=/root/target-prof/release/oxide-devnet
OUTD=/root/results/profiles; mkdir -p $OUTD
LOG=$OUTD/profile-runs.log; : > $LOG
run() { # label n cores smt rate extra-env
  label=$1; n=$2; c=$3; smt=$4; rate=$5; shift 5
  flag=""; [ $smt = 1 ] && flag="--smt"
  pre=$((rate*45+200))
  echo "== $label" >> $LOG
  env "$@" python3 scripts/consensus-bench.py --bin $BIN --validators $n --cores $c $flag --orders 64 --markets 16 \
     --rate $rate --presign $pre --duration 15 --warmup 8 --perf-out $OUTD/$label.perf.data 2>&1 | grep -v "^logs kept" >> $LOG
  perf report -i $OUTD/$label.perf.data --no-children --sort comm,sym --percent-limit 0.6 --stdio -g none 2>/dev/null \
     | grep -E "^ +[0-9]" | head -60 > $OUTD/$label.top.txt
  perf report -i $OUTD/$label.perf.data --no-children --sort comm --stdio -g none 2>/dev/null \
     | grep -E "^ +[0-9]" | head -20 > $OUTD/$label.threads.txt
  perf script -i $OUTD/$label.perf.data -F comm,ip,sym 2>/dev/null | python3 - $label $OUTD <<'PY'
import sys,collections
label,outd=sys.argv[1],sys.argv[2]
# folded stacks (root-first) for flamegraph tools; keep only the top 4000 distinct
folded=collections.Counter(); stack=[]; comm=None
for line in sys.stdin:
    line=line.rstrip("\n")
    if not line.strip():
        if stack: folded[comm+";"+";".join(reversed(stack))]+=1
        stack=[]; comm=None; continue
    if not line.startswith((" ","\t")):
        comm=line.split()[0] if line.split() else "?"; stack=[]; continue
    p=line.split(None,1); stack.append(p[1] if len(p)>1 else p[0])
with open(f"{outd}/{label}.folded","w") as f:
    for k,v in folded.most_common(4000): f.write(f"{k} {v}\n")
PY
}
export OXIDE_P2P_INGRESS_BYTES_PER_SEC=400000000
# 1) the knee on the best layout and a 3-validator layout, ingress limit raised
run p-4x3-r800    4 3 0 800  MIMALLOC_SHOW_STATS=1 OXIDE_P2P_INGRESS_BYTES_PER_SEC=400000000
run p-3x4-r800    3 4 0 800  OXIDE_P2P_INGRESS_BYTES_PER_SEC=400000000
run p-4x6smt-r1600 4 3 1 1600 OXIDE_P2P_INGRESS_BYTES_PER_SEC=400000000
# 2) the same knee with the DEFAULT ingress limit (unset): what the limit costs under order traffic
run p-4x3-r800-default 4 3 0 800 -u OXIDE_P2P_INGRESS_BYTES_PER_SEC A=1
echo ALLDONE >> $LOG
