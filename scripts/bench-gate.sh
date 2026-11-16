#!/usr/bin/env bash
# Machine-independent performance gates for the chain path (plan W0/W7).
#
# Absolute tx/s depends on the host, so every gate is a RATIO between two runs of
# the same host, i.e. a structural property of the code:
#
#   G1  root stage:   EVM-transfer loop tx/s with the root stage  >= G1_MIN x synchronous
#   G2  propose:      propose tx/s >= ingest tx/s (the proposer must not be the bottleneck;
#                     it was 11 us/tx = ~85k/s when it cloned the whole pool per block)
#   G4  bundles:     admission (orders/s) of 64-order bundles >= G4_MIN x per-order admission
#                     (docs/bundle-auth-spec.md gate 4: one recovery per bundle)
#   G3  flat in n:    CLOB loop tx/s at 100k accounts >= G3_MIN x at 1k accounts
#                     (plan target: within 1.5x, i.e. 0.67, NOT yet met; the floor was 0.45 and
#                     is 0.35 because 1k-account CLOB got faster (lazy fold) while the 100k case is
#                     bound by ~29k EVM-account touches per block)
#
# Usage: scripts/bench-gate.sh [--txs N]     (exit 1 on a failed gate)
# Env:   G4_MIN (default 10)  G1_MIN (default 1.15)  G3_MIN (default 0.35)  RAYON_NUM_THREADS (default 4)
set -uo pipefail
TXS=${TXS:-120000}
while [ $# -gt 0 ]; do case "$1" in --txs) TXS=$2; shift 2;; *) shift;; esac; done
G1_MIN=${G1_MIN:-1.15}
G3_MIN=${G3_MIN:-0.35}
G4_MIN=${G4_MIN:-10}
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-4}
THREADS=${THREADS:-4}

run() { # mode mix accounts -> prints "propose_tps loop_tps ingest_tps"
  local mode=$1 mix=$2 accts=$3 out rc
  out=$(CHAIN_MIX_LANE=$mode cargo bench -q -p executor --bench chain_mix -- \
        --mix "$mix" --txs "$TXS" --threads "$THREADS" --accounts "$accts" 2>&1); rc=$?
  if [ $rc -ne 0 ]; then echo "bench failed (rc=$rc): $mode $mix $accts" >&2; echo "$out" >&2; exit 2; fi
  python3 - "$out" <<'PY'
import re,sys
t=sys.argv[1]
st=[l for l in t.splitlines() if l.startswith("stages,")]
row=[l for l in t.splitlines() if re.match(r"^[a-z]+/[a-z]+,",l)]
if not st or not row:
    sys.exit("could not parse chain_mix output")
loop=float(re.search(r"loop_tps=(\d+)",st[0]).group(1))
f=row[0].split(",")
print(f"{float(f[4]):.0f} {loop:.0f} {float(f[3]):.0f}")
PY
}

read -r p_sync l_sync i_sync < <(run sync transfer 512)
read -r p_root l_root i_root < <(run root transfer 512)
read -r _ l_1k _ < <(run root clob 1000)
read -r _ l_100k i_clob < <(run root clob 100000)
read -r _ _ i_bundle < <(run root bundle 1000)

fail=0
check() { # name value op threshold
  python3 - "$1" "$2" "$3" "$4" <<'PY' || fail=1
import sys
name,val,op,thr=sys.argv[1],float(sys.argv[2]),sys.argv[3],float(sys.argv[4])
ok = val>=thr if op==">=" else val<=thr
print(("PASS" if ok else "FAIL"), f"{name}: {val:.3f} {op} {thr:.3f}")
sys.exit(0 if ok else 1)
PY
}
echo "transfer: sync loop=$l_sync root loop=$l_root propose=$p_root ingest=$i_root | clob: 1k=$l_1k 100k=$l_100k"
check "G1 root-stage speedup (EVM transfers)" "$(python3 -c "print($l_root/$l_sync)")" ">=" "$G1_MIN"
check "G2 propose vs ingest" "$(python3 -c "print($p_root/$i_root)")" ">=" "1.0"
check "G4 bundle admission vs per-order" "$(python3 -c "print($i_bundle/$i_clob)")" ">=" "$G4_MIN"
check "G3 CLOB flat in accounts (100k/1k)" "$(python3 -c "print($l_100k/$l_1k)")" ">=" "$G3_MIN"
exit $fail
