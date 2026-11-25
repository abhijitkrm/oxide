#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
OUT=/root/results/consensus-matrix2.log; : > $OUT
export OXIDE_P2P_INGRESS_BYTES_PER_SEC=400000000
for cfg in "4 3 0" "3 4 0" "4 3 1" "3 4 1"; do set -- $cfg; n=$1; c=$2; smt=$3
  for rate in 4000 8000 16000; do
    flag=""; [ $smt = 1 ] && flag="--smt"
    r=$(python3 scripts/consensus-bench.py --validators $n --cores $c $flag --rate $rate --presign 300000 --duration 12 --warmup 5 2>&1 | grep "^RESULT")
    echo "$r" >> $OUT
  done
done
echo ALLDONE >> $OUT
