#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
OUT=/root/results/order-matrix2.log; : > $OUT
export OXIDE_P2P_INGRESS_BYTES_PER_SEC=400000000
for cfg in "4 3 0 3200" "4 3 0 6400" "4 3 0 12800" "4 3 1 3200" "4 3 1 6400" "4 3 1 12800" "3 4 0 3200" "3 4 0 6400" "3 4 1 6400" "3 4 1 12800"; do set -- $cfg; n=$1; c=$2; smt=$3; rate=$4
  flag=""; [ $smt = 1 ] && flag="--smt"
  pre=$((rate*40+200))
  r=$(python3 scripts/consensus-bench.py --validators $n --cores $c $flag --orders 64 --markets 16 --rate $rate --presign $pre --duration 12 --warmup 6 2>&1 | grep "^RESULT")
  echo "$r" >> $OUT
done
echo ALLDONE >> $OUT
