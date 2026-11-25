#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
git fetch -q origin consensus-bench && git reset -q --hard origin/consensus-bench
OUT=/root/results/consensus-matrix.log; : > $OUT
cargo build -q --release -p oxide-devnet >> /root/results/cmatrix-build.log 2>&1
# validators cores smt
for cfg in "4 3 0" "3 4 0" "4 3 1" "3 4 1"; do set -- $cfg; n=$1; c=$2; smt=$3
  for rate in 2000 4000 6000 8000; do
    flag=""; [ $smt = 1 ] && flag="--smt"
    r=$(python3 scripts/consensus-bench.py --validators $n --cores $c $flag --rate $rate --presign 300000 --duration 10 --warmup 5 2>&1 | grep "^RESULT")
    echo "$r" >> $OUT
  done
done
echo ALLDONE >> $OUT
