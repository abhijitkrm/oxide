#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
git fetch -q origin localnet-orders && git reset -q --hard origin/localnet-orders
cargo build -q --release -p oxide-devnet >> /root/results/omatrix-build.log 2>&1
CARGO_TARGET_DIR=/root/target-prof CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTFLAGS="-C force-frame-pointers=yes" cargo build -q --release -p oxide-devnet >> /root/results/omatrix-build.log 2>&1
OUT=/root/results/order-matrix.log; : > $OUT
export OXIDE_P2P_INGRESS_BYTES_PER_SEC=400000000
for cfg in "4 3 0" "3 4 0" "4 3 1" "3 4 1"; do set -- $cfg; n=$1; c=$2; smt=$3
  for rate in 100 200 400 800 1600; do
    flag=""; [ $smt = 1 ] && flag="--smt"
    pre=$((rate*40+200))
    r=$(python3 scripts/consensus-bench.py --validators $n --cores $c $flag --orders 64 --markets 16 --rate $rate --presign $pre --duration 12 --warmup 6 2>&1 | grep "^RESULT")
    echo "$r" >> $OUT
  done
done
echo ALLDONE >> $OUT
