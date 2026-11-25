#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
git fetch -q origin exchange-lanes && git checkout -q exchange-lanes && git reset -q --hard origin/exchange-lanes
OUT=/root/results/matrix-lane-cap.log; : > $OUT
cargo build -q --release -p executor --bench chain_mix >> /root/results/matrix3-build.log 2>&1
for mk in 12 16 32 64 256; do
  for cfg in "12 0" "12 1" "24 1"; do set -- $cfg; th=$1; lanes=$2
    for rep in 1 2 3; do
      r=$(RAYON_NUM_THREADS=$th CHAIN_MIX_LANE=root CHAIN_MIX_EX_LANES=$lanes cargo bench -q -p executor --bench chain_mix -- --mix bundle --txs 3000000 --threads 12 --accounts 512 --markets $mk 2>&1 | grep -E "^stages,|^roots," | tr '\n' ' ')
      echo "markets=$mk rayon=$th lanes=$lanes rep=$rep :: $r" >> $OUT
    done
  done
done
echo ALLDONE >> $OUT
