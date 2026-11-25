#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
git fetch -q origin exchange-lanes && git reset -q --hard origin/exchange-lanes
OUT=/root/results/matrix-concurrent.log; : > $OUT
cargo build -q --release -p executor --bench chain_mix >> /root/results/matrix4-build.log 2>&1
for cfg in "bundle 16 4 1" "bundle 16 6 1" "bundle 16 8 1" "bundle 16 12 1" "bundle 16 8 0" "clob 16 12 1" "clob 16 12 0"; do set -- $cfg; mix=$1; mk=$2; th=$3; lanes=$4
  if [ $mix = bundle ]; then TXS=6000000; else TXS=600000; fi
  for rep in 1 2 3; do
    r=$(RAYON_NUM_THREADS=12 CHAIN_MIX_CONCURRENT=1 CHAIN_MIX_BLOCK_MS=50 CHAIN_MIX_LANE=root CHAIN_MIX_EX_LANES=$lanes cargo bench -q -p executor --bench chain_mix -- --mix $mix --txs $TXS --threads $th --accounts 512 --markets $mk 2>&1 | grep -E "^wall|^stages" | sed -E "s/serial_floor_tps=[0-9]+,//" | tr '\n' ' ')
    echo "mix=$mix markets=$mk ingest_threads=$th lanes=$lanes rep=$rep :: $r" >> $OUT
  done
done
echo ALLDONE >> $OUT
