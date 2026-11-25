#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
git fetch -q origin exchange-lanes && git reset -q --hard origin/exchange-lanes
OUT=/root/results/matrix-concurrent2.log; : > $OUT
cargo build -q --release -p executor --bench chain_mix >> /root/results/matrix5-build.log 2>&1
# block interval ms, block bytes, gas limit
for cfg in "50 67108864 6000000000 8" "50 67108864 6000000000 12" "100 67108864 6000000000 8" "100 134217728 12000000000 8" "100 134217728 12000000000 12" "20 33554432 3000000000 8"; do set -- $cfg; ms=$1; by=$2; gas=$3; th=$4
  for rep in 1 2 3; do
    r=$(RAYON_NUM_THREADS=12 CHAIN_MIX_CONCURRENT=1 CHAIN_MIX_BLOCK_MS=$ms CHAIN_MIX_BLOCK_BYTES=$by CHAIN_MIX_GAS_LIMIT=$gas CHAIN_MIX_LANE=root cargo bench -q -p executor --bench chain_mix -- --mix bundle --txs 8000000 --threads $th --accounts 512 --markets 16 2>&1 | grep -E "^wall|^stages" | sed -E "s/serial_floor_tps=[0-9]+,//" | tr '\n' ' ')
    echo "block_ms=$ms block_bytes=$by gas=$gas ingest_threads=$th rep=$rep :: $r" >> $OUT
  done
done
echo ALLDONE >> $OUT
