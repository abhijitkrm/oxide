#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
OUT=/root/results/matrix-ingest-sweep.log; : > $OUT
for mix in transfer clob; do
  for th in 4 6 8 10 12 16; do
    r=$(RAYON_NUM_THREADS=12 CHAIN_MIX_CONCURRENT=1 CHAIN_MIX_BLOCK_MS=50 CHAIN_MIX_LANE=root cargo bench -q -p executor --bench chain_mix -- --mix $mix --txs 1500000 --threads $th --accounts 512 --markets 16 2>&1 | grep -E "^wall|^stages" | sed -E "s/serial_floor_tps=[0-9]+,//" | tr '\n' ' ')
    echo "mix=$mix ingest_threads=$th :: $r" >> $OUT
  done
done
echo ALLDONE >> $OUT
