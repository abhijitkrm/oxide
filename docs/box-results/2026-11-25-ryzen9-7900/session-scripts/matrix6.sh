#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
OUT=/root/results/matrix-steady.log; : > $OUT
run(){ label=$1; shift
  r=$(RAYON_NUM_THREADS=12 CHAIN_MIX_CONCURRENT=1 CHAIN_MIX_LANE=root "$@" 2>&1 | grep -E "^wall|^stages|^bundle/|^clob/|^transfer/" | sed -E "s/serial_floor_tps=[0-9]+,//" | tr '\n' ' ')
  echo "$label :: $r" >> $OUT; }
B="cargo bench -q -p executor --bench chain_mix --"
for rep in 1 2; do
  run "bundle16 60M-orders 50ms 64MiB rep=$rep" env CHAIN_MIX_BLOCK_MS=50 CHAIN_MIX_BLOCK_BYTES=67108864 CHAIN_MIX_GAS_LIMIT=6000000000 $B --mix bundle --txs 60000000 --threads 12 --accounts 512 --markets 16
done
for rep in 1 2; do
  run "clob16 lanes=1 3M-orders rep=$rep" env CHAIN_MIX_BLOCK_MS=50 $B --mix clob --txs 3000000 --threads 12 --accounts 512 --markets 16
done
run "clob16 lanes=0 3M-orders rep=1" env CHAIN_MIX_EX_LANES=0 CHAIN_MIX_BLOCK_MS=50 $B --mix clob --txs 3000000 --threads 12 --accounts 512 --markets 16
for rep in 1 2; do
  run "evm-transfer 3M-tx rep=$rep" env CHAIN_MIX_BLOCK_MS=50 $B --mix transfer --txs 3000000 --threads 12 --accounts 512
done
echo ALLDONE >> $OUT
