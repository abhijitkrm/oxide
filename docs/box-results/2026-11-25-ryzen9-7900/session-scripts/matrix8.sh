#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
git fetch -q origin cheap-auth && git checkout -q cheap-auth && git reset -q --hard origin/cheap-auth
OUT=/root/results/matrix-dbundle.log; : > $OUT
cargo build -q --release -p executor --bench chain_mix >> /root/results/matrix8-build.log 2>&1
# exactness probe: lanes off/on, single ingest thread (deterministic)
for l in 0 1; do
  r=$(CHAIN_MIX_EX_LANES=$l CHAIN_MIX_LANE=sync CHAIN_MIX_GATEWAYS=16 cargo bench -q -p executor --bench chain_mix -- --mix dbundle --txs 400000 --threads 1 --accounts 512 --markets 16 2>&1 | grep -E "^roots" | sed -E "s/StateAttestation \{ height: height [0-9]+, root: //" | tr '\n' ' ')
  echo "exact lanes=$l :: $r" >> $OUT
done
# loop-only and sustained concurrent
for mix in bundle dbundle; do
  for rep in 1 2 3; do
    r=$(RAYON_NUM_THREADS=12 CHAIN_MIX_LANE=root CHAIN_MIX_GATEWAYS=32 cargo bench -q -p executor --bench chain_mix -- --mix $mix --txs 3000000 --threads 12 --accounts 512 --markets 16 2>&1 | grep -E "^stages|^wall|^lane_phases" | sed -E "s/serial_floor_tps=[0-9]+,//" | tr '\n' ' ')
    echo "loop-only mix=$mix rep=$rep :: $r" >> $OUT
  done
  for rep in 1 2; do
    r=$(RAYON_NUM_THREADS=12 CHAIN_MIX_CONCURRENT=1 CHAIN_MIX_BLOCK_MS=50 CHAIN_MIX_BLOCK_BYTES=67108864 CHAIN_MIX_GAS_LIMIT=6000000000 CHAIN_MIX_LANE=root CHAIN_MIX_GATEWAYS=32 cargo bench -q -p executor --bench chain_mix -- --mix $mix --txs 30000000 --threads 12 --accounts 512 --markets 16 2>&1 | grep -E "^wall|^stages" | sed -E "s/serial_floor_tps=[0-9]+,//" | tr '\n' ' ')
    echo "sustained mix=$mix rep=$rep :: $r" >> $OUT
  done
done
echo ALLDONE >> $OUT
