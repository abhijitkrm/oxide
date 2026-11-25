#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
OUT=/root/results/matrix-exchange-lanes.log; : > $OUT
cargo build -q --release -p executor --bench chain_mix >> /root/results/matrix2-build.log 2>&1
for mix in bundle clob; do
  if [ $mix = bundle ]; then TXS=3000000; else TXS=600000; fi
  for mk in 1 4 8 12; do for lanes in 0 1; do for rep in 1 2 3; do
    r=$(RAYON_NUM_THREADS=12 CHAIN_MIX_LANE=root CHAIN_MIX_EX_LANES=$lanes cargo bench -q -p executor --bench chain_mix -- --mix $mix --txs $TXS --threads 12 --accounts 512 --markets $mk 2>&1 | grep -E "^stages,|^roots," | tr '\n' ' ')
    echo "mix=$mix markets=$mk lanes=$lanes rep=$rep :: $r" >> $OUT
  done; done; done
done
echo ALLDONE >> $OUT
