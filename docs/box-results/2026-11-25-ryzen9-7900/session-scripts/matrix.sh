#!/usr/bin/env bash
. $HOME/.cargo/env; cd /root/oxide
OUT=/root/results/matrix.log; : > $OUT
for th in 12 24; do for mix in transfer mixed; do for lanes in 0 1; do for rep in 1 2 3 4 5; do
  r=$(RAYON_NUM_THREADS=$th CHAIN_MIX_LANE=root CHAIN_MIX_EVM_LANES=$lanes cargo bench -q -p executor --bench chain_mix -- --mix $mix --txs 120000 --threads $th --accounts 512 2>&1 | grep -E "^stages,|^[a-z]+/[a-z]+," | tr '\n' ' ')
  echo "th=$th mix=$mix lanes=$lanes rep=$rep :: $r" >> $OUT
done; done; done; done
echo ALLDONE >> $OUT
