# Session scripts (box, 25 Nov 2026)

The ad-hoc drivers that produced the numbers in `docs/devlog.md`, saved verbatim from the retired box (`/root/`). They assume the
box layout (`/root/oxide`, `/root/results`, binaries under `/root/target-*`), so treat them as the record of exactly how each matrix was run.

| Script | What it ran |
|---|---|
| `matrix.sh` .. `matrix8.sh` | `chain_mix` matrices: EVM lanes, exchange lanes, lane cap, concurrent/steady-state, ingest sweep, delegated bundles |
| `cmatrix.sh`, `cmatrix2.sh` | consensus matrices (EVM transfers; default and raised ingress limit) |
| `omatrix.sh`, `omatrix2.sh` | order throughput through consensus (rates and saturation sweep) |
| `pmatrix.sh` | profile session (perf per layout, default-limit comparison) |
| `an.py`, `folded.py` | perf-script callee breakdown and folded-stack extraction |
| `stallsample.py` | the thread-state sampler (attached to the wrong process in its one run; see the devlog) |
