# Box data archive, 25 Nov 2026 (AMD Ryzen 9 7900, 12 cores / 24 threads, 93 GB)

`box-data-2026-11-25.tar.xz` (11.3 MB, xz -9e; 240 MB uncompressed) holds everything the box produced during the
session, so nothing needs the (retired) machine again.

- SHA-256: `6f2f951ec39967354f8df95de5959ba139c7ffcffe30d360011e3b356e374c1c`
- Extract: `tar -xJf box-data-2026-11-25.tar.xz` (creates `results/`)

Contents of `results/`:

| Path | What it is |
|---|---|
| `*.log`, `*.out`, `lanes-a.csv` | every benchmark matrix and run log (lanes, exchange lanes, allocator, concurrent and steady-state, dbundle, consensus, orders), full test and gate output |
| `perf-*.data` | `perf record` captures of the chain_mix pipeline (EVM transfer, bundle, lanes), frame-pointer builds |
| `profiles/*.perf.data` | system-wide `perf record` of 4 and 3 real validators under order load (4x3, 3x4, 4x6 SMT, and 4x3 with the default ingress limit) |
| `profiles/*.folded` | folded stacks (comm;frame;frame count) for flame-graph tools, top 6000 stacks per profile |
| `profiles/*.top.txt`, `*.threads.txt` | the `perf report` summaries (also committed as text under `orders/profiles/`) |
| `profiles/stall-*` | the stall-evidence attempts (empty or wrong-process: see `docs/devlog.md`, "order throughput through real consensus") |

Analysis: `docs/devlog.md` (entries dated 25 Nov 2026). View a profile with
`perf report -i results/profiles/p-4x3-r800.perf.data --no-children --sort comm,sym --stdio` (binaries were built with
frame pointers and line tables; the `/root/target-prof/...` paths in the data will not exist elsewhere, so symbol resolution of
those binaries needs a rebuild of the same commits: `localnet-orders` / `main` at the time).
