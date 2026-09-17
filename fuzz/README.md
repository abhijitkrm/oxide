# Oxide fuzzing

cargo-fuzz (libFuzzer) targets over every untrusted-bytes boundary in the
system. Nightly CI runs each target for 10 minutes; the minimized corpus
is committed under `corpus/<target>/` so coverage accretes across runs.
`artifacts/`, `target/`, `coverage/`, and `soak_logs/` are gitignored.

```sh
cargo +nightly fuzz run <target> -- -max_total_time=600   # local soak
cargo +nightly fuzz coverage <target>                     # LLVM source coverage
```

Requires the nightly toolchain with `rustup component add llvm-tools`.

## Targets and input contracts

Each harness defines a mapping from fuzz bytes to the system under test.
**A harness that maps bytes into a shape the production parser ignores is
a silent no-op** — check the contract before trusting coverage numbers.

| Target | Input contract |
|---|---|
| `codec-decode` | First byte selects a fixed-width decode; remainder is also walked as a varint/byte-stream to reach `Reader::read_varint`/`read_bytes` length-prefixed paths. |
| `consensus-msg` | Raw bytes decoded as wire messages (votes, QCs, proposals). |
| `evm-execute` | Bytes drive transaction construction + `revm` execution. |
| `journal-replay` | Bytes are written as `segment-0.log` inside a fresh journal dir and replayed. **The filename must match `SEGMENT_PREFIX<seq>.log`** (`segment-0.log`) — `segment_files()` skips foreign names, so a bare `0.log` exercises only the empty-replay path. Valid inputs need the `OXDJRN01` magic + `[len:u32][crc32:u32][payload]` records. Named seeds: `jr_valid`, `jr_torn`, `jr_badcrc`, `jr_badlen`. |
| `mmr-proof-verify` | Bytes encode leaf index + proof nodes for `Mmr::verify`. |
| `sync-decode` | Raw bytes decoded as state-sync wire messages (manifests, chunks). |
| `trading-engine` | Byte stream drives order ops against the matching engine. |
| `trading-order-validate` | `[side:1][type:1][tif:1][price:u64][qty:u64]` (19 bytes) → `Order::validate`. Saturated at 14 edges — all branches covered by `seed_*` files. |
| `types-decode` | Raw bytes decoded as core types (`Address`, `Hash`, headers). |

## Coverage snapshot

`llvm-cov` report over the instrumented release binary after the
10-minute soak + corpus merge. These numbers measure *this corpus's*
reach into first-party source — they are a floor, not a ceiling.

| Target | File | Lines |
|---|---|---|
| `types-decode` | `crates/types/src/lib.rs` | ~28.9% |
| `codec-decode` | `crates/codec/src/lib.rs` | ~47.3% |
| `trading-engine` | `crates/trading/src/engine.rs` | ~56.4% (regions) |
| `journal-replay` | `crates/storage/src/journal.rs` | ~24.8% |

Regenerate after harness or corpus changes; record material movements in
`docs/devlog.md`.

## Crash workflow

A `crash-*`/`oom-*`/`timeout-*` artifact under `artifacts/<target>/` is a
release blocker: reproduce with `cargo +nightly fuzz run <target>
artifacts/<target>/<file>`, reduce to a unit test, fix, then delete the
artifact. Bare SHA1-named files in `artifacts/` are stray corpus units
(libFuzzer writes interesting inputs to the first corpus dir) — they are
not crashes.
