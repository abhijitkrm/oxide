# Oxide Security Self-Review

**Date:** 2025-01-30
**Scope:** BLS aggregation, perps ADL/oracle/liquidation, mempool
replay protection, executor nonce enforcement, storage overflow,
state root tamper-proofing.
**Method:** Three parallel code reviews covering consensus, perps,
and mempool/executor/storage.

## Findings by severity

### CRITICAL

#### C1: Perps liquidation scale mismatch

**File:** `modules/perps/src/lib.rs:573-589`

`total_loss` is scale-14 (from `unrealized_pnl`), `margin_total` is
scale-6 (from `cross_margin` + `isolated_margin`). They are added
directly: `let net = margin_total + total_loss;`. This mixes scales
by 10^8, making every liquidation with a loss either wipe the
insurance fund or trigger ADL incorrectly.

**Status:** Fixed — convert `total_loss` to scale-6 before combining.

#### C2: Oracle TAG_SET_MARK bypasses deviation check

**File:** `modules/perps/src/lib.rs:908-919`

The `handle` method for `TAG_SET_MARK` directly inserts into
`inner.marks` without calling `set_mark_price`, bypassing the 10%
deviation guard. A single transaction can move the mark price by any
amount.

**Status:** Fixed — `handle` now calls `set_mark_price`.

#### C3: BLS vote malleability — phase not bound in signature

**File:** `crates/consensus/src/engine.rs:694-704`

Votes sign only `block_hash.as_bytes()` under `Domain::Vote`. The
`view`, `phase`, and `epoch` are not included in the signed message.
A Prepare vote signature can be replayed as a PreCommit or Commit
vote for the same block.

**Status:** Fixed — votes now sign `(view, phase, block_hash, epoch)`.

#### C4: `deliver_qc().expect()` panics on malformed QC

**File:** `crates/consensus/src/engine.rs:1218`

`step()` calls `self.deliver_qc(qc).expect("...")`. If `deliver_qc`
returns `Err` (e.g., `InvalidQcSignature`), the node panics. A
malformed self-formed QC crashes the node.

**Status:** Fixed — replaced with error logging.

### HIGH

#### H1: Perps `maintenance_margin` can overflow u128

**File:** `modules/perps/src/lib.rs:200`

`notional * mmr_rate` can exceed u128 when notional is near 2^127
and mmr_rate is up to 65535.

**Status:** Fixed — use saturating_mul.

#### H2: Perps `apply_funding` can overflow i128

**File:** `modules/perps/src/lib.rs:510`

`size * mark * rate` triple product can exceed i128 with unbounded
`rate` from the message body.

**Status:** Fixed — use checked_mul and reject on overflow.

#### H3: ADL rounding leaves dust

**File:** `modules/perps/src/lib.rs:712-745`

`close_qty` is computed via two integer floor divisions. The
debited `clawback` may not equal the realized PnL. For tiny
clawback, `close_qty` can be 0 (no-op).

**Status:** Fixed — compute close_qty from scale-14 and debit
realized amount.

#### H4: Mempool replay — no persistent executed-nonce tracking

**File:** `crates/mempool/src/lib.rs:211`

The mempool only rejects duplicates currently in the pool. Once a
tx is removed after block selection, the same bytes can be
re-submitted and re-executed. No per-account on-chain nonce gate.

**Status:** Documented — requires executor-level nonce enforcement
(scheduled for follow-up).

#### H5: Executor does not enforce nonce ordering

**File:** `crates/executor/src/lib.rs:792-916, 1075-1097`

`execute_block` and `process_proposal` do not validate per-account
nonce ordering. A byzantine proposer can reorder same-account txs.

**Status:** Documented — requires executor-level nonce map
(scheduled for follow-up).

#### H6: `aggregate().unwrap_or(ZERO)` masks failures

**File:** `crates/consensus/src/engine.rs:812, 1196`

Failed BLS aggregation is silently replaced with all-zero
aggregate, producing an invalid QC instead of propagating the error.

**Status:** Fixed — propagate errors with `?`.

### MEDIUM

#### M1: Timeout signatures don't bind epoch

**File:** `crates/consensus/src/engine.rs:1011-1012`

Timeout signatures sign only `view.to_le_bytes()`, not `(view,
epoch)`. A timeout for view v in epoch 0 can be replayed in epoch 1.

**Status:** Fixed — sign `(view, epoch)`.

#### M2: Mempool/executor/storage plain arithmetic overflow

**Files:** `crates/mempool/src/lib.rs:355,377,387`,
`crates/executor/src/lib.rs:750,1123,1137`,
`crates/storage/src/journal.rs:184,197,229,352`,
`crates/storage/src/mmr.rs:204,217,271,256,316`

Multiple plain `+`/`+=` on u64/usize that can wrap in release builds.

**Status:** Documented — scheduled for systematic sweep.

#### M3: Snapshot import trusts supplied module roots

**File:** `crates/executor/src/lib.rs:691-753`

`import_snapshot` verifies the aggregate root but does not recompute
individual module roots from imported KV data. A crafted snapshot
with arbitrary KV + matching roots is accepted.

**Status:** Documented — scheduled for follow-up.

#### M4: No per-block oracle rate limit

**File:** `modules/perps/src/lib.rs:870/930`

Even with the deviation check, there is no limit on the number of
oracle updates per block. Rapid 9.99% updates can achieve large
cumulative moves.

**Status:** Documented — scheduled for follow-up (per-block
cumulative cap or min-height interval).

## Summary

| Severity | Count | Fixed | Documented |
|----------|-------|-------|------------|
| Critical | 4     | 4     | 0          |
| High     | 6     | 3     | 3          |
| Medium   | 4     | 1     | 3          |
| **Total**| 14    | 8     | 6          |

The most critical finding is C1 (perps liquidation scale mismatch)
— this would have made the entire liquidation/insurance-fund/ADL
pipeline economically incorrect. C2 (oracle bypass) and C3 (BLS vote
malleability) are consensus-safety issues. C4 is a DoS vector.

The remaining documented issues (H4, H5, M2, M3, M4) require
broader refactoring and are scheduled for follow-up.
