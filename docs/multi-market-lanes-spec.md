# Per-market parallel execution of the exchange (spec, draft 25 Nov 2026)

Status: IMPLEMENTED and measured on the box (25 Nov): bundle mix 2.5M -> 5.8M orders/s at 12 markets, roots identical lanes on/off;
see `docs/devlog.md`. Single-order transactions gain nothing (signature-bound). User decision (25 Nov): "we have 12 cores, we are not running
parallel matching?" then "yes" to building it. This is the chain-path counterpart of the EVM sender lanes
(`docs/multi-lane-evm-spec.md`).

## 1. Why

Measured on the Ryzen 9 7900 box (`docs/devlog.md`, 25 Nov): the standalone engine does 103M orders/s at 8 shards and 144M at
12 (74 ns per order, no auth, nothing shared), but the chain path does ~1.6-2.3M orders/s in the bundle mix: every exchange
transaction runs on the single exec lane. Profile of that lane (bundle mix, exec-lane samples only): 82% of its time is the
exchange `handle`; the engine's `place` is ~24% of that, the rest is bookkeeping around it (ledger moves, settlement apply,
custody maps, the resting-book fold hash). Orders on different markets do not interact, so they can execute on different cores.

## 2. What is shared between markets (and what is not)

A book-path order (`place`, `cancel`, and bundles of them) touches:

| State | Keyed by | Cross-market? |
|---|---|---|
| matching engine (book, order ids, STP) | market | no |
| free base custody, resting-sell holds | `(owner, market)` | no |
| protocol fee vault | market | no |
| native ledger (quote debit/credit) | account | **yes**: one account trades several markets |
| events | tx order | assembled back in canonical order |

So the only coupling is the native ledger: debits (buy reservations, envelope fees) and credits (fill proceeds, refunds).

## 3. Design

For a contiguous exchange run that is eligible, partition transactions by market (union-find over the markets one bundle
touches), give each lane its markets' engines, and run each lane's transactions in canonical sub-order on a rayon task. The
order logic is the *same code* as the serial path: `place_core`/`cancel_core` over the `BookView` trait (serial backend: the
live committed maps; lane backend: a private overlay plus ledger deltas), so the two paths cannot drift.

### Exactness: why parallel equals serial

Every serial effect on a lane's state is a function of that lane's own transactions in canonical order, except one: whether a
ledger **debit succeeds**. A debit's outcome depends on the account's balance at that instant, which other lanes' credits and
debits move. Credits only add, and debits commute with each other, *provided none fails*. So the run is eligible only if no
debit can fail in any interleaving:

> For every sender S: balance(S) at run start >= sum over the run of S's fees + S's buy reservations (price x qty per limit buy
> item). Credits received during the run are ignored (conservative).

Under this precondition every ledger operation commutes, so applying the lanes' net per-account deltas after the run equals
the serial result. Fees are charged before the lanes run (they cannot fail, by the same precondition).

### Preconditions (any failure: the whole run takes the serial path, nothing touched)

1. Ledger wired; run is large enough to pay for the fork (`LANE_MIN_ORDERS`).
2. Every transaction is `place` (not a market buy: its reservation depends on the book), `cancel`, or a bundle of those.
   Malformed transactions are allowed (they touch no state).
3. The sufficiency condition above.
4. At least two independent market components (otherwise there is nothing to parallelize).

### Merge (single pass, only touched keys)

Engines go back; each lane's overlay entries are inserted into the committed maps (keys are disjoint across lanes because the
market is part of every key); per-account ledger deltas are applied as one credit or debit; events are placed back at their
transaction index.

## 4. Acceptance gates

1. **Differential:** random multi-market streams (limit/IOC/post-only variants, cancels, bundles, cross-market bundles, STP,
   rejects, unfunded accounts, accounts trading several markets) through the serial path and the lane path: per-transaction
   results and events, `state_root`, every account's ledger balance, custody maps and fee vaults must be byte-equal.
2. **Mutation check:** drop the sufficiency check; the unfunded-multi-market case must fail the differential.
3. **Fallback:** amend, market buys, unfunded senders and single-market runs take the serial path and are equal.
4. **Performance (`chain_mix --markets N`):** exec-stage us per order with lanes on vs off at 12 threads on the box, interleaved,
   spread reported. Claim to falsify: dispatch scales >= 2x from 1 to 4 markets.
