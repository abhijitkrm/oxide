# Amend-order specification (exchange + perps)

Status: implemented (`trading::MatchingEngine::amend`, `exchange` tag 15,
`perps` tag 8). Wire change: one new tag per module; no state-format change
and no change to any existing state root.

## Message

`[tag][market:1][order_id:8 LE][price:8 LE][qty:8 LE][stp:1]` — body 26 bytes.
`price` is scale-8, `qty` scale-6 (as in place). `stp` is the place encoding
(0 none, 1 cancel-newest, 2 cancel-oldest, 3 decrement-and-cancel). The tx
sender must own the order. Tags: exchange `15`, perps `8`.

## Semantics

An amend is **cancel-then-place with one atomic admission and the same order
id**:

1. *Same price and `qty <= remaining`:* the order is resized in place and
   **keeps its queue position**. (`qty == remaining` is a no-op.)
2. *Otherwise (price change or size increase):* the order loses priority. It
   leaves its queue, crosses the opposite side at the new price exactly like
   an incoming GTC limit order with the given `stp`, and any remainder rests at
   the **back** of its new level. Fills are produced and settled as for a
   taker. The id is preserved.
3. Side, owner and TIF (GTC) never change. A reduce-only perps order stays
   reduce-only.
4. `price`/`qty` must satisfy the market's tick, lot and band rules; otherwise
   the amend is rejected and **nothing changes**.
5. If self-trade prevention cancels the re-crossing order, the order is gone
   (`canceled_remainder`), fills booked so far stand.

## Atomicity rule (C6)

Every check that can fail — ownership, market rules, funds / base custody,
initial margin, reduce-only cover — runs **before** any ledger, custody,
margin or book mutation. After the engine call nothing may fail (the engine
lives in module memory and is not rolled back by the executor).

## Exchange accounting

Escrow is netted, not released-then-retaken:

- *Buy:* old hold `⌊old_price × old_qty / SCALE⌋` of quote is already debited.
  New requirement `⌊new_price × new_qty / SCALE⌋`. The difference is debited
  (reject on insufficient funds) or credited. The new requirement is then the
  taker `reservation`; `BookSettlement::apply` settles fills at maker prices,
  keeps `⌊price × resting_qty / SCALE⌋` held for the remainder and refunds the
  rest — identical to a place.
- *Sell:* `min(base_holds, old_qty)` returns to free custody, then the new
  `qty` leaves free custody as the taker base. Rejected if `free + released <
  new_qty`.
- Events: fills, then `amended [market][id][price][qty]` when the order still
  rests, else the place outcome event (`filled`, `canceled_remainder`), then
  STP removal events.

## Perps accounting

The initial-margin gate runs with the order's old reservation treated as
released (`initial_margin_gate(.., skip = Some(id))`), then the old
`open_orders` entry is dropped, the order re-crosses (reduce-only cap
applies), fills apply to positions, and the new remainder's reservation is
recorded. Post-trade margin checks cover the amender and every maker, in
first-fill order, as for a place. Event: `amended [market][id][price][qty]`.

## Verification

- `trading`: `amend_matches_cancel_place_model` (random stream vs cancel +
  place, fold == recompute after every op), corpus digest identical to
  matcher-rust.
- `exchange`: unit tests for each branch, plus `amend_conserves_value_over_random_ops`
  (quote and base conserved, book never crossed, all STP modes).
- `perps`: unit tests, plus `amend_matches_cancel_then_place_on_margin_and_positions`
  (books, margin and positions identical to the path amend replaces).
