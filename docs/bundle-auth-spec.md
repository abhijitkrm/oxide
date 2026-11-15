# Bundle authentication on the chain path (spec, draft 15 Nov 2026)

Status: DRAFT, not implemented. Plan W2 of `docs/hft-production-plan.md`. Decision recorded 15 Nov: individually signed
("retail") traffic is under 5% of load, so the verify budget is sized for bundle, session and gateway traffic.

## 1. Problem

Measured on the laptop (8 ingest threads, signed transactions through the real executor): admission is bound by one
secp256k1 recovery per transaction, ~145-155k tx/s, while the executor now sustains 240k (CLOB at 100k accounts) to
350k (CLOB at 1k accounts) tx/s behind it. At the 10M target one signature per order is 430+ cores (the reference
stack's number for ed25519; ours is worse). The matcher service already has cheap schemes (`docs/lanes-spec.md`:
session MAC 4.8M/s, gateway certificate 1.9M/s) but the chain path (`Executor::ingest_tx`, EIP-712 v1 envelope) accepts
only a per-transaction secp256k1 signature.

## 2. Design: one signature, many orders

A **bundle transaction** is an ordinary v1 envelope whose module id carries a new flag and whose payload is a list of
exchange messages. The envelope's single signature (secp256k1 EIP-712, unchanged) authenticates the whole list:

```
[sender 20][nonce 8][fee 8][module_id | 0x80 (signed) | 0x40 (bundle)][sig 64][recid 1][payload]
payload = [count u16][ item_i = [len u16][exchange message] ]...
```

- **Signed content:** the EIP-712 `payload` hash covers the bundle bytes, so every item is covered by the one signature.
- **Authority:** all items act for the envelope sender (the signer). Items for other accounts are refused. Sub-accounts
  and agents already exist in the exchange module (`TAG_LINK_TRADING_KEY`, linked accounts): a bundle may carry items for
  accounts the sender is *linked* to, checked per item against the module's link table.
- **Nonce and fee:** one envelope nonce is consumed per bundle; one envelope fee covers the bundle plus a per-item
  protocol fee charged by the exchange (so a bundle cannot be cheaper than the sum of its work). Gas estimate =
  `base + sum(item gas)`; counted against the block gas limit as today.
- **Execution:** items execute in order inside one `handle` call. Failure is per item (a rejected order does not abort
  the bundle), reported in the events; a malformed bundle (bad count/lengths) fails whole and consumes the nonce and
  fee like any rejected tx. Per-item replay protection is the exchange's own order-id / client-id rules.
- **Bounds (DoS):** `MAX_BUNDLE_ITEMS` (proposed 1,024) and `MAX_BUNDLE_BYTES` (proposed 128 KiB), checked before the
  signature is recovered (cheapest reject first).

Cost: one recovery (~50 us) per bundle: 64 items = 0.8 us/item, 1,024 items = 0.05 us/item. At 10M items/s with
1,024-item bundles that is ~10k recoveries/s, about 0.5 core.

## 3. Variants considered

| Scheme | Who signs | Trust | When |
|---|---|---|---|
| Owner-signed bundle (this spec) | the trader / market maker | none beyond today | market makers, algos: one account, many orders |
| Gateway-certified bundle | a gateway for many accounts (already in `lanes`: `Certified`) | gateway can forge for its sessions; audited sample, slashing hook | retail aggregation; separate spec step since it needs validator-side audit and gateway registry on chain |
| Session MAC | per-session key | scoped session, revocable | matcher service today; chain path needs session registry in state |
| Aggregate signatures (BLS) | many traders, one aggregate | none | stretch (100M), needs new key type |

Recommendation: owner-signed bundle first (smallest consensus surface: one new envelope flag and one module `handle`
variant), then gateway-certified bundles reusing the `lanes` audit and slashing hooks.

## 4. Acceptance gates

1. Equivalence: a bundle of N orders produces the same book, balances and fills as the same N orders as N separate
   transactions with consecutive nonces (property test over generated streams, including rejects and cancels).
2. Mutation: flipping any bundle byte (count, length, item) after signing is rejected at admission (signature) and,
   if the signature is recomputed, still cannot spend another account's funds (authority check).
3. Bounds: oversize/zero-count/truncated bundles are rejected before signature recovery (fuzz target for the decoder).
4. Performance (`chain_mix --mix bundle`): admission >= 10x per-order admission at 64 items/bundle on the same host; the
   `stages,` line shows plan us per item falling accordingly.
5. Replay/journal: a bundle round-trips the journal and replays to the same root (existing replay drills).

## 5. Rollout

Flag-gated activation height in genesis/upgrade (the envelope flag is rejected before activation); wallet/SDK change;
docs and `oxide-loadgen --scheme bundle`. No change to blocks, consensus or state format beyond the new envelope kind.
