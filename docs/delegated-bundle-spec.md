# Delegated bundles: cheap authentication on the chain path (spec, draft 25 Nov 2026)

Status: IMPLEMENTED and measured on the box (25 Nov): ~5M orders/s sustained for delegated bundles; see `docs/devlog.md`. Open: the per-item fee model. User decision (25 Nov): "trim bundles first then cheap-auth", after the box showed that
a single signed order costs ~30 us of secp256k1 recovery out of ~40 us end to end (~300k orders/s sustained on 12 cores) while
owner-signed bundles reach 9.1-9.4M orders/s. Builds on `docs/bundle-auth-spec.md` (section 3, "gateway-certified bundle") and the
exchange's `docs/lanes-spec.md` authentication seam.

## 1. Problem and why not a MAC

Every order from a different trader needs its own authenticated sender. The matcher service uses per-session MACs (4.8M/s per core),
but a MAC needs the verifier to hold the secret: on a chain every validator verifies, so any validator could forge any session's
orders. The chain path therefore needs an authentication that validators can check *without* being able to forge: a signature, or a
signature-backed delegation.

## 2. Design: delegate once, bundle many

1. **Delegate** (`TAG_DELEGATE`, 20). The owner signs an ordinary transaction (envelope sender = owner) naming an *agent* address
   (a gateway key), a scope and an expiry. One recovery, once.
2. **Delegated bundle** (`TAG_DBUNDLE`, 22). The agent signs ONE transaction whose payload is a list of items, each naming the
   `owner` it acts for. One recovery covers the whole bundle; each item is authorized by a table lookup.
3. **Revoke** (`TAG_REVOKE_DELEGATE`, 21). The owner removes an agent at any time.

The gateway authenticates its own users off-chain (sessions, MACs, certificates: `docs/lanes-spec.md` section 4), exactly as the
matcher service does today, and submits their orders as delegated bundles. Direct users keep signing their own orders.

### Messages

```
TAG_DELEGATE        [20][agent:20][flags:1][expiry_height:8 LE][max_item_notional:8 LE]   envelope sender = owner
TAG_REVOKE_DELEGATE [21][agent:20]                                                         envelope sender = owner
TAG_DBUNDLE         [22][count:u16 LE] then count x ( [owner:20][len:u16 LE][item] )      envelope sender = agent
```

`item` is exactly a bundle item: a `TAG_PLACE` or `TAG_CANCEL` message (amend is not allowed in a delegated bundle in this version).
`flags`: bit 0 = may place, bit 1 = may cancel. `expiry_height`: the delegation is valid while `current height < expiry_height`.
`max_item_notional`: largest `price x qty / PRICE_SCALE` of one placed order, in quote units (0 = unlimited).

### State

Delegations live in the exchange's committed key-value store (the same store that holds market configs and dispute records), key
`"dlg/" || owner || agent`, value `flags || expiry_height || max_item_notional` (17 bytes). The store is already folded into
the module state root and exported in snapshots, so there is **no state-format change**: roots are byte-identical while no
delegation exists, and snapshot sync carries delegations for free.

### Execution semantics

For each item of a delegated bundle, in order: look up `(owner, agent = envelope sender)`. An owner equal to the agent needs no
delegation (the agent trades its own account). Otherwise the item is **rejected** (reported as a `bundle_item_rejected` event with
the item index, the rest of the bundle still runs) when there is no delegation, it has expired, the flag for the item's kind is
missing, or a placed order exceeds `max_item_notional`. An authorized item runs exactly as if `owner` had signed it: the order
owner, reservations (the owner's ledger balance and base custody), self-trade checks and cancel authority are all the owner's.
The agent pays the envelope fee and the per-item gas; the agent's nonce is consumed once per bundle.

### Trust model (what delegation does and does not give an agent)

An agent can place and cancel orders for an owner *within the delegated scope*. It cannot withdraw, transfer or deposit: those
messages are not accepted from agents. It can still lose the owner's funds by trading badly or against its own counterparty, so
delegating to a gateway is a trust decision, like handing a broker an API key. `max_item_notional` and `expiry_height` bound the
damage per order and over time; revocation takes effect for every bundle in a later transaction. Choosing a gateway, and the
gateway's own audit and bonding, are deployment policy (`docs/lanes-spec.md` section 7.2).

## 3. Interaction with the exchange lanes

A delegated bundle debits the *owners'* balances, not the envelope sender's. The lane planner's funds proof therefore keys each
item's reservation by its owner (the fee stays with the agent), and delegated bundles are eligible for lanes. Delegate and revoke
transactions are not lane-eligible, so a run containing one takes the serial path: delegations never change inside a lane run, which
keeps the per-item authority checks exact.

## 4. Acceptance gates

1. **Equivalence:** a delegated bundle produces the same book, balances, fills and events (modulo the agent's fee and nonce) as the
   same items sent as separate owner-signed transactions (differential test, including cancels, rejects, cross-market items).
2. **Authority:** an item for an owner with no delegation, an expired or revoked one, a missing flag, or an oversize order is rejected
   and moves nothing; mutation check (drop the authority check: must fail).
3. **Funds:** owners are debited and the agent is not; the lane funds proof covers owners (unfunded owner: lane path declines and the
   serial path result is equal).
4. **Lanes:** delegated bundles equal serial execution under lanes (extends the multi-market lane differential).
5. **Performance (`chain_mix --mix dbundle`):** admission and sustained orders/s per signed order at 64 items per bundle, against
   single signed orders on the same host.
6. **Bounds:** the same size and count bounds as bundles are checked before any recovery.
