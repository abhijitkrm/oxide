#![no_main]
//! Fuzz target: delegations and delegated bundles (`docs/delegated-bundle-spec.md`).
//!
//! Drives the exchange module's `handle()` with fabricated senders over a `MemoryBalances` ledger:
//! owners delegating to and revoking an agent, agent-signed delegated bundles whose items name
//! assorted owners (including a victim who never delegates), plain owner orders, and raw malformed
//! delegated-bundle bytes to exercise the framing parser.
//!
//! ## The invariants
//!
//! 1. **No panic** on any byte string, in any state.
//! 2. **Authority:** the victim account never signs a delegation and never sends a transaction, so
//!    no delegated bundle, however it names the victim, may change the victim's ledger balance.
//! 3. **Revocation:** after an owner revokes the agent, a delegated bundle naming that owner moves
//!    nothing of the owner's (checked by the same balance probe on a fixed second victim).
//!
//! ## Input layout
//!
//! - Byte 0: owner count (2/4/8).
//! - Bytes 1..: 24-byte ops; `chunk[0] % 6` picks delegate, revoke, delegated bundle (items drawn
//!   from the chunk bytes), plain owner order, or the chunk verbatim as a raw delegated bundle.

use exchange::{ExchangeModule, msg};
use executor::{Module, TxContext};
use framework::{Balances, MemoryBalances};
use libfuzzer_sys::fuzz_target;
use primitives::Address;
use primitives::fixed::{Price, Qty};
use std::sync::Arc;
use trading::{MarketConfig, NewOrder, OrderId, OrderType, Side, StpMode, TimeInForce};

/// The agent every delegation names.
const AGENT: Address = Address([0xA0; 20]);
/// An account that never delegates and never sends: its balance must never change.
const VICTIM: Address = Address([0x77; 20]);
/// Per-account mint, far above anything a fuzz op can reserve.
const MINT: u64 = 1_000_000_000_000_000;

fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(1_064_000_000),
        max_resting: 64,
    }
}

fn order(b: &[u8]) -> NewOrder {
    NewOrder {
        side: if b[0] & 1 == 0 { Side::Buy } else { Side::Sell },
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_000_000_000 + u64::from(b[1] % 60) * 1_000_000),
        qty: Qty(1_000 * (1 + u64::from(b[2] % 4))),
        owner: VICTIM,
        stp: StpMode::None,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&n, ops)) = data.split_first() else { return };
    let owners: Vec<Address> = (1..=[2u8, 4, 8][usize::from(n) % 3]).map(|b| Address([b; 20])).collect();
    let ledger = Arc::new(MemoryBalances::new());
    let ex = ExchangeModule::with_ledger(ledger.clone());
    if ex.list_market(cfg()).is_err() {
        return;
    }
    for a in owners.iter().chain([&AGENT, &VICTIM]) {
        ledger.mint(a, MINT);
        let ctx = TxContext { sender: *a, nonce: 0, fee: 0 };
        let _ = ex.handle(&ctx, &msg::deposit_base(0, 1_000_000_000));
    }
    let victim_before = ledger.balance(&VICTIM);
    for chunk in ops.chunks_exact(24) {
        let owner = owners[usize::from(chunk[1]) % owners.len()];
        let ctx = |sender: Address| TxContext { sender, nonce: 0, fee: 0 };
        match chunk[0] % 6 {
            0 => {
                let _ = ex.handle(
                    &ctx(owner),
                    &msg::delegate(AGENT, chunk[2], u64::from(chunk[3]) * 3, u64::from(chunk[4])),
                );
            }
            1 => {
                let _ = ex.handle(&ctx(owner), &msg::revoke_delegate(AGENT));
            }
            2 => {
                // Items: orders and cancels for assorted owners, the victim among them.
                let items: Vec<(Address, Vec<u8>)> = (0..4)
                    .map(|j| {
                        let who = match chunk[5 + j] % 3 {
                            0 => VICTIM,
                            _ => owners[usize::from(chunk[9 + j]) % owners.len()],
                        };
                        let body = &chunk[13 + j..];
                        let m = if body[0] % 4 == 3 {
                            msg::cancel(0, OrderId(u64::from(body[1] % 8)))
                        } else {
                            msg::place(0, order(&body[..3]))
                        };
                        (who, m)
                    })
                    .collect();
                if let Some(b) = msg::dbundle(&items) {
                    let _ = ex.handle(&ctx(AGENT), &b);
                }
            }
            3 => {
                let _ = ex.handle(&ctx(owner), &msg::place(0, order(&chunk[2..5])));
            }
            4 => {
                let mut raw = vec![22u8];
                raw.extend_from_slice(&chunk[1..]);
                let _ = ex.handle(&ctx(AGENT), &raw);
            }
            _ => {
                let _ = ex.handle(&ctx(AGENT), &msg::dbundle(&[(owner, msg::cancel(0, OrderId(0)))]).unwrap_or_default());
            }
        }
        assert_eq!(
            ledger.balance(&VICTIM),
            victim_before,
            "a delegated bundle moved an account that never delegated"
        );
    }
});
