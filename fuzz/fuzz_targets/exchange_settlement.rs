#![no_main]
//! Fuzz target: exchange module settlement + custody accounting.
//!
//! The book-level target (`trading_engine`) proves the matcher core;
//! this one drives the *settlement* layer — the module's `handle()`
//! with fabricated `TxContext`s over a `MemoryBalances` ledger:
//! deposits/withdrawals (custody), book places/cancels (escrowed
//! orders), registered-order lifecycle, and operator batch-settle
//! legs consuming those registrations. Malformed raw messages are
//! mixed in to exercise parser rejection.
//!
//! ## The invariant
//!
//! **Money conservation, checked after every op.** Every native unit
//! must sit in exactly one bucket: a free ledger balance, a buy-side
//! quote escrow (resting bid or registered `reserved`), the per-market
//! `fee_vault`, or base custody backing (`base_balances`, `base_holds`,
//! or registered-sell `reserved`). A leak — an unrefunded reservation,
//! a fill that mints, a cancel that double-releases — breaks the
//! equation immediately.
//!
//! ## Input layout
//!
//! - Byte 0: owner count (2/4/8) — small sets force self-trades and
//!   repeated-key collisions.
//! - Byte 1: market config variant (two listed markets, one fixed
//!   plus one derived).
//! - Bytes 2..: 24-byte ops. `chunk[0] % 8` picks the op: place,
//!   cancel, deposit, withdraw, register, cancel-registered,
//!   batch-settle, or raw-malformed (the chunk verbatim as msg).

use std::sync::Arc;

use exchange::{BatchFillEntry, ExchangeModule, OrderKey, msg};
use executor::{Module, TxContext};
use framework::{Balances, MemoryBalances};
use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::{NewOrder, OrderId, OrderType, Side, StpMode, TimeInForce};

/// The fixed settlement operator — batch-settle txs must come from
/// this address (they do; the fuzzer also probes wrong-sender legs).
const OPERATOR: Address = Address([0xFE; 20]);

/// Per-owner mint — comfortably above anything a fuzz op can reserve.
const MINT: u64 = 1_000_000_000_000_000;

/// Two fixture market geometries: tight and wide.
const CONFIGS: [trading::MarketConfig; 2] = [
    trading::MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(1_064_000_000),
        max_resting: 64,
    },
    trading::MarketConfig {
        market_id: 0,
        tick_size: Price(1_000),
        lot_size: Qty(1),
        min_price: Price(10_000_000),
        max_price: Price(10_128_000),
        max_resting: 128,
    },
];

/// Read a little-endian u64 out of `chunk` starting at `off`
/// (clamped so short tails still decode — a truncated tail is just
/// another input, never a panic).
fn u64_at(chunk: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    let n = chunk.len().saturating_sub(off).min(8);
    b[..n].copy_from_slice(&chunk[off..off + n]);
    u64::from_le_bytes(b)
}

/// Assert money conservation: `minted == Σ ledger + Σ module buckets`.
fn assert_conservation(
    ex: &ExchangeModule,
    ledger: &MemoryBalances,
    owners: &[Address],
    market_ids: &[u8],
    minted: u128,
) {
    let mut total = 0u128;
    // Free quote: every tracked account's ledger balance. (The
    // operator is included — it must never accrue funds.)
    for o in owners.iter().chain(std::iter::once(&OPERATOR)) {
        total += u128::from(ledger.balance(o));
    }
    for &m in market_ids {
        total += u128::from(ex.fee_vault(m));
        total += u128::from(ex.escrowed_quote(m));
        total += u128::from(ex.escrowed_base(m));
        for o in owners {
            total += u128::from(ex.base_balance(*o, m).0);
            total += u128::from(ex.base_hold(*o, m).0);
        }
    }
    assert_eq!(total, minted, "money conservation broke");
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let owner_count = [2usize, 4, 8][(data[0] % 3) as usize];
    let owners: Vec<Address> = (0..owner_count).map(|i| Address([i as u8 + 1; 20])).collect();

    let ledger = Arc::new(MemoryBalances::new());
    for o in &owners {
        ledger.mint(o, MINT);
    }
    let minted = u128::from(MINT) * owner_count as u128;

    let ex = ExchangeModule::with_ledger(ledger.clone())
        .with_settlement_operator(OPERATOR);
    // Two markets: the fixed tight band plus the wide-band variant —
    // different tick/lot geometry exercises scale conversions.
    let mut market_ids = Vec::new();
    let mut cfg0 = CONFIGS[0];
    cfg0.market_id = 0;
    if let Ok(id) = ex.list_market(cfg0) {
        market_ids.push(id);
    }
    let mut cfg1 = CONFIGS[(data[1] % 2) as usize];
    cfg1.market_id = 0; // assigned slot is whatever list_market returns
    if let Ok(id) = ex.list_market(cfg1) {
        market_ids.push(id);
    }
    if market_ids.is_empty() {
        return;
    }

    // Registered-order keys the fuzzer has observed (for batch-settle
    // legs) — entries may be consumed/canceled; stale keys exercise
    // rejection.
    let mut reg_keys: Vec<OrderKey> = Vec::new();
    // Book order ids are sequential per market — raw ids in
    // [0, issued) hit live and dead orders alike.
    let mut issued_ids: u64 = 0;

    for chunk in data[2..].chunks(24) {
        if chunk.len() < 24 {
            break;
        }
        let owner = owners[(chunk[1] as usize) % owners.len()];
        let market = market_ids[(chunk[2] as usize) % market_ids.len()];
        let ctx = TxContext { sender: owner, nonce: u64_at(chunk, 16), fee: 0 };
        let op = chunk[0] % 8;

        let msg: Vec<u8> = match op {
            // Place: book order — loosely validated fields.
            0 => {
                let side = if chunk[2] & 1 == 0 { Side::Buy } else { Side::Sell };
                let band = CONFIGS[(market as usize) % 2].min_price.0;
                let price = band + (u64_at(chunk, 3) % 200) * 1_000;
                let qty = (u64_at(chunk, 11) % 1_000_000).max(1);
                let order = NewOrder {
                    side,
                    order_type: match (chunk[3] >> 4) % 3 {
                        0 => OrderType::Limit,
                        1 => OrderType::Market,
                        _ => OrderType::PostOnly,
                    },
                    tif: match (chunk[3] >> 6) % 3 {
                        0 => TimeInForce::Gtc,
                        1 => TimeInForce::Ioc,
                        _ => TimeInForce::Fok,
                    },
                    price: Price(price),
                    qty: Qty(qty),
                    owner,
                    stp: match chunk[19] % 4 {
                        0 => StpMode::None,
                        1 => StpMode::CancelNewest,
                        2 => StpMode::CancelOldest,
                        _ => StpMode::DecrementAndCancel,
                    },
                };
                issued_ids += 1;
                msg::place(market, order)
            }
            // Cancel: raw id space — hits live and dead ids.
            1 => msg::cancel(market, OrderId(u64_at(chunk, 3) % (issued_ids.max(1) + 8))),
            // Deposit into base custody.
            2 => msg::deposit_base(market, u64_at(chunk, 3) % 1_000_000_000),
            // Withdraw free custody.
            3 => msg::withdraw_base(market, u64_at(chunk, 3) % 1_000_000_000),
            // Register an order (small client-id space → dup rejects).
            4 => {
                let side = if chunk[2] & 1 == 0 { Side::Buy } else { Side::Sell };
                let key = OrderKey { owner, client_id: u64_at(chunk, 18) % 8 };
                reg_keys.push(key);
                if reg_keys.len() > 128 {
                    reg_keys.drain(..64);
                }
                let band = CONFIGS[(market as usize) % 2].min_price.0;
                msg::register_order(
                    u16::from(market),
                    side,
                    band + (u64_at(chunk, 3) % 200) * 1_000,
                    (u64_at(chunk, 11) % 1_000_000).max(1),
                    key.client_id,
                )
            }
            // Cancel a registered order (sender-scoped).
            5 => msg::cancel_registered(u64_at(chunk, 3) % 8),
            // Batch settle: 1-3 legs over known/fabricated keys, sent
            // as the operator (or a wrong sender ~1/4 of the time).
            6 => {
                let leg_count = 1 + (chunk[19] % 3) as usize;
                let mut fills = Vec::new();
                for l in 0..leg_count {
                    let pick = |off: usize, salt: u64| -> OrderKey {
                        if reg_keys.is_empty() || (u64_at(chunk, off) ^ salt) % 3 == 0 {
                            OrderKey {
                                owner: owners[((u64_at(chunk, off) ^ salt) as usize)
                                    % owners.len()],
                                client_id: (u64_at(chunk, off) ^ salt) % 8,
                            }
                        } else {
                            reg_keys[((u64_at(chunk, off) ^ salt) as usize) % reg_keys.len()]
                        }
                    };
                    fills.push(BatchFillEntry {
                        market: u16::from(market),
                        price: Price(
                            CONFIGS[(market as usize) % 2].min_price.0
                                + (u64_at(chunk, 3 + l) % 200) * 1_000,
                        ),
                        qty: Qty((u64_at(chunk, 11 + l) % 1_000_000).max(1)),
                        buy: pick(4, 0xB0),
                        sell: pick(12, 0x5E),
                    });
                }
                // ~1/4 of settles come from a non-operator sender.
                let actx = if chunk[20] % 4 == 0 {
                    TxContext { sender: owner, nonce: 0, fee: 0 }
                } else {
                    TxContext { sender: OPERATOR, nonce: 0, fee: 0 }
                };
                let _ = ex.handle(&actx, &msg::batch_settle(&fills));
                assert_conservation(&ex, &ledger, &owners, &market_ids, minted);
                continue;
            }
            // Raw malformed: the chunk verbatim as the message.
            _ => chunk.to_vec(),
        };

        let _ = ex.handle(&ctx, &msg);
        assert_conservation(&ex, &ledger, &owners, &market_ids, minted);
    }
});
