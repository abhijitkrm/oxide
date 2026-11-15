//! Admission cost per authentication scheme, measured through the
//! matcher's own [`matcher::auth::Authenticator`] implementations.
//!
//! Each scheme authenticates the same-shaped batches (default 1024
//! orders) from many accounts; the output is orders/s on one thread
//! (and on `--threads` for EVM recovery), the number the target-to-cores
//! table needs for the matcher's ingress.
//!
//! Output CSV: `scheme,threads,orders_per_s,ns_per_order`.
//! Gate: informational.
//!
//! Usage: `cargo bench -p matcher --bench auth -- [--secs S] [--batch N] [--threads 1,4]`

#![allow(
    missing_docs,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::time::{Duration, Instant};

use matcher::auth::{
    Authenticator, Certified, Ed25519Batch, Ed25519PerItem, EvmRecover, MarketScope, Multi,
    Schemes, SessionMac, SessionOpen, certify, sign_order_evm, sign_order_session,
};
use matcher::protocol::{CHAIN_ID, OrderRequest, sign_order};
use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::{OrderType, Side, TimeInForce};

const ACCOUNTS: usize = 64;

fn blank(nonce: u64) -> OrderRequest {
    OrderRequest {
        market: 0,
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce,
        owner: Address([0; 20]),
        pubkey: [0; 32],
        signature: [0; 64],
    }
}

fn rate(secs: f64, batch: &[OrderRequest], mut f: impl FnMut(&[OrderRequest])) -> f64 {
    f(batch); // warm
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs_f64(secs);
    let mut n = 0u64;
    while Instant::now() < deadline {
        f(batch);
        n += batch.len() as u64;
    }
    n as f64 / t0.elapsed().as_secs_f64()
}

fn row(scheme: &str, threads: usize, r: f64) {
    println!("{scheme},{threads},{r:.0},{:.1}", 1e9 / r * threads as f64);
}

fn main() {
    let mut secs = 2.0f64;
    let mut batch_n = 1024usize;
    let mut threads = vec![1usize, 4];
    let a: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < a.len() {
        let v = a.get(i + 1);
        match a[i].as_str() {
            "--secs" => secs = v.and_then(|v| v.parse().ok()).unwrap_or(secs),
            "--batch" => batch_n = v.and_then(|v| v.parse().ok()).unwrap_or(batch_n),
            "--threads" => {
                if let Some(v) = v {
                    threads = v.split(',').filter_map(|t| t.parse().ok()).collect();
                }
            }
            _ => {
                i += 1;
                continue;
            }
        }
        i += 2;
    }

    let eds: Vec<_> = (0..ACCOUNTS).map(|i| matcher_key(i as u8)).collect();
    let ed_batch: Vec<OrderRequest> = (0..batch_n)
        .map(|n| {
            let mut r = blank(n as u64 + 1);
            sign_order(&mut r, &eds[n % ACCOUNTS]);
            r
        })
        .collect();
    let evm_batch: Vec<OrderRequest> = (0..batch_n)
        .map(|n| {
            let mut r = blank(n as u64 + 1);
            let mut k = [1u8; 32];
            k[1] = (n % ACCOUNTS) as u8 + 1;
            sign_order_evm(&mut r, &k, CHAIN_ID);
            r
        })
        .collect();

    // Session MAC: one session per account.
    let mac = SessionMac::default();
    let key = [7u8; 32];
    let sessions: Vec<u32> = eds
        .iter()
        .map(|sk| {
            mac.open_session(
                &SessionOpen::sign_ed25519(sk, key, MarketScope::all(), CHAIN_ID),
                CHAIN_ID,
            )
            .expect("open")
        })
        .collect();
    let mac_batch: Vec<OrderRequest> = (0..batch_n)
        .map(|n| {
            let mut r = blank(n as u64 + 1);
            r.owner = crypto::ed25519::owner_address(&eds[n % ACCOUNTS].verifying_key());
            sign_order_session(&mut r, sessions[n % ACCOUNTS], &key, CHAIN_ID);
            r
        })
        .collect();

    // Gateway certificate over the ed25519 batch, audited 1 in 64.
    let gw = matcher_key(200);
    let cert_auth = Certified::new(vec![gw.verifying_key().to_bytes()], 64, Box::new(Ed25519Batch));
    let cert = certify(&gw, &ed_batch, CHAIN_ID);

    println!("scheme,threads,orders_per_s,ns_per_order_per_thread");
    row(
        "ed25519_per_item",
        1,
        rate(secs, &ed_batch, |b| {
            std::hint::black_box(Ed25519PerItem.orders(b, CHAIN_ID));
        }),
    );
    row(
        "ed25519_batch",
        1,
        rate(secs, &ed_batch, |b| {
            std::hint::black_box(Ed25519Batch.orders(b, CHAIN_ID));
        }),
    );
    for &t in &threads {
        let evm = EvmRecover { threads: t };
        row(
            "evm_recover",
            t,
            rate(secs, &evm_batch, |b| {
                std::hint::black_box(evm.orders(b, CHAIN_ID));
            }),
        );
    }
    row(
        "session_mac",
        1,
        rate(secs, &mac_batch, |b| {
            std::hint::black_box(mac.orders(b, CHAIN_ID));
        }),
    );
    row(
        "certified_audit64",
        1,
        rate(secs, &ed_batch, |b| {
            std::hint::black_box(cert_auth.certified_orders(b, &cert, CHAIN_ID));
        }),
    );
    // Mixed traffic through Multi: a third each of ed25519, EVM and MAC.
    let multi = Multi::new(Schemes::all(), 1, None);
    let key2 = [8u8; 32];
    let sessions2: Vec<u32> = eds
        .iter()
        .map(|sk| {
            multi
                .open_session(
                    &SessionOpen::sign_ed25519(sk, key2, MarketScope::all(), CHAIN_ID),
                    CHAIN_ID,
                )
                .expect("open")
        })
        .collect();
    let mixed: Vec<OrderRequest> = (0..batch_n)
        .map(|n| match n % 3 {
            0 => ed_batch[n],
            1 => evm_batch[n],
            _ => {
                let mut r = blank(n as u64 + 1);
                r.owner = crypto::ed25519::owner_address(&eds[n % ACCOUNTS].verifying_key());
                sign_order_session(&mut r, sessions2[n % ACCOUNTS], &key2, CHAIN_ID);
                r
            }
        })
        .collect();
    row(
        "multi_mixed_thirds",
        1,
        rate(secs, &mixed, |b| {
            std::hint::black_box(multi.orders(b, CHAIN_ID));
        }),
    );
}

fn matcher_key(seed: u8) -> crypto::ed25519::Ed25519SecretKey {
    crypto::ed25519::Ed25519SecretKey::from_bytes(&[seed.wrapping_add(1); 32])
}
