//! Real-service shard scaling: the production `MultiMarketMatcher` (one worker
//! thread per market) driven by one submitter thread per market, with the
//! command journal off, queued or durable and a chosen authentication scheme.
//!
//! This is the number the lane prototype cannot give: it includes the real
//! admission path (authentication, the shared replay gate, balance
//! reservation, risk checks), the per-market worker, the settlement buffer
//! and, optionally, the journal's group-commit fsync. Orders are built and
//! authenticated before the clock starts; each submitter calls
//! `submit_batch` directly (no TCP), so the figure is the service core's.
//!
//! Output CSV: `markets,journal,auth,orders,seconds,orders_per_s,per_market_per_s,rejects`.
//! Gate: informational.
//!
//! ```sh
//! cargo bench -p matcher --bench shards -- \
//!     [--markets 1,2,4,8] [--journal off,queued,durable] [--auth session_mac|ed25519_batch|evm] \
//!     [--orders 200000] [--batch 500] [--sub 1,4,16] [--dir /path/on/the/disk/under/test]
//!
//! `--sub N` runs N submitter threads per market (each owns a disjoint set of
//! accounts, so per-account nonces stay ordered). With a durable journal each
//! batch waits for an fsync, so more concurrent submitters let group commit
//! amortize it: durable throughput is roughly submitters x batch / fsync latency.
//! ```

#![allow(
    missing_docs,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use std::sync::{Arc, Barrier};
use std::time::Instant;

use crypto::ed25519::{Ed25519SecretKey, owner_address};
use matcher::auth::{
    AuthConfig, AuthKind, MarketScope, SessionOpen, sign_order_evm, sign_order_session,
};
use matcher::cmdlog::{AckPolicy, JournalConfig};
use matcher::protocol::{CHAIN_ID, OrderRequest, sign_order};
use matcher::{AtomicBalanceCache, MultiMarketMatcher, RiskConfig};
use primitives::Address;
use primitives::fixed::{Price, Qty};
use trading::{MarketConfig, OrderType, Side, TimeInForce};

/// Accounts per market. Disjoint across markets so each market's nonce
/// streams are independent (the replay gate is still one shared lock).
const ACCOUNTS: usize = 64;

fn ed(seed: usize) -> Ed25519SecretKey {
    let mut k = [7u8; 32];
    k[..8].copy_from_slice(&(seed as u64).to_le_bytes());
    Ed25519SecretKey::from_bytes(&k)
}

fn evm_key(seed: usize) -> [u8; 32] {
    let mut k = [3u8; 32];
    k[1..9].copy_from_slice(&(seed as u64 + 1).to_le_bytes());
    k
}

fn market_cfg(id: usize) -> MarketConfig {
    MarketConfig {
        market_id: id as u16,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 16,
    }
}

fn blank(market: usize, i: usize) -> OrderRequest {
    OrderRequest {
        market: market as u8,
        side: if i.is_multiple_of(2) { Side::Sell } else { Side::Buy },
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_500_000_000),
        qty: Qty(1_000),
        nonce: (i / ACCOUNTS) as u64 + 1,
        owner: Address([0; 20]),
        pubkey: [0; 32],
        signature: [0; 64],
    }
}

struct Args {
    markets: Vec<usize>,
    journals: Vec<String>,
    auth: String,
    orders: usize,
    batch: usize,
    subs: Vec<usize>,
    dir: std::path::PathBuf,
}

fn parse() -> Args {
    let mut a = Args {
        markets: vec![1, 2, 4, 8],
        journals: vec!["off".into(), "queued".into(), "durable".into()],
        auth: "session_mac".into(),
        orders: 200_000,
        batch: 500,
        subs: vec![1],
        dir: std::env::temp_dir().join(format!("oxide-shards-{}", std::process::id())),
    };
    let v: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < v.len() {
        let val = v.get(i + 1);
        match v[i].as_str() {
            "--markets" => {
                if let Some(x) = val {
                    a.markets = x.split(',').filter_map(|t| t.parse().ok()).collect();
                }
            }
            "--journal" => {
                if let Some(x) = val {
                    a.journals = x.split(',').map(str::to_owned).collect();
                }
            }
            "--auth" => a.auth = val.cloned().unwrap_or(a.auth),
            "--orders" => a.orders = val.and_then(|x| x.parse().ok()).unwrap_or(a.orders),
            "--batch" => a.batch = val.and_then(|x| x.parse().ok()).unwrap_or(a.batch),
            "--sub" => {
                if let Some(x) = val {
                    a.subs = x.split(',').filter_map(|t| t.parse().ok()).collect();
                }
            }
            "--dir" => {
                if let Some(x) = val {
                    a.dir = x.into();
                }
            }
            _ => {
                i += 1;
                continue;
            }
        }
        i += 2;
    }
    a
}

fn run(a: &Args, markets: usize, journal: &str, subs: usize) -> (f64, f64, u64) {
    let kind = match a.auth.as_str() {
        "ed25519_batch" => AuthKind::Ed25519Batch,
        "evm" => AuthKind::Evm,
        _ => AuthKind::SessionMac,
    };
    let auth =
        AuthConfig { kind, max_session_ttl_ms: None, evm_threads: 1, ..AuthConfig::default() }
            .build();
    let key = [0x5a; 32];

    // Capacity is the number of accounts the lock-free tiers can hold
    // (`oxide-matcher --accounts-cap`, default 1M). A tiny value here pushes
    // every account onto the global-mutex overflow map and measures that
    // instead of the service.
    let balances = Arc::new(AtomicBalanceCache::new((markets * ACCOUNTS * 4).max(4096)));
    // Derived once: computing an address from a secret key costs a scalar
    // multiplication (~20 us), which per order would dominate the setup.
    let addrs: Vec<Vec<Address>> = (0..markets)
        .map(|m| {
            (0..ACCOUNTS)
                .map(|acct| {
                    if a.auth == "evm" {
                        crypto::secp::signable_pubkey_address(&evm_key(m * ACCOUNTS + acct))
                            .expect("key")
                    } else {
                        owner_address(&ed(m * ACCOUNTS + acct).verifying_key())
                    }
                })
                .collect()
        })
        .collect();
    for per_market in &addrs {
        for addr in per_market {
            balances.set(addr, 1_000_000_000_000_000);
        }
    }
    let jcfg = match journal {
        "off" => None,
        other => {
            let dir = a.dir.join(format!("m{markets}-{other}"));
            let _ = std::fs::remove_dir_all(&dir);
            let mut c = JournalConfig::new(dir);
            c.ack = if other == "durable" { AckPolicy::Durable } else { AckPolicy::Queued };
            Some(c)
        }
    };
    let matcher = Arc::new(
        MultiMarketMatcher::with_journal_options(
            (0..markets).map(market_cfg).collect(),
            balances,
            Arc::new(|| 0),
            CHAIN_ID,
            None,
            RiskConfig::default(),
            None,
            jcfg,
        )
        .expect("matcher")
        .with_authenticator(Arc::clone(&auth)),
    );

    // Sessions: one per account (session MAC only).
    let sessions: Vec<Vec<u32>> = (0..markets)
        .map(|m| {
            (0..ACCOUNTS)
                .map(|acct| {
                    if a.auth == "session_mac" {
                        auth.open_session(
                            &SessionOpen::sign_ed25519(
                                &ed(m * ACCOUNTS + acct),
                                key,
                                MarketScope::all(),
                                CHAIN_ID,
                            ),
                            CHAIN_ID,
                        )
                        .expect("open")
                    } else {
                        0
                    }
                })
                .collect()
        })
        .collect();

    // Build and authenticate every submitter's batches before the clock starts.
    // Submitter k of a market owns the accounts with `acct % subs == k`, so
    // each account's nonces stay on one thread and increase in order.
    let per_submitter: Vec<Vec<Vec<OrderRequest>>> = (0..markets)
        .flat_map(|m| {
            let sessions = &sessions;
            let addrs = &addrs;
            (0..subs).map(move |k| {
                let orders: Vec<OrderRequest> = (0..a.orders)
                    .filter(|i| (i % ACCOUNTS) % subs == k)
                    .map(|i| {
                        let acct = i % ACCOUNTS;
                        let mut r = blank(m, i);
                        match a.auth.as_str() {
                            "evm" => {
                                sign_order_evm(&mut r, &evm_key(m * ACCOUNTS + acct), CHAIN_ID);
                            }
                            "ed25519_batch" => sign_order(&mut r, &ed(m * ACCOUNTS + acct)),
                            _ => {
                                r.owner = addrs[m][acct];
                                sign_order_session(&mut r, sessions[m][acct], &key, CHAIN_ID);
                            }
                        }
                        r
                    })
                    .collect();
                orders.chunks(a.batch).map(<[OrderRequest]>::to_vec).collect()
            })
        })
        .collect();

    let barrier = Arc::new(Barrier::new(markets * subs + 1));
    let handles: Vec<_> = per_submitter
        .into_iter()
        .map(|batches| {
            let m = Arc::clone(&matcher);
            let b = Arc::clone(&barrier);
            std::thread::spawn(move || {
                b.wait();
                let mut rejects = 0u64;
                for batch in batches {
                    for r in m.submit_batch(batch) {
                        rejects += u64::from(r.rejected);
                    }
                }
                rejects
            })
        })
        .collect();
    barrier.wait();
    eprintln!("timed phase start ({markets} markets x {subs} submitters, journal {journal})");
    let t0 = Instant::now();
    let rejects: u64 = handles.into_iter().map(|h| h.join().expect("submitter")).sum();
    let secs = t0.elapsed().as_secs_f64();

    // Let the journal drain before dropping (dropping does not join workers).
    let t = Instant::now();
    while matcher.journal_stats().iter().any(|s| s.lag > 0) && t.elapsed().as_secs() < 30 {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    (secs, (markets * a.orders) as f64 / secs, rejects)
}

fn main() {
    let a = parse();
    println!(
        "markets,submitters_per_market,journal,auth,orders,seconds,orders_per_s,per_market_per_s,rejects"
    );
    for &m in &a.markets {
        for j in &a.journals {
            for &k in &a.subs {
                let (secs, rate, rejects) = run(&a, m, j, k);
                println!(
                    "{m},{k},{j},{},{},{secs:.2},{rate:.0},{:.0},{rejects}",
                    a.auth,
                    m * a.orders,
                    rate / m as f64
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&a.dir);
}
