//! End-to-end tests of the journaled market workers: recovery equals
//! the live run, ack policies, checkpoint + truncation, and a real
//! `SIGKILL` crash test.

use std::path::PathBuf;
use std::sync::Arc;

use primitives::fixed::{Price, Qty};
use trading::{MarketConfig, OrderType, Side, TimeInForce};

use crate::cmdlog::{AckPolicy, JournalConfig};
use crate::protocol::{ActionRequest, ActionType, OrderRequest};
use crate::{AtomicBalanceCache, MultiMarketMatcher, RiskConfig};

/// Wait until everything the matcher journaled is durable — the
/// "quiet moment" before a clean stop; the crash test does NOT call it.
fn settle(m: &MultiMarketMatcher) {
    let t = std::time::Instant::now();
    while m.journal_stats().iter().any(|s| s.lag > 0) {
        assert!(t.elapsed().as_secs() < 10, "journal never caught up");
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

fn cfg() -> MarketConfig {
    MarketConfig {
        market_id: 0,
        tick_size: Price(1_000_000),
        lot_size: Qty(1_000),
        min_price: Price(1_000_000_000),
        max_price: Price(2_000_000_000),
        max_resting: 1 << 16,
    }
}

fn account(seed: u8) -> (crypto::ed25519::Ed25519SecretKey, primitives::Address) {
    let secret = crypto::ed25519::Ed25519SecretKey::from_bytes(&[seed; 32]);
    let owner = crypto::ed25519::owner_address(&secret.verifying_key());
    (secret, owner)
}

fn order(
    sk: &crypto::ed25519::Ed25519SecretKey,
    side: Side,
    nonce: u64,
    ticks: u64,
    lots: u64,
) -> OrderRequest {
    let mut req = OrderRequest {
        market: 0,
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price(1_000_000_000 + ticks * 1_000_000),
        qty: Qty(lots * 1_000),
        nonce,
        owner: primitives::Address([0; 20]),
        pubkey: [0; 32],
        signature: [0; 64],
    };
    crate::protocol::sign_order(&mut req, sk);
    req
}

fn cancel(sk: &crypto::ed25519::Ed25519SecretKey, order_id: u64, nonce: u64) -> ActionRequest {
    let mut req = ActionRequest {
        action_type: ActionType::Cancel,
        order_id,
        new_price: Price(0),
        new_qty: Qty(0),
        side: Side::Buy,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        nonce,
        owner: primitives::Address([0; 20]),
        pubkey: [0; 32],
        signature: [0; 64],
    };
    crate::protocol::sign_action(&mut req, sk);
    req
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("oxide-jw-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn funded()
-> (Arc<AtomicBalanceCache>, [(crypto::ed25519::Ed25519SecretKey, primitives::Address); 3]) {
    let accts = [account(1), account(2), account(3)];
    let balances = Arc::new(AtomicBalanceCache::new(8));
    for (_, a) in &accts {
        balances.set(a, 1_000_000_000_000);
    }
    (balances, accts)
}

fn start(
    balances: &Arc<AtomicBalanceCache>,
    journal: Option<JournalConfig>,
) -> Result<MultiMarketMatcher, String> {
    MultiMarketMatcher::with_journal_options(
        vec![cfg()],
        Arc::clone(balances),
        Arc::new(|| 0),
        crate::protocol::CHAIN_ID,
        None,
        RiskConfig::default(),
        None,
        journal,
    )
}

/// One deterministic flow: crossing and resting orders from three
/// accounts, cancels, and a seal every `seal_every` steps. Returns
/// every fill sealed along the way.
fn run_flow(
    m: &MultiMarketMatcher,
    steps: u64,
    seal_every: u64,
) -> Vec<crate::settlement::SettledFill> {
    let (_, accts) = funded();
    let mut nonces = [0u64; 3];
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let mut sealed = Vec::new();
    for step in 1..=steps {
        let who = usize::try_from(rnd(3)).unwrap();
        let (sk, _) = &accts[who];
        let n = nonces[who];
        nonces[who] += 1;
        if rnd(10) < 7 {
            let side = if rnd(2) == 0 { Side::Buy } else { Side::Sell };
            let _ = m.submit_one(order(sk, side, n, 480 + rnd(40), 1 + rnd(5)));
        } else {
            let _ = m.submit_action(&cancel(sk, rnd(step + 1), n));
        }
        if step % seal_every == 0 {
            sealed.extend(m.seal_batch());
        }
    }
    sealed
}

fn fill_key(f: &crate::settlement::SettledFill) -> (u64, u64, [u8; 20], u64, [u8; 20], u64, u64) {
    (f.price.0, f.qty.0, f.buyer.0, f.buyer_id, f.seller.0, f.seller_id, f.quote_amount)
}

/// Recovery rebuilds exactly what the live run had: same resting
/// count, same pending (unsealed) fills, same behavior afterwards.
#[test]
fn recovered_matcher_equals_the_live_run() {
    let dir = tmp("equal");
    let (balances, _) = funded();
    let mut jc = JournalConfig::new(&dir);
    jc.checkpoint_after_records = 0;

    // Reference: same flow, no journal.
    let (b2, _) = funded();
    let reference = start(&b2, None).unwrap();
    let ref_sealed = run_flow(&reference, 400, 97);
    let ref_stats = reference.stats();
    let ref_pending = reference.seal_batch();

    // Journaled run, dropped without a final seal ("crash").
    let live = start(&balances, Some(jc.clone())).unwrap();
    let live_sealed = run_flow(&live, 400, 97);
    assert_eq!(
        live_sealed.iter().map(fill_key).collect::<Vec<_>>(),
        ref_sealed.iter().map(fill_key).collect::<Vec<_>>(),
        "journaling must not change behavior"
    );
    settle(&live);
    drop(live);

    let (b3, _) = funded();
    let recovered = start(&b3, Some(jc)).unwrap();
    let report = &recovered.recovery_reports()[0];
    assert!(report.replayed > 0 && report.last_seq >= report.replayed);
    let stats = recovered.stats();
    assert_eq!(stats.resting_count, ref_stats.resting_count);
    assert_eq!(stats.pending_settlements, ref_stats.pending_settlements);
    let pending = recovered.seal_batch();
    assert_eq!(
        pending.iter().map(fill_key).collect::<Vec<_>>(),
        ref_pending.iter().map(fill_key).collect::<Vec<_>>(),
        "the unsealed batch survives the restart, fill for fill"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Checkpoints are taken at seals, truncate the journal, and recovery
/// from checkpoint + tail equals recovery from the whole journal.
#[test]
fn checkpoint_truncates_and_recovery_still_matches() {
    let dir = tmp("ckpt");
    let (balances, _) = funded();
    let mut jc = JournalConfig::new(&dir);
    jc.checkpoint_after_records = 25;

    let (b2, _) = funded();
    let reference = start(&b2, None).unwrap();
    let _ = run_flow(&reference, 600, 40);
    let ref_stats = reference.stats();
    let ref_pending = reference.seal_batch();

    let live = start(&balances, Some(jc.clone())).unwrap();
    let _ = run_flow(&live, 600, 40);
    settle(&live);
    drop(live);

    let mdir = jc.market_dir(0);
    let names: Vec<String> = std::fs::read_dir(&mdir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names.iter().filter(|n| n.starts_with("checkpoint-")).count(),
        1,
        "exactly one (the newest) checkpoint is kept: {names:?}"
    );
    let first_segment = names.iter().filter(|n| n.starts_with("cmd-")).min().unwrap();
    assert_ne!(first_segment, "cmd-0000000000000001.journal", "old segments were truncated");

    let (b3, _) = funded();
    let recovered = start(&b3, Some(jc)).unwrap();
    let report = &recovered.recovery_reports()[0];
    assert!(report.checkpoint_seq > 0, "recovery started from a checkpoint");
    let stats = recovered.stats();
    assert_eq!(stats.resting_count, ref_stats.resting_count);
    assert_eq!(
        recovered.seal_batch().iter().map(fill_key).collect::<Vec<_>>(),
        ref_pending.iter().map(fill_key).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Recovered resting buys report the quote reservations the service
/// must re-apply.
#[test]
fn recovery_reports_buy_reservations() {
    let dir = tmp("resv");
    let (balances, accts) = funded();
    let jc = JournalConfig::new(&dir);
    let live = start(&balances, Some(jc.clone())).unwrap();
    let _ = live.submit_one(order(&accts[0].0, Side::Buy, 0, 100, 4)); // $11.00 × 4 lots
    let _ = live.submit_one(order(&accts[0].0, Side::Sell, 1, 300, 2));
    settle(&live);
    drop(live);
    let (b2, _) = funded();
    let rec = start(&b2, Some(jc)).unwrap();
    let r = &rec.recovery_reports()[0];
    assert_eq!(r.resting, 2);
    assert_eq!(r.buy_reservations, vec![(accts[0].1, 1_100_000_000 * 4_000 / 100_000_000)]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `Durable` holds the response until the batch is on disk; `Queued`
/// answers first and the journal catches up within a group commit.
#[test]
fn ack_policies_and_metrics() {
    for policy in [AckPolicy::Durable, AckPolicy::Queued] {
        let dir = tmp("ack");
        let (balances, accts) = funded();
        let mut jc = JournalConfig::new(&dir);
        jc.ack = policy;
        let m = start(&balances, Some(jc)).unwrap();
        for i in 0..20 {
            let r = m.submit_one(order(&accts[0].0, Side::Buy, i, 100 + i, 1));
            assert!(!r.rejected, "{policy:?}");
        }
        let s = m.journal_stats()[0];
        assert_eq!(s.appended, 20);
        if policy == AckPolicy::Durable {
            assert_eq!(s.durable, 20, "every acknowledged order is durable");
            assert_eq!(s.lag, 0);
        } else {
            // Flushed at batch end, so durable within one group commit.
            let t = std::time::Instant::now();
            while m.journal_stats()[0].durable < 20 {
                assert!(t.elapsed().as_secs() < 5, "queued journal never became durable");
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        assert!(m.journal_stats()[0].fsyncs >= 1);
        drop(m);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A torn final record is repaired at start; mid-file damage refuses
/// to start.
#[test]
fn recovery_repairs_a_torn_tail_but_refuses_a_hole() {
    let dir = tmp("torn");
    let (balances, accts) = funded();
    let jc = JournalConfig::new(&dir);
    let m = start(&balances, Some(jc.clone())).unwrap();
    for i in 0..10 {
        let _ = m.submit_one(order(&accts[0].0, Side::Buy, i, 100 + i, 1));
    }
    settle(&m);
    drop(m);
    let seg = jc.market_dir(0).join("cmd-0000000000000001.journal");
    let full = std::fs::read(&seg).unwrap();
    std::fs::write(&seg, &full[..full.len() - 5]).unwrap(); // tear the last record
    let (b2, _) = funded();
    let rec = start(&b2, Some(jc.clone())).unwrap();
    assert_eq!(rec.recovery_reports()[0].resting, 9, "the torn order was never durable");
    drop(rec);
    let mut bad = full.clone();
    bad[10] ^= 0xFF; // inside the first record
    std::fs::write(&seg, &bad).unwrap();
    let (b3, _) = funded();
    assert!(start(&b3, Some(jc)).is_err(), "a hole must stop the start");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Crash test (real SIGKILL) ────────────────────────────────────────

const CHILD_ENV: &str = "OXIDE_JOURNAL_CRASH_DIR";

/// Child half of the crash test — only meaningful when launched by
/// [`acknowledged_orders_survive_sigkill`]; a no-op otherwise.
#[test]
fn crash_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else { return };
    let (balances, accts) = funded();
    let mut jc = JournalConfig::new(&dir);
    jc.ack = AckPolicy::Durable;
    jc.checkpoint_after_records = 0;
    let m = start(&balances, Some(jc)).unwrap();
    let mut out = std::io::stdout().lock();
    let mut i = 0u64;
    loop {
        let r = m.submit_one(order(&accts[0].0, Side::Buy, i, 100 + (i % 500), 1));
        if !r.rejected {
            // The acknowledgement the client would have seen.
            use std::io::Write;
            writeln!(out, "ACK {i}").unwrap();
            out.flush().unwrap();
        }
        i += 1;
    }
}

/// Kill the matcher with SIGKILL while it is acknowledging orders
/// under `AckPolicy::Durable`; every acknowledged order must be
/// resting after recovery.
#[test]
fn acknowledged_orders_survive_sigkill() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let dir = tmp("kill");
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args(["journal_wiring_tests::crash_child", "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, &dir)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut acked = 0u64;
    for line in BufReader::new(child.stdout.take().unwrap()).lines() {
        let line = line.unwrap();
        if let Some(n) = line.strip_prefix("ACK ") {
            acked = n.parse::<u64>().unwrap() + 1;
        }
        if acked >= 300 {
            break;
        }
    }
    child.kill().unwrap(); // SIGKILL: no destructors, no flush
    child.wait().unwrap();
    assert!(acked >= 300, "child produced too few acknowledgements: {acked}");

    let (balances, _) = funded();
    let rec = start(&balances, Some(JournalConfig::new(&dir))).unwrap();
    let r = &rec.recovery_reports()[0];
    assert!(
        u64::from(r.resting) >= acked && r.last_seq >= acked,
        "acknowledged {acked}, recovered resting {} / seq {}",
        r.resting,
        r.last_seq
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rough cost of journaling (run with `--release -- --ignored --nocapture`).
/// Orders are pre-signed; batches of 256 so group commit amortizes.
#[test]
#[ignore = "measurement, not a correctness test"]
fn journal_overhead() {
    let (_, accts) = funded();
    let mk = |n: u64| -> Vec<Vec<OrderRequest>> {
        (0..n / 256)
            .map(|b| {
                (0..256)
                    .map(|i| {
                        let k = b * 256 + i;
                        order(&accts[0].0, Side::Buy, k, 1 + (k % 900), 1)
                    })
                    .collect()
            })
            .collect()
    };
    for (name, jc) in
        [("off", None), ("queued", Some(AckPolicy::Queued)), ("durable", Some(AckPolicy::Durable))]
    {
        let dir = tmp("perf");
        let (balances, _) = funded();
        let journal = jc.map(|ack| {
            let mut c = JournalConfig::new(&dir);
            c.ack = ack;
            c.checkpoint_after_records = 0;
            c
        });
        let m = start(&balances, journal).unwrap();
        let batches = mk(20_480);
        let t = std::time::Instant::now();
        for b in batches {
            let _ = m.submit_batch(b);
        }
        let s = t.elapsed().as_secs_f64();
        println!("{name:8} {:>9.0} orders/s ({:.1} ms/batch)", 20_480.0 / s, s * 1000.0 / 80.0);
        drop(m);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Recovery re-reserves what resting buys hold, so a fresh cache ends
/// up exactly where the live one was.
#[test]
fn reservations_are_reapplied_to_a_fresh_balance_cache() {
    let dir = tmp("rereserve");
    let (balances, accts) = funded();
    let jc = JournalConfig::new(&dir);
    let live = start(&balances, Some(jc.clone())).unwrap();
    let _ = live.submit_one(order(&accts[0].0, Side::Buy, 0, 100, 4));
    let _ = live.submit_one(order(&accts[1].0, Side::Buy, 0, 120, 2));
    let live_balances = [balances.get(&accts[0].1), balances.get(&accts[1].1)];
    settle(&live);
    drop(live);

    let (fresh, _) = funded();
    assert_ne!(fresh.get(&accts[0].1), live_balances[0], "fresh cache has no reservations");
    let rec = start(&fresh, Some(jc)).unwrap();
    let failed = crate::cmdlog::reapply_reservations(&fresh, rec.recovery_reports());
    assert!(failed.is_empty(), "{failed:?}");
    assert_eq!([fresh.get(&accts[0].1), fresh.get(&accts[1].1)], live_balances);
    // A cache that cannot cover a reservation is reported, not half-debited.
    let (poor, _) = funded();
    poor.set(&accts[0].1, 1);
    let failed = crate::cmdlog::reapply_reservations(&poor, rec.recovery_reports());
    assert_eq!(failed.len(), 1);
    assert_eq!(poor.get(&accts[0].1), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two markets journal and recover independently; each report is its
/// own market's.
#[test]
fn markets_recover_independently() {
    let dir = tmp("two");
    let (balances, accts) = funded();
    let jc = JournalConfig::new(&dir);
    let cfgs = |n: u16| -> Vec<MarketConfig> {
        (0..n).map(|m| MarketConfig { market_id: m, ..cfg() }).collect()
    };
    let start2 = |b: &Arc<AtomicBalanceCache>| {
        MultiMarketMatcher::with_journal_options(
            cfgs(2),
            Arc::clone(b),
            Arc::new(|| 0),
            crate::protocol::CHAIN_ID,
            None,
            RiskConfig::default(),
            None,
            Some(jc.clone()),
        )
        .unwrap()
    };
    let live = start2(&balances);
    let mut n = 0;
    for (market, count) in [(0u8, 3u64), (1, 5)] {
        for i in 0..count {
            let mut o = order(&accts[0].0, Side::Buy, n, 100 + i, 1);
            o.market = market;
            crate::protocol::sign_order(&mut o, &accts[0].0);
            assert!(!live.submit_one(o).rejected);
            n += 1;
        }
    }
    settle(&live);
    drop(live);
    let (b2, _) = funded();
    let rec = start2(&b2);
    let r = rec.recovery_reports();
    assert_eq!((r[0].market, r[0].resting, r[1].market, r[1].resting), (0, 3, 1, 5));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A record logged outside any submit path still reaches disk without
/// further traffic: the worker's timer flush hands it over.
#[test]
fn idle_flush_makes_a_lone_record_durable() {
    let dir = tmp("idle");
    let (balances, accts) = funded();
    let m = start(&balances, Some(JournalConfig::new(&dir))).unwrap();
    let _ = m.submit_one(order(&accts[0].0, Side::Buy, 0, 100, 1));
    settle(&m); // returns only once the journal caught up with no more traffic
    assert_eq!(m.journal_stats()[0].durable, 1);
    let _ = std::fs::remove_dir_all(&dir);
}
