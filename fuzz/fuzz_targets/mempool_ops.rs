#![no_main]
//! Fuzz target: arbitrary operation sequences against the mempool.
//!
//! The pool takes untrusted envelopes from every peer and RPC client,
//! so its bookkeeping (dedup, replace-by-fee, fee eviction, the
//! per-sender pending and nonce-spread bounds, in-flight sets) must
//! hold under any interleaving. After every operation the target
//! checks the invariants a validator relies on: the pool never
//! exceeds its capacity, no sender exceeds its pending cap, and a
//! selection never exceeds its byte budget.

use mempool::{Mempool, build_tx};
use primitives::Address;

const MAX_ENTRIES: usize = 64;
const MAX_PENDING: usize = 8;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut pool = Mempool::new(MAX_ENTRIES).with_max_pending_per_sender(MAX_PENDING);
    let mut height = 0u64;
    for op in data.chunks(6) {
        let [kind, a, b, c, d, e] = match op {
            [k, a, b, c, d, e] => [*k, *a, *b, *c, *d, *e],
            _ => break,
        };
        let sender = Address([a % 6; 20]);
        // Nonces cluster near small values but sometimes jump far,
        // exercising both the anchor and the spread bounds.
        let nonce = if b & 0x80 == 0 { u64::from(b & 0x3f) } else { u64::from(b) << (c % 48) };
        let fee = u64::from(c) * 10 + u64::from(d);
        match kind % 5 {
            0 | 1 => {
                let _ = pool.submit(build_tx(sender, nonce, fee, &vec![e; usize::from(e % 32)]));
            }
            2 => pool.set_executed_nonce(sender, nonce),
            3 => {
                let budget = u64::from(e) * 16;
                let picked = pool.select(budget);
                let bytes: u64 = picked.iter().map(|t| t.as_bytes().len() as u64).sum();
                assert!(bytes <= budget, "selection {bytes}B exceeds budget {budget}B");
                if d & 1 == 0 {
                    pool.note_proposed(&picked);
                } else {
                    height += 1;
                    pool.remove_committed(&picked, height);
                }
            }
            _ => {
                height += 1;
                pool.remove_committed(&[], height);
            }
        }
        assert!(pool.len() <= MAX_ENTRIES, "pool over capacity: {}", pool.len());
        // The snapshot omits stale txs (nonce below the executed
        // anchor, awaiting `refresh_anchors`), so it is a subset of
        // the pool, never larger.
        let snap = pool.txpool_snapshot();
        assert!(snap.len() <= pool.len(), "snapshot {} > pool {}", snap.len(), pool.len());
        for s in 0..6u8 {
            let n = snap.iter().filter(|(a, ..)| *a == Address([s; 20])).count();
            assert!(n <= MAX_PENDING, "sender {s} holds {n} > {MAX_PENDING} pending");
        }
    }
});
