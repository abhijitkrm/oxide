//! MPT state root benchmark — the Ethereum-compatible root computation.
//!
//! This benchmarks the full Merkle-Patricia Trie root computation
//! over the EVM's account state. It is the "state root floor" for
//! the EVM module: every `end_block` call computes the root to
//! commit in the block header.
//!
//! ## Acceptance gate
//!
//! The gate for the **incremental** path (B3, future) is: incremental
//! root for 100 touched accounts in a 1M-account state < 10ms.
//!
//! This benchmark measures the **full rebuild** baseline — the
//! displaced alternative that B3 must beat asymptotically. The full
//! rebuild is O(N) in the number of accounts; the incremental path
//! is O(touched) — independent of total state size.
//!
//! ## What this measures
//!
//! - `state_root_full_rebuild/{1k, 10k, 100k}`: full MPT root
//!   computation over N accounts, each with a balance and nonce.
//!   Shows the O(N) scaling that motivates B3.
//! - `storage_root/{10, 100, 1000}`: per-account storage trie root
//!   for N storage slots. This is the per-account cost that feeds
//!   into the state root.

#![allow(missing_docs)]

use std::hint::black_box;

use alloy_primitives::{Address, B256, U256};
use alloy_trie::{EMPTY_ROOT_HASH, TrieAccount};
use criterion::{Criterion, criterion_group, criterion_main};
use evm::trie;

/// Build N accounts with deterministic balances and nonces.
fn build_accounts(n: usize) -> Vec<(Address, TrieAccount)> {
    (0..n)
        .map(|i| {
            let mut addr_bytes = [0u8; 20];
            addr_bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let addr = Address::from(addr_bytes);
            let account = TrieAccount {
                nonce: i as u64,
                balance: U256::from(i as u128 * 1_000_000_000),
                storage_root: EMPTY_ROOT_HASH,
                code_hash: alloy_primitives::utils::KECCAK256_EMPTY,
            };
            (addr, account)
        })
        .collect()
}

/// Build N storage slots with deterministic values.
fn build_storage(n: usize) -> Vec<(B256, U256)> {
    (0..n)
        .map(|i| {
            let mut slot_bytes = [0u8; 32];
            slot_bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let slot = B256::from(slot_bytes);
            let value = U256::from(i as u128);
            (slot, value)
        })
        .collect()
}

fn bench_state_root_full_rebuild(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_root_full_rebuild");

    for &n in &[1_000, 10_000, 100_000] {
        let accounts = build_accounts(n);
        group.bench_function(format!("{n}"), |b| {
            b.iter(|| {
                let root = trie::state_root(black_box(accounts.iter().copied()));
                black_box(root);
            });
        });
    }

    group.finish();
}

fn bench_storage_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("storage_root");

    for &n in &[10, 100, 1_000] {
        let storage = build_storage(n);
        group.bench_function(format!("{n}"), |b| {
            b.iter(|| {
                let root = trie::storage_root(black_box(storage.iter().copied()));
                black_box(root);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_state_root_full_rebuild, bench_storage_root);
criterion_main!(benches);
