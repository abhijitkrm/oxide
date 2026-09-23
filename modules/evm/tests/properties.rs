//! Property tests — differential execution equivalence.
//!
//! The parallel executor speculates on per-sender state views and
//! merges validated results in canonical order. The safety property
//! under test: **every entry path must produce identical state** for
//! identical input — serial `handle`, serial `handle_batch`,
//! `handle_batch_parallel`, and `handle_batch_parallel_preverified`
//! are interchangeable execution engines, and a node must not be
//! able to influence its state root by choosing between them.
//!
//! The generated workload is deliberately contract-heavy: contracts
//! carry pre-existing storage, and generated txs read, write, and
//! zero slots on shared contracts from different senders. That mix
//! is what the account-granular OCC scheduler must interleave
//! correctly — pure-transfer batches cannot reach the merge paths
//! where storage loss once lived (the `preserves_unread_storage`
//! unit regression covers the minimal case).

use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::{Module, TxContext};
use primitives::{Address, Height};
use proptest::prelude::*;
use revm::primitives::{Bytes, U256};

/// Chain ID every generated tx is signed with (matches the module
/// built in `setup`).
const CHAIN_ID: u64 = 1;
/// Gas limit on every generated tx — ample for the fixed bytecode
/// set (all contracts here are ≤ ~10 instructions).
const GAS_LIMIT: u64 = 1_000_000;
/// Gas price — comfortably above the module's 7 wei base fee.
const GAS_PRICE: u64 = 1_000_000_000;

// ── Fixed contract set ─────────────────────────────────────────
// All bytecode is hand-assembled, ≤ 10 instructions, and chosen to
// exercise a distinct merge hazard. Contracts are deployed at
// genesis via `genesis_insert_account` with pre-existing storage.

/// SSTORE(slot = calldata[0..32], value = calldata[32..64]); STOP.
/// The calldata-parameterized writer lets generated txs touch
/// arbitrary slots of one shared contract.
const WRITER: &[u8] = &[0x60, 0x20, 0x35, 0x60, 0x00, 0x35, 0x55, 0x00];
/// SSTORE(4, SLOAD(1) + 1); STOP — reads an existing slot, writes a
/// different one (read-set/write-set split inside one tx).
const READER_WRITER: &[u8] = &[0x60, 0x01, 0x54, 0x60, 0x01, 0x01, 0x60, 0x04, 0x55, 0x00];
/// SSTORE(2, 0); STOP — zeroes a pre-existing slot.
const ZEROER: &[u8] = &[0x60, 0x00, 0x60, 0x02, 0x55, 0x00];
/// REVERT(0, 0) — reverts after paying gas; only the caller's
/// nonce/balance and the coinbase tip may commit.
const REVERTER: &[u8] = &[0x60, 0x00, 0x60, 0x00, 0xfd];
/// BALANCE(coinbase); STOP — observes the fee recipient (address
/// zero in tests) mid-block, forcing the coinbase-read
/// re-execution path when the running tip total has moved.
const COINBASE_READER: &[u8] = &[
    0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00,
];
/// SELFDESTRUCT(0xBB..BB) — a pre-existing contract, so post-Cancun
/// semantics keep the account and its storage but move the balance.
const SELFDESTRUCTER: &[u8] = &[
    0x73, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xff,
];

/// One genesis-deployed contract: `(name, runtime, initial
/// storage)`. The name is diagnostic-only, for failure messages.
type ContractSpec = (&'static str, &'static [u8], &'static [(u64, u64)]);

/// The deployed contract set, index-aligned with the `contract`
/// field of generated [`Op::Call`] ops.
const CONTRACTS: &[ContractSpec] = &[
    ("WRITER", WRITER, &[(1, 42), (2, 43)]),
    ("READER_WRITER", READER_WRITER, &[(1, 7)]),
    ("ZEROER", ZEROER, &[(2, 77)]),
    ("REVERTER", REVERTER, &[]),
    ("COINBASE_READER", COINBASE_READER, &[]),
    ("SELFDESTRUCTER", SELFDESTRUCTER, &[(9, 99)]),
];

/// Contract addresses are fixed per index so generated batches hit
/// the same state on every leg.
fn contract_address(idx: usize) -> Address {
    let mut a = [0xC0u8; 20];
    a[19] = u8::try_from(idx).expect("contract index fits u8");
    Address(a)
}

/// Pool of plain-transfer recipients (code-less EOAs).
fn transfer_recipient(idx: usize) -> revm::primitives::Address {
    let mut a = [0x77u8; 20];
    a[19] = u8::try_from(idx).expect("recipient index fits u8");
    revm::primitives::Address::from(a)
}

// ── Generated transaction ops ──────────────────────────────────

/// One generated transaction, before signing. `sender` indexes the
/// fixed key pool; the nonce is assigned at materialization time so
/// each sender's txs are strictly sequential.
#[derive(Debug, Clone)]
enum Op {
    /// Plain value transfer to a code-less recipient — exercises the
    /// native fast path in the batch legs.
    Transfer { recipient: usize, value: u64 },
    /// Parameterized SSTORE on the shared WRITER contract.
    Write { slot: u8, value: u8 },
    /// Zero-calldata call to one of the fixed contracts.
    Call { contract: usize },
    /// Deploy a minimal contract (CREATE) — exercises the
    /// new-contract merge payload.
    Create,
    /// Second sender lane hitting the same WRITER contract — the
    /// account-granular conflict that forces canonical re-execution
    /// is generated naturally by interleaving senders.
    WriteAlt { slot: u8, value: u8 },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..4usize, 0..1000u64).prop_map(|(recipient, value)| Op::Transfer { recipient, value }),
        (0..8u8, 0..64u8).prop_map(|(slot, value)| Op::Write { slot, value }),
        (0..CONTRACTS.len()).prop_map(|contract| Op::Call { contract }),
        Just(Op::Create),
        (0..8u8, 0..64u8).prop_map(|(slot, value)| Op::WriteAlt { slot, value }),
    ]
}

/// A generated batch: up to 24 txs across up to 4 senders.
fn batch_strategy() -> impl Strategy<Value = Vec<(usize, Op)>> {
    proptest::collection::vec((0..4usize, op_strategy()), 0..24)
}

/// Sign one generated op for `sender` at `nonce`.
fn sign_op(pk: &[u8; 32], nonce: u64, op: &Op) -> Vec<u8> {
    let (to, data, value) = match *op {
        Op::Transfer { recipient, value } => {
            (TxKind::Call(transfer_recipient(recipient)), Bytes::new(), U256::from(value))
        }
        Op::Write { slot, value } | Op::WriteAlt { slot, value } => {
            // WRITER is contract index 0 — both variants hit it so
            // different senders write different slots of one account.
            let mut data = vec![0u8; 64];
            data[31] = slot;
            data[63] = value;
            (
                TxKind::Call(revm::primitives::Address::from(contract_address(0).0)),
                Bytes::from(data),
                U256::ZERO,
            )
        }
        Op::Call { contract } => (
            TxKind::Call(revm::primitives::Address::from(contract_address(contract).0)),
            Bytes::new(),
            U256::ZERO,
        ),
        Op::Create => (
            TxKind::Create,
            // Minimal init: returns empty runtime code.
            Bytes::from_static(&[0x60, 0x80, 0x60, 0x40, 0x52]),
            U256::ZERO,
        ),
    };
    let tx = TxLegacy {
        fields: TxFields { nonce, gas_limit: GAS_LIMIT, to, value, data, chain_id: CHAIN_ID },
        gas_price: U256::from(GAS_PRICE),
    };
    SignedTx::sign_legacy(tx, pk).expect("sign").encode_to_bytes()
}

/// Build a fresh module with the fixed contract set and all senders
/// funded — identical starting state for every execution leg.
fn setup(sender_addrs: &[Address]) -> EvmModule {
    let m = EvmModule::new(CHAIN_ID, 7);
    for (i, (_, code, storage)) in CONTRACTS.iter().enumerate() {
        let storage = storage.iter().map(|(k, v)| (U256::from(*k), U256::from(*v))).collect();
        // The selfdestructer carries a balance so its post-Cancun
        // beneficiary credit is exercised.
        let balance = if i == 5 { 7 } else { 0 };
        m.genesis_insert_account(&contract_address(i), balance, 1, code.to_vec(), storage);
    }
    for addr in sender_addrs {
        m.fund_account_for_test(addr, u128::MAX);
    }
    m
}

/// Execute `txs` on a fresh module via the serial per-tx path.
fn run_serial(txs: &[Vec<u8>], sender_addrs: &[Address]) -> EvmModule {
    let m = setup(sender_addrs);
    let ctx = TxContext { sender: Address([0; 20]), nonce: 0, fee: 0 };
    m.begin_block(Height::new(1));
    for raw in txs {
        let _ = m.handle(&ctx, raw);
    }
    m.end_block(Height::new(1));
    m
}

/// Execute `txs` on a fresh module via `handle_batch`.
fn run_batch(txs: &[Vec<u8>], sender_addrs: &[Address]) -> EvmModule {
    let m = setup(sender_addrs);
    let ctx = TxContext { sender: Address([0; 20]), nonce: 0, fee: 0 };
    m.begin_block(Height::new(1));
    let _ = m.handle_batch(&ctx, txs);
    m.end_block(Height::new(1));
    m
}

/// Execute `txs` on a fresh module via `handle_batch_parallel`.
fn run_parallel(txs: &[Vec<u8>], sender_addrs: &[Address]) -> EvmModule {
    let m = setup(sender_addrs);
    let ctx = TxContext { sender: Address([0; 20]), nonce: 0, fee: 0 };
    m.begin_block(Height::new(1));
    let _ = m.handle_batch_parallel(&ctx, txs);
    m.end_block(Height::new(1));
    m
}

/// Execute `txs` on a fresh module via `handle_batch_parallel_preverified`.
fn run_preverified(txs: &[Vec<u8>], sender_addrs: &[Address]) -> EvmModule {
    let m = setup(sender_addrs);
    let ctx = TxContext { sender: Address([0; 20]), nonce: 0, fee: 0 };
    m.begin_block(Height::new(1));
    let pvs: Vec<_> = m
        .preverify_batch(txs)
        .into_iter()
        .map(|r| r.expect("generated txs must preverify"))
        .collect();
    let _ = m.handle_batch_parallel_preverified(&ctx, &pvs);
    m.end_block(Height::new(1));
    m
}

/// Deterministic keypool: the same four senders every run so
/// contract addresses and genesis state are stable.
fn sender_pool() -> Vec<([u8; 32], Address)> {
    (0..4u8)
        .map(|i| {
            (
                crypto::secp::test_identity_key(i),
                crypto::secp::test_identity_address(i).expect("identity keys are valid"),
            )
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Serial, batch, parallel, and preverified-parallel execution
    /// must agree on the entire post-block state — the state root
    /// covers accounts, balances, nonces, code and storage, so
    /// equality is the full differential claim. Watched storage
    /// slots are additionally compared verbatim so a root-collision
    /// argument is never load-bearing.
    #[test]
    fn execution_paths_produce_identical_state(ops in batch_strategy()) {
        let pool = sender_pool();
        let sender_addrs: Vec<Address> = pool.iter().map(|(_, a)| *a).collect();

        // Materialize: assign sequential nonces per sender.
        let mut next_nonce = [0u64; 4];
        let mut txs = Vec::with_capacity(ops.len());
        for (sender_idx, op) in &ops {
            let nonce = next_nonce[*sender_idx];
            next_nonce[*sender_idx] += 1;
            txs.push(sign_op(&pool[*sender_idx].0, nonce, op));
        }

        let serial = run_serial(&txs, &sender_addrs);
        let batch = run_batch(&txs, &sender_addrs);
        let parallel = run_parallel(&txs, &sender_addrs);
        let preverified = run_preverified(&txs, &sender_addrs);

        let root = serial.state_root();
        prop_assert_eq!(batch.state_root(), root, "handle_batch root diverged");
        prop_assert_eq!(parallel.state_root(), root, "handle_batch_parallel root diverged");
        prop_assert_eq!(
            preverified.state_root(),
            root,
            "handle_batch_parallel_preverified root diverged"
        );

        // Verbatim slot comparison over the contract set — the slots
        // generated txs can reach plus the genesis-resident ones.
        for (i, (_, _, _)) in CONTRACTS.iter().enumerate() {
            for slot in 0..8u64 {
                let expected = serial.storage_at(&contract_address(i), &U256::from(slot));
                for (name, m) in
                    [("batch", &batch), ("parallel", &parallel), ("preverified", &preverified)]
                {
                    prop_assert_eq!(
                        m.storage_at(&contract_address(i), &U256::from(slot)),
                        expected,
                        "{}: contract {} slot {} diverged from serial",
                        name,
                        i,
                        slot
                    );
                }
            }
        }
    }

    /// Read traffic must not perturb committed state: two modules
    /// executing the same batch — one serving interleaved
    /// `eth_call` / `eth_estimateGas` / `eth_createAccessList` /
    /// `debug_traceCall` / `eth_getStorageAt` traffic (some aimed at
    /// accounts that do not exist) — must finish with identical
    /// roots and identical storage. This is the "node under RPC
    /// load vs quiet node" equivalence the read-isolation fix
    /// guarantees: revm caches every read miss into the db it
    /// executes against, so any path that served reads on the
    /// authoritative map would leak zero-slot entries and
    /// `NotExisting` tombstones into consensus state.
    #[test]
    fn read_traffic_does_not_change_committed_state(ops in batch_strategy()) {
        let pool = sender_pool();
        let sender_addrs: Vec<Address> = pool.iter().map(|(_, a)| *a).collect();

        let mut next_nonce = [0u64; 4];
        let mut txs = Vec::with_capacity(ops.len());
        for (sender_idx, op) in &ops {
            let nonce = next_nonce[*sender_idx];
            next_nonce[*sender_idx] += 1;
            txs.push(sign_op(&pool[*sender_idx].0, nonce, op));
        }

        let quiet = run_serial(&txs, &sender_addrs);

        // Same block, but every tx is preceded by reads — including
        // calls aimed at an address that does not exist, the miss
        // pattern that used to install `NotExisting` tombstones.
        let served = setup(&sender_addrs);
        let ctx = TxContext { sender: Address([0; 20]), nonce: 0, fee: 0 };
        served.begin_block(Height::new(1));
        for (i, raw) in txs.iter().enumerate() {
            let req = evm::CallRequest {
                to: Some(if i % 3 == 0 {
                    Address([0xEE; 20])
                } else {
                    contract_address(i % CONTRACTS.len())
                }),
                ..evm::CallRequest::default()
            };
            match i % 4 {
                0 => drop(served.call_read(&req)),
                1 => drop(served.estimate_call_gas(&req)),
                2 => drop(served.create_access_list(&req)),
                _ => drop(served.call_read_traced(&req)),
            }
            let _ = served.storage_at(&contract_address(i % CONTRACTS.len()), &U256::from(i % 8));
            let _ = served.handle(&ctx, raw);
        }
        served.end_block(Height::new(1));

        prop_assert_eq!(
            served.state_root(),
            quiet.state_root(),
            "read traffic changed the state root"
        );
        for (i, (_, _, _)) in CONTRACTS.iter().enumerate() {
            for slot in 0..8u64 {
                prop_assert_eq!(
                    served.storage_at(&contract_address(i), &U256::from(slot)),
                    quiet.storage_at(&contract_address(i), &U256::from(slot)),
                    "read traffic changed contract {} slot {}",
                    i,
                    slot
                );
            }
        }
    }
}
