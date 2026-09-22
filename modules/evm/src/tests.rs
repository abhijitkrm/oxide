//! Unit tests — extracted from the implementation file so the
//! production code reads top-to-bottom without the test bulk
//! (split-giant-modules pass: every entry point's enforcement
//! stays visible).

use super::*;
use crate::trie::prefix_range;
use crypto::secp;
use revm::primitives::U256;

fn make_module() -> EvmModule {
    EvmModule::new(1, 7)
}

/// A fixed private key for deterministic tests. This key is
/// generated fresh per test run via `generate_keypair_for_test`,
/// which uses the secp256k1 crate's RNG. The address is derived
/// from the recovered public key.
fn test_keypair() -> ([u8; 32], Address) {
    let (privkey, addr) = secp::generate_keypair_for_test();
    (privkey, Address(addr.0))
}

/// Build a signed legacy transaction for testing.
fn signed_tx(privkey: &[u8], nonce: u64, to: tx::TxKind, data: &[u8]) -> Vec<u8> {
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce,
            gas_limit: DEFAULT_GAS_LIMIT,
            to,
            value: U256::ZERO,
            data: revm::primitives::Bytes::copy_from_slice(data),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    let signed = tx::SignedTx::sign_legacy(tx, privkey).expect("sign must succeed");
    signed.encode_to_bytes()
}

/// A `TxContext` with a dummy sender (the EVM module ignores it
/// and recovers the sender from the signature).
fn dummy_ctx() -> TxContext {
    TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 }
}

/// Fund an account with a large balance for testing.
fn fund(m: &EvmModule, addr: &Address) {
    m.fund_account_for_test(addr, u128::MAX);
}

#[test]
fn module_id_is_evm() {
    let m = make_module();
    assert_eq!(m.id(), MODULE_ID);
    assert_eq!(m.id(), module_id::EVM);
}

#[test]
fn name_is_evm() {
    let m = make_module();
    assert_eq!(m.name(), "evm");
}

#[test]
fn chain_id_round_trips() {
    let m = EvmModule::new(42, 1);
    assert_eq!(m.chain_id(), 42);
}

#[test]
fn base_fee_round_trips() {
    let m = EvmModule::new(1, 10_000_000_000);
    assert_eq!(m.base_fee(), 10_000_000_000);
}

#[test]
fn handle_rejects_short_message() {
    let m = make_module();
    let result = m.handle(&dummy_ctx(), b"too short");
    assert!(matches!(result, Err(ExecError::Malformed)));
}

#[test]
fn handle_executes_signed_deploy() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    // Deploy a contract: `to` = Create, calldata = simple bytecode.
    let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
    let result = m.handle(&dummy_ctx(), &msg).expect("handle must succeed");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].module, "evm");
    assert_eq!(result[0].kind, "evm_call");
    // The sender's nonce must be 1 after a deploy.
    assert_eq!(m.nonce(&sender), 1, "sender nonce must be 1 after deploy");
}

#[test]
fn handle_rejects_wrong_chain_id() {
    let (privkey, _) = test_keypair();
    let m = EvmModule::new(42, 7); // chain ID 42
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce: 0,
            gas_limit: DEFAULT_GAS_LIMIT,
            to: tx::TxKind::Create,
            value: U256::ZERO,
            data: revm::primitives::Bytes::new(),
            chain_id: 1, // wrong chain ID
        },
        gas_price: U256::from(1_000_000_000),
    };
    let signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign must succeed");
    let msg = signed.encode_to_bytes();
    let result = m.handle(&dummy_ctx(), &msg);
    assert!(matches!(result, Err(ExecError::Malformed)), "wrong chain ID must reject");
}

#[test]
fn handle_rejects_invalid_signature() {
    let m = make_module();
    // A valid RLP-encoded legacy tx with a tampered signature.
    let (privkey, _) = test_keypair();
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce: 0,
            gas_limit: DEFAULT_GAS_LIMIT,
            to: tx::TxKind::Create,
            value: U256::ZERO,
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    let mut signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign must succeed");
    // Tamper with the signature.
    if let tx::SignedTx::Legacy(_, ref mut sig) = signed {
        sig.r = U256::ZERO; // invalid r
    }
    let msg = signed.encode_to_bytes();
    let result = m.handle(&dummy_ctx(), &msg);
    assert!(matches!(result, Err(ExecError::Malformed)), "invalid signature must reject");
}

#[test]
fn begin_block_does_not_panic() {
    let m = make_module();
    m.begin_block(Height::new(0));
}

#[test]
fn end_block_does_not_panic() {
    let m = make_module();
    m.end_block(Height::new(0));
}

#[test]
fn state_root_is_deterministic() {
    let m1 = make_module();
    let m2 = make_module();
    assert_eq!(m1.state_root(), m2.state_root(), "two fresh modules must have the same state root");
}

/// An empty EVM state must produce Ethereum's `EMPTY_ROOT_HASH`.
/// This is the most important MPT invariant: if our empty root
/// differs from mainnet, no state root will ever match.
#[test]
fn empty_state_root_matches_ethereum_constant() {
    let m = make_module();
    let root = m.state_root();
    // Ethereum's EMPTY_ROOT_HASH — the state root of a chain
    // with zero accounts.
    let expected = Hash([
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
        0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
        0xb4, 0x21,
    ]);
    assert_eq!(root, expected, "empty state root must match Ethereum's EMPTY_ROOT_HASH");
}

#[test]
fn balance_defaults_to_zero() {
    let m = make_module();
    assert_eq!(m.balance(&Address([0u8; 20])), 0);
}

#[test]
fn nonce_defaults_to_zero() {
    let m = make_module();
    assert_eq!(m.nonce(&Address([0u8; 20])), 0);
}

#[test]
fn state_root_changes_after_deploy() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    let root_before = m.state_root();
    let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
    m.handle(&dummy_ctx(), &msg).expect("deploy must succeed");
    let root_after = m.state_root();
    assert_ne!(root_before, root_after, "state root must change after a deploy");
}

#[test]
fn deploy_increases_caller_nonce() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    // Before any tx, the caller has no account (nonce 0).
    assert_eq!(m.nonce(&sender), 0);
    // Deploy a contract.
    let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
    m.handle(&dummy_ctx(), &msg).expect("deploy must succeed");
    // After a successful deploy, the caller's nonce must be 1.
    assert_eq!(m.nonce(&sender), 1, "caller nonce must be 1 after a deploy");
}

#[test]
fn sender_is_recovered_not_trusted() {
    // The EVM module must recover the sender from the signature,
    // not trust ctx.sender. We verify by setting ctx.sender to a
    // different address and checking that the recovered sender
    // (not ctx.sender) gets the nonce increment.
    let (privkey, real_sender) = test_keypair();
    let fake_sender = Address([0xFF; 20]);
    let m = make_module();
    fund(&m, &real_sender);
    let ctx = TxContext { sender: fake_sender, nonce: 999, fee: 999 };
    let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
    m.handle(&ctx, &msg).expect("deploy must succeed");
    // The real sender's nonce must be 1, not the fake sender's.
    assert_eq!(m.nonce(&real_sender), 1, "real sender nonce must be 1");
    assert_eq!(m.nonce(&fake_sender), 0, "fake sender nonce must stay 0");
}

// ---- A4: validate (mempool admission) tests ----------------------

#[test]
fn validate_accepts_well_formed_tx() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    // Fund the account so the balance check passes.
    m.fund_account_for_test(&sender, u128::MAX);
    let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
    assert!(m.validate(&dummy_ctx(), &msg).is_ok(), "well-formed tx must validate");
}

#[test]
fn validate_rejects_malformed_rlp() {
    let m = make_module();
    assert!(matches!(m.validate(&dummy_ctx(), b"not rlp"), Err(ExecError::Malformed)));
}

#[test]
fn validate_rejects_wrong_chain_id() {
    let (privkey, _) = test_keypair();
    let m = EvmModule::new(42, 7); // chain ID 42
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce: 0,
            gas_limit: DEFAULT_GAS_LIMIT,
            to: tx::TxKind::Create,
            value: U256::ZERO,
            data: revm::primitives::Bytes::new(),
            chain_id: 1, // wrong
        },
        gas_price: U256::from(1_000_000_000),
    };
    let signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign");
    let msg = signed.encode_to_bytes();
    assert!(matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::Malformed)));
}

#[test]
fn validate_rejects_bad_signature() {
    let (privkey, _) = test_keypair();
    let m = make_module();
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce: 0,
            gas_limit: DEFAULT_GAS_LIMIT,
            to: tx::TxKind::Create,
            value: U256::ZERO,
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    let mut signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign");
    if let tx::SignedTx::Legacy(_, ref mut sig) = signed {
        sig.r = U256::ZERO;
    }
    let msg = signed.encode_to_bytes();
    assert!(matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::Malformed)));
}

#[test]
fn validate_rejects_stale_nonce() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    m.fund_account_for_test(&sender, u128::MAX);
    // Execute nonce 0 (deploy).
    let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
    m.handle(&dummy_ctx(), &msg).expect("deploy");
    assert_eq!(m.nonce(&sender), 1);
    // Now validate a tx with nonce 0 (stale) — must reject.
    let stale_msg = signed_tx(&privkey, 0, tx::TxKind::Create, &data);
    assert!(matches!(m.validate(&dummy_ctx(), &stale_msg), Err(ExecError::ModuleRejected(_))));
}

#[test]
fn validate_accepts_future_nonce() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    m.fund_account_for_test(&sender, u128::MAX);
    // A tx with nonce 5 (future) should be accepted for mempool
    // queueing.
    let data = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];
    let msg = signed_tx(&privkey, 5, tx::TxKind::Create, &data);
    assert!(m.validate(&dummy_ctx(), &msg).is_ok(), "future nonce must validate");
}

#[test]
fn validate_rejects_zero_gas_limit() {
    let (privkey, _) = test_keypair();
    let m = make_module();
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce: 0,
            gas_limit: 0,
            to: tx::TxKind::Create,
            value: U256::ZERO,
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    let signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign");
    let msg = signed.encode_to_bytes();
    assert!(matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::ModuleRejected(_))));
}

#[test]
fn validate_rejects_insufficient_balance() {
    let (privkey, _) = test_keypair();
    let m = make_module();
    // A brand-new account has 0 balance. Any tx with gas_cost > 0
    // must be rejected.
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce: 0,
            gas_limit: DEFAULT_GAS_LIMIT,
            to: tx::TxKind::Create,
            value: U256::ZERO,
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000), // 1 gwei
    };
    let signed = tx::SignedTx::sign_legacy(tx, &privkey).expect("sign");
    let msg = signed.encode_to_bytes();
    // gas_cost = 30M * 1 gwei = 30M gwei = 0.03 ETH — but balance is 0.
    assert!(matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::ModuleRejected(_))));
}

/// The 1.5 regression at the execution trust boundary: a tx with
/// valid RLP followed by trailing junk must be `Malformed` at
/// `validate` — previously the executor's `Decodable::decode`
/// ignored the cursor remainder, so bytes the RPC parse rejected
/// were admitted and executed (with a tx hash computed over the
/// noncanonical encoding).
#[test]
fn validate_rejects_trailing_bytes_after_valid_rlp() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    let mut msg = signed_tx(&privkey, 0, tx::TxKind::Create, &[]);
    msg.push(0x00);
    assert!(
        matches!(m.validate(&dummy_ctx(), &msg), Err(ExecError::Malformed)),
        "trailing junk must be Malformed at the executor boundary too"
    );
}

/// Same boundary strictness through `handle` — the path a
/// proposed block's txs actually execute through.
#[test]
fn handle_rejects_trailing_bytes_after_valid_rlp() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    let mut msg = signed_tx(&privkey, 0, tx::TxKind::Create, &[]);
    msg.push(0x00);
    assert!(
        matches!(m.handle(&dummy_ctx(), &msg), Err(ExecError::Malformed)),
        "a tx with trailing junk must not execute"
    );
    // The canonical bytes still succeed — the bound rejects
    // noncanonical encodings, not valid transactions.
    let msg = signed_tx(&privkey, 0, tx::TxKind::Create, &[]);
    m.handle(&dummy_ctx(), &msg).expect("canonical tx must execute");
}

#[test]
fn handle_batch_executes_all_txs() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Build 10 transfer txs with incrementing nonces.
    let txs: Vec<Vec<u8>> = (0u64..10)
        .map(|i| {
            let tx = tx::TxLegacy {
                fields: tx::TxFields {
                    nonce: i,
                    gas_limit: DEFAULT_GAS_LIMIT,
                    to: tx::TxKind::Call(recipient),
                    value: U256::from(1_000_000_000),
                    data: revm::primitives::Bytes::new(),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            };
            tx::SignedTx::sign_legacy(tx, &privkey).expect("sign").encode_to_bytes()
        })
        .collect();

    let results = m.handle_batch(&dummy_ctx(), &txs);
    assert_eq!(results.len(), 10, "must return 10 results");
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "tx {i} must succeed");
    }
    assert_eq!(m.nonce(&sender), 10, "sender nonce must be 10");
    let oxide_recipient = primitives::Address(recipient.0.into());
    assert_eq!(m.balance(&oxide_recipient), 10_000_000_000, "recipient must have 10 * 1M");
}

#[test]
fn handle_batch_skips_invalid_txs() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Build a valid tx (nonce 0) and an invalid tx (wrong chain ID).
    let valid_tx = {
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Call(recipient),
                value: U256::from(1_000_000_000),
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000),
        };
        tx::SignedTx::sign_legacy(tx, &privkey).expect("sign").encode_to_bytes()
    };

    let invalid_tx = {
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 1,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Call(recipient),
                value: U256::from(1_000_000_000),
                data: revm::primitives::Bytes::new(),
                chain_id: 999, // wrong chain ID
            },
            gas_price: U256::from(1_000_000_000),
        };
        tx::SignedTx::sign_legacy(tx, &privkey).expect("sign").encode_to_bytes()
    };

    let txs = vec![valid_tx, invalid_tx];
    let results = m.handle_batch(&dummy_ctx(), &txs);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(), "valid tx must succeed");
    assert!(results[1].is_err(), "invalid tx must fail");
    assert_eq!(m.nonce(&sender), 1, "only the valid tx incremented nonce");
}

// ── Parallel speculative execution tests ──────────────────────

/// Build a signed transfer tx (test helper for parallel tests).
fn signed_transfer_tx(
    privkey: &[u8],
    nonce: u64,
    to: revm::primitives::Address,
    value: u128,
) -> Vec<u8> {
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce,
            gas_limit: DEFAULT_GAS_LIMIT,
            to: tx::TxKind::Call(to),
            value: U256::from(value),
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    tx::SignedTx::sign_legacy(tx, privkey).expect("sign").encode_to_bytes()
}

/// Parallel execution with multiple senders, distinct
/// recipients — the conflict-free fast path. State and nonces
/// must match serial execution.
#[test]
fn handle_batch_parallel_multi_sender_distinct_recipients() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let m = make_module();
    fund(&m, &addr_a);
    fund(&m, &addr_b);
    let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
    let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

    // Sender A -> recipient A (nonce 0)
    // Sender B -> recipient B (nonce 0)
    let txs = vec![
        signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
        signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
    ];

    let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(), "tx 0 must succeed");
    assert!(results[1].is_ok(), "tx 1 must succeed");
    assert_eq!(m.nonce(&addr_a), 1, "sender A nonce must be 1");
    assert_eq!(m.nonce(&addr_b), 1, "sender B nonce must be 1");
    let oxide_recipient_a = primitives::Address(recipient_a.0.into());
    let oxide_recipient_b = primitives::Address(recipient_b.0.into());
    assert_eq!(m.balance(&oxide_recipient_a), 1_000_000_000, "recipient A balance");
    assert_eq!(m.balance(&oxide_recipient_b), 1_000_000_000, "recipient B balance");
}

/// Parallel execution with mixed tx types (transfers + deployments)
/// must produce correct nonces. This reproduces the devnet load-test
/// scenario: multiple senders, each with a mix of transfers and
/// CREATE txs, executed through the parallel speculative path.
#[test]
fn handle_batch_parallel_mixed_tx_types_nonces() {
    let n_senders = 10;
    let txs_per_sender = 10;
    let mut keys = Vec::new();
    let mut addrs = Vec::new();
    for _ in 0..n_senders {
        let (pk, addr) = test_keypair();
        keys.push(pk);
        addrs.push(addr);
    }
    let recipient = revm::primitives::Address::from_slice(&[0x99; 20]);
    let deploy_bytecode = revm::primitives::Bytes::copy_from_slice(&[0x60, 0x80, 0x60, 0x40, 0x52]);

    // Build txs: each sender has a mix of transfers and deployments.
    // Nonces are sequential per sender.
    let mut txs = Vec::new();
    for (pk, _) in keys.iter().zip(addrs.iter()) {
        for nonce in 0..txs_per_sender {
            if nonce % 2 == 0 {
                // Transfer
                txs.push(signed_transfer_tx(pk, nonce, recipient, 1_000_000_000));
            } else {
                // Deploy
                txs.push(signed_tx(pk, nonce, tx::TxKind::Create, deploy_bytecode.as_ref()));
            }
        }
    }

    let m = make_module();
    for addr in &addrs {
        fund(&m, addr);
    }
    let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
    assert_eq!(results.len(), n_senders * usize::try_from(txs_per_sender).unwrap());
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "tx {i} must succeed");
    }
    // Each sender's nonce must be txs_per_sender.
    for (i, addr) in addrs.iter().enumerate() {
        let actual = m.nonce(addr);
        assert_eq!(
            actual, txs_per_sender,
            "sender {i} nonce must be {txs_per_sender}, got {actual}"
        );
    }
}

/// Regression test: parallel execution with conflicting groups
/// (multiple senders transferring to the same recipient) must
/// preserve nonce continuity. The tx-granular conflict
/// re-execution path previously broke nonce continuity by not
/// applying non-conflicting txs' state changes to the main DB
/// before re-executing conflicting txs, causing `NonceTooHigh`
/// failures.
#[test]
fn handle_batch_parallel_conflict_nonce_continuity() {
    let n_senders = 10;
    let txs_per_sender = 5;
    let mut keys = Vec::new();
    let mut addrs = Vec::new();
    for _ in 0..n_senders {
        let (pk, addr) = test_keypair();
        keys.push(pk);
        addrs.push(addr);
    }
    // All senders transfer to the SAME recipient — this creates
    // a write-write conflict on the recipient account, forcing
    // the conflict re-execution path.
    let shared_recipient = revm::primitives::Address::from_slice(&[0x99; 20]);

    let mut txs = Vec::new();
    for (pk, _) in keys.iter().zip(addrs.iter()) {
        for nonce in 0..txs_per_sender {
            txs.push(signed_transfer_tx(pk, nonce, shared_recipient, 1_000_000_000));
        }
    }

    let m = make_module();
    for addr in &addrs {
        fund(&m, addr);
    }
    let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
    assert_eq!(results.len(), n_senders * usize::try_from(txs_per_sender).unwrap());
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "tx {i} must succeed");
    }
    // Each sender's nonce must be txs_per_sender.
    for (i, addr) in addrs.iter().enumerate() {
        let actual = m.nonce(addr);
        assert_eq!(
            actual, txs_per_sender,
            "sender {i} nonce must be {txs_per_sender}, got {actual}"
        );
    }
}

/// Parallel execution must produce the same state root as serial
/// execution for the same multi-sender workload.
#[test]
fn handle_batch_parallel_matches_serial_state_root() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
    let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

    // Serial module.
    let m_serial = make_module();
    fund(&m_serial, &addr_a);
    fund(&m_serial, &addr_b);
    let txs = vec![
        signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
        signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
    ];
    m_serial.begin_block(Height::new(1));
    for raw in &txs {
        m_serial.handle(&dummy_ctx(), raw).expect("serial tx must succeed");
    }
    m_serial.end_block(Height::new(1));
    let serial_root = m_serial.state_root();

    // Parallel module.
    let m_par = make_module();
    fund(&m_par, &addr_a);
    fund(&m_par, &addr_b);
    m_par.begin_block(Height::new(1));
    let results = m_par.handle_batch_parallel(&dummy_ctx(), &txs);
    m_par.end_block(Height::new(1));
    let parallel_root = m_par.state_root();

    assert!(results.iter().all(std::result::Result::is_ok), "all parallel txs must succeed");
    assert_eq!(serial_root, parallel_root, "state roots must match");
}

/// The native fast path (simple transfers bypass revm) must
/// produce identical state roots to the revm path. This is the
/// correctness invariant: native is an optimization, not a
/// semantic change.
#[test]
fn native_transfer_matches_revm_state_root() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Path 1: handle() — uses revm for every tx.
    let m1 = make_module();
    fund(&m1, &addr);
    let tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
    m1.begin_block(Height::new(1));
    m1.handle(&dummy_ctx(), &tx).expect("revm tx must succeed");
    m1.end_block(Height::new(1));
    let root1 = m1.state_root();

    // Path 2: handle_batch() — uses native fast path for simple
    // transfers (empty calldata, EOA recipient).
    let m2 = make_module();
    fund(&m2, &addr);
    m2.begin_block(Height::new(1));
    m2.handle_batch(&dummy_ctx(), std::slice::from_ref(&tx));
    m2.end_block(Height::new(1));
    let root2 = m2.state_root();

    assert_eq!(root1, root2, "revm and native state roots must match");
}

/// Native fast path with multiple transfers from the same sender.
/// Verifies nonce sequencing and balance deductions match revm.
#[test]
fn native_transfer_multi_tx_matches_revm() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let txs: Vec<Vec<u8>> =
        (0..5).map(|nonce| signed_transfer_tx(&pk, nonce, recipient, 1_000_000_000)).collect();

    // Path 1: handle() per tx — uses revm.
    let m1 = make_module();
    fund(&m1, &addr);
    m1.begin_block(Height::new(1));
    for raw in &txs {
        m1.handle(&dummy_ctx(), raw).expect("revm tx must succeed");
    }
    m1.end_block(Height::new(1));
    let root1 = m1.state_root();

    // Path 2: handle_batch() — uses native fast path.
    let m2 = make_module();
    fund(&m2, &addr);
    m2.begin_block(Height::new(1));
    m2.handle_batch(&dummy_ctx(), &txs);
    m2.end_block(Height::new(1));
    let root2 = m2.state_root();

    assert_eq!(root1, root2, "revm and native state roots must match");
}

/// Native fast path should NOT activate for contract calls
/// (non-empty calldata). The tx must fall through to revm.
/// The fast paths must never answer a precompile call.
///
/// A precompile has no account code, so the "no code ⇒ plain
/// transfer / empty call" shortcuts previously treated it as an EOA:
/// the call reported success with no output, skipping the
/// precompile's execution and charging calldata gas instead of
/// precompile gas. `sha256` (0x02) called with empty input must
/// return the 32-byte digest of empty input — the shortcut returned
/// nothing, which is a consensus-visible divergence from every other
/// EVM.
#[test]
fn precompile_recipients_are_excluded_from_fast_paths() {
    // Ethereum's set, taken from revm so a future EIP precompile is
    // covered without editing this list.
    for byte in 1u8..=0x0a {
        let mut addr = [0u8; 20];
        addr[19] = byte;
        assert!(
            EvmModule::recipient_is_precompile(
                &revm::primitives::Address::from(addr),
                SpecId::PRAGUE
            ),
            "0x{byte:02x} is an Ethereum precompile and must not take a fast path"
        );
    }
    // Oxide's native precompiles live in their own address space, so
    // revm's set does not know about them.
    let native = crate::precompiles::precompile_address(0x0C, 0x01);
    assert!(
        EvmModule::recipient_is_precompile(
            &revm::primitives::Address::from(native.0),
            SpecId::PRAGUE
        ),
        "the native staking precompile must be excluded from fast paths"
    );
    // An ordinary account is not a precompile.
    assert!(
        !EvmModule::recipient_is_precompile(
            &revm::primitives::Address::from([0x42u8; 20]),
            SpecId::PRAGUE
        ),
        "a plain EOA must keep taking the fast path"
    );
}

/// Differential test for the same fix: a call to a precompile must
/// produce the same state root whether it executes through revm
/// (`handle`) or through the batch fast paths (`handle_batch`).
///
/// A precompile has no account code, so before this fix the "no code
/// ⇒ plain transfer" shortcut answered the call itself: the
/// precompile never ran, so `sha256` returned nothing instead of the
/// 32-byte digest, and the sender was charged the flat 21 000
/// transfer gas instead of the precompile's own schedule. Both the
/// output and the sender's balance differ, and the balance lands in
/// the state root — a consensus-visible divergence from every other
/// EVM.
///
/// Empty calldata is the case that exposes it: with calldata, Prague's
/// EIP-7623 floor dominates the intrinsic cost and can mask the
/// precompile's gas, but a bare call to `sha256` has nothing to hide
/// behind.
#[test]
fn precompile_call_matches_revm_state_root() {
    let (pk, addr) = test_keypair();
    let precompile = revm::primitives::Address::from_slice(&{
        let mut a = [0u8; 20];
        a[19] = 0x02; // sha256 precompile
        a
    });
    let tx = signed_tx(&pk, 0, tx::TxKind::Call(precompile), &[]);

    // Path 1: handle() — executes the call through revm.
    let m1 = make_module();
    fund(&m1, &addr);
    m1.begin_block(Height::new(1));
    m1.handle(&dummy_ctx(), &tx).expect("revm tx must succeed");
    m1.end_block(Height::new(1));
    let root1 = m1.state_root();

    // Path 2: handle_batch() — tries the fast paths first.
    let m2 = make_module();
    fund(&m2, &addr);
    m2.begin_block(Height::new(1));
    m2.handle_batch(&dummy_ctx(), std::slice::from_ref(&tx));
    m2.end_block(Height::new(1));
    let root2 = m2.state_root();

    assert_eq!(root1, root2, "a precompile call must not be answered by the empty-code fast path");
}

#[test]
fn native_transfer_skipped_for_calldata() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Build a tx with non-empty calldata — should NOT take the
    // native fast path.
    let tx = signed_tx(&pk, 0, tx::TxKind::Call(recipient), &[0x01, 0x02, 0x03]);

    // handle_batch should still succeed (falls through to revm).
    let m = make_module();
    fund(&m, &addr);
    m.begin_block(Height::new(1));
    let results = m.handle_batch(&dummy_ctx(), &[tx]);
    m.end_block(Height::new(1));

    // The tx should succeed (revm handles the call to a
    // non-existent contract — it just executes the CALL opcode
    // with no code to run, which succeeds).
    assert!(
        results.iter().all(std::result::Result::is_ok),
        "calldata tx should succeed via revm fallback"
    );
}

/// `try_empty_code_call` fast path: a call with calldata to an
/// EOA (no code) should produce the same state root as revm.
/// This is the differential test for the empty-code call fast
/// path — it verifies that the native gas calculation and state
/// changes match revm exactly.
#[test]
fn empty_code_call_matches_revm_state_root() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Build a tx with non-empty calldata to an EOA (no code).
    // This triggers `try_empty_code_call` in the batch path.
    let calldata = [0x60, 0xfe, 0x47, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let tx = signed_tx(&pk, 0, tx::TxKind::Call(recipient), &calldata);

    // Path 1: handle() — uses revm for the call.
    let m1 = make_module();
    fund(&m1, &addr);
    m1.begin_block(Height::new(1));
    m1.handle(&dummy_ctx(), &tx).expect("revm tx must succeed");
    m1.end_block(Height::new(1));
    let root1 = m1.state_root();

    // Path 2: handle_batch() — uses try_empty_code_call fast path.
    let m2 = make_module();
    fund(&m2, &addr);
    m2.begin_block(Height::new(1));
    m2.handle_batch(&dummy_ctx(), std::slice::from_ref(&tx));
    m2.end_block(Height::new(1));
    let root2 = m2.state_root();

    assert_eq!(root1, root2, "revm and empty-code-call state roots must match");
}

/// `try_empty_code_call` with multiple txs from the same sender.
/// Verifies nonce sequencing and gas deductions match revm.
#[test]
fn empty_code_call_multi_tx_matches_revm() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let calldata = [0x6d, 0x4c, 0xe6, 0x3c]; // get() selector
    let txs: Vec<Vec<u8>> =
        (0..5).map(|nonce| signed_tx(&pk, nonce, tx::TxKind::Call(recipient), &calldata)).collect();

    // Path 1: handle() per tx — uses revm.
    let m1 = make_module();
    fund(&m1, &addr);
    m1.begin_block(Height::new(1));
    for raw in &txs {
        m1.handle(&dummy_ctx(), raw).expect("revm tx must succeed");
    }
    m1.end_block(Height::new(1));
    let root1 = m1.state_root();

    // Path 2: handle_batch() — uses try_empty_code_call fast path.
    let m2 = make_module();
    fund(&m2, &addr);
    m2.begin_block(Height::new(1));
    m2.handle_batch(&dummy_ctx(), &txs);
    m2.end_block(Height::new(1));
    let root2 = m2.state_root();

    assert_eq!(root1, root2, "revm and empty-code-call multi-tx state roots must match");
}

/// Parallel execution with conflicting recipients (two senders
/// transfer to the same recipient). The conflict must be detected
/// and the second group re-executed sequentially. The final
/// recipient balance must be the sum of both transfers.
#[test]
fn handle_batch_parallel_conflict_same_recipient() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let m = make_module();
    fund(&m, &addr_a);
    fund(&m, &addr_b);
    let shared_recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Both senders transfer to the SAME recipient -> conflict.
    let txs = vec![
        signed_transfer_tx(&pk_a, 0, shared_recipient, 1_000_000_000),
        signed_transfer_tx(&pk_b, 0, shared_recipient, 2_000_000_000),
    ];

    let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(), "tx 0 must succeed");
    assert!(results[1].is_ok(), "tx 1 must succeed");
    let oxide_recipient = primitives::Address(shared_recipient.0.into());
    assert_eq!(
        m.balance(&oxide_recipient),
        3_000_000_000,
        "recipient must have sum of both transfers"
    );
}

/// Parallel execution with conflicting recipients must produce the
/// same state root as serial execution.
#[test]
fn handle_batch_parallel_conflict_matches_serial_state_root() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let shared_recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let txs = vec![
        signed_transfer_tx(&pk_a, 0, shared_recipient, 1_000_000_000),
        signed_transfer_tx(&pk_b, 0, shared_recipient, 2_000_000_000),
    ];

    // Serial.
    let m_serial = make_module();
    fund(&m_serial, &addr_a);
    fund(&m_serial, &addr_b);
    m_serial.begin_block(Height::new(1));
    for raw in &txs {
        m_serial.handle(&dummy_ctx(), raw).expect("serial tx");
    }
    m_serial.end_block(Height::new(1));
    let serial_root = m_serial.state_root();

    // Parallel.
    let m_par = make_module();
    fund(&m_par, &addr_a);
    fund(&m_par, &addr_b);
    m_par.begin_block(Height::new(1));
    let results = m_par.handle_batch_parallel(&dummy_ctx(), &txs);
    m_par.end_block(Height::new(1));
    let parallel_root = m_par.state_root();

    assert!(results.iter().all(std::result::Result::is_ok), "all parallel txs must succeed");
    assert_eq!(serial_root, parallel_root, "conflict state roots must match");
}

/// Parallel execution with multiple nonces per sender. Each
/// sender's txs must execute in nonce order within the group.
#[test]
fn handle_batch_parallel_multi_nonce_per_sender() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let m = make_module();
    fund(&m, &addr_a);
    fund(&m, &addr_b);
    let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
    let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

    // Sender A: 3 txs (nonces 0, 1, 2)
    // Sender B: 2 txs (nonces 0, 1)
    let txs = vec![
        signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
        signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
        signed_transfer_tx(&pk_a, 1, recipient_a, 1_000_000_000),
        signed_transfer_tx(&pk_b, 1, recipient_b, 1_000_000_000),
        signed_transfer_tx(&pk_a, 2, recipient_a, 1_000_000_000),
    ];

    let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
    assert_eq!(results.len(), 5);
    assert!(results.iter().all(std::result::Result::is_ok), "all txs must succeed");
    assert_eq!(m.nonce(&addr_a), 3, "sender A nonce must be 3");
    assert_eq!(m.nonce(&addr_b), 2, "sender B nonce must be 2");
    let oxide_recipient_a = primitives::Address(recipient_a.0.into());
    assert_eq!(m.balance(&oxide_recipient_a), 3_000_000_000, "recipient A balance");
    let oxide_recipient_b = primitives::Address(recipient_b.0.into());
    assert_eq!(m.balance(&oxide_recipient_b), 2_000_000_000, "recipient B balance");
}

/// Parallel execution with a single sender falls back to
/// `handle_batch` (no parallelism, but must be correct).
#[test]
fn handle_batch_parallel_single_sender_fallback() {
    let (pk, addr) = test_keypair();
    let m = make_module();
    fund(&m, &addr);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let txs: Vec<Vec<u8>> =
        (0..5).map(|i| signed_transfer_tx(&pk, i, recipient, 1_000_000_000)).collect();

    let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
    assert_eq!(results.len(), 5);
    assert!(results.iter().all(std::result::Result::is_ok), "all txs must succeed");
    assert_eq!(m.nonce(&addr), 5, "nonce must be 5");
    let oxide_recipient = primitives::Address(recipient.0.into());
    assert_eq!(m.balance(&oxide_recipient), 5_000_000_000, "recipient balance");
}

/// Parallel execution with empty batch returns empty results.
#[test]
fn handle_batch_parallel_empty_batch() {
    let m = make_module();
    let results = m.handle_batch_parallel(&dummy_ctx(), &Vec::<&[u8]>::new());
    assert!(results.is_empty());
}

/// Parallel execution with invalid txs mixed in. Invalid txs
/// must not affect valid txs.
#[test]
fn handle_batch_parallel_skips_invalid_txs() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let m = make_module();
    fund(&m, &addr_a);
    fund(&m, &addr_b);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let valid_a = signed_transfer_tx(&pk_a, 0, recipient, 1_000_000_000);
    let valid_b = signed_transfer_tx(&pk_b, 0, recipient, 1_000_000_000);

    // Invalid tx: wrong chain ID.
    let invalid_tx = {
        let tx = tx::TxLegacy {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: DEFAULT_GAS_LIMIT,
                to: tx::TxKind::Call(recipient),
                value: U256::from(1_000_000_000),
                data: revm::primitives::Bytes::new(),
                chain_id: 999,
            },
            gas_price: U256::from(1_000_000_000),
        };
        tx::SignedTx::sign_legacy(tx, &pk_a).expect("sign").encode_to_bytes()
    };

    let txs = vec![valid_a, invalid_tx, valid_b];
    let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok(), "valid tx 0 must succeed");
    assert!(results[1].is_err(), "invalid tx must fail");
    assert!(results[2].is_ok(), "valid tx 2 must succeed");
}

/// Parallel execution determinism: running the same batch twice
/// must produce the same state root.
#[test]
fn handle_batch_parallel_deterministic_state_root() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
    let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

    let txs = vec![
        signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
        signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
    ];

    // Run 1.
    let m1 = make_module();
    fund(&m1, &addr_a);
    fund(&m1, &addr_b);
    m1.begin_block(Height::new(1));
    m1.handle_batch_parallel(&dummy_ctx(), &txs);
    m1.end_block(Height::new(1));
    let root1 = m1.state_root();

    // Run 2.
    let m2 = make_module();
    fund(&m2, &addr_a);
    fund(&m2, &addr_b);
    m2.begin_block(Height::new(1));
    m2.handle_batch_parallel(&dummy_ctx(), &txs);
    m2.end_block(Height::new(1));
    let root2 = m2.state_root();

    assert_eq!(root1, root2, "state roots must be deterministic");
}

// ── Pre-verified sender recovery tests ──────────────────────

/// `preverify_batch` recovers senders correctly: the
/// pre-recovered address matches what `SignedTx::recover_sender`
/// would produce.
#[test]
fn preverify_batch_recovers_correct_senders() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);
    let m = make_module();

    let txs = vec![
        signed_transfer_tx(&pk, 0, recipient, 1_000_000_000),
        signed_transfer_tx(&pk, 1, recipient, 1_000_000_000),
    ];

    let preverified = m.preverify_batch(&txs);
    assert_eq!(preverified.len(), 2, "must return one result per tx");
    for (i, pv) in preverified.iter().enumerate() {
        let pv = pv.as_ref().expect("valid tx must preverify");
        let expected = alloy_primitives_address(addr.0);
        assert_eq!(pv.sender, expected, "pre-recovered sender must match keypair address");
        assert_eq!(pv.raw, txs[i], "raw bytes must be preserved");
    }
}

/// `preverify_batch` rejects malformed transactions.
#[test]
fn preverify_batch_rejects_malformed() {
    let m = make_module();
    let garbage = vec![vec![0xff, 0xff, 0xff]];
    let preverified = m.preverify_batch(&garbage);
    assert_eq!(preverified.len(), 1);
    assert!(preverified[0].is_err(), "malformed tx must fail preverify");
}

/// `handle_batch_preverified` produces identical state roots to
/// `handle_batch` (which recovers senders internally). This is the
/// core correctness invariant: pre-verified recovery is an
/// optimization, not a semantic change.
#[test]
fn preverified_matches_recovery_state_root() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let txs: Vec<Vec<u8>> =
        (0..10).map(|i| signed_transfer_tx(&pk, i, recipient, 1_000_000_000)).collect();

    // Path 1: handle_batch (recovers senders internally).
    let m1 = make_module();
    fund(&m1, &addr);
    m1.begin_block(Height::new(1));
    m1.handle_batch(&dummy_ctx(), &txs);
    m1.end_block(Height::new(1));
    let root1 = m1.state_root();

    // Path 2: preverify + handle_batch_preverified.
    let m2 = make_module();
    fund(&m2, &addr);
    let preverified: Vec<PreverifiedTx<'_>> =
        m2.preverify_batch(&txs).into_iter().map(|r| r.expect("preverify must succeed")).collect();
    m2.begin_block(Height::new(1));
    m2.handle_batch_preverified(&dummy_ctx(), &preverified);
    m2.end_block(Height::new(1));
    let root2 = m2.state_root();

    assert_eq!(root1, root2, "pre-verified and recovery state roots must match");
}

/// `handle_batch_parallel_preverified` produces identical state
/// roots to `handle_batch_parallel` (which recovers senders
/// internally). This verifies the pre-verified path is correct
/// for the parallel speculative execution algorithm.
#[test]
fn preverified_parallel_matches_recovery_parallel_state_root() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let recipient_a = revm::primitives::Address::from_slice(&[0x42; 20]);
    let recipient_b = revm::primitives::Address::from_slice(&[0x43; 20]);

    let txs = vec![
        signed_transfer_tx(&pk_a, 0, recipient_a, 1_000_000_000),
        signed_transfer_tx(&pk_b, 0, recipient_b, 1_000_000_000),
        signed_transfer_tx(&pk_a, 1, recipient_a, 1_000_000_000),
        signed_transfer_tx(&pk_b, 1, recipient_b, 1_000_000_000),
    ];

    // Path 1: handle_batch_parallel (recovers senders internally).
    let m1 = make_module();
    fund(&m1, &addr_a);
    fund(&m1, &addr_b);
    m1.begin_block(Height::new(1));
    m1.handle_batch_parallel(&dummy_ctx(), &txs);
    m1.end_block(Height::new(1));
    let root1 = m1.state_root();

    // Path 2: preverify + handle_batch_parallel_preverified.
    let m2 = make_module();
    fund(&m2, &addr_a);
    fund(&m2, &addr_b);
    let preverified: Vec<PreverifiedTx<'_>> =
        m2.preverify_batch(&txs).into_iter().map(|r| r.expect("preverify must succeed")).collect();
    m2.begin_block(Height::new(1));
    m2.handle_batch_parallel_preverified(&dummy_ctx(), &preverified);
    m2.end_block(Height::new(1));
    let root2 = m2.state_root();

    assert_eq!(root1, root2, "pre-verified parallel and recovery parallel state roots must match");
}

/// `handle_batch_preverified` with an empty batch returns an empty
/// result vector (no panic).
#[test]
fn preverified_empty_batch() {
    let m = make_module();
    let results = m.handle_batch_preverified(&dummy_ctx(), &[]);
    assert!(results.is_empty(), "empty batch must return empty results");
}

/// `handle_batch_parallel_preverified` with an empty batch returns
/// an empty result vector (no panic).
#[test]
fn preverified_parallel_empty_batch() {
    let m = make_module();
    let results = m.handle_batch_parallel_preverified(&dummy_ctx(), &[]);
    assert!(results.is_empty(), "empty batch must return empty results");
}

/// `handle_batch_preverified` skips invalid txs without aborting
/// the batch (same semantics as `handle_batch`).
#[test]
fn preverified_skips_invalid_txs() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let valid_tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
    let garbage = vec![0xff_u8; 10];

    let m = make_module();
    fund(&m, &addr);

    // Pre-verify: the valid tx succeeds, the garbage fails.
    let raw_txs = vec![valid_tx.clone(), garbage];
    let preverified: Vec<PreverifiedTx<'_>> =
        m.preverify_batch(&raw_txs).into_iter().filter_map(std::result::Result::ok).collect();
    assert_eq!(preverified.len(), 1, "only the valid tx should preverify");

    m.begin_block(Height::new(1));
    let results = m.handle_batch_preverified(&dummy_ctx(), &preverified);
    m.end_block(Height::new(1));

    assert_eq!(results.len(), 1, "one tx in, one result out");
    assert!(results[0].is_ok(), "valid tx must succeed");
    assert_eq!(m.nonce(&addr), 1, "nonce must increment for the valid tx");
}

// ── EVM integration: full pipeline ingest→propose→finalize ──

/// Build a signed legacy EVM transfer tx (test helper for
/// integration tests).
fn pipeline_signed_transfer(
    privkey: &[u8],
    nonce: u64,
    to: revm::primitives::Address,
    value: u128,
) -> Vec<u8> {
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce,
            gas_limit: 100_000,
            to: tx::TxKind::Call(to),
            value: U256::from(value),
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    tx::SignedTx::sign_legacy(tx, privkey).expect("sign must succeed").encode_to_bytes()
}

/// The full EVM pipeline: submit signed EVM txs through the
/// executor's mempool, propose a block, finalize it, and verify
/// the state root is non-zero (the EVM executed the txs).
///
/// This is the integration test that proves the pipeline is wired:
/// `ingest_tx` → mempool → `prepare_proposal` → `process_proposal`
/// → `finalize_block` → `execute_block` → EVM `handle_batch` →
/// state root.
#[test]
fn evm_txs_through_executor_pipeline() {
    use ports::AppInterface;
    use std::sync::Arc;

    let (privkey, addr) = test_keypair();
    let oxide_addr = Address(addr.0);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Build the executor with an EVM module.
    let evm_module = EvmModule::new(1, 7);
    evm_module.fund_account_for_test(&oxide_addr, u128::MAX);
    let mut executor = executor::Executor::new(1000);
    executor.register_module(Arc::new(evm_module));

    // Build 3 signed EVM transfer txs and wrap them in the v0
    // envelope format for the mempool.
    for nonce in 0..3u64 {
        let rlp = pipeline_signed_transfer(&privkey, nonce, recipient, 1_000_000_000);
        let envelope = wrap_evm_tx_envelope(&oxide_addr, nonce, 1_000_000_000, &rlp);
        let ack = executor.ingest_tx(types::TxBytes::new(envelope));
        assert!(
            matches!(ack, types::MempoolAck::Accepted),
            "EVM tx {nonce} must be accepted by mempool"
        );
    }

    // Prepare a proposal — the mempool should select all 3 txs.
    let budget = types::CHAIN_BLOCK_BUDGET;
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 3, "mempool must select all 3 EVM txs");

    // Process the proposal — should be accepted (all txs are valid).
    match executor.process_proposal(&proposal) {
        types::Verdict::Accept => {}
        types::Verdict::Reject { reason } => panic!("proposal must be accepted: {reason}"),
    }

    // Finalize the block — executes the EVM txs.
    let block = types::FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(0),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    let ack = executor.finalize_block(&block);
    assert_eq!(ack.height, Height::new(0));

    // The state root must be non-zero — the EVM executed the txs
    // and changed the state (sender balance decreased, recipient
    // balance increased, nonce advanced).
    let attestation = executor.attest_state(Height::new(0)).expect("executed");
    assert_ne!(
        attestation.root,
        primitives::Hash::ZERO,
        "state root must be non-zero after EVM execution"
    );
}

/// EVM txs through the full `SequencerEngine` pipeline: submit →
/// propose → finalize → attest, driven by the consensus engine.
#[test]
fn evm_txs_through_sequencer_engine_pipeline() {
    use ports::ConsensusEngine;
    use std::sync::Arc;

    let (privkey, addr) = test_keypair();
    let oxide_addr = Address(addr.0);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let evm_module = EvmModule::new(1, 7);
    evm_module.fund_account_for_test(&oxide_addr, u128::MAX);
    let mut executor = executor::Executor::new(1000);
    executor.register_module(Arc::new(evm_module));

    let app: Arc<dyn ports::AppInterface> = Arc::new(executor);
    let mut engine = consensus::SequencerEngine::new(app);

    // Submit 3 EVM txs through the engine.
    for nonce in 0..3u64 {
        let rlp = pipeline_signed_transfer(&privkey, nonce, recipient, 1_000_000_000);
        let envelope = wrap_evm_tx_envelope(&oxide_addr, nonce, 1_000_000_000, &rlp);
        engine.submit_tx(types::TxBytes::new(envelope));
    }
    engine.run_until_idle();

    // The engine should have finalized a block.
    assert!(engine.finalized_height().is_some(), "engine must finalize a block");

    // The state root must be non-zero.
    let app = engine.app();
    let attestation = app.attest_state(Height::new(0)).expect("executed");
    assert_ne!(
        attestation.root,
        primitives::Hash::ZERO,
        "state root must be non-zero after EVM execution through engine"
    );
}

/// EVM pipeline with 5 txs produces a different state root than
/// an empty block. This proves the EVM txs are actually executed
/// through the pipeline (not silently skipped).
#[test]
fn evm_pipeline_state_root_differs_from_empty_block() {
    use ports::AppInterface;
    use std::sync::Arc;

    let (privkey, addr) = test_keypair();
    let oxide_addr = Address(addr.0);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Path 1: executor with 5 EVM txs.
    let evm_module = EvmModule::new(1, 7);
    evm_module.fund_account_for_test(&oxide_addr, u128::MAX);
    let mut executor = executor::Executor::new(1000);
    executor.register_module(Arc::new(evm_module));

    for nonce in 0..5u64 {
        let rlp = pipeline_signed_transfer(&privkey, nonce, recipient, 1_000_000_000);
        let envelope = wrap_evm_tx_envelope(&oxide_addr, nonce, 1_000_000_000, &rlp);
        executor.ingest_tx(types::TxBytes::new(envelope));
    }
    let budget = types::CHAIN_BLOCK_BUDGET;
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 5, "mempool must select all 5 EVM txs");
    let block = types::FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: proposal.txs,
        signers: Vec::new(),
    };
    executor.finalize_block(&block);
    let tx_root = executor.attest_state(Height::new(1)).expect("executed").root;

    // Path 2: executor with an empty block (same EVM module, same
    // funding, but no txs).
    let evm_module_empty = EvmModule::new(1, 7);
    evm_module_empty.fund_account_for_test(&oxide_addr, u128::MAX);
    let mut exec_empty = executor::Executor::new(1000);
    exec_empty.register_module(Arc::new(evm_module_empty));
    let empty_block = types::FinalizedBlock {
        context: types::BlockContext::default(),
        height: Height::new(1),
        txs: vec![],
        signers: Vec::new(),
    };
    exec_empty.finalize_block(&empty_block);
    let empty_root = exec_empty.attest_state(Height::new(1)).expect("executed").root;

    assert_ne!(tx_root, empty_root, "pipeline with 5 EVM txs must differ from empty block");
}

// ---- Read-write conflict detection (hardening) -------------------
//
// These tests prove the parallel path detects read-write conflicts
// (Group B reads an account Group A wrote) and re-executes to match
// serial execution. Without `accessed_accounts` tracking, the
// conflict would be missed and Group B would commit stale state.

/// Read-write conflict: Group A writes to account R (via native
/// transfer), Group B reads R's balance (via BALANCE opcode in
/// contract D) and stores it in D's storage. Without read-set
/// tracking, Group B would not detect the conflict and would
/// commit with R's stale balance. The fix adds `accessed_accounts`
/// tracking, which includes all accounts in the group's cache
/// (read + write), enabling read-write conflict detection.
#[test]
fn handle_batch_parallel_read_write_conflict_matches_serial() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let (pk_deploy, addr_deploy) = test_keypair();

    // R is a random EOA that will receive ETH from sender A.
    let recipient_r = revm::primitives::Address::from_slice(&[0x99; 20]);

    // Contract D runtime bytecode: reads an address from calldata
    // (offset 0), gets its balance via BALANCE, and stores the
    // balance in slot 0.
    //   PUSH1 0x00  (60 00)  - calldata offset 0
    //   CALLDATALOAD (35)    - load 32 bytes (address in lower 20)
    //   BALANCE     (31)     - get balance of the address
    //   PUSH1 0x00  (60 00)  - slot 0
    //   SSTORE      (55)     - store balance in slot 0
    //   STOP        (00)
    //
    // Init code: copies the 8-byte runtime code to memory and
    // returns it.
    //   PUSH1 0x08  (60 08)  - runtime code length (8 bytes)
    //   PUSH1 0x0c  (60 0c)  - runtime code offset (12 = init len)
    //   PUSH1 0x00  (60 00)  - destination offset in memory (0)
    //   CODECOPY    (39)     - copy runtime code to memory
    //   PUSH1 0x08  (60 08)  - runtime code length (8 bytes)
    //   PUSH1 0x00  (60 00)  - memory offset (0)
    //   RETURN      (f3)     - return runtime code from memory
    let d_init_code: Vec<u8> = vec![
        0x60, 0x08, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x08, 0x60, 0x00, 0xf3, 0x60, 0x00, 0x35,
        0x31, 0x60, 0x00, 0x55, 0x00,
    ];

    // Fund R with an initial balance so the BALANCE opcode reads a
    // non-zero value. This makes the read-write conflict observable:
    // without the fix, Group B reads R's stale (pre-A) balance; with
    // the fix, Group B re-executes and reads R's updated balance.
    let oxide_r = primitives::Address(recipient_r.0.into());

    // Compute D's address (deployer at nonce 0).
    let d_address = revm::primitives::Address::from_slice(&addr_deploy.0).create(0);

    // Build the deploy tx and test txs once.
    let deploy_tx = signed_tx(&pk_deploy, 0, tx::TxKind::Create, &d_init_code);
    let tx_a = signed_transfer_tx(&pk_a, 0, recipient_r, 1_000_000_000);
    let mut calldata = [0u8; 32];
    calldata[12..].copy_from_slice(recipient_r.as_slice());
    let tx_b = signed_tx(&pk_b, 0, tx::TxKind::Call(d_address), &calldata);

    // --- Serial execution ---
    let m_serial = make_module();
    fund(&m_serial, &addr_a);
    fund(&m_serial, &addr_b);
    fund(&m_serial, &addr_deploy);
    m_serial.fund_account_for_test(&oxide_r, 1_000_000_000);
    m_serial.begin_block(Height::new(1));
    m_serial.handle(&dummy_ctx(), &deploy_tx).expect("deploy D (serial)");
    m_serial.handle(&dummy_ctx(), &tx_a).expect("serial tx A");
    m_serial.handle(&dummy_ctx(), &tx_b).expect("serial tx B");
    m_serial.end_block(Height::new(1));
    let serial_root = m_serial.state_root();

    // --- Parallel execution ---
    let m_par = make_module();
    fund(&m_par, &addr_a);
    fund(&m_par, &addr_b);
    fund(&m_par, &addr_deploy);
    m_par.fund_account_for_test(&oxide_r, 1_000_000_000);
    m_par.begin_block(Height::new(1));
    // Deploy D first (serial, before the parallel batch).
    m_par.handle(&dummy_ctx(), &deploy_tx).expect("deploy D (parallel)");
    // Run txs A and B in parallel.
    let txs = vec![tx_a.clone(), tx_b.clone()];
    let results = m_par.handle_batch_parallel(&dummy_ctx(), &txs);
    m_par.end_block(Height::new(1));
    let parallel_root = m_par.state_root();

    assert!(results.iter().all(std::result::Result::is_ok), "all txs must succeed");
    assert_eq!(
        serial_root, parallel_root,
        "read-write conflict: parallel state root must match serial"
    );
}

/// Interleaved sender ordering — the `A0, B0, A1` case the audit
/// flagged: sender-grouped speculation effectively ran `A0, A1,
/// B0`, and group-order commit merged `A1`'s result — computed
/// without `B0`'s writes — before `B` ever ran. Canonical-order
/// commit validates `A1` at its true position (index 2), detects
/// that `B0` wrote the account `A1` reads, and re-executes `A1`
/// against the canonical state.
///
/// Contract D reads `BALANCE(R)` into its storage slot 0, so the
/// stale-vs-canonical divergence is directly observable in state.
#[test]
fn handle_batch_parallel_interleaved_senders_matches_serial() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let (pk_deploy, addr_deploy) = test_keypair();

    // R is an EOA that B0 funds; D stores R's balance in slot 0.
    let recipient_r = revm::primitives::Address::from_slice(&[0x99; 20]);
    // A0's recipient — deliberately disjoint from R so the only
    // cross-group dependency is B0 → A1.
    let other = revm::primitives::Address::from_slice(&[0x77; 20]);

    // Contract D runtime: CALLDATALOAD(0) → BALANCE → SSTORE(0)
    // — identical to the read-write conflict test above.
    let d_init_code: Vec<u8> = vec![
        0x60, 0x08, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x08, 0x60, 0x00, 0xf3, 0x60, 0x00, 0x35,
        0x31, 0x60, 0x00, 0x55, 0x00,
    ];
    let d_address = revm::primitives::Address::from_slice(&addr_deploy.0).create(0);
    let oxide_d = primitives::Address(d_address.0.into());

    let deploy_tx = signed_tx(&pk_deploy, 0, tx::TxKind::Create, &d_init_code);
    // A0: touches only `other` — no dependency on B0 or R.
    let tx_a0 = signed_transfer_tx(&pk_a, 0, other, 5);
    // B0: funds R — canonically precedes A1.
    let tx_b0 = signed_transfer_tx(&pk_b, 0, recipient_r, 1_000_000_000);
    // A1: reads R's balance into D's slot 0. Canonical order says
    // it must observe B0's transfer; group-order commit merged
    // the pre-B0 read.
    let mut calldata = [0u8; 32];
    calldata[12..].copy_from_slice(recipient_r.as_slice());
    let tx_a1 = signed_tx(&pk_a, 1, tx::TxKind::Call(d_address), &calldata);

    // --- Serial execution ---
    let m_serial = make_module();
    fund(&m_serial, &addr_a);
    fund(&m_serial, &addr_b);
    fund(&m_serial, &addr_deploy);
    m_serial.begin_block(Height::new(1));
    m_serial.handle(&dummy_ctx(), &deploy_tx).expect("deploy D (serial)");
    m_serial.handle(&dummy_ctx(), &tx_a0).expect("serial A0");
    m_serial.handle(&dummy_ctx(), &tx_b0).expect("serial B0");
    m_serial.handle(&dummy_ctx(), &tx_a1).expect("serial A1");
    m_serial.end_block(Height::new(1));
    let serial_root = m_serial.state_root();
    let serial_slot0 = m_serial.storage_at(&oxide_d, &revm::primitives::U256::ZERO);

    // --- Parallel execution ---
    let m_par = make_module();
    fund(&m_par, &addr_a);
    fund(&m_par, &addr_b);
    fund(&m_par, &addr_deploy);
    m_par.begin_block(Height::new(1));
    m_par.handle(&dummy_ctx(), &deploy_tx).expect("deploy D (parallel)");
    // Canonical order A0, B0, A1 — A0 and A1 share a sender, so
    // speculation groups them together.
    let txs = vec![tx_a0, tx_b0, tx_a1];
    let results = m_par.handle_batch_parallel(&dummy_ctx(), &txs);
    m_par.end_block(Height::new(1));
    let parallel_root = m_par.state_root();
    let parallel_slot0 = m_par.storage_at(&oxide_d, &revm::primitives::U256::ZERO);

    assert!(results.iter().all(std::result::Result::is_ok), "all txs must succeed");
    assert_eq!(
        serial_slot0, parallel_slot0,
        "A1 must observe R's post-B0 balance, not the pre-block balance"
    );
    assert_eq!(serial_root, parallel_root, "interleaved state roots must match");
}

/// Speculative native-precompile safety: a mutating staking
/// precompile inside a speculative run must never touch the
/// shared `StakingModule`, and the suppressed call must force
/// canonical re-execution — not a committed stale revert.
///
/// The batch `A0(delegate call), B0(transfer), A1(transfer)`
/// interleaves three positions: `A0` re-executes because its
/// delegate precompile was suppressed (`native_blocked`), `A1`
/// re-executes on the same-sender cascade, and `B0` merges
/// speculatively. Final delegation must be exactly the one the
/// canonical `A0` applied: `0` would mean the speculative revert
/// was committed; `2_000` would mean speculation leaked into
/// shared state on top of the canonical application.
#[test]
fn handle_batch_parallel_native_precompile_no_speculative_mutation() {
    let (pk_a, addr_a) = test_keypair();
    let (pk_b, addr_b) = test_keypair();
    let contract = Address([0xC0; 20]);
    let validator = Address([0xAA; 20]);
    let (m, staking_mod) = staking_wired_module(
        contract,
        10_000,
        delegate_then_revert_runtime(validator.0, 1_000, false),
    );
    staking_mod.register_validator(validator);
    fund(&m, &addr_a);
    fund(&m, &addr_b);

    let contract_evm = revm::primitives::Address::from_slice(&contract.0);
    let other = revm::primitives::Address::from_slice(&[0x77; 20]);
    // A0: call the contract → delegate precompile (suppressed in
    // speculation, applied for real in canonical re-execution).
    let tx_a0 = signed_tx(&pk_a, 0, tx::TxKind::Call(contract_evm), &[]);
    // B0: independent transfer — merges speculatively.
    let tx_b0 = signed_transfer_tx(&pk_b, 0, other, 7);
    // A1: same-sender successor — re-executes on the cascade.
    let tx_a1 = signed_transfer_tx(&pk_a, 1, other, 3);

    m.begin_block(Height::new(1));
    let txs = vec![tx_a0, tx_b0, tx_a1];
    let results = m.handle_batch_parallel(&dummy_ctx(), &txs);
    m.end_block(Height::new(1));

    assert!(results.iter().all(std::result::Result::is_ok), "all txs must succeed");
    assert_eq!(
        staking_mod.delegation(&contract, &validator),
        1_000,
        "canonical re-execution must apply the delegation exactly once"
    );
    assert_eq!(staking_mod.stake(&validator), 1_000);
    assert_eq!(
        Balances::balance(m.as_ref(), &contract),
        9_000,
        "the canonical bond must debit the delegator"
    );
    assert_eq!(Balances::balance(m.as_ref(), &staking::BONDED_POOL), 1_000);
    assert_eq!(m.nonce(&addr_a), 2, "A0 and A1 both committed");
    assert_eq!(m.nonce(&addr_b), 1, "B0 committed");
}

/// Regression test: a byzantine proposer supplying a wrong
/// pre-recovered sender must be rejected. `handle_batch_preverified`
/// re-recovers the sender from the signature and checks it
/// matches `pv.sender`. A mismatch returns `ExecError::Malformed`.
#[test]
fn preverified_rejects_wrong_sender() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let txs: Vec<Vec<u8>> =
        (0..1).map(|i| signed_transfer_tx(&pk, i, recipient, 1_000_000_000)).collect();

    // Pre-verify to get the correct sender.
    let m = make_module();
    let preverified: Vec<PreverifiedTx<'_>> =
        m.preverify_batch(&txs).into_iter().map(|r| r.expect("preverify must succeed")).collect();

    // Tamper: replace the sender with a wrong address.
    let wrong_addr = revm::primitives::Address::from_slice(&[0x99; 20]);
    let tampered: Vec<PreverifiedTx<'_>> = preverified
        .into_iter()
        .map(|pv| PreverifiedTx { raw: pv.raw, sender: wrong_addr })
        .collect();

    // Execute: must reject the tampered sender.
    m.begin_block(Height::new(1));
    let results = m.handle_batch_preverified(&dummy_ctx(), &tampered);
    m.end_block(Height::new(1));

    assert!(
        results.iter().all(|r| matches!(r, Err(ExecError::Malformed))),
        "wrong sender must be rejected with Malformed"
    );
    // The real sender's balance must be untouched.
    assert_eq!(m.balance(&addr), 0, "no state change on rejected tx");
}

/// Regression test: a byzantine proposer supplying a wrong
/// pre-recovered sender must be rejected in the parallel path too.
#[test]
fn preverified_parallel_rejects_wrong_sender() {
    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let txs: Vec<Vec<u8>> =
        (0..2).map(|i| signed_transfer_tx(&pk, i, recipient, 1_000_000_000)).collect();

    let m = make_module();
    let preverified: Vec<PreverifiedTx<'_>> =
        m.preverify_batch(&txs).into_iter().map(|r| r.expect("preverify must succeed")).collect();

    let wrong_addr = revm::primitives::Address::from_slice(&[0x99; 20]);
    let tampered: Vec<PreverifiedTx<'_>> = preverified
        .into_iter()
        .map(|pv| PreverifiedTx { raw: pv.raw, sender: wrong_addr })
        .collect();

    m.begin_block(Height::new(1));
    let results = m.handle_batch_parallel_preverified(&dummy_ctx(), &tampered);
    m.end_block(Height::new(1));

    assert!(
        results.iter().all(|r| matches!(r, Err(ExecError::Malformed))),
        "wrong sender must be rejected with Malformed (parallel)"
    );
    assert_eq!(m.balance(&addr), 0, "no state change on rejected tx");
}

/// Regression test: `flush_to_storage` emits `Op::Delete` for
/// self-destructed accounts so they don't reappear on reload.
#[test]
fn flush_emits_delete_for_selfdestructed() {
    use storage::Volatile;

    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    // Create a module with a Volatile backend.
    let backend = Box::new(Volatile::new());
    let m = EvmModule::with_storage(1, 7, backend);
    fund(&m, &addr);

    // Execute a transfer to touch the sender account.
    let tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
    m.begin_block(Height::new(1));
    let results = m.handle_batch(&dummy_ctx(), &[tx]);
    assert!(results.iter().all(Result::is_ok), "tx must succeed: {results:?}");
    m.end_block(Height::new(1));

    // The sender account should be persisted.
    let oxide_addr = primitives::Address(addr.0);
    let key = persist::account_key(&oxide_addr);
    {
        let backend_guard = m.backend.lock().expect("backend lock");
        let backend_ref = backend_guard.as_ref().expect("backend is Some");
        assert!(backend_ref.get(&key).is_some(), "account must be persisted");
    }

    // Now check that a Delete op is emitted when the account
    // becomes NotExisting. We simulate this by directly
    // manipulating the cache.
    let evm_addr = alloy_primitives_address(addr.0);
    m.begin_block(Height::new(2));
    {
        let mut db = m.db.lock().expect("db lock");
        let db = Arc::make_mut(&mut *db);
        if let Some(account) = db.cache.accounts.get_mut(&evm_addr) {
            account.account_state = revm::database::AccountState::NotExisting;
        }
        m.touched.lock().expect("touched lock").insert(evm_addr);
    }
    m.end_block(Height::new(2));

    // The account should now be deleted from storage.
    {
        let backend_guard = m.backend.lock().expect("backend lock");
        let backend_ref = backend_guard.as_ref().expect("backend is Some");
        assert!(backend_ref.get(&key).is_none(), "self-destructed account must be deleted");
    }
}

/// Regression test: `flush_to_storage` serializes storage slots
/// in sorted order so the persisted blob is deterministic.
#[test]
fn flush_serializes_slots_in_sorted_order() {
    use storage::Volatile;

    let (pk, addr) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);

    let backend = Box::new(Volatile::new());
    let m = EvmModule::with_storage(1, 7, backend);
    fund(&m, &addr);

    // Execute a transfer to touch the sender account.
    let tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
    m.begin_block(Height::new(1));
    let results = m.handle_batch(&dummy_ctx(), &[tx]);
    assert!(results.iter().all(Result::is_ok), "tx must succeed: {results:?}");
    m.end_block(Height::new(1));

    // Read the persisted value and verify it's deterministic.
    // The account should have no storage slots (EOA), so this
    // tests the serialization path without slot ordering.
    let oxide_addr = primitives::Address(addr.0);
    let key = persist::account_key(&oxide_addr);
    let value1 = {
        let backend_guard = m.backend.lock().expect("backend lock");
        let backend_ref = backend_guard.as_ref().expect("backend is Some");
        backend_ref.get(&key).expect("account must be persisted")
    };

    // Reload and re-flush — the value must be byte-identical.
    let backend2 = Box::new(Volatile::new());
    let m2 = EvmModule::with_storage(1, 7, backend2);
    fund(&m2, &addr);
    let tx2 = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
    m2.begin_block(Height::new(1));
    let results2 = m2.handle_batch(&dummy_ctx(), &[tx2]);
    assert!(results2.iter().all(Result::is_ok), "tx must succeed: {results2:?}");
    m2.end_block(Height::new(1));

    let value2 = {
        let backend_guard = m2.backend.lock().expect("backend lock");
        let backend_ref = backend_guard.as_ref().expect("backend is Some");
        backend_ref.get(&key).expect("account must be persisted")
    };

    assert_eq!(value1, value2, "persisted value must be deterministic");
}

/// Regression test: the touched-account set must contain EVERY
/// account a tx modifies — not just `caller`/`to`/`created`/
/// `coinbase`.
/// A SELFDESTRUCT beneficiary is a third-party account: under the
/// old top-level-only tracking it was updated in the `CacheDB` but
/// never marked touched, so `flush_to_storage` skipped it and the
/// incremental state root reused its stale storage root —
/// diverging durable state from in-memory state.
#[test]
fn selfdestruct_beneficiary_is_tracked_as_touched() {
    let (pk_caller, addr_caller) = test_keypair();
    let (pk_deploy, addr_deploy) = test_keypair();
    let beneficiary = revm::primitives::Address::from_slice(&[0xBB; 20]);
    let oxide_beneficiary = primitives::Address(beneficiary.0.into());

    // Runtime code: PUSH20 <beneficiary> ; SELFDESTRUCT — sends
    // the contract's whole balance to `beneficiary` and removes
    // the contract.
    //   0x73 <20 bytes> = PUSH20, 0xff = SELFDESTRUCT (22 bytes)
    // Init code: copy 22-byte runtime (at offset 12) and return it.
    //   PUSH1 0x16 PUSH1 0x0c PUSH1 0x00 CODECOPY PUSH1 0x16
    //   PUSH1 0x00 RETURN (12 bytes)
    let mut deploy_data: Vec<u8> =
        vec![0x60, 0x16, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, 0x16, 0x60, 0x00, 0xf3, 0x73];
    deploy_data.extend_from_slice(beneficiary.as_slice());
    deploy_data.push(0xff);

    let contract_addr = revm::primitives::Address::from_slice(&addr_deploy.0).create(0);
    let oxide_contract = primitives::Address(contract_addr.0.into());

    let m = make_module();
    fund(&m, &addr_caller);
    fund(&m, &addr_deploy);
    m.begin_block(Height::new(1));
    m.handle(&dummy_ctx(), &signed_tx(&pk_deploy, 0, tx::TxKind::Create, &deploy_data))
        .expect("deploy must succeed");

    // Give the contract a balance to selfdestruct away.
    m.fund_account_for_test(&oxide_contract, 5_000_000_000);

    // Call the contract — runs SELFDESTRUCT, paying the
    // beneficiary (a third-party account absent from the old
    // touched set). Assert *before* `end_block`: `end_block`
    // consumes the set for the storage flush and the incremental
    // state root, then clears it so the executor's aggregate
    // `state_root` call hits the O(1) cached path.
    let call = signed_tx(&pk_caller, 0, tx::TxKind::Call(contract_addr), &[]);
    m.handle(&dummy_ctx(), &call).expect("call must succeed");

    assert!(
        framework::lock_state(&m.touched).contains(&beneficiary),
        "selfdestruct beneficiary must be tracked as touched"
    );
    m.end_block(Height::new(1));
    assert_eq!(
        m.balance(&oxide_beneficiary),
        5_000_000_000,
        "beneficiary must receive the contract balance"
    );
}

/// Regression test: `balance()` must not panic on a U256 balance
/// above `u128::MAX` (reachable via crafted snapshot import). The
/// accessor saturates rather than crashing the node.
#[test]
fn balance_saturates_above_u128() {
    let m = make_module();
    let evm_addr = revm::primitives::Address::from_slice(&[0xCC; 20]);
    let oxide_addr = primitives::Address(evm_addr.0.into());

    // Insert an account with a U256::MAX balance directly —
    // beyond what `fund_account_for_test` (u128) can express.
    {
        let mut db_guard = framework::lock_state(&m.db);
        let db = Arc::make_mut(&mut *db_guard);
        db.cache.accounts.insert(
            evm_addr,
            revm::database::DbAccount {
                info: revm::database::state::AccountInfo {
                    balance: U256::MAX,
                    nonce: 0,
                    code_hash: revm::primitives::B256::ZERO,
                    account_id: None,
                    code: Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::new())),
                },
                account_state: revm::database::AccountState::None,
                storage: revm::primitives::HashMap::default(),
            },
        );
    }

    // Previously `to::<u128>()` panicked here.
    assert_eq!(m.balance(&oxide_addr), u128::MAX);
}

/// Regression test: `estimate_gas` must return the tx's declared
/// `gas_limit`, not the `1000 + len` size proxy — a 30M-gas tx
/// must count as 30M gas toward the block limit. Undecodable
/// payloads count as `u64::MAX` (un-includable, fail-safe).
#[test]
fn estimate_gas_returns_declared_limit() {
    let m = make_module();
    let (pk, _) = test_keypair();
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);
    let raw = signed_tx(&pk, 0, tx::TxKind::Call(recipient), &[]);
    assert_eq!(m.estimate_gas(&raw), DEFAULT_GAS_LIMIT);
    // Undecodable payload → u64::MAX (any block containing it is
    // over-limit → rejected, fail-safe direction).
    assert_eq!(m.estimate_gas(&[0xff, 0x00]), u64::MAX);
}

/// The EVM is self-funded: revm charges `gas_used × effective
/// gas price` from the sender inside execution (bounded below
/// by the block base fee). The envelope fee must not be charged
/// on top — that would double-charge every EVM user.
#[test]
fn evm_module_pays_own_fee() {
    let m = make_module();
    assert!(m.pays_own_fee());
}

/// `charge_fee` collects the envelope fee into the configured
/// recipient (staking's `FEE_POOL` in production wiring) when
/// one is set — the collection half of the distribution loop.
/// Without a recipient the fee burns: sender debited, nobody
/// credited (Ethereum base-fee semantics).
#[test]
fn charge_fee_collects_or_burns() {
    use framework::Balances;
    let sender = primitives::Address([0xAA; 20]);
    let pool = primitives::Address(*b"oxide/staking/fee!!!");

    // Recipient wired → transfer: sender −fee, pool +fee.
    let m = make_module().with_fee_recipient(pool);
    m.fund_account_for_test(&sender, u128::from(1_000u64) * framework::WEI_PER_UNIT);
    let ctx = TxContext { sender: primitives::Address([0xAA; 20]), nonce: 0, fee: 5 };
    m.charge_fee(&ctx).unwrap();
    assert_eq!(Balances::balance(&m, &pool), 5, "pool must collect the fee");
    assert_eq!(Balances::balance(&m, &sender), 995, "sender loses the fee");

    // No recipient → burn: sender −fee, total supply shrinks.
    let m = make_module();
    m.fund_account_for_test(&sender, u128::from(1_000u64) * framework::WEI_PER_UNIT);
    m.charge_fee(&ctx).unwrap();
    assert_eq!(Balances::balance(&m, &sender), 995);
    assert_eq!(Balances::balance(&m, &pool), 0, "nothing collects the burn");

    // Zero fee → no ledger touch (fresh-sender admission).
    let ctx0 = TxContext { fee: 0, ..ctx };
    m.charge_fee(&ctx0).unwrap();
}

// ───────────────────────────────────────────────────────────
// Ceiling 3: sparse state-root regression tests.
//
// These tests verify that the sparse incremental walk produces
// the same state root as a full rebuild, across insertions,
// deletions, mutations, and at scale (1k–100k accounts). The
// 1M-account case is covered by the benchmark gate
// (`state_root_incremental/1M_accts_*_touched`).
// ───────────────────────────────────────────────────────────

/// Build N deterministic test addresses.
fn make_addrs(n: usize) -> Vec<primitives::Address> {
    (0..n)
        .map(|i| {
            let mut a = [0u8; 20];
            a[..8].copy_from_slice(&(i as u64).to_be_bytes());
            primitives::Address(a)
        })
        .collect()
}

/// Compute the "ground truth" state root by forcing a full
/// rebuild (resets the leaf cache + retained branches so the
/// next `state_root` call walks every leaf from scratch).
fn full_rebuild_root(m: &EvmModule) -> Hash {
    m.reset_leaf_cache_for_test();
    executor::Module::state_root(m)
}

/// Sparse root must match full rebuild after a single mutation.
#[test]
fn sparse_root_matches_full_after_single_mutation() {
    let m = EvmModule::with_storage(1, 1_000_000_000, Box::new(storage::Volatile::new()));
    let addrs = make_addrs(1_000);
    for a in &addrs {
        m.fund_account_for_test(a, 1_000_000);
    }
    // First call = full build (warms the leaf map + retained branches).
    let root0 = executor::Module::state_root(&m);

    // Touch one account and recompute.
    m.mark_touched_for_test(&addrs[0]);
    m.fund_account_for_test(&addrs[0], 2_000_000);
    let root1 = executor::Module::state_root(&m);

    // Must differ (balance changed).
    assert_ne!(root1, root0, "root must change after mutation");

    // Must match a full rebuild.
    let truth = full_rebuild_root(&m);
    assert_eq!(root1, truth, "sparse root must match full rebuild");
}

/// Sparse root must match full rebuild after touching 100
/// accounts in a 10k-account state.
#[test]
fn sparse_root_matches_full_10k_100_touched() {
    let m = EvmModule::with_storage(1, 1_000_000_000, Box::new(storage::Volatile::new()));
    let addrs = make_addrs(10_000);
    for a in &addrs {
        m.fund_account_for_test(a, 1_000_000);
    }
    executor::Module::state_root(&m); // full build

    for (i, a) in addrs[..100].iter().enumerate() {
        m.mark_touched_for_test(a);
        m.fund_account_for_test(a, 1_000_000 + i as u128);
    }
    let root = executor::Module::state_root(&m);
    let truth = full_rebuild_root(&m);
    assert_eq!(root, truth, "sparse root must match full rebuild at 10k/100");
}

/// Sparse root must match full rebuild after touching 100
/// accounts in a 100k-account state.
#[test]
fn sparse_root_matches_full_100k_100_touched() {
    let m = EvmModule::with_storage(1, 1_000_000_000, Box::new(storage::Volatile::new()));
    let addrs = make_addrs(100_000);
    for a in &addrs {
        m.fund_account_for_test(a, 1_000_000);
    }
    executor::Module::state_root(&m); // full build

    for (i, a) in addrs[..100].iter().enumerate() {
        m.mark_touched_for_test(a);
        m.fund_account_for_test(a, 1_000_000 + i as u128);
    }
    let root = executor::Module::state_root(&m);
    let truth = full_rebuild_root(&m);
    assert_eq!(root, truth, "sparse root must match full rebuild at 100k/100");
}

/// Sparse root must match full rebuild after multiple
/// incremental rounds (each round touches a different set).
#[test]
fn sparse_root_matches_full_multiple_rounds() {
    let m = EvmModule::with_storage(1, 1_000_000_000, Box::new(storage::Volatile::new()));
    let addrs = make_addrs(5_000);
    for a in &addrs {
        m.fund_account_for_test(a, 1_000_000);
    }
    executor::Module::state_root(&m); // full build

    // 10 rounds, each touching 50 accounts.
    for round in 0..10u128 {
        let offset = (round as usize) * 50;
        for (i, a) in addrs[offset..offset + 50].iter().enumerate() {
            m.mark_touched_for_test(a);
            m.fund_account_for_test(a, 1_000_000 + round * 100 + i as u128);
        }
        let root = executor::Module::state_root(&m);
        let truth = full_rebuild_root(&m);
        assert_eq!(root, truth, "sparse root must match full rebuild at round {round}");
    }
}

/// Sparse root must match full rebuild after account insertion
/// (new account not in the previous build).
#[test]
fn sparse_root_matches_full_after_insertion() {
    let m = EvmModule::with_storage(1, 1_000_000_000, Box::new(storage::Volatile::new()));
    let addrs = make_addrs(1_000);
    for a in &addrs {
        m.fund_account_for_test(a, 1_000_000);
    }
    executor::Module::state_root(&m); // full build

    // Insert a new account whose hashed key may create a new
    // branch child (the address is outside the original range).
    let new_addr = {
        let mut a = [0u8; 20];
        a[..8].copy_from_slice(&(0xDEAD_BEEFu64).to_be_bytes());
        primitives::Address(a)
    };
    m.fund_account_for_test(&new_addr, 1_000_000);
    m.mark_touched_for_test(&new_addr);
    let root = executor::Module::state_root(&m);
    let truth = full_rebuild_root(&m);
    assert_eq!(root, truth, "sparse root must match full rebuild after insertion");
}

/// Sparse root must match full rebuild after touching the same
/// account twice (idempotent re-touch).
#[test]
fn sparse_root_matches_full_retouch() {
    let m = EvmModule::with_storage(1, 1_000_000_000, Box::new(storage::Volatile::new()));
    let addrs = make_addrs(500);
    for a in &addrs {
        m.fund_account_for_test(a, 1_000_000);
    }
    executor::Module::state_root(&m);

    m.mark_touched_for_test(&addrs[0]);
    m.fund_account_for_test(&addrs[0], 2_000_000);
    executor::Module::state_root(&m);

    // Touch the same account again.
    m.mark_touched_for_test(&addrs[0]);
    m.fund_account_for_test(&addrs[0], 3_000_000);
    let root = executor::Module::state_root(&m);
    let truth = full_rebuild_root(&m);
    assert_eq!(root, truth, "sparse root must match full rebuild after retouch");
}

/// Sparse root must match full rebuild when touching accounts
/// that share a long key prefix (same branch subtree).
#[test]
fn sparse_root_matches_full_same_subtree() {
    let m = EvmModule::with_storage(1, 1_000_000_000, Box::new(storage::Volatile::new()));
    let addrs = make_addrs(2_000);
    for a in &addrs {
        m.fund_account_for_test(a, 1_000_000);
    }
    executor::Module::state_root(&m);

    // Touch 10 consecutive accounts (likely in the same subtree).
    for (i, a) in addrs[..10].iter().enumerate() {
        m.mark_touched_for_test(a);
        m.fund_account_for_test(a, 1_000_000 + i as u128);
    }
    let root = executor::Module::state_root(&m);
    let truth = full_rebuild_root(&m);
    assert_eq!(root, truth, "sparse root must match full rebuild in same subtree");
}

/// Sparse root must match full rebuild when touching accounts
/// spread across the entire key space (different subtrees).
#[test]
fn sparse_root_matches_full_spread_subtrees() {
    let m = EvmModule::with_storage(1, 1_000_000_000, Box::new(storage::Volatile::new()));
    let addrs = make_addrs(10_000);
    for a in &addrs {
        m.fund_account_for_test(a, 1_000_000);
    }
    executor::Module::state_root(&m);

    // Touch every 100th account — spread across the key space.
    for (i, a) in addrs.iter().step_by(100).enumerate() {
        m.mark_touched_for_test(a);
        m.fund_account_for_test(a, 1_000_000 + i as u128);
    }
    let root = executor::Module::state_root(&m);
    let truth = full_rebuild_root(&m);
    assert_eq!(root, truth, "sparse root must match full rebuild across subtrees");
}

/// `prefix_range` must produce correct inclusive bounds.
#[test]
fn prefix_range_correct_bounds() {
    use alloy_primitives::B256;

    // Empty prefix: start=0, end=MAX.
    let (s, e) = prefix_range(&alloy_trie::Nibbles::default());
    assert_eq!(s, B256::ZERO);
    assert_eq!(e, B256::repeat_byte(0xFF));

    // Single nibble 0: start=00..00, end=0F..FF.
    let mut p = alloy_trie::Nibbles::default();
    p.push(0x0);
    let (s, e) = prefix_range(&p);
    assert_eq!(s, B256::ZERO);
    let mut expected_end = [0xFFu8; 32];
    expected_end[0] = 0x0F;
    assert_eq!(e, B256::from_slice(&expected_end));

    // Single nibble F: start=F0..00, end=FF..FF.
    let mut p = alloy_trie::Nibbles::default();
    p.push(0xF);
    let (s, e) = prefix_range(&p);
    let mut expected_start = [0u8; 32];
    expected_start[0] = 0xF0;
    assert_eq!(s, B256::from_slice(&expected_start));
    assert_eq!(e, B256::repeat_byte(0xFF));

    // Two nibbles C, 9: start=C9..00, end=C9..FF.
    let mut p = alloy_trie::Nibbles::default();
    p.push(0xC);
    p.push(0x9);
    let (s, e) = prefix_range(&p);
    let mut expected_start = [0u8; 32];
    expected_start[0] = 0xC9;
    assert_eq!(s, B256::from_slice(&expected_start));
    let mut expected_end = [0xFFu8; 32];
    expected_end[0] = 0xC9;
    assert_eq!(e, B256::from_slice(&expected_end));
}

// ── call_read / estimate_call_gas / history tests ────────────────

/// Runtime: PUSH1 0x2a PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00
/// RETURN — returns the 32-byte word 42.
const RETURN42_RUNTIME: [u8; 10] = [0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3];
/// Runtime: PUSH1 0x00 PUSH1 0x00 REVERT — always reverts, no data.
const REVERT_RUNTIME: [u8; 5] = [0x60, 0x00, 0x60, 0x00, 0xfd];
/// Runtime: PUSH1 0x01 PUSH1 0x00 SSTORE STOP — writes slot 0 = 1.
const SSTORE_RUNTIME: [u8; 6] = [0x60, 0x01, 0x60, 0x00, 0x55, 0x00];

/// Build deploy initcode: `PUSH1 <len> PUSH1 0x0c PUSH1 0x00
/// CODECOPY PUSH1 <len> PUSH1 0x00 RETURN` + runtime.
fn deploy_initcode(runtime: &[u8]) -> Vec<u8> {
    let len = u8::try_from(runtime.len()).expect("test runtime < 256 bytes");
    let mut code = vec![0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3];
    code.extend_from_slice(runtime);
    code
}

/// Deploy `runtime` as a contract at block `h` and return its
/// address (sender.create(nonce)).
fn deploy_contract(
    m: &EvmModule,
    pk: &[u8],
    caller: &Address,
    runtime: &[u8],
) -> revm::primitives::Address {
    let initcode = deploy_initcode(runtime);
    let msg = signed_tx(pk, 0, tx::TxKind::Create, &initcode);
    m.handle(&dummy_ctx(), &msg).expect("deploy must succeed");
    let evm_caller = alloy_primitives_address(caller.0);
    evm_caller.create(0)
}

fn call_req(to: revm::primitives::Address, data: &[u8]) -> CallRequest {
    CallRequest { to: Some(Address(*to.0)), data: data.to_vec(), ..CallRequest::default() }
}

#[test]
fn call_read_returns_contract_output() {
    let (pk, caller) = test_keypair();
    let m = make_module();
    fund(&m, &caller);
    m.begin_block(Height::new(1));
    let contract = deploy_contract(&m, &pk, &caller, &RETURN42_RUNTIME);
    let out = m.call_read(&call_req(contract, &[])).expect("call must succeed");
    let mut expected = [0u8; 32];
    expected[31] = 0x2a;
    assert_eq!(out.output, expected, "eth_call must return the contract's data");
    assert!(out.gas_used > 21_000, "contract call costs more than a transfer");
}

#[test]
fn call_read_revert_carries_data() {
    let (pk, caller) = test_keypair();
    let m = make_module();
    fund(&m, &caller);
    m.begin_block(Height::new(1));
    let contract = deploy_contract(&m, &pk, &caller, &REVERT_RUNTIME);
    match m.call_read(&call_req(contract, &[])) {
        Err(CallError::Revert { output, gas_used }) => {
            assert!(output.is_empty());
            assert!(gas_used > 0);
        }
        other => panic!("expected CallError::Revert, got {other:?}"),
    }
}

#[test]
fn call_read_never_persists_state() {
    let (pk, caller) = test_keypair();
    let m = make_module();
    fund(&m, &caller);
    m.begin_block(Height::new(1));
    let contract = deploy_contract(&m, &pk, &caller, &SSTORE_RUNTIME);
    // Simulated SSTORE must not land in state — eth_call is
    // strictly read-only even though the EVM "wrote" slot 0.
    let oxide_contract = Address(*contract.0);
    m.call_read(&call_req(contract, &[])).expect("call must succeed");
    assert_eq!(
        m.storage_at(&oxide_contract, &revm::primitives::U256::ZERO),
        revm::primitives::U256::ZERO,
        "simulated SSTORE must not persist"
    );
    assert_eq!(m.code(&oxide_contract), SSTORE_RUNTIME.to_vec());
}

#[test]
fn estimate_call_gas_simple_transfer() {
    let (_, caller) = test_keypair();
    let (_, to) = test_keypair();
    let m = make_module();
    fund(&m, &caller);
    m.begin_block(Height::new(1));
    let req = CallRequest {
        from: Some(caller),
        to: Some(to),
        value: revm::primitives::U256::from(1u64),
        ..CallRequest::default()
    };
    assert_eq!(
        m.estimate_call_gas(&req).expect("estimate must succeed"),
        21_000,
        "plain value transfer estimates at intrinsic cost"
    );
}

#[test]
fn estimate_call_gas_contract_call() {
    let (pk, caller) = test_keypair();
    let m = make_module();
    fund(&m, &caller);
    m.begin_block(Height::new(1));
    let contract = deploy_contract(&m, &pk, &caller, &RETURN42_RUNTIME);
    let mut req = call_req(contract, &[]);
    req.from = Some(caller);
    let est = m.estimate_call_gas(&req).expect("estimate must succeed");
    assert!((21_000..=100_000).contains(&est), "return-42 call: got {est}");
}

#[test]
fn estimate_call_gas_reverting_call_errors() {
    let (pk, caller) = test_keypair();
    let m = make_module();
    fund(&m, &caller);
    m.begin_block(Height::new(1));
    let contract = deploy_contract(&m, &pk, &caller, &REVERT_RUNTIME);
    let mut req = call_req(contract, &[]);
    req.from = Some(caller);
    match m.estimate_call_gas(&req) {
        Err(CallError::Revert { .. }) => {}
        other => panic!("always-reverting call must error, got {other:?}"),
    }
}

#[test]
fn call_read_zero_balance_caller_with_value_fails() {
    let (_, broke) = test_keypair();
    let (_, to) = test_keypair();
    let m = make_module();
    m.begin_block(Height::new(1));
    // Balance check stays enabled in the sim env (geth `DoCall`
    // semantics): a zero-balance caller cannot send value.
    let req = CallRequest {
        from: Some(broke),
        to: Some(to),
        value: revm::primitives::U256::from(1u64),
        ..CallRequest::default()
    };
    assert!(
        matches!(m.call_read(&req), Err(CallError::Rejected(_))),
        "zero-balance value transfer must be rejected"
    );
    // Same caller with no value and no gas price costs nothing —
    // geth allows this (unsigned calls default gasPrice=0).
    let req = CallRequest { from: Some(broke), to: Some(to), ..CallRequest::default() };
    assert!(m.call_read(&req).is_ok(), "no-value no-fee call must succeed");
}

#[test]
fn history_records_block_transactions_and_logs() {
    let (pk, caller) = test_keypair();
    let (_, recipient) = test_keypair();
    let m = make_module();
    fund(&m, &caller);
    m.begin_block(Height::new(7));

    let to = tx::TxKind::Call(revm::primitives::Address::from_slice(&recipient.0));
    let tx0 = signed_tx(&pk, 0, to, &[]);
    let tx1 = signed_tx(&pk, 1, to, &[0xaa, 0xbb]); // calldata → non-native path
    let res = m.handle_batch(&dummy_ctx(), &[tx0.clone(), tx1.clone()]);
    assert!(res.iter().all(Result::is_ok), "both txs must execute: {res:?}");
    m.end_block(Height::new(7));

    let h = m.history();
    let block = h.block(7).expect("block 7 sealed");
    assert_eq!(block.txs.len(), 2, "two executed txs recorded");
    assert_eq!(block.receipts.len(), 2);
    assert_eq!(block.number, 7);
    assert_ne!(block.hash, alloy_primitives::B256::ZERO);
    assert_eq!(block.receipts[0].gas_used, 21_000, "plain transfer");
    assert!(
        block.receipts[1].gas_used > 21_000,
        "calldata costs intrinsic gas: {}",
        block.receipts[1].gas_used
    );
    assert_eq!(block.gas_used, block.receipts.iter().map(|r| r.gas_used).sum::<u64>(),);
    assert_eq!(block.txs[0].tx_index, 0);
    assert_eq!(block.txs[1].tx_index, 1);
    assert_eq!(block.txs[0].from, alloy_primitives_address(caller.0));
    assert_eq!(block.txs[0].to, Some(revm::primitives::Address::from_slice(&recipient.0)),);

    let hash0 = alloy_primitives::keccak256(&tx0);
    assert_eq!(block.txs[0].hash, hash0, "canonical keccak256(raw) hash");
    assert_eq!(h.tx_location(&hash0), Some((7, 0)));
    assert_eq!(h.block_by_hash(&block.hash).unwrap().number, 7);
    assert_eq!(h.latest(), Some(7));
    drop(h);

    // Next block seals with parent linkage.
    m.begin_block(Height::new(8));
    m.end_block(Height::new(8));
    let h = m.history();
    let b8 = h.block(8).expect("block 8 sealed");
    assert_eq!(b8.parent_hash, h.block(7).unwrap().hash);
}

#[test]
fn history_only_records_executed_txs() {
    let (pk, caller) = test_keypair();
    let (_, recipient) = test_keypair();
    let m = make_module();
    fund(&m, &caller);
    m.begin_block(Height::new(1));

    // One good tx + one undecodable tx + one wrong-chain tx.
    // Only the executed one may appear in history — malformed txs
    // are dropped pre-execution, not sealed in the block.
    let to = tx::TxKind::Call(revm::primitives::Address::from_slice(&recipient.0));
    let good = signed_tx(&pk, 0, to, &[]);
    let garbage = vec![0xff, 0xfe, 0x00];
    let res = m.handle_batch(&dummy_ctx(), &[good, garbage]);
    assert!(res[0].is_ok() && res[1].is_err());
    m.end_block(Height::new(1));

    let h = m.history();
    let block = h.block(1).expect("block sealed");
    assert_eq!(block.txs.len(), 1, "only the executed tx is in history");
}

// ---- Preinstalls ----

/// Every preinstall lands at its canonical address with nonce 1
/// and bytecode byte-identical to the mainnet deployment.
#[test]
fn preinstalls_install_all_contracts() {
    let m = make_module();
    m.install_preinstalls();
    for p in preinstalls::PREINSTALLS {
        let addr = preinstalls::preinstall_address(p);
        let code = m.code(&addr);
        assert_eq!(
            code,
            preinstalls::preinstall_code(p),
            "{} must have its canonical runtime code",
            p.name
        );
        assert_eq!(m.nonce(&addr), 1, "{} must carry nonce 1", p.name);
    }
}

/// The CREATE2 factory actually works end-to-end: send a real tx
/// with `salt ++ initcode`, get the deployed address back in the
/// receipt-returned... (the factory returns it; we verify by
/// reading the deployed code from state).
#[test]
fn preinstalled_create2_factory_deploys() {
    let (pk, caller) = test_keypair();
    let m = make_module();
    m.install_preinstalls();
    fund(&m, &caller);
    m.begin_block(Height::new(1));

    // Initcode that returns RETURN42_RUNTIME as the deployed code:
    // `PUSH1 len PUSH1 offset PUSH1 0 CODECOPY PUSH1 len PUSH1 0
    // RETURN` — offset 0x0c = the 12-byte prefix length.
    let runtime: &[u8] = &RETURN42_RUNTIME;
    let rt_len = u8::try_from(runtime.len()).expect("test runtime < 256 bytes");
    let mut initcode =
        vec![0x60, rt_len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, rt_len, 0x60, 0x00, 0xf3];
    initcode.extend_from_slice(runtime);

    // Factory calldata: salt (32B) ++ initcode.
    let factory = preinstalls::preinstall_address(&preinstalls::PREINSTALLS[0]);
    let mut calldata = [0u8; 32].to_vec();
    calldata.extend_from_slice(&initcode);
    let to = tx::TxKind::Call(revm::primitives::Address::from_slice(&factory.0));
    let msg = signed_tx(&pk, 0, to, &calldata);
    let res = m.handle(&dummy_ctx(), &msg);
    assert!(res.is_ok(), "factory call must succeed: {res:?}");

    // The deployed address is derivable: keccak256(0xff ++
    // factory ++ salt ++ keccak256(initcode))[12:].
    let code_hash = alloy_primitives::keccak256(&initcode);
    let mut preimage = vec![0xffu8];
    preimage.extend_from_slice(&factory.0);
    preimage.extend_from_slice(&[0u8; 32]);
    preimage.extend_from_slice(code_hash.as_slice());
    let deployed = alloy_primitives::keccak256(&preimage);
    let deployed_addr = Address(deployed[12..].try_into().unwrap());
    assert_eq!(
        m.code(&deployed_addr),
        runtime.to_vec(),
        "CREATE2-deployed contract must exist at the derived address"
    );
}

/// Runtime bytecode: `CALL` the staking-delegate precompile
/// (`0x0C_01`) with `[validator:20B][amount:32B]` calldata built
/// in memory, then either `STOP` (keep the delegation) or
/// `REVERT` (the delegation must be undone by the native journal).
fn delegate_then_revert_runtime(validator: [u8; 20], amount: u64, revert: bool) -> Vec<u8> {
    let precompile = precompiles::precompile_address(
        precompiles::STAKING_DELEGATE.0,
        precompiles::STAKING_DELEGATE.1,
    );
    let mut code = Vec::new();
    // mstore(0, validator << 96) — validator left-aligned at mem[0..20].
    code.push(0x73); // PUSH20
    code.extend_from_slice(&validator);
    code.extend_from_slice(&[0x60, 0x60, 0x1b, 0x60, 0x00, 0x52]); // PUSH1 96 SHL PUSH1 0 MSTORE
    // mstore(20, amount) — amount BE at mem[20..52].
    code.push(0x67); // PUSH8
    code.extend_from_slice(&amount.to_be_bytes());
    code.extend_from_slice(&[0x60, 0x14, 0x52]); // PUSH1 20 MSTORE
    // CALL(gas=0xffff, to=precompile, value=0, in=0..52, out=0..0).
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00]); // out_size, out_offset
    code.extend_from_slice(&[0x60, 0x34, 0x60, 0x00]); // in_size=52, in_offset=0
    code.push(0x60);
    code.push(0x00); // value=0
    code.push(0x73); // PUSH20
    code.extend_from_slice(precompile.as_bytes());
    code.extend_from_slice(&[0x61, 0xff, 0xff]); // gas = 65535
    code.push(0xf1); // CALL
    code.push(0x50); // POP the success flag
    if revert {
        code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0xfd]); // REVERT(0,0)
    } else {
        code.push(0x00); // STOP
    }
    code
}

/// A staking pair wired into the module, with `contract`
/// deployed carrying `balance_units` on the EVM ledger (it will
/// be the delegator) and `runtime` as its code. The balance is
/// set in the same genesis insert as the code — a separate mint
/// first would be overwritten by the insert. Returns the module
/// in an `Arc` so the same handle can serve as staking's
/// out-of-transaction ledger.
fn staking_wired_module(
    contract: Address,
    balance_units: u64,
    runtime: Vec<u8>,
) -> (Arc<EvmModule>, Arc<staking::StakingModule>) {
    let m = Arc::new(make_module());
    m.genesis_insert_account(
        &contract,
        u128::from(balance_units) * framework::WEI_PER_UNIT,
        0,
        runtime,
        vec![],
    );
    let staking_mod = Arc::new(staking::StakingModule::new());
    // Wire the module's out-of-tx ledger for staking's native
    // paths (end_block payouts, rewards); the precompile bond
    // itself moves through revm's journal inside the frame.
    staking_mod.set_ledger(m.clone());
    m.set_staking(staking_mod.clone());
    (m, staking_mod)
}

#[test]
fn staking_delegate_precompile_applies_on_success() {
    let (pk, caller) = test_keypair();
    let contract = Address([0xC0; 20]);
    let validator = Address([0xAA; 20]);
    let (m, staking_mod) = staking_wired_module(
        contract,
        10_000,
        delegate_then_revert_runtime(validator.0, 1_000, false),
    );
    staking_mod.register_validator(validator);
    fund(&m, &caller);

    m.begin_block(Height::new(1));
    let to = tx::TxKind::Call(revm::primitives::Address::from_slice(&contract.0));
    let msg = signed_tx(&pk, 0, to, &[]);
    m.handle(&dummy_ctx(), &msg).expect("tx must be included");

    assert_eq!(
        staking_mod.delegation(&contract, &validator),
        1_000,
        "delegation must persist after a successful frame"
    );
    assert_eq!(staking_mod.stake(&validator), 1_000);
    assert_eq!(Balances::balance(m.as_ref(), &contract), 9_000, "delegator debited");
    assert_eq!(Balances::balance(m.as_ref(), &staking::BONDED_POOL), 1_000);
    m.end_block(Height::new(1));
}

#[test]
fn staking_delegate_precompile_undone_on_revert() {
    // The security property: a contract that delegates then
    // reverts must leave NO trace in staking or the ledger — the
    // native journal replays `undo_delegate` while revm's journal
    // restores the bond transfer itself.
    let (pk, caller) = test_keypair();
    let contract = Address([0xC0; 20]);
    let validator = Address([0xAA; 20]);
    let (m, staking_mod) = staking_wired_module(
        contract,
        10_000,
        delegate_then_revert_runtime(validator.0, 1_000, true),
    );
    staking_mod.register_validator(validator);
    fund(&m, &caller);

    m.begin_block(Height::new(1));
    let to = tx::TxKind::Call(revm::primitives::Address::from_slice(&contract.0));
    let msg = signed_tx(&pk, 0, to, &[]);
    // The tx executes and is included (revert is a valid receipt),
    // but its native side effects must be fully rolled back.
    m.handle(&dummy_ctx(), &msg).expect("tx must be included");

    assert_eq!(
        staking_mod.delegation(&contract, &validator),
        0,
        "reverted frame must undo the delegation"
    );
    assert_eq!(staking_mod.stake(&validator), 0, "no stake may survive a revert");
    assert_eq!(
        Balances::balance(m.as_ref(), &contract),
        10_000,
        "delegator refunded by revm\'s journal revert"
    );
    assert_eq!(Balances::balance(m.as_ref(), &staking::BONDED_POOL), 0, "pool unchanged");
    m.end_block(Height::new(1));
}

#[test]
fn staking_delegate_precompile_rejects_static_and_sim() {
    // eth_call must never touch native state: the same contract
    // through `call_read` (read_only mode) gets a precompile
    // revert, not a delegation.
    let (_pk, caller) = test_keypair();
    let contract = Address([0xC0; 20]);
    let validator = Address([0xAA; 20]);
    let (m, staking_mod) = staking_wired_module(
        contract,
        10_000,
        delegate_then_revert_runtime(validator.0, 1_000, false),
    );
    staking_mod.register_validator(validator);
    fund(&m, &caller);

    m.begin_block(Height::new(1));
    let req = call_req(revm::primitives::Address::from_slice(&contract.0), &[]);
    let _ = m.call_read(&req); // outcome irrelevant; state is what matters
    assert_eq!(
        staking_mod.delegation(&contract, &validator),
        0,
        "read-only simulation must not mutate staking state"
    );
    assert_eq!(Balances::balance(m.as_ref(), &staking::BONDED_POOL), 0);
    m.end_block(Height::new(1));
}

#[test]
fn handle_eip7702_delegates_authority_code() {
    let (sender_key, sender) = test_keypair();
    let (auth_key, authority) = test_keypair();
    let delegate = Address([0x77; 20]);
    let m = make_module();
    fund(&m, &sender);
    fund(&m, &authority);

    // The authority signs an authorization delegating its account
    // to `delegate`. chain_id 1 matches the module's chain.
    let auth = tx::TxAuthorization::sign(
        U256::from(1),
        revm::primitives::Address::from(delegate.0),
        0,
        &auth_key,
    )
    .expect("auth sign must succeed");

    // A different sender relays the type-4 transaction (the
    // common sponsored-delegation pattern).
    let signed = tx::SignedTx::sign_eip7702(
        tx::TxEip7702 {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: 200_000,
                to: tx::TxKind::Call(revm::primitives::Address::from(sender.0)),
                value: U256::ZERO,
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            max_priority_fee_per_gas: U256::from(1_000_000_000),
            max_fee_per_gas: U256::from(2_000_000_000),
            access_list: Vec::new(),
            authorization_list: vec![auth],
        },
        &sender_key,
    )
    .expect("7702 sign must succeed");
    let msg = signed.encode_to_bytes();

    let result = m.handle(&dummy_ctx(), &msg).expect("handle must succeed");
    assert_eq!(result[0].kind, "evm_call");

    // The authority's account now holds the delegation designator
    // `0xef0100 || delegate` (EIP-7702 set-code), 23 bytes.
    let code = m.code(&authority);
    let mut want = vec![0xef, 0x01, 0x00];
    want.extend_from_slice(&delegate.0);
    assert_eq!(code, want, "authority must carry the delegation designator");
}

#[test]
fn eip7702_rejected_pre_prague() {
    let (sender_key, sender) = test_keypair();
    let (auth_key, _) = test_keypair();
    // Berlin predates Prague — type-4 txs must not execute.
    let m = EvmModule::with_spec(1, 7, SpecId::BERLIN);
    fund(&m, &sender);
    let auth = tx::TxAuthorization::sign(
        U256::from(1),
        revm::primitives::Address::from([0x77; 20]),
        0,
        &auth_key,
    )
    .expect("auth sign");
    let signed = tx::SignedTx::sign_eip7702(
        tx::TxEip7702 {
            fields: tx::TxFields {
                nonce: 0,
                gas_limit: 200_000,
                to: tx::TxKind::Call(revm::primitives::Address::from(sender.0)),
                value: U256::ZERO,
                data: revm::primitives::Bytes::new(),
                chain_id: 1,
            },
            max_priority_fee_per_gas: U256::from(1_000_000_000),
            max_fee_per_gas: U256::from(2_000_000_000),
            access_list: Vec::new(),
            authorization_list: vec![auth],
        },
        &sender_key,
    )
    .expect("sign must succeed");
    let result = m.handle(&dummy_ctx(), &signed.encode_to_bytes());
    assert!(
        matches!(result, Err(ExecError::Malformed)),
        "type-4 tx on a pre-Prague spec must be rejected: {result:?}"
    );
}

#[test]
fn simulation_respects_wall_clock_timeout() {
    // `JUMPDEST PUSH1 0 JUMP` — an unbounded loop that would run
    // until the gas cap without a deadline.
    let loop_contract = Address([0x99; 20]);
    let mut m = make_module();
    m.set_sim_timeout(std::time::Duration::from_millis(50));
    m.genesis_insert_account(&loop_contract, 0, 1, vec![0x5b, 0x60, 0x00, 0x56], Vec::new());
    let req =
        CallRequest { to: Some(loop_contract), gas: Some(30_000_000), ..CallRequest::default() };
    let started = std::time::Instant::now();
    let result = m.call_read(&req);
    // The deadline inspector halts the interpreter within ~50ms
    // — not the seconds a 30M-gas loop would take.
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    match result {
        Err(CallError::Halt { reason, .. }) => {
            assert_eq!(reason, "execution timed out", "timeout must surface distinctly");
        }
        other => panic!("expected a timeout halt, got {other:?}"),
    }
}

#[test]
fn simulation_without_deadline_runs_to_gas_cap() {
    // A default-timeout module running the same loop burns the
    // whole gas limit and halts OutOfGas — no timeout fires.
    let loop_contract = Address([0x98; 20]);
    let m = make_module();
    m.genesis_insert_account(&loop_contract, 0, 1, vec![0x5b, 0x60, 0x00, 0x56], Vec::new());
    let req = CallRequest {
        to: Some(loop_contract),
        gas: Some(21_000), // small gas: OOG long before any timeout
        ..CallRequest::default()
    };
    match m.call_read(&req) {
        Err(CallError::Halt { reason, .. }) => {
            assert_ne!(reason, "execution timed out", "OOG, not a timeout");
        }
        other => panic!("expected OOG halt, got {other:?}"),
    }
}

// ── Historical state window (undo-log) ──────────────────────

/// Drive a full block lifecycle: `begin` → batch → `end`. The
/// undo accumulator folds into `versioned` only at `end_block`,
/// so tests must seal to make heights readable.
fn drive_block(m: &EvmModule, height: u64, txs: &[Vec<u8>]) {
    m.begin_block(Height::new(height));
    if !txs.is_empty() {
        let results = m.handle_batch(&dummy_ctx(), txs);
        for (i, r) in results.iter().enumerate() {
            assert!(r.is_ok(), "tx {i} in block {height} must execute: {r:?}");
        }
    }
    m.end_block(Height::new(height));
}

fn signed_transfer(privkey: &[u8], nonce: u64, to: Address, value: u128) -> Vec<u8> {
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce,
            gas_limit: DEFAULT_GAS_LIMIT,
            to: tx::TxKind::Call(revm::primitives::Address::from(to.0)),
            value: U256::from(value),
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    tx::SignedTx::sign_legacy(tx, privkey).expect("sign").encode_to_bytes()
}

/// The core historical-read guarantee: a value overwritten in a
/// later block reads correctly at both heights.
#[test]
fn historical_reads_serve_past_heights() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    let recipient = Address([0x42; 20]);

    drive_block(&m, 1, &[signed_transfer(&privkey, 0, recipient, 1_000_000)]);
    drive_block(&m, 2, &[signed_transfer(&privkey, 1, recipient, 1_000_000)]);

    // Recipient balance: 1M at h=1, 2M at h=2/latest.
    assert_eq!(m.balance_at(&recipient, 1).unwrap(), 1_000_000);
    assert_eq!(m.balance_at(&recipient, 2).unwrap(), 2_000_000);
    // Sender nonce: 1 at h=1, 2 at h=2.
    assert_eq!(m.nonce_at(&sender, 1).unwrap(), 1);
    assert_eq!(m.nonce_at(&sender, 2).unwrap(), 2);
    // Future height rejects.
    assert!(matches!(m.balance_at(&recipient, 9), Err(StateError::TooNew { .. })));
}

/// Storage slots read correctly at past heights — the undo map
/// preserves the pre-write slot set.
#[test]
fn historical_storage_reads() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    // Contract: `SSTORE(0, 0x2a)` then STOP — writes slot 0.
    let writer = Address([0x77; 20]);
    m.genesis_insert_account(
        &writer,
        0,
        1,
        vec![0x60, 0x2a, 0x60, 0x00, 0x55, 0x00], // PUSH1 42 PUSH1 0 SSTORE STOP
        Vec::new(),
    );
    drive_block(&m, 1, &[]); // contract exists but slot untouched
    drive_block(&m, 2, &[signed_tx(&privkey, 0, tx::TxKind::Call(writer.0.into()), &[])]);

    let slot = U256::ZERO;
    assert_eq!(m.storage_at_height(&writer, &slot, 1).unwrap(), U256::ZERO);
    assert_eq!(m.storage_at_height(&writer, &slot, 2).unwrap(), U256::from(42));
}

/// Reads below the retained window fail closed — the undo
/// entries needed to reconstruct them were pruned.
#[test]
fn pruned_heights_fail_closed() {
    let (privkey, sender) = test_keypair();
    let m = EvmModule::with_history_window(1, 7, 3);
    fund(&m, &sender);
    let recipient = Address([0x55; 20]);
    for h in 1..=6u64 {
        drive_block(&m, h, &[signed_transfer(&privkey, h - 1, recipient, 1)]);
    }
    // Window keeps the newest 3 sealed blocks: heights 4,5,6.
    // Servable reads: h >= floor-1 = 3. h=2 must fail.
    assert!(matches!(m.balance_at(&recipient, 2), Err(StateError::Pruned { requested: 2, .. })));
    assert!(m.balance_at(&recipient, 3).is_ok());
    assert!(m.balance_at(&recipient, 6).is_ok());
}

/// `eth_call` at a past height sees that height's storage — the
/// overlay serves `SLOAD` through the undo log.
#[test]
fn eth_call_at_past_height() {
    let (privkey, sender) = test_keypair();
    let m = make_module();
    fund(&m, &sender);
    // One contract doubles as writer+reader:
    //   CALLDATALOAD(0) SSTORE(0, v) → SLOAD(0) → return 32B.
    //   600035 600055 600054 600052 6020 6000 f3
    // One contract, two entry points:
    //   empty calldata   → return SLOAD(0)         (pure read)
    //   nonempty calldata → SSTORE(0, calldata[0]) then read.
    let store = Address([0x78; 20]);
    m.genesis_insert_account(
        &store,
        0,
        1,
        vec![
            0x36, //       CALLDATASIZE
            0x15, //       ISZERO          → [size==0]
            0x60, 0x0B, // PUSH1 0x0B      → [dest, cond]
            0x57, //       JUMPI           → read path if empty
            0x60, 0x00, // PUSH1 0
            0x35, //       CALLDATALOAD(0) → [v]
            0x60, 0x00, // PUSH1 0         → [key, v]
            0x55, //       SSTORE(0, v)
            0x5B, //       JUMPDEST (0x0B) — read path lands here
            0x60, 0x00, // PUSH1 0
            0x54, //       SLOAD(0)        → [val]
            0x60, 0x00, // PUSH1 0
            0x52, //       MSTORE(0, val)
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xF3, //       RETURN(0, 32)
        ],
        vec![(U256::ZERO, U256::from(3))], // slot 0 = 3 at genesis
    );
    drive_block(&m, 1, &[]);
    // Block 2: write 42 into slot 0 via the calldata path.
    drive_block(
        &m,
        2,
        &[signed_tx(
            &privkey,
            0,
            tx::TxKind::Call(store.0.into()),
            &U256::from(42).to_be_bytes::<32>(),
        )],
    );

    // eth_call at h=1 must see the pre-write value (3); at h=2,
    // the post-write value (42) — SLOAD served by the overlay.
    let read = CallRequest {
        to: Some(store),
        gas: Some(200_000),
        data: Vec::new(),
        ..CallRequest::default()
    };
    let at_1 = m.call_read_at(&read, 1).expect("eth_call at h=1");
    assert_eq!(U256::from_be_slice(&at_1.output), U256::from(3));
    let at_2 = m.call_read_at(&read, 2).expect("eth_call at h=2");
    assert_eq!(U256::from_be_slice(&at_2.output), U256::from(42));
}
/// Restart persistence: sealed history (blocks, txs, receipts,
/// traces) and the undo window are written to the backend on
/// every `end_block` and rebuilt by `load_from_storage`.
#[test]
fn restart_restores_history_and_versioned_state() {
    use storage::Volatile;

    let (pk, sender) = test_keypair();
    let recipient = Address([0x42; 20]);
    let m = EvmModule::with_storage(1, 7, Box::new(Volatile::new()));
    fund(&m, &sender);
    drive_block(&m, 1, &[signed_transfer_tx(&pk, 0, recipient.0.into(), 1_000_000)]);
    drive_block(&m, 2, &[signed_transfer_tx(&pk, 1, recipient.0.into(), 1_000_000)]);

    let block1_hash = m.history().block(1).unwrap().hash;
    let block2_hash = m.history().block(2).unwrap().hash;
    let bal_h1 = m.balance_at(&recipient, 1).unwrap();
    assert_eq!(bal_h1, 1_000_000);

    // "Restart": hand the same backend to a fresh module.
    let backend = m.backend_for_test();
    let m2 = EvmModule::with_storage(1, 7, backend);

    // History survived: heights, hashes, tx lookups, receipts.
    assert_eq!(m2.history().latest(), Some(2));
    assert_eq!(m2.history().block(1).unwrap().hash, block1_hash);
    assert_eq!(m2.history().block(2).unwrap().hash, block2_hash);
    let tx_hash = m2.history().block(2).unwrap().txs[0].hash;
    assert_eq!(m2.history().tx_location(&tx_hash), Some((2, 0)));
    assert_eq!(m2.history().block_by_hash(&block1_hash).unwrap().number, 1);
    // Receipts and call-traces round-trip too — `debug_trace*`
    // keeps working across restart.
    let block2 = m2.history().block(2).unwrap().clone();
    assert_eq!(block2.receipts.len(), 1);
    assert!(block2.receipts[0].status);
    let root_frame = block2.traces[0].as_ref().expect("trace must round-trip");
    assert_eq!(root_frame.kind, "CALL");
    assert_eq!(root_frame.to, Some(recipient.0.into()));

    // The undo window survived too: state at h=1 reads the
    // pre-block-2 balance even though latest is 2.
    assert_eq!(m2.balance_at(&recipient, 1).unwrap(), 1_000_000);
    assert_eq!(m2.balance_at(&recipient, 2).unwrap(), 2_000_000);
    // A block below the window that was never persisted still
    // fail-closes (h=0 < floor-1? floor=1 → h=0 is servable as
    // the genesis view: recipient absent → 0).
    assert_eq!(m2.balance_at(&recipient, 0).unwrap(), 0);

    // The chain keeps sealing with correct parent linkage — the
    // restored block-2 hash feeds block 3's parent_hash.
    drive_block(&m2, 3, &[signed_transfer_tx(&pk, 2, recipient.0.into(), 5)]);
    {
        let hist = m2.history();
        assert_eq!(hist.block(3).unwrap().parent_hash, block2_hash);
    }
    assert_eq!(m2.balance_at(&recipient, 3).unwrap(), 2_000_005);
}

/// The schema-version meta slot (`0x04`) must be written on the
/// first flush and survive a restart — it's what `migrate`
/// reads to know which upgrade steps an old backend needs.
#[test]
fn state_version_persists_across_restart() {
    use storage::Volatile;

    let (pk, sender) = test_keypair();
    let m = EvmModule::with_storage(1, 7, Box::new(Volatile::new()));
    fund(&m, &sender);
    drive_block(&m, 1, &[signed_transfer_tx(&pk, 0, Address([0x42; 20]).0.into(), 5)]);

    // The flush batch carried the version write.
    let backend = m.backend_for_test();
    let raw = backend.get(&persist::state_version_key()).expect("version must persist");
    let stored = u32::from_le_bytes(raw.as_slice().try_into().expect("4-byte version"));
    assert_eq!(stored, m.state_version());

    // A fresh module over the same backend reads the stored
    // version; stored == declared → no migration needed.
    let m2 = EvmModule::with_storage(1, 7, backend);
    assert_eq!(m2.state_version(), stored);
}

/// Window pruning applies to persisted records: evicted block
/// records and undo blobs are deleted from the backend, and a
/// restart sees exactly the in-memory window.
#[test]
fn restart_prunes_persisted_window() {
    use storage::Volatile;

    let (pk, sender) = test_keypair();
    let recipient = Address([0x42; 20]);
    // Window of 2: blocks 1,2 evicted once 3,4 seal.
    let m = EvmModule::with_storage_and_window(1, 7, Box::new(Volatile::new()), 2);
    fund(&m, &sender);
    for h in 1..=4u64 {
        let tx = signed_transfer_tx(&pk, h - 1, recipient.0.into(), 100);
        drive_block(&m, h, &[tx]);
    }
    assert_eq!(m.history().blocks_floor(), Some(3));

    let backend = m.backend_for_test();
    // The evicted records must be gone from durable storage too.
    assert!(backend.get(&persist::block_key(1)).is_none());
    assert!(backend.get(&persist::undo_key(1)).is_none());
    assert!(backend.get(&persist::block_key(4)).is_some());

    let m2 = EvmModule::with_storage_and_window(1, 7, backend, 2);
    assert_eq!(m2.history().latest(), Some(4));
    assert_eq!(m2.history().blocks_floor(), Some(3));
    assert!(m2.history().block(2).is_none(), "evicted block must not restore");
    // h=1/2 undo blobs were deleted → reads below floor fail.
    assert!(m2.balance_at(&recipient, 1).is_err());
    // h=2 == floor-1: servable from undo[3] (pre-block-3 state =
    // end of block 2 → recipient has 200).
    assert_eq!(m2.balance_at(&recipient, 2).unwrap(), 200);
    assert_eq!(m2.balance_at(&recipient, 4).unwrap(), 400);
}

/// EIP-2935: the history contract is preinstalled at the
/// canonical address, `begin_block` records the parent hash in
/// its ring buffer, and the contract's `get` path serves it to
/// ordinary callers through a real EVM call.
#[test]
fn eip2935_history_contract() {
    let m = make_module();
    m.install_preinstalls();
    let hist_addr = Address(HISTORY_STORAGE_ADDRESS.0.0);

    // Preinstall landed with the canonical bytecode.
    assert!(!m.code_at(&hist_addr, 0).unwrap().is_empty());

    drive_block(&m, 1, &[]);
    drive_block(&m, 2, &[]);
    drive_block(&m, 3, &[]);

    let hash1 = m.history().block(1).unwrap().hash;
    let hash2 = m.history().block(2).unwrap().hash;
    // Slot `(n) % 8191` holds hash(n), written during block n+1.
    assert_eq!(m.storage_at(&hist_addr, &U256::from(1)), U256::from_be_bytes(hash1.0));
    assert_eq!(m.storage_at(&hist_addr, &U256::from(2)), U256::from_be_bytes(hash2.0));

    // Attribution: the slot-2 write belongs to block 3, so a
    // historical read at h=2 still sees the empty slot.
    assert_eq!(m.storage_at_height(&hist_addr, &U256::from(2), 2).unwrap(), U256::ZERO);
    assert_eq!(
        m.storage_at_height(&hist_addr, &U256::from(2), 3).unwrap(),
        U256::from_be_bytes(hash2.0)
    );

    // End-to-end through real bytecode: `get` with calldata =
    // 32-byte block number returns the stored hash.
    let mut calldata = [0u8; 32];
    calldata[31] = 1;
    let out = m
        .call_read(&CallRequest {
            from: None,
            to: Some(hist_addr),
            gas: None,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            value: U256::ZERO,
            data: calldata.to_vec(),
            nonce: None,
            access_list: tx::AccessList::default(),
        })
        .expect("history get must succeed");
    assert_eq!(out.output, hash1.0.to_vec());
}

/// EIP-2935 is Prague-gated: a Cancun spec neither installs the
/// contract nor writes its storage (the write would diverge the
/// state root from the real fork).
#[test]
fn eip2935_gated_on_prague() {
    let m = EvmModule::with_spec(1, 7, SpecId::CANCUN);
    m.install_preinstalls();
    let hist_addr = Address(HISTORY_STORAGE_ADDRESS.0.0);
    assert!(m.code_at(&hist_addr, 0).unwrap().is_empty());

    drive_block(&m, 1, &[]);
    drive_block(&m, 2, &[]);
    assert_eq!(m.storage_at(&hist_addr, &U256::from(1)), U256::ZERO);
}

/// Audit 3.2 round-trip: a snapshot's accounts must rebuild the
/// same Ethereum MPT root on a scratch verification BEFORE the
/// backend is touched, and re-import must land byte-identical
/// state.
#[test]
fn state_snapshot_round_trips() {
    use storage::Volatile;

    let (pk, addr) = test_keypair();
    let src = EvmModule::with_storage(1, 7, Box::new(Volatile::new()));
    fund(&src, &addr);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);
    let tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
    src.begin_block(Height::new(1));
    let results = src.handle_batch(&dummy_ctx(), &[tx]);
    assert!(results.iter().all(Result::is_ok), "tx must succeed: {results:?}");
    src.end_block(Height::new(1));

    let snapshot = Module::export_state(&src).expect("evm exports state");
    // The staged account set must reproduce the module's root.
    assert_eq!(Module::inspect_state(&src, &snapshot).unwrap(), src.state_root());

    let dst = EvmModule::with_storage(1, 7, Box::new(Volatile::new()));
    Module::import_state(&dst, &snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    let oxide_recipient = primitives::Address(recipient.0.into());
    assert_eq!(dst.balance(&oxide_recipient), 1_000_000_000);
}

/// A tampered account balance still parses — inspection must
/// return a DIFFERENT root (the executor compares against the
/// claimed root), while truncated or unsorted entries fail
/// outright.
#[test]
fn state_snapshot_verifies_root_and_rejects_malformed() {
    use storage::Volatile;

    let (pk, addr) = test_keypair();
    let src = EvmModule::with_storage(1, 7, Box::new(Volatile::new()));
    fund(&src, &addr);
    let recipient = revm::primitives::Address::from_slice(&[0x42; 20]);
    let tx = signed_transfer_tx(&pk, 0, recipient, 1_000_000_000);
    src.begin_block(Height::new(1));
    let results = src.handle_batch(&dummy_ctx(), &[tx]);
    assert!(results.iter().all(Result::is_ok), "tx must succeed: {results:?}");
    src.end_block(Height::new(1)); // flush touched accounts to backend

    let snapshot = Module::export_state(&src).unwrap();
    assert!(snapshot.entries.iter().any(|(k, _)| k.0[0] == 0x01), "an account exists");

    // Bit-flip a balance byte: structurally valid, wrong root.
    let mut tampered = snapshot.clone();
    let entry = tampered.entries.iter_mut().find(|(k, _)| k.0[0] == 0x01).expect("account entry");
    entry.1[0] ^= 0xFF;
    let inspected = Module::inspect_state(&src, &tampered).unwrap();
    assert_ne!(inspected, src.state_root(), "tampered state must change the root");

    // Truncated value: structural rejection.
    let mut truncated = snapshot.clone();
    let entry = truncated.entries.iter_mut().find(|(k, _)| k.0[0] == 0x01).expect("account entry");
    entry.1.truncate(40);
    assert!(Module::inspect_state(&src, &truncated).is_err());
    assert!(
        Module::import_state(&EvmModule::with_storage(1, 7, Box::new(Volatile::new())), &truncated)
            .is_err()
    );

    // Unsorted entry list violates the Snapshot contract.
    let mut unsorted = snapshot.clone();
    unsorted.entries.reverse();
    assert!(Module::inspect_state(&src, &unsorted).is_err());
}

/// `deserialize_account_strict` rejects what the lenient decoder
/// accepts: trailing bytes, unsorted/duplicate storage slots,
/// and a `code_hash` that doesn't bind its code bytes.
#[test]
fn account_deserialize_strict_rejects_noncanonical() {
    let slot_a = U256::from(1);
    let slot_b = U256::from(2);
    // Slots out of order — the lenient decoder accepts, strict rejects.
    let out_of_order = persist::serialize_account(
        U256::ZERO,
        0,
        revm::primitives::KECCAK_EMPTY,
        &[],
        &[(slot_b, U256::from(9)), (slot_a, U256::from(9))],
    );
    assert!(persist::deserialize_account(&out_of_order).is_some());
    assert!(persist::deserialize_account_strict(&out_of_order).is_none());

    // Trailing bytes after the last slot.
    let mut trailing =
        persist::serialize_account(U256::ZERO, 0, revm::primitives::KECCAK_EMPTY, &[], &[]);
    trailing.push(0);
    assert!(persist::deserialize_account(&trailing).is_some());
    assert!(persist::deserialize_account_strict(&trailing).is_none());

    // Empty code with a non-empty hash — unverifiable.
    let no_body = persist::serialize_account(U256::ZERO, 0, revm::primitives::B256::ZERO, &[], &[]);
    assert!(persist::deserialize_account_strict(&no_body).is_none());
}

/// A signed legacy transfer with an explicit gas limit — the
/// block-context tests need txs whose `gas_limit` fits inside a
/// deliberately small consensus block budget.
fn signed_transfer_with_gas(
    privkey: &[u8],
    nonce: u64,
    to: Address,
    value: u128,
    gas_limit: u64,
) -> Vec<u8> {
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce,
            gas_limit,
            to: tx::TxKind::Call(revm::primitives::Address::from(to.0)),
            value: U256::from(value),
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(1_000_000_000),
    };
    tx::SignedTx::sign_legacy(tx, privkey).expect("sign").encode_to_bytes()
}

/// `begin_block_ctx` applies the consensus-committed context:
/// the header timestamp (ms → s), the proposer's staking
/// address as fee beneficiary, and the consensus-enforced gas
/// limit all replace the locally derived stand-ins.
#[test]
fn begin_block_ctx_applies_consensus_context() {
    let m = make_module();
    let ctx = types::BlockContext {
        timestamp_ms: 1_700_000_000_500,
        beneficiary: Address([0x77; 20]),
        gas_limit: 42_000,
    };
    m.begin_block_ctx(Height::new(10), &ctx);

    // Header stamps milliseconds; `block.timestamp` is whole
    // seconds — 1_700_000_000_500 ms truncates to …000 s, not
    // the height-derived `10 * BLOCK_TIME_SECS = 150`.
    assert_eq!(
        *framework::lock_state(&m.block_timestamp),
        1_700_000_000,
        "block.timestamp must be the consensus timestamp in seconds"
    );
    assert_eq!(
        m.coinbase(),
        revm::primitives::Address::from([0x77; 20]),
        "beneficiary must reach the fee-recipient slot"
    );
    assert_eq!(m.block_gas_limit(), 42_000, "consensus gas limit must apply");

    // The sealed block record carries the same committed values.
    m.end_block_ctx(Height::new(10), &ctx);
    let sealed = {
        let history = m.history();
        history.block(10).cloned()
    }
    .expect("block sealed");
    assert_eq!(sealed.timestamp, 1_700_000_000);
    assert_eq!(sealed.gas_limit, 42_000);
    assert_eq!(sealed.coinbase, revm::primitives::Address::from([0x77; 20]));
}

/// An all-zero context is the documented "no consensus data"
/// sentinel: timestamp, beneficiary, and gas limit all fall back
/// to the legacy configured behavior so context-less paths
/// (module tests, clockless engines, pre-context journal
/// replay) keep working byte-for-byte.
#[test]
fn begin_block_ctx_zero_context_keeps_legacy() {
    let m = make_module();
    m.begin_block_ctx(Height::new(4), &types::BlockContext::default());
    assert_eq!(
        *framework::lock_state(&m.block_timestamp),
        4 * BLOCK_TIME_SECS,
        "zero context falls back to the height-derived timestamp"
    );
    assert_eq!(m.block_gas_limit(), CHAIN_BLOCK_GAS_LIMIT);
}

/// `end_block_ctx` advances the EIP-1559 base fee from the
/// block's *measured* gas usage: an empty block is below target
/// and the fee decreases per the EIP-1559 rule
/// (`delta = base_fee / elasticity`).
#[test]
fn end_block_ctx_lowers_base_fee_when_underutilized() {
    let m = EvmModule::new(1, 1_000);
    let ctx = types::BlockContext::default();
    m.begin_block_ctx(Height::new(0), &ctx);
    m.end_block_ctx(Height::new(0), &ctx);
    // gas_used = 0 << target → fee falls by exactly base_fee/8.
    assert_eq!(m.base_fee(), 875, "EIP-1559 underutilization: 1000 - 1000/8");
}

/// Congestion raises the fee: a block whose measured `gas_used`
/// exceeds `target = gas_limit / 2` updates the next block's
/// base fee by `base_fee * (used - target) / target / 8` — and
/// the sealed record keeps the fee the block was *executed
/// under*, per Ethereum `block.baseFee` semantics.
#[test]
fn end_block_ctx_raises_base_fee_on_congestion() {
    let (privkey, sender) = test_keypair();
    let m = EvmModule::new(1, 1_000);
    fund(&m, &sender);
    // A 42k-gas block budget → 21k target; two 21k transfers
    // fill it to exactly 2x target.
    let ctx = types::BlockContext {
        timestamp_ms: 1_700_000_000_000,
        beneficiary: Address::ZERO,
        gas_limit: 42_000,
    };
    let recipient = Address([0x42; 20]);
    m.begin_block_ctx(Height::new(0), &ctx);
    let results = m.handle_batch(
        &dummy_ctx(),
        &[
            signed_transfer_with_gas(&privkey, 0, recipient, 1, 21_000),
            signed_transfer_with_gas(&privkey, 1, recipient, 1, 21_000),
        ],
    );
    assert!(results.iter().all(Result::is_ok), "both transfers execute: {results:?}");
    m.end_block_ctx(Height::new(0), &ctx);

    // delta = 1000 * (42000 - 21000) / 21000 / 8 = 125.
    assert_eq!(m.base_fee(), 1_125, "EIP-1559 congestion: 1000 + 125");
    let sealed = m.history().block(0).cloned().expect("sealed");
    assert_eq!(sealed.gas_used, 42_000);
    assert_eq!(sealed.base_fee, 1_000, "sealed block keeps its executed-under fee");

    // The NEXT block runs under the updated fee.
    m.begin_block_ctx(Height::new(1), &ctx);
    let results = m
        .handle_batch(&dummy_ctx(), &[signed_transfer_with_gas(&privkey, 2, recipient, 1, 21_000)]);
    assert!(results.iter().all(Result::is_ok), "tx under new fee: {results:?}");
    m.end_block_ctx(Height::new(1), &ctx);
    let sealed1 = m.history().block(1).cloned().expect("sealed");
    assert_eq!(sealed1.base_fee, 1_125, "block 1 executes under the evolved fee");
}

/// The fee state survives restart: it is reconstructed from the
/// newest sealed block's `base_fee`/`gas_limit`/`gas_used` by
/// replaying the same EIP-1559 update `end_block_ctx` applied —
/// so a reloaded module charges the fee the live one would have.
#[test]
fn fee_state_rehydrates_from_storage() {
    use storage::Volatile;

    let backend = Box::new(Volatile::new());
    let m = EvmModule::with_storage(1, 1_000, backend);
    // Seal one empty block — fee falls to 875 (underutilized).
    let ctx = types::BlockContext::default();
    m.begin_block_ctx(Height::new(0), &ctx);
    m.end_block_ctx(Height::new(0), &ctx);
    assert_eq!(m.base_fee(), 875);

    // Reload from the same backend with a DIFFERENT constructor
    // seed — the rehydrated state must come from the sealed
    // block, not the seed.
    let m2 = EvmModule::with_storage(1, 9_999, m.backend_for_test());
    assert_eq!(m2.base_fee(), 875, "reloaded fee matches the evolved value");
}
