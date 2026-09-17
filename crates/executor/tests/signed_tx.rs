//! End-to-end tests for EIP-712-signed native module transactions.
//!
//! These live in an integration test (not `src/lib.rs` unit tests)
//! because `staking` and `evm` depend on `executor`: in a unit-test
//! build the test crate's `Module` trait would differ from the one
//! the modules implement. From `tests/` both resolve to the same
//! external crate, so the real modules can be registered on a real
//! `Executor`.
//!
//! The scenarios prove the security property the feature exists for:
//! before EIP-712 envelopes, a native tx's `sender` field was merely
//! *declared* — any node could submit a delegate spending a victim's
//! balance. These tests drive full blocks through `finalize_block`
//! and check settled balances on the EVM ledger — the single
//! native-token ledger — not just admission verdicts.

use std::sync::Arc;

use executor::{Executor, UnsignedTxPolicy};
use framework::{Balances, module_id};
use mempool::build_signed_tx;
use ports::AppInterface;
use primitives::{Address, Height};
use types::{BlockBudget, FinalizedBlock, MempoolAck, TxBytes};

/// The validator every delegate tx targets — registered at genesis.
const VALIDATOR: Address = Address([0x77; 20]);

/// Build a signed staking-delegate envelope with a fresh keypair.
/// Returns `(tx_bytes, sender)`.
fn signed_delegate_tx(chain_id: u64, nonce: u64, fee: u64, amount: u64) -> (TxBytes, Address) {
    let (privkey, sender) = crypto::secp::generate_keypair_for_test();
    let tx = build_signed_tx(
        &privkey,
        chain_id,
        nonce,
        fee,
        module_id::STAKING,
        &staking::msg::delegate(VALIDATOR, amount),
    )
    .expect("a valid keypair always produces a signature");
    (tx, sender)
}

/// Build an unsigned v0 envelope claiming `claimed_sender` — the
/// pre-EIP-712 forgery primitive.
fn unsigned_tx(claimed_sender: Address, nonce: u64, fee: u64, payload: &[u8]) -> TxBytes {
    let mut bytes = Vec::with_capacity(37 + payload.len());
    bytes.extend_from_slice(&claimed_sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id::STAKING);
    bytes.extend_from_slice(payload);
    TxBytes::new(bytes)
}

/// An executor with the EVM ledger (fee module) + staking wired to
/// it — the same ledger topology as a production node.
fn executor_with_ledger() -> (Executor, Arc<evm::EvmModule>) {
    let mut executor = Executor::new(1_000);
    let evm = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    executor.register_module(evm.clone());
    executor.set_fee_module(module_id::EVM);
    let staking = staking::StakingModule::new();
    staking.set_ledger(evm.clone());
    staking.genesis_register_validator(VALIDATOR, 1_000_000);
    executor.register_module(Arc::new(staking));
    (executor, evm)
}

/// A properly signed delegate is admitted, included, and settles:
/// sender pays fee + bond, the bonded pool is credited.
#[test]
fn signed_delegate_executes_and_settles() {
    let (executor, ledger) = executor_with_ledger();
    let (tx, sender) = signed_delegate_tx(1, 0, 10, 200);
    ledger.mint(&sender, 1_000);

    assert!(matches!(executor.ingest_tx(tx), MempoolAck::Accepted));
    let budget = BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    assert_eq!(proposal.txs.len(), 1);
    executor.finalize_block(&FinalizedBlock { height: Height::new(0), txs: proposal.txs });

    assert_eq!(Balances::balance(ledger.as_ref(), &sender), 1_000 - 10 - 200);
    assert_eq!(Balances::balance(ledger.as_ref(), &staking::BONDED_POOL), 200);
}

/// The core security property: forging the declared `sender` field
/// on a signed envelope cannot spend a victim's funds — the
/// recovered signer won't match.
#[test]
fn forged_sender_cannot_debit_victim() {
    let (executor, ledger) = executor_with_ledger();
    let victim = Address([0xEE; 20]);
    ledger.mint(&victim, 10_000);

    // Sign a legit tx with the attacker's key, then overwrite the
    // declared sender with the victim's address.
    let (tx, _attacker) = signed_delegate_tx(1, 0, 0, 5_000);
    let mut bytes = tx.as_bytes().to_vec();
    bytes[..20].copy_from_slice(&victim.0);

    assert!(matches!(executor.ingest_tx(TxBytes::new(bytes)), MempoolAck::Rejected { .. }));
    assert_eq!(Balances::balance(ledger.as_ref(), &victim), 10_000);
}

/// Under `UnsignedTxPolicy::Reject` the pre-EIP-712 forgery is dead:
/// an unsigned tx claiming the victim's sender is rejected at
/// admission and skipped at execution.
#[test]
fn unsigned_forgery_rejected_when_signatures_required() {
    let mut executor = Executor::new(1_000).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
    let evm = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    executor.register_module(evm.clone());
    executor.set_fee_module(module_id::EVM);
    let staking = staking::StakingModule::new();
    staking.set_ledger(evm.clone());
    staking.genesis_register_validator(VALIDATOR, 1_000_000);
    executor.register_module(Arc::new(staking));

    let victim = Address([0xEE; 20]);
    evm.mint(&victim, 10_000);

    let forged = unsigned_tx(victim, 0, 0, &staking::msg::delegate(VALIDATOR, 5_000));
    assert!(matches!(executor.ingest_tx(forged.clone()), MempoolAck::Rejected { .. }));

    // Even if a foreign proposer injects it into a block, execution
    // skips it deterministically.
    executor.finalize_block(&FinalizedBlock { height: Height::new(0), txs: vec![forged] });
    assert_eq!(Balances::balance(evm.as_ref(), &victim), 10_000, "victim funds untouched");
}

/// A signed tx arriving in a foreign proposal (never ingested into
/// this node's mempool) is verified inline at execution.
#[test]
fn foreign_signed_tx_executes_without_ingest() {
    let mut executor = Executor::new(1_000).with_unsigned_tx_policy(UnsignedTxPolicy::Reject);
    let evm = Arc::new(evm::EvmModule::new(1, 7_000_000_000));
    executor.register_module(evm.clone());
    executor.set_fee_module(module_id::EVM);
    let staking = staking::StakingModule::new();
    staking.set_ledger(evm.clone());
    staking.genesis_register_validator(VALIDATOR, 1_000_000);
    executor.register_module(Arc::new(staking));

    let (tx, sender) = signed_delegate_tx(1, 0, 0, 200);
    evm.mint(&sender, 1_000);

    executor.finalize_block(&FinalizedBlock { height: Height::new(0), txs: vec![tx] });
    assert_eq!(Balances::balance(evm.as_ref(), &staking::BONDED_POOL), 200);
    assert_eq!(Balances::balance(evm.as_ref(), &sender), 800);
}

/// Compat policy documents the migration path: with the default
/// `Allow`, unsigned txs still execute (devnet/tests) — production
/// validators run `Reject` via `--require-signed-txs`.
#[test]
fn unsigned_tx_executes_under_compat_policy() {
    let (executor, ledger) = executor_with_ledger();
    let sender = Address([9; 20]);
    ledger.mint(&sender, 1_000);

    let tx = unsigned_tx(sender, 0, 0, &staking::msg::delegate(VALIDATOR, 300));
    assert!(matches!(executor.ingest_tx(tx), MempoolAck::Accepted));
    let budget = BlockBudget { max_bytes: 1 << 20, max_gas: 1 << 30 };
    let proposal = executor.prepare_proposal(&budget);
    executor.finalize_block(&FinalizedBlock { height: Height::new(0), txs: proposal.txs });
    assert_eq!(Balances::balance(ledger.as_ref(), &staking::BONDED_POOL), 300);
}
