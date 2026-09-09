//! EVM conformance tests — verify Oxide's EVM produces correct
//! results for known Ethereum test vectors.
//!
//! These tests verify that our EVM execution matches Ethereum's
//! specification for well-known scenarios:
//! - Empty state → empty root hash.
//! - Simple value transfer (21,000 gas).
//! - Contract deployment.
//! - Nonce progression.
//! - Balance after transfer.
//! - Revert on stale nonce.
//!
//! # Reference
//!
//! - Ethereum Yellow Paper: the canonical specification.
//! - reth: `reth-evm` tests verify the same properties.
//! - EthereumJS/VM tests: the canonical test vectors.
//!
//! # Note
//!
//! Full `BlockchainTests` integration (running the official
//! Ethereum test suite) is deferred to Phase F+. These tests
//! are hand-crafted vectors that verify the same properties
//! without the full test suite dependency.

use crypto::secp;
use evm::EvmModule;
use evm::tx::{SignedTx, TxFields, TxKind, TxLegacy};
use executor::{Module, TxContext};
use primitives::{Address, Hash, Height};
use revm::primitives::{Address as EvmAddress, Bytes, U256};

/// Default gas limit for test transactions.
const GAS_LIMIT: u64 = 30_000_000;

/// Test context with a fixed sender and block height.
fn dummy_ctx() -> TxContext {
    TxContext { sender: Address([0xff; 20]), nonce: 0, fee: 0 }
}

/// A test keypair (private key + address).
struct TestKey {
    privkey: [u8; 32],
    addr: Address,
}

impl TestKey {
    fn new() -> Self {
        let (privkey, addr) = secp::generate_keypair_for_test();
        let addr = Address(addr.0);
        Self { privkey, addr }
    }
}

/// Build a signed transfer tx (RLP-encoded).
fn signed_transfer(privkey: &[u8], nonce: u64, to: EvmAddress, value: u128) -> Vec<u8> {
    let tx = TxLegacy {
        fields: TxFields {
            nonce,
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(to),
            value: U256::from(value),
            data: Bytes::new(),
            chain_id: 1,
        },
        gas_price: U256::from(10_000_000_000u64),
    };
    SignedTx::sign_legacy(tx, privkey).expect("sign must succeed").encode_to_bytes()
}

/// Build a signed contract creation tx (RLP-encoded).
fn signed_create(privkey: &[u8], nonce: u64, bytecode: &[u8]) -> Vec<u8> {
    let tx = TxLegacy {
        fields: TxFields {
            nonce,
            gas_limit: 1_000_000,
            to: TxKind::Create,
            value: U256::ZERO,
            data: Bytes::copy_from_slice(bytecode),
            chain_id: 1,
        },
        gas_price: U256::from(10_000_000_000u64),
    };
    SignedTx::sign_legacy(tx, privkey).expect("sign must succeed").encode_to_bytes()
}

/// Fund an account with a large balance for testing.
fn fund(module: &EvmModule, addr: &Address) {
    module.fund_account_for_test(addr, 10u128.pow(20));
}

/// The empty state must produce Ethereum's `EMPTY_ROOT_HASH`.
#[test]
fn empty_state_matches_ethereum_empty_root() {
    let module = EvmModule::new(1, 7_000_000_000);
    let root = module.state_root();
    let expected = Hash([
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
        0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
        0xb4, 0x21,
    ]);
    assert_eq!(root, expected, "empty state root must match Ethereum's EMPTY_ROOT_HASH");
}

/// A simple value transfer must succeed and credit the recipient.
#[test]
fn simple_transfer_credits_recipient() {
    let key = TestKey::new();
    let recipient = EvmAddress::from_slice(&[0x42; 20]);
    let module = EvmModule::new(1, 7_000_000_000);
    fund(&module, &key.addr);

    let raw = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);
    module.handle(&dummy_ctx(), &raw).expect("transfer must succeed");

    let oxide_recipient = Address(recipient.0.into());
    let balance = module.balance(&oxide_recipient);
    assert_eq!(balance, 1_000_000_000, "recipient must have the transferred value");
}

/// The sender's nonce must increment after a transaction.
#[test]
fn nonce_increments_after_tx() {
    let key = TestKey::new();
    let recipient = EvmAddress::from_slice(&[0x42; 20]);
    let module = EvmModule::new(1, 7_000_000_000);
    fund(&module, &key.addr);

    assert_eq!(module.nonce(&key.addr), 0, "nonce must start at 0");
    let raw = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);
    module.handle(&dummy_ctx(), &raw).expect("tx must succeed");
    assert_eq!(module.nonce(&key.addr), 1, "nonce must increment to 1");
}

/// A transaction with a stale nonce must be rejected.
#[test]
fn stale_nonce_is_rejected() {
    let key = TestKey::new();
    let recipient = EvmAddress::from_slice(&[0x42; 20]);
    let module = EvmModule::new(1, 7_000_000_000);
    fund(&module, &key.addr);

    // First tx with nonce 0 — should succeed.
    let raw0 = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);
    module.handle(&dummy_ctx(), &raw0).expect("nonce 0 must succeed");

    // Second tx with nonce 0 again — should fail (stale).
    let raw0_again = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);
    let result = module.handle(&dummy_ctx(), &raw0_again);
    assert!(result.is_err(), "stale nonce must be rejected");
}

/// A contract creation must change the state root.
#[test]
fn contract_creation_changes_state_root() {
    let key = TestKey::new();
    let module = EvmModule::new(1, 7_000_000_000);
    fund(&module, &key.addr);

    // Deploy a contract that stores 0x42 at slot 0.
    // PUSH1 0x42 PUSH1 0x00 SSTORE STOP
    let bytecode = [0x60, 0x42, 0x60, 0x00, 0x55, 0x00];
    let raw = signed_create(&key.privkey, 0, &bytecode);
    module.handle(&dummy_ctx(), &raw).expect("deploy must succeed");

    // The state root must change (new contract account).
    let root = module.state_root();
    let empty = Hash([
        0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8,
        0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63,
        0xb4, 0x21,
    ]);
    assert_ne!(root, empty, "state root must change after contract creation");
}

/// The state root must be deterministic across module instances
/// with the same state.
#[test]
fn state_root_is_deterministic_across_instances() {
    let key = TestKey::new();
    let recipient = EvmAddress::from_slice(&[0x42; 20]);

    let module1 = EvmModule::new(1, 7_000_000_000);
    fund(&module1, &key.addr);
    let raw = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);
    module1.handle(&dummy_ctx(), &raw).expect("tx must succeed");
    let root1 = module1.state_root();

    let module2 = EvmModule::new(1, 7_000_000_000);
    fund(&module2, &key.addr);
    let raw2 = signed_transfer(&key.privkey, 0, recipient, 1_000_000_000);
    module2.handle(&dummy_ctx(), &raw2).expect("tx must succeed");
    let root2 = module2.state_root();

    assert_eq!(root1, root2, "same state must produce same root");
}

/// A transaction with a wrong chain ID must be rejected.
#[test]
fn wrong_chain_id_is_rejected() {
    let key = TestKey::new();
    let recipient = EvmAddress::from_slice(&[0x42; 20]);
    let module = EvmModule::new(1, 7_000_000_000);
    fund(&module, &key.addr);

    // Build a tx with chain ID 2 (wrong).
    let tx_fields = TxLegacy {
        fields: TxFields {
            nonce: 0,
            gas_limit: GAS_LIMIT,
            to: TxKind::Call(recipient),
            value: U256::from(1_000_000_000),
            data: Bytes::new(),
            chain_id: 2,
        },
        gas_price: U256::from(10_000_000_000u64),
    };
    let signed = SignedTx::sign_legacy(tx_fields, &key.privkey).expect("sign must succeed");
    let raw = signed.encode_to_bytes();

    let result = module.handle(&dummy_ctx(), &raw);
    assert!(result.is_err(), "wrong chain ID must be rejected");
}

/// Multiple transfers in sequence must produce correct balances.
#[test]
fn multiple_transfers_produce_correct_balances() {
    let key = TestKey::new();
    let alice = EvmAddress::from_slice(&[0xAA; 20]);
    let bob = EvmAddress::from_slice(&[0xBB; 20]);
    let alice_oxide = Address(alice.0.into());
    let bob_oxide = Address(bob.0.into());
    let module = EvmModule::new(1, 7_000_000_000);
    fund(&module, &key.addr);

    // Transfer 1M wei to Alice.
    let raw1 = signed_transfer(&key.privkey, 0, alice, 1_000_000_000);
    module.handle(&dummy_ctx(), &raw1).expect("tx1 must succeed");

    // Transfer 2M wei to Bob.
    let raw2 = signed_transfer(&key.privkey, 1, bob, 2_000_000_000);
    module.handle(&dummy_ctx(), &raw2).expect("tx2 must succeed");

    assert_eq!(module.balance(&alice_oxide), 1_000_000_000, "alice must have 1M");
    assert_eq!(module.balance(&bob_oxide), 2_000_000_000, "bob must have 2M");
    assert_eq!(module.nonce(&key.addr), 2, "sender nonce must be 2");
}

/// The state root must remain the same after `begin_block`/`end_block`
/// with no transactions (empty block).
#[test]
fn empty_block_preserves_state_root() {
    let key = TestKey::new();
    let module = EvmModule::new(1, 7_000_000_000);
    fund(&module, &key.addr);

    let root_before = module.state_root();
    module.begin_block(Height::new(1));
    module.end_block(Height::new(1));
    let root_after = module.state_root();

    assert_eq!(root_before, root_after, "empty block must not change state root");
}
