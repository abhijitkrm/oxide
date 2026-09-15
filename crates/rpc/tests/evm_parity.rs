//! EVM-parity integration tests: drive a real `EvmModule` through a
//! block lifecycle (begin → execute signed txs → seal history) and
//! verify every newly wired `eth_*` endpoint serves real data —
//! transactions, receipts, logs, blocks, `eth_call`, and
//! `eth_estimateGas`.
//!
//! These are the RPC surface a MetaMask/Foundry client exercises;
//! each assertion maps to the shape geth/reth return.

use std::sync::Arc;

use evm::{EvmModule, tx};
use executor::Module;
use primitives::{Address, Height};
use rpc::{RpcRequest, RpcServer};
use serde_json::{Value, json};

/// Deterministic test private key — sender recovery is exercised
/// through `SignedTx::recover_sender`, so the address derives from
/// the signature rather than being hardcoded.
const PRIVKEY: [u8; 32] = [0x11; 32];

/// Runtime code that emits `LOG0` with 32 bytes ending in 0x42:
/// `PUSH1 0x42 PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 LOG0`.
const LOG_CONTRACT: &str = "604260005260206000a0";

/// Runtime code that returns 32 bytes ending in 0x2a:
/// `PUSH1 0x2a PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN`.
const RETURN_CONTRACT: &str = "602a60005260206000f3";

/// Runtime code that always reverts with empty data:
/// `PUSH1 0 PUSH1 0 REVERT`.
const REVERT_CONTRACT: &str = "60006000fd";

fn sign_transfer(privkey: &[u8; 32], nonce: u64, to: Address, value: u128) -> Vec<u8> {
    let tx = tx::TxLegacy {
        fields: tx::TxFields {
            nonce,
            gas_limit: 30_000_000,
            to: tx::TxKind::Call(alloy_primitives::Address::from(to.0)),
            value: revm::primitives::U256::from(value),
            data: revm::primitives::Bytes::new(),
            chain_id: 1,
        },
        gas_price: revm::primitives::U256::from(1_000_000_000u64),
    };
    tx::SignedTx::sign_legacy(tx, privkey).expect("sign").encode_to_bytes()
}

fn sign_call(privkey: &[u8; 32], nonce: u64, to: Address) -> Vec<u8> {
    sign_transfer(privkey, nonce, to, 0)
}

/// Recover the test sender address from a signed tx.
fn sender_of(raw: &[u8]) -> Address {
    let signed = tx::SignedTx::decode_raw(raw).expect("decode");
    signed.recover_sender().expect("recover")
}

fn keccak256(data: &[u8]) -> String {
    format!("0x{}", hex::encode(alloy_primitives::keccak256(data)))
}

struct Harness {
    rpc: RpcServer,
    sender: Address,
    log_contract: Address,
    return_contract: Address,
    revert_contract: Address,
}

/// Build a server + module, alloc-fund the sender, install three
/// contracts, execute a block containing a value transfer and a
/// log-emitting call, and seal it — leaving `harness` with real
/// history to query.
fn make_harness() -> Harness {
    let evm = Arc::new(EvmModule::new(1, 7));

    // Deterministic addresses for the genesis-installed contracts.
    let log_contract = Address([0xAA; 20]);
    let return_contract = Address([0xBB; 20]);
    let revert_contract = Address([0xCC; 20]);
    for (addr, code) in [
        (log_contract, LOG_CONTRACT),
        (return_contract, RETURN_CONTRACT),
        (revert_contract, REVERT_CONTRACT),
    ] {
        evm.genesis_insert_account(
            &addr,
            0,
            1,
            hex::decode(code).expect("contract hex"),
            Vec::new(),
        );
    }

    // Fund the sender via genesis alloc semantics.
    let probe = sign_transfer(&PRIVKEY, 0, Address([0x99; 20]), 0);
    let sender = sender_of(&probe);
    evm.genesis_insert_account(&sender, u128::MAX, 0, Vec::new(), Vec::new());

    // Execute block 1: one value transfer + one log-emitting call.
    let transfer = sign_transfer(&PRIVKEY, 0, Address([0x42; 20]), 1_000_000);
    let log_call = sign_call(&PRIVKEY, 1, log_contract);
    let ctx = executor::TxContext { sender: Address([0u8; 20]), nonce: 0, fee: 0 };
    evm.begin_block(Height::new(1));
    let results = evm.handle_batch(&ctx, &[transfer, log_call]);
    for (i, r) in results.iter().enumerate() {
        assert!(r.is_ok(), "tx {i} must execute: {r:?}");
    }
    evm.end_block(Height::new(1));

    let mut rpc = RpcServer::new(1, 7);
    rpc.set_evm(evm.clone());
    rpc.set_block_height(1);
    Harness { rpc, sender, log_contract, return_contract, revert_contract }
}

fn handle(server: &RpcServer, method: &str, params: Vec<Value>) -> Value {
    let req =
        RpcRequest { method: method.to_string(), params, id: json!(1), jsonrpc: "2.0".to_string() };
    let resp = server.handle(&req);
    assert!(resp.error.is_none(), "{method} errored: {:?}", resp.error);
    resp.result.unwrap()
}

fn hex_addr(a: &Address) -> String {
    format!("0x{}", hex::encode(a.0))
}

#[test]
fn get_block_by_number_returns_real_block() {
    let h = make_harness();
    let block = handle(&h.rpc, "eth_getBlockByNumber", vec![json!("latest"), json!(false)]);
    assert_eq!(block["number"], json!("0x1"));
    assert_ne!(
        block["hash"],
        json!("0x0000000000000000000000000000000000000000000000000000000000000000")
    );
    assert_eq!(block["transactions"].as_array().unwrap().len(), 2);
    assert_eq!(block["gasUsed"], json!("0xa699")); // 21_000 + 21_649 (LOG0 data cost)
    assert_eq!(block["baseFeePerGas"], json!("0x7"));
    // `transactions` are bare hashes when full=false.
    assert!(block["transactions"][0].is_string());
}

#[test]
fn get_block_by_number_full_txs() {
    let h = make_harness();
    let block = handle(&h.rpc, "eth_getBlockByNumber", vec![json!("0x1"), json!(true)]);
    let txs = block["transactions"].as_array().unwrap();
    assert_eq!(txs[0]["from"], json!(hex_addr(&h.sender)));
    assert_eq!(txs[0]["to"], json!(hex_addr(&Address([0x42; 20]))));
    assert_eq!(txs[0]["nonce"], json!("0x0"));
    assert_eq!(txs[0]["type"], json!("0x0"));
}

#[test]
fn get_block_by_hash_matches_number() {
    let h = make_harness();
    let by_num = handle(&h.rpc, "eth_getBlockByNumber", vec![json!("latest"), json!(false)]);
    let hash = by_num["hash"].clone();
    let by_hash = handle(&h.rpc, "eth_getBlockByHash", vec![hash, json!(false)]);
    assert_eq!(by_num, by_hash);
}

#[test]
fn get_transaction_by_hash_returns_full_tx() {
    let h = make_harness();
    let raw = sign_transfer(&PRIVKEY, 0, Address([0x42; 20]), 1_000_000);
    let hash = keccak256(&raw);
    let tx = handle(&h.rpc, "eth_getTransactionByHash", vec![json!(hash)]);
    assert_eq!(tx["blockNumber"], json!("0x1"));
    assert_eq!(tx["transactionIndex"], json!("0x0"));
    assert_eq!(tx["from"], json!(hex_addr(&h.sender)));
    assert_eq!(tx["value"], json!("0xf4240"));
    assert_eq!(tx["gas"], json!("0x1c9c380"));
    assert!(tx["v"].is_string() && tx["r"].is_string() && tx["s"].is_string());
}

#[test]
fn get_transaction_receipt_has_status_and_logs() {
    let h = make_harness();
    let log_call = sign_call(&PRIVKEY, 1, h.log_contract);
    let hash = keccak256(&log_call);
    let receipt = handle(&h.rpc, "eth_getTransactionReceipt", vec![json!(hash)]);
    assert_eq!(receipt["status"], json!("0x1"));
    assert_eq!(receipt["blockNumber"], json!("0x1"));
    assert_eq!(receipt["transactionIndex"], json!("0x1"));
    assert_eq!(receipt["gasUsed"], json!("0x5491")); // 21_000 + LOG0 data cost
    assert_eq!(receipt["cumulativeGasUsed"], json!("0xa699"));
    let logs = receipt["logs"].as_array().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0]["address"], json!(hex_addr(&h.log_contract)));
    assert_eq!(logs[0]["logIndex"], json!("0x0"));
    assert!(logs[0]["data"].as_str().unwrap().ends_with("42"));
    // Failed lookups return null, not an error.
    let missing = handle(
        &h.rpc,
        "eth_getTransactionReceipt",
        vec![json!("0x0000000000000000000000000000000000000000000000000000000000000001")],
    );
    assert_eq!(missing, Value::Null);
}

#[test]
fn get_logs_filters_by_address_and_range() {
    let h = make_harness();
    // Address filter hits.
    let logs = handle(
        &h.rpc,
        "eth_getLogs",
        vec![json!({
            "fromBlock": "0x0",
            "toBlock": "latest",
            "address": hex_addr(&h.log_contract),
        })],
    );
    assert_eq!(logs.as_array().unwrap().len(), 1);
    // Different address → empty.
    let logs = handle(
        &h.rpc,
        "eth_getLogs",
        vec![json!({
            "fromBlock": "0x0",
            "toBlock": "latest",
            "address": hex_addr(&Address([0x77; 20])),
        })],
    );
    assert_eq!(logs.as_array().unwrap().len(), 0);
    // blockHash form (EIP-234).
    let block = handle(&h.rpc, "eth_getBlockByNumber", vec![json!("latest"), json!(false)]);
    let logs = handle(&h.rpc, "eth_getLogs", vec![json!({"blockHash": block["hash"]})]);
    assert_eq!(logs.as_array().unwrap().len(), 1);
}

#[test]
fn call_executes_readonly() {
    let h = make_harness();
    // RETURN_CONTRACT returns 32 bytes ending in 0x2a.
    let out = handle(
        &h.rpc,
        "eth_call",
        vec![json!({"to": hex_addr(&h.return_contract)}), json!("latest")],
    );
    let ret = out.as_str().unwrap();
    assert!(ret.starts_with("0x") && ret.ends_with("2a"), "call output: {ret}");
    // eth_call must not mutate state — balance unchanged.
    let bal = handle(
        &h.rpc,
        "eth_getBalance",
        vec![json!(hex_addr(&h.return_contract)), json!("latest")],
    );
    assert_eq!(bal, json!("0x0"));
}

#[test]
fn call_revert_returns_code_3_with_data() {
    let h = make_harness();
    let req = RpcRequest {
        method: "eth_call".to_string(),
        params: vec![json!({"to": hex_addr(&h.revert_contract)}), json!("latest")],
        id: json!(1),
        jsonrpc: "2.0".to_string(),
    };
    let resp = h.rpc.handle(&req);
    let err = resp.error.expect("revert must error");
    assert_eq!(err.code, 3);
    assert!(err.message.contains("execution reverted"));
    assert!(err.data.is_some());
}

#[test]
fn estimate_gas_returns_intrinsic() {
    let h = make_harness();
    // A plain value transfer estimates at exactly 21_000.
    let out = handle(
        &h.rpc,
        "eth_estimateGas",
        vec![json!({
            "from": hex_addr(&h.sender),
            "to": hex_addr(&Address([0x42; 20])),
            "value": "0x1",
        })],
    );
    assert_eq!(out, json!("0x5208"));
}

#[test]
fn estimate_gas_reverting_call_errors() {
    let h = make_harness();
    let req = RpcRequest {
        method: "eth_estimateGas".to_string(),
        params: vec![json!({
            "from": hex_addr(&h.sender),
            "to": hex_addr(&h.revert_contract),
        })],
        id: json!(1),
        jsonrpc: "2.0".to_string(),
    };
    let resp = h.rpc.handle(&req);
    assert!(resp.error.is_some(), "reverting call must not estimate");
}

#[test]
fn account_queries_serve_real_state() {
    let h = make_harness();
    // Sender executed nonce 0 and 1 → nonce is 2.
    let nonce = handle(
        &h.rpc,
        "eth_getTransactionCount",
        vec![json!(hex_addr(&h.sender)), json!("latest")],
    );
    assert_eq!(nonce, json!("0x2"));
    // Recipient got the transfer.
    let bal = handle(
        &h.rpc,
        "eth_getBalance",
        vec![json!(hex_addr(&Address([0x42; 20]))), json!("latest")],
    );
    assert_eq!(bal, json!("0xf4240"));
    // Contract code retrievable.
    let code =
        handle(&h.rpc, "eth_getCode", vec![json!(hex_addr(&h.log_contract)), json!("latest")]);
    assert_eq!(code, json!(format!("0x{LOG_CONTRACT}")));
    // Historic tags on state queries error (no trie window yet).
    let req = RpcRequest {
        method: "eth_getBalance".to_string(),
        params: vec![json!(hex_addr(&h.sender)), json!("0x0")],
        id: json!(1),
        jsonrpc: "2.0".to_string(),
    };
    let resp = h.rpc.handle(&req);
    assert!(resp.error.is_some(), "historic state must error");
}

#[test]
fn block_receipts_and_counts_and_fee_history() {
    let h = make_harness();
    let count = handle(&h.rpc, "eth_getBlockTransactionCountByNumber", vec![json!("latest")]);
    assert_eq!(count, json!("0x2"));
    let receipts = handle(&h.rpc, "eth_getBlockReceipts", vec![json!("0x1")]);
    assert_eq!(receipts.as_array().unwrap().len(), 2);
    assert_eq!(receipts[1]["cumulativeGasUsed"], json!("0xa699"));

    let tx0 =
        handle(&h.rpc, "eth_getTransactionByBlockNumberAndIndex", vec![json!("0x1"), json!("0x0")]);
    assert_eq!(tx0["nonce"], json!("0x0"));

    let fees = handle(&h.rpc, "eth_feeHistory", vec![json!("0x4"), json!("latest"), json!([50.0])]);
    assert!(fees["baseFeePerGas"].is_array());
    // Only block 1 exists — the range clamps to the retained window.
    assert_eq!(fees["oldestBlock"], json!("0x1"));
    // The sealed block's reward percentile row exists.
    assert!(fees["reward"].as_array().unwrap().iter().any(|r| !r.is_null()));
}
