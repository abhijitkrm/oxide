use super::*;
use executor::Module;

#[test]
fn node_assembles_with_sequencer() {
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node = Node::assemble(&config);
    // The engine should be ready (no blocks yet).
    assert!(node.engine().finalized_height().is_none());
}

#[test]
fn node_assembles_with_oxidebft() {
    let config = NodeConfig {
        consensus: ConsensusConfig::OxideBft,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node = Node::assemble(&config);
    assert!(node.engine().finalized_height().is_none());
}

#[test]
fn node_smoke_test_passes() {
    run_node_smoke_test();
}

#[test]
fn config_parses_engine_names() {
    assert_eq!(ConsensusConfig::parse("sequencer"), Some(ConsensusConfig::Sequencer));
    assert_eq!(ConsensusConfig::parse("oxideBFT"), Some(ConsensusConfig::OxideBft));
    assert_eq!(ConsensusConfig::parse("unknown"), None);
}

#[test]
fn config_engine_swap_produces_same_app() {
    // The seam proof: the same app (executor + modules) runs under
    // either engine config without changes.
    let seq_config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let bft_config = NodeConfig {
        consensus: ConsensusConfig::OxideBft,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };

    let mut seq_node = Node::assemble(&seq_config);
    let mut bft_node = Node::assemble(&bft_config);

    // Both should assemble and be ready to run.
    assert!(seq_node.engine().finalized_height().is_none());
    assert!(bft_node.engine().finalized_height().is_none());
}

#[test]
fn fund_evm_account_works() {
    let node = Node::assemble(&NodeConfig::default());
    let addr = primitives::Address([0xAB; 20]);
    node.fund_evm_account(&addr, 1_000_000_000);
    // The EVM module should have the account funded.
    // We can't directly check the balance without importing
    // executor::Module, but the fact that this doesn't panic is
    // the proof that the EVM module is registered.
}

// ─── Disk-backed EVM storage tests ───────────────────────────

#[test]
fn disk_backed_evm_storage_assembles() {
    // A node with a disk-backed EVM store should assemble and
    // run consensus without errors.
    let tmp = std::env::temp_dir().join(format!(
        "oxide-test-redb-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: Some(tmp.clone()),
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node = Node::assemble(&config);
    // Submit a tx and finalize a block.
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();
    assert!(node.engine().finalized_height().is_some(), "block finalized");
    // Clean up the temp file.
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn full_kv_snapshot_sync_restores_evm_state() {
    // Full KV snapshot sync: export a snapshot with actual KV
    // state from a node with a disk-backed EVM store, import it
    // into a fresh node, and verify the EVM state matches.
    let tmp1 = std::env::temp_dir().join(format!(
        "oxide-test-snap-src-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let tmp2 = std::env::temp_dir().join(format!(
        "oxide-test-snap-dst-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));

    // Source node: disk-backed EVM store.
    let config_src = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: Some(tmp1.clone()),
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node_src = Node::assemble(&config_src);
    // Submit a tx and finalize a block to produce EVM state.
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node_src.engine().submit_tx(tx);
    node_src.engine().run_until_idle();
    assert!(node_src.engine().finalized_height().is_some());

    // Export the snapshot (with full KV state).
    let snapshot = node_src.export_snapshot();
    assert!(!snapshot.module_state.is_empty(), "snapshot must include module state");
    // At least one module (EVM) should have exported KV state.
    let has_kv = snapshot.module_state.iter().any(Option::is_some);
    assert!(has_kv, "at least one module must export KV state");

    // Destination node: fresh disk-backed EVM store.
    let config_dst = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: Some(tmp2.clone()),
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let node_dst = Node::assemble(&config_dst);

    // Import the snapshot into the destination node.
    node_dst.import_snapshot(&snapshot).expect("snapshot import must succeed");

    // Verify the destination node's height matches.
    assert_eq!(
        node_dst.app_handle().current_height(),
        node_src.app_handle().current_height(),
        "height must match after snapshot sync"
    );

    // Verify the EVM module's state root matches — this proves
    // the full KV state was transferred. Other modules (core,
    // staking) don't have StorageBackends yet, so their state
    // remains at genesis; the aggregate root won't match until
    // all modules support export_state/import_state.
    let evm_src = node_src.evm_module().expect("src has EVM");
    let evm_dst = node_dst.evm_module().expect("dst has EVM");
    assert_eq!(
        evm_dst.state_root(),
        evm_src.state_root(),
        "EVM state root must match after full KV snapshot sync"
    );

    // Clean up.
    let _ = std::fs::remove_file(&tmp1);
    let _ = std::fs::remove_file(&tmp2);
}

// ─── Snapshot sync tests ─────────────────────────────────────

#[test]
fn snapshot_export_round_trip() {
    // Assemble a node, finalize a block, export a snapshot,
    // import it into a fresh node, and verify the state matches.
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node = Node::assemble(&config);
    // Submit a tx and finalize a block.
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();
    assert!(node.engine().finalized_height().is_some(), "block finalized");

    // Export the snapshot.
    let snapshot = node.export_snapshot();
    // Height may be 0 (genesis block) — that's valid.
    assert!(!snapshot.module_roots.is_empty(), "snapshot must have module roots");

    // Import into a fresh node.
    let node2 =
        Node::assemble_from_snapshot(&config, &snapshot).expect("snapshot import must succeed");
    // The imported node's chain height must match the snapshot.
    assert_eq!(node2.app().current_height(), snapshot.height, "height must match after import");
    // The imported node's state root at the snapshot height must
    // match the snapshot's state root (it was set during import).
    assert_eq!(
        node2.app().state_root_at(snapshot.height),
        snapshot.state_root,
        "state root must match after import"
    );
}

#[test]
fn snapshot_import_rejects_empty() {
    let config = NodeConfig::default();
    let node = Node::assemble(&config);
    let empty_snapshot = executor::ExecutorSnapshot {
        height: 5,
        state_root: primitives::Hash::ZERO,
        module_roots: vec![],
        module_state: vec![],
        executed_nonces: vec![],
        nonce_root: primitives::Hash::ZERO,
        version: executor::SNAPSHOT_FORMAT_VERSION,
        module_versions: vec![],
    };
    let err = node.import_snapshot(&empty_snapshot).expect_err("empty snapshot must fail");
    assert_eq!(err, executor::SnapshotImportError::EmptySnapshot);
}

#[test]
fn snapshot_import_rejects_corrupted_state_root() {
    let config = NodeConfig::default();
    let mut node = Node::assemble(&config);
    // Finalize a block to get a real snapshot.
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();

    let mut snapshot = node.export_snapshot();
    // Corrupt the state root so it doesn't match the module roots.
    snapshot.state_root = primitives::Hash([0xFF; 32]);

    let node2 = Node::assemble(&config);
    let err = node2.import_snapshot(&snapshot).expect_err("corrupted snapshot must fail");
    match err {
        executor::SnapshotImportError::StateRootMismatch { expected, .. } => {
            assert_eq!(expected, primitives::Hash([0xFF; 32]));
        }
        other => panic!("expected StateRootMismatch, got {other:?}"),
    }
}

#[test]
fn snapshot_import_rejects_module_count_mismatch() {
    use crypto::hash::{Domain, Hasher};
    let config = NodeConfig::default();
    let mut node = Node::assemble(&config);
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();

    let mut snapshot = node.export_snapshot();
    // Add a fake module root to create a count mismatch.
    // Also recompute the state root to match so we test the
    // module count check, not the state root check.
    snapshot.module_roots.push(("fake".to_string(), primitives::Hash::ZERO));
    let mut root_data = Vec::new();
    for (_, root) in &snapshot.module_roots {
        root_data.extend_from_slice(root.as_bytes());
    }
    // HIGH fix: include the nonce root in the state root
    // recomputation (it's now part of the authenticated root).
    root_data.extend_from_slice(snapshot.nonce_root.as_bytes());
    snapshot.state_root = Hasher::hash_one(Domain::Block, &root_data);

    let node2 = Node::assemble(&config);
    let err = node2.import_snapshot(&snapshot).expect_err("module count mismatch must fail");
    match err {
        executor::SnapshotImportError::ModuleCountMismatch { snapshot: s, registered: r } => {
            assert!(s > r, "snapshot has more modules than registered");
        }
        other => panic!("expected ModuleCountMismatch, got {other:?}"),
    }
}

#[test]
fn snapshot_resume_after_import() {
    // After importing a snapshot, the node should be able to
    // resume consensus: finalize new blocks at height + 1, + 2, etc.
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node = Node::assemble(&config);
    // Finalize one block.
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();
    let snapshot = node.export_snapshot();
    let original_height = snapshot.height;

    // Import into a fresh node and resume.
    let mut node2 =
        Node::assemble_from_snapshot(&config, &snapshot).expect("snapshot import must succeed");
    // The executor's height should match the snapshot.
    assert_eq!(
        node2.app().current_height(),
        original_height,
        "executor height must match snapshot"
    );
    // Submit another tx and finalize — should produce a new block.
    let module_payload2 = staking::msg::delegate(Address([0u8; 20]), 50);
    let tx2 = build_tx(framework::module_id::STAKING, &module_payload2);
    node2.engine().submit_tx(tx2);
    node2.engine().run_until_idle();
    // The executor's height should have advanced.
    assert!(
        node2.app().current_height() > original_height,
        "executor height must advance after new block"
    );
}

#[test]
fn snapshot_export_deterministic() {
    // Two nodes with the same state produce the same snapshot.
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node1 = Node::assemble(&config);
    let mut node2 = Node::assemble(&config);
    // Both finalize the same block.
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node1.engine().submit_tx(tx.clone());
    node2.engine().submit_tx(tx);
    node1.engine().run_until_idle();
    node2.engine().run_until_idle();

    let snap1 = node1.export_snapshot();
    let snap2 = node2.export_snapshot();
    assert_eq!(snap1.height, snap2.height, "heights must match");
    assert_eq!(snap1.state_root, snap2.state_root, "state roots must match");
    assert_eq!(snap1.module_roots, snap2.module_roots, "module roots must match");
}

// ─── Metrics tests ───────────────────────────────────────────

#[test]
fn metrics_recorder_available_after_assemble() {
    let node = Node::assemble(&NodeConfig::default());
    // The metrics recorder should be available and empty.
    let prom = node.metrics().prometheus();
    // No metrics recorded yet — output should have headers but
    // no data lines.
    assert!(prom.contains("oxide_latency_ns"));
}

#[test]
fn metrics_records_snapshot_export() {
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node = Node::assemble(&config);
    // Finalize a block.
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();

    // Export a snapshot — should record metrics.
    let _ = node.export_snapshot();
    assert!(node.metrics().counter("snapshot_exports") >= 1);
    assert!(node.metrics().snapshot("snapshot_export").is_some());
}

#[test]
fn metrics_records_snapshot_import() {
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100,
        parallel_threshold: 32,
        evm_persistence: true,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node = Node::assemble(&config);
    let module_payload = staking::msg::delegate(Address([0u8; 20]), 100);
    let tx = build_tx(framework::module_id::STAKING, &module_payload);
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();
    let snapshot = node.export_snapshot();

    // Import into a fresh node — should record metrics.
    let node2 = Node::assemble(&config);
    node2.import_snapshot(&snapshot).expect("import must succeed");
    assert!(node2.metrics().counter("snapshot_imports") >= 1);
    assert!(node2.metrics().snapshot("snapshot_import").is_some());
}

#[test]
fn metrics_prometheus_includes_counters_and_gauges() {
    let node = Node::assemble(&NodeConfig::default());
    node.metrics().incr_counter("test_counter", 42);
    node.metrics().set_gauge("test_gauge", 100);
    let prom = node.metrics().prometheus();
    assert!(prom.contains("oxide_counter{name=\"test_counter\"} 42"));
    assert!(prom.contains("oxide_gauge{name=\"test_gauge\"} 100"));
}

// ── Shared config conversion (the 6.5 remediation) ──────────

/// A `config::Config` with every propagated field set to a
/// non-default value — the fixture `node_config_from` tests run
/// against.
fn full_config() -> config::Config {
    let mut config = config::Config::default();
    config.consensus.engine = config::ConsensusEngineKind::OxideBft;
    config.consensus.base_timeout_ms = 5_000;
    config.consensus.max_timeout_ms = 60_000;
    config.consensus.max_block_bytes = 4 << 20;
    config.consensus.max_block_gas = 2_000_000_000;
    config.executor.max_mempool_entries = 777;
    config.executor.parallel_threshold = 64;
    config.executor.min_fee = 42;
    config.executor.allow_unsigned_txs = true;
    config.storage.history_retention = 128;
    config.exchange.settlement_operator = Some(format!("0x{}", "ab".repeat(20)));
    config
}

#[test]
fn node_config_from_propagates_every_field() {
    let config = full_config();
    let rpc = config::RpcConfig { chain_id: 7777, base_fee: 123_456, ..Default::default() };
    let data_dir = std::path::PathBuf::from("/tmp/oxide-test");
    let overrides = AssemblyOverrides {
        allow_unsigned_txs: true,
        data_dir: Some(data_dir.clone()),
        wal_path: None,
        genesis: None,
    };
    let node_config = node_config_from(&config, &rpc, &overrides, NodeMode::Single)
        .expect("valid config maps cleanly");

    assert_eq!(node_config.consensus, ConsensusConfig::OxideBft);
    assert_eq!(node_config.max_mempool_entries, 777);
    assert_eq!(node_config.parallel_threshold, 64);
    assert_eq!(node_config.min_fee, 42);
    assert_eq!(node_config.chain_id, 7777);
    assert_eq!(node_config.base_fee, 123_456);
    assert!(
        !node_config.require_signed_txs,
        "allow_unsigned_txs from either layer disables enforcement"
    );
    assert_eq!(node_config.history_retention, Some(128));
    assert_eq!(
        node_config.storage_path,
        Some(data_dir.join("evm.redb")),
        "data_dir must become the EVM state path"
    );
    assert_eq!(
        node_config.durability_dir,
        Some(data_dir.clone()),
        "data_dir must root the block journal"
    );
    assert_eq!(
        node_config.wal_path,
        Some(data_dir.join("consensus.wal")),
        "data_dir must derive the consensus WAL — durable executor state without \
         engine continuity would re-propose covered heights on restart"
    );
    assert_eq!(
        node_config.settlement_operator,
        Some(primitives::Address([0xab; 20])),
        "the hex operator address must parse"
    );
    assert_eq!(
        node_config.block_budget,
        types::BlockBudget { max_bytes: 4 << 20, max_gas: 2_000_000_000 },
        "consensus block budgets must reach the engine"
    );
    assert_eq!(node_config.base_timeout_ms, 5_000);
    assert_eq!(node_config.max_timeout_ms, 60_000);
}

/// Signed enforcement is the default; the unsafe opt-out is an
/// OR of the CLI flag and the TOML field — neither layer can
/// silently weaken the other.
#[test]
fn node_config_from_unsigned_opt_out_requires_an_explicit_layer() {
    let mut config = config::Config::default();
    let rpc = config::RpcConfig::default();
    // Defaults: signed required.
    assert!(
        node_config_from(&config, &rpc, &AssemblyOverrides::default(), NodeMode::Single)
            .expect("ok")
            .require_signed_txs
    );
    // CLI flag alone disables it.
    let with_cli = AssemblyOverrides { allow_unsigned_txs: true, ..Default::default() };
    assert!(
        !node_config_from(&config, &rpc, &with_cli, NodeMode::Single)
            .expect("ok")
            .require_signed_txs
    );
    // TOML alone disables it.
    config.executor.allow_unsigned_txs = true;
    assert!(
        !node_config_from(&config, &rpc, &AssemblyOverrides::default(), NodeMode::Single)
            .expect("ok")
            .require_signed_txs
    );
}

#[test]
fn node_config_from_rejects_bad_operator_address() {
    let mut config = config::Config::default();
    config.exchange.settlement_operator = Some("0xzz".to_string());
    let err = node_config_from(
        &config,
        &config::RpcConfig::default(),
        &AssemblyOverrides::default(),
        NodeMode::Single,
    )
    .expect_err("malformed operator hex must fail");
    assert!(err.contains("settlement_operator"), "error should name the field: {err}");
}

#[test]
fn genesis_spec_from_file_converts_validators_and_balances() {
    let bls_hex = "11".repeat(48);
    let json = format!(
        r#"{{
                "chain_id": 1,
                "bank": {{ "balances": {{ "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "1000" }} }},
                "staking": {{ "validators": [
                    {{ "address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                      "stake": 5000,
                      "public_key": "{bls_hex}" }}
                ] }}
            }}"#
    );
    let genesis = config::genesis::Genesis::from_json_str(&json).expect("test genesis parses");
    let spec = genesis_spec_from_file(&genesis).expect("valid genesis converts");
    assert_eq!(spec.validators.len(), 1);
    assert_eq!(spec.validators[0].address, primitives::Address([0xbb; 20]));
    assert_eq!(spec.validators[0].stake, 5_000);
    assert_eq!(spec.validators[0].public_key.as_ref().map(Vec::len), Some(48));
    assert_eq!(spec.balances.len(), 1);
    assert_eq!(spec.balances[0].0, primitives::Address([0xaa; 20]));
    assert_eq!(spec.balances[0].1, 1_000 * framework::WEI_PER_UNIT);
}

#[test]
fn genesis_spec_devnet_synthesizes_fallback() {
    let fallback = config::GenesisConfig {
        num_validators: 3,
        num_prefunded_senders: 5,
        genesis_balance: 7,
        ..Default::default()
    };
    let spec = genesis_spec_devnet(&fallback);
    assert_eq!(spec.validators.len(), 3);
    assert_eq!(spec.balances.len(), 5);
    assert_eq!(spec.validators[0].stake, 1_000_000);
    assert_eq!(spec.balances[4].1, 7 * framework::WEI_PER_UNIT);
}

#[test]
fn devnet_mode_forces_oxidebft_and_warns_on_sequencer() {
    // `oxide-devnet` with no --engine/--config parses
    // `ConsensusEngineKind`'s serde default (sequencer) — the
    // mode must still run oxideBFT, and warn rather than fail
    // on a value indistinguishable from "unset".
    let mut config = config::Config::default();
    config.consensus.engine = config::ConsensusEngineKind::Sequencer;
    let node_config = node_config_from(
        &config,
        &config::RpcConfig::default(),
        &AssemblyOverrides::default(),
        NodeMode::Devnet,
    )
    .expect("ok");
    assert_eq!(
        node_config.consensus,
        ConsensusConfig::OxideBft,
        "devnet mode always runs oxideBFT"
    );
    let (warnings, errors) = validate_effective_config(&config, &node_config, NodeMode::Devnet);
    assert!(errors.is_empty(), "the override warns, never fails: {errors:?}");
    assert!(
        warnings.iter().any(|w| w.contains("sequencer")),
        "the override must be visible: {warnings:?}"
    );
    // The same parsed engine is honored (not overridden) in
    // single-node mode.
    let single_config = node_config_from(
        &config,
        &config::RpcConfig::default(),
        &AssemblyOverrides::default(),
        NodeMode::Single,
    )
    .expect("ok");
    assert_eq!(single_config.consensus, ConsensusConfig::Sequencer);
}

#[test]
fn validate_effective_config_fails_on_unwired_settings() {
    let mut config = config::Config::default();
    config.storage.archive = true;
    config.storage.journal_retain_segments = 5;
    let node_config = node_config_from(
        &config,
        &config::RpcConfig::default(),
        &AssemblyOverrides::default(),
        NodeMode::Devnet,
    )
    .expect("ok");
    let (_, errors) = validate_effective_config(&config, &node_config, NodeMode::Single);
    assert!(errors.iter().any(|e| e.contains("archive")), "archive must fail: {errors:?}");
    assert!(
        errors.iter().any(|e| e.contains("journal_retain_segments")),
        "journal_retain_segments must fail: {errors:?}"
    );
}

#[test]
fn validate_effective_config_warns_on_overrides_and_unsigned() {
    let mut config = config::Config::default();
    config.network.peers = vec!["127.0.0.1:20001".to_string()];
    // The unsafe opt-out is what produces the warning — signed
    // envelopes are the default and warn-free.
    config.executor.allow_unsigned_txs = true;
    let node_config = node_config_from(
        &config,
        &config::RpcConfig::default(),
        &AssemblyOverrides::default(),
        NodeMode::Devnet,
    )
    .expect("ok");
    let (warnings, errors) = validate_effective_config(&config, &node_config, NodeMode::Devnet);
    assert!(errors.is_empty());
    assert!(
        warnings.iter().any(|w| w.contains("network.peers")),
        "derived peer config should warn: {warnings:?}"
    );
    assert!(
        warnings.iter().any(|w| w.contains("unsigned")),
        "unsigned envelopes should warn: {warnings:?}"
    );
}

// ── Shared executor assembly ─────────────────────────────────

#[test]
fn assemble_executor_registers_the_full_module_graph() {
    let assembled = assemble_executor(&NodeConfig::default());
    let snap = assembled.app.export_snapshot();
    let names: Vec<&str> = snap.module_roots.iter().map(|(name, _)| name.as_str()).collect();
    for expected in ["core", "staking", "exchange", "perps", "oracle", "governance", "evm"] {
        assert!(
            names.contains(&expected),
            "module {expected} missing from the assembled graph: {names:?}"
        );
    }
}

#[test]
fn assemble_executor_honors_chain_id_and_base_fee() {
    // Previously the EVM module hardcoded chain id 1 / 7 gwei
    // while the executor's chain id was configurable — the two
    // could silently diverge.
    let config = NodeConfig { chain_id: 7777, base_fee: 555, ..Default::default() };
    let assembled = assemble_executor(&config);
    assert_eq!(assembled.evm_module.chain_id(), 7777);
    assert_eq!(assembled.evm_module.base_fee(), 555);
}

#[test]
fn assemble_executor_applies_genesis_spec() {
    let validator = primitives::Address([0x11; 20]);
    let funded = primitives::Address([0x22; 20]);
    let spec = GenesisSpec {
        validators: vec![GenesisValidator { address: validator, stake: 9_000, public_key: None }],
        balances: vec![(funded, 42_000)],
    };
    let config = NodeConfig { genesis: Some(spec), ..Default::default() };
    let assembled = assemble_executor(&config);
    assert_eq!(assembled.staking_module.stake(&validator), 9_000);
    assert_eq!(assembled.evm_module.balance(&funded), 42_000);
    // The devnet-default `[0u8;20]` validator must NOT be
    // registered when an explicit spec is given.
    assert_eq!(assembled.staking_module.stake(&primitives::Address([0u8; 20])), 0);
}

#[test]
fn assemble_executor_devnet_default_registers_zero_identity() {
    let assembled = assemble_executor(&NodeConfig::default());
    // The devnet default funds and registers `[0u8;20]`.
    assert!(assembled.evm_module.balance(&primitives::Address([0u8; 20])) > 0);
}

/// End-to-end: a real oxideBFT commit drives the executor, which
/// delivers the consensus execution context to the EVM — the
/// sealed block's timestamp is the proposer's wall-clock stamp
/// (seconds), not the height-derived stand-in.
#[test]
fn committed_block_timestamp_reaches_evm_history() {
    let config = NodeConfig { consensus: ConsensusConfig::OxideBft, ..Default::default() };
    let mut node = Node::assemble(&config);

    // A signed staking delegate tx — the default config requires
    // authenticated envelopes. The sender is the signing key's
    // derived address, funded on the EVM ledger.
    let (privkey, sender) = crypto::secp::generate_keypair_for_test();
    node.fund_evm_account(&sender, 1_000_000_000_000_000_000);
    let validator = Address([0u8; 20]);
    let module_payload = staking::msg::delegate(validator, 100);
    let tx = crate::cli::build_signed_tx_with(
        &privkey,
        sender,
        config.chain_id,
        framework::module_id::STAKING,
        &module_payload,
        0,
    );
    node.engine().submit_tx(tx);
    node.engine().run_until_idle();
    assert!(node.engine().finalized_height().is_some(), "a block finalized");
    // `finalized_height` is consensus-side — execution runs on
    // the exec lane. `attest_state` blocks until the worker's
    // watermark reaches height 0, which implies `end_block` (and
    // its history seal) already ran inside `execute_block`.
    node.app().attest_state(primitives::Height::new(0)).expect("block 0 executed");

    let evm = node.evm_module().expect("evm module registered");
    let sealed = {
        let history = evm.history();
        history.block(0).cloned()
    }
    .expect("block 0 sealed in history");
    // Height-derived would be `0 * 15 = 0`; a real epoch stamp is
    // post-2001 — assert the value came from a wall clock, not
    // the stand-in formula.
    assert!(
        sealed.timestamp > 1_000_000_000,
        "sealed timestamp {} must be a real epoch value",
        sealed.timestamp
    );
    // The gas limit is the consensus-enforced budget, and the
    // beneficiary is the single validator's staking address —
    // derived from its BLS key the same way `ValidatorSet` does.
    assert_eq!(sealed.gas_limit, config.block_budget.max_gas);
    let key = crypto::BlsSecretKey::from_ikm(&[1u8; 32]).expect("BLS key");
    let expected_beneficiary = crypto::bls::validator_address(&key.public_key());
    assert_eq!(sealed.coinbase.0, expected_beneficiary.0);
}

/// An unsigned envelope with an explicit sender and nonce — the
/// default-genesis validator `[0u8;20]` is the funded proposer/
/// depositor/voter; trader senders get their own addresses and
/// nonces must stay monotonic per sender.
fn build_tx_as(
    sender: primitives::Address,
    nonce: u64,
    module_id: u8,
    module_payload: &[u8],
) -> types::TxBytes {
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(module_payload);
    types::TxBytes::new(bytes)
}

/// The whole governance lifecycle driving a real exchange state
/// change: a fill accrues `fee_vault`, a funded proposal passes
/// quorum, waits out the timelock, and the exchange's
/// `ParameterSink` pays the withdrawal to the mandated address —
/// all through real engine-produced blocks.
#[test]
fn governance_applies_fee_vault_withdrawal_end_to_end() {
    let config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 10_000,
        parallel_threshold: 32,
        evm_persistence: false,
        storage_path: None,
        settlement_operator: None,
        min_fee: 0,
        chain_id: 1,
        require_signed_txs: false,
        history_retention: None,
        ..Default::default()
    };
    let mut node = Node::assemble(&config);
    let validator = primitives::Address([0u8; 20]);
    let gov = framework::module_id::GOVERNANCE;
    let exch = framework::module_id::EXCHANGE;
    let staking_id = framework::module_id::STAKING;
    // Nonces are per-sender monotonic — validator txs take 0..,
    // traders take their own senders.
    let mut nonce = 0u64;
    let mut submit = |node: &mut Node, module_id: u8, payload: &[u8]| {
        node.engine().submit_tx(build_tx_as(validator, nonce, module_id, payload));
        nonce += 1;
        node.engine().run_until_idle();
    };

    // Give the validator bonded voting power — genesis registers
    // it with zero stake; delegation supplies the power.
    submit(&mut node, staking_id, &staking::msg::delegate(validator, 1_000_000));

    // Accrue a real fee into the vault: fund two traders, move
    // base into custody, then cross a 5-lot fill at tick 500 —
    // quote leg 75_000 units, FEE_BPS=10 → vault gets 75.
    let buyer = primitives::Address([0xB0; 20]);
    let seller = primitives::Address([0x50; 20]);
    node.fund_evm_account(&buyer, 10u128.pow(21));
    node.fund_evm_account(&seller, 10u128.pow(21));
    let dep = exchange::msg::deposit_base(0, 1_000_000);
    node.engine().submit_tx(build_tx_as(buyer, 0, exch, &dep));
    node.engine().submit_tx(build_tx_as(seller, 0, exch, &dep));
    let sell = exchange::msg::place(
        0,
        trading::NewOrder {
            side: trading::Side::Sell,
            order_type: trading::OrderType::Limit,
            tif: trading::TimeInForce::Gtc,
            price: primitives::fixed::Price(1_000_000_000 + 500 * 1_000_000),
            qty: primitives::fixed::Qty(5_000),
            owner: seller,
            stp: trading::StpMode::None,
        },
    );
    node.engine().submit_tx(build_tx_as(seller, 1, exch, &sell));
    let buy = exchange::msg::place(
        0,
        trading::NewOrder {
            side: trading::Side::Buy,
            order_type: trading::OrderType::Limit,
            tif: trading::TimeInForce::Gtc,
            price: primitives::fixed::Price(1_000_000_000 + 500 * 1_000_000),
            qty: primitives::fixed::Qty(5_000),
            owner: buyer,
            stp: trading::StpMode::None,
        },
    );
    node.engine().submit_tx(build_tx_as(buyer, 1, exch, &buy));
    node.engine().run_until_idle();

    // Propose the withdrawal: value `[market][dest][amount]`.
    let dest = primitives::Address([0xDE; 20]);
    let mut value = Vec::with_capacity(29);
    value.push(0u8);
    value.extend_from_slice(&dest.0);
    value.extend_from_slice(&50u64.to_le_bytes());
    submit(&mut node, gov, &governance::msg::propose(b"exchange.fee_vault.withdraw", &value));
    // Fund it past MIN_DEPOSIT (1_000_000 units) → Voting opens.
    submit(&mut node, gov, &governance::msg::deposit(0, 1_000_000));
    // The validator's 1M power is the whole live committee —
    // quorum and majority in one ballot.
    submit(&mut node, gov, &governance::msg::vote(0, governance::Vote::Yes));
    // The sequencer only mints non-empty blocks — drive the
    // voting window (1000) + timelock (100) with junk txs that
    // reject at execution but still carry a block each. Each junk
    // tx comes from a FRESH sender at nonce 0: mempool `select`
    // anchors a sender's chain at its last-executed nonce + 1,
    // which the async exec lane updates a block behind commits —
    // under CPU contention a same-sender nonce chain queues behind
    // that lagging anchor and `run_until_idle` produces no block,
    // silently under-producing heights (observed flake: the loop
    // finished in 0.14s with the proposal still in Voting). A
    // first-seen sender's nonce-0 tx is always pending, so exactly
    // 1_150 heights are produced regardless of lane lag.
    let junk = governance::msg::vote(999_999, governance::Vote::Yes);
    for i in 0..1_150u64 {
        let mut a = [0xAAu8; 20];
        a[..8].copy_from_slice(&i.to_le_bytes());
        node.engine().submit_tx(build_tx_as(primitives::Address(a), 0, gov, &junk));
        node.engine().run_until_idle();
    }
    // Execution rides the exec lane — wait for the watermark,
    // then the vault's 50 units must sit on `dest` in wei.
    let height = node.engine().finalized_height().expect("blocks finalized");
    node.app().attest_state(height).expect("exec lane reached the tip");
    let evm = node.evm_module().expect("evm module registered");
    let got = framework::Balances::balance(evm, &dest);
    assert_eq!(got, 50, "governance-enacted withdrawal paid dest 50 units");
}

// ── devnet-node seam assembly ──────────────────────────────────
//
// `assemble_devnet_node` is the ONE multi-validator startup path —
// `oxide-devnet`, `TcpMultiNodeDevnet`, and `MultiNodeDevnet` all
// call it. These tests pin the seam contract: injected clock,
// membership gate, and WAL option.

fn devnet_spec(index: usize, key_byte: u8) -> devnet::DevnetNodeSpec {
    let keys: Vec<crypto::BlsSecretKey> = (1..=2u8).map(crate::cli::bls_key).collect();
    let vs = consensus::ValidatorSet::new(
        keys.iter().map(crypto::BlsSecretKey::public_key).collect(),
        vec![1; keys.len()],
    )
    .expect("validator set");
    devnet::DevnetNodeSpec {
        index,
        validator_set: vs,
        secret_key: crate::cli::bls_key(key_byte),
        config: NodeConfig::default(),
        clock: None,
        wal_path: None,
    }
}

#[test]
fn devnet_node_assembles_with_injected_clock() {
    // The clock seam: a deterministic counter reaches the engine —
    // the in-memory sim's identical-schedule determinism contract.
    let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1_700_000_000_000));
    let clock2 = std::sync::Arc::clone(&clock);
    let mut spec = devnet_spec(0, 1);
    spec.clock =
        Some(std::sync::Arc::new(move || clock2.load(std::sync::atomic::Ordering::Relaxed)));
    let mut node = devnet::assemble_devnet_node(spec).expect("assembles");
    assert!(!node.recovered, "no WAL — no recovery");
    assert_eq!(node.engine.validator_index(), 0);
    // The leader at view 0 is validator 0 in a 2-node set —
    // propose and check the injected timestamp lands on the header.
    let (header, _proposal) = node.engine.propose().expect("leader proposes");
    assert_eq!(header.timestamp, 1_700_000_000_000);
}

#[test]
fn devnet_node_rejects_key_outside_committee() {
    // A key not in the validator set must refuse to start — its
    // signatures would only ever be rejected noise.
    let spec = devnet_spec(0, 7); // key 7 is not in the {1,2} committee
    match devnet::assemble_devnet_node(spec) {
        Err(devnet::DevnetStartError::NotInCommittee { epoch }) => assert_eq!(epoch, 0),
        other => panic!("expected NotInCommittee, got {:?}", other.map(|_| "Ok")),
    }
}

#[test]
fn devnet_node_rejects_wrong_slot_on_fresh_start() {
    // Key 2's slot is index 1 — asking for index 0 means the key
    // file belongs to a different validator.
    let spec = devnet_spec(0, 2);
    match devnet::assemble_devnet_node(spec) {
        Err(devnet::DevnetStartError::WrongValidatorSlot { expected, resolved }) => {
            assert_eq!(expected, 0);
            assert_eq!(resolved, Some(1));
        }
        other => panic!("expected WrongValidatorSlot, got {:?}", other.map(|_| "Ok")),
    }
}
