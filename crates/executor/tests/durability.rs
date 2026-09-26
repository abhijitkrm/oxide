//! Crash-durability tests for the executor's block journal.
//!
//! The property under test: **after any crash, restart must recover
//! the same committed state every module had** — EVM accounts, native
//! module state, executed nonces, and per-height state roots alike.
//! Before the journal existed, only the EVM flushed per-block; a
//! crash left native modules at genesis while the EVM sat at the tip.
//!
//! "Crash" is modeled in-process: drop the `Executor` (and every
//! module `Arc`) without running a shutdown checkpoint, then rebuild
//! a fresh executor over the same data directory — the EVM's redb
//! backend reloads its flushed state (the half that was always
//! durable), and `recover_durable_state` must replay the journal to
//! bring every other module to the same height.

use std::path::Path;
use std::sync::Arc;

use executor::{DurabilityConfig, DurabilityError, Executor};
use framework::{Balances, module_id};
use mempool::build_signed_tx;
use ports::AppInterface;
use primitives::{Address, Height};
use types::{FinalizedBlock, TxBytes};

/// The validator every delegate tx targets — registered at genesis.
const VALIDATOR: Address = Address([0x77; 20]);

/// Test EVM chain id — matches the signed envelopes built below.
const CHAIN_ID: u64 = 1;
/// Base fee the ledger charges — any fixed value works; execution
/// just needs both replicas to agree.
const BASE_FEE: u64 = 7_000_000_000;

/// A deterministic sender key — reusing one signer across crashes
/// keeps nonce progression under test control (each crash cycle
/// advances the same account's nonce).
fn sender_keypair() -> ([u8; 32], Address) {
    let key = crypto::secp::test_identity_key(0);
    let addr =
        crypto::secp::test_identity_address(0).expect("devnet identity 0 derives an address");
    (key, addr)
}

/// Build a signed delegate envelope from the fixed sender.
fn delegate_tx(nonce: u64, fee: u64, amount: u64) -> TxBytes {
    let (privkey, _) = sender_keypair();
    build_signed_tx(
        &privkey,
        CHAIN_ID,
        nonce,
        fee,
        module_id::STAKING,
        &staking::msg::delegate(VALIDATOR, amount),
    )
    .expect("test keypair signs")
}

/// Assemble a durability-enabled executor over `dir`: EVM ledger
/// backed by a real `redb` store (so its state survives the
/// executor's drop — the half that was always durable) plus the
/// staking module (the native state the journal exists to save).
///
/// Returns the executor and the EVM handle for balance assertions.
/// The caller drops BOTH before "restarting" — `redb` holds a file
/// lock that a second `open` would otherwise wait on.
fn durable_executor(
    dir: &Path,
    checkpoint_interval: u64,
) -> (Executor, Arc<evm::EvmModule>, Arc<staking::StakingModule>) {
    let mut executor = Executor::new(1_000)
        .with_durability(
            DurabilityConfig::new(dir.join("state")).with_checkpoint_interval(checkpoint_interval),
        )
        .expect("journal dir is writable");
    // `DatabaseAlreadyOpen` means the previous incarnation's `redb`
    // file lock hasn't been released yet: `Arc::drop` reads
    // `strong_count == 0` the moment the last ref decrements, while
    // `EvmModule`'s destructor (and the `Database` close underneath
    // it) is still unwinding on whichever thread released it. A
    // simulated restart has to wait that out — the honest signal is
    // the flock itself, so retry until the OS releases it rather
    // than guessing at a sleep. Any other open error is fatal.
    let path = dir.join("state/evm.redb");
    let backend = Box::new(
        (0..500)
            .find_map(|_| match storage::RedbBackend::open(&path) {
                Err(redb::DatabaseError::DatabaseAlreadyOpen) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    None
                }
                result => Some(result.expect("redb backend opens")),
            })
            .expect("redb file lock released within 5s of the previous drop"),
    );
    let evm = Arc::new(evm::EvmModule::with_storage(CHAIN_ID, BASE_FEE, backend));
    executor.register_module(evm.clone());
    executor.set_fee_module(module_id::EVM);
    let staking = Arc::new(staking::StakingModule::new());
    staking.set_ledger(evm.clone());
    staking.genesis_register_validator(VALIDATOR, 1_000_000);
    executor.register_module(staking.clone());
    (executor, evm, staking)
}

/// Fund the test sender with `wei` on the ledger.
fn fund(evm: &evm::EvmModule) -> Address {
    let (_, sender) = sender_keypair();
    evm.mint(&sender, 1_000_000_000);
    sender
}

/// Finalize `blocks` starting at height `first`, each carrying
/// `txs_per` delegate txs from the fixed sender. Returns the
/// post-block state roots keyed by height.
fn run_blocks(
    executor: &Executor,
    first: u64,
    blocks: u64,
    txs_per: u64,
    nonce_start: u64,
) -> Vec<(u64, primitives::Hash)> {
    let mut roots = Vec::new();
    let mut nonce = nonce_start;
    for h in first..first + blocks {
        let txs: Vec<TxBytes> = (0..txs_per).map(|i| delegate_tx(nonce + i, 1, 100 + i)).collect();
        nonce += txs_per;
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(h),
            txs,
            signers: Vec::new(),
        });
        roots.push((h, executor.state_root_at(h)));
    }
    roots
}

/// Restart onto `dir`: fresh modules, `redb` reloads whatever the
/// EVM flushed, then journal replay must reproduce the live run.
/// Returns the rebuilt pair (the caller asserts against it).
fn restart(
    dir: &Path,
    checkpoint_interval: u64,
) -> (Executor, Arc<evm::EvmModule>, Arc<staking::StakingModule>) {
    let (executor, evm, staking) = durable_executor(dir, checkpoint_interval);
    // Recovery is explicit in production (the binary's boot path);
    // callers here do it themselves so the report is inspectable.
    (executor, evm, staking)
}

/// A crash with no snapshot.bin at all — the journal's baseline
/// record must re-root every module, including the `redb`-backed
/// EVM whose own flush already advanced past genesis.
#[test]
fn crash_before_first_checkpoint_replays_from_baseline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (executor, evm, staking) = durable_executor(dir.path(), u64::MAX);
    let sender = fund(&evm);
    let roots = run_blocks(&executor, 0, 5, 2, 0);
    let expected_nonce = executor.executed_nonce_of(&sender);
    let expected_bonded = Balances::balance(evm.as_ref(), &staking::BONDED_POOL);
    drop(executor);
    drop(evm);
    drop(staking);

    // Crash: no snapshot.bin exists (checkpoint interval never hit),
    // but evm.redb holds height-4 state on disk.
    assert!(!dir.path().join("state/snapshot.bin").exists());

    let (executor, evm, ..) = restart(dir.path(), u64::MAX);
    let report = executor
        .recover_durable_state()
        .expect("recovery must succeed")
        .expect("durability is configured");
    assert_eq!(report.blocks_replayed, 5);
    assert_eq!(report.recovered_height, 4);

    for (h, root) in &roots {
        assert_eq!(
            &executor.state_root_at(*h),
            root,
            "state root at {h} must match the pre-crash run"
        );
    }
    assert_eq!(executor.executed_nonce_of(&sender), expected_nonce);
    assert_eq!(Balances::balance(evm.as_ref(), &staking::BONDED_POOL), expected_bonded);
}

/// A checkpoint mid-run bounds replay: after a crash, only the
/// blocks above the checkpoint are re-executed; the journal's
/// covered segments are gone.
#[test]
fn checkpoint_bounds_replay() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (executor, evm, staking) = durable_executor(dir.path(), 4);
    let sender = fund(&evm);
    let roots = run_blocks(&executor, 0, 10, 1, 0);
    let expected_nonce = executor.executed_nonce_of(&sender);
    drop(executor);
    drop(evm);
    drop(staking);

    // Checkpoints at heights 4 and 8 → snapshot.bin captures h=8.
    assert!(dir.path().join("state/snapshot.bin").exists());

    let (executor, evm, ..) = restart(dir.path(), 4);
    let report = executor
        .recover_durable_state()
        .expect("recovery must succeed")
        .expect("durability is configured");
    assert_eq!(report.snapshot_height, Some(8));
    // Only heights 9 (and any post-checkpoint stragglers) replay —
    // heights ≤ 8 are covered by the imported checkpoint.
    assert_eq!(report.blocks_replayed, 1);
    assert_eq!(report.recovered_height, 9);

    for (h, root) in &roots {
        if *h < 8 {
            // Below the checkpoint the executor keeps no per-height
            // root — the checkpoint's planted root is the proof the
            // covered prefix is intact (import verified it against
            // the staged module state). This is the bounded-history
            // contract, not missing state.
            assert_eq!(executor.state_root_at(*h), primitives::Hash::ZERO);
        } else {
            assert_eq!(&executor.state_root_at(*h), root, "state root at {h}");
        }
    }
    assert_eq!(executor.executed_nonce_of(&sender), expected_nonce);
    assert!(Balances::balance(evm.as_ref(), &staking::BONDED_POOL) > 0);
}

/// Repeated crash/recovery cycles: each restart resumes where the
/// journal left off, and new blocks keep journaling on top — the
/// chain's durable prefix only ever grows.
#[test]
fn repeated_crashes_recover_the_full_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (executor, evm, staking) = durable_executor(dir.path(), u64::MAX);
    let sender = fund(&evm);
    let mut roots = run_blocks(&executor, 0, 3, 1, 0);
    drop(executor);
    drop(evm);
    drop(staking);

    let (executor, evm, ..) = restart(dir.path(), u64::MAX);
    executor.recover_durable_state().expect("recover").expect("configured");
    // The chain resumes at the journaled tip — new blocks journal
    // on top of the recovered prefix.
    roots.extend(run_blocks(&executor, 3, 3, 1, 3));
    drop(executor);
    drop(evm);

    let (executor, evm, ..) = restart(dir.path(), u64::MAX);
    let report = executor.recover_durable_state().expect("recover").expect("configured");
    assert_eq!(report.recovered_height, 5);
    for (h, root) in &roots {
        assert_eq!(&executor.state_root_at(*h), root, "state root at {h}");
    }
    assert_eq!(executor.executed_nonce_of(&sender), 6);
    assert!(Balances::balance(evm.as_ref(), &staking::BONDED_POOL) > 0);
}

/// A torn tail — a crash mid-append — must truncate at the last
/// complete record, never error or replay garbage.
#[test]
fn torn_journal_tail_stops_at_last_complete_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (executor, evm, staking) = durable_executor(dir.path(), u64::MAX);
    fund(&evm);
    let roots = run_blocks(&executor, 0, 3, 1, 0);
    drop(executor);
    drop(evm);
    drop(staking);

    // Corrupt the tail: append garbage bytes after the last complete
    // record in the newest segment. CRC framing must stop replay
    // exactly there.
    let journal_dir = dir.path().join("state/block-journal");
    let segment = std::fs::read_dir(&journal_dir)
        .expect("journal dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .max()
        .expect("a segment exists");
    let mut bytes = std::fs::read(&segment).expect("read segment");
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
    std::fs::write(&segment, &bytes).expect("write torn tail");

    let (executor, _evm, ..) = restart(dir.path(), u64::MAX);
    let report = executor.recover_durable_state().expect("recover").expect("configured");
    assert_eq!(report.recovered_height, 2, "torn tail truncates, never errors");
    for (h, root) in &roots {
        assert_eq!(&executor.state_root_at(*h), root);
    }
}

/// A stale `snapshot.bin` — an operator dropping a foreign or torn
/// file into the data dir — must not kill the boot: the journal is
/// the authority while its full prefix survives, so a rejected
/// checkpoint degrades to a full replay, and the rejection is
/// reported rather than silently swallowed.
#[test]
fn corrupt_snapshot_falls_back_to_journal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (executor, evm, staking) = durable_executor(dir.path(), u64::MAX);
    let sender = fund(&evm);
    let roots = run_blocks(&executor, 0, 6, 1, 0);
    drop(executor);
    drop(evm);
    drop(staking);

    // No checkpoint ever ran — snapshot.bin is a foreign file.
    let snap_path = dir.path().join("state/snapshot.bin");
    assert!(!snap_path.exists());
    std::fs::write(&snap_path, b"not a snapshot").expect("corrupt snapshot");

    let (executor, _evm, ..) = restart(dir.path(), u64::MAX);
    let report = executor.recover_durable_state().expect("recover").expect("configured");
    assert!(report.snapshot_rejected.is_some(), "corruption must be reported");
    // Journal replay covers the whole chain: baseline + blocks 0..5.
    assert_eq!(report.recovered_height, 5);
    assert_eq!(report.blocks_replayed, 6);
    for (h, root) in &roots {
        assert_eq!(&executor.state_root_at(*h), root);
    }
    assert_eq!(executor.executed_nonce_of(&sender), 6);
}

/// After a checkpoint, `snapshot.bin` is load-bearing: pruning has
/// already deleted the journaled prefix it covers, so corrupting it
/// leaves no path to the covered heights — recovery must fail
/// loudly, never resume at a divergent state.
#[test]
fn corrupt_checkpoint_with_pruned_journal_fails_loudly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (executor, evm, staking) = durable_executor(dir.path(), 4);
    fund(&evm);
    run_blocks(&executor, 0, 6, 1, 0);
    drop(executor);
    drop(evm);
    drop(staking);

    // Checkpoint@4 pruned blocks 0..4 from the journal; snapshot.bin
    // is now the only copy of that prefix. Corrupt it.
    let snap_path = dir.path().join("state/snapshot.bin");
    assert!(snap_path.exists());
    std::fs::write(&snap_path, b"not a snapshot").expect("corrupt snapshot");

    let (executor, _evm, ..) = restart(dir.path(), 4);
    let err = executor
        .recover_durable_state()
        .expect_err("a pruned journal cannot cover a corrupt checkpoint");
    // The first surviving record is block 5 — heights 0..4 are gone.
    assert!(
        matches!(err, DurabilityError::JournalGap { expected: 0, found: 5 }),
        "expected JournalGap(0→5), got {err:?}"
    );
}

/// A journal with a hole must fail loudly — replaying past a gap
/// would silently skip committed history and diverge from peers.
#[test]
fn journal_gap_fails_loudly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let (executor, evm, staking) = durable_executor(dir.path(), u64::MAX);
    fund(&evm);
    run_blocks(&executor, 0, 2, 1, 0);
    drop(executor);
    drop(evm);
    drop(staking);

    // Forge a gap: append a block at height 5 directly to the
    // journal (a second writer lands it in a fresh segment after the
    // existing records).
    {
        let mut writer = storage::journal::JournalWriter::create(
            &state_dir.join("block-journal"),
            storage::journal::JournalConfig::default(),
        )
        .expect("journal opens");
        let block = FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(5),
            txs: vec![delegate_tx(2, 1, 1)],
            signers: Vec::new(),
        };
        let mut payload = vec![0x00u8]; // TAG_BLOCK
        codec::Encode::encode(&block, &mut payload);
        writer.append_at_height(5, &payload).expect("append");
        writer.sync().expect("sync");
    }

    let (executor, _evm, ..) = restart(dir.path(), u64::MAX);
    let err = executor.recover_durable_state().expect_err("a gapped journal must not recover");
    assert!(
        matches!(err, DurabilityError::JournalGap { expected: 2, found: 5 }),
        "expected JournalGap(2→5), got {err:?}"
    );
}

/// `atomic_write` leaves exactly one durable file: no `.tmp`
/// residue, and an existing destination is replaced whole.
#[test]
fn atomic_write_replaces_without_residue() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("snapshot.bin");
    executor::durability::atomic_write(&path, b"first").expect("write");
    executor::durability::atomic_write(&path, b"second-and-longer").expect("rewrite");
    assert_eq!(std::fs::read(&path).expect("read"), b"second-and-longer");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("list dir")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "no .tmp files may survive");
}

/// `commit_durability_barrier` is the engine's pre-WAL-sync hook:
/// whatever the commit path buffered into the journal must be durable
/// before it returns. With the async lane spawned, `journal_append`
/// is buffer-only — a crash between the append and the lane's own
/// drain-sync must still not lose a committed record once the barrier
/// has run, or the WAL's durable commit evidence would suppress the
/// re-finalization that record exists to drive.
#[test]
fn commit_durability_barrier_flushes_pending_journal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (executor, evm, staking) = durable_executor(dir.path(), u64::MAX);
    let executor = Arc::new(executor);
    let sender = fund(&evm);
    executor.spawn_exec_lane();
    // The records are buffered on this thread; whether the worker
    // already drained-and-synced them is deliberately left to timing —
    // the barrier must cover both cases and be synchronous about it.
    run_blocks(&executor, 0, 3, 1, 0);
    executor.commit_durability_barrier();
    // "Crash": drop the executor outright. The lane worker may still
    // be holding a transient strong ref mid-execution — `Executor`'s
    // drop (which releases the EVM module) runs on whichever thread
    // releases the last ref, so wait for that ref to go. The `redb`
    // file lock can lag the drop by a moment (the destructor runs
    // *after* the count reads 0); `durable_executor` retries the open
    // to cover that tail.
    let evm_probe = Arc::downgrade(&evm);
    drop(executor);
    drop(evm);
    drop(staking);
    for _ in 0..500 {
        if evm_probe.strong_count() == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(evm_probe.strong_count(), 0, "lane worker must release the executor");

    let (executor, evm, ..) = restart(dir.path(), u64::MAX);
    let report = executor
        .recover_durable_state()
        .expect("recovery must succeed")
        .expect("durability is configured");
    assert_eq!(report.blocks_replayed, 3, "every committed block must replay");
    assert_eq!(report.recovered_height, 2);
    assert_eq!(executor.executed_nonce_of(&sender), 3);
    assert!(Balances::balance(evm.as_ref(), &staking::BONDED_POOL) > 0);
}

/// In lane mode the per-commit fsync moves off the caller: the lane
/// syncs once per drain batch. The observable contract that must hold
/// either way is recovery after a crash *without* the barrier — the
/// lane drains asynchronously, so whichever records were synced before
/// the drop form a contiguous prefix; replay must never gap on it.
#[test]
fn lane_mode_crash_recovers_synced_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (executor, evm, staking) = durable_executor(dir.path(), u64::MAX);
    let executor = Arc::new(executor);
    let sender = fund(&evm);
    executor.spawn_exec_lane();
    for h in 0..3 {
        executor.finalize_block(&FinalizedBlock {
            context: types::BlockContext::default(),
            height: Height::new(h),
            txs: vec![delegate_tx(h, 1, 100 + h)],
            signers: Vec::new(),
        });
    }
    // Let the lane catch up, then drop — everything synced is a
    // recoverable prefix. `attest_state` waits on the executed
    // watermark, which the worker only advances past a block after
    // its journal sync.
    let attest = executor.attest_state(Height::new(2));
    assert!(attest.is_some(), "lane must execute height 2");
    // The lane worker is idle now — its `Weak` cannot keep the
    // executor alive, but a mid-iteration transient upgrade can lag
    // a few microseconds; probe the EVM handle (whose drop closes
    // the redb file) so the "restart" is deterministic. The lock
    // release can trail the drop itself by a hair — the restart
    // helper retries `AlreadyOpen` to cover it.
    let evm_probe = Arc::downgrade(&evm);
    drop(executor);
    drop(evm);
    drop(staking);
    for _ in 0..500 {
        if evm_probe.strong_count() == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(evm_probe.strong_count(), 0, "lane worker must release the executor");

    let (executor, evm, ..) = restart(dir.path(), u64::MAX);
    let report = executor
        .recover_durable_state()
        .expect("recovery must succeed")
        .expect("durability is configured");
    assert_eq!(report.blocks_replayed, 3);
    assert_eq!(report.recovered_height, 2);
    assert_eq!(executor.executed_nonce_of(&sender), 3);
    assert!(Balances::balance(evm.as_ref(), &staking::BONDED_POOL) > 0);
}
